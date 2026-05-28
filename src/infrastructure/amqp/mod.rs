use lapin::{
    options::{BasicPublishOptions, ExchangeDeclareOptions},
    types::FieldTable,
    BasicProperties, Channel, Connection, ConnectionProperties, ExchangeKind,
};

#[derive(Clone)]
pub struct AmqpPublisher {
    channel: Channel,
    exchange: String,
}

impl AmqpPublisher {
    pub async fn connect(amqp_url: &str, exchange: &str) -> Result<Self, lapin::Error> {
        let conn = Connection::connect(amqp_url, ConnectionProperties::default()).await?;
        let channel = conn.create_channel().await?;

        channel
            .exchange_declare(
                exchange,
                ExchangeKind::Topic,
                ExchangeDeclareOptions {
                    durable: true,
                    ..Default::default()
                },
                FieldTable::default(),
            )
            .await?;

        tracing::info!(exchange, "AMQP publisher ready");
        Ok(Self {
            channel,
            exchange: exchange.to_string(),
        })
    }

    pub fn publish(&self, routing_key: impl Into<String>, payload: serde_json::Value) {
        let channel = self.channel.clone();
        let exchange = self.exchange.clone();
        let routing_key = routing_key.into();

        tokio::spawn(async move {
            let body = match serde_json::to_vec(&payload) {
                Ok(body) => body,
                Err(error) => {
                    tracing::warn!(?error, routing_key, "AMQP serialize failed");
                    return;
                }
            };

            if let Err(error) = channel
                .basic_publish(
                    &exchange,
                    &routing_key,
                    BasicPublishOptions::default(),
                    &body,
                    BasicProperties::default()
                        .with_content_type("application/json".into())
                        .with_delivery_mode(2),
                )
                .await
            {
                tracing::warn!(?error, routing_key, "AMQP publish failed");
            }
        });
    }
}
