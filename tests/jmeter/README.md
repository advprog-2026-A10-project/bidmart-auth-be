# Auth API JMeter Plan

This folder contains a lightweight JMeter plan for the Auth BE UAS/final-project quality evidence.

Run from the project root after starting Auth BE:

```powershell
D:\rustrover\adpro_50\apache-jmeter-5.6.3\bin\jmeter.bat -n -t .\tests\jmeter\auth-api-smoke.jmx -l .\tests\jmeter\auth-api-smoke.jtl
```

Useful overrides:

```powershell
D:\rustrover\adpro_50\apache-jmeter-5.6.3\bin\jmeter.bat -n -t .\tests\jmeter\auth-api-smoke.jmx -Jhost=127.0.0.1 -Jport=8080 -Jthreads=10 -Jloops=5 -l .\tests\jmeter\auth-api-smoke.jtl
```

For local registration testing without a real Resend key, start Auth BE with:

```text
APP_EMAIL_DELIVERY_MODE=log
```

