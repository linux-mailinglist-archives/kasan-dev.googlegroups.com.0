Return-Path: <kasan-dev+bncBAABBIOVSPFQMGQEAKA35NQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-dl1-x123a.google.com (mail-dl1-x123a.google.com [IPv6:2607:f8b0:4864:20::123a])
	by mail.lfdr.de (Postfix) with ESMTPS id 345DAD12915
	for <lists+kasan-dev@lfdr.de>; Mon, 12 Jan 2026 13:35:48 +0100 (CET)
Received: by mail-dl1-x123a.google.com with SMTP id a92af1059eb24-121b1cb8377sf9261118c88.0
        for <lists+kasan-dev@lfdr.de>; Mon, 12 Jan 2026 04:35:48 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1768221346; cv=pass;
        d=google.com; s=arc-20240605;
        b=R3YAM7lSH57qajXiGiqlTT+AWXSHOF8fyyhAQRCW+82gqbAcDiSu3I61WTSvwEvrIf
         WifPB1SurLW8OlURRAd0Q+F9NvCwF2IUWGBtlqgSXQ2PliYHQOJlm2TWxyUSUinnUZjG
         l9SY1zdm6/uIN4Q250g8vgpmvgletU8Rn4+zEE0ZyqEmonW6BMbSQb2BaX/Z7IdaKRx0
         oaNIhAk84JPmSagfU3w2qs5hTDLErVBBRdvY3zJcK3c43FxQC/OSTu2lG1/V2ZwZz5wA
         hw30pkSLXMwvJS9tMJAfw6mI8oFXw8aW1lx+pBH/4dOGUzM4y0o4Seiv+34lIEZV2kzK
         UiZA==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:content-language
         :accept-language:message-id:date:thread-index:thread-topic:subject
         :to:from:sender:dkim-signature;
        bh=FWfuuAWDxgnJqzxQSo0PMkhHtilhE1Qyzl8Sx0shljU=;
        fh=FyYrwvzIAJXRccNo2LWpWC3OPLAugj757sucGTb0P5c=;
        b=JmqmhuyUtt3ElRxVdgILw24mxYub7bKlJMchm6UkZdhGeY8Sqe4e36k3vkCotMQEsC
         X1jdMK8ccmrCzJzAJRxW9vS/mKkJQwvR43M3AxE2GDpKixSAofirkzOnPauLhSR5/ByG
         Oaqe28xtj0i7wP3i/sUoeuKgImwvl1evdFR5MDG0NCk7KIKrnliR/izyTueHfIqyE88p
         28xEHCDt2I95+ZKgqMtDLREUK4uSUWJD/+Zw7ggqPHZkOdX8AUsms3oQY4PiZ4ZJ9N3O
         S0t8jB78/eFfYqWsUC2xKftHyUd1/dr3rQuIQE/2Dm+gOs+N0L0YgeN2E2I48fMHUozk
         Kptw==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@outlook.com header.s=selector1 header.b="R/CktwMO";
       arc=pass (i=1);
       spf=pass (google.com: domain of onken.dominga.70@outlook.com designates 2a01:111:f403:d215::3 as permitted sender) smtp.mailfrom=onken.dominga.70@outlook.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=outlook.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768221346; x=1768826146; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:content-language:accept-language
         :message-id:date:thread-index:thread-topic:subject:to:from:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=FWfuuAWDxgnJqzxQSo0PMkhHtilhE1Qyzl8Sx0shljU=;
        b=pHf+XOrpRygBkrYSMY4/eX9faJFamQxEg0TBuaARqOxFN76vWDo8+KbmA28DjoGVCW
         TB2Db4zJhlICg2CdXlDMHWs2Fc41QDaE0kpvMrlkthxD0opRALY8dWuJRtq9Qj7JIgVP
         vLM28/TJNit+SPR+5NnOEMOQzKc9OZF6JVXDPuPLodqrsNQMjTlFyPn39hBvoIPlMqWC
         CMg8js7qL4aXBy6jJ7YFp1J26raVPCCHay8EUrMdWQXOSQkyxx3ARrTa6D+WS4RtE9XP
         ru9oxhaCLCkvkt3M4vZprrbbg6IpC3vEK6sT2oTYt7A6N2m5jHUKISmXZLdHNhlSlq0L
         Dvyw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768221346; x=1768826146;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :content-language:accept-language:message-id:date:thread-index
         :thread-topic:subject:to:from:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=FWfuuAWDxgnJqzxQSo0PMkhHtilhE1Qyzl8Sx0shljU=;
        b=Z9lGz9v+vkoEhcCr/6PTUp5UA7G7YB0O1U4SgKOTE3t43CCw8yrdunc1MxZ9Mq6Sbv
         kKWElG0+OlZpKiXHF8glCwtNekK7FPW53UzvFsXHmZecGts64HpJ9RiWn08+/A7NJgdI
         J8WHU4qPKQw7VHW5VxDzVwLH2M7g2PWMCYjxb7kVENfqUMcGRvUPj0tIKfZUK8VbW4uJ
         driskmR0QNTtgGnYsMNoSu27PPMqPSf/cLoom2WtAmpbnKkRHq4vqNyDn5nt0Q3hJxKw
         5m2cW/6b4UOodO5NwaiC0wzKNqgwEtcBjlzb1dNr0JA7R3t5KdstBOeBC09SpKLpRyZ7
         5qgA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=3; AJvYcCVEyyRtwk9OxpoGzBhuf5smqCI//R+qOwQNFSlKO3DvtJqFq7rOCCwh/OPTry0xPcMtUM7ohw==@lfdr.de
X-Gm-Message-State: AOJu0Yzt+e1YQUtTA9bf57RNy8Wesq6IjnKwi0gREMQU1DBfI5RwlHjB
	nIvq1kj7USEW9h5P0Rq6rxqA3HWs/nbt0fW79+90cxhG8vv4n5eaUiQy
X-Google-Smtp-Source: AGHT+IFKZx4roeJXInZMvpIhn8V6FrbVGnw/PEFRCE6j3tGv1Ewo8y2kYlX7sriepxtTd47bWxGQzw==
X-Received: by 2002:a05:7022:43a0:b0:11b:9e5e:1a40 with SMTP id a92af1059eb24-121f8b16430mr14416777c88.15.1768221346196;
        Mon, 12 Jan 2026 04:35:46 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+GtrFn7F59Ug3QnaXnH7nejcI+JqMpn266HfVTzJRhZeg=="
Received: by 2002:a05:7022:11f:b0:11b:519:bafe with SMTP id
 a92af1059eb24-121f1389398ls3866282c88.2.-pod-prod-09-us; Mon, 12 Jan 2026
 04:35:45 -0800 (PST)
X-Received: by 2002:a05:7022:620:b0:11b:a73b:2327 with SMTP id a92af1059eb24-121f8b7b38dmr15900894c88.30.1768221344644;
        Mon, 12 Jan 2026 04:35:44 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768221344; cv=pass;
        d=google.com; s=arc-20240605;
        b=WFnYxKLm0KiFIA8IqCw0pdeYfHDfGniBYVeiH2E9lggjuYDwmlLJf9XAtGeHrBJujs
         umruZUVcR2V7KcwE9iAycX2ufb4xApSP3i4xjclXixoLqivk+w6JH+a15wPRBbPlmmVK
         1FyY7OFEU9AaeerFK5Q2raC+wAD1rWQGlwZX9t56T3WFsc8ip+kQzvuxdjPBa4EoQaQg
         SURD1lkIZrgGiiWg8E18ycuBw81Dp6d/5SxXMDJJ5qRN4LivN6RmGOM0EqocfKLm0nru
         PfPQYPyFLVw8ZOoG09/C2fGuFVxs2zCGV0sRJAbFBmuc/7ViPPxO3chvAzfTRSw17kQ/
         FFXA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:content-language:accept-language:message-id:date
         :disposition-notification-to:thread-index:thread-topic:subject:to
         :from:dkim-signature;
        bh=SV65NEcb4/Vmvl20sia1Nr4Gsj3TXHKkTsMwvhSCuQE=;
        fh=RYEHzHU/HAyeZBCO4E+IbnoHdOzcm1YWiVKtSJ7fCDU=;
        b=SZm8MzsjttbZ20hSCj8LP5QkiEUIFc4jfhGcUOvZl1pzwzc2kspSW/R+LfICrj3WqH
         2O8twWs3CUJexEJBPNHZ5xX/CFaLESr54UlJGU+Sd8UhAEctVHNcmn4EtZY0RPHUvqWb
         F3V3a7WP2FEk/EV5PulwdpTD7/VGVb3b1n21NR/ZW+JAlZYnv8NCI4LfTphxmxW7MRV3
         tmEbBXq9X8cLXopo+d7T1zYT5qQ7iJAyeZkXUiNfyaUP12iJzT8gIWueGuAowgFftpAJ
         9I8nEqZKmDSZuDiAfTZ1/lmR91OvOQkK9wvFMV/rLTP348AgLO0mGeAy5x7OOXlp1eVZ
         TGEQ==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@outlook.com header.s=selector1 header.b="R/CktwMO";
       arc=pass (i=1);
       spf=pass (google.com: domain of onken.dominga.70@outlook.com designates 2a01:111:f403:d215::3 as permitted sender) smtp.mailfrom=onken.dominga.70@outlook.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=outlook.com
Received: from MI0P293CU007.outbound.protection.outlook.com (mail-italynorthazolkn190130003.outbound.protection.outlook.com. [2a01:111:f403:d215::3])
        by gmr-mx.google.com with ESMTPS id a92af1059eb24-121f29a8c8csi573110c88.3.2026.01.12.04.35.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 12 Jan 2026 04:35:44 -0800 (PST)
Received-SPF: pass (google.com: domain of onken.dominga.70@outlook.com designates 2a01:111:f403:d215::3 as permitted sender) client-ip=2a01:111:f403:d215::3;
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=yY+PCC+5tr3rgo+8sUJbm+iJRuKlfqcOGM2dIZh8Ak7HeSDaPxtsf0+a4g11/XR+QEEjziITUokEZ4r+j7P89IBrAeSwKdZqg5onQHIIVgDmO7bwQA69SIWNzFbC7kvkq7a1NxWIlocJ3NL8FiYkkYgnabl5Ut8DWEUgyl6gSVP1lQahujR3YGfvnQnodTY/8R88i5shGdWOyetd1DnHxVxQqgBxFa0ZlOCmk1rYxE1rFw80NJ7YTirwvAOVq/R6XAu2Kp1tc1Uaxi6BAAJO04zi+rYdW7+XVyf15DtjdDy1rWhqTJMjjqHVzvizw1OlA9VGYxqnuaGuTqeq1eW0jQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=SV65NEcb4/Vmvl20sia1Nr4Gsj3TXHKkTsMwvhSCuQE=;
 b=u64Y5ijcfGSUKBTG6drabbJvfx5rpupqdKfF07uGFW4H3+79x1x9+LEkHIIN80d/C6lKwdaor7bSuGwYGUhLNJ1lCrPxGcF+a0ySfHMbWwG9LUM0mZ1Xja97ufBqFzaawezxKTkcV2yvJHC1KL/NwrN5b0Fe7I7uVJrepgFnv/RqKdmNbwiVPwVe/aaAEXxXgnPw3qxC7vNHUFINXFsQgfZfC4+Q6eVbv7xMrHnRglPnQ7iMuY7imoYtML8b/+1yLYToAfGhpyL6N70qG8XWRcjdTTyMnz+eeVOWRFtHLxnObe4o6G6JEzMAz4bPFYaIITWBNVX4L85YZrCMnAELgw==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=none; dmarc=none;
 dkim=none; arc=none
Received: from MI0P293MB0112.ITAP293.PROD.OUTLOOK.COM (2603:10a6:290:3e::6) by
 MI1P293MB0086.ITAP293.PROD.OUTLOOK.COM (2603:10a6:290:c::12) with Microsoft
 SMTP Server (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.20.9478.4; Mon, 12 Jan 2026 12:35:41 +0000
Received: from MI0P293MB0112.ITAP293.PROD.OUTLOOK.COM
 ([fe80::74db:96bd:91e9:a8fd]) by MI0P293MB0112.ITAP293.PROD.OUTLOOK.COM
 ([fe80::74db:96bd:91e9:a8fd%7]) with mapi id 15.20.9499.002; Mon, 12 Jan 2026
 12:35:41 +0000
From: Dominga Onken <onken.dominga.70@outlook.com>
To: "kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>
Subject: Your Thoughts?
Thread-Topic: Your Thoughts?
Thread-Index: AdyDv+tCKQLjVsK0SCiJ9RBJ4JFnJQ==
Date: Mon, 12 Jan 2026 12:35:41 +0000
Message-ID: <MI0P293MB01122E542C370B66F9AB1F41DD81A@MI0P293MB0112.ITAP293.PROD.OUTLOOK.COM>
Accept-Language: en-US
Content-Language: en-US
X-MS-Has-Attach: 
X-MS-TNEF-Correlator: 
x-ms-publictraffictype: Email
x-ms-traffictypediagnostic: MI0P293MB0112:EE_|MI1P293MB0086:EE_
x-ms-office365-filtering-correlation-id: bd944a70-ad64-4259-9b31-08de51d71959
x-ms-exchange-slblob-mailprops: bHQ38DpbEWAayy1Fxvh9DGGZQkLoCo9lnJwzH/w2yBKeAsIPSlliKMRhHlidpi9Ua/cVYPR3agFE0SwHS68PdHDPjPS3sWGyGGn/tiOoRWTTMdHgGdd9rEzHWXBFmv8HWWpniF8kA2MbyiMfo6/CV5oT4/Jty1hhGnfP92y3OgXmp3siJClAxUZach67gWcaPCoO83H+X2j9taWzpS4RLgz3L09/FiJwFF0MgcRdwq8d9KDp1IEI9rteT9NGOUkWIAyNiXtHLGEP/KxhjviG+5YaAYlJ1UbCKjF/KyganMguwPAJUYlYMKky2E3yd0q5m2vGjxQbaddpGmYlnRBXWJEwkAvxv7FOn+mPZv4WJS06Q1FBrcry0eSKVAUCkD7bbwAsx4MhOGNzI9xklDdxgufl1Ba4e2FvEokhewwRe7cO+/fRGVwTMfOS2tydvKifMdEWnwmfJOmf1I2gdchIL0U3+IXkpDPzp/tGg7t0dOsJtmrVVS0R33uxEcgqGm3fyHdbqVWhGpiKISoy3UC+OavMMPysbE1+712kVgN1WSov9ujGtnWBAn4/6BVRbA5mcbsV/V05CZfKzi5o1jpYtx3rf0A8a+FYjFuC7dPk/bfL/Y69kCqlBxZE8W2/7O/2IJFS9L32+5jx3+Kkq+M7m3JJjaskAMHar8GmR9Xil0UDZSJAUehRAw==
x-microsoft-antispam: BCL:0;ARA:14566002|31061999003|461199028|8060799015|15080799012|20031999003|19110799012|39105399006|10092599007|8062599012|13091999003|3412199025|40105399003|440099028|19111999003|102099032;
x-microsoft-antispam-message-info: =?us-ascii?Q?LJcv9Uv5/eKO/+YG7pKn8jbss41pgn8F5IyAWbR/g8pkOf6Cl4xuN7+WUJBA?=
 =?us-ascii?Q?lcMfKaBu7qSwbK7BgGlGSEkB5tBoW2tLF/K96+SCKcPiuW5XDbpVEgfFtRHd?=
 =?us-ascii?Q?/XRvV2JQpBDNo+8PLTYBsZAwgqg43fG10tT3Mr/BtBCEUBNJ46sAGlMAevIi?=
 =?us-ascii?Q?AdWn/Ow95oYRsLDI6tJu51nnsrj6St1W5dQy3I4mFAl/TVuBuTcLVVIyA/zA?=
 =?us-ascii?Q?ucPF2CvRr3UWL0sgYsr0Sc6bAbgZQ2sQW2hdD6MUzIKPfr3LMnjAxgsXKf1F?=
 =?us-ascii?Q?Zhk/xF7uFiiitR2Av6YC2QTqkLCobFkohlUiiT9E/A6eIl0an0njr8Tlej+J?=
 =?us-ascii?Q?j5JtPeDarYpp9c1O/YUgFynYRIlis4ISFHcWEgmeq6KFNQVTTHZA3BkBPE0C?=
 =?us-ascii?Q?DeH0zHCK8Fl0Y0o+Uc5xat7VOehdbNu0QwDFSLHBTxyxbzLrvT3Nmz+rnPLY?=
 =?us-ascii?Q?7Cx8YQGC7JGmWGaHrM2PBbYs8a/0LHXEKm4v0BlON4S6JSrabAu9PdLz18wJ?=
 =?us-ascii?Q?JEZ88QFurvRx98pY9QmwAl0MHTpOR7IYEalQYrnzxgVZvjDt2oJJ4RFk+sOn?=
 =?us-ascii?Q?I+gKprCvOIop4yhifcH+3gYyP4H44abNIhnCHsinj0QO9hDYjTH88bdhsgs/?=
 =?us-ascii?Q?2rrMYQSBsXt7wMOHaDXKVnQUQC5zo3EaFLiwi2A/IWouBcCoVCsuWp4S8KJo?=
 =?us-ascii?Q?goHQWg8wvZaXJyX0cSb8ldVPRZcTVuY0C347Slai1lT0VKEIqwSvMhFtnOMV?=
 =?us-ascii?Q?FN/eXIeA9LUcrAW1uJw7aEddvAI0YRseLnTBuWg0pIhSRiSOV0pnHq2UJIRG?=
 =?us-ascii?Q?HwcNHbVZFOR0JeSmPjaKMY0MGfyrvyP+xyDrmpDL/kfdFoKMKEk0aFfpAHAi?=
 =?us-ascii?Q?atomPScTfISyuMv/zUOpiLg2hkn7oNo5rmW0VD6aPKOxuDegPpgF+fR5uYj1?=
 =?us-ascii?Q?y9G/jfvcWB45S/cw3x1QjyQCdBTZ81DEdmMe3lYqL397JD0bZuXIvEeBOWhi?=
 =?us-ascii?Q?AJYT2m3qFhI2C+bor7Hjn6VUJJNLJe+tbzU0kufgSUKeVnK1iQY2T1eF3FtJ?=
 =?us-ascii?Q?PLHxtLy3idQhGDR0F8XmuJx7rOK5kFVzmsvHDgV9nPr6bd0E1JIy9XZ87OdE?=
 =?us-ascii?Q?A761pnc/NMw46BX+KGOyCjnzCvMShG10zjoZdkQPte7qrJI8U2EnvQDWABdv?=
 =?us-ascii?Q?sobZEcrsdOWmR8Cw9W/DuMZHTHOU11XwWsoEbV2GgYJbLCrTwrVhvagU1mhG?=
 =?us-ascii?Q?ohFNRI4y8fKanruxQ5UAAdE1cvcn2zDYhx2gyTv87K+b7XEQU3GpnWOeLreg?=
 =?us-ascii?Q?A6XsID82YGSb3hHI5obFqK77?=
x-ms-exchange-antispam-messagedata-chunkcount: 1
x-ms-exchange-antispam-messagedata-0: =?us-ascii?Q?jXJnz+BfVCQj1GMSNm3mNju9C14W4w+F6C1hpK65OE3ak1dJ7en+25bxf2xb?=
 =?us-ascii?Q?n4sa8+TJx7g7Myi1roPBO9tDXC/Az7lwFvjIEmOz4sIfdgGJw3iGg8GBYcf0?=
 =?us-ascii?Q?3oP0ZfrZvKwbvAVlZABXXyQU0jLaK9iG7Hy32VaUEPfo2UhwcFoW0ZbdAw4K?=
 =?us-ascii?Q?n333lg6TkF0RZLVbYuLmN0QmenPHCDMUQ/pNUdh9BoZ/sH2FDU0FASSiZ8tE?=
 =?us-ascii?Q?EUQTZnBFvYmL78iZh8upQGl9pBKCJ81mhEIsyUkXvEC+ALtFAThHf8tR6jOp?=
 =?us-ascii?Q?tGtRoectPyMz5M4TQfzj+n0kkqdCXC0QEJ/r9bi8WZjWY7AA8Gya/45AoYwv?=
 =?us-ascii?Q?/pthmkkEntVvU8/oe1beTdq9N+eT0/k8nU9md6CJGgqKc5QVu2Oyubd3vtr3?=
 =?us-ascii?Q?4/S7UsvjuhffxTmDyUVHd3uKiFdBWRT8W0enkL9Y1RhIrOMsoJow7EeznPsF?=
 =?us-ascii?Q?mUX59gikrGEd83Rnj+WeAHGV2Dt5gh9urbC9GfUcKYpJQt/xU9D00Al3RfvH?=
 =?us-ascii?Q?3F+O1Z9nXAzxlP6WGBj/RQiFy0oMz2UVwZJYdPJ48ZEshflr1IkJYQrlmYRe?=
 =?us-ascii?Q?3lV1hL+5OZQa4ttRT3iaPRuVFeK9F/z865VGDkkpOjgBWLBMxwkMQW4sMqa5?=
 =?us-ascii?Q?jDD7/dDvapS4rcxQ1J8ukES/K7Ni/yWCSo0awufcBRCLDiOKFnubhBRKxB2P?=
 =?us-ascii?Q?2gy010IsNDiB1t67Fq9ovpqASbDUPvVwJxhDYzBTn+H8ygmS4AsKDVmdKh4X?=
 =?us-ascii?Q?N+FsmGPoqcrj2G2HEh2NwdZG9WfIPL5cl7YXfKC6tCL0U8frb2zk61n5KGHn?=
 =?us-ascii?Q?Ubdrs6oJOeGgJLL9ZrYo5+mDvQvmXrIivb9X9kWSh6p+62UQebDl/D79H/AP?=
 =?us-ascii?Q?Wl8rUhnnGmzazUeAPOLw+jYgsgNpgbC1y2qpBywsiDN3/emvhUb0xeeS88Hi?=
 =?us-ascii?Q?DuvKVhzdcCYKdwwiHgtgo48VeihPnylhLkB7+JSeoIP4rwi26JcZvS6nwk2M?=
 =?us-ascii?Q?Gjv9R6bDSOTYLQcLPAUTlb/3fH+qvB/+TTzEoM1oYESYf/z5PngFHaCwstDG?=
 =?us-ascii?Q?lRLEBPPjx+R5d5EQmcC0dg72YgBwGnJtKcsxasIu6fVEv0rXwXjWVPR5Yh+P?=
 =?us-ascii?Q?M/N2eikklzqm6TLnLSeX5rieNDIDRqIwyKa/rFcCW8viKLMVD4LXDtEXn8ef?=
 =?us-ascii?Q?Of3Qcxr9ujq+bBU9+GQlZs2VLRDq/4K11ycfa5EMjOkBQl0n+q3D73+XD+2y?=
 =?us-ascii?Q?bSeG6AJKhBzuK9xW7+7gLXSR/7nWHMJta4AVpMdobGO5rk31ecNZJulqL/Hc?=
 =?us-ascii?Q?0T55Zn/4YmbHCEF26qb7syScjUIuiHvSeYkCx5r/jQJySzQi57MLTAg2Na7m?=
 =?us-ascii?Q?6M6yTsREuCoMIQv3WR1LEVfu/AJYA7y13JJ7pPeN955e56oWeg=3D=3D?=
Content-Type: multipart/alternative;
	boundary="_000_MI0P293MB01122E542C370B66F9AB1F41DD81AMI0P293MB0112ITAP_"
MIME-Version: 1.0
X-OriginatorOrg: outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-AuthSource: MI0P293MB0112.ITAP293.PROD.OUTLOOK.COM
X-MS-Exchange-CrossTenant-RMS-PersistedConsumerOrg: 00000000-0000-0000-0000-000000000000
X-MS-Exchange-CrossTenant-Network-Message-Id: bd944a70-ad64-4259-9b31-08de51d71959
X-MS-Exchange-CrossTenant-originalarrivaltime: 12 Jan 2026 12:35:41.8103
 (UTC)
X-MS-Exchange-CrossTenant-fromentityheader: Hosted
X-MS-Exchange-CrossTenant-id: 84df9e7f-e9f6-40af-b435-aaaaaaaaaaaa
X-MS-Exchange-CrossTenant-rms-persistedconsumerorg: 00000000-0000-0000-0000-000000000000
X-MS-Exchange-Transport-CrossTenantHeadersStamped: MI1P293MB0086
X-Original-Sender: onken.dominga.70@outlook.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@outlook.com header.s=selector1 header.b="R/CktwMO";       arc=pass
 (i=1);       spf=pass (google.com: domain of onken.dominga.70@outlook.com
 designates 2a01:111:f403:d215::3 as permitted sender) smtp.mailfrom=onken.dominga.70@outlook.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=outlook.com
Precedence: list
Mailing-list: list kasan-dev@googlegroups.com; contact kasan-dev+owners@googlegroups.com
List-ID: <kasan-dev.googlegroups.com>
X-Spam-Checked-In-Group: kasan-dev@googlegroups.com
X-Google-Group-Id: 358814495539
List-Post: <https://groups.google.com/group/kasan-dev/post>, <mailto:kasan-dev@googlegroups.com>
List-Help: <https://groups.google.com/support/>, <mailto:kasan-dev+help@googlegroups.com>
List-Archive: <https://groups.google.com/group/kasan-dev
List-Subscribe: <https://groups.google.com/group/kasan-dev/subscribe>, <mailto:kasan-dev+subscribe@googlegroups.com>
List-Unsubscribe: <mailto:googlegroups-manage+358814495539+unsubscribe@googlegroups.com>,
 <https://groups.google.com/group/kasan-dev/subscribe>

--_000_MI0P293MB01122E542C370B66F9AB1F41DD81AMI0P293MB0112ITAP_
Content-Type: text/plain; charset="UTF-8"

Dear Kasandev,

I hope this message finds you well. A friend of mine is giving away her late husband's Yamaha piano to an instrument lover. It's a special piece with a lot of meaning, and she'd be so happy if it went to someone who truly appreciates music.

Please let me know if you're interested or know someone who might be.

I'd be grateful for any thoughts or connections you might have.

Best regards,
Dominga Onken

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/MI0P293MB01122E542C370B66F9AB1F41DD81A%40MI0P293MB0112.ITAP293.PROD.OUTLOOK.COM.

--_000_MI0P293MB01122E542C370B66F9AB1F41DD81AMI0P293MB0112ITAP_
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2//EN">
<html>
<head>
<meta http-equiv=3D"Content-Type" content=3D"text/html; charset=3Dus-ascii"=
>
<meta name=3D"Generator" content=3D"MS Exchange Server version 16.0.19426.2=
0218">
<title></title>
</head>
<body>
<!-- Converted from text/rtf format -->
<p><font face=3D"Aptos">Dear Kasandev,</font> </p>
<p><font face=3D"Aptos">I hope this message finds you well. A friend of min=
e is giving away her late husband&#8217;s Yamaha piano to an instrument lov=
er. It&#8217;s a special piece with a lot of meaning, and she&#8217;d be so=
 happy if it went to someone who truly appreciates music.</font></p>
<p><font face=3D"Aptos">Please let me know if you&#8217;re interested or kn=
ow someone who might be.</font>
</p>
<p><font face=3D"Aptos">I&#8217;d be grateful for any thoughts or connectio=
ns you might have.</font>
</p>
<p><font face=3D"Aptos">Best regards,</font> <br>
<font face=3D"Aptos">Dominga Onken</font> </p>
</body>
</html>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion visit <a href=3D"https://groups.google.com/d/msgid/=
kasan-dev/MI0P293MB01122E542C370B66F9AB1F41DD81A%40MI0P293MB0112.ITAP293.PR=
OD.OUTLOOK.COM?utm_medium=3Demail&utm_source=3Dfooter">https://groups.googl=
e.com/d/msgid/kasan-dev/MI0P293MB01122E542C370B66F9AB1F41DD81A%40MI0P293MB0=
112.ITAP293.PROD.OUTLOOK.COM</a>.<br />

--_000_MI0P293MB01122E542C370B66F9AB1F41DD81AMI0P293MB0112ITAP_--
