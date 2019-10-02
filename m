Return-Path: <kasan-dev+bncBCSM5AFK2UKBBF6H2PWAKGQEAH7IKJQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33b.google.com (mail-ot1-x33b.google.com [IPv6:2607:f8b0:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id F0EF5C903A
	for <lists+kasan-dev@lfdr.de>; Wed,  2 Oct 2019 19:51:20 +0200 (CEST)
Received: by mail-ot1-x33b.google.com with SMTP id l25sf10278569otp.10
        for <lists+kasan-dev@lfdr.de>; Wed, 02 Oct 2019 10:51:20 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1570038679; cv=pass;
        d=google.com; s=arc-20160816;
        b=XjA4aufyFBKwW2T97Qg5TfdtlFJ3RRf65CGfNWDd2tFjNQi7zw0enOowInuMUZBo7T
         XntzHthrV8o0W0eONH7nNc1VIh4srLUAG1mB8E5RwSKh8lKs4SQGgh3BM4xg2grRR6+O
         KendFuGYsV+gqxZ9EpMiNjW4Ud1kdaQUSd6wFLiYAqk2dHiHCCjdQ1QvuaHCGLH96dw2
         Th9peFjvUIxlsvPpjXXlfm7YrUhKoBLKl1LUVCOGnMfyLbYJA7Skpq69AnbfjsF3lzEB
         i4xujVjY3bEKey4XVXXjIdsE0JSEq7VlhpV7ej8Yf4bSRK2Ckcc/30cSWz62exJplnwf
         kCpg==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:content-language
         :accept-language:message-id:date:thread-index:thread-topic:subject
         :from:sender:dkim-signature;
        bh=p836EtKvp77HW3/Jz5DqT4qvi5mnWZPP/YyytfjeXHY=;
        b=yDNr1IxX0q9Eouhj9At15GX8jFQAvNs0QLcOQ4oKk3dwho1k339kRroJxlM1bumkIH
         kIFvcoNTB74LCtDvVRbEX/1QPjVMQXBwI0fmpNVKWaVYkC2vCnAL5Icss3t77L5Mw4xM
         QIT7U80uqD9BW/98vgaQjv6+RRRQo1sSl3LwboAMaQADsTXlPlZjnOZP7SMrXL1/Evi2
         zbteM9xy7CWOvTeFCKrRtfc9rYcUEB4b+d91e/Am9usCe8nVfdMJs1YYol206FsemWeS
         g3V0SwZshfwTGN5oy1T3ss+jDlBj+d3ntKQFCxBP857nCDTNPYoAcLp5kysNj2XU90Tw
         TBXQ==
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@hotmail.com header.s=selector1 header.b=FlABwyst;
       arc=pass (i=1);
       spf=pass (google.com: domain of patmikando@hotmail.com designates 40.92.10.51 as permitted sender) smtp.mailfrom=patmikando@hotmail.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=hotmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:subject:thread-topic:thread-index:date:message-id
         :accept-language:content-language:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=p836EtKvp77HW3/Jz5DqT4qvi5mnWZPP/YyytfjeXHY=;
        b=MfCmz0seCS0f5odZB709Qt/BM3jQtvt9x9ZhEjWSuEccUvO5okKXeGC8JbVoLHxhrI
         Bu+hpeHbJh6DzKrXLjnIxSR8scVP/F+Mc5h1iM2WCYEFKcIlO0tUTg6poa8mT5ZKb08t
         4lcH+k9sKT8+ZA1Kj1t4309bItpL6iODLvJIRkhSglcHDMtt8DOgn9R82Vh+4t/UWHG2
         Fxd7K348VZ5cjmdV5nyMM4KJTvKI56mRGvIaMfLkL1RXaG/NAdWfSxw9Ktp5gRJefjSI
         bZiQFCfuZFeVrT7h4vF48XsJSRcbjGqXGwYuUmSeyI5ZlMqROsbaWNTI+OMjPt5gsbiM
         /kWQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:subject:thread-topic:thread-index
         :date:message-id:accept-language:content-language:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=p836EtKvp77HW3/Jz5DqT4qvi5mnWZPP/YyytfjeXHY=;
        b=e6Y8rv15wuc5OGKaWnlydvhc5C/r/1lzHBjM88fvLM5hnziR0vRZJ0qYCJzgeShFae
         P5xgYROlC8HlVigyMqLxlBxTGjHK+43tBJ4EX3j6U1FTcvSoEbXpW9TF3u17v+FjkMM0
         OwtBjCZNrEgr5W6jtprsz/yNrw96gGzgkKr7U36uBJwM30Bfs1vnXErfI0NFkH0V3SlZ
         0CaI9oMS5k+3IVZy16ho1z2QPyLICE2wNDUoVxpPjMcPZCBQtgq5V0Dnb71MjoaWRCeE
         Cga/qisNJy/DDv2GeQKnBX68YPYBMx+DjIBtyd4kTghL1HR+E1lB2EaK5i5kUEnvNUjU
         NHVQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAUq2VH2cx+D1FWN+mtXNKLWPNEGwLOHUA3pVAXs9/+OHwCVve8o
	yh7jwjEl4G9cX6XDz3JxB0s=
X-Google-Smtp-Source: APXvYqyOG1XOcTbrAIRV0aQjDj5whBpWKh7kCAQzWUWbXom7Us/F4rTtW2kErRywJYJlbEn2RxHpMg==
X-Received: by 2002:a9d:5544:: with SMTP id h4mr3515348oti.347.1570038679778;
        Wed, 02 Oct 2019 10:51:19 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:bd44:: with SMTP id n65ls635711oif.6.gmail; Wed, 02 Oct
 2019 10:51:19 -0700 (PDT)
X-Received: by 2002:aca:da87:: with SMTP id r129mr3863877oig.177.1570038679520;
        Wed, 02 Oct 2019 10:51:19 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1570038679; cv=pass;
        d=google.com; s=arc-20160816;
        b=QeB1sPF/J1FxTVJZCDLHDgOLdn53G5h2MvGAiRBUM+TEYs9IpbIe3laN+fK23XBnU4
         iqtto++JRcTAWkkYwN4jrP3cXyvZRao/QTPaLn0YlMCsbNDU3V6pVHv3BlXthqWRsmh+
         nfqurbG8pqy6vyVxhaRJJAMF0w6gvrVvUzk3v0SbusdKHUPB/Me+ZMTiFd+wlzS3W9c7
         w7SFRVkOwhs049UE1hIqgA9vJE692QcWOnbrECo3do0Ndbvj+qms/s+966peztUPssBK
         xc1p49hdK1ckdAi7YSd2ic189RlxcC7k5Ay6Z+1lJoW93L54g2dgVsSWBuggE2Lz5g6l
         NZQA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-language:accept-language:message-id:date
         :thread-index:thread-topic:subject:from:dkim-signature;
        bh=YZtYyvbx2rOAgGLhcsX0swMSOCJrlZlEXxET1LFiCTo=;
        b=Q1WU3HKKzReepDLbXnILRpweEFj+HTXZOKeAhjEBn9z+Z76/jNMC6yoMIOmyMqG9Fw
         G9+fg/ykewuv9bXzsVMSJiXY/BD5kmbn/sfh20PYl3YumEPXiyRxilAgey3XrfOUA9UV
         0oONWtabSBu2oRfoKqLZrcnxBpKeyt6qa512bbDDxCAlzE5KQaDjT4hQlR2xse+HTGG8
         4YGyfzp7o0xnqyiY4Lqm6kJPcic1LoAq223thOIbyREQAxid8VfiYr8omHRoQFdT6T20
         3YemRuDUf01bnD3a6NKwtr2Ek1PPdinK1CgrrIehlcIpcYZ3Zx8/NgZWKPCWYUrfsItk
         EWWw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@hotmail.com header.s=selector1 header.b=FlABwyst;
       arc=pass (i=1);
       spf=pass (google.com: domain of patmikando@hotmail.com designates 40.92.10.51 as permitted sender) smtp.mailfrom=patmikando@hotmail.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=hotmail.com
Received: from NAM04-CO1-obe.outbound.protection.outlook.com (mail-oln040092010051.outbound.protection.outlook.com. [40.92.10.51])
        by gmr-mx.google.com with ESMTPS id n63si1071484oib.3.2019.10.02.10.51.19
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 02 Oct 2019 10:51:19 -0700 (PDT)
Received-SPF: pass (google.com: domain of patmikando@hotmail.com designates 40.92.10.51 as permitted sender) client-ip=40.92.10.51;
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=eVbuEUTQw2NgKuGPjt2IL9VBrpyfDzqdgvdwB8KpT9QT25swbs5nmK/JofWQuhnsIoX28Tem1SD+cAksg734Nq6rjAWqcb0/eJT9iJZJg3JFQ5pTYukhUxXcZYYYTSB2jL8hDbWocgovhPj27dL8dj4YP+WrUW+FVgn6m9t+ELaksREOZaiREpXwuPp4ZRNGDZbeT1u1ta5d/CKut5g4xlOJTzYOVHIucssgTP1qA1+ipJ55p4LpcVamlVxvOwKL8EWgO8/GS+Qmy/8m6p3avzJWv1UMqMmWm9t4xgIa9orJg4Gz/9bqAT7vxzNzuVZBEJ2Hh5sIuG/1/AvQ0EiS2w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-SenderADCheck;
 bh=YZtYyvbx2rOAgGLhcsX0swMSOCJrlZlEXxET1LFiCTo=;
 b=RxXbPGkWZmmVqYNjC0dO1Jigi18mtpKdDRcMtluYI2e3XJYVDOz4OkcnNVrD3BdE3K36K7dLfcdsWUNcDtpJ8iDz1+WGmfTk7XVUyvPGRAo1h2+PAxbZsjZ3GfxcraAwxSV0XgD5bUKHQYy98eVgT4VFZsYv9ciNKYYn2Zg+qlG6ByzPbYqLmH/lS9jOPoMEZDiTR1CQtozw01TFH03n4AsZbfY4AucXu56+HT3haQzJs0o62Y10+UnruSn81/rFVt7Wtu7fUHN6ciDF/w8VFXQGOiBaxf1sdpa0Du5TmDdsyARCNoESb8A2iUjXjV+QIvOfeXgZ7hwFYDcFx0+gYg==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=none; dmarc=none;
 dkim=none; arc=none
Received: from SN1NAM04FT048.eop-NAM04.prod.protection.outlook.com
 (10.152.88.60) by SN1NAM04HT187.eop-NAM04.prod.protection.outlook.com
 (10.152.89.14) with Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384) id 15.20.2305.15; Wed, 2 Oct
 2019 17:51:17 +0000
Received: from SN6PR05MB3935.namprd05.prod.outlook.com (10.152.88.60) by
 SN1NAM04FT048.mail.protection.outlook.com (10.152.89.195) with Microsoft SMTP
 Server (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384) id
 15.20.2327.20 via Frontend Transport; Wed, 2 Oct 2019 17:51:17 +0000
Received: from SN6PR05MB3935.namprd05.prod.outlook.com
 ([fe80::d561:a657:2019:ed6c]) by SN6PR05MB3935.namprd05.prod.outlook.com
 ([fe80::d561:a657:2019:ed6c%5]) with mapi id 15.20.2327.021; Wed, 2 Oct 2019
 17:51:17 +0000
From: Patricia Mikando <patmikando@hotmail.com>
Subject: =?iso-8859-1?Q?W=FCnsche_dir_das_Beste?=
Thread-Topic: =?iso-8859-1?Q?W=FCnsche_dir_das_Beste?=
Thread-Index: AQHVeDy35jrF9+1pJ02uUhWphcHJ2Q==
Date: Wed, 2 Oct 2019 17:51:17 +0000
Message-ID: <SN6PR05MB39355261EBAFA196DC5BCA6FC19D0@SN6PR05MB3935.namprd05.prod.outlook.com>
Accept-Language: en-US
Content-Language: en-US
X-MS-Has-Attach: 
X-MS-TNEF-Correlator: 
x-incomingtopheadermarker: OriginalChecksum:E17C9F5F241E9AB22BD0A8ABF92EB4D1252EA15460330A5E4F263FBC87F9A695;UpperCasedChecksum:98FCC33C2C822B132D06695EFDC1B220395A43560E59EA7C9BD6FB2DFDC365D6;SizeAsReceived:8049;Count:40
x-tmn: [VuESFPfoIcyNHblNaSCFoT9/niMyv3Ie]
x-ms-publictraffictype: Email
x-incomingheadercount: 40
x-eopattributedmessage: 0
x-ms-traffictypediagnostic: SN1NAM04HT187:
x-microsoft-antispam: BCL:0;
x-microsoft-antispam-message-info: ecXQYSqnNUyJbtTbaQDXiNxRcYKQFY1wsRNz8pnks6kHIB6zw0lIVd7QzF67TdNDSowT4ognG53dUMcNW3Bw+1BbOFt6dIxdVmfV+15uX0aViHs+cdTcORZ5MLOF1lEvBO3ssOKB1yrx8dk/0prCxX8yHd8sSWThZufZP1jeoEzTnwPcOWqCzQm7pMCpVWPC
x-ms-exchange-transport-forked: True
Content-Type: multipart/alternative;
	boundary="_000_SN6PR05MB39355261EBAFA196DC5BCA6FC19D0SN6PR05MB3935namp_"
MIME-Version: 1.0
X-OriginatorOrg: hotmail.com
X-MS-Exchange-CrossTenant-RMS-PersistedConsumerOrg: 00000000-0000-0000-0000-000000000000
X-MS-Exchange-CrossTenant-Network-Message-Id: 10b76b5a-ea92-4e9c-b7ea-08d747612029
X-MS-Exchange-CrossTenant-rms-persistedconsumerorg: 00000000-0000-0000-0000-000000000000
X-MS-Exchange-CrossTenant-originalarrivaltime: 02 Oct 2019 17:51:17.2519
 (UTC)
X-MS-Exchange-CrossTenant-fromentityheader: Internet
X-MS-Exchange-CrossTenant-id: 84df9e7f-e9f6-40af-b435-aaaaaaaaaaaa
X-MS-Exchange-Transport-CrossTenantHeadersStamped: SN1NAM04HT187
X-Original-Sender: patmikando@hotmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@hotmail.com header.s=selector1 header.b=FlABwyst;       arc=pass
 (i=1);       spf=pass (google.com: domain of patmikando@hotmail.com
 designates 40.92.10.51 as permitted sender) smtp.mailfrom=patmikando@hotmail.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=hotmail.com
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

--_000_SN6PR05MB39355261EBAFA196DC5BCA6FC19D0SN6PR05MB3935namp_
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

Ich hoffe diese E-Mail findet dich.
Ich m=C3=B6chte wissen, ob Sie die letzte Nachricht erhalten haben, die ich=
 Ihnen gesendet habe?
Ich m=C3=B6chte wirklich von dir h=C3=B6ren.
W=C3=BCnsche dir das Beste.
Patricia Mikando.....
Ich freue mich auf ihre Antwort.

I hope this email finds you.
I want to know if you received the last message I sent you?
I really want to hear from you.
wish you all the best.
Patricia Mikando
I look forward to your response.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/SN6PR05MB39355261EBAFA196DC5BCA6FC19D0%40SN6PR05MB3935.namprd05.p=
rod.outlook.com.

--_000_SN6PR05MB39355261EBAFA196DC5BCA6FC19D0SN6PR05MB3935namp_
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<html>
<head>
<meta http-equiv=3D"Content-Type" content=3D"text/html; charset=3Diso-8859-=
1">
<style type=3D"text/css" style=3D"display:none;"> P {margin-top:0;margin-bo=
ttom:0;} </style>
</head>
<body dir=3D"ltr">
<div style=3D"font-family:Calibri,Helvetica,sans-serif; font-size:12pt; col=
or:rgb(0,0,0)">
</div>
<div style=3D"font-family:Calibri,Helvetica,sans-serif; font-size:12pt; col=
or:rgb(0,0,0)">
<div style=3D"margin:0px; font-size:12pt; font-family:Calibri,Helvetica,san=
s-serif; background-color:rgb(255,255,255)">
<span style=3D"margin:0px"><span style=3D"margin:0px">Ich hoffe diese E-Mai=
l findet dich.<br>
</span></span></div>
<div style=3D"margin:0px; font-size:12pt; font-family:Calibri,Helvetica,san=
s-serif; background-color:rgb(255,255,255)">
<span style=3D"margin:0px">
<div style=3D"margin:0px">Ich m=C3=B6chte wissen, ob Sie die letzte Nachric=
ht erhalten haben, die ich Ihnen gesendet habe?<br>
</div>
<div style=3D"margin:0px">Ich m=C3=B6chte wirklich von dir h=C3=B6ren.<br>
</div>
<div style=3D"margin:0px">W=C3=BCnsche dir das Beste.<br>
</div>
<div style=3D"margin:0px">Patricia Mikando.....<br>
</div>
<span style=3D"margin:0px">Ich freue mich auf ihre Antwort.</span><br>
</span></div>
<div style=3D"margin:0px; font-size:12pt; font-family:Calibri,Helvetica,san=
s-serif; background-color:rgb(255,255,255)">
<span style=3D"margin:0px"><br>
</span></div>
<div style=3D"margin:0px; font-size:12pt; font-family:Calibri,Helvetica,san=
s-serif; background-color:rgb(255,255,255)">
<span style=3D"margin:0px">I hope this email finds you.<br>
</span></div>
<div style=3D"margin:0px; font-size:12pt; font-family:Calibri,Helvetica,san=
s-serif; background-color:rgb(255,255,255)">
<span style=3D"margin:0px"></span></div>
<div style=3D"margin:0px; font-size:12pt; font-family:Calibri,Helvetica,san=
s-serif; background-color:rgb(255,255,255)">
<div style=3D"margin:0px">I want to know if you received the last message I=
 sent you?<br>
</div>
<div style=3D"margin:0px">I really want to hear from you.<br>
</div>
<div style=3D"margin:0px">wish you all the best.<br>
</div>
<div style=3D"margin:0px">Patricia Mikando<br>
</div>
<span style=3D"margin:0px">I look forward to your response.</span></div>
<br>
</div>
</body>
</html>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion on the web visit <a href=3D"https://groups.google.c=
om/d/msgid/kasan-dev/SN6PR05MB39355261EBAFA196DC5BCA6FC19D0%40SN6PR05MB3935=
.namprd05.prod.outlook.com?utm_medium=3Demail&utm_source=3Dfooter">https://=
groups.google.com/d/msgid/kasan-dev/SN6PR05MB39355261EBAFA196DC5BCA6FC19D0%=
40SN6PR05MB3935.namprd05.prod.outlook.com</a>.<br />

--_000_SN6PR05MB39355261EBAFA196DC5BCA6FC19D0SN6PR05MB3935namp_--
