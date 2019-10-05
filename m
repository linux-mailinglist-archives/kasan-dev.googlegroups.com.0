Return-Path: <kasan-dev+bncBAABBPWZ4TWAKGQEHURMO3A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33e.google.com (mail-wm1-x33e.google.com [IPv6:2a00:1450:4864:20::33e])
	by mail.lfdr.de (Postfix) with ESMTPS id 10AADCCD55
	for <lists+kasan-dev@lfdr.de>; Sun,  6 Oct 2019 01:52:31 +0200 (CEST)
Received: by mail-wm1-x33e.google.com with SMTP id r187sf3717434wme.0
        for <lists+kasan-dev@lfdr.de>; Sat, 05 Oct 2019 16:52:31 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1570319550; cv=pass;
        d=google.com; s=arc-20160816;
        b=mXj426cI2gTAo2ENE5zuSb1talqaPZwc9WhBRzfHCVoHmN5NSNGHJujYqizNnexO4b
         xuf5YDvA1EEfCaKtjZXT9qP/It+Ap/h8wRNaQn1WhbASyF6XbNYl74ljHybRjeAuEgTz
         YyMOOI+kaVgJYazo4iRZ/AnsPFrinpAR9Y6kIODG/IZR8p02cS9eYMzF/4/1Kck0gMri
         RTMi/vxBrE5tAL/NuW4qE5A2zSixWHR6koebAikpllGjO03Fv/LYXuIFn7qRVpByw/pI
         q8ALx169U2g1x4cjOcc8W8P9lCBIGBOGRmXOpYfDe5Cc0u8k1uQDAg7NJSHRTFsxn9Tk
         /VFQ==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:content-language
         :accept-language:message-id:date:thread-index:thread-topic:subject
         :from:sender:dkim-signature;
        bh=dG1RKHOp6bu+PKJZkzvuCCpPA2H6ooUfG8C4A+OmOi4=;
        b=lT5ZJdV+zOLJ2OIlOsEMwecSwmQeBIFwjFUWIXXN9LnqlR1hqJ0jBCWFZ6WV9W8mQA
         afeB6NOzk/nJfWlFAEu7RwGSG2NlFiqqe1v5uJd1ZrnS0LRbeYgfo2kQOpbPSjkg+wOR
         BcNHJEVS0z8+yWP2KQgZF0061vJFriLjBg0rbMbvSTx/PZFemPbKRm6yr87N9tMbFBjX
         Tk2fcjKarKT5VeTYLDwCJhHk1C+y8QThpChHAP8fHPRi6YZpUUFjxClZfeUX3YNYrrOS
         Njnh+Uuzmxxq984mXT21rd1GhaArO1JGZujwkALnmbtWSvZQnbB0Hj161wwEPjeIgz+X
         MoyQ==
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@hotmail.com header.s=selector1 header.b=Ahzvicov;
       arc=pass (i=1);
       spf=pass (google.com: domain of miran20089@hotmail.com designates 40.92.67.32 as permitted sender) smtp.mailfrom=miran20089@hotmail.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=hotmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:subject:thread-topic:thread-index:date:message-id
         :accept-language:content-language:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=dG1RKHOp6bu+PKJZkzvuCCpPA2H6ooUfG8C4A+OmOi4=;
        b=RXj79tpFriqh77YN/BQJV82OlunkQAOZGaDLhyEbvP+qmLYCa07+dV7Aly9+2H/Ok7
         jwIr7uPyvuc08Pu/ZeGV90JXebSO52Qsiis3aYMYcY8JqYFhNz+8GBZ1SXoimGK78qkY
         OAAkfSmjBv3uL6geYEbUPKNIjlukXcteXRyc1bcA9ssJWp2pjuOC1p+3IOqyrMjyl8Eo
         NeqFo8m3Jcrj3ggliGFx1UQmmInWD2fUBOX9Hp2XYCaaQd21RSn81f2JVdSgYBa5vy/C
         mHamGmDWU9Hz9f2KW5aO5F/Odg6S+quD2HahpEqHPZYlpKwFuUvjPOKtGVgiP8L4ImCH
         Q0fQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:subject:thread-topic:thread-index
         :date:message-id:accept-language:content-language:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=dG1RKHOp6bu+PKJZkzvuCCpPA2H6ooUfG8C4A+OmOi4=;
        b=HKpiLWVr54ZbUlRYasLFyE09oNLI54WmJgQHZ+A+T5FNTi98P76pfnUtRuYBsWsA+D
         5ShQbqifW8ggi1bG0BM4fxDz2RLUu/L7qORT5deHq+DW4t+T/GAfMOhvCF+MaGfRLS4N
         Rw+SSh4PryILLQqx+ACzefNYh/6b2Ol23nDKwVqV+4/R2kFaYvb0zWbtZP9hhp2WNRWE
         u79YlRXQukqiYWp2v22s1FDkurGEvVhFzc66Krz+1B7xe0CMg+rg9fo9kSxc4/eyxnOm
         rrnLgzdXQR+v/Hr+uxlT32mq0U+2gQRf9cnaLRMYJvo1roAsthGZt/F4Yga2FEQNwdTU
         MLVg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVOorr315bgma/aCmfITu6CkybdULTpzqiv//GoUKQ1ccUKCMsn
	kN128kdJtlNHyNGW+0MeizM=
X-Google-Smtp-Source: APXvYqx7UnfltuYXzDEtT3nlLXKl1f4mFRIHWUlaJpDpcZe4vLrjShablwOXxnjmn+h/q0Hvv99M4Q==
X-Received: by 2002:a1c:4108:: with SMTP id o8mr16386332wma.129.1570319550606;
        Sat, 05 Oct 2019 16:52:30 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a7b:c772:: with SMTP id x18ls2385673wmk.1.canary-gmail; Sat,
 05 Oct 2019 16:52:30 -0700 (PDT)
X-Received: by 2002:a7b:ce0a:: with SMTP id m10mr15426041wmc.121.1570319550301;
        Sat, 05 Oct 2019 16:52:30 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1570319550; cv=pass;
        d=google.com; s=arc-20160816;
        b=oFPIfhF0TAEGd54C81T8TlGTReqcaqPD1sgQP5Kv8luSZ9y0uClFJQR/c9SNhEhdkI
         x1/Nnl4X8Nw8EvI4BL1snrhTEn1qqLauU1UZZ3PasQ7a984udDm+WDSQo/6iU7BQto/I
         gJbdJWv9LRYf51IAFKNS58ALxC0JsksnJi8qsZwkUV6K6uU2c3B4LWXpHmxTp0cGsYeo
         5SdHrc6xJ2moHh/4dKZ8wgVhvN4YObgEDR2snQ0/w4IpM0+6F8OFxVh1NZwjF599xYA1
         4DZM+UrOSOrfwjZAvW862nQDP2MXDAoK8cQqwBq91UgtHrlT9Va0/zhTrvxj0o3A2eAG
         qU8A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-language:accept-language:message-id:date
         :thread-index:thread-topic:subject:from:dkim-signature;
        bh=Afux0x8s3w6LnRdZF5CB+buDJph7bcYvMYUs5ZuJ518=;
        b=bvDtkR4j+bGjPunCj5RbLAKq6vNS3NpCFz2esnZCkojmixETkAUIvnUK8siD2H6aLW
         QU/uO49gHS4JGfptToNOTOxFpZnnWXkjvvkMESo19AtvAcItGs2Ai9bZAwXw8/PU3Lyy
         SV8g7Dh6wuclXMsnjndOEVC1UyM/CP/09wLtD359UYLsVXntJnL4FXauitK3md9qA87F
         yOrtKnNUAq4ZgYZVix7db8KSy2MLYwj3tgr+872fx7oYtPC+uirIUxj0WfyIJW8sSBKT
         gtNnGjyK9vt9W92LPVRYHaCA79qthx5we3pZwbvN+i34IMo1yW8iUC6MeI61cTkn1DIU
         hXYw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@hotmail.com header.s=selector1 header.b=Ahzvicov;
       arc=pass (i=1);
       spf=pass (google.com: domain of miran20089@hotmail.com designates 40.92.67.32 as permitted sender) smtp.mailfrom=miran20089@hotmail.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=hotmail.com
Received: from EUR02-AM5-obe.outbound.protection.outlook.com (mail-oln040092067032.outbound.protection.outlook.com. [40.92.67.32])
        by gmr-mx.google.com with ESMTPS id f11si780315wrp.3.2019.10.05.16.52.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-SHA bits=128/128);
        Sat, 05 Oct 2019 16:52:30 -0700 (PDT)
Received-SPF: pass (google.com: domain of miran20089@hotmail.com designates 40.92.67.32 as permitted sender) client-ip=40.92.67.32;
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=lulbNBgIO45uJdTtLBuWhL8knR7SwYIyy24H5CRQ2T6ojXsUBq5nXjJEVgbHnFsTODnhi830tujlYm78HvzhG10xANi4ST6/mHvTUMiTTMHtReuuJgCt6BKw5moKn5Y70zSVbLdJcvEUK4eAAjKJbBUCdq134Dn8v2/w/abp1xQy5dXo1V+foJXAMEI5vwc7s+0dfInfOj8jy0uKhPTOBm3eYoSWzy6Jdu+0QCiZxHD+XLydcW45vZmkcy7wy7bXsVyEKV2w82GmP6PP5AghYFy5M/rDJntQXNpcP/GUx7tivC9Ru39vqYkHTw9FD8BOndu5YhArzg8ZvpXY2gaXTQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-SenderADCheck;
 bh=Afux0x8s3w6LnRdZF5CB+buDJph7bcYvMYUs5ZuJ518=;
 b=GkbQ6AHwlwizQAp8u0NPmcWTauJy3k6DHNS0MDfyOuNgQK6wDh82DCq6MRc74HfyD49zqf6mVQDDEPvKr0jjnjySMT+88EUVZ0pZyN0sNrH4P0FqAIiV8D1+UGz4ZKIjTdt3cDc9hxUoCAMN0J/bU+4hF3YVC+8vhBem0cSMSc1oEPpSTpRTX6J8N8mA6zIp7Dq+UR0OWP6JosEgT4pNOC08wIVJEqP43z6lCMad9nIi7PTm9fWD2rL6lIatd/o07/RdmMVltoV5xu/WEYumwYgbd+Albx93KA478LWZaJ2nYITL1O+fwaK43xnZM70EhW5WWQZ5rwahWcLzkwrI2A==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=none; dmarc=none;
 dkim=none; arc=none
Received: from HE1EUR02FT024.eop-EUR02.prod.protection.outlook.com
 (10.152.10.57) by HE1EUR02HT060.eop-EUR02.prod.protection.outlook.com
 (10.152.11.252) with Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384) id 15.20.2327.20; Sat, 5 Oct
 2019 23:52:29 +0000
Received: from AM6PR07MB3894.eurprd07.prod.outlook.com (10.152.10.55) by
 HE1EUR02FT024.mail.protection.outlook.com (10.152.10.181) with Microsoft SMTP
 Server (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.20.2327.20 via Frontend Transport; Sat, 5 Oct 2019 23:52:28 +0000
Received: from AM6PR07MB3894.eurprd07.prod.outlook.com
 ([fe80::693f:fc5d:b08f:f4fc]) by AM6PR07MB3894.eurprd07.prod.outlook.com
 ([fe80::693f:fc5d:b08f:f4fc%7]) with mapi id 15.20.2305.023; Sat, 5 Oct 2019
 23:52:28 +0000
From: Miran Posser <miran20089@hotmail.com>
Subject: Hello
Thread-Topic: Hello
Thread-Index: AQHVe9dbz2QtCBCpt06enMdfCYbInA==
Date: Sat, 5 Oct 2019 23:52:28 +0000
Message-ID: <AM6PR07MB38943EC002ACAF95FCA5910E85990@AM6PR07MB3894.eurprd07.prod.outlook.com>
Accept-Language: en-US
Content-Language: en-US
X-MS-Has-Attach: 
X-MS-TNEF-Correlator: 
x-incomingtopheadermarker: OriginalChecksum:060B6ABBBC5D035CD8D3A02644361D200CE8EFC2EF23952228D58BBAABE9200B;UpperCasedChecksum:114BB859A7CC9D4F85F93056390A50F2EACE3DE119480AC5A1DC85278E0DD227;SizeAsReceived:7552;Count:40
x-tmn: [FcnZFcltqnhCyanukoVo+VT7An4ceEm/]
x-ms-publictraffictype: Email
x-incomingheadercount: 40
x-eopattributedmessage: 0
x-ms-traffictypediagnostic: HE1EUR02HT060:
x-microsoft-antispam: BCL:0;
x-microsoft-antispam-message-info: XCv8zegljCB4dmlK/AVcBCdB3XsEGrkXv6Wvf+WJTNwJ7HTcBIJBSDGf26oJUpFQO1KcSZURDOewddLTfnFbJn6I8auy1wfr8GdhEvmVpg2urCYBl8cHdnW6vnxpCCjO8FdlGSjrNQJu9g6bViyRbqaoC8NNIkF5J3yFU6A5Iqo0g+qh4fYha9qgYrUicaO+
x-ms-exchange-transport-forked: True
Content-Type: multipart/alternative;
	boundary="_000_AM6PR07MB38943EC002ACAF95FCA5910E85990AM6PR07MB3894eurp_"
MIME-Version: 1.0
X-OriginatorOrg: hotmail.com
X-MS-Exchange-CrossTenant-RMS-PersistedConsumerOrg: 00000000-0000-0000-0000-000000000000
X-MS-Exchange-CrossTenant-Network-Message-Id: cef6116b-2641-4b58-357b-08d749ef14b7
X-MS-Exchange-CrossTenant-rms-persistedconsumerorg: 00000000-0000-0000-0000-000000000000
X-MS-Exchange-CrossTenant-originalarrivaltime: 05 Oct 2019 23:52:28.9287
 (UTC)
X-MS-Exchange-CrossTenant-fromentityheader: Internet
X-MS-Exchange-CrossTenant-id: 84df9e7f-e9f6-40af-b435-aaaaaaaaaaaa
X-MS-Exchange-Transport-CrossTenantHeadersStamped: HE1EUR02HT060
X-Original-Sender: miran20089@hotmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@hotmail.com header.s=selector1 header.b=Ahzvicov;       arc=pass
 (i=1);       spf=pass (google.com: domain of miran20089@hotmail.com
 designates 40.92.67.32 as permitted sender) smtp.mailfrom=miran20089@hotmail.com;
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

--_000_AM6PR07MB38943EC002ACAF95FCA5910E85990AM6PR07MB3894eurp_
Content-Type: text/plain; charset="UTF-8"

Hello , i will be very happy to have a steady communication with you.
To make this successful, do communicate me to this address.
Thanks i am waiting to hear from you soonest

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/AM6PR07MB38943EC002ACAF95FCA5910E85990%40AM6PR07MB3894.eurprd07.prod.outlook.com.

--_000_AM6PR07MB38943EC002ACAF95FCA5910E85990AM6PR07MB3894eurp_
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
<div style=3D"font-family: Calibri, Helvetica, sans-serif; font-size: 12pt;=
 color: rgb(0, 0, 0);">
<div style=3D"margin: 0px; font-size: 12pt; font-family: Calibri, Helvetica=
, sans-serif">
<span style=3D"margin: 0px; font-family: Calibri, Arial, Helvetica, sans-se=
rif; background-color: rgb(255, 255, 255); display: inline !important">Hell=
o , i will be very happy to have a steady communication with you.</span></d=
iv>
<div style=3D"margin: 0px; font-size: 12pt; font-family: Calibri, Helvetica=
, sans-serif">
<span style=3D"margin: 0px; font-family: Calibri, Arial, Helvetica, sans-se=
rif; background-color: rgb(255, 255, 255); display: inline !important">To m=
ake this successful, do communicate me to this address.</span></div>
<div style=3D"margin: 0px; font-size: 12pt; font-family: Calibri, Helvetica=
, sans-serif">
<span style=3D"margin: 0px; font-family: Calibri, Arial, Helvetica, sans-se=
rif; background-color: rgb(255, 255, 255); display: inline !important">Than=
ks i am waiting to hear from you soonest</span></div>
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
om/d/msgid/kasan-dev/AM6PR07MB38943EC002ACAF95FCA5910E85990%40AM6PR07MB3894=
.eurprd07.prod.outlook.com?utm_medium=3Demail&utm_source=3Dfooter">https://=
groups.google.com/d/msgid/kasan-dev/AM6PR07MB38943EC002ACAF95FCA5910E85990%=
40AM6PR07MB3894.eurprd07.prod.outlook.com</a>.<br />

--_000_AM6PR07MB38943EC002ACAF95FCA5910E85990AM6PR07MB3894eurp_--
