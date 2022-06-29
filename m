Return-Path: <kasan-dev+bncBDLKPY4HVQKBB7MK6CKQMGQEIWH2TWY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33c.google.com (mail-wm1-x33c.google.com [IPv6:2a00:1450:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id BB80455F99E
	for <lists+kasan-dev@lfdr.de>; Wed, 29 Jun 2022 09:55:41 +0200 (CEST)
Received: by mail-wm1-x33c.google.com with SMTP id c185-20020a1c35c2000000b0039db3e56c39sf10145745wma.5
        for <lists+kasan-dev@lfdr.de>; Wed, 29 Jun 2022 00:55:41 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1656489341; cv=pass;
        d=google.com; s=arc-20160816;
        b=IIrrgTAnDsTefbi0DGsNWcVD3p8SJ/OYvgXcQHmOrEopC98nL+oiG2wk8YKFnS3/Mn
         xu0CujYJLa6fHxsIM2Z4fg/CV5qdrykHebWGWyahixr/yVodRO0iV0SuJ5RPhHYPq8/w
         HUN11mgOryAZnevItRPirKkm1iOxwj/BL9G17EkXBRW/UPIsd1zLrEfgHag5DUUrOHZ7
         evACMAYYWmQVIeaYVbG4VegaAUN4wLdg1mTo9T+cAAxNGdR3OyTMUmGZsJxvYgfUZBpf
         3qTaZjyNq2bY4mWm0ARR0CuPvFu+40WcFGiN74jBj6MA3u7HhcVvwQp3C+SWwFYPADyt
         lMJg==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version
         :content-transfer-encoding:content-id:user-agent:content-language
         :accept-language:in-reply-to:references:message-id:date:thread-index
         :thread-topic:subject:cc:to:from:sender:dkim-signature;
        bh=d0GTuvM7WuvHoG9KB6Rpu0Yts/Eao6+mf9cL193PcyQ=;
        b=nydV5NKxwXsHGRLJRFhsb/9LuEE5u1Efr9bIvBqeEipb92Yb68uJgLNmZRAZyg/zHL
         gcqs5gx1peFeTws1Cxmxp02tveec9a2Y3riLb8fM4q3qX0O70pU1H5EiP2mgRidpIMK6
         qCfT9XNOARSyUGfB4+g22nAEYnk3h4w1s2C+29UrnEF+/1QuVAik0lblZmKUf0MN/uxQ
         L0LKaLTzyBXkjpcPH+3X2EGSUTO13JFIYkHJTfVPwjd5EKGClofWOGp9+3L9iKRkAEuP
         D6uElpWOQSQoLQamh6Zn+qT1lui2urWA3x0JuxIqSIflGV2+X7m30V4wKprhlqqz0kyz
         bIRg==
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@csgroup.eu header.s=selector1 header.b="B6GdPV/k";
       arc=pass (i=1 spf=pass spfdomain=csgroup.eu dkim=pass dkdomain=csgroup.eu dmarc=pass fromdomain=csgroup.eu);
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates 40.107.9.73 as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:thread-topic:thread-index:date:message-id
         :references:in-reply-to:accept-language:content-language:user-agent
         :content-id:content-transfer-encoding:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=d0GTuvM7WuvHoG9KB6Rpu0Yts/Eao6+mf9cL193PcyQ=;
        b=HHzsKzv1VbUvTlrkav5gFbLJC4Xm5/69BOTTw9qJg3YYbNYxHt8j4YOxI8tS4ErmCn
         9UoTCFyD4jL+GWIY/Dz1RbBdyOddkxvow53oKH2rSh/XjzLGnk7zQX32VbIuUDaIODHU
         q324xZ+rgSLEGogoBL/pji23sv4pdOp79oLAHw7xb3Gm0tfwJR9CABFMI0QgNnxGKWnn
         8anr1uspqv4y4eUZvS1L7d2OdsZehCLwmLBzysSLfylIP97vdLqQbbCESKRWfooTPxSx
         xb4giFlV3O9YWuHv6xAyfOU3TY1YjoUk033YBPI6sjFu9qP/whkOHpIj0zSmIrwKm6Z1
         dO8Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:thread-topic
         :thread-index:date:message-id:references:in-reply-to:accept-language
         :content-language:user-agent:content-id:content-transfer-encoding
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=d0GTuvM7WuvHoG9KB6Rpu0Yts/Eao6+mf9cL193PcyQ=;
        b=w8dYiFv9FJB0SI+r4umHldvKnOnqwiMDFl75XbCBIYCq3M1wpoWvDIH0c59OWAolOj
         LRhjDMfAQakCkvDvHdnGB8fPGMuZ/6mGC0cdfo/TEWb/AT0g0UlKo1b6aygXpuftdvdM
         hZ9YVPv40JQSCvSol/gYwDdIAeXhRgVBNf/DVfGNyFhs4UitArqxs54+RbOKWjB6rK2o
         6hKW8xxgglamJ+12eI0ltz6RLG0+wNPxYYO2jMfkfduXA1iY3kJ4cT7UYJQn6eJYicZ/
         yHbo0iW7uzfJthzP4udtjk44uqZ8A+F1dURQ6COHxhMronfiEIs6fXADrfDm88WJgkfv
         DhKg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AJIora9RwqIB581u+dZQEnOSmpq7JJ7/LMy/dV6sw/b/jX3UWm3bGnKa
	C/9MZPNYyF98HiE9F4mXP7w=
X-Google-Smtp-Source: AGRyM1vgvi2MPxgAbX+1nxaaBDFTOW1XIWrpAnV5gIQawnAkK70JdRr6atwECdOFdHWB1Q08vmHt+A==
X-Received: by 2002:a05:6000:1683:b0:21b:93b0:898f with SMTP id y3-20020a056000168300b0021b93b0898fmr1704425wrd.662.1656489341310;
        Wed, 29 Jun 2022 00:55:41 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:34c6:b0:3a0:4f27:977f with SMTP id
 d6-20020a05600c34c600b003a04f27977fls1186362wmq.2.gmail; Wed, 29 Jun 2022
 00:55:40 -0700 (PDT)
X-Received: by 2002:a7b:c20d:0:b0:3a0:39e4:19e8 with SMTP id x13-20020a7bc20d000000b003a039e419e8mr4094571wmi.166.1656489340330;
        Wed, 29 Jun 2022 00:55:40 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1656489340; cv=pass;
        d=google.com; s=arc-20160816;
        b=U7KgzzWL3u6HR8kDKrdOrRiBlz4CE2fjdcxYPmQq932LTble15SBIXIzuuBjMANZss
         wbGvim+RBFBnyPUcnMJpFf67h+qOQ+JTBmTlWRQojJWvtjViZeF6GYy7AeqyxmOsCRiT
         WBUbY0b6EWFTKqpLR7shlsl/iJq+U+y65o24sK7NpBcNiAn5wUw7uZ7l6z2HwrMvGY6z
         1e24oi1qi1Fi0t29nounOUXWnQkqQiblNlYi5uAd6/OEXekTSZQSaPtFs1OjBeGwVWWP
         pAhwdNBn0MxtfwPVudluuMnPqARMuPHdZ4/gk7Fvh7AI7COFLW0S83/6emOEmy8uqlsC
         lq5Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-transfer-encoding:content-id:user-agent
         :content-language:accept-language:in-reply-to:references:message-id
         :date:thread-index:thread-topic:subject:cc:to:from:dkim-signature;
        bh=SiZWd74AOsn2ljeL5I4/vl9Bsa5oSL1qa4Ot50Pwl9I=;
        b=UnchPHoFjL7kNiBp6C5xgYAj3FfhzUij7mdO1SoE9vVDXol+5jeQ8z9tVBxiL3ArO6
         7Qp1WBpts7wjSrUvYzBFHWcHPNkPFCwJNwOuSZ0VjxV9YnmRjFd7xoFMtClmQZ+QAuM1
         ur8N5yVkOHXVKVjgypbXYTnqN2Z0GjY+U80VXTsvKfqSO4Otvk4o1R4ZvmjPffv2tj0Y
         ncCnHue8J1losk3Zag/7xdG9MguiICX2NV+aXzzgkaOn7csCqGMdaTd757kKwsf2tepY
         nV7yL2LG4jJ+rxyc+wyCMJFxr41An0G9Yf4w0eYWrJN5aHtTXl0yyqlbdLhzSI1pNeg0
         kTLw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@csgroup.eu header.s=selector1 header.b="B6GdPV/k";
       arc=pass (i=1 spf=pass spfdomain=csgroup.eu dkim=pass dkdomain=csgroup.eu dmarc=pass fromdomain=csgroup.eu);
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates 40.107.9.73 as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu
Received: from FRA01-MR2-obe.outbound.protection.outlook.com (mail-eopbgr90073.outbound.protection.outlook.com. [40.107.9.73])
        by gmr-mx.google.com with ESMTPS id m7-20020adffa07000000b0021a07a20517si530034wrr.7.2022.06.29.00.55.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 29 Jun 2022 00:55:40 -0700 (PDT)
Received-SPF: pass (google.com: domain of christophe.leroy@csgroup.eu designates 40.107.9.73 as permitted sender) client-ip=40.107.9.73;
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=ZGmPgwn0dfRTUbpxSxzAW31yflWGkYQTMUHL+mHscfZOv4cD5DcMjTsyAjaP5L4EUUXDybYpwvUqeEqVB6A8UNfkqEpwH3MX6d0XtlNHtSiPU3ZT5QdshH2FoRYw/YaeZgg+xKITEbKn1ro56ZH6ADm/mZSLNr/kwOvFJl3qf9VygHfnoY0IkJ4BxS2gNSfBwysp35LuHn3E8eOHroUNpJeZzYF3Wmw0qfVAkwHizcetpT5rraO7y7XsXSSFGbnOwmhBZuntkmuwClV/afiiQvPX9A0Ec5afM/Bz2eewEdqpR42vr1qJD26sttMOqYVqOOf20cLo7pd6AKUyLkNazA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=SiZWd74AOsn2ljeL5I4/vl9Bsa5oSL1qa4Ot50Pwl9I=;
 b=jJHiDYl6vlPoASrQak392AHepuEzgOUkOkgIYeVRO5z7sORcit1x2BcGYQ1Mk2TNKi2grkfbUBHbWgsdmPfqMZcvqCnIiGzz3+/FZUMyauUrJBwgIIfmL2CtXyRZcRgxUUa16ziYlshpd1anjx7Vu4SJYtQSgbNu4aQpsr6Vkt+t4OApvf7A4uTN1e7Y3auqnM80mxJhF9/9Bz0Bx5PErBBHEmm6Q/F1xjraIxAq+OKMdQxNKziS/l6F+YFz38fx3lVfqLfBYa2Hd2XkizN6Wtrk72l/moe7dS2JAo7x80LDnGYaZLaSCQdPntkiK0dcyT+dJYESlGlemri1y4Tl9g==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=csgroup.eu; dmarc=pass action=none header.from=csgroup.eu;
 dkim=pass header.d=csgroup.eu; arc=none
Received: from MRZP264MB2988.FRAP264.PROD.OUTLOOK.COM (2603:10a6:501:31::15)
 by MRZP264MB2426.FRAP264.PROD.OUTLOOK.COM (2603:10a6:501:7::24) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.5395.14; Wed, 29 Jun
 2022 07:55:38 +0000
Received: from MRZP264MB2988.FRAP264.PROD.OUTLOOK.COM
 ([fe80::e10e:bd98:2143:4d44]) by MRZP264MB2988.FRAP264.PROD.OUTLOOK.COM
 ([fe80::e10e:bd98:2143:4d44%3]) with mapi id 15.20.5373.022; Wed, 29 Jun 2022
 07:55:38 +0000
From: Christophe Leroy <christophe.leroy@csgroup.eu>
To: =?utf-8?B?VXdlIEtsZWluZS1Lw7ZuaWc=?= <u.kleine-koenig@pengutronix.de>,
	Jeremy Kerr <jk@codeconstruct.com.au>
CC: "linux-fbdev@vger.kernel.org" <linux-fbdev@vger.kernel.org>, Greg
 Kroah-Hartman <gregkh@linuxfoundation.org>, "linux-iio@vger.kernel.org"
	<linux-iio@vger.kernel.org>, "dri-devel@lists.freedesktop.org"
	<dri-devel@lists.freedesktop.org>, "platform-driver-x86@vger.kernel.org"
	<platform-driver-x86@vger.kernel.org>, "linux-mtd@lists.infradead.org"
	<linux-mtd@lists.infradead.org>, "linux-i2c@vger.kernel.org"
	<linux-i2c@vger.kernel.org>, "linux-stm32@st-md-mailman.stormreply.com"
	<linux-stm32@st-md-mailman.stormreply.com>, "linux-rtc@vger.kernel.org"
	<linux-rtc@vger.kernel.org>, "chrome-platform@lists.linux.dev"
	<chrome-platform@lists.linux.dev>, "linux-staging@lists.linux.dev"
	<linux-staging@lists.linux.dev>, "kasan-dev@googlegroups.com"
	<kasan-dev@googlegroups.com>, Broadcom internal kernel review list
	<bcm-kernel-feedback-list@broadcom.com>, "linux-serial@vger.kernel.org"
	<linux-serial@vger.kernel.org>, "linux-input@vger.kernel.org"
	<linux-input@vger.kernel.org>, "linux-media@vger.kernel.org"
	<linux-media@vger.kernel.org>, "linux-pwm@vger.kernel.org"
	<linux-pwm@vger.kernel.org>, "linux-watchdog@vger.kernel.org"
	<linux-watchdog@vger.kernel.org>, "linux-pm@vger.kernel.org"
	<linux-pm@vger.kernel.org>, "acpi4asus-user@lists.sourceforge.net"
	<acpi4asus-user@lists.sourceforge.net>, "linux-gpio@vger.kernel.org"
	<linux-gpio@vger.kernel.org>, "linux-mediatek@lists.infradead.org"
	<linux-mediatek@lists.infradead.org>, "linux-rpi-kernel@lists.infradead.org"
	<linux-rpi-kernel@lists.infradead.org>,
	"openipmi-developer@lists.sourceforge.net"
	<openipmi-developer@lists.sourceforge.net>,
	"linux-arm-kernel@lists.infradead.org"
	<linux-arm-kernel@lists.infradead.org>, "linux-hwmon@vger.kernel.org"
	<linux-hwmon@vger.kernel.org>, Support Opensource
	<support.opensource@diasemi.com>, "netdev@vger.kernel.org"
	<netdev@vger.kernel.org>, Wolfram Sang <wsa@kernel.org>,
	"linux-crypto@vger.kernel.org" <linux-crypto@vger.kernel.org>, Pengutronix
 Kernel Team <kernel@pengutronix.de>, "patches@opensource.cirrus.com"
	<patches@opensource.cirrus.com>, "linux-integrity@vger.kernel.org"
	<linux-integrity@vger.kernel.org>, "linuxppc-dev@lists.ozlabs.org"
	<linuxppc-dev@lists.ozlabs.org>
Subject: Re: [PATCH 6/6] i2c: Make remove callback return void
Thread-Topic: [PATCH 6/6] i2c: Make remove callback return void
Thread-Index: AQHYivfzv66d74QuGEeH1kE1xo+T/61l9tkAgAAFWwCAAAkYgA==
Date: Wed, 29 Jun 2022 07:55:38 +0000
Message-ID: <5517f329-b6ba-efbd-ccab-3d5caa658b80@csgroup.eu>
References: <20220628140313.74984-1-u.kleine-koenig@pengutronix.de>
 <20220628140313.74984-7-u.kleine-koenig@pengutronix.de>
 <60cc6796236f23c028a9ae76dbe00d1917df82a5.camel@codeconstruct.com.au>
 <20220629072304.qazmloqdi5h5kdre@pengutronix.de>
In-Reply-To: <20220629072304.qazmloqdi5h5kdre@pengutronix.de>
Accept-Language: fr-FR, en-US
Content-Language: en-US
X-MS-Has-Attach: 
X-MS-TNEF-Correlator: 
user-agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101
 Thunderbird/91.10.0
x-ms-publictraffictype: Email
x-ms-office365-filtering-correlation-id: 846fb32b-6214-4099-d82e-08da59a4c1d0
x-ms-traffictypediagnostic: MRZP264MB2426:EE_
x-ms-exchange-senderadcheck: 1
x-ms-exchange-antispam-relay: 0
x-microsoft-antispam: BCL:0;
x-microsoft-antispam-message-info: CYomIx3nRK8MHvVOXFC46FqFYoYkf0bo/4h3Xkh9Q/zEx3vOhDgZ4cTm3BEjRMmtkQXvfxQ0QICVEnuVjNPfYX+EAm5xa0NkomLw7YuakKBsrjyUyfpuWuLZYPf0bHUOibAae716Ak0WNzG9ENkL2e1byLDGyP+HBIGTl0jL6XUqwTxIWvlOhEftjZZJMHrV2JWIb6cJEU58HycXD/rAb/MuIc0RQ89wGfOyWrWvWXiaGGedWX+f3R3RB4sjGn5mbRYpp0AkhnSQCfxccZ+/mXAPu1Om8Fa3N/fnfnIEuwnxZONOoM09FcsH5osILf6O7zPnmeazl5oXapgCqkbkVxcUt+nrqH1mTaD5+m+CNJ2kPOUmjnwE/TNTj3i4TNmoG/TQgaMaBvLShDQFmx87mtOIHmGZOn9MUL5s+zZn2+edT4C6ac4wrf2/li2YBGpl/rQ1kvqJwUmybFobso9lp14gb1cVisBaeRTT+mLc0DesSbqEVRXmac69TDbimKbh7Mxm3Sxt67Ty/oGO0ONlkyIKuawb4OBrD5Y3d4DjbfGTfuE+CEyQX6nup6VVdawF7JaBAdCX14tzoeEc3ul2n9DmVuWT6FjYwM4Uy9zevwNpaH1jtQAMJszRPoByTDpForTQR4pZKXlvZYrFVT3sW+ZAWeKK+YMqBVA4QBxXo5NAA0+9+gP5qfEuKq6Xt6zeFSc492B3XuTRDBijLpI9XDYdq7y5PL7qDLBifuBOE6mebafV0nGOaeMUtj67vgCTazq9OpTHlpU03MBeOWb+UVXD0PLvdyKbDbPTNtzKXKX1L9h44EJIAEUA+zC/lOYE/44v0R2q1FXEC7JgEP2vimbIS7DAbjk7UokWPkTZcqv7GDADALn60d3P96JesSu0N140vDdyP79s/lcWn+e5gQ==
x-forefront-antispam-report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:MRZP264MB2988.FRAP264.PROD.OUTLOOK.COM;PTR:;CAT:NONE;SFS:(13230016)(4636009)(396003)(366004)(136003)(346002)(39850400004)(376002)(6486002)(966005)(8676002)(2906002)(7416002)(7406005)(71200400001)(44832011)(5660300002)(478600001)(122000001)(38070700005)(110136005)(91956017)(31696002)(86362001)(316002)(54906003)(64756008)(66946007)(66446008)(8936002)(76116006)(4326008)(66556008)(66476007)(186003)(83380400001)(66574015)(26005)(6512007)(41300700001)(2616005)(6506007)(38100700002)(31686004)(36756003)(45980500001)(43740500002);DIR:OUT;SFP:1101;
x-ms-exchange-antispam-messagedata-chunkcount: 1
x-ms-exchange-antispam-messagedata-0: =?utf-8?B?cXJYTXlTcHk0UTNxalNEMlNPL3h1K2F1M3dNc2Y1cUVqV0sxbVgwSVZSNGZu?=
 =?utf-8?B?a2J1VWlLWEl2cStZSC9ZaTBXRHJXK2UyTTZoM0ZjWVRRN2tTVForSnA3Y1Zt?=
 =?utf-8?B?a1dwVzJ5VTVZdytoL3h4UHExaGgrbkkwQlQ0T2E3YWNOVUY3YkM1dW5kcDk5?=
 =?utf-8?B?blRDMHRGeU0rQ0JST1FIYnRQZVJ1NkdaYjNpOXVTNHp6NjVJUEo2YUlGRmlk?=
 =?utf-8?B?cU1NVEQzTjZWY09JWjBIUFl5d2JrNmtZRVRObGtKSzlWeno4aHZNY0UvQnI2?=
 =?utf-8?B?cTB0R0JqYTdNOFJYZXF5b3UvTXMrVTdFRUI4Ky9YT2p5VUxjZXJKekJBOHNx?=
 =?utf-8?B?bHdyWUhBNFo1RE56RUVSczVYUWxZUWZORGVrdTBON3ZjSzNYRFdOeG00UjV0?=
 =?utf-8?B?clVhK25yZHVBMTdpcHpiQTh4cUFQSE5vakhXL2tWU0xpUHRjZ0g2L2t3TURj?=
 =?utf-8?B?elB3Smp3bGl6L0drU0NUN1E0Yklad0V5VkxxMmFZbGpNTkdhb1plNnJrLzRO?=
 =?utf-8?B?SENQOWhYQSt1RXhUM3gyczZVaDFOR2ZGclF5RnpqbjRYR1hBclJzUXNsR0wr?=
 =?utf-8?B?ZHQ0V2EyRE1EZlBSRUxIQ1VuUEFnRmpOK21nWmRHZGJwejNUbUR6VW54TVJT?=
 =?utf-8?B?RWx6YjR1SEpDUXZCZjFnd0FDZndhV1dDMFRBd0NnTFhIVWpMTmo2bXNydWlG?=
 =?utf-8?B?M3dkVlQzQmJXNkh0SjJncVkzSit0Q0lQRkg5Q25tL082cWVSVy9QdldBK0RG?=
 =?utf-8?B?YVNoL3E0TDR2aGxxeVFlaGFocjUvWmdqWXFjQzA1eit1U0pNQkNpV2hjV1Nz?=
 =?utf-8?B?RDJxbnQvREZkNGNDeUhZZVhHbkNNQmV2YytzWkZEUEFhTndtbndQYURwaXFE?=
 =?utf-8?B?cVJ6bk8wdjFtNTVhMnVLcG83Rlo0QnJ3VWN0RzlOUmVQRG9XVEQ2NW0wdVh1?=
 =?utf-8?B?QjhxTmVoTlByMXMrOUJCN3gzd1NqTE1xSEtiNXIvVjFTdzdJbFIzOUwrbnBP?=
 =?utf-8?B?aWtIVndJMHJVaTUrTGxwRDUyQ2l0YU12d3lMeWVDYTEwTkFCN0VaQjlhNUN6?=
 =?utf-8?B?T2J6cG5sL0xrWkEyNTcvMnY3d05Bc20yWmFDcWtudzdmV0tmS1BDZUFrZEsr?=
 =?utf-8?B?d3FUMWlFVXJ3bUh5VWZOUS9yOWp6OGIxRkNBbkQvZnpzTnRtSURYNzAzMTN6?=
 =?utf-8?B?ZG5kaDMvTThYaStQZHRNV3JPeVBSSDRaVDVtNkU3Y1NwWHJjMmpzSHNzNHJl?=
 =?utf-8?B?Zlk2MklyNm9pSFhhY25FcVhlYndDRnBUblBkTVBCODd2NDNqWTJNTWFwT29X?=
 =?utf-8?B?KzZBVEdENzdVZUV1NklWV1Vhd3pnM05IUnZtUCtQMXFoa0F5dHA2TEswUEgy?=
 =?utf-8?B?ZkVubElpN3RWbXczR1ExNEt5V1d4YjRnNjJFS0FSYkNkK0hFQjlJaG0wT3NY?=
 =?utf-8?B?eC9DNERnK1dNblExb3paOERSMTUvOFNDM0xCTGhBSlFYY3phWjJrdC9MS1ow?=
 =?utf-8?B?bGVTQTJYcGFoVUxuUTJhRXBzZThHeFR0MFJvaGRZcVZvRlVZdUpYZStHYTFj?=
 =?utf-8?B?YWN6Q2M2My83ZmdUME1qTE42UGpKdWpRY05CbHdzOGVFK3dsaTVRNzFBSkQy?=
 =?utf-8?B?RW41cnp5ZUZETURlOHpscGo0a1ZlMlZYYUgways1dDZvR2R2UlNRdUhTc1JR?=
 =?utf-8?B?aFF1aVJRdjNjaWhBbmN0RFZiNHBHSzN4dUtzUXJjeGxNZnBRMXZ4N2FTMjln?=
 =?utf-8?B?c2M2Q0tNVUI0YnhCYXR4Zml2cDBoYkEreVFjbXNHOEE0WGZhMkNZRlU5b211?=
 =?utf-8?B?TVBMQmVCN3FSVGZxQ1E5b2ROOFNQQ0tMc1FUUmx2aU1qWVNoaHN5dG02SlZw?=
 =?utf-8?B?UWlPbGhPYmRqMHlRYm5YeEdZVk8vNkF6RVB2NVhzd2N3cm9Talo3M09CbEZW?=
 =?utf-8?B?clVXelZaT2xrTGF3YkMrQjJRYWpMVkkrTTFaQjFDOUkzNDRmRllRaU53TlVO?=
 =?utf-8?B?RXQ4UTU4ZHJORExrVEZKNjBoZDNGNnc2bWJtZlZDLzYrS040ZEpiRC9oOUtH?=
 =?utf-8?B?VjNRQko3MzlTZjhZT0xPTllvNUpaUnFxTTNiZW5ZR3BacTVmeU1odWwwM0NS?=
 =?utf-8?B?RlFiTE05b3Fqd3o5YTlyNXVLeHdZR25BVE9zOE11QXphNjRqWTF6V3RnVW1M?=
 =?utf-8?Q?u+Wy+mgQrCfCDZS1C1j43WI=3D?=
Content-Type: text/plain; charset="UTF-8"
Content-ID: <39828658DC65DC4C831FDA136BD44EB9@FRAP264.PROD.OUTLOOK.COM>
Content-Transfer-Encoding: quoted-printable
MIME-Version: 1.0
X-OriginatorOrg: csgroup.eu
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-AuthSource: MRZP264MB2988.FRAP264.PROD.OUTLOOK.COM
X-MS-Exchange-CrossTenant-Network-Message-Id: 846fb32b-6214-4099-d82e-08da59a4c1d0
X-MS-Exchange-CrossTenant-originalarrivaltime: 29 Jun 2022 07:55:38.7075
 (UTC)
X-MS-Exchange-CrossTenant-fromentityheader: Hosted
X-MS-Exchange-CrossTenant-id: 9914def7-b676-4fda-8815-5d49fb3b45c8
X-MS-Exchange-CrossTenant-mailboxtype: HOSTED
X-MS-Exchange-CrossTenant-userprincipalname: jWJw5Q3ejJJE6olRWuuRrdOPzCjdRptR0XegOyT8t8a3QdfUnesEWOYx/mHkRkwOXeYBol3k++f1J5K5J5cUoH+SRpzbNEynWupEewBpo9A=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: MRZP264MB2426
X-Original-Sender: christophe.leroy@csgroup.eu
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@csgroup.eu header.s=selector1 header.b="B6GdPV/k";       arc=pass
 (i=1 spf=pass spfdomain=csgroup.eu dkim=pass dkdomain=csgroup.eu dmarc=pass
 fromdomain=csgroup.eu);       spf=pass (google.com: domain of
 christophe.leroy@csgroup.eu designates 40.107.9.73 as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu
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



Le 29/06/2022 =C3=A0 09:23, Uwe Kleine-K=C3=B6nig a =C3=A9crit=C2=A0:
> Hello,
>=20
> [I dropped nearly all individuals from the Cc: list because various
> bounces reported to be unhappy about the long (logical) line.]

Good idea, even patchwork made a mess of it, see=20
https://patchwork.ozlabs.org/project/linuxppc-dev/patch/20220628140313.7498=
4-7-u.kleine-koenig@pengutronix.de/

>=20
> On Wed, Jun 29, 2022 at 03:03:54PM +0800, Jeremy Kerr wrote:
>> Looks good - just one minor change for the mctp-i2c driver, but only
>> worthwhile if you end up re-rolling this series for other reasons:
>>
>>> -static int mctp_i2c_remove(struct i2c_client *client)
>>> +static void mctp_i2c_remove(struct i2c_client *client)
>>>  =C2=A0{
>>>  =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct mctp_i2c_client=
 *mcli =3D i2c_get_clientdata(client);
>>>  =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct mctp_i2c_dev *m=
idev =3D NULL, *tmp =3D NULL;
>>> @@ -1000,7 +1000,6 @@ static int mctp_i2c_remove(struct i2c_client *cli=
ent)
>>>  =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0mctp_i2c_free_client(m=
cli);
>>>  =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0mutex_unlock(&driver_c=
lients_lock);
>>>  =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0/* Callers ignore retu=
rn code */
>>> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
>>>  =C2=A0}
>>
>> The comment there no longer makes much sense, I'd suggest removing that
>> too.
>=20
> Yeah, that was already pointed out to me in a private reply. It's
> already fixed in
>=20
> 	https://git.pengutronix.de/cgit/ukl/linux/log/?h=3Di2c-remove-void
>=20
>> Either way:
>>
>> Reviewed-by: Jeremy Kerr <jk@codeconstruct.com.au>
>=20
> Added to my tree, too.
>=20
> Thanks
> Uwe
>=20

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/5517f329-b6ba-efbd-ccab-3d5caa658b80%40csgroup.eu.
