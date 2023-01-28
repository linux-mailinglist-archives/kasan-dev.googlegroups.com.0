Return-Path: <kasan-dev+bncBDY7XDHKR4OBBIXQ2SPAMGQE23BHZWI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa3f.google.com (mail-vk1-xa3f.google.com [IPv6:2607:f8b0:4864:20::a3f])
	by mail.lfdr.de (Postfix) with ESMTPS id A886967F8DF
	for <lists+kasan-dev@lfdr.de>; Sat, 28 Jan 2023 15:58:43 +0100 (CET)
Received: by mail-vk1-xa3f.google.com with SMTP id w6-20020a1f9406000000b00388997b8d31sf2829477vkd.3
        for <lists+kasan-dev@lfdr.de>; Sat, 28 Jan 2023 06:58:43 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1674917922; cv=pass;
        d=google.com; s=arc-20160816;
        b=0IlIUeRjS9eivRgS+28aat2Ajoh8Aena5SkmlBEz3e5bkJiMrXfXp+mx5LlKjxBVrE
         hlskTqdc7QD1yn/oBmdQtc9x5inEFVDv/0OjLdy0CDtDMXGba6agbEwPcTxDGZHHmyuN
         WOiv/Etq/IOW0zqSUbT+Yb+mUSZIrV/V4nEMfOU9dgh1IQqXMViIkkOt/lN9A94ai6EM
         SSbFfdkElzrn8hvGsj2f0DVwDl7EIxHTnc06qoEWhlbgqedZCnXA23OUUH9Wl8Mf6yG4
         YYJnwkM0foHaKXkewqolMuDm+A477silUhUP8CwUuBLii905Tdbzc6MrIZXL/JaSZZRN
         Gi2A==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version
         :content-transfer-encoding:content-id:content-language
         :accept-language:in-reply-to:references:message-id:date:thread-index
         :thread-topic:subject:cc:to:from:dkim-signature;
        bh=1vrk30A+HYhQfbh8iid6UXYwAG818a4ffeWROeEEdOw=;
        b=r+bOKUL+vuFoPrZWL3f1UgN+fn1BN5cN2EcIHcaIwj2soxCGHpeNP/0y6qTOpxsorQ
         zm2dchNwm/3+4Zc7Ft4oH/Lo4Dm/H6A7LjbAw201qBawczmP82FMeMR58w472hdS5p+/
         iWPf9g50TO8NCyzK+ErkzzGLG2cGuR3W1R/fhNl2muzGGt2Vo3Tj9YsLy3J3vOQNt6xe
         sCtPUDtWObnOCyRyy8RzoyKw+uDhiySvM/sd/VxpwvFtZZjQkdiSWrzOwo6m4IkSzNUf
         W/n72icBYgf+h7XXT87dl8v5KNQRyh1GQzOHiGooYrN7mxAXQ6INqLWOohigLNrJ9+Lb
         VDJA==
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=UjBwyEed;
       dkim=pass header.i=@mediateko365.onmicrosoft.com header.s=selector2-mediateko365-onmicrosoft-com header.b="Z5cVS/lE";
       arc=pass (i=1 spf=pass spfdomain=mediatek.com dkim=pass dkdomain=mediatek.com dmarc=pass fromdomain=mediatek.com);
       spf=pass (google.com: domain of kuan-ying.lee@mediatek.com designates 60.244.123.138 as permitted sender) smtp.mailfrom=kuan-ying.lee@mediatek.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :content-transfer-encoding:content-id:content-language
         :accept-language:in-reply-to:references:message-id:date:thread-index
         :thread-topic:subject:cc:to:from:from:to:cc:subject:date:message-id
         :reply-to;
        bh=1vrk30A+HYhQfbh8iid6UXYwAG818a4ffeWROeEEdOw=;
        b=bLGa/6eP0AH6PJhd55HhO0ZsL+uBzmENqeGpSQY3ZZ02dweWv7AxlRki9YDzvBgCrP
         zGi8mTu2K6OJfOG2iWkVgv1b9xa9EWb1jAbFgVZ30e1eYpWDYkopZbZV7+A3jnJgLRrz
         oZ1RbcV9cdJ4CU8JM3VpU0I3abYUv8OFmJv4K03ZdpXl1dG4y3OBIoJcb96gv97Gplms
         Qf5ib4YGZMS7ffBLKFBUcZGgUESZzWf4iw3xRK6qQcbfEfjjdZtDEa8tlHThpCbvofP4
         GclF7jf0rI5DrV+lAcuWfIPlbU7z1t+W1QgWnpDpILHbFwZk9ljVFN0VR2N+kqm7HBwV
         J3IQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :content-transfer-encoding:content-id:content-language
         :accept-language:in-reply-to:references:message-id:date:thread-index
         :thread-topic:subject:cc:to:from:x-gm-message-state:from:to:cc
         :subject:date:message-id:reply-to;
        bh=1vrk30A+HYhQfbh8iid6UXYwAG818a4ffeWROeEEdOw=;
        b=6L3b+m3RNqoj0b59TB2EukoYjjIWSb4/KEKIROvpd3asenp5Zc7xYBUfY4VYColwIz
         sYSDWbayPTtzxWTopmc7v0mGUtQjwXv1kvVWFxTZJwZOGf/L5OMrV6tKZfJJpgWlQFMg
         zCHnmSBDmX5f2IhxjLEyp/UEcT2QUyxfg2Te69WwtFDyAaWEW9QJkqQUez+RakaiMw3L
         6q1otiRtKcRG87PeGuYT0aHJvm+RJca31VyO+A7Q3b/mPRwTJPBm59R2e02Ti2hmq3lk
         MBvGJOmmJly9w7zz9cP2xyKjBiQWRZXHf3EGnbV2XGzDKJqZf/cFs7Ycf79T9LM4biiD
         VYog==
X-Gm-Message-State: AFqh2krV58MZnwJl/dPgXvLrdHfyGAf9iFcODbG1WAQrFsu6nJyHHAxV
	cN4aBos/ixaq8gbRR8C3FkM=
X-Google-Smtp-Source: AMrXdXvpbH+DG0FCoaBQXjN5r2KQrQ07pbnzcocnnsupMz4sl7AZfyXkU3WMgRIcRSsJNFCy3e/BzA==
X-Received: by 2002:a1f:accc:0:b0:3e1:9e11:8654 with SMTP id v195-20020a1faccc000000b003e19e118654mr5796982vke.3.1674917922292;
        Sat, 28 Jan 2023 06:58:42 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1f:4350:0:b0:3b5:df37:23a6 with SMTP id q77-20020a1f4350000000b003b5df3723a6ls1320364vka.7.-pod-prod-gmail;
 Sat, 28 Jan 2023 06:58:41 -0800 (PST)
X-Received: by 2002:a1f:aad2:0:b0:3e8:a035:4861 with SMTP id t201-20020a1faad2000000b003e8a0354861mr4792287vke.9.1674917921574;
        Sat, 28 Jan 2023 06:58:41 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1674917921; cv=pass;
        d=google.com; s=arc-20160816;
        b=VadCaDcXansUqBB21WgA5lMCVJWuaF0ZByQvR1Wf3Pd8SnqXsAbYq0vnldC6lUKdw5
         KzmG5aH4g0MVtDQMNKDLLlgBF7QdraItDanuRUwixfxcWQ3l8DQRMFr/YLZlDejWp4cy
         LzHqwMvMUOD16INfDShbTp6VNrG2kX9bAp1yXqsEmPAfI2CWGg6uJ12Gf1kr+Or/IS0+
         sLqJsTq4r/JTeAP3ZVkZo3WQjx7Th+bRrBsrVl4qXpI76kP8IbBOtLueRwAUzlc1EeKE
         1sZaus9C0BxTP78x48ocqRMzd9xbLakNXT8SyN7xfDjTDBWTKMG51Tjl5c5nEzPXzLMR
         ZeoA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-transfer-encoding:content-id:content-language
         :accept-language:in-reply-to:references:message-id:date:thread-index
         :thread-topic:subject:cc:to:from:dkim-signature:dkim-signature;
        bh=8v/cCGgYZRfzG3Te+rmSI/vigoxlLGgcK744xQ9doDU=;
        b=iX52EEGasiT/RZg+HJSD2bsBFvT7+4teoykr598UvF15D4oCmjDE1x06zVsOZAOxRB
         L+oeGw/aeiHkeP2tBbXj+FqJoi2v8uzFGlVqDWPofovCgK1DAtN0jdtuLfaaUOIIPSwp
         Lqvy7jkkY4onTkmVvEgtFFnDLRDUbIn2uyvaiGh+AAOnJO2fac2CpA8YZK2bfzxhDVtW
         1kDUUBVEQYBY+5r/yBc1eHSraPPVnGiSooS22Bl7+yxPIUVhS09BMWPisfp+BCIZxlgG
         /vMkxDy1LWP3bmIVmw9BcL0rAzh+JbAEiCYgmY59XcJfgUgWphSzvEEDQvnUJKGvstyB
         6DiA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=UjBwyEed;
       dkim=pass header.i=@mediateko365.onmicrosoft.com header.s=selector2-mediateko365-onmicrosoft-com header.b="Z5cVS/lE";
       arc=pass (i=1 spf=pass spfdomain=mediatek.com dkim=pass dkdomain=mediatek.com dmarc=pass fromdomain=mediatek.com);
       spf=pass (google.com: domain of kuan-ying.lee@mediatek.com designates 60.244.123.138 as permitted sender) smtp.mailfrom=kuan-ying.lee@mediatek.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=mediatek.com
Received: from mailgw01.mediatek.com ([60.244.123.138])
        by gmr-mx.google.com with ESMTPS id u27-20020ac5c93b000000b003e7cdc9f219si517955vkl.2.2023.01.28.06.58.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sat, 28 Jan 2023 06:58:40 -0800 (PST)
Received-SPF: pass (google.com: domain of kuan-ying.lee@mediatek.com designates 60.244.123.138 as permitted sender) client-ip=60.244.123.138;
X-UUID: 3c3351f89f1c11eda06fc9ecc4dadd91-20230128
X-CID-P-RULE: Release_Ham
X-CID-O-INFO: VERSION:1.1.18,REQID:ebb9be83-895d-4b5c-ba85-388c680c7dbf,IP:0,U
	RL:0,TC:0,Content:0,EDM:0,RT:0,SF:0,FILE:0,BULK:0,RULE:Release_Ham,ACTION:
	release,TS:0
X-CID-META: VersionHash:3ca2d6b,CLOUDID:e0ccc5f6-ff42-4fb0-b929-626456a83c14,B
	ulkID:nil,BulkQuantity:0,Recheck:0,SF:102,TC:nil,Content:0,EDM:-3,IP:nil,U
	RL:1,File:nil,Bulk:nil,QS:nil,BEC:nil,COL:0,OSI:0,OSA:0
X-CID-BVR: 0,NGT
X-UUID: 3c3351f89f1c11eda06fc9ecc4dadd91-20230128
Received: from mtkmbs11n2.mediatek.inc [(172.21.101.187)] by mailgw01.mediatek.com
	(envelope-from <kuan-ying.lee@mediatek.com>)
	(Generic MTA with TLSv1.2 ECDHE-RSA-AES256-GCM-SHA384 256/256)
	with ESMTP id 1298309249; Sat, 28 Jan 2023 22:58:33 +0800
Received: from mtkmbs10n2.mediatek.inc (172.21.101.183) by
 mtkmbs13n1.mediatek.inc (172.21.101.193) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.2.792.15; Sat, 28 Jan 2023 22:58:32 +0800
Received: from APC01-SG2-obe.outbound.protection.outlook.com (172.21.101.239)
 by mtkmbs10n2.mediatek.inc (172.21.101.183) with Microsoft SMTP Server id
 15.2.792.3 via Frontend Transport; Sat, 28 Jan 2023 22:58:32 +0800
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=KXFxJf3WAQQqgIqdE+Ofiw9Za5MwVHEZQHNJHqnZ9eWQwQnGUuQfc/O9VqB0er4xFN4h7r6/sXjT7R/RABUcqQjU0pND6RG/ztyGDw+xmuUncv8n8BvtO+ojvNqkRF3yA1pHQKzVqyPpeS4QGsJVGIbHuNoKY+dZrgaRhOflbXpbIYUKpzNY197+tTfmRWuQJuoantjvNbY/SLCSDKphRi2GjbTObuXBK4rrmBRKAWUG33Vzq8B7ZEM5xANy0OS4pUZrOrvuKttvDDHZVHZFnEXyy78deCvpQzGrTawxPT1CjPVtOmtPE6Y7M9C9Oli/iecYZsvua5ha2L3GvrrRPA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=8v/cCGgYZRfzG3Te+rmSI/vigoxlLGgcK744xQ9doDU=;
 b=jGCZcPAmUj/kpW+E9xNPXEDd1neAi6+X8z89EKJRO0jZ338LKU/IGqsMWxBIMT8CESMwLZnqxGqT3A9EnGsA12Roko6sd/kBz9rbkC586mhwEIxsumi7CeswdOVP0oUP1LelurCvyWlVPWo/E1Px8+NIdkroArBbu3KoO7zeUZKwei6XipXyaQlqg27fpLluaL90RF6Fcq6gV3GbdXYANdkVoOLMs+pbBycu5Xh3VvibeVyVcIxlUbNmSGQjUA+Oh3b8ACEnzgxkJbCAsNcg3OqIkAnT6QLzOyERsbbZtptAQjbmBgPBjo6I+hIgRCaD2F2okPM6MDrLel2gzgbjHQ==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=mediatek.com; dmarc=pass action=none header.from=mediatek.com;
 dkim=pass header.d=mediatek.com; arc=none
Received: from PUZPR03MB5964.apcprd03.prod.outlook.com (2603:1096:301:b4::11)
 by SI2PR03MB5529.apcprd03.prod.outlook.com (2603:1096:4:128::10) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.6043.25; Sat, 28 Jan
 2023 14:58:30 +0000
Received: from PUZPR03MB5964.apcprd03.prod.outlook.com
 ([fe80::c43a:ce45:4a27:bd80]) by PUZPR03MB5964.apcprd03.prod.outlook.com
 ([fe80::c43a:ce45:4a27:bd80%7]) with mapi id 15.20.6043.030; Sat, 28 Jan 2023
 14:58:30 +0000
From: =?UTF-8?B?J0t1YW4tWWluZyBMZWUgKOadjuWGoOepjiknIHZpYSBrYXNhbi1kZXY=?= <kasan-dev@googlegroups.com>
To: "andreyknvl@gmail.com" <andreyknvl@gmail.com>
CC: "linux-kernel@vger.kernel.org" <linux-kernel@vger.kernel.org>,
	"linux-mediatek@lists.infradead.org" <linux-mediatek@lists.infradead.org>,
	=?utf-8?B?UXVuLXdlaSBMaW4gKOael+e+pOW0tCk=?= <Qun-wei.Lin@mediatek.com>,
	"linux-mm@kvack.org" <linux-mm@kvack.org>,
	=?utf-8?B?Q2hpbndlbiBDaGFuZyAo5by16Yym5paHKQ==?=
	<chinwen.chang@mediatek.com>, "dvyukov@google.com" <dvyukov@google.com>,
	"kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>,
	"akpm@linux-foundation.org" <akpm@linux-foundation.org>,
	"ryabinin.a.a@gmail.com" <ryabinin.a.a@gmail.com>,
	"linux-arm-kernel@lists.infradead.org"
	<linux-arm-kernel@lists.infradead.org>, "vincenzo.frascino@arm.com"
	<vincenzo.frascino@arm.com>, "glider@google.com" <glider@google.com>,
	"matthias.bgg@gmail.com" <matthias.bgg@gmail.com>
Subject: Re: [PATCH v2] kasan: infer the requested size by scanning shadow
 memory
Thread-Topic: [PATCH v2] kasan: infer the requested size by scanning shadow
 memory
Thread-Index: AQHZKyCyrTNFvvt7mEemldTI9O5rMa6skisAgAdpiYA=
Date: Sat, 28 Jan 2023 14:58:30 +0000
Message-ID: <414630a65853f18c450cf1451e013b749382cbac.camel@mediatek.com>
References: <20230118093832.1945-1-Kuan-Ying.Lee@mediatek.com>
	 <CA+fCnZcS-p5nCALg4-96cp+sXNZSvN_u=L+=xK+zaH2rigJMKw@mail.gmail.com>
In-Reply-To: <CA+fCnZcS-p5nCALg4-96cp+sXNZSvN_u=L+=xK+zaH2rigJMKw@mail.gmail.com>
Accept-Language: zh-TW, en-US
Content-Language: en-US
X-MS-Has-Attach: 
X-MS-TNEF-Correlator: 
x-mailer: Evolution 3.28.5-0ubuntu0.18.04.2
x-ms-publictraffictype: Email
x-ms-traffictypediagnostic: PUZPR03MB5964:EE_|SI2PR03MB5529:EE_
x-ms-office365-filtering-correlation-id: 73102858-5023-48d8-e494-08db01401e52
x-ms-exchange-senderadcheck: 1
x-ms-exchange-antispam-relay: 0
x-microsoft-antispam: BCL:0;
x-microsoft-antispam-message-info: baR8vdz3Nl4InlnehFNohhMpKzjcX8JcII52vbmuP2e+KSQ5WgMDaA8x+noGk9Po5iS7eOWfTV5XxPzwl9o0zXTQUWD/TqzI4KQ8uv8TrIG/fBezBOS0Nb+JZnI2CDEXs+/fVkGc6D4bxFTm7WXcX8Ex5heD2EJd37ZQxaQRYT73Ez68ba7fJEpFkye9k/7SInlMFr7NDXGZWP3SGe3sbEPHMrH2MxD+muTM0WQgFqzSas8o/1ECjvqYJCo7aBZaK7xawiUyTXIcQeGecks/BLrOw6mqSb3yJDl+ItMBqTFMldPaMEjDQlftcFDCqAHZxgbovggtEMhX8/6nn792YZ/2ht3HogB6It0W5xRn3ABI7IjA0cE1qIPEilmb3Wm6ImfjDpeLF+dqgCHHCF61xUfbodi/zT6Eja7hiv9e6H6OlR3BTHjcmPIqTWvvVu2CiLJoL/k/KWjpyNu0ltF9OslIhVmOVRC9+dIyli+VEnowrJM49nuXrJHhblo+7tLp8BR5joSp0fQPNHyD6xQICOMEAeKZnM/bwSqVUlelb2arhfQp8mcNlHz+ZhZSJK5BN2PCQlLlEp1KK9aZLRgmomI9bDizHSiT1XW3KJeuoOznaPxVx4W6RkphPbnBF4U5zoehA4rrhSkQifMNUOI02fySwnIrD2MgoaB0moxGRYEQGSYYIOygly5r2uU8qtigS0EHeIrrSX1v9yWJD7IMeKUXl/PQtRRlq3nTTuw/iuje0vx3xk4OfbDzFKoEopt1s5jha7zDDezj0m1fRiHwYjx7wCFUajG0Lito/9H19ZGfQWeiMEyaZL71foaXYQgkmYiXfnh6NdV0YgASk2d4cQ==
x-forefront-antispam-report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:PUZPR03MB5964.apcprd03.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230025)(4636009)(366004)(376002)(136003)(346002)(396003)(39860400002)(451199018)(36756003)(85182001)(86362001)(2906002)(54906003)(2616005)(186003)(26005)(4326008)(76116006)(53546011)(66446008)(6512007)(8676002)(66946007)(64756008)(66556008)(66476007)(6916009)(91956017)(71200400001)(6506007)(316002)(6486002)(966005)(478600001)(38100700002)(122000001)(5660300002)(38070700005)(8936002)(7416002)(41300700001)(83380400001)(99106002)(505234007);DIR:OUT;SFP:1102;
x-ms-exchange-antispam-messagedata-chunkcount: 1
x-ms-exchange-antispam-messagedata-0: =?utf-8?B?UU5ETlYrSHpYTFpBOGRoMXVmN0ZRUDlpSjRvRmZ4Tm9MTDlkZ2xKcm9hMWxn?=
 =?utf-8?B?SjVxMXR5bWV0a1ViTFRBNk9wN2tIaS9jM3U1NUU2eHpseXllaTVudkIrRFZp?=
 =?utf-8?B?ajRFRDVZTHZBNFdMRzQyODhMVm9LQk9GWis4UXVTRzNhQVpiM25TMW9KSkFP?=
 =?utf-8?B?VkorcmZINHhkTVh4NEtORDJuQWpUeW9GUHUyaDVkTDlETGFlS1hETTBMUGtn?=
 =?utf-8?B?K2NneEJrZ2w5TFhMMGFrYk84SndCNWx4SFQya1dXZTFvVnkyenlUckVLNDBq?=
 =?utf-8?B?UkdpY3JYdTI2blZyWmkxaWdCNG8wM0IvaE0wdHhJZE5HcGNhWjRNVi80cENm?=
 =?utf-8?B?SGEyNm0vdlVMY3ZySGo5VTI1ZE9QVHQwTStZQUhoNFRZMndKcnMyb3kzOHRq?=
 =?utf-8?B?eTdKZDltTWxVbTNIWHBDL2J4SzNONXJsZ29YWFV1bEtxMnBmZENWeDdJT1Fn?=
 =?utf-8?B?VVVWbm81NjhlWTB2aUQrcFdzSlc4Zk8vejlCVE1BaTdIMHF3ZDhYV1poTWRD?=
 =?utf-8?B?SUZwOElXVk1JRVJXS2pLSFg1QSt0MFY2S3hEQU1IMGZxT3RGd2VnazJGM1hG?=
 =?utf-8?B?djZkbm1WdWoxZS9EbGw1NzlDQktQZ1BzTHZqU1RlMEdyQ0ZDdmQwTmo3bjQ1?=
 =?utf-8?B?bXhLdUJXaUw5R3dQU2ZlaHZSdDBPVmkrd2xsRzBCeE0zMVIyK1ZRTTRGYi9o?=
 =?utf-8?B?Smt6Q0V1aDY3eHhxVWNkMENFSHBwSGJUT08yZkU5b21Uc0ZSeldlM1lnSGFq?=
 =?utf-8?B?c1ZiWEFzM041dVhGQUk0RWVRejFIcktaeWlmN0xWNHJrMGEzTmR2Q3M2YmRM?=
 =?utf-8?B?eThlT0dPalBtZ2p6d0RWQ0s1QzZFMGkwM2tlTzJOZ2NyQ0FibS90SjQ1c2JS?=
 =?utf-8?B?MHR6alJwTmsxam43Qk5mVUNPT3ZCS2dpcXRvcm1INTdRcy9JQjUyejRnZXNv?=
 =?utf-8?B?QzNGQnVzSjUyVGR0aXdTbGFWbzNTNjRMc2tIN29FbTBXMHVqVEtXVU1ZUzNK?=
 =?utf-8?B?bDlqckh3dGNVYm5VQXFCQU1lVFhxVFFISVlxdTErZGFQdlZGTUtUNzhLTGcx?=
 =?utf-8?B?b3prRjRvSDJ2N3luTU9abEludlo1OUxVRnoxOE55YTM1c05hYUJxVTFCaFd6?=
 =?utf-8?B?YmUwK3o3ejVIL2RBcUk0bVQ0b3R3Uk03b1ZvQ2Rod0d6VnJVRllBY0VkNDBk?=
 =?utf-8?B?L21taExlUEoxclYweXRJV3RQOXRkMHRsL1lRcC9vOUdGSXpMR3l0Y2lDdFlz?=
 =?utf-8?B?UU9rOWxQL2wyQ0xGYVVSL1Jka3c5QTIyWCtrbVZ1RXFEVG45VThiR0lUUDNs?=
 =?utf-8?B?bkJqZi9CRFZ6cXdidXI1N3EvWWJLZW0weS9hNFlBZWV3NW1FUnhwcXBWV0tw?=
 =?utf-8?B?Ym9DcTFGUkFFN09UYjN0ZnlSaWtHZXQyMS9uTDF3UjdKdGVCaGNGdklVY3lZ?=
 =?utf-8?B?ZHh6MWFHZDVNN09oT2FCUEl2RnRsL0ZsVE9ZS2lOZ0t4YTBIOG9BeTFCVldV?=
 =?utf-8?B?WFJoS1lqSCtCcTVhSXlwNm54V0lhbEZYYkRYc3A0N3pWbHk5RXIraFg3bFJT?=
 =?utf-8?B?Ujg2UDBxNlJVTkpWdnlBdlJ6Z3NZRS9zL3VReEtpcmJPTnFLU2JQaDJrUFJL?=
 =?utf-8?B?TytMYUZWQW5uWGQrS1hvNEJLT3RLdDJKZDVDK2tteTk3d0NNMWc3VW5HdUpJ?=
 =?utf-8?B?Z3JPTEV0U2d0MDdIaCtVVFNPdU1uelBIVU83dFljMzZDTlkwK2pwOEMrQkdG?=
 =?utf-8?B?RnZxcXBqUW9PN0txMHBuYlJuUVlpTytGUzN2S3FOK0ZiVWR2Tm5HdEI0SkRu?=
 =?utf-8?B?RXR2cWFMdC9JZk9KL01tcXVRU01GZXFvZExIaWdjeG1jbnMvR2dCTVFYdk1X?=
 =?utf-8?B?VlhEU2huV0IrU1A2cWZUWG9lc1VRb2lNYTc0Q2V6ZlFFSkNXanNGM1F0R3ov?=
 =?utf-8?B?R09iYXlIVXhkeGRybmwwbTdmdkZCMEhGM2NKYXhlWXRESzBwNSs1c29oRzlp?=
 =?utf-8?B?L0tNbGh4R0JKOVJuRXM2aUZ6cUZZVllFKzFZTVdIb3Z0bnQ5RXNXdnpieVla?=
 =?utf-8?B?bnFzdWNJbGZ0YXdXTXVZMU11NUhZWTVmaUNlUEUvSndRMUFGZ0tLTGJMVmNp?=
 =?utf-8?B?RytvMVBJR2owdkpEaTF0VU13RUMrV2Y5SnJxOWczK3dGZWhUbFljVWhhbklV?=
 =?utf-8?B?N0E9PQ==?=
Content-Type: text/plain; charset="UTF-8"
Content-ID: <E94C125E35F5E94E8193876607E24EA4@apcprd03.prod.outlook.com>
Content-Transfer-Encoding: quoted-printable
MIME-Version: 1.0
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-AuthSource: PUZPR03MB5964.apcprd03.prod.outlook.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 73102858-5023-48d8-e494-08db01401e52
X-MS-Exchange-CrossTenant-originalarrivaltime: 28 Jan 2023 14:58:30.0715
 (UTC)
X-MS-Exchange-CrossTenant-fromentityheader: Hosted
X-MS-Exchange-CrossTenant-id: a7687ede-7a6b-4ef6-bace-642f677fbe31
X-MS-Exchange-CrossTenant-mailboxtype: HOSTED
X-MS-Exchange-CrossTenant-userprincipalname: C0A6kjEvqWU9jaf5yPFj4gbH8FfkAMdSVpNBamtlhFzeSvalJwhHr1o0f8Driw5ntpRTMM653iuvXPoPEz2vMmEUVrKVNxaixcIQpzNUMdA=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: SI2PR03MB5529
X-MTK: N
X-Original-Sender: Kuan-Ying.Lee@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@mediatek.com header.s=dk header.b=UjBwyEed;       dkim=pass
 header.i=@mediateko365.onmicrosoft.com header.s=selector2-mediateko365-onmicrosoft-com
 header.b="Z5cVS/lE";       arc=pass (i=1 spf=pass spfdomain=mediatek.com
 dkim=pass dkdomain=mediatek.com dmarc=pass fromdomain=mediatek.com);
       spf=pass (google.com: domain of kuan-ying.lee@mediatek.com designates
 60.244.123.138 as permitted sender) smtp.mailfrom=kuan-ying.lee@mediatek.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=mediatek.com
X-Original-From: =?utf-8?B?S3Vhbi1ZaW5nIExlZSAo5p2O5Yag56mOKQ==?=
	<Kuan-Ying.Lee@mediatek.com>
Reply-To: =?utf-8?B?S3Vhbi1ZaW5nIExlZSAo5p2O5Yag56mOKQ==?=
	<Kuan-Ying.Lee@mediatek.com>
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

On Mon, 2023-01-23 at 22:46 +0100, Andrey Konovalov wrote:
> On Wed, Jan 18, 2023 at 10:39 AM Kuan-Ying Lee
> <Kuan-Ying.Lee@mediatek.com> wrote:
> >=20
> > We scan the shadow memory to infer the requested size instead of
> > printing cache->object_size directly.
> >=20
> > This patch will fix the confusing kasan slab-out-of-bounds
> > report like below. [1]
> > Report shows "cache kmalloc-192 of size 192", but user
> > actually kmalloc(184).
> >=20
> > =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
> > BUG: KASAN: slab-out-of-bounds in _find_next_bit+0x143/0x160
> > lib/find_bit.c:109
> > Read of size 8 at addr ffff8880175766b8 by task kworker/1:1/26
> > ...
> > The buggy address belongs to the object at ffff888017576600
> >  which belongs to the cache kmalloc-192 of size 192
> > The buggy address is located 184 bytes inside of
> >  192-byte region [ffff888017576600, ffff8880175766c0)
> > ...
> > Memory state around the buggy address:
> >  ffff888017576580: fb fb fb fb fb fb fb fb fc fc fc fc fc fc fc fc
> >  ffff888017576600: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
> > > ffff888017576680: 00 00 00 00 00 00 00 fc fc fc fc fc fc fc fc fc
> >=20
> >                                         ^
> >  ffff888017576700: fc fc fc fc fc fc fc fc fc fc fc fc fc fc fc fc
> >  ffff888017576780: fc fc fc fc fc fc fc fc fc fc fc fc fc fc fc fc
> > =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
> >=20
> > After this patch, slab-out-of-bounds report will show as below.
> > =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
> > ...
> > The buggy address belongs to the object at ffff888017576600
> >  which belongs to the cache kmalloc-192 of size 192
> > The buggy address is located 0 bytes right of
> >  allocated 184-byte region [ffff888017576600, ffff8880175766b8)
> > ...
> > =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
> >=20
> > Link:=20
> > https://urldefense.com/v3/__https://bugzilla.kernel.org/show_bug.cgi?id=
=3D216457__;!!CTRNKA9wMg0ARbw!iEOOICl7DzhvfYobmQ8MsNFAWmbqicXdjd0LYWw9uBOqw=
j8lai7oEODVdRJyWUEXr11A3-m7wbIX2cdpxLwiW6Tm$
> > $   [1]
> >=20
> > Signed-off-by: Kuan-Ying Lee <Kuan-Ying.Lee@mediatek.com>
> > ---
> > V1 -> V2:
> >  - Implement getting allocated size of object for tag-based kasan.
> >  - Refine the kasan report.
> >  - Check if it is slab-out-of-bounds report type.
> >  - Thanks for Andrey and Dmitry suggestion.
>=20
> Hi Kuan-Ying,
>=20
> I came up with a few more things to fix while testing your patch and
> decided to address them myself. Please check the v3 here:
>=20
>=20
https://urldefense.com/v3/__https://github.com/xairy/linux/commit/012a584a9=
f11ba08a6051b075f7fd0a0eb54c719__;!!CTRNKA9wMg0ARbw!iEOOICl7DzhvfYobmQ8MsNF=
AWmbqicXdjd0LYWw9uBOqwj8lai7oEODVdRJyWUEXr11A3-m7wbIX2cdpxNwCtfpJ$=C2=A0
> =20
>=20
> The significant changes are to print "freed" for a slab-use-after-
> free
> and only print the region state for the Generic mode (printing it for
> Tag-Based modes doesn't work properly atm, see the comment in the
> code). The rest is clean-ups and a few added comments. See the full
> list of changes in the commit message.
>=20
> Please check whether this v3 looks good to you, and then feel free to
> submit it.

It looks good to me.
I will send the v3.
Thank you.

> Thank you!

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/414630a65853f18c450cf1451e013b749382cbac.camel%40mediatek.com.
