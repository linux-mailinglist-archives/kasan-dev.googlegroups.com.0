Return-Path: <kasan-dev+bncBDY7XDHKR4OBBZ6DY6TQMGQESODKK4I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33c.google.com (mail-ot1-x33c.google.com [IPv6:2607:f8b0:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id 872D978FE0E
	for <lists+kasan-dev@lfdr.de>; Fri,  1 Sep 2023 15:06:49 +0200 (CEST)
Received: by mail-ot1-x33c.google.com with SMTP id 46e09a7af769-6bc7afd0498sf2100053a34.0
        for <lists+kasan-dev@lfdr.de>; Fri, 01 Sep 2023 06:06:49 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1693573608; cv=pass;
        d=google.com; s=arc-20160816;
        b=WE/pLL5VpNEifIgUXoVOU3YpnWFro8Dn1ZOOrtg1LqHbk98RjTC7bFoSCjPH0fJ4BQ
         WnUXbk3mJz7HoHRYUdyB+ve2dLqSsqLNrTh+IYN18APUv+n5x4j5sy0DJCYcRudq9K4y
         kNl0nBVHhukLbu6oKsW5NMPmtBI9TNCHYCzWlYfXNtGloWcPXu7l+ewQwcMeGuhiYGwt
         pyz/bgIEfTmx6W/788jhdK84bF+ENh0KzFJ5p5OEvW4jWdwHh+lL4B+xbEmXHtYdsZE1
         jLNn16sVkuqcxf5zL34qeIIyhMdqA458MuwuCj8QDz3OqRApJIp0AEtCPu8WeZ7cBGiw
         9MOg==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:content-id
         :content-language:accept-language:in-reply-to:references:message-id
         :date:thread-index:thread-topic:subject:cc:to:from:dkim-signature;
        bh=o111CCw9ZN8sPXETCC3XleC68j1KP+TEUF+S+6Q7NR8=;
        fh=w0GGIxU+HXSP+M6hud+ASnPIID5mY1vD5hbUpeCSkCo=;
        b=e+I4bMzq0Qg7PNJhxeYgAWXihmxCDLuEvB36iDeW81pqBIv9xTj0GlNRVfpqS/6S8X
         5yq/dJvCPb9tNFshnRXA5INLe5mpLv0vq+7OswSpwLLOoB7wcRfhhl5LwrOOThbfuZYD
         1n39KwGqIN/TAfa1XjQ5Qryogy9tFXePAtCQMZmIDMFhYKsUnngccKalk8hv4+k6MDJH
         A+a5t0U8RmU6d3hQZyvm4lC9UdIrv/NxZPYWM2dvHNctgwesuqvl9C/3WxsFYRE4hR1I
         xaJfhkA/Nqw8p6H4ykO/2XpIaX2yMsi7ZbGC5QvWMQ88g/d2lpjjqF06eBeI513Tgwtk
         OVrQ==
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=ClwdAhc1;
       dkim=pass header.i=@mediateko365.onmicrosoft.com header.s=selector2-mediateko365-onmicrosoft-com header.b="jwy/7S8b";
       arc=pass (i=1 spf=pass spfdomain=mediatek.com dkim=pass dkdomain=mediatek.com dmarc=pass fromdomain=mediatek.com);
       spf=pass (google.com: domain of kuan-ying.lee@mediatek.com designates 60.244.123.138 as permitted sender) smtp.mailfrom=kuan-ying.lee@mediatek.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1693573608; x=1694178408; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :content-id:content-language:accept-language:in-reply-to:references
         :message-id:date:thread-index:thread-topic:subject:cc:to:from:from
         :to:cc:subject:date:message-id:reply-to;
        bh=o111CCw9ZN8sPXETCC3XleC68j1KP+TEUF+S+6Q7NR8=;
        b=vupsW6YyW9bK/kRdPJQBG/4UTTGEWqEy0B+IlfxWy7jgwjrqvX7mNz5jTKU1H0ey7k
         /Ivzu8ewuSUfkozpyJFP/VQOHkbSDWWyytWrW9Bu/gayf08z5T3SsVzvYR/FCVjMpsi9
         LRKVl1Dm1t0K2m+X+uu+mZlwAR0CsREyN4JBPCrvQCamhpyezfByvi/PtBJilWTd4Mhp
         8Gs4JY6IMGRDPlnCAXF/J1L9vaSXe8eGLZ29Q1v790L8ZerhQHfWjBPS9zmmObqgFBU8
         HxgoXm8/UUZBgb2nZ39yuXQGltHpfJUx8V/u9UTiyy8rnKTji/dEtawiJQ2dEHaTj72G
         OfUw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1693573608; x=1694178408;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :content-id:content-language:accept-language:in-reply-to:references
         :message-id:date:thread-index:thread-topic:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=o111CCw9ZN8sPXETCC3XleC68j1KP+TEUF+S+6Q7NR8=;
        b=IpKfSOpKNxLxGV34D0+WNE+sH3BTkaBP+vxxAoXhSLGmfxPYEvhGIqegQQsfkZPQbR
         7seq+bZa7xLd86NDjTKL+ovLq84caf5pHPWub5kb6jFHKQmJgCmtDl8V6FelFjfW8qrD
         +9gLhWQmPYrBgTw0nJqxXnLxfIsxl72mxG2ddOh2MmUXu749edIrsE3Q3gVlmPNMVox4
         sY41OqkZ7JAjrLQtoYgOrmy5jLhWL16LAmtJXMBA4/rf6Ke3fDhSlkghB/3aKpKZdUWH
         lXQo4DOPuxC4KQQ55BXEGhJttf2XJaXvR9PaUZEMLRHaacEVg+o3LRkSxZwGmlOd4TyP
         9lvQ==
X-Gm-Message-State: AOJu0YySH+S4YV+8jYj/3h9Eoth6G4GTirNlTqtbPuS1OGc2Dvj5cgNM
	9ZG188iJyJfGHd0crM/nQdk=
X-Google-Smtp-Source: AGHT+IFscFIE8lRqW9yv4jFRLo712vj6eWsLq3ZUAQYJ+apVbMMrBUFwRND1sa6nWqxgbTYZhjAeXg==
X-Received: by 2002:a05:6870:709e:b0:1bb:5f4d:5dc8 with SMTP id v30-20020a056870709e00b001bb5f4d5dc8mr2827320oae.23.1693573607796;
        Fri, 01 Sep 2023 06:06:47 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:808d:b0:1c3:e0f6:4173 with SMTP id
 q13-20020a056870808d00b001c3e0f64173ls2040119oab.2.-pod-prod-08-us; Fri, 01
 Sep 2023 06:06:47 -0700 (PDT)
X-Received: by 2002:a05:6870:c18b:b0:1be:f23f:99b with SMTP id h11-20020a056870c18b00b001bef23f099bmr2747072oad.42.1693573606904;
        Fri, 01 Sep 2023 06:06:46 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1693573606; cv=pass;
        d=google.com; s=arc-20160816;
        b=kDeHzGtLnC0b7drEm2oejdhXLVPDR4p/hys/xaxO2+xhUz6U39odddDjML+umfrLAj
         GkFDA0MH3X+RO2CHY3tupTdBAoN6zyeS5PfdFCvRjf1XgCLoQgTPr8qLyWJ7v5u0oTOR
         UiaO3s5dWE0CyYmynVrHRLoev5pvA27CB4tVP89uLiy6iBDSbL/CznI+iaV2Ij2tM7E7
         HF0hCEKiUVfrKG1yJ4k2OsYoN9SBmqIbB0bbrcu1fw46RMsKXGpi6pRrxUYibSHf7GW2
         cD0eufoDtxuYR/41+5U8pZgPdqR0yFYLW4GBjvOSrro7+v3Sj2y7BT4PIndNM8iJaHMB
         kvzw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-transfer-encoding:content-id:content-language
         :accept-language:in-reply-to:references:message-id:date:thread-index
         :thread-topic:subject:cc:to:from:dkim-signature:dkim-signature;
        bh=t0YRgkRIlS9+vnFMWn7gItbSc+nRJINg2/PDAFnBcbY=;
        fh=w0GGIxU+HXSP+M6hud+ASnPIID5mY1vD5hbUpeCSkCo=;
        b=UNSnJ9kMwHLjd1EfNrpM8T4cUuUPGTn/OF2R/H/XajNY2b3idITcyTgltuaOBJnl4q
         jBWkTxdma3g9IULt/fCAKfMep/WpW4sDv5UQ4QsA15Gw+KE/BW8sC8TVffk07NhB7LMn
         gF0JgmC8Bl/hkT1f11BCbkx64wUP6hWNWrO/l+ZQcZhivXk0+8v1yzwc8PWM4sDC199x
         G2Dh+bOpg+PM9y9rqXd2Mm1Xr2kFrP9fmvNOrPU7NTcZ7heZSGtHYQlYDZWzUzMDpHm/
         Fn6qIk9so/1JKzuCQ47sNMe1gjZc1+f+lmR7jJG7q3v9mXJ8WnTEEGzYVbgbkFpsfLXU
         MgwA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=ClwdAhc1;
       dkim=pass header.i=@mediateko365.onmicrosoft.com header.s=selector2-mediateko365-onmicrosoft-com header.b="jwy/7S8b";
       arc=pass (i=1 spf=pass spfdomain=mediatek.com dkim=pass dkdomain=mediatek.com dmarc=pass fromdomain=mediatek.com);
       spf=pass (google.com: domain of kuan-ying.lee@mediatek.com designates 60.244.123.138 as permitted sender) smtp.mailfrom=kuan-ying.lee@mediatek.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=mediatek.com
Received: from mailgw01.mediatek.com ([60.244.123.138])
        by gmr-mx.google.com with ESMTPS id qf11-20020a05687148cb00b001b730b9901fsi375834oab.4.2023.09.01.06.06.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 01 Sep 2023 06:06:46 -0700 (PDT)
Received-SPF: pass (google.com: domain of kuan-ying.lee@mediatek.com designates 60.244.123.138 as permitted sender) client-ip=60.244.123.138;
X-UUID: 6513547848c811eea33bb35ae8d461a2-20230901
X-CID-P-RULE: Release_Ham
X-CID-O-INFO: VERSION:1.1.31,REQID:faa18feb-a2bf-4d22-b8b5-89a4395985c3,IP:0,U
	RL:0,TC:0,Content:0,EDM:0,RT:0,SF:0,FILE:0,BULK:0,RULE:Release_Ham,ACTION:
	release,TS:0
X-CID-META: VersionHash:0ad78a4,CLOUDID:147f0320-33fd-4aaa-bb43-d3fd68d9d5ae,B
	ulkID:nil,BulkQuantity:0,Recheck:0,SF:102,TC:nil,Content:0,EDM:-3,IP:nil,U
	RL:0,File:nil,Bulk:nil,QS:nil,BEC:nil,COL:0,OSI:0,OSA:0,AV:0,LES:1,SPR:NO,
	DKR:0,DKP:0,BRR:0,BRE:0
X-CID-BVR: 0,NGT
X-CID-BAS: 0,NGT,0,_
X-CID-FACTOR: TF_CID_SPAM_SNR
X-UUID: 6513547848c811eea33bb35ae8d461a2-20230901
Received: from mtkmbs11n2.mediatek.inc [(172.21.101.187)] by mailgw01.mediatek.com
	(envelope-from <kuan-ying.lee@mediatek.com>)
	(Generic MTA with TLSv1.2 ECDHE-RSA-AES256-GCM-SHA384 256/256)
	with ESMTP id 1421861690; Fri, 01 Sep 2023 21:06:42 +0800
Received: from mtkmbs10n1.mediatek.inc (172.21.101.34) by
 mtkmbs11n1.mediatek.inc (172.21.101.185) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.2.1118.26; Fri, 1 Sep 2023 21:06:41 +0800
Received: from APC01-TYZ-obe.outbound.protection.outlook.com (172.21.101.237)
 by mtkmbs10n1.mediatek.inc (172.21.101.34) with Microsoft SMTP Server id
 15.2.1118.26 via Frontend Transport; Fri, 1 Sep 2023 21:06:40 +0800
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=MvPqLcoimgwhwEyCD0bq8Rgle77xBo9YI/LDDcRoX+6MaI0NfeomiSOP5UYVm/I91pesd1MHViQdisRo7wMmgtrZL9IXOGTUpSaf8qv+wnBS6u52mN9BfeHdpBdDHGAeEQU+2lecK6+gEOHWKuD9bOZD49tDLSfbywZXZlE5zjx/JxHUOh/0NDZSCYD4AEUKQ8qdZGDZmMdDnyLxOeLVo2vwEx1Vf9lzx4fWWTQSzpVHiQSVQKad6H+OFtIarORkP8xL5amiZNzQEX9WaAYZpe9DmaExqHcTR6kjU37qwPNCd27/qIcM5WqPP/6rHyfFtvu8QdojmGit9zanv4l4cg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=t0YRgkRIlS9+vnFMWn7gItbSc+nRJINg2/PDAFnBcbY=;
 b=IHhr1aApNtNypYQS2X92v9gYVyYANeGQUPbVf/ztHdnR+qpv/aQFW20saAGNF7NAdrMhvaMkGpIiLwWrWEcG+mX1OvsVZFs0idaBoKPHRFU09ffYd57ChDuOOAbshiUmXF1IHX4SWEMI+SONJx3Y5QRzygz/a0NOrd0AAJDypL3PfCEEGZBIiyTMvhhWb38Ozs8NvMFSO8dN5ZzEmd360xTdSbF9XB8JViRZihf+gR9ShO+6siKv7CZuUqebjbqU/fv0f1JdojlR4UlNQeukei5aVUO+18ajayrRTLfUQfNyrbURrv72X+85GPGDWw74VTlNQvU6obT6plFSYs+ycQ==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=mediatek.com; dmarc=pass action=none header.from=mediatek.com;
 dkim=pass header.d=mediatek.com; arc=none
Received: from PUZPR03MB5964.apcprd03.prod.outlook.com (2603:1096:301:b4::11)
 by SEYPR03MB8031.apcprd03.prod.outlook.com (2603:1096:101:16e::6) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.6745.23; Fri, 1 Sep
 2023 13:06:36 +0000
Received: from PUZPR03MB5964.apcprd03.prod.outlook.com
 ([fe80::4731:7196:588d:ba27]) by PUZPR03MB5964.apcprd03.prod.outlook.com
 ([fe80::4731:7196:588d:ba27%3]) with mapi id 15.20.6745.023; Fri, 1 Sep 2023
 13:06:36 +0000
From: =?UTF-8?B?J0t1YW4tWWluZyBMZWUgKOadjuWGoOepjiknIHZpYSBrYXNhbi1kZXY=?= <kasan-dev@googlegroups.com>
To: "glider@google.com" <glider@google.com>, "elver@google.com"
	<elver@google.com>, "andrey.konovalov@linux.dev" <andrey.konovalov@linux.dev>
CC: "andreyknvl@google.com" <andreyknvl@google.com>,
	"linux-kernel@vger.kernel.org" <linux-kernel@vger.kernel.org>,
	"linux-mm@kvack.org" <linux-mm@kvack.org>, "andreyknvl@gmail.com"
	<andreyknvl@gmail.com>, "vbabka@suse.cz" <vbabka@suse.cz>,
	"kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>,
	"dvyukov@google.com" <dvyukov@google.com>, "akpm@linux-foundation.org"
	<akpm@linux-foundation.org>, =?utf-8?B?S3Vhbi1ZaW5nIExlZSAo5p2O5Yag56mOKQ==?=
	<Kuan-Ying.Lee@mediatek.com>, "eugenis@google.com" <eugenis@google.com>
Subject: Re: [PATCH 12/15] stackdepot: add refcount for records
Thread-Topic: [PATCH 12/15] stackdepot: add refcount for records
Thread-Index: AQHZ3NNZTBG64M2aWEav85Ytu2p3zrAF8J6A
Date: Fri, 1 Sep 2023 13:06:36 +0000
Message-ID: <bb2f8a4f90432452822326b927e8cab58665cd09.camel@mediatek.com>
References: <cover.1693328501.git.andreyknvl@google.com>
	 <306aeddcd3c01f432d308043c382669e5f63b395.1693328501.git.andreyknvl@google.com>
In-Reply-To: <306aeddcd3c01f432d308043c382669e5f63b395.1693328501.git.andreyknvl@google.com>
Accept-Language: zh-TW, en-US
Content-Language: en-US
X-MS-Has-Attach: 
X-MS-TNEF-Correlator: 
x-mailer: Evolution 3.28.5-0ubuntu0.18.04.2
x-ms-publictraffictype: Email
x-ms-traffictypediagnostic: PUZPR03MB5964:EE_|SEYPR03MB8031:EE_
x-ms-office365-filtering-correlation-id: cb25dec5-435e-4a30-528d-08dbaaec45f8
x-ms-exchange-senderadcheck: 1
x-ms-exchange-antispam-relay: 0
x-microsoft-antispam: BCL:0;
x-microsoft-antispam-message-info: XLpC86w+Sfyw+a4kj3gEsOiAv0DriWnNDWRL4TINlPHJztRCjOPhSXeGeWtUmL/YkJEac78nuu4woUziYg6ns+zNk/E4u7vm+WtT/vJo/EKADV/DUD3l8YN0onSBXNKF36PuAUSeW/be0w/u//j+Gu+OJwqEUE998AcCdHVDvz7V9nL8g+WhPkDK+IiRErYyId4iyWR+BzX9Kd6fJlLcpY0bHTBuLmDm+EqY9cuuZs63/64JHAjeL1jgFt7fNrJdRKhGw+coMaTZZ9YLEtFf5CG/4XSCOw7VQI37Ib43y2QDwxG71THTRZWruNErYAGdQOJr7/QrQ0MYm0cFdm/yZ6KIVSXQMQiZjiN4YI5JNDPRYIsteX0twTfTu7VLNrdrPDSi14SrUtwuQgRgN9kKQjhF+Ac9AVbKQvHmn8dWXdGeFzFMHp1mVV62nzza7gu2sXWrrgdGVHqLcb0spENGVmyQ2rxxvFTQo0adVaXAUnkCwjTpPJZkCnVlCLHZINhIlb3hoyJ8Wu8Z+DGAVhTNHCcCeJa/bz/TV/KZq+oMFy97AqFkaRDXBRzvMaDB/bRe7BObSvZ78PPRQsFp/NN/mAd0XFgjwm5JLWYC54ROxDh7cnbjkr5Jh/S1GA8/peL+9AkgWaCJcPccR9IwDbHCNOpq8URSAdzYktVoUpnblnepTQJfKKn3nzGnN5FeASfU
x-forefront-antispam-report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:PUZPR03MB5964.apcprd03.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230031)(396003)(39860400002)(346002)(376002)(366004)(136003)(186009)(1800799009)(451199024)(71200400001)(6486002)(6506007)(6512007)(478600001)(83380400001)(26005)(2616005)(2906002)(7416002)(54906003)(64756008)(66446008)(66476007)(66556008)(316002)(41300700001)(66946007)(76116006)(91956017)(110136005)(5660300002)(8936002)(8676002)(4326008)(85182001)(36756003)(86362001)(38070700005)(38100700002)(122000001)(99106002);DIR:OUT;SFP:1102;
x-ms-exchange-antispam-messagedata-chunkcount: 1
x-ms-exchange-antispam-messagedata-0: =?utf-8?B?ZlZWNDFmaXN0T09GL3dUYS9sL0FTaXlMdzIrZjZJdit5OE9kbCtib3RZNjAy?=
 =?utf-8?B?RTBzcDh6bGNIdC91UEF3dmZQbjdGaThNVUhjcXo4M0NlUXFkNkVESTNjeEl6?=
 =?utf-8?B?UEI2MGRkUXY1RzZ1c0ZWMFd5TW5GVmYycTVyOHJhbUczbEJwdkRCTUFTb1A2?=
 =?utf-8?B?Z1laQjhVejNSNzZScTYxUithV2ltWWQ4K1g1SnZOVXFIU0xDaEl2VkZMTm92?=
 =?utf-8?B?bmF3aDNhbVVybGMvQW9FMUQ1ZGtWZERFa1BhWUNZOEtKRDV5UmRqRGNOSm1I?=
 =?utf-8?B?VHJ5YWRIcUtyVWlSbHBGd01QRmhTa0VWbkZ5M2ZHZ3l2NW9PZmYvblhDSUVW?=
 =?utf-8?B?UDdaUTRieCs4U3Z0LzQzVWRXT09lYW41L1VKYmNSNE0xdXpBMEdCa1pyQWlR?=
 =?utf-8?B?ZS80SlZnQUNJSEF4V3ZhSnpwU21DU1REQ1o0c1EvWlNuWEtYYVVGZHIzT09w?=
 =?utf-8?B?NWZzM3hCOEtoT1hmNzlrZG9NdTFmRHZDS25vOTQvQzVPUXZON0hyVzUrTnc1?=
 =?utf-8?B?U0gwOGkySnhsYk93aUtyUEkzQ0MyV0NMeWFKeTFGUWhhTTQwRE9TRGhpWVg4?=
 =?utf-8?B?RWx3WnhUYnZFWEU1NThpUHdIT2paOWdkL0V3VDBzNy9sU3lVMHhnLzlGdnFD?=
 =?utf-8?B?MXFPYWE2LzF2M2hnblZaTGhDVjNwMlh2aTdpWG00S3plU3NhTFU3ZWxNTG02?=
 =?utf-8?B?UlBFQTdvR2VmUmNxditQSnZSTFBURlFvUmtIMGd6K05mMFliUHdqYzB1dmtr?=
 =?utf-8?B?d1cvdmd6Zk1vV0ZCZkxaU2kzUzFSMlhyWTlIUGJNY1MyY1IxUkRzdEN4R0Zy?=
 =?utf-8?B?MXJRcTdLclkyc2pjOUkwKzRzaUdRWjlGajd1VWZkODVGcmc1OWdBajF2RXlL?=
 =?utf-8?B?Q09DcWRRcVZ2aFJEZGJQTDVQWmV0Wld5UzdCSHlJenNnT1poZGZtSS9MVnYw?=
 =?utf-8?B?TVdaSUlVRFRMU0xsQWdKVGVaaGY1S2o2MFhXRjhDdUtpVkUxdnZkbG9rR2xm?=
 =?utf-8?B?RjhuQzNxTVI0aWQrYjFvZDk5b1VFZmZrcGgzRllUVER3M3BURy9uUU9lSlhK?=
 =?utf-8?B?a200cjkvNzFuWFpTdWNKTDhZbDRORndNZEt1aDRzZnQzbnNNN2pWdHN3Z05p?=
 =?utf-8?B?dEhhOE5LNDNIT1dLUDhYdGdja3RZSHVlelBtVElSUXJLS3JiR3RhZ2hOVCt0?=
 =?utf-8?B?QlZMdCtxQVgwaEpyVWRQaXk1dXN6NkdJSzZKWWl1NHVjTmFqcTJmQ2hRNncw?=
 =?utf-8?B?T2hoNHo5d0hhNFhxVmZITU1HUit1NUhWUzAzVHlqQitOc3pjUmtOWFVScUhZ?=
 =?utf-8?B?L2swZ1ZoR3pYWTNjc3Mxc2wyTFRqMnhOSmFXOHdQQUphSmFOTnZmcjYySDJN?=
 =?utf-8?B?STZZbHhxTTd3dXVBRGNaK0ljeThwZDBUL3VBaTFlUFhNNmJCeUNNTGdESStz?=
 =?utf-8?B?ZFhlRDBVVFp1QXh5Um9VWnc0WUhHWVpVcXhGTGhJWUVodG03ZkdGM0ZUYnI3?=
 =?utf-8?B?M2o5WjQ0ZExENW96eGx3VjdzMEI3N1JoTWxVbjgxbDlpMS9YTFZ1eG9mMStv?=
 =?utf-8?B?WkY5bnB0MUFBNEVjejdac2oyTURlalhidVBaaDNqd2JxMjI5SzFpcjNjOUZs?=
 =?utf-8?B?VGtaVlhzRTZXVUhUakNBZmIwK2Iwdm9OTFRRdmpCbWMzb3c2dk4vVmdCaFlI?=
 =?utf-8?B?N0lHemVuL1Y2UGp5Z2dhdXFaQlhQaWYrRTY5dUJIQUpGWFltN3E0UWd2dlpD?=
 =?utf-8?B?Q0NmN1JZaVJrV1UzbVBEeWRIdGhYM3Yrczd5ZDhHRnNqdlNOL0p6Zmw0QzJY?=
 =?utf-8?B?TGhVSGdza0xJS25wM2ZMVjlnYWF0TGFQNG5LVUVTaVErZ1RjcVU4SFVjMkU3?=
 =?utf-8?B?ekZCZUU2Sk1ZL2VkSTE4dlk4a1lWeE1vbGdwMUI1Nlovdm9BOGJmUUY4U2Fi?=
 =?utf-8?B?YnBPNjZsWm4zYzFpSWVtd3pjbVFmbFB6cC9ZMUdMdUIrbTVoU2l3WnhtL0lr?=
 =?utf-8?B?MjVwamZLbmRYbEJtV0ppaDd1YnNZUWZwVjJjUkVGRkkzdndtalF5Rm8zMnNn?=
 =?utf-8?B?Zm1waTdUMTRSbmJjYlk4bk5mSk1rSkFCSFZQYzdtNkJ4OExJNFNPUTQwN25w?=
 =?utf-8?B?RSsvYkszQ2ZDOS95V1F2ZlJIV0ZOb1hQQm1BREJ3RmRkY3V3UVErVmRjb3JM?=
 =?utf-8?B?Smc9PQ==?=
Content-Type: text/plain; charset="UTF-8"
Content-ID: <F88510005A1112479A34CD0732DF5D25@apcprd03.prod.outlook.com>
MIME-Version: 1.0
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-AuthSource: PUZPR03MB5964.apcprd03.prod.outlook.com
X-MS-Exchange-CrossTenant-Network-Message-Id: cb25dec5-435e-4a30-528d-08dbaaec45f8
X-MS-Exchange-CrossTenant-originalarrivaltime: 01 Sep 2023 13:06:36.5953
 (UTC)
X-MS-Exchange-CrossTenant-fromentityheader: Hosted
X-MS-Exchange-CrossTenant-id: a7687ede-7a6b-4ef6-bace-642f677fbe31
X-MS-Exchange-CrossTenant-mailboxtype: HOSTED
X-MS-Exchange-CrossTenant-userprincipalname: laC0eefhA2uYmxjqyZQSdJMunO9ay5AwBJ5SgHjGwnxyVZS/uO6EBo7HIUE595rVRHgPZHiEiVS0G6h3kRR9mhtU71OjtggCvjdsP6ZLy3M=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: SEYPR03MB8031
X-MTK: N
X-Original-Sender: Kuan-Ying.Lee@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@mediatek.com header.s=dk header.b=ClwdAhc1;       dkim=pass
 header.i=@mediateko365.onmicrosoft.com header.s=selector2-mediateko365-onmicrosoft-com
 header.b="jwy/7S8b";       arc=pass (i=1 spf=pass spfdomain=mediatek.com
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

On Tue, 2023-08-29 at 19:11 +0200, andrey.konovalov@linux.dev wrote:
> From: Andrey Konovalov <andreyknvl@google.com>
> 
> Add a reference counter for how many times a stack records has been
> added
> to stack depot.
> 
> Do no yet decrement the refcount, this is implemented in one of the
> following patches.
> 
> This is preparatory patch for implementing the eviction of stack
> records
> from the stack depot.
> 
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> ---
>  lib/stackdepot.c | 4 ++++
>  1 file changed, 4 insertions(+)
> 
> diff --git a/lib/stackdepot.c b/lib/stackdepot.c
> index 5ad454367379..a84c0debbb9e 100644
> --- a/lib/stackdepot.c
> +++ b/lib/stackdepot.c
> @@ -22,6 +22,7 @@
>  #include <linux/mutex.h>
>  #include <linux/percpu.h>
>  #include <linux/printk.h>
> +#include <linux/refcount.h>
>  #include <linux/slab.h>
>  #include <linux/spinlock.h>
>  #include <linux/stacktrace.h>
> @@ -60,6 +61,7 @@ struct stack_record {
>  	u32 hash;			/* Hash in hash table */
>  	u32 size;			/* Number of stored frames */
>  	union handle_parts handle;
> +	refcount_t count;
>  	unsigned long entries[DEPOT_STACK_MAX_FRAMES];	/* Frames */
>  };
>  
> @@ -348,6 +350,7 @@ depot_alloc_stack(unsigned long *entries, int
> size, u32 hash, void **prealloc)
>  	stack->hash = hash;
>  	stack->size = size;
>  	/* stack->handle is already filled in by depot_init_pool. */
> +	refcount_set(&stack->count, 1);
>  	memcpy(stack->entries, entries, flex_array_size(stack, entries,
> size));
>  
>  	/*
> @@ -452,6 +455,7 @@ depot_stack_handle_t __stack_depot_save(unsigned
> long *entries,
>  	/* Fast path: look the stack trace up without full locking. */
>  	found = find_stack(*bucket, entries, nr_entries, hash);
>  	if (found) {
> +		refcount_inc(&found->count);
>  		read_unlock_irqrestore(&pool_rwlock, flags);
>  		goto exit;
>  	}

Hi Andrey,

There are two find_stack() function calls in __stack_depot_save().

Maybe we need to add refcount_inc() for both two find_stack()?

Thanks,
Kuan-Ying Lee

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bb2f8a4f90432452822326b927e8cab58665cd09.camel%40mediatek.com.
