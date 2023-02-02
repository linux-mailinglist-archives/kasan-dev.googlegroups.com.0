Return-Path: <kasan-dev+bncBDY7XDHKR4OBBOES5WPAMGQEM2LDCBA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa39.google.com (mail-vk1-xa39.google.com [IPv6:2607:f8b0:4864:20::a39])
	by mail.lfdr.de (Postfix) with ESMTPS id 23EEA68750D
	for <lists+kasan-dev@lfdr.de>; Thu,  2 Feb 2023 06:25:14 +0100 (CET)
Received: by mail-vk1-xa39.google.com with SMTP id n142-20020a1fbd94000000b003e89edf83ecsf357805vkf.7
        for <lists+kasan-dev@lfdr.de>; Wed, 01 Feb 2023 21:25:14 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1675315512; cv=pass;
        d=google.com; s=arc-20160816;
        b=QhhId7dT1smR4k1m58TTGGqLyDcT1hIByTJyENqNRJjO2y0DQWEY19xGRcEb38l4n2
         wNzdPknowdrwbcuQvXyY7RKasHD7Xdw8Lim6M7isrDIbTUzIuyhbq9ie3SB8wZUuvhL+
         ZDb6u3FDehxGBz8KPqkw00mBvom45UIBjeSfE7YUHoUPVFyTYt+lwoI22rOUnKUnj/Nm
         yfbynzW2kyHwlC5H50dyb0XvsbZ75J2jPbalM3yQj6VoR3DIDbiJmgOSQe9AAMvfbQp0
         3ZNmVUBdok7mkA4NKPXUgN/+0ljbtwVNvlGeA9QFP9LEYE2GEmszTBNzYDhEdiA7jtih
         tt9w==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:content-id
         :content-language:accept-language:in-reply-to:references:message-id
         :date:thread-index:thread-topic:subject:cc:to:from:dkim-signature;
        bh=HODtIPVpvfEuIISqngb7lTQ7KiGRbw11d8h4e8C8rPI=;
        b=PREqPTRD7lwth3RYRG7LK3l+932GUaFzCei1uUjXF/lSMWiGnRBSa5vlnRzs4cfK0g
         Corp1h167bjLGlG3kjPsFAtg3AXOFDyyK7e11nLmo5QGpP8XR08tD6C6x2sBwKi3q8Ri
         4j6ko8uNImZDZxcsfwzmwBZzFxgLhPDcGMn408W17yKlLw2pBGukIU5R6mt02gwu8yX9
         R9/809Qbw/KN4k7DXkXJ/ZfzermqT3GsGpkppBFkHzHWXLDiQf9VvXCV+zNsdoe19zBV
         3FlyldyWJO+SdW8bhXFzYje/Oft6vgJysJMaRL1Ik69JqB66b1PplHVIJZpoLsCuTBa/
         wSHg==
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=nhBSJ8nx;
       dkim=pass header.i=@mediateko365.onmicrosoft.com header.s=selector2-mediateko365-onmicrosoft-com header.b=appsI3Bx;
       arc=pass (i=1 spf=pass spfdomain=mediatek.com dkim=pass dkdomain=mediatek.com dmarc=pass fromdomain=mediatek.com);
       spf=pass (google.com: domain of kuan-ying.lee@mediatek.com designates 60.244.123.138 as permitted sender) smtp.mailfrom=kuan-ying.lee@mediatek.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :content-id:content-language:accept-language:in-reply-to:references
         :message-id:date:thread-index:thread-topic:subject:cc:to:from:from
         :to:cc:subject:date:message-id:reply-to;
        bh=HODtIPVpvfEuIISqngb7lTQ7KiGRbw11d8h4e8C8rPI=;
        b=D+7vJGDZeF8KIXa1FpSjKWg1KdUjGZcH5ukmrQtA/2wF8jGN+tExNAn+bQeQptXPJ4
         NUPzU4zlfg+60xOAo3H0MHk3uZs6RDsrJ+2wYbvE9U6sVBDYyRQDj3TdLDjbpQCSh2qH
         CrP09WLX+zndLu7c2q3d7oZEEXIuGJqEY+TnWdvxEUQ5Qevk6dTsgsdnSHXq3JMftVC7
         ext8IdaCw1L08rSpSs/CD79vxfOkZF2uo0o2sqtEjleNdfeP/0806i9NqDSob/xobQKF
         w8lX/mI55am+NQ3etFOZayO5Cw+CBg4qsPYDvsuiA2iDUiXoROLpIJokmnSUbog0BmZZ
         dyig==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :content-id:content-language:accept-language:in-reply-to:references
         :message-id:date:thread-index:thread-topic:subject:cc:to:from
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=HODtIPVpvfEuIISqngb7lTQ7KiGRbw11d8h4e8C8rPI=;
        b=lu42+BI/EmOIwYxV6CIe28oiuUA9O+MtLv0hUzXc8TN3P+ZJhqmXKocR/E8Av2hQVD
         mcdMtrCSVqV5rEwXF2P6CgVMnLR8aKgPxC69zvUvYpoCizuOmcjdMoHRU1xOrYps0L1x
         CEyUobcA2RHbgo8Z4V9MEfFUVH/20FddvCHcbyH8KIPdkiC+OrD1/PkAANp+16yDBQVB
         tByxjnxRfGNA3ew4iTm1MEdcuscuc72fE9TtMgSpsA/pJbkURxabYrEqkgY9Jpi1Kp3W
         jZ74kqVkWPC5f1BepmYsVRlPLLeaBl7l2fEACpaulH1zByCgeVuXLdORZ08KtqUjO8+R
         NKMQ==
X-Gm-Message-State: AO0yUKXjDg1LUbGhU5rvwID9DY/KJYOxkqsK+WTJd3BNdWAJnTLzHFy1
	wpJcwGHC84Q7UFLeB/lnnaI=
X-Google-Smtp-Source: AK7set+ekSd0iRAns10RjVCT3dOg4j4BviETSh7u28enJBLhh3ipJqhpJSwuNMZtimx4MQYQeG1HhQ==
X-Received: by 2002:a05:6102:36d3:b0:3e9:13d4:5997 with SMTP id z19-20020a05610236d300b003e913d45997mr833486vss.79.1675315512480;
        Wed, 01 Feb 2023 21:25:12 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6102:ce:b0:3f6:c79c:3ce9 with SMTP id
 u14-20020a05610200ce00b003f6c79c3ce9ls246678vsp.5.-pod-prod-gmail; Wed, 01
 Feb 2023 21:25:11 -0800 (PST)
X-Received: by 2002:a05:6102:33d5:b0:3ec:b3f9:c917 with SMTP id w21-20020a05610233d500b003ecb3f9c917mr1811299vsh.27.1675315511716;
        Wed, 01 Feb 2023 21:25:11 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1675315511; cv=pass;
        d=google.com; s=arc-20160816;
        b=B0XDqmEzFpmjTJNJDSOfGakjQLYGlhfCTNkPMylIM2tLpLRZ0UcGPawRkPvi0KOmSk
         3ygEHDP16JvsCEIQcMIvWBfJgGRzmckzv2t0YJL8riv0y0UQ/+LHUChAI8ICO6DQJGHR
         sl8HSz0P0MATo/WT/RPng5QiVRl55o5Dn6FacFs1FdgMCjojox06Hse+ZXRAWK768arx
         6GH2LCuEBTxb4frWsAVOWwil8M1Vt4sc6BNgLu8dQ/m/JkqZ7djTF4Otkf6jvcmJ+RI7
         II5t/OfWng3fY/L+wAdlPVbht58Ae9oJSvxq1OrrTaokLIJ87HbxEYpmYPUH1k0x6Qdz
         TV+A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-transfer-encoding:content-id:content-language
         :accept-language:in-reply-to:references:message-id:date:thread-index
         :thread-topic:subject:cc:to:from:dkim-signature:dkim-signature;
        bh=OkmbNnuj7F1HWOZTR3RwYgW3CN01NND7V9UnNOCEc9U=;
        b=cH7i3SeKSJ2bOtJ8/Ohwf/DWnfpPZucAIu/CpiGEqoKKGx1WB/3+nvTxWusfnYCL9Y
         g4tT/0iAE4dgMx3pkFnl8P3UDJIhL9QRLHpth+wAEBi953hKjOwUcGsYSYVelT73CR3m
         RUqm+vFN5HXhEas5VtxAoUtRzmRcJfiOnzCbAMd+yCHR4h+8It4S9+dls2JOvQJqsEyV
         vGacKJscvfU2DR0RnxhQlHUSddbC1cv4Ok0XaJugYvaKCUQLqFss1PdRoqdIy+BvEpS9
         bYAlwFZSQ9OAcJO3MY3jQNYopFDUisVTJc5LfQk9W29SrLoIqF1v5NWNtA9gGTzZrzLJ
         YX+w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=nhBSJ8nx;
       dkim=pass header.i=@mediateko365.onmicrosoft.com header.s=selector2-mediateko365-onmicrosoft-com header.b=appsI3Bx;
       arc=pass (i=1 spf=pass spfdomain=mediatek.com dkim=pass dkdomain=mediatek.com dmarc=pass fromdomain=mediatek.com);
       spf=pass (google.com: domain of kuan-ying.lee@mediatek.com designates 60.244.123.138 as permitted sender) smtp.mailfrom=kuan-ying.lee@mediatek.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=mediatek.com
Received: from mailgw01.mediatek.com ([60.244.123.138])
        by gmr-mx.google.com with ESMTPS id u16-20020a056102375000b003d04209e4e2si1268111vst.0.2023.02.01.21.25.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 01 Feb 2023 21:25:11 -0800 (PST)
Received-SPF: pass (google.com: domain of kuan-ying.lee@mediatek.com designates 60.244.123.138 as permitted sender) client-ip=60.244.123.138;
X-UUID: f32b45dca2b911eda06fc9ecc4dadd91-20230202
X-CID-P-RULE: Release_Ham
X-CID-O-INFO: VERSION:1.1.18,REQID:1fb2251c-9c8f-4975-bf77-41df3049bbf4,IP:0,U
	RL:0,TC:0,Content:0,EDM:0,RT:0,SF:-5,FILE:0,BULK:0,RULE:Release_Ham,ACTION
	:release,TS:-5
X-CID-INFO: VERSION:1.1.18,REQID:1fb2251c-9c8f-4975-bf77-41df3049bbf4,IP:0,URL
	:0,TC:0,Content:0,EDM:0,RT:0,SF:-5,FILE:0,BULK:0,RULE:Release_Ham,ACTION:r
	elease,TS:-5
X-CID-META: VersionHash:3ca2d6b,CLOUDID:479f0f56-dd49-462e-a4be-2143a3ddc739,B
	ulkID:2302021325078HTJ9SWT,BulkQuantity:0,Recheck:0,SF:38|17|19|102,TC:nil
	,Content:0,EDM:-3,IP:nil,URL:1,File:nil,Bulk:nil,QS:nil,BEC:nil,COL:0,OSI:
	0,OSA:0
X-CID-BVR: 0,NGT
X-UUID: f32b45dca2b911eda06fc9ecc4dadd91-20230202
Received: from mtkmbs10n1.mediatek.inc [(172.21.101.34)] by mailgw01.mediatek.com
	(envelope-from <kuan-ying.lee@mediatek.com>)
	(Generic MTA with TLSv1.2 ECDHE-RSA-AES256-GCM-SHA384 256/256)
	with ESMTP id 1917494201; Thu, 02 Feb 2023 13:25:05 +0800
Received: from mtkmbs10n1.mediatek.inc (172.21.101.34) by
 mtkmbs10n1.mediatek.inc (172.21.101.34) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.2.792.15; Thu, 2 Feb 2023 13:25:03 +0800
Received: from APC01-SG2-obe.outbound.protection.outlook.com (172.21.101.239)
 by mtkmbs10n1.mediatek.com (172.21.101.34) with Microsoft SMTP Server id
 15.2.792.15 via Frontend Transport; Thu, 2 Feb 2023 13:25:03 +0800
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=lsgGrBIuKOdolNu7oMWGf8nD9F4Tnlj8VJPkMymXKgPDvvaTXe/HtwttoQ7clvT8hjJC2SkMGsPSHerTHFWyTXhcLzhgPVVzDe1tkD1+XhjTUuiWRAIJ58r2eHbgP9dgBqfqC5yOc4p5+yI42zCwr9TiTGiviZbvCLfl/UdD2OPs1sdBYvGUmdpJ3F65fhXL0YWEiUvsxZiB4/sAMkL7+MH0PnScLYj69Sy9YfwbN49Ny6QW6SVsu2t+dyXaImahnJ5pRhwODNyDyeR8o2ij/fYxbG4bEgMt7XhzdMpBAZnNXYKAgLRupP43IxPyGBLUjCJRSUBZNXXXB4TGH/QNqw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=OkmbNnuj7F1HWOZTR3RwYgW3CN01NND7V9UnNOCEc9U=;
 b=fH8MaS2IhZk+sXnh5Yxf1wSEXP48rNYBIncT8uTVucP0uQQ3uy6QhjBTVLP2zELhJaAJlAemOCwREMyk3V+qXCG6pyNNMtpT0bkwDuEsWl4ksPnAuevnFfKLNL2N2FC+SATl83Y9MvehvEDTfXj3lV7wzbwWqooC/uDOovGwHwzp8TTZVfDUqq0I3UcI//4Nfoj5s3h2fiOSQSgpy5EcW2Kb1LSvYUktidap3hz5Vz9nz7+Yi9MuSi36jL6E6zgZST/BzGulbUGrv1SWLAdbspsrzIgphP1JxBmoxiXkO2IHwfhV8lfdMg4Ij/UorFui/Ns2hpotndhxJXAbCGICOw==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=mediatek.com; dmarc=pass action=none header.from=mediatek.com;
 dkim=pass header.d=mediatek.com; arc=none
Received: from PUZPR03MB5964.apcprd03.prod.outlook.com (2603:1096:301:b4::11)
 by KL1PR0302MB5219.apcprd03.prod.outlook.com (2603:1096:820:41::13) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.6064.25; Thu, 2 Feb
 2023 05:25:00 +0000
Received: from PUZPR03MB5964.apcprd03.prod.outlook.com
 ([fe80::c43a:ce45:4a27:bd80]) by PUZPR03MB5964.apcprd03.prod.outlook.com
 ([fe80::c43a:ce45:4a27:bd80%7]) with mapi id 15.20.6064.025; Thu, 2 Feb 2023
 05:25:00 +0000
From: =?UTF-8?B?J0t1YW4tWWluZyBMZWUgKOadjuWGoOepjiknIHZpYSBrYXNhbi1kZXY=?= <kasan-dev@googlegroups.com>
To: "ryabinin.a.a@gmail.com" <ryabinin.a.a@gmail.com>, "andreyknvl@gmail.com"
	<andreyknvl@gmail.com>, "catalin.marinas@arm.com" <catalin.marinas@arm.com>
CC: =?utf-8?B?UXVuLXdlaSBMaW4gKOael+e+pOW0tCk=?= <Qun-wei.Lin@mediatek.com>,
	=?utf-8?B?R3Vhbmd5ZSBZYW5nICjmnajlhYnkuJop?= <guangye.yang@mediatek.com>,
	"linux-mm@kvack.org" <linux-mm@kvack.org>, "kasan-dev@googlegroups.com"
	<kasan-dev@googlegroups.com>,
	=?utf-8?B?S3Vhbi1ZaW5nIExlZSAo5p2O5Yag56mOKQ==?=
	<Kuan-Ying.Lee@mediatek.com>, "linux-arm-kernel@lists.infradead.org"
	<linux-arm-kernel@lists.infradead.org>, "pcc@google.com" <pcc@google.com>,
	"vincenzo.frascino@arm.com" <vincenzo.frascino@arm.com>, "will@kernel.org"
	<will@kernel.org>
Subject: Re: [PATCH v2 0/4] kasan: Fix ordering between MTE tag colouring and
 page->flags
Thread-Topic: [PATCH v2 0/4] kasan: Fix ordering between MTE tag colouring and
 page->flags
Thread-Index: AQHYfN3UQ2ZS5zhImUiCo/W/1QNefK68k6aA
Date: Thu, 2 Feb 2023 05:25:00 +0000
Message-ID: <66cc7277b0e9778ba33e8b22a4a51c19a50fe6f0.camel@mediatek.com>
References: <20220610152141.2148929-1-catalin.marinas@arm.com>
In-Reply-To: <20220610152141.2148929-1-catalin.marinas@arm.com>
Accept-Language: zh-TW, en-US
Content-Language: en-US
X-MS-Has-Attach: 
X-MS-TNEF-Correlator: 
x-mailer: Evolution 3.28.5-0ubuntu0.18.04.2
x-ms-publictraffictype: Email
x-ms-traffictypediagnostic: PUZPR03MB5964:EE_|KL1PR0302MB5219:EE_
x-ms-office365-filtering-correlation-id: e44d6acc-89e2-492a-df34-08db04ddd4be
x-ms-exchange-senderadcheck: 1
x-ms-exchange-antispam-relay: 0
x-microsoft-antispam: BCL:0;
x-microsoft-antispam-message-info: fzo5KyFdpqbPRxRj8fq4SQ/2TJZwv+ZlQJoZZhGFi5gVc9ueiCde+1j9vrCm9UaxIT1DhK0D2bJaJWvnLenS5iJgqDS2OmupErUaa247XfUsbVapPsBe5Q39/QincyWWlOCr3HIbWuGqSg5n/PAXNQiA5VTPZwfHG8TAvLy9LSXlq8nauwjQtaar0kbsLdUUO38NlwHN5I3PCTd4LBmMKM2l/lR2InH9Gy6OTTcs1Ly/D5Xyky0UFCOegmAEziLpfjObPd9zag4UrquEXRKVXjYd53pql4yvTt5cguG6A61SQQd/U+qbdROZZi/A9LhDUh6ZWBPzUihiiZ36u84t6bZ6zUUD43vGB6h0+ereq+wMY4dKBZf0RlZhHJgGxz24u1tJolzPT3Sx4exMgtf8OJzS9potb44nNbdHIZu4v6XIdWp368F4FP89WS4gcqweMXXf4G/mzsLHqLZkPh8uf2rl4wv7mxd5lfK7EbYdC7P17f5HYWktlHE6GXxEcUwRgFvCfnf8mhWVJm1oBVzrsKI0NKwkgR2Om+yON+Ndvb0+X4iZPMNazvm2ajKZ3eC3UKRrcilde0pHVcU8CGhoBUgpQOrXrkIr/BbeJFGdMRxb1u9jeJlsiCo9ak3xez5Rm37ANetFLiSpi6LbK220MhmTBjxRrw2h348Co1ygyYh1clfgILr1qHupR6Q8pdVjUKD0ZaYlQNesmnbeDJlS+PsarQWMvHhUkerZ51Bh+yk3WQwESZaLRn13FUb/DWDS
x-forefront-antispam-report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:PUZPR03MB5964.apcprd03.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230025)(4636009)(346002)(39860400002)(396003)(366004)(376002)(136003)(451199018)(91956017)(66446008)(66556008)(66946007)(66476007)(76116006)(83380400001)(86362001)(2616005)(38100700002)(38070700005)(122000001)(54906003)(36756003)(85182001)(64756008)(316002)(6512007)(26005)(186003)(110136005)(6506007)(6486002)(966005)(71200400001)(478600001)(2906002)(41300700001)(8936002)(5660300002)(8676002)(4326008)(99106002);DIR:OUT;SFP:1102;
x-ms-exchange-antispam-messagedata-chunkcount: 1
x-ms-exchange-antispam-messagedata-0: =?utf-8?B?b1FyRUFFZEhTVE9lcWx6dmJjdnhic3pXVTVrOGJWcTI3NS94N3Zuem5IbVdZ?=
 =?utf-8?B?TGVieVRUcyt5ZUtsZnpSU1pyTm9ZdzlTczZwUzVuaTFSS0VXejJQOUFGQTdM?=
 =?utf-8?B?UFJjY2laa0dsQWlNZGIycUtkV2FYUktSOVBJOE1ZaVVDTm00ZjU5Z2Ixc2tE?=
 =?utf-8?B?UXpneElHT0Vsb0h5US80ZWVoSGdlSTlpSVRzWUV3OUFDVGdyRSt4cEpiNHFk?=
 =?utf-8?B?UUhnT2xwa2JpcTk0YkFkQzQxMi9haytraExMS2hxSStneVAzUjhlcitMdU1s?=
 =?utf-8?B?aTkvVzRSRmx4VXNoUm5FcncvRlVLY2VDYTE4andvc2htRTVJNnNKbWFEMllC?=
 =?utf-8?B?aXM5azIrRzVrZjZUbWdkWjNrS2pHbUF6SnplSk8zdFBHRDNWa2tOWkc3ZnpJ?=
 =?utf-8?B?OHdCVGt5NjdMRHJDMjg0Wkgyakxtb1JsVkNra3ZiN2M2cUZ6MmtNTUVLVllF?=
 =?utf-8?B?eDZFU3F4d3g1Y3BZMXd4ZjNWTUpPTHo1MXBzQyt5dTI3WFViT04yTmpCdTFB?=
 =?utf-8?B?eU1BbklkdFh3Q2NRNUFIbHVEQjVaWXhzeTVJMzFwMnZDTnpnWEZOOW1pUDNx?=
 =?utf-8?B?UitzelFMeFlULzZ5UVN6VGNEeVV4djZlSENSQjVmT2FzY3VYY1Z0STdXM2RK?=
 =?utf-8?B?bUpHc1l1UUY4ZnJSaHVDZlErd3g0VUsxbkd3NjBTWlloTFd3ZzRLYWRaQk5j?=
 =?utf-8?B?WHZBeFBLN2dVWkJiUERqOTBaTGovcjJQZXB4czVnaDVzLzVqOTVFQkwrN1lo?=
 =?utf-8?B?RTkrZVVQQjd6SGMyS3NzNVU4aEk1a0hxaUNMUWZHK1drMkZJdVlzRnhHTE1Y?=
 =?utf-8?B?TXVTM2VhajNsSmhKSnVpbU9tY2Rqc0pnZlg5cWRrK2RPMUhxNlQxSlQ4djVo?=
 =?utf-8?B?cVJlYTNwWFJQa0h5QzRNajh4L2QwQ1Nkem1qaTgySiszYmdrQVZ5RWlGR05y?=
 =?utf-8?B?RWtIbG4yVlBmWlNnOS83c2tpMnhLSFBUWFNVdkllemkzWjdvcWVZL2JVQXd4?=
 =?utf-8?B?ZzExTTl0cU11THc4akozTkpha3dnbnNNanJPdGNMRGYxMm5ISkxlRysyYmFa?=
 =?utf-8?B?ZlBUNnltZUNEK1NPNi93bzB5M0Q3czBGRDd0V3B1VzUrazNKNUtZekJnTDk4?=
 =?utf-8?B?TmZVTnFpRThiR1lzWjlyTWd6b1A1N0g1WGova3FNVHJJN1NqKzZzSTRjSjNk?=
 =?utf-8?B?aU1hV1hmdDRyQVdsUFRrWGthWFNHZndQOG0vaytLR09Ra0RHSEIzd3NYSVBi?=
 =?utf-8?B?d3RhQ1E1T0IvSlZleStmZ1lYaVRjdVFyVHk0SkNhMjFPRnFzd29EbENZR2pn?=
 =?utf-8?B?Q0dFRStZcHE0eDhoTzlGb0ZRSVhnVkgwTWhxMHppUkY4MStHVTIxbGtXRm1s?=
 =?utf-8?B?NHJoazJmTUp3dERTd0UwTUJISnBhRlRyODREZHVMekpvbTBiempOME0wQklX?=
 =?utf-8?B?a0x0RHR4Z1lQUlRmOTFZREpVSE1vc2tMam5PZ2JDejBMb3A4MmxRZkIwWWd0?=
 =?utf-8?B?NFU2c1VobWN3QUVWb0ZOalo0NzQ1Q2NZUEZnVHozVllrQUVLTTUvRlNJZXhi?=
 =?utf-8?B?ckVoYW5ITEdzQ205VjZjOFdHQmFGZ2pLZEF5dWM4dFBadkNpRy9kL2d6TWo1?=
 =?utf-8?B?WCsvczR4YlJmRXdheVhkUjZ4RCtIOENJYTFvUEhjRm5pZFNlWXc2ZEpSRStq?=
 =?utf-8?B?akMwRW9QNWdaTE55NFZWcS9nRnRTYW5QcldYTHY5alhGb0FsWU80S1VvQlpW?=
 =?utf-8?B?cVBFSERFc3o4N3VhOVg4NCtxV2lpU2czUk4xM3lUSVVORVhQSnZzdG1WQkFy?=
 =?utf-8?B?dW5Ea1N6VWJrV2tKa2lzOGdYUStaaVVoK2ZxVlhkNzF1Q3B5VXlQVWdjK1pW?=
 =?utf-8?B?b3dwK0JSN0tMSlk2ZGcxYUxmV3o4QjNYeEFJUUtZNGdIYko1QUROekY1T0hI?=
 =?utf-8?B?RFFhMUU0ODY2R01rYzArekpXa2dRSEZaWUlCdytxcGVRUHNXR2llRStQdEdV?=
 =?utf-8?B?UmFZbjdicjgxaVBiV0Z3OFJmVzZBODFVWkNmdnNwWFUzN2JleURCTHVqQ01Z?=
 =?utf-8?B?YlRCbFFuejBHT0cwb21RblI2dC9YaTBPWExJdVdpMXZnY1ZPTjFWZTJ4ZXYy?=
 =?utf-8?B?SGJTMXFDV0Rrb2ZFUmQ5S3dER2VrN0krb0pGcXhZcUEwSDZSeHVGMTlKbVoy?=
 =?utf-8?Q?zzo/7C48Ld0YaokBt+tO8y0=3D?=
Content-Type: text/plain; charset="UTF-8"
Content-ID: <836AF8DB52E9E647A3FE22E720494D63@apcprd03.prod.outlook.com>
MIME-Version: 1.0
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-AuthSource: PUZPR03MB5964.apcprd03.prod.outlook.com
X-MS-Exchange-CrossTenant-Network-Message-Id: e44d6acc-89e2-492a-df34-08db04ddd4be
X-MS-Exchange-CrossTenant-originalarrivaltime: 02 Feb 2023 05:25:00.6462
 (UTC)
X-MS-Exchange-CrossTenant-fromentityheader: Hosted
X-MS-Exchange-CrossTenant-id: a7687ede-7a6b-4ef6-bace-642f677fbe31
X-MS-Exchange-CrossTenant-mailboxtype: HOSTED
X-MS-Exchange-CrossTenant-userprincipalname: nGdEJUUaCaP4AoznrQyfwSdNJ8i0Wv++tIPo2k/3xj8SkM3RVADJew31rn0XEoGFuMBVnFYjRNOutKMflG5cBj8DfCle3Q7xXtq6lmf7ytM=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: KL1PR0302MB5219
X-MTK: N
X-Original-Sender: Kuan-Ying.Lee@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@mediatek.com header.s=dk header.b=nhBSJ8nx;       dkim=pass
 header.i=@mediateko365.onmicrosoft.com header.s=selector2-mediateko365-onmicrosoft-com
 header.b=appsI3Bx;       arc=pass (i=1 spf=pass spfdomain=mediatek.com
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

On Fri, 2022-06-10 at 16:21 +0100, Catalin Marinas wrote:
> Hi,
> 
> That's a second attempt on fixing the race race between setting the
> allocation (in-memory) tags in a page and the corresponding logical
> tag
> in page->flags. Initial version here:
> 
> 
https://lore.kernel.org/r/20220517180945.756303-1-catalin.marinas@arm.com
> 
> This new series does not introduce any new GFP flags but instead
> always
> skips unpoisoning of the user pages (we already skip the poisoning on
> free). Any unpoisoned page will have the page->flags tag reset.
> 
> For the background:
> 
> On a system with MTE and KASAN_HW_TAGS enabled, when a page is
> allocated
> kasan_unpoison_pages() sets a random tag and saves it in page->flags
> so
> that page_to_virt() re-creates the correct tagged pointer. We need to
> ensure that the in-memory tags are visible before setting the
> page->flags:
> 
> P0 (__kasan_unpoison_range):    P1 (access via virt_to_page):
>   Wtags=x                         Rflags=x
>     |                               |
>     | DMB                           | address dependency
>     V                               V
>   Wflags=x                        Rtags=x
> 
> The first patch changes the order of page unpoisoning with the tag
> storing in page->flags. page_kasan_tag_set() has the right barriers
> through try_cmpxchg().
> 
> If a page is mapped in user-space with PROT_MTE, the architecture
> code
> will set the allocation tag to 0 and a subsequent page_to_virt()
> dereference will fault. We currently try to fix this by resetting the
> tag in page->flags so that it is 0xff (match-all, not faulting).
> However, setting the tags and flags can race with another CPU reading
> the flags (page_to_virt()) and barriers can't help, e.g.:
> 
> P0 (mte_sync_page_tags):        P1 (memcpy from virt_to_page):
>                                   Rflags!=0xff
>   Wflags=0xff
>   DMB (doesn't help)
>   Wtags=0
>                                   Rtags=0   // fault
> 
> Since clearing the flags in the arch code doesn't work, to do this at
> page allocation time when __GFP_SKIP_KASAN_UNPOISON is passed.
> 
> Thanks.
> 
> Catalin Marinas (4):
>   mm: kasan: Ensure the tags are visible before the tag in page-
> >flags
>   mm: kasan: Skip unpoisoning of user pages
>   mm: kasan: Skip page unpoisoning only if __GFP_SKIP_KASAN_UNPOISON
>   arm64: kasan: Revert "arm64: mte: reset the page tag in page-
> >flags"
> 
>  arch/arm64/kernel/hibernate.c |  5 -----
>  arch/arm64/kernel/mte.c       |  9 ---------
>  arch/arm64/mm/copypage.c      |  9 ---------
>  arch/arm64/mm/fault.c         |  1 -
>  arch/arm64/mm/mteswap.c       |  9 ---------
>  include/linux/gfp.h           |  2 +-
>  mm/kasan/common.c             |  3 ++-
>  mm/page_alloc.c               | 19 ++++++++++---------
>  8 files changed, 13 insertions(+), 44 deletions(-)
> 

Hi kasan maintainers,

We hit the following issue on the android-6.1 devices with MTE and HW
tag kasan enabled.

I observe that the anon flag doesn't have skip_kasan_poison and
skip_kasan_unpoison flag and kasantag is weird.

AFAIK, kasantag of anon flag needs to be 0x0.

[   71.953938] [T1403598] FramePolicy:
[name:report&]=========================================================
=========
[   71.955305] [T1403598] FramePolicy: [name:report&]BUG: KASAN:
invalid-access in copy_page+0x10/0xd0
[   71.956476] [T1403598] FramePolicy: [name:report&]Read at addr
f0ffff81332a8000 by task FramePolicy/3598
[   71.957673] [T1403598] FramePolicy: [name:report_hw_tags&]Pointer
tag: [f0], memory tag: [ff]
[   71.958746] [T1403598] FramePolicy: [name:report&]
[   71.959354] [T1403598] FramePolicy: CPU: 4 PID: 3598 Comm:
FramePolicy Tainted: G S      W  OE      6.1.0-mainline-android14-0-
ga8a53f83b9e4 #1
[   71.960978] [T1403598] FramePolicy: Hardware name: MT6985(ENG) (DT)
[   71.961767] [T1403598] FramePolicy: Call trace:
[   71.962338] [T1403598] FramePolicy:  dump_backtrace+0x108/0x158
[   71.963097] [T1403598] FramePolicy:  show_stack+0x20/0x48
[   71.963782] [T1403598] FramePolicy:  dump_stack_lvl+0x6c/0x88
[   71.964512] [T1403598] FramePolicy:  print_report+0x2cc/0xa64
[   71.965263] [T1403598] FramePolicy:  kasan_report+0xb8/0x138
[   71.965986] [T1403598] FramePolicy:  __do_kernel_fault+0xd4/0x248
[   71.966782] [T1403598] FramePolicy:  do_bad_area+0x38/0xe8
[   71.967484] [T1403598] FramePolicy:  do_tag_check_fault+0x24/0x38
[   71.968261] [T1403598] FramePolicy:  do_mem_abort+0x48/0xb0
[   71.968973] [T1403598] FramePolicy:  el1_abort+0x44/0x68
[   71.969646] [T1403598] FramePolicy:  el1h_64_sync_handler+0x68/0xb8
[   71.970440] [T1403598] FramePolicy:  el1h_64_sync+0x68/0x6c
[   71.971146] [T1403598] FramePolicy:  copy_page+0x10/0xd0
[   71.971824] [T1403598] FramePolicy:  copy_user_highpage+0x20/0x40
[   71.972603] [T1403598] FramePolicy:  wp_page_copy+0xd0/0x9f8
[   71.973344] [T1403598] FramePolicy:  do_wp_page+0x374/0x3b0
[   71.974056] [T1403598] FramePolicy:  handle_mm_fault+0x3ec/0x119c
[   71.974833] [T1403598] FramePolicy:  do_page_fault+0x344/0x4ac
[   71.975583] [T1403598] FramePolicy:  do_mem_abort+0x48/0xb0
[   71.976294] [T1403598] FramePolicy:  el0_da+0x4c/0xe0
[   71.976934] [T1403598] FramePolicy:  el0t_64_sync_handler+0xd4/0xfc
[   71.977725] [T1403598] FramePolicy:  el0t_64_sync+0x1a0/0x1a4
[   71.978451] [T1403598] FramePolicy: [name:report&]
[   71.979057] [T1403598] FramePolicy: [name:report&]The buggy address
belongs to the physical page:
[   71.980173] [T1403598] FramePolicy:
[name:debug&]page:fffffffe04ccaa00 refcount:14 mapcount:13
mapping:0000000000000000 index:0x7884c74 pfn:0x1732a8
[   71.981849] [T1403598] FramePolicy:
[name:debug&]memcg:faffff80c0241000
[   71.982680] [T1403598] FramePolicy: [name:debug&]anon flags:
0x43c000000048003e(referenced|uptodate|dirty|lru|active|swapbacked|arch
_2|zone=1|kasantag=0xf)
[   71.984446] [T1403598] FramePolicy: raw: 43c000000048003e
fffffffe04b99648 fffffffe04cca308 f2ffff8103390831
[   71.985684] [T1403598] FramePolicy: raw: 0000000007884c74
0000000000000000 0000000e0000000c faffff80c0241000
[   71.986919] [T1403598] FramePolicy: [name:debug&]page dumped
because: kasan: bad access detected
[   71.988022] [T1403598] FramePolicy: [name:report&]
[   71.988624] [T1403598] FramePolicy: [name:report&]Memory state
around the buggy address:
[   71.989641] [T1403598] FramePolicy:  ffffff81332a7e00: fe fe fe fe
fe fe fe fe fe fe fe fe fe fe fe fe
[   71.990811] [T1403598] FramePolicy:  ffffff81332a7f00: fe fe fe fe
fe fe fe fe fe fe fe fe fe fe fe fe
[   71.991982] [T1403598] FramePolicy: >ffffff81332a8000: ff ff ff ff
f0 f0 fc fc fc fc fc fc fc f0 f0 f3
[   71.993149] [T1403598] FramePolicy:
[name:report&]                   ^
[   71.993972] [T1403598] FramePolicy:  ffffff81332a8100: f3 f3 f3 f3
f3 f3 f0 f0 f8 f8 f8 f8 f8 f8 f8 f0
[   71.995141] [T1403598] FramePolicy:  ffffff81332a8200: f0 fb fb fb
fb fb fb fb f0 f0 fe fe fe fe fe fe
[   71.996332] [T1403598] FramePolicy:
[name:report&]=========================================================
=========

Originally, I suspect that some userspace pages have been migrated so
the page->flags will be lost and page->flags is re-generated by
alloc_pages().

I try the following diff, but it didn't help.

diff --git a/mm/migrate.c b/mm/migrate.c
index dff333593a8a..ed2065908418 100644
--- a/mm/migrate.c
+++ b/mm/migrate.c
@@ -51,6 +51,7 @@
 #include <linux/random.h>
 #include <linux/sched/sysctl.h>
 #include <linux/memory-tiers.h>
+#include <linux/kasan.h>
 
 #include <asm/tlbflush.h>
 
@@ -611,6 +612,14 @@ void folio_migrate_flags(struct folio *newfolio,
struct folio *folio)
 
 	if (!folio_test_hugetlb(folio))
 		mem_cgroup_migrate(folio, newfolio);
+
+#ifdef CONFIG_KASAN_HW_TAGS
+	if (kasan_hw_tags_enabled()) {
+		if (folio_test_skip_kasan_poison(folio))
+			folio_set_skip_kasan_poison(newfolio);
+		page_kasan_tag_set(&newfolio->page,
page_kasan_tag(&folio->page));
+	}
+#endif
 }
 EXPORT_SYMBOL(folio_migrate_flags);
 

After I revert this patchset (4 patches), this issue disappear.

> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/66cc7277b0e9778ba33e8b22a4a51c19a50fe6f0.camel%40mediatek.com.
