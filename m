Return-Path: <kasan-dev+bncBCINXLESYINBB7O2S2PQMGQEWVZNL7I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23b.google.com (mail-lj1-x23b.google.com [IPv6:2a00:1450:4864:20::23b])
	by mail.lfdr.de (Postfix) with ESMTPS id 5415E6916B6
	for <lists+kasan-dev@lfdr.de>; Fri, 10 Feb 2023 03:35:42 +0100 (CET)
Received: by mail-lj1-x23b.google.com with SMTP id r17-20020a2eb891000000b00290658792cesf1039220ljp.4
        for <lists+kasan-dev@lfdr.de>; Thu, 09 Feb 2023 18:35:42 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1675996541; cv=pass;
        d=google.com; s=arc-20160816;
        b=DycoPBv2lihujuVH8FmJBKo/S8grGzDWXgO7/GrPxbL5I3H533A+LB88p4KZHpxm85
         pZfZDw0x1AsRWtVUdPux0+Qu2vHmgKzrd+aJbeujgGH3aDRH34jIQ3ROlPnR1ZmcXU/f
         WYmfCkxA+8+f8LCfBr1jfPmfriBfdvbZmkdkf9PglgFMNe3cpYAbjwfppi0GoGufNYua
         VGrPKOY0WBnYxyiaXmE85TIXi2f/ate+MYI2kj5+oW8E0XnIWYdbpS4bh2eq/C11CbQA
         W1EnbMxogp+pYbgh/xpqvdpsMin3M1YETy0BwX1mvENkSvXAXRJdyjx6UVrXhr8jfWrs
         GL0g==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version
         :content-transfer-encoding:content-language:accept-language
         :in-reply-to:references:message-id:date:thread-index:thread-topic
         :subject:cc:to:from:sender:dkim-signature;
        bh=wfYQi1vigedOYlhOxEGysgL2WOcLtohJ6Z3Aj2/ZvMA=;
        b=ut1nxZ9oYzA5LqpdUdYjO3rjZXVI9HoSpwJ6ZlH8nyAYeSUwSf9h+8K6PukmPbM//e
         PrLyenI10EYzC1Ezlm+gIitaOWeiVf+ZlpsMueJXSIJOjMZJbZYoJJtNkORNR3+mCJ7o
         T/7iq7yuIQI8SNVbucPcSCaE8ZGWPmoY6nqRmQcFVaksT50RW3+9flw/fmvSrpt7II43
         NdXzBJGCGNzXVpvzmpYIOBEDuczlvF3XyNq9yayHyiXAVETx8dzdEjHoPqRGEEx2hif3
         triQ4NhKTyBLY7DjLOeK20Jh5vEWepElB/qQTSRfaNb028CX6gReXH6Rw6hB5kqzkiYI
         dEdA==
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@zeku.com header.s=selector1 header.b=VXUDygMd;
       arc=pass (i=1 spf=pass spfdomain=zeku.com dmarc=pass fromdomain=zeku.com);
       spf=pass (google.com: domain of yuanshuai@zeku.com designates 2a01:111:f403:704b::704 as permitted sender) smtp.mailfrom=yuanshuai@zeku.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=zeku.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:content-transfer-encoding
         :content-language:accept-language:in-reply-to:references:message-id
         :date:thread-index:thread-topic:subject:cc:to:from:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=wfYQi1vigedOYlhOxEGysgL2WOcLtohJ6Z3Aj2/ZvMA=;
        b=pkpYQcTySCDvWFx9b3doZcigGkbu+DSOL04fVE8RsS2Lpj+WKRDNJilSEpVb5dc9RS
         STBVQRxAU7IJhxfEJ5BWluOK0GJLaNx8xNmXv1SUkiXadT0cEU32sgGL6FxsO8BfFUoD
         tCsJhGhYM+VAoMFqRlUsID97g9BqmPEbSOpen4E5zNLKyULtM/krTZI3by5hRBur13N4
         vsuK2MbuylgTJJfFHbQXirm9xnb/EeCGb3ePxZSugxuWKE4oDhx2O1iImX0MFuciQ7LP
         zUrsdY+Ab0yzWU3BYVtus9IMUP2cITIRdQxVdpggZWJkAVHd10RMU11NXrf3tISWi6S0
         BAog==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :content-transfer-encoding:content-language:accept-language
         :in-reply-to:references:message-id:date:thread-index:thread-topic
         :subject:cc:to:from:x-gm-message-state:sender:from:to:cc:subject
         :date:message-id:reply-to;
        bh=wfYQi1vigedOYlhOxEGysgL2WOcLtohJ6Z3Aj2/ZvMA=;
        b=CWdGDPT0oo1JYc/+pueKkluj3p2PUEjoZUIMEKdrzfsh7aswlk+BcdVAG3proGQY7s
         soyyFqipEr8jgq5KxpxOT+ztEojntPnKqIuN/Y4DpqlgiHu6S1VLfJyYMOjVGmvJWGwJ
         mQSSaMSMWOKUfSxf3hSnaZ/47ZS++bgBR4K6x8yYiHSKvuCt2x3OjmbXU0//7Qd4BXwx
         fU4Q/0jhPo4Dh+7Qvoa5YObCPxtMh5DXnZv/sHxE6M74RpTkUQVJXp96/LpvQH+gm7Zl
         aerK8LC1mLu5VCyxoX3Brcb6Bc9soJCNWNzaH20Uw+/v19siqlyG51c35iNM/2e/n4ME
         6IlQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKXLOS+0cR1b35rEzQvifUzgNwN/gknPT/9jNyvU9UCnHmnFIP2P
	34SJKoY/NloxxaALVzBDqqk=
X-Google-Smtp-Source: AK7set9LaDhbP1ZUyydkD1v7KKkrjz5AJhSImPDK9pYouacPPbsaMGbdLkJOHJKPfe4sabCGYPRCwg==
X-Received: by 2002:ac2:4a99:0:b0:4a2:4b43:9aad with SMTP id l25-20020ac24a99000000b004a24b439aadmr2069361lfp.213.1675996541370;
        Thu, 09 Feb 2023 18:35:41 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:239f:b0:4cf:ff9f:bbfd with SMTP id
 c31-20020a056512239f00b004cfff9fbbfdls2641003lfv.1.-pod-prod-gmail; Thu, 09
 Feb 2023 18:35:40 -0800 (PST)
X-Received: by 2002:ac2:4f86:0:b0:4cc:725d:9d3d with SMTP id z6-20020ac24f86000000b004cc725d9d3dmr4040083lfs.54.1675996539921;
        Thu, 09 Feb 2023 18:35:39 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1675996539; cv=pass;
        d=google.com; s=arc-20160816;
        b=kpyv6v4sFKdWVPB7u79Q7U6Aht/OKT/ocIxcRLtteMLmNgC8W3URbzdFsRQ6TsT64k
         /M3QLNy7TPR9pfwQKJpXYjnDXGEJ3DgFMnpoiibgRAy45Vd+3bs7Js7ZGSL2rWIfR+0/
         IdumyXIx+qo+9xZxLOwKv1JwHZXCdRJ90iNva9JkHr0HlVxz5021/BOeWaJHjAzXNPbl
         x4o+y3Y0OcfAdz+Uw4T453SDpPZRWNi5WZeDvTNvKvSK5m2CuOZUUkj7cyvvVQJwPabX
         nv+7EK+PbUyAwr0prHFKvrdX5IPbe2lXi/jy747S0j/ydLwhncuDtmIGCLEIC24JWuIc
         evnA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-transfer-encoding:content-language
         :accept-language:in-reply-to:references:message-id:date:thread-index
         :thread-topic:subject:cc:to:from:dkim-signature;
        bh=b0yKomsjRaumVznH1jBW7gj+dR6xWuoQ6qn0ryUfhNo=;
        b=pInkmY4VWS5RP/hv/V5OZtRtXQGHqgSTy3s0IBdEEkOg5Jxlh7llDWvjY6mvnVVj/K
         91w7akuMiha+OYzAoezjBj8xY2Yk2fJZBnDpPzn9NgSi/Amx92VEdjkzo0+Kjb2thVx9
         7j7bxUcp7V5bewKWBPNhtFPkTL6knhYSYX8hTTQPd/Pmr5qdNsOsYAqXP/CpiFvlZqX0
         z/mDYD0g8oJYFPRcqa+6jRP2HcYDrO7okUUEyqXZUTvzmCUbCgAheJaoGhlfy9h9ME6D
         q9FxaVaRZNv46rpWPsPKZntaaT8y6Vxu9mXv8eKJ7t9zJoqCBWmZQGSLwHOtu9/2RshW
         ab4w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@zeku.com header.s=selector1 header.b=VXUDygMd;
       arc=pass (i=1 spf=pass spfdomain=zeku.com dmarc=pass fromdomain=zeku.com);
       spf=pass (google.com: domain of yuanshuai@zeku.com designates 2a01:111:f403:704b::704 as permitted sender) smtp.mailfrom=yuanshuai@zeku.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=zeku.com
Received: from APC01-TYZ-obe.outbound.protection.outlook.com (mail-tyzapc01on20704.outbound.protection.outlook.com. [2a01:111:f403:704b::704])
        by gmr-mx.google.com with ESMTPS id be18-20020a056512251200b004d09f629f63si192188lfb.8.2023.02.09.18.35.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 09 Feb 2023 18:35:39 -0800 (PST)
Received-SPF: pass (google.com: domain of yuanshuai@zeku.com designates 2a01:111:f403:704b::704 as permitted sender) client-ip=2a01:111:f403:704b::704;
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=TGVvx9gYG87xo1bxpoPx4UzGPTMK6wgpZZLS5uo66T/H/X+ZK+K4Pk13W+sYvoiqqn4DQP1X32bBsGfl2pj/kBtTiR7LXORnIxYCk0CHZNnbl53pj2dJ2sZRIJcMF1iQcdKADupQu6TYW6MjHLzl7ve2unbjPFJZq11pFxVzewjWwsbMSHndu0PTpZcbKvOskDKMjep8m7YDdwr7LE25KeBKoqHpJEI4s7KOQ+I7L3zzXia6UCqYrVHNpiqhQzqZ/mN/EDEZP++PqQnXrk8fC01oiEYC53vvbeutcaW1aRVPSK28TauK/ScP9ZfmMtH2F5X/3YS9W5hMEwESjxtMjA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=b0yKomsjRaumVznH1jBW7gj+dR6xWuoQ6qn0ryUfhNo=;
 b=F+j+7GijukDc34JHY3thdZU7xwpdzO3yMMmhjvMuup5b2ZgPmPGetmIQ2+vl4WKAr/nxLyvRU7u+3xu42SEUKYo6XeyeEBFSftt+zFQnvDQf5JCak49KMeS0wuAb/NE0GNKAmVIaJZNSy4O/jKhlI0+ot1XD+eZ6eJ0gVyQz2AtZao5h48EmucNYj3nWZzJUlgKgtTYtCW6o2/ZiDmBGwDl+GMrD8WU2boFNMkbEWA+OiLOBQrfIGq9+jMoDcnokEFwbSYt2hFPgLnwwNcHLyx7d8hFeNZZWVkOcdUE/qMVZ98VbL1BO0+zWwGuKng9Tu7b/VEd5h2YJ40okd24bLA==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass (sender ip is
 103.192.253.182) smtp.rcpttodomain=gmail.com smtp.mailfrom=zeku.com;
 dmarc=pass (p=none sp=none pct=100) action=none header.from=zeku.com;
 dkim=none (message not signed); arc=none
Received: from PS2PR01CA0048.apcprd01.prod.exchangelabs.com
 (2603:1096:300:58::36) by TYZPR02MB6161.apcprd02.prod.outlook.com
 (2603:1096:400:28a::8) with Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.6086.18; Fri, 10 Feb
 2023 02:35:36 +0000
Received: from PSAAPC01FT049.eop-APC01.prod.protection.outlook.com
 (2603:1096:300:58:cafe::d3) by PS2PR01CA0048.outlook.office365.com
 (2603:1096:300:58::36) with Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.6086.19 via Frontend
 Transport; Fri, 10 Feb 2023 02:35:36 +0000
X-MS-Exchange-Authentication-Results: spf=pass (sender IP is 103.192.253.182)
 smtp.mailfrom=zeku.com; dkim=none (message not signed)
 header.d=none;dmarc=pass action=none header.from=zeku.com;
Received-SPF: Pass (protection.outlook.com: domain of zeku.com designates
 103.192.253.182 as permitted sender) receiver=protection.outlook.com;
 client-ip=103.192.253.182; helo=sh-exhtc2.internal.zeku.com; pr=C
Received: from sh-exhtc2.internal.zeku.com (103.192.253.182) by
 PSAAPC01FT049.mail.protection.outlook.com (10.13.39.177) with Microsoft SMTP
 Server (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.20.6086.19 via Frontend Transport; Fri, 10 Feb 2023 02:35:36 +0000
Received: from sh-exhtc5.internal.zeku.com (10.123.154.252) by
 sh-exhtc2.internal.zeku.com (10.123.21.106) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2375.12; Fri, 10 Feb 2023 10:32:30 +0800
Received: from sh-exhtc4.internal.zeku.com (10.123.154.251) by
 sh-exhtc5.internal.zeku.com (10.123.154.252) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.2.986.5;
 Fri, 10 Feb 2023 10:32:29 +0800
Received: from sh-exhtc4.internal.zeku.com ([fe80::b447:eb25:37fd:3fd8]) by
 sh-exhtc4.internal.zeku.com ([fe80::b447:eb25:37fd:3fd8%3]) with mapi id
 15.02.0986.005; Fri, 10 Feb 2023 10:32:29 +0800
From: =?utf-8?B?6KKB5biFKFNodWFpIFl1YW4p?= <yuanshuai@zeku.com>
To: Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov
	<dvyukov@google.com>
CC: =?utf-8?B?5qyn6Ziz54Kc6ZKKKFdlaXpoYW8gT3V5YW5nKQ==?=
	<ouyangweizhao@zeku.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander
 Potapenko <glider@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Andrew Morton <akpm@linux-foundation.org>, "kasan-dev@googlegroups.com"
	<kasan-dev@googlegroups.com>, "linux-mm@kvack.org" <linux-mm@kvack.org>,
	"linux-kernel@vger.kernel.org" <linux-kernel@vger.kernel.org>, Weizhao Ouyang
	<o451686892@gmail.com>, =?utf-8?B?5Lu756uL6bmPKFBlbmcgUmVuKQ==?=
	<renlipeng@zeku.com>
Subject: RE: [PATCH v2] kasan: fix deadlock in start_report()
Thread-Topic: [PATCH v2] kasan: fix deadlock in start_report()
Thread-Index: AQHZPDZzScKWhyj5L0eV70o/eMb/rq7FygeAgACH4+D//5aGAIAAy+8AgAC6aDA=
Date: Fri, 10 Feb 2023 02:32:29 +0000
Message-ID: <b058a424e46d4f94a1f2fdc61292606b@zeku.com>
References: <20230209031159.2337445-1-ouyangweizhao@zeku.com>
 <CACT4Y+Zrz4KOU82jjEperYOM0sEp6TCmgse4XVMPkwAkS+dXrA@mail.gmail.com>
 <93b94f59016145adbb1e01311a1103f8@zeku.com>
 <CACT4Y+a=BaMNUf=_suQ5or9=ZksX2ht9gX8=XBSDEgHogyy3mg@mail.gmail.com>
 <CA+fCnZf3k-rsaOeti0Q7rqkmvsqDb2XxgxOq6V5Gqp6FGLH7Yg@mail.gmail.com>
In-Reply-To: <CA+fCnZf3k-rsaOeti0Q7rqkmvsqDb2XxgxOq6V5Gqp6FGLH7Yg@mail.gmail.com>
Accept-Language: zh-CN, en-US
Content-Language: zh-CN
X-MS-Has-Attach: 
X-MS-TNEF-Correlator: 
x-originating-ip: [10.122.89.15]
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
MIME-Version: 1.0
X-EOPAttributedMessage: 0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: PSAAPC01FT049:EE_|TYZPR02MB6161:EE_
X-MS-Office365-Filtering-Correlation-Id: aff9e88e-5d38-48f6-f4f9-08db0b0f7d9d
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;
X-Microsoft-Antispam-Message-Info: y6LRCeDAcY71pXlxfgRGa74xJa9NWLWxXYi+6K5tCUzNo3XXIpSBcbVqT3ksJGnHlCBu/GnN9+4AEqCUy++d0f9Jkh2rnpignpKDsZza8DHJIFwl64JwFBmPpXORKRrYtmcT530FiZyPoTGCwBlsa9U1nvq5rDNczlJQgtds9JhFF62rh2hTYOosIslJ1yEkwXTphFVrSi9N6Ke91TGM8PBfgQi5W7X8gNFQHFaqdF3RUmG2LY6FVHu10snRxQms4KfLUUGMJTch0FtleJgoT/RChYEF1PklD16+3rJK8syfZCm/NY9ra1g1V8Al8Izz7nXMxz09PasPBXCnqq+A3tKbQVRGd//xN1dIcnCP9hjIXQ1lBpHhMm/t6Zt1YwaID/rPC8BTsSezsWoroLFI3lk4OvjljyPaeBOove0X6IU0Sa2OPSKsLgVdd+FNkzZyiC2Gfb/iqF8G7ZyCQ+dsE5xLm988kLAP5BAyCBuhhi6d/0pemkGr+ewYyAXYAIxIqwxBq+ivmV1Kl+MtoncoLLbvWhVYPNi/nktPDt05G1aXJIFuBH4ke2QjV2+sSKeoxcNyfeopA8GnUEQ2X/C49jVOFbN4op3yke1FKDUCNfHi8dPD7RCZBjUAW3zN8yYYOxmdgg+9MP33KROcauJvvsbEwqo5rvXYSn5hS8lZ/shjpWKSgy4Kjl+sK0dtSz3QHbAu2nBe7LgjeOnYZVqp6aamnKPY5r+Zt5ZZvKIFT/o=
X-Forefront-Antispam-Report: CIP:103.192.253.182;CTRY:CN;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:sh-exhtc2.internal.zeku.com;PTR:InfoDomainNonexistent;CAT:NONE;SFS:(13230025)(4636009)(346002)(376002)(396003)(39850400004)(136003)(451199018)(36840700001)(46966006)(2906002)(186003)(7416002)(86362001)(426003)(47076005)(108616005)(2616005)(8936002)(81166007)(336012)(5660300002)(26005)(82310400005)(36756003)(966005)(7696005)(478600001)(53546011)(24736004)(85182001)(107886003)(83380400001)(316002)(41300700001)(4326008)(40480700001)(8676002)(70586007)(82740400003)(54906003)(356005)(36860700001)(70206006)(110136005)(36900700001);DIR:OUT;SFP:1102;
X-OriginatorOrg: zeku.com
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 10 Feb 2023 02:35:36.1101
 (UTC)
X-MS-Exchange-CrossTenant-Network-Message-Id: aff9e88e-5d38-48f6-f4f9-08db0b0f7d9d
X-MS-Exchange-CrossTenant-Id: 171aedba-f024-43df-bc82-290d40e185ac
X-MS-Exchange-CrossTenant-OriginalAttributedTenantConnectingIp: TenantId=171aedba-f024-43df-bc82-290d40e185ac;Ip=[103.192.253.182];Helo=[sh-exhtc2.internal.zeku.com]
X-MS-Exchange-CrossTenant-AuthSource: PSAAPC01FT049.eop-APC01.prod.protection.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Anonymous
X-MS-Exchange-CrossTenant-FromEntityHeader: HybridOnPrem
X-MS-Exchange-Transport-CrossTenantHeadersStamped: TYZPR02MB6161
X-Original-Sender: yuanshuai@zeku.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@zeku.com header.s=selector1 header.b=VXUDygMd;       arc=pass (i=1
 spf=pass spfdomain=zeku.com dmarc=pass fromdomain=zeku.com);       spf=pass
 (google.com: domain of yuanshuai@zeku.com designates 2a01:111:f403:704b::704
 as permitted sender) smtp.mailfrom=yuanshuai@zeku.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=zeku.com
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

On Friday, February 10, 2023 at 6:54 AM Andrey Konovalov <andreyknvl@gmail.=
com>
wrote:
> On Thu, Feb 9, 2023 at 11:44 AM Dmitry Vyukov <dvyukov@google.com>
> wrote:
> >
> >  On Thu, 9 Feb 2023 at 10:19, =E8=A2=81=E5=B8=85(Shuai Yuan) <yuanshuai=
@zeku.com>
> wrote:
> > >
> > > Hi Dmitry Vyukov
> > >
> > > Thanks, I see that your means.
> > >
> > > Currently, report_suppressed() seem not work in Kasan-HW mode, it
> always return false.
> > > Do you think should change the report_suppressed function?
> > > I don't know why CONFIG_KASAN_HW_TAGS was blocked separately
> before.
> >
> > That logic was added by Andrey in:
> > https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/com
> > mit/?id=3Dc068664c97c7cf
> >
> > Andrey, can we make report_enabled() check current->kasan_depth and
> > remove report_suppressed()?
>
> I decided to not use kasan_depth for HW_TAGS, as we can always use a
> match-all tag to make "invalid" memory accesses.
>
> I think we can fix the reporting code to do exactly that so that it doesn=
't
> cause MTE faults.
>
> Shuai, could you clarify, at which point due kasan_report_invalid_free an
> MTE exception is raised in your tests?

Yes, I need some time to clarify this problem with a clear log by test.

> > Then we can also remove the comment in kasan_report_invalid_free().
> >
> > It looks like kasan_disable_current() in kmemleak needs to affect
> > HW_TAGS mode as well:
> > https://elixir.bootlin.com/linux/v6.2-rc7/source/mm/kmemleak.c#L301
>
> It uses kasan_reset_tag, so it should work properly with HW_TAGS.
ZEKU
=E4=BF=A1=E6=81=AF=E5=AE=89=E5=85=A8=E5=A3=B0=E6=98=8E=EF=BC=9A=E6=9C=AC=E9=
=82=AE=E4=BB=B6=E5=8C=85=E5=90=AB=E4=BF=A1=E6=81=AF=E5=BD=92=E5=8F=91=E4=BB=
=B6=E4=BA=BA=E6=89=80=E5=9C=A8=E7=BB=84=E7=BB=87ZEKU=E6=89=80=E6=9C=89=E3=
=80=82 =E7=A6=81=E6=AD=A2=E4=BB=BB=E4=BD=95=E4=BA=BA=E5=9C=A8=E6=9C=AA=E7=
=BB=8F=E6=8E=88=E6=9D=83=E7=9A=84=E6=83=85=E5=86=B5=E4=B8=8B=E4=BB=A5=E4=BB=
=BB=E4=BD=95=E5=BD=A2=E5=BC=8F=EF=BC=88=E5=8C=85=E6=8B=AC=E4=BD=86=E4=B8=8D=
=E9=99=90=E4=BA=8E=E5=85=A8=E9=83=A8=E6=88=96=E9=83=A8=E5=88=86=E6=8A=AB=E9=
=9C=B2=E3=80=81=E5=A4=8D=E5=88=B6=E6=88=96=E4=BC=A0=E6=92=AD=EF=BC=89=E4=BD=
=BF=E7=94=A8=E5=8C=85=E5=90=AB=E7=9A=84=E4=BF=A1=E6=81=AF=E3=80=82=E8=8B=A5=
=E6=82=A8=E9=94=99=E6=94=B6=E4=BA=86=E6=9C=AC=E9=82=AE=E4=BB=B6=EF=BC=8C=E8=
=AF=B7=E7=AB=8B=E5=8D=B3=E7=94=B5=E8=AF=9D=E6=88=96=E9=82=AE=E4=BB=B6=E9=80=
=9A=E7=9F=A5=E5=8F=91=E4=BB=B6=E4=BA=BA=EF=BC=8C=E5=B9=B6=E5=88=A0=E9=99=A4=
=E6=9C=AC=E9=82=AE=E4=BB=B6=E5=8F=8A=E9=99=84=E4=BB=B6=E3=80=82
Information Security Notice: The information contained in this mail is sole=
ly property of the sender's organization ZEKU. Any use of the information c=
ontained herein in any way (including, but not limited to, total or partial=
 disclosure, reproduction, or dissemination) by persons other than the inte=
nded recipient(s) is prohibited. If you receive this email in error, please=
 notify the sender by phone or email immediately and delete it.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/b058a424e46d4f94a1f2fdc61292606b%40zeku.com.
