Return-Path: <kasan-dev+bncBCINXLESYINBBJXVSKPQMGQE3SRPVPQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x237.google.com (mail-lj1-x237.google.com [IPv6:2a00:1450:4864:20::237])
	by mail.lfdr.de (Postfix) with ESMTPS id E71EE690331
	for <lists+kasan-dev@lfdr.de>; Thu,  9 Feb 2023 10:19:35 +0100 (CET)
Received: by mail-lj1-x237.google.com with SMTP id j13-20020a2ea90d000000b002904f23836bsf230201ljq.17
        for <lists+kasan-dev@lfdr.de>; Thu, 09 Feb 2023 01:19:35 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1675934375; cv=pass;
        d=google.com; s=arc-20160816;
        b=zwXvHOmhof1Ap0njMxce1j0j4GpA8BLWUqHbkT+JJpXijl8CdI5925R/wbuHfuUH+t
         fzB7EKWfdRww3OR/HooBBSeAoNKzkP8LhRhkEDf8M81UN+iXNHSz2mx/cP/cqP604QdW
         W1YFPtLtJNPzGDRvzkRYc9q+y09Y27XjgamK64oDY/BnO1gd/HhT+f5oLSlUpfZUHSuE
         FR6SGZLQs18FJ68JTO57JI8KA9zW199DpBfajQsWRMjn9ULkv/qo9XYk1YELaBYYVPHf
         4kLdTnklLYoU+F6trZLoIMnMKqwJ4NKomvbfhdqePVUqXFSIfuUwbtzQG/Q43yjVRKHZ
         7YkA==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version
         :content-transfer-encoding:content-language:accept-language
         :in-reply-to:references:message-id:date:thread-index:thread-topic
         :subject:cc:to:from:sender:dkim-signature;
        bh=fcli6pdFtx59Hm3Yh5OJVeWDUR/7P6XvYI8kvRSat0o=;
        b=Ac+aab1YndXGk1IgJQUWtQLw19R8/m8FS7r1iJcbvRrkyLNKZZNpe0s7wwphNHlBbs
         9JI/qt9WzERu011l8mYI8xyWJoE931tpNiIiLwCdeXA3eeENYPJS7ERu+Ki6R4NYw7fX
         esOY7pGa4Dl8VbHD8odODlQ2MUrx26atm8z/B1pbdR0GvLlp5sfUbp7Ay3iOQ1n/E0sy
         ElqOJSkHMt38ncQC/ec394nQOev0Jmz/R9A9VmZrLK1Q/qiOiGdGXTXGtpTiRZnP2arr
         a3aapS7vuwnzO1AuhzNJ6GxlerjRM9DzilkBQh8y1QFQs/zOuETnYYMt9w0CRBbnAJKY
         NWwQ==
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@zeku.com header.s=selector1 header.b=73wEl8j7;
       arc=pass (i=1 spf=pass spfdomain=zeku.com dmarc=pass fromdomain=zeku.com);
       spf=pass (google.com: domain of yuanshuai@zeku.com designates 2a01:111:f400:feab::721 as permitted sender) smtp.mailfrom=yuanshuai@zeku.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=zeku.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:content-transfer-encoding
         :content-language:accept-language:in-reply-to:references:message-id
         :date:thread-index:thread-topic:subject:cc:to:from:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=fcli6pdFtx59Hm3Yh5OJVeWDUR/7P6XvYI8kvRSat0o=;
        b=k/cr+wv60CTPkLqR+mHDC6eUjfSOxFTAgnV9U0WyVmALONeNym9xZvTI5TUedGGwMI
         ojvvNZEsNG0ddevhAmWGocnXqESXxLPL1loNm8jUMPx6LyJcUEIcMUpqE3qV9Uu33PU3
         BLE8+dbhg7qsz6yf4UdaZQ4lY2asEYfkD3pVPpA6eeIRzX/7kAJ5dLzb0aaiHou05j9S
         dGapgwyQG5cF6mQXoLSi56fBUBWAGnrQhLph0SfRxyGPa7akRGzfwK3zRGJbkeCsNz58
         pOWt/ElY/jecOAIhuombXcwl24femZb/Qv7aNFSI1TewqRPVC7GATTXupW0XEjK6cOC+
         y+7g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :content-transfer-encoding:content-language:accept-language
         :in-reply-to:references:message-id:date:thread-index:thread-topic
         :subject:cc:to:from:x-gm-message-state:sender:from:to:cc:subject
         :date:message-id:reply-to;
        bh=fcli6pdFtx59Hm3Yh5OJVeWDUR/7P6XvYI8kvRSat0o=;
        b=3VtO/UQNxtCNzJ8DWIRTOEC6IdNuN79nAOym0sKyd7lTDErheldbmsc0Ix8iNrsACY
         lB7Ye0QoiK70LeF+rKk8nRmCuy4mQgzRg8qKtt2L7mJtmhQeGo4V7ft8PIvp8HCoepq9
         1jwpLDJCldAmP2tIO04fPOrHDzFfstpAK8sasWdTHd4vQ4SrEL8p2cxOFBaI02Mllo8U
         yiRNEgzXhcyFqH+nuPDri4u35fRqOj2+qKtfEi3J7wXFt1q0fET12/RemgaSIfvZ2KZB
         UIN4aEHWBnI07YUivlXrPvQG3Z20XDET/5ZaIIYvMgHi42wh7iWHvMatoIlxSh46jyiI
         Algw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKXJTqLTSpobTPb+6v1V0BX47zfdvCdWUGDTqSV0ALlB0LXq3mzt
	qXPSLBRR6Qjdir6wrUMZVRQ=
X-Google-Smtp-Source: AK7set9T47x2Zx6y0on3mHB/i0XV3hqu3G/o7knH53UhlY5tE5c2Uo+VxJmmQpwqMcof3LyOlRECMQ==
X-Received: by 2002:a05:6512:910:b0:4d7:bda4:e6af with SMTP id e16-20020a056512091000b004d7bda4e6afmr1789314lft.184.1675934375095;
        Thu, 09 Feb 2023 01:19:35 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:239f:b0:4cf:ff9f:bbfd with SMTP id
 c31-20020a056512239f00b004cfff9fbbfdls995891lfv.1.-pod-prod-gmail; Thu, 09
 Feb 2023 01:19:33 -0800 (PST)
X-Received: by 2002:a19:f603:0:b0:4d2:551e:3838 with SMTP id x3-20020a19f603000000b004d2551e3838mr3121370lfe.29.1675934373671;
        Thu, 09 Feb 2023 01:19:33 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1675934373; cv=pass;
        d=google.com; s=arc-20160816;
        b=iCtWLDxkOuA05j0MANVBrBUK0+Vg4OzDwq/Uyf3GrgWIji8RkqTd18tMJ0dHwX1xas
         Dd2hLL7Nx8I0tycVPQG5svsi4ptcPa2KbBOIOBcdu1O/82oMIjsCNQaX9uvoKqxRbunc
         S3oJmYamua5Smei+gtnyS/oc3TpgzkZx9JNTSOy0NmjWm2ohV4OECUId3/QfgElnefeC
         avK6lLwF6fOQHfsrIurEY+wOIKRYoZGU2nrKgaUNEmI92ovu/SseCg+3OrqWeL0/YUc+
         iR49S9WOxulmbbwi43oQIElWy3Oc7MePMkzkbRS0tvmt6dZ9V3nQ4KiGhLZTt30NOrVu
         Pn0Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-transfer-encoding:content-language
         :accept-language:in-reply-to:references:message-id:date:thread-index
         :thread-topic:subject:cc:to:from:dkim-signature;
        bh=McAQJGMKN/TmiQo7yu4Phiw0Odr17i6xAvCZt7wtyXs=;
        b=i6jlIJQ9Pe4AqF1PXENtbWc7nFS47yYzHhB8q6os7ZfPmW5lObrheVRye1vv6SNScK
         ck6CsK851bpAjminnz31kKqgj5GIbkgrBaAxRJYPD7ZPAp0MCOk7XApsXgMuysyEllkf
         3i528JCQZND95j7nSzS+KX8N+8LZxdtGNL+jugN7+o2a1CGU9GZZkNDjChxKHQ2N7qvN
         BVEhjO/VLseXjYnJNJUohGwgr91Wtq7WN8BU0AxrqAhCeomBVrvooWY0sTAtDkAI7Xlk
         KMQYcmFUAPwJs4RhjwmGzmvtPMo6LnFoILUt8fh3HM4hjQRXrNoE1QwHz+RVkJ2Pr08I
         IOWg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@zeku.com header.s=selector1 header.b=73wEl8j7;
       arc=pass (i=1 spf=pass spfdomain=zeku.com dmarc=pass fromdomain=zeku.com);
       spf=pass (google.com: domain of yuanshuai@zeku.com designates 2a01:111:f400:feab::721 as permitted sender) smtp.mailfrom=yuanshuai@zeku.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=zeku.com
Received: from APC01-SG2-obe.outbound.protection.outlook.com (mail-sgaapc01on20721.outbound.protection.outlook.com. [2a01:111:f400:feab::721])
        by gmr-mx.google.com with ESMTPS id g14-20020a056512118e00b004d5e038aba2si45205lfr.7.2023.02.09.01.19.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 09 Feb 2023 01:19:32 -0800 (PST)
Received-SPF: pass (google.com: domain of yuanshuai@zeku.com designates 2a01:111:f400:feab::721 as permitted sender) client-ip=2a01:111:f400:feab::721;
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=mditzaUP/IK1twdcLeJIWZMMZC6gI5ScMKtnvmn37aZxyekfQyeFfc68p243lbfLZqc01lWsAYJyriNvraIX1i7pgY4hvah+PC+1pZiF5ugkJO+U8BYLfnYYrW3XNIGCf38PRg5QLUKuY5LMCRGBB1aXTywW+DfUasjNvuMQ3Kgye1cBYpmuYW0uo0bEP2hUlTXaVCtws9BvqWsHwXbNzlsqjnthviam0rC97MAEabTDiwjl6hFNCB7iQo59w8WDPSFpTqGzh0384MkDd0aWasrRM2AmbrsLy/vwh1vTSLHDdjAJ1Kfo6506D3VjubcizIHnIhEQr8FjmsG8pBsuZw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=McAQJGMKN/TmiQo7yu4Phiw0Odr17i6xAvCZt7wtyXs=;
 b=Wizo1r1hfxS4belXhqX9onPEREC9wMN0D9o0M4QGGZsFpt6KxJ/ESi9uMwtvwTffSbvJiO9snqsIKWtYahGsbFz3uflWuLd7RkpgtTIguV5CiGu8WQkIZMfux0b08XW/2SPtFEO1RRwL01aDuNio3Wz0LF+EVD9Q8uhue+erLHTBO1wk9iDYzdhPSy336pZMm/VvRKeyGJHcduQK9XWG+LDIR3NB3FJdDeNrB7352KQtm/Py6DVFwk+o+OI0EtFwwGATQRgiYC62SwYNV2/cUc1wyF+9DWTnE+2/8iLytjXQ0zorn6ADfUZdys4fAubfgC1lqyMm/nAnr7JJYgSCaQ==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass (sender ip is
 103.192.253.182) smtp.rcpttodomain=google.com smtp.mailfrom=zeku.com;
 dmarc=pass (p=none sp=none pct=100) action=none header.from=zeku.com;
 dkim=none (message not signed); arc=none
Received: from SL2P216CA0216.KORP216.PROD.OUTLOOK.COM (2603:1096:101:18::11)
 by PSAPR02MB4567.apcprd02.prod.outlook.com (2603:1096:301:23::6) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.6064.35; Thu, 9 Feb
 2023 09:19:27 +0000
Received: from PSAAPC01FT030.eop-APC01.prod.protection.outlook.com
 (2603:1096:101:18:cafe::c5) by SL2P216CA0216.outlook.office365.com
 (2603:1096:101:18::11) with Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.6086.19 via Frontend
 Transport; Thu, 9 Feb 2023 09:19:26 +0000
X-MS-Exchange-Authentication-Results: spf=pass (sender IP is 103.192.253.182)
 smtp.mailfrom=zeku.com; dkim=none (message not signed)
 header.d=none;dmarc=pass action=none header.from=zeku.com;
Received-SPF: Pass (protection.outlook.com: domain of zeku.com designates
 103.192.253.182 as permitted sender) receiver=protection.outlook.com;
 client-ip=103.192.253.182; helo=sh-exhtc2.internal.zeku.com; pr=C
Received: from sh-exhtc2.internal.zeku.com (103.192.253.182) by
 PSAAPC01FT030.mail.protection.outlook.com (10.13.39.119) with Microsoft SMTP
 Server (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.20.6086.19 via Frontend Transport; Thu, 9 Feb 2023 09:19:26 +0000
Received: from sh-exhtc1.internal.zeku.com (10.123.21.105) by
 sh-exhtc2.internal.zeku.com (10.123.21.106) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2375.12; Thu, 9 Feb 2023 17:19:25 +0800
Received: from sh-exhtc4.internal.zeku.com (10.123.154.251) by
 sh-exhtc1.internal.zeku.com (10.123.21.105) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2375.12; Thu, 9 Feb 2023 17:19:25 +0800
Received: from sh-exhtc4.internal.zeku.com ([fe80::b447:eb25:37fd:3fd8]) by
 sh-exhtc4.internal.zeku.com ([fe80::b447:eb25:37fd:3fd8%3]) with mapi id
 15.02.0986.005; Thu, 9 Feb 2023 17:19:25 +0800
From: =?utf-8?B?6KKB5biFKFNodWFpIFl1YW4p?= <yuanshuai@zeku.com>
To: Dmitry Vyukov <dvyukov@google.com>,
	=?utf-8?B?5qyn6Ziz54Kc6ZKKKFdlaXpoYW8gT3V5YW5nKQ==?= <ouyangweizhao@zeku.com>
CC: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko
	<glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, "Vincenzo
 Frascino" <vincenzo.frascino@arm.com>, Andrew Morton
	<akpm@linux-foundation.org>, "kasan-dev@googlegroups.com"
	<kasan-dev@googlegroups.com>, "linux-mm@kvack.org" <linux-mm@kvack.org>,
	"linux-kernel@vger.kernel.org" <linux-kernel@vger.kernel.org>, Weizhao Ouyang
	<o451686892@gmail.com>, =?utf-8?B?5Lu756uL6bmPKFBlbmcgUmVuKQ==?=
	<renlipeng@zeku.com>
Subject: =?utf-8?B?562U5aSNOiBbUEFUQ0ggdjJdIGthc2FuOiBmaXggZGVhZGxvY2sgaW4gc3Rh?=
 =?utf-8?Q?rt=5Freport()?=
Thread-Topic: [PATCH v2] kasan: fix deadlock in start_report()
Thread-Index: AQHZPDZzScKWhyj5L0eV70o/eMb/rq7FygeAgACH4+A=
Date: Thu, 9 Feb 2023 09:19:24 +0000
Message-ID: <93b94f59016145adbb1e01311a1103f8@zeku.com>
References: <20230209031159.2337445-1-ouyangweizhao@zeku.com>
 <CACT4Y+Zrz4KOU82jjEperYOM0sEp6TCmgse4XVMPkwAkS+dXrA@mail.gmail.com>
In-Reply-To: <CACT4Y+Zrz4KOU82jjEperYOM0sEp6TCmgse4XVMPkwAkS+dXrA@mail.gmail.com>
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
X-MS-TrafficTypeDiagnostic: PSAAPC01FT030:EE_|PSAPR02MB4567:EE_
X-MS-Office365-Filtering-Correlation-Id: f8a950e9-5094-47d7-94d1-08db0a7ebd79
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;
X-Microsoft-Antispam-Message-Info: l2PJueE/mc0UibPlfP171yloPOivmSXdhBrGOk07u94H7c7ExkN9UD706J/ET9xQ3nPMRHxOYpR/04LejNZLuzZhxS+XXQLFwjp16OoOONBsfm+EuxrxLK1vzcrKeLDVLhOoryezOuFnQIhjgUFJRPPYIPzBPjkhCc2QBbgQYEEQbsij0R9kIKBW6BnG1WhFpCHea95U9Y5yuZDzZwfSoLeuVGOpLkfSqcwZLy6xHfpF5YWdY8gFolDBTjCNExZRbqA/hbhrpglyvUFBrke7Z/9T0KVWtrMKzfTaxxT0K77IJaZpNXQMWhgq74q/hfoFVePa9ztx5EEuwMULfVH3/GIMN1lNZw5TfQ5ax/VB9PGeL2jrkNYv0dwEoh8hR3+lcTifp7JFQWJCdp/+1F59uWd7V8MdB4zMlCJEZNsPp+OmekBG1yCAslGZ3VJZ9uxiCmVYim4z10YY0WzLZOuOp8A3OJy04xuEyvkkwMCq/NMJGMu1gb6IIaUBwqqrbOT1ytcS/pEEZJQF0wArt7VmL8TNXN4ccxVjX9QuRB4wpKem969HBSrVdCRevWXHDfwL6+lPd/SHUdJ8D4rOrQjXYpb3wTPIzndJAXrKenzA1JYilvigGK3h1eWaL6YSNbN53jMMDJD9+jqYFCNy3zclOLAVEOlOX+InoK72xxthPveiq83ruCTArtJgYGBiWnUn5w35yLWYHFOL9MPNSu73Gw==
X-Forefront-Antispam-Report: CIP:103.192.253.182;CTRY:CN;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:sh-exhtc2.internal.zeku.com;PTR:InfoDomainNonexistent;CAT:NONE;SFS:(13230025)(4636009)(396003)(346002)(376002)(39850400004)(136003)(451199018)(36840700001)(46966006)(81166007)(24736004)(70206006)(70586007)(108616005)(41300700001)(26005)(4326008)(8936002)(186003)(54906003)(478600001)(966005)(82310400005)(86362001)(107886003)(6636002)(224303003)(83380400001)(110136005)(2906002)(7696005)(426003)(5660300002)(7416002)(40480700001)(356005)(336012)(85182001)(36756003)(2616005)(47076005)(316002)(82740400003)(36860700001)(66899018)(36900700001);DIR:OUT;SFP:1102;
X-OriginatorOrg: zeku.com
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 09 Feb 2023 09:19:26.2044
 (UTC)
X-MS-Exchange-CrossTenant-Network-Message-Id: f8a950e9-5094-47d7-94d1-08db0a7ebd79
X-MS-Exchange-CrossTenant-Id: 171aedba-f024-43df-bc82-290d40e185ac
X-MS-Exchange-CrossTenant-OriginalAttributedTenantConnectingIp: TenantId=171aedba-f024-43df-bc82-290d40e185ac;Ip=[103.192.253.182];Helo=[sh-exhtc2.internal.zeku.com]
X-MS-Exchange-CrossTenant-AuthSource: PSAAPC01FT030.eop-APC01.prod.protection.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Anonymous
X-MS-Exchange-CrossTenant-FromEntityHeader: HybridOnPrem
X-MS-Exchange-Transport-CrossTenantHeadersStamped: PSAPR02MB4567
X-Original-Sender: yuanshuai@zeku.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@zeku.com header.s=selector1 header.b=73wEl8j7;       arc=pass (i=1
 spf=pass spfdomain=zeku.com dmarc=pass fromdomain=zeku.com);       spf=pass
 (google.com: domain of yuanshuai@zeku.com designates 2a01:111:f400:feab::721
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

Hi Dmitry Vyukov

Thanks, I see that your means.

Currently, report_suppressed() seem not work in Kasan-HW mode, it always re=
turn false.
Do you think should change the report_suppressed function?
I don't know why CONFIG_KASAN_HW_TAGS was blocked separately before.

-----=E9=82=AE=E4=BB=B6=E5=8E=9F=E4=BB=B6-----
=E5=8F=91=E4=BB=B6=E4=BA=BA: Dmitry Vyukov <dvyukov@google.com>
=E5=8F=91=E9=80=81=E6=97=B6=E9=97=B4: 2023=E5=B9=B42=E6=9C=889=E6=97=A5 16:=
56
=E6=94=B6=E4=BB=B6=E4=BA=BA: =E6=AC=A7=E9=98=B3=E7=82=9C=E9=92=8A(Weizhao O=
uyang) <ouyangweizhao@zeku.com>
=E6=8A=84=E9=80=81: Andrey Ryabinin <ryabinin.a.a@gmail.com>; Alexander Pot=
apenko <glider@google.com>; Andrey Konovalov <andreyknvl@gmail.com>; Vincen=
zo Frascino <vincenzo.frascino@arm.com>; Andrew Morton <akpm@linux-foundati=
on.org>; kasan-dev@googlegroups.com; linux-mm@kvack.org; linux-kernel@vger.=
kernel.org; Weizhao Ouyang <o451686892@gmail.com>; =E8=A2=81=E5=B8=85(Shuai=
 Yuan) <yuanshuai@zeku.com>; =E4=BB=BB=E7=AB=8B=E9=B9=8F(Peng Ren) <renlipe=
ng@zeku.com>
=E4=B8=BB=E9=A2=98: Re: [PATCH v2] kasan: fix deadlock in start_report()

On Thu, 9 Feb 2023 at 04:27, Weizhao Ouyang <ouyangweizhao@zeku.com> wrote:
>
> From: Weizhao Ouyang <o451686892@gmail.com>
>
> From: Shuai Yuan <yuanshuai@zeku.com>
>
> Calling start_report() again between start_report() and end_report()
> will result in a race issue for the report_lock. In extreme cases this
> problem arose in Kunit tests in the hardware tag-based Kasan mode.
>
> For example, when an invalid memory release problem is found,
> kasan_report_invalid_free() will print error log, but if an MTE
> exception is raised during the output log, the kasan_report() is
> called, resulting in a deadlock problem. The kasan_depth not protect
> it in hardware tag-based Kasan mode.

I think checking report_suppressed() would be cleaner and simpler than igno=
ring all trylock failures. If trylock fails, it does not mean that the curr=
ent thread is holding it. We of course could do a custom lock which stores =
current->tid in the lock word, but it looks effectively equivalent to check=
ing report_suppressed().



> Signed-off-by: Shuai Yuan <yuanshuai@zeku.com>
> Reviewed-by: Weizhao Ouyang <ouyangweizhao@zeku.com>
> Reviewed-by: Peng Ren <renlipeng@zeku.com>
> ---
> Changes in v2:
> -- remove redundant log
>
>  mm/kasan/report.c | 25 ++++++++++++++++++++-----
>  1 file changed, 20 insertions(+), 5 deletions(-)
>
> diff --git a/mm/kasan/report.c b/mm/kasan/report.c index
> 22598b20c7b7..aa39aa8b1855 100644
> --- a/mm/kasan/report.c
> +++ b/mm/kasan/report.c
> @@ -166,7 +166,7 @@ static inline void fail_non_kasan_kunit_test(void)
> { }
>
>  static DEFINE_SPINLOCK(report_lock);
>
> -static void start_report(unsigned long *flags, bool sync)
> +static bool start_report(unsigned long *flags, bool sync)
>  {
>         fail_non_kasan_kunit_test();
>         /* Respect the /proc/sys/kernel/traceoff_on_warning interface.
> */ @@ -175,8 +175,13 @@ static void start_report(unsigned long *flags, bo=
ol sync)
>         lockdep_off();
>         /* Make sure we don't end up in loop. */
>         kasan_disable_current();
> -       spin_lock_irqsave(&report_lock, *flags);
> +       if (!spin_trylock_irqsave(&report_lock, *flags)) {
> +               lockdep_on();
> +               kasan_enable_current();
> +               return false;
> +       }
>
> pr_err("=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
> =3D=3D=3D=3D\n");
> +       return true;
>  }
>
>  static void end_report(unsigned long *flags, void *addr) @@ -468,7
> +473,10 @@ void kasan_report_invalid_free(void *ptr, unsigned long ip, en=
um kasan_report_ty
>         if (unlikely(!report_enabled()))
>                 return;
>
> -       start_report(&flags, true);
> +       if (!start_report(&flags, true)) {
> +               pr_err("%s: report ignore\n", __func__);
> +               return;
> +       }
>
>         memset(&info, 0, sizeof(info));
>         info.type =3D type;
> @@ -503,7 +511,11 @@ bool kasan_report(unsigned long addr, size_t size, b=
ool is_write,
>                 goto out;
>         }
>
> -       start_report(&irq_flags, true);
> +       if (!start_report(&irq_flags, true)) {
> +               ret =3D false;
> +               pr_err("%s: report ignore\n", __func__);
> +               goto out;
> +       }
>
>         memset(&info, 0, sizeof(info));
>         info.type =3D KASAN_REPORT_ACCESS; @@ -536,7 +548,10 @@ void
> kasan_report_async(void)
>         if (unlikely(!report_enabled()))
>                 return;
>
> -       start_report(&flags, false);
> +       if (!start_report(&flags, false)) {
> +               pr_err("%s: report ignore\n", __func__);
> +               return;
> +       }
>         pr_err("BUG: KASAN: invalid-access\n");
>         pr_err("Asynchronous fault: no details available\n");
>         pr_err("\n");
> --
> 2.25.1
>
> --
> You received this message because you are subscribed to the Google Groups=
 "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an=
 email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgi=
d/kasan-dev/20230209031159.2337445-1-ouyangweizhao%40zeku.com.
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
kasan-dev/93b94f59016145adbb1e01311a1103f8%40zeku.com.
