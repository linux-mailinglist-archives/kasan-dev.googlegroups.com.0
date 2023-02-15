Return-Path: <kasan-dev+bncBCINXLESYINBBMFZWOPQMGQE5WGF2UQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x439.google.com (mail-wr1-x439.google.com [IPv6:2a00:1450:4864:20::439])
	by mail.lfdr.de (Postfix) with ESMTPS id 77420697D10
	for <lists+kasan-dev@lfdr.de>; Wed, 15 Feb 2023 14:22:58 +0100 (CET)
Received: by mail-wr1-x439.google.com with SMTP id g8-20020a5d46c8000000b002c54a27803csf2790752wrs.22
        for <lists+kasan-dev@lfdr.de>; Wed, 15 Feb 2023 05:22:58 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1676467377; cv=pass;
        d=google.com; s=arc-20160816;
        b=Qtme75zYLez/e0W2oJUbEpUxIpm8ktCuRP9u6fe+HiNs0GjhidlERQiMfGJiEL7vVK
         mqzFsxeG7orKPDR+KwYeEkQPHSeEn1FaI0Ui4KlH1q6WY1PDu+pOBS65peiAF6ZHYP5R
         /t///96y8LX4Lz7wejk/ixUzeZCWdJMKoLVMYJhI5Sw7+k9pH4CBG2XUWC5zEypCV2EF
         XCr99Y3GWe9rLOeZyN3w27Ll93UPdOUgqgmsoxKNpdAeghDoc4/20EgZU3sXZXhwZ6C/
         QdfyNGyTiqd06AfGIo/Id812uU6TPVUAQVP0G8pl/kKOcwaT7LaqxJE5jrScXVhWe/v6
         1N8A==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version
         :content-transfer-encoding:content-language:accept-language
         :in-reply-to:references:message-id:date:thread-index:thread-topic
         :subject:cc:to:from:sender:dkim-signature;
        bh=B5/Snb6UP240FzBrVqSyG7LqPjV0EMvYCC6ZoOkIDyY=;
        b=eMez/DXEkxVsfcnu15g8WXHwU00e7rPph1d3BnoHoRiDDEEW5pM5TwTEKjXgYJOE6b
         agyejP4IkQgKBzzazCb3oIgYPAFFzXNTg3wyELF2h9igauus1s/QsnVlypxmfTcUZAMi
         I1uBm4gHZbo/vKHYnDieC5dv2VDtgCeVx33D0cIc5jfCTAGwp0yPxgEFYVFz4AI1xd5q
         egjeP3jhQkYA+moszK0Y+Rdi7bXRMbcCWd6aHbwEZCeMJT98+jSwIXx/u0HeAEsq+hLu
         7LJi4NHKl5KHAxtDhUD7cqqpOIRz8vMIo6OSByNlxYzwmwFvL9sEvMDJ+AvKx5zRrK2W
         3Sag==
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@zeku.com header.s=selector1 header.b=fe3lAT8Q;
       arc=pass (i=1 spf=pass spfdomain=zeku.com dmarc=pass fromdomain=zeku.com);
       spf=pass (google.com: domain of yuanshuai@zeku.com designates 2a01:111:f400:feae::719 as permitted sender) smtp.mailfrom=yuanshuai@zeku.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=zeku.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:content-transfer-encoding
         :content-language:accept-language:in-reply-to:references:message-id
         :date:thread-index:thread-topic:subject:cc:to:from:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=B5/Snb6UP240FzBrVqSyG7LqPjV0EMvYCC6ZoOkIDyY=;
        b=TQhXGNFOemoQ71/021ZZz8mezAlqgFBwFN1a0TKl6/Occ4zsmGfsP5xUpbIN+2eiNs
         SuLKRsIB8qd9l8edjBxGhIO1o93OXOp0LmDCuito91CKunH58Hk6UBqMQLqwsLXPotS0
         qYyXy6aJK5nm2XUuB8RSJ5mZjgxso+zZmUD9777rMvGX7GpcXQ1yleSjy6K8RCjrtmBM
         trYwpAsNt8buvCrAkQHz7cDFvpV0fmeoHY4afp/+iQjTmo6tp8yTLZPDft59zKI80mlJ
         zH5fy4WTNLdb+2o0tfDzmKUBvMLRpdXs3dCDyg8cJyL4z3CyHE40l/imx/bZljE3PecS
         r0gA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :content-transfer-encoding:content-language:accept-language
         :in-reply-to:references:message-id:date:thread-index:thread-topic
         :subject:cc:to:from:x-gm-message-state:sender:from:to:cc:subject
         :date:message-id:reply-to;
        bh=B5/Snb6UP240FzBrVqSyG7LqPjV0EMvYCC6ZoOkIDyY=;
        b=GlaFSMLnOJkF/QnPyuk8wJ6FGybLVIViUQC8RZV5nyKQhhG3bWR46n0ej5pdN6knv4
         XEIzMdKdj6/9QJylEHF8SUuuL+QF+nvVz8pNMAayJNByAcDrSXm9/oSXHqt8vlf37ibm
         /CxYGHQiwsSNB/WoMaH2nWRxz49e4JK2PM1qlVt5WqwY179BkTQGd1f7Xn0jipET6Qec
         acIxS9KN8jh2HhIGtGH4mX6BFS0dO9PXLPCzAtVmjpdlNmid0YvU+KtXNotJopeL0Ahq
         eT0675J6VAZt+b3HjHqbeMpH34ZlajSvgrbVi/XBSmvl8ard45nRzh8iP3MKAcMaMTlS
         4KBw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKVi26gPuQh/UxYkVjQgAzRkTAx2pgzNyBYDFPSwymbUIFZEpLlF
	1vUJOmz/nBFE02GP7ZzH8xo=
X-Google-Smtp-Source: AK7set/vY3PovPq0JFI11M8u19r5nzXV8bzrLn2kxk/aAtJ55uKe4PfCHVMY3dampekMh5wXFdMwLg==
X-Received: by 2002:a05:6000:10d0:b0:2c5:5939:f82e with SMTP id b16-20020a05600010d000b002c55939f82emr100035wrx.336.1676467376826;
        Wed, 15 Feb 2023 05:22:56 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:1e05:b0:3dc:4f57:78be with SMTP id
 ay5-20020a05600c1e0500b003dc4f5778bels1002503wmb.2.-pod-control-gmail; Wed,
 15 Feb 2023 05:22:55 -0800 (PST)
X-Received: by 2002:a05:600c:474a:b0:3da:fd06:a6f1 with SMTP id w10-20020a05600c474a00b003dafd06a6f1mr1901201wmo.31.1676467375550;
        Wed, 15 Feb 2023 05:22:55 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1676467375; cv=pass;
        d=google.com; s=arc-20160816;
        b=R5RAr+eW+EYjflJyaYxljMWV7Ay0LmzEgUGW1dzU9KJ68XSszqklQCuIw+Z9Cdch1P
         kRgh1zXnHYnUxb3bXfF/TbvfL4NT0zVGdyDFEeEatvv/xfHVDfIXwBxZhi6Ts/uy45x6
         r6E6gKZy+dnjclvxH29bllLecQ8WdNQL9kDLFFqGfR7sQ+XneSu/SqEwAauLozPfTjuF
         drv/8CtztUhP4Kp2Wa84REx9Znihq8ItFONIYy8rwTdE1iAvsQzvHYc0oHSm6J3But1l
         duufDW84sMWKYTki+YI9Y8JgOGk/BmXUNfVbYP3eLx1oNApiLv0/gmKWUt3nYBW5Dltm
         ypZw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-transfer-encoding:content-language
         :accept-language:in-reply-to:references:message-id:date:thread-index
         :thread-topic:subject:cc:to:from:dkim-signature;
        bh=ixnyI4LJMibIS6FJFI7BeG7vFDSm0ifyXMvFTJeuOjg=;
        b=ynckdkM7zq8k9G7GEwNv8+COAIIzWisMBsxpT2Vj5coVIGeWzeDBl0hQoZCr1Qu8JB
         5FtviL55CAYDxONgYB+HHrOZYuWKOGAOEoFPTYqrJqOrhV7Wa+CIx7qzweN+FutPXVlj
         vYjBW+xlfjThoKk6sBpt6MmAN6q4aev0o5tvvTEKOma7etSRr8Zq0JmNV8GVp1Qn/YoA
         G8oDvi9lGhDIv6YD8i/5/VvOQ84skOAh1cB/gpaCErfhCIdAPEHDeWpMsuFQl0YjpvJH
         u6JbAYmc3DSE1l4jHT57T14ZMTGamnSZL71qKRqvaO7jA3ZQ1lDR6VpHRI2pKzf+E3aE
         fV8w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@zeku.com header.s=selector1 header.b=fe3lAT8Q;
       arc=pass (i=1 spf=pass spfdomain=zeku.com dmarc=pass fromdomain=zeku.com);
       spf=pass (google.com: domain of yuanshuai@zeku.com designates 2a01:111:f400:feae::719 as permitted sender) smtp.mailfrom=yuanshuai@zeku.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=zeku.com
Received: from APC01-PSA-obe.outbound.protection.outlook.com (mail-psaapc01on20719.outbound.protection.outlook.com. [2a01:111:f400:feae::719])
        by gmr-mx.google.com with ESMTPS id d5-20020a05600c3ac500b003e1eddc40cfsi185507wms.3.2023.02.15.05.22.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 15 Feb 2023 05:22:55 -0800 (PST)
Received-SPF: pass (google.com: domain of yuanshuai@zeku.com designates 2a01:111:f400:feae::719 as permitted sender) client-ip=2a01:111:f400:feae::719;
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=G1iy4QqtLhKc2F/nyG8+UdTc8yD9yvFZSLI3bDpPKFaY/zGyite58TgIN+pod9PaEDrGAtsFvSzQIugR4fSlFe4oHgTnInSM0eBTgk7nZvKBhWk2eCuJwjkLzBR7RjHAABqoCDPSa3OCt2ahUCq12kSEfybc2riUKKNbvQ9M3Wv3hecAiSaLGIgyOLrOf60Xekvfd9XVe7f1oIegRrILQlrrqRD0EowqMzfTEezuU5mm0kshIxBMTSEiP1yRKvNilXbOzL4I4A5WxGYjPd9/5iJcsK9uu44blIXG1/z3KaT63CX2P6uUcnljtcQAuSDbl8xl3cwIlZEFJDAB7X2HPw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=ixnyI4LJMibIS6FJFI7BeG7vFDSm0ifyXMvFTJeuOjg=;
 b=RMjnEIQSj2/hnHtyVJA1/mb4aXjttUZaQFxsUBz9IblQLef8Im3OsWQM+O1mShfBzxbNR0w2TS3B7jSYuJWdQ02bQ8QDqfMOFSNuBo/rL5H/716iKDdtMvZgbZxVQxjmxoAV9N6gvgfupBXI4oFaO7dZlaO30BOhnf16a7OjP853NfABgL4v934o0PgcOvIrxFQJlTYof8LZcgzJbmktTBEEb2c42bRlo5od6scuI4Ebdn/1OMjTpLredcwTeVfHBS8seWjEVTYPpYvq39keFJL5pXLP5iRXP0borf2nN5DBf4wrHdv51aE4dmTbQgY8UlvvGFwOHOjMMz89/CTgkA==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass (sender ip is
 103.192.253.182) smtp.rcpttodomain=gmail.com smtp.mailfrom=zeku.com;
 dmarc=pass (p=none sp=none pct=100) action=none header.from=zeku.com;
 dkim=none (message not signed); arc=none
Received: from SG2P153CA0049.APCP153.PROD.OUTLOOK.COM (2603:1096:4:c6::18) by
 TYZPR02MB4879.apcprd02.prod.outlook.com (2603:1096:400:50::13) with Microsoft
 SMTP Server (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.20.6086.26; Wed, 15 Feb 2023 13:22:51 +0000
Received: from SG2APC01FT0006.eop-APC01.prod.protection.outlook.com
 (2603:1096:4:c6:cafe::19) by SG2P153CA0049.outlook.office365.com
 (2603:1096:4:c6::18) with Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.6134.6 via Frontend
 Transport; Wed, 15 Feb 2023 13:22:51 +0000
X-MS-Exchange-Authentication-Results: spf=pass (sender IP is 103.192.253.182)
 smtp.mailfrom=zeku.com; dkim=none (message not signed)
 header.d=none;dmarc=pass action=none header.from=zeku.com;
Received-SPF: Pass (protection.outlook.com: domain of zeku.com designates
 103.192.253.182 as permitted sender) receiver=protection.outlook.com;
 client-ip=103.192.253.182; helo=sh-exhtc2.internal.zeku.com; pr=C
Received: from sh-exhtc2.internal.zeku.com (103.192.253.182) by
 SG2APC01FT0006.mail.protection.outlook.com (10.13.37.55) with Microsoft SMTP
 Server (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.20.6111.12 via Frontend Transport; Wed, 15 Feb 2023 13:22:50 +0000
Received: from sh-exhtc4.internal.zeku.com (10.123.154.251) by
 sh-exhtc2.internal.zeku.com (10.123.21.106) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2375.12; Wed, 15 Feb 2023 21:22:50 +0800
Received: from sh-exhtc4.internal.zeku.com ([fe80::b447:eb25:37fd:3fd8]) by
 sh-exhtc4.internal.zeku.com ([fe80::b447:eb25:37fd:3fd8%3]) with mapi id
 15.02.0986.005; Wed, 15 Feb 2023 21:22:50 +0800
From: =?utf-8?B?6KKB5biFKFNodWFpIFl1YW4p?= <yuanshuai@zeku.com>
To: Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov
	<dvyukov@google.com>
CC: =?utf-8?B?5qyn6Ziz54Kc6ZKKKFdlaXpoYW8gT3V5YW5nKQ==?=
	<ouyangweizhao@zeku.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	"Alexander Potapenko" <glider@google.com>, Vincenzo Frascino
	<vincenzo.frascino@arm.com>, Andrew Morton <akpm@linux-foundation.org>,
	"kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>,
	"linux-mm@kvack.org" <linux-mm@kvack.org>, "linux-kernel@vger.kernel.org"
	<linux-kernel@vger.kernel.org>, Weizhao Ouyang <o451686892@gmail.com>,
	=?utf-8?B?5Lu756uL6bmPKFBlbmcgUmVuKQ==?= <renlipeng@zeku.com>
Subject: RE: [PATCH v2] kasan: fix deadlock in start_report()
Thread-Topic: [PATCH v2] kasan: fix deadlock in start_report()
Thread-Index: AQHZPDZzScKWhyj5L0eV70o/eMb/rq7FygeAgACH4+D//5aGAIAAy+8AgAC6aDCACH5tEA==
Date: Wed, 15 Feb 2023 13:22:50 +0000
Message-ID: <2b57491a9fab4ce9a643bd0922e03e73@zeku.com>
References: <20230209031159.2337445-1-ouyangweizhao@zeku.com>
 <CACT4Y+Zrz4KOU82jjEperYOM0sEp6TCmgse4XVMPkwAkS+dXrA@mail.gmail.com>
 <93b94f59016145adbb1e01311a1103f8@zeku.com>
 <CACT4Y+a=BaMNUf=_suQ5or9=ZksX2ht9gX8=XBSDEgHogyy3mg@mail.gmail.com>
 <CA+fCnZf3k-rsaOeti0Q7rqkmvsqDb2XxgxOq6V5Gqp6FGLH7Yg@mail.gmail.com>
 <b058a424e46d4f94a1f2fdc61292606b@zeku.com>
In-Reply-To: <b058a424e46d4f94a1f2fdc61292606b@zeku.com>
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
X-MS-TrafficTypeDiagnostic: SG2APC01FT0006:EE_|TYZPR02MB4879:EE_
X-MS-Office365-Filtering-Correlation-Id: 3afc5847-753f-40d8-3845-08db0f57bd09
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;
X-Microsoft-Antispam-Message-Info: 9FVuDwCMAIkcZQRuXFVuAbmFyPL9b+AcOkYHSKdcfXNxy2RV7kd6YPBZtJDrUWKehS6ZL6FEsHQdxvyuNCRKKccO7705smO2fIC7s9uCLLeyF1Xkyx7zjl/eZQYM65Xq4qx4eHE3CU/W6XbW6TLAW3F3szecOxJqP8uWOMBBeWXMzq47gZi9y8AAWJgFxDH/++SnPi07kHBL3SgK/o9IofPXiuaqq+sXCKsytmWniTwM1vyytHXZgJv7Qfd5UDs7i4ApIoGCcr+xfAYY3XBIfzb2LbosIAf56os0qj/Ij4yLSSzlnnv/bKsS4e2h8Pp7XsygHqECjI9L4x596Np2I0/336KXMdJzCWTOuZXGxuaBJK4CrEVzcatgWWJrQ01rxEaJhdGtRj9QOp4T/qnkkD3Lt+9R1ib3r1R9IkkQq9ngUKwxVZBZ2Qu2SVUHR5ChNb4SBisOW2+B/sltfal7ydX7LkgzUgoIhkJ9foj8WmdHssRhAg76JfEpu60V0wk0z3K8Y4tGgsJIcE15G/lWzUhypupQtzzFaGl+C6Qyc1WW56zKao+AnP5ZTR9w/JIbvU0lYetzZpeidAaxQ8s1rh5Qg+LMJO36zG4r93lzZq9gfhoFVZ6Q9aPjjypHA+6rg4186OCnYqlNZsyrEsQMDeREfmCBc3nl02R0rZgjm9o55MKbpNoAs7qngFTN+ZlN
X-Forefront-Antispam-Report: CIP:103.192.253.182;CTRY:CN;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:sh-exhtc2.internal.zeku.com;PTR:InfoDomainNonexistent;CAT:NONE;SFS:(13230025)(4636009)(346002)(376002)(136003)(39850400004)(396003)(451199018)(36840700001)(46966006)(7416002)(81166007)(316002)(356005)(8676002)(4326008)(36860700001)(41300700001)(8936002)(82740400003)(2906002)(70206006)(966005)(70586007)(107886003)(478600001)(5660300002)(336012)(26005)(2616005)(24736004)(53546011)(108616005)(86362001)(83380400001)(110136005)(82310400005)(54906003)(36756003)(7696005)(426003)(40480700001)(47076005)(85182001)(186003)(36900700001);DIR:OUT;SFP:1102;
X-OriginatorOrg: zeku.com
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 15 Feb 2023 13:22:50.9720
 (UTC)
X-MS-Exchange-CrossTenant-Network-Message-Id: 3afc5847-753f-40d8-3845-08db0f57bd09
X-MS-Exchange-CrossTenant-Id: 171aedba-f024-43df-bc82-290d40e185ac
X-MS-Exchange-CrossTenant-OriginalAttributedTenantConnectingIp: TenantId=171aedba-f024-43df-bc82-290d40e185ac;Ip=[103.192.253.182];Helo=[sh-exhtc2.internal.zeku.com]
X-MS-Exchange-CrossTenant-AuthSource: SG2APC01FT0006.eop-APC01.prod.protection.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Anonymous
X-MS-Exchange-CrossTenant-FromEntityHeader: HybridOnPrem
X-MS-Exchange-Transport-CrossTenantHeadersStamped: TYZPR02MB4879
X-Original-Sender: yuanshuai@zeku.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@zeku.com header.s=selector1 header.b=fe3lAT8Q;       arc=pass (i=1
 spf=pass spfdomain=zeku.com dmarc=pass fromdomain=zeku.com);       spf=pass
 (google.com: domain of yuanshuai@zeku.com designates 2a01:111:f400:feae::719
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

> On Friday, February 10, 2023 at 6:54 AM Andrey Konovalov
> <andreyknvl@gmail.com>
> wrote:
> > On Thu, Feb 9, 2023 at 11:44 AM Dmitry Vyukov <dvyukov@google.com>
> > wrote:
> > >
> > >  On Thu, 9 Feb 2023 at 10:19, =E8=A2=81=E5=B8=85(Shuai Yuan) <yuanshu=
ai@zeku.com>
> > wrote:
> > > >
> > > > Hi Dmitry Vyukov
> > > >
> > > > Thanks, I see that your means.
> > > >
> > > > Currently, report_suppressed() seem not work in Kasan-HW mode, it
> > always return false.
> > > > Do you think should change the report_suppressed function?
> > > > I don't know why CONFIG_KASAN_HW_TAGS was blocked separately
> > before.
> > >
> > > That logic was added by Andrey in:
> > > https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/c
> > > om
> > > mit/?id=3Dc068664c97c7cf
> > >
> > > Andrey, can we make report_enabled() check current->kasan_depth and
> > > remove report_suppressed()?
> >
> > I decided to not use kasan_depth for HW_TAGS, as we can always use a
> > match-all tag to make "invalid" memory accesses.
> >
> > I think we can fix the reporting code to do exactly that so that it
> > doesn't cause MTE faults.
> >
> > Shuai, could you clarify, at which point due kasan_report_invalid_free
> > an MTE exception is raised in your tests?
>
> Yes, I need some time to clarify this problem with a clear log by test.
>

Hi Andrey and Dmitry

I have got valid information to clarify the problem and solutions. I made
a few changes to the code to do this.

a) I was testing on a device that had hardware issues with MTE,
    and the memory tag sometimes changed randomly.

b) I did this test on kernel version 5.15, but this problem should
    exist on the latest kernel version from a code perspective.

c) Run the kernel with a single core by "maxcpus=3D1".

d) Code modify,
    (1) Call dump_stack_lvl(KERN_ERR) when start_report() returns false,
    this is done based on the current patch v2.

    (2) Add some log in print_address_description() to show kmem_cache addr=
ess
    and memory tag.
    https://elixir.bootlin.com/linux/v5.15.94/source/mm/kasan/report.c#L252
   @@ -255,24 +260,25 @@ static void print_address_description(void *addr, =
u8 tag)

 dump_stack_lvl(KERN_ERR);
 pr_err("\n");
  -
  +pr_err("ys:1\n");
 if (page && PageSlab(page)) {
 struct kmem_cache    *cache =3D page->slab_cache;
  -void *object =3D nearest_obj(cache, page,addr);
  +void *object =3D NULL;
  +pr_err("ys:cache start %llx, mtag:%x, page_address:%llx\n",
  +cache, hw_get_mem_tag(cache), page_address(page));
  +object =3D nearest_obj(cache, page, addr);
  +                         pr_err("ys:cache end %llx, object %llx, page_ad=
dress:%llx\n",
  +                                        cache, object, page_address(page=
));
describe_object(cache, object, addr, tag);
 }

    (3) Add kasan_enable_tagging() to KUNIT_EXPECT_KASAN_FAIL in
    https://elixir.bootlin.com/linux/v5.15.94/source/lib/test_kasan.c#L94
    This ensures that kunit is tested on this unstable device.

e) With the above modification we can get the backtrace:
ys:1
ys:cache start f4ffff8140005380, mtag:fe, page_address:ffffff8140328000
ys:cache change f4ffff8140005380, mtag:fe, page_address:ffffff8140328000
ys: error address:f4ffff8140005398
Pointer tag: [f4], memory tag: [fe]
CPU: 0 PID: 100 Comm: kunit_try_catch Tainted:
Call trace:
dump_backtrace.cfi_jt+0x0/0x8
 show_stack+0x28/0x38
 dump_stack_lvl+0x68/0x98
 __kasan_report+0x110/0x29c
kasan_report+0x40/0x8c
 __do_kernel_fault+0xd4/0x2c4
 do_bad_area+0x40/0x100
 do_tag_check_fault+0x2c/0x40
 do_mem_abort+0x74/0x138
el1_abort+0x40/0x64
 el1h_64_sync_handler+0x60/0xa0
 el1h_64_sync+0x7c/0x80
 print_address_description+0x154/0x2e8
 __kasan_report+0x200/0x29c
kasan_report+0x40/0x8c
 __do_kernel_fault+0xd4/0x2c4
 do_bad_area+0x40/0x100
 do_tag_check_fault+0x2c/0x40
 do_mem_abort+0x74/0x138
el1_abort+0x40/0x64
 el1h_64_sync_handler+0x60/0xa0
 el1h_64_sync+0x7c/0x80
 enqueue_entity+0x23c/0x4b8
enqueue_task_fair+0x13c/0x48c
 enqueue_task.llvm.1684042887774774428+0xd0/0x250
 __do_set_cpus_allowed+0x1ac/0x304
 __set_cpus_allowed_ptr_locked+0x168/0x28c
 migrate_enable+0xf0/0x17c
kasan_strings+0x59c/0x72c
kunit_try_run_case+0x84/0x128
kunit_generic_run_threadfn_adapter+0x48/0x80
kthread+0x17c/0x1e8
ret_from_fork+0x10/0x20
ys:cache end f4ffff8140005380, object ffffff814032ca00, page_address:ffffff=
8140328000

f) From the above log, you can see that the system tried to call kasan_repo=
rt() twice,
   because we visit tag address by kmem_cache and this tag have change..
   Normally this doesn't happen easily. So I think we can add kasan_reset_t=
ag() to handle
   the kmem_cache address.

   For example, the following changes are used for the latest kernel versio=
n.
diff --git a/mm/kasan/report.c b/mm/kasan/report.c
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -412,7 +412,7 @@ static void complete_report_info(struct kasan_report_in=
fo *info)
        slab =3D kasan_addr_to_slab(addr);
        if (slab) {
-               info->cache =3D slab->slab_cache;
+               info->cache =3D kasan_reset_tag(slab->slab_cache);
                info->object =3D nearest_obj(info->cache, slab, addr);

   I have tested Kernel5.15 using a similar approach and it seems to work.
   On the other hand, I think there should be other solutions and hope to g=
et your feedback.
   Thanks a lot.

> > > Then we can also remove the comment in kasan_report_invalid_free().
> > >
> > > It looks like kasan_disable_current() in kmemleak needs to affect
> > > HW_TAGS mode as well:
> > > https://elixir.bootlin.com/linux/v6.2-rc7/source/mm/kmemleak.c#L301
> >
> > It uses kasan_reset_tag, so it should work properly with HW_TAGS.
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
kasan-dev/2b57491a9fab4ce9a643bd0922e03e73%40zeku.com.
