Return-Path: <kasan-dev+bncBDBLJCHX2YFBB7GDSGPQMGQEFBFMYDA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x337.google.com (mail-wm1-x337.google.com [IPv6:2a00:1450:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id 0AF4968FDA1
	for <lists+kasan-dev@lfdr.de>; Thu,  9 Feb 2023 04:01:17 +0100 (CET)
Received: by mail-wm1-x337.google.com with SMTP id b19-20020a05600c4e1300b003e10d3e1c23sf1757646wmq.1
        for <lists+kasan-dev@lfdr.de>; Wed, 08 Feb 2023 19:01:17 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1675911676; cv=pass;
        d=google.com; s=arc-20160816;
        b=LfE4wxLDNrAT2bzfqF4kaCeq5bV7178jwnayrp0yyWhO3GMvt9601ywuyKk3EcuBVu
         lC1K4m/mlwzYq2wSNg7adDoWfzjWhHeM5lbHJqyEF2fWVPJqQiUBITiq7S0kN3TMmgzp
         cDqW3Jr3ZJdJ9P6gEtLYVAuI7oq+2u9CWQj51l0dHHxD47tsCZav5YAyYl51V0SWObjO
         A7ZgY0URiU3aNqkEGmm5lcqarY73MIz/wHHER1K+yZxEF2uvbS71Im8xvQuc4j+I2rKQ
         0YnsUd0oSsQJeCsokME+bZZfF461/7whAF3aQ3kEvCVhgUsLFq2Zy4sDdkCCrZs7xiD1
         JpHw==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=pD7OpiniP1mowOx08avvCZx7jt9SYxQgyj7NPkKmjYw=;
        b=Sko7EcW4hH9FZ3z49G7wIhaZHcfa5AHtMWQdJykKWK0bqerlYBDwkhTZPKJJvwZRl2
         4Ssscji4i6f8H3I/SEgterjdrGPZAGOZxn8gJmoriCkjreE1Jkt70NlQBV6hrQOE35hE
         uIQWPvVEOFb6Uqsq4mx/+mOpnlPpVg2C5gScbRP5yOIcn+XBv8bUoOLwQac8pth+2p7f
         zftmUsDbk+zCjEHZRPDw1tQUSMPoMGQf3CwrjtGly75jxH8VnUq1CmcrRxDw4i4UH61q
         JIk5oC6UQDX0AcPaBcaqUtMjtDWtEsFU7Bg65Juu9OcqcWB9OVZjfEiTWqkoZ8Yqo7u+
         /NGA==
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@zeku.com header.s=selector1 header.b=y381y1oc;
       arc=pass (i=1 spf=pass spfdomain=zeku.com dmarc=pass fromdomain=zeku.com);
       spf=pass (google.com: domain of ouyangweizhao@zeku.com designates 2a01:111:f403:704b::729 as permitted sender) smtp.mailfrom=ouyangweizhao@zeku.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=zeku.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=pD7OpiniP1mowOx08avvCZx7jt9SYxQgyj7NPkKmjYw=;
        b=OUZe3OvA/wZQWx2XVhUoKZmZyeijXAu1Yhf3GIZ/AaWoyZMGwo+B+og0fnGt1673gv
         XbDodn1DMx7MzwtBtfwuWRchfH7RO2OAuKSz02zNp2Mi+ShIMM1+a8KWWOb1IEKYWJBX
         pZLnrHAtqpS5u9wojyteRn88bMcC82rDXwHg/dxjvcagwrH8UzAcdmgy7P++NxrTlPpx
         LCqdbk6LDeZApL0qxcyt8IcNqQ1G2h4f1v6+8/rLV8Rm0Vhr8HrmyDc12VoVRH4ENc5d
         eUt07HyfFKErQxeqHX0g/F+zw+TIcMpUbE/g0RwWSPk5hU1urKhu5lIw3z9BmcKGYmEb
         uiEQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-gm-message-state:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=pD7OpiniP1mowOx08avvCZx7jt9SYxQgyj7NPkKmjYw=;
        b=zOFdVHXLVNA7TyKcrji1V7wLzE7M6kR9RxQKAg2qPQ6j40UUtoE+aL01Ao3nXRC4aY
         hXV8gk+cVvNJqj6kTPHm3Zrn0PGedPpzHGb563i+euzj4Go3JAp3fXvzoLmxiPWAUS03
         z+XvhlVsmtuD1EE5NBlqtM9smVyQQYbNttAzch9jfqEO10FtdWaUj3GgIY8BozYQ4HRI
         L83p0Ye3hFEcCwABal1M8a5rF7TlTODvkabZntTPxiiAm++rwRW38x4rx6vMuFy8eVDO
         pChiE470N0F31mjtqJmriQrbNWv0VYQKWMz3NDaeT+8R6JgnnEuvS5bGtOtTCHEYwT9b
         Elag==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKWP2YvGnsPVhpB38CZeH8w/cryUY9HS1fkhxMIJY4hCvBteoNfN
	AfgAxQbtRdSh1vnpLnhkMVQ=
X-Google-Smtp-Source: AK7set9C4mapwuI4QommV3k/LUZRvbgFCSEceKH80etrdja6dhYW2b7uH/j7sPbNOGxGeAc5s9UdEQ==
X-Received: by 2002:a5d:6686:0:b0:2c4:6a8:d2a5 with SMTP id l6-20020a5d6686000000b002c406a8d2a5mr110507wru.303.1675911676581;
        Wed, 08 Feb 2023 19:01:16 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:6588:0:b0:2bf:ae0c:669b with SMTP id q8-20020a5d6588000000b002bfae0c669bls990525wru.2.-pod-prod-gmail;
 Wed, 08 Feb 2023 19:01:15 -0800 (PST)
X-Received: by 2002:adf:e710:0:b0:2c4:855:c7e7 with SMTP id c16-20020adfe710000000b002c40855c7e7mr1104095wrm.62.1675911675379;
        Wed, 08 Feb 2023 19:01:15 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1675911675; cv=pass;
        d=google.com; s=arc-20160816;
        b=gZXY4A1cU+A+Rx0m+YK0pu37aBTwAR9C/gFq8i83NKpzIbD4yH+vdtGqy7oU0TWOa8
         j0id8VE/RH+9ekqfnu/M9EYSgoUHpufbwRnj9qBZ0J5X3/K9wtXwEibGjoV4k1cTJjp6
         mq2yn/L6v8USXZYEIjW3qLF3fYxBGTJxf+OD70VzaKMJFce60YH40MZdVGE38wpRs7d/
         FT8Kw5l6N4rwGvch+ROqts4bah6nSm+WSYAKbHHnm3TrUl7LZ4pDNPf/JJPmbHoW6Kzz
         ZSDNy0dg/i8J8lS7nHSsN/avYArGXGo0G+okj9GoAoJho0cv8GnKOyt5MAJ+f06LZC78
         GCdQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=dWaUhcl4kG0zsK/TYIg/dCOuIL+aus58oCG3ZDDofFQ=;
        b=JVC90StnvHfGPpCY4M0uOekSl1EfaLbydykW9tlOpwmaBLJopKqpuaW0a+CW7yDYSs
         RNV5vCknScoIEnSbJb15og0WNqea7tdpXbEBNqgrmmdDrgjSc86z8N2Sc7rBn6ktQ8Qs
         kONxYb2jGf1Kk6wijSCr31UHCLiTUavHoLPUEKg8vqgvCOM2aFvsqVrcpjF1rLFRYRvi
         Vk3y5gecDaGyv7KY1hIDE+uOKrFP93cs7ARSZgEoFBxhdm67k1WiyY9l+IYv7jF8uOe9
         sF2yCt8aIRDa3Q0CGWEO2wS+dzrcrCsG6ssKQIY89qRYegm0tpjb9aFw/z/tBxztor7N
         OOHQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@zeku.com header.s=selector1 header.b=y381y1oc;
       arc=pass (i=1 spf=pass spfdomain=zeku.com dmarc=pass fromdomain=zeku.com);
       spf=pass (google.com: domain of ouyangweizhao@zeku.com designates 2a01:111:f403:704b::729 as permitted sender) smtp.mailfrom=ouyangweizhao@zeku.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=zeku.com
Received: from APC01-TYZ-obe.outbound.protection.outlook.com (mail-tyzapc01on20729.outbound.protection.outlook.com. [2a01:111:f403:704b::729])
        by gmr-mx.google.com with ESMTPS id az25-20020adfe199000000b002c3ea753692si7894wrb.0.2023.02.08.19.01.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 08 Feb 2023 19:01:15 -0800 (PST)
Received-SPF: pass (google.com: domain of ouyangweizhao@zeku.com designates 2a01:111:f403:704b::729 as permitted sender) client-ip=2a01:111:f403:704b::729;
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=DlG2zw9WLZWMOQZgFVpY7O9luAXzQgLOJ0GDnX7g3uOAoVnToviIvUzprejLmTSVhFLHNLlJOcPnzO4F8/JiVB95lMM39MXKQ5NHcalEtIz1MNzz5gUl3aktwQFD4xDOsGIZiZMD8wL9d467m04DZvYNEYes4qEwCUJHCBR0zC+0zCPnXJcjmJke9Fkc3wosoAo8udGarlVJjT+BvZ69wR8ZBQ97nCF+tsOPmPUxZOWxr5i5ElXIDeqkFNfl11VtSIKH5PHuX7fqbcKAmyt6DGO7kQR4yJiscQUVKwxDk9qfgGosKI/PSwY+Yy1t2tfpLcUR3C37MznFovPTPgSf+g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=dWaUhcl4kG0zsK/TYIg/dCOuIL+aus58oCG3ZDDofFQ=;
 b=XMRG5V0MXtCzocmihDslMoTGmhAzVOiehH1/IZyj3mcrIUBM0/fsPOC5X0y3LwTujw+2cQFzZr5OpINtmycAighvlSVQZseNTN4tcpS9lDNfk1o6kZgp70NReON39M0wrKq9lL0ifWhIJPMhlunP8ClU/oiy8LB/2AaQg0z1rVlL5YGy65ld3wDbFU+CMR8GI52ggFg2Z7tsislkGmDVg2eOa9+f62q/rw11EjZvp0k4cohzEgyPgkO5AnG+WB9G5zoq5D8WGB/Fufn/rRU1mTYonCTpuIZBhHPBwAZWPQRHhHRkm0sAkBJ4I2iejth99UA6XdtGPMyG7rw2bkkukg==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass (sender ip is
 103.192.253.182) smtp.rcpttodomain=gmail.com smtp.mailfrom=zeku.com;
 dmarc=pass (p=none sp=none pct=100) action=none header.from=zeku.com;
 dkim=none (message not signed); arc=none
Received: from SGAP274CA0017.SGPP274.PROD.OUTLOOK.COM (2603:1096:4:b6::29) by
 SEZPR02MB5784.apcprd02.prod.outlook.com (2603:1096:101:42::14) with Microsoft
 SMTP Server (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.20.6064.35; Thu, 9 Feb 2023 03:01:07 +0000
Received: from SG2APC01FT0038.eop-APC01.prod.protection.outlook.com
 (2603:1096:4:b6:cafe::95) by SGAP274CA0017.outlook.office365.com
 (2603:1096:4:b6::29) with Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.6086.19 via Frontend
 Transport; Thu, 9 Feb 2023 03:01:07 +0000
X-MS-Exchange-Authentication-Results: spf=pass (sender IP is 103.192.253.182)
 smtp.mailfrom=zeku.com; dkim=none (message not signed)
 header.d=none;dmarc=pass action=none header.from=zeku.com;
Received-SPF: Pass (protection.outlook.com: domain of zeku.com designates
 103.192.253.182 as permitted sender) receiver=protection.outlook.com;
 client-ip=103.192.253.182; helo=sh-exhtc2.internal.zeku.com; pr=C
Received: from sh-exhtc2.internal.zeku.com (103.192.253.182) by
 SG2APC01FT0038.mail.protection.outlook.com (10.13.37.151) with Microsoft SMTP
 Server (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.20.6086.17 via Frontend Transport; Thu, 9 Feb 2023 03:01:06 +0000
Received: from sh-exhtc1.internal.zeku.com (10.123.21.105) by
 sh-exhtc2.internal.zeku.com (10.123.21.106) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2375.12; Thu, 9 Feb 2023 11:01:05 +0800
Received: from sh-exhtc1.internal.zeku.com (10.123.21.105) by
 sh-exhtc1.internal.zeku.com (10.123.21.105) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2375.12; Thu, 9 Feb 2023 11:01:05 +0800
Received: from localhost.localdomain (10.123.154.19) by
 sh-exhtc1.internal.zeku.com (10.123.21.105) with Microsoft SMTP Server id
 15.1.2375.12 via Frontend Transport; Thu, 9 Feb 2023 11:01:05 +0800
From: Weizhao Ouyang <ouyangweizhao@zeku.com>
To: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko
	<glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov
	<dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, "Andrew
 Morton" <akpm@linux-foundation.org>
CC: <kasan-dev@googlegroups.com>, <linux-mm@kvack.org>,
	<linux-kernel@vger.kernel.org>, Weizhao Ouyang <ouyangweizhao@zeku.com>,
	Shuai Yuan <yuanshuai@zeku.com>, Peng Ren <renlipeng@zeku.com>
Subject: [PATCH] kasan: fix deadlock in start_report()
Date: Thu, 9 Feb 2023 10:45:36 +0800
Message-ID: <20230209024536.2334644-1-ouyangweizhao@zeku.com>
X-Mailer: git-send-email 2.25.1
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-EOPAttributedMessage: 0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: SG2APC01FT0038:EE_|SEZPR02MB5784:EE_
X-MS-Office365-Filtering-Correlation-Id: 3eac3196-879c-4f1d-9cc0-08db0a49e362
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;
X-Microsoft-Antispam-Message-Info: wksN0Y9Vip71lZFpkS5My1FoolxuYdrr76CkEWPxYoTpiF/rCPPBJFE15tRFLePMzyCtrmYNFbsjIpS8Qqyj7Lk9iygHDFwkFyNktxVg6qPGHdcITmfi8tjl///ssWzsnEfr1Iwikg5FFqj/WZ2oVc9+yol6I9CuUKaYKYp0CtaVVIxscfji8e4ZJLVgac0kDY/uE1DfVl0cnFP32EQ1OmBkuNmMs9Ag4XCB84c9F9CgFEMJsDRBmDFY65/BBNOGB7Z351g4hXDebJtyWbbCgFKJIeabJlapoHgu9YJ6a43DRlb3Y69HG9CVJ094p/PSjGietJLtlpXZOOaezie3PZuWKKDwxaqFrNs4tFE56pTFEw/yulJIUS35sNZkKu09VzdrG0KtFJlx7SfvcDBTCNGtAToNkRWCzIhadASGcWFpnseDC8/Uhj5ETQRR7/bCintCSC0ezjnTB1nTz0yNrduUejrB5LoGLYJ8JuPIlfgngyYhAeWDgK3BPAwHX8R6KVrHf6VezfBsMDom5SvLE5ppWQbGsfOVlf7uUKMQVLuGlumbPKkFR15/gqJT63xjT/HZS3kSDN6acLGBqZH40tNFYXA5wW+IVbIpd6a1d72bQVcUdQSxhzsa0zvNT/5FcK8DxLq0Q9PzV0NdCrR3xxv+iX3m7js/vRvmck7fxlyoUGB3cHmGP/+CRMGKURBy
X-Forefront-Antispam-Report: CIP:103.192.253.182;CTRY:CN;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:sh-exhtc2.internal.zeku.com;PTR:InfoDomainNonexistent;CAT:NONE;SFS:(13230025)(4636009)(136003)(39850400004)(346002)(396003)(376002)(451199018)(36840700001)(46966006)(356005)(2906002)(8936002)(1076003)(6666004)(81166007)(82740400003)(5660300002)(107886003)(36860700001)(110136005)(82310400005)(426003)(2616005)(47076005)(41300700001)(36756003)(54906003)(70206006)(4326008)(83380400001)(70586007)(86362001)(8676002)(40480700001)(316002)(336012)(26005)(186003)(478600001)(36900700001);DIR:OUT;SFP:1102;
X-OriginatorOrg: zeku.com
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 09 Feb 2023 03:01:06.5432
 (UTC)
X-MS-Exchange-CrossTenant-Network-Message-Id: 3eac3196-879c-4f1d-9cc0-08db0a49e362
X-MS-Exchange-CrossTenant-Id: 171aedba-f024-43df-bc82-290d40e185ac
X-MS-Exchange-CrossTenant-OriginalAttributedTenantConnectingIp: TenantId=171aedba-f024-43df-bc82-290d40e185ac;Ip=[103.192.253.182];Helo=[sh-exhtc2.internal.zeku.com]
X-MS-Exchange-CrossTenant-AuthSource: SG2APC01FT0038.eop-APC01.prod.protection.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Anonymous
X-MS-Exchange-CrossTenant-FromEntityHeader: HybridOnPrem
X-MS-Exchange-Transport-CrossTenantHeadersStamped: SEZPR02MB5784
X-Original-Sender: ouyangweizhao@zeku.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@zeku.com header.s=selector1 header.b=y381y1oc;       arc=pass (i=1
 spf=pass spfdomain=zeku.com dmarc=pass fromdomain=zeku.com);       spf=pass
 (google.com: domain of ouyangweizhao@zeku.com designates 2a01:111:f403:704b::729
 as permitted sender) smtp.mailfrom=ouyangweizhao@zeku.com;       dmarc=pass
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

From: Shuai Yuan <yuanshuai@zeku.com>

Calling start_report() again between start_report() and end_report()
will result in a race issue for the report_lock. In extreme cases this
problem arose in Kunit tests in the hardware tag-based Kasan mode.

For example, when an invalid memory release problem is found,
kasan_report_invalid_free() will print error log, but if an MTE exception
is raised during the output log, the kasan_report() is called, resulting
in a deadlock problem. The kasan_depth not protect it in hardware
tag-based Kasan mode.

Signed-off-by: Shuai Yuan <yuanshuai@zeku.com>
Reviewed-by: Weizhao Ouyang <ouyangweizhao@zeku.com>
Reviewed-by: Peng Ren <renlipeng@zeku.com>
---
 mm/kasan/report.c | 26 +++++++++++++++++++++-----
 1 file changed, 21 insertions(+), 5 deletions(-)

diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index 22598b20c7b7..82aa75259cf4 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -166,7 +166,7 @@ static inline void fail_non_kasan_kunit_test(void) { }
 
 static DEFINE_SPINLOCK(report_lock);
 
-static void start_report(unsigned long *flags, bool sync)
+static bool start_report(unsigned long *flags, bool sync)
 {
 	fail_non_kasan_kunit_test();
 	/* Respect the /proc/sys/kernel/traceoff_on_warning interface. */
@@ -175,8 +175,14 @@ static void start_report(unsigned long *flags, bool sync)
 	lockdep_off();
 	/* Make sure we don't end up in loop. */
 	kasan_disable_current();
-	spin_lock_irqsave(&report_lock, *flags);
+	if (!spin_trylock_irqsave(&report_lock, *flags)) {
+		lockdep_on();
+		kasan_enable_current();
+		pr_err("%s ignore\n", __func__);
+		return false;
+	}
 	pr_err("==================================================================\n");
+	return true;
 }
 
 static void end_report(unsigned long *flags, void *addr)
@@ -468,7 +474,10 @@ void kasan_report_invalid_free(void *ptr, unsigned long ip, enum kasan_report_ty
 	if (unlikely(!report_enabled()))
 		return;
 
-	start_report(&flags, true);
+	if (!start_report(&flags, true)) {
+		pr_err("%s: start report ignore\n", __func__);
+		return;
+	}
 
 	memset(&info, 0, sizeof(info));
 	info.type = type;
@@ -500,10 +509,14 @@ bool kasan_report(unsigned long addr, size_t size, bool is_write,
 
 	if (unlikely(report_suppressed()) || unlikely(!report_enabled())) {
 		ret = false;
+		pr_err("%s: start report ignore\n", __func__);
 		goto out;
 	}
 
-	start_report(&irq_flags, true);
+	if (!start_report(&irq_flags, true)) {
+		ret = false;
+		goto out;
+	}
 
 	memset(&info, 0, sizeof(info));
 	info.type = KASAN_REPORT_ACCESS;
@@ -536,7 +549,10 @@ void kasan_report_async(void)
 	if (unlikely(!report_enabled()))
 		return;
 
-	start_report(&flags, false);
+	if (!start_report(&flags, false)) {
+		pr_err("%s: start report ignore\n", __func__);
+		return;
+	}
 	pr_err("BUG: KASAN: invalid-access\n");
 	pr_err("Asynchronous fault: no details available\n");
 	pr_err("\n");
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230209024536.2334644-1-ouyangweizhao%40zeku.com.
