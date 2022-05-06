Return-Path: <kasan-dev+bncBCJZ5QGEQAFBBOHT2KJQMGQENGPXMCA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33f.google.com (mail-wm1-x33f.google.com [IPv6:2a00:1450:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id 27D8E51D0F5
	for <lists+kasan-dev@lfdr.de>; Fri,  6 May 2022 08:01:29 +0200 (CEST)
Received: by mail-wm1-x33f.google.com with SMTP id e9-20020a05600c4e4900b00394779649b1sf908352wmq.3
        for <lists+kasan-dev@lfdr.de>; Thu, 05 May 2022 23:01:29 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1651816889; cv=pass;
        d=google.com; s=arc-20160816;
        b=sdZakwD1kpwr5vI1fmNUAu4Qqx8yMF1M05wDLoNov4D4Cf5Gc2Hxj/PBRvEAeEDDw1
         ZLPFLpo7sVh++e2QG6dLiVwti60KP696Y0HmBuRV36htHaYh0KrJudE1btrz4mUCXsQO
         0dxMVaz0a2Ro3AaDa/8aw89NIXilRNTARN19IhDIhYOqg0H67FTE51ulfS7NSMyz1nRr
         HrKQbRopdacBmxM7mtqFo+2mS3y9KzijyEKri5RGAOLOdGlhtIEn4NOjPzpsT4tF/EO+
         TPuIbsnn0E5Nq3eUdaRAgO/9/3lMwQXU+7R01KbzFCo/RXhpRU9Kx0vVtFH+5/sLCBuY
         +q0A==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=Z9Ai5inAqyZeVQE5sd+M+QWZCAh1dleLHNwaNb7N1uA=;
        b=EX+RYj8Y2sLH5uTFKCPd6r42+pjvdurET4MlywzHgPSoe//GiTu1AuGt0G2+rQP1rA
         zcGRP5e2LEPC5lwZe67/aqP3AkhfdlW++mjdTSHCcymF/1vjbOxIOXscAXOwNWU/60l4
         5fce+hEfeMW9j7ge6y9NawP2CzoZruk4dMEf7+zCYKIUbB6P+KWuXfeyQyTU2cYPBlpD
         hAP+kZrjh+iVFwiSxCliQVL5d/mARi+tI7pIlo3z6fCWz6mbDzdGg+j/Mtm3JBgstr5k
         B+N0J+KMgnN/ehPg3bVdVkzmO5frX/Gi0XA9heNGRn3NCsTVjTEvprpGQ23f5a3gQP/d
         sYzQ==
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@nokia.onmicrosoft.com header.s=selector1-nokia-onmicrosoft-com header.b=yqvyLYXp;
       arc=pass (i=1 spf=pass spfdomain=nokia.com dmarc=pass fromdomain=nokia.com);
       spf=pass (google.com: domain of alexander.sverdlin@nokia.com designates 2a01:111:f400:fe02::72b as permitted sender) smtp.mailfrom=alexander.sverdlin@nokia.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=nokia.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Z9Ai5inAqyZeVQE5sd+M+QWZCAh1dleLHNwaNb7N1uA=;
        b=Vv4KASh3+hr+j9izIwhpHnrKZc4ebXNxBvF89pca+K6a8tCkTAh7k/k+WIPURbTwuL
         mH+WojjkjZUxKrcEWI/j0XH2KayKQz1/ATgrWHco0k3TXNqzmYqEzZ6M5aR1eloACp45
         2AOpBuCB8NY/4yfGo+T8AnDHAB+SrBuXbbIf9OdlWoZxUp6igwymck7JA2v2v5U9aXZ9
         OHCl8Ggnf9BaPRLcGw9gAEiNLos3S1VLV3dSyGPMjd8+yjuhzKOiwcAOfNa04o33XgcE
         gQaoq/rdIZ69OxiPHyqtX36CwGD1i2nb24NytIUSvjuBVBZrzOOKTHa8IdlIbSY4IZQ1
         x+3g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Z9Ai5inAqyZeVQE5sd+M+QWZCAh1dleLHNwaNb7N1uA=;
        b=S0B3qdWPF5GGLoGRrBlVm/b7bKmTettikAE5ujkeeoKLYF3/v/C0dc69nr/76JWWTJ
         +ZZ56HdSAZApom5MqXG+FE8+b4/gPIf1a5NRoS8x/fxnliiUyyjqLNM7+Kpcp20PBDqe
         rXojnQ2E4C3xDLTWAotMVYlN+F3V6z9F/N7m5jwYRpdfyNsTcG+WUjqna2L9yS5Aqi8o
         qEobq5HeAu1i1xuePCcig+Nfm2hpnaPGO5jmZliw9RlRGTbOxW8N+fp2OVNwc+fgCWUz
         P1wbht1hNG3sMJGAUItzheQFNfPyGxcpiAC6j07URQzGC5ba5HW21VYcwVdYBweqSRIx
         vgug==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531sFGdOqNF8GgbpQ+Por7SbYBZV4HjyEdMaUW3RU9jNe+1iVbSl
	2CARsKqfpLX4NXHuOo/DdI8=
X-Google-Smtp-Source: ABdhPJy4RRSYtEhZ6D+diw3nfR9EJGg0E0EZ+tfSgvow4Oj+34Qh0sRaPWrev5uQlE0sH21r60joqQ==
X-Received: by 2002:a05:600c:a45:b0:346:5e67:cd54 with SMTP id c5-20020a05600c0a4500b003465e67cd54mr8271162wmq.127.1651816888414;
        Thu, 05 May 2022 23:01:28 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:1567:b0:20c:5e04:8d9e with SMTP id
 7-20020a056000156700b0020c5e048d9els455467wrz.1.gmail; Thu, 05 May 2022
 23:01:27 -0700 (PDT)
X-Received: by 2002:a5d:47cc:0:b0:20c:6b7c:8a19 with SMTP id o12-20020a5d47cc000000b0020c6b7c8a19mr1214913wrc.608.1651816887532;
        Thu, 05 May 2022 23:01:27 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1651816887; cv=pass;
        d=google.com; s=arc-20160816;
        b=oQVlFLqh9vNGmDDA9xwqlmjqteEEfQytyb01gOXj1XNVxvZPek4fBEKNDjAU0WKLuH
         XCwMdzfcsh8nZ3xuAtmXe+mHJY8DrQnbAhWZAeYKSHJx0CTpYRccNd44eWpBDBXZWP8y
         SDWqSGCS7cQ4hgEcK1wfZYwrzmUQsj47GBsimYUvQ3YiWf/lkHtCeq1aMIqzSQniFWUD
         6ZkEcuus+KYuikevjRxm0WoXFkUe1oI3XPZLqyGbJjFQrOmTb33fc5rIQrgiJgr2+UT/
         DL7F6O0tEp0Dmwglib0xIj81jhpmS1fU3zev6qWsU8UI+8FlG5k6ym+Ow39Z7eLe4u1g
         m+Iw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:subject:cc:to:from:dkim-signature;
        bh=El7Nc3mtKX+LWr3Br1RKEhRC/VMyrNOKCfkT1H7wHB4=;
        b=Me826VUQ35tdPaAAVVq5M8wyAwiOqzbWw/uett+2/xPBRZeX7cpemG3aaPDnlJSwa6
         fdI2vanN82AkPyrWXI6EIDd3FcKIBcwvGOhPSVR19RH9Z1FHd00guEO9Hg5LNk/Q9nqg
         36lr0CG0dvqBpoY1fEcrlho46fSyWYrqSXLJWzI8y4UPicSnb/bkbUy2EDabqe369zWq
         AWSuQhi0wz1LOLPE5qz3DNIUkO/4hGWsfNg6TlH0rW93kk/93oNxX+i2lrtEYGwCEbH2
         0XTy3rHrELHOrtBHv2G3tIZyB1S28v8p4yxHmtEFKToaBuiwDwt06soo8VGjAFcNvazw
         W52w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@nokia.onmicrosoft.com header.s=selector1-nokia-onmicrosoft-com header.b=yqvyLYXp;
       arc=pass (i=1 spf=pass spfdomain=nokia.com dmarc=pass fromdomain=nokia.com);
       spf=pass (google.com: domain of alexander.sverdlin@nokia.com designates 2a01:111:f400:fe02::72b as permitted sender) smtp.mailfrom=alexander.sverdlin@nokia.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=nokia.com
Received: from EUR01-DB5-obe.outbound.protection.outlook.com (mail-db5eur01on072b.outbound.protection.outlook.com. [2a01:111:f400:fe02::72b])
        by gmr-mx.google.com with ESMTPS id a11-20020a05600c348b00b00393eb6edf83si260831wmq.0.2022.05.05.23.01.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 05 May 2022 23:01:27 -0700 (PDT)
Received-SPF: pass (google.com: domain of alexander.sverdlin@nokia.com designates 2a01:111:f400:fe02::72b as permitted sender) client-ip=2a01:111:f400:fe02::72b;
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=j9TH530hMOko4y+a3OZixMLL4FSUZTCGFVxsekcbEMpMBv24cmxpAs9+46/Ufve5cme+FAGrvm+6TgGmLHimymN1NelysnQYG/QMEGQYIOUJtmh3/HV/K5qbNaDVo5tTJ7JCKsuEPgvrZt5/pAn1rOHDtzx+3+ZRIy7KPCD1G5nxvYHia/QYfYqC3/ts+3adckH/ytdgQckyzUAHcgtSqZyk2dEAm5uHy9Tzo3LCPmPGoBYhY5YwaYU9bvOdxyRPYX55POv3xkTSrHhGKMcaQm5mMteX1/xAHzSaB9fWumUYsE/BlJEID6NwJTFJ2MM9GFiuS+nk1KFltO9pW2KbRw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=El7Nc3mtKX+LWr3Br1RKEhRC/VMyrNOKCfkT1H7wHB4=;
 b=i3/IQ2t8UADmh/R/TUGJ0uWl8JvzTvFFGOcKj2/FGr3gGFiqFa07y66k+OXg89qzOPb/JZeuEp9XrxPzTKNCS+b/PXdwTX/4nSj8Gs2p6bJ5BssmhVOy/pkAockWmAjd17HOtcEmDrI1PyClHLQypkWrpGvHI7kJZXYcvBs9mRPKORfZWwPVoJrFOiL9b+vgqHdbWv13jD4sHWaHvJ6Jpawzx5SSVyM4gX3pRSOs9FFkow4keEH6prZUztS5sRNbXQK/jVxBL20BhyBmNlatIJem8kE4YdlVJ3izr9DvVAm+CqrljM6uIKg80zolrqvqHIs8FVkN3/ukJOzR5/beTw==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass (sender ip is
 131.228.2.8) smtp.rcpttodomain=vger.kernel.org smtp.mailfrom=nokia.com;
 dmarc=pass (p=none sp=none pct=100) action=none header.from=nokia.com;
 dkim=none (message not signed); arc=none
Received: from DU2PR04CA0267.eurprd04.prod.outlook.com (2603:10a6:10:28e::32)
 by HE1PR0701MB2345.eurprd07.prod.outlook.com (2603:10a6:3:6c::13) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.5227.18; Fri, 6 May
 2022 06:01:25 +0000
Received: from DBAEUR03FT012.eop-EUR03.prod.protection.outlook.com
 (2603:10a6:10:28e:cafe::74) by DU2PR04CA0267.outlook.office365.com
 (2603:10a6:10:28e::32) with Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.5206.27 via Frontend
 Transport; Fri, 6 May 2022 06:01:25 +0000
X-MS-Exchange-Authentication-Results: spf=pass (sender IP is 131.228.2.8)
 smtp.mailfrom=nokia.com; dkim=none (message not signed)
 header.d=none;dmarc=pass action=none header.from=nokia.com;
Received-SPF: Pass (protection.outlook.com: domain of nokia.com designates
 131.228.2.8 as permitted sender) receiver=protection.outlook.com;
 client-ip=131.228.2.8; helo=fihe3nok0734.emea.nsn-net.net;
Received: from fihe3nok0734.emea.nsn-net.net (131.228.2.8) by
 DBAEUR03FT012.mail.protection.outlook.com (100.127.142.126) with Microsoft
 SMTP Server (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.20.5227.15 via Frontend Transport; Fri, 6 May 2022 06:01:24 +0000
Received: from ulegcparamis.emea.nsn-net.net (ulegcparamis.emea.nsn-net.net [10.151.74.146])
	by fihe3nok0734.emea.nsn-net.net (GMO) with ESMTP id 24661GKm018644;
	Fri, 6 May 2022 06:01:16 GMT
From: Alexander A Sverdlin <alexander.sverdlin@nokia.com>
To: kasan-dev@googlegroups.com
Cc: Alexander Sverdlin <alexander.sverdlin@nokia.com>,
        Russell King <linux@armlinux.org.uk>,
        Andrey Ryabinin <ryabinin.a.a@gmail.com>,
        Alexander Potapenko <glider@google.com>,
        Andrey Konovalov <andreyknvl@gmail.com>,
        Dmitry Vyukov <dvyukov@google.com>,
        Vincenzo Frascino <vincenzo.frascino@arm.com>,
        linux-arm-kernel@lists.infradead.org, linux-kernel@vger.kernel.org
Subject: [PATCH 1/2] ARM: kasan: Support CONFIG_KASAN_VMALLOC
Date: Fri,  6 May 2022 08:01:12 +0200
Message-Id: <20220506060113.14881-1-alexander.sverdlin@nokia.com>
X-Mailer: git-send-email 2.10.2
X-EOPAttributedMessage: 0
X-MS-PublicTrafficType: Email
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-MS-Office365-Filtering-Correlation-Id: 713b2b9f-6663-482e-3fe7-08da2f25da59
X-MS-TrafficTypeDiagnostic: HE1PR0701MB2345:EE_
X-Microsoft-Antispam-PRVS: <HE1PR0701MB23452F77D62B50C75F5E170F88C59@HE1PR0701MB2345.eurprd07.prod.outlook.com>
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;
X-Microsoft-Antispam-Message-Info: LCndEZ7kDQgrKM6WQIG7+/l6CITyedr4GCGis7nNQ8mUqgXk/w3rsgHZIDK8y9W/k5x8lxAUD6hxqBTBoCCGXH54oMSwNaMqL34N7j5O1Rl61yNtNjc75TDeX/H4by/O8ozeuPwmBJ/6QD6rIDDdsXCcfnx1r4UHCxzk3PVpGHw4H0PVu9JcMp4xdeFGUxl4HOlX8SjBGsND2sQUZOAihsELFWps1Ssqx2nTW8CIuSF2LOEwuautBHVbkpi5aFgI3hGygrtQYomL6cBPnJO9LzG1gXb85xWGMKUyfW/PjjzIq2dJmDCNbbx6Mwj4s3LkUC3lhtogAULkjz+yRytCBgjfMmQFt9SVc1ELeg8dmGtmoY1DHZzLTRdRx25bsUOfVUK6QjbudDtQn44QNweiru2MpF6BTyebu0NSL48vOmW6Lp1CDEI41l5VzdrtWvSM2IQId38BhVzleNXMnpVGANg7ZH3OkMfvaB7yVrPTkhPFErJ2/5j3m5QaWv+YBpP7qLY6lyqOGwbjWCkEZg5Mko8c/5YRqiBkDyRsYAgqzdRpb8bHTaOnsTEbvIhvbCw3RzhTvKqRFTdnsNg3YxGZadBMIESPPXPo6LKid4KPVnAvmGTHhiKmvFZr9wLoUlh3q2zlWv0h0PyDeDLkSekNuZvxSHZOBv4IAkvRo+nXYWH7CBXpIi2oqqKivL7O6vEoPt07OzfC79LERn5/Lc5u9PvESeol36M8NS1i+A8j/3B9eQlLnyHWPNPTyIQYcR15
X-Forefront-Antispam-Report: CIP:131.228.2.8;CTRY:FI;LANG:en;SCL:1;SRV:;IPV:CAL;SFV:NSPM;H:fihe3nok0734.emea.nsn-net.net;PTR:InfoDomainNonexistent;CAT:NONE;SFS:(13230001)(4636009)(46966006)(40470700004)(36840700001)(36756003)(26005)(82960400001)(81166007)(36860700001)(47076005)(336012)(83380400001)(2906002)(508600001)(40460700003)(5660300002)(86362001)(8936002)(186003)(316002)(2616005)(6666004)(356005)(82310400005)(70206006)(70586007)(8676002)(4326008)(6916009)(54906003)(1076003)(36900700001);DIR:OUT;SFP:1102;
X-OriginatorOrg: nokia.com
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 06 May 2022 06:01:24.8986
 (UTC)
X-MS-Exchange-CrossTenant-Network-Message-Id: 713b2b9f-6663-482e-3fe7-08da2f25da59
X-MS-Exchange-CrossTenant-Id: 5d471751-9675-428d-917b-70f44f9630b0
X-MS-Exchange-CrossTenant-OriginalAttributedTenantConnectingIp: TenantId=5d471751-9675-428d-917b-70f44f9630b0;Ip=[131.228.2.8];Helo=[fihe3nok0734.emea.nsn-net.net]
X-MS-Exchange-CrossTenant-AuthSource: DBAEUR03FT012.eop-EUR03.prod.protection.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Anonymous
X-MS-Exchange-CrossTenant-FromEntityHeader: HybridOnPrem
X-MS-Exchange-Transport-CrossTenantHeadersStamped: HE1PR0701MB2345
X-Original-Sender: alexander.sverdlin@nokia.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@nokia.onmicrosoft.com header.s=selector1-nokia-onmicrosoft-com
 header.b=yqvyLYXp;       arc=pass (i=1 spf=pass spfdomain=nokia.com
 dmarc=pass fromdomain=nokia.com);       spf=pass (google.com: domain of
 alexander.sverdlin@nokia.com designates 2a01:111:f400:fe02::72b as permitted
 sender) smtp.mailfrom=alexander.sverdlin@nokia.com;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=nokia.com
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

From: Alexander Sverdlin <alexander.sverdlin@nokia.com>

Create KASAN mapping between VMALLOC_START and VMALLOC_END instead of
early shadow if KASAN_VMALLOC is configured.

Signed-off-by: Alexander Sverdlin <alexander.sverdlin@nokia.com>
---
 arch/arm/Kconfig         | 1 +
 arch/arm/mm/kasan_init.c | 7 ++++++-
 2 files changed, 7 insertions(+), 1 deletion(-)

diff --git a/arch/arm/Kconfig b/arch/arm/Kconfig
index 2e8091e..f440cf5 100644
--- a/arch/arm/Kconfig
+++ b/arch/arm/Kconfig
@@ -75,6 +75,7 @@ config ARM
 	select HAVE_ARCH_KFENCE if MMU && !XIP_KERNEL
 	select HAVE_ARCH_KGDB if !CPU_ENDIAN_BE32 && MMU
 	select HAVE_ARCH_KASAN if MMU && !XIP_KERNEL
+	select HAVE_ARCH_KASAN_VMALLOC if HAVE_ARCH_KASAN
 	select HAVE_ARCH_MMAP_RND_BITS if MMU
 	select HAVE_ARCH_PFN_VALID
 	select HAVE_ARCH_SECCOMP
diff --git a/arch/arm/mm/kasan_init.c b/arch/arm/mm/kasan_init.c
index 5ad0d6c5..c2f49f7 100644
--- a/arch/arm/mm/kasan_init.c
+++ b/arch/arm/mm/kasan_init.c
@@ -236,7 +236,12 @@ void __init kasan_init(void)
 
 	clear_pgds(KASAN_SHADOW_START, KASAN_SHADOW_END);
 
-	kasan_populate_early_shadow(kasan_mem_to_shadow((void *)VMALLOC_START),
+	if (IS_ENABLED(CONFIG_KASAN_VMALLOC))
+		create_mapping((void *)VMALLOC_START, (void *)VMALLOC_END);
+	else
+		kasan_populate_early_shadow(kasan_mem_to_shadow((void *)VMALLOC_START),
+					    kasan_mem_to_shadow((void *)VMALLOC_END));
+	kasan_populate_early_shadow(kasan_mem_to_shadow((void *)VMALLOC_END),
 				    kasan_mem_to_shadow((void *)-1UL) + 1);
 
 	for_each_mem_range(i, &pa_start, &pa_end) {
-- 
2.10.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220506060113.14881-1-alexander.sverdlin%40nokia.com.
