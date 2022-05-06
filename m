Return-Path: <kasan-dev+bncBCJZ5QGEQAFBBM7T2KJQMGQEBVBOZLY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43e.google.com (mail-wr1-x43e.google.com [IPv6:2a00:1450:4864:20::43e])
	by mail.lfdr.de (Postfix) with ESMTPS id 90C5451D0F4
	for <lists+kasan-dev@lfdr.de>; Fri,  6 May 2022 08:01:23 +0200 (CEST)
Received: by mail-wr1-x43e.google.com with SMTP id w4-20020adfbac4000000b0020acba4b779sf2198604wrg.22
        for <lists+kasan-dev@lfdr.de>; Thu, 05 May 2022 23:01:23 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1651816883; cv=pass;
        d=google.com; s=arc-20160816;
        b=gFdpJnZOLUx9aohrGQH26X01xv57E/j7cw/2xy6uBX/ZP9UL0WCetmso+9Sil21di/
         QKLkz6gOklXkYZBqf3YJNF37MfT/Up48hSKRMKFI1PdZpkg3VWsWoPWKz3KVFT+Uet8Q
         epX3fQl+AoXqpEjR+Ru/5RhgefyB573yyW2+eTiFZKfpwQPw50W3zZCXC3IZS8hSfLTc
         ZOgjpGp8j5/b+YDdagXA4skQ2Dcc3rnnBsuaExQJG+RXXIeso8E8jaTEBAv2t9tsp4YC
         vniFXmubQ7Aq5RQ43hqIRAncrRk/jx10GMg3R8g32/4c2+NjZ8DVC3+FO5JcIogY+4LT
         Tb0A==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=ZtOPMuqUUvETDiq4va9GZQ0BMQibVOC9l6gf6goPhGY=;
        b=B8R+tZzlaxUNBRtvBe1sJ9/s1omArO6MokI4Qr3vAzGS9N7I76vk+k5YX0xpSS5qZr
         uJi687fHZFXqKG2mPOz5P+l4coKN9azHm3dPFeYRG+9k52pXzsrVrfYOlyFXMwz4Z8ae
         4ImKy20DuDRD1JqvymNoud70cek8XcaEDCqnUXBpuSK5SFzwby0t5h747GEB4z2hSP0P
         OGoFq2XDQ+ZAMNZgIPASg53WW8555dsqlOrpwYt/fPiPgOMsMjqcWrWxO9O6CShAmxKT
         jW+MPZVKmcQEwQJrnRRV13hYe+gapsknnT1dMzpLb/YKDLYLQ6OcXD8PAf3oiVbADlaO
         JBhw==
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@nokia.onmicrosoft.com header.s=selector1-nokia-onmicrosoft-com header.b=MOhkFsuN;
       arc=pass (i=1 spf=pass spfdomain=nokia.com dmarc=pass fromdomain=nokia.com);
       spf=pass (google.com: domain of alexander.sverdlin@nokia.com designates 2a01:111:f400:fe0c::702 as permitted sender) smtp.mailfrom=alexander.sverdlin@nokia.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=nokia.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ZtOPMuqUUvETDiq4va9GZQ0BMQibVOC9l6gf6goPhGY=;
        b=qPk6n+wpdZ5t+Igc0NPPdYWsvSwHOfXqnmV2NAFOTfkkP7atqZkqb07VxDsINEvjGb
         vh+/VDzSGhWLDw7q3mPg2C+rwD8CWjuOZr4uekHM+nN722lmD0TVowI4OLbmyLI22vcd
         YXCl6xboFegZl1o58lh9mKkAZ4pIatdc2gNM/pJTLRBfMgSnVLnxBdYzrPsmAYOMUxCz
         7Be1ikwD+bAU4Wxnn+YWI0fEF9kL6bIRYe9OLkSMRm3eV0R3iRwiuCvLoJnoW3Jnm6NL
         1tOMpoCHG8PSgHX23OEALou7aVJI34eYxqv9wFyOLR5yA+m6R5zTNnci00SFf39Idmdd
         PYLA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ZtOPMuqUUvETDiq4va9GZQ0BMQibVOC9l6gf6goPhGY=;
        b=PZoF6rlVTNV0GpHnLWNAgpnQS35BLDIKPvAappeaZpRZStLJFwclz3aWEN3soEv2hy
         uxvGE2MLw0Uhkt5igwoyXzUzoXHK+7Evv4V9fBXkeXG1HurMJv59prkFCNrbC7FOCQtL
         y8RarVmlP1S5eZAO2HQSeHJCGrOlSExlQW5J8dJu0r+FvnEZ3BUuz9Y3ptEwUZCls1fd
         oI09Hc6XKOnz0CdSBWqoBBg9JNPv33hWhhvbuF3yY3jvfciQYhs3iamy8aEemTY/ty/q
         smgOPZj04F8UhM92mVdUPkrZK2Kt0o7f63ToqUS4Uquu6OP0RDJ6NWfk0y6CDM2P80KE
         Zjvg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533Mi/y8fTkhBIFZMj12nhTX3LOnFrTW5dhFgZfD+T584hThrlc5
	9VslAF8MjmXB1iFQdDidkQI=
X-Google-Smtp-Source: ABdhPJzex93ftE9WA6vuhocGbph6/369u9eIMT2+cBJbmziZZh+QRmUxM8ONUmyBBorxy3reLKXagQ==
X-Received: by 2002:a7b:c347:0:b0:37e:68e6:d85c with SMTP id l7-20020a7bc347000000b0037e68e6d85cmr8508030wmj.176.1651816883207;
        Thu, 05 May 2022 23:01:23 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:1567:b0:20c:5e04:8d9e with SMTP id
 7-20020a056000156700b0020c5e048d9els455060wrz.1.gmail; Thu, 05 May 2022
 23:01:22 -0700 (PDT)
X-Received: by 2002:a05:6000:168c:b0:20c:6072:f82a with SMTP id y12-20020a056000168c00b0020c6072f82amr1227068wrd.410.1651816882250;
        Thu, 05 May 2022 23:01:22 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1651816882; cv=pass;
        d=google.com; s=arc-20160816;
        b=R3d4AV2HR9O4sXTuuFMHozv2sxGNGHujUhaKXH8gi25Z2EauARf9I0o1EDRc54w1Rs
         03XOKh2awdI9YK22Ao4Xj8EW4yYQCO6b4w33TtF/9f5x9aOU9vHiykbd8lqM+p0/STWH
         gxvqK543hyXE2x6Bt/RLGxj6t68c9BPbaioKo3pxKjuAkZi3BXhQ0AImGfEcwxBxB6eP
         Lzctw43fVjrq138m3Sq0XjnZ5XC3AhEGnOz1V/TMXjZqOlLkq5ASsXwqaeqZR8oxKo+D
         hxHuuvSU3RGyd6Ow7xEXxlPaRYNy+aELWDbEh2Fhh+S0XqYaFgVoR1PX6mLVCT/JGEvb
         tSTw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:in-reply-to:message-id:date:subject:cc:to
         :from:dkim-signature;
        bh=cbriUybfpReIgm3SoMDo3ayAPM+zbPmOVTAUaWJ5WJk=;
        b=NQ4iUifDTHjGTvQALNu7/BnwS+6PXOCWJsJIPqB6Lgd6qHUVL/Tu72SCWA956MzwQC
         IohQp+8az/45q0lI3AHc6wz9hSYmOxZOCpFWvUsGjAeVTpxdInsqJk1cyqxmeDcrux+J
         RYHQONY2WzM76G84s+KesM2omF7gptC/k5rtCTegOe5yzU6yBCvhhdRCpFMAv0MME7OT
         iHHcdShCpwVaVXoKY9t69xZqiTOfXpYLXfBaq9ZFZm41F9YXn0mxaV8YEXVpSc+GwL0x
         e8Yt7wfMN303uINOZbv800OdbxE6BDSgR9zAAJK41NQ13gK5RzA64CB0EAMzAyFZY8sy
         t+oA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@nokia.onmicrosoft.com header.s=selector1-nokia-onmicrosoft-com header.b=MOhkFsuN;
       arc=pass (i=1 spf=pass spfdomain=nokia.com dmarc=pass fromdomain=nokia.com);
       spf=pass (google.com: domain of alexander.sverdlin@nokia.com designates 2a01:111:f400:fe0c::702 as permitted sender) smtp.mailfrom=alexander.sverdlin@nokia.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=nokia.com
Received: from EUR04-DB3-obe.outbound.protection.outlook.com (mail-db3eur04on0702.outbound.protection.outlook.com. [2a01:111:f400:fe0c::702])
        by gmr-mx.google.com with ESMTPS id h11-20020a5d548b000000b0020c6d76cc7fsi171682wrv.7.2022.05.05.23.01.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 05 May 2022 23:01:22 -0700 (PDT)
Received-SPF: pass (google.com: domain of alexander.sverdlin@nokia.com designates 2a01:111:f400:fe0c::702 as permitted sender) client-ip=2a01:111:f400:fe0c::702;
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=G61DInEOv2eEeuxmvw7aZas/y97RtQjE10UCQLLn9DTuJEWTEpBWfjfGV2JQRvyXpfswUg6zdYfRZ3bAFwjJQkiN86JxEnynOqGjJL3QhVR6mrb3zXg185F73fyO7souUPabsmASpWQ1+1ERcF0CJIqGr9dqbJIcyMFQYg6XZGY3qcmrrB/jFYmig+TSaqdUjTZ27Vcby83HNqImg4np8cs+n8akIk42hoGUJaTaHwjFCV97qnuk4tBonEZ4dDJICcOdohr3qfnYGVIjdV4wEsgeeQTI5KxLXfC+azSTFBAMp+5RDS+3CU1YoZtKZmvOJLyrGqk2fN4oYG1p6cOPig==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=cbriUybfpReIgm3SoMDo3ayAPM+zbPmOVTAUaWJ5WJk=;
 b=n15VzyxqNzf+y3K/zv682Q/yvhNVM7SicMkT7QiGcvF4hGHcHoo89pS8x9HP473oQYbv80VgXYJBSQ0r6RG43WqdDFMaoI5zf8CSqH/V9fFDINaxSeP9T21ixdC27fbmKIpzArFQrAy5GqCNn5bcQDHJBwATxEIZXB0tUd+BFgAnfgDjjAn0w8ogszMpDJiRW0lVtS4W5731nqlJtnsSpMW/QJL7ETrQ9pXCc6ZgHGJ7UMi6zfVigRFfHviS3UD5JJcwzkhO8jMGYAEStUT8L2ZpFP/u5WxVFxkPnizFK5ILT10VBAwoKD4vKmxV3YqE60oBGlKoule6rCWMGCDQIQ==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass (sender ip is
 131.228.2.8) smtp.rcpttodomain=vger.kernel.org smtp.mailfrom=nokia.com;
 dmarc=pass (p=none sp=none pct=100) action=none header.from=nokia.com;
 dkim=none (message not signed); arc=none
Received: from DB7PR05CA0008.eurprd05.prod.outlook.com (2603:10a6:10:36::21)
 by AM0PR07MB4449.eurprd07.prod.outlook.com (2603:10a6:208:75::18) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.5227.18; Fri, 6 May
 2022 06:01:20 +0000
Received: from DBAEUR03FT036.eop-EUR03.prod.protection.outlook.com
 (2603:10a6:10:36:cafe::4) by DB7PR05CA0008.outlook.office365.com
 (2603:10a6:10:36::21) with Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.5206.27 via Frontend
 Transport; Fri, 6 May 2022 06:01:20 +0000
X-MS-Exchange-Authentication-Results: spf=pass (sender IP is 131.228.2.8)
 smtp.mailfrom=nokia.com; dkim=none (message not signed)
 header.d=none;dmarc=pass action=none header.from=nokia.com;
Received-SPF: Pass (protection.outlook.com: domain of nokia.com designates
 131.228.2.8 as permitted sender) receiver=protection.outlook.com;
 client-ip=131.228.2.8; helo=fihe3nok0734.emea.nsn-net.net;
Received: from fihe3nok0734.emea.nsn-net.net (131.228.2.8) by
 DBAEUR03FT036.mail.protection.outlook.com (100.127.142.193) with Microsoft
 SMTP Server (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.20.5227.15 via Frontend Transport; Fri, 6 May 2022 06:01:20 +0000
Received: from ulegcparamis.emea.nsn-net.net (ulegcparamis.emea.nsn-net.net [10.151.74.146])
	by fihe3nok0734.emea.nsn-net.net (GMO) with ESMTP id 24661GKn018644;
	Fri, 6 May 2022 06:01:17 GMT
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
Subject: [PATCH 2/2] ARM: kasan: Fix compatibility with ARM_MODULE_PLTS
Date: Fri,  6 May 2022 08:01:13 +0200
Message-Id: <20220506060113.14881-2-alexander.sverdlin@nokia.com>
X-Mailer: git-send-email 2.10.2
In-Reply-To: <20220506060113.14881-1-alexander.sverdlin@nokia.com>
References: <20220506060113.14881-1-alexander.sverdlin@nokia.com>
X-EOPAttributedMessage: 0
X-MS-PublicTrafficType: Email
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-MS-Office365-Filtering-Correlation-Id: 7de4f0e2-98d3-4c56-72bd-08da2f25d779
X-MS-TrafficTypeDiagnostic: AM0PR07MB4449:EE_
X-Microsoft-Antispam-PRVS: <AM0PR07MB444962B664766BF74F13758788C59@AM0PR07MB4449.eurprd07.prod.outlook.com>
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;
X-Microsoft-Antispam-Message-Info: S2DYiuXfkYQpAtZoe76SBLfw9+dFnXW61J7q6fc2o7a4KT+9LVexjiC7V+1SOH+6SPAE1uImu0mFQvqyM6Y0wuZ7KRi7pVg0u/6B0FmmNbk3WdB3bYSmaeepoRjmGhEoBNAAKpfLiggXa6Ic4DxEgaDhXH9fSNxiv4s1t8E//vk14ZHYnwBxXISjgNSMgbSTBXvLPblDHQECtgnJvqNVyj7O6wZOKmkX/GtffsubKM057n6QtuRY5Gb8bXHHZ8G5iI3vLVgYZ1uxCP1T5UEnwUNQXkB1Iq/lHFBEMpN//4KVlxnysAOPLgUT4plCNhV4OfEpRhc80lnt3plRpHJRr8K5lbVwuq47uTbizE+n7huLAP9YFNRrdb+EO5htPIOXMtbnn4OoLBa7+fXL4+aMAfWH/r5vht+mYo/alvygO5ACqJjRt3hzdqBUXEW8MfqVvrkVArBeiYIvZ2FpyKa+HCF8cHu8T1XIeZ5SKGSxEyS6TVo62YWnKQLulAhQ7Q1JoPrNLbqZHAbke4VT3mEnYQ45uw3ZPJHA8OUftIf5yx/a7eBV8WVAguhC0ajFGSKRWbCmSRpr9I9oRKZdCj1dejvp+BTf5E2uJdCtlYq4PtufK34ulBQ6YNiPWe3lpoUyaLN48aN21Crt5r0IbDKxTUyzHcAPvT5oyf2j/oAoEOvt16INL70PRgSi/ajPqeDVlUOJK9OVMYOnUsuVAzF5fQ0kI8JZ3/P1ouebn5U49lNql/zyMl3p570KkSskDwfiE5pKH3WmCWpuhPjlRjUAzw==
X-Forefront-Antispam-Report: CIP:131.228.2.8;CTRY:FI;LANG:en;SCL:1;SRV:;IPV:CAL;SFV:NSPM;H:fihe3nok0734.emea.nsn-net.net;PTR:InfoDomainNonexistent;CAT:NONE;SFS:(13230001)(4636009)(46966006)(40470700004)(36840700001)(36860700001)(83380400001)(47076005)(2906002)(40460700003)(6666004)(336012)(82310400005)(70586007)(8676002)(4326008)(70206006)(356005)(8936002)(508600001)(36756003)(82960400001)(81166007)(316002)(6916009)(54906003)(1076003)(2616005)(186003)(5660300002)(26005)(86362001)(36900700001);DIR:OUT;SFP:1102;
X-OriginatorOrg: nokia.com
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 06 May 2022 06:01:20.0765
 (UTC)
X-MS-Exchange-CrossTenant-Network-Message-Id: 7de4f0e2-98d3-4c56-72bd-08da2f25d779
X-MS-Exchange-CrossTenant-Id: 5d471751-9675-428d-917b-70f44f9630b0
X-MS-Exchange-CrossTenant-OriginalAttributedTenantConnectingIp: TenantId=5d471751-9675-428d-917b-70f44f9630b0;Ip=[131.228.2.8];Helo=[fihe3nok0734.emea.nsn-net.net]
X-MS-Exchange-CrossTenant-AuthSource: DBAEUR03FT036.eop-EUR03.prod.protection.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Anonymous
X-MS-Exchange-CrossTenant-FromEntityHeader: HybridOnPrem
X-MS-Exchange-Transport-CrossTenantHeadersStamped: AM0PR07MB4449
X-Original-Sender: alexander.sverdlin@nokia.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@nokia.onmicrosoft.com header.s=selector1-nokia-onmicrosoft-com
 header.b=MOhkFsuN;       arc=pass (i=1 spf=pass spfdomain=nokia.com
 dmarc=pass fromdomain=nokia.com);       spf=pass (google.com: domain of
 alexander.sverdlin@nokia.com designates 2a01:111:f400:fe0c::702 as permitted
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

Select KASAN_VMALLOC if KASAN && ARM_MODULE_PLT. Otherwise module load into
vmalloc area crashes the kernel:

Unable to handle kernel paging request at virtual address bce42b5c
CPU: 1 PID: 454 Comm: systemd-udevd
PC is at mmioset+0x7e/0xa0
LR is at kasan_unpoison_shadow+0x1b/0x24
Stack:
(mmioset) from (kasan_unpoison_shadow+0x1b/0x24)
(kasan_unpoison_shadow) from (__asan_register_globals+0x27/0x4c)
(__asan_register_globals) from (do_init_module+0x13d/0x5b8)
(do_init_module) from (load_module+0x6733/0x80f8)
(load_module) from (sys_finit_module+0x119/0x140)
(sys_finit_module) from (ret_fast_syscall+0x1/0x5a)

Signed-off-by: Alexander Sverdlin <alexander.sverdlin@nokia.com>
---
 arch/arm/Kconfig | 1 +
 1 file changed, 1 insertion(+)

diff --git a/arch/arm/Kconfig b/arch/arm/Kconfig
index f440cf5..d9d60a3 100644
--- a/arch/arm/Kconfig
+++ b/arch/arm/Kconfig
@@ -1519,6 +1519,7 @@ config HW_PERF_EVENTS
 config ARM_MODULE_PLTS
 	bool "Use PLTs to allow module memory to spill over into vmalloc area"
 	depends on MODULES
+	select KASAN_VMALLOC if KASAN
 	default y
 	help
 	  Allocate PLTs when loading modules so that jumps and calls whose
-- 
2.10.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220506060113.14881-2-alexander.sverdlin%40nokia.com.
