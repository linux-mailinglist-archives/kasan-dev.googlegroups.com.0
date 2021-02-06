Return-Path: <kasan-dev+bncBCN7B3VUS4CRB7NJ7GAAMGQEYKUIMNA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83d.google.com (mail-qt1-x83d.google.com [IPv6:2607:f8b0:4864:20::83d])
	by mail.lfdr.de (Postfix) with ESMTPS id A1558311C30
	for <lists+kasan-dev@lfdr.de>; Sat,  6 Feb 2021 09:36:14 +0100 (CET)
Received: by mail-qt1-x83d.google.com with SMTP id v13sf7036058qtq.18
        for <lists+kasan-dev@lfdr.de>; Sat, 06 Feb 2021 00:36:14 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1612600573; cv=pass;
        d=google.com; s=arc-20160816;
        b=LIPC9XgIalaVJu5Y0F2HBF6v36C9QMvkFBuJYypEtvHn3aQP0kEbwVs+hdOHtYPSPQ
         ftGxJmK0f1rGt3mXlcxNqrftY3dcwevOcW4+od9vYcVZEdIMG/bL51zzZPMsG5uvj6Wv
         GFocJD9ehnFKVerR6yeuVeQKBl02uo9hnoj8CIzsv7XFUI16/BeXFIK/ib8q7M+hIyLl
         kYlzOiXVIKSpPdmoARTjrDdpWWaJwx6n0Klg++PWZswcS1RTTGGBhYfpgpCnwqLliVN4
         ujJo0zQTWZR//t10U2ibJi8PEB2vnhAkSBVFarxSNbNqH+8aRuIa8JsXjFp/c39nZOKU
         Ti4g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=pf8LoM0As9Pf7Ubu2PJJ7FaLiapOIoMZsAuUcfjIWd8=;
        b=ql0Q09cHXosm3fDaBBqp78MGobdbaB7lmmhMZ3i/geoS9dDZwmsGBwCydONWw+xHab
         /rIm8i21xzbDvpyhOXv67Z9D+y9QSk8WVWlhlqk8bEmiGb3JPUkzDMQ3tqIdCrQSdrVM
         SqYtZrz5f36mRRGwub9odvOFGyQvfMNcS+AM/GESs3ZdNJLNNQyBkhigWXpPdbQZGI2D
         sFnqeJJmNP0G4jZviD2H0VO4HZ+YkR9hfxYKQs/oZ+O/ntTWRism/vKsGO4hkP35+QqX
         lH9giP+g77l4Qjl/rNiG/UHJO77oMD0wIsgArIACpdDyeeBtWkkSq2wMGl+pQnehDdBJ
         rXiA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of lecopzer.chen@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=lecopzer.chen@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=pf8LoM0As9Pf7Ubu2PJJ7FaLiapOIoMZsAuUcfjIWd8=;
        b=f6wjiIbPBEOFJTKbgJ+fXljPdgvqe6y6ODyrLHQirezAYrwwTizXkwd5iQPaFKEj+J
         /j7Zv++F7cUfYCtctcsVVx2ATQEEJmY03ZKiuXUxl+0GiF99s7MGdw+xGsaps11ed4hj
         xojJDuoHzBRCj3HOjc9Sp/u6O7wx7HXq80bAThDm2TY6N8TAyt837mZppykD1eqL0o01
         UInOA14u4QOdGtqG5Rwvb5mTPvogW2zips3eOPU/2xJCX3+F6aLJaZhHGfTdqZ2Hz4W+
         sK0l4dvNI5x7imnGhT9QlJcVRwiEHUtuSCUaGiu4cGg7wKhU86IJ60vLcfYVa32cUx0F
         MQIQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=pf8LoM0As9Pf7Ubu2PJJ7FaLiapOIoMZsAuUcfjIWd8=;
        b=cxdRTWIjE+WE95Hmybm8kINrvALRFQyfu4xffysdJEGqhnWqVq6K8amk4MnQkQj966
         1zkoByUNfNsSZ3JtxFfow1vAszTvmWusZBs4SsrcUiY5kNBvUUI97MYaIVKFWI83esH6
         Xlh1qQGybk/xQUv7nLscOgjVaI0bIZuyamRP08clCBm9wA38IwNI/5PVcsj3imRfGJ6b
         M1NAGqVdvsofohygM7WECli5lY/VKENn/bYjHLheS4j14ARd7wpP4jDk93022pXXXdPK
         dNNpZzM23pZgANfoOuyR8+VwxlRxqyvTlJSxibIaN6654ysB0rZIRm9LJ6ioMdzrG0Iw
         /Lvg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533fo+yGU15JFZFrBLykk9Gr/reAl5UuzB1WqxvVEL11PM35ZQRt
	iO3BtrVJN1WqAZ11nQaZZnA=
X-Google-Smtp-Source: ABdhPJzS+HP6fZLRWRVa7knEOel9WiH6LxQHLzJlUnoS3wf+GSToi142ZwWuCFDSPF22cUJ0t2qBeg==
X-Received: by 2002:a05:622a:514:: with SMTP id l20mr8072619qtx.62.1612600573336;
        Sat, 06 Feb 2021 00:36:13 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0c:e60c:: with SMTP id z12ls2847045qvm.0.gmail; Sat, 06 Feb
 2021 00:36:13 -0800 (PST)
X-Received: by 2002:a0c:abce:: with SMTP id k14mr8235058qvb.23.1612600573002;
        Sat, 06 Feb 2021 00:36:13 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1612600572; cv=none;
        d=google.com; s=arc-20160816;
        b=IFrEguY3SWIe7hraJagW+E+GvX23T9+LQENn2q7+qdCSWgE9fto+1V2SyhjNnFMbUk
         F0IWDsubg2V6AbiB9YSVxBAsm6c/EI30PBBmgtRr3v7Vcjj4OEYavbksg/uuLZRVfhmj
         GetIU6FGj5g7H1pwld/g9vuzuHYkA2F7TBgPaSalvifSR+afggjZcPEPyqB4UAQrZwSZ
         oMT7bsy+tbaEee0hLuksBtTtaxahkncozULF0XyB0IPYw3r3rQaqOQoN5Ozqc02HP5yg
         MJ+KH8n/woKTMo8ad0HO6GATZEzQcYtPkQEzZ293caTf3wbzJP+1lUau1FxyU5AAhPEQ
         7o9Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:in-reply-to:message-id:date:subject:cc:to
         :from;
        bh=xjESqlUb86RQ6iRPUx+QrIUmLWqLivYfrQTN5THOZlI=;
        b=svvenPgrdZ+BRbAWLIjMZR9ib6/G+P+oXewxzwdl/gMsTiJiMaQwTT7ya0gOHKip9d
         MrbZH+Xgc9xCSVPwlXmTxstnxlzazelanRUNn9fgCsz6ivmoY3gibBqY12GPiCzKSRZ7
         y2z7KM4hSfyzOxwgO7qvG3MGi+fBC2H87ote9D0m/2xgw/jmTjgBfpH04NJkG+Hv05MQ
         HayjEqFfILde6VIFT8oujY0BYw6u5RQAJPJBiHU86iCK0V8Lywezlz0++1aXlWv0WeBk
         jhNmAnrmGyCiZSi5/S+TlEtbXRZPA3Oa/YVW2AGsvMn5ZNzIYPscsUzoEtqeeC1OJMBf
         QgVw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of lecopzer.chen@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=lecopzer.chen@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw02.mediatek.com ([210.61.82.184])
        by gmr-mx.google.com with ESMTP id p6si538757qti.1.2021.02.06.00.36.12
        for <kasan-dev@googlegroups.com>;
        Sat, 06 Feb 2021 00:36:12 -0800 (PST)
Received-SPF: pass (google.com: domain of lecopzer.chen@mediatek.com designates 210.61.82.184 as permitted sender) client-ip=210.61.82.184;
X-UUID: 9d3405466d6343438602b56379476005-20210206
X-UUID: 9d3405466d6343438602b56379476005-20210206
Received: from mtkmrs01.mediatek.inc [(172.21.131.159)] by mailgw02.mediatek.com
	(envelope-from <lecopzer.chen@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.14 Build 0819 with TLSv1.2 ECDHE-RSA-AES256-SHA384 256/256)
	with ESMTP id 1824139656; Sat, 06 Feb 2021 16:36:09 +0800
Received: from mtkcas11.mediatek.inc (172.21.101.40) by
 mtkmbs08n2.mediatek.inc (172.21.101.56) with Microsoft SMTP Server (TLS) id
 15.0.1497.2; Sat, 6 Feb 2021 16:36:07 +0800
Received: from mtksdccf07.mediatek.inc (172.21.84.99) by mtkcas11.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Sat, 6 Feb 2021 16:36:08 +0800
From: Lecopzer Chen <lecopzer.chen@mediatek.com>
To: <linux-kernel@vger.kernel.org>, <linux-mm@kvack.org>,
	<kasan-dev@googlegroups.com>, <linux-arm-kernel@lists.infradead.org>,
	<will@kernel.org>
CC: <dan.j.williams@intel.com>, <aryabinin@virtuozzo.com>,
	<glider@google.com>, <dvyukov@google.com>, <akpm@linux-foundation.org>,
	<linux-mediatek@lists.infradead.org>, <yj.chiang@mediatek.com>,
	<catalin.marinas@arm.com>, <ardb@kernel.org>, <andreyknvl@google.com>,
	<broonie@kernel.org>, <linux@roeck-us.net>, <rppt@kernel.org>,
	<tyhicks@linux.microsoft.com>, <robin.murphy@arm.com>,
	<vincenzo.frascino@arm.com>, <gustavoars@kernel.org>, <lecopzer@gmail.com>,
	Lecopzer Chen <lecopzer.chen@mediatek.com>
Subject: [PATCH v3 4/5] arm64: kaslr: support randomized module area with KASAN_VMALLOC
Date: Sat, 6 Feb 2021 16:35:51 +0800
Message-ID: <20210206083552.24394-5-lecopzer.chen@mediatek.com>
X-Mailer: git-send-email 2.18.0
In-Reply-To: <20210206083552.24394-1-lecopzer.chen@mediatek.com>
References: <20210206083552.24394-1-lecopzer.chen@mediatek.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-TM-SNTS-SMTP: DEC81A8B4BED333FFD3CB4BEEA964F8E7288657F38F621992E8AA30C4139E42E2000:8
X-MTK: N
X-Original-Sender: lecopzer.chen@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of lecopzer.chen@mediatek.com designates 210.61.82.184 as
 permitted sender) smtp.mailfrom=lecopzer.chen@mediatek.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
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

After KASAN_VMALLOC works in arm64, we can randomize module region
into vmalloc area now.

Test:
	VMALLOC area ffffffc010000000 fffffffdf0000000

	before the patch:
		module_alloc_base/end ffffffc008b80000 ffffffc010000000
	after the patch:
		module_alloc_base/end ffffffdcf4bed000 ffffffc010000000

	And the function that insmod some modules is fine.

Suggested-by: Ard Biesheuvel <ardb@kernel.org>
Signed-off-by: Lecopzer Chen <lecopzer.chen@mediatek.com>
---
 arch/arm64/kernel/kaslr.c  | 18 ++++++++++--------
 arch/arm64/kernel/module.c | 16 +++++++++-------
 2 files changed, 19 insertions(+), 15 deletions(-)

diff --git a/arch/arm64/kernel/kaslr.c b/arch/arm64/kernel/kaslr.c
index 1c74c45b9494..a2858058e724 100644
--- a/arch/arm64/kernel/kaslr.c
+++ b/arch/arm64/kernel/kaslr.c
@@ -161,15 +161,17 @@ u64 __init kaslr_early_init(u64 dt_phys)
 	/* use the top 16 bits to randomize the linear region */
 	memstart_offset_seed = seed >> 48;
 
-	if (IS_ENABLED(CONFIG_KASAN_GENERIC) ||
-	    IS_ENABLED(CONFIG_KASAN_SW_TAGS))
+	if (!IS_ENABLED(CONFIG_KASAN_VMALLOC) &&
+	    (IS_ENABLED(CONFIG_KASAN_GENERIC) ||
+	     IS_ENABLED(CONFIG_KASAN_SW_TAGS)))
 		/*
-		 * KASAN does not expect the module region to intersect the
-		 * vmalloc region, since shadow memory is allocated for each
-		 * module at load time, whereas the vmalloc region is shadowed
-		 * by KASAN zero pages. So keep modules out of the vmalloc
-		 * region if KASAN is enabled, and put the kernel well within
-		 * 4 GB of the module region.
+		 * KASAN without KASAN_VMALLOC does not expect the module region
+		 * to intersect the vmalloc region, since shadow memory is
+		 * allocated for each module at load time, whereas the vmalloc
+		 * region is shadowed by KASAN zero pages. So keep modules
+		 * out of the vmalloc region if KASAN is enabled without
+		 * KASAN_VMALLOC, and put the kernel well within 4 GB of the
+		 * module region.
 		 */
 		return offset % SZ_2G;
 
diff --git a/arch/arm64/kernel/module.c b/arch/arm64/kernel/module.c
index fe21e0f06492..b5ec010c481f 100644
--- a/arch/arm64/kernel/module.c
+++ b/arch/arm64/kernel/module.c
@@ -40,14 +40,16 @@ void *module_alloc(unsigned long size)
 				NUMA_NO_NODE, __builtin_return_address(0));
 
 	if (!p && IS_ENABLED(CONFIG_ARM64_MODULE_PLTS) &&
-	    !IS_ENABLED(CONFIG_KASAN_GENERIC) &&
-	    !IS_ENABLED(CONFIG_KASAN_SW_TAGS))
+	    (IS_ENABLED(CONFIG_KASAN_VMALLOC) ||
+	     (!IS_ENABLED(CONFIG_KASAN_GENERIC) &&
+	      !IS_ENABLED(CONFIG_KASAN_SW_TAGS))))
 		/*
-		 * KASAN can only deal with module allocations being served
-		 * from the reserved module region, since the remainder of
-		 * the vmalloc region is already backed by zero shadow pages,
-		 * and punching holes into it is non-trivial. Since the module
-		 * region is not randomized when KASAN is enabled, it is even
+		 * KASAN without KASAN_VMALLOC can only deal with module
+		 * allocations being served from the reserved module region,
+		 * since the remainder of the vmalloc region is already
+		 * backed by zero shadow pages, and punching holes into it
+		 * is non-trivial. Since the module region is not randomized
+		 * when KASAN is enabled without KASAN_VMALLOC, it is even
 		 * less likely that the module region gets exhausted, so we
 		 * can simply omit this fallback in that case.
 		 */
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210206083552.24394-5-lecopzer.chen%40mediatek.com.
