Return-Path: <kasan-dev+bncBCC7DBWDQAJBBIWHT2TAMGQEAJPYHOQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x139.google.com (mail-il1-x139.google.com [IPv6:2607:f8b0:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id C98F176958F
	for <lists+kasan-dev@lfdr.de>; Mon, 31 Jul 2023 14:05:55 +0200 (CEST)
Received: by mail-il1-x139.google.com with SMTP id e9e14a558f8ab-34916ad5387sf11495425ab.1
        for <lists+kasan-dev@lfdr.de>; Mon, 31 Jul 2023 05:05:55 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1690805154; cv=pass;
        d=google.com; s=arc-20160816;
        b=JoAU0KqQ6r0WCP76hAzlNPGQKsXiONNp+RBvNLW72S5msmQm/nN5wg2bRzGlfxb2oI
         ypxHrV5MC4GeyoKHurNR0+B029KMF/21YoIkrTTfS1pVtQlrYkIJ/YtRDW8VQGeNLF0j
         ruuqp2kVJnaowUZY+WDg20OaGNEkozlegCXxTlVxKjwcken7PRj2W4S/bY1j33C3zHJ3
         kzPBt4qpgH0GpEYgt6r6BVgDDrfi4DASMvGEQaGU/olJ9+qVO20dYHk+JAY22wxnaa4J
         GWyXJXYIJmdpnqgaXmp8Cy70me0LOZGJcunjANhVJx5yXSZA/37ymqhwSAsaqWeUsF3O
         QYUA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:message-id
         :date:subject:cc:to:from:dkim-signature;
        bh=NbcykpXd4WIZ7BmQ8WQWNeRSRRZkQzuw3tm05Fe3jPo=;
        fh=KzuEqemKgsvLg+WwwA1JssjMW5ynv/9KW0G5Swvjx1o=;
        b=AMMfGBWtvdOC/RPLVmdlyuAOLXXxELwmuwVhOAEx8At7db8WoiQ444+XD7QSYwJAm3
         WMYJIC1VNaVy3gcMKQUyptS7tDaGt8NtJ92K0Ve6CIisfPwcKIlJewRaHHk1QmOV6Hb5
         j+RwRWjaKsSlt/va3H/X5RaWjSLYJ3+etsiiBFqS0WUfo9pVXA3Izd6QuyWdJrKr1jQ8
         T/rEYV2AUSme+vE4UOavMvLOoCgpjawLt3qx3Wv4Os0fOZh0NDtyR28JhZQb7kRjd4ZS
         iVPLZNpvxLZ8kKgDzUCl1Cww8iNf8q4av9h3qN4uFxFRR/AmbP4OAfMx61DkO6O10x7h
         aXVQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=dkhSndMq;
       spf=pass (google.com: domain of mark-pk.tsai@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=mark-pk.tsai@mediatek.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1690805154; x=1691409954;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:from:to:cc:subject:date
         :message-id:reply-to;
        bh=NbcykpXd4WIZ7BmQ8WQWNeRSRRZkQzuw3tm05Fe3jPo=;
        b=O7/gMGDKe2CB10kcvcqvHYfggHbu+7j7Y8TPkZrdUdgT27I5YfUqCnoL9yS1OoXI+x
         9dEgQew/lWy/8GoAkcZadaxEknixMiJUi1Cn660sJz0xH4ZghQ/UOGOXTMuMZkoLbSel
         kSvBa3vCHpoTBaia95VI08mTndsd06tbmBNSWZ+Q2wi5Xc00F9sokbGOokBW008LosJp
         KEwLn+TyZLJcbe+con6YyYQfYJcImkepR/mM/j1GtWjRkmkaUq47Himj9dpQFFmS+QfR
         bqn7yC7e/DwJj4zKHfPPlxHwnJI2Y2FYXEdIP27FN9Ozpx31UIlXgbe0ZzkvBieXtVLe
         GgrA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1690805154; x=1691409954;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=NbcykpXd4WIZ7BmQ8WQWNeRSRRZkQzuw3tm05Fe3jPo=;
        b=hYwG0CbZYfF3mgIOLShhCoGALHjwYnMTMI1VJ4aG9i2VaYj4Xe5WdMD01ZDVZ8Zn4A
         aWmviuUJo1hr5XixWJGyA8JmQyOFBx/gEBi6HWZJ8cZgTxnLE3UdqCTzve6nmKbkSeEY
         ERYeGP5KLmsDZmBewo40lfWDXsbmgrWnXOBDrGDVZFy11rThiY0MKIfm0zOtOBvfL7md
         M3rxeVyT/Bgt2WDuOl9syI7ce8OS9ACNWIqKdkA3dLRMev5O1LgRhJnrR0uw7AI3QAfl
         gyWMcy0w5oCE/EW6l2ErZVWiwFJ6bufYjxSGYum7tF62+NklJ3bJNgJujA8UeVsRPMxx
         AYUA==
X-Gm-Message-State: ABy/qLbTT9mCsvX4INQEWzPdhBibNoyNG8wZXg+y0ZnJ8tQjJhO+NYlF
	zukbXtWw/n8UgF5emrpw2/4=
X-Google-Smtp-Source: APBJJlFAgnO2NlpIQqaQzii3JQcWL+noIgLvtrMM6fF58jbBVHOJinnoEetyPBopwjzAmB2GJ03Wnw==
X-Received: by 2002:a05:6e02:1d05:b0:348:9e12:13f8 with SMTP id i5-20020a056e021d0500b003489e1213f8mr9277090ila.27.1690805154190;
        Mon, 31 Jul 2023 05:05:54 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:7c0a:0:b0:348:81c5:d1cf with SMTP id x10-20020a927c0a000000b0034881c5d1cfls2928872ilc.1.-pod-prod-06-us;
 Mon, 31 Jul 2023 05:05:53 -0700 (PDT)
X-Received: by 2002:a05:6e02:def:b0:349:6b7:b03f with SMTP id m15-20020a056e020def00b0034906b7b03fmr7971167ilj.23.1690805153389;
        Mon, 31 Jul 2023 05:05:53 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1690805153; cv=none;
        d=google.com; s=arc-20160816;
        b=it+3eXrCQBQV14NKuhWJFocRNm5ZlpWN352JSLpy9BARRKsmEiaLvKU1GtY6TdUHku
         z8XPM4MNXUkHdHu/cDCxslqaxEXjJNXw0gFqvjSq2/nRvdJVTJ4F3ez3CLXjOpyM1c/h
         WSPTcvRkuo+rCwg1rstZAGgZqMDROx23JuFxc2EuDGQNlsUBRlciM4dnW0q5R6PU6jBq
         0rwrM2w+khg2aqPQyKZJO/yPjQqlggxF1Uo6hDMk+827ZU9DrCowqMbNqQksdAB6Eecq
         mtUhwJ2NEcChFIfSrTsCZ2sRKd4LaEQF5pTqcdb8T9OhVq3srkRETXbwUmcjhQvWbAyD
         WO+g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:subject:cc:to:from:dkim-signature;
        bh=C6CrSBdjoAyzVpB6u/w8qzO48wNDLvceWe2rRQBmWzY=;
        fh=xPz9/4W86eE1k+3tCnyVusRA5QBWjrMuJUN7jlubcu4=;
        b=aiJv3KuNqPtSen9IuDugVFyUq+5uUXTlc6hUWp0LbfrqdZU0cYYU1vx529r50Zojm/
         59vUQrvV63MItE9IOTl8AH/qYhUdF4vJ+nbx7JwT6HMSeCYmDc/EY9GIU6Vo+HKrdVq1
         j1lHiJGc0mZU4CdVJ+UN1KhAzTMi10XQe7bJKD9jy8W8c9ZK/sIQZTmMHQaQzeoElpoi
         aeZ2RxLBiVdN27phddYLQm6TImteseC4ZlTWHZMtt3d3KV39NlVOlKGzj0e6r7HRs0Oy
         VRLYxONMUoY5Saez0MOs32b/vUnQA9Y+ecXklyeXHgq5vW5BhcU63ojrxuJIP/Ckz7q0
         n7pA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=dkhSndMq;
       spf=pass (google.com: domain of mark-pk.tsai@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=mark-pk.tsai@mediatek.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=mediatek.com
Received: from mailgw02.mediatek.com ([210.61.82.184])
        by gmr-mx.google.com with ESMTPS id h8-20020a056e02052800b00348ce3977b5si615447ils.1.2023.07.31.05.05.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 31 Jul 2023 05:05:53 -0700 (PDT)
Received-SPF: pass (google.com: domain of mark-pk.tsai@mediatek.com designates 210.61.82.184 as permitted sender) client-ip=210.61.82.184;
X-UUID: 966417702f9a11eeb20a276fd37b9834-20230731
X-CID-P-RULE: Release_Ham
X-CID-O-INFO: VERSION:1.1.30,REQID:e10c6e47-7cf2-4c21-9392-b58fe3e93d76,IP:0,U
	RL:0,TC:0,Content:-25,EDM:0,RT:0,SF:0,FILE:0,BULK:0,RULE:Release_Ham,ACTIO
	N:release,TS:-25
X-CID-META: VersionHash:1fcc6f8,CLOUDID:c39bfbb3-a467-4aa9-9e04-f584452e3794,B
	ulkID:nil,BulkQuantity:0,Recheck:0,SF:102,TC:nil,Content:0,EDM:-3,IP:nil,U
	RL:0,File:nil,Bulk:nil,QS:nil,BEC:nil,COL:0,OSI:0,OSA:0,AV:0,LES:1,SPR:NO,
	DKR:0,DKP:0,BRR:0,BRE:0
X-CID-BVR: 0
X-CID-BAS: 0,_,0,_
X-CID-FACTOR: TF_CID_SPAM_SNR
X-UUID: 966417702f9a11eeb20a276fd37b9834-20230731
Received: from mtkmbs10n2.mediatek.inc [(172.21.101.183)] by mailgw02.mediatek.com
	(envelope-from <mark-pk.tsai@mediatek.com>)
	(Generic MTA with TLSv1.2 ECDHE-RSA-AES256-GCM-SHA384 256/256)
	with ESMTP id 1546789419; Mon, 31 Jul 2023 20:05:48 +0800
Received: from mtkmbs11n2.mediatek.inc (172.21.101.187) by
 mtkmbs11n2.mediatek.inc (172.21.101.187) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.2.1118.26; Mon, 31 Jul 2023 20:05:47 +0800
Received: from mtksdccf07.mediatek.inc (172.21.84.99) by
 mtkmbs11n2.mediatek.inc (172.21.101.73) with Microsoft SMTP Server id
 15.2.1118.26 via Frontend Transport; Mon, 31 Jul 2023 20:05:47 +0800
From: "'Mark-PK Tsai' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko
	<glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov
	<dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, Russell
 King <linux@armlinux.org.uk>, Matthias Brugger <matthias.bgg@gmail.com>,
	AngeloGioacchino Del Regno <angelogioacchino.delregno@collabora.com>
CC: <yj.chiang@mediatek.com>, Mark-PK Tsai <mark-pk.tsai@mediatek.com>,
	<kasan-dev@googlegroups.com>, <linux-arm-kernel@lists.infradead.org>,
	<linux-kernel@vger.kernel.org>, <linux-mediatek@lists.infradead.org>
Subject: [PATCH] arm: kasan: Use memblock_alloc_try_nid_raw for shadow page allocation
Date: Mon, 31 Jul 2023 20:05:36 +0800
Message-ID: <20230731120537.13152-1-mark-pk.tsai@mediatek.com>
X-Mailer: git-send-email 2.18.0
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-MTK: N
X-Original-Sender: mark-pk.tsai@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@mediatek.com header.s=dk header.b=dkhSndMq;       spf=pass
 (google.com: domain of mark-pk.tsai@mediatek.com designates 210.61.82.184 as
 permitted sender) smtp.mailfrom=mark-pk.tsai@mediatek.com;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=mediatek.com
X-Original-From: Mark-PK Tsai <mark-pk.tsai@mediatek.com>
Reply-To: Mark-PK Tsai <mark-pk.tsai@mediatek.com>
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

kasan_pte_populate fill KASAN_SHADOW_INIT in the newly
allocated shadow page, so it's unnecessary to
use memblock_alloc_try_nid, which always zero the
new allocated memory.

Use memblock_alloc_try_nid_raw instead of
memblock_alloc_try_nid like arm64 does which
can make kasan init faster.

Signed-off-by: Mark-PK Tsai <mark-pk.tsai@mediatek.com>
---
 arch/arm/mm/kasan_init.c | 8 +++++++-
 1 file changed, 7 insertions(+), 1 deletion(-)

diff --git a/arch/arm/mm/kasan_init.c b/arch/arm/mm/kasan_init.c
index 24d71b5db62d..111d4f703136 100644
--- a/arch/arm/mm/kasan_init.c
+++ b/arch/arm/mm/kasan_init.c
@@ -28,6 +28,12 @@ static pgd_t tmp_pgd_table[PTRS_PER_PGD] __initdata __aligned(PGD_SIZE);
 
 pmd_t tmp_pmd_table[PTRS_PER_PMD] __page_aligned_bss;
 
+static __init void *kasan_alloc_block_raw(size_t size)
+{
+	return memblock_alloc_try_nid_raw(size, size, __pa(MAX_DMA_ADDRESS),
+				      MEMBLOCK_ALLOC_NOLEAKTRACE, NUMA_NO_NODE);
+}
+
 static __init void *kasan_alloc_block(size_t size)
 {
 	return memblock_alloc_try_nid(size, size, __pa(MAX_DMA_ADDRESS),
@@ -50,7 +56,7 @@ static void __init kasan_pte_populate(pmd_t *pmdp, unsigned long addr,
 			if (!pte_none(READ_ONCE(*ptep)))
 				continue;
 
-			p = kasan_alloc_block(PAGE_SIZE);
+			p = kasan_alloc_block_raw(PAGE_SIZE);
 			if (!p) {
 				panic("%s failed to allocate shadow page for address 0x%lx\n",
 				      __func__, addr);
-- 
2.18.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230731120537.13152-1-mark-pk.tsai%40mediatek.com.
