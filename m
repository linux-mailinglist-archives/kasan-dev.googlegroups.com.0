Return-Path: <kasan-dev+bncBDUNBGN3R4KRBGNAV2PAMGQEW6FGDXA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13b.google.com (mail-il1-x13b.google.com [IPv6:2607:f8b0:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id 3BDCA6764E1
	for <lists+kasan-dev@lfdr.de>; Sat, 21 Jan 2023 08:11:23 +0100 (CET)
Received: by mail-il1-x13b.google.com with SMTP id j11-20020a056e02218b00b0030f3e7a27a8sf4736036ila.2
        for <lists+kasan-dev@lfdr.de>; Fri, 20 Jan 2023 23:11:23 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1674285082; cv=pass;
        d=google.com; s=arc-20160816;
        b=IQgxCqn42njzu4RNFnFPHSI8pC2z0oxrDuBhkpgNJuMWUjnv9w0Js7jKsn1homHXBa
         AR+PJfQJRO463ilhY+G3Y1aSRC9rqJM34npy5s0Ul8CnoQlZjBUtTXzF9YKMZeFYOEpn
         +CJIkUXsBk0BSx0TfEskFU3YmlcVZSBwBEBA75AhSpR9Y2FX5xgvuG66PwcHDRb+SLzm
         qN+2JT4OyKEHA+UUYYw1+Sxihn+afWm3/fERdgFP4XQ/fmPgHVLEEQyci7aEsHA8iro5
         kiIzBbWeCkeVyx3j1PCW0p7jN8qeuMTmt48HvFnqSbZx52KeBzaiBNnSiGyU8dLe9yeU
         gMvg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=mhEQY7QJUMR5P50UCEskgIDjWyyJw2vtwOWV8rGNS/w=;
        b=fb7En260PVYQpSbDGMsPN3AjGbp9wKR1CkRLb5fUdshZ8FehtPePy+Ywd1/ddi1CJd
         iWMNLbq1XEFm5+3pFcnrrMuU6d5mRyw0tV7CiF4BU+BcVv7FRgRInq2DijQX7zF6Ew/0
         UHeqcyd2IAUkL//NgEI4EF1lHv2aBKC1iuDVGhh4mHfL7sRhjm8Bmpw+tFLfgYt6WXVn
         hRBv23j3FU1y9g4+zlvfqximbEoW+yzw7Oc8j8v8dA4Gz9r8LuogO+fS7N35qXvFqtuh
         VFVDNPkqanAq5l20/vV9ealydKp/lW9fU4IE9c6/FLuMKLJO1tQEKByxflI6v/0cn2W3
         JY1g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=bombadil.20210309 header.b=vk156WbC;
       spf=none (google.com: bombadil.srs.infradead.org does not designate permitted sender hosts) smtp.mailfrom=BATV+1651c3ebed9361b307e7+7090+infradead.org+hch@bombadil.srs.infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=mhEQY7QJUMR5P50UCEskgIDjWyyJw2vtwOWV8rGNS/w=;
        b=Jhe75nTr7WUTEpmyX7SF2pgAY5Wg87ee5YjHBXJs5H5okmqdDJoJrt64szZ8/bccSv
         WMere+EMn8/UERIgmhAbXx/iKcfrMEVn4i6RD0Snzj4oGRs7FS38yKccBkhwnTcrKLuJ
         SRuh99ysHeQgrwYYquI/AMbaFcHNcykY7M40M5CQdGAW4ZeS9+1WmGp4gaDI0VDdQ1nt
         9jxZG77skCZ85nduGPwZt/xGqJsbghQ2fwFXDW2IM3BhmxhKQcMsgtFrz5FpOw2/pjaC
         hl4DPHupd8pBKGp6kpSc3+8yNcnZ9/nqEFITZj0clVYrfz1SyIn91jVHiSyaCs21oSEg
         eOxQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=mhEQY7QJUMR5P50UCEskgIDjWyyJw2vtwOWV8rGNS/w=;
        b=xPWLQafvoT6lll26fp8QP2R9I/v3cyT4rPrUgg1ivc/VFnOAfgLm7HU63r/uzoUwPz
         NgLZ3IpCfxYGBzuktZzsnGraZS8nz/VywYWilbVGqaZJcd0eaAOyq/JZ2eSXaG1VbPIg
         9uX3KnTjB8XOgTcIDVgFr5S/zYeeROHmHoYcFkrw8SLnKFbaRiY6kz+Q1Zr19RCclL5S
         VMHhowzitfIxGVCcsYLCMo1oA6awZABPjxDgAPz0PoyJAmDeRGJRcAVoNN1SDuwXa9/i
         M3aPnptvqMCe17RRfLSAeDuwvanjFBC0ks2QCVfzLXKYU9xw14vDyit12mkbzLHCVjTT
         tj+Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2krRJSgyUa6Dw8z3YJxLsWUPad9tzICH6GpNX4uRcdwdPpDPG70E
	SIeffb0wym5XuQxEmMH0lPo=
X-Google-Smtp-Source: AMrXdXslJf7wjdnCC8fUvgoHRODcs4LT3hf51aDvM7EFuxIckdsF/SZyOL7XnUdiW2l7vVro/P8A4g==
X-Received: by 2002:a05:6e02:48b:b0:30e:fdfe:3858 with SMTP id b11-20020a056e02048b00b0030efdfe3858mr1802507ils.215.1674285081876;
        Fri, 20 Jan 2023 23:11:21 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:7a10:0:b0:30f:5830:d010 with SMTP id v16-20020a927a10000000b0030f5830d010ls1006628ilc.2.-pod-prod-gmail;
 Fri, 20 Jan 2023 23:11:21 -0800 (PST)
X-Received: by 2002:a92:d284:0:b0:30e:f15d:4bed with SMTP id p4-20020a92d284000000b0030ef15d4bedmr12982424ilp.30.1674285081280;
        Fri, 20 Jan 2023 23:11:21 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1674285081; cv=none;
        d=google.com; s=arc-20160816;
        b=zrJokhmD1TVI4Q2ivYd2dONqtfZB46yIyhtprWxFebHu1tyVL1ux0D5wuPvaSQ6HPA
         kBmHGmlyCAyD0tSTGnbo8aV+i/zvvN/t6ENDR1u49qLfzO2ncnQkuJj3MBX9k0PIf9l2
         8H64ClsA7kOvl1pWlqjVHLFG2WocizFbyJCHwOEgr5upBqz/a55BDZ44I6B2GSIn/oC5
         a5m5U5xJHLDNgro6gezY9ojc8wY3mYBhq/N+WeT0ZtglTV75FizXeCU84y11xBHjEZXQ
         eihTJ2en0M21kxlMaWuf3iwNT5LH70lhic4tnNKzM9225uz3S5K4aFh13C1hLHx8aEyb
         XrrQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=2FZpTb+3bZJMUpb6YA7LoDb6w4aUjCraFIBMJjAahss=;
        b=b+z2TTJcQ9egL7XNeV6U2tLNG7zyGf4N05wvdg0tr0tDpTXZSEW1GvdZdfQCP/F/Ba
         LFmWA4UM18lBXOtJsbMBPBmv/h69M20CAnjkTiIQVlfALqKiHpM3B/+j/8XbsknByL0M
         YohDnHozDC38R8dWCFg8sl+0yahnA08jMRzLFq5acVxKbqYgZ8L396lUo4U9JCn/tRIp
         yUhjaTndl6d2ae5oBVuCjSdEqoOci6rA54333d00Su0yLVggykBM526NynBFk2QEjLny
         +YuSORmSvq8E0JfCzhKOUBfX067nVtPt/YeJjhi3GgxWux3PAFXAtqjEJcY6dskTSl7d
         cWmw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=bombadil.20210309 header.b=vk156WbC;
       spf=none (google.com: bombadil.srs.infradead.org does not designate permitted sender hosts) smtp.mailfrom=BATV+1651c3ebed9361b307e7+7090+infradead.org+hch@bombadil.srs.infradead.org
Received: from bombadil.infradead.org (bombadil.infradead.org. [2607:7c80:54:3::133])
        by gmr-mx.google.com with ESMTPS id f14-20020a02b78e000000b003a60ce0de5asi880987jam.0.2023.01.20.23.11.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 20 Jan 2023 23:11:21 -0800 (PST)
Received-SPF: none (google.com: bombadil.srs.infradead.org does not designate permitted sender hosts) client-ip=2607:7c80:54:3::133;
Received: from [2001:4bb8:19a:2039:6754:cc81:9ace:36fc] (helo=localhost)
	by bombadil.infradead.org with esmtpsa (Exim 4.94.2 #2 (Red Hat Linux))
	id 1pJ821-00DTsL-5M; Sat, 21 Jan 2023 07:11:17 +0000
From: Christoph Hellwig <hch@lst.de>
To: Andrew Morton <akpm@linux-foundation.org>,
	Uladzislau Rezki <urezki@gmail.com>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org
Subject: [PATCH 09/10] mm: split __vunmap
Date: Sat, 21 Jan 2023 08:10:50 +0100
Message-Id: <20230121071051.1143058-10-hch@lst.de>
X-Mailer: git-send-email 2.39.0
In-Reply-To: <20230121071051.1143058-1-hch@lst.de>
References: <20230121071051.1143058-1-hch@lst.de>
MIME-Version: 1.0
X-SRS-Rewrite: SMTP reverse-path rewritten from <hch@infradead.org> by bombadil.infradead.org. See http://www.infradead.org/rpr.html
X-Original-Sender: hch@lst.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=bombadil.20210309 header.b=vk156WbC;
       spf=none (google.com: bombadil.srs.infradead.org does not designate
 permitted sender hosts) smtp.mailfrom=BATV+1651c3ebed9361b307e7+7090+infradead.org+hch@bombadil.srs.infradead.org
Content-Type: text/plain; charset="UTF-8"
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

vunmap only needs to find and free the vmap_area and vm_strut, so open
code that there and merge the rest of the code into vfree.

Signed-off-by: Christoph Hellwig <hch@lst.de>
---
 mm/vmalloc.c | 84 +++++++++++++++++++++++++---------------------------
 1 file changed, 41 insertions(+), 43 deletions(-)

diff --git a/mm/vmalloc.c b/mm/vmalloc.c
index 5b432508319a4f..6bd811e4b7561d 100644
--- a/mm/vmalloc.c
+++ b/mm/vmalloc.c
@@ -2666,45 +2666,6 @@ static void vm_remove_mappings(struct vm_struct *area, int deallocate_pages)
 	set_area_direct_map(area, set_direct_map_default_noflush);
 }
 
-static void __vunmap(const void *addr, int deallocate_pages)
-{
-	struct vm_struct *area;
-
-	if (!addr)
-		return;
-
-	area = remove_vm_area(addr);
-	if (unlikely(!area)) {
-		WARN(1, KERN_ERR "Trying to vfree() nonexistent vm area (%p)\n",
-				addr);
-		return;
-	}
-
-	vm_remove_mappings(area, deallocate_pages);
-
-	if (deallocate_pages) {
-		int i;
-
-		for (i = 0; i < area->nr_pages; i++) {
-			struct page *page = area->pages[i];
-
-			BUG_ON(!page);
-			mod_memcg_page_state(page, MEMCG_VMALLOC, -1);
-			/*
-			 * High-order allocs for huge vmallocs are split, so
-			 * can be freed as an array of order-0 allocations
-			 */
-			__free_pages(page, 0);
-			cond_resched();
-		}
-		atomic_long_sub(area->nr_pages, &nr_vmalloc_pages);
-
-		kvfree(area->pages);
-	}
-
-	kfree(area);
-}
-
 static void delayed_vfree_work(struct work_struct *w)
 {
 	struct vfree_deferred *p = container_of(w, struct vfree_deferred, wq);
@@ -2757,6 +2718,9 @@ void vfree_atomic(const void *addr)
  */
 void vfree(const void *addr)
 {
+	struct vm_struct *vm;
+	int i;
+
 	if (unlikely(in_interrupt())) {
 		vfree_atomic(addr);
 		return;
@@ -2766,8 +2730,32 @@ void vfree(const void *addr)
 	kmemleak_free(addr);
 	might_sleep();
 
-	if (addr)
-		__vunmap(addr, 1);
+	if (!addr)
+		return;
+
+	vm = remove_vm_area(addr);
+	if (unlikely(!vm)) {
+		WARN(1, KERN_ERR "Trying to vfree() nonexistent vm area (%p)\n",
+				addr);
+		return;
+	}
+
+	vm_remove_mappings(vm, true);
+	for (i = 0; i < vm->nr_pages; i++) {
+		struct page *page = vm->pages[i];
+
+		BUG_ON(!page);
+		mod_memcg_page_state(page, MEMCG_VMALLOC, -1);
+		/*
+		 * High-order allocs for huge vmallocs are split, so
+		 * can be freed as an array of order-0 allocations
+		 */
+		__free_pages(page, 0);
+		cond_resched();
+	}
+	atomic_long_sub(vm->nr_pages, &nr_vmalloc_pages);
+	kvfree(vm->pages);
+	kfree(vm);
 }
 EXPORT_SYMBOL(vfree);
 
@@ -2782,10 +2770,20 @@ EXPORT_SYMBOL(vfree);
  */
 void vunmap(const void *addr)
 {
+	struct vm_struct *vm;
+
 	BUG_ON(in_interrupt());
 	might_sleep();
-	if (addr)
-		__vunmap(addr, 0);
+
+	if (!addr)
+		return;
+	vm = remove_vm_area(addr);
+	if (unlikely(!vm)) {
+		WARN(1, KERN_ERR "Trying to vunmap() nonexistent vm area (%p)\n",
+				addr);
+		return;
+	}
+	kfree(vm);
 }
 EXPORT_SYMBOL(vunmap);
 
-- 
2.39.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230121071051.1143058-10-hch%40lst.de.
