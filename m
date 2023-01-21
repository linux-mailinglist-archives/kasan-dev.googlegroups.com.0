Return-Path: <kasan-dev+bncBDUNBGN3R4KRBFFAV2PAMGQEIFTQASI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x738.google.com (mail-qk1-x738.google.com [IPv6:2607:f8b0:4864:20::738])
	by mail.lfdr.de (Postfix) with ESMTPS id 49D976764DE
	for <lists+kasan-dev@lfdr.de>; Sat, 21 Jan 2023 08:11:17 +0100 (CET)
Received: by mail-qk1-x738.google.com with SMTP id bm30-20020a05620a199e00b007090f3c5ec0sf3251650qkb.21
        for <lists+kasan-dev@lfdr.de>; Fri, 20 Jan 2023 23:11:17 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1674285076; cv=pass;
        d=google.com; s=arc-20160816;
        b=u1302aAAx3t5gGI592F376/ipKFWb22Urb0H7rf7FCOVchqmMl6dFHo6s2xlwoHJNt
         adUUNMoRNI9erv1diCcWhb+7gpZG5KDha8b2y8gXUrIOux7eTlxqkiYosjucq+TDgx26
         o1xRc32LUfEm1SsQnwEFhF0FlQCLXN6nNSYTjQ6UZBUAawgT16Rqdvlbxn2K8wppCaYG
         3G/yaMogVEv1JVninOsQIWqha9/M1X+WFdkFefp+wgT79z5LSoStMJ7ZXCdw+uFIVv/N
         QaMHzQ30dkLIRNq0KMgz579OXOy+E7wgwjkuOnIoi+pbyPu2lUWIwqalQLb1GCjoWILZ
         UoEw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=10UgKPWAp0gxDI0Yb/badHlOP/wBo3xVGWWg1FMdl0U=;
        b=kRVUDZiXueMSStjeQhNY6/qEN1Fn37R+y+p+FFUxOryFUg3sNigPPWs6HVMJgI7T3G
         /6kcP1zlFWtK6nKFLhh8+hHDObbh38PjoC/9mlGrC1p7tENa0A63Hxp5RcfCM3nCguGK
         3BC8NI48dhS3OdS7TkKDGYB7We4nKokeZCv6URpYTVnrB+zksM55ffZeUC2/UtWSTT+7
         QFHhbYK4S/ok4e1znJ/JwgBnHScwzS7WrOcsqvLsg62YNKSEaaYcYV9xb0MNnu1EkddS
         Au59afMJWnWUoQbGBcb1JvpE2ff0aTZGmfFSlKTvH5pTM3ldBnv4SWG5flmRuEK0Zq2O
         JXEg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=bombadil.20210309 header.b=XM+vtBXe;
       spf=none (google.com: bombadil.srs.infradead.org does not designate permitted sender hosts) smtp.mailfrom=BATV+1651c3ebed9361b307e7+7090+infradead.org+hch@bombadil.srs.infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=10UgKPWAp0gxDI0Yb/badHlOP/wBo3xVGWWg1FMdl0U=;
        b=Y57KpzEbSu8P99LFnbF9bg7zhDphFnMn9swy8HIRlLdqlElst2LyeB3Zfihtg9oVRr
         z+SlUXcty3RLJzeb/AsCHOCIqS0zBG0+dbuj1gueKcvZB8nyEyP8ZCxqI3SqsiWNFKoc
         uLQRupyM2KbxBZ0fQa83F/9MUIN8yuvzDdozI/vmMv/6YeIIQ82F/8q/PgqSNFd3hI+q
         0CMBNrSdEUjO8BmdQVFy9rtPuiVHhK4H5xPVqcvm7LberN4l8pp9OjKkttFh/rh93iBT
         +VQ2kwG3ogeXhvQQeGHtbXFL3nUupPpUasbpSuPoG12ws2izJ+8DPZKoaZqxZ6c6vuxY
         2hNQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=10UgKPWAp0gxDI0Yb/badHlOP/wBo3xVGWWg1FMdl0U=;
        b=GXRnW85poraP5ct71QRftWbFmfNVbmDOjSocGZaJrmnfMFCxdAPsAevT9aE5Fzr41A
         /eImFyS2LmFBS3piJxCdVu564EOOSxfQxpOWdiWuZ3tQMOvduH6jSOdiU9jXoalPgdAQ
         j1IWmO+roPjFeDgFmhxCiGkxIKCggZKLd7TadowK2ic3KhmWF0wXiLBZMfY67g87HPTs
         QkjktdnvTu9YpBBhrxSezGrm0OKPOfnZOW7j9zKeKrIEmm5I/yU9dE/ejqMdGyZyhTkY
         4J0COflZ7fmeF0bNIzMYx9TmPvY2JrzRC+BitteUvWloqmc4TBKVgeaod1JwF+dVap8d
         HjWA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2krzsPUqTRFTZFmYK9iqmd4SZfAlSkwfkzWHGHv3lhuHzo2cOLui
	bCdTgjWQna7l2mj1Ruoawds=
X-Google-Smtp-Source: AMrXdXu6jXHSIC/myBR8N2C3MJVKpi5dvkwZV0VaAKjoTb7cXsCnhhYD1JrtPSE2mI4F7IgH1A+XSQ==
X-Received: by 2002:ad4:418e:0:b0:535:5d2b:f91f with SMTP id e14-20020ad4418e000000b005355d2bf91fmr352544qvp.38.1674285076423;
        Fri, 20 Jan 2023 23:11:16 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0c:a914:0:b0:532:228d:cad5 with SMTP id y20-20020a0ca914000000b00532228dcad5ls4163717qva.2.-pod-prod-gmail;
 Fri, 20 Jan 2023 23:11:16 -0800 (PST)
X-Received: by 2002:a0c:910d:0:b0:535:2730:c922 with SMTP id q13-20020a0c910d000000b005352730c922mr23631741qvq.42.1674285075967;
        Fri, 20 Jan 2023 23:11:15 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1674285075; cv=none;
        d=google.com; s=arc-20160816;
        b=J3HkkQoIKdvy2xvaRQ1H5YiXCTAhl/uuVfppkz7pK2dRqBY801O7XmvE6Qtw6U+YWM
         FXvTpF35hsO92ZCViVwNWlicfHZ2SPkhJCRIxjmOoo1VnuxGDdBHypBHVF+oVUAQ2OOO
         fHhyX2F01Gkz8WtOpjWSxovrAJDdOi7h4LO/To886XphgXP76KYY7RX3jPlwiV20wUuD
         YXzfqxo84Eiv7hQqEPJW2ooC89kbRJGuDAyXI7EcTAgPn0oj9BKrJolCe5JGa7UUc8Se
         3QOvjn13zGG1Oqr+6lVvZPkCSPtgGwVNSCm5FOuBkUntwtn1sn48SZnGraFm0/wg4aSP
         u4GQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=/LORA17lyKlGYgS2Flqkv2l85bKFZsz0OAvq3/+VRvg=;
        b=Rt2NDJipRsBxb0GUWQ9jz+NbcVH5OFYr3ZDdH630Groxb+oHFd1Wf+P1HtTeg0NvvV
         oBEmG9C1Ar/Wxs7S+L+pRNFn5TSU8JRMZLPO0wbew30EXB/1SlW3eK0WmALC3PxtKsdK
         0+L4FyFowPhglD6HflkLNf6jBoktk6yWKwapZXU33pH3afIgJINB5E2fEmcY8OMkYRgg
         tIGHDcTyD0Dwghp0D9Mj74QmWFHwgN56o4NCn/62DuoR55bx8AahMHc+iOJC8zIugpEj
         E65apk+25V7JuIYRQig2//VNOfhaWailpEhss69UkEmttxCkESAfA6mVFNeNKqJhIqcr
         CxmQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=bombadil.20210309 header.b=XM+vtBXe;
       spf=none (google.com: bombadil.srs.infradead.org does not designate permitted sender hosts) smtp.mailfrom=BATV+1651c3ebed9361b307e7+7090+infradead.org+hch@bombadil.srs.infradead.org
Received: from bombadil.infradead.org (bombadil.infradead.org. [2607:7c80:54:3::133])
        by gmr-mx.google.com with ESMTPS id j14-20020a05620a146e00b007066299ced4si1316897qkl.5.2023.01.20.23.11.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 20 Jan 2023 23:11:15 -0800 (PST)
Received-SPF: none (google.com: bombadil.srs.infradead.org does not designate permitted sender hosts) client-ip=2607:7c80:54:3::133;
Received: from [2001:4bb8:19a:2039:6754:cc81:9ace:36fc] (helo=localhost)
	by bombadil.infradead.org with esmtpsa (Exim 4.94.2 #2 (Red Hat Linux))
	id 1pJ81v-00DTqj-OJ; Sat, 21 Jan 2023 07:11:12 +0000
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
Subject: [PATCH 07/10] mm: use remove_vm_area in __vunmap
Date: Sat, 21 Jan 2023 08:10:48 +0100
Message-Id: <20230121071051.1143058-8-hch@lst.de>
X-Mailer: git-send-email 2.39.0
In-Reply-To: <20230121071051.1143058-1-hch@lst.de>
References: <20230121071051.1143058-1-hch@lst.de>
MIME-Version: 1.0
X-SRS-Rewrite: SMTP reverse-path rewritten from <hch@infradead.org> by bombadil.infradead.org. See http://www.infradead.org/rpr.html
X-Original-Sender: hch@lst.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=bombadil.20210309 header.b=XM+vtBXe;
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

Use the common helper to find and remove a vmap_area instead of open
coding it.

Signed-off-by: Christoph Hellwig <hch@lst.de>
Reviewed-by: Uladzislau Rezki (Sony) <urezki@gmail.com>
---
 mm/vmalloc.c | 33 ++++++++++++---------------------
 1 file changed, 12 insertions(+), 21 deletions(-)

diff --git a/mm/vmalloc.c b/mm/vmalloc.c
index ee0d641019c30b..97156eab6fe581 100644
--- a/mm/vmalloc.c
+++ b/mm/vmalloc.c
@@ -2571,20 +2571,6 @@ struct vm_struct *find_vm_area(const void *addr)
 	return va->vm;
 }
 
-static struct vm_struct *__remove_vm_area(struct vmap_area *va)
-{
-	struct vm_struct *vm;
-
-	if (!va || !va->vm)
-		return NULL;
-
-	vm = va->vm;
-	kasan_free_module_shadow(vm);
-	free_unmap_vmap_area(va);
-
-	return vm;
-}
-
 /**
  * remove_vm_area - find and remove a continuous kernel virtual area
  * @addr:	    base address
@@ -2597,10 +2583,18 @@ static struct vm_struct *__remove_vm_area(struct vmap_area *va)
  */
 struct vm_struct *remove_vm_area(const void *addr)
 {
+	struct vmap_area *va;
+	struct vm_struct *vm;
+
 	might_sleep();
 
-	return __remove_vm_area(
-		find_unlink_vmap_area((unsigned long) addr));
+	va = find_unlink_vmap_area((unsigned long)addr);
+	if (!va || !va->vm)
+		return NULL;
+	vm = va->vm;
+	kasan_free_module_shadow(vm);
+	free_unmap_vmap_area(va);
+	return vm;
 }
 
 static inline void set_area_direct_map(const struct vm_struct *area,
@@ -2666,7 +2660,6 @@ static void vm_remove_mappings(struct vm_struct *area, int deallocate_pages)
 static void __vunmap(const void *addr, int deallocate_pages)
 {
 	struct vm_struct *area;
-	struct vmap_area *va;
 
 	if (!addr)
 		return;
@@ -2675,20 +2668,18 @@ static void __vunmap(const void *addr, int deallocate_pages)
 			addr))
 		return;
 
-	va = find_unlink_vmap_area((unsigned long)addr);
-	if (unlikely(!va)) {
+	area = remove_vm_area(addr);
+	if (unlikely(!area)) {
 		WARN(1, KERN_ERR "Trying to vfree() nonexistent vm area (%p)\n",
 				addr);
 		return;
 	}
 
-	area = va->vm;
 	debug_check_no_locks_freed(area->addr, get_vm_area_size(area));
 	debug_check_no_obj_freed(area->addr, get_vm_area_size(area));
 
 	kasan_poison_vmalloc(area->addr, get_vm_area_size(area));
 
-	__remove_vm_area(va);
 	vm_remove_mappings(area, deallocate_pages);
 
 	if (deallocate_pages) {
-- 
2.39.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230121071051.1143058-8-hch%40lst.de.
