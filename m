Return-Path: <kasan-dev+bncBDUNBGN3R4KRBDFAV2PAMGQEDVVZG5I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x113c.google.com (mail-yw1-x113c.google.com [IPv6:2607:f8b0:4864:20::113c])
	by mail.lfdr.de (Postfix) with ESMTPS id E039B6764DC
	for <lists+kasan-dev@lfdr.de>; Sat, 21 Jan 2023 08:11:09 +0100 (CET)
Received: by mail-yw1-x113c.google.com with SMTP id 00721157ae682-4c11ae6ab25sf71401337b3.8
        for <lists+kasan-dev@lfdr.de>; Fri, 20 Jan 2023 23:11:09 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1674285069; cv=pass;
        d=google.com; s=arc-20160816;
        b=bgYR8l7rTqfrS56XwtAPVyx1jkuniY+AAWO6thgod8OO96LBNflWu6Z6IdbzCeKwDW
         8pvIBq9Gu8ez7yyuNTs81IV50VoHEBMLpDPmYDfUT5FYPMdh2NXj9iZYKXZkkWo0GxKb
         0Yuqb+AbVPcZM7e7ECKD9278zyqle1CBha16LlMOqfodKh/otXggiKCD6b4WzsmpRltU
         y6H1ovNflYqhnR/po/R9nfJITeoj6/BNcpbiXEol3Z5vIpz7vI5R1khh/X0YwbDPjIWb
         SqD53z2mqypo86lXmLyxge5+Hi1Xw5Y9Dj5ERMN7ZsW2SzHfVh15ZbJ4ZyGCmstudgHf
         nDiA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=zsBUBOqa3gnBCr96LKM8bfd1hEct/3Rob97fyiyAN8o=;
        b=Os0liupCMdhsXMgWoBLC+EuKukodogx6jQezFiJGaUq5QEzsQc23TLe2zskckTf9o6
         llCCSKbHX8jtAoB/oP1zoKGuq2YlnOIJAyntLZaIPL/nKFbzePbh+NjLGzVWoq9P9LPn
         wuz7pT8BjNoK5+OcmLoUiLpq/s3UrAqBsKYjY1OFBWReuPUA988iC2VUc2H/M8syL1c2
         V99L2Pg6Ukwv9FILoqe1v7/L6gt+9Os2WCLOQ4EqSsSMk7sfXut5AiIhg7Lo3UKZi/+9
         TrmZS5vaKlNTkFmi6dKrGNN7wCYvsdl+VF/1Fo010UOTtJsSmefvstx7vaHDtqiN4Ec6
         EOiA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=bombadil.20210309 header.b=mCKo0YMQ;
       spf=none (google.com: bombadil.srs.infradead.org does not designate permitted sender hosts) smtp.mailfrom=BATV+1651c3ebed9361b307e7+7090+infradead.org+hch@bombadil.srs.infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=zsBUBOqa3gnBCr96LKM8bfd1hEct/3Rob97fyiyAN8o=;
        b=Z+IdzImeszj75JJO5h23pxmpp2GgTx7angcsUhdnMTKnFNEV7zGZ07fTJuAc5O4bz8
         S/zcKn0Dn/oHmtJsuB9sYO+uQmpYc8kp+fBpiivMv0OMVfJs3G5+Xf99ob3wdderdd5j
         fxNaZl5nW+fn4SQ7c/ch1zHL6OtGgVSNQ5/2ChHm1M0dytGBDUTwCQ5a6IcbSGwx3YPO
         ct7H4Eh70oN7emitPlXVkL0xx6BdrhTuKvpw21aFdrFjEvwW+Zq69GldIH1VsCHjtPlW
         Rg2O9X2vryGmcJTVWYQuwJ7oz85kssJGsvVDeLKN5ipLFufeY+GfDSG80UwgzRpMrYt+
         LhwA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=zsBUBOqa3gnBCr96LKM8bfd1hEct/3Rob97fyiyAN8o=;
        b=q29EFkIdwXquyp2bEqu3+QOLQi1SciOr+5x62HSefY+P9ri5Fx5Rv0Kw+LUtkf2fBH
         8x/cnPuGOfCVWOIGcrf7RoQwYbngo8gkEZATvbVvEI9Fquy69mWWgp9ACubVmOPfROXr
         Up0LKiVOf0dyJIGZNplLAU7YXZU/OcSWBSX4m/AowfPumAxiPe/hIFOYJhBtCzp/jqsE
         YVP0qzYVX1OhjdKLhkA2I9sahbJubx4yQJPrYf4G340xWIa10QxlImWKUd42WN78TlDo
         PzB/fbp54rbEZRxuW1kKYPtrTY1UEnmCcQpnjW2s4QPkkazo7KNhEy20kVvQhhMiT9mX
         +Suw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2kpiDTzLlj4vwgZ3MVj2QGTbF9EWME0nCbpLNsg+ulKB2NmnyP+c
	QVylY89NR0wO05HmXEfKhOU=
X-Google-Smtp-Source: AMrXdXtUccOBNDRK6x66FLF2H8X0IfaSUoScwEx7GWbEeX/Syqp8JbJryxjv2yEh14rUKRcyPJ+yvg==
X-Received: by 2002:a81:1b97:0:b0:4db:ea4d:3a48 with SMTP id b145-20020a811b97000000b004dbea4d3a48mr2219890ywb.323.1674285068917;
        Fri, 20 Jan 2023 23:11:08 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:5083:0:b0:803:a6eb:e217 with SMTP id e125-20020a255083000000b00803a6ebe217ls1316950ybb.8.-pod-prod-gmail;
 Fri, 20 Jan 2023 23:11:08 -0800 (PST)
X-Received: by 2002:a25:d242:0:b0:803:17d0:22b8 with SMTP id j63-20020a25d242000000b0080317d022b8mr2384781ybg.54.1674285068342;
        Fri, 20 Jan 2023 23:11:08 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1674285068; cv=none;
        d=google.com; s=arc-20160816;
        b=UUmGU9iMLQUL+ix8QuSV5njfUntRzePLHuz8s6wuomj2OW+ciw7i2UaX93LoibS7ya
         mHdHMAFpP4bo6zQz6oFR7wAvUbJSE/cTTEfea7eiZ1Ur285buQmrreMlsrYy8yTbwrBf
         dsSAESDjUdriryM3ej2jAlliX+E6P8jO66y4fJ3ZKFTdhrc0bkAYF7+uccRPWzHpTQD0
         HPbBg1T6Ss11yijNGIDC8D32zzkMn0ZnB8su0kOg7+yrBJf+vT4Gvl/h7f7AqYAwiwSJ
         z9z46rYr6rZQI+wb8uDtCeVCqBQ8koOdVfMpZGli1MANcxDlosuKfe0dv2MXoZAeOCR4
         F87Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=2b7jwqEZ/VORicHVoAJulj/DOUixU6O3VS17e+UwuxA=;
        b=Owc6zJWbBZzNlrdK/SMgojLDwGwOcl63MbJdGoRgzmO4b4Hfnw5X2tUkoHTSgYjLmS
         krX5gsMuzoAAmcLC1VWiZPQbirkJKpmVnqe/WMGvk9vyNLgq6Ix32s6crX5d9oKEkddp
         rgd9FpV04rljxguB4ILXuImIjQ9cOGVvTMBze8LlECL/jN4EF8eCw9o0OQ8uDghcehTc
         RxEIRnMSYFoKgouru/hOWlzZkZjcUXPIQintqNo7to85oZaycsq1P0guwQBGzpXf11Jx
         U26zhvUwKlKzW1Fw6VHlEmm9GxDesWuKIncqneIlaHkcYeXDi0XlN9L3T/Nd+EIVRKpd
         ZBsA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=bombadil.20210309 header.b=mCKo0YMQ;
       spf=none (google.com: bombadil.srs.infradead.org does not designate permitted sender hosts) smtp.mailfrom=BATV+1651c3ebed9361b307e7+7090+infradead.org+hch@bombadil.srs.infradead.org
Received: from bombadil.infradead.org (bombadil.infradead.org. [2607:7c80:54:3::133])
        by gmr-mx.google.com with ESMTPS id a2-20020a25ca02000000b007ddb8337f72si557809ybg.1.2023.01.20.23.11.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 20 Jan 2023 23:11:08 -0800 (PST)
Received-SPF: none (google.com: bombadil.srs.infradead.org does not designate permitted sender hosts) client-ip=2607:7c80:54:3::133;
Received: from [2001:4bb8:19a:2039:6754:cc81:9ace:36fc] (helo=localhost)
	by bombadil.infradead.org with esmtpsa (Exim 4.94.2 #2 (Red Hat Linux))
	id 1pJ81o-00DTnU-2G; Sat, 21 Jan 2023 07:11:04 +0000
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
Subject: [PATCH 04/10] mm: move vmalloc_init and free_work down in vmalloc.c
Date: Sat, 21 Jan 2023 08:10:45 +0100
Message-Id: <20230121071051.1143058-5-hch@lst.de>
X-Mailer: git-send-email 2.39.0
In-Reply-To: <20230121071051.1143058-1-hch@lst.de>
References: <20230121071051.1143058-1-hch@lst.de>
MIME-Version: 1.0
X-SRS-Rewrite: SMTP reverse-path rewritten from <hch@infradead.org> by bombadil.infradead.org. See http://www.infradead.org/rpr.html
X-Original-Sender: hch@lst.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=bombadil.20210309 header.b=mCKo0YMQ;
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

Move these two functions around a bit to avoid forward declarations.

Signed-off-by: Christoph Hellwig <hch@lst.de>
Reviewed-by: Uladzislau Rezki (Sony) <urezki@gmail.com>
---
 mm/vmalloc.c | 105 +++++++++++++++++++++++++--------------------------
 1 file changed, 52 insertions(+), 53 deletions(-)

diff --git a/mm/vmalloc.c b/mm/vmalloc.c
index fafb6227f4428f..daeb28b54663d5 100644
--- a/mm/vmalloc.c
+++ b/mm/vmalloc.c
@@ -89,17 +89,6 @@ struct vfree_deferred {
 };
 static DEFINE_PER_CPU(struct vfree_deferred, vfree_deferred);
 
-static void __vunmap(const void *, int);
-
-static void free_work(struct work_struct *w)
-{
-	struct vfree_deferred *p = container_of(w, struct vfree_deferred, wq);
-	struct llist_node *t, *llnode;
-
-	llist_for_each_safe(llnode, t, llist_del_all(&p->list))
-		__vunmap((void *)llnode, 1);
-}
-
 /*** Page table manipulation functions ***/
 static int vmap_pte_range(pmd_t *pmd, unsigned long addr, unsigned long end,
 			phys_addr_t phys_addr, pgprot_t prot,
@@ -2449,48 +2438,6 @@ static void vmap_init_free_space(void)
 	}
 }
 
-void __init vmalloc_init(void)
-{
-	struct vmap_area *va;
-	struct vm_struct *tmp;
-	int i;
-
-	/*
-	 * Create the cache for vmap_area objects.
-	 */
-	vmap_area_cachep = KMEM_CACHE(vmap_area, SLAB_PANIC);
-
-	for_each_possible_cpu(i) {
-		struct vmap_block_queue *vbq;
-		struct vfree_deferred *p;
-
-		vbq = &per_cpu(vmap_block_queue, i);
-		spin_lock_init(&vbq->lock);
-		INIT_LIST_HEAD(&vbq->free);
-		p = &per_cpu(vfree_deferred, i);
-		init_llist_head(&p->list);
-		INIT_WORK(&p->wq, free_work);
-	}
-
-	/* Import existing vmlist entries. */
-	for (tmp = vmlist; tmp; tmp = tmp->next) {
-		va = kmem_cache_zalloc(vmap_area_cachep, GFP_NOWAIT);
-		if (WARN_ON_ONCE(!va))
-			continue;
-
-		va->va_start = (unsigned long)tmp->addr;
-		va->va_end = va->va_start + tmp->size;
-		va->vm = tmp;
-		insert_vmap_area(va, &vmap_area_root, &vmap_area_list);
-	}
-
-	/*
-	 * Now we can initialize a free vmap space.
-	 */
-	vmap_init_free_space();
-	vmap_initialized = true;
-}
-
 static inline void setup_vmalloc_vm_locked(struct vm_struct *vm,
 	struct vmap_area *va, unsigned long flags, const void *caller)
 {
@@ -2769,6 +2716,15 @@ static void __vunmap(const void *addr, int deallocate_pages)
 	kfree(area);
 }
 
+static void delayed_vfree_work(struct work_struct *w)
+{
+	struct vfree_deferred *p = container_of(w, struct vfree_deferred, wq);
+	struct llist_node *t, *llnode;
+
+	llist_for_each_safe(llnode, t, llist_del_all(&p->list))
+		__vunmap((void *)llnode, 1);
+}
+
 /**
  * vfree_atomic - release memory allocated by vmalloc()
  * @addr:	  memory base address
@@ -4315,3 +4271,46 @@ static int __init proc_vmalloc_init(void)
 module_init(proc_vmalloc_init);
 
 #endif
+
+void __init vmalloc_init(void)
+{
+	struct vmap_area *va;
+	struct vm_struct *tmp;
+	int i;
+
+	/*
+	 * Create the cache for vmap_area objects.
+	 */
+	vmap_area_cachep = KMEM_CACHE(vmap_area, SLAB_PANIC);
+
+	for_each_possible_cpu(i) {
+		struct vmap_block_queue *vbq;
+		struct vfree_deferred *p;
+
+		vbq = &per_cpu(vmap_block_queue, i);
+		spin_lock_init(&vbq->lock);
+		INIT_LIST_HEAD(&vbq->free);
+		p = &per_cpu(vfree_deferred, i);
+		init_llist_head(&p->list);
+		INIT_WORK(&p->wq, delayed_vfree_work);
+	}
+
+	/* Import existing vmlist entries. */
+	for (tmp = vmlist; tmp; tmp = tmp->next) {
+		va = kmem_cache_zalloc(vmap_area_cachep, GFP_NOWAIT);
+		if (WARN_ON_ONCE(!va))
+			continue;
+
+		va->va_start = (unsigned long)tmp->addr;
+		va->va_end = va->va_start + tmp->size;
+		va->vm = tmp;
+		insert_vmap_area(va, &vmap_area_root, &vmap_area_list);
+	}
+
+	/*
+	 * Now we can initialize a free vmap space.
+	 */
+	vmap_init_free_space();
+	vmap_initialized = true;
+}
+
-- 
2.39.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230121071051.1143058-5-hch%40lst.de.
