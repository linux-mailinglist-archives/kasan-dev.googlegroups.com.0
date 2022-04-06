Return-Path: <kasan-dev+bncBC7OBJGL2MHBBG5FW2JAMGQE4VJSIWQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13a.google.com (mail-lf1-x13a.google.com [IPv6:2a00:1450:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id 6611F4F5EF0
	for <lists+kasan-dev@lfdr.de>; Wed,  6 Apr 2022 15:16:12 +0200 (CEST)
Received: by mail-lf1-x13a.google.com with SMTP id h11-20020a0565123c8b00b0044b05b775cesf849473lfv.6
        for <lists+kasan-dev@lfdr.de>; Wed, 06 Apr 2022 06:16:12 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1649250972; cv=pass;
        d=google.com; s=arc-20160816;
        b=vogBqTWOh8AUPO5dWk5CudehnAQ4ojuA3k9MWbYw/Gi+4v4mwHFanJT6FStqhqCsuY
         p2ylBpCBRhvTqfgS58xH6wnj2VrGkRtIm4OnmiEfQjoITirVlHm6gzNX4okjieUxRgxs
         ZVE4a/u+/iIyVP76FmF7hAYfJqAUvhSrZFnojIF7AR+ThiVI5GWYr4pG12wCP8i0peov
         ovKaPyxFmC1iGvPFsL3EVyxRXAzodCjQcVtCWJkoqCtv0AMtbm6/x+SBdmwJuqTewKJE
         RB4OaQA6ONar0SU/S/Uloxbe5Hw+d9pUexbbqGrBLPlhdMMI2YgVGnUeHvFXvtPEtT8f
         IcLw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=gIP3znCr2n+SwkFHNS+mEcYIz3zY3qq3N3Bo1ebsMC4=;
        b=vE2dfyviNZwjM//5tpmSss14Tm6cyt1R5EVWXBRqe8XN9NJFXmLggu/ConmYb9VWkG
         hT/xGsTQq9wtODz9C5btEbIWHOt6nHCaWqVfgaM7jitvDjh1J4ZfZXIQKHinwnizUTwu
         5sgDYyjIUqIizrr9rzZ8tKMVDUDgt6qTrTs9A8s9GUPS6Kn9kgbaVudI7HHwvy/HiL2N
         xsleTavgkrc0tWlf6frzSoCalnltlI9mya0brTY6H+ZKl0ZIKO0rFymNIQ2Lu7toHkC1
         uKNgChLAvsnHPk/N8xb6io580kT5NDh6bknRa8GYncMwvbd7e9FE749FVrVEsTkllGqx
         lsYQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=Noky0cu7;
       spf=pass (google.com: domain of 3mjjnygukcq0ry8r4t11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--elver.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3mJJNYgUKCQ0ry8r4t11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=gIP3znCr2n+SwkFHNS+mEcYIz3zY3qq3N3Bo1ebsMC4=;
        b=rPvEC/OG9AW1rrXj9BhyQauuuZMIMHCXSGAn02I2aytWjjpOrkc2xL0KYIgfFUlgPK
         Wa9GfumOoUQucMqpz32oAM/OF2D9WixV5+19ogNOD3PzjJMvTxc8l10Cy9F12CJmjEbk
         Mrk5/QPVqftO/8nIlLV3X3M70KBA9wsg2iprpbuprbamvsioTWFx357f4M9NS3IEmwQM
         loTCfiz0S6gEbBdqcmfEg6BdxflRsjxRiXR6/wu+WYndgrS5I4E9bqBqjQXexgAck3uI
         TS32I4O0SZ+mQMziG4DbgUzsPp1zO6RzJnnixzLnGtcCfqHof+ZtSbfRj2LbT0Vp4NuI
         v6aA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=gIP3znCr2n+SwkFHNS+mEcYIz3zY3qq3N3Bo1ebsMC4=;
        b=wbzpiHyeGNvQfs666CyLAe9AK4u8SrxdQsQTr9RkEEddqiOszrKmCKU7kS2bvkUUYT
         3O9OVDeWAX3Ta5e66OA0fFMfbqJ2xs9zhtCs1oCdf15CKgVpIzato40dM0sEDY2fyMGN
         gTt84C8Q1F3kChcPef33RxviO+wRzX5eXBIY71mmHiL31u4LXpF7Zr6mIZnZaF7FKSGh
         YbGe16DItdrcRbdpjhevcTFiVMvxgrGlUQuV5GQs2iB5kKQ+RfwzYC8nqfDl9pjDrrat
         kV339qaXUwAJAWI+l1IU8woiBXeZ4l/HQelNvCRhJzlTpUfeFcrMGrTNhkdrC+otp6js
         D3xg==
X-Gm-Message-State: AOAM531+1gBxT34C1xyvFfXuo4JB8ecVwvmoK/6bQDuiXfBNF/REkQu6
	vmqrLqdql23QeATyBRDQLuw=
X-Google-Smtp-Source: ABdhPJxKqX/mRq1phRn7iBaONt5DLLCndU0BYXtWASt9XipbOUSwr0flW2gJxem6jdt6c0QS4yvEmw==
X-Received: by 2002:a05:6512:3a8c:b0:44a:adb:3c1b with SMTP id q12-20020a0565123a8c00b0044a0adb3c1bmr6160089lfu.145.1649250971737;
        Wed, 06 Apr 2022 06:16:11 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:211c:b0:24b:4b3:cb8f with SMTP id
 a28-20020a05651c211c00b0024b04b3cb8fls1979078ljq.6.gmail; Wed, 06 Apr 2022
 06:16:08 -0700 (PDT)
X-Received: by 2002:a2e:a54d:0:b0:249:8dd1:9da1 with SMTP id e13-20020a2ea54d000000b002498dd19da1mr5385943ljn.372.1649250968837;
        Wed, 06 Apr 2022 06:16:08 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1649250968; cv=none;
        d=google.com; s=arc-20160816;
        b=g0AuaxjEL9qXRp3nbc5Ya2VLjaldN5htOt6NcRMpFpBaUy2PXsp5vM5PG1N952TWIu
         smb5owmiLTCJ8NKVdj+OewAWDD1nZp7IWnBlxmXY/H/EYSVl1O5eoVylsXwVf1l7S3Kb
         HBVc3hWoSNFxlBhIlA7OmlxPj/aIeMQnbqL+GGyRz1UFWZnxZBdlPX7TLyfcL/rwU7ad
         ZRbJxBvPz/YEFyQ/Q5vcinktPS+4v/YbIlUmhiqBu4EzP5n0n2c7nCe2HTlu3P/ItTxj
         0TGuR27ZQN2trJ2Hti3Xu8pQMH8E2ievOmtBmiY6f0UYP4HOnWM3/qP3ybwO84e3nB85
         QhzA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=EHYoTVl+gP3yMHYun3dql2NLB7u3fhlJOn8FiiSfr2I=;
        b=cjWuJp4P/DnwNGI267kyXLEU4Vww486YwyNNR+2NsWkKmdxkV33TzVJN44ywkzDaJr
         8ck7Qnx1h19BsRWJL8LOAmxDiYSM7WUuKVpV1upVft5qQ2SCL39Z6lVZSZ0AczyfCOEe
         PlmZiI1enRcniUbKhxQPziyZXx/I0pqX20dnQF87A5qxVUqKf0KdTUhROKtntNy+gueG
         ctJDsxNIlfRJ34mfcRMTJhTdfzMdho13qdKuLmM/WJydtUPOWajXXci9a8qo439tHQr2
         hn5j2sFKCRJdR+1xcX1NJbSwk77neIWOp2CkDwfoOVCWxMgsUBz5a4vcMXUpuoYkIVPn
         sztQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=Noky0cu7;
       spf=pass (google.com: domain of 3mjjnygukcq0ry8r4t11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--elver.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3mJJNYgUKCQ0ry8r4t11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ej1-x649.google.com (mail-ej1-x649.google.com. [2a00:1450:4864:20::649])
        by gmr-mx.google.com with ESMTPS id be12-20020a056512250c00b0044ada592076si398351lfb.4.2022.04.06.06.16.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 06 Apr 2022 06:16:08 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3mjjnygukcq0ry8r4t11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--elver.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) client-ip=2a00:1450:4864:20::649;
Received: by mail-ej1-x649.google.com with SMTP id k16-20020a17090632d000b006ae1cdb0f07so1184155ejk.16
        for <kasan-dev@googlegroups.com>; Wed, 06 Apr 2022 06:16:08 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:5d29:f2b6:6b0b:ac46])
 (user=elver job=sendgmr) by 2002:a50:fe0d:0:b0:415:e2ee:65af with SMTP id
 f13-20020a50fe0d000000b00415e2ee65afmr8642207edt.383.1649250968143; Wed, 06
 Apr 2022 06:16:08 -0700 (PDT)
Date: Wed,  6 Apr 2022 15:15:58 +0200
Message-Id: <20220406131558.3558585-1-elver@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.35.1.1094.g7c7d902a7c-goog
Subject: [PATCH] mm, kfence: support kmem_dump_obj() for KFENCE objects
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, Andrew Morton <akpm@linux-foundation.org>
Cc: Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Christoph Lameter <cl@linux.com>, Pekka Enberg <penberg@kernel.org>, David Rientjes <rientjes@google.com>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, Vlastimil Babka <vbabka@suse.cz>, 
	Roman Gushchin <roman.gushchin@linux.dev>, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, 
	kernel test robot <oliver.sang@intel.com>, Hyeonggon Yoo <42.hyeyoo@gmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=Noky0cu7;       spf=pass
 (google.com: domain of 3mjjnygukcq0ry8r4t11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3mJJNYgUKCQ0ry8r4t11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

Calling kmem_obj_info() via kmem_dump_obj() on KFENCE objects has been
producing garbage data due to the object not actually being maintained
by SLAB or SLUB.

Fix this by implementing __kfence_obj_info() that copies relevant
information to struct kmem_obj_info when the object was allocated by
KFENCE; this is called by a common kmem_obj_info(), which also calls the
slab/slub/slob specific variant now called __kmem_obj_info().

For completeness, kmem_dump_obj() now displays if the object was
allocated by KFENCE.

Link: https://lore.kernel.org/all/20220323090520.GG16885@xsang-OptiPlex-9020/
Fixes: b89fb5ef0ce6 ("mm, kfence: insert KFENCE hooks for SLUB")
Fixes: d3fb45f370d9 ("mm, kfence: insert KFENCE hooks for SLAB")
Reported-by: kernel test robot <oliver.sang@intel.com>
Signed-off-by: Marco Elver <elver@google.com>
Reviewed-by: Hyeonggon Yoo <42.hyeyoo@gmail.com>
---
 include/linux/kfence.h | 24 +++++++++++++++++++++
 mm/kfence/core.c       | 21 -------------------
 mm/kfence/kfence.h     | 21 +++++++++++++++++++
 mm/kfence/report.c     | 47 ++++++++++++++++++++++++++++++++++++++++++
 mm/slab.c              |  2 +-
 mm/slab.h              |  2 +-
 mm/slab_common.c       |  9 ++++++++
 mm/slob.c              |  2 +-
 mm/slub.c              |  2 +-
 9 files changed, 105 insertions(+), 25 deletions(-)

diff --git a/include/linux/kfence.h b/include/linux/kfence.h
index f49e64222628..726857a4b680 100644
--- a/include/linux/kfence.h
+++ b/include/linux/kfence.h
@@ -204,6 +204,22 @@ static __always_inline __must_check bool kfence_free(void *addr)
  */
 bool __must_check kfence_handle_page_fault(unsigned long addr, bool is_write, struct pt_regs *regs);
 
+#ifdef CONFIG_PRINTK
+struct kmem_obj_info;
+/**
+ * __kfence_obj_info() - fill kmem_obj_info struct
+ * @kpp: kmem_obj_info to be filled
+ * @object: the object
+ *
+ * Return:
+ * * false - not a KFENCE object
+ * * true - a KFENCE object, filled @kpp
+ *
+ * Copies information to @kpp for KFENCE objects.
+ */
+bool __kfence_obj_info(struct kmem_obj_info *kpp, void *object, struct slab *slab);
+#endif
+
 #else /* CONFIG_KFENCE */
 
 static inline bool is_kfence_address(const void *addr) { return false; }
@@ -221,6 +237,14 @@ static inline bool __must_check kfence_handle_page_fault(unsigned long addr, boo
 	return false;
 }
 
+#ifdef CONFIG_PRINTK
+struct kmem_obj_info;
+static inline bool __kfence_obj_info(struct kmem_obj_info *kpp, void *object, struct slab *slab)
+{
+	return false;
+}
+#endif
+
 #endif
 
 #endif /* _LINUX_KFENCE_H */
diff --git a/mm/kfence/core.c b/mm/kfence/core.c
index a203747ad2c0..9b2b5f56f4ae 100644
--- a/mm/kfence/core.c
+++ b/mm/kfence/core.c
@@ -231,27 +231,6 @@ static bool kfence_unprotect(unsigned long addr)
 	return !KFENCE_WARN_ON(!kfence_protect_page(ALIGN_DOWN(addr, PAGE_SIZE), false));
 }
 
-static inline struct kfence_metadata *addr_to_metadata(unsigned long addr)
-{
-	long index;
-
-	/* The checks do not affect performance; only called from slow-paths. */
-
-	if (!is_kfence_address((void *)addr))
-		return NULL;
-
-	/*
-	 * May be an invalid index if called with an address at the edge of
-	 * __kfence_pool, in which case we would report an "invalid access"
-	 * error.
-	 */
-	index = (addr - (unsigned long)__kfence_pool) / (PAGE_SIZE * 2) - 1;
-	if (index < 0 || index >= CONFIG_KFENCE_NUM_OBJECTS)
-		return NULL;
-
-	return &kfence_metadata[index];
-}
-
 static inline unsigned long metadata_to_pageaddr(const struct kfence_metadata *meta)
 {
 	unsigned long offset = (meta - kfence_metadata + 1) * PAGE_SIZE * 2;
diff --git a/mm/kfence/kfence.h b/mm/kfence/kfence.h
index 9a6c4b1b12a8..600f2e2431d6 100644
--- a/mm/kfence/kfence.h
+++ b/mm/kfence/kfence.h
@@ -96,6 +96,27 @@ struct kfence_metadata {
 
 extern struct kfence_metadata kfence_metadata[CONFIG_KFENCE_NUM_OBJECTS];
 
+static inline struct kfence_metadata *addr_to_metadata(unsigned long addr)
+{
+	long index;
+
+	/* The checks do not affect performance; only called from slow-paths. */
+
+	if (!is_kfence_address((void *)addr))
+		return NULL;
+
+	/*
+	 * May be an invalid index if called with an address at the edge of
+	 * __kfence_pool, in which case we would report an "invalid access"
+	 * error.
+	 */
+	index = (addr - (unsigned long)__kfence_pool) / (PAGE_SIZE * 2) - 1;
+	if (index < 0 || index >= CONFIG_KFENCE_NUM_OBJECTS)
+		return NULL;
+
+	return &kfence_metadata[index];
+}
+
 /* KFENCE error types for report generation. */
 enum kfence_error_type {
 	KFENCE_ERROR_OOB,		/* Detected a out-of-bounds access. */
diff --git a/mm/kfence/report.c b/mm/kfence/report.c
index f93a7b2a338b..f5a6d8ba3e21 100644
--- a/mm/kfence/report.c
+++ b/mm/kfence/report.c
@@ -273,3 +273,50 @@ void kfence_report_error(unsigned long address, bool is_write, struct pt_regs *r
 	/* We encountered a memory safety error, taint the kernel! */
 	add_taint(TAINT_BAD_PAGE, LOCKDEP_STILL_OK);
 }
+
+#ifdef CONFIG_PRINTK
+static void kfence_to_kp_stack(const struct kfence_track *track, void **kp_stack)
+{
+	int i, j;
+
+	i = get_stack_skipnr(track->stack_entries, track->num_stack_entries, NULL);
+	for (j = 0; i < track->num_stack_entries && j < KS_ADDRS_COUNT; ++i, ++j)
+		kp_stack[j] = (void *)track->stack_entries[i];
+	if (j < KS_ADDRS_COUNT)
+		kp_stack[j] = NULL;
+}
+
+bool __kfence_obj_info(struct kmem_obj_info *kpp, void *object, struct slab *slab)
+{
+	struct kfence_metadata *meta = addr_to_metadata((unsigned long)object);
+	unsigned long flags;
+
+	if (!meta)
+		return false;
+
+	/*
+	 * If state is UNUSED at least show the pointer requested; the rest
+	 * would be garbage data.
+	 */
+	kpp->kp_ptr = object;
+
+	/* Requesting info an a never-used object is almost certainly a bug. */
+	if (WARN_ON(meta->state == KFENCE_OBJECT_UNUSED))
+		return true;
+
+	raw_spin_lock_irqsave(&meta->lock, flags);
+
+	kpp->kp_slab = slab;
+	kpp->kp_slab_cache = meta->cache;
+	kpp->kp_objp = (void *)meta->addr;
+	kfence_to_kp_stack(&meta->alloc_track, kpp->kp_stack);
+	if (meta->state == KFENCE_OBJECT_FREED)
+		kfence_to_kp_stack(&meta->free_track, kpp->kp_free_stack);
+	/* get_stack_skipnr() ensures the first entry is outside allocator. */
+	kpp->kp_ret = kpp->kp_stack[0];
+
+	raw_spin_unlock_irqrestore(&meta->lock, flags);
+
+	return true;
+}
+#endif
diff --git a/mm/slab.c b/mm/slab.c
index b04e40078bdf..0edb474edef1 100644
--- a/mm/slab.c
+++ b/mm/slab.c
@@ -3665,7 +3665,7 @@ EXPORT_SYMBOL(__kmalloc_node_track_caller);
 #endif /* CONFIG_NUMA */
 
 #ifdef CONFIG_PRINTK
-void kmem_obj_info(struct kmem_obj_info *kpp, void *object, struct slab *slab)
+void __kmem_obj_info(struct kmem_obj_info *kpp, void *object, struct slab *slab)
 {
 	struct kmem_cache *cachep;
 	unsigned int objnr;
diff --git a/mm/slab.h b/mm/slab.h
index fd7ae2024897..95eb34174c1b 100644
--- a/mm/slab.h
+++ b/mm/slab.h
@@ -868,7 +868,7 @@ struct kmem_obj_info {
 	void *kp_stack[KS_ADDRS_COUNT];
 	void *kp_free_stack[KS_ADDRS_COUNT];
 };
-void kmem_obj_info(struct kmem_obj_info *kpp, void *object, struct slab *slab);
+void __kmem_obj_info(struct kmem_obj_info *kpp, void *object, struct slab *slab);
 #endif
 
 #ifdef CONFIG_HAVE_HARDENED_USERCOPY_ALLOCATOR
diff --git a/mm/slab_common.c b/mm/slab_common.c
index 6ee64d6208b3..2b3206a2c3b5 100644
--- a/mm/slab_common.c
+++ b/mm/slab_common.c
@@ -555,6 +555,13 @@ bool kmem_valid_obj(void *object)
 }
 EXPORT_SYMBOL_GPL(kmem_valid_obj);
 
+static void kmem_obj_info(struct kmem_obj_info *kpp, void *object, struct slab *slab)
+{
+	if (__kfence_obj_info(kpp, object, slab))
+		return;
+	__kmem_obj_info(kpp, object, slab);
+}
+
 /**
  * kmem_dump_obj - Print available slab provenance information
  * @object: slab object for which to find provenance information.
@@ -590,6 +597,8 @@ void kmem_dump_obj(void *object)
 		pr_cont(" slab%s %s", cp, kp.kp_slab_cache->name);
 	else
 		pr_cont(" slab%s", cp);
+	if (is_kfence_address(object))
+		pr_cont(" (kfence)");
 	if (kp.kp_objp)
 		pr_cont(" start %px", kp.kp_objp);
 	if (kp.kp_data_offset)
diff --git a/mm/slob.c b/mm/slob.c
index dfa6808dff36..40ea6e2d4ccd 100644
--- a/mm/slob.c
+++ b/mm/slob.c
@@ -463,7 +463,7 @@ static void slob_free(void *block, int size)
 }
 
 #ifdef CONFIG_PRINTK
-void kmem_obj_info(struct kmem_obj_info *kpp, void *object, struct slab *slab)
+void __kmem_obj_info(struct kmem_obj_info *kpp, void *object, struct slab *slab)
 {
 	kpp->kp_ptr = object;
 	kpp->kp_slab = slab;
diff --git a/mm/slub.c b/mm/slub.c
index 74d92aa4a3a2..ed5c2c03a47a 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -4312,7 +4312,7 @@ int __kmem_cache_shutdown(struct kmem_cache *s)
 }
 
 #ifdef CONFIG_PRINTK
-void kmem_obj_info(struct kmem_obj_info *kpp, void *object, struct slab *slab)
+void __kmem_obj_info(struct kmem_obj_info *kpp, void *object, struct slab *slab)
 {
 	void *base;
 	int __maybe_unused i;
-- 
2.35.1.1094.g7c7d902a7c-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220406131558.3558585-1-elver%40google.com.
