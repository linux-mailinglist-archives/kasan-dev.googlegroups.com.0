Return-Path: <kasan-dev+bncBDWLZXP6ZEPRB2PQZOGAMGQEUDJUVIQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43e.google.com (mail-wr1-x43e.google.com [IPv6:2a00:1450:4864:20::43e])
	by mail.lfdr.de (Postfix) with ESMTPS id 64491451C87
	for <lists+kasan-dev@lfdr.de>; Tue, 16 Nov 2021 01:16:42 +0100 (CET)
Received: by mail-wr1-x43e.google.com with SMTP id q17-20020adff791000000b00183e734ba48sf4103790wrp.8
        for <lists+kasan-dev@lfdr.de>; Mon, 15 Nov 2021 16:16:42 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1637021802; cv=pass;
        d=google.com; s=arc-20160816;
        b=jRy+wISFLWx+j06kfpNrIuf8PsZqW2ljI2bL4sMchaoN0kJiaF7uRazQo33Hd4ns3E
         MwDiqegW6b0W09Nn13OlLxEqWuthRmJmpeB9Il9v41ymvD+nAWkd0sSA80UHgQYq7+FF
         BugP1jkt4p/h22mEhSRTnC+UXvnxS8cWAvBlj+mC4+7NUW0isZasy2udDYM0rxjSmEYF
         VuZIDqibiS0cYcOpf1eq9yE280E8MAPiRD3ZN258MJq8SNIA+A7B/2kXkU1Wm1IA9nYs
         OrNzjQtrcrxMCTsKzzbrtFHOaXFbmPGGGbUBKLO/bROKPIm+4UxfW6SpBJMp0J2JVbeA
         KdbA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=ZnEKNh575ZBYfCxSIal8uYmxO1YSYu80yj41XbogbVU=;
        b=ze/ss7CwakCZA8pHUeAQlbxzv8d9q2gFue7UxaJ9SR8GZNxjWSRcjJLRltYCNcazxh
         siwXouIZBOpjPjZTP1rx5ea3aZWzj/Emm4bqexpOL/x+0hPSdp15A9n5iCk4qAlUORrs
         U7xS82IUxZdLLoFIVBRLTzdqhPDO5aj/AAGK2pTPd8SwNvkPnazutEUpUiZA2KDhuC7Y
         7Wa1GpN40vEgorXyrrfhDV1ZuR2RpAOxiL25y+As7Sogtc6JtA8v7v2Et0TA5wg4Z4uK
         Ay0wrWNd8+q0quddWMsTh2X3VYKeTw+iWMyJZoA9mj+Jx2WzcdkWYYbHa9GLAuEl4r9+
         EMIg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=Lr1Ty2VG;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=vUc5IZ1J;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.28 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ZnEKNh575ZBYfCxSIal8uYmxO1YSYu80yj41XbogbVU=;
        b=goGP8wqHnXikI1t527afUPISya4tt5i6kcyusJ6/5oNZTTrv0h4sI0kINZZWDUlHnr
         TWJWtLmPUA09bB2cJwrqh79xdwcS0jJnMp9I5G32/sRX/qfrNRsA/Menf31KBcTUYcmU
         AHHbgC2SnZSBuj7++0/wi5dshWjspyulWAgGc9xb12MpE8MeMjP/7hjbzNLpds0ibI7F
         m7340ALsa9YcTfRb0CGrTtGQmQBXgPbkueNOQS4G6tE9KckDg62HRKscskPk50OUUQ95
         VUxyklNXrX+rwV8KLaqJ8rB3xevFibn+rX1NIgG52PvEHsIhKR7MxZTUEjOvD3ZZFOFC
         GqhA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ZnEKNh575ZBYfCxSIal8uYmxO1YSYu80yj41XbogbVU=;
        b=VEeBikW3e7SMeLw6eFW3lXp5fQAu4E4kNO/Acvt/yN9bVtKh+mZl8ipQ+sjJpL7tHC
         eXgQ1Yi5bLvUc72m8b2321h4P9x3xh7+MBXqnXDFguzvOtqm8QHNjEGu2nSahUyvdD1t
         tGnCvA14OS+U/8cApF+zVRnZRnexu5/JQxQTMiikzTfol3qYIyCS5v07kemn9vewAV3j
         2Apu9Bde+pO9WkwVCHTJOgevPs6QPSI3E1h7qrG6MdSdXybMsJzlyOUVfk1H8vbySiCb
         THdIky0gWBd9MtMz2pdX2Ebjs7KRh7fA92UvtwqPq18g+jyagCaMQ2zCVlK9VqAlGiI5
         wc7Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533B58MCeZG1ynCqdpxCbZ6g4FKt15vyf8JTtCdHaZvWgEPDY6t2
	vPSwOM0VzZLlsTAewiSYMMs=
X-Google-Smtp-Source: ABdhPJxDu2H+0pD+W7XaTteke+TxpPZi13+ck3p/35AvWPH8FzkuRlnXTwQHBAmaYvbUBPRYx4VbQg==
X-Received: by 2002:a1c:7e04:: with SMTP id z4mr52269460wmc.134.1637021802117;
        Mon, 15 Nov 2021 16:16:42 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:fe0b:: with SMTP id n11ls12454977wrr.0.gmail; Mon, 15
 Nov 2021 16:16:41 -0800 (PST)
X-Received: by 2002:adf:df0d:: with SMTP id y13mr4043793wrl.176.1637021801208;
        Mon, 15 Nov 2021 16:16:41 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1637021801; cv=none;
        d=google.com; s=arc-20160816;
        b=G/iX3AIrJlfqCVuWOfs3ZwC9DhNrDWwFjKSjEAUp10zip2fbUqpxOUc+CpLMuDE8DB
         WYOWv76lxSLWHRNLHgsrUimIZKSblzeSu1gloRG366iBtbrE+iLh2q+60mM4TL2LlpRQ
         lazc24OeYGWSo91nh2b2iWnWO1my6j/qabIfqPZ4bCFcGPRslgsvGju+FRU9fxBWnhed
         Mdp++cfz8awLKm57b4HWD9LcCzHyet+S24E4SbFnMcCHT9foYLm7hsM+pf7t7xBy2N6+
         snUumTaxNzOE8TdO+O9WQyk6PZ9QcZhYjH6u8XN0oeMiAAyc8gkJyLKpGkQra494iytO
         1Gbw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature:dkim-signature;
        bh=oKgYHhJrS0qYL3+eEFgT/EDodvY21YYFEwQrY2CX1eQ=;
        b=ZlCCDRlOjw1zTsbDn5cVKcskhtyLwaa23hEzFexoiqQ2Y4TNZmY1zaRwamlc4hJ39K
         AVS8CtgduZmeDtVTY05qNw+q7O98NrmpoWvra9fRuVudl2CDs21fGdgLzu7ibO+SH/wy
         MMPebo2bV+jvFAJYa+i3UzjEifwMrqSdfhkV0agib4Iv310RFxOPuFtCbE/lrDvvWOko
         kAHTcu2cugPVI0jolXTc0Cttqudre29y3XjvTwYUPWeSWThxNWk8mmrkHdRZDbsAoyaU
         Nub90T1M8tBnBlaepx2vori+2Wtu9FIJ2VykTf46uDdeZoqPttjLdSscvkTgEBKJQx2E
         5wuA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=Lr1Ty2VG;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=vUc5IZ1J;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.28 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [195.135.220.28])
        by gmr-mx.google.com with ESMTPS id 201si70326wma.1.2021.11.15.16.16.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 15 Nov 2021 16:16:41 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.220.28 as permitted sender) client-ip=195.135.220.28;
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id 01D1D21983;
	Tue, 16 Nov 2021 00:16:41 +0000 (UTC)
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by imap2.suse-dmz.suse.de (Postfix) with ESMTPS id BF20713F72;
	Tue, 16 Nov 2021 00:16:40 +0000 (UTC)
Received: from dovecot-director2.suse.de ([192.168.254.65])
	by imap2.suse-dmz.suse.de with ESMTPSA
	id SJe2LWj4kmFjXAAAMHmgww
	(envelope-from <vbabka@suse.cz>); Tue, 16 Nov 2021 00:16:40 +0000
From: Vlastimil Babka <vbabka@suse.cz>
To: Matthew Wilcox <willy@infradead.org>,
	linux-mm@kvack.org,
	Christoph Lameter <cl@linux.com>,
	David Rientjes <rientjes@google.com>,
	Joonsoo Kim <iamjoonsoo.kim@lge.com>,
	Pekka Enberg <penberg@kernel.org>
Cc: Vlastimil Babka <vbabka@suse.cz>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	kasan-dev@googlegroups.com
Subject: [RFC PATCH 24/32] mm/kasan: Convert to struct slab
Date: Tue, 16 Nov 2021 01:16:20 +0100
Message-Id: <20211116001628.24216-25-vbabka@suse.cz>
X-Mailer: git-send-email 2.33.1
In-Reply-To: <20211116001628.24216-1-vbabka@suse.cz>
References: <20211116001628.24216-1-vbabka@suse.cz>
MIME-Version: 1.0
X-Developer-Signature: v=1; a=openpgp-sha256; l=9387; i=vbabka@suse.cz; h=from:subject; bh=a5ZRfoEeg9Mn0RPqjl/VZ4MQ3wxOdC+BZraGOPr01us=; b=owEBbQGS/pANAwAIAeAhynPxiakQAcsmYgBhkvhM5SC2HiNVv0EofhvfS3qDDSwabNdyq3Y2Z/AK jWnOaWmJATMEAAEIAB0WIQSNS5MBqTXjGL5IXszgIcpz8YmpEAUCYZL4TAAKCRDgIcpz8YmpEMNxCA C1+/YABDkNwaGGpwdq1804bPQeSBCdDmhVvXi7biuZ7pPuyTwOtq7faN4B7a7MNwMrF77cOg4mm/T4 77VDJZ0+8vi5x6XVrYui2ycUP0dRz+2256KPzHnFV3u0J6ua+enh9Nc4gEkfp997fEhBf+LytEfP4Z ugIikDpPq3qUYgqICfipL0kQ0k274cjleJ8MjaVvFZZfaqnCuN37I1bUxfjiQglZ7bxr5rUwwsJsen AXl+7PKhXlyHtBWFEq5oaLc7P6KbdyuDtTtWI58qEHPcHjyFiWC/erShq047A2nSWOVBxpVVl2LAay jdTHRpAJcC7gN5Gs310ZKftToWSQm6
X-Developer-Key: i=vbabka@suse.cz; a=openpgp; fpr=A940D434992C2E8E99103D50224FA7E7CC82A664
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=Lr1Ty2VG;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=vUc5IZ1J;
       spf=pass (google.com: domain of vbabka@suse.cz designates
 195.135.220.28 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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

From: "Matthew Wilcox (Oracle)" <willy@infradead.org>

KASAN accesses some slab related struct page fields so we need to convert it
to struct slab. Some places are a bit simplified thanks to kasan_addr_to_slab()
encapsulating the PageSlab flag check through virt_to_slab().

[ vbabka@suse.cz: adjust to differences in previous patches ]

Signed-off-by: Matthew Wilcox (Oracle) <willy@infradead.org>
Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>
Cc: Alexander Potapenko <glider@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>
Cc: Dmitry Vyukov <dvyukov@google.com>
Cc: <kasan-dev@googlegroups.com>
---
 include/linux/kasan.h  |  9 +++++----
 mm/kasan/common.c      | 21 +++++++++++----------
 mm/kasan/generic.c     |  8 ++++----
 mm/kasan/kasan.h       |  1 +
 mm/kasan/quarantine.c  |  2 +-
 mm/kasan/report.c      | 12 ++++++++++--
 mm/kasan/report_tags.c | 10 +++++-----
 mm/slab.c              |  2 +-
 mm/slub.c              |  2 +-
 9 files changed, 39 insertions(+), 28 deletions(-)

diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index d8783b682669..fb78108d694e 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -9,6 +9,7 @@
 
 struct kmem_cache;
 struct page;
+struct slab;
 struct vm_struct;
 struct task_struct;
 
@@ -193,11 +194,11 @@ static __always_inline size_t kasan_metadata_size(struct kmem_cache *cache)
 	return 0;
 }
 
-void __kasan_poison_slab(struct page *page);
-static __always_inline void kasan_poison_slab(struct page *page)
+void __kasan_poison_slab(struct slab *slab);
+static __always_inline void kasan_poison_slab(struct slab *slab)
 {
 	if (kasan_enabled())
-		__kasan_poison_slab(page);
+		__kasan_poison_slab(slab);
 }
 
 void __kasan_unpoison_object_data(struct kmem_cache *cache, void *object);
@@ -322,7 +323,7 @@ static inline void kasan_cache_create(struct kmem_cache *cache,
 				      slab_flags_t *flags) {}
 static inline void kasan_cache_create_kmalloc(struct kmem_cache *cache) {}
 static inline size_t kasan_metadata_size(struct kmem_cache *cache) { return 0; }
-static inline void kasan_poison_slab(struct page *page) {}
+static inline void kasan_poison_slab(struct slab *slab) {}
 static inline void kasan_unpoison_object_data(struct kmem_cache *cache,
 					void *object) {}
 static inline void kasan_poison_object_data(struct kmem_cache *cache,
diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index 6a1cd2d38bff..f0091112a381 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -247,8 +247,9 @@ struct kasan_free_meta *kasan_get_free_meta(struct kmem_cache *cache,
 }
 #endif
 
-void __kasan_poison_slab(struct page *page)
+void __kasan_poison_slab(struct slab *slab)
 {
+	struct page *page = slab_page(slab);
 	unsigned long i;
 
 	for (i = 0; i < compound_nr(page); i++)
@@ -401,9 +402,9 @@ void __kasan_kfree_large(void *ptr, unsigned long ip)
 
 void __kasan_slab_free_mempool(void *ptr, unsigned long ip)
 {
-	struct page *page;
+	struct folio *folio;
 
-	page = virt_to_head_page(ptr);
+	folio = page_folio(virt_to_page(ptr));
 
 	/*
 	 * Even though this function is only called for kmem_cache_alloc and
@@ -411,12 +412,12 @@ void __kasan_slab_free_mempool(void *ptr, unsigned long ip)
 	 * !PageSlab() when the size provided to kmalloc is larger than
 	 * KMALLOC_MAX_SIZE, and kmalloc falls back onto page_alloc.
 	 */
-	if (unlikely(!PageSlab(page))) {
+	if (unlikely(!folio_test_slab(folio))) {
 		if (____kasan_kfree_large(ptr, ip))
 			return;
-		kasan_poison(ptr, page_size(page), KASAN_FREE_PAGE, false);
+		kasan_poison(ptr, folio_size(folio), KASAN_FREE_PAGE, false);
 	} else {
-		____kasan_slab_free(page->slab_cache, ptr, ip, false, false);
+		____kasan_slab_free(folio_slab(folio)->slab_cache, ptr, ip, false, false);
 	}
 }
 
@@ -560,7 +561,7 @@ void * __must_check __kasan_kmalloc_large(const void *ptr, size_t size,
 
 void * __must_check __kasan_krealloc(const void *object, size_t size, gfp_t flags)
 {
-	struct page *page;
+	struct slab *slab;
 
 	if (unlikely(object == ZERO_SIZE_PTR))
 		return (void *)object;
@@ -572,13 +573,13 @@ void * __must_check __kasan_krealloc(const void *object, size_t size, gfp_t flag
 	 */
 	kasan_unpoison(object, size, false);
 
-	page = virt_to_head_page(object);
+	slab = virt_to_slab(object);
 
 	/* Piggy-back on kmalloc() instrumentation to poison the redzone. */
-	if (unlikely(!PageSlab(page)))
+	if (unlikely(!slab))
 		return __kasan_kmalloc_large(object, size, flags);
 	else
-		return ____kasan_kmalloc(page->slab_cache, object, size, flags);
+		return ____kasan_kmalloc(slab->slab_cache, object, size, flags);
 }
 
 bool __kasan_check_byte(const void *address, unsigned long ip)
diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
index 5d0b79416c4e..a25ad4090615 100644
--- a/mm/kasan/generic.c
+++ b/mm/kasan/generic.c
@@ -330,16 +330,16 @@ DEFINE_ASAN_SET_SHADOW(f8);
 
 static void __kasan_record_aux_stack(void *addr, bool can_alloc)
 {
-	struct page *page = kasan_addr_to_page(addr);
+	struct slab *slab = kasan_addr_to_slab(addr);
 	struct kmem_cache *cache;
 	struct kasan_alloc_meta *alloc_meta;
 	void *object;
 
-	if (is_kfence_address(addr) || !(page && PageSlab(page)))
+	if (is_kfence_address(addr) || !slab)
 		return;
 
-	cache = page->slab_cache;
-	object = nearest_obj(cache, page_slab(page), addr);
+	cache = slab->slab_cache;
+	object = nearest_obj(cache, slab, addr);
 	alloc_meta = kasan_get_alloc_meta(cache, object);
 	if (!alloc_meta)
 		return;
diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index aebd8df86a1f..c17fa8d26ffe 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -265,6 +265,7 @@ bool kasan_report(unsigned long addr, size_t size,
 void kasan_report_invalid_free(void *object, unsigned long ip);
 
 struct page *kasan_addr_to_page(const void *addr);
+struct slab *kasan_addr_to_slab(const void *addr);
 
 depot_stack_handle_t kasan_save_stack(gfp_t flags, bool can_alloc);
 void kasan_set_track(struct kasan_track *track, gfp_t flags);
diff --git a/mm/kasan/quarantine.c b/mm/kasan/quarantine.c
index d8ccff4c1275..587da8995f2d 100644
--- a/mm/kasan/quarantine.c
+++ b/mm/kasan/quarantine.c
@@ -117,7 +117,7 @@ static unsigned long quarantine_batch_size;
 
 static struct kmem_cache *qlink_to_cache(struct qlist_node *qlink)
 {
-	return virt_to_head_page(qlink)->slab_cache;
+	return virt_to_slab(qlink)->slab_cache;
 }
 
 static void *qlink_to_object(struct qlist_node *qlink, struct kmem_cache *cache)
diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index e00999dc6499..7df696c0422c 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -149,6 +149,13 @@ struct page *kasan_addr_to_page(const void *addr)
 		return virt_to_head_page(addr);
 	return NULL;
 }
+struct slab *kasan_addr_to_slab(const void *addr)
+{
+	if ((addr >= (void *)PAGE_OFFSET) &&
+			(addr < high_memory))
+		return virt_to_slab(addr);
+	return NULL;
+}
 
 static void describe_object_addr(struct kmem_cache *cache, void *object,
 				const void *addr)
@@ -248,8 +255,9 @@ static void print_address_description(void *addr, u8 tag)
 	pr_err("\n");
 
 	if (page && PageSlab(page)) {
-		struct kmem_cache *cache = page->slab_cache;
-		void *object = nearest_obj(cache, page_slab(page),	addr);
+		struct slab *slab = page_slab(page);
+		struct kmem_cache *cache = slab->slab_cache;
+		void *object = nearest_obj(cache, slab,	addr);
 
 		describe_object(cache, object, addr, tag);
 	}
diff --git a/mm/kasan/report_tags.c b/mm/kasan/report_tags.c
index 06c21dd77493..1b41de88c53e 100644
--- a/mm/kasan/report_tags.c
+++ b/mm/kasan/report_tags.c
@@ -12,7 +12,7 @@ const char *kasan_get_bug_type(struct kasan_access_info *info)
 #ifdef CONFIG_KASAN_TAGS_IDENTIFY
 	struct kasan_alloc_meta *alloc_meta;
 	struct kmem_cache *cache;
-	struct page *page;
+	struct slab *slab;
 	const void *addr;
 	void *object;
 	u8 tag;
@@ -20,10 +20,10 @@ const char *kasan_get_bug_type(struct kasan_access_info *info)
 
 	tag = get_tag(info->access_addr);
 	addr = kasan_reset_tag(info->access_addr);
-	page = kasan_addr_to_page(addr);
-	if (page && PageSlab(page)) {
-		cache = page->slab_cache;
-		object = nearest_obj(cache, page_slab(page), (void *)addr);
+	slab = kasan_addr_to_slab(addr);
+	if (slab) {
+		cache = slab->slab_cache;
+		object = nearest_obj(cache, slab, (void *)addr);
 		alloc_meta = kasan_get_alloc_meta(cache, object);
 
 		if (alloc_meta) {
diff --git a/mm/slab.c b/mm/slab.c
index adf688d2da64..5aa601c5756a 100644
--- a/mm/slab.c
+++ b/mm/slab.c
@@ -2605,7 +2605,7 @@ static struct slab *cache_grow_begin(struct kmem_cache *cachep,
 	 * page_address() in the latter returns a non-tagged pointer,
 	 * as it should be for slab pages.
 	 */
-	kasan_poison_slab(slab_page(slab));
+	kasan_poison_slab(slab);
 
 	/* Get slab management. */
 	freelist = alloc_slabmgmt(cachep, slab, offset,
diff --git a/mm/slub.c b/mm/slub.c
index 981e40a88bab..1ff3fa2ab528 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -1961,7 +1961,7 @@ static struct slab *allocate_slab(struct kmem_cache *s, gfp_t flags, int node)
 
 	slab->slab_cache = s;
 
-	kasan_poison_slab(slab_page(slab));
+	kasan_poison_slab(slab);
 
 	start = slab_address(slab);
 
-- 
2.33.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211116001628.24216-25-vbabka%40suse.cz.
