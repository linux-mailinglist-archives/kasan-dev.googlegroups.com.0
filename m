Return-Path: <kasan-dev+bncBDWLZXP6ZEPRBE5BZ2HAMGQEW6V77UY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23f.google.com (mail-lj1-x23f.google.com [IPv6:2a00:1450:4864:20::23f])
	by mail.lfdr.de (Postfix) with ESMTPS id 2092C483968
	for <lists+kasan-dev@lfdr.de>; Tue,  4 Jan 2022 01:11:00 +0100 (CET)
Received: by mail-lj1-x23f.google.com with SMTP id a13-20020a05651c210d00b0022e1dc44d53sf3522262ljq.17
        for <lists+kasan-dev@lfdr.de>; Mon, 03 Jan 2022 16:11:00 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1641255059; cv=pass;
        d=google.com; s=arc-20160816;
        b=jSqQ04CwaJ4qyMoOdnpdEZ4FGn2EWTWHi4edlIeggXrDIBQIxn5AsAu/m9CfoqjqNF
         gcFl2+h5Op1fDzHdDPLQBylna2WIPmjCnC3uLQjVGYLvH3D1ybL6QPJ6/B2A502c/tr6
         cfDbYrDaHSsHVQpukT/46E+4/DpaCsmHJ0MfjZayjXFowKojnSfscOdVpP/sY7XKdkPb
         ZHMozCZp1bU/awqBqLt0ydUBLCUARKrazk8AssJ1ToVFv0Ws0aqXQBj51mT/vsQjkEDl
         mnp15hyOepNydMTzMbmYRb4ro8XhWFCiNGX2pwlbGfYIhm3OrPor/LVDkWq7pRrV7oXR
         PiLA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=15LgvSLAZe5MEItVMPbftG36w6RvGrrsuadAQ9HMWQ0=;
        b=Lelzto+1M2wpPVILeD36hClKiS704dMy6b7mfK0x2fTdA8nI0jsoDLPncoM3MoZIFz
         o2PP0zRhOnraxzmNEw7SvHLwqkgBE6AdtD2JAe1OM8G1n02eb5q8++h0K5WZoAL+8OLW
         cmTdkoOO8N8++UvTP65aT9Wigce2s3BiycP9ZY+9cMugDK9AUm4vuYKm/5TueAXQe5Ep
         tP/MtgwnwiAWXI37ilRtnApZzQtpOFtWBAxk5nx5AYYmTUVPo286oaS5Iy+BtZGTNtyW
         aOS2jdeG5qHTGyUxwyikgHtXOc4mevM0gJO5IWc3VDvi2CKfRGKH4vMDltY988X1QhDO
         14dw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=oCBXUdLS;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.28 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=15LgvSLAZe5MEItVMPbftG36w6RvGrrsuadAQ9HMWQ0=;
        b=ikrY6YBg0SEHWcMyypoJvjOO5kDfZYWHBwFtQjhFrVXz44UjVSuO/CjX64OB3gkXD5
         2o8EfkNaEyJjU1xvUjzDLU3ENTlB4wsFhjvabChzmVc5dVO0qhuaCvlqQIbdT0PkO29D
         QHywK1Ppilve9NjurIGN5cd7//iMScMrEUJIQFiW+dICZ6WIqJWaPo54IWqQLHc5iPeZ
         HIkq7B/+f3YcMqvjw4jKNY4KAHgQtzOO5LYC6xyqqy5ziJw3JV+ppEO68nAJyAqsktlM
         mGSIuCXRbXs4AJyHRJflg0+RBqBkglVGZz6898crch32GXsu9eNIrJMGYslUDcTSUKoY
         0fVA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=15LgvSLAZe5MEItVMPbftG36w6RvGrrsuadAQ9HMWQ0=;
        b=s6/p/fRbRCcsrZkh3RH2Lkty5XTptgPxnF3imN/9/iXklxvkzpbRUMi23Slcukm1aK
         NPUqNfrS/oprgVrBKjWolWoQUr5qvRJ3XouVovkq4got1NRfQ8sX7aDWr1zYEUWFJJ7P
         lXlIC18H6YqrISmJQGsxDw0SMn8iZxEoBZeA9J6NCJxpGjP1doIBd5aGpNSxk+Wdysr1
         7WqmUEFDVDhJq9JFK6n31m6CpQMGz8/rfIamdhelUiWEXTQghzkFWaNZNvUUL3ZYuZ3C
         TjEmLtTiSb1cyaDuTtu9+CgmlEJpL5ee8GNnstXeCJORhxpWBbPalYgAMJ5Ufb2hSB4w
         orYg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531TDi4/m5UU2qAKou84HXrwnC1eXjCg0BvcREvcbbGcsIu4Fr8j
	far2pBNfGhNRnsxGdeV3Ric=
X-Google-Smtp-Source: ABdhPJytjEnjHYUE6rzZ5NMs9pZ2umg4sMcc7bF2jJ//LGiD6AUDed/z0GvSeBuqLVFkoAzmKuQzEA==
X-Received: by 2002:a05:6512:33c2:: with SMTP id d2mr41161073lfg.149.1641255059589;
        Mon, 03 Jan 2022 16:10:59 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:a7c4:: with SMTP id x4ls2229717ljp.3.gmail; Mon, 03 Jan
 2022 16:10:58 -0800 (PST)
X-Received: by 2002:a05:651c:2106:: with SMTP id a6mr31939733ljq.285.1641255058524;
        Mon, 03 Jan 2022 16:10:58 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1641255058; cv=none;
        d=google.com; s=arc-20160816;
        b=UN3L+BtxzSO+BJNdWTPUxLaP7a6NUUGeaJerzCCckyEW5D8pdaLLWpLgyVMoFIgEg+
         h1ZPlhrfUeDklJPCHJWhdhM2yPK0tHOgyH9ute61/+3HXbC/lTEEDSCYg1n4Zpt7suwT
         5KxeR5tpfA/fbUfC8g99LpVxsykBDVSLyCj40/oLTL345KCJB8PhC+dkYMLasc62CTcc
         YjAtufyZvXdyUVOHYKWEoq/oxEnqzAYrVCoTecSZ5B0oUsz5PJbBMckwiIG54uzHJIbc
         3Jj+rCND3yI+VSZYGWd8a3qL0NwsZORcc4JDoYqPE8HHmoc84CP+Tov7Js38mc42ISjH
         eAcg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature:dkim-signature;
        bh=mkiaYIAV+e1pNFN68hb42AyH/4TaudTug3/IeXmDCtk=;
        b=OqeR6yX+JeK51XK5aJlgyai3t/ByUttD0Vb2KDRrsuwBCYbYcIs6z9/StfkwkHpWAS
         KUqrtfJKAM1O0gFNwOBGmgqUQ6STfLGeizJcmsg4QTDxCCI05gKIm+InkvMLejJ9ZWqe
         v9HcGEYubABsM2yO1KDupeCbPwXG1GxYaux1kVEHVBb9zjItqYv2Ecjb7lPdRrx0w7An
         zmGSxAnQkiUaDeFXTO9hQwHulW6HbI5N6wBWQVdMefrEMwShBzPHhU3gGzcDo78uHzFd
         pZQMIwN/IvCh4bzB/Ygmj1Opht5QEl/l2tTpDO+zy4q/rjz4WHGoxyx1T5MqNtOFjYab
         LN+w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=oCBXUdLS;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.28 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [195.135.220.28])
        by gmr-mx.google.com with ESMTPS id t65si1392725lff.11.2022.01.03.16.10.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 03 Jan 2022 16:10:58 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.220.28 as permitted sender) client-ip=195.135.220.28;
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id E07A2212BF;
	Tue,  4 Jan 2022 00:10:57 +0000 (UTC)
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by imap2.suse-dmz.suse.de (Postfix) with ESMTPS id AB2E4139EE;
	Tue,  4 Jan 2022 00:10:57 +0000 (UTC)
Received: from dovecot-director2.suse.de ([192.168.254.65])
	by imap2.suse-dmz.suse.de with ESMTPSA
	id UDgwKZGQ02FEQwAAMHmgww
	(envelope-from <vbabka@suse.cz>); Tue, 04 Jan 2022 00:10:57 +0000
From: Vlastimil Babka <vbabka@suse.cz>
To: Matthew Wilcox <willy@infradead.org>,
	Christoph Lameter <cl@linux.com>,
	David Rientjes <rientjes@google.com>,
	Joonsoo Kim <iamjoonsoo.kim@lge.com>,
	Pekka Enberg <penberg@kernel.org>
Cc: linux-mm@kvack.org,
	Andrew Morton <akpm@linux-foundation.org>,
	Johannes Weiner <hannes@cmpxchg.org>,
	Roman Gushchin <guro@fb.com>,
	Hyeonggon Yoo <42.hyeyoo@gmail.com>,
	patches@lists.linux.dev,
	Vlastimil Babka <vbabka@suse.cz>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	kasan-dev@googlegroups.com
Subject: [PATCH v4 25/32] mm/kasan: Convert to struct folio and struct slab
Date: Tue,  4 Jan 2022 01:10:39 +0100
Message-Id: <20220104001046.12263-26-vbabka@suse.cz>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <20220104001046.12263-1-vbabka@suse.cz>
References: <20220104001046.12263-1-vbabka@suse.cz>
MIME-Version: 1.0
X-Developer-Signature: v=1; a=openpgp-sha256; l=9697; i=vbabka@suse.cz; h=from:subject; bh=ozZ8KOt5BHbAfr/2UNvOj+vZjSf6IOzowUCmBHCM+N0=; b=owEBbQGS/pANAwAIAeAhynPxiakQAcsmYgBh05B/g9KuznWEfE9jFnl54hBrK4dBpe9Og6ihP1hp i2c5B6eJATMEAAEIAB0WIQSNS5MBqTXjGL5IXszgIcpz8YmpEAUCYdOQfwAKCRDgIcpz8YmpEOCUB/ sHwUMxzjusCsajk2cNWP3jr6DaZAKU/1QqsIOmqrV0RXXvBpCbYlPp5gaadble4a7SRhOc3uBOny9n BHCXTJbz3EwYocZIIpvM3l4+KSVnuzynIhP4QGS7sH1VXWx3jXxIoMhOPRwpajrn2elGkbmnAcslqT 65gPGy49yR87LfgSRMXniRMVcfCNwBsuwSV4D70DFt/l74SamFUNg4nbL/FabyqcUxmvY4TA+80i3D TFQ336gFi/UzCggtUMrhZ8u9bLjcikVlVg/gID8L1w5vZV9pt9/u2Jb+j2W8qwrPPX1IfIk3QusNWF zoZysZr+O91kIUT1cQ3NlsShF4ilw7
X-Developer-Key: i=vbabka@suse.cz; a=openpgp; fpr=A940D434992C2E8E99103D50224FA7E7CC82A664
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=oCBXUdLS;       dkim=neutral
 (no key) header.i=@suse.cz;       spf=pass (google.com: domain of
 vbabka@suse.cz designates 195.135.220.28 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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

KASAN accesses some slab related struct page fields so we need to
convert it to struct slab. Some places are a bit simplified thanks to
kasan_addr_to_slab() encapsulating the PageSlab flag check through
virt_to_slab().  When resolving object address to either a real slab or
a large kmalloc, use struct folio as the intermediate type for testing
the slab flag to avoid unnecessary implicit compound_head().

[ vbabka@suse.cz: use struct folio, adjust to differences in previous
  patches ]

Signed-off-by: Matthew Wilcox (Oracle) <willy@infradead.org>
Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>
Tested-by: Hyeongogn Yoo <42.hyeyoo@gmail.com>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>
Cc: Alexander Potapenko <glider@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>
Cc: Dmitry Vyukov <dvyukov@google.com>
Cc: <kasan-dev@googlegroups.com>
---
 include/linux/kasan.h  |  9 +++++----
 mm/kasan/common.c      | 23 +++++++++++++----------
 mm/kasan/generic.c     |  8 ++++----
 mm/kasan/kasan.h       |  1 +
 mm/kasan/quarantine.c  |  2 +-
 mm/kasan/report.c      | 13 +++++++++++--
 mm/kasan/report_tags.c | 10 +++++-----
 mm/slab.c              |  2 +-
 mm/slub.c              |  2 +-
 9 files changed, 42 insertions(+), 28 deletions(-)

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
index 6a1cd2d38bff..7c06db78a76c 100644
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
+	folio = virt_to_folio(ptr);
 
 	/*
 	 * Even though this function is only called for kmem_cache_alloc and
@@ -411,12 +412,14 @@ void __kasan_slab_free_mempool(void *ptr, unsigned long ip)
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
+		struct slab *slab = folio_slab(folio);
+
+		____kasan_slab_free(slab->slab_cache, ptr, ip, false, false);
 	}
 }
 
@@ -560,7 +563,7 @@ void * __must_check __kasan_kmalloc_large(const void *ptr, size_t size,
 
 void * __must_check __kasan_krealloc(const void *object, size_t size, gfp_t flags)
 {
-	struct page *page;
+	struct slab *slab;
 
 	if (unlikely(object == ZERO_SIZE_PTR))
 		return (void *)object;
@@ -572,13 +575,13 @@ void * __must_check __kasan_krealloc(const void *object, size_t size, gfp_t flag
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
index e00999dc6499..3ad9624dcc56 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -150,6 +150,14 @@ struct page *kasan_addr_to_page(const void *addr)
 	return NULL;
 }
 
+struct slab *kasan_addr_to_slab(const void *addr)
+{
+	if ((addr >= (void *)PAGE_OFFSET) &&
+			(addr < high_memory))
+		return virt_to_slab(addr);
+	return NULL;
+}
+
 static void describe_object_addr(struct kmem_cache *cache, void *object,
 				const void *addr)
 {
@@ -248,8 +256,9 @@ static void print_address_description(void *addr, u8 tag)
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
index c13258116791..ddf5737c63d9 100644
--- a/mm/slab.c
+++ b/mm/slab.c
@@ -2604,7 +2604,7 @@ static struct slab *cache_grow_begin(struct kmem_cache *cachep,
 	 * page_address() in the latter returns a non-tagged pointer,
 	 * as it should be for slab pages.
 	 */
-	kasan_poison_slab(slab_page(slab));
+	kasan_poison_slab(slab);
 
 	/* Get slab management. */
 	freelist = alloc_slabmgmt(cachep, slab, offset,
diff --git a/mm/slub.c b/mm/slub.c
index ddf21c7a381a..d08ba1025aae 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -1961,7 +1961,7 @@ static struct slab *allocate_slab(struct kmem_cache *s, gfp_t flags, int node)
 
 	slab->slab_cache = s;
 
-	kasan_poison_slab(slab_page(slab));
+	kasan_poison_slab(slab);
 
 	start = slab_address(slab);
 
-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220104001046.12263-26-vbabka%40suse.cz.
