Return-Path: <kasan-dev+bncBAABBX5WT2KQMGQEUTNZHGA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33c.google.com (mail-wm1-x33c.google.com [IPv6:2a00:1450:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id 0BFCC549ECE
	for <lists+kasan-dev@lfdr.de>; Mon, 13 Jun 2022 22:17:36 +0200 (CEST)
Received: by mail-wm1-x33c.google.com with SMTP id l3-20020a05600c1d0300b0039c7efa2526sf3735954wms.3
        for <lists+kasan-dev@lfdr.de>; Mon, 13 Jun 2022 13:17:36 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1655151455; cv=pass;
        d=google.com; s=arc-20160816;
        b=a+gVG9YCzWbUDjSv1a3mJ+zAU32onx4W6WQhTRLr0/JROvou4FcV6+gD7Cqqdzk1Om
         fQqG/IxsotF1CehF3Nfn8t/Bew/ZqPbE21SWXxxq+JQJj+3A+4QYu0asT4mIDCcZbN5R
         OKv+C7Hz+v2xJMXHKF10x4u/RY56ssTPvcDKIDVei8bmGVXW1gdEjX+so9/5OL8CbOfE
         Qoqtu2fwvbrGf6+upnfeLOQaKBQpeIws+WNBYkgEjQ+Ai1oY23LHk2MCr91zASJyRoPa
         DFloipER72CN6gJ8Zo9FZoWdi1ICZyBhcbnSD01MPh78THOGQmQM2hvEBYDYXn/iIDY/
         y0IA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=PuEalnpB0VW7WllBzVBibgj+oRQSKzwEcfvsFSECaO4=;
        b=Abm7k4/a9nNw0cuqVckxFObjOM2AS+S3Cp77S/8orM2M/QHr3B/qdBX2V5VACO9Wox
         ewzsQ9W0AOJJu4COUO2hgh6NGkAVw4uw8eAMtm4lV8wna1waJUezIKAWth7rMOnF4c7m
         9G+jXeXPfwSm9x9Xn6WTSiZvnSXrwwh4wmeXwG9oH+T3qgWK6lOyflFGQCMLKlYotOA/
         +5a2S2thaNhMI/xCPXS7EQO/w94IhJDxD8WAZIPLSMZ+995/g6st+YA8gSRroYFHuZCa
         2S1K63j3EIobtUQqr9geNWBA+JPnndffzUun+YW5SHbeHuKoNZhkRxjb1KokY8nIr2Js
         f8SA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=me0bkbVm;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 91.121.223.63 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=PuEalnpB0VW7WllBzVBibgj+oRQSKzwEcfvsFSECaO4=;
        b=PGs0aebxWszX8h9ULjD/NKTKvYZcWjwUhGOncOp8BDYKPRysL3sLyAsHT5RizpBmzD
         nRclnu73tPgkqlJK328WpVTh+QzlnlYhBM3KqjATIRF431b8DEX9tuQzWenbELRZ1thn
         D+qZ8Uvr1Wc/qN4pVzjjNx/L7LKSklvNZmZt4s2fIDpkPiwaAtHNPG32oSCy21qJzcH/
         H9WhMMqEhdVPKAvkDjjnQZDuJY0DFde1YNy3NOTw6aHhEIRtggayCB0vnnWqfRcKLJrC
         kbNyUYPPCAcK56erBNsygcd4XNDpJVxVT91PmiYqnPQpVjKEzWOVxCqgKKCiLJeFXrbH
         +Irw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=PuEalnpB0VW7WllBzVBibgj+oRQSKzwEcfvsFSECaO4=;
        b=HgAkGzXIooOj3yNnBTOTmsxlhY6Um+8i9srrXE7pLyCyzQAuOqUYzuU53r8lJVOPQ1
         ad5JTYxHkHE0hNGy2r6u4WPRRrZ1RRDwRRkm5AcwpZj4xCrH0sNcSVsaf1nNj2QW+iRP
         UAPPCxTslUh/jjFdNTeyvAeVSgaO9+bev/tp6eJfEiz3GNBFFJeoI6RsnwnNMqT3XDAc
         Y5FAAhJVJVXui9cDCAPWGVFLloO6rn7ZABTWIPv9p789VE9WB5zXj9/ehu+RRChe7bZ6
         gmdO3yjNxk2ePI0l1FbHBEh/BjeA85f6VTu8sb8oLV7WT9VmmhNFZnPruHrMB6TxnC5k
         YzXQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533GQC4FjiHMf78F5TIffUHw2L7UdwCFr1PebAYq6PyjKdwrFPTB
	vBslEmDzPp+TOhGpN5GgHG8=
X-Google-Smtp-Source: ABdhPJw/N1OE1AAQGZ9gwxUBgmx5DUOmILdXnKbzvo7v9Hbdqa0VH0dp8l91y9nWXNs8JNyqjzS0hg==
X-Received: by 2002:a05:600c:414e:b0:397:55aa:ccc0 with SMTP id h14-20020a05600c414e00b0039755aaccc0mr435859wmm.51.1655151455649;
        Mon, 13 Jun 2022 13:17:35 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:1887:b0:218:5c3b:1a23 with SMTP id
 a7-20020a056000188700b002185c3b1a23ls334311wri.0.gmail; Mon, 13 Jun 2022
 13:17:34 -0700 (PDT)
X-Received: by 2002:a05:6000:c5:b0:213:b635:d73f with SMTP id q5-20020a05600000c500b00213b635d73fmr1382577wrx.578.1655151454873;
        Mon, 13 Jun 2022 13:17:34 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1655151454; cv=none;
        d=google.com; s=arc-20160816;
        b=g21GBtJv6g7mk+NG/w1Ta0om5Dp9ui2EwgBw4vWz6BzFHKo5Bj1EhJqk3s2lWkPx4L
         OAcMgswp6iuk4uCZE5Ll89eqljE4Fi9jb9eBDj1BgP3K9UcPlOxIEj7BcGVwPBAYKnJB
         CmwZ161a0xndUg+AnDMFjj2C0B6MDCIG3gFB5JTaUFPAqDgxejKfK2GrOtEsNXLwoVfS
         7OjK8ereOCQGKtCe6+reXznUIBwEQfjZY/M3ZMlg1eohOT6Uz9KeIKhU7igMqQAixuRk
         V0ftPoFzb10oPHPrYgMycg8EUas3/PS4//bJmmmOZwLAF4NgX7x5lWuOPVwkuM2vKWH1
         w+RQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=Pq3SVj2SILQniBWfHmFbw4zt5aRrCme3SaUMW3qAt2g=;
        b=pf5ra1J/I3hB8h/sAIahIc/zs/JOWvWyU9W9yMUiuEHP1TeihGSvLck/fWIL+7Opma
         LPvCxgDykAXbNjv0OYIaAtBJgKXxVnDMkt6hz8BcHkt4/vj8nu0ynhRcji6G4zAYh6aj
         abhAA4KIbMoKwHrncTvJaovz9fppWgoHBOqzlPY7KdW+j6EmO04EHBGhNFlvsQp70xCK
         Ggb5HhcpgucB7hxjUhcKfD/D8YWusu6MbgyFRzi1hgWNxNn9raXPOpWDJfnTS1CtxMRk
         jQaJL/RcCrPcfpyweJPbBNVHkwOaXKVy03Z1DDn0fmHsUDIIa/bcHxpswLJ64YiBGpHl
         p1Eg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=me0bkbVm;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 91.121.223.63 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out1.migadu.com (out1.migadu.com. [91.121.223.63])
        by gmr-mx.google.com with ESMTPS id co9-20020a0560000a0900b0021719593c28si277434wrb.8.2022.06.13.13.17.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 13 Jun 2022 13:17:34 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 91.121.223.63 as permitted sender) client-ip=91.121.223.63;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	Peter Collingbourne <pcc@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Florian Mayer <fmayer@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH 14/32] kasan: only define kasan_metadata_size for Generic mode
Date: Mon, 13 Jun 2022 22:14:05 +0200
Message-Id: <bf0388b6b2cec65114f32b5b96423c97a0704b4a.1655150842.git.andreyknvl@google.com>
In-Reply-To: <cover.1655150842.git.andreyknvl@google.com>
References: <cover.1655150842.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=me0bkbVm;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 91.121.223.63 as
 permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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

From: Andrey Konovalov <andreyknvl@google.com>

KASAN provides a helper for calculating the size of per-object metadata
stored in the redzone.

As now only the Generic mode uses per-object metadata, only define
kasan_metadata_size() for this mode.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 include/linux/kasan.h | 17 ++++++++---------
 mm/kasan/common.c     | 11 -----------
 mm/kasan/generic.c    | 11 +++++++++++
 3 files changed, 19 insertions(+), 20 deletions(-)

diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index b092277bf48d..027df7599573 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -150,14 +150,6 @@ static __always_inline void kasan_cache_create_kmalloc(struct kmem_cache *cache)
 		__kasan_cache_create_kmalloc(cache);
 }
 
-size_t __kasan_metadata_size(struct kmem_cache *cache);
-static __always_inline size_t kasan_metadata_size(struct kmem_cache *cache)
-{
-	if (kasan_enabled())
-		return __kasan_metadata_size(cache);
-	return 0;
-}
-
 void __kasan_poison_slab(struct slab *slab);
 static __always_inline void kasan_poison_slab(struct slab *slab)
 {
@@ -282,7 +274,6 @@ static inline void kasan_cache_create(struct kmem_cache *cache,
 				      unsigned int *size,
 				      slab_flags_t *flags) {}
 static inline void kasan_cache_create_kmalloc(struct kmem_cache *cache) {}
-static inline size_t kasan_metadata_size(struct kmem_cache *cache) { return 0; }
 static inline void kasan_poison_slab(struct slab *slab) {}
 static inline void kasan_unpoison_object_data(struct kmem_cache *cache,
 					void *object) {}
@@ -333,6 +324,8 @@ static inline void kasan_unpoison_task_stack(struct task_struct *task) {}
 
 #ifdef CONFIG_KASAN_GENERIC
 
+size_t kasan_metadata_size(struct kmem_cache *cache);
+
 void kasan_cache_shrink(struct kmem_cache *cache);
 void kasan_cache_shutdown(struct kmem_cache *cache);
 void kasan_record_aux_stack(void *ptr);
@@ -340,6 +333,12 @@ void kasan_record_aux_stack_noalloc(void *ptr);
 
 #else /* CONFIG_KASAN_GENERIC */
 
+/* Tag-based KASAN modes do not use per-object metadata. */
+static inline size_t kasan_metadata_size(struct kmem_cache *cache)
+{
+	return 0;
+}
+
 static inline void kasan_cache_shrink(struct kmem_cache *cache) {}
 static inline void kasan_cache_shutdown(struct kmem_cache *cache) {}
 static inline void kasan_record_aux_stack(void *ptr) {}
diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index 8a83ca9ad738..a0ddbf02aa6d 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -138,17 +138,6 @@ void __kasan_cache_create_kmalloc(struct kmem_cache *cache)
 	cache->kasan_info.is_kmalloc = true;
 }
 
-size_t __kasan_metadata_size(struct kmem_cache *cache)
-{
-	if (!kasan_requires_meta())
-		return 0;
-	return (cache->kasan_info.alloc_meta_offset ?
-		sizeof(struct kasan_alloc_meta) : 0) +
-		((cache->kasan_info.free_meta_offset &&
-		  cache->kasan_info.free_meta_offset != KASAN_NO_FREE_META) ?
-		 sizeof(struct kasan_free_meta) : 0);
-}
-
 void __kasan_poison_slab(struct slab *slab)
 {
 	struct page *page = slab_page(slab);
diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
index 5125fad76f70..806ab92032c3 100644
--- a/mm/kasan/generic.c
+++ b/mm/kasan/generic.c
@@ -427,6 +427,17 @@ void kasan_init_object_meta(struct kmem_cache *cache, const void *object)
 		__memset(alloc_meta, 0, sizeof(*alloc_meta));
 }
 
+size_t kasan_metadata_size(struct kmem_cache *cache)
+{
+	if (!kasan_requires_meta())
+		return 0;
+	return (cache->kasan_info.alloc_meta_offset ?
+		sizeof(struct kasan_alloc_meta) : 0) +
+		((cache->kasan_info.free_meta_offset &&
+		  cache->kasan_info.free_meta_offset != KASAN_NO_FREE_META) ?
+		 sizeof(struct kasan_free_meta) : 0);
+}
+
 static void __kasan_record_aux_stack(void *addr, bool can_alloc)
 {
 	struct slab *slab = kasan_addr_to_slab(addr);
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bf0388b6b2cec65114f32b5b96423c97a0704b4a.1655150842.git.andreyknvl%40google.com.
