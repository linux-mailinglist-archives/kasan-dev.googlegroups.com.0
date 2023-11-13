Return-Path: <kasan-dev+bncBDXYDPH3S4OBBBPLZGVAMGQE632IULY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23b.google.com (mail-lj1-x23b.google.com [IPv6:2a00:1450:4864:20::23b])
	by mail.lfdr.de (Postfix) with ESMTPS id 1CE437EA365
	for <lists+kasan-dev@lfdr.de>; Mon, 13 Nov 2023 20:14:15 +0100 (CET)
Received: by mail-lj1-x23b.google.com with SMTP id 38308e7fff4ca-2c562dab105sf31797551fa.1
        for <lists+kasan-dev@lfdr.de>; Mon, 13 Nov 2023 11:14:15 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1699902854; cv=pass;
        d=google.com; s=arc-20160816;
        b=WESq2YaLyhjmvdw12yVekhwb0HWoz3snfsGUZrCEPgUSTMT1CWeHm53PMHpi9VEmzx
         420ELrPrqc9DBT7WgTXikJk1RLT/XT7gJ2wbIZSebthiRzFrjWQiITLigqdDNCKpvprv
         hdCQMHC77RmXp7gPW2pyTH2TNYj4wu/FZ8zLobClOzPJqm/H/WSnStuu6IIZ9P4xxzDb
         uE3atCY+xQPJGRbWR/+U0odHc0+psxTZ+9Z2/mG2vBwuiWd9f4FtxuFe/APrx8xlVYxP
         MwstROzI9z8eeOXEqCH34SQ8ctXJWdvn0FhsnBI/rssKrm0dPt6oaVeyX7lGnWnrtkKG
         gEzg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=Z4hiqUl7PJ9CZF4/RUVE3vpKYM03Bu41iuIin+c9ugU=;
        fh=RPAmrUlnQQdc1FhCirEqyhGh/OnPyRxUfAdj7ygPMx4=;
        b=u7GN5MrYnNqKcVyv86+2g+HbLRNkImo56xvUhzwCg4aTHI6DBDFfaPW9Bwl15CLElw
         kfXUa6usWDzNnFLSLhZNJbNammv/+Gz7Tqa2qQhNiLb847oodJ8eo2LJiCjVjv5FRp1M
         DB/TQFSIk5ipWMd4OukgsEoSqZDfaYvZ3muQHbP5dfvaMWxB9HcGipan4shlsyAbz2rw
         4aL1RKk5XEFMN2+dbmonmEte+1yDoMMRr2FtrylodoW6DeYIhMMRy9VeNXL0PranKTKQ
         /i/aT9SdTcEdoWKtPLamVohj+DCwEj+j0UiZJ1gvWD6YXPiMtNz52I5X++cNQOdZQEQh
         /WCg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=JkDwUha8;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=7F+W9fjH;
       spf=softfail (google.com: domain of transitioning vbabka@suse.cz does not designate 2001:67c:2178:6::1d as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1699902854; x=1700507654; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Z4hiqUl7PJ9CZF4/RUVE3vpKYM03Bu41iuIin+c9ugU=;
        b=T7mTQ/tOxEQToLdFuQDDmhF2FvrWYw+cLVUuM42XU6wchNCOVazg4zZgjxCFw03Kht
         3eBnSKxXvRMOZHyTwDAmE9M8qZS9IIu2J4kAJ0QJNDyBJb0zecNr8r142f9fuB6Xr4QB
         LYjJPQKpOHOpl9PmlLJMcebPSiHt7XRffSQwU2ptdWxS0di2yY6yiKM9QERTZb30Xei2
         H4lzLpZ2XEL2mmjcCPP4jCoI4IjQwUh3xIRMGzl5TLvvsU+H4BcNFya4aqLCidU12LZT
         Gy7rDLRoycfithQtI9/f/YrWd38Apqv4o5PXTyuhA92aMQ+ILJQUGEEkvXhAKHI+bJoj
         mW1g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1699902854; x=1700507654;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=Z4hiqUl7PJ9CZF4/RUVE3vpKYM03Bu41iuIin+c9ugU=;
        b=ixTC8j6j9RIdXza2YR5+4JPAWTT9QJqDCr+OGpmL07ZIXyRE2Hk82RhKRtazhr84cm
         069RrfTIpGVRISMQP2R+sJGQQJFo4GQtfDXg0SM6HVC6I3PYCrfx7ZAc2iq+e44bma3J
         WBihMNXxw7/wJVRXRMIeYCNiT+Zg5ZL3Rt+7b1L2FG8/s10T6Ulvcu8T3xijbb7045WZ
         vF/7ntyra3g3yc2EUJE/Mh5jLY8JZn7uO9iw0WZ1RS2UE5QMn6Oz6HHI0M/m0ENpvU7m
         nL8hNOCeUFietZ5qG3gSJst6RT1SiikX2+Yr37/EmjSKRF2gA8AbMnt+rTT8LR+6orcw
         fczA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YxFq9GWkaGpvnr/OP4abcEunLsjl9g3Y1b/6oYMAkgQFyoNDLu6
	5YnvP1WiybgRhDfflyqflCg=
X-Google-Smtp-Source: AGHT+IGiSaX15D4Y7EQje+oEls78JZVPVdE0qJCpJGbEFfjInzL9rFoGiKiaf7SGyWtuk4EsOCywoA==
X-Received: by 2002:a05:6512:6cb:b0:509:d962:3c66 with SMTP id u11-20020a05651206cb00b00509d9623c66mr145419lff.21.1699902853976;
        Mon, 13 Nov 2023 11:14:13 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3e1f:b0:505:14bb:6259 with SMTP id
 i31-20020a0565123e1f00b0050514bb6259ls867530lfv.0.-pod-prod-00-eu; Mon, 13
 Nov 2023 11:14:12 -0800 (PST)
X-Received: by 2002:a05:6512:15a6:b0:50a:6fb8:a0c0 with SMTP id bp38-20020a05651215a600b0050a6fb8a0c0mr152050lfb.19.1699902852042;
        Mon, 13 Nov 2023 11:14:12 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1699902852; cv=none;
        d=google.com; s=arc-20160816;
        b=a3VMsDIr1v8Gm8xqnUeKwIj8kyA7LybcVF3gef2F6ymajzpl7iY1GJ9AZCxT5vbR7Q
         irLBbo4YSU9qiALeveEFluYJf85f/QWauN3G0FcDeTNYNFjQRfhoLuvZ7FJQ1UdGuB7O
         DX0AoUKpHZWRY306T0vPFM51/vm21ToYCO9W5mu9dwmFZhBN61EPeADuWov1eExmOoSJ
         VkCx9s6wfZ6wbYZfX0XI69ceb5SkbOUkfapb7z6EcknIqh5C7cGifKSdE1qam/SgKvWB
         Y3U5WwIn9Vg1n0Nwz3hKEvVwWvmy0UoDyg8ttwQUirTu4Q9VvO/vriF4KuMHB27rbMh2
         6UPQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature:dkim-signature;
        bh=foUH5Pkv5cwwnwudHkR/uUiz9PA77WygUi4ZtZ6vDeI=;
        fh=RPAmrUlnQQdc1FhCirEqyhGh/OnPyRxUfAdj7ygPMx4=;
        b=ARALssbC8QuZpd0q4ti0cSc1E8VvaaLsB9whm/pFGPHh3BUVw1HqWKYJs0ZVq94I0V
         zNvoAcPgYip7RM6Qrxvi82Yag2YPz4nxy0TLTjPm0ulPgdipzjGLYvzn87TNvUemB+t3
         O4bWJ5tkqDzUTw0HHC3s17aOs1mia3fAVNA/01Gsqf9IL06CMFbzwwqfsBG7m7YXKx0a
         ZWWlluLiu06/0NYL6FNxPl4eupI/FMv3UFZKglhEBwj+1IiwZC9/HTAjEwyjZ5Ivrzj3
         hGvor0pvPnPMAl4sfHHvQr2+jK/86HshdjE1SLmD/JIrGlWn2/qi+KnEWkq1UCqyA4WE
         QC/w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=JkDwUha8;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=7F+W9fjH;
       spf=softfail (google.com: domain of transitioning vbabka@suse.cz does not designate 2001:67c:2178:6::1d as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [2001:67c:2178:6::1d])
        by gmr-mx.google.com with ESMTPS id v18-20020a056512097200b005068bf0b332si243569lft.1.2023.11.13.11.14.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 13 Nov 2023 11:14:12 -0800 (PST)
Received-SPF: softfail (google.com: domain of transitioning vbabka@suse.cz does not designate 2001:67c:2178:6::1d as permitted sender) client-ip=2001:67c:2178:6::1d;
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id 70BFD1F86A;
	Mon, 13 Nov 2023 19:14:11 +0000 (UTC)
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by imap2.suse-dmz.suse.de (Postfix) with ESMTPS id 1307813398;
	Mon, 13 Nov 2023 19:14:11 +0000 (UTC)
Received: from dovecot-director2.suse.de ([192.168.254.65])
	by imap2.suse-dmz.suse.de with ESMTPSA
	id 6MwFBIN1UmVFOgAAMHmgww
	(envelope-from <vbabka@suse.cz>); Mon, 13 Nov 2023 19:14:11 +0000
From: Vlastimil Babka <vbabka@suse.cz>
To: David Rientjes <rientjes@google.com>,
	Christoph Lameter <cl@linux.com>,
	Pekka Enberg <penberg@kernel.org>,
	Joonsoo Kim <iamjoonsoo.kim@lge.com>
Cc: Andrew Morton <akpm@linux-foundation.org>,
	Hyeonggon Yoo <42.hyeyoo@gmail.com>,
	Roman Gushchin <roman.gushchin@linux.dev>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	patches@lists.linux.dev,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Marco Elver <elver@google.com>,
	Johannes Weiner <hannes@cmpxchg.org>,
	Michal Hocko <mhocko@kernel.org>,
	Shakeel Butt <shakeelb@google.com>,
	Muchun Song <muchun.song@linux.dev>,
	Kees Cook <keescook@chromium.org>,
	kasan-dev@googlegroups.com,
	cgroups@vger.kernel.org,
	Vlastimil Babka <vbabka@suse.cz>
Subject: [PATCH 06/20] mm/slab: remove CONFIG_SLAB code from slab common code
Date: Mon, 13 Nov 2023 20:13:47 +0100
Message-ID: <20231113191340.17482-28-vbabka@suse.cz>
X-Mailer: git-send-email 2.42.1
In-Reply-To: <20231113191340.17482-22-vbabka@suse.cz>
References: <20231113191340.17482-22-vbabka@suse.cz>
MIME-Version: 1.0
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=JkDwUha8;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=7F+W9fjH;
       spf=softfail (google.com: domain of transitioning vbabka@suse.cz does
 not designate 2001:67c:2178:6::1d as permitted sender) smtp.mailfrom=vbabka@suse.cz
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

In slab_common.c and slab.h headers, we can now remove all code behind
CONFIG_SLAB and CONFIG_DEBUG_SLAB ifdefs, and remove all CONFIG_SLUB
ifdefs.

Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
---
 include/linux/slab.h | 13 +--------
 mm/slab.h            | 69 ++++----------------------------------------
 mm/slab_common.c     | 22 ++------------
 3 files changed, 8 insertions(+), 96 deletions(-)

diff --git a/include/linux/slab.h b/include/linux/slab.h
index 34e43cddc520..90fb1f0d843a 100644
--- a/include/linux/slab.h
+++ b/include/linux/slab.h
@@ -24,7 +24,6 @@
 
 /*
  * Flags to pass to kmem_cache_create().
- * The ones marked DEBUG are only valid if CONFIG_DEBUG_SLAB is set.
  */
 /* DEBUG: Perform (expensive) checks on alloc/free */
 #define SLAB_CONSISTENCY_CHECKS	((slab_flags_t __force)0x00000100U)
@@ -302,25 +301,15 @@ static inline unsigned int arch_slab_minalign(void)
  * Kmalloc array related definitions
  */
 
-#ifdef CONFIG_SLAB
 /*
- * SLAB and SLUB directly allocates requests fitting in to an order-1 page
+ * SLUB directly allocates requests fitting in to an order-1 page
  * (PAGE_SIZE*2).  Larger requests are passed to the page allocator.
  */
 #define KMALLOC_SHIFT_HIGH	(PAGE_SHIFT + 1)
 #define KMALLOC_SHIFT_MAX	(MAX_ORDER + PAGE_SHIFT)
 #ifndef KMALLOC_SHIFT_LOW
-#define KMALLOC_SHIFT_LOW	5
-#endif
-#endif
-
-#ifdef CONFIG_SLUB
-#define KMALLOC_SHIFT_HIGH	(PAGE_SHIFT + 1)
-#define KMALLOC_SHIFT_MAX	(MAX_ORDER + PAGE_SHIFT)
-#ifndef KMALLOC_SHIFT_LOW
 #define KMALLOC_SHIFT_LOW	3
 #endif
-#endif
 
 /* Maximum allocatable size */
 #define KMALLOC_MAX_SIZE	(1UL << KMALLOC_SHIFT_MAX)
diff --git a/mm/slab.h b/mm/slab.h
index 3d07fb428393..014c36ea51fa 100644
--- a/mm/slab.h
+++ b/mm/slab.h
@@ -42,21 +42,6 @@ typedef union {
 struct slab {
 	unsigned long __page_flags;
 
-#if defined(CONFIG_SLAB)
-
-	struct kmem_cache *slab_cache;
-	union {
-		struct {
-			struct list_head slab_list;
-			void *freelist;	/* array of free object indexes */
-			void *s_mem;	/* first object */
-		};
-		struct rcu_head rcu_head;
-	};
-	unsigned int active;
-
-#elif defined(CONFIG_SLUB)
-
 	struct kmem_cache *slab_cache;
 	union {
 		struct {
@@ -91,10 +76,6 @@ struct slab {
 	};
 	unsigned int __unused;
 
-#else
-#error "Unexpected slab allocator configured"
-#endif
-
 	atomic_t __page_refcount;
 #ifdef CONFIG_MEMCG
 	unsigned long memcg_data;
@@ -111,7 +92,7 @@ SLAB_MATCH(memcg_data, memcg_data);
 #endif
 #undef SLAB_MATCH
 static_assert(sizeof(struct slab) <= sizeof(struct page));
-#if defined(system_has_freelist_aba) && defined(CONFIG_SLUB)
+#if defined(system_has_freelist_aba)
 static_assert(IS_ALIGNED(offsetof(struct slab, freelist), sizeof(freelist_aba_t)));
 #endif
 
@@ -228,13 +209,7 @@ static inline size_t slab_size(const struct slab *slab)
 	return PAGE_SIZE << slab_order(slab);
 }
 
-#ifdef CONFIG_SLAB
-#include <linux/slab_def.h>
-#endif
-
-#ifdef CONFIG_SLUB
 #include <linux/slub_def.h>
-#endif
 
 #include <linux/memcontrol.h>
 #include <linux/fault-inject.h>
@@ -320,26 +295,16 @@ static inline bool is_kmalloc_cache(struct kmem_cache *s)
 			 SLAB_CACHE_DMA32 | SLAB_PANIC | \
 			 SLAB_TYPESAFE_BY_RCU | SLAB_DEBUG_OBJECTS )
 
-#if defined(CONFIG_DEBUG_SLAB)
-#define SLAB_DEBUG_FLAGS (SLAB_RED_ZONE | SLAB_POISON | SLAB_STORE_USER)
-#elif defined(CONFIG_SLUB_DEBUG)
+#ifdef CONFIG_SLUB_DEBUG
 #define SLAB_DEBUG_FLAGS (SLAB_RED_ZONE | SLAB_POISON | SLAB_STORE_USER | \
 			  SLAB_TRACE | SLAB_CONSISTENCY_CHECKS)
 #else
 #define SLAB_DEBUG_FLAGS (0)
 #endif
 
-#if defined(CONFIG_SLAB)
-#define SLAB_CACHE_FLAGS (SLAB_MEM_SPREAD | SLAB_NOLEAKTRACE | \
-			  SLAB_RECLAIM_ACCOUNT | SLAB_TEMPORARY | \
-			  SLAB_ACCOUNT | SLAB_NO_MERGE)
-#elif defined(CONFIG_SLUB)
 #define SLAB_CACHE_FLAGS (SLAB_NOLEAKTRACE | SLAB_RECLAIM_ACCOUNT | \
 			  SLAB_TEMPORARY | SLAB_ACCOUNT | \
 			  SLAB_NO_USER_FLAGS | SLAB_KMALLOC | SLAB_NO_MERGE)
-#else
-#define SLAB_CACHE_FLAGS (SLAB_NOLEAKTRACE)
-#endif
 
 /* Common flags available with current configuration */
 #define CACHE_CREATE_MASK (SLAB_CORE_FLAGS | SLAB_DEBUG_FLAGS | SLAB_CACHE_FLAGS)
@@ -672,18 +637,14 @@ size_t __ksize(const void *objp);
 
 static inline size_t slab_ksize(const struct kmem_cache *s)
 {
-#ifndef CONFIG_SLUB
-	return s->object_size;
-
-#else /* CONFIG_SLUB */
-# ifdef CONFIG_SLUB_DEBUG
+#ifdef CONFIG_SLUB_DEBUG
 	/*
 	 * Debugging requires use of the padding between object
 	 * and whatever may come after it.
 	 */
 	if (s->flags & (SLAB_RED_ZONE | SLAB_POISON))
 		return s->object_size;
-# endif
+#endif
 	if (s->flags & SLAB_KASAN)
 		return s->object_size;
 	/*
@@ -697,7 +658,6 @@ static inline size_t slab_ksize(const struct kmem_cache *s)
 	 * Else we can use all the padding etc for the allocation
 	 */
 	return s->size;
-#endif
 }
 
 static inline struct kmem_cache *slab_pre_alloc_hook(struct kmem_cache *s,
@@ -775,23 +735,6 @@ static inline void slab_post_alloc_hook(struct kmem_cache *s,
  * The slab lists for all objects.
  */
 struct kmem_cache_node {
-#ifdef CONFIG_SLAB
-	raw_spinlock_t list_lock;
-	struct list_head slabs_partial;	/* partial list first, better asm code */
-	struct list_head slabs_full;
-	struct list_head slabs_free;
-	unsigned long total_slabs;	/* length of all slab lists */
-	unsigned long free_slabs;	/* length of free slab list only */
-	unsigned long free_objects;
-	unsigned int free_limit;
-	unsigned int colour_next;	/* Per-node cache coloring */
-	struct array_cache *shared;	/* shared per node */
-	struct alien_cache **alien;	/* on other nodes */
-	unsigned long next_reap;	/* updated without locking */
-	int free_touched;		/* updated without locking */
-#endif
-
-#ifdef CONFIG_SLUB
 	spinlock_t list_lock;
 	unsigned long nr_partial;
 	struct list_head partial;
@@ -800,8 +743,6 @@ struct kmem_cache_node {
 	atomic_long_t total_objects;
 	struct list_head full;
 #endif
-#endif
-
 };
 
 static inline struct kmem_cache_node *get_node(struct kmem_cache *s, int node)
@@ -818,7 +759,7 @@ static inline struct kmem_cache_node *get_node(struct kmem_cache *s, int node)
 		 if ((__n = get_node(__s, __node)))
 
 
-#if defined(CONFIG_SLAB) || defined(CONFIG_SLUB_DEBUG)
+#ifdef CONFIG_SLUB_DEBUG
 void dump_unreclaimable_slab(void);
 #else
 static inline void dump_unreclaimable_slab(void)
diff --git a/mm/slab_common.c b/mm/slab_common.c
index 8d431193c273..63b8411db7ce 100644
--- a/mm/slab_common.c
+++ b/mm/slab_common.c
@@ -71,10 +71,8 @@ static int __init setup_slab_merge(char *str)
 	return 1;
 }
 
-#ifdef CONFIG_SLUB
 __setup_param("slub_nomerge", slub_nomerge, setup_slab_nomerge, 0);
 __setup_param("slub_merge", slub_merge, setup_slab_merge, 0);
-#endif
 
 __setup("slab_nomerge", setup_slab_nomerge);
 __setup("slab_merge", setup_slab_merge);
@@ -197,10 +195,6 @@ struct kmem_cache *find_mergeable(unsigned int size, unsigned int align,
 		if (s->size - size >= sizeof(void *))
 			continue;
 
-		if (IS_ENABLED(CONFIG_SLAB) && align &&
-			(align > s->align || s->align % align))
-			continue;
-
 		return s;
 	}
 	return NULL;
@@ -1222,12 +1216,8 @@ void cache_random_seq_destroy(struct kmem_cache *cachep)
 }
 #endif /* CONFIG_SLAB_FREELIST_RANDOM */
 
-#if defined(CONFIG_SLAB) || defined(CONFIG_SLUB_DEBUG)
-#ifdef CONFIG_SLAB
-#define SLABINFO_RIGHTS (0600)
-#else
+#ifdef CONFIG_SLUB_DEBUG
 #define SLABINFO_RIGHTS (0400)
-#endif
 
 static void print_slabinfo_header(struct seq_file *m)
 {
@@ -1235,18 +1225,10 @@ static void print_slabinfo_header(struct seq_file *m)
 	 * Output format version, so at least we can change it
 	 * without _too_ many complaints.
 	 */
-#ifdef CONFIG_DEBUG_SLAB
-	seq_puts(m, "slabinfo - version: 2.1 (statistics)\n");
-#else
 	seq_puts(m, "slabinfo - version: 2.1\n");
-#endif
 	seq_puts(m, "# name            <active_objs> <num_objs> <objsize> <objperslab> <pagesperslab>");
 	seq_puts(m, " : tunables <limit> <batchcount> <sharedfactor>");
 	seq_puts(m, " : slabdata <active_slabs> <num_slabs> <sharedavail>");
-#ifdef CONFIG_DEBUG_SLAB
-	seq_puts(m, " : globalstat <listallocs> <maxobjs> <grown> <reaped> <error> <maxfreeable> <nodeallocs> <remotefrees> <alienoverflow>");
-	seq_puts(m, " : cpustat <allochit> <allocmiss> <freehit> <freemiss>");
-#endif
 	seq_putc(m, '\n');
 }
 
@@ -1370,7 +1352,7 @@ static int __init slab_proc_init(void)
 }
 module_init(slab_proc_init);
 
-#endif /* CONFIG_SLAB || CONFIG_SLUB_DEBUG */
+#endif /* CONFIG_SLUB_DEBUG */
 
 static __always_inline __realloc_size(2) void *
 __do_krealloc(const void *p, size_t new_size, gfp_t flags)
-- 
2.42.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231113191340.17482-28-vbabka%40suse.cz.
