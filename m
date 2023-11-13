Return-Path: <kasan-dev+bncBDXYDPH3S4OBBBXLZGVAMGQE5P7265A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13a.google.com (mail-lf1-x13a.google.com [IPv6:2a00:1450:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id EBAB67EA368
	for <lists+kasan-dev@lfdr.de>; Mon, 13 Nov 2023 20:14:15 +0100 (CET)
Received: by mail-lf1-x13a.google.com with SMTP id 2adb3069b0e04-507a3ae32b2sf4538380e87.2
        for <lists+kasan-dev@lfdr.de>; Mon, 13 Nov 2023 11:14:15 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1699902855; cv=pass;
        d=google.com; s=arc-20160816;
        b=OpyeVs/rsGUYmfLCkFfYJYD1GKkfzCE1zvW6kcrX4cdF4/52hiPRobVM/jPw27gJXZ
         KvfU07Aq9D1ISTcJsJnTRZ94tvmXecMCFTcuOoTveNA66mcaf9sY402NGam1oeSb9H43
         tHM3WB+bMqPZWKbkgosbf6smlMILly3qHKqs0x/VhaXB9nyyehBkzsb4cfM4vCPbDFiw
         1yupH2wlr1gx2yhX1oBwR9QPp2s7gveswqYtaVh1NLn5gcZrZcM4GEbjQtwttHbS44p6
         0q8FOs8WW/ptM8epI+r9Op3E2NdppfgQaL5q7F5HwNAK1EqnA8bWhhKjCS2Bwz/g7J/U
         R/Ig==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=DVa6s5588u1s4v4ORG/3L8rCYXrQO0CxDiMIQMTr2F8=;
        fh=RPAmrUlnQQdc1FhCirEqyhGh/OnPyRxUfAdj7ygPMx4=;
        b=YTACbOZvyZ830nIaN1N67aVxIg7Cg6Qkc2KUneDSFL/IP9wzKsiFIBi8RkVj/MI8E3
         AU5gJkbg37Cuyxx9Q/trPk5nePC0ZdKGu5VB7TZ/ZGFDWfx7jzDwQoZWJdgWKs26DhVK
         9fke+oLd3/2WbvQbvFdHjiz0f6bpd5T4EC77v62wKVofRtLaWN+NYdDSZPiLGx+MUX7o
         C/0fodPplHgaRa8raB6U3/RtAVAzRDUqZ80qWA5q85f+VsDOKfrTjJFw4ezjMUiAMBT6
         Y8ziTXLwXKEIz2BNX32JYAzFUkmv9IYoSsjpoQPFVu6dYJLg9fWVGHwD2OrOyOklUa8V
         Kc0g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b="J/xXyVkR";
       dkim=neutral (no key) header.i=@suse.cz header.b=x7V0Kskh;
       spf=softfail (google.com: domain of transitioning vbabka@suse.cz does not designate 2001:67c:2178:6::1d as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1699902855; x=1700507655; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=DVa6s5588u1s4v4ORG/3L8rCYXrQO0CxDiMIQMTr2F8=;
        b=jyZP25LmD98bedsIBlMz1kh29JgUWecTOtP7GNQEVtJyDa7N50m2LrqtdiYMAIIfp1
         clM+BWzJ6SRwJMhLH0cbbGuSgcOBVqiDk/1DGkCmV5pNHI2X+Xs+fopIZ6hwn+ztlVH1
         lp+OgxE+qaR7OjMqeNdOUQVMykPcXuluCgtbdtUoA1WbsmVs0DpD1qgEdR7vaSM+oUqK
         uFGtvQWqgslgWDZTGabCsGyZdhZWpZiZRpOubMjtyGAEEo0iuzB9NK8SbSfgOi8mvep+
         ryQhsKJSVHO2X3F1Dnzwdgk6QuG6IOjNH/Ab2TMhjuc7mliaLmJ26y+xfN8Ex+Y5I4DO
         hwhg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1699902855; x=1700507655;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=DVa6s5588u1s4v4ORG/3L8rCYXrQO0CxDiMIQMTr2F8=;
        b=lRabyyU6N3selaZt9JC2RiztbpcfMoWotFtew/1MnSNkqtTSxncjkTxo1cvFEj2UmT
         thas2wJXqW6AJMV7p2sm6DOPIfta+luRLrL9ASSdGzV1fegi6gZ/swua+Yt3+T50UCYi
         WuNT+tSpZwrIkVPRT5bLC8C6Xv6X/+AW4pYLWeQ786xXIw7t4mzKcLu8HtZ+RtZi1oKz
         0fK7fI4styh0AP1U8ONs67jO7tmkAFpnKPhDxMP/Ta1UvTjFWiiPLLssBA4pd2O6+mbG
         V0ABQLiryHFzzKtz2KQKmKq4sgTqzM464Rq2nVN60a9WLqrfDgJbiRFrqHRwTRWdpyv0
         YMaw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YwaxXM9BuLWsnNInY6bk//R7qO4TSLZDe5L+KNIV7phEYsokX2c
	C0oy2FEO9sK+1l47xHFK7s0=
X-Google-Smtp-Source: AGHT+IHsoBI2RP5ilh+Js0t3XZGkj8jASAvsBeo65k7ITerDbl+FemWis+jHifr0K8T/O8uBRwHjxg==
X-Received: by 2002:a05:6512:3b0c:b0:508:225e:e79f with SMTP id f12-20020a0565123b0c00b00508225ee79fmr6686216lfv.22.1699902855064;
        Mon, 13 Nov 2023 11:14:15 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:281b:b0:509:105e:64f2 with SMTP id
 cf27-20020a056512281b00b00509105e64f2ls295724lfb.0.-pod-prod-04-eu; Mon, 13
 Nov 2023 11:14:13 -0800 (PST)
X-Received: by 2002:a05:6512:61c:b0:509:4645:b78b with SMTP id b28-20020a056512061c00b005094645b78bmr4895979lfe.10.1699902853093;
        Mon, 13 Nov 2023 11:14:13 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1699902853; cv=none;
        d=google.com; s=arc-20160816;
        b=WOOLaQokkQLka+UXJgSSzzx2b4mzb1imSEdqebRXCcUXygxRKZxrmy1VHAaImZ2KEg
         xSeFZ0m9s/uXelUBwai93aFCUp/G+DKimBEk++y7ZEtoDVd2FoDifsP4JH/wZ1c+auLg
         EQtdrOSYSGkGiPJdBYknZQNpsVMvEPqMJJjbJPP7FkgKaqVnehIDkSL1bpeOYVMs05ef
         GvDvy3oe6X/4OTsF8YueufafS2b2SLpO7K8rwcRRQj7lYpp7Xw19cxahc/iYMfxgMprB
         ewadbXbpr+5EpOdBCUP06sfgIiWJkMAFUAD7fCQpO9TOkPVFmHiunBUvEKZApdCUOuyJ
         z84Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature:dkim-signature;
        bh=cXA2SgJxJZfvYr5jQXRsm4AX40wbUd1muC5Hg9F2/Ho=;
        fh=RPAmrUlnQQdc1FhCirEqyhGh/OnPyRxUfAdj7ygPMx4=;
        b=gHqPx+rYm0r+ZS81vuvWvzMOCNtLJjX5bL7yPcQpBZpeNE1w4L/giSf+xPMtFlPPyO
         3/KmPlijUXsPRuly6FVgfypqo16JMn6EYcWBcc8BP7hbNNX7whuqyJpElfyR7zlEH5NC
         KB574rvNoPprDnPeSOTjgB3fKp5w2woOCNc5ALWLI9GnXlt11rD0EWCVSzyo/AXIB0B2
         FxlVOg7wxiAEjX0H8US/J+Eq/59c+2UWdGr49QGxqJc1AcPnt99m0NnE9kZ26hRMWla4
         k+GdxvO4lqY8vxKoU9plkzWcf4wlCaewK6dl/au43SLf4/kRfbji8sRiH/CWK1BHAzSz
         Oy4Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b="J/xXyVkR";
       dkim=neutral (no key) header.i=@suse.cz header.b=x7V0Kskh;
       spf=softfail (google.com: domain of transitioning vbabka@suse.cz does not designate 2001:67c:2178:6::1d as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [2001:67c:2178:6::1d])
        by gmr-mx.google.com with ESMTPS id i13-20020a0564020f0d00b0053e90546ff6si259141eda.1.2023.11.13.11.14.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 13 Nov 2023 11:14:13 -0800 (PST)
Received-SPF: softfail (google.com: domain of transitioning vbabka@suse.cz does not designate 2001:67c:2178:6::1d as permitted sender) client-ip=2001:67c:2178:6::1d;
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id DAF4D1F88C;
	Mon, 13 Nov 2023 19:14:12 +0000 (UTC)
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by imap2.suse-dmz.suse.de (Postfix) with ESMTPS id 817BD13398;
	Mon, 13 Nov 2023 19:14:12 +0000 (UTC)
Received: from dovecot-director2.suse.de ([192.168.254.65])
	by imap2.suse-dmz.suse.de with ESMTPSA
	id iCnpHoR1UmVFOgAAMHmgww
	(envelope-from <vbabka@suse.cz>); Mon, 13 Nov 2023 19:14:12 +0000
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
Subject: [PATCH 10/20] mm/slab: move the rest of slub_def.h to mm/slab.h
Date: Mon, 13 Nov 2023 20:13:51 +0100
Message-ID: <20231113191340.17482-32-vbabka@suse.cz>
X-Mailer: git-send-email 2.42.1
In-Reply-To: <20231113191340.17482-22-vbabka@suse.cz>
References: <20231113191340.17482-22-vbabka@suse.cz>
MIME-Version: 1.0
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b="J/xXyVkR";
       dkim=neutral (no key) header.i=@suse.cz header.b=x7V0Kskh;
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

mm/slab.h is the only place to include include/linux/slub_def.h which
has allowed switching between SLAB and SLUB. Now we can simply move the
contents over and remove slub_def.h.

Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
---
 include/linux/slub_def.h | 150 ---------------------------------------
 mm/slab.h                | 137 ++++++++++++++++++++++++++++++++++-
 2 files changed, 136 insertions(+), 151 deletions(-)
 delete mode 100644 include/linux/slub_def.h

diff --git a/include/linux/slub_def.h b/include/linux/slub_def.h
deleted file mode 100644
index a0229ea42977..000000000000
--- a/include/linux/slub_def.h
+++ /dev/null
@@ -1,150 +0,0 @@
-/* SPDX-License-Identifier: GPL-2.0 */
-#ifndef _LINUX_SLUB_DEF_H
-#define _LINUX_SLUB_DEF_H
-
-/*
- * SLUB : A Slab allocator without object queues.
- *
- * (C) 2007 SGI, Christoph Lameter
- */
-#include <linux/kfence.h>
-#include <linux/kobject.h>
-#include <linux/reciprocal_div.h>
-#include <linux/local_lock.h>
-
-#ifdef CONFIG_SLUB_CPU_PARTIAL
-#define slub_percpu_partial(c)		((c)->partial)
-
-#define slub_set_percpu_partial(c, p)		\
-({						\
-	slub_percpu_partial(c) = (p)->next;	\
-})
-
-#define slub_percpu_partial_read_once(c)     READ_ONCE(slub_percpu_partial(c))
-#else
-#define slub_percpu_partial(c)			NULL
-
-#define slub_set_percpu_partial(c, p)
-
-#define slub_percpu_partial_read_once(c)	NULL
-#endif // CONFIG_SLUB_CPU_PARTIAL
-
-/*
- * Word size structure that can be atomically updated or read and that
- * contains both the order and the number of objects that a slab of the
- * given order would contain.
- */
-struct kmem_cache_order_objects {
-	unsigned int x;
-};
-
-/*
- * Slab cache management.
- */
-struct kmem_cache {
-#ifndef CONFIG_SLUB_TINY
-	struct kmem_cache_cpu __percpu *cpu_slab;
-#endif
-	/* Used for retrieving partial slabs, etc. */
-	slab_flags_t flags;
-	unsigned long min_partial;
-	unsigned int size;	/* The size of an object including metadata */
-	unsigned int object_size;/* The size of an object without metadata */
-	struct reciprocal_value reciprocal_size;
-	unsigned int offset;	/* Free pointer offset */
-#ifdef CONFIG_SLUB_CPU_PARTIAL
-	/* Number of per cpu partial objects to keep around */
-	unsigned int cpu_partial;
-	/* Number of per cpu partial slabs to keep around */
-	unsigned int cpu_partial_slabs;
-#endif
-	struct kmem_cache_order_objects oo;
-
-	/* Allocation and freeing of slabs */
-	struct kmem_cache_order_objects min;
-	gfp_t allocflags;	/* gfp flags to use on each alloc */
-	int refcount;		/* Refcount for slab cache destroy */
-	void (*ctor)(void *);
-	unsigned int inuse;		/* Offset to metadata */
-	unsigned int align;		/* Alignment */
-	unsigned int red_left_pad;	/* Left redzone padding size */
-	const char *name;	/* Name (only for display!) */
-	struct list_head list;	/* List of slab caches */
-#ifdef CONFIG_SYSFS
-	struct kobject kobj;	/* For sysfs */
-#endif
-#ifdef CONFIG_SLAB_FREELIST_HARDENED
-	unsigned long random;
-#endif
-
-#ifdef CONFIG_NUMA
-	/*
-	 * Defragmentation by allocating from a remote node.
-	 */
-	unsigned int remote_node_defrag_ratio;
-#endif
-
-#ifdef CONFIG_SLAB_FREELIST_RANDOM
-	unsigned int *random_seq;
-#endif
-
-#ifdef CONFIG_KASAN_GENERIC
-	struct kasan_cache kasan_info;
-#endif
-
-#ifdef CONFIG_HARDENED_USERCOPY
-	unsigned int useroffset;	/* Usercopy region offset */
-	unsigned int usersize;		/* Usercopy region size */
-#endif
-
-	struct kmem_cache_node *node[MAX_NUMNODES];
-};
-
-#if defined(CONFIG_SYSFS) && !defined(CONFIG_SLUB_TINY)
-#define SLAB_SUPPORTS_SYSFS
-void sysfs_slab_unlink(struct kmem_cache *);
-void sysfs_slab_release(struct kmem_cache *);
-#else
-static inline void sysfs_slab_unlink(struct kmem_cache *s)
-{
-}
-static inline void sysfs_slab_release(struct kmem_cache *s)
-{
-}
-#endif
-
-void *fixup_red_left(struct kmem_cache *s, void *p);
-
-static inline void *nearest_obj(struct kmem_cache *cache, const struct slab *slab,
-				void *x) {
-	void *object = x - (x - slab_address(slab)) % cache->size;
-	void *last_object = slab_address(slab) +
-		(slab->objects - 1) * cache->size;
-	void *result = (unlikely(object > last_object)) ? last_object : object;
-
-	result = fixup_red_left(cache, result);
-	return result;
-}
-
-/* Determine object index from a given position */
-static inline unsigned int __obj_to_index(const struct kmem_cache *cache,
-					  void *addr, void *obj)
-{
-	return reciprocal_divide(kasan_reset_tag(obj) - addr,
-				 cache->reciprocal_size);
-}
-
-static inline unsigned int obj_to_index(const struct kmem_cache *cache,
-					const struct slab *slab, void *obj)
-{
-	if (is_kfence_address(obj))
-		return 0;
-	return __obj_to_index(cache, slab_address(slab), obj);
-}
-
-static inline int objs_per_slab(const struct kmem_cache *cache,
-				     const struct slab *slab)
-{
-	return slab->objects;
-}
-#endif /* _LINUX_SLUB_DEF_H */
diff --git a/mm/slab.h b/mm/slab.h
index 014c36ea51fa..6e76216ac74e 100644
--- a/mm/slab.h
+++ b/mm/slab.h
@@ -209,7 +209,142 @@ static inline size_t slab_size(const struct slab *slab)
 	return PAGE_SIZE << slab_order(slab);
 }
 
-#include <linux/slub_def.h>
+#include <linux/kfence.h>
+#include <linux/kobject.h>
+#include <linux/reciprocal_div.h>
+#include <linux/local_lock.h>
+
+#ifdef CONFIG_SLUB_CPU_PARTIAL
+#define slub_percpu_partial(c)		((c)->partial)
+
+#define slub_set_percpu_partial(c, p)		\
+({						\
+	slub_percpu_partial(c) = (p)->next;	\
+})
+
+#define slub_percpu_partial_read_once(c)     READ_ONCE(slub_percpu_partial(c))
+#else
+#define slub_percpu_partial(c)			NULL
+
+#define slub_set_percpu_partial(c, p)
+
+#define slub_percpu_partial_read_once(c)	NULL
+#endif // CONFIG_SLUB_CPU_PARTIAL
+
+/*
+ * Word size structure that can be atomically updated or read and that
+ * contains both the order and the number of objects that a slab of the
+ * given order would contain.
+ */
+struct kmem_cache_order_objects {
+	unsigned int x;
+};
+
+/*
+ * Slab cache management.
+ */
+struct kmem_cache {
+#ifndef CONFIG_SLUB_TINY
+	struct kmem_cache_cpu __percpu *cpu_slab;
+#endif
+	/* Used for retrieving partial slabs, etc. */
+	slab_flags_t flags;
+	unsigned long min_partial;
+	unsigned int size;	/* The size of an object including metadata */
+	unsigned int object_size;/* The size of an object without metadata */
+	struct reciprocal_value reciprocal_size;
+	unsigned int offset;	/* Free pointer offset */
+#ifdef CONFIG_SLUB_CPU_PARTIAL
+	/* Number of per cpu partial objects to keep around */
+	unsigned int cpu_partial;
+	/* Number of per cpu partial slabs to keep around */
+	unsigned int cpu_partial_slabs;
+#endif
+	struct kmem_cache_order_objects oo;
+
+	/* Allocation and freeing of slabs */
+	struct kmem_cache_order_objects min;
+	gfp_t allocflags;	/* gfp flags to use on each alloc */
+	int refcount;		/* Refcount for slab cache destroy */
+	void (*ctor)(void *object);	/* Object constructor */
+	unsigned int inuse;		/* Offset to metadata */
+	unsigned int align;		/* Alignment */
+	unsigned int red_left_pad;	/* Left redzone padding size */
+	const char *name;	/* Name (only for display!) */
+	struct list_head list;	/* List of slab caches */
+#ifdef CONFIG_SYSFS
+	struct kobject kobj;	/* For sysfs */
+#endif
+#ifdef CONFIG_SLAB_FREELIST_HARDENED
+	unsigned long random;
+#endif
+
+#ifdef CONFIG_NUMA
+	/*
+	 * Defragmentation by allocating from a remote node.
+	 */
+	unsigned int remote_node_defrag_ratio;
+#endif
+
+#ifdef CONFIG_SLAB_FREELIST_RANDOM
+	unsigned int *random_seq;
+#endif
+
+#ifdef CONFIG_KASAN_GENERIC
+	struct kasan_cache kasan_info;
+#endif
+
+#ifdef CONFIG_HARDENED_USERCOPY
+	unsigned int useroffset;	/* Usercopy region offset */
+	unsigned int usersize;		/* Usercopy region size */
+#endif
+
+	struct kmem_cache_node *node[MAX_NUMNODES];
+};
+
+#if defined(CONFIG_SYSFS) && !defined(CONFIG_SLUB_TINY)
+#define SLAB_SUPPORTS_SYSFS
+void sysfs_slab_unlink(struct kmem_cache *s);
+void sysfs_slab_release(struct kmem_cache *s);
+#else
+static inline void sysfs_slab_unlink(struct kmem_cache *s) { }
+static inline void sysfs_slab_release(struct kmem_cache *s) { }
+#endif
+
+void *fixup_red_left(struct kmem_cache *s, void *p);
+
+static inline void *nearest_obj(struct kmem_cache *cache,
+				const struct slab *slab, void *x) {
+	void *object = x - (x - slab_address(slab)) % cache->size;
+	void *last_object = slab_address(slab) +
+		(slab->objects - 1) * cache->size;
+	void *result = (unlikely(object > last_object)) ? last_object : object;
+
+	result = fixup_red_left(cache, result);
+	return result;
+}
+
+/* Determine object index from a given position */
+static inline unsigned int __obj_to_index(const struct kmem_cache *cache,
+					  void *addr, void *obj)
+{
+	return reciprocal_divide(kasan_reset_tag(obj) - addr,
+				 cache->reciprocal_size);
+}
+
+static inline unsigned int obj_to_index(const struct kmem_cache *cache,
+					const struct slab *slab, void *obj)
+{
+	if (is_kfence_address(obj))
+		return 0;
+	return __obj_to_index(cache, slab_address(slab), obj);
+}
+
+static inline int objs_per_slab(const struct kmem_cache *cache,
+				const struct slab *slab)
+{
+	return slab->objects;
+}
 
 #include <linux/memcontrol.h>
 #include <linux/fault-inject.h>
-- 
2.42.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231113191340.17482-32-vbabka%40suse.cz.
