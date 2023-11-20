Return-Path: <kasan-dev+bncBDXYDPH3S4OBBRGN52VAMGQEUDVA3WI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13f.google.com (mail-lf1-x13f.google.com [IPv6:2a00:1450:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id 54BFC7F1C80
	for <lists+kasan-dev@lfdr.de>; Mon, 20 Nov 2023 19:34:45 +0100 (CET)
Received: by mail-lf1-x13f.google.com with SMTP id 2adb3069b0e04-507a3ae32b2sf4315257e87.2
        for <lists+kasan-dev@lfdr.de>; Mon, 20 Nov 2023 10:34:45 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1700505285; cv=pass;
        d=google.com; s=arc-20160816;
        b=YXztGeqezlkMbus7gpChujd098eWeyR52aC1q0JObyN71JfCD0wgPjx9jU/lS80HLH
         +r6YuqakaHUlE08hYMc0Yd/hsu4wbsRRloa2aj4k3JniYX/0XxNOwdNVxapBqMWRZ1Zk
         QRKDfuRD+dX/cutzGQRSLK08a6RBYNFr3d1gAxd55y8zeFEk9xuELmwmCAwkaaWt5Nex
         5ZOdXjBRYCh0JQuaq4gW8kS15nca6ioXXbCVdvTO7P46v5Un5SVddXMwCGFyYWL/oFNS
         ymDhsaOix7XcVOaLB57zrF0U2uSB5E3Vv/AtdunaPTsqjMAJ9AGp/+bYlMivTSQ+N0CT
         2M6Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:in-reply-to:references
         :message-id:mime-version:subject:date:from:sender:dkim-signature;
        bh=o9G3bku/BdI4vasm7abd5E4r7a7lX923wbD5Avcjh3I=;
        fh=ONqwzSuNvSIo96fWAp0pW54nN9xAdzTfApSlC7LEvRU=;
        b=DVm7F9++SYG3ugyVImAy+yUmRvlYk2e8ugNFlZg3bDmUeGb8MqjKoAjeS4sXym0DZU
         /iRR8qD9KiHH+mNJKXwmPsy1N45ymq9GfLm2ojlXZmS2fKq5N6XaTQlQLmJlwXpyZcP3
         qvm4XQHLxOK7au84ujcqL3JqS+oWm5DSUQbCchaH/rTSvU2SbMRtCGvxs9o2tC5VNvuN
         YSgnCpnNcRv2UOKr1TxVPqi04xPRxk862atyTPDmPnT3U8V1/6Kt8F3J0nrVY3fNeT3I
         qWEr2kvSmPKzvzTHNz8iaNnKGYtpRXzylRuoikgi4bySZysCFKQDKaynbuOCCk5kUQd9
         mZMQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=OPvbGApq;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.29 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1700505285; x=1701110085; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:in-reply-to:references:message-id
         :mime-version:subject:date:from:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=o9G3bku/BdI4vasm7abd5E4r7a7lX923wbD5Avcjh3I=;
        b=PF1uzFffvDO2ibp3/RUzvZ1UR2oCaDYTVZEYFiOMwiJqK29IMSLG0szGeZnB/Dx9Li
         PNcf8XBF5iPhA76FpClgqgrElImw5V24aKEmy163GaJ66jD5I+P2SYQyynGkPfptHHyy
         hzY0iqujK4XtozUd//hNKqWMuE8PDCE6qA3Hv7Bul4elPrIp8Hi4RjXm3gfIOIUPpc14
         YVqsDT6fRZ5Ot36pwI6bwLix4KvsISsbPgO7H4Eih35mHKh+i0YQbnGXw9ODm/xIVnO7
         xZqvmq7MZ0V3jpG43oXXKScI2MwQ0kDw+CxbhE1kwK1c7Tk2vuTx9PpuI1W3l8LjgYbq
         FEzg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1700505285; x=1701110085;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to
         :in-reply-to:references:message-id:mime-version:subject:date:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=o9G3bku/BdI4vasm7abd5E4r7a7lX923wbD5Avcjh3I=;
        b=IB0mFXOUEpGcbeQ1gvFTZRs9YrSkXmH7BMzr5jBhpQbbilEITpzs/iHmW9Pjce9sOs
         hSUHJhCMeliZl3rIXo94gzMP+WaZOHoLLq78o2LIFxGPiY7NyC2Bsk/7YxUvRbonO2eJ
         b6/AgSma0Wwz7gC+PNIc0ELPUfacq61a6B46cmkbt3GyBMB6Y4sbEDv/acZhVOV81wkc
         6rsVERlLDAC23QAmbOW6bMVx7PfHzA9T2G1iKJlEt6CdY128o5vqztIg+r6F/ul9oIeM
         DZTHmPM9MFZuxrCK8cs57b7KJG+IqzRcXC7cg92H6Js8PbktS9xhlisu5fmkvKWXoVv/
         kNBQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YxOXGVA+juVR0I8UClhoGTs/haifGxzu5ciE1fGXk6tkmXqzIMq
	jiy5TFKoWV16VRQDHFlNW0g=
X-Google-Smtp-Source: AGHT+IEpbRtIN0IKsv0+H/vpgLx/9f3qf+afKphrxiqI0AjfhUwlu4fXcDlyDl7LrLjY6AysaRMP/w==
X-Received: by 2002:ac2:4469:0:b0:509:e5a4:2b03 with SMTP id y9-20020ac24469000000b00509e5a42b03mr6168818lfl.13.1700505284561;
        Mon, 20 Nov 2023 10:34:44 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:b10:b0:50a:68f4:6371 with SMTP id
 w16-20020a0565120b1000b0050a68f46371ls128094lfu.2.-pod-prod-04-eu; Mon, 20
 Nov 2023 10:34:43 -0800 (PST)
X-Received: by 2002:ac2:55b8:0:b0:503:17fd:76bb with SMTP id y24-20020ac255b8000000b0050317fd76bbmr5772095lfg.39.1700505282671;
        Mon, 20 Nov 2023 10:34:42 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1700505282; cv=none;
        d=google.com; s=arc-20160816;
        b=KF0+uQsD/O2CASuShLZrPzSTWHdrXrICsoCqP/qDPZifoOWTROpOpwbaMsPU8IeyxM
         9jpZgwQZgz4hOWZTRgWjCHiNFU/8b1k6JmJ3HEhE/0agYMfi3+W5VykrJjkGUzUmrFHE
         qVUfMDhv8wj4aTnjEzO8uZjrIhk1EvzIVdU8lj9kFz92R4FOYwVSqYVupZP9NC2NVqJr
         iOYqj0lMfDFVxkA2SEskjdeVTJcQOlagbRhBcIkNAi+p0+ISeFhPuqyz5nTNJIjpuYGu
         +HVX/tHN+oJrPlK5j+CAVKBRtHfV73ofaxTewoZSOqQY0yJLrL4cS6tltyoIjIoNtIwh
         92iA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:in-reply-to:references:message-id:content-transfer-encoding
         :mime-version:subject:date:from:dkim-signature:dkim-signature;
        bh=W55q0OyvkcE8yjYUFiHdbA7mtkQVxDvl8PeQMRev8+4=;
        fh=ONqwzSuNvSIo96fWAp0pW54nN9xAdzTfApSlC7LEvRU=;
        b=Wzuk/xiwGwKVeP+gVK+bsdZVIRnVkIeyhl442CGdm1YQKz6gwhyRE0U6w338OVczsR
         Lps5QowDgtTVb7p9cHgWqvSYBmCcYCBigP1IG7kP5BHyB508AOiFpgfQXsW2yqmXB7VR
         NkJygr80ayPrmVICEeS2q4g8A3v1dwJ4dTuu+X/12kiHPsBAXFkGIIKCQIRXj3rpmYSG
         QrPRd1I9vDa+kcD+NBW3veN+S2pVHXYaPeaZn2dP8DIlYCY86oHaZZATQUaX3N5QUJEr
         yev9AH595dJkWnNbOJzaADvAwmMfQ7uhWHoJSQp+HxUKFze1J2VC2/CZmtM8XX33ITDw
         bXlQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=OPvbGApq;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.29 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [195.135.220.29])
        by gmr-mx.google.com with ESMTPS id f41-20020a0565123b2900b0050aa8c18295si213773lfv.5.2023.11.20.10.34.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 20 Nov 2023 10:34:42 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.220.29 as permitted sender) client-ip=195.135.220.29;
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id 126E71F8AE;
	Mon, 20 Nov 2023 18:34:42 +0000 (UTC)
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by imap2.suse-dmz.suse.de (Postfix) with ESMTPS id D5D6C139E9;
	Mon, 20 Nov 2023 18:34:41 +0000 (UTC)
Received: from dovecot-director2.suse.de ([192.168.254.65])
	by imap2.suse-dmz.suse.de with ESMTPSA
	id 6AnBM8GmW2UUMgAAMHmgww
	(envelope-from <vbabka@suse.cz>); Mon, 20 Nov 2023 18:34:41 +0000
From: Vlastimil Babka <vbabka@suse.cz>
Date: Mon, 20 Nov 2023 19:34:22 +0100
Subject: [PATCH v2 11/21] mm/slab: move the rest of slub_def.h to mm/slab.h
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Message-Id: <20231120-slab-remove-slab-v2-11-9c9c70177183@suse.cz>
References: <20231120-slab-remove-slab-v2-0-9c9c70177183@suse.cz>
In-Reply-To: <20231120-slab-remove-slab-v2-0-9c9c70177183@suse.cz>
To: David Rientjes <rientjes@google.com>, Christoph Lameter <cl@linux.com>, 
 Pekka Enberg <penberg@kernel.org>, Joonsoo Kim <iamjoonsoo.kim@lge.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, 
 Hyeonggon Yoo <42.hyeyoo@gmail.com>, 
 Roman Gushchin <roman.gushchin@linux.dev>, 
 Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
 Alexander Potapenko <glider@google.com>, 
 Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
 Vincenzo Frascino <vincenzo.frascino@arm.com>, 
 Marco Elver <elver@google.com>, Johannes Weiner <hannes@cmpxchg.org>, 
 Michal Hocko <mhocko@kernel.org>, Shakeel Butt <shakeelb@google.com>, 
 Muchun Song <muchun.song@linux.dev>, Kees Cook <keescook@chromium.org>, 
 linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
 kasan-dev@googlegroups.com, cgroups@vger.kernel.org, 
 linux-hardening@vger.kernel.org, Vlastimil Babka <vbabka@suse.cz>
X-Mailer: b4 0.12.4
X-Spam-Level: *
X-Spam-Score: 1.30
X-Spamd-Result: default: False [1.30 / 50.00];
	 ARC_NA(0.00)[];
	 RCVD_VIA_SMTP_AUTH(0.00)[];
	 RCVD_TLS_ALL(0.00)[];
	 FROM_HAS_DN(0.00)[];
	 TO_DN_SOME(0.00)[];
	 FREEMAIL_ENVRCPT(0.00)[gmail.com];
	 TO_MATCH_ENVRCPT_ALL(0.00)[];
	 TAGGED_RCPT(0.00)[];
	 MIME_GOOD(-0.10)[text/plain];
	 REPLY(-4.00)[];
	 CLAM_VIRUS_FAIL(0.00)[failed to scan and retransmits exceed];
	 MID_RHS_MATCH_FROM(0.00)[];
	 NEURAL_HAM_LONG(-1.00)[-1.000];
	 R_RATELIMIT(0.00)[to_ip_from(RL563rtnmcmc9sawm86hmgtctc)];
	 BAYES_SPAM(5.10)[100.00%];
	 DKIM_SIGNED(0.00)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	 NEURAL_HAM_SHORT(-0.20)[-1.000];
	 RCPT_COUNT_TWELVE(0.00)[24];
	 FUZZY_BLOCKED(0.00)[rspamd.com];
	 FROM_EQ_ENVFROM(0.00)[];
	 MIME_TRACE(0.00)[0:+];
	 FREEMAIL_CC(0.00)[linux-foundation.org,gmail.com,linux.dev,google.com,arm.com,cmpxchg.org,kernel.org,chromium.org,kvack.org,vger.kernel.org,googlegroups.com,suse.cz];
	 RCVD_COUNT_TWO(0.00)[2];
	 SUSPICIOUS_RECIPS(1.50)[]
X-Spam-Flag: NO
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=OPvbGApq;       dkim=neutral
 (no key) header.i=@suse.cz;       spf=pass (google.com: domain of
 vbabka@suse.cz designates 195.135.220.29 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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

Use this opportunity to fix up some whitespace (alignment) issues.

Reviewed-by: Kees Cook <keescook@chromium.org>
Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
---
 include/linux/slub_def.h | 150 -----------------------------------------------
 mm/slab.h                | 138 ++++++++++++++++++++++++++++++++++++++++++-
 2 files changed, 137 insertions(+), 151 deletions(-)

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
index 014c36ea51fa..3a8d13c099fa 100644
--- a/mm/slab.h
+++ b/mm/slab.h
@@ -209,7 +209,143 @@ static inline size_t slab_size(const struct slab *slab)
 	return PAGE_SIZE << slab_order(slab);
 }
 
-#include <linux/slub_def.h>
+#include <linux/kfence.h>
+#include <linux/kobject.h>
+#include <linux/reciprocal_div.h>
+#include <linux/local_lock.h>
+
+#ifdef CONFIG_SLUB_CPU_PARTIAL
+#define slub_percpu_partial(c)			((c)->partial)
+
+#define slub_set_percpu_partial(c, p)		\
+({						\
+	slub_percpu_partial(c) = (p)->next;	\
+})
+
+#define slub_percpu_partial_read_once(c)	READ_ONCE(slub_percpu_partial(c))
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
+	unsigned int size;		/* Object size including metadata */
+	unsigned int object_size;	/* Object size without metadata */
+	struct reciprocal_value reciprocal_size;
+	unsigned int offset;		/* Free pointer offset */
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
+	gfp_t allocflags;		/* gfp flags to use on each alloc */
+	int refcount;			/* Refcount for slab cache destroy */
+	void (*ctor)(void *object);	/* Object constructor */
+	unsigned int inuse;		/* Offset to metadata */
+	unsigned int align;		/* Alignment */
+	unsigned int red_left_pad;	/* Left redzone padding size */
+	const char *name;		/* Name (only for display!) */
+	struct list_head list;		/* List of slab caches */
+#ifdef CONFIG_SYSFS
+	struct kobject kobj;		/* For sysfs */
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
+				const struct slab *slab, void *x)
+{
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231120-slab-remove-slab-v2-11-9c9c70177183%40suse.cz.
