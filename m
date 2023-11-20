Return-Path: <kasan-dev+bncBDXYDPH3S4OBBQ6N52VAMGQEGGY4CLI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x138.google.com (mail-lf1-x138.google.com [IPv6:2a00:1450:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id 46F687F1C7F
	for <lists+kasan-dev@lfdr.de>; Mon, 20 Nov 2023 19:34:45 +0100 (CET)
Received: by mail-lf1-x138.google.com with SMTP id 2adb3069b0e04-5090b341d6bsf3582658e87.1
        for <lists+kasan-dev@lfdr.de>; Mon, 20 Nov 2023 10:34:45 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1700505284; cv=pass;
        d=google.com; s=arc-20160816;
        b=eE4KrMETSDG9p/sNE/ZrFcJGqJnY6DOw8GdZhzZ/6w7o/bv5sCvDN/weWJ2yp/uX9b
         7sxguetTllE2bqdc6RXeVdw9KsjUX4gs03V84gm/I1yRwpyMBBd842XKbDauOXPgGyxM
         1GKZAH0RVHnnID/pxWfQSFPxoeRGFdLuEBrP4Mql9wHVYZuDdhHhSgbyjiW0P/2UJEjG
         GIFybOdZdz6RaAn7F8AjZtdl4pYK19bf4HVok0leQwMLVul9riWs5NPh25mTJ2U7G1Cu
         3G2W98GNr9cmGtOTiO1qfKIsOHBFg2vv3abBajC5b9gpjeEW/6XLSJ2IixA+CT7pSmPA
         YdaQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:in-reply-to:references
         :message-id:mime-version:subject:date:from:sender:dkim-signature;
        bh=xWYMFrCmHGXTGldE7gRXOX5FJtcEkb4grWH8W+49uG8=;
        fh=ONqwzSuNvSIo96fWAp0pW54nN9xAdzTfApSlC7LEvRU=;
        b=ORu3sfqxgpSSnKAgXmbEJeHUQtxl2fPPOOxfXpF4vjaINhhRx8xUYehvDmzM7cSVpx
         xckpxrEikJae3EXMR0UcSbCE+22NXg8zJShNE6AhJKahGntBYISRff9xErXFl/w2i7CK
         WAQ6jlsdX2zOOD5CkokuDjJEPhnv/QjjOKbOjMm4xHWQMyHWzEdBN0hV+Q7t6uLulm05
         3XZwDiQqmNo5N/qdOmk323o8zDSl9oCsuQKpbIORZMqYMl4T4vDQhIVJ0glgovLF0Joi
         +Hg8ZW/CmEf1nDMkxIcQhdJhn9pZNWBEkSpSCphhC1S5BAiUfP+Ld7NdA2/Pf4eUF+1M
         HonQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=UYk+nbOd;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=q32ZDjRb;
       spf=softfail (google.com: domain of transitioning vbabka@suse.cz does not designate 2001:67c:2178:6::1d as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1700505284; x=1701110084; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:in-reply-to:references:message-id
         :mime-version:subject:date:from:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=xWYMFrCmHGXTGldE7gRXOX5FJtcEkb4grWH8W+49uG8=;
        b=BFW0vw+oeR4kH7cAbH50/RyR84rloRFssD+vuWcBjA1lJgkF3LahQk5KzSOQlqSvUJ
         I8GqFUQI82AlerLQNmVOjgTqgb1Fy+1qMJd9IKqFCMgs/oWBD21z/bXudqO4t/AO9iDz
         2L3OsEYCe+ZC+IzSyxiTR1/pP60Vy3nXn5+5zH4uv+NxxfFGcCLmrA1g7ZA1tvzOmKAC
         VHU9k4m7tsKuuTczdUyUryc2e7ozinun474jdhhPh/JoXeTamUZsO3Xliw0LgHApaqVu
         Uwt7T9IRlvY9rdlWptYPske8KwjN/ar8oI+pfHrcvtJyi1/Cd2YDXInQT4UkrGEN0kJO
         Axbw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1700505284; x=1701110084;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to
         :in-reply-to:references:message-id:mime-version:subject:date:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=xWYMFrCmHGXTGldE7gRXOX5FJtcEkb4grWH8W+49uG8=;
        b=teREzudrflagjZqw3G3S9jysXX3JgAi3IOs/yy1Gj2lzDtmeNPwMDaVqFz9TDIR6sd
         /6A8eKIBXPkNXjD2xEwXj97SxRsx15dEuPlWvqnir118w/3S+lBL0FBi1SNK6qUIlHjp
         uhzCq8m9m9+W73NpGIyD4tuWC7xa8LPtCobEOv42q4FTOOVvT0nIFlJCYT7yctd+luIZ
         aKajKYeQ2mhyIePuWFLzAKmJRm+QrYToNQDZK0JFORs/ft+Ydtsiv4SYDccmyjl869YS
         KCjtqbjE2ETw3iz7DzLqmUxjRbGRU+GWaJuPgt9Ak1WQlEvbgdTeKeZiOy6sPRQS2Igi
         CeqA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YwlN5+k/oGfZ599EnHQEB6gU2CW6HQj8Kr4iDLdQ5z0qw9KtToK
	CtgcMDx8G3MgWvixQjC0EvQ=
X-Google-Smtp-Source: AGHT+IGklubiuZieISwJrJsG6hJMgIgBbDlekrtkozOyAYZ7rrrrEre8yRwjddBHBdN+1uzEY0exKQ==
X-Received: by 2002:a05:6512:b91:b0:50a:aa64:ed2a with SMTP id b17-20020a0565120b9100b0050aaa64ed2amr137763lfv.1.1700505283903;
        Mon, 20 Nov 2023 10:34:43 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:e99:b0:4ff:9bbc:f4b6 with SMTP id
 bi25-20020a0565120e9900b004ff9bbcf4b6ls951606lfb.2.-pod-prod-00-eu; Mon, 20
 Nov 2023 10:34:42 -0800 (PST)
X-Received: by 2002:a05:6512:696:b0:501:ba04:f352 with SMTP id t22-20020a056512069600b00501ba04f352mr122750lfe.1.1700505281857;
        Mon, 20 Nov 2023 10:34:41 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1700505281; cv=none;
        d=google.com; s=arc-20160816;
        b=NtMxjhu+P3B+fvxZILDLx5isTVkZeIZNTlgbbHlV2pj/4DMHWlSUblNdEsVmlS0WDj
         I49be/qS6SNqLsCGYeU5WT3YgWwkzY6xM1wgMiy59kIpwz6hVr1MNNNp9gNtKWE5eVbT
         jRrA7AePQlcBGRXmQQbsgCJIoKBFKyFwyAtzqfmbPPjh8BDZzbR4hVpQUyblb2ykvlqz
         8oWS6ZCIwE8c41an1ueILjXeJxbCEIeEKBw7ZTKcHOdCmqn/F9XJEJt5w5rbftwlH7CP
         +L4i1EPibG43wly60TvJvjMKIF2eDmmlxojV6UoQ9BjQFP6MJdhWRvfb6obPe2+LoYq/
         GS/A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:in-reply-to:references:message-id:content-transfer-encoding
         :mime-version:subject:date:from:dkim-signature:dkim-signature;
        bh=f1ToxzDptD57b6Vsib7GAjPh04DR/y9DB96sNqNT2KE=;
        fh=ONqwzSuNvSIo96fWAp0pW54nN9xAdzTfApSlC7LEvRU=;
        b=SLkDVWz2nvwu+w90KXeMmG2Mitc3nDex0VvYdc0pbPuFyKEBsqLYcI02DYYPrKrAkn
         JChScmMoBdmkmlnYxTdd7oRMOUxYBsLGgd4dF76QNgORLUoQKmrd8n+6FEBljKbHVeqt
         RmAvwAXBXaG/voDjxJhxcwEJcvOqp+bqAmRAfoAdJZLR6u6YW+4bjU77Bez8l63lNfAv
         +kJDaGXcBU7KZV1pQmPiiFcWqcLMw4F/Ald6lX7n0UcdC+9zDi9DBvIX1oJVSwau2a2o
         cmITjjO4NoXcTZz5GhS6V/7/FULgmRaCfX+FMCuHeIsG5Wkrd1J6n1+7hvMmGCpZy0vb
         OqAQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=UYk+nbOd;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=q32ZDjRb;
       spf=softfail (google.com: domain of transitioning vbabka@suse.cz does not designate 2001:67c:2178:6::1d as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [2001:67c:2178:6::1d])
        by gmr-mx.google.com with ESMTPS id k10-20020a0565123d8a00b0050aa9bd7f72si221297lfv.1.2023.11.20.10.34.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 20 Nov 2023 10:34:41 -0800 (PST)
Received-SPF: softfail (google.com: domain of transitioning vbabka@suse.cz does not designate 2001:67c:2178:6::1d as permitted sender) client-ip=2001:67c:2178:6::1d;
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id 2B5711F8A8;
	Mon, 20 Nov 2023 18:34:41 +0000 (UTC)
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by imap2.suse-dmz.suse.de (Postfix) with ESMTPS id ED71413499;
	Mon, 20 Nov 2023 18:34:40 +0000 (UTC)
Received: from dovecot-director2.suse.de ([192.168.254.65])
	by imap2.suse-dmz.suse.de with ESMTPSA
	id mOKCOcCmW2UUMgAAMHmgww
	(envelope-from <vbabka@suse.cz>); Mon, 20 Nov 2023 18:34:40 +0000
From: Vlastimil Babka <vbabka@suse.cz>
Date: Mon, 20 Nov 2023 19:34:18 +0100
Subject: [PATCH v2 07/21] mm/slab: remove CONFIG_SLAB code from slab common
 code
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Message-Id: <20231120-slab-remove-slab-v2-7-9c9c70177183@suse.cz>
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
 header.i=@suse.cz header.s=susede2_rsa header.b=UYk+nbOd;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=q32ZDjRb;
       spf=softfail (google.com: domain of transitioning vbabka@suse.cz does
 not designate 2001:67c:2178:6::1d as permitted sender) smtp.mailfrom=vbabka@suse.cz
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

Reviewed-by: Kees Cook <keescook@chromium.org>
Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
---
 include/linux/slab.h | 14 ++---------
 mm/slab.h            | 69 ++++------------------------------------------------
 mm/slab_common.c     | 22 ++---------------
 3 files changed, 9 insertions(+), 96 deletions(-)

diff --git a/include/linux/slab.h b/include/linux/slab.h
index 34e43cddc520..b2015d0e01ad 100644
--- a/include/linux/slab.h
+++ b/include/linux/slab.h
@@ -24,7 +24,7 @@
 
 /*
  * Flags to pass to kmem_cache_create().
- * The ones marked DEBUG are only valid if CONFIG_DEBUG_SLAB is set.
+ * The ones marked DEBUG need CONFIG_SLUB_DEBUG enabled, otherwise are no-op
  */
 /* DEBUG: Perform (expensive) checks on alloc/free */
 #define SLAB_CONSISTENCY_CHECKS	((slab_flags_t __force)0x00000100U)
@@ -302,25 +302,15 @@ static inline unsigned int arch_slab_minalign(void)
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231120-slab-remove-slab-v2-7-9c9c70177183%40suse.cz.
