Return-Path: <kasan-dev+bncBDXYDPH3S4OBBCHLZGVAMGQE6N3PIAI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53a.google.com (mail-ed1-x53a.google.com [IPv6:2a00:1450:4864:20::53a])
	by mail.lfdr.de (Postfix) with ESMTPS id B2EDF7EA36E
	for <lists+kasan-dev@lfdr.de>; Mon, 13 Nov 2023 20:14:17 +0100 (CET)
Received: by mail-ed1-x53a.google.com with SMTP id 4fb4d7f45d1cf-54366567af4sf5494457a12.1
        for <lists+kasan-dev@lfdr.de>; Mon, 13 Nov 2023 11:14:17 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1699902857; cv=pass;
        d=google.com; s=arc-20160816;
        b=Z3aKHf04XNC6mGYr/5aqZyYjL/AsIxi0u3lX0+DMjND7hcNO5ss4JfkVNY0attSWkY
         w3wRnZGVhIyDamDSIUBSYG5zVLk3Suipa+vLEhcWF+QAyvXVmwizJqVLK9hgsjcmcVzm
         Ut/wg/rzuVA5/uLPpJtcwwe5CP45pFnaGG5FJH8C2eZkm7smvsIB3HT+9xIrbf6v1hHy
         MxI/549bOeqkWOv38X8L9bC1Pb0Yub8rmhgb68jDFJdOFl//LVvyrsEp1lXn+uokhgTr
         R2uRDEJY3q4SUF6Q52p8oq+WgmzgIak7kWDprSWwgHxN/VCP9108u4jzPrqzaPN9EKhd
         d4Sg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=xUwugJfvDVPVjdKwRhjyS62Wo+BUkEO7UD3I2dQzZDU=;
        fh=RPAmrUlnQQdc1FhCirEqyhGh/OnPyRxUfAdj7ygPMx4=;
        b=VxdBUgQR/Rumd50TlqYBUVkW0fRIzPk4gWBAjS0DmjLSwWpy7lqYZCmFFo3UAz8Ecb
         1VejbqpKtlFHffZlMuUv+4lDdreZpI0GZjC+vpNCJGdJSb6dURrxuhxDDRZ4/KTo7f6e
         J8/syKllqrAnCZ2taCRJrTtIKR7fno3GY9VDpTaITzGGDh5Kyg78udiLGg1dTeLYYFnj
         eD7oggnAKGMK6Vc771QahkUw4USUfZ0rKtYKIZx6e/1RCTG7J3s/mh/eE7F02tYD7+E2
         aqzfOZCLlmiWnSrU8ODDLqGIgJJQyWW0bG1AJCdrCZRdfflNMFXROUbJz15pCKsjgRUu
         lSdA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=oIHlLgRj;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.29 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1699902857; x=1700507657; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=xUwugJfvDVPVjdKwRhjyS62Wo+BUkEO7UD3I2dQzZDU=;
        b=FuTWji240o6655O1IcvPruBeuxW2BvFKJSUH/3CpiJAlyjn6KaLhDAOIjIaqCfl48U
         XeLJ6UU+0eZm08TVMfGTsv7MYRIA5PfKVq4nsXNnCWYaZPz/OMMwCi0PUoqVeSWUpu4b
         sK8I546vYv5p2H9jLtt06/z+DAU0Dxj2OMLHN+bpLJNGaVT9hwyoche4e84qABJYavDL
         5OIVybNPwN7DMiehUMczbnv5GjUEsiJW4YBytCFm4vZC7o1eX4pIq7Y/zgPkdaBnxrdU
         v7169vmkQUbDaRVTZ6kDj5lZE4CD8VVDcKLc6HGpc6Ix2Iitp3mCbUH84wU45IHag8OX
         78cg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1699902857; x=1700507657;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=xUwugJfvDVPVjdKwRhjyS62Wo+BUkEO7UD3I2dQzZDU=;
        b=N/By8IOls0jKepG6DnQGf5UsOnd+9CjnEZNsi4oLgJqmP85a6Tf8yczhtSo2zoc3pP
         6OrfpvSXnImROqaLuNacg/VwxRab/jZz7IxxkHmncsNtsH2BFn9te40YKYjmdDaAnsDU
         iKSa0EsQYBEGdEwmpa1zf+/IdSumdqPRuPOw6hotPWAwre72ya7jfc2R5yPF5pEHeJ1M
         0zUcjtptNVSKxQZjXdrlibQiCh174xfLf9SW9db9JxeetvD2onBDUWNlgK3TGm0Op0M5
         rjSSHC4erGg5o/FiG6Mv0EZ+iKbMAgox7ipf7XeIlMe5tyq1YJqq0madWcgm9rVJGnZp
         7QMA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yw83bb09g4VPqN+/lA64a7M9bnlR2CfDin+0tnU0Nw0RQ0srvM/
	qE9FVl8ul59tw9iB14vh5g8=
X-Google-Smtp-Source: AGHT+IEzVW55pXaeJ3240laKixUaeGn7SxeoiNKwU/wFnEwmQIECuBJjsr+UYTfRnqHmsPnYKudUGg==
X-Received: by 2002:a05:6402:42d1:b0:534:6b86:eda2 with SMTP id i17-20020a05640242d100b005346b86eda2mr360851edc.21.1699902856895;
        Mon, 13 Nov 2023 11:14:16 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:c4e:b0:547:2571:d5ae with SMTP id
 cs14-20020a0564020c4e00b005472571d5aels522482edb.1.-pod-prod-00-eu; Mon, 13
 Nov 2023 11:14:15 -0800 (PST)
X-Received: by 2002:a05:6402:3547:b0:52e:3ce8:e333 with SMTP id f7-20020a056402354700b0052e3ce8e333mr418975edd.18.1699902855087;
        Mon, 13 Nov 2023 11:14:15 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1699902855; cv=none;
        d=google.com; s=arc-20160816;
        b=ufUWZGnJYvNYHbpf3SMez4TsYXwn1HqtJnqFxPBlufFsd9YrhIR0w/zCdJrzchjDyS
         SS6aH0VZcbbU1UG6/4y/iJiOC74BhfbAKkCVVsRUxYHepuVTL+lRkwu4lqfv9+y+m6tJ
         BWJaJSem4vOQePX9BYIpm3auE8qExGI1wXzlWDz3ZkgF9vBg0HzG9oK4yMSZLBhhLM0P
         xM+qAaHGfNGyi4ni7Me+N+SNVbUtrNzVhfy57SehYA481SaEpkNlXdtvymDmGIjWq7Vb
         DS1AimNpcOk4K/bLqbIDALcA7AZ4apQoEYW///x49zm2WV1iM8rpfBkGptCa6QpK6pWr
         2wSA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature:dkim-signature;
        bh=AvYULxpvTpi0KZyzNL3YX1bvF9SuuOz0+MetYRBUoJQ=;
        fh=RPAmrUlnQQdc1FhCirEqyhGh/OnPyRxUfAdj7ygPMx4=;
        b=DZLZ5mHPN6AhoHdV1ig6G27FSGhep1YwU2Oqx1MgRTbomoT+aEpWmfLlobzeeorvv/
         39GREqH2w3WvOIwAQMucnE5SVyhUScnQhlO3mKnDrga+4r1vXJh3vy46aClmUuePASqf
         Ix7yAJ51sXjShgj6k1wnr+hv17mAE4qNZZtdp5t6IN55PB69c5DMBFMgskqI8tvhD190
         93PvlJUIXn2OZEU+CAoXKVOTNKRcRgiCC4zqodtt7W0AzmYH6LJIkhbQ/fLqJD8Dk2CN
         dl5xWTYkIwPiNwaiP0k+ihhaT61Z9Ll/JBdBq28rDj3nUhvjHTTkbadET+9DVYbqz+se
         n/Cw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=oIHlLgRj;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.29 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [195.135.220.29])
        by gmr-mx.google.com with ESMTPS id g36-20020a056402322400b005457f8a07e6si225791eda.4.2023.11.13.11.14.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 13 Nov 2023 11:14:15 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.220.29 as permitted sender) client-ip=195.135.220.29;
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id E153B1F88E;
	Mon, 13 Nov 2023 19:14:14 +0000 (UTC)
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by imap2.suse-dmz.suse.de (Postfix) with ESMTPS id 9CF6613398;
	Mon, 13 Nov 2023 19:14:14 +0000 (UTC)
Received: from dovecot-director2.suse.de ([192.168.254.65])
	by imap2.suse-dmz.suse.de with ESMTPSA
	id sLfCJYZ1UmVFOgAAMHmgww
	(envelope-from <vbabka@suse.cz>); Mon, 13 Nov 2023 19:14:14 +0000
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
Subject: [PATCH 16/20] mm/slab: move kmalloc_slab() to mm/slab.h
Date: Mon, 13 Nov 2023 20:13:57 +0100
Message-ID: <20231113191340.17482-38-vbabka@suse.cz>
X-Mailer: git-send-email 2.42.1
In-Reply-To: <20231113191340.17482-22-vbabka@suse.cz>
References: <20231113191340.17482-22-vbabka@suse.cz>
MIME-Version: 1.0
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=oIHlLgRj;       dkim=neutral
 (no key) header.i=@suse.cz;       spf=pass (google.com: domain of
 vbabka@suse.cz designates 195.135.220.29 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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

In preparation for the next patch, move the kmalloc_slab() function to
the header, as it will have callers from two files, and make it inline.
To avoid unnecessary bloat, remove all size checks/warnings from
kmalloc_slab() as they just duplicate those in callers, especially after
recent changes to kmalloc_size_roundup(). We just need to adjust handling
of zero size in __do_kmalloc_node(). Also we can stop handling NULL
result from kmalloc_slab() there as that now cannot happen (unless
called too early during boot).

The size_index array becomes visible so rename it to a more specific
kmalloc_size_index.

Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
---
 mm/slab.h        | 28 ++++++++++++++++++++++++++--
 mm/slab_common.c | 43 ++++++++-----------------------------------
 2 files changed, 34 insertions(+), 37 deletions(-)

diff --git a/mm/slab.h b/mm/slab.h
index 179467e8aacc..744384efa7be 100644
--- a/mm/slab.h
+++ b/mm/slab.h
@@ -388,8 +388,32 @@ extern const struct kmalloc_info_struct {
 void setup_kmalloc_cache_index_table(void);
 void create_kmalloc_caches(slab_flags_t);
 
-/* Find the kmalloc slab corresponding for a certain size */
-struct kmem_cache *kmalloc_slab(size_t size, gfp_t flags, unsigned long caller);
+extern u8 kmalloc_size_index[24];
+
+static inline unsigned int size_index_elem(unsigned int bytes)
+{
+	return (bytes - 1) / 8;
+}
+
+/*
+ * Find the kmem_cache structure that serves a given size of
+ * allocation
+ *
+ * This assumes size is larger than zero and not larger than
+ * KMALLOC_MAX_CACHE_SIZE and the caller must check that.
+ */
+static inline struct kmem_cache *
+kmalloc_slab(size_t size, gfp_t flags, unsigned long caller)
+{
+	unsigned int index;
+
+	if (size <= 192)
+		index = kmalloc_size_index[size_index_elem(size)];
+	else
+		index = fls(size - 1);
+
+	return kmalloc_caches[kmalloc_type(flags, caller)][index];
+}
 
 void *__kmem_cache_alloc_node(struct kmem_cache *s, gfp_t gfpflags,
 			      int node, size_t orig_size,
diff --git a/mm/slab_common.c b/mm/slab_common.c
index f4f275613d2a..31ade17a7ad9 100644
--- a/mm/slab_common.c
+++ b/mm/slab_common.c
@@ -665,7 +665,7 @@ EXPORT_SYMBOL(random_kmalloc_seed);
  * of two cache sizes there. The size of larger slabs can be determined using
  * fls.
  */
-static u8 size_index[24] __ro_after_init = {
+u8 kmalloc_size_index[24] __ro_after_init = {
 	3,	/* 8 */
 	4,	/* 16 */
 	5,	/* 24 */
@@ -692,33 +692,6 @@ static u8 size_index[24] __ro_after_init = {
 	2	/* 192 */
 };
 
-static inline unsigned int size_index_elem(unsigned int bytes)
-{
-	return (bytes - 1) / 8;
-}
-
-/*
- * Find the kmem_cache structure that serves a given size of
- * allocation
- */
-struct kmem_cache *kmalloc_slab(size_t size, gfp_t flags, unsigned long caller)
-{
-	unsigned int index;
-
-	if (size <= 192) {
-		if (!size)
-			return ZERO_SIZE_PTR;
-
-		index = size_index[size_index_elem(size)];
-	} else {
-		if (WARN_ON_ONCE(size > KMALLOC_MAX_CACHE_SIZE))
-			return NULL;
-		index = fls(size - 1);
-	}
-
-	return kmalloc_caches[kmalloc_type(flags, caller)][index];
-}
-
 size_t kmalloc_size_roundup(size_t size)
 {
 	if (size && size <= KMALLOC_MAX_CACHE_SIZE) {
@@ -843,9 +816,9 @@ void __init setup_kmalloc_cache_index_table(void)
 	for (i = 8; i < KMALLOC_MIN_SIZE; i += 8) {
 		unsigned int elem = size_index_elem(i);
 
-		if (elem >= ARRAY_SIZE(size_index))
+		if (elem >= ARRAY_SIZE(kmalloc_size_index))
 			break;
-		size_index[elem] = KMALLOC_SHIFT_LOW;
+		kmalloc_size_index[elem] = KMALLOC_SHIFT_LOW;
 	}
 
 	if (KMALLOC_MIN_SIZE >= 64) {
@@ -854,7 +827,7 @@ void __init setup_kmalloc_cache_index_table(void)
 		 * is 64 byte.
 		 */
 		for (i = 64 + 8; i <= 96; i += 8)
-			size_index[size_index_elem(i)] = 7;
+			kmalloc_size_index[size_index_elem(i)] = 7;
 
 	}
 
@@ -865,7 +838,7 @@ void __init setup_kmalloc_cache_index_table(void)
 		 * instead.
 		 */
 		for (i = 128 + 8; i <= 192; i += 8)
-			size_index[size_index_elem(i)] = 8;
+			kmalloc_size_index[size_index_elem(i)] = 8;
 	}
 }
 
@@ -977,10 +950,10 @@ void *__do_kmalloc_node(size_t size, gfp_t flags, int node, unsigned long caller
 		return ret;
 	}
 
-	s = kmalloc_slab(size, flags, caller);
+	if (unlikely(!size))
+		return ZERO_SIZE_PTR;
 
-	if (unlikely(ZERO_OR_NULL_PTR(s)))
-		return s;
+	s = kmalloc_slab(size, flags, caller);
 
 	ret = __kmem_cache_alloc_node(s, flags, node, size, caller);
 	ret = kasan_kmalloc(s, ret, size, flags);
-- 
2.42.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231113191340.17482-38-vbabka%40suse.cz.
