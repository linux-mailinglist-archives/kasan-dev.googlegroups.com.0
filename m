Return-Path: <kasan-dev+bncBDXYDPH3S4OBBCXLZGVAMGQEJOWBTVI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x337.google.com (mail-wm1-x337.google.com [IPv6:2a00:1450:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id 0282E7EA372
	for <lists+kasan-dev@lfdr.de>; Mon, 13 Nov 2023 20:14:19 +0100 (CET)
Received: by mail-wm1-x337.google.com with SMTP id 5b1f17b1804b1-4084e263ec4sf32927695e9.2
        for <lists+kasan-dev@lfdr.de>; Mon, 13 Nov 2023 11:14:19 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1699902858; cv=pass;
        d=google.com; s=arc-20160816;
        b=rMGHatWc1JctIl/+KhU09HK7TQuv2mBnoCBEHBGcTTYeD5SFWNupAoDfEeZSuig1fC
         I+tefbzhZiJ5Lqasy6SOT3Ff364D/4HHxXpa4I84sFMrbaQUSvxdccTeaxGqe/2I4LEe
         V6kBrJQsRD2vjVd8JiifDtQW2RxlGw1PeE3y7Ow36eU2MqhO2HD8bHMMpOe9E0a3GGyM
         Oo0Pw5J84pQGJCTf6p74B2YOQFvbOAAe24xTB22KWM49rd2y/vBN3sTj7Ew/O7gVSagt
         iIfWgjzsgYlnchGiDLB99mUbxO1iD0RXueLpDQ8s3D8M3XlduUD+Ueh+IEPZKY7PAYw2
         Xeaw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=WG9XUfX5IujjGUqvnm7l0DYEjRPLWMBBOLMJWY7saF8=;
        fh=RPAmrUlnQQdc1FhCirEqyhGh/OnPyRxUfAdj7ygPMx4=;
        b=obYMA1TD7qF9FLxlB6lu9ro9rtlzT7XNPnFARYIRD23yeUlI3QhkdQH6HL/YRDfECJ
         rsHS/9JXeAPjvAZLMf3KXaMy/0+SX8dkQAbpV5dT0zjPyiFVOekgPhLFQohOS+7YxHEN
         Oye9yukKWeZjDS61Uc42krQUl3Dg4NNAZPQtsLOIM1CR9/3iNCT1r4b9p2O55Xhv8qar
         vkAE9eLuPgXpgD7Q3+RVyZZuuSTphHfTMKSiH2vTGfnCpi9c7BiMCCGvlX77RBk14UZv
         e5SWZts805DHfOYbvHAC8FBbkz5mUDNFGd2F620n/5Vcb+D8winmf0gSdqDJZ5efJnET
         ayOg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=MCduxZYm;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.29 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1699902858; x=1700507658; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=WG9XUfX5IujjGUqvnm7l0DYEjRPLWMBBOLMJWY7saF8=;
        b=fqiSp/BT9GhXwhe/Jo3j+p5qAqWN9K0EBk/ddWpYnHk/HiXRO2k2S4c+0dB1QQ1OAG
         T5UzZfNcVt5K+J5rKzOECJkLi272O8IOKrKgvraqhv8hSm2JJWnj9iBmXwPzUn7sa/y6
         Wl4dloqfG9sD2gKb6DYOiUflpwtnUGkTfuDkxNewxU68NtWMxBkNvcyalUyougRBTt6s
         vM5dw9LiqAbpcDohFY5KHxw7qDKAxapLNlchRDFw/+QA8JD2KoTlOsb5HbXTAk/gb93V
         zG7iDEvg+IH8PxfDW4/Jm4lxL5OoDUDEdRmZby/s/ONyo55+/vSV46/MMQgZQqpA9JRj
         DARg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1699902858; x=1700507658;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=WG9XUfX5IujjGUqvnm7l0DYEjRPLWMBBOLMJWY7saF8=;
        b=qBmbXUcOBCw61IUurXxuxx9jVYyogfBkFqlSBNRllnjJpuku+GgVrvmeYK8dEzgVkC
         zWgM9ayd9CPALaYeqVlAWpQXt3lsg9k2S9iu61tR9bxf51laAapPTpGP42CdcCoaGI4n
         8N4pEMsbkgmeQeY4qpVkai9OlX6hT6n2klc17BB+jXdjM/kSerefrqKDNSGqb12kd+Vp
         6QPd4bbebiG2XIDMFsA+DIgVMfVdUlx9Nit1Vf+mZUBIU8gIeoogfm8FXj5Q1YVHqI70
         UAtajKPVqWJYtA5c4hVqh2apwuk/YDkkMc/hYkm6c3fUXU9J6/+ambWdoLIToB5BCqsi
         gd/A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yx6EAPfLTbcNzAN60ZC4kn0L16x3zmsY4R2B6yuyqpxug4XiFPu
	FZOnedd6fwTmwqgdMoCgMUg=
X-Google-Smtp-Source: AGHT+IEMBt0bO8g//6ae7VCLg6MqKzz6vB4C+3Ok7ffJ5l4DBzJuTrzhO7vWYHMyohFnGNrhGK1Fjw==
X-Received: by 2002:a05:600c:1f87:b0:40a:57b3:d006 with SMTP id je7-20020a05600c1f8700b0040a57b3d006mr1879615wmb.22.1699902858331;
        Mon, 13 Nov 2023 11:14:18 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:6024:b0:405:8e:cdfc with SMTP id
 az36-20020a05600c602400b00405008ecdfcls1842247wmb.1.-pod-prod-09-eu; Mon, 13
 Nov 2023 11:14:16 -0800 (PST)
X-Received: by 2002:a05:600c:19cd:b0:405:36a0:108f with SMTP id u13-20020a05600c19cd00b0040536a0108fmr6161647wmq.41.1699902856481;
        Mon, 13 Nov 2023 11:14:16 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1699902856; cv=none;
        d=google.com; s=arc-20160816;
        b=qVs+MhPyA3FtaGuL6fsDwfYhEAt+O4YO1Iu8LBRK7gjVkVjk583pGeYqofjiDTpnoC
         xl/rsMMsN2yb6L9rPX4yHuoy1ZT+7T4fgfb2temsVNlY6VCTaAwRfH3HVJWARsgVF6YB
         7B5KupsO0i45wdK9k10zTcupJs8jv6c8WosHHJ0crbax79PFZkz46K+XuR++Ikf9o6hH
         LHh+feZFfPxQGwID1/q5U9g9O1Or4bZ6yEN9ECdHkrnyuXNse9puum1mDSXgW/xZtqAs
         ksyBHaBkqQFPiDmlg7I6eRCg0EHVVt41pFXKlHjt3MiRPFvo6Edb4bSTrHSeTGCADL2T
         h16Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature:dkim-signature;
        bh=HPRL/KrzqhhRv//jIzaBEKs7IEvhqlXTEPf11LGvT+E=;
        fh=RPAmrUlnQQdc1FhCirEqyhGh/OnPyRxUfAdj7ygPMx4=;
        b=qHZpupXs9vNqPp/uOu7fZqeIzXXyNFXU0vWBwlqPYkPd01GwZamCMV5r7xDix9g2WB
         rWPfS5Eft//73lX7QZcWYhaNElrNueveUvIEezPK7PfjdWmYVc9BaG00UnjAgdl/2fcs
         RBeE1PETXXd8TRCIt7SwIFxTtnyxzVu0i083atqa7IUdBoL6mofTTvX8Fo68+Uja5LZU
         d72lIIuWNu4PrdxY15mW2nTYXqWdSAWMkf+468GS8uq/N6nttxomRePQRdtl3yCRGVbL
         OK3q1Au5H/yWJ6sA9ahBZfvQVeZ0a2987uL9E+ApMBTI8OEfe5JZAbHV6wUFebH7l6Zo
         20vg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=MCduxZYm;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.29 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [195.135.220.29])
        by gmr-mx.google.com with ESMTPS id he5-20020a05600c540500b0040a25ec1cfesi232wmb.0.2023.11.13.11.14.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 13 Nov 2023 11:14:16 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.220.29 as permitted sender) client-ip=195.135.220.29;
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id 237611F88F;
	Mon, 13 Nov 2023 19:14:16 +0000 (UTC)
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by imap2.suse-dmz.suse.de (Postfix) with ESMTPS id C7F5313398;
	Mon, 13 Nov 2023 19:14:15 +0000 (UTC)
Received: from dovecot-director2.suse.de ([192.168.254.65])
	by imap2.suse-dmz.suse.de with ESMTPSA
	id aLpDMId1UmVFOgAAMHmgww
	(envelope-from <vbabka@suse.cz>); Mon, 13 Nov 2023 19:14:15 +0000
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
Subject: [PATCH 20/20] mm/slub: optimize free fast path code layout
Date: Mon, 13 Nov 2023 20:14:01 +0100
Message-ID: <20231113191340.17482-42-vbabka@suse.cz>
X-Mailer: git-send-email 2.42.1
In-Reply-To: <20231113191340.17482-22-vbabka@suse.cz>
References: <20231113191340.17482-22-vbabka@suse.cz>
MIME-Version: 1.0
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=MCduxZYm;       dkim=neutral
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

Inspection of kmem_cache_free() disassembly showed we could make the
fast path smaller by providing few more hints to the compiler, and
splitting the memcg_slab_free_hook() into an inline part that only
checks if there's work to do, and an out of line part doing the actual
uncharge.

bloat-o-meter results:
add/remove: 2/0 grow/shrink: 0/3 up/down: 286/-554 (-268)
Function                                     old     new   delta
__memcg_slab_free_hook                         -     270    +270
__pfx___memcg_slab_free_hook                   -      16     +16
kfree                                        828     665    -163
kmem_cache_free                             1116     948    -168
kmem_cache_free_bulk.part                   1701    1478    -223

Checking kmem_cache_free() disassembly now shows the non-fastpath
cases are handled out of line, which should reduce instruction cache
usage.

Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
---
 mm/slub.c | 40 ++++++++++++++++++++++++----------------
 1 file changed, 24 insertions(+), 16 deletions(-)

diff --git a/mm/slub.c b/mm/slub.c
index 7a40132b717a..ae1e6e635253 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -1959,20 +1959,11 @@ void memcg_slab_post_alloc_hook(struct kmem_cache *s, struct obj_cgroup *objcg,
 	return __memcg_slab_post_alloc_hook(s, objcg, flags, size, p);
 }
 
-static inline void memcg_slab_free_hook(struct kmem_cache *s, struct slab *slab,
-					void **p, int objects)
+static void __memcg_slab_free_hook(struct kmem_cache *s, struct slab *slab,
+				   void **p, int objects,
+				   struct obj_cgroup **objcgs)
 {
-	struct obj_cgroup **objcgs;
-	int i;
-
-	if (!memcg_kmem_online())
-		return;
-
-	objcgs = slab_objcgs(slab);
-	if (!objcgs)
-		return;
-
-	for (i = 0; i < objects; i++) {
+	for (int i = 0; i < objects; i++) {
 		struct obj_cgroup *objcg;
 		unsigned int off;
 
@@ -1988,6 +1979,22 @@ static inline void memcg_slab_free_hook(struct kmem_cache *s, struct slab *slab,
 		obj_cgroup_put(objcg);
 	}
 }
+
+static __fastpath_inline
+void memcg_slab_free_hook(struct kmem_cache *s, struct slab *slab, void **p,
+			  int objects)
+{
+	struct obj_cgroup **objcgs;
+
+	if (!memcg_kmem_online())
+		return;
+
+	objcgs = slab_objcgs(slab);
+	if (likely(!objcgs))
+		return;
+
+	__memcg_slab_free_hook(s, slab, p, objects, objcgs);
+}
 #else /* CONFIG_MEMCG_KMEM */
 static inline struct mem_cgroup *memcg_from_slab_obj(void *ptr)
 {
@@ -2047,7 +2054,7 @@ static __always_inline bool slab_free_hook(struct kmem_cache *s,
 	 * The initialization memset's clear the object and the metadata,
 	 * but don't touch the SLAB redzone.
 	 */
-	if (init) {
+	if (unlikely(init)) {
 		int rsize;
 
 		if (!kasan_has_integrated_init())
@@ -2083,7 +2090,8 @@ static inline bool slab_free_freelist_hook(struct kmem_cache *s,
 		next = get_freepointer(s, object);
 
 		/* If object's reuse doesn't have to be delayed */
-		if (!slab_free_hook(s, object, slab_want_init_on_free(s))) {
+		if (likely(!slab_free_hook(s, object,
+					   slab_want_init_on_free(s)))) {
 			/* Move object to the new freelist */
 			set_freepointer(s, object, *head);
 			*head = object;
@@ -4270,7 +4278,7 @@ static __fastpath_inline void slab_free(struct kmem_cache *s, struct slab *slab,
 	 * With KASAN enabled slab_free_freelist_hook modifies the freelist
 	 * to remove objects, whose reuse must be delayed.
 	 */
-	if (slab_free_freelist_hook(s, &head, &tail, &cnt))
+	if (likely(slab_free_freelist_hook(s, &head, &tail, &cnt)))
 		do_slab_free(s, slab, head, tail, cnt, addr);
 }
 
-- 
2.42.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231113191340.17482-42-vbabka%40suse.cz.
