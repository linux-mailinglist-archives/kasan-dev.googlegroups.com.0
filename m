Return-Path: <kasan-dev+bncBDXYDPH3S4OBBRON52VAMGQEYH5G65Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x439.google.com (mail-wr1-x439.google.com [IPv6:2a00:1450:4864:20::439])
	by mail.lfdr.de (Postfix) with ESMTPS id 037517F1C82
	for <lists+kasan-dev@lfdr.de>; Mon, 20 Nov 2023 19:34:46 +0100 (CET)
Received: by mail-wr1-x439.google.com with SMTP id ffacd0b85a97d-32f8371247fsf2561262f8f.2
        for <lists+kasan-dev@lfdr.de>; Mon, 20 Nov 2023 10:34:46 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1700505285; cv=pass;
        d=google.com; s=arc-20160816;
        b=bSUFfsiQjF4mqmyqMBQATjFCvrowRH7o25ZslJZT2zhUKlBDd3c2bmata2F38osbic
         s8WJG+agOFsOG0FUolFrFkkQMOk4Oa3yJ9bcdGQ+MTmRxkQAIEazXYHHmWDUX/FLgJ8/
         yAfz4McZHgYJGAALjyXJAdLpRB4LWST2t1x/rT7mhoxIHm1n2I7rId+Lml6Kjz4zT9+S
         0P2isU9TTXakspk5MOQGQoxSth/kdiwnOsPgK29Xmt+vzGSwSJFtPeoxRtNnHO0MT50q
         PYzq77w2RJvln/zSAxPuUvxcpclTqMJfVX4RT9ufWeA+uO7x2PjWvwsvDnRHhVZSg47E
         8Q2A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:in-reply-to:references
         :message-id:mime-version:subject:date:from:sender:dkim-signature;
        bh=vGjZJFuNbgxfaIq7BTsZOLQTkndV4Q7wJX16FkxK2z8=;
        fh=ONqwzSuNvSIo96fWAp0pW54nN9xAdzTfApSlC7LEvRU=;
        b=k6LRdVKgMAeKlt+dppuCj2nuXQ/39TXbD9S/z39ryI26We8cUqnrBs0wADAK/739o+
         OHvGFYYEKVnhs8IaynH7wnFwAyfoMh+EksDuSux320QLIkbDxUgcIXGnVPiHf7Vr5vaC
         UU+Aq8LKKRfgz7ALRv88kkuPjZephlhr0IHGxBnHxegXOyfX0DJYNKx7CKxsGrsvVXPE
         U25yx60ZrqbqDE2bEvURMnLVBSSYIJCzUTXENBRMbO262oph+vjFqdLjdJl7ovTzbaD/
         AJeFpfVfkgBeq1IgqXD6rcuqYl1wefGfn2V3UeWzGBdAqEClar4TsZZ7fKlmGJ9z6cQr
         ih9A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=GurbnCGj;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.29 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1700505285; x=1701110085; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:in-reply-to:references:message-id
         :mime-version:subject:date:from:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=vGjZJFuNbgxfaIq7BTsZOLQTkndV4Q7wJX16FkxK2z8=;
        b=v0+dEpEqHCPdksznAP93tTmuDpX3jSMGdN5hSkGVQbCX7mTrErtl5Po+CsqncD6HSy
         mbTYYOfIkM2f5qR8IyVMzVfbeibH/Z30nveID+/m3iDeUMJTPoB3B34s9mbxrdZzHZo5
         f9JdVAlh4e6T/yEd/POoDdPKJ+H2hCX5xbQQMLobgIbs0gxxEG4PAm6HveAihRlHK0b7
         PhXjlQ8UORspAy3A0QCDHWXZdPKrpyOW8fITdnHhW4QcER/bkl2DoNNkY09Prw3iR1jF
         JGuJXrqcxtnIHbKBJZtFiXoYBXIQ37EaT/Grm+CmQoJw6CUWrUl+rjJb3iSCFfmtmDT7
         pgmg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1700505285; x=1701110085;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to
         :in-reply-to:references:message-id:mime-version:subject:date:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=vGjZJFuNbgxfaIq7BTsZOLQTkndV4Q7wJX16FkxK2z8=;
        b=EZCm7h6K0WJ8+FdHv8YswqskuJ/EZMglhQ29LlzdjKDIm1tmGPnBxohtpB5ZZAaMR9
         QCfHBVcvhDue7DSzPwb5BhObG6QzAwWz6FHSZVaMK/KaY3MUQxVuGwbIbfbAylpiO0Xq
         sHTYTw7spEMUACy1S6GA7EYrAonGwN1MC3DBkbTS2rW+LsGP2mhNS/XtQsojO5HGAIsO
         Flc1SjkhqVZYXvIy95FXmTdRh9UlOhisOQ8LuyQVsNdWj0YrDMkMA7IyaLNzYPpQ9tFD
         GK4B7V2Nl8a6bS/h1ZXm767vN4HJa+mzcebgbINKdu1XfhVH1RL3JsC7+/xxaakJkrLC
         qx9w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YzpYrvrOD+2952QV5lXq9h9ZF5R2g+rQqiKmEDW+xCNDUST1ep4
	ZLftBtRZTWktPAD4vxvcOtM=
X-Google-Smtp-Source: AGHT+IFVNyQBCp8FmkAcoikBvoEZ/b4R5MQ7dasYVrzQryVOrUMMIlnyKcCreLPW+pHcvcLpRusa3A==
X-Received: by 2002:a5d:598e:0:b0:332:ca80:a9ea with SMTP id n14-20020a5d598e000000b00332ca80a9eamr1987289wri.41.1700505285277;
        Mon, 20 Nov 2023 10:34:45 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:fe88:0:b0:323:2285:9258 with SMTP id l8-20020adffe88000000b0032322859258ls51940wrr.2.-pod-prod-02-eu;
 Mon, 20 Nov 2023 10:34:43 -0800 (PST)
X-Received: by 2002:a05:600c:1908:b0:409:1d9a:1ded with SMTP id j8-20020a05600c190800b004091d9a1dedmr7059394wmq.39.1700505283552;
        Mon, 20 Nov 2023 10:34:43 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1700505283; cv=none;
        d=google.com; s=arc-20160816;
        b=nUkQ5Jp29x4+HKE32VW3yVoqd4fDL445mIKjGC6mycryWcgmhi91oznrgyo/FFbOdA
         Y/9QmrfoM58oDmKw8sKDzrbxdEBhWnfF/Y84bpnwoplSDBD34HoHGErKFKhE2r+5dYce
         DDej4BC4fpw6WxQMyXn4DBBiiVbSXXiykZH5ShCGUylXlHpLEYvLUJJTr4x14JP1bB82
         gOFaQwjcSWP+bvTCT5w3zFswo8UcEUn+uwqjoeq/oNzJm0TGRKMEEVSl2xo5lCPRqN0n
         Iz8/okKPJdndS5pXw+u2hpwH4uYgNcVdRx0x5ryHSuzT9uU8yR3QKqRPQNxX5f9N6hg8
         DqTA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:in-reply-to:references:message-id:content-transfer-encoding
         :mime-version:subject:date:from:dkim-signature:dkim-signature;
        bh=0dd/IArvjIRWfQN3Q+n8Y43IiuEYmqtBXkwN7diMKwU=;
        fh=ONqwzSuNvSIo96fWAp0pW54nN9xAdzTfApSlC7LEvRU=;
        b=dkUQi2M4bEyuAUuU5UIqZaT11peOIYjNAW3fyZvjinh0r5IbstZ0+wDDM1B4zm24By
         G0HhFVVvfJhbXPMevEy6uWudmunHzQPOvRFi2cJ4OhV6d9hdOurI2E7gGyMEosO5t98C
         Egs5m15ZVF9mmKftoqFhDd1UWgQ90LLWXw9dOok0nyTlG6SkEug0MpNnMuydDX0hfo8E
         soQru23pvmqljiSmE85a2hrKhjL8mouwE83FSJcI/EGzmDdJ1slFQoA9+t/2t3fW6yu4
         9vAC1jW8iZGHi5n7f6kHCgxMSSuI7nD99VybACKapopMrjnRKKeF9KsDGLTeZvEhwIOd
         xg9Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=GurbnCGj;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.29 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [195.135.220.29])
        by gmr-mx.google.com with ESMTPS id bi24-20020a05600c3d9800b00405c7dd428csi438574wmb.2.2023.11.20.10.34.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 20 Nov 2023 10:34:43 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.220.29 as permitted sender) client-ip=195.135.220.29;
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id 34F561F8C0;
	Mon, 20 Nov 2023 18:34:43 +0000 (UTC)
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by imap2.suse-dmz.suse.de (Postfix) with ESMTPS id F1FA313499;
	Mon, 20 Nov 2023 18:34:42 +0000 (UTC)
Received: from dovecot-director2.suse.de ([192.168.254.65])
	by imap2.suse-dmz.suse.de with ESMTPSA
	id QEOSOsKmW2UUMgAAMHmgww
	(envelope-from <vbabka@suse.cz>); Mon, 20 Nov 2023 18:34:42 +0000
From: Vlastimil Babka <vbabka@suse.cz>
Date: Mon, 20 Nov 2023 19:34:27 +0100
Subject: [PATCH v2 16/21] mm/slab: move kfree() from slab_common.c to
 slub.c
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Message-Id: <20231120-slab-remove-slab-v2-16-9c9c70177183@suse.cz>
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
X-Spam-Level: 
X-Spam-Score: -6.79
X-Spamd-Result: default: False [-6.79 / 50.00];
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
	 DKIM_SIGNED(0.00)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	 NEURAL_HAM_SHORT(-0.20)[-1.000];
	 BAYES_HAM(-2.99)[99.94%];
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
 header.i=@suse.cz header.s=susede2_rsa header.b=GurbnCGj;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519;       spf=pass
 (google.com: domain of vbabka@suse.cz designates 195.135.220.29 as permitted
 sender) smtp.mailfrom=vbabka@suse.cz
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

This should result in better code. Currently kfree() makes a function
call between compilation units to __kmem_cache_free() which does its own
virt_to_slab(), throwing away the struct slab pointer we already had in
kfree(). Now it can be reused. Additionally kfree() can now inline the
whole SLUB freeing fastpath.

Also move over free_large_kmalloc() as the only callsites are now in
slub.c, and make it static.

Reviewed-by: Kees Cook <keescook@chromium.org>
Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
---
 mm/slab.h        |  4 ----
 mm/slab_common.c | 45 ---------------------------------------------
 mm/slub.c        | 51 ++++++++++++++++++++++++++++++++++++++++++++++-----
 3 files changed, 46 insertions(+), 54 deletions(-)

diff --git a/mm/slab.h b/mm/slab.h
index 5ae6a978e9c2..35a55c4a407d 100644
--- a/mm/slab.h
+++ b/mm/slab.h
@@ -395,8 +395,6 @@ struct kmem_cache *kmalloc_slab(size_t size, gfp_t flags, unsigned long caller);
 void *__kmem_cache_alloc_node(struct kmem_cache *s, gfp_t gfpflags,
 			      int node, size_t orig_size,
 			      unsigned long caller);
-void __kmem_cache_free(struct kmem_cache *s, void *x, unsigned long caller);
-
 gfp_t kmalloc_fix_flags(gfp_t flags);
 
 /* Functions provided by the slab allocators */
@@ -559,8 +557,6 @@ static inline int memcg_alloc_slab_cgroups(struct slab *slab,
 }
 #endif /* CONFIG_MEMCG_KMEM */
 
-void free_large_kmalloc(struct folio *folio, void *object);
-
 size_t __ksize(const void *objp);
 
 static inline size_t slab_ksize(const struct kmem_cache *s)
diff --git a/mm/slab_common.c b/mm/slab_common.c
index bbc2e3f061f1..f4f275613d2a 100644
--- a/mm/slab_common.c
+++ b/mm/slab_common.c
@@ -963,22 +963,6 @@ void __init create_kmalloc_caches(slab_flags_t flags)
 	slab_state = UP;
 }
 
-void free_large_kmalloc(struct folio *folio, void *object)
-{
-	unsigned int order = folio_order(folio);
-
-	if (WARN_ON_ONCE(order == 0))
-		pr_warn_once("object pointer: 0x%p\n", object);
-
-	kmemleak_free(object);
-	kasan_kfree_large(object);
-	kmsan_kfree_large(object);
-
-	mod_lruvec_page_state(folio_page(folio, 0), NR_SLAB_UNRECLAIMABLE_B,
-			      -(PAGE_SIZE << order));
-	__free_pages(folio_page(folio, 0), order);
-}
-
 static void *__kmalloc_large_node(size_t size, gfp_t flags, int node);
 static __always_inline
 void *__do_kmalloc_node(size_t size, gfp_t flags, int node, unsigned long caller)
@@ -1023,35 +1007,6 @@ void *__kmalloc_node_track_caller(size_t size, gfp_t flags,
 }
 EXPORT_SYMBOL(__kmalloc_node_track_caller);
 
-/**
- * kfree - free previously allocated memory
- * @object: pointer returned by kmalloc() or kmem_cache_alloc()
- *
- * If @object is NULL, no operation is performed.
- */
-void kfree(const void *object)
-{
-	struct folio *folio;
-	struct slab *slab;
-	struct kmem_cache *s;
-
-	trace_kfree(_RET_IP_, object);
-
-	if (unlikely(ZERO_OR_NULL_PTR(object)))
-		return;
-
-	folio = virt_to_folio(object);
-	if (unlikely(!folio_test_slab(folio))) {
-		free_large_kmalloc(folio, (void *)object);
-		return;
-	}
-
-	slab = folio_slab(folio);
-	s = slab->slab_cache;
-	__kmem_cache_free(s, (void *)object, _RET_IP_);
-}
-EXPORT_SYMBOL(kfree);
-
 /**
  * __ksize -- Report full size of underlying allocation
  * @object: pointer to the object
diff --git a/mm/slub.c b/mm/slub.c
index cc801f8258fe..2baa9e94d9df 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -4197,11 +4197,6 @@ static inline struct kmem_cache *cache_from_obj(struct kmem_cache *s, void *x)
 	return cachep;
 }
 
-void __kmem_cache_free(struct kmem_cache *s, void *x, unsigned long caller)
-{
-	slab_free(s, virt_to_slab(x), x, NULL, &x, 1, caller);
-}
-
 /**
  * kmem_cache_free - Deallocate an object
  * @s: The cache the allocation was from.
@@ -4220,6 +4215,52 @@ void kmem_cache_free(struct kmem_cache *s, void *x)
 }
 EXPORT_SYMBOL(kmem_cache_free);
 
+static void free_large_kmalloc(struct folio *folio, void *object)
+{
+	unsigned int order = folio_order(folio);
+
+	if (WARN_ON_ONCE(order == 0))
+		pr_warn_once("object pointer: 0x%p\n", object);
+
+	kmemleak_free(object);
+	kasan_kfree_large(object);
+	kmsan_kfree_large(object);
+
+	mod_lruvec_page_state(folio_page(folio, 0), NR_SLAB_UNRECLAIMABLE_B,
+			      -(PAGE_SIZE << order));
+	__free_pages(folio_page(folio, 0), order);
+}
+
+/**
+ * kfree - free previously allocated memory
+ * @object: pointer returned by kmalloc() or kmem_cache_alloc()
+ *
+ * If @object is NULL, no operation is performed.
+ */
+void kfree(const void *object)
+{
+	struct folio *folio;
+	struct slab *slab;
+	struct kmem_cache *s;
+	void *x = (void *)object;
+
+	trace_kfree(_RET_IP_, object);
+
+	if (unlikely(ZERO_OR_NULL_PTR(object)))
+		return;
+
+	folio = virt_to_folio(object);
+	if (unlikely(!folio_test_slab(folio))) {
+		free_large_kmalloc(folio, (void *)object);
+		return;
+	}
+
+	slab = folio_slab(folio);
+	s = slab->slab_cache;
+	slab_free(s, slab, x, NULL, &x, 1, _RET_IP_);
+}
+EXPORT_SYMBOL(kfree);
+
 struct detached_freelist {
 	struct slab *slab;
 	void *tail;

-- 
2.42.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231120-slab-remove-slab-v2-16-9c9c70177183%40suse.cz.
