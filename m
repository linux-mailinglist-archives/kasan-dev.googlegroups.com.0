Return-Path: <kasan-dev+bncBDXYDPH3S4OBBSXG5DDQMGQE5Y75WUQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x339.google.com (mail-wm1-x339.google.com [IPv6:2a00:1450:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id 15981C018E2
	for <lists+kasan-dev@lfdr.de>; Thu, 23 Oct 2025 15:53:16 +0200 (CEST)
Received: by mail-wm1-x339.google.com with SMTP id 5b1f17b1804b1-471125c8bc1sf11909685e9.3
        for <lists+kasan-dev@lfdr.de>; Thu, 23 Oct 2025 06:53:16 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1761227595; cv=pass;
        d=google.com; s=arc-20240605;
        b=jX80mA48ljBgKlrJ3EzmWrCLzNyDi6LUqQAbmN+XK40m1e4V7ya6kAKfoIimjR6px0
         lZba8hz22zWwGBAyfVMGUJ5FzD8RYsH+1JJHDXdexFXW9ed4v41k+x8hYzxqwqHSltg7
         HTNEm55kkc59Py/b25UPq3T/wm6ANpXB+SlPyRROLHyQM5VfLEgfd1Qar5UW1utMQJfL
         TO52JEAd6LhJcyL/6vHY+mtOinfleHVeyuyNX3V2vOmT/cwidZDZE0mWqYWlFMSbyX5c
         ktl7PeYgn+RcylFOdCBgcpLataFWcWmPTzuwKCswnN5X0zHXz4hfgvB7FCxVEzn1vibl
         YJPQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:in-reply-to:references
         :message-id:mime-version:subject:date:from:sender:dkim-signature;
        bh=KjxYrpzNeuNswqz2piEzdZnaI0bCdPfOLtI5zIC9Jkk=;
        fh=gb1fk31OALMavH7iPvecUO77MK4TRVq4g+eST6V2yxA=;
        b=Si+B3AOOZots+ULBf++gwOWPvhZhUqBw9ZHmcEl4OtSy6lx/QlWW4Rbs7ThncyQYXm
         Om2aMWGU4/YkQKWEAPc3bcF4+fDZp0hUBirJdQX9nPlNGnRTRMRlWtNDMDg9jcP265I4
         UWGUSajrQ7OihXL8VOmqnZb0qtARmUmrK1t/aYHwodC1xKlhBjigmaE3EoOQDXkxtn6q
         t9rM7L7A0adq8TSo7YwekSsj4BUc3z0/bZel0+yR4C7HtPnm5xWdqxSPWLuH5Yoy7/mr
         4elZ3ecfNl86pFypouJsc4V2oYBq0WLieJxsFuZX2z9Bs03h1W20g15lCC5+HyGHUAPX
         CgYw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=wqZuf521;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=CnYeHNMj;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=cByGnC2S;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=YD2XioWV;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1761227595; x=1761832395; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:in-reply-to:references:message-id
         :mime-version:subject:date:from:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=KjxYrpzNeuNswqz2piEzdZnaI0bCdPfOLtI5zIC9Jkk=;
        b=GEAJQkHYAiQusaiO3xj+Ug5VJf0T1z3sYPoKhiXNWaCkwWsnFfBj7JKuvYkzARkt1K
         D7m/+oyBQKWcydv1Isxvi197mA+tbf9IUUpccm9DTWArJsmmqMOuzWSi9oFP91NHcJJc
         HhhWXwARg0DfDbB5jKByi54NuDvtu0MselS4SkWe+eoe7WJpEwQQvO+CIOlPmZL5JOUT
         EpOhrBNApnYXAOfTRirJGAZyu4fZjNys9L4DxD12AeXiBkjtMZW9XE/+PS8tPawSRhOY
         TDoJNzY7FqBgWokaFzThvhFv2CB2Z18el24tQM/Qpt9DMlf1S5rJsdJs9ZE+IsVWWsS9
         16Sw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1761227595; x=1761832395;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to
         :in-reply-to:references:message-id:mime-version:subject:date:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=KjxYrpzNeuNswqz2piEzdZnaI0bCdPfOLtI5zIC9Jkk=;
        b=pLlGYTQOcZeEfUJXK34ol5KYXP3eGv7VRbfUAQsgiC4KhY+/ini4XuthJ5dd0+ewnb
         71kAUFsdCIP1YmkMyT+y9xjZ1xA5ir6uRleoKURM1vQtAeo1I5NsoYeZNFLoPixmcf+z
         AmVHcq3W5jQzcNdz4dYg+QropdmG6BFLTfzSZwD7rGshVacHnYSXAUpbDj0Or2DyAxZg
         p7TzgfZ+4E8QyIws6rQvkWuB8yOy9KquCgWNsUb23MmOegMxGX/wZRneyuqJPpm/dHOC
         QL7/0CfMtYcr9JUqcuFX6Rj1lgTnmZb8S3u/ofkMPaRfCLL+b+PAy0lHjQdI4pkb5qSA
         da7A==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCX2rrDxGcVO+ZU1yytmNtM6UQUNw4hLLxE4eS7zGRH1QSNKluNq+MYdtVOoaSMwrohfDiqQzA==@lfdr.de
X-Gm-Message-State: AOJu0Yzmff4bv7SuKHEa4hQ4rL7qykSL0msIEYXTo7sjAPsWGVQ23DUX
	JK4/xT7CrIkB2FFpBVDsELIbDpPT4GPI+KbXZkqSg7gMcgwfoChJNoTx
X-Google-Smtp-Source: AGHT+IFit05c+HyeS4biV9Dd1THVQlh8EaniQ+8Jc8Q2ZNmbfWKUFJApHaTPo7KLjFcQGL4DtTpIng==
X-Received: by 2002:a05:600c:820b:b0:471:1717:40a with SMTP id 5b1f17b1804b1-471178a8245mr173632715e9.18.1761227595365;
        Thu, 23 Oct 2025 06:53:15 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="ARHlJd60VpnJL5y9yDFrubJ+g28BF8+4fyAVGx+fvD2zVdTUXA=="
Received: by 2002:a05:600d:15a:10b0:46e:2f7f:7b52 with SMTP id
 5b1f17b1804b1-475ca903db6ls3165065e9.0.-pod-prod-07-eu; Thu, 23 Oct 2025
 06:53:12 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUDZuWi+JJ6qWISGeeMOCu51Hj+kMeT606bhTbu8YdvoKGfpzCimdt40uRrXPMyTZP9la11HAeP0Pw=@googlegroups.com
X-Received: by 2002:a05:600c:3b03:b0:471:15df:9fc7 with SMTP id 5b1f17b1804b1-47117906a72mr171106825e9.26.1761227592396;
        Thu, 23 Oct 2025 06:53:12 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1761227592; cv=none;
        d=google.com; s=arc-20240605;
        b=HIbJXRoJ8F0pIV7Pz/BhK9Ysei0icz7cIusDmA17U3eAjN9djFRmYw5l4mQ9neML3t
         TioGHVUyHFKdrnlmWDHrP2d3JKsmILKKrUZymQrUhr3hcZ6QnSViKaKAU4CsuFMu3WRp
         9r+IyQlZrPfGuhIevT9vfYKpszWde4FRn6M1uby571xULHa2kkAMBBNTgvvD8/Q6wmTL
         0BBxd77P9JFVTobqlhvO9iiysgfwHtbN9lyudQH6sWYa8aDlf10aEW8y1Akx4qZbK6cd
         uTu/vcTAP9UzL3hp008WxcWAanyJq6MqJxwQXQkZC6TEY70u4mydPciTvucTi5fDZlQy
         dA1w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:in-reply-to:references:message-id:content-transfer-encoding
         :mime-version:subject:date:from:dkim-signature:dkim-signature
         :dkim-signature:dkim-signature;
        bh=fdXDD3/ZApJgGZ00uKWLh+CAcEIa/UY+x34vKoVNPc8=;
        fh=P0r4/dMJvcdpdyMOyJR1abGuGu+lkksl0rleFR28jng=;
        b=AlSHdVcTUMj7y8O3q+GsmRpU+yUX8v6p5Mk0pQOrrsEJJOG6KeuC31gEd0HFB6Hv0z
         4e4yCKI9RWmIZ+vb9vTFB0B37VfWrQb+qXRav1kipBpT2YygJW6yvOQ6IYldAR690NP2
         mm3N7Hahv7RvtyrZkRQq0buZm3+UN3viRTb7ogil/AmGNeH+YTw1OaBLIEi60VMSQgJN
         OWAi0NRodsk2F4calWlp6elyLScNRCncUNObm1qFhH8bWRtTQ0qaQzGJ0ycrQlyb8Hts
         Ho9zoxiO0Dv4inFIiEaAHPVubpvJjd6iKXOjFkC0q4UwLKtaFnEACqkPnPN3cT2jL5MX
         wofQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=wqZuf521;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=CnYeHNMj;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=cByGnC2S;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=YD2XioWV;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [2a07:de40:b251:101:10:150:64:2])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-47496b28e1esi1771205e9.2.2025.10.23.06.53.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 23 Oct 2025 06:53:12 -0700 (PDT)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) client-ip=2a07:de40:b251:101:10:150:64:2;
Received: from imap1.dmz-prg2.suse.org (unknown [10.150.64.97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id 5A2011F7E2;
	Thu, 23 Oct 2025 13:52:53 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 3099A13AAB;
	Thu, 23 Oct 2025 13:52:53 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id yIGWCzUz+mjvQQAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Thu, 23 Oct 2025 13:52:53 +0000
From: Vlastimil Babka <vbabka@suse.cz>
Date: Thu, 23 Oct 2025 15:52:24 +0200
Subject: [PATCH RFC 02/19] slab: handle pfmemalloc slabs properly with
 sheaves
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Message-Id: <20251023-sheaves-for-all-v1-2-6ffa2c9941c0@suse.cz>
References: <20251023-sheaves-for-all-v1-0-6ffa2c9941c0@suse.cz>
In-Reply-To: <20251023-sheaves-for-all-v1-0-6ffa2c9941c0@suse.cz>
To: Andrew Morton <akpm@linux-foundation.org>, 
 Christoph Lameter <cl@gentwo.org>, David Rientjes <rientjes@google.com>, 
 Roman Gushchin <roman.gushchin@linux.dev>, Harry Yoo <harry.yoo@oracle.com>
Cc: Uladzislau Rezki <urezki@gmail.com>, 
 "Liam R. Howlett" <Liam.Howlett@oracle.com>, 
 Suren Baghdasaryan <surenb@google.com>, 
 Sebastian Andrzej Siewior <bigeasy@linutronix.de>, 
 Alexei Starovoitov <ast@kernel.org>, linux-mm@kvack.org, 
 linux-kernel@vger.kernel.org, linux-rt-devel@lists.linux.dev, 
 bpf@vger.kernel.org, kasan-dev@googlegroups.com, 
 Vlastimil Babka <vbabka@suse.cz>
X-Mailer: b4 0.14.3
X-Spam-Level: 
X-Spamd-Result: default: False [-8.30 / 50.00];
	REPLY(-4.00)[];
	BAYES_HAM(-3.00)[100.00%];
	NEURAL_HAM_LONG(-1.00)[-1.000];
	NEURAL_HAM_SHORT(-0.20)[-1.000];
	MIME_GOOD(-0.10)[text/plain];
	RCVD_TLS_ALL(0.00)[];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	MIME_TRACE(0.00)[0:+];
	TO_DN_SOME(0.00)[];
	RCPT_COUNT_TWELVE(0.00)[16];
	ARC_NA(0.00)[];
	MID_RHS_MATCH_FROM(0.00)[];
	FREEMAIL_ENVRCPT(0.00)[gmail.com];
	DKIM_SIGNED(0.00)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	FROM_HAS_DN(0.00)[];
	FREEMAIL_CC(0.00)[gmail.com,oracle.com,google.com,linutronix.de,kernel.org,kvack.org,vger.kernel.org,lists.linux.dev,googlegroups.com,suse.cz];
	R_RATELIMIT(0.00)[to_ip_from(RLwn5r54y1cp81no5tmbbew5oc)];
	FROM_EQ_ENVFROM(0.00)[];
	RCVD_COUNT_TWO(0.00)[2];
	TO_MATCH_ENVRCPT_ALL(0.00)[];
	DBL_BLOCKED_OPENRESOLVER(0.00)[suse.cz:email,suse.cz:mid,imap1.dmz-prg2.suse.org:helo]
X-Spam-Flag: NO
X-Spam-Score: -8.30
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=wqZuf521;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=CnYeHNMj;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=cByGnC2S;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519
 header.b=YD2XioWV;       spf=pass (google.com: domain of vbabka@suse.cz
 designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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

When a pfmemalloc allocation actually dips into reserves, the slab is
marked accordingly and non-pfmemalloc allocations should not be allowed
to allocate from it. The sheaves percpu caching currently doesn't follow
this rule, so implement it before we expand sheaves usage to all caches.

Make sure objects from pfmemalloc slabs don't end up in percpu sheaves.
When freeing, skip sheaves when freeing an object from pfmemalloc slab.
When refilling sheaves, use __GFP_NOMEMALLOC to override any pfmemalloc
context - the allocation will fallback to regular slab allocations when
sheaves are depleted and can't be refilled because of the override.

For kfree_rcu(), detect pfmemalloc slabs after processing the rcu_sheaf
after the grace period in __rcu_free_sheaf_prepare() and simply flush
it if any object is from pfmemalloc slabs.

For prefilled sheaves, try to refill them first with __GFP_NOMEMALLOC
and if it fails, retry without __GFP_NOMEMALLOC but then mark the sheaf
pfmemalloc, which makes it flushed back to slabs when returned.

Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
---
 mm/slub.c | 65 +++++++++++++++++++++++++++++++++++++++++++++++++--------------
 1 file changed, 51 insertions(+), 14 deletions(-)

diff --git a/mm/slub.c b/mm/slub.c
index 4731b9e461c2..ab03f29dc3bf 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -469,7 +469,10 @@ struct slab_sheaf {
 		struct rcu_head rcu_head;
 		struct list_head barn_list;
 		/* only used for prefilled sheafs */
-		unsigned int capacity;
+		struct {
+			unsigned int capacity;
+			bool pfmemalloc;
+		};
 	};
 	struct kmem_cache *cache;
 	unsigned int size;
@@ -2645,7 +2648,7 @@ static struct slab_sheaf *alloc_full_sheaf(struct kmem_cache *s, gfp_t gfp)
 	if (!sheaf)
 		return NULL;
 
-	if (refill_sheaf(s, sheaf, gfp)) {
+	if (refill_sheaf(s, sheaf, gfp | __GFP_NOMEMALLOC)) {
 		free_empty_sheaf(s, sheaf);
 		return NULL;
 	}
@@ -2723,12 +2726,13 @@ static void sheaf_flush_unused(struct kmem_cache *s, struct slab_sheaf *sheaf)
 	sheaf->size = 0;
 }
 
-static void __rcu_free_sheaf_prepare(struct kmem_cache *s,
+static bool __rcu_free_sheaf_prepare(struct kmem_cache *s,
 				     struct slab_sheaf *sheaf)
 {
 	bool init = slab_want_init_on_free(s);
 	void **p = &sheaf->objects[0];
 	unsigned int i = 0;
+	bool pfmemalloc = false;
 
 	while (i < sheaf->size) {
 		struct slab *slab = virt_to_slab(p[i]);
@@ -2741,8 +2745,13 @@ static void __rcu_free_sheaf_prepare(struct kmem_cache *s,
 			continue;
 		}
 
+		if (slab_test_pfmemalloc(slab))
+			pfmemalloc = true;
+
 		i++;
 	}
+
+	return pfmemalloc;
 }
 
 static void rcu_free_sheaf_nobarn(struct rcu_head *head)
@@ -5031,7 +5040,7 @@ __pcs_replace_empty_main(struct kmem_cache *s, struct slub_percpu_sheaves *pcs,
 		return NULL;
 
 	if (empty) {
-		if (!refill_sheaf(s, empty, gfp)) {
+		if (!refill_sheaf(s, empty, gfp | __GFP_NOMEMALLOC)) {
 			full = empty;
 		} else {
 			/*
@@ -5331,6 +5340,26 @@ void *kmem_cache_alloc_node_noprof(struct kmem_cache *s, gfp_t gfpflags, int nod
 }
 EXPORT_SYMBOL(kmem_cache_alloc_node_noprof);
 
+static int __prefill_sheaf_pfmemalloc(struct kmem_cache *s,
+				      struct slab_sheaf *sheaf, gfp_t gfp)
+{
+	int ret = 0;
+
+	ret = refill_sheaf(s, sheaf, gfp | __GFP_NOMEMALLOC);
+
+	if (likely(!ret || !gfp_pfmemalloc_allowed(gfp)))
+		return ret;
+
+	/*
+	 * if we are allowed to, refill sheaf with pfmemalloc but then remember
+	 * it for when it's returned
+	 */
+	ret = refill_sheaf(s, sheaf, gfp);
+	sheaf->pfmemalloc = true;
+
+	return ret;
+}
+
 /*
  * returns a sheaf that has at least the requested size
  * when prefilling is needed, do so with given gfp flags
@@ -5401,17 +5430,18 @@ kmem_cache_prefill_sheaf(struct kmem_cache *s, gfp_t gfp, unsigned int size)
 	if (!sheaf)
 		sheaf = alloc_empty_sheaf(s, gfp);
 
-	if (sheaf && sheaf->size < size) {
-		if (refill_sheaf(s, sheaf, gfp)) {
+	if (sheaf) {
+		sheaf->capacity = s->sheaf_capacity;
+		sheaf->pfmemalloc = false;
+
+		if (sheaf->size < size &&
+		    __prefill_sheaf_pfmemalloc(s, sheaf, gfp)) {
 			sheaf_flush_unused(s, sheaf);
 			free_empty_sheaf(s, sheaf);
 			sheaf = NULL;
 		}
 	}
 
-	if (sheaf)
-		sheaf->capacity = s->sheaf_capacity;
-
 	return sheaf;
 }
 
@@ -5431,7 +5461,8 @@ void kmem_cache_return_sheaf(struct kmem_cache *s, gfp_t gfp,
 	struct slub_percpu_sheaves *pcs;
 	struct node_barn *barn;
 
-	if (unlikely(sheaf->capacity != s->sheaf_capacity)) {
+	if (unlikely((sheaf->capacity != s->sheaf_capacity)
+		     || sheaf->pfmemalloc)) {
 		sheaf_flush_unused(s, sheaf);
 		kfree(sheaf);
 		return;
@@ -5497,7 +5528,7 @@ int kmem_cache_refill_sheaf(struct kmem_cache *s, gfp_t gfp,
 
 	if (likely(sheaf->capacity >= size)) {
 		if (likely(sheaf->capacity == s->sheaf_capacity))
-			return refill_sheaf(s, sheaf, gfp);
+			return __prefill_sheaf_pfmemalloc(s, sheaf, gfp);
 
 		if (!__kmem_cache_alloc_bulk(s, gfp, sheaf->capacity - sheaf->size,
 					     &sheaf->objects[sheaf->size])) {
@@ -6177,8 +6208,12 @@ static void rcu_free_sheaf(struct rcu_head *head)
 	 * handles it fine. The only downside is that sheaf will serve fewer
 	 * allocations when reused. It only happens due to debugging, which is a
 	 * performance hit anyway.
+	 *
+	 * If it returns true, there was at least one object from pfmemalloc
+	 * slab so simply flush everything.
 	 */
-	__rcu_free_sheaf_prepare(s, sheaf);
+	if (__rcu_free_sheaf_prepare(s, sheaf))
+		goto flush;
 
 	n = get_node(s, sheaf->node);
 	if (!n)
@@ -6333,7 +6368,8 @@ static void free_to_pcs_bulk(struct kmem_cache *s, size_t size, void **p)
 			continue;
 		}
 
-		if (unlikely(IS_ENABLED(CONFIG_NUMA) && slab_nid(slab) != node)) {
+		if (unlikely((IS_ENABLED(CONFIG_NUMA) && slab_nid(slab) != node)
+			     || slab_test_pfmemalloc(slab))) {
 			remote_objects[remote_nr] = p[i];
 			p[i] = p[--size];
 			if (++remote_nr >= PCS_BATCH_MAX)
@@ -6631,7 +6667,8 @@ void slab_free(struct kmem_cache *s, struct slab *slab, void *object,
 		return;
 
 	if (s->cpu_sheaves && likely(!IS_ENABLED(CONFIG_NUMA) ||
-				     slab_nid(slab) == numa_mem_id())) {
+				     slab_nid(slab) == numa_mem_id())
+			   && likely(!slab_test_pfmemalloc(slab))) {
 		if (likely(free_to_pcs(s, object)))
 			return;
 	}

-- 
2.51.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251023-sheaves-for-all-v1-2-6ffa2c9941c0%40suse.cz.
