Return-Path: <kasan-dev+bncBDXYDPH3S4OBBRHG5DDQMGQEFAPGZZI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23a.google.com (mail-lj1-x23a.google.com [IPv6:2a00:1450:4864:20::23a])
	by mail.lfdr.de (Postfix) with ESMTPS id 38008C018D3
	for <lists+kasan-dev@lfdr.de>; Thu, 23 Oct 2025 15:53:10 +0200 (CEST)
Received: by mail-lj1-x23a.google.com with SMTP id 38308e7fff4ca-333f8ddf072sf3507411fa.0
        for <lists+kasan-dev@lfdr.de>; Thu, 23 Oct 2025 06:53:10 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1761227589; cv=pass;
        d=google.com; s=arc-20240605;
        b=ZiLVuaYh2/lF+I0WDesEwA5QjDdDxs2i7p5ANrEkEOAqmnyP6V6hqQj+EJHHfimrQe
         NSjKY7AH/+Nht8R8Vu99kxX0BuaFCLAzkquf+XXwHmu+7oPcdV8WK6Rgbio8eUwqqvVy
         EtPASl4qoNaMVB/d+O4wxRulj9ZDaarHRAHqmx1gjtAxkANr0KvF0AHGxZW6Qqp/gMtz
         XznUZkuHxVZ/wscXPgpinixw0S2f8kmTMtXAvqDDbptqakFp2d9+n1vPlcopMnlyIFd3
         em6XxMWdYilIOX9H0Av+7fQuOsnNgQfBLReGtYmFHYMv87TEAe4AvKwWGaErG0/OpiiW
         fgLA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:in-reply-to:references
         :message-id:mime-version:subject:date:from:sender:dkim-signature;
        bh=qNHiWmrJv77GB4bOP0d0hf/s7aG2fNlpsMlr3R0FD9s=;
        fh=/E17zIgIvJTOjKPYY9WxyuJWosKe+NDvC/DauDrcjSA=;
        b=YrlRJLx/iQ5zMZyi1ke0+owBiNli1GQTeeYDhlgvypbnfd79G25HZC68NDY1s2nOgM
         Uh3cUa0xKkNZ2MDAQcZ4cotUSZYNhzs2VcoyqDtjjZqyKNxnFJ+IK7twaA/OS2kSpx/g
         G9GOYcOcV+QhBUZiG49/j8RPyBTf/hOaE00xezMHmV4YcZyLhzJoNzU0/LBAYpVm8dbc
         7fqjqGqPS05H89JUYAaV7uyzIxlKqReu7Nk4+/WVYyuZwYqxzYzQ+Pq30aZAPO5i1QYp
         0qcaQtN1Fm8+epVqrWTm6At6iDtmtk1WwHaldoEqb2nhxNhaCKXKQEGDiaiEEZqg9eBm
         pO4g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=Mdy9BKbL;
       dkim=neutral (no key) header.i=@suse.cz header.b=+uOlwOB7;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=EPf6Y90J;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1761227589; x=1761832389; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:in-reply-to:references:message-id
         :mime-version:subject:date:from:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=qNHiWmrJv77GB4bOP0d0hf/s7aG2fNlpsMlr3R0FD9s=;
        b=QPHAoMWRhMnwilEnbGgi/vcco/QVd60KFRiFM2xIcilo6M0iC4vrFgtnla4G5ARHdb
         0aRDQh365qZx6tRJEgCALWwWU4TVsj3Qu0aNE0M4zIBM2Sba5k+RUCzmx71UCEM5xwyR
         goaKCuSY3pOFzOor9oFJKv60u0YrKD5+F9CKGLUzs7UvhhJQtDca/U/oEVFFsUsWVfI+
         snbi1EY1XZKrH3cRGu4hZy10j0ZECNH74B8GrgsCxMjNvx8mLgsP/DugP5VkacvkA3Jv
         +ErNniK60RvuC9vhdv9ZRnxDM4XchNgT0jS73AhfUWKbocePELWNzc3V8mh4Y1R9J9WX
         TXMQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1761227589; x=1761832389;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to
         :in-reply-to:references:message-id:mime-version:subject:date:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=qNHiWmrJv77GB4bOP0d0hf/s7aG2fNlpsMlr3R0FD9s=;
        b=sQwc4rLlmPQCHEImsUmxOjGBveNuHLI+EqP15NyUkAq88sj5JhH6AtkxteByvPXeYW
         74S1VTnzrlITD9Kqd2X1NPGhLYbmOl50irVAECxzqFKjIHhIcVtlNICn0rLB9RYJ+d3D
         rlwFxzfodEvQEnKlH4XljQRJiaiscHptaNwmBLI0eLn0TsV59/Tm3De4HsniuuhqxgMh
         IVAGD4SiRoW1twjdYfdCvV939IVM+eLD9BSs/o0rHC2eMRDyqksGSfi2AznI8tiiLWVr
         d70beWjiMLIWBBhX6/54T3LatOnWFTwpJzpWALqwfUjdFS7pK/Y4kwe5967ytOsR/ekE
         GGTQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXBlEBebTuBRtgCzqSfDJZBrwesuORPIVmaVc/MINIgW4oTi5KhjcV0luP5bh81HFvkKELHmw==@lfdr.de
X-Gm-Message-State: AOJu0YyT1etHWfkxmAG1mHHtKd9Ogwz9hiwmQJgWJKUGKZq9QVy7yuqy
	w6UX4QZqN1gTxR0+HyaP0HGptlTubBVKaCNlMjjcVuhgtq9d2vB2LT1b
X-Google-Smtp-Source: AGHT+IHqneh784LcKNh2NmhjAADxb5NMiDt4h/YEXsGysgkyBRQrapJceftn0xFTohkr2zrOyj5Jlw==
X-Received: by 2002:a05:651c:1142:b0:372:9fd0:8c44 with SMTP id 38308e7fff4ca-377978263f8mr67842921fa.3.1761227589090;
        Thu, 23 Oct 2025 06:53:09 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="ARHlJd4ywT+EY3KzyTp0C2GrAbmJStlCemwV229OJL32W06EAw=="
Received: by 2002:a2e:8619:0:b0:372:9093:f49f with SMTP id 38308e7fff4ca-378d64cc268ls219821fa.1.-pod-prod-02-eu;
 Thu, 23 Oct 2025 06:53:06 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCU280NktBRG5pIqQfGCuOOCm5TWr1Knwe8BUGeEH727yA4pWAf5ZSn9dIjyMoIxsq53Vu0Xo0lJNDs=@googlegroups.com
X-Received: by 2002:a05:651c:4393:10b0:378:cc43:59c6 with SMTP id 38308e7fff4ca-378cc435d68mr16034301fa.38.1761227585942;
        Thu, 23 Oct 2025 06:53:05 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1761227585; cv=none;
        d=google.com; s=arc-20240605;
        b=R1E6zTtuzkXanJwJmhk0yCkfZ1+m40z2tikrE3TSKKEj6CGBVztGHQ/d3zfqlitlcD
         +ndQXM5+zrKYzKd/8lS+0Dj8N8p5wVzg7J2cC2gQbswecqAVydImIzSImp/sZhHX81Np
         CYWncnBdX6YlLD8fLnNIubZP766UC4q8elrYBWJuoA+oK+clI0RzzbJf/BHVA68jaEyA
         cFH50uBBPl2aO9zfIPItoFVQq64rTDzT7/dYZElUQ1UR8Y0ugcVQQuasA83CEYekxixP
         rDkR5c0dufna0yo/nS+Faggcf25y7XJxdIlD2IDIkdIOUIQYgMO9mAROz+U7DjcjigS8
         ATXA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:in-reply-to:references:message-id:content-transfer-encoding
         :mime-version:subject:date:from:dkim-signature:dkim-signature
         :dkim-signature:dkim-signature;
        bh=BMsUktfL5WtFwPCNB5fqm7HAiF7pw4pM7Su8oc/8OIE=;
        fh=sn5LZh+L0Rfa+joht6VqgjJVwsYeldC59hPTZcGo6Vo=;
        b=BpI9CCZbi/n0VcofLhRza1zn56CZ/epHmifFpvlJYyKA5QOcL4Hb/S/x9Nwjl0AjJF
         hjQC7we3c3zSPLIFgPQVpSEJG9sAZvoArCiHWZonvhwKldJSeHo9tmIWrBWKbetwI2Kh
         P5PFjvVK4OMzjxXuXLPo4sLxemb1gigP1JjyxpukpTrzxAQ1ZqTVhk0sp986C/c6yYsP
         bEjzbjNwk1GGxSbOC73RPxDWoD0TwAwDTjqabPowQgN0FOfpWtoJzDu6kF1ChUDwcs81
         2KcsIGeNUlWqPql045Vk+mDp2cGjojKWmymJcmKwSd7DJ05ik68YlFHnyzDF7fxgLCQ/
         FfTg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=Mdy9BKbL;
       dkim=neutral (no key) header.i=@suse.cz header.b=+uOlwOB7;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=EPf6Y90J;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [2a07:de40:b251:101:10:150:64:2])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-378d6792b06si486191fa.5.2025.10.23.06.53.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 23 Oct 2025 06:53:05 -0700 (PDT)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) client-ip=2a07:de40:b251:101:10:150:64:2;
Received: from imap1.dmz-prg2.suse.org (unknown [10.150.64.97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id 356491F7E1;
	Thu, 23 Oct 2025 13:52:53 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 11D48139D2;
	Thu, 23 Oct 2025 13:52:53 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id 6O8UBDUz+mjvQQAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Thu, 23 Oct 2025 13:52:53 +0000
From: Vlastimil Babka <vbabka@suse.cz>
Date: Thu, 23 Oct 2025 15:52:23 +0200
Subject: [PATCH RFC 01/19] slab: move kfence_alloc() out of internal bulk
 alloc
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Message-Id: <20251023-sheaves-for-all-v1-1-6ffa2c9941c0@suse.cz>
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
 Vlastimil Babka <vbabka@suse.cz>, Alexander Potapenko <glider@google.com>, 
 Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>
X-Mailer: b4 0.14.3
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
	RCPT_COUNT_TWELVE(0.00)[19];
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
	DBL_BLOCKED_OPENRESOLVER(0.00)[imap1.dmz-prg2.suse.org:helo,suse.cz:mid,suse.cz:email]
X-Spam-Flag: NO
X-Spam-Score: -8.30
X-Spam-Level: 
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=Mdy9BKbL;       dkim=neutral
 (no key) header.i=@suse.cz header.b=+uOlwOB7;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=EPf6Y90J;       dkim=neutral
 (no key) header.i=@suse.cz;       spf=pass (google.com: domain of
 vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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

SLUB's internal bulk allocation __kmem_cache_alloc_bulk() can currently
allocate some objects from KFENCE, i.e. when refilling a sheaf. It works
but it's conceptually the wrong layer, as KFENCE allocations should only
happen when objects are actually handed out from slab to its users.

Currently for sheaf-enabled caches, slab_alloc_node() can return KFENCE
object via kfence_alloc(), but also via alloc_from_pcs() when a sheaf
was refilled with KFENCE objects. Continuing like this would also
complicate the upcoming sheaf refill changes.

Thus remove KFENCE allocation from __kmem_cache_alloc_bulk() and move it
to the places that return slab objects to users. slab_alloc_node() is
already covered (see above). Add kfence_alloc() to
kmem_cache_alloc_from_sheaf() to handle KFENCE allocations from
prefilled sheafs, with a comment that the caller should not expect the
sheaf size to decrease after every allocation because of this
possibility.

For kmem_cache_alloc_bulk() implement a different strategy to handle
KFENCE upfront and rely on internal batched operations afterwards.
Assume there will be at most once KFENCE allocation per bulk allocation
and then assign its index in the array of objects randomly.

Cc: Alexander Potapenko <glider@google.com>
Cc: Marco Elver <elver@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>
Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
---
 mm/slub.c | 44 ++++++++++++++++++++++++++++++++++++--------
 1 file changed, 36 insertions(+), 8 deletions(-)

diff --git a/mm/slub.c b/mm/slub.c
index 87a1d2f9de0d..4731b9e461c2 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -5530,6 +5530,9 @@ int kmem_cache_refill_sheaf(struct kmem_cache *s, gfp_t gfp,
  *
  * The gfp parameter is meant only to specify __GFP_ZERO or __GFP_ACCOUNT
  * memcg charging is forced over limit if necessary, to avoid failure.
+ *
+ * It is possible that the allocation comes from kfence and then the sheaf
+ * size is not decreased.
  */
 void *
 kmem_cache_alloc_from_sheaf_noprof(struct kmem_cache *s, gfp_t gfp,
@@ -5541,7 +5544,10 @@ kmem_cache_alloc_from_sheaf_noprof(struct kmem_cache *s, gfp_t gfp,
 	if (sheaf->size == 0)
 		goto out;
 
-	ret = sheaf->objects[--sheaf->size];
+	ret = kfence_alloc(s, s->object_size, gfp);
+
+	if (likely(!ret))
+		ret = sheaf->objects[--sheaf->size];
 
 	init = slab_want_init_on_alloc(gfp, s);
 
@@ -7361,14 +7367,8 @@ int __kmem_cache_alloc_bulk(struct kmem_cache *s, gfp_t flags, size_t size,
 	local_lock_irqsave(&s->cpu_slab->lock, irqflags);
 
 	for (i = 0; i < size; i++) {
-		void *object = kfence_alloc(s, s->object_size, flags);
-
-		if (unlikely(object)) {
-			p[i] = object;
-			continue;
-		}
+		void *object = c->freelist;
 
-		object = c->freelist;
 		if (unlikely(!object)) {
 			/*
 			 * We may have removed an object from c->freelist using
@@ -7449,6 +7449,7 @@ int kmem_cache_alloc_bulk_noprof(struct kmem_cache *s, gfp_t flags, size_t size,
 				 void **p)
 {
 	unsigned int i = 0;
+	void *kfence_obj;
 
 	if (!size)
 		return 0;
@@ -7457,6 +7458,20 @@ int kmem_cache_alloc_bulk_noprof(struct kmem_cache *s, gfp_t flags, size_t size,
 	if (unlikely(!s))
 		return 0;
 
+	/*
+	 * to make things simpler, only assume at most once kfence allocated
+	 * object per bulk allocation and choose its index randomly
+	 */
+	kfence_obj = kfence_alloc(s, s->object_size, flags);
+
+	if (unlikely(kfence_obj)) {
+		if (unlikely(size == 1)) {
+			p[0] = kfence_obj;
+			goto out;
+		}
+		size--;
+	}
+
 	if (s->cpu_sheaves)
 		i = alloc_from_pcs_bulk(s, size, p);
 
@@ -7468,10 +7483,23 @@ int kmem_cache_alloc_bulk_noprof(struct kmem_cache *s, gfp_t flags, size_t size,
 		if (unlikely(__kmem_cache_alloc_bulk(s, flags, size - i, p + i) == 0)) {
 			if (i > 0)
 				__kmem_cache_free_bulk(s, i, p);
+			if (kfence_obj)
+				__kfence_free(kfence_obj);
 			return 0;
 		}
 	}
 
+	if (unlikely(kfence_obj)) {
+		int idx = get_random_u32_below(size + 1);
+
+		if (idx != size)
+			p[size] = p[idx];
+		p[idx] = kfence_obj;
+
+		size++;
+	}
+
+out:
 	/*
 	 * memcg and kmem_cache debug support and memory initialization.
 	 * Done outside of the IRQ disabled fastpath loop.

-- 
2.51.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251023-sheaves-for-all-v1-1-6ffa2c9941c0%40suse.cz.
