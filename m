Return-Path: <kasan-dev+bncBDXYDPH3S4OBB5NVZTFQMGQEUUU3ULI@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id mMTDL/Yac2mwsAAAu9opvQ
	(envelope-from <kasan-dev+bncBDXYDPH3S4OBB5NVZTFQMGQEUUU3ULI@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Fri, 23 Jan 2026 07:53:42 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x140.google.com (mail-lf1-x140.google.com [IPv6:2a00:1450:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id 74D8B71346
	for <lists+kasan-dev@lfdr.de>; Fri, 23 Jan 2026 07:53:42 +0100 (CET)
Received: by mail-lf1-x140.google.com with SMTP id 2adb3069b0e04-59dd6e96023sf1286440e87.2
        for <lists+kasan-dev@lfdr.de>; Thu, 22 Jan 2026 22:53:42 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1769151222; cv=pass;
        d=google.com; s=arc-20240605;
        b=c3jszPzHspXpAKSqUfjaBAJG0mOkOgCHjiQ/pQ3xe9hvnOIkBrlvlDHz7B9AhQ5t4w
         bzHPbLBK94c3PTZjaZNyHs6uz8+qGM5Ynoai1rHYFlrPjeBkaH5jhzB9TGGW8S7ywBrT
         OA3eHCve6S9G2Yzk7KLoJ++iLGT28DfsSvQOeGxi4Y1RYbsrlimk0z5/iPKapuV8IfJ4
         BF/L8LeUBQnXTDcxn8ZmaApgBEGl9lA9KVBhI1fQTwW5Vb0mPZqac6kL5X5hJYyXGRoZ
         BYW+xbhqxe9kMSyzV7kG+GdE3H1mS9JzAkXQOYIFfdc5stJllZYT8bitH6Bs+UzICoSv
         VqkA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:in-reply-to:references
         :message-id:mime-version:subject:date:from:sender:dkim-signature;
        bh=TW1KkPN2vA4WGOKZx8Ivhnu6s26u/bAWBKe61flw3Is=;
        fh=6qG3LZO3xGex7U6omwO9buOH5DymCFlC+dyeQONS6cM=;
        b=YVgvezo8+jsQAHUoDffWnOQLzzZ0YRzi5jbIilgcqi1qwxPFU0Q53LfiROlNTs8zEO
         RFppOgU3KKJehpNBUyYSvDni0ATrmuyIcA/Y3tRgn31S7Rq8faM6qkYl+AgsbNga0+LM
         fGwD2EjeHRi38RmYKNteDwlQKruhO8QC5Lp8Oc3/9DBkzRP9xpkD2akbCQwuospkpIMY
         Ji2nzS6dmoXcSZ7//DYFgVxHgXKZsuRhnpgYZLAxkhSY955slxfaXK1YgcZ9XVcnXSKQ
         y/9iYgUtMQachoydXRaVZaQUz3N7hg2OAZyEpuBljAnTBdW0llaXoW+e2WVqbegDwNkH
         3udw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=o5AeQSFY;
       dkim=neutral (no key) header.i=@suse.cz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=o5AeQSFY;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1769151222; x=1769756022; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:in-reply-to:references:message-id
         :mime-version:subject:date:from:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=TW1KkPN2vA4WGOKZx8Ivhnu6s26u/bAWBKe61flw3Is=;
        b=PMEUn+KI5KeM4xu0zmXZ1In/hu41RxEh59tBsc1nucXkhhpTBsm0J7nmzzk188zsJg
         Hty1jBPsXwPxAgbhiGeWPsFm9t/MFRRqk1dyxt2ZcOh7WnmuLjhKdRmGR+7udktltH4v
         uOCZoae2Wxb1FqQFdpIDOI8iIkXpbMEWEYYEPCc6hpfqfJug4CFSCWH4iEVF8cSen26B
         ko4zqEU4eI9c7x+wDnMZJpkGzaKLmm7As37M8rM05LQOEVNpq6ZAFY32P61xjfY3FPQN
         u11Y3RKLMj9pHdtdq5nLeLvsGsSfdaNHvFvCghmXHH+d5HTSUBbHOWgehdaFwRxHTgYV
         /6lQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1769151222; x=1769756022;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to
         :in-reply-to:references:message-id:mime-version:subject:date:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=TW1KkPN2vA4WGOKZx8Ivhnu6s26u/bAWBKe61flw3Is=;
        b=gzgMvfTx+QpwQWFQ7BVOovtw+DYpM1jJ6reYqkF8u0Ov9dcriXDBkEGfvfAhphNCKL
         VxOmmiVBEEb7Y95mhmE/Z9y0i5roRydkicqUS/Ad6RdqK2kZFMhgTSooa15xvOgEXnoK
         gjexiNCpVn50PeKBdV60Dc/O7tGNBdKfvlsYaT4Xs5yIK9zupjHMU92M1aU3P2V2Cj6Z
         gvZXnlz0DBmx35q62AbQfyigqiUpQknSclyChWuVRomkxfJCzsqKD8s/8k2g1w22JL2A
         X/HTmeo2SC67fIHDng3wunsTBloyoZ/OURPUDULYl4cCbmmTjvZViqkRqvytXO4c115u
         q0Cw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXkCZMw5GQ7NC+aMvwharkNiS5iJYajJsoeyf2G2EZXwZ86DIIM5nY4sTYepRUD6A+Xt0H1PA==@lfdr.de
X-Gm-Message-State: AOJu0YzAjNdayBk8QRzccbCxsoB+iz1lBJwubuR4BMmZHx/9llDWUQLt
	tFtMFDvGdRpbnBEDvdRCNfai/xgHhxod1Yy6cWPwPdvfP3X23E7mFAEg
X-Received: by 2002:a05:6512:a94:b0:59b:7016:951c with SMTP id 2adb3069b0e04-59de4a2b38cmr671970e87.48.1769151221596;
        Thu, 22 Jan 2026 22:53:41 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+FckWTAN6LoPDXN7+6UWJldH8enJXxMGEmQf4aq/+BjDw=="
Received: by 2002:a05:6512:2352:b0:59b:6cb8:9cf3 with SMTP id
 2adb3069b0e04-59dd797aabfls603075e87.1.-pod-prod-03-eu; Thu, 22 Jan 2026
 22:53:39 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXNLq4EgrguvvxSNct4HWvbox2eHAw0GJV3YjC/dMnIUy/72M+y+TLhsqPKOpoYAAyCJ/62khTfi30=@googlegroups.com
X-Received: by 2002:a05:6512:b95:b0:59b:7301:2378 with SMTP id 2adb3069b0e04-59de4a254a8mr466152e87.42.1769151218895;
        Thu, 22 Jan 2026 22:53:38 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1769151218; cv=none;
        d=google.com; s=arc-20240605;
        b=ddgAHgv675tlZPZiy/BWkeDMz6cSYcPBSZZ4gZBB0jdIKzz1n8pukqxpuy33bYECO5
         kDMaJQjXtUO4NKEA9iJZgJEqCDIGbdkW6DX1xi1nwblvr4vPbcEzvyBq0Usk7PR/2b7o
         w11tbaPJOslim858CG6iSpcmvW1EIPpOxXYWxZrYOPLmNo70/nOpuj87vkd+5dDoCFa9
         VfAvUhN2I1vBcKnQgvLMAnJBcMhnp7M5359ielVR/uWELs72d82Xa9jVgH/NJ5mgn0oc
         EbZilZGi8JFCXqYe179UPMMeaztdGMC/vec6ykkTiTEZXZ+RvCvENogYMN6TDgeIPr4q
         4C0w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:in-reply-to:references:message-id:content-transfer-encoding
         :mime-version:subject:date:from:dkim-signature:dkim-signature
         :dkim-signature:dkim-signature;
        bh=TLMwhN+Q0BRaAd8zNAL02f9ktCLgn+VwTLulNhwHIcU=;
        fh=+YiR3k2M4/hjhpad8/hMpDOxCdG92wPg4T+KQWP+jEY=;
        b=e7vxFHNHbNVfMhcevv/TAgHIiShS5Rkap3DnQe3gDktuE+lcTe8ILh5S1A4wzHih3R
         7YXChSHTSr53VfSg+1liYuS/WzBRe0ISZP5osZqh8JpyKpW1cIJwRUuLQeYqC87Ua/4J
         IiCdomCgnvbbgUZ5hgYkTrIpn1K3+SxD6JcaiClQT8yGJOXOnVv0S6cJonb468uILCtA
         ILBZ7rSw7hBFgxroY8KHJNI4jrx5we8OQVuT1w1fXY+xEkdNqMWBIJlN+HrSDwuE3K2u
         p5tuA0kFU5aTsD8SQNJGmcsSI5NOm7sk55EL7BJH6HPTPimQ0vyBT1oI3EGFAbjqzIdC
         +8IA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=o5AeQSFY;
       dkim=neutral (no key) header.i=@suse.cz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=o5AeQSFY;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [195.135.223.130])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-59de45b1da0si27995e87.0.2026.01.22.22.53.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 22 Jan 2026 22:53:38 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) client-ip=195.135.223.130;
Received: from imap1.dmz-prg2.suse.org (unknown [10.150.64.97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id C49C633770;
	Fri, 23 Jan 2026 06:53:10 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 457A9139F2;
	Fri, 23 Jan 2026 06:53:10 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id 8GasENYac2k4YgAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Fri, 23 Jan 2026 06:53:10 +0000
From: Vlastimil Babka <vbabka@suse.cz>
Date: Fri, 23 Jan 2026 07:52:49 +0100
Subject: [PATCH v4 11/22] slab: remove cpu (partial) slabs usage from
 allocation paths
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Message-Id: <20260123-sheaves-for-all-v4-11-041323d506f7@suse.cz>
References: <20260123-sheaves-for-all-v4-0-041323d506f7@suse.cz>
In-Reply-To: <20260123-sheaves-for-all-v4-0-041323d506f7@suse.cz>
To: Harry Yoo <harry.yoo@oracle.com>, Petr Tesarik <ptesarik@suse.com>, 
 Christoph Lameter <cl@gentwo.org>, David Rientjes <rientjes@google.com>, 
 Roman Gushchin <roman.gushchin@linux.dev>
Cc: Hao Li <hao.li@linux.dev>, Andrew Morton <akpm@linux-foundation.org>, 
 Uladzislau Rezki <urezki@gmail.com>, 
 "Liam R. Howlett" <Liam.Howlett@oracle.com>, 
 Suren Baghdasaryan <surenb@google.com>, 
 Sebastian Andrzej Siewior <bigeasy@linutronix.de>, 
 Alexei Starovoitov <ast@kernel.org>, linux-mm@kvack.org, 
 linux-kernel@vger.kernel.org, linux-rt-devel@lists.linux.dev, 
 bpf@vger.kernel.org, kasan-dev@googlegroups.com, 
 Vlastimil Babka <vbabka@suse.cz>
X-Mailer: b4 0.14.3
X-Spam-Score: -8.30
X-Spam-Level: 
X-Spam-Flag: NO
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=o5AeQSFY;       dkim=neutral
 (no key) header.i=@suse.cz;       dkim=pass header.i=@suse.cz
 header.s=susede2_rsa header.b=o5AeQSFY;       dkim=neutral (no key)
 header.i=@suse.cz;       spf=pass (google.com: domain of vbabka@suse.cz
 designates 195.135.223.130 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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
X-Rspamd-Server: lfdr
X-Spamd-Result: default: False [-1.71 / 15.00];
	ARC_ALLOW(-1.00)[google.com:s=arc-20240605:i=2];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601];
	MAILLIST(-0.20)[googlegroups];
	R_SPF_ALLOW(-0.20)[+ip6:2a00:1450:4000::/36:c];
	MIME_GOOD(-0.10)[text/plain];
	HAS_LIST_UNSUB(-0.01)[];
	TAGGED_FROM(0.00)[bncBDXYDPH3S4OBB5NVZTFQMGQEUUU3ULI];
	RCVD_TLS_LAST(0.00)[];
	FROM_HAS_DN(0.00)[];
	DMARC_NA(0.00)[suse.cz];
	FORGED_SENDER_MAILLIST(0.00)[];
	FREEMAIL_CC(0.00)[linux.dev,linux-foundation.org,gmail.com,oracle.com,google.com,linutronix.de,kernel.org,kvack.org,vger.kernel.org,lists.linux.dev,googlegroups.com,suse.cz];
	RCPT_COUNT_TWELVE(0.00)[18];
	MIME_TRACE(0.00)[0:+];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	ASN(0.00)[asn:15169, ipnet:2a00:1450::/32, country:US];
	TO_DN_SOME(0.00)[];
	RCVD_COUNT_FIVE(0.00)[6];
	FROM_NEQ_ENVFROM(0.00)[vbabka@suse.cz,kasan-dev@googlegroups.com];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	NEURAL_HAM(-0.00)[-0.976];
	TAGGED_RCPT(0.00)[kasan-dev];
	MID_RHS_MATCH_FROM(0.00)[];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	DBL_BLOCKED_OPENRESOLVER(0.00)[googlegroups.com:email,googlegroups.com:dkim,suse.cz:mid,suse.cz:email,oracle.com:email]
X-Rspamd-Queue-Id: 74D8B71346
X-Rspamd-Action: no action

We now rely on sheaves as the percpu caching layer and can refill them
directly from partial or newly allocated slabs. Start removing the cpu
(partial) slabs code, first from allocation paths.

This means that any allocation not satisfied from percpu sheaves will
end up in ___slab_alloc(), where we remove the usage of cpu (partial)
slabs, so it will only perform get_partial() or new_slab(). In the
latter case we reuse alloc_from_new_slab() (when we don't use
the debug/tiny alloc_single_from_new_slab() variant).

In get_partial_node() we used to return a slab for freezing as the cpu
slab and to refill the partial slab. Now we only want to return a single
object and leave the slab on the list (unless it became full). We can't
simply reuse alloc_single_from_partial() as that assumes freeing uses
free_to_partial_list(). Instead we need to use __slab_update_freelist()
to work properly against a racing __slab_free().

To reflect the new purpose of get_partial() functions, rename them to
get_from_partial(), get_from_partial_node(), and get_from_any_partial().

The rest of the changes is removing functions that no longer have any
callers.

Reviewed-by: Harry Yoo <harry.yoo@oracle.com>
Reviewed-by: Hao Li <hao.li@linux.dev>
Reviewed-by: Suren Baghdasaryan <surenb@google.com>
Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
---
 mm/slub.c | 628 +++++++++-----------------------------------------------------
 1 file changed, 87 insertions(+), 541 deletions(-)

diff --git a/mm/slub.c b/mm/slub.c
index 142a1099bbc1..3a78cee811cf 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -241,11 +241,10 @@ DEFINE_STATIC_KEY_FALSE(slub_debug_enabled);
 static DEFINE_STATIC_KEY_FALSE(strict_numa);
 #endif
 
-/* Structure holding parameters for get_partial() call chain */
+/* Structure holding parameters for get_from_partial() call chain */
 struct partial_context {
 	gfp_t flags;
 	unsigned int orig_size;
-	void *object;
 };
 
 /* Structure holding parameters for get_partial_node_bulk() */
@@ -604,36 +603,6 @@ static inline void *get_freepointer(struct kmem_cache *s, void *object)
 	return freelist_ptr_decode(s, p, ptr_addr);
 }
 
-static void prefetch_freepointer(const struct kmem_cache *s, void *object)
-{
-	prefetchw(object + s->offset);
-}
-
-/*
- * When running under KMSAN, get_freepointer_safe() may return an uninitialized
- * pointer value in the case the current thread loses the race for the next
- * memory chunk in the freelist. In that case this_cpu_cmpxchg_double() in
- * slab_alloc_node() will fail, so the uninitialized value won't be used, but
- * KMSAN will still check all arguments of cmpxchg because of imperfect
- * handling of inline assembly.
- * To work around this problem, we apply __no_kmsan_checks to ensure that
- * get_freepointer_safe() returns initialized memory.
- */
-__no_kmsan_checks
-static inline void *get_freepointer_safe(struct kmem_cache *s, void *object)
-{
-	unsigned long freepointer_addr;
-	freeptr_t p;
-
-	if (!debug_pagealloc_enabled_static())
-		return get_freepointer(s, object);
-
-	object = kasan_reset_tag(object);
-	freepointer_addr = (unsigned long)object + s->offset;
-	copy_from_kernel_nofault(&p, (freeptr_t *)freepointer_addr, sizeof(p));
-	return freelist_ptr_decode(s, p, freepointer_addr);
-}
-
 static inline void set_freepointer(struct kmem_cache *s, void *object, void *fp)
 {
 	unsigned long freeptr_addr = (unsigned long)object + s->offset;
@@ -713,23 +682,11 @@ static void slub_set_cpu_partial(struct kmem_cache *s, unsigned int nr_objects)
 	nr_slabs = DIV_ROUND_UP(nr_objects * 2, oo_objects(s->oo));
 	s->cpu_partial_slabs = nr_slabs;
 }
-
-static inline unsigned int slub_get_cpu_partial(struct kmem_cache *s)
-{
-	return s->cpu_partial_slabs;
-}
-#else
-#ifdef SLAB_SUPPORTS_SYSFS
+#elif defined(SLAB_SUPPORTS_SYSFS)
 static inline void
 slub_set_cpu_partial(struct kmem_cache *s, unsigned int nr_objects)
 {
 }
-#endif
-
-static inline unsigned int slub_get_cpu_partial(struct kmem_cache *s)
-{
-	return 0;
-}
 #endif /* CONFIG_SLUB_CPU_PARTIAL */
 
 /*
@@ -1071,7 +1028,7 @@ static void set_track_update(struct kmem_cache *s, void *object,
 	p->handle = handle;
 #endif
 	p->addr = addr;
-	p->cpu = smp_processor_id();
+	p->cpu = raw_smp_processor_id();
 	p->pid = current->pid;
 	p->when = jiffies;
 }
@@ -3579,20 +3536,20 @@ static bool get_partial_node_bulk(struct kmem_cache *s,
 }
 
 /*
- * Try to allocate a partial slab from a specific node.
+ * Try to allocate object from a partial slab on a specific node.
  */
-static struct slab *get_partial_node(struct kmem_cache *s,
-				     struct kmem_cache_node *n,
-				     struct partial_context *pc)
+static void *get_from_partial_node(struct kmem_cache *s,
+				   struct kmem_cache_node *n,
+				   struct partial_context *pc)
 {
-	struct slab *slab, *slab2, *partial = NULL;
+	struct slab *slab, *slab2;
 	unsigned long flags;
-	unsigned int partial_slabs = 0;
+	void *object = NULL;
 
 	/*
 	 * Racy check. If we mistakenly see no partial slabs then we
 	 * just allocate an empty slab. If we mistakenly try to get a
-	 * partial slab and there is none available then get_partial()
+	 * partial slab and there is none available then get_from_partial()
 	 * will return NULL.
 	 */
 	if (!n || !n->nr_partial)
@@ -3603,54 +3560,55 @@ static struct slab *get_partial_node(struct kmem_cache *s,
 	else if (!spin_trylock_irqsave(&n->list_lock, flags))
 		return NULL;
 	list_for_each_entry_safe(slab, slab2, &n->partial, slab_list) {
+
+		struct freelist_counters old, new;
+
 		if (!pfmemalloc_match(slab, pc->flags))
 			continue;
 
 		if (IS_ENABLED(CONFIG_SLUB_TINY) || kmem_cache_debug(s)) {
-			void *object = alloc_single_from_partial(s, n, slab,
+			object = alloc_single_from_partial(s, n, slab,
 							pc->orig_size);
-			if (object) {
-				partial = slab;
-				pc->object = object;
+			if (object)
 				break;
-			}
 			continue;
 		}
 
-		remove_partial(n, slab);
+		/*
+		 * get a single object from the slab. This might race against
+		 * __slab_free(), which however has to take the list_lock if
+		 * it's about to make the slab fully free.
+		 */
+		do {
+			old.freelist = slab->freelist;
+			old.counters = slab->counters;
 
-		if (!partial) {
-			partial = slab;
-			stat(s, ALLOC_FROM_PARTIAL);
+			new.freelist = get_freepointer(s, old.freelist);
+			new.counters = old.counters;
+			new.inuse++;
 
-			if ((slub_get_cpu_partial(s) == 0)) {
-				break;
-			}
-		} else {
-			put_cpu_partial(s, slab, 0);
-			stat(s, CPU_PARTIAL_NODE);
+		} while (!__slab_update_freelist(s, slab, &old, &new, "get_from_partial_node"));
 
-			if (++partial_slabs > slub_get_cpu_partial(s) / 2) {
-				break;
-			}
-		}
+		object = old.freelist;
+		if (!new.freelist)
+			remove_partial(n, slab);
+
+		break;
 	}
 	spin_unlock_irqrestore(&n->list_lock, flags);
-	return partial;
+	return object;
 }
 
 /*
- * Get a slab from somewhere. Search in increasing NUMA distances.
+ * Get an object from somewhere. Search in increasing NUMA distances.
  */
-static struct slab *get_any_partial(struct kmem_cache *s,
-				    struct partial_context *pc)
+static void *get_from_any_partial(struct kmem_cache *s, struct partial_context *pc)
 {
 #ifdef CONFIG_NUMA
 	struct zonelist *zonelist;
 	struct zoneref *z;
 	struct zone *zone;
 	enum zone_type highest_zoneidx = gfp_zone(pc->flags);
-	struct slab *slab;
 	unsigned int cpuset_mems_cookie;
 
 	/*
@@ -3685,8 +3643,10 @@ static struct slab *get_any_partial(struct kmem_cache *s,
 
 			if (n && cpuset_zone_allowed(zone, pc->flags) &&
 					n->nr_partial > s->min_partial) {
-				slab = get_partial_node(s, n, pc);
-				if (slab) {
+
+				void *object = get_from_partial_node(s, n, pc);
+
+				if (object) {
 					/*
 					 * Don't check read_mems_allowed_retry()
 					 * here - if mems_allowed was updated in
@@ -3694,7 +3654,7 @@ static struct slab *get_any_partial(struct kmem_cache *s,
 					 * between allocation and the cpuset
 					 * update
 					 */
-					return slab;
+					return object;
 				}
 			}
 		}
@@ -3704,22 +3664,22 @@ static struct slab *get_any_partial(struct kmem_cache *s,
 }
 
 /*
- * Get a partial slab, lock it and return it.
+ * Get an object from a partial slab
  */
-static struct slab *get_partial(struct kmem_cache *s, int node,
-				struct partial_context *pc)
+static void *get_from_partial(struct kmem_cache *s, int node,
+			      struct partial_context *pc)
 {
-	struct slab *slab;
 	int searchnode = node;
+	void *object;
 
 	if (node == NUMA_NO_NODE)
 		searchnode = numa_mem_id();
 
-	slab = get_partial_node(s, get_node(s, searchnode), pc);
-	if (slab || (node != NUMA_NO_NODE && (pc->flags & __GFP_THISNODE)))
-		return slab;
+	object = get_from_partial_node(s, get_node(s, searchnode), pc);
+	if (object || (node != NUMA_NO_NODE && (pc->flags & __GFP_THISNODE)))
+		return object;
 
-	return get_any_partial(s, pc);
+	return get_from_any_partial(s, pc);
 }
 
 #ifdef CONFIG_PREEMPTION
@@ -4277,19 +4237,6 @@ static int slub_cpu_dead(unsigned int cpu)
 	return 0;
 }
 
-/*
- * Check if the objects in a per cpu structure fit numa
- * locality expectations.
- */
-static inline int node_match(struct slab *slab, int node)
-{
-#ifdef CONFIG_NUMA
-	if (node != NUMA_NO_NODE && slab_nid(slab) != node)
-		return 0;
-#endif
-	return 1;
-}
-
 #ifdef CONFIG_SLUB_DEBUG
 static int count_free(struct slab *slab)
 {
@@ -4474,36 +4421,6 @@ __update_cpu_freelist_fast(struct kmem_cache *s,
 					     &old.freelist_tid, new.freelist_tid);
 }
 
-/*
- * Check the slab->freelist and either transfer the freelist to the
- * per cpu freelist or deactivate the slab.
- *
- * The slab is still frozen if the return value is not NULL.
- *
- * If this function returns NULL then the slab has been unfrozen.
- */
-static inline void *get_freelist(struct kmem_cache *s, struct slab *slab)
-{
-	struct freelist_counters old, new;
-
-	lockdep_assert_held(this_cpu_ptr(&s->cpu_slab->lock));
-
-	do {
-		old.freelist = slab->freelist;
-		old.counters = slab->counters;
-
-		new.freelist = NULL;
-		new.counters = old.counters;
-
-		new.inuse = old.objects;
-		new.frozen = old.freelist != NULL;
-
-
-	} while (!__slab_update_freelist(s, slab, &old, &new, "get_freelist"));
-
-	return old.freelist;
-}
-
 /*
  * Get the slab's freelist and do not freeze it.
  *
@@ -4531,29 +4448,6 @@ static inline void *get_freelist_nofreeze(struct kmem_cache *s, struct slab *sla
 	return old.freelist;
 }
 
-/*
- * Freeze the partial slab and return the pointer to the freelist.
- */
-static inline void *freeze_slab(struct kmem_cache *s, struct slab *slab)
-{
-	struct freelist_counters old, new;
-
-	do {
-		old.freelist = slab->freelist;
-		old.counters = slab->counters;
-
-		new.freelist = NULL;
-		new.counters = old.counters;
-		VM_BUG_ON(new.frozen);
-
-		new.inuse = old.objects;
-		new.frozen = 1;
-
-	} while (!slab_update_freelist(s, slab, &old, &new, "freeze_slab"));
-
-	return old.freelist;
-}
-
 /*
  * If the object has been wiped upon free, make sure it's fully initialized by
  * zeroing out freelist pointer.
@@ -4621,170 +4515,23 @@ static unsigned int alloc_from_new_slab(struct kmem_cache *s, struct slab *slab,
 }
 
 /*
- * Slow path. The lockless freelist is empty or we need to perform
- * debugging duties.
- *
- * Processing is still very fast if new objects have been freed to the
- * regular freelist. In that case we simply take over the regular freelist
- * as the lockless freelist and zap the regular freelist.
- *
- * If that is not working then we fall back to the partial lists. We take the
- * first element of the freelist as the object to allocate now and move the
- * rest of the freelist to the lockless freelist.
+ * Slow path. We failed to allocate via percpu sheaves or they are not available
+ * due to bootstrap or debugging enabled or SLUB_TINY.
  *
- * And if we were unable to get a new slab from the partial slab lists then
- * we need to allocate a new slab. This is the slowest path since it involves
- * a call to the page allocator and the setup of a new slab.
- *
- * Version of __slab_alloc to use when we know that preemption is
- * already disabled (which is the case for bulk allocation).
+ * We try to allocate from partial slab lists and fall back to allocating a new
+ * slab.
  */
 static void *___slab_alloc(struct kmem_cache *s, gfp_t gfpflags, int node,
-			  unsigned long addr, struct kmem_cache_cpu *c, unsigned int orig_size)
+			   unsigned long addr, unsigned int orig_size)
 {
 	bool allow_spin = gfpflags_allow_spinning(gfpflags);
-	void *freelist;
+	void *object;
 	struct slab *slab;
-	unsigned long flags;
 	struct partial_context pc;
 	bool try_thisnode = true;
 
 	stat(s, ALLOC_SLOWPATH);
 
-reread_slab:
-
-	slab = READ_ONCE(c->slab);
-	if (!slab) {
-		/*
-		 * if the node is not online or has no normal memory, just
-		 * ignore the node constraint
-		 */
-		if (unlikely(node != NUMA_NO_NODE &&
-			     !node_isset(node, slab_nodes)))
-			node = NUMA_NO_NODE;
-		goto new_slab;
-	}
-
-	if (unlikely(!node_match(slab, node))) {
-		/*
-		 * same as above but node_match() being false already
-		 * implies node != NUMA_NO_NODE.
-		 *
-		 * We don't strictly honor pfmemalloc and NUMA preferences
-		 * when !allow_spin because:
-		 *
-		 * 1. Most kmalloc() users allocate objects on the local node,
-		 *    so kmalloc_nolock() tries not to interfere with them by
-		 *    deactivating the cpu slab.
-		 *
-		 * 2. Deactivating due to NUMA or pfmemalloc mismatch may cause
-		 *    unnecessary slab allocations even when n->partial list
-		 *    is not empty.
-		 */
-		if (!node_isset(node, slab_nodes) ||
-		    !allow_spin) {
-			node = NUMA_NO_NODE;
-		} else {
-			stat(s, ALLOC_NODE_MISMATCH);
-			goto deactivate_slab;
-		}
-	}
-
-	/*
-	 * By rights, we should be searching for a slab page that was
-	 * PFMEMALLOC but right now, we are losing the pfmemalloc
-	 * information when the page leaves the per-cpu allocator
-	 */
-	if (unlikely(!pfmemalloc_match(slab, gfpflags) && allow_spin))
-		goto deactivate_slab;
-
-	/* must check again c->slab in case we got preempted and it changed */
-	local_lock_cpu_slab(s, flags);
-
-	if (unlikely(slab != c->slab)) {
-		local_unlock_cpu_slab(s, flags);
-		goto reread_slab;
-	}
-	freelist = c->freelist;
-	if (freelist)
-		goto load_freelist;
-
-	freelist = get_freelist(s, slab);
-
-	if (!freelist) {
-		c->slab = NULL;
-		c->tid = next_tid(c->tid);
-		local_unlock_cpu_slab(s, flags);
-		stat(s, DEACTIVATE_BYPASS);
-		goto new_slab;
-	}
-
-	stat(s, ALLOC_REFILL);
-
-load_freelist:
-
-	lockdep_assert_held(this_cpu_ptr(&s->cpu_slab->lock));
-
-	/*
-	 * freelist is pointing to the list of objects to be used.
-	 * slab is pointing to the slab from which the objects are obtained.
-	 * That slab must be frozen for per cpu allocations to work.
-	 */
-	VM_BUG_ON(!c->slab->frozen);
-	c->freelist = get_freepointer(s, freelist);
-	c->tid = next_tid(c->tid);
-	local_unlock_cpu_slab(s, flags);
-	return freelist;
-
-deactivate_slab:
-
-	local_lock_cpu_slab(s, flags);
-	if (slab != c->slab) {
-		local_unlock_cpu_slab(s, flags);
-		goto reread_slab;
-	}
-	freelist = c->freelist;
-	c->slab = NULL;
-	c->freelist = NULL;
-	c->tid = next_tid(c->tid);
-	local_unlock_cpu_slab(s, flags);
-	deactivate_slab(s, slab, freelist);
-
-new_slab:
-
-#ifdef CONFIG_SLUB_CPU_PARTIAL
-	while (slub_percpu_partial(c)) {
-		local_lock_cpu_slab(s, flags);
-		if (unlikely(c->slab)) {
-			local_unlock_cpu_slab(s, flags);
-			goto reread_slab;
-		}
-		if (unlikely(!slub_percpu_partial(c))) {
-			local_unlock_cpu_slab(s, flags);
-			/* we were preempted and partial list got empty */
-			goto new_objects;
-		}
-
-		slab = slub_percpu_partial(c);
-		slub_set_percpu_partial(c, slab);
-
-		if (likely(node_match(slab, node) &&
-			   pfmemalloc_match(slab, gfpflags)) ||
-		    !allow_spin) {
-			c->slab = slab;
-			freelist = get_freelist(s, slab);
-			VM_BUG_ON(!freelist);
-			stat(s, CPU_PARTIAL_ALLOC);
-			goto load_freelist;
-		}
-
-		local_unlock_cpu_slab(s, flags);
-
-		slab->next = NULL;
-		__put_partials(s, slab);
-	}
-#endif
-
 new_objects:
 
 	pc.flags = gfpflags;
@@ -4792,12 +4539,12 @@ static void *___slab_alloc(struct kmem_cache *s, gfp_t gfpflags, int node,
 	 * When a preferred node is indicated but no __GFP_THISNODE
 	 *
 	 * 1) try to get a partial slab from target node only by having
-	 *    __GFP_THISNODE in pc.flags for get_partial()
+	 *    __GFP_THISNODE in pc.flags for get_from_partial()
 	 * 2) if 1) failed, try to allocate a new slab from target node with
 	 *    GPF_NOWAIT | __GFP_THISNODE opportunistically
 	 * 3) if 2) failed, retry with original gfpflags which will allow
-	 *    get_partial() try partial lists of other nodes before potentially
-	 *    allocating new page from other nodes
+	 *    get_from_partial() try partial lists of other nodes before
+	 *    potentially allocating new page from other nodes
 	 */
 	if (unlikely(node != NUMA_NO_NODE && !(gfpflags & __GFP_THISNODE)
 		     && try_thisnode)) {
@@ -4809,33 +4556,11 @@ static void *___slab_alloc(struct kmem_cache *s, gfp_t gfpflags, int node,
 	}
 
 	pc.orig_size = orig_size;
-	slab = get_partial(s, node, &pc);
-	if (slab) {
-		if (IS_ENABLED(CONFIG_SLUB_TINY) || kmem_cache_debug(s)) {
-			freelist = pc.object;
-			/*
-			 * For debug caches here we had to go through
-			 * alloc_single_from_partial() so just store the
-			 * tracking info and return the object.
-			 *
-			 * Due to disabled preemption we need to disallow
-			 * blocking. The flags are further adjusted by
-			 * gfp_nested_mask() in stack_depot itself.
-			 */
-			if (s->flags & SLAB_STORE_USER)
-				set_track(s, freelist, TRACK_ALLOC, addr,
-					  gfpflags & ~(__GFP_DIRECT_RECLAIM));
-
-			return freelist;
-		}
-
-		freelist = freeze_slab(s, slab);
-		goto retry_load_slab;
-	}
+	object = get_from_partial(s, node, &pc);
+	if (object)
+		goto success;
 
-	slub_put_cpu_ptr(s->cpu_slab);
 	slab = new_slab(s, pc.flags, node);
-	c = slub_get_cpu_ptr(s->cpu_slab);
 
 	if (unlikely(!slab)) {
 		if (node != NUMA_NO_NODE && !(gfpflags & __GFP_THISNODE)
@@ -4850,70 +4575,31 @@ static void *___slab_alloc(struct kmem_cache *s, gfp_t gfpflags, int node,
 	stat(s, ALLOC_SLAB);
 
 	if (IS_ENABLED(CONFIG_SLUB_TINY) || kmem_cache_debug(s)) {
-		freelist = alloc_single_from_new_slab(s, slab, orig_size, gfpflags);
-
-		if (unlikely(!freelist)) {
-			/* This could cause an endless loop. Fail instead. */
-			if (!allow_spin)
-				return NULL;
-			goto new_objects;
-		}
-
-		if (s->flags & SLAB_STORE_USER)
-			set_track(s, freelist, TRACK_ALLOC, addr,
-				  gfpflags & ~(__GFP_DIRECT_RECLAIM));
-
-		return freelist;
-	}
-
-	/*
-	 * No other reference to the slab yet so we can
-	 * muck around with it freely without cmpxchg
-	 */
-	freelist = slab->freelist;
-	slab->freelist = NULL;
-	slab->inuse = slab->objects;
-	slab->frozen = 1;
+		object = alloc_single_from_new_slab(s, slab, orig_size, gfpflags);
 
-	inc_slabs_node(s, slab_nid(slab), slab->objects);
+		if (likely(object))
+			goto success;
+	} else {
+		alloc_from_new_slab(s, slab, &object, 1, allow_spin);
 
-	if (unlikely(!pfmemalloc_match(slab, gfpflags) && allow_spin)) {
-		/*
-		 * For !pfmemalloc_match() case we don't load freelist so that
-		 * we don't make further mismatched allocations easier.
-		 */
-		deactivate_slab(s, slab, get_freepointer(s, freelist));
-		return freelist;
+		/* we don't need to check SLAB_STORE_USER here */
+		if (likely(object))
+			return object;
 	}
 
-retry_load_slab:
-
-	local_lock_cpu_slab(s, flags);
-	if (unlikely(c->slab)) {
-		void *flush_freelist = c->freelist;
-		struct slab *flush_slab = c->slab;
-
-		c->slab = NULL;
-		c->freelist = NULL;
-		c->tid = next_tid(c->tid);
-
-		local_unlock_cpu_slab(s, flags);
-
-		if (unlikely(!allow_spin)) {
-			/* Reentrant slub cannot take locks, defer */
-			defer_deactivate_slab(flush_slab, flush_freelist);
-		} else {
-			deactivate_slab(s, flush_slab, flush_freelist);
-		}
+	if (allow_spin)
+		goto new_objects;
 
-		stat(s, CPUSLAB_FLUSH);
+	/* This could cause an endless loop. Fail instead. */
+	return NULL;
 
-		goto retry_load_slab;
-	}
-	c->slab = slab;
+success:
+	if (kmem_cache_debug_flags(s, SLAB_STORE_USER))
+		set_track(s, object, TRACK_ALLOC, addr, gfpflags);
 
-	goto load_freelist;
+	return object;
 }
+
 /*
  * We disallow kprobes in ___slab_alloc() to prevent reentrance
  *
@@ -4928,87 +4614,11 @@ static void *___slab_alloc(struct kmem_cache *s, gfp_t gfpflags, int node,
  */
 NOKPROBE_SYMBOL(___slab_alloc);
 
-/*
- * A wrapper for ___slab_alloc() for contexts where preemption is not yet
- * disabled. Compensates for possible cpu changes by refetching the per cpu area
- * pointer.
- */
-static void *__slab_alloc(struct kmem_cache *s, gfp_t gfpflags, int node,
-			  unsigned long addr, struct kmem_cache_cpu *c, unsigned int orig_size)
-{
-	void *p;
-
-#ifdef CONFIG_PREEMPT_COUNT
-	/*
-	 * We may have been preempted and rescheduled on a different
-	 * cpu before disabling preemption. Need to reload cpu area
-	 * pointer.
-	 */
-	c = slub_get_cpu_ptr(s->cpu_slab);
-#endif
-	if (unlikely(!gfpflags_allow_spinning(gfpflags))) {
-		if (local_lock_is_locked(&s->cpu_slab->lock)) {
-			/*
-			 * EBUSY is an internal signal to kmalloc_nolock() to
-			 * retry a different bucket. It's not propagated
-			 * to the caller.
-			 */
-			p = ERR_PTR(-EBUSY);
-			goto out;
-		}
-	}
-	p = ___slab_alloc(s, gfpflags, node, addr, c, orig_size);
-out:
-#ifdef CONFIG_PREEMPT_COUNT
-	slub_put_cpu_ptr(s->cpu_slab);
-#endif
-	return p;
-}
-
 static __always_inline void *__slab_alloc_node(struct kmem_cache *s,
 		gfp_t gfpflags, int node, unsigned long addr, size_t orig_size)
 {
-	struct kmem_cache_cpu *c;
-	struct slab *slab;
-	unsigned long tid;
 	void *object;
 
-redo:
-	/*
-	 * Must read kmem_cache cpu data via this cpu ptr. Preemption is
-	 * enabled. We may switch back and forth between cpus while
-	 * reading from one cpu area. That does not matter as long
-	 * as we end up on the original cpu again when doing the cmpxchg.
-	 *
-	 * We must guarantee that tid and kmem_cache_cpu are retrieved on the
-	 * same cpu. We read first the kmem_cache_cpu pointer and use it to read
-	 * the tid. If we are preempted and switched to another cpu between the
-	 * two reads, it's OK as the two are still associated with the same cpu
-	 * and cmpxchg later will validate the cpu.
-	 */
-	c = raw_cpu_ptr(s->cpu_slab);
-	tid = READ_ONCE(c->tid);
-
-	/*
-	 * Irqless object alloc/free algorithm used here depends on sequence
-	 * of fetching cpu_slab's data. tid should be fetched before anything
-	 * on c to guarantee that object and slab associated with previous tid
-	 * won't be used with current tid. If we fetch tid first, object and
-	 * slab could be one associated with next tid and our alloc/free
-	 * request will be failed. In this case, we will retry. So, no problem.
-	 */
-	barrier();
-
-	/*
-	 * The transaction ids are globally unique per cpu and per operation on
-	 * a per cpu queue. Thus they can be guarantee that the cmpxchg_double
-	 * occurs on the right processor and that there was no operation on the
-	 * linked list in between.
-	 */
-
-	object = c->freelist;
-	slab = c->slab;
-
 #ifdef CONFIG_NUMA
 	if (static_branch_unlikely(&strict_numa) &&
 			node == NUMA_NO_NODE) {
@@ -5017,47 +4627,20 @@ static __always_inline void *__slab_alloc_node(struct kmem_cache *s,
 
 		if (mpol) {
 			/*
-			 * Special BIND rule support. If existing slab
+			 * Special BIND rule support. If the local node
 			 * is in permitted set then do not redirect
 			 * to a particular node.
 			 * Otherwise we apply the memory policy to get
 			 * the node we need to allocate on.
 			 */
-			if (mpol->mode != MPOL_BIND || !slab ||
-					!node_isset(slab_nid(slab), mpol->nodes))
-
+			if (mpol->mode != MPOL_BIND ||
+					!node_isset(numa_mem_id(), mpol->nodes))
 				node = mempolicy_slab_node();
 		}
 	}
 #endif
 
-	if (!USE_LOCKLESS_FAST_PATH() ||
-	    unlikely(!object || !slab || !node_match(slab, node))) {
-		object = __slab_alloc(s, gfpflags, node, addr, c, orig_size);
-	} else {
-		void *next_object = get_freepointer_safe(s, object);
-
-		/*
-		 * The cmpxchg will only match if there was no additional
-		 * operation and if we are on the right processor.
-		 *
-		 * The cmpxchg does the following atomically (without lock
-		 * semantics!)
-		 * 1. Relocate first pointer to the current per cpu area.
-		 * 2. Verify that tid and freelist have not been changed
-		 * 3. If they were not changed replace tid and freelist
-		 *
-		 * Since this is without lock semantics the protection is only
-		 * against code executing on this cpu *not* from access by
-		 * other cpus.
-		 */
-		if (unlikely(!__update_cpu_freelist_fast(s, object, next_object, tid))) {
-			note_cmpxchg_failure("slab_alloc", s, tid);
-			goto redo;
-		}
-		prefetch_freepointer(s, next_object);
-		stat(s, ALLOC_FASTPATH);
-	}
+	object = ___slab_alloc(s, gfpflags, node, addr, orig_size);
 
 	return object;
 }
@@ -7739,62 +7322,25 @@ static inline
 int __kmem_cache_alloc_bulk(struct kmem_cache *s, gfp_t flags, size_t size,
 			    void **p)
 {
-	struct kmem_cache_cpu *c;
-	unsigned long irqflags;
 	int i;
 
 	/*
-	 * Drain objects in the per cpu slab, while disabling local
-	 * IRQs, which protects against PREEMPT and interrupts
-	 * handlers invoking normal fastpath.
+	 * TODO: this might be more efficient (if necessary) by reusing
+	 * __refill_objects()
 	 */
-	c = slub_get_cpu_ptr(s->cpu_slab);
-	local_lock_irqsave(&s->cpu_slab->lock, irqflags);
-
 	for (i = 0; i < size; i++) {
-		void *object = c->freelist;
-
-		if (unlikely(!object)) {
-			/*
-			 * We may have removed an object from c->freelist using
-			 * the fastpath in the previous iteration; in that case,
-			 * c->tid has not been bumped yet.
-			 * Since ___slab_alloc() may reenable interrupts while
-			 * allocating memory, we should bump c->tid now.
-			 */
-			c->tid = next_tid(c->tid);
-
-			local_unlock_irqrestore(&s->cpu_slab->lock, irqflags);
-
-			/*
-			 * Invoking slow path likely have side-effect
-			 * of re-populating per CPU c->freelist
-			 */
-			p[i] = ___slab_alloc(s, flags, NUMA_NO_NODE,
-					    _RET_IP_, c, s->object_size);
-			if (unlikely(!p[i]))
-				goto error;
-
-			c = this_cpu_ptr(s->cpu_slab);
-			maybe_wipe_obj_freeptr(s, p[i]);
 
-			local_lock_irqsave(&s->cpu_slab->lock, irqflags);
+		p[i] = ___slab_alloc(s, flags, NUMA_NO_NODE, _RET_IP_,
+				     s->object_size);
+		if (unlikely(!p[i]))
+			goto error;
 
-			continue; /* goto for-loop */
-		}
-		c->freelist = get_freepointer(s, object);
-		p[i] = object;
 		maybe_wipe_obj_freeptr(s, p[i]);
-		stat(s, ALLOC_FASTPATH);
 	}
-	c->tid = next_tid(c->tid);
-	local_unlock_irqrestore(&s->cpu_slab->lock, irqflags);
-	slub_put_cpu_ptr(s->cpu_slab);
 
 	return i;
 
 error:
-	slub_put_cpu_ptr(s->cpu_slab);
 	__kmem_cache_free_bulk(s, i, p);
 	return 0;
 

-- 
2.52.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20260123-sheaves-for-all-v4-11-041323d506f7%40suse.cz.
