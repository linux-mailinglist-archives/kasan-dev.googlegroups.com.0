Return-Path: <kasan-dev+bncBDXYDPH3S4OBBXHG5DDQMGQE5XTU4RY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x63e.google.com (mail-ej1-x63e.google.com [IPv6:2a00:1450:4864:20::63e])
	by mail.lfdr.de (Postfix) with ESMTPS id F2F4FC01909
	for <lists+kasan-dev@lfdr.de>; Thu, 23 Oct 2025 15:53:33 +0200 (CEST)
Received: by mail-ej1-x63e.google.com with SMTP id a640c23a62f3a-b5bd7e8736bsf14352066b.0
        for <lists+kasan-dev@lfdr.de>; Thu, 23 Oct 2025 06:53:33 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1761227613; cv=pass;
        d=google.com; s=arc-20240605;
        b=c7WSrKS3zQJoaRSaWHtBeXJG+8WfxcSehlOYQtkjzq/FrpkYn7ckvmxzVf6tnUezaS
         vvzzlJ8lAu/9a/5QexcbaicjJuTpCtECC8YvRn9pGNL7XShlS41TnN67qcUWoK2brTQ6
         h4duXFsmmKWIxzIfrdqz6nmWqxMszmUANXRCYMsyuAGnN478UhgyT+RR/OMW24p3K4DU
         S/FNdrKj1fBIVyUnmp7lXtungGABfbc+dGTWqgk8bGvyiKEEs8G6YzBoQlEAvmvCwsYQ
         vx0Pb1VPjE95m7SOnComODIYvlmn+unBOpRHbGOTsi/4joq8ll8KbPEseaestXAz19xH
         TLXg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:in-reply-to:references
         :message-id:mime-version:subject:date:from:sender:dkim-signature;
        bh=tgWSwKrNuzjeFDG7uz2LiBqDKX4L76lwaTK/oXFQQSw=;
        fh=Fs0eM9H9/3427E8isitw91Tot4tVDzU/+NxDfMt7jIg=;
        b=eauuUfPZp+u8TUbCKMlIc467Xa8I7AaNIt1/8g2tFAc11L9PdgkKfDNTpevGQoyywB
         L6RHiw4Q6gZM34xsyHyQ5nJd0u5FGIPIUPIoYUpFnkUaRO38iI4pm4e0DoFVQjVgrhC1
         BF//J2cJCy7dZVRVuN9w4KoyqnKAUBZqJa2I+dZOydV8Squ5WSClxvyOtNK8+Iw+OngC
         pDah20d8b86ZEzNYflqHlwlc+cIENKV37S0fijpOZ8GWQ+vQYUttWOZxF5UTi/JDO9vG
         N3wmfvjCa6RsnOFpxzp4g+DMX7Reim2dpjBkaM5SMUdRgUD14O6xvosVBVHtx2tZ4N00
         C2eA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=cZm6O1A6;
       dkim=neutral (no key) header.i=@suse.cz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=ZFs7Go34;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1761227613; x=1761832413; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:in-reply-to:references:message-id
         :mime-version:subject:date:from:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=tgWSwKrNuzjeFDG7uz2LiBqDKX4L76lwaTK/oXFQQSw=;
        b=ardfTYeBIfnEdEOGCos32a0nleuu91PmCvI4Pk0h4H5Wt73Tb1g1upTMQIsot5UunD
         xEu4YJ7rj1/OabXrvV/P6KtrrP80PdIbCyZBkWDtSY7uRmZCZJ3LQVotwz/yVInAKRRi
         uAEv0v+e4ragD+ki1GFVIC51+0aQ9LB021NwQp7r51YjHC9piIM9luKPTgGjwC0/cilV
         zKy/edxVhOE+Brk2N9iCZ+IWOY8ZGishWd/vDY7Z6QPu3gFxqI52CJ6DES5itJkKfM6R
         bXouxY1EhNB79kTG/xQDKWbAkNaee4TxGNswsQAMQKMTy3MRJImcCqX2cFnT2+aB4uMv
         343Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1761227613; x=1761832413;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to
         :in-reply-to:references:message-id:mime-version:subject:date:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=tgWSwKrNuzjeFDG7uz2LiBqDKX4L76lwaTK/oXFQQSw=;
        b=qPw1y9ExOEeI1vpal1StTr9AzWznSdB3d0hri/LX4YNuIUAQyE/M5FUl0cFvu1x0b+
         AaCFADBidmXqPzGbRaun8IUZV3rNmpYRNX3PgllfKjR0iXz1BEzvoDMZF0L0dB1CFb41
         xM2FD2hDeHQOLGPPr8r4kKHqbVlpg/xaP3d1RFz7Bg7yFc7MRrgUcOvA0k3p694X6KPY
         zme6Gih1mooRiLsj1KQwUQaWpP6zlFMKd/Xko+xYMLUStEu50nfCmHd3j2x35byBN89r
         HiW5ZDpthjTjmbP9y27K8tfl3fQPdLDPA4s9AsaCtjjQceglgCL5nNzMKpMoeuv4iXsV
         9wPQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUCRmB5SvK0pEVerMfj5z4XJTG9N1yodQZKZ8KTW7Y1XY25amuy3PseXonpdZOdLeTGbvyOzg==@lfdr.de
X-Gm-Message-State: AOJu0Yxy560BBv4cQiX3fdX/Tz7MHS78s6aTX6UgNzGwkaome/a0FCH1
	DdpSA+grh0PwDZIr6oeSuUtstIVpVtDrMHXjRenseXrZnwz6mjdJE4ai
X-Google-Smtp-Source: AGHT+IHTUYUjaHEP9uq1oWU8xSWWoGy1lG6zeJM/IhSvIgZGMcWA/e9byCNKDZ+5XbgoPjvuKks6XA==
X-Received: by 2002:a05:6402:40d2:b0:637:e5dd:ef81 with SMTP id 4fb4d7f45d1cf-63d2404895emr6368189a12.8.1761227613369;
        Thu, 23 Oct 2025 06:53:33 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="ARHlJd4DD8sp2pshCEaboSDxTnnn4HYO5uKRITYEmXEeplQMWg=="
Received: by 2002:a05:6402:20d5:20b0:63c:159e:759f with SMTP id
 4fb4d7f45d1cf-63e3eb6a141ls381560a12.1.-pod-prod-00-eu; Thu, 23 Oct 2025
 06:53:30 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVtiDF5Dl0QKEBlLXOdvaKEd6I24RD778L0wMJeHJLKrs0ruopc7M3UwUj+axZbWF+wiznTbMt00VI=@googlegroups.com
X-Received: by 2002:a05:6402:1d52:b0:63b:ee76:3f63 with SMTP id 4fb4d7f45d1cf-63e172b389emr7212883a12.7.1761227610332;
        Thu, 23 Oct 2025 06:53:30 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1761227610; cv=none;
        d=google.com; s=arc-20240605;
        b=aMjOdufU54cd7zAn9Xv+3QIHk55BOL3WOCu9I0m6i1Y8xIdJ0CB16g33iZTHKewd4f
         hMxkoHpPHyitoWbH1tkIzxn4yKOwEDP8lm2Nc5Xk2ewnltG8lb8ogS0tdE3UefIrcU8j
         /A75KByYpQEBSiOEEU/JEYEYQ9c/uQ/BDLi8LOJzGhNjF56BmDlUuz/YpXBUr5eE/yoj
         05bu3jZmqdpFu8hS5PwvxpK3LoEgEkgctrqHeTfYJQfn85O9SZLAk/H63nqLZWD18wcW
         lw8hSf5swfcXQU2zoE7/LjMQVu7QgbXg7yIbV63rkezVkv9TiA8KD9davsEqNNxLX/vY
         FuDQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:in-reply-to:references:message-id:content-transfer-encoding
         :mime-version:subject:date:from:dkim-signature:dkim-signature
         :dkim-signature:dkim-signature;
        bh=TglC9ZZ5FVFxD2QhacSyfGZQOaO+qN5KAuegpPVCrcs=;
        fh=P0r4/dMJvcdpdyMOyJR1abGuGu+lkksl0rleFR28jng=;
        b=X6F6TFG4lWqiextKl/dYUcJGy+VxfD+8KkhJh2HosXTbHUsHX6bVI2XFrezrBBKENd
         uUcqziyTUZpbliKRFIn4S402v7Ro+CgLOj0rCg1zVADgHr0Q6xLzZ3VdNN5X/tTvL7UE
         Lux9c0ym4OKwaMqO1rylc8V8TsZBlNiSoaTsddThMZFdzG6q/WpaSRUgeHNN2GGB3mBq
         EvKbq417CazpPqru8UHbym8V52hANrT75ehJG5xzhjLCiiimbjkQEHmFem7BCP1OB33Y
         7AQW7UyCJrIXwxv/2GcbUOJNofsk1c+hra8otLOAFHE7Pg1m4WkDsNJZT4jco/bBua1D
         av8g==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=cZm6O1A6;
       dkim=neutral (no key) header.i=@suse.cz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=ZFs7Go34;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [2a07:de40:b251:101:10:150:64:1])
        by gmr-mx.google.com with ESMTPS id 4fb4d7f45d1cf-63e3f327707si35547a12.5.2025.10.23.06.53.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 23 Oct 2025 06:53:30 -0700 (PDT)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) client-ip=2a07:de40:b251:101:10:150:64:1;
Received: from imap1.dmz-prg2.suse.org (unknown [10.150.64.97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id 8844D2120C;
	Thu, 23 Oct 2025 13:53:01 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id F3F2D13B08;
	Thu, 23 Oct 2025 13:52:53 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id OCRFOzUz+mjvQQAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Thu, 23 Oct 2025 13:52:53 +0000
From: Vlastimil Babka <vbabka@suse.cz>
Date: Thu, 23 Oct 2025 15:52:32 +0200
Subject: [PATCH RFC 10/19] slab: remove cpu (partial) slabs usage from
 allocation paths
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Message-Id: <20251023-sheaves-for-all-v1-10-6ffa2c9941c0@suse.cz>
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
	DBL_BLOCKED_OPENRESOLVER(0.00)[suse.cz:mid,suse.cz:email,imap1.dmz-prg2.suse.org:helo]
X-Spam-Flag: NO
X-Spam-Score: -8.30
X-Spam-Level: 
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=cZm6O1A6;       dkim=neutral
 (no key) header.i=@suse.cz;       dkim=pass header.i=@suse.cz
 header.s=susede2_rsa header.b=ZFs7Go34;       dkim=neutral (no key)
 header.i=@suse.cz;       spf=pass (google.com: domain of vbabka@suse.cz
 designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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

We now rely on sheaves as the percpu caching layer and can refill them
directly from partial or newly allocated slabs. Start removing the cpu
(partial) slabs code, first from allocation paths.

This means that any allocation not satisfied from percpu sheaves will
end up in ___slab_alloc(), where we remove the usage of cpu (partial)
slabs, so it will only perform get_partial() or new_slab().

In get_partial_node() we used to return a slab for freezing as the cpu
slab and to refill the partial slab. Now we only want to return a single
object and leave the slab on the list (unless it became full). We can't
simply reuse alloc_single_from_partial() as that assumes freeing uses
free_to_partial_list(). Instead we need to use __slab_update_freelist()
to work properly against a racing __slab_free().

The rest of the changes is removing functions that no longer have any
callers.

Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
---
 mm/slub.c | 614 ++++++++------------------------------------------------------
 1 file changed, 71 insertions(+), 543 deletions(-)

diff --git a/mm/slub.c b/mm/slub.c
index e2b052657d11..bd67336e7c1f 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -245,7 +245,6 @@ static DEFINE_STATIC_KEY_FALSE(strict_numa);
 struct partial_context {
 	gfp_t flags;
 	unsigned int orig_size;
-	void *object;
 	unsigned int min_objects;
 	unsigned int max_objects;
 	struct list_head slabs;
@@ -598,36 +597,6 @@ static inline void *get_freepointer(struct kmem_cache *s, void *object)
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
@@ -707,23 +676,11 @@ static void slub_set_cpu_partial(struct kmem_cache *s, unsigned int nr_objects)
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
@@ -1075,7 +1032,7 @@ static void set_track_update(struct kmem_cache *s, void *object,
 	p->handle = handle;
 #endif
 	p->addr = addr;
-	p->cpu = smp_processor_id();
+	p->cpu = raw_smp_processor_id();
 	p->pid = current->pid;
 	p->when = jiffies;
 }
@@ -3575,15 +3532,15 @@ static bool get_partial_node_bulk(struct kmem_cache *s,
 }
 
 /*
- * Try to allocate a partial slab from a specific node.
+ * Try to allocate object from a partial slab on a specific node.
  */
-static struct slab *get_partial_node(struct kmem_cache *s,
-				     struct kmem_cache_node *n,
-				     struct partial_context *pc)
+static void *get_partial_node(struct kmem_cache *s,
+			      struct kmem_cache_node *n,
+			      struct partial_context *pc)
 {
-	struct slab *slab, *slab2, *partial = NULL;
+	struct slab *slab, *slab2;
 	unsigned long flags;
-	unsigned int partial_slabs = 0;
+	void *object;
 
 	/*
 	 * Racy check. If we mistakenly see no partial slabs then we
@@ -3599,54 +3556,54 @@ static struct slab *get_partial_node(struct kmem_cache *s,
 	else if (!spin_trylock_irqsave(&n->list_lock, flags))
 		return NULL;
 	list_for_each_entry_safe(slab, slab2, &n->partial, slab_list) {
+
+		unsigned long counters;
+		struct slab new;
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
-
-		if (!partial) {
-			partial = slab;
-			stat(s, ALLOC_FROM_PARTIAL);
-
-			if ((slub_get_cpu_partial(s) == 0)) {
-				break;
-			}
-		} else {
-			put_cpu_partial(s, slab, 0);
-			stat(s, CPU_PARTIAL_NODE);
-
-			if (++partial_slabs > slub_get_cpu_partial(s) / 2) {
-				break;
-			}
-		}
+		/*
+		 * get a single object from the slab. This might race against
+		 * __slab_free(), which however has to take the list_lock if
+		 * it's about to make the slab fully free.
+		 */
+		do {
+			object = slab->freelist;
+			counters = slab->counters;
+			new.freelist = get_freepointer(s, object);
+			new.counters = counters;
+			new.inuse++;
+		} while (!__slab_update_freelist(s, slab,
+			object, counters,
+			new.freelist, new.counters,
+			"get_partial_node"));
+
+		if (!new.freelist)
+			remove_partial(n, slab);
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
+static void *get_any_partial(struct kmem_cache *s, struct partial_context *pc)
 {
 #ifdef CONFIG_NUMA
 	struct zonelist *zonelist;
 	struct zoneref *z;
 	struct zone *zone;
 	enum zone_type highest_zoneidx = gfp_zone(pc->flags);
-	struct slab *slab;
 	unsigned int cpuset_mems_cookie;
 
 	/*
@@ -3681,8 +3638,8 @@ static struct slab *get_any_partial(struct kmem_cache *s,
 
 			if (n && cpuset_zone_allowed(zone, pc->flags) &&
 					n->nr_partial > s->min_partial) {
-				slab = get_partial_node(s, n, pc);
-				if (slab) {
+				void *object = get_partial_node(s, n, pc);
+				if (object) {
 					/*
 					 * Don't check read_mems_allowed_retry()
 					 * here - if mems_allowed was updated in
@@ -3690,7 +3647,7 @@ static struct slab *get_any_partial(struct kmem_cache *s,
 					 * between allocation and the cpuset
 					 * update
 					 */
-					return slab;
+					return object;
 				}
 			}
 		}
@@ -3700,20 +3657,20 @@ static struct slab *get_any_partial(struct kmem_cache *s,
 }
 
 /*
- * Get a partial slab, lock it and return it.
+ * Get an object from a partial slab
  */
-static struct slab *get_partial(struct kmem_cache *s, int node,
-				struct partial_context *pc)
+static void *get_partial(struct kmem_cache *s, int node,
+			 struct partial_context *pc)
 {
-	struct slab *slab;
 	int searchnode = node;
+	void *object;
 
 	if (node == NUMA_NO_NODE)
 		searchnode = numa_mem_id();
 
-	slab = get_partial_node(s, get_node(s, searchnode), pc);
-	if (slab || (node != NUMA_NO_NODE && (pc->flags & __GFP_THISNODE)))
-		return slab;
+	object = get_partial_node(s, get_node(s, searchnode), pc);
+	if (object || (node != NUMA_NO_NODE && (pc->flags & __GFP_THISNODE)))
+		return object;
 
 	return get_any_partial(s, pc);
 }
@@ -4272,19 +4229,6 @@ static int slub_cpu_dead(unsigned int cpu)
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
@@ -4469,39 +4413,6 @@ __update_cpu_freelist_fast(struct kmem_cache *s,
 					     &old.full, new.full);
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
-	struct slab new;
-	unsigned long counters;
-	void *freelist;
-
-	lockdep_assert_held(this_cpu_ptr(&s->cpu_slab->lock));
-
-	do {
-		freelist = slab->freelist;
-		counters = slab->counters;
-
-		new.counters = counters;
-
-		new.inuse = slab->objects;
-		new.frozen = freelist != NULL;
-
-	} while (!__slab_update_freelist(s, slab,
-		freelist, counters,
-		NULL, new.counters,
-		"get_freelist"));
-
-	return freelist;
-}
-
 /*
  * Get the slab's freelist and do not freeze it.
  *
@@ -4535,197 +4446,23 @@ static inline void *get_freelist_nofreeze(struct kmem_cache *s, struct slab *sla
 }
 
 /*
- * Freeze the partial slab and return the pointer to the freelist.
- */
-static inline void *freeze_slab(struct kmem_cache *s, struct slab *slab)
-{
-	struct slab new;
-	unsigned long counters;
-	void *freelist;
-
-	do {
-		freelist = slab->freelist;
-		counters = slab->counters;
-
-		new.counters = counters;
-		VM_BUG_ON(new.frozen);
-
-		new.inuse = slab->objects;
-		new.frozen = 1;
-
-	} while (!slab_update_freelist(s, slab,
-		freelist, counters,
-		NULL, new.counters,
-		"freeze_slab"));
-
-	return freelist;
-}
-
-/*
- * Slow path. The lockless freelist is empty or we need to perform
- * debugging duties.
- *
- * Processing is still very fast if new objects have been freed to the
- * regular freelist. In that case we simply take over the regular freelist
- * as the lockless freelist and zap the regular freelist.
+ * Slow path. We failed to allocate via percpu sheaves or they are not available
+ * due to bootstrap or debugging enabled or SLUB_TINY.
  *
- * If that is not working then we fall back to the partial lists. We take the
- * first element of the freelist as the object to allocate now and move the
- * rest of the freelist to the lockless freelist.
- *
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
 	void *freelist;
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
@@ -4750,33 +4487,15 @@ static void *___slab_alloc(struct kmem_cache *s, gfp_t gfpflags, int node,
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
+	freelist = get_partial(s, node, &pc);
+	if (freelist) {
+		if (kmem_cache_debug_flags(s, SLAB_STORE_USER))
+			set_track(s, freelist, TRACK_ALLOC, addr, gfpflags);
 
-			return freelist;
-		}
-
-		freelist = freeze_slab(s, slab);
-		goto retry_load_slab;
+		return freelist;
 	}
 
-	slub_put_cpu_ptr(s->cpu_slab);
 	slab = new_slab(s, pc.flags, node);
-	c = slub_get_cpu_ptr(s->cpu_slab);
 
 	if (unlikely(!slab)) {
 		if (node != NUMA_NO_NODE && !(gfpflags & __GFP_THISNODE)
@@ -4790,66 +4509,15 @@ static void *___slab_alloc(struct kmem_cache *s, gfp_t gfpflags, int node,
 
 	stat(s, ALLOC_SLAB);
 
-	if (IS_ENABLED(CONFIG_SLUB_TINY) || kmem_cache_debug(s)) {
-		freelist = alloc_single_from_new_slab(s, slab, orig_size, gfpflags);
-
-		if (unlikely(!freelist))
-			goto new_objects;
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
-
-	inc_slabs_node(s, slab_nid(slab), slab->objects);
+	freelist = alloc_single_from_new_slab(s, slab, orig_size, gfpflags);
 
-	if (unlikely(!pfmemalloc_match(slab, gfpflags) && allow_spin)) {
-		/*
-		 * For !pfmemalloc_match() case we don't load freelist so that
-		 * we don't make further mismatched allocations easier.
-		 */
-		deactivate_slab(s, slab, get_freepointer(s, freelist));
-		return freelist;
-	}
+	if (unlikely(!freelist))
+		goto new_objects;
 
-retry_load_slab:
+	if (kmem_cache_debug_flags(s, SLAB_STORE_USER))
+		set_track(s, freelist, TRACK_ALLOC, addr, gfpflags);
 
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
-
-		stat(s, CPUSLAB_FLUSH);
-
-		goto retry_load_slab;
-	}
-	c->slab = slab;
-
-	goto load_freelist;
+	return freelist;
 }
 /*
  * We disallow kprobes in ___slab_alloc() to prevent reentrance
@@ -4865,87 +4533,11 @@ static void *___slab_alloc(struct kmem_cache *s, gfp_t gfpflags, int node,
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
@@ -4954,47 +4546,20 @@ static __always_inline void *__slab_alloc_node(struct kmem_cache *s,
 
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
@@ -7638,62 +7203,25 @@ static inline
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
 
-		if (unlikely(!object)) {
-			/*
-			 * We may have removed an object from c->freelist using
-			 * the fastpath in the previous iteration; in that case,
-			 * c->tid has not been bumped yet.
-			 * Since ___slab_alloc() may reenable interrupts while
-			 * allocating memory, we should bump c->tid now.
-			 */
-			c->tid = next_tid(c->tid);
+		p[i] = ___slab_alloc(s, flags, NUMA_NO_NODE, _RET_IP_,
+				     s->object_size);
+		if (unlikely(!p[i]))
+			goto error;
 
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
-
-			local_lock_irqsave(&s->cpu_slab->lock, irqflags);
-
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
2.51.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251023-sheaves-for-all-v1-10-6ffa2c9941c0%40suse.cz.
