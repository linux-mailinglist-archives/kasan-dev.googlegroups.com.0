Return-Path: <kasan-dev+bncBDXYDPH3S4OBBLEBX2VQMGQEP2IJNAI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13b.google.com (mail-il1-x13b.google.com [IPv6:2607:f8b0:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id 8EFF8805EE9
	for <lists+kasan-dev@lfdr.de>; Tue,  5 Dec 2023 20:57:34 +0100 (CET)
Received: by mail-il1-x13b.google.com with SMTP id e9e14a558f8ab-35d6c0983e1sf28848495ab.0
        for <lists+kasan-dev@lfdr.de>; Tue, 05 Dec 2023 11:57:34 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1701806253; cv=pass;
        d=google.com; s=arc-20160816;
        b=SNTfQnnOf23JbRy/B56ndcQMhDlJEQMqlqw+BktY/vd7FJ7QFgoxNBjN1fN8T6cAXR
         Pty8U/8DW0emwmkO5vd37tSkd0DLk5XGok7vRrjRLdL5o1FNaV1+/wTjA+y05UnTAUyC
         VHYfmQHo83Yp72ud4ywuOv+KJP9/3zA58Qqn9mwcQBUjt8nbwoCjrt3McKgijDCF+d0D
         GZjHPFpwnK/sVUagTkxLXJJZH8VqM8lhuD8JvvI9No64+mjup7UlEStdkrrCIROiXGe9
         /m9XUIbHjagREwNllZsOdznMr9g6Xv76ruQf8A+9QAmCrPBUueHqmER4n0MdbxBWSr4D
         BKlA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=p9WaN9edzzNJQj8hbjqvwxhl20HApj8NTuKvYt5sQhY=;
        fh=9X7yEfYxJ/tFgIQ5VFuCUNBLLeevXlUaPxar/RtzLRg=;
        b=ym7nYe2d9j5AomkA63yR7XEdni8GAb7uVRVEf931/nROcVDtvkBhdjWBQk3/FcYzV1
         A082grw3bMpoSlUIHe7j6mJ+Lhs+eqCxwXHkMRNa0F914CF1iqNtDJ3v4jvh9+/u1PoG
         /XzVP1xX0F4e/bPSskRdqSdqc9pZiGMtIzjF8Azd8lMlLfiV5zVUrrSCndsIxbuiASzb
         ZYo+1X6y9RsjFANi7v7h1Bdgkm0wenqfACEEjOmsIedojIbMSOtbDDU7OdhObZtzgB4P
         DVHuw5N9bY92gKMsQJKoQzi0TfAhkhDaPGv85UnbI7QLCHg/MmRSwvKPJ3IjFMvi3zv1
         EZXA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1701806253; x=1702411053; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=p9WaN9edzzNJQj8hbjqvwxhl20HApj8NTuKvYt5sQhY=;
        b=JxMqYjvbO5KWVqTv0ONFixW82bKFgH7S+QLAFbCflu4R9f5uO58aPOqjhbYCfwlR0U
         nOG/v+/mpjTl0MqHbtbZt3I/7gqJdYpEaNWg8FvJr/blewzetd7ctE9fC/sbGxZLI1EE
         KNzOXEjorxoGYL87wKGkgJZryQS5LGxPZv74cLAdjtZdtHFEdEWSVyNnmJQCYiUV4Dhh
         1TtLglkG/n0PffsAE1fLAiaIRqWMJ+8l1aQTYXNDpsYq7KepELJ9RbvFBpcyKxT+jRju
         S4KtV2fmTi7eS7nTC2SAdowaJBEX+IhJFI4FBJOauXZNg0MtLM491vLv3HA1gLfxbyY1
         NrRQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1701806253; x=1702411053;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=p9WaN9edzzNJQj8hbjqvwxhl20HApj8NTuKvYt5sQhY=;
        b=lBzmy/+zqV4KqPXFTalW1YS0qW//e3F2vfU3Jj5IdnHWJ1+IIGkx2crVQ0L3P3Nehe
         CKONiygA6cKkV8E6JQL1cpaeaHRaSf32zB2101Ta6xbfqka/Pcvya5o2wjIZ/kH83dGV
         PNAtbfGjafvBhR61ki3Q6R/X8+LG2Uq6yR5lCpufuhEy6b703yPXsKFXkqyykOQt1N+U
         WOi8zcfuaVllFBUGWQJifK8WOBjTnEuUZltUY+HopnyINtzR7pYa2TSuf2eccLPKaMaU
         JyXAoLRPooFqPn7wfXXJ7SEknePB5PCLwxxBAcOQU5rN7PTl//5dI1NSl5LPcwmHyYrU
         h1hQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YxC2DgkY+eQGEjKEWyhhcZvE8RNTZanP9IXSwjRaQ/qD69KsPvZ
	KxN+J5/K8PmVJrQzoXVxNQU=
X-Google-Smtp-Source: AGHT+IEvTI6RrtM33PF83viKiTGUOEhg+sRP1G5DqNSVDfZmR1aUUg7Q1vxlnA/BQWwCPmPgiVCXxA==
X-Received: by 2002:a92:520d:0:b0:357:fa1b:48d with SMTP id g13-20020a92520d000000b00357fa1b048dmr4345356ilb.25.1701806253010;
        Tue, 05 Dec 2023 11:57:33 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:1a27:b0:35c:8345:23ef with SMTP id
 g7-20020a056e021a2700b0035c834523efls4135768ile.0.-pod-prod-03-us; Tue, 05
 Dec 2023 11:57:32 -0800 (PST)
X-Received: by 2002:a05:6e02:e51:b0:35d:59a2:bbd with SMTP id l17-20020a056e020e5100b0035d59a20bbdmr3417713ilk.83.1701806251772;
        Tue, 05 Dec 2023 11:57:31 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1701806251; cv=none;
        d=google.com; s=arc-20160816;
        b=RDnSbBVcNYiHLK2tg7NS2BCb4p+JuTaHKswpKEdZmPIWJlK2jhsF2DXnTfW3zzIMNv
         VrMikvAaJog9Lu8cEYo3o86faur07OIvSZWoY/j/IK5YlgxIaoQyKktgfn2C+/kCVP90
         +LHd0KQ/Wpamfey7eh5gKPKTUnAH6YEz1cScVHGG5l6xEUNrI80qcFZh0utXCuz1lbrC
         l+4g2UPYWDfsegT6JPtQ4OdsCjg/2BfvklErJUkbl2jIgmArOLHLmK0ZvSxLdEqRliJb
         2+SnLKWqEVCG7vZX3PK/IlF3GOD4SLWWkfBY6Zl8NSw2EGlaOeqcZdgOTybOiDJZROPh
         30nA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id;
        bh=LhIG1fVzDNglHsiKr4yk9WQ8XF7B2IJ11t7fkuXrPoQ=;
        fh=9X7yEfYxJ/tFgIQ5VFuCUNBLLeevXlUaPxar/RtzLRg=;
        b=yfcsyckeb5DEbIVnHWd9+Tb5xbcvYnQRtUYQ8CRYI2i5bX65DHtXKjYSSjje+KpYTc
         V+BnbOzt6epMBObM8533wUINWLtParwRBrUWSnaNvvRpoT7E5ee+3tnSWJR27tJhJ/Km
         FOh74fpk0fw/qyzxWpdOi1QB3J4tpRt9OB42A6/V+DZLNm+ZlK7Nl+GNXcEt9hMKVkgO
         JYSGdFmvQsVDzdBOl4yYOa7Wvy46L900QLj2B2SCRmdPF4oSG0S8m7A1005WfFqGbYIb
         6l1Oz5pgDkd9IVvyE5z0ZogeVgQUzc0/OPWNXss0v9vTPqZRoV48cYGcY80ZVwIX+J1u
         O8Ow==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [2a07:de40:b251:101:10:150:64:2])
        by gmr-mx.google.com with ESMTPS id e16-20020a02a790000000b004667fd6f6besi845189jaj.5.2023.12.05.11.57.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 05 Dec 2023 11:57:31 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) client-ip=2a07:de40:b251:101:10:150:64:2;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [IPv6:2a07:de40:b281:104:10:150:64:97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id 19C301FBB0;
	Tue,  5 Dec 2023 19:57:30 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id EA5051386E;
	Tue,  5 Dec 2023 19:57:29 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id MMEmOKmAb2UkRwAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Tue, 05 Dec 2023 19:57:29 +0000
Message-ID: <25eb93ee-e71a-c257-ef4b-9fbb3b694faf@suse.cz>
Date: Tue, 5 Dec 2023 20:57:29 +0100
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101
 Thunderbird/102.15.1
Subject: Re: [PATCH 2/4] mm/slub: introduce __kmem_cache_free_bulk() without
 free hooks
Content-Language: en-US
To: Chengming Zhou <chengming.zhou@linux.dev>,
 Christoph Lameter <cl@linux.com>, Pekka Enberg <penberg@kernel.org>,
 David Rientjes <rientjes@google.com>, Joonsoo Kim <iamjoonsoo.kim@lge.com>
Cc: Andrew Morton <akpm@linux-foundation.org>,
 Roman Gushchin <roman.gushchin@linux.dev>,
 Hyeonggon Yoo <42.hyeyoo@gmail.com>, Alexander Potapenko
 <glider@google.com>, Marco Elver <elver@google.com>,
 Dmitry Vyukov <dvyukov@google.com>, linux-mm@kvack.org,
 linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com
References: <20231204-slub-cleanup-hooks-v1-0-88b65f7cd9d5@suse.cz>
 <20231204-slub-cleanup-hooks-v1-2-88b65f7cd9d5@suse.cz>
 <30f88452-740b-441f-bb4f-a2d946e35cf5@linux.dev>
From: Vlastimil Babka <vbabka@suse.cz>
In-Reply-To: <30f88452-740b-441f-bb4f-a2d946e35cf5@linux.dev>
Content-Type: text/plain; charset="UTF-8"
X-Spam-Level: *********
X-Spamd-Bar: +++++++++
X-Rspamd-Server: rspamd2
X-Spamd-Result: default: False [9.41 / 50.00];
	 RCVD_VIA_SMTP_AUTH(0.00)[];
	 ARC_NA(0.00)[];
	 MID_RHS_MATCH_FROM(0.00)[];
	 FROM_HAS_DN(0.00)[];
	 TO_DN_SOME(0.00)[];
	 FREEMAIL_ENVRCPT(0.00)[gmail.com];
	 TO_MATCH_ENVRCPT_ALL(0.00)[];
	 TAGGED_RCPT(0.00)[];
	 MIME_GOOD(-0.10)[text/plain];
	 DMARC_NA(1.20)[suse.cz];
	 R_SPF_SOFTFAIL(4.60)[~all];
	 BAYES_HAM(-2.85)[99.35%];
	 RCVD_COUNT_THREE(0.00)[3];
	 NEURAL_SPAM_SHORT(2.86)[0.955];
	 MX_GOOD(-0.01)[];
	 RCPT_COUNT_TWELVE(0.00)[14];
	 FUZZY_BLOCKED(0.00)[rspamd.com];
	 FROM_EQ_ENVFROM(0.00)[];
	 R_DKIM_NA(2.20)[];
	 MIME_TRACE(0.00)[0:+];
	 FREEMAIL_CC(0.00)[linux-foundation.org,linux.dev,gmail.com,google.com,kvack.org,vger.kernel.org,googlegroups.com];
	 RCVD_TLS_ALL(0.00)[];
	 SUSPICIOUS_RECIPS(1.50)[]
X-Spam-Score: 9.41
X-Rspamd-Queue-Id: 19C301FBB0
X-Spam-Flag: NO
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2
 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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

On 12/5/23 09:19, Chengming Zhou wrote:
> On 2023/12/5 03:34, Vlastimil Babka wrote:
>> Currently, when __kmem_cache_alloc_bulk() fails, it frees back the
>> objects that were allocated before the failure, using
>> kmem_cache_free_bulk(). Because kmem_cache_free_bulk() calls the free
>> hooks (KASAN etc.) and those expect objects that were processed by the
>> post alloc hooks, slab_post_alloc_hook() is called before
>> kmem_cache_free_bulk().
>> 
>> This is wasteful, although not a big concern in practice for the rare
>> error path. But in order to efficiently handle percpu array batch refill
>> and free in the near future, we will also need a variant of
>> kmem_cache_free_bulk() that avoids the free hooks. So introduce it now
>> and use it for the failure path.
>> 
>> As a consequence, __kmem_cache_alloc_bulk() no longer needs the objcg
>> parameter, remove it.
> 
> The objects may have been charged before, but it seems __kmem_cache_alloc_bulk()
> forget to uncharge them? I can't find "uncharge" in do_slab_free(), or maybe
> the bulk interface won't be used on chargeable slab?

You're right! I missed that the memcg_pre_alloc_hook() already does the
charging, so we need to uncharge. How does this look? Thanks for noticing!

----8<----
From 52f8e77fdfeabffffdce6b761ba5508e940df3be Mon Sep 17 00:00:00 2001
From: Vlastimil Babka <vbabka@suse.cz>
Date: Thu, 2 Nov 2023 16:34:39 +0100
Subject: [PATCH 2/4] mm/slub: introduce __kmem_cache_free_bulk() without free
 hooks

Currently, when __kmem_cache_alloc_bulk() fails, it frees back the
objects that were allocated before the failure, using
kmem_cache_free_bulk(). Because kmem_cache_free_bulk() calls the free
hooks (KASAN etc.) and those expect objects that were processed by the
post alloc hooks, slab_post_alloc_hook() is called before
kmem_cache_free_bulk().

This is wasteful, although not a big concern in practice for the rare
error path. But in order to efficiently handle percpu array batch refill
and free in the near future, we will also need a variant of
kmem_cache_free_bulk() that avoids the free hooks. So introduce it now
and use it for the failure path.

In case of failure we however still need to perform memcg uncharge so
handle that in a new memcg_slab_alloc_error_hook(). Thanks to Chengming
Zhou for noticing the missing uncharge.

As a consequence, __kmem_cache_alloc_bulk() no longer needs the objcg
parameter, remove it.

Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
---
 mm/slub.c | 56 ++++++++++++++++++++++++++++++++++++++++++++++---------
 1 file changed, 47 insertions(+), 9 deletions(-)

diff --git a/mm/slub.c b/mm/slub.c
index d7b0ca6012e0..0a9e4bd0dd68 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -2003,6 +2003,14 @@ void memcg_slab_free_hook(struct kmem_cache *s, struct slab *slab, void **p,
 
 	__memcg_slab_free_hook(s, slab, p, objects, objcgs);
 }
+
+static inline
+void memcg_slab_alloc_error_hook(struct kmem_cache *s, int objects,
+			   struct obj_cgroup *objcg)
+{
+	if (objcg)
+		obj_cgroup_uncharge(objcg, objects * obj_full_size(s));
+}
 #else /* CONFIG_MEMCG_KMEM */
 static inline struct mem_cgroup *memcg_from_slab_obj(void *ptr)
 {
@@ -2032,6 +2040,12 @@ static inline void memcg_slab_free_hook(struct kmem_cache *s, struct slab *slab,
 					void **p, int objects)
 {
 }
+
+static inline
+void memcg_slab_alloc_error_hook(struct kmem_cache *s, int objects,
+				 struct obj_cgroup *objcg)
+{
+}
 #endif /* CONFIG_MEMCG_KMEM */
 
 /*
@@ -4478,6 +4492,27 @@ int build_detached_freelist(struct kmem_cache *s, size_t size,
 	return same;
 }
 
+/*
+ * Internal bulk free of objects that were not initialised by the post alloc
+ * hooks and thus should not be processed by the free hooks
+ */
+static void __kmem_cache_free_bulk(struct kmem_cache *s, size_t size, void **p)
+{
+	if (!size)
+		return;
+
+	do {
+		struct detached_freelist df;
+
+		size = build_detached_freelist(s, size, p, &df);
+		if (!df.slab)
+			continue;
+
+		do_slab_free(df.s, df.slab, df.freelist, df.tail, df.cnt,
+			     _RET_IP_);
+	} while (likely(size));
+}
+
 /* Note that interrupts must be enabled when calling this function. */
 void kmem_cache_free_bulk(struct kmem_cache *s, size_t size, void **p)
 {
@@ -4498,8 +4533,9 @@ void kmem_cache_free_bulk(struct kmem_cache *s, size_t size, void **p)
 EXPORT_SYMBOL(kmem_cache_free_bulk);
 
 #ifndef CONFIG_SLUB_TINY
-static inline int __kmem_cache_alloc_bulk(struct kmem_cache *s, gfp_t flags,
-			size_t size, void **p, struct obj_cgroup *objcg)
+static inline
+int __kmem_cache_alloc_bulk(struct kmem_cache *s, gfp_t flags, size_t size,
+			    void **p)
 {
 	struct kmem_cache_cpu *c;
 	unsigned long irqflags;
@@ -4563,14 +4599,13 @@ static inline int __kmem_cache_alloc_bulk(struct kmem_cache *s, gfp_t flags,
 
 error:
 	slub_put_cpu_ptr(s->cpu_slab);
-	slab_post_alloc_hook(s, objcg, flags, i, p, false, s->object_size);
-	kmem_cache_free_bulk(s, i, p);
+	__kmem_cache_free_bulk(s, i, p);
 	return 0;
 
 }
 #else /* CONFIG_SLUB_TINY */
 static int __kmem_cache_alloc_bulk(struct kmem_cache *s, gfp_t flags,
-			size_t size, void **p, struct obj_cgroup *objcg)
+				   size_t size, void **p)
 {
 	int i;
 
@@ -4593,8 +4628,7 @@ static int __kmem_cache_alloc_bulk(struct kmem_cache *s, gfp_t flags,
 	return i;
 
 error:
-	slab_post_alloc_hook(s, objcg, flags, i, p, false, s->object_size);
-	kmem_cache_free_bulk(s, i, p);
+	__kmem_cache_free_bulk(s, i, p);
 	return 0;
 }
 #endif /* CONFIG_SLUB_TINY */
@@ -4614,15 +4648,19 @@ int kmem_cache_alloc_bulk(struct kmem_cache *s, gfp_t flags, size_t size,
 	if (unlikely(!s))
 		return 0;
 
-	i = __kmem_cache_alloc_bulk(s, flags, size, p, objcg);
+	i = __kmem_cache_alloc_bulk(s, flags, size, p);
 
 	/*
 	 * memcg and kmem_cache debug support and memory initialization.
 	 * Done outside of the IRQ disabled fastpath loop.
 	 */
-	if (i != 0)
+	if (likely(i != 0)) {
 		slab_post_alloc_hook(s, objcg, flags, size, p,
 			slab_want_init_on_alloc(flags, s), s->object_size);
+	} else {
+		memcg_slab_alloc_error_hook(s, size, objcg);
+	}
+
 	return i;
 }
 EXPORT_SYMBOL(kmem_cache_alloc_bulk);
-- 
2.43.0


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/25eb93ee-e71a-c257-ef4b-9fbb3b694faf%40suse.cz.
