Return-Path: <kasan-dev+bncBDWLZXP6ZEPRB2XQZOGAMGQESHKUKWA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43e.google.com (mail-wr1-x43e.google.com [IPv6:2a00:1450:4864:20::43e])
	by mail.lfdr.de (Postfix) with ESMTPS id 5319A451C8A
	for <lists+kasan-dev@lfdr.de>; Tue, 16 Nov 2021 01:16:43 +0100 (CET)
Received: by mail-wr1-x43e.google.com with SMTP id d3-20020adfa343000000b0018ed6dd4629sf4073541wrb.2
        for <lists+kasan-dev@lfdr.de>; Mon, 15 Nov 2021 16:16:43 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1637021803; cv=pass;
        d=google.com; s=arc-20160816;
        b=OQ8jTJw8C0qn9Id+HtEPueUT1zzL9YJ/+CF+Ep9Pn8ao3bJQ1oODyW/fBa5FcvZv0s
         nEKZSRW3MoAEa8AEMl3rODZOKnHCAgSCj8mnArY+tWz/p848w8i//II7FZSjMIWLnsw3
         WqN4L9thIFmB8PYFb5ffvt/lJx+JUbthADVAH8a3bqbMAwVpW2GyZKDhgnHOGJDNCb8I
         YK0rWGJX9yK69XcvUprEmnf+0y8O+EjhG9hvWMTh5I9Tcn3CaA2DVKnViKbFoTWL0SzL
         iqeqJFt75Pz3vmJKsAO9HtdFjTB0NwnMT/hBUlmCZ6fvu4DlJWDou0gc31GimrLMbDBf
         A7fQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=2fAuVwAJrB5SDH0kqwPAbeYPaOWs4y96h7DgvqDdVO0=;
        b=BzoO1sD0bB2eevu4S/R9cSoOwp14xrx+6mZI95Kso+Oljt5yR5qjClUocCilGNjYWr
         bhb0sSu90aMqiEHq6xPxKCfye/BSaL0Oe9Qkb6RbDfijcJ7a64mM1z31sFe4kQv7eYCT
         BwomDmUI4qmD+YI0lA8TruZ+s1utaU6lriecCAgDouJ77vIRj4+nDwQStjds6LGfJPkO
         9ecQWH63GuexYqp1GvumD7BPREn1ht3ZIOk5nkx8ch+5u/7AK7HTkOva3YUKH4mbHoN9
         RvcFon/EVhwqaQbYXT1DJzf5bBKKnAqwliBGujtEzxts/In5yYlIqawbdVxHMdfVM5ow
         lFHg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=RFFv6xjO;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.29 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=2fAuVwAJrB5SDH0kqwPAbeYPaOWs4y96h7DgvqDdVO0=;
        b=GBtGmpmqE1oHI64uqgm3wiSNDWvFYln3IW/jmlLrkXyLp75Cx7CK/S1/Tl+yBYRhqN
         isE+9SC/1GsRbSBKrmYCVsH6EX2Ug6kfr9f3v4bDcGMaLTsbwTpAvZY8F/rJPrRiq/Vt
         kbg2qdEmlxpfBIsK8jbS+EV+RoysryPhwJ+/S7Sy/nISbrF0oUFQRZQjQukxojDwnSFm
         SRGoloPL2xKcdgLaZhIUQR+oM0kAH4IhZN/zybbpUd+aWEfwIsfRGRLmiq/Uwhq7ibH6
         YXU1clIlrDeeYWr2JJa1hOOedh2WlrapM46cpBeNkCe/x5RnARAyKGgDf4JaupCK+K78
         BdyA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=2fAuVwAJrB5SDH0kqwPAbeYPaOWs4y96h7DgvqDdVO0=;
        b=6y8gx/hPOpgMBebDxFjli9KUlWtX8ScVH5B0cEWB12UdGhBoD4KbED7t7T1JnntQnK
         +wxl16qVmLtNI8DEcCvfXDjlXX3MVbVaiohPvlmXH0qsoqiWy5Hh3KgHxJ6u9WqWkxfY
         WKpJXBjQQH1A+RfiYa0nmAbZiOSor0ENvfI5cP1nHBDWm2FMZ5OulPuOz9oBZRalA+9U
         aLqfA7JNC+X9Tc7t4wJy1xv7un6I2FyxQEWbPguncPhpqkux6c3A9yLrmiVuTlyCOVr7
         /DPN11CkoyRIRUr6dEvBDt1wLzYgUt4by0OjlYHBknxA9/trLaD7I5MfocXwY97CeFsB
         iJww==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532+/dcW7S6uUObF3/8ocNml8OmX5fYcIw1rm/UjQmBZibMbeGhc
	fpSnCLx+GOeFYt5eQRpOeKk=
X-Google-Smtp-Source: ABdhPJz/WSG/NowuojvdI+mERKIgqzN0TFQoyvA4drXcOplPjYKVwvXuoRmO4AQFtqKE42xIsyOtyw==
X-Received: by 2002:a5d:6d84:: with SMTP id l4mr4138480wrs.266.1637021803082;
        Mon, 15 Nov 2021 16:16:43 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:fe0b:: with SMTP id n11ls12455003wrr.0.gmail; Mon, 15
 Nov 2021 16:16:42 -0800 (PST)
X-Received: by 2002:a5d:64c3:: with SMTP id f3mr4009612wri.377.1637021802310;
        Mon, 15 Nov 2021 16:16:42 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1637021802; cv=none;
        d=google.com; s=arc-20160816;
        b=bXOHavZTZKhOaoz7UjdwH5ax8jcRc2Ew7AVmOM48SpyupuHVtd4dR/DjrmYzyPAwYE
         Rcz1eDY9eKlNbYgai2EJUWv6pxK1IccfImIuN5n4qg1GLUV+GPJ2qoupy7bOJgKVSG1/
         5XCisSHvzaJarx3PUqFiNF2f5gnjBDTm/ThqgGKYveid+ARv/4C9/hMHpPWFQgaVSfcw
         9IMa5KY1ZijUWAFh63HomJRlquVHJsTRpNgfqAfXwvKvJuMKJGfBochkx2tFCYqv9zZI
         YTomfpVc6QGM9zEIBwSunzs2FREiFg8wVs3yPzk5KwHQZdmdS+OnhdGMXclN1hkLMpCc
         BQXQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature:dkim-signature;
        bh=4HEc0a+5kUJeYeUUKFV/Jr2mozOhZtMjtJch9JnNS5g=;
        b=yH7Szm6vfmj+aRCQDMnEDd8rsuDwAu+0URD92KBSu8GXU7qShHmgNe/FgghaPnY0En
         nWxeWi4qYD0qgQUrY5xdc+pf62h3Z/+BE7s5wk1F+MGMgJNHWt+flWt1ogHKc6uwKIuV
         oYLAzNMtvcY2qV8BrWAR6BfPijLJqzsPwvEWI3FfncehjlRmRO10spyYjbNkwd7QBnQP
         X3Cb8m+ktPrwdtq1978WzrSRrebnl9sgQIXBegl6TMaEih9JRUqJ86hwbR2TMsKSDD3/
         QtWp0MXCspIWqB8cyb1JfD1Vy+x2Cn3cBxDv/8IQSa3HlaC6TvljNiT56KXlG9gnjDoT
         wePQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=RFFv6xjO;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.29 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [195.135.220.29])
        by gmr-mx.google.com with ESMTPS id d9si1092026wrf.0.2021.11.15.16.16.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 15 Nov 2021 16:16:42 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.220.29 as permitted sender) client-ip=195.135.220.29;
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id 1CED61FD73;
	Tue, 16 Nov 2021 00:16:42 +0000 (UTC)
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by imap2.suse-dmz.suse.de (Postfix) with ESMTPS id DDC0113F72;
	Tue, 16 Nov 2021 00:16:41 +0000 (UTC)
Received: from dovecot-director2.suse.de ([192.168.254.65])
	by imap2.suse-dmz.suse.de with ESMTPSA
	id 0AONNWn4kmFjXAAAMHmgww
	(envelope-from <vbabka@suse.cz>); Tue, 16 Nov 2021 00:16:41 +0000
From: Vlastimil Babka <vbabka@suse.cz>
To: Matthew Wilcox <willy@infradead.org>,
	linux-mm@kvack.org,
	Christoph Lameter <cl@linux.com>,
	David Rientjes <rientjes@google.com>,
	Joonsoo Kim <iamjoonsoo.kim@lge.com>,
	Pekka Enberg <penberg@kernel.org>
Cc: Vlastimil Babka <vbabka@suse.cz>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	kasan-dev@googlegroups.com
Subject: [RFC PATCH 30/32] mm/sl*b: Differentiate struct slab fields by sl*b implementations
Date: Tue, 16 Nov 2021 01:16:26 +0100
Message-Id: <20211116001628.24216-31-vbabka@suse.cz>
X-Mailer: git-send-email 2.33.1
In-Reply-To: <20211116001628.24216-1-vbabka@suse.cz>
References: <20211116001628.24216-1-vbabka@suse.cz>
MIME-Version: 1.0
X-Developer-Signature: v=1; a=openpgp-sha256; l=4583; h=from:subject; bh=HpvxF6blYd9Gxl8D0B/0lpH3ep8bdHVJ8W1r0M/ydds=; b=owEBbQGS/pANAwAIAeAhynPxiakQAcsmYgBhkvhXodE76eu6sNsRldmo9f4ZC/NuS3j9IsK5x5/Q lJgFbd+JATMEAAEIAB0WIQSNS5MBqTXjGL5IXszgIcpz8YmpEAUCYZL4VwAKCRDgIcpz8YmpEMxSCA Ck/Bodg7xN+SrNWGfwBc0nMLXkVJZUg7QYlOMYrbg14Wb7jdiq4aWhvJ3MkwpN4FUj6qBfxkfNf30X f73MrCXMmKfS63JbXwd0aPcM9ANzTYT31Cys3tiZC8cdObSIq+5iJhxzxlwe24Vh7BW3QbX2+fiTF5 NKXYxdR21dc057mZ/MRTmxIalYYM+5rcFEmUss/Liq8uVAaMMQzuIlSAc4/4DAUl2/y5Nyzp0gIK6s tAwWcynBsk07XBA8OwaI530/l903irks6siXta4ruUOV8hdAq2CZPFAjzpKqchwsegJnJRAmvta9P2 GJQZpz1QcgMKz19hJf3O5SHJeS0zzx
X-Developer-Key: i=vbabka@suse.cz; a=openpgp; fpr=A940D434992C2E8E99103D50224FA7E7CC82A664
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=RFFv6xjO;       dkim=neutral
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

With a struct slab definition separate from struct page, we can go further and
define only fields that the chosen sl*b implementation uses. This means
everything between __page_flags and __page_refcount placeholders now depends on
the chosen CONFIG_SL*B. Some fields exist in all implementations (slab_list)
but can be part of a union in some, so it's simpler to repeat them than
complicate the definition with ifdefs even more.

The patch doesn't change physical offsets of the fields, although it could be
done later - for example it's now clear that tighter packing in SLOB could be
possible.

This should also prevent accidental use of fields that don't exist in given
implementation. Before this patch virt_to_cache() and and cache_from_obj() was
visible for SLOB (albeit not used), although it relies on the slab_cache field
that isn't set by SLOB. With this patch it's now a compile error, so these
functions are now hidden behind #ifndef CONFIG_SLOB.

Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
Cc: Alexander Potapenko <glider@google.com> (maintainer:KFENCE)
Cc: Marco Elver <elver@google.com> (maintainer:KFENCE)
Cc: Dmitry Vyukov <dvyukov@google.com> (reviewer:KFENCE)
Cc: <kasan-dev@googlegroups.com>
---
 mm/kfence/core.c |  9 +++++----
 mm/slab.h        | 46 ++++++++++++++++++++++++++++++++++++----------
 2 files changed, 41 insertions(+), 14 deletions(-)

diff --git a/mm/kfence/core.c b/mm/kfence/core.c
index 4eb60cf5ff8b..46103a7628a6 100644
--- a/mm/kfence/core.c
+++ b/mm/kfence/core.c
@@ -427,10 +427,11 @@ static void *kfence_guarded_alloc(struct kmem_cache *cache, size_t size, gfp_t g
 	/* Set required slab fields. */
 	slab = virt_to_slab((void *)meta->addr);
 	slab->slab_cache = cache;
-	if (IS_ENABLED(CONFIG_SLUB))
-		slab->objects = 1;
-	if (IS_ENABLED(CONFIG_SLAB))
-		slab->s_mem = addr;
+#if defined(CONFIG_SLUB)
+	slab->objects = 1;
+#elif defined (CONFIG_SLAB)
+	slab->s_mem = addr;
+#endif
 
 	/* Memory initialization. */
 	for_each_canary(meta, set_canary_byte);
diff --git a/mm/slab.h b/mm/slab.h
index 58b65e5e5d49..10a9ee195249 100644
--- a/mm/slab.h
+++ b/mm/slab.h
@@ -8,9 +8,24 @@
 /* Reuses the bits in struct page */
 struct slab {
 	unsigned long __page_flags;
+
+#if defined(CONFIG_SLAB)
+
+	union {
+		struct list_head slab_list;
+		struct rcu_head rcu_head;
+	};
+	struct kmem_cache *slab_cache;
+	void *freelist;	/* array of free object indexes */
+	void * s_mem;	/* first object */
+	unsigned int active;
+
+#elif defined(CONFIG_SLUB)
+
 	union {
 		struct list_head slab_list;
-		struct {	/* Partial pages */
+		struct rcu_head rcu_head;
+		struct {
 			struct slab *next;
 #ifdef CONFIG_64BIT
 			int slabs;	/* Nr of slabs left */
@@ -18,25 +33,32 @@ struct slab {
 			short int slabs;
 #endif
 		};
-		struct rcu_head rcu_head;
 	};
-	struct kmem_cache *slab_cache; /* not slob */
+	struct kmem_cache *slab_cache;
 	/* Double-word boundary */
 	void *freelist;		/* first free object */
 	union {
-		void *s_mem;	/* slab: first object */
-		unsigned long counters;		/* SLUB */
-		struct {			/* SLUB */
+		unsigned long counters;
+		struct {
 			unsigned inuse:16;
 			unsigned objects:15;
 			unsigned frozen:1;
 		};
 	};
+	unsigned int __unused;
+
+#elif defined(CONFIG_SLOB)
+
+	struct list_head slab_list;
+	void * __unused_1;
+	void *freelist;		/* first free block */
+	void * __unused_2;
+	int units;
+
+#else
+#error "Unexpected slab allocator configured"
+#endif
 
-	union {
-		unsigned int active;		/* SLAB */
-		int units;			/* SLOB */
-	};
 	atomic_t __page_refcount;
 #ifdef CONFIG_MEMCG
 	unsigned long memcg_data;
@@ -47,7 +69,9 @@ struct slab {
 	static_assert(offsetof(struct page, pg) == offsetof(struct slab, sl))
 SLAB_MATCH(flags, __page_flags);
 SLAB_MATCH(compound_head, slab_list);	/* Ensure bit 0 is clear */
+#ifndef CONFIG_SLOB
 SLAB_MATCH(rcu_head, rcu_head);
+#endif
 SLAB_MATCH(_refcount, __page_refcount);
 #ifdef CONFIG_MEMCG
 SLAB_MATCH(memcg_data, memcg_data);
@@ -623,6 +647,7 @@ static inline void memcg_slab_free_hook(struct kmem_cache *s,
 }
 #endif /* CONFIG_MEMCG_KMEM */
 
+#ifndef CONFIG_SLOB
 static inline struct kmem_cache *virt_to_cache(const void *obj)
 {
 	struct slab *slab;
@@ -669,6 +694,7 @@ static inline struct kmem_cache *cache_from_obj(struct kmem_cache *s, void *x)
 		print_tracking(cachep, x);
 	return cachep;
 }
+#endif /* CONFIG_SLOB */
 
 static inline size_t slab_ksize(const struct kmem_cache *s)
 {
-- 
2.33.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211116001628.24216-31-vbabka%40suse.cz.
