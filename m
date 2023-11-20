Return-Path: <kasan-dev+bncBDXYDPH3S4OBBQON52VAMGQEPA2LHNI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x340.google.com (mail-wm1-x340.google.com [IPv6:2a00:1450:4864:20::340])
	by mail.lfdr.de (Postfix) with ESMTPS id 009097F1C74
	for <lists+kasan-dev@lfdr.de>; Mon, 20 Nov 2023 19:34:42 +0100 (CET)
Received: by mail-wm1-x340.google.com with SMTP id 5b1f17b1804b1-40a48806258sf14871205e9.3
        for <lists+kasan-dev@lfdr.de>; Mon, 20 Nov 2023 10:34:42 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1700505282; cv=pass;
        d=google.com; s=arc-20160816;
        b=qW1pJq+xKziUh5CLPe8DohngRtcO52uLy1kL9C7tT9sebQC59gwfJfumDD2tRyYeLN
         IhNHksFfhgD9LDx3dS5sSExRlUsBs57LsnwZhPmNvnbXYJZFHlafM1+dteEB5ICTP2dj
         yWQIN44IWXzNrX04//a34WuQW7mpBEGytsSnxYYsN8r5QOP3hYBrW/CNnVLphsvj8wKB
         U72YAlQif8KtWQzbC9hTrmGOOzv9KDiNQsbTI5FW1M3QN0ZI+kid56Uq8rD5U6Kpis1r
         PKdXs0bwhoEEqAqScGl8IWeMXo/aShXxas83SjOn5pKa7qYiGKfdXfq94dTt5O3BIPFS
         AV2Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:in-reply-to:references
         :message-id:mime-version:subject:date:from:sender:dkim-signature;
        bh=4IXxRmIFN3ks8pmjvFx5l+5yHy4FrczHMRuRAZnu9SQ=;
        fh=ONqwzSuNvSIo96fWAp0pW54nN9xAdzTfApSlC7LEvRU=;
        b=HK+ZgEMHFS4Yv+xVKXxlXcA16ooJMypvktce9a7uOoyQ1PQR29Mcxbs1QwkgSFdFtD
         qXjrv0u050BUfNOPGG/aaqJrkCHMOq8h8ERopdSMH/aqYJWcSmTRbRhPePVwIG2cf/cg
         ykE7Cf/CcIedbnxCewzozGx2fzWdvW4Z1hkceC5acmGg/ZMl5MRXE7fR8NfrnH/FPGRc
         NHUgkVkzVZOCdXTCKL8rFkNKeNByHr748FhmZHS6bHZhLQ1W02WN06sGUgeI59v5JNsu
         SJihcwYSI6Jo4CCjUfGtxBAUvMdfegzs5ADZNhsvXrJN9HKb8vm3bBLruIGVuGNgFDeN
         +mbg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b="A/zYVT7F";
       dkim=neutral (no key) header.i=@suse.cz;
       spf=softfail (google.com: domain of transitioning vbabka@suse.cz does not designate 2001:67c:2178:6::1c as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1700505282; x=1701110082; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:in-reply-to:references:message-id
         :mime-version:subject:date:from:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=4IXxRmIFN3ks8pmjvFx5l+5yHy4FrczHMRuRAZnu9SQ=;
        b=FtBwvPSTCFZg5AWEt7ZlLoY8qbiuruXxw6tau3545HHUid1L1FFa0xARa8Y73KsG61
         btHi3Si8Qg4cEXUtD1PvUpWF5v7E/o1yTHXwJaf8Ok2A5AutqEaggztgM3AV7qFRVIp/
         HB4bzdNeUoKuD7uDqHnq5PCG2GflRPg1kOblm6IZ0CJLHI86cBksPfAF3nMf0w19mw8A
         dN+wrBWamkGu9B09qFF4IG9Pi9phq+N06nc33ShVlXLh7VP611vrE65JR1MXInBqX2uQ
         sOfuxq/KIYzX5GH9/LLfZqW5LvuVfMACOXoQ4letRigEYFadPXIXaVT6HF4XBcp36+RR
         /Efw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1700505282; x=1701110082;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to
         :in-reply-to:references:message-id:mime-version:subject:date:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=4IXxRmIFN3ks8pmjvFx5l+5yHy4FrczHMRuRAZnu9SQ=;
        b=AhJ3OJaNFEP5cqO15HL6mfTGWDav9wjHGbC4sBSqaoLgTbS3aKDUsi4jRXxkwD1I3F
         ICVrhaG3S9UwDIWmkpppdzLqv89oM5l0GW1sKUxaJ4x/IEKkl+IVCpTMFDxadPSwuRGf
         s9o4zIrlrjp98dJOJPWWJOy0ichFus0RNUZIkMW//+NnDtS1ys8/WkaygbhFHj5E/M2c
         fFe2nEWdpjnM7YEwJHDXGr2sQbJB0aK8tXR/eEuDSBFdR5WD+RvNkHdUrGLJ7abdOUxw
         IH5ntJ2bwyRz4pz7w3vJ+YlK0h5vwa1X1lNDcFtkQdNRaSnmFhfwYibgkTcH4FnaXZf7
         8C4w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YxFVRrscWEV1/Olvv65RFAjzlJjOUvmQQRIi480Kez97q41k5jq
	eObnGhZoeXGDad8aw+2QDCk=
X-Google-Smtp-Source: AGHT+IERXXxxxZfw6Dq4mNEkfp0yVlsguRhY3vIyJCkFShJNtJgDr0Yt48CqIo48RGUt2wU1OWTKyQ==
X-Received: by 2002:a05:600c:3582:b0:405:359a:c950 with SMTP id p2-20020a05600c358200b00405359ac950mr6394216wmq.19.1700505281926;
        Mon, 20 Nov 2023 10:34:41 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:1d26:b0:409:3542:341d with SMTP id
 l38-20020a05600c1d2600b004093542341dls1097926wms.1.-pod-prod-08-eu; Mon, 20
 Nov 2023 10:34:40 -0800 (PST)
X-Received: by 2002:a05:600c:4fd1:b0:408:3ac4:dc3f with SMTP id o17-20020a05600c4fd100b004083ac4dc3fmr6889046wmq.29.1700505280264;
        Mon, 20 Nov 2023 10:34:40 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1700505280; cv=none;
        d=google.com; s=arc-20160816;
        b=u5IJHwtKFVbRRLTYkM6qIINiGjtGIqkOLUfVK5UG0+qDWMwvg6uXXsdc1v8zxKbefO
         ux7EbiyyE0JmEY+wnjf7kfVlWBRVsyTfjlU6fecPFVzGZc/ZCkJMBqLdXW8xysSgwAgc
         g3srMFu+FLzvbLPupX1NjxznaoCIW1Ykw/2/lHHaugPe2AmXveAagHaiLGymDI6s9nZl
         yArKs16Ztt601wLwU9rV6vyk/AiHM5Zui2zEum5tfqNnq/PDvuSLVs0el5Pk5xSlP/Y/
         C8aeysLkSlHY14wb9eP/BFkFcWor258CYGa/ZKQvXFSsAgN0ITFaU+bwIqtCDMVxNtwS
         qrBw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:in-reply-to:references:message-id:content-transfer-encoding
         :mime-version:subject:date:from:dkim-signature:dkim-signature;
        bh=XDePevE9GX1BKoA1NhlhcvLNyMlxXLyXeY5y95pZ5hE=;
        fh=ONqwzSuNvSIo96fWAp0pW54nN9xAdzTfApSlC7LEvRU=;
        b=QabdPhj2LIs9TImv8YQQZenzvZP8wKSUBniuex4ekMNZKppXGDacZXGHbT7A+KlKD2
         YzOXAobG7XVUqmhG/3KO8bpW4R9E3Qh4Gzb8Y7JpU8FKg9g6bemaBO6F0rBC5I7ShrNL
         15QEQR6xE4swJz4H4HZJZ7mh1pLSgc7yt1y4tPS4p0EruzLYhSxxlluAa338+DA4DX8Z
         6jZMTvdHPGH0lzdL5pLrtmLnOj1wfLSkm1o9LAkIlDp8Z7wM80Yu13km2rEbsKGl/Fz9
         DSNExkxC1m7UIBuSAkfwY+jTrNWfOaJcMrblzPcqQThDJ9Z079gLlHeD1uv4yBmOg+W/
         c1Pg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b="A/zYVT7F";
       dkim=neutral (no key) header.i=@suse.cz;
       spf=softfail (google.com: domain of transitioning vbabka@suse.cz does not designate 2001:67c:2178:6::1c as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [2001:67c:2178:6::1c])
        by gmr-mx.google.com with ESMTPS id m18-20020a05600c3b1200b003fe2591111dsi403773wms.1.2023.11.20.10.34.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 20 Nov 2023 10:34:40 -0800 (PST)
Received-SPF: softfail (google.com: domain of transitioning vbabka@suse.cz does not designate 2001:67c:2178:6::1c as permitted sender) client-ip=2001:67c:2178:6::1c;
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id C8EED218F8;
	Mon, 20 Nov 2023 18:34:39 +0000 (UTC)
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by imap2.suse-dmz.suse.de (Postfix) with ESMTPS id 7F7D213912;
	Mon, 20 Nov 2023 18:34:39 +0000 (UTC)
Received: from dovecot-director2.suse.de ([192.168.254.65])
	by imap2.suse-dmz.suse.de with ESMTPSA
	id +I10Hr+mW2UUMgAAMHmgww
	(envelope-from <vbabka@suse.cz>); Mon, 20 Nov 2023 18:34:39 +0000
From: Vlastimil Babka <vbabka@suse.cz>
Date: Mon, 20 Nov 2023 19:34:12 +0100
Subject: [PATCH v2 01/21] mm/slab, docs: switch mm-api docs generation from
 slab.c to slub.c
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Message-Id: <20231120-slab-remove-slab-v2-1-9c9c70177183@suse.cz>
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
X-Spam-Score: -6.45
X-Spamd-Result: default: False [-6.45 / 50.00];
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
	 BAYES_HAM(-2.65)[98.46%];
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
 header.i=@suse.cz header.s=susede2_rsa header.b="A/zYVT7F";
       dkim=neutral (no key) header.i=@suse.cz;       spf=softfail
 (google.com: domain of transitioning vbabka@suse.cz does not designate
 2001:67c:2178:6::1c as permitted sender) smtp.mailfrom=vbabka@suse.cz
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

The SLAB implementation is going to be removed, and mm-api.rst currently
uses mm/slab.c to obtain kerneldocs for some API functions. Switch it to
mm/slub.c and move the relevant kerneldocs of exported functions from
one to the other. The rest of kerneldocs in slab.c is for static SLAB
implementation-specific functions that don't have counterparts in slub.c
and thus can be simply removed with the implementation.

Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
---
 Documentation/core-api/mm-api.rst |  2 +-
 mm/slab.c                         | 21 ---------------------
 mm/slub.c                         | 21 +++++++++++++++++++++
 3 files changed, 22 insertions(+), 22 deletions(-)

diff --git a/Documentation/core-api/mm-api.rst b/Documentation/core-api/mm-api.rst
index 2d091c873d1e..af8151db88b2 100644
--- a/Documentation/core-api/mm-api.rst
+++ b/Documentation/core-api/mm-api.rst
@@ -37,7 +37,7 @@ The Slab Cache
 .. kernel-doc:: include/linux/slab.h
    :internal:
 
-.. kernel-doc:: mm/slab.c
+.. kernel-doc:: mm/slub.c
    :export:
 
 .. kernel-doc:: mm/slab_common.c
diff --git a/mm/slab.c b/mm/slab.c
index 9ad3d0f2d1a5..37efe3241f9c 100644
--- a/mm/slab.c
+++ b/mm/slab.c
@@ -3491,19 +3491,6 @@ int kmem_cache_alloc_bulk(struct kmem_cache *s, gfp_t flags, size_t size,
 }
 EXPORT_SYMBOL(kmem_cache_alloc_bulk);
 
-/**
- * kmem_cache_alloc_node - Allocate an object on the specified node
- * @cachep: The cache to allocate from.
- * @flags: See kmalloc().
- * @nodeid: node number of the target node.
- *
- * Identical to kmem_cache_alloc but it will allocate memory on the given
- * node, which can improve the performance for cpu bound structures.
- *
- * Fallback to other node is possible if __GFP_THISNODE is not set.
- *
- * Return: pointer to the new object or %NULL in case of error
- */
 void *kmem_cache_alloc_node(struct kmem_cache *cachep, gfp_t flags, int nodeid)
 {
 	void *ret = slab_alloc_node(cachep, NULL, flags, nodeid, cachep->object_size, _RET_IP_);
@@ -3564,14 +3551,6 @@ void __kmem_cache_free(struct kmem_cache *cachep, void *objp,
 	__do_kmem_cache_free(cachep, objp, caller);
 }
 
-/**
- * kmem_cache_free - Deallocate an object
- * @cachep: The cache the allocation was from.
- * @objp: The previously allocated object.
- *
- * Free an object which was previously allocated from this
- * cache.
- */
 void kmem_cache_free(struct kmem_cache *cachep, void *objp)
 {
 	cachep = cache_from_obj(cachep, objp);
diff --git a/mm/slub.c b/mm/slub.c
index 63d281dfacdb..3e01731783df 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -3518,6 +3518,19 @@ void *__kmem_cache_alloc_node(struct kmem_cache *s, gfp_t gfpflags,
 			       caller, orig_size);
 }
 
+/**
+ * kmem_cache_alloc_node - Allocate an object on the specified node
+ * @s: The cache to allocate from.
+ * @gfpflags: See kmalloc().
+ * @node: node number of the target node.
+ *
+ * Identical to kmem_cache_alloc but it will allocate memory on the given
+ * node, which can improve the performance for cpu bound structures.
+ *
+ * Fallback to other node is possible if __GFP_THISNODE is not set.
+ *
+ * Return: pointer to the new object or %NULL in case of error
+ */
 void *kmem_cache_alloc_node(struct kmem_cache *s, gfp_t gfpflags, int node)
 {
 	void *ret = slab_alloc_node(s, NULL, gfpflags, node, _RET_IP_, s->object_size);
@@ -3822,6 +3835,14 @@ void __kmem_cache_free(struct kmem_cache *s, void *x, unsigned long caller)
 	slab_free(s, virt_to_slab(x), x, NULL, &x, 1, caller);
 }
 
+/**
+ * kmem_cache_free - Deallocate an object
+ * @s: The cache the allocation was from.
+ * @x: The previously allocated object.
+ *
+ * Free an object which was previously allocated from this
+ * cache.
+ */
 void kmem_cache_free(struct kmem_cache *s, void *x)
 {
 	s = cache_from_obj(s, x);

-- 
2.42.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231120-slab-remove-slab-v2-1-9c9c70177183%40suse.cz.
