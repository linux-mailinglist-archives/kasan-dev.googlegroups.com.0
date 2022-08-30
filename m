Return-Path: <kasan-dev+bncBC7OD3FKWUERBDEMXKMAMGQEVXWRTBA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33b.google.com (mail-ot1-x33b.google.com [IPv6:2607:f8b0:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id 6DAD15A6F92
	for <lists+kasan-dev@lfdr.de>; Tue, 30 Aug 2022 23:50:05 +0200 (CEST)
Received: by mail-ot1-x33b.google.com with SMTP id k7-20020a0568301be700b0063aa5238236sf5492475otb.4
        for <lists+kasan-dev@lfdr.de>; Tue, 30 Aug 2022 14:50:05 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1661896204; cv=pass;
        d=google.com; s=arc-20160816;
        b=SYXCGyN15THxAcFrCuiV+r82SqFTP0VzM+DayicM8nKjnp4MMGm56TbtthiN5S3dqv
         7KVar44DWFOu8RFHRZWWan9OqCwrKWlcNQ1yUcQR0eyuQApR3ef9pzTuiYVW4aCvH1DP
         SGAyjEGb3fgckoBdED+OeMMSMx6c70qe7Tpdc2K+1ffxKdaHT55aFhzVF8DC6BbRznXQ
         0y9w+5gO3q4qcO8mWWQkDULRJwt8BUAeYAQzUjpwacX229LNpV0J+hkGDdwD5OpoRMhd
         ZxBKUZqKNstrL13oMOKY7OZ+E+sNGH+pcyOBAqLyFY/8Cat3LrvFS2AyS7P+bcDgHb/2
         jPSQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=3OEosmJ/wKGXj6fO87OvIIlTUMkOgsE6+EXdJkIr404=;
        b=M1iK0l0DPNNfEZlZLtIQfdiyrcmpUxNg7bNr+OvFyBltoEJMUdp7msWuxZITl37F/q
         d4jJDf1GrTMuOcalpl+ajNjlKjLkTZQ3enc9uXwutSCvwz4qfE0E148LS+OJ6FJhhTKf
         ecuvZ9VImSQ/eQlmHeAPtUb9tD2Zg3YkGKNt2zRcSvrEXUjZHMIWkjH6Et5VhBuupov8
         0uDxQc8iqKn0R4zrJtoWNUpqzBKN40KnorB9yUKYPBZRRdPTMj4R8oEQC4Hk5dsAtoDK
         Rb87WlPY5o2OX9jNhSOE4oOPAghUvWQAX++4wx2EQIMftZnJJWnG1SdcknawRwNC2hqH
         AsDA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=Q1PzL2bT;
       spf=pass (google.com: domain of 3c4yoywykcxagifsbpuccuzs.qcayogob-rsjuccuzsufcidg.qca@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3C4YOYwYKCXAgifSbPUccUZS.QcaYOgOb-RSjUccUZSUfcidg.Qca@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc;
        bh=3OEosmJ/wKGXj6fO87OvIIlTUMkOgsE6+EXdJkIr404=;
        b=H45u3OJIJLGU/GslzRedSgvtKx1xI1WDwttpE6ftmzxUbFImDh/NnBk+lf3MSmNKwg
         Z3WHq3ksZkBIQ8mxs/pJiE3JCqR5PrjZrSDxzUqVqQ/iHUhCvm8ISg55x7fuHlRUZGDQ
         hsqJbBpBE2wanVERu5D7Hc0GdakFJV9/lL/4veRZusOWOMrVYOSXvysxjS0x1E97yv2v
         bnQ2Dh0GAEhc3B1k6aSW5pA9vzCtBAZAnF1Gxav0zQKZfAXtxwSVJYcxGeNu9YB28RSX
         pBCyRxXSvfMiUC0dZEYnhBRLtqwVSi/BY67HgH142mMpuCBQk7dOTt+ULpkZOpKMUfze
         cN6w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-gm-message-state:from:to:cc;
        bh=3OEosmJ/wKGXj6fO87OvIIlTUMkOgsE6+EXdJkIr404=;
        b=bsk5KmWdmKXwtbh7exhgLtctjM6oE2L+ZziBq3XqqBHzV68++jEFnCfZCV1frkrFSP
         yvgmmWiPBM8uAMACzzQKguRrClZaRzVsUrSKq19PbuE6ZoJvTc3xPteec5HNRUmAyIXS
         zD1uo6jADaiVfU5RCh1FOR6fu3DslPZ+SqltRuPmsvfTc4MqDWG2doC4WMtwNn8/PHCa
         1YnAs9nJCX2uqOlr4CfqTeHiIPGU+g3SzbMGHir56fp28gsQRz51/d5C98uzvnsD3sjK
         jI0VhlfKrjVbOg20X8feVxPnNCq/Dg5F4RrpfgHZNoEHBetXiuMGSZ1NSFTEsuYXNGh2
         RrEw==
X-Gm-Message-State: ACgBeo0sAepkU74oiTObZ8gvLRgXSzNQDzEKHrQxhMBcf2L6l0R9+9QW
	GLBL2kob4H/x2RBOBOSPWR4=
X-Google-Smtp-Source: AA6agR5gJ19tTiyAG317wo+hUtWVUxFCTtRhjyvmGf2ss6YFJXk62u7/+0kfL5hytMp5FhhZRBNS3A==
X-Received: by 2002:aca:1b13:0:b0:344:d3f5:4df0 with SMTP id b19-20020aca1b13000000b00344d3f54df0mr16389oib.209.1661896204366;
        Tue, 30 Aug 2022 14:50:04 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:a586:b0:11e:e2d7:74d7 with SMTP id
 c6-20020a056870a58600b0011ee2d774d7ls2513186oam.1.-pod-prod-gmail; Tue, 30
 Aug 2022 14:50:04 -0700 (PDT)
X-Received: by 2002:a05:6870:2391:b0:11d:2161:27f1 with SMTP id e17-20020a056870239100b0011d216127f1mr17619oap.147.1661896203959;
        Tue, 30 Aug 2022 14:50:03 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1661896203; cv=none;
        d=google.com; s=arc-20160816;
        b=MS+FNJ3dpxF/aECH56BtGyXdcKQN14NAjm1yv8egU1bOUAFpXVvYwJWJPLH36C+AFM
         NrZABAMkMHp+05W/h5qL1Zux2RSBjwxfxxGuNy88IC29IUZzirOYqHZ+N0+L4j82Y6Kk
         d3qqCbthtqYIVZc58AZ9LXAIyZ6u9m2gaDuy1jaqtFnFt/QYUX6k/G0V3/i5//QvyfT9
         e8DhjED1KF6MRu3gDIgmOKRZ3TQY9Yww/4mIqfbR/2aOv8QeDknW6zzmFTKDjj1AZpBl
         E/6oYtC0Msn7tLFYU9kuoJy3EIl3uri3CV5Pzs2pZq5OkhBGGLCqhZRvadlwaLNpgE7P
         JUJw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=w9gVcgQRdZitDZxjqrDoJq6Gs/0aEjUQjbVWDU06BvI=;
        b=dXoo97aDB+yqw26ayNkC/m/zornykmxtWSZ37BCVA7Cxv4eEiAyqpruOiNOTQjsmiM
         XTUiYzTjIa9qynMjWAFNlnIVRHiJ5hXFb447y8zOWHBBa4FJA0BtOYc+HP8HEHM6vzvq
         dSVOzQfkaDvNnDrrZpPaEuZxOwFukHDrZWl7RUurvkX+14bT8JGsBPybXxdPG9dKIEBG
         LhtEsGLFXuKMCMls+rU0qcbYNx/rY8Hkf+NonEUREEEQZVDXRC1Ucze6dT7k756sFc3O
         pwjrvEhJkh2aNHrs3NOgoK/7QPtPQrnUzBv4ol3rQv0NjtQ09khs97NQmbRjI7jOBI2N
         +v9g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=Q1PzL2bT;
       spf=pass (google.com: domain of 3c4yoywykcxagifsbpuccuzs.qcayogob-rsjuccuzsufcidg.qca@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3C4YOYwYKCXAgifSbPUccUZS.QcaYOgOb-RSjUccUZSUfcidg.Qca@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x1149.google.com (mail-yw1-x1149.google.com. [2607:f8b0:4864:20::1149])
        by gmr-mx.google.com with ESMTPS id t133-20020aca5f8b000000b0033a351b0b4asi685865oib.3.2022.08.30.14.50.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 30 Aug 2022 14:50:03 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3c4yoywykcxagifsbpuccuzs.qcayogob-rsjuccuzsufcidg.qca@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) client-ip=2607:f8b0:4864:20::1149;
Received: by mail-yw1-x1149.google.com with SMTP id 00721157ae682-340c6cfc388so139167357b3.20
        for <kasan-dev@googlegroups.com>; Tue, 30 Aug 2022 14:50:03 -0700 (PDT)
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:200:a005:55b3:6c26:b3e4])
 (user=surenb job=sendgmr) by 2002:a25:e6c6:0:b0:695:f4dc:8c4f with SMTP id
 d189-20020a25e6c6000000b00695f4dc8c4fmr13235724ybh.329.1661896203524; Tue, 30
 Aug 2022 14:50:03 -0700 (PDT)
Date: Tue, 30 Aug 2022 14:49:04 -0700
In-Reply-To: <20220830214919.53220-1-surenb@google.com>
Mime-Version: 1.0
References: <20220830214919.53220-1-surenb@google.com>
X-Mailer: git-send-email 2.37.2.672.g94769d06f0-goog
Message-ID: <20220830214919.53220-16-surenb@google.com>
Subject: [RFC PATCH 15/30] lib: introduce slab allocation tagging
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
To: akpm@linux-foundation.org
Cc: kent.overstreet@linux.dev, mhocko@suse.com, vbabka@suse.cz, 
	hannes@cmpxchg.org, roman.gushchin@linux.dev, mgorman@suse.de, 
	dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com, 
	void@manifault.com, peterz@infradead.org, juri.lelli@redhat.com, 
	ldufour@linux.ibm.com, peterx@redhat.com, david@redhat.com, axboe@kernel.dk, 
	mcgrof@kernel.org, masahiroy@kernel.org, nathan@kernel.org, 
	changbin.du@intel.com, ytcoode@gmail.com, vincent.guittot@linaro.org, 
	dietmar.eggemann@arm.com, rostedt@goodmis.org, bsegall@google.com, 
	bristot@redhat.com, vschneid@redhat.com, cl@linux.com, penberg@kernel.org, 
	iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com, glider@google.com, 
	elver@google.com, dvyukov@google.com, shakeelb@google.com, 
	songmuchun@bytedance.com, arnd@arndb.de, jbaron@akamai.com, 
	rientjes@google.com, minchan@google.com, kaleshsingh@google.com, 
	surenb@google.com, kernel-team@android.com, linux-mm@kvack.org, 
	iommu@lists.linux.dev, kasan-dev@googlegroups.com, io-uring@vger.kernel.org, 
	linux-arch@vger.kernel.org, xen-devel@lists.xenproject.org, 
	linux-bcache@vger.kernel.org, linux-modules@vger.kernel.org, 
	linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: surenb@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=Q1PzL2bT;       spf=pass
 (google.com: domain of 3c4yoywykcxagifsbpuccuzs.qcayogob-rsjuccuzsufcidg.qca@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3C4YOYwYKCXAgifSbPUccUZS.QcaYOgOb-RSjUccUZSUfcidg.Qca@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Suren Baghdasaryan <surenb@google.com>
Reply-To: Suren Baghdasaryan <surenb@google.com>
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

Introduce CONFIG_SLAB_ALLOC_TAGGING which provides helper functions
to easily instrument slab allocators and adds a codetag_ref field into
slabobj_ext to store a pointer to the allocation tag associated with
the code that allocated the slab object.

Signed-off-by: Suren Baghdasaryan <surenb@google.com>
Co-developed-by: Kent Overstreet <kent.overstreet@linux.dev>
Signed-off-by: Kent Overstreet <kent.overstreet@linux.dev>
---
 include/linux/memcontrol.h |  5 +++++
 include/linux/slab.h       | 25 +++++++++++++++++++++++++
 include/linux/slab_def.h   |  2 +-
 include/linux/slub_def.h   |  4 ++--
 lib/Kconfig.debug          | 11 +++++++++++
 mm/slab_common.c           | 33 +++++++++++++++++++++++++++++++++
 6 files changed, 77 insertions(+), 3 deletions(-)

diff --git a/include/linux/memcontrol.h b/include/linux/memcontrol.h
index 315399f77173..97c0153f0247 100644
--- a/include/linux/memcontrol.h
+++ b/include/linux/memcontrol.h
@@ -232,7 +232,12 @@ struct obj_cgroup {
  * if MEMCG_DATA_OBJEXTS is set.
  */
 struct slabobj_ext {
+#ifdef CONFIG_MEMCG_KMEM
 	struct obj_cgroup *objcg;
+#endif
+#ifdef CONFIG_SLAB_ALLOC_TAGGING
+	union codetag_ref ref;
+#endif
 } __aligned(8);
 
 /*
diff --git a/include/linux/slab.h b/include/linux/slab.h
index 55ae3ea864a4..5a198aa02a08 100644
--- a/include/linux/slab.h
+++ b/include/linux/slab.h
@@ -438,6 +438,31 @@ static __always_inline unsigned int __kmalloc_index(size_t size,
 #define kmalloc_index(s) __kmalloc_index(s, true)
 #endif /* !CONFIG_SLOB */
 
+#ifdef CONFIG_SLAB_ALLOC_TAGGING
+
+#include <linux/alloc_tag.h>
+
+union codetag_ref *get_slab_tag_ref(const void *objp);
+
+#define slab_tag_add(_old, _new)					\
+do {									\
+	if (!ZERO_OR_NULL_PTR(_new) && _old != _new)			\
+		alloc_tag_add(get_slab_tag_ref(_new), __ksize(_new));	\
+} while (0)
+
+static inline void slab_tag_dec(const void *ptr)
+{
+	if (!ZERO_OR_NULL_PTR(ptr))
+		alloc_tag_sub(get_slab_tag_ref(ptr), __ksize(ptr));
+}
+
+#else
+
+#define slab_tag_add(_old, _new) do {} while (0)
+static inline void slab_tag_dec(const void *ptr) {}
+
+#endif
+
 void *__kmalloc(size_t size, gfp_t flags) __assume_kmalloc_alignment __alloc_size(1);
 void *kmem_cache_alloc(struct kmem_cache *s, gfp_t flags) __assume_slab_alignment __malloc;
 void *kmem_cache_alloc_lru(struct kmem_cache *s, struct list_lru *lru,
diff --git a/include/linux/slab_def.h b/include/linux/slab_def.h
index e24c9aff6fed..25feb5f7dc32 100644
--- a/include/linux/slab_def.h
+++ b/include/linux/slab_def.h
@@ -106,7 +106,7 @@ static inline void *nearest_obj(struct kmem_cache *cache, const struct slab *sla
  *   reciprocal_divide(offset, cache->reciprocal_buffer_size)
  */
 static inline unsigned int obj_to_index(const struct kmem_cache *cache,
-					const struct slab *slab, void *obj)
+					const struct slab *slab, const void *obj)
 {
 	u32 offset = (obj - slab->s_mem);
 	return reciprocal_divide(offset, cache->reciprocal_buffer_size);
diff --git a/include/linux/slub_def.h b/include/linux/slub_def.h
index f9c68a9dac04..940c146768d4 100644
--- a/include/linux/slub_def.h
+++ b/include/linux/slub_def.h
@@ -170,14 +170,14 @@ static inline void *nearest_obj(struct kmem_cache *cache, const struct slab *sla
 
 /* Determine object index from a given position */
 static inline unsigned int __obj_to_index(const struct kmem_cache *cache,
-					  void *addr, void *obj)
+					  void *addr, const void *obj)
 {
 	return reciprocal_divide(kasan_reset_tag(obj) - addr,
 				 cache->reciprocal_size);
 }
 
 static inline unsigned int obj_to_index(const struct kmem_cache *cache,
-					const struct slab *slab, void *obj)
+					const struct slab *slab, const void *obj)
 {
 	if (is_kfence_address(obj))
 		return 0;
diff --git a/lib/Kconfig.debug b/lib/Kconfig.debug
index 6686648843b3..08c97a978906 100644
--- a/lib/Kconfig.debug
+++ b/lib/Kconfig.debug
@@ -989,6 +989,17 @@ config PAGE_ALLOC_TAGGING
 	  initiated at that code location. The mechanism can be used to track
 	  memory leaks with a low performance impact.
 
+config SLAB_ALLOC_TAGGING
+	bool "Enable slab allocation tagging"
+	default n
+	select ALLOC_TAGGING
+	select SLAB_OBJ_EXT
+	help
+	  Instrument slab allocators to track allocation source code and
+	  collect statistics on the number of allocations and their total size
+	  initiated at that code location. The mechanism can be used to track
+	  memory leaks with a low performance impact.
+
 source "lib/Kconfig.kasan"
 source "lib/Kconfig.kfence"
 
diff --git a/mm/slab_common.c b/mm/slab_common.c
index 17996649cfe3..272eda62ecaa 100644
--- a/mm/slab_common.c
+++ b/mm/slab_common.c
@@ -202,6 +202,39 @@ struct kmem_cache *find_mergeable(unsigned int size, unsigned int align,
 	return NULL;
 }
 
+#ifdef CONFIG_SLAB_ALLOC_TAGGING
+
+union codetag_ref *get_slab_tag_ref(const void *objp)
+{
+	struct slabobj_ext *obj_exts;
+	union codetag_ref *res = NULL;
+	struct slab *slab;
+	unsigned int off;
+
+	slab = virt_to_slab(objp);
+	/*
+	 * We could be given a kmalloc_large() object, skip those. They use
+	 * alloc_pages and can be tracked by page allocation tracking.
+	 */
+	if (!slab)
+		goto out;
+
+	obj_exts = slab_obj_exts(slab);
+	if (!obj_exts)
+		goto out;
+
+	if (!slab->slab_cache)
+		goto out;
+
+	off = obj_to_index(slab->slab_cache, slab, objp);
+	res = &obj_exts[off].ref;
+out:
+	return res;
+}
+EXPORT_SYMBOL(get_slab_tag_ref);
+
+#endif /* CONFIG_SLAB_ALLOC_TAGGING */
+
 static struct kmem_cache *create_cache(const char *name,
 		unsigned int object_size, unsigned int align,
 		slab_flags_t flags, unsigned int useroffset,
-- 
2.37.2.672.g94769d06f0-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220830214919.53220-16-surenb%40google.com.
