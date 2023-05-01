Return-Path: <kasan-dev+bncBC7OD3FKWUERBJW6X6RAMGQEHDMHTAY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe3e.google.com (mail-vs1-xe3e.google.com [IPv6:2607:f8b0:4864:20::e3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 77AB76F33E2
	for <lists+kasan-dev@lfdr.de>; Mon,  1 May 2023 18:56:07 +0200 (CEST)
Received: by mail-vs1-xe3e.google.com with SMTP id ada2fe7eead31-430063e0910sf2051486137.0
        for <lists+kasan-dev@lfdr.de>; Mon, 01 May 2023 09:56:07 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1682960166; cv=pass;
        d=google.com; s=arc-20160816;
        b=T6DE6McaOK14gDHD8EgbxaWQLewjxNe87DOaciSdOMl6m94wp5zE7OR4a5Ou2DT5Ho
         M85BFDO7PB1i2D0KAMqRGKJCWqKzcqe8vx9x/AVXK6hRIRddm8rat0AJFAHWBNtQOVZi
         xThvLWE1RhcssIehrFiyhMqwi7ueG3rheywcOuf1CYm+dbb5UBJdBe1Ugk5GEuo5cmVG
         4cfGX5IYP3H+ySDa6L7K9V4t7Bcpt1V+7pgP1k4H92laghAvBvKXWgdHlTYyVeU1xd4H
         q0bIwzILcvC1qfSYBUNkOjKJIVm1pJas1vqa9hTcSU/AManqchrDXQyRRrON96YBVOCA
         qlUg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=UtigJxIvFbvMMi1x/TKnKkMKcqg8g4uvmKG/H18Zj4A=;
        b=odDxNFklcOjtqSiDPSqQzb3ffb7ZVb9D5cAtHm/IBwRD0rxMXVwsq4DAL4P52S392U
         f2Vpyy9yF1NclDfrkAi8LFRA+YbhzowDr1QOHx3PZb6WxRh31gssyd6/8fnhSwGishO9
         KJw2Vf/EIWzBkMGeQj5p+niNKznFi8w4G00J1GrL6hQ3TpnO1EoqabAfemhsbVkH/9Xc
         XytfYz+sBtgBBj3D1b+RwYdQlDH1fSMCqng2/4ramBbfbX9W2QyOH8swGi0ns3howEuE
         MC1G9rVaVGRvpXvlwL1yi7vHdeAEXYLeOBMhDRRdZ4H7bttJ4YgrfV/yj+ly1kAHBtjB
         znrA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b="Hn84O/Fj";
       spf=pass (google.com: domain of 3je9pzaykcwwceboxlqyyqvo.mywukckx-nofqyyqvoqbyezc.myw@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3Je9PZAYKCWwcebOXLQYYQVO.MYWUKcKX-NOfQYYQVOQbYeZc.MYW@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1682960166; x=1685552166;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=UtigJxIvFbvMMi1x/TKnKkMKcqg8g4uvmKG/H18Zj4A=;
        b=MZ3YumL2z6wUykE9fesKrbovCg8pT383zSfwjMj4c5rVY3o7Yz7dvxKFdieMnRBMuP
         SWJd/3ca10BLM6pSSO+fJJw0ZS7lhGhPfAdK0WJePtnB5HxBieL8JtxQfaOEQDeAAzJ5
         l6XR50mMeFWFSMIcrcTjM4oMSoyoxht7OgJtHXCME22zOD2aipG1cofAvfjhXlFIiWHL
         tvEFt5zdzBZk1j4/OUJxGLzrfJQc1S5NAM2yNBEBniG7OVhlJl1Tir7si5ZUeGwfVyKD
         oXm67wmL33ra9C7q/1/fOczUWAZqepnmdwXHTYZBx8DWyyhY/SHEmnXHUqEZFtRUjp02
         Qr/w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1682960166; x=1685552166;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=UtigJxIvFbvMMi1x/TKnKkMKcqg8g4uvmKG/H18Zj4A=;
        b=HUe7pijBstEZyaee4JADCwXtpiS3heq1XIW6NZ1IfYLTqnhlwcuEhFZdg+H53gXGtx
         H6cR0Q4bhjjxOGNVLdJed4rVjbBebg/Wl+boAGcMqIM6mlZo9sS54+qOnGJvOf95ROy2
         A6Pw7FZ+s7CDVT762/515iT+VmpsE5Pn2jvTjMv7vodYL7vstnf1dgoA7itWB76bs4IU
         a3foPC29kRljbr2+z8tPdIzza+zV4d8R698vqpwMUIm6GoDtzztGH8CG+kyu3EH2Ea4m
         EDE1E0BEzopNOR5+BdYDgO1lF9ay++LVRd/QZqXEfkq65elyzbce2bnbZ8zylWdq7CEy
         gq5Q==
X-Gm-Message-State: AC+VfDyfZErGJQqomdKUk9Q8ZULKWKFEH4jyJEnK9ctYf5T4C7IW5UJ+
	Q7FxuVhiMYUZGXFHZr5AQl0=
X-Google-Smtp-Source: ACHHUZ6nVwwoxdFWFgafox0tme2AQnjXo9BE/pirYJS3etGiYKNE/NJIb2TMIQOt+xq6xPHTgN/S0A==
X-Received: by 2002:a67:cb91:0:b0:42e:63a5:c0d6 with SMTP id h17-20020a67cb91000000b0042e63a5c0d6mr7650461vsl.0.1682960166408;
        Mon, 01 May 2023 09:56:06 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6122:8cf:b0:440:3c61:8c2d with SMTP id
 15-20020a05612208cf00b004403c618c2dls1222138vkg.2.-pod-prod-gmail; Mon, 01
 May 2023 09:56:05 -0700 (PDT)
X-Received: by 2002:a1f:d585:0:b0:43f:9aaf:b629 with SMTP id m127-20020a1fd585000000b0043f9aafb629mr4326069vkg.0.1682960165703;
        Mon, 01 May 2023 09:56:05 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1682960165; cv=none;
        d=google.com; s=arc-20160816;
        b=I19u/6W+7rg6SSuQ2N4aNGLyAqvrpfkyaX9+cPBX5FEEv1vAxOuY82vKngk2jJwX5J
         3rGzkB+3BezVBoAVR3ouhDXovWGQXaJBlVoEBoolat28YChy08Lz+dY2SUF94/S+aKvu
         BIycg41ERjoCwDcK7MPLQIKHe2J8ddPzSJUjr1PFBte7YDzIU2t89u/9CFOGjdaIuZX3
         L9PshiCweB9EiA+/ae0F8/pHYpVCT4x9GaG8E5ldpBgmb22qY7o4QYIrqtNskf95c5Qn
         udkHu+h6ZCP5BlngWkAkzC1IsoZE1I61DPOGL3HIb6B21YaNxMdoKfKQxv1+1tJrAKVJ
         3tNw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=AlFKqZpStCoPEOrrPZX1wMSDo35mmKSmNx34G8mCjEo=;
        b=L0N4F0xNKh5M0K4Pa0mes8ODVyLomemHcvkgVutzFOUAEfcnsXyOr0DwTAgdbslAcx
         4w/43RYa85zxFFgUQgESGn7BKED14KY8aee2wljc05KcsungJiVKI0aNJQ5BdzmTxfMK
         MKycosEImkK2VoE7sleTPb1hSikSr2stkBDUtAprBxpTFgW/beTdTL35Uhy9GEtUC2eH
         66ewCnet13DLDF+qVbs3Uh2XKNfRdVrS96//cGVgCmKHzpZKNnE3gS+khL+8sdkGHs00
         DoIP2hTM+PX1RXQUkLMsGWBLRoRRfrucTQtCM1J0p/UUAg2t6gVIa9kX+i+DsrshY25C
         F+6g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b="Hn84O/Fj";
       spf=pass (google.com: domain of 3je9pzaykcwwceboxlqyyqvo.mywukckx-nofqyyqvoqbyezc.myw@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3Je9PZAYKCWwcebOXLQYYQVO.MYWUKcKX-NOfQYYQVOQbYeZc.MYW@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb49.google.com (mail-yb1-xb49.google.com. [2607:f8b0:4864:20::b49])
        by gmr-mx.google.com with ESMTPS id p20-20020a056122115400b004401f15502esi1546946vko.1.2023.05.01.09.56.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 01 May 2023 09:56:05 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3je9pzaykcwwceboxlqyyqvo.mywukckx-nofqyyqvoqbyezc.myw@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) client-ip=2607:f8b0:4864:20::b49;
Received: by mail-yb1-xb49.google.com with SMTP id 3f1490d57ef6-b9a25f6aa0eso5007126276.1
        for <kasan-dev@googlegroups.com>; Mon, 01 May 2023 09:56:05 -0700 (PDT)
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:201:6d24:3efd:facc:7ac4])
 (user=surenb job=sendgmr) by 2002:a25:3242:0:b0:b8f:6944:afeb with SMTP id
 y63-20020a253242000000b00b8f6944afebmr5782469yby.3.1682960165175; Mon, 01 May
 2023 09:56:05 -0700 (PDT)
Date: Mon,  1 May 2023 09:54:35 -0700
In-Reply-To: <20230501165450.15352-1-surenb@google.com>
Mime-Version: 1.0
References: <20230501165450.15352-1-surenb@google.com>
X-Mailer: git-send-email 2.40.1.495.gc816e09b53d-goog
Message-ID: <20230501165450.15352-26-surenb@google.com>
Subject: [PATCH 25/40] mm/slab: enable slab allocation tagging for kmalloc and friends
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
To: akpm@linux-foundation.org
Cc: kent.overstreet@linux.dev, mhocko@suse.com, vbabka@suse.cz, 
	hannes@cmpxchg.org, roman.gushchin@linux.dev, mgorman@suse.de, 
	dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com, 
	corbet@lwn.net, void@manifault.com, peterz@infradead.org, 
	juri.lelli@redhat.com, ldufour@linux.ibm.com, catalin.marinas@arm.com, 
	will@kernel.org, arnd@arndb.de, tglx@linutronix.de, mingo@redhat.com, 
	dave.hansen@linux.intel.com, x86@kernel.org, peterx@redhat.com, 
	david@redhat.com, axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org, 
	nathan@kernel.org, dennis@kernel.org, tj@kernel.org, muchun.song@linux.dev, 
	rppt@kernel.org, paulmck@kernel.org, pasha.tatashin@soleen.com, 
	yosryahmed@google.com, yuzhao@google.com, dhowells@redhat.com, 
	hughd@google.com, andreyknvl@gmail.com, keescook@chromium.org, 
	ndesaulniers@google.com, gregkh@linuxfoundation.org, ebiggers@google.com, 
	ytcoode@gmail.com, vincent.guittot@linaro.org, dietmar.eggemann@arm.com, 
	rostedt@goodmis.org, bsegall@google.com, bristot@redhat.com, 
	vschneid@redhat.com, cl@linux.com, penberg@kernel.org, iamjoonsoo.kim@lge.com, 
	42.hyeyoo@gmail.com, glider@google.com, elver@google.com, dvyukov@google.com, 
	shakeelb@google.com, songmuchun@bytedance.com, jbaron@akamai.com, 
	rientjes@google.com, minchan@google.com, kaleshsingh@google.com, 
	surenb@google.com, kernel-team@android.com, linux-doc@vger.kernel.org, 
	linux-kernel@vger.kernel.org, iommu@lists.linux.dev, 
	linux-arch@vger.kernel.org, linux-fsdevel@vger.kernel.org, linux-mm@kvack.org, 
	linux-modules@vger.kernel.org, kasan-dev@googlegroups.com, 
	cgroups@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: surenb@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20221208 header.b="Hn84O/Fj";       spf=pass
 (google.com: domain of 3je9pzaykcwwceboxlqyyqvo.mywukckx-nofqyyqvoqbyezc.myw@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3Je9PZAYKCWwcebOXLQYYQVO.MYWUKcKX-NOfQYYQVOQbYeZc.MYW@flex--surenb.bounces.google.com;
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

Redefine kmalloc, krealloc, kzalloc, kcalloc, etc. to record allocations
and deallocations done by these functions.

Signed-off-by: Suren Baghdasaryan <surenb@google.com>
Co-developed-by: Kent Overstreet <kent.overstreet@linux.dev>
Signed-off-by: Kent Overstreet <kent.overstreet@linux.dev>
---
 include/linux/slab.h | 175 ++++++++++++++++++++++---------------------
 mm/slab.c            |  16 ++--
 mm/slab_common.c     |  22 +++---
 mm/slub.c            |  17 +++--
 mm/util.c            |  10 +--
 5 files changed, 124 insertions(+), 116 deletions(-)

diff --git a/include/linux/slab.h b/include/linux/slab.h
index 99a146f3cedf..43c922524081 100644
--- a/include/linux/slab.h
+++ b/include/linux/slab.h
@@ -213,7 +213,10 @@ int kmem_cache_shrink(struct kmem_cache *s);
 /*
  * Common kmalloc functions provided by all allocators
  */
-void * __must_check krealloc(const void *objp, size_t new_size, gfp_t flags) __realloc_size(2);
+void * __must_check _krealloc(const void *objp, size_t new_size, gfp_t flags) __realloc_size(2);
+#define krealloc(_p, _size, _flags)					\
+	alloc_hooks(_krealloc(_p, _size, _flags), void*, NULL)
+
 void kfree(const void *objp);
 void kfree_sensitive(const void *objp);
 size_t __ksize(const void *objp);
@@ -451,6 +454,8 @@ static __always_inline unsigned int __kmalloc_index(size_t size,
 static_assert(PAGE_SHIFT <= 20);
 #define kmalloc_index(s) __kmalloc_index(s, true)
 
+#include <linux/alloc_tag.h>
+
 void *__kmalloc(size_t size, gfp_t flags) __assume_kmalloc_alignment __alloc_size(1);
 
 /**
@@ -463,9 +468,15 @@ void *__kmalloc(size_t size, gfp_t flags) __assume_kmalloc_alignment __alloc_siz
  *
  * Return: pointer to the new object or %NULL in case of error
  */
-void *kmem_cache_alloc(struct kmem_cache *cachep, gfp_t flags) __assume_slab_alignment __malloc;
-void *kmem_cache_alloc_lru(struct kmem_cache *s, struct list_lru *lru,
-			   gfp_t gfpflags) __assume_slab_alignment __malloc;
+void *_kmem_cache_alloc(struct kmem_cache *cachep, gfp_t flags) __assume_slab_alignment __malloc;
+#define kmem_cache_alloc(_s, _flags)				\
+	alloc_hooks(_kmem_cache_alloc(_s, _flags), void*, NULL)
+
+void *_kmem_cache_alloc_lru(struct kmem_cache *s, struct list_lru *lru,
+			    gfp_t gfpflags) __assume_slab_alignment __malloc;
+#define kmem_cache_alloc_lru(_s, _lru, _flags)			\
+	alloc_hooks(_kmem_cache_alloc_lru(_s, _lru, _flags), void*, NULL)
+
 void kmem_cache_free(struct kmem_cache *s, void *objp);
 
 /*
@@ -476,7 +487,9 @@ void kmem_cache_free(struct kmem_cache *s, void *objp);
  * Note that interrupts must be enabled when calling these functions.
  */
 void kmem_cache_free_bulk(struct kmem_cache *s, size_t size, void **p);
-int kmem_cache_alloc_bulk(struct kmem_cache *s, gfp_t flags, size_t size, void **p);
+int _kmem_cache_alloc_bulk(struct kmem_cache *s, gfp_t flags, size_t size, void **p);
+#define kmem_cache_alloc_bulk(_s, _flags, _size, _p)		\
+	alloc_hooks(_kmem_cache_alloc_bulk(_s, _flags, _size, _p), int, 0)
 
 static __always_inline void kfree_bulk(size_t size, void **p)
 {
@@ -485,20 +498,32 @@ static __always_inline void kfree_bulk(size_t size, void **p)
 
 void *__kmalloc_node(size_t size, gfp_t flags, int node) __assume_kmalloc_alignment
 							 __alloc_size(1);
-void *kmem_cache_alloc_node(struct kmem_cache *s, gfp_t flags, int node) __assume_slab_alignment
-									 __malloc;
+void *_kmem_cache_alloc_node(struct kmem_cache *s, gfp_t flags, int node) __assume_slab_alignment
+									  __malloc;
+#define kmem_cache_alloc_node(_s, _flags, _node)		\
+	alloc_hooks(_kmem_cache_alloc_node(_s, _flags, _node), void*, NULL)
 
-void *kmalloc_trace(struct kmem_cache *s, gfp_t flags, size_t size)
+void *_kmalloc_trace(struct kmem_cache *s, gfp_t flags, size_t size)
 		    __assume_kmalloc_alignment __alloc_size(3);
 
-void *kmalloc_node_trace(struct kmem_cache *s, gfp_t gfpflags,
+void *_kmalloc_node_trace(struct kmem_cache *s, gfp_t gfpflags,
 			 int node, size_t size) __assume_kmalloc_alignment
 						__alloc_size(4);
-void *kmalloc_large(size_t size, gfp_t flags) __assume_page_alignment
+#define kmalloc_trace(_s, _flags, _size)		\
+	alloc_hooks(_kmalloc_trace(_s, _flags, _size), void*, NULL)
+
+#define kmalloc_node_trace(_s, _gfpflags, _node, _size)	\
+	alloc_hooks(_kmalloc_node_trace(_s, _gfpflags, _node, _size), void*, NULL)
+
+void *_kmalloc_large(size_t size, gfp_t flags) __assume_page_alignment
 					      __alloc_size(1);
+#define kmalloc_large(_size, _flags)			\
+	alloc_hooks(_kmalloc_large(_size, _flags), void*, NULL)
 
-void *kmalloc_large_node(size_t size, gfp_t flags, int node) __assume_page_alignment
+void *_kmalloc_large_node(size_t size, gfp_t flags, int node) __assume_page_alignment
 							     __alloc_size(1);
+#define kmalloc_large_node(_size, _flags, _node)	\
+	alloc_hooks(_kmalloc_large_node(_size, _flags, _node), void*, NULL)
 
 /**
  * kmalloc - allocate kernel memory
@@ -554,37 +579,40 @@ void *kmalloc_large_node(size_t size, gfp_t flags, int node) __assume_page_align
  *	Try really hard to succeed the allocation but fail
  *	eventually.
  */
-static __always_inline __alloc_size(1) void *kmalloc(size_t size, gfp_t flags)
+static __always_inline __alloc_size(1) void *_kmalloc(size_t size, gfp_t flags)
 {
 	if (__builtin_constant_p(size) && size) {
 		unsigned int index;
 
 		if (size > KMALLOC_MAX_CACHE_SIZE)
-			return kmalloc_large(size, flags);
+			return _kmalloc_large(size, flags);
 
 		index = kmalloc_index(size);
-		return kmalloc_trace(
+		return _kmalloc_trace(
 				kmalloc_caches[kmalloc_type(flags)][index],
 				flags, size);
 	}
 	return __kmalloc(size, flags);
 }
+#define kmalloc(_size, _flags)  alloc_hooks(_kmalloc(_size, _flags), void*, NULL)
 
-static __always_inline __alloc_size(1) void *kmalloc_node(size_t size, gfp_t flags, int node)
+static __always_inline __alloc_size(1) void *_kmalloc_node(size_t size, gfp_t flags, int node)
 {
 	if (__builtin_constant_p(size) && size) {
 		unsigned int index;
 
 		if (size > KMALLOC_MAX_CACHE_SIZE)
-			return kmalloc_large_node(size, flags, node);
+			return _kmalloc_large_node(size, flags, node);
 
 		index = kmalloc_index(size);
-		return kmalloc_node_trace(
+		return _kmalloc_node_trace(
 				kmalloc_caches[kmalloc_type(flags)][index],
 				flags, node, size);
 	}
 	return __kmalloc_node(size, flags, node);
 }
+#define kmalloc_node(_size, _flags, _node)		\
+	alloc_hooks(_kmalloc_node(_size, _flags, _node), void*, NULL)
 
 /**
  * kmalloc_array - allocate memory for an array.
@@ -592,16 +620,18 @@ static __always_inline __alloc_size(1) void *kmalloc_node(size_t size, gfp_t fla
  * @size: element size.
  * @flags: the type of memory to allocate (see kmalloc).
  */
-static inline __alloc_size(1, 2) void *kmalloc_array(size_t n, size_t size, gfp_t flags)
+static inline __alloc_size(1, 2) void *_kmalloc_array(size_t n, size_t size, gfp_t flags)
 {
 	size_t bytes;
 
 	if (unlikely(check_mul_overflow(n, size, &bytes)))
 		return NULL;
 	if (__builtin_constant_p(n) && __builtin_constant_p(size))
-		return kmalloc(bytes, flags);
-	return __kmalloc(bytes, flags);
+		return _kmalloc(bytes, flags);
+	return _kmalloc(bytes, flags);
 }
+#define kmalloc_array(_n, _size, _flags)		\
+	alloc_hooks(_kmalloc_array(_n, _size, _flags), void*, NULL)
 
 /**
  * krealloc_array - reallocate memory for an array.
@@ -610,18 +640,20 @@ static inline __alloc_size(1, 2) void *kmalloc_array(size_t n, size_t size, gfp_
  * @new_size: new size of a single member of the array
  * @flags: the type of memory to allocate (see kmalloc)
  */
-static inline __realloc_size(2, 3) void * __must_check krealloc_array(void *p,
-								      size_t new_n,
-								      size_t new_size,
-								      gfp_t flags)
+static inline __realloc_size(2, 3) void * __must_check _krealloc_array(void *p,
+								       size_t new_n,
+								       size_t new_size,
+								       gfp_t flags)
 {
 	size_t bytes;
 
 	if (unlikely(check_mul_overflow(new_n, new_size, &bytes)))
 		return NULL;
 
-	return krealloc(p, bytes, flags);
+	return _krealloc(p, bytes, flags);
 }
+#define krealloc_array(_p, _n, _size, _flags)		\
+	alloc_hooks(_krealloc_array(_p, _n, _size, _flags), void*, NULL)
 
 /**
  * kcalloc - allocate memory for an array. The memory is set to zero.
@@ -629,16 +661,14 @@ static inline __realloc_size(2, 3) void * __must_check krealloc_array(void *p,
  * @size: element size.
  * @flags: the type of memory to allocate (see kmalloc).
  */
-static inline __alloc_size(1, 2) void *kcalloc(size_t n, size_t size, gfp_t flags)
-{
-	return kmalloc_array(n, size, flags | __GFP_ZERO);
-}
+#define kcalloc(_n, _size, _flags)			\
+	kmalloc_array(_n, _size, (_flags) | __GFP_ZERO)
 
 void *__kmalloc_node_track_caller(size_t size, gfp_t flags, int node,
 				  unsigned long caller) __alloc_size(1);
 #define kmalloc_node_track_caller(size, flags, node) \
-	__kmalloc_node_track_caller(size, flags, node, \
-				    _RET_IP_)
+	alloc_hooks(__kmalloc_node_track_caller(size, flags, node, \
+				    _RET_IP_), void*, NULL)
 
 /*
  * kmalloc_track_caller is a special version of kmalloc that records the
@@ -648,11 +678,10 @@ void *__kmalloc_node_track_caller(size_t size, gfp_t flags, int node,
  * allocator where we care about the real place the memory allocation
  * request comes from.
  */
-#define kmalloc_track_caller(size, flags) \
-	__kmalloc_node_track_caller(size, flags, \
-				    NUMA_NO_NODE, _RET_IP_)
+#define kmalloc_track_caller(size, flags)		\
+	kmalloc_node_track_caller(size, flags, NUMA_NO_NODE)
 
-static inline __alloc_size(1, 2) void *kmalloc_array_node(size_t n, size_t size, gfp_t flags,
+static inline __alloc_size(1, 2) void *_kmalloc_array_node(size_t n, size_t size, gfp_t flags,
 							  int node)
 {
 	size_t bytes;
@@ -660,75 +689,53 @@ static inline __alloc_size(1, 2) void *kmalloc_array_node(size_t n, size_t size,
 	if (unlikely(check_mul_overflow(n, size, &bytes)))
 		return NULL;
 	if (__builtin_constant_p(n) && __builtin_constant_p(size))
-		return kmalloc_node(bytes, flags, node);
+		return _kmalloc_node(bytes, flags, node);
 	return __kmalloc_node(bytes, flags, node);
 }
+#define kmalloc_array_node(_n, _size, _flags, _node)	\
+	alloc_hooks(_kmalloc_array_node(_n, _size, _flags, _node), void*, NULL)
 
-static inline __alloc_size(1, 2) void *kcalloc_node(size_t n, size_t size, gfp_t flags, int node)
-{
-	return kmalloc_array_node(n, size, flags | __GFP_ZERO, node);
-}
+#define kcalloc_node(_n, _size, _flags, _node)		\
+	kmalloc_array_node(_n, _size, (_flags) | __GFP_ZERO, _node)
 
 /*
  * Shortcuts
  */
-static inline void *kmem_cache_zalloc(struct kmem_cache *k, gfp_t flags)
-{
-	return kmem_cache_alloc(k, flags | __GFP_ZERO);
-}
+#define kmem_cache_zalloc(_k, _flags)			\
+	kmem_cache_alloc(_k, (_flags)|__GFP_ZERO)
 
 /**
  * kzalloc - allocate memory. The memory is set to zero.
  * @size: how many bytes of memory are required.
  * @flags: the type of memory to allocate (see kmalloc).
  */
-static inline __alloc_size(1) void *kzalloc(size_t size, gfp_t flags)
-{
-	return kmalloc(size, flags | __GFP_ZERO);
-}
-
-/**
- * kzalloc_node - allocate zeroed memory from a particular memory node.
- * @size: how many bytes of memory are required.
- * @flags: the type of memory to allocate (see kmalloc).
- * @node: memory node from which to allocate
- */
-static inline __alloc_size(1) void *kzalloc_node(size_t size, gfp_t flags, int node)
-{
-	return kmalloc_node(size, flags | __GFP_ZERO, node);
-}
+#define kzalloc(_size, _flags)			kmalloc(_size, (_flags)|__GFP_ZERO)
+#define kzalloc_node(_size, _flags, _node)	kmalloc_node(_size, (_flags)|__GFP_ZERO, _node)
 
-extern void *kvmalloc_node(size_t size, gfp_t flags, int node) __alloc_size(1);
-static inline __alloc_size(1) void *kvmalloc(size_t size, gfp_t flags)
-{
-	return kvmalloc_node(size, flags, NUMA_NO_NODE);
-}
-static inline __alloc_size(1) void *kvzalloc_node(size_t size, gfp_t flags, int node)
-{
-	return kvmalloc_node(size, flags | __GFP_ZERO, node);
-}
-static inline __alloc_size(1) void *kvzalloc(size_t size, gfp_t flags)
-{
-	return kvmalloc(size, flags | __GFP_ZERO);
-}
+extern void *_kvmalloc_node(size_t size, gfp_t flags, int node) __alloc_size(1);
+#define kvmalloc_node(_size, _flags, _node)              \
+	alloc_hooks(_kvmalloc_node(_size, _flags, _node), void*, NULL)
 
-static inline __alloc_size(1, 2) void *kvmalloc_array(size_t n, size_t size, gfp_t flags)
-{
-	size_t bytes;
+#define kvmalloc(_size, _flags)			kvmalloc_node(_size, _flags, NUMA_NO_NODE)
+#define kvzalloc(_size, _flags)			kvmalloc(_size, _flags|__GFP_ZERO)
 
-	if (unlikely(check_mul_overflow(n, size, &bytes)))
-		return NULL;
+#define kvzalloc_node(_size, _flags, _node)	kvmalloc_node(_size, _flags|__GFP_ZERO, _node)
 
-	return kvmalloc(bytes, flags);
-}
+#define kvmalloc_array(_n, _size, _flags)						\
+({											\
+	size_t _bytes;									\
+											\
+	!check_mul_overflow(_n, _size, &_bytes) ? kvmalloc(_bytes, _flags) : NULL;	\
+})
 
-static inline __alloc_size(1, 2) void *kvcalloc(size_t n, size_t size, gfp_t flags)
-{
-	return kvmalloc_array(n, size, flags | __GFP_ZERO);
-}
+#define kvcalloc(_n, _size, _flags)		kvmalloc_array(_n, _size, _flags|__GFP_ZERO)
 
-extern void *kvrealloc(const void *p, size_t oldsize, size_t newsize, gfp_t flags)
+extern void *_kvrealloc(const void *p, size_t oldsize, size_t newsize, gfp_t flags)
 		      __realloc_size(3);
+
+#define kvrealloc(_p, _oldsize, _newsize, _flags)					\
+	alloc_hooks(_kvrealloc(_p, _oldsize, _newsize, _flags), void*, NULL)
+
 extern void kvfree(const void *addr);
 extern void kvfree_sensitive(const void *addr, size_t len);
 
diff --git a/mm/slab.c b/mm/slab.c
index 026f0c08708a..e08bd3496f56 100644
--- a/mm/slab.c
+++ b/mm/slab.c
@@ -3448,18 +3448,18 @@ void *__kmem_cache_alloc_lru(struct kmem_cache *cachep, struct list_lru *lru,
 	return ret;
 }
 
-void *kmem_cache_alloc(struct kmem_cache *cachep, gfp_t flags)
+void *_kmem_cache_alloc(struct kmem_cache *cachep, gfp_t flags)
 {
 	return __kmem_cache_alloc_lru(cachep, NULL, flags);
 }
-EXPORT_SYMBOL(kmem_cache_alloc);
+EXPORT_SYMBOL(_kmem_cache_alloc);
 
-void *kmem_cache_alloc_lru(struct kmem_cache *cachep, struct list_lru *lru,
+void *_kmem_cache_alloc_lru(struct kmem_cache *cachep, struct list_lru *lru,
 			   gfp_t flags)
 {
 	return __kmem_cache_alloc_lru(cachep, lru, flags);
 }
-EXPORT_SYMBOL(kmem_cache_alloc_lru);
+EXPORT_SYMBOL(_kmem_cache_alloc_lru);
 
 static __always_inline void
 cache_alloc_debugcheck_after_bulk(struct kmem_cache *s, gfp_t flags,
@@ -3471,7 +3471,7 @@ cache_alloc_debugcheck_after_bulk(struct kmem_cache *s, gfp_t flags,
 		p[i] = cache_alloc_debugcheck_after(s, flags, p[i], caller);
 }
 
-int kmem_cache_alloc_bulk(struct kmem_cache *s, gfp_t flags, size_t size,
+int _kmem_cache_alloc_bulk(struct kmem_cache *s, gfp_t flags, size_t size,
 			  void **p)
 {
 	struct obj_cgroup *objcg = NULL;
@@ -3510,7 +3510,7 @@ int kmem_cache_alloc_bulk(struct kmem_cache *s, gfp_t flags, size_t size,
 	kmem_cache_free_bulk(s, i, p);
 	return 0;
 }
-EXPORT_SYMBOL(kmem_cache_alloc_bulk);
+EXPORT_SYMBOL(_kmem_cache_alloc_bulk);
 
 /**
  * kmem_cache_alloc_node - Allocate an object on the specified node
@@ -3525,7 +3525,7 @@ EXPORT_SYMBOL(kmem_cache_alloc_bulk);
  *
  * Return: pointer to the new object or %NULL in case of error
  */
-void *kmem_cache_alloc_node(struct kmem_cache *cachep, gfp_t flags, int nodeid)
+void *_kmem_cache_alloc_node(struct kmem_cache *cachep, gfp_t flags, int nodeid)
 {
 	void *ret = slab_alloc_node(cachep, NULL, flags, nodeid, cachep->object_size, _RET_IP_);
 
@@ -3533,7 +3533,7 @@ void *kmem_cache_alloc_node(struct kmem_cache *cachep, gfp_t flags, int nodeid)
 
 	return ret;
 }
-EXPORT_SYMBOL(kmem_cache_alloc_node);
+EXPORT_SYMBOL(_kmem_cache_alloc_node);
 
 void *__kmem_cache_alloc_node(struct kmem_cache *cachep, gfp_t flags,
 			     int nodeid, size_t orig_size,
diff --git a/mm/slab_common.c b/mm/slab_common.c
index 42777d66d0e3..a05333bbb7f1 100644
--- a/mm/slab_common.c
+++ b/mm/slab_common.c
@@ -1101,7 +1101,7 @@ size_t __ksize(const void *object)
 	return slab_ksize(folio_slab(folio)->slab_cache);
 }
 
-void *kmalloc_trace(struct kmem_cache *s, gfp_t gfpflags, size_t size)
+void *_kmalloc_trace(struct kmem_cache *s, gfp_t gfpflags, size_t size)
 {
 	void *ret = __kmem_cache_alloc_node(s, gfpflags, NUMA_NO_NODE,
 					    size, _RET_IP_);
@@ -1111,9 +1111,9 @@ void *kmalloc_trace(struct kmem_cache *s, gfp_t gfpflags, size_t size)
 	ret = kasan_kmalloc(s, ret, size, gfpflags);
 	return ret;
 }
-EXPORT_SYMBOL(kmalloc_trace);
+EXPORT_SYMBOL(_kmalloc_trace);
 
-void *kmalloc_node_trace(struct kmem_cache *s, gfp_t gfpflags,
+void *_kmalloc_node_trace(struct kmem_cache *s, gfp_t gfpflags,
 			 int node, size_t size)
 {
 	void *ret = __kmem_cache_alloc_node(s, gfpflags, node, size, _RET_IP_);
@@ -1123,7 +1123,7 @@ void *kmalloc_node_trace(struct kmem_cache *s, gfp_t gfpflags,
 	ret = kasan_kmalloc(s, ret, size, gfpflags);
 	return ret;
 }
-EXPORT_SYMBOL(kmalloc_node_trace);
+EXPORT_SYMBOL(_kmalloc_node_trace);
 
 gfp_t kmalloc_fix_flags(gfp_t flags)
 {
@@ -1168,7 +1168,7 @@ static void *__kmalloc_large_node(size_t size, gfp_t flags, int node)
 	return ptr;
 }
 
-void *kmalloc_large(size_t size, gfp_t flags)
+void *_kmalloc_large(size_t size, gfp_t flags)
 {
 	void *ret = __kmalloc_large_node(size, flags, NUMA_NO_NODE);
 
@@ -1176,9 +1176,9 @@ void *kmalloc_large(size_t size, gfp_t flags)
 		      flags, NUMA_NO_NODE);
 	return ret;
 }
-EXPORT_SYMBOL(kmalloc_large);
+EXPORT_SYMBOL(_kmalloc_large);
 
-void *kmalloc_large_node(size_t size, gfp_t flags, int node)
+void *_kmalloc_large_node(size_t size, gfp_t flags, int node)
 {
 	void *ret = __kmalloc_large_node(size, flags, node);
 
@@ -1186,7 +1186,7 @@ void *kmalloc_large_node(size_t size, gfp_t flags, int node)
 		      flags, node);
 	return ret;
 }
-EXPORT_SYMBOL(kmalloc_large_node);
+EXPORT_SYMBOL(_kmalloc_large_node);
 
 #ifdef CONFIG_SLAB_FREELIST_RANDOM
 /* Randomize a generic freelist */
@@ -1405,7 +1405,7 @@ __do_krealloc(const void *p, size_t new_size, gfp_t flags)
 		return (void *)p;
 	}
 
-	ret = kmalloc_track_caller(new_size, flags);
+	ret = __kmalloc_node_track_caller(new_size, flags, NUMA_NO_NODE, _RET_IP_);
 	if (ret && p) {
 		/* Disable KASAN checks as the object's redzone is accessed. */
 		kasan_disable_current();
@@ -1429,7 +1429,7 @@ __do_krealloc(const void *p, size_t new_size, gfp_t flags)
  *
  * Return: pointer to the allocated memory or %NULL in case of error
  */
-void *krealloc(const void *p, size_t new_size, gfp_t flags)
+void *_krealloc(const void *p, size_t new_size, gfp_t flags)
 {
 	void *ret;
 
@@ -1444,7 +1444,7 @@ void *krealloc(const void *p, size_t new_size, gfp_t flags)
 
 	return ret;
 }
-EXPORT_SYMBOL(krealloc);
+EXPORT_SYMBOL(_krealloc);
 
 /**
  * kfree_sensitive - Clear sensitive information in memory before freeing
diff --git a/mm/slub.c b/mm/slub.c
index 507b71372ee4..8f57fd086f69 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -3470,18 +3470,18 @@ void *__kmem_cache_alloc_lru(struct kmem_cache *s, struct list_lru *lru,
 	return ret;
 }
 
-void *kmem_cache_alloc(struct kmem_cache *s, gfp_t gfpflags)
+void *_kmem_cache_alloc(struct kmem_cache *s, gfp_t gfpflags)
 {
 	return __kmem_cache_alloc_lru(s, NULL, gfpflags);
 }
-EXPORT_SYMBOL(kmem_cache_alloc);
+EXPORT_SYMBOL(_kmem_cache_alloc);
 
-void *kmem_cache_alloc_lru(struct kmem_cache *s, struct list_lru *lru,
+void *_kmem_cache_alloc_lru(struct kmem_cache *s, struct list_lru *lru,
 			   gfp_t gfpflags)
 {
 	return __kmem_cache_alloc_lru(s, lru, gfpflags);
 }
-EXPORT_SYMBOL(kmem_cache_alloc_lru);
+EXPORT_SYMBOL(_kmem_cache_alloc_lru);
 
 void *__kmem_cache_alloc_node(struct kmem_cache *s, gfp_t gfpflags,
 			      int node, size_t orig_size,
@@ -3491,7 +3491,7 @@ void *__kmem_cache_alloc_node(struct kmem_cache *s, gfp_t gfpflags,
 			       caller, orig_size);
 }
 
-void *kmem_cache_alloc_node(struct kmem_cache *s, gfp_t gfpflags, int node)
+void *_kmem_cache_alloc_node(struct kmem_cache *s, gfp_t gfpflags, int node)
 {
 	void *ret = slab_alloc_node(s, NULL, gfpflags, node, _RET_IP_, s->object_size);
 
@@ -3499,7 +3499,7 @@ void *kmem_cache_alloc_node(struct kmem_cache *s, gfp_t gfpflags, int node)
 
 	return ret;
 }
-EXPORT_SYMBOL(kmem_cache_alloc_node);
+EXPORT_SYMBOL(_kmem_cache_alloc_node);
 
 static noinline void free_to_partial_list(
 	struct kmem_cache *s, struct slab *slab,
@@ -3779,6 +3779,7 @@ static __fastpath_inline void slab_free(struct kmem_cache *s, struct slab *slab,
 				      unsigned long addr)
 {
 	memcg_slab_free_hook(s, slab, p, cnt);
+	alloc_tagging_slab_free_hook(s, slab, p, cnt);
 	/*
 	 * With KASAN enabled slab_free_freelist_hook modifies the freelist
 	 * to remove objects, whose reuse must be delayed.
@@ -4009,7 +4010,7 @@ static int __kmem_cache_alloc_bulk(struct kmem_cache *s, gfp_t flags,
 #endif /* CONFIG_SLUB_TINY */
 
 /* Note that interrupts must be enabled when calling this function. */
-int kmem_cache_alloc_bulk(struct kmem_cache *s, gfp_t flags, size_t size,
+int _kmem_cache_alloc_bulk(struct kmem_cache *s, gfp_t flags, size_t size,
 			  void **p)
 {
 	int i;
@@ -4034,7 +4035,7 @@ int kmem_cache_alloc_bulk(struct kmem_cache *s, gfp_t flags, size_t size,
 			slab_want_init_on_alloc(flags, s), s->object_size);
 	return i;
 }
-EXPORT_SYMBOL(kmem_cache_alloc_bulk);
+EXPORT_SYMBOL(_kmem_cache_alloc_bulk);
 
 
 /*
diff --git a/mm/util.c b/mm/util.c
index dd12b9531ac4..e9077d1af676 100644
--- a/mm/util.c
+++ b/mm/util.c
@@ -579,7 +579,7 @@ EXPORT_SYMBOL(vm_mmap);
  *
  * Return: pointer to the allocated memory of %NULL in case of failure
  */
-void *kvmalloc_node(size_t size, gfp_t flags, int node)
+void *_kvmalloc_node(size_t size, gfp_t flags, int node)
 {
 	gfp_t kmalloc_flags = flags;
 	void *ret;
@@ -601,7 +601,7 @@ void *kvmalloc_node(size_t size, gfp_t flags, int node)
 		kmalloc_flags &= ~__GFP_NOFAIL;
 	}
 
-	ret = kmalloc_node(size, kmalloc_flags, node);
+	ret = _kmalloc_node(size, kmalloc_flags, node);
 
 	/*
 	 * It doesn't really make sense to fallback to vmalloc for sub page
@@ -630,7 +630,7 @@ void *kvmalloc_node(size_t size, gfp_t flags, int node)
 			flags, PAGE_KERNEL, VM_ALLOW_HUGE_VMAP,
 			node, __builtin_return_address(0));
 }
-EXPORT_SYMBOL(kvmalloc_node);
+EXPORT_SYMBOL(_kvmalloc_node);
 
 /**
  * kvfree() - Free memory.
@@ -669,7 +669,7 @@ void kvfree_sensitive(const void *addr, size_t len)
 }
 EXPORT_SYMBOL(kvfree_sensitive);
 
-void *kvrealloc(const void *p, size_t oldsize, size_t newsize, gfp_t flags)
+void *_kvrealloc(const void *p, size_t oldsize, size_t newsize, gfp_t flags)
 {
 	void *newp;
 
@@ -682,7 +682,7 @@ void *kvrealloc(const void *p, size_t oldsize, size_t newsize, gfp_t flags)
 	kvfree(p);
 	return newp;
 }
-EXPORT_SYMBOL(kvrealloc);
+EXPORT_SYMBOL(_kvrealloc);
 
 /**
  * __vmalloc_array - allocate memory for a virtually contiguous array.
-- 
2.40.1.495.gc816e09b53d-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230501165450.15352-26-surenb%40google.com.
