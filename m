Return-Path: <kasan-dev+bncBC7OD3FKWUERBRVAVKXAMGQEWZD5JEI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63e.google.com (mail-pl1-x63e.google.com [IPv6:2607:f8b0:4864:20::63e])
	by mail.lfdr.de (Postfix) with ESMTPS id 63F8D851FE4
	for <lists+kasan-dev@lfdr.de>; Mon, 12 Feb 2024 22:40:24 +0100 (CET)
Received: by mail-pl1-x63e.google.com with SMTP id d9443c01a7336-1d932efabe2sf69855ad.0
        for <lists+kasan-dev@lfdr.de>; Mon, 12 Feb 2024 13:40:24 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1707774023; cv=pass;
        d=google.com; s=arc-20160816;
        b=Z+tm83n82vSgyZU3qXy95/hqt5f8DnRIJQPTViCI8YRfxsanGPKatUYpQv14xh0+Ce
         Cdz7FJe+k3v5QnZPHMBdspwk9kfa+YZYgpC0TlMfvnOpy6IsUMrfA8RLjwvwNo9881L8
         5qmnXGRclHAt9pn3PWc/DPIkouUaC/sZbtZjCYvl7rAsaz5I8MwuiT4CJ1lh9Vn/l9qq
         eUxIfdWrHqFf2kQNn/ctijQArrYHhG9Vr8aBqDF2f7S/sM5x/vk9kZJdG34ZdHZe4Q8g
         ty0dW3aVNe7YtvwHyzvELVGsqA/wRVHmpmRgkMxNQfNsUrQlWsKZB+GRZ5CEGHs9Dm99
         YVnA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=+Mpfo2fbr4HgVmCxr1U5sW5fIsrV6hvuqTnk9tgNIr8=;
        fh=4Y6oHd2k0MyIxU4Yf0N6IKVmJ6c1/tAcCaX59o/3jzw=;
        b=Zqay3wPJv9c55Zr/iup7QGBBjZ4vaZt0j84JJy5eRkHAcGWNjfST4f5+eKjTxve5Ru
         kih7FvddH1QdXSLN9rOYRW/O+zlp/SSA3DJXqsLHG+tGkLeN4ebuxUc8MN1meqdzqlOU
         DsnIrZuJbEVw+wWP4bzvWQOBRZGXzjfLXrUrPR7jayGTVS8GcwowiDUXPf2zQFiBTOPk
         bpM4Tj1znGh9gR28Qi6cDj3+4bD6S3YIig7mYr9oBaFr5Ow2i1fnDqOUV0qy1bX81InY
         mhKBbt+PCNnks8DNmEqq0/JmNGUb+znGLTW0L+l/JlGdNumAgKho/TgmlalXFepcnovR
         n6GA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="mR4/Rwx0";
       spf=pass (google.com: domain of 3rjdkzqykccm130nwkpxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3RJDKZQYKCcM130nwkpxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1707774023; x=1708378823; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=+Mpfo2fbr4HgVmCxr1U5sW5fIsrV6hvuqTnk9tgNIr8=;
        b=u/6KRVMMlj0X6FlcbxDEVIdSZ1VRlK73RvcEeBYOysf72ys5jjd7RbJfn6r0rHaJQM
         qOwrLLcBmvhuUGNkW2ofpltIHPG5We/XoWSp/eBz7Vj7phTyU0K96gpc/srAFlHqjL1s
         pwUc/Xn3nofoPZDKmx9AZ6THRU3sc1VWPO/6kxxZ4Ix2RntHs5vnySirJs6oZ5571jGw
         sHANe8dOa7VzwDLZLRu2zXuduMRPTE7+0wwwOw6TpF449o289z0Skw4qRDMuJPqdcl2o
         EYvjdMZqbPru6HGFf89kvpm0k8vf0JQBsEHZsfCfiGF95UJXvSBlrXHR/cCMbxLGxuC5
         ccwg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1707774023; x=1708378823;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=+Mpfo2fbr4HgVmCxr1U5sW5fIsrV6hvuqTnk9tgNIr8=;
        b=h4fb1pzDc2ISQ43iHfQS4vw66zhcKmtkJQxDzhAbUMrDd3KWC30ixg7WxTP7iYNuCE
         Y2icy9hiWa9mSFotZSasw0JmBYcI0safdWB9/YOGGOBoAGe7egslNuohgad/izLy/Urx
         FO/Wl7Qah3ZM8pVJBo1VBxLpPA5OHib9Y9yhnkR6uGeRphkWz7J5mxIr7hYtfcBZqZNg
         4oqCup7HSgyM61uSqPl85sLW+/WW3nZEm+nLZXMkSKwygFrXWLPzBHu5mcOkoktBgrJK
         cM7c3pK1ctzsXHZPPgiu8OHvWJrbV7oktKUtmaW9J/2cKHwCQA/LKsVQWE7MjqMbkrOL
         VS7A==
X-Forwarded-Encrypted: i=2; AJvYcCWnA/czxgRts/D/H16e7WSyTxlvBfhB/rmsUK12Sho+96Ap6FbqaoNSK9LT5v31RTAvXvjxy4arl2gmDyCGICrYox3ZNq2WqA==
X-Gm-Message-State: AOJu0YwCPL77npNLFJaiFiOwW41q1yhQjeO9P1eBy7iN8yqGGMPCIPEC
	pkRKEW1rFU3obQboqCT++FKi4SZKeS3M+y9GZTteXyg8rvlMwV12
X-Google-Smtp-Source: AGHT+IH5YWKQlmAN46xZZ6J6Ermm+LNzFzv6Ol05Vr6HQvmeRWyWTxXh7As5ASjcXIfHnmZ8aDNR9A==
X-Received: by 2002:a17:902:bcc6:b0:1d9:f4c5:6322 with SMTP id o6-20020a170902bcc600b001d9f4c56322mr22893pls.4.1707774022873;
        Mon, 12 Feb 2024 13:40:22 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:1d1a:b0:6e0:f00b:3ffe with SMTP id
 a26-20020a056a001d1a00b006e0f00b3ffels352493pfx.0.-pod-prod-01-us; Mon, 12
 Feb 2024 13:40:21 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXaBd8cgaW7T8atoVTiQxxBFm3n3BoMrW13wvE68IbsVRNJ4JN79nkBQu1t4hCjAW/AsY206xxjXtNVxSWr+Kj9Vao+x0D//QWLWQ==
X-Received: by 2002:a62:e309:0:b0:6e0:dc68:409d with SMTP id g9-20020a62e309000000b006e0dc68409dmr3285276pfh.2.1707774021730;
        Mon, 12 Feb 2024 13:40:21 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1707774021; cv=none;
        d=google.com; s=arc-20160816;
        b=PFAE4U2wturHVEOjvKGj27us7yEghgVAtzUePhDKiYo1rZ9xa+dMcC5+D3oPyW/Ydl
         NTEKeJxpjSg1smBDoXQF29HCR0BnMFwcd5IAsfyOtv4Qday0wPTAj09Hda1sA72YtU6R
         BH++rvYKZJSr4s0cUG9fBV6/gm5KEAD6PaJKTtSC0KcJRDmwrTNhvEhVY27egl6sBtN3
         WIoGieBo9ctfXu9bEUKsgLK5Yv5l1I/784Efv2Lffk+Y45IABi2nQwyGl7sGde56PERp
         IneB/jUoFZ7pJAjj12k3SdnI6eG7cboZtVJrumwpzf9ZqIcvZMlcZTw950BMQoIyKFUF
         cfuA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=BW+F7aNEsn42MAqFjWDXBChBmgYKTAcf/l21NhAmWHo=;
        fh=lUsMXV5vp6KCMCvB3R2fosuqb5RnAwBBItxWahiISwI=;
        b=Gy/RwNJj7XSLQn8VAbSH4mUoTeTudhvWWaJk5Ay3VLJGnLDLB3dUKBDPLxJEApYDKc
         NTAbURuoJd5JPi8RHKl6JWfmth8R+4J3nDvMk4VRpPr7YbPxnI12zvhwCKspnhlx/GPN
         sjcu35kJi8sHa0Pq7F/YJtrsSd1KYvmO834K2J4vH9btUgJo5jCue1s05lxem0FIouTv
         42REYroNqAFhiHgpogFSxAg0KKarBF3b83N1M64zBCt3v0oociPMQeR57p2Tdanb+PQu
         UuACfr2KyLLb5OxeESv0+IHcyXyNr+cvYQt7CsM6DwLiiC4L7Vh2Q6yCImGd2Amcq5a9
         eA4g==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="mR4/Rwx0";
       spf=pass (google.com: domain of 3rjdkzqykccm130nwkpxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3RJDKZQYKCcM130nwkpxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Forwarded-Encrypted: i=1; AJvYcCU0BIde20zxa1POq4ZUkZUmRUeXk3t40Y8VGN8R1RWI723EkgUBWGUVhPSoNbGOgCuW1M2K3Ul+IvFmvVnmVVX1sHgCuPRXwo3NLA==
Received: from mail-yb1-xb49.google.com (mail-yb1-xb49.google.com. [2607:f8b0:4864:20::b49])
        by gmr-mx.google.com with ESMTPS id p6-20020a625b06000000b006e06c8a8c7esi1189722pfb.1.2024.02.12.13.40.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 12 Feb 2024 13:40:21 -0800 (PST)
Received-SPF: pass (google.com: domain of 3rjdkzqykccm130nwkpxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) client-ip=2607:f8b0:4864:20::b49;
Received: by mail-yb1-xb49.google.com with SMTP id 3f1490d57ef6-dc6dbdcfd39so7591526276.2
        for <kasan-dev@googlegroups.com>; Mon, 12 Feb 2024 13:40:21 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCVfImXwlEo6Ai9bQIV9y9pHg1gvy1aBW8ipednaN8JftLaevK0UdoPSwGsBrP4r6F1gMCnfT7nEFhoS3DF70qTwQ9h0OfKsS9s8eg==
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:201:b848:2b3f:be49:9cbc])
 (user=surenb job=sendgmr) by 2002:a05:6902:124a:b0:dc6:9e4a:f950 with SMTP id
 t10-20020a056902124a00b00dc69e4af950mr2042179ybu.3.1707774020742; Mon, 12 Feb
 2024 13:40:20 -0800 (PST)
Date: Mon, 12 Feb 2024 13:39:08 -0800
In-Reply-To: <20240212213922.783301-1-surenb@google.com>
Mime-Version: 1.0
References: <20240212213922.783301-1-surenb@google.com>
X-Mailer: git-send-email 2.43.0.687.g38aa6559b0-goog
Message-ID: <20240212213922.783301-23-surenb@google.com>
Subject: [PATCH v3 22/35] mm/slab: enable slab allocation tagging for kmalloc
 and friends
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
To: akpm@linux-foundation.org
Cc: kent.overstreet@linux.dev, mhocko@suse.com, vbabka@suse.cz, 
	hannes@cmpxchg.org, roman.gushchin@linux.dev, mgorman@suse.de, 
	dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com, 
	corbet@lwn.net, void@manifault.com, peterz@infradead.org, 
	juri.lelli@redhat.com, catalin.marinas@arm.com, will@kernel.org, 
	arnd@arndb.de, tglx@linutronix.de, mingo@redhat.com, 
	dave.hansen@linux.intel.com, x86@kernel.org, peterx@redhat.com, 
	david@redhat.com, axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org, 
	nathan@kernel.org, dennis@kernel.org, tj@kernel.org, muchun.song@linux.dev, 
	rppt@kernel.org, paulmck@kernel.org, pasha.tatashin@soleen.com, 
	yosryahmed@google.com, yuzhao@google.com, dhowells@redhat.com, 
	hughd@google.com, andreyknvl@gmail.com, keescook@chromium.org, 
	ndesaulniers@google.com, vvvvvv@google.com, gregkh@linuxfoundation.org, 
	ebiggers@google.com, ytcoode@gmail.com, vincent.guittot@linaro.org, 
	dietmar.eggemann@arm.com, rostedt@goodmis.org, bsegall@google.com, 
	bristot@redhat.com, vschneid@redhat.com, cl@linux.com, penberg@kernel.org, 
	iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com, glider@google.com, 
	elver@google.com, dvyukov@google.com, shakeelb@google.com, 
	songmuchun@bytedance.com, jbaron@akamai.com, rientjes@google.com, 
	minchan@google.com, kaleshsingh@google.com, surenb@google.com, 
	kernel-team@android.com, linux-doc@vger.kernel.org, 
	linux-kernel@vger.kernel.org, iommu@lists.linux.dev, 
	linux-arch@vger.kernel.org, linux-fsdevel@vger.kernel.org, linux-mm@kvack.org, 
	linux-modules@vger.kernel.org, kasan-dev@googlegroups.com, 
	cgroups@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: surenb@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b="mR4/Rwx0";       spf=pass
 (google.com: domain of 3rjdkzqykccm130nwkpxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3RJDKZQYKCcM130nwkpxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--surenb.bounces.google.com;
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
 include/linux/fortify-string.h |   5 +-
 include/linux/slab.h           | 177 ++++++++++++++++-----------------
 include/linux/string.h         |   4 +-
 mm/slab_common.c               |   6 +-
 mm/slub.c                      |  54 +++++-----
 mm/util.c                      |  20 ++--
 6 files changed, 134 insertions(+), 132 deletions(-)

diff --git a/include/linux/fortify-string.h b/include/linux/fortify-string.h
index 89a6888f2f9e..55f66bd8a366 100644
--- a/include/linux/fortify-string.h
+++ b/include/linux/fortify-string.h
@@ -697,9 +697,9 @@ __FORTIFY_INLINE void *memchr_inv(const void * const POS0 p, int c, size_t size)
 	return __real_memchr_inv(p, c, size);
 }
 
-extern void *__real_kmemdup(const void *src, size_t len, gfp_t gfp) __RENAME(kmemdup)
+extern void *__real_kmemdup(const void *src, size_t len, gfp_t gfp) __RENAME(kmemdup_noprof)
 								    __realloc_size(2);
-__FORTIFY_INLINE void *kmemdup(const void * const POS0 p, size_t size, gfp_t gfp)
+__FORTIFY_INLINE void *kmemdup_noprof(const void * const POS0 p, size_t size, gfp_t gfp)
 {
 	const size_t p_size = __struct_size(p);
 
@@ -709,6 +709,7 @@ __FORTIFY_INLINE void *kmemdup(const void * const POS0 p, size_t size, gfp_t gfp
 		fortify_panic(__func__);
 	return __real_kmemdup(p, size, gfp);
 }
+#define kmemdup(...)	alloc_hooks(kmemdup_noprof(__VA_ARGS__))
 
 /**
  * strcpy - Copy a string into another string buffer
diff --git a/include/linux/slab.h b/include/linux/slab.h
index 3ac2fc830f0f..910473e07e86 100644
--- a/include/linux/slab.h
+++ b/include/linux/slab.h
@@ -230,7 +230,10 @@ int kmem_cache_shrink(struct kmem_cache *s);
 /*
  * Common kmalloc functions provided by all allocators
  */
-void * __must_check krealloc(const void *objp, size_t new_size, gfp_t flags) __realloc_size(2);
+void * __must_check krealloc_noprof(const void *objp, size_t new_size,
+				    gfp_t flags) __realloc_size(2);
+#define krealloc(...)				alloc_hooks(krealloc_noprof(__VA_ARGS__))
+
 void kfree(const void *objp);
 void kfree_sensitive(const void *objp);
 size_t __ksize(const void *objp);
@@ -482,7 +485,10 @@ static __always_inline unsigned int __kmalloc_index(size_t size,
 static_assert(PAGE_SHIFT <= 20);
 #define kmalloc_index(s) __kmalloc_index(s, true)
 
-void *__kmalloc(size_t size, gfp_t flags) __assume_kmalloc_alignment __alloc_size(1);
+#include <linux/alloc_tag.h>
+
+void *__kmalloc_noprof(size_t size, gfp_t flags) __assume_kmalloc_alignment __alloc_size(1);
+#define __kmalloc(...)				alloc_hooks(__kmalloc_noprof(__VA_ARGS__))
 
 /**
  * kmem_cache_alloc - Allocate an object
@@ -494,9 +500,14 @@ void *__kmalloc(size_t size, gfp_t flags) __assume_kmalloc_alignment __alloc_siz
  *
  * Return: pointer to the new object or %NULL in case of error
  */
-void *kmem_cache_alloc(struct kmem_cache *cachep, gfp_t flags) __assume_slab_alignment __malloc;
-void *kmem_cache_alloc_lru(struct kmem_cache *s, struct list_lru *lru,
-			   gfp_t gfpflags) __assume_slab_alignment __malloc;
+void *kmem_cache_alloc_noprof(struct kmem_cache *cachep,
+			      gfp_t flags) __assume_slab_alignment __malloc;
+#define kmem_cache_alloc(...)			alloc_hooks(kmem_cache_alloc_noprof(__VA_ARGS__))
+
+void *kmem_cache_alloc_lru_noprof(struct kmem_cache *s, struct list_lru *lru,
+			    gfp_t gfpflags) __assume_slab_alignment __malloc;
+#define kmem_cache_alloc_lru(...)	alloc_hooks(kmem_cache_alloc_lru_noprof(__VA_ARGS__))
+
 void kmem_cache_free(struct kmem_cache *s, void *objp);
 
 /*
@@ -507,29 +518,40 @@ void kmem_cache_free(struct kmem_cache *s, void *objp);
  * Note that interrupts must be enabled when calling these functions.
  */
 void kmem_cache_free_bulk(struct kmem_cache *s, size_t size, void **p);
-int kmem_cache_alloc_bulk(struct kmem_cache *s, gfp_t flags, size_t size, void **p);
+
+int kmem_cache_alloc_bulk_noprof(struct kmem_cache *s, gfp_t flags, size_t size, void **p);
+#define kmem_cache_alloc_bulk(...)	alloc_hooks(kmem_cache_alloc_bulk_noprof(__VA_ARGS__))
 
 static __always_inline void kfree_bulk(size_t size, void **p)
 {
 	kmem_cache_free_bulk(NULL, size, p);
 }
 
-void *__kmalloc_node(size_t size, gfp_t flags, int node) __assume_kmalloc_alignment
+void *__kmalloc_node_noprof(size_t size, gfp_t flags, int node) __assume_kmalloc_alignment
 							 __alloc_size(1);
-void *kmem_cache_alloc_node(struct kmem_cache *s, gfp_t flags, int node) __assume_slab_alignment
-									 __malloc;
+#define __kmalloc_node(...)			alloc_hooks(__kmalloc_node_noprof(__VA_ARGS__))
 
-void *kmalloc_trace(struct kmem_cache *s, gfp_t flags, size_t size)
+void *kmem_cache_alloc_node_noprof(struct kmem_cache *s, gfp_t flags,
+				   int node) __assume_slab_alignment __malloc;
+#define kmem_cache_alloc_node(...)	alloc_hooks(kmem_cache_alloc_node_noprof(__VA_ARGS__))
+
+void *kmalloc_trace_noprof(struct kmem_cache *s, gfp_t flags, size_t size)
 		    __assume_kmalloc_alignment __alloc_size(3);
 
-void *kmalloc_node_trace(struct kmem_cache *s, gfp_t gfpflags,
-			 int node, size_t size) __assume_kmalloc_alignment
+void *kmalloc_node_trace_noprof(struct kmem_cache *s, gfp_t gfpflags,
+		int node, size_t size) __assume_kmalloc_alignment
 						__alloc_size(4);
-void *kmalloc_large(size_t size, gfp_t flags) __assume_page_alignment
+#define kmalloc_trace(...)			alloc_hooks(kmalloc_trace_noprof(__VA_ARGS__))
+
+#define kmalloc_node_trace(...)			alloc_hooks(kmalloc_node_trace_noprof(__VA_ARGS__))
+
+void *kmalloc_large_noprof(size_t size, gfp_t flags) __assume_page_alignment
 					      __alloc_size(1);
+#define kmalloc_large(...)			alloc_hooks(kmalloc_large_noprof(__VA_ARGS__))
 
-void *kmalloc_large_node(size_t size, gfp_t flags, int node) __assume_page_alignment
+void *kmalloc_large_node_noprof(size_t size, gfp_t flags, int node) __assume_page_alignment
 							     __alloc_size(1);
+#define kmalloc_large_node(...)			alloc_hooks(kmalloc_large_node_noprof(__VA_ARGS__))
 
 /**
  * kmalloc - allocate kernel memory
@@ -585,37 +607,39 @@ void *kmalloc_large_node(size_t size, gfp_t flags, int node) __assume_page_align
  *	Try really hard to succeed the allocation but fail
  *	eventually.
  */
-static __always_inline __alloc_size(1) void *kmalloc(size_t size, gfp_t flags)
+static __always_inline __alloc_size(1) void *kmalloc_noprof(size_t size, gfp_t flags)
 {
 	if (__builtin_constant_p(size) && size) {
 		unsigned int index;
 
 		if (size > KMALLOC_MAX_CACHE_SIZE)
-			return kmalloc_large(size, flags);
+			return kmalloc_large_noprof(size, flags);
 
 		index = kmalloc_index(size);
-		return kmalloc_trace(
+		return kmalloc_trace_noprof(
 				kmalloc_caches[kmalloc_type(flags, _RET_IP_)][index],
 				flags, size);
 	}
-	return __kmalloc(size, flags);
+	return __kmalloc_noprof(size, flags);
 }
+#define kmalloc(...)				alloc_hooks(kmalloc_noprof(__VA_ARGS__))
 
-static __always_inline __alloc_size(1) void *kmalloc_node(size_t size, gfp_t flags, int node)
+static __always_inline __alloc_size(1) void *kmalloc_node_noprof(size_t size, gfp_t flags, int node)
 {
 	if (__builtin_constant_p(size) && size) {
 		unsigned int index;
 
 		if (size > KMALLOC_MAX_CACHE_SIZE)
-			return kmalloc_large_node(size, flags, node);
+			return kmalloc_large_node_noprof(size, flags, node);
 
 		index = kmalloc_index(size);
-		return kmalloc_node_trace(
+		return kmalloc_node_trace_noprof(
 				kmalloc_caches[kmalloc_type(flags, _RET_IP_)][index],
 				flags, node, size);
 	}
-	return __kmalloc_node(size, flags, node);
+	return __kmalloc_node_noprof(size, flags, node);
 }
+#define kmalloc_node(...)			alloc_hooks(kmalloc_node_noprof(__VA_ARGS__))
 
 /**
  * kmalloc_array - allocate memory for an array.
@@ -623,16 +647,17 @@ static __always_inline __alloc_size(1) void *kmalloc_node(size_t size, gfp_t fla
  * @size: element size.
  * @flags: the type of memory to allocate (see kmalloc).
  */
-static inline __alloc_size(1, 2) void *kmalloc_array(size_t n, size_t size, gfp_t flags)
+static inline __alloc_size(1, 2) void *kmalloc_array_noprof(size_t n, size_t size, gfp_t flags)
 {
 	size_t bytes;
 
 	if (unlikely(check_mul_overflow(n, size, &bytes)))
 		return NULL;
 	if (__builtin_constant_p(n) && __builtin_constant_p(size))
-		return kmalloc(bytes, flags);
-	return __kmalloc(bytes, flags);
+		return kmalloc_noprof(bytes, flags);
+	return kmalloc_noprof(bytes, flags);
 }
+#define kmalloc_array(...)			alloc_hooks(kmalloc_array_noprof(__VA_ARGS__))
 
 /**
  * krealloc_array - reallocate memory for an array.
@@ -641,18 +666,19 @@ static inline __alloc_size(1, 2) void *kmalloc_array(size_t n, size_t size, gfp_
  * @new_size: new size of a single member of the array
  * @flags: the type of memory to allocate (see kmalloc)
  */
-static inline __realloc_size(2, 3) void * __must_check krealloc_array(void *p,
-								      size_t new_n,
-								      size_t new_size,
-								      gfp_t flags)
+static inline __realloc_size(2, 3) void * __must_check krealloc_array_noprof(void *p,
+								       size_t new_n,
+								       size_t new_size,
+								       gfp_t flags)
 {
 	size_t bytes;
 
 	if (unlikely(check_mul_overflow(new_n, new_size, &bytes)))
 		return NULL;
 
-	return krealloc(p, bytes, flags);
+	return krealloc_noprof(p, bytes, flags);
 }
+#define krealloc_array(...)			alloc_hooks(krealloc_array_noprof(__VA_ARGS__))
 
 /**
  * kcalloc - allocate memory for an array. The memory is set to zero.
@@ -660,16 +686,12 @@ static inline __realloc_size(2, 3) void * __must_check krealloc_array(void *p,
  * @size: element size.
  * @flags: the type of memory to allocate (see kmalloc).
  */
-static inline __alloc_size(1, 2) void *kcalloc(size_t n, size_t size, gfp_t flags)
-{
-	return kmalloc_array(n, size, flags | __GFP_ZERO);
-}
+#define kcalloc(_n, _size, _flags)		kmalloc_array(_n, _size, (_flags) | __GFP_ZERO)
 
-void *__kmalloc_node_track_caller(size_t size, gfp_t flags, int node,
+void *kmalloc_node_track_caller_noprof(size_t size, gfp_t flags, int node,
 				  unsigned long caller) __alloc_size(1);
-#define kmalloc_node_track_caller(size, flags, node) \
-	__kmalloc_node_track_caller(size, flags, node, \
-				    _RET_IP_)
+#define kmalloc_node_track_caller(...)		\
+	alloc_hooks(kmalloc_node_track_caller_noprof(__VA_ARGS__, _RET_IP_))
 
 /*
  * kmalloc_track_caller is a special version of kmalloc that records the
@@ -679,11 +701,9 @@ void *__kmalloc_node_track_caller(size_t size, gfp_t flags, int node,
  * allocator where we care about the real place the memory allocation
  * request comes from.
  */
-#define kmalloc_track_caller(size, flags) \
-	__kmalloc_node_track_caller(size, flags, \
-				    NUMA_NO_NODE, _RET_IP_)
+#define kmalloc_track_caller(...)		kmalloc_node_track_caller(__VA_ARGS__, NUMA_NO_NODE)
 
-static inline __alloc_size(1, 2) void *kmalloc_array_node(size_t n, size_t size, gfp_t flags,
+static inline __alloc_size(1, 2) void *kmalloc_array_node_noprof(size_t n, size_t size, gfp_t flags,
 							  int node)
 {
 	size_t bytes;
@@ -691,75 +711,52 @@ static inline __alloc_size(1, 2) void *kmalloc_array_node(size_t n, size_t size,
 	if (unlikely(check_mul_overflow(n, size, &bytes)))
 		return NULL;
 	if (__builtin_constant_p(n) && __builtin_constant_p(size))
-		return kmalloc_node(bytes, flags, node);
-	return __kmalloc_node(bytes, flags, node);
+		return kmalloc_node_noprof(bytes, flags, node);
+	return __kmalloc_node_noprof(bytes, flags, node);
 }
+#define kmalloc_array_node(...)			alloc_hooks(kmalloc_array_node_noprof(__VA_ARGS__))
 
-static inline __alloc_size(1, 2) void *kcalloc_node(size_t n, size_t size, gfp_t flags, int node)
-{
-	return kmalloc_array_node(n, size, flags | __GFP_ZERO, node);
-}
+#define kcalloc_node(_n, _size, _flags, _node)	\
+	kmalloc_array_node(_n, _size, (_flags) | __GFP_ZERO, _node)
 
 /*
  * Shortcuts
  */
-static inline void *kmem_cache_zalloc(struct kmem_cache *k, gfp_t flags)
-{
-	return kmem_cache_alloc(k, flags | __GFP_ZERO);
-}
+#define kmem_cache_zalloc(_k, _flags)		kmem_cache_alloc(_k, (_flags)|__GFP_ZERO)
 
 /**
  * kzalloc - allocate memory. The memory is set to zero.
  * @size: how many bytes of memory are required.
  * @flags: the type of memory to allocate (see kmalloc).
  */
-static inline __alloc_size(1) void *kzalloc(size_t size, gfp_t flags)
+static inline __alloc_size(1) void *kzalloc_noprof(size_t size, gfp_t flags)
 {
-	return kmalloc(size, flags | __GFP_ZERO);
+	return kmalloc_noprof(size, flags | __GFP_ZERO);
 }
+#define kzalloc(...)				alloc_hooks(kzalloc_noprof(__VA_ARGS__))
+#define kzalloc_node(_size, _flags, _node)	kmalloc_node(_size, (_flags)|__GFP_ZERO, _node)
 
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
+extern void *kvmalloc_node_noprof(size_t size, gfp_t flags, int node) __alloc_size(1);
+#define kvmalloc_node(...)			alloc_hooks(kvmalloc_node_noprof(__VA_ARGS__))
 
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
+#define kvmalloc(_size, _flags)			kvmalloc_node(_size, _flags, NUMA_NO_NODE)
+#define kvzalloc(_size, _flags)			kvmalloc(_size, _flags|__GFP_ZERO)
 
-static inline __alloc_size(1, 2) void *kvmalloc_array(size_t n, size_t size, gfp_t flags)
-{
-	size_t bytes;
-
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
+extern void *kvrealloc_noprof(const void *p, size_t oldsize, size_t newsize, gfp_t flags)
 		      __realloc_size(3);
+#define kvrealloc(...)				alloc_hooks(kvrealloc_noprof(__VA_ARGS__))
+
 extern void kvfree(const void *addr);
 DEFINE_FREE(kvfree, void *, if (_T) kvfree(_T))
 
diff --git a/include/linux/string.h b/include/linux/string.h
index ab148d8dbfc1..14e4fb4340f4 100644
--- a/include/linux/string.h
+++ b/include/linux/string.h
@@ -214,7 +214,9 @@ extern void kfree_const(const void *x);
 extern char *kstrdup(const char *s, gfp_t gfp) __malloc;
 extern const char *kstrdup_const(const char *s, gfp_t gfp);
 extern char *kstrndup(const char *s, size_t len, gfp_t gfp);
-extern void *kmemdup(const void *src, size_t len, gfp_t gfp) __realloc_size(2);
+extern void *kmemdup_noprof(const void *src, size_t len, gfp_t gfp) __realloc_size(2);
+#define kmemdup(...)	alloc_hooks(kmemdup_noprof(__VA_ARGS__))
+
 extern void *kvmemdup(const void *src, size_t len, gfp_t gfp) __realloc_size(2);
 extern char *kmemdup_nul(const char *s, size_t len, gfp_t gfp);
 
diff --git a/mm/slab_common.c b/mm/slab_common.c
index 83fec2dd2e2d..21b0b9e9cd9e 100644
--- a/mm/slab_common.c
+++ b/mm/slab_common.c
@@ -1234,7 +1234,7 @@ __do_krealloc(const void *p, size_t new_size, gfp_t flags)
 		return (void *)p;
 	}
 
-	ret = kmalloc_track_caller(new_size, flags);
+	ret = kmalloc_node_track_caller_noprof(new_size, flags, NUMA_NO_NODE, _RET_IP_);
 	if (ret && p) {
 		/* Disable KASAN checks as the object's redzone is accessed. */
 		kasan_disable_current();
@@ -1258,7 +1258,7 @@ __do_krealloc(const void *p, size_t new_size, gfp_t flags)
  *
  * Return: pointer to the allocated memory or %NULL in case of error
  */
-void *krealloc(const void *p, size_t new_size, gfp_t flags)
+void *krealloc_noprof(const void *p, size_t new_size, gfp_t flags)
 {
 	void *ret;
 
@@ -1273,7 +1273,7 @@ void *krealloc(const void *p, size_t new_size, gfp_t flags)
 
 	return ret;
 }
-EXPORT_SYMBOL(krealloc);
+EXPORT_SYMBOL(krealloc_noprof);
 
 /**
  * kfree_sensitive - Clear sensitive information in memory before freeing
diff --git a/mm/slub.c b/mm/slub.c
index f4d5794c1e86..9ea03d6e9c9d 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -3871,7 +3871,7 @@ static __fastpath_inline void *slab_alloc_node(struct kmem_cache *s, struct list
 	return object;
 }
 
-void *kmem_cache_alloc(struct kmem_cache *s, gfp_t gfpflags)
+void *kmem_cache_alloc_noprof(struct kmem_cache *s, gfp_t gfpflags)
 {
 	void *ret = slab_alloc_node(s, NULL, gfpflags, NUMA_NO_NODE, _RET_IP_,
 				    s->object_size);
@@ -3880,9 +3880,9 @@ void *kmem_cache_alloc(struct kmem_cache *s, gfp_t gfpflags)
 
 	return ret;
 }
-EXPORT_SYMBOL(kmem_cache_alloc);
+EXPORT_SYMBOL(kmem_cache_alloc_noprof);
 
-void *kmem_cache_alloc_lru(struct kmem_cache *s, struct list_lru *lru,
+void *kmem_cache_alloc_lru_noprof(struct kmem_cache *s, struct list_lru *lru,
 			   gfp_t gfpflags)
 {
 	void *ret = slab_alloc_node(s, lru, gfpflags, NUMA_NO_NODE, _RET_IP_,
@@ -3892,10 +3892,10 @@ void *kmem_cache_alloc_lru(struct kmem_cache *s, struct list_lru *lru,
 
 	return ret;
 }
-EXPORT_SYMBOL(kmem_cache_alloc_lru);
+EXPORT_SYMBOL(kmem_cache_alloc_lru_noprof);
 
 /**
- * kmem_cache_alloc_node - Allocate an object on the specified node
+ * kmem_cache_alloc_node_noprof - Allocate an object on the specified node
  * @s: The cache to allocate from.
  * @gfpflags: See kmalloc().
  * @node: node number of the target node.
@@ -3907,7 +3907,7 @@ EXPORT_SYMBOL(kmem_cache_alloc_lru);
  *
  * Return: pointer to the new object or %NULL in case of error
  */
-void *kmem_cache_alloc_node(struct kmem_cache *s, gfp_t gfpflags, int node)
+void *kmem_cache_alloc_node_noprof(struct kmem_cache *s, gfp_t gfpflags, int node)
 {
 	void *ret = slab_alloc_node(s, NULL, gfpflags, node, _RET_IP_, s->object_size);
 
@@ -3915,7 +3915,7 @@ void *kmem_cache_alloc_node(struct kmem_cache *s, gfp_t gfpflags, int node)
 
 	return ret;
 }
-EXPORT_SYMBOL(kmem_cache_alloc_node);
+EXPORT_SYMBOL(kmem_cache_alloc_node_noprof);
 
 /*
  * To avoid unnecessary overhead, we pass through large allocation requests
@@ -3932,7 +3932,7 @@ static void *__kmalloc_large_node(size_t size, gfp_t flags, int node)
 		flags = kmalloc_fix_flags(flags);
 
 	flags |= __GFP_COMP;
-	folio = (struct folio *)alloc_pages_node(node, flags, order);
+	folio = (struct folio *)alloc_pages_node_noprof(node, flags, order);
 	if (folio) {
 		ptr = folio_address(folio);
 		lruvec_stat_mod_folio(folio, NR_SLAB_UNRECLAIMABLE_B,
@@ -3947,7 +3947,7 @@ static void *__kmalloc_large_node(size_t size, gfp_t flags, int node)
 	return ptr;
 }
 
-void *kmalloc_large(size_t size, gfp_t flags)
+void *kmalloc_large_noprof(size_t size, gfp_t flags)
 {
 	void *ret = __kmalloc_large_node(size, flags, NUMA_NO_NODE);
 
@@ -3955,9 +3955,9 @@ void *kmalloc_large(size_t size, gfp_t flags)
 		      flags, NUMA_NO_NODE);
 	return ret;
 }
-EXPORT_SYMBOL(kmalloc_large);
+EXPORT_SYMBOL(kmalloc_large_noprof);
 
-void *kmalloc_large_node(size_t size, gfp_t flags, int node)
+void *kmalloc_large_node_noprof(size_t size, gfp_t flags, int node)
 {
 	void *ret = __kmalloc_large_node(size, flags, node);
 
@@ -3965,7 +3965,7 @@ void *kmalloc_large_node(size_t size, gfp_t flags, int node)
 		      flags, node);
 	return ret;
 }
-EXPORT_SYMBOL(kmalloc_large_node);
+EXPORT_SYMBOL(kmalloc_large_node_noprof);
 
 static __always_inline
 void *__do_kmalloc_node(size_t size, gfp_t flags, int node,
@@ -3992,26 +3992,26 @@ void *__do_kmalloc_node(size_t size, gfp_t flags, int node,
 	return ret;
 }
 
-void *__kmalloc_node(size_t size, gfp_t flags, int node)
+void *__kmalloc_node_noprof(size_t size, gfp_t flags, int node)
 {
 	return __do_kmalloc_node(size, flags, node, _RET_IP_);
 }
-EXPORT_SYMBOL(__kmalloc_node);
+EXPORT_SYMBOL(__kmalloc_node_noprof);
 
-void *__kmalloc(size_t size, gfp_t flags)
+void *__kmalloc_noprof(size_t size, gfp_t flags)
 {
 	return __do_kmalloc_node(size, flags, NUMA_NO_NODE, _RET_IP_);
 }
-EXPORT_SYMBOL(__kmalloc);
+EXPORT_SYMBOL(__kmalloc_noprof);
 
-void *__kmalloc_node_track_caller(size_t size, gfp_t flags,
-				  int node, unsigned long caller)
+void *kmalloc_node_track_caller_noprof(size_t size, gfp_t flags,
+				       int node, unsigned long caller)
 {
 	return __do_kmalloc_node(size, flags, node, caller);
 }
-EXPORT_SYMBOL(__kmalloc_node_track_caller);
+EXPORT_SYMBOL(kmalloc_node_track_caller_noprof);
 
-void *kmalloc_trace(struct kmem_cache *s, gfp_t gfpflags, size_t size)
+void *kmalloc_trace_noprof(struct kmem_cache *s, gfp_t gfpflags, size_t size)
 {
 	void *ret = slab_alloc_node(s, NULL, gfpflags, NUMA_NO_NODE,
 					    _RET_IP_, size);
@@ -4021,9 +4021,9 @@ void *kmalloc_trace(struct kmem_cache *s, gfp_t gfpflags, size_t size)
 	ret = kasan_kmalloc(s, ret, size, gfpflags);
 	return ret;
 }
-EXPORT_SYMBOL(kmalloc_trace);
+EXPORT_SYMBOL(kmalloc_trace_noprof);
 
-void *kmalloc_node_trace(struct kmem_cache *s, gfp_t gfpflags,
+void *kmalloc_node_trace_noprof(struct kmem_cache *s, gfp_t gfpflags,
 			 int node, size_t size)
 {
 	void *ret = slab_alloc_node(s, NULL, gfpflags, node, _RET_IP_, size);
@@ -4033,7 +4033,7 @@ void *kmalloc_node_trace(struct kmem_cache *s, gfp_t gfpflags,
 	ret = kasan_kmalloc(s, ret, size, gfpflags);
 	return ret;
 }
-EXPORT_SYMBOL(kmalloc_node_trace);
+EXPORT_SYMBOL(kmalloc_node_trace_noprof);
 
 static noinline void free_to_partial_list(
 	struct kmem_cache *s, struct slab *slab,
@@ -4304,6 +4304,7 @@ void slab_free(struct kmem_cache *s, struct slab *slab, void *object,
 	       unsigned long addr)
 {
 	memcg_slab_free_hook(s, slab, &object, 1);
+	alloc_tagging_slab_free_hook(s, slab, &object, 1);
 
 	if (likely(slab_free_hook(s, object, slab_want_init_on_free(s))))
 		do_slab_free(s, slab, object, object, 1, addr);
@@ -4314,6 +4315,7 @@ void slab_free_bulk(struct kmem_cache *s, struct slab *slab, void *head,
 		    void *tail, void **p, int cnt, unsigned long addr)
 {
 	memcg_slab_free_hook(s, slab, p, cnt);
+	alloc_tagging_slab_free_hook(s, slab, p, cnt);
 	/*
 	 * With KASAN enabled slab_free_freelist_hook modifies the freelist
 	 * to remove objects, whose reuse must be delayed.
@@ -4640,8 +4642,8 @@ static int __kmem_cache_alloc_bulk(struct kmem_cache *s, gfp_t flags,
 #endif /* CONFIG_SLUB_TINY */
 
 /* Note that interrupts must be enabled when calling this function. */
-int kmem_cache_alloc_bulk(struct kmem_cache *s, gfp_t flags, size_t size,
-			  void **p)
+int kmem_cache_alloc_bulk_noprof(struct kmem_cache *s, gfp_t flags, size_t size,
+				 void **p)
 {
 	int i;
 	struct obj_cgroup *objcg = NULL;
@@ -4669,7 +4671,7 @@ int kmem_cache_alloc_bulk(struct kmem_cache *s, gfp_t flags, size_t size,
 
 	return i;
 }
-EXPORT_SYMBOL(kmem_cache_alloc_bulk);
+EXPORT_SYMBOL(kmem_cache_alloc_bulk_noprof);
 
 
 /*
diff --git a/mm/util.c b/mm/util.c
index 5a6a9802583b..291f7945190f 100644
--- a/mm/util.c
+++ b/mm/util.c
@@ -115,7 +115,7 @@ char *kstrndup(const char *s, size_t max, gfp_t gfp)
 EXPORT_SYMBOL(kstrndup);
 
 /**
- * kmemdup - duplicate region of memory
+ * kmemdup_noprof - duplicate region of memory
  *
  * @src: memory region to duplicate
  * @len: memory region length
@@ -124,16 +124,16 @@ EXPORT_SYMBOL(kstrndup);
  * Return: newly allocated copy of @src or %NULL in case of error,
  * result is physically contiguous. Use kfree() to free.
  */
-void *kmemdup(const void *src, size_t len, gfp_t gfp)
+void *kmemdup_noprof(const void *src, size_t len, gfp_t gfp)
 {
 	void *p;
 
-	p = kmalloc_track_caller(len, gfp);
+	p = kmalloc_node_track_caller_noprof(len, gfp, NUMA_NO_NODE, _RET_IP_);
 	if (p)
 		memcpy(p, src, len);
 	return p;
 }
-EXPORT_SYMBOL(kmemdup);
+EXPORT_SYMBOL(kmemdup_noprof);
 
 /**
  * kvmemdup - duplicate region of memory
@@ -577,7 +577,7 @@ unsigned long vm_mmap(struct file *file, unsigned long addr,
 EXPORT_SYMBOL(vm_mmap);
 
 /**
- * kvmalloc_node - attempt to allocate physically contiguous memory, but upon
+ * kvmalloc_node_noprof - attempt to allocate physically contiguous memory, but upon
  * failure, fall back to non-contiguous (vmalloc) allocation.
  * @size: size of the request.
  * @flags: gfp mask for the allocation - must be compatible (superset) with GFP_KERNEL.
@@ -592,7 +592,7 @@ EXPORT_SYMBOL(vm_mmap);
  *
  * Return: pointer to the allocated memory of %NULL in case of failure
  */
-void *kvmalloc_node(size_t size, gfp_t flags, int node)
+void *kvmalloc_node_noprof(size_t size, gfp_t flags, int node)
 {
 	gfp_t kmalloc_flags = flags;
 	void *ret;
@@ -614,7 +614,7 @@ void *kvmalloc_node(size_t size, gfp_t flags, int node)
 		kmalloc_flags &= ~__GFP_NOFAIL;
 	}
 
-	ret = kmalloc_node(size, kmalloc_flags, node);
+	ret = kmalloc_node_noprof(size, kmalloc_flags, node);
 
 	/*
 	 * It doesn't really make sense to fallback to vmalloc for sub page
@@ -643,7 +643,7 @@ void *kvmalloc_node(size_t size, gfp_t flags, int node)
 			flags, PAGE_KERNEL, VM_ALLOW_HUGE_VMAP,
 			node, __builtin_return_address(0));
 }
-EXPORT_SYMBOL(kvmalloc_node);
+EXPORT_SYMBOL(kvmalloc_node_noprof);
 
 /**
  * kvfree() - Free memory.
@@ -682,7 +682,7 @@ void kvfree_sensitive(const void *addr, size_t len)
 }
 EXPORT_SYMBOL(kvfree_sensitive);
 
-void *kvrealloc(const void *p, size_t oldsize, size_t newsize, gfp_t flags)
+void *kvrealloc_noprof(const void *p, size_t oldsize, size_t newsize, gfp_t flags)
 {
 	void *newp;
 
@@ -695,7 +695,7 @@ void *kvrealloc(const void *p, size_t oldsize, size_t newsize, gfp_t flags)
 	kvfree(p);
 	return newp;
 }
-EXPORT_SYMBOL(kvrealloc);
+EXPORT_SYMBOL(kvrealloc_noprof);
 
 /**
  * __vmalloc_array - allocate memory for a virtually contiguous array.
-- 
2.43.0.687.g38aa6559b0-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240212213922.783301-23-surenb%40google.com.
