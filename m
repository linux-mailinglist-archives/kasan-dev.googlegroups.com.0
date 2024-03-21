Return-Path: <kasan-dev+bncBC7OD3FKWUERB4GE6GXQMGQEVSN45SA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3f.google.com (mail-oo1-xc3f.google.com [IPv6:2607:f8b0:4864:20::c3f])
	by mail.lfdr.de (Postfix) with ESMTPS id D0E39885DC4
	for <lists+kasan-dev@lfdr.de>; Thu, 21 Mar 2024 17:38:09 +0100 (CET)
Received: by mail-oo1-xc3f.google.com with SMTP id 006d021491bc7-5a4873596e8sf1052203eaf.1
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Mar 2024 09:38:09 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1711039088; cv=pass;
        d=google.com; s=arc-20160816;
        b=vwUme/cl+5mx2hwgFfCBihP33Tf/5qODkSgZrJhQhS1mmiPAfuEvrmZ8EKw98Lz542
         s6K91oYBsQNw8MsYkXVRYyvtpDOyFLx+zJ4GGfu5/mYgcq0yYiRx5K6BkbhcSxndfyKI
         Zz02XjX6/d+m4iqrLzdYDT2RdU/83WRUzKnqM+wZGuodcprItDsXagONwiM7UvgVN2/4
         2QgCvvoiXgSe+ysZYuleWQFArYVFFaSZh/cjSGxEBbkXkxaK5Qvj1CNuiwXR79SACh/+
         SI+iHBatm/FbX+Ef0DRzHiU05SgcRex4FwCUHAhh4jf4b8O/JRJDk7/PIFwDrcvzlOte
         MmKw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=e7+0lbXmGIYXioVKrwz1DXqssWHCWBtFpOEdjtj6pI0=;
        fh=2zbqZ2APyACfxNly+tDE3MPthV+fsyrvnYXE1BU/HDI=;
        b=xujNQjYE2QDWCWpVvnbNNxy2lsT4vrjgR12PlDFwzM4hYa5cvNBARNnAyljQTKKFVy
         vDvNYzaprWXJt7BUeX6tAQJtBMU+EBnx5Ke/F3yAFnD8rBW5xWrQRDALMbv/d7LHzNLY
         oxjNHpMTAsuMuWTkB5yhRwIV5fQsPXNFPh2Q0i/nH7F608bZ+yEXkfFrQ4xIWlF92HUi
         l5jNRQXGrwBNS+m/YW+Yp87DRRgSB4JzA2uVv3zafYfkLQOIB3zx0mYF1mcrYtFBjukG
         vi6tgFBt8/CYotvmIcPgyOC4VEp8lbiNlsWcJlyx7uEza7DW8kRu4cDzqxv556vArRSK
         fDsw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=i8Ja1UVS;
       spf=pass (google.com: domain of 3bml8zqykcvslnk7g49hh9e7.5hfd3l3g-67o9hh9e79khnil.5hf@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=3bmL8ZQYKCVsLNK7G49HH9E7.5HFD3L3G-67O9HH9E79KHNIL.5HF@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1711039088; x=1711643888; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=e7+0lbXmGIYXioVKrwz1DXqssWHCWBtFpOEdjtj6pI0=;
        b=XylxVHLFXjL+90Urji5H11OkABvyc/5aj2bnW5AxuetIqDTP90ACGaEOzzWyJKEFM+
         TH4zBMmgLmPQB5PGiqHfy+2NUqdiJIdMO3yODyMEh1EKwETqgBr2ACYz49yfQV3dYtO+
         2xSuXWfct7Yqf/gaFgrcu8CK3pawLg9n0GJ8Q5CVsncbm3gipKt8LiErDttSyX2cbL5E
         KPk5h89eMkFB7hRfG7O1aJNBob9hKDWW52Q5fHkxx4utzJE1VmUoSjMHKQd4foA0OGJM
         bmEGT6Afg8Kbld+NOxSqvkt0N9q+ugWpdRejZgysPiGkYAVP9IWbZvMjTTAYSq0MtFuf
         1Tfw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1711039088; x=1711643888;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=e7+0lbXmGIYXioVKrwz1DXqssWHCWBtFpOEdjtj6pI0=;
        b=jeVmRota7O1yIOzavtjytxhe/3whmlAStlte1v3WsJm+WBEb23hBrFNvTijyMCxpjC
         iz/aRy8NTRzO/guQrbNghNEAOSpHxH5kWrAaMqNKXLN8xAj5dIOGv72ubC6XLzTvxrGT
         STSat2SqA5hcbNC8PTfnBnvWkaEyoQRC/xwp77n1ChnI6Um/EyuYY0YrE7A9dRm4TtMj
         Bym4O7Vuf9G3EhbzM/41eolSLrTlEGygsO48EgbRHwxAZ9YPKax1Y43ZmPCzpc1gLIJ9
         rDtjXAJj8Xwj9nl3LRkSG1DGdJE0ZF6bmaEbf0Vq1MgcOVLxC2z+zWpjp35d9lqDygAH
         Zv9Q==
X-Forwarded-Encrypted: i=2; AJvYcCVCY+neLZ48X8kGXs+gB67FbskMVm9FTwnNn4QG6iwagDbPskS+RNsiWtRi1b0+xycbtBpKIEkR0Z35hezb92y8PKcWW2AfJg==
X-Gm-Message-State: AOJu0Ywzk2ACaKEgezrlMyCMPfZ1BSMUN6Ob46tOl2gcFfUgQ8ZP80ur
	YDjG7FL5gYVFa8YoAUhwDzCOjN4M0yll07NAGJmLTmkeC9V9DpsV
X-Google-Smtp-Source: AGHT+IHG0zYagQpliS+qvCBjDEGxlFE3feUlK/iac6x+UGy+7w8IHDNhs//foVh/5BRCsY6pLq0kJw==
X-Received: by 2002:a05:6871:7508:b0:229:819a:d2e6 with SMTP id ny8-20020a056871750800b00229819ad2e6mr8227212oac.15.1711039088616;
        Thu, 21 Mar 2024 09:38:08 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6871:5b26:b0:229:c76b:7b5 with SMTP id
 op38-20020a0568715b2600b00229c76b07b5ls776188oac.0.-pod-prod-01-us; Thu, 21
 Mar 2024 09:38:07 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVRFFR8i27vxM0Jxcr6QIdFSY5JptznzLMAXSSS8XTcgSciYvebLKk+A8wKy2fct0PxctNoYPgiZascGX2jbX1NjuLD/lLlip4jTg==
X-Received: by 2002:a05:6870:a10c:b0:222:619f:9510 with SMTP id m12-20020a056870a10c00b00222619f9510mr24441655oae.27.1711039087089;
        Thu, 21 Mar 2024 09:38:07 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1711039087; cv=none;
        d=google.com; s=arc-20160816;
        b=muXi8G9vhA3E6OHLVryE/La/j+iIJWvgRunboAjWzuaKFDkKflZe47A5nEucXiPI02
         lmBCqCguf46dl+lZcHO1q2ZD0eetjaF2C3amzVOD+5dBQEUB41QvykOOW8pee97mVLE+
         xgyBknsbPzsvh+T/BYnoY7RGk9xkqfsr+XQHmJXYj5bB4Q14MKd9Qslre/VS6fRVDvAU
         o2QExuW1LOcXj+6vOu7SZdP4A2ktWWxWDajZdBtHx5pZVWC3k2+2vLXH5DrrIVR7yW08
         RpWHLksM5TaOwc9hY5VHQJ9pl5JbN4LsP239AP23hh52DfD3tFiFJImCNSH+A9tEQf3z
         bW0g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=kbJXFr2w8KI4PQ3iTaDylf6laxNigfzl4BgVu2a2cxc=;
        fh=d3SuDXP8Iw/h4YLtg6Ae5zNxb/su6W+xnG10Sts/hXg=;
        b=NN7tI2wOeQ4x9F/+GdoyWJtt6tWhYme4khub9/LqjvDFLi/OqNJlr6LOEMK619+bm5
         Hsf5zkqbjHyPukrT+cOty0DPAEFPLKkHTgsUT6j90PTAbuqsIhTb7GD/BKSvWgiUgvB8
         kTtAulWw47dV6sG+y5TneHCj1t4STNTwriVFWnP8rCaXxjroZQIi40s7HzIdqBNKjqmQ
         7Yxfqb5loe+cytSK7fJj8jsRx7UaaIar552K51J6WrCmCinyhXaxPev1RNQ5DLMx5L3v
         KKbGDtPiIIM3YVMMaPQ4WvRJ7KEIAcmdn3IBB+3C0KISpUxS/HLvU0fEd9+5arvGIiPR
         J7Dw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=i8Ja1UVS;
       spf=pass (google.com: domain of 3bml8zqykcvslnk7g49hh9e7.5hfd3l3g-67o9hh9e79khnil.5hf@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=3bmL8ZQYKCVsLNK7G49HH9E7.5HFD3L3G-67O9HH9E79KHNIL.5HF@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x114a.google.com (mail-yw1-x114a.google.com. [2607:f8b0:4864:20::114a])
        by gmr-mx.google.com with ESMTPS id hm14-20020a0568701b8e00b00221d905d771si34653oab.2.2024.03.21.09.38.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 21 Mar 2024 09:38:07 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3bml8zqykcvslnk7g49hh9e7.5hfd3l3g-67o9hh9e79khnil.5hf@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) client-ip=2607:f8b0:4864:20::114a;
Received: by mail-yw1-x114a.google.com with SMTP id 00721157ae682-60a605154d0so14623387b3.0
        for <kasan-dev@googlegroups.com>; Thu, 21 Mar 2024 09:38:07 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUMRU+FJnAe1h3SXM0H5eibnmpN3/nGvCRTAOJuHuL5zo1oAiZeyQvwaG3VcY5Toeyk9/bn08zpF6KphQwxXlIYbDY9yCN3f1ydfQ==
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:201:a489:6433:be5d:e639])
 (user=surenb job=sendgmr) by 2002:a81:a1d2:0:b0:610:e44b:acc3 with SMTP id
 y201-20020a81a1d2000000b00610e44bacc3mr857961ywg.4.1711039086504; Thu, 21 Mar
 2024 09:38:06 -0700 (PDT)
Date: Thu, 21 Mar 2024 09:36:48 -0700
In-Reply-To: <20240321163705.3067592-1-surenb@google.com>
Mime-Version: 1.0
References: <20240321163705.3067592-1-surenb@google.com>
X-Mailer: git-send-email 2.44.0.291.gc1ea87d7ee-goog
Message-ID: <20240321163705.3067592-27-surenb@google.com>
Subject: [PATCH v6 26/37] mempool: Hook up to memory allocation profiling
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
To: akpm@linux-foundation.org
Cc: kent.overstreet@linux.dev, mhocko@suse.com, vbabka@suse.cz, 
	hannes@cmpxchg.org, roman.gushchin@linux.dev, mgorman@suse.de, 
	dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com, 
	penguin-kernel@i-love.sakura.ne.jp, corbet@lwn.net, void@manifault.com, 
	peterz@infradead.org, juri.lelli@redhat.com, catalin.marinas@arm.com, 
	will@kernel.org, arnd@arndb.de, tglx@linutronix.de, mingo@redhat.com, 
	dave.hansen@linux.intel.com, x86@kernel.org, peterx@redhat.com, 
	david@redhat.com, axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org, 
	nathan@kernel.org, dennis@kernel.org, jhubbard@nvidia.com, tj@kernel.org, 
	muchun.song@linux.dev, rppt@kernel.org, paulmck@kernel.org, 
	pasha.tatashin@soleen.com, yosryahmed@google.com, yuzhao@google.com, 
	dhowells@redhat.com, hughd@google.com, andreyknvl@gmail.com, 
	keescook@chromium.org, ndesaulniers@google.com, vvvvvv@google.com, 
	gregkh@linuxfoundation.org, ebiggers@google.com, ytcoode@gmail.com, 
	vincent.guittot@linaro.org, dietmar.eggemann@arm.com, rostedt@goodmis.org, 
	bsegall@google.com, bristot@redhat.com, vschneid@redhat.com, cl@linux.com, 
	penberg@kernel.org, iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com, 
	glider@google.com, elver@google.com, dvyukov@google.com, 
	songmuchun@bytedance.com, jbaron@akamai.com, aliceryhl@google.com, 
	rientjes@google.com, minchan@google.com, kaleshsingh@google.com, 
	surenb@google.com, kernel-team@android.com, linux-doc@vger.kernel.org, 
	linux-kernel@vger.kernel.org, iommu@lists.linux.dev, 
	linux-arch@vger.kernel.org, linux-fsdevel@vger.kernel.org, linux-mm@kvack.org, 
	linux-modules@vger.kernel.org, kasan-dev@googlegroups.com, 
	cgroups@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: surenb@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=i8Ja1UVS;       spf=pass
 (google.com: domain of 3bml8zqykcvslnk7g49hh9e7.5hfd3l3g-67o9hh9e79khnil.5hf@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=3bmL8ZQYKCVsLNK7G49HH9E7.5HFD3L3G-67O9HH9E79KHNIL.5HF@flex--surenb.bounces.google.com;
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

From: Kent Overstreet <kent.overstreet@linux.dev>

This adds hooks to mempools for correctly annotating mempool-backed
allocations at the correct source line, so they show up correctly in
/sys/kernel/debug/allocations.

Various inline functions are converted to wrappers so that we can invoke
alloc_hooks() in fewer places.

Signed-off-by: Kent Overstreet <kent.overstreet@linux.dev>
Signed-off-by: Suren Baghdasaryan <surenb@google.com>
---
 include/linux/mempool.h | 73 ++++++++++++++++++++---------------------
 mm/mempool.c            | 36 ++++++++------------
 2 files changed, 49 insertions(+), 60 deletions(-)

diff --git a/include/linux/mempool.h b/include/linux/mempool.h
index 16c5cc807ff6..7b151441341b 100644
--- a/include/linux/mempool.h
+++ b/include/linux/mempool.h
@@ -5,6 +5,8 @@
 #ifndef _LINUX_MEMPOOL_H
 #define _LINUX_MEMPOOL_H
 
+#include <linux/sched.h>
+#include <linux/alloc_tag.h>
 #include <linux/wait.h>
 #include <linux/compiler.h>
 
@@ -39,18 +41,32 @@ void mempool_exit(mempool_t *pool);
 int mempool_init_node(mempool_t *pool, int min_nr, mempool_alloc_t *alloc_fn,
 		      mempool_free_t *free_fn, void *pool_data,
 		      gfp_t gfp_mask, int node_id);
-int mempool_init(mempool_t *pool, int min_nr, mempool_alloc_t *alloc_fn,
+
+int mempool_init_noprof(mempool_t *pool, int min_nr, mempool_alloc_t *alloc_fn,
 		 mempool_free_t *free_fn, void *pool_data);
+#define mempool_init(...)						\
+	alloc_hooks(mempool_init_noprof(__VA_ARGS__))
 
 extern mempool_t *mempool_create(int min_nr, mempool_alloc_t *alloc_fn,
 			mempool_free_t *free_fn, void *pool_data);
-extern mempool_t *mempool_create_node(int min_nr, mempool_alloc_t *alloc_fn,
+
+extern mempool_t *mempool_create_node_noprof(int min_nr, mempool_alloc_t *alloc_fn,
 			mempool_free_t *free_fn, void *pool_data,
 			gfp_t gfp_mask, int nid);
+#define mempool_create_node(...)					\
+	alloc_hooks(mempool_create_node_noprof(__VA_ARGS__))
+
+#define mempool_create(_min_nr, _alloc_fn, _free_fn, _pool_data)	\
+	mempool_create_node(_min_nr, _alloc_fn, _free_fn, _pool_data,	\
+			    GFP_KERNEL, NUMA_NO_NODE)
 
 extern int mempool_resize(mempool_t *pool, int new_min_nr);
 extern void mempool_destroy(mempool_t *pool);
-extern void *mempool_alloc(mempool_t *pool, gfp_t gfp_mask) __malloc;
+
+extern void *mempool_alloc_noprof(mempool_t *pool, gfp_t gfp_mask) __malloc;
+#define mempool_alloc(...)						\
+	alloc_hooks(mempool_alloc_noprof(__VA_ARGS__))
+
 extern void *mempool_alloc_preallocated(mempool_t *pool) __malloc;
 extern void mempool_free(void *element, mempool_t *pool);
 
@@ -62,19 +78,10 @@ extern void mempool_free(void *element, mempool_t *pool);
 void *mempool_alloc_slab(gfp_t gfp_mask, void *pool_data);
 void mempool_free_slab(void *element, void *pool_data);
 
-static inline int
-mempool_init_slab_pool(mempool_t *pool, int min_nr, struct kmem_cache *kc)
-{
-	return mempool_init(pool, min_nr, mempool_alloc_slab,
-			    mempool_free_slab, (void *) kc);
-}
-
-static inline mempool_t *
-mempool_create_slab_pool(int min_nr, struct kmem_cache *kc)
-{
-	return mempool_create(min_nr, mempool_alloc_slab, mempool_free_slab,
-			      (void *) kc);
-}
+#define mempool_init_slab_pool(_pool, _min_nr, _kc)			\
+	mempool_init(_pool, (_min_nr), mempool_alloc_slab, mempool_free_slab, (void *)(_kc))
+#define mempool_create_slab_pool(_min_nr, _kc)			\
+	mempool_create((_min_nr), mempool_alloc_slab, mempool_free_slab, (void *)(_kc))
 
 /*
  * a mempool_alloc_t and a mempool_free_t to kmalloc and kfree the
@@ -83,17 +90,12 @@ mempool_create_slab_pool(int min_nr, struct kmem_cache *kc)
 void *mempool_kmalloc(gfp_t gfp_mask, void *pool_data);
 void mempool_kfree(void *element, void *pool_data);
 
-static inline int mempool_init_kmalloc_pool(mempool_t *pool, int min_nr, size_t size)
-{
-	return mempool_init(pool, min_nr, mempool_kmalloc,
-			    mempool_kfree, (void *) size);
-}
-
-static inline mempool_t *mempool_create_kmalloc_pool(int min_nr, size_t size)
-{
-	return mempool_create(min_nr, mempool_kmalloc, mempool_kfree,
-			      (void *) size);
-}
+#define mempool_init_kmalloc_pool(_pool, _min_nr, _size)		\
+	mempool_init(_pool, (_min_nr), mempool_kmalloc, mempool_kfree,	\
+		     (void *)(unsigned long)(_size))
+#define mempool_create_kmalloc_pool(_min_nr, _size)			\
+	mempool_create((_min_nr), mempool_kmalloc, mempool_kfree,	\
+		       (void *)(unsigned long)(_size))
 
 void *mempool_kvmalloc(gfp_t gfp_mask, void *pool_data);
 void mempool_kvfree(void *element, void *pool_data);
@@ -115,16 +117,11 @@ static inline mempool_t *mempool_create_kvmalloc_pool(int min_nr, size_t size)
 void *mempool_alloc_pages(gfp_t gfp_mask, void *pool_data);
 void mempool_free_pages(void *element, void *pool_data);
 
-static inline int mempool_init_page_pool(mempool_t *pool, int min_nr, int order)
-{
-	return mempool_init(pool, min_nr, mempool_alloc_pages,
-			    mempool_free_pages, (void *)(long)order);
-}
-
-static inline mempool_t *mempool_create_page_pool(int min_nr, int order)
-{
-	return mempool_create(min_nr, mempool_alloc_pages, mempool_free_pages,
-			      (void *)(long)order);
-}
+#define mempool_init_page_pool(_pool, _min_nr, _order)			\
+	mempool_init(_pool, (_min_nr), mempool_alloc_pages,		\
+		     mempool_free_pages, (void *)(long)(_order))
+#define mempool_create_page_pool(_min_nr, _order)			\
+	mempool_create((_min_nr), mempool_alloc_pages,			\
+		       mempool_free_pages, (void *)(long)(_order))
 
 #endif /* _LINUX_MEMPOOL_H */
diff --git a/mm/mempool.c b/mm/mempool.c
index 076c736f5f1f..602e6eba68d3 100644
--- a/mm/mempool.c
+++ b/mm/mempool.c
@@ -240,17 +240,17 @@ EXPORT_SYMBOL(mempool_init_node);
  *
  * Return: %0 on success, negative error code otherwise.
  */
-int mempool_init(mempool_t *pool, int min_nr, mempool_alloc_t *alloc_fn,
-		 mempool_free_t *free_fn, void *pool_data)
+int mempool_init_noprof(mempool_t *pool, int min_nr, mempool_alloc_t *alloc_fn,
+			mempool_free_t *free_fn, void *pool_data)
 {
 	return mempool_init_node(pool, min_nr, alloc_fn, free_fn,
 				 pool_data, GFP_KERNEL, NUMA_NO_NODE);
 
 }
-EXPORT_SYMBOL(mempool_init);
+EXPORT_SYMBOL(mempool_init_noprof);
 
 /**
- * mempool_create - create a memory pool
+ * mempool_create_node - create a memory pool
  * @min_nr:    the minimum number of elements guaranteed to be
  *             allocated for this pool.
  * @alloc_fn:  user-defined element-allocation function.
@@ -265,17 +265,9 @@ EXPORT_SYMBOL(mempool_init);
  *
  * Return: pointer to the created memory pool object or %NULL on error.
  */
-mempool_t *mempool_create(int min_nr, mempool_alloc_t *alloc_fn,
-				mempool_free_t *free_fn, void *pool_data)
-{
-	return mempool_create_node(min_nr, alloc_fn, free_fn, pool_data,
-				   GFP_KERNEL, NUMA_NO_NODE);
-}
-EXPORT_SYMBOL(mempool_create);
-
-mempool_t *mempool_create_node(int min_nr, mempool_alloc_t *alloc_fn,
-			       mempool_free_t *free_fn, void *pool_data,
-			       gfp_t gfp_mask, int node_id)
+mempool_t *mempool_create_node_noprof(int min_nr, mempool_alloc_t *alloc_fn,
+				      mempool_free_t *free_fn, void *pool_data,
+				      gfp_t gfp_mask, int node_id)
 {
 	mempool_t *pool;
 
@@ -291,7 +283,7 @@ mempool_t *mempool_create_node(int min_nr, mempool_alloc_t *alloc_fn,
 
 	return pool;
 }
-EXPORT_SYMBOL(mempool_create_node);
+EXPORT_SYMBOL(mempool_create_node_noprof);
 
 /**
  * mempool_resize - resize an existing memory pool
@@ -374,7 +366,7 @@ int mempool_resize(mempool_t *pool, int new_min_nr)
 EXPORT_SYMBOL(mempool_resize);
 
 /**
- * mempool_alloc - allocate an element from a specific memory pool
+ * mempool_alloc_noprof - allocate an element from a specific memory pool
  * @pool:      pointer to the memory pool which was allocated via
  *             mempool_create().
  * @gfp_mask:  the usual allocation bitmask.
@@ -387,7 +379,7 @@ EXPORT_SYMBOL(mempool_resize);
  *
  * Return: pointer to the allocated element or %NULL on error.
  */
-void *mempool_alloc(mempool_t *pool, gfp_t gfp_mask)
+void *mempool_alloc_noprof(mempool_t *pool, gfp_t gfp_mask)
 {
 	void *element;
 	unsigned long flags;
@@ -454,7 +446,7 @@ void *mempool_alloc(mempool_t *pool, gfp_t gfp_mask)
 	finish_wait(&pool->wait, &wait);
 	goto repeat_alloc;
 }
-EXPORT_SYMBOL(mempool_alloc);
+EXPORT_SYMBOL(mempool_alloc_noprof);
 
 /**
  * mempool_alloc_preallocated - allocate an element from preallocated elements
@@ -562,7 +554,7 @@ void *mempool_alloc_slab(gfp_t gfp_mask, void *pool_data)
 {
 	struct kmem_cache *mem = pool_data;
 	VM_BUG_ON(mem->ctor);
-	return kmem_cache_alloc(mem, gfp_mask);
+	return kmem_cache_alloc_noprof(mem, gfp_mask);
 }
 EXPORT_SYMBOL(mempool_alloc_slab);
 
@@ -580,7 +572,7 @@ EXPORT_SYMBOL(mempool_free_slab);
 void *mempool_kmalloc(gfp_t gfp_mask, void *pool_data)
 {
 	size_t size = (size_t)pool_data;
-	return kmalloc(size, gfp_mask);
+	return kmalloc_noprof(size, gfp_mask);
 }
 EXPORT_SYMBOL(mempool_kmalloc);
 
@@ -610,7 +602,7 @@ EXPORT_SYMBOL(mempool_kvfree);
 void *mempool_alloc_pages(gfp_t gfp_mask, void *pool_data)
 {
 	int order = (int)(long)pool_data;
-	return alloc_pages(gfp_mask, order);
+	return alloc_pages_noprof(gfp_mask, order);
 }
 EXPORT_SYMBOL(mempool_alloc_pages);
 
-- 
2.44.0.291.gc1ea87d7ee-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240321163705.3067592-27-surenb%40google.com.
