Return-Path: <kasan-dev+bncBC7OD3FKWUERBX6E6GXQMGQEECMAYIY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x140.google.com (mail-il1-x140.google.com [IPv6:2607:f8b0:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id D7FCB885DB5
	for <lists+kasan-dev@lfdr.de>; Thu, 21 Mar 2024 17:37:52 +0100 (CET)
Received: by mail-il1-x140.google.com with SMTP id e9e14a558f8ab-3684bee9c40sf9265525ab.0
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Mar 2024 09:37:52 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1711039071; cv=pass;
        d=google.com; s=arc-20160816;
        b=m+U33D08FJj2mXZZB4IekOHYXk6sJAXBEdBzU9EI0oN+GGxmkySdYKbF6mbnbI+5fO
         TMmTiutT/M/T8gFIf19fwooMLiqWfhnw5D03bZd2jwlnLm3BQiYHRFlq3G5VISAA3iHL
         CYj123bbsJPXUgZzdVmsPdGrho6E86S4Ns2mgN7bJWYhXSttZ2EGFb+DXZIXnIgw/MLX
         M+jNLjzMXGBNRyHwX7SAEi3uN3nsFzF+Iqt097rTaUvP7xVLKTqSf4t8GUQShfX5ugid
         FV8nDSs9g0dbECfJG0qkXyEVq0l99EMozBJAG9j0YXI/k0U//t15zKcSXtED6Q4hVouv
         nD9w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=+8PaUQimgEdciVEk2qkRjiNyaBEJwsQ+HJs4//pYewc=;
        fh=VYxC7H8ISxcAvaUbl5x23t+vIouUKqAN3gItcOLfq00=;
        b=qBY0DHdGz+aJCv+ux0dEr95a6yb1ivPGT8vLT5T58G7PeEo/Ab9ndqmt7atAUnK5Zs
         cPsdYQ6LKtf2Dii/m7JBGLha4644KXq4f2eigfBw4mC2tmUgPkQxL+8vrGs1OO1sNJRN
         /E/iyjzBh5x6ruoamvB8kLSV31dODhSQz2Tp5qMTTmIKvuyN5ew4/h4OlnwqtuHsvvzp
         xfqTHSSgKsrF6r1/x579IOasknpvXwOWTpgUN3E/mdD7RYLsdpau5vj46oCR0cdZUdCY
         TQqk/ZLgrxELr+bhIjbULtQYTux1zqhKFRsdjw5dCAWhKQM0CIO6600fYo+bLeuG6Tlb
         GKfw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=wIknqUAu;
       spf=pass (google.com: domain of 3xwl8zqykcuo463qzns00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=3XWL8ZQYKCUo463qzns00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1711039071; x=1711643871; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=+8PaUQimgEdciVEk2qkRjiNyaBEJwsQ+HJs4//pYewc=;
        b=DmFwjY47wGNaeuBtRS6zMmZ27ED5D05Oi3ewsxQMYy0o/8Bi9Te9/PQ1EwARBE7n+R
         SkUNFqSs8OlVcqUUm4dNZ0GA62B+DHqKIe0hGnyF3JoEF+vZv3WU5rWuAZNme+VLx3rB
         rNXlRM+7wA8+sLdSIqF2Iws5HMM6K7zV3ysNjGDWy1dnkVQqSzCdAuDs9gHqFgeXhyD3
         7eFlkK/Q10QC45m22bmWHrqrYoKmvqpRjWnLkg8FLTALxpCNqHYC8m7xS7t1oUc9OhKR
         m/ArNjf19SxmPUQPbc4qocyvbYSNLTYxg6BqMPlug863HDw9IdBFvqQVKc0Y7WTG0r0I
         xtzw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1711039071; x=1711643871;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=+8PaUQimgEdciVEk2qkRjiNyaBEJwsQ+HJs4//pYewc=;
        b=ELZ32kwsl+7hYs4QW8CD/wtTNA3N1iD3XEpx6GWeh5U1zpYOyCvnILjMFMKvIeXvkE
         HkVS7vNmQLA141ZNd8QDwSqIwdqx5uuB8GP7RQXdPgmWAL65poTfC1k7lZ77D1p5/GfC
         1hcN00Xf1seX/kQPtIOqEsDGS74YXHoDI3+rvXRNG8AbWLrIsTg1WF83sD7phpGiulXC
         U39J4+Lw2HDOJ11JONrr+oxnj9qT07QBLuzv4pVEMmtFDU6xQD3muxMgIEsDCKZhzDkX
         F6t5Y4oJH4DQ+l7yB++W+ydTfxYMK8CrcGqSXF7hBq8FZ7nqREd5WCZ0rvcziIX2pWBU
         czKw==
X-Forwarded-Encrypted: i=2; AJvYcCWL41uXhEoWDzcb0YHt63q1X85u2tx3+O4pxp8WFo3feMbs/DNMMMPIBxcTpWJ5l02QDJGV2a2wOPxfzCy2YfljvMr/mL5s1g==
X-Gm-Message-State: AOJu0YyLv+RbGJ1BFr+Tvt33djtGLMP4iQC3MTdsv5r6GAMcOmT2hVf/
	tBqaysgVTE36EQr4KnGoSQJzauGS330h980FNk7a6Xxbv1aa8a8I
X-Google-Smtp-Source: AGHT+IHkW+uzjZ2ohIthwB4y6woXH7LjjhIdwhbx6OrVz84xSUJHKLyul/95hjjSrMn7c/7Zdhpv7Q==
X-Received: by 2002:a92:d702:0:b0:366:7901:9036 with SMTP id m2-20020a92d702000000b0036679019036mr5742iln.16.1711039071711;
        Thu, 21 Mar 2024 09:37:51 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:1c8c:b0:366:70d:8658 with SMTP id
 w12-20020a056e021c8c00b00366070d8658ls630108ill.1.-pod-prod-00-us; Thu, 21
 Mar 2024 09:37:50 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCV0rdpyocRQu4zC0huW7RZHTpT7W4k1M7MrU+qrqIa2xKOY1S7Vmzvg6mNErIhOZSd7mo7CVv5om+NHOa81PAcqFZVZXnOimzIZ4g==
X-Received: by 2002:a6b:7841:0:b0:7cf:1ed2:95bb with SMTP id h1-20020a6b7841000000b007cf1ed295bbmr2192772iop.10.1711039070177;
        Thu, 21 Mar 2024 09:37:50 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1711039070; cv=none;
        d=google.com; s=arc-20160816;
        b=jS62utjQTYt7ST3whv/mhfhAGbwWjJRLYrAxsKjzBEq9ETHWms5T4IAsAApOOgLHOV
         RaJukk+EsFkYo//GL1ehju9NRgLCYkJg9crbuTh5nJvr2UQnXJBsXLnCzLu4Pd0iHnmp
         pLEN9FI3hP0G7EiTtqVWUwrFWz+axAU46zt4sJWHz7uF4rPijX96Se5HWGITUKEQiGcv
         9IA9e5sqZUXINT/aUFJVAnz3cwb0+1sjMZbqrgZ9Cll2fM1z+Gk+UcgYL9VqZ+mauirI
         3jW7L+/Ds3gbyLzR9J8yDF3Z/MgOg+QIdXjfpHpObfJ/IGsSHAgOnX41wPCHGjzyPEwf
         m0Eg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=7FdsBQ7dxKBT3Q0hroP+RtUALgw5JCKh9olno1yd0hA=;
        fh=WgO/B9bgk2yOFieiQ0AOg+pnEF+4f+fpiP4c4oN4OwA=;
        b=TfsCillCjV2feRGr2Tjn221YjpTLPYqF7wdLS9dFA2RF2xU+Q+hTnFSj9vXTIPY1RB
         dloCcpVHpCK9oKA19jAgSgnWgTF1VTgSStPJuyrAZknKZ0GZu93hmypwnaJ8onlO9VIy
         mwMnBVsotjAyLUJNB8n4a/lzvS/61QwRqldxRvCGfU7DO+2ubuj2M/9EdDhYiohN1pbh
         PKNInt++9gD7S8bihgPyMzqtCBzr0zyCQ4ifIDVzV7hDkP1boYFS4hVe0n0xVrxiTPfX
         uRIvj0MOd6mg8+1agrVWppUuiqCRg5MlgVb5Rp8OwAHYOrdR/RR3VqS1Mu0nG7uGcawZ
         vckA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=wIknqUAu;
       spf=pass (google.com: domain of 3xwl8zqykcuo463qzns00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=3XWL8ZQYKCUo463qzns00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x114a.google.com (mail-yw1-x114a.google.com. [2607:f8b0:4864:20::114a])
        by gmr-mx.google.com with ESMTPS id y2-20020a023542000000b00478070af315si880115jae.3.2024.03.21.09.37.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 21 Mar 2024 09:37:50 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3xwl8zqykcuo463qzns00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) client-ip=2607:f8b0:4864:20::114a;
Received: by mail-yw1-x114a.google.com with SMTP id 00721157ae682-60ff1816749so19575237b3.3
        for <kasan-dev@googlegroups.com>; Thu, 21 Mar 2024 09:37:50 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXGKL8neqQW2UTvck6NlgqZYTRjDh4m97WsqdzKhUFPdrr5vlNKJ5EGgHpEeWCniDcRlGQ9uLJniKJcEZJJpqsUsma55cuUPLNb6A==
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:201:a489:6433:be5d:e639])
 (user=surenb job=sendgmr) by 2002:a0d:eb41:0:b0:60a:6a7b:3c61 with SMTP id
 u62-20020a0deb41000000b0060a6a7b3c61mr3979557ywe.5.1711039069400; Thu, 21 Mar
 2024 09:37:49 -0700 (PDT)
Date: Thu, 21 Mar 2024 09:36:40 -0700
In-Reply-To: <20240321163705.3067592-1-surenb@google.com>
Mime-Version: 1.0
References: <20240321163705.3067592-1-surenb@google.com>
X-Mailer: git-send-email 2.44.0.291.gc1ea87d7ee-goog
Message-ID: <20240321163705.3067592-19-surenb@google.com>
Subject: [PATCH v6 18/37] mm: enable page allocation tagging
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
 header.i=@google.com header.s=20230601 header.b=wIknqUAu;       spf=pass
 (google.com: domain of 3xwl8zqykcuo463qzns00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=3XWL8ZQYKCUo463qzns00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--surenb.bounces.google.com;
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

Redefine page allocators to record allocation tags upon their invocation.
Instrument post_alloc_hook and free_pages_prepare to modify current
allocation tag.

Signed-off-by: Suren Baghdasaryan <surenb@google.com>
Co-developed-by: Kent Overstreet <kent.overstreet@linux.dev>
Signed-off-by: Kent Overstreet <kent.overstreet@linux.dev>
Reviewed-by: Kees Cook <keescook@chromium.org>
---
 include/linux/alloc_tag.h |  14 +++++
 include/linux/gfp.h       | 126 ++++++++++++++++++++++++--------------
 include/linux/pagemap.h   |   9 ++-
 mm/compaction.c           |   7 ++-
 mm/filemap.c              |   6 +-
 mm/mempolicy.c            |  52 ++++++++--------
 mm/page_alloc.c           |  60 +++++++++---------
 7 files changed, 164 insertions(+), 110 deletions(-)

diff --git a/include/linux/alloc_tag.h b/include/linux/alloc_tag.h
index b970ff1c80dc..28c0005edae1 100644
--- a/include/linux/alloc_tag.h
+++ b/include/linux/alloc_tag.h
@@ -142,4 +142,18 @@ static inline void alloc_tag_sub(union codetag_ref *ref, size_t bytes) {}
 
 #endif /* CONFIG_MEM_ALLOC_PROFILING */
 
+#define alloc_hooks_tag(_tag, _do_alloc)				\
+({									\
+	struct alloc_tag * __maybe_unused _old = alloc_tag_save(_tag);	\
+	typeof(_do_alloc) _res = _do_alloc;				\
+	alloc_tag_restore(_tag, _old);					\
+	_res;								\
+})
+
+#define alloc_hooks(_do_alloc)						\
+({									\
+	DEFINE_ALLOC_TAG(_alloc_tag);					\
+	alloc_hooks_tag(&_alloc_tag, _do_alloc);			\
+})
+
 #endif /* _LINUX_ALLOC_TAG_H */
diff --git a/include/linux/gfp.h b/include/linux/gfp.h
index c775ea3c6015..450c2cbcf04b 100644
--- a/include/linux/gfp.h
+++ b/include/linux/gfp.h
@@ -6,6 +6,8 @@
 
 #include <linux/mmzone.h>
 #include <linux/topology.h>
+#include <linux/alloc_tag.h>
+#include <linux/sched.h>
 
 struct vm_area_struct;
 struct mempolicy;
@@ -175,42 +177,46 @@ static inline void arch_free_page(struct page *page, int order) { }
 static inline void arch_alloc_page(struct page *page, int order) { }
 #endif
 
-struct page *__alloc_pages(gfp_t gfp, unsigned int order, int preferred_nid,
+struct page *__alloc_pages_noprof(gfp_t gfp, unsigned int order, int preferred_nid,
 		nodemask_t *nodemask);
-struct folio *__folio_alloc(gfp_t gfp, unsigned int order, int preferred_nid,
+#define __alloc_pages(...)			alloc_hooks(__alloc_pages_noprof(__VA_ARGS__))
+
+struct folio *__folio_alloc_noprof(gfp_t gfp, unsigned int order, int preferred_nid,
 		nodemask_t *nodemask);
+#define __folio_alloc(...)			alloc_hooks(__folio_alloc_noprof(__VA_ARGS__))
 
-unsigned long __alloc_pages_bulk(gfp_t gfp, int preferred_nid,
+unsigned long alloc_pages_bulk_noprof(gfp_t gfp, int preferred_nid,
 				nodemask_t *nodemask, int nr_pages,
 				struct list_head *page_list,
 				struct page **page_array);
+#define __alloc_pages_bulk(...)			alloc_hooks(alloc_pages_bulk_noprof(__VA_ARGS__))
 
-unsigned long alloc_pages_bulk_array_mempolicy(gfp_t gfp,
+unsigned long alloc_pages_bulk_array_mempolicy_noprof(gfp_t gfp,
 				unsigned long nr_pages,
 				struct page **page_array);
+#define  alloc_pages_bulk_array_mempolicy(...)				\
+	alloc_hooks(alloc_pages_bulk_array_mempolicy_noprof(__VA_ARGS__))
 
 /* Bulk allocate order-0 pages */
-static inline unsigned long
-alloc_pages_bulk_list(gfp_t gfp, unsigned long nr_pages, struct list_head *list)
-{
-	return __alloc_pages_bulk(gfp, numa_mem_id(), NULL, nr_pages, list, NULL);
-}
+#define alloc_pages_bulk_list(_gfp, _nr_pages, _list)			\
+	__alloc_pages_bulk(_gfp, numa_mem_id(), NULL, _nr_pages, _list, NULL)
 
-static inline unsigned long
-alloc_pages_bulk_array(gfp_t gfp, unsigned long nr_pages, struct page **page_array)
-{
-	return __alloc_pages_bulk(gfp, numa_mem_id(), NULL, nr_pages, NULL, page_array);
-}
+#define alloc_pages_bulk_array(_gfp, _nr_pages, _page_array)		\
+	__alloc_pages_bulk(_gfp, numa_mem_id(), NULL, _nr_pages, NULL, _page_array)
 
 static inline unsigned long
-alloc_pages_bulk_array_node(gfp_t gfp, int nid, unsigned long nr_pages, struct page **page_array)
+alloc_pages_bulk_array_node_noprof(gfp_t gfp, int nid, unsigned long nr_pages,
+				   struct page **page_array)
 {
 	if (nid == NUMA_NO_NODE)
 		nid = numa_mem_id();
 
-	return __alloc_pages_bulk(gfp, nid, NULL, nr_pages, NULL, page_array);
+	return alloc_pages_bulk_noprof(gfp, nid, NULL, nr_pages, NULL, page_array);
 }
 
+#define alloc_pages_bulk_array_node(...)				\
+	alloc_hooks(alloc_pages_bulk_array_node_noprof(__VA_ARGS__))
+
 static inline void warn_if_node_offline(int this_node, gfp_t gfp_mask)
 {
 	gfp_t warn_gfp = gfp_mask & (__GFP_THISNODE|__GFP_NOWARN);
@@ -230,82 +236,104 @@ static inline void warn_if_node_offline(int this_node, gfp_t gfp_mask)
  * online. For more general interface, see alloc_pages_node().
  */
 static inline struct page *
-__alloc_pages_node(int nid, gfp_t gfp_mask, unsigned int order)
+__alloc_pages_node_noprof(int nid, gfp_t gfp_mask, unsigned int order)
 {
 	VM_BUG_ON(nid < 0 || nid >= MAX_NUMNODES);
 	warn_if_node_offline(nid, gfp_mask);
 
-	return __alloc_pages(gfp_mask, order, nid, NULL);
+	return __alloc_pages_noprof(gfp_mask, order, nid, NULL);
 }
 
+#define  __alloc_pages_node(...)		alloc_hooks(__alloc_pages_node_noprof(__VA_ARGS__))
+
 static inline
-struct folio *__folio_alloc_node(gfp_t gfp, unsigned int order, int nid)
+struct folio *__folio_alloc_node_noprof(gfp_t gfp, unsigned int order, int nid)
 {
 	VM_BUG_ON(nid < 0 || nid >= MAX_NUMNODES);
 	warn_if_node_offline(nid, gfp);
 
-	return __folio_alloc(gfp, order, nid, NULL);
+	return __folio_alloc_noprof(gfp, order, nid, NULL);
 }
 
+#define  __folio_alloc_node(...)		alloc_hooks(__folio_alloc_node_noprof(__VA_ARGS__))
+
 /*
  * Allocate pages, preferring the node given as nid. When nid == NUMA_NO_NODE,
  * prefer the current CPU's closest node. Otherwise node must be valid and
  * online.
  */
-static inline struct page *alloc_pages_node(int nid, gfp_t gfp_mask,
-						unsigned int order)
+static inline struct page *alloc_pages_node_noprof(int nid, gfp_t gfp_mask,
+						   unsigned int order)
 {
 	if (nid == NUMA_NO_NODE)
 		nid = numa_mem_id();
 
-	return __alloc_pages_node(nid, gfp_mask, order);
+	return __alloc_pages_node_noprof(nid, gfp_mask, order);
 }
 
+#define  alloc_pages_node(...)			alloc_hooks(alloc_pages_node_noprof(__VA_ARGS__))
+
 #ifdef CONFIG_NUMA
-struct page *alloc_pages(gfp_t gfp, unsigned int order);
-struct page *alloc_pages_mpol(gfp_t gfp, unsigned int order,
+struct page *alloc_pages_noprof(gfp_t gfp, unsigned int order);
+struct page *alloc_pages_mpol_noprof(gfp_t gfp, unsigned int order,
 		struct mempolicy *mpol, pgoff_t ilx, int nid);
-struct folio *folio_alloc(gfp_t gfp, unsigned int order);
-struct folio *vma_alloc_folio(gfp_t gfp, int order, struct vm_area_struct *vma,
+struct folio *folio_alloc_noprof(gfp_t gfp, unsigned int order);
+struct folio *vma_alloc_folio_noprof(gfp_t gfp, int order, struct vm_area_struct *vma,
 		unsigned long addr, bool hugepage);
 #else
-static inline struct page *alloc_pages(gfp_t gfp_mask, unsigned int order)
+static inline struct page *alloc_pages_noprof(gfp_t gfp_mask, unsigned int order)
 {
-	return alloc_pages_node(numa_node_id(), gfp_mask, order);
+	return alloc_pages_node_noprof(numa_node_id(), gfp_mask, order);
 }
-static inline struct page *alloc_pages_mpol(gfp_t gfp, unsigned int order,
+static inline struct page *alloc_pages_mpol_noprof(gfp_t gfp, unsigned int order,
 		struct mempolicy *mpol, pgoff_t ilx, int nid)
 {
-	return alloc_pages(gfp, order);
+	return alloc_pages_noprof(gfp, order);
 }
-static inline struct folio *folio_alloc(gfp_t gfp, unsigned int order)
+static inline struct folio *folio_alloc_noprof(gfp_t gfp, unsigned int order)
 {
 	return __folio_alloc_node(gfp, order, numa_node_id());
 }
-#define vma_alloc_folio(gfp, order, vma, addr, hugepage)		\
-	folio_alloc(gfp, order)
+#define vma_alloc_folio_noprof(gfp, order, vma, addr, hugepage)		\
+	folio_alloc_noprof(gfp, order)
 #endif
+
+#define alloc_pages(...)			alloc_hooks(alloc_pages_noprof(__VA_ARGS__))
+#define alloc_pages_mpol(...)			alloc_hooks(alloc_pages_mpol_noprof(__VA_ARGS__))
+#define folio_alloc(...)			alloc_hooks(folio_alloc_noprof(__VA_ARGS__))
+#define vma_alloc_folio(...)			alloc_hooks(vma_alloc_folio_noprof(__VA_ARGS__))
+
 #define alloc_page(gfp_mask) alloc_pages(gfp_mask, 0)
-static inline struct page *alloc_page_vma(gfp_t gfp,
+
+static inline struct page *alloc_page_vma_noprof(gfp_t gfp,
 		struct vm_area_struct *vma, unsigned long addr)
 {
-	struct folio *folio = vma_alloc_folio(gfp, 0, vma, addr, false);
+	struct folio *folio = vma_alloc_folio_noprof(gfp, 0, vma, addr, false);
 
 	return &folio->page;
 }
+#define alloc_page_vma(...)			alloc_hooks(alloc_page_vma_noprof(__VA_ARGS__))
+
+extern unsigned long get_free_pages_noprof(gfp_t gfp_mask, unsigned int order);
+#define __get_free_pages(...)			alloc_hooks(get_free_pages_noprof(__VA_ARGS__))
 
-extern unsigned long __get_free_pages(gfp_t gfp_mask, unsigned int order);
-extern unsigned long get_zeroed_page(gfp_t gfp_mask);
+extern unsigned long get_zeroed_page_noprof(gfp_t gfp_mask);
+#define get_zeroed_page(...)			alloc_hooks(get_zeroed_page_noprof(__VA_ARGS__))
+
+void *alloc_pages_exact_noprof(size_t size, gfp_t gfp_mask) __alloc_size(1);
+#define alloc_pages_exact(...)			alloc_hooks(alloc_pages_exact_noprof(__VA_ARGS__))
 
-void *alloc_pages_exact(size_t size, gfp_t gfp_mask) __alloc_size(1);
 void free_pages_exact(void *virt, size_t size);
-__meminit void *alloc_pages_exact_nid(int nid, size_t size, gfp_t gfp_mask) __alloc_size(2);
 
-#define __get_free_page(gfp_mask) \
-		__get_free_pages((gfp_mask), 0)
+__meminit void *alloc_pages_exact_nid_noprof(int nid, size_t size, gfp_t gfp_mask) __alloc_size(2);
+#define alloc_pages_exact_nid(...)					\
+	alloc_hooks(alloc_pages_exact_nid_noprof(__VA_ARGS__))
+
+#define __get_free_page(gfp_mask)					\
+	__get_free_pages((gfp_mask), 0)
 
-#define __get_dma_pages(gfp_mask, order) \
-		__get_free_pages((gfp_mask) | GFP_DMA, (order))
+#define __get_dma_pages(gfp_mask, order)				\
+	__get_free_pages((gfp_mask) | GFP_DMA, (order))
 
 extern void __free_pages(struct page *page, unsigned int order);
 extern void free_pages(unsigned long addr, unsigned int order);
@@ -374,10 +402,14 @@ extern gfp_t vma_thp_gfp_mask(struct vm_area_struct *vma);
 
 #ifdef CONFIG_CONTIG_ALLOC
 /* The below functions must be run on a range from a single zone. */
-extern int alloc_contig_range(unsigned long start, unsigned long end,
+extern int alloc_contig_range_noprof(unsigned long start, unsigned long end,
 			      unsigned migratetype, gfp_t gfp_mask);
-extern struct page *alloc_contig_pages(unsigned long nr_pages, gfp_t gfp_mask,
-				       int nid, nodemask_t *nodemask);
+#define alloc_contig_range(...)			alloc_hooks(alloc_contig_range_noprof(__VA_ARGS__))
+
+extern struct page *alloc_contig_pages_noprof(unsigned long nr_pages, gfp_t gfp_mask,
+					      int nid, nodemask_t *nodemask);
+#define alloc_contig_pages(...)			alloc_hooks(alloc_contig_pages_noprof(__VA_ARGS__))
+
 #endif
 void free_contig_range(unsigned long pfn, unsigned long nr_pages);
 
diff --git a/include/linux/pagemap.h b/include/linux/pagemap.h
index 2df35e65557d..35636e67e2e1 100644
--- a/include/linux/pagemap.h
+++ b/include/linux/pagemap.h
@@ -542,14 +542,17 @@ static inline void *detach_page_private(struct page *page)
 #endif
 
 #ifdef CONFIG_NUMA
-struct folio *filemap_alloc_folio(gfp_t gfp, unsigned int order);
+struct folio *filemap_alloc_folio_noprof(gfp_t gfp, unsigned int order);
 #else
-static inline struct folio *filemap_alloc_folio(gfp_t gfp, unsigned int order)
+static inline struct folio *filemap_alloc_folio_noprof(gfp_t gfp, unsigned int order)
 {
-	return folio_alloc(gfp, order);
+	return folio_alloc_noprof(gfp, order);
 }
 #endif
 
+#define filemap_alloc_folio(...)				\
+	alloc_hooks(filemap_alloc_folio_noprof(__VA_ARGS__))
+
 static inline struct page *__page_cache_alloc(gfp_t gfp)
 {
 	return &filemap_alloc_folio(gfp, 0)->page;
diff --git a/mm/compaction.c b/mm/compaction.c
index 807b58e6eb68..70b01190d2f3 100644
--- a/mm/compaction.c
+++ b/mm/compaction.c
@@ -1851,7 +1851,7 @@ static void isolate_freepages(struct compact_control *cc)
  * This is a migrate-callback that "allocates" freepages by taking pages
  * from the isolated freelists in the block we are migrating to.
  */
-static struct folio *compaction_alloc(struct folio *src, unsigned long data)
+static struct folio *compaction_alloc_noprof(struct folio *src, unsigned long data)
 {
 	struct compact_control *cc = (struct compact_control *)data;
 	struct folio *dst;
@@ -1898,6 +1898,11 @@ static struct folio *compaction_alloc(struct folio *src, unsigned long data)
 	return page_rmappable_folio(&dst->page);
 }
 
+static struct folio *compaction_alloc(struct folio *src, unsigned long data)
+{
+	return alloc_hooks(compaction_alloc_noprof(src, data));
+}
+
 /*
  * This is a migrate-callback that "frees" freepages back to the isolated
  * freelist.  All pages on the freelist are from the same zone, so there is no
diff --git a/mm/filemap.c b/mm/filemap.c
index a2ca78d13321..ba6d1ba60a2a 100644
--- a/mm/filemap.c
+++ b/mm/filemap.c
@@ -966,7 +966,7 @@ int filemap_add_folio(struct address_space *mapping, struct folio *folio,
 EXPORT_SYMBOL_GPL(filemap_add_folio);
 
 #ifdef CONFIG_NUMA
-struct folio *filemap_alloc_folio(gfp_t gfp, unsigned int order)
+struct folio *filemap_alloc_folio_noprof(gfp_t gfp, unsigned int order)
 {
 	int n;
 	struct folio *folio;
@@ -981,9 +981,9 @@ struct folio *filemap_alloc_folio(gfp_t gfp, unsigned int order)
 
 		return folio;
 	}
-	return folio_alloc(gfp, order);
+	return folio_alloc_noprof(gfp, order);
 }
-EXPORT_SYMBOL(filemap_alloc_folio);
+EXPORT_SYMBOL(filemap_alloc_folio_noprof);
 #endif
 
 /*
diff --git a/mm/mempolicy.c b/mm/mempolicy.c
index c4d439efcadf..b270b8f8519a 100644
--- a/mm/mempolicy.c
+++ b/mm/mempolicy.c
@@ -2201,15 +2201,15 @@ static struct page *alloc_pages_preferred_many(gfp_t gfp, unsigned int order,
 	 */
 	preferred_gfp = gfp | __GFP_NOWARN;
 	preferred_gfp &= ~(__GFP_DIRECT_RECLAIM | __GFP_NOFAIL);
-	page = __alloc_pages(preferred_gfp, order, nid, nodemask);
+	page = __alloc_pages_noprof(preferred_gfp, order, nid, nodemask);
 	if (!page)
-		page = __alloc_pages(gfp, order, nid, NULL);
+		page = __alloc_pages_noprof(gfp, order, nid, NULL);
 
 	return page;
 }
 
 /**
- * alloc_pages_mpol - Allocate pages according to NUMA mempolicy.
+ * alloc_pages_mpol_noprof - Allocate pages according to NUMA mempolicy.
  * @gfp: GFP flags.
  * @order: Order of the page allocation.
  * @pol: Pointer to the NUMA mempolicy.
@@ -2218,7 +2218,7 @@ static struct page *alloc_pages_preferred_many(gfp_t gfp, unsigned int order,
  *
  * Return: The page on success or NULL if allocation fails.
  */
-struct page *alloc_pages_mpol(gfp_t gfp, unsigned int order,
+struct page *alloc_pages_mpol_noprof(gfp_t gfp, unsigned int order,
 		struct mempolicy *pol, pgoff_t ilx, int nid)
 {
 	nodemask_t *nodemask;
@@ -2249,7 +2249,7 @@ struct page *alloc_pages_mpol(gfp_t gfp, unsigned int order,
 			 * First, try to allocate THP only on local node, but
 			 * don't reclaim unnecessarily, just compact.
 			 */
-			page = __alloc_pages_node(nid,
+			page = __alloc_pages_node_noprof(nid,
 				gfp | __GFP_THISNODE | __GFP_NORETRY, order);
 			if (page || !(gfp & __GFP_DIRECT_RECLAIM))
 				return page;
@@ -2262,7 +2262,7 @@ struct page *alloc_pages_mpol(gfp_t gfp, unsigned int order,
 		}
 	}
 
-	page = __alloc_pages(gfp, order, nid, nodemask);
+	page = __alloc_pages_noprof(gfp, order, nid, nodemask);
 
 	if (unlikely(pol->mode == MPOL_INTERLEAVE) && page) {
 		/* skip NUMA_INTERLEAVE_HIT update if numa stats is disabled */
@@ -2278,7 +2278,7 @@ struct page *alloc_pages_mpol(gfp_t gfp, unsigned int order,
 }
 
 /**
- * vma_alloc_folio - Allocate a folio for a VMA.
+ * vma_alloc_folio_noprof - Allocate a folio for a VMA.
  * @gfp: GFP flags.
  * @order: Order of the folio.
  * @vma: Pointer to VMA.
@@ -2293,7 +2293,7 @@ struct page *alloc_pages_mpol(gfp_t gfp, unsigned int order,
  *
  * Return: The folio on success or NULL if allocation fails.
  */
-struct folio *vma_alloc_folio(gfp_t gfp, int order, struct vm_area_struct *vma,
+struct folio *vma_alloc_folio_noprof(gfp_t gfp, int order, struct vm_area_struct *vma,
 		unsigned long addr, bool hugepage)
 {
 	struct mempolicy *pol;
@@ -2301,15 +2301,15 @@ struct folio *vma_alloc_folio(gfp_t gfp, int order, struct vm_area_struct *vma,
 	struct page *page;
 
 	pol = get_vma_policy(vma, addr, order, &ilx);
-	page = alloc_pages_mpol(gfp | __GFP_COMP, order,
-				pol, ilx, numa_node_id());
+	page = alloc_pages_mpol_noprof(gfp | __GFP_COMP, order,
+				       pol, ilx, numa_node_id());
 	mpol_cond_put(pol);
 	return page_rmappable_folio(page);
 }
-EXPORT_SYMBOL(vma_alloc_folio);
+EXPORT_SYMBOL(vma_alloc_folio_noprof);
 
 /**
- * alloc_pages - Allocate pages.
+ * alloc_pages_noprof - Allocate pages.
  * @gfp: GFP flags.
  * @order: Power of two of number of pages to allocate.
  *
@@ -2322,7 +2322,7 @@ EXPORT_SYMBOL(vma_alloc_folio);
  * flags are used.
  * Return: The page on success or NULL if allocation fails.
  */
-struct page *alloc_pages(gfp_t gfp, unsigned int order)
+struct page *alloc_pages_noprof(gfp_t gfp, unsigned int order)
 {
 	struct mempolicy *pol = &default_policy;
 
@@ -2333,16 +2333,16 @@ struct page *alloc_pages(gfp_t gfp, unsigned int order)
 	if (!in_interrupt() && !(gfp & __GFP_THISNODE))
 		pol = get_task_policy(current);
 
-	return alloc_pages_mpol(gfp, order,
-				pol, NO_INTERLEAVE_INDEX, numa_node_id());
+	return alloc_pages_mpol_noprof(gfp, order, pol, NO_INTERLEAVE_INDEX,
+				       numa_node_id());
 }
-EXPORT_SYMBOL(alloc_pages);
+EXPORT_SYMBOL(alloc_pages_noprof);
 
-struct folio *folio_alloc(gfp_t gfp, unsigned int order)
+struct folio *folio_alloc_noprof(gfp_t gfp, unsigned int order)
 {
-	return page_rmappable_folio(alloc_pages(gfp | __GFP_COMP, order));
+	return page_rmappable_folio(alloc_pages_noprof(gfp | __GFP_COMP, order));
 }
-EXPORT_SYMBOL(folio_alloc);
+EXPORT_SYMBOL(folio_alloc_noprof);
 
 static unsigned long alloc_pages_bulk_array_interleave(gfp_t gfp,
 		struct mempolicy *pol, unsigned long nr_pages,
@@ -2361,13 +2361,13 @@ static unsigned long alloc_pages_bulk_array_interleave(gfp_t gfp,
 
 	for (i = 0; i < nodes; i++) {
 		if (delta) {
-			nr_allocated = __alloc_pages_bulk(gfp,
+			nr_allocated = alloc_pages_bulk_noprof(gfp,
 					interleave_nodes(pol), NULL,
 					nr_pages_per_node + 1, NULL,
 					page_array);
 			delta--;
 		} else {
-			nr_allocated = __alloc_pages_bulk(gfp,
+			nr_allocated = alloc_pages_bulk_noprof(gfp,
 					interleave_nodes(pol), NULL,
 					nr_pages_per_node, NULL, page_array);
 		}
@@ -2504,11 +2504,11 @@ static unsigned long alloc_pages_bulk_array_preferred_many(gfp_t gfp, int nid,
 	preferred_gfp = gfp | __GFP_NOWARN;
 	preferred_gfp &= ~(__GFP_DIRECT_RECLAIM | __GFP_NOFAIL);
 
-	nr_allocated  = __alloc_pages_bulk(preferred_gfp, nid, &pol->nodes,
+	nr_allocated  = alloc_pages_bulk_noprof(preferred_gfp, nid, &pol->nodes,
 					   nr_pages, NULL, page_array);
 
 	if (nr_allocated < nr_pages)
-		nr_allocated += __alloc_pages_bulk(gfp, numa_node_id(), NULL,
+		nr_allocated += alloc_pages_bulk_noprof(gfp, numa_node_id(), NULL,
 				nr_pages - nr_allocated, NULL,
 				page_array + nr_allocated);
 	return nr_allocated;
@@ -2520,7 +2520,7 @@ static unsigned long alloc_pages_bulk_array_preferred_many(gfp_t gfp, int nid,
  * It can accelerate memory allocation especially interleaving
  * allocate memory.
  */
-unsigned long alloc_pages_bulk_array_mempolicy(gfp_t gfp,
+unsigned long alloc_pages_bulk_array_mempolicy_noprof(gfp_t gfp,
 		unsigned long nr_pages, struct page **page_array)
 {
 	struct mempolicy *pol = &default_policy;
@@ -2544,8 +2544,8 @@ unsigned long alloc_pages_bulk_array_mempolicy(gfp_t gfp,
 
 	nid = numa_node_id();
 	nodemask = policy_nodemask(gfp, pol, NO_INTERLEAVE_INDEX, &nid);
-	return __alloc_pages_bulk(gfp, nid, nodemask,
-				  nr_pages, NULL, page_array);
+	return alloc_pages_bulk_noprof(gfp, nid, nodemask,
+				       nr_pages, NULL, page_array);
 }
 
 int vma_dup_policy(struct vm_area_struct *src, struct vm_area_struct *dst)
diff --git a/mm/page_alloc.c b/mm/page_alloc.c
index 48cdd25261ea..9c86ef2a0296 100644
--- a/mm/page_alloc.c
+++ b/mm/page_alloc.c
@@ -4427,7 +4427,7 @@ static inline bool prepare_alloc_pages(gfp_t gfp_mask, unsigned int order,
  *
  * Returns the number of pages on the list or array.
  */
-unsigned long __alloc_pages_bulk(gfp_t gfp, int preferred_nid,
+unsigned long alloc_pages_bulk_noprof(gfp_t gfp, int preferred_nid,
 			nodemask_t *nodemask, int nr_pages,
 			struct list_head *page_list,
 			struct page **page_array)
@@ -4563,7 +4563,7 @@ unsigned long __alloc_pages_bulk(gfp_t gfp, int preferred_nid,
 	pcp_trylock_finish(UP_flags);
 
 failed:
-	page = __alloc_pages(gfp, 0, preferred_nid, nodemask);
+	page = __alloc_pages_noprof(gfp, 0, preferred_nid, nodemask);
 	if (page) {
 		if (page_list)
 			list_add(&page->lru, page_list);
@@ -4574,13 +4574,13 @@ unsigned long __alloc_pages_bulk(gfp_t gfp, int preferred_nid,
 
 	goto out;
 }
-EXPORT_SYMBOL_GPL(__alloc_pages_bulk);
+EXPORT_SYMBOL_GPL(alloc_pages_bulk_noprof);
 
 /*
  * This is the 'heart' of the zoned buddy allocator.
  */
-struct page *__alloc_pages(gfp_t gfp, unsigned int order, int preferred_nid,
-							nodemask_t *nodemask)
+struct page *__alloc_pages_noprof(gfp_t gfp, unsigned int order,
+				      int preferred_nid, nodemask_t *nodemask)
 {
 	struct page *page;
 	unsigned int alloc_flags = ALLOC_WMARK_LOW;
@@ -4642,38 +4642,38 @@ struct page *__alloc_pages(gfp_t gfp, unsigned int order, int preferred_nid,
 
 	return page;
 }
-EXPORT_SYMBOL(__alloc_pages);
+EXPORT_SYMBOL(__alloc_pages_noprof);
 
-struct folio *__folio_alloc(gfp_t gfp, unsigned int order, int preferred_nid,
+struct folio *__folio_alloc_noprof(gfp_t gfp, unsigned int order, int preferred_nid,
 		nodemask_t *nodemask)
 {
-	struct page *page = __alloc_pages(gfp | __GFP_COMP, order,
+	struct page *page = __alloc_pages_noprof(gfp | __GFP_COMP, order,
 					preferred_nid, nodemask);
 	return page_rmappable_folio(page);
 }
-EXPORT_SYMBOL(__folio_alloc);
+EXPORT_SYMBOL(__folio_alloc_noprof);
 
 /*
  * Common helper functions. Never use with __GFP_HIGHMEM because the returned
  * address cannot represent highmem pages. Use alloc_pages and then kmap if
  * you need to access high mem.
  */
-unsigned long __get_free_pages(gfp_t gfp_mask, unsigned int order)
+unsigned long get_free_pages_noprof(gfp_t gfp_mask, unsigned int order)
 {
 	struct page *page;
 
-	page = alloc_pages(gfp_mask & ~__GFP_HIGHMEM, order);
+	page = alloc_pages_noprof(gfp_mask & ~__GFP_HIGHMEM, order);
 	if (!page)
 		return 0;
 	return (unsigned long) page_address(page);
 }
-EXPORT_SYMBOL(__get_free_pages);
+EXPORT_SYMBOL(get_free_pages_noprof);
 
-unsigned long get_zeroed_page(gfp_t gfp_mask)
+unsigned long get_zeroed_page_noprof(gfp_t gfp_mask)
 {
-	return __get_free_page(gfp_mask | __GFP_ZERO);
+	return get_free_pages_noprof(gfp_mask | __GFP_ZERO, 0);
 }
-EXPORT_SYMBOL(get_zeroed_page);
+EXPORT_SYMBOL(get_zeroed_page_noprof);
 
 /**
  * __free_pages - Free pages allocated with alloc_pages().
@@ -4875,7 +4875,7 @@ static void *make_alloc_exact(unsigned long addr, unsigned int order,
 }
 
 /**
- * alloc_pages_exact - allocate an exact number physically-contiguous pages.
+ * alloc_pages_exact_noprof - allocate an exact number physically-contiguous pages.
  * @size: the number of bytes to allocate
  * @gfp_mask: GFP flags for the allocation, must not contain __GFP_COMP
  *
@@ -4889,7 +4889,7 @@ static void *make_alloc_exact(unsigned long addr, unsigned int order,
  *
  * Return: pointer to the allocated area or %NULL in case of error.
  */
-void *alloc_pages_exact(size_t size, gfp_t gfp_mask)
+void *alloc_pages_exact_noprof(size_t size, gfp_t gfp_mask)
 {
 	unsigned int order = get_order(size);
 	unsigned long addr;
@@ -4897,13 +4897,13 @@ void *alloc_pages_exact(size_t size, gfp_t gfp_mask)
 	if (WARN_ON_ONCE(gfp_mask & (__GFP_COMP | __GFP_HIGHMEM)))
 		gfp_mask &= ~(__GFP_COMP | __GFP_HIGHMEM);
 
-	addr = __get_free_pages(gfp_mask, order);
+	addr = get_free_pages_noprof(gfp_mask, order);
 	return make_alloc_exact(addr, order, size);
 }
-EXPORT_SYMBOL(alloc_pages_exact);
+EXPORT_SYMBOL(alloc_pages_exact_noprof);
 
 /**
- * alloc_pages_exact_nid - allocate an exact number of physically-contiguous
+ * alloc_pages_exact_nid_noprof - allocate an exact number of physically-contiguous
  *			   pages on a node.
  * @nid: the preferred node ID where memory should be allocated
  * @size: the number of bytes to allocate
@@ -4914,7 +4914,7 @@ EXPORT_SYMBOL(alloc_pages_exact);
  *
  * Return: pointer to the allocated area or %NULL in case of error.
  */
-void * __meminit alloc_pages_exact_nid(int nid, size_t size, gfp_t gfp_mask)
+void * __meminit alloc_pages_exact_nid_noprof(int nid, size_t size, gfp_t gfp_mask)
 {
 	unsigned int order = get_order(size);
 	struct page *p;
@@ -4922,7 +4922,7 @@ void * __meminit alloc_pages_exact_nid(int nid, size_t size, gfp_t gfp_mask)
 	if (WARN_ON_ONCE(gfp_mask & (__GFP_COMP | __GFP_HIGHMEM)))
 		gfp_mask &= ~(__GFP_COMP | __GFP_HIGHMEM);
 
-	p = alloc_pages_node(nid, gfp_mask, order);
+	p = alloc_pages_node_noprof(nid, gfp_mask, order);
 	if (!p)
 		return NULL;
 	return make_alloc_exact((unsigned long)page_address(p), order, size);
@@ -6359,7 +6359,7 @@ int __alloc_contig_migrate_range(struct compact_control *cc,
 }
 
 /**
- * alloc_contig_range() -- tries to allocate given range of pages
+ * alloc_contig_range_noprof() -- tries to allocate given range of pages
  * @start:	start PFN to allocate
  * @end:	one-past-the-last PFN to allocate
  * @migratetype:	migratetype of the underlying pageblocks (either
@@ -6379,7 +6379,7 @@ int __alloc_contig_migrate_range(struct compact_control *cc,
  * pages which PFN is in [start, end) are allocated for the caller and
  * need to be freed with free_contig_range().
  */
-int alloc_contig_range(unsigned long start, unsigned long end,
+int alloc_contig_range_noprof(unsigned long start, unsigned long end,
 		       unsigned migratetype, gfp_t gfp_mask)
 {
 	unsigned long outer_start, outer_end;
@@ -6503,15 +6503,15 @@ int alloc_contig_range(unsigned long start, unsigned long end,
 	undo_isolate_page_range(start, end, migratetype);
 	return ret;
 }
-EXPORT_SYMBOL(alloc_contig_range);
+EXPORT_SYMBOL(alloc_contig_range_noprof);
 
 static int __alloc_contig_pages(unsigned long start_pfn,
 				unsigned long nr_pages, gfp_t gfp_mask)
 {
 	unsigned long end_pfn = start_pfn + nr_pages;
 
-	return alloc_contig_range(start_pfn, end_pfn, MIGRATE_MOVABLE,
-				  gfp_mask);
+	return alloc_contig_range_noprof(start_pfn, end_pfn, MIGRATE_MOVABLE,
+				   gfp_mask);
 }
 
 static bool pfn_range_valid_contig(struct zone *z, unsigned long start_pfn,
@@ -6546,7 +6546,7 @@ static bool zone_spans_last_pfn(const struct zone *zone,
 }
 
 /**
- * alloc_contig_pages() -- tries to find and allocate contiguous range of pages
+ * alloc_contig_pages_noprof() -- tries to find and allocate contiguous range of pages
  * @nr_pages:	Number of contiguous pages to allocate
  * @gfp_mask:	GFP mask to limit search and used during compaction
  * @nid:	Target node
@@ -6566,8 +6566,8 @@ static bool zone_spans_last_pfn(const struct zone *zone,
  *
  * Return: pointer to contiguous pages on success, or NULL if not successful.
  */
-struct page *alloc_contig_pages(unsigned long nr_pages, gfp_t gfp_mask,
-				int nid, nodemask_t *nodemask)
+struct page *alloc_contig_pages_noprof(unsigned long nr_pages, gfp_t gfp_mask,
+				 int nid, nodemask_t *nodemask)
 {
 	unsigned long ret, pfn, flags;
 	struct zonelist *zonelist;
-- 
2.44.0.291.gc1ea87d7ee-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240321163705.3067592-19-surenb%40google.com.
