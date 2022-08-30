Return-Path: <kasan-dev+bncBC7OD3FKWUERB7ULXKMAMGQEBM5XJWY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb38.google.com (mail-yb1-xb38.google.com [IPv6:2607:f8b0:4864:20::b38])
	by mail.lfdr.de (Postfix) with ESMTPS id B8DD95A6F8C
	for <lists+kasan-dev@lfdr.de>; Tue, 30 Aug 2022 23:49:51 +0200 (CEST)
Received: by mail-yb1-xb38.google.com with SMTP id s15-20020a5b044f000000b00680c4eb89f1sf711154ybp.7
        for <lists+kasan-dev@lfdr.de>; Tue, 30 Aug 2022 14:49:51 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1661896190; cv=pass;
        d=google.com; s=arc-20160816;
        b=VRAsVqn3DgD5tI6ajX1P/XsxPAdaDvHBg5YDDDWtv7P6vHHeTYl7C9eqan3bJ88/Pe
         Mva2bRmIXod5BgTY5EGY2SvGrMtssMz21W5vJV4DWH7+hwVS0+n6pll2htl3j5Y7kJ9Q
         /gt7dN+d5rhdHu5Z/cURqfhrEbgqriZYlsxtjJvGnr8l0Sn3kJxazLyk9zAiBzynrGTU
         tsdsFXdhXD5qihM9FR0hWHeUzhsZc1o/1lKoWOsYE+YBQx3oClCYiut1DMy2nT7XKCcu
         DnNQiOhC2sELkv4k6l65UDtesMgjFQwFG1yFsMD0oMibqKCG084ahuLNrsGy3wIL8Sdy
         xWPg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=Tj2PtEQzr1r3neuXrsvSp6kuQfY9WFSyi18bqOVgCFM=;
        b=WuxYoW+rEeYhI3fgCKi1S8IIYaeYptFwQqnkuVCZLIzcU4ZMiFQ0ZvhtofzKqIp17C
         M0hRjpH4W5uqz60mDfptgUcBbQo0cWT2sfmGbBR3MLCeRJJBXX6bWcbFx5q0ahGrQUV2
         XYz3TD4SFGNbUFI5fQbmpxzY0UQSl9neG2AUWoQG0gHBA0rPTwe/fLp2qp2A8pk1U8xV
         +aQCsPvG6XnJrzIHcLRQPHzqwmRJO6/VMgslawwOm65xf6vhNvKsXEOB9ozFH00Q2pst
         f0z0U8LDCX5G3uZXkwIwIg2Hz701KjWE/IpFmn9miwEnJIzOYB9qXXkWgiFsE8sRxIpZ
         Nf0A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=dfpyzvwd;
       spf=pass (google.com: domain of 3_yuoywykcwisurenbgoogle.comkasan-devgooglegroups.com@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=3_YUOYwYKCWISURENBGOOGLE.COMKASAN-DEVGOOGLEGROUPS.COM@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc;
        bh=Tj2PtEQzr1r3neuXrsvSp6kuQfY9WFSyi18bqOVgCFM=;
        b=VT8WsG4ryuEyiYReIi133CCjofrXdhxjwBdkLkz22n6geXMU1qdieFG8EBroJHiLuO
         LFf0ICXHZc+SznYCaLni5/rfPCJwR3Cbf02bxKsijomfmI3MXmdUq0Z3/w1i1kC0sFUK
         rXPZD2zJy8zKXTTvRR+QOkZISIrRfgq/vVhHiEdKhtK3kyz1MjVyv2FQpamiEClrxBex
         mK+BCA50iaGAJ+mC9T7aRRe65PLJ7DVtAzeRCeSOhnWL+4jhocJUSd3YRrDeWsVRo33J
         0SUlqFDTz7ZSoulFLVLFAaVMwiUpcf2o0/V9Z3U7qsbvpXq0b6Qyzw9jOIwVfbDoM6/0
         kniA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-gm-message-state:from:to:cc;
        bh=Tj2PtEQzr1r3neuXrsvSp6kuQfY9WFSyi18bqOVgCFM=;
        b=o8ik/qPQSfwD6Vp6IEZG/eLaJc+R9rqEcflY7x9TnDY1pasWYa9d6iwVG4BxTSR8m4
         RR12jukmgC2wp3fmV9UHSq4aMnl6zydnT8g8FxY2P2JQwF7O20bbsGm/X7U+yIfQ2mCB
         XzcZbTEf2VqS+oHnf4nNjdf4cu5u938bKSWLdzTN3j1d1Sk72mOHnfdnrlFttBhFkTnp
         0eCWyPtAEIrjlxlWvRHM6oRgZRcodolM5lgGuKryJRzv6RuA2V2LCNHsOpbKYecEoDZt
         JlnW0lI8envluzScWU2aC/d3trQgGxTc1LC5oUI1qnc9+XatewPhGuKnoscHHYOZzSI2
         UErg==
X-Gm-Message-State: ACgBeo1prPVGpu+2W9R+705FMqKdAbp4WRMx9JuFRz19URkNR2+lkWhg
	P+E9N5fkObwHCXvNeij5Djg=
X-Google-Smtp-Source: AA6agR5bnhXYhR0C6P9PHPRpm0fRBpqkMuP+E4xRMV44l7hUi5Jlxlq/ecQz+5a5RXqCLm0ZTtCGsw==
X-Received: by 2002:a0d:d842:0:b0:33d:cac3:bacf with SMTP id a63-20020a0dd842000000b0033dcac3bacfmr15761371ywe.251.1661896190757;
        Tue, 30 Aug 2022 14:49:50 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:b206:0:b0:671:60f4:9231 with SMTP id i6-20020a25b206000000b0067160f49231ls4905447ybj.7.-pod-prod-gmail;
 Tue, 30 Aug 2022 14:49:50 -0700 (PDT)
X-Received: by 2002:a25:945:0:b0:694:3f2e:667c with SMTP id u5-20020a250945000000b006943f2e667cmr12766961ybm.581.1661896190287;
        Tue, 30 Aug 2022 14:49:50 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1661896190; cv=none;
        d=google.com; s=arc-20160816;
        b=DlSTd9sHUKurSkoY14hiyF6q1v1Sal8kLl0yjooVS0umirwGybHITuGlYCMwiz0Gy3
         KH0CjL6uqL4CRtUkRDHlM0qtdY4JyTL09FNBjroDClCs/A/LcfbEP96DNiVsoolMMbw9
         /B6FAfahcg+84py1ARYlA4UW2zZSMm5gOOaRSrAZE1BBfoK9L3Q7RzhpylE+HRTisGXw
         IrUfUDF/unEL9TwHKxx3L4YVqqN4vaQdicfoKCFE7HBLLkT7sb7uH2Gcz6Mv501Ow32U
         1CQBb/Tt+R/9JCl7+lT3F7yw12m4jCnS7wJMxeM1/eCrBZVIR4vXZYaP3Z3otou+25dT
         SAQg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=hT6Mz/zinVpRQBPKe7V7vUNm2EL+nNA0Rd6lje133es=;
        b=CHc3leHodBphahBgpDDw9uLd6zEd0Bhwhdt/qGeEq0eLNGGIK/lfgScFxwdybOQnjE
         9i6KYoglbjy8nj/tyAUBLsD/noLhLJGJBCNiIQJwqfpFJ+OgeJ6vIdw9Bcar9zXiMR1c
         7u3uK76QiWMfIO8KAWB59+xwv6do2VxtRQhF263ODlLEnCA23dwXHg9B4ndV680t3+SM
         W5/JLFZ1x0ZxG1ObB+zsjIrKfQsw8EHDcUjXp7yLjIu1bjEyw73sWIPf2w4PnwLNdYLu
         FGM0bVPOl8D4o0Lu/vEkxYF/+qZLDJP1oe36YU3gas01e63dZQjAHWTms4OJKdY7AiZV
         5CbQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=dfpyzvwd;
       spf=pass (google.com: domain of 3_yuoywykcwisurenbgoogle.comkasan-devgooglegroups.com@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=3_YUOYwYKCWISURENBGOOGLE.COMKASAN-DEVGOOGLEGROUPS.COM@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x114a.google.com (mail-yw1-x114a.google.com. [2607:f8b0:4864:20::114a])
        by gmr-mx.google.com with ESMTPS id d11-20020a25afcb000000b0069498aacd1dsi489912ybj.2.2022.08.30.14.49.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 30 Aug 2022 14:49:50 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3_yuoywykcwisurenbgoogle.comkasan-devgooglegroups.com@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) client-ip=2607:f8b0:4864:20::114a;
Received: by mail-yw1-x114a.google.com with SMTP id 00721157ae682-340e618b145so120881237b3.2
        for <kasan-dev@googlegroups.com>; Tue, 30 Aug 2022 14:49:50 -0700 (PDT)
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:200:a005:55b3:6c26:b3e4])
 (user=surenb job=sendgmr) by 2002:a25:cf0e:0:b0:696:42f1:3889 with SMTP id
 f14-20020a25cf0e000000b0069642f13889mr13000431ybg.175.1661896189937; Tue, 30
 Aug 2022 14:49:49 -0700 (PDT)
Date: Tue, 30 Aug 2022 14:48:59 -0700
In-Reply-To: <20220830214919.53220-1-surenb@google.com>
Mime-Version: 1.0
References: <20220830214919.53220-1-surenb@google.com>
X-Mailer: git-send-email 2.37.2.672.g94769d06f0-goog
Message-ID: <20220830214919.53220-11-surenb@google.com>
Subject: [RFC PATCH 10/30] mm: enable page allocation tagging for
 __get_free_pages and alloc_pages
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
 header.i=@google.com header.s=20210112 header.b=dfpyzvwd;       spf=pass
 (google.com: domain of 3_yuoywykcwisurenbgoogle.comkasan-devgooglegroups.com@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=3_YUOYwYKCWISURENBGOOGLE.COMKASAN-DEVGOOGLEGROUPS.COM@flex--surenb.bounces.google.com;
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

Redefine alloc_pages, __get_free_pages to record allocations done by
these functions. Instrument deallocation hooks to record object freeing.

Signed-off-by: Suren Baghdasaryan <surenb@google.com>
---
 include/linux/gfp.h         | 10 +++++++---
 include/linux/page_ext.h    |  3 ++-
 include/linux/pgalloc_tag.h | 35 +++++++++++++++++++++++++++++++++++
 mm/mempolicy.c              |  4 ++--
 mm/page_alloc.c             | 13 ++++++++++---
 5 files changed, 56 insertions(+), 9 deletions(-)

diff --git a/include/linux/gfp.h b/include/linux/gfp.h
index f314be58fa77..5cb950a49d40 100644
--- a/include/linux/gfp.h
+++ b/include/linux/gfp.h
@@ -6,6 +6,7 @@
 
 #include <linux/mmzone.h>
 #include <linux/topology.h>
+#include <linux/pgalloc_tag.h>
 
 struct vm_area_struct;
 
@@ -267,12 +268,12 @@ static inline struct page *alloc_pages_node(int nid, gfp_t gfp_mask,
 }
 
 #ifdef CONFIG_NUMA
-struct page *alloc_pages(gfp_t gfp, unsigned int order);
+struct page *_alloc_pages(gfp_t gfp, unsigned int order);
 struct folio *folio_alloc(gfp_t gfp, unsigned order);
 struct folio *vma_alloc_folio(gfp_t gfp, int order, struct vm_area_struct *vma,
 		unsigned long addr, bool hugepage);
 #else
-static inline struct page *alloc_pages(gfp_t gfp_mask, unsigned int order)
+static inline struct page *_alloc_pages(gfp_t gfp_mask, unsigned int order)
 {
 	return alloc_pages_node(numa_node_id(), gfp_mask, order);
 }
@@ -283,6 +284,7 @@ static inline struct folio *folio_alloc(gfp_t gfp, unsigned int order)
 #define vma_alloc_folio(gfp, order, vma, addr, hugepage)		\
 	folio_alloc(gfp, order)
 #endif
+#define alloc_pages(gfp, order) pgtag_alloc_pages(gfp, order)
 #define alloc_page(gfp_mask) alloc_pages(gfp_mask, 0)
 static inline struct page *alloc_page_vma(gfp_t gfp,
 		struct vm_area_struct *vma, unsigned long addr)
@@ -292,7 +294,9 @@ static inline struct page *alloc_page_vma(gfp_t gfp,
 	return &folio->page;
 }
 
-extern unsigned long __get_free_pages(gfp_t gfp_mask, unsigned int order);
+extern unsigned long _get_free_pages(gfp_t gfp_mask, unsigned int order,
+				     struct page **ppage);
+#define __get_free_pages(gfp_mask, order) pgtag_get_free_pages(gfp_mask, order)
 extern unsigned long get_zeroed_page(gfp_t gfp_mask);
 
 void *alloc_pages_exact(size_t size, gfp_t gfp_mask) __alloc_size(1);
diff --git a/include/linux/page_ext.h b/include/linux/page_ext.h
index fabb2e1e087f..b26077110fb3 100644
--- a/include/linux/page_ext.h
+++ b/include/linux/page_ext.h
@@ -4,7 +4,6 @@
 
 #include <linux/types.h>
 #include <linux/stacktrace.h>
-#include <linux/stackdepot.h>
 
 struct pglist_data;
 struct page_ext_operations {
@@ -14,6 +13,8 @@ struct page_ext_operations {
 	void (*init)(void);
 };
 
+#include <linux/stackdepot.h>
+
 #ifdef CONFIG_PAGE_EXTENSION
 
 enum page_ext_flags {
diff --git a/include/linux/pgalloc_tag.h b/include/linux/pgalloc_tag.h
index f525abfe51d4..154ea7436fec 100644
--- a/include/linux/pgalloc_tag.h
+++ b/include/linux/pgalloc_tag.h
@@ -5,6 +5,8 @@
 #ifndef _LINUX_PGALLOC_TAG_H
 #define _LINUX_PGALLOC_TAG_H
 
+#ifdef CONFIG_PAGE_ALLOC_TAGGING
+
 #include <linux/alloc_tag.h>
 #include <linux/page_ext.h>
 
@@ -25,4 +27,37 @@ static inline void pgalloc_tag_dec(struct page *page, unsigned int order)
 		alloc_tag_sub(get_page_tag_ref(page), PAGE_SIZE << order);
 }
 
+/*
+ * Redefinitions of the common page allocators/destructors
+ */
+#define pgtag_alloc_pages(gfp, order)					\
+({									\
+	struct page *_page = _alloc_pages((gfp), (order));		\
+									\
+	if (_page)							\
+		alloc_tag_add(get_page_tag_ref(_page), PAGE_SIZE << (order));\
+	_page;								\
+})
+
+#define pgtag_get_free_pages(gfp_mask, order)				\
+({									\
+	struct page *_page;						\
+	unsigned long _res = _get_free_pages((gfp_mask), (order), &_page);\
+									\
+	if (_res)							\
+		alloc_tag_add(get_page_tag_ref(_page), PAGE_SIZE << (order));\
+	_res;								\
+})
+
+#else /* CONFIG_PAGE_ALLOC_TAGGING */
+
+#define pgtag_alloc_pages(gfp, order) _alloc_pages(gfp, order)
+
+#define pgtag_get_free_pages(gfp_mask, order) \
+	_get_free_pages((gfp_mask), (order), NULL)
+
+#define pgalloc_tag_dec(__page, __size)		do {} while (0)
+
+#endif /* CONFIG_PAGE_ALLOC_TAGGING */
+
 #endif /* _LINUX_PGALLOC_TAG_H */
diff --git a/mm/mempolicy.c b/mm/mempolicy.c
index b73d3248d976..f7e6d9564a49 100644
--- a/mm/mempolicy.c
+++ b/mm/mempolicy.c
@@ -2249,7 +2249,7 @@ EXPORT_SYMBOL(vma_alloc_folio);
  * flags are used.
  * Return: The page on success or NULL if allocation fails.
  */
-struct page *alloc_pages(gfp_t gfp, unsigned order)
+struct page *_alloc_pages(gfp_t gfp, unsigned int order)
 {
 	struct mempolicy *pol = &default_policy;
 	struct page *page;
@@ -2273,7 +2273,7 @@ struct page *alloc_pages(gfp_t gfp, unsigned order)
 
 	return page;
 }
-EXPORT_SYMBOL(alloc_pages);
+EXPORT_SYMBOL(_alloc_pages);
 
 struct folio *folio_alloc(gfp_t gfp, unsigned order)
 {
diff --git a/mm/page_alloc.c b/mm/page_alloc.c
index e5486d47406e..165daba19e2a 100644
--- a/mm/page_alloc.c
+++ b/mm/page_alloc.c
@@ -763,6 +763,7 @@ static inline bool pcp_allowed_order(unsigned int order)
 
 static inline void free_the_page(struct page *page, unsigned int order)
 {
+
 	if (pcp_allowed_order(order))		/* Via pcp? */
 		free_unref_page(page, order);
 	else
@@ -1120,6 +1121,8 @@ static inline void __free_one_page(struct page *page,
 	VM_BUG_ON_PAGE(pfn & ((1 << order) - 1), page);
 	VM_BUG_ON_PAGE(bad_range(zone, page), page);
 
+	pgalloc_tag_dec(page, order);
+
 	while (order < MAX_ORDER - 1) {
 		if (compaction_capture(capc, page, order, migratetype)) {
 			__mod_zone_freepage_state(zone, -(1 << order),
@@ -3440,6 +3443,7 @@ static void free_unref_page_commit(struct zone *zone, struct per_cpu_pages *pcp,
 	int pindex;
 	bool free_high;
 
+	pgalloc_tag_dec(page, order);
 	__count_vm_event(PGFREE);
 	pindex = order_to_pindex(migratetype, order);
 	list_add(&page->pcp_list, &pcp->lists[pindex]);
@@ -5557,16 +5561,19 @@ EXPORT_SYMBOL(__folio_alloc);
  * address cannot represent highmem pages. Use alloc_pages and then kmap if
  * you need to access high mem.
  */
-unsigned long __get_free_pages(gfp_t gfp_mask, unsigned int order)
+unsigned long _get_free_pages(gfp_t gfp_mask, unsigned int order,
+			      struct page **ppage)
 {
 	struct page *page;
 
-	page = alloc_pages(gfp_mask & ~__GFP_HIGHMEM, order);
+	page = _alloc_pages(gfp_mask & ~__GFP_HIGHMEM, order);
+	if (ppage)
+		*ppage = page;
 	if (!page)
 		return 0;
 	return (unsigned long) page_address(page);
 }
-EXPORT_SYMBOL(__get_free_pages);
+EXPORT_SYMBOL(_get_free_pages);
 
 unsigned long get_zeroed_page(gfp_t gfp_mask)
 {
-- 
2.37.2.672.g94769d06f0-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220830214919.53220-11-surenb%40google.com.
