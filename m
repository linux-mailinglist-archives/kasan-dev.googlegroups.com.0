Return-Path: <kasan-dev+bncBDX4HWEMTEBRBXFEVT6QKGQEVFO4MPQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53e.google.com (mail-ed1-x53e.google.com [IPv6:2a00:1450:4864:20::53e])
	by mail.lfdr.de (Postfix) with ESMTPS id 098642AE33F
	for <lists+kasan-dev@lfdr.de>; Tue, 10 Nov 2020 23:21:17 +0100 (CET)
Received: by mail-ed1-x53e.google.com with SMTP id b16sf4809531edn.6
        for <lists+kasan-dev@lfdr.de>; Tue, 10 Nov 2020 14:21:17 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605046876; cv=pass;
        d=google.com; s=arc-20160816;
        b=ClIKwCV3EO8vnanMA/tGkCkh4NqVYjcw6ZeaK4rNke687VKQCQxU62A4yhPqye0rL6
         eJz2aRb7NGZ0vpDlJpoqkf39v7jdVh3U4J4W5v8jEI8BSbhv0DF3t0YLT9GZjL+2lPsE
         zC7hr/Wsr5SVvLQY/OAQ8khaeArkv4aKphM5Zo+srBKeSbgZg4BdVF83c9grWVRoBVJF
         UjFAYZInsJJ1rRuVfXOYpLzlqnKpDvtMMLPrcxCVHQG7C+kXxgv6zppxPzOC9HKYdZVO
         oEgNCZsHbBi4lMD2Pm+Oz+ehPukLmCYf/qHiCtAP+PRBKjXEs1WuymxylFDyjFTRzf7M
         Dvkw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=OycFwXeweLkSP5svU0mDpUVYlU0+MwpCJLsZC1wWDNA=;
        b=p0Jgc3uMQCPaGEDCzcH1S41kIKbbJuCI4E0MalBDuQhjmHLVVN1By1yOySicDsMn2a
         mAwohdFAiCBj15LDfolGpelnkT5x7WEsGM5mxvFGErq0OGPVzCwmMu903VvtSj5KPEnG
         8HrozI00gT5lWKu3HzwPk8x+o7havmMHlnB7J6l23NeQdRtI3WIXM6w4/a4luGREqy1v
         d1TPWCMfzM7/CbDd5MJ/RUgPWO7g1U552H7XFfeZ2sx+UpVbF0iXIC05Hq7xg54PXTaW
         CNVa+Atyhy2TOf5LV0Jb9vQzd2XPmaEGvMqTGl+cOqoQMx0yPlZoiGVUVi/4EY48BAZr
         PMog==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=MvPjJraT;
       spf=pass (google.com: domain of 3wxkrxwokctamzpdqkwzhxsaasxq.oaywmemz-pqhsaasxqsdagbe.oay@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3WxKrXwoKCTAMZPdQkWZhXSaaSXQ.OaYWMeMZ-PQhSaaSXQSdagbe.OaY@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=OycFwXeweLkSP5svU0mDpUVYlU0+MwpCJLsZC1wWDNA=;
        b=OJ0F75oi3UorFs3LZsN/tpOtjaAbsTHH9uEhHAHztFO/iA/zRhmRo5sv61MnzXODz4
         1adS+YANLkbJlDB5O+4pm7v0M3ywT6ZrqLvIQY17eEjXT8gMmtwZwbZn1Ph3mhnZR1YB
         rfGIY7SveYkx1wc8ujPzr80DCB5YB8lrAdK2rmR6O45TWIMmocoUe32MaZgf2gVNwCJa
         Vpb/xOZoDqa+uQRQvUI1+eTHG9orwtGzQoDZ3pmmNkwgVkJ+p9hFmrIAZa/6bJY+qXAP
         wEKFP5IRSoru6AzfQEK5UYq5bXK2GZyMs/ZZELJIEgplt9nneML7W3xoOgE0Utl+73T2
         T2dQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=OycFwXeweLkSP5svU0mDpUVYlU0+MwpCJLsZC1wWDNA=;
        b=KiU+S65s5UOlAqTPFcLxIWVjHsgXwW8Tcm3QfHVRjchDB2ypvrg6vSlznnLygC/jq4
         HOMy8ts+dIx5/uddDhdGIjLWc1ys6HDyW5I+44sWFND1a/JONBjzHXmJ7xRFLhz36rlb
         SvHFC9fvLIruuA2wfBR9uOwzoMJOPP94evBqa0yRbe1buBGbxPapeeFZxzRtbJ3vNRwq
         VMzWLjwbo/K//KzQHqHr2VJAaD84BQ/m2cHa2XysZrIF8POYsexdWhtlXGQji+hobijM
         rgavPqvBcLwgsJUVPllJMmd/3aQrBOQVgOQCexA7ZhDFfpRPl8sEyEwsYtbQg4zuY6Fq
         BEfg==
X-Gm-Message-State: AOAM531KKhrM3ksgBKtvgZGK5QBaTdH8iIR8kYioDlghODvrZ8C3NH7Z
	w5enDOGQBST4ZStcDKsFUKE=
X-Google-Smtp-Source: ABdhPJwtl2YSGxlezutgx2BcK2dGMaHlVp3UIODqDqkNxjFGIGMWAOpBFI5ivsxerLRkT0HN6xbXtQ==
X-Received: by 2002:a50:af65:: with SMTP id g92mr23830143edd.273.1605046876830;
        Tue, 10 Nov 2020 14:21:16 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:cc8b:: with SMTP id p11ls14289124edt.3.gmail; Tue, 10
 Nov 2020 14:21:16 -0800 (PST)
X-Received: by 2002:a05:6402:759:: with SMTP id p25mr1688833edy.22.1605046875916;
        Tue, 10 Nov 2020 14:21:15 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605046875; cv=none;
        d=google.com; s=arc-20160816;
        b=zRS96Je+yeOrgpshbOKsTo8BVJ8mOFQ3ck0V3cnOpR0NFUboh+k8lwKp842DDd+DoM
         rISQ+Q65gRe2MvvJILsyCvcZHT0JUQn5XD2uU10K1Rqga7JeFBkMJdHeG4+WHD78nyc4
         qD21rUKHNsa6nBjo0rTXbdT14dI0nejY0aXNVB+d0hdj8lNiqNeOH5ss3UEtG/e4CfD/
         MSoq3ubG+oeJU+VxzyZVvpbnhSvs+SWDkVIX4iCMeUQmXY1MHKGv0FplbQsoCgQN6dvS
         SDFNWUZ4Oxr2soHdM+Q5laJIKWHvPaKPBWZ6kigkDWK4kM3Pfz6Aash/SUQNC0Xh1v6y
         jjCQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=NSEnP5/Ymw2+CzfuUjUL3yzFjWGlVw3jfopzq6nBhYw=;
        b=qnIdUYu+dTInF0PPvx6jzxjuYFCuE7RSo1hmnaIee9STeXFCpdnBxxcj2rtyaIzbXh
         SClwKrbe4ZRDHSczIOvJpAiXi1OVD4gF9RVfn5yiogKp7DIbTB+3ToheADk0RTvHwl4D
         Z9xmtw1prjxmr8a0jGb9HYdWscKBkRMef7g2fKycu5stD3urHwhwJcwhMa4hsKijn2ny
         8sH5YkYWHkkQcDxDYMMDiamZwtP3B7S20YGiWALBmpJBJiBhs1ILPAxhAOnMoyrNUAxU
         hC7ZNDSW4/152KGXlA4QjhgOEgJBKHCW6DCRaeNPgWvX0oGvYlnL5YybYMMe7j1xVFB3
         nkvA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=MvPjJraT;
       spf=pass (google.com: domain of 3wxkrxwokctamzpdqkwzhxsaasxq.oaywmemz-pqhsaasxqsdagbe.oay@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3WxKrXwoKCTAMZPdQkWZhXSaaSXQ.OaYWMeMZ-PQhSaaSXQSdagbe.OaY@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x34a.google.com (mail-wm1-x34a.google.com. [2a00:1450:4864:20::34a])
        by gmr-mx.google.com with ESMTPS id a11si3037edq.1.2020.11.10.14.21.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 10 Nov 2020 14:21:15 -0800 (PST)
Received-SPF: pass (google.com: domain of 3wxkrxwokctamzpdqkwzhxsaasxq.oaywmemz-pqhsaasxqsdagbe.oay@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) client-ip=2a00:1450:4864:20::34a;
Received: by mail-wm1-x34a.google.com with SMTP id z62so1675612wmb.1
        for <kasan-dev@googlegroups.com>; Tue, 10 Nov 2020 14:21:15 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a7b:c772:: with SMTP id
 x18mr262720wmk.185.1605046875625; Tue, 10 Nov 2020 14:21:15 -0800 (PST)
Date: Tue, 10 Nov 2020 23:20:23 +0100
In-Reply-To: <cover.1605046662.git.andreyknvl@google.com>
Message-Id: <936c0c198145b663e031527c49a6895bd21ac3a0.1605046662.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1605046662.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.2.222.g5d2a92d10f8-goog
Subject: [PATCH v2 19/20] kasan, mm: allow cache merging with no metadata
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Dmitry Vyukov <dvyukov@google.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Evgenii Stepanov <eugenis@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=MvPjJraT;       spf=pass
 (google.com: domain of 3wxkrxwokctamzpdqkwzhxsaasxq.oaywmemz-pqhsaasxqsdagbe.oay@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3WxKrXwoKCTAMZPdQkWZhXSaaSXQ.OaYWMeMZ-PQhSaaSXQSdagbe.OaY@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

The reason cache merging is disabled with KASAN is because KASAN puts its
metadata right after the allocated object. When the merged caches have
slightly different sizes, the metadata ends up in different places, which
KASAN doesn't support.

It might be possible to adjust the metadata allocation algorithm and make
it friendly to the cache merging code. Instead this change takes a simpler
approach and allows merging caches when no metadata is present. Which is
the case for hardware tag-based KASAN with kasan.mode=prod.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Link: https://linux-review.googlesource.com/id/Ia114847dfb2244f297d2cb82d592bf6a07455dba
---
 include/linux/kasan.h | 26 ++++++++++++++++++++++++--
 mm/kasan/common.c     | 11 +++++++++++
 mm/slab_common.c      | 11 ++++++++---
 3 files changed, 43 insertions(+), 5 deletions(-)

diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index 534ab3e2935a..c754eca356f7 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -81,17 +81,35 @@ struct kasan_cache {
 };
 
 #ifdef CONFIG_KASAN_HW_TAGS
+
 DECLARE_STATIC_KEY_FALSE(kasan_flag_enabled);
+
 static inline kasan_enabled(void)
 {
 	return static_branch_likely(&kasan_flag_enabled);
 }
-#else
+
+slab_flags_t __kasan_never_merge(slab_flags_t flags);
+static inline slab_flags_t kasan_never_merge(slab_flags_t flags)
+{
+	if (kasan_enabled())
+		return __kasan_never_merge(flags);
+	return flags;
+}
+
+#else /* CONFIG_KASAN_HW_TAGS */
+
 static inline kasan_enabled(void)
 {
 	return true;
 }
-#endif
+
+static inline slab_flags_t kasan_never_merge(slab_flags_t flags)
+{
+	return flags;
+}
+
+#endif /* CONFIG_KASAN_HW_TAGS */
 
 void __kasan_alloc_pages(struct page *page, unsigned int order);
 static inline void kasan_alloc_pages(struct page *page, unsigned int order)
@@ -240,6 +258,10 @@ static inline kasan_enabled(void)
 {
 	return false;
 }
+static inline slab_flags_t kasan_never_merge(slab_flags_t flags)
+{
+	return flags;
+}
 static inline void kasan_alloc_pages(struct page *page, unsigned int order) {}
 static inline void kasan_free_pages(struct page *page, unsigned int order) {}
 static inline void kasan_cache_create(struct kmem_cache *cache,
diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index 940b42231069..25b18c145b06 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -81,6 +81,17 @@ asmlinkage void kasan_unpoison_task_stack_below(const void *watermark)
 }
 #endif /* CONFIG_KASAN_STACK */
 
+/*
+ * Only allow cache merging when stack collection is disabled and no metadata
+ * is present.
+ */
+slab_flags_t __kasan_never_merge(slab_flags_t flags)
+{
+	if (kasan_stack_collection_enabled())
+		return flags;
+	return flags & ~SLAB_KASAN;
+}
+
 void __kasan_alloc_pages(struct page *page, unsigned int order)
 {
 	u8 tag;
diff --git a/mm/slab_common.c b/mm/slab_common.c
index f1b0c4a22f08..3042ee8ea9ce 100644
--- a/mm/slab_common.c
+++ b/mm/slab_common.c
@@ -18,6 +18,7 @@
 #include <linux/seq_file.h>
 #include <linux/proc_fs.h>
 #include <linux/debugfs.h>
+#include <linux/kasan.h>
 #include <asm/cacheflush.h>
 #include <asm/tlbflush.h>
 #include <asm/page.h>
@@ -49,12 +50,16 @@ static DECLARE_WORK(slab_caches_to_rcu_destroy_work,
 		    slab_caches_to_rcu_destroy_workfn);
 
 /*
- * Set of flags that will prevent slab merging
+ * Set of flags that will prevent slab merging.
+ * Use slab_never_merge() instead.
  */
 #define SLAB_NEVER_MERGE (SLAB_RED_ZONE | SLAB_POISON | SLAB_STORE_USER | \
 		SLAB_TRACE | SLAB_TYPESAFE_BY_RCU | SLAB_NOLEAKTRACE | \
 		SLAB_FAILSLAB | SLAB_KASAN)
 
+/* KASAN allows merging in some configurations and will remove SLAB_KASAN. */
+#define slab_never_merge() (kasan_never_merge(SLAB_NEVER_MERGE))
+
 #define SLAB_MERGE_SAME (SLAB_RECLAIM_ACCOUNT | SLAB_CACHE_DMA | \
 			 SLAB_CACHE_DMA32 | SLAB_ACCOUNT)
 
@@ -164,7 +169,7 @@ static unsigned int calculate_alignment(slab_flags_t flags,
  */
 int slab_unmergeable(struct kmem_cache *s)
 {
-	if (slab_nomerge || (s->flags & SLAB_NEVER_MERGE))
+	if (slab_nomerge || (s->flags & slab_never_merge()))
 		return 1;
 
 	if (s->ctor)
@@ -198,7 +203,7 @@ struct kmem_cache *find_mergeable(unsigned int size, unsigned int align,
 	size = ALIGN(size, align);
 	flags = kmem_cache_flags(size, flags, name, NULL);
 
-	if (flags & SLAB_NEVER_MERGE)
+	if (flags & slab_never_merge())
 		return NULL;
 
 	list_for_each_entry_reverse(s, &slab_caches, list) {
-- 
2.29.2.222.g5d2a92d10f8-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/936c0c198145b663e031527c49a6895bd21ac3a0.1605046662.git.andreyknvl%40google.com.
