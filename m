Return-Path: <kasan-dev+bncBAABBT6TXOHQMGQEXKHJ5RY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x139.google.com (mail-lf1-x139.google.com [IPv6:2a00:1450:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id CBF1049878E
	for <lists+kasan-dev@lfdr.de>; Mon, 24 Jan 2022 19:02:56 +0100 (CET)
Received: by mail-lf1-x139.google.com with SMTP id w42-20020a0565120b2a00b00432f6a227e0sf9363349lfu.3
        for <lists+kasan-dev@lfdr.de>; Mon, 24 Jan 2022 10:02:56 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1643047376; cv=pass;
        d=google.com; s=arc-20160816;
        b=YbMHoVafT3H0qCBRuia76FplACYyojeDyt/f/78nM91ynH7UWVDr3ZTvaTd5RHNTFS
         OtE9in+ABqa2dgKPPqUnEJF2dznnQF/l0TeGADKn9eC6maii28xHoxqDvKfD5tyMK6hL
         HMvIQgVx9Rl+cd+yxk2F8FOyQ/tB0jDF+kb5NcRzM4Nd+9oIAcjL/MbQP5IMDMDDRGpn
         5q99vT3LMiu7DAfl6sgK43aLM2lkgdqL7fjvOcyRVnhgmdulN6klzHPaJvHUKEUXiJUX
         OMzB/JFu+cnSSyd5sM6n+zrprgMxxIL7PzWrX6QAiPB5hocqA8dGaLHGu1nrdA6xGJ6C
         Im5g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=HwthbnDXXfoqQseV7VaNfynRmq3avETXdkUhZeHTsw0=;
        b=bqfyWOV4MqPxarNnmOXrfYSiWnSXLKYOszlKah95fh+BvYkshTGON85JIAtn6f8QiB
         PaEOiuYTHxQVXN6wlQlckidQNXmBcVms5A9RtsLPtHT5x/jWdn7RIhBwxR1cDp/k27ls
         jRZQmhCGJ0V9IKWLRmMbhLKVvg/k0M5lDlAYr5oEEj0kQJ35ImJaXbE3CNEc5MUEYrZr
         A2PW6i3f+ZxRgGP5r13ZuH17SVl6VPllF3iGIUj9RD/6rtlNjuwMk59NoLaJBgoholos
         nKpoHRtzhqap4ewRzJODESuLPDOLwP5MIx5BqUorQD6UXFkwHlAUe+6N/Jl4a1kWi8Ea
         SHCA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=sJTI5Fax;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=HwthbnDXXfoqQseV7VaNfynRmq3avETXdkUhZeHTsw0=;
        b=FsV7HEbssdjLASbMkblXVZ67ham+Ec/1UYmBVjc/HraWwddV6lLE/qRepqYmr72peD
         0IP7wkN3BfqVA11WAYm3Dfn/g3M8p0Rjeu7eDBHBL2BHvsoXqsrg9EXarF8YHktdqhIe
         azTwhkNGbfpomxo+RrEMfT1sRvfJuhchug1/1yWd67Jvp+/dYqlhgg7jZrn4sDFG6S/v
         i+lzP0zdB960EEYFyNO4T2zK3l/AdDudBWDDIL/kvIuTtbxuKERHoSQOg1OvzhWWZjH5
         PEoUmCtDU5Yq5+KW7Es6v3WOjdcdsePDQZTZ8fEqQ7gYL9JVAeKXXyOXinj8juNHUM2i
         cuYg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=HwthbnDXXfoqQseV7VaNfynRmq3avETXdkUhZeHTsw0=;
        b=KfdiGgTwck+DKmpAgMauqW80gfubOuczgCr06P+MnRd1Gle/z/pnBoVEWHZP6HZL3b
         zyT+ng4XsotZg+2PHd7ETSmLj81tAjXLu3ypT1J4cNVxL/mlIwm1HULjAo+peNfdPTI+
         VE1y7u1XlB0WD9Dl3kkwXAajmYLwGIPc8dG7dfGZvkruEYwqridX/BeQI3O8xiQyW2lD
         FchDQ26utJGXzQQzjdXfXmYqPyOSJxzjj7stBmB+ur6LRT4GFjrv66lmZScLOV/ILLAB
         Ow6httQMeo7Ikz15GAYe5VCp6Lahnwngfhx9fS7ivLkJbLG5OFeyLuHWBla46p7w6qMk
         /EGA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530wltcGzz2O+iKeuaa8BZxuBiOc2W95FhTvBdJKW7UZEY2hVTbs
	ho7x8xLsRMOsBI+p/uHtEeQ=
X-Google-Smtp-Source: ABdhPJxyJx6AKwFjJvqIJNym3fTHa7AMGpTou2Gmd/DNlHegs9t4ixFONfhdHf2ax0tAZmXW6NvsQw==
X-Received: by 2002:a05:6512:128e:: with SMTP id u14mr14400090lfs.239.1643047375898;
        Mon, 24 Jan 2022 10:02:55 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3c97:: with SMTP id h23ls229190lfv.2.gmail; Mon, 24
 Jan 2022 10:02:55 -0800 (PST)
X-Received: by 2002:a05:6512:3dac:: with SMTP id k44mr7819949lfv.436.1643047375026;
        Mon, 24 Jan 2022 10:02:55 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1643047375; cv=none;
        d=google.com; s=arc-20160816;
        b=SH/02u6ejumqnR7bA9oKud8OYiOrcb1al2LVWIMG4R68tgyvs36Y15SXTNp920ezFS
         sxn10phw7o1WKSnZQ0ALvY1sIEY1HZ9iGmhkdxEjaCBV+99rWKg9v92f1ryzAOaBBlkH
         hrHvbnHpq19AKXX1tGk9y20181ySE8ZvxnYqS+e0FMyT2XbbcjZ9celOd4Cwmf5v+ADm
         yoBkj+dqGb3s46m24kfHFI+y33riiJTn/6yfV39g82g4jO1lz2EgOPvJcdsS58DE+n5o
         NEwjRz+hLWkH9wfgtS+sX9iYSlqaQe3w2Wsytkn1HTiyMueE56ROdPPe2ciTsET0ToKB
         2F6w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=gDlDqsc+3DHa6tPXFigQr9tfOOtGP10nZ0GpFTN28Vg=;
        b=Z+8RHt4kA4imrCVSkG0jG07qRE+vOngDJM3cy/HZRRn8mGxN+3cSHb1ERme7wfp5Vo
         molRLvphht7A2ci0v/vQWAFB6DZ05BW5FY2KTJdOZ3FQtoEioAa+Yhqo+o+pQbN2m6hi
         dHAus5wDT1RGoidDa+jsJsbiEp0TPTmpQ3W7ZWDKD559YnR4JuVvkGTa9h5Gt3j2MMaa
         Zq/+Rr2hSIfqUYvveKLUA8ozphqeIGOfVC33S9JuOOS7/k6D8OzhO+Rl8quOHVpjqXj4
         4tmIHez2/hjMKI5o8ZuhiCBHrfaNiKBsh1bQIh340XocnMeLcY94mTKmodG2f8NB1USj
         tczg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=sJTI5Fax;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out0.migadu.com (out0.migadu.com. [94.23.1.103])
        by gmr-mx.google.com with ESMTPS id e11si359316lfr.7.2022.01.24.10.02.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 24 Jan 2022 10:02:54 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as permitted sender) client-ip=94.23.1.103;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will@kernel.org>,
	Mark Rutland <mark.rutland@arm.com>,
	linux-arm-kernel@lists.infradead.org,
	Peter Collingbourne <pcc@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH v6 01/39] kasan, page_alloc: deduplicate should_skip_kasan_poison
Date: Mon, 24 Jan 2022 19:02:09 +0100
Message-Id: <658b79f5fb305edaf7dc16bc52ea870d3220d4a8.1643047180.git.andreyknvl@google.com>
In-Reply-To: <cover.1643047180.git.andreyknvl@google.com>
References: <cover.1643047180.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=sJTI5Fax;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as
 permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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

From: Andrey Konovalov <andreyknvl@google.com>

Currently, should_skip_kasan_poison() has two definitions: one for when
CONFIG_DEFERRED_STRUCT_PAGE_INIT is enabled, one for when it's not.

Instead of duplicating the checks, add a deferred_pages_enabled()
helper and use it in a single should_skip_kasan_poison() definition.

Also move should_skip_kasan_poison() closer to its caller and clarify
all conditions in the comment.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

---

Changes v2->v3:
- Update patch description.
---
 mm/page_alloc.c | 55 +++++++++++++++++++++++++++++--------------------
 1 file changed, 33 insertions(+), 22 deletions(-)

diff --git a/mm/page_alloc.c b/mm/page_alloc.c
index 3589febc6d31..25d4f9ad3525 100644
--- a/mm/page_alloc.c
+++ b/mm/page_alloc.c
@@ -378,25 +378,9 @@ int page_group_by_mobility_disabled __read_mostly;
  */
 static DEFINE_STATIC_KEY_TRUE(deferred_pages);
 
-/*
- * Calling kasan_poison_pages() only after deferred memory initialization
- * has completed. Poisoning pages during deferred memory init will greatly
- * lengthen the process and cause problem in large memory systems as the
- * deferred pages initialization is done with interrupt disabled.
- *
- * Assuming that there will be no reference to those newly initialized
- * pages before they are ever allocated, this should have no effect on
- * KASAN memory tracking as the poison will be properly inserted at page
- * allocation time. The only corner case is when pages are allocated by
- * on-demand allocation and then freed again before the deferred pages
- * initialization is done, but this is not likely to happen.
- */
-static inline bool should_skip_kasan_poison(struct page *page, fpi_t fpi_flags)
+static inline bool deferred_pages_enabled(void)
 {
-	return static_branch_unlikely(&deferred_pages) ||
-	       (!IS_ENABLED(CONFIG_KASAN_GENERIC) &&
-		(fpi_flags & FPI_SKIP_KASAN_POISON)) ||
-	       PageSkipKASanPoison(page);
+	return static_branch_unlikely(&deferred_pages);
 }
 
 /* Returns true if the struct page for the pfn is uninitialised */
@@ -447,11 +431,9 @@ defer_init(int nid, unsigned long pfn, unsigned long end_pfn)
 	return false;
 }
 #else
-static inline bool should_skip_kasan_poison(struct page *page, fpi_t fpi_flags)
+static inline bool deferred_pages_enabled(void)
 {
-	return (!IS_ENABLED(CONFIG_KASAN_GENERIC) &&
-		(fpi_flags & FPI_SKIP_KASAN_POISON)) ||
-	       PageSkipKASanPoison(page);
+	return false;
 }
 
 static inline bool early_page_uninitialised(unsigned long pfn)
@@ -1271,6 +1253,35 @@ static int free_tail_pages_check(struct page *head_page, struct page *page)
 	return ret;
 }
 
+/*
+ * Skip KASAN memory poisoning when either:
+ *
+ * 1. Deferred memory initialization has not yet completed,
+ *    see the explanation below.
+ * 2. Skipping poisoning is requested via FPI_SKIP_KASAN_POISON,
+ *    see the comment next to it.
+ * 3. Skipping poisoning is requested via __GFP_SKIP_KASAN_POISON,
+ *    see the comment next to it.
+ *
+ * Poisoning pages during deferred memory init will greatly lengthen the
+ * process and cause problem in large memory systems as the deferred pages
+ * initialization is done with interrupt disabled.
+ *
+ * Assuming that there will be no reference to those newly initialized
+ * pages before they are ever allocated, this should have no effect on
+ * KASAN memory tracking as the poison will be properly inserted at page
+ * allocation time. The only corner case is when pages are allocated by
+ * on-demand allocation and then freed again before the deferred pages
+ * initialization is done, but this is not likely to happen.
+ */
+static inline bool should_skip_kasan_poison(struct page *page, fpi_t fpi_flags)
+{
+	return deferred_pages_enabled() ||
+	       (!IS_ENABLED(CONFIG_KASAN_GENERIC) &&
+		(fpi_flags & FPI_SKIP_KASAN_POISON)) ||
+	       PageSkipKASanPoison(page);
+}
+
 static void kernel_init_free_pages(struct page *page, int numpages, bool zero_tags)
 {
 	int i;
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/658b79f5fb305edaf7dc16bc52ea870d3220d4a8.1643047180.git.andreyknvl%40google.com.
