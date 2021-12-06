Return-Path: <kasan-dev+bncBAABBM76XGGQMGQEWQKB4UA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53b.google.com (mail-ed1-x53b.google.com [IPv6:2a00:1450:4864:20::53b])
	by mail.lfdr.de (Postfix) with ESMTPS id 9EA9646AA59
	for <lists+kasan-dev@lfdr.de>; Mon,  6 Dec 2021 22:22:59 +0100 (CET)
Received: by mail-ed1-x53b.google.com with SMTP id w5-20020a05640234c500b003f1b9ab06d2sf9477931edc.13
        for <lists+kasan-dev@lfdr.de>; Mon, 06 Dec 2021 13:22:59 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1638825779; cv=pass;
        d=google.com; s=arc-20160816;
        b=ZDnE6jjSeGN7WcXywo4PUY1b0VzSsV6kYAZe7h9ammDk2JpQQoLaHXqrj+rCELafTf
         CyY4K+exVb0dQbSB6M4a7+k6Whh0CF6Vvdnyu5GheaC65jv3R6o/mQruwEg7PqzI3p0i
         WU01qoKPpito1Yivd1T7x1xo63Xl/Fn5nQvEzC3DHbQX8Cbul0pwgBHp86tl6wNNtGCa
         hMi19VqP9KyfEtBpsKSmtVlyH0JBFuTVOLN0bOez1P+6SwbZGLcuBKvF6+Bk6sGB0TR4
         doXRnUzFVC6u4hJGX5+ITahvkdCos2P48YUd1lmK1JFe9hrCOVhcLPjgXot8VukjKCb1
         dq9g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=1Tr+r51+7xKagJNnDhmm9JaUcX3iXbIcvsmO/qWsQmE=;
        b=WMe6yHG9aCWbq1e2RfghvITW9zNfa+Tmb8ZVp3Bn1wTDoPzYLhnk/GSLWwng2S/rD5
         EkJXL409BDCMRFqjgEoaD5oKklDN5fhw3ZUHwyLU8enrcFpoOACdxXniXpjIpDyh7nQh
         NKVp+JMJ7KO9GcMiWc7xv0XQ6x+DC43oY78es+RAQvBbQkBM6Ue8fSD7YWxz26w+CLJg
         q0RejPsf+TvyTvUCi6m4uCCtjd6oIliQB9+4y3z82UuDbnlH3YtM/2cMACYI0MQrWM7n
         XRHNxG+sPx2ynlmJESbeHB6fhlLz15I/RF4QOxZRw/7ph0pgO4pWNLo5UISzCKXLePZN
         h2Wg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b="AfFY/elQ";
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:267:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=1Tr+r51+7xKagJNnDhmm9JaUcX3iXbIcvsmO/qWsQmE=;
        b=mtw1bfu8VUf6b+eCe1DBpKMOQdC/qAim2sRf2cav5oEM9M3TxlBok74e6rkiT24hmI
         XXWDUnMBSoW8sn0JjAXhuLNd9F/U3qG7KqWNC3Ugf1Ko7IAq2G42qFslYdWm7FwByaiQ
         np0yfQsJzr4iSPnJut9r/+pAPAJ6lvfoadAgYPH9CqlwWH1cBPQiHEzRRL65VZM7NEOH
         SMAIVRsf7+ZGGYJsJpYXvidV7xSLu5AFfYzG4v0GSmufWGAIqEF87Vso3mgY2TjiJwiS
         1qKIx/ikmLBrQFSw0dwp4xAmkR6ODmmzvwZNWwx7qgOuaCpgURpN/sPYutQn/iTrCYmq
         sLnQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=1Tr+r51+7xKagJNnDhmm9JaUcX3iXbIcvsmO/qWsQmE=;
        b=5LhsUUrJS4xVUQ9OenJp94amkz0xhy1y3KiYIwOxfWs/Gz0qBBG3zGLmB+tVBhjcOk
         OUbZ2VK24KdajWpX5PKU2WVb6facSW71KU7GsPgkqIGPrhETu+LXiYov31ZRxl14tyyH
         R/GkTAc76jIz4tEGWRPBBnWELD7cO8w2mq7+5+9wlieZ+UjXdkB/UW4c5oOTJjGwKxCb
         9hRx7O4CAXWcB/PYiPazc56/esMNhf8hNvx8ENftxwwHN5e970CGVeFCOF+QJVFP8oR9
         pCw30WkEAOUWSNQDHXlerwc8ZbF1pEgR0n4fj5DQ6wYVbem2HUda3dJOld6CE7wlDW/H
         VzZg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532SQBmejBB1TTvle3rVtAvO4d+wnVPUtlGpB9fBOSKAueBVvX65
	fKAyCp/0AJgoUeST/EwjMDQ=
X-Google-Smtp-Source: ABdhPJy3p1G120aHz2tfaPmuO2ZRHQXKpYMMbug/MMYTLD/p0i24lSPfTB/gfFS3QIF+ImLM0bmPYg==
X-Received: by 2002:a50:d741:: with SMTP id i1mr2436449edj.37.1638825779421;
        Mon, 06 Dec 2021 13:22:59 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a50:fd09:: with SMTP id i9ls2472815eds.3.gmail; Mon, 06 Dec
 2021 13:22:58 -0800 (PST)
X-Received: by 2002:aa7:dc14:: with SMTP id b20mr2368118edu.133.1638825778634;
        Mon, 06 Dec 2021 13:22:58 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1638825778; cv=none;
        d=google.com; s=arc-20160816;
        b=RCx5HIM7nKw7ySwTh1/xUfiaO0h+XWLKfXrk3eG1kmFicTbhQXsZ5wI6eZ3nGU3rv5
         /WCndu4iIlXJOTu13a6PLk/JyzOS4lsqa12Ut8mCjN3fWjs1NkhGOt4QtVIMH8Kl7aWK
         sXq2Sy46WJ1okVlLM8SIdyBvUUFUXo4n55aUd7/Fns+YBJp9wIP0EwagnPGqoYe+MnoZ
         WsZV+Zs79IvxrjGL6l2lxIF35i1zgiPgvVm+pcCD3rEfSEYulU1EBin7CQ6jDLCj3bP7
         +jBbEHCpd+Qscyzt8kKykBjL3DAw8NgybC2L/M3wX6mQNubvwt0xeEv85f2r4VMvQtzO
         juDg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=4G8h4hgySaJey6iKxW5y4/UhksHPaOzWIIS8r9vmE5w=;
        b=b2p+X4fJxoCJ/cYQAlkuGGpetOog8vs6Y5GDgcmJMbXhA42swmISZjkYGgtbtc7y6i
         owu3el8Ut+ZmMh+ToDRqFxNVuZQis+O51OsYIHmhKs5IaO4KXThZ8a1fZAiIVjbSpjdp
         6+25xNXLVUNJGMeduTJOOtvr7HP1EsnspFujaXH8i+yk00W9ctV0BPdn4w+Kgcs6s9G2
         zN/8tTLzDpJMMkPwkF+Upoz54KhpD2QT+6OO7pkKjX2Y8euPO2A5AuXwL0KB6V8LesNg
         yWMqYhMoP9K/yyTyrk0LkXSdYoLIjyLWgG03iKjQ0mJ7PICsixjZtLlqtX7m0A/gA55+
         onzg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b="AfFY/elQ";
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:267:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out0.migadu.com (out0.migadu.com. [2001:41d0:2:267::])
        by gmr-mx.google.com with ESMTPS id i23si815338edr.1.2021.12.06.13.22.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 06 Dec 2021 13:22:58 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:267:: as permitted sender) client-ip=2001:41d0:2:267::;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Peter Collingbourne <pcc@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	Will Deacon <will@kernel.org>,
	Mark Rutland <mark.rutland@arm.com>,
	linux-arm-kernel@lists.infradead.org,
	Evgenii Stepanov <eugenis@google.com>,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH v2 01/34] kasan, page_alloc: deduplicate should_skip_kasan_poison
Date: Mon,  6 Dec 2021 22:22:05 +0100
Message-Id: <9644e588df352734bb5c166caac2d440052cd04f.1638825394.git.andreyknvl@google.com>
In-Reply-To: <cover.1638825394.git.andreyknvl@google.com>
References: <cover.1638825394.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b="AfFY/elQ";       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:2:267:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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
 mm/page_alloc.c | 55 +++++++++++++++++++++++++++++--------------------
 1 file changed, 33 insertions(+), 22 deletions(-)

diff --git a/mm/page_alloc.c b/mm/page_alloc.c
index c5952749ad40..c99566a3b67e 100644
--- a/mm/page_alloc.c
+++ b/mm/page_alloc.c
@@ -375,25 +375,9 @@ int page_group_by_mobility_disabled __read_mostly;
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
@@ -444,11 +428,9 @@ defer_init(int nid, unsigned long pfn, unsigned long end_pfn)
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
@@ -1258,6 +1240,35 @@ static int free_tail_pages_check(struct page *head_page, struct page *page)
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/9644e588df352734bb5c166caac2d440052cd04f.1638825394.git.andreyknvl%40google.com.
