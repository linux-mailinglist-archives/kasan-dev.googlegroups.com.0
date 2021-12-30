Return-Path: <kasan-dev+bncBAABBMEJXCHAMGQE6GB62SI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23b.google.com (mail-lj1-x23b.google.com [IPv6:2a00:1450:4864:20::23b])
	by mail.lfdr.de (Postfix) with ESMTPS id 432A2481F77
	for <lists+kasan-dev@lfdr.de>; Thu, 30 Dec 2021 20:12:49 +0100 (CET)
Received: by mail-lj1-x23b.google.com with SMTP id e7-20020a05651c090700b0022d70efe931sf8496294ljq.10
        for <lists+kasan-dev@lfdr.de>; Thu, 30 Dec 2021 11:12:49 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1640891568; cv=pass;
        d=google.com; s=arc-20160816;
        b=E7PVEstHgcLuFAJVYrhv478zdXSCSsw/GOE5IMjhYnwxuUwvhCJoWHH+Eku3jdZMCi
         fhXyuzIW8rCqBT+ptaR/9335tjhOWK+TGQM+x/kpq2ByFUSPLDG1t0qifuljd2p8nLPM
         Jei9RBCrQ15BNXBjZaN9d1uudmrmwzS8rKL3J4BSQR4lBHgYvdAoXkQYyAUxVIMC0qZ6
         iZQM0lrNdmLuR03610LzJEB/epaTfC6XOIqTXRFaeAAvKvokMJ7Qj32OFt7Fuu5QwFK9
         oYUrGinSG4rfq8lKCb5Ixr4bUTzkPZ9vb7fbtkCK4+NgetiyVlBy2LtJFq1tMutlHxeY
         s+BA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=Dtq4lAgkMt1Z2pBinuJclWxBoFU/ekhec/z9QW4bFbE=;
        b=ixdwXTbPLSh2RKa8wnzvzc4LYyde3BDK5BGm+OdpZGEDIWjGU9Fw5GZpKRtCNRGqkv
         l2CuSr8SOfhYnYO9X1zuyG0lcnDnJMbx75H+CBoD3Pq3kFt0kXg62unNmtHtKKzm0r7d
         KpI9lAH6RoOHWr3B34w1+XZp6eVSzFiz6TjMVi/Z9oqQg3yTyHEPRgGiz/uUoLngfZtO
         89e1KyFQOAfTMgbkUVudlWO0XTMxbmKzEtXIIpwNV8PGeEMaZeP5gAiHiuHVCm8N9IiQ
         gCGGWi9BFCSah0AFfffgeVNVnN0Z6cSA2wdpyZOg6L9LS5daAN24RIWv8D3fxmiluYM/
         /YIg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b="wy2Y/R4N";
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Dtq4lAgkMt1Z2pBinuJclWxBoFU/ekhec/z9QW4bFbE=;
        b=jr7QAod0wwt78JZl9iA9eTnJ1NmXqMwBJ85YemrTNgVBhpLCX0rS6YmsD/OCNbBcqy
         S+UCtfTCAzDLcwvB7q7YNYLZcoztMy4tZWAor3fjl/D9r6HGpxHaWvo2ljVZmcH/EX9r
         LFGSB+GVwGjj1nPWJKrIsVeOUOmj7KGPPJjPbLsTXA0hIHaJEvUx/ajC4ksY8J5ekn00
         k8d1Ffu5nctMLom4+iIKMf6BH+yANm5FKA9p0R6Z+tB9zlfNNbMVHFSmWvGxsevvCRg+
         qxHJYs9QjHF+znfKtKUwDh3Yucfvlh1ODs84cfA/XruSao/s05a5Hc2xoMpJHYsAQ7yc
         4EBQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Dtq4lAgkMt1Z2pBinuJclWxBoFU/ekhec/z9QW4bFbE=;
        b=tmuCmZ1rtCpBtJoTyOTzEqPBeThU45NhtFGF0dmhOemIfs8j4NH31ukE0XCdkcYIgO
         CGZt5fmOcWBOswQjpGfgwqaCwR1ELYStLoHd+Aw045znEjr453IBgbaOt67UOEuHADdR
         n0n1+dua7HfEPIYh61hmf4IZc1L1CImx5Zog8YSRslaGWnpXOBDDH2mYFI8ZS8Hfyc43
         d57OfcQwFGvS6YqS+EAWQlBxP65A13igkPELOdziSeM/jxIo6Iwz4iu938WCHce2oHis
         DUqw8ephQPOUMc4npt0iMS6ST6Oqhhnl19tH1pCBPU7SoxVLRack5q+QgK9MD056YqFK
         yPFA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532XfNYVFxVBmexgYARJ8r91Api7SPzYd/UK/FOiIb6XRzUNaNo8
	/iQILKK196AIyeXAEEF7OV0=
X-Google-Smtp-Source: ABdhPJy67eQNEjzzo4L7yBcsS5pywnnclAz5XPLa7eRrqbctzNTl8gWwoaWba6Rbuj081qzuCO7WgQ==
X-Received: by 2002:a05:651c:12c7:: with SMTP id 7mr9543354lje.432.1640891568749;
        Thu, 30 Dec 2021 11:12:48 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:5304:: with SMTP id c4ls2235899lfh.3.gmail; Thu, 30 Dec
 2021 11:12:48 -0800 (PST)
X-Received: by 2002:a05:6512:22ca:: with SMTP id g10mr27766178lfu.244.1640891567948;
        Thu, 30 Dec 2021 11:12:47 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1640891567; cv=none;
        d=google.com; s=arc-20160816;
        b=WM0eIDL0cAAzJcB7hrVUdt2JACITXHD3GpmXDWBkhYdE2SAJV1/+JYVEj8Pr+zmHbs
         bv+PB/Ub/cWNtMM8GGqJhkkv6uSKBwJ+HkeiY5VPwiN5ytPF9KQjgqCOuax6Hd49tg7Q
         JOo0xQMCik2IAGj5b52BYo1QEMei1BcSYG73L+ikSX7m1B80aMImdnS4eeJKceebEFIG
         azlv0hWvSBEgrbDdVj+eBhWY24ApZkprgGXQTzJnFQ2GFS/cHq81DyUaAwiiy60CzJKQ
         w9GtW9gyWAYyCpSw8jhb2ezOwcsZGJlwPETGoc6FYK49z5Y/NDqImV77R9OzTZ16SnRV
         016A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=VpIEA2ez9QPMzuCI87VHilXXhkqy76AAMsuBz6cCsL4=;
        b=RG2QiaZuf2pTslaWL56mlffHu5c4Kzah08ItmXv+znlBH7doOG7j5me89o5IK9ycIT
         gD/3Dw7+KzWqCIPd/WdaZxbfot2qMdxCwQ8sKNRAEzI4MMbEGp4Yy5b9q4MSxjz+GvHN
         2hmQAmlddkCy7YhXtQWZbFOyKQf+e04na93lp22O5iNbDtWBcAzU1LlnQYrrxvAul21o
         L/77LUN9nExrx78D/QSpGtF+9xImGLQpeYCyxqEM42tNGOXz+yLGGBcxBCpiYiYZiVQ9
         dyAJO4bReV8Oe+je+dignrdJD8F/+DOqMzk9Vb3PCHWujNRJa/oGmWJ4pDMwNAsdzAEb
         AC6Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b="wy2Y/R4N";
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out0.migadu.com (out0.migadu.com. [94.23.1.103])
        by gmr-mx.google.com with ESMTPS id v76si976463lfa.6.2021.12.30.11.12.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Thu, 30 Dec 2021 11:12:47 -0800 (PST)
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
Subject: [PATCH mm v5 01/39] kasan, page_alloc: deduplicate should_skip_kasan_poison
Date: Thu, 30 Dec 2021 20:12:03 +0100
Message-Id: <137aca7e7c055f2f7bc678afb86f347aec454a4a.1640891329.git.andreyknvl@google.com>
In-Reply-To: <cover.1640891329.git.andreyknvl@google.com>
References: <cover.1640891329.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b="wy2Y/R4N";       spf=pass
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
index b5d62e1c8d81..8ecc715a3614 100644
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/137aca7e7c055f2f7bc678afb86f347aec454a4a.1640891329.git.andreyknvl%40google.com.
