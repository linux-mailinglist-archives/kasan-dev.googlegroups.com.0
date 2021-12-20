Return-Path: <kasan-dev+bncBAABBJPZQOHAMGQEMK5JU3A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x239.google.com (mail-lj1-x239.google.com [IPv6:2a00:1450:4864:20::239])
	by mail.lfdr.de (Postfix) with ESMTPS id 8FE2147B56D
	for <lists+kasan-dev@lfdr.de>; Mon, 20 Dec 2021 22:59:02 +0100 (CET)
Received: by mail-lj1-x239.google.com with SMTP id t25-20020a2e8e79000000b0021b5c659213sf1870855ljk.10
        for <lists+kasan-dev@lfdr.de>; Mon, 20 Dec 2021 13:59:02 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1640037542; cv=pass;
        d=google.com; s=arc-20160816;
        b=t7Z6EMP0h4OcKC07VhSrshs14qCP7WwSIEmMqCjtbwe3H7CUmy4guf3yS4NKKbBMuA
         H1YJXJDphZRzxf+988BRKbN7PiOQKexB2B/j1ABLqLDXHGyelBwLzr5QXFyMV+9kDAg7
         /LfGNcSjf6APpgqi8HK8t0kk8tzPiWllJ1bB0fKLAQ2F5pVs91Ac02kOV2rLUJmca/Ei
         QodwpUaWRaPoNbBLfa48A3nwXlzPbfjWB2EhmiYkN2m3ycWZZdB1MSQ7uq2XboU2QJXP
         4hYQw+CGI3sXEfzaJRegndkwtKku4ZS/8hCPQoTDtNhGtYUOCsANS4yOEy8EoKNvz99G
         VvlQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=HIbRdLRuNjlPEEWPpgN6VpOGiifYUh9KKBQWrvJbQXs=;
        b=ZaPHzhLLHIvY8CduNgxFtFCXfAp1Tikiz9mBniBM4J9jjMdVc2l7+GAA5s5SdxfEpG
         hBeTAiYf/mN9OmFTA2+s5fraTlDAZ+3CCg4nMAKGFwFzyI40oa6/IIkRbWHbAffZjJS1
         T8SXdkIV1ELwiOCy/UQ4S43/K5fSQ3lt/ppDwkxhvAWHsGTz300MsMx6aeiNBMbSdTPc
         uvno1KmVvIWpvfkxiFR6uSkBZa3h+t0RF2sMygBe530Q/kaxc8NJKXMdzbPrRTYEWnu2
         SPJImeGou6BfvdGu1VY1u57TDFs3HG4UfmOu90rJV25kt+fBDpXJTmNwFY3EB0UqOxwJ
         6W6A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=fgp95qjO;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=HIbRdLRuNjlPEEWPpgN6VpOGiifYUh9KKBQWrvJbQXs=;
        b=irTttJLL0/G5JXOgFLxQlVnhvb8AFDZXDwIXIK38cUwtE1WeAPBBSv0ScOb0LnSKLj
         dmA5Mb1b9zXSj+0jUUfWigosUN31Jyob5oG/YIlnIn+iWs8JCG+apQMSJ/Y+V5ua03SB
         eBnbkU0ga6QG4X3oMHqK3S43NjX4kkeHG7qNOzTJ/utp52workOtw2WcNAFzPMAD1NpY
         HEj/QCQkZI+OWEKW4vNTBv+poSYKwI2QdMR7N3ZWvxGSBCcVwjKZRfKhkhiAI7BEhWJA
         bEVkXBd/Y4Yeoxfbj38pMMW/9KcxrJATyXCYbqAWuRsyzWntU0HbIQzNWF4VHxe5Jxsr
         FWkQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=HIbRdLRuNjlPEEWPpgN6VpOGiifYUh9KKBQWrvJbQXs=;
        b=4r2AAQNI9eG71JBP0v+JNT7C39KRJDdjRt21e4Cz1KSY7B3bya2IG6Se/WM8KCex55
         TBplSMedkR1ktxNIZzy+P/cSZWndvP004FfquvPRi3tnblrJ38N3V1E6ev7Qr4+m1NKV
         zGlqjQr983bQofUm+L1H2CalkUYd8IR8XAYKxcCHEeAgeqkduvxl73+/LG5wBvaqlabB
         gqiSN9yYvqlu6oJDS2Rh7/jjby83lYhjQXdKvmWSbhXlHtPX5udkZpHvvNe6MB4PZf7b
         VXTjeGjF5eo+uCQhCxOp1Heb88GZmo5c6BvnmVrlme9MixuehBfxHA49RS61gS9QdTzA
         sqwA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530k2Ki//1DNEuMG2+Xe6kiVfdV8V7m9ktvvTRZKchk8G+mAI4N7
	bi/k0ca8X01TzW9MuAJ60kw=
X-Google-Smtp-Source: ABdhPJxc/PGICbE2dQ7EgT5lZde0lee2QRVNQg0Hnqv8yFEVFxAPf5JiyfmGlw1kEc4wBT9DQzjApg==
X-Received: by 2002:a2e:720b:: with SMTP id n11mr47795ljc.351.1640037541971;
        Mon, 20 Dec 2021 13:59:01 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:8e74:: with SMTP id t20ls2683524ljk.11.gmail; Mon, 20
 Dec 2021 13:59:01 -0800 (PST)
X-Received: by 2002:a2e:9081:: with SMTP id l1mr45003ljg.399.1640037541164;
        Mon, 20 Dec 2021 13:59:01 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1640037541; cv=none;
        d=google.com; s=arc-20160816;
        b=u34JQtB9/VoSkEbkg/QEJIqL0z1DLX+bwQfvc6ZXg0G/c5Lkgq1vmr+jDloLERH5mJ
         n20VsxxzpoowDDrV9IG95WxlkANbqsMufT+vqI6CMBCF7Qk4QBrm5rWb4IsCOWYLqgme
         cIFg5nBxBm7I3DcSwMCyIrI8Gjqde9PubOFXloPXEYpugMYq5syKyroJX9LvkFmDNOYj
         +l6FGCNq09t3zLvi4vSBqTPYIOO7dhmhk+SKtztUNc0eMOGu9tTK9S0A1o5Kv9mbt/K7
         e7xrbBJvjG7uOXGJDwalXpbotaoabCIkU2eVbgRCHI9M+eMv5fcfUJyZgJw6F04gZKOH
         4BTw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=HTPWk4VEgIiC15H1k53BSSNevm2/MKWkVZ7PL0Pz+og=;
        b=oVina7+PL4/CV7ebb73r0GnmkBRyQ6d/XgRuV63NxZ9deDgeijN9Md2OkmbmqXvtNo
         S2uEt3UToY0M7lGWKcySul5mfhU9gRE/B6r4BWfGQlsM1msVs1D7rsRoKdrE7z3wwzOY
         aOQ0fMPlx0+Wn5EZN/MKvk8yCfzED1i2OeGoMqqkmcigHt/g2MJtP2eNy5vT4DSuu8Ie
         ipgJ7Fp/I6cWunEjBnIUdPrIBVWPw2+9ryiiqRiNhO1RUMENOeSdF2/w+7nUxwZWWbQS
         TwEXioP1os5qiOTb+6UEZVEokaQMXZui1mKsdzT+edsXLPyP60rHglDIFJBIXOUOuyK6
         fMLw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=fgp95qjO;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out2.migadu.com (out2.migadu.com. [2001:41d0:2:aacc::])
        by gmr-mx.google.com with ESMTPS id f11si970553lfv.6.2021.12.20.13.59.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 20 Dec 2021 13:59:01 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) client-ip=2001:41d0:2:aacc::;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
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
Subject: [PATCH mm v4 01/39] kasan, page_alloc: deduplicate should_skip_kasan_poison
Date: Mon, 20 Dec 2021 22:58:16 +0100
Message-Id: <157f8aec0be7f54666b9cc433a0c0450416b68b4.1640036051.git.andreyknvl@google.com>
In-Reply-To: <cover.1640036051.git.andreyknvl@google.com>
References: <cover.1640036051.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=fgp95qjO;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
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

Changes v2->v3:
- Update patch description.
---
 mm/page_alloc.c | 55 +++++++++++++++++++++++++++++--------------------
 1 file changed, 33 insertions(+), 22 deletions(-)

diff --git a/mm/page_alloc.c b/mm/page_alloc.c
index edfd6c81af82..f0bcecac19cd 100644
--- a/mm/page_alloc.c
+++ b/mm/page_alloc.c
@@ -377,25 +377,9 @@ int page_group_by_mobility_disabled __read_mostly;
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
@@ -446,11 +430,9 @@ defer_init(int nid, unsigned long pfn, unsigned long end_pfn)
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
@@ -1270,6 +1252,35 @@ static int free_tail_pages_check(struct page *head_page, struct page *page)
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/157f8aec0be7f54666b9cc433a0c0450416b68b4.1640036051.git.andreyknvl%40google.com.
