Return-Path: <kasan-dev+bncBAABBM4JXCHAMGQESXZ3MAI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x339.google.com (mail-wm1-x339.google.com [IPv6:2a00:1450:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id 251C1481F7D
	for <lists+kasan-dev@lfdr.de>; Thu, 30 Dec 2021 20:12:52 +0100 (CET)
Received: by mail-wm1-x339.google.com with SMTP id j207-20020a1c23d8000000b00345b181302esf13791767wmj.1
        for <lists+kasan-dev@lfdr.de>; Thu, 30 Dec 2021 11:12:52 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1640891572; cv=pass;
        d=google.com; s=arc-20160816;
        b=o6OBATw8SVU/b33Hd1DDFy/nO0eLElJ4Lmd81Kliz5J9aGIsZO5FY/eip8UqVXJ9Gx
         FztRZcMh40QdJL6Y4hysVrKEKhC2OgN8q91Xi69T2jQ+4B66R0f4KALkXUeYlhCy+MMI
         QgAcFE4oVv/E+24nTiSRDKDNiW0LptIQWiv5RsIYhLRPFQwf4EkzaXnwZHYCkWWe9z0Y
         +/H3m3yxvttOi5Ix75OEx+Yec4OcZqAYR2mEXGhDRSfEUoVdcxzGrgErPqKYXgPUB9zT
         fetRRt/QcgAPeLvzjzjPEo8P9AmyMoy3/Fbi9BVeH6NEGgnmfJybtSsb2v/tC7ow5a4p
         M3bQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=9APBl91cRzVdUF0J3HQCVKaG6fuZ3Gwl5EPB7dmhMBE=;
        b=xCcgHhHsb4X6daPsziTrMkHsCxOu748lX4wdwfP/WnYa0inni+w6lhlpdwRCx/Ryy8
         rXJmAOs/YV42ox2vFOuie0IEmqnv1Nl9rn1q9wRbrtnE4o2TUVl2FDrkmgDQNpTjrmId
         XqlFT66qISfs0ttotfXNlLwXcR3rQm8068ZwgP2HGSXDnlAOzJP0dDHayxi5jksH4FI4
         u6c/t3o45g1zoZwondTY7baEohT4OGsE/7owhxZSLiZW7ZbMzFq1CxaiwwkE01yqJc6g
         AEagc7wkU+CeLR2oBb5DtzjMb6BpfVutE3XMNLCYzksEAOFkD83/QUwYmsdV6XMyA5hk
         yBQg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b="pw4B/mv+";
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=9APBl91cRzVdUF0J3HQCVKaG6fuZ3Gwl5EPB7dmhMBE=;
        b=BvHz3qYHFyWnVJB6TTtmJoYhe1JcXh8ak6qnA7oED14RE0kIwesMgos+YW3qktFn5S
         VyPYeVPVLyDet0PDADF1/Ek3nIp+9xRvoqoWGE2EphieUP5Vuv1y53byX6UOTmZfZ3ln
         +aXxf7lh05u3/f8zoN3pVvqtDZy0Jw21jrtFndTF4/7Vp6cJLVj4fcnMM7WUAZEdnBjZ
         caF/9Fnl6ZIShKHUy8mxJOczRwlv5kRlpt8Yfql5i578lLiDxa52kgwxmngsCZdGb6yx
         fNwPt40VIzYnw/SyGJFFF18pUsNzUZnJaYBXoAVoAk5Ca2VsRKtpeWYL/PFy39ec0QEh
         0fJQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=9APBl91cRzVdUF0J3HQCVKaG6fuZ3Gwl5EPB7dmhMBE=;
        b=L9jvOSNAPGRuTpXmVss59DSKCVzOln2F7JJuZvYeKvZ8t6ivh+5Jq2BWwepg2jKCTk
         RZ46IycG+ZDNId5CXpeGvCHb1M2Z+W5HEshLck0jSjwY+NBfrZ9Vu5nRB/ZVh2Gr4nZD
         IMpfLITE9IWQ3ZLTINpyZPHkzhh7DAMIxq1L68p/Ct8rozwP7wJjCM7z9zmL8zPsLDff
         yXmRnnwb8s2N18InhoNGEKnPvGf4BARzXt2ccS0G6NGyLojs0SKVWuYioOzrPnXKSdid
         9yF7FN20hAzH4HEj4M3/jXSR6OHRPIjmp6dmnEbb7a+X/LsGuqJeac/8ZC4yUTdocP9S
         ohYg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533oXWz6KqvR7LKntpRwlPw+jN6NWOvBiMvyqbzc09VG+dxxGNet
	+azNpuzTEVrA6Ej0ECdEQjQ=
X-Google-Smtp-Source: ABdhPJwS/wWoyg9qdbZHtj4h8t96+RBaw6zVpC8OgEl0caRFUBnhAHras8hLcBQaG4d+h7ZCkitmxQ==
X-Received: by 2002:a05:600c:1549:: with SMTP id f9mr26873971wmg.112.1640891571796;
        Thu, 30 Dec 2021 11:12:51 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:5082:: with SMTP id a2ls298038wrt.1.gmail; Thu, 30 Dec
 2021 11:12:51 -0800 (PST)
X-Received: by 2002:adf:a399:: with SMTP id l25mr25940353wrb.51.1640891571214;
        Thu, 30 Dec 2021 11:12:51 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1640891571; cv=none;
        d=google.com; s=arc-20160816;
        b=fqHTv9099G6K5p7WZk/3hHKbAX65eIkHVZImsUMmEnyZrmgh/XYjTfa2XsS+jvfdfm
         TN4s/m1p0gPPwT061m3nXwaT1r/rkLscfexSC4aT3t7KG0DrJvIzi488YC2YwPm29vRh
         vsudkDxNIQPIKWZUG3LkssFXL68slHwiCB5LYrSWIfcijTZx+JEmReHI/2ziKwO3XB+G
         x0oWGstIdxaVKQvHXesKUS13f47TrRxz1c1L2Pm+HyzgipJRQKHtZG1+ZmIR61vp+rRt
         6GmAfnxJaHkOo7r62WmcFMYDx6wkMv5rFFCP8+bhqTwn2+dnLr9nkLocvtH2la1GBXBm
         e3Pg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=xnqKCORSMEQ47RSDW3t8iqQ4D0wOklW1skdJyr8OyH0=;
        b=0dHmerA5x0LNolfEODXEFvHgfFfJL+NQVCf/H6cBEZmXhed/LSCuFzVUsU+IQjGNqP
         /kow4F9pWyDcc239sGncKUFrQ86828O7wZDb5LbN5ZVqGTn/ZzGAwUAKuQNXmOM47AQY
         +XuLXKKOHIncExiAxwxtpB4UeH/pULVRkROiqUW5YyeJ9f8djQxdGh7nN/HaKywcpJGB
         OzLdNZUBlNeHI6uy/nS7YiqYleqhREsvxS0RvwfK6QZaTg+YxCH3jzLDYdoeTlhCc2Os
         A/6JplEWJa/UrkQPKl5h3hbZr2ifv5KuTVhtFKxLBCKNnAJoAk2fLnq9OnyEQBifMU3e
         N/nA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b="pw4B/mv+";
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out0.migadu.com (out0.migadu.com. [94.23.1.103])
        by gmr-mx.google.com with ESMTPS id h15si1116874wrv.0.2021.12.30.11.12.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Thu, 30 Dec 2021 11:12:51 -0800 (PST)
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
Subject: [PATCH mm v5 06/39] kasan: drop skip_kasan_poison variable in free_pages_prepare
Date: Thu, 30 Dec 2021 20:12:08 +0100
Message-Id: <0f86c00ea72f31ddd0c48eb5e7bc7adfb44cce73.1640891329.git.andreyknvl@google.com>
In-Reply-To: <cover.1640891329.git.andreyknvl@google.com>
References: <cover.1640891329.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b="pw4B/mv+";       spf=pass
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

skip_kasan_poison is only used in a single place.
Call should_skip_kasan_poison() directly for simplicity.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Suggested-by: Marco Elver <elver@google.com>

---

Changes v1->v2:
- Add this patch.
---
 mm/page_alloc.c | 3 +--
 1 file changed, 1 insertion(+), 2 deletions(-)

diff --git a/mm/page_alloc.c b/mm/page_alloc.c
index 37e121ff99b1..2dcfcaada9c6 100644
--- a/mm/page_alloc.c
+++ b/mm/page_alloc.c
@@ -1301,7 +1301,6 @@ static __always_inline bool free_pages_prepare(struct page *page,
 			unsigned int order, bool check_free, fpi_t fpi_flags)
 {
 	int bad = 0;
-	bool skip_kasan_poison = should_skip_kasan_poison(page, fpi_flags);
 	bool init = want_init_on_free();
 
 	VM_BUG_ON_PAGE(PageTail(page), page);
@@ -1375,7 +1374,7 @@ static __always_inline bool free_pages_prepare(struct page *page,
 	 * With hardware tag-based KASAN, memory tags must be set before the
 	 * page becomes unavailable via debug_pagealloc or arch_free_page.
 	 */
-	if (!skip_kasan_poison) {
+	if (!should_skip_kasan_poison(page, fpi_flags)) {
 		kasan_poison_pages(page, order, init);
 
 		/* Memory is already initialized if KASAN did it internally. */
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/0f86c00ea72f31ddd0c48eb5e7bc7adfb44cce73.1640891329.git.andreyknvl%40google.com.
