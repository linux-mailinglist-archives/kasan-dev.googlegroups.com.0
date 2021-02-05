Return-Path: <kasan-dev+bncBDX4HWEMTEBRBQUD62AAMGQEXPIQYTA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23c.google.com (mail-lj1-x23c.google.com [IPv6:2a00:1450:4864:20::23c])
	by mail.lfdr.de (Postfix) with ESMTPS id 7F51D310EC1
	for <lists+kasan-dev@lfdr.de>; Fri,  5 Feb 2021 18:34:59 +0100 (CET)
Received: by mail-lj1-x23c.google.com with SMTP id r20sf5852826ljg.21
        for <lists+kasan-dev@lfdr.de>; Fri, 05 Feb 2021 09:34:59 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1612546499; cv=pass;
        d=google.com; s=arc-20160816;
        b=n0cSm+WDmzZm/9DOCxGBoCUesJxxux7kIYVy6MflSRuNiBdDmoKMj4+/JDyxGVhcc/
         PPEn52pSFUNR/HGmhM0er+uLraK/ce5NK5uET2NRpFPx9ii4zmLlJ1O/yc3occUrK1/e
         9IBv40DwnCJQla2A6Aw7zjBTS9Xbky+s2nVZ1UK1bj4Q3ZIqRXk12C4bpkHC6FZm7CxE
         z6J7KzUA34Q8mALitMKwDJRZikj4oy3Z/glhDiFDg4KTwIhU9ZMElfHo9WsXqhEndNk2
         xUfOzzpHDjPwz10/Fov47IzCVb7fVBC35ovS0TPipqisEOF/YFgXXd3xqxCOo7aQGANB
         u1RQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=oBBdw4aPgKZRvzlVA7ExK4jQCg+++3JGdXNzYaosTII=;
        b=wqmHR29geIkiCjYXphQ6dcdTB/28pv1F51+CIuRLuo8lowST1IiQQyZKzWlQTz7PPx
         AZ+5DSp2YM/N8Z3G61r3Cds0COXikGoXRnAt+VMOI/asc77uB70XM0Bv/ibav10wl6RU
         Nr76MFUsBOLZgatgrUPvRGJEBrFGSyhAT25hTZopQAEWhws8+WnWbuAQP5jr6vMhpsEO
         RrOc0GBnj6IE811JDuixkuRPSNQcMIVMNsimOd2zJQNt9GEkyUWobyYhXEBFGjLarVpX
         EmuTkygiJW+D4rvCQ8FL84rj3J/0wEd6Fv4Z6JOeeLg+mDQmJuT4jBAf09BaDkcshHqW
         ywTg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=EooVbzbf;
       spf=pass (google.com: domain of 3wyedyaokcuierhvi2orzpksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3wYEdYAoKCUIerhvi2orzpksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=oBBdw4aPgKZRvzlVA7ExK4jQCg+++3JGdXNzYaosTII=;
        b=fofX+lzqh4gGZMF7ZXhsl1urk5M8qllu3jwcyf/ewBElUhEUjg27OReS1f1ELwafIR
         pEBIGXMMA2SKK2XX79YtbdKuQ424P8L44HLWU5w1IxOq7WNL9OV3kTnl0GehW4s3/8GX
         T4Ku71uiszQIoLYRQKg+0q2lGrkr+/kw3gzvx/L2MF2I1ZwhfzPmICffjArDLV25oNaQ
         eGAZOsopapTcLLCcjJtXxDSlT9g3rHflnfiPyJCxVEch/wg1t4MF35mUjeFOuVlF+KPR
         GnbtCOtf9z4dOpfPcv0Wz8rv2apVmwJPKsuln9QVespqDZh2ZNaqVH2p8nINSB8GbZaG
         XGKQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=oBBdw4aPgKZRvzlVA7ExK4jQCg+++3JGdXNzYaosTII=;
        b=oXo1FG3Cl2gh3y3hX8zZcOjdYOke1+9ZufABMLXG2M+98z6KiDuXIP7BitjtoVxddf
         1P2bSHn4MJ4pd+qzGCGreNeqf3oApPjAaUNzdRyfiRGMrrm/Xbvs8GPp+AugfPOZ6qL9
         eXkTmBsh+aNkuZTB+8aHBQ4aXc4c5Ascz7F8O/Ba2hUcqUyu+HYI4T8v8Q/AOI7LtDou
         Oz1rrmYW3HZffFoXkexXtmCsXEuuFqy0sfzvZoiZh7FG6+STnnOhXVleRSWEDN4uXZpQ
         wFjGQFhubYREdBlCDdVt5j0vqYjRm2X/+ZL9fqIXqzTdw5K4SaV0VREbr891TcomBt/i
         w8OQ==
X-Gm-Message-State: AOAM530rSqT0sxJ7LwRMc0I5Btn81OvPTOnxUDhx0m4nTaFrWL3uAdek
	m3Sb/kklV5xE4uwDWLB361U=
X-Google-Smtp-Source: ABdhPJwJOx5lN2Yh3tEh4UM5XvncfRkpht+cykqbq6ezFgxgK0z83bPqHgsmxZRhHLIE+ibvBinmhQ==
X-Received: by 2002:ac2:5055:: with SMTP id a21mr3127069lfm.528.1612546499077;
        Fri, 05 Feb 2021 09:34:59 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:4adc:: with SMTP id m28ls172292lfp.0.gmail; Fri, 05 Feb
 2021 09:34:58 -0800 (PST)
X-Received: by 2002:a19:3849:: with SMTP id d9mr2858251lfj.157.1612546498107;
        Fri, 05 Feb 2021 09:34:58 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1612546498; cv=none;
        d=google.com; s=arc-20160816;
        b=Levcd3qZKAZ6URmcARN+882JVY1nLYIKskp6mB0dWGvV8z3zcjRzOWkiX+jvdtzJXq
         XI5IfGOI9VzFv9i/D8Ig9QLWQwLBS+Jp+mXp0kDZDw++qjZCgOCrEe/td8SOotAKNw2Y
         yRl0ufNeeKXwPxPFmHkUcrR6lPsDjomwHY6Vhyvhmh4s2ciqe1U9LE275WQNugR2syRR
         jAZJnZNksIYLzvYEawteqJzxg2JhM3mr4l3CJlO8u9BOSm5NL4BzQH1al/jwAl5A846g
         hRqGmmeV7H4C5K+a7CaxSb6mWBC/VkBlMsizMkVN8nCxk8dj4LUrHDS1hsqm8kw11uY5
         UuUg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=tljlSxhBzcxqidAVSdVdhM6oUJ+nJ3d1xitEmX2Ppf0=;
        b=ZMmUiP1eK8Am0RJBYF4pgzkd+enOYqG2VuIOdT+SRX5vQVLYnIufXFNL/NPqK3eTSg
         TeXmJFygMsr3RyU66dJNojmCHwZvgOrGiYsHiJYAETaSe/WWXTSi/i8XmPhuuED22vb9
         D/6aLSX1ZiwyfLKSAq8+n3mIxw64J/oo4otNvF4iQcsc0fyyu3TQvHegO5a86Su/CCK6
         kMIis2GDIVCv/xzXaNu9Oc18GDgcfntBsQU8eJLcwjhWqZgf3EMC6tVNg1ih0uX5sHJ8
         mF2/yVNYUz0BFJW6G0GTG4nMqUEw67y8EyvEJRwmQdvg8I4F5zteiRTMqA+is2pC0ePV
         ZcIw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=EooVbzbf;
       spf=pass (google.com: domain of 3wyedyaokcuierhvi2orzpksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3wYEdYAoKCUIerhvi2orzpksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x44a.google.com (mail-wr1-x44a.google.com. [2a00:1450:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id c20si428966lff.11.2021.02.05.09.34.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 05 Feb 2021 09:34:58 -0800 (PST)
Received-SPF: pass (google.com: domain of 3wyedyaokcuierhvi2orzpksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) client-ip=2a00:1450:4864:20::44a;
Received: by mail-wr1-x44a.google.com with SMTP id l10so5718202wry.16
        for <kasan-dev@googlegroups.com>; Fri, 05 Feb 2021 09:34:58 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:edb8:b79c:2e20:e531])
 (user=andreyknvl job=sendgmr) by 2002:a5d:53c3:: with SMTP id
 a3mr6032044wrw.43.1612546497774; Fri, 05 Feb 2021 09:34:57 -0800 (PST)
Date: Fri,  5 Feb 2021 18:34:37 +0100
In-Reply-To: <cover.1612546384.git.andreyknvl@google.com>
Message-Id: <33dee5aac0e550ad7f8e26f590c9b02c6129b4a3.1612546384.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1612546384.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.30.0.365.g02bc693789-goog
Subject: [PATCH v3 mm 03/13] kasan: optimize large kmalloc poisoning
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrew Morton <akpm@linux-foundation.org>, Catalin Marinas <catalin.marinas@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>
Cc: Will Deacon <will.deacon@arm.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Peter Collingbourne <pcc@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=EooVbzbf;       spf=pass
 (google.com: domain of 3wyedyaokcuierhvi2orzpksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3wYEdYAoKCUIerhvi2orzpksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--andreyknvl.bounces.google.com;
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

Similarly to kasan_kmalloc(), kasan_kmalloc_large() doesn't need
to unpoison the object as it as already unpoisoned by alloc_pages()
(or by ksize() for krealloc()).

This patch changes kasan_kmalloc_large() to only poison the redzone.

Reviewed-by: Marco Elver <elver@google.com>
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 mm/kasan/common.c | 20 +++++++++++++++-----
 1 file changed, 15 insertions(+), 5 deletions(-)

diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index 00edbc3eb32e..f2a6bae13053 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -494,7 +494,6 @@ EXPORT_SYMBOL(__kasan_kmalloc);
 void * __must_check __kasan_kmalloc_large(const void *ptr, size_t size,
 						gfp_t flags)
 {
-	struct page *page;
 	unsigned long redzone_start;
 	unsigned long redzone_end;
 
@@ -504,12 +503,23 @@ void * __must_check __kasan_kmalloc_large(const void *ptr, size_t size,
 	if (unlikely(ptr == NULL))
 		return NULL;
 
-	page = virt_to_page(ptr);
+	/*
+	 * The object has already been unpoisoned by kasan_alloc_pages() for
+	 * alloc_pages() or by ksize() for krealloc().
+	 */
+
+	/*
+	 * The redzone has byte-level precision for the generic mode.
+	 * Partially poison the last object granule to cover the unaligned
+	 * part of the redzone.
+	 */
+	if (IS_ENABLED(CONFIG_KASAN_GENERIC))
+		kasan_poison_last_granule(ptr, size);
+
+	/* Poison the aligned part of the redzone. */
 	redzone_start = round_up((unsigned long)(ptr + size),
 				KASAN_GRANULE_SIZE);
-	redzone_end = (unsigned long)ptr + page_size(page);
-
-	kasan_unpoison(ptr, size);
+	redzone_end = (unsigned long)ptr + page_size(virt_to_page(ptr));
 	kasan_poison((void *)redzone_start, redzone_end - redzone_start,
 		     KASAN_PAGE_REDZONE);
 
-- 
2.30.0.365.g02bc693789-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/33dee5aac0e550ad7f8e26f590c9b02c6129b4a3.1612546384.git.andreyknvl%40google.com.
