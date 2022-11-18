Return-Path: <kasan-dev+bncBCF5XGNWYQBRBDMF3SNQMGQEDAUU62Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3b.google.com (mail-oa1-x3b.google.com [IPv6:2001:4860:4864:20::3b])
	by mail.lfdr.de (Postfix) with ESMTPS id EE26E62EC94
	for <lists+kasan-dev@lfdr.de>; Fri, 18 Nov 2022 04:57:07 +0100 (CET)
Received: by mail-oa1-x3b.google.com with SMTP id 586e51a60fabf-13cbfc38be2sf1774442fac.0
        for <lists+kasan-dev@lfdr.de>; Thu, 17 Nov 2022 19:57:07 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1668743821; cv=pass;
        d=google.com; s=arc-20160816;
        b=iPHONUISN6Ou8TbqNqTwq0V2qQGtTMumfYz1TCb4n4uTTlRkRibfbdPpxHrxPuI64j
         akW5Qho80XUSr9IvyZGTyDgQC/VtwOWzBrJEqpCx2ALL6p9P33TDgl0RehGmbCfFcSVN
         1ucASewBP/lvD4mZmjsNkoVn7f9+gNdMumgLsU7HBqmfPAipX6iQt+THJ4Y7Ul1QYxJR
         Deqpa+K7rvFgviwEU+sKak0ewEXqUJ1O3PhMaxAyjlmJRG9Sb2x8A2tNDTkBTPIM748/
         rwDUrugsr+aQrQu0XSkA+txf1xPsaDdIrWiWjUtBWocLCEcEXQsj8RTtlZHfyJ8IietW
         l/pA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=INHp3enrmLVTj6KmjxLX8BbxXlOStBAHijb8shhvN6E=;
        b=vuRnREOFimLDlCYKQTdexzq4JFQv9aVWb8u1PrZ2g9t79DIE1qNrDJVmBvw07fHild
         1WQHBMfaIt2gy8cXPuJ0EG8qZs4iY69LMUFrxtO20u7v4tvwmAlfYPmplBxfbldKYDRk
         Pd9Cr0vgx9B+OGNq9wxFgmdZkdUM94Kob5a1RrIiclZmaAYRqKigUNlTME8JJc/fe9fi
         n5HGbBCUif0Scbd/Ze+CVqNB1U3vEbEL06qrXkHe6q+xsxt8ht0xB7lpua/MY612jKz4
         aq/Bs14g7hgY+BnW/p3CQTf7EMjsfD4ngB+ho3jv/u0Nsakcp66wQxAUgqDquon37NaX
         1Cyw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=cR9j3NBA;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::102c as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=INHp3enrmLVTj6KmjxLX8BbxXlOStBAHijb8shhvN6E=;
        b=NwC8r9Q29lCyfLItWrT3V3U96OLgftpREyO5cpdMpA7P8znB07pCJa0LjmERFo3j4Q
         5QZQDY4dTl1DK5okQxkiEzBCmIxp+L7WQ8PGs7m65Z4TQY2c6OejiU2p37Bm53QDdWbF
         kliuDcnpZ/AeHHIr8UqnmWIQbofYUXReaPhdht5OSYmCoColc3vN3iYjp8z+i2AVEoOP
         6q7XKYk3yznqbsWCqUQujcnDRvvH9TLzGSaC5EB53Pcm5YdM5WmFhUM13cf2tw5O5ewC
         GCBEi7uJU9Z4D4WnowQv0EJYdRQi2VoXBsLY1htf+p1eJVBqIk/iX+QgDSEPftLnHdtP
         AUHw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-gm-message-state:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=INHp3enrmLVTj6KmjxLX8BbxXlOStBAHijb8shhvN6E=;
        b=CYQBGiOIfFKay2mS+Dgt6iceRqGy76RpWrbiP2CikZNqAA0Lv7CeEaEqEACMKYs3Cj
         59xiiz+r3S4mZjrqP7xZV6riH4FIXBIc1GJ/m8rO3/N9RwaOIMS+fYGnW7Ob9OzMu94Q
         VJekNdgpd7xH3syzWKJQ4Z8G9hWvCtx/NE/ztPh/loDJzQ+f45Mez3Lu6pxN/vL9XXNm
         bJJMcMVnodvovFAbSg8czpDGg5m0UbaM8USg8ulkUFIBHYInyuR+iM5RLwVqx+QqHsjZ
         1BxQeK3cFdoj14laEX9okSqIh9tfj9cdxFgOjGDNHBj1gSvXs8p1uynPN6HyuEaFpc8k
         CA9A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANoB5pmNCPdZItefSkCvJaqeCgtk9h9UTP6WIBHk/cqjf8Yv5vNs90Ur
	+3T8bDLa6CrLqfeuKuoLbbU=
X-Google-Smtp-Source: AA0mqf6WFKc+T8VKd7pgmxo04vOusW8t3yHVh1cSiUXAJ48xiz3CqLqvXLvqQrlvVXpafGDISlLDSg==
X-Received: by 2002:a05:6870:ac97:b0:13d:3935:d06e with SMTP id ns23-20020a056870ac9700b0013d3935d06emr2966272oab.197.1668743821269;
        Thu, 17 Nov 2022 19:57:01 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:6487:b0:66c:7df0:d6be with SMTP id
 ck7-20020a056830648700b0066c7df0d6bels822159otb.8.-pod-prod-gmail; Thu, 17
 Nov 2022 19:57:00 -0800 (PST)
X-Received: by 2002:a9d:5f13:0:b0:66c:753a:844d with SMTP id f19-20020a9d5f13000000b0066c753a844dmr2880805oti.285.1668743820797;
        Thu, 17 Nov 2022 19:57:00 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1668743820; cv=none;
        d=google.com; s=arc-20160816;
        b=QGQGKYiJZ9oB/gpOYzIbY54PXjcgohAY+lBO4wxjAkcl0H3GXNFQGOJFck6updIEBz
         sK96XBRVWxDaKCgNFN5CfG+2wxqg4HRFUZJV80FaaqwdEyeUJldUYF2BAzM6AYFZGZne
         T0dJv+6fCjT7FWL75LxYqOtHvrkNZGf4pFGziRrtezTxztD5SQEgZ5ZjTVP6BMvIJ4cv
         YYp6YupWn0q327olxjCsHMtD9WLzyvFwJm7Bj0iY+lH5KFCI5QSYrGb9vuz+Pgg9ykAA
         //AOg+ZctUhNoNr18zAqTBDjfdtlLoB7aVAZ6PP5FHz69tG4cedFGxAUFkeVS23wqqq+
         17VA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=8B1s0J4vkfD99lkbpUfX7NsV2A8gl/zFhB0jTXPx4F4=;
        b=NdnTdTjQBWf7zsceiplS+PvrCPUNNimK/+StsWaLXavwhH3GDQZWqrZsFNcW5K30/c
         i3BRAo74mXqEIcDAoCEm5tTJnYCO5S9+yP1vhVrWgklo3YRv3WwfWpG0SmZ0U2xhkMWh
         iWziVAu56h79nhBP3GulMoZcD9GsugkXFKPXiFeMfYZB80CfXyiPdyUA9XDcZn1T7ThM
         9s8LrvV2E5KYwulhHIcKL1/nyXS72gj2rIQmQ5gsgLH4SYcy+KPn8Jo331zPJyqKB6DF
         sURhL6+67nhqJHWCEoBafGez8jUrtBW/EP1Sm5rx0TM46eRahwP4B5BUtQEp4asVxAEK
         H23w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=cR9j3NBA;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::102c as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-pj1-x102c.google.com (mail-pj1-x102c.google.com. [2607:f8b0:4864:20::102c])
        by gmr-mx.google.com with ESMTPS id l28-20020a056830055c00b0066c427f94ecsi175789otb.3.2022.11.17.19.57.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 17 Nov 2022 19:57:00 -0800 (PST)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::102c as permitted sender) client-ip=2607:f8b0:4864:20::102c;
Received: by mail-pj1-x102c.google.com with SMTP id h14so3424642pjv.4
        for <kasan-dev@googlegroups.com>; Thu, 17 Nov 2022 19:57:00 -0800 (PST)
X-Received: by 2002:a17:90a:b298:b0:212:f923:2f90 with SMTP id c24-20020a17090ab29800b00212f9232f90mr5755322pjr.93.1668743820127;
        Thu, 17 Nov 2022 19:57:00 -0800 (PST)
Received: from www.outflux.net (smtp.outflux.net. [198.145.64.163])
        by smtp.gmail.com with ESMTPSA id t6-20020a656086000000b0047722bc3016sm683354pgu.80.2022.11.17.19.56.59
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 17 Nov 2022 19:56:59 -0800 (PST)
From: Kees Cook <keescook@chromium.org>
To: Andrey Konovalov <andreyknvl@gmail.com>
Cc: Kees Cook <keescook@chromium.org>,
	Christoph Lameter <cl@linux.com>,
	Pekka Enberg <penberg@kernel.org>,
	David Rientjes <rientjes@google.com>,
	Joonsoo Kim <iamjoonsoo.kim@lge.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Roman Gushchin <roman.gushchin@linux.dev>,
	Hyeonggon Yoo <42.hyeyoo@gmail.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	linux-mm@kvack.org,
	kasan-dev@googlegroups.com,
	Vlastimil Babka <vbabka@suse.cz>,
	linux-kernel@vger.kernel.org,
	linux-hardening@vger.kernel.org
Subject: [PATCH v2] mm: Make ksize() a reporting-only function
Date: Thu, 17 Nov 2022 19:56:57 -0800
Message-Id: <20221118035656.gonna.698-kees@kernel.org>
X-Mailer: git-send-email 2.34.1
MIME-Version: 1.0
X-Developer-Signature: v=1; a=openpgp-sha256; l=4800; h=from:subject:message-id; bh=Z9YyO0LwjFqRuv/Azz2xAdd8WdFra8on/pdrLBKRfK0=; b=owEBbQKS/ZANAwAKAYly9N/cbcAmAcsmYgBjdwKJFMoqLEX42onP27WvbKXgxbbST+JJjwmiMqFo 9nXiQxiJAjMEAAEKAB0WIQSlw/aPIp3WD3I+bhOJcvTf3G3AJgUCY3cCiQAKCRCJcvTf3G3AJq/ZD/ sGlZyzLuKKDjnPxvjXfOv1yhSHIWk/DAFlOwg9tQcertx2R8rm/uJPICL+RuB5KqnNHu1aiZg3Co/O WLmLHBqvIUb0MUCpAZNSLgm6nTuaabey28O0f+yW8vlNwSKT14xHFUSMxStc1YmnMEFs/F/LmLAug/ bmoobIxZeqa0Aq+ImsvMy+Semml0HLZAzfr22XJ13xyZNaAE06fGjHUM4h63wV4RswGPe+COqw0PTt KSX+ZfMfD4m4Ltw5HSUHAr4BP5Pxz8f05jgHNdCTll/d9UHZ9Xn0WpStS4tLQikIwbs2cuqjdSsN5K 4jNFdBkZhZDfzhq6wmUCy4pixNs+o/eTCq1EE6JVIYPDrM+RmPBv0iwIqF3+jWtTXPUiY7SL1saXC7 OObPcdFfDrY5VKam7Yde+T2C/EbZy9uZmR0tkEo90H0igCyjHVsBwjNsMFYfaJB8mjO18+1YzaInSR Hj4ndnFz2O/hWh9z7t1iC1TsjLHtZSv12AdCVeWAvSUGDl7wDow8/4L+IKDGs7Ee4CTbrdJmqKpvmz 6BldL3a+p9hTtV9M68PnjlWm7KkvFGSFxD8dRVU2fQ0hExGLs39UsMVK/ckoHeXHHKOKtBPeVczBCw MUC//OycG4vu0Qn3A0CeEIUlcUKu7E7cklt41zMfMR88e6fwpoah2SPTGK5A==
X-Developer-Key: i=keescook@chromium.org; a=openpgp; fpr=A5C3F68F229DD60F723E6E138972F4DFDC6DC026
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=cR9j3NBA;       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::102c
 as permitted sender) smtp.mailfrom=keescook@chromium.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=chromium.org
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

With all "silently resizing" callers of ksize() refactored, remove the
logic in ksize() that would allow it to be used to effectively change
the size of an allocation (bypassing __alloc_size hints, etc). Users
wanting this feature need to either use kmalloc_size_roundup() before an
allocation, or use krealloc() directly.

For kfree_sensitive(), move the unpoisoning logic inline. Replace the
some of the partially open-coded ksize() in __do_krealloc with ksize()
now that it doesn't perform unpoisoning.

Adjust the KUnit tests to match the new ksize() behavior.

Cc: Andrey Konovalov <andreyknvl@gmail.com>
Cc: Christoph Lameter <cl@linux.com>
Cc: Pekka Enberg <penberg@kernel.org>
Cc: David Rientjes <rientjes@google.com>
Cc: Joonsoo Kim <iamjoonsoo.kim@lge.com>
Cc: Andrew Morton <akpm@linux-foundation.org>
Cc: Roman Gushchin <roman.gushchin@linux.dev>
Cc: Hyeonggon Yoo <42.hyeyoo@gmail.com>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>
Cc: Alexander Potapenko <glider@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>
Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>
Cc: linux-mm@kvack.org
Cc: kasan-dev@googlegroups.com
Acked-by: Vlastimil Babka <vbabka@suse.cz>
Signed-off-by: Kees Cook <keescook@chromium.org>
---
v2:
- improve kunit test precision (andreyknvl)
- add Ack (vbabka)
v1: https://lore.kernel.org/all/20221022180455.never.023-kees@kernel.org
---
 mm/kasan/kasan_test.c | 14 +++++++++-----
 mm/slab_common.c      | 26 ++++++++++----------------
 2 files changed, 19 insertions(+), 21 deletions(-)

diff --git a/mm/kasan/kasan_test.c b/mm/kasan/kasan_test.c
index 7502f03c807c..fc4b22916587 100644
--- a/mm/kasan/kasan_test.c
+++ b/mm/kasan/kasan_test.c
@@ -821,7 +821,7 @@ static void kasan_global_oob_left(struct kunit *test)
 	KUNIT_EXPECT_KASAN_FAIL(test, *(volatile char *)p);
 }
 
-/* Check that ksize() makes the whole object accessible. */
+/* Check that ksize() does NOT unpoison whole object. */
 static void ksize_unpoisons_memory(struct kunit *test)
 {
 	char *ptr;
@@ -829,15 +829,19 @@ static void ksize_unpoisons_memory(struct kunit *test)
 
 	ptr = kmalloc(size, GFP_KERNEL);
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
+
 	real_size = ksize(ptr);
+	KUNIT_EXPECT_GT(test, real_size, size);
 
 	OPTIMIZER_HIDE_VAR(ptr);
 
-	/* This access shouldn't trigger a KASAN report. */
-	ptr[size] = 'x';
+	/* These accesses shouldn't trigger a KASAN report. */
+	ptr[0] = 'x';
+	ptr[size - 1] = 'x';
 
-	/* This one must. */
-	KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr)[real_size]);
+	/* These must trigger a KASAN report. */
+	KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr)[size]);
+	KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr)[real_size - 1]);
 
 	kfree(ptr);
 }
diff --git a/mm/slab_common.c b/mm/slab_common.c
index 8276022f0da4..27caa57af070 100644
--- a/mm/slab_common.c
+++ b/mm/slab_common.c
@@ -1335,11 +1335,11 @@ __do_krealloc(const void *p, size_t new_size, gfp_t flags)
 	void *ret;
 	size_t ks;
 
-	/* Don't use instrumented ksize to allow precise KASAN poisoning. */
+	/* Check for double-free before calling ksize. */
 	if (likely(!ZERO_OR_NULL_PTR(p))) {
 		if (!kasan_check_byte(p))
 			return NULL;
-		ks = kfence_ksize(p) ?: __ksize(p);
+		ks = ksize(p);
 	} else
 		ks = 0;
 
@@ -1407,21 +1407,21 @@ void kfree_sensitive(const void *p)
 	void *mem = (void *)p;
 
 	ks = ksize(mem);
-	if (ks)
+	if (ks) {
+		kasan_unpoison_range(mem, ks);
 		memzero_explicit(mem, ks);
+	}
 	kfree(mem);
 }
 EXPORT_SYMBOL(kfree_sensitive);
 
 size_t ksize(const void *objp)
 {
-	size_t size;
-
 	/*
-	 * We need to first check that the pointer to the object is valid, and
-	 * only then unpoison the memory. The report printed from ksize() is
-	 * more useful, then when it's printed later when the behaviour could
-	 * be undefined due to a potential use-after-free or double-free.
+	 * We need to first check that the pointer to the object is valid.
+	 * The KASAN report printed from ksize() is more useful, then when
+	 * it's printed later when the behaviour could be undefined due to
+	 * a potential use-after-free or double-free.
 	 *
 	 * We use kasan_check_byte(), which is supported for the hardware
 	 * tag-based KASAN mode, unlike kasan_check_read/write().
@@ -1435,13 +1435,7 @@ size_t ksize(const void *objp)
 	if (unlikely(ZERO_OR_NULL_PTR(objp)) || !kasan_check_byte(objp))
 		return 0;
 
-	size = kfence_ksize(objp) ?: __ksize(objp);
-	/*
-	 * We assume that ksize callers could use whole allocated area,
-	 * so we need to unpoison this area.
-	 */
-	kasan_unpoison_range(objp, size);
-	return size;
+	return kfence_ksize(objp) ?: __ksize(objp);
 }
 EXPORT_SYMBOL(ksize);
 
-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20221118035656.gonna.698-kees%40kernel.org.
