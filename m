Return-Path: <kasan-dev+bncBDX4HWEMTEBRBUG72L7QKGQEHRNWBIA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x337.google.com (mail-wm1-x337.google.com [IPv6:2a00:1450:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id 6E6112EB28E
	for <lists+kasan-dev@lfdr.de>; Tue,  5 Jan 2021 19:28:32 +0100 (CET)
Received: by mail-wm1-x337.google.com with SMTP id h21sf158476wmq.7
        for <lists+kasan-dev@lfdr.de>; Tue, 05 Jan 2021 10:28:32 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1609871312; cv=pass;
        d=google.com; s=arc-20160816;
        b=ay8fbcBaiGaJMKKNTq9SYAeSIArZEH9sPWUx1ZU4qwdNLFk6VQIbaYdcXTUKgiY8Vu
         sShPGASGObmxD8vFeNTg9ijCrrvRtw046iy/ZXhWACxNFiRZVuKL+VVR0l1tJbbLBA5T
         JW50IGzYMBj07Ru50u+O71gVp1MNUuS4aMqC5LYPJf7GMUvF9zG/Fxs3bFhr7L+MDNUy
         wXfX7+aC8wUeqK69ekOPSdsxXDAPbPYfRIV5Wq1vGkQSw9oErDX5ov2cestC+doBL6sV
         YzfCe/67rVq4ubgNhymYMdPdzJQsUZz6g2YReampOWrk8/S7goqffmjipQhX+Wz/rXYb
         1L/Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=NIxrrhc1pZXgApAPFWOLXL16cp+Sb3L3z7//XDzmVvk=;
        b=QVSnokPysMDgGhLynq3Yawp2PCIN5s1Pn/+GMGGsSrneqNCVd0NNfgjxiEYwFTmd6f
         EjiAlTkzJcUgE/6wlALk5Fvn9QvGTHRqpktiEsqZRLbMkd9UQCMEe4G5hS+vSnwhXEoH
         5vR3PW7LakIBVNJBfk+kFDJuYQPKoBhL01oSl6PQmMJT4uvBlvcq5MUSMMT6MmAvpbRy
         doP8lNNylanYdhTEemF2S3hzf0pNkGgNUQiNfSaFLn7CWJAfnxKdYLec5ewXb3/XgDU3
         SA7DDCLWOyXDeoHYBs/j2c++t0KhJ1zcWz6e5nCFS9cyPato1yCKqORp6++112wpfVJL
         mxsA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=VubKJ4tG;
       spf=pass (google.com: domain of 3z6_0xwokcqgivlzm6sv3towwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3z6_0XwoKCQgivlzm6sv3towwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=NIxrrhc1pZXgApAPFWOLXL16cp+Sb3L3z7//XDzmVvk=;
        b=s1jjjp+awLnO0NVKqYVla1JG+z9d7u0oLxCL7DedD+xAZqPOhzyrvKpoNBi8JxPscK
         aJXT/Y5WuTTihxofYM1v2hQJg78oHUk516VMVxKd9GlyBxKxyqXFvujpV6OSodEcSOqb
         vJ3DRpQguWa/DlUZeRKxPuzsRKahRUX3pvmmzFDqlh8eUDxHu5LrCelarDB2h3UG1EOS
         baD1aIdVQu+TzY5jZcCBLWVk0mH8WrB31HAPOSxQ3O+JedZgW8z6VJJL7OL/721B3d06
         MSYUbOZPtOj31695S96bRu/dSl4r+XbPErTf9Kz9NSecKEt8Ti05Ity30oqFRTkVVHZ9
         j6jQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=NIxrrhc1pZXgApAPFWOLXL16cp+Sb3L3z7//XDzmVvk=;
        b=F3H31ZGkf2Rrde3peoDzy2pMJx1nDOQSw4dzqWPygYLtuNWP5fvi6tY9626vWK3m+B
         erXxDEPncWlO1aqO5TKh7853+dDR/qUHinLWnFGmrHLwUXiYXGZoP0uaZHTqrOi3+yFe
         VihV4vQBiQ1VaOaOvqGaCazg7V8eWLws2Axq42c3gxCZYdJRYeDbvR0Al4RgAqxK5Dnd
         wFNQ5VJc6m4Vpku0rcZGs838cJ2qFkD50H0P8oCZcQEbSlHMio3oTl4AQzpG8+qllHXg
         NuiA0bM8HriYKwKfjQlhZX/IYzS/9hfkLgWf/yVGF+jguVsQtBKOGU6jpH4qKOQrAO4y
         XxMw==
X-Gm-Message-State: AOAM532gjMu/8kezSZMg96Xvqz5/CvX/XupkUOstMLnYGQtXtLsl/c/d
	vp+3cKhv8XlcfaJhDRxVxq4=
X-Google-Smtp-Source: ABdhPJzJEze4jwGXulPNt/SXhRrY8c03tcd3TvFEo3066fpf9XOPTBJZBwxWrFSL1ypiUY7gRe72wA==
X-Received: by 2002:a05:6000:108b:: with SMTP id y11mr773136wrw.379.1609871312215;
        Tue, 05 Jan 2021 10:28:32 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:1d8a:: with SMTP id d132ls236788wmd.0.gmail; Tue, 05 Jan
 2021 10:28:31 -0800 (PST)
X-Received: by 2002:a1c:c204:: with SMTP id s4mr377192wmf.73.1609871311349;
        Tue, 05 Jan 2021 10:28:31 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1609871311; cv=none;
        d=google.com; s=arc-20160816;
        b=S0IWh7JoYKFNG9GSabnmEI8Ww3eU2GHTP7+EqqtmGRa/hRp+zDDbhQ6YN0ktE+3lRe
         IYm3OT3FEIkLcUl3+gcXC+kj0QpeFApN590cZcYwAJW+RURPtg3fNnry2qtfMNAiKfjh
         8po1XVI1awM5WdGFIt1WR41zHDpMIHnV02FXF6CT14BK2t+VBjmX9SCfig7IIrHpyBzH
         GEm1CyKUy3PjGOo7PlTXbMlkdNgjERadrKRlpNRGhfk85bwuMXBR4gOS99SSV8Ns5G6k
         gYRdJ5MSccdAC7aJEz9ArtfxyrWLBv4wioanAnpgfo0kx5sanP/pX4G+mxxjawwEV7jR
         DAnQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=oRho7+sQYL8W8g66lzn3SO+/RCe3iCmUxBQsmdc55nY=;
        b=WNGkH15kshjWWavpg9FGpAZB8lhdxV2m8mfGjZkUIY38r8UL+I90T/eE1ba+6ubS0q
         8V3y9zHdCmLbbG8GIe+M+oZoGFyfQ0IslIR+lirwVvFIgqaSMEYQXXkRqqoBScbnn9zL
         smbd8vkb5+cozLk0fk2rHQMyJLF0W+Bop9UeVBqqsvqBhk3PWdLhJ6mHsdNnTtuvilgZ
         tv+2V4FvSV2CYEtNyBMxnPLlBF42zWq/DHF5kc57BgK/oxowSmj4DJQhsvAhfkDo/+wZ
         /laaaG8tBaucH3aikkKiV4vf2lDQwW8TQAUD2n8gR/hOGeFJDy/hftpZcn+xqor7LjJ/
         U6ww==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=VubKJ4tG;
       spf=pass (google.com: domain of 3z6_0xwokcqgivlzm6sv3towwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3z6_0XwoKCQgivlzm6sv3towwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x34a.google.com (mail-wm1-x34a.google.com. [2a00:1450:4864:20::34a])
        by gmr-mx.google.com with ESMTPS id d17si179367wma.4.2021.01.05.10.28.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 05 Jan 2021 10:28:31 -0800 (PST)
Received-SPF: pass (google.com: domain of 3z6_0xwokcqgivlzm6sv3towwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) client-ip=2a00:1450:4864:20::34a;
Received: by mail-wm1-x34a.google.com with SMTP id b184so55470wmh.6
        for <kasan-dev@googlegroups.com>; Tue, 05 Jan 2021 10:28:31 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:adf:9b98:: with SMTP id
 d24mr846317wrc.240.1609871311014; Tue, 05 Jan 2021 10:28:31 -0800 (PST)
Date: Tue,  5 Jan 2021 19:27:55 +0100
In-Reply-To: <cover.1609871239.git.andreyknvl@google.com>
Message-Id: <15ca1976b26aa9edcec4a9d0f3b73f5b6536e5d0.1609871239.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1609871239.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.2.729.g45daf8777d-goog
Subject: [PATCH 11/11] kasan: add proper page allocator tests
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Catalin Marinas <catalin.marinas@arm.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Will Deacon <will.deacon@arm.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Evgenii Stepanov <eugenis@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=VubKJ4tG;       spf=pass
 (google.com: domain of 3z6_0xwokcqgivlzm6sv3towwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3z6_0XwoKCQgivlzm6sv3towwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--andreyknvl.bounces.google.com;
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

The currently existing page allocator tests rely on kmalloc fallback
with large sizes that is only present for SLUB. Add proper tests that
use alloc/free_pages().

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Link: https://linux-review.googlesource.com/id/Ia173d5a1b215fe6b2548d814ef0f4433cf983570
---
 lib/test_kasan.c | 54 +++++++++++++++++++++++++++++++++++++++++++-----
 1 file changed, 49 insertions(+), 5 deletions(-)

diff --git a/lib/test_kasan.c b/lib/test_kasan.c
index 6261521e57ad..24798c034d05 100644
--- a/lib/test_kasan.c
+++ b/lib/test_kasan.c
@@ -128,6 +128,12 @@ static void kmalloc_node_oob_right(struct kunit *test)
 	kfree(ptr);
 }
 
+/*
+ * These kmalloc_pagealloc_* tests try allocating a memory chunk that doesn't
+ * fit into a slab cache and therefore is allocated via the page allocator
+ * fallback. Since this kind of fallback is only implemented for SLUB, these
+ * tests are limited to that allocator.
+ */
 static void kmalloc_pagealloc_oob_right(struct kunit *test)
 {
 	char *ptr;
@@ -138,14 +144,11 @@ static void kmalloc_pagealloc_oob_right(struct kunit *test)
 		return;
 	}
 
-	/*
-	 * Allocate a chunk that does not fit into a SLUB cache to trigger
-	 * the page allocator fallback.
-	 */
 	ptr = kmalloc(size, GFP_KERNEL);
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
 
 	KUNIT_EXPECT_KASAN_FAIL(test, ptr[size + OOB_TAG_OFF] = 0);
+
 	kfree(ptr);
 }
 
@@ -161,8 +164,8 @@ static void kmalloc_pagealloc_uaf(struct kunit *test)
 
 	ptr = kmalloc(size, GFP_KERNEL);
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
-
 	kfree(ptr);
+
 	KUNIT_EXPECT_KASAN_FAIL(test, ptr[0] = 0);
 }
 
@@ -182,6 +185,45 @@ static void kmalloc_pagealloc_invalid_free(struct kunit *test)
 	KUNIT_EXPECT_KASAN_FAIL(test, kfree(ptr + 1));
 }
 
+static void pagealloc_oob_right(struct kunit *test)
+{
+	char *ptr;
+	struct page *pages;
+	size_t order = 4;
+	size_t size = (1UL << (PAGE_SHIFT + order));
+
+	/*
+	 * With generic KASAN page allocations have no redzones, thus
+	 * out-of-bounds detection is not guaranteed.
+	 * See https://bugzilla.kernel.org/show_bug.cgi?id=210503.
+	 */
+	if (IS_ENABLED(CONFIG_KASAN_GENERIC)) {
+		kunit_info(test, "skipping, CONFIG_KASAN_GENERIC enabled");
+		return;
+	}
+
+	pages = alloc_pages(GFP_KERNEL, order);
+	ptr = page_address(pages);
+	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
+
+	KUNIT_EXPECT_KASAN_FAIL(test, ptr[size] = 0);
+	free_pages((unsigned long)ptr, order);
+}
+
+static void pagealloc_uaf(struct kunit *test)
+{
+	char *ptr;
+	struct page *pages;
+	size_t order = 4;
+
+	pages = alloc_pages(GFP_KERNEL, order);
+	ptr = page_address(pages);
+	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
+	free_pages((unsigned long)ptr, order);
+
+	KUNIT_EXPECT_KASAN_FAIL(test, ptr[0] = 0);
+}
+
 static void kmalloc_large_oob_right(struct kunit *test)
 {
 	char *ptr;
@@ -933,6 +975,8 @@ static struct kunit_case kasan_kunit_test_cases[] = {
 	KUNIT_CASE(kmalloc_pagealloc_oob_right),
 	KUNIT_CASE(kmalloc_pagealloc_uaf),
 	KUNIT_CASE(kmalloc_pagealloc_invalid_free),
+	KUNIT_CASE(pagealloc_oob_right),
+	KUNIT_CASE(pagealloc_uaf),
 	KUNIT_CASE(kmalloc_large_oob_right),
 	KUNIT_CASE(kmalloc_oob_krealloc_more),
 	KUNIT_CASE(kmalloc_oob_krealloc_less),
-- 
2.29.2.729.g45daf8777d-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/15ca1976b26aa9edcec4a9d0f3b73f5b6536e5d0.1609871239.git.andreyknvl%40google.com.
