Return-Path: <kasan-dev+bncBDX4HWEMTEBRB7NT4GAAMGQEMO72Y2Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x237.google.com (mail-lj1-x237.google.com [IPv6:2a00:1450:4864:20::237])
	by mail.lfdr.de (Postfix) with ESMTPS id 66D7B30B0A0
	for <lists+kasan-dev@lfdr.de>; Mon,  1 Feb 2021 20:43:58 +0100 (CET)
Received: by mail-lj1-x237.google.com with SMTP id a5sf2034286ljp.5
        for <lists+kasan-dev@lfdr.de>; Mon, 01 Feb 2021 11:43:58 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1612208638; cv=pass;
        d=google.com; s=arc-20160816;
        b=pJjBtIJuK7/XtezQIrw2uS5RVwz36lOC/IQu01Av41RAOJOeVcSzHa1aNNlz9q6y0/
         tuQ06I7u53Afj6Xg+bqg40wD2Ea/Q5SukRvUbnWeIbzYHDT3uNeYASuDGOkHrrBd0j4Y
         o7j6kEt1AJLDTy8OUzfCr+ZK1aXJgtcnsjXQDFk0e8yadeDlYbpKqhhGwMSL21kSn7N3
         SjHzApsPkyjIwkCBvQAR6Zr65QSZOoYahv7QFXim2zSfbYinLuS2lEwCl2zuhnEkqazu
         bOtbY8pJEARcklBcdWi8uXjcgM5SKf18D48hUDC0geAWdTiwNC5+dwtS9kpH1LEt1vIa
         VG9Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=2X17sG4oPvBrUF04hdVbHhK9vkv/w8wFxNzXQxKqMHs=;
        b=BULHNbPn0D/EhU6RBfUz7L14Oc7yqiHWuV4YcYtwWPQo5UG7gKWw/Z7RCdOvnUEFRQ
         k6V6rULvsW77rC0dnA0ZP4Fbi5M76DdN7a5V7+t+16TILofrQzHpJoj8qXdwXGkDWYYR
         GaVJx2VIrA6OYr5O4dd16+lkCWmvDLnOPxu7kh8ZxQUSAObLYIawMLf4PUds3emyR95D
         ZAkQjnprhzbZoj8mx/KVgmRM/TPdBGuw0ggoaMrToiJezYgOwGtW3IVNU5j7/JwWV00y
         BtvqSw/w63X2wsjzw2txjPWA/gnNTPpSWRbAcBXMMKHR77+wnejcNiqt9aB3i2oFfig6
         S8Cw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ivESTfLf;
       spf=pass (google.com: domain of 3_fkyyaokcrkzc2g3n9cka5dd5a3.1db9zhzc-23k5dd5a35gdjeh.1db@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3_FkYYAoKCRkzC2G3N9CKA5DD5A3.1DB9zHzC-23K5DD5A35GDJEH.1DB@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=2X17sG4oPvBrUF04hdVbHhK9vkv/w8wFxNzXQxKqMHs=;
        b=HPAV+TSKuqPBT/LNbnzo32wmziQk81oNJZqlFWJqXJgkuI1bzzB9QxMS+v0RQ2Slr7
         KnM2VoiDYquKwqZI8D8ZUOhurFZ41M0X48oJHcH/7Ayc0eNjMucr/uwBNhbZegdY4fFq
         udaRcawzjNLBo75pMnLtG351yNMsweguv38SOqrTQjZiaKYsJZk6PkFRFH++spfov+UX
         APmJ4bbUo+kGPZUHEz+U9myqnIWieHDmlE/qryh7ewuTcRXPL1jbQs+joTClLnO1uGrx
         JNGGGa7DMtyZqbgP2Mc4z6fedzKoYSbEZzK5YQRJAFLowITBiZ7pHWPayfrV4jphwGg+
         LGow==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=2X17sG4oPvBrUF04hdVbHhK9vkv/w8wFxNzXQxKqMHs=;
        b=H1ZmWjK/ay+85HOVhRkv3TWegPZeFDdJ/9d9rM2fdLeH3p4BPrrJMeOi8gkelrYVF1
         J7yIZ0v4njpjj8ny2XUL9PjzLpZG+oLD52DIxMxK/HV7ZqoPvl+WXUIgLbzyqex5x15F
         je/UEedY92pMHyO81Bc4Qopic+ZyyYtSR70E47jLCz2vlGIXohD/bI48jwH27c932bMp
         9aAke0DQSCrWvlrx3puBY8S6iDwWCmrWPY1IYPeObnnXux/NQsobeXCpPwzwuVBV1TFi
         /rCXnAABsuvGKHCxOcj6Olh7QYfAM13/CHxCNX8TwcMqmajnpcZeNu0gHflTk84oh+gL
         j3Vg==
X-Gm-Message-State: AOAM530ZwR7dT2GU7GT6+dcNHQer7FLjxkAR44tL3Ohzg+jD+pUpEsCN
	KGUxhIOa5D56aztC7OE8BIE=
X-Google-Smtp-Source: ABdhPJwNTSTGYvel0jtBY4jhBcMYpKxotfMOahjNXa9rlCFnlOgaI9IOhESz8rzv6q9gMpPbFEkCFA==
X-Received: by 2002:a05:651c:548:: with SMTP id q8mr10963781ljp.256.1612208638000;
        Mon, 01 Feb 2021 11:43:58 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:8850:: with SMTP id z16ls3354768ljj.4.gmail; Mon, 01 Feb
 2021 11:43:57 -0800 (PST)
X-Received: by 2002:a2e:b5ba:: with SMTP id f26mr10675627ljn.92.1612208637044;
        Mon, 01 Feb 2021 11:43:57 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1612208637; cv=none;
        d=google.com; s=arc-20160816;
        b=Rn+VnVsQLZ1hu75Tcas2XkhPn9/gkdUfcV22e/6IL5GM/x2Yihggdec6clNnOWOt2F
         VO5j7O9iyh4qaptgoY1/qkmzIgFpu5AaNOS5cUV+ZdglFgES+ax1TpOeWwc5XadGLyf0
         1C+K+pqPqpUxJB6rW8+LnqvhC30+AVC6y9r7VZ/4+Mywif2TfsRDMahj2wDFQHNz9fLi
         QNtIlDlKKRqAbmcly5JOICYMS/NejLI+kQRPrFP11f3noRa/XbvuhaxCiv6qbb8ylB9f
         qXmzhHLRgXhv8Lu7TqwvsOxG+wlYbedCAo+TstAGBcsIXk1RimQ9xAF0vBw7AaSgx8I3
         eFZA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=yMQgrLxhHIKq4G0a2NCbXbKyDrvusdwY4yeazjCtuyk=;
        b=mQwRAPmAIXKvC7zS8MaSs5iA472pMXezOL9fr5BCpoFRMZ071DNfxEUX4xv2wjuJAA
         FX9pPsrvzySRs+hWDFaUPngs1gMTh8SkF8e+pmeFjeDGew3/FM1nQiykDAHOS3knbCiI
         9Ql4CdJnA6FcNYPmSVMUUitvXOb1xQmtcXEsj1HeLg+Uatx4LqYZF1/0M+qq4vuJ9QPW
         OHKqBevJ0Gwqwkodn/HwHS+NMLD3iD6tXDnQPkpJ+Kj1B+2o32808qBARv+v+ySlbH9O
         KYNOelC53C9wmody35QHH7w5rYM4QemIVGscmgZ9PBt0dN/RinD/C6ZdhT6+atusNVx5
         tSgA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ivESTfLf;
       spf=pass (google.com: domain of 3_fkyyaokcrkzc2g3n9cka5dd5a3.1db9zhzc-23k5dd5a35gdjeh.1db@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3_FkYYAoKCRkzC2G3N9CKA5DD5A3.1DB9zHzC-23K5DD5A35GDJEH.1DB@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x34a.google.com (mail-wm1-x34a.google.com. [2a00:1450:4864:20::34a])
        by gmr-mx.google.com with ESMTPS id 139si615615lfi.1.2021.02.01.11.43.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 01 Feb 2021 11:43:57 -0800 (PST)
Received-SPF: pass (google.com: domain of 3_fkyyaokcrkzc2g3n9cka5dd5a3.1db9zhzc-23k5dd5a35gdjeh.1db@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) client-ip=2a00:1450:4864:20::34a;
Received: by mail-wm1-x34a.google.com with SMTP id h25so172560wmb.6
        for <kasan-dev@googlegroups.com>; Mon, 01 Feb 2021 11:43:57 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a1c:7711:: with SMTP id
 t17mr441041wmi.64.1612208636543; Mon, 01 Feb 2021 11:43:56 -0800 (PST)
Date: Mon,  1 Feb 2021 20:43:31 +0100
In-Reply-To: <cover.1612208222.git.andreyknvl@google.com>
Message-Id: <884e37ddff31b671725f4d83106111c7dcf8fb9b.1612208222.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1612208222.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.30.0.365.g02bc693789-goog
Subject: [PATCH 07/12] kasan, mm: remove krealloc side-effect
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Catalin Marinas <catalin.marinas@arm.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Will Deacon <will.deacon@arm.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Peter Collingbourne <pcc@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, kasan-dev@googlegroups.com, 
	linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=ivESTfLf;       spf=pass
 (google.com: domain of 3_fkyyaokcrkzc2g3n9cka5dd5a3.1db9zhzc-23k5dd5a35gdjeh.1db@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3_FkYYAoKCRkzC2G3N9CKA5DD5A3.1DB9zHzC-23K5DD5A35GDJEH.1DB@flex--andreyknvl.bounces.google.com;
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

Currently, if krealloc() is called on a freed object with KASAN enabled,
it allocates and returns a new object, but doesn't copy any memory from
the old one as ksize() returns 0. This makes a caller believe that
krealloc() succeeded (KASAN report is printed though).

This patch adds an accessibility check into __do_krealloc(). If the check
fails, krealloc() returns NULL. This check duplicates the one in ksize();
this is fixed in the following patch.

This patch also adds a KASAN-KUnit test to check krealloc() behaviour
when it's called on a freed object.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 lib/test_kasan.c | 20 ++++++++++++++++++++
 mm/slab_common.c |  3 +++
 2 files changed, 23 insertions(+)

diff --git a/lib/test_kasan.c b/lib/test_kasan.c
index 2bb52853f341..61bc894d9f7e 100644
--- a/lib/test_kasan.c
+++ b/lib/test_kasan.c
@@ -359,6 +359,25 @@ static void krealloc_pagealloc_less_oob(struct kunit *test)
 					KMALLOC_MAX_CACHE_SIZE + 201);
 }
 
+/*
+ * Check that krealloc() detects a use-after-free, returns NULL,
+ * and doesn't unpoison the freed object.
+ */
+static void krealloc_uaf(struct kunit *test)
+{
+	char *ptr1, *ptr2;
+	int size1 = 201;
+	int size2 = 235;
+
+	ptr1 = kmalloc(size1, GFP_KERNEL);
+	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr1);
+	kfree(ptr1);
+
+	KUNIT_EXPECT_KASAN_FAIL(test, ptr2 = krealloc(ptr1, size2, GFP_KERNEL));
+	KUNIT_ASSERT_PTR_EQ(test, (void *)ptr2, NULL);
+	KUNIT_EXPECT_KASAN_FAIL(test, *(volatile char *)ptr1);
+}
+
 static void kmalloc_oob_16(struct kunit *test)
 {
 	struct {
@@ -1056,6 +1075,7 @@ static struct kunit_case kasan_kunit_test_cases[] = {
 	KUNIT_CASE(krealloc_less_oob),
 	KUNIT_CASE(krealloc_pagealloc_more_oob),
 	KUNIT_CASE(krealloc_pagealloc_less_oob),
+	KUNIT_CASE(krealloc_uaf),
 	KUNIT_CASE(kmalloc_oob_16),
 	KUNIT_CASE(kmalloc_uaf_16),
 	KUNIT_CASE(kmalloc_oob_in_memset),
diff --git a/mm/slab_common.c b/mm/slab_common.c
index 39d1a8ff9bb8..dad70239b54c 100644
--- a/mm/slab_common.c
+++ b/mm/slab_common.c
@@ -1140,6 +1140,9 @@ static __always_inline void *__do_krealloc(const void *p, size_t new_size,
 	void *ret;
 	size_t ks;
 
+	if (likely(!ZERO_OR_NULL_PTR(p)) && !kasan_check_byte(p))
+		return NULL;
+
 	ks = ksize(p);
 
 	if (ks >= new_size) {
-- 
2.30.0.365.g02bc693789-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/884e37ddff31b671725f4d83106111c7dcf8fb9b.1612208222.git.andreyknvl%40google.com.
