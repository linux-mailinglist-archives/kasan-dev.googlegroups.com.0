Return-Path: <kasan-dev+bncBDX4HWEMTEBRBTED62AAMGQEJL474KA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x63f.google.com (mail-ej1-x63f.google.com [IPv6:2a00:1450:4864:20::63f])
	by mail.lfdr.de (Postfix) with ESMTPS id 14618310EC5
	for <lists+kasan-dev@lfdr.de>; Fri,  5 Feb 2021 18:35:09 +0100 (CET)
Received: by mail-ej1-x63f.google.com with SMTP id dc21sf7125463ejb.19
        for <lists+kasan-dev@lfdr.de>; Fri, 05 Feb 2021 09:35:09 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1612546508; cv=pass;
        d=google.com; s=arc-20160816;
        b=yM7FUw60trfE5jQdDN6Z6gHvcsI4IE2bagv8oZTBtjGnDXrnhl6wlLlGnDtG6LD2vJ
         vPBcN1ucjMR4mHXz581Rcgi3I/pTdjKxYA8QDT78iT12tkhcxGkcDPRKc5j4ciBsbRQg
         QLP8XgC1xZYg1dogU0e1QBE0wA9hZjDacdB+ZO1RDZTW04zl7ROzOMYSIpT25aKoY+Y3
         VTfCGy1dpK4IuGmUIG5YfhaTytWLbaEdiU3d+bw9shJF1aO9F5/HF6qNCwcbwXKH2pLe
         UJZ46hmfgni823vBdTtJmFKdPRP+3ORUE5MRSPbz6Mh2OUXWzTyp78U/sziuIVMgu7cn
         jukQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=HW2APKh/Inf8+LmRxMJoZFicRzA1UFv4NBo14Qr+f7Q=;
        b=j4hAOCvmchBQaHLf1ILSrmtGzR/MFzL/A2yO67PmxmE6cenEWHwPpRJ5iivbPgUAAx
         MbaLEC9WLT9JXBWzV/clgAsFmHQ0jDktmNlp2rrohnq9c3LJWG0+4hFTQice9x6nHV/k
         mnuHnTRnyMGTRykNkjKvGOKECR/Zzfmjx1GvDmb6B9jxm7FtBO5lrIsu+LBE/5GCSsKi
         1eIVcbSnAhS0CHMfN4b4VP2UG9FKwIyUUNB0JvqlzBTiy/QysGNH8K/xUFoQ0wGIzCvu
         9I4S1ghmidOCUjWEK0XZRsk4tUQbl6248ai2IXqZs8uHqmuVcZZqFt3sCb14e6dIT16N
         owxQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=hr9DzLw8;
       spf=pass (google.com: domain of 3y4edyaokcuwo1r5scy19zu22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3y4EdYAoKCUwo1r5sCy19zu22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=HW2APKh/Inf8+LmRxMJoZFicRzA1UFv4NBo14Qr+f7Q=;
        b=Y+3t5VthPBjEDYCIyonxyYhbIzgzV68BbkwsmGMttuBS2fUdgc3MZbpVxme3lZvRW1
         p51oJjBSltmCfyrT1sNRspuAFH9QRZZJhYm2SvEX+EkdGDGk0UmS4GSeyR45hD6GHAua
         keehgJJ8znhP8mbivYA81pXmjR8wqD0Kyig88d2Qh/JiP4Hg3w0UvnjGtU2esIVruyQj
         zKj8dqWM8njeQQnxdtrU6idsPSZfjp1wBCbUxx9KWowtSF0qDuWLmRpHPr1BSo3zJ4bm
         ghR4a4aDI0iAUIsckHrnQ5Qc0px/49v6J4W2qEQm6OeSfaCPyJjhR4vtRtrMrXOt7LSs
         hUGQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=HW2APKh/Inf8+LmRxMJoZFicRzA1UFv4NBo14Qr+f7Q=;
        b=HCZvTAotT2gd3mVzfhYW6L9gSfQ1acUi9uau0wVoFmXlVEuceBJPufcSvGAxFilOjE
         XKtYcTlr47EnAqOBOrdzZap7j7RomYcYjIntbpnN0FuKSEYGffRN7/n++z5TMHydKlvf
         IsPrLwTopJOmgJjBJa3x4wZXgf1dVt3rxS8nGbk/Mj6hbtrhn1FU/9HUXrXOBVG+GRFN
         DAHWt4Tz/TY7oBLwRFJpyp6dlgIHEpmLFATpA+ZRMVNjt+tlQ6pgMEKoYL67+/D+S3UT
         JSV3FHDkMjpz0oeLb9XA8wRVGi69WJiIsY/kRU80bn7yQcbGSMvCAt4fijx6N6p89d0H
         iMow==
X-Gm-Message-State: AOAM530UIh12DIG03iuqLzGEzFXmUZ8LHwRh2YmtyW8z1kqjcqGVsJqt
	ZExfpwPM8y0DR9CBoyd0U6I=
X-Google-Smtp-Source: ABdhPJzhNk/XGHVawS4ATAISKJWdJqvRMNNHHG0UtLNBR4PeyTH01retHEPY2PLctxI3p9eFdwKKbg==
X-Received: by 2002:a17:906:d84:: with SMTP id m4mr5014859eji.437.1612546508848;
        Fri, 05 Feb 2021 09:35:08 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:1432:: with SMTP id c18ls694576edx.0.gmail; Fri, 05
 Feb 2021 09:35:08 -0800 (PST)
X-Received: by 2002:aa7:da55:: with SMTP id w21mr4774274eds.138.1612546508055;
        Fri, 05 Feb 2021 09:35:08 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1612546508; cv=none;
        d=google.com; s=arc-20160816;
        b=YBIfiJxaoyE9T44iMTtsvBfl6txpf3iW+EJ6TDk8tJJes0oCdCkTA1ujbhD7rLGUR7
         MkLBTLz3T63YSFcirdlXADJk/XUTVU0dixG6vRYa3CK5ZJnaFkKfCrSWDu3rRfrZjNp2
         k7PsK6uy/3gkpQRKsHFQLRxphwKuGNI+VdIPPF+3UAFderA/qXsOsHYiO8cNr2IU/MWP
         PVhXh5MOb0sOGCPgWhLtDt1Plx10ZyUNVCEL9vLw0X5erjVJtXFKb623XkEeTKWrbLwe
         mNNwJOUzb14GXs7UGJuHdtokuigatGC1ifigNIowk2Ba2eRbEgfFz5/NRHfK9TEJOpAK
         1wWw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=6RV3PXvNWDRRLwJfhc9nA9uOtjOO4vRR2YJTlHhgy1g=;
        b=fqgWMM77k9ijrweGnj7u25JR5xpMDMmQBEG+LRtWsMCbGTr7v1yWxLT+BD+wch2cdA
         HWQVMSkYzjouMIUQyf6EMAZIhQxq9rduTs8Z2WwZlYgRP6AEqVuHNq7kBhLz98BaLXwW
         Xx0dOsaBtsNK4/4ZwmKCOlAkCQUIhXGYaCaqyGoEAFN6uTRWy0VZXS5dj6+rp68TExFR
         66tIlrEhpc5h7/MzWASerLdiGVZiSkxKNa9bnYa+8h/aRHeV49lDzqBiv0aiysneAWbr
         ZeEu2+6frharI4zULziptPuWE2JxLI055Fxp5kpElCN2MdU2gYfgD9A7rbTefw8PLH+d
         RacA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=hr9DzLw8;
       spf=pass (google.com: domain of 3y4edyaokcuwo1r5scy19zu22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3y4EdYAoKCUwo1r5sCy19zu22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x44a.google.com (mail-wr1-x44a.google.com. [2a00:1450:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id r19si453490edq.5.2021.02.05.09.35.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 05 Feb 2021 09:35:08 -0800 (PST)
Received-SPF: pass (google.com: domain of 3y4edyaokcuwo1r5scy19zu22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) client-ip=2a00:1450:4864:20::44a;
Received: by mail-wr1-x44a.google.com with SMTP id x12so5712752wrw.21
        for <kasan-dev@googlegroups.com>; Fri, 05 Feb 2021 09:35:08 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:edb8:b79c:2e20:e531])
 (user=andreyknvl job=sendgmr) by 2002:a1c:3185:: with SMTP id
 x127mr4375625wmx.117.1612546507585; Fri, 05 Feb 2021 09:35:07 -0800 (PST)
Date: Fri,  5 Feb 2021 18:34:41 +0100
In-Reply-To: <cover.1612546384.git.andreyknvl@google.com>
Message-Id: <cbcf7b02be0a1ca11de4f833f2ff0b3f2c9b00c8.1612546384.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1612546384.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.30.0.365.g02bc693789-goog
Subject: [PATCH v3 mm 07/13] kasan, mm: fail krealloc on freed objects
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
 header.i=@google.com header.s=20161025 header.b=hr9DzLw8;       spf=pass
 (google.com: domain of 3y4edyaokcuwo1r5scy19zu22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3y4EdYAoKCUwo1r5sCy19zu22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--andreyknvl.bounces.google.com;
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
the old one as ksize() returns 0. This makes the caller believe that
krealloc() succeeded (KASAN report is printed though).

This patch adds an accessibility check into __do_krealloc(). If the check
fails, krealloc() returns NULL. This check duplicates the one in ksize();
this is fixed in the following patch.

This patch also adds a KASAN-KUnit test to check krealloc() behaviour
when it's called on a freed object.

Reviewed-by: Marco Elver <elver@google.com>
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 lib/test_kasan.c | 20 ++++++++++++++++++++
 mm/slab_common.c |  3 +++
 2 files changed, 23 insertions(+)

diff --git a/lib/test_kasan.c b/lib/test_kasan.c
index ffebad2f0e6e..1328c468fdb5 100644
--- a/lib/test_kasan.c
+++ b/lib/test_kasan.c
@@ -353,6 +353,25 @@ static void krealloc_pagealloc_less_oob(struct kunit *test)
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
@@ -1050,6 +1069,7 @@ static struct kunit_case kasan_kunit_test_cases[] = {
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/cbcf7b02be0a1ca11de4f833f2ff0b3f2c9b00c8.1612546384.git.andreyknvl%40google.com.
