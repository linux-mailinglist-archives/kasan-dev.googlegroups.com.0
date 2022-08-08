Return-Path: <kasan-dev+bncBC5JXFXXVEGRB7GPYGLQMGQE4EJ63ZQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x340.google.com (mail-wm1-x340.google.com [IPv6:2a00:1450:4864:20::340])
	by mail.lfdr.de (Postfix) with ESMTPS id BE14058BEE5
	for <lists+kasan-dev@lfdr.de>; Mon,  8 Aug 2022 03:33:48 +0200 (CEST)
Received: by mail-wm1-x340.google.com with SMTP id a17-20020a05600c349100b003a545125f6esf317282wmq.4
        for <lists+kasan-dev@lfdr.de>; Sun, 07 Aug 2022 18:33:48 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1659922428; cv=pass;
        d=google.com; s=arc-20160816;
        b=TiPs2ReJq60M6dpkc/p2oJcD8ALX1Iq4sFTrUquZJCqI7JCpc4YKYVJnw1xEeBymKv
         ufnE38iIcaoLkLvKT22PYv2jgsjrZYQrvt1b+oGYFNzk8IHB1FQvjwyO/4vM68lQiM9G
         Ihua90KL6IKfSauU7Lq/FblntYAPn8PVA1j4bY/3G6dSMHYKfFMEZAXqDExHyMe4D3ZO
         yg8jW4Rf9jpxM5g8w3hSj7lBbMhEAmBP/j3lBwTBWunYZ6BfSzHTNqhn6lJMP020rcq+
         fQAjyhgXV31TEd2tSJLK1fSR3FyC5Drvk3PbAKXOCcc8sHFvz2nY67vdXNY/lTTQwopo
         LHRQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=Y/j0ymwNgGSA3iUOHiu5GYwTwQSIXRR1PkX8fspID0Y=;
        b=xeB6InseoKbyQ765FrclJirvCnRu/NfHDaKv3rOJpCbKetTonoEnZ3F1RLUjJelOM1
         oLXvfdAumz4oopmKcXqhRAMsfqUBVzxytnSvBhTAoxkL4+6R6BzbvBVA5t7PVxXWEl4M
         jt1dgBdwaxSkDJpBr6sFyEgZH4rfjEtDOyD9zUbeDOVsXrmGiFuJLmskGvyFu36o7Sy8
         O2m+5GDpId7VGLkcbjedey7xbQZ9fWFflRVInwepL2v2DO6H5FuRIJ6JujKN2ov+x0m8
         dz5nOB3pY/lvUT90v0bXZfU0TiPVlPxmJbTpq/+nEeBHiJ8Gb0LF2DWGBNSt8r42soyH
         M9JA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=VYhjA4VU;
       spf=pass (google.com: domain of sashal@kernel.org designates 145.40.68.75 as permitted sender) smtp.mailfrom=sashal@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc;
        bh=Y/j0ymwNgGSA3iUOHiu5GYwTwQSIXRR1PkX8fspID0Y=;
        b=JRep5IHa8y/w0nGj5qSS3Ss/EVRjpob0Li6B7GLQeUBgpRzci1vejyJ6esZUXjiGDE
         8al7pKNTYqt8VIq5a6KjCjAwPyZn5OO+6Ib42k81DgH5xETl010E7u2Kfxj8G/+NBJwP
         S1lyuLsoHOQdJhXft5Z6wxiYaAQZJOsNtQlFuNcMRNMc9N3N0Jys3VAHRt9F3LdHN2lw
         TKYT9mX10q/0gi27I9RyJJ5QiGeFQH6VEIeJqZJ+xeh+uIHNs9QrBGPkzKegXo0BwNC/
         xEMzgR2Aj71v5jjTv07XthhonUTAzdP6ACT9LXZhL4xaOH5Z+RpqaklPhU89CfI9ZqPu
         ky9Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:sender:from:to:cc;
        bh=Y/j0ymwNgGSA3iUOHiu5GYwTwQSIXRR1PkX8fspID0Y=;
        b=uiMpIEbFwZRnnXzp2P50XTQJpjvI6TsgNzC+FACCXjQA2bzECodHzNEK0nuaNN+in7
         OlTbQohl3fjba7ms2cbMPXBKm4qCLTDPrTfYgBhQPtj1I/EL+nvrmxf/Ze7KRpgdb3+B
         pkdtOUEqGnq+KEzk4shW53EsdCDlbOtPzIo9SMrPj/qY0r06zGViQLLZ5AIK83VuG+U6
         e8wxnLDeC9gsYwpBXPP71Pvb91IspevwKng9UXkvjTbgj3OqYAez7ZK7XmiDaxlGuhDh
         owtUJidC/JeW/LOzHwtYJzZQoXE2vkihHj3D8OhmDmBsEaWFrA/85ZW64VOgCTs4hVwM
         jIlg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo07pFLxxNsF465Gzs43rnc8TMmeZHtBEHdE2SLpxg0L1rGADO6U
	2R6cWyhyGACFrFUIbvbxqxE=
X-Google-Smtp-Source: AA6agR6nUd7IkxokYK+FmUCmU/xhxhEE4QzaRv3/IFAvC+c1GZjgL/TOoZFlZqi0s+co7nL1c6SK3A==
X-Received: by 2002:a1c:7508:0:b0:3a5:923:3994 with SMTP id o8-20020a1c7508000000b003a509233994mr10750484wmc.173.1659922428199;
        Sun, 07 Aug 2022 18:33:48 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a7b:c5d1:0:b0:397:344c:c4f3 with SMTP id n17-20020a7bc5d1000000b00397344cc4f3ls3100074wmk.2.-pod-prod-gmail;
 Sun, 07 Aug 2022 18:33:47 -0700 (PDT)
X-Received: by 2002:a05:600c:35c7:b0:3a3:2612:f823 with SMTP id r7-20020a05600c35c700b003a32612f823mr10772170wmq.33.1659922426919;
        Sun, 07 Aug 2022 18:33:46 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1659922426; cv=none;
        d=google.com; s=arc-20160816;
        b=Vm/oTbVWhrhfge18KrQOrhJYbn6A/XkPqJeNIoH0hCenyx+PrDZ3tJuf8cpVfhU80R
         ABEz4dSQewE6nIoPcD/9M/n9ePBsM6JDQGCKfeHFpvncSPsoMHpr/bhoxNVmyanRRdXf
         6aXCCoB31QuyA6PCSnD9jzApapVhicGoNS6VNVNuEFangJEEm8/fNTjXixepJfTPhH9d
         jMZmqbiQlUkIIr9Y5QGEs9vrD4N6SHsq1NhO3V5oVolL/QIf8IO+tnzsWpgN45oKMjAW
         FRsjKRd1pJlyosoV+FimcEG/hsyPNLyMac1EquTuP2au/lj4jCwM7QjxCH1ISCLjf0W1
         KaVA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=gEsiCc1uHZf2iIl1jS/mS/QK/9xcwoIBVTzboVIh2IQ=;
        b=vYRHRVxaYhW1HPc/YBC4M3Su1gqyCszivV/7tSSMXcDxLxW4zkGThSndDMnZNgxINH
         MoxiZ8iC65EtXIZnnohZRU9t6ptcAtMH7fEt6AHmZ7SShEQ+VHgG0DwkgxKZUrK3Z+a/
         O19EZxSqoLENlzii1UXUTKhKrA1lHbW2CkUIvxILiPtkuH57rHjQybjHHEpNqnU8KRL6
         X9yBmLu6IZcRjYxq8dpqfdlsuscAsn90kLVqurOzxOJwFN68yFSZB/py7/LCdnVdzaEd
         lARJ2DWpfostmJaLMAttSpYteREDcgv8IhmNLSLmmNHMqxPdPjwuh7L8bJr27ufbYBqv
         1eXA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=VYhjA4VU;
       spf=pass (google.com: domain of sashal@kernel.org designates 145.40.68.75 as permitted sender) smtp.mailfrom=sashal@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from ams.source.kernel.org (ams.source.kernel.org. [145.40.68.75])
        by gmr-mx.google.com with ESMTPS id u11-20020a056000038b00b0022068e0dba1si353643wrf.4.2022.08.07.18.33.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sun, 07 Aug 2022 18:33:46 -0700 (PDT)
Received-SPF: pass (google.com: domain of sashal@kernel.org designates 145.40.68.75 as permitted sender) client-ip=145.40.68.75;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ams.source.kernel.org (Postfix) with ESMTPS id A51DBB80E0D;
	Mon,  8 Aug 2022 01:33:46 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 04E9AC4314A;
	Mon,  8 Aug 2022 01:33:44 +0000 (UTC)
From: Sasha Levin <sashal@kernel.org>
To: linux-kernel@vger.kernel.org,
	stable@vger.kernel.org
Cc: Kees Cook <keescook@chromium.org>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	kasan-dev@googlegroups.com,
	Sasha Levin <sashal@kernel.org>
Subject: [PATCH AUTOSEL 5.19 57/58] kasan: test: Silence GCC 12 warnings
Date: Sun,  7 Aug 2022 21:31:15 -0400
Message-Id: <20220808013118.313965-57-sashal@kernel.org>
X-Mailer: git-send-email 2.35.1
In-Reply-To: <20220808013118.313965-1-sashal@kernel.org>
References: <20220808013118.313965-1-sashal@kernel.org>
MIME-Version: 1.0
X-stable: review
X-Patchwork-Hint: Ignore
X-Original-Sender: sashal@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=VYhjA4VU;       spf=pass
 (google.com: domain of sashal@kernel.org designates 145.40.68.75 as permitted
 sender) smtp.mailfrom=sashal@kernel.org;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=kernel.org
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

From: Kees Cook <keescook@chromium.org>

[ Upstream commit aaf50b1969d7933a51ea421b11432a7fb90974e3 ]

GCC 12 continues to get smarter about array accesses. The KASAN tests
are expecting to explicitly test out-of-bounds conditions at run-time,
so hide the variable from GCC, to avoid warnings like:

../lib/test_kasan.c: In function 'ksize_uaf':
../lib/test_kasan.c:790:61: warning: array subscript 120 is outside array bounds of 'void[120]' [-Warray-bounds]
  790 |         KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr)[size]);
      |                                       ~~~~~~~~~~~~~~~~~~~~~~^~~~~~
../lib/test_kasan.c:97:9: note: in definition of macro 'KUNIT_EXPECT_KASAN_FAIL'
   97 |         expression; \
      |         ^~~~~~~~~~

Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>
Cc: Alexander Potapenko <glider@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>
Cc: Dmitry Vyukov <dvyukov@google.com>
Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>
Cc: kasan-dev@googlegroups.com
Signed-off-by: Kees Cook <keescook@chromium.org>
Link: https://lore.kernel.org/r/20220608214024.1068451-1-keescook@chromium.org
Signed-off-by: Sasha Levin <sashal@kernel.org>
---
 lib/test_kasan.c | 10 ++++++++++
 1 file changed, 10 insertions(+)

diff --git a/lib/test_kasan.c b/lib/test_kasan.c
index c233b1a4e984..58c1b01ccfe2 100644
--- a/lib/test_kasan.c
+++ b/lib/test_kasan.c
@@ -131,6 +131,7 @@ static void kmalloc_oob_right(struct kunit *test)
 	ptr = kmalloc(size, GFP_KERNEL);
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
 
+	OPTIMIZER_HIDE_VAR(ptr);
 	/*
 	 * An unaligned access past the requested kmalloc size.
 	 * Only generic KASAN can precisely detect these.
@@ -159,6 +160,7 @@ static void kmalloc_oob_left(struct kunit *test)
 	ptr = kmalloc(size, GFP_KERNEL);
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
 
+	OPTIMIZER_HIDE_VAR(ptr);
 	KUNIT_EXPECT_KASAN_FAIL(test, *ptr = *(ptr - 1));
 	kfree(ptr);
 }
@@ -171,6 +173,7 @@ static void kmalloc_node_oob_right(struct kunit *test)
 	ptr = kmalloc_node(size, GFP_KERNEL, 0);
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
 
+	OPTIMIZER_HIDE_VAR(ptr);
 	KUNIT_EXPECT_KASAN_FAIL(test, ptr[0] = ptr[size]);
 	kfree(ptr);
 }
@@ -191,6 +194,7 @@ static void kmalloc_pagealloc_oob_right(struct kunit *test)
 	ptr = kmalloc(size, GFP_KERNEL);
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
 
+	OPTIMIZER_HIDE_VAR(ptr);
 	KUNIT_EXPECT_KASAN_FAIL(test, ptr[size + OOB_TAG_OFF] = 0);
 
 	kfree(ptr);
@@ -271,6 +275,7 @@ static void kmalloc_large_oob_right(struct kunit *test)
 	ptr = kmalloc(size, GFP_KERNEL);
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
 
+	OPTIMIZER_HIDE_VAR(ptr);
 	KUNIT_EXPECT_KASAN_FAIL(test, ptr[size] = 0);
 	kfree(ptr);
 }
@@ -410,6 +415,8 @@ static void kmalloc_oob_16(struct kunit *test)
 	ptr2 = kmalloc(sizeof(*ptr2), GFP_KERNEL);
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr2);
 
+	OPTIMIZER_HIDE_VAR(ptr1);
+	OPTIMIZER_HIDE_VAR(ptr2);
 	KUNIT_EXPECT_KASAN_FAIL(test, *ptr1 = *ptr2);
 	kfree(ptr1);
 	kfree(ptr2);
@@ -756,6 +763,8 @@ static void ksize_unpoisons_memory(struct kunit *test)
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
 	real_size = ksize(ptr);
 
+	OPTIMIZER_HIDE_VAR(ptr);
+
 	/* This access shouldn't trigger a KASAN report. */
 	ptr[size] = 'x';
 
@@ -778,6 +787,7 @@ static void ksize_uaf(struct kunit *test)
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
 	kfree(ptr);
 
+	OPTIMIZER_HIDE_VAR(ptr);
 	KUNIT_EXPECT_KASAN_FAIL(test, ksize(ptr));
 	KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr)[0]);
 	KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr)[size]);
-- 
2.35.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220808013118.313965-57-sashal%40kernel.org.
