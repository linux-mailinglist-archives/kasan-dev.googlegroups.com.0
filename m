Return-Path: <kasan-dev+bncBDAOJ6534YNBBTFET64AMGQEZWOZXLA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x340.google.com (mail-wm1-x340.google.com [IPv6:2a00:1450:4864:20::340])
	by mail.lfdr.de (Postfix) with ESMTPS id 8B6D7998737
	for <lists+kasan-dev@lfdr.de>; Thu, 10 Oct 2024 15:10:38 +0200 (CEST)
Received: by mail-wm1-x340.google.com with SMTP id 5b1f17b1804b1-42cb374f0cdsf5442165e9.0
        for <lists+kasan-dev@lfdr.de>; Thu, 10 Oct 2024 06:10:38 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1728565838; cv=pass;
        d=google.com; s=arc-20240605;
        b=YqEJ0CVUu9IfGtReFwSt2RneoYR4g3oR4TcNDXuEW9Ywvq99TwjYzpkx5/2OqVRSnu
         qEdqQiMnaj7jfo1b0arFL/2MH1FZTCJf7gM61vhcGPcSgPGNvt9C1hZ38T1IFDx5Ajvv
         Ex74tTzGG58ObbcMQn9GWzL+f6VI0h+pmOryvGkLEX6fTOufnGial9vmo7J0n1LtifDv
         f4gGQAEUzUmnhguq5ER+EVSQz5W6DMu2YEmTO4Y90R5ud6mWnAGL62+Ug6ClBVg2mNfl
         FXz0/HhUh/ovMRLXHBvp+WBrthIdixLXG6c585vqqjxhZe7AD0vFYWCfshxvyaxWWW/d
         k33g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=dddodtdu6dA7ewUBfnYBhlHhGxpIrb2FxW2mrKxw2CM=;
        fh=vun/ycwrk5Qs5w4tgRUZFNnGDgcJ9WQUnLlndvZDwms=;
        b=X2R4XzBIq2zbLijYbGjmNVXXOCkWOriYjOssnn2b/fQP/63Yy4koG6w3ZU8OK/RZTq
         Ry7yzs4ZGoGouYf4hF9ESmxTWhBhxbal9dEfEZptZXlOfET4IITsvwXakB/ifSEAGHfx
         3sxaIcYmMj98EW6hlYCiLgl8upI909KEficcd1brUjLBeq6aYr1IYJ8pM09fnzq5vs88
         Qn8rANp//eLeiRbm6VsZlJNREQtVSA8ibsGkwE4g+VrLRKbngrG7u4LK2nMOxiuDQnHV
         Ps2CmJH7L45SSV8LKthad/yrNLV5jG+REg7WGA4Zrh/MXJhVi/lK9XOu4T3mpaUetUVP
         cU3w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=Mgz0V1gg;
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::133 as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1728565838; x=1729170638; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=dddodtdu6dA7ewUBfnYBhlHhGxpIrb2FxW2mrKxw2CM=;
        b=rigmUbaigVBtZddO1KWQiyijAbEHPd3fnQv7yKuQwUa0ShOEtl3IbZEsv7ldNLl1wW
         WkQeb/9aNwgOTxiWa4pPCDIR4x/YrN9egivutsKhO2xYldc2sKzxL2oLowmDvZdhXtOx
         NFQGIbxWUwNAqnFYRn8fJyumH0UtmWXDthf1mKCIvr/sMKpdoogMGcBWPkZJrntJ/26C
         g5SMY4PeXzQ+EDgfbv1G0JopRaz7WH+0wMrHVxz3JVX364sYnrPU5EJYpJXjAE3jQbHo
         jQaaLou2Db0YCEaGfRhsSztDgwAwz26nn6gj8N54SlZDkImKLXv3oC39iSer18mcthsK
         DHvw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1728565838; x=1729170638; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=dddodtdu6dA7ewUBfnYBhlHhGxpIrb2FxW2mrKxw2CM=;
        b=IjlJNVPju+EVcgYedlf1/S8kwXGkI0cXiZReF/nu2W+j1daubHt5CFv1lsvI6e/6ML
         rOJYb+KtvBOm4ztNJaePJ6HBRsmxHq0mThrHCDIog29IrACbYXCaftXqIk02I0t5jbH0
         PoxMnJPVsI2XJPu5wxgwsjEASXd86tR5Pn5Rh4+scp6wq5/wLUu3juRUgu69eAmdC8J9
         SDUbuXtUXdQbPwFp6kU+10uoUyhoqNqG3ypJeP8bWfqg5VBYqWhsAbacnkK+UmoZ94v+
         OTBCcPu1SbtWPuaZBc3omDplelMS3AJ6sfjhqgWUvVWrPaqLtrwCe63Gjaz3Ze48oPh8
         EjDw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1728565838; x=1729170638;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=dddodtdu6dA7ewUBfnYBhlHhGxpIrb2FxW2mrKxw2CM=;
        b=oLB0TU6s+v+sTPcGn3L0KOB7sr9LWvdHJjrqe37jsp5DqM/WBP5IzRRSolCQnANesV
         9TwwTzSol7MLriYOQNQzUS9vvCp22Ys5QhCm1XaaBrvK2V2edXAHKSvAM6uAED3WlovR
         2gjeTAtauc1vHHadZivm2texeQ6pGFO2KtTnAXnfvHL1HwXst/uA5JIZF14EMerBN8z4
         01MlbZJ1tlUMFErNLV5A+CuvqsjUxPT9yG8s06lAFzgwtOwOdf1JA6Qbbh7vso0LdSRB
         lPpFVX085j8HNrD+ez0x3tIW0Z4R5t/H5eXxVItBPE5XXeLOzDTwLbns5shAA9Tj/1hU
         vECQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVLB5qhhU+8I92IpscMts4zKHIJuwOl6M5dBXyK9AiYoLgdgNJIkv5uu3XlX7N9uXEyfOzMpw==@lfdr.de
X-Gm-Message-State: AOJu0Yx9HskgYpVAtYcL+ZR1y15rAown4JvnznGbhQY4sBuF1SyaFNj3
	F0/q9jJRJhtx23NcR6UPebza5Vzjj6sVyALEnA1ky+W55dDb9rwY
X-Google-Smtp-Source: AGHT+IFxFr15jk1eOr/fKYTrSLgdrijgjGoBB7PVX+nbVIoeqeqkpBYNqDjmePjIgIugNF1IeDvYwg==
X-Received: by 2002:a05:600c:4f14:b0:42c:b826:a26c with SMTP id 5b1f17b1804b1-43115aa7323mr27521045e9.8.1728565837007;
        Thu, 10 Oct 2024 06:10:37 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:5121:b0:42c:b037:5fb1 with SMTP id
 5b1f17b1804b1-43115fd9c61ls3752605e9.1.-pod-prod-00-eu; Thu, 10 Oct 2024
 06:10:35 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXb89Xmkc/Ci+A/fX2sjONEt8ZnWonQuRu2rTCTSuymg3/uBVAhCOuIbrfkiFc1yIoFCOSlpSXduRM=@googlegroups.com
X-Received: by 2002:a05:600c:4f14:b0:42c:b826:a26c with SMTP id 5b1f17b1804b1-43115aa7323mr27519885e9.8.1728565835055;
        Thu, 10 Oct 2024 06:10:35 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1728565835; cv=none;
        d=google.com; s=arc-20240605;
        b=X9qwVDJUV3MxDtNWT7EXL9zXsb5RJLS4IUnlUjnGSW7jiH2mjUTc8/Q4JF9RSvylBq
         ybOh2XFz3TydCYMDnIXLV9gQ6r17ozJ8MbIZ6TGuus/kojEA2c7pGKByWSf6QSIldJ1W
         s+9r0rbfupn+8DjCHNQYG0W/0gz/HAhySfzl778uEA6dssCFgyTorRl0DXiCN9BxRCjO
         sTQCjpJzAzac3iylNprU8mPyRQ0Tnt/b22fhNar/BrQkk+OrmdDF7lK98Qw75e5x4JhC
         frtedK8NZgFv46sGZ7dx2Fj/Gah3gXVpkBvNnvkA2I9WurgdMK6Hzy4GDukpGUI85nOI
         DVpA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=OuJiu2A9K3F7RxlNpRBbTBdPuLTp339ni2HcpWnX9u0=;
        fh=2l1VSvDPewi84gC3snNuTJcCjx+P9M+Di0HBltquZr8=;
        b=iyhNxY1h3AHoXgfKCuVmhGxomDoC8fIqVZ6ypTMjzOz6ceVasD7o6jgrm5p6BkcnWd
         cx6MV9GcQ0J+uiAXLilfkWZIzok82dxmkZINQjoUaqMPSClDKB3Xs5HVBm9AdZ+WINo/
         1Ov+DV6/OT64CMea+vOw4bPa7Q7EA6mPzPflfeC2fIa01eWBHcbDOgpEUFq1+Lt0Cr6t
         eOqckVF2ZhIydyFPHTfeROoa6HrqvUnl/LLzpd3eW0mj8p6+lc+WB2pff+DXnu3T9Chs
         br9i5sNYoXbpVZ8OKLxSkhkX/caZkkmS5TlXrn9FXEE5dOfZL4rU9t9GdpgVNhMQ4iyz
         oirQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=Mgz0V1gg;
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::133 as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-lf1-x133.google.com (mail-lf1-x133.google.com. [2a00:1450:4864:20::133])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-37d4b778841si25846f8f.3.2024.10.10.06.10.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 10 Oct 2024 06:10:35 -0700 (PDT)
Received-SPF: pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::133 as permitted sender) client-ip=2a00:1450:4864:20::133;
Received: by mail-lf1-x133.google.com with SMTP id 2adb3069b0e04-5398e58ceebso846644e87.0
        for <kasan-dev@googlegroups.com>; Thu, 10 Oct 2024 06:10:35 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXrY9ZGMMIjQO08N5dnLeDZ4AuFu0tyKsq2CvoIia9njuiMT6Ltht2Ly61CGm1vyBKDlNf6ARu/R2o=@googlegroups.com
X-Received: by 2002:a05:6512:3d10:b0:539:933c:51c6 with SMTP id 2adb3069b0e04-539c9895961mr1182236e87.29.1728565833803;
        Thu, 10 Oct 2024 06:10:33 -0700 (PDT)
Received: from work.. (2.133.25.254.dynamic.telecom.kz. [2.133.25.254])
        by smtp.gmail.com with ESMTPSA id 2adb3069b0e04-539cb8d800esm248596e87.126.2024.10.10.06.10.31
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 10 Oct 2024 06:10:33 -0700 (PDT)
From: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
To: elver@google.com
Cc: akpm@linux-foundation.org,
	andreyknvl@gmail.com,
	bpf@vger.kernel.org,
	dvyukov@google.com,
	glider@google.com,
	kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org,
	linux-mm@kvack.org,
	ryabinin.a.a@gmail.com,
	snovitoll@gmail.com,
	syzbot+61123a5daeb9f7454599@syzkaller.appspotmail.com,
	vincenzo.frascino@arm.com
Subject: [PATCH v5] mm, kasan, kmsan: copy_from/to_kernel_nofault
Date: Thu, 10 Oct 2024 18:11:30 +0500
Message-Id: <20241010131130.2903601-1-snovitoll@gmail.com>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <CANpmjNNPnEMBxF1-Lr_BACmPYxOTRa=k6Vwi=EFR=BED=G8akg@mail.gmail.com>
References: <CANpmjNNPnEMBxF1-Lr_BACmPYxOTRa=k6Vwi=EFR=BED=G8akg@mail.gmail.com>
MIME-Version: 1.0
X-Original-Sender: snovitoll@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=Mgz0V1gg;       spf=pass
 (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::133
 as permitted sender) smtp.mailfrom=snovitoll@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
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

Instrument copy_from_kernel_nofault() with KMSAN for uninitialized kernel
memory check and copy_to_kernel_nofault() with KASAN, KCSAN to detect
the memory corruption.

syzbot reported that bpf_probe_read_kernel() kernel helper triggered
KASAN report via kasan_check_range() which is not the expected behaviour
as copy_from_kernel_nofault() is meant to be a non-faulting helper.

Solution is, suggested by Marco Elver, to replace KASAN, KCSAN check in
copy_from_kernel_nofault() with KMSAN detection of copying uninitilaized
kernel memory. In copy_to_kernel_nofault() we can retain
instrument_write() explicitly for the memory corruption instrumentation.

copy_to_kernel_nofault() is tested on x86_64 and arm64 with
CONFIG_KASAN_SW_TAGS. On arm64 with CONFIG_KASAN_HW_TAGS,
kunit test currently fails. Need more clarification on it.

Link: https://lore.kernel.org/linux-mm/CANpmjNMAVFzqnCZhEity9cjiqQ9CVN1X7qeeeAp_6yKjwKo8iw@mail.gmail.com/
Reviewed-by: Marco Elver <elver@google.com>
Suggested-by: Marco Elver <elver@google.com>
Reported-by: syzbot+61123a5daeb9f7454599@syzkaller.appspotmail.com
Closes: https://syzkaller.appspot.com/bug?extid=61123a5daeb9f7454599
Reported-by: Andrey Konovalov <andreyknvl@gmail.com>
Closes: https://bugzilla.kernel.org/show_bug.cgi?id=210505
Signed-off-by: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
---
v2:
- squashed previous submitted in -mm tree 2 patches based on Linus tree
v3:
- moved checks to *_nofault_loop macros per Marco's comments
- edited the commit message
v4:
- replaced Suggested-by with Reviewed-by
v5:
- addressed Andrey's comment on deleting CONFIG_KASAN_HW_TAGS check in
  mm/kasan/kasan_test_c.c
- added explanatory comment in kasan_test_c.c
- added Suggested-by: Marco Elver back per Andrew's comment.
---
 mm/kasan/kasan_test_c.c | 37 +++++++++++++++++++++++++++++++++++++
 mm/kmsan/kmsan_test.c   | 17 +++++++++++++++++
 mm/maccess.c            | 10 ++++++++--
 3 files changed, 62 insertions(+), 2 deletions(-)

diff --git a/mm/kasan/kasan_test_c.c b/mm/kasan/kasan_test_c.c
index a181e4780d9d..cb6ad84641ec 100644
--- a/mm/kasan/kasan_test_c.c
+++ b/mm/kasan/kasan_test_c.c
@@ -1954,6 +1954,42 @@ static void rust_uaf(struct kunit *test)
 	KUNIT_EXPECT_KASAN_FAIL(test, kasan_test_rust_uaf());
 }
 
+static void copy_to_kernel_nofault_oob(struct kunit *test)
+{
+	char *ptr;
+	char buf[128];
+	size_t size = sizeof(buf);
+
+	/* This test currently fails with the HW_TAGS mode.
+	 * The reason is unknown and needs to be investigated. */
+	ptr = kmalloc(size - KASAN_GRANULE_SIZE, GFP_KERNEL);
+	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
+	OPTIMIZER_HIDE_VAR(ptr);
+
+	if (IS_ENABLED(CONFIG_KASAN_SW_TAGS)) {
+		/* Check that the returned pointer is tagged. */
+		KUNIT_EXPECT_GE(test, (u8)get_tag(ptr), (u8)KASAN_TAG_MIN);
+		KUNIT_EXPECT_LT(test, (u8)get_tag(ptr), (u8)KASAN_TAG_KERNEL);
+	}
+
+	/*
+	* We test copy_to_kernel_nofault() to detect corrupted memory that is
+	* being written into the kernel. In contrast, copy_from_kernel_nofault()
+	* is primarily used in kernel helper functions where the source address
+	* might be random or uninitialized. Applying KASAN instrumentation to
+	* copy_from_kernel_nofault() could lead to false positives.
+	* By focusing KASAN checks only on copy_to_kernel_nofault(),
+	* we ensure that only valid memory is written to the kernel,
+	* minimizing the risk of kernel corruption while avoiding
+	* false positives in the reverse case.
+	*/
+	KUNIT_EXPECT_KASAN_FAIL(test,
+		copy_to_kernel_nofault(&buf[0], ptr, size));
+	KUNIT_EXPECT_KASAN_FAIL(test,
+		copy_to_kernel_nofault(ptr, &buf[0], size));
+	kfree(ptr);
+}
+
 static struct kunit_case kasan_kunit_test_cases[] = {
 	KUNIT_CASE(kmalloc_oob_right),
 	KUNIT_CASE(kmalloc_oob_left),
@@ -2027,6 +2063,7 @@ static struct kunit_case kasan_kunit_test_cases[] = {
 	KUNIT_CASE(match_all_not_assigned),
 	KUNIT_CASE(match_all_ptr_tag),
 	KUNIT_CASE(match_all_mem_tag),
+	KUNIT_CASE(copy_to_kernel_nofault_oob),
 	KUNIT_CASE(rust_uaf),
 	{}
 };
diff --git a/mm/kmsan/kmsan_test.c b/mm/kmsan/kmsan_test.c
index 13236d579eba..9733a22c46c1 100644
--- a/mm/kmsan/kmsan_test.c
+++ b/mm/kmsan/kmsan_test.c
@@ -640,6 +640,22 @@ static void test_unpoison_memory(struct kunit *test)
 	KUNIT_EXPECT_TRUE(test, report_matches(&expect));
 }
 
+static void test_copy_from_kernel_nofault(struct kunit *test)
+{
+	long ret;
+	char buf[4], src[4];
+	size_t size = sizeof(buf);
+
+	EXPECTATION_UNINIT_VALUE_FN(expect, "copy_from_kernel_nofault");
+	kunit_info(
+		test,
+		"testing copy_from_kernel_nofault with uninitialized memory\n");
+
+	ret = copy_from_kernel_nofault((char *)&buf[0], (char *)&src[0], size);
+	USE(ret);
+	KUNIT_EXPECT_TRUE(test, report_matches(&expect));
+}
+
 static struct kunit_case kmsan_test_cases[] = {
 	KUNIT_CASE(test_uninit_kmalloc),
 	KUNIT_CASE(test_init_kmalloc),
@@ -664,6 +680,7 @@ static struct kunit_case kmsan_test_cases[] = {
 	KUNIT_CASE(test_long_origin_chain),
 	KUNIT_CASE(test_stackdepot_roundtrip),
 	KUNIT_CASE(test_unpoison_memory),
+	KUNIT_CASE(test_copy_from_kernel_nofault),
 	{},
 };
 
diff --git a/mm/maccess.c b/mm/maccess.c
index 518a25667323..3ca55ec63a6a 100644
--- a/mm/maccess.c
+++ b/mm/maccess.c
@@ -13,9 +13,14 @@ bool __weak copy_from_kernel_nofault_allowed(const void *unsafe_src,
 	return true;
 }
 
+/*
+ * The below only uses kmsan_check_memory() to ensure uninitialized kernel
+ * memory isn't leaked.
+ */
 #define copy_from_kernel_nofault_loop(dst, src, len, type, err_label)	\
 	while (len >= sizeof(type)) {					\
-		__get_kernel_nofault(dst, src, type, err_label);		\
+		__get_kernel_nofault(dst, src, type, err_label);	\
+		kmsan_check_memory(src, sizeof(type));			\
 		dst += sizeof(type);					\
 		src += sizeof(type);					\
 		len -= sizeof(type);					\
@@ -49,7 +54,8 @@ EXPORT_SYMBOL_GPL(copy_from_kernel_nofault);
 
 #define copy_to_kernel_nofault_loop(dst, src, len, type, err_label)	\
 	while (len >= sizeof(type)) {					\
-		__put_kernel_nofault(dst, src, type, err_label);		\
+		__put_kernel_nofault(dst, src, type, err_label);	\
+		instrument_write(dst, sizeof(type));			\
 		dst += sizeof(type);					\
 		src += sizeof(type);					\
 		len -= sizeof(type);					\
-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20241010131130.2903601-1-snovitoll%40gmail.com.
