Return-Path: <kasan-dev+bncBDAOJ6534YNBBEMMSS4AMGQEL5TFNWI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x339.google.com (mail-wm1-x339.google.com [IPv6:2a00:1450:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id 9251E99451C
	for <lists+kasan-dev@lfdr.de>; Tue,  8 Oct 2024 12:14:43 +0200 (CEST)
Received: by mail-wm1-x339.google.com with SMTP id 5b1f17b1804b1-42cb236ad4asf33328365e9.3
        for <lists+kasan-dev@lfdr.de>; Tue, 08 Oct 2024 03:14:43 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1728382483; cv=pass;
        d=google.com; s=arc-20240605;
        b=baMm66+3JHjJ1yr4VLxecI2hfrgkQ6OCeJI9bH76Ka8Q4qAduWmjtlzlKStmyd8T69
         1A/E/UNKuNvvWCqCuiF1MRc57CHUKQMZFbfRXKwpB7F3VgiXD19v5M9XVnV8wApsE0jb
         kuWSozqhYqKUbgalRqvydUoj0Jr0orDd32JWcVmYihxD15356PM2di0sX5EXnLVp9RHn
         jgjGphDYd9aCz5JWy1iXbiBQLnxHTyfMKzarOjR/+RTgvedg7FfP6xwd+iK1AaxEZlxR
         EBYrRZ6LZBTwQojm0UPPLHEoFPlTZ9qLAfrpKI2hO8M8hCrtQo53sl/6L91IeZgqpzyV
         YuYQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=OKyX06n5SO+9jcvT41d43yUmqsw1ODci+fj7eAcF2eU=;
        fh=z/8SZvbNFfiUbBXS/Uf/Z6z1l7m/lZp5rhQ326vAJjE=;
        b=HKZp3PBGRhBBjoMPenfJyo9dMZh2cfZAi/9+Gs7DlASYo89/KL/L03FVZbKLEzVby2
         5SQNYgPVaTjmveR20GwFB9b8Ay20i6vAe+HNCrZus81YdLkUkXp+cDHqjX/JD/3AHe0/
         pdRoXPKWnwPAQlLVMTW1mqMqQqH6/g7lqwsC4w1ar9DmSXPKtMRyN6B63Ppb0DDmRR09
         4tLTS+gbzi6pPa3XCEaBZVojSK/7Z6JuCixKdVQl/0bqwtLeg4xi+rtqSQCM66zkpA66
         6AlsfG0vq+HRCU6u5cG2giwMGEVM2pePG3TCWxKbCBilrY/RfW+/s+hXghAY3uInLH/2
         +QVg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="IGNSEJ7/";
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::32b as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1728382483; x=1728987283; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=OKyX06n5SO+9jcvT41d43yUmqsw1ODci+fj7eAcF2eU=;
        b=dAxKJ4XF3OWZp5Xa/zw06kO5s3lbpNmjxyqTNm8+uVRbpTNlbndJkWSbXhni0O9sbs
         FiCznhSiGVA7mwj4JRpKTeKG0QwDMtdwM2WAfDmnAwigfSsN37V/1ZI92cVnKok/ISRN
         SDxR9QmC7DO6IfbbCuZk18TCrlptB7Q+LG81pta4qpvK6bdUSgZUkjQIicoVM8ueUZbY
         0hrWzE2kH86sJz62M7fHoPXYTFvDQIVdEGAcMToPCFv5mdkOnRSvU/btqcGsQ0Ep6jQ+
         1f87TX22c2WLz0vFmI+WoUxpZUNfpSxE2uVFTfvB/6d+5hhkesfyC2jHnPlYC77rpH/+
         nvng==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1728382483; x=1728987283; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=OKyX06n5SO+9jcvT41d43yUmqsw1ODci+fj7eAcF2eU=;
        b=KJGUnxf3DY996A3GwREA4tNFF08nEf7KkNPvffSvnqPqopLV/80S/Y7BsduULcDr+W
         cYAcY+xTl8XkCIoXPTMSyqA8Xbb86WNzh+TPs+3RkXC98qDsqM9LQYQVVjHz6iPWItB8
         ax8T44dX3afgClbNt4yo5vKsqClUyqHFGPuf72dtZKDGLeg/DyAJkrDBSWT62jecqQAG
         QTrVmij4hcsnfSYuYrZU9ncLYP4FJYe/R1+dSqmMOzhFKq/2LmDfM04Q9RbN6ZtTG2HO
         2h58wZJ3E+mTTCWlO3NlBWtT9dI/d9p/nI3EAnLZA2QeB7Gtj4/kD9bNnvC4LyXBeTE7
         ifaQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1728382483; x=1728987283;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=OKyX06n5SO+9jcvT41d43yUmqsw1ODci+fj7eAcF2eU=;
        b=W7ZN+TNsaAobwTI2IWdedNSYsiDBXnr/SC/1wN11JrgMfDfDkgZPuaG3s7MKi8sJ6B
         2dv3neKMKlRpyjVR+3s68tdMIff6L5h75DiJIQaN7ggJ1LplFmndcVI83A7m+QMkphRw
         jGBb0KAAwVbqH554XFdfXNHy0A4r/BUBQLmWLVFtH2ce1coqxyS49Hd4/ppp6bEA2Ux9
         o06VAX8xpnlsBbMarps4+pDF/jI0mA2T/9yZsFSG+4JwmHDW+KMkNUTNDLwCEJsjktAd
         cLSOrCNWxm6DZE0VNXIp845ukHPOwxT5XqkaZbqJ5JXfQaCZNEIiP0OJm/3MRKgfQyrr
         45xw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXpbntRNW/cj+sXTqJTtZ0pl9qa+D3eD2D/YvF+F6A+vs9aVIYEIhoCqEjvpN5CwrtSPn+odQ==@lfdr.de
X-Gm-Message-State: AOJu0Yxh+5QA636SpLPfvF3gx/b/anuBOZ8x5uqsD18Qf6MzfEM4JWQA
	umPL8KORhPOQ5K2fQkdKtKP4V9PY/uDexXJ2tRrNkOFbOGdi+2tD
X-Google-Smtp-Source: AGHT+IE1AtrPfPAcVuh45xUgUV5fMAiXLaTnbiIP16CRFfUWI1v1IbZ5UFCJ2etPw4o6yIu7UkpSqQ==
X-Received: by 2002:a05:600c:1daa:b0:42f:8515:e482 with SMTP id 5b1f17b1804b1-42f85ab59b8mr118117585e9.9.1728382481929;
        Tue, 08 Oct 2024 03:14:41 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:3147:b0:430:5356:acb2 with SMTP id
 5b1f17b1804b1-4305356b020ls1730185e9.0.-pod-prod-08-eu; Tue, 08 Oct 2024
 03:14:40 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXyfrl6fdlgoDTYS8n+MfUzMTdRYRZeoiFYrV+nd5jusLwoizUUlH7z4cAAVNzBGc0Igzt9a4TAoI8=@googlegroups.com
X-Received: by 2002:a05:600c:548a:b0:425:7bbf:fd07 with SMTP id 5b1f17b1804b1-42f85aa3c1dmr120154055e9.5.1728382479870;
        Tue, 08 Oct 2024 03:14:39 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1728382479; cv=none;
        d=google.com; s=arc-20240605;
        b=leG0pCvBWunPpX6qmSdXsAoeQWFEcjucw9Yj3p3j4wJHHqN/uRehlzWBJv/eo3kcWO
         BoXrQc+djsUmC/3vomU3qPjM2cKlqcSk/nnXN+vskIv1aCh26LvxVL/8NyeHzcCZyxDO
         FoIZFjf+GNUUo0OiEg8rC485GnUCmOARJa6GhbAnwfsvKMSOEPRgP8kyn/d6DHVSfb92
         LuqFzVC1Ro2V2QCTCzy9Dpj+sCANfjm/uS1QB1CDEGihNo/EFCIue+/RCCpNm/BMe/i0
         c+icBnLU1LP24P7Rz5KHu+VejW3v2PAKidakC99tb4Hk3KiEa2sP+EQ1bAc55cqkWY7r
         /hQg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=Imn45k5J9wM19h9i9/RuyLoAF2diDSxFA12TsgI6H5w=;
        fh=8B1XQn8qCuhkh8n3OGRoTvHcrjeOEDWguvyLgwpMFV8=;
        b=AxUV8zdW98E9OQj//44b39U/xYMLhg4ysZZ+GMlAMPc0vzELMC4zbaALEwgJlNtk+Y
         JhM+RW2VQtFrkzfS2YKPk3hNdhz4QQXMvwlmjCUECYbzG0D8Fe05JrH0l5ezTOjHq+GG
         5b9+COIs0rgC+YpMDxiA5NXjDbFcMebMeHsYNfnel1D5lxk+IcO3qRsxxN6Ug7vHjFPD
         8nwrk4SUnHv4vCGakgIFqQtkUMggcSHv1F/nC7dH/Unj3AayNcWnQDVEmZpkq/+QwqkQ
         QXHE98L4Xt0MZZfqSj+4DSWpV2wK0TnroYdeNmA7elDqL+dx5906xPp6U1LZU4OBVKGT
         Op9g==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="IGNSEJ7/";
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::32b as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x32b.google.com (mail-wm1-x32b.google.com. [2a00:1450:4864:20::32b])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-43053f83cf9si541625e9.0.2024.10.08.03.14.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 08 Oct 2024 03:14:39 -0700 (PDT)
Received-SPF: pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::32b as permitted sender) client-ip=2a00:1450:4864:20::32b;
Received: by mail-wm1-x32b.google.com with SMTP id 5b1f17b1804b1-42ca4e0299eso48508815e9.2
        for <kasan-dev@googlegroups.com>; Tue, 08 Oct 2024 03:14:39 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUfK6XyIZKlZhcU0BudMcUnYjTqR1hHd7t63m6PRo+PWwEiRMDftx31Fq+5IegovZDGXstWhIqkl7g=@googlegroups.com
X-Received: by 2002:a05:600c:4f14:b0:42b:a88f:f872 with SMTP id 5b1f17b1804b1-42f85af5387mr96155965e9.32.1728382479035;
        Tue, 08 Oct 2024 03:14:39 -0700 (PDT)
Received: from work.. ([94.200.20.179])
        by smtp.gmail.com with ESMTPSA id 5b1f17b1804b1-42f89e89624sm103790585e9.12.2024.10.08.03.14.35
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 08 Oct 2024 03:14:38 -0700 (PDT)
From: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
To: elver@google.com,
	akpm@linux-foundation.org
Cc: andreyknvl@gmail.com,
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
Subject: [PATCH v3] mm, kasan, kmsan: copy_from/to_kernel_nofault
Date: Tue,  8 Oct 2024 15:15:26 +0500
Message-Id: <20241008101526.2591147-1-snovitoll@gmail.com>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <CACzwLxh1yWXQZ4LAO3gFMjK8KPDFfNOR6wqWhtXyucJ0+YXurw@mail.gmail.com>
References: <CACzwLxh1yWXQZ4LAO3gFMjK8KPDFfNOR6wqWhtXyucJ0+YXurw@mail.gmail.com>
MIME-Version: 1.0
X-Original-Sender: snovitoll@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b="IGNSEJ7/";       spf=pass
 (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::32b
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
kunit test currently fails. Need more clarification on it
- currently, disabled in kunit test.

Link: https://lore.kernel.org/linux-mm/CANpmjNMAVFzqnCZhEity9cjiqQ9CVN1X7qeeeAp_6yKjwKo8iw@mail.gmail.com/
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
---
 mm/kasan/kasan_test_c.c | 27 +++++++++++++++++++++++++++
 mm/kmsan/kmsan_test.c   | 17 +++++++++++++++++
 mm/maccess.c            | 10 ++++++++--
 3 files changed, 52 insertions(+), 2 deletions(-)

diff --git a/mm/kasan/kasan_test_c.c b/mm/kasan/kasan_test_c.c
index a181e4780d9d..5cff90f831db 100644
--- a/mm/kasan/kasan_test_c.c
+++ b/mm/kasan/kasan_test_c.c
@@ -1954,6 +1954,32 @@ static void rust_uaf(struct kunit *test)
 	KUNIT_EXPECT_KASAN_FAIL(test, kasan_test_rust_uaf());
 }
 
+static void copy_to_kernel_nofault_oob(struct kunit *test)
+{
+	char *ptr;
+	char buf[128];
+	size_t size = sizeof(buf);
+
+	/* Not detecting fails currently with HW_TAGS */
+	KASAN_TEST_NEEDS_CONFIG_OFF(test, CONFIG_KASAN_HW_TAGS);
+
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
@@ -2027,6 +2053,7 @@ static struct kunit_case kasan_kunit_test_cases[] = {
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20241008101526.2591147-1-snovitoll%40gmail.com.
