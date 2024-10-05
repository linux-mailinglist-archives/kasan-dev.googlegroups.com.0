Return-Path: <kasan-dev+bncBDAOJ6534YNBBJO3QW4AMGQEUVFBXVA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13c.google.com (mail-lf1-x13c.google.com [IPv6:2a00:1450:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id 05447991868
	for <lists+kasan-dev@lfdr.de>; Sat,  5 Oct 2024 18:47:36 +0200 (CEST)
Received: by mail-lf1-x13c.google.com with SMTP id 2adb3069b0e04-539947ac1e8sf2920700e87.2
        for <lists+kasan-dev@lfdr.de>; Sat, 05 Oct 2024 09:47:35 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1728146855; cv=pass;
        d=google.com; s=arc-20240605;
        b=JahTFRwl9DBJUxgAx7OCusGYAQ+Uvo7GN7RcTq2u1jguKjeTFJMBRWUqCJj+pCWZZ1
         XL7NvtJaEPv2biZXp14ZNk0J0HKTylctK9RPLv9q9ajF/Bw7wBdluVXN6x3r44ISntm3
         u/30npT3WbX1EFEpiYgMlYsIIARB7jyWzG/NHs6CEij2ZN5mql6W8NYkzHEDb10dvnXC
         oO+JMHfEyS+62eBTzlFud9dnwaemyHmFPmdiRVclff0lxuwHR+/IYh11kBJvUQSIPAWr
         BUlh7pmgiHcmoZYYx+OQ1D6HFfFpzPnOpguj2Aotsh/boYE4w7+6nXnuN2BW4DT5Luj6
         Uzww==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=PBBkyCFa1ezocYuPiIP+jBiZWSHoJ1+vIvK9MjxRuF8=;
        fh=8eRB1U7sy7ldwXQ8y6C5+a/AmtGp3tbv735bSMccybE=;
        b=LL5rhQGMfsP3phRwcyJstarc50/+z5hOWcRp4lndQ30f/T5pdF6xXN403Ed5GlCb5N
         LXIVvyF9aFlQMOvyHKfKU/s3EYR9M2UwFZqxjwIgzP4DcR42dLQRM7SlrMkHhDQvmO0F
         4F6djOJC3mtLY58COEp4HE3hOf4b58uVRDh/uuRBda4HdPunZjDkmDYfDFzxMNgHiNrs
         4D1WTqGVxHSfx0RY+jObuk02EP4llTDQoK+UmzIXas/sQbhhLKN3+aR5TgOHdch6Ws+J
         q1ODmTO3zrTWCewffWEw3XDZFvRqCYvu8ojkATmI9DYPEX2u5w7iolPd3ft44ENXQPt7
         jRyA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=BApoiD5V;
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::32b as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1728146855; x=1728751655; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=PBBkyCFa1ezocYuPiIP+jBiZWSHoJ1+vIvK9MjxRuF8=;
        b=G2hCxUgmLPIhivwoA0Wv4ZW/rxIuTiokBWZgSclSaPTC4yUdYVR1llyageuxtaNubz
         XhhpyRVZwtAnVMGqDG4dp5EywAOsI2waUuA1/bHnlrTsLyjHYPHjp96jomuuLj85kJ6q
         dp46bVHEol3L9UaaDtpz34BTYn6ali9oC1+87onhz1yYjv9zPrCvb/NnSz0pDIisEowh
         uOUAMwK8tmXl/IchKIuV+gPIA0CeLy7z5cyUTCWhB5pWtohjZZgLE5gkqa92N60mcK4g
         hLGb/1e64grwwtmOwZeuPcz5c2qhztuIMhyMMHO9b9F4TCGbA9OOeSFgQTitfeKJHHDT
         1HiQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1728146855; x=1728751655; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=PBBkyCFa1ezocYuPiIP+jBiZWSHoJ1+vIvK9MjxRuF8=;
        b=W3pi0ZoHBWbJlYWsCWoAdyxNUsXQGoWxK3cvVFmSG/CvRS7aHmhumg0BkuFZIn4QRH
         /QGKol6M8wfQnpYBAqDRc2IMPdoppNk2XP/pxjZ/IW4j2UaxM2gZ4cJbiiLUsic+kopE
         ykYXSLbHr5THFuoCZzHzLxQ5kemE6K1hikeaD00HgH8Y9Js37PToeZck3JuJt+D/D2E+
         DQNDCL+xu/LzTTNsYWhtICm/ZjiTI42hlmL+aDpKvJCUNlRvCwFIwJibM9DTMphTXNnA
         NAYe6FhXj+7gpAubPtu1Zkttd7yjPaxOMSZQ0IJ5bB9DLPf5lzuT4KTNIHCQvmRmcdwX
         3K2g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1728146855; x=1728751655;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=PBBkyCFa1ezocYuPiIP+jBiZWSHoJ1+vIvK9MjxRuF8=;
        b=ai577WI0UDGb+Z9OQtqT/1kFwa5WrCcvxusLJMPKaAdJvLrzc1pLnn2GsGtcHlyLbE
         FGIbV07t3bDX/80FOYFOZDC+sJvw8x3JMIrVOca7Sn0FUyXn2HBKeSDItLHWP5MMtgcV
         SSSG0G2N2Be+NRAeR266o3PkvlRvC4RCXHjhMeVGE7IL6yEtESCgyJFOKDK06+qoQNKX
         bKJk/rEMmZfyV9t97boLszhR0C8o0EQp0OR1DjyoNY9xlv9NFe7TGVKpiT5c9kRZgSc2
         C7w9887zPB79El488at3ovq9KtNy3NFv8VLr5oCdwlVcAeYi/AMaDOPeYx59U5TgFzvX
         ApFQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXbCic9ZTkl3F6pbA70t8LfLigPrK4a/HAdVRu/b8RDzj8q0+zTVilRTv1ASyohclHxkeobxg==@lfdr.de
X-Gm-Message-State: AOJu0YwxhrIRstDolSxyqPynMLn49iuldk0cz9c6ElV1r9PiwIJReGAd
	cXZ5fDEQlRKGPEBYCBEAd2MWzb90S0lrddVM0S1ZFRhlQfquenc6
X-Google-Smtp-Source: AGHT+IGAmy71jPOwZ+yo/bToNoRTAypL13k7fEdYNgJtkeCPt0oPEONL9gugW9q5q6X6lF9B5ngyFQ==
X-Received: by 2002:a05:6512:3d21:b0:536:562d:dd11 with SMTP id 2adb3069b0e04-539ab84e0admr3515755e87.11.1728146853758;
        Sat, 05 Oct 2024 09:47:33 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:ac8:b0:539:9565:da14 with SMTP id
 2adb3069b0e04-539a6323cafls1020680e87.0.-pod-prod-03-eu; Sat, 05 Oct 2024
 09:47:32 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWk5wFxgw+6CAat7qFIvTO0PkGeFOXmLQlOgUZBFCleBrnkKbgNaY4YhlxnW+d/Vjx828JWbcRZ/LQ=@googlegroups.com
X-Received: by 2002:a05:6512:33d2:b0:539:9e9d:18b5 with SMTP id 2adb3069b0e04-539ab86655fmr3310539e87.21.1728146851606;
        Sat, 05 Oct 2024 09:47:31 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1728146851; cv=none;
        d=google.com; s=arc-20240605;
        b=hpJGRLYjyQeVnYUfim+vnyJnk1fS6abkiEwMxZ+Uy3QoVViJTPooZhzwB54yUIHZ3W
         JX0a0/afP5dLkkSBeyZw5/qE6y7s0CLP8f250K/dk9ciAtilqeg1P9DHP/8ZgV2z30B7
         3wVgmypZVD5vAL+oxCGQhhOqIAcYLpoFUlFfPWvZLisLgoGFiOg64Ie/s2K63zk4pVUF
         bemZ6JTLmN0ub2xgcctOzGhpU27UPw1m/8EcGiZv1WI/rMGlZVOwjrn24zUFie/Nq80k
         nPUmR73vp4XIr2n16Gy+fOmpNYi1CISQhLlQoJegN3O7lDL6LB0+gnxM7QJtdllExd5S
         zquQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=q6F6OyhiHlCOdmPRfgY5RV4ZY7u4wQoO0FaQWpwh0ps=;
        fh=tu9DR4nXwNdFP9goDotZKoT9UVOVLzxpQ9+IXUkxqKM=;
        b=hiNoLqgYmlRrAzbhLhx99fmXpSEE5fK6vpCF7CDzdJ6DbdkFp3/rSIEsntQtth/R9l
         iy6O+FAgRKVH8PgPPGDISXC5/CMKxAD5J7xE+nAzIXRxAwIXfu2ZVOuEYlZVJZnejOMF
         0svftAPS0ZVM/BzeqJ0Osh+cNggFUevrXFlKKYGOPCEuJtgPOl/4jtU55P3V8gHdYYLk
         7DIqXrzYSmNVdBppXH5+6aL/lSl1FsfLBZv6b8PX+53dhcvEPM3MD4yg8LZVJuDbV1NT
         myCwNzHA6FGETXgXt3Z275G9mOL703s/89VlmqdZ5wF73JOaBr14gfKS2D7EpH52Srlg
         4L9w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=BApoiD5V;
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::32b as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x32b.google.com (mail-wm1-x32b.google.com. [2a00:1450:4864:20::32b])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-539aff1ee9dsi40046e87.9.2024.10.05.09.47.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 05 Oct 2024 09:47:31 -0700 (PDT)
Received-SPF: pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::32b as permitted sender) client-ip=2a00:1450:4864:20::32b;
Received: by mail-wm1-x32b.google.com with SMTP id 5b1f17b1804b1-42cb806623eso27128605e9.2
        for <kasan-dev@googlegroups.com>; Sat, 05 Oct 2024 09:47:31 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWNXiXGQe6mg+/61A9C2bepkevSpTQN0psNV3aed4cOrwuJZeahpe0AHOJuP1bgU34lqp3UPu5eONw=@googlegroups.com
X-Received: by 2002:a05:600c:1f82:b0:42c:b750:19f3 with SMTP id 5b1f17b1804b1-42f859be4cdmr52608925e9.0.1728146850889;
        Sat, 05 Oct 2024 09:47:30 -0700 (PDT)
Received: from work.. ([94.200.20.179])
        by smtp.gmail.com with ESMTPSA id 5b1f17b1804b1-42f89ec71aesm26481515e9.33.2024.10.05.09.47.27
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sat, 05 Oct 2024 09:47:30 -0700 (PDT)
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
Subject: [PATCH v2 1/1] mm, kasan, kmsan: copy_from/to_kernel_nofault
Date: Sat,  5 Oct 2024 21:48:13 +0500
Message-Id: <20241005164813.2475778-2-snovitoll@gmail.com>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <20241005164813.2475778-1-snovitoll@gmail.com>
References: <CANpmjNOZ4N5mhqWGvEU9zGBxj+jqhG3Q_eM1AbHp0cbSF=HqFw@mail.gmail.com>
 <20241005164813.2475778-1-snovitoll@gmail.com>
MIME-Version: 1.0
X-Original-Sender: snovitoll@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=BApoiD5V;       spf=pass
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
instrument_write() for the memory corruption instrumentation but before
pagefault_disable().

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
---
 mm/kasan/kasan_test_c.c | 27 +++++++++++++++++++++++++++
 mm/kmsan/kmsan_test.c   | 17 +++++++++++++++++
 mm/maccess.c            |  7 +++++--
 3 files changed, 49 insertions(+), 2 deletions(-)

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
index 518a25667323..a91a39a56cfd 100644
--- a/mm/maccess.c
+++ b/mm/maccess.c
@@ -15,7 +15,7 @@ bool __weak copy_from_kernel_nofault_allowed(const void *unsafe_src,
 
 #define copy_from_kernel_nofault_loop(dst, src, len, type, err_label)	\
 	while (len >= sizeof(type)) {					\
-		__get_kernel_nofault(dst, src, type, err_label);		\
+		__get_kernel_nofault(dst, src, type, err_label);	\
 		dst += sizeof(type);					\
 		src += sizeof(type);					\
 		len -= sizeof(type);					\
@@ -31,6 +31,8 @@ long copy_from_kernel_nofault(void *dst, const void *src, size_t size)
 	if (!copy_from_kernel_nofault_allowed(src, size))
 		return -ERANGE;
 
+	/* Make sure uninitialized kernel memory isn't copied. */
+	kmsan_check_memory(src, size);
 	pagefault_disable();
 	if (!(align & 7))
 		copy_from_kernel_nofault_loop(dst, src, size, u64, Efault);
@@ -49,7 +51,7 @@ EXPORT_SYMBOL_GPL(copy_from_kernel_nofault);
 
 #define copy_to_kernel_nofault_loop(dst, src, len, type, err_label)	\
 	while (len >= sizeof(type)) {					\
-		__put_kernel_nofault(dst, src, type, err_label);		\
+		__put_kernel_nofault(dst, src, type, err_label);	\
 		dst += sizeof(type);					\
 		src += sizeof(type);					\
 		len -= sizeof(type);					\
@@ -62,6 +64,7 @@ long copy_to_kernel_nofault(void *dst, const void *src, size_t size)
 	if (!IS_ENABLED(CONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS))
 		align = (unsigned long)dst | (unsigned long)src;
 
+	instrument_write(dst, size);
 	pagefault_disable();
 	if (!(align & 7))
 		copy_to_kernel_nofault_loop(dst, src, size, u64, Efault);
-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20241005164813.2475778-2-snovitoll%40gmail.com.
