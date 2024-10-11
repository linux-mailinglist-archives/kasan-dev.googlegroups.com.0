Return-Path: <kasan-dev+bncBDAOJ6534YNBB4WBUK4AMGQEHHSBWMQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13c.google.com (mail-lf1-x13c.google.com [IPv6:2a00:1450:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id EE1B6999B56
	for <lists+kasan-dev@lfdr.de>; Fri, 11 Oct 2024 05:52:20 +0200 (CEST)
Received: by mail-lf1-x13c.google.com with SMTP id 2adb3069b0e04-539b0693028sf1610365e87.0
        for <lists+kasan-dev@lfdr.de>; Thu, 10 Oct 2024 20:52:20 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1728618740; cv=pass;
        d=google.com; s=arc-20240605;
        b=TQFokWRifSdU0njkTqD4fdDCwuKbKmYKgYxzuK5OzZ8seeZg+dskOyXrdhTQB0pTnI
         EjsWlNdMNpK1UB7yQtqrC0+q0/niQ6DmktlFNsoIit7OqO6lUqdaglvNaf2T6v7d1ALL
         54nne3HqPXxUzDdrwpwDZHzYnqp48iLe5vTNO3AFIIOjcr+0sOOh8AaOfCekIsI28CS/
         WMlUw82YdCFD+oGhMnU3uP9NhyWahJtkGath90Iaopb8kjRydQaCaUCSd6gGsT907mhn
         xM7JITq5Ho9uEwGJ5FN/Gv13oReEy7Kq7GyuG7PB2wUor71Shg00d/eKZ8Rx3tfnuExG
         hF0w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=iH8E7VefAki0AbmETwRmGKxCGfzLNh5tNQBsipY6JV4=;
        fh=AHUICMAJBq/sW1xtu/qOO1rptQ6Y/8o6GVPj8BPk4Gs=;
        b=SglPq63wF0OBCEJSbmLa+GL801WJDepv/fc2x1NfiOu3gjm6pFOyJ9Wu/UI4yspWxP
         8fDt9Wf188hciThWDX3AY3nPuJKDcQLqHznvQI2MiaIjARr6ba2fzCjjSagLPxXPhdaS
         1Xfe51ZQg5nN7Mq4oCmjNFvSqcHEDSR7pV326m8e2WQmVkdzMnQulkWQTcBjoHbsn8U0
         B1RrgF3SrwrwSH5p2xKKerUd90q//ZeQ0JKXML1WwxruaGcE14xXePtLS7ySokEslXu1
         Exc1ztG12fdS4A32WdtjXUWFVA/3SXFYzIcbUVbbwaHwnmxY8fvskVZ04QS24U53uT3j
         r2FA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=abeakVCm;
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::229 as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1728618740; x=1729223540; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=iH8E7VefAki0AbmETwRmGKxCGfzLNh5tNQBsipY6JV4=;
        b=xOC0HCRfs+/+04Kr5D7PTIwfSN1HkJV52khUfXnQ2LSZsM6ChUt071Cf5eBdKZ5obT
         qap08ZybP6ntR8//dW8+FIckPRY6aJ6qILOnNFYISCx5jPB6kHBAwCQtokNKZCrmIliB
         a25EeQGdnPUNCoRdwL+e0GSDGaqWl4ogYJCr+6zQcUEb3gaAuV4OXxPFZJseZiQE0N7I
         aUrMjKWC89LOcmVvM4WSJ/woqqMWkBfp2PI2KNbeaiDE5WW7TJ9KFGYKSJddxvJfzH2f
         dQB3kgWyBuJecmShUvtUrzgEbxUlpdwnRH9s7A8+Pj/dRBXpDjqjY/qQltNyxn2kVK/o
         Ol3Q==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1728618740; x=1729223540; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=iH8E7VefAki0AbmETwRmGKxCGfzLNh5tNQBsipY6JV4=;
        b=WDKX+jeyc092TEirnG3twhAn9PASIx5lyJcZQCarXT2DkKj3i9aX6XwobwK79W5/mt
         RpWJqiVeaiLkIUG0L3I6bk9YOE4fWSBGukQ/PsKFvP+wU8GUqIXOqaebdfJsq5ePNrp3
         +/YnSpjeWwUPokGeHC1CfHP7tY8z9/SWMlLr2s7Ia573VXwvGin8EV63TJ2GWCpnD7Ml
         kEyLyPgW2riXhO7ypqd3XG/EtKVgOO6BDTjWtlzTEAWhe84QeAm9kRR0oZX3rIYHCrXd
         g+WBlFhHm5A6rjPqJtVEiJ1g4WUUoh1S2R0owyVAKJNyde6u/QocuSXhxoIEj855cKSE
         kUvA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1728618740; x=1729223540;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=iH8E7VefAki0AbmETwRmGKxCGfzLNh5tNQBsipY6JV4=;
        b=pZHcF9dVvuI3rCDAkCs9pLxovPswB37cn+Jsagfgbxf0MdsWjC0ofkwp8rqE1SIdlU
         53IJ/3k7l0L3WfI/GYztHTzN6Os2RPMISQ72Pe33cBI0ZGmzX/v3pz23vIPmltI7QVya
         21cKJ5J+TPWQ8ve8+pXB4co/epUGUqwWHnMYvEgCyvrTp2mISF0UzhInrS8vybf9YZAg
         PPKaRQR56O9PAB26WUlyDn+2TVygKoWvqUefA5QKsoKEukGMIZ74cQc5WV7NOiMV/Q8A
         T+3/q/x27CUOPRGUhBtOxLQ9JGMQxnNrPgMAATzs+8y1IoY6kSsl1jW0TjMCMKE4m8hK
         LFtg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUI1NAlA7OrmnpQ7AsAH+nyDCoBa8JUqd+nrPDjKJ5wFN+vDORKHfmDh+KCSfDRu2HAFtBNvQ==@lfdr.de
X-Gm-Message-State: AOJu0YzyGB1g7qW+p8RpokGcaKrquCFtMBVXpPVIactynDJ2Kd8fSNvm
	cUH4//vNQwWJeZ+n+JsoSkVgL/WJg9+iW246syoJI4Ao/g85ZbJ2
X-Google-Smtp-Source: AGHT+IFawLCdm7vMaenCAamsx7H2+GK71Mu/27AL8zTLMRk0WqTNKvvossYZUE3oL/9GyOS2nQj7Xg==
X-Received: by 2002:a05:6512:131d:b0:539:a2e0:4e94 with SMTP id 2adb3069b0e04-539d6ef4d72mr258665e87.30.1728618738394;
        Thu, 10 Oct 2024 20:52:18 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3b2b:b0:52f:c72f:ddd with SMTP id
 2adb3069b0e04-539c9b6610als528463e87.0.-pod-prod-00-eu; Thu, 10 Oct 2024
 20:52:15 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUKl86OCMAtnAdJJGoPoFmITaz3IhC0wkDuO+MqWGUzGbImi7cQtOITooI8EQ+oEWYR9gR7Q5MLqf8=@googlegroups.com
X-Received: by 2002:a05:6512:1154:b0:539:9ff9:5c94 with SMTP id 2adb3069b0e04-539c986c55cmr1717472e87.8.1728618734716;
        Thu, 10 Oct 2024 20:52:14 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1728618734; cv=none;
        d=google.com; s=arc-20240605;
        b=SbCEGxfPyy2CcYRSat54KuYGdRPDz48EtZJnviB5ANNi/FSs4EYd0WofrV2aWi8cgK
         Pw80mMi5Qw36Smli8/DomKm36QM5/JmOdTzTOxWcDHcUFnXshWr/v3oZxkh6YmzJ+sTl
         I0bN3Sr64v4K9tOnwyRVMl3V7UYXAMJEWBQTgsw8UZ/GD/ccaq2Cl3LyHd+jjOIbff2t
         2EJBdmrGFFsnOsUd17pshk/Z2pY3JWnFe7+J2CzT7fm07QnROH3VyYYjb6LdYDTZDYtu
         +snTJqvbBMyM0rXB1EcL9VbayV2BnM+vjn0E7/gptAlKf42LUFwQ3DsND0qvGWVKo7NG
         EM5A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=w0fnDdAXdFFiAdPLRHXqXwWbKuYcXlWeTLq43KdMa6k=;
        fh=7jE7pGaarrbY0rouR3s5qnk3HjzF5plRTswX/lomsVg=;
        b=J074AiqSO7AdBeK9dU/5TtbEpfk6Bgej0oWb6qgX7jC9qJPohLqbEPayrUSD03XYAr
         j3UDDQ3s7SSEIA/LDcVQWvMuyTu5vFuCKnxvXqFXMJTASPQHaog/6Qe1NsABvNYAR6cR
         uizwHdq7oKPZXvDVOlUaJjT8Owx02q8WWgdVw9ir4Y7SmHuzZBUqwZvkEkkPvU1oW1AF
         b7KqOU3TA7RFMI2HNF0CzHOqyhS9sRoZb7+klZ76kO54ukbRyvoWNoKeCvHCzPDW9F7+
         8Lykb8XvPJlKC3916UTASyMT9CiB4YuicoAng+qJm8Myxd/K9vdFuvPhmeEJRC3OU+N/
         QJlg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=abeakVCm;
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::229 as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-lj1-x229.google.com (mail-lj1-x229.google.com. [2a00:1450:4864:20::229])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-539cb8dbf59si47620e87.9.2024.10.10.20.52.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 10 Oct 2024 20:52:14 -0700 (PDT)
Received-SPF: pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::229 as permitted sender) client-ip=2a00:1450:4864:20::229;
Received: by mail-lj1-x229.google.com with SMTP id 38308e7fff4ca-2fb2e21b631so5594921fa.0
        for <kasan-dev@googlegroups.com>; Thu, 10 Oct 2024 20:52:14 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWuSZ2kM6df+53ZX100Efgk2pNdVOYhZk1n/hTFlabsILlzORoxmwWQxmhA9aZJF6YAew7X3ZQn1c8=@googlegroups.com
X-Received: by 2002:a05:6512:3a91:b0:539:9135:698c with SMTP id 2adb3069b0e04-539c9881bc8mr1605719e87.16.1728618733895;
        Thu, 10 Oct 2024 20:52:13 -0700 (PDT)
Received: from work.. (2.133.25.254.dynamic.telecom.kz. [2.133.25.254])
        by smtp.gmail.com with ESMTPSA id 2adb3069b0e04-539df2fe2d5sm36383e87.61.2024.10.10.20.52.11
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 10 Oct 2024 20:52:13 -0700 (PDT)
From: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
To: andreyknvl@gmail.com
Cc: akpm@linux-foundation.org,
	bpf@vger.kernel.org,
	dvyukov@google.com,
	elver@google.com,
	glider@google.com,
	kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org,
	linux-mm@kvack.org,
	ryabinin.a.a@gmail.com,
	snovitoll@gmail.com,
	syzbot+61123a5daeb9f7454599@syzkaller.appspotmail.com,
	vincenzo.frascino@arm.com
Subject: [PATCH v6] mm, kasan, kmsan: copy_from/to_kernel_nofault
Date: Fri, 11 Oct 2024 08:53:10 +0500
Message-Id: <20241011035310.2982017-1-snovitoll@gmail.com>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <CA+fCnZfs6bwdxkKPWWdNCjFH6H6hs0pFjaic12=HgB4b=Vv-xw@mail.gmail.com>
References: <CA+fCnZfs6bwdxkKPWWdNCjFH6H6hs0pFjaic12=HgB4b=Vv-xw@mail.gmail.com>
MIME-Version: 1.0
X-Original-Sender: snovitoll@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=abeakVCm;       spf=pass
 (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::229
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
v6:
- deleted checks KASAN_TAG_MIN, KASAN_TAG_KERNEL per Andrey's comment.
- added empty line before kfree.
---
 mm/kasan/kasan_test_c.c | 34 ++++++++++++++++++++++++++++++++++
 mm/kmsan/kmsan_test.c   | 17 +++++++++++++++++
 mm/maccess.c            | 10 ++++++++--
 3 files changed, 59 insertions(+), 2 deletions(-)

diff --git a/mm/kasan/kasan_test_c.c b/mm/kasan/kasan_test_c.c
index a181e4780d9d..716f2cac9708 100644
--- a/mm/kasan/kasan_test_c.c
+++ b/mm/kasan/kasan_test_c.c
@@ -1954,6 +1954,39 @@ static void rust_uaf(struct kunit *test)
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
+	KASAN_TEST_NEEDS_CONFIG_OFF(test, CONFIG_KASAN_HW_TAGS);
+
+	ptr = kmalloc(size - KASAN_GRANULE_SIZE, GFP_KERNEL);
+	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
+	OPTIMIZER_HIDE_VAR(ptr);
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
+
+	kfree(ptr);
+}
+
 static struct kunit_case kasan_kunit_test_cases[] = {
 	KUNIT_CASE(kmalloc_oob_right),
 	KUNIT_CASE(kmalloc_oob_left),
@@ -2027,6 +2060,7 @@ static struct kunit_case kasan_kunit_test_cases[] = {
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20241011035310.2982017-1-snovitoll%40gmail.com.
