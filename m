Return-Path: <kasan-dev+bncBDAOJ6534YNBBV4PS24AMGQEHNXVRLA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43e.google.com (mail-wr1-x43e.google.com [IPv6:2a00:1450:4864:20::43e])
	by mail.lfdr.de (Postfix) with ESMTPS id D291E995798
	for <lists+kasan-dev@lfdr.de>; Tue,  8 Oct 2024 21:28:24 +0200 (CEST)
Received: by mail-wr1-x43e.google.com with SMTP id ffacd0b85a97d-37d2e66cf9fsf432491f8f.1
        for <lists+kasan-dev@lfdr.de>; Tue, 08 Oct 2024 12:28:24 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1728415704; cv=pass;
        d=google.com; s=arc-20240605;
        b=WAtp/7mO5X6YIyxWWgtTlwFlusBUEh1141HXtgbivqNwcZozPJETB3DObYbZ57D8Ev
         VqsUKKYDPg0aPOfd9smkl07zCvQJV9DDIgHtHCnI8nHhunclc+9w8fhmULnKInmAvbkY
         QABbNaOBgSbTLmA2xquFoJD+3yPpI99iSRJdQZUBJRg1BaiMn9O3YPgOC/VLOcJx0ssi
         k+6ljLr1vUue0N7c/yjQCNzMpcGRMiiPbnZ6Q1QohJOtL4HVWfqNHyVgJjXLLe3Zqkhi
         Kv4MTuc7+QIBh4mJf5e+C7NOpM6RejfdSyfCRLSwGnHVEnhA/89qlty8d/n0ZUP1B+CH
         VFNg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=7RPO8XZpo3b4KlVepSvoCPdSHnhx8FmDfE+UYOlsxLc=;
        fh=n/m5gAe5enub3MfzQ8zrG6QVDOffRBFzD0Bdspa0VvM=;
        b=epeWCGJV9cc3y5ktTH0TYQNwfeXUWFCUats7QP449vrdRbRkb/8iKBZt9D+L6Bg6o+
         bZvKsR+1k0tl1wJGZpsvh9QP9M8qiIw9ZnSA4BAO8QcEiWTZqpbo+UiqOFMkYFohQ9D0
         yi32U1lRXzmevGgy2YJeG/YVWtqkrjYKoyYeVuYrI6SxdUmU4zbeGzOHwufUnIOCnQMQ
         ZGQI+poquf/Gn8x8yFggfZzHTvkpKL2PBKLBoqs6ndt11Jcw8yGm0DjP2zMlqMBfajij
         mUu4Mq3TE5LwRi5jw/wvYjh8eITl7Vn8S/JCW/ml+otgAsDYgQKtpANxeQkGR+wBTsqg
         f2EQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=iJUZ8r4o;
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::331 as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1728415704; x=1729020504; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=7RPO8XZpo3b4KlVepSvoCPdSHnhx8FmDfE+UYOlsxLc=;
        b=wSfJu8LeIr82oLVuemtnmtaFTsKiTtIkbRAY2J+m98zBPcCA72o8iE4rcknodseGUO
         97b9XJLfsMFQoBDC2fknXlDHiS43txmOxYhX1mXLNMOiYrAGNJrJrUmYe1Hbm8q384gC
         9ASslM1ryDE8xMK+6siZyPyadAn87JwzEz+z+9vn5INNZACMeVnJigkbjwyRpvEgFpbQ
         LB7wZOXg+QghZzSXJ4rb7Gk8UcogY65NcfGmbZdNtcw6fpos3no+7cFddCFex7W+Hylj
         AmRdICPrdMahpBmsXBRdjwd7uW2NHqo1tPHO6UIdBQ+oUHPHR3uLyjTDmqEsDjGuvZ/S
         9xFg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1728415704; x=1729020504; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=7RPO8XZpo3b4KlVepSvoCPdSHnhx8FmDfE+UYOlsxLc=;
        b=Q2f1QozVIoYEcJtF0CL5FkNkPBho3IPTaCa5yhrvKXmrCus/MT54xWFM0UXKrsrb0H
         Vw6aXb+HfDvYgUUC7MqvrHrzAAVjiWBKO9XbmypEe5oKQT8SD744E4kl8QaUO4oSbW82
         yqIiMYAdz5Y36PLLxVxwB73Ed0FxsNRwlClEdx074g7aQzBd6QzzVB9kovFuDfpA3St8
         kg3L3rAOmJzFvRTWsXESOvaUNIE31A8lrJDW5N0YrVkV7LsPplf/ucby2vd7zjuvsiRH
         yPc2PDCNYSt78PaVT/FkrW+vKGuwgJsn2Rgq2GvO5zLqaLmUVYlXd8/SE37THNe1KwVc
         xk3Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1728415704; x=1729020504;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=7RPO8XZpo3b4KlVepSvoCPdSHnhx8FmDfE+UYOlsxLc=;
        b=s2dCFzqURKX9T+ObEpNYquKR7aJ1wnUnuHw/9sLtlm5DIjOraFKYmlQk/ZfwwIq6Cz
         rO97fqZoFJeSAaVGZwBf9wQF9lUVc6z5OiLUUoIybEK/jKrcArTFyyxsCPkMWiekJUgK
         MlHzpjo4whtr7d+ilUW2D7mQdslL32Bhx1KdAYFN+E/X2Z0a2KwdUVA2bAxGJMIkZpwV
         KlywjWBTNARQf8R6uz6EieTjYloPlerrpAHJ9qDnmggB1gcSH1bO2cb6O4BCJ7VbmOlt
         3Q0AwR4JQneJrG0+t+j2FpJDy1dqtnxx6W3EyAJpleuDexqLD5lzV/es76AI9/Chb/EO
         ck5Q==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCX+Cs5Esm8Z0k7iGqVo28v6EFUxqEY5Oqb2iEYR0wyKjyHQcZgH75XAIKvJne5EVJf5zPVu9A==@lfdr.de
X-Gm-Message-State: AOJu0YxdKT2BGUZoLVmd6V0ucfw+tzXqKhvID7IICTt4Uo/qVX8t27N0
	h2qCVPXHO0K0s3J5U1NLFwiTl3rMSlFlIOUN/Oc3wQK4qjrj6kXs
X-Google-Smtp-Source: AGHT+IE12Ldjjoo6nncemly8RCkgTdHjRbSfV1Bm+zI8tY7SzxgMI2/WsbJ96dQmcTaQ4wIXtzZ9oA==
X-Received: by 2002:a05:6000:e42:b0:374:b6f4:d8d1 with SMTP id ffacd0b85a97d-37d0e7137a2mr8859411f8f.13.1728415703535;
        Tue, 08 Oct 2024 12:28:23 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:e643:0:b0:374:c0b6:44ba with SMTP id ffacd0b85a97d-37d04ad92b0ls1253560f8f.0.-pod-prod-06-eu;
 Tue, 08 Oct 2024 12:28:21 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCU88ObGgUd0slQn5Sh3vGxvVb4XGb4RQUFkUihnvRKUp1gxx39j0WPIRiTkbOAGTLTQLq+YctiKttE=@googlegroups.com
X-Received: by 2002:adf:cc12:0:b0:37c:cdcd:689e with SMTP id ffacd0b85a97d-37d0e777d3fmr8827351f8f.31.1728415701529;
        Tue, 08 Oct 2024 12:28:21 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1728415701; cv=none;
        d=google.com; s=arc-20240605;
        b=hEf8zT6hjyxFsFBKLvW1QMW168DDyIrPjZwu84p7UbdSJ5BcN2b0u8kun3ZTB+f3fp
         kTTa5LLy54YIXGumc+oq53TRQweorR95tO5p498X2LFzkXBLQMUfoVXXHx2ol5ExxrFc
         0sTlSfTbYCPi+8wC1bthdX06l6EDfcYJrBO+D36m3tnCRDcxSeUJzZ7lkreA2X74h9zZ
         JDRlJ9uS3p3ht8/y7BzBFoSM6u0oIr72KbTlM8WYTOQrrQ0lK2gVY3mQxl7UAZupfQqs
         7GOu/F4ryRa3GEsJcX5teL5ry8OwmBWNn7P1ih0LMuC4FTDzq1c04e4UgDCeq2cIH6Tt
         LBXg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=4YU80h+e3WqJR9RRP2zzYoIrqiryuhlMCUmmaZXckb4=;
        fh=XUm505q8PxtG4kUeCCg1Hbxv2PMOFIvE5trGuupBdNs=;
        b=h+mD9TAIFzaz6iLm5CnBCeJ+l2x21EYaClroARKQo6tkqVOThxNM+0SG1QoV3PTK+u
         0vgIrdh9mXV1CO/q8vQ986aHcxcw2jgHgwZHtKC2eoLfzLnZug7sPDvxJT6ED4Xi+uCT
         hjsiqkGIk9W4943SWjH8Th8bGhuL8nsqcodOlKoxBFB4UsRJpoE1ItU4LpJqs05VhrSd
         Z+nMa5W1X0IfT970F6bxOUqEyg2Ut8GkcYMN4RoL1jD8VRMfj8yrZQqiv6XfMMu2Waab
         nHjbH2BfSVY0yAtBHTjcm+z5JSF0lo9MdIkbNGyk+ajYoYA5FX7WvweH1Ve+zL4NXvIy
         +Szg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=iJUZ8r4o;
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::331 as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x331.google.com (mail-wm1-x331.google.com. [2a00:1450:4864:20::331])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-37d16b9eeacsi167145f8f.8.2024.10.08.12.28.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 08 Oct 2024 12:28:21 -0700 (PDT)
Received-SPF: pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::331 as permitted sender) client-ip=2a00:1450:4864:20::331;
Received: by mail-wm1-x331.google.com with SMTP id 5b1f17b1804b1-42cbc22e1c4so48465055e9.2
        for <kasan-dev@googlegroups.com>; Tue, 08 Oct 2024 12:28:21 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVYLMLTS0eXMtHm1Vh6tZKoGbFty1zWH8v3UdT2nV3qQwqxtR4aw/Q6jYQQqdQwZL6QBckkcjqfx5A=@googlegroups.com
X-Received: by 2002:a05:6000:4590:b0:374:ca16:e09b with SMTP id ffacd0b85a97d-37d0e6dad03mr8291114f8f.9.1728415700750;
        Tue, 08 Oct 2024 12:28:20 -0700 (PDT)
Received: from work.. ([94.200.20.179])
        by smtp.gmail.com with ESMTPSA id ffacd0b85a97d-37d39ea2eacsm181675f8f.15.2024.10.08.12.28.15
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 08 Oct 2024 12:28:20 -0700 (PDT)
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
Subject: [PATCH v4] mm, kasan, kmsan: copy_from/to_kernel_nofault
Date: Wed,  9 Oct 2024 00:29:10 +0500
Message-Id: <20241008192910.2823726-1-snovitoll@gmail.com>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <CANpmjNN3OYXXamVb3FcSLxfnN5og-cS31-4jJiB3jrbN_Rsuag@mail.gmail.com>
References: <CANpmjNN3OYXXamVb3FcSLxfnN5og-cS31-4jJiB3jrbN_Rsuag@mail.gmail.com>
MIME-Version: 1.0
X-Original-Sender: snovitoll@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=iJUZ8r4o;       spf=pass
 (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::331
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
- replaced Suggested-By with Reviewed-By: Marco Elver
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20241008192910.2823726-1-snovitoll%40gmail.com.
