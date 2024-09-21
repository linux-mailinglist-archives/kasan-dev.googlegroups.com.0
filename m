Return-Path: <kasan-dev+bncBDAOJ6534YNBBLHCXG3QMGQEKL5MYRQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33e.google.com (mail-wm1-x33e.google.com [IPv6:2a00:1450:4864:20::33e])
	by mail.lfdr.de (Postfix) with ESMTPS id E53BB97DBEC
	for <lists+kasan-dev@lfdr.de>; Sat, 21 Sep 2024 09:09:33 +0200 (CEST)
Received: by mail-wm1-x33e.google.com with SMTP id 5b1f17b1804b1-42cb479fab2sf17533345e9.1
        for <lists+kasan-dev@lfdr.de>; Sat, 21 Sep 2024 00:09:33 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1726902573; cv=pass;
        d=google.com; s=arc-20240605;
        b=kZikGPr7gjjK1YkqwSijz7ioihh0um1g/Duoj9Dot0vppn8z8T7WlQiH1F7FZsPiPk
         mhugyrTN/Rh+60dWVZNatBU+FO4nALnWf4IRAQQqF9LVoYf4ZcYCYj+urRL8+WlybdAW
         MyL1forjJmW7o0QJrAG1ofKs27Cl0K5TAmlUqQjzBN/m/Ht0jGfAMJ3khOo6AvlhVF5/
         fPRCyecsk2rBpIJCymtHnVA4uzxkexepdgjNKllO5S8hTGf5MKCLPqb9BrFwZGIh0Uti
         D7kw6zcQU8VFExu8hD21xb9Xszw/svbslSbstajFmlFu9Yexj7jhbM/UQkF81mmrLAWi
         UNkA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=UGoojx9HxL6aqD5E02R1JDAl5BvvA2/GF6bFj9GvNGc=;
        fh=ZnRanYIpnECicKvReb1pRcHhvpymUOtRdEmi78BSJOw=;
        b=hcIgbLQq9Q1/r4WIHIQfKl0kFlFQ/6dwo4hY1v2Yih0O/v6Nnt6e7L9dJZXpLlAQ1y
         giJAEDwh8gRXJYppwqQyoODp1O6Y4Y0dpkN9y2zt9d+kCf0Jj2mNplBnxEe+jynU6Q8Q
         d4yHH67sfVfwsr5R/dcLvMgD79AnWNAdJwQiWU+HfO96y/4AmjUX+UtMv8FLMxqAmjd1
         lX7NDdMdJpZcXuCg6V3PUPlyO8V7iiYXkk17BGToWmx6vU1+vh42UJzKkIwZ9OsWlYyA
         /awQCLM1MBhFHN/M1KAOFTqF1Q5QfGJX6QLHRBU2sQ2t6/N9HuaB+3Qlx028jFQIr15G
         WRHQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=AUjFCycQ;
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::232 as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1726902573; x=1727507373; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=UGoojx9HxL6aqD5E02R1JDAl5BvvA2/GF6bFj9GvNGc=;
        b=XPKrm/PK+ANhvisRES6gXzsnHaA64eB1ogF2XNZezkOF3qSHfhn8Cl7lq2E3Y2pckz
         QCLzSd6eyeLTvggm92AWM+x3obG4pRDRTjjbY6RM5FnaiRkyxkCrOWwdHh9tcW2ofTgz
         8/j4GpVyY27XgOpd6Bu3D5iMfHrGLegngY+ZHcDXbNF314dpxA1ZKpmNHMq5AqtMEyNv
         U7//kOdQMM5mAYpbv1IUW0MKU5cxsO2ta7XwV872fZvQ42cKgodPK4UPAYA8izG3zzxQ
         2wB18krHamOEMZH/s6u16wnr0XqMdisz9YjR7txVIg45NVUsPGL4lv0fZOZFPmT1mnbl
         7v/Q==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1726902573; x=1727507373; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=UGoojx9HxL6aqD5E02R1JDAl5BvvA2/GF6bFj9GvNGc=;
        b=edZyhmAT8ojrAAWesbMWpWQ4quzRA+KFebPe/NMae3Rtq6kMcGoD+kI5kKjVyvalY5
         F53DX7aqVYe50wDFabIFgxiHopPKfupI7wiMyXNmGP2NWDSJ81nnW2BpEvCdDFTLlW7U
         MgA8gaSaIH2huUGiDDZz+t3dmMcMzVhHJNK78uIt5DhR8uz/5u2HqqchTsVwJlIQRDe4
         jBsvu7DDHqZQ6cptei2BW/+ggZC39GR50ksBfA0QSkGKh4ElDznkBHFIjhyuZjBl6rt7
         rWaJ8nqcasOfKRmvVmYOacmbasNeyJOsJiWDqKwQn6U9A2eeqf1M1mUFUa+wk5KjrZVw
         +8+g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1726902573; x=1727507373;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=UGoojx9HxL6aqD5E02R1JDAl5BvvA2/GF6bFj9GvNGc=;
        b=JZVUjoHUqwVNhGue6we78SiS15N0JN56/X3GKVf2Js0qDW6Mq0OdSSG+3anMTsx/6/
         V7yytZwjVFaZ3bGwjao+fHbGD4rsgs1kO98t297liHHkCfUqYI2Hf8OGGH23RKRd5EOh
         Om4jZe9DQGlU+EHgyaRMSt83PIb6yArNvmLVPkOgJdT/4bCnOI+Q3H2xHWHlhfX3wM46
         RBDFih02j3FHizN8b93R+OSsuKUZ9yjMNzZ+9l46iqD3VrD6u4nDX3kD9+osPbioqQgV
         g6zFwsAkS86HkH09aGIOxV4+ivCdgQKCwIHZb/IDfFDG+6D97eh59mxgv9WCHKkwaAQM
         /vyQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVGqbKmxM1suVDbfXH3o4FQtDERU7Jlw5fXEJcxx2MJen+9yMC8J1h1fQvblSv1W9BBoq250Q==@lfdr.de
X-Gm-Message-State: AOJu0YxfPlrZ1oKiQ0PVPZhmhp8tEAPf44cFtFKghl8cF/XAbtREm/6u
	giJYfA0kRLcr54oJ7ZslTs7/bz4fP8wN0W/pVYpobGdonuZCsIIP
X-Google-Smtp-Source: AGHT+IEQ8rwCe75CBiMIMUZWszacU7KlLTwT5pzw32JE1kRmGCv6oan01xHoXpX9FQxgbeBjMYvF1A==
X-Received: by 2002:adf:a31b:0:b0:374:c33d:377d with SMTP id ffacd0b85a97d-379a860baa4mr4679301f8f.28.1726902572532;
        Sat, 21 Sep 2024 00:09:32 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:5114:b0:42c:b037:5fb1 with SMTP id
 5b1f17b1804b1-42e748f5669ls2280065e9.1.-pod-prod-00-eu; Sat, 21 Sep 2024
 00:09:31 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVM20FgBIFFLhn+W45uCs+HlFb77Yg6Aiia4ENcBkfzjDUhFDMrthjajxEzFNUbosJYjYqTrmWepmE=@googlegroups.com
X-Received: by 2002:a05:600c:3397:b0:42c:b336:8f1 with SMTP id 5b1f17b1804b1-42e7aab2467mr30786175e9.13.1726902570839;
        Sat, 21 Sep 2024 00:09:30 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1726902570; cv=none;
        d=google.com; s=arc-20240605;
        b=CttcxwT6M1dNBktnw93AZ7VuiCushsudEvljfZYzocjcKjdogTSUDNNHQjoSGIs845
         JQMjUf2NLd3YtMzrBsUtXzMu07JdAAgqA1V+TcqSioponZ4eZ5L4Dqfj7dTPKcySQjUS
         GSG7ZhtTjcVXDMoI7Srs/u1V7ZaPwM8Q2v9G57WTIWByGQNDSKjV7YAEqCWdZTGMFxG0
         s2DrFR5TxHCH9Su3siyClFPbkzkauyWJnf3OaKlN054VDPllj5ZDNEfc7ZBi4dXzkp+h
         QfEBAwL3gnBwF/K8Jfa0WBIyuLJ6Ftr7iXhxP82mTRD93U6QAr5m9mih4ivInc2u8RmH
         hRNA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=+ohAzvebGtlWdpIGNEivr1Zt3bErXvsBaqlk21HjfVY=;
        fh=JQy+Y20IwZBNvDKrYdt1Qsw+ltzDvkdqKtOr1zd8PxE=;
        b=aJA9vv5hGC9VtAbSm7+Ay0JZfhLQWqYCHFLt6/ELGWjZTx5zDAb6h1vXmvp8lY31vF
         dK/rim59bhAP7yY/INKmDqPPvHxaHzZXI/1lAj/XH/bcK0U+xew77EZe8qHQabJdA4BS
         hfrpytGqUJXgP0HHSb22aP9J05VmZmmy4xyooVwpUejGsEOwGIIjwlNXe3NOyfrFdvB/
         oSfRkUbnyUbi6Qyi1tdlOXj+IHVhC3QWHkfJV50fKNamtV9MJIccpP39FqDC9M49DQsS
         zhBvFdfY8+inQ9v29Hlg2ENXJWF8JgkY9BKG3cl1voU93I7godxp+Qa5hPHmTBAakCV7
         Fv9A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=AUjFCycQ;
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::232 as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-lj1-x232.google.com (mail-lj1-x232.google.com. [2a00:1450:4864:20::232])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-42e75b546ebsi4196635e9.1.2024.09.21.00.09.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 21 Sep 2024 00:09:30 -0700 (PDT)
Received-SPF: pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::232 as permitted sender) client-ip=2a00:1450:4864:20::232;
Received: by mail-lj1-x232.google.com with SMTP id 38308e7fff4ca-2f6580c2bbfso32261511fa.1
        for <kasan-dev@googlegroups.com>; Sat, 21 Sep 2024 00:09:30 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVKpUoE/M2aU53GRKEIpsLWXlUokGjBEHXtbxiWS+ThoWr87A7UTV0vkicYOQDUSyzNTqbmDLSItk4=@googlegroups.com
X-Received: by 2002:a05:651c:199f:b0:2f5:375:c1da with SMTP id 38308e7fff4ca-2f7c3d09a2fmr31608841fa.1.1726902569682;
        Sat, 21 Sep 2024 00:09:29 -0700 (PDT)
Received: from work.. (2.133.25.254.dynamic.telecom.kz. [2.133.25.254])
        by smtp.gmail.com with ESMTPSA id 38308e7fff4ca-2f79d485f2csm22082221fa.115.2024.09.21.00.09.26
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sat, 21 Sep 2024 00:09:28 -0700 (PDT)
From: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
To: andreyknvl@gmail.com
Cc: akpm@linux-foundation.org,
	bp@alien8.de,
	brauner@kernel.org,
	dave.hansen@linux.intel.com,
	dhowells@redhat.com,
	dvyukov@google.com,
	glider@google.com,
	hpa@zytor.com,
	kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org,
	linux-mm@kvack.org,
	mingo@redhat.com,
	ryabinin.a.a@gmail.com,
	snovitoll@gmail.com,
	tglx@linutronix.de,
	vincenzo.frascino@arm.com,
	x86@kernel.org
Subject: [PATCH v4] mm: x86: instrument __get/__put_kernel_nofault
Date: Sat, 21 Sep 2024 12:10:05 +0500
Message-Id: <20240921071005.909660-1-snovitoll@gmail.com>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <CA+fCnZeiVRiO76h+RR+uKkWNNGGNsVt_yRGGod+fmC8O519T+g@mail.gmail.com>
References: <CA+fCnZeiVRiO76h+RR+uKkWNNGGNsVt_yRGGod+fmC8O519T+g@mail.gmail.com>
MIME-Version: 1.0
X-Original-Sender: snovitoll@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=AUjFCycQ;       spf=pass
 (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::232
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

Instrument copy_from_kernel_nofault(), copy_to_kernel_nofault(),
strncpy_from_kernel_nofault() where __put_kernel_nofault,
__get_kernel_nofault macros are used.

__get_kernel_nofault needs instrument_memcpy_before() which handles
KASAN, KCSAN checks for src, dst address, whereas for __put_kernel_nofault
macro, instrument_write() check should be enough as it's validated via
kmsan_copy_to_user() in instrument_put_user().

__get_user_size was appended with instrument_get_user() for KMSAN check in
commit 888f84a6da4d("x86: asm: instrument usercopy in get_user() and
put_user()") but only for CONFIG_CC_HAS_ASM_GOTO_OUTPUT.

copy_from_to_kernel_nofault_oob() kunit test triggers 4 KASAN OOB
bug reports as expected, one for each copy_from/to_kernel_nofault call.

Reported-by: Andrey Konovalov <andreyknvl@gmail.com>
Closes: https://bugzilla.kernel.org/show_bug.cgi?id=210505
Signed-off-by: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
---
v3: changed kunit test from UAF to OOB case and git commit message.
v4: updated a grammar in git commit message.
---
 arch/x86/include/asm/uaccess.h |  4 ++++
 mm/kasan/kasan_test.c          | 21 +++++++++++++++++++++
 2 files changed, 25 insertions(+)

diff --git a/arch/x86/include/asm/uaccess.h b/arch/x86/include/asm/uaccess.h
index 3a7755c1a441..87fb59071e8c 100644
--- a/arch/x86/include/asm/uaccess.h
+++ b/arch/x86/include/asm/uaccess.h
@@ -353,6 +353,7 @@ do {									\
 	default:							\
 		(x) = __get_user_bad();					\
 	}								\
+	instrument_get_user(x);						\
 } while (0)
 
 #define __get_user_asm(x, addr, err, itype)				\
@@ -620,6 +621,7 @@ do {									\
 
 #ifdef CONFIG_CC_HAS_ASM_GOTO_OUTPUT
 #define __get_kernel_nofault(dst, src, type, err_label)			\
+	instrument_memcpy_before(dst, src, sizeof(type));		\
 	__get_user_size(*((type *)(dst)), (__force type __user *)(src),	\
 			sizeof(type), err_label)
 #else // !CONFIG_CC_HAS_ASM_GOTO_OUTPUT
@@ -627,6 +629,7 @@ do {									\
 do {									\
 	int __kr_err;							\
 									\
+	instrument_memcpy_before(dst, src, sizeof(type));		\
 	__get_user_size(*((type *)(dst)), (__force type __user *)(src),	\
 			sizeof(type), __kr_err);			\
 	if (unlikely(__kr_err))						\
@@ -635,6 +638,7 @@ do {									\
 #endif // CONFIG_CC_HAS_ASM_GOTO_OUTPUT
 
 #define __put_kernel_nofault(dst, src, type, err_label)			\
+	instrument_write(dst, sizeof(type));				\
 	__put_user_size(*((type *)(src)), (__force type __user *)(dst),	\
 			sizeof(type), err_label)
 
diff --git a/mm/kasan/kasan_test.c b/mm/kasan/kasan_test.c
index 7b32be2a3cf0..d13f1a514750 100644
--- a/mm/kasan/kasan_test.c
+++ b/mm/kasan/kasan_test.c
@@ -1899,6 +1899,26 @@ static void match_all_mem_tag(struct kunit *test)
 	kfree(ptr);
 }
 
+static void copy_from_to_kernel_nofault_oob(struct kunit *test)
+{
+	char *ptr;
+	char buf[128];
+	size_t size = sizeof(buf);
+
+	ptr = kmalloc(size - KASAN_GRANULE_SIZE, GFP_KERNEL);
+	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
+
+	KUNIT_EXPECT_KASAN_FAIL(test,
+		copy_from_kernel_nofault(&buf[0], ptr, size));
+	KUNIT_EXPECT_KASAN_FAIL(test,
+		copy_from_kernel_nofault(ptr, &buf[0], size));
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
@@ -1971,6 +1991,7 @@ static struct kunit_case kasan_kunit_test_cases[] = {
 	KUNIT_CASE(match_all_not_assigned),
 	KUNIT_CASE(match_all_ptr_tag),
 	KUNIT_CASE(match_all_mem_tag),
+	KUNIT_CASE(copy_from_to_kernel_nofault_oob),
 	{}
 };
 
-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240921071005.909660-1-snovitoll%40gmail.com.
