Return-Path: <kasan-dev+bncBDAOJ6534YNBBNEX3O3QMGQE7E3FRWY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33a.google.com (mail-wm1-x33a.google.com [IPv6:2a00:1450:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id E9582988808
	for <lists+kasan-dev@lfdr.de>; Fri, 27 Sep 2024 17:14:26 +0200 (CEST)
Received: by mail-wm1-x33a.google.com with SMTP id 5b1f17b1804b1-42cae76d589sf3521305e9.1
        for <lists+kasan-dev@lfdr.de>; Fri, 27 Sep 2024 08:14:26 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1727450037; cv=pass;
        d=google.com; s=arc-20240605;
        b=WLh9iCc3OYA00Pd0IfNhsX/W+3hun0a1vfPCmP8npMWukW4/XmNerFe5HaX1lyo8g9
         GRR85D/J3/nehu/hnk4BM3kUxc84VCC47NAc5+wczUujDkVBGAqF1s9f6XKA2ljD6HZ4
         Fah5FgU0I9rWs9LWAAbteYcuiUXq502G0Y5nJ/mkwJ6z3HNc8gR/RNaoNUnAA6oTZgX5
         Uvo5H0Fqjno8rv9Moe6YBGEIF4+Vmk11kZmmNT75RO/4pnVdrIwbHXYyinEOZxSHXNrl
         UeDAIqAuVDh23cw/E2KP8jUDdi2YjsxtDAa+vmatGqzpu4/0nV496gq6IZiS4DtNF8/m
         1vWQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature:dkim-signature;
        bh=0f2iD+bJ4eYGWZXU0EECvWHae4oMAD0u22zrbDaBjhw=;
        fh=xD5wWpNF+nuKhPDoFUsdJK81ogPlTqTH45rCv7gh74Y=;
        b=iLTETJlSDoihWfVYLT0Jl/sLzXgjmT1mSkOJ2C2hGElHK8AW4h4ToBMWt0sZQO6Z+5
         AVLgVTand2eSkaH5dbKABx+38MM0rnCWVA7LqZD6Rj4QaDZbB5VeZvIhwNDnjxG2O+on
         6GBK0FmUqerXJH87X6z7HB6yF2ssYuMiValudE3mhve9f8rDkfH3oMk5WqeruG6bKnVF
         ORQOSMSCly86+kP06QCPgOup/F2A1z4RjR0eK1/jrjg3UG4b6C/JA1BeOIj1wAr0ycGo
         I+m5jk8vFwS+y9xOC6hM39++ew2rVoiJ7lYTE9JGti2PtMvSiNPj2lwo5//1tUTaFieZ
         3KDQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=O7GSsaGn;
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::135 as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1727450037; x=1728054837; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=0f2iD+bJ4eYGWZXU0EECvWHae4oMAD0u22zrbDaBjhw=;
        b=dzz9R5EMffCZw/Xhl6hTggTQxJBys7guHWsUrzRZX5M8iEFILMAkUXDWa4ELVhBOhI
         Yv21Vt+vtV60UqqnOtnVqshBb38DZiU2fOKjb+ZbKfBaEuqxczVkAdYPi8AlSoe6hm4/
         fiPKhNRYzsyr2nt+xDTY+A2BizkTLraQYgkXmONxRIvBt2+R5oec9MURN+W0HlEiuPTG
         yo/XO+W1Z38Usjtar20OIsp4tc/1c6ctGtzB7RsZqeoEHicf14pFjUqHH2PgYolXwx+u
         +eMHYVsE8wytLjnVNaT++HpuNLjDJ01c7oK97q9aTyZZlkPh4ToYetb6zdwapm+3tysZ
         rwiA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1727450037; x=1728054837; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :from:to:cc:subject:date:message-id:reply-to;
        bh=0f2iD+bJ4eYGWZXU0EECvWHae4oMAD0u22zrbDaBjhw=;
        b=A1zwieJ6YK90eygRSO+jPICDN3yk5Q83MouhG06Lt7G3Q4h0n7f2/Yi3NOkQL4CpNx
         4dkYLyawC7OMOkNGYFfOV6mZglsFrNZryxs1+tNzboE1K2AvJLaCveCGUL/YWnejoAAC
         r479q2jD4c4hHxg+LUCJWv2LDlUgR332DUTzpJKzg7yApWv9w7RDCYj5WHW/WRzQPrrZ
         09Le2mFxhxdxvw35T+BGljWoVKRcHJPyunthTeOVYkOPo4+NwkiQbEPe/ywn1DP9tr9+
         VvSx084wjboF1qk27zDiz0vBWhlYHLZacL8aJoapphfG46wPC1pvBJ8Kd0Ba6x2MOirl
         Ck7Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1727450037; x=1728054837;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=0f2iD+bJ4eYGWZXU0EECvWHae4oMAD0u22zrbDaBjhw=;
        b=iLDreELGVDpdf4xpIWZhWbD9oIt+zObPQGDcUmjQLmLdFF5M6wBujM4QH5JdY4KrE/
         AOswEtKAk44OAZouMqoLr/5LjWcp1FkhGlLGGFVIivSoedSyn8FAo4ChOHGjcSF8CLou
         e9qtzZUsC80iSJgl70+n1IRAE4HJgjT7X0QSWKog9qwfsz3GAx4G35WnGYFvcBLesrwP
         0FlTAV8jJj/Srox2ydizJpeeqLkS6UprFbsrrOcTsi7L2Tw7alRpim9J72oYA7FuTx3Q
         H0g1aeRy1C9cdGsrcqIiBhgaCBkE1PGQ9C8JP5vRhHymKgjzaF0+MqdPz9aK+LEYvNiE
         Tb3A==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVB8StxNE34pUlPe1kDnMkolXsMoBmHI3ngCy8kwjqV/pIxKaI1Zpz+qFqv66yRHa3lAYzDgw==@lfdr.de
X-Gm-Message-State: AOJu0YznH8Ls4mJldag+b5g5emu7ziEMaVIdAIOwBh1BmIIzJQ6HYKJ6
	m55n+mqDWdLSPn4AKVoRcq7KV4hWneZeRgsb9rQZtEFbPULh2uqH
X-Google-Smtp-Source: AGHT+IH4kOO37AX+14TuXpUBtG+MEojexLVrv4upV2mK89Ii2F1pNqv4qDjz19kHOcUA4pszUDoOqQ==
X-Received: by 2002:a05:600c:1c8b:b0:42c:aeee:da86 with SMTP id 5b1f17b1804b1-42f584a54c5mr11777415e9.8.1727450036228;
        Fri, 27 Sep 2024 08:13:56 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:1c2a:b0:42c:af5b:fac1 with SMTP id
 5b1f17b1804b1-42f5768586als9251465e9.1.-pod-prod-05-eu; Fri, 27 Sep 2024
 08:13:54 -0700 (PDT)
X-Received: by 2002:a05:600c:1d20:b0:42c:ba83:3f00 with SMTP id 5b1f17b1804b1-42f5840e1efmr35292475e9.1.1727450034230;
        Fri, 27 Sep 2024 08:13:54 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1727450034; cv=none;
        d=google.com; s=arc-20240605;
        b=NAzLw2aLZebj2ehXSKj9dJNKoMrPX5d099MIT1R0gnu1h88UYmSLXu+7HFGQWP9Kpd
         eYJVQIrhE9nvlowvzkYdRGWVXmPqGTEl4hpHQyWH8W+dFdUrqlAvspGeVcJ1lshjUCxz
         DTmIDaT2VqC12JlNj/3WKkQFdgv0TdAR8uyfjN7yJSDqIQ39hUJs+056w53BWm8KUcR1
         5Jyma3XsVpd4zf7XisSdZ3Dz54gGh+eBNnLZkustRcz1/Vt0TNV1kp06TmcVJVsuD05Q
         Dgtwapruvfz0yV1EwwedNsSo2OSCXxLx9MZH/0Xs9bX8PsbUf9cw7ERSvI0jP7NPdRAT
         PB4g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=C2yd0eA80h4rdtqxp/kh9iCrWOEyI0g4hsGihttS/Wc=;
        fh=8b844EQrbV6pv8DbIcRZTflergcmCz1L3YswQNqdOR0=;
        b=Tlb11apNhFVLMhB6Oymf5Jzik4TJX++kw9x3rB0qOkqfmYdrok35bWKYlZvC+wFCBD
         KIB1IJYw+KOlK8NIT9mxvFlGbd0JVf23+VsykwPYVGoTdWVqnyAJgPEhLN8slHdHkPJa
         eXtcYdUFY3vBJaBOI8OI+YuTHKB+4ZhZdHnYzXSaCv8pncsV7jGpyMMM0My8DAm+DVNT
         QBTNF0Cv0+cJPGS1P1S3jAXs/+TcuykTxIY5AP4Fkpkw4jyYxEro+IqOmC3w1elMsZg7
         PcmPwbqhaRG1xREM8y6VR9IPrfLYUkj+k+p8q2ZHBU/DoJxYxXZWoiOFzlVov04wdo+h
         y8qA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=O7GSsaGn;
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::135 as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-lf1-x135.google.com (mail-lf1-x135.google.com. [2a00:1450:4864:20::135])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-42e9025c970si6652025e9.0.2024.09.27.08.13.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 27 Sep 2024 08:13:54 -0700 (PDT)
Received-SPF: pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::135 as permitted sender) client-ip=2a00:1450:4864:20::135;
Received: by mail-lf1-x135.google.com with SMTP id 2adb3069b0e04-5356aa9a0afso3636240e87.2
        for <kasan-dev@googlegroups.com>; Fri, 27 Sep 2024 08:13:54 -0700 (PDT)
X-Received: by 2002:a05:6512:3343:b0:531:8f2f:8ae7 with SMTP id 2adb3069b0e04-5389fc46b2dmr3479365e87.25.1727450033114;
        Fri, 27 Sep 2024 08:13:53 -0700 (PDT)
Received: from work.. (2.133.25.254.dynamic.telecom.kz. [2.133.25.254])
        by smtp.gmail.com with ESMTPSA id 2adb3069b0e04-53979921f54sm268143e87.152.2024.09.27.08.13.51
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 27 Sep 2024 08:13:52 -0700 (PDT)
From: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
To: ryabinin.a.a@gmail.com,
	glider@google.com,
	andreyknvl@gmail.com,
	dvyukov@google.com,
	vincenzo.frascino@arm.com,
	akpm@linux-foundation.org
Cc: kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	snovitoll@gmail.com
Subject: [PATCH] mm: instrument copy_from/to_kernel_nofault
Date: Fri, 27 Sep 2024 20:14:38 +0500
Message-Id: <20240927151438.2143936-1-snovitoll@gmail.com>
X-Mailer: git-send-email 2.34.1
MIME-Version: 1.0
X-Original-Sender: snovitoll@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=O7GSsaGn;       spf=pass
 (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::135
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

Instrument copy_from_kernel_nofault(), copy_to_kernel_nofault()
with instrument_memcpy_before() for KASAN, KCSAN checks and
instrument_memcpy_after() for KMSAN.

Tested on x86_64 and arm64 with CONFIG_KASAN_SW_TAGS.
On arm64 with CONFIG_KASAN_HW_TAGS, kunit test currently fails.
Need more clarification on it - currently, disabled in kunit test.

Reported-by: Andrey Konovalov <andreyknvl@gmail.com>
Closes: https://bugzilla.kernel.org/show_bug.cgi?id=210505
Signed-off-by: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
---
 mm/kasan/kasan_test.c | 31 +++++++++++++++++++++++++++++++
 mm/maccess.c          |  8 ++++++--
 2 files changed, 37 insertions(+), 2 deletions(-)

diff --git a/mm/kasan/kasan_test.c b/mm/kasan/kasan_test.c
index 567d33b49..329d81518 100644
--- a/mm/kasan/kasan_test.c
+++ b/mm/kasan/kasan_test.c
@@ -1944,6 +1944,36 @@ static void match_all_mem_tag(struct kunit *test)
 	kfree(ptr);
 }
 
+static void copy_from_to_kernel_nofault_oob(struct kunit *test)
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
@@ -2017,6 +2047,7 @@ static struct kunit_case kasan_kunit_test_cases[] = {
 	KUNIT_CASE(match_all_not_assigned),
 	KUNIT_CASE(match_all_ptr_tag),
 	KUNIT_CASE(match_all_mem_tag),
+	KUNIT_CASE(copy_from_to_kernel_nofault_oob),
 	{}
 };
 
diff --git a/mm/maccess.c b/mm/maccess.c
index 518a25667..2c4251df4 100644
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
@@ -32,6 +32,7 @@ long copy_from_kernel_nofault(void *dst, const void *src, size_t size)
 		return -ERANGE;
 
 	pagefault_disable();
+	instrument_memcpy_before(dst, src, size);
 	if (!(align & 7))
 		copy_from_kernel_nofault_loop(dst, src, size, u64, Efault);
 	if (!(align & 3))
@@ -39,6 +40,7 @@ long copy_from_kernel_nofault(void *dst, const void *src, size_t size)
 	if (!(align & 1))
 		copy_from_kernel_nofault_loop(dst, src, size, u16, Efault);
 	copy_from_kernel_nofault_loop(dst, src, size, u8, Efault);
+	instrument_memcpy_after(dst, src, size, 0);
 	pagefault_enable();
 	return 0;
 Efault:
@@ -49,7 +51,7 @@ EXPORT_SYMBOL_GPL(copy_from_kernel_nofault);
 
 #define copy_to_kernel_nofault_loop(dst, src, len, type, err_label)	\
 	while (len >= sizeof(type)) {					\
-		__put_kernel_nofault(dst, src, type, err_label);		\
+		__put_kernel_nofault(dst, src, type, err_label);	\
 		dst += sizeof(type);					\
 		src += sizeof(type);					\
 		len -= sizeof(type);					\
@@ -63,6 +65,7 @@ long copy_to_kernel_nofault(void *dst, const void *src, size_t size)
 		align = (unsigned long)dst | (unsigned long)src;
 
 	pagefault_disable();
+	instrument_memcpy_before(dst, src, size);
 	if (!(align & 7))
 		copy_to_kernel_nofault_loop(dst, src, size, u64, Efault);
 	if (!(align & 3))
@@ -70,6 +73,7 @@ long copy_to_kernel_nofault(void *dst, const void *src, size_t size)
 	if (!(align & 1))
 		copy_to_kernel_nofault_loop(dst, src, size, u16, Efault);
 	copy_to_kernel_nofault_loop(dst, src, size, u8, Efault);
+	instrument_memcpy_after(dst, src, size, 0);
 	pagefault_enable();
 	return 0;
 Efault:
-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240927151438.2143936-1-snovitoll%40gmail.com.
