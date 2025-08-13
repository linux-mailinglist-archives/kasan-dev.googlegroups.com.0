Return-Path: <kasan-dev+bncBDP53XW3ZQCBBYVK6LCAMGQEZRIBBWQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x439.google.com (mail-wr1-x439.google.com [IPv6:2a00:1450:4864:20::439])
	by mail.lfdr.de (Postfix) with ESMTPS id 11F3AB24ABC
	for <lists+kasan-dev@lfdr.de>; Wed, 13 Aug 2025 15:38:44 +0200 (CEST)
Received: by mail-wr1-x439.google.com with SMTP id ffacd0b85a97d-3b785d52c19sf3193021f8f.1
        for <lists+kasan-dev@lfdr.de>; Wed, 13 Aug 2025 06:38:44 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755092323; cv=pass;
        d=google.com; s=arc-20240605;
        b=kZHZ/9GppWv6o2LbnWAcYJPLZFDRS5uVKk/xqOdoM7eX1jshFRcfN46JeOCgSLdGpo
         d/N9GGH4ETwD2KwalxRu1yustn1yLLR8fl+Vt2C85Xy1AkibYiI6ugi6C8bMgz3uaLdi
         6ruhJyfETZYnCu6WOIhviGkjNzxuAPxOpJzFt79lQCvxuBvYz2+q9rOj4ywy4ybm1KqT
         NXGLQUbgHkPy5yP4CJiIkM3CasDLDM95ZHsOsDl8dNNIkZs/W4DkuaPe/GNXSzIezUmi
         7JyLuU+ksmAy/oFKP62yhFLH9z+pJneyP1qbNdf8ip6W/WcW8Gk64z3VcG168qoDxvqc
         8RzA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=OnPHVcLHW6HitnAxz+jDJW4oIuETyINJxT+tBjGyuzE=;
        fh=WX/NTw89LQKK+/BSTzM/OXnOiLiqKW6nhML6+nMKyh0=;
        b=R/cF4ILZwQLKeoZdAglrIgDdCadCaTvDRPqUNorbsZ7lY5COzFoxG+Ytm0S57DU05N
         ObO2uGu/37a8UGB8LEWdfk7RIQb1CHKF7Mm1ecUzA52NkQ2Q5FtuIJfRSWHXTKXiYKbe
         HuW+fFV0rXlUkt4ISfS22eFy8YJ0TRKAdEApfQ4JOTqVgLCq5dpjzqACoJkNvC1/6hA6
         FIj0yDh9NbnHa2gPu4w5+qx/2ladKl+n91le+Wvvp/RrpbMHmGex/NwSyDOoTUB/foEj
         1jDi0NSbpSrQUj3kzFqHb3VmkDGxq8E97W597orwKv0t0BjjMbgx27UzhhI5DaUoWUvG
         XSXA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=SSbfq4XO;
       spf=pass (google.com: domain of ethan.w.s.graham@gmail.com designates 2a00:1450:4864:20::431 as permitted sender) smtp.mailfrom=ethan.w.s.graham@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755092323; x=1755697123; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=OnPHVcLHW6HitnAxz+jDJW4oIuETyINJxT+tBjGyuzE=;
        b=KQPX55SY6HD+zYjeTqxv27ek51XC161FUr3RBQge8pJCXlkj+3K6I1MgjUw/oigep0
         WlRJUndSBO5z4CsEq4nfBYbtnMR5QWU+zswVvta2c6bzCEjUM77KYUQBdIiEuFE3hCIT
         +x3FON0pquXBHU/sqyozRrGwuKmC/qr8xKzzGJfSqNCuehTaA7gjx6uXP3WzkPZQ8hrA
         DJJ/HgZ1ftQ4BrNs2FYQklP4YL9HtDmxShLTe2nIruejpDePkW6eFa0yNUu6SNW1wMQa
         tRuCMGKiTaT/Y7JymQSvXxP6Pz7hBxlKRXaAzTfDN7Dwg7NV4T2AtP3Z7o5SbOEoBebN
         bMsA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1755092323; x=1755697123; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=OnPHVcLHW6HitnAxz+jDJW4oIuETyINJxT+tBjGyuzE=;
        b=T/xJEc08wrN2NbVLdSwlZQEDmTZND3l9drmgC1X+YLAOyb2MrBaRzaVzyqFFi41IdH
         Ff71YXvvEpTZYy3wwML9kaN+F7MLWd/Ai2DuWZbTWEy5Sb3mrDhJirvtzhPLW8pkCHtc
         9rbIKhmKG8SCaGrm1Ww3I5V9+enR9U/F8S73uRAHSsVy9qgi4f0dcu3UQvPtdpEmYUyz
         UQpR6WWvKSwlHDTlUfCZaNQaDJRgMvWDFEiFpCvBPMjbiVUNtT2Oas/cunpkONSPGqpF
         SHOXPwXcOzkjbHg17Jg2fYWS6RyPbDjZQ4B8WKvkb1Bp8cdIYEy6JAIthEe++rKw+cd1
         Xcsw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755092323; x=1755697123;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=OnPHVcLHW6HitnAxz+jDJW4oIuETyINJxT+tBjGyuzE=;
        b=Othd46WUFln/z3rKXe8lJSzK1g7+RXlsGsI5B3tbisZ5UW/A4FdbP3h6UPVpv1avK+
         Ua9vGCJlCWzkJYoCuIy4lopVIfdwDKUxG87d2fVHue0heYtk0Ff8RnZrwpuYtLEjeHTx
         NURjvX0niwamcQiGBA3CVeZwTgL4Wy1zKbUgKRA/Pc/ltuUkVbIDM+R1ATpnfvGMVmZh
         jpyVcRoqdCfUVLGkZiTRDkuotSnCKcV+mUC7uRw5vgoWxSjmL+rN8vX1N1wCt9CMYZzz
         FYWI6WMzMLrp9O0cbmHwxCs7mE7SwPKdynJAobqOjsIuNvdgknly7wKSydWxKoTtMwEN
         QQUQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUCu7v2l0fbpifYaTc25WDZSDtqFlFsZy0Uq7G7SBLx4DUZoJn3dVQzZ+kfF0QRzCcEAB6zzw==@lfdr.de
X-Gm-Message-State: AOJu0Yy10cpZVz5MQDB+1nOov5hxgaxK+skNn+vvbzy0L4prAUWheBd8
	x1knLicCSf6dhm9GRf0+ULKhUDK1GLbnFHKvmOptrLtMwhFDWDP+T/gL
X-Google-Smtp-Source: AGHT+IFdE6889vfFl+zdp6GVkhl0yhmPcEQxnjApe9ygdAcXCLQcCxm/VSfRfSgSpT4Mp4nMHFpkmA==
X-Received: by 2002:a05:6000:18a3:b0:3b8:fb9d:249d with SMTP id ffacd0b85a97d-3b917e31b20mr2285477f8f.21.1755092323356;
        Wed, 13 Aug 2025 06:38:43 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZe8UcOKVjkWHIwxP75RJvlo5QIgF2RNGrfMgJTM8QK+Ng==
Received: by 2002:a05:6000:26cb:b0:3a4:e706:5305 with SMTP id
 ffacd0b85a97d-3b915580b1bls783862f8f.0.-pod-prod-08-eu; Wed, 13 Aug 2025
 06:38:40 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWQDdpIT+g//8V/PR94xVEDMTL3Sc46ht867iIVtuknsTQ+OevGPLkmWf8VDZdAxGe88Zr2KOitTIg=@googlegroups.com
X-Received: by 2002:a05:6000:310d:b0:3b7:8154:aa36 with SMTP id ffacd0b85a97d-3b917d24577mr2589521f8f.7.1755092320236;
        Wed, 13 Aug 2025 06:38:40 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755092320; cv=none;
        d=google.com; s=arc-20240605;
        b=j7/inzVjwkQOrFfCyfkhSkvCqm89PJFX3FKgv5FlLM1PwqTb3DJmkTNg22E23BWgtz
         /TB9JqsQul0745na683/qUsb+85AB6kbSlRIsMq00gbqXDOCnO6CoUibaJUDx9TPjiGK
         Eeqn3/9FSiHB2BlyCmULehpZDEo1cmgPKed/u/OhR4FVdPETT5EjsrwSE1s0XERvTyGw
         DWDw+Hhm2Zzgy/s4B7sXZCOI2FuTK0XzecpC2FIJWQwVnHCUW754I4R5qIOZbCSNZ/e1
         UbXer9TzLAEQhZXf7LmS3LkpMCHGITINWwdVIS64AA5hILVw/IOJMptcoMFu71lqTsfH
         RGUg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=7I1CLCGLbU0y9mn/lwEJ1bdLkYwEZFUd6f7/dKgAqBc=;
        fh=TD5w1n5aw1DWvI6fZr19oyhw+W0EeA0xL1y9CWlGSx8=;
        b=VgrZsWVmbrwsQQaD2aKoYR3p2xXGYbcAkCBZIWwi4JEuPBQIYGpR+xxga10VRtNCUL
         wbmc2+ARZ9Z1bY23Jy5vKiELFxMtlLLXygy45xMxemhjaRvwwQNzj1hj2lC2K/aRQ18g
         bMXX36R4Z6Ca+ommeXwUITHn8VcHUqGyMf0ixjzM+AaEfznKQwIM54p07MyrTswrmrrF
         CoJvDKSHVRT6+T93STFWuhrMH+0SUzpItqsF4mTkN98b33Pq4zxlq9/LF5YtlfzAq1jC
         IIF4UMArnRbSsiN1an5Zj1K/4D3bo89QYWnSFdTUWKkyWwoWmWvP6jQmvSMS5TkdCpKJ
         D4GQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=SSbfq4XO;
       spf=pass (google.com: domain of ethan.w.s.graham@gmail.com designates 2a00:1450:4864:20::431 as permitted sender) smtp.mailfrom=ethan.w.s.graham@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x431.google.com (mail-wr1-x431.google.com. [2a00:1450:4864:20::431])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-45a1a508b3bsi52095e9.1.2025.08.13.06.38.40
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 13 Aug 2025 06:38:40 -0700 (PDT)
Received-SPF: pass (google.com: domain of ethan.w.s.graham@gmail.com designates 2a00:1450:4864:20::431 as permitted sender) client-ip=2a00:1450:4864:20::431;
Received: by mail-wr1-x431.google.com with SMTP id ffacd0b85a97d-3b78d337dd9so4271253f8f.3;
        Wed, 13 Aug 2025 06:38:40 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVDK3vFSpKQKEu+NUyWL6SYZoWwqHA3kdwtrBp5/vhJf/HzePPW0O1bEM6/heN8XPLS1PiFQ56+Law=@googlegroups.com, AJvYcCXlEVF/IzrcCZzgIwx6B8QrkSV44oo2Sgj8kZZKz5la0zyYbFinLM4CdvETGTqfIXF51YwToFAUNLGJ@googlegroups.com
X-Gm-Gg: ASbGncuwQi41nLd4N/PAaS8Ooi01VtxLIOUCghFGHvhdLlNJ/LSNpSyWb4eg7pEqB60
	i3Sf1azrtQ7ixUpa5awXlI5EWqvdXR4MxuIyDtoSXppdOo/XYl6HeZBbjh8/XvJrqQKC/KB8Os/
	EIdS4q1nKqdmRqwANjFmqlOFHAllFYmS5eZFGTwCMA5NK2oaUtE449gxTh3zPRSi94iPMAXGoC2
	nBTK8nsotL9oKUsquqAYD9jT96usLSC9uyg1J7pK+DFwbr2VL9fNpL4q0JZuxpKIWh2uQ4WATOT
	z0I3FcDDwnI+4ij3osYuJJIJZenTsGIenY3ZHo1bAhPzRsSSgnSwKsGlpAttSSlwO2M8UkRl8dO
	xnMx0EoUGFUUA3xpMczjFp/SjWJ15fWOy1iIPqzBQkW7UXZpx8+UtZtSXz34H2cmKzLTLhf6Qqs
	5oF+54TY+8Q7EWb/+Dfun7zJHFIg==
X-Received: by 2002:a05:6000:258a:b0:3b7:974d:5359 with SMTP id ffacd0b85a97d-3b917eacf60mr2328459f8f.32.1755092319463;
        Wed, 13 Aug 2025 06:38:39 -0700 (PDT)
Received: from xl-nested.c.googlers.com.com (87.220.76.34.bc.googleusercontent.com. [34.76.220.87])
        by smtp.gmail.com with ESMTPSA id ffacd0b85a97d-3b8f8b1bc81sm25677444f8f.69.2025.08.13.06.38.38
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 13 Aug 2025 06:38:39 -0700 (PDT)
From: Ethan Graham <ethan.w.s.graham@gmail.com>
To: ethangraham@google.com,
	glider@google.com
Cc: andreyknvl@gmail.com,
	brendan.higgins@linux.dev,
	davidgow@google.com,
	dvyukov@google.com,
	jannh@google.com,
	elver@google.com,
	rmoar@google.com,
	shuah@kernel.org,
	tarasmadan@google.com,
	kasan-dev@googlegroups.com,
	kunit-dev@googlegroups.com,
	linux-kernel@vger.kernel.org,
	linux-mm@kvack.org
Subject: [PATCH v1 RFC 1/6] mm/kasan: implement kasan_poison_range
Date: Wed, 13 Aug 2025 13:38:07 +0000
Message-ID: <20250813133812.926145-2-ethan.w.s.graham@gmail.com>
X-Mailer: git-send-email 2.51.0.rc0.205.g4a044479a3-goog
In-Reply-To: <20250813133812.926145-1-ethan.w.s.graham@gmail.com>
References: <20250813133812.926145-1-ethan.w.s.graham@gmail.com>
MIME-Version: 1.0
X-Original-Sender: ethan.w.s.graham@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=SSbfq4XO;       spf=pass
 (google.com: domain of ethan.w.s.graham@gmail.com designates
 2a00:1450:4864:20::431 as permitted sender) smtp.mailfrom=ethan.w.s.graham@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
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

From: Ethan Graham <ethangraham@google.com>

Introduce a new helper function, kasan_poison_range(), to encapsulate
the logic for poisoning an arbitrary memory range of a given size, and
expose it publically in <include/linux/kasan.h>.

This is a preparatory change for the upcoming KFuzzTest patches, which
requires the ability to poison the inter-region padding in its input
buffers.

No functional change to any other subsystem is intended by this commit.

Signed-off-by: Ethan Graham <ethangraham@google.com>
---
 include/linux/kasan.h | 16 ++++++++++++++++
 mm/kasan/shadow.c     | 31 +++++++++++++++++++++++++++++++
 2 files changed, 47 insertions(+)

diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index 890011071f2b..09baeb6c9f4d 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -102,6 +102,21 @@ static inline bool kasan_has_integrated_init(void)
 }
 
 #ifdef CONFIG_KASAN
+
+/**
+ * kasan_poison_range - poison the memory range [start, start + size)
+ *
+ * The exact behavior is subject to alignment with KASAN_GRANULE_SIZE, defined
+ * in <mm/kasan/kasan.h>.
+ *
+ * - If @start is unaligned, the initial partial granule at the beginning
+ *	of the range is only poisoned if CONFIG_KASAN_GENERIC is enabled.
+ * - The poisoning of the range only extends up to the last full granule before
+ *	the end of the range. Any remaining bytes in a final partial granule are
+ *	ignored.
+ */
+void kasan_poison_range(const void *start, size_t size);
+
 void __kasan_unpoison_range(const void *addr, size_t size);
 static __always_inline void kasan_unpoison_range(const void *addr, size_t size)
 {
@@ -402,6 +417,7 @@ static __always_inline bool kasan_check_byte(const void *addr)
 
 #else /* CONFIG_KASAN */
 
+static inline void kasan_poison_range(const void *start, size_t size) {}
 static inline void kasan_unpoison_range(const void *address, size_t size) {}
 static inline void kasan_poison_pages(struct page *page, unsigned int order,
 				      bool init) {}
diff --git a/mm/kasan/shadow.c b/mm/kasan/shadow.c
index d2c70cd2afb1..a1b6bfb35f07 100644
--- a/mm/kasan/shadow.c
+++ b/mm/kasan/shadow.c
@@ -147,6 +147,37 @@ void kasan_poison(const void *addr, size_t size, u8 value, bool init)
 }
 EXPORT_SYMBOL_GPL(kasan_poison);
 
+void kasan_poison_range(const void *start, size_t size)
+{
+	void *end = (char *)start + size;
+	uintptr_t start_addr = (uintptr_t)start;
+	uintptr_t head_granule_start;
+	uintptr_t poison_body_start;
+	uintptr_t poison_body_end;
+	size_t head_prefix_size;
+	uintptr_t end_addr;
+
+	end_addr = ALIGN_DOWN((uintptr_t)end, KASAN_GRANULE_SIZE);
+	if (start_addr >= end_addr)
+		return;
+
+	head_granule_start = ALIGN_DOWN(start_addr, KASAN_GRANULE_SIZE);
+	head_prefix_size = start_addr - head_granule_start;
+
+	if (IS_ENABLED(CONFIG_KASAN_GENERIC) && head_prefix_size > 0)
+		kasan_poison_last_granule((void *)head_granule_start,
+					  head_prefix_size);
+
+	poison_body_start = ALIGN(start_addr, KASAN_GRANULE_SIZE);
+	poison_body_end = ALIGN_DOWN(end_addr, KASAN_GRANULE_SIZE);
+
+	if (poison_body_start < poison_body_end)
+		kasan_poison((void *)poison_body_start,
+			     poison_body_end - poison_body_start,
+			     KASAN_SLAB_REDZONE, false);
+}
+EXPORT_SYMBOL(kasan_poison_range);
+
 #ifdef CONFIG_KASAN_GENERIC
 void kasan_poison_last_granule(const void *addr, size_t size)
 {
-- 
2.51.0.rc0.205.g4a044479a3-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250813133812.926145-2-ethan.w.s.graham%40gmail.com.
