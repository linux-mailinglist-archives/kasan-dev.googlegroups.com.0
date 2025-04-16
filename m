Return-Path: <kasan-dev+bncBCCMH5WKTMGRB27A7W7QMGQEZWX2U3Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13a.google.com (mail-lf1-x13a.google.com [IPv6:2a00:1450:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id D798EA8B474
	for <lists+kasan-dev@lfdr.de>; Wed, 16 Apr 2025 10:55:09 +0200 (CEST)
Received: by mail-lf1-x13a.google.com with SMTP id 2adb3069b0e04-549b3bf4664sf2993132e87.1
        for <lists+kasan-dev@lfdr.de>; Wed, 16 Apr 2025 01:55:09 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1744793709; cv=pass;
        d=google.com; s=arc-20240605;
        b=NB5ePKWsBTlxiiVzuJClqMZytZh4L/XisU0PGwwLJAosAji5Svu+GKn8Acv/kK/eQ2
         P7eX/h5yrh/bl3+LwuH1CwkDc7WG+0roP+gf7f7EK+kDP8UScK3MxKLY27n5ZYAE1K+p
         ACDA49oob/Q0RNmgZXaZWMMGWiyMTZfJjJqPLFj4mYuuRjSzAmAlPDylS+YmSbP/MvWc
         SUFBkGtRAigtYWwj1JbJjfgk1qS2da5v53fnxT2NXeBro5ZX+OB/x0ozM+5C8EjD3cG9
         K4ANK7vzcyFpfIP1xQ5N5I2X7B10/iy4jXh/fcf4S+Wqs3FSCNlR4An4z8qG1Jki7aZz
         lHyQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=Dw83ieTx0GZYrSgXzCwTc6IhMmo4qplDr328RQ2ANmo=;
        fh=X3+9Tudzc5erTo0U3vEh7GjA1cT8nHrN7nCv8s6R/1A=;
        b=LlVU/U7byEwVI+FKnoeNi49vOn2biRyrf6/pXvEROysAOhdxhSgb37ANKsRzTOxufq
         C/thmQL2L1JtYAfF0R7JszClmsn1B0UDOVPVPr+QybaZ13i/MI4FP3jUWtfXGmJV8cJi
         2kY3A+Pboa8bFLOs/AlNTDBuYYF8mTqdo4l50fEqRZrxyJJXso0WEYb/6RxzlJCt4GAH
         f/rORU6XtJnKkAv8Ctz7Zs31ae6K7UoS/K8VMiRqPc1Nv00nM9ZEIgDItvRip+x4cRlO
         czsQEpozmf8yqW9pFxFda/sYRgiJw7LiqJXXHfO/ka5JvA+mK8+7kTzhKVoTQtVZiscE
         FSuw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=zRpTtpsT;
       spf=pass (google.com: domain of 3axd_zwykcy4y30vw9y66y3w.u642sas5-vwdy66y3wy96c7a.u64@flex--glider.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3aXD_ZwYKCY4y30vw9y66y3w.u642sAs5-vwDy66y3wy96C7A.u64@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1744793709; x=1745398509; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=Dw83ieTx0GZYrSgXzCwTc6IhMmo4qplDr328RQ2ANmo=;
        b=I0CNVdBXnyTRINwUvvVgAL6HjIiF9ScS6zTfCp2U/nslU5Llr50w1EUUmpMe1oox1t
         nAKgYt+dVe2oM5FEkMjhtlsGCjtB8c2R9ITTFbUEBIHNAJceJ1sjrVYbcrsrfH5jFW6+
         ehGPolJVzw/02HmU1oCHRGmCAncBtwg0CVRDZL2xsSM9Bb9M/7f4eBi51zGbcdS/zm+P
         iWWNoQpiUMBQLJeAdVcXV5SiXGNdnMBuhzJsA0CnM6HSi0h86VRh3fZxu8yR58RlrJdP
         J9D0QdlrdLu30UnYF0z+gXUiC1012LmX3z7wbtCqjdv7pnWxa1G+h72FAfwjlxvAMBlF
         3uzw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1744793709; x=1745398509;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Dw83ieTx0GZYrSgXzCwTc6IhMmo4qplDr328RQ2ANmo=;
        b=Mm813uW3C54UqJH2XqFXq2thnTarVDnYfGiC0cho9/VE3itmAQW14qUAiO3612Zd5C
         ULmlioxAY+2aZcpIS1jSMFaIurAKe4T9OPwBvNGu0ja+hRW+7oV6de/fMoaGITzZyOjn
         LNGpgiku77pyH5Mjr7gT7sdqUDVesXhBZsY47EqFsKNCW3yZWajgltLG9c4VmoMXcsLY
         PvqaWyLyrQRouUNe4lcBYd1Zax7NWa6gu+8vf61sbrCyBOvQGsPMLHER9B+xX2Ph4A2i
         WU1sr3vLGnyWR9eA2l3QfajbkQoBVJ7J3245CoIa2f2+AqyX8HdcYpvz6YsUB33OaJYL
         kQng==
X-Forwarded-Encrypted: i=2; AJvYcCVyjS6et7UINER7WQ+Nn7yVuhvKEPrb4lrj39ZE5fiQ6uZZTEdVmzURhvV0htTad1VeZVZgJA==@lfdr.de
X-Gm-Message-State: AOJu0YxG4N3ssQFcIod4RwjsENOBxZsJCjSthumZRDemToTZk9L/g02f
	EH7wV+Z5yo9NFh2Bs9eNHbqh1uGhuY1wRY+Y08qa7Lao2O+T1qJN
X-Google-Smtp-Source: AGHT+IFdVf2XoBtdbVFdcSXuiKGgLhyS0HaSuT96PYhCqBIHBvzmeta/c7H1Q4jqqsQx6Ou3PYhjnQ==
X-Received: by 2002:a05:6512:3b95:b0:549:8d60:ca76 with SMTP id 2adb3069b0e04-54d64aee0b1mr291498e87.38.1744793708461;
        Wed, 16 Apr 2025 01:55:08 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARLLPAKBE1KYD9C+Uds+h1Eq005Ob4gJZL759O7fgUeZp3yv7Q==
Received: by 2002:a05:6512:3f04:b0:549:9b17:deaf with SMTP id
 2adb3069b0e04-54c4e2b4cf2ls87603e87.0.-pod-prod-02-eu; Wed, 16 Apr 2025
 01:55:06 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWOK3W1zcVc2QgFdVK/sRih/gfGQ4TLViQ/Ffp7XknY2QywsJFEsaZW+ML1Bef9jeo+k98DYYfvLtM=@googlegroups.com
X-Received: by 2002:a05:6512:6d0:b0:549:9044:94ac with SMTP id 2adb3069b0e04-54d64a9c246mr301589e87.23.1744793705592;
        Wed, 16 Apr 2025 01:55:05 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1744793705; cv=none;
        d=google.com; s=arc-20240605;
        b=JWfGwmyCJT4PTGUXlxdIzmciXLMtCPYPJfbyLoxH0MBJH1KSfi98kKJH0i1RdB7FzD
         f4cC0zbHI2X5CrJ3uyev+O03VHjBTtIdVKV+OYdrGg7mEUckhaIqlaHu4cGQeu6fdz7z
         V22194q+M12uxzkngC1DjD3bmHUFWADmIa5Mm6lf3Pp4ut32+BdG4CyH4rSQTiTxJ6yZ
         t2nkeCrUl2wzXl/cpIZ8jqPmjGj5Vm8aWrCg/+xj5rtv9j+FJE/fIGKOGUaUC20phyfl
         78yHTdJNbBjHGsob/6BLffYQ5kAzFnywxsrjgU7/Bmyb0Z9yP1FlHj7BCAeDq7GsariO
         IGIw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=hH2r0HpjHA+TAtMnP8ob7jw0ZAHM0/6/eJ5rdM10bGc=;
        fh=Amw/50wpFWy4qL4of1HJ8s4XX/NxN5zeUH3d5Sb4g2M=;
        b=OSNwSrTEDWFCeO0RLeIYjj0NVdR8rVhj/CT7s6p0fWHcF0h7ch6S23GawNIjNSnpmU
         QF9xqVt+GQrO0KuM1bm16nDjiU6Q3ea4Kz2qE1zZr4060eB5JMB2buDGgDZN69Cxt3p9
         NSusPGi2KADjU7L+Fblb6B21tvTWlxjrSJF72eNtQMuG4Rgw43RG8Xe50a4JR4tL/EDD
         mQlaBwZkFaWqv0zT7C7AOfwK4ndCWIA8xfWbeAhO5P2zvi+28nZ+Elchlor1wNmZDeVv
         DLFDJSmqhpl/OVhpTDEb5Osc3v7/EbKO6fQuGQOOrst4ckhmhbYPsYof0nN4Z4x/+NBt
         fkcA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=zRpTtpsT;
       spf=pass (google.com: domain of 3axd_zwykcy4y30vw9y66y3w.u642sas5-vwdy66y3wy96c7a.u64@flex--glider.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3aXD_ZwYKCY4y30vw9y66y3w.u642sAs5-vwDy66y3wy96C7A.u64@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ej1-x64a.google.com (mail-ej1-x64a.google.com. [2a00:1450:4864:20::64a])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-54d3d508a4bsi408833e87.6.2025.04.16.01.55.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 16 Apr 2025 01:55:05 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3axd_zwykcy4y30vw9y66y3w.u642sas5-vwdy66y3wy96c7a.u64@flex--glider.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) client-ip=2a00:1450:4864:20::64a;
Received: by mail-ej1-x64a.google.com with SMTP id a640c23a62f3a-ac6a0443bafso678261666b.2
        for <kasan-dev@googlegroups.com>; Wed, 16 Apr 2025 01:55:05 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUywAT7LMlKbW0FkzsPgXlkDUz49+w/xQr4mq+MjfudLnm2YvJGUUnUDYUZ6vKAbEp9iQ/IJ3W7HBI=@googlegroups.com
X-Received: from ejkh19.prod.google.com ([2002:a17:906:7193:b0:aca:c1c0:e337])
 (user=glider job=prod-delivery.src-stubby-dispatcher) by 2002:a17:907:9494:b0:acb:349d:f909
 with SMTP id a640c23a62f3a-acb42a50028mr74361466b.31.1744793705000; Wed, 16
 Apr 2025 01:55:05 -0700 (PDT)
Date: Wed, 16 Apr 2025 10:54:41 +0200
In-Reply-To: <20250416085446.480069-1-glider@google.com>
Mime-Version: 1.0
References: <20250416085446.480069-1-glider@google.com>
X-Mailer: git-send-email 2.49.0.604.gff1f9ca942-goog
Message-ID: <20250416085446.480069-4-glider@google.com>
Subject: [PATCH 3/7] kcov: x86: introduce CONFIG_KCOV_ENABLE_GUARDS
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
To: glider@google.com
Cc: quic_jiangenj@quicinc.com, linux-kernel@vger.kernel.org, 
	kasan-dev@googlegroups.com, x86@kernel.org, 
	Aleksandr Nogikh <nogikh@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, Borislav Petkov <bp@alien8.de>, 
	Dave Hansen <dave.hansen@linux.intel.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Ingo Molnar <mingo@redhat.com>, Josh Poimboeuf <jpoimboe@kernel.org>, Marco Elver <elver@google.com>, 
	Peter Zijlstra <peterz@infradead.org>, Thomas Gleixner <tglx@linutronix.de>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=zRpTtpsT;       spf=pass
 (google.com: domain of 3axd_zwykcy4y30vw9y66y3w.u642sas5-vwdy66y3wy96c7a.u64@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3aXD_ZwYKCY4y30vw9y66y3w.u642sAs5-vwDy66y3wy96C7A.u64@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

The new config switches coverage instrumentation to using
  __sanitizer_cov_trace_pc_guard(u32 *guard)
instead of
  __sanitizer_cov_trace_pc(void)

Each callback receives a unique 32-bit guard variable residing in the
__sancov_guards section. Those guards can be used by kcov to deduplicate
the coverage on the fly.

As a first step, we make the new instrumentation mode 1:1 compatible with
the old one.

Cc: x86@kernel.org
Signed-off-by: Alexander Potapenko <glider@google.com>
---
 arch/x86/kernel/vmlinux.lds.S     |  1 +
 include/asm-generic/vmlinux.lds.h | 14 ++++++-
 include/linux/kcov.h              |  2 +
 kernel/kcov.c                     | 61 +++++++++++++++++++++----------
 lib/Kconfig.debug                 | 16 ++++++++
 scripts/Makefile.kcov             |  4 ++
 scripts/module.lds.S              | 23 ++++++++++++
 tools/objtool/check.c             |  1 +
 8 files changed, 101 insertions(+), 21 deletions(-)

diff --git a/arch/x86/kernel/vmlinux.lds.S b/arch/x86/kernel/vmlinux.lds.S
index 0deb4887d6e96..2acfbbde33820 100644
--- a/arch/x86/kernel/vmlinux.lds.S
+++ b/arch/x86/kernel/vmlinux.lds.S
@@ -390,6 +390,7 @@ SECTIONS
 		. = ALIGN(PAGE_SIZE);
 		__bss_stop = .;
 	}
+	SANCOV_GUARDS_BSS
 
 	/*
 	 * The memory occupied from _text to here, __end_of_kernel_reserve, is
diff --git a/include/asm-generic/vmlinux.lds.h b/include/asm-generic/vmlinux.lds.h
index 0d5b186abee86..3ff150f152737 100644
--- a/include/asm-generic/vmlinux.lds.h
+++ b/include/asm-generic/vmlinux.lds.h
@@ -102,7 +102,8 @@
  * sections to be brought in with rodata.
  */
 #if defined(CONFIG_LD_DEAD_CODE_DATA_ELIMINATION) || defined(CONFIG_LTO_CLANG) || \
-defined(CONFIG_AUTOFDO_CLANG) || defined(CONFIG_PROPELLER_CLANG)
+	defined(CONFIG_AUTOFDO_CLANG) || defined(CONFIG_PROPELLER_CLANG) || \
+	defined(CONFIG_KCOV_ENABLE_GUARDS)
 #define TEXT_MAIN .text .text.[0-9a-zA-Z_]*
 #else
 #define TEXT_MAIN .text
@@ -121,6 +122,17 @@ defined(CONFIG_AUTOFDO_CLANG) || defined(CONFIG_PROPELLER_CLANG)
 #define SBSS_MAIN .sbss
 #endif
 
+#if defined(CONFIG_KCOV_ENABLE_GUARDS)
+#define SANCOV_GUARDS_BSS			\
+	__sancov_guards(NOLOAD) : {		\
+		__start___sancov_guards = .;	\
+		*(__sancov_guards);		\
+		__stop___sancov_guards = .;	\
+	}
+#else
+#define SANCOV_GUARDS_BSS
+#endif
+
 /*
  * GCC 4.5 and later have a 32 bytes section alignment for structures.
  * Except GCC 4.9, that feels the need to align on 64 bytes.
diff --git a/include/linux/kcov.h b/include/linux/kcov.h
index e1f7d793c1cb3..7ec2669362fd1 100644
--- a/include/linux/kcov.h
+++ b/include/linux/kcov.h
@@ -107,6 +107,8 @@ typedef unsigned long long kcov_u64;
 #endif
 
 void __sanitizer_cov_trace_pc(void);
+void __sanitizer_cov_trace_pc_guard(u32 *guard);
+void __sanitizer_cov_trace_pc_guard_init(uint32_t *start, uint32_t *stop);
 void __sanitizer_cov_trace_cmp1(u8 arg1, u8 arg2);
 void __sanitizer_cov_trace_cmp2(u16 arg1, u16 arg2);
 void __sanitizer_cov_trace_cmp4(u32 arg1, u32 arg2);
diff --git a/kernel/kcov.c b/kernel/kcov.c
index 8fcbca236bec5..b97f429d17436 100644
--- a/kernel/kcov.c
+++ b/kernel/kcov.c
@@ -193,27 +193,15 @@ static notrace unsigned long canonicalize_ip(unsigned long ip)
 	return ip;
 }
 
-/*
- * Entry point from instrumented code.
- * This is called once per basic-block/edge.
- */
-void notrace __sanitizer_cov_trace_pc(void)
+static void sanitizer_cov_write_subsequent(unsigned long *area, int size,
+					   unsigned long ip)
 {
-	struct task_struct *t;
-	unsigned long *area;
-	unsigned long ip = canonicalize_ip(_RET_IP_);
-	unsigned long pos;
-
-	t = current;
-	if (!check_kcov_mode(KCOV_MODE_TRACE_PC, t))
-		return;
-
-	area = t->kcov_state.s.area;
 	/* The first 64-bit word is the number of subsequent PCs. */
-	pos = READ_ONCE(area[0]) + 1;
-	if (likely(pos < t->kcov_state.s.size)) {
-		/* Previously we write pc before updating pos. However, some
-		 * early interrupt code could bypass check_kcov_mode() check
+	unsigned long pos = READ_ONCE(area[0]) + 1;
+
+	if (likely(pos < size)) {
+		/*
+		 * Some early interrupt code could bypass check_kcov_mode() check
 		 * and invoke __sanitizer_cov_trace_pc(). If such interrupt is
 		 * raised between writing pc and updating pos, the pc could be
 		 * overitten by the recursive __sanitizer_cov_trace_pc().
@@ -224,7 +212,40 @@ void notrace __sanitizer_cov_trace_pc(void)
 		area[pos] = ip;
 	}
 }
+
+/*
+ * Entry point from instrumented code.
+ * This is called once per basic-block/edge.
+ */
+#ifndef CONFIG_KCOV_ENABLE_GUARDS
+void notrace __sanitizer_cov_trace_pc(void)
+{
+	if (!check_kcov_mode(KCOV_MODE_TRACE_PC, current))
+		return;
+
+	sanitizer_cov_write_subsequent(current->kcov_state.s.area,
+				       current->kcov_state.s.size,
+				       canonicalize_ip(_RET_IP_));
+}
 EXPORT_SYMBOL(__sanitizer_cov_trace_pc);
+#else
+void notrace __sanitizer_cov_trace_pc_guard(u32 *guard)
+{
+	if (!check_kcov_mode(KCOV_MODE_TRACE_PC, current))
+		return;
+
+	sanitizer_cov_write_subsequent(current->kcov_state.s.area,
+				       current->kcov_state.s.size,
+				       canonicalize_ip(_RET_IP_));
+}
+EXPORT_SYMBOL(__sanitizer_cov_trace_pc_guard);
+
+void notrace __sanitizer_cov_trace_pc_guard_init(uint32_t *start,
+						 uint32_t *stop)
+{
+}
+EXPORT_SYMBOL(__sanitizer_cov_trace_pc_guard_init);
+#endif
 
 #ifdef CONFIG_KCOV_ENABLE_COMPARISONS
 static void notrace write_comp_data(u64 type, u64 arg1, u64 arg2, u64 ip)
@@ -252,7 +273,7 @@ static void notrace write_comp_data(u64 type, u64 arg1, u64 arg2, u64 ip)
 	start_index = 1 + count * KCOV_WORDS_PER_CMP;
 	end_pos = (start_index + KCOV_WORDS_PER_CMP) * sizeof(u64);
 	if (likely(end_pos <= max_pos)) {
-		/* See comment in __sanitizer_cov_trace_pc(). */
+		/* See comment in sanitizer_cov_write_subsequent(). */
 		WRITE_ONCE(area[0], count + 1);
 		barrier();
 		area[start_index] = type;
diff --git a/lib/Kconfig.debug b/lib/Kconfig.debug
index 35796c290ca35..a81d086b8e1ff 100644
--- a/lib/Kconfig.debug
+++ b/lib/Kconfig.debug
@@ -2135,6 +2135,8 @@ config ARCH_HAS_KCOV
 config CC_HAS_SANCOV_TRACE_PC
 	def_bool $(cc-option,-fsanitize-coverage=trace-pc)
 
+config CC_HAS_SANCOV_TRACE_PC_GUARD
+	def_bool $(cc-option,-fsanitize-coverage=trace-pc-guard)
 
 config KCOV
 	bool "Code coverage for fuzzing"
@@ -2151,6 +2153,20 @@ config KCOV
 
 	  For more details, see Documentation/dev-tools/kcov.rst.
 
+config KCOV_ENABLE_GUARDS
+	depends on KCOV
+	depends on CC_HAS_SANCOV_TRACE_PC_GUARD
+	bool "Use fsanitize-coverage=trace-pc-guard for kcov"
+	help
+	  Use coverage guards instrumentation for kcov, passing
+	  -fsanitize-coverage=trace-pc-guard to the compiler.
+
+	  Every coverage callback is associated with a global variable that
+	  allows to efficiently deduplicate coverage at collection time.
+
+	  This comes at a cost of increased binary size (4 bytes of .bss
+	  per basic block, plus 1-2 instructions to pass an extra parameter).
+
 config KCOV_ENABLE_COMPARISONS
 	bool "Enable comparison operands collection by KCOV"
 	depends on KCOV
diff --git a/scripts/Makefile.kcov b/scripts/Makefile.kcov
index 67e8cfe3474b7..ec63d471d5773 100644
--- a/scripts/Makefile.kcov
+++ b/scripts/Makefile.kcov
@@ -1,5 +1,9 @@
 # SPDX-License-Identifier: GPL-2.0-only
+ifeq ($(CONFIG_KCOV_ENABLE_GUARDS),y)
+kcov-flags-$(CONFIG_CC_HAS_SANCOV_TRACE_PC_GUARD) += -fsanitize-coverage=trace-pc-guard
+else
 kcov-flags-$(CONFIG_CC_HAS_SANCOV_TRACE_PC)	+= -fsanitize-coverage=trace-pc
+endif
 kcov-flags-$(CONFIG_KCOV_ENABLE_COMPARISONS)	+= -fsanitize-coverage=trace-cmp
 kcov-flags-$(CONFIG_GCC_PLUGIN_SANCOV)		+= -fplugin=$(objtree)/scripts/gcc-plugins/sancov_plugin.so
 
diff --git a/scripts/module.lds.S b/scripts/module.lds.S
index 450f1088d5fd3..ec7e9247f8de6 100644
--- a/scripts/module.lds.S
+++ b/scripts/module.lds.S
@@ -64,6 +64,29 @@ SECTIONS {
 		MOD_CODETAG_SECTIONS()
 	}
 #endif
+
+#ifdef CONFIG_KCOV_ENABLE_GUARDS
+	__sancov_guards(NOLOAD) : {
+		__start___sancov_guards = .;
+		*(__sancov_guards);
+		__stop___sancov_guards = .;
+	}
+
+	.text : {
+		*(.text .text.[0-9a-zA-Z_]*)
+		*(.text..L*)
+	}
+
+	.init.text : {
+		*(.init.text .init.text.[0-9a-zA-Z_]*)
+		*(.init.text..L*)
+	}
+	.exit.text : {
+		*(.exit.text .exit.text.[0-9a-zA-Z_]*)
+		*(.exit.text..L*)
+	}
+#endif
+
 	MOD_SEPARATE_CODETAG_SECTIONS()
 }
 
diff --git a/tools/objtool/check.c b/tools/objtool/check.c
index ce973d9d8e6d8..a5db690dd2def 100644
--- a/tools/objtool/check.c
+++ b/tools/objtool/check.c
@@ -1149,6 +1149,7 @@ static const char *uaccess_safe_builtin[] = {
 	"write_comp_data",
 	"check_kcov_mode",
 	"__sanitizer_cov_trace_pc",
+	"__sanitizer_cov_trace_pc_guard",
 	"__sanitizer_cov_trace_const_cmp1",
 	"__sanitizer_cov_trace_const_cmp2",
 	"__sanitizer_cov_trace_const_cmp4",
-- 
2.49.0.604.gff1f9ca942-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250416085446.480069-4-glider%40google.com.
