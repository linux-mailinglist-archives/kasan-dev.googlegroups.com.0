Return-Path: <kasan-dev+bncBC7OBJGL2MHBB2MDXH3AKGQEOGRHXSQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53a.google.com (mail-pg1-x53a.google.com [IPv6:2607:f8b0:4864:20::53a])
	by mail.lfdr.de (Postfix) with ESMTPS id 5EB061E3F11
	for <lists+kasan-dev@lfdr.de>; Wed, 27 May 2020 12:33:15 +0200 (CEST)
Received: by mail-pg1-x53a.google.com with SMTP id u76sf19068815pgc.1
        for <lists+kasan-dev@lfdr.de>; Wed, 27 May 2020 03:33:15 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1590575594; cv=pass;
        d=google.com; s=arc-20160816;
        b=x5dfBDB5rpWRIYFG1HEiRe7/k8ixIj+LEznRpJBVMjaxBIJ84rqFjfD6o+EysvBe5E
         BE4K69WNZvRVxzi7E8u/ZzNjfQohjupuPQ4p+xQcGo08IgwrX19CJIDspYpkGcSlgqSE
         2bUKrqAAtETA3TW8/Wm4s8KspPFQ6BxFsu8+hZniFHCTiScFNsnJDJ9jsOJOcbPWJg07
         cCM7rMuFnz4d5bifRYBMHvBmNuPE8bgtAvrCQI5SBKdP88ZnxQaMUAmbt9T1ixTOksZN
         kLS0+k8f+CQ0PjUxDu3fP1UnIoM2Fzu9rZy4fiiWeTsApCfpc3XQVEPUfRANgMRM4b/d
         ZMig==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=yN720wMtCcYHva+10BkI+SvMx3WutZ1UTsLkiVlG8l4=;
        b=vwezSVenIZOWZcc83ZZ9HP6kksJVOIwgyxeyolv9T3xXN99AVAe1RnGNIBixO2i6Wn
         ohSBRmub+XiBBo0kdW0bKXfryOllD9I0UOcmyGcq66bUE9NQwIKbkrtQSXGOFhYrJ0YE
         hBq5znE6SgSvYVL3sFBB2PQROslqIXguETHZtc8EgPKw/MbEF2o6nXXPMd7s7cp9fokW
         rrwuVJBJsqfOJFdd/4n+md1asG6t0QmmAJocca0dwCxLxbRPF6xhRTxYRYF+ayyr5EUN
         A0i39tcHQet3zGxnLxW9ut6+7WpmWSIMADBWlJDBW/9uMwtYQUVm1xZfoYiWCQ3BSsl1
         1fXQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=h9B95SbK;
       spf=pass (google.com: domain of 350hoxgukcaaelvergoogle.comkasan-devgooglegroups.com@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=350HOXgUKCaAELVERGOOGLE.COMKASAN-DEVGOOGLEGROUPS.COM@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=yN720wMtCcYHva+10BkI+SvMx3WutZ1UTsLkiVlG8l4=;
        b=q2ZmwApTUf9DPpuS6Ilroz/mlS5ZqanDA+KQ49Be8jHZbeM0/rBA5VMssa07+lhtuX
         t8/Y/V6e9L4zKCyMa15ILU/MKXiofZHxRmaE4ny8NYg+u6RFw+ietduUFRKA9qTjDlc3
         SRwbJfDfscwHRzZcpDy7EKVI5JB/A1r3f0+mYMDnC5ra8UzETuuPutdghdQ590idyf/r
         3PTw16TiI60EFDYiQYSFjUC9LGKqUc2mHbCcpJWZfbhuUilt1L/fapfWqMDXbLSWZ4jK
         LRFIvx4cqqR91fUWFVvk8+d0F4SI2Oq0WK1H4LX68FiNw3gHw/3grnZx1rFdXz8ixgKE
         iW8Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=yN720wMtCcYHva+10BkI+SvMx3WutZ1UTsLkiVlG8l4=;
        b=NugyFpGQtCvzm6iJk40mLw+RO/PJzLo4MBI4+o+yf5MF6f8TuQwp9gHMkaMU+pgtJo
         SR3kpfYxAjiMp1aNDK9kfmZWcYHiid3qePkA05uBGgjbx/NrcKDIIzGT9ZKEyTt9EYuS
         FhCxJowIml8PTb+YH99DgAwlcO3CNCLxRVT43cD4NC2rgU74qO/QWLIXR/vAcBVj6JRb
         uQyGpxvG4tGesoVBTVEdZNtHArilEaU6sFhOsbxgQumr0b2EtLaU26pq/37hUJEABpW+
         fZyG8o6b//tw7z802edpw3USEoke3rOS6RTmrQMXIPFxjx+xiUTlD1pDWPqt2g4b6Z3S
         IgoQ==
X-Gm-Message-State: AOAM5338paxRqK6kGnFnGb7+Z2qDY/0sL/OMRC6B2HbYLv2bcnGv1lJO
	4omiYKcL+HLWGYZMILPQ0K8=
X-Google-Smtp-Source: ABdhPJzLtBDa76VbsXWwBJTZD2BuqMxevQKb3I0XDG3Fdbw/wzIudWhtLWFqaBA/QMWXaL4Oee91Vg==
X-Received: by 2002:aa7:955d:: with SMTP id w29mr3391958pfq.133.1590575593179;
        Wed, 27 May 2020 03:33:13 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:384c:: with SMTP id nl12ls1317679pjb.2.canary-gmail;
 Wed, 27 May 2020 03:33:12 -0700 (PDT)
X-Received: by 2002:a17:90b:3c7:: with SMTP id go7mr4467315pjb.67.1590575592684;
        Wed, 27 May 2020 03:33:12 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1590575592; cv=none;
        d=google.com; s=arc-20160816;
        b=ZdGQCXxcyAMmMsmWe6exQHX+4VZljstMU8WCXh/nGW/TyQCUZXDJbChW4E332jC3qj
         XcbWgaUtiI/sKUqogKdbGD9Tl+LRAZc3G1ML2kmMJwg7XyBNYEgGuYfimaikQQpTJdI2
         1TcV8Ea4d88Jw8WfRzgigXAd01Ya4P2WJka9NjjrbuEDKC4SuTh2ZxwbPCMJUnUU+J5B
         t0HduJIp4PlKHVPd651vUZdHprotYEojKqg1DFHK3O/AnnYxef9Zcy97l1FVctIiUqco
         CTAMmWcVoDsbAEWvuJ5JpdH1xlBdlk4vhohXOGJ607K82/eZ4c7qPbJATuIsujGUWOPh
         W/nQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=DosOYF3ps8rgQKGpMQeCZ1cwpGKFHV+Ez1qTc9wvzYQ=;
        b=qsi5IbuaXBieoHfDBdn9KPQ7BPb47u3I//tAeMrqgT+lIP3rad42Otrx5iZABt03ye
         xDWZboKyyYo01eyhWJ55rdxD2SCUdrIPLoJiCVG2oRaOHqST0O6zkvXU9KNHgtnklyTH
         abX71pcQYFLXPGLUea6isooGiwzU4GgQc9ROvGXkupTmakZu1CBdOEK3rfDonPUVN7x1
         j37eN/hB4WqeCcvqtk4uJjrt4cVw0cvddZ8ajGjSrBpRe5k4CFxpoiJC2+2lui9QRNiA
         rXIxwIMYgviPup5EzlO+dUiliVJTwvxJvGwiryUcjz/q4AcUFZiZr7PaXijULKAZlJY1
         GUoA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=h9B95SbK;
       spf=pass (google.com: domain of 350hoxgukcaaelvergoogle.comkasan-devgooglegroups.com@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=350HOXgUKCaAELVERGOOGLE.COMKASAN-DEVGOOGLEGROUPS.COM@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x74a.google.com (mail-qk1-x74a.google.com. [2607:f8b0:4864:20::74a])
        by gmr-mx.google.com with ESMTPS id y7si65729pjv.0.2020.05.27.03.33.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 27 May 2020 03:33:12 -0700 (PDT)
Received-SPF: pass (google.com: domain of 350hoxgukcaaelvergoogle.comkasan-devgooglegroups.com@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) client-ip=2607:f8b0:4864:20::74a;
Received: by mail-qk1-x74a.google.com with SMTP id v6so23349481qkd.9
        for <kasan-dev@googlegroups.com>; Wed, 27 May 2020 03:33:12 -0700 (PDT)
X-Received: by 2002:ad4:5684:: with SMTP id bc4mr24918443qvb.85.1590575591788;
 Wed, 27 May 2020 03:33:11 -0700 (PDT)
Date: Wed, 27 May 2020 12:32:36 +0200
Message-Id: <20200527103236.148700-1-elver@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.27.0.rc0.183.gde8f92d652-goog
Subject: [PATCH -tip] compiler_types.h: Optimize __unqual_scalar_typeof
 compilation time
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com
Cc: will@kernel.org, peterz@infradead.org, bp@alien8.de, tglx@linutronix.de, 
	mingo@kernel.org, clang-built-linux@googlegroups.com, paulmck@kernel.org, 
	dvyukov@google.com, glider@google.com, andreyknvl@google.com, 
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	Arnd Bergmann <arnd@arndb.de>, Nick Desaulniers <ndesaulniers@google.com>, 
	Stephen Rothwell <sfr@canb.auug.org.au>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=h9B95SbK;       spf=pass
 (google.com: domain of 350hoxgukcaaelvergoogle.comkasan-devgooglegroups.com@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=350HOXgUKCaAELVERGOOGLE.COMKASAN-DEVGOOGLEGROUPS.COM@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

If the compiler supports C11's _Generic, use it to speed up compilation
times of __unqual_scalar_typeof(). GCC version 4.9 or later and
all supported versions of Clang support the feature (the oldest
supported compiler that doesn't support _Generic is GCC 4.8, for which
we use the slower alternative).

The non-_Generic variant relies on multiple expansions of
__pick_integer_type -> __pick_scalar_type -> __builtin_choose_expr,
which increases pre-processed code size, and can cause compile times to
increase in files with numerous expansions of READ_ONCE(), or other
users of __unqual_scalar_typeof().

Summary of compile-time benchmarking done by Arnd Bergmann [1]:

	<baseline normalized time>  clang-11   gcc-9
	this patch                      0.78    0.91
	ideal                           0.76    0.86

[1] https://lkml.kernel.org/r/CAK8P3a3UYQeXhiufUevz=rwe09WM_vSTCd9W+KvJHJcOeQyWVA@mail.gmail.com

Further compile-testing done with:
	gcc 4.8, 4.9, 5.5, 6.4, 7.5, 8.4;
	clang 9, 10.

Reported-by: Arnd Bergmann <arnd@arndb.de>
Signed-off-by: Marco Elver <elver@google.com>
Cc: Borislav Petkov <bp@alien8.de>
Cc: Ingo Molnar <mingo@kernel.org>
Cc: Nick Desaulniers <ndesaulniers@google.com>
Cc: Paul E. McKenney <paulmck@kernel.org>
Cc: Peter Zijlstra <peterz@infradead.org>
Cc: Stephen Rothwell <sfr@canb.auug.org.au>
Cc: Thomas Gleixner <tglx@linutronix.de>
Cc: Will Deacon <will@kernel.org>
Link: https://lkml.kernel.org/r/CAK8P3a0RJtbVi1JMsfik=jkHCNFv+DJn_FeDg-YLW+ueQW3tNg@mail.gmail.com
---
Same version as in:
https://lkml.kernel.org/r/20200526173312.GA30240@google.com
---
 include/linux/compiler_types.h | 22 +++++++++++++++++++++-
 1 file changed, 21 insertions(+), 1 deletion(-)

diff --git a/include/linux/compiler_types.h b/include/linux/compiler_types.h
index 5faf68eae204..a529fa263906 100644
--- a/include/linux/compiler_types.h
+++ b/include/linux/compiler_types.h
@@ -245,7 +245,9 @@ struct ftrace_likely_data {
 /*
  * __unqual_scalar_typeof(x) - Declare an unqualified scalar type, leaving
  *			       non-scalar types unchanged.
- *
+ */
+#if defined(CONFIG_CC_IS_GCC) && CONFIG_GCC_VERSION < 40900
+/*
  * We build this out of a couple of helper macros in a vain attempt to
  * help you keep your lunch down while reading it.
  */
@@ -267,6 +269,24 @@ struct ftrace_likely_data {
 			__pick_integer_type(x, int,				\
 				__pick_integer_type(x, long,			\
 					__pick_integer_type(x, long long, x))))))
+#else
+/*
+ * If supported, prefer C11 _Generic for better compile-times. As above, 'char'
+ * is not type-compatible with 'signed char', and we define a separate case.
+ */
+#define __scalar_type_to_expr_cases(type)				\
+		type: (type)0, unsigned type: (unsigned type)0
+
+#define __unqual_scalar_typeof(x) typeof(				\
+		_Generic((x),						\
+			 __scalar_type_to_expr_cases(char),		\
+			 signed char: (signed char)0,			\
+			 __scalar_type_to_expr_cases(short),		\
+			 __scalar_type_to_expr_cases(int),		\
+			 __scalar_type_to_expr_cases(long),		\
+			 __scalar_type_to_expr_cases(long long),	\
+			 default: (x)))
+#endif
 
 /* Is this type a native word size -- useful for atomic operations */
 #define __native_word(t) \
-- 
2.27.0.rc0.183.gde8f92d652-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200527103236.148700-1-elver%40google.com.
