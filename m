Return-Path: <kasan-dev+bncBC7OBJGL2MHBBLUIYXTQKGQETGZTDFY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd38.google.com (mail-io1-xd38.google.com [IPv6:2607:f8b0:4864:20::d38])
	by mail.lfdr.de (Postfix) with ESMTPS id CD6C1310F1
	for <lists+kasan-dev@lfdr.de>; Fri, 31 May 2019 17:11:43 +0200 (CEST)
Received: by mail-io1-xd38.google.com with SMTP id f22sf7794963ioh.22
        for <lists+kasan-dev@lfdr.de>; Fri, 31 May 2019 08:11:43 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1559315502; cv=pass;
        d=google.com; s=arc-20160816;
        b=pvcwaoYN92klKF+JRFO07b+jGEVgoKcvvmlOBc4g4xxFHlPgoaH4CeDd5WBNoOGu8O
         vx4YFsH5uFCx1UIjaMKe1gpUI+DyjEnWQm5teW0QwO/Y6HLHoLMH8RKqGs66N8C8Jx+T
         BtswSBulw3ENinMvMj/XA9iKpM9vtB97kZLoTA+XWg7lb052d09r2fYRn8ykGUEBmO+O
         SwRYAnVSiLponyF7bkJzkY+INS4SOMlRzR06hdzn+qFehZOL4tCFDxHslQrg95V17Gpd
         be6eyb4aFS33CMLUKg+/UUMeICHXYRX6rJ3F86FAdJoGTzZT35a6h8LAhSUymen0cehC
         Nyog==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=VKuuXpYz9TIEnXMiHGGcbhtWdhnkbGiXA8vDRNoS8B4=;
        b=ZMVELyf+6UtLCG4Tlo0wwZExEzBCoEAKRY89nQTmco+WvqSqzHpLM/255AxinpHt4L
         J8XKg1zgNNpQ1Q2HUHpKVi3kwCKNBOy2/8PiyqyayFisS3bta+j8gCuv1XGtc6DvAEOT
         o3MMW1Wx4C1qRnhd5U4p5Bcy3IzR5iDwPrGvgxkB6I/NUHqt3mFF5z4c3Wj4+28l4rxo
         9ubsxi/kDTZ5kPQ+Q3pQNJL1gTPZTyw1raiAxSA5BZrne+IeXceNakPywlPqthGRbq0N
         I8Kt7159xBAVSMzXXwzAPEJlNUQdyFc45JnliFD5gwoiYL+W7i4cRnQZHd/lSqtINpFH
         Kzzw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ozkPZplA;
       spf=pass (google.com: domain of 3lutxxaukcwgkrbkxmuumrk.iusqgygt-jkbmuumrkmxuavy.ius@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::e4a as permitted sender) smtp.mailfrom=3LUTxXAUKCWgKRbKXMUUMRK.IUSQGYGT-JKbMUUMRKMXUaVY.IUS@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=VKuuXpYz9TIEnXMiHGGcbhtWdhnkbGiXA8vDRNoS8B4=;
        b=bJHqh/Lls1XITzkHI03+F9OfwHgMMTLs5l4L8xxVlcWtbJ9hQubGzsdpcmQSxy8UnI
         GrNDRybhtD/T/DnnqUW1BWm3LlIL4aie44f+Hy4zBpzbFkIZVazOhfWE2rWHyyuHl4uQ
         Ra1Sy4b+WY1yP6lLOea4YYbeYVT67nO5dG9SCFAaf0neirBPv5CiThPxSiCXLcuAqMlZ
         ZpY1VisEU51IyZ7cYr6NsA6aKFstxvBMLIzPourippTKiEo1ZJVdsF3SpQnfzwZRs/yn
         F4gtIFp+uVSnbYvmmMICYW5NZlaLYIN/REYW1OVVMsAzH2Tpo3XLroReILMEUFJIb4wP
         /QVA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=VKuuXpYz9TIEnXMiHGGcbhtWdhnkbGiXA8vDRNoS8B4=;
        b=XxLKu27q/NpoKtr9uineSnRWMtxMRQyPfH463AePaqhXFtBVDqTwmSgVBFknaC2RZd
         GkxzNA+GnInid4Z4mq4fxg6u3CxApiiR5CNCL1eUso96Iej0U3rJ2eD/ZzlAxK8INWbY
         u7udK/z+qFWnGxgkhcXR7t+FhEQPQzptOAoPJfOAO6doYbwUeYkoiV/gIDwwbViXRE1W
         j05kkxznBNHMENBIxO2cXpIsaH+boClra097AGKymS1Ui2s/r+Rv8M2+9MC/xxrRY7+a
         OJkUentX8iLa84Zp/CFLS7DtdG9tKQVbD9KYcVm+Hj557v52fId3wsbHABKDKxLanOBy
         EcOA==
X-Gm-Message-State: APjAAAXFqKgk3N0yjcfUy8HdyRvxbbPfsUuAyZfxEnYUdg3amtUwevwB
	lsLi3PXBHwYHRLl5y6xeCrs=
X-Google-Smtp-Source: APXvYqw8A1f7z+SrMJWBTMD8Ltb7ufkSZ46GUU1P41q3Jvzeb0XIZ0XEfwM8GSZEa1v85MglGZWZxQ==
X-Received: by 2002:a02:6d48:: with SMTP id e8mr6622580jaf.89.1559315502408;
        Fri, 31 May 2019 08:11:42 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a24:6412:: with SMTP id t18ls1804022itc.4.gmail; Fri, 31 May
 2019 08:11:42 -0700 (PDT)
X-Received: by 2002:a05:660c:14b:: with SMTP id r11mr7662933itk.44.1559315502049;
        Fri, 31 May 2019 08:11:42 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1559315502; cv=none;
        d=google.com; s=arc-20160816;
        b=SvbbHWXP1fn9ePbvWsUgiqSeGu0EM4766461a3HJ2ar7R059eJYv4ZwsFkpLP/zQur
         8kI/KKDbaq713SCjU1x9yXUE4opZBZZ6fn31LWbpaC8P9PNZgJiy6qv0cJWvYV6BnwFa
         XvNb8COSe7TagIXURUmIKfklc9DioA+7HaJazKNtFVUyQLOwfJc5qBCCzEK8STBXXNhV
         yrBMlSOuxUvMlYwg0wuqYWCbkOU6j5WBF9wJLvHvPGDXJa7VmOXaMGdUABDezxPOlb9e
         kPaONT3aOFiz20FXuxIa75VUUHwi1E8aEcKRb00YA+Nf46kr+I4OqEUVUrXewCBJelHq
         yEig==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=LNEghw4B+GvmCMDyCJlZQOSF0gWgpI6UWg+d86gG2mc=;
        b=BguCTJ/U7c53ngm3aH5FRhxo516qsoSpiWBocVzgeUgkh8FoGDo86h2uQB2gLZ7j7y
         RsAaaoR5yZSU4eygE7ctX/7OVLayWdRE4DF4sm/tmutz3Lth7OugwMsmwVJWMRTBNQGp
         cwplQXEDIryqc01X+5HWyWhAScxo6B/9yNOr/sAL9OFDGAT16XZ8jLv2nU3ouXU4udR/
         qoYvA3kiM+4mOmlamZbF03fDkmng9+Wkq4EA03Aj29nBy30g1UkBS8xARZIwjWkevxcH
         WSYuc6UWFnkyq57IeYXy42cqgSn+ALIEP8TFzKo1o9SCtSizE8l6hhRC/Rg3S6J3tAlw
         TrZw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ozkPZplA;
       spf=pass (google.com: domain of 3lutxxaukcwgkrbkxmuumrk.iusqgygt-jkbmuumrkmxuavy.ius@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::e4a as permitted sender) smtp.mailfrom=3LUTxXAUKCWgKRbKXMUUMRK.IUSQGYGT-JKbMUUMRKMXUaVY.IUS@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-vs1-xe4a.google.com (mail-vs1-xe4a.google.com. [2607:f8b0:4864:20::e4a])
        by gmr-mx.google.com with ESMTPS id l75si449867itb.4.2019.05.31.08.11.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=AEAD-AES128-GCM-SHA256 bits=128/128);
        Fri, 31 May 2019 08:11:42 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3lutxxaukcwgkrbkxmuumrk.iusqgygt-jkbmuumrkmxuavy.ius@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::e4a as permitted sender) client-ip=2607:f8b0:4864:20::e4a;
Received: by mail-vs1-xe4a.google.com with SMTP id p70so220440vsd.2
        for <kasan-dev@googlegroups.com>; Fri, 31 May 2019 08:11:42 -0700 (PDT)
X-Received: by 2002:ac5:c215:: with SMTP id m21mr4221628vkk.84.1559315501278;
 Fri, 31 May 2019 08:11:41 -0700 (PDT)
Date: Fri, 31 May 2019 17:08:30 +0200
In-Reply-To: <20190531150828.157832-1-elver@google.com>
Message-Id: <20190531150828.157832-3-elver@google.com>
Mime-Version: 1.0
References: <20190531150828.157832-1-elver@google.com>
X-Mailer: git-send-email 2.22.0.rc1.257.g3120a18244-goog
Subject: [PATCH v3 2/3] x86: Use static_cpu_has in uaccess region to avoid instrumentation
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: peterz@infradead.org, aryabinin@virtuozzo.com, dvyukov@google.com, 
	glider@google.com, andreyknvl@google.com, mark.rutland@arm.com, hpa@zytor.com
Cc: corbet@lwn.net, tglx@linutronix.de, mingo@redhat.com, bp@alien8.de, 
	x86@kernel.org, arnd@arndb.de, jpoimboe@redhat.com, linux-doc@vger.kernel.org, 
	linux-kernel@vger.kernel.org, linux-arch@vger.kernel.org, 
	kasan-dev@googlegroups.com, Marco Elver <elver@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=ozkPZplA;       spf=pass
 (google.com: domain of 3lutxxaukcwgkrbkxmuumrk.iusqgygt-jkbmuumrkmxuavy.ius@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::e4a as permitted sender) smtp.mailfrom=3LUTxXAUKCWgKRbKXMUUMRK.IUSQGYGT-JKbMUUMRKMXUaVY.IUS@flex--elver.bounces.google.com;
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

This patch is a pre-requisite for enabling KASAN bitops instrumentation;
using static_cpu_has instead of boot_cpu_has avoids instrumentation of
test_bit inside the uaccess region. With instrumentation, the KASAN
check would otherwise be flagged by objtool.

For consistency, kernel/signal.c was changed to mirror this change,
however, is never instrumented with KASAN (currently unsupported under
x86 32bit).

Signed-off-by: Marco Elver <elver@google.com>
Suggested-by: H. Peter Anvin <hpa@zytor.com>
---
Changes in v3:
* Use static_cpu_has instead of moving boot_cpu_has outside uaccess
  region.

Changes in v2:
* Replaces patch: 'tools/objtool: add kasan_check_* to uaccess
  whitelist'
---
 arch/x86/ia32/ia32_signal.c | 2 +-
 arch/x86/kernel/signal.c    | 2 +-
 2 files changed, 2 insertions(+), 2 deletions(-)

diff --git a/arch/x86/ia32/ia32_signal.c b/arch/x86/ia32/ia32_signal.c
index 629d1ee05599..1cee10091b9f 100644
--- a/arch/x86/ia32/ia32_signal.c
+++ b/arch/x86/ia32/ia32_signal.c
@@ -358,7 +358,7 @@ int ia32_setup_rt_frame(int sig, struct ksignal *ksig,
 		put_user_ex(ptr_to_compat(&frame->uc), &frame->puc);
 
 		/* Create the ucontext.  */
-		if (boot_cpu_has(X86_FEATURE_XSAVE))
+		if (static_cpu_has(X86_FEATURE_XSAVE))
 			put_user_ex(UC_FP_XSTATE, &frame->uc.uc_flags);
 		else
 			put_user_ex(0, &frame->uc.uc_flags);
diff --git a/arch/x86/kernel/signal.c b/arch/x86/kernel/signal.c
index 364813cea647..52eb1d551aed 100644
--- a/arch/x86/kernel/signal.c
+++ b/arch/x86/kernel/signal.c
@@ -391,7 +391,7 @@ static int __setup_rt_frame(int sig, struct ksignal *ksig,
 		put_user_ex(&frame->uc, &frame->puc);
 
 		/* Create the ucontext.  */
-		if (boot_cpu_has(X86_FEATURE_XSAVE))
+		if (static_cpu_has(X86_FEATURE_XSAVE))
 			put_user_ex(UC_FP_XSTATE, &frame->uc.uc_flags);
 		else
 			put_user_ex(0, &frame->uc.uc_flags);
-- 
2.22.0.rc1.257.g3120a18244-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20190531150828.157832-3-elver%40google.com.
For more options, visit https://groups.google.com/d/optout.
