Return-Path: <kasan-dev+bncBC7OBJGL2MHBB2G67L2QKGQED2CORFA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x538.google.com (mail-pg1-x538.google.com [IPv6:2607:f8b0:4864:20::538])
	by mail.lfdr.de (Postfix) with ESMTPS id 1B8C21D52FE
	for <lists+kasan-dev@lfdr.de>; Fri, 15 May 2020 17:04:10 +0200 (CEST)
Received: by mail-pg1-x538.google.com with SMTP id q5sf2012849pgt.16
        for <lists+kasan-dev@lfdr.de>; Fri, 15 May 2020 08:04:10 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1589555049; cv=pass;
        d=google.com; s=arc-20160816;
        b=UQNQbS0cujuvNExdlvQzeOFqJ7V0iIk8xmNlLZ6VLcwgfuht92Lp5KMXXUGopTUQgm
         Q7enURohJm6wwtq77pCwrTuq4iniUjhEwxLqJstlz1Cz9lYspim1jYCwUo2tTllMpymy
         UJcrxMeZvEbw7ZSUFrlZ5Hn5MmGCCj1nqwFJZSiStZOx5BZU1A//bhNvo4yGY7pRq3yV
         NxjnoQRFsQWEBsmInb7gfmTFZ2+o9/6zdqVCw+23fA6fVFENkrbV/h/DL1THvFN3Z0Eo
         Tap+0m/+dgtH4rOJRKD1/E9Lx+J3Plei97cwEUX2OsiGPfEI5mn2qvaTW7zYYZ5zr1HA
         PD7w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=rZdpT1F/pJK5w9L6+OmhW+oArHzJjmTDG04ZpteNJQQ=;
        b=gmICpc1thVJ3JD2Fn5rmiS+1R2NPTkPVyeOqmkN7S8Pkvog+OUO+To/Tg4sxYQ2OxI
         wA3fjabjcD/WZWxOIebjG7Cw+K006Pawdws3O+DmRfk9EhgcVcRyffvWa+cJ1Umj/fjJ
         WvSEGrAFPhToVSqrxUwPsGoSWKAUu7oC01QsiWIPGJuprprKIlfc1N95lJsSOxDQckmB
         WVrgJfdziBULcUNONo2RRpXVMnTtB7yFHMN+ux9Kqx0zjXEdZHZjbVYgCZ6qMdI59TUa
         FMVx4TMdWc9HsER8F/3XQaCnPR1tgr8b0njGJQKFvFTMA1O+h4C+ICX3uJBUpQG2WJus
         DqVg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=MBA9I9Ds;
       spf=pass (google.com: domain of 3z6--xgukcbwgnxgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3Z6--XgUKCbwgnxgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=rZdpT1F/pJK5w9L6+OmhW+oArHzJjmTDG04ZpteNJQQ=;
        b=UaaxKOWpwbOn7CVItdjezufu01g7xxB7TfZvCAQjpI7bcA/ijnkoYja/tSvz4BmSYn
         ImRVC4/0lc8NXgHwSiCRirgaKiM3GYuiZkbRbiEpJYE3QlvyFaTqeCirwzZi+9aQACr/
         RserfVyIGxOFKCcTaf0qNpT87yyWXCA8JDRM6O5m6ieXULZM2zIRqOEAMbAA/YAoKiYT
         EbrViPwSKiuTaovTsFXcfg54Mw0mv9mSbDvTCoEwY/M5ZUlEfDApLo1ThiY8Jp8wH8m+
         JvgL/7P3358O8D2aEutjtRnZl01r+475IYER3cooMSMK6+wRTy5fZNwCcx4c+PGCCp+f
         wNAA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=rZdpT1F/pJK5w9L6+OmhW+oArHzJjmTDG04ZpteNJQQ=;
        b=Y1tN+dy5fg03/LiUMQbVm99gkKzy8l9crNDHfu9C73GaZrIw5uoOE1EuUr9rjR/cos
         VzC15Zg39X3v3xiuM0wqKAQf+yzFxewQAz3BKoqN07sO3eP73yVf7PJJKf9Y7b0toYyv
         rGeADwxY3JJ8Id7lNDrv1hVuHyaOCUqEWjpHb50l9l3vpwtnmIS5Ig+2OQ94iAjx6UNX
         G6yPl6kQJvdB8bSAJp+2Cd9jFgBu506ZhRXyAv1kawkmwV5M6R3VWzaM8XZBMizzzE8P
         hHXzqaiuKU7DYt5bPQT7qgN+zsT8I9U1Zb3GqDrJ9m8hH3JTMAP7sK8p6wmvCvseKea+
         cNiw==
X-Gm-Message-State: AOAM5301LfnDBYwEZPMU1ZM7Pnu/NTvDtzuByKifg3x5+7Ebomxz/6oG
	To0BqzyNw+Q9UqqmQtvpZ1g=
X-Google-Smtp-Source: ABdhPJxb3u7mH0p3qs0ZQhmcJTfR9SrV70uIsaQ5faCBOUlUJen1M/hozKCMfmagFRVyynGEQVS4Iw==
X-Received: by 2002:aa7:92cc:: with SMTP id k12mr4133770pfa.184.1589555048639;
        Fri, 15 May 2020 08:04:08 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:b219:: with SMTP id x25ls820350pge.8.gmail; Fri, 15 May
 2020 08:04:08 -0700 (PDT)
X-Received: by 2002:aa7:985e:: with SMTP id n30mr4205309pfq.163.1589555048134;
        Fri, 15 May 2020 08:04:08 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1589555048; cv=none;
        d=google.com; s=arc-20160816;
        b=vCsk7yOf9oV0dyGxc+nPmfDn2zDCTTKZ1p/uDSfK0b5gtg0+mFgOnzHPmY6RcXjBUY
         fhTEkbjPdEpBROG/ktavc3u1lrIMRQ+7AwaT0auB3NVRSXiHrIv3sm5DQsPJagb1MdzH
         AU/73McuRpbCjP8ly8+HTn6Qi6b1/q2SBNZ4KahTMRjEGtvKyO4Q4uKXktu91FgejTEp
         P8uxsPZiArW2vGEGDVv+EIsAPSXDpCs2mtxc5fRJgF6OP34/Yhs5+Frm0Rl93j43mNAw
         zPlXE4q9T3M15MbuuAm2fQdymdMfWzt972VIy7mOZUT2PTFvsNaFyZXrxddb/JZ2U31d
         MoUw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=B+kcPzRw4VpBcmlaWaCawRXGVLL4Q9ilUa578zhnNe4=;
        b=XAkKTDVyhezK/yJAr9kWMpju5WfkOBL8sU2HLLWohdky0LS4KQzPKxQ2NBkJAOMZma
         IfgjUv4TUV39SMnbcz/SnnOaIjVU39HHentn9HIRRt4fmA/BzclSNmkpJCrZoWvffKe+
         V8YI2bKVSJFPA9S1ZQ6qifLKK15N4vZQHqYaNB+svPfZNqQ0eHdbr7SBDP9341Tmy5E1
         DcPL3AiLZiuyvL86SAk9seKfjKl4knznBls8rxEdLm3fFWFqfcERUwHklqdtXAkfI347
         9Dp2xsBOm9d6Jthr03RH3Utu6nCN5GRGgv22xP1SoAvkfnFzBJgXA8YUbk1XNN3lfBvN
         RYRw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=MBA9I9Ds;
       spf=pass (google.com: domain of 3z6--xgukcbwgnxgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3Z6--XgUKCbwgnxgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf49.google.com (mail-qv1-xf49.google.com. [2607:f8b0:4864:20::f49])
        by gmr-mx.google.com with ESMTPS id u6si225139plz.5.2020.05.15.08.04.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 15 May 2020 08:04:08 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3z6--xgukcbwgnxgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) client-ip=2607:f8b0:4864:20::f49;
Received: by mail-qv1-xf49.google.com with SMTP id j6so2867285qvn.9
        for <kasan-dev@googlegroups.com>; Fri, 15 May 2020 08:04:08 -0700 (PDT)
X-Received: by 2002:a05:6214:164:: with SMTP id y4mr3698355qvs.249.1589555047207;
 Fri, 15 May 2020 08:04:07 -0700 (PDT)
Date: Fri, 15 May 2020 17:03:37 +0200
In-Reply-To: <20200515150338.190344-1-elver@google.com>
Message-Id: <20200515150338.190344-10-elver@google.com>
Mime-Version: 1.0
References: <20200515150338.190344-1-elver@google.com>
X-Mailer: git-send-email 2.26.2.761.g0e0b3e54be-goog
Subject: [PATCH -tip 09/10] compiler.h: Move function attributes to compiler_types.h
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com
Cc: paulmck@kernel.org, dvyukov@google.com, glider@google.com, 
	andreyknvl@google.com, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, tglx@linutronix.de, mingo@kernel.org, 
	peterz@infradead.org, will@kernel.org, clang-built-linux@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=MBA9I9Ds;       spf=pass
 (google.com: domain of 3z6--xgukcbwgnxgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3Z6--XgUKCbwgnxgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--elver.bounces.google.com;
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

Cleanup and move the KASAN and KCSAN related function attributes to
compiler_types.h, where the rest of the same kind live.

No functional change intended.

Signed-off-by: Marco Elver <elver@google.com>
---
 include/linux/compiler.h       | 29 -----------------------------
 include/linux/compiler_types.h | 29 +++++++++++++++++++++++++++++
 2 files changed, 29 insertions(+), 29 deletions(-)

diff --git a/include/linux/compiler.h b/include/linux/compiler.h
index fce56402c082..a7b01e750dd3 100644
--- a/include/linux/compiler.h
+++ b/include/linux/compiler.h
@@ -259,35 +259,6 @@ do {									\
 	__WRITE_ONCE_SCALAR(x, val);					\
 } while (0)
 
-#ifdef CONFIG_KASAN
-/*
- * We can't declare function 'inline' because __no_sanitize_address conflicts
- * with inlining. Attempt to inline it may cause a build failure.
- *     https://gcc.gnu.org/bugzilla/show_bug.cgi?id=67368
- * '__maybe_unused' allows us to avoid defined-but-not-used warnings.
- */
-# define __no_kasan_or_inline __no_sanitize_address notrace __maybe_unused
-# define __no_sanitize_or_inline __no_kasan_or_inline
-#else
-# define __no_kasan_or_inline __always_inline
-#endif
-
-#define __no_kcsan __no_sanitize_thread
-#ifdef __SANITIZE_THREAD__
-/*
- * Rely on __SANITIZE_THREAD__ instead of CONFIG_KCSAN, to avoid not inlining in
- * compilation units where instrumentation is disabled.
- */
-# define __no_kcsan_or_inline __no_kcsan notrace __maybe_unused
-# define __no_sanitize_or_inline __no_kcsan_or_inline
-#else
-# define __no_kcsan_or_inline __always_inline
-#endif
-
-#ifndef __no_sanitize_or_inline
-#define __no_sanitize_or_inline __always_inline
-#endif
-
 static __no_sanitize_or_inline
 unsigned long __read_once_word_nocheck(const void *addr)
 {
diff --git a/include/linux/compiler_types.h b/include/linux/compiler_types.h
index 6ed0612bc143..b190a12e7089 100644
--- a/include/linux/compiler_types.h
+++ b/include/linux/compiler_types.h
@@ -167,6 +167,35 @@ struct ftrace_likely_data {
  */
 #define noinline_for_stack noinline
 
+#ifdef CONFIG_KASAN
+/*
+ * We can't declare function 'inline' because __no_sanitize_address conflicts
+ * with inlining. Attempt to inline it may cause a build failure.
+ *     https://gcc.gnu.org/bugzilla/show_bug.cgi?id=67368
+ * '__maybe_unused' allows us to avoid defined-but-not-used warnings.
+ */
+# define __no_kasan_or_inline __no_sanitize_address notrace __maybe_unused
+# define __no_sanitize_or_inline __no_kasan_or_inline
+#else
+# define __no_kasan_or_inline __always_inline
+#endif
+
+#define __no_kcsan __no_sanitize_thread
+#ifdef __SANITIZE_THREAD__
+/*
+ * Rely on __SANITIZE_THREAD__ instead of CONFIG_KCSAN, to avoid not inlining in
+ * compilation units where instrumentation is disabled.
+ */
+# define __no_kcsan_or_inline __no_kcsan notrace __maybe_unused
+# define __no_sanitize_or_inline __no_kcsan_or_inline
+#else
+# define __no_kcsan_or_inline __always_inline
+#endif
+
+#ifndef __no_sanitize_or_inline
+#define __no_sanitize_or_inline __always_inline
+#endif
+
 #endif /* __KERNEL__ */
 
 #endif /* __ASSEMBLY__ */
-- 
2.26.2.761.g0e0b3e54be-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200515150338.190344-10-elver%40google.com.
