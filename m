Return-Path: <kasan-dev+bncBC7OBJGL2MHBBG637TEAMGQEQMHDOXY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33d.google.com (mail-wm1-x33d.google.com [IPv6:2a00:1450:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id E53A3C74B99
	for <lists+kasan-dev@lfdr.de>; Thu, 20 Nov 2025 16:02:52 +0100 (CET)
Received: by mail-wm1-x33d.google.com with SMTP id 5b1f17b1804b1-477632ef599sf11815865e9.1
        for <lists+kasan-dev@lfdr.de>; Thu, 20 Nov 2025 07:02:52 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1763650972; cv=pass;
        d=google.com; s=arc-20240605;
        b=c+1YGfuqGg8+/t7R/M7GWbHuNoG7WVztFBykVyUV+L0fjIRL49w502azC0+L7GhSqW
         +RBlO+B2fW18Q2OB5l97rqyYMCI2EWF/S/O/7NlLqnwoCLSZZOdE7cIyaUcqc4gvizr2
         IqUVdo8FVkQF1ohR9fyppJ2ZBiU/Ls/bPhGreOq5FADqcNyKq/9BPlC6PZIwdcPSS/qZ
         DZt468QywIiBEwj5kJcpAQqcSna0vFKh0wyhzeTQ47Fwd81fkp+JH4zndv2T50Y2p5yD
         Ofmvjl3ApmNUMPKZGbwmTTI2KUn0JmLslpWZemF1W62rGNBQOvUTGxx/wVC0nQreMWQr
         nQGg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=Ok8Fy2Gnu12MkIYtW/6djTQWmxzTK1jdEtF+zG8UqfM=;
        fh=0u2/qfQodeg5JyughmsgE02xw6Z0ElCGgvqmuY2ine4=;
        b=BdT0QU/j7/I+q4f0lqaD2+udDa1FfbV2XQZxml0ZwUWQPgKLvsRiT5yEmK727jWhq3
         OioOdNvVBsiYW9JsBspUYKA/jYAJyNQomXqmKIlaT113iB99qI19WXbeANxrfaaI/r9m
         uutNZGFMhZPvw/UigeP/mi4sERWmw4PIfL/+Ws9YqlV29e5HltKIr0jdMnB6y01VBNZl
         oXBbQVX+f+sWcIOQbJ7g6qtSEONrpteloNUbofh35WTsNXHZ3qNz52OxhuSS480CruPg
         kJYFrKo4lL+b32rRAVPnwXbHRBovKvpX2ecmaFAdHHZA6Ovt15Cs82JP8piCws0+2u5y
         ZbkQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="K7JFt7/r";
       spf=pass (google.com: domain of 3ly0faqukcb4ipzivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3ly0faQUKCb4ipzivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1763650972; x=1764255772; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=Ok8Fy2Gnu12MkIYtW/6djTQWmxzTK1jdEtF+zG8UqfM=;
        b=NRSMiFYuTTASqbY4eYtHAhyRVpxmoYoYUDo3ej9QpZsIUJKtRlk3fnP8f7Q9vq7gDv
         3GbXSvvc78CRtHydCkX59v/PiBDj1QvxPaniB96Vmn1+p4iArlpZcfCMWFoZPSkhZNN2
         yyimmE1henRdVioM9+hXn8KvA1D3n9nYOfEf9NkasjHlTAr+tS/sKrida3tQj9R7Jile
         m0k8viNjWa5Kre5uqBKt0yugbJWAX2tRWIhcXWWbROkNRrQjP45MZ1aRQ6K0YeXYoRyY
         1TXqcbnOc+0CLiRYavKHXhfyN1jy3QmH4dWZcNKhrpvyezLV+X1ifBMlmYfowoiRpA07
         Vrsg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1763650972; x=1764255772;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Ok8Fy2Gnu12MkIYtW/6djTQWmxzTK1jdEtF+zG8UqfM=;
        b=ojy6o1zPlv1hnCKjLI1Chg1optxUAzBET2yL4/Wn46iGoUnAM42o/llgiabb/CoZ0M
         jsBITpYZlbfrMpqe/nipiDNOCG0uiJIEBJtTiKMVhiQ4l6XZh/D0SwyiQOS0YXyb0FzF
         ZUpOaYzMP5dDVt1KWkuY+vFSLp4iM2ZIrmwLENjGKNn/kekCT4WYL70kWp73VwQhdB2y
         874iRhH2SAaQrdXGVgXtq+VP+KtdHy6n0rDnLgPpqzVj4fG1I65oiIWsXw9d5Nn0n/WU
         uhUyK41AllLuc5AcxQOB2+fSrkTOTw6EhamVFajwc9xY32AmbYOmGBRWqyeThNHYh9ot
         BjxQ==
X-Forwarded-Encrypted: i=2; AJvYcCWnroT1k98FuJNrRLStlbvYh8HLZ20fChogyLon6OnHVz/88/dOi0aZSPozy5wfTDPCZIVhqw==@lfdr.de
X-Gm-Message-State: AOJu0Yxd1fMJzbZt5l8hHtFcjkbdz7JKt0w5dFFRc5mM09MDN0clWH05
	OhS8aKDu9I6VXTgoYi1Q7+/zJA/6AZhgjYtQttSu2ABIm1uM08rcruDc
X-Google-Smtp-Source: AGHT+IEMpv9bq/e3za7qALu95IHVf85/6weh663pegjzrPE/rfyJPPE1dsIH4/LFVjNnh7vr0ndoXA==
X-Received: by 2002:a05:600c:4fc5:b0:46f:a2ba:581f with SMTP id 5b1f17b1804b1-477b9ecf58bmr34618045e9.16.1763650971893;
        Thu, 20 Nov 2025 07:02:51 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+afzxQfLa5gn9b/WsYbB3W6np7sFN7KY9TmvbHqqOa/BA=="
Received: by 2002:a05:600c:3490:b0:477:a036:8e6d with SMTP id
 5b1f17b1804b1-477b8e1bc51ls3417705e9.1.-pod-prod-00-eu; Thu, 20 Nov 2025
 07:02:49 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXbHbf7iyM6yDHET2pzDJAXdgBsKbsyJiZVeqXoRfEvz7V9gwEG7OuINPBH/67g0sX/lTacPRfppTA=@googlegroups.com
X-Received: by 2002:a05:600c:c4b7:b0:471:5c0:94fc with SMTP id 5b1f17b1804b1-477b9eb43c3mr31477785e9.6.1763650968852;
        Thu, 20 Nov 2025 07:02:48 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1763650968; cv=none;
        d=google.com; s=arc-20240605;
        b=eAnFNU8x5ipkpm7PQ1KHRa7IKllvbbQICPWHuuWl3R7iNOw7VA+t+OQJDZ8M4SJKDP
         Gx4IQ7I0JCs0vBo4lEyruiYBX3vjW6pOHAGIqJdozQYUP+HM8E958NQKmXRzwwPxzJFS
         QtEnta4fO6HtiQzkw/+mFRpbOulnVJLXtc6r0oiAMY7ZTZ40TJ/Psv82PRESIzu4SBsG
         LGXSX0ftDYwaRElucCSOKqRQ83dFEvwgHPLjWijFqoBLn5saWu0Pmzmem82LPP/mrgoF
         eIJuXLAdzr8agTXqaNxqGUZ2p6eGJ19x2T5gopopMgmmzxs9tGOg8P9SLA+C888sQdAD
         thYQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=+xm08Oqaiz0C+41w88sCv4Knf0HeT4Y61beURoEgshc=;
        fh=OhH9fIxKIPwgeJOXY+9FPP7MycbYqS2dOUfHqszG4jI=;
        b=hv9PQlawJIBns4d1It1WkReV/3cINomsxskcMIZLxSBAg9bCTOt9DSHQu+G2daEVaI
         ByXnVAyDpB4TKEtxhPKy3XvCNhwVWMmeYbJlKqXLN/bmRTq1dTjDSh4Hg/MNnPFNjlYL
         gSDOC7DLKVz3rufifvPAwO5H6zYdWlHGwAmbETylsxT7YlXIK8gkwmG8nN5e1YnGVPCX
         3rn+1wHlfWD+kvJF3FnEDYcGsU+89j8uh1Z9rqgRdPIDUhSqYvsbm6PVnSFeekA0D9CI
         mqrWB5JHL0NigEvjKym0qtRP0erLy0NvsKGlSYvdbg4W6XiU3yU3/6ShOoh9okVsmeeO
         nEQQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="K7JFt7/r";
       spf=pass (google.com: domain of 3ly0faqukcb4ipzivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3ly0faQUKCb4ipzivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x349.google.com (mail-wm1-x349.google.com. [2a00:1450:4864:20::349])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-477a9da5ae2si631005e9.3.2025.11.20.07.02.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 20 Nov 2025 07:02:48 -0800 (PST)
Received-SPF: pass (google.com: domain of 3ly0faqukcb4ipzivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) client-ip=2a00:1450:4864:20::349;
Received: by mail-wm1-x349.google.com with SMTP id 5b1f17b1804b1-477563e531cso9729605e9.1
        for <kasan-dev@googlegroups.com>; Thu, 20 Nov 2025 07:02:48 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCUO+fsS4jy3Zud5ErjWC1ixpFR3jzzHbQXKzGTlan+mw5KSXzcRp6XPiHu2I9Ahc3IbN3aEkDpwwyo=@googlegroups.com
X-Received: from wmbd17.prod.google.com ([2002:a05:600c:58d1:b0:477:76e1:9b4e])
 (user=elver job=prod-delivery.src-stubby-dispatcher) by 2002:a05:600c:470a:b0:477:1bb6:17e5
 with SMTP id 5b1f17b1804b1-477b8d8b887mr39140845e9.30.1763650967589; Thu, 20
 Nov 2025 07:02:47 -0800 (PST)
Date: Thu, 20 Nov 2025 15:49:03 +0100
In-Reply-To: <20251120145835.3833031-2-elver@google.com>
Mime-Version: 1.0
References: <20251120145835.3833031-2-elver@google.com>
X-Mailer: git-send-email 2.52.0.rc1.455.g30608eb744-goog
Message-ID: <20251120145835.3833031-3-elver@google.com>
Subject: [PATCH v4 01/35] compiler_types: Move lock checking attributes to compiler-context-analysis.h
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, Peter Zijlstra <peterz@infradead.org>, 
	Boqun Feng <boqun.feng@gmail.com>, Ingo Molnar <mingo@kernel.org>, Will Deacon <will@kernel.org>
Cc: "David S. Miller" <davem@davemloft.net>, Luc Van Oostenryck <luc.vanoostenryck@gmail.com>, 
	Chris Li <sparse@chrisli.org>, "Paul E. McKenney" <paulmck@kernel.org>, 
	Alexander Potapenko <glider@google.com>, Arnd Bergmann <arnd@arndb.de>, Bart Van Assche <bvanassche@acm.org>, 
	Christoph Hellwig <hch@lst.de>, Dmitry Vyukov <dvyukov@google.com>, Eric Dumazet <edumazet@google.com>, 
	Frederic Weisbecker <frederic@kernel.org>, Greg Kroah-Hartman <gregkh@linuxfoundation.org>, 
	Herbert Xu <herbert@gondor.apana.org.au>, Ian Rogers <irogers@google.com>, 
	Jann Horn <jannh@google.com>, Joel Fernandes <joelagnelf@nvidia.com>, 
	Johannes Berg <johannes.berg@intel.com>, Jonathan Corbet <corbet@lwn.net>, 
	Josh Triplett <josh@joshtriplett.org>, Justin Stitt <justinstitt@google.com>, 
	Kees Cook <kees@kernel.org>, Kentaro Takeda <takedakn@nttdata.co.jp>, 
	Lukas Bulwahn <lukas.bulwahn@gmail.com>, Mark Rutland <mark.rutland@arm.com>, 
	Mathieu Desnoyers <mathieu.desnoyers@efficios.com>, Miguel Ojeda <ojeda@kernel.org>, 
	Nathan Chancellor <nathan@kernel.org>, Neeraj Upadhyay <neeraj.upadhyay@kernel.org>, 
	Nick Desaulniers <nick.desaulniers+lkml@gmail.com>, Steven Rostedt <rostedt@goodmis.org>, 
	Tetsuo Handa <penguin-kernel@I-love.SAKURA.ne.jp>, Thomas Gleixner <tglx@linutronix.de>, 
	Thomas Graf <tgraf@suug.ch>, Uladzislau Rezki <urezki@gmail.com>, Waiman Long <longman@redhat.com>, 
	kasan-dev@googlegroups.com, linux-crypto@vger.kernel.org, 
	linux-doc@vger.kernel.org, linux-kbuild@vger.kernel.org, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, 
	linux-security-module@vger.kernel.org, linux-sparse@vger.kernel.org, 
	linux-wireless@vger.kernel.org, llvm@lists.linux.dev, rcu@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b="K7JFt7/r";       spf=pass
 (google.com: domain of 3ly0faqukcb4ipzivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3ly0faQUKCb4ipzivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
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

The conditional definition of lock checking macros and attributes is
about to become more complex. Factor them out into their own header for
better readability, and to make it obvious which features are supported
by which mode (currently only Sparse). This is the first step towards
generalizing towards "context analysis".

No functional change intended.

Signed-off-by: Marco Elver <elver@google.com>
Reviewed-by: Bart Van Assche <bvanassche@acm.org>
---
v4:
* Rename capability -> context analysis.
---
 include/linux/compiler-context-analysis.h | 32 +++++++++++++++++++++++
 include/linux/compiler_types.h            | 18 ++-----------
 2 files changed, 34 insertions(+), 16 deletions(-)
 create mode 100644 include/linux/compiler-context-analysis.h

diff --git a/include/linux/compiler-context-analysis.h b/include/linux/compiler-context-analysis.h
new file mode 100644
index 000000000000..f8af63045281
--- /dev/null
+++ b/include/linux/compiler-context-analysis.h
@@ -0,0 +1,32 @@
+/* SPDX-License-Identifier: GPL-2.0 */
+/*
+ * Macros and attributes for compiler-based static context analysis.
+ */
+
+#ifndef _LINUX_COMPILER_CONTEXT_ANALYSIS_H
+#define _LINUX_COMPILER_CONTEXT_ANALYSIS_H
+
+#ifdef __CHECKER__
+
+/* Sparse context/lock checking support. */
+# define __must_hold(x)		__attribute__((context(x,1,1)))
+# define __acquires(x)		__attribute__((context(x,0,1)))
+# define __cond_acquires(x)	__attribute__((context(x,0,-1)))
+# define __releases(x)		__attribute__((context(x,1,0)))
+# define __acquire(x)		__context__(x,1)
+# define __release(x)		__context__(x,-1)
+# define __cond_lock(x, c)	((c) ? ({ __acquire(x); 1; }) : 0)
+
+#else /* !__CHECKER__ */
+
+# define __must_hold(x)
+# define __acquires(x)
+# define __cond_acquires(x)
+# define __releases(x)
+# define __acquire(x)		(void)0
+# define __release(x)		(void)0
+# define __cond_lock(x, c)	(c)
+
+#endif /* __CHECKER__ */
+
+#endif /* _LINUX_COMPILER_CONTEXT_ANALYSIS_H */
diff --git a/include/linux/compiler_types.h b/include/linux/compiler_types.h
index 0a1b9598940d..7eb8d8db6c28 100644
--- a/include/linux/compiler_types.h
+++ b/include/linux/compiler_types.h
@@ -24,6 +24,8 @@
 # define BTF_TYPE_TAG(value) /* nothing */
 #endif
 
+#include <linux/compiler-context-analysis.h>
+
 /* sparse defines __CHECKER__; see Documentation/dev-tools/sparse.rst */
 #ifdef __CHECKER__
 /* address spaces */
@@ -34,14 +36,6 @@
 # define __rcu		__attribute__((noderef, address_space(__rcu)))
 static inline void __chk_user_ptr(const volatile void __user *ptr) { }
 static inline void __chk_io_ptr(const volatile void __iomem *ptr) { }
-/* context/locking */
-# define __must_hold(x)	__attribute__((context(x,1,1)))
-# define __acquires(x)	__attribute__((context(x,0,1)))
-# define __cond_acquires(x) __attribute__((context(x,0,-1)))
-# define __releases(x)	__attribute__((context(x,1,0)))
-# define __acquire(x)	__context__(x,1)
-# define __release(x)	__context__(x,-1)
-# define __cond_lock(x,c)	((c) ? ({ __acquire(x); 1; }) : 0)
 /* other */
 # define __force	__attribute__((force))
 # define __nocast	__attribute__((nocast))
@@ -62,14 +56,6 @@ static inline void __chk_io_ptr(const volatile void __iomem *ptr) { }
 
 # define __chk_user_ptr(x)	(void)0
 # define __chk_io_ptr(x)	(void)0
-/* context/locking */
-# define __must_hold(x)
-# define __acquires(x)
-# define __cond_acquires(x)
-# define __releases(x)
-# define __acquire(x)	(void)0
-# define __release(x)	(void)0
-# define __cond_lock(x,c) (c)
 /* other */
 # define __force
 # define __nocast
-- 
2.52.0.rc1.455.g30608eb744-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251120145835.3833031-3-elver%40google.com.
