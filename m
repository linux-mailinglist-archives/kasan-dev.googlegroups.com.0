Return-Path: <kasan-dev+bncBC7OBJGL2MHBBT7ZSO6QMGQE5TT2C2A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x140.google.com (mail-lf1-x140.google.com [IPv6:2a00:1450:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id 09755A2B048
	for <lists+kasan-dev@lfdr.de>; Thu,  6 Feb 2025 19:17:54 +0100 (CET)
Received: by mail-lf1-x140.google.com with SMTP id 2adb3069b0e04-543bb2be3dcsf817182e87.2
        for <lists+kasan-dev@lfdr.de>; Thu, 06 Feb 2025 10:17:54 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1738865873; cv=pass;
        d=google.com; s=arc-20240605;
        b=EqOf3YHymfcvXEnGHte8zWeIL8q9QG87IdfxZxY7aZySiOMI1cfCC28qpOttwCchaQ
         3cCuByY8cHdbB05iXfxioYnYODFVw6mQKs4aney7hmmMCFIk2Vv/liNxuzZjtEhPNXgy
         empaF5LqcbiBM37GSaBkZI5a2eiakIEespOH15LrT8k+EyMLDjeVFXvWb9Tjil8ICehj
         1Dv48aBJNb6DaZkJPKHx13DUcGlVi5jXllgFt/bjtj60VZnXr7WSSxwp3AnIbBkDEMAs
         xjtvas29F5KfhGx1cFutm5/KlRvb9lZHaIe31XDGAhm9fgCfOhmYN7KnUO9/nHEl5zod
         g2UA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=b8Tn8Aaxdw6hmtORSRdhrYLXy+2Aawz1+2QDoUROLiI=;
        fh=rvx/DnjOsfH2GqGn4fFLGiaT3BqJA9tAAocqW9xn0uc=;
        b=Ojyu/j16xqzT4YP974euQNzhzVWOTKectBOHZ/95TEEqMwZvZKlXMR6W29FutMkng+
         8LhRjtxi3sdkbW/LDCjwtQ5rket71P8uRt9wbPShHhfNOiNEtcQsza7JlD0YXbsn2iDZ
         WcPRXpATBRrTYkRLLEwo4iAyTbEUpDQZOikpgjnTLp+dq0rnhic8i3eYOPHXbBQTfVCL
         ku5GDMc9FodKF8UvHX0NttJ0ROrPxRvb9HJOtM+SZccpzIV9eZRHr65F7SPa9GJapGbl
         X5fWKFgwQT9z4EuPlfV+A6qMaAlu7HY4YkFyORLU5QEH+9DboIvN9bOBrkV42DgdAGcD
         VKxQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=qcoDaXru;
       spf=pass (google.com: domain of 3zpykzwukcz0bisbodlldib.9ljh7p7k-absdlldibdolrmp.9lj@flex--elver.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3zPykZwUKCZ0BISBODLLDIB.9LJH7P7K-ABSDLLDIBDOLRMP.9LJ@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1738865873; x=1739470673; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=b8Tn8Aaxdw6hmtORSRdhrYLXy+2Aawz1+2QDoUROLiI=;
        b=wEJdal67/vfbMCEy00FiPfp8wvNJxwPy+of4pnCVHyE3lmyG+cwpG4MKTW7GEsR+Sw
         8bDEDXnLzcpg3234cgmeOgA2cpEc0gS2QbdGF29r6HwuSBqOks5gk2csOPsZyjq4HufV
         D6H0v39TY29UvKpDmr7dzhjyGDs85xhXK+LaIQhih9RN/0Oqyj/TpaY9cqzfJUEluQpM
         75EOLKg8wzCkWcloxZfKK2EMY8YaDFKEvnrjceXLlhDrQyb7vwwqfh9y+SKUP0c/MH8u
         /qE///677Q4qiy1Xzxakl9+woHzXoPEx2eaMTW5CQabKl/ZcbAsCM2tt+6QLAj44LRES
         wLXw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1738865873; x=1739470673;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=b8Tn8Aaxdw6hmtORSRdhrYLXy+2Aawz1+2QDoUROLiI=;
        b=RbtA2/YW3Ubu97MEORRHNnDEtfoX/1P4qIwJ9h8Y2V+HK24FEtPbvH8Tne3RyirEY5
         v1AHVllAlDbo1S1YPOYD13qpJGyb/no87M3tytU32dvuumDHbnKFFnHyF0Q13GjwI63n
         jpqf0owYxV9iY/m7m1DxcFTwg3x/hLPprDxEypJKbGcH62OOgUMFWhr4TS8fKWEY8WF6
         8YaraeaHv3Yz8CgG0zxJ5jw7cGSIhKBb+vSQ8naboMNfjj4U3yFnBBNonhastzvIgP5X
         qM7Qh7sJ/svswUWe9tdTGAcyWwxt3DeoHUtcfLUe3MgZv1jdM+EtfDwQsZqGTD4MYAzh
         Kluw==
X-Forwarded-Encrypted: i=2; AJvYcCUaupd4BIeEGJ1+RgmkwvIwmlLbRbUHkjSJLAvfWCHfjLw+Ga+BUd6yP+N3IKvJnmJclNpf9w==@lfdr.de
X-Gm-Message-State: AOJu0YzIB8skqfKKDDGc/Lu75d/BhyG/teEMs7GU2+u5wdxSvbMELalV
	vZenbFfQvweMprQnH+UVE71DbZW2DZw6wTAvZJaEToPAQKuKpPyj
X-Google-Smtp-Source: AGHT+IG8CxREHZKzWjHMxdbBFK96K2kbhCoKDW/m1x3GWjNfualkYohOWf24CJzPvAHUlRrlLTD75g==
X-Received: by 2002:a05:6512:132a:b0:540:353a:df8e with SMTP id 2adb3069b0e04-54405a44cf5mr3020035e87.39.1738865871685;
        Thu, 06 Feb 2025 10:17:51 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:5fd1:0:b0:544:125f:71cf with SMTP id 2adb3069b0e04-54413c78859ls57782e87.2.-pod-prod-09-eu;
 Thu, 06 Feb 2025 10:17:49 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCX2cnnux62TGIQxM5JY1h0r4T5gZGRhOgSSzvVVlQF5Z993rD9+I9AeyExJmuezC85wgLnpvTG9zrQ=@googlegroups.com
X-Received: by 2002:a2e:bc1d:0:b0:300:41a8:125b with SMTP id 38308e7fff4ca-307cf386426mr31999481fa.37.1738865868770;
        Thu, 06 Feb 2025 10:17:48 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1738865868; cv=none;
        d=google.com; s=arc-20240605;
        b=MZKMR+bYvomGu+niAjt2Y/sc10aGzU74HNbBOY96DyBZD1fgj7ZB61lo0ATSWZGX05
         9wQFHLiJVWwimgfcZDI5M/bdGVhXk2nBFORzxIQnkIa5VApJ9eEzlVdUjJs2OizUWAbj
         w/RMoEbceX9ZoazMY30G/tdVZF6nId/wlUb8lOursUuUBAGwjBKRnBEwqawD/+q5Ab1b
         HaBXNQpEoVq5ZOsA1huvyfoCjzYM/wRZljzBDkP7C4T5RXc2/zg6DnBvfymXk9xIiAY6
         UanUuTGOFWUNKkz3OQN0X266AXfXGXIlSbuSQgZ8FN/xRkayWuqAMtQdQQPANl2ki06e
         z9Fw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=qF82DJs8+giiKRyetuSOsU+JANR9VCfWNPadmkefX9I=;
        fh=s3h4gLzbBpvtM9ocMaHQK91Cbuk/PJGTJ4Zfq+ziwiY=;
        b=cCMZOf104BAoqF4Uv5pDWvYB724XFJ7McsC2TEWCWnILyovCS/irOCJXfB9WpsP4pI
         F1JAsDj7eaUoXEpwUQG1D2DB7Y7lKqPFra6hjpaPqnOldyQs6C3+uUAp6B3DIulAJmHr
         llBQLgekWb+PvKW5ukiq2kZDU5YZI5v5pNUaa7OQ9MdVwJgbNEYvKI0fHXvV54VDmUC6
         oKmCUdsZzGZ1cpRcA01VvOIgbowwP9C57oGj1eIr7MBSDd/zjGC8+y8bZMGGwPMPFHqE
         ysG4Ul562HhM2hf3CndA+mPt6LGwWdA9npjegDhuA6114JCMyaovttkAe/g937Cui5fX
         SRDw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=qcoDaXru;
       spf=pass (google.com: domain of 3zpykzwukcz0bisbodlldib.9ljh7p7k-absdlldibdolrmp.9lj@flex--elver.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3zPykZwUKCZ0BISBODLLDIB.9LJH7P7K-ABSDLLDIBDOLRMP.9LJ@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ed1-x549.google.com (mail-ed1-x549.google.com. [2a00:1450:4864:20::549])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-307de1c50ecsi386541fa.4.2025.02.06.10.17.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 06 Feb 2025 10:17:48 -0800 (PST)
Received-SPF: pass (google.com: domain of 3zpykzwukcz0bisbodlldib.9ljh7p7k-absdlldibdolrmp.9lj@flex--elver.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) client-ip=2a00:1450:4864:20::549;
Received: by mail-ed1-x549.google.com with SMTP id 4fb4d7f45d1cf-5d89a53fc46so1424182a12.2
        for <kasan-dev@googlegroups.com>; Thu, 06 Feb 2025 10:17:48 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCU/o/MW7vz5SQP+hiKeW/vlfhQLEVFyYzH02/cEstgnHHC1S/gqg0N54UuVB7WM2oWkM14ijE+AAfw=@googlegroups.com
X-Received: from edbcs11.prod.google.com ([2002:a05:6402:c4b:b0:5dc:22e2:2325])
 (user=elver job=prod-delivery.src-stubby-dispatcher) by 2002:a05:6402:5290:b0:5dc:5a2f:a726
 with SMTP id 4fb4d7f45d1cf-5de45072314mr470242a12.22.1738865868148; Thu, 06
 Feb 2025 10:17:48 -0800 (PST)
Date: Thu,  6 Feb 2025 19:09:55 +0100
In-Reply-To: <20250206181711.1902989-1-elver@google.com>
Mime-Version: 1.0
References: <20250206181711.1902989-1-elver@google.com>
X-Mailer: git-send-email 2.48.1.502.g6dc24dfdaf-goog
Message-ID: <20250206181711.1902989-2-elver@google.com>
Subject: [PATCH RFC 01/24] compiler_types: Move lock checking attributes to compiler-capability-analysis.h
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com
Cc: "Paul E. McKenney" <paulmck@kernel.org>, Alexander Potapenko <glider@google.com>, 
	Bart Van Assche <bvanassche@acm.org>, Bill Wendling <morbo@google.com>, Boqun Feng <boqun.feng@gmail.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Frederic Weisbecker <frederic@kernel.org>, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>, Ingo Molnar <mingo@kernel.org>, 
	Jann Horn <jannh@google.com>, Joel Fernandes <joel@joelfernandes.org>, 
	Jonathan Corbet <corbet@lwn.net>, Josh Triplett <josh@joshtriplett.org>, 
	Justin Stitt <justinstitt@google.com>, Kees Cook <kees@kernel.org>, 
	Mark Rutland <mark.rutland@arm.com>, Mathieu Desnoyers <mathieu.desnoyers@efficios.com>, 
	Miguel Ojeda <ojeda@kernel.org>, Nathan Chancellor <nathan@kernel.org>, 
	Neeraj Upadhyay <neeraj.upadhyay@kernel.org>, Nick Desaulniers <ndesaulniers@google.com>, 
	Peter Zijlstra <peterz@infradead.org>, Steven Rostedt <rostedt@goodmis.org>, 
	Thomas Gleixner <tglx@linutronix.de>, Uladzislau Rezki <urezki@gmail.com>, Waiman Long <longman@redhat.com>, 
	Will Deacon <will@kernel.org>, kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	llvm@lists.linux.dev, rcu@vger.kernel.org, linux-crypto@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=qcoDaXru;       spf=pass
 (google.com: domain of 3zpykzwukcz0bisbodlldib.9ljh7p7k-absdlldibdolrmp.9lj@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3zPykZwUKCZ0BISBODLLDIB.9LJH7P7K-ABSDLLDIBDOLRMP.9LJ@flex--elver.bounces.google.com;
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
generalizing towards "capability analysis".

No functional change intended.

Signed-off-by: Marco Elver <elver@google.com>
---
 include/linux/compiler-capability-analysis.h | 32 ++++++++++++++++++++
 include/linux/compiler_types.h               | 18 ++---------
 2 files changed, 34 insertions(+), 16 deletions(-)
 create mode 100644 include/linux/compiler-capability-analysis.h

diff --git a/include/linux/compiler-capability-analysis.h b/include/linux/compiler-capability-analysis.h
new file mode 100644
index 000000000000..7546ddb83f86
--- /dev/null
+++ b/include/linux/compiler-capability-analysis.h
@@ -0,0 +1,32 @@
+/* SPDX-License-Identifier: GPL-2.0 */
+/*
+ * Macros and attributes for compiler-based static capability analysis.
+ */
+
+#ifndef _LINUX_COMPILER_CAPABILITY_ANALYSIS_H
+#define _LINUX_COMPILER_CAPABILITY_ANALYSIS_H
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
+#endif /* _LINUX_COMPILER_CAPABILITY_ANALYSIS_H */
diff --git a/include/linux/compiler_types.h b/include/linux/compiler_types.h
index 981cc3d7e3aa..4a458e41293c 100644
--- a/include/linux/compiler_types.h
+++ b/include/linux/compiler_types.h
@@ -24,6 +24,8 @@
 # define BTF_TYPE_TAG(value) /* nothing */
 #endif
 
+#include <linux/compiler-capability-analysis.h>
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
2.48.1.502.g6dc24dfdaf-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250206181711.1902989-2-elver%40google.com.
