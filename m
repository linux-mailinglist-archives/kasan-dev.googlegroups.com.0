Return-Path: <kasan-dev+bncBC7OBJGL2MHBBQHA6CFAMGQETN7UZCA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33c.google.com (mail-wm1-x33c.google.com [IPv6:2a00:1450:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id 38ED2422428
	for <lists+kasan-dev@lfdr.de>; Tue,  5 Oct 2021 13:00:17 +0200 (CEST)
Received: by mail-wm1-x33c.google.com with SMTP id d7-20020a1c7307000000b0030d6982305bsf1143784wmb.5
        for <lists+kasan-dev@lfdr.de>; Tue, 05 Oct 2021 04:00:17 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1633431617; cv=pass;
        d=google.com; s=arc-20160816;
        b=VkJn72dmf/4msLlSRHoaig1ZDL/dOSQx+WQQTAGRIwx42O6nYC6vFPTVwnTued2ITY
         WhdgQhDve6pTkx7t0uo9D65Ph/9Et8vAPK6FST257xbat6X0rvcYqr4dM4CBc1j2IlsZ
         AkyKdvrvFhQKhXV+sMHkuiPTzydbvPBZN9gPwhvrKZ8RT7w/YazssWI+sayKhJUlnOFb
         WEPgzWHwdrL9jqCcCvnmbv36wC6thHdh2qe0MDhAFJIXMns3Yh/Fxkuj/e6pyCNebpLP
         dunkTAf+FV9B6t+/SRl0Cp5LOI8hMsHGLvI2NsMNnPfcBY94QABrYHzPYja0ZzbiP9ET
         nJ/Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=oZE/NhwU+BORGRv/Nx3TCAqVsgt50r/nFLk2t7UIvCA=;
        b=zHo7xIo4dwh0DIFMxBMrESUCzl/FtMFTFV3ooNF2JzSSYQZToatqa2EwuPm4DSxYLs
         IAJPHr9sf0PYEuYC5SyHq6t+N/XkcaWv1YTRaZqmRJQF8SM8dqgmeEBDqYCPOpV/7Xn7
         ydudi0xdMBuWc4RcDvppaJP+15B6tUsaKsMpM1TY2zCo+vezZkPivyWtXBl1BsDZy9ES
         URk6vB7fPdIsGnIwhOI/WOgQAZAU6Rde9j9yx1ge5ROyNRSDP5PrJrqRmC74vTWvWrh3
         tFg4rgJE2BnSEuoEhEb4tcO1Y8S+iBoyoK+P2j4+zaOh7YwY3Q61InLZreYanqEnC+5Q
         jXpA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=gHVBD0A+;
       spf=pass (google.com: domain of 3pzbcyqukcsicjtcpemmejc.amki8q8l-bctemmejcepmsnq.amk@flex--elver.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3PzBcYQUKCSICJTCPEMMEJC.AMKI8Q8L-BCTEMMEJCEPMSNQ.AMK@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=oZE/NhwU+BORGRv/Nx3TCAqVsgt50r/nFLk2t7UIvCA=;
        b=cLhYUtUpYf8wEH6CJRh+ZE0nuwnvwieKBkvZ7WM5k+gWKm7p5aDCMMSVxwj7qQZRxg
         6s+VGcjgo4FZdYufS49qoWp2VULIZz0oUdR19l/b+xBJ4yrXWLTwqs0BMYh5k1yArd14
         W62Ka5lNoxkxM3b8ejgm2RPjUvOdgzIMqu2OKNk2y3Jkvy+YtlSpqCRtspqJAo3Cs/ae
         5cn0xtF4oqFgreIHF8kJq09eHUNQj2XgjenBxW6ZQhU4eZNKCL2C7oJAbw3AELj4MALt
         avIJBgcog9k5JCx7yHkS3y4At6Jug4nlvSPxYEcfcHCbD2Yr0NW3rppSY7pgpxb76fJS
         I2zw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=oZE/NhwU+BORGRv/Nx3TCAqVsgt50r/nFLk2t7UIvCA=;
        b=Ga1tE/oym3z0atqiT1YV/ZLpQwL682u3GE+9DuLNX2BhCU1mNzpwrc6o9LqzGpQ06O
         RCi6/NBdxpbxnPnwm33U4eROG7ucqbQmC+QlfqwxPZoinr16hGxoxVyWz5hXv/lrYOWa
         sN5jvCKCUtPsq/GPp+udrLIgHy9upD2v5PndF/H3zxP/geWG61/qkT/6sHVPoCdnDqbI
         iZX+YJgTUUz/UIKpcpmAumFV8UeQzOIRRNlLzec77LNk63n5KhGW5RclZ1c0SC1HCOak
         2oTYNXrIO/TgYac8CaBR0YQJZBCejlZh09hKKrFuzS+jOmtblZA8KNslFUhu/RS57leB
         fl8Q==
X-Gm-Message-State: AOAM531ug+EEUZkkNSPaJdF4mZQfpjNhzab5coupriHLMOI5Df6y+1nO
	/FlNmyy+ir4pkYLf2ou5dyc=
X-Google-Smtp-Source: ABdhPJwFqdP6pELF2Adbu98aXHn1XHDPWIyiDCptJadwNMORPYrTJvg858edx9TIrajEA3CKPaXdAg==
X-Received: by 2002:a05:6000:1544:: with SMTP id 4mr20982972wry.370.1633431616982;
        Tue, 05 Oct 2021 04:00:16 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:c782:: with SMTP id l2ls1838883wrg.2.gmail; Tue, 05 Oct
 2021 04:00:16 -0700 (PDT)
X-Received: by 2002:adf:bb49:: with SMTP id x9mr595867wrg.413.1633431616083;
        Tue, 05 Oct 2021 04:00:16 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1633431616; cv=none;
        d=google.com; s=arc-20160816;
        b=wfQaC2Ql4N8rT57Wyvld/feDs1ESzbnL3TxpIC/Yey3DiR5h29xVX+8Zsv4DpJuuoq
         S4rYpkJbAQXPPaaGu2PpSOPNSpvvvssvxvpPN3basjA6okWPODk82BZeocfpn7zuj7j/
         r+2rpHW/F180HYe9knntKIIsUiFH0nbirgrUzG+cdTQLOHl3jnKb+v07wxtlK0dGY/Wf
         rjfBC21hZjiC7EE0aq/wh+3LTNl5SWMwfXmJfPfbV5fVDFIkecIFyuqhzZ6ZiQdIvGQf
         yf74cxNSTot6vtsSmJBFc7HfUudwJnuQa3xjKkcFfbdC5l4a8u/Awu82YqY2WtC8ZCtL
         ca9A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=E3HFvEWei3GORNCVEmwUUOkLQSsacsR5poZwBNsW3No=;
        b=cMrAnufNCfgsanwDAVZLnM2yhq8I3z43siS+QvzjCng2aBvpugGdIlciLp0BjatCzl
         hyvJMcK74uFt4OICVLOyOfbziRqCD9v//6KrnZFulQiEIBbcIIHzA/sV9ZdY2elppbID
         GwHVYsYOKJuDPNeTz/WUkK2IyC69ftRbeIMHWolCXhoaW+V4GBvKoDnUSwkFXsibGsno
         1X7Mgk/t9cysHVX1941S0yhbRqxriEcK1LLdqDdPu+V9lLD5yfsvSzkVyM/Id8XT9IQT
         jFpB6/bPSddCJlUTy5W7Z39mWqZUL6tIEFkzejVsydChbuJYfAxRW0fBY6fAU0rw28Bf
         XI+A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=gHVBD0A+;
       spf=pass (google.com: domain of 3pzbcyqukcsicjtcpemmejc.amki8q8l-bctemmejcepmsnq.amk@flex--elver.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3PzBcYQUKCSICJTCPEMMEJC.AMKI8Q8L-BCTEMMEJCEPMSNQ.AMK@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x449.google.com (mail-wr1-x449.google.com. [2a00:1450:4864:20::449])
        by gmr-mx.google.com with ESMTPS id j9si300958wrs.3.2021.10.05.04.00.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 05 Oct 2021 04:00:16 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3pzbcyqukcsicjtcpemmejc.amki8q8l-bctemmejcepmsnq.amk@flex--elver.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) client-ip=2a00:1450:4864:20::449;
Received: by mail-wr1-x449.google.com with SMTP id k2-20020adfc702000000b0016006b2da9bso5580142wrg.1
        for <kasan-dev@googlegroups.com>; Tue, 05 Oct 2021 04:00:16 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:e44f:5054:55f8:fcb8])
 (user=elver job=sendgmr) by 2002:a1c:f31a:: with SMTP id q26mr2540960wmq.159.1633431615667;
 Tue, 05 Oct 2021 04:00:15 -0700 (PDT)
Date: Tue,  5 Oct 2021 12:58:56 +0200
In-Reply-To: <20211005105905.1994700-1-elver@google.com>
Message-Id: <20211005105905.1994700-15-elver@google.com>
Mime-Version: 1.0
References: <20211005105905.1994700-1-elver@google.com>
X-Mailer: git-send-email 2.33.0.800.g4c38ced690-goog
Subject: [PATCH -rcu/kcsan 14/23] locking/barriers, kcsan: Add instrumentation
 for barriers
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, "Paul E . McKenney" <paulmck@kernel.org>
Cc: Alexander Potapenko <glider@google.com>, Boqun Feng <boqun.feng@gmail.com>, 
	Borislav Petkov <bp@alien8.de>, Dmitry Vyukov <dvyukov@google.com>, Ingo Molnar <mingo@kernel.org>, 
	Josh Poimboeuf <jpoimboe@redhat.com>, Mark Rutland <mark.rutland@arm.com>, 
	Peter Zijlstra <peterz@infradead.org>, Thomas Gleixner <tglx@linutronix.de>, 
	Waiman Long <longman@redhat.com>, Will Deacon <will@kernel.org>, kasan-dev@googlegroups.com, 
	linux-arch@vger.kernel.org, linux-doc@vger.kernel.org, 
	linux-kbuild@vger.kernel.org, linux-kernel@vger.kernel.org, 
	linux-mm@kvack.org, x86@kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=gHVBD0A+;       spf=pass
 (google.com: domain of 3pzbcyqukcsicjtcpemmejc.amki8q8l-bctemmejcepmsnq.amk@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3PzBcYQUKCSICJTCPEMMEJC.AMKI8Q8L-BCTEMMEJCEPMSNQ.AMK@flex--elver.bounces.google.com;
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

Adds the required KCSAN instrumentation for barriers if CONFIG_SMP.
KCSAN supports modeling the effects of:

	smp_mb()
	smp_rmb()
	smp_wmb()
	smp_store_release()

Signed-off-by: Marco Elver <elver@google.com>
---
 include/asm-generic/barrier.h | 29 +++++++++++++++--------------
 include/linux/spinlock.h      |  2 +-
 2 files changed, 16 insertions(+), 15 deletions(-)

diff --git a/include/asm-generic/barrier.h b/include/asm-generic/barrier.h
index 640f09479bdf..27a9c9edfef6 100644
--- a/include/asm-generic/barrier.h
+++ b/include/asm-generic/barrier.h
@@ -14,6 +14,7 @@
 #ifndef __ASSEMBLY__
 
 #include <linux/compiler.h>
+#include <linux/kcsan-checks.h>
 #include <asm/rwonce.h>
 
 #ifndef nop
@@ -62,15 +63,15 @@
 #ifdef CONFIG_SMP
 
 #ifndef smp_mb
-#define smp_mb()	__smp_mb()
+#define smp_mb()	do { kcsan_mb(); __smp_mb(); } while (0)
 #endif
 
 #ifndef smp_rmb
-#define smp_rmb()	__smp_rmb()
+#define smp_rmb()	do { kcsan_rmb(); __smp_rmb(); } while (0)
 #endif
 
 #ifndef smp_wmb
-#define smp_wmb()	__smp_wmb()
+#define smp_wmb()	do { kcsan_wmb(); __smp_wmb(); } while (0)
 #endif
 
 #else	/* !CONFIG_SMP */
@@ -123,19 +124,19 @@ do {									\
 #ifdef CONFIG_SMP
 
 #ifndef smp_store_mb
-#define smp_store_mb(var, value)  __smp_store_mb(var, value)
+#define smp_store_mb(var, value)  do { kcsan_mb(); __smp_store_mb(var, value); } while (0)
 #endif
 
 #ifndef smp_mb__before_atomic
-#define smp_mb__before_atomic()	__smp_mb__before_atomic()
+#define smp_mb__before_atomic()	do { kcsan_mb(); __smp_mb__before_atomic(); } while (0)
 #endif
 
 #ifndef smp_mb__after_atomic
-#define smp_mb__after_atomic()	__smp_mb__after_atomic()
+#define smp_mb__after_atomic()	do { kcsan_mb(); __smp_mb__after_atomic(); } while (0)
 #endif
 
 #ifndef smp_store_release
-#define smp_store_release(p, v) __smp_store_release(p, v)
+#define smp_store_release(p, v) do { kcsan_release(); __smp_store_release(p, v); } while (0)
 #endif
 
 #ifndef smp_load_acquire
@@ -178,13 +179,13 @@ do {									\
 #endif	/* CONFIG_SMP */
 
 /* Barriers for virtual machine guests when talking to an SMP host */
-#define virt_mb() __smp_mb()
-#define virt_rmb() __smp_rmb()
-#define virt_wmb() __smp_wmb()
-#define virt_store_mb(var, value) __smp_store_mb(var, value)
-#define virt_mb__before_atomic() __smp_mb__before_atomic()
-#define virt_mb__after_atomic()	__smp_mb__after_atomic()
-#define virt_store_release(p, v) __smp_store_release(p, v)
+#define virt_mb() do { kcsan_mb(); __smp_mb(); } while (0)
+#define virt_rmb() do { kcsan_rmb(); __smp_rmb(); } while (0)
+#define virt_wmb() do { kcsan_wmb(); __smp_wmb(); } while (0)
+#define virt_store_mb(var, value) do { kcsan_mb(); __smp_store_mb(var, value); } while (0)
+#define virt_mb__before_atomic() do { kcsan_mb(); __smp_mb__before_atomic(); } while (0)
+#define virt_mb__after_atomic()	do { kcsan_mb(); __smp_mb__after_atomic(); } while (0)
+#define virt_store_release(p, v) do { kcsan_release(); __smp_store_release(p, v); } while (0)
 #define virt_load_acquire(p) __smp_load_acquire(p)
 
 /**
diff --git a/include/linux/spinlock.h b/include/linux/spinlock.h
index 45310ea1b1d7..f6d69808b929 100644
--- a/include/linux/spinlock.h
+++ b/include/linux/spinlock.h
@@ -172,7 +172,7 @@ do {									\
  * Architectures that can implement ACQUIRE better need to take care.
  */
 #ifndef smp_mb__after_spinlock
-#define smp_mb__after_spinlock()	do { } while (0)
+#define smp_mb__after_spinlock()	kcsan_mb()
 #endif
 
 #ifdef CONFIG_DEBUG_SPINLOCK
-- 
2.33.0.800.g4c38ced690-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211005105905.1994700-15-elver%40google.com.
