Return-Path: <kasan-dev+bncBC7OBJGL2MHBBY7GSXFAMGQEXM6S4MQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x339.google.com (mail-wm1-x339.google.com [IPv6:2a00:1450:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id 97647CD0986
	for <lists+kasan-dev@lfdr.de>; Fri, 19 Dec 2025 16:46:44 +0100 (CET)
Received: by mail-wm1-x339.google.com with SMTP id 5b1f17b1804b1-4788112ec09sf18337275e9.3
        for <lists+kasan-dev@lfdr.de>; Fri, 19 Dec 2025 07:46:44 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1766159204; cv=pass;
        d=google.com; s=arc-20240605;
        b=gvYK1Y+7dplMFHZKhShEdM2abp0UDs9joLtk2iQ5uSxeprYk5JWQuixu90cMylwkIh
         eoZ3nq4yHxc0BvRSB6Xxxknu+L6cmYRxP8oNq/mZMo5pyYJAbtty8QWe1VhCXn9x00ox
         E3I6ZlRYzCdA8JTJB4Z4dxCWYkegUvPOx8jjseuhh9U+LBC6WjOFE7X2OTpGjzuj0I1E
         qGBfUPur364fpe5CCNv1a9PVDFXJ0gLzGbT9jYSfCgR6nrarnYLyGz7QCpdz069Vdl4e
         w9k95NzA3Nf211Qv/V/fmuxNf0u1a3zqBHxULs0Z/DL27IJSRfOdRMmlefQrGLbxsZlp
         6CMQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=edrrjpOVCS6p999IatOCVT88tsLT+K28MSshfnF4yDQ=;
        fh=dVzDDW3Cl1ZO8w71hHlKl3gF3URmXdeCG4f22m++Fgc=;
        b=hBMiMFytwEADtoVq5KBHFExzZ+sSVbRqOSEcCpHx1ZiTbm5MOryBZdUeYh++XMvNT4
         GPPNdwMBQKMTwboODw+oatVOjd1rSjUtXO1tfF0CQQgeAYoSRAhLo6zVcP30YNNVp4kb
         c11ryEg9p//EgPJPzDRFlQmsdYmr7erLqDAfU37cALw5tqMnG00rUhZG2t2duOJ2ENhf
         l9dvbIpxWh6E9+YGx3V+JwMUmhw3nB/iA8lVeyFbyG+oEntTjZc42FzmakPF6tboPgpj
         X/gPvjpIuTYJPA9mQo4cPGB5c8ZwrJb0mxm6wCbRRSQd89uHmqufCBLU16H75ByL8Eeb
         j7PA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=SW7OVcit;
       spf=pass (google.com: domain of 3yhnfaqukca0ryiretbbtyr.pbzxnfna-qritbbtyrtebhcf.pbz@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3YHNFaQUKCa0RYiReTbbTYR.PbZXNfNa-QRiTbbTYRTebhcf.PbZ@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1766159204; x=1766764004; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=edrrjpOVCS6p999IatOCVT88tsLT+K28MSshfnF4yDQ=;
        b=HLFF/PU8V5hJH4zWRq+0n6NF2DqQm0A7lja3dp7rPU/P2lexL71JWc+1CguCgFz3DK
         fHjcwmOFs25qNliSqmRkheaIWPbA9sTykZPSIFOxNcCKAO1sivtJDz9aHfdRguZsWrPv
         7ugCTCmISIdbVESfUlCyYjOryLgIBcmiG0ayIUQ8AEUtXzugeFP60oEWuNvlgW/47Ksv
         C8pjPze+4BfWthfi2nC5AAn9XLp1uzrPh8/xAFf0AdD4IoCe2qZhzixc0QGAaxdjUUAX
         9jiWSGgwp8b4eeib870bW/bAvG23o7dedGRNL0h4zkm5rtUxBHvATB1OBZX+LQjVIl33
         r8nw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1766159204; x=1766764004;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=edrrjpOVCS6p999IatOCVT88tsLT+K28MSshfnF4yDQ=;
        b=R0iSdIi/QlBPngyfeUkJsWTiHck9NMn/ox/XJl3gQOD4alD1+//4S/iR0ccqn7Hlz0
         xz4FWAR9yrncSbK2K56Y4ODktc3KOBfkcpyk+QKQ4T+blon4DDtSZBNyEtoTaxdpcZGU
         k9Ln1XADGXRW+N3gOrx9QFcq2eQRBtMfLelhdRddn8gNFnIxjX9EtznOfRFYYlC+3iVY
         in7wgTXa1SIUwktD0+NPQicRc1Gcidd3rhnStjPSziPUJqY9l5g/xDKlbu1BBWvBwn6h
         KQgboLs2YMxXMQo70dKa0GHc0mWbQoDAU2xQVmXLppLAVEePoAVPE7ZZRiJNAyHlzyU+
         76fA==
X-Forwarded-Encrypted: i=2; AJvYcCXoCwfbfpOgNyP6mCgM1uoMafmMikutAicqhgFxrAeIu9hthG1NAwQXpQJcfq5iDgYMTz7TJQ==@lfdr.de
X-Gm-Message-State: AOJu0Yw430GqYIbCAGo/PuqX2/zUQr3c98iXc+mgBW8V9URzivf1/fQH
	0XEYZOluDfbbuXyV0fVZt7r9LDS9q4CxEgjWpHkMPa7KwmcSvbndKdSK
X-Google-Smtp-Source: AGHT+IFrHMvTSDE5Mi8dxZtGRFkhkgRQxDTavM9Qs02rLNGkFSuYfRScvVyEd7q0jL7WqM8tKPcpFA==
X-Received: by 2002:a05:600c:350c:b0:477:7658:572a with SMTP id 5b1f17b1804b1-47d19584900mr25427765e9.20.1766159203948;
        Fri, 19 Dec 2025 07:46:43 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWahrQ+kcOpWpSO0byv9YvpXOvcUegw1hea9AKDvFwaMYg=="
Received: by 2002:a05:600c:1c09:b0:477:5c4c:acc2 with SMTP id
 5b1f17b1804b1-47a8ec51ac3ls57207745e9.1.-pod-prod-08-eu; Fri, 19 Dec 2025
 07:46:41 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWTb4spxWVn3gLdrcO/+RxbbEUSa0zwn8Q4CUmBlDcjo4Cz91/5b35nV0lM0hzUZizMoLybr/yA5jw=@googlegroups.com
X-Received: by 2002:a05:600c:350c:b0:477:7658:572a with SMTP id 5b1f17b1804b1-47d19584900mr25426835e9.20.1766159201344;
        Fri, 19 Dec 2025 07:46:41 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1766159201; cv=none;
        d=google.com; s=arc-20240605;
        b=B7qrVjGyjmbCQ6aAKZHxlEKM8eOj931Hq7iXSedcLtyPZJLjiZY6AWxVD7JTfMas7a
         jRCow+4blSZy1CqWjUT7E+W9Dqrrfy8hY+xVysVfvufqX0R5a8SQ5fEo3PCMpsSUpDx/
         y8EXMMrimI2c9X3dheM6BmY+5dDlnuwtNp0dK5bnKlBGe1QIIFltZ+kobmVZGj010ugC
         oSvRV6p8ADLAvfV96f0lE514N+j2UOayQzueIeJRjz1/dFZBfuIeyayUwBEHZPdIMPkk
         bK88uR68j5ObdV4kbGYSiOkEM0Jfb5DmW3QipaaqlBbpF1ro8Y4Owi44EXmUKCXr0nNn
         +NQg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=OmbIhVE6lrQtlGznaoJubWA1ZdiFv/Z/aaL1L4DndHU=;
        fh=+Vuj9g/FVh/TbrL34M6+aafq1nOSIxiGeu0WkKFbEwc=;
        b=bi7wqLI4uWJZ8CY1H/d7JjyKEOnGy8H2LWnL9v7IV0/kd4fTCvYoNxvoJxjiw/Lk2P
         MPrRLX9VHOn5hVxZ+e26UsFNgYwMu8Z7uh0iwdVf7hv+lWGBt5swFdQMg/snOS0o5WKV
         Of90cQg68agn/HYvf8XRSR/S6odxG/yw5yYKpAn9d6oL5qtjL0upevQaPzFxyFP4rdYX
         fexgI4oB7kxMfuFvbwGsXEQJuD+x1bHnTst9/UPJSYvpToC+yylWqYWpywoK+YUqhTkN
         mC+Y9+1FlTLFvDb/lh7n9FOSSM6Lg9ZpzCrF+JJ61bM7A7+pQaY1d+Mg3ZBkZJqwwwF2
         K+Bw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=SW7OVcit;
       spf=pass (google.com: domain of 3yhnfaqukca0ryiretbbtyr.pbzxnfna-qritbbtyrtebhcf.pbz@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3YHNFaQUKCa0RYiReTbbTYR.PbZXNfNa-QRiTbbTYRTebhcf.PbZ@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x34a.google.com (mail-wm1-x34a.google.com. [2a00:1450:4864:20::34a])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-47be3a5b84csi830995e9.2.2025.12.19.07.46.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 19 Dec 2025 07:46:41 -0800 (PST)
Received-SPF: pass (google.com: domain of 3yhnfaqukca0ryiretbbtyr.pbzxnfna-qritbbtyrtebhcf.pbz@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) client-ip=2a00:1450:4864:20::34a;
Received: by mail-wm1-x34a.google.com with SMTP id 5b1f17b1804b1-477cf2230c8so19796035e9.0
        for <kasan-dev@googlegroups.com>; Fri, 19 Dec 2025 07:46:41 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCXwQOxsje0QEyKbeSCQglMWQxNe2iTo85yDf4Pgg0uPOTccNqqh1YKcCba1m7jsC2s8GU9CtFJ1SdQ=@googlegroups.com
X-Received: from wmoo8-n2.prod.google.com ([2002:a05:600d:108:20b0:47b:daaa:51cf])
 (user=elver job=prod-delivery.src-stubby-dispatcher) by 2002:a05:600c:4fc6:b0:465:a51d:d4
 with SMTP id 5b1f17b1804b1-47d1953b768mr30732635e9.6.1766159200542; Fri, 19
 Dec 2025 07:46:40 -0800 (PST)
Date: Fri, 19 Dec 2025 16:40:08 +0100
In-Reply-To: <20251219154418.3592607-1-elver@google.com>
Mime-Version: 1.0
References: <20251219154418.3592607-1-elver@google.com>
X-Mailer: git-send-email 2.52.0.322.g1dd061c0dc-goog
Message-ID: <20251219154418.3592607-20-elver@google.com>
Subject: [PATCH v5 19/36] locking/local_lock: Support Clang's context analysis
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
 header.i=@google.com header.s=20230601 header.b=SW7OVcit;       spf=pass
 (google.com: domain of 3yhnfaqukca0ryiretbbtyr.pbzxnfna-qritbbtyrtebhcf.pbz@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3YHNFaQUKCa0RYiReTbbTYR.PbZXNfNa-QRiTbbTYRTebhcf.PbZ@flex--elver.bounces.google.com;
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

Add support for Clang's context analysis for local_lock_t and
local_trylock_t.

Signed-off-by: Marco Elver <elver@google.com>
---
v5:
* Rename "context guard" -> "context lock".
* Use new cleanup.h helpers to properly support scoped lock guards.

v4:
* Rename capability -> context analysis.

v3:
* Switch to DECLARE_LOCK_GUARD_1_ATTRS() (suggested by Peter)
* __assert -> __assume rename
* Rework __this_cpu_local_lock helper
* Support local_trylock_t
---
 Documentation/dev-tools/context-analysis.rst |  2 +-
 include/linux/local_lock.h                   | 51 ++++++++------
 include/linux/local_lock_internal.h          | 71 +++++++++++++++----
 lib/test_context-analysis.c                  | 73 ++++++++++++++++++++
 4 files changed, 161 insertions(+), 36 deletions(-)

diff --git a/Documentation/dev-tools/context-analysis.rst b/Documentation/dev-tools/context-analysis.rst
index 7b660c3003a0..a48b75f45e79 100644
--- a/Documentation/dev-tools/context-analysis.rst
+++ b/Documentation/dev-tools/context-analysis.rst
@@ -80,7 +80,7 @@ Supported Kernel Primitives
 
 Currently the following synchronization primitives are supported:
 `raw_spinlock_t`, `spinlock_t`, `rwlock_t`, `mutex`, `seqlock_t`,
-`bit_spinlock`, RCU, SRCU (`srcu_struct`), `rw_semaphore`.
+`bit_spinlock`, RCU, SRCU (`srcu_struct`), `rw_semaphore`, `local_lock_t`.
 
 For context locks with an initialization function (e.g., `spin_lock_init()`),
 calling this function before initializing any guarded members or globals
diff --git a/include/linux/local_lock.h b/include/linux/local_lock.h
index b0e6ab329b00..99c06e499375 100644
--- a/include/linux/local_lock.h
+++ b/include/linux/local_lock.h
@@ -14,13 +14,13 @@
  * local_lock - Acquire a per CPU local lock
  * @lock:	The lock variable
  */
-#define local_lock(lock)		__local_lock(this_cpu_ptr(lock))
+#define local_lock(lock)		__local_lock(__this_cpu_local_lock(lock))
 
 /**
  * local_lock_irq - Acquire a per CPU local lock and disable interrupts
  * @lock:	The lock variable
  */
-#define local_lock_irq(lock)		__local_lock_irq(this_cpu_ptr(lock))
+#define local_lock_irq(lock)		__local_lock_irq(__this_cpu_local_lock(lock))
 
 /**
  * local_lock_irqsave - Acquire a per CPU local lock, save and disable
@@ -29,19 +29,19 @@
  * @flags:	Storage for interrupt flags
  */
 #define local_lock_irqsave(lock, flags)				\
-	__local_lock_irqsave(this_cpu_ptr(lock), flags)
+	__local_lock_irqsave(__this_cpu_local_lock(lock), flags)
 
 /**
  * local_unlock - Release a per CPU local lock
  * @lock:	The lock variable
  */
-#define local_unlock(lock)		__local_unlock(this_cpu_ptr(lock))
+#define local_unlock(lock)		__local_unlock(__this_cpu_local_lock(lock))
 
 /**
  * local_unlock_irq - Release a per CPU local lock and enable interrupts
  * @lock:	The lock variable
  */
-#define local_unlock_irq(lock)		__local_unlock_irq(this_cpu_ptr(lock))
+#define local_unlock_irq(lock)		__local_unlock_irq(__this_cpu_local_lock(lock))
 
 /**
  * local_unlock_irqrestore - Release a per CPU local lock and restore
@@ -50,7 +50,7 @@
  * @flags:      Interrupt flags to restore
  */
 #define local_unlock_irqrestore(lock, flags)			\
-	__local_unlock_irqrestore(this_cpu_ptr(lock), flags)
+	__local_unlock_irqrestore(__this_cpu_local_lock(lock), flags)
 
 /**
  * local_trylock_init - Runtime initialize a lock instance
@@ -66,7 +66,7 @@
  * locking constrains it will _always_ fail to acquire the lock in NMI or
  * HARDIRQ context on PREEMPT_RT.
  */
-#define local_trylock(lock)		__local_trylock(this_cpu_ptr(lock))
+#define local_trylock(lock)		__local_trylock(__this_cpu_local_lock(lock))
 
 #define local_lock_is_locked(lock)	__local_lock_is_locked(lock)
 
@@ -81,27 +81,36 @@
  * HARDIRQ context on PREEMPT_RT.
  */
 #define local_trylock_irqsave(lock, flags)			\
-	__local_trylock_irqsave(this_cpu_ptr(lock), flags)
-
-DEFINE_GUARD(local_lock, local_lock_t __percpu*,
-	     local_lock(_T),
-	     local_unlock(_T))
-DEFINE_GUARD(local_lock_irq, local_lock_t __percpu*,
-	     local_lock_irq(_T),
-	     local_unlock_irq(_T))
+	__local_trylock_irqsave(__this_cpu_local_lock(lock), flags)
+
+DEFINE_LOCK_GUARD_1(local_lock, local_lock_t __percpu,
+		    local_lock(_T->lock),
+		    local_unlock(_T->lock))
+DEFINE_LOCK_GUARD_1(local_lock_irq, local_lock_t __percpu,
+		    local_lock_irq(_T->lock),
+		    local_unlock_irq(_T->lock))
 DEFINE_LOCK_GUARD_1(local_lock_irqsave, local_lock_t __percpu,
 		    local_lock_irqsave(_T->lock, _T->flags),
 		    local_unlock_irqrestore(_T->lock, _T->flags),
 		    unsigned long flags)
 
 #define local_lock_nested_bh(_lock)				\
-	__local_lock_nested_bh(this_cpu_ptr(_lock))
+	__local_lock_nested_bh(__this_cpu_local_lock(_lock))
 
 #define local_unlock_nested_bh(_lock)				\
-	__local_unlock_nested_bh(this_cpu_ptr(_lock))
-
-DEFINE_GUARD(local_lock_nested_bh, local_lock_t __percpu*,
-	     local_lock_nested_bh(_T),
-	     local_unlock_nested_bh(_T))
+	__local_unlock_nested_bh(__this_cpu_local_lock(_lock))
+
+DEFINE_LOCK_GUARD_1(local_lock_nested_bh, local_lock_t __percpu,
+		    local_lock_nested_bh(_T->lock),
+		    local_unlock_nested_bh(_T->lock))
+
+DECLARE_LOCK_GUARD_1_ATTRS(local_lock, __acquires(_T), __releases(*(local_lock_t __percpu **)_T))
+#define class_local_lock_constructor(_T) WITH_LOCK_GUARD_1_ATTRS(local_lock, _T)
+DECLARE_LOCK_GUARD_1_ATTRS(local_lock_irq, __acquires(_T), __releases(*(local_lock_t __percpu **)_T))
+#define class_local_lock_irq_constructor(_T) WITH_LOCK_GUARD_1_ATTRS(local_lock_irq, _T)
+DECLARE_LOCK_GUARD_1_ATTRS(local_lock_irqsave, __acquires(_T), __releases(*(local_lock_t __percpu **)_T))
+#define class_local_lock_irqsave_constructor(_T) WITH_LOCK_GUARD_1_ATTRS(local_lock_irqsave, _T)
+DECLARE_LOCK_GUARD_1_ATTRS(local_lock_nested_bh, __acquires(_T), __releases(*(local_lock_t __percpu **)_T))
+#define class_local_lock_nested_bh_constructor(_T) WITH_LOCK_GUARD_1_ATTRS(local_lock_nested_bh, _T)
 
 #endif
diff --git a/include/linux/local_lock_internal.h b/include/linux/local_lock_internal.h
index 1a1ea1232add..e8c4803d8db4 100644
--- a/include/linux/local_lock_internal.h
+++ b/include/linux/local_lock_internal.h
@@ -10,21 +10,23 @@
 
 #ifndef CONFIG_PREEMPT_RT
 
-typedef struct {
+context_lock_struct(local_lock) {
 #ifdef CONFIG_DEBUG_LOCK_ALLOC
 	struct lockdep_map	dep_map;
 	struct task_struct	*owner;
 #endif
-} local_lock_t;
+};
+typedef struct local_lock local_lock_t;
 
 /* local_trylock() and local_trylock_irqsave() only work with local_trylock_t */
-typedef struct {
+context_lock_struct(local_trylock) {
 #ifdef CONFIG_DEBUG_LOCK_ALLOC
 	struct lockdep_map	dep_map;
 	struct task_struct	*owner;
 #endif
 	u8		acquired;
-} local_trylock_t;
+};
+typedef struct local_trylock local_trylock_t;
 
 #ifdef CONFIG_DEBUG_LOCK_ALLOC
 # define LOCAL_LOCK_DEBUG_INIT(lockname)		\
@@ -84,9 +86,14 @@ do {								\
 			      0, LD_WAIT_CONFIG, LD_WAIT_INV,	\
 			      LD_LOCK_PERCPU);			\
 	local_lock_debug_init(lock);				\
+	__assume_ctx_lock(lock);				\
 } while (0)
 
-#define __local_trylock_init(lock) __local_lock_init((local_lock_t *)lock)
+#define __local_trylock_init(lock)				\
+do {								\
+	__local_lock_init((local_lock_t *)lock);		\
+	__assume_ctx_lock(lock);				\
+} while (0)
 
 #define __spinlock_nested_bh_init(lock)				\
 do {								\
@@ -97,6 +104,7 @@ do {								\
 			      0, LD_WAIT_CONFIG, LD_WAIT_INV,	\
 			      LD_LOCK_NORMAL);			\
 	local_lock_debug_init(lock);				\
+	__assume_ctx_lock(lock);				\
 } while (0)
 
 #define __local_lock_acquire(lock)					\
@@ -119,22 +127,25 @@ do {								\
 	do {							\
 		preempt_disable();				\
 		__local_lock_acquire(lock);			\
+		__acquire(lock);				\
 	} while (0)
 
 #define __local_lock_irq(lock)					\
 	do {							\
 		local_irq_disable();				\
 		__local_lock_acquire(lock);			\
+		__acquire(lock);				\
 	} while (0)
 
 #define __local_lock_irqsave(lock, flags)			\
 	do {							\
 		local_irq_save(flags);				\
 		__local_lock_acquire(lock);			\
+		__acquire(lock);				\
 	} while (0)
 
 #define __local_trylock(lock)					\
-	({							\
+	__try_acquire_ctx_lock(lock, ({				\
 		local_trylock_t *__tl;				\
 								\
 		preempt_disable();				\
@@ -148,10 +159,10 @@ do {								\
 				(local_lock_t *)__tl);		\
 		}						\
 		!!__tl;						\
-	})
+	}))
 
 #define __local_trylock_irqsave(lock, flags)			\
-	({							\
+	__try_acquire_ctx_lock(lock, ({				\
 		local_trylock_t *__tl;				\
 								\
 		local_irq_save(flags);				\
@@ -165,7 +176,7 @@ do {								\
 				(local_lock_t *)__tl);		\
 		}						\
 		!!__tl;						\
-	})
+	}))
 
 /* preemption or migration must be disabled before calling __local_lock_is_locked */
 #define __local_lock_is_locked(lock) READ_ONCE(this_cpu_ptr(lock)->acquired)
@@ -188,18 +199,21 @@ do {								\
 
 #define __local_unlock(lock)					\
 	do {							\
+		__release(lock);				\
 		__local_lock_release(lock);			\
 		preempt_enable();				\
 	} while (0)
 
 #define __local_unlock_irq(lock)				\
 	do {							\
+		__release(lock);				\
 		__local_lock_release(lock);			\
 		local_irq_enable();				\
 	} while (0)
 
 #define __local_unlock_irqrestore(lock, flags)			\
 	do {							\
+		__release(lock);				\
 		__local_lock_release(lock);			\
 		local_irq_restore(flags);			\
 	} while (0)
@@ -208,13 +222,19 @@ do {								\
 	do {							\
 		lockdep_assert_in_softirq();			\
 		local_lock_acquire((lock));			\
+		__acquire(lock);				\
 	} while (0)
 
 #define __local_unlock_nested_bh(lock)				\
-	local_lock_release((lock))
+	do {							\
+		__release(lock);				\
+		local_lock_release((lock));			\
+	} while (0)
 
 #else /* !CONFIG_PREEMPT_RT */
 
+#include <linux/spinlock.h>
+
 /*
  * On PREEMPT_RT local_lock maps to a per CPU spinlock, which protects the
  * critical section while staying preemptible.
@@ -269,7 +289,7 @@ do {								\
 } while (0)
 
 #define __local_trylock(lock)					\
-	({							\
+	__try_acquire_ctx_lock(lock, context_unsafe(({		\
 		int __locked;					\
 								\
 		if (in_nmi() | in_hardirq()) {			\
@@ -281,17 +301,40 @@ do {								\
 				migrate_enable();		\
 		}						\
 		__locked;					\
-	})
+	})))
 
 #define __local_trylock_irqsave(lock, flags)			\
-	({							\
+	__try_acquire_ctx_lock(lock, ({				\
 		typecheck(unsigned long, flags);		\
 		flags = 0;					\
 		__local_trylock(lock);				\
-	})
+	}))
 
 /* migration must be disabled before calling __local_lock_is_locked */
 #define __local_lock_is_locked(__lock)					\
 	(rt_mutex_owner(&this_cpu_ptr(__lock)->lock) == current)
 
 #endif /* CONFIG_PREEMPT_RT */
+
+#if defined(WARN_CONTEXT_ANALYSIS)
+/*
+ * Because the compiler only knows about the base per-CPU variable, use this
+ * helper function to make the compiler think we lock/unlock the @base variable,
+ * and hide the fact we actually pass the per-CPU instance to lock/unlock
+ * functions.
+ */
+static __always_inline local_lock_t *__this_cpu_local_lock(local_lock_t __percpu *base)
+	__returns_ctx_lock(base) __attribute__((overloadable))
+{
+	return this_cpu_ptr(base);
+}
+#ifndef CONFIG_PREEMPT_RT
+static __always_inline local_trylock_t *__this_cpu_local_lock(local_trylock_t __percpu *base)
+	__returns_ctx_lock(base) __attribute__((overloadable))
+{
+	return this_cpu_ptr(base);
+}
+#endif /* CONFIG_PREEMPT_RT */
+#else  /* WARN_CONTEXT_ANALYSIS */
+#define __this_cpu_local_lock(base) this_cpu_ptr(base)
+#endif /* WARN_CONTEXT_ANALYSIS */
diff --git a/lib/test_context-analysis.c b/lib/test_context-analysis.c
index 1c96c56cf873..003e64cac540 100644
--- a/lib/test_context-analysis.c
+++ b/lib/test_context-analysis.c
@@ -6,7 +6,9 @@
 
 #include <linux/bit_spinlock.h>
 #include <linux/build_bug.h>
+#include <linux/local_lock.h>
 #include <linux/mutex.h>
+#include <linux/percpu.h>
 #include <linux/rcupdate.h>
 #include <linux/rwsem.h>
 #include <linux/seqlock.h>
@@ -458,3 +460,74 @@ static void __used test_srcu_guard(struct test_srcu_data *d)
 	{ guard(srcu_fast)(&d->srcu); (void)srcu_dereference(d->data, &d->srcu); }
 	{ guard(srcu_fast_notrace)(&d->srcu); (void)srcu_dereference(d->data, &d->srcu); }
 }
+
+struct test_local_lock_data {
+	local_lock_t lock;
+	int counter __guarded_by(&lock);
+};
+
+static DEFINE_PER_CPU(struct test_local_lock_data, test_local_lock_data) = {
+	.lock = INIT_LOCAL_LOCK(lock),
+};
+
+static void __used test_local_lock_init(struct test_local_lock_data *d)
+{
+	local_lock_init(&d->lock);
+	d->counter = 0;
+}
+
+static void __used test_local_lock(void)
+{
+	unsigned long flags;
+
+	local_lock(&test_local_lock_data.lock);
+	this_cpu_add(test_local_lock_data.counter, 1);
+	local_unlock(&test_local_lock_data.lock);
+
+	local_lock_irq(&test_local_lock_data.lock);
+	this_cpu_add(test_local_lock_data.counter, 1);
+	local_unlock_irq(&test_local_lock_data.lock);
+
+	local_lock_irqsave(&test_local_lock_data.lock, flags);
+	this_cpu_add(test_local_lock_data.counter, 1);
+	local_unlock_irqrestore(&test_local_lock_data.lock, flags);
+
+	local_lock_nested_bh(&test_local_lock_data.lock);
+	this_cpu_add(test_local_lock_data.counter, 1);
+	local_unlock_nested_bh(&test_local_lock_data.lock);
+}
+
+static void __used test_local_lock_guard(void)
+{
+	{ guard(local_lock)(&test_local_lock_data.lock); this_cpu_add(test_local_lock_data.counter, 1); }
+	{ guard(local_lock_irq)(&test_local_lock_data.lock); this_cpu_add(test_local_lock_data.counter, 1); }
+	{ guard(local_lock_irqsave)(&test_local_lock_data.lock); this_cpu_add(test_local_lock_data.counter, 1); }
+	{ guard(local_lock_nested_bh)(&test_local_lock_data.lock); this_cpu_add(test_local_lock_data.counter, 1); }
+}
+
+struct test_local_trylock_data {
+	local_trylock_t lock;
+	int counter __guarded_by(&lock);
+};
+
+static DEFINE_PER_CPU(struct test_local_trylock_data, test_local_trylock_data) = {
+	.lock = INIT_LOCAL_TRYLOCK(lock),
+};
+
+static void __used test_local_trylock_init(struct test_local_trylock_data *d)
+{
+	local_trylock_init(&d->lock);
+	d->counter = 0;
+}
+
+static void __used test_local_trylock(void)
+{
+	local_lock(&test_local_trylock_data.lock);
+	this_cpu_add(test_local_trylock_data.counter, 1);
+	local_unlock(&test_local_trylock_data.lock);
+
+	if (local_trylock(&test_local_trylock_data.lock)) {
+		this_cpu_add(test_local_trylock_data.counter, 1);
+		local_unlock(&test_local_trylock_data.lock);
+	}
+}
-- 
2.52.0.322.g1dd061c0dc-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251219154418.3592607-20-elver%40google.com.
