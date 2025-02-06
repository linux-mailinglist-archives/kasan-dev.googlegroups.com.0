Return-Path: <kasan-dev+bncBC7OBJGL2MHBB7HZSO6QMGQELKCYNNY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x538.google.com (mail-ed1-x538.google.com [IPv6:2a00:1450:4864:20::538])
	by mail.lfdr.de (Postfix) with ESMTPS id CCEBAA2B062
	for <lists+kasan-dev@lfdr.de>; Thu,  6 Feb 2025 19:18:38 +0100 (CET)
Received: by mail-ed1-x538.google.com with SMTP id 4fb4d7f45d1cf-5dc5b397109sf1443924a12.2
        for <lists+kasan-dev@lfdr.de>; Thu, 06 Feb 2025 10:18:38 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1738865918; cv=pass;
        d=google.com; s=arc-20240605;
        b=Kp/jwHwzeS3HZ+FEYMFasHIm+YS038n6B3OGyoSuE69q0ArJ1PxQifwHtUD2KWp6Mg
         bY2hbNcHx7eFtF7a+SBjGJmL967DqTQwNZe/DTn+mYQAC70UK5p+WGSwpEm5o5nv3+M5
         hcO5GOoVqNk8dQt9s4fnMWOWUlh1v3tVEc7RhTXU27Sry3MkhmkXavmHdV7q4TIoyv7e
         aIDAzQmEvW3w6q8yCbRU9ZcwDpXdGO4cZYsY/UBTaLwVaYyXwLFmeLoA9L2fSpfv/zIp
         cU8EH1Q0aZ+8JEIzKw51EelYZlLbGJWdhGAod7J5JD2XNrlOqEbR7GcYTuh8c6zXNjiW
         ggKw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=qa5JOxxSxlMmL/eHWdeNyGgtsQ+t3kfE7cIsWhjgN40=;
        fh=5pecNELSBBEcGQ9wadQxcPvBkl1OiYO1rx2usLwfmN8=;
        b=HsEbutBy9530UaMjA7reShqY0vFJk/IMvcO7GEfoeKS3JAHfj8Zas25YLRQGsP1GyU
         fTO+wTRfzx977hyK2K666vNTk721r0dfxb5Cz6oaPros4b2ZFnVEhrVBCd2JyAYRf9Lp
         pzevbcg9yTUpOZPXegxrJ4rm44MTqCh4rBcDxt+nN2hyGOmFJQIZFugBhoo2Shqljm0/
         2KJkzgBid2d7KOrFOTcH6XTqopVGi/t9Z86OlGcXe824bR9ODza1sa5gqsjMED0hxuXG
         n6G6QLKxQQD32/kK3Zeg92vD3ULRZXdz5q2wCHPXdAAJ9f/KPWSJrPWRkajviW6+4z2J
         qalg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=ucVz0STT;
       spf=pass (google.com: domain of 3-vykzwukccsv2cv8x55x2v.t531r9r4-uvcx55x2vx85b69.t53@flex--elver.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3-vykZwUKCcsv2Cv8x55x2v.t531r9r4-uvCx55x2vx85B69.t53@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1738865918; x=1739470718; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=qa5JOxxSxlMmL/eHWdeNyGgtsQ+t3kfE7cIsWhjgN40=;
        b=Lv+nTEBYAvACSmyDPJa2I1rFn3Mp2Q4Bux3V8mZ9NVnqIQmODMma3XCC2ACQa3WfgX
         4ZGck+JwXVS73dkNi5UMmxJBm2XZv6eojEfdcfQu93hwEVdQvJqyCmoAlw9roDlVFfCw
         JAXnnboIsIYyETv5yPb67TbETEHEWpfb4RJ2cpWubLUsiYgg7ys/jWWq5ikKogEgi7Pd
         tD7LPUYnV1xfvfip/OCwQ5OxsUie0d0DA+ykdIpF9/WgJC3g/J42yvPqLUnOPg7qX6uY
         Pr2Vp9TAjvLd+ckZn5c5iIznGUijdzqhrhPManvStrdXVgmMZYtSJHoEoLrfx7L+UZkf
         10Hw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1738865918; x=1739470718;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=qa5JOxxSxlMmL/eHWdeNyGgtsQ+t3kfE7cIsWhjgN40=;
        b=vC3pbcmxGcd7BYQ8znRCdJTCh6+1mHevFlM0cxkgeM9kgabfSzaFPGVZOambQ7yaaN
         qsUlKzqA8lsxZd9S1zrf6lnEvClhBa1AWdjie4MbRW5eBQ2DRycAtwE0WJ2C8JiywdRi
         1ZNWlu6akPliv1kSYjNhpmnlY+NIQuWSDi30spkDXQYH9dym1o4cVgopE6g61rvpCeks
         XhA89I3An+iYfqktV2EGmpLeCNm6+YXjBaJYiTibDVOWIhnTnyQT2GwcEqQStxbe7ZYO
         eP9xFshQLmqMId72xlGl2rC9JSHXoOEd3zXrkJcTWGpzxKq99JjU17m3lwm5BaeoeE8C
         +Rcw==
X-Forwarded-Encrypted: i=2; AJvYcCVPf+ybB1BQ+1dWdrJBS25uRp+g+bDcLk68j6eDES+n4A+RCGbkFEuEmtyAtdjsu9COqWfOBA==@lfdr.de
X-Gm-Message-State: AOJu0YyTMN23QvyBERRqSckMI/bwoi/5FpesZ2898RJNV2zwM3EsWmEw
	1fXt/eUm8IOHUzkBPfVQVKpv4Pr3mCn8X6VzE/zPrjZAeu/DrRll
X-Google-Smtp-Source: AGHT+IGW2HeNRdyjup5AjoEC50F2XR0d3xg1yZJtfHoPDEAjAOqfPZ++bn6TDebSQGBkWd8XJJ1J9g==
X-Received: by 2002:a05:6402:5290:b0:5dc:ebb8:fe64 with SMTP id 4fb4d7f45d1cf-5de45019313mr566600a12.14.1738865916909;
        Thu, 06 Feb 2025 10:18:36 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a50:d55c:0:b0:5dc:d09c:bd1e with SMTP id 4fb4d7f45d1cf-5de44e69465ls117284a12.1.-pod-prod-07-eu;
 Thu, 06 Feb 2025 10:18:34 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWnA0wkFQsYwtaJaK1aBl2aMyqvibQuPnrfBB3Frclo6MD+wgKg1RsY5yHhg0Ch2ttDt28g0dup3+c=@googlegroups.com
X-Received: by 2002:a17:907:9616:b0:ab7:6a57:1778 with SMTP id a640c23a62f3a-ab76a571916mr776361866b.0.1738865914452;
        Thu, 06 Feb 2025 10:18:34 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1738865914; cv=none;
        d=google.com; s=arc-20240605;
        b=jIpKtzYaqvgc2RnY4xjHitTyokCOuI4uRV0sZ8GUND4iCegv9wrPfGpaH4l+KZgAIP
         E1jC7EHOR5JnNzvbzk71aeWNyw+GyfLWNZszg2X2Fl5NWTkNbv6o1YD+De6NGhHGsr/C
         cLJcLInY226JyL8d2TZotzgAD7N74cGvfMidb5PrDUbAm4F8dMuDFDG9G11TNJlj/8Gk
         HQHja2LuwGW0bPBfhtyDHiRk4leHO1pQODIustKz+IBrKyyrNVQXWL+hCh+VYxiMIdgG
         7agDCowHASPZJwCvWJNJFKL5hKp2oPUlxaXHUbcKHHOqF4ySU7LuU8jNkayJK8bveY1E
         qmBQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=/4B3dc+uw3kIUoAQrEfaYRIJGMzUFqPSDxrvx8H6TaQ=;
        fh=RX3M7tVwuDzzUmwLf+qJjUf1VD/mxrOqFKfyK24Dkc0=;
        b=KmslaK8QuejJU+x8DuTkyC7OG2vOuTtBwDppMPo268gUopkcJ10nSsHK5oFo/Rbccj
         HDnWlfvXFNCXc6ZGZa2HbCWq1tKgBcmo1L2F8xT066R/2ALS/wqvCB9Bh5ea5WkuXaKe
         ZmMLnW25THH0C35PcFyuFNE8enZOSL2TDfQcXkFUgsROLFu7w7bELhvRw1AD94uH6WWK
         AkR4gadH8FZYjXa8No8zzdqZzWH7R4iID6v3rzld66jNH65K6ehEcB6PfxSSirokGLDW
         BBYnZzxc74ZQRkJ/YVnfatXbdvrVUcoMdMfa6lUkqR7FxWDuo64Fz2LvCylqtaShpOvb
         LFdQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=ucVz0STT;
       spf=pass (google.com: domain of 3-vykzwukccsv2cv8x55x2v.t531r9r4-uvcx55x2vx85b69.t53@flex--elver.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3-vykZwUKCcsv2Cv8x55x2v.t531r9r4-uvCx55x2vx85B69.t53@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ej1-x649.google.com (mail-ej1-x649.google.com. [2a00:1450:4864:20::649])
        by gmr-mx.google.com with ESMTPS id a640c23a62f3a-ab772faa9a9si5918866b.2.2025.02.06.10.18.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 06 Feb 2025 10:18:34 -0800 (PST)
Received-SPF: pass (google.com: domain of 3-vykzwukccsv2cv8x55x2v.t531r9r4-uvcx55x2vx85b69.t53@flex--elver.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) client-ip=2a00:1450:4864:20::649;
Received: by mail-ej1-x649.google.com with SMTP id a640c23a62f3a-ab6eecc3221so165361466b.0
        for <kasan-dev@googlegroups.com>; Thu, 06 Feb 2025 10:18:34 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCWNSOCpQ9bAtcPvS9xcgtQHdvXidUElx1f7c374FeqLIusocVirgOnQ/cLGiw2exrCRf5OQz9PyFHo=@googlegroups.com
X-Received: from ejctl25.prod.google.com ([2002:a17:907:c319:b0:aa6:a222:16ac])
 (user=elver job=prod-delivery.src-stubby-dispatcher) by 2002:a17:907:6094:b0:ab6:f4e7:52f9
 with SMTP id a640c23a62f3a-ab75e26494emr827537866b.25.1738865914032; Thu, 06
 Feb 2025 10:18:34 -0800 (PST)
Date: Thu,  6 Feb 2025 19:10:13 +0100
In-Reply-To: <20250206181711.1902989-1-elver@google.com>
Mime-Version: 1.0
References: <20250206181711.1902989-1-elver@google.com>
X-Mailer: git-send-email 2.48.1.502.g6dc24dfdaf-goog
Message-ID: <20250206181711.1902989-20-elver@google.com>
Subject: [PATCH RFC 19/24] locking/local_lock: Support Clang's capability analysis
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
 header.i=@google.com header.s=20230601 header.b=ucVz0STT;       spf=pass
 (google.com: domain of 3-vykzwukccsv2cv8x55x2v.t531r9r4-uvcx55x2vx85b69.t53@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3-vykZwUKCcsv2Cv8x55x2v.t531r9r4-uvCx55x2vx85B69.t53@flex--elver.bounces.google.com;
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

Add support for Clang's capability analysis for local_lock_t.

Signed-off-by: Marco Elver <elver@google.com>
---
 .../dev-tools/capability-analysis.rst         |  2 +-
 include/linux/local_lock.h                    | 18 ++++----
 include/linux/local_lock_internal.h           | 41 ++++++++++++++---
 lib/test_capability-analysis.c                | 46 +++++++++++++++++++
 4 files changed, 90 insertions(+), 17 deletions(-)

diff --git a/Documentation/dev-tools/capability-analysis.rst b/Documentation/dev-tools/capability-analysis.rst
index 719986739b0e..1e9ce018e30e 100644
--- a/Documentation/dev-tools/capability-analysis.rst
+++ b/Documentation/dev-tools/capability-analysis.rst
@@ -86,7 +86,7 @@ Supported Kernel Primitives
 
 Currently the following synchronization primitives are supported:
 `raw_spinlock_t`, `spinlock_t`, `rwlock_t`, `mutex`, `seqlock_t`,
-`bit_spinlock`, RCU, SRCU (`srcu_struct`), `rw_semaphore`.
+`bit_spinlock`, RCU, SRCU (`srcu_struct`), `rw_semaphore`, `local_lock_t`.
 
 For capabilities with an initialization function (e.g., `spin_lock_init()`),
 calling this function on the capability instance before initializing any
diff --git a/include/linux/local_lock.h b/include/linux/local_lock.h
index 091dc0b6bdfb..63fadcf66216 100644
--- a/include/linux/local_lock.h
+++ b/include/linux/local_lock.h
@@ -51,12 +51,12 @@
 #define local_unlock_irqrestore(lock, flags)			\
 	__local_unlock_irqrestore(lock, flags)
 
-DEFINE_GUARD(local_lock, local_lock_t __percpu*,
-	     local_lock(_T),
-	     local_unlock(_T))
-DEFINE_GUARD(local_lock_irq, local_lock_t __percpu*,
-	     local_lock_irq(_T),
-	     local_unlock_irq(_T))
+DEFINE_LOCK_GUARD_1(local_lock, local_lock_t __percpu,
+		    local_lock(_T->lock),
+		    local_unlock(_T->lock))
+DEFINE_LOCK_GUARD_1(local_lock_irq, local_lock_t __percpu,
+		    local_lock_irq(_T->lock),
+		    local_unlock_irq(_T->lock))
 DEFINE_LOCK_GUARD_1(local_lock_irqsave, local_lock_t __percpu,
 		    local_lock_irqsave(_T->lock, _T->flags),
 		    local_unlock_irqrestore(_T->lock, _T->flags),
@@ -68,8 +68,8 @@ DEFINE_LOCK_GUARD_1(local_lock_irqsave, local_lock_t __percpu,
 #define local_unlock_nested_bh(_lock)				\
 	__local_unlock_nested_bh(_lock)
 
-DEFINE_GUARD(local_lock_nested_bh, local_lock_t __percpu*,
-	     local_lock_nested_bh(_T),
-	     local_unlock_nested_bh(_T))
+DEFINE_LOCK_GUARD_1(local_lock_nested_bh, local_lock_t __percpu,
+		    local_lock_nested_bh(_T->lock),
+		    local_unlock_nested_bh(_T->lock))
 
 #endif
diff --git a/include/linux/local_lock_internal.h b/include/linux/local_lock_internal.h
index 8dd71fbbb6d2..031de28d8ffb 100644
--- a/include/linux/local_lock_internal.h
+++ b/include/linux/local_lock_internal.h
@@ -8,12 +8,13 @@
 
 #ifndef CONFIG_PREEMPT_RT
 
-typedef struct {
+struct_with_capability(local_lock) {
 #ifdef CONFIG_DEBUG_LOCK_ALLOC
 	struct lockdep_map	dep_map;
 	struct task_struct	*owner;
 #endif
-} local_lock_t;
+};
+typedef struct local_lock local_lock_t;
 
 #ifdef CONFIG_DEBUG_LOCK_ALLOC
 # define LOCAL_LOCK_DEBUG_INIT(lockname)		\
@@ -60,6 +61,7 @@ do {								\
 			      0, LD_WAIT_CONFIG, LD_WAIT_INV,	\
 			      LD_LOCK_PERCPU);			\
 	local_lock_debug_init(lock);				\
+	__assert_cap(lock);					\
 } while (0)
 
 #define __spinlock_nested_bh_init(lock)				\
@@ -71,40 +73,47 @@ do {								\
 			      0, LD_WAIT_CONFIG, LD_WAIT_INV,	\
 			      LD_LOCK_NORMAL);			\
 	local_lock_debug_init(lock);				\
+	__assert_cap(lock);					\
 } while (0)
 
 #define __local_lock(lock)					\
 	do {							\
 		preempt_disable();				\
 		local_lock_acquire(this_cpu_ptr(lock));		\
+		__acquire(lock);				\
 	} while (0)
 
 #define __local_lock_irq(lock)					\
 	do {							\
 		local_irq_disable();				\
 		local_lock_acquire(this_cpu_ptr(lock));		\
+		__acquire(lock);				\
 	} while (0)
 
 #define __local_lock_irqsave(lock, flags)			\
 	do {							\
 		local_irq_save(flags);				\
 		local_lock_acquire(this_cpu_ptr(lock));		\
+		__acquire(lock);				\
 	} while (0)
 
 #define __local_unlock(lock)					\
 	do {							\
+		__release(lock);				\
 		local_lock_release(this_cpu_ptr(lock));		\
 		preempt_enable();				\
 	} while (0)
 
 #define __local_unlock_irq(lock)				\
 	do {							\
+		__release(lock);				\
 		local_lock_release(this_cpu_ptr(lock));		\
 		local_irq_enable();				\
 	} while (0)
 
 #define __local_unlock_irqrestore(lock, flags)			\
 	do {							\
+		__release(lock);				\
 		local_lock_release(this_cpu_ptr(lock));		\
 		local_irq_restore(flags);			\
 	} while (0)
@@ -113,19 +122,37 @@ do {								\
 	do {							\
 		lockdep_assert_in_softirq();			\
 		local_lock_acquire(this_cpu_ptr(lock));	\
+		__acquire(lock);				\
 	} while (0)
 
 #define __local_unlock_nested_bh(lock)				\
-	local_lock_release(this_cpu_ptr(lock))
+	do {							\
+		__release(lock);				\
+		local_lock_release(this_cpu_ptr(lock));		\
+	} while (0)
 
 #else /* !CONFIG_PREEMPT_RT */
 
+#include <linux/spinlock.h>
+
 /*
  * On PREEMPT_RT local_lock maps to a per CPU spinlock, which protects the
  * critical section while staying preemptible.
  */
 typedef spinlock_t local_lock_t;
 
+/*
+ * Because the compiler only knows about the base per-CPU variable, use this
+ * helper function to make the compiler think we lock/unlock the @base variable,
+ * and hide the fact we actually pass the per-CPU instance @pcpu to lock/unlock
+ * functions.
+ */
+static inline local_lock_t *__local_lock_alias(local_lock_t __percpu *base, local_lock_t *pcpu)
+	__returns_cap(base)
+{
+	return pcpu;
+}
+
 #define INIT_LOCAL_LOCK(lockname) __LOCAL_SPIN_LOCK_UNLOCKED((lockname))
 
 #define __local_lock_init(l)					\
@@ -136,7 +163,7 @@ typedef spinlock_t local_lock_t;
 #define __local_lock(__lock)					\
 	do {							\
 		migrate_disable();				\
-		spin_lock(this_cpu_ptr((__lock)));		\
+		spin_lock(__local_lock_alias(__lock, this_cpu_ptr((__lock)))); \
 	} while (0)
 
 #define __local_lock_irq(lock)			__local_lock(lock)
@@ -150,7 +177,7 @@ typedef spinlock_t local_lock_t;
 
 #define __local_unlock(__lock)					\
 	do {							\
-		spin_unlock(this_cpu_ptr((__lock)));		\
+		spin_unlock(__local_lock_alias(__lock, this_cpu_ptr((__lock)))); \
 		migrate_enable();				\
 	} while (0)
 
@@ -161,12 +188,12 @@ typedef spinlock_t local_lock_t;
 #define __local_lock_nested_bh(lock)				\
 do {								\
 	lockdep_assert_in_softirq_func();			\
-	spin_lock(this_cpu_ptr(lock));				\
+	spin_lock(__local_lock_alias(lock, this_cpu_ptr(lock))); \
 } while (0)
 
 #define __local_unlock_nested_bh(lock)				\
 do {								\
-	spin_unlock(this_cpu_ptr((lock)));			\
+	spin_unlock(__local_lock_alias(lock, this_cpu_ptr((lock)))); \
 } while (0)
 
 #endif /* CONFIG_PREEMPT_RT */
diff --git a/lib/test_capability-analysis.c b/lib/test_capability-analysis.c
index 4638d220f474..dd3fccff2352 100644
--- a/lib/test_capability-analysis.c
+++ b/lib/test_capability-analysis.c
@@ -6,7 +6,9 @@
 
 #include <linux/bit_spinlock.h>
 #include <linux/build_bug.h>
+#include <linux/local_lock.h>
 #include <linux/mutex.h>
+#include <linux/percpu.h>
 #include <linux/rcupdate.h>
 #include <linux/rwsem.h>
 #include <linux/seqlock.h>
@@ -433,3 +435,47 @@ static void __used test_srcu_guard(struct test_srcu_data *d)
 	guard(srcu)(&d->srcu);
 	(void)srcu_dereference(d->data, &d->srcu);
 }
+
+struct test_local_lock_data {
+	local_lock_t lock;
+	int counter __var_guarded_by(&lock);
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
-- 
2.48.1.502.g6dc24dfdaf-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250206181711.1902989-20-elver%40google.com.
