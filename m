Return-Path: <kasan-dev+bncBC7OBJGL2MHBB4XZSO6QMGQE3QX6DUI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x338.google.com (mail-wm1-x338.google.com [IPv6:2a00:1450:4864:20::338])
	by mail.lfdr.de (Postfix) with ESMTPS id C243DA2B05C
	for <lists+kasan-dev@lfdr.de>; Thu,  6 Feb 2025 19:18:29 +0100 (CET)
Received: by mail-wm1-x338.google.com with SMTP id 5b1f17b1804b1-436225d4389sf11192275e9.1
        for <lists+kasan-dev@lfdr.de>; Thu, 06 Feb 2025 10:18:29 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1738865909; cv=pass;
        d=google.com; s=arc-20240605;
        b=cLjeRJdCR+nbMT+F5gYhp7VWijjL4Sf4RBqS/kLmNeAaEYQ/PDsQy6vWDJf4lDGVxb
         AP7VMzaPIkg3fInRM5AT8dwA1bWlJFSqZpCHhRcx7wnAusuZjzbRX0CpGEQVbvds9uLD
         /co4gfSekIB4bHJ1i9b7QIunSwS4cASsWeHHVhCYQXb8vh1S7dTx6AjkNdXvlJtJPg3T
         lZ8c2ZtWFa3bwua4ouPaPkGfPsFpa9EodYFqMky4oZbuz2dubi0QJIuvTJ5d43kneHhU
         XYH0mfma+8uSABkmDukDIPsDgC4zyhFGymOYzZ4FuMwPrS0uepJpGJPgJs2D8TxYDhOG
         9lFg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=BCbwLfO7JmOcSORSzcAJHXltH95Jsk59u6dpsjDKA9c=;
        fh=MNbkusYl7pVd/3rsuSRGIgnqtYDghIjyT/YAlE6hV1Q=;
        b=HogIWcpn9qyOGEsE9/953QRFlvc/+lXzDqZU/dh/M/eyQLf3Ht03IH4FXh196M4A5X
         w82zKFMDfnPwyprdyKf1AVBIK0QAWRistiuw0oRJLnEz9NvTqU6qW0nMp8UTIYHRupJn
         ocbtenv4rRyvBrW3aTLW4LJpCfozQ1HbI+UmxmQrX69+vZKt5odXS+jweGovX83f/XBf
         CmxJtN9Pp7MYcEMM883/0lli1LfKdKpCvNxz3k2zsvYU55AV2wFDAB3uvfjODkCBQF74
         MX2mR4qENI/jx/MNQk41v5JgX8d3EAAyC51zP72419nWviirK2lp+54B++ad4qymbxaW
         Cguw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=R0iwMCiZ;
       spf=pass (google.com: domain of 37_ykzwukccakr1kxmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--elver.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=37_ykZwUKCcAkr1kxmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1738865909; x=1739470709; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=BCbwLfO7JmOcSORSzcAJHXltH95Jsk59u6dpsjDKA9c=;
        b=hhuG7QbzUcs8K1Xn7KnR9UPRL4vuRqGptIXQkiAZiF/vSTDUuHBseCEeOfKlzMLlRg
         YlIBGFUm4xW5RThiaEURPKoVEVoWrYzFDhzVfwcK5dZI2yTn5u5TATt9+8nsX2jAIqSk
         gvbTAU3tzEnfyPZQ/bYihs8a1zZmYVzcVca5VJe08lN956No+SVxwc5hV0yDjolqrtbN
         5UEw6gO7Wrd9u8ghyj1wpgSZ+97t1wSdeDVdA6sw1f1cRasTPK57kfQXVuqPyLrutxJ7
         SRlSd0elgUEZ4IQftboTsrBgykAiiEkWMkYirBzJ6/3q1/jKkJYqS1EAZ4Y/1JmWpzkf
         oChQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1738865909; x=1739470709;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=BCbwLfO7JmOcSORSzcAJHXltH95Jsk59u6dpsjDKA9c=;
        b=M1scGZp8cUwzK4y/AiohOdHc3e5rE7k0qrdYFT9m43hjgH+R0WFb6j9Zj6817NrZ4s
         223WBNcAPajUf/OGjfEBA8TE8u9TbsFrXkKZiRT+8LPXtoMErmNlgH9kpmRX4/nycOru
         ixl1PpXVPstW01d+vKggXOU/Sf3b1XDqKg/5jjPZMaoPcHBucNy0TEy3/lVPNASDrDmo
         RGOuS+4awgKVzo+Qnbk/cS2aSr+uDWAaeyTI7+yd5ctA4P+X60aP72abRl8lOsDxNZW8
         TIwaA9t7FsfY3oN+kgoMgN9ChVLh+iBLzDDIoLyAGBrfxRFBk3RfdrIzZud5Twj722C/
         u0Qw==
X-Forwarded-Encrypted: i=2; AJvYcCW/vuTKN8L/3F+O/2DrlsR/1KjLtq+Bu19XJ38oXniuBAuXaUkZMJz9hG0OJP5u4ZhVgr76/A==@lfdr.de
X-Gm-Message-State: AOJu0YyXBDuC3vwOLX200zTXPwSwbgBZdXdLTFS2yr1a+DNwT/fz3BGf
	09yFBuRV/78AbCKBvg/VBlu6OZ0y88JeCY5iFxGSF55J+cq5zbGF
X-Google-Smtp-Source: AGHT+IGVQxcMB5MfOJjkRy7clDc0+dMjQxSaIPA7RZbyN2KXK+GiG1mq4cMj3jt0x9NGzeWlXSvpAw==
X-Received: by 2002:a5d:64ec:0:b0:38d:a695:6daf with SMTP id ffacd0b85a97d-38dbb28895cmr3028007f8f.19.1738865906642;
        Thu, 06 Feb 2025 10:18:26 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:a1d7:0:b0:38a:876d:d86b with SMTP id ffacd0b85a97d-38dbad3a195ls359952f8f.0.-pod-prod-00-eu;
 Thu, 06 Feb 2025 10:18:24 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXfmOjQYkcpJomLu05yTHLANQffzX8wGEM2Cx3NQ7hN6d4Yj5nbcAEkahpZPeKxfljl6wRiFZBlceM=@googlegroups.com
X-Received: by 2002:a05:6000:178c:b0:386:34af:9bae with SMTP id ffacd0b85a97d-38dbb20b21fmr3171451f8f.4.1738865904316;
        Thu, 06 Feb 2025 10:18:24 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1738865904; cv=none;
        d=google.com; s=arc-20240605;
        b=Q0OrWdy7aVyMVH/jVRBtlQFyqfPK7FpwMmFrNgGg/XOgl4VYsHzAGjocx2+FwCGLlB
         pOVaKquo31MwdtOzQ7YIkba9tYDrxUJtKzHg19goBuiw56GD4ew1rw6U7bM1EQqGRZg6
         WdUYk/DOvN5ou2DbfGUbfq6aWpygGXYIvcHCIdk9RTmlSR5ooPtopdtbgOb6eBEb3qOH
         55RLMYDHmpw0zCf3tNgP285mGu3u4krpHgVrksQ2rKt5vpnSx4HEo8Z3E2l9qVm4OuGl
         icEpwai71ntp0gxJ8jJiYDv+E6i3ZVIzewBk1mQPt9BX7JB9YSZMru9xkMCOckuYLp4P
         NO+g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=JOzjkOrq5kterB3FAixUHWQIVtw7H/sF/ZXjRLk43E0=;
        fh=t+7jRzGYRF1Xksj40ZGWUtr+vcbljQFTaqpLEbnxcBk=;
        b=awYjK7AFJ5zNZImWfd73cBCUOU28xjkZX2DhBCemW4fawO8TUhjhdAfEh5X1efSR8k
         NEJp1eU/sDcwslNUo/yfoIaVtgYkDWv6zbg0TcVTgQMifUnFxoBHtdvBn343bz2RB26i
         8jC4rXnlGlCC6DwPfb9AhqjZJ61mUMXDfh7t9SfhLYezzPfkEjbZOMDRNhQXtaCZVTnH
         oMR/eAb1aVNebfDKcxux8GjvZIIo1UHFoIwMHXrriZPIG7O6x3qanTf72o6q3cFJ6WyP
         tVQbcGJI6+H4Y9efZ0Q605w4s3WGJirc/6m3gY3IacvKqJvOJWiqITiPho9Ly3wqmbPF
         qpaA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=R0iwMCiZ;
       spf=pass (google.com: domain of 37_ykzwukccakr1kxmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--elver.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=37_ykZwUKCcAkr1kxmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ej1-x649.google.com (mail-ej1-x649.google.com. [2a00:1450:4864:20::649])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-43907f18ffcsi2804555e9.1.2025.02.06.10.18.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 06 Feb 2025 10:18:24 -0800 (PST)
Received-SPF: pass (google.com: domain of 37_ykzwukccakr1kxmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--elver.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) client-ip=2a00:1450:4864:20::649;
Received: by mail-ej1-x649.google.com with SMTP id a640c23a62f3a-ab6d5363a4bso137032666b.3
        for <kasan-dev@googlegroups.com>; Thu, 06 Feb 2025 10:18:24 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCVWYJJjD2r33K4P9p6if/xaW9OZn1bcAoES4aV4p+urzm5QdiN6ZaM2Of77Y85hWMxtecZqh7IjenM=@googlegroups.com
X-Received: from edben24.prod.google.com ([2002:a05:6402:5298:b0:5dc:37ed:79fc])
 (user=elver job=prod-delivery.src-stubby-dispatcher) by 2002:a17:907:7ba8:b0:ab6:ed8a:601f
 with SMTP id a640c23a62f3a-ab75e23496emr716074566b.12.1738865903775; Thu, 06
 Feb 2025 10:18:23 -0800 (PST)
Date: Thu,  6 Feb 2025 19:10:09 +0100
In-Reply-To: <20250206181711.1902989-1-elver@google.com>
Mime-Version: 1.0
References: <20250206181711.1902989-1-elver@google.com>
X-Mailer: git-send-email 2.48.1.502.g6dc24dfdaf-goog
Message-ID: <20250206181711.1902989-16-elver@google.com>
Subject: [PATCH RFC 15/24] rcu: Support Clang's capability analysis
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
 header.i=@google.com header.s=20230601 header.b=R0iwMCiZ;       spf=pass
 (google.com: domain of 37_ykzwukccakr1kxmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=37_ykZwUKCcAkr1kxmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--elver.bounces.google.com;
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

Improve the existing annotations to properly support Clang's capability
analysis.

The old annotations distinguished between RCU, RCU_BH, and RCU_SCHED.
However, it does not make sense to acquire rcu_read_lock_bh() after
rcu_read_lock() - annotate the _bh() and _sched() variants to also
acquire 'RCU', so that Clang (and also Sparse) can warn about it.

The above change also simplified introducing annotations, where it would
not matter if RCU, RCU_BH, or RCU_SCHED is acquired: through the
introduction of __rcu_guarded, we can use Clang's capability analysis to
warn if a pointer is dereferenced without any of the RCU locks held, or
updated without the appropriate helpers.

The primitives rcu_assign_pointer() and friends are wrapped with
capability_unsafe(), which enforces using them to update RCU-protected
pointers marked with __rcu_guarded.

Signed-off-by: Marco Elver <elver@google.com>
---
 .../dev-tools/capability-analysis.rst         |  2 +-
 include/linux/cleanup.h                       |  4 +
 include/linux/rcupdate.h                      | 73 +++++++++++++------
 lib/test_capability-analysis.c                | 68 +++++++++++++++++
 4 files changed, 123 insertions(+), 24 deletions(-)

diff --git a/Documentation/dev-tools/capability-analysis.rst b/Documentation/dev-tools/capability-analysis.rst
index a34dfe7b0b09..73dd28a23b11 100644
--- a/Documentation/dev-tools/capability-analysis.rst
+++ b/Documentation/dev-tools/capability-analysis.rst
@@ -86,7 +86,7 @@ Supported Kernel Primitives
 
 Currently the following synchronization primitives are supported:
 `raw_spinlock_t`, `spinlock_t`, `rwlock_t`, `mutex`, `seqlock_t`,
-`bit_spinlock`.
+`bit_spinlock`, RCU.
 
 For capabilities with an initialization function (e.g., `spin_lock_init()`),
 calling this function on the capability instance before initializing any
diff --git a/include/linux/cleanup.h b/include/linux/cleanup.h
index 93a166549add..7d70d308357a 100644
--- a/include/linux/cleanup.h
+++ b/include/linux/cleanup.h
@@ -404,6 +404,10 @@ static inline class_##_name##_t class_##_name##_constructor(void)	\
 	return _t;							\
 }
 
+#define DECLARE_LOCK_GUARD_0_ATTRS(_name, _lock, _unlock)		\
+static inline class_##_name##_t class_##_name##_constructor(void) _lock;\
+static inline void class_##_name##_destructor(class_##_name##_t *_T) _unlock
+
 #define DEFINE_LOCK_GUARD_1(_name, _type, _lock, _unlock, ...)		\
 __DEFINE_CLASS_IS_CONDITIONAL(_name, false);				\
 __DEFINE_UNLOCK_GUARD(_name, _type, _unlock, __VA_ARGS__)		\
diff --git a/include/linux/rcupdate.h b/include/linux/rcupdate.h
index 48e5c03df1dd..ee68095ba9f0 100644
--- a/include/linux/rcupdate.h
+++ b/include/linux/rcupdate.h
@@ -31,6 +31,16 @@
 #include <asm/processor.h>
 #include <linux/context_tracking_irq.h>
 
+token_capability(RCU);
+token_capability_instance(RCU, RCU_SCHED);
+token_capability_instance(RCU, RCU_BH);
+
+/*
+ * A convenience macro that can be used for RCU-protected globals or struct
+ * members; adds type qualifier __rcu, and also enforces __var_guarded_by(RCU).
+ */
+#define __rcu_guarded __rcu __var_guarded_by(RCU)
+
 #define ULONG_CMP_GE(a, b)	(ULONG_MAX / 2 >= (a) - (b))
 #define ULONG_CMP_LT(a, b)	(ULONG_MAX / 2 < (a) - (b))
 
@@ -431,7 +441,8 @@ static inline void rcu_preempt_sleep_check(void) { }
 
 // See RCU_LOCKDEP_WARN() for an explanation of the double call to
 // debug_lockdep_rcu_enabled().
-static inline bool lockdep_assert_rcu_helper(bool c)
+static inline bool lockdep_assert_rcu_helper(bool c, const struct __capability_RCU *cap)
+	__asserts_shared_cap(RCU) __asserts_shared_cap(cap)
 {
 	return debug_lockdep_rcu_enabled() &&
 	       (c || !rcu_is_watching() || !rcu_lockdep_current_cpu_online()) &&
@@ -444,7 +455,7 @@ static inline bool lockdep_assert_rcu_helper(bool c)
  * Splats if lockdep is enabled and there is no rcu_read_lock() in effect.
  */
 #define lockdep_assert_in_rcu_read_lock() \
-	WARN_ON_ONCE(lockdep_assert_rcu_helper(!lock_is_held(&rcu_lock_map)))
+	WARN_ON_ONCE(lockdep_assert_rcu_helper(!lock_is_held(&rcu_lock_map), RCU))
 
 /**
  * lockdep_assert_in_rcu_read_lock_bh - WARN if not protected by rcu_read_lock_bh()
@@ -454,7 +465,7 @@ static inline bool lockdep_assert_rcu_helper(bool c)
  * actual rcu_read_lock_bh() is required.
  */
 #define lockdep_assert_in_rcu_read_lock_bh() \
-	WARN_ON_ONCE(lockdep_assert_rcu_helper(!lock_is_held(&rcu_bh_lock_map)))
+	WARN_ON_ONCE(lockdep_assert_rcu_helper(!lock_is_held(&rcu_bh_lock_map), RCU_BH))
 
 /**
  * lockdep_assert_in_rcu_read_lock_sched - WARN if not protected by rcu_read_lock_sched()
@@ -464,7 +475,7 @@ static inline bool lockdep_assert_rcu_helper(bool c)
  * instead an actual rcu_read_lock_sched() is required.
  */
 #define lockdep_assert_in_rcu_read_lock_sched() \
-	WARN_ON_ONCE(lockdep_assert_rcu_helper(!lock_is_held(&rcu_sched_lock_map)))
+	WARN_ON_ONCE(lockdep_assert_rcu_helper(!lock_is_held(&rcu_sched_lock_map), RCU_SCHED))
 
 /**
  * lockdep_assert_in_rcu_reader - WARN if not within some type of RCU reader
@@ -482,17 +493,17 @@ static inline bool lockdep_assert_rcu_helper(bool c)
 	WARN_ON_ONCE(lockdep_assert_rcu_helper(!lock_is_held(&rcu_lock_map) &&			\
 					       !lock_is_held(&rcu_bh_lock_map) &&		\
 					       !lock_is_held(&rcu_sched_lock_map) &&		\
-					       preemptible()))
+					       preemptible(), RCU))
 
 #else /* #ifdef CONFIG_PROVE_RCU */
 
 #define RCU_LOCKDEP_WARN(c, s) do { } while (0 && (c))
 #define rcu_sleep_check() do { } while (0)
 
-#define lockdep_assert_in_rcu_read_lock() do { } while (0)
-#define lockdep_assert_in_rcu_read_lock_bh() do { } while (0)
-#define lockdep_assert_in_rcu_read_lock_sched() do { } while (0)
-#define lockdep_assert_in_rcu_reader() do { } while (0)
+#define lockdep_assert_in_rcu_read_lock() __assert_shared_cap(RCU)
+#define lockdep_assert_in_rcu_read_lock_bh() __assert_shared_cap(RCU_BH)
+#define lockdep_assert_in_rcu_read_lock_sched() __assert_shared_cap(RCU_SCHED)
+#define lockdep_assert_in_rcu_reader() __assert_shared_cap(RCU)
 
 #endif /* #else #ifdef CONFIG_PROVE_RCU */
 
@@ -512,11 +523,11 @@ static inline bool lockdep_assert_rcu_helper(bool c)
 #endif /* #else #ifdef __CHECKER__ */
 
 #define __unrcu_pointer(p, local)					\
-({									\
+capability_unsafe(							\
 	typeof(*p) *local = (typeof(*p) *__force)(p);			\
 	rcu_check_sparse(p, __rcu);					\
 	((typeof(*p) __force __kernel *)(local)); 			\
-})
+)
 /**
  * unrcu_pointer - mark a pointer as not being RCU protected
  * @p: pointer needing to lose its __rcu property
@@ -592,7 +603,7 @@ static inline bool lockdep_assert_rcu_helper(bool c)
  * other macros that it invokes.
  */
 #define rcu_assign_pointer(p, v)					      \
-do {									      \
+capability_unsafe(							      \
 	uintptr_t _r_a_p__v = (uintptr_t)(v);				      \
 	rcu_check_sparse(p, __rcu);					      \
 									      \
@@ -600,7 +611,7 @@ do {									      \
 		WRITE_ONCE((p), (typeof(p))(_r_a_p__v));		      \
 	else								      \
 		smp_store_release(&p, RCU_INITIALIZER((typeof(p))_r_a_p__v)); \
-} while (0)
+)
 
 /**
  * rcu_replace_pointer() - replace an RCU pointer, returning its old value
@@ -843,9 +854,10 @@ do {									      \
  * only when acquiring spinlocks that are subject to priority inheritance.
  */
 static __always_inline void rcu_read_lock(void)
+	__acquires_shared(RCU)
 {
 	__rcu_read_lock();
-	__acquire(RCU);
+	__acquire_shared(RCU);
 	rcu_lock_acquire(&rcu_lock_map);
 	RCU_LOCKDEP_WARN(!rcu_is_watching(),
 			 "rcu_read_lock() used illegally while idle");
@@ -874,11 +886,12 @@ static __always_inline void rcu_read_lock(void)
  * See rcu_read_lock() for more information.
  */
 static inline void rcu_read_unlock(void)
+	__releases_shared(RCU)
 {
 	RCU_LOCKDEP_WARN(!rcu_is_watching(),
 			 "rcu_read_unlock() used illegally while idle");
 	rcu_lock_release(&rcu_lock_map); /* Keep acq info for rls diags. */
-	__release(RCU);
+	__release_shared(RCU);
 	__rcu_read_unlock();
 }
 
@@ -897,9 +910,11 @@ static inline void rcu_read_unlock(void)
  * was invoked from some other task.
  */
 static inline void rcu_read_lock_bh(void)
+	__acquires_shared(RCU) __acquires_shared(RCU_BH)
 {
 	local_bh_disable();
-	__acquire(RCU_BH);
+	__acquire_shared(RCU);
+	__acquire_shared(RCU_BH);
 	rcu_lock_acquire(&rcu_bh_lock_map);
 	RCU_LOCKDEP_WARN(!rcu_is_watching(),
 			 "rcu_read_lock_bh() used illegally while idle");
@@ -911,11 +926,13 @@ static inline void rcu_read_lock_bh(void)
  * See rcu_read_lock_bh() for more information.
  */
 static inline void rcu_read_unlock_bh(void)
+	__releases_shared(RCU) __releases_shared(RCU_BH)
 {
 	RCU_LOCKDEP_WARN(!rcu_is_watching(),
 			 "rcu_read_unlock_bh() used illegally while idle");
 	rcu_lock_release(&rcu_bh_lock_map);
-	__release(RCU_BH);
+	__release_shared(RCU_BH);
+	__release_shared(RCU);
 	local_bh_enable();
 }
 
@@ -935,9 +952,11 @@ static inline void rcu_read_unlock_bh(void)
  * rcu_read_lock_sched() was invoked from an NMI handler.
  */
 static inline void rcu_read_lock_sched(void)
+	__acquires_shared(RCU) __acquires_shared(RCU_SCHED)
 {
 	preempt_disable();
-	__acquire(RCU_SCHED);
+	__acquire_shared(RCU);
+	__acquire_shared(RCU_SCHED);
 	rcu_lock_acquire(&rcu_sched_lock_map);
 	RCU_LOCKDEP_WARN(!rcu_is_watching(),
 			 "rcu_read_lock_sched() used illegally while idle");
@@ -945,9 +964,11 @@ static inline void rcu_read_lock_sched(void)
 
 /* Used by lockdep and tracing: cannot be traced, cannot call lockdep. */
 static inline notrace void rcu_read_lock_sched_notrace(void)
+	__acquires_shared(RCU) __acquires_shared(RCU_SCHED)
 {
 	preempt_disable_notrace();
-	__acquire(RCU_SCHED);
+	__acquire_shared(RCU);
+	__acquire_shared(RCU_SCHED);
 }
 
 /**
@@ -956,18 +977,22 @@ static inline notrace void rcu_read_lock_sched_notrace(void)
  * See rcu_read_lock_sched() for more information.
  */
 static inline void rcu_read_unlock_sched(void)
+	__releases_shared(RCU) __releases_shared(RCU_SCHED)
 {
 	RCU_LOCKDEP_WARN(!rcu_is_watching(),
 			 "rcu_read_unlock_sched() used illegally while idle");
 	rcu_lock_release(&rcu_sched_lock_map);
-	__release(RCU_SCHED);
+	__release_shared(RCU_SCHED);
+	__release_shared(RCU);
 	preempt_enable();
 }
 
 /* Used by lockdep and tracing: cannot be traced, cannot call lockdep. */
 static inline notrace void rcu_read_unlock_sched_notrace(void)
+	__releases_shared(RCU) __releases_shared(RCU_SCHED)
 {
-	__release(RCU_SCHED);
+	__release_shared(RCU_SCHED);
+	__release_shared(RCU);
 	preempt_enable_notrace();
 }
 
@@ -1010,10 +1035,10 @@ static inline notrace void rcu_read_unlock_sched_notrace(void)
  * ordering guarantees for either the CPU or the compiler.
  */
 #define RCU_INIT_POINTER(p, v) \
-	do { \
+	capability_unsafe( \
 		rcu_check_sparse(p, __rcu); \
 		WRITE_ONCE(p, RCU_INITIALIZER(v)); \
-	} while (0)
+	)
 
 /**
  * RCU_POINTER_INITIALIZER() - statically initialize an RCU protected pointer
@@ -1172,4 +1197,6 @@ DEFINE_LOCK_GUARD_0(rcu,
 	} while (0),
 	rcu_read_unlock())
 
+DECLARE_LOCK_GUARD_0_ATTRS(rcu, __acquires_shared(RCU), __releases_shared(RCU));
+
 #endif /* __LINUX_RCUPDATE_H */
diff --git a/lib/test_capability-analysis.c b/lib/test_capability-analysis.c
index fc8dcad2a994..f5a1dda6ca38 100644
--- a/lib/test_capability-analysis.c
+++ b/lib/test_capability-analysis.c
@@ -7,6 +7,7 @@
 #include <linux/bit_spinlock.h>
 #include <linux/build_bug.h>
 #include <linux/mutex.h>
+#include <linux/rcupdate.h>
 #include <linux/seqlock.h>
 #include <linux/spinlock.h>
 
@@ -277,3 +278,70 @@ static void __used test_bit_spin_lock(struct test_bit_spinlock_data *d)
 		bit_spin_unlock(3, &d->bits);
 	}
 }
+
+/*
+ * Test that we can mark a variable guarded by RCU, and we can dereference and
+ * write to the pointer with RCU's primitives.
+ */
+struct test_rcu_data {
+	long __rcu_guarded *data;
+};
+
+static void __used test_rcu_guarded_reader(struct test_rcu_data *d)
+{
+	rcu_read_lock();
+	(void)rcu_dereference(d->data);
+	rcu_read_unlock();
+
+	rcu_read_lock_bh();
+	(void)rcu_dereference(d->data);
+	rcu_read_unlock_bh();
+
+	rcu_read_lock_sched();
+	(void)rcu_dereference(d->data);
+	rcu_read_unlock_sched();
+}
+
+static void __used test_rcu_guard(struct test_rcu_data *d)
+{
+	guard(rcu)();
+	(void)rcu_dereference(d->data);
+}
+
+static void __used test_rcu_guarded_updater(struct test_rcu_data *d)
+{
+	rcu_assign_pointer(d->data, NULL);
+	RCU_INIT_POINTER(d->data, NULL);
+	(void)unrcu_pointer(d->data);
+}
+
+static void wants_rcu_held(void)	__must_hold_shared(RCU)       { }
+static void wants_rcu_held_bh(void)	__must_hold_shared(RCU_BH)    { }
+static void wants_rcu_held_sched(void)	__must_hold_shared(RCU_SCHED) { }
+
+static void __used test_rcu_lock_variants(void)
+{
+	rcu_read_lock();
+	wants_rcu_held();
+	rcu_read_unlock();
+
+	rcu_read_lock_bh();
+	wants_rcu_held_bh();
+	rcu_read_unlock_bh();
+
+	rcu_read_lock_sched();
+	wants_rcu_held_sched();
+	rcu_read_unlock_sched();
+}
+
+static void __used test_rcu_assert_variants(void)
+{
+	lockdep_assert_in_rcu_read_lock();
+	wants_rcu_held();
+
+	lockdep_assert_in_rcu_read_lock_bh();
+	wants_rcu_held_bh();
+
+	lockdep_assert_in_rcu_read_lock_sched();
+	wants_rcu_held_sched();
+}
-- 
2.48.1.502.g6dc24dfdaf-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250206181711.1902989-16-elver%40google.com.
