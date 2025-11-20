Return-Path: <kasan-dev+bncBC7OBJGL2MHBBY677TEAMGQERXTGHDQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x338.google.com (mail-wm1-x338.google.com [IPv6:2a00:1450:4864:20::338])
	by mail.lfdr.de (Postfix) with ESMTPS id D87BEC74C39
	for <lists+kasan-dev@lfdr.de>; Thu, 20 Nov 2025 16:12:36 +0100 (CET)
Received: by mail-wm1-x338.google.com with SMTP id 5b1f17b1804b1-477964c22e0sf6874655e9.0
        for <lists+kasan-dev@lfdr.de>; Thu, 20 Nov 2025 07:12:36 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1763651556; cv=pass;
        d=google.com; s=arc-20240605;
        b=IgSnpzx2HSvGFT8uDMxxEh/1ixoFmSIyY6IwbVm8i+hID0MxfhuZg9OJJj+PyURYLA
         9q+HFTo2urvbhAQm4legE8vemW8XXwAhhu84cXt0iJeZ7DpuFwm3bLoBOFyOOcDzXXvy
         3lgZoAkt9IB/ZyPCf2UEEQeKK6RxqHqApxAs6QjjDi2qMarSQxLU7xUt5hS4NO5e++hU
         rj2sgEo8e2vXWR9HJOYYDnMoljSNuFmC7isyjAOuL3VvEPTMzHeKbnrsGimd5F1zg0Dt
         be6IVwrx7/+qd0d8LRIH4U8D18rylBATzBwlVa+TlHWP0TYCzLnJf5rAJK5sXeQyVrqS
         yfGQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=qqzMnJtEH9DJifBxitDr/Jzva7CeaOWXlokoI0kr854=;
        fh=NJdZ9Rj8AGRO2Onk7CJtg/iFQaXr0x0DOrHHJMBZzLs=;
        b=USDXWo6I2IEBj+WlQAr3AUJmpKaaepNQ/xUDEZiqmyU4YvvpE4Xd7RWf3bsDhUn3My
         HTLdmIFohr8w3yOSYSC1ILixFofTRHw1YVZ5eNCYnryAbpNW53A+uc/ivlKOfXshOv1L
         B9HVmT0fA/uDf2tTx/MAwvp9eIWS/t0QFyTcsebJGnhxUIHE7m+dCTv/6C4wioUufvs3
         +5VnnT+HxaZIcHR9+ZY7LNDJcmBX83q1UYIDvKpEgaCXQDDclGUD+gBmjoQN4G7NBQQo
         bNNFcq+T+uNkiXnIWWTRRjo9MbOBny/KvWM6Mxrwg7gcJLsWKkVQS6VM90S2ncewYLrK
         CFuQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=DsOM27tW;
       spf=pass (google.com: domain of 34c8faqukcq0ry8r4t11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=34C8faQUKCQ0ry8r4t11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1763651556; x=1764256356; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=qqzMnJtEH9DJifBxitDr/Jzva7CeaOWXlokoI0kr854=;
        b=OzeSHPHpK7MrriLNDDJMCFo6fwO8E0SG5pykIQ9HV20iq6yEF4h6uVOIC5CBXf7tpu
         DHGaEud8uYSZawVTa8yE2vv2/FROuGmCHE5XK6e7dcxhSZVf6e1OErD6tVSHBJRO9Qfp
         20IujTgKsv0N3BO6SDLqXCmJAH4sdeKXXHzDHK3qp1tOKShfB0AIt6SgwsoouimnWFtk
         SjA95B5PHWNkrJXeWb0C7JDuXNDCAiJR9rInkrvgoNnr2SV/tPPRE3FatcFOq0xAHKR0
         o9kHI2BUZHEJG00xG8KXntAmw+iLRzIYnqAyGCXFrsIcSJ1OI2luB7NrwN/ccNNOuLlg
         KoaQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1763651556; x=1764256356;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=qqzMnJtEH9DJifBxitDr/Jzva7CeaOWXlokoI0kr854=;
        b=cYvpSndaAC8LbZ2/ZTwJo0IPhBXGfEuvGPFPCtwn9wVK/2OKcaXFdHvPJWG5DZQdnP
         jYP7mp6qqKeZ9NIeIgvU7zQCvQLCkU4/7QIKDSbNl+AvUtjReBfj9pcW2rbqu2n8Ww7J
         p6e8PeYPr01NFeEmtq4cQrh2hQM3rlRz3VZBr/xCIhdsIwxpHZtbouxqoLLSNN8HMNG1
         PWjMb1VxaQf2+rERH//J98iU9lQTAtd3BwpjFbWoNqG520jfEzcm2SDk8o+uUyA+mE4u
         nd1w0DQ1LWahfNknCM9miagla6RKBb83lwNWcSm7xAUtQ/pUSb7kJPw6qu8KjzwzQy/z
         z03g==
X-Forwarded-Encrypted: i=2; AJvYcCW3MZA1G0mffmf5cwZYmasNWAvp3QJ9885flT4zyeYRX4fv4d2rcawp/l1vK43ysnUiO8iZ0A==@lfdr.de
X-Gm-Message-State: AOJu0YzhtZ8o00/KDXJZ3SbbEuO39XL1efcGRF1gY+WvVWrLqcBES0hN
	hOtlha77OXZViXBObI94h0eZXLzo9pDq3bfW9ELYeHqZ/0mddBfU4k0V
X-Google-Smtp-Source: AGHT+IE2mikSikemLoKj4++HBCMugX0vQb9cBj2VjK8fR4ywQ/kjDsAlU5Yqnj4zWZ0bxqYW4coZqQ==
X-Received: by 2002:a05:600c:2155:b0:475:de06:dbaf with SMTP id 5b1f17b1804b1-477b9efe351mr21350125e9.17.1763651556111;
        Thu, 20 Nov 2025 07:12:36 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+acT0Q/Sw7Kz8GbCxvR+qN49loOxR6Ryih1lv38rAGecA=="
Received: by 2002:a05:600c:1f13:b0:477:2205:db97 with SMTP id
 5b1f17b1804b1-477b6fcbee3ls6624605e9.0.-pod-prod-00-eu-canary; Thu, 20 Nov
 2025 07:12:33 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCX0NDxKqVSkcS55fzBFFY1cU9Qy77k9DiGUDqh/PJ7KxXS+peyL0n5ANsFxwT4Oir3zmvW3DeBmNh8=@googlegroups.com
X-Received: by 2002:a05:600c:1396:b0:475:ddad:c3a9 with SMTP id 5b1f17b1804b1-477b9ec3b5emr31048735e9.13.1763651553121;
        Thu, 20 Nov 2025 07:12:33 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1763651553; cv=none;
        d=google.com; s=arc-20240605;
        b=Clz9NWokqtR/3XtT254LT+g48KLQcypVjgZ0ukbUVZtFR6iy+ZX0hafG/RAAO6FUDG
         5ieggwJBhLTl83yH+lXBmj6QWbU0CBVmdIFfhYqIIzX08hnUxjC/ltoB67Y6H43iF0t3
         xB71hPq/t6pzH9kfnaQJzPME9/o9nFBm0k5Lo9L91MChGJ8OHx7r58v96QdiYLM5FjLm
         2JZC4JbDaoRoIoe1WuKGjN9V2wgZtNUYf2h8SXfgb5+mebtdOC0Q9ZrZrmIBLn9CWb3l
         ID2VPLKbXez4XQobU5vOHQgGTquLCu9GDCP6I/sxxLPG5zEU7SaXTx7aB+L1Cn/zYQH2
         Hngg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=Ln7UVfCWiCp9IlXxOO2xIWRuRprEYh3pWr1qQfgYpRY=;
        fh=b9SCRKttgPrydkgES/mR+nLCtOrjEgsYLe2t8uzJGw8=;
        b=KfM47CU8wY/ehNUN93d+D6Ps4m10ZwOfgPKOGSY0P9i2A8itbZNrfbeo9s1o9BytsQ
         chKtazELXLhWvNhc/Ha9f5WJi93SPkdQVa/PL/ydqPbxlfC2Iw23SJhn0izJUXhQoPAn
         3IGIqMNWVnuUT7/YgdUtFM6HUkM/IgL+Twnk3XhomnJm++AH40pRPJFn2ycectrDkL/5
         X3r1Sehx9eFdOiZdCreyXLursCzNVl0eG4E1M9f9rT4mszUmzHVR1cNqK0AJ3r09Jd8U
         OgGp9LRx392AsW3ndWdkhRQHFMG/ScrjHpRwOzDD9XPlbWos9u8blTCbIj/AiCBwPIH8
         PvDQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=DsOM27tW;
       spf=pass (google.com: domain of 34c8faqukcq0ry8r4t11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=34C8faQUKCQ0ry8r4t11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x44a.google.com (mail-wr1-x44a.google.com. [2a00:1450:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-477a9739730si496965e9.1.2025.11.20.07.12.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 20 Nov 2025 07:12:33 -0800 (PST)
Received-SPF: pass (google.com: domain of 34c8faqukcq0ry8r4t11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) client-ip=2a00:1450:4864:20::44a;
Received: by mail-wr1-x44a.google.com with SMTP id ffacd0b85a97d-429cbd8299cso446887f8f.1
        for <kasan-dev@googlegroups.com>; Thu, 20 Nov 2025 07:12:32 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCVcBpHuRR3uJhiEEFyBVkTPimF51EMmMxVUxeNaGov3+ElI5rDxwWXMtXVHBzUcANL2AWgcLnbRZMA=@googlegroups.com
X-Received: from wrs17.prod.google.com ([2002:a05:6000:651:b0:42b:328d:1994])
 (user=elver job=prod-delivery.src-stubby-dispatcher) by 2002:a05:6000:2c05:b0:42b:4267:83d5
 with SMTP id ffacd0b85a97d-42cb9a11c12mr2935283f8f.8.1763651552168; Thu, 20
 Nov 2025 07:12:32 -0800 (PST)
Date: Thu, 20 Nov 2025 16:09:39 +0100
In-Reply-To: <20251120151033.3840508-7-elver@google.com>
Mime-Version: 1.0
References: <20251120145835.3833031-2-elver@google.com> <20251120151033.3840508-7-elver@google.com>
X-Mailer: git-send-email 2.52.0.rc1.455.g30608eb744-goog
Message-ID: <20251120151033.3840508-15-elver@google.com>
Subject: [PATCH v4 14/35] rcu: Support Clang's context analysis
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
 header.i=@google.com header.s=20230601 header.b=DsOM27tW;       spf=pass
 (google.com: domain of 34c8faqukcq0ry8r4t11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=34C8faQUKCQ0ry8r4t11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--elver.bounces.google.com;
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

Improve the existing annotations to properly support Clang's context
analysis.

The old annotations distinguished between RCU, RCU_BH, and RCU_SCHED;
however, to more easily be able to express that "hold the RCU read lock"
without caring if the normal, _bh(), or _sched() variant was used we'd
have to remove the distinction of the latter variants: change the _bh()
and _sched() variants to also acquire "RCU".

When (and if) we introduce context guards to denote more generally that
"IRQ", "BH", "PREEMPT" contexts are disabled, it would make sense to
acquire these instead of RCU_BH and RCU_SCHED respectively.

The above change also simplified introducing __guarded_by support, where
only the "RCU" context guard needs to be held: introduce __rcu_guarded,
where Clang's context analysis warns if a pointer is dereferenced
without any of the RCU locks held, or updated without the appropriate
helpers.

The primitives rcu_assign_pointer() and friends are wrapped with
context_unsafe(), which enforces using them to update RCU-protected
pointers marked with __rcu_guarded.

Signed-off-by: Marco Elver <elver@google.com>
---
v3:
* Properly support reentrancy via new compiler support.

v2:
* Reword commit message and point out reentrancy caveat.
---
 Documentation/dev-tools/context-analysis.rst |  2 +-
 include/linux/rcupdate.h                     | 77 ++++++++++++------
 lib/test_context-analysis.c                  | 85 ++++++++++++++++++++
 3 files changed, 139 insertions(+), 25 deletions(-)

diff --git a/Documentation/dev-tools/context-analysis.rst b/Documentation/dev-tools/context-analysis.rst
index a3d925ce2df4..05164804a92a 100644
--- a/Documentation/dev-tools/context-analysis.rst
+++ b/Documentation/dev-tools/context-analysis.rst
@@ -81,7 +81,7 @@ Supported Kernel Primitives
 
 Currently the following synchronization primitives are supported:
 `raw_spinlock_t`, `spinlock_t`, `rwlock_t`, `mutex`, `seqlock_t`,
-`bit_spinlock`.
+`bit_spinlock`, RCU.
 
 For context guards with an initialization function (e.g., `spin_lock_init()`),
 calling this function before initializing any guarded members or globals
diff --git a/include/linux/rcupdate.h b/include/linux/rcupdate.h
index c5b30054cd01..5cddb9019a99 100644
--- a/include/linux/rcupdate.h
+++ b/include/linux/rcupdate.h
@@ -31,6 +31,16 @@
 #include <asm/processor.h>
 #include <linux/context_tracking_irq.h>
 
+token_context_guard(RCU, __reentrant_ctx_guard);
+token_context_guard_instance(RCU, RCU_SCHED);
+token_context_guard_instance(RCU, RCU_BH);
+
+/*
+ * A convenience macro that can be used for RCU-protected globals or struct
+ * members; adds type qualifier __rcu, and also enforces __guarded_by(RCU).
+ */
+#define __rcu_guarded __rcu __guarded_by(RCU)
+
 #define ULONG_CMP_GE(a, b)	(ULONG_MAX / 2 >= (a) - (b))
 #define ULONG_CMP_LT(a, b)	(ULONG_MAX / 2 < (a) - (b))
 
@@ -425,7 +435,8 @@ static inline void rcu_preempt_sleep_check(void) { }
 
 // See RCU_LOCKDEP_WARN() for an explanation of the double call to
 // debug_lockdep_rcu_enabled().
-static inline bool lockdep_assert_rcu_helper(bool c)
+static inline bool lockdep_assert_rcu_helper(bool c, const struct __ctx_guard_RCU *ctx)
+	__assumes_shared_ctx_guard(RCU) __assumes_shared_ctx_guard(ctx)
 {
 	return debug_lockdep_rcu_enabled() &&
 	       (c || !rcu_is_watching() || !rcu_lockdep_current_cpu_online()) &&
@@ -438,7 +449,7 @@ static inline bool lockdep_assert_rcu_helper(bool c)
  * Splats if lockdep is enabled and there is no rcu_read_lock() in effect.
  */
 #define lockdep_assert_in_rcu_read_lock() \
-	WARN_ON_ONCE(lockdep_assert_rcu_helper(!lock_is_held(&rcu_lock_map)))
+	WARN_ON_ONCE(lockdep_assert_rcu_helper(!lock_is_held(&rcu_lock_map), RCU))
 
 /**
  * lockdep_assert_in_rcu_read_lock_bh - WARN if not protected by rcu_read_lock_bh()
@@ -448,7 +459,7 @@ static inline bool lockdep_assert_rcu_helper(bool c)
  * actual rcu_read_lock_bh() is required.
  */
 #define lockdep_assert_in_rcu_read_lock_bh() \
-	WARN_ON_ONCE(lockdep_assert_rcu_helper(!lock_is_held(&rcu_bh_lock_map)))
+	WARN_ON_ONCE(lockdep_assert_rcu_helper(!lock_is_held(&rcu_bh_lock_map), RCU_BH))
 
 /**
  * lockdep_assert_in_rcu_read_lock_sched - WARN if not protected by rcu_read_lock_sched()
@@ -458,7 +469,7 @@ static inline bool lockdep_assert_rcu_helper(bool c)
  * instead an actual rcu_read_lock_sched() is required.
  */
 #define lockdep_assert_in_rcu_read_lock_sched() \
-	WARN_ON_ONCE(lockdep_assert_rcu_helper(!lock_is_held(&rcu_sched_lock_map)))
+	WARN_ON_ONCE(lockdep_assert_rcu_helper(!lock_is_held(&rcu_sched_lock_map), RCU_SCHED))
 
 /**
  * lockdep_assert_in_rcu_reader - WARN if not within some type of RCU reader
@@ -476,17 +487,17 @@ static inline bool lockdep_assert_rcu_helper(bool c)
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
+#define lockdep_assert_in_rcu_read_lock() __assume_shared_ctx_guard(RCU)
+#define lockdep_assert_in_rcu_read_lock_bh() __assume_shared_ctx_guard(RCU_BH)
+#define lockdep_assert_in_rcu_read_lock_sched() __assume_shared_ctx_guard(RCU_SCHED)
+#define lockdep_assert_in_rcu_reader() __assume_shared_ctx_guard(RCU)
 
 #endif /* #else #ifdef CONFIG_PROVE_RCU */
 
@@ -506,11 +517,11 @@ static inline bool lockdep_assert_rcu_helper(bool c)
 #endif /* #else #ifdef __CHECKER__ */
 
 #define __unrcu_pointer(p, local)					\
-({									\
+context_unsafe(								\
 	typeof(*p) *local = (typeof(*p) *__force)(p);			\
 	rcu_check_sparse(p, __rcu);					\
-	((typeof(*p) __force __kernel *)(local)); 			\
-})
+	((typeof(*p) __force __kernel *)(local)) 			\
+)
 /**
  * unrcu_pointer - mark a pointer as not being RCU protected
  * @p: pointer needing to lose its __rcu property
@@ -586,7 +597,7 @@ static inline bool lockdep_assert_rcu_helper(bool c)
  * other macros that it invokes.
  */
 #define rcu_assign_pointer(p, v)					      \
-do {									      \
+context_unsafe(							      \
 	uintptr_t _r_a_p__v = (uintptr_t)(v);				      \
 	rcu_check_sparse(p, __rcu);					      \
 									      \
@@ -594,7 +605,7 @@ do {									      \
 		WRITE_ONCE((p), (typeof(p))(_r_a_p__v));		      \
 	else								      \
 		smp_store_release(&p, RCU_INITIALIZER((typeof(p))_r_a_p__v)); \
-} while (0)
+)
 
 /**
  * rcu_replace_pointer() - replace an RCU pointer, returning its old value
@@ -861,9 +872,10 @@ do {									      \
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
@@ -891,11 +903,12 @@ static __always_inline void rcu_read_lock(void)
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
 
@@ -914,9 +927,11 @@ static inline void rcu_read_unlock(void)
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
@@ -928,11 +943,13 @@ static inline void rcu_read_lock_bh(void)
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
 
@@ -952,9 +969,11 @@ static inline void rcu_read_unlock_bh(void)
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
@@ -962,9 +981,11 @@ static inline void rcu_read_lock_sched(void)
 
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
@@ -973,22 +994,27 @@ static inline notrace void rcu_read_lock_sched_notrace(void)
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
 
 static __always_inline void rcu_read_lock_dont_migrate(void)
+	__acquires_shared(RCU)
 {
 	if (IS_ENABLED(CONFIG_PREEMPT_RCU))
 		migrate_disable();
@@ -996,6 +1022,7 @@ static __always_inline void rcu_read_lock_dont_migrate(void)
 }
 
 static inline void rcu_read_unlock_migrate(void)
+	__releases_shared(RCU)
 {
 	rcu_read_unlock();
 	if (IS_ENABLED(CONFIG_PREEMPT_RCU))
@@ -1041,10 +1068,10 @@ static inline void rcu_read_unlock_migrate(void)
  * ordering guarantees for either the CPU or the compiler.
  */
 #define RCU_INIT_POINTER(p, v) \
-	do { \
+	context_unsafe( \
 		rcu_check_sparse(p, __rcu); \
 		WRITE_ONCE(p, RCU_INITIALIZER(v)); \
-	} while (0)
+	)
 
 /**
  * RCU_POINTER_INITIALIZER() - statically initialize an RCU protected pointer
@@ -1206,4 +1233,6 @@ DEFINE_LOCK_GUARD_0(rcu,
 	} while (0),
 	rcu_read_unlock())
 
+DECLARE_LOCK_GUARD_0_ATTRS(rcu, __acquires_shared(RCU), __releases_shared(RCU))
+
 #endif /* __LINUX_RCUPDATE_H */
diff --git a/lib/test_context-analysis.c b/lib/test_context-analysis.c
index 77e599a9281b..f18b7252646d 100644
--- a/lib/test_context-analysis.c
+++ b/lib/test_context-analysis.c
@@ -7,6 +7,7 @@
 #include <linux/bit_spinlock.h>
 #include <linux/build_bug.h>
 #include <linux/mutex.h>
+#include <linux/rcupdate.h>
 #include <linux/seqlock.h>
 #include <linux/spinlock.h>
 
@@ -277,3 +278,87 @@ static void __used test_bit_spin_lock(struct test_bit_spinlock_data *d)
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
+static void __used test_rcu_lock_reentrant(void)
+{
+	rcu_read_lock();
+	rcu_read_lock();
+	rcu_read_lock_bh();
+	rcu_read_lock_bh();
+	rcu_read_lock_sched();
+	rcu_read_lock_sched();
+
+	rcu_read_unlock_sched();
+	rcu_read_unlock_sched();
+	rcu_read_unlock_bh();
+	rcu_read_unlock_bh();
+	rcu_read_unlock();
+	rcu_read_unlock();
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
2.52.0.rc1.455.g30608eb744-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251120151033.3840508-15-elver%40google.com.
