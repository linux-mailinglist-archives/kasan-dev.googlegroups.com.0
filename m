Return-Path: <kasan-dev+bncBC7OBJGL2MHBBUHGSXFAMGQEA6EOTUA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x138.google.com (mail-lf1-x138.google.com [IPv6:2a00:1450:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id 9290CCD0965
	for <lists+kasan-dev@lfdr.de>; Fri, 19 Dec 2025 16:46:25 +0100 (CET)
Received: by mail-lf1-x138.google.com with SMTP id 2adb3069b0e04-597d5b80d55sf2483631e87.2
        for <lists+kasan-dev@lfdr.de>; Fri, 19 Dec 2025 07:46:25 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1766159185; cv=pass;
        d=google.com; s=arc-20240605;
        b=RE3BDkR/554Jynrb1OT20QYarv2tEK57PjnKEiSwHjHnwkHaADBZuD6QaU+fxHsybZ
         MafSjEokdJKmJa1M0teKofmnpkNSqrO1L02+HJlbgrG/DIKLtBA5nZNHvyJkFSZe6B4J
         dFMCec2zw/3pjL0yPyw3ccD53odpASZr4R+RFoFhJ2EK4pu6TXUivhJvKjmJukrGTT8+
         /qPyd8fhW0fJ9CYX45amVfdOIk3jpl5Xz6vri+jf7Wanbc66Ha8ssffvv/v9MFcENdew
         gtg0SqunYzHXD5EC4PHMHLWTJkCrV80SvYZQarYlqRtrz4wyj5A15Zgpc2ycX3vDiQA+
         QVxw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=i7pEROCnZDupSh5npGss0l/wGpX1BMNV2OnJKSjeesc=;
        fh=kDZY87oDNrrEgEfDG4AOKH2frJryzkY5oDAUg2AfPPY=;
        b=k6Pxxzb15/MTsiO8TL9ABVLFrPKuF3sERMJCsCJarVy2v5IIf2ML9ZwrXG3OBI3e/s
         EOz8U6M0JDG0HOJ0iAVi06vKpM8FV0WBsLTIvcbuaIX6+FrcR+ZdtPuRO8tuWqMT8vHN
         62TsgJJB/uFtLW28xP3CV3DpL6fVk3tHHFAg3FVsxUMbdnoPD3A6/VVcfZ4frDmd+ovG
         ogFEQyO87PMvFStCg0fI6Ov08SKVzHtEMmETN60ZZbWI32gtGHs8r04MTx/ifxIHVmwm
         VO0W4TCIivSXmUM+YcTMWOrd3TjsqxvWWNXgJ4LH3C9UqPaESfUniHQEsRT+pDFWZGIh
         yJQw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=hHUJJAHa;
       spf=pass (google.com: domain of 3thnfaqukczk7eo7k9hh9e7.5hfd3l3g-67o9hh9e79khnil.5hf@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3THNFaQUKCZk7EO7K9HH9E7.5HFD3L3G-67O9HH9E79KHNIL.5HF@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1766159185; x=1766763985; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=i7pEROCnZDupSh5npGss0l/wGpX1BMNV2OnJKSjeesc=;
        b=SL32rA4tQ/1vtQzT2qe0xtCzQKabApJ9788G6AIuosaLynxhcwphP9tnfEisuSUBSA
         sAymleCMDKTaNz/lyy0BYGTIGjbLoKJsATH4SH2zgh+mGwA1uNEY5RuvEtsAKbY6LYmZ
         OCMA+ZDK+VLyi4C2rcbqKm8Al3EZM3Bn5ZTmjDAtMccGwywUlk9RcMhmubdnqsP0ThV3
         MCUEC9n9lZGc7pi8mr/2oLKswm9HRmEnNTG3Rxykaq4YDdFaO//dXv7bohjgL8f3cmfh
         m7urNxE5r8vlP8xzcb3Fre100cmYnld/fm8mqlb3XJmV0YcRiQ3ZQjMnSlaEXQeKg6mz
         /VoA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1766159185; x=1766763985;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=i7pEROCnZDupSh5npGss0l/wGpX1BMNV2OnJKSjeesc=;
        b=szkgUbajrb0HTPylc2PLv4z2Z7t97QMDcgCAYUNsVaGBs/mwPZ8duQ9Yg7ZJ7WTOMt
         fND8+GmSBaD7vMG85cu0sG8UFwPWCnI04+7Y2trEpGnLmQ82xNSQCpampwV0dgNDvQCW
         oMgRIjWN3DMk/9zDy28nYpnsDRmm8NBC0xmE6vuZRIvF2GwhW3px2GEuOS69kVTjP0zT
         wFBNA3IToVzaPHk0ETh//dvFrS6PVNb2I6vVNCadpq0ua/DrVg0Ll49BjLCS4Qr8wgu6
         EIhmxymTX75RpG/q9TnTPRVR+CR5VOYqw8uZe/omj8o858W74VPBqsKKZoAZkvPFhoql
         sq3w==
X-Forwarded-Encrypted: i=2; AJvYcCV9gA4thgJHwRO/arHGSr20V24djp9bcIGWjWllG4/tDLLS1/HXTmFVYPPT8IkXpDOA85s7aQ==@lfdr.de
X-Gm-Message-State: AOJu0YxIVEMdaxPtObEFItJccvmM17hiTvknnAmlK705XUxXVqnbSs08
	qKl0FKSCO1xNKDwbAvXiy1kwuRq5t/1bCQR6qmI6j0RN7U88FFdNx5Pw
X-Google-Smtp-Source: AGHT+IGJpNj+4ZpL1/Woo8a/DFGLsnGZwdIBZLZARqSJOQj8E/E4qP9lQek0drNKaXFYcL97mXlQnQ==
X-Received: by 2002:a05:6512:3d0b:b0:595:9d86:2cc7 with SMTP id 2adb3069b0e04-59a17d442c5mr1680951e87.39.1766159184706;
        Fri, 19 Dec 2025 07:46:24 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWZb+EXwO/RUvGnM+TTiSOfjR+E09iklKGptXRgVLu7Ndw=="
Received: by 2002:a05:6512:3f26:b0:598:efe5:2880 with SMTP id
 2adb3069b0e04-598fa38b6a3ls2508427e87.0.-pod-prod-03-eu; Fri, 19 Dec 2025
 07:46:21 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCX8rN6gurkBo5SyP6t3ju7WBXm9nU1QIfDLVEGLQ+K/oUn8UaEdejIPdKIaVCdjF3iDhdsDVe5rX7s=@googlegroups.com
X-Received: by 2002:a05:6512:b90:b0:594:2654:5e3a with SMTP id 2adb3069b0e04-59a17d0e9c8mr1137619e87.18.1766159181618;
        Fri, 19 Dec 2025 07:46:21 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1766159181; cv=none;
        d=google.com; s=arc-20240605;
        b=fbz2fLXpAe/4f8ZC3hngAaX7QDus68XQb1v99LFA9tPYqHdw2dv1ILEAK+ktH9onch
         4pLmJ0Bo578dewilDdL5mEp8uAe6/v5hdW79GvDN8d8GtgIeQ4zFhtVmf/SGERr0ESrA
         X8VeZSXQ1z5ubov8vGQ6mNbTvqLakzHBsUmbexqLL0GjfGrDBQwVfPXbQdywlrBETiYu
         sb+DNkYst3gFsGBUIT0xjpoXPLxelV4a4FKPfHB/ZRWeKmKPZuJuEgnh/AxKdBWdtdxD
         3c9nMwDohouQCvam/6prykuW2buSS4eUFImUOYY98W/Ms0Pku8NCrJau+GmTG9cj9TQa
         0o2A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=+jYEguITBPTs5G6jcojPovTyLNy31gBuOV4hxWkZ9us=;
        fh=koyTIxM7acB2/elNUH/BmqQkM76GjKrPYVCsVPsIs6s=;
        b=X5lS8McJPwvhMifIY6fFgbQc/hjcoCvU1lH0WOtjqYfIZ074XymB2VbMk+xY2vR6x6
         ONWsZmb+qepR0aeXVrdfNa5/Jy7sZ0Nu3Yn5NcL0My+fFsuoUTxRzXWSsYGxfLU485+n
         /KoTYIdyPPqlj6YPDBZWYsGdoggzqMXqh4qufYwQMfCmvld8SwQUgezoizL5oN4b21Xq
         +L96dFm/dr781fqFEUeqnhsK/JP+tW3xOQghfWHii99aXKyCgu0thy1E/qas3idrdj6/
         Mals/Lq7TjwF0gBJDVhCxCoXnr2B/rI02X8pFAQ5Vdqeq5suuH9Gt07tAVt/VvQWqCeD
         2aIQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=hHUJJAHa;
       spf=pass (google.com: domain of 3thnfaqukczk7eo7k9hh9e7.5hfd3l3g-67o9hh9e79khnil.5hf@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3THNFaQUKCZk7EO7K9HH9E7.5HFD3L3G-67O9HH9E79KHNIL.5HF@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x34a.google.com (mail-wm1-x34a.google.com. [2a00:1450:4864:20::34a])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-59a1860cf52si63627e87.3.2025.12.19.07.46.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 19 Dec 2025 07:46:21 -0800 (PST)
Received-SPF: pass (google.com: domain of 3thnfaqukczk7eo7k9hh9e7.5hfd3l3g-67o9hh9e79khnil.5hf@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) client-ip=2a00:1450:4864:20::34a;
Received: by mail-wm1-x34a.google.com with SMTP id 5b1f17b1804b1-4775f51ce36so17568725e9.1
        for <kasan-dev@googlegroups.com>; Fri, 19 Dec 2025 07:46:21 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCWCAwNv3rDRFTGnQYYV66ry/weQRvGUJzYWXEDG1E20yMzaXVngZEIG39zUu28YZVzvyGQGrxPzCu8=@googlegroups.com
X-Received: from wma9.prod.google.com ([2002:a05:600c:8909:b0:477:a0cb:7165])
 (user=elver job=prod-delivery.src-stubby-dispatcher) by 2002:a05:600c:5487:b0:47b:da85:b9f3
 with SMTP id 5b1f17b1804b1-47d195a72c0mr32797025e9.23.1766159180751; Fri, 19
 Dec 2025 07:46:20 -0800 (PST)
Date: Fri, 19 Dec 2025 16:40:03 +0100
In-Reply-To: <20251219154418.3592607-1-elver@google.com>
Mime-Version: 1.0
References: <20251219154418.3592607-1-elver@google.com>
X-Mailer: git-send-email 2.52.0.322.g1dd061c0dc-goog
Message-ID: <20251219154418.3592607-15-elver@google.com>
Subject: [PATCH v5 14/36] rcu: Support Clang's context analysis
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
 header.i=@google.com header.s=20230601 header.b=hHUJJAHa;       spf=pass
 (google.com: domain of 3thnfaqukczk7eo7k9hh9e7.5hfd3l3g-67o9hh9e79khnil.5hf@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3THNFaQUKCZk7EO7K9HH9E7.5HFD3L3G-67O9HH9E79KHNIL.5HF@flex--elver.bounces.google.com;
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

When (and if) we introduce context locks to denote more generally that
"IRQ", "BH", "PREEMPT" contexts are disabled, it would make sense to
acquire these instead of RCU_BH and RCU_SCHED respectively.

The above change also simplified introducing __guarded_by support, where
only the "RCU" context lock needs to be held: introduce __rcu_guarded,
where Clang's context analysis warns if a pointer is dereferenced
without any of the RCU locks held, or updated without the appropriate
helpers.

The primitives rcu_assign_pointer() and friends are wrapped with
context_unsafe(), which enforces using them to update RCU-protected
pointers marked with __rcu_guarded.

Signed-off-by: Marco Elver <elver@google.com>
Acked-by: Paul E. McKenney <paulmck@kernel.org>
---
v5:
* Rename "context guard" -> "context lock".

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
index b2d69fb4a884..3bc72f71fe25 100644
--- a/Documentation/dev-tools/context-analysis.rst
+++ b/Documentation/dev-tools/context-analysis.rst
@@ -80,7 +80,7 @@ Supported Kernel Primitives
 
 Currently the following synchronization primitives are supported:
 `raw_spinlock_t`, `spinlock_t`, `rwlock_t`, `mutex`, `seqlock_t`,
-`bit_spinlock`.
+`bit_spinlock`, RCU.
 
 For context locks with an initialization function (e.g., `spin_lock_init()`),
 calling this function before initializing any guarded members or globals
diff --git a/include/linux/rcupdate.h b/include/linux/rcupdate.h
index c5b30054cd01..50e63eade019 100644
--- a/include/linux/rcupdate.h
+++ b/include/linux/rcupdate.h
@@ -31,6 +31,16 @@
 #include <asm/processor.h>
 #include <linux/context_tracking_irq.h>
 
+token_context_lock(RCU, __reentrant_ctx_lock);
+token_context_lock_instance(RCU, RCU_SCHED);
+token_context_lock_instance(RCU, RCU_BH);
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
+static inline bool lockdep_assert_rcu_helper(bool c, const struct __ctx_lock_RCU *ctx)
+	__assumes_shared_ctx_lock(RCU) __assumes_shared_ctx_lock(ctx)
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
+#define lockdep_assert_in_rcu_read_lock() __assume_shared_ctx_lock(RCU)
+#define lockdep_assert_in_rcu_read_lock_bh() __assume_shared_ctx_lock(RCU_BH)
+#define lockdep_assert_in_rcu_read_lock_sched() __assume_shared_ctx_lock(RCU_SCHED)
+#define lockdep_assert_in_rcu_reader() __assume_shared_ctx_lock(RCU)
 
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
+	((typeof(*p) __force __kernel *)(local))			\
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
index be0c5d462a48..559df32fb5f8 100644
--- a/lib/test_context-analysis.c
+++ b/lib/test_context-analysis.c
@@ -7,6 +7,7 @@
 #include <linux/bit_spinlock.h>
 #include <linux/build_bug.h>
 #include <linux/mutex.h>
+#include <linux/rcupdate.h>
 #include <linux/seqlock.h>
 #include <linux/spinlock.h>
 
@@ -284,3 +285,87 @@ static void __used test_bit_spin_lock(struct test_bit_spinlock_data *d)
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
2.52.0.322.g1dd061c0dc-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251219154418.3592607-15-elver%40google.com.
