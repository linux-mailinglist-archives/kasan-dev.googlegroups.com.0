Return-Path: <kasan-dev+bncBC7OBJGL2MHBBUNDWDDAMGQEPJ67PAA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x539.google.com (mail-ed1-x539.google.com [IPv6:2a00:1450:4864:20::539])
	by mail.lfdr.de (Postfix) with ESMTPS id 02D8CB84FB7
	for <lists+kasan-dev@lfdr.de>; Thu, 18 Sep 2025 16:06:13 +0200 (CEST)
Received: by mail-ed1-x539.google.com with SMTP id 4fb4d7f45d1cf-62f637d59bbsf1067725a12.1
        for <lists+kasan-dev@lfdr.de>; Thu, 18 Sep 2025 07:06:13 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758204372; cv=pass;
        d=google.com; s=arc-20240605;
        b=h2snlMrEDkK58Rq4Xxn7UCYKKS9ZoEfu8SLDM5XNWBJatzarH05boqrtFNdE8C+Ho9
         5zEoiuDOLqjkAtsPT7ph231fY0saKXrekT4ik93wMZG94Do+yol54rLcPQUpgTEQfEMw
         MciqsbA5jWOIj28QZTbbajFb+GE+Aqt+bJ0Pf70+yQXMLhPpe+B02AlJfv3bAgQsEIyy
         8QFzyXUDlS6fYeu7Dsr1MmTPPK4IuAoD4p39RXjpJ8Oe1BGI4GuqiQHYOfstIvCnfnQT
         qFhOdx0d/0wqgfCkYYmJopnWbLsDbUcvgfUlDHlld43exlVuj4I5uHwq0wQ3xu2c0R8e
         q+iA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=MGfoGwK98+H75Jq6LP5TrwHSQjGulPih63dZJEL21Gc=;
        fh=XEVkxauicU2VjaBvU9LxxXOFzAb8A2gsKH1h2r9Oz4M=;
        b=Ca1mYvRpyw8YTcWsHjIqiHhIKmBXxB8YqNWRxwo6inLthHqlN/zatgm0ZfIjNMyO2D
         zWqsggazxy/uoMi3+2MvUCOLZbfSrwe2tQ8Ds5H8qrbOGPUfaoK46j5ehTQfdXPuMhOr
         t6gBQIkNV3h/9nr82R0eOMtZe0oQR5RPh/J5q5fdxHnS8wOoaqCF5gvVBaomhREWwW9f
         n79BK+nPGoHKLpcK1WbiMqO5CJbX+ZR8jDGTLEZwnPPGEzTh9eg5Q9RuaUn5PvNfmsHy
         J9GW2hXDJS38ipvlhHaGEgupA02d/gRacymdMcAVSL4n3uD8StzK1iawhwIbj3ZemH1X
         e1Yw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=O7HI99ez;
       spf=pass (google.com: domain of 3zbhmaaukcw0pwgpcrzzrwp.nzxvldly-opgrzzrwprczfad.nzx@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3zBHMaAUKCW0PWgPcRZZRWP.NZXVLdLY-OPgRZZRWPRcZfad.NZX@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758204372; x=1758809172; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=MGfoGwK98+H75Jq6LP5TrwHSQjGulPih63dZJEL21Gc=;
        b=rZbnNjnnC5DXhG1dMAT9j3wymeVXFhmewh0KqZh6dbLhLmVROlHG84ZyGNbJSfY8Bv
         CIpzBLZ+VpMGn5+Fwlecq5Zlz3Y4iwR1DWb3JwRyNPFkZJqeSnqYJTxnAq5cG2mQgScn
         Ql+O0qCdrfhG9FwC+G1Jet8Qj7KC7P16XHY28cTZwbQCbaGZ7W9T7WQ5L1jlrc8eI2KH
         Kw2fOSqwN6+kgIEwOV024hH5lt0bS26WTVo2kJtZZViMO/M932Aq7n2MvzeMWOAv/hUt
         3aDHjn8KQbNY2oahABwvssIMqFjtRQoj1cJPLzTwMZgG4wAuzoXdMV+A6rWSClvwq6R2
         M4Xg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758204372; x=1758809172;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=MGfoGwK98+H75Jq6LP5TrwHSQjGulPih63dZJEL21Gc=;
        b=XxbPzCWoPSVzyyAYUJm+UiALW1wVIDd9pAnAfDBGIINi9AXhEtVbJEdfuZ1Pt4hz//
         w2HN6h26pf7/M0JpFHUQA2E/Ttdg8rKoXgWKl1HYcx9+PB+/H1DD1WAKZiJBHvck/y87
         YeTvs++Elcj+crdbbA9jCzcGWlXpEtFOJ+HbkCZ/rEKCeoZ9TCS6Ml5GIx/QWr9ny3RI
         9+TBxoCwuJxxgjnE2wcDRa88nQZD3PqQKaGPDlX9XNdFdyaW5e2YmWThXqikNh6zjz8A
         roisoAVrqCTr6TXMVszxt00GDrSBmw6LIM+Lgp1zSyagoBH8bqSjWfVUCSKcz0r9+2jJ
         r0NA==
X-Forwarded-Encrypted: i=2; AJvYcCXp/NwdV9Hfs8hoAmHoKwnyrXXzhx3sOPENVdZkwgnQ2in1jvmXl5V3LPPtrbq4rUCPMrWZiw==@lfdr.de
X-Gm-Message-State: AOJu0YxqI6NTBvLm8bfAlbbkFzE/znFUVv7zLRM8TpHmvrCVMwGKt+gt
	U58+cAisY/d8E3YkiX+PII6mi2fLfLyAuHx94WtWQga/GsWxUtxCFrCZ
X-Google-Smtp-Source: AGHT+IH2Llyug8HqEP6l2UvM+Nz08P/oqVYAJpo3M7UIA/FVnaRxI99KxSCJPBNx5SzMQ6CwvZNWkw==
X-Received: by 2002:a05:6402:3553:b0:62f:67bb:d399 with SMTP id 4fb4d7f45d1cf-62f842405f1mr4784390a12.29.1758204369858;
        Thu, 18 Sep 2025 07:06:09 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd7ZX8vnwrb5hyH8odVGp56+3SGm+v+nM63wtrGZGaHSAA==
Received: by 2002:a50:d6cd:0:b0:61c:61c3:b9b8 with SMTP id 4fb4d7f45d1cf-62fa7713acbls720238a12.1.-pod-prod-08-eu;
 Thu, 18 Sep 2025 07:06:05 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCV5DyMKVGnRLCU1o31cYuG8pngpkeDgCdENkwV6tQYxdAChGYUfX5AN+9KouHxMhqOEca0Nz6CB15Y=@googlegroups.com
X-Received: by 2002:a05:6402:3553:b0:62f:67bb:d399 with SMTP id 4fb4d7f45d1cf-62f842405f1mr4784137a12.29.1758204365606;
        Thu, 18 Sep 2025 07:06:05 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1758204365; cv=none;
        d=google.com; s=arc-20240605;
        b=DGuKvZo5sBIiHzA8M64xces4rapoD3eVUt+d97zHY/xQgII1Xg9dIFNSJ1T9o0286k
         bM+xHs35TajiUnOoD6qV5uZlAsBTTieoP9Bt9IFhODSFecWUawJf+gFJpMdFqr9zHL+5
         UyuJZSfT4U1gMeEtABtskKP8lG80q9muFi8SQ0rB3/rh3S3xD/irT39RX6sOP82XvyyO
         /sUf5kn9gxBNfhL2ZJabIZOgQCl2q4ATLMuNjGMxkzQji1qVzioh0sIqKzDh7y6x4sLN
         6k7Ut6R11Qvzh4wrhyAxaChqSqz0oXy5i44DSmlxyLNj51q6+EMsnQLIUTdnSkaSQz6g
         n0PA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=mBolDvDOcn9D07EK9oOcgseWQJt3GEJTc9gsXdDIsBk=;
        fh=jjlLECXhH/JjEGfedJfna0eMkysJC4OY5o64gmCefwY=;
        b=eqkKQAXHT20Iwqb7lPIxuCBvHWEfd3v39cUz/jM/Ua0dXrTBGgY5a3YvC4YaFa8c8r
         Z3AAvYcL5g8SuywK1HqwA8IAGgzfCWo1sOJ6iWr3rwIqgUb/+wWFPfYjUr6bedMQaZTk
         JYYWufw7nwdwYfY7XT+5GVCZIFyxN38xXsnAvxZYbyuv+h2n2O5EAGAsNHEGRUfDJVu8
         lTd/3crpgrwN6GjShceD+EdLEia5Sjh0VBw1+WZTCxLxg909i0prq7gVBwGLYHR8pc5x
         qLDgptgn1YUknYns6ouy9OOWShT3+eO+N/rentm7/+VkLrH6QaEArD2jt9hJPA/kOh5U
         3S9g==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=O7HI99ez;
       spf=pass (google.com: domain of 3zbhmaaukcw0pwgpcrzzrwp.nzxvldly-opgrzzrwprczfad.nzx@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3zBHMaAUKCW0PWgPcRZZRWP.NZXVLdLY-OPgRZZRWPRcZfad.NZX@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x34a.google.com (mail-wm1-x34a.google.com. [2a00:1450:4864:20::34a])
        by gmr-mx.google.com with ESMTPS id 4fb4d7f45d1cf-62fa5f34c70si46665a12.5.2025.09.18.07.06.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 18 Sep 2025 07:06:05 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3zbhmaaukcw0pwgpcrzzrwp.nzxvldly-opgrzzrwprczfad.nzx@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) client-ip=2a00:1450:4864:20::34a;
Received: by mail-wm1-x34a.google.com with SMTP id 5b1f17b1804b1-45f29eb22f8so5212295e9.0
        for <kasan-dev@googlegroups.com>; Thu, 18 Sep 2025 07:06:05 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXGApfnS6UcT1p1PGjY4iNyNqcnGkfzviDWFFCQvR1eufNOsfor7EZ4QJePkHjALFPtDdvJnqFtke4=@googlegroups.com
X-Received: from wmbhh13.prod.google.com ([2002:a05:600c:530d:b0:45d:cf67:3908])
 (user=elver job=prod-delivery.src-stubby-dispatcher) by 2002:a05:600c:c87:b0:45d:d5c6:482
 with SMTP id 5b1f17b1804b1-46205cc836cmr63930155e9.18.1758204364942; Thu, 18
 Sep 2025 07:06:04 -0700 (PDT)
Date: Thu, 18 Sep 2025 15:59:25 +0200
In-Reply-To: <20250918140451.1289454-1-elver@google.com>
Mime-Version: 1.0
References: <20250918140451.1289454-1-elver@google.com>
X-Mailer: git-send-email 2.51.0.384.g4c02a37b29-goog
Message-ID: <20250918140451.1289454-15-elver@google.com>
Subject: [PATCH v3 14/35] rcu: Support Clang's capability analysis
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, Peter Zijlstra <peterz@infradead.org>, 
	Boqun Feng <boqun.feng@gmail.com>, Ingo Molnar <mingo@kernel.org>, Will Deacon <will@kernel.org>
Cc: "David S. Miller" <davem@davemloft.net>, Luc Van Oostenryck <luc.vanoostenryck@gmail.com>, 
	"Paul E. McKenney" <paulmck@kernel.org>, Alexander Potapenko <glider@google.com>, Arnd Bergmann <arnd@arndb.de>, 
	Bart Van Assche <bvanassche@acm.org>, Bill Wendling <morbo@google.com>, Christoph Hellwig <hch@lst.de>, 
	Dmitry Vyukov <dvyukov@google.com>, Eric Dumazet <edumazet@google.com>, 
	Frederic Weisbecker <frederic@kernel.org>, Greg Kroah-Hartman <gregkh@linuxfoundation.org>, 
	Herbert Xu <herbert@gondor.apana.org.au>, Ian Rogers <irogers@google.com>, 
	Jann Horn <jannh@google.com>, Joel Fernandes <joelagnelf@nvidia.com>, 
	Jonathan Corbet <corbet@lwn.net>, Josh Triplett <josh@joshtriplett.org>, 
	Justin Stitt <justinstitt@google.com>, Kees Cook <kees@kernel.org>, 
	Kentaro Takeda <takedakn@nttdata.co.jp>, Lukas Bulwahn <lukas.bulwahn@gmail.com>, 
	Mark Rutland <mark.rutland@arm.com>, Mathieu Desnoyers <mathieu.desnoyers@efficios.com>, 
	Miguel Ojeda <ojeda@kernel.org>, Nathan Chancellor <nathan@kernel.org>, 
	Neeraj Upadhyay <neeraj.upadhyay@kernel.org>, 
	Nick Desaulniers <nick.desaulniers+lkml@gmail.com>, Steven Rostedt <rostedt@goodmis.org>, 
	Tetsuo Handa <penguin-kernel@I-love.SAKURA.ne.jp>, Thomas Gleixner <tglx@linutronix.de>, 
	Thomas Graf <tgraf@suug.ch>, Uladzislau Rezki <urezki@gmail.com>, Waiman Long <longman@redhat.com>, 
	kasan-dev@googlegroups.com, linux-crypto@vger.kernel.org, 
	linux-doc@vger.kernel.org, linux-kbuild@vger.kernel.org, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, 
	linux-security-module@vger.kernel.org, linux-sparse@vger.kernel.org, 
	llvm@lists.linux.dev, rcu@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=O7HI99ez;       spf=pass
 (google.com: domain of 3zbhmaaukcw0pwgpcrzzrwp.nzxvldly-opgrzzrwprczfad.nzx@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3zBHMaAUKCW0PWgPcRZZRWP.NZXVLdLY-OPgRZZRWPRcZfad.NZX@flex--elver.bounces.google.com;
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

The old annotations distinguished between RCU, RCU_BH, and RCU_SCHED;
however, to more easily be able to express that "hold the RCU read lock"
without caring if the normal, _bh(), or _sched() variant was used we'd
have to remove the distinction of the latter variants: change the _bh()
and _sched() variants to also acquire "RCU".

When (and if) we introduce capabilities to denote more generally that
"IRQ", "BH", "PREEMPT" are disabled, it would make sense to acquire
these capabilities instead of RCU_BH and RCU_SCHED respectively.

The above change also simplified introducing __guarded_by support, where
only the "RCU" capability needs to be held: introduce __rcu_guarded,
where Clang's capability analysis warns if a pointer is dereferenced
without any of the RCU locks held, or updated without the appropriate
helpers.

The primitives rcu_assign_pointer() and friends are wrapped with
capability_unsafe(), which enforces using them to update RCU-protected
pointers marked with __rcu_guarded.

Signed-off-by: Marco Elver <elver@google.com>
---
v3:
* Properly support reentrancy via new compiler support.

v2:
* Reword commit message and point out reentrancy caveat.
---
 .../dev-tools/capability-analysis.rst         |  2 +-
 include/linux/rcupdate.h                      | 73 +++++++++++-----
 lib/test_capability-analysis.c                | 85 +++++++++++++++++++
 3 files changed, 136 insertions(+), 24 deletions(-)

diff --git a/Documentation/dev-tools/capability-analysis.rst b/Documentation/dev-tools/capability-analysis.rst
index 56c6ba7205aa..fdacc7f73da8 100644
--- a/Documentation/dev-tools/capability-analysis.rst
+++ b/Documentation/dev-tools/capability-analysis.rst
@@ -82,7 +82,7 @@ Supported Kernel Primitives
 
 Currently the following synchronization primitives are supported:
 `raw_spinlock_t`, `spinlock_t`, `rwlock_t`, `mutex`, `seqlock_t`,
-`bit_spinlock`.
+`bit_spinlock`, RCU.
 
 For capabilities with an initialization function (e.g., `spin_lock_init()`),
 calling this function on the capability instance before initializing any
diff --git a/include/linux/rcupdate.h b/include/linux/rcupdate.h
index 120536f4c6eb..8eeece72492c 100644
--- a/include/linux/rcupdate.h
+++ b/include/linux/rcupdate.h
@@ -31,6 +31,16 @@
 #include <asm/processor.h>
 #include <linux/context_tracking_irq.h>
 
+token_capability(RCU, __reentrant_cap);
+token_capability_instance(RCU, RCU_SCHED);
+token_capability_instance(RCU, RCU_BH);
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
+static inline bool lockdep_assert_rcu_helper(bool c, const struct __capability_RCU *cap)
+	__assumes_shared_cap(RCU) __assumes_shared_cap(cap)
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
+#define lockdep_assert_in_rcu_read_lock() __assume_shared_cap(RCU)
+#define lockdep_assert_in_rcu_read_lock_bh() __assume_shared_cap(RCU_BH)
+#define lockdep_assert_in_rcu_read_lock_sched() __assume_shared_cap(RCU_SCHED)
+#define lockdep_assert_in_rcu_reader() __assume_shared_cap(RCU)
 
 #endif /* #else #ifdef CONFIG_PROVE_RCU */
 
@@ -506,11 +517,11 @@ static inline bool lockdep_assert_rcu_helper(bool c)
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
@@ -586,7 +597,7 @@ static inline bool lockdep_assert_rcu_helper(bool c)
  * other macros that it invokes.
  */
 #define rcu_assign_pointer(p, v)					      \
-do {									      \
+capability_unsafe(							      \
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
@@ -835,9 +846,10 @@ do {									      \
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
@@ -865,11 +877,12 @@ static __always_inline void rcu_read_lock(void)
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
 
@@ -888,9 +901,11 @@ static inline void rcu_read_unlock(void)
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
@@ -902,11 +917,13 @@ static inline void rcu_read_lock_bh(void)
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
 
@@ -926,9 +943,11 @@ static inline void rcu_read_unlock_bh(void)
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
@@ -936,9 +955,11 @@ static inline void rcu_read_lock_sched(void)
 
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
@@ -947,18 +968,22 @@ static inline notrace void rcu_read_lock_sched_notrace(void)
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
 
@@ -1001,10 +1026,10 @@ static inline notrace void rcu_read_unlock_sched_notrace(void)
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
@@ -1166,4 +1191,6 @@ DEFINE_LOCK_GUARD_0(rcu,
 	} while (0),
 	rcu_read_unlock())
 
+DECLARE_LOCK_GUARD_0_ATTRS(rcu, __acquires_shared(RCU), __releases_shared(RCU))
+
 #endif /* __LINUX_RCUPDATE_H */
diff --git a/lib/test_capability-analysis.c b/lib/test_capability-analysis.c
index ad362d5a7916..31c9bc1e2405 100644
--- a/lib/test_capability-analysis.c
+++ b/lib/test_capability-analysis.c
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
2.51.0.384.g4c02a37b29-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250918140451.1289454-15-elver%40google.com.
