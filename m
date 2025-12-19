Return-Path: <kasan-dev+bncBC7OBJGL2MHBBS7GSXFAMGQEVNOCETY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13e.google.com (mail-lf1-x13e.google.com [IPv6:2a00:1450:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id 9EAD4CD095F
	for <lists+kasan-dev@lfdr.de>; Fri, 19 Dec 2025 16:46:21 +0100 (CET)
Received: by mail-lf1-x13e.google.com with SMTP id 2adb3069b0e04-598eb48cf69sf957551e87.1
        for <lists+kasan-dev@lfdr.de>; Fri, 19 Dec 2025 07:46:21 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1766159181; cv=pass;
        d=google.com; s=arc-20240605;
        b=Q71sEC1Gd6OuIiE4GaDQ9OcAY1h4ROmuwKVbaFvF7524yDw8oD1bjCY3D6iDUhaRyl
         FomQedhMMEgPrUXWgjk+9NwQIkPXi6qT9YLqbkPq64JH6uPCBRouvCScMMXPppeUytEv
         HLgEJX63ThBiH8AV3h9Ix4H7L8gnRV6NILmoEp0Tc4bOhpZcV7hz870xJ1vhC/W5U/vD
         JaPOVeH0e9ZdBFjnXqOIuLA7evtIEtTBz2kye206TvUvobg+HRQlcTSuM8bcQKOe32HZ
         tEmNfriseUXQ6F7upQRJntn+p0jaStm8k/772K4sZWwtNTT1y18SRhB+4S1Uot5su53i
         gbkA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=69AJhrAZuqV1C/mLRlnyVmAuWkHRkjkhbLAYAI9031U=;
        fh=jxG+/efK7n3yc0ZZxC759597mrzL2XijVsvi+xTIx28=;
        b=UWECXfLLyfW/OOOggKknLAbZ/6kUpcyne7JcA4AmTr8hAL+wp/Yw2KH69LxTE6DxHo
         6j/27YiZm3SierxByslHeMs9ZOZ2YkXbSW/TtmMbn93Jf+nLIpCZgZGOHO3MK65C2vlm
         v1uZJBMnDHedXgWtnVinVFF2HqAeUaCPnVXBCRLJO5ZydPy01mJR1rZufw28TP/rqLxM
         I/JsJ2L1MAYIHr5bLJqbfM8KlOP8TULqOCtZIv5DHjoB+nUyZOCBAZRu3UIZ3eI8QczZ
         9r6wVe1oseNdM9Z8bemyL4vQmP07yVZoGjaEp/QquXHVv+z37t96ArAk7iPe8V4f1Yff
         eYPQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="K/tJquGS";
       spf=pass (google.com: domain of 3sxnfaqukczy4bl4h6ee6b4.2eca0i0d-34l6ee6b46hekfi.2ec@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3SXNFaQUKCZY4BL4H6EE6B4.2ECA0I0D-34L6EE6B46HEKFI.2EC@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1766159181; x=1766763981; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=69AJhrAZuqV1C/mLRlnyVmAuWkHRkjkhbLAYAI9031U=;
        b=A3+5GBUFFyPreT1oQ82uQ5vFKVQjoMUaH/OzMApxpHZYJ8SAVHmmyr+9JLeDWjaiDS
         3a3z9yfOAQatEfCGLNADvQdEeXLyWGGWriKnfgGS5+qWKjTLSdgwNSuBO+LuIMB0OMrD
         zWAY4ooX8+jJM7168ZS7CarpFL8XPfvAKzkwLQNCS3VKQt5PesMGw1dV0Ri+SAUOH1Mq
         l5GVJdTKI1V7Ago4VA4PrXywxXO+//hvpEOCK5eWihSPURAy/nRs/3xG7nDL19KIUiEq
         2WwRKmYb+o30WnpWXqa3SOC1rXy2P3pcFWTux/SP+qlcfaximuZilmW4S2eg9UK+TUCz
         g7Xg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1766159181; x=1766763981;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=69AJhrAZuqV1C/mLRlnyVmAuWkHRkjkhbLAYAI9031U=;
        b=A5eA85BramyRZwh1nGwFTy7nqEzHmU0eJgtazbVNSeYRukyE2/ImZIwPCBa0uVlPql
         GNDiXQXaNqWwvSHg8YVOaRD3MFQ02u8nhqIU2/v/TJnYfT+wfjpCbozylHMEy7aOQcm/
         9w4u6u48GOXmAXJIuY+/x+kd7AmEkKDHfOkiiifqDrsyR9LPd5KkR4DmsgbVpQqMyS7L
         WbMfeCYq5az1kbcfVg1MHobVdBy/xlHc/wJrGpSKgR6IGgdBi0X3w4hRhKD7KvszCGHy
         BAaG5AaMrfLfLETGV8y1Rnbx7GjOLsZBtRAG1hz/HMbK1/FjnSCeybABOMFrdeXPpBm3
         xRyQ==
X-Forwarded-Encrypted: i=2; AJvYcCXU6/edEx/yUpSljgpfOnnUBryuapufEiejBRPhgNimr1H1f1SH8jxdZPBfuHfyxHrjaygm+Q==@lfdr.de
X-Gm-Message-State: AOJu0YwS9w+CV5gl0yDcmuZURmgSycGgUHsYLNps0Kn32fQT4lUMHI0v
	BluvYnfEk5T8x5eW+ekNqitMjUG6OmgLx9B7sCUOV3jl69Ge84hVT5YD
X-Google-Smtp-Source: AGHT+IHcfAJW2I+e7t3gl/pILfPi3szcfznFov5PB2LW4T80B25yVqFrn2gmUqNIP6SePBOinJ808w==
X-Received: by 2002:a05:6512:3d1e:b0:598:8f91:a03e with SMTP id 2adb3069b0e04-59a17df1de2mr1163961e87.50.1766159180745;
        Fri, 19 Dec 2025 07:46:20 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWYYesjJ3ZDE1Cfp50/yc8br3K/Q5oM6U7NpFW7Ig+3hDw=="
Received: by 2002:a05:6512:159e:b0:598:f0c5:381e with SMTP id
 2adb3069b0e04-598fa40e77als2986999e87.2.-pod-prod-08-eu; Fri, 19 Dec 2025
 07:46:18 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXHDgfixBKljKvILUvJ2e9+3MguIZKFaD2ZpOb2KbaXDKTfdaV9zBYrGdeRaEPYv5N4u3RfEyRmOU8=@googlegroups.com
X-Received: by 2002:ac2:4c4d:0:b0:595:831d:2308 with SMTP id 2adb3069b0e04-59a17d74455mr1027353e87.1.1766159177824;
        Fri, 19 Dec 2025 07:46:17 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1766159177; cv=none;
        d=google.com; s=arc-20240605;
        b=KZzPg1ef2y85zVJzsQexOXrPPjLDESX9ryRlYlPGMJhtB8R7T2kELJTjPdwJDHh5Vv
         7+Nc5CETB/JQzmUW+Se3hrtQwMSEVWqrmZTjYMmasgD6/KZG3Zu+Oo0KkAlVazT4JQke
         VVBDbaY0FewexMxWD4W0cTtn3ostIMShSG0QWNdCie7L3fosOXzSj8Q+WBbTPec8DgNU
         AFYHfHT73cprWFPZ86aSxxuxyFQy8EPQItn+kwS4Bi8t3AoGp2oVt9BTVye3CsuJUwKp
         6Fa6RreRpFyCsjUq+lPlCoPdgQfu5XBCcULjXZrjGLeGZlIWToGgfU0jDGnmnK9gBFgp
         mQPw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=xxzeiPbUa31+hz0U8Tv6bmU7luRcJmafBg2S0XNVzY0=;
        fh=Q+Q8OKCuOatkCGMsvqKvGwq2LAlo0KkK06M/Wq++DE0=;
        b=d4/CX4kSnvaz6QfK9FVbCNmphFaKagbm7s5wBMv9Tg6oQrQGDlf1KQ0K9Q9nMbls14
         8XAex7kWypIVh3vxQhJn0+CF+XqdyyGixzTo9eWfAhPyH5TqBh0+GFqaKEKDMPAQ5QvE
         0d9SBUcrFlBA8g6fVFNdcZE6gqiZUUhBeN1oPcZ2Zhs/w84glOLOCPNVrFxcUx7nq5jd
         1Suio+hnDBGG7Vr292Z4ab1Bs+YMebU6buVDPKTAc1ZYbh2PvcC0YXCA7g9AdplBA2jj
         dIBs9oymWNho1+MO4xndxmFc3xh9NZSFYnbQIo8lOlVZ6BB2lVoTa/3qnY6vS9FvGcJa
         5GpQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="K/tJquGS";
       spf=pass (google.com: domain of 3sxnfaqukczy4bl4h6ee6b4.2eca0i0d-34l6ee6b46hekfi.2ec@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3SXNFaQUKCZY4BL4H6EE6B4.2ECA0I0D-34L6EE6B46HEKFI.2EC@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x349.google.com (mail-wm1-x349.google.com. [2a00:1450:4864:20::349])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-59a1860d04bsi83400e87.4.2025.12.19.07.46.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 19 Dec 2025 07:46:17 -0800 (PST)
Received-SPF: pass (google.com: domain of 3sxnfaqukczy4bl4h6ee6b4.2eca0i0d-34l6ee6b46hekfi.2ec@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) client-ip=2a00:1450:4864:20::349;
Received: by mail-wm1-x349.google.com with SMTP id 5b1f17b1804b1-477b8a667bcso23228755e9.2
        for <kasan-dev@googlegroups.com>; Fri, 19 Dec 2025 07:46:17 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCVs3YxpsHnsv0son4HuHbfxFWUlUzDYBgmzX6DcBMsDsRtpLlpsSIJ0AvvPTf7kLt48O2uwL3oya18=@googlegroups.com
X-Received: from wmbgx16.prod.google.com ([2002:a05:600c:8590:b0:47a:90c7:e279])
 (user=elver job=prod-delivery.src-stubby-dispatcher) by 2002:a05:600c:820d:b0:479:3a87:208f
 with SMTP id 5b1f17b1804b1-47d195aa085mr30269305e9.36.1766159177290; Fri, 19
 Dec 2025 07:46:17 -0800 (PST)
Date: Fri, 19 Dec 2025 16:40:02 +0100
In-Reply-To: <20251219154418.3592607-1-elver@google.com>
Mime-Version: 1.0
References: <20251219154418.3592607-1-elver@google.com>
X-Mailer: git-send-email 2.52.0.322.g1dd061c0dc-goog
Message-ID: <20251219154418.3592607-14-elver@google.com>
Subject: [PATCH v5 13/36] bit_spinlock: Support Clang's context analysis
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
 header.i=@google.com header.s=20230601 header.b="K/tJquGS";       spf=pass
 (google.com: domain of 3sxnfaqukczy4bl4h6ee6b4.2eca0i0d-34l6ee6b46hekfi.2ec@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3SXNFaQUKCZY4BL4H6EE6B4.2ECA0I0D-34L6EE6B46HEKFI.2EC@flex--elver.bounces.google.com;
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

The annotations for bit_spinlock.h have simply been using "bitlock" as
the token. For Sparse, that was likely sufficient in most cases. But
Clang's context analysis is more precise, and we need to ensure we
can distinguish different bitlocks.

To do so, add a token context, and a macro __bitlock(bitnum, addr)
that is used to construct unique per-bitlock tokens.

Add the appropriate test.

<linux/list_bl.h> is implicitly included through other includes, and
requires 2 annotations to indicate that acquisition (without release)
and release (without prior acquisition) of its bitlock is intended.

Signed-off-by: Marco Elver <elver@google.com>
---
v5:
* Rename "context guard" -> "context lock".

v4:
* Rename capability -> context analysis.
---
 Documentation/dev-tools/context-analysis.rst |  3 ++-
 include/linux/bit_spinlock.h                 | 22 ++++++++++++++---
 include/linux/list_bl.h                      |  2 ++
 lib/test_context-analysis.c                  | 26 ++++++++++++++++++++
 4 files changed, 48 insertions(+), 5 deletions(-)

diff --git a/Documentation/dev-tools/context-analysis.rst b/Documentation/dev-tools/context-analysis.rst
index 690565910084..b2d69fb4a884 100644
--- a/Documentation/dev-tools/context-analysis.rst
+++ b/Documentation/dev-tools/context-analysis.rst
@@ -79,7 +79,8 @@ Supported Kernel Primitives
 ~~~~~~~~~~~~~~~~~~~~~~~~~~~
 
 Currently the following synchronization primitives are supported:
-`raw_spinlock_t`, `spinlock_t`, `rwlock_t`, `mutex`, `seqlock_t`.
+`raw_spinlock_t`, `spinlock_t`, `rwlock_t`, `mutex`, `seqlock_t`,
+`bit_spinlock`.
 
 For context locks with an initialization function (e.g., `spin_lock_init()`),
 calling this function before initializing any guarded members or globals
diff --git a/include/linux/bit_spinlock.h b/include/linux/bit_spinlock.h
index 59e345f74b0e..7869a6e59b6a 100644
--- a/include/linux/bit_spinlock.h
+++ b/include/linux/bit_spinlock.h
@@ -9,6 +9,16 @@
 
 #include <asm/processor.h>  /* for cpu_relax() */
 
+/*
+ * For static context analysis, we need a unique token for each possible bit
+ * that can be used as a bit_spinlock. The easiest way to do that is to create a
+ * fake context that we can cast to with the __bitlock(bitnum, addr) macro
+ * below, which will give us unique instances for each (bit, addr) pair that the
+ * static analysis can use.
+ */
+context_lock_struct(__context_bitlock) { };
+#define __bitlock(bitnum, addr) (struct __context_bitlock *)(bitnum + (addr))
+
 /*
  *  bit-based spin_lock()
  *
@@ -16,6 +26,7 @@
  * are significantly faster.
  */
 static __always_inline void bit_spin_lock(int bitnum, unsigned long *addr)
+	__acquires(__bitlock(bitnum, addr))
 {
 	/*
 	 * Assuming the lock is uncontended, this never enters
@@ -34,13 +45,14 @@ static __always_inline void bit_spin_lock(int bitnum, unsigned long *addr)
 		preempt_disable();
 	}
 #endif
-	__acquire(bitlock);
+	__acquire(__bitlock(bitnum, addr));
 }
 
 /*
  * Return true if it was acquired
  */
 static __always_inline int bit_spin_trylock(int bitnum, unsigned long *addr)
+	__cond_acquires(true, __bitlock(bitnum, addr))
 {
 	preempt_disable();
 #if defined(CONFIG_SMP) || defined(CONFIG_DEBUG_SPINLOCK)
@@ -49,7 +61,7 @@ static __always_inline int bit_spin_trylock(int bitnum, unsigned long *addr)
 		return 0;
 	}
 #endif
-	__acquire(bitlock);
+	__acquire(__bitlock(bitnum, addr));
 	return 1;
 }
 
@@ -57,6 +69,7 @@ static __always_inline int bit_spin_trylock(int bitnum, unsigned long *addr)
  *  bit-based spin_unlock()
  */
 static __always_inline void bit_spin_unlock(int bitnum, unsigned long *addr)
+	__releases(__bitlock(bitnum, addr))
 {
 #ifdef CONFIG_DEBUG_SPINLOCK
 	BUG_ON(!test_bit(bitnum, addr));
@@ -65,7 +78,7 @@ static __always_inline void bit_spin_unlock(int bitnum, unsigned long *addr)
 	clear_bit_unlock(bitnum, addr);
 #endif
 	preempt_enable();
-	__release(bitlock);
+	__release(__bitlock(bitnum, addr));
 }
 
 /*
@@ -74,6 +87,7 @@ static __always_inline void bit_spin_unlock(int bitnum, unsigned long *addr)
  *  protecting the rest of the flags in the word.
  */
 static __always_inline void __bit_spin_unlock(int bitnum, unsigned long *addr)
+	__releases(__bitlock(bitnum, addr))
 {
 #ifdef CONFIG_DEBUG_SPINLOCK
 	BUG_ON(!test_bit(bitnum, addr));
@@ -82,7 +96,7 @@ static __always_inline void __bit_spin_unlock(int bitnum, unsigned long *addr)
 	__clear_bit_unlock(bitnum, addr);
 #endif
 	preempt_enable();
-	__release(bitlock);
+	__release(__bitlock(bitnum, addr));
 }
 
 /*
diff --git a/include/linux/list_bl.h b/include/linux/list_bl.h
index ae1b541446c9..df9eebe6afca 100644
--- a/include/linux/list_bl.h
+++ b/include/linux/list_bl.h
@@ -144,11 +144,13 @@ static inline void hlist_bl_del_init(struct hlist_bl_node *n)
 }
 
 static inline void hlist_bl_lock(struct hlist_bl_head *b)
+	__acquires(__bitlock(0, b))
 {
 	bit_spin_lock(0, (unsigned long *)b);
 }
 
 static inline void hlist_bl_unlock(struct hlist_bl_head *b)
+	__releases(__bitlock(0, b))
 {
 	__bit_spin_unlock(0, (unsigned long *)b);
 }
diff --git a/lib/test_context-analysis.c b/lib/test_context-analysis.c
index 53abea0008f2..be0c5d462a48 100644
--- a/lib/test_context-analysis.c
+++ b/lib/test_context-analysis.c
@@ -4,6 +4,7 @@
  * positive errors when compiled with Clang's context analysis.
  */
 
+#include <linux/bit_spinlock.h>
 #include <linux/build_bug.h>
 #include <linux/mutex.h>
 #include <linux/seqlock.h>
@@ -258,3 +259,28 @@ static void __used test_seqlock_scoped(struct test_seqlock_data *d)
 		(void)d->counter;
 	}
 }
+
+struct test_bit_spinlock_data {
+	unsigned long bits;
+	int counter __guarded_by(__bitlock(3, &bits));
+};
+
+static void __used test_bit_spin_lock(struct test_bit_spinlock_data *d)
+{
+	/*
+	 * Note, the analysis seems to have false negatives, because it won't
+	 * precisely recognize the bit of the fake __bitlock() token.
+	 */
+	bit_spin_lock(3, &d->bits);
+	d->counter++;
+	bit_spin_unlock(3, &d->bits);
+
+	bit_spin_lock(3, &d->bits);
+	d->counter++;
+	__bit_spin_unlock(3, &d->bits);
+
+	if (bit_spin_trylock(3, &d->bits)) {
+		d->counter++;
+		bit_spin_unlock(3, &d->bits);
+	}
+}
-- 
2.52.0.322.g1dd061c0dc-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251219154418.3592607-14-elver%40google.com.
