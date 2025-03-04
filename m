Return-Path: <kasan-dev+bncBC7OBJGL2MHBBM4OTO7AMGQEOQPSMSA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33e.google.com (mail-wm1-x33e.google.com [IPv6:2a00:1450:4864:20::33e])
	by mail.lfdr.de (Postfix) with ESMTPS id AB0D5A4D815
	for <lists+kasan-dev@lfdr.de>; Tue,  4 Mar 2025 10:26:12 +0100 (CET)
Received: by mail-wm1-x33e.google.com with SMTP id 5b1f17b1804b1-4394c747c72sf21151895e9.1
        for <lists+kasan-dev@lfdr.de>; Tue, 04 Mar 2025 01:26:12 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1741080372; cv=pass;
        d=google.com; s=arc-20240605;
        b=jtzDJy6UAE85tWIU6+AyUeCR1pFLyM1VN3SipCNP0JCARQb8fziiktGlkNlzOtfCyh
         AAxI/t4RuZbiMpixMQ9l+GxV+/qs80r9Ij2v7sP8QddQtgw3za9XXJJoe0D0j4nRE6er
         vEMehyujGd3mNka7yNx4oeRtFYoYeusnMLI+CCk66DkcF/FJKlaHPpXuqR62VS7BFicf
         /whYUsgnWNoe0yIBMV2bpxJTsnmwRZhPgL0aY6NP4BcRYU2owOxD5V0BVwXdarcKkSfu
         6dLDlai38oyBKtgi6PE8tZ4elv4n6VHZ6BKzhswWEfxyyD5QDJXtWUz14FnpzoUrukoD
         +RAQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=rQbLzLggkn7dt+fAIb0jzna0ZKhnfNSAxde+EbAqmxA=;
        fh=CwqLKf5ArCQt7JaaQi7GS2Cd9vwmJMH02Dfgsj6cASs=;
        b=IFurvZqPrLFSikEnGfY8FI63qYaPCY8LOgP1GPQx+drThIgSeh9hezjGPPZlnnV5Bp
         4NwwHfpwV8t6RVFtXXfm6jelYqia9IU4NSgXVrTkv5+hxMX7GblTJLWBdFP3CD62U1//
         QejaJ38UOleKRCek8wXZA3T16M+nAvKmtAjnB5aVTXylR+q+jrQUV1qw1R6fODfAhmbJ
         Hd/6PnwnnLDLxLjOmDQZSBKuLHCH58+ZL/e0CdU6rzK88D0iFDunBqGYH00tY754VTEt
         LqZXhEhIAnlBagPykHqBZNC7sP71hd63LQ4ui94yWaUTNgaFmx+UGiNSVH/rt+6RNfZX
         5z9w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="w/jl8RpE";
       spf=pass (google.com: domain of 3mmfgzwukcr89gq9mbjjbg9.7jhf5n5i-89qbjjbg9bmjpkn.7jh@flex--elver.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3MMfGZwUKCR89GQ9MBJJBG9.7JHF5N5I-89QBJJBG9BMJPKN.7JH@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1741080372; x=1741685172; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=rQbLzLggkn7dt+fAIb0jzna0ZKhnfNSAxde+EbAqmxA=;
        b=sbOhR8VnzeTxSz2ihjTlydne/nv7vsDp0pvbmf8zgMzHZyUA4A8Nks8NZAi+KeMGBa
         TyDENlIyzvueoWZhAjFT995BK6E623nIywPgQIWD56QKpDM6PAUzjREnjsrCZFXEKad0
         KD29C5n+HBQklk1s51TlYxlL51bl27tfeN8x07RYamF/XheFiD5Hkl43jPQ1tWnPpPV0
         2hKDDdxyzVvkEh+mhnpxZ6HuosD7Ljh+K/zDdp9pGe+S310mzPGcajiUU7mBnNnAnvKH
         UaCvDdDaA8kYWcjSQ4An6uoS9BvdGMOyBe/ePPLHDKqpWJm1p/hk8QpRsiBNZeiivzc+
         xSCA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1741080372; x=1741685172;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=rQbLzLggkn7dt+fAIb0jzna0ZKhnfNSAxde+EbAqmxA=;
        b=L3fm6zNjBskubMw43sp4uLWsC/BMr/1btKEp/zscAhYJj3kfJ6Zyi6fCTpH8eB0VHS
         nnA2SOTF5EKVckPyQIZONx1NjhcDhD4YI6gKgSaPJQ6So0OPjX1KnKm6Cy4D8ntVa10S
         j75MY/PDb6zAyBoYocS5RmWqtbgqhVasn7FhzU0SiVy5onsyNOck2GdlrJmJgsJ5nCm+
         5NNUvG8RVwfMsaOQFF39VDKDYm9oZwmqlPbfMWGfTk7e3w4nXF08wK09AhU0iubs1k+q
         1/yeYJWKfYAUWKX5v7wF4afxagzxgSMd0NAmcndM6s6eWAsJmE8K4uhSTaHzvCUxUKiv
         XCsg==
X-Forwarded-Encrypted: i=2; AJvYcCVRvboraz8Og6BuHaoLrxtOJHglNveywh1iPFzNDHz102H7pq1fwKElX/cn4dnv5iquUO2rxA==@lfdr.de
X-Gm-Message-State: AOJu0YwAtomFrD07bRXkLrdDiyADmAhwjzLn/uQ1h+vYBSYxDcijb0UE
	cfBvSOeeEJ1mXV7sxF5eSykkxuoir16aiHcEsXEHZoksuiZkh/np
X-Google-Smtp-Source: AGHT+IHkrtxZV88NZnybd75a0JqvHpUu6XONhRBmfUTtbyGI6irSD+dPJXBFwvjdCsCWuJSJtFODqQ==
X-Received: by 2002:a05:600c:2d82:b0:43b:c0fa:f9c0 with SMTP id 5b1f17b1804b1-43bc0fb0089mr46659245e9.28.1741080371820;
        Tue, 04 Mar 2025 01:26:11 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVE9FlCRw1Ld8mmvJ3dEvwIAv+DwibNOoTCBYMA7Nbpmgg==
Received: by 2002:a05:600c:1c2a:b0:43b:c82b:4337 with SMTP id
 5b1f17b1804b1-43bc82b4435ls7020895e9.0.-pod-prod-01-eu; Tue, 04 Mar 2025
 01:26:09 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCW7/dx5Nik0A92R4L0IkX4T+5GH5N4ZDEukJoWai6k+jM/CEA0ZD6Akdbgl1CHdpSRPLksudW6pvXg=@googlegroups.com
X-Received: by 2002:a05:600c:4693:b0:439:88bb:d017 with SMTP id 5b1f17b1804b1-43ba66da7aamr128145275e9.6.1741080369290;
        Tue, 04 Mar 2025 01:26:09 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1741080369; cv=none;
        d=google.com; s=arc-20240605;
        b=f2pVMLZYP1v9/wJ+43mrla5wkC+6nkn10LQEvSSVJbvNsu0COxkhQsiXol0+3qBNYO
         LYj+s5TYYNlW48WnfDtJFd/8BTGcmwZIsc+CdgHzis+EmUJG2hb5pJa49aqG+13ybdgC
         RcYLN2V93UKqwl3b5sKaPRXqBvh/HxK/LVhtGvGn6s/ElsLQzSFsVgKVC+GeZFr8Tpd8
         Q+SW1GXiqGUosV/fqilT/beQXhSd6QqytH4/fIeCpyT4V6kYbUGU9vaBix4lmFj8Vc3D
         fk5czfyGvsj/f7uV3kWrB2wQKQt9m8NVCV9GM7s60agC64grMBjP9qhtwEwdbgf5+7l7
         trTQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=P1I/GQ+v/3j1AzYCm6S00P34ezPJ7HmSy44l1ZDIovo=;
        fh=ZxpLaSGed9Ab6MDKVDXl0bvFWyDiXEFVwP2FfPVFhok=;
        b=AgoYkZPynmokZtZRyf5GzIWaaOx8dydmFxcLF+rFwG4/TI5g2C5WWIK4P4zSJwKi3F
         rV67Y/j5AHQwjwnZYuvkNyqpFVCyiZA1SE4GSDEuZPzG9VXF5VEWzfttfNDQp4kl24BG
         42U2zx5IwcOBe20p/PnWKjS7POtlgC6Ekr/9ld7k99M9SjYgueBtV+/uJgBx8SrlAhDv
         Qi0mm7m40YVKDpOEt69RxV0EqMC6Ti5DFPLSNE13sxjLlIiuHDQ4z/qwMczWQor53b2c
         F7gIDQ/VUDPDbu0GdprRiYzh6BNGRo8vPsLuROViXhE3SV8muxuuCRYGyQm8LE1/3foD
         pQrA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="w/jl8RpE";
       spf=pass (google.com: domain of 3mmfgzwukcr89gq9mbjjbg9.7jhf5n5i-89qbjjbg9bmjpkn.7jh@flex--elver.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3MMfGZwUKCR89GQ9MBJJBG9.7JHF5N5I-89QBJJBG9BMJPKN.7JH@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ed1-x54a.google.com (mail-ed1-x54a.google.com. [2a00:1450:4864:20::54a])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-43bcc13b8a9si394825e9.1.2025.03.04.01.26.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 04 Mar 2025 01:26:09 -0800 (PST)
Received-SPF: pass (google.com: domain of 3mmfgzwukcr89gq9mbjjbg9.7jhf5n5i-89qbjjbg9bmjpkn.7jh@flex--elver.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) client-ip=2a00:1450:4864:20::54a;
Received: by mail-ed1-x54a.google.com with SMTP id 4fb4d7f45d1cf-5e5810f84cbso1237860a12.3
        for <kasan-dev@googlegroups.com>; Tue, 04 Mar 2025 01:26:09 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCVOiCanrlbC4acsay/UiyfYCz/bN0BHqo6JE6e3bRZiSrioUOUCpQt0v3WPil9pV8mgXwqIH+dQcdI=@googlegroups.com
X-Received: from edbet14.prod.google.com ([2002:a05:6402:378e:b0:5e5:762:2c87])
 (user=elver job=prod-delivery.src-stubby-dispatcher) by 2002:a05:6402:4407:b0:5dc:a44d:36a9
 with SMTP id 4fb4d7f45d1cf-5e4d6af158dmr16857891a12.14.1741080368800; Tue, 04
 Mar 2025 01:26:08 -0800 (PST)
Date: Tue,  4 Mar 2025 10:21:21 +0100
In-Reply-To: <20250304092417.2873893-1-elver@google.com>
Mime-Version: 1.0
References: <20250304092417.2873893-1-elver@google.com>
X-Mailer: git-send-email 2.48.1.711.g2feabab25a-goog
Message-ID: <20250304092417.2873893-23-elver@google.com>
Subject: [PATCH v2 22/34] compiler-capability-analysis: Remove Sparse support
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com
Cc: "David S. Miller" <davem@davemloft.net>, Luc Van Oostenryck <luc.vanoostenryck@gmail.com>, 
	"Paul E. McKenney" <paulmck@kernel.org>, Alexander Potapenko <glider@google.com>, Arnd Bergmann <arnd@arndb.de>, 
	Bart Van Assche <bvanassche@acm.org>, Bill Wendling <morbo@google.com>, Boqun Feng <boqun.feng@gmail.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Eric Dumazet <edumazet@google.com>, 
	Frederic Weisbecker <frederic@kernel.org>, Greg Kroah-Hartman <gregkh@linuxfoundation.org>, 
	Herbert Xu <herbert@gondor.apana.org.au>, Ingo Molnar <mingo@kernel.org>, 
	Jann Horn <jannh@google.com>, Jiri Slaby <jirislaby@kernel.org>, 
	Joel Fernandes <joel@joelfernandes.org>, Jonathan Corbet <corbet@lwn.net>, 
	Josh Triplett <josh@joshtriplett.org>, Justin Stitt <justinstitt@google.com>, 
	Kees Cook <kees@kernel.org>, Kentaro Takeda <takedakn@nttdata.co.jp>, 
	Mark Rutland <mark.rutland@arm.com>, Mathieu Desnoyers <mathieu.desnoyers@efficios.com>, 
	Miguel Ojeda <ojeda@kernel.org>, Nathan Chancellor <nathan@kernel.org>, 
	Neeraj Upadhyay <neeraj.upadhyay@kernel.org>, Peter Zijlstra <peterz@infradead.org>, 
	Steven Rostedt <rostedt@goodmis.org>, Tetsuo Handa <penguin-kernel@I-love.SAKURA.ne.jp>, 
	Thomas Gleixner <tglx@linutronix.de>, Uladzislau Rezki <urezki@gmail.com>, Waiman Long <longman@redhat.com>, 
	Will Deacon <will@kernel.org>, kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	llvm@lists.linux.dev, rcu@vger.kernel.org, linux-crypto@vger.kernel.org, 
	linux-serial@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b="w/jl8RpE";       spf=pass
 (google.com: domain of 3mmfgzwukcr89gq9mbjjbg9.7jhf5n5i-89qbjjbg9bmjpkn.7jh@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3MMfGZwUKCR89GQ9MBJJBG9.7JHF5N5I-89QBJJBG9BMJPKN.7JH@flex--elver.bounces.google.com;
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

Remove Sparse support as discussed at [1].

The kernel codebase is still scattered with numerous places that try to
appease Sparse's context tracking ("annotation for sparse", "fake out
sparse", "work around sparse", etc.). Eventually, as more subsystems
enable Clang's capability analysis, these places will show up and need
adjustment or removal of the workarounds altogether.

Link: https://lore.kernel.org/all/20250207083335.GW7145@noisy.programming.kicks-ass.net/ [1]
Link: https://lore.kernel.org/all/Z6XTKTo_LMj9KmbY@elver.google.com/ [2]
Cc: "Luc Van Oostenryck" <luc.vanoostenryck@gmail.com>
Cc: Peter Zijlstra <peterz@infradead.org>
Signed-off-by: Marco Elver <elver@google.com>
---
v2:
* New patch.
---
 Documentation/dev-tools/sparse.rst           | 19 -------
 include/linux/compiler-capability-analysis.h | 56 ++++++--------------
 include/linux/rcupdate.h                     | 15 +-----
 3 files changed, 17 insertions(+), 73 deletions(-)

diff --git a/Documentation/dev-tools/sparse.rst b/Documentation/dev-tools/sparse.rst
index dc791c8d84d1..37b20170835d 100644
--- a/Documentation/dev-tools/sparse.rst
+++ b/Documentation/dev-tools/sparse.rst
@@ -53,25 +53,6 @@ sure that bitwise types don't get mixed up (little-endian vs big-endian
 vs cpu-endian vs whatever), and there the constant "0" really _is_
 special.
 
-Using sparse for lock checking
-------------------------------
-
-The following macros are undefined for gcc and defined during a sparse
-run to use the "context" tracking feature of sparse, applied to
-locking.  These annotations tell sparse when a lock is held, with
-regard to the annotated function's entry and exit.
-
-__must_hold - The specified lock is held on function entry and exit.
-
-__acquires - The specified lock is held on function exit, but not entry.
-
-__releases - The specified lock is held on function entry, but not exit.
-
-If the function enters and exits without the lock held, acquiring and
-releasing the lock inside the function in a balanced way, no
-annotation is needed.  The three annotations above are for cases where
-sparse would otherwise report a context imbalance.
-
 Getting sparse
 --------------
 
diff --git a/include/linux/compiler-capability-analysis.h b/include/linux/compiler-capability-analysis.h
index 832727fea140..741f88e1177f 100644
--- a/include/linux/compiler-capability-analysis.h
+++ b/include/linux/compiler-capability-analysis.h
@@ -231,30 +231,8 @@
 	extern const struct __capability_##cap *name
 
 /*
- * Common keywords for static capability analysis. Both Clang's capability
- * analysis and Sparse's context tracking are currently supported.
+ * Common keywords for static capability analysis.
  */
-#ifdef __CHECKER__
-
-/* Sparse context/lock checking support. */
-# define __must_hold(x)		__attribute__((context(x,1,1)))
-# define __must_not_hold(x)
-# define __acquires(x)		__attribute__((context(x,0,1)))
-# define __cond_acquires(ret, x) __attribute__((context(x,0,-1)))
-# define __releases(x)		__attribute__((context(x,1,0)))
-# define __acquire(x)		__context__(x,1)
-# define __release(x)		__context__(x,-1)
-# define __cond_lock(x, c)	((c) ? ({ __acquire(x); 1; }) : 0)
-/* For Sparse, there's no distinction between exclusive and shared locks. */
-# define __must_hold_shared	__must_hold
-# define __acquires_shared	__acquires
-# define __cond_acquires_shared __cond_acquires
-# define __releases_shared	__releases
-# define __acquire_shared	__acquire
-# define __release_shared	__release
-# define __cond_lock_shared	__cond_acquire
-
-#else /* !__CHECKER__ */
 
 /**
  * __must_hold() - function attribute, caller must hold exclusive capability
@@ -263,7 +241,7 @@
  * Function attribute declaring that the caller must hold the given capability
  * instance @x exclusively.
  */
-# define __must_hold(x)		__requires_cap(x)
+#define __must_hold(x)		__requires_cap(x)
 
 /**
  * __must_not_hold() - function attribute, caller must not hold capability
@@ -272,7 +250,7 @@
  * Function attribute declaring that the caller must not hold the given
  * capability instance @x.
  */
-# define __must_not_hold(x)	__excludes_cap(x)
+#define __must_not_hold(x)	__excludes_cap(x)
 
 /**
  * __acquires() - function attribute, function acquires capability exclusively
@@ -281,7 +259,7 @@
  * Function attribute declaring that the function acquires the given
  * capability instance @x exclusively, but does not release it.
  */
-# define __acquires(x)		__acquires_cap(x)
+#define __acquires(x)		__acquires_cap(x)
 
 /*
  * Clang's analysis does not care precisely about the value, only that it is
@@ -308,7 +286,7 @@
  *
  * @ret may be one of: true, false, nonzero, 0, nonnull, NULL.
  */
-# define __cond_acquires(ret, x) __cond_acquires_impl_##ret(x)
+#define __cond_acquires(ret, x) __cond_acquires_impl_##ret(x)
 
 /**
  * __releases() - function attribute, function releases a capability exclusively
@@ -317,7 +295,7 @@
  * Function attribute declaring that the function releases the given capability
  * instance @x exclusively. The capability must be held on entry.
  */
-# define __releases(x)		__releases_cap(x)
+#define __releases(x)		__releases_cap(x)
 
 /**
  * __acquire() - function to acquire capability exclusively
@@ -325,7 +303,7 @@
  *
  * No-op function that acquires the given capability instance @x exclusively.
  */
-# define __acquire(x)		__acquire_cap(x)
+#define __acquire(x)		__acquire_cap(x)
 
 /**
  * __release() - function to release capability exclusively
@@ -333,7 +311,7 @@
  *
  * No-op function that releases the given capability instance @x.
  */
-# define __release(x)		__release_cap(x)
+#define __release(x)		__release_cap(x)
 
 /**
  * __cond_lock() - function that conditionally acquires a capability
@@ -352,7 +330,7 @@
  *
  *	#define spin_trylock(l) __cond_lock(&lock, _spin_trylock(&lock))
  */
-# define __cond_lock(x, c)	__try_acquire_cap(x, c)
+#define __cond_lock(x, c)	__try_acquire_cap(x, c)
 
 /**
  * __must_hold_shared() - function attribute, caller must hold shared capability
@@ -361,7 +339,7 @@
  * Function attribute declaring that the caller must hold the given capability
  * instance @x with shared access.
  */
-# define __must_hold_shared(x)	__requires_shared_cap(x)
+#define __must_hold_shared(x)	__requires_shared_cap(x)
 
 /**
  * __acquires_shared() - function attribute, function acquires capability shared
@@ -370,7 +348,7 @@
  * Function attribute declaring that the function acquires the given
  * capability instance @x with shared access, but does not release it.
  */
-# define __acquires_shared(x)	__acquires_shared_cap(x)
+#define __acquires_shared(x)	__acquires_shared_cap(x)
 
 /**
  * __cond_acquires_shared() - function attribute, function conditionally
@@ -384,7 +362,7 @@
  *
  * @ret may be one of: true, false, nonzero, 0, nonnull, NULL.
  */
-# define __cond_acquires_shared(ret, x) __cond_acquires_impl_##ret(x, _shared)
+#define __cond_acquires_shared(ret, x) __cond_acquires_impl_##ret(x, _shared)
 
 /**
  * __releases_shared() - function attribute, function releases a
@@ -394,7 +372,7 @@
  * Function attribute declaring that the function releases the given capability
  * instance @x with shared access. The capability must be held on entry.
  */
-# define __releases_shared(x)	__releases_shared_cap(x)
+#define __releases_shared(x)	__releases_shared_cap(x)
 
 /**
  * __acquire_shared() - function to acquire capability shared
@@ -403,7 +381,7 @@
  * No-op function that acquires the given capability instance @x with shared
  * access.
  */
-# define __acquire_shared(x)	__acquire_shared_cap(x)
+#define __acquire_shared(x)	__acquire_shared_cap(x)
 
 /**
  * __release_shared() - function to release capability shared
@@ -412,7 +390,7 @@
  * No-op function that releases the given capability instance @x with shared
  * access.
  */
-# define __release_shared(x)	__release_shared_cap(x)
+#define __release_shared(x)	__release_shared_cap(x)
 
 /**
  * __cond_lock_shared() - function that conditionally acquires a capability
@@ -426,8 +404,6 @@
  * access, if the boolean expression @c is true. The result of @c is the return
  * value, to be able to create a capability-enabled interface.
  */
-# define __cond_lock_shared(x, c) __try_acquire_shared_cap(x, c)
-
-#endif /* __CHECKER__ */
+#define __cond_lock_shared(x, c) __try_acquire_shared_cap(x, c)
 
 #endif /* _LINUX_COMPILER_CAPABILITY_ANALYSIS_H */
diff --git a/include/linux/rcupdate.h b/include/linux/rcupdate.h
index ef8875c4e621..75a2e8c30a3f 100644
--- a/include/linux/rcupdate.h
+++ b/include/linux/rcupdate.h
@@ -1183,20 +1183,7 @@ rcu_head_after_call_rcu(struct rcu_head *rhp, rcu_callback_t f)
 extern int rcu_expedited;
 extern int rcu_normal;
 
-DEFINE_LOCK_GUARD_0(rcu,
-	do {
-		rcu_read_lock();
-		/*
-		 * sparse doesn't call the cleanup function,
-		 * so just release immediately and don't track
-		 * the context. We don't need to anyway, since
-		 * the whole point of the guard is to not need
-		 * the explicit unlock.
-		 */
-		__release(RCU);
-	} while (0),
-	rcu_read_unlock())
-
+DEFINE_LOCK_GUARD_0(rcu, rcu_read_lock(), rcu_read_unlock())
 DECLARE_LOCK_GUARD_0_ATTRS(rcu, __acquires_shared(RCU), __releases_shared(RCU));
 
 #endif /* __LINUX_RCUPDATE_H */
-- 
2.48.1.711.g2feabab25a-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250304092417.2873893-23-elver%40google.com.
