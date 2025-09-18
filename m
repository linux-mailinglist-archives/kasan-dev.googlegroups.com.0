Return-Path: <kasan-dev+bncBC7OBJGL2MHBBYFDWDDAMGQE3WHKMQI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23e.google.com (mail-lj1-x23e.google.com [IPv6:2a00:1450:4864:20::23e])
	by mail.lfdr.de (Postfix) with ESMTPS id 04DF0B84FCC
	for <lists+kasan-dev@lfdr.de>; Thu, 18 Sep 2025 16:06:26 +0200 (CEST)
Received: by mail-lj1-x23e.google.com with SMTP id 38308e7fff4ca-34cc36bd494sf5907361fa.3
        for <lists+kasan-dev@lfdr.de>; Thu, 18 Sep 2025 07:06:25 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758204385; cv=pass;
        d=google.com; s=arc-20240605;
        b=Z9EVh4X+sdMKoeWaQcp1HpWcyoPrALhsD/my1vkY6l7kEHMCdLy99ZQ7LLSr+nwMcx
         E+1511fNlJe7a4vBOH6efChO99mG3I3sckSgIz9osel1906itjenLj0FRnG4zKw3wB9d
         jgxBumWTSjq4tpDKhLA8xOZWIkAmY43qhSAeJFoqFvXltXuEb1bGVFTe1YJ72mwQ8noW
         HDkSL/JeJJfj6/+hDsQR0h6OYVVQUEQX3cKqWPWHfYYHZe48YVHcbmiw7dTjMHJoAQ+w
         H72KnWTm0EzJTofeo3oe214cqobViiYbsmD+oVoVozfZOBmWOXI04Rta8KSTFtd2I+CM
         32JQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=QCA1P/I0IbYCZmH8l+XEFrex1daiWSvMDs/J9CMb+Fs=;
        fh=2r25MAfNFF8kbRrwVgySIk3VwDMFMJ82VebrOD8JTyY=;
        b=Kk58oM6cOYQeBg8EPzZJQqRMsQuRNAcuQMQjrqLZkMVzduXwSWSUZavtqkLaJvo3a2
         SXelomOT8I+64OnF7QeAozZ5TqapO5TmKxViTSDLPqgnxUNQxmz0mfZgW1yGzc4iyEAV
         NgPcJm9KUSmLf7XAWt/ZEXrxghgJh3rpBsDfzAeuSKV/O4qhf8Gap4iGnnKnxcUxoqQx
         Sd7eDM2JVHK+cDRPYlGAiTAt1V96L6561rMh/km0pIgr6eK0IctQvGWgvEhC/RfN6itt
         L+uLjOIAe1ZuLDm6tS+QOllNhwy4kI+A/drJZti0kAQsyENw2qEfhDAQ67p+8frdRKMR
         wpiQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=a5j9E88g;
       spf=pass (google.com: domain of 33rhmaaukcx4gnxgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=33RHMaAUKCX4gnxgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758204385; x=1758809185; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=QCA1P/I0IbYCZmH8l+XEFrex1daiWSvMDs/J9CMb+Fs=;
        b=kRFBYx1aJrOs3g7nLk5uqeEfzcdlbrBIWsvS+xD2vcFtQkJ0W4sMR1XBCYKWLY27LA
         8yMSn/1wxe3yOt7ZzsGaP3nzTRgtdH0EjilQ14SnycTai2uUBsvW8JkYYa8CJKClIys2
         q2iqg90MHRx8jXdvDgs7V1vbHYuqwUU52U/qPOq7j+9+MU5XvATk1RFhnhOIWWov+BvZ
         kg47l7ge8ZjcnteB5BLbGyXhRdi1sPTq5YAWmtcC6IPztPoRArQBszLlibVeTgg4Z+b1
         NJNbbBUswBHctRZIGA/tfVMInLcyVM0OE44tIxD538nxsW+qPone9ixog3z3pJ+BYjyg
         u/eA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758204385; x=1758809185;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=QCA1P/I0IbYCZmH8l+XEFrex1daiWSvMDs/J9CMb+Fs=;
        b=INSvOfxm13DZhtGU/bnhTEDY35IJQWmPEbnpRWt42I9ZDm6jKG2PeJV/ZR+W/lFi+I
         XOBJ8D5SRJkDKQnbzgdEZu0poUbaNcfMA5t3fJVcjBK0dqi9aQGsrKkQ8c6Wr+LlRahZ
         zqIEqv0rI9SY7ncJVD2+tDWdqY87rgjVNWwTs++eIcHnt3lTLYXojKZJs8csh23HcB57
         L26S24Umef2+5Iqdz+LcPHV+xDpWzZljxatQpgGOW28n7PAbdgC2iG21aGlDSlFkwEkf
         VmTyy4Fm1HFORbVnvjpLm1Y/XnJ4qtePpiCNqc3f0vSOK0jdAIq0qu+i+7+jmIN4U6+s
         ZdMw==
X-Forwarded-Encrypted: i=2; AJvYcCVJ4gu3Fs3Jtp4/VVewvVjxYrAQv2WhkVn80pfrNxpyauiCaM0OLsGHij4VCWOA8DbO4BAqsw==@lfdr.de
X-Gm-Message-State: AOJu0Yx9ZlTdWNu4h+55vpR3ajrCCwhOjESMFTuJQ/3hs4raNE4kkNbg
	iky2y11tIgjMbrYkrkYdD0wZx9kyr0byvQuxiZbNR1dYqwc/rD1GG431
X-Google-Smtp-Source: AGHT+IFX/TLcYtXH+Mzybad4DS7R5ovpEO0KdEswEWq7bUsgUgNQsYHvD7AvGF/kcFD57vcXzKPq6w==
X-Received: by 2002:a2e:a545:0:b0:336:8809:676b with SMTP id 38308e7fff4ca-35f5fe9d7ebmr16709351fa.4.1758204385058;
        Thu, 18 Sep 2025 07:06:25 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd4SiU+u5V+ZMA5h8duYtAYePPkOQPTwNZcuLjQRl5UmGw==
Received: by 2002:a05:651c:b06:b0:332:2df3:1cb6 with SMTP id
 38308e7fff4ca-361c8bdaa11ls2851521fa.2.-pod-prod-02-eu; Thu, 18 Sep 2025
 07:06:22 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVq1AHXLkN8Uc10YGfuFdQfmJEs4WB0DUqvyvTjyXF+1wAkdqPIMK5+nCOLvnMWsPvR+pkFsZhsNbc=@googlegroups.com
X-Received: by 2002:a2e:beab:0:b0:35f:fc7e:ce47 with SMTP id 38308e7fff4ca-35ffc7ed1a9mr17150141fa.40.1758204382032;
        Thu, 18 Sep 2025 07:06:22 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1758204382; cv=none;
        d=google.com; s=arc-20240605;
        b=ephO9gGpiSwtchx9AuFEVbFN3ABw7JApAdkeBWXsSxudXPby1EW0Ptg8wmqlKdpXHF
         w+0mQ6bBl7CAs88jfi52ezGEKhWKXu3+tQNULK+dFzPrqc6fe7ixqPM2O4vfzRp+e2+u
         qwcpP5ujjH1FDo40xqR+r1yTNEimBAew0NGfzqvBnVAO1jqk9/66wk+uVGiAhNrsf8r5
         jxT23HsH3sEM6fuKooMYNbb2MD8NuSvqDHi94AwXMU+fWNyAe4c2T2nv5hoISUajx6fC
         3wtBCB8Bm3ta/LJWhJI4eZUKdzl0MeOowElFOpyeyjqAUBHS65l4pJX7Zzmz7kcN32EE
         wGCg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=ELhsFQQQ03C4hLdoxnucw/8+AkmAKW9zLdfFvUdcDbU=;
        fh=/1/TsBh9GiEVyIFF93X1DulE5I09nwfElqmudtn/1+8=;
        b=ie+dt5QHpievTIP61PNUJ4af+ohzR3W0y7aKzt/Ibd7vHdQsDV6hkfeqK00+77we2M
         zltO8c1Jzzj2a5jU78MYQnfn0vVjDthNywckEZPSW5onpq1cDQ5q+eRqnAMqDa1GYE6/
         +4ovC1yxw8ZqvqOH6s3ZbP5Kvcjcypxy9myijlyQ684ztq+2yr8gqiStzS58IJ6/ki8y
         dK7EjPQtHcUz9G7lM1Zae1RGkGzSWmKE5XBg+7n7SLYbxh2rzl0Y63Zn75HDumIDeMSH
         cNxHwx7O1EsJPNdOPHY3mk5+WCX9yeezj/m9ds1DusIm1OiG6g1dzTqLBRTGG5X5upCX
         KwhQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=a5j9E88g;
       spf=pass (google.com: domain of 33rhmaaukcx4gnxgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=33RHMaAUKCX4gnxgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x34a.google.com (mail-wm1-x34a.google.com. [2a00:1450:4864:20::34a])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-361a6d7c976si411721fa.5.2025.09.18.07.06.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 18 Sep 2025 07:06:22 -0700 (PDT)
Received-SPF: pass (google.com: domain of 33rhmaaukcx4gnxgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) client-ip=2a00:1450:4864:20::34a;
Received: by mail-wm1-x34a.google.com with SMTP id 5b1f17b1804b1-45f2f15003aso6521855e9.0
        for <kasan-dev@googlegroups.com>; Thu, 18 Sep 2025 07:06:21 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUfowkvAtFECpovoVdgmiI+MrBDtgccpJtS1/VcYCaPflgnLMZuKLJhaFr0NJCEPKBgARGLmpO/06c=@googlegroups.com
X-Received: from wmbbi7.prod.google.com ([2002:a05:600c:3d87:b0:45d:d522:48a9])
 (user=elver job=prod-delivery.src-stubby-dispatcher) by 2002:a05:600c:2a93:b0:462:cd41:c2f8
 with SMTP id 5b1f17b1804b1-464c6761397mr28424195e9.5.1758204381270; Thu, 18
 Sep 2025 07:06:21 -0700 (PDT)
Date: Thu, 18 Sep 2025 15:59:31 +0200
In-Reply-To: <20250918140451.1289454-1-elver@google.com>
Mime-Version: 1.0
References: <20250918140451.1289454-1-elver@google.com>
X-Mailer: git-send-email 2.51.0.384.g4c02a37b29-goog
Message-ID: <20250918140451.1289454-21-elver@google.com>
Subject: [PATCH v3 20/35] locking/ww_mutex: Support Clang's capability analysis
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
 header.i=@google.com header.s=20230601 header.b=a5j9E88g;       spf=pass
 (google.com: domain of 33rhmaaukcx4gnxgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=33RHMaAUKCX4gnxgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--elver.bounces.google.com;
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

Add support for Clang's capability analysis for ww_mutex.

The programming model for ww_mutex is subtly more complex than other
locking primitives when using ww_acquire_ctx. Encoding the respective
pre-conditions for ww_mutex lock/unlock based on ww_acquire_ctx state
using Clang's capability analysis makes incorrect use of the API harder.

Signed-off-by: Marco Elver <elver@google.com>
---
v3:
* __assert -> __assume rename

v2:
* New patch.
---
 .../dev-tools/capability-analysis.rst         |  3 +-
 include/linux/ww_mutex.h                      | 22 ++++--
 lib/test_capability-analysis.c                | 69 +++++++++++++++++++
 3 files changed, 87 insertions(+), 7 deletions(-)

diff --git a/Documentation/dev-tools/capability-analysis.rst b/Documentation/dev-tools/capability-analysis.rst
index 9fb964e94920..2b89d346723b 100644
--- a/Documentation/dev-tools/capability-analysis.rst
+++ b/Documentation/dev-tools/capability-analysis.rst
@@ -82,7 +82,8 @@ Supported Kernel Primitives
 
 Currently the following synchronization primitives are supported:
 `raw_spinlock_t`, `spinlock_t`, `rwlock_t`, `mutex`, `seqlock_t`,
-`bit_spinlock`, RCU, SRCU (`srcu_struct`), `rw_semaphore`, `local_lock_t`.
+`bit_spinlock`, RCU, SRCU (`srcu_struct`), `rw_semaphore`, `local_lock_t`,
+`ww_mutex`.
 
 For capabilities with an initialization function (e.g., `spin_lock_init()`),
 calling this function on the capability instance before initializing any
diff --git a/include/linux/ww_mutex.h b/include/linux/ww_mutex.h
index 45ff6f7a872b..549d75aee76a 100644
--- a/include/linux/ww_mutex.h
+++ b/include/linux/ww_mutex.h
@@ -44,7 +44,7 @@ struct ww_class {
 	unsigned int is_wait_die;
 };
 
-struct ww_mutex {
+struct_with_capability(ww_mutex) {
 	struct WW_MUTEX_BASE base;
 	struct ww_acquire_ctx *ctx;
 #ifdef DEBUG_WW_MUTEXES
@@ -52,7 +52,7 @@ struct ww_mutex {
 #endif
 };
 
-struct ww_acquire_ctx {
+struct_with_capability(ww_acquire_ctx) {
 	struct task_struct *task;
 	unsigned long stamp;
 	unsigned int acquired;
@@ -107,6 +107,7 @@ struct ww_acquire_ctx {
  */
 static inline void ww_mutex_init(struct ww_mutex *lock,
 				 struct ww_class *ww_class)
+	__assumes_cap(lock)
 {
 	ww_mutex_base_init(&lock->base, ww_class->mutex_name, &ww_class->mutex_key);
 	lock->ctx = NULL;
@@ -141,6 +142,7 @@ static inline void ww_mutex_init(struct ww_mutex *lock,
  */
 static inline void ww_acquire_init(struct ww_acquire_ctx *ctx,
 				   struct ww_class *ww_class)
+	__acquires(ctx) __no_capability_analysis
 {
 	ctx->task = current;
 	ctx->stamp = atomic_long_inc_return_relaxed(&ww_class->stamp);
@@ -179,6 +181,7 @@ static inline void ww_acquire_init(struct ww_acquire_ctx *ctx,
  * data structures.
  */
 static inline void ww_acquire_done(struct ww_acquire_ctx *ctx)
+	__releases(ctx) __acquires_shared(ctx) __no_capability_analysis
 {
 #ifdef DEBUG_WW_MUTEXES
 	lockdep_assert_held(ctx);
@@ -196,6 +199,7 @@ static inline void ww_acquire_done(struct ww_acquire_ctx *ctx)
  * mutexes have been released with ww_mutex_unlock.
  */
 static inline void ww_acquire_fini(struct ww_acquire_ctx *ctx)
+	__releases_shared(ctx) __no_capability_analysis
 {
 #ifdef CONFIG_DEBUG_LOCK_ALLOC
 	mutex_release(&ctx->first_lock_dep_map, _THIS_IP_);
@@ -245,7 +249,8 @@ static inline void ww_acquire_fini(struct ww_acquire_ctx *ctx)
  *
  * A mutex acquired with this function must be released with ww_mutex_unlock.
  */
-extern int /* __must_check */ ww_mutex_lock(struct ww_mutex *lock, struct ww_acquire_ctx *ctx);
+extern int /* __must_check */ ww_mutex_lock(struct ww_mutex *lock, struct ww_acquire_ctx *ctx)
+	__cond_acquires(0, lock) __must_hold(ctx);
 
 /**
  * ww_mutex_lock_interruptible - acquire the w/w mutex, interruptible
@@ -278,7 +283,8 @@ extern int /* __must_check */ ww_mutex_lock(struct ww_mutex *lock, struct ww_acq
  * A mutex acquired with this function must be released with ww_mutex_unlock.
  */
 extern int __must_check ww_mutex_lock_interruptible(struct ww_mutex *lock,
-						    struct ww_acquire_ctx *ctx);
+						    struct ww_acquire_ctx *ctx)
+	__cond_acquires(0, lock) __must_hold(ctx);
 
 /**
  * ww_mutex_lock_slow - slowpath acquiring of the w/w mutex
@@ -305,6 +311,7 @@ extern int __must_check ww_mutex_lock_interruptible(struct ww_mutex *lock,
  */
 static inline void
 ww_mutex_lock_slow(struct ww_mutex *lock, struct ww_acquire_ctx *ctx)
+	__acquires(lock) __must_hold(ctx) __no_capability_analysis
 {
 	int ret;
 #ifdef DEBUG_WW_MUTEXES
@@ -342,6 +349,7 @@ ww_mutex_lock_slow(struct ww_mutex *lock, struct ww_acquire_ctx *ctx)
 static inline int __must_check
 ww_mutex_lock_slow_interruptible(struct ww_mutex *lock,
 				 struct ww_acquire_ctx *ctx)
+	__cond_acquires(0, lock) __must_hold(ctx)
 {
 #ifdef DEBUG_WW_MUTEXES
 	DEBUG_LOCKS_WARN_ON(!ctx->contending_lock);
@@ -349,10 +357,11 @@ ww_mutex_lock_slow_interruptible(struct ww_mutex *lock,
 	return ww_mutex_lock_interruptible(lock, ctx);
 }
 
-extern void ww_mutex_unlock(struct ww_mutex *lock);
+extern void ww_mutex_unlock(struct ww_mutex *lock) __releases(lock);
 
 extern int __must_check ww_mutex_trylock(struct ww_mutex *lock,
-					 struct ww_acquire_ctx *ctx);
+					 struct ww_acquire_ctx *ctx)
+	__cond_acquires(true, lock) __must_hold(ctx);
 
 /***
  * ww_mutex_destroy - mark a w/w mutex unusable
@@ -363,6 +372,7 @@ extern int __must_check ww_mutex_trylock(struct ww_mutex *lock,
  * this function is called.
  */
 static inline void ww_mutex_destroy(struct ww_mutex *lock)
+	__must_not_hold(lock)
 {
 #ifndef CONFIG_PREEMPT_RT
 	mutex_destroy(&lock->base);
diff --git a/lib/test_capability-analysis.c b/lib/test_capability-analysis.c
index e506dadb3933..12fd9716f0a4 100644
--- a/lib/test_capability-analysis.c
+++ b/lib/test_capability-analysis.c
@@ -14,6 +14,7 @@
 #include <linux/seqlock.h>
 #include <linux/spinlock.h>
 #include <linux/srcu.h>
+#include <linux/ww_mutex.h>
 
 /*
  * Test that helper macros work as expected.
@@ -523,3 +524,71 @@ static void __used test_local_trylock(void)
 		local_unlock(&test_local_trylock_data.lock);
 	}
 }
+
+static DEFINE_WD_CLASS(ww_class);
+
+struct test_ww_mutex_data {
+	struct ww_mutex mtx;
+	int counter __guarded_by(&mtx);
+};
+
+static void __used test_ww_mutex_init(struct test_ww_mutex_data *d)
+{
+	ww_mutex_init(&d->mtx, &ww_class);
+	d->counter = 0;
+}
+
+static void __used test_ww_mutex_lock_noctx(struct test_ww_mutex_data *d)
+{
+	if (!ww_mutex_lock(&d->mtx, NULL)) {
+		d->counter++;
+		ww_mutex_unlock(&d->mtx);
+	}
+
+	if (!ww_mutex_lock_interruptible(&d->mtx, NULL)) {
+		d->counter++;
+		ww_mutex_unlock(&d->mtx);
+	}
+
+	if (ww_mutex_trylock(&d->mtx, NULL)) {
+		d->counter++;
+		ww_mutex_unlock(&d->mtx);
+	}
+
+	ww_mutex_lock_slow(&d->mtx, NULL);
+	d->counter++;
+	ww_mutex_unlock(&d->mtx);
+
+	ww_mutex_destroy(&d->mtx);
+}
+
+static void __used test_ww_mutex_lock_ctx(struct test_ww_mutex_data *d)
+{
+	struct ww_acquire_ctx ctx;
+
+	ww_acquire_init(&ctx, &ww_class);
+
+	if (!ww_mutex_lock(&d->mtx, &ctx)) {
+		d->counter++;
+		ww_mutex_unlock(&d->mtx);
+	}
+
+	if (!ww_mutex_lock_interruptible(&d->mtx, &ctx)) {
+		d->counter++;
+		ww_mutex_unlock(&d->mtx);
+	}
+
+	if (ww_mutex_trylock(&d->mtx, &ctx)) {
+		d->counter++;
+		ww_mutex_unlock(&d->mtx);
+	}
+
+	ww_mutex_lock_slow(&d->mtx, &ctx);
+	d->counter++;
+	ww_mutex_unlock(&d->mtx);
+
+	ww_acquire_done(&ctx);
+	ww_acquire_fini(&ctx);
+
+	ww_mutex_destroy(&d->mtx);
+}
-- 
2.51.0.384.g4c02a37b29-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250918140451.1289454-21-elver%40google.com.
