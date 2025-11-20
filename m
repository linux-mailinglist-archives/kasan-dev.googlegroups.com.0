Return-Path: <kasan-dev+bncBC7OBJGL2MHBBCHA7TEAMGQECAMQHVY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x137.google.com (mail-lf1-x137.google.com [IPv6:2a00:1450:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id A1250C74C5D
	for <lists+kasan-dev@lfdr.de>; Thu, 20 Nov 2025 16:13:13 +0100 (CET)
Received: by mail-lf1-x137.google.com with SMTP id 2adb3069b0e04-59436279838sf1186211e87.0
        for <lists+kasan-dev@lfdr.de>; Thu, 20 Nov 2025 07:13:13 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1763651593; cv=pass;
        d=google.com; s=arc-20240605;
        b=LsZhnEGk/Q4Q//Q2fKvpqwP6JXg+FzePE688F+o6gUsYsHFiyIqIhCWU+VO8BVvKN9
         bO+gx8oxkC1T4LE2v31KF9hEOt2JSOPBpWI5YpIGiKjmqVPPrHdsQ0bccMZ8/3ceZVUz
         RZkW4sl48va0HGW8HUXm4MSsXgO25iLiO+Ta57n3RHX6LCYONicRn/MziDa3o3tBCjX6
         EA4I2qOafYyhA8KCoSUqCaNC+uUlQoDgxjVe2cCc8ptZmFcoYalH7Iy35MQLCbhq3H6M
         7d5bX70ZYB8QpMm0UJ7ffapvkLLlhOYP4soYywy8UNBm0sUKOIK3s/ByddfHN0SRlHdn
         BqwQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=LyzP4AF2GxuSj7ddWKQvxQuB0cB/W7suD9/VWLc/4lo=;
        fh=xg0VOaluPsDDaSVO6xVVylc6kmHly0c0AGHMYDDo5o4=;
        b=JANN0wptL5eTDx9LSFSNFyuwAzdyHa27aTn4Q+LPTYWt9ounPQkMihUZ6S+kHT+B6y
         x7WcspPfgawWjPLHrqTl6Z4tgzL0C5+q5CMpwZ/LxckdmK7iyyzyclDGijnA6qynA/JJ
         Gb6wjvZIVlj+RuqTKSLKFyVTHtbvfZLaY9yx4ZTmC147XBHNfcbZ5LccBUw2DN+S7tIU
         w45VHg36Xu0zaG2nerTGLUPQxgTcV1MzqrcfstYGZorLz4uCkKLdRTY2p6WQJwDyXj7E
         wNXvTDucnRUZkCpcByedxuDnuoFG0NFcsnsUvwjai9c2pUePoW2vZhAIGe3YQPzCbDxN
         8I4w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=XMvK2Mhe;
       spf=pass (google.com: domain of 3bdafaqukcteryiretbbtyr.pbzxnfna-qritbbtyrtebhcf.pbz@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3BDAfaQUKCTERYiReTbbTYR.PbZXNfNa-QRiTbbTYRTebhcf.PbZ@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1763651593; x=1764256393; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=LyzP4AF2GxuSj7ddWKQvxQuB0cB/W7suD9/VWLc/4lo=;
        b=TAdyFUunSv9xUsxh+8sg0P6d1uTqGPgGitZSVtE8RjvXnDx1TWK4t8sFEw7wmiShe8
         eCJWurT9uNrNZWnZw+uX87W6gdYFGd1HY/ma8qGgZx4ew1Q8WMKkJ/efYEhaoMEXcA2t
         ML78wONviN3GLZO2vYjnXvg/yP6TbwdYErGm2wLo4ApYwZRb8UhfbSHxKZCc0BwWutPP
         wxKp7zfGYiAWaFmizI+UbJ2Bai8rKl1kFIQg1rj0qYDW1gP1mpPOJQTCgXuI9ZNXjYze
         wEsfZuNuhOTiz+unRkNXK1SX240HNWQTI69CZl1lGGgz4cdkBP5B0ZAdr4aBXvUeAVV5
         vO2Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1763651593; x=1764256393;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=LyzP4AF2GxuSj7ddWKQvxQuB0cB/W7suD9/VWLc/4lo=;
        b=QgHk3yx3IE8w2CRRJ/N5S3Q+gzmS8a99gsJnyjW/DxhfftbYxdjc/1BwH2RtPMur14
         uZ3ENjKadXY3U8zobVYy/Q2x85PrgaoqTHh/WFyXftvLwmD70Qzg/AhTTzUSGxYpMowU
         naSmPR70o1Z2+QYP9X2DDzsy9fT6rFCWDpcRuE1O/W0YYdrl6+XqvuitK+vL3bgWGw9q
         HxdMChOehzvOuIS0GNbwgmF8uJIYdbGEZnWebll6ZyX0q/oWjpRLGOkE1CsDjlQ3M8ET
         Fs+SMNkdpakkL42Po9At/g+okHfLUFhAEbsB6kbzWHRQ5q46T7OsqYtG5Fd++3B0XduY
         wcpw==
X-Forwarded-Encrypted: i=2; AJvYcCWoIe8UFRniKm9SmB7CafM5B9nXhMs7MmuqtBAIT353EQM5qfCcHB4Q982re01BuKIWbwD4iw==@lfdr.de
X-Gm-Message-State: AOJu0YxZIEq6laH05lTsFbvzj7DsCnZP59wIqCMHQmbwQbOWWhyK53wv
	90nXyceayZkoYS40JWT/WDFoI7mvvJ3muNHiq2jK6NZBkSB7OvjhzIq0
X-Google-Smtp-Source: AGHT+IFBPmq+Fy2CELRAd6Wvpp7LLTrF8B2McnmQR2cC5GeTzxpAbP2DGdsy8Khiiq/IWS0B6ZaojQ==
X-Received: by 2002:a05:6512:3b20:b0:595:7dcc:3a8d with SMTP id 2adb3069b0e04-5969e3224bcmr1144932e87.48.1763651592638;
        Thu, 20 Nov 2025 07:13:12 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+a+bhLoxVDHGd39Cq2fCqUtI5Uzw4esb/WdrNfwi4KI0A=="
Received: by 2002:ac2:4f15:0:b0:596:a251:4d4f with SMTP id 2adb3069b0e04-596a2514deals46026e87.2.-pod-prod-05-eu;
 Thu, 20 Nov 2025 07:13:09 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXnQvWSny+3VE5DdqSQyyGZNdiRlsyyaPFp9fCqnKiMdD3WUXDi1jVt1hwun8b7VfE4whrv3tTdu2s=@googlegroups.com
X-Received: by 2002:a05:6512:33cc:b0:594:4b7f:f946 with SMTP id 2adb3069b0e04-5969e30c6b6mr1276980e87.33.1763651589428;
        Thu, 20 Nov 2025 07:13:09 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1763651589; cv=none;
        d=google.com; s=arc-20240605;
        b=fKs1aQD4ssdESs4rZ8IIDaqhYKCR0AqGcV8uq2m7kVAnfztlabCyG4gAUsULZMC4u6
         vpyA/rF9FUZyg1+sDzEQjuIFmU1Bjo6GqNykaorc+o9i3lA+Ux80NoouEMkVS6+p6One
         xDlV8rw420DJD0c59I/FxbKgOrNo05TdobKiGWqf8YvxrAkrVu7t2wQCgVLrXFMAcH3C
         0NyQ88XzRzQMPSoTMv83VFtRhLp3sYWChhH6lRkg7ZBO5Y31gfEw5wPDJqB0xpVkupzC
         UmFz5TtbqyHgQwnjNQcWD4DSsirtRTnH2NkkMfNRf92LcMcuGKvDKkCENckA+Av/Y6U1
         pA5A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=dkmPbZNSmdMyreEK/bsAoZcLQrwuNTqttZsMG2m8BsQ=;
        fh=fbS4oP/2bAMcRYI3lfIQJcYLjI5saS/oUdk6OsX/MCs=;
        b=WkbxVEQHkX26mdrrZbPZjGr+eESxeSD1DSNlM96O24udI/IHI+K3QFV1GxshRtAr3j
         czdZs7EtUWET+0znXWkIEVNZOLv5RMfL02UDp4ufJycLnL7cDAcZAN8aVGSeGY8ub3Ye
         +flDZkmxp8hUTEKPKuKoDCS2VrX+hOXMJAqQ9hyKQurC+SZFdfI7ItXAVqvIEJWlntoQ
         SzYF9FXedKrZa2P45Hig9o+9htg9YVpA2ebL4AlyHDVA3BJYe8HoanoMdpN3KUqBCCT6
         FwY7Ko20qi836+ru0ANQyZ1E5FODbb5+AYRl1JVwWKuTqW6TCCLASKjoW+lCU8cZrs1e
         burA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=XMvK2Mhe;
       spf=pass (google.com: domain of 3bdafaqukcteryiretbbtyr.pbzxnfna-qritbbtyrtebhcf.pbz@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3BDAfaQUKCTERYiReTbbTYR.PbZXNfNa-QRiTbbTYRTebhcf.PbZ@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x349.google.com (mail-wm1-x349.google.com. [2a00:1450:4864:20::349])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-5969dba093esi48140e87.3.2025.11.20.07.13.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 20 Nov 2025 07:13:09 -0800 (PST)
Received-SPF: pass (google.com: domain of 3bdafaqukcteryiretbbtyr.pbzxnfna-qritbbtyrtebhcf.pbz@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) client-ip=2a00:1450:4864:20::349;
Received: by mail-wm1-x349.google.com with SMTP id 5b1f17b1804b1-477563a0c75so5571995e9.1
        for <kasan-dev@googlegroups.com>; Thu, 20 Nov 2025 07:13:09 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCVaj+4OE7tew+K4dcUEaY/Yvb2KUpL3ouLJNlveI6KnH5y+9rKBfMhUNvq+9M91ELs4w7j7AxXdItw=@googlegroups.com
X-Received: from wmbbd8.prod.google.com ([2002:a05:600c:1f08:b0:470:fd92:351d])
 (user=elver job=prod-delivery.src-stubby-dispatcher) by 2002:a05:600c:1987:b0:45d:d97c:236c
 with SMTP id 5b1f17b1804b1-477b8a8a5damr33381975e9.21.1763651588400; Thu, 20
 Nov 2025 07:13:08 -0800 (PST)
Date: Thu, 20 Nov 2025 16:09:45 +0100
In-Reply-To: <20251120151033.3840508-7-elver@google.com>
Mime-Version: 1.0
References: <20251120145835.3833031-2-elver@google.com> <20251120151033.3840508-7-elver@google.com>
X-Mailer: git-send-email 2.52.0.rc1.455.g30608eb744-goog
Message-ID: <20251120151033.3840508-21-elver@google.com>
Subject: [PATCH v4 20/35] locking/ww_mutex: Support Clang's context analysis
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
 header.i=@google.com header.s=20230601 header.b=XMvK2Mhe;       spf=pass
 (google.com: domain of 3bdafaqukcteryiretbbtyr.pbzxnfna-qritbbtyrtebhcf.pbz@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3BDAfaQUKCTERYiReTbbTYR.PbZXNfNa-QRiTbbTYRTebhcf.PbZ@flex--elver.bounces.google.com;
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

Add support for Clang's context analysis for ww_mutex.

The programming model for ww_mutex is subtly more complex than other
locking primitives when using ww_acquire_ctx. Encoding the respective
pre-conditions for ww_mutex lock/unlock based on ww_acquire_ctx state
using Clang's context analysis makes incorrect use of the API harder.

Signed-off-by: Marco Elver <elver@google.com>
---
v4:
* Rename capability -> context analysis.

v3:
* __assert -> __assume rename

v2:
* New patch.
---
 Documentation/dev-tools/context-analysis.rst |  3 +-
 include/linux/ww_mutex.h                     | 22 +++++--
 lib/test_context-analysis.c                  | 69 ++++++++++++++++++++
 3 files changed, 87 insertions(+), 7 deletions(-)

diff --git a/Documentation/dev-tools/context-analysis.rst b/Documentation/dev-tools/context-analysis.rst
index 8737de63a707..2936666651f3 100644
--- a/Documentation/dev-tools/context-analysis.rst
+++ b/Documentation/dev-tools/context-analysis.rst
@@ -81,7 +81,8 @@ Supported Kernel Primitives
 
 Currently the following synchronization primitives are supported:
 `raw_spinlock_t`, `spinlock_t`, `rwlock_t`, `mutex`, `seqlock_t`,
-`bit_spinlock`, RCU, SRCU (`srcu_struct`), `rw_semaphore`, `local_lock_t`.
+`bit_spinlock`, RCU, SRCU (`srcu_struct`), `rw_semaphore`, `local_lock_t`,
+`ww_mutex`.
 
 For context guards with an initialization function (e.g., `spin_lock_init()`),
 calling this function before initializing any guarded members or globals
diff --git a/include/linux/ww_mutex.h b/include/linux/ww_mutex.h
index 45ff6f7a872b..f6253e8ba9af 100644
--- a/include/linux/ww_mutex.h
+++ b/include/linux/ww_mutex.h
@@ -44,7 +44,7 @@ struct ww_class {
 	unsigned int is_wait_die;
 };
 
-struct ww_mutex {
+context_guard_struct(ww_mutex) {
 	struct WW_MUTEX_BASE base;
 	struct ww_acquire_ctx *ctx;
 #ifdef DEBUG_WW_MUTEXES
@@ -52,7 +52,7 @@ struct ww_mutex {
 #endif
 };
 
-struct ww_acquire_ctx {
+context_guard_struct(ww_acquire_ctx) {
 	struct task_struct *task;
 	unsigned long stamp;
 	unsigned int acquired;
@@ -107,6 +107,7 @@ struct ww_acquire_ctx {
  */
 static inline void ww_mutex_init(struct ww_mutex *lock,
 				 struct ww_class *ww_class)
+	__assumes_ctx_guard(lock)
 {
 	ww_mutex_base_init(&lock->base, ww_class->mutex_name, &ww_class->mutex_key);
 	lock->ctx = NULL;
@@ -141,6 +142,7 @@ static inline void ww_mutex_init(struct ww_mutex *lock,
  */
 static inline void ww_acquire_init(struct ww_acquire_ctx *ctx,
 				   struct ww_class *ww_class)
+	__acquires(ctx) __no_context_analysis
 {
 	ctx->task = current;
 	ctx->stamp = atomic_long_inc_return_relaxed(&ww_class->stamp);
@@ -179,6 +181,7 @@ static inline void ww_acquire_init(struct ww_acquire_ctx *ctx,
  * data structures.
  */
 static inline void ww_acquire_done(struct ww_acquire_ctx *ctx)
+	__releases(ctx) __acquires_shared(ctx) __no_context_analysis
 {
 #ifdef DEBUG_WW_MUTEXES
 	lockdep_assert_held(ctx);
@@ -196,6 +199,7 @@ static inline void ww_acquire_done(struct ww_acquire_ctx *ctx)
  * mutexes have been released with ww_mutex_unlock.
  */
 static inline void ww_acquire_fini(struct ww_acquire_ctx *ctx)
+	__releases_shared(ctx) __no_context_analysis
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
+	__acquires(lock) __must_hold(ctx) __no_context_analysis
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
diff --git a/lib/test_context-analysis.c b/lib/test_context-analysis.c
index 74eca21f7aaa..522769c9586d 100644
--- a/lib/test_context-analysis.c
+++ b/lib/test_context-analysis.c
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
2.52.0.rc1.455.g30608eb744-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251120151033.3840508-21-elver%40google.com.
