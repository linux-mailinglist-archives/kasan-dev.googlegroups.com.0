Return-Path: <kasan-dev+bncBC7OBJGL2MHBBXNDWDDAMGQECZA2EJQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x340.google.com (mail-wm1-x340.google.com [IPv6:2a00:1450:4864:20::340])
	by mail.lfdr.de (Postfix) with ESMTPS id 192D1B84FC6
	for <lists+kasan-dev@lfdr.de>; Thu, 18 Sep 2025 16:06:23 +0200 (CEST)
Received: by mail-wm1-x340.google.com with SMTP id 5b1f17b1804b1-45b986a7b8asf5467725e9.0
        for <lists+kasan-dev@lfdr.de>; Thu, 18 Sep 2025 07:06:23 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758204382; cv=pass;
        d=google.com; s=arc-20240605;
        b=lJrnUYIuMMmDBMhCq7GbNu/dZZAUyUDDVpC6tRlTtUIfbpzGM/gSk6IwsuZDRRCkid
         m5I00FthtFf+ox+lzmtKsfmKQROSF4lgmeqkaYt73RC71ELzUqEcBZK8l/6RyyprXA6y
         v1ihrdmVohZnl0G26yqPjlxyNQsm9hWkZPzl3qy1NOpQiqBec9f2xsX4LOcYN23HKbfF
         0/Qc87RKAk49FZoY/ys5PaUeVE6IvBemX49WOUN7JvaXeYTbpnBdq0RN2aox5MwCzhSL
         iR7ktmuf6LTdtjx9P1wFMrfaRgKYr82O5Ctz8tugu7TMSlz7SYWvq36A2eY/vyy6l0r0
         LYRQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=l+5p10DDmUKbP5O+/XvyO54b1SmQztvFeYimQs10Tc0=;
        fh=bPpHpdS5BZfS8opbihs9GrdJfQ4xw5YWv7Uy0PZqlQc=;
        b=g5RsIO/ahcUDn+skYO4PPgZPr1VXEBR662f4dQ7K+196a0E9wzCFHgnNUAYzRa7osk
         FzEQJimIa22wZLkBfaH7rOCUv1Sg9LGfTsFHIkVYxPcne2vPCYXx4SEFPwP+l9y7qOyD
         kDs/eZkM8B/13Oanc4Z8YrYVxBLCohdhxgvJSaQfvU9zRzt2UWzZyI8eb+AJ/Luyp2CI
         BBswCwJsyZs7NTnyqZ5ataIza2xtGwbP/LQl1bHkOuymGLPPzb3kZiVywqcxJPUr+Gkj
         6yueOkyIdHvd6pp97DnLZ04yAxwUtcwL+/QRc+vuGms37lAvsq8+5GK24YgH2Q+yhLcZ
         Be/g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=4IBFIX52;
       spf=pass (google.com: domain of 32hhmaaukcxsdkudqfnnfkd.bnljzrzm-cdufnnfkdfqntor.bnl@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=32hHMaAUKCXsdkudqfnnfkd.bnljZrZm-cdufnnfkdfqntor.bnl@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758204382; x=1758809182; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=l+5p10DDmUKbP5O+/XvyO54b1SmQztvFeYimQs10Tc0=;
        b=RfQC5ijr6y2pBfNKuFz1/1DDJIsKicqeHLfG0PX0wUgI/6GGx9HTbQDuyl2ljiHDa1
         dwbfwdzobMrfZPdTIGs560kmqNTHcPC+zVkOpEW5k5apRj0AH2BwtEicWifFg9e5QDbA
         cZB0u4wlmZ1Ka/1Lk3kaHfTSM38P0Rd9y5F2iFXv+haUgbeFesXFidFMGjhD9rZ+RH1H
         45addJJ6VG1Z9KwOECjNXllCfsvkQK/CcvUTprj6/7P5eSkH6qQtlJec+zDvFpY3TRrW
         2EAmw/laN51hLspXH13XmADYhpscCpkzST/4g7NF2CDPcNo4wSxndWBKJ/J3E51xGheE
         HfqA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758204382; x=1758809182;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=l+5p10DDmUKbP5O+/XvyO54b1SmQztvFeYimQs10Tc0=;
        b=fTGQxt3SZd4Eqv8nVFWhsW2pPvqPlQEtQ5nW7znNNyv7tcNkop6XuHcRaa1kC6YNeu
         gTb9zb7AlS5pvsaOhoavVAEqFeIQq5PnApgenXWSwbqgjDWC67VS/9hsbiBtgczc7yxC
         wxhxZD8Sh8kGinMp4FeolcX9LO7phby5bpK1GIYkMeOkBOU8xC3zLIaNfr4DBXHQ0FZy
         1Ua3He84aF/LUBAzaBOfP2tapjZWknUuDsJnmjaoz/vgVhBv33HIlrXSB6lumEzzJUDd
         SaMGTR12b4tTtPNqmTTXq+9V05dtvW+Wmoh5FF1boze5uT9pVAE9WdSMIh2PwglA2kJY
         TTbg==
X-Forwarded-Encrypted: i=2; AJvYcCUlGHyJ04yfdhYoyJ76oHdPYZ22CkfGhBTASubvLXOTzmcrNj8O5X65xeAL0k4JdmumRF0jbQ==@lfdr.de
X-Gm-Message-State: AOJu0YyiM2txiyZm0oHJGZpna7ibWESGH1yAL6ojWzULfin7Q4hO8H0J
	RzMGNGQjOpmF2/96Vq8Mj2kMGjzzHpLbZIW7c0R5Rsje4j/JMGO2HoJY
X-Google-Smtp-Source: AGHT+IEtHxROp1Hmt8U03elkyzSO0Z8BRe+XmGH5hJ9F1zDvWLeSPFM+Vc2Xlos7F6Ol1ZczHXjQUQ==
X-Received: by 2002:a05:6000:1889:b0:3ee:1492:aeac with SMTP id ffacd0b85a97d-3ee1492bd04mr1493923f8f.38.1758204382373;
        Thu, 18 Sep 2025 07:06:22 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd4dgnapHKW0mURztJA9gSHpIAxxg+r8xrHZZGD0ItZOiQ==
Received: by 2002:a05:6000:40ca:b0:3ed:8e48:5e0d with SMTP id
 ffacd0b85a97d-3ee106bfb24ls558934f8f.1.-pod-prod-04-eu; Thu, 18 Sep 2025
 07:06:19 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWQCOxVZpkRKqpl37ot733b/m49MkzyNM1/kRN4XgxCrKFHt/QV/GfDyz5tRXwBoVvluLaYQp6Tz7o=@googlegroups.com
X-Received: by 2002:a05:6000:2305:b0:3ec:4eeb:48db with SMTP id ffacd0b85a97d-3ecdfa52bcfmr5833959f8f.36.1758204379703;
        Thu, 18 Sep 2025 07:06:19 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1758204379; cv=none;
        d=google.com; s=arc-20240605;
        b=TotAQ6STYA/zCOlPPiOfjKaKpIUrejSXvcwwT2PfpbY4HsWMnq6UNeaOMgaC3hwwwg
         jIX2/1++ztFjnrkxM7TeZUWB7Jr5JaotU14nkyYZpo58x4YaORwTKZ+fhHCR/sv9jUJ2
         cezwub/LkAz7Am1+VfXP3rFtmUNXsuX/Vp0O8Geu+IcZjNf8fdRm0Mn0N5asZDEHYAsV
         TB7L/fg4mUbAYlvDDdt67xDVAG7p7OuCplJ+TlbmmteuptNxMtoNoTnq5nUx6idP0SGF
         iwE3qOzbdvQq4in5KsyIPSGO0G4NJwr9oyCC3vvpN64h6fnginPK6rpYQS0oqsmqiIJi
         op9g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=q4us2nxi3JpTZDeL0scdeAdIw4lyPkneoFt53x8qoK8=;
        fh=nAkILN0Y7RBmUbJHghswVDHqg5tLbNLI7IkWT+GM0+4=;
        b=beENvOnvP54foIfbybnMwAkvbFNtONQe5S6IB+wE0VIIWtmj0O7mbXSqSBc+Kr8W+n
         lo5SJ+ZBYULp02Sny/3JGqiU786zm+iLvENQ1De+97cYlSNfwgENRGfDE5NpbuSOAF76
         sMxqhlt0iqYi6B8yMSIoHGAiKCV4pnTN4n/uf/X7TU0SrL44uDulja7iKdJV3efb+UsB
         rknUVhYCgIJgzfQYFrxXVK2nTlC11rD9HsQ87fCU45Ruj6YnSgyG1bVJBRZsnIJv7J/u
         RvtlY4Zt1X3a9kz/wdlNI5xRm8H40Punb9R8hsi6uO4IOjDbXY/N7Sa/a1XJMfUUpSvf
         grpw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=4IBFIX52;
       spf=pass (google.com: domain of 32hhmaaukcxsdkudqfnnfkd.bnljzrzm-cdufnnfkdfqntor.bnl@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=32hHMaAUKCXsdkudqfnnfkd.bnljZrZm-cdufnnfkdfqntor.bnl@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x44a.google.com (mail-wr1-x44a.google.com. [2a00:1450:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-465c53d4bcdsi330145e9.1.2025.09.18.07.06.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 18 Sep 2025 07:06:19 -0700 (PDT)
Received-SPF: pass (google.com: domain of 32hhmaaukcxsdkudqfnnfkd.bnljzrzm-cdufnnfkdfqntor.bnl@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) client-ip=2a00:1450:4864:20::44a;
Received: by mail-wr1-x44a.google.com with SMTP id ffacd0b85a97d-3ece0cb7c9cso670150f8f.1
        for <kasan-dev@googlegroups.com>; Thu, 18 Sep 2025 07:06:19 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXUytIrOGeulJi9AcLnKN7R6GKuuq8q4OJjkZriGK5hB3XpPFVDJCZg+toSwo3CwMSUeRv8lUvfyvM=@googlegroups.com
X-Received: from wrml2.prod.google.com ([2002:adf:e582:0:b0:3ec:dab8:7d45])
 (user=elver job=prod-delivery.src-stubby-dispatcher) by 2002:a05:6000:2307:b0:3e4:bb5f:ee6d
 with SMTP id ffacd0b85a97d-3ecdf9bed46mr5359337f8f.15.1758204378633; Thu, 18
 Sep 2025 07:06:18 -0700 (PDT)
Date: Thu, 18 Sep 2025 15:59:30 +0200
In-Reply-To: <20250918140451.1289454-1-elver@google.com>
Mime-Version: 1.0
References: <20250918140451.1289454-1-elver@google.com>
X-Mailer: git-send-email 2.51.0.384.g4c02a37b29-goog
Message-ID: <20250918140451.1289454-20-elver@google.com>
Subject: [PATCH v3 19/35] locking/local_lock: Support Clang's capability analysis
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
 header.i=@google.com header.s=20230601 header.b=4IBFIX52;       spf=pass
 (google.com: domain of 32hhmaaukcxsdkudqfnnfkd.bnljzrzm-cdufnnfkdfqntor.bnl@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=32hHMaAUKCXsdkudqfnnfkd.bnljZrZm-cdufnnfkdfqntor.bnl@flex--elver.bounces.google.com;
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

Add support for Clang's capability analysis for local_lock_t and
local_trylock_t.

Signed-off-by: Marco Elver <elver@google.com>
---
v3:
* Switch to DECLARE_LOCK_GUARD_1_ATTRS() (suggested by Peter)
* __assert -> __assume rename
* Rework __this_cpu_local_lock helper
* Support local_trylock_t
---
 .../dev-tools/capability-analysis.rst         |  2 +-
 include/linux/local_lock.h                    | 45 +++++++-----
 include/linux/local_lock_internal.h           | 71 ++++++++++++++----
 lib/test_capability-analysis.c                | 73 +++++++++++++++++++
 4 files changed, 156 insertions(+), 35 deletions(-)

diff --git a/Documentation/dev-tools/capability-analysis.rst b/Documentation/dev-tools/capability-analysis.rst
index 7a4c2238c910..9fb964e94920 100644
--- a/Documentation/dev-tools/capability-analysis.rst
+++ b/Documentation/dev-tools/capability-analysis.rst
@@ -82,7 +82,7 @@ Supported Kernel Primitives
 
 Currently the following synchronization primitives are supported:
 `raw_spinlock_t`, `spinlock_t`, `rwlock_t`, `mutex`, `seqlock_t`,
-`bit_spinlock`, RCU, SRCU (`srcu_struct`), `rw_semaphore`.
+`bit_spinlock`, RCU, SRCU (`srcu_struct`), `rw_semaphore`, `local_lock_t`.
 
 For capabilities with an initialization function (e.g., `spin_lock_init()`),
 calling this function on the capability instance before initializing any
diff --git a/include/linux/local_lock.h b/include/linux/local_lock.h
index 2ba846419524..cfdca5bee89e 100644
--- a/include/linux/local_lock.h
+++ b/include/linux/local_lock.h
@@ -13,13 +13,13 @@
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
@@ -28,19 +28,19 @@
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
@@ -49,7 +49,7 @@
  * @flags:      Interrupt flags to restore
  */
 #define local_unlock_irqrestore(lock, flags)			\
-	__local_unlock_irqrestore(this_cpu_ptr(lock), flags)
+	__local_unlock_irqrestore(__this_cpu_local_lock(lock), flags)
 
 /**
  * local_lock_init - Runtime initialize a lock instance
@@ -64,7 +64,7 @@
  * locking constrains it will _always_ fail to acquire the lock in NMI or
  * HARDIRQ context on PREEMPT_RT.
  */
-#define local_trylock(lock)		__local_trylock(this_cpu_ptr(lock))
+#define local_trylock(lock)		__local_trylock(__this_cpu_local_lock(lock))
 
 /**
  * local_trylock_irqsave - Try to acquire a per CPU local lock, save and disable
@@ -77,27 +77,32 @@
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
+	__local_unlock_nested_bh(__this_cpu_local_lock(_lock))
 
-DEFINE_GUARD(local_lock_nested_bh, local_lock_t __percpu*,
-	     local_lock_nested_bh(_T),
-	     local_unlock_nested_bh(_T))
+DEFINE_LOCK_GUARD_1(local_lock_nested_bh, local_lock_t __percpu,
+		    local_lock_nested_bh(_T->lock),
+		    local_unlock_nested_bh(_T->lock))
+
+DECLARE_LOCK_GUARD_1_ATTRS(local_lock, __assumes_cap(_T), /* */)
+DECLARE_LOCK_GUARD_1_ATTRS(local_lock_irq, __assumes_cap(_T), /* */)
+DECLARE_LOCK_GUARD_1_ATTRS(local_lock_irqsave, __assumes_cap(_T), /* */)
+DECLARE_LOCK_GUARD_1_ATTRS(local_lock_nested_bh, __assumes_cap(_T), /* */)
 
 #endif
diff --git a/include/linux/local_lock_internal.h b/include/linux/local_lock_internal.h
index 4c0e117d2d08..22ffaf06d9eb 100644
--- a/include/linux/local_lock_internal.h
+++ b/include/linux/local_lock_internal.h
@@ -10,18 +10,20 @@
 
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
 
 /* local_trylock() and local_trylock_irqsave() only work with local_trylock_t */
-typedef struct {
+struct_with_capability(local_trylock) {
 	local_lock_t	llock;
 	u8		acquired;
-} local_trylock_t;
+};
+typedef struct local_trylock local_trylock_t;
 
 #ifdef CONFIG_DEBUG_LOCK_ALLOC
 # define LOCAL_LOCK_DEBUG_INIT(lockname)		\
@@ -81,9 +83,14 @@ do {								\
 			      0, LD_WAIT_CONFIG, LD_WAIT_INV,	\
 			      LD_LOCK_PERCPU);			\
 	local_lock_debug_init(lock);				\
+	__assume_cap(lock);					\
 } while (0)
 
-#define __local_trylock_init(lock) __local_lock_init(lock.llock)
+#define __local_trylock_init(lock)				\
+do {								\
+	__local_lock_init(lock.llock);				\
+	__assume_cap(lock);					\
+} while (0)
 
 #define __spinlock_nested_bh_init(lock)				\
 do {								\
@@ -94,6 +101,7 @@ do {								\
 			      0, LD_WAIT_CONFIG, LD_WAIT_INV,	\
 			      LD_LOCK_NORMAL);			\
 	local_lock_debug_init(lock);				\
+	__assume_cap(lock);					\
 } while (0)
 
 #define __local_lock_acquire(lock)					\
@@ -116,22 +124,25 @@ do {								\
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
+	__try_acquire_cap(lock, ({				\
 		local_trylock_t *tl;				\
 								\
 		preempt_disable();				\
@@ -145,10 +156,10 @@ do {								\
 				(local_lock_t *)tl);		\
 		}						\
 		!!tl;						\
-	})
+	}))
 
 #define __local_trylock_irqsave(lock, flags)			\
-	({							\
+	__try_acquire_cap(lock, ({				\
 		local_trylock_t *tl;				\
 								\
 		local_irq_save(flags);				\
@@ -162,7 +173,7 @@ do {								\
 				(local_lock_t *)tl);		\
 		}						\
 		!!tl;						\
-	})
+	}))
 
 #define __local_lock_release(lock)					\
 	do {								\
@@ -182,18 +193,21 @@ do {								\
 
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
@@ -202,13 +216,19 @@ do {								\
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
@@ -263,7 +283,7 @@ do {								\
 } while (0)
 
 #define __local_trylock(lock)					\
-	({							\
+	__try_acquire_cap(lock, capability_unsafe(({		\
 		int __locked;					\
 								\
 		if (in_nmi() | in_hardirq()) {			\
@@ -275,13 +295,36 @@ do {								\
 				migrate_enable();		\
 		}						\
 		__locked;					\
-	})
+	})))
 
 #define __local_trylock_irqsave(lock, flags)			\
-	({							\
+	__try_acquire_cap(lock, ({				\
 		typecheck(unsigned long, flags);		\
 		flags = 0;					\
 		__local_trylock(lock);				\
-	})
+	}))
+
+#endif /* CONFIG_PREEMPT_RT */
 
+#if defined(WARN_CAPABILITY_ANALYSIS)
+/*
+ * Because the compiler only knows about the base per-CPU variable, use this
+ * helper function to make the compiler think we lock/unlock the @base variable,
+ * and hide the fact we actually pass the per-CPU instance to lock/unlock
+ * functions.
+ */
+static __always_inline local_lock_t *__this_cpu_local_lock(local_lock_t __percpu *base)
+	__returns_cap(base) __attribute__((overloadable))
+{
+	return this_cpu_ptr(base);
+}
+#ifndef CONFIG_PREEMPT_RT
+static __always_inline local_trylock_t *__this_cpu_local_lock(local_trylock_t __percpu *base)
+	__returns_cap(base) __attribute__((overloadable))
+{
+	return this_cpu_ptr(base);
+}
 #endif /* CONFIG_PREEMPT_RT */
+#else  /* WARN_CAPABILITY_ANALYSIS */
+#define __this_cpu_local_lock(base) this_cpu_ptr(base)
+#endif /* WARN_CAPABILITY_ANALYSIS */
diff --git a/lib/test_capability-analysis.c b/lib/test_capability-analysis.c
index 3c6dad0ba065..e506dadb3933 100644
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
@@ -450,3 +452,74 @@ static void __used test_srcu_guard(struct test_srcu_data *d)
 	guard(srcu)(&d->srcu);
 	(void)srcu_dereference(d->data, &d->srcu);
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
2.51.0.384.g4c02a37b29-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250918140451.1289454-20-elver%40google.com.
