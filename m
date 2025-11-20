Return-Path: <kasan-dev+bncBC7OBJGL2MHBB7G77TEAMGQE3AFTFQQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23a.google.com (mail-lj1-x23a.google.com [IPv6:2a00:1450:4864:20::23a])
	by mail.lfdr.de (Postfix) with ESMTPS id B275FC74C54
	for <lists+kasan-dev@lfdr.de>; Thu, 20 Nov 2025 16:13:01 +0100 (CET)
Received: by mail-lj1-x23a.google.com with SMTP id 38308e7fff4ca-37bbb9113e7sf10349221fa.1
        for <lists+kasan-dev@lfdr.de>; Thu, 20 Nov 2025 07:13:01 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1763651581; cv=pass;
        d=google.com; s=arc-20240605;
        b=Y+50cHS8m1FZX9dYuGk/vGF/VKPU4n2nbQP3jO0jrMlp8rXKJHgaEkQw1/Mu+xFoMo
         rK2JgpXXES9oJjVsvciua2TbXPfsWht9tN1qF6RAwgI/Xn7A6LZ9m/6U1kL5EC2hRjIt
         lUtELP+IjxCznjkfGF+ssfBEkdNCmCLGmqMhWlClv+VKbO+C1xFA5z4LfOJuvyynzDFQ
         c6YQn1bqbf+AepATZj4mso7d5cvHY2/aTRl5cbotSrB3+flZsfpeIacLo2OQL70deU/z
         zRrVVpBSStjhCYCIrY1PlVGR/CYd2vS8mejlE3dKPINa5hPVKXGolo6JiM+4i3X+uxWY
         D/1A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=D6c5peY5oYmdBlupPdQs8uiCHIGRjtDz1bnN/3hwj0w=;
        fh=axiRmXIOAdIYcislJFXmyoPHekGa4r06N0d9FDRG3Us=;
        b=gv3gfNcWBhGusVoNhCW1NTq3Xd5DujKKHL9g6mWgN+Xi4TZ8ZYYbcfJx36/Gtri5KR
         ee8YMFk4XXF/rzbUMXi2zJM0/eOvz0AY4CXAK2Kfn1EdfhXjndHcOuq2IXiD3DaZI7YJ
         JUvf16Ri4j+qBwTmP0mxrmrlArRKViuj+1DSbSLkLnDJs729I5UtFns+4XxXUfcVEbLt
         hY6cY8VoQ1wEPavR95xvTtP1/tqBMjd9JS2hasLarowHNMHXl+sBZO1A1DPEbvtVFz7R
         O8w9VGSBGCdjnqXkX2Qn3rkNp432WgoVXbrP2tabU6HF8im2wbeLnuNKU2+y/99WRo7a
         f2CQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=EWVsiA08;
       spf=pass (google.com: domain of 3-c8faqukcsufmwfshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3-C8faQUKCSUFMWFSHPPHMF.DPNLBTBO-EFWHPPHMFHSPVQT.DPN@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1763651581; x=1764256381; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=D6c5peY5oYmdBlupPdQs8uiCHIGRjtDz1bnN/3hwj0w=;
        b=cVpTQDeCdOdEKedFfOqbzuK8Dlrpt2SuyN0XvesPm5dSaGQehQVYlhhmcmPrSYQu2A
         ISwJ+kGH5uXgw87SxurGti6oAsRDnOT/MhSSl36lBiR1ixETONWY0CmBw04V3ghXPcZu
         MuK4aUNh2m/l0OKh8C3qq0KYe+B9FSj3bsuXviOS8gKwcVfifinL5e1/Su8TG8PseBzB
         XF2HYmMHRtn8ZHXxUQNt6EEyXIejcsLK46mpFKHWB6HOzHW3+aTR4fbDnIn+hB9qCvdM
         F2pLW9R2yQs8klZjiCZ0t9T3W/R1iE0FguL0aspHrvCIOO+QYGXU7DUAxikHG5qpqDGz
         FdUg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1763651581; x=1764256381;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=D6c5peY5oYmdBlupPdQs8uiCHIGRjtDz1bnN/3hwj0w=;
        b=mcgebJ0wXj8RHdhjEZRcX/GFpSsR5p6Cb/yOnyjdJpCA2st58x9zBIIFWwsaHSasCi
         ZZGDFI3koP97doWMYkt8xujvx1shwk/4p9hWwDad1VVEJHQ6JMPfuqaPDakAnFe6kruq
         kHi8Na2HSnz4nHggbpiSsxK4rQQjJ8QLyPtTtRsO6/A2YqrnbwCJnmk+HJqGJDm2gET6
         ZCUeWHYH1aBx3CtGTSnYxoqId7NuKqu0wnF3xn5INZq2bHByxfTHuX0X7B25ZIqXzTfy
         6VeCP/U+BaxedYiOia6gxds1UL5VhVgUC33j0vaV37u223RylbiBr4EzA53vNo8j80bf
         5c8w==
X-Forwarded-Encrypted: i=2; AJvYcCWY5SRPVu5Cra0P12zvTApGmIWO2jl/YRfiWX4hsTIab9R1z9Qb37t0A34RqvhsUY2HvElEQw==@lfdr.de
X-Gm-Message-State: AOJu0YxwHkW/HfCW1hsAZpcSbcuNeAmS+ITInyJ7rCZDcfE3JIWEHm6P
	krlStkkiPE2sfBXEDzSUDBfeB8a6cvpBWMuBkKkNxg0KmPIKGO5ZwPOg
X-Google-Smtp-Source: AGHT+IHGrqMiGRB7dhOoW/0eTbsjOIrI+oNU1rFDhHIpuuk29ykpDc4UChiyaRZWgc5ODv1zK5Al3w==
X-Received: by 2002:a2e:ab87:0:b0:37a:5939:1187 with SMTP id 38308e7fff4ca-37cc834e592mr7390461fa.10.1763651580856;
        Thu, 20 Nov 2025 07:13:00 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+bigLXD/dviDzQaXNJdIW9+KHwe8E+6LwN2LlDMMKtWsg=="
Received: by 2002:a2e:a1cb:0:b0:37a:3ee8:f671 with SMTP id 38308e7fff4ca-37bcfe4a010ls1390751fa.0.-pod-prod-00-eu-canary;
 Thu, 20 Nov 2025 07:12:58 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVVZttJ+KNIsPOz00JW85HzIfX0ra9j6Nn4K0RM79Au3pIMAdp3mned+uOZeEaYaOv8IdU+xT5cVQw=@googlegroups.com
X-Received: by 2002:a05:651c:41ca:b0:336:b891:18db with SMTP id 38308e7fff4ca-37cc82b4a59mr9488361fa.2.1763651577809;
        Thu, 20 Nov 2025 07:12:57 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1763651577; cv=none;
        d=google.com; s=arc-20240605;
        b=DpSZEiHnzEC/ssPi0jxzLIZWNwPdSbuUKXpdIAOzzPhCznXZ/js06c4tKirmF3hIx6
         1Mq30bFGcqIPRk0vpuL9J9jbuJ2t3GyfZlnlSFLBnAZvv9PL2/EAOriyBmJSzT2fWh2n
         tyQEOrsbsF8nEZTOI7vtYHVWu1t9L+w+pQa6T0o4jAtA0ojfzHynQC8p0Nzyida/prw9
         jss1hCAaZrYOv53MKVh6+CYIOc9/gFBt0YFoG2atR69XpVFIeXQZN86XILUY/nuTiYGI
         uGo4if/kmN19aGpsENnPuK7dggAKi2pnI+X1BA6BifWZ79y4Qbk9DJBLCzBSak/+yKdv
         hVJw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=z5PhmCa+DLEqmDE5eb5xrg5+OT8/kRfk1ooPiNLHiV0=;
        fh=FYru/WuhwS6dqXfUlCdyJcDR1nHHMr+Vxeg0wbebPVE=;
        b=JWsDtFH0coZlTiWeRmmqPgZjfHSuBvEZBW2bl9zE5zES6U8mrO6VKgKX95gwmLE9QD
         i7flc03bFfZn3Z1+5hp6Yu3/RKgPIMhOoEghmGauYgOaR+6kScs4wrOho+GDGq0uV3vg
         My+wd8iLJ1oeQbCsiPZFXEYdfPUPd524pKCMaaRQCC9btXchIy+jR4moKovczdHe6esV
         c7PfG3hxuJEN6JIl2bGQr1WP6HYeK8QhJP6v1wLyhelQ7M4/mQxcE44fsCfNyhm978Mk
         DHU7G+Ce43qJjGdoL8jYuDEUPtaab9K3FHyZ9pK2xIEpoEBiNprL4v9jd9jXnEaE6xZM
         ZETw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=EWVsiA08;
       spf=pass (google.com: domain of 3-c8faqukcsufmwfshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3-C8faQUKCSUFMWFSHPPHMF.DPNLBTBO-EFWHPPHMFHSPVQT.DPN@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x34a.google.com (mail-wm1-x34a.google.com. [2a00:1450:4864:20::34a])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-37cc6b2b844si306111fa.1.2025.11.20.07.12.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 20 Nov 2025 07:12:57 -0800 (PST)
Received-SPF: pass (google.com: domain of 3-c8faqukcsufmwfshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) client-ip=2a00:1450:4864:20::34a;
Received: by mail-wm1-x34a.google.com with SMTP id 5b1f17b1804b1-477563e531cso9824475e9.1
        for <kasan-dev@googlegroups.com>; Thu, 20 Nov 2025 07:12:57 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCUCL5mW0gB2RWilSGclMCttIfE1HHFtKRqlu+TxeRzOZD+aGuZcaHTx0ckPwJ/VUMWGbRrGN/ke3xc=@googlegroups.com
X-Received: from wmbb9.prod.google.com ([2002:a05:600c:5889:b0:477:9e14:84dc])
 (user=elver job=prod-delivery.src-stubby-dispatcher) by 2002:a05:600c:3b05:b0:477:a978:3a7b
 with SMTP id 5b1f17b1804b1-477b8a9f30amr31592855e9.22.1763651576808; Thu, 20
 Nov 2025 07:12:56 -0800 (PST)
Date: Thu, 20 Nov 2025 16:09:42 +0100
In-Reply-To: <20251120151033.3840508-7-elver@google.com>
Mime-Version: 1.0
References: <20251120145835.3833031-2-elver@google.com> <20251120151033.3840508-7-elver@google.com>
X-Mailer: git-send-email 2.52.0.rc1.455.g30608eb744-goog
Message-ID: <20251120151033.3840508-18-elver@google.com>
Subject: [PATCH v4 17/35] locking/rwsem: Support Clang's context analysis
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
 header.i=@google.com header.s=20230601 header.b=EWVsiA08;       spf=pass
 (google.com: domain of 3-c8faqukcsufmwfshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3-C8faQUKCSUFMWFSHPPHMF.DPNLBTBO-EFWHPPHMFHSPVQT.DPN@flex--elver.bounces.google.com;
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

Add support for Clang's context analysis for rw_semaphore.

Signed-off-by: Marco Elver <elver@google.com>
---
v4:
* Rename capability -> context analysis.

v3:
* Switch to DECLARE_LOCK_GUARD_1_ATTRS() (suggested by Peter)
* __assert -> __assume rename
---
 Documentation/dev-tools/context-analysis.rst |  2 +-
 include/linux/rwsem.h                        | 66 ++++++++++++--------
 lib/test_context-analysis.c                  | 64 +++++++++++++++++++
 3 files changed, 106 insertions(+), 26 deletions(-)

diff --git a/Documentation/dev-tools/context-analysis.rst b/Documentation/dev-tools/context-analysis.rst
index 59fc8e4cc203..dc7ae4f641f2 100644
--- a/Documentation/dev-tools/context-analysis.rst
+++ b/Documentation/dev-tools/context-analysis.rst
@@ -81,7 +81,7 @@ Supported Kernel Primitives
 
 Currently the following synchronization primitives are supported:
 `raw_spinlock_t`, `spinlock_t`, `rwlock_t`, `mutex`, `seqlock_t`,
-`bit_spinlock`, RCU, SRCU (`srcu_struct`).
+`bit_spinlock`, RCU, SRCU (`srcu_struct`), `rw_semaphore`.
 
 For context guards with an initialization function (e.g., `spin_lock_init()`),
 calling this function before initializing any guarded members or globals
diff --git a/include/linux/rwsem.h b/include/linux/rwsem.h
index f1aaf676a874..922790635f79 100644
--- a/include/linux/rwsem.h
+++ b/include/linux/rwsem.h
@@ -45,7 +45,7 @@
  * reduce the chance that they will share the same cacheline causing
  * cacheline bouncing problem.
  */
-struct rw_semaphore {
+context_guard_struct(rw_semaphore) {
 	atomic_long_t count;
 	/*
 	 * Write owner or one of the read owners as well flags regarding
@@ -76,11 +76,13 @@ static inline int rwsem_is_locked(struct rw_semaphore *sem)
 }
 
 static inline void rwsem_assert_held_nolockdep(const struct rw_semaphore *sem)
+	__assumes_ctx_guard(sem)
 {
 	WARN_ON(atomic_long_read(&sem->count) == RWSEM_UNLOCKED_VALUE);
 }
 
 static inline void rwsem_assert_held_write_nolockdep(const struct rw_semaphore *sem)
+	__assumes_ctx_guard(sem)
 {
 	WARN_ON(!(atomic_long_read(&sem->count) & RWSEM_WRITER_LOCKED));
 }
@@ -119,6 +121,7 @@ do {								\
 	static struct lock_class_key __key;			\
 								\
 	__init_rwsem((sem), #sem, &__key);			\
+	__assume_ctx_guard(sem);				\
 } while (0)
 
 /*
@@ -148,7 +151,7 @@ extern bool is_rwsem_reader_owned(struct rw_semaphore *sem);
 
 #include <linux/rwbase_rt.h>
 
-struct rw_semaphore {
+context_guard_struct(rw_semaphore) {
 	struct rwbase_rt	rwbase;
 #ifdef CONFIG_DEBUG_LOCK_ALLOC
 	struct lockdep_map	dep_map;
@@ -172,6 +175,7 @@ do {								\
 	static struct lock_class_key __key;			\
 								\
 	__init_rwsem((sem), #sem, &__key);			\
+	__assume_ctx_guard(sem);				\
 } while (0)
 
 static __always_inline int rwsem_is_locked(const struct rw_semaphore *sem)
@@ -180,11 +184,13 @@ static __always_inline int rwsem_is_locked(const struct rw_semaphore *sem)
 }
 
 static __always_inline void rwsem_assert_held_nolockdep(const struct rw_semaphore *sem)
+	__assumes_ctx_guard(sem)
 {
 	WARN_ON(!rwsem_is_locked(sem));
 }
 
 static __always_inline void rwsem_assert_held_write_nolockdep(const struct rw_semaphore *sem)
+	__assumes_ctx_guard(sem)
 {
 	WARN_ON(!rw_base_is_write_locked(&sem->rwbase));
 }
@@ -202,6 +208,7 @@ static __always_inline int rwsem_is_contended(struct rw_semaphore *sem)
  */
 
 static inline void rwsem_assert_held(const struct rw_semaphore *sem)
+	__assumes_ctx_guard(sem)
 {
 	if (IS_ENABLED(CONFIG_LOCKDEP))
 		lockdep_assert_held(sem);
@@ -210,6 +217,7 @@ static inline void rwsem_assert_held(const struct rw_semaphore *sem)
 }
 
 static inline void rwsem_assert_held_write(const struct rw_semaphore *sem)
+	__assumes_ctx_guard(sem)
 {
 	if (IS_ENABLED(CONFIG_LOCKDEP))
 		lockdep_assert_held_write(sem);
@@ -220,48 +228,56 @@ static inline void rwsem_assert_held_write(const struct rw_semaphore *sem)
 /*
  * lock for reading
  */
-extern void down_read(struct rw_semaphore *sem);
-extern int __must_check down_read_interruptible(struct rw_semaphore *sem);
-extern int __must_check down_read_killable(struct rw_semaphore *sem);
+extern void down_read(struct rw_semaphore *sem) __acquires_shared(sem);
+extern int __must_check down_read_interruptible(struct rw_semaphore *sem) __cond_acquires_shared(0, sem);
+extern int __must_check down_read_killable(struct rw_semaphore *sem) __cond_acquires_shared(0, sem);
 
 /*
  * trylock for reading -- returns 1 if successful, 0 if contention
  */
-extern int down_read_trylock(struct rw_semaphore *sem);
+extern int down_read_trylock(struct rw_semaphore *sem) __cond_acquires_shared(true, sem);
 
 /*
  * lock for writing
  */
-extern void down_write(struct rw_semaphore *sem);
-extern int __must_check down_write_killable(struct rw_semaphore *sem);
+extern void down_write(struct rw_semaphore *sem) __acquires(sem);
+extern int __must_check down_write_killable(struct rw_semaphore *sem) __cond_acquires(0, sem);
 
 /*
  * trylock for writing -- returns 1 if successful, 0 if contention
  */
-extern int down_write_trylock(struct rw_semaphore *sem);
+extern int down_write_trylock(struct rw_semaphore *sem) __cond_acquires(true, sem);
 
 /*
  * release a read lock
  */
-extern void up_read(struct rw_semaphore *sem);
+extern void up_read(struct rw_semaphore *sem) __releases_shared(sem);
 
 /*
  * release a write lock
  */
-extern void up_write(struct rw_semaphore *sem);
+extern void up_write(struct rw_semaphore *sem) __releases(sem);
 
-DEFINE_GUARD(rwsem_read, struct rw_semaphore *, down_read(_T), up_read(_T))
-DEFINE_GUARD_COND(rwsem_read, _try, down_read_trylock(_T))
-DEFINE_GUARD_COND(rwsem_read, _intr, down_read_interruptible(_T), _RET == 0)
+DEFINE_LOCK_GUARD_1(rwsem_read, struct rw_semaphore, down_read(_T->lock), up_read(_T->lock))
+DEFINE_LOCK_GUARD_1_COND(rwsem_read, _try, down_read_trylock(_T->lock))
+DEFINE_LOCK_GUARD_1_COND(rwsem_read, _intr, down_read_interruptible(_T->lock), _RET == 0)
 
-DEFINE_GUARD(rwsem_write, struct rw_semaphore *, down_write(_T), up_write(_T))
-DEFINE_GUARD_COND(rwsem_write, _try, down_write_trylock(_T))
-DEFINE_GUARD_COND(rwsem_write, _kill, down_write_killable(_T), _RET == 0)
+DECLARE_LOCK_GUARD_1_ATTRS(rwsem_read, __assumes_ctx_guard(_T), /* */)
+DECLARE_LOCK_GUARD_1_ATTRS(rwsem_read_try, __assumes_ctx_guard(_T), /* */)
+DECLARE_LOCK_GUARD_1_ATTRS(rwsem_read_intr, __assumes_ctx_guard(_T), /* */)
+
+DEFINE_LOCK_GUARD_1(rwsem_write, struct rw_semaphore, down_write(_T->lock), up_write(_T->lock))
+DEFINE_LOCK_GUARD_1_COND(rwsem_write, _try, down_write_trylock(_T->lock))
+DEFINE_LOCK_GUARD_1_COND(rwsem_write, _kill, down_write_killable(_T->lock), _RET == 0)
+
+DECLARE_LOCK_GUARD_1_ATTRS(rwsem_write, __assumes_ctx_guard(_T), /* */)
+DECLARE_LOCK_GUARD_1_ATTRS(rwsem_write_try, __assumes_ctx_guard(_T), /* */)
+DECLARE_LOCK_GUARD_1_ATTRS(rwsem_write_kill, __assumes_ctx_guard(_T), /* */)
 
 /*
  * downgrade write lock to read lock
  */
-extern void downgrade_write(struct rw_semaphore *sem);
+extern void downgrade_write(struct rw_semaphore *sem) __releases(sem) __acquires_shared(sem);
 
 #ifdef CONFIG_DEBUG_LOCK_ALLOC
 /*
@@ -277,11 +293,11 @@ extern void downgrade_write(struct rw_semaphore *sem);
  * lockdep_set_class() at lock initialization time.
  * See Documentation/locking/lockdep-design.rst for more details.)
  */
-extern void down_read_nested(struct rw_semaphore *sem, int subclass);
-extern int __must_check down_read_killable_nested(struct rw_semaphore *sem, int subclass);
-extern void down_write_nested(struct rw_semaphore *sem, int subclass);
-extern int down_write_killable_nested(struct rw_semaphore *sem, int subclass);
-extern void _down_write_nest_lock(struct rw_semaphore *sem, struct lockdep_map *nest_lock);
+extern void down_read_nested(struct rw_semaphore *sem, int subclass) __acquires_shared(sem);
+extern int __must_check down_read_killable_nested(struct rw_semaphore *sem, int subclass) __cond_acquires_shared(0, sem);
+extern void down_write_nested(struct rw_semaphore *sem, int subclass) __acquires(sem);
+extern int down_write_killable_nested(struct rw_semaphore *sem, int subclass) __cond_acquires(0, sem);
+extern void _down_write_nest_lock(struct rw_semaphore *sem, struct lockdep_map *nest_lock) __acquires(sem);
 
 # define down_write_nest_lock(sem, nest_lock)			\
 do {								\
@@ -295,8 +311,8 @@ do {								\
  * [ This API should be avoided as much as possible - the
  *   proper abstraction for this case is completions. ]
  */
-extern void down_read_non_owner(struct rw_semaphore *sem);
-extern void up_read_non_owner(struct rw_semaphore *sem);
+extern void down_read_non_owner(struct rw_semaphore *sem) __acquires_shared(sem);
+extern void up_read_non_owner(struct rw_semaphore *sem) __releases_shared(sem);
 #else
 # define down_read_nested(sem, subclass)		down_read(sem)
 # define down_read_killable_nested(sem, subclass)	down_read_killable(sem)
diff --git a/lib/test_context-analysis.c b/lib/test_context-analysis.c
index bd75b5ade8ff..2203a57cd40d 100644
--- a/lib/test_context-analysis.c
+++ b/lib/test_context-analysis.c
@@ -8,6 +8,7 @@
 #include <linux/build_bug.h>
 #include <linux/mutex.h>
 #include <linux/rcupdate.h>
+#include <linux/rwsem.h>
 #include <linux/seqlock.h>
 #include <linux/spinlock.h>
 #include <linux/srcu.h>
@@ -255,6 +256,69 @@ static void __used test_seqlock_writer(struct test_seqlock_data *d)
 	write_sequnlock_irqrestore(&d->sl, flags);
 }
 
+struct test_rwsem_data {
+	struct rw_semaphore sem;
+	int counter __guarded_by(&sem);
+};
+
+static void __used test_rwsem_init(struct test_rwsem_data *d)
+{
+	init_rwsem(&d->sem);
+	d->counter = 0;
+}
+
+static void __used test_rwsem_reader(struct test_rwsem_data *d)
+{
+	down_read(&d->sem);
+	(void)d->counter;
+	up_read(&d->sem);
+
+	if (down_read_trylock(&d->sem)) {
+		(void)d->counter;
+		up_read(&d->sem);
+	}
+}
+
+static void __used test_rwsem_writer(struct test_rwsem_data *d)
+{
+	down_write(&d->sem);
+	d->counter++;
+	up_write(&d->sem);
+
+	down_write(&d->sem);
+	d->counter++;
+	downgrade_write(&d->sem);
+	(void)d->counter;
+	up_read(&d->sem);
+
+	if (down_write_trylock(&d->sem)) {
+		d->counter++;
+		up_write(&d->sem);
+	}
+}
+
+static void __used test_rwsem_assert(struct test_rwsem_data *d)
+{
+	rwsem_assert_held_nolockdep(&d->sem);
+	d->counter++;
+}
+
+static void __used test_rwsem_guard(struct test_rwsem_data *d)
+{
+	{ guard(rwsem_read)(&d->sem); (void)d->counter; }
+	{ guard(rwsem_write)(&d->sem); d->counter++; }
+}
+
+static void __used test_rwsem_cond_guard(struct test_rwsem_data *d)
+{
+	scoped_cond_guard(rwsem_read_try, return, &d->sem) {
+		(void)d->counter;
+	}
+	scoped_cond_guard(rwsem_write_try, return, &d->sem) {
+		d->counter++;
+	}
+}
+
 struct test_bit_spinlock_data {
 	unsigned long bits;
 	int counter __guarded_by(__bitlock(3, &bits));
-- 
2.52.0.rc1.455.g30608eb744-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251120151033.3840508-18-elver%40google.com.
