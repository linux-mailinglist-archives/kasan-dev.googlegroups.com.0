Return-Path: <kasan-dev+bncBC7OBJGL2MHBB5XZSO6QMGQE4X7JBAA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x237.google.com (mail-lj1-x237.google.com [IPv6:2a00:1450:4864:20::237])
	by mail.lfdr.de (Postfix) with ESMTPS id 434FEA2B05E
	for <lists+kasan-dev@lfdr.de>; Thu,  6 Feb 2025 19:18:33 +0100 (CET)
Received: by mail-lj1-x237.google.com with SMTP id 38308e7fff4ca-307db648a5fsf6227661fa.1
        for <lists+kasan-dev@lfdr.de>; Thu, 06 Feb 2025 10:18:33 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1738865912; cv=pass;
        d=google.com; s=arc-20240605;
        b=TNUDT/X1g/qB8PEBlj8N/28R9gbiV+kQ5lq8iyFZ24g3QRwNb7nkWYKsGN2TytCfcK
         b2n+KwiwwnMhxSwTnoqthNAG1cJvRHppOuM1uJll23sUPkBO7LESmOIooeBq1W8FBlKf
         8AwJXmsxpTkiP1Z2in162ubPmnjP46nV2r4/RGLBCLCzx+cEvzkj4ykA7UV3l6YcbUdN
         ef0QlGRDGdB8NdA3r+qmSC18QVf/FGtKV//riUxquLhBUtWylwy5sYx6WMXfh/V5QVEY
         SE8jlFsbTJvSHqqZ/HJTDTf5GBi84BTrn+9Op4jHA1Tek2b7ES07U4Eq3B1vn1i24egs
         Cv+Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=MlfBrB2GAgFXbkceKfuGGpoHznAGMWIp5TSeDBoJXfM=;
        fh=VCn1wiUU5XrL98wV5QQdfrpPiSygOkMPpcIMUqEcwik=;
        b=LufUK9S4OmImJe6GpF/c0fRI8eJiVp1QpL0IKKZXvlwdiNljDde8498FuTMKFA9j+J
         avZXmT1uH2fQRXYWyBEKVd8jP/6KTLTOspVGPXn05gFMlCfrYH2/XSKuFwxyt4+42jsF
         LFqQkQkaeNJKjqRwmWJ3TuhKoCSIxn8h7nVmigVfr2JS9ELQe0WeTMzD3LAPqkEamAJj
         A1nIihJy+bhGASlIoaT/E2FZeWWcLl1wqpp7MUSKODKi4vWWDp6QlHSFN9qIoscWYkq/
         cC2EZLrv8X2O84q1VxHCOy9AGUZQSYoVOJji8uybgh8dZ8Cnt/ogg2RBCd90vyzAi0x5
         p5Qw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=s49s69Sk;
       spf=pass (google.com: domain of 38vykzwukccmnu4n0pxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--elver.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=38vykZwUKCcMnu4n0pxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1738865912; x=1739470712; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=MlfBrB2GAgFXbkceKfuGGpoHznAGMWIp5TSeDBoJXfM=;
        b=U2aHjp0/jNPllsXDdjaNBpmlYI11MjtDdYFhhQpEzx5ELzagFM6Zo4FHEWkGgyMfLp
         AhWSOBsSzMP+k2jUdB4V5Ha2abH2IcE7Nz9SRK0XnN8kKI9QZOzGkSrLPiBeH8fO1XOy
         Zd7/ihhkVfRwzNjsz+MSDxWNY3XqmAeGthHFn7Mggffo92p8Uetw7JH0Jyo7mIm3ut0k
         wjlkRHC/5OaMYqKYNjmaS2quAT1gkHAo8ZXnrF+tR4N9NwygB5yMsUj+xw7guD0I+/YT
         jUhNf6Unplv+jmQK/YKxlDJFoiDBtZGci6VDDQL9GC7fZvY2I0wysmMxylaMK2jl0PL1
         SGYQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1738865912; x=1739470712;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=MlfBrB2GAgFXbkceKfuGGpoHznAGMWIp5TSeDBoJXfM=;
        b=VEsF49J08RjS88ljOELbTf6W4Lkjh+xx5mNo5HMpuNNPp7DQ1DsHeNKqhKVaVM3S/r
         ZBH7qNALa/AJGSnSy2Zu0ikNQ1biG6vkrp07SvSLLaIzLZerLLMP68pdnpyenDaP7q7r
         6h8g7I63CmzbOLwVHLY5/PBT55Uncq14Gxs/EyC3WjGcVe54w4mM0piigeAy85iEXkkQ
         6vlMmY+8ke8P4ANAYLx5omFL9BIm7e/of2H9ELJjnr6MiFY3QIi4JHYrNOTyant1GmZB
         g+r0mexT+iHBlesQXo5ahVdfMUrn1ALK9Be4vGFHzm4in8PKMLtmLid15oG8Cw6jZmVL
         ZHig==
X-Forwarded-Encrypted: i=2; AJvYcCVKtx5o4Higp1C64fN5rwNP2O6HLSdcKY+dchq8Xj1XmIf4tQSRVkgkCOlT8TGXTN9S63WXbQ==@lfdr.de
X-Gm-Message-State: AOJu0Ywppw8JXaCDn1fo4XU30uEUKNJz8dHelTGGGJKkcWfxLx5IrO7N
	D3lrNTLkIc3nJD+WPn2/qu9ThbL9DDRQYDxfKdDChzqqatR0ln/B
X-Google-Smtp-Source: AGHT+IFcquUDqaipr3wQgXid1hcvgxqVoY9izyX/JVA3yJj+z3EaqNr0qmeB4ONZd2LyOqHbZYLkwg==
X-Received: by 2002:a05:651c:888:b0:300:7f87:a65 with SMTP id 38308e7fff4ca-307cf38fa9cmr30706681fa.35.1738865911223;
        Thu, 06 Feb 2025 10:18:31 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:be11:0:b0:300:160f:8559 with SMTP id 38308e7fff4ca-307e579e0ddls6421fa.2.-pod-prod-06-eu;
 Thu, 06 Feb 2025 10:18:27 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXqmZejW+6B399CfQmBE8bpUh+tR5wqvv92dNv3cY7trtkBNRF7eIbFvUEy1OWJRNDInMqocXbkajY=@googlegroups.com
X-Received: by 2002:a05:651c:1585:b0:2fb:cc0:2a05 with SMTP id 38308e7fff4ca-307cf38fa91mr31709761fa.37.1738865907038;
        Thu, 06 Feb 2025 10:18:27 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1738865907; cv=none;
        d=google.com; s=arc-20240605;
        b=hfAVRfbiwM8uWFnde/N4VuL+IEl1RcNHaDMXztWeECOs2oe52zyMo/7NUb/ICbJQNT
         COuPzgMNLqHiGzMlAFpdlsWsIyrMh1v3i+EmKpfYNtD4AcKo20gUSDQtYZi2jLQ6Vvwg
         p6BivravWSAErHYSfJvU+Pha7k568L+/PcHfB3xZPcJuKUecnGh9handaSCyT8hhxtTf
         PLO3cTd7dRuf31XkydQfZIivjFY45L0dzocUI/98T6nSwR7J+x4vtJm0ZFqwec+/+vS5
         aKZgJyA+UygFsvvwGSyVKAX8ChCccs5v/1WOzK/fzWLqLIO0AYkPzgfdoKPDzGR4JQhK
         uSzA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=MQXyMw84n+KN7BKVw/OtNJwL/he84+ejRwU4F35ugF4=;
        fh=/EYOkp/yH6/UI8aRqaqQBh3s4e8CdcjafYd+wIlpae8=;
        b=UllVwJKyrf1d5vHR4FqKilR+Le2pTO+5iXkuTrQFjngn9qHCE5Fh3Yae16pr8unWMi
         ptr13hXFl6fza/TeNIa6ETZjYxOJlBU+oG1xT5z/agbPbU89Kg8TlWLeIxCct/7SDX5i
         u8Ix3Lz8YJf/AO+Mo01RTXBufnXWr8l+JVpnqrloHsUSCXtGOVdbuGgjU4cqxeWVmrWs
         9IjB+TUfE+Ys0UGyskFyq+8gUr8aE1hrnUoXfYSK8C97KqNF1fBeKp9BqEx641s3aZjZ
         gaJii6DobL/oen+/sjloD9L/kfqVRsjLA2qvZuGsofDkwCzp3u+r85GVNkDjhdYGGXbz
         kl3Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=s49s69Sk;
       spf=pass (google.com: domain of 38vykzwukccmnu4n0pxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--elver.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=38vykZwUKCcMnu4n0pxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ej1-x64a.google.com (mail-ej1-x64a.google.com. [2a00:1450:4864:20::64a])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-307de2215c2si381041fa.8.2025.02.06.10.18.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 06 Feb 2025 10:18:27 -0800 (PST)
Received-SPF: pass (google.com: domain of 38vykzwukccmnu4n0pxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--elver.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) client-ip=2a00:1450:4864:20::64a;
Received: by mail-ej1-x64a.google.com with SMTP id a640c23a62f3a-aa689b88293so130821066b.3
        for <kasan-dev@googlegroups.com>; Thu, 06 Feb 2025 10:18:27 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCW5tax4RRn2ATFKSDc3fXkPmDgG5RDVSCrHhL2NWmFnMxl4kQ4+J14RGkhiPUF7UaUFIqM/IdENpTI=@googlegroups.com
X-Received: from ejcss11.prod.google.com ([2002:a17:907:c00b:b0:ab7:822d:f553])
 (user=elver job=prod-delivery.src-stubby-dispatcher) by 2002:a17:906:856:b0:ab7:6606:a8d5
 with SMTP id a640c23a62f3a-ab76606b5camr644091966b.48.1738865906398; Thu, 06
 Feb 2025 10:18:26 -0800 (PST)
Date: Thu,  6 Feb 2025 19:10:10 +0100
In-Reply-To: <20250206181711.1902989-1-elver@google.com>
Mime-Version: 1.0
References: <20250206181711.1902989-1-elver@google.com>
X-Mailer: git-send-email 2.48.1.502.g6dc24dfdaf-goog
Message-ID: <20250206181711.1902989-17-elver@google.com>
Subject: [PATCH RFC 16/24] srcu: Support Clang's capability analysis
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
 header.i=@google.com header.s=20230601 header.b=s49s69Sk;       spf=pass
 (google.com: domain of 38vykzwukccmnu4n0pxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=38vykZwUKCcMnu4n0pxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--elver.bounces.google.com;
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

Add support for Clang's capability analysis for SRCU.

Signed-off-by: Marco Elver <elver@google.com>
---
 .../dev-tools/capability-analysis.rst         |  2 +-
 include/linux/srcu.h                          | 61 +++++++++++++------
 lib/test_capability-analysis.c                | 24 ++++++++
 3 files changed, 66 insertions(+), 21 deletions(-)

diff --git a/Documentation/dev-tools/capability-analysis.rst b/Documentation/dev-tools/capability-analysis.rst
index 73dd28a23b11..3766ac466470 100644
--- a/Documentation/dev-tools/capability-analysis.rst
+++ b/Documentation/dev-tools/capability-analysis.rst
@@ -86,7 +86,7 @@ Supported Kernel Primitives
 
 Currently the following synchronization primitives are supported:
 `raw_spinlock_t`, `spinlock_t`, `rwlock_t`, `mutex`, `seqlock_t`,
-`bit_spinlock`, RCU.
+`bit_spinlock`, RCU, SRCU (`srcu_struct`).
 
 For capabilities with an initialization function (e.g., `spin_lock_init()`),
 calling this function on the capability instance before initializing any
diff --git a/include/linux/srcu.h b/include/linux/srcu.h
index d7ba46e74f58..560310643c54 100644
--- a/include/linux/srcu.h
+++ b/include/linux/srcu.h
@@ -21,7 +21,7 @@
 #include <linux/workqueue.h>
 #include <linux/rcu_segcblist.h>
 
-struct srcu_struct;
+struct_with_capability(srcu_struct);
 
 #ifdef CONFIG_DEBUG_LOCK_ALLOC
 
@@ -60,14 +60,14 @@ int init_srcu_struct(struct srcu_struct *ssp);
 void call_srcu(struct srcu_struct *ssp, struct rcu_head *head,
 		void (*func)(struct rcu_head *head));
 void cleanup_srcu_struct(struct srcu_struct *ssp);
-int __srcu_read_lock(struct srcu_struct *ssp) __acquires(ssp);
-void __srcu_read_unlock(struct srcu_struct *ssp, int idx) __releases(ssp);
+int __srcu_read_lock(struct srcu_struct *ssp) __acquires_shared(ssp);
+void __srcu_read_unlock(struct srcu_struct *ssp, int idx) __releases_shared(ssp);
 #ifdef CONFIG_TINY_SRCU
 #define __srcu_read_lock_lite __srcu_read_lock
 #define __srcu_read_unlock_lite __srcu_read_unlock
 #else // #ifdef CONFIG_TINY_SRCU
-int __srcu_read_lock_lite(struct srcu_struct *ssp) __acquires(ssp);
-void __srcu_read_unlock_lite(struct srcu_struct *ssp, int idx) __releases(ssp);
+int __srcu_read_lock_lite(struct srcu_struct *ssp) __acquires_shared(ssp);
+void __srcu_read_unlock_lite(struct srcu_struct *ssp, int idx) __releases_shared(ssp);
 #endif // #else // #ifdef CONFIG_TINY_SRCU
 void synchronize_srcu(struct srcu_struct *ssp);
 
@@ -110,14 +110,16 @@ static inline bool same_state_synchronize_srcu(unsigned long oldstate1, unsigned
 }
 
 #ifdef CONFIG_NEED_SRCU_NMI_SAFE
-int __srcu_read_lock_nmisafe(struct srcu_struct *ssp) __acquires(ssp);
-void __srcu_read_unlock_nmisafe(struct srcu_struct *ssp, int idx) __releases(ssp);
+int __srcu_read_lock_nmisafe(struct srcu_struct *ssp) __acquires_shared(ssp);
+void __srcu_read_unlock_nmisafe(struct srcu_struct *ssp, int idx) __releases_shared(ssp);
 #else
 static inline int __srcu_read_lock_nmisafe(struct srcu_struct *ssp)
+	__acquires_shared(ssp)
 {
 	return __srcu_read_lock(ssp);
 }
 static inline void __srcu_read_unlock_nmisafe(struct srcu_struct *ssp, int idx)
+	__releases_shared(ssp)
 {
 	__srcu_read_unlock(ssp, idx);
 }
@@ -189,6 +191,14 @@ static inline int srcu_read_lock_held(const struct srcu_struct *ssp)
 
 #endif /* #else #ifdef CONFIG_DEBUG_LOCK_ALLOC */
 
+/*
+ * No-op helper to denote that ssp must be held. Because SRCU-protected pointers
+ * should still be marked with __rcu_guarded, and we do not want to mark them
+ * with __var_guarded_by(ssp) as it would complicate annotations for writers, we
+ * choose the following strategy: srcu_dereference_check() calls this helper
+ * that checks that the passed ssp is held, and then fake-acquires 'RCU'.
+ */
+static inline void __srcu_read_lock_must_hold(const struct srcu_struct *ssp) __must_hold_shared(ssp) { }
 
 /**
  * srcu_dereference_check - fetch SRCU-protected pointer for later dereferencing
@@ -202,9 +212,15 @@ static inline int srcu_read_lock_held(const struct srcu_struct *ssp)
  * to 1.  The @c argument will normally be a logical expression containing
  * lockdep_is_held() calls.
  */
-#define srcu_dereference_check(p, ssp, c) \
-	__rcu_dereference_check((p), __UNIQUE_ID(rcu), \
-				(c) || srcu_read_lock_held(ssp), __rcu)
+#define srcu_dereference_check(p, ssp, c)					\
+({										\
+	__srcu_read_lock_must_hold(ssp);					\
+	__acquire_shared_cap(RCU);						\
+	__auto_type __v = __rcu_dereference_check((p), __UNIQUE_ID(rcu),	\
+				(c) || srcu_read_lock_held(ssp), __rcu);	\
+	__release_shared_cap(RCU);						\
+	__v;									\
+})
 
 /**
  * srcu_dereference - fetch SRCU-protected pointer for later dereferencing
@@ -247,7 +263,8 @@ static inline int srcu_read_lock_held(const struct srcu_struct *ssp)
  * invoke srcu_read_unlock() from one task and the matching srcu_read_lock()
  * from another.
  */
-static inline int srcu_read_lock(struct srcu_struct *ssp) __acquires(ssp)
+static inline int srcu_read_lock(struct srcu_struct *ssp)
+	__acquires_shared(ssp)
 {
 	int retval;
 
@@ -274,7 +291,8 @@ static inline int srcu_read_lock(struct srcu_struct *ssp) __acquires(ssp)
  * where RCU is watching, that is, from contexts where it would be legal
  * to invoke rcu_read_lock().  Otherwise, lockdep will complain.
  */
-static inline int srcu_read_lock_lite(struct srcu_struct *ssp) __acquires(ssp)
+static inline int srcu_read_lock_lite(struct srcu_struct *ssp)
+	__acquires_shared(ssp)
 {
 	int retval;
 
@@ -295,7 +313,8 @@ static inline int srcu_read_lock_lite(struct srcu_struct *ssp) __acquires(ssp)
  * then none of the other flavors may be used, whether before, during,
  * or after.
  */
-static inline int srcu_read_lock_nmisafe(struct srcu_struct *ssp) __acquires(ssp)
+static inline int srcu_read_lock_nmisafe(struct srcu_struct *ssp)
+	__acquires_shared(ssp)
 {
 	int retval;
 
@@ -307,7 +326,8 @@ static inline int srcu_read_lock_nmisafe(struct srcu_struct *ssp) __acquires(ssp
 
 /* Used by tracing, cannot be traced and cannot invoke lockdep. */
 static inline notrace int
-srcu_read_lock_notrace(struct srcu_struct *ssp) __acquires(ssp)
+srcu_read_lock_notrace(struct srcu_struct *ssp)
+	__acquires_shared(ssp)
 {
 	int retval;
 
@@ -337,7 +357,8 @@ srcu_read_lock_notrace(struct srcu_struct *ssp) __acquires(ssp)
  * Calls to srcu_down_read() may be nested, similar to the manner in
  * which calls to down_read() may be nested.
  */
-static inline int srcu_down_read(struct srcu_struct *ssp) __acquires(ssp)
+static inline int srcu_down_read(struct srcu_struct *ssp)
+	__acquires_shared(ssp)
 {
 	WARN_ON_ONCE(in_nmi());
 	srcu_check_read_flavor(ssp, SRCU_READ_FLAVOR_NORMAL);
@@ -352,7 +373,7 @@ static inline int srcu_down_read(struct srcu_struct *ssp) __acquires(ssp)
  * Exit an SRCU read-side critical section.
  */
 static inline void srcu_read_unlock(struct srcu_struct *ssp, int idx)
-	__releases(ssp)
+	__releases_shared(ssp)
 {
 	WARN_ON_ONCE(idx & ~0x1);
 	srcu_check_read_flavor(ssp, SRCU_READ_FLAVOR_NORMAL);
@@ -368,7 +389,7 @@ static inline void srcu_read_unlock(struct srcu_struct *ssp, int idx)
  * Exit a light-weight SRCU read-side critical section.
  */
 static inline void srcu_read_unlock_lite(struct srcu_struct *ssp, int idx)
-	__releases(ssp)
+	__releases_shared(ssp)
 {
 	WARN_ON_ONCE(idx & ~0x1);
 	srcu_check_read_flavor(ssp, SRCU_READ_FLAVOR_LITE);
@@ -384,7 +405,7 @@ static inline void srcu_read_unlock_lite(struct srcu_struct *ssp, int idx)
  * Exit an SRCU read-side critical section, but in an NMI-safe manner.
  */
 static inline void srcu_read_unlock_nmisafe(struct srcu_struct *ssp, int idx)
-	__releases(ssp)
+	__releases_shared(ssp)
 {
 	WARN_ON_ONCE(idx & ~0x1);
 	srcu_check_read_flavor(ssp, SRCU_READ_FLAVOR_NMI);
@@ -394,7 +415,7 @@ static inline void srcu_read_unlock_nmisafe(struct srcu_struct *ssp, int idx)
 
 /* Used by tracing, cannot be traced and cannot call lockdep. */
 static inline notrace void
-srcu_read_unlock_notrace(struct srcu_struct *ssp, int idx) __releases(ssp)
+srcu_read_unlock_notrace(struct srcu_struct *ssp, int idx) __releases_shared(ssp)
 {
 	srcu_check_read_flavor(ssp, SRCU_READ_FLAVOR_NORMAL);
 	__srcu_read_unlock(ssp, idx);
@@ -409,7 +430,7 @@ srcu_read_unlock_notrace(struct srcu_struct *ssp, int idx) __releases(ssp)
  * the same context as the maching srcu_down_read().
  */
 static inline void srcu_up_read(struct srcu_struct *ssp, int idx)
-	__releases(ssp)
+	__releases_shared(ssp)
 {
 	WARN_ON_ONCE(idx & ~0x1);
 	WARN_ON_ONCE(in_nmi());
diff --git a/lib/test_capability-analysis.c b/lib/test_capability-analysis.c
index f5a1dda6ca38..8bc8c3e6cb5c 100644
--- a/lib/test_capability-analysis.c
+++ b/lib/test_capability-analysis.c
@@ -10,6 +10,7 @@
 #include <linux/rcupdate.h>
 #include <linux/seqlock.h>
 #include <linux/spinlock.h>
+#include <linux/srcu.h>
 
 /*
  * Test that helper macros work as expected.
@@ -345,3 +346,26 @@ static void __used test_rcu_assert_variants(void)
 	lockdep_assert_in_rcu_read_lock_sched();
 	wants_rcu_held_sched();
 }
+
+struct test_srcu_data {
+	struct srcu_struct srcu;
+	long __rcu_guarded *data;
+};
+
+static void __used test_srcu(struct test_srcu_data *d)
+{
+	init_srcu_struct(&d->srcu);
+
+	int idx = srcu_read_lock(&d->srcu);
+	long *data = srcu_dereference(d->data, &d->srcu);
+	(void)data;
+	srcu_read_unlock(&d->srcu, idx);
+
+	rcu_assign_pointer(d->data, NULL);
+}
+
+static void __used test_srcu_guard(struct test_srcu_data *d)
+{
+	guard(srcu)(&d->srcu);
+	(void)srcu_dereference(d->data, &d->srcu);
+}
-- 
2.48.1.502.g6dc24dfdaf-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250206181711.1902989-17-elver%40google.com.
