Return-Path: <kasan-dev+bncBC7OBJGL2MHBBU7GSXFAMGQEXA6I6LI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x138.google.com (mail-lf1-x138.google.com [IPv6:2a00:1450:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id 5175ECD0968
	for <lists+kasan-dev@lfdr.de>; Fri, 19 Dec 2025 16:46:29 +0100 (CET)
Received: by mail-lf1-x138.google.com with SMTP id 2adb3069b0e04-596af6ada80sf1956253e87.1
        for <lists+kasan-dev@lfdr.de>; Fri, 19 Dec 2025 07:46:29 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1766159189; cv=pass;
        d=google.com; s=arc-20240605;
        b=Hg9PFOz9wHx2Ogfx3P1C4jwi2k8ax55DzfW9odFUVdHNZ6OfP/STUZJmAhuZwuXx8i
         2OKmWkcXq8JsigVQuYQqcKCtNPZhBkoM9S9S5/ITel3p4LWarC5gMmb9DvQr48nTaHho
         dPXtHidNb8xBRwE9qEB6adHN/MThekkqufcuKLtoa2P1jRILJ3DUe1U8VemQ5AX+mHm9
         qebkjbqEoXhIHAfW5Z57tuSD/iEfR9TbGiX2uVHJ0dL0K5Kah/lV/upVwo1zi932Qs22
         03sS6gZHoTiR4EL00my3QkQJC6JPCCt/b/wj9naXCw6g6jCrGyAJxpWKpxTwF7lP8NBc
         Furw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=7etnXqwAku2SFiHWpZC38TmQYRrLRISyW1geSPk9yeY=;
        fh=LUfpzydN1jJfIR/XH5xX9Ci2ayKztlB9YyfKgeZAcPk=;
        b=OZN/52sFuD6Njj1Oxx/n7Sdk7I+MG7pVf3MJl+zZRodkgS7EEQj7b463KC/76y5H4K
         CqZ61vqypVqF5WXX/z8ppc5o0ab+gXI96SufDeAvfj/jp+20hJTyspm232WuNq15yF7M
         Kh81d9Z+o/k7xheOB8Dd2eSek6Yde9/OafemXaKsGvr5UK9vvL/7cY05NfesH+2XdDM1
         dbduqzITRdE5rpXpRdSFNaH6AseTSAY8LLlsQz7giGuRF4Y1Qx0TFFcxtA52aGhtDgO6
         L+qwGpy/n1HWh6Xfgm4GAsQ5WrNQ1lQWS3DPuejbaiFR0LEggKqEbUk3sJfHOVNfyv8k
         D6Pg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=yIWtFNtk;
       spf=pass (google.com: domain of 3uhnfaqukcz0bisbodlldib.9ljh7p7k-absdlldibdolrmp.9lj@flex--elver.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3UHNFaQUKCZ0BISBODLLDIB.9LJH7P7K-ABSDLLDIBDOLRMP.9LJ@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1766159189; x=1766763989; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=7etnXqwAku2SFiHWpZC38TmQYRrLRISyW1geSPk9yeY=;
        b=vWeDSOWFkbB37jqGj2Fa0Yg0fmfU6OFz/KEHA+PlG0t/97Qy5kXIGdsrJ1dWY27dlC
         89o18oE0aV8ZP/slnB+6k7GdrZbWP1RwKYAJRO8lzDPvvCOPyhlbgdeJ7khJ2Ms0d+oF
         6ptpbl26BYmGKKsyIK8nugSgywl/hlkTTNgD1+wYJ9OoVH3wCShDcnwEj3/TPvu8d1ec
         84Cp3m8E7X3YK8kdfhib9snQmXFxqtbApDB/WCfAv8/2N+owgOHQzE30jLsTDyj/lR7A
         qmH9/+6S5dVl4Uys6taRjg5RoCuINxhZr8/PIdqboAjxCIVik27wHUP1qygfD9YvCWwq
         jZ5g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1766159189; x=1766763989;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=7etnXqwAku2SFiHWpZC38TmQYRrLRISyW1geSPk9yeY=;
        b=aY8X7zkJXbPsnN8pQB8Tkor0OMDd/aJWhHC2514ZiHQY0YCSFEURNRMJfIh+lDU8gd
         pc1qf0QRY21/L3DorPXSwEgGxsNUZJzTcxNkjwwPVoTN9dX6p/BIQTvDOrQwKpxRKGsv
         hjLgR9fusAbN0r2vVtCDB9cr0Ao36w4HB43Lo/Uvj0w4beU0Z4DDbUr/Vd69BzZjA13f
         tn9ilguFMG7QPMv3qGaMDwQ9Jn7bU8cmkzpXvdUcxBg+cBoMEfS2JEhS/Sf4jgkW72Sp
         c8GSR47b4KLpCxUwYUvChKb6Lwek8pXeizhB60F0aOvJehZU4wFLjGpfhNEdZxIrsDUw
         92jQ==
X-Forwarded-Encrypted: i=2; AJvYcCXgdutswQTgZ7AuEncRGoOGZM7JKysq/toVCYPUhzuMP1lKbeLwFDqTGaW7uuvSXyGQJ3royg==@lfdr.de
X-Gm-Message-State: AOJu0Yy3BkOCOreRYHNnm0kBWxY/X2kTJoTWQEuqvD42L6ZQB36Kd1mU
	3Om618feFsEG6Yoj6PVgV4EnAGMwIw69TO354XvWQz42euds/36LwSER
X-Google-Smtp-Source: AGHT+IHMq+Cavzvce+nnht3QqfOuaY1UI1tbyW0wKuzyv7477oV0NQq2XJAJZsA5teAJ46RxJmbipA==
X-Received: by 2002:a05:6512:6d4:b0:595:7fed:aae9 with SMTP id 2adb3069b0e04-59a17d0a26emr1400836e87.12.1766159188351;
        Fri, 19 Dec 2025 07:46:28 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWYrmZhhgrBTaEubXbDYjOObPbn/C7hULMTm/NJg9JTKXQ=="
Received: by 2002:a05:6512:118a:b0:598:f360:1eef with SMTP id
 2adb3069b0e04-598fa3fdac8ls2710042e87.1.-pod-prod-07-eu; Fri, 19 Dec 2025
 07:46:25 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCX3i0Sc0iOyxDr5XbRN3lDeSXqIWmvd7xhmvqTAIyzxZT2kR1406uffAMbSfcw5ndj1TOoh3/YP0QU=@googlegroups.com
X-Received: by 2002:a05:6512:39ce:b0:597:d765:19f9 with SMTP id 2adb3069b0e04-59a17d057c9mr1140835e87.4.1766159185347;
        Fri, 19 Dec 2025 07:46:25 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1766159185; cv=none;
        d=google.com; s=arc-20240605;
        b=Yhkjiasl+zCVe14GZ/S96QHgw0Q5eGNc0M2SCHscgTSwkiYy1cLo5SI1sNAQw8vw6U
         eXNU2FwdkjJPbkyAJDshC8uLjPAFh4X2KqaI59pq2THml9C9aFhutV4ckasBeEgkK9YV
         YQV/DubAROTUoARzjdHeu4hp5YV4ewLlNxRe9wO5xZwSJI+UrvED2Iyx0GsXaBbdwkba
         26w1406/ZMqwSOCIHkxUr3OTCZmlj7aYDVz3C0DNSsKbs6OdZD/FsFr+Aj2JW5YKCRYc
         4yy/dKh7j6pofWmuuZ9rcFEgSrW8OwPcf05BjXQQ4eP92HWxEYg2mgT2qLglRM5JtN7i
         DplQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=HOUwolzbiNJSOFKZRnPKrSxaUxMsy/Gxmzf+65/vXT8=;
        fh=qPznzppoISK09w77awtdv82VcA5rfvnBeh3XzIA1VVQ=;
        b=kBiK4YsXfrNXomiA9gVayCwOR/3SWCYOEeAtQBw7sH9BWBhD9zyRY8KTlqnwTbmt9M
         u7lVaTuHiw74xTMJcLeR22A69fjwugYLlP+7XXg2NSaqeW24qokAzxLg2/i6kD0FztkM
         tKZyU0zbf8WOeBCWgHsLvq2SpX1BfFUmDqtfnB2VRGHcROiWK0Znfni94d+nlJWDoOzS
         AdDPF0ZOqnPX6AFgiwnlHz7BV5Eq9UWUfyRz7V5nc49HKrGdHsf2rkt78iPjxoemqhug
         Xjy9sliakONk+aMp3l/y08CEij2VrFhTBSj6wDqVPzWiKEuQrvac8a7eKtnrXjl21Ifu
         Lgog==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=yIWtFNtk;
       spf=pass (google.com: domain of 3uhnfaqukcz0bisbodlldib.9ljh7p7k-absdlldibdolrmp.9lj@flex--elver.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3UHNFaQUKCZ0BISBODLLDIB.9LJH7P7K-ABSDLLDIBDOLRMP.9LJ@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ed1-x54a.google.com (mail-ed1-x54a.google.com. [2a00:1450:4864:20::54a])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-59a1861bd48si62089e87.8.2025.12.19.07.46.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 19 Dec 2025 07:46:25 -0800 (PST)
Received-SPF: pass (google.com: domain of 3uhnfaqukcz0bisbodlldib.9ljh7p7k-absdlldibdolrmp.9lj@flex--elver.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) client-ip=2a00:1450:4864:20::54a;
Received: by mail-ed1-x54a.google.com with SMTP id 4fb4d7f45d1cf-64d01707c32so10339a12.1
        for <kasan-dev@googlegroups.com>; Fri, 19 Dec 2025 07:46:25 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCUfMPY+I3yyBlkkGxLI541a4DFS1pD7lgCTn+HqgppZfswpQm6JReuT3cabc2lYSMTSegSkjvM1VUc=@googlegroups.com
X-Received: from edzd6.prod.google.com ([2002:a05:6402:8c6:b0:64b:6d46:21e6])
 (user=elver job=prod-delivery.src-stubby-dispatcher) by 2002:a05:6402:1d53:b0:64b:654f:8738
 with SMTP id 4fb4d7f45d1cf-64b8e94bf4emr2676096a12.14.1766159184533; Fri, 19
 Dec 2025 07:46:24 -0800 (PST)
Date: Fri, 19 Dec 2025 16:40:04 +0100
In-Reply-To: <20251219154418.3592607-1-elver@google.com>
Mime-Version: 1.0
References: <20251219154418.3592607-1-elver@google.com>
X-Mailer: git-send-email 2.52.0.322.g1dd061c0dc-goog
Message-ID: <20251219154418.3592607-16-elver@google.com>
Subject: [PATCH v5 15/36] srcu: Support Clang's context analysis
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
 header.i=@google.com header.s=20230601 header.b=yIWtFNtk;       spf=pass
 (google.com: domain of 3uhnfaqukcz0bisbodlldib.9ljh7p7k-absdlldibdolrmp.9lj@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3UHNFaQUKCZ0BISBODLLDIB.9LJH7P7K-ABSDLLDIBDOLRMP.9LJ@flex--elver.bounces.google.com;
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

Add support for Clang's context analysis for SRCU.

Signed-off-by: Marco Elver <elver@google.com>
Acked-by: Paul E. McKenney <paulmck@kernel.org>
---
v5:
* Fix up annotation for recently added SRCU interfaces.
* Rename "context guard" -> "context lock".
* Use new cleanup.h helpers to properly support scoped lock guards.

v4:
* Rename capability -> context analysis.

v3:
* Switch to DECLARE_LOCK_GUARD_1_ATTRS() (suggested by Peter)
* Support SRCU being reentrant.
---
 Documentation/dev-tools/context-analysis.rst |  2 +-
 include/linux/srcu.h                         | 73 ++++++++++++++------
 include/linux/srcutiny.h                     |  6 ++
 include/linux/srcutree.h                     | 10 ++-
 lib/test_context-analysis.c                  | 25 +++++++
 5 files changed, 91 insertions(+), 25 deletions(-)

diff --git a/Documentation/dev-tools/context-analysis.rst b/Documentation/dev-tools/context-analysis.rst
index 3bc72f71fe25..f7736f1c0767 100644
--- a/Documentation/dev-tools/context-analysis.rst
+++ b/Documentation/dev-tools/context-analysis.rst
@@ -80,7 +80,7 @@ Supported Kernel Primitives
 
 Currently the following synchronization primitives are supported:
 `raw_spinlock_t`, `spinlock_t`, `rwlock_t`, `mutex`, `seqlock_t`,
-`bit_spinlock`, RCU.
+`bit_spinlock`, RCU, SRCU (`srcu_struct`).
 
 For context locks with an initialization function (e.g., `spin_lock_init()`),
 calling this function before initializing any guarded members or globals
diff --git a/include/linux/srcu.h b/include/linux/srcu.h
index 344ad51c8f6c..bb44a0bd7696 100644
--- a/include/linux/srcu.h
+++ b/include/linux/srcu.h
@@ -21,7 +21,7 @@
 #include <linux/workqueue.h>
 #include <linux/rcu_segcblist.h>
 
-struct srcu_struct;
+context_lock_struct(srcu_struct, __reentrant_ctx_lock);
 
 #ifdef CONFIG_DEBUG_LOCK_ALLOC
 
@@ -77,7 +77,7 @@ int init_srcu_struct_fast_updown(struct srcu_struct *ssp);
 #define SRCU_READ_FLAVOR_SLOWGP		(SRCU_READ_FLAVOR_FAST | SRCU_READ_FLAVOR_FAST_UPDOWN)
 						// Flavors requiring synchronize_rcu()
 						// instead of smp_mb().
-void __srcu_read_unlock(struct srcu_struct *ssp, int idx) __releases(ssp);
+void __srcu_read_unlock(struct srcu_struct *ssp, int idx) __releases_shared(ssp);
 
 #ifdef CONFIG_TINY_SRCU
 #include <linux/srcutiny.h>
@@ -131,14 +131,16 @@ static inline bool same_state_synchronize_srcu(unsigned long oldstate1, unsigned
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
@@ -210,6 +212,14 @@ static inline int srcu_read_lock_held(const struct srcu_struct *ssp)
 
 #endif /* #else #ifdef CONFIG_DEBUG_LOCK_ALLOC */
 
+/*
+ * No-op helper to denote that ssp must be held. Because SRCU-protected pointers
+ * should still be marked with __rcu_guarded, and we do not want to mark them
+ * with __guarded_by(ssp) as it would complicate annotations for writers, we
+ * choose the following strategy: srcu_dereference_check() calls this helper
+ * that checks that the passed ssp is held, and then fake-acquires 'RCU'.
+ */
+static inline void __srcu_read_lock_must_hold(const struct srcu_struct *ssp) __must_hold_shared(ssp) { }
 
 /**
  * srcu_dereference_check - fetch SRCU-protected pointer for later dereferencing
@@ -223,9 +233,15 @@ static inline int srcu_read_lock_held(const struct srcu_struct *ssp)
  * to 1.  The @c argument will normally be a logical expression containing
  * lockdep_is_held() calls.
  */
-#define srcu_dereference_check(p, ssp, c) \
-	__rcu_dereference_check((p), __UNIQUE_ID(rcu), \
-				(c) || srcu_read_lock_held(ssp), __rcu)
+#define srcu_dereference_check(p, ssp, c)					\
+({										\
+	__srcu_read_lock_must_hold(ssp);					\
+	__acquire_shared_ctx_lock(RCU);					\
+	__auto_type __v = __rcu_dereference_check((p), __UNIQUE_ID(rcu),	\
+				(c) || srcu_read_lock_held(ssp), __rcu);	\
+	__release_shared_ctx_lock(RCU);					\
+	__v;									\
+})
 
 /**
  * srcu_dereference - fetch SRCU-protected pointer for later dereferencing
@@ -268,7 +284,8 @@ static inline int srcu_read_lock_held(const struct srcu_struct *ssp)
  * invoke srcu_read_unlock() from one task and the matching srcu_read_lock()
  * from another.
  */
-static inline int srcu_read_lock(struct srcu_struct *ssp) __acquires(ssp)
+static inline int srcu_read_lock(struct srcu_struct *ssp)
+	__acquires_shared(ssp)
 {
 	int retval;
 
@@ -304,7 +321,8 @@ static inline int srcu_read_lock(struct srcu_struct *ssp) __acquires(ssp)
  * contexts where RCU is watching, that is, from contexts where it would
  * be legal to invoke rcu_read_lock().  Otherwise, lockdep will complain.
  */
-static inline struct srcu_ctr __percpu *srcu_read_lock_fast(struct srcu_struct *ssp) __acquires(ssp)
+static inline struct srcu_ctr __percpu *srcu_read_lock_fast(struct srcu_struct *ssp) __acquires_shared(ssp)
+	__acquires_shared(ssp)
 {
 	struct srcu_ctr __percpu *retval;
 
@@ -344,7 +362,7 @@ static inline struct srcu_ctr __percpu *srcu_read_lock_fast(struct srcu_struct *
  * complain.
  */
 static inline struct srcu_ctr __percpu *srcu_read_lock_fast_updown(struct srcu_struct *ssp)
-__acquires(ssp)
+	__acquires_shared(ssp)
 {
 	struct srcu_ctr __percpu *retval;
 
@@ -360,7 +378,7 @@ __acquires(ssp)
  * See srcu_read_lock_fast() for more information.
  */
 static inline struct srcu_ctr __percpu *srcu_read_lock_fast_notrace(struct srcu_struct *ssp)
-	__acquires(ssp)
+	__acquires_shared(ssp)
 {
 	struct srcu_ctr __percpu *retval;
 
@@ -381,7 +399,7 @@ static inline struct srcu_ctr __percpu *srcu_read_lock_fast_notrace(struct srcu_
  * and srcu_read_lock_fast().  However, the same definition/initialization
  * requirements called out for srcu_read_lock_safe() apply.
  */
-static inline struct srcu_ctr __percpu *srcu_down_read_fast(struct srcu_struct *ssp) __acquires(ssp)
+static inline struct srcu_ctr __percpu *srcu_down_read_fast(struct srcu_struct *ssp) __acquires_shared(ssp)
 {
 	WARN_ON_ONCE(IS_ENABLED(CONFIG_PROVE_RCU) && in_nmi());
 	RCU_LOCKDEP_WARN(!rcu_is_watching(), "RCU must be watching srcu_down_read_fast().");
@@ -400,7 +418,8 @@ static inline struct srcu_ctr __percpu *srcu_down_read_fast(struct srcu_struct *
  * then none of the other flavors may be used, whether before, during,
  * or after.
  */
-static inline int srcu_read_lock_nmisafe(struct srcu_struct *ssp) __acquires(ssp)
+static inline int srcu_read_lock_nmisafe(struct srcu_struct *ssp)
+	__acquires_shared(ssp)
 {
 	int retval;
 
@@ -412,7 +431,8 @@ static inline int srcu_read_lock_nmisafe(struct srcu_struct *ssp) __acquires(ssp
 
 /* Used by tracing, cannot be traced and cannot invoke lockdep. */
 static inline notrace int
-srcu_read_lock_notrace(struct srcu_struct *ssp) __acquires(ssp)
+srcu_read_lock_notrace(struct srcu_struct *ssp)
+	__acquires_shared(ssp)
 {
 	int retval;
 
@@ -443,7 +463,8 @@ srcu_read_lock_notrace(struct srcu_struct *ssp) __acquires(ssp)
  * which calls to down_read() may be nested.  The same srcu_struct may be
  * used concurrently by srcu_down_read() and srcu_read_lock().
  */
-static inline int srcu_down_read(struct srcu_struct *ssp) __acquires(ssp)
+static inline int srcu_down_read(struct srcu_struct *ssp)
+	__acquires_shared(ssp)
 {
 	WARN_ON_ONCE(in_nmi());
 	srcu_check_read_flavor(ssp, SRCU_READ_FLAVOR_NORMAL);
@@ -458,7 +479,7 @@ static inline int srcu_down_read(struct srcu_struct *ssp) __acquires(ssp)
  * Exit an SRCU read-side critical section.
  */
 static inline void srcu_read_unlock(struct srcu_struct *ssp, int idx)
-	__releases(ssp)
+	__releases_shared(ssp)
 {
 	WARN_ON_ONCE(idx & ~0x1);
 	srcu_check_read_flavor(ssp, SRCU_READ_FLAVOR_NORMAL);
@@ -474,7 +495,7 @@ static inline void srcu_read_unlock(struct srcu_struct *ssp, int idx)
  * Exit a light-weight SRCU read-side critical section.
  */
 static inline void srcu_read_unlock_fast(struct srcu_struct *ssp, struct srcu_ctr __percpu *scp)
-	__releases(ssp)
+	__releases_shared(ssp)
 {
 	srcu_check_read_flavor(ssp, SRCU_READ_FLAVOR_FAST);
 	srcu_lock_release(&ssp->dep_map);
@@ -490,7 +511,7 @@ static inline void srcu_read_unlock_fast(struct srcu_struct *ssp, struct srcu_ct
  * Exit an SRCU-fast-updown read-side critical section.
  */
 static inline void
-srcu_read_unlock_fast_updown(struct srcu_struct *ssp, struct srcu_ctr __percpu *scp) __releases(ssp)
+srcu_read_unlock_fast_updown(struct srcu_struct *ssp, struct srcu_ctr __percpu *scp) __releases_shared(ssp)
 {
 	srcu_check_read_flavor(ssp, SRCU_READ_FLAVOR_FAST_UPDOWN);
 	srcu_lock_release(&ssp->dep_map);
@@ -504,7 +525,7 @@ srcu_read_unlock_fast_updown(struct srcu_struct *ssp, struct srcu_ctr __percpu *
  * See srcu_read_unlock_fast() for more information.
  */
 static inline void srcu_read_unlock_fast_notrace(struct srcu_struct *ssp,
-						 struct srcu_ctr __percpu *scp) __releases(ssp)
+						 struct srcu_ctr __percpu *scp) __releases_shared(ssp)
 {
 	srcu_check_read_flavor(ssp, SRCU_READ_FLAVOR_FAST);
 	__srcu_read_unlock_fast(ssp, scp);
@@ -519,7 +540,7 @@ static inline void srcu_read_unlock_fast_notrace(struct srcu_struct *ssp,
  * the same context as the maching srcu_down_read_fast().
  */
 static inline void srcu_up_read_fast(struct srcu_struct *ssp, struct srcu_ctr __percpu *scp)
-	__releases(ssp)
+	__releases_shared(ssp)
 {
 	WARN_ON_ONCE(IS_ENABLED(CONFIG_PROVE_RCU) && in_nmi());
 	srcu_check_read_flavor(ssp, SRCU_READ_FLAVOR_FAST_UPDOWN);
@@ -535,7 +556,7 @@ static inline void srcu_up_read_fast(struct srcu_struct *ssp, struct srcu_ctr __
  * Exit an SRCU read-side critical section, but in an NMI-safe manner.
  */
 static inline void srcu_read_unlock_nmisafe(struct srcu_struct *ssp, int idx)
-	__releases(ssp)
+	__releases_shared(ssp)
 {
 	WARN_ON_ONCE(idx & ~0x1);
 	srcu_check_read_flavor(ssp, SRCU_READ_FLAVOR_NMI);
@@ -545,7 +566,7 @@ static inline void srcu_read_unlock_nmisafe(struct srcu_struct *ssp, int idx)
 
 /* Used by tracing, cannot be traced and cannot call lockdep. */
 static inline notrace void
-srcu_read_unlock_notrace(struct srcu_struct *ssp, int idx) __releases(ssp)
+srcu_read_unlock_notrace(struct srcu_struct *ssp, int idx) __releases_shared(ssp)
 {
 	srcu_check_read_flavor(ssp, SRCU_READ_FLAVOR_NORMAL);
 	__srcu_read_unlock(ssp, idx);
@@ -560,7 +581,7 @@ srcu_read_unlock_notrace(struct srcu_struct *ssp, int idx) __releases(ssp)
  * the same context as the maching srcu_down_read().
  */
 static inline void srcu_up_read(struct srcu_struct *ssp, int idx)
-	__releases(ssp)
+	__releases_shared(ssp)
 {
 	WARN_ON_ONCE(idx & ~0x1);
 	WARN_ON_ONCE(in_nmi());
@@ -600,15 +621,21 @@ DEFINE_LOCK_GUARD_1(srcu, struct srcu_struct,
 		    _T->idx = srcu_read_lock(_T->lock),
 		    srcu_read_unlock(_T->lock, _T->idx),
 		    int idx)
+DECLARE_LOCK_GUARD_1_ATTRS(srcu, __acquires_shared(_T), __releases_shared(*(struct srcu_struct **)_T))
+#define class_srcu_constructor(_T) WITH_LOCK_GUARD_1_ATTRS(srcu, _T)
 
 DEFINE_LOCK_GUARD_1(srcu_fast, struct srcu_struct,
 		    _T->scp = srcu_read_lock_fast(_T->lock),
 		    srcu_read_unlock_fast(_T->lock, _T->scp),
 		    struct srcu_ctr __percpu *scp)
+DECLARE_LOCK_GUARD_1_ATTRS(srcu_fast, __acquires_shared(_T), __releases_shared(*(struct srcu_struct **)_T))
+#define class_srcu_fast_constructor(_T) WITH_LOCK_GUARD_1_ATTRS(srcu_fast, _T)
 
 DEFINE_LOCK_GUARD_1(srcu_fast_notrace, struct srcu_struct,
 		    _T->scp = srcu_read_lock_fast_notrace(_T->lock),
 		    srcu_read_unlock_fast_notrace(_T->lock, _T->scp),
 		    struct srcu_ctr __percpu *scp)
+DECLARE_LOCK_GUARD_1_ATTRS(srcu_fast_notrace, __acquires_shared(_T), __releases_shared(*(struct srcu_struct **)_T))
+#define class_srcu_fast_notrace_constructor(_T) WITH_LOCK_GUARD_1_ATTRS(srcu_fast_notrace, _T)
 
 #endif
diff --git a/include/linux/srcutiny.h b/include/linux/srcutiny.h
index e0698024667a..dec7cbe015aa 100644
--- a/include/linux/srcutiny.h
+++ b/include/linux/srcutiny.h
@@ -73,6 +73,7 @@ void synchronize_srcu(struct srcu_struct *ssp);
  * index that must be passed to the matching srcu_read_unlock().
  */
 static inline int __srcu_read_lock(struct srcu_struct *ssp)
+	__acquires_shared(ssp)
 {
 	int idx;
 
@@ -80,6 +81,7 @@ static inline int __srcu_read_lock(struct srcu_struct *ssp)
 	idx = ((READ_ONCE(ssp->srcu_idx) + 1) & 0x2) >> 1;
 	WRITE_ONCE(ssp->srcu_lock_nesting[idx], READ_ONCE(ssp->srcu_lock_nesting[idx]) + 1);
 	preempt_enable();
+	__acquire_shared(ssp);
 	return idx;
 }
 
@@ -96,22 +98,26 @@ static inline struct srcu_ctr __percpu *__srcu_ctr_to_ptr(struct srcu_struct *ss
 }
 
 static inline struct srcu_ctr __percpu *__srcu_read_lock_fast(struct srcu_struct *ssp)
+	__acquires_shared(ssp)
 {
 	return __srcu_ctr_to_ptr(ssp, __srcu_read_lock(ssp));
 }
 
 static inline void __srcu_read_unlock_fast(struct srcu_struct *ssp, struct srcu_ctr __percpu *scp)
+	__releases_shared(ssp)
 {
 	__srcu_read_unlock(ssp, __srcu_ptr_to_ctr(ssp, scp));
 }
 
 static inline struct srcu_ctr __percpu *__srcu_read_lock_fast_updown(struct srcu_struct *ssp)
+	__acquires_shared(ssp)
 {
 	return __srcu_ctr_to_ptr(ssp, __srcu_read_lock(ssp));
 }
 
 static inline
 void __srcu_read_unlock_fast_updown(struct srcu_struct *ssp, struct srcu_ctr __percpu *scp)
+	__releases_shared(ssp)
 {
 	__srcu_read_unlock(ssp, __srcu_ptr_to_ctr(ssp, scp));
 }
diff --git a/include/linux/srcutree.h b/include/linux/srcutree.h
index d6f978b50472..958cb7ef41cb 100644
--- a/include/linux/srcutree.h
+++ b/include/linux/srcutree.h
@@ -233,7 +233,7 @@ struct srcu_struct {
 #define DEFINE_STATIC_SRCU_FAST_UPDOWN(name) \
 					__DEFINE_SRCU(name, SRCU_READ_FLAVOR_FAST_UPDOWN, static)
 
-int __srcu_read_lock(struct srcu_struct *ssp) __acquires(ssp);
+int __srcu_read_lock(struct srcu_struct *ssp) __acquires_shared(ssp);
 void synchronize_srcu_expedited(struct srcu_struct *ssp);
 void srcu_barrier(struct srcu_struct *ssp);
 void srcu_expedite_current(struct srcu_struct *ssp);
@@ -286,6 +286,7 @@ static inline struct srcu_ctr __percpu *__srcu_ctr_to_ptr(struct srcu_struct *ss
  * implementations of this_cpu_inc().
  */
 static inline struct srcu_ctr __percpu notrace *__srcu_read_lock_fast(struct srcu_struct *ssp)
+	__acquires_shared(ssp)
 {
 	struct srcu_ctr __percpu *scp = READ_ONCE(ssp->srcu_ctrp);
 
@@ -294,6 +295,7 @@ static inline struct srcu_ctr __percpu notrace *__srcu_read_lock_fast(struct src
 	else
 		atomic_long_inc(raw_cpu_ptr(&scp->srcu_locks));  // Y, and implicit RCU reader.
 	barrier(); /* Avoid leaking the critical section. */
+	__acquire_shared(ssp);
 	return scp;
 }
 
@@ -308,7 +310,9 @@ static inline struct srcu_ctr __percpu notrace *__srcu_read_lock_fast(struct src
  */
 static inline void notrace
 __srcu_read_unlock_fast(struct srcu_struct *ssp, struct srcu_ctr __percpu *scp)
+	__releases_shared(ssp)
 {
+	__release_shared(ssp);
 	barrier();  /* Avoid leaking the critical section. */
 	if (!IS_ENABLED(CONFIG_NEED_SRCU_NMI_SAFE))
 		this_cpu_inc(scp->srcu_unlocks.counter);  // Z, and implicit RCU reader.
@@ -326,6 +330,7 @@ __srcu_read_unlock_fast(struct srcu_struct *ssp, struct srcu_ctr __percpu *scp)
  */
 static inline
 struct srcu_ctr __percpu notrace *__srcu_read_lock_fast_updown(struct srcu_struct *ssp)
+	__acquires_shared(ssp)
 {
 	struct srcu_ctr __percpu *scp = READ_ONCE(ssp->srcu_ctrp);
 
@@ -334,6 +339,7 @@ struct srcu_ctr __percpu notrace *__srcu_read_lock_fast_updown(struct srcu_struc
 	else
 		atomic_long_inc(raw_cpu_ptr(&scp->srcu_locks));  // Y, and implicit RCU reader.
 	barrier(); /* Avoid leaking the critical section. */
+	__acquire_shared(ssp);
 	return scp;
 }
 
@@ -348,7 +354,9 @@ struct srcu_ctr __percpu notrace *__srcu_read_lock_fast_updown(struct srcu_struc
  */
 static inline void notrace
 __srcu_read_unlock_fast_updown(struct srcu_struct *ssp, struct srcu_ctr __percpu *scp)
+	__releases_shared(ssp)
 {
+	__release_shared(ssp);
 	barrier();  /* Avoid leaking the critical section. */
 	if (!IS_ENABLED(CONFIG_NEED_SRCU_NMI_SAFE))
 		this_cpu_inc(scp->srcu_unlocks.counter);  // Z, and implicit RCU reader.
diff --git a/lib/test_context-analysis.c b/lib/test_context-analysis.c
index 559df32fb5f8..39e03790c0f6 100644
--- a/lib/test_context-analysis.c
+++ b/lib/test_context-analysis.c
@@ -10,6 +10,7 @@
 #include <linux/rcupdate.h>
 #include <linux/seqlock.h>
 #include <linux/spinlock.h>
+#include <linux/srcu.h>
 
 /*
  * Test that helper macros work as expected.
@@ -369,3 +370,27 @@ static void __used test_rcu_assert_variants(void)
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
+	{ guard(srcu)(&d->srcu); (void)srcu_dereference(d->data, &d->srcu); }
+	{ guard(srcu_fast)(&d->srcu); (void)srcu_dereference(d->data, &d->srcu); }
+	{ guard(srcu_fast_notrace)(&d->srcu); (void)srcu_dereference(d->data, &d->srcu); }
+}
-- 
2.52.0.322.g1dd061c0dc-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251219154418.3592607-16-elver%40google.com.
