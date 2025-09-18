Return-Path: <kasan-dev+bncBC7OBJGL2MHBBUVDWDDAMGQERXTUD6Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33b.google.com (mail-wm1-x33b.google.com [IPv6:2a00:1450:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id 35483B84FAE
	for <lists+kasan-dev@lfdr.de>; Thu, 18 Sep 2025 16:06:12 +0200 (CEST)
Received: by mail-wm1-x33b.google.com with SMTP id 5b1f17b1804b1-45dd5c1b67dsf5230715e9.2
        for <lists+kasan-dev@lfdr.de>; Thu, 18 Sep 2025 07:06:12 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758204371; cv=pass;
        d=google.com; s=arc-20240605;
        b=Qd5igD9E2GHOratpEoPyu/0GaOW7RKAQWHDPkH44AzmGqLfksvkIMR1K2KM59kfsNi
         /DmcXZWn2tK8fV/nB3C21hgHjdj9FXxGkcvVOd8+UOMfCujXSQEFBTiRhR9X+q74NHC6
         qPdPLI3UyKvgsRrOB5ooDpawT2UMnAN7b7gnEstKkhIGP4vUQKpsaODkO/cZ4BBykvKF
         UZBHlGCj5dh2WNQ5cBO2vUYtyCVQ+LO2B6LX9TJzNgUbLhUjkSpmbKAr3RzL8yvZTRz7
         FNWx5gGGvwoiNEVkL/Q7cxsPoLLPzAuSO7hNCFbkrzgMuQUvUqLZpzfTSx/juxnBATNc
         E6NQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=WC4WXv7rxJ4oeIJ3QBG0sF5k2dpUBIj9TlygB28jWdE=;
        fh=eWvAPnvnZ8BltTsnrakXpU+ceP5Du3SdLj3Qwmgf7oE=;
        b=Sw1yCLgCCvAYBLF9/HxNpUp+6LDUQ6UArCmO7dnDTbe7c0Het6/Y8jC17TZQb4/TVU
         swdieG9uiRZ4qC+wYni5rWyXVqjtUU0pgAn+4bP8OYPFFXhPihVun5UL6DP59Bov/CKU
         FIfcfPOoZXGRvpAa9HgcqEXZ7Y2e4OOWGf+gNUH6fFUgySs59Hid9R9s9AbmAm+euzNi
         SOa7zINsWbLtZXJ+wX25YQgPTeopgzj+Y2zdF97q7vm6/cwarNLT3vtMhrXcGOdB6qkh
         FVJ/FKp6mPViqGqP0yzKIVAh7aTSFUcyv8MZFtoG+aZ2nkzmiBSGIkOMiHahnsd33cGg
         ltbg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=nOaWrsFs;
       spf=pass (google.com: domain of 3zxhmaaukcxaszjsfuccuzs.qcayogob-rsjuccuzsufcidg.qca@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3zxHMaAUKCXASZjSfUccUZS.QcaYOgOb-RSjUccUZSUfcidg.Qca@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758204371; x=1758809171; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=WC4WXv7rxJ4oeIJ3QBG0sF5k2dpUBIj9TlygB28jWdE=;
        b=BZ6EBJVR7YaxU4nEV9Qy1oQgVieflC26sm1jmZ/vxCITXy/UTRqI+ieejd03F7RWhS
         AEfrpdBUvOERkZm9Q81acAOx/5Wh+FH2aaXteyuxIqoJPj+hUf9ACTtM6mj/jbJxtano
         N/jsMQmD1wL7U+6PuHkyxQFPeorxXJPVQxs7cyMoPuL4nA5OlYVbhqt8vCvO+37d2hnX
         eVUBRdc2ArzhakYMy0Sqf3Om5Xnq6epfJqoo4adcIpzoTgYw0dmpvCFvT1R9Fia7em6w
         LjAn7jIMd4absNUHwE3MEJh5y+VFz7ZmBXagUU+5aOh+aKLXFw8nTKniqELeXLt5UNVi
         QKnQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758204371; x=1758809171;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=WC4WXv7rxJ4oeIJ3QBG0sF5k2dpUBIj9TlygB28jWdE=;
        b=sznQmb7F6essQzwJ5iXdHmmXhQackDulCaiyIhxtnmNrANnuPJJGryJZppKMGRkO8b
         gLKFid/KKg5MkpDBe+i8HjI+ZhsFpfg3iYCQWZALsXphjq/p05xxJoT9aSYhDJiL7zx4
         9JKAEfO1cINtRLTl6wO5DNeoUNjz2koieS2eW9iLgQOzplV5dJoFY8CTVn5aZ2sOBSG7
         OAEE71o7g7fTDl/dh0PadTYTZ4Ia0ufbS8jINKEdtU/RSzCaXdKXzEsA6GMzK/00DqLZ
         LyzDwKjlLBozsJvMCMhpuzPxImgv2evf6k9RYON4n0dC//J/gqPwmr2W1bY2UZEcoiKx
         NfiQ==
X-Forwarded-Encrypted: i=2; AJvYcCUaacBc9aDikrExB77EYsdoCUbRrknqMkhz6KNBJ72MViNo8TYswtiTaZ+F16AF2ycDRFPmVw==@lfdr.de
X-Gm-Message-State: AOJu0YxCO/VormK20lew+dwgGhy5SrqLE5EfaLn2gNo650pRYBmpBQ7U
	grNA9UeN2GjSSGZhDd/5oMiwAmKl8E27S3G0ES33j4iYbxrsgbPvbtTY
X-Google-Smtp-Source: AGHT+IEbeP/e3K4qW0ETyBIuMUaHFhTcvUOaBAhTjSE52KVTTgi8yVpQb6wjqIvLEXOduRMxp046Zg==
X-Received: by 2002:a05:600c:4fc7:b0:45f:2843:e779 with SMTP id 5b1f17b1804b1-46202bf79c1mr73025355e9.8.1758204371433;
        Thu, 18 Sep 2025 07:06:11 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd4bRoasbTlC09LhYjE0Ad+UNXFI18yM6HkhfrJEavHvIA==
Received: by 2002:a05:600c:4ed4:b0:456:241d:50bd with SMTP id
 5b1f17b1804b1-46543cea6d3ls4791255e9.2.-pod-prod-04-eu; Thu, 18 Sep 2025
 07:06:08 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVrZnA9ZxzJfjdtllQErjEW+LNTcBLV5YbkPWRF8hveHQcrbsEIXt/jzQyu6JBE41obGSXzF3ygTwg=@googlegroups.com
X-Received: by 2002:a05:6000:2901:b0:3e4:64b0:a75d with SMTP id ffacd0b85a97d-3ecdfa5295bmr4896109f8f.30.1758204368405;
        Thu, 18 Sep 2025 07:06:08 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1758204368; cv=none;
        d=google.com; s=arc-20240605;
        b=BUJYKOX5FHIxAVUy65oFwBi4cUZEVucE0gUthC3Pl+GA+NdhkNqRrjd5i36o9C0vVJ
         5ABlgdGpauJZ3l9QlYwqTvxraBqhtagLKwl6/5ZnrfdYdqg1JZuAagl3OU9kal/nlqME
         WG65JfRIMT8hNgHuZCap0p+5yA77/ka878zO7m5cK+INofLOwgpx5VWqPc3zoBNPoDZg
         ux+KXzdQUe1xKVfhYDKc3MiQyvEJ0DnwsZKcKxZRWQdrWEGLkzLiKqvh+KesVU3u1I59
         QeyQSNkvmvWt+qgxdo9XKhqDJmrEKRLHhZv1fsbmBrxjOb0TX5NIpNhJBQU4/+PJmA41
         NDyg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=uZC4ZOE8JE+M8LbYw3r+YcY7P7dk+Wk5ZJQlr/Vrksc=;
        fh=e88Jp9WlUtzGqFHc15/cituRmGNUEYjCOXGyucLSOPY=;
        b=FKTOBmgzWm3+FVu037brJ4jkCdardypYFLMzM5eSEuQ9yp+Jl8lTqrET/0tdxiLd/8
         1y6y/igamC1TeX7Xxl4H6dLJTfctihFc40+h651MyjZzIbK6+5/xm7IiO8Xh7aZUP4JD
         xx3vcNG4EwkRxfAPu9v8s27PM/GdZGYh2I7avO3t3qwiLKRkrFmCbWLaiu6FUUIxRCo1
         eZ2t7/OuzqioKbBgRGXuDC4GsN84z5pTRJPka5dCpG63ehd7O+L1ik2yNhIWhG8v9vII
         pxSrjt5YVr6t3exC8o/zXMltuXdOgfEs51sfc5tnPt/fhjYMyH8RpqkacQR9ueZTjS7K
         WtuQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=nOaWrsFs;
       spf=pass (google.com: domain of 3zxhmaaukcxaszjsfuccuzs.qcayogob-rsjuccuzsufcidg.qca@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3zxHMaAUKCXASZjSfUccUZS.QcaYOgOb-RSjUccUZSUfcidg.Qca@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x349.google.com (mail-wm1-x349.google.com. [2a00:1450:4864:20::349])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-3edff885cf2si50020f8f.0.2025.09.18.07.06.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 18 Sep 2025 07:06:08 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3zxhmaaukcxaszjsfuccuzs.qcayogob-rsjuccuzsufcidg.qca@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) client-ip=2a00:1450:4864:20::349;
Received: by mail-wm1-x349.google.com with SMTP id 5b1f17b1804b1-45de18e7eccso5837685e9.0
        for <kasan-dev@googlegroups.com>; Thu, 18 Sep 2025 07:06:08 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXaI9TasREVdz8WczuHtufNh2+t36kmm8uc9ucj6euGWXqhFaRbKHE9kFKMkj+L1z4LQtzQZyFKYXc=@googlegroups.com
X-Received: from wrva2.prod.google.com ([2002:a5d:5702:0:b0:3ed:e1d6:f198])
 (user=elver job=prod-delivery.src-stubby-dispatcher) by 2002:a05:6000:2601:b0:3e2:da00:44af
 with SMTP id ffacd0b85a97d-3ecdfa1ebbfmr5132620f8f.36.1758204367579; Thu, 18
 Sep 2025 07:06:07 -0700 (PDT)
Date: Thu, 18 Sep 2025 15:59:26 +0200
In-Reply-To: <20250918140451.1289454-1-elver@google.com>
Mime-Version: 1.0
References: <20250918140451.1289454-1-elver@google.com>
X-Mailer: git-send-email 2.51.0.384.g4c02a37b29-goog
Message-ID: <20250918140451.1289454-16-elver@google.com>
Subject: [PATCH v3 15/35] srcu: Support Clang's capability analysis
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
 header.i=@google.com header.s=20230601 header.b=nOaWrsFs;       spf=pass
 (google.com: domain of 3zxhmaaukcxaszjsfuccuzs.qcayogob-rsjuccuzsufcidg.qca@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3zxHMaAUKCXASZjSfUccUZS.QcaYOgOb-RSjUccUZSUfcidg.Qca@flex--elver.bounces.google.com;
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
v3:
* Switch to DECLARE_LOCK_GUARD_1_ATTRS() (suggested by Peter)
* Support SRCU being reentrant.
---
 .../dev-tools/capability-analysis.rst         |  2 +-
 include/linux/srcu.h                          | 60 +++++++++++++------
 include/linux/srcutiny.h                      |  4 ++
 include/linux/srcutree.h                      |  6 +-
 lib/test_capability-analysis.c                | 24 ++++++++
 5 files changed, 75 insertions(+), 21 deletions(-)

diff --git a/Documentation/dev-tools/capability-analysis.rst b/Documentation/dev-tools/capability-analysis.rst
index fdacc7f73da8..779ecb5ec17a 100644
--- a/Documentation/dev-tools/capability-analysis.rst
+++ b/Documentation/dev-tools/capability-analysis.rst
@@ -82,7 +82,7 @@ Supported Kernel Primitives
 
 Currently the following synchronization primitives are supported:
 `raw_spinlock_t`, `spinlock_t`, `rwlock_t`, `mutex`, `seqlock_t`,
-`bit_spinlock`, RCU.
+`bit_spinlock`, RCU, SRCU (`srcu_struct`).
 
 For capabilities with an initialization function (e.g., `spin_lock_init()`),
 calling this function on the capability instance before initializing any
diff --git a/include/linux/srcu.h b/include/linux/srcu.h
index f179700fecaf..6cafaf6dde71 100644
--- a/include/linux/srcu.h
+++ b/include/linux/srcu.h
@@ -21,7 +21,7 @@
 #include <linux/workqueue.h>
 #include <linux/rcu_segcblist.h>
 
-struct srcu_struct;
+struct_with_capability(srcu_struct, __reentrant_cap);
 
 #ifdef CONFIG_DEBUG_LOCK_ALLOC
 
@@ -53,7 +53,7 @@ int init_srcu_struct(struct srcu_struct *ssp);
 #define SRCU_READ_FLAVOR_SLOWGP	SRCU_READ_FLAVOR_FAST
 						// Flavors requiring synchronize_rcu()
 						// instead of smp_mb().
-void __srcu_read_unlock(struct srcu_struct *ssp, int idx) __releases(ssp);
+void __srcu_read_unlock(struct srcu_struct *ssp, int idx) __releases_shared(ssp);
 
 #ifdef CONFIG_TINY_SRCU
 #include <linux/srcutiny.h>
@@ -107,14 +107,16 @@ static inline bool same_state_synchronize_srcu(unsigned long oldstate1, unsigned
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
@@ -186,6 +188,14 @@ static inline int srcu_read_lock_held(const struct srcu_struct *ssp)
 
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
@@ -199,9 +209,15 @@ static inline int srcu_read_lock_held(const struct srcu_struct *ssp)
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
@@ -244,7 +260,8 @@ static inline int srcu_read_lock_held(const struct srcu_struct *ssp)
  * invoke srcu_read_unlock() from one task and the matching srcu_read_lock()
  * from another.
  */
-static inline int srcu_read_lock(struct srcu_struct *ssp) __acquires(ssp)
+static inline int srcu_read_lock(struct srcu_struct *ssp)
+	__acquires_shared(ssp)
 {
 	int retval;
 
@@ -271,7 +288,8 @@ static inline int srcu_read_lock(struct srcu_struct *ssp) __acquires(ssp)
  * where RCU is watching, that is, from contexts where it would be legal
  * to invoke rcu_read_lock().  Otherwise, lockdep will complain.
  */
-static inline struct srcu_ctr __percpu *srcu_read_lock_fast(struct srcu_struct *ssp) __acquires(ssp)
+static inline struct srcu_ctr __percpu *srcu_read_lock_fast(struct srcu_struct *ssp) __acquires_shared(ssp)
+	__acquires_shared(ssp)
 {
 	struct srcu_ctr __percpu *retval;
 
@@ -292,7 +310,7 @@ static inline struct srcu_ctr __percpu *srcu_read_lock_fast(struct srcu_struct *
  * The same srcu_struct may be used concurrently by srcu_down_read_fast()
  * and srcu_read_lock_fast().
  */
-static inline struct srcu_ctr __percpu *srcu_down_read_fast(struct srcu_struct *ssp) __acquires(ssp)
+static inline struct srcu_ctr __percpu *srcu_down_read_fast(struct srcu_struct *ssp) __acquires_shared(ssp)
 {
 	WARN_ON_ONCE(IS_ENABLED(CONFIG_PROVE_RCU) && in_nmi());
 	srcu_check_read_flavor_force(ssp, SRCU_READ_FLAVOR_FAST);
@@ -310,7 +328,8 @@ static inline struct srcu_ctr __percpu *srcu_down_read_fast(struct srcu_struct *
  * then none of the other flavors may be used, whether before, during,
  * or after.
  */
-static inline int srcu_read_lock_nmisafe(struct srcu_struct *ssp) __acquires(ssp)
+static inline int srcu_read_lock_nmisafe(struct srcu_struct *ssp)
+	__acquires_shared(ssp)
 {
 	int retval;
 
@@ -322,7 +341,8 @@ static inline int srcu_read_lock_nmisafe(struct srcu_struct *ssp) __acquires(ssp
 
 /* Used by tracing, cannot be traced and cannot invoke lockdep. */
 static inline notrace int
-srcu_read_lock_notrace(struct srcu_struct *ssp) __acquires(ssp)
+srcu_read_lock_notrace(struct srcu_struct *ssp)
+	__acquires_shared(ssp)
 {
 	int retval;
 
@@ -353,7 +373,8 @@ srcu_read_lock_notrace(struct srcu_struct *ssp) __acquires(ssp)
  * which calls to down_read() may be nested.  The same srcu_struct may be
  * used concurrently by srcu_down_read() and srcu_read_lock().
  */
-static inline int srcu_down_read(struct srcu_struct *ssp) __acquires(ssp)
+static inline int srcu_down_read(struct srcu_struct *ssp)
+	__acquires_shared(ssp)
 {
 	WARN_ON_ONCE(in_nmi());
 	srcu_check_read_flavor(ssp, SRCU_READ_FLAVOR_NORMAL);
@@ -368,7 +389,7 @@ static inline int srcu_down_read(struct srcu_struct *ssp) __acquires(ssp)
  * Exit an SRCU read-side critical section.
  */
 static inline void srcu_read_unlock(struct srcu_struct *ssp, int idx)
-	__releases(ssp)
+	__releases_shared(ssp)
 {
 	WARN_ON_ONCE(idx & ~0x1);
 	srcu_check_read_flavor(ssp, SRCU_READ_FLAVOR_NORMAL);
@@ -384,7 +405,7 @@ static inline void srcu_read_unlock(struct srcu_struct *ssp, int idx)
  * Exit a light-weight SRCU read-side critical section.
  */
 static inline void srcu_read_unlock_fast(struct srcu_struct *ssp, struct srcu_ctr __percpu *scp)
-	__releases(ssp)
+	__releases_shared(ssp)
 {
 	srcu_check_read_flavor(ssp, SRCU_READ_FLAVOR_FAST);
 	srcu_lock_release(&ssp->dep_map);
@@ -400,7 +421,7 @@ static inline void srcu_read_unlock_fast(struct srcu_struct *ssp, struct srcu_ct
  * the same context as the maching srcu_down_read_fast().
  */
 static inline void srcu_up_read_fast(struct srcu_struct *ssp, struct srcu_ctr __percpu *scp)
-	__releases(ssp)
+	__releases_shared(ssp)
 {
 	WARN_ON_ONCE(IS_ENABLED(CONFIG_PROVE_RCU) && in_nmi());
 	srcu_check_read_flavor(ssp, SRCU_READ_FLAVOR_FAST);
@@ -415,7 +436,7 @@ static inline void srcu_up_read_fast(struct srcu_struct *ssp, struct srcu_ctr __
  * Exit an SRCU read-side critical section, but in an NMI-safe manner.
  */
 static inline void srcu_read_unlock_nmisafe(struct srcu_struct *ssp, int idx)
-	__releases(ssp)
+	__releases_shared(ssp)
 {
 	WARN_ON_ONCE(idx & ~0x1);
 	srcu_check_read_flavor(ssp, SRCU_READ_FLAVOR_NMI);
@@ -425,7 +446,7 @@ static inline void srcu_read_unlock_nmisafe(struct srcu_struct *ssp, int idx)
 
 /* Used by tracing, cannot be traced and cannot call lockdep. */
 static inline notrace void
-srcu_read_unlock_notrace(struct srcu_struct *ssp, int idx) __releases(ssp)
+srcu_read_unlock_notrace(struct srcu_struct *ssp, int idx) __releases_shared(ssp)
 {
 	srcu_check_read_flavor(ssp, SRCU_READ_FLAVOR_NORMAL);
 	__srcu_read_unlock(ssp, idx);
@@ -440,7 +461,7 @@ srcu_read_unlock_notrace(struct srcu_struct *ssp, int idx) __releases(ssp)
  * the same context as the maching srcu_down_read().
  */
 static inline void srcu_up_read(struct srcu_struct *ssp, int idx)
-	__releases(ssp)
+	__releases_shared(ssp)
 {
 	WARN_ON_ONCE(idx & ~0x1);
 	WARN_ON_ONCE(in_nmi());
@@ -480,6 +501,7 @@ DEFINE_LOCK_GUARD_1(srcu, struct srcu_struct,
 		    _T->idx = srcu_read_lock(_T->lock),
 		    srcu_read_unlock(_T->lock, _T->idx),
 		    int idx)
+DECLARE_LOCK_GUARD_1_ATTRS(srcu, __assumes_cap(_T), /* */)
 
 DEFINE_LOCK_GUARD_1(srcu_fast, struct srcu_struct,
 		    _T->scp = srcu_read_lock_fast(_T->lock),
diff --git a/include/linux/srcutiny.h b/include/linux/srcutiny.h
index 51ce25f07930..c194b3c7c43b 100644
--- a/include/linux/srcutiny.h
+++ b/include/linux/srcutiny.h
@@ -61,6 +61,7 @@ void synchronize_srcu(struct srcu_struct *ssp);
  * index that must be passed to the matching srcu_read_unlock().
  */
 static inline int __srcu_read_lock(struct srcu_struct *ssp)
+	__acquires_shared(ssp)
 {
 	int idx;
 
@@ -68,6 +69,7 @@ static inline int __srcu_read_lock(struct srcu_struct *ssp)
 	idx = ((READ_ONCE(ssp->srcu_idx) + 1) & 0x2) >> 1;
 	WRITE_ONCE(ssp->srcu_lock_nesting[idx], READ_ONCE(ssp->srcu_lock_nesting[idx]) + 1);
 	preempt_enable();
+	__acquire_shared(ssp);
 	return idx;
 }
 
@@ -84,11 +86,13 @@ static inline struct srcu_ctr __percpu *__srcu_ctr_to_ptr(struct srcu_struct *ss
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
diff --git a/include/linux/srcutree.h b/include/linux/srcutree.h
index bf44d8d1e69e..43754472e07a 100644
--- a/include/linux/srcutree.h
+++ b/include/linux/srcutree.h
@@ -207,7 +207,7 @@ struct srcu_struct {
 #define DEFINE_SRCU(name)		__DEFINE_SRCU(name, /* not static */)
 #define DEFINE_STATIC_SRCU(name)	__DEFINE_SRCU(name, static)
 
-int __srcu_read_lock(struct srcu_struct *ssp) __acquires(ssp);
+int __srcu_read_lock(struct srcu_struct *ssp) __acquires_shared(ssp);
 void synchronize_srcu_expedited(struct srcu_struct *ssp);
 void srcu_barrier(struct srcu_struct *ssp);
 void srcu_torture_stats_print(struct srcu_struct *ssp, char *tt, char *tf);
@@ -241,6 +241,7 @@ static inline struct srcu_ctr __percpu *__srcu_ctr_to_ptr(struct srcu_struct *ss
  * implementations of this_cpu_inc().
  */
 static inline struct srcu_ctr __percpu *__srcu_read_lock_fast(struct srcu_struct *ssp)
+	__acquires_shared(ssp)
 {
 	struct srcu_ctr __percpu *scp = READ_ONCE(ssp->srcu_ctrp);
 
@@ -250,6 +251,7 @@ static inline struct srcu_ctr __percpu *__srcu_read_lock_fast(struct srcu_struct
 	else
 		atomic_long_inc(raw_cpu_ptr(&scp->srcu_locks));  /* Z */
 	barrier(); /* Avoid leaking the critical section. */
+	__acquire_shared(ssp);
 	return scp;
 }
 
@@ -269,7 +271,9 @@ static inline struct srcu_ctr __percpu *__srcu_read_lock_fast(struct srcu_struct
  * implementations of this_cpu_inc().
  */
 static inline void __srcu_read_unlock_fast(struct srcu_struct *ssp, struct srcu_ctr __percpu *scp)
+	__releases_shared(ssp)
 {
+	__release_shared(ssp);
 	barrier();  /* Avoid leaking the critical section. */
 	if (!IS_ENABLED(CONFIG_NEED_SRCU_NMI_SAFE))
 		this_cpu_inc(scp->srcu_unlocks.counter);  /* Z */
diff --git a/lib/test_capability-analysis.c b/lib/test_capability-analysis.c
index 31c9bc1e2405..5b17fd94f31e 100644
--- a/lib/test_capability-analysis.c
+++ b/lib/test_capability-analysis.c
@@ -10,6 +10,7 @@
 #include <linux/rcupdate.h>
 #include <linux/seqlock.h>
 #include <linux/spinlock.h>
+#include <linux/srcu.h>
 
 /*
  * Test that helper macros work as expected.
@@ -362,3 +363,26 @@ static void __used test_rcu_assert_variants(void)
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
2.51.0.384.g4c02a37b29-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250918140451.1289454-16-elver%40google.com.
