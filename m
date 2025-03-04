Return-Path: <kasan-dev+bncBC7OBJGL2MHBBD4OTO7AMGQE6RMRPLY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x438.google.com (mail-wr1-x438.google.com [IPv6:2a00:1450:4864:20::438])
	by mail.lfdr.de (Postfix) with ESMTPS id 329B4A4D7FF
	for <lists+kasan-dev@lfdr.de>; Tue,  4 Mar 2025 10:25:37 +0100 (CET)
Received: by mail-wr1-x438.google.com with SMTP id ffacd0b85a97d-390f6aa50c5sf2005842f8f.2
        for <lists+kasan-dev@lfdr.de>; Tue, 04 Mar 2025 01:25:37 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1741080336; cv=pass;
        d=google.com; s=arc-20240605;
        b=akwc2VfTxqB6xX8a7JhaSutqwftrvzXuKqJq4JWRSuV34FxDl0h7Pq20/ytH1tO2tA
         BIupnCcq8k3ivysOgzupH2gsE6EpQC2s+XtguUCWxxD733WJYyRzNZINoyK/Do1fEy6W
         kYyw9WRSjFEGvUJLoXtzspOdhDHfpzCzdnhc8I3qEHNuLWnlMH6QdZRrXkwmA9iiquw4
         UbVagdxskzjNVFmBrxpJf7HjwPSph1a73MaCFcpHPKAnN0PYTMqaYbZzV0BvbSA729mh
         ItL/16en5DKE+m04KWiWa5jVZhvRk0rU8K2L/qXd8PgJbuOdO/5qAAMqhzQZ2U2DXWfw
         +H/A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=YfQV0gNrxDGPL8EotoPa+R06rbkeYtuzS06fpYGSNFE=;
        fh=L8F5D+YSrd+zRVITB028t41ySs6FDXMPcZ6adu6wxjs=;
        b=XF1wriqoQrEVHe4sriQmX5oLHdWjWy6WfjM3tB2Y58+02H/0XO5VH2l0Pqqn6L3t4o
         9DCogsji65ZFVwqanDOsTZ/0mkTobKXFFHudk59kx649PAv/2Fvbh8hVft7YkSfHweJ9
         gHKLhIXpnBXW8a11G20Zo9tdNArTd/yMA5S72NEjWf8r+oUtECn7QcDuTNyhXXBXj0p4
         F0KZZCT4/1qS0ScBfNlCG8YJyqpQLl1tFugv7j6ne0s+u15xNFFA19sc84fvVUqvGZM6
         zJ7R2XDr2f8n0gYaMRfyG48tp/WITIvhyTl9FMJpgtfqXIvbX68sbw/t8Iw9h5uKMH4Y
         mH+g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=O6UCdObb;
       spf=pass (google.com: domain of 3dcfgzwukcfognxgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--elver.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3DcfGZwUKCfognxgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1741080336; x=1741685136; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=YfQV0gNrxDGPL8EotoPa+R06rbkeYtuzS06fpYGSNFE=;
        b=eTcarEKQ0hAvj1QWqj3MvpHwhDhEZUgxvzhtWs0eZs5/q7dr3a07RsWqNnTR9Pf2HS
         /6Hr3LuvqpZXB4q2AGfWkpYRq9VfdriNiu0jl59j94HogZ6l3iDTrdArqFVqeo1WF2fg
         SPREJJ/SQmYuYOiyGgSzvqijAREL8Z/n5ubjVGwzTcYFZhqFfUsZzAaABG0tVVHNyHou
         krrI1Zp0Uhpy3/n1xCc4lek51iYDcRd3U2ZcBty8Fxe9CtbvxqmsIhA2L+LaD6tN37tn
         06CTp668I2oIFggcTtUyKaaTeJQyDAdReVqzcdWOt1IjSK5p+XH3d8iF9HGyeRENp9wI
         5arg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1741080336; x=1741685136;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=YfQV0gNrxDGPL8EotoPa+R06rbkeYtuzS06fpYGSNFE=;
        b=wEnDTPUbcXROHxXl6QthU4DCU18HrojPoa/EMZktC+37fg6LLbNdsaaHh9PU/txOPs
         F5gwTWVFS+xwmVBuk+F107C8k6V6gSppgThK5L+Pd32UXIgu/UdTQeNCoWP+mgBwgJ7D
         4/2IeUibCBZS2L0irYT6F/aqMhYcciylHrabOESWNTaz9g4mC6JTOPR3GqU7UtIlPWp+
         u6LuCEXfxcRAgqQ1J32HMtbkCub34aZgft+4IlSkP326G8lwqa/ZOX35vTIOhD3gBYc7
         /IHdnvAZvUpmcdoNTlkFpStEfSpzTQCfISjxcUD6wm60lhJeGSbCgKZUuyaHcn6DGLQA
         8CyA==
X-Forwarded-Encrypted: i=2; AJvYcCUJvT75p/k8+qwvkFDdrTGo6RmHdlEfofhZw2jJx6Qye4VYlRcFsB4Z8TnxQ/475xwvnGRh2Q==@lfdr.de
X-Gm-Message-State: AOJu0Yy0MrQX5lv3hw8CiUXhj4o0nF10+tVfR8kPH/tiKwdKGTuEZLye
	KNHULkPIehEIzX0LyqUsmglqfShiIya1oOsVTaafmPOrLOMf6ODe
X-Google-Smtp-Source: AGHT+IF/EG+utjGAopCam/a0tkbZUZSmZKHVpsw866HhfyM9ABWSV5KYjssVLMgo1LfSt5iOx7Eaog==
X-Received: by 2002:a5d:64ad:0:b0:390:f699:8c27 with SMTP id ffacd0b85a97d-390f6998ccemr9517749f8f.12.1741080336196;
        Tue, 04 Mar 2025 01:25:36 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVH0yBTA8MIvSuDNKiSMnohetwMx4ZLfdalHSIFu6bl3jQ==
Received: by 2002:a05:6000:1787:b0:38f:2234:229c with SMTP id
 ffacd0b85a97d-390e13071adls1740600f8f.1.-pod-prod-07-eu; Tue, 04 Mar 2025
 01:25:33 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVxptsqADGVGXR4+fM44/tYnf30vaRsUKaoGXEMuw0n+mIaTZBlZbR4RxiJcvTShIDRlUOHjI7WJcc=@googlegroups.com
X-Received: by 2002:a5d:5849:0:b0:391:268:648e with SMTP id ffacd0b85a97d-39102686778mr6654426f8f.46.1741080333583;
        Tue, 04 Mar 2025 01:25:33 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1741080333; cv=none;
        d=google.com; s=arc-20240605;
        b=AXu7cLQwzGBMh3+WBsjOVG+9CWUMSarSWYIZvEIEW9HdJBced1jssMdks9d1/jsRT7
         a3TCW2BLi22LYuKGYvJ+mmL0UmfpdUTbiTuh0+IQ9kiKPqz7IUPhEkIhPg3POG9IHyD6
         6eZTn/hKwuaDIGYn+auSUhuPhTCdFNr3GeWX3jNUgcDaWqtECSHtGhcDCeEZ+HV6aacx
         qLL+5kziNI4XGlmobVzLm6tgwwasXB2tj67HWkmv/ZNikZmAzwZFco3ILqsoL1c+kUXA
         BmVokyK11I7r5quoDlqY+xuj5vmFw3r2MBpCBxhcXx5UCwUz/wjbOvWX1KVTUZwevV7e
         1wDg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=3N8S7JUPE1q89goF9WrUxLudC8JOfTuJ5GayTplf0i0=;
        fh=l0Z3Cz2PcOD4eBOxKzGkflK60WxC/vPi61WprEwU+bA=;
        b=Ht5Jryjw2Zq/2oJVleA063cRWra2wn8wdGj5u/2h77hqZ8meISIodXrj31ndRp7Ro9
         FIynU8iJirSqNlTx4WT6Rnef2Ed8Mx1uMaWY1ACNsbl7WhiIuKnF2lZ0QFRjGrn6ywHf
         Mwqu7QuOzKr1bwlWUBl/IBl93033G5wrN/5mx2sDNf+Kp5e5jTs+HoO8bsBVVr0i4Khh
         C9rFEQhxmBEwiwYKfHq2Dax1EZe972zAv7JeV6sNv5m03q/x0bx5dw7Mu3Bf4JAVPcad
         3cPyH4yzaLyTuHcfyT7vWijb/CzvkJyvoIhz1uDUPgv87S2vStQgMwftWlUrTQ0kP9SA
         wNpQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=O6UCdObb;
       spf=pass (google.com: domain of 3dcfgzwukcfognxgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--elver.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3DcfGZwUKCfognxgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ed1-x54a.google.com (mail-ed1-x54a.google.com. [2a00:1450:4864:20::54a])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-390e482d56csi439441f8f.8.2025.03.04.01.25.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 04 Mar 2025 01:25:33 -0800 (PST)
Received-SPF: pass (google.com: domain of 3dcfgzwukcfognxgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--elver.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) client-ip=2a00:1450:4864:20::54a;
Received: by mail-ed1-x54a.google.com with SMTP id 4fb4d7f45d1cf-5e4b6eba254so6168941a12.3
        for <kasan-dev@googlegroups.com>; Tue, 04 Mar 2025 01:25:33 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCVXlhAXx/K+SAP8h2gYUKd0guM4RyeJeouSMOwkDQ4RzfSi4FYclG+eGI0sVpJ5GKfeD/d80O8m4cc=@googlegroups.com
X-Received: from edc18.prod.google.com ([2002:a05:6402:4612:b0:5e5:29f3:27af])
 (user=elver job=prod-delivery.src-stubby-dispatcher) by 2002:a05:6402:4603:b0:5e5:4807:5441
 with SMTP id 4fb4d7f45d1cf-5e5480755bfmr7319106a12.30.1741080333339; Tue, 04
 Mar 2025 01:25:33 -0800 (PST)
Date: Tue,  4 Mar 2025 10:21:08 +0100
In-Reply-To: <20250304092417.2873893-1-elver@google.com>
Mime-Version: 1.0
References: <20250304092417.2873893-1-elver@google.com>
X-Mailer: git-send-email 2.48.1.711.g2feabab25a-goog
Message-ID: <20250304092417.2873893-10-elver@google.com>
Subject: [PATCH v2 09/34] compiler-capability-analysis: Change __cond_acquires
 to take return value
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
 header.i=@google.com header.s=20230601 header.b=O6UCdObb;       spf=pass
 (google.com: domain of 3dcfgzwukcfognxgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3DcfGZwUKCfognxgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--elver.bounces.google.com;
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

While Sparse is oblivious to the return value of conditional acquire
functions, Clang's capability analysis needs to know the return value
which indicates successful acquisition.

Add the additional argument, and convert existing uses.

Notably, Clang's interpretation of the value merely relates to the use
in a later conditional branch, i.e. 1 ==> capability acquired in branch
taken if condition non-zero, and 0 ==> capability acquired in branch
taken if condition is zero. Given the precise value does not matter,
introduce symbolic variants to use instead of either 0 or 1, which
should be more intuitive.

No functional change intended.

Signed-off-by: Marco Elver <elver@google.com>
---
v2:
* Use symbolic values for __cond_acquires() and __cond_acquires_shared()
  (suggested by Bart).
---
 fs/dlm/lock.c                                |  2 +-
 include/linux/compiler-capability-analysis.h | 31 ++++++++++++++++----
 include/linux/refcount.h                     |  6 ++--
 include/linux/spinlock.h                     |  6 ++--
 include/linux/spinlock_api_smp.h             |  8 ++---
 net/ipv4/tcp_sigpool.c                       |  2 +-
 6 files changed, 38 insertions(+), 17 deletions(-)

diff --git a/fs/dlm/lock.c b/fs/dlm/lock.c
index c8ff88f1cdcf..6799cb0c8f50 100644
--- a/fs/dlm/lock.c
+++ b/fs/dlm/lock.c
@@ -343,7 +343,7 @@ void dlm_hold_rsb(struct dlm_rsb *r)
 /* TODO move this to lib/refcount.c */
 static __must_check bool
 dlm_refcount_dec_and_write_lock_bh(refcount_t *r, rwlock_t *lock)
-__cond_acquires(lock)
+      __cond_acquires(true, lock)
 {
 	if (refcount_dec_not_one(r))
 		return false;
diff --git a/include/linux/compiler-capability-analysis.h b/include/linux/compiler-capability-analysis.h
index c47d9ed18303..832727fea140 100644
--- a/include/linux/compiler-capability-analysis.h
+++ b/include/linux/compiler-capability-analysis.h
@@ -240,7 +240,7 @@
 # define __must_hold(x)		__attribute__((context(x,1,1)))
 # define __must_not_hold(x)
 # define __acquires(x)		__attribute__((context(x,0,1)))
-# define __cond_acquires(x)	__attribute__((context(x,0,-1)))
+# define __cond_acquires(ret, x) __attribute__((context(x,0,-1)))
 # define __releases(x)		__attribute__((context(x,1,0)))
 # define __acquire(x)		__context__(x,1)
 # define __release(x)		__context__(x,-1)
@@ -283,15 +283,32 @@
  */
 # define __acquires(x)		__acquires_cap(x)
 
+/*
+ * Clang's analysis does not care precisely about the value, only that it is
+ * either zero or non-zero. So the __cond_acquires() interface might be
+ * misleading if we say that @ret is the value returned if acquired. Instead,
+ * provide symbolic variants which we translate.
+ */
+#define __cond_acquires_impl_true(x, ...)     __try_acquires##__VA_ARGS__##_cap(1, x)
+#define __cond_acquires_impl_false(x, ...)    __try_acquires##__VA_ARGS__##_cap(0, x)
+#define __cond_acquires_impl_nonzero(x, ...)  __try_acquires##__VA_ARGS__##_cap(1, x)
+#define __cond_acquires_impl_0(x, ...)        __try_acquires##__VA_ARGS__##_cap(0, x)
+#define __cond_acquires_impl_nonnull(x, ...)  __try_acquires##__VA_ARGS__##_cap(1, x)
+#define __cond_acquires_impl_NULL(x, ...)     __try_acquires##__VA_ARGS__##_cap(0, x)
+
 /**
  * __cond_acquires() - function attribute, function conditionally
  *                     acquires a capability exclusively
+ * @ret: abstract value returned by function if capability acquired
  * @x: capability instance pointer
  *
  * Function attribute declaring that the function conditionally acquires the
- * given capability instance @x exclusively, but does not release it.
+ * given capability instance @x exclusively, but does not release it. The
+ * function return value @ret denotes when the capability is acquired.
+ *
+ * @ret may be one of: true, false, nonzero, 0, nonnull, NULL.
  */
-# define __cond_acquires(x)	__try_acquires_cap(1, x)
+# define __cond_acquires(ret, x) __cond_acquires_impl_##ret(x)
 
 /**
  * __releases() - function attribute, function releases a capability exclusively
@@ -358,12 +375,16 @@
 /**
  * __cond_acquires_shared() - function attribute, function conditionally
  *                            acquires a capability shared
+ * @ret: abstract value returned by function if capability acquired
  * @x: capability instance pointer
  *
  * Function attribute declaring that the function conditionally acquires the
- * given capability instance @x with shared access, but does not release it.
+ * given capability instance @x with shared access, but does not release it. The
+ * function return value @ret denotes when the capability is acquired.
+ *
+ * @ret may be one of: true, false, nonzero, 0, nonnull, NULL.
  */
-# define __cond_acquires_shared(x) __try_acquires_shared_cap(1, x)
+# define __cond_acquires_shared(ret, x) __cond_acquires_impl_##ret(x, _shared)
 
 /**
  * __releases_shared() - function attribute, function releases a
diff --git a/include/linux/refcount.h b/include/linux/refcount.h
index 35f039ecb272..88a6e292271d 100644
--- a/include/linux/refcount.h
+++ b/include/linux/refcount.h
@@ -353,9 +353,9 @@ static inline void refcount_dec(refcount_t *r)
 
 extern __must_check bool refcount_dec_if_one(refcount_t *r);
 extern __must_check bool refcount_dec_not_one(refcount_t *r);
-extern __must_check bool refcount_dec_and_mutex_lock(refcount_t *r, struct mutex *lock) __cond_acquires(lock);
-extern __must_check bool refcount_dec_and_lock(refcount_t *r, spinlock_t *lock) __cond_acquires(lock);
+extern __must_check bool refcount_dec_and_mutex_lock(refcount_t *r, struct mutex *lock) __cond_acquires(true, lock);
+extern __must_check bool refcount_dec_and_lock(refcount_t *r, spinlock_t *lock) __cond_acquires(true, lock);
 extern __must_check bool refcount_dec_and_lock_irqsave(refcount_t *r,
 						       spinlock_t *lock,
-						       unsigned long *flags) __cond_acquires(lock);
+						       unsigned long *flags) __cond_acquires(true, lock);
 #endif /* _LINUX_REFCOUNT_H */
diff --git a/include/linux/spinlock.h b/include/linux/spinlock.h
index 09124713b115..12369fa9e3bb 100644
--- a/include/linux/spinlock.h
+++ b/include/linux/spinlock.h
@@ -362,7 +362,7 @@ static __always_inline void spin_lock_bh(spinlock_t *lock)
 }
 
 static __always_inline int spin_trylock(spinlock_t *lock)
-	__cond_acquires(lock) __no_capability_analysis
+	__cond_acquires(true, lock) __no_capability_analysis
 {
 	return raw_spin_trylock(&lock->rlock);
 }
@@ -420,13 +420,13 @@ static __always_inline void spin_unlock_irqrestore(spinlock_t *lock, unsigned lo
 }
 
 static __always_inline int spin_trylock_bh(spinlock_t *lock)
-	__cond_acquires(lock) __no_capability_analysis
+	__cond_acquires(true, lock) __no_capability_analysis
 {
 	return raw_spin_trylock_bh(&lock->rlock);
 }
 
 static __always_inline int spin_trylock_irq(spinlock_t *lock)
-	__cond_acquires(lock) __no_capability_analysis
+	__cond_acquires(true, lock) __no_capability_analysis
 {
 	return raw_spin_trylock_irq(&lock->rlock);
 }
diff --git a/include/linux/spinlock_api_smp.h b/include/linux/spinlock_api_smp.h
index fab02d8bf0c9..a77b76003ebb 100644
--- a/include/linux/spinlock_api_smp.h
+++ b/include/linux/spinlock_api_smp.h
@@ -34,8 +34,8 @@ unsigned long __lockfunc _raw_spin_lock_irqsave(raw_spinlock_t *lock)
 unsigned long __lockfunc
 _raw_spin_lock_irqsave_nested(raw_spinlock_t *lock, int subclass)
 								__acquires(lock);
-int __lockfunc _raw_spin_trylock(raw_spinlock_t *lock)		__cond_acquires(lock);
-int __lockfunc _raw_spin_trylock_bh(raw_spinlock_t *lock)	__cond_acquires(lock);
+int __lockfunc _raw_spin_trylock(raw_spinlock_t *lock)		__cond_acquires(true, lock);
+int __lockfunc _raw_spin_trylock_bh(raw_spinlock_t *lock)	__cond_acquires(true, lock);
 void __lockfunc _raw_spin_unlock(raw_spinlock_t *lock)		__releases(lock);
 void __lockfunc _raw_spin_unlock_bh(raw_spinlock_t *lock)	__releases(lock);
 void __lockfunc _raw_spin_unlock_irq(raw_spinlock_t *lock)	__releases(lock);
@@ -84,7 +84,7 @@ _raw_spin_unlock_irqrestore(raw_spinlock_t *lock, unsigned long flags)
 #endif
 
 static inline int __raw_spin_trylock(raw_spinlock_t *lock)
-	__cond_acquires(lock)
+	__cond_acquires(true, lock)
 {
 	preempt_disable();
 	if (do_raw_spin_trylock(lock)) {
@@ -177,7 +177,7 @@ static inline void __raw_spin_unlock_bh(raw_spinlock_t *lock)
 }
 
 static inline int __raw_spin_trylock_bh(raw_spinlock_t *lock)
-	__cond_acquires(lock)
+	__cond_acquires(true, lock)
 {
 	__local_bh_disable_ip(_RET_IP_, SOFTIRQ_LOCK_OFFSET);
 	if (do_raw_spin_trylock(lock)) {
diff --git a/net/ipv4/tcp_sigpool.c b/net/ipv4/tcp_sigpool.c
index d8a4f192873a..10b2e5970c40 100644
--- a/net/ipv4/tcp_sigpool.c
+++ b/net/ipv4/tcp_sigpool.c
@@ -257,7 +257,7 @@ void tcp_sigpool_get(unsigned int id)
 }
 EXPORT_SYMBOL_GPL(tcp_sigpool_get);
 
-int tcp_sigpool_start(unsigned int id, struct tcp_sigpool *c) __cond_acquires(RCU_BH)
+int tcp_sigpool_start(unsigned int id, struct tcp_sigpool *c) __cond_acquires(0, RCU_BH)
 {
 	struct crypto_ahash *hash;
 
-- 
2.48.1.711.g2feabab25a-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250304092417.2873893-10-elver%40google.com.
