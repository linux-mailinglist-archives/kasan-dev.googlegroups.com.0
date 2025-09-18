Return-Path: <kasan-dev+bncBC7OBJGL2MHBBQVDWDDAMGQEECRZ6CQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x438.google.com (mail-wr1-x438.google.com [IPv6:2a00:1450:4864:20::438])
	by mail.lfdr.de (Postfix) with ESMTPS id AC5C9B84F8A
	for <lists+kasan-dev@lfdr.de>; Thu, 18 Sep 2025 16:05:55 +0200 (CEST)
Received: by mail-wr1-x438.google.com with SMTP id ffacd0b85a97d-3e997eb7232sf453652f8f.3
        for <lists+kasan-dev@lfdr.de>; Thu, 18 Sep 2025 07:05:55 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758204355; cv=pass;
        d=google.com; s=arc-20240605;
        b=K2DYp+Gdh09WYhLVva/9iTtqxgWwFS0cAYzjmf1DXeoOWkHTRirSonhB+e8qsYG51K
         aammSu9h+6PkQwsv33yowIiGO7R/wzMGH1YWuFHGwsLOr8l7azlp2T7a8mBbAoy3lyN2
         qJLrfkbSOvICTSMnh0wFZbxNuSeBqELxEPibdYLPuOrG24ciiVrymZK7NyVcFVtytnNf
         9aWh+/xm+33L/OiUQjC2vbEFGKnTX1CKtqMfQ7iKU0rXvFqV0sKF+CygTGcnvGPINOm4
         WO9NO+4CX+PZkA7GrSHz0n05auXlCS9oApMkuyH8OqL60FQuzolxiTmsadUzvQROvwmh
         2QbQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=PYWaklkmwrp9SUOIAZTKSYmN44wrDpIBGE9rNWh+C/Q=;
        fh=695i4zPjMMzD0mJqYjw649GwaRH8FG2zYPrRPFGCVnA=;
        b=Tsy9BbGLhrkzm7809HNop8H7j6z5gznaWnfWvNqGphglyOBHPHRHrgceQSdxUw3Jh3
         Y+9maiRaKAp/SSBRt4ilQKoBGsxLIMDJOw2ewtQ/y9SfasD7GkppM7Sp5auKKppU0lOP
         0PlWk7M/93edgt/4dkGXC40krKoQWlytHSLLCVeX3P1QXxsW6iyvitshUWMHFWt30N8m
         8eKCN2w5ZQu2Y1us99bU8LWzBryuCDK391DW7ed22DqcI8iaoJBaB72Vhw6S7MEFaz3k
         y8/yU43USDug97xXf3FnkxUFBPh91CrNn8ngdMlNfpLSUyIwtlHj7ly2/NjmZZ58K4wk
         6g3w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=sN3CL7n8;
       spf=pass (google.com: domain of 3vxhmaaukcwacjtcpemmejc.amki8q8l-bctemmejcepmsnq.amk@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3vxHMaAUKCWACJTCPEMMEJC.AMKI8Q8L-BCTEMMEJCEPMSNQ.AMK@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758204355; x=1758809155; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=PYWaklkmwrp9SUOIAZTKSYmN44wrDpIBGE9rNWh+C/Q=;
        b=PC8K3GFOa4jZ/S1IzbITQ3GsMkUcpJa9+NhTIxZ/FuMjBGwSmNaVZmxiNv446cGBmI
         gyu44K0PHkOLeFwp45FDx81dm0WfErbDAUojaTuJYWCM+tUyWki2JPkQ9g7Ykm1prcUR
         EmmxZewaW+EzEIhVUgaHoSGps5f+MBdI8RJElUf0WfOYIM3b33iEJ/4gENPrKVDGeLry
         2LwiXLX+GKHNQw7LaOX0249Ld6lKOoRXlcJuMrLrcBQ0nA4DRdZ2tt3Wt3aTmsXHK7Y/
         q8T0sMqWgYIK/urgxulzZfLe3GO3XS9SdHiRKgD+vFLu2vD5AaiwOX4cXHMG2ZqzTtH9
         fiSA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758204355; x=1758809155;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=PYWaklkmwrp9SUOIAZTKSYmN44wrDpIBGE9rNWh+C/Q=;
        b=HxDGVtdiNo/KWaahiIH/ancK9no0S0GyCsjw/LY1uht5jah7E3Dao85ReWtZx09nS+
         FbTfMcPcBkQ/htifUdjp6xnbgPWC1iOoksZcTTe0ZkgFdHV/GW0xQfQQPmSSRlP5cokJ
         wMYwbxOyQr7lk/y1uYN4VdKKrecnYz1IyLhF+5s97xPxsOgNQCbF5HId2HlqIfcGrIgS
         QgCOk5/+6WuTgUOZuvSVvaG+5RcL84p/2jDd5KXmxgdIrGqs619T9uLBUilCZ1Hx7yCC
         lIScnpAvrA8MZtZSk9ToiAsU95E7dgUIykJu0cSXMzIz8MEtSeT1s6T6/qwNHBJziI3I
         QZQw==
X-Forwarded-Encrypted: i=2; AJvYcCWyO3GvG8A/4k3s0naFbscOk7AONnBF5ciZ4vZRqiwHhhUherFMTK8+qJeOdf3Fn05KsENFjQ==@lfdr.de
X-Gm-Message-State: AOJu0YwtvH8h4pg0qbTssGmk9zUFT+egldvntV8YkxODsrVt8FFugdHy
	lWZxbEqpn2ztRhblB3kM7dyx1EwLx1QDcM/sGOV4y975MgLRJEF34ZoD
X-Google-Smtp-Source: AGHT+IFDYD7HTA3l2+9on9soD+sqztsgR8dNOlzR40sar5Kt+EbEVcRL47LllrXcMgYeSv3b0uK5dg==
X-Received: by 2002:a5d:5f91:0:b0:3ea:6680:8fae with SMTP id ffacd0b85a97d-3ecdf9b8993mr5241833f8f.2.1758204355001;
        Thu, 18 Sep 2025 07:05:55 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd5ybxD9QJGYCvGEvHcYcd1D4BOUZVFIbwMU5IJ46bULyA==
Received: by 2002:a5d:5d0f:0:b0:3da:cb77:e987 with SMTP id ffacd0b85a97d-3ee10310db2ls389206f8f.0.-pod-prod-06-eu;
 Thu, 18 Sep 2025 07:05:52 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUsi9A4bDlp5G/Hwf+7bYY7KHvRuJxcS0UVDRbCxpZmE/E41qWNOnkMh5LSIZdfC2IEPNuHQumkNik=@googlegroups.com
X-Received: by 2002:a05:6000:178e:b0:3e4:957d:d00 with SMTP id ffacd0b85a97d-3ecdfa5b498mr5586894f8f.58.1758204352176;
        Thu, 18 Sep 2025 07:05:52 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1758204352; cv=none;
        d=google.com; s=arc-20240605;
        b=PlZCc429y+xv3jpqNqY6aTkdLivtrGc1P13H0t4iS1CfpdEFMqRRrp0TfCGjTuSTNT
         AJlA6631WX9SZFHuVWxCADXyJJAkrd3XimmzxAnf/8LgKMPtxJKBYS0x5dMHhy0bYNar
         9UXfhYa7QeiKTP/NrteASlTBXrkCYPX1+Uf9AhosFpNw+fVzkEwBY5GJmP3dXph2RwVk
         x0++e6U8JO9SGB6ZAxJ+EcYaB6+VNYPoNxoeJ4IIlLxWsCJLVPALhEDRhKmGduGI3tRI
         TNP6M6slPTU5SVZvxwAR92gnhe5Ctm4LUYHWtcGYs4gaRVkPZ9J9BIwq8zQNyF/gNDWF
         8usw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=nuqSkrvcyBiCelh3qy9Lvs4g4xmbG9dFvEFi0HZqJaY=;
        fh=xRtSByK3OaxT9s6wPE0KfVkw4Q0jsnkrKWJ6cHZ0F5k=;
        b=C4oNNajMn4FZVn31nF7UblSPMpVYaXSqvf9yiiYOeTGIul53FF9U7KWQbJpWJez95y
         Y9r+8J5l3QnboDZJ9pHaiHrQlrbn8igD1Bgu+7TXbk7iw0HGSyg90PX6moaPhqmSqhfA
         04eQpBqFtfAy4TtlITJieRzOZ7xmqYLzs9aY19GFZkJ4byKkiI0fu8pEmxbSqRm8SOwF
         Y7dzwfu9/hoDI1hytyYUOrOjL9O9diTV+MneLcXgmGtoNhlG94ThFW/rl11QQHS/4CmG
         Y5vq13VUFK+axuzAqPtNgQ6Uzyxrzx2V0fUGRMluSBgKnVkn5CFCXb5V8mHJa8R3IAjr
         IcmQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=sN3CL7n8;
       spf=pass (google.com: domain of 3vxhmaaukcwacjtcpemmejc.amki8q8l-bctemmejcepmsnq.amk@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3vxHMaAUKCWACJTCPEMMEJC.AMKI8Q8L-BCTEMMEJCEPMSNQ.AMK@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x34a.google.com (mail-wm1-x34a.google.com. [2a00:1450:4864:20::34a])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-3ee0fbb336fsi61337f8f.5.2025.09.18.07.05.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 18 Sep 2025 07:05:52 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3vxhmaaukcwacjtcpemmejc.amki8q8l-bctemmejcepmsnq.amk@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) client-ip=2a00:1450:4864:20::34a;
Received: by mail-wm1-x34a.google.com with SMTP id 5b1f17b1804b1-4612d068c47so6287035e9.3
        for <kasan-dev@googlegroups.com>; Thu, 18 Sep 2025 07:05:52 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWC5973T9zsl8GS646or4r9jK05e7a3h92BlGVxqvF2XIbHzvg+YijUuY4sirOpS/tdhZoOZTDj0bI=@googlegroups.com
X-Received: from wmqb22.prod.google.com ([2002:a05:600c:4e16:b0:45f:28be:a3aa])
 (user=elver job=prod-delivery.src-stubby-dispatcher) by 2002:a05:600c:154a:b0:45d:f897:fbe1
 with SMTP id 5b1f17b1804b1-46208321e5fmr56432605e9.32.1758204351462; Thu, 18
 Sep 2025 07:05:51 -0700 (PDT)
Date: Thu, 18 Sep 2025 15:59:20 +0200
In-Reply-To: <20250918140451.1289454-1-elver@google.com>
Mime-Version: 1.0
References: <20250918140451.1289454-1-elver@google.com>
X-Mailer: git-send-email 2.51.0.384.g4c02a37b29-goog
Message-ID: <20250918140451.1289454-10-elver@google.com>
Subject: [PATCH v3 09/35] compiler-capability-analysis: Change __cond_acquires
 to take return value
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
 header.i=@google.com header.s=20230601 header.b=sN3CL7n8;       spf=pass
 (google.com: domain of 3vxhmaaukcwacjtcpemmejc.amki8q8l-bctemmejcepmsnq.amk@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3vxHMaAUKCWACJTCPEMMEJC.AMKI8Q8L-BCTEMMEJCEPMSNQ.AMK@flex--elver.bounces.google.com;
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
index 6dd3a524cd35..006eb284c8a7 100644
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
index 6f3f185478bc..ccd312dbbf06 100644
--- a/include/linux/compiler-capability-analysis.h
+++ b/include/linux/compiler-capability-analysis.h
@@ -257,7 +257,7 @@ static inline void _capability_unsafe_alias(void **p) { }
 # define __must_hold(x)		__attribute__((context(x,1,1)))
 # define __must_not_hold(x)
 # define __acquires(x)		__attribute__((context(x,0,1)))
-# define __cond_acquires(x)	__attribute__((context(x,0,-1)))
+# define __cond_acquires(ret, x) __attribute__((context(x,0,-1)))
 # define __releases(x)		__attribute__((context(x,1,0)))
 # define __acquire(x)		__context__(x,1)
 # define __release(x)		__context__(x,-1)
@@ -300,15 +300,32 @@ static inline void _capability_unsafe_alias(void **p) { }
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
@@ -375,12 +392,16 @@ static inline void _capability_unsafe_alias(void **p) { }
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
index 80dc023ac2bf..3da377ffb0c2 100644
--- a/include/linux/refcount.h
+++ b/include/linux/refcount.h
@@ -478,9 +478,9 @@ static inline void refcount_dec(refcount_t *r)
 
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
index 7679f39071e9..22295a126c3a 100644
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
@@ -422,13 +422,13 @@ static __always_inline void spin_unlock_irqrestore(spinlock_t *lock, unsigned lo
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
2.51.0.384.g4c02a37b29-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250918140451.1289454-10-elver%40google.com.
