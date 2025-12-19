Return-Path: <kasan-dev+bncBC7OBJGL2MHBBO7GSXFAMGQEE3P5Y5A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13c.google.com (mail-lf1-x13c.google.com [IPv6:2a00:1450:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id E76B8CD0950
	for <lists+kasan-dev@lfdr.de>; Fri, 19 Dec 2025 16:46:04 +0100 (CET)
Received: by mail-lf1-x13c.google.com with SMTP id 2adb3069b0e04-598e12eab38sf2328799e87.1
        for <lists+kasan-dev@lfdr.de>; Fri, 19 Dec 2025 07:46:04 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1766159164; cv=pass;
        d=google.com; s=arc-20240605;
        b=Sf0Ayo7xyqwjRgnNY6HysAWoDi+DJG8SdSdfZ39GJH1wYqwurz6SAnan/VrLsugBqb
         OpciSIm3Jxfdk0PkAx0zT2LHavrbaNt+GmqkCLrK3iGj9qmdd+liriuVAYruOz314kc9
         sQ5iVoAlMvZB75TeLwN3Bf/DD/+ycCjy5RK/WvJCjzISZ5sdlQjcdCVOKP9+NPhiIxlJ
         swGKQ6GgnppnicRhBzNdfpIefGpReg4/cMq1sBC5RMBmaNal2LBvlAk7CHCpdB4nmIrU
         Fc0e1YCzbSczsuUqNrgrkBOl6Rd2u9BqtH4QJMgIx88CW+7fLawV8r64arjOv1hBYBee
         9WdA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=Ayhyf1JKbulPuBNilkcpG59MH/frf8fMCnjVZhasluA=;
        fh=4fVQdFfrnHOLdH8uJddGOP0/JWCTeZOOOdZCklAoX4I=;
        b=VPO1NvEO0iARickO+9sxQjSpssJ25oo+LGIfLCE2uFgIMt6qvZxhQN9XbpKbm3zxtS
         InvaWKbOwDP+FHxK5RGKCIwZxkqm2gEcQb/5U8tn+t6u9ppCCevRKC1Rcb79UK36Rg0n
         sLANCDN2ZKuL7t/DnjowXynuUUvUX3Vb+bKDWhTz8OG9xhmMOmwguq16DeHvhbhS+j21
         FXvmZ+uyyPVJ+djXcTthGzIsm9y8kvQGYjOrCVcYpeqRgoeyGcg0vPQb7nm6OGAVNmlJ
         /u2Q9aNAXZko6pnzYLBCovCtcMDI/LHv4A/KFhXAxpNXfjZPB922eUdLgSq0U2GJMiJC
         OSgw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=C5Qlgvzi;
       spf=pass (google.com: domain of 3n3nfaqukcyqmt3mzowwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3N3NFaQUKCYQmt3mzowwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1766159164; x=1766763964; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=Ayhyf1JKbulPuBNilkcpG59MH/frf8fMCnjVZhasluA=;
        b=Yvdh2Axy3r2umysiRvwX+e5l/I45obh06YIW24A0imQZ096d1sPjVNQDLfGQ+Tiopt
         R0NpwdzkaDKTf6A2TWSUFzdYkgP5wxIdvw1B6W6AzcQK20fbgppL3hfz8tfWxST4/wyv
         lnyKEU6EFQFyrPubFVjpOUTibLy3tZYVeCWXSQXZtaXvF9xzepBNPPou39lqgDUebfQB
         1ahHtMfnm8bl8ZUIUudZHG2X1pGhKlwKK+pNZCMRvxWXo1Lv4oQ4x+Km/ZSIuKkF569g
         WtaJ7aRBUXnsqNZd822y9byHfgX7IIoZtcYnt1GXwki9OOnt/9G9TJAcINTT5EiovB/c
         ickA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1766159164; x=1766763964;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Ayhyf1JKbulPuBNilkcpG59MH/frf8fMCnjVZhasluA=;
        b=q2nqKo7VptZQERvCcIY11KXLFFoXfIE00PI0Rd4XTUISkIWhuyDhGNfmQclM/UDSVn
         Hd/6AnTNa4dSweThSq5zYh8cMmo7RUVrFBnPTMM3jK9GQJv60e3v9crAdV/i3znQwcyr
         2ch9XoaNTnKs+QXqX3JzYvH/vgTD/2S2rP8zBnHKOzJcLrzuwcxBIZLn5qF3UBJfq5rg
         YGNraHKVaBRrLnQwMJr528+1eydrFjALZjD5KTtDdFWgB4ju+Rm4AAANjxlRMrPxH5B6
         GPkdhcrM394eoXN7SjVXB6sT8SKeam4KoWR0krqk1mGISkCs8RC0hhNnaWJBqcZxv/Ac
         mFZg==
X-Forwarded-Encrypted: i=2; AJvYcCV6RzNawVzgMUGojLHAoJWjLelCpS/kc6w5INtil6V6wcjdLH9wPYYp1OlM4kkGvJhfTVfSxQ==@lfdr.de
X-Gm-Message-State: AOJu0YzNUsmPSwrzLIdOxy07OtJJ2iP9twZ7p/MnfKRvh2F6CTM/wPCR
	kEeti3TSvS7emw/48Ya26T1mni97wawWm+62zeUo5k5hkSmOSm1MOZv7
X-Google-Smtp-Source: AGHT+IGGCTboiV9u1p/jprwNSJCkQBhdn3iOZkEmbtopODE/aP7KBlnjgD2IqM6fYvSxs79quU/mqQ==
X-Received: by 2002:a05:6512:3ca8:b0:598:ef5a:8d66 with SMTP id 2adb3069b0e04-59a17d1253dmr1312679e87.19.1766159163861;
        Fri, 19 Dec 2025 07:46:03 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWbVEMQXTRZlvgZwnKdag337/hroV+wya8LJDcsBVBCPEA=="
Received: by 2002:a05:6512:1188:b0:597:d79e:e081 with SMTP id
 2adb3069b0e04-598fa3fb651ls942646e87.1.-pod-prod-03-eu; Fri, 19 Dec 2025
 07:46:01 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUZPXGXNp3+p62qk8d+f8FJMsFFhltTc1dEjRpAyuAvCbVzanQ474ywtYDddvdyBuh5uINcgu/Z8Ws=@googlegroups.com
X-Received: by 2002:a05:6512:32c7:b0:598:8f91:6d0f with SMTP id 2adb3069b0e04-59a17d58f83mr1325856e87.50.1766159160800;
        Fri, 19 Dec 2025 07:46:00 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1766159160; cv=none;
        d=google.com; s=arc-20240605;
        b=DhT5hIb+ibE93YWSj1gNpDtBEZ3lIX2YLGv64LO/BBrrZ5aJPVqGo3yNOfmG7NIe4s
         U1XhjeB15noqCFP/PUjog3mNnUfLlNZu9kMgtOvJ00LBFDNaWnCKtgTOsoMofz3tWX1v
         ImoJIFqGohL14/RWNqsm2NftEZeoq0sBf21gHHolDP/cxQ3zTJ5e/wGUaoLNB/NEE+lw
         3j4cZAL6pFLQezXLQA6YnnFkMXBqsfpKcWYm4Inp9kmwKqjObixWIdBfubdCCBbnGaA5
         6KlUwMFfHm/2VIEAZhG2K4XFKdE0NS05sJmoPq9dlF0BxQ3cmm/lzuXmonutPngQdjgZ
         0cmg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=lGbYnpIDd95/4deu1O5Gyvn5GxdfmH9SCDxje2/Aqi4=;
        fh=hyUSDs67r7R9jLjcENikpo/AW4uwhe2SmxxIArp9Szw=;
        b=dZtVN6KN2N+guLB3QIyFM1SNau6qA6p41oqdtsKmIc/fQHZoLG3SGn5GzZw/lGYYb5
         +BxkVeaihXg+JuFf6bOSdGzhEOE1B2skTyyKgaXBrF4A3tfI6yrhZpzhDolq8QDXMrVX
         JqbLCdjkUMvEzMs/LaZdVp97Okf47x4wD2ZqvAPnTjgpz9MIGfTLmVfayhCltJe4Y1jE
         bx9Du2PxpRZqzJIw9wf95im6gXxw/4Sem76gc19ZJWKRKVcS9IoSRtw9h5gQ/9s5XhoL
         VU8KG8xGGuXa9RbD+Zo+ZutWl29ytUJvYHoO2BgmLOBwgsenoh9G7PBw0pOZjruxDMoa
         0XHg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=C5Qlgvzi;
       spf=pass (google.com: domain of 3n3nfaqukcyqmt3mzowwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3N3NFaQUKCYQmt3mzowwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x349.google.com (mail-wm1-x349.google.com. [2a00:1450:4864:20::349])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-59a1860cf52si63591e87.3.2025.12.19.07.46.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 19 Dec 2025 07:46:00 -0800 (PST)
Received-SPF: pass (google.com: domain of 3n3nfaqukcyqmt3mzowwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) client-ip=2a00:1450:4864:20::349;
Received: by mail-wm1-x349.google.com with SMTP id 5b1f17b1804b1-4792bd2c290so17582935e9.1
        for <kasan-dev@googlegroups.com>; Fri, 19 Dec 2025 07:46:00 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCW5gdoyPErrUFKDAyw2QA6pHXFuPERqbHbZpxNphIMDweFIN2zCNZ4lP4vNKQOMf4e/1Rd0f+tHG9c=@googlegroups.com
X-Received: from wmma6.prod.google.com ([2002:a05:600c:2246:b0:477:40c1:3e61])
 (user=elver job=prod-delivery.src-stubby-dispatcher) by 2002:a05:600c:8b12:b0:46e:1fb7:a1b3
 with SMTP id 5b1f17b1804b1-47d19595fcfmr36884125e9.23.1766159159900; Fri, 19
 Dec 2025 07:45:59 -0800 (PST)
Date: Fri, 19 Dec 2025 16:39:58 +0100
In-Reply-To: <20251219154418.3592607-1-elver@google.com>
Mime-Version: 1.0
References: <20251219154418.3592607-1-elver@google.com>
X-Mailer: git-send-email 2.52.0.322.g1dd061c0dc-goog
Message-ID: <20251219154418.3592607-10-elver@google.com>
Subject: [PATCH v5 09/36] compiler-context-analysis: Change __cond_acquires to
 take return value
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
 header.i=@google.com header.s=20230601 header.b=C5Qlgvzi;       spf=pass
 (google.com: domain of 3n3nfaqukcyqmt3mzowwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3N3NFaQUKCYQmt3mzowwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--elver.bounces.google.com;
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
functions, Clang's context analysis needs to know the return value
which indicates successful acquisition.

Add the additional argument, and convert existing uses.

Notably, Clang's interpretation of the value merely relates to the use
in a later conditional branch, i.e. 1 ==> context lock acquired in
branch taken if condition non-zero, and 0 ==> context lock acquired in
branch taken if condition is zero. Given the precise value does not
matter, introduce symbolic variants to use instead of either 0 or 1,
which should be more intuitive.

No functional change intended.

Signed-off-by: Marco Elver <elver@google.com>
---
v5:
* Rename "context guard" -> "context lock".

v4:
* Rename capability -> context analysis.

v2:
* Use symbolic values for __cond_acquires() and __cond_acquires_shared()
  (suggested by Bart).
---
 fs/dlm/lock.c                             |  2 +-
 include/linux/compiler-context-analysis.h | 31 +++++++++++++++++++----
 include/linux/refcount.h                  |  6 ++---
 include/linux/spinlock.h                  |  6 ++---
 include/linux/spinlock_api_smp.h          |  8 +++---
 net/ipv4/tcp_sigpool.c                    |  2 +-
 6 files changed, 38 insertions(+), 17 deletions(-)

diff --git a/fs/dlm/lock.c b/fs/dlm/lock.c
index be938fdf17d9..0ce04be0d3de 100644
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
diff --git a/include/linux/compiler-context-analysis.h b/include/linux/compiler-context-analysis.h
index afff910d8930..9ad800e27692 100644
--- a/include/linux/compiler-context-analysis.h
+++ b/include/linux/compiler-context-analysis.h
@@ -271,7 +271,7 @@ static inline void _context_unsafe_alias(void **p) { }
 # define __must_hold(x)		__attribute__((context(x,1,1)))
 # define __must_not_hold(x)
 # define __acquires(x)		__attribute__((context(x,0,1)))
-# define __cond_acquires(x)	__attribute__((context(x,0,-1)))
+# define __cond_acquires(ret, x) __attribute__((context(x,0,-1)))
 # define __releases(x)		__attribute__((context(x,1,0)))
 # define __acquire(x)		__context__(x,1)
 # define __release(x)		__context__(x,-1)
@@ -314,15 +314,32 @@ static inline void _context_unsafe_alias(void **p) { }
  */
 # define __acquires(x)		__acquires_ctx_lock(x)
 
+/*
+ * Clang's analysis does not care precisely about the value, only that it is
+ * either zero or non-zero. So the __cond_acquires() interface might be
+ * misleading if we say that @ret is the value returned if acquired. Instead,
+ * provide symbolic variants which we translate.
+ */
+#define __cond_acquires_impl_true(x, ...)     __try_acquires##__VA_ARGS__##_ctx_lock(1, x)
+#define __cond_acquires_impl_false(x, ...)    __try_acquires##__VA_ARGS__##_ctx_lock(0, x)
+#define __cond_acquires_impl_nonzero(x, ...)  __try_acquires##__VA_ARGS__##_ctx_lock(1, x)
+#define __cond_acquires_impl_0(x, ...)        __try_acquires##__VA_ARGS__##_ctx_lock(0, x)
+#define __cond_acquires_impl_nonnull(x, ...)  __try_acquires##__VA_ARGS__##_ctx_lock(1, x)
+#define __cond_acquires_impl_NULL(x, ...)     __try_acquires##__VA_ARGS__##_ctx_lock(0, x)
+
 /**
  * __cond_acquires() - function attribute, function conditionally
  *                     acquires a context lock exclusively
+ * @ret: abstract value returned by function if context lock acquired
  * @x: context lock instance pointer
  *
  * Function attribute declaring that the function conditionally acquires the
- * given context lock instance @x exclusively, but does not release it.
+ * given context lock instance @x exclusively, but does not release it. The
+ * function return value @ret denotes when the context lock is acquired.
+ *
+ * @ret may be one of: true, false, nonzero, 0, nonnull, NULL.
  */
-# define __cond_acquires(x)	__try_acquires_ctx_lock(1, x)
+# define __cond_acquires(ret, x) __cond_acquires_impl_##ret(x)
 
 /**
  * __releases() - function attribute, function releases a context lock exclusively
@@ -389,12 +406,16 @@ static inline void _context_unsafe_alias(void **p) { }
 /**
  * __cond_acquires_shared() - function attribute, function conditionally
  *                            acquires a context lock shared
+ * @ret: abstract value returned by function if context lock acquired
  * @x: context lock instance pointer
  *
  * Function attribute declaring that the function conditionally acquires the
- * given context lock instance @x with shared access, but does not release it.
+ * given context lock instance @x with shared access, but does not release it. The
+ * function return value @ret denotes when the context lock is acquired.
+ *
+ * @ret may be one of: true, false, nonzero, 0, nonnull, NULL.
  */
-# define __cond_acquires_shared(x) __try_acquires_shared_ctx_lock(1, x)
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
index 72aabdd4fa3f..7e560c7a7b23 100644
--- a/include/linux/spinlock.h
+++ b/include/linux/spinlock.h
@@ -362,7 +362,7 @@ static __always_inline void spin_lock_bh(spinlock_t *lock)
 }
 
 static __always_inline int spin_trylock(spinlock_t *lock)
-	__cond_acquires(lock) __no_context_analysis
+	__cond_acquires(true, lock) __no_context_analysis
 {
 	return raw_spin_trylock(&lock->rlock);
 }
@@ -422,13 +422,13 @@ static __always_inline void spin_unlock_irqrestore(spinlock_t *lock, unsigned lo
 }
 
 static __always_inline int spin_trylock_bh(spinlock_t *lock)
-	__cond_acquires(lock) __no_context_analysis
+	__cond_acquires(true, lock) __no_context_analysis
 {
 	return raw_spin_trylock_bh(&lock->rlock);
 }
 
 static __always_inline int spin_trylock_irq(spinlock_t *lock)
-	__cond_acquires(lock) __no_context_analysis
+	__cond_acquires(true, lock) __no_context_analysis
 {
 	return raw_spin_trylock_irq(&lock->rlock);
 }
diff --git a/include/linux/spinlock_api_smp.h b/include/linux/spinlock_api_smp.h
index d19327e04df9..7e7d7d373213 100644
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
2.52.0.322.g1dd061c0dc-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251219154418.3592607-10-elver%40google.com.
