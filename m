Return-Path: <kasan-dev+bncBC7OBJGL2MHBB5HGSXFAMGQE25F73KY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x237.google.com (mail-lj1-x237.google.com [IPv6:2a00:1450:4864:20::237])
	by mail.lfdr.de (Postfix) with ESMTPS id C3D95CD099B
	for <lists+kasan-dev@lfdr.de>; Fri, 19 Dec 2025 16:47:01 +0100 (CET)
Received: by mail-lj1-x237.google.com with SMTP id 38308e7fff4ca-37fe2aa9387sf226331fa.1
        for <lists+kasan-dev@lfdr.de>; Fri, 19 Dec 2025 07:47:01 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1766159221; cv=pass;
        d=google.com; s=arc-20240605;
        b=lB1TLK3Y3diciwPkZ/7ulYqkVMibp2tAGn3tKTyHb85GfxZfZZudzMGEUNcqPxlhx5
         SXVLJ1T74uyZQ0TGN7tEnUtcNNZjCBCmbK1l1MsnlicdGcxGfetAsg2YvbqK7WOIi2X3
         cdFP2RdGXGL0oyHRpttSaFJ6SIwAFHBgOVpi3I/Gv1sZXfBnPRy6d1YmCHVRkaIdhKt9
         Gc1nRGFAuY+Icvz2yQv2YlSxmn1WdKy0vftRmzqmtHwQw5OitAji23R0gsg9G5/yaCL3
         WW8wDTz77T/wB1R8o6PCOhzZNGamiTft/Qm1dF+16iP6IgPr8d9N+00yupz6k/iA0rOU
         bgKQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=ruViPzlNQHlqSjnM2DVAzGeO5aUj7gRIMHpeRQuCjfM=;
        fh=2z+DRCCFynAUr72Kv/8m57Pw8XbZOg368Y/XMrn4R44=;
        b=b9ojEjnIeBkN3Eq9spnsa7IUEc5OcY58jyXy9ciWqnGBRW6dKsY4TmF6tgLjj7BtAo
         TpgUPdnKpPv2d4EccVrTtZB7/L0PfzlIhm5YBACI05RFEcdZSvLVZmxaVZEf2bnRtDKs
         l8u8PHdGzaGFaSvmbX/Eqbp0VpCFxr6aV94SGCQsHdPNGHBtF/O/WqXjtcYxnBxlG+2q
         p0TFYM+ZnIsLNRCvgEl0h8mH7Lwb95/LiTQH9o0o0L51+20/FnW6YSFcCjdHUer4iqkB
         XqfyxfaGTvP0CC8mkejnrijMzBDpBenXIO2flwa8+Vg6GP5L6/2lARV96q3ksaiQel6l
         MhxA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=uRcNmLn4;
       spf=pass (google.com: domain of 3cxnfaqukcb4ipzivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--elver.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3cXNFaQUKCb4ipzivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1766159221; x=1766764021; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=ruViPzlNQHlqSjnM2DVAzGeO5aUj7gRIMHpeRQuCjfM=;
        b=bSCLqZORPXDR6lRUG0QOnKlVAmGUDMaNaqWrxw0QFs5AB4FZQpKWbLR4n09n760uZz
         1Niy3vGLR4zuENSTJBtf7/FvCOwa0nfd0vZfU8qqKiYCOipPvx5nQledKk7WJOByChfn
         pAQ+2B+wKGrg+k+yYqHBfH/Cl3tALKqqi361YQsMN3CT5TkSdJkqBPaaCh7MHwDU0Ah9
         cA4pmMvhaCNpm6cGXTpLQur/HE7pZBbetWj3eZScne38BWgO4nQS5XYuj+mvVG1ygXqU
         xkfxOdJPyQlRaKorhL8Dh2AA4fXVkDrK/xaznI70DyMjnXyatLRPmkyi5Uq0fYToE/20
         Tz+g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1766159221; x=1766764021;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=ruViPzlNQHlqSjnM2DVAzGeO5aUj7gRIMHpeRQuCjfM=;
        b=KsUXyzFgrs5xxzmEuVnzvlMoPAXk7mOCRviDmeDvsfMKcX52NlYVIhhf3nSn7w58LM
         /NrJ+TQAd7Exn7SjC4UDmN7eyd+FtSWk853mRb4bmhNRbAHyujo0Z3mkWeABH0ktGFZW
         s9JPAWhw3Ja6YFVltxgUog813OWeuIc/1nkjFyE+LjeKsuF6FGC60qcoGF+DpHBHx6Og
         kk1NmS09P+lM20sNicLYeMJwKUYbhrdSVevul1uhzD3VtKRRod2Vd/AzZ1jQRFy3Q/LO
         fDHYr8qe/OJ0cSMARubLS7UmmGMzFwzpOV5IyLASANnjbu8xl6if3oPp61aWgEbFA1nO
         EVwg==
X-Forwarded-Encrypted: i=2; AJvYcCWAKXkkqDmZZEIa7JGgMuslM4inZeZholoslQeVaIud0qDjUempidziqRBCEH16hQ0h9QhgZQ==@lfdr.de
X-Gm-Message-State: AOJu0YxDr8Muau+hMqu1yi8/KJIt7eEMbsVw4nNITJzm4cdznTv9Y4RX
	BK1CuOj086LvxKLMhAVUlZ+ykOas5k/H6o2wNz/M164kvTZ9xsQxuu8x
X-Google-Smtp-Source: AGHT+IE8cHN+QkgGEoGJR5ZUbZhTEuj6cI7c5NtIky7gabWysNYF4laIVX7GcJ2EBcGtyxko1S6DIw==
X-Received: by 2002:a05:6512:3e1b:b0:594:5607:3b1a with SMTP id 2adb3069b0e04-59a17cbfb40mr739993e87.0.1766159220866;
        Fri, 19 Dec 2025 07:47:00 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWa4ehD1tVAOeDtmSSX64hqPJrI/nVAB+Ix8JhrX05Kl1Q=="
Received: by 2002:a05:6512:131a:b0:597:d6d8:7e76 with SMTP id
 2adb3069b0e04-598fa385bfcls2568991e87.0.-pod-prod-08-eu; Fri, 19 Dec 2025
 07:46:58 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUxInKUCLu9sOIRfE9KtICOInLGfxQGmujeez3Fc+idMob1jKXVRFyPaTvz89gegmGAnvPPSNMNl38=@googlegroups.com
X-Received: by 2002:a05:6512:4016:b0:598:f4cb:aafd with SMTP id 2adb3069b0e04-59a17d958b8mr1220227e87.19.1766159218208;
        Fri, 19 Dec 2025 07:46:58 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1766159218; cv=none;
        d=google.com; s=arc-20240605;
        b=ONMieUAs33/IcUHR4PL+uv8bZXuQl6xTkljpRUo5reAQn+R5o8zQnkR0eGx3NBhEYX
         4cCdKCKfERvnaXU2l3HhLDIy/hVZ7VGPA7uxgtrNDlSXM82hfT4XBfS64zrXw2YCA9uM
         AJbz271M1KTQOvSQ3P9XQPpiyMYsv6FxFyDpfypBnSDuShsyNM4h7wwElNW4sCc7S/pV
         sr5+iHtv8ax3vfZR86AaFSRbPuqgUd2fkIwyab5DfXYWoWoKyhPnaqnUHc96jhMv00ll
         zSRwMU706sCw22zo2W+hSc7Jf7a/i04EbWrZDkm1r1jGbRBm7MaPyGc4wJ9euCb3OgV2
         lUtA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=BXcHXIDfWoSkrk6mEFbnYEvAXHgRRlXY75uZgyD6jWc=;
        fh=qzIXbeEN4Yme11l9R4rnD+90GBj5tO3M2iLcihX9ldc=;
        b=J400w2jBkFm5E7omsp+tovAO9d+RSwU/AO38ZPGmYejkyDP+/ssDaO5a2EKoUX36F7
         yzQXzNMygVXX19B0oAdfCWH00LQWu1uO8oGLFEE7rQvnwbyNJWpzWJ8ecMjoLejXy1tF
         2bQQG6Zq1KqBWiDV3Wf09u5ZoqQS6LrY6g81NfXXpdE+8XPRhGzHCa5wFrrCcRnyxA5E
         qK9zXHzHtCcslnfJQbpk3AdrVkTAHcy8sCB7wCdUR8lnHCvDgFzFVGEKeqs6lO6JsaQX
         /IMa5+Z0qYnp7xyCO7MySSvrgGQxh0HDXuwBGjzooKNNJZLYmVFlRuy61oqffEP0kyVk
         uPHA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=uRcNmLn4;
       spf=pass (google.com: domain of 3cxnfaqukcb4ipzivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--elver.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3cXNFaQUKCb4ipzivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x449.google.com (mail-wr1-x449.google.com. [2a00:1450:4864:20::449])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-59a186137b6si60699e87.5.2025.12.19.07.46.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 19 Dec 2025 07:46:58 -0800 (PST)
Received-SPF: pass (google.com: domain of 3cxnfaqukcb4ipzivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--elver.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) client-ip=2a00:1450:4864:20::449;
Received: by mail-wr1-x449.google.com with SMTP id ffacd0b85a97d-430ffa9fd7fso1120422f8f.0
        for <kasan-dev@googlegroups.com>; Fri, 19 Dec 2025 07:46:58 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCVtoEgpl4IQE3yjYVWarS799WUYfbiv+tPt5jx3LUaeBBJdcugyeBSgEhdZqTpi+f0V0KHvwECtJs4=@googlegroups.com
X-Received: from wmco28.prod.google.com ([2002:a05:600c:a31c:b0:477:afa:d217])
 (user=elver job=prod-delivery.src-stubby-dispatcher) by 2002:a05:600c:45cf:b0:47a:7fdd:2906
 with SMTP id 5b1f17b1804b1-47d1954a550mr28322755e9.12.1766159217354; Fri, 19
 Dec 2025 07:46:57 -0800 (PST)
Date: Fri, 19 Dec 2025 16:40:12 +0100
In-Reply-To: <20251219154418.3592607-1-elver@google.com>
Mime-Version: 1.0
References: <20251219154418.3592607-1-elver@google.com>
X-Mailer: git-send-email 2.52.0.322.g1dd061c0dc-goog
Message-ID: <20251219154418.3592607-24-elver@google.com>
Subject: [PATCH v5 23/36] compiler-context-analysis: Remove Sparse support
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
 header.i=@google.com header.s=20230601 header.b=uRcNmLn4;       spf=pass
 (google.com: domain of 3cxnfaqukcb4ipzivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3cXNFaQUKCb4ipzivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--elver.bounces.google.com;
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

Remove Sparse support as discussed at [1].

The kernel codebase is still scattered with numerous places that try to
appease Sparse's context tracking ("annotation for sparse", "fake out
sparse", "work around sparse", etc.). Eventually, as more subsystems
enable Clang's context analysis, these places will show up and need
adjustment or removal of the workarounds altogether.

Link: https://lore.kernel.org/all/20250207083335.GW7145@noisy.programming.kicks-ass.net/ [1]
Link: https://lore.kernel.org/all/Z6XTKTo_LMj9KmbY@elver.google.com/ [2]
Cc: Chris Li <sparse@chrisli.org>
Cc: "Luc Van Oostenryck" <luc.vanoostenryck@gmail.com>
Cc: Peter Zijlstra <peterz@infradead.org>
Signed-off-by: Marco Elver <elver@google.com>
---
v5:
* Rename "context guard" -> "context lock".

v4:
* Rename capability -> context analysis.

v2:
* New patch.
---
 Documentation/dev-tools/sparse.rst        | 19 -----
 include/linux/compiler-context-analysis.h | 85 +++++++----------------
 include/linux/rcupdate.h                  | 15 +---
 3 files changed, 28 insertions(+), 91 deletions(-)

diff --git a/Documentation/dev-tools/sparse.rst b/Documentation/dev-tools/sparse.rst
index dc791c8d84d1..37b20170835d 100644
--- a/Documentation/dev-tools/sparse.rst
+++ b/Documentation/dev-tools/sparse.rst
@@ -53,25 +53,6 @@ sure that bitwise types don't get mixed up (little-endian vs big-endian
 vs cpu-endian vs whatever), and there the constant "0" really _is_
 special.
 
-Using sparse for lock checking
-------------------------------
-
-The following macros are undefined for gcc and defined during a sparse
-run to use the "context" tracking feature of sparse, applied to
-locking.  These annotations tell sparse when a lock is held, with
-regard to the annotated function's entry and exit.
-
-__must_hold - The specified lock is held on function entry and exit.
-
-__acquires - The specified lock is held on function exit, but not entry.
-
-__releases - The specified lock is held on function entry, but not exit.
-
-If the function enters and exits without the lock held, acquiring and
-releasing the lock inside the function in a balanced way, no
-annotation is needed.  The three annotations above are for cases where
-sparse would otherwise report a context imbalance.
-
 Getting sparse
 --------------
 
diff --git a/include/linux/compiler-context-analysis.h b/include/linux/compiler-context-analysis.h
index 9ad800e27692..fccd6d68158e 100644
--- a/include/linux/compiler-context-analysis.h
+++ b/include/linux/compiler-context-analysis.h
@@ -262,57 +262,32 @@ static inline void _context_unsafe_alias(void **p) { }
 	extern const struct __ctx_lock_##ctx *name
 
 /*
- * Common keywords for static context analysis. Both Clang's "capability
- * analysis" and Sparse's "context tracking" are currently supported.
- */
-#ifdef __CHECKER__
-
-/* Sparse context/lock checking support. */
-# define __must_hold(x)		__attribute__((context(x,1,1)))
-# define __must_not_hold(x)
-# define __acquires(x)		__attribute__((context(x,0,1)))
-# define __cond_acquires(ret, x) __attribute__((context(x,0,-1)))
-# define __releases(x)		__attribute__((context(x,1,0)))
-# define __acquire(x)		__context__(x,1)
-# define __release(x)		__context__(x,-1)
-# define __cond_lock(x, c)	((c) ? ({ __acquire(x); 1; }) : 0)
-/* For Sparse, there's no distinction between exclusive and shared locks. */
-# define __must_hold_shared	__must_hold
-# define __acquires_shared	__acquires
-# define __cond_acquires_shared __cond_acquires
-# define __releases_shared	__releases
-# define __acquire_shared	__acquire
-# define __release_shared	__release
-# define __cond_lock_shared	__cond_acquire
-
-#else /* !__CHECKER__ */
+ * Common keywords for static context analysis.
+ */
 
 /**
  * __must_hold() - function attribute, caller must hold exclusive context lock
- * @x: context lock instance pointer
  *
  * Function attribute declaring that the caller must hold the given context
- * lock instance @x exclusively.
+ * lock instance(s) exclusively.
  */
-# define __must_hold(x)		__requires_ctx_lock(x)
+#define __must_hold(...)	__requires_ctx_lock(__VA_ARGS__)
 
 /**
  * __must_not_hold() - function attribute, caller must not hold context lock
- * @x: context lock instance pointer
  *
  * Function attribute declaring that the caller must not hold the given context
- * lock instance @x.
+ * lock instance(s).
  */
-# define __must_not_hold(x)	__excludes_ctx_lock(x)
+#define __must_not_hold(...)	__excludes_ctx_lock(__VA_ARGS__)
 
 /**
  * __acquires() - function attribute, function acquires context lock exclusively
- * @x: context lock instance pointer
  *
  * Function attribute declaring that the function acquires the given context
- * lock instance @x exclusively, but does not release it.
+ * lock instance(s) exclusively, but does not release them.
  */
-# define __acquires(x)		__acquires_ctx_lock(x)
+#define __acquires(...)		__acquires_ctx_lock(__VA_ARGS__)
 
 /*
  * Clang's analysis does not care precisely about the value, only that it is
@@ -339,17 +314,16 @@ static inline void _context_unsafe_alias(void **p) { }
  *
  * @ret may be one of: true, false, nonzero, 0, nonnull, NULL.
  */
-# define __cond_acquires(ret, x) __cond_acquires_impl_##ret(x)
+#define __cond_acquires(ret, x) __cond_acquires_impl_##ret(x)
 
 /**
  * __releases() - function attribute, function releases a context lock exclusively
- * @x: context lock instance pointer
  *
  * Function attribute declaring that the function releases the given context
- * lock instance @x exclusively. The associated context must be active on
+ * lock instance(s) exclusively. The associated context(s) must be active on
  * entry.
  */
-# define __releases(x)		__releases_ctx_lock(x)
+#define __releases(...)		__releases_ctx_lock(__VA_ARGS__)
 
 /**
  * __acquire() - function to acquire context lock exclusively
@@ -357,7 +331,7 @@ static inline void _context_unsafe_alias(void **p) { }
  *
  * No-op function that acquires the given context lock instance @x exclusively.
  */
-# define __acquire(x)		__acquire_ctx_lock(x)
+#define __acquire(x)		__acquire_ctx_lock(x)
 
 /**
  * __release() - function to release context lock exclusively
@@ -365,7 +339,7 @@ static inline void _context_unsafe_alias(void **p) { }
  *
  * No-op function that releases the given context lock instance @x.
  */
-# define __release(x)		__release_ctx_lock(x)
+#define __release(x)		__release_ctx_lock(x)
 
 /**
  * __cond_lock() - function that conditionally acquires a context lock
@@ -383,25 +357,23 @@ static inline void _context_unsafe_alias(void **p) { }
  *
  *	#define spin_trylock(l) __cond_lock(&lock, _spin_trylock(&lock))
  */
-# define __cond_lock(x, c)	__try_acquire_ctx_lock(x, c)
+#define __cond_lock(x, c)	__try_acquire_ctx_lock(x, c)
 
 /**
  * __must_hold_shared() - function attribute, caller must hold shared context lock
- * @x: context lock instance pointer
  *
  * Function attribute declaring that the caller must hold the given context
- * lock instance @x with shared access.
+ * lock instance(s) with shared access.
  */
-# define __must_hold_shared(x)	__requires_shared_ctx_lock(x)
+#define __must_hold_shared(...)	__requires_shared_ctx_lock(__VA_ARGS__)
 
 /**
  * __acquires_shared() - function attribute, function acquires context lock shared
- * @x: context lock instance pointer
  *
  * Function attribute declaring that the function acquires the given
- * context lock instance @x with shared access, but does not release it.
+ * context lock instance(s) with shared access, but does not release them.
  */
-# define __acquires_shared(x)	__acquires_shared_ctx_lock(x)
+#define __acquires_shared(...)	__acquires_shared_ctx_lock(__VA_ARGS__)
 
 /**
  * __cond_acquires_shared() - function attribute, function conditionally
@@ -410,23 +382,22 @@ static inline void _context_unsafe_alias(void **p) { }
  * @x: context lock instance pointer
  *
  * Function attribute declaring that the function conditionally acquires the
- * given context lock instance @x with shared access, but does not release it. The
- * function return value @ret denotes when the context lock is acquired.
+ * given context lock instance @x with shared access, but does not release it.
+ * The function return value @ret denotes when the context lock is acquired.
  *
  * @ret may be one of: true, false, nonzero, 0, nonnull, NULL.
  */
-# define __cond_acquires_shared(ret, x) __cond_acquires_impl_##ret(x, _shared)
+#define __cond_acquires_shared(ret, x) __cond_acquires_impl_##ret(x, _shared)
 
 /**
  * __releases_shared() - function attribute, function releases a
  *                       context lock shared
- * @x: context lock instance pointer
  *
  * Function attribute declaring that the function releases the given context
- * lock instance @x with shared access. The associated context must be active
- * on entry.
+ * lock instance(s) with shared access. The associated context(s) must be
+ * active on entry.
  */
-# define __releases_shared(x)	__releases_shared_ctx_lock(x)
+#define __releases_shared(...)	__releases_shared_ctx_lock(__VA_ARGS__)
 
 /**
  * __acquire_shared() - function to acquire context lock shared
@@ -435,7 +406,7 @@ static inline void _context_unsafe_alias(void **p) { }
  * No-op function that acquires the given context lock instance @x with shared
  * access.
  */
-# define __acquire_shared(x)	__acquire_shared_ctx_lock(x)
+#define __acquire_shared(x)	__acquire_shared_ctx_lock(x)
 
 /**
  * __release_shared() - function to release context lock shared
@@ -444,7 +415,7 @@ static inline void _context_unsafe_alias(void **p) { }
  * No-op function that releases the given context lock instance @x with shared
  * access.
  */
-# define __release_shared(x)	__release_shared_ctx_lock(x)
+#define __release_shared(x)	__release_shared_ctx_lock(x)
 
 /**
  * __cond_lock_shared() - function that conditionally acquires a context lock shared
@@ -457,9 +428,7 @@ static inline void _context_unsafe_alias(void **p) { }
  * shared access, if the boolean expression @c is true. The result of @c is the
  * return value.
  */
-# define __cond_lock_shared(x, c) __try_acquire_shared_ctx_lock(x, c)
-
-#endif /* __CHECKER__ */
+#define __cond_lock_shared(x, c) __try_acquire_shared_ctx_lock(x, c)
 
 /**
  * __acquire_ret() - helper to acquire context lock of return value
diff --git a/include/linux/rcupdate.h b/include/linux/rcupdate.h
index 50e63eade019..d828a4673441 100644
--- a/include/linux/rcupdate.h
+++ b/include/linux/rcupdate.h
@@ -1219,20 +1219,7 @@ rcu_head_after_call_rcu(struct rcu_head *rhp, rcu_callback_t f)
 extern int rcu_expedited;
 extern int rcu_normal;
 
-DEFINE_LOCK_GUARD_0(rcu,
-	do {
-		rcu_read_lock();
-		/*
-		 * sparse doesn't call the cleanup function,
-		 * so just release immediately and don't track
-		 * the context. We don't need to anyway, since
-		 * the whole point of the guard is to not need
-		 * the explicit unlock.
-		 */
-		__release(RCU);
-	} while (0),
-	rcu_read_unlock())
-
+DEFINE_LOCK_GUARD_0(rcu, rcu_read_lock(), rcu_read_unlock())
 DECLARE_LOCK_GUARD_0_ATTRS(rcu, __acquires_shared(RCU), __releases_shared(RCU))
 
 #endif /* __LINUX_RCUPDATE_H */
-- 
2.52.0.322.g1dd061c0dc-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251219154418.3592607-24-elver%40google.com.
