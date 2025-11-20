Return-Path: <kasan-dev+bncBC7OBJGL2MHBBFPA7TEAMGQEUSJ5OAQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x240.google.com (mail-lj1-x240.google.com [IPv6:2a00:1450:4864:20::240])
	by mail.lfdr.de (Postfix) with ESMTPS id E298FC74C78
	for <lists+kasan-dev@lfdr.de>; Thu, 20 Nov 2025 16:13:26 +0100 (CET)
Received: by mail-lj1-x240.google.com with SMTP id 38308e7fff4ca-37a34f910f8sf5961731fa.0
        for <lists+kasan-dev@lfdr.de>; Thu, 20 Nov 2025 07:13:26 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1763651606; cv=pass;
        d=google.com; s=arc-20240605;
        b=Gb0xpgWl/MPD/V1RKal/g3eZwh0+KIsA71zSNL5UQaINvPZB8DvcW9p1m97abmHaSt
         LWJT/HI3pZEYkTQeiTqqocvfVYVsWmHAaZ0uns07jhKHqKlGlRfIU/KeBTHZtq2qUePQ
         WzDAnST4KIpn7+lzpREuTsMYMYBt6c0S3Gt/E8fjOJgy4dETDlJlIffavZ+V7WV9FP+A
         v1ltdFzKSHzg33IocZg2W0M9DrtfV1uwlpOy8TIMgM3s+PMl30TTMU8coXJuS6+7zZGU
         87U5+DcR6FNBBNK4+89Z8sRWkmuBEN/ZYApefI7KfgCaFS4fc8p+NCvmb0/xd1G5fsIM
         G/gw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=2eEcMbyzXEXzwzH4b331ZXwbAdwEGOUlhxFoMGVGnS4=;
        fh=VmSw8+b8deVA+AeHO9lg2OfyZ9a1tY01eCEIb7KMAq8=;
        b=br1+sxR1+3p9tjKLii/LOEd2ifQolyw4lt6Ye2jpbIEr89iG5rkQDQkn1EI61ee5pZ
         3NkYUelXXckV1b7JTBVKYlCoxDN37nFDrgczFohHDjQdh/7BOUjgOLbQ37MjnX6z3+QC
         oqwqudu4UlUY9Gc5d3dpbVEPmwUBl1dvPvTuHTsqvQ66Wbz4UJBD0J4YxxCiZ8PegOik
         ky+0p4AuHGULT/S/OjMF5qoS9u+dsjJsmCpMNKlHWBzwGqyY1d7dk3Pluw+wtciS/99Z
         qfHJyzXbmaQxgvJgd+7AkB/41E/JeXVlmzlU1/YTMk7siA58Tbs4t1MzfvuQGx05imW1
         Us1g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=QfdXWIDU;
       spf=pass (google.com: domain of 3czafaqukctgyfpylaiiafy.wigeumuh-xypaiiafyaliojm.wig@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3CzAfaQUKCTgYfpYlaiiafY.WigeUmUh-XYpaiiafYaliojm.Wig@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1763651606; x=1764256406; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=2eEcMbyzXEXzwzH4b331ZXwbAdwEGOUlhxFoMGVGnS4=;
        b=CVCjPEXO50ylnU/p97p7jcr1zBU0LRu/+4fA6sIRvp1lL0G6XMtiLl8Z4gFkJB2+Qv
         E2emyTSn8c7wn7ihmXfR8r1VbTiS8zbCmtgOxKELZ5EUYKnbHRuXKao+v7ByEjgrPq21
         azbw5GztakniawaDrYgN/TY1lKCaIiiS+twndY+uaenWFwRqCi33RXoDK8saKKSn05pE
         tOvNTj3SS3qcYKICYeN8ilFs4nExpQgRd8IaLzDae1VFWdgV7JYVivAfSM0p/rA46cek
         m/TGYykYOmWSReehqJlXuDXBoGqgKvkAHtfnyj5Rfr/3qoA/KYNHd5WY2oGsSFRXKCmy
         PDEw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1763651606; x=1764256406;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=2eEcMbyzXEXzwzH4b331ZXwbAdwEGOUlhxFoMGVGnS4=;
        b=Ht5anD2mWRtA4WrMhXxy6Ra2gAKIXyPA28c+KcmSkxsKNT9th8/kMUMM2jn5UlUf2f
         Q51piMUeXo8g/y1a2ymITRQbEgDDox3AxrcEsbvsAauDZaNwRopTzDSEQmB4rBipfafz
         CesSPcoWdnhdoFEowIa4Xczef9OrHp8/S+VWI85K3Gby8re69jMwMOdThzJcLYH7nCcY
         Es4P6X4gcofsv74UR29xXJ35asDBLUh9HBbztSchS1E5utMhVF/IZ6T6juy/i6RJl5n2
         hBW+pCPxn0j9qa7P1xss5cHVPshbcvjdhqf3VR8kfFt2XoSFwiVqPbBjHLtEi/AOJkgE
         lb2Q==
X-Forwarded-Encrypted: i=2; AJvYcCUE4IxgZGqFp0SNZbmrBsQZCB7scWyFzh66nqlm6xpOWnktmabvtztqvACF744E7CQ1clGfWQ==@lfdr.de
X-Gm-Message-State: AOJu0Yx/h7lWuyE5/K9zoxg9Eaayr353EQ5/oK16d8R64LnFFSmbkUG9
	YkrbptUgjWjKPqIPcpp0PRAzGhG1l/uQlR0OiWIgOpb10Dp0IAZnIFta
X-Google-Smtp-Source: AGHT+IFhHLhB+N0iqzHlnGXWSrkQ9/VDQREaAQzOgRbIwF8SwpMeWLA/qz/FSOPAid+peczLQqvgsg==
X-Received: by 2002:a05:6512:3093:b0:594:3a5f:4e36 with SMTP id 2adb3069b0e04-5969f4d4a77mr811866e87.40.1763651606103;
        Thu, 20 Nov 2025 07:13:26 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+aWoX8K7bXXEcxnmmOtgzPpH7JfHpentCVkKUmYvNb+pA=="
Received: by 2002:a05:6512:250b:b0:595:958b:70b5 with SMTP id
 2adb3069b0e04-5969dc109b2ls480361e87.0.-pod-prod-01-eu; Thu, 20 Nov 2025
 07:13:23 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUus3tE/BqNjX7rrJ/nZHjbxARl/k2GPvmDOiN94kVPgkIlTLh/B5t0wMW5cu9Ia4jg2c10KYB25CI=@googlegroups.com
X-Received: by 2002:a05:6512:401d:b0:594:51ac:138 with SMTP id 2adb3069b0e04-5969f273572mr825120e87.2.1763651602820;
        Thu, 20 Nov 2025 07:13:22 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1763651602; cv=none;
        d=google.com; s=arc-20240605;
        b=hrKMzMSksVHpMIBCqwC609XL2ztU305nJFiX2BszZ6aC7Cjmfsl0iHMhepF9bF5vwv
         xxsPTvvKIwueWIjH3OvI92FrEaGPjXPE+GDr7dODqEaDk5Jr09G8LaXmMm7IuqsSe54g
         54/3t2Q11LOXjKRis41l2ZW3aUheZX9hMDF1hf4abMrrPX4dgG/cyOqz0mrldmSu8fea
         sTZI0igTSQaFPKQWLpheEi0+HCN45qDzwQbF+BQ482BhkO0/OTJI+1piDu4zBKPSlGjQ
         2C9Mg+Dzg8ZsYqL/pE53AikXYLOfbr7Rgee6pNq3mxUNQvWAV9xub1aapmqzIC5Y51VF
         P9DQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=FM+v7kmKwxv6mQJTQvhb3JUsaW+ES8Jzb95oMtr52Zo=;
        fh=+iFTkNm4FkBlHXbjD+OCAMoKLC3pHCLqgKGGgJGQrbI=;
        b=UBb1cJRGkCYjWc+LdxM4o6lrtDpVExwGsaKF943zhurLiFSGskan5a0Yi5G2O3uT98
         XL+/1OyvSqbvlmXLmleuBDEA92RjbPgwSwdfAAuJOt4H5YYJw/Vr/jPfOXb/A8ubVOZC
         aPi0WrvvfAPCWIH3Kpylx0Z31n/A/S2XPuygUYVujB47/eS+vXVGibTIqCQdj2D/XFwk
         RWcsE0JMxljVGVNyQTIBiWcE1jJysVLOn8eCkSrVTZ0Le8pkvXrhmupxZJauSVoKqzMe
         5F9+MZsyj+1QFL6jbwN3533e/ciec+ZjhqpExx/68VDKScUqB8Z4kVwL0B3GdILHAE5w
         BmMw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=QfdXWIDU;
       spf=pass (google.com: domain of 3czafaqukctgyfpylaiiafy.wigeumuh-xypaiiafyaliojm.wig@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3CzAfaQUKCTgYfpYlaiiafY.WigeUmUh-XYpaiiafYaliojm.Wig@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x349.google.com (mail-wm1-x349.google.com. [2a00:1450:4864:20::349])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-5969dba0852si45657e87.4.2025.11.20.07.13.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 20 Nov 2025 07:13:22 -0800 (PST)
Received-SPF: pass (google.com: domain of 3czafaqukctgyfpylaiiafy.wigeumuh-xypaiiafyaliojm.wig@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) client-ip=2a00:1450:4864:20::349;
Received: by mail-wm1-x349.google.com with SMTP id 5b1f17b1804b1-477a11d9f89so5144095e9.3
        for <kasan-dev@googlegroups.com>; Thu, 20 Nov 2025 07:13:22 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCWYhPWCAnYlVKWz1DIofF/MyMo4bPPjG9I7OEyRTnTS5SZ2suniOVTUEMy396/xZTEtRhG0kMWHxN4=@googlegroups.com
X-Received: from wmgi8.prod.google.com ([2002:a05:600c:2d88:b0:475:d94e:4d5d])
 (user=elver job=prod-delivery.src-stubby-dispatcher) by 2002:a05:600c:458e:b0:46e:396b:f5ae
 with SMTP id 5b1f17b1804b1-477bac0cfb5mr29573045e9.16.1763651595671; Thu, 20
 Nov 2025 07:13:15 -0800 (PST)
Date: Thu, 20 Nov 2025 16:09:47 +0100
In-Reply-To: <20251120151033.3840508-7-elver@google.com>
Mime-Version: 1.0
References: <20251120145835.3833031-2-elver@google.com> <20251120151033.3840508-7-elver@google.com>
X-Mailer: git-send-email 2.52.0.rc1.455.g30608eb744-goog
Message-ID: <20251120151033.3840508-23-elver@google.com>
Subject: [PATCH v4 22/35] compiler-context-analysis: Remove Sparse support
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
 header.i=@google.com header.s=20230601 header.b=QfdXWIDU;       spf=pass
 (google.com: domain of 3czafaqukctgyfpylaiiafy.wigeumuh-xypaiiafyaliojm.wig@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3CzAfaQUKCTgYfpYlaiiafY.WigeUmUh-XYpaiiafYaliojm.Wig@flex--elver.bounces.google.com;
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
index 935e59089d75..6990cab7a4a9 100644
--- a/include/linux/compiler-context-analysis.h
+++ b/include/linux/compiler-context-analysis.h
@@ -250,57 +250,32 @@ static inline void _context_unsafe_alias(void **p) { }
 	extern const struct __ctx_guard_##ctx *name
 
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
  * __must_hold() - function attribute, caller must hold exclusive context guard
- * @x: context guard instance pointer
  *
  * Function attribute declaring that the caller must hold the given context
- * guard instance @x exclusively.
+ * guard instance(s) exclusively.
  */
-# define __must_hold(x)		__requires_ctx_guard(x)
+#define __must_hold(...)	__requires_ctx_guard(__VA_ARGS__)
 
 /**
  * __must_not_hold() - function attribute, caller must not hold context guard
- * @x: context guard instance pointer
  *
  * Function attribute declaring that the caller must not hold the given context
- * guard instance @x.
+ * guard instance(s).
  */
-# define __must_not_hold(x)	__excludes_ctx_guard(x)
+#define __must_not_hold(...)	__excludes_ctx_guard(__VA_ARGS__)
 
 /**
  * __acquires() - function attribute, function acquires context guard exclusively
- * @x: context guard instance pointer
  *
  * Function attribute declaring that the function acquires the given context
- * guard instance @x exclusively, but does not release it.
+ * guard instance(s) exclusively, but does not release them.
  */
-# define __acquires(x)		__acquires_ctx_guard(x)
+#define __acquires(...)		__acquires_ctx_guard(__VA_ARGS__)
 
 /*
  * Clang's analysis does not care precisely about the value, only that it is
@@ -327,17 +302,16 @@ static inline void _context_unsafe_alias(void **p) { }
  *
  * @ret may be one of: true, false, nonzero, 0, nonnull, NULL.
  */
-# define __cond_acquires(ret, x) __cond_acquires_impl_##ret(x)
+#define __cond_acquires(ret, x) __cond_acquires_impl_##ret(x)
 
 /**
  * __releases() - function attribute, function releases a context guard exclusively
- * @x: context guard instance pointer
  *
  * Function attribute declaring that the function releases the given context
- * guard instance @x exclusively. The associated context must be active on
+ * guard instance(s) exclusively. The associated context(s) must be active on
  * entry.
  */
-# define __releases(x)		__releases_ctx_guard(x)
+#define __releases(...)		__releases_ctx_guard(__VA_ARGS__)
 
 /**
  * __acquire() - function to acquire context guard exclusively
@@ -345,7 +319,7 @@ static inline void _context_unsafe_alias(void **p) { }
  *
  * No-op function that acquires the given context guard instance @x exclusively.
  */
-# define __acquire(x)		__acquire_ctx_guard(x)
+#define __acquire(x)		__acquire_ctx_guard(x)
 
 /**
  * __release() - function to release context guard exclusively
@@ -353,7 +327,7 @@ static inline void _context_unsafe_alias(void **p) { }
  *
  * No-op function that releases the given context guard instance @x.
  */
-# define __release(x)		__release_ctx_guard(x)
+#define __release(x)		__release_ctx_guard(x)
 
 /**
  * __cond_lock() - function that conditionally acquires a context guard
@@ -371,25 +345,23 @@ static inline void _context_unsafe_alias(void **p) { }
  *
  *	#define spin_trylock(l) __cond_lock(&lock, _spin_trylock(&lock))
  */
-# define __cond_lock(x, c)	__try_acquire_ctx_guard(x, c)
+#define __cond_lock(x, c)	__try_acquire_ctx_guard(x, c)
 
 /**
  * __must_hold_shared() - function attribute, caller must hold shared context guard
- * @x: context guard instance pointer
  *
  * Function attribute declaring that the caller must hold the given context
- * guard instance @x with shared access.
+ * guard instance(s) with shared access.
  */
-# define __must_hold_shared(x)	__requires_shared_ctx_guard(x)
+#define __must_hold_shared(...)	__requires_shared_ctx_guard(__VA_ARGS__)
 
 /**
  * __acquires_shared() - function attribute, function acquires context guard shared
- * @x: context guard instance pointer
  *
  * Function attribute declaring that the function acquires the given
- * context guard instance @x with shared access, but does not release it.
+ * context guard instance(s) with shared access, but does not release them.
  */
-# define __acquires_shared(x)	__acquires_shared_ctx_guard(x)
+#define __acquires_shared(...)	__acquires_shared_ctx_guard(__VA_ARGS__)
 
 /**
  * __cond_acquires_shared() - function attribute, function conditionally
@@ -398,23 +370,22 @@ static inline void _context_unsafe_alias(void **p) { }
  * @x: context guard instance pointer
  *
  * Function attribute declaring that the function conditionally acquires the
- * given context guard instance @x with shared access, but does not release it. The
- * function return value @ret denotes when the context guard is acquired.
+ * given context guard instance @x with shared access, but does not release it.
+ * The function return value @ret denotes when the context guard is acquired.
  *
  * @ret may be one of: true, false, nonzero, 0, nonnull, NULL.
  */
-# define __cond_acquires_shared(ret, x) __cond_acquires_impl_##ret(x, _shared)
+#define __cond_acquires_shared(ret, x) __cond_acquires_impl_##ret(x, _shared)
 
 /**
  * __releases_shared() - function attribute, function releases a
  *                       context guard shared
- * @x: context guard instance pointer
  *
  * Function attribute declaring that the function releases the given context
- * guard instance @x with shared access. The associated context must be active
- * on entry.
+ * guard instance(s) with shared access. The associated context(s) must be
+ * active on entry.
  */
-# define __releases_shared(x)	__releases_shared_ctx_guard(x)
+#define __releases_shared(...)	__releases_shared_ctx_guard(__VA_ARGS__)
 
 /**
  * __acquire_shared() - function to acquire context guard shared
@@ -423,7 +394,7 @@ static inline void _context_unsafe_alias(void **p) { }
  * No-op function that acquires the given context guard instance @x with shared
  * access.
  */
-# define __acquire_shared(x)	__acquire_shared_ctx_guard(x)
+#define __acquire_shared(x)	__acquire_shared_ctx_guard(x)
 
 /**
  * __release_shared() - function to release context guard shared
@@ -432,7 +403,7 @@ static inline void _context_unsafe_alias(void **p) { }
  * No-op function that releases the given context guard instance @x with shared
  * access.
  */
-# define __release_shared(x)	__release_shared_ctx_guard(x)
+#define __release_shared(x)	__release_shared_ctx_guard(x)
 
 /**
  * __cond_lock_shared() - function that conditionally acquires a context guard shared
@@ -445,9 +416,7 @@ static inline void _context_unsafe_alias(void **p) { }
  * shared access, if the boolean expression @c is true. The result of @c is the
  * return value.
  */
-# define __cond_lock_shared(x, c) __try_acquire_shared_ctx_guard(x, c)
-
-#endif /* __CHECKER__ */
+#define __cond_lock_shared(x, c) __try_acquire_shared_ctx_guard(x, c)
 
 /**
  * __acquire_ret() - helper to acquire context guard of return value
diff --git a/include/linux/rcupdate.h b/include/linux/rcupdate.h
index 5cddb9019a99..dd12e738e073 100644
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
2.52.0.rc1.455.g30608eb744-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251120151033.3840508-23-elver%40google.com.
