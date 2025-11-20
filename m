Return-Path: <kasan-dev+bncBC7OBJGL2MHBBHW37TEAMGQEOYB275Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x340.google.com (mail-wm1-x340.google.com [IPv6:2a00:1450:4864:20::340])
	by mail.lfdr.de (Postfix) with ESMTPS id AAD46C74B9C
	for <lists+kasan-dev@lfdr.de>; Thu, 20 Nov 2025 16:02:55 +0100 (CET)
Received: by mail-wm1-x340.google.com with SMTP id 5b1f17b1804b1-477939321e6sf5925015e9.0
        for <lists+kasan-dev@lfdr.de>; Thu, 20 Nov 2025 07:02:55 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1763650975; cv=pass;
        d=google.com; s=arc-20240605;
        b=gDeiVk/tuJfuSimxEu7DKv1tObCA3KzKO8T0jXp0UT845wdFFGWVF/scP5IBf2uoit
         YTta0oBw+cymkrulkf7bWAoQHjksZaFfb/5ZJQkm6CyRwEJMyTZCJH47gqJSk4K+2929
         g3SlpAgvEwB1f29ejZeBB84C4MFMeri/+JBUTiJ1+86PNe63cuUpf1p0LhIOfAeLQ4m5
         p2WD4pSmXmz2ImHCcwpLtfNzXReVlAQwKkDMkRviM5Ak0rnqXjlrZxWVkOgafntCcGOQ
         kGWaXXU77ygglqUeEuqwDb0HEjiRzBvEk5jMpoEY4R3L66LqTI96wSwujCXkXSywYdP9
         vaoQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=VyJBCyI4sDWN4uoyN06aCUoNaDh3de1583igEnVTs8A=;
        fh=NcUApknRXY8nSAnG2BXtX9Sksbrm6zOiQpx2g2Yuit4=;
        b=Ru8Qy9Jyi+/ZXRWZJg5kOa4pD2Kj27F7smR1UavHSdDlJRa5mF7MmGNR08rYJnIF+i
         h+t5ZAeOkiNv0lhe1bhJJX0lB0+c/qrhuAD+TIimMTTjra6vn0GDD4nu1KsKdCwJUrWh
         ZsmIHppfGwP6zQsB0DAy9Nyt03vP9WuytQ1eyyYJJvN1nk3EqYIKUM3da8+jiIu2yFft
         n3TBdzaoZh8oBdZYR1o+w8PyvZDgthLdt42j6cEzlpRZn9LzBcEbFwtZhWs8F052nUoy
         3Yrvz1xa/0Wqm94M4YTJNDH8PdRufX9V3Pfci1Cny9bUSR+M0Hfjutzmn5UKJjt2zBXz
         BrUg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=t8UXBSIl;
       spf=pass (google.com: domain of 3mi0faqukccels2lynvvnsl.jvtrhzhu-kl2nvvnslnyv1wz.jvt@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3mi0faQUKCcEls2lynvvnsl.jvtrhzhu-kl2nvvnslnyv1wz.jvt@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1763650975; x=1764255775; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=VyJBCyI4sDWN4uoyN06aCUoNaDh3de1583igEnVTs8A=;
        b=MUyQOmJzjR0CyoRafZ3EVAtwbp+Sh7UVE2iGZweG0ajEYDzZk8iMVTU0F0G2p3bFvl
         LP3g2bcMNTWXEwPLv7JJJCbS9K2fxzA7Smt7wsYyU9ARUrcAHRz1FJ35IqG5dmslfVv8
         nUHlmouEie+eqDSnP91HagXrezp7gphAmgaXd+uJuaZjBh5P+mq8kgs7HskbwJ/8arFc
         c+9UYptz/WBP3kS4rrsRcoLDFD96BQlfXEpD32+k6NGsuSLQKMylYMsREYCPlJ2i1ytn
         r/yStHqcAK4xLus+AAx9SeFEbg2Xc3hznotw2IbJSwYBS0MxYMn+ukwD2yCGctjuz7JX
         iwJw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1763650975; x=1764255775;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=VyJBCyI4sDWN4uoyN06aCUoNaDh3de1583igEnVTs8A=;
        b=nbDxVSlZcrO/aZQCVXnSQtciZMsVVtGUFqKWvjkK4OFHZHRXsARPpMBkrR6g9pROlY
         PBoA88Z527Rb1fQRmBytEFT/2OLXFStHfLU4puPpS9uVvKecsWiPCCv/+PYmaYRrOuwb
         erHihQfF77RjKq/h2AdrdaSIxvebBhjWLVjJh2TCdBgOwsZiR+LTD4WFXGIuI3APO3gd
         Ve1eiogm8ZVWwtEQ3rrfOXJUeSJlVCccs6YO+Ks75M8JMxp1oBWi4Eahwnj2kEPi87q6
         hSDsHDld8VgESORKpiTU8i1OqDcEfmXflJse3j1YX5ll+v0+qOWlpcKTk+3Llhd2WtIC
         3N/w==
X-Forwarded-Encrypted: i=2; AJvYcCWQtwvHJfcvFHyqhIc3tWS1tbLnG4YitBDJlRkd4hJahsBORVw2uVO9uP2qXVdslld1JXxdnQ==@lfdr.de
X-Gm-Message-State: AOJu0Yzh7cll6RuzwRMSL1OYmh4ts4N5/gek1aqxP+Zgt6TiLztF7POA
	vF0/YaksIPGKdnP1IYqQJFWehtiT5TaoLv1M9f/sqEYbwRiAopwdMhJ6
X-Google-Smtp-Source: AGHT+IElLZqRPTslsMloLqUZyCyps5sB9GJsYImBp7K2LdN7tQsut0DKQkmB4Hx9lEc0jx5JUM9kiw==
X-Received: by 2002:a05:600c:3b01:b0:477:942:7521 with SMTP id 5b1f17b1804b1-477b8a50cf7mr33367435e9.14.1763650974610;
        Thu, 20 Nov 2025 07:02:54 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+bxEN1k9Byk6AaVVNJMMXP0qdhfT+3NSqD/xw36cFEJ4g=="
Received: by 2002:a05:6000:2dc9:b0:42b:52c4:664f with SMTP id
 ffacd0b85a97d-42cb816bf3als583337f8f.0.-pod-prod-08-eu; Thu, 20 Nov 2025
 07:02:51 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWuaCxyMbKIjoUr7WS4Qv5UXGOKyDRY8S8WShnZ4lKmV6l7LXD2G1VdSk15gNt4ZrtA5vnOd5TcDRs=@googlegroups.com
X-Received: by 2002:a05:6000:2681:b0:425:7e45:a4df with SMTP id ffacd0b85a97d-42cb9a204cbmr3418194f8f.11.1763650971291;
        Thu, 20 Nov 2025 07:02:51 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1763650971; cv=none;
        d=google.com; s=arc-20240605;
        b=PgEtFa2QkA/lPL2XGH2tsbs1O5sqRTm8FpW0QdAeG6UBYdsLfT4OrOslmtijRoyRc8
         y5i9IVQv7d1GKZufHpGC8qJaPNN641L8gAnUrRKbfBSql4kj15kjGwNf8+iNUNU5bJ3I
         WopmvCixjmi+PFf6YKPezGHGCj8k3AzGNRhc66C1Tc2lIqtzixX96AIXcj9/bUjH0s+I
         YOKRYy0coB89JfqCU+lBGSl8Gq7zhI6NGJZcvo8BBjI2kkkU/4+L7V9WUjzSPOmI++AX
         RFw3ES1llMb2qhkDEDDZX9Y1gTO7XLHvUYgFfouMzxRAU1u0fM+rgbJVDZICJMyU7TmS
         u1gg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=pO9hFwvp+ZAw4faY1qJIaLxAu4rxu7t5oxtHI4nO9RE=;
        fh=GIcPush40E9EHJrUYS6UOldqW9OW1ukgjbTDFUSTEXk=;
        b=ieaM1JkvciN9KfVKXa0ZV3gljn82aYbji05Jc5N0RO3OEqfUK0hbtJwOL/rikqviza
         RzedEQ2widQn8izZJECwDqru/Aa103TQGSsGgWYro+1o5vr8+LAhtsFm24MeWGvpXqT2
         rGwZGs11HS2DlRfvpmzk4pPNLX+hR3udJ+jDpXHds5vdfJs5hXrQttca4Qv7Q+sDxk0X
         /MZGAsMSH5W4l7W2z6NJcGCCXQV41qEDHnva4sggPnn7ayITMVwBJX9E6FSzSZ/v9haj
         1Omz3+yHQ0/9c8Zuw9wdXtGxCLAUMbfME3N7yxnjdSlgQtgC6LS6On26cpd7snMLstUx
         VMIA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=t8UXBSIl;
       spf=pass (google.com: domain of 3mi0faqukccels2lynvvnsl.jvtrhzhu-kl2nvvnslnyv1wz.jvt@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3mi0faQUKCcEls2lynvvnsl.jvtrhzhu-kl2nvvnslnyv1wz.jvt@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x44a.google.com (mail-wr1-x44a.google.com. [2a00:1450:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-42cb7f38f93si35156f8f.5.2025.11.20.07.02.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 20 Nov 2025 07:02:51 -0800 (PST)
Received-SPF: pass (google.com: domain of 3mi0faqukccels2lynvvnsl.jvtrhzhu-kl2nvvnslnyv1wz.jvt@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) client-ip=2a00:1450:4864:20::44a;
Received: by mail-wr1-x44a.google.com with SMTP id ffacd0b85a97d-42b2f79759bso1093311f8f.2
        for <kasan-dev@googlegroups.com>; Thu, 20 Nov 2025 07:02:51 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCXnpdp2v6VXLlcEbo/xYHsQvCidhJFaiiFodE/WXTE238Fu3XFDPz7uum8Or/1KtXA2c4/9WMpt7Jg=@googlegroups.com
X-Received: from wrsy7.prod.google.com ([2002:a5d:4ac7:0:b0:42b:3a01:7811])
 (user=elver job=prod-delivery.src-stubby-dispatcher) by 2002:a5d:460f:0:b0:42b:396e:27fd
 with SMTP id ffacd0b85a97d-42cb9a5612emr2389445f8f.38.1763650970452; Thu, 20
 Nov 2025 07:02:50 -0800 (PST)
Date: Thu, 20 Nov 2025 15:49:04 +0100
In-Reply-To: <20251120145835.3833031-2-elver@google.com>
Mime-Version: 1.0
References: <20251120145835.3833031-2-elver@google.com>
X-Mailer: git-send-email 2.52.0.rc1.455.g30608eb744-goog
Message-ID: <20251120145835.3833031-4-elver@google.com>
Subject: [PATCH v4 02/35] compiler-context-analysis: Add infrastructure for
 Context Analysis with Clang
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
 header.i=@google.com header.s=20230601 header.b=t8UXBSIl;       spf=pass
 (google.com: domain of 3mi0faqukccels2lynvvnsl.jvtrhzhu-kl2nvvnslnyv1wz.jvt@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3mi0faQUKCcEls2lynvvnsl.jvtrhzhu-kl2nvvnslnyv1wz.jvt@flex--elver.bounces.google.com;
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

Context Analysis is a language extension, which enables statically
checking that required contexts are active (or inactive), by acquiring
and releasing user-definable "context guards". An obvious application is
lock-safety checking for the kernel's various synchronization primitives
(each of which represents a "context guard"), and checking that locking
rules are not violated.

Clang originally called the feature "Thread Safety Analysis" [1]. This
was later changed and the feature became more flexible, gaining the
ability to define custom "capabilities". Its foundations can be found in
"Capability Systems" [2], used to specify the permissibility of
operations to depend on some "capability" being held (or not held).

Because the feature is not just able to express "capabilities" related
to synchronization primitives, and "capability" is already overloaded in
the kernel, the naming chosen for the kernel departs from Clang's
"Thread Safety" and "capability" nomenclature; we refer to the feature
as "Context Analysis" to avoid confusion. The internal implementation
still makes references to Clang's terminology in a few places, such as
`-Wthread-safety` being the warning option that also still appears in
diagnostic messages.

 [1] https://clang.llvm.org/docs/ThreadSafetyAnalysis.html
 [2] https://www.cs.cornell.edu/talc/papers/capabilities.pdf

See more details in the kernel-doc documentation added in this and
subsequent changes.

Clang version 22+ is required.

Signed-off-by: Marco Elver <elver@google.com>
---
v4:
* Rename capability -> context analysis.

v3:
* Require Clang 22 or later (reentrant capabilities, basic alias analysis).
* Rename __assert_cap/__asserts_cap -> __assume_cap/__assumes_cap (suggested by Peter).
* Add __acquire_ret and __acquire_shared_ret helper macros - can be used
  to define function-like macros that return objects which contains a
  held capabilities. Works now because of capability alias analysis.
* Add capability_unsafe_alias() helper, where the analysis rightfully
  points out we're doing strange things with aliases but we don't care.
* Support multi-argument attributes.

v2:
* New -Wthread-safety feature rename to -Wthread-safety-pointer (was
  -Wthread-safety-addressof).
* Introduce __capability_unsafe() function attribute.
* Rename __var_guarded_by to simply __guarded_by. The initial idea was
  to be explicit if the variable or pointed-to data is guarded by, but
  having a shorter attribute name is likely better long-term.
* Rename __ref_guarded_by to __pt_guarded_by (pointed-to guarded by).
---
 Makefile                                  |   1 +
 include/linux/compiler-context-analysis.h | 452 +++++++++++++++++++++-
 lib/Kconfig.debug                         |  30 ++
 scripts/Makefile.context-analysis         |   7 +
 scripts/Makefile.lib                      |  10 +
 5 files changed, 493 insertions(+), 7 deletions(-)
 create mode 100644 scripts/Makefile.context-analysis

diff --git a/Makefile b/Makefile
index d763c2c75cdb..0cad6e76f801 100644
--- a/Makefile
+++ b/Makefile
@@ -1093,6 +1093,7 @@ include-$(CONFIG_RANDSTRUCT)	+= scripts/Makefile.randstruct
 include-$(CONFIG_KSTACK_ERASE)	+= scripts/Makefile.kstack_erase
 include-$(CONFIG_AUTOFDO_CLANG)	+= scripts/Makefile.autofdo
 include-$(CONFIG_PROPELLER_CLANG)	+= scripts/Makefile.propeller
+include-$(CONFIG_WARN_CONTEXT_ANALYSIS) += scripts/Makefile.context-analysis
 include-$(CONFIG_GCC_PLUGINS)	+= scripts/Makefile.gcc-plugins
 
 include $(addprefix $(srctree)/, $(include-y))
diff --git a/include/linux/compiler-context-analysis.h b/include/linux/compiler-context-analysis.h
index f8af63045281..8c75e1d0034a 100644
--- a/include/linux/compiler-context-analysis.h
+++ b/include/linux/compiler-context-analysis.h
@@ -6,27 +6,465 @@
 #ifndef _LINUX_COMPILER_CONTEXT_ANALYSIS_H
 #define _LINUX_COMPILER_CONTEXT_ANALYSIS_H
 
+#if defined(WARN_CONTEXT_ANALYSIS)
+
+/*
+ * These attributes define new context guard (Clang: capability) types.
+ * Internal only.
+ */
+# define __ctx_guard_type(name)			__attribute__((capability(#name)))
+# define __reentrant_ctx_guard			__attribute__((reentrant_capability))
+# define __acquires_ctx_guard(...)		__attribute__((acquire_capability(__VA_ARGS__)))
+# define __acquires_shared_ctx_guard(...)	__attribute__((acquire_shared_capability(__VA_ARGS__)))
+# define __try_acquires_ctx_guard(ret, var)	__attribute__((try_acquire_capability(ret, var)))
+# define __try_acquires_shared_ctx_guard(ret, var) __attribute__((try_acquire_shared_capability(ret, var)))
+# define __releases_ctx_guard(...)		__attribute__((release_capability(__VA_ARGS__)))
+# define __releases_shared_ctx_guard(...)	__attribute__((release_shared_capability(__VA_ARGS__)))
+# define __assumes_ctx_guard(...)		__attribute__((assert_capability(__VA_ARGS__)))
+# define __assumes_shared_ctx_guard(...)	__attribute__((assert_shared_capability(__VA_ARGS__)))
+# define __returns_ctx_guard(var)		__attribute__((lock_returned(var)))
+
+/*
+ * The below are used to annotate code being checked. Internal only.
+ */
+# define __excludes_ctx_guard(...)		__attribute__((locks_excluded(__VA_ARGS__)))
+# define __requires_ctx_guard(...)		__attribute__((requires_capability(__VA_ARGS__)))
+# define __requires_shared_ctx_guard(...)	__attribute__((requires_shared_capability(__VA_ARGS__)))
+
+/**
+ * __guarded_by - struct member and globals attribute, declares variable
+ *                only accessible within active context
+ *
+ * Declares that the struct member or global variable is only accessible within
+ * the context entered by the given context guard. Read operations on the data
+ * require shared access, while write operations require exclusive access.
+ *
+ * .. code-block:: c
+ *
+ *	struct some_state {
+ *		spinlock_t lock;
+ *		long counter __guarded_by(&lock);
+ *	};
+ */
+# define __guarded_by(...)		__attribute__((guarded_by(__VA_ARGS__)))
+
+/**
+ * __pt_guarded_by - struct member and globals attribute, declares pointed-to
+ *                   data only accessible within active context
+ *
+ * Declares that the data pointed to by the struct member pointer or global
+ * pointer is only accessible within the context entered by the given context
+ * guard. Read operations on the data require shared access, while write
+ * operations require exclusive access.
+ *
+ * .. code-block:: c
+ *
+ *	struct some_state {
+ *		spinlock_t lock;
+ *		long *counter __pt_guarded_by(&lock);
+ *	};
+ */
+# define __pt_guarded_by(...)		__attribute__((pt_guarded_by(__VA_ARGS__)))
+
+/**
+ * context_guard_struct() - declare or define a context guard struct
+ * @name: struct name
+ *
+ * Helper to declare or define a struct type that is also a context guard.
+ *
+ * .. code-block:: c
+ *
+ *	context_guard_struct(my_handle) {
+ *		int foo;
+ *		long bar;
+ *	};
+ *
+ *	struct some_state {
+ *		...
+ *	};
+ *	// ... declared elsewhere ...
+ *	context_guard_struct(some_state);
+ *
+ * Note: The implementation defines several helper functions that can acquire
+ * and release the context guard.
+ */
+# define context_guard_struct(name, ...)								\
+	struct __ctx_guard_type(name) __VA_ARGS__ name;							\
+	static __always_inline void __acquire_ctx_guard(const struct name *var)				\
+		__attribute__((overloadable)) __no_context_analysis __acquires_ctx_guard(var) { }	\
+	static __always_inline void __acquire_shared_ctx_guard(const struct name *var)			\
+		__attribute__((overloadable)) __no_context_analysis __acquires_shared_ctx_guard(var) { } \
+	static __always_inline bool __try_acquire_ctx_guard(const struct name *var, bool ret)		\
+		__attribute__((overloadable)) __no_context_analysis __try_acquires_ctx_guard(1, var)	\
+	{ return ret; }											\
+	static __always_inline bool __try_acquire_shared_ctx_guard(const struct name *var, bool ret)	\
+		__attribute__((overloadable)) __no_context_analysis __try_acquires_shared_ctx_guard(1, var) \
+	{ return ret; }											\
+	static __always_inline void __release_ctx_guard(const struct name *var)				\
+		__attribute__((overloadable)) __no_context_analysis __releases_ctx_guard(var) { }	\
+	static __always_inline void __release_shared_ctx_guard(const struct name *var)			\
+		__attribute__((overloadable)) __no_context_analysis __releases_shared_ctx_guard(var) { } \
+	static __always_inline void __assume_ctx_guard(const struct name *var)				\
+		__attribute__((overloadable)) __assumes_ctx_guard(var) { }				\
+	static __always_inline void __assume_shared_ctx_guard(const struct name *var)			\
+		__attribute__((overloadable)) __assumes_shared_ctx_guard(var) { }			\
+	struct name
+
+/**
+ * disable_context_analysis() - disables context analysis
+ *
+ * Disables context analysis. Must be paired with a later
+ * enable_context_analysis().
+ */
+# define disable_context_analysis()				\
+	__diag_push();						\
+	__diag_ignore_all("-Wunknown-warning-option", "")	\
+	__diag_ignore_all("-Wthread-safety", "")		\
+	__diag_ignore_all("-Wthread-safety-pointer", "")
+
+/**
+ * enable_context_analysis() - re-enables context analysis
+ *
+ * Re-enables context analysis. Must be paired with a prior
+ * disable_context_analysis().
+ */
+# define enable_context_analysis() __diag_pop()
+
+/**
+ * __no_context_analysis - function attribute, disables context analysis
+ *
+ * Function attribute denoting that context analysis is disabled for the
+ * whole function. Prefer use of `context_unsafe()` where possible.
+ */
+# define __no_context_analysis	__attribute__((no_thread_safety_analysis))
+
+#else /* !WARN_CONTEXT_ANALYSIS */
+
+# define __ctx_guard_type(name)
+# define __reentrant_ctx_guard
+# define __acquires_ctx_guard(...)
+# define __acquires_shared_ctx_guard(...)
+# define __try_acquires_ctx_guard(ret, var)
+# define __try_acquires_shared_ctx_guard(ret, var)
+# define __releases_ctx_guard(...)
+# define __releases_shared_ctx_guard(...)
+# define __assumes_ctx_guard(...)
+# define __assumes_shared_ctx_guard(...)
+# define __returns_ctx_guard(var)
+# define __guarded_by(...)
+# define __pt_guarded_by(...)
+# define __excludes_ctx_guard(...)
+# define __requires_ctx_guard(...)
+# define __requires_shared_ctx_guard(...)
+# define __acquire_ctx_guard(var)			do { } while (0)
+# define __acquire_shared_ctx_guard(var)		do { } while (0)
+# define __try_acquire_ctx_guard(var, ret)		(ret)
+# define __try_acquire_shared_ctx_guard(var, ret)	(ret)
+# define __release_ctx_guard(var)			do { } while (0)
+# define __release_shared_ctx_guard(var)		do { } while (0)
+# define __assume_ctx_guard(var)			do { (void)(var); } while (0)
+# define __assume_shared_ctx_guard(var)			do { (void)(var); } while (0)
+# define context_guard_struct(name, ...)		struct __VA_ARGS__ name
+# define disable_context_analysis()
+# define enable_context_analysis()
+# define __no_context_analysis
+
+#endif /* WARN_CONTEXT_ANALYSIS */
+
+/**
+ * context_unsafe() - disable context checking for contained code
+ *
+ * Disables context checking for contained statements or expression.
+ *
+ * .. code-block:: c
+ *
+ *	struct some_data {
+ *		spinlock_t lock;
+ *		int counter __guarded_by(&lock);
+ *	};
+ *
+ *	int foo(struct some_data *d)
+ *	{
+ *		// ...
+ *		// other code that is still checked ...
+ *		// ...
+ *		return context_unsafe(d->counter);
+ *	}
+ */
+#define context_unsafe(...)		\
+({					\
+	disable_context_analysis();	\
+	__VA_ARGS__;			\
+	enable_context_analysis()	\
+})
+
+/**
+ * __context_unsafe() - function attribute, disable context checking
+ * @comment: comment explaining why opt-out is safe
+ *
+ * Function attribute denoting that context analysis is disabled for the
+ * whole function. Forces adding an inline comment as argument.
+ */
+#define __context_unsafe(comment) __no_context_analysis
+
+/**
+ * context_unsafe_alias() - helper to insert a context guard "alias barrier"
+ * @p: pointer aliasing a context guard or object containing context guards
+ *
+ * No-op function that acts as a "context guard alias barrier", where the
+ * analysis rightfully detects that we're switching aliases, but the switch is
+ * considered safe but beyond the analysis reasoning abilities.
+ *
+ * This should be inserted before the first use of such an alias.
+ *
+ * Implementation Note: The compiler ignores aliases that may be reassigned but
+ * their value cannot be determined (e.g. when passing a non-const pointer to an
+ * alias as a function argument).
+ */
+#define context_unsafe_alias(p) _context_unsafe_alias((void **)&(p))
+static inline void _context_unsafe_alias(void **p) { }
+
+/**
+ * token_context_guard() - declare an abstract global context guard instance
+ * @name: token context guard name
+ *
+ * Helper that declares an abstract global context guard instance @name, but not
+ * backed by a real data structure (linker error if accidentally referenced).
+ * The type name is `__ctx_guard_@name`.
+ */
+#define token_context_guard(name, ...)					\
+	context_guard_struct(__ctx_guard_##name, ##__VA_ARGS__) {};	\
+	extern const struct __ctx_guard_##name *name
+
+/**
+ * token_context_guard_instance() - declare another instance of a global context guard
+ * @ctx: token context guard previously declared with token_context_guard()
+ * @name: name of additional global context guard instance
+ *
+ * Helper that declares an additional instance @name of the same token context
+ * guard class @ctx. This is helpful where multiple related token contexts are
+ * declared, to allow using the same underlying type (`__ctx_guard_@ctx`) as
+ * function arguments.
+ */
+#define token_context_guard_instance(ctx, name)		\
+	extern const struct __ctx_guard_##ctx *name
+
+/*
+ * Common keywords for static context analysis. Both Clang's "capability
+ * analysis" and Sparse's "context tracking" are currently supported.
+ */
 #ifdef __CHECKER__
 
 /* Sparse context/lock checking support. */
 # define __must_hold(x)		__attribute__((context(x,1,1)))
+# define __must_not_hold(x)
 # define __acquires(x)		__attribute__((context(x,0,1)))
 # define __cond_acquires(x)	__attribute__((context(x,0,-1)))
 # define __releases(x)		__attribute__((context(x,1,0)))
 # define __acquire(x)		__context__(x,1)
 # define __release(x)		__context__(x,-1)
 # define __cond_lock(x, c)	((c) ? ({ __acquire(x); 1; }) : 0)
+/* For Sparse, there's no distinction between exclusive and shared locks. */
+# define __must_hold_shared	__must_hold
+# define __acquires_shared	__acquires
+# define __cond_acquires_shared __cond_acquires
+# define __releases_shared	__releases
+# define __acquire_shared	__acquire
+# define __release_shared	__release
+# define __cond_lock_shared	__cond_acquire
 
 #else /* !__CHECKER__ */
 
-# define __must_hold(x)
-# define __acquires(x)
-# define __cond_acquires(x)
-# define __releases(x)
-# define __acquire(x)		(void)0
-# define __release(x)		(void)0
-# define __cond_lock(x, c)	(c)
+/**
+ * __must_hold() - function attribute, caller must hold exclusive context guard
+ * @x: context guard instance pointer
+ *
+ * Function attribute declaring that the caller must hold the given context
+ * guard instance @x exclusively.
+ */
+# define __must_hold(x)		__requires_ctx_guard(x)
+
+/**
+ * __must_not_hold() - function attribute, caller must not hold context guard
+ * @x: context guard instance pointer
+ *
+ * Function attribute declaring that the caller must not hold the given context
+ * guard instance @x.
+ */
+# define __must_not_hold(x)	__excludes_ctx_guard(x)
+
+/**
+ * __acquires() - function attribute, function acquires context guard exclusively
+ * @x: context guard instance pointer
+ *
+ * Function attribute declaring that the function acquires the given context
+ * guard instance @x exclusively, but does not release it.
+ */
+# define __acquires(x)		__acquires_ctx_guard(x)
+
+/**
+ * __cond_acquires() - function attribute, function conditionally
+ *                     acquires a context guard exclusively
+ * @x: context guard instance pointer
+ *
+ * Function attribute declaring that the function conditionally acquires the
+ * given context guard instance @x exclusively, but does not release it.
+ */
+# define __cond_acquires(x)	__try_acquires_ctx_guard(1, x)
+
+/**
+ * __releases() - function attribute, function releases a context guard exclusively
+ * @x: context guard instance pointer
+ *
+ * Function attribute declaring that the function releases the given context
+ * guard instance @x exclusively. The associated context must be active on
+ * entry.
+ */
+# define __releases(x)		__releases_ctx_guard(x)
+
+/**
+ * __acquire() - function to acquire context guard exclusively
+ * @x: context guard instance pointer
+ *
+ * No-op function that acquires the given context guard instance @x exclusively.
+ */
+# define __acquire(x)		__acquire_ctx_guard(x)
+
+/**
+ * __release() - function to release context guard exclusively
+ * @x: context guard instance pointer
+ *
+ * No-op function that releases the given context guard instance @x.
+ */
+# define __release(x)		__release_ctx_guard(x)
+
+/**
+ * __cond_lock() - function that conditionally acquires a context guard
+ *                 exclusively
+ * @x: context guard instance pinter
+ * @c: boolean expression
+ *
+ * Return: result of @c
+ *
+ * No-op function that conditionally acquires context guard instance @x
+ * exclusively, if the boolean expression @c is true. The result of @c is the
+ * return value; for example:
+ *
+ * .. code-block:: c
+ *
+ *	#define spin_trylock(l) __cond_lock(&lock, _spin_trylock(&lock))
+ */
+# define __cond_lock(x, c)	__try_acquire_ctx_guard(x, c)
+
+/**
+ * __must_hold_shared() - function attribute, caller must hold shared context guard
+ * @x: context guard instance pointer
+ *
+ * Function attribute declaring that the caller must hold the given context
+ * guard instance @x with shared access.
+ */
+# define __must_hold_shared(x)	__requires_shared_ctx_guard(x)
+
+/**
+ * __acquires_shared() - function attribute, function acquires context guard shared
+ * @x: context guard instance pointer
+ *
+ * Function attribute declaring that the function acquires the given
+ * context guard instance @x with shared access, but does not release it.
+ */
+# define __acquires_shared(x)	__acquires_shared_ctx_guard(x)
+
+/**
+ * __cond_acquires_shared() - function attribute, function conditionally
+ *                            acquires a context guard shared
+ * @x: context guard instance pointer
+ *
+ * Function attribute declaring that the function conditionally acquires the
+ * given context guard instance @x with shared access, but does not release it.
+ */
+# define __cond_acquires_shared(x) __try_acquires_shared_ctx_guard(1, x)
+
+/**
+ * __releases_shared() - function attribute, function releases a
+ *                       context guard shared
+ * @x: context guard instance pointer
+ *
+ * Function attribute declaring that the function releases the given context
+ * guard instance @x with shared access. The associated context must be active
+ * on entry.
+ */
+# define __releases_shared(x)	__releases_shared_ctx_guard(x)
+
+/**
+ * __acquire_shared() - function to acquire context guard shared
+ * @x: context guard instance pointer
+ *
+ * No-op function that acquires the given context guard instance @x with shared
+ * access.
+ */
+# define __acquire_shared(x)	__acquire_shared_ctx_guard(x)
+
+/**
+ * __release_shared() - function to release context guard shared
+ * @x: context guard instance pointer
+ *
+ * No-op function that releases the given context guard instance @x with shared
+ * access.
+ */
+# define __release_shared(x)	__release_shared_ctx_guard(x)
+
+/**
+ * __cond_lock_shared() - function that conditionally acquires a context guard shared
+ * @x: context guard instance pinter
+ * @c: boolean expression
+ *
+ * Return: result of @c
+ *
+ * No-op function that conditionally acquires context guard instance @x with
+ * shared access, if the boolean expression @c is true. The result of @c is the
+ * return value.
+ */
+# define __cond_lock_shared(x, c) __try_acquire_shared_ctx_guard(x, c)
 
 #endif /* __CHECKER__ */
 
+/**
+ * __acquire_ret() - helper to acquire context guard of return value
+ * @call: call expression
+ * @ret_expr: acquire expression that uses __ret
+ */
+#define __acquire_ret(call, ret_expr)		\
+	({					\
+		__auto_type __ret = call;	\
+		__acquire(ret_expr);		\
+		__ret;				\
+	})
+
+/**
+ * __acquire_shared_ret() - helper to acquire context guard shared of return value
+ * @call: call expression
+ * @ret_expr: acquire shared expression that uses __ret
+ */
+#define __acquire_shared_ret(call, ret_expr)	\
+	({					\
+		__auto_type __ret = call;	\
+		__acquire_shared(ret_expr);	\
+		__ret;				\
+	})
+
+/*
+ * Attributes to mark functions returning acquired context guards.
+ *
+ * This is purely cosmetic to help readability, and should be used with the
+ * above macros as follows:
+ *
+ *   struct foo { spinlock_t lock; ... };
+ *   ...
+ *   #define myfunc(...) __acquire_ret(_myfunc(__VA_ARGS__), &__ret->lock)
+ *   struct foo *_myfunc(int bar) __acquires_ret;
+ *   ...
+ */
+#define __acquires_ret		__no_context_analysis
+#define __acquires_shared_ret	__no_context_analysis
+
 #endif /* _LINUX_COMPILER_CONTEXT_ANALYSIS_H */
diff --git a/lib/Kconfig.debug b/lib/Kconfig.debug
index 3034e294d50d..696e2a148a15 100644
--- a/lib/Kconfig.debug
+++ b/lib/Kconfig.debug
@@ -613,6 +613,36 @@ config DEBUG_FORCE_WEAK_PER_CPU
 	  To ensure that generic code follows the above rules, this
 	  option forces all percpu variables to be defined as weak.
 
+config WARN_CONTEXT_ANALYSIS
+	bool "Compiler context-analysis warnings"
+	depends on CC_IS_CLANG && CLANG_VERSION >= 220000
+	# Branch profiling re-defines "if", which messes with the compiler's
+	# ability to analyze __cond_acquires(..), resulting in false positives.
+	depends on !TRACE_BRANCH_PROFILING
+	default y
+	help
+	  Context Analysis is a language extension, which enables statically
+	  checking that required contexts are active (or inactive) by acquiring
+	  and releasing user-definable "context guards".
+
+	  Clang's name of the feature is "Thread Safety Analysis". Requires
+	  Clang 22 or later.
+
+	  Produces warnings by default. Select CONFIG_WERROR if you wish to
+	  turn these warnings into errors.
+
+	  For more details, see Documentation/dev-tools/context-analysis.rst.
+
+config WARN_CONTEXT_ANALYSIS_ALL
+	bool "Enable context analysis for all source files"
+	depends on WARN_CONTEXT_ANALYSIS
+	depends on EXPERT && !COMPILE_TEST
+	help
+	  Enable tree-wide context analysis. This is likely to produce a
+	  large number of false positives - enable at your own risk.
+
+	  If unsure, say N.
+
 endmenu # "Compiler options"
 
 menu "Generic Kernel Debugging Instruments"
diff --git a/scripts/Makefile.context-analysis b/scripts/Makefile.context-analysis
new file mode 100644
index 000000000000..70549f7fae1a
--- /dev/null
+++ b/scripts/Makefile.context-analysis
@@ -0,0 +1,7 @@
+# SPDX-License-Identifier: GPL-2.0
+
+context-analysis-cflags := -DWARN_CONTEXT_ANALYSIS		\
+	-fexperimental-late-parse-attributes -Wthread-safety	\
+	-Wthread-safety-pointer -Wthread-safety-beta
+
+export CFLAGS_CONTEXT_ANALYSIS := $(context-analysis-cflags)
diff --git a/scripts/Makefile.lib b/scripts/Makefile.lib
index 1d581ba5df66..aa45b3273f7c 100644
--- a/scripts/Makefile.lib
+++ b/scripts/Makefile.lib
@@ -105,6 +105,16 @@ _c_flags += $(if $(patsubst n%,, \
 	-D__KCSAN_INSTRUMENT_BARRIERS__)
 endif
 
+#
+# Enable context analysis flags only where explicitly opted in.
+# (depends on variables CONTEXT_ANALYSIS_obj.o, CONTEXT_ANALYSIS)
+#
+ifeq ($(CONFIG_WARN_CONTEXT_ANALYSIS),y)
+_c_flags += $(if $(patsubst n%,, \
+		$(CONTEXT_ANALYSIS_$(target-stem).o)$(CONTEXT_ANALYSIS)$(if $(is-kernel-object),$(CONFIG_WARN_CONTEXT_ANALYSIS_ALL))), \
+		$(CFLAGS_CONTEXT_ANALYSIS))
+endif
+
 #
 # Enable AutoFDO build flags except some files or directories we don't want to
 # enable (depends on variables AUTOFDO_PROFILE_obj.o and AUTOFDO_PROFILE).
-- 
2.52.0.rc1.455.g30608eb744-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251120145835.3833031-4-elver%40google.com.
