Return-Path: <kasan-dev+bncBC7OBJGL2MHBBIXGSXFAMGQEGTLPX6Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33a.google.com (mail-wm1-x33a.google.com [IPv6:2a00:1450:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id 49637CD093E
	for <lists+kasan-dev@lfdr.de>; Fri, 19 Dec 2025 16:45:40 +0100 (CET)
Received: by mail-wm1-x33a.google.com with SMTP id 5b1f17b1804b1-477a11d9e67sf9454735e9.2
        for <lists+kasan-dev@lfdr.de>; Fri, 19 Dec 2025 07:45:40 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1766159139; cv=pass;
        d=google.com; s=arc-20240605;
        b=j4/oTmpWFtdZtakZ9ng9KD4fm10QIQz5XZKXn6mCwNISyqB+hETIH7HCXOvYIwwP3K
         luK5U0inxwDV/LV4RWWaOcJBdpKcMkhhlY79CzMMI8VeCahCRIEuL0KXr2jMZmK/ryBQ
         Zo9MOBSUG5uts57aKLtV/PEUrp9gDe64WfSxuGig4b+bp7EhZiF0yzB14FT/BztU2UZX
         rNO3bmJcosZVZKuGQCbhf8n1V9TNKo2ajrHyt0734J4oo8rTDbuNa+kc/rRJK4h2wrg8
         R8ENb0+4cgRzPOqKRv4HQr6B1+zJVZhZBzdxci+esh1lsEulS9FYNPQQt355XrpPB95V
         1kJg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=uDeQJXzz2QWMRh9FymRr7J14vgn1DcCMZrCG9y76usk=;
        fh=A8EbxMN+5fVdZ+H8OYU6I0Fxo3C5hc38KKtWedPSiXE=;
        b=h+PZZ4VoPb5e5D8SaHmXSYW3R51x0GEe6DGEaBzkIsWI297f/Zu9LZMxGy8BGyN99j
         GdRuMjU/vGlfwprNeNFfHVvF1OMh1q3CxUNFmq+ZAi5PvCkFJcKM7SIxcd24t2EkuTkL
         BdBqZFCHBgYImjylgAH/XQJoDLe5BpvQqqsnheP9+XR5jP+ihIl1IGsJE61UeU9Tx5Dh
         h+ci+U+NujoXcLxiysZZ6pAsmQofagLfM2Jcq+B84mMPSm6IJkFEFoCfLlTWa1rVuvxz
         +gtxtjOIpRiEzmB62CD6XSgEKF3y2qaRU7maB3YsITGOdsYrCTdIZ1A32TdIsafae9Vr
         5ITw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=xEvxA1O7;
       spf=pass (google.com: domain of 3h3nfaqukcwwovfobqyyqvo.mywukckx-nofqyyqvoqbyezc.myw@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3H3NFaQUKCWwOVfObQYYQVO.MYWUKcKX-NOfQYYQVOQbYeZc.MYW@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1766159139; x=1766763939; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=uDeQJXzz2QWMRh9FymRr7J14vgn1DcCMZrCG9y76usk=;
        b=awNjzgc4clN4brlrjM7E4NZcuuXb/urYfMZqWQ3vl/Tz1iMQguvfxSh6T3TktRiZcF
         N9XaAtJkF+NBvqpjtblA8v14WEkbG1aQOj/UHdF7ntcpc5rYzSTPzowKudHZEwJp71fu
         def6fvCeouTLVoWqQP1IQL2ffRRSNeOZ6wg9cg5qbZRRJ3znftxG9lf04GBS863z7zlf
         vgRMh/sgxl0U4vwgqgXHySPO3f7jjD+KKTZaKJng4P3oaok5/1VV6vIBn9xOUzW0ta+8
         SycsIM45a8puqsPaPJACgNGD/DbH8qsXZ2AHlOCHiECu8KNy/Quw3lg23NO/hgfeDKGG
         DwGQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1766159139; x=1766763939;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=uDeQJXzz2QWMRh9FymRr7J14vgn1DcCMZrCG9y76usk=;
        b=XNkTcNL8ryUTDeUS6aDzSf2PHLf19kyU+YDa0aesQuuhZ4/BkJNOEPutPfNwc/RGHl
         4Kuk3F/oGs0+njorSz6ohGBSNrmfmVTSjZBLbnMJWIHuHL8Rzgo039SOpxffNcYlNajt
         ezXERBxuBdk5l1/DgP0t09VE8yd4mMzrr9kbZnnCtnm3Go74YJe6vL2EYssh1yzikgpd
         X5t1b1AAIP62WWBVkHhjnFuxvg4Dd8WJtjgYaEkzdIiH+UNWEiHIqbAw0ZfR8O+hEOTA
         TyVBZia/QrXN7Jch/Zt+UW2Fuoh9ZmtV630mRJSK0fSMXYDi9ztu7UNwFn44OMrdVQau
         rOpw==
X-Forwarded-Encrypted: i=2; AJvYcCVgrVIbhf7GSedoYy0eET8FG2XKW1CoN18sZPKImVl38oaEviQis70b+6vVBWdMwgAIkvr4EQ==@lfdr.de
X-Gm-Message-State: AOJu0YzBcNpC+immCAe38dn2GWm7n1j9sV9WH0lrGqybFtCU29EBTIxU
	Y6mV3p8DJonTHugqj98eDzfIattxSi4IHhURlAsU/MiUNIn0b+PSxgtI
X-Google-Smtp-Source: AGHT+IF3Vah3tQZ7g3M19PUaXBzC8vpDUj/qtHm5IgS132BLrvUtd/DfQUUV5klnpbGN2ZtwtptuyQ==
X-Received: by 2002:a05:600c:858e:b0:47a:81b7:9a20 with SMTP id 5b1f17b1804b1-47d1c62930dmr18861955e9.9.1766159139552;
        Fri, 19 Dec 2025 07:45:39 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWYYhXaKRuFLQYmUgTGTDrotZFQBXQmrK1ZjBCn9C/jhiw=="
Received: by 2002:a05:600c:4ece:b0:477:5a45:da9e with SMTP id
 5b1f17b1804b1-47a8ea108f3ls35435385e9.0.-pod-prod-04-eu; Fri, 19 Dec 2025
 07:45:36 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCU01sBRyV89uv6+Tp9ZSx/4x9I27RB1TufacVotR3Gzqt4pIv/ar96KGcky4/WxwX5S4LJhTy71grY=@googlegroups.com
X-Received: by 2002:a05:600d:8:b0:477:5897:a0c4 with SMTP id 5b1f17b1804b1-47d1c13fcfdmr18918745e9.4.1766159136553;
        Fri, 19 Dec 2025 07:45:36 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1766159136; cv=none;
        d=google.com; s=arc-20240605;
        b=jC/6D0ZJol8R0QI1/xcQ5xdL2CyTdkVra4xQV0YHmH5ZmRbUbrTokg2/E4dRtH2EOp
         WAOhINf5ZUkC2qGNgPnJ+gOZIbADghmR8yrX2xR6JVKZKZLQFcspJmXQZ1F7owDakleU
         crhTyYJx9Lci6y0sVJ1THgi4bFUadCx3gBOiscSF/VgFXK20rg23e+PcwJj+dSoit/Pq
         wOz/H8kWauRuXnH4mBx8I4O7JWWlgo9/LgAerAo+ECPu70xAOMrUkX2wBEnDB0ffWwQ3
         r+SGlHeHD/P8CxGlnsyorco45QsfmIWW4gNdlDvB1lowdWWRGuX4tjwJ1Giv80f7lXzX
         XhfQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=wNypD57EGX2MX8ivTIXP0XbqOR/mFQo2ssZAJ4O2zXU=;
        fh=LIsISbMr9YsGjPBebXroLcbR+e+CacSOx7beCW53miE=;
        b=afiw7QcaF8giu2hKisOq/0PLeV9I73LGfLVeMi3nFDxdXX6V02BiyQyY+LAsV4dUAv
         S3CC/3Pd5YMKe9gX/lqBe16BwxJ+GiXSsd+mXkn7YfuFw8EJH2lvT7DrVbkqTEgASotP
         dWAtf8Q23Xy6voeeJxILw+v1OJIyHnNpPBJbieBmSyYnzR2gJyZ/e8Ss47NPsj4IR0En
         vgB9ccTfWVcXMwdA5gapX5nkB3IikhMQRz3eKzYOM+KTNp3wbEhR+TYHs1n0yGJD5wVT
         Kcxg08ZHbX5jdcshqB8jmc08hw/dvtRJvBFsdXOZLmxRFMUQSXkvKfspQjgz496majyZ
         JIjw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=xEvxA1O7;
       spf=pass (google.com: domain of 3h3nfaqukcwwovfobqyyqvo.mywukckx-nofqyyqvoqbyezc.myw@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3H3NFaQUKCWwOVfObQYYQVO.MYWUKcKX-NOfQYYQVOQbYeZc.MYW@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x34a.google.com (mail-wm1-x34a.google.com. [2a00:1450:4864:20::34a])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-47be3a7801fsi687305e9.3.2025.12.19.07.45.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 19 Dec 2025 07:45:36 -0800 (PST)
Received-SPF: pass (google.com: domain of 3h3nfaqukcwwovfobqyyqvo.mywukckx-nofqyyqvoqbyezc.myw@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) client-ip=2a00:1450:4864:20::34a;
Received: by mail-wm1-x34a.google.com with SMTP id 5b1f17b1804b1-47910af0c8bso15817915e9.2
        for <kasan-dev@googlegroups.com>; Fri, 19 Dec 2025 07:45:36 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCUbv6pEYepuQ4JWZ7a5QILj27JP7xZZoUTINKXG40KeEKCr7p0ckhjDyIEvD9dYvImvUdc8UigTs0s=@googlegroups.com
X-Received: from wmco28.prod.google.com ([2002:a05:600c:a31c:b0:477:9976:8214])
 (user=elver job=prod-delivery.src-stubby-dispatcher) by 2002:a05:600c:828c:b0:479:3a87:2092
 with SMTP id 5b1f17b1804b1-47d19598e86mr23981475e9.36.1766159135626; Fri, 19
 Dec 2025 07:45:35 -0800 (PST)
Date: Fri, 19 Dec 2025 16:39:53 +0100
In-Reply-To: <20251219154418.3592607-1-elver@google.com>
Mime-Version: 1.0
References: <20251219154418.3592607-1-elver@google.com>
X-Mailer: git-send-email 2.52.0.322.g1dd061c0dc-goog
Message-ID: <20251219154418.3592607-5-elver@google.com>
Subject: [PATCH v5 04/36] Documentation: Add documentation for Compiler-Based
 Context Analysis
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
 header.i=@google.com header.s=20230601 header.b=xEvxA1O7;       spf=pass
 (google.com: domain of 3h3nfaqukcwwovfobqyyqvo.mywukckx-nofqyyqvoqbyezc.myw@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3H3NFaQUKCWwOVfObQYYQVO.MYWUKcKX-NOfQYYQVOQbYeZc.MYW@flex--elver.bounces.google.com;
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

Adds documentation in Documentation/dev-tools/context-analysis.rst, and
adds it to the index.

Signed-off-by: Marco Elver <elver@google.com>
---
v5:
* Rename "context guard" -> "context lock".

v4:
* Rename capability -> context analysis.

v2:
* Remove cross-reference to Sparse, since we plan to remove Sparse
  support anyway.
* Mention __no_context_analysis should be avoided.
---
 Documentation/dev-tools/context-analysis.rst | 144 +++++++++++++++++++
 Documentation/dev-tools/index.rst            |   1 +
 2 files changed, 145 insertions(+)
 create mode 100644 Documentation/dev-tools/context-analysis.rst

diff --git a/Documentation/dev-tools/context-analysis.rst b/Documentation/dev-tools/context-analysis.rst
new file mode 100644
index 000000000000..47eb547eb716
--- /dev/null
+++ b/Documentation/dev-tools/context-analysis.rst
@@ -0,0 +1,144 @@
+.. SPDX-License-Identifier: GPL-2.0
+.. Copyright (C) 2025, Google LLC.
+
+.. _context-analysis:
+
+Compiler-Based Context Analysis
+===============================
+
+Context Analysis is a language extension, which enables statically checking
+that required contexts are active (or inactive) by acquiring and releasing
+user-definable "context locks". An obvious application is lock-safety checking
+for the kernel's various synchronization primitives (each of which represents a
+"context lock"), and checking that locking rules are not violated.
+
+The Clang compiler currently supports the full set of context analysis
+features. To enable for Clang, configure the kernel with::
+
+    CONFIG_WARN_CONTEXT_ANALYSIS=y
+
+The feature requires Clang 22 or later.
+
+The analysis is *opt-in by default*, and requires declaring which modules and
+subsystems should be analyzed in the respective `Makefile`::
+
+    CONTEXT_ANALYSIS_mymodule.o := y
+
+Or for all translation units in the directory::
+
+    CONTEXT_ANALYSIS := y
+
+It is possible to enable the analysis tree-wide, however, which will result in
+numerous false positive warnings currently and is *not* generally recommended::
+
+    CONFIG_WARN_CONTEXT_ANALYSIS_ALL=y
+
+Programming Model
+-----------------
+
+The below describes the programming model around using context lock types.
+
+.. note::
+   Enabling context analysis can be seen as enabling a dialect of Linux C with
+   a Context System. Some valid patterns involving complex control-flow are
+   constrained (such as conditional acquisition and later conditional release
+   in the same function).
+
+Context analysis is a way to specify permissibility of operations to depend on
+context locks being held (or not held). Typically we are interested in
+protecting data and code in a critical section by requiring a specific context
+to be active, for example by holding a specific lock. The analysis ensures that
+callers cannot perform an operation without the required context being active.
+
+Context locks are associated with named structs, along with functions that
+operate on struct instances to acquire and release the associated context lock.
+
+Context locks can be held either exclusively or shared. This mechanism allows
+assigning more precise privileges when a context is active, typically to
+distinguish where a thread may only read (shared) or also write (exclusive) to
+data guarded within a context.
+
+The set of contexts that are actually active in a given thread at a given point
+in program execution is a run-time concept. The static analysis works by
+calculating an approximation of that set, called the context environment. The
+context environment is calculated for every program point, and describes the
+set of contexts that are statically known to be active, or inactive, at that
+particular point. This environment is a conservative approximation of the full
+set of contexts that will actually be active in a thread at run-time.
+
+More details are also documented `here
+<https://clang.llvm.org/docs/ThreadSafetyAnalysis.html>`_.
+
+.. note::
+   Clang's analysis explicitly does not infer context locks acquired or
+   released by inline functions. It requires explicit annotations to (a) assert
+   that it's not a bug if a context lock is released or acquired, and (b) to
+   retain consistency between inline and non-inline function declarations.
+
+Supported Kernel Primitives
+~~~~~~~~~~~~~~~~~~~~~~~~~~~
+
+.. Currently the following synchronization primitives are supported:
+
+For context locks with an initialization function (e.g., `spin_lock_init()`),
+calling this function before initializing any guarded members or globals
+prevents the compiler from issuing warnings about unguarded initialization.
+
+Lockdep assertions, such as `lockdep_assert_held()`, inform the compiler's
+context analysis that the associated synchronization primitive is held after
+the assertion. This avoids false positives in complex control-flow scenarios
+and encourages the use of Lockdep where static analysis is limited. For
+example, this is useful when a function doesn't *always* require a lock, making
+`__must_hold()` inappropriate.
+
+Keywords
+~~~~~~~~
+
+.. kernel-doc:: include/linux/compiler-context-analysis.h
+   :identifiers: context_lock_struct
+                 token_context_lock token_context_lock_instance
+                 __guarded_by __pt_guarded_by
+                 __must_hold
+                 __must_not_hold
+                 __acquires
+                 __cond_acquires
+                 __releases
+                 __must_hold_shared
+                 __acquires_shared
+                 __cond_acquires_shared
+                 __releases_shared
+                 __acquire
+                 __release
+                 __cond_lock
+                 __acquire_shared
+                 __release_shared
+                 __cond_lock_shared
+                 __acquire_ret
+                 __acquire_shared_ret
+                 context_unsafe
+                 __context_unsafe
+                 disable_context_analysis enable_context_analysis
+
+.. note::
+   The function attribute `__no_context_analysis` is reserved for internal
+   implementation of context lock types, and should be avoided in normal code.
+
+Background
+----------
+
+Clang originally called the feature `Thread Safety Analysis
+<https://clang.llvm.org/docs/ThreadSafetyAnalysis.html>`_, with some keywords
+and documentation still using the thread-safety-analysis-only terminology. This
+was later changed and the feature became more flexible, gaining the ability to
+define custom "capabilities". Its foundations can be found in `Capability
+Systems <https://www.cs.cornell.edu/talc/papers/capabilities.pdf>`_, used to
+specify the permissibility of operations to depend on some "capability" being
+held (or not held).
+
+Because the feature is not just able to express capabilities related to
+synchronization primitives, and "capability" is already overloaded in the
+kernel, the naming chosen for the kernel departs from Clang's initial "Thread
+Safety" and "capability" nomenclature; we refer to the feature as "Context
+Analysis" to avoid confusion. The internal implementation still makes
+references to Clang's terminology in a few places, such as `-Wthread-safety`
+being the warning option that also still appears in diagnostic messages.
diff --git a/Documentation/dev-tools/index.rst b/Documentation/dev-tools/index.rst
index 4b8425e348ab..d864b3da4cc7 100644
--- a/Documentation/dev-tools/index.rst
+++ b/Documentation/dev-tools/index.rst
@@ -21,6 +21,7 @@ Documentation/process/debugging/index.rst
    checkpatch
    clang-format
    coccinelle
+   context-analysis
    sparse
    kcov
    gcov
-- 
2.52.0.322.g1dd061c0dc-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251219154418.3592607-5-elver%40google.com.
