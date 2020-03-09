Return-Path: <kasan-dev+bncBAABBPVGTLZQKGQE2HH7G7Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x537.google.com (mail-pg1-x537.google.com [IPv6:2607:f8b0:4864:20::537])
	by mail.lfdr.de (Postfix) with ESMTPS id 293D117E7E3
	for <lists+kasan-dev@lfdr.de>; Mon,  9 Mar 2020 20:04:32 +0100 (CET)
Received: by mail-pg1-x537.google.com with SMTP id m29sf7109399pgd.9
        for <lists+kasan-dev@lfdr.de>; Mon, 09 Mar 2020 12:04:32 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1583780671; cv=pass;
        d=google.com; s=arc-20160816;
        b=Yt7JhD1UM7QTZQf4v2yUc0WWF7zOnrLcz4jPFVsSjVw76mzxPJBW5OjPN9cLXgek+G
         YZZEks9cJ+Ry+VkuHYqKUvgraAUOUFBwV2rPLgbRVQLh5plZ8K7R7/NkxvqUsiSnOLV+
         AVVKWGIt8Hx7hR7DFeH31hX/cPT6gKP2omnySkISSApiiogc3DZUzI+YQye3isao6hpZ
         Z46MA6Ek0ByPpTuwTQISQEFzqKs0/9lUMmXpFv21rDS8ZZWcW+aOjJnb1/ZnGte7jPq+
         8xzJnm9yno2kCX3F6aDef9lbT+voynXy7+WZUjkb1tYW+/6U5BHqcd65H9o0XYLrq3RU
         gSUA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:references:in-reply-to:message-id
         :date:subject:cc:to:from:mime-version:sender:dkim-signature;
        bh=jPXe9qDlUFwfT/KsEi677nL31nW6Nq+fWSB5aH73xwQ=;
        b=H+DQjgza4QZ+3Pp4vWv8qJVP+FHyBPumwBVJFczaa8QJev3Ano7tr/kFcf4lyRu6uy
         E2ySGJV3YikV4QuCsb+KRIq9Zq3/DN0L4LasPz6b2013vYNk2AKaGI7D0jQ7qzxOsO3X
         a81R/+npUVw1GEii+q26GWoUELZM3LqkyEasKXZ+8jpnxBYGPXJvL+ChDaT77pM+aZLg
         gJ4r76iQsX9gnhED2h4OaTSmgMiRRjBMHaO39TqpiyM3VMyL0T/+/B7+zbFn1Tqc8e02
         sMo6p7XJ5nksSTlevP8wc7nGM9Jnw11Qq+XIxN+X88CkJ+YgYyxrWZcaBOb5NK7JUfO7
         vzLw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=ekbeaMqF;
       spf=pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=paulmck@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:from:to:cc:subject:date:message-id:in-reply-to
         :references:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=jPXe9qDlUFwfT/KsEi677nL31nW6Nq+fWSB5aH73xwQ=;
        b=Q/97pj+3wtDMfnqWN8FljZaBbGblzn+XOl4EZAcorWxQD5BRqes+jg5affBX3KNHnp
         dAW/JSSustxTbFEZ8rV3jT3oWB8V9XO6yfiIvdMU+PtXOHrUV+9Ep7XOMLjbkKu4a0cb
         kbM3D3JQbZms+4PpC1/0SWjH4DyTr2G/fnrAqDrIgk3Amn1+JF3EoqKdcsd78dDwyY4U
         f8QFslgZpOg5HtO7/0Xp4r2lqKJ0hjBKHet5wIJDNnB/1lHGcOo9eqS07HQ3YYjqLvR5
         7BWo8LTyNFNtcuk+X46Wp1hKB7Ryfwn5J0rVQ2u4AFXru3DQnRz/Fp/vtFAf3hDxZ2G3
         p2EQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:from:to:cc:subject:date
         :message-id:in-reply-to:references:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=jPXe9qDlUFwfT/KsEi677nL31nW6Nq+fWSB5aH73xwQ=;
        b=TIvAUOtaWidzet9KbUQe3huQFi0zUvuwZgA5PP7fDATyXklZdlqz2G8AwY6PuGJboA
         PgHOviRW07puPxgsJhgYeAjfTx4dTab6ZufAVaFo7lh2R+ueFcmjO8jDTrtOW5cYz+jP
         ll5BVSpxnM+pf7donfE76dPyTcXRDVWbp6Vn+SbpuNAiDiOxJSXag12O8XQMkjEgOFbI
         GqtD94XDz9WKMwhyZjL2CA1oNtud15WWv8vVtpu50yIO5U9QHzhbqKJCsxGFIwXJ9Sqe
         IsEr+7WCfWH4qt8+1JOn7bCsZj28/XuFxxA8uvaIu1329aHKwSGNrudrvTd3UAf3v3Y6
         b7ow==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANhLgQ2Wld+6izKK/kpf+fdc3kxUaszKfGefXLkvzwZpsvywc/2F40dr
	QXeS6CL3MqiNSYpP697FB0E=
X-Google-Smtp-Source: ADFU+vsQyxrdJN+mcEKv2QFl2w4OKY0NE3SJaUel5vxyxHUSV/WWotw2fhvPaFbYpQoxtuEA60gjMA==
X-Received: by 2002:a17:902:123:: with SMTP id 32mr17523337plb.38.1583780670718;
        Mon, 09 Mar 2020 12:04:30 -0700 (PDT)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:834a:: with SMTP id h71ls3937752pge.4.gmail; Mon, 09 Mar
 2020 12:04:30 -0700 (PDT)
X-Received: by 2002:aa7:9839:: with SMTP id q25mr684488pfl.2.1583780670257;
        Mon, 09 Mar 2020 12:04:30 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1583780670; cv=none;
        d=google.com; s=arc-20160816;
        b=QWEnwBCpU4tfEq8q4BgZGY2QieTk4gmXoScwVvnANCFVkTLimxjWNPSUQzVWCa3exQ
         bcJPwXqMqNcsueoRROBx79X5CPsLcGaoQDVA661EvD/OUHNN+rIjNiRo//bzyIVYetpy
         CTHW9WCkgcpMbPqfm2s3Nv+lRXb05cvq7aQlAB6YzhkQ1anwOlJ6T0QgpGNceQthVJOZ
         IDkxgB/yvTTXuhKTj6NfjaejQOPZNivsAnkFBspboDli8MQEqm+kTcfWCd6X7HC6j7dH
         kk0lmTgPW4o3GAIJZMNU8qSLGZGKC/Yi0upLIRYsFkc7yoMik6QtPfd2Vs9px1xRWVx6
         qTmg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=references:in-reply-to:message-id:date:subject:cc:to:from
         :dkim-signature;
        bh=VWGV3Oh2t4vg/yvSflJc31AFxSN6SLbjBjxVcgjRDbk=;
        b=DE2h+TT/6iT/K14xWUC6yUNPaIcTJ+yTC7YqX8cNfWMhwd/1TkoaH8XSQt6VcufxTH
         Q1izAHo3QR084Y0q0FdGSkEG6mMqWST5M44LxbNhy19B3Ox34RNoGZymQEYujdTtw9fh
         CaOJuiKjQbsgAVXIKsGujPG65C/ovZHVzZ+QrBVJ3oV6z4/LbSy9bs7QQU/FkftsA2nk
         N8JW29rJX/h1cV//s9w7VsfpaR9JW02suWweUAi8ZaqWCUZmmwVm+l4MtjITxhb7In1G
         sX6siIY/5YYePcg+hhhvjPCaS96JbcCrC8j+B7kM+8rfRDwzhcH4pmFRgL9IgRXgSKvC
         st6Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=ekbeaMqF;
       spf=pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=paulmck@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id hg11si29129pjb.2.2020.03.09.12.04.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 09 Mar 2020 12:04:30 -0700 (PDT)
Received-SPF: pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (50-39-105-78.bvtn.or.frontiernet.net [50.39.105.78])
	(using TLSv1.2 with cipher ECDHE-RSA-AES128-GCM-SHA256 (128/128 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id DBAF824670;
	Mon,  9 Mar 2020 19:04:29 +0000 (UTC)
From: paulmck@kernel.org
To: linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	kernel-team@fb.com,
	mingo@kernel.org
Cc: elver@google.com,
	andreyknvl@google.com,
	glider@google.com,
	dvyukov@google.com,
	cai@lca.pw,
	boqun.feng@gmail.com,
	"Paul E . McKenney" <paulmck@kernel.org>
Subject: [PATCH kcsan 31/32] kcsan: Update Documentation/dev-tools/kcsan.rst
Date: Mon,  9 Mar 2020 12:04:19 -0700
Message-Id: <20200309190420.6100-31-paulmck@kernel.org>
X-Mailer: git-send-email 2.9.5
In-Reply-To: <20200309190359.GA5822@paulmck-ThinkPad-P72>
References: <20200309190359.GA5822@paulmck-ThinkPad-P72>
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=ekbeaMqF;       spf=pass
 (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as
 permitted sender) smtp.mailfrom=paulmck@kernel.org;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=kernel.org
Content-Type: text/plain; charset="UTF-8"
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

From: Marco Elver <elver@google.com>

Extend and improve based on recent changes, and summarize important
bits that have been missing. Tested with "make htmldocs".

Signed-off-by: Marco Elver <elver@google.com>
Cc: Qian Cai <cai@lca.pw>
Signed-off-by: Paul E. McKenney <paulmck@kernel.org>
---
 Documentation/dev-tools/kcsan.rst | 227 ++++++++++++++++++++++++--------------
 1 file changed, 144 insertions(+), 83 deletions(-)

diff --git a/Documentation/dev-tools/kcsan.rst b/Documentation/dev-tools/kcsan.rst
index 65a0be5..52a5d6f 100644
--- a/Documentation/dev-tools/kcsan.rst
+++ b/Documentation/dev-tools/kcsan.rst
@@ -1,27 +1,22 @@
 The Kernel Concurrency Sanitizer (KCSAN)
 ========================================
 
-Overview
---------
-
-*Kernel Concurrency Sanitizer (KCSAN)* is a dynamic data race detector for
-kernel space. KCSAN is a sampling watchpoint-based data race detector. Key
-priorities in KCSAN's design are lack of false positives, scalability, and
-simplicity. More details can be found in `Implementation Details`_.
-
-KCSAN uses compile-time instrumentation to instrument memory accesses. KCSAN is
-supported in both GCC and Clang. With GCC it requires version 7.3.0 or later.
-With Clang it requires version 7.0.0 or later.
+The Kernel Concurrency Sanitizer (KCSAN) is a dynamic race detector, which
+relies on compile-time instrumentation, and uses a watchpoint-based sampling
+approach to detect races. KCSAN's primary purpose is to detect `data races`_.
 
 Usage
 -----
 
-To enable KCSAN configure kernel with::
+KCSAN is supported in both GCC and Clang. With GCC it requires version 7.3.0 or
+later. With Clang it requires version 7.0.0 or later.
+
+To enable KCSAN configure the kernel with::
 
     CONFIG_KCSAN = y
 
 KCSAN provides several other configuration options to customize behaviour (see
-their respective help text for more info).
+the respective help text in ``lib/Kconfig.kcsan`` for more info).
 
 Error reports
 ~~~~~~~~~~~~~
@@ -96,7 +91,8 @@ The other less common type of data race report looks like this::
 This report is generated where it was not possible to determine the other
 racing thread, but a race was inferred due to the data value of the watched
 memory location having changed. These can occur either due to missing
-instrumentation or e.g. DMA accesses.
+instrumentation or e.g. DMA accesses. These reports will only be generated if
+``CONFIG_KCSAN_REPORT_RACE_UNKNOWN_ORIGIN=y`` (selected by default).
 
 Selective analysis
 ~~~~~~~~~~~~~~~~~~
@@ -110,9 +106,26 @@ the below options are available:
   behaviour when encountering a data race is deemed safe.
 
 * Disabling data race detection for entire functions can be accomplished by
-  using the function attribute ``__no_kcsan`` (or ``__no_kcsan_or_inline`` for
-  ``__always_inline`` functions). To dynamically control for which functions
-  data races are reported, see the `debugfs`_ blacklist/whitelist feature.
+  using the function attribute ``__no_kcsan``::
+
+    __no_kcsan
+    void foo(void) {
+        ...
+
+  To dynamically limit for which functions to generate reports, see the
+  `DebugFS interface`_ blacklist/whitelist feature.
+
+  For ``__always_inline`` functions, replace ``__always_inline`` with
+  ``__no_kcsan_or_inline`` (which implies ``__always_inline``)::
+
+    static __no_kcsan_or_inline void foo(void) {
+        ...
+
+  Note: Older compiler versions (GCC < 9) also do not always honor the
+  ``__no_kcsan`` attribute on regular ``inline`` functions. If false positives
+  with these compilers cannot be tolerated, for small functions where
+  ``__always_inline`` would be appropriate, ``__no_kcsan_or_inline`` should be
+  preferred instead.
 
 * To disable data race detection for a particular compilation unit, add to the
   ``Makefile``::
@@ -124,13 +137,29 @@ the below options are available:
 
     KCSAN_SANITIZE := n
 
-debugfs
-~~~~~~~
+Furthermore, it is possible to tell KCSAN to show or hide entire classes of
+data races, depending on preferences. These can be changed via the following
+Kconfig options:
+
+* ``CONFIG_KCSAN_REPORT_VALUE_CHANGE_ONLY``: If enabled and a conflicting write
+  is observed via a watchpoint, but the data value of the memory location was
+  observed to remain unchanged, do not report the data race.
+
+* ``CONFIG_KCSAN_ASSUME_PLAIN_WRITES_ATOMIC``: Assume that plain aligned writes
+  up to word size are atomic by default. Assumes that such writes are not
+  subject to unsafe compiler optimizations resulting in data races. The option
+  causes KCSAN to not report data races due to conflicts where the only plain
+  accesses are aligned writes up to word size.
+
+DebugFS interface
+~~~~~~~~~~~~~~~~~
+
+The file ``/sys/kernel/debug/kcsan`` provides the following interface:
 
-* The file ``/sys/kernel/debug/kcsan`` can be read to get stats.
+* Reading ``/sys/kernel/debug/kcsan`` returns various runtime statistics.
 
-* KCSAN can be turned on or off by writing ``on`` or ``off`` to
-  ``/sys/kernel/debug/kcsan``.
+* Writing ``on`` or ``off`` to ``/sys/kernel/debug/kcsan`` allows turning KCSAN
+  on or off, respectively.
 
 * Writing ``!some_func_name`` to ``/sys/kernel/debug/kcsan`` adds
   ``some_func_name`` to the report filter list, which (by default) blacklists
@@ -142,91 +171,120 @@ debugfs
   can be used to silence frequently occurring data races; the whitelist feature
   can help with reproduction and testing of fixes.
 
+Tuning performance
+~~~~~~~~~~~~~~~~~~
+
+Core parameters that affect KCSAN's overall performance and bug detection
+ability are exposed as kernel command-line arguments whose defaults can also be
+changed via the corresponding Kconfig options.
+
+* ``kcsan.skip_watch`` (``CONFIG_KCSAN_SKIP_WATCH``): Number of per-CPU memory
+  operations to skip, before another watchpoint is set up. Setting up
+  watchpoints more frequently will result in the likelihood of races to be
+  observed to increase. This parameter has the most significant impact on
+  overall system performance and race detection ability.
+
+* ``kcsan.udelay_task`` (``CONFIG_KCSAN_UDELAY_TASK``): For tasks, the
+  microsecond delay to stall execution after a watchpoint has been set up.
+  Larger values result in the window in which we may observe a race to
+  increase.
+
+* ``kcsan.udelay_interrupt`` (``CONFIG_KCSAN_UDELAY_INTERRUPT``): For
+  interrupts, the microsecond delay to stall execution after a watchpoint has
+  been set up. Interrupts have tighter latency requirements, and their delay
+  should generally be smaller than the one chosen for tasks.
+
+They may be tweaked at runtime via ``/sys/module/kcsan/parameters/``.
+
 Data Races
 ----------
 
-Informally, two operations *conflict* if they access the same memory location,
-and at least one of them is a write operation. In an execution, two memory
-operations from different threads form a **data race** if they *conflict*, at
-least one of them is a *plain access* (non-atomic), and they are *unordered* in
-the "happens-before" order according to the `LKMM
-<../../tools/memory-model/Documentation/explanation.txt>`_.
+In an execution, two memory accesses form a *data race* if they *conflict*,
+they happen concurrently in different threads, and at least one of them is a
+*plain access*; they *conflict* if both access the same memory location, and at
+least one is a write. For a more thorough discussion and definition, see `"Plain
+Accesses and Data Races" in the LKMM`_.
+
+.. _"Plain Accesses and Data Races" in the LKMM: https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/tools/memory-model/Documentation/explanation.txt#n1922
 
-Relationship with the Linux Kernel Memory Model (LKMM)
-~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
+Relationship with the Linux-Kernel Memory Consistency Model (LKMM)
+~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 
 The LKMM defines the propagation and ordering rules of various memory
 operations, which gives developers the ability to reason about concurrent code.
 Ultimately this allows to determine the possible executions of concurrent code,
 and if that code is free from data races.
 
-KCSAN is aware of *atomic* accesses (``READ_ONCE``, ``WRITE_ONCE``,
-``atomic_*``, etc.), but is oblivious of any ordering guarantees. In other
-words, KCSAN assumes that as long as a plain access is not observed to race
-with another conflicting access, memory operations are correctly ordered.
+KCSAN is aware of *marked atomic operations* (``READ_ONCE``, ``WRITE_ONCE``,
+``atomic_*``, etc.), but is oblivious of any ordering guarantees and simply
+assumes that memory barriers are placed correctly. In other words, KCSAN
+assumes that as long as a plain access is not observed to race with another
+conflicting access, memory operations are correctly ordered.
 
 This means that KCSAN will not report *potential* data races due to missing
-memory ordering. If, however, missing memory ordering (that is observable with
-a particular compiler and architecture) leads to an observable data race (e.g.
-entering a critical section erroneously), KCSAN would report the resulting
-data race.
-
-Race conditions vs. data races
-~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
-
-Race conditions are logic bugs, where unexpected interleaving of racing
-concurrent operations result in an erroneous state.
-
-Data races on the other hand are defined at the *memory model/language level*.
-Many data races are also harmful race conditions, which a tool like KCSAN
-reports!  However, not all data races are race conditions and vice-versa.
-KCSAN's intent is to report data races according to the LKMM. A data race
-detector can only work at the memory model/language level.
-
-Deeper analysis, to find high-level race conditions only, requires conveying
-the intended kernel logic to a tool. This requires (1) the developer writing a
-specification or model of their code, and then (2) the tool verifying that the
-implementation matches. This has been done for small bits of code using model
-checkers and other formal methods, but does not scale to the level of what can
-be covered with a dynamic analysis based data race detector such as KCSAN.
-
-For reasons outlined in this `article <https://lwn.net/Articles/793253/>`_,
-data races can be much more subtle, but can cause no less harm than high-level
-race conditions.
+memory ordering. Developers should therefore carefully consider the required
+memory ordering requirements that remain unchecked. If, however, missing
+memory ordering (that is observable with a particular compiler and
+architecture) leads to an observable data race (e.g. entering a critical
+section erroneously), KCSAN would report the resulting data race.
+
+Race Detection Beyond Data Races
+--------------------------------
+
+For code with complex concurrency design, race-condition bugs may not always
+manifest as data races. Race conditions occur if concurrently executing
+operations result in unexpected system behaviour. On the other hand, data races
+are defined at the C-language level. The following macros can be used to check
+properties of concurrent code where bugs would not manifest as data races.
+
+.. kernel-doc:: include/linux/kcsan-checks.h
+    :functions: ASSERT_EXCLUSIVE_WRITER ASSERT_EXCLUSIVE_ACCESS
+                ASSERT_EXCLUSIVE_BITS
 
 Implementation Details
 ----------------------
 
-The general approach is inspired by `DataCollider
+KCSAN relies on observing that two accesses happen concurrently. Crucially, we
+want to (a) increase the chances of observing races (especially for races that
+manifest rarely), and (b) be able to actually observe them. We can accomplish
+(a) by injecting various delays, and (b) by using address watchpoints (or
+breakpoints).
+
+If we deliberately stall a memory access, while we have a watchpoint for its
+address set up, and then observe the watchpoint to fire, two accesses to the
+same address just raced. Using hardware watchpoints, this is the approach taken
+in `DataCollider
 <http://usenix.org/legacy/events/osdi10/tech/full_papers/Erickson.pdf>`_.
 Unlike DataCollider, KCSAN does not use hardware watchpoints, but instead
-relies on compiler instrumentation. Watchpoints are implemented using an
-efficient encoding that stores access type, size, and address in a long; the
-benefits of using "soft watchpoints" are portability and greater flexibility in
-limiting which accesses trigger a watchpoint.
+relies on compiler instrumentation and "soft watchpoints".
 
-More specifically, KCSAN requires instrumenting plain (unmarked, non-atomic)
-memory operations; for each instrumented plain access:
+In KCSAN, watchpoints are implemented using an efficient encoding that stores
+access type, size, and address in a long; the benefits of using "soft
+watchpoints" are portability and greater flexibility. KCSAN then relies on the
+compiler instrumenting plain accesses. For each instrumented plain access:
 
 1. Check if a matching watchpoint exists; if yes, and at least one access is a
    write, then we encountered a racing access.
 
 2. Periodically, if no matching watchpoint exists, set up a watchpoint and
-   stall for a small delay.
+   stall for a small randomized delay.
 
 3. Also check the data value before the delay, and re-check the data value
    after delay; if the values mismatch, we infer a race of unknown origin.
 
-To detect data races between plain and atomic memory operations, KCSAN also
-annotates atomic accesses, but only to check if a watchpoint exists
-(``kcsan_check_atomic_*``); i.e.  KCSAN never sets up a watchpoint on atomic
-accesses.
+To detect data races between plain and marked accesses, KCSAN also annotates
+marked accesses, but only to check if a watchpoint exists; i.e. KCSAN never
+sets up a watchpoint on marked accesses. By never setting up watchpoints for
+marked operations, if all accesses to a variable that is accessed concurrently
+are properly marked, KCSAN will never trigger a watchpoint and therefore never
+report the accesses.
 
 Key Properties
 ~~~~~~~~~~~~~~
 
-1. **Memory Overhead:**  The current implementation uses a small array of longs
-   to encode watchpoint information, which is negligible.
+1. **Memory Overhead:**  The overall memory overhead is only a few MiB
+   depending on configuration. The current implementation uses a small array of
+   longs to encode watchpoint information, which is negligible.
 
 2. **Performance Overhead:** KCSAN's runtime aims to be minimal, using an
    efficient watchpoint encoding that does not require acquiring any shared
@@ -253,14 +311,17 @@ Key Properties
 Alternatives Considered
 -----------------------
 
-An alternative data race detection approach for the kernel can be found in
+An alternative data race detection approach for the kernel can be found in the
 `Kernel Thread Sanitizer (KTSAN) <https://github.com/google/ktsan/wiki>`_.
 KTSAN is a happens-before data race detector, which explicitly establishes the
 happens-before order between memory operations, which can then be used to
-determine data races as defined in `Data Races`_. To build a correct
-happens-before relation, KTSAN must be aware of all ordering rules of the LKMM
-and synchronization primitives. Unfortunately, any omission leads to false
-positives, which is especially important in the context of the kernel which
-includes numerous custom synchronization mechanisms. Furthermore, KTSAN's
-implementation requires metadata for each memory location (shadow memory);
-currently, for each page, KTSAN requires 4 pages of shadow memory.
+determine data races as defined in `Data Races`_.
+
+To build a correct happens-before relation, KTSAN must be aware of all ordering
+rules of the LKMM and synchronization primitives. Unfortunately, any omission
+leads to large numbers of false positives, which is especially detrimental in
+the context of the kernel which includes numerous custom synchronization
+mechanisms. To track the happens-before relation, KTSAN's implementation
+requires metadata for each memory location (shadow memory), which for each page
+corresponds to 4 pages of shadow memory, and can translate into overhead of
+tens of GiB on a large system.
-- 
2.9.5

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200309190420.6100-31-paulmck%40kernel.org.
