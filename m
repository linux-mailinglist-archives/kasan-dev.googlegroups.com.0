Return-Path: <kasan-dev+bncBC7OBJGL2MHBB2H57T3AKGQEQE6N63Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23c.google.com (mail-oi1-x23c.google.com [IPv6:2607:f8b0:4864:20::23c])
	by mail.lfdr.de (Postfix) with ESMTPS id D509B1F356C
	for <lists+kasan-dev@lfdr.de>; Tue,  9 Jun 2020 09:48:57 +0200 (CEST)
Received: by mail-oi1-x23c.google.com with SMTP id n130sf9445712oig.9
        for <lists+kasan-dev@lfdr.de>; Tue, 09 Jun 2020 00:48:57 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1591688936; cv=pass;
        d=google.com; s=arc-20160816;
        b=fLOxEVcHtIlEmHsHEvwHP95Ck4w7lQGUnM64Aqrbd8JrM25NgEq/T7HVuQXNqvhsqr
         Dg8mBBDdoI5QGuSRYJP3TG5vZ86EYzPQ768YHld9X8T9cN2OfmGNosGkzEzZXrHbpIEW
         Ar0m3mVHSxdtd3yaW8uKgNy3UA9b9ppd95fYTHgh/UgdSSTKRAseIvpvZ+P/GjNOF/jh
         /aw1PVnl4IRZiudDFfbCKnQ61rPmUG+ccp/NDPXlfV07/UhaUbPute+ERjGeO8wO4nAE
         BxWCrYtCpbtke25LWUiso5HEUy6wJg2OXc3IssWhQ9QM36w1YwqnMkD0Isn9AhzJIpTc
         /uOQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=v8gVRWHFx2UdmsL4ZpW0BD+1xc3h7C6VX0fAiBYUz8Q=;
        b=T5W9hPs5agdxxk0M8387gMqiCjAl8zdXfoz4patZE1uLoo06sjfuNNTpZI8sEtEFib
         fV/RVz0KsAM18epwkeevf7QOo+RLHz2J79YlFBAE7RCxGkPX68Bd/WhsrPc9OyfAXU6r
         aVsKfj2rjevWFaD94W+4q1LSCsHKk96ZAaRzUaM+xoo9c7AlgP9zZ/7HR1vObP3frv06
         v0OxrZy2mvpdP0EFOnt2yqpFt5++8p8ofL+xMOioOc5TGJkrPTW5rg9mc3NlDqCLG+lE
         o++BNDr02MO7D5q6Py4KvyXUFApV5UmVgw0XWLhL8Mf8PLXshW0oKJ+B0TzcvD+/kS1x
         oS6Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=qu7dQ32B;
       spf=pass (google.com: domain of 35z7fxgukcd4elvergoogle.comkasan-devgooglegroups.com@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=35z7fXgUKCd4ELVERGOOGLE.COMKASAN-DEVGOOGLEGROUPS.COM@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=v8gVRWHFx2UdmsL4ZpW0BD+1xc3h7C6VX0fAiBYUz8Q=;
        b=TF+nsyzaCfnoAQtA0gAOBsRhxAjmy8Obd7eemcx7lKtlcyUri10w0UHYrIfIG2zvKt
         oPm+Bz1D4CNR4duP+rwwl40ce+GAGkKxNvcM8bRIlYE9gDk6jT6A9yOlZfLgrSurR7qy
         09XEfiy1jwkVutpKAzWbg1zQVVffAZO2nr0FvFJbjUgI9DclRUEYu+EShRtgGyZOUvsQ
         4kcgfckml/xkoqBCvvAeHppGXlK7y63vdhFg4A07G7MxMSvS6+T6BXQybRPtWDTR8jtU
         Avxyz011QwHLoxejaCMMUvFy0yC0JUmeYFeUH43hjWBoFT48LU+9t8NWSInCAWJEBYTr
         oLkw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=v8gVRWHFx2UdmsL4ZpW0BD+1xc3h7C6VX0fAiBYUz8Q=;
        b=VtmR5S7XUT6z8C1/qUBGr6TO7WRHEGYKDj30ZMVnB8mBrAgIWaEixvevnke+Wf0jIk
         XcC1NI/F8JjY+3A2rE3dGo105H8l+rPgjt5Wa3zt+5bwTNVY1jeR9Qi7jDaPZ5bImVKa
         Y7+t4XSfeH3su4KsCdgnRQqPE/UFZYXWymGUx/rQi05TUGR38a8vEC8jNDlQYywTv4ca
         8fbcLvO++WAPwSNXP94tPiz+qhBp9HA4Zg7slyFxM/NheSSFF1gNWCNfHwMVBbd25uBV
         XvE0gQrizSOe8f4WMZi9WoYkF63uDpc8jssumWdJQGK/vxaaJH6avFxXzSMT34+C3jAs
         YxHQ==
X-Gm-Message-State: AOAM530pz+jZndNVUyy6mcATcevwCtZT8gaBx19oa2Jx2U/zomzJhXt3
	65fE7NRyUEJA3609g930yoY=
X-Google-Smtp-Source: ABdhPJyrWryQjyRC7gxjbf97iNG22SqgyZK8eRFNJ7FYghQaduRGs/yRGFjrcaIaMkay/ggSH6wF/g==
X-Received: by 2002:aca:d510:: with SMTP id m16mr2431880oig.13.1591688936427;
        Tue, 09 Jun 2020 00:48:56 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:4fc3:: with SMTP id d186ls3702442oib.1.gmail; Tue, 09
 Jun 2020 00:48:56 -0700 (PDT)
X-Received: by 2002:aca:b706:: with SMTP id h6mr2433661oif.121.1591688936089;
        Tue, 09 Jun 2020 00:48:56 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1591688936; cv=none;
        d=google.com; s=arc-20160816;
        b=HRL7yDe6XOYxTT8LjD5XPLMRLQrvuG+n/tB5CIQINUd58iq3bYYaM9i+asL6oMim8j
         yLaOR523OfrSSre7kCMSWC3SnNB3qG/t03q2kEVRh6lKiPpIPguo0vaqmIQM+h9xakF6
         OjL0zGReU+XL2n+O1D2VENuF1TfW4Xcia1OwvS4+4BSMUtmPYSZMW+tgcPTYEtbUTOOQ
         yi56CIK3pIrLl03cUN2zhIxvyzaqO/eO0oz0kd8gbOFA1qSRd6oBvnOfGT3HzqxoQIYC
         xA0qiibwYwJqWijGfdJ5rlzdBRbZCbzY35ge4blzJrb/UKKHIhlRSeimRD0Qrg+dN5E/
         DX0w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=ozhFgVYs8Dn30CIS1D97NALmc19CQxn6RRMJYTF7bpI=;
        b=heZniK9mJnyyJjKIOwttRtcAj3oSmKHz5JRGDPSnedjfPBJrC2UmiMwvfmANMVG9Tv
         MXtKe8PlDZW6KQEL8GzsjZMT447i/QW/dJ8UhwZfbfLsSMPBdzruV6Xap1DmXRa8btyX
         MFcCgpEAtHuizg585HsBUAqsuLeGQhSAcMKyPqRZc43/ie6jWLwcHWR9DGLExCrpcVoX
         7+a9O9kex36KG6MFwQ3w3otHKVa7iOgNILR6oKaVvMoHtBKhByWP8l2pcaoE/r8dtzG9
         7AnqMh+8QUoAHGBez5wcQ9ThKfEVjYG7YsXeneo18MbA5hBqrKGWMCmuxQVY7EJH6d+w
         Y/eg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=qu7dQ32B;
       spf=pass (google.com: domain of 35z7fxgukcd4elvergoogle.comkasan-devgooglegroups.com@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=35z7fXgUKCd4ELVERGOOGLE.COMKASAN-DEVGOOGLEGROUPS.COM@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x749.google.com (mail-qk1-x749.google.com. [2607:f8b0:4864:20::749])
        by gmr-mx.google.com with ESMTPS id k65si721728oib.2.2020.06.09.00.48.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 09 Jun 2020 00:48:56 -0700 (PDT)
Received-SPF: pass (google.com: domain of 35z7fxgukcd4elvergoogle.comkasan-devgooglegroups.com@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) client-ip=2607:f8b0:4864:20::749;
Received: by mail-qk1-x749.google.com with SMTP id a5so16454256qkk.12
        for <kasan-dev@googlegroups.com>; Tue, 09 Jun 2020 00:48:56 -0700 (PDT)
X-Received: by 2002:a05:6214:4af:: with SMTP id w15mr2568619qvz.11.1591688935520;
 Tue, 09 Jun 2020 00:48:55 -0700 (PDT)
Date: Tue,  9 Jun 2020 09:48:34 +0200
Message-Id: <20200609074834.215975-1-elver@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.27.0.278.ge193c7cf3a9-goog
Subject: [PATCH v2] tsan: Add optional support for distinguishing volatiles
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: gcc-patches@gcc.gnu.org, jakub@redhat.com, mliska@suse.cz
Cc: elver@google.com, kasan-dev@googlegroups.com, dvyukov@google.com, 
	bp@alien8.de, Dmitry Vyukov <dvuykov@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=qu7dQ32B;       spf=pass
 (google.com: domain of 35z7fxgukcd4elvergoogle.comkasan-devgooglegroups.com@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=35z7fXgUKCd4ELVERGOOGLE.COMKASAN-DEVGOOGLEGROUPS.COM@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
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

Add support to optionally emit different instrumentation for accesses to
volatile variables. While the default TSAN runtime likely will never
require this feature, other runtimes for different environments that
have subtly different memory models or assumptions may require
distinguishing volatiles.

One such environment are OS kernels, where volatile is still used in
various places, and often declare volatile to be
appropriate even in multi-threaded contexts. One such example is the
Linux kernel, which implements various synchronization primitives using
volatile (READ_ONCE(), WRITE_ONCE()).

Here the Kernel Concurrency Sanitizer (KCSAN), is a runtime that uses
TSAN instrumentation but otherwise implements a very different approach
to race detection from TSAN:

	https://github.com/google/ktsan/wiki/KCSAN

Due to recent changes in requirements by the Linux kernel, KCSAN
requires that the compiler supports tsan-distinguish-volatile (among
several new requirements):

	https://lore.kernel.org/lkml/20200521142047.169334-7-elver@google.com/

gcc/
	* params.opt: Define --param=tsan-distinguish-volatile=[0,1].
	* sanitizer.def (BUILT_IN_TSAN_VOLATILE_READ1): Define new
	builtin for volatile instrumentation of reads/writes.
	(BUILT_IN_TSAN_VOLATILE_READ2): Likewise.
	(BUILT_IN_TSAN_VOLATILE_READ4): Likewise.
	(BUILT_IN_TSAN_VOLATILE_READ8): Likewise.
	(BUILT_IN_TSAN_VOLATILE_READ16): Likewise.
	(BUILT_IN_TSAN_VOLATILE_WRITE1): Likewise.
	(BUILT_IN_TSAN_VOLATILE_WRITE2): Likewise.
	(BUILT_IN_TSAN_VOLATILE_WRITE4): Likewise.
	(BUILT_IN_TSAN_VOLATILE_WRITE8): Likewise.
	(BUILT_IN_TSAN_VOLATILE_WRITE16): Likewise.
	* tsan.c (get_memory_access_decl): Argument if access is
	volatile. If param tsan-distinguish-volatile is non-zero, and
	access if volatile, return volatile instrumentation decl.
	(instrument_expr): Check if access is volatile.

gcc/testsuite/
	* c-c++-common/tsan/volatile.c: New test.

Acked-by: Dmitry Vyukov <dvuykov@google.com>
---
v2:
* Add Optimization keyword to -param=tsan-distinguish-volatile= as the
  parameter can be different per TU.
* Add tree-dump check to test.
---
 gcc/params.opt                             |  4 ++
 gcc/sanitizer.def                          | 21 +++++++
 gcc/testsuite/c-c++-common/tsan/volatile.c | 67 ++++++++++++++++++++++
 gcc/tsan.c                                 | 53 +++++++++++------
 4 files changed, 128 insertions(+), 17 deletions(-)
 create mode 100644 gcc/testsuite/c-c++-common/tsan/volatile.c

diff --git a/gcc/params.opt b/gcc/params.opt
index 4aec480798b..c751416bcad 100644
--- a/gcc/params.opt
+++ b/gcc/params.opt
@@ -908,6 +908,10 @@ Stop reverse growth if the reverse probability of best edge is less than this th
 Common Joined UInteger Var(param_tree_reassoc_width) Param Optimization
 Set the maximum number of instructions executed in parallel in reassociated tree.  If 0, use the target dependent heuristic.
 
+-param=tsan-distinguish-volatile=
+Common Joined UInteger Var(param_tsan_distinguish_volatile) IntegerRange(0, 1) Param Optimization
+Emit special instrumentation for accesses to volatiles.
+
 -param=uninit-control-dep-attempts=
 Common Joined UInteger Var(param_uninit_control_dep_attempts) Init(1000) IntegerRange(1, 65536) Param Optimization
 Maximum number of nested calls to search for control dependencies during uninitialized variable analysis.
diff --git a/gcc/sanitizer.def b/gcc/sanitizer.def
index 11eb6467eba..a32715ddb92 100644
--- a/gcc/sanitizer.def
+++ b/gcc/sanitizer.def
@@ -214,6 +214,27 @@ DEF_SANITIZER_BUILTIN(BUILT_IN_TSAN_READ_RANGE, "__tsan_read_range",
 DEF_SANITIZER_BUILTIN(BUILT_IN_TSAN_WRITE_RANGE, "__tsan_write_range",
 		      BT_FN_VOID_PTR_PTRMODE, ATTR_NOTHROW_LEAF_LIST)
 
+DEF_SANITIZER_BUILTIN(BUILT_IN_TSAN_VOLATILE_READ1, "__tsan_volatile_read1",
+		      BT_FN_VOID_PTR, ATTR_NOTHROW_LEAF_LIST)
+DEF_SANITIZER_BUILTIN(BUILT_IN_TSAN_VOLATILE_READ2, "__tsan_volatile_read2",
+		      BT_FN_VOID_PTR, ATTR_NOTHROW_LEAF_LIST)
+DEF_SANITIZER_BUILTIN(BUILT_IN_TSAN_VOLATILE_READ4, "__tsan_volatile_read4",
+		      BT_FN_VOID_PTR, ATTR_NOTHROW_LEAF_LIST)
+DEF_SANITIZER_BUILTIN(BUILT_IN_TSAN_VOLATILE_READ8, "__tsan_volatile_read8",
+		      BT_FN_VOID_PTR, ATTR_NOTHROW_LEAF_LIST)
+DEF_SANITIZER_BUILTIN(BUILT_IN_TSAN_VOLATILE_READ16, "__tsan_volatile_read16",
+		      BT_FN_VOID_PTR, ATTR_NOTHROW_LEAF_LIST)
+DEF_SANITIZER_BUILTIN(BUILT_IN_TSAN_VOLATILE_WRITE1, "__tsan_volatile_write1",
+		      BT_FN_VOID_PTR, ATTR_NOTHROW_LEAF_LIST)
+DEF_SANITIZER_BUILTIN(BUILT_IN_TSAN_VOLATILE_WRITE2, "__tsan_volatile_write2",
+		      BT_FN_VOID_PTR, ATTR_NOTHROW_LEAF_LIST)
+DEF_SANITIZER_BUILTIN(BUILT_IN_TSAN_VOLATILE_WRITE4, "__tsan_volatile_write4",
+		      BT_FN_VOID_PTR, ATTR_NOTHROW_LEAF_LIST)
+DEF_SANITIZER_BUILTIN(BUILT_IN_TSAN_VOLATILE_WRITE8, "__tsan_volatile_write8",
+		      BT_FN_VOID_PTR, ATTR_NOTHROW_LEAF_LIST)
+DEF_SANITIZER_BUILTIN(BUILT_IN_TSAN_VOLATILE_WRITE16, "__tsan_volatile_write16",
+		      BT_FN_VOID_PTR, ATTR_NOTHROW_LEAF_LIST)
+
 DEF_SANITIZER_BUILTIN(BUILT_IN_TSAN_ATOMIC8_LOAD,
 		      "__tsan_atomic8_load",
 		      BT_FN_I1_CONST_VPTR_INT, ATTR_NOTHROW_LEAF_LIST)
diff --git a/gcc/testsuite/c-c++-common/tsan/volatile.c b/gcc/testsuite/c-c++-common/tsan/volatile.c
new file mode 100644
index 00000000000..68379921685
--- /dev/null
+++ b/gcc/testsuite/c-c++-common/tsan/volatile.c
@@ -0,0 +1,67 @@
+/* { dg-options "--param=tsan-distinguish-volatile=1 -fdump-tree-optimized" } */
+
+#include <assert.h>
+#include <stdint.h>
+#include <stdio.h>
+
+int32_t Global4;
+volatile int32_t VolatileGlobal4;
+volatile int64_t VolatileGlobal8;
+
+static int nvolatile_reads;
+static int nvolatile_writes;
+
+#ifdef __cplusplus
+extern "C" {
+#endif
+
+__attribute__((no_sanitize_thread))
+void __tsan_volatile_read4(void *addr) {
+  assert(addr == &VolatileGlobal4);
+  nvolatile_reads++;
+}
+__attribute__((no_sanitize_thread))
+void __tsan_volatile_write4(void *addr) {
+  assert(addr == &VolatileGlobal4);
+  nvolatile_writes++;
+}
+__attribute__((no_sanitize_thread))
+void __tsan_volatile_read8(void *addr) {
+  assert(addr == &VolatileGlobal8);
+  nvolatile_reads++;
+}
+__attribute__((no_sanitize_thread))
+void __tsan_volatile_write8(void *addr) {
+  assert(addr == &VolatileGlobal8);
+  nvolatile_writes++;
+}
+
+#ifdef __cplusplus
+}
+#endif
+
+__attribute__((no_sanitize_thread))
+static void check() {
+  assert(nvolatile_reads == 4);
+  assert(nvolatile_writes == 4);
+}
+
+int main() {
+  Global4 = 1;
+
+  VolatileGlobal4 = 1;
+  Global4 = VolatileGlobal4;
+  VolatileGlobal4 = 1 + VolatileGlobal4;
+
+  VolatileGlobal8 = 1;
+  Global4 = (int32_t)VolatileGlobal8;
+  VolatileGlobal8 = 1 + VolatileGlobal8;
+
+  check();
+  return 0;
+}
+
+// { dg-final { scan-tree-dump-times "__tsan_volatile_read4 \\(&VolatileGlobal4" 2 "optimized" } }
+// { dg-final { scan-tree-dump-times "__tsan_volatile_read8 \\(&VolatileGlobal8" 2 "optimized" } }
+// { dg-final { scan-tree-dump-times "__tsan_volatile_write4 \\(&VolatileGlobal4" 2 "optimized" } }
+// { dg-final { scan-tree-dump-times "__tsan_volatile_write8 \\(&VolatileGlobal8" 2 "optimized" } }
diff --git a/gcc/tsan.c b/gcc/tsan.c
index 8d22a776377..04e92559584 100644
--- a/gcc/tsan.c
+++ b/gcc/tsan.c
@@ -52,25 +52,41 @@ along with GCC; see the file COPYING3.  If not see
    void __tsan_read/writeX (void *addr);  */
 
 static tree
-get_memory_access_decl (bool is_write, unsigned size)
+get_memory_access_decl (bool is_write, unsigned size, bool volatilep)
 {
   enum built_in_function fcode;
 
-  if (size <= 1)
-    fcode = is_write ? BUILT_IN_TSAN_WRITE1
-		     : BUILT_IN_TSAN_READ1;
-  else if (size <= 3)
-    fcode = is_write ? BUILT_IN_TSAN_WRITE2
-		     : BUILT_IN_TSAN_READ2;
-  else if (size <= 7)
-    fcode = is_write ? BUILT_IN_TSAN_WRITE4
-		     : BUILT_IN_TSAN_READ4;
-  else if (size <= 15)
-    fcode = is_write ? BUILT_IN_TSAN_WRITE8
-		     : BUILT_IN_TSAN_READ8;
+  if (param_tsan_distinguish_volatile && volatilep)
+    {
+      if (size <= 1)
+        fcode = is_write ? BUILT_IN_TSAN_VOLATILE_WRITE1
+            : BUILT_IN_TSAN_VOLATILE_READ1;
+      else if (size <= 3)
+        fcode = is_write ? BUILT_IN_TSAN_VOLATILE_WRITE2
+            : BUILT_IN_TSAN_VOLATILE_READ2;
+      else if (size <= 7)
+        fcode = is_write ? BUILT_IN_TSAN_VOLATILE_WRITE4
+            : BUILT_IN_TSAN_VOLATILE_READ4;
+      else if (size <= 15)
+        fcode = is_write ? BUILT_IN_TSAN_VOLATILE_WRITE8
+            : BUILT_IN_TSAN_VOLATILE_READ8;
+      else
+        fcode = is_write ? BUILT_IN_TSAN_VOLATILE_WRITE16
+            : BUILT_IN_TSAN_VOLATILE_READ16;
+    }
   else
-    fcode = is_write ? BUILT_IN_TSAN_WRITE16
-		     : BUILT_IN_TSAN_READ16;
+    {
+      if (size <= 1)
+        fcode = is_write ? BUILT_IN_TSAN_WRITE1 : BUILT_IN_TSAN_READ1;
+      else if (size <= 3)
+        fcode = is_write ? BUILT_IN_TSAN_WRITE2 : BUILT_IN_TSAN_READ2;
+      else if (size <= 7)
+        fcode = is_write ? BUILT_IN_TSAN_WRITE4 : BUILT_IN_TSAN_READ4;
+      else if (size <= 15)
+        fcode = is_write ? BUILT_IN_TSAN_WRITE8 : BUILT_IN_TSAN_READ8;
+      else
+        fcode = is_write ? BUILT_IN_TSAN_WRITE16 : BUILT_IN_TSAN_READ16;
+    }
 
   return builtin_decl_implicit (fcode);
 }
@@ -204,8 +220,11 @@ instrument_expr (gimple_stmt_iterator gsi, tree expr, bool is_write)
       g = gimple_build_call (builtin_decl, 2, expr_ptr, size_int (size));
     }
   else if (rhs == NULL)
-    g = gimple_build_call (get_memory_access_decl (is_write, size),
-			   1, expr_ptr);
+    {
+      builtin_decl = get_memory_access_decl (is_write, size,
+                                             TREE_THIS_VOLATILE(expr));
+      g = gimple_build_call (builtin_decl, 1, expr_ptr);
+    }
   else
     {
       builtin_decl = builtin_decl_implicit (BUILT_IN_TSAN_VPTR_UPDATE);
-- 
2.27.0.278.ge193c7cf3a9-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200609074834.215975-1-elver%40google.com.
