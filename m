Return-Path: <kasan-dev+bncBC7OBJGL2MHBBEPPQ32QKGQEYFS4UBY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x93b.google.com (mail-ua1-x93b.google.com [IPv6:2607:f8b0:4864:20::93b])
	by mail.lfdr.de (Postfix) with ESMTPS id CF00C1B5FB7
	for <lists+kasan-dev@lfdr.de>; Thu, 23 Apr 2020 17:43:14 +0200 (CEST)
Received: by mail-ua1-x93b.google.com with SMTP id j2sf3253088uak.3
        for <lists+kasan-dev@lfdr.de>; Thu, 23 Apr 2020 08:43:14 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1587656594; cv=pass;
        d=google.com; s=arc-20160816;
        b=AuISkleE04zD96snCNXXKK5Kf+e4jMzJK1f7k5Z2ypxxkzateIhD8fxiHrLQnYf3s5
         nhSel2XyeaBtyvDM6+O55pD+P5JAFLoBYrVsKWTrU7LaPSSdG+oK+oB35hlT9dz0jhEI
         ZWPJ5Gn6SMa7cP5vFYgaiwxeZjEH0xec+rHul9SSosY1JzUpuRx/oUknUx5R0XrNCkdr
         /lNVs+85SK6QRG1MdI+Sag8De+7PHJ8/o7C2+9IeDRka61mP1CAN0uR5Pvq2UPJKfHa7
         iisdsPiBn9fLPy6Abd0ZBvl/6EubUyyPjc1Dws5DSCGM5cvGbhmLvSEKy/WEhiel9P+J
         bhGg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=K968jO3LygAG9WgWWwVslh+kYlEj2IHR4iDKfaa9T1w=;
        b=AnI3VwWYKWS31GMd/WfgW0u1zjuXkd9XxuQ/tzV9hTKwowYNWbX6DzkpyCWdPk0nev
         Ex6HHLYj2Y0RfArjZCDFoNEtq1KpJ6du797b+z7GngqiiSIPm41fX3wsC+iw+IIWa1Cu
         Hlm0fMEswhEsfYYbtNN8RPKE+QI1ez+BX9LCuiU7VrYsJDDa0mHHEv6E9IxwYvPnPut5
         xBLAPCcNuclbr6KoXz3l+Bh7TyAYBBQtZTdN+Q1IdspswEFGBgAx3iaH4sdeAHKzLzeU
         PQUF/m9PRZIQ4dKqNswUoNX5CWuQDTkOMl/a+aDbRUPep6N9H8j2xdcl8j+Hyxufvyno
         IyMw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=OxnBRUJ4;
       spf=pass (google.com: domain of 3klehxgukcyejq0jwlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::a4a as permitted sender) smtp.mailfrom=3kLehXgUKCYEjq0jwlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=K968jO3LygAG9WgWWwVslh+kYlEj2IHR4iDKfaa9T1w=;
        b=sTPFsRIyIScwzOV9FDjUSWeGX6fzv2jfnHLveNCJFBPh7XAmPkdF92p6McLQ7w2ryL
         4oDOYARAt2MDou89DfMR7yhuV5HnQnCnzhRxQ3YD056zWmbSNE68SYkQzCStzTXfVh+p
         up0yprgcfIYE0M/eB2SmvFx1QWUAIBP2Yqwp8EL6hrtvHgpQjk3GQWiQ9yFtmVmTE4FF
         9p3OjIRZALxdBF8UIP6dsM+AN/NllQR5QHoQimKvhkRMvB8vzGGh6SQlcKR0uAkXezAJ
         KVLcmayAehSjCG6/ibf9YaYualWZH93JuDgEskp4Hlkw6Q9LjLn1guE7ENJkpbgd36jl
         tVvg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=K968jO3LygAG9WgWWwVslh+kYlEj2IHR4iDKfaa9T1w=;
        b=QpnWBuujXdhq717tBgu1AM2Nm9vse4n3HA3lk3C6XWpnooU4nMfOJUmAH18pM4N7mD
         gXleoxt4suTPA15z7IPTqZCmZfvNVlrIquR0KZ9e+F6zayHNI61+K2zdpnuU5vmbKu3h
         cbtiq6yhxHw0YItgOlFLXLb/UTFD3qjAMVEJtwsTtRsPK3FYjA61Mv6vSB7IKzAeBHnR
         bq15ME3JxLjYgVkqWOCUnErp5EV/rcJ/adHIkv5Fog+AA/0Wme5qCR3a8KxQD6j07mYB
         QJIgHPYnZzUQYsSoHJFaNxk86PE0BsB1s3PWZrpFBFzxfiEsyibW1zWHQ1WZnObnXSMw
         WcDA==
X-Gm-Message-State: AGi0PuaNjaWtAQpoQVIktqVuEgzo+zPAhMIagJu4FtBGOdNcSU29vMSW
	+n61Juksye6GfxMI2PRgw5k=
X-Google-Smtp-Source: APiQypLaNlRSJMZsqKiwyKQ5yvRXgxQSW/wG7+0nNev6dB+nzFQuOZY4nnmaIlGkKxF3eyJlYQWQpQ==
X-Received: by 2002:a1f:3649:: with SMTP id d70mr3966827vka.12.1587656593791;
        Thu, 23 Apr 2020 08:43:13 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:2c86:: with SMTP id s128ls926242vss.3.gmail; Thu, 23 Apr
 2020 08:43:13 -0700 (PDT)
X-Received: by 2002:a05:6102:392:: with SMTP id m18mr3885132vsq.38.1587656592574;
        Thu, 23 Apr 2020 08:43:12 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1587656592; cv=none;
        d=google.com; s=arc-20160816;
        b=M1bp7OVkZRUSphRNQ6kOtfPsN3MT9OzdIQCE9Ksjz/JWPEA/UFkpVHZFFFV7Qoyssv
         n1yTPWJucaMdx7PEUvxF4ZbwyJaxnaTQj6F7zu2Y9K41Tm8r9p/UOJQ4vuBUklc7H671
         2W0J3r0ndVFHYeuVGxJy4cj5efuXtIBvB/YMR6p/lBS5cxbjt5qGZBaB5HiF1DuU1ETU
         I8FBrFsUTVx8bdYLiOytrzJ4bASFezAuBJUHwb3gS29wb/Tlq+2JFCn/Zr9yALPLGx7A
         GT/dr3XAu4PRO02Fhi/I6d759XdNn/Gk6xDTOuRvZfGpys0F1qj6wisCaeNRz6/CwqcX
         sRdw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=EiX2uL8drSQ7Y08i5a75xrD0rRGZVKBAB52jPTId8Os=;
        b=oKyiNCbrPCG5q7e408rTBJlcXJL6C0lB/SBGCGKBUJ7gKEXspi1NtCygYO2f7KW9s1
         vUq4Fdrynjfe9MV6mfqbf8F4jN9LDToles+6kZaSzsqGpKQh+C7pABX4CXAUo3mBkK0h
         GnQdwfb5GrNTQYNB0x+5QYYIJpxQlvvWei+44yilLIRRqdPvLtY91GfXYcvvFtdn2JSb
         7noA5+KpMIIc7vgXz7sPBWfmE2uPkF2Q9xpvcTICrlkGF6ac63npfDPvElDI4gbJPS4P
         GRynOuGPTNwZmiQf9Xg15g7EHoThBaPwpXBOw3t5/tA1fu8VEHSflLcV12jbhv/VgH0l
         jjRQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=OxnBRUJ4;
       spf=pass (google.com: domain of 3klehxgukcyejq0jwlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::a4a as permitted sender) smtp.mailfrom=3kLehXgUKCYEjq0jwlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-vk1-xa4a.google.com (mail-vk1-xa4a.google.com. [2607:f8b0:4864:20::a4a])
        by gmr-mx.google.com with ESMTPS id i26si154352vsk.0.2020.04.23.08.43.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 23 Apr 2020 08:43:12 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3klehxgukcyejq0jwlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::a4a as permitted sender) client-ip=2607:f8b0:4864:20::a4a;
Received: by mail-vk1-xa4a.google.com with SMTP id o68so828674vkc.19
        for <kasan-dev@googlegroups.com>; Thu, 23 Apr 2020 08:43:12 -0700 (PDT)
X-Received: by 2002:a1f:1e11:: with SMTP id e17mr4013563vke.73.1587656592201;
 Thu, 23 Apr 2020 08:43:12 -0700 (PDT)
Date: Thu, 23 Apr 2020 17:42:50 +0200
Message-Id: <20200423154250.10973-1-elver@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.26.1.301.g55bc3eb7cb9-goog
Subject: [PATCH] tsan: Add optional support for distinguishing volatiles
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: gcc-patches@gcc.gnu.org, jakub@redhat.com
Cc: elver@google.com, kasan-dev@googlegroups.com, dvyukov@google.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=OxnBRUJ4;       spf=pass
 (google.com: domain of 3klehxgukcyejq0jwlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::a4a as permitted sender) smtp.mailfrom=3kLehXgUKCYEjq0jwlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--elver.bounces.google.com;
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
various places for various reasons, and often declare volatile to be
"safe enough" even in multi-threaded contexts. One such example is the
Linux kernel, which implements various synchronization primitives using
volatile (READ_ONCE(), WRITE_ONCE()). Here the Kernel Concurrency
Sanitizer (KCSAN) [1], is a runtime that uses TSAN instrumentation but
otherwise implements a very different approach to race detection from
TSAN.

While in the Linux kernel it is generally discouraged to use volatiles
explicitly, the topic will likely come up again, and we will eventually
need to distinguish volatile accesses [2]. The other use-case is
ignoring data races on specially marked variables in the kernel, for
example bit-flags (here we may hide 'volatile' behind a different name
such as 'no_data_race').

[1] https://github.com/google/ktsan/wiki/KCSAN
[2] https://lkml.kernel.org/r/CANpmjNOfXNE-Zh3MNP=-gmnhvKbsfUfTtWkyg_=VqTxS4nnptQ@mail.gmail.com

2020-04-23  Marco Elver  <elver@google.com>

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
---
 gcc/ChangeLog                              | 19 +++++++
 gcc/params.opt                             |  4 ++
 gcc/sanitizer.def                          | 21 ++++++++
 gcc/testsuite/ChangeLog                    |  4 ++
 gcc/testsuite/c-c++-common/tsan/volatile.c | 62 ++++++++++++++++++++++
 gcc/tsan.c                                 | 53 ++++++++++++------
 6 files changed, 146 insertions(+), 17 deletions(-)
 create mode 100644 gcc/testsuite/c-c++-common/tsan/volatile.c

diff --git a/gcc/ChangeLog b/gcc/ChangeLog
index 5f299e463db..aa2bb98ae05 100644
--- a/gcc/ChangeLog
+++ b/gcc/ChangeLog
@@ -1,3 +1,22 @@
+2020-04-23  Marco Elver  <elver@google.com>
+
+	* params.opt: Define --param=tsan-distinguish-volatile=[0,1].
+	* sanitizer.def (BUILT_IN_TSAN_VOLATILE_READ1): Define new
+	builtin for volatile instrumentation of reads/writes.
+	(BUILT_IN_TSAN_VOLATILE_READ2): Likewise.
+	(BUILT_IN_TSAN_VOLATILE_READ4): Likewise.
+	(BUILT_IN_TSAN_VOLATILE_READ8): Likewise.
+	(BUILT_IN_TSAN_VOLATILE_READ16): Likewise.
+	(BUILT_IN_TSAN_VOLATILE_WRITE1): Likewise.
+	(BUILT_IN_TSAN_VOLATILE_WRITE2): Likewise.
+	(BUILT_IN_TSAN_VOLATILE_WRITE4): Likewise.
+	(BUILT_IN_TSAN_VOLATILE_WRITE8): Likewise.
+	(BUILT_IN_TSAN_VOLATILE_WRITE16): Likewise.
+	* tsan.c (get_memory_access_decl): Argument if access is
+	volatile. If param tsan-distinguish-volatile is non-zero, and
+	access if volatile, return volatile instrumentation decl.
+	(instrument_expr): Check if access is volatile.
+
 2020-04-23  Srinath Parvathaneni  <srinath.parvathaneni@arm.com>
 
 	* config/arm/arm_mve.h (__arm_vbicq_n_u16): Modify function parameter's
diff --git a/gcc/params.opt b/gcc/params.opt
index 4aec480798b..9b564bb046c 100644
--- a/gcc/params.opt
+++ b/gcc/params.opt
@@ -908,6 +908,10 @@ Stop reverse growth if the reverse probability of best edge is less than this th
 Common Joined UInteger Var(param_tree_reassoc_width) Param Optimization
 Set the maximum number of instructions executed in parallel in reassociated tree.  If 0, use the target dependent heuristic.
 
+-param=tsan-distinguish-volatile=
+Common Joined UInteger Var(param_tsan_distinguish_volatile) IntegerRange(0, 1) Param
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
diff --git a/gcc/testsuite/ChangeLog b/gcc/testsuite/ChangeLog
index 245c1512c76..f1d3e236b86 100644
--- a/gcc/testsuite/ChangeLog
+++ b/gcc/testsuite/ChangeLog
@@ -1,3 +1,7 @@
+2020-04-23  Marco Elver  <elver@google.com>
+
+	* c-c++-common/tsan/volatile.c: New test.
+
 2020-04-23  Jakub Jelinek  <jakub@redhat.com>
 
 	PR target/94707
diff --git a/gcc/testsuite/c-c++-common/tsan/volatile.c b/gcc/testsuite/c-c++-common/tsan/volatile.c
new file mode 100644
index 00000000000..d51d1e3ce8d
--- /dev/null
+++ b/gcc/testsuite/c-c++-common/tsan/volatile.c
@@ -0,0 +1,62 @@
+/* { dg-additional-options "--param=tsan-distinguish-volatile=1" } */
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
2.26.1.301.g55bc3eb7cb9-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200423154250.10973-1-elver%40google.com.
