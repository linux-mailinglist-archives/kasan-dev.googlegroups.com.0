Return-Path: <kasan-dev+bncBC7OBJGL2MHBBGMX733AKGQETTP365I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53e.google.com (mail-pg1-x53e.google.com [IPv6:2607:f8b0:4864:20::53e])
	by mail.lfdr.de (Postfix) with ESMTPS id 389181F3BB2
	for <lists+kasan-dev@lfdr.de>; Tue,  9 Jun 2020 15:16:11 +0200 (CEST)
Received: by mail-pg1-x53e.google.com with SMTP id k15sf15513158pgt.21
        for <lists+kasan-dev@lfdr.de>; Tue, 09 Jun 2020 06:16:11 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1591708569; cv=pass;
        d=google.com; s=arc-20160816;
        b=j2iXOjXnn6ikGr3AZuTXeKS8CeZwoH0ObcM/1xYq3o22JWaHmSAWHG5GdjMIus1NXe
         yk3P4QYI/us/fs3fRL+XNINVjCsZlXNrAmi/d5wSpWrUfchk5EVTCu8Ixm1HS88/tb4F
         Ya+ZMo4hpWzxOINd6NKAdBZLo686/2YNITfWmloGtvn75dWcww9Mete6gGBFkFf9g88Z
         GVWzQ6lSdQE1qz/qKgZjdqYjBLNR8IeJd8F8fugzDxnAeQpnJTs1n10ZoDHn8iDX/Jjp
         iVN7talUyz6OlyZ8qBrHnN3n8tKPlnENoaa/byiPxdqo3CHHtB8f1BZAGUySSEQ0Ylxn
         Weog==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=LbDm1qSizwNBCwHikjNtPAKGAzo1ECyMgLDwGV6gSGs=;
        b=GTJ58ZItmN1uKqr/igwVUu7LE8gvfToltuvm+AT3fz1faBSj62vsMlAKDyN+YVTeSw
         rFwRKj3oG+uGAaBIEuIh5tsErQXA+oHW2PMf1/35EWnyNRDbNm19/gezJV5bjjL3+K1d
         Wz5n1FBwvJTOHh/y+9p/lalUV5WemGkXnmbv6zBmTPD5nZwvouE6STgnWuiEZEjl9+aL
         LGZT4z6mEMvQK/NxqEAQcoKhkMHXehWLsrDEImhBwlaSg4X9A3S7WprG2MYmn5lXRd5+
         BECBEAftLuVdfomMq5rSlAn2zKCeSa47lm19JA6pncPp1E3ljqgYAPmVI+ZdqWhZoWob
         XMwg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=cpDWunLn;
       spf=pass (google.com: domain of 3l4vfxgukcsokrbkxmuumrk.iusqgygt-jkbmuumrkmxuavy.ius@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3l4vfXgUKCSoKRbKXMUUMRK.IUSQGYGT-JKbMUUMRKMXUaVY.IUS@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=LbDm1qSizwNBCwHikjNtPAKGAzo1ECyMgLDwGV6gSGs=;
        b=Wg2nLBLp+tKyMKeb4dHxA25Ndywrfkc52gGTDtW8joXTdcmJTuW5IbCgPzbuOWjv2x
         CofE23RxR6OQRqk2+RdTwjbRbDEYkbutEHsRTgXMGTMwzVkb21md0egVag97bakvO4fT
         JDspgXjGSs8KTi1iO89m/Dw07DZzRkNsyB7NGygr4CV0fmQqerZHyPjtueVZMA8YUu89
         D4wttfL5ZaxHvBYsx7n1Ccy4btViqk6y3cW/5/LrN/uc1bueEj+x5hZc2nT5dLTe/skt
         s44yc2xJ6Zc/kXNyp9kFuzISHXP0HaYOUfRVBOTYNgo+UAsTtNNtiOr8GWsET1Tat2Lt
         wibw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=LbDm1qSizwNBCwHikjNtPAKGAzo1ECyMgLDwGV6gSGs=;
        b=IhthI2NIQnmJs7fHj+FAextekQsLrotMaetLId+cOg2nN13LKsVl7dd2takkgJ04hR
         POxPjCQL6Ms/MjoyKgWB49vvvjnTvl8S2fp2ohgqnQwLs88lDotuSojAjEafvWiufmUg
         6YU4j++4yeyXZagNPWFQcLZODXtC9fY/K4vkzTdIehKqgtNj3MwpO2M50s4d4q4bOc4Z
         YFn0bqtu5+Pl930MXKRAlgojwtMVK41DWGAg1tIh8sulAFD4THiTxQRWuchgij2c5B/s
         GwZMFSzYEXcGak79A73TXAGszQjihhOI25DqULgaX1MUfcYEnGDzyzaRGFbFxPAP02jm
         ppXQ==
X-Gm-Message-State: AOAM531p773mKKpyk0zOkb513E7O8yLY0A52UOHMhjTPsrWMfakS0J/q
	/CPQOyLlzsOPypMoJOaxjLU=
X-Google-Smtp-Source: ABdhPJwxir+BmHnjUp6tyljlPumdDEuy17tl57nSts289mnCBoaUIb4oyFL8mJ2pCZdQEPa8NdYtfA==
X-Received: by 2002:a17:90a:1485:: with SMTP id k5mr4735106pja.108.1591708569514;
        Tue, 09 Jun 2020 06:16:09 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:6845:: with SMTP id f5ls7284846pln.8.gmail; Tue, 09
 Jun 2020 06:16:09 -0700 (PDT)
X-Received: by 2002:a17:90a:f198:: with SMTP id bv24mr4894777pjb.206.1591708568949;
        Tue, 09 Jun 2020 06:16:08 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1591708568; cv=none;
        d=google.com; s=arc-20160816;
        b=eZnZrCXJDvTrUC2YwPMYNGshyxiY8XtqLqN63jhRDxR/REWim7XJxiIHcs5/rFFcPg
         RsOo/Yt6xe/NG1ZiZwC0gEDWTCl5WzmWzcM+9Uuhpuk6Di/AKHxFflEpq4npzHvaEeCG
         hoWLlipbXFR30kpMxLdfJ0W/z4DxjJVwyrRqdj7b+U8EMg/k1oA1Umva/85yo4D8S9Ds
         6IGS1Ny1gKx4qsvueKe8WqLSQyqtneXwgyfIGf4Kj2JekyNkXdCwGlxi8abMZiiwduGN
         el4eko47EQ5SyYLmcGKshGmeApDtPtGLzIyJtc/jEu5SSbj8ixHTlespd+2PnTuf65xA
         +OEA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=zec7QSzEYQWe9ApvuL8d2IDmXXWOq0s9cwNr6MpRm7M=;
        b=IpymAi1++xlCA85geVXcOCUFyBYycBKObC+nv9sWlLNOX+7be0GAclyzSqq8CTcOrB
         2WslmkeHVpgbl0WAkXEsRi/03vEw8XG9pakOmA6sTf2GZll48oYTW25vkODTGS3x2L6N
         LeErmgpTbNUs8JOlujJoYIYMfYSBWprvkq7zYMcXcO/0mowvP5Tfw6TxL0VGPkAJhpns
         uaA/8rDxGHrMWH+UVeAEVMyqOGG0OWPWfV5Xh/MDkCyD6l0JczKTDr83Rjn7p66/qYpY
         kTmTxTFJjT+Nkwrqg2z5GLIpibboeKse3aY3nUSrcRrdYHB490Bcj+4crN52URd1Jocb
         9Efw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=cpDWunLn;
       spf=pass (google.com: domain of 3l4vfxgukcsokrbkxmuumrk.iusqgygt-jkbmuumrkmxuavy.ius@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3l4vfXgUKCSoKRbKXMUUMRK.IUSQGYGT-JKbMUUMRKMXUaVY.IUS@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x84a.google.com (mail-qt1-x84a.google.com. [2607:f8b0:4864:20::84a])
        by gmr-mx.google.com with ESMTPS id t23si317126plr.4.2020.06.09.06.16.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 09 Jun 2020 06:16:08 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3l4vfxgukcsokrbkxmuumrk.iusqgygt-jkbmuumrkmxuavy.ius@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) client-ip=2607:f8b0:4864:20::84a;
Received: by mail-qt1-x84a.google.com with SMTP id l26so18371510qtr.14
        for <kasan-dev@googlegroups.com>; Tue, 09 Jun 2020 06:16:08 -0700 (PDT)
X-Received: by 2002:a0c:e9cd:: with SMTP id q13mr3935309qvo.23.1591708567960;
 Tue, 09 Jun 2020 06:16:07 -0700 (PDT)
Date: Tue,  9 Jun 2020 15:15:39 +0200
Message-Id: <20200609131539.180522-1-elver@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.27.0.278.ge193c7cf3a9-goog
Subject: [PATCH v3] tsan: Add optional support for distinguishing volatiles
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: gcc-patches@gcc.gnu.org, jakub@redhat.com, mliska@suse.cz
Cc: elver@google.com, kasan-dev@googlegroups.com, dvyukov@google.com, 
	bp@alien8.de
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=cpDWunLn;       spf=pass
 (google.com: domain of 3l4vfxgukcsokrbkxmuumrk.iusqgygt-jkbmuumrkmxuavy.ius@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3l4vfXgUKCSoKRbKXMUUMRK.IUSQGYGT-JKbMUUMRKMXUaVY.IUS@flex--elver.bounces.google.com;
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
various places, and often declare volatile to be appropriate even in
multi-threaded contexts. One such example is the Linux kernel, which
implements various synchronization primitives using volatile
(READ_ONCE(), WRITE_ONCE()).

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

Acked-by: Dmitry Vyukov <dvyukov@google.com>
---
v3:
* Remove Optimization from -param=tsan-distinguish-volatile.
* Simplify get_memory_access_decl.
* Avoid use of builtin_decl temporary.

v2:
* Add Optimization keyword to -param=tsan-distinguish-volatile= as the
  parameter can be different per TU.
* Add tree-dump check to test.
---
 gcc/params.opt                             |  4 ++
 gcc/sanitizer.def                          | 21 +++++++
 gcc/testsuite/c-c++-common/tsan/volatile.c | 67 ++++++++++++++++++++++
 gcc/tsan.c                                 | 31 +++++-----
 4 files changed, 110 insertions(+), 13 deletions(-)
 create mode 100644 gcc/testsuite/c-c++-common/tsan/volatile.c

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
index 8d22a776377..fcb2653ebbe 100644
--- a/gcc/tsan.c
+++ b/gcc/tsan.c
@@ -52,25 +52,29 @@ along with GCC; see the file COPYING3.  If not see
    void __tsan_read/writeX (void *addr);  */
 
 static tree
-get_memory_access_decl (bool is_write, unsigned size)
+get_memory_access_decl (bool is_write, unsigned size, bool volatilep)
 {
   enum built_in_function fcode;
+  int pos;
 
   if (size <= 1)
-    fcode = is_write ? BUILT_IN_TSAN_WRITE1
-		     : BUILT_IN_TSAN_READ1;
+    pos = 0;
   else if (size <= 3)
-    fcode = is_write ? BUILT_IN_TSAN_WRITE2
-		     : BUILT_IN_TSAN_READ2;
+    pos = 1;
   else if (size <= 7)
-    fcode = is_write ? BUILT_IN_TSAN_WRITE4
-		     : BUILT_IN_TSAN_READ4;
+    pos = 2;
   else if (size <= 15)
-    fcode = is_write ? BUILT_IN_TSAN_WRITE8
-		     : BUILT_IN_TSAN_READ8;
+    pos = 3;
+  else
+    pos = 4;
+
+  if (param_tsan_distinguish_volatile && volatilep)
+    fcode = is_write ? BUILT_IN_TSAN_VOLATILE_WRITE1
+                     : BUILT_IN_TSAN_VOLATILE_READ1;
   else
-    fcode = is_write ? BUILT_IN_TSAN_WRITE16
-		     : BUILT_IN_TSAN_READ16;
+    fcode = is_write ? BUILT_IN_TSAN_WRITE1
+                     : BUILT_IN_TSAN_READ1;
+  fcode = (built_in_function)(fcode + pos);
 
   return builtin_decl_implicit (fcode);
 }
@@ -204,8 +208,9 @@ instrument_expr (gimple_stmt_iterator gsi, tree expr, bool is_write)
       g = gimple_build_call (builtin_decl, 2, expr_ptr, size_int (size));
     }
   else if (rhs == NULL)
-    g = gimple_build_call (get_memory_access_decl (is_write, size),
-			   1, expr_ptr);
+    g = gimple_build_call (get_memory_access_decl (is_write, size,
+                                                   TREE_THIS_VOLATILE (expr)),
+                           1, expr_ptr);
   else
     {
       builtin_decl = builtin_decl_implicit (BUILT_IN_TSAN_VPTR_UPDATE);
-- 
2.27.0.278.ge193c7cf3a9-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200609131539.180522-1-elver%40google.com.
