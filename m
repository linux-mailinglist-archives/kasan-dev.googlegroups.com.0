Return-Path: <kasan-dev+bncBC7OBJGL2MHBBREYR33QKGQERGLX5JA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x540.google.com (mail-pg1-x540.google.com [IPv6:2607:f8b0:4864:20::540])
	by mail.lfdr.de (Postfix) with ESMTPS id 89E971F7949
	for <lists+kasan-dev@lfdr.de>; Fri, 12 Jun 2020 16:08:06 +0200 (CEST)
Received: by mail-pg1-x540.google.com with SMTP id 21sf6440655pgk.9
        for <lists+kasan-dev@lfdr.de>; Fri, 12 Jun 2020 07:08:06 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1591970885; cv=pass;
        d=google.com; s=arc-20160816;
        b=Mf3xUR0DWUmVB8pTrowPum1F7/V7JaTojG72riTSc0U7iw09U8A6sY94fbOmR5ZExH
         zkR7pd3DWIDFnpyereeilfcwFWsRhMvRcGiJH3ouxgdYJNnMd7HvS8v/EGa/2BhcRIYj
         QMK7M+wyEF9wYfm5vRxsaxb59kwfRtxw1S7VKDIbIS12Cw3ebFD58lz/edZaOD+D7TFe
         xd05g+IMORtRmmYm+AZLdSvErJCum90xm9Rpqd2cS0c82hkWYHXB4iqCnQuQmkytAOyE
         oqShkSskbthn6hEaqQzG2BfcWXbLj+gC4CnMeF1sI6bCHaa1BNCrQdkGxpbVSEofOx89
         3c8A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=xLMBJ82BhNkGMEpE7BPZaUsvhobNlKI5lYS6qlKRWk0=;
        b=JK2c0B70HkI+xhw9I5vyzgrgJNr8CD+TnsbugqwQZ6mveR4p9LG21lwnvQ6XlVZPo5
         GD8fduO8UXylouuJsPQvzmSBRWw0HSM+mJMs0SMaR8z0G5s1tyJy5ccq/7wb9yzKdVci
         XSS7eTIoR+nPALC4N0GvV0RnO4IBpebh8b3EV0uj1DLgfZUNegTJTAmwldz0AfPdRQIX
         QBp9DALI6YdjnO1ll/2xVbDF0gkjURh/ONsIg0mXGb73Yp3iINAttDCilMA1RNmNL2qk
         T/J3v5nyzPvv5KCiJ4Wid+aEZ/rEEai81Q41T2q8pNPsAaonlLOxL10/YmF7qj+BPSvV
         hIkg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="pVpMfci/";
       spf=pass (google.com: domain of 3q4zjxgukceymtdmzowwotm.kwusiaiv-lmdowwotmozwcxa.kwu@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3Q4zjXgUKCeYMTdMZOWWOTM.KWUSIaIV-LMdOWWOTMOZWcXa.KWU@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=xLMBJ82BhNkGMEpE7BPZaUsvhobNlKI5lYS6qlKRWk0=;
        b=pO1g5dvWsMD9qKt8ifgTTN8cdU/mwa/E7Xa3eaquFPVYhX8iNbyp+21YZSMUkWE2Hw
         dNez16r1t7+iZrfWZFqzXzcVPZgbY3a5afLumf4+SCABP5y+L4MHxC679AQOV9FqjvZm
         2yEjaWOcXT/wUrHdNx4YJtBeQS8Zx0WeHIZvBtVfkaZ/7bdrCl+hsdultzKPjVYbSWxU
         w0qMgs4d6t9GgnWNTdX2S8pvGPLjl8UNlKt0abzZW1bcEyfSHV1EbjMqiV7PXZMOxclt
         hcJNbJWDaZwTn3xTrk3RImIG1kJ2dBf6xrp9SOUF+RZd6hyuqXuGv3bIlaut1pUB3Pxw
         SCwQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=xLMBJ82BhNkGMEpE7BPZaUsvhobNlKI5lYS6qlKRWk0=;
        b=m1gp6il/Vji1WXr8rtNJlVwziFE3Mr1RNqAVwiKQ8/zlBvV3/EzGQHyqj4mVJjB5K/
         N2YM8DmtOw87v6ilUyBXYV86BG/BQ40IY28Kzaw733zFD/VXVcAbCDh/237mD1RIbagp
         U+m9H38KpSDCq7DhbiLzjWy2xzh5Zz4wVU7Qv9kVSTQ4TnyWYM6IPykjACX6pntQAB31
         pUt6W2ywpMYN4A+TTayzZwVs/ON1vGScwk1dco61lwJhXoLu4wvjx++d1SVtSnCZMTvT
         Oes9vLOdQuCj/Ug1ZBjB05FQiyxKqJMaJqjlzXHqLnr3bM0l7FgbvWri4ZQ7ZDTjukVa
         4fmQ==
X-Gm-Message-State: AOAM532dKFoXZVK7hAmbNIiEIUYVzqmktrI+Qheavpe2gHWH7ZVsXN8B
	4Wq64Mk71+LYs5kdbtdXbuE=
X-Google-Smtp-Source: ABdhPJymtfT1f0ccGrbEQZgsZLSIZ991t5keME7jeeAq6ic04H4zd9FyfWIQ9rvQDZe581aDp0XCqQ==
X-Received: by 2002:a17:90a:ae04:: with SMTP id t4mr13137890pjq.75.1591970884725;
        Fri, 12 Jun 2020 07:08:04 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:6b02:: with SMTP id o2ls2132155plk.7.gmail; Fri, 12
 Jun 2020 07:08:04 -0700 (PDT)
X-Received: by 2002:a17:90a:8c96:: with SMTP id b22mr13849422pjo.88.1591970884185;
        Fri, 12 Jun 2020 07:08:04 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1591970884; cv=none;
        d=google.com; s=arc-20160816;
        b=pRmG/5DF0qQcLrqks/yRVlUCgb+PXBDZzgUZmYTZC8Ah6+CVjoxncDdCUm+Lhx8pgi
         cDSzItDU21ptwod7JYfgLOJ9AuhpUa8Kx92U1RDqoL8DF0cDm4KG0NpTquLoNGc+55S1
         YOCXbOgIknZ3ylpQCE08jCAsTD+RT/qB66/+H6I/udI/8hNRF7+c92i+ITMHEIxfnZar
         7jhh3t81vkI863RM9YjLviD0yKw2Icww1tVXYAZgWh5XfgSpNzIoy5vTz/61ky16dBC1
         sdAMsjYpUVjh4yY7ZQAwP9uRiNYoYl6vbirqUEqV9u7b9t00u3XlAdkHZBM4jSlCK03f
         daDg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=yhPU74iw+SK2z6hJTzpeQPnEoSZUJ7GU5oCMfdaW2DY=;
        b=YiNzZR81Io+vnX+rTnronS26SLK7mtK0BQc6X8qsYFoMxv8OwoQpTAGmdtDbUOAbVW
         EHl1+jdUqAyxnoJEPuP7dc1reKKgRCrl462S9IWllKBfqXWezmUyKreLEhxiRLLrERe6
         9oPFiKRFJGOOPdKe5/UdxpMnoEqMPDDVqh0RKHhl7hR6zG38LC2Gun/a+OgDXB8nCN0T
         a/xMwr5k+6CTfmnU9bD9I5bLPodKT6j31SvAsqQ0jvZ02NY4VEYfUsnIl5iCJi5Zg8Ch
         j92mjg2hNX5jg5LgQKuPXkYaKIaDKbypikqoVLKzsWBdy6pYZO9Zlw5O4HE7QNraLyxA
         66ZA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="pVpMfci/";
       spf=pass (google.com: domain of 3q4zjxgukceymtdmzowwotm.kwusiaiv-lmdowwotmozwcxa.kwu@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3Q4zjXgUKCeYMTdMZOWWOTM.KWUSIaIV-LMdOWWOTMOZWcXa.KWU@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf49.google.com (mail-qv1-xf49.google.com. [2607:f8b0:4864:20::f49])
        by gmr-mx.google.com with ESMTPS id q1si263444pjj.0.2020.06.12.07.08.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 12 Jun 2020 07:08:04 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3q4zjxgukceymtdmzowwotm.kwusiaiv-lmdowwotmozwcxa.kwu@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) client-ip=2607:f8b0:4864:20::f49;
Received: by mail-qv1-xf49.google.com with SMTP id h30so7026209qva.17
        for <kasan-dev@googlegroups.com>; Fri, 12 Jun 2020 07:08:04 -0700 (PDT)
X-Received: by 2002:a0c:fd8a:: with SMTP id p10mr8084704qvr.30.1591970883249;
 Fri, 12 Jun 2020 07:08:03 -0700 (PDT)
Date: Fri, 12 Jun 2020 16:07:57 +0200
Message-Id: <20200612140757.246773-1-elver@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.27.0.290.gba653c62da-goog
Subject: [PATCH v2] tsan: Add param to disable func-entry-exit instrumentation
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: gcc-patches@gcc.gnu.org, jakub@redhat.com, mliska@suse.cz
Cc: elver@google.com, kasan-dev@googlegroups.com, dvyukov@google.com, 
	bp@alien8.de
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="pVpMfci/";       spf=pass
 (google.com: domain of 3q4zjxgukceymtdmzowwotm.kwusiaiv-lmdowwotmozwcxa.kwu@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3Q4zjXgUKCeYMTdMZOWWOTM.KWUSIaIV-LMdOWWOTMOZWcXa.KWU@flex--elver.bounces.google.com;
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

Adds param tsan-instrument-func-entry-exit, which controls if
__tsan_func_{entry,exit} calls should be emitted or not. The default
behaviour is to emit the calls.

This may be required by alternative race detection runtimes. One such
runtime is the Kernel Concurrency Sanitizer (KCSAN):

	https://github.com/google/ktsan/wiki/KCSAN

After this change, GCC should satisfy all requirements for KCSAN:

	https://lore.kernel.org/lkml/20200515150338.190344-7-elver@google.com/

gcc/ChangeLog:

	* params.opt: Add --param=tsan-instrument-func-entry-exit=.
	* tsan.c (instrument_gimple): Make return value if func entry
	and exit should be instrumented dependent on param.

gcc/testsuite/ChangeLog:

	* c-c++-common/tsan/func_entry_exit.c: New test.
	* c-c++-common/tsan/func_entry_exit_disabled.c: New test.
---
v2:
* Instead of modifying the return value of instrument_gimple(), change
  the boolean expression for fentry_exit_instrument.
* Optimize gimplify and do not emit IFN_TSAN_FUNC_EXIT in a finally
  block if we do not need it.
* Change test to also look at gimple dump.
---
 gcc/gimplify.c                                |  3 +-
 gcc/params.opt                                |  4 +++
 .../c-c++-common/tsan/func_entry_exit.c       | 29 +++++++++++++++++++
 .../tsan/func_entry_exit_disabled.c           | 29 +++++++++++++++++++
 gcc/tsan.c                                    |  4 ++-
 5 files changed, 67 insertions(+), 2 deletions(-)
 create mode 100644 gcc/testsuite/c-c++-common/tsan/func_entry_exit.c
 create mode 100644 gcc/testsuite/c-c++-common/tsan/func_entry_exit_disabled.c

diff --git a/gcc/gimplify.c b/gcc/gimplify.c
index e14932fafaf..416fb609b94 100644
--- a/gcc/gimplify.c
+++ b/gcc/gimplify.c
@@ -15011,7 +15011,8 @@ gimplify_function_tree (tree fndecl)
       bind = new_bind;
     }
 
-  if (sanitize_flags_p (SANITIZE_THREAD))
+  if (sanitize_flags_p (SANITIZE_THREAD)
+      && param_tsan_instrument_func_entry_exit)
     {
       gcall *call = gimple_build_call_internal (IFN_TSAN_FUNC_EXIT, 0);
       gimple *tf = gimple_build_try (seq, call, GIMPLE_TRY_FINALLY);
diff --git a/gcc/params.opt b/gcc/params.opt
index 9b564bb046c..e29a44e7712 100644
--- a/gcc/params.opt
+++ b/gcc/params.opt
@@ -912,6 +912,10 @@ Set the maximum number of instructions executed in parallel in reassociated tree
 Common Joined UInteger Var(param_tsan_distinguish_volatile) IntegerRange(0, 1) Param
 Emit special instrumentation for accesses to volatiles.
 
+-param=tsan-instrument-func-entry-exit=
+Common Joined UInteger Var(param_tsan_instrument_func_entry_exit) Init(1) IntegerRange(0, 1) Param
+Emit instrumentation calls to __tsan_func_entry() and __tsan_func_exit().
+
 -param=uninit-control-dep-attempts=
 Common Joined UInteger Var(param_uninit_control_dep_attempts) Init(1000) IntegerRange(1, 65536) Param Optimization
 Maximum number of nested calls to search for control dependencies during uninitialized variable analysis.
diff --git a/gcc/testsuite/c-c++-common/tsan/func_entry_exit.c b/gcc/testsuite/c-c++-common/tsan/func_entry_exit.c
new file mode 100644
index 00000000000..9c1b697411c
--- /dev/null
+++ b/gcc/testsuite/c-c++-common/tsan/func_entry_exit.c
@@ -0,0 +1,29 @@
+/* { dg-do compile } */
+/* { dg-options "-fdump-tree-gimple -fdump-tree-optimized" } */
+
+int x;
+
+__attribute__((noinline))
+void fn1(void)
+{
+  x++;
+}
+
+__attribute__((noinline))
+void fn2(void)
+{
+  fn1();
+}
+
+__attribute__((noinline))
+int main(int argc, char *argv[])
+{
+  fn1();
+  fn2();
+  return 0;
+}
+
+// { dg-final { scan-tree-dump "TSAN_FUNC_EXIT" "gimple" } }
+// { dg-final { scan-tree-dump-times "__tsan_func_entry" 3 "optimized" } }
+// { dg-final { scan-tree-dump-times "__tsan_func_exit" 3 "optimized" } }
+// { dg-final { scan-tree-dump "__tsan_write" "optimized" } }
diff --git a/gcc/testsuite/c-c++-common/tsan/func_entry_exit_disabled.c b/gcc/testsuite/c-c++-common/tsan/func_entry_exit_disabled.c
new file mode 100644
index 00000000000..63cc73b9eba
--- /dev/null
+++ b/gcc/testsuite/c-c++-common/tsan/func_entry_exit_disabled.c
@@ -0,0 +1,29 @@
+/* { dg-do compile } */
+/* { dg-options "--param=tsan-instrument-func-entry-exit=0 -fdump-tree-gimple -fdump-tree-optimized" } */
+
+int x;
+
+__attribute__((noinline))
+void fn1(void)
+{
+  x++;
+}
+
+__attribute__((noinline))
+void fn2(void)
+{
+  fn1();
+}
+
+__attribute__((noinline))
+int main(int argc, char *argv[])
+{
+  fn1();
+  fn2();
+  return 0;
+}
+
+// { dg-final { scan-tree-dump-not "TSAN_FUNC_EXIT" "gimple" } }
+// { dg-final { scan-tree-dump-not "__tsan_func_entry" "optimized" } }
+// { dg-final { scan-tree-dump-not "__tsan_func_exit" "optimized" } }
+// { dg-final { scan-tree-dump "__tsan_write" "optimized" } }
diff --git a/gcc/tsan.c b/gcc/tsan.c
index 447acccfafd..4d6223454b5 100644
--- a/gcc/tsan.c
+++ b/gcc/tsan.c
@@ -804,7 +804,9 @@ instrument_memory_accesses (bool *cfg_changed)
 	      func_exit_seen = true;
 	    }
 	  else
-	    fentry_exit_instrument |= instrument_gimple (&gsi);
+	    fentry_exit_instrument
+	      |= (instrument_gimple (&gsi)
+		  && param_tsan_instrument_func_entry_exit);
 	}
       if (gimple_purge_dead_eh_edges (bb))
 	*cfg_changed = true;
-- 
2.27.0.290.gba653c62da-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200612140757.246773-1-elver%40google.com.
