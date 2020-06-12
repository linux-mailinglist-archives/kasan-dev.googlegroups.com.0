Return-Path: <kasan-dev+bncBC7OBJGL2MHBBDNCRX3QKGQEDABKRZA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63b.google.com (mail-pl1-x63b.google.com [IPv6:2607:f8b0:4864:20::63b])
	by mail.lfdr.de (Postfix) with ESMTPS id E90281F7643
	for <lists+kasan-dev@lfdr.de>; Fri, 12 Jun 2020 11:55:26 +0200 (CEST)
Received: by mail-pl1-x63b.google.com with SMTP id be7sf5810193plb.21
        for <lists+kasan-dev@lfdr.de>; Fri, 12 Jun 2020 02:55:26 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1591955725; cv=pass;
        d=google.com; s=arc-20160816;
        b=BgF5D53pLRW2O9Eq3MSujyJut8cl4eFLFNzi6V7DKOM+v4SZRgQ+paFYcnYFlCHYuu
         gj2PbfP79Uph8x67BlBmTqkLsE+F9KB3hVgaU7/lrRmG3nOmiWxbJrmZmdeNhUdCC9uq
         CbCj7Esj4S2cGK12fZOY1LeBELWW52F3e+RFLRyj8CJwQ8VL5W5VAKFsTgaPAM1wBZLZ
         7EteXJViUEeUfiB3QXic2EJ/4C06BtK3ymLtWMo2QKY7SQb1SSWc/zz9QthIQX+WzPJn
         o5fZyqpT+SEZDRnK4+TLXHat4j77OKacneNiFw41XWhtSbtYPwTCrGUj9NAwbjWe4xOc
         JS5w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=GFupi1Ya9NdbvL3UIZ5oKDruQcCbHDp9WY0GGpVVlVE=;
        b=iGn1p5agd796hdpbaqvZ0uTZDSXwKX17XFA0Lkgc4DGg5Y3STOVFYAqZW1NFqkRDIA
         F/wvXeZc4uCWUKseqGjQF2wOdvtbAapAWfgeWM7rWkp71K+vXeT/1WsWHapSU7eOLkeQ
         nVp3UMrCm6s3DAR9U/3HE1CnYZMA38viw1UKvkoM9BZoLL0Qkrr4Ceko+Z3BrcLCZwV6
         FvTcAR+t5xV4fHWkLMWJZTnw+gH21KcQOOVyfHLDwdR4bDQSBAQUs6gTCM46kgN3ZD3R
         /pDQPsMyVFTQAT6RKlpsOIkVoer4JiIsqoKB4iL0LwUyzU7wmFw50UzAB3J7kEtYqBGN
         AZXg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Cuigmyka;
       spf=pass (google.com: domain of 3dfhjxgukctkzgqzmbjjbgz.xjhfvnvi-yzqbjjbgzbmjpkn.xjh@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3DFHjXgUKCTkZgqZmbjjbgZ.XjhfVnVi-YZqbjjbgZbmjpkn.Xjh@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=GFupi1Ya9NdbvL3UIZ5oKDruQcCbHDp9WY0GGpVVlVE=;
        b=UCw5MZ3FW4UUV2Q25ajo9O09mRQoe/MazvxaRwqrTthafgfRjOe66BFKXvl9jeTEeR
         fabY/Egc/SYRd23Q3ldAwAu+zZhuRfYUeXJuxFOtn0J1TjvTdBGQT1iI1tpDV2dd5JkU
         p2X+Qtuh3nfcltMRA7X/dzGnTMTWk3ZncgqKDTJXdD+49yeIzwBQTb38uZ3F0GRPP5rO
         fHcnD3YCXXGhXPdSnY9AWh1E5PXhat0hsP/Fyv3ziikCUD75Owud1Ye8QtVH7KEO04E3
         Da/P2h3eNTNfxbq/oDjjDJgV3+b5KC+psyb4wFI/JbB/GBG52WWbZ2ezv2oYKWp+uBdB
         pN7g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=GFupi1Ya9NdbvL3UIZ5oKDruQcCbHDp9WY0GGpVVlVE=;
        b=qOGd50kfZC32etmnKlOPy9I0g157YW+pGk9g1qglOcxQE/lIvD/RQA1/fQgEZKn4Df
         3fR3RCzhpQx91/3EC0KEbQraznaiE9uC+/ol42791xAzBUuP5Do4Un2pC8U+XAmyFGRI
         dvefUWTPKDRDzvrQEkx1y/joMKhiEghlXYv+iaiHBGX5W2AB9mx4PU0cFnTWlnqTXl1s
         5LiyQvwCDNNizhKATAcaQO4tadRO9Q41CMXH2hK3HKOeoFPJmMq1CNfsgDImFrHbOP3V
         hiWiMaLztdFKnp4KLtCrAVwVvS5yH5QGNrrVEsfK3io9QNqEoY0TbgO8mREUUM1XATEK
         KjLQ==
X-Gm-Message-State: AOAM531WGNzVRfQFCkuxcJiQ0tk8RmXwclawHss1oLXNt+emwMclv76E
	LhEZQMT5gEgxIGbh3a+aNl4=
X-Google-Smtp-Source: ABdhPJxO+mIalxZwmbMLReZjgsakrVjM2Zfmm4uVoqvl55KYfZafmbc6Uz41ViI7xU9BJcAvyVChlw==
X-Received: by 2002:a63:6dc2:: with SMTP id i185mr10077195pgc.250.1591955725655;
        Fri, 12 Jun 2020 02:55:25 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:7b91:: with SMTP id w17ls1923214pll.10.gmail; Fri,
 12 Jun 2020 02:55:25 -0700 (PDT)
X-Received: by 2002:a17:90a:7643:: with SMTP id s3mr12506399pjl.183.1591955725106;
        Fri, 12 Jun 2020 02:55:25 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1591955725; cv=none;
        d=google.com; s=arc-20160816;
        b=ZBimzbLC6Kwwt9PjZ3Ih+JIW7P3YcXz8Q6W2C0FqiWKWfEbMgDzSrdpy/t/vICAYC7
         1/dSUje3QMVG4M34cCvoxZne2njMNwu/yfo+2JHa15NnRIFXb7OFhit3/Fa/Z+yCe3Li
         XLLpuaid7OE+EUkLclSOhSf3laZEDBOU4YT+m2DV5Ro45jIFXwijOVZ78GUCirnlrHIu
         gOIKGtw0lKWQpIQzRDOAYa3frv9uG95QT1PyiUEaC/ey9y+VuWBhf/XJh1tOxcxIOY+G
         fiWhaAv5hWqG0xE3xorjM3KW0akbaItWiCAg12Jrel6ul3Nv5LdM/jMnkhgIiq93O29j
         stFA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=I5vEU/xhtT/AM8U7bKJzWmndmRQJCON9OMkB3XH+R0M=;
        b=MZnkFIGkpz0c0nVkuvrxYmzI2YDSQmHBrqKkW13a67M54Wn/xnm6R5Ni+1RUSvaO2h
         JZaID4cE5iPCxbwl9wW+W9tgadg5neAPnZq0SUS9zJ4i8Z/aTCqXs/0QmZ046W+7VP1A
         nCzgK8zU8aXGTESJJiq1dk9FQZuXEWnllq3TfpNLbrq02LYwxzYA4M59YqIp6EuZbM4n
         A0bSlRFZ9Ou84BQh881qS2QunQKm3NMNAmWObtCLWpd8v3BT0EmS9LZCH+ZQyFaos2i0
         NXvpEzTng/l0faGTVHxzLkdHt1oAP5S1IsJsdgeOk2YuWJxr51iiB+s3zX7kpTMsU1F/
         Umag==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Cuigmyka;
       spf=pass (google.com: domain of 3dfhjxgukctkzgqzmbjjbgz.xjhfvnvi-yzqbjjbgzbmjpkn.xjh@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3DFHjXgUKCTkZgqZmbjjbgZ.XjhfVnVi-YZqbjjbgZbmjpkn.Xjh@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x84a.google.com (mail-qt1-x84a.google.com. [2607:f8b0:4864:20::84a])
        by gmr-mx.google.com with ESMTPS id b2si377964plz.5.2020.06.12.02.55.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 12 Jun 2020 02:55:25 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3dfhjxgukctkzgqzmbjjbgz.xjhfvnvi-yzqbjjbgzbmjpkn.xjh@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) client-ip=2607:f8b0:4864:20::84a;
Received: by mail-qt1-x84a.google.com with SMTP id q21so7122436qtn.20
        for <kasan-dev@googlegroups.com>; Fri, 12 Jun 2020 02:55:25 -0700 (PDT)
X-Received: by 2002:a05:6214:11a1:: with SMTP id u1mr11766236qvv.91.1591955724101;
 Fri, 12 Jun 2020 02:55:24 -0700 (PDT)
Date: Fri, 12 Jun 2020 09:21:59 +0200
Message-Id: <20200612072159.187505-1-elver@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.27.0.290.gba653c62da-goog
Subject: [PATCH] tsan: Add param to disable func-entry-exit instrumentation
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: gcc-patches@gcc.gnu.org, jakub@redhat.com, mliska@suse.cz
Cc: elver@google.com, kasan-dev@googlegroups.com, dvyukov@google.com, 
	bp@alien8.de
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=Cuigmyka;       spf=pass
 (google.com: domain of 3dfhjxgukctkzgqzmbjjbgz.xjhfvnvi-yzqbjjbgzbmjpkn.xjh@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3DFHjXgUKCTkZgqZmbjjbgZ.XjhfVnVi-YZqbjjbgZbmjpkn.Xjh@flex--elver.bounces.google.com;
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
	* tsan.c (instrument_gimple): Make return value if
	  func entry and exit  should be instrumented dependent on
	  param.

gcc/testsuite/ChangeLog:

	* c-c++-common/tsan/func_entry_exit.c: New test.
	* c-c++-common/tsan/func_entry_exit_disabled.c: New test.
---
 gcc/params.opt                                |  4 +++
 .../c-c++-common/tsan/func_entry_exit.c       | 28 +++++++++++++++++++
 .../tsan/func_entry_exit_disabled.c           | 28 +++++++++++++++++++
 gcc/tsan.c                                    |  4 +--
 4 files changed, 62 insertions(+), 2 deletions(-)
 create mode 100644 gcc/testsuite/c-c++-common/tsan/func_entry_exit.c
 create mode 100644 gcc/testsuite/c-c++-common/tsan/func_entry_exit_disabled.c

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
index 00000000000..5bb524c73ae
--- /dev/null
+++ b/gcc/testsuite/c-c++-common/tsan/func_entry_exit.c
@@ -0,0 +1,28 @@
+/* { dg-do compile } */
+/* { dg-options "-fdump-tree-optimized" } */
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
+// { dg-final { scan-tree-dump-times "__tsan_func_entry" 3 "optimized" } }
+// { dg-final { scan-tree-dump-times "__tsan_func_exit" 3 "optimized" } }
+// { dg-final { scan-tree-dump "__tsan_write" "optimized" } }
diff --git a/gcc/testsuite/c-c++-common/tsan/func_entry_exit_disabled.c b/gcc/testsuite/c-c++-common/tsan/func_entry_exit_disabled.c
new file mode 100644
index 00000000000..b7e0d9d1019
--- /dev/null
+++ b/gcc/testsuite/c-c++-common/tsan/func_entry_exit_disabled.c
@@ -0,0 +1,28 @@
+/* { dg-do compile } */
+/* { dg-options "--param=tsan-instrument-func-entry-exit=0 -fdump-tree-optimized" } */
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
+// { dg-final { scan-tree-dump-not "__tsan_func_entry" "optimized" } }
+// { dg-final { scan-tree-dump-not "__tsan_func_exit" "optimized" } }
+// { dg-final { scan-tree-dump "__tsan_write" "optimized" } }
diff --git a/gcc/tsan.c b/gcc/tsan.c
index 447acccfafd..02625a952c3 100644
--- a/gcc/tsan.c
+++ b/gcc/tsan.c
@@ -718,7 +718,7 @@ instrument_gimple (gimple_stmt_iterator *gsi)
       gimple_call_set_tail (as_a <gcall *> (stmt), false);
       if (gimple_call_builtin_p (stmt, BUILT_IN_NORMAL))
 	instrument_builtin_call (gsi);
-      return true;
+      return param_tsan_instrument_func_entry_exit;
     }
   else if (is_gimple_assign (stmt)
 	   && !gimple_clobber_p (stmt))
@@ -734,7 +734,7 @@ instrument_gimple (gimple_stmt_iterator *gsi)
 	  instrumented = instrument_expr (*gsi, rhs, false);
 	}
     }
-  return instrumented;
+  return param_tsan_instrument_func_entry_exit && instrumented;
 }
 
 /* Replace TSAN_FUNC_EXIT internal call with function exit tsan builtin.  */
-- 
2.27.0.290.gba653c62da-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200612072159.187505-1-elver%40google.com.
