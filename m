Return-Path: <kasan-dev+bncBC7OBJGL2MHBBUUZTTZAKGQEUW6KTEQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x340.google.com (mail-wm1-x340.google.com [IPv6:2a00:1450:4864:20::340])
	by mail.lfdr.de (Postfix) with ESMTPS id 23DC315F86F
	for <lists+kasan-dev@lfdr.de>; Fri, 14 Feb 2020 22:10:43 +0100 (CET)
Received: by mail-wm1-x340.google.com with SMTP id w12sf4138903wmc.3
        for <lists+kasan-dev@lfdr.de>; Fri, 14 Feb 2020 13:10:43 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1581714642; cv=pass;
        d=google.com; s=arc-20160816;
        b=LfZrF7N+FA3VD01dUWJR6kgWLCP9RaR1R4K4jSZmEUMuQsG8nBdbZ6pgtUX5nePUv1
         IqFA8qenlXiFiTdTqAA/eZwJWeJy6C9GYIgMtAXS5rdNEutWJlluQ/+qOEH8T6W4+5gR
         jdzbedC6PzCzyEnK/SuBxZ/tieIKMPU0RI48vLYzcDje2V6rFDcbVS0O7Hw4TxDA+i5k
         l3qs/ZjOgT1QE26W+eEcnQoIv3QKCBqwmDDaSbIcsRvURguhBL2u51Z8H1VFLhpmw6ty
         x3rGt1wkkbYa0nBFD09iQ/5dtzvk52GzlmF0sdMEU6pkFiNOUH4f11reGqZvmjbcQGo2
         QR0w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=Yvo8jFWuv/fC0IoysaVga9JeH/jFFnkYYUQn9/8ja/o=;
        b=Qv8GJ0aEEOPyY/Fm+EotbTocNJ80xY9CjFXWXBYhBIPIYZ8Chml/B+enA69r7l4gXi
         sFZQqu80oTWXdAmEfbgq+Dtf4Rek0h+PwipQpVv/pyR9y7LJxV7leuESDW6DRt+EQYd0
         gGlgFuWWt8rCuyFryrIpZLbn32jehjMyZ8BaEJ3lzN9ilDnK2qY1pgYwSbWocbKKHPaG
         AqEp2nWcrVMDhvLIe1Ry9OLy2KX477cVmQ/Bvm4iiKUgML6hTrPPoekcHnJkp2G6N4bb
         6+va3bNGNa1iSQ8AoJHLS0QxjmRy4rNwd9YO+6uidTYGfEsTiH0iF8+f9slIMqZMGtSG
         KZCg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="Ja3/jRqi";
       spf=pass (google.com: domain of 30qxhxgukcf4kr1kxmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=30QxHXgUKCf4kr1kxmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=Yvo8jFWuv/fC0IoysaVga9JeH/jFFnkYYUQn9/8ja/o=;
        b=mUwZ8CkCNMgCq4O56o44IujqSb8/ZMxf8SnOqpSQx1YBI+2OgN/GyRV+FNNmaiCCS8
         CjZvT1j7iRGbuhS8IZhf82u8P4SQkRf1/yMZY1wMLpTDbum2c6nsAo+pi9lC7t6b/ATV
         0Hug4cfJBC4IbmF955H/aO8STDDfKSeJLY7a2C0M/FvDzg/Dsn9JIIGOgerRtuzhX3kM
         rJ7gIB4NSNpUagY2G4qWXO8ouDuxN5sX/IJ0ZuQ5PJjXzsXTqYTdRN2ZQ1yf58Beo44T
         AmN16pSnxEDDbIdqEG9pE7gGgw2WGjhyTSof9vDvUM83ac9swqPZm4sOvYQeoZR5iR01
         rX3g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Yvo8jFWuv/fC0IoysaVga9JeH/jFFnkYYUQn9/8ja/o=;
        b=A5RpTw24zAqJwjqtSrC7xTpBLz4MgKNagMY/bSNpYoyXb/8zvDbjcxD0B5aTYq+TQg
         w8jfbBBMEM8AedEPSmGl7rCPKrH0pto2OKesX6ap1oFOsoYiu20v46OVYcfvsd26+EzD
         i5s8TUZOzfo9Kevf6LOMbRGBzi+FRYQbdn08JIsWMUStBY6V2ogsvHpfTcdCO6rD1NP5
         ZJSCbz5PRAwKGPYayu9mS/Ga/h/8uRBqw8NUBMy5nDPKgq33D2WyHyBxjOCJE8FkutYd
         VIVkmKw35vLMMZ/5sNz9Xttk+UkWk0RTxjrBliwZET0cKns7v3EppITCEGRoe/eHsZf1
         vDkA==
X-Gm-Message-State: APjAAAWTmcnQVDqHqshULSB9uS9aVQlhPR2fMnFrL5S/aksqUWfFd2eu
	r6lIqQ2Ueu3WcTH9OR0f7HI=
X-Google-Smtp-Source: APXvYqxx8WcA2HCIOm1ZdK8N+Gjrp9LwRvQCPxMQQrulLRhJCbfjViDBkYclmx5bDmOKxG5NK5nE+g==
X-Received: by 2002:adf:dd0b:: with SMTP id a11mr6211365wrm.150.1581714642838;
        Fri, 14 Feb 2020 13:10:42 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:7e50:: with SMTP id z77ls1861240wmc.2.canary-gmail; Fri,
 14 Feb 2020 13:10:42 -0800 (PST)
X-Received: by 2002:a7b:c08d:: with SMTP id r13mr6766286wmh.104.1581714642206;
        Fri, 14 Feb 2020 13:10:42 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1581714642; cv=none;
        d=google.com; s=arc-20160816;
        b=KJBlvhYSc+yjEatW9igS/Xaj3e/5XsqtNDPE6lGQ5p/V2Mkw2keQ52atSE7Eo3vNxJ
         gOYXXYHKggbVurXVJamHt6Nst2lWKmEW8KBA2YiyRKdRyvVpw8Q2KseuZPOe/fsc/sot
         OoCbxUcz6LAIdvCtxIIF70B8P4LfeJVo1XaTAKzPutTz2hJXYY1AdB4WFj0hrqT0Jm2L
         gwgQ64ndIJUa8qlhtntqKsLhdw/trxcREXdqsvhJ5LwvTpCrLBUNXmfmpsrs4KhSStvS
         YMk2Epb3YeyGNUeaFZnTrn6pFohto40mlv/txkEdXCDQ+Hdg80ISdrY+51PoI88VETvT
         X0mg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=Ufl0bc7Q05nhLG68rp3n5GYIY7pKcd3WxY8W5KB8D0U=;
        b=l9ioh9AgHiUQEllcQHvBo3mNv4b57QNseCL7QM43V2ZdbAABVx3ZFSgN3ItwvbtK3O
         EJ8usyVO4tp03IAqASqvUZ8ywL1LvtSaTBaFs8Orklfo6IyRhg4IPpZvcUTTKIvzRL/2
         QqHQ4lm/OZAOuxjY7dPR/wD8zkps8hrGj8tDcTMgyZqhrjjr1n/mGvlJEElj2DQp0dPh
         HzDiJhQa3XRt4t+Kfauk4VeFY80LoDREuMnl3uMS4adL4zCIGCakax5/JIpCi1UwUJt3
         5dSq/zBIBDPn2kg1S/rFoIIHkYCDWxxo5nzPWdo0R/PvkruwYgisxQ5HvUaeC2JIK60K
         UURw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="Ja3/jRqi";
       spf=pass (google.com: domain of 30qxhxgukcf4kr1kxmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=30QxHXgUKCf4kr1kxmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x34a.google.com (mail-wm1-x34a.google.com. [2a00:1450:4864:20::34a])
        by gmr-mx.google.com with ESMTPS id m2si184779wmi.3.2020.02.14.13.10.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 14 Feb 2020 13:10:42 -0800 (PST)
Received-SPF: pass (google.com: domain of 30qxhxgukcf4kr1kxmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) client-ip=2a00:1450:4864:20::34a;
Received: by mail-wm1-x34a.google.com with SMTP id z7so4554655wmi.0
        for <kasan-dev@googlegroups.com>; Fri, 14 Feb 2020 13:10:42 -0800 (PST)
X-Received: by 2002:a5d:5485:: with SMTP id h5mr1534876wrv.346.1581714641597;
 Fri, 14 Feb 2020 13:10:41 -0800 (PST)
Date: Fri, 14 Feb 2020 22:10:35 +0100
Message-Id: <20200214211035.209972-1-elver@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.25.0.265.gbab2e86ba0-goog
Subject: [PATCH v2] kcsan, trace: Make KCSAN compatible with tracing
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com
Cc: paulmck@kernel.org, andreyknvl@google.com, glider@google.com, 
	dvyukov@google.com, kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	rostedt@goodmis.org, mingo@redhat.com, x86@kernel.org, Qian Cai <cai@lca.pw>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="Ja3/jRqi";       spf=pass
 (google.com: domain of 30qxhxgukcf4kr1kxmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=30QxHXgUKCf4kr1kxmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--elver.bounces.google.com;
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

Previously the system would lock up if ftrace was enabled together with
KCSAN. This is due to recursion on reporting if the tracer code is
instrumented with KCSAN.

To avoid this for all types of tracing, disable KCSAN instrumentation
for all of kernel/trace.

Furthermore, since KCSAN relies on udelay() to introduce delay, we have
to disable ftrace for udelay() (currently done for x86) in case KCSAN is
used together with lockdep and ftrace. The reason is that it may corrupt
lockdep IRQ flags tracing state due to a peculiar case of recursion
(details in Makefile comment).

Signed-off-by: Marco Elver <elver@google.com>
Reported-by: Qian Cai <cai@lca.pw>
Cc: Paul E. McKenney <paulmck@kernel.org>
Cc: Steven Rostedt <rostedt@goodmis.org>
---
v2:
*  Fix KCSAN+lockdep+ftrace compatibility.
---
 arch/x86/lib/Makefile | 5 +++++
 kernel/kcsan/Makefile | 2 ++
 kernel/trace/Makefile | 3 +++
 3 files changed, 10 insertions(+)

diff --git a/arch/x86/lib/Makefile b/arch/x86/lib/Makefile
index 432a077056775..6110bce7237bd 100644
--- a/arch/x86/lib/Makefile
+++ b/arch/x86/lib/Makefile
@@ -8,6 +8,11 @@ KCOV_INSTRUMENT_delay.o	:= n
 
 # KCSAN uses udelay for introducing watchpoint delay; avoid recursion.
 KCSAN_SANITIZE_delay.o := n
+ifdef CONFIG_KCSAN
+# In case KCSAN+lockdep+ftrace are enabled, disable ftrace for delay.o to avoid
+# lockdep -> [other libs] -> KCSAN -> udelay -> ftrace -> lockdep recursion.
+CFLAGS_REMOVE_delay.o = $(CC_FLAGS_FTRACE)
+endif
 
 # Early boot use of cmdline; don't instrument it
 ifdef CONFIG_AMD_MEM_ENCRYPT
diff --git a/kernel/kcsan/Makefile b/kernel/kcsan/Makefile
index df6b7799e4927..d4999b38d1be5 100644
--- a/kernel/kcsan/Makefile
+++ b/kernel/kcsan/Makefile
@@ -4,6 +4,8 @@ KCOV_INSTRUMENT := n
 UBSAN_SANITIZE := n
 
 CFLAGS_REMOVE_core.o = $(CC_FLAGS_FTRACE)
+CFLAGS_REMOVE_debugfs.o = $(CC_FLAGS_FTRACE)
+CFLAGS_REMOVE_report.o = $(CC_FLAGS_FTRACE)
 
 CFLAGS_core.o := $(call cc-option,-fno-conserve-stack,) \
 	$(call cc-option,-fno-stack-protector,)
diff --git a/kernel/trace/Makefile b/kernel/trace/Makefile
index f9dcd19165fa2..6b601d88bf71e 100644
--- a/kernel/trace/Makefile
+++ b/kernel/trace/Makefile
@@ -6,6 +6,9 @@ ifdef CONFIG_FUNCTION_TRACER
 ORIG_CFLAGS := $(KBUILD_CFLAGS)
 KBUILD_CFLAGS = $(subst $(CC_FLAGS_FTRACE),,$(ORIG_CFLAGS))
 
+# Avoid recursion due to instrumentation.
+KCSAN_SANITIZE := n
+
 ifdef CONFIG_FTRACE_SELFTEST
 # selftest needs instrumentation
 CFLAGS_trace_selftest_dynamic.o = $(CC_FLAGS_FTRACE)
-- 
2.25.0.265.gbab2e86ba0-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200214211035.209972-1-elver%40google.com.
