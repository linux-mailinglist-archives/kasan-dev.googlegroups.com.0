Return-Path: <kasan-dev+bncBAABBPNGTLZQKGQEHKXXC2Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3d.google.com (mail-io1-xd3d.google.com [IPv6:2607:f8b0:4864:20::d3d])
	by mail.lfdr.de (Postfix) with ESMTPS id B06AD17E7DD
	for <lists+kasan-dev@lfdr.de>; Mon,  9 Mar 2020 20:04:30 +0100 (CET)
Received: by mail-io1-xd3d.google.com with SMTP id d16sf7222934iop.17
        for <lists+kasan-dev@lfdr.de>; Mon, 09 Mar 2020 12:04:30 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1583780669; cv=pass;
        d=google.com; s=arc-20160816;
        b=eE7iB99ZCimn4pLeH5hAGlB2ZRM3yvgAuI8tSb5ZCWY7NWCB5NOB1BwkIsHR4fbonA
         2MPMMDsydamxSTSHBBsT/OM2P6M2LuHk9U2s3DfN0fot6NGUg78zu7+ghtmgqO0doqwO
         kgXGsJbjNxfF46ZccmDznwoWgdxyyxaKYt1OxMo8vhWWh1avgDM82nlPF+WNVgvhgzqM
         pfqxczGLk69GuIkaQ1WY8vV6dUz3NQorLH36ATolH5tuvNDIz70JkYj8vYhA200E9MHd
         YtO7RsiQgIgkUpUTIlplFtOdSAvNkcScP2xoLudQIGlFHSPbLnH81FENJGm4/bWZGzg7
         ZzOA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:references:in-reply-to:message-id
         :date:subject:cc:to:from:mime-version:sender:dkim-signature;
        bh=Rw7NNnFkd1S73KL9CMUkuCEsN6HRpT18+WuSQ531xaw=;
        b=tlWfndl5X4tiHM+xUotGNRFAlqgKZclvR1BvjUAzRBtTQ3id9Bqpf1Y1/GDwHh4iH/
         XDZ0Snt0sJFwaBcKPpU7jMbirXQZcUY9ye5rJtRSM67JJQIjATkGd0xll+arRc7VXwKq
         PsKDS1uDbrrAEPoF3XrT/6rNSbVnx9EDW/yVui74xL9gwYQYgfqJhRDVeZy7oBzgOmVS
         R2cIHYCAfsCla2OTndqyos7+EqVhnH6bx1gxtSXJ437zHXsH4jrKh/wrwlO/TLEbmFKE
         vaKRW2dtF0/MrV6GaSPcvsoAf8/LlKXBzcwwRmqN422mvX0bUs/RcRvSBibpLeUtpyWU
         VaDg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=pDsVVlZ+;
       spf=pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=paulmck@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:from:to:cc:subject:date:message-id:in-reply-to
         :references:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Rw7NNnFkd1S73KL9CMUkuCEsN6HRpT18+WuSQ531xaw=;
        b=Bdx4h/6K5XHIQcoCfMHiXf3MOgWSfYNcanCyHGtecwCJgUVr/AFNkqYzaBE9Hug2as
         ji9Vs00L5ABNAwJewr3yEKhIQrS0qRwqdGs/fDwzMyPjsfl6w4YMU89yf65x8HGJ4TmU
         ktgUDm/3iMkCK/5aAdf/xUgTNGmc6OKEpDPPX3jRr8xIWnlxo42MzgFJpiJ00cFw5Y28
         FOsrNp8i4jlUExy+NQqwvwSoeeMWQkL/PSNjT57eSScrvYcHHyyr/tpvuGTdYXZTJZ8s
         EtKpPygz2ASZvgcX2+fW//aI2/B9RfG+rWbUk0pI6dqo7EdVS+CLmoBBw7lgrpFFV1Di
         Swdg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:from:to:cc:subject:date
         :message-id:in-reply-to:references:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Rw7NNnFkd1S73KL9CMUkuCEsN6HRpT18+WuSQ531xaw=;
        b=pEFf0teRg6cac2pGxLbB5pi1OzsoxYy/uy+5OZLffTBSd/6HyL3wYzOXqxvCWX8/Yv
         F126mmW1JuPsYy+wpDZn6joxe+VA4w0TMuvSmHBbHpW1OgxxfgLEgLWq9zyucclsNnRF
         RweVkZhazOdtzOKqUoip1eZlcaK+tU3R7Q3O4EZAihHe9YgaSqZ833vC4ui3/dr3OSXq
         4BclPtoi72hL6EgNCK31bnKuebioOtVEoalSvxxKawEfEEVBCT8WLvb9UhcXIaMIA9Fq
         9thXVuKfUC0Pq7d1E1Dk6rwmnTh/qZaDGOFYQr4A2gXljdKkCNqFtLZUjLYGO83LXDVD
         F+UQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANhLgQ2yUdKJ1Iv+FjYQ95yWm9ZoVqeZn70AUcjgrsQ6SgJ2r+1jgGxe
	TPlLwVWrqTbV6TGjOdwlLNU=
X-Google-Smtp-Source: ADFU+vslLgBTfWDjenfMN3ik4SqQTY6uEglIlDy1igeX8bEhemit3xHAMvPmySazOXno8qe902SVhw==
X-Received: by 2002:a6b:7c04:: with SMTP id m4mr14624096iok.208.1583780669633;
        Mon, 09 Mar 2020 12:04:29 -0700 (PDT)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:cfc7:: with SMTP id y7ls2736523ilr.6.gmail; Mon, 09 Mar
 2020 12:04:29 -0700 (PDT)
X-Received: by 2002:a92:c80e:: with SMTP id v14mr17836024iln.259.1583780669310;
        Mon, 09 Mar 2020 12:04:29 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1583780669; cv=none;
        d=google.com; s=arc-20160816;
        b=eTrDUIUrVCjkdVuo+Io0f4SLk3gkQiK2kEpI1T4KJp+uw4rvJKrpPPKx+Rf/ULb9fF
         5f9SqKmTTNt8UXOomHzl59ffAE27aVGb9PkDQII3PT0TS1NAtPIF8QsCWHhKGp4yfrXw
         MV6QlqDB+kqIPt/Ys8KETrQaKd/361nPymWBe5cm+/v8Qh5L4+V3uisl7bGxc5w1sM4x
         +MziK2qxgjzxhgbuIMMD50EnEGEISp168AG79lohhb04bQiHm28PvNgnqyIDnwRU/swN
         cYsZYk15/xxjaJ2wv/LsNW2B4uuJMaHeXKoygC4iBkrOvYI80zbPtEgzzbAhE45whiyH
         KWMg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=references:in-reply-to:message-id:date:subject:cc:to:from
         :dkim-signature;
        bh=9lhj7nT7XzJ+Tj7SxsRHezvOwRlQAKZy4KBye0MrdLM=;
        b=Se2iUyDEcJq/ugTtdDrLAUwChJr0BCnIzIcqHWtFRMeFc50VArcH42CWshQnKE4h2p
         mxC18tUVgxjd64hqoJG3jMWrw3wHPSM3q3TDdMQ4FWYVv+UaxEMXWe0zwP3CDfH1U3a0
         ZOqEC4XkgUXdSrDz5tELamskMKivyyf15JXpxsTz0sO0M1taNUDbmHAEs6eVNJAJJ4XF
         8Bsux15evTeO9Fa+pGC/bQW8hOo6/+ayUuZwn7AARZLBIlBIRbqviDonmA9mPVLJ4Qeg
         HTiWZtfSoByQWL1TlVzoGwvka0Gb9g9v3W3kVwuOAhKXVKV5qUjgBDVjBZ15HfRYrd4F
         SUKg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=pDsVVlZ+;
       spf=pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=paulmck@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id k88si146004ilg.1.2020.03.09.12.04.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 09 Mar 2020 12:04:29 -0700 (PDT)
Received-SPF: pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (50-39-105-78.bvtn.or.frontiernet.net [50.39.105.78])
	(using TLSv1.2 with cipher ECDHE-RSA-AES128-GCM-SHA256 (128/128 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 9A1CA22525;
	Mon,  9 Mar 2020 19:04:28 +0000 (UTC)
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
	"Paul E . McKenney" <paulmck@kernel.org>,
	Steven Rostedt <rostedt@goodmis.org>
Subject: [PATCH kcsan 26/32] kcsan, trace: Make KCSAN compatible with tracing
Date: Mon,  9 Mar 2020 12:04:14 -0700
Message-Id: <20200309190420.6100-26-paulmck@kernel.org>
X-Mailer: git-send-email 2.9.5
In-Reply-To: <20200309190359.GA5822@paulmck-ThinkPad-P72>
References: <20200309190359.GA5822@paulmck-ThinkPad-P72>
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=pDsVVlZ+;       spf=pass
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
Signed-off-by: Paul E. McKenney <paulmck@kernel.org>
Tested-by: Qian Cai <cai@lca.pw>
---
 arch/x86/lib/Makefile | 5 +++++
 kernel/kcsan/Makefile | 2 ++
 kernel/trace/Makefile | 3 +++
 3 files changed, 10 insertions(+)

diff --git a/arch/x86/lib/Makefile b/arch/x86/lib/Makefile
index 432a077..6110bce7 100644
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
index df6b779..d4999b3 100644
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
index 0e63db6..9072486 100644
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
2.9.5

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200309190420.6100-26-paulmck%40kernel.org.
