Return-Path: <kasan-dev+bncBC7OBJGL2MHBBFXJVT3QKGQEZ4FCCFA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x640.google.com (mail-pl1-x640.google.com [IPv6:2607:f8b0:4864:20::640])
	by mail.lfdr.de (Postfix) with ESMTPS id 8C8DF1FEEB3
	for <lists+kasan-dev@lfdr.de>; Thu, 18 Jun 2020 11:32:07 +0200 (CEST)
Received: by mail-pl1-x640.google.com with SMTP id 59sf3474171pla.12
        for <lists+kasan-dev@lfdr.de>; Thu, 18 Jun 2020 02:32:07 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1592472726; cv=pass;
        d=google.com; s=arc-20160816;
        b=GZQMj1UdAMXDD0J3X7JnFtBUATrkbD1xEO7jDY2aywHiEK4GwQSwsVH3d0wqxiwWUh
         wqtQKi1IiLBjDTfmWJmrEBaWLHwfVeKUtl4pHcQf8cL/0GIa+Ulw453rgH0U3DUZ718u
         X5A5+SbL2QUABjJXLEg82ASAEBYT6rng4hYdaj3s6gVZBgMuTDBquVuteyqZ4em6mpLP
         p94ipWA/w7jr/4FBOjCnWP8WjOWUdboFJ/2yscs/uHBqLNGOflY9DE+VZIM961velNLU
         NvXobK17rBWgbQyL/JjYPGamSkpW8zQoy+pgOUWy1xMJXKUS8KTct7M6GNcSQkps+mM6
         Hjfw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=JbsfYJbv0AjbUnSfTeOiSCkvXz6auWhUHvxcalkFWVw=;
        b=AUOMGS1ug/k/rvK7ZuTfS4ME30JkYPGm00P9yVYH9MX3nWrYtO4OMcwKrQO+v8U3yP
         RY6QceK4sCLQ3Mlu7BodJD8v4FuPRIq9dbP2qo5/ZWm4axhPZyd/D0gIeFNW2rePoDEa
         uXJ5NNQxhRSvDGTXbifz/DlzOiY/V7HVaNZh/vsaemq1xeOEBnBgnDj3zeTopwljbqmY
         IYnjqsJHV5wapjHkSa0DlTN4rF/cqCa2l7HuEvS2RcGAxfy/wfgdvwRr3yrp5oc0QshZ
         StWTkMuKrpBb+NqruqZekWPXbgxfcEWCrNY2k0HSUmml9x5GMzDRj1NaC9dlQwBpc8g1
         eWrg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=C8BIq7mE;
       spf=pass (google.com: domain of 3ldtrxgukcaclsclynvvnsl.jvtrhzhu-klcnvvnslnyvbwz.jvt@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3lDTrXgUKCacLScLYNVVNSL.JVTRHZHU-KLcNVVNSLNYVbWZ.JVT@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=JbsfYJbv0AjbUnSfTeOiSCkvXz6auWhUHvxcalkFWVw=;
        b=sbsAU2kNHsWrwvRz46oePImsQc3Ge9i+HCuY7N0u5qFCk11LGzYvxUZTX+312dPxGH
         4sO5ch3oIoAMG+alCaN/AH8sszlfJ8p9L4gLB83mO1TMEsKFkdQIYwZgqc4t8U3Ra3sF
         hzQcU4VK5qUtXjvyUT1dYiqMAaWkvGNCasAxctJALkIgPdqK1fyF+DHSWEai1ImPcG0r
         ELEEFR6hRVv/6ezird7jU5SVzvgdgjzzfIY5fR6JBR3WSiPULG/7JNarTwYk0SPZW9j9
         C+HvlpHH3kRhE/daBGwO3Mcm+nNVyeeEj18hRTd8FGJKmH8qWOCGBh19XxSjtmcXh+DQ
         fvDg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=JbsfYJbv0AjbUnSfTeOiSCkvXz6auWhUHvxcalkFWVw=;
        b=IEREA9l+Q31Ru7HbOQjx3RffkGLOsgj1PfXxDaQVUbWHwziHVDs3fDM/c2rpIsmnSc
         88RAWzNSVZp1uK+LRPQcixCk5eWgpwa10ulnv9tKDxaelYD1yqTc51xC2nnGuO8WtbOj
         8sQQ/8w6Dd9HR+fa0OOZtYzHueg/V0c0aJW3Pk4atr0IX3M5aOCDdyQ5K7oUfRfWQ4z0
         E2gt1OCjtDU2t89iuiQxJWViXqrBxi4KKf5xMR+Pk6nstt5q1KjdwWJMrIEf1KsXXkXN
         4R3RscIdFn1KgazU8Dfg29u51NTC97HQdix1xWdnWSKDNifSQCOXDEFivInOqIOByr7+
         5Rwg==
X-Gm-Message-State: AOAM530ejCUkoAKIXBd4/EmmDukA7yOTW0evyaSoNPWzsQbbeIlz/RO2
	PQrBhoujTiHacRvAEAUSPsU=
X-Google-Smtp-Source: ABdhPJyXvOz/iahQYeh3qvlYqzaBOtQJpX9puAEIqXfu+zhnVZQDTLy5n7AHbgvJKS+Q0V94WN5IYQ==
X-Received: by 2002:a17:90a:f684:: with SMTP id cl4mr3400740pjb.172.1592472726139;
        Thu, 18 Jun 2020 02:32:06 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:8548:: with SMTP id d8ls2030244plo.11.gmail; Thu, 18
 Jun 2020 02:32:05 -0700 (PDT)
X-Received: by 2002:a17:90a:f485:: with SMTP id bx5mr3468294pjb.77.1592472725629;
        Thu, 18 Jun 2020 02:32:05 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1592472725; cv=none;
        d=google.com; s=arc-20160816;
        b=t87OZMrRt3azo79Bz7cj+4lA42g1VgPzGGak08e6+Max7+DGRP6wm/y2MKsuMoRLat
         p0bhXPXAN98C7SQ2kzDrMe6S2TfZQ9IvYHhRgXmL43I7C4tFFo95kuPGvXP18xwQABb0
         dslMeSUVpmuy64XB+Jgn6KMw5bMcDRXEfLV0rxRGaJHhAIBmoIPBHzKkmnb6WYkjlt4n
         m6xsiKrdGgL0zpHiR2FnmentDlZf74tlzjqwOoPtr0h9p4XivsA7nPzffx9emRZqEcw4
         +cOHaP8o9+sFPBJirpfc81WgDQ8e7xrb136w8p334ij3YCUAHlpYxkbPEXGTVzGZEuq1
         6Fqg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=wAC/0zMBk1R1mKjHS4CraP1dln5upgDgvVtxjRPVBbA=;
        b=IRUGU4N9V09EDUnk7AkKa088TGUP0bVS/S8fivuXARJSMeHWZyfqdtGWPLlXJhyep6
         1wKaPd21/3hsb2UB3uU2yXmLsaQjKI81OlgEbwjJM9My3JLtkTuiSb399HWFJ0clIHk6
         t6Zvxx0UkT33JRELY2fIJgQoXPnIjPXxx3oTs0i0ZJI3uXKbtAV9GPYRqWJWhOB1ntKh
         NHUagZh3/NDAG6DAXIaTZBlJpDZUU4mva2zykDzF8q4qe6w8fM4wvv36opThF9t2Ds4s
         9k281Y/b57iu6qkvZH+bAIAFdGO7fphQbqmfnWoWJ97Zg8lqbWlqDhZbQL8Xe3FtwDei
         KSiw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=C8BIq7mE;
       spf=pass (google.com: domain of 3ldtrxgukcaclsclynvvnsl.jvtrhzhu-klcnvvnslnyvbwz.jvt@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3lDTrXgUKCacLScLYNVVNSL.JVTRHZHU-KLcNVVNSLNYVbWZ.JVT@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb49.google.com (mail-yb1-xb49.google.com. [2607:f8b0:4864:20::b49])
        by gmr-mx.google.com with ESMTPS id p9si105591plr.1.2020.06.18.02.32.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 18 Jun 2020 02:32:05 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3ldtrxgukcaclsclynvvnsl.jvtrhzhu-klcnvvnslnyvbwz.jvt@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) client-ip=2607:f8b0:4864:20::b49;
Received: by mail-yb1-xb49.google.com with SMTP id n11so5776535ybg.15
        for <kasan-dev@googlegroups.com>; Thu, 18 Jun 2020 02:32:05 -0700 (PDT)
X-Received: by 2002:a25:348a:: with SMTP id b132mr5314699yba.491.1592472724817;
 Thu, 18 Jun 2020 02:32:04 -0700 (PDT)
Date: Thu, 18 Jun 2020 11:31:18 +0200
In-Reply-To: <20200618093118.247375-1-elver@google.com>
Message-Id: <20200618093118.247375-4-elver@google.com>
Mime-Version: 1.0
References: <20200618093118.247375-1-elver@google.com>
X-Mailer: git-send-email 2.27.0.290.gba653c62da-goog
Subject: [PATCH 3/3] kcsan: Disable branch tracing in core runtime
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, paulmck@kernel.org
Cc: will@kernel.org, peterz@infradead.org, bp@alien8.de, tglx@linutronix.de, 
	mingo@kernel.org, dvyukov@google.com, cai@lca.pw, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=C8BIq7mE;       spf=pass
 (google.com: domain of 3ldtrxgukcaclsclynvvnsl.jvtrhzhu-klcnvvnslnyvbwz.jvt@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3lDTrXgUKCacLScLYNVVNSL.JVTRHZHU-KLcNVVNSLNYVbWZ.JVT@flex--elver.bounces.google.com;
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

Disable branch tracing in core KCSAN runtime if branches are being
traced (TRACE_BRANCH_PROFILING). This it to avoid its performance
impact, but also avoid recursion in case KCSAN is enabled for the branch
tracing runtime.

The latter had already been a problem for KASAN:
https://lore.kernel.org/lkml/CANpmjNOeXmD5E3O50Z3MjkiuCYaYOPyi+1rq=GZvEKwBvLR0Ug@mail.gmail.com/

Signed-off-by: Marco Elver <elver@google.com>
---
 kernel/kcsan/Makefile | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/kernel/kcsan/Makefile b/kernel/kcsan/Makefile
index fea064afc4f7..65ca5539c470 100644
--- a/kernel/kcsan/Makefile
+++ b/kernel/kcsan/Makefile
@@ -8,7 +8,7 @@ CFLAGS_REMOVE_debugfs.o = $(CC_FLAGS_FTRACE)
 CFLAGS_REMOVE_report.o = $(CC_FLAGS_FTRACE)
 
 CFLAGS_core.o := $(call cc-option,-fno-conserve-stack) \
-	-fno-stack-protector
+	-fno-stack-protector -DDISABLE_BRANCH_PROFILING
 
 obj-y := core.o debugfs.o report.o
 obj-$(CONFIG_KCSAN_SELFTEST) += selftest.o
-- 
2.27.0.290.gba653c62da-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200618093118.247375-4-elver%40google.com.
