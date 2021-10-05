Return-Path: <kasan-dev+bncBC7OBJGL2MHBBJXA6CFAMGQEJ3JF5FA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23b.google.com (mail-oi1-x23b.google.com [IPv6:2607:f8b0:4864:20::23b])
	by mail.lfdr.de (Postfix) with ESMTPS id 97B4E42240D
	for <lists+kasan-dev@lfdr.de>; Tue,  5 Oct 2021 12:59:51 +0200 (CEST)
Received: by mail-oi1-x23b.google.com with SMTP id v18-20020acaac12000000b0027652280a72sf10502911oie.17
        for <lists+kasan-dev@lfdr.de>; Tue, 05 Oct 2021 03:59:51 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1633431590; cv=pass;
        d=google.com; s=arc-20160816;
        b=YMWgdMSD1VPUYFpuAljUg/inWFRTypPy8sWZpZKh6jDn+dR170qpWAfkbBYlG1SSS2
         LpKEcNMYTrVNVwuibpl7FRmfpiYffeT4K+7yJbdVSwWkcbwMRYDHk/W5ENphUEXG+mvL
         V3i/h8O8DuVFytRC4Z178A7+kSvkY7qEZGV+9kFjLg9+Lb+dJsOEQ0JrMVRbBLIUgu2U
         XWP8NcQU+a2V5mXTwkdA9rrNaRHlPfrU4+hc4+62CqSMU1/ahnRSYSJN0/6n2eBdoFdt
         zdYwCaJvTH7ht8o72FajlYYKAat7xvIV/d/Y/yrGOY8pbgS84yKCR08UiXfP7lB9u1ii
         icDQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=0+bPT5A9aQOnA5Cj4aeZMHtRJZAlu6u2+QoRfMhTHO0=;
        b=atmMKkgVJyf2oZBAPKdbdnc4NsUiKaesCkaGbKIAcaisvzffYAkLunk/lMPL87QMms
         YYsu2Wmc3gLreSpU+epduEqIGsdL+L9ZhJ6g9I+L+V9LwLQO+pWw120orKKgbnOO9mU8
         oNseP/K0yZNl9pSbeTNirKECpg1jVLqu4YxYQMopShwvjYhDNyXfy+hfvyqY59SweYEd
         OctAny4nFPf3clToh5Di9EOigzKXOct1clv3E4406odMXDAdO28BCMTBfCPyNi/DHzpB
         vdGo5qumL4hwFXmMqAvDLAF0slZEcq1oczGC/AqnPUQJ+gGGTuFEwtFzpyJ+blFxUGWP
         rpTQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=rEZQ6gHE;
       spf=pass (google.com: domain of 3jtbcyqukcqgmt3mzowwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3JTBcYQUKCQgmt3mzowwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=0+bPT5A9aQOnA5Cj4aeZMHtRJZAlu6u2+QoRfMhTHO0=;
        b=pkYMb8qz5g/Cbhh7dDfaPSIZ1T3695Rdyf6NGk69T8SBevedWvIqdtNB2OKbvd+ZbZ
         hxDYrFUP3kMmMoW1onPkiRaFNKTVthgyo8u32SKihHaWjPgpYNLBwXwCyyhZefVMNvZM
         +bTplFbpHNq6CitO3w/B9HUMfz5r4wS2h5Qztpmj4lpXMifenSYJJbJaL6c0kyty5Tu2
         +7LnOBbwaiAAEeJCqMh9JpUhZhMf1MOlNGnAuuZFKx9KIR5oFwrTA8jR3f/qYpS21Jlf
         XRnKkI/tJ3fJje4MJTaLpCh9Ee5y/IWZNBkZ4uiBajzM4/x+IvxNB9uu8ihokY1/aNVx
         5XWQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=0+bPT5A9aQOnA5Cj4aeZMHtRJZAlu6u2+QoRfMhTHO0=;
        b=Az8/rK9cWirFrsoquKJoifKWkLnqkul0+1sPIEjIwSMo7cyBR54noAfPT+n7CLsTQP
         F+yJhlbdlRjzgMC+/qy5UuxQxqGNy1Lbq1PzbYwDush/XcE2Xfk0mMibAv9IMrLsB8Qa
         ngEnJZn4MHYgbRqcwi0+LQzz/qcek/z38XZ8o1nZJHeHRkdB2xLQOa6h39m5qgUwd2KU
         NBLaIif4bNoXTc9LizqSLpKBhbitP4PZ8nv/Q8JFdzkIb7oM9opd6p3QDzMcN0AIOQYG
         IQpxQSL7nelJtEEi9gR7Ccmh4SJqaBTtDb0jw9MmPRr9UuruyGZ3LKkxR1UbRvX6XY9x
         XOog==
X-Gm-Message-State: AOAM531JthVKGItffvPIyKn+HJ094zDH4vKkARJlsADP00aIaWdMFECA
	IvUSYvW//fbzcOMqNz304Y4=
X-Google-Smtp-Source: ABdhPJxaP8BIWPk8cOQq8eszSTIpT6nNdvpUbRZ2PVab6a3XwoDK3gAZb6J89rXs99H94tRVoGBJIw==
X-Received: by 2002:a54:4404:: with SMTP id k4mr1934653oiw.132.1633431590553;
        Tue, 05 Oct 2021 03:59:50 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:1e02:: with SMTP id m2ls5780547oic.2.gmail; Tue, 05 Oct
 2021 03:59:50 -0700 (PDT)
X-Received: by 2002:a05:6808:130b:: with SMTP id y11mr1929541oiv.55.1633431590214;
        Tue, 05 Oct 2021 03:59:50 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1633431590; cv=none;
        d=google.com; s=arc-20160816;
        b=BNAWBlQ7hNv1n0XsuOdE8fuKYDmaGGNDylgkGE9qOFPLO7TuYVzAw9du8np5RHE/kX
         A4xyPg3QIhpg1scI0E1BGirbs5PCQ9uFoT8WNRdO/7bZHUhRHx8N1L2o4FF/K0Ess/z4
         au0m0eety4MCFlz0bX9KwKxvKlLZmo8sfDMdbmusRY3uM/Sx+j2zYarCE1o7hm2JHDc1
         irtC2oSl+++cilhsszaIlRLXW9I12qPoEzK9pLsB6arzK87RlhXL4TWSMnufqCUrifE2
         4TUteViCOtaQ4hRdRy1EYU9rkfAlNZgMs6qrqRB9EPi3LHeZcuApMr2XdeYxmH7JCB64
         Qc3g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=kUUBsv4TZ+s6mxdftD0CD4qwCQSHLXZlKlhseQGR4HI=;
        b=BKw+fQk92EuVJdIbDJFTt0680xZvOq6I6cmdchyUnD1skhM4vWYYTvIzkoH52ak663
         JtOI747cWYGHTN/YFNgZuTdbdMP3f+geMRTQbM5hiwl3BqRvveP3mn4LgIzves/jy78e
         hu12+ogEObHpW1PMRNP94qadrA6c/T4GmVxrBbT2/Y3kwtwCsPu+45T8niiqSBbOgciJ
         i0i6LAta2yfSFY1g3j3EZWnMLi3HZZXJ88J33/5n2Y5Nv+zOVeaqC5bmjbEplVM9cQXI
         B9IAXoeYkWtaitv60TyH2xedxQ3X63FhdrfUW0WadnD5aikxy8jFef1rzrsSQrz+Pc4Q
         ZIhQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=rEZQ6gHE;
       spf=pass (google.com: domain of 3jtbcyqukcqgmt3mzowwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3JTBcYQUKCQgmt3mzowwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb49.google.com (mail-yb1-xb49.google.com. [2607:f8b0:4864:20::b49])
        by gmr-mx.google.com with ESMTPS id bd5si2139592oib.2.2021.10.05.03.59.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 05 Oct 2021 03:59:50 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3jtbcyqukcqgmt3mzowwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) client-ip=2607:f8b0:4864:20::b49;
Received: by mail-yb1-xb49.google.com with SMTP id 83-20020a251956000000b0059948f541cbso27808141ybz.7
        for <kasan-dev@googlegroups.com>; Tue, 05 Oct 2021 03:59:50 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:e44f:5054:55f8:fcb8])
 (user=elver job=sendgmr) by 2002:a5b:f03:: with SMTP id x3mr20807187ybr.546.1633431589883;
 Tue, 05 Oct 2021 03:59:49 -0700 (PDT)
Date: Tue,  5 Oct 2021 12:58:45 +0200
In-Reply-To: <20211005105905.1994700-1-elver@google.com>
Message-Id: <20211005105905.1994700-4-elver@google.com>
Mime-Version: 1.0
References: <20211005105905.1994700-1-elver@google.com>
X-Mailer: git-send-email 2.33.0.800.g4c38ced690-goog
Subject: [PATCH -rcu/kcsan 03/23] kcsan: Avoid checking scoped accesses from
 nested contexts
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, "Paul E . McKenney" <paulmck@kernel.org>
Cc: Alexander Potapenko <glider@google.com>, Boqun Feng <boqun.feng@gmail.com>, 
	Borislav Petkov <bp@alien8.de>, Dmitry Vyukov <dvyukov@google.com>, Ingo Molnar <mingo@kernel.org>, 
	Josh Poimboeuf <jpoimboe@redhat.com>, Mark Rutland <mark.rutland@arm.com>, 
	Peter Zijlstra <peterz@infradead.org>, Thomas Gleixner <tglx@linutronix.de>, 
	Waiman Long <longman@redhat.com>, Will Deacon <will@kernel.org>, kasan-dev@googlegroups.com, 
	linux-arch@vger.kernel.org, linux-doc@vger.kernel.org, 
	linux-kbuild@vger.kernel.org, linux-kernel@vger.kernel.org, 
	linux-mm@kvack.org, x86@kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=rEZQ6gHE;       spf=pass
 (google.com: domain of 3jtbcyqukcqgmt3mzowwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3JTBcYQUKCQgmt3mzowwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--elver.bounces.google.com;
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

Avoid checking scoped accesses from nested contexts (such as nested
interrupts or in scheduler code) which share the same kcsan_ctx.

This is to avoid detecting false positive races of accesses in the same
thread with currently scoped accesses: consider setting up a watchpoint
for a non-scoped (normal) access that also "conflicts" with a current
scoped access. In a nested interrupt (or in the scheduler), which shares
the same kcsan_ctx, we cannot check scoped accesses set up in the parent
context -- simply ignore them in this case.

With the introduction of kcsan_ctx::disable_scoped, we can also clean up
kcsan_check_scoped_accesses()'s recursion guard, and do not need to
modify the list's prev pointer.

Signed-off-by: Marco Elver <elver@google.com>
---
 include/linux/kcsan.h |  1 +
 kernel/kcsan/core.c   | 18 +++++++++++++++---
 2 files changed, 16 insertions(+), 3 deletions(-)

diff --git a/include/linux/kcsan.h b/include/linux/kcsan.h
index fc266ecb2a4d..13cef3458fed 100644
--- a/include/linux/kcsan.h
+++ b/include/linux/kcsan.h
@@ -21,6 +21,7 @@
  */
 struct kcsan_ctx {
 	int disable_count; /* disable counter */
+	int disable_scoped; /* disable scoped access counter */
 	int atomic_next; /* number of following atomic ops */
 
 	/*
diff --git a/kernel/kcsan/core.c b/kernel/kcsan/core.c
index e34a1710b7bc..bd359f8ee63a 100644
--- a/kernel/kcsan/core.c
+++ b/kernel/kcsan/core.c
@@ -204,15 +204,17 @@ check_access(const volatile void *ptr, size_t size, int type, unsigned long ip);
 static noinline void kcsan_check_scoped_accesses(void)
 {
 	struct kcsan_ctx *ctx = get_ctx();
-	struct list_head *prev_save = ctx->scoped_accesses.prev;
 	struct kcsan_scoped_access *scoped_access;
 
-	ctx->scoped_accesses.prev = NULL;  /* Avoid recursion. */
+	if (ctx->disable_scoped)
+		return;
+
+	ctx->disable_scoped++;
 	list_for_each_entry(scoped_access, &ctx->scoped_accesses, list) {
 		check_access(scoped_access->ptr, scoped_access->size,
 			     scoped_access->type, scoped_access->ip);
 	}
-	ctx->scoped_accesses.prev = prev_save;
+	ctx->disable_scoped--;
 }
 
 /* Rules for generic atomic accesses. Called from fast-path. */
@@ -465,6 +467,15 @@ kcsan_setup_watchpoint(const volatile void *ptr, size_t size, int type, unsigned
 		goto out;
 	}
 
+	/*
+	 * Avoid races of scoped accesses from nested interrupts (or scheduler).
+	 * Assume setting up a watchpoint for a non-scoped (normal) access that
+	 * also conflicts with a current scoped access. In a nested interrupt,
+	 * which shares the context, it would check a conflicting scoped access.
+	 * To avoid, disable scoped access checking.
+	 */
+	ctx->disable_scoped++;
+
 	/*
 	 * Save and restore the IRQ state trace touched by KCSAN, since KCSAN's
 	 * runtime is entered for every memory access, and potentially useful
@@ -578,6 +589,7 @@ kcsan_setup_watchpoint(const volatile void *ptr, size_t size, int type, unsigned
 	if (!kcsan_interrupt_watcher)
 		local_irq_restore(irq_flags);
 	kcsan_restore_irqtrace(current);
+	ctx->disable_scoped--;
 out:
 	user_access_restore(ua_flags);
 }
-- 
2.33.0.800.g4c38ced690-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211005105905.1994700-4-elver%40google.com.
