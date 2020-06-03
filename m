Return-Path: <kasan-dev+bncBCV5TUXXRUIBBJMZ333AKGQEZVDZC4I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x837.google.com (mail-qt1-x837.google.com [IPv6:2607:f8b0:4864:20::837])
	by mail.lfdr.de (Postfix) with ESMTPS id 168451ECEA7
	for <lists+kasan-dev@lfdr.de>; Wed,  3 Jun 2020 13:42:31 +0200 (CEST)
Received: by mail-qt1-x837.google.com with SMTP id e8sf1504104qtq.22
        for <lists+kasan-dev@lfdr.de>; Wed, 03 Jun 2020 04:42:31 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1591184550; cv=pass;
        d=google.com; s=arc-20160816;
        b=c08mlgkho9hBjYGfAx0SNUdQMWyRxjTUeLXzg3K7bImIyW16S2Jyq9qzNWqGWImG6/
         BYpcDs1ltDD9M33pTkiNn3ABOpv8iCUU0Yx/MUtRy0U9gubksjmaKaSUi5YTLncu7JL2
         t7v44Gu6HtrdrPKDSM1wIEzPvlkfeu0JkYxb1SA5xfpiJBPHgVXAFJDfm9+Mlry2D9Qn
         J4Am522JlwS0wyAYX/nZs2kgWOCdcU0S6t/hDMfD+W1N9ab9sbVHtEQG1OJPwIiZUutB
         N7s/YcX/Z7ctCo7YK/q+n3tCaGJWNjeljPIewrqtnme8RSxNeAs/jjqJyqLINa7v7QRV
         OXAA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:subject:cc
         :to:from:date:user-agent:message-id:sender:dkim-signature;
        bh=Y7OFgOkVwjley+gvPZFdYeGNGJXmW+RCrpNiPL1mbM8=;
        b=vSeA92TRUOR+1ExojUHxRMCeGOR7jVeQI3pOCaw/aY8+BGMtlnr6wbZx5zQ8qxSMYg
         ttE48x7MWD6Lt1mCL1hZaB3mDNXeBwggryGMu1qC0PMT8QDwdMDu0nU7hwDdzNzGM9yl
         XB0yrvUli4UeUw4OB2a2JIDoTBpscWLzS6ePPTAgswQGIcCvlSTQCzNzw4T9lKyWjWjF
         cC9yuQESPoocoHEuki3A7iBN+DhsXZqNZ1ACjMOZThuy3FZZ5GTe6OnQKrkLOlC1cbnz
         PyRWpksTN2cwOH5J8ano1pzs0O6FfBOLWYSL4HVYoJVdF1J6A6m1J4khUO6vPDu9GqZy
         Ck4Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=bombadil.20170209 header.b=TjVx+5Zu;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2607:7c80:54:e::133 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:message-id:user-agent:date:from:to:cc:subject:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Y7OFgOkVwjley+gvPZFdYeGNGJXmW+RCrpNiPL1mbM8=;
        b=UnqopIT3gMeGxqeUjQztPuhDTVCqA+aRc1anxpWMDFUQnrVCAAs/8ZgEoPCmN9Qpeb
         5JOlaeD94c4EQW3qQCygqOHo50sK034pxv21MhpZNii3Zb5eskzth0D1qhQC+l+1TcYp
         oYyk8H9Y5uNKXIpOju8A3WwKHVc6j3KW/u0VBGfTFCnlym9JVHueE3CRYMdhLTCoYtIF
         gEvCANVprZKQabThWOfdepSy0CGc02qWcZOs1yMdgqT111cIR6XzyehOJlsrt3EmhE14
         uJdw+Gub+V0wJa4ssCmwhSXpTLzTXiD3CRZq/yaxgkn3ct67TVv+6Tf9j6MjtYLiP2xk
         BLXA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:message-id:user-agent:date:from:to:cc
         :subject:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Y7OFgOkVwjley+gvPZFdYeGNGJXmW+RCrpNiPL1mbM8=;
        b=A8JrBDy8Bz2ipc2m1utk0U7vFoCUDPeLwJn1XPEdQKJ59YWxdr/RkZOsThvdlBKiZ+
         T2AuVvfVqzyX2NqhzqPhXc3UHr+e5RyWL8LHr6xgZRHJorFxHX0DkjtDEAS+TYpXkE+G
         S6GiUtxCUbjG2sAxvZpHCVvU5qMMXrlg1Eiic57+XER0O25l7enyxrWhVkPZExGTrEMX
         0NbBd4E6YuXHaDypOI7yOJ4A6OSHsDdaQj5ZY0CX0wt5x4xBs7Dwl9uq0OF7PN/Ra/Nk
         D+Jn69L5H1nArWWfAo6yrWpRtDSTG0l9Jij6mXv0cjDxO3GMPjbk2nkPEwfCjZlAHs7V
         pLnA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530DgVE0O2zYyes2h/q/VKcg980PCuRkDFoVS8eGb41NfPbwMD+Z
	mwZXxhDowK1fFJQMPKPCR4U=
X-Google-Smtp-Source: ABdhPJzwi6C5wUr08yHLdziUkCBNNMuZ95m6x82kna3V6E3A6Nx8nYnNL4UUUerOw9ClNCNP85Mlow==
X-Received: by 2002:ac8:7c8e:: with SMTP id y14mr32536861qtv.112.1591184549892;
        Wed, 03 Jun 2020 04:42:29 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ad4:4f30:: with SMTP id fc16ls464642qvb.2.gmail; Wed, 03 Jun
 2020 04:42:29 -0700 (PDT)
X-Received: by 2002:ad4:510c:: with SMTP id g12mr13106241qvp.231.1591184549544;
        Wed, 03 Jun 2020 04:42:29 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1591184549; cv=none;
        d=google.com; s=arc-20160816;
        b=iR2ag895tJDrVDvNKSQOQAuDUYFkuLeoeTRB/IeZtfp6hSOsLnkjxWmIYnS/Qj7gqd
         n02u7pNqUJiSHw0hPihHseEvOdKtdwEYdaKCsPMWvhvUGfl5I89eNMVdLYmhOi5R5B1A
         TH6fMuVndQXoU3NDugicPjljl7sF1HqMsJ4UFe04cPisGVnWz7p31ixCuG9QQpAPTeS1
         CLg7Ez3o6vt4sAo0ZnjZzOS0m6AoOZFXyY8sh4B0lVriHrpcgj5ddil0BEPoEg/QCuEl
         6XrpW8uvYS15mKFiLoT3eo5cuP1A2OrO9j7cv+HdYJ4aVCASYjMmbl59X9NQmk3vngWW
         qysA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:subject:cc:to:from:date:user-agent
         :message-id:dkim-signature;
        bh=Zodw8aXeLpceTUL1wV4Hv4B/SlGPd+0UwOQWXPD0C6I=;
        b=G2kPqG3e02/oKhuxeA7xgBa8fm9bp+hFHODsCKlazsHXSp0ytd2YXRxCV4pAbO+oga
         jWR76FKudFXMxQ3BptDEUSxJctk+BxsoYjrjgDnvManEESqR4Frb2M6SyFcgnq1W8AkU
         69xJMzef6hJIrO0f/19CGaVXjHs1Mkp7FMQAhNY7plzYqr3XD/zo7DIz+GKicR1Z8+Is
         g93IEb4iU0NDlaIxVRx2nZM9jXO7286YHn2/VOe+7gVFXumlvCB4WcbbtWXm1kczxiVN
         EJ7iHJQWH9r2tLwWDKl4+WcWobBxtpIK49W9GXRSnG/uWgXdbjluZvgVDGsouFfKEV/c
         aEvA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=bombadil.20170209 header.b=TjVx+5Zu;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2607:7c80:54:e::133 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from bombadil.infradead.org (bombadil.infradead.org. [2607:7c80:54:e::133])
        by gmr-mx.google.com with ESMTPS id a78si119623qkb.1.2020.06.03.04.42.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 03 Jun 2020 04:42:29 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2607:7c80:54:e::133 as permitted sender) client-ip=2607:7c80:54:e::133;
Received: from j217100.upc-j.chello.nl ([24.132.217.100] helo=noisy.programming.kicks-ass.net)
	by bombadil.infradead.org with esmtpsa (Exim 4.92.3 #3 (Red Hat Linux))
	id 1jgRmt-0005ju-8u; Wed, 03 Jun 2020 11:42:27 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id BD077306BB7;
	Wed,  3 Jun 2020 13:42:23 +0200 (CEST)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 0)
	id AB926209DB0C4; Wed,  3 Jun 2020 13:42:23 +0200 (CEST)
Message-ID: <20200603114051.954401211@infradead.org>
User-Agent: quilt/0.66
Date: Wed, 03 Jun 2020 13:40:17 +0200
From: Peter Zijlstra <peterz@infradead.org>
To: tglx@linutronix.de
Cc: x86@kernel.org,
 elver@google.com,
 paulmck@kernel.org,
 kasan-dev@googlegroups.com,
 linux-kernel@vger.kernel.org,
 peterz@infradead.org,
 will@kernel.org,
 dvyukov@google.com,
 glider@google.com,
 andreyknvl@google.com
Subject: [PATCH 3/9] x86/entry: __always_inline debugreg for noinstr
References: <20200603114014.152292216@infradead.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=bombadil.20170209 header.b=TjVx+5Zu;
       spf=pass (google.com: best guess record for domain of
 peterz@infradead.org designates 2607:7c80:54:e::133 as permitted sender) smtp.mailfrom=peterz@infradead.org
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

vmlinux.o: warning: objtool: exc_debug()+0x21: call to native_get_debugreg() leaves .noinstr.text section

Signed-off-by: Peter Zijlstra (Intel) <peterz@infradead.org>
---
 arch/x86/include/asm/debugreg.h |    6 +++---
 1 file changed, 3 insertions(+), 3 deletions(-)

--- a/arch/x86/include/asm/debugreg.h
+++ b/arch/x86/include/asm/debugreg.h
@@ -18,7 +18,7 @@ DECLARE_PER_CPU(unsigned long, cpu_dr7);
 	native_set_debugreg(register, value)
 #endif
 
-static inline unsigned long native_get_debugreg(int regno)
+static __always_inline unsigned long native_get_debugreg(int regno)
 {
 	unsigned long val = 0;	/* Damn you, gcc! */
 
@@ -47,7 +47,7 @@ static inline unsigned long native_get_d
 	return val;
 }
 
-static inline void native_set_debugreg(int regno, unsigned long value)
+static __always_inline void native_set_debugreg(int regno, unsigned long value)
 {
 	switch (regno) {
 	case 0:
@@ -85,7 +85,7 @@ static inline void hw_breakpoint_disable
 	set_debugreg(0UL, 3);
 }
 
-static inline bool hw_breakpoint_active(void)
+static __always_inline bool hw_breakpoint_active(void)
 {
 	return __this_cpu_read(cpu_dr7) & DR_GLOBAL_ENABLE_MASK;
 }


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200603114051.954401211%40infradead.org.
