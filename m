Return-Path: <kasan-dev+bncBCV5TUXXRUIBBCEY4P3AKGQE5NHJETA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x437.google.com (mail-pf1-x437.google.com [IPv6:2607:f8b0:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id 3DA5F1EE25D
	for <lists+kasan-dev@lfdr.de>; Thu,  4 Jun 2020 12:25:14 +0200 (CEST)
Received: by mail-pf1-x437.google.com with SMTP id p18sf4435054pfq.14
        for <lists+kasan-dev@lfdr.de>; Thu, 04 Jun 2020 03:25:14 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1591266312; cv=pass;
        d=google.com; s=arc-20160816;
        b=bfLRTpgMnLHXutCEhysBGjj/u3J4ubg7Sa9BX3ciOskKVMWZ/08V6Cc6v7BZDCq4MY
         whab2cCH7U7Xy6MWS2NuIe6O2yN+WRtFnkKTuiB5cTxouHtfsd+ehR6jkEJcp5pPeqoB
         MJqlnZDTc1uA7ynR9Y2xx0Lfni4hT7MkndkjE327JEvSLB2zDPaeRLP9MnOxtTfThCAl
         iO0lbnR0efAZuMoS28wFCwTU8mgYQuWmqOuqk/l23elOeK020Pz/J6PMkaq+100gI+bs
         Fy7A4YoSlrRjszCzxl6hGgbUnW5UBmsghUCpdYqzRNWBWINwp/i4ja4fhGrSL3vS+Oj6
         h3Ng==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:subject:cc
         :to:from:date:user-agent:message-id:sender:dkim-signature;
        bh=elyjymCu/+i2Zz3KEkP6qO6VLu6MAxnY1QOTd4x+X1Y=;
        b=J9JpNzApp/u5n9SIULbXNu5T2vurRopSlw6Y8VJGd0UlDIjo2HoNUOtj4S4mjctfqO
         bMs3oR7mZ395GsGL1ggssR/RPlPMJkgyigdgbqImElp6EtfTUhG9GXdv11YdUP8Xhrd1
         I/TPKJ5PiB2exNQPsnkMDzvPzedBHyJTEx+CdXTfXzjQfXjLOT+mqv29PpEnue+jq1ix
         tMa25Z+urbQ049sX2iu/5pKo5pDmwWfisqHduSExCxpYyK5ltKfRaZvc8StNhHLVFcIX
         JVMHPM3eVqGVTkqKvG8OKdP//3qE9GsUOnkmGy+WgbBJJSCerGyX6mZiUoWCrAT8/hh5
         bgfQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=bombadil.20170209 header.b=Pc+UK6AQ;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2607:7c80:54:e::133 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:message-id:user-agent:date:from:to:cc:subject:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=elyjymCu/+i2Zz3KEkP6qO6VLu6MAxnY1QOTd4x+X1Y=;
        b=CZKIbqMN7vTMcYAvT/FbWcUz8xGA6fmoSzHUq6jGIPt+0SH25sNHcFcACdTuhgjHMO
         1e2GEii5UK0T/d/DGebAdRC6pBjV+mT4y1aZUTyliG8doqoofpzv78AtgK21Rtg/2Mty
         NTzNaMSl164NbzF3FpBNhwbyens5kyz1Y6N7F11IDZHbKFxPCRYFKZKW3rBomb6ciHCM
         OvGBRLKEaj3sKHIIgW22AzfleiyQ+8nSY7TD3HCpSHlUcqPrT/tWDCsnmHBDKXPTCwJM
         8ga14iaQSP1QyUUzsAYRAryVAxsfJtDqanDQjuOG7bdW4gPQSRMQ8y20GZ2F6CupOinM
         Venw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:message-id:user-agent:date:from:to:cc
         :subject:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=elyjymCu/+i2Zz3KEkP6qO6VLu6MAxnY1QOTd4x+X1Y=;
        b=PllRcQ65JvjgOAlCO5NMILCRlC9yQjB3JF3/g0lrcHQqBBlKtoXOq9dnKmlsYMggX/
         V92eJGBx3tYNnjP0ix3LvwTnr6wotFn+lM67w6waizu3+WZJMft0+wwxfjhx0ZdJyKKd
         6+iBRjQ11IgefxKjKw2DXo4gqiIfuV8mGEcCKWj7rDjGCcdCfpYyREXTvAhGbUlvf8vK
         EMTzRay2qtiTJip8Vw5u6qV8o9vN/SqreJcT9h6eFMCRGWhU4rswLwdlduRC3fbTvi1p
         3KYo+jLNCisPhZIxaBLF3Ljxel8wFSuWv6kt1JWzNC1ka3dKxd8S7FErun0/Eifaikbg
         oyew==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533mokF6NDPtmci42SslkroXCCTxKim1TOPrxObpCcKbYZ7gsDtf
	Dgq6PtYkHfrvkEFouag0irA=
X-Google-Smtp-Source: ABdhPJxJRzgoCSN/4Vi4fp5/9CHtBAtHJqwbWNjlTaE7CZqbowNLIhBE2VwZiGQNP4UaJ+Uho+m2mA==
X-Received: by 2002:a65:68c9:: with SMTP id k9mr3699327pgt.77.1591266312746;
        Thu, 04 Jun 2020 03:25:12 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:185e:: with SMTP id 30ls1523538pgy.9.gmail; Thu, 04 Jun
 2020 03:25:12 -0700 (PDT)
X-Received: by 2002:aa7:8f1c:: with SMTP id x28mr3716390pfr.19.1591266312299;
        Thu, 04 Jun 2020 03:25:12 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1591266312; cv=none;
        d=google.com; s=arc-20160816;
        b=d3oQG1BM2bxlhY9gMeFfg1N6y1iZDot1o4zPn19wA78PDn4QIgOApHNGPVsBJe5HEI
         7evJBplShSzDVQfrYx2XMk/wIVvkqigvBmq/duiloMa+ebDlGsXK3NVcjgpzvFt6/rTe
         VdCyleRcQBZX1DoRewLGtHnoNAgyMhW6YjvQo7eV7XsL0GaAXrrBVAJ3D6X8t1j17mZk
         ZzXIGApAN1qX0Qxv1EPSh+wUBmx69eoqiYrs99M2mbq8l3qAXqyLklxHchYBDE328bEB
         Z3Z9gPwCGhvhIisXvWfPk9HYgT3FMvDs1KzWwvHm+ZycnQ+gIf9N89OGMyRGqpb7K/Qz
         7Wsg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:subject:cc:to:from:date:user-agent
         :message-id:dkim-signature;
        bh=HLUlGVzGh8D/8ZTgbqliDFpKr8IxVRxtSm/kD93Ik8k=;
        b=OlgvaiBUUrJcX7Y5M7pruAlmJhDinjT2m/c2uhh0yT7IWsmy3t9sC2wrYUn7NWghTP
         7cfaeF1HGSpd7ufwrHUuagaOSTJ2RKb50cNSHBONW9eAwBkRsNgYRM4sRcWeFMl9IMlW
         QZa4vlFOu62SsU157Up5IutPotuD7Jmbnf57kVeP4Rrx9nsEgYO9VHnUxt2Hlrmfhnw/
         qJCKAGPGSLD10jIjfdRBtnzPXbck+ZPsucrpjOH9F4ANMteo5MWV+KT7OCbwITjk4zR9
         BMNdAWGyAaZ3Vt+LFQvx6avOhPv3IotmwIYIs5rMP4p56QPdJbQ2+++gwpIMcHybSYuj
         RBEw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=bombadil.20170209 header.b=Pc+UK6AQ;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2607:7c80:54:e::133 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from bombadil.infradead.org (bombadil.infradead.org. [2607:7c80:54:e::133])
        by gmr-mx.google.com with ESMTPS id o9si253646plk.0.2020.06.04.03.25.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 04 Jun 2020 03:25:12 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2607:7c80:54:e::133 as permitted sender) client-ip=2607:7c80:54:e::133;
Received: from j217100.upc-j.chello.nl ([24.132.217.100] helo=noisy.programming.kicks-ass.net)
	by bombadil.infradead.org with esmtpsa (Exim 4.92.3 #3 (Red Hat Linux))
	id 1jgn3d-0001ap-Io; Thu, 04 Jun 2020 10:25:09 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id 0F023306D6D;
	Thu,  4 Jun 2020 12:25:08 +0200 (CEST)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 0)
	id E9B2420CC68B5; Thu,  4 Jun 2020 12:25:07 +0200 (CEST)
Message-ID: <20200604102428.307943402@infradead.org>
User-Agent: quilt/0.66
Date: Thu, 04 Jun 2020 12:22:48 +0200
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
Subject: [PATCH 7/8] x86/entry, ubsan, objtool: Whitelist __ubsan_handle_*()
References: <20200604102241.466509982@infradead.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=bombadil.20170209 header.b=Pc+UK6AQ;
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

The UBSAN instrumentation only inserts external CALLs when things go
'BAD', much like WARN(). So treat them similar to WARN()s for noinstr,
that is: allow them, at the risk of taking the machine down, to get
their message out.

Suggested-by: Marco Elver <elver@google.com>
Signed-off-by: Peter Zijlstra (Intel) <peterz@infradead.org>
Acked-by: Marco Elver <elver@google.com>
---
 include/linux/compiler_types.h |    2 +-
 tools/objtool/check.c          |   28 +++++++++++++++++++++++++++-
 2 files changed, 28 insertions(+), 2 deletions(-)

--- a/include/linux/compiler_types.h
+++ b/include/linux/compiler_types.h
@@ -199,7 +199,7 @@ struct ftrace_likely_data {
 /* Section for code which can't be instrumented at all */
 #define noinstr								\
 	noinline notrace __attribute((__section__(".noinstr.text")))	\
-	__no_kcsan __no_sanitize_address __no_sanitize_undefined
+	__no_kcsan __no_sanitize_address
 
 #endif /* __KERNEL__ */
 
--- a/tools/objtool/check.c
+++ b/tools/objtool/check.c
@@ -2190,10 +2190,36 @@ static inline const char *call_dest_name
 	return "{dynamic}";
 }
 
+static inline bool noinstr_call_dest(struct symbol *func)
+{
+	/*
+	 * We can't deal with indirect function calls at present;
+	 * assume they're instrumented.
+	 */
+	if (!func)
+		return false;
+
+	/*
+	 * If the symbol is from a noinstr section; we good.
+	 */
+	if (func->sec->noinstr)
+		return true;
+
+	/*
+	 * The __ubsan_handle_*() calls are like WARN(), they only happen when
+	 * something 'BAD' happened. At the risk of taking the machine down,
+	 * let them proceed to get the message out.
+	 */
+	if (!strncmp(func->name, "__ubsan_handle_", 15))
+		return true;
+
+	return false;
+}
+
 static int validate_call(struct instruction *insn, struct insn_state *state)
 {
 	if (state->noinstr && state->instr <= 0 &&
-	    (!insn->call_dest || !insn->call_dest->sec->noinstr)) {
+	    !noinstr_call_dest(insn->call_dest)) {
 		WARN_FUNC("call to %s() leaves .noinstr.text section",
 				insn->sec, insn->offset, call_dest_name(insn));
 		return 1;


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200604102428.307943402%40infradead.org.
