Return-Path: <kasan-dev+bncBCV5TUXXRUIBBDGS373AKGQERS6SO6I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83a.google.com (mail-qt1-x83a.google.com [IPv6:2607:f8b0:4864:20::83a])
	by mail.lfdr.de (Postfix) with ESMTPS id CA5A41ED5F5
	for <lists+kasan-dev@lfdr.de>; Wed,  3 Jun 2020 20:16:45 +0200 (CEST)
Received: by mail-qt1-x83a.google.com with SMTP id n8sf2639105qtk.11
        for <lists+kasan-dev@lfdr.de>; Wed, 03 Jun 2020 11:16:45 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1591208204; cv=pass;
        d=google.com; s=arc-20160816;
        b=zd3FKJumGF//XAYegSGjczL/Q8kAZYtwkbY2WsZHk3vbU7tZCKeNjVxGGc5na1CjKX
         c7L9onVC5g9oupRkg7mN2XK5XsMQQl+O1ca06JaNXBd25mz4ZYsiHH7T07wSUs6KzW/l
         1FkjiCC/lxSQX2xRsI1ansiJrwRztJVxx7JImze+jtctJlMBU+dCiCXP6pU+Usa5/aXW
         ajvdr5D6HaiehmwBxOhzIKgKDWf6Vsrg485l79f9PqGlbdgEEk8mpyueCmzETI6lAiGZ
         G9DQFd7eFnywSucZnjrn21/OEE64X5E8m55ixgtmkPjRhCrey1GOoRrRLVnQy8PtuN3U
         vAsQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=jxuqWMcI61MTxuiO2Drx3Zxbhq/hwpqWp1PREwo3wGA=;
        b=joBiaF6T1Y7GSO4MhkfTO/yV7HIKhU2nzc+6TpbySHE91GzifKEA978YTHvRbexLnd
         j702+bIY10g3mPTawLA6SNWbyH+fAyhOaOmDOD5ykMOBZqW6lLhDn6uTiARkVyBw3K2X
         dRnfZ3FtMROVUG+umYKtA6ipp7ugT7yAh70/CpUmvworC99bTVfQMj4brQLDfsrGo/gr
         djSeN488k2oXzw3tz4UJIDIkcSSeatDUeaVC0sfhF4i/WFrdA2wY5lehgJeQe35GZpQt
         FAUHHWCqfQAp8DqQFqpO4Dp+Q9d9E4izDDkPiGQfE9sCMIcZ/OWyzSi1DZyz+9hdvKlW
         9mzg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=merlin.20170209 header.b=3iIhUE01;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=jxuqWMcI61MTxuiO2Drx3Zxbhq/hwpqWp1PREwo3wGA=;
        b=pCm4iYw8rYA4TK2YIEzxZAcHACN+h4BRJ+jqjW24COpshxrJz/tG8lu5JPMQDaCKvZ
         QPxHjAWUlrR6tENNnD91gDaGKyVqSfpXeW0Qe+/Qcy78kYQr5a60k491MFlU/TAG1sYK
         /vLivOA6Jw4SrxniYi14sHtHrCcgPBopqqO6xjOcv1kHHeJkOYg71Jfl7CWppcOWkVEx
         fkaoYAITegkeWIv9YkphQ0wNF3KdI1IrFZk4FikewrF4lA5dlMN7n+7Gqh0ZjFuW6QEw
         eeYy/I7lL4X1QtcNarHB8irK7T2dgtN5LzwCfzZb6PQirVrpKa2WLwou+spLOesq/VQu
         CwEw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=jxuqWMcI61MTxuiO2Drx3Zxbhq/hwpqWp1PREwo3wGA=;
        b=eTH7LqQXo08aDjQN7RmdiOKLpBxXNCfnftz4WyR7N4/ImjuToN8ugQS9HxynDok1HR
         ky91F0USPbdhmtWVILQc0OpukjOmPg4hNA2m8/2j9//A3Pqtsg1KXIrGYJNa0LTBPIlT
         egE/ZpW3IZ0yaqJZaR0sReP4lhqg11hMXOzx3+ShMEFxAS3bFstL6/I9+zA0fy87fu/o
         iWmq8rZJhub6OzAfoMhpUJ2scw5LNIkp6Jci7b+Nd9WX9UNy+cFLbEGj0yVttIZkr//j
         P48ozYjPqxcPdP97RchQvCxar9dxPXBnY+iD4r1voQW4q38uNl4tLaPuccLPU4HQqF4W
         dflA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531VisSdUsEUckpnzSA/Y4qbv2U2RGdvHORLyyeT652zW9SQzb/E
	wdz5N+wArhquN4jZNgB31WE=
X-Google-Smtp-Source: ABdhPJzn+N5+EyZ/zdm/YjTQWNGZDnZ549kLJeVqTaaGPxl7rnIIJZYSQOSc0r2D+8QiNn4Tk/vykg==
X-Received: by 2002:a37:9f43:: with SMTP id i64mr941112qke.173.1591208204514;
        Wed, 03 Jun 2020 11:16:44 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ad4:55c7:: with SMTP id bt7ls758530qvb.3.gmail; Wed, 03 Jun
 2020 11:16:44 -0700 (PDT)
X-Received: by 2002:a0c:908c:: with SMTP id p12mr1053487qvp.95.1591208204202;
        Wed, 03 Jun 2020 11:16:44 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1591208204; cv=none;
        d=google.com; s=arc-20160816;
        b=tDmUAXavfHXfHyzb7dco93L5+sp9AuGqXrzz6Q5qEv6HK+7oydJvIceokoO9/zZ38k
         QX/R8q0CLtCuIwRI8FuE6Dpn1E27/zrgyqMPf+yqYiCsSyPodiGoOm39WIPfv9x7i6n0
         7ChauXNBDi58nHGROmW6gd+VuEHjYo7juOp2lfDFjt7iMF0qUy8sGv7ANNlQQ15mRc5l
         2hOhJ4TuoxC1moZQMlDyqhRvDOa9xj6gdCGcz12rnb2VLNtZIDRYnk1FmmKhFdzABcRm
         TLWYB1s9MRdq/iMeKeJ1RZ0VHgQWKS91IoheF5V2lQ90Dhxg4oiy/88ZQxoYbiM41uHp
         EnYA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=vsOgcRZrbdf5xHzmcx7xUeya+RKEZLT28sw6blnmXJQ=;
        b=jwebYOQUl0M1cRVzRIL5cdAI6SUTMwOnLE9TQKvQrO67cqi+mx04+R/ulNMYc16Juh
         E99JAHGcGqR/E8rusyByZeMLPG4qfzj6IgjfaHoAXLJ3EoQq7NQCitiQ6EtY54Hfp0i5
         Za5ivq3wqm7zx+MklHS8R1XVHUmx1J+i7lCYw8feVyVMY3l2kWKMWIzUkwLHbnb3mUvk
         81lyrEu6IAGruu9OYXEqjjXYJRH5TKOxm3+xZPrIS4C7F6qkUwS2y1+E1ub7zivGylPF
         sBGynVk1gMOS1VD8Gwnfczs3b1LUST/AADMx5IpIZ0SZLK8Jfi3DeqxhukfQNiRDJv//
         qwTw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=merlin.20170209 header.b=3iIhUE01;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from merlin.infradead.org (merlin.infradead.org. [2001:8b0:10b:1231::1])
        by gmr-mx.google.com with ESMTPS id y21si249171qka.2.2020.06.03.11.16.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 03 Jun 2020 11:16:44 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) client-ip=2001:8b0:10b:1231::1;
Received: from j217100.upc-j.chello.nl ([24.132.217.100] helo=noisy.programming.kicks-ass.net)
	by merlin.infradead.org with esmtpsa (Exim 4.92.3 #3 (Red Hat Linux))
	id 1jgXwP-0006Wj-5Y; Wed, 03 Jun 2020 18:16:42 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id 729D23006D0;
	Wed,  3 Jun 2020 20:16:38 +0200 (CEST)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 1000)
	id 5E2DC20C6A1FA; Wed,  3 Jun 2020 20:16:38 +0200 (CEST)
Date: Wed, 3 Jun 2020 20:16:38 +0200
From: Peter Zijlstra <peterz@infradead.org>
To: Marco Elver <elver@google.com>
Cc: Thomas Gleixner <tglx@linutronix.de>,
	the arch/x86 maintainers <x86@kernel.org>,
	"Paul E. McKenney" <paulmck@kernel.org>,
	kasan-dev <kasan-dev@googlegroups.com>,
	LKML <linux-kernel@vger.kernel.org>, Will Deacon <will@kernel.org>,
	Dmitry Vyukov <dvyukov@google.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@google.com>
Subject: Re: [PATCH 0/9] x86/entry fixes
Message-ID: <20200603181638.GD2627@hirez.programming.kicks-ass.net>
References: <20200603114014.152292216@infradead.org>
 <20200603120037.GA2570@hirez.programming.kicks-ass.net>
 <20200603120818.GC2627@hirez.programming.kicks-ass.net>
 <CANpmjNOxLkqh=qpHQjUC_bZ0GCjkoJ4NxF3UuNGKhJSvcjavaA@mail.gmail.com>
 <20200603121815.GC2570@hirez.programming.kicks-ass.net>
 <CANpmjNPxMo0sNmkbMHmVYn=WJJwtmYR03ZtFDyPhmiMuR1ug=w@mail.gmail.com>
 <CANpmjNPzmynV2X+e76roUmt_3oq8KDDKyLLsgn__qtAb8i0aXQ@mail.gmail.com>
 <20200603160722.GD2570@hirez.programming.kicks-ass.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20200603160722.GD2570@hirez.programming.kicks-ass.net>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=merlin.20170209 header.b=3iIhUE01;
       spf=pass (google.com: best guess record for domain of
 peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
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

On Wed, Jun 03, 2020 at 06:07:22PM +0200, Peter Zijlstra wrote:
> On Wed, Jun 03, 2020 at 04:47:54PM +0200, Marco Elver wrote:

> > With that in mind, you could whitelist "__ubsan_handle"-prefixed
> > functions in objtool. Given the __always_inline+noinstr+__ubsan_handle
> > case is quite rare, it might be reasonable.
> 
> Yes, I think so. Let me go have dinner and then I'll try and do a patch
> to that effect.

Here's a slightly more radical patch, it unconditionally allows UBSAN.

I've not actually boot tested this.. yet.

---
Subject: x86/entry, ubsan, objtool: Whitelist __ubsan_handle_*()
From: Peter Zijlstra <peterz@infradead.org>
Date: Wed Jun  3 20:09:06 CEST 2020

The UBSAN instrumentation only inserts external CALLs when things go
'BAD', much like WARN(). So treat them similar to WARN()s for noinstr,
that is: allow them, at the risk of taking the machine down, to get
their message out.

Suggested-by: Marco Elver <elver@google.com>
Signed-off-by: Peter Zijlstra (Intel) <peterz@infradead.org>
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200603181638.GD2627%40hirez.programming.kicks-ass.net.
