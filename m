Return-Path: <kasan-dev+bncBCV5TUXXRUIBBN6FWXZAKGQEFD4JTLA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x538.google.com (mail-ed1-x538.google.com [IPv6:2a00:1450:4864:20::538])
	by mail.lfdr.de (Postfix) with ESMTPS id A9B89164A65
	for <lists+kasan-dev@lfdr.de>; Wed, 19 Feb 2020 17:30:47 +0100 (CET)
Received: by mail-ed1-x538.google.com with SMTP id n18sf528657edo.17
        for <lists+kasan-dev@lfdr.de>; Wed, 19 Feb 2020 08:30:47 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1582129847; cv=pass;
        d=google.com; s=arc-20160816;
        b=w3RjhGeFkTUK3GVPc0Qh4UpBrDte4BG1hzVAsJd2U8TRlP+bbP6ePby3qaGZqBPf1h
         U5jOUkXjopHq33JbvShtaStkeVrxQEbXFL2/xuPQW5wlsEn4Umi6Bs713q5NcsoGpN1T
         uDy9jEy8Mwdu3FbfSh1cJ4NoB/SPKJmO7+W1YRwPKh+SSKvcsksGX7nNABPyRMhrVGKC
         3IBgBmgayPGOPonno7a+ZW9XTgCqkanjw+0slEI3mxeDkkkcFEjG2mgm3/xp7Xt75vSj
         uTpEEL+J9ejKx9zfS6xlm3CGPyxyPTgAGxdKniRWtHUFgCFDeKRTf/XhmNyu1ihefF8K
         LHpg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=tRRmX9M6z6P5ulF94ECFsrTnMcvS5lvLXTxT+In07PE=;
        b=HCGh5OT31BOIPRcPixruzNsrvHhwESNrM8Pi4/I9rhDpcd6/Yn2GEx/MRESo5CQ61W
         PDBQzOqCqjlotHr1rRcviPONqEJEC2TK2EefJvpOFqzdt5SzoIyA+q04YYfHTyvjrgLL
         nTAi63h3ineige8Gl30E88B9aDGnmPUui8Gfl13nbEck6m14rqzKPS8G1t9rdkJ2pCPS
         iG9tm3Ai1yCCeJz+18TYNpeihhGBw/O/1mnbzLq79oVWwlRvsY6I6S2u95TBLFBxQKO5
         NvZuKZSQCOjCJTrEbWtmEDkEnHBRtQ5L//u5OARDkWcMOG8nCAMIIM0Vs7WTX13yQWHC
         Tqcg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=bombadil.20170209 header.b=ORvjDlmq;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2607:7c80:54:e::133 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=tRRmX9M6z6P5ulF94ECFsrTnMcvS5lvLXTxT+In07PE=;
        b=Buag6iDL128bpKCnD9STE+mdcGIWsDZ9tPo65oTHX15LiKvV1Ps35oAW2uZ9xA2/GO
         gXxd+INFaSLL97mVbi2HWcsYsx8RFsjvst8cTwZPxXB+HBDCYk6YRhrdftDC/no8s4k2
         JxFrpEJ80G0ssrUHQPuECRc63KOm42cjLWX8mONNenmQskLhiOZSlbwe6Qg2RO5rSDJI
         OSSZf14SIfbcLCgsFjN/wYE8iqa2OTqTg1WOHIW2Upl2UONr1I4KTHtfddY2iGUXM2RN
         gQcdVGrxFBXDOY+YP0LiTROhY1T0+GzkpCkzeszCVpTiC4hJP4kM0hyfmimiI5Oo4Aio
         mGjg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=tRRmX9M6z6P5ulF94ECFsrTnMcvS5lvLXTxT+In07PE=;
        b=U6/jTRj5YEAlsoc0romRejp/UmdnVqyv35xrYR6k3JWE7btZFpZHW0Gh7pLG6LRh8o
         0CnkMR+mHISQ/1HFE3mpnH7hFk4CWosJKUGavOaQg4bmizRcK26xWKP1GXvKMgOs/srF
         7qihks0k2iZdQ8A+0INJkgLCKwhrmnQJAhVwmzjPnIH2nFkv+r2PIUnMEgJBby6FgOUS
         yd7T/LiDUwzo0gnSZxBSsE3Pn+u8oO7lHxtD09Jmu5gLyJswBywwblCsVl5Uq+3CVtj6
         HI+ikiex1ab2twqNhK0l/gjbH0vU5cR2+xeArwCF4+enigMPOAfATAZP68LhdstjmQuX
         Pqxg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAWcleMWmoA+nOaCoIpecJ2Bekn6JONalq5NyCAgJ6KFQa5+DuNJ
	1rJdWKesrWgxZtdek8bDv58=
X-Google-Smtp-Source: APXvYqxQHzPdLmVYg0qbv6Ow3VvlKzJDmVwD25IxR5HMRqGADEMEKv5ZkIsc1cwHf3bQcKdcseJe1A==
X-Received: by 2002:a17:906:34d2:: with SMTP id h18mr24533341ejb.76.1582129847333;
        Wed, 19 Feb 2020 08:30:47 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:584f:: with SMTP id h15ls7654193ejs.9.gmail; Wed, 19
 Feb 2020 08:30:46 -0800 (PST)
X-Received: by 2002:a25:2c51:: with SMTP id s78mr26008367ybs.54.1582129846307;
        Wed, 19 Feb 2020 08:30:46 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1582129846; cv=none;
        d=google.com; s=arc-20160816;
        b=jpJE+0Ky4NMeDcPtJqEF0p0qk94XSXLq2fXpPZtb0/GuIc2cQFDiceakn9NSauTOov
         a3PehHGNB2r901cERaw0fZooGRz0hWaHMcT9+MX6SQeiCUPh/4SSU/oONQ8WGeLbVXSn
         Aske6QmTTgbXHDxXsPt8PNEd79OjIjWPEzRak93ALbOw6XUTxtHV6VXJp271TRCbDgBv
         CvqOlfd6pi7XVt6S/ShrzJKtl47/+XTigvNz6EPa/aGh7HwjBON5XLB1P5e3VfMq0rgW
         E7AGtWAhj+UU4jSZTFoEJW3HWG1Ha6EpqfRhKimVtzNLwPgzOMklTPBzCPVAy6v+L5AX
         oE6A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=Qa5MZXsY7UPTTol/FJvhlBtevBmctxCysX0lVvI/ets=;
        b=bN6u2bs3uK0+XR8zLc6doRbThvCIPx792AMlGuU4cl4NMDF0byy3npYtfJMNyxPMJF
         Vn4KaJMSsXFhumsZoKsBkIaxZecL43iYGh2QzqPzhFJN5wApc5X+/mz4JxM6iTDasHWg
         2Ltur3W9JxmPyqzZ6DkNUyu1jEz/nuj3Wu54kYQGn6cgVawRCsZXOdp/6dVsmsabDlo2
         9WjSTmIl863gkkOIg7WOK+aPnpTT1P+IqYylT0NePz3R7tzVAgRj7hXRzzmoVvMui/DW
         TaC5yPRwWR8yf0/fHfr+HjJ59ErHcNLM22yzAgtW27csZAckraogsO//XkDm0Tl1O7fC
         t2kg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=bombadil.20170209 header.b=ORvjDlmq;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2607:7c80:54:e::133 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from bombadil.infradead.org (bombadil.infradead.org. [2607:7c80:54:e::133])
        by gmr-mx.google.com with ESMTPS id p187si10897ywe.1.2020.02.19.08.30.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 19 Feb 2020 08:30:46 -0800 (PST)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2607:7c80:54:e::133 as permitted sender) client-ip=2607:7c80:54:e::133;
Received: from j217100.upc-j.chello.nl ([24.132.217.100] helo=noisy.programming.kicks-ass.net)
	by bombadil.infradead.org with esmtpsa (Exim 4.92.3 #3 (Red Hat Linux))
	id 1j4SF2-0004Yt-Q2; Wed, 19 Feb 2020 16:30:29 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id 397F3300606;
	Wed, 19 Feb 2020 17:28:32 +0100 (CET)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 1000)
	id 636E5201BADC9; Wed, 19 Feb 2020 17:30:25 +0100 (CET)
Date: Wed, 19 Feb 2020 17:30:25 +0100
From: Peter Zijlstra <peterz@infradead.org>
To: Dmitry Vyukov <dvyukov@google.com>
Cc: LKML <linux-kernel@vger.kernel.org>,
	linux-arch <linux-arch@vger.kernel.org>,
	Steven Rostedt <rostedt@goodmis.org>,
	Ingo Molnar <mingo@kernel.org>,
	Joel Fernandes <joel@joelfernandes.org>,
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
	"Gustavo A. R. Silva" <gustavo@embeddedor.com>,
	Thomas Gleixner <tglx@linutronix.de>,
	"Paul E. McKenney" <paulmck@kernel.org>,
	Josh Triplett <josh@joshtriplett.org>,
	Mathieu Desnoyers <mathieu.desnoyers@efficios.com>,
	Lai Jiangshan <jiangshanlai@gmail.com>,
	Andy Lutomirski <luto@kernel.org>, tony.luck@intel.com,
	Frederic Weisbecker <frederic@kernel.org>,
	Dan Carpenter <dan.carpenter@oracle.com>,
	Masami Hiramatsu <mhiramat@kernel.org>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	kasan-dev <kasan-dev@googlegroups.com>
Subject: Re: [PATCH v3 22/22] x86/int3: Ensure that poke_int3_handler() is
 not sanitized
Message-ID: <20200219163025.GH18400@hirez.programming.kicks-ass.net>
References: <20200219144724.800607165@infradead.org>
 <20200219150745.651901321@infradead.org>
 <CACT4Y+Y+nPcnbb8nXGQA1=9p8BQYrnzab_4SvuPwbAJkTGgKOQ@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CACT4Y+Y+nPcnbb8nXGQA1=9p8BQYrnzab_4SvuPwbAJkTGgKOQ@mail.gmail.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=bombadil.20170209 header.b=ORvjDlmq;
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

On Wed, Feb 19, 2020 at 05:06:03PM +0100, Dmitry Vyukov wrote:
> On Wed, Feb 19, 2020 at 4:14 PM Peter Zijlstra <peterz@infradead.org> wrote:
> >
> > In order to ensure poke_int3_handler() is completely self contained --
> > we call this while we're modifying other text, imagine the fun of
> > hitting another INT3 -- ensure that everything is without sanitize
> > crud.
> 
> +kasan-dev
> 
> Hi Peter,
> 
> How do we hit another INT3 here? 

INT3 is mostly the result of either kprobes (someone sticks a kprobe in
the middle of *SAN) or self modifying text stuff (jump_labels, ftrace
and soon static_call).

> Does the code do
> out-of-bounds/use-after-free writes?
> Debugging later silent memory corruption may be no less fun :)

It all stinks, debugging a recursive exception is also not fun.

> Not sanitizing bsearch entirely is a bit unfortunate. We won't find
> any bugs in it when called from other sites too.

Agreed.

> It may deserve a comment at least. Tomorrow I may want to remove
> __no_sanitize, just because sanitizing more is better, and no int3
> test will fail to stop me from doing that...

If only I actually had a test-case for this :/

> It's quite fragile. Tomorrow poke_int3_handler handler calls more of
> fewer functions, and both ways it's not detected by anything.

Yes; not having tools for this is pretty annoying. In 0/n I asked Dan if
smatch could do at least the normal tracing stuff, the compiler
instrumentation bits are going to be far more difficult because smatch
doesn't work at that level :/

(I actually have

> And if we ignore all by one function, it is still not helpful, right?
> Depending on failure cause/mode, using kasan_disable/enable_current
> may be a better option.

kasan_disable_current() could mostly work; but only covers kasan, not
ubsan or kcsan. It then also relies on kasan_disable_current() itself
being notrace as well as all instrumentation functions itself (which I
think is currently true because of mm/kasan/Makefile stripping
CC_FLAGS_FTRACE).

But what stops someone from sticking a kprobe or #DB before you check
that variable?

By inlining everything in poke_int3_handler() (except bsearch :/) we can
mark the whole function off limits to everything and call it a day. That
simplicity has been the guiding principle so far.

Alternatively we can provide an __always_inline variant of bsearch().

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200219163025.GH18400%40hirez.programming.kicks-ass.net.
