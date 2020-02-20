Return-Path: <kasan-dev+bncBCMIZB7QWENRBQXEXLZAKGQE6I24WEA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3b.google.com (mail-io1-xd3b.google.com [IPv6:2607:f8b0:4864:20::d3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 2A90516624A
	for <lists+kasan-dev@lfdr.de>; Thu, 20 Feb 2020 17:22:29 +0100 (CET)
Received: by mail-io1-xd3b.google.com with SMTP id d13sf3203406ioc.3
        for <lists+kasan-dev@lfdr.de>; Thu, 20 Feb 2020 08:22:29 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1582215747; cv=pass;
        d=google.com; s=arc-20160816;
        b=h7WeUwINjKOCpbw1Mzi3kHek/f9YC9XKEkolmhH0IkaC+dBnNuwzw8sEeKuG8rYTk9
         1dpELwRzQRDxiV72HRHCSnGqvgKUGd8LlFcRknwdbWC21wgstFfn3/He33fhXQ68sOsm
         HaXPvEZLoCqawMpVcGyOUrNVM4ivLpE9R8pAizzqgpfJmQTSmBl5fn2xX5kpF6KbV5qg
         t1jbQZfzUDj/QH4Gg9dK1HjcYO6bw1tMQM9hNFGWP60e8CsyJZztWeJGoeJIzxU3imqn
         ug8nhb74ikoIRREJd04VK09jBfqSJmSMLGVgf86fPUzyvswq8gOV7D1kye/AGDBdb3Ls
         S6tw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=XMGH6d/z8HzpumihdyfiIt5ZYlFv0EjdsvSvunmE3yk=;
        b=vAvy9c56aJuU1CifzMJhwmjJydTuYt4ZCWC/qBX76JCJnHh3atizXD297wVShIj49J
         qwER86RDZC5pF8sEprJHUapvndWHEr/DNPBK+Ew2VAPKs51uckxeLFifIpTEgv3JjxXy
         6gwtbxQY71dI8OGjYWd2MLlxaf7l44FvbI4iNGh+CSchW0WfibyYpo+MLlwWODv5PsRl
         /Yakis1m/JPDb3CasoYE2xNqEDi/UEZ99F/T69PltdibsdYDzS/0LUk+Jo5ST5Zb1N5S
         ynYfN08LCv7WxPcuPWCIQ6N7QYqN4M5QV1buTqwTEbIEYamU9BYtp6LwH1z8bEm6Vg9V
         DfEA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=jYlXHI4X;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::842 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=XMGH6d/z8HzpumihdyfiIt5ZYlFv0EjdsvSvunmE3yk=;
        b=eeE6+BUzdz68unv97NF/DZzpNRgo/aoWvk2iS4lLeDFql+CPMkPoearoIRWNfpPhW9
         ePdaDd7pZ1Nvvue5XamDeDwP0icaYJS3+omHr5zWw3YyQrrdhOZc8CFjOk8vxXXjq0in
         RrFmca9aibsdTPdpNWrSMT2a2S9MFideUoDqY6wjvfGtJFGl19NzPjUykJpPHi+DKGmh
         81dE0rN0mPalsft3BHhCKgzTTBGkcsYmcgHbwW7Bq56q6n2NbiWKmai3PFKB421W9hv6
         FcAZIXV9D2JZTleywkEeujNc2EU5asa/FAZRS+edkNj5NHrJZoVXmC0XzUFy7483adLt
         KN9A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=XMGH6d/z8HzpumihdyfiIt5ZYlFv0EjdsvSvunmE3yk=;
        b=r6Q+AAWnJ+VY6ZFH27NFQWUNucX1dRnrR6gsiSmyAIeAKvWZVPDqkTA7pUdvz4rz3G
         lwbZtFjrqX0StK0x98TmslfvMf62c3V87XAiXQ+ZKWTTUK0v0+2mQlWkyovit8T0DQGr
         aa5QVrsSQSPolEqK4Mf/1aoJu1o8u/MJABv3M4cZxIyReZoqpaKCg3FSE8WQ38OeAUGr
         /c5PaQFeuZKH2KYmD7OISo8nEwhwNRgTXIdh4o7LjfkGfKvTJuVVLPZZsCO6e4B1SCIp
         QiklDjkH4A+SDQB6QigV9+jLvEYgDrlIXWarO5bbEV+q8bklHTApd2EcU8ZyC3fIGuRL
         h44A==
X-Gm-Message-State: APjAAAX295JkE4xjP7XHsYPRU5syBo+Shag+8N/l3CadKY5wnO8WKh4W
	oqUD8r0JYKkEvV2XhRFHQ1s=
X-Google-Smtp-Source: APXvYqyQunkh06o9EoxmC5iPUgSoyyOES8cLH0MkMMinGH3gY/brg6C4xgQQ35wF/09726ncHsF7CQ==
X-Received: by 2002:a02:a694:: with SMTP id j20mr26737668jam.69.1582215746589;
        Thu, 20 Feb 2020 08:22:26 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:db04:: with SMTP id b4ls306634iln.5.gmail; Thu, 20 Feb
 2020 08:22:26 -0800 (PST)
X-Received: by 2002:a92:d8d0:: with SMTP id l16mr30645104ilo.43.1582215745852;
        Thu, 20 Feb 2020 08:22:25 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1582215745; cv=none;
        d=google.com; s=arc-20160816;
        b=HYqrrgvkFiH0Xl7hsSMMLAKj0tG/L3cxMW3B6oEvMBKEJLeeLdQwxifEoynxybCAdn
         ZjLTrplwOWegCX/5WvvLd/1Hl2PZgw9CnpCkim0tqmah3NOQkRPamYEgAtHWuAybu3uI
         o0YpNgc4aQjKmaF8ubJOoK1P1/ABRNyqDPqczgzOBvmfyU3DNSDe/0X6KDVCneqsIUYL
         wc4q4eAKfRjp//giaCFHGWjei2WJHkRassrFRxL9KRYQuXtgpf1AGp6b5jCe7yLeW60k
         43wGQFC76ySPj/tJyR5XM+9Ofm7nItOG5BCodwTADof7O8YN6U4PA7OkoM3agdItURvL
         3ruQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=BxjPH3EKrwjdqvJZzEhss/or1cFxBJl747SKit3fjVY=;
        b=LzqgK1rg9huKiPLPtMHF1jvhfinHmTTVHuBNGy6qR2+0J63KgJrMSBALCutQKxd0dN
         ESzx0VBQdUmLYt/QzOeW87r9UpmmMJVqgj2RBhB+/WPLCQDYdkwSTe/gdhFjTM3qKRFR
         piLohSM+gbC63XpTF3chWGhMRFpZwhMLr1wfYqROJhVD9FOLMlYtGnTiwviUZmNtPJv5
         cwpXqS8ETeLQIFCyg6K9Dt1h5EhCrYz9ACcuRVhryUU6KCn7Ti4TFE1z05Ynwkkmy+dK
         vZvF5P66uIecnjJY9k+1V/OByaQJg3pAIjXPYK29dm1lklaAynUcvNHkbkZT+8s2xb6w
         W0mA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=jYlXHI4X;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::842 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x842.google.com (mail-qt1-x842.google.com. [2607:f8b0:4864:20::842])
        by gmr-mx.google.com with ESMTPS id z6si217111iof.2.2020.02.20.08.22.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 20 Feb 2020 08:22:25 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::842 as permitted sender) client-ip=2607:f8b0:4864:20::842;
Received: by mail-qt1-x842.google.com with SMTP id i23so3272410qtr.5
        for <kasan-dev@googlegroups.com>; Thu, 20 Feb 2020 08:22:25 -0800 (PST)
X-Received: by 2002:ac8:1b18:: with SMTP id y24mr26811345qtj.158.1582215745116;
 Thu, 20 Feb 2020 08:22:25 -0800 (PST)
MIME-Version: 1.0
References: <20200219144724.800607165@infradead.org> <20200219150745.651901321@infradead.org>
 <CACT4Y+Y+nPcnbb8nXGQA1=9p8BQYrnzab_4SvuPwbAJkTGgKOQ@mail.gmail.com>
 <20200219163025.GH18400@hirez.programming.kicks-ass.net> <20200219172014.GI14946@hirez.programming.kicks-ass.net>
 <CACT4Y+ZfxqMuiL_UF+rCku628hirJwp3t3vW5WGM8DWG6OaCeg@mail.gmail.com> <20200220120631.GX18400@hirez.programming.kicks-ass.net>
In-Reply-To: <20200220120631.GX18400@hirez.programming.kicks-ass.net>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 20 Feb 2020 17:22:14 +0100
Message-ID: <CACT4Y+bj_Onff8jUP97AVRhmdeN0QRrGcd9KRPSfnFTHAHyxtA@mail.gmail.com>
Subject: Re: [PATCH v3 22/22] x86/int3: Ensure that poke_int3_handler() is not sanitized
To: Peter Zijlstra <peterz@infradead.org>
Cc: LKML <linux-kernel@vger.kernel.org>, linux-arch <linux-arch@vger.kernel.org>, 
	Steven Rostedt <rostedt@goodmis.org>, Ingo Molnar <mingo@kernel.org>, 
	Joel Fernandes <joel@joelfernandes.org>, Greg Kroah-Hartman <gregkh@linuxfoundation.org>, 
	"Gustavo A. R. Silva" <gustavo@embeddedor.com>, Thomas Gleixner <tglx@linutronix.de>, 
	"Paul E. McKenney" <paulmck@kernel.org>, Josh Triplett <josh@joshtriplett.org>, 
	Mathieu Desnoyers <mathieu.desnoyers@efficios.com>, Lai Jiangshan <jiangshanlai@gmail.com>, 
	Andy Lutomirski <luto@kernel.org>, tony.luck@intel.com, 
	Frederic Weisbecker <frederic@kernel.org>, Dan Carpenter <dan.carpenter@oracle.com>, 
	Masami Hiramatsu <mhiramat@kernel.org>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=jYlXHI4X;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::842
 as permitted sender) smtp.mailfrom=dvyukov@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Dmitry Vyukov <dvyukov@google.com>
Reply-To: Dmitry Vyukov <dvyukov@google.com>
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

On Thu, Feb 20, 2020 at 1:06 PM Peter Zijlstra <peterz@infradead.org> wrote:
>
> On Thu, Feb 20, 2020 at 11:37:32AM +0100, Dmitry Vyukov wrote:
> > On Wed, Feb 19, 2020 at 6:20 PM Peter Zijlstra <peterz@infradead.org> wrote:
> > >
> > > On Wed, Feb 19, 2020 at 05:30:25PM +0100, Peter Zijlstra wrote:
> > >
> > > > By inlining everything in poke_int3_handler() (except bsearch :/) we can
> > > > mark the whole function off limits to everything and call it a day. That
> > > > simplicity has been the guiding principle so far.
> > > >
> > > > Alternatively we can provide an __always_inline variant of bsearch().
> > >
> > > This reduces the __no_sanitize usage to just the exception entry
> > > (do_int3) and the critical function: poke_int3_handler().
> > >
> > > Is this more acceptible?
> >
> > Let's say it's more acceptable.
> >
> > Acked-by: Dmitry Vyukov <dvyukov@google.com>
>
> Thanks, I'll go make it happen.
>
> > I guess there is no ideal solution here.
> >
> > Just a straw man proposal: expected number of elements is large enough
> > to make bsearch profitable, right? I see 1 is a common case, but the
> > other case has multiple entries.
>
> Latency was the consideration; the linear search would dramatically
> increase the runtime of the exception.
>
> The current limit is 256 entries and we're hitting that quite often.
>
> (we can trivially increase, but nobody has been able to show significant
> benefits for that -- as of yet)

I see. Thanks for explaining. Just wanted to check because inlining a
linear search would free us from all these unpleasant problems.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2Bbj_Onff8jUP97AVRhmdeN0QRrGcd9KRPSfnFTHAHyxtA%40mail.gmail.com.
