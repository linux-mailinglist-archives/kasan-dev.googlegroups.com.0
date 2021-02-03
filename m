Return-Path: <kasan-dev+bncBCSJ7B6JQALRBBPD5SAAMGQEPAF7BLI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3b.google.com (mail-io1-xd3b.google.com [IPv6:2607:f8b0:4864:20::d3b])
	by mail.lfdr.de (Postfix) with ESMTPS id CFB0530E74A
	for <lists+kasan-dev@lfdr.de>; Thu,  4 Feb 2021 00:28:06 +0100 (CET)
Received: by mail-io1-xd3b.google.com with SMTP id j2sf1140060iow.18
        for <lists+kasan-dev@lfdr.de>; Wed, 03 Feb 2021 15:28:06 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1612394886; cv=pass;
        d=google.com; s=arc-20160816;
        b=qBkVG5JSXPyKwvawO3SpM4a77ViaQ142FYGVdMR1DPbIXfVv2/Wnh3b78xyUS0j/2T
         tMTZWG7VzU5zRXjFBiF4x/Wtn+YuFcsJz5v+xRV8ZuyZ7Gi9ycsVQSR1c61g4VgT4DBE
         ARVtNBCVNuTGv6ModqT2uhR6BPDp6uAk5LoLoeUC6wztjDFfHoGHY26rABhuOHr6Db27
         iPwDBbVHvwSL+Cuq761VKB87wosqSre8fp2jYfI+/a+WlYoy38lLOH8nLYi7oT39Yorn
         3t80CCYNbUCmdGtXsHi8jYi0szFnho2rLSeHhvJbKDcqW4BzKDd/f2zx4YghFmelmEql
         QVQA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=6nxGFhtf5GjlY9RtLY44mGbhcV1uBRG7hnmb77XMj8E=;
        b=oCcwOtUzWQ9hx8LtZzjg+3FkkOSAfhnKS08Ngucc/E5ihxp85XPjcVqXTe14+CcBw9
         3Dgo1OnrwefS5zdNqDNP1jrFtH9rsBtTzcTubvh7N+1P2wnTSRzth+5jLT2PqfF2DmWq
         rJPMxKnwWAku1fqxG66FjYb0aWBSx6tTf2KyMEHQ9f5xc5CxKZgNwAJtqRE2+kFxB0fB
         g+4cC6AmpG+qabreCI9nWzb7LRYpcOA6gYXyByx5oghXkujuz+DNmdBD+0N4pD6828yW
         /Y+KFTiK/Rff4k55VeeNAgkz7koxgSUo3MwoQ5zn6i2Ci1jmb3lQy5XbxlnF3k+DF9x/
         o1ow==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=Eazmsv3W;
       spf=pass (google.com: domain of jpoimboe@redhat.com designates 216.205.24.124 as permitted sender) smtp.mailfrom=jpoimboe@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=6nxGFhtf5GjlY9RtLY44mGbhcV1uBRG7hnmb77XMj8E=;
        b=peMtcFeyB2Cn4H9YNkUJrdwKaFfdn/p/0ByIdO52MidY/sZCjWbGdPEKj1uuKIAEu7
         I/0iLqqV/rEZ7R2H1y9hQMNMDUIqI2d8O7yfmFlHiQnKKRqyugOp2lrqm6hNpBnd8D40
         NI1E/r83tRMkv4Aq/RPphk5w/Xub3VwFcBJm88k+MEOLhMJ6GtfWV8vIC1x24rBglnsV
         6IhXc518OIqH2PfKnRLhiY+D9y6DS519AGl0VWOBun36XOohe6saUu2H2UG3gxOJSu7W
         2VDRYWLfgaB+h+zV95VQfrW8l8j7L7fZbunToXz9ZPQi7+rThF4sPAPtlD1UB4l3HCQ7
         F0GA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=6nxGFhtf5GjlY9RtLY44mGbhcV1uBRG7hnmb77XMj8E=;
        b=sPmdSJuDAT0QDelwTyYKikvdYzl6rz57udtKTBfXmxys6nd//By0/joyV1YmsMSo5j
         xHXOeY0ltYG04GC+Df3dwOUiqEmCgd48SeHWKHcMLgvmXetVddlSxb5mhQvhkbKw4PsH
         AtuRC0nu3i2BmyjirtL22EOMD86hcB2ynSlgIhRz4Ai4hkubUZBfa/2568Qe8NC2INP3
         WR/OQBfE4J0RMiz+JpLXMFD1BrXTXzl1nemFQJsrMzY3oVvdh0RudcVQI1F5cR9/B599
         3RVNe/DEKkyJ4HPCaokuP1VnJ+OoMxZEBjgA+9VLDH0woAnE2xJW++bP3azmO38/TSr4
         OOtw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531iJiQgHW63BSa7q9R6ZWIbuMSTYhVl6e2EpB2lanQZDnRb7kFV
	wGBluEEPQBM5oJpC34inA3s=
X-Google-Smtp-Source: ABdhPJxVSIRAjbN90HTzoGJs9dSq9KA+VfrFbXwGSgBc1mOWSH7Tcyptwu07r7BunFPPNMFUFpqTFA==
X-Received: by 2002:a05:6e02:1b8b:: with SMTP id h11mr4524179ili.32.1612394885821;
        Wed, 03 Feb 2021 15:28:05 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:5ac:: with SMTP id k12ls856554ils.7.gmail; Wed, 03
 Feb 2021 15:28:05 -0800 (PST)
X-Received: by 2002:a05:6e02:12e3:: with SMTP id l3mr4571719iln.24.1612394885405;
        Wed, 03 Feb 2021 15:28:05 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1612394885; cv=none;
        d=google.com; s=arc-20160816;
        b=gc7+ZSOzELycnLBKEEYmxJdAgBepoTYdVspUMoICetch2BrlOvTVIYOAsdXPwajH/0
         3xipKC/SbpK877d3GuWBWOpUtSsJF++8QoGl+oqtOtMkxAlTS3CIlzuIjWddhBgLectn
         YaBc+L5/PMe8eCyzf6h16NA7WCn90WACgkrQ5N1xZIoTBOVNs4pjhrBb3oXnkp/GMixs
         sxuvBo/O6g8UMrHCWaXYQkvabEh8cAlzParyKxbEs1vQ9F+ZWMctlklXbd+zhdeS4rou
         O3oArqLOBbf5LLKFnQ/pTk2HXwYls0sFvdu/8x2tm4HRwNo71RNOHe5dTtez5aLOdutZ
         OPEw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=qk0MRndwsudTUKG83wO3htOmgtnK5DShnl+yULNhutc=;
        b=muK6z9TlsvDo+Owc39A9xexEG0mC+qNyUOFBtM9+qGm/DR3ZcnRbKOc6i1kVV5au9U
         GOQBqeJMmu9+CIOZaovcLnv6xnB4id1kMIKGiP0zNnC3244EADgzFslVjeAbLFp3xgwa
         Oo7k2ODinjOVCl/WxWoqVzLR0M/5tz9lcckhsLeymLtIftuXF4UPnOxF/8wwplhTp14x
         /ECY+EDbLyvBxwxSOTNXKhQUVOlSmQ3HUUh2PNgIZu8ugJnXPDqqek/khcZHsBkINpRo
         7G3MXmYAORIhBeQLyq2CmuNoxg/MZbxcTEaOZbzeeA9gyXsmEvJvwm5lv5zd1zucImUj
         Pi1g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=Eazmsv3W;
       spf=pass (google.com: domain of jpoimboe@redhat.com designates 216.205.24.124 as permitted sender) smtp.mailfrom=jpoimboe@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [216.205.24.124])
        by gmr-mx.google.com with ESMTPS id o7si235894ilt.4.2021.02.03.15.28.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 03 Feb 2021 15:28:05 -0800 (PST)
Received-SPF: pass (google.com: domain of jpoimboe@redhat.com designates 216.205.24.124 as permitted sender) client-ip=216.205.24.124;
Received: from mimecast-mx01.redhat.com (mimecast-mx01.redhat.com
 [209.132.183.4]) (Using TLS) by relay.mimecast.com with ESMTP id
 us-mta-217-sP3f55tYM9yrX1Mu_6I9qQ-1; Wed, 03 Feb 2021 18:28:00 -0500
X-MC-Unique: sP3f55tYM9yrX1Mu_6I9qQ-1
Received: from smtp.corp.redhat.com (int-mx06.intmail.prod.int.phx2.redhat.com [10.5.11.16])
	(using TLSv1.2 with cipher AECDH-AES256-SHA (256/256 bits))
	(No client certificate requested)
	by mimecast-mx01.redhat.com (Postfix) with ESMTPS id EA5B41083E9D;
	Wed,  3 Feb 2021 23:27:55 +0000 (UTC)
Received: from treble (ovpn-113-81.rdu2.redhat.com [10.10.113.81])
	by smtp.corp.redhat.com (Postfix) with ESMTPS id 27B245C1B4;
	Wed,  3 Feb 2021 23:27:44 +0000 (UTC)
Date: Wed, 3 Feb 2021 17:27:35 -0600
From: Josh Poimboeuf <jpoimboe@redhat.com>
To: Ivan Babrou <ivan@cloudflare.com>
Cc: Peter Zijlstra <peterz@infradead.org>,
	kernel-team <kernel-team@cloudflare.com>,
	Ignat Korchagin <ignat@cloudflare.com>,
	Hailong liu <liu.hailong6@zte.com.cn>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Thomas Gleixner <tglx@linutronix.de>,
	Ingo Molnar <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>,
	x86@kernel.org, "H. Peter Anvin" <hpa@zytor.com>,
	Miroslav Benes <mbenes@suse.cz>,
	Julien Thierry <jthierry@redhat.com>,
	Jiri Slaby <jirislaby@kernel.org>, kasan-dev@googlegroups.com,
	linux-mm@kvack.org, linux-kernel <linux-kernel@vger.kernel.org>,
	Alasdair Kergon <agk@redhat.com>, Mike Snitzer <snitzer@redhat.com>,
	dm-devel@redhat.com,
	"Steven Rostedt (VMware)" <rostedt@goodmis.org>,
	Alexei Starovoitov <ast@kernel.org>,
	Daniel Borkmann <daniel@iogearbox.net>,
	Martin KaFai Lau <kafai@fb.com>, Song Liu <songliubraving@fb.com>,
	Yonghong Song <yhs@fb.com>, Andrii Nakryiko <andriin@fb.com>,
	John Fastabend <john.fastabend@gmail.com>,
	KP Singh <kpsingh@chromium.org>, Robert Richter <rric@kernel.org>,
	"Joel Fernandes (Google)" <joel@joelfernandes.org>,
	Mathieu Desnoyers <mathieu.desnoyers@efficios.com>,
	Linux Kernel Network Developers <netdev@vger.kernel.org>,
	bpf@vger.kernel.org, Alexey Kardashevskiy <aik@ozlabs.ru>
Subject: Re: BUG: KASAN: stack-out-of-bounds in
 unwind_next_frame+0x1df5/0x2650
Message-ID: <20210203232735.nw73kugja56jp4ls@treble>
References: <CABWYdi3HjduhY-nQXzy2ezGbiMB1Vk9cnhW2pMypUa+P1OjtzQ@mail.gmail.com>
 <CABWYdi27baYc3ShHcZExmmXVmxOQXo9sGO+iFhfZLq78k8iaAg@mail.gmail.com>
 <YBrTaVVfWu2R0Hgw@hirez.programming.kicks-ass.net>
 <CABWYdi2ephz57BA8bns3reMGjvs5m0hYp82+jBLZ6KD3Ba6zdQ@mail.gmail.com>
 <20210203190518.nlwghesq75enas6n@treble>
 <CABWYdi1ya41Ju9SsHMtRQaFQ=s8N23D3ADn6OV6iBwWM6H8=Zw@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CABWYdi1ya41Ju9SsHMtRQaFQ=s8N23D3ADn6OV6iBwWM6H8=Zw@mail.gmail.com>
X-Scanned-By: MIMEDefang 2.79 on 10.5.11.16
X-Original-Sender: jpoimboe@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=Eazmsv3W;
       spf=pass (google.com: domain of jpoimboe@redhat.com designates
 216.205.24.124 as permitted sender) smtp.mailfrom=jpoimboe@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
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

On Wed, Feb 03, 2021 at 02:41:53PM -0800, Ivan Babrou wrote:
> On Wed, Feb 3, 2021 at 11:05 AM Josh Poimboeuf <jpoimboe@redhat.com> wrote:
> >
> > On Wed, Feb 03, 2021 at 09:46:55AM -0800, Ivan Babrou wrote:
> > > > Can you pretty please not line-wrap console output? It's unreadable.
> > >
> > > GMail doesn't make it easy, I'll send a link to a pastebin next time.
> > > Let me know if you'd like me to regenerate the decoded stack.
> > >
> > > > > edfd9b7838ba5e47f19ad8466d0565aba5c59bf0 is the first bad commit
> > > > > commit edfd9b7838ba5e47f19ad8466d0565aba5c59bf0
> > > >
> > > > Not sure what tree you're on, but that's not the upstream commit.
> > >
> > > I mentioned that it's a rebased core-static_call-2020-10-12 tag and
> > > added a link to the upstream hash right below.
> > >
> > > > > Author: Steven Rostedt (VMware) <rostedt@goodmis.org>
> > > > > Date:   Tue Aug 18 15:57:52 2020 +0200
> > > > >
> > > > >     tracepoint: Optimize using static_call()
> > > > >
> > > >
> > > > There's a known issue with that patch, can you try:
> > > >
> > > >   http://lkml.kernel.org/r/20210202220121.435051654@goodmis.org
> > >
> > > I've tried it on top of core-static_call-2020-10-12 tag rebased on top
> > > of v5.9 (to make it reproducible), and the patch did not help. Do I
> > > need to apply the whole series or something else?
> >
> > Can you recreate with this patch, and add "unwind_debug" to the cmdline?
> > It will spit out a bunch of stack data.
> 
> Here's the three I'm building:
> 
> * https://github.com/bobrik/linux/tree/ivan/static-call-5.9
> 
> It contains:
> 
> * v5.9 tag as the base
> * static_call-2020-10-12 tag
> * dm-crypt patches to reproduce the issue with KASAN
> * x86/unwind: Add 'unwind_debug' cmdline option
> * tracepoint: Fix race between tracing and removing tracepoint
> 
> The very same issue can be reproduced on 5.10.11 with no patches,
> but I'm going with 5.9, since it boils down to static call changes.
> 
> Here's the decoded stack from the kernel with unwind debug enabled:
> 
> * https://gist.github.com/bobrik/ed052ac0ae44c880f3170299ad4af56b
> 
> See my first email for the exact commands that trigger this.

Thanks.  Do you happen to have the original dmesg, before running it
through the post-processing script?


I assume you're using decode_stacktrace.sh?  It could use some
improvement, it's stripping the function offset.

Also spaces are getting inserted in odd places, messing the alignment.

[  137.291837][    C0] ffff88809c409858: d7c4f3ce817a1700 (0xd7c4f3ce817a1700)
[  137.291837][    C0] ffff88809c409860: 0000000000000000 (0x0)
[  137.291839][    C0] ffff88809c409868: 00000000ffffffff (0xffffffff)
[ 137.291841][ C0] ffff88809c409870: ffffffffa4f01a52 unwind_next_frame (arch/x86/kernel/unwind_orc.c:380 arch/x86/kernel/unwind_orc.c:553)
[ 137.291843][ C0] ffff88809c409878: ffffffffa4f01a52 unwind_next_frame (arch/x86/kernel/unwind_orc.c:380 arch/x86/kernel/unwind_orc.c:553)
[  137.291844][    C0] ffff88809c409880: ffff88809c409ac8 (0xffff88809c409ac8)
[  137.291845][    C0] ffff88809c409888: 0000000000000086 (0x86)

-- 
Josh

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210203232735.nw73kugja56jp4ls%40treble.
