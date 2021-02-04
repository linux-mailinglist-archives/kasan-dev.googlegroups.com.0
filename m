Return-Path: <kasan-dev+bncBD62HEF5UYIBBZUK5WAAMGQEI3NGMYQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23e.google.com (mail-lj1-x23e.google.com [IPv6:2a00:1450:4864:20::23e])
	by mail.lfdr.de (Postfix) with ESMTPS id 5209030E8F5
	for <lists+kasan-dev@lfdr.de>; Thu,  4 Feb 2021 01:52:55 +0100 (CET)
Received: by mail-lj1-x23e.google.com with SMTP id m16sf1215928ljb.20
        for <lists+kasan-dev@lfdr.de>; Wed, 03 Feb 2021 16:52:55 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1612399975; cv=pass;
        d=google.com; s=arc-20160816;
        b=koHvP5Gk9tzE38eR15S5N9VfMtbNHeqxXrgLPXphkXWGOeg2ltEL4M5pHo/HxS8u+w
         HBRCnE/Zlk8VseAtJXz2knX3G2SIvQeWVXP/SNIrGKikNdlb38KwSPCHJA1KcJtzTFjJ
         cddu/4+thBUJ6ffPko4zComSk2C/ZDjSBxa+QukQkLpv1LDExrM5lBJF28l2p9ygZG4i
         UOt0VwiXOLs+tgjxv6qLzhFBKQfmnTnpXV11SJIS5AgY8VzqjeSSLe67bv1ppjSgIoWs
         srMES9vTG4MYCLFoo7tWqDTG+cQJEnw5z29laCiGr+WNOeUhUQrZJkSC2D51XasZcfhY
         hYdQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=QpN6EuYwsuscTYKTMJHKgXSWyfkITOSxsBsrYY3q/54=;
        b=PT6dZ3FVkJkzriH6rBteHxQc83uw0DLWeCEDUL+9DB1dGtnWHRSFcFXWpc6CsbuDLu
         cN5SPxlS37hV69gXzKf7TM3Cfa+zDFje+i7y6CnrxFSHBXGu2vthBj4ne1qznAPVI4Vm
         2PHq0bT3Ztz8bnGi/6HPhFH6RYYpnQ15lU4BYaUjMAqAEPseSnoZ795dbO7Ma03eBk4E
         1AtFGVkTYEB7hY8irlcWmDKgialFDDgjU3503Wfk665+1iD6fkMYTAIJraNiss65pVnN
         vcWmsDY0lrv5Ml8uvD3Xos+rrv9UAa95TT28G49+gsPI8Yz36m/CDb/a1Ut0oEWGjyWH
         Qmxg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@cloudflare.com header.s=google header.b="gVr/bTGS";
       spf=pass (google.com: domain of ivan@cloudflare.com designates 2a00:1450:4864:20::129 as permitted sender) smtp.mailfrom=ivan@cloudflare.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=cloudflare.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=QpN6EuYwsuscTYKTMJHKgXSWyfkITOSxsBsrYY3q/54=;
        b=KKMvRiydvFY2/+MPqsv5yf2t1/1+rOiPwMAT8Y4OgkhN8x9FRPRbQvde3X2wVnftvr
         TXwfQX6hy7T3eAF6/NYrrkYOhcyyDAfY92qw8OwNcgFTmlMeQ8Kl57mfk+CVGUORgFlc
         Qck9glg1oNk1D8K3w8zgZ5vhPWwIFWUEPPx2kxLvxWMt26YrWQA2/npOLV4vRhSYj2yT
         DrPYtIfHb9TLjliAsG3gW3FiMr7zClYVmiSB4Cfx24MZ0ZzfewBTSaPnisBh75szGH4n
         36WViCjzTzug6xeuHPZ1lxmiYZtPKgHC6plTLRaLRhdvRA2YxNfndgXi6Qs2hB70eNl0
         i/8g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=QpN6EuYwsuscTYKTMJHKgXSWyfkITOSxsBsrYY3q/54=;
        b=knmuckW/oYuqZHJcw2B3hWUMNUQFGzTlh8FVbQ5vnW1Hx+xyCOCWLjhf/X3nG//sWy
         Mtw4BRZo/ZMayspmuyYj4Qls4OIejE75Fvohbu9NNH6t/Yplc6wABUhbGuEE6mFs4TWI
         3zKEcfDz5jIfG1vnlvKTUjgdVRGPvUiCVhMX8lSm4w32/q1fGa6i1E/mxX4y6LDm2MAI
         z1ntoXqNVufh36eGjFWMiy23bPwAiHkMPOcoV/HLaITP7AzdC1H12C1jfABE5sFamo4r
         7MBsPfA0nHCiAvTtB4REnglkKYXW2f46bsCB1wGHbLPVJzyOoonz2xQAukaFCoxm00TF
         C9Aw==
X-Gm-Message-State: AOAM5309aQPJUbsMv1NvnLNJJFKfmwnMRGPDGOKz2xegr5oe5uIS/y8o
	afdmi4RDDLP+jkbcbNfapxo=
X-Google-Smtp-Source: ABdhPJzGPyt5KmksFwp6nV5/5OuP/TlcVB02lfTf/4nBdM7yafm0HKoAzKU8lzokplzbRfilyMfJsw==
X-Received: by 2002:a19:40d4:: with SMTP id n203mr3309317lfa.350.1612399974847;
        Wed, 03 Feb 2021 16:52:54 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:4adc:: with SMTP id m28ls1473601lfp.0.gmail; Wed, 03 Feb
 2021 16:52:53 -0800 (PST)
X-Received: by 2002:ac2:53a3:: with SMTP id j3mr3034609lfh.438.1612399973915;
        Wed, 03 Feb 2021 16:52:53 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1612399973; cv=none;
        d=google.com; s=arc-20160816;
        b=cqiC5jnpeZGaxr0WNUXm6qwc7Se8nXUKMlb777dZeFsouOM00t2OHfUqAbF9vaVG1X
         NhQmMm79lku9uEDffhTANZH0yqNZ+2OLAV3hKJ48pU+XLzg3GhONyeRYuzUEO17EvgPx
         +VQ1hTuCjtTFqtFADtx2C0AFhHico/vx8saYXRruHdq9Y8yIwfcM7ljDBQSW9yGvPDad
         WvgBlSkVQDTVVlf+6+CLTC15Ows8j4IHUU/RZC4hHpbQjvmxHL3k2O9YtQhmLq4uS/z/
         yn178H5YffYkrj9bS6S45IrYkfovf8Q5tPWeoMW7LeSFnnE7QBRQDPXrBHVui/1jn2Js
         QkPw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=z0j8u/cgjNk63BrE1ROiiO7WIMH6hW9ZaraaxN/GjSE=;
        b=GrcdJ3ograUAWSe46TcnFTf4RR3AXl+UT4t37B+PmjynhWMWu7MUlgdotJ48K8x0RV
         eEpCoQNWu9chqp2Ar40DCDUwV/LL0JyR4DZAZSbSbvALLYfF3zeVu9zbtaW6SCdixG+U
         VJcdnslyk3AhrbrKjHyGb/D6mJ1fMn0JvMmLeuThOwgAQXkmHLutdKpXUVhoNPLNmviP
         GtC9CRetnt25B7OwKrsCHzaQCzqeZhMH/r2a4cBhGvQPKimo8ZZPBOLQbPYMOdBLukSZ
         0FbgHEKPVM6glBMqltBN46yfy4y4uQSUMhMOBvHX1d/GulGH7sP2YWcaf7syNYL81nZV
         LtOQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@cloudflare.com header.s=google header.b="gVr/bTGS";
       spf=pass (google.com: domain of ivan@cloudflare.com designates 2a00:1450:4864:20::129 as permitted sender) smtp.mailfrom=ivan@cloudflare.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=cloudflare.com
Received: from mail-lf1-x129.google.com (mail-lf1-x129.google.com. [2a00:1450:4864:20::129])
        by gmr-mx.google.com with ESMTPS id u15si175014ljj.5.2021.02.03.16.52.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 03 Feb 2021 16:52:53 -0800 (PST)
Received-SPF: pass (google.com: domain of ivan@cloudflare.com designates 2a00:1450:4864:20::129 as permitted sender) client-ip=2a00:1450:4864:20::129;
Received: by mail-lf1-x129.google.com with SMTP id b2so2049606lfq.0
        for <kasan-dev@googlegroups.com>; Wed, 03 Feb 2021 16:52:53 -0800 (PST)
X-Received: by 2002:a05:6512:3190:: with SMTP id i16mr3254379lfe.200.1612399973566;
 Wed, 03 Feb 2021 16:52:53 -0800 (PST)
MIME-Version: 1.0
References: <CABWYdi3HjduhY-nQXzy2ezGbiMB1Vk9cnhW2pMypUa+P1OjtzQ@mail.gmail.com>
 <CABWYdi27baYc3ShHcZExmmXVmxOQXo9sGO+iFhfZLq78k8iaAg@mail.gmail.com>
 <YBrTaVVfWu2R0Hgw@hirez.programming.kicks-ass.net> <CABWYdi2ephz57BA8bns3reMGjvs5m0hYp82+jBLZ6KD3Ba6zdQ@mail.gmail.com>
 <20210203190518.nlwghesq75enas6n@treble> <CABWYdi1ya41Ju9SsHMtRQaFQ=s8N23D3ADn6OV6iBwWM6H8=Zw@mail.gmail.com>
 <20210203232735.nw73kugja56jp4ls@treble> <CABWYdi1zd51Jb35taWeGC-dR9SChq-4ixvyKms3KOKgV0idfPg@mail.gmail.com>
 <20210204001700.ry6dpqvavcswyvy7@treble>
In-Reply-To: <20210204001700.ry6dpqvavcswyvy7@treble>
From: "'Ivan Babrou' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 3 Feb 2021 16:52:42 -0800
Message-ID: <CABWYdi0p91Y+TDUu38eey-p2GtxL6f=VHicTxS629VCMmrNLpQ@mail.gmail.com>
Subject: Re: BUG: KASAN: stack-out-of-bounds in unwind_next_frame+0x1df5/0x2650
To: Josh Poimboeuf <jpoimboe@redhat.com>
Cc: Peter Zijlstra <peterz@infradead.org>, kernel-team <kernel-team@cloudflare.com>, 
	Ignat Korchagin <ignat@cloudflare.com>, Hailong liu <liu.hailong6@zte.com.cn>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>, x86@kernel.org, 
	"H. Peter Anvin" <hpa@zytor.com>, Miroslav Benes <mbenes@suse.cz>, Julien Thierry <jthierry@redhat.com>, 
	Jiri Slaby <jirislaby@kernel.org>, kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	linux-kernel <linux-kernel@vger.kernel.org>, Alasdair Kergon <agk@redhat.com>, 
	Mike Snitzer <snitzer@redhat.com>, dm-devel@redhat.com, 
	"Steven Rostedt (VMware)" <rostedt@goodmis.org>, Alexei Starovoitov <ast@kernel.org>, 
	Daniel Borkmann <daniel@iogearbox.net>, Martin KaFai Lau <kafai@fb.com>, Song Liu <songliubraving@fb.com>, 
	Yonghong Song <yhs@fb.com>, Andrii Nakryiko <andriin@fb.com>, John Fastabend <john.fastabend@gmail.com>, 
	KP Singh <kpsingh@chromium.org>, Robert Richter <rric@kernel.org>, 
	"Joel Fernandes (Google)" <joel@joelfernandes.org>, Mathieu Desnoyers <mathieu.desnoyers@efficios.com>, 
	Linux Kernel Network Developers <netdev@vger.kernel.org>, bpf@vger.kernel.org, 
	Alexey Kardashevskiy <aik@ozlabs.ru>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: ivan@cloudflare.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@cloudflare.com header.s=google header.b="gVr/bTGS";       spf=pass
 (google.com: domain of ivan@cloudflare.com designates 2a00:1450:4864:20::129
 as permitted sender) smtp.mailfrom=ivan@cloudflare.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=cloudflare.com
X-Original-From: Ivan Babrou <ivan@cloudflare.com>
Reply-To: Ivan Babrou <ivan@cloudflare.com>
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

On Wed, Feb 3, 2021 at 4:17 PM Josh Poimboeuf <jpoimboe@redhat.com> wrote:
>
> On Wed, Feb 03, 2021 at 03:30:35PM -0800, Ivan Babrou wrote:
> > > > > Can you recreate with this patch, and add "unwind_debug" to the cmdline?
> > > > > It will spit out a bunch of stack data.
> > > >
> > > > Here's the three I'm building:
> > > >
> > > > * https://github.com/bobrik/linux/tree/ivan/static-call-5.9
> > > >
> > > > It contains:
> > > >
> > > > * v5.9 tag as the base
> > > > * static_call-2020-10-12 tag
> > > > * dm-crypt patches to reproduce the issue with KASAN
> > > > * x86/unwind: Add 'unwind_debug' cmdline option
> > > > * tracepoint: Fix race between tracing and removing tracepoint
> > > >
> > > > The very same issue can be reproduced on 5.10.11 with no patches,
> > > > but I'm going with 5.9, since it boils down to static call changes.
> > > >
> > > > Here's the decoded stack from the kernel with unwind debug enabled:
> > > >
> > > > * https://gist.github.com/bobrik/ed052ac0ae44c880f3170299ad4af56b
> > > >
> > > > See my first email for the exact commands that trigger this.
> > >
> > > Thanks.  Do you happen to have the original dmesg, before running it
> > > through the post-processing script?
> >
> > Yes, here it is:
> >
> > * https://gist.github.com/bobrik/8c13e6a02555fb21cadabb74cdd6f9ab
>
> It appears the unwinder is getting lost in crypto code.  No idea what
> this has to do with static calls though.  Or maybe you're seeing
> multiple issues.
>
> Does this fix it?

It does for the dm-crypt case! But so does the following commit in
5.11 (and 5.10.12):

* https://github.com/torvalds/linux/commit/ce8f86ee94?w=1

The reason I stuck to dm-crypt reproduction is that it reproduces reliably.

We also have the following stack that doesn't touch any crypto:

* https://gist.github.com/bobrik/40e2559add2f0b26ae39da30dc451f1e

I cannot reproduce this one, and it took 2 days of uptime for it to
happen. Is there anything I can do to help diagnose it?

My goal is to enable multishot KASAN in our pre-production
environment, but currently it sometimes starves TX queues on the NIC
due to multiple reports in a row in an interrupt about
unwind_next_frame, which disables network interface, which is not
something we can tolerate.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CABWYdi0p91Y%2BTDUu38eey-p2GtxL6f%3DVHicTxS629VCMmrNLpQ%40mail.gmail.com.
