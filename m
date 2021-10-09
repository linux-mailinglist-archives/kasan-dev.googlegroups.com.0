Return-Path: <kasan-dev+bncBCJZRXGY5YJBBU6URCFQMGQEUS5JZLA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe38.google.com (mail-vs1-xe38.google.com [IPv6:2607:f8b0:4864:20::e38])
	by mail.lfdr.de (Postfix) with ESMTPS id 2168C427E17
	for <lists+kasan-dev@lfdr.de>; Sun, 10 Oct 2021 01:48:37 +0200 (CEST)
Received: by mail-vs1-xe38.google.com with SMTP id a67-20020a671a46000000b002d50de61230sf1689830vsa.2
        for <lists+kasan-dev@lfdr.de>; Sat, 09 Oct 2021 16:48:37 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1633823316; cv=pass;
        d=google.com; s=arc-20160816;
        b=BoAc0nKNaIxSh2Xu+90NDW/dnp/Ddk5VhLLeHmMeTZq3Ie5uruO01ufQDdl5SG2ctL
         9X6yiYgaBKj3RSg4KYU3jhOBA81wL7ESWW+4jdrcRJZ6TkOzpe2U/88pr0KQkqwEjyAL
         BVC2pKpwyJhs7dl8IjuO9gC7wJYD9bHDvx2rV3OJbGuwETa6cgE1P+9AXGJ77WNTcbvr
         q2h7wJK7fDcBxsacLbSKxckdXFlCc7jbo+ceNDPN9orAyiwuFWF0G819Gd+guVEOtM3o
         VGQ0eEdZmG0/kwyE9mdXMuXxHLtR/CXak3pC7cxfXHlHms3bciRqDaxeHkYpIX4KdgaO
         bEiw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:reply-to:message-id:subject:cc:to:from:date
         :sender:dkim-signature;
        bh=1dbuWh9ZBzBFI5eqonYYCBbK9qIrOKlrchBaMHDXhGQ=;
        b=Lcb3CddlB749L1nnTVShlxwGdGLX5C3/MGanZ19z7nhVU2oQYoWYFF1db17sxV6eyv
         5wfxbLhw/2HmrEY1sNjNfpExS5lh6mcOH7yVflgcnzaYfDowpYUa++0rQ7UMxOFwbTF+
         cl0Hjxqj2aPbg51ImtEIkvrUGi4DkO5Mrx2qW3fTCFXfGEDVLoGKUV6hLzpXtoXE9xQf
         yPzbCgUaiX8UP4M2H3cvdsNp1irKOQTl3e2he5mDcUfPFIE86in/NkMosjmN+4QosO/B
         OtkiF7occOwknfeUdTzBD73PUIROOd3rEJhZfvlEH2ARnW/iJrz6G3Ts4AJKJZQ6ddSh
         2MbA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=l4NlNTMh;
       spf=pass (google.com: domain of srs0=ppam=o5=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=pPAm=O5=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=1dbuWh9ZBzBFI5eqonYYCBbK9qIrOKlrchBaMHDXhGQ=;
        b=MJLhsj9wtFScUfZA9mwc2SZf1+zmnL1RVBvuaFOiPGZc11Q7VkoIEAFbhXlXWbDrMP
         Mk1cb7DcHY05Nl/6usP/1FD79FlYDp3H/kmfR5ipWdTo5sxcTpJj2fpCXkbzRTVOMCw9
         oOZLw1l6AHaL9GxWJfJLMFVzzicKo6Q804o5N3MxoGAQwtsXVVuvKk/14bBebRGTq/eP
         5tzRHerJ2DjkFUqzEacvvihWuYDZuYc8IdRERDlysu9iLVE3EZqD6Jeeky/AGhvHAAZA
         Rsas56xViZdPuN+vKKcBFvIcQl2AguEOEoeKcZTCcB0HVhOE5HHW21IVsQlDgScqqrME
         3GCA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=1dbuWh9ZBzBFI5eqonYYCBbK9qIrOKlrchBaMHDXhGQ=;
        b=h0ZCNuROBqJt9lrNAQmGF/DkJk1ZlgCQE4Y/IGID3YEN0RczqvVLcsPCuRAjRvtNPA
         a/fnkEwFGJcraYe7PUiJs9wrptsRiHoaP8tNQZVYW13FAL8aUgXnS1L6JTz4tBXASS1m
         IPq9+5T4ccaT+dDvcuS85veqb+jWmSKcVgy6yY1aRaYiSG8eKDWlpwRHE3fqjtGdAwAa
         PLPHCoQJVxOYAnJ1zvmj1qpvb6SpdTlL2UsVkuKlASkelK4pI+8FoxuNFhPQo2KaGtKJ
         crvKA8cfmemPpILRLkrmiih9IRMpbQgdO9+Q0WGizxM2K5vDU7vokPkCXt8C9ND99KjA
         JOtw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532r8BFv2TG19LGoVx3VbOvJ6wd7Zf36LuyOLxu5xYsqBc1SyJo+
	nT1M7M+JG/mgXSY5ix2nnbE=
X-Google-Smtp-Source: ABdhPJzN1vHSWRLCVOx3iZMilohX0VyI5UT+boNdqvWFA/U79xueYzgg17/T98EVyPLQHo0JfCfG1w==
X-Received: by 2002:a05:6130:426:: with SMTP id ba38mr10587723uab.108.1633823315896;
        Sat, 09 Oct 2021 16:48:35 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ab0:2907:: with SMTP id v7ls1041299uap.5.gmail; Sat, 09 Oct
 2021 16:48:35 -0700 (PDT)
X-Received: by 2002:ab0:540e:: with SMTP id n14mr10044546uaa.73.1633823315438;
        Sat, 09 Oct 2021 16:48:35 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1633823315; cv=none;
        d=google.com; s=arc-20160816;
        b=Il9SXHDSxai8pyJyI6Imrzo1zVZwWlcdpfcrq/+UY4e3pMkKAwf6wiL1B24KGhY2Km
         vD8lroeShNsVuIgwAv18x0Ad5aovksvSbWn+OXkJawGtuOHAFNo9Oa8Eaxt756QewRWJ
         +Q5dIn/oykYC9apz0j88qH+6w5eaYUgTErUGKWnhjTqKj79yTdds7XS+eftttht0pLkN
         h1RYQLTJhcbsf3rxBctjJEGWvlJ6k4G0H05t5SvIe+fe7h31gs/NAAhgf0VXgJaOg2IE
         Ov3FtX94nKLbefO9HvEDF8mOGbP+kQK+wimCQ5hHfSdpCuDdN7rdAlBVSGPIRgylJ4Hb
         hhVw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=A097Pn36Tq8aeVKovOC6CYYvK004o7CsJpRHyrEVZgs=;
        b=lW0tYuxSaq7s+ibQx424UgjGa3UXcoWZ4MJ3y88KVH74jx0uFkvsYsA14wQihLfKpN
         0c2onDmznW6FVNs4vrYMqULNWgGOoitmt78TnSL7BVHD53If3r7Vr5niUofdWIRCTLr/
         XQhigXiO4l3y1DWh0sBOb/hAT0mSws8cGIKzCFirfvWG1yDsMQv6DeQcy3oMmoMxmNGV
         JgkwkQgOzzlHCqG1bvJ182kve6G+m7GPOCUOsnPgJfFEqbI99vM1S97+wFf2VRe50dvE
         qqXOVIYRY1n7jIT1X31q31f6oiMoyB/6xoxJbijSxIKGsu7OqWfJU8AbbK/tgO1MLVGL
         7ujA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=l4NlNTMh;
       spf=pass (google.com: domain of srs0=ppam=o5=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=pPAm=O5=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id u64si201794vku.4.2021.10.09.16.48.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sat, 09 Oct 2021 16:48:35 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=ppam=o5=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 657A160F43;
	Sat,  9 Oct 2021 23:48:34 +0000 (UTC)
Received: by paulmck-ThinkPad-P17-Gen-1.home (Postfix, from userid 1000)
	id 276B65C0887; Sat,  9 Oct 2021 16:48:34 -0700 (PDT)
Date: Sat, 9 Oct 2021 16:48:34 -0700
From: "Paul E. McKenney" <paulmck@kernel.org>
To: Miguel Ojeda <miguel.ojeda.sandonis@gmail.com>
Cc: Gary Guo <gary@garyguo.net>, Marco Elver <elver@google.com>,
	Boqun Feng <boqun.feng@gmail.com>,
	kasan-dev <kasan-dev@googlegroups.com>,
	rust-for-linux <rust-for-linux@vger.kernel.org>
Subject: Re: Can the Kernel Concurrency Sanitizer Own Rust Code?
Message-ID: <20211009234834.GX880162@paulmck-ThinkPad-P17-Gen-1>
Reply-To: paulmck@kernel.org
References: <CANpmjNOA3NfGDLK2dribst+0899GrwWsinMp7YKYiGvAjnT-qA@mail.gmail.com>
 <CANiq72k2TwCY1Os2siGB=hBNRtrhzJtgRS5FQ3JDDYM-TXyq2Q@mail.gmail.com>
 <20211007185029.GK880162@paulmck-ThinkPad-P17-Gen-1>
 <20211007224247.000073c5@garyguo.net>
 <20211007223010.GN880162@paulmck-ThinkPad-P17-Gen-1>
 <20211008000601.00000ba1@garyguo.net>
 <20211007234247.GO880162@paulmck-ThinkPad-P17-Gen-1>
 <CANiq72nLXmN0SJOQ-aGD4P2dUTs_vXBXMDnr2eWP-+R7H2ecEw@mail.gmail.com>
 <20211008235744.GU880162@paulmck-ThinkPad-P17-Gen-1>
 <CANiq72m76-nRDNAceEqUmC_k75FZj+OZr1_HSFUdksysWgCsCA@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANiq72m76-nRDNAceEqUmC_k75FZj+OZr1_HSFUdksysWgCsCA@mail.gmail.com>
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=l4NlNTMh;       spf=pass
 (google.com: domain of srs0=ppam=o5=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=pPAm=O5=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
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

On Sat, Oct 09, 2021 at 06:30:10PM +0200, Miguel Ojeda wrote:
> On Sat, Oct 9, 2021 at 1:57 AM Paul E. McKenney <paulmck@kernel.org> wrote:
> >
> > But some other library could have a wild-pointer bug in unsafe Rust code
> > or in C code, correct?  And such a bug could subvert a rather wide range
> 
> Indeed, but that would require a bug somewhere in unsafe Rust code --
> safe Rust code cannot do so on its own. That is why I mentioned
> "outside safe code".

Understood.

> > of code, including that of correct libraries, right?  If I am wrong,
> > please tell me what Rust is doing to provide the additional protection.
> 
> Of course, an unsafe code bug, or C code going wild, or a compiler
> bug, or a hardware bug, or a single-event upset etc. can subvert
> everything (see the other reply).
> 
> This is why I emphasize that the guarantees Rust aims to provide are
> conditional to all that. After all, it is just a language -- there is
> no way it could make a system (including hardware) immune to that.

And understood here as well.

> > I would like to believe that, but I have seen too many cases where
> > UB propagates far and wide.  :-(
> 
> To be clear, the "effectively contain UB" above did not imply that
> Rust somehow prevents UB from breaking everything if it actually
> happens (this relates to the previous point). It means that, as a
> tool, it seems to be an effective way to write less UB-related bugs
> compared to using languages like C.
> 
> In other words, UB-related bugs can definitely still happen, but the
> idea is to reduce the amount of issues involving UB as much as
> possible via reducing the amount of code that we need to write that
> requires potentially-UB operations. So it is a matter of reducing the
> probabilities you mentioned -- but Rust alone will not make them zero
> nor guarantee no UB in an absolute manner.

And understood here, too.

> > Except that all too many compiler writers are actively looking for more
> > UB to exploit.  So this would be a difficult moving target.
> 
> If you mean it in the sense of C and C++ (i.e. where it is easy to
> trigger UB without realizing it because the optimizer may not take
> advantage of that today, but may actually take advantage of it
> tomorrow); then in safe Rust that would be a bug.
> 
> That is, such a bug may be in the compiler frontend, it may be a bug
> in LLVM, or in the language spec, or in the stdlib, or in our own
> unsafe code in the kernel, etc. But ultimately, it would be considered
> a bug.
> 
> The idea is that the safe subset of Rust does not allow you to write
> UB at all, whatever you write. So, for instance, no optimizer (whether
> today's version or tomorrow's version) will be able to break your code
> (again, assuming no bugs in the optimizer etc.).
> 
> This is in contrast with C (or unsafe Rust!), where not only we have
> the risk of compiler bugs like in safe Rust, but also all the UB
> landmines in the language itself that correct optimizers can exploit
> (assuming we agreed what is "legal" by the standard, which is a whole
> another discussion).

As long as a significant number of compiler writers evaluate themselves by
improved optimization, they will be working hard to create additional UB
opportunities.  From what you say above, their doing so has the potential
to generate bugs in the Rust compiler.  Suppose this happens ten years
from now.  Do you propose to force rework not just the compiler, but
large quantities of Rust code that might have been written by that time?

> > Let me see if I can summarize with a bit of interpretation...
> >
> > 1.      Rust modules are a pointless distraction here.  Unless you object,
> >         I will remove all mention of them from this blog series.
> 
> I agree it is best to omit them. However, it is not that Rust modules
> are irrelevant/unrelated to the safety story in Rust, but for
> newcomers to Rust, I think it is a detail that can easily mislead
> them.

Plus the connection to a Rust memory model is not all that strong.

> > 2.      Safe Rust code might have bugs, as might any other code.
> >
> >         For example, even if Linux-kernel RCU were to somehow be rewritten
> >         into Rust with no unsafe code whatsoever, there is not a verifier
> >         alive today that is going to realize that changing the value of
> >         RCU_JIFFIES_FQS_DIV from 256 to (say) 16 is a really bad idea.
> 
> Definitely: logic bugs are not prevented by safe Rust.
> 
> It may reduce the chances of logic bugs compared to C though (e.g.
> through its stricter type system etc.), but this is another topic,
> mostly unrelated to the safety/UB discussion.

The thing is that you have still not convinced me that UB is all that
separate of a category from logic bugs, especially given that either
can generate the other.

> > 3.      Correctly written unsafe Rust code defends itself (and the safe
> >         code invoking it) from misuse.  And presumably the same applies
> >         for wrappers written for C code, given that there is probably
> >         an "unsafe" lurking somewhere in such wrappers.
> 
> Yes. And definitely, calling C code is unsafe, since C code does not
> have a way to promise in its signature that it is safe.

Hence the Rust-unsafe wrappering for C code, presumably.

> > 4.      Rust's safety properties are focused more on UB in particular
> >         than on bugs in general.
> 
> Yes, safety in Rust is all about UB, not logic bugs.
> 
> This does not mean that Rust was not designed to try to minimize logic
> bugs too, of course, but that is another discussion.

This focus on UB surprises me.  Unless the goal is mainly comfort for
compiler writers looking for more UB to "optimize".  ;-)

> > And one final thing to keep in mind...  If I turn this blog series into
> > a rosy hymn to Rust, nobody is going to believe it.  ;-)
> 
> I understand :)
> 
> As a personal note: I am trying my best to give a fair assessment of
> Rust for the kernel, and trying hard to describe what Rust actually
> aims to guarantee and what not. I do not enjoy when Rust is portrayed
> as the solution to every single problem -- it does not solve all
> issues, at all. But I think it is a big enough improvement to be
> seriously considered for kernel development.

It will be interesting to see how the experiment plays out.  And to
be sure, part of my skepticism is the fact that UB is rarely (if ever)
the cause of my Linux-kernel RCU bugs.  But the other option that the
kernel uses is gcc and clang/LLVM flags to cause the compiler to define
standard-C UB, one example being signed integer overflow.

But my main official focus is of course the memory model.

						Thanx, Paul

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211009234834.GX880162%40paulmck-ThinkPad-P17-Gen-1.
