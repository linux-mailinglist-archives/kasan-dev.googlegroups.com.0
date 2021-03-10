Return-Path: <kasan-dev+bncBDV37XP3XYDRBTW4UKBAMGQEGPTB6CI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33f.google.com (mail-ot1-x33f.google.com [IPv6:2607:f8b0:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id 56C6B333B79
	for <lists+kasan-dev@lfdr.de>; Wed, 10 Mar 2021 12:32:31 +0100 (CET)
Received: by mail-ot1-x33f.google.com with SMTP id 97sf10877303otm.11
        for <lists+kasan-dev@lfdr.de>; Wed, 10 Mar 2021 03:32:31 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1615375950; cv=pass;
        d=google.com; s=arc-20160816;
        b=LBbYASCXDNGl2hZZCZyR8BbZ8AD65ffM2YtVy0msB4ci+vWibYtbOnh21mEQTs6uW6
         4iwLKJXudDSNg3u6cxZjFgxaKEzxYyY5MauAj90BdG8R5pZeUsmfaT/uQBW5sL1UxfDI
         QB4klNoMEGH+Mx+QML28FVSZz4YyVHXpz1IeMTlDZnugLCmwn/B4TiQpKlJJX7cPEyIc
         Z6SAULpz/XzxsrTpK1zY0eRYsdrwkNU5fo6kniEz5W5hJdnrKYYkljpEha1lF6qHXaqG
         8bdIlg449HJOrTnRVjBFGGcQ0MJ5+RuJEQMQpowZ/wuVWRcvFzMoitYc5+l0x1rEyfI8
         +jsw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=d/pxy/DuLi1JLbcQazcVO6KaWpwXsvCe5n3LiSeQajE=;
        b=hSk4jbSBeu1oFOTSOEp/Ao2EbnCx4EDqGmNPsLuF1QnB2Fy77zbpuI+8nvSd6sk1Wc
         TeYALB01QSJGrBhDNrJlOO15njX3OhjD9NGERJr96FfJazd+78w76ofC+xnbnO25umMX
         HpgZP0AwLoI8Lhvic6CpDJ85rCekgnDWvuv1GHmvQI7twtH+msGGG0YNwqpZqG51Dt6+
         4OC6BaAOsUihA4t1Ee3zDViWlE1uelSyUwxSGqFE5+6KiYyd2SldmOJ8WPNevnNyKiAk
         M+fTUJVP2eSImZ0/BGCrT9OjqMhDyqevtCTRUF6e3kXIG4Ik7rtJf0Af6kvQXUC6t2wn
         WGEQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=d/pxy/DuLi1JLbcQazcVO6KaWpwXsvCe5n3LiSeQajE=;
        b=UrmV4YT22l2kBSQwPtCWrc1Yos/jdJLxh2Rx80hXdT51huCf9alqbqvinCntaTAuQq
         U++MUnJiQEwILA+7U79sdDcf53Ci0s5DuZmFXO7hRJEWr+gWxdcWKw88y2NNzxcXxwH1
         jwbOlCOd/u9/iMqRkdppJW+BKdquS4Yz4OEiO9OfRdU04PPhI24C8HugvOWT/pkwX+OH
         G/0hoRH7o+RfBNw6DO3QpecsI+mHU7HaG0ZReRnCo6gwtMoY6s8KW+0YnTWw1qP5+gmA
         MolBqoO+yQTx+kuBh8XMhmxKW3s5UDJL/NnJrrszO4yzuUkgQ52WyibtcUDzB8YWhuCX
         HIeQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=d/pxy/DuLi1JLbcQazcVO6KaWpwXsvCe5n3LiSeQajE=;
        b=NBmw+27p+F/UEW/lfWHm4Ji+oBNpvBpDHjORV6s35BMGpj1S5mgM/lTSAsKIvNajkR
         jOx6Y+LvL+pLlcJnYEnVkobrkNZ669zB9DraknJnZmi4VVBDXm0Z71Q+K55/OgmxU1uI
         JrGDIin9gKZ7072Bkdt1I9cNQffY7gdIqmoYO7/70ZmYNUaHAUCadQF4/MIW9bCvqaEZ
         wd1GiXYbHXE6dVKPf8LC7fAePOMnh9bsCQ31xG6n+qop10pyySlwr53Xce7TXz4XB21D
         A4qm+kGHQz713bsIvg03bkAJe2Wxyl3zAzyyQfp/gMEcnxNlQ+irGi5oz8qHBD4pJPkp
         goHA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533FPuXj5VrCMEB9+x3i48mCkvd2Ut+6M0MRRcAifI40dtNYtXJu
	B+E1P/KWP0VoqfcFYTM+FaI=
X-Google-Smtp-Source: ABdhPJybJuSwKvXOH0HoA6HViO+uVS7cRn0mhfc0h/Dyjw+JAzPl4ZnUBtieTn1JVyD+6hdwZ8TelA==
X-Received: by 2002:a05:6830:1e4d:: with SMTP id e13mr2317151otj.146.1615375950202;
        Wed, 10 Mar 2021 03:32:30 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:9b89:: with SMTP id x9ls121171ooj.5.gmail; Wed, 10 Mar
 2021 03:32:29 -0800 (PST)
X-Received: by 2002:a4a:a223:: with SMTP id m35mr1897134ool.39.1615375949773;
        Wed, 10 Mar 2021 03:32:29 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1615375949; cv=none;
        d=google.com; s=arc-20160816;
        b=XO21whd/jx/fSDRR/Gbv4aTa1hmQumkp1qrD5b58alXzKASpw71FrmoZhLJfWUuxvZ
         C/1n1/keh8ioGQR2H+nig/U5IZOxMJ0Dy2sqigeXCkUYqRPEXsD+uu+r2BwG0FfcgCAZ
         1ubSrauDcFnhnE9mWB4i6eV+EDG6wyZbWqwoqtSJqQCRv2wUIBil7fhUdD4U+ORV2uFz
         2byBAZh2WlWN5SksqiHF+JuD+Kula3UWukycF0CXhuC7E0fWIysqcrLEMFjNexuVJdvh
         u5OS9049AqzO/BW0Z3uqpOLhDSb6y1ZhYWlmq7o39f6OvMajcgBNa06JuN+8z++WyWmc
         br5A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date;
        bh=vSgtdoRkX2MjqOMkDlvQudRJ7YvupDJOblb3p03kwNg=;
        b=zFFPHfo+JA67qU+9SEs1EPckfEd4vOFrPeyQvqb1B+KnMaT/66w9ub8jemwQC09T/i
         RrXJgEKhZuNu8nIKeizLg2tPa9SReeQkkI/boqIhQUrcOrUZrMmU5woItP95v3rQzj8z
         KHhTOSFDWkznnaMy9nmiWHlQPMwFTKh8X5fpkiKMU5j3WHOQhMDrGjwfg0P9EREiV77G
         w139KR5XQIWsd+qd3TEMFpqxskK6k9tRmWzrUZJrYPQRFv+L8wLTrNwbHnwaZYDeYt5Q
         lHxrg+EVNQTzHDfmYpdtWjCv0gvr4eMEBlhohMvDlTudDKWvA/L2aC+XmGO57zn4Ityz
         p9LA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id i14si34688ots.4.2021.03.10.03.32.29
        for <kasan-dev@googlegroups.com>;
        Wed, 10 Mar 2021 03:32:29 -0800 (PST)
Received-SPF: pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 2A6BF1063;
	Wed, 10 Mar 2021 03:32:29 -0800 (PST)
Received: from C02TD0UTHF1T.local (unknown [10.57.52.108])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id BF2773F85F;
	Wed, 10 Mar 2021 03:32:26 -0800 (PST)
Date: Wed, 10 Mar 2021 11:32:20 +0000
From: Mark Rutland <mark.rutland@arm.com>
To: Segher Boessenkool <segher@kernel.crashing.org>
Cc: Marco Elver <elver@google.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will@kernel.org>, LKML <linux-kernel@vger.kernel.org>,
	broonie@kernel.org, Paul Mackerras <paulus@samba.org>,
	kasan-dev <kasan-dev@googlegroups.com>,
	linuxppc-dev@lists.ozlabs.org, linux-arm-kernel@lists.infradead.org
Subject: Re: [PATCH v1] powerpc: Include running function as first entry in
 save_stack_trace() and friends
Message-ID: <20210310112441.GA19619@C02TD0UTHF1T.local>
References: <e2e8728c4c4553bbac75a64b148e402183699c0c.1614780567.git.christophe.leroy@csgroup.eu>
 <CANpmjNOvgbUCf0QBs1J-mO0yEPuzcTMm7aS1JpPB-17_LabNHw@mail.gmail.com>
 <1802be3e-dc1a-52e0-1754-a40f0ea39658@csgroup.eu>
 <YD+o5QkCZN97mH8/@elver.google.com>
 <20210304145730.GC54534@C02TD0UTHF1T.local>
 <20210304215448.GU29191@gate.crashing.org>
 <20210309160505.GA4979@C02TD0UTHF1T.local>
 <20210309220532.GI29191@gate.crashing.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20210309220532.GI29191@gate.crashing.org>
X-Original-Sender: mark.rutland@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as
 permitted sender) smtp.mailfrom=mark.rutland@arm.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=arm.com
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

On Tue, Mar 09, 2021 at 04:05:32PM -0600, Segher Boessenkool wrote:
> Hi!
> 
> On Tue, Mar 09, 2021 at 04:05:23PM +0000, Mark Rutland wrote:
> > On Thu, Mar 04, 2021 at 03:54:48PM -0600, Segher Boessenkool wrote:
> > > On Thu, Mar 04, 2021 at 02:57:30PM +0000, Mark Rutland wrote:
> > > > It looks like GCC is happy to give us the function-entry-time FP if we use
> > > > __builtin_frame_address(1),
> > > 
> > > From the GCC manual:
> > >      Calling this function with a nonzero argument can have
> > >      unpredictable effects, including crashing the calling program.  As
> > >      a result, calls that are considered unsafe are diagnosed when the
> > >      '-Wframe-address' option is in effect.  Such calls should only be
> > >      made in debugging situations.
> > > 
> > > It *does* warn (the warning is in -Wall btw), on both powerpc and
> > > aarch64.  Furthermore, using this builtin causes lousy code (it forces
> > > the use of a frame pointer, which we normally try very hard to optimise
> > > away, for good reason).
> > > 
> > > And, that warning is not an idle warning.  Non-zero arguments to
> > > __builtin_frame_address can crash the program.  It won't on simpler
> > > functions, but there is no real definition of what a simpler function
> > > *is*.  It is meant for debugging, not for production use (this is also
> > > why no one has bothered to make it faster).
> > >
> > > On Power it should work, but on pretty much any other arch it won't.
> > 
> > I understand this is true generally, and cannot be relied upon in
> > portable code. However as you hint here for Power, I believe that on
> > arm64 __builtin_frame_address(1) shouldn't crash the program due to the
> > way frame records work on arm64, but I'll go check with some local
> > compiler folk. I agree that __builtin_frame_address(2) and beyond
> > certainly can, e.g.  by NULL dereference and similar.
> 
> I still do not know the aarch64 ABI well enough.  If only I had time!
> 
> > For context, why do you think this would work on power specifically? I
> > wonder if our rationale is similar.
> 
> On most 64-bit Power ABIs all stack frames are connected together as a
> linked list (which is updated atomically, importantly).  This makes it
> possible to always find all previous stack frames.

We have something similar on arm64, where the kernel depends on being
built with a frame pointer following the AAPCS frame pointer rules.

Every stack frame contains a "frame record" *somewhere* within that
stack frame, and the frame records are chained together as a linked
list. The frame pointer points at the most recent frame record (and this
is what __builtin_frame_address(0) returns).

The records themselves are basically:

struct record {
	struct record *next;
	unsigned long ret_addr;
};

At function call boundaries, we know that the FP is the caller's record
(or NULL for the first function), and the LR is the address the current
function should return to. Within a function with a stack frame, we can
access that function's record and the `next` field (equivalent to the FP
at the time of entry to the function) is what __builtin_frame_address(1)
should return.

> > Are you aware of anything in particular that breaks using
> > __builtin_frame_address(1) in non-portable code, or is this just a
> > general sentiment of this not being a supported use-case?
> 
> It is not supported, and trying to do it anyway can crash: it can use
> random stack contents as pointer!  Not really "random" of course, but
> where it thinks to find a pointer into the previous frame, which is not
> something it can rely on (unless the ABI guarantees it somehow).
> 
> See gcc.gnu.org/PR60109 for example.

Sure; I see that being true generally (and Ramana noted that on 32-bit
arm a frame pointer wasn't mandated), but I think in this case we have a
stronger target (and configuration) specific guarantee.

> > > > Unless we can get some strong guarantees from compiler folk such that we
> > > > can guarantee a specific function acts boundary for unwinding (and
> > > > doesn't itself get split, etc), the only reliable way I can think to
> > > > solve this requires an assembly trampoline. Whatever we do is liable to
> > > > need some invasive rework.
> > > 
> > > You cannot get such a guarantee, other than not letting the compiler
> > > see into the routine at all, like with assembler code (not inline asm,
> > > real assembler code).
> > 
> > If we cannot reliably ensure this then I'm happy to go write an assembly
> > trampoline to snapshot the state at a function call boundary (where our
> > procedure call standard mandates the state of the LR, FP, and frame
> > records pointed to by the FP).
> 
> Is the frame pointer required?!

The arm64 Linux port mandates frame pointers for kernel code. It is
generally possible to build code without frame pointers (e.g. userspace),
but doing that for kernel code would be a bug.

> > This'll require reworking a reasonable
> > amount of code cross-architecture, so I'll need to get some more
> > concrete justification (e.g. examples of things that can go wrong in
> > practice).
> 
> Say you have a function that does dynamic stack allocation, then there
> is usually no way to find the previous stack frame (without function-
> specific knowledge).  So __builtin_frame_address cannot work (it knows
> nothing about frames further up).
> 
> Dynamic stack allocation (alloca, or variable length automatic arrays)
> is just the most common and most convenient example; it is not the only
> case you have problems here.

I agree with those as general concerns, but I don't think that affects
arm64's frame records, since their location within a stack frame is
immaterial given the chaining.

> > > The real way forward is to bite the bullet and to no longer pretend you
> > > can do a full backtrace from just the stack contents.  You cannot.
> > 
> > I think what you mean here is that there's no reliable way to handle the
> > current/leaf function, right? If so I do agree.
> 
> No, I meant what I said.
> 
> There is the separate issue that you do not know where the return
> address (etc.) is stored in a function that has not yet done a call
> itself, sure.  You cannot assume anything the ABI does not tell you you
> can depend on.

This is in the frame record per the AAPCS.

> > Beyond that I believe that arm64's frame records should be sufficient.
> 
> Do you have a simple linked list connecting all frames?

Yes.

Thanks,
Mark.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210310112441.GA19619%40C02TD0UTHF1T.local.
