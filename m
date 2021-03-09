Return-Path: <kasan-dev+bncBD4LX4523YGBBK7DT6BAMGQE5SVX42I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x137.google.com (mail-il1-x137.google.com [IPv6:2607:f8b0:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id BC0CB33315C
	for <lists+kasan-dev@lfdr.de>; Tue,  9 Mar 2021 23:07:40 +0100 (CET)
Received: by mail-il1-x137.google.com with SMTP id o7sf11330489ilt.5
        for <lists+kasan-dev@lfdr.de>; Tue, 09 Mar 2021 14:07:40 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1615327659; cv=pass;
        d=google.com; s=arc-20160816;
        b=rBWwHV6OC3gBL3FdtFl4/okAaJHPYiWfHSFn6IBpkWmyOPUglX9QYEjjE6Pwu8r29w
         QDB0s8EP8UfTuV54T2c8HrYKBCZ/MWVE8fR9R8gv7iMTZubpVZAOkNlUDg38wgfJEdEG
         BxDRCczfTTnRDQAjyz4/8tIfC52B2l3IS5lFCg74enBNvuoPDTWip9sma5NBw5CHy6Os
         cUjF2vno1zW68CSrTInK4rdKbqvj9upW75zJ6N8d4cU5Ro1xyL8R52mWWiLFqftBBCQw
         UTiIgBS4lPjCkmSxBR0/6ByHMMqZTg+qrC0uKzEKdB59ILmEybeVdzRGW5wwS+cfOIMH
         iBHA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=xWtvw//fppdHFI6hmgdVZS5V2XlFrZ1hFTjBVnkZr2E=;
        b=Y3dKvep1R6pPFE5W5XyhM1/26ca7KcvA0wERg71kAy7eZPU0JoNuYXLze06QzqZdWp
         TrYZ76BGIMNH5LSYevFwvJB76O1oSaFwnfVngPXdCs2CQRXRmjPKYNyEBCzfy8vQk8sn
         suUcSep5Ib/wVLAvpj4nfxgzvEISe9/STC4eg0ZOCtMT9myjvhH20fG/D5s8ul7SGHcw
         1pCeYPRUSAcwJ7P4br0gTg3ueBdRdHTP5Xyr/iZK0TZE9TuHoziClA1+teK3nv87O606
         oAnfxLH8xSl+HNW0RMD1XkJ9rLqnfREsYEL50SDVXj2Hu4M+o+jMTs0YmrbrmoRMfpMP
         6xXg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of segher@kernel.crashing.org designates 63.228.1.57 as permitted sender) smtp.mailfrom=segher@kernel.crashing.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=xWtvw//fppdHFI6hmgdVZS5V2XlFrZ1hFTjBVnkZr2E=;
        b=ocygkoi+fR1FpnDWKSas5Twp5lNp6bQVb18bJdV4fKwW3hJyOHQaDzf5lxxuquznr1
         aaXujR7b6ekhLyAN/q14d4RSXi3uwpcXAMCxkjbAStQN47qzfGLGd2Vk4HiAC4nujkbR
         m/L38FZ5vaQpo3h80Sccjs7CcmqsK7gyUrVRkT+JN+vRsOvLLFnGuT1k3JRdpDki/Xf8
         DbQ1yiFXZDgIsVGz577gPD24D5XDeukhka2GP0nhMFV1OvE1H6ei0anuAxMnlSKAcyWU
         qpuOlTTT2y8NP3yKcci8bEWogYqnueZ+6u0gwUeTS96+4ANBQzrvvIEm6BUCk5vHk86i
         In1g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=xWtvw//fppdHFI6hmgdVZS5V2XlFrZ1hFTjBVnkZr2E=;
        b=iecc2xFJXDCzs2H3feK4m0XvD0yNrwAik2ZRbldhiVbUl86g7OD+brke8ZPt+2GHZy
         iKm4lnp6JAgVcJZfy0+T0Ya8FjXpUJQUkcxSNDGu9bHhpVxVlYU+sg9e/WRLfYPP49Ks
         wJkFkqS6fwj1gpjPnVtXLWBrJZC2trEOtzQ1nAKmDBr9+2h8kYwKJo6J2WEUFpwUUDoC
         1eyh4yfhmfqkElR9atM5U9NSq1UpsNDGzdFvm9C1UJf2iyIZto6IV7gT/rfQW9BYgqhQ
         0EaWm+UFXkwm7wJpMUWxYPwHRaW4cyFF9MNFDWPhEONiZTil/VnnbNxPoJIJZk6AtW3L
         Dn7Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530usXrP4OVJQbS1o59+T21Au/x8RUnn7Bz5ooDYRxn6EyB94Rx5
	3K/muqGFYPPBaggoaKY7tIU=
X-Google-Smtp-Source: ABdhPJxN+SZgdnHM8OOUyIHxxn9SQGtErcVr9nCxS1clWJQqxumHf5fq7deFXqmUpkqZ2vmZN0z34A==
X-Received: by 2002:a92:c010:: with SMTP id q16mr286965ild.250.1615327659609;
        Tue, 09 Mar 2021 14:07:39 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6638:3590:: with SMTP id v16ls382170jal.5.gmail; Tue, 09
 Mar 2021 14:07:39 -0800 (PST)
X-Received: by 2002:a02:a506:: with SMTP id e6mr243067jam.56.1615327659257;
        Tue, 09 Mar 2021 14:07:39 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1615327659; cv=none;
        d=google.com; s=arc-20160816;
        b=oZgdbgfWAhdMWa2sIbkDYmgvgHb7QolqvfUbndEmtHI4PbNfEZ1zLPD8pCyciSPilp
         M6jD9k+NLvqvGJnlRvbyBdU3MAT0vakHGChSJamTcpN4z4p37NC3VqHfPbtAjp5OyVtf
         TJ58O6rkIdZhVGqSD+dfEoirLkoEssmS1oTV9wbOBsyHqt5FQAt/m1BEprqV7mDBxcC8
         ZOzzVbiKnmyiOneRFlj6xRpRdsqdFECVQiB0Unh/2tMUgxZQ2KQCxHJ0gk+BVYhzjpAW
         rFDdLsn1EDdnmgr3v2u4+C7svySjqtHtML+3cgL3zo54VG0Ln/nbCyNoNvZGgUxlJo2/
         K92g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=6SbblWsI6E//dvKpJssuzpDeCQZpyOq8LJ1RAIxvTc0=;
        b=RuuCFR3GkXI55Mmo0vUfpFcXPIHJtJx8E0DBtcwUfh1wLgAmlrIzk2b9eKwAIQ6ZHZ
         TgNT6j+NtxujcM+ZQi6jCRrn1idKcqIDTe/JLUm3AN4LVkpTB+A3YL6KihGfUHl/rDiV
         Oos6mimTACcLMP2Q0K8/9kU/56RNCnRhg7WtO0fdeFKGYuUMoA/f9DqxdkdHmLFhHVEa
         aldmqQYv5PtRcdEIR0/lON7df2dG4kUjZLJRZOUUWY3RD1U6iysGcC2FHsSMjW7FfYkM
         CRRkE9dEx+0h+/kvQgWbU2vaMWuywbejgPyl3/RBjCPTwsGPDEzo9hS2xbCCDHqlqJll
         d4RQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of segher@kernel.crashing.org designates 63.228.1.57 as permitted sender) smtp.mailfrom=segher@kernel.crashing.org
Received: from gate.crashing.org (gate.crashing.org. [63.228.1.57])
        by gmr-mx.google.com with ESMTP id l15si66767ilh.0.2021.03.09.14.07.39
        for <kasan-dev@googlegroups.com>;
        Tue, 09 Mar 2021 14:07:39 -0800 (PST)
Received-SPF: pass (google.com: domain of segher@kernel.crashing.org designates 63.228.1.57 as permitted sender) client-ip=63.228.1.57;
Received: from gate.crashing.org (localhost.localdomain [127.0.0.1])
	by gate.crashing.org (8.14.1/8.14.1) with ESMTP id 129M5XDc030658;
	Tue, 9 Mar 2021 16:05:34 -0600
Received: (from segher@localhost)
	by gate.crashing.org (8.14.1/8.14.1/Submit) id 129M5X7J030657;
	Tue, 9 Mar 2021 16:05:33 -0600
X-Authentication-Warning: gate.crashing.org: segher set sender to segher@kernel.crashing.org using -f
Date: Tue, 9 Mar 2021 16:05:32 -0600
From: Segher Boessenkool <segher@kernel.crashing.org>
To: Mark Rutland <mark.rutland@arm.com>
Cc: Marco Elver <elver@google.com>, Catalin Marinas <catalin.marinas@arm.com>,
        Will Deacon <will@kernel.org>, LKML <linux-kernel@vger.kernel.org>,
        broonie@kernel.org, Paul Mackerras <paulus@samba.org>,
        kasan-dev <kasan-dev@googlegroups.com>, linuxppc-dev@lists.ozlabs.org,
        linux-arm-kernel@lists.infradead.org
Subject: Re: [PATCH v1] powerpc: Include running function as first entry in save_stack_trace() and friends
Message-ID: <20210309220532.GI29191@gate.crashing.org>
References: <e2e8728c4c4553bbac75a64b148e402183699c0c.1614780567.git.christophe.leroy@csgroup.eu> <CANpmjNOvgbUCf0QBs1J-mO0yEPuzcTMm7aS1JpPB-17_LabNHw@mail.gmail.com> <1802be3e-dc1a-52e0-1754-a40f0ea39658@csgroup.eu> <YD+o5QkCZN97mH8/@elver.google.com> <20210304145730.GC54534@C02TD0UTHF1T.local> <20210304215448.GU29191@gate.crashing.org> <20210309160505.GA4979@C02TD0UTHF1T.local>
Mime-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20210309160505.GA4979@C02TD0UTHF1T.local>
User-Agent: Mutt/1.4.2.3i
X-Original-Sender: segher@kernel.crashing.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of segher@kernel.crashing.org designates 63.228.1.57 as
 permitted sender) smtp.mailfrom=segher@kernel.crashing.org
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

Hi!

On Tue, Mar 09, 2021 at 04:05:23PM +0000, Mark Rutland wrote:
> On Thu, Mar 04, 2021 at 03:54:48PM -0600, Segher Boessenkool wrote:
> > On Thu, Mar 04, 2021 at 02:57:30PM +0000, Mark Rutland wrote:
> > > It looks like GCC is happy to give us the function-entry-time FP if we use
> > > __builtin_frame_address(1),
> > 
> > From the GCC manual:
> >      Calling this function with a nonzero argument can have
> >      unpredictable effects, including crashing the calling program.  As
> >      a result, calls that are considered unsafe are diagnosed when the
> >      '-Wframe-address' option is in effect.  Such calls should only be
> >      made in debugging situations.
> > 
> > It *does* warn (the warning is in -Wall btw), on both powerpc and
> > aarch64.  Furthermore, using this builtin causes lousy code (it forces
> > the use of a frame pointer, which we normally try very hard to optimise
> > away, for good reason).
> > 
> > And, that warning is not an idle warning.  Non-zero arguments to
> > __builtin_frame_address can crash the program.  It won't on simpler
> > functions, but there is no real definition of what a simpler function
> > *is*.  It is meant for debugging, not for production use (this is also
> > why no one has bothered to make it faster).
> >
> > On Power it should work, but on pretty much any other arch it won't.
> 
> I understand this is true generally, and cannot be relied upon in
> portable code. However as you hint here for Power, I believe that on
> arm64 __builtin_frame_address(1) shouldn't crash the program due to the
> way frame records work on arm64, but I'll go check with some local
> compiler folk. I agree that __builtin_frame_address(2) and beyond
> certainly can, e.g.  by NULL dereference and similar.

I still do not know the aarch64 ABI well enough.  If only I had time!

> For context, why do you think this would work on power specifically? I
> wonder if our rationale is similar.

On most 64-bit Power ABIs all stack frames are connected together as a
linked list (which is updated atomically, importantly).  This makes it
possible to always find all previous stack frames.

> Are you aware of anything in particular that breaks using
> __builtin_frame_address(1) in non-portable code, or is this just a
> general sentiment of this not being a supported use-case?

It is not supported, and trying to do it anyway can crash: it can use
random stack contents as pointer!  Not really "random" of course, but
where it thinks to find a pointer into the previous frame, which is not
something it can rely on (unless the ABI guarantees it somehow).

See gcc.gnu.org/PR60109 for example.

> > > Unless we can get some strong guarantees from compiler folk such that we
> > > can guarantee a specific function acts boundary for unwinding (and
> > > doesn't itself get split, etc), the only reliable way I can think to
> > > solve this requires an assembly trampoline. Whatever we do is liable to
> > > need some invasive rework.
> > 
> > You cannot get such a guarantee, other than not letting the compiler
> > see into the routine at all, like with assembler code (not inline asm,
> > real assembler code).
> 
> If we cannot reliably ensure this then I'm happy to go write an assembly
> trampoline to snapshot the state at a function call boundary (where our
> procedure call standard mandates the state of the LR, FP, and frame
> records pointed to by the FP).

Is the frame pointer required?!

> This'll require reworking a reasonable
> amount of code cross-architecture, so I'll need to get some more
> concrete justification (e.g. examples of things that can go wrong in
> practice).

Say you have a function that does dynamic stack allocation, then there
is usually no way to find the previous stack frame (without function-
specific knowledge).  So __builtin_frame_address cannot work (it knows
nothing about frames further up).

Dynamic stack allocation (alloca, or variable length automatic arrays)
is just the most common and most convenient example; it is not the only
case you have problems here.

> > The real way forward is to bite the bullet and to no longer pretend you
> > can do a full backtrace from just the stack contents.  You cannot.
> 
> I think what you mean here is that there's no reliable way to handle the
> current/leaf function, right? If so I do agree.

No, I meant what I said.

There is the separate issue that you do not know where the return
address (etc.) is stored in a function that has not yet done a call
itself, sure.  You cannot assume anything the ABI does not tell you you
can depend on.

> Beyond that I believe that arm64's frame records should be sufficient.

Do you have a simple linked list connecting all frames?  The aarch64 GCC
port does not define anything special here (DYNAMIC_CHAIN_ADDRESS), so
the default will be used: every frame pointer has to point to the
previous one, no exceptions whatsoever.


Segher

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210309220532.GI29191%40gate.crashing.org.
