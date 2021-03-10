Return-Path: <kasan-dev+bncBD4LX4523YGBBRMIUSBAMGQE7UNO2XY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3c.google.com (mail-yb1-xb3c.google.com [IPv6:2607:f8b0:4864:20::b3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 0DE90334542
	for <lists+kasan-dev@lfdr.de>; Wed, 10 Mar 2021 18:39:19 +0100 (CET)
Received: by mail-yb1-xb3c.google.com with SMTP id 127sf22005655ybc.19
        for <lists+kasan-dev@lfdr.de>; Wed, 10 Mar 2021 09:39:19 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1615397958; cv=pass;
        d=google.com; s=arc-20160816;
        b=kimAqdcTt02CgrSYbl4lUGQDOoPCCC081SGv0wfh5uSs45c9htyc4xxiuONVT/a3nI
         FZdZ+Rp1fytrpi9b8twAyNQ4vwGSuuy6rVskQqnwLeexkScP5rDZ07wF7TDZG4+xfBk0
         GG2PKgw3cNhXwpxSiz/tSuMBy2Q/FXZCN8AZnygNWqMIP7E/kAfFAXCP72gn39I9/Mbo
         X7VrETtnRHRhfTCe4YHSoOxdbClkxQrZZ+KT8X22Veo/IdhjA7G0O8O7D0dCEGAvhT3W
         E+aywlKtPzqsdqHM4uaHm+fGLg3YeXs4qqqjnVkpqmIUTYUsLCnKfnm+wiRiE19aXc0E
         pz8g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=s246EMu3I5dybVrTqw9SzZ4WMbe+I3j6ivAIxWeQGO8=;
        b=A1L2Ot9lHkGYjDbCC3QN60ITaSuUiqELAx1F5cL6Md1RSj9EpBoT3abLZ+iqL23EI2
         m4UdOWV1TUkK7p2oSKw8yc+oHAxRj7qOFHW0tLFF2KGq9GfIGTPQb03qMQFwQfmxLnX8
         G/gRX9myGdUlaglL33GlHrgDi5fqkcaxq3jI1hbiFE1ETQ0B5tfMkEMot1vWuHWc2O3B
         hXjz8oAxJGLkJkL+un5xMQpLGxVf11EnslJ3xbBUwh9Tnl9J7cJR26H514aIPVXvq/bJ
         BxAd36S8wXZLCKUlUBLy/AZKJ4AzqCZdHS9Hllp/2Gu78ZFBudhCW3zngb+vkSL5UNfQ
         C7Ig==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of segher@kernel.crashing.org designates 63.228.1.57 as permitted sender) smtp.mailfrom=segher@kernel.crashing.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=s246EMu3I5dybVrTqw9SzZ4WMbe+I3j6ivAIxWeQGO8=;
        b=WHGz4u0wHNTpwcjEcsOaRFnoA8HmNt9+4KHG3QizOaG23tamMjXq5Q7JBopxPSzEg7
         WeVRdjVVY3Afij0c9U2/f3nzNgXEC3RFQqd15KbBFJLe6JcISn6SHtpFTy3aw/od5fs/
         uwXUecsoK9+JNKFDdfNv7zjw/NVChoJqwC75ALQc8ptE/sPoopJXe7vx7bPxpfYlSGLX
         OCrhVe+duebu9risI3bgA/YTcb1EQOns8c0guckyZrdFbuL2jGrrzUvhVC/RKRbPbBKO
         jgQXAQh4j42nSBgIIr0/e2yQr4WsP9Han+WVfo0oDaubUcFKbA1qsQ8Y4Nz7Zjq/NtDA
         ZeJg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=s246EMu3I5dybVrTqw9SzZ4WMbe+I3j6ivAIxWeQGO8=;
        b=WK2mRxVs8zM2uCkhWLSnaTE8qEgncra2uNkYKrppBIP25lb/Xjc1SiLpf+GTAIQQr+
         85ZqO5fk89nq8F/N4O2TY5IT98B3gQr9B8aXdrQfZ5TSua+DQFBqg0Rx+m0kIdLGyb1D
         PKZnEEnoT9oh8apRY7nYwJ7CORmP1NRKubE/H9BjU8o9Bi5WyXKF/3+L9R4tW7tDk9+E
         8ruqOOQ1hr21tNOo7lwyAxiJSgI5hqAx8ITJMj3zg3rzEpNFMic5qJeoz5noMf7qBLww
         d2+YqBoa8iXjkyynEc3LOT/g7Oh0HNK8JY8jtzpoVsLpnoXjrRn+1CbXNKr1gjzfBvxr
         oPnA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532IKbBrc/hf/MimjyziJQ6U0sxhFaJpHABeZ1jiHSutZOh1GVc4
	VPkC9n4F2vPetNSIjDmAATM=
X-Google-Smtp-Source: ABdhPJziWc/w/c2HnnPuSvLArqHxeDQ/v62ipsz7l5Ai8Se4SmmPWI7U5EpgPCqjL1TGoKZLW6khzg==
X-Received: by 2002:a25:8687:: with SMTP id z7mr5045114ybk.209.1615397958065;
        Wed, 10 Mar 2021 09:39:18 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:d8c7:: with SMTP id p190ls1268207ybg.6.gmail; Wed, 10
 Mar 2021 09:39:17 -0800 (PST)
X-Received: by 2002:a25:5b0b:: with SMTP id p11mr5423405ybb.300.1615397957461;
        Wed, 10 Mar 2021 09:39:17 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1615397957; cv=none;
        d=google.com; s=arc-20160816;
        b=RH9smSehN2EhvwmVGz4kOhqv9x4XFsAyxsvz1KgZUNW05njTYks1AspTjmV9hAkAhd
         R9mMJ6m3aUKoIAMEV63wQxn3AuLNAlivJhIBGbHMXE6ZBV7cHz9dtcrTaGxePu6NSmq5
         HSeZb5ndLumEP0QtLUbNVWXWxsuKgGWt3suqh/Zxh15tHGwixIk0rXwGCJuEe3U+Dqqg
         IuDwMkQ8lcVmCY7mETi5N+qRDdGIZ2E7V2SifYzLzOuGkVYMzADlDk2HmoN5/TirBoV7
         KbIrC9t0bSrUrOiWgvFlBUYXnpeExUtwfNKSDaBktcahdYChXZVXqpPvXst/SOst0OKf
         O/eQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=2sV+huuln8WlrZMl2ukDzYv+nyn3ohzL56f6EYqGSQM=;
        b=aPGxJ/zZSqCF0NbJoXW0dgt5ZLvgi67bqs6MrDLfs/kI4Hf5uQxROeKQ4fUOW2sQLz
         OWKvKbSI2VwL3gXgzu7MpzhwnXGTTYofrti/ZuXPe6+8b8eTvjVe+fFxwTZrJVlsiL11
         88up99IrvMAiFpHQceo/Xm7cuGBq15qaTPh/nawb9U3XzzURUl3/j3L+q+33etQQxa4k
         BSLdz6xrGVhBZkbG6xoA56UGEK4oKmuHcU+6Bz7bO+YWlJA0Yd7fGN0gZiwFv5yeUlBn
         Z6VUV0Loq5svEViUh9MXZUGuzQ6a8IhGeXvtDfibHpvR8HTaMCWZeaTjfRzRWr+weRE9
         tPGw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of segher@kernel.crashing.org designates 63.228.1.57 as permitted sender) smtp.mailfrom=segher@kernel.crashing.org
Received: from gate.crashing.org (gate.crashing.org. [63.228.1.57])
        by gmr-mx.google.com with ESMTP id s44si17407ybi.3.2021.03.10.09.39.17
        for <kasan-dev@googlegroups.com>;
        Wed, 10 Mar 2021 09:39:17 -0800 (PST)
Received-SPF: pass (google.com: domain of segher@kernel.crashing.org designates 63.228.1.57 as permitted sender) client-ip=63.228.1.57;
Received: from gate.crashing.org (localhost.localdomain [127.0.0.1])
	by gate.crashing.org (8.14.1/8.14.1) with ESMTP id 12AHbCRi007688;
	Wed, 10 Mar 2021 11:37:12 -0600
Received: (from segher@localhost)
	by gate.crashing.org (8.14.1/8.14.1/Submit) id 12AHbAOa007687;
	Wed, 10 Mar 2021 11:37:10 -0600
X-Authentication-Warning: gate.crashing.org: segher set sender to segher@kernel.crashing.org using -f
Date: Wed, 10 Mar 2021 11:37:10 -0600
From: Segher Boessenkool <segher@kernel.crashing.org>
To: Mark Rutland <mark.rutland@arm.com>
Cc: Marco Elver <elver@google.com>, Catalin Marinas <catalin.marinas@arm.com>,
        Will Deacon <will@kernel.org>, LKML <linux-kernel@vger.kernel.org>,
        broonie@kernel.org, Paul Mackerras <paulus@samba.org>,
        kasan-dev <kasan-dev@googlegroups.com>, linuxppc-dev@lists.ozlabs.org,
        linux-arm-kernel@lists.infradead.org
Subject: Re: [PATCH v1] powerpc: Include running function as first entry in save_stack_trace() and friends
Message-ID: <20210310173710.GL29191@gate.crashing.org>
References: <e2e8728c4c4553bbac75a64b148e402183699c0c.1614780567.git.christophe.leroy@csgroup.eu> <CANpmjNOvgbUCf0QBs1J-mO0yEPuzcTMm7aS1JpPB-17_LabNHw@mail.gmail.com> <1802be3e-dc1a-52e0-1754-a40f0ea39658@csgroup.eu> <YD+o5QkCZN97mH8/@elver.google.com> <20210304145730.GC54534@C02TD0UTHF1T.local> <20210304215448.GU29191@gate.crashing.org> <20210309160505.GA4979@C02TD0UTHF1T.local> <20210309220532.GI29191@gate.crashing.org> <20210310112441.GA19619@C02TD0UTHF1T.local>
Mime-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20210310112441.GA19619@C02TD0UTHF1T.local>
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

On Wed, Mar 10, 2021 at 11:32:20AM +0000, Mark Rutland wrote:
> On Tue, Mar 09, 2021 at 04:05:32PM -0600, Segher Boessenkool wrote:
> > On Tue, Mar 09, 2021 at 04:05:23PM +0000, Mark Rutland wrote:
> > > On Thu, Mar 04, 2021 at 03:54:48PM -0600, Segher Boessenkool wrote:
> > > > On Thu, Mar 04, 2021 at 02:57:30PM +0000, Mark Rutland wrote:
> > > > > It looks like GCC is happy to give us the function-entry-time FP if we use
> > > > > __builtin_frame_address(1),
> > > > 
> > > > From the GCC manual:
> > > >      Calling this function with a nonzero argument can have
> > > >      unpredictable effects, including crashing the calling program.  As
> > > >      a result, calls that are considered unsafe are diagnosed when the
> > > >      '-Wframe-address' option is in effect.  Such calls should only be
> > > >      made in debugging situations.
> > > > 
> > > > It *does* warn (the warning is in -Wall btw), on both powerpc and
> > > > aarch64.  Furthermore, using this builtin causes lousy code (it forces
> > > > the use of a frame pointer, which we normally try very hard to optimise
> > > > away, for good reason).
> > > > 
> > > > And, that warning is not an idle warning.  Non-zero arguments to
> > > > __builtin_frame_address can crash the program.  It won't on simpler
> > > > functions, but there is no real definition of what a simpler function
> > > > *is*.  It is meant for debugging, not for production use (this is also
> > > > why no one has bothered to make it faster).
> > > >
> > > > On Power it should work, but on pretty much any other arch it won't.
> > > 
> > > I understand this is true generally, and cannot be relied upon in
> > > portable code. However as you hint here for Power, I believe that on
> > > arm64 __builtin_frame_address(1) shouldn't crash the program due to the
> > > way frame records work on arm64, but I'll go check with some local
> > > compiler folk. I agree that __builtin_frame_address(2) and beyond
> > > certainly can, e.g.  by NULL dereference and similar.
> > 
> > I still do not know the aarch64 ABI well enough.  If only I had time!
> > 
> > > For context, why do you think this would work on power specifically? I
> > > wonder if our rationale is similar.
> > 
> > On most 64-bit Power ABIs all stack frames are connected together as a
> > linked list (which is updated atomically, importantly).  This makes it
> > possible to always find all previous stack frames.
> 
> We have something similar on arm64, where the kernel depends on being
> built with a frame pointer following the AAPCS frame pointer rules.

The huge difference is on Power this is about the stack itself: you do
not need a frame pointer at all for it (there is no specific register
named as frame pointer, even).

> Every stack frame contains a "frame record" *somewhere* within that
> stack frame, and the frame records are chained together as a linked
> list. The frame pointer points at the most recent frame record (and this
> is what __builtin_frame_address(0) returns).

> > See gcc.gnu.org/PR60109 for example.
> 
> Sure; I see that being true generally (and Ramana noted that on 32-bit
> arm a frame pointer wasn't mandated), but I think in this case we have a
> stronger target (and configuration) specific guarantee.

It sounds like it, yes.  You need to have a frame pointer in the ABI,
with pretty strong rules, and have everything follow those rules.

> > Is the frame pointer required?!
> 
> The arm64 Linux port mandates frame pointers for kernel code. It is
> generally possible to build code without frame pointers (e.g. userspace),
> but doing that for kernel code would be a bug.

I see.  And it even is less expensive to do this than on most machines,
because of register pair load/store instructions :-)

> > > > The real way forward is to bite the bullet and to no longer pretend you
> > > > can do a full backtrace from just the stack contents.  You cannot.
> > > 
> > > I think what you mean here is that there's no reliable way to handle the
> > > current/leaf function, right? If so I do agree.
> > 
> > No, I meant what I said.
> > 
> > There is the separate issue that you do not know where the return
> > address (etc.) is stored in a function that has not yet done a call
> > itself, sure.  You cannot assume anything the ABI does not tell you you
> > can depend on.
> 
> This is in the frame record per the AAPCS.

But you do not know where in the function it will store that.  It often
can be optimised by the compiler to only store the LR and FP on paths
where a call will happen later, and there is no way (without DWARF info
or similar) to know whether that has happened yet or not.

This is a well-known problem of course.  For the current function you
cannot know in general if there is an activation frame yet or not.


Segher

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210310173710.GL29191%40gate.crashing.org.
