Return-Path: <kasan-dev+bncBD4LX4523YGBBJ5PQWBAMGQEAF6Q6MI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb39.google.com (mail-yb1-xb39.google.com [IPv6:2607:f8b0:4864:20::b39])
	by mail.lfdr.de (Postfix) with ESMTPS id A37B032DC9D
	for <lists+kasan-dev@lfdr.de>; Thu,  4 Mar 2021 22:56:56 +0100 (CET)
Received: by mail-yb1-xb39.google.com with SMTP id j4sf92402ybt.23
        for <lists+kasan-dev@lfdr.de>; Thu, 04 Mar 2021 13:56:56 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1614895015; cv=pass;
        d=google.com; s=arc-20160816;
        b=GwSuyGJq/GNEgmcS3R17yi7ww1a5CIyIRsO/W0g7uvzsCOwBDBS0SyizQ8muJwVpqI
         /pP5IPz0cI6CoCCwTiNa2SVO5r8k91RfNEXTrjvOP4XjSt2xC5Ghk1WrMak8xMA/BRma
         0PhSameFR/pjNNt7mN0PG9Qq47NcMVb5WILfNjMeREGUh3vOlJ7qK8xFIXJvnAKLbR5U
         3lbF8a1ysiArLKE2akenW2+AepBw2D1oC9qbEjoUIGlh0AaoNTOUhwtp3R8Cq0NeTS1K
         aG01YzDGCfn1CXHLGIsUuKLNpWMTfDnk2Y7p4kEQW1Pc2iXXmeRr0r22M5VfUloMMISF
         cQiw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=IvbptQ4p++Y0wgvCCZig7VRnQni+BiZLYLE8hb2UgXg=;
        b=vTm9ch4nH0yh3npWXtFu5XqDd3DPls2bWDb7N3hrdxUou5O30V+4/83B/EoqXPc9nq
         Fq+qDIMO6tZRChF8i5DLp4/H4X9ZTgydxGh11cYQS9crnz/grDk5KQJW0qAWCxowQvXz
         RNBMLd6B4WLCrBSIaRpbC8Xrv4R52Tp8yDKiBnG3532L5JhoOwQ7/+PQSdGX5M3pwTXj
         M5YDa0a0Lj6SaDnPSKM8qkE8v+4xW9/kj8xa9iR7FXhgbmtbi1i0j7jdFLl7qyzn0yoR
         727D+nN03/kTYgvEbn33tiwIs8KpZvkVs7ceOxPLNabeg+zSQpbYkR7mrFlcMuR+pw90
         ++cw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of segher@kernel.crashing.org designates 63.228.1.57 as permitted sender) smtp.mailfrom=segher@kernel.crashing.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=IvbptQ4p++Y0wgvCCZig7VRnQni+BiZLYLE8hb2UgXg=;
        b=r4hhPMR8Xu1cDdhp8XJpSGXwyTVVeink3KAjq8F8JS/Wik+38ovY++JECKMC0haEBx
         YoeNLCCMU7fsgM079uwQOYdRbT4XiaWXInnE1skBY4gfKHqykkwX7hMSkeQnzKMj5b6/
         ZuQ1WVU8DxbHkPEmPM2WmX6aZG0gKmVvBvhFn3+Rg469qH5hR8cM1Dn0+j7ds/CxHvlM
         FhF0XmHQwpDkchtAoCjL5Cyv63zYlZAy6JrFn5f/K1imAmQZlobJReam3y1czGp892ie
         lArSC7mWjxzqUBZ9cYiM1imM0bAT6XGSjynVctjZfcdTTYTpP++qtfaeTTMINuLGClBK
         JzeQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=IvbptQ4p++Y0wgvCCZig7VRnQni+BiZLYLE8hb2UgXg=;
        b=l2p3bHpWLzSOFW35nTtO7STkgNmu5EU1JmQfyNpAN+UXzsLCJtjwlYjXTdMyhoBJQ3
         psZK82hsf5gHkKetzGdTwQGxoWlvSjpNCB0YULjDEwEvx6fbAEbM/YBDI8+P53TqxS3Z
         joGyraK3lOjVOA4rLqGUzJw+7djWzJG1AwGWTSiBry/IcxovHUJ3tyy7WD2k2IZEZ+lY
         p3xNOFxzN9QBeKvb/kLQC6FNj8N8mrfmYRhNSHno/oe4wT74Y4cePjg7pyoOEYXP7BUH
         tK4+GwCmcHMbl7b94xWmGHYsVb+BA3TRvOJiqvGWtMj+ecZC7QGPt2inmNqYzb/89oQv
         U38A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533z9amXSINnfq6Gi6Qr+9SJPP0ZQ++m7zTe8XqouvwP4YGxc2I5
	BiLTULVvv/rorlMCN5cQnnM=
X-Google-Smtp-Source: ABdhPJxY3Sz0A/TSltQ769CVT1KlDNwAlGbZWdeXXqXwSWO4a+MkKRyIirbYL6MaO5mghi7qbKpR3Q==
X-Received: by 2002:a05:6902:4b2:: with SMTP id r18mr9583299ybs.226.1614895015531;
        Thu, 04 Mar 2021 13:56:55 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:d907:: with SMTP id q7ls3488556ybg.3.gmail; Thu, 04 Mar
 2021 13:56:55 -0800 (PST)
X-Received: by 2002:a25:ca88:: with SMTP id a130mr9438428ybg.414.1614895015055;
        Thu, 04 Mar 2021 13:56:55 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1614895015; cv=none;
        d=google.com; s=arc-20160816;
        b=IxzO2vLX1RIyoyux1ayg0R1Ki7t/yu89RmBdoZXVhQe4Gb/whqLPsEITnd8mb2UpoD
         LiP9JmsXYOrK+PkCYkK8OegojafO2lPqroLkbWgeDPOYMiD9CYz+Q0i049w1ymAgirDl
         u4qh7/RLhaXZD6WBhoEY1/QjRsUCUIfnfVCCPbqYcc3ituhHkiovySKIFv6LsUryHUpW
         1lblxYTrBkJyY0lokOwGWk4LXprCaQzyBtu8ZhrtM0GIZH0gzTYJyEjHxwvZAsp2m0mR
         MzhqknGer4irZehuB8IaYtw14ozySZSu8OjwBTuYXgimAA7koRuSFeKsZqVv6p4Ye7PD
         g2Lg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=GXVrh8xVvhHcAA4BfYXh++X/tXAX/hAbk8CkgR05Vug=;
        b=KYyJjPotNa6a76Ye0c5oReV/Xji4IhBepbMTR4gnCTVlz1MZlSS3hYviMKfl9i/Hu0
         wEBzvvaZKnL2XUX/mAmsY/Savsn6pprAEMbthpd/Tj9IsXTFS8qXWReukeYn2artqINB
         SbgnZzcronnMIARTYUXup1drhTVA4I8tQo2zj4xELw45NQqW4d/4b8wz+C0eDtTnZzFY
         ornEf5fVXpkIJptwBpy/yu8UQfps33nE7D+8W+Y3N30RGLnLALzyhVwCe4G4YEa50tlg
         Msxz1K9pF7CN/IizW/wI+2cEYTRCIXjP8yd4ZmLvYStsU6JumXh1RgpIl0Wztu39J6xX
         bkRg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of segher@kernel.crashing.org designates 63.228.1.57 as permitted sender) smtp.mailfrom=segher@kernel.crashing.org
Received: from gate.crashing.org (gate.crashing.org. [63.228.1.57])
        by gmr-mx.google.com with ESMTP id s44si44662ybi.3.2021.03.04.13.56.54
        for <kasan-dev@googlegroups.com>;
        Thu, 04 Mar 2021 13:56:54 -0800 (PST)
Received-SPF: pass (google.com: domain of segher@kernel.crashing.org designates 63.228.1.57 as permitted sender) client-ip=63.228.1.57;
Received: from gate.crashing.org (localhost.localdomain [127.0.0.1])
	by gate.crashing.org (8.14.1/8.14.1) with ESMTP id 124Lsnob015064;
	Thu, 4 Mar 2021 15:54:49 -0600
Received: (from segher@localhost)
	by gate.crashing.org (8.14.1/8.14.1/Submit) id 124Lsm4r015063;
	Thu, 4 Mar 2021 15:54:48 -0600
X-Authentication-Warning: gate.crashing.org: segher set sender to segher@kernel.crashing.org using -f
Date: Thu, 4 Mar 2021 15:54:48 -0600
From: Segher Boessenkool <segher@kernel.crashing.org>
To: Mark Rutland <mark.rutland@arm.com>
Cc: Marco Elver <elver@google.com>, Catalin Marinas <catalin.marinas@arm.com>,
        Will Deacon <will@kernel.org>, LKML <linux-kernel@vger.kernel.org>,
        broonie@kernel.org, Paul Mackerras <paulus@samba.org>,
        kasan-dev <kasan-dev@googlegroups.com>, linuxppc-dev@lists.ozlabs.org,
        linux-arm-kernel@lists.infradead.org
Subject: Re: [PATCH v1] powerpc: Include running function as first entry in save_stack_trace() and friends
Message-ID: <20210304215448.GU29191@gate.crashing.org>
References: <e2e8728c4c4553bbac75a64b148e402183699c0c.1614780567.git.christophe.leroy@csgroup.eu> <CANpmjNOvgbUCf0QBs1J-mO0yEPuzcTMm7aS1JpPB-17_LabNHw@mail.gmail.com> <1802be3e-dc1a-52e0-1754-a40f0ea39658@csgroup.eu> <YD+o5QkCZN97mH8/@elver.google.com> <20210304145730.GC54534@C02TD0UTHF1T.local>
Mime-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20210304145730.GC54534@C02TD0UTHF1T.local>
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

On Thu, Mar 04, 2021 at 02:57:30PM +0000, Mark Rutland wrote:
> It looks like GCC is happy to give us the function-entry-time FP if we use
> __builtin_frame_address(1),

From the GCC manual:
     Calling this function with a nonzero argument can have
     unpredictable effects, including crashing the calling program.  As
     a result, calls that are considered unsafe are diagnosed when the
     '-Wframe-address' option is in effect.  Such calls should only be
     made in debugging situations.

It *does* warn (the warning is in -Wall btw), on both powerpc and
aarch64.  Furthermore, using this builtin causes lousy code (it forces
the use of a frame pointer, which we normally try very hard to optimise
away, for good reason).

And, that warning is not an idle warning.  Non-zero arguments to
__builtin_frame_address can crash the program.  It won't on simpler
functions, but there is no real definition of what a simpler function
*is*.  It is meant for debugging, not for production use (this is also
why no one has bothered to make it faster).

On Power it should work, but on pretty much any other arch it won't.

> Unless we can get some strong guarantees from compiler folk such that we
> can guarantee a specific function acts boundary for unwinding (and
> doesn't itself get split, etc), the only reliable way I can think to
> solve this requires an assembly trampoline. Whatever we do is liable to
> need some invasive rework.

You cannot get such a guarantee, other than not letting the compiler
see into the routine at all, like with assembler code (not inline asm,
real assembler code).

The real way forward is to bite the bullet and to no longer pretend you
can do a full backtrace from just the stack contents.  You cannot.


Segher

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210304215448.GU29191%40gate.crashing.org.
