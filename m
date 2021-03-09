Return-Path: <kasan-dev+bncBDV37XP3XYDRBT5ZT2BAMGQEZ5ARKJQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23d.google.com (mail-oi1-x23d.google.com [IPv6:2607:f8b0:4864:20::23d])
	by mail.lfdr.de (Postfix) with ESMTPS id D58C4332B6C
	for <lists+kasan-dev@lfdr.de>; Tue,  9 Mar 2021 17:05:36 +0100 (CET)
Received: by mail-oi1-x23d.google.com with SMTP id v25sf6572424oiv.7
        for <lists+kasan-dev@lfdr.de>; Tue, 09 Mar 2021 08:05:36 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1615305936; cv=pass;
        d=google.com; s=arc-20160816;
        b=j+1AHVgZ1sXrAtdHk5rvVl0ssGF0RT4RaXvAQ78BKm2bSjcuWGTgwsT+tOyUdeXMww
         zglziemSkMAWnLlsl31WPMBdl59KWNqEwJjpkBaUVGfReUPwHQ99+EAeoWvmScwqXLAZ
         0tmlab4nRZbHXGZmp3NZXuLIFVorcttDJEg87yNllsOpmV5o/AiyKHgHRaPUpvgQU0h+
         08LXQ2PhhX3rnvXOBgKfTHF4mKOS964cHCMRQa2isJN8DflccPU/U/qHGgxBgikLppID
         uG7Fssi5QMKoBq8V2ldaiRB3Ji3KIFX+QhDNrvNZlwl0ZNJx9cPKjLGsvofdibvut2L8
         MTEQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=yajgSR6SxhNC2IJOlmGhxsIKIhZyylzZHyWDpQIGcac=;
        b=MzDlgyEjjYl1fmrLJMo+hrx1vTGh7SE+JTgqXYXuS+0qxvswvZUc9dwgwffcPQDZAX
         yOhOOc+meCrrKxshggVlwpQoLfZpPwsyhFVr1HRzGqd84mgSS/sC3hsF08uCuSeznI6w
         C5V8Vbu/oZxd3kRYhYsa4CuTjFdv4vxBHTgnJI5lAxmN9/WExRxWAdnDARhpsfSpHSZR
         c0uY9/uRZe6lr3Qy8X3dtqFwxuTHUtjwH8uaxz1H06V/Ns4woVXWP3LAnhHTErshnxb7
         vQerRtQfSYoSNpinnfQWSxDVaQake2Yk5+u2Yunj/zPlbsluILdDO6En4o2788IVRLAw
         KKsA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=yajgSR6SxhNC2IJOlmGhxsIKIhZyylzZHyWDpQIGcac=;
        b=GMwS64eYr8HQ4ZH8bap5OLyMFk2nx4AKussniqUpIbljgEO39TVwiZvzt+BRpEn4fk
         CFM5D6GwZsx4FFDbsBV255bCKCLgsFUVCFo/ZL+S1VOHY9jDnfSS0p6g/7mw7FzLaRI0
         mUFBAaGZI7I6ZjU4ubet9ynH8nGvJRClwILs0ZaPhsRZ0BWN48YaA0bciDLMjNneLZm6
         B6/c3YC0yeatqST+gb78lW0MtjKjQK1dudQPnjFBqAeM07u0zjpxQxzOzkMNqgTaxELA
         tRd7VRdDbYaYYDWNH0bg7QXX131pn+mULi+xaKaVcLriKESVivnCi56WJvYwWosWOen6
         R6+w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=yajgSR6SxhNC2IJOlmGhxsIKIhZyylzZHyWDpQIGcac=;
        b=ATdV5ij3WJ7wE8r++oJ1YCj1/mK40K+NE36gLerjvkHGev2s98waIUo+YI8YS3h5Gz
         cuigu+B+rAhaqsi0pT0zUf/XtqPre1d0GyScGAu3MRRXbpPJij9fjqUnLMMwqmVNfwNO
         8unaE9TtlFQi7jhoeVVw4+RVEaooYg5COZFeFeZUVYVWsmkGCNIXW9mNkbLu31JTpsvN
         +GU/xBQ7Xw23bpHs2y5Ro+5yzvwbF4iiOg2WOTBFZio5BNTi0kzasPVsQo2BsSturXWZ
         YXvQJxUcbFdr/c0utTGg8ka0Ql+b2wodtCLJf1AQrL7B82czxeBGK7FXKmlH0e3r3RMF
         5WdQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5309v+kRX8k8XbN3KLvuh4oG9yAM/warAr9BVUXJo7+LDq6ZC9s8
	MGC+vVsNdoXYuqbgEcdFQKE=
X-Google-Smtp-Source: ABdhPJyagT7645eBeuVJ+D2zXBm3hqukQ1neg0g2qC6pxDsnm55fjU9i6AgqCCinLFcFp3gdr2KYDw==
X-Received: by 2002:aca:c3c8:: with SMTP id t191mr3413716oif.171.1615305935872;
        Tue, 09 Mar 2021 08:05:35 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:dfb8:: with SMTP id k24ls1092093ook.1.gmail; Tue, 09 Mar
 2021 08:05:35 -0800 (PST)
X-Received: by 2002:a4a:e382:: with SMTP id l2mr13268704oov.17.1615305935488;
        Tue, 09 Mar 2021 08:05:35 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1615305935; cv=none;
        d=google.com; s=arc-20160816;
        b=COB7HRDwwNKWAN+BNO58kA2R/FoKOtLFUErwGHOZjaC27Xt5lxpH8lgWjTNtJ1nY3d
         bb4hPxbiRSRfNfVhBNecxqecG7l3zEQokEqbqfK9SK9f4MRcfqhPRmRQJ6D0wXV9Ecn4
         mCQQvzBDUFmhDotxRKcLPUTPwvUNDN2jvUrD1Hspj7zju0waTlvG4PsGom2J7V2Qznqr
         /7s7dyYnEND8iWZbtnwKrOMRDmqUmvsA0HI4GwVmfLNWW3PdJ+ioZiX5g0X6KmEykTHh
         itGFbiJ+IAN6FFuS6k/s+xB0Pls4tK/WHK6dWHqRP9u/JlfSCLrt98tbLnOJA6U5DDND
         cOrw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date;
        bh=yFAwMPF/mYBjd+sQQiiLnso3D1Cs6lFBNtWuDonXEEw=;
        b=ct1YMb2af21sM/zTEmnhrGdNDfEbKdyiCOBZe66oLTypPU26zwTu4jx6nrgo0f1Nci
         xynSa6+UnvpxA6DZSl+klYNVdA18k15ZNoPZPZFAAZZCFoutj5a7mcRYz6k8T1mkKsIw
         836yobbc66qMChinhuUTB8l2WonSX0YPWRzJgaco77mNF2koJLf/VQebdLh7hplM8Ohs
         P6LmCRk0/2s/umTTy/cBeZvQ1vrWfDpua3WzqF9ydJmkc/HTS0OkI17ZNbE4pkRjcA8h
         jtHqwo3TVQMvdDucLwc22C/GM1Z+qb7GnL9xeaHVVto+2viXV8TaZG513cMq7ITNYTSe
         fR6Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id v4si1381057oiv.4.2021.03.09.08.05.35
        for <kasan-dev@googlegroups.com>;
        Tue, 09 Mar 2021 08:05:35 -0800 (PST)
Received-SPF: pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 2DFF21042;
	Tue,  9 Mar 2021 08:05:35 -0800 (PST)
Received: from C02TD0UTHF1T.local (unknown [10.57.49.159])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 032A13F71B;
	Tue,  9 Mar 2021 08:05:32 -0800 (PST)
Date: Tue, 9 Mar 2021 16:05:23 +0000
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
Message-ID: <20210309160505.GA4979@C02TD0UTHF1T.local>
References: <e2e8728c4c4553bbac75a64b148e402183699c0c.1614780567.git.christophe.leroy@csgroup.eu>
 <CANpmjNOvgbUCf0QBs1J-mO0yEPuzcTMm7aS1JpPB-17_LabNHw@mail.gmail.com>
 <1802be3e-dc1a-52e0-1754-a40f0ea39658@csgroup.eu>
 <YD+o5QkCZN97mH8/@elver.google.com>
 <20210304145730.GC54534@C02TD0UTHF1T.local>
 <20210304215448.GU29191@gate.crashing.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20210304215448.GU29191@gate.crashing.org>
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

On Thu, Mar 04, 2021 at 03:54:48PM -0600, Segher Boessenkool wrote:
> Hi!

Hi Segher,

> On Thu, Mar 04, 2021 at 02:57:30PM +0000, Mark Rutland wrote:
> > It looks like GCC is happy to give us the function-entry-time FP if we use
> > __builtin_frame_address(1),
> 
> From the GCC manual:
>      Calling this function with a nonzero argument can have
>      unpredictable effects, including crashing the calling program.  As
>      a result, calls that are considered unsafe are diagnosed when the
>      '-Wframe-address' option is in effect.  Such calls should only be
>      made in debugging situations.
> 
> It *does* warn (the warning is in -Wall btw), on both powerpc and
> aarch64.  Furthermore, using this builtin causes lousy code (it forces
> the use of a frame pointer, which we normally try very hard to optimise
> away, for good reason).
> 
> And, that warning is not an idle warning.  Non-zero arguments to
> __builtin_frame_address can crash the program.  It won't on simpler
> functions, but there is no real definition of what a simpler function
> *is*.  It is meant for debugging, not for production use (this is also
> why no one has bothered to make it faster).
>
> On Power it should work, but on pretty much any other arch it won't.

I understand this is true generally, and cannot be relied upon in
portable code. However as you hint here for Power, I believe that on
arm64 __builtin_frame_address(1) shouldn't crash the program due to the
way frame records work on arm64, but I'll go check with some local
compiler folk. I agree that __builtin_frame_address(2) and beyond
certainly can, e.g.  by NULL dereference and similar.

For context, why do you think this would work on power specifically? I
wonder if our rationale is similar.

Are you aware of anything in particular that breaks using
__builtin_frame_address(1) in non-portable code, or is this just a
general sentiment of this not being a supported use-case?

> > Unless we can get some strong guarantees from compiler folk such that we
> > can guarantee a specific function acts boundary for unwinding (and
> > doesn't itself get split, etc), the only reliable way I can think to
> > solve this requires an assembly trampoline. Whatever we do is liable to
> > need some invasive rework.
> 
> You cannot get such a guarantee, other than not letting the compiler
> see into the routine at all, like with assembler code (not inline asm,
> real assembler code).

If we cannot reliably ensure this then I'm happy to go write an assembly
trampoline to snapshot the state at a function call boundary (where our
procedure call standard mandates the state of the LR, FP, and frame
records pointed to by the FP). This'll require reworking a reasonable
amount of code cross-architecture, so I'll need to get some more
concrete justification (e.g. examples of things that can go wrong in
practice).

> The real way forward is to bite the bullet and to no longer pretend you
> can do a full backtrace from just the stack contents.  You cannot.

I think what you mean here is that there's no reliable way to handle the
current/leaf function, right? If so I do agree.

Beyond that I believe that arm64's frame records should be sufficient.

Thanks,
Mark.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210309160505.GA4979%40C02TD0UTHF1T.local.
