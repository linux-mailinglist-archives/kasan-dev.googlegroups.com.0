Return-Path: <kasan-dev+bncBDX4HWEMTEBRB7XMT35AKGQERZC5J5A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3a.google.com (mail-oo1-xc3a.google.com [IPv6:2607:f8b0:4864:20::c3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 2C4A9254602
	for <lists+kasan-dev@lfdr.de>; Thu, 27 Aug 2020 15:34:56 +0200 (CEST)
Received: by mail-oo1-xc3a.google.com with SMTP id r66sf2988926ooa.17
        for <lists+kasan-dev@lfdr.de>; Thu, 27 Aug 2020 06:34:56 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1598535295; cv=pass;
        d=google.com; s=arc-20160816;
        b=LWddejoZffz2RCTAoqt14dFGV7qm5w/BLEwn/E86PqXYF9CUuGOMyco3nienL0h91t
         RJ+uw14J8XEylXQ0TeTkoO/Oa/U4b7P4AQQEklLKt1tqyTiM65wPD76xJDRloE9f28ot
         WE2pa/8CsIoLrNk+WZPHCmRfPDk2cOGk2KovtHuvNgW8xmL5Q4Uwk3x0DCFCZvRc3uA3
         oGzzLjWX9v7tXivxw1JUrwFfnZi6A4BuYS2K94vK0NKnNveL3VaFw8h1mLPondVIlQfP
         E1zyV3I+vgdzRolh/PDs8z2Qdz0xttnqqmi9x51ooUDD+EYZ6IGJsmz8v6uOopDXZs0l
         EHlQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=QfodHDNoFh3W7Q/VWHU0Tt2pG4yeACTkrTKL1Goy9dw=;
        b=wU2Zd3TF5Dy7WCNxW1kHoxVaezH2FetVfZb+pbIhXWc1xVavpAaJHh0MXn7ccHZIEG
         9tOk42xBMLdiXMHM0mzhfJ3rZls4DC0YECXohZQ3X4SWKOPIJ5rqeY7yplkgQtQJxLoj
         YuGJnSVX5welnUl5awxnNYP5m+yOilYZkVIrik7TwXp/ou7zdeRLHSbGxz6Lw19RjyLV
         3WbMjt8zyvEUKu+CDOFrLNMLIcv3t18wUQ4VlbsVzrB3nG++ww5LrcWY2/+st96TwZWr
         xhlzAyfTnr7DYPUsuHG235wnk9DLGC+Azxi8poueF2lEYtLCDrv3ZBtIz0FKJZcD3NCi
         Nxzw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=VFTQz853;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::442 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=QfodHDNoFh3W7Q/VWHU0Tt2pG4yeACTkrTKL1Goy9dw=;
        b=MBZ2wTGF+KWsOXNF0mHO0GYLUSY7i+EakfGsdhKCEj2hqaoFqKHTqPsmfE0mZxP9ME
         bC5VzlMuZZ3FUllpKpQVeYAvCvkLDy39LI55ByS3ujR20UWO+asKLO4roGhdVMt/bpbr
         IYak/KhK9f7VEE1tZBOvnDaT4QZeKe7wtiGdGVxerkGtKdvbRsa+HZ/v4F3xc8B76IBd
         36Y+EKCnvE2dypMOk90tT4kPYc3EtqbFh/6n5zKK07k22wATbF/mRGyjed5tAA06Dbcn
         /w2ieXv3oaE1X3HggLWsSj9+urmTSJfIxyP5TNinGGNmJvnCWqo+JY9AiCeA26c8e2zw
         Cl/Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=QfodHDNoFh3W7Q/VWHU0Tt2pG4yeACTkrTKL1Goy9dw=;
        b=UX1qZmABx4XxuauiTuCvx2LK0muKVtHC3zH7sxFttxwmWQBb0nSVDC5GEV2ZSSx/GK
         NGeMfZdAcfAnhCRAo9g1OdiUNReF8hGEgtAK7HoDhyCJ1RuoxCbMibB+qNWrNiwZrWdq
         z+ADjzWtrfTYvPtRyDPtEVDYNg9JRbFd6dj2tlD4AuUsrjVXg9WjUgbc61/59AtMeyZX
         x4rwpHOeMfnjGD7eQfRS1uuVchfN+2ZpBPrPsMU20damSFrM2xcsOWnPXkv6oPfl6ida
         6o4SEwvDNbWSe8dn2LLwNTwYE3PnoZX0ipB9RWB93XFjMbx9wPl9l2Zqn2dVzxFV+HzH
         kg7Q==
X-Gm-Message-State: AOAM531Ozozid1S+xFciggzRlFavyyWgdWD6NvygL6fcbCw1PKuYVY2E
	UIPgSEqJXbDMk2fw3JTNFIU=
X-Google-Smtp-Source: ABdhPJwHDfGfelC5DhP4vlZybMRhCzPLq7psVCMhYZEk1duowpGw/qoHDtbCcigeu3bK6IH5anul1g==
X-Received: by 2002:a54:4504:: with SMTP id l4mr5773858oil.122.1598535295059;
        Thu, 27 Aug 2020 06:34:55 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:5f98:: with SMTP id g24ls625482oti.10.gmail; Thu, 27 Aug
 2020 06:34:54 -0700 (PDT)
X-Received: by 2002:a9d:328:: with SMTP id 37mr13934903otv.196.1598535294654;
        Thu, 27 Aug 2020 06:34:54 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1598535294; cv=none;
        d=google.com; s=arc-20160816;
        b=W6CFmGmKyxtB1fy+y7YvymrOOvkPUPw+VujPBtI23C8EQwriB7MAukX261MyPfUN0E
         FS91bKq/ERt4rcTsX63wPYRrRo34h2zGco6k65OWioHsqDnx0X7rthinjBfx5FYwJJZ5
         wehEwPX0LRHGoqlq3IwkMQ3oXcG3a1D0zxxQ63j0bKVOt2EjuKnxOUOwU6Fg3tunHoBk
         pFAoe9nXqGdHiQgFS+GDKNLmGoQjKqrfjbqR9xTL20Ox6Gr+I07tbdA9hWtgMoAMGMck
         tfaKTmTWOeri6ikdD2JrPk8MRkdvYTqviVVYL2iUT0/brlwP8ijTaDHpfp9tkvz/glrL
         qlFQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=fOtOQwtAMnsiuZkel6P+QKLSzAWGFcwbvl4MhWbUo1c=;
        b=jAUM9M1hEaxvHCEpdylaAyyADVt0iqko+fTA7gFtCJpGNkSRuvdJl0/oS03IEJE1ly
         A21c3D53Ra7z2brlds+VT9tdv5k6uL2OBDLsCAjq+HIjM7iF2zcigRqrKlnepV6bnb7P
         h8CMsSgqYbl36SdMOKnyE2nEyY0Jl4vtSV61IMe2UZtupLGB6HGYWi8kVaTV9aE8Kc3G
         VnRkuA7w1sJzmSAcC9gLplPNIvASyFaZ4N/z9r8o+wprEDMYs4jpxoHKce9KMfw2XgRQ
         +7nepyGoI3+ebnde9CfK9JCTR8UceJf0mpqlWQPRMs+4LF7YLPjbnTkMPNtumfVR1wkE
         SBWA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=VFTQz853;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::442 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pf1-x442.google.com (mail-pf1-x442.google.com. [2607:f8b0:4864:20::442])
        by gmr-mx.google.com with ESMTPS id d11si157526oti.2.2020.08.27.06.34.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 27 Aug 2020 06:34:54 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::442 as permitted sender) client-ip=2607:f8b0:4864:20::442;
Received: by mail-pf1-x442.google.com with SMTP id u128so3513167pfb.6
        for <kasan-dev@googlegroups.com>; Thu, 27 Aug 2020 06:34:54 -0700 (PDT)
X-Received: by 2002:a17:902:b589:: with SMTP id a9mr15940749pls.98.1598535293587;
 Thu, 27 Aug 2020 06:34:53 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1597425745.git.andreyknvl@google.com> <f173aacd755e4644485c551198549ac52d1eb650.1597425745.git.andreyknvl@google.com>
 <20200827095429.GC29264@gaia> <CAAeHK+xHQDMsTehppknjNTEMFh18ufWB1XLUGdVFoc-QZ-mVrw@mail.gmail.com>
 <20200827131045.GM29264@gaia>
In-Reply-To: <20200827131045.GM29264@gaia>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 27 Aug 2020 15:34:42 +0200
Message-ID: <CAAeHK+xraz7E41b4LW6VW9xOH51UoZ+odNEDrDGtaJ71n=bQ3A@mail.gmail.com>
Subject: Re: [PATCH 21/35] arm64: mte: Add in-kernel tag fault handler
To: Catalin Marinas <catalin.marinas@arm.com>
Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Elena Petrova <lenaptr@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	Will Deacon <will.deacon@arm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=VFTQz853;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::442
 as permitted sender) smtp.mailfrom=andreyknvl@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

On Thu, Aug 27, 2020 at 3:10 PM Catalin Marinas <catalin.marinas@arm.com> wrote:
>
> On Thu, Aug 27, 2020 at 02:31:23PM +0200, Andrey Konovalov wrote:
> > On Thu, Aug 27, 2020 at 11:54 AM Catalin Marinas
> > <catalin.marinas@arm.com> wrote:
> > > On Fri, Aug 14, 2020 at 07:27:03PM +0200, Andrey Konovalov wrote:
> > > > +static int do_tag_recovery(unsigned long addr, unsigned int esr,
> > > > +                        struct pt_regs *regs)
> > > > +{
> > > > +     report_tag_fault(addr, esr, regs);
> > > > +
> > > > +     /* Skip over the faulting instruction and continue: */
> > > > +     arm64_skip_faulting_instruction(regs, AARCH64_INSN_SIZE);
> > >
> > > Ooooh, do we expect the kernel to still behave correctly after this? I
> > > thought the recovery means disabling tag checking altogether and
> > > restarting the instruction rather than skipping over it.
> >
> > The intention is to be able to catch multiple MTE faults without
> > panicking or disabling MTE when executing KASAN tests (those do
> > multiple bad accesses one after another).
>
> The problem is that for MTE synchronous tag check faults, the access has
> not happened, so you basically introduce memory corruption by skipping
> the access.

Yes, you're right.

> > We do arm64_skip_faulting_instruction() for software tag-based KASAN
> > too, it's not ideal, but works for testing purposes.
>
> IIUC, KASAN only skips over the brk instruction which doesn't have any
> other side-effects.

Oh, yes, indeed. For some reason I confused myself thinking that we
also skip the access for software KASAN.

> Has the actual memory access taken place when it
> hits the brk?

IIRC, no, but it will be executed right after we skip the brk.

> > Can we disable MTE, reexecute the instruction, and then reenable MTE,
> > or something like that?
>
> If you want to preserve the MTE enabled, you could single-step the
> instruction or execute it out of line, though it's a bit more convoluted
> (we have a similar mechanism for kprobes/uprobes).
>
> Another option would be to attempt to set the matching tag in memory,
> under the assumption that it is writable (if it's not, maybe it's fine
> to panic). Not sure how this interacts with the slub allocator since,
> presumably, the logical tag in the pointer is wrong rather than the
> allocation one.
>
> Yet another option would be to change the tag in the register and
> re-execute but this may confuse the compiler.

Which one of these would be simpler to implement?

Perhaps we could somehow only skip faulting instructions that happen
in the KASAN test module?.. Decoding stack trace would be an option,
but that's a bit weird.

Overall, this feature is not essential, but will make testing simpler.

> > When running in-kernel MTE in production, we'll either panic or
> > disable MTE after the first fault. This was controlled by the
> > panic_on_mte_fault option Vincenzo initially had.
>
> I prefer to disable MTE, print something and continue, but no panic.

OK, we can do this.

> > > We only skip if we emulated it.
> >
> > I'm not sure I understand this part, what do you mean by emulating?
>
> Executing it out of line or other form of instruction emulation (see
> arch/arm64/kernel/probes/simulate-insn.c) so that the access actually
> takes place. But you can single-step or experiment with some of the
> other tricks above.
>
> --
> Catalin

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2Bxraz7E41b4LW6VW9xOH51UoZ%2BodNEDrDGtaJ71n%3DbQ3A%40mail.gmail.com.
