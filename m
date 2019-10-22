Return-Path: <kasan-dev+bncBC7OBJGL2MHBB6X3XPWQKGQEOE7NBBI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53e.google.com (mail-pg1-x53e.google.com [IPv6:2607:f8b0:4864:20::53e])
	by mail.lfdr.de (Postfix) with ESMTPS id 6E959E0468
	for <lists+kasan-dev@lfdr.de>; Tue, 22 Oct 2019 15:02:52 +0200 (CEST)
Received: by mail-pg1-x53e.google.com with SMTP id s1sf12491589pgm.2
        for <lists+kasan-dev@lfdr.de>; Tue, 22 Oct 2019 06:02:52 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1571749371; cv=pass;
        d=google.com; s=arc-20160816;
        b=U8X3YvqBepVDvgDc4OOm0EUC7psqCavtQfQZ6pvPUoWboE9ZpERtZO6aIdLrjkGhwP
         McfPyA4kChGh6hd6V9Qqq46qE5jxE7Ao9f7LvejJrIvjguCKGbTfpvAqIF1oh2LFpKRg
         C+f0sD6A5/Z3Y2EGC6h4rJE7+pdroFhFMTGg9T2XEAddw01dBwFasXBATRF7rcb4ONKE
         ShPCiBHvSoMSwegsy15dh+cpYSr9QJp3av6cBAxDikLlLgWT4dbaczA89INo8tUl5nuI
         C9Sf8DihrpIT3+OMKBXrK3nw1PE33d/L9a2vKlVsTuUNYs5l7/nX3UhVV4dJU1A1rl/Y
         yUlw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=ew/dl2IkXxFKI7vMzgnB5A+rTVxRXk9XEWy3z9WKtDA=;
        b=X4O86iBU4n0Vu3fKXOKwQ7aMdG/h26yS5e0DqSVfUl3j2sdVED7UcbuNzNy81QaH6s
         /pLp5/Mc11exxWF3P4u35jksB+uTXJc+hldoAFDOu1EVTmzgj+eg9ySMT/f0ZjQdL0mm
         5RcWJX6mWLteB7KtvTr5nidIY+/EQ0dFFjc3zo+xCYXn1J9C1/wBKtQu8oNqPZrkEew5
         YrM6utsS3XOcRDQD62c2BrcLKt/d3tS8Ze/B8NEwYXkLeTxiiq2I5MhadQNB9WmuO3c1
         Y7wUPcuNPtJZ2ebkoZnEg2t70/dxX/ctlB72hYNboKihFYjxLYxCxKJrWAYRmhc3g17O
         ZJAA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=OA8cRa7t;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::244 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ew/dl2IkXxFKI7vMzgnB5A+rTVxRXk9XEWy3z9WKtDA=;
        b=pd7+5UfQZOQc+d0QAwUIb4YyLXIsT+MZrJ2qYcyNRUa9Gfpx6+2zHmv+mm3ScwvnEv
         /kQn8QbPd2Hf3I/MQJ0fGrzZr6rYkUJt5F/n4J74nO/L6+AYUpdz6sxUS3bYugP+v7Gx
         o61TFUZPVrHUoA8hgoB/W9r28qatIVFtLGS+bB4E7OWy4wZ3zTpNjWWI2Zi82gcIkbq9
         mDmt8teSB60wu5maZI/gxDEK+ZEnOfZrCRLUQxVYsO1Q+ulTfbMPtP/F351DytjnkIl9
         3a8Zak0VyU25K8yg9WF982fNhqVCF11wFXYeayYh0D6cskIEGN+2hpFkQE++2btukQMb
         +j8g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ew/dl2IkXxFKI7vMzgnB5A+rTVxRXk9XEWy3z9WKtDA=;
        b=pk22aO4c8m9zbA5My8/lhAvevJBoomewHgYWEjIIZEDQvNJX7NzdtQwdpnvIWSS/dq
         4KWbSkz/WpW90KULdrlJrG4LCdfrwFSZznH3qxLW6REhmqhAW2e1ZRUZcwyamZdVPNXj
         Y4o7EqNMJD0hB6ZQ+kAcvXpjO21MhZspxEMih4iMRWOtA1F0DYRmUvFnU2DpnU1JHVJJ
         l3kPRyBTFGajOsfpKCiPIRCdHqJsksS7+9r3EqSRF9BnD/P0InNkdcqyTVOADkKMtX9T
         crlK7VEm0ZAA+5pFyhAZBtUuuDHrjDApajr7wSvgC2lxPvlKWXg90KU679yOq4iV2jm8
         am8Q==
X-Gm-Message-State: APjAAAXupsbuHEM0sRoZ4GCOv1m0NcxppWJoUFfODVfz5wIczQlti8+x
	KRNpahT24GAoHmE/iKTZuK8=
X-Google-Smtp-Source: APXvYqwW/xvHvH8CajBxUoq2/zJE+4e1nEPYgetDU5x0LY37tUAPJM6L1juPU/PPpTHfN7vO73iuKg==
X-Received: by 2002:a63:cb4f:: with SMTP id m15mr3764885pgi.325.1571749370787;
        Tue, 22 Oct 2019 06:02:50 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:204c:: with SMTP id r12ls4496465pgm.1.gmail; Tue, 22 Oct
 2019 06:02:50 -0700 (PDT)
X-Received: by 2002:a63:7405:: with SMTP id p5mr3728634pgc.264.1571749370250;
        Tue, 22 Oct 2019 06:02:50 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1571749370; cv=none;
        d=google.com; s=arc-20160816;
        b=huJIxuWGOOPelk2o3vHUZedCIAiFAu7uJbMmNtncadAIGWwf3KEBWMMarM+VG+PhVu
         nDC3gsuTKmVV19iO0uQw30RdjuWLQyM3g+Cb/YSwSkujkVSR2XfTVlXV/rXjRF+xIV12
         L5YEAsCCppSoVdSTNdupebDkHt0ryETlhUasX2l1vPC2uftJVSFearPA8Bs4phJKptzr
         IzJtqqhyGffPiVjYOW/wVJxO7ZpF08mwrrUNkFFmMPo6LGn5nA6lHYh1heyLmbxIB+sL
         Z+xokn7NdC5apn+0AhWdKk5dlke8iYrlrSxf7oHwr7pob+dXWThDMxeqpXQ7Le52aRKK
         wB8w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=kuKLQUxYTkpNquMkRmE+sotbdgdLrnH62e1xn6PHfbU=;
        b=Dt9JxpJsZ8Tc/r10jhmg4OreblzaVpwCDmF0GDM4OF7qwcb/W9fR0oX9jnzmLJ72u4
         mGyR7m5bn5LuBCveYXdxG8TaObmGy1vimxTWO0HofRAbYbNPWAkMUIpFfLfQo93t/twa
         orGuJsOlkwmQ6dEB2PNtuejsc3g57Nu8Ie0PnehdYKYdW0Vh+mQX89GmP0qWU2vIEKTJ
         itdaEq9dBbkZgHioU3eB0LvXk0vbC3pijf/opO8Kz0ySrdE5AzRAs+tqP3VoctP9AOI3
         dB1iUbZaa7S5VwTT2D7yTE7rCrWN07giLnvZ1RKee4wwOqGCpDbbwPPVw6sV2GmiyR8K
         JBuw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=OA8cRa7t;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::244 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x244.google.com (mail-oi1-x244.google.com. [2607:f8b0:4864:20::244])
        by gmr-mx.google.com with ESMTPS id e6si696815pjp.2.2019.10.22.06.02.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 22 Oct 2019 06:02:50 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::244 as permitted sender) client-ip=2607:f8b0:4864:20::244;
Received: by mail-oi1-x244.google.com with SMTP id g81so14055562oib.8
        for <kasan-dev@googlegroups.com>; Tue, 22 Oct 2019 06:02:50 -0700 (PDT)
X-Received: by 2002:aca:f1a:: with SMTP id 26mr2807399oip.172.1571749369044;
 Tue, 22 Oct 2019 06:02:49 -0700 (PDT)
MIME-Version: 1.0
References: <20191017141305.146193-1-elver@google.com> <20191017141305.146193-9-elver@google.com>
 <20191022125921.GD11583@lakrids.cambridge.arm.com>
In-Reply-To: <20191022125921.GD11583@lakrids.cambridge.arm.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 22 Oct 2019 15:02:37 +0200
Message-ID: <CANpmjNPcToD2Joe_BE4xgLDOGCscHrtJdqivDPfFjE6nCpq5PQ@mail.gmail.com>
Subject: Re: [PATCH v2 8/8] x86, kcsan: Enable KCSAN for x86
To: Mark Rutland <mark.rutland@arm.com>
Cc: LKMM Maintainers -- Akira Yokosawa <akiyks@gmail.com>, Alan Stern <stern@rowland.harvard.edu>, 
	Alexander Potapenko <glider@google.com>, Andrea Parri <parri.andrea@gmail.com>, 
	Andrey Konovalov <andreyknvl@google.com>, Andy Lutomirski <luto@kernel.org>, 
	Ard Biesheuvel <ard.biesheuvel@linaro.org>, Arnd Bergmann <arnd@arndb.de>, 
	Boqun Feng <boqun.feng@gmail.com>, Borislav Petkov <bp@alien8.de>, Daniel Axtens <dja@axtens.net>, 
	Daniel Lustig <dlustig@nvidia.com>, Dave Hansen <dave.hansen@linux.intel.com>, 
	David Howells <dhowells@redhat.com>, Dmitry Vyukov <dvyukov@google.com>, 
	"H. Peter Anvin" <hpa@zytor.com>, Ingo Molnar <mingo@redhat.com>, Jade Alglave <j.alglave@ucl.ac.uk>, 
	Joel Fernandes <joel@joelfernandes.org>, Jonathan Corbet <corbet@lwn.net>, 
	Josh Poimboeuf <jpoimboe@redhat.com>, Luc Maranget <luc.maranget@inria.fr>, 
	Nicholas Piggin <npiggin@gmail.com>, "Paul E. McKenney" <paulmck@linux.ibm.com>, 
	Peter Zijlstra <peterz@infradead.org>, Thomas Gleixner <tglx@linutronix.de>, Will Deacon <will@kernel.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, linux-arch <linux-arch@vger.kernel.org>, 
	"open list:DOCUMENTATION" <linux-doc@vger.kernel.org>, linux-efi@vger.kernel.org, 
	Linux Kbuild mailing list <linux-kbuild@vger.kernel.org>, LKML <linux-kernel@vger.kernel.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, "the arch/x86 maintainers" <x86@kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=OA8cRa7t;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::244 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Tue, 22 Oct 2019 at 14:59, Mark Rutland <mark.rutland@arm.com> wrote:
>
> On Thu, Oct 17, 2019 at 04:13:05PM +0200, Marco Elver wrote:
> > This patch enables KCSAN for x86, with updates to build rules to not use
> > KCSAN for several incompatible compilation units.
> >
> > Signed-off-by: Marco Elver <elver@google.com>
> > ---
> > v2:
> > * Document build exceptions where no previous above comment explained
> >   why we cannot instrument.
> > ---
> >  arch/x86/Kconfig                      | 1 +
> >  arch/x86/boot/Makefile                | 2 ++
> >  arch/x86/boot/compressed/Makefile     | 2 ++
> >  arch/x86/entry/vdso/Makefile          | 3 +++
> >  arch/x86/include/asm/bitops.h         | 6 +++++-
> >  arch/x86/kernel/Makefile              | 7 +++++++
> >  arch/x86/kernel/cpu/Makefile          | 3 +++
> >  arch/x86/lib/Makefile                 | 4 ++++
> >  arch/x86/mm/Makefile                  | 3 +++
> >  arch/x86/purgatory/Makefile           | 2 ++
> >  arch/x86/realmode/Makefile            | 3 +++
> >  arch/x86/realmode/rm/Makefile         | 3 +++
> >  drivers/firmware/efi/libstub/Makefile | 2 ++
> >  13 files changed, 40 insertions(+), 1 deletion(-)
>
> > diff --git a/drivers/firmware/efi/libstub/Makefile b/drivers/firmware/efi/libstub/Makefile
> > index 0460c7581220..693d0a94b118 100644
> > --- a/drivers/firmware/efi/libstub/Makefile
> > +++ b/drivers/firmware/efi/libstub/Makefile
> > @@ -31,7 +31,9 @@ KBUILD_CFLAGS                       := $(cflags-y) -DDISABLE_BRANCH_PROFILING \
> >                                  -D__DISABLE_EXPORTS
> >
> >  GCOV_PROFILE                 := n
> > +# Sanitizer runtimes are unavailable and cannot be linked here.
> >  KASAN_SANITIZE                       := n
> > +KCSAN_SANITIZE                       := n
> >  UBSAN_SANITIZE                       := n
> >  OBJECT_FILES_NON_STANDARD    := y
>
> Not a big deal, but it might make sense to move the EFI stub exception
> to patch 3 since it isn't x86 specific (and will also apply for arm64).

Thanks for spotting, moved for v3.

-- Marco

> Otherwise this looks good to me.
>
> Thanks,
> Mark.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNPcToD2Joe_BE4xgLDOGCscHrtJdqivDPfFjE6nCpq5PQ%40mail.gmail.com.
