Return-Path: <kasan-dev+bncBDX4HWEMTEBRBJ6PT35AKGQEGF3NC4Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3a.google.com (mail-yb1-xb3a.google.com [IPv6:2607:f8b0:4864:20::b3a])
	by mail.lfdr.de (Postfix) with ESMTPS id F12962544FD
	for <lists+kasan-dev@lfdr.de>; Thu, 27 Aug 2020 14:31:36 +0200 (CEST)
Received: by mail-yb1-xb3a.google.com with SMTP id b127sf7122409ybh.21
        for <lists+kasan-dev@lfdr.de>; Thu, 27 Aug 2020 05:31:36 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1598531496; cv=pass;
        d=google.com; s=arc-20160816;
        b=rIledvAxlg6xkgpnC0PpTGoMOA/nXEFj6fgzsUASoA295/ivporpmPVFS8ifOfi/6i
         IueiM5Vd/1q/5mPbYIyYMBVnJuGb+Z9XGxhApFSU+yM8rhoK2QHuBT9X3+euOE1e7FMX
         UocrTl+mXzO1DuKyivo494f11UbkmlTk2eFufsCgkvNQ+woht75iJnnwRwIX+N6yYlz9
         ee5RtaGVRXhVIR5ugGIIUZ+GYzSICRtB5hgaStoxVf6pMn8NPNNO0Bnt6n7nfYUKG+BP
         S0cF4NZzFqknAuBzp0wAEHo3c/oii8y0EK681VWrxzN6TXIMW1BZ6GOfUsVHzVWuBYG1
         l7rg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=r3ldFKvo2cWS7fDOeNb+0md9N+/WkP4KmnGFrcGmIpI=;
        b=ydvLB43H6lzzocgR3RLkQyyvXMCFpTJn5dV83k/hHGuI2a7A2SV+e49ywe+F3KTPeC
         nGB0m2xz12okhU1zyTBLnBV+N28HWalpKpHwlIWitil2UAyEi0rBhF03dVIXk55JyrAV
         bwzzS2MXc0/oVszLHxl56jGK/vHW+g7apumU+sOojdk28X/cTA971ooZinLWazzS6/Uo
         i4k/rkqf8F1btjyQfMaOV+YuhukW4sqD2vNPoeeUTJ9njjW+quSCF+e8iL3ZCx6sjo69
         OiZUl+dXgsVeKjtkrqbRW1dl9Vkq0B3BdQAyLylAc+IuibfiWdCrIbIKUWA4Q97nBLIS
         EXnA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=I1epf77j;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1041 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=r3ldFKvo2cWS7fDOeNb+0md9N+/WkP4KmnGFrcGmIpI=;
        b=do3TGq7WEy34ytkt9F+qdAgeORc37C29FPrKamV8l9ylHiSsmWpgVUEqMCk6bY42kd
         HbtntySw4LhPDZR+qRbYUVV7TD/d/Xu0/hVmJSJJiyQFelsAZDfo5Ly/iS+NU69/qFvs
         57HN9o3Gonb8LiMruChLbgzk4vS0JDWpRF40XHc2/y1n/O2eukzu3P8Ebd1tvWARTIxl
         unGdphmBG6Xkg91856KirtFKzxKJ/IlJ0eM4RVdDgOOFZAr0syjbJcQy+/wohq4xP0/g
         Zk1Wsxiwncu66pF48ZoViZUkRDHMKumQB2WmDrkD9Hi7RvHQbz7FZ+45zE1ho/Conmzc
         KgCw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=r3ldFKvo2cWS7fDOeNb+0md9N+/WkP4KmnGFrcGmIpI=;
        b=X2cbUBSVMm52uqLlSQyUtOTV3ydtyWvInKNynNggn9D803H2g0mNF6851gQyt65T5N
         CTGMuIYamfSiZEb80LeFdveBcDE9xTJw+X1qJ0rJC0qGeVUDzEks12aupUDe0He6iUAL
         cMOlPjBYuvqTYTy7qZt/+4Ldq6PJ2yeDhxSydeCsu49vdVaY6WBGUEsekc1d2r5Res/N
         Go7jzpWHM3802EvYavtInXJOXGvUgX5EBQh3mYEwQPmiCbBiFkhSkcXf58FHXXJWL39i
         ghvu5e9ByfoZf7gslpdje6xhvDhBfQxbW+n+AaQL92gOD5nvZoT1clQZSrF+Kk1yJm8E
         pkwQ==
X-Gm-Message-State: AOAM533dzLrZzdA/oAHuapPVb/J8jug1TQEA/F+Ssq9R7ARI7Rkk/mjX
	M2I7IdDxdk2v62VqP+utNmA=
X-Google-Smtp-Source: ABdhPJz1fjDxsv+qcfq2NsgQ7sm//PmHvQ3wEunWI5S6C9IlygiohLShvYIDcMoO2hdbrTm0p2L+NA==
X-Received: by 2002:a25:dac2:: with SMTP id n185mr28697067ybf.396.1598531495967;
        Thu, 27 Aug 2020 05:31:35 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:5755:: with SMTP id l82ls908845ybb.5.gmail; Thu, 27 Aug
 2020 05:31:35 -0700 (PDT)
X-Received: by 2002:a25:7491:: with SMTP id p139mr30729313ybc.293.1598531495571;
        Thu, 27 Aug 2020 05:31:35 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1598531495; cv=none;
        d=google.com; s=arc-20160816;
        b=eRHWoCHkXWVPdZA1yZlR7XgI6cNQ/JEjotT1obUs5npzVjTpPECR/Z9kTpBrX35DB2
         wKEWf5SxfeRmsA6X/6kIRjj3o3d9Ukj+avpeGikvmUSqjG4+qK4E6vFjsH+UHF2hbNIP
         GUk5FNumEDDZfFVpc8OH94I9esC/mTzleodKEKpK+ZJvH7mTBGId5cowPX9ybcjH9cKW
         pocYqkg6PLMBUPqhWTOKQELiioVi1isY9zfQ88AmCW++ssJAByPfIF3UM3txkHaCqbDX
         mddJd4QNYzTwUSi+hY67DZ2OlMc4IfKeMMqpy3Xyow2ZRkhfeETBiznW+0vjovRtUUjl
         KYnA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=yQ34VdsT1gZZpD4I8FVa5CTJn00Te78jNd2pA6lLPkY=;
        b=Ys/I/vADFqBRIrtx+tHoZOGdzoJnGa4UiVLLDtX9+QIBi3tdIgF9SASBvvPo22evnj
         06A/EgQaq3Lv8xysQrbPXDwIkNtDMB0UppP0NSIdyHFTMPukO4INd5byJ8ZM6KKDeNfQ
         0ruiPFhrF8GVfxhUn+yrJ8afedlaZUXT3Na7vqryxJr4I4uXsc2HXElOC+OhXGK13pWa
         C1fgzsUYte7iVK4nWDsxX+793+6afulG3L6nIZuHJhK6jTOrZQfELeRgm1jiJYgo/SHc
         eBr3sedNUPrZbYyrM/uZP5rt7BYYPDVCYT/Gq0H3rgS9qGasMi4MCzcqGQD77EaAgl34
         ufjA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=I1epf77j;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1041 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pj1-x1041.google.com (mail-pj1-x1041.google.com. [2607:f8b0:4864:20::1041])
        by gmr-mx.google.com with ESMTPS id y18si114568ybk.3.2020.08.27.05.31.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 27 Aug 2020 05:31:35 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1041 as permitted sender) client-ip=2607:f8b0:4864:20::1041;
Received: by mail-pj1-x1041.google.com with SMTP id q93so2572549pjq.0
        for <kasan-dev@googlegroups.com>; Thu, 27 Aug 2020 05:31:35 -0700 (PDT)
X-Received: by 2002:a17:90a:a791:: with SMTP id f17mr10252307pjq.136.1598531494572;
 Thu, 27 Aug 2020 05:31:34 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1597425745.git.andreyknvl@google.com> <f173aacd755e4644485c551198549ac52d1eb650.1597425745.git.andreyknvl@google.com>
 <20200827095429.GC29264@gaia>
In-Reply-To: <20200827095429.GC29264@gaia>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 27 Aug 2020 14:31:23 +0200
Message-ID: <CAAeHK+xHQDMsTehppknjNTEMFh18ufWB1XLUGdVFoc-QZ-mVrw@mail.gmail.com>
Subject: Re: [PATCH 21/35] arm64: mte: Add in-kernel tag fault handler
To: Catalin Marinas <catalin.marinas@arm.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>
Cc: Dmitry Vyukov <dvyukov@google.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Elena Petrova <lenaptr@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=I1epf77j;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1041
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

On Thu, Aug 27, 2020 at 11:54 AM Catalin Marinas
<catalin.marinas@arm.com> wrote:
>
> On Fri, Aug 14, 2020 at 07:27:03PM +0200, Andrey Konovalov wrote:
> > diff --git a/arch/arm64/mm/fault.c b/arch/arm64/mm/fault.c
> > index 5e832b3387f1..c62c8ba85c0e 100644
> > --- a/arch/arm64/mm/fault.c
> > +++ b/arch/arm64/mm/fault.c
> > @@ -33,6 +33,7 @@
> >  #include <asm/debug-monitors.h>
> >  #include <asm/esr.h>
> >  #include <asm/kprobes.h>
> > +#include <asm/mte.h>
> >  #include <asm/processor.h>
> >  #include <asm/sysreg.h>
> >  #include <asm/system_misc.h>
> > @@ -222,6 +223,20 @@ int ptep_set_access_flags(struct vm_area_struct *vma,
> >       return 1;
> >  }
> >
> > +static bool is_el1_mte_sync_tag_check_fault(unsigned int esr)
> > +{
> > +     unsigned int ec = ESR_ELx_EC(esr);
> > +     unsigned int fsc = esr & ESR_ELx_FSC;
> > +
> > +     if (ec != ESR_ELx_EC_DABT_CUR)
> > +             return false;
> > +
> > +     if (fsc == ESR_ELx_FSC_MTE)
> > +             return true;
> > +
> > +     return false;
> > +}
> > +
> >  static bool is_el1_instruction_abort(unsigned int esr)
> >  {
> >       return ESR_ELx_EC(esr) == ESR_ELx_EC_IABT_CUR;
> > @@ -294,6 +309,18 @@ static void die_kernel_fault(const char *msg, unsigned long addr,
> >       do_exit(SIGKILL);
> >  }
> >
> > +static void report_tag_fault(unsigned long addr, unsigned int esr,
> > +                          struct pt_regs *regs)
> > +{
> > +     bool is_write = ((esr & ESR_ELx_WNR) >> ESR_ELx_WNR_SHIFT) != 0;
> > +
> > +     pr_alert("Memory Tagging Extension Fault in %pS\n", (void *)regs->pc);
> > +     pr_alert("  %s at address %lx\n", is_write ? "Write" : "Read", addr);
> > +     pr_alert("  Pointer tag: [%02x], memory tag: [%02x]\n",
> > +                     mte_get_ptr_tag(addr),
> > +                     mte_get_mem_tag((void *)addr));
> > +}
> > +
> >  static void __do_kernel_fault(unsigned long addr, unsigned int esr,
> >                             struct pt_regs *regs)
> >  {
> > @@ -317,12 +344,16 @@ static void __do_kernel_fault(unsigned long addr, unsigned int esr,
> >                       msg = "execute from non-executable memory";
> >               else
> >                       msg = "read from unreadable memory";
> > +     } else if (is_el1_mte_sync_tag_check_fault(esr)) {
> > +             report_tag_fault(addr, esr, regs);
> > +             msg = "memory tagging extension fault";
>
> IIUC, that's dead code. See my comment below on do_tag_check_fault().
>
> >       } else if (addr < PAGE_SIZE) {
> >               msg = "NULL pointer dereference";
> >       } else {
> >               msg = "paging request";
> >       }
> >
> > +
>
> Unnecessary empty line.
>
> >       die_kernel_fault(msg, addr, esr, regs);
> >  }
> >
> > @@ -658,10 +689,27 @@ static int do_sea(unsigned long addr, unsigned int esr, struct pt_regs *regs)
> >       return 0;
> >  }
> >
> > +static int do_tag_recovery(unsigned long addr, unsigned int esr,
> > +                        struct pt_regs *regs)
> > +{
> > +     report_tag_fault(addr, esr, regs);
> > +
> > +     /* Skip over the faulting instruction and continue: */
> > +     arm64_skip_faulting_instruction(regs, AARCH64_INSN_SIZE);
>
> Ooooh, do we expect the kernel to still behave correctly after this? I
> thought the recovery means disabling tag checking altogether and
> restarting the instruction rather than skipping over it.

The intention is to be able to catch multiple MTE faults without
panicking or disabling MTE when executing KASAN tests (those do
multiple bad accesses one after another). We do
arm64_skip_faulting_instruction() for software tag-based KASAN too,
it's not ideal, but works for testing purposes.

Can we disable MTE, reexecute the instruction, and then reenable MTE,
or something like that?

When running in-kernel MTE in production, we'll either panic or
disable MTE after the first fault. This was controlled by the
panic_on_mte_fault option Vincenzo initially had.

> We only skip if we emulated it.

I'm not sure I understand this part, what do you mean by emulating?

>
> > +
> > +     return 0;
> > +}
> > +
> > +
> >  static int do_tag_check_fault(unsigned long addr, unsigned int esr,
> >                             struct pt_regs *regs)
> >  {
> > -     do_bad_area(addr, esr, regs);
> > +     /* The tag check fault (TCF) is per TTBR */
> > +     if (is_ttbr0_addr(addr))
> > +             do_bad_area(addr, esr, regs);
> > +     else
> > +             do_tag_recovery(addr, esr, regs);
>
> So we never invoke __do_kernel_fault() for a synchronous tag check in
> the kernel. What's with all the is_el1_mte_sync_tag_check_fault() check
> above?
>
> --
> Catalin
>
> --
> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200827095429.GC29264%40gaia.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2BxHQDMsTehppknjNTEMFh18ufWB1XLUGdVFoc-QZ-mVrw%40mail.gmail.com.
