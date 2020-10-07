Return-Path: <kasan-dev+bncBC7OBJGL2MHBB5H3635QKGQEOPIJKHQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x939.google.com (mail-ua1-x939.google.com [IPv6:2607:f8b0:4864:20::939])
	by mail.lfdr.de (Postfix) with ESMTPS id CD2A0285FC9
	for <lists+kasan-dev@lfdr.de>; Wed,  7 Oct 2020 15:09:10 +0200 (CEST)
Received: by mail-ua1-x939.google.com with SMTP id o59sf576952uao.17
        for <lists+kasan-dev@lfdr.de>; Wed, 07 Oct 2020 06:09:10 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1602076150; cv=pass;
        d=google.com; s=arc-20160816;
        b=qgXNm9KmPBmOUDtTnpYKpgzm2MHDxDfzEdqeZf9dRxf5JXdXuKlLgytxtK6PoQCdcl
         l54kZd8kR9WF8RWqURuXU1LFDYka8QnXqApbXYVgWFSCOQ1TswwacUOuqlifg+4p+XNi
         RiJon3ykhEB54M/1ZM+Q1j1GzhSfROg+bFEM2/AGJx5s5PWVeiPeKMXPTxHMOAvGIJIs
         9sYBQJ7+PWW8Su7V2BiaQMFzxXTymuPU3rkWibYPIqUCf+mLlRGU1f0bJY21BhY+/D2S
         qv6YQcDzdwZthz4fvvOlLsBj+9918MhCy76rr6qsQ1R9cXNJ76/r++hNjBQL+SPCyE4c
         32BQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=blf6pOb3TR8ENIoo2Mz+8CKo9sASotjKhaALtai5Png=;
        b=l+YB97TEqkCO7kq4/kup8qtTPNkHBjpJJ3iwsOmLNWBWZ4TdU9CpZ8reav1Bj042UH
         jvr5+6jU5T1HqLQKRsdT5OPv6LIX8pa6mYuV+2fHmkV/qSCY1djQeo6Rqs5PGEUe+xXg
         gHdDaKZFAz9gbMI+AAvq8l8EnF2aonm2a0Zx+98L5nM28FmRGM5COi7I+eL5aFRBMCaY
         11tOqMAOF3kpcilVpgD/DKhMIYtarfG5+q5G2EFGbaR74soXopVj/PlsDgolTLBA10De
         WOLH0+udl7+QMfPzvlRBVwHBlvN1XN1Sla0X0cnQL3rifStPJ1oWLfKuVVXKsOhum5Va
         2DDg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="DA6B/QuW";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::343 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=blf6pOb3TR8ENIoo2Mz+8CKo9sASotjKhaALtai5Png=;
        b=BOnZs1MVURn3kFlhcLxeQ7+qODhYaEFnRzFTfSrGEKIm/ESC8U64dIlXPk/gmy68gu
         z8EjTyLoaIrRNTpoVsfBz5inLHVw7ibuYHEqunqK3motf6TFcyEpXLva06ts9vLZ6RQk
         I+DXjWjP7qW9xL85PaA+LW5ohufSh+5bFfMEj2RoNdAGgk+gNiqVt0Vpi5/H0zk4xmgh
         uYWHqjR1U3Ym+DW+fmXTQ0WsmojixT0Fnsjw02z+QbFbWBbTCb7zN57BrNjqdHz81Pan
         2xtbnlTa8qk5FyssplR039WQcnMndoXJNyLjOCnFcOpXNXvCF4Rb+MNkYaygBIZVwGde
         7xjw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=blf6pOb3TR8ENIoo2Mz+8CKo9sASotjKhaALtai5Png=;
        b=G54q28tPpDew+hmQlEjs67WlVFibCH8DPjAonofRT1yJRTnbVXJfe2nq+qzJxyVeul
         yV28VCNnM3BVQeHky3dcrHxCoieyhORHPSYk7V3LUSdPgQGqEUT5mve+B7cJRoJRbyVl
         nRx+j0G6SK7tqq/Yu09SIHunDsMbJRSHfGjXzPDBeDcYxwLDXRHENT5t0YrCwRWbuu76
         au4wHjwt+Smqg0bnXmLPo7fH6H0hieCQaU1uxRdCbCiiIzSwf1GX2jbLWw2hlwcJe6Eu
         38bKveep4y60ZNmWkO6cJrlYgT9+RSXVzHscca3A3xGzN9JYZUxX92BWzPDtQam5OnCx
         yPew==
X-Gm-Message-State: AOAM5302guTzk6VOgjM+v0r7zqcDHGj2fn8JqcvqnT7EJOP/HyF1VGtY
	8s+T0kKk8TRdK2yNnj8XT6w=
X-Google-Smtp-Source: ABdhPJyzyZCYzgM6GKQiY8rwzJ/zFfThkUVhUkFwUj0yN1KLVvFk+7SQozXC7JCOV0DmNGlJVjt5+g==
X-Received: by 2002:a67:2bc5:: with SMTP id r188mr1543614vsr.17.1602076149129;
        Wed, 07 Oct 2020 06:09:09 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ab0:4754:: with SMTP id i20ls133812uac.0.gmail; Wed, 07 Oct
 2020 06:09:08 -0700 (PDT)
X-Received: by 2002:ab0:72d8:: with SMTP id g24mr1363961uap.98.1602076148290;
        Wed, 07 Oct 2020 06:09:08 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1602076148; cv=none;
        d=google.com; s=arc-20160816;
        b=Q29s5OSjogmJfyhYHH9bo9pjgPRcxJOW2s9DSYxM0R9B8rxjQ/kyuVxHqLz5qtlp4B
         qJ2a0Crwo2fEMtEDvRyD64FM/+Vmg6+guf4ekGY677g3N1aNbZx6kFj9LbmAYo5uvLdV
         7dQFqm4exXzXxyGFSrXCKdyFoDUtytRj6dlbcyZRErFHLbRO8ILh+yTdcf6K6yEyMrvo
         RhqACYttchi6p4OLOqcZomSxH1PyvwuCzTYZabeRLBCai84iNA9L0lRWSov/mEXXaiKt
         WVrmETO01O5mIAQQGxvwyOpcn3dCUFJzmr3opdu2TvF/JeFaaeSA2ho96AHKF4IyjC5K
         vGUg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=A+vdTZV1rixc4rZMr4BboFv1cYBtz4vmBbW7LOKVMmM=;
        b=uJ7r8HuwUa5gDMX7mKDDGkU1lUQi0dk08zFp/BFowuIILd9WpBtiOPUkdM+d1N+Muq
         I05dXaBWR/VLYC+KJjv6vQNOPFwy9FwzW0hSDDGzcWNS8jxIGdgJA/rqn9cToEiemaNH
         LPhDvi3ShROjBZK+pR3Y/XJMb3Ci3BxfAYKSL17oYGjNQSXSq8Dg1/+SDEXTnZifY47X
         BLCqishXSjtER+PZb9ZPh3eTPD+lJSZLvqSZrMx39V6XERnRlAkk1n/PXhVg6I1Legfg
         q0RfHxUudogKyWD5T4MhDrVlxCWDZWZp+xDdIg+lumPk3aKHJnzku6O0POiIOxHz4wzX
         4geQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="DA6B/QuW";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::343 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x343.google.com (mail-ot1-x343.google.com. [2607:f8b0:4864:20::343])
        by gmr-mx.google.com with ESMTPS id y65si96231vkf.1.2020.10.07.06.09.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 07 Oct 2020 06:09:08 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::343 as permitted sender) client-ip=2607:f8b0:4864:20::343;
Received: by mail-ot1-x343.google.com with SMTP id q21so2093601ota.8
        for <kasan-dev@googlegroups.com>; Wed, 07 Oct 2020 06:09:08 -0700 (PDT)
X-Received: by 2002:a9d:66a:: with SMTP id 97mr1884792otn.233.1602076147446;
 Wed, 07 Oct 2020 06:09:07 -0700 (PDT)
MIME-Version: 1.0
References: <20200929133814.2834621-1-elver@google.com> <20200929133814.2834621-3-elver@google.com>
 <CAG48ez3OKj5Y8BURmqU9BAYWFJH8E8B5Dj9c0=UHutqf7r3hhg@mail.gmail.com>
In-Reply-To: <CAG48ez3OKj5Y8BURmqU9BAYWFJH8E8B5Dj9c0=UHutqf7r3hhg@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 7 Oct 2020 15:08:55 +0200
Message-ID: <CANpmjNP6mukCZ931_aW9dDqbkOyv=a2zbS7MuEMkE+unb7nYeg@mail.gmail.com>
Subject: Re: [PATCH v4 02/11] x86, kfence: enable KFENCE for x86
To: Jann Horn <jannh@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Alexander Potapenko <glider@google.com>, 
	"H . Peter Anvin" <hpa@zytor.com>, "Paul E . McKenney" <paulmck@kernel.org>, 
	Andrey Konovalov <andreyknvl@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Andy Lutomirski <luto@kernel.org>, Borislav Petkov <bp@alien8.de>, 
	Catalin Marinas <catalin.marinas@arm.com>, Christoph Lameter <cl@linux.com>, 
	Dave Hansen <dave.hansen@linux.intel.com>, David Rientjes <rientjes@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Eric Dumazet <edumazet@google.com>, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>, Hillf Danton <hdanton@sina.com>, 
	Ingo Molnar <mingo@redhat.com>, Jonathan Cameron <Jonathan.Cameron@huawei.com>, 
	Jonathan Corbet <corbet@lwn.net>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, 
	Kees Cook <keescook@chromium.org>, Mark Rutland <mark.rutland@arm.com>, 
	Pekka Enberg <penberg@kernel.org>, Peter Zijlstra <peterz@infradead.org>, 
	SeongJae Park <sjpark@amazon.com>, Thomas Gleixner <tglx@linutronix.de>, Vlastimil Babka <vbabka@suse.cz>, 
	Will Deacon <will@kernel.org>, "the arch/x86 maintainers" <x86@kernel.org>, 
	"open list:DOCUMENTATION" <linux-doc@vger.kernel.org>, kernel list <linux-kernel@vger.kernel.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, Linux-MM <linux-mm@kvack.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="DA6B/QuW";       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::343 as
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

On Fri, 2 Oct 2020 at 07:45, Jann Horn <jannh@google.com> wrote:
>
> On Tue, Sep 29, 2020 at 3:38 PM Marco Elver <elver@google.com> wrote:
> > Add architecture specific implementation details for KFENCE and enable
> > KFENCE for the x86 architecture. In particular, this implements the
> > required interface in <asm/kfence.h> for setting up the pool and
> > providing helper functions for protecting and unprotecting pages.
> >
> > For x86, we need to ensure that the pool uses 4K pages, which is done
> > using the set_memory_4k() helper function.
> [...]
> > diff --git a/arch/x86/include/asm/kfence.h b/arch/x86/include/asm/kfence.h
> [...]
> > +/* Protect the given page and flush TLBs. */
> > +static inline bool kfence_protect_page(unsigned long addr, bool protect)
> > +{
> > +       unsigned int level;
> > +       pte_t *pte = lookup_address(addr, &level);
> > +
> > +       if (!pte || level != PG_LEVEL_4K)
>
> Do we actually expect this to happen, or is this just a "robustness"
> check? If we don't expect this to happen, there should be a WARN_ON()
> around the condition.

It's not obvious here, but we already have this covered with a WARN:
the core.c code has a KFENCE_WARN_ON, which disables KFENCE on a
warning.

> > +               return false;
> > +
> > +       if (protect)
> > +               set_pte(pte, __pte(pte_val(*pte) & ~_PAGE_PRESENT));
> > +       else
> > +               set_pte(pte, __pte(pte_val(*pte) | _PAGE_PRESENT));
>
> Hmm... do we have this helper (instead of using the existing helpers
> for modifying memory permissions) to work around the allocation out of
> the data section?

I just played around with using the set_memory.c functions, to remind
myself why this didn't work. I experimented with using
set_memory_{np,p}() functions; set_memory_p() isn't implemented, but
is easily added (which I did for below experiment). However, this
didn't quite work:

WARNING: CPU: 6 PID: 107 at kernel/smp.c:490
smp_call_function_many_cond+0x9c/0x2a0 kernel/smp.c:490
[...]
Call Trace:
 smp_call_function_many kernel/smp.c:577 [inline]
 smp_call_function kernel/smp.c:599 [inline]
 on_each_cpu+0x3e/0x90 kernel/smp.c:698
 __purge_vmap_area_lazy+0x58/0x670 mm/vmalloc.c:1352
 _vm_unmap_aliases.part.0+0x10b/0x140 mm/vmalloc.c:1770
 change_page_attr_set_clr+0xb4/0x1c0 arch/x86/mm/pat/set_memory.c:1732
 change_page_attr_set arch/x86/mm/pat/set_memory.c:1782 [inline]
 set_memory_p+0x21/0x30 arch/x86/mm/pat/set_memory.c:1950
 kfence_protect_page arch/x86/include/asm/kfence.h:55 [inline]
 kfence_protect_page arch/x86/include/asm/kfence.h:43 [inline]
 kfence_unprotect+0x42/0x70 mm/kfence/core.c:139
 no_context+0x115/0x300 arch/x86/mm/fault.c:705
 handle_page_fault arch/x86/mm/fault.c:1431 [inline]
 exc_page_fault+0xa7/0x170 arch/x86/mm/fault.c:1486
 asm_exc_page_fault+0x1e/0x30 arch/x86/include/asm/idtentry.h:538

For one, smp_call_function_many_cond() doesn't want to be called with
interrupts disabled, and we may very well get a KFENCE allocation or
page fault with interrupts disabled / within interrupts.

Therefore, to be safe, we should avoid IPIs. It follows that setting
the page attribute is best-effort, and we can tolerate some
inaccuracy. Lazy fault handling should take care of faults after we
set the page as PRESENT.

Which hopefully also answers your other comment:

> flush_tlb_one_kernel() -> flush_tlb_one_user() ->
> __flush_tlb_one_user() -> native_flush_tlb_one_user() only flushes on
> the local CPU core, not on others. If you want to leave it this way, I
> think this needs a comment explaining why we're not doing a global
> flush (locking context / performance overhead / ... ?).

We'll add a comment to clarify why it's done this way.

> > +       flush_tlb_one_kernel(addr);
> > +       return true;
> > +}
> > +
> > +#endif /* _ASM_X86_KFENCE_H */
> > diff --git a/arch/x86/mm/fault.c b/arch/x86/mm/fault.c
> [...]
> > @@ -701,6 +702,9 @@ no_context(struct pt_regs *regs, unsigned long error_code,
> >         }
> >  #endif
> >
> > +       if (kfence_handle_page_fault(address))
> > +               return;
> > +
> >         /*
> >          * 32-bit:
> >          *
>
> The standard 5 lines of diff context don't really make it obvious
> what's going on here. Here's a diff with more context:
>
>
>         /*
>          * Stack overflow?  During boot, we can fault near the initial
>          * stack in the direct map, but that's not an overflow -- check
>          * that we're in vmalloc space to avoid this.
>          */
>         if (is_vmalloc_addr((void *)address) &&
>             (((unsigned long)tsk->stack - 1 - address < PAGE_SIZE) ||
>              address - ((unsigned long)tsk->stack + THREAD_SIZE) < PAGE_SIZE)) {
>                 unsigned long stack = __this_cpu_ist_top_va(DF) -
> sizeof(void *);
>                 /*
>                  * We're likely to be running with very little stack space
>                  * left.  It's plausible that we'd hit this condition but
>                  * double-fault even before we get this far, in which case
>                  * we're fine: the double-fault handler will deal with it.
>                  *
>                  * We don't want to make it all the way into the oops code
>                  * and then double-fault, though, because we're likely to
>                  * break the console driver and lose most of the stack dump.
>                  */
>                 asm volatile ("movq %[stack], %%rsp\n\t"
>                               "call handle_stack_overflow\n\t"
>                               "1: jmp 1b"
>                               : ASM_CALL_CONSTRAINT
>                               : "D" ("kernel stack overflow (page fault)"),
>                                 "S" (regs), "d" (address),
>                                 [stack] "rm" (stack));
>                 unreachable();
>         }
>  #endif
>
> +       if (kfence_handle_page_fault(address))
> +               return;
> +
>         /*
>          * 32-bit:
>          *
>          *   Valid to do another page fault here, because if this fault
>          *   had been triggered by is_prefetch fixup_exception would have
>          *   handled it.
>          *
>          * 64-bit:
>          *
>          *   Hall of shame of CPU/BIOS bugs.
>          */
>         if (is_prefetch(regs, error_code, address))
>                 return;
>
>         if (is_errata93(regs, address))
>                 return;
>
>         /*
>          * Buggy firmware could access regions which might page fault, try to
>          * recover from such faults.
>          */
>         if (IS_ENABLED(CONFIG_EFI))
>                 efi_recover_from_page_fault(address);
>
>  oops:
>         /*
>          * Oops. The kernel tried to access some bad page. We'll have to
>          * terminate things with extreme prejudice:
>          */
>         flags = oops_begin();
>
>
>
> Shouldn't kfence_handle_page_fault() happen after prefetch handling,
> at least? Maybe directly above the "oops" label?

Good question. AFAIK it doesn't matter, as is_kfence_address() should
never apply for any of those that follow, right? In any case, it
shouldn't hurt to move it down.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNP6mukCZ931_aW9dDqbkOyv%3Da2zbS7MuEMkE%2Bunb7nYeg%40mail.gmail.com.
