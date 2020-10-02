Return-Path: <kasan-dev+bncBC7OBJGL2MHBBR6C3X5QKGQEO5BWQTI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x440.google.com (mail-wr1-x440.google.com [IPv6:2a00:1450:4864:20::440])
	by mail.lfdr.de (Postfix) with ESMTPS id 1C1D528190C
	for <lists+kasan-dev@lfdr.de>; Fri,  2 Oct 2020 19:20:08 +0200 (CEST)
Received: by mail-wr1-x440.google.com with SMTP id v5sf802160wrr.0
        for <lists+kasan-dev@lfdr.de>; Fri, 02 Oct 2020 10:20:08 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1601659207; cv=pass;
        d=google.com; s=arc-20160816;
        b=dBAYEJZOD4SnwTmBtR1z6ys3SCzhQ8scYiiXqf7lQ/SSVvPHKehM49dRrlVRPz+pgR
         oWCgshC1eD629N9EOa74OrEbucUkRIrvEain4O9rqGyDJL+DzDXiI4pHYwIZjlv8llfW
         SnuxKraB8ouH+lHsRlWVXlQb2GvPDzf8kXhy44B4gyOr20Wd5zMnFBHuzhbaYnFGJupL
         tVoGRh5gs4ID6pPElGqMNmvUQJteQ3ceh8/4Q5UPRhlTQPAvk9rANWgYVX8QEkpHPtKA
         sdl0SoRHSjQWYTV9Kpflt9cRnCDV7DdNhXpnkaaxc/1/g1puVwQaQia1tsu6KrXZP+vL
         a5Jg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=OWNtI/EMqAjTIIX+uQc4Hbr4wq7AMFAHaH7TDiXQXbE=;
        b=FKGuEsLVl9VJvZXoSdcuWusJjSXglL30YDMl3qzg7tr/yIowBpJNB7DG5DhRDOx58c
         dXTdn3r88vfcms8kMLl8NiA6UMSfgUv9YwxlIiBh2lSPB1XP3/A7CBADT17HDel0Fz9A
         81fiVTqdPV9ex+dMCsEmlf00LJkV8Oc7Ia3ZSxrjXW9w88kNQKbkJ6UZWTI+teOZqsHt
         zXwHs1WHibZc9JUDW/pywOFhb7JyrOpuJF994Dla9df2mIyK/D89KwwdltmuZ/m+R17v
         S/AKTlpKnAe1gzLcjRd2P1HQeP4/kNMiUwYnYJs29KrE1mqB3of0Zd3bQWBV8SvmC0oI
         td3g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=TB7iBsky;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::442 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=OWNtI/EMqAjTIIX+uQc4Hbr4wq7AMFAHaH7TDiXQXbE=;
        b=h7pfo/9BuAT1kPvDTxTqMJwNJstDVxybBVNFFRdO78yTBittJusomgCvWEYnZxJ9XJ
         SMAlNtbYOA3mo2RxZU8zHnmaOyDhRdTexKhgGcoqVBaL0r70Xebvd2yQlKx7trUjJUAP
         /OqKxv+WcgCObvg1BEHANc4oXw6pNs1lJdg1TmP5v5vzpp8BjwY8leXfCNmbzuGirLET
         7Xi58+2u37PAHcCU3PP7BnfePocvnuywWL5RqQbPmA6QU09BatfwvQzeR3ihgpiQhCBz
         Fjm6nEvQmcTH2/0kGczXwtZJZ4oOrAQPmmhZ4cKgTs+T0PVMdgcpNplaZHiviSM5GY64
         mZZQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=OWNtI/EMqAjTIIX+uQc4Hbr4wq7AMFAHaH7TDiXQXbE=;
        b=A6atYp4XxlGdYg0lYxBPbNOOFuXdG8/RAZPoob2wgNuPe72Qms9DNczBPkNUmdZS79
         nrn8ZGD1zkOEU4Zm/gHlpeIX93yE3EexVjTuHO2yRHY4FUYi010Uls08dhhUlBzMOh8V
         H1xpOCTq2M3j/cR+6OTRdL8N/8K1LVHa8CniQx3cr6np0BHFnwUU/GsCcs3WYSbrky10
         KDEZAU+hsYwvoAEwLPBQ6npgmSe9KwV9Z6PKbDGj+GCEaoNAeQSFdVU+up2R6ygFAWvc
         P2Ox2xnzkSV4OjO+SkXQG90TMTXuchxEDpmCJqTK6a3eayIR4yuvI3bLiQjRFOtloyul
         LUtA==
X-Gm-Message-State: AOAM532Dr9XIrUmIpdI5YxZqDlhPRKxyWu9UymNmsW0hMcsc+DEjs4Cp
	vcN3ZP2q1jxk4ixpjOh2TVs=
X-Google-Smtp-Source: ABdhPJyDTpG3hTnWSeJebmoLoiGZ1QhJsZH+ekSq6CCyrs4mAHJsyvuAJLXnjvjPeGu0BRGpWjXNJA==
X-Received: by 2002:a5d:6cb1:: with SMTP id a17mr4348825wra.386.1601659207778;
        Fri, 02 Oct 2020 10:20:07 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:9e53:: with SMTP id h80ls1260905wme.1.canary-gmail; Fri,
 02 Oct 2020 10:20:06 -0700 (PDT)
X-Received: by 2002:a1c:b409:: with SMTP id d9mr4210222wmf.106.1601659206792;
        Fri, 02 Oct 2020 10:20:06 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1601659206; cv=none;
        d=google.com; s=arc-20160816;
        b=rwuvsPck9It8NvMl8m5XpFb8oVhzkeQW4QpQBX/yIVTj0SpLjaj+jnx5Gb3DiDlVC1
         AMMsZ394SPO3REr+46cyVGEfFqtOlBxlrPmUTcuLd6pE+O9wav25/FmjiWYP/QNykeyD
         0levn9d2r/OCqfMycPrNde3TVhuUBmnA6KCFH88YKUXTDqXD8KSE5dMSfLGG2OewjaL9
         LEp1YqZv0U/AIYq4FZjeZ9rQBjGPjAdA7Fm+Ia+DDp4fUqx+gCCk7oIx1EuA9KbKKkw8
         CsEH4pO2o8VJLnOY/UhgBpFCsZ0etsXhMTKuVdIj3l22b5dh8Dd+rHD1sD6X2+YYE7vd
         2oNg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=v/hEFFtQ+0xxAg96E+/6Cxc0JK2K443dm/brFX78osE=;
        b=XAX6oqWEWi6cxOMxGR4vsePrTjsNcgfaidcW+NLfhrVyY+uXlg/Lz14nFHuTrPIdAn
         50y/nHXyO/zr37QQaQUI1rpPas5+chZil1eVDWk04zVgUOOSRhJKX+YhYgtKJFKuajlv
         rXsTyDDEZnJD3CTjZeiLXPOHO6JJ5sZDOvD9PLIYQ4N91jVHNLjwpguIf3oXHWji1G9t
         mx2dGAlMisNY7ZW0VCU77posc112K45lMaUwX5XIjsQeKuQjj7/8RaT2raBbANxVFxdo
         PENqFPqFSwlj2hpRl+p6Jg6ccpTeUIklL/48N2eqUp4+/KvyIoFgpOCM5OHyPvdjr41p
         35tg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=TB7iBsky;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::442 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x442.google.com (mail-wr1-x442.google.com. [2a00:1450:4864:20::442])
        by gmr-mx.google.com with ESMTPS id k14si68964wrx.1.2020.10.02.10.20.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 02 Oct 2020 10:20:06 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::442 as permitted sender) client-ip=2a00:1450:4864:20::442;
Received: by mail-wr1-x442.google.com with SMTP id g4so2629447wrs.5
        for <kasan-dev@googlegroups.com>; Fri, 02 Oct 2020 10:20:06 -0700 (PDT)
X-Received: by 2002:adf:fed1:: with SMTP id q17mr4073978wrs.85.1601659206022;
        Fri, 02 Oct 2020 10:20:06 -0700 (PDT)
Received: from elver.google.com ([100.105.32.75])
        by smtp.gmail.com with ESMTPSA id f14sm2634897wme.22.2020.10.02.10.20.04
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 02 Oct 2020 10:20:05 -0700 (PDT)
Date: Fri, 2 Oct 2020 19:19:59 +0200
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: Jann Horn <jannh@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>,
	Alexander Potapenko <glider@google.com>,
	"H . Peter Anvin" <hpa@zytor.com>,
	"Paul E . McKenney" <paulmck@kernel.org>,
	Andrey Konovalov <andreyknvl@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Andy Lutomirski <luto@kernel.org>, Borislav Petkov <bp@alien8.de>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Christoph Lameter <cl@linux.com>,
	Dave Hansen <dave.hansen@linux.intel.com>,
	David Rientjes <rientjes@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Eric Dumazet <edumazet@google.com>,
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
	Hillf Danton <hdanton@sina.com>, Ingo Molnar <mingo@redhat.com>,
	Jonathan.Cameron@huawei.com, Jonathan Corbet <corbet@lwn.net>,
	Joonsoo Kim <iamjoonsoo.kim@lge.com>,
	Kees Cook <keescook@chromium.org>,
	Mark Rutland <mark.rutland@arm.com>,
	Pekka Enberg <penberg@kernel.org>,
	Peter Zijlstra <peterz@infradead.org>, sjpark@amazon.com,
	Thomas Gleixner <tglx@linutronix.de>,
	Vlastimil Babka <vbabka@suse.cz>, Will Deacon <will@kernel.org>,
	"the arch/x86 maintainers" <x86@kernel.org>,
	linux-doc@vger.kernel.org,
	kernel list <linux-kernel@vger.kernel.org>,
	kasan-dev <kasan-dev@googlegroups.com>,
	Linux ARM <linux-arm-kernel@lists.infradead.org>,
	Linux-MM <linux-mm@kvack.org>, SeongJae Park <sjpark@amazon.de>
Subject: Re: [PATCH v4 01/11] mm: add Kernel Electric-Fence infrastructure
Message-ID: <20201002171959.GA986344@elver.google.com>
References: <20200929133814.2834621-1-elver@google.com>
 <20200929133814.2834621-2-elver@google.com>
 <CAG48ez3+_K6YXoXgKBkB8AMeSQj++Mxi5u2OT--B+mJgE7Cyfg@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CAG48ez3+_K6YXoXgKBkB8AMeSQj++Mxi5u2OT--B+mJgE7Cyfg@mail.gmail.com>
User-Agent: Mutt/1.14.5 (2020-06-23)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=TB7iBsky;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::442 as
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

Hi Jann,

Thanks for your comments!!

On Fri, Oct 02, 2020 at 08:33AM +0200, Jann Horn wrote:
> On Tue, Sep 29, 2020 at 3:38 PM Marco Elver <elver@google.com> wrote:
> > This adds the Kernel Electric-Fence (KFENCE) infrastructure. KFENCE is a
> > low-overhead sampling-based memory safety error detector of heap
> > use-after-free, invalid-free, and out-of-bounds access errors.
> >
> > KFENCE is designed to be enabled in production kernels, and has near
> > zero performance overhead. Compared to KASAN, KFENCE trades performance
> > for precision. The main motivation behind KFENCE's design, is that with
> > enough total uptime KFENCE will detect bugs in code paths not typically
> > exercised by non-production test workloads. One way to quickly achieve a
> > large enough total uptime is when the tool is deployed across a large
> > fleet of machines.
> >
> > KFENCE objects each reside on a dedicated page, at either the left or
> > right page boundaries.
> 
> (modulo slab alignment)

There are a bunch more details missing; this is just a high-level
summary. Because as soon as we mention "modulo slab alignment" one may
wonder about missed OOBs, which we solve with redzones. We should not
replicate Documentation/dev-tools/kfence.rst; we do refer to it instead.
;-)

> > The pages to the left and right of the object
> > page are "guard pages", whose attributes are changed to a protected
> > state, and cause page faults on any attempted access to them. Such page
> > faults are then intercepted by KFENCE, which handles the fault
> > gracefully by reporting a memory access error. To detect out-of-bounds
> > writes to memory within the object's page itself, KFENCE also uses
> > pattern-based redzones. The following figure illustrates the page
> > layout:
> [...]
> > diff --git a/include/linux/kfence.h b/include/linux/kfence.h
> [...]
> > +/**
> > + * is_kfence_address() - check if an address belongs to KFENCE pool
> > + * @addr: address to check
> > + *
> > + * Return: true or false depending on whether the address is within the KFENCE
> > + * object range.
> > + *
> > + * KFENCE objects live in a separate page range and are not to be intermixed
> > + * with regular heap objects (e.g. KFENCE objects must never be added to the
> > + * allocator freelists). Failing to do so may and will result in heap
> > + * corruptions, therefore is_kfence_address() must be used to check whether
> > + * an object requires specific handling.
> > + */
> > +static __always_inline bool is_kfence_address(const void *addr)
> > +{
> > +       return unlikely((char *)addr >= __kfence_pool &&
> > +                       (char *)addr < __kfence_pool + KFENCE_POOL_SIZE);
> > +}
> 
> If !CONFIG_HAVE_ARCH_KFENCE_STATIC_POOL, this should probably always
> return false if __kfence_pool is NULL, right?

That's another check; we don't want to make this more expensive.

This should never receive a NULL, given the places it's used from, which
should only be allocator internals where we already know we have a
non-NULL object. If it did receive a NULL, I think something else is
wrong. Or did we miss a place where it can legally receive a NULL?

> [...]
> > diff --git a/lib/Kconfig.kfence b/lib/Kconfig.kfence
> [...]
> > +menuconfig KFENCE
> > +       bool "KFENCE: low-overhead sampling-based memory safety error detector"
> > +       depends on HAVE_ARCH_KFENCE && !KASAN && (SLAB || SLUB)
> > +       depends on JUMP_LABEL # To ensure performance, require jump labels
> > +       select STACKTRACE
> > +       help
> > +         KFENCE is low-overhead sampling-based detector for heap out-of-bounds
> 
> nit: "is a"

Done.

> > +         access, use-after-free, and invalid-free errors. KFENCE is designed
> > +         to have negligible cost to permit enabling it in production
> > +         environments.
> [...]
> > diff --git a/mm/kfence/core.c b/mm/kfence/core.c
> [...]
> > +module_param_named(sample_interval, kfence_sample_interval, ulong, 0600);
> 
> This is a writable module parameter, but if the sample interval was 0
> or a very large value, changing this value at runtime won't actually
> change the effective interval because the work item will never get
> kicked off again, right?

When KFENCE has been enabled, setting this to 0 actually reschedules the
work immediately; we do not disable KFENCE once it has been enabled.

Conversely, if KFENCE has been disabled at boot (this param is 0),
changing this to anything else will not enable KFENCE.

This simplifies a lot of things, in particular, if KFENCE was disabled
we do not want to run initialization code and also do not want to kick
off KFENCE initialization code were we to allow dynamically turning
KFENCE on/off (it complicates a bunch of things, e.g. the various
arch-specific initialization would need to be able to deal with all
this).

> Should this maybe use module_param_cb() instead, with a "set" callback
> that not only changes the value, but also schedules the work item?

Whether or not we want to reschedule the work if the value was changed
from a huge value to a smaller one is another question. Probably...
we'll consider it.

> [...]
> > +/*
> > + * The pool of pages used for guard pages and objects. If supported, allocated
> > + * statically, so that is_kfence_address() avoids a pointer load, and simply
> > + * compares against a constant address. Assume that if KFENCE is compiled into
> > + * the kernel, it is usually enabled, and the space is to be allocated one way
> > + * or another.
> > + */
> 
> If this actually brings a performance win, the proper way to do this
> would probably be to implement this as generic kernel infrastructure
> that makes the compiler emit large-offset relocations (either through
> compiler support or using inline asm statements that move an immediate
> into a register output and register the location in a special section,
> kinda like how e.g. static keys work) and patches them at boot time,
> or something like that - there are other places in the kernel where
> very hot code uses global pointers that are only ever written once
> during boot, e.g. the dentry cache of the VFS and the futex hash
> table. Those are probably far hotter than the kfence code.
> 
> While I understand that that goes beyond the scope of this project, it
> might be something to work on going forward - this kind of
> special-case logic that turns the kernel data section into heap memory
> would not be needed if we had that kind of infrastructure.
> 
> > +#ifdef CONFIG_HAVE_ARCH_KFENCE_STATIC_POOL
> > +char __kfence_pool[KFENCE_POOL_SIZE] __kfence_pool_attrs;
> > +#else
> > +char *__kfence_pool __read_mostly;
> 
> not __ro_after_init ?

Changed, thanks.

> > +#endif
> [...]
> > +/* Freelist with available objects. */
> > +static struct list_head kfence_freelist = LIST_HEAD_INIT(kfence_freelist);
> > +static DEFINE_RAW_SPINLOCK(kfence_freelist_lock); /* Lock protecting freelist. */
> [...]
> > +/* Gates the allocation, ensuring only one succeeds in a given period. */
> > +static atomic_t allocation_gate = ATOMIC_INIT(1);
> 
> I don't think you need to initialize this to anything?
> toggle_allocation_gate() will set it to zero before enabling the
> static key, so I don't think anyone will ever see this value.

Sure. But does it hurt anyone? At least this way we don't need to think
about yet another state that only exists on initialization; who knows
what we'll change in future.

> [...]
> > +/* Check canary byte at @addr. */
> > +static inline bool check_canary_byte(u8 *addr)
> > +{
> > +       if (*addr == KFENCE_CANARY_PATTERN(addr))
> 
> You could maybe add a likely() hint here if you want.

Added; but none of this is in a hot path.

> > +               return true;
> > +
> > +       atomic_long_inc(&counters[KFENCE_COUNTER_BUGS]);
> > +       kfence_report_error((unsigned long)addr, addr_to_metadata((unsigned long)addr),
> > +                           KFENCE_ERROR_CORRUPTION);
> > +       return false;
> > +}
> > +
> > +static inline void for_each_canary(const struct kfence_metadata *meta, bool (*fn)(u8 *))
> 
> Given how horrendously slow this would be if the compiler decided to
> disregard the "inline" hint and did an indirect call for every byte,
> you may want to use __always_inline here.

Done.

> > +{
> > +       unsigned long addr;
> > +
> > +       lockdep_assert_held(&meta->lock);
> > +
> > +       for (addr = ALIGN_DOWN(meta->addr, PAGE_SIZE); addr < meta->addr; addr++) {
> > +               if (!fn((u8 *)addr))
> > +                       break;
> > +       }
> > +
> > +       for (addr = meta->addr + meta->size; addr < PAGE_ALIGN(meta->addr); addr++) {
> 
> Hmm... if the object is on the left side (meaning meta->addr is
> page-aligned) and the padding is on the right side, won't
> PAGE_ALIGN(meta->addr)==meta->addr , and therefore none of the padding
> will be checked?

No, you're thinking of ALIGN_DOWN. PAGE_ALIGN gives us the next page.

> > +               if (!fn((u8 *)addr))
> > +                       break;
> > +       }
> > +}
> > +
> > +static void *kfence_guarded_alloc(struct kmem_cache *cache, size_t size, gfp_t gfp)
> > +{
> > +       struct kfence_metadata *meta = NULL;
> > +       unsigned long flags;
> > +       void *addr;
> > +
> > +       /* Try to obtain a free object. */
> > +       raw_spin_lock_irqsave(&kfence_freelist_lock, flags);
> > +       if (!list_empty(&kfence_freelist)) {
> > +               meta = list_entry(kfence_freelist.next, struct kfence_metadata, list);
> > +               list_del_init(&meta->list);
> > +       }
> > +       raw_spin_unlock_irqrestore(&kfence_freelist_lock, flags);
> > +       if (!meta)
> > +               return NULL;
> 
> Should this use pr_warn_once(), or something like that, to inform the
> user that kfence might be stuck with all allocations used by
> long-living objects and therefore no longer doing anything?

I don't think so; it might as well recover, and seeing this message once
is no indication that we're stuck. Instead, we should (and plan to)
monitor /sys/kernel/debug/kfence/stats.

> [...]
> > +}
> [...]
> > +/* === Allocation Gate Timer ================================================ */
> > +
> > +/*
> > + * Set up delayed work, which will enable and disable the static key. We need to
> > + * use a work queue (rather than a simple timer), since enabling and disabling a
> > + * static key cannot be done from an interrupt.
> > + */
> > +static struct delayed_work kfence_timer;
> > +static void toggle_allocation_gate(struct work_struct *work)
> > +{
> > +       if (!READ_ONCE(kfence_enabled))
> > +               return;
> > +
> > +       /* Enable static key, and await allocation to happen. */
> > +       atomic_set(&allocation_gate, 0);
> > +       static_branch_enable(&kfence_allocation_key);
> > +       wait_event(allocation_wait, atomic_read(&allocation_gate) != 0);
> > +
> > +       /* Disable static key and reset timer. */
> > +       static_branch_disable(&kfence_allocation_key);
> > +       schedule_delayed_work(&kfence_timer, msecs_to_jiffies(kfence_sample_interval));
> 
> We end up doing two IPIs to all CPU cores for each kfence allocation
> because of those static branch calls, right? Might be worth adding a
> comment to point that out, or something like that. (And if it ends up
> being a problem in the future, we could probably get away with using
> some variant that avoids the IPI, but flushes the instruction pipeline
> if we observe the allocation_gate being nonzero, or something like
> that. At the cost of not immediately capturing new allocations if the
> relevant instructions are cached. But the current version is
> definitely fine for an initial implementation, and for now, you should
> probably *not* implement what I just described.)

Thanks, yeah, this is a good point, and I wondered if we could optimize
this along these lines. We'll add a comment. Maybe somebody wants to
optimize this in future. :-)

> > +}
> > +static DECLARE_DELAYED_WORK(kfence_timer, toggle_allocation_gate);
> > +
> > +/* === Public interface ===================================================== */
> > +
> > +void __init kfence_init(void)
> > +{
> > +       /* Setting kfence_sample_interval to 0 on boot disables KFENCE. */
> > +       if (!kfence_sample_interval)
> > +               return;
> > +
> > +       if (!kfence_initialize_pool()) {
> > +               pr_err("%s failed\n", __func__);
> > +               return;
> > +       }
> > +
> > +       WRITE_ONCE(kfence_enabled, true);
> > +       schedule_delayed_work(&kfence_timer, 0);
> 
> This is schedule_work(&kfence_timer).

No, schedule_work() is not generic and does not take a struct delayed_work.

> [...]
> > +}
> [...]
> > diff --git a/mm/kfence/kfence.h b/mm/kfence/kfence.h
> [...]
> > +/* KFENCE metadata per guarded allocation. */
> > +struct kfence_metadata {
> [...]
> > +       /*
> > +        * In case of an invalid access, the page that was unprotected; we
> > +        * optimistically only store address.
> 
> Is this supposed to say something like "only store one address"?

Done.

> > +        */
> > +       unsigned long unprotected_page;
> > +};
> [...]
> > +#endif /* MM_KFENCE_KFENCE_H */
> > diff --git a/mm/kfence/report.c b/mm/kfence/report.c
> [...]
> > +void kfence_report_error(unsigned long address, const struct kfence_metadata *meta,
> > +                        enum kfence_error_type type)
> > +{
> [...]
> > +       pr_err("==================================================================\n");
> > +       /* Print report header. */
> > +       switch (type) {
> [...]
> > +       case KFENCE_ERROR_INVALID_FREE:
> > +               pr_err("BUG: KFENCE: invalid free in %pS\n\n", (void *)stack_entries[skipnr]);
> > +               pr_err("Invalid free of 0x" PTR_FMT " (in kfence-#%zd):\n", (void *)address,
> > +                      object_index);
> > +               break;
> > +       }
> > +
> > +       /* Print stack trace and object info. */
> > +       stack_trace_print(stack_entries + skipnr, num_stack_entries - skipnr, 0);
> > +
> > +       if (meta) {
> > +               pr_err("\n");
> > +               kfence_print_object(NULL, meta);
> > +       }
> > +
> > +       /* Print report footer. */
> > +       pr_err("\n");
> > +       dump_stack_print_info(KERN_DEFAULT);
> 
> Shouldn't this be KERN_ERR, to keep the loglevel consistent with the
> previous messages?

Done.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201002171959.GA986344%40elver.google.com.
