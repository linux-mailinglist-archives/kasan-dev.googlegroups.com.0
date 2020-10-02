Return-Path: <kasan-dev+bncBC7OBJGL2MHBBONP335QKGQEMHTILPA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13e.google.com (mail-lf1-x13e.google.com [IPv6:2a00:1450:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id 52D42281D75
	for <lists+kasan-dev@lfdr.de>; Fri,  2 Oct 2020 23:12:26 +0200 (CEST)
Received: by mail-lf1-x13e.google.com with SMTP id y9sf1062944lfe.17
        for <lists+kasan-dev@lfdr.de>; Fri, 02 Oct 2020 14:12:26 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1601673146; cv=pass;
        d=google.com; s=arc-20160816;
        b=awLy1sSph4rC96D4z5oneUOhDrzPs45PHYwTuXpMAkbgCNuEkl2pGFT5fTrLLK8y0u
         5jc3YAadbDhoUzoseLHpXF4FdVILDj8Kt/IQ/Ll+vnVOkE9Nd6sX2IUwF2+/0D1cG83X
         pH2uZ8s6wXqAsx+XzQ39OSKedn5xHknFyHGjkWRi47Omw9ZZWFhOkh6f3lMOcyYLKFCJ
         zhpiVEC1ryM98H7wBRtSbvGs8ANm5bp/UFi19ctlZg/rde0ulR06KBgm4/HX6eqd2yzr
         LSwt1KNMUgbVHTr4TzMn0Qo84FIy0WE85mTk6GRSuA1glO1BXQfZjvOQgmc2HqCas9vz
         195w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=uoQ3xIxNIBAexzPJW8kQAOXbq2C9gvIIo0dtAixwiI0=;
        b=0w7vMkxCTNBOX33B0U4uswTfOe576JPDJ22Pnq5ZaPox+k//At8ChvwcwEcbHrxauN
         qmddChc/HLaaqWjko3n2eFISsvHH3aar1kEX0TA/xyaZxl2a2FZ4hD4Xhu/VW4+g42DP
         uq6CSM8r8KZkOAAXtmMFlMT4Pw5Dbs6P2+0HdWy6KC7pIkPfxdmcjiIWT4PK+jqNNKMX
         87EnR05huI85plGUUswvS/60zuP4wePlnznGcC9Lo78FCjZpZn8Ld9RwTryExUgE/C9s
         cSa/tk3SXimymta8MSe+GcNj/8lENPWT2zNTMhvNsQIqb85pnVelZUZd2Tif7tfF5lvL
         cfHA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=H6RsUyuM;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::442 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=uoQ3xIxNIBAexzPJW8kQAOXbq2C9gvIIo0dtAixwiI0=;
        b=fnLytqVuvoON8mK05TWkW9/kvlinPYvY6m30lm9fvFJMxB4fTknED3w8WqUoViq5Fv
         NoM+jCmiO1253Y7y9HrxEmzZNwXWY66HrAPzleB806lmUa3CCKBfpc3/88ZFu0LX0JiY
         gFSmw5XcOfuj4dQsm0bFvid15tRAXSxxWm6y1U53z5rXBitFYA/sx2b1bl0kw1i9rez+
         ZdTOCm7lRHGYEKZ1Z5kAshSvUyDMviOl3dMzkDjRoTdGy8Xa83tQD0Y1KbdmlF6wvqwj
         IVUI2xPdx+9kABYuoKO3573eoVs/A7vYDO4h/AvM086O3Xs+rjj+lAjeXjXq+R+V48eJ
         cITA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=uoQ3xIxNIBAexzPJW8kQAOXbq2C9gvIIo0dtAixwiI0=;
        b=V3aUjkCQvgxZDN+r8AUhYWgRAfZGf6S4kB7oDfeBYc5bq5QgjI/FGOkbrFOL8P+TrI
         9RbEr513fB0giyy2qz6Boeyp+I8mYQiV79MfyO5UX6A66DAnRSanMt/WdBebtqjDZwJY
         kL8MHQrLcngnXsxgUBqHudew2/lJjwolf/5BhlNPOSN7ActgD/EyTXLMqP9fhpOdkPfK
         1mj26aCs1DsuvbxAIcMpdomCVbU3pU3JGgcdXWKxMQCzh5Lam5G/9+FKu6fltmXjHMZ4
         CINcBla2Y6latkneU0ItBLHUbGEO4+duMyjNRCFVb0gj7AUnjgyXP0ijspzL3oGGYl2y
         LwTA==
X-Gm-Message-State: AOAM532GK3YIYN5NS7TX2E5LgsFgsG8TsvAhCUvHocwkiC7bOoCk7D7D
	OjrfOk3gWnmamLP9K9idtOM=
X-Google-Smtp-Source: ABdhPJzf7i9OoAd7IYUZT9pmUDTouoqQjQzyvvDv4rVX5Y/4mo15yriLccKC4DP3M8RicXfMs8qb1A==
X-Received: by 2002:a2e:9aca:: with SMTP id p10mr1268451ljj.237.1601673145742;
        Fri, 02 Oct 2020 14:12:25 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:93:: with SMTP id 19ls385150ljq.4.gmail; Fri, 02
 Oct 2020 14:12:24 -0700 (PDT)
X-Received: by 2002:a2e:7e0f:: with SMTP id z15mr1105460ljc.117.1601673144478;
        Fri, 02 Oct 2020 14:12:24 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1601673144; cv=none;
        d=google.com; s=arc-20160816;
        b=LHXXjd1jrSgzFrEEdhed+macwGnFl1uFOqw3MHxd7O2HBQe5vFY4zGE64LAifUqGX3
         sQoX2ZFqWCd1WReMDwZucANDCi0zglFADZKZ2WApPb2AjExzFwt7YEmZl+mcbDWCToog
         mmDMG51NumuN3ws1CHGdhRuz80lmgIcKevUFdrESBMPoLCP2+tuShL7/W0zEVff7N6+p
         67yxWtULn7gSHO0cizaa0Nz/ignl7fgvxFETP5oyE0L23JJ71ErAi75QowKi2RP4LVpS
         G838fE5eW04jCcitJVZeqTU4/FE5xNRYFNG+HP8uW18sDXh+hYJ0zHJTXJ4Cq+yWXN7v
         /DnA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=VgFFQ0f1iW52kXzjz/2eKYH+NB9j2SKHy/BefzscIIA=;
        b=DHBg3d+yxZ/SAjmFAUtYzfetdpOka2IV+K0DMkRN0JfMLR5087bWHuV8kzYRj5It+h
         qqshPJgmFcvpnAkkrRO9d0uEHXyuJbgK9iNWY4vZGP/PIiZoCWSsb0orHQMnhMZ1rSis
         /wVV279V0bnLcQe1Beh7s+8Co3UA51RXQXkydQ/5mi7X02osK/kCgQixSS/cQflIROZr
         0MCNaCzQ6Ii9tEwuun/wbUR3HQ0KG58j/y8V/4shgW+PthmsLBugXJWxQcV2LfWQJ8Ny
         0u6VQ/bBd2HCJkILlH9Nm3egelhMzCG4QqYS8c/UlreO///veu8MTd+ZuAsP/XoqEaap
         XdyA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=H6RsUyuM;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::442 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x442.google.com (mail-wr1-x442.google.com. [2a00:1450:4864:20::442])
        by gmr-mx.google.com with ESMTPS id d1si91254lfa.11.2020.10.02.14.12.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 02 Oct 2020 14:12:24 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::442 as permitted sender) client-ip=2a00:1450:4864:20::442;
Received: by mail-wr1-x442.google.com with SMTP id t10so3221702wrv.1
        for <kasan-dev@googlegroups.com>; Fri, 02 Oct 2020 14:12:24 -0700 (PDT)
X-Received: by 2002:adf:d4c1:: with SMTP id w1mr5049675wrk.108.1601673143625;
        Fri, 02 Oct 2020 14:12:23 -0700 (PDT)
Received: from elver.google.com ([100.105.32.75])
        by smtp.gmail.com with ESMTPSA id m10sm3051130wmc.9.2020.10.02.14.12.22
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 02 Oct 2020 14:12:22 -0700 (PDT)
Date: Fri, 2 Oct 2020 23:12:16 +0200
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
	Jonathan Cameron <Jonathan.Cameron@huawei.com>,
	Jonathan Corbet <corbet@lwn.net>,
	Joonsoo Kim <iamjoonsoo.kim@lge.com>,
	Kees Cook <keescook@chromium.org>,
	Mark Rutland <mark.rutland@arm.com>,
	Pekka Enberg <penberg@kernel.org>,
	Peter Zijlstra <peterz@infradead.org>,
	SeongJae Park <sjpark@amazon.com>,
	Thomas Gleixner <tglx@linutronix.de>,
	Vlastimil Babka <vbabka@suse.cz>, Will Deacon <will@kernel.org>,
	"the arch/x86 maintainers" <x86@kernel.org>,
	"open list:DOCUMENTATION" <linux-doc@vger.kernel.org>,
	kernel list <linux-kernel@vger.kernel.org>,
	kasan-dev <kasan-dev@googlegroups.com>,
	Linux ARM <linux-arm-kernel@lists.infradead.org>,
	Linux-MM <linux-mm@kvack.org>, SeongJae Park <sjpark@amazon.de>
Subject: Re: [PATCH v4 01/11] mm: add Kernel Electric-Fence infrastructure
Message-ID: <20201002211216.GA1108095@elver.google.com>
References: <20200929133814.2834621-1-elver@google.com>
 <20200929133814.2834621-2-elver@google.com>
 <CAG48ez3+_K6YXoXgKBkB8AMeSQj++Mxi5u2OT--B+mJgE7Cyfg@mail.gmail.com>
 <20201002171959.GA986344@elver.google.com>
 <CAG48ez0D1+hStZaDOigwbqNqFHJAJtXK+8Nadeuiu1Byv+xp5A@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CAG48ez0D1+hStZaDOigwbqNqFHJAJtXK+8Nadeuiu1Byv+xp5A@mail.gmail.com>
User-Agent: Mutt/1.14.5 (2020-06-23)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=H6RsUyuM;       spf=pass
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

On Fri, Oct 02, 2020 at 09:31PM +0200, Jann Horn wrote:
[...]
> > >
> > > If !CONFIG_HAVE_ARCH_KFENCE_STATIC_POOL, this should probably always
> > > return false if __kfence_pool is NULL, right?
> >
> > That's another check; we don't want to make this more expensive.
> 
> Ah, right, I missed that this is the one piece of KFENCE that is
> actually really hot code until Dmitry pointed that out.
> 
> But actually, can't you reduce how hot this is for SLUB by moving
> is_kfence_address() down into the freeing slowpath? At the moment you
> use it in slab_free_freelist_hook(), which is in the super-hot
> fastpath, but you should be able to at least move it down into
> __slab_free()...
> 
> Actually, you already have hooked into __slab_free(), so can't you
> just get rid of the check in the slab_free_freelist_hook()?
> 
> Also, you could do the NULL *after* the range check said "true". That
> way the NULL check would be on the slowpath and have basically no
> performance impact.

True; let's try to do that then, and hope the few extra instructions do
not hurt us.

> > This should never receive a NULL, given the places it's used from, which
> > should only be allocator internals where we already know we have a
> > non-NULL object. If it did receive a NULL, I think something else is
> > wrong. Or did we miss a place where it can legally receive a NULL?
> 
> Well... not exactly "legally", but e.g. a kernel NULL deref (landing
> in kfence_handle_page_fault()) might get weird.
> 
> [...]
> > > > +         access, use-after-free, and invalid-free errors. KFENCE is designed
> > > > +         to have negligible cost to permit enabling it in production
> > > > +         environments.
> > > [...]
> > > > diff --git a/mm/kfence/core.c b/mm/kfence/core.c
> > > [...]
> > > > +module_param_named(sample_interval, kfence_sample_interval, ulong, 0600);
> > >
> > > This is a writable module parameter, but if the sample interval was 0
> > > or a very large value, changing this value at runtime won't actually
> > > change the effective interval because the work item will never get
> > > kicked off again, right?
> >
> > When KFENCE has been enabled, setting this to 0 actually reschedules the
> > work immediately; we do not disable KFENCE once it has been enabled.
> 
> Those are weird semantics. One value should IMO unambiguously mean one
> thing, independent of when it was set. In particular, I think that if
> someone decides to read the current value of kfence_sample_interval
> through sysfs, and sees the value "0", that should not ambiguously
> mean "either kfence triggers all the time or it is completely off".
> 
> If you don't want to support runtime disabling, can you maybe make the
> handler refuse to write 0 if kfence has already been initialized?

I could live with 0 being rejected; will change it. (I personally had
used piping 0 at runtime to stress test, but perhaps if it's only devs
doing it we can just change the code for debugging/testing.)

> [...]
> > > > +#endif
> > > [...]
> > > > +/* Freelist with available objects. */
> > > > +static struct list_head kfence_freelist = LIST_HEAD_INIT(kfence_freelist);
> > > > +static DEFINE_RAW_SPINLOCK(kfence_freelist_lock); /* Lock protecting freelist. */
> > > [...]
> > > > +/* Gates the allocation, ensuring only one succeeds in a given period. */
> > > > +static atomic_t allocation_gate = ATOMIC_INIT(1);
> > >
> > > I don't think you need to initialize this to anything?
> > > toggle_allocation_gate() will set it to zero before enabling the
> > > static key, so I don't think anyone will ever see this value.
> >
> > Sure. But does it hurt anyone? At least this way we don't need to think
> > about yet another state that only exists on initialization; who knows
> > what we'll change in future.
> 
> Well, no, it doesn't hurt. But I see this as equivalent to writing code like:
> 
> int ret = 0;
> ret = -EINVAL;
> if (...)
>   return ret;
> 
> where a write can never have any effect because a second write will
> clobber the value before it can be read, which is IMO an antipattern.

Agree fully ^

Just being defensive with global states that can potentially be read for
other purposes before toggle_allocation_gate(); I think elsewhere you
e.g. suggested to use allocation_gate for the IPI optimization. It's
these types of changes that depend on our global states, where making
the initial state non-special just saves us trouble.

> But it admittedly is less clear here, so if you like it better your
> way, I don't really have a problem with that.
[...]
> [...]
> > > > +{
> > > > +       unsigned long addr;
> > > > +
> > > > +       lockdep_assert_held(&meta->lock);
> > > > +
> > > > +       for (addr = ALIGN_DOWN(meta->addr, PAGE_SIZE); addr < meta->addr; addr++) {
> > > > +               if (!fn((u8 *)addr))
> > > > +                       break;
> > > > +       }
> > > > +
> > > > +       for (addr = meta->addr + meta->size; addr < PAGE_ALIGN(meta->addr); addr++) {
> > >
> > > Hmm... if the object is on the left side (meaning meta->addr is
> > > page-aligned) and the padding is on the right side, won't
> > > PAGE_ALIGN(meta->addr)==meta->addr , and therefore none of the padding
> > > will be checked?
> >
> > No, you're thinking of ALIGN_DOWN. PAGE_ALIGN gives us the next page.
> 
> Hm, really? Let me go through those macros...
> 
> 
> #define __AC(X,Y) (X##Y)
> #define _AC(X,Y) __AC(X,Y)
> #define PAGE_SHIFT 12
> #define PAGE_SIZE (_AC(1,UL) << PAGE_SHIFT)
> 
> so:
> PAGE_SIZE == (1UL << 12) == 0x1000UL
> 
> #define __ALIGN_KERNEL_MASK(x, mask) (((x) + (mask)) & ~(mask))
> #define __ALIGN_KERNEL(x, a) __ALIGN_KERNEL_MASK(x, (typeof(x))(a) - 1)
> #define ALIGN(x, a) __ALIGN_KERNEL((x), (a))
> 
> so (omitting casts):
> ALIGN(x, a) == ((x + (a - 1)) & ~(a - 1))
> 
> #define PAGE_ALIGN(addr) ALIGN(addr, PAGE_SIZE)
> 
> so (omitting casts):
> PAGE_ALIGN(addr) == ((addr + (0x1000UL - 1)) & ~(0x1000UL - 1))
>   == ((addr + 0xfffUL) & 0xfffffffffffff000UL)
> 
> meaning that if we e.g. pass in 0x5000, we get:
> 
> PAGE_ALIGN(0x5000) == ((0x5000 + 0xfffUL) & 0xfffffffffffff000UL)
>  == 0x5fffUL & 0xfffffffffffff000UL == 0x5000UL
> 
> So if the object is on the left side (meaning meta->addr is
> page-aligned), we won't check padding.
> 
> 
> ALIGN_DOWN rounds down, while PAGE_ALIGN rounds up, but both leave the
> value as-is if it is already page-aligned.

Ah, yes, sorry about that; I confused myself with the comment above PAGE_ALIGN.

We'll fix this. And add a test. :-)

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201002211216.GA1108095%40elver.google.com.
