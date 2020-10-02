Return-Path: <kasan-dev+bncBCQ2XPNX7EOBBPUA335QKGQEVHEXZAI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x137.google.com (mail-lf1-x137.google.com [IPv6:2a00:1450:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id BAA75281C0E
	for <lists+kasan-dev@lfdr.de>; Fri,  2 Oct 2020 21:32:15 +0200 (CEST)
Received: by mail-lf1-x137.google.com with SMTP id 1sf962571lfq.18
        for <lists+kasan-dev@lfdr.de>; Fri, 02 Oct 2020 12:32:15 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1601667135; cv=pass;
        d=google.com; s=arc-20160816;
        b=B2ZgXc8YuFGty6jycgUNrICd5XLe6m85RV+J0dHTj1jnebNOyS7xfkLWL2x0t0kNbK
         8Wzbl/iP6pb0jY6w82lRcjZyeReqq/2Ta0UTMwQUI0zM0eRIyWu7PcviiCr6Mpc/xWMI
         MNnXTKUBaJLhbkDwlj8nKp8sAUjlzIj7R3F4/sre35ojt7iY4dLugFPbZlhUr7voEGhF
         6F1xpQ8XE6nkKt2gvJCv8kmAWSdxrw1LWckoFdmEWMSn3xViV8UY5m4zjf3iotsApL+c
         q+cSrTjFrB5oKi2lPCveSguYlYDmPWy/E+GxTIvLmO6UefipnJs1yE3vOUU4Ls9tP8TF
         ry6w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=jBqesrFf9DC7HwaAEW3oDvrp0EwR+GoPmgcRsvLqfrY=;
        b=bx3Us7WN7uXp9rllfEjfI7PpVz1z6xDZF+Vo+T5YK+ZlRCxXxVRJ15JP0SdBVk+NMk
         oGqrWUcWbQNkEflqVZ2aiG/T5x5PAsTx1TcNbfKR2S9zOTK+p6l3S3+SJh58I/LlhY6x
         zkytZQ/uLBp4+Jj20M4iEVObZdDEVY9Hbl69XWWxW1Sy5jNc8t6M0ffZUS0DTzxF0bSL
         YXM+xlV4dEka4iQXfxRNUYd/bNzuDbSTIBTjuInLn4M+tetQWXzH/UN6ZoTk44EyKSn+
         Ml+AVPxYnKvzPC9ZkEaB0Ge2dXX+1Az64ox8D1oN3gCxcOhqo+w8adV/oD5VD5orCumZ
         QaNA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=uJ8KWfv+;
       spf=pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::542 as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=jBqesrFf9DC7HwaAEW3oDvrp0EwR+GoPmgcRsvLqfrY=;
        b=Sbv3VVAiRBjvOz6f9J+woW8bMFUvRiPAWrjuhYLPmbt1id0h59xXVzRiFGGWY5rsQs
         LdBwYkVETBoZ13XSgVQjiewa7dtWcLUbjfEEEbSCDhMMRj4di3sQN+SQI3Ml4MzQ0iAC
         iyP3kOKHMF77bSL6B2P+qNUTkUHMBoDDNCUUH5dnRKPr9J9wcGTHYGGTAsUrTzWbjvMu
         3zUos1xT241W+SxFYxCXEz6fE7gBmT51ZJGefYeIjoz+EYC0gHOAZUBAJ71XImxxupSL
         kFGQZ3Iadwr3Dfc2pgbEBLOSB4fpSizqGgOAUab5UImJw/4PjWDef30edyI1ONMQl/cX
         mZWQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=jBqesrFf9DC7HwaAEW3oDvrp0EwR+GoPmgcRsvLqfrY=;
        b=kvRk0vNViTEmMA7YHmQxdPOM8V9scYQoRw51c2orYlkEr8EnUPcmMzOeS1+ZQzZ7iN
         Ay8XtAvhlj07Ptxqz3w1aJRf+dLUnPz+cUfmAh2AwCQlTfIa1Dg45OLKPOhozhYbLFjb
         01DeSbmJUKgX46Ug5COgFNTH7EY5+Z8LJfsMbNLKaxYU5OdA0joGL3td6RDUzopeCdeA
         K3+95JKnwN+aRk3SrquyNg4X2TDJlGDxPpMSO1P4CckGxYYADHaUd0xWdvHRggcUpEMu
         aBFkIulD345KddDmXJKYj4ENSit83J0RG+JzzWyRZKo3xLpzALO8Ku6Y+7u1hnHshAu/
         Ti+w==
X-Gm-Message-State: AOAM532dckV72nthWtPKJlfcTNAFKOBu1waUqgD6xrZfsSXpCy4UW0Vf
	jxlfFhl9FJotdaZH1fThuhg=
X-Google-Smtp-Source: ABdhPJx7lPFGWQs9f93r4UR3mE/K6P+Z9zItszc8seDzRdaM4UsxvXT+OxZsl0zZle4zwM0SuqbXkg==
X-Received: by 2002:ac2:4315:: with SMTP id l21mr1489588lfh.494.1601667135207;
        Fri, 02 Oct 2020 12:32:15 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:5c44:: with SMTP id s4ls1376452lfp.3.gmail; Fri, 02 Oct
 2020 12:32:14 -0700 (PDT)
X-Received: by 2002:a19:894:: with SMTP id 142mr1494441lfi.559.1601667134101;
        Fri, 02 Oct 2020 12:32:14 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1601667134; cv=none;
        d=google.com; s=arc-20160816;
        b=W5dFDWbrP9ISSmAk0XVoCSfs9hMKuPjTJJ+q36jW1gwPeibghIiuGf1EsKG5ysurie
         TwDxv9d8rU6cgFtFr33UvDE2ATC7kSBNK79K0TQM2dF4CZf/NsRkWIXlKLsf75yOBkM0
         i6HZ7CbImWlgHmb7LWtzImEGZO7zlZCoVhDXKyDjX66D2FPCEn7DcXTfybw23ftn1MF6
         psM6kfEiSxyuK4xMBFH4aHyEa5hP5K6+8ZFmZpRtArJaGD+TLHMv2/8IGoNvnFEtN2um
         fLKe3spYL0GsmeruL2YGgwjoyk9QTNb7dcoV4nii8yyuvWEQk3Ua538ZeStXC0hd82WH
         /8bQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=8Zinz0oexRJUeJTiDko3PiAzAmypZjIdFBb1syJchnI=;
        b=Kme9Fdjv2BBLcYKwuBKPAIxZ+dyfTV4NXYF9/ow3bXT+lwtd+UG5Ls7xsf2AOLlcc4
         tc2sx1WwVtHJhW/nu8CUJUqd193+p+4D47BjmS4aJgPP6ffENMh+tUhFsctcNeSzPOmR
         rJQYTWtr7o8vAShkq4a1UjfTX7puQ9MwjRTUgbcIJt76SMWD0v5X2n8Bbghn9Zz5UrKc
         NYP7bNd7qsy50WPH9LuGg6D97VaKXGP2+sQZDfpEl/vzhaw36sLJAL0wxgwPXHcjcBmA
         o6UDTIFmTMM7Vn161yPKuxsLHYVo/HT5pvLlGi0m0nAN4sRyMjgIs4MT0N9SQWIcaaAh
         ZbeQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=uJ8KWfv+;
       spf=pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::542 as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x542.google.com (mail-ed1-x542.google.com. [2a00:1450:4864:20::542])
        by gmr-mx.google.com with ESMTPS id q20si67061lji.2.2020.10.02.12.32.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 02 Oct 2020 12:32:14 -0700 (PDT)
Received-SPF: pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::542 as permitted sender) client-ip=2a00:1450:4864:20::542;
Received: by mail-ed1-x542.google.com with SMTP id g4so2885956edk.0
        for <kasan-dev@googlegroups.com>; Fri, 02 Oct 2020 12:32:14 -0700 (PDT)
X-Received: by 2002:a50:e807:: with SMTP id e7mr4232314edn.84.1601667133289;
 Fri, 02 Oct 2020 12:32:13 -0700 (PDT)
MIME-Version: 1.0
References: <20200929133814.2834621-1-elver@google.com> <20200929133814.2834621-2-elver@google.com>
 <CAG48ez3+_K6YXoXgKBkB8AMeSQj++Mxi5u2OT--B+mJgE7Cyfg@mail.gmail.com> <20201002171959.GA986344@elver.google.com>
In-Reply-To: <20201002171959.GA986344@elver.google.com>
From: "'Jann Horn' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 2 Oct 2020 21:31:46 +0200
Message-ID: <CAG48ez0D1+hStZaDOigwbqNqFHJAJtXK+8Nadeuiu1Byv+xp5A@mail.gmail.com>
Subject: Re: [PATCH v4 01/11] mm: add Kernel Electric-Fence infrastructure
To: Marco Elver <elver@google.com>
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
	Linux ARM <linux-arm-kernel@lists.infradead.org>, Linux-MM <linux-mm@kvack.org>, 
	SeongJae Park <sjpark@amazon.de>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: jannh@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=uJ8KWfv+;       spf=pass
 (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::542 as
 permitted sender) smtp.mailfrom=jannh@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Jann Horn <jannh@google.com>
Reply-To: Jann Horn <jannh@google.com>
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

On Fri, Oct 2, 2020 at 7:20 PM Marco Elver <elver@google.com> wrote:
> On Fri, Oct 02, 2020 at 08:33AM +0200, Jann Horn wrote:
> > On Tue, Sep 29, 2020 at 3:38 PM Marco Elver <elver@google.com> wrote:
> > > This adds the Kernel Electric-Fence (KFENCE) infrastructure. KFENCE is a
> > > low-overhead sampling-based memory safety error detector of heap
> > > use-after-free, invalid-free, and out-of-bounds access errors.
> > >
> > > KFENCE is designed to be enabled in production kernels, and has near
> > > zero performance overhead. Compared to KASAN, KFENCE trades performance
> > > for precision. The main motivation behind KFENCE's design, is that with
> > > enough total uptime KFENCE will detect bugs in code paths not typically
> > > exercised by non-production test workloads. One way to quickly achieve a
> > > large enough total uptime is when the tool is deployed across a large
> > > fleet of machines.
> > >
> > > KFENCE objects each reside on a dedicated page, at either the left or
> > > right page boundaries.
> >
> > (modulo slab alignment)
>
> There are a bunch more details missing; this is just a high-level
> summary. Because as soon as we mention "modulo slab alignment" one may
> wonder about missed OOBs, which we solve with redzones. We should not
> replicate Documentation/dev-tools/kfence.rst; we do refer to it instead.
> ;-)

Heh, fair.

> > > The pages to the left and right of the object
> > > page are "guard pages", whose attributes are changed to a protected
> > > state, and cause page faults on any attempted access to them. Such page
> > > faults are then intercepted by KFENCE, which handles the fault
> > > gracefully by reporting a memory access error. To detect out-of-bounds
> > > writes to memory within the object's page itself, KFENCE also uses
> > > pattern-based redzones. The following figure illustrates the page
> > > layout:
> > [...]
> > > diff --git a/include/linux/kfence.h b/include/linux/kfence.h
> > [...]
> > > +/**
> > > + * is_kfence_address() - check if an address belongs to KFENCE pool
> > > + * @addr: address to check
> > > + *
> > > + * Return: true or false depending on whether the address is within the KFENCE
> > > + * object range.
> > > + *
> > > + * KFENCE objects live in a separate page range and are not to be intermixed
> > > + * with regular heap objects (e.g. KFENCE objects must never be added to the
> > > + * allocator freelists). Failing to do so may and will result in heap
> > > + * corruptions, therefore is_kfence_address() must be used to check whether
> > > + * an object requires specific handling.
> > > + */
> > > +static __always_inline bool is_kfence_address(const void *addr)
> > > +{
> > > +       return unlikely((char *)addr >= __kfence_pool &&
> > > +                       (char *)addr < __kfence_pool + KFENCE_POOL_SIZE);
> > > +}
> >
> > If !CONFIG_HAVE_ARCH_KFENCE_STATIC_POOL, this should probably always
> > return false if __kfence_pool is NULL, right?
>
> That's another check; we don't want to make this more expensive.

Ah, right, I missed that this is the one piece of KFENCE that is
actually really hot code until Dmitry pointed that out.

But actually, can't you reduce how hot this is for SLUB by moving
is_kfence_address() down into the freeing slowpath? At the moment you
use it in slab_free_freelist_hook(), which is in the super-hot
fastpath, but you should be able to at least move it down into
__slab_free()...

Actually, you already have hooked into __slab_free(), so can't you
just get rid of the check in the slab_free_freelist_hook()?

Also, you could do the NULL *after* the range check said "true". That
way the NULL check would be on the slowpath and have basically no
performance impact.

> This should never receive a NULL, given the places it's used from, which
> should only be allocator internals where we already know we have a
> non-NULL object. If it did receive a NULL, I think something else is
> wrong. Or did we miss a place where it can legally receive a NULL?

Well... not exactly "legally", but e.g. a kernel NULL deref (landing
in kfence_handle_page_fault()) might get weird.

[...]
> > > +         access, use-after-free, and invalid-free errors. KFENCE is designed
> > > +         to have negligible cost to permit enabling it in production
> > > +         environments.
> > [...]
> > > diff --git a/mm/kfence/core.c b/mm/kfence/core.c
> > [...]
> > > +module_param_named(sample_interval, kfence_sample_interval, ulong, 0600);
> >
> > This is a writable module parameter, but if the sample interval was 0
> > or a very large value, changing this value at runtime won't actually
> > change the effective interval because the work item will never get
> > kicked off again, right?
>
> When KFENCE has been enabled, setting this to 0 actually reschedules the
> work immediately; we do not disable KFENCE once it has been enabled.

Those are weird semantics. One value should IMO unambiguously mean one
thing, independent of when it was set. In particular, I think that if
someone decides to read the current value of kfence_sample_interval
through sysfs, and sees the value "0", that should not ambiguously
mean "either kfence triggers all the time or it is completely off".

If you don't want to support runtime disabling, can you maybe make the
handler refuse to write 0 if kfence has already been initialized?

[...]
> > > +#endif
> > [...]
> > > +/* Freelist with available objects. */
> > > +static struct list_head kfence_freelist = LIST_HEAD_INIT(kfence_freelist);
> > > +static DEFINE_RAW_SPINLOCK(kfence_freelist_lock); /* Lock protecting freelist. */
> > [...]
> > > +/* Gates the allocation, ensuring only one succeeds in a given period. */
> > > +static atomic_t allocation_gate = ATOMIC_INIT(1);
> >
> > I don't think you need to initialize this to anything?
> > toggle_allocation_gate() will set it to zero before enabling the
> > static key, so I don't think anyone will ever see this value.
>
> Sure. But does it hurt anyone? At least this way we don't need to think
> about yet another state that only exists on initialization; who knows
> what we'll change in future.

Well, no, it doesn't hurt. But I see this as equivalent to writing code like:

int ret = 0;
ret = -EINVAL;
if (...)
  return ret;

where a write can never have any effect because a second write will
clobber the value before it can be read, which is IMO an antipattern.
But it admittedly is less clear here, so if you like it better your
way, I don't really have a problem with that.

> > [...]
> > > +/* Check canary byte at @addr. */
> > > +static inline bool check_canary_byte(u8 *addr)
> > > +{
> > > +       if (*addr == KFENCE_CANARY_PATTERN(addr))
> >
> > You could maybe add a likely() hint here if you want.
>
> Added; but none of this is in a hot path.

Yeah, but when we do hit the kfence alloc/free paths, we should
probably still try to be reasonably fast to reduce jitter?

[...]
> > > +{
> > > +       unsigned long addr;
> > > +
> > > +       lockdep_assert_held(&meta->lock);
> > > +
> > > +       for (addr = ALIGN_DOWN(meta->addr, PAGE_SIZE); addr < meta->addr; addr++) {
> > > +               if (!fn((u8 *)addr))
> > > +                       break;
> > > +       }
> > > +
> > > +       for (addr = meta->addr + meta->size; addr < PAGE_ALIGN(meta->addr); addr++) {
> >
> > Hmm... if the object is on the left side (meaning meta->addr is
> > page-aligned) and the padding is on the right side, won't
> > PAGE_ALIGN(meta->addr)==meta->addr , and therefore none of the padding
> > will be checked?
>
> No, you're thinking of ALIGN_DOWN. PAGE_ALIGN gives us the next page.

Hm, really? Let me go through those macros...


#define __AC(X,Y) (X##Y)
#define _AC(X,Y) __AC(X,Y)
#define PAGE_SHIFT 12
#define PAGE_SIZE (_AC(1,UL) << PAGE_SHIFT)

so:
PAGE_SIZE == (1UL << 12) == 0x1000UL

#define __ALIGN_KERNEL_MASK(x, mask) (((x) + (mask)) & ~(mask))
#define __ALIGN_KERNEL(x, a) __ALIGN_KERNEL_MASK(x, (typeof(x))(a) - 1)
#define ALIGN(x, a) __ALIGN_KERNEL((x), (a))

so (omitting casts):
ALIGN(x, a) == ((x + (a - 1)) & ~(a - 1))

#define PAGE_ALIGN(addr) ALIGN(addr, PAGE_SIZE)

so (omitting casts):
PAGE_ALIGN(addr) == ((addr + (0x1000UL - 1)) & ~(0x1000UL - 1))
  == ((addr + 0xfffUL) & 0xfffffffffffff000UL)

meaning that if we e.g. pass in 0x5000, we get:

PAGE_ALIGN(0x5000) == ((0x5000 + 0xfffUL) & 0xfffffffffffff000UL)
 == 0x5fffUL & 0xfffffffffffff000UL == 0x5000UL

So if the object is on the left side (meaning meta->addr is
page-aligned), we won't check padding.


ALIGN_DOWN rounds down, while PAGE_ALIGN rounds up, but both leave the
value as-is if it is already page-aligned.


> > > +               if (!fn((u8 *)addr))
> > > +                       break;
> > > +       }
> > > +}
> > > +
> > > +static void *kfence_guarded_alloc(struct kmem_cache *cache, size_t size, gfp_t gfp)
> > > +{
> > > +       struct kfence_metadata *meta = NULL;
> > > +       unsigned long flags;
> > > +       void *addr;
> > > +
> > > +       /* Try to obtain a free object. */
> > > +       raw_spin_lock_irqsave(&kfence_freelist_lock, flags);
> > > +       if (!list_empty(&kfence_freelist)) {
> > > +               meta = list_entry(kfence_freelist.next, struct kfence_metadata, list);
> > > +               list_del_init(&meta->list);
> > > +       }
> > > +       raw_spin_unlock_irqrestore(&kfence_freelist_lock, flags);
> > > +       if (!meta)
> > > +               return NULL;
> >
> > Should this use pr_warn_once(), or something like that, to inform the
> > user that kfence might be stuck with all allocations used by
> > long-living objects and therefore no longer doing anything?
>
> I don't think so; it might as well recover, and seeing this message once
> is no indication that we're stuck. Instead, we should (and plan to)
> monitor /sys/kernel/debug/kfence/stats.

Ah, I guess that's reasonable.

[...]
> > > +}
> > > +static DECLARE_DELAYED_WORK(kfence_timer, toggle_allocation_gate);
> > > +
> > > +/* === Public interface ===================================================== */
> > > +
> > > +void __init kfence_init(void)
> > > +{
> > > +       /* Setting kfence_sample_interval to 0 on boot disables KFENCE. */
> > > +       if (!kfence_sample_interval)
> > > +               return;
> > > +
> > > +       if (!kfence_initialize_pool()) {
> > > +               pr_err("%s failed\n", __func__);
> > > +               return;
> > > +       }
> > > +
> > > +       WRITE_ONCE(kfence_enabled, true);
> > > +       schedule_delayed_work(&kfence_timer, 0);
> >
> > This is schedule_work(&kfence_timer).
>
> No, schedule_work() is not generic and does not take a struct delayed_work.

Ah, of course. Never mind.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAG48ez0D1%2BhStZaDOigwbqNqFHJAJtXK%2B8Nadeuiu1Byv%2Bxp5A%40mail.gmail.com.
