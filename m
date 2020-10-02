Return-Path: <kasan-dev+bncBCQ2XPNX7EOBBS7C3X5QKGQEYR3VUAI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x540.google.com (mail-ed1-x540.google.com [IPv6:2a00:1450:4864:20::540])
	by mail.lfdr.de (Postfix) with ESMTPS id 44674281ADB
	for <lists+kasan-dev@lfdr.de>; Fri,  2 Oct 2020 20:28:28 +0200 (CEST)
Received: by mail-ed1-x540.google.com with SMTP id g16sf994839edy.22
        for <lists+kasan-dev@lfdr.de>; Fri, 02 Oct 2020 11:28:28 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1601663308; cv=pass;
        d=google.com; s=arc-20160816;
        b=XsrhO2yuJVAFTSGQnB6kscb9J9pnjKKHKPwQpOpz3GPgSP9ZofKaBR9TumDnjfgazn
         q30bkjOnnDqTNKRnGSo9/cjyCwkhXg4yI3HKMOJlTlpLcuk+fvxb68cQwNaHLfnNFSql
         liswWhmKM5WMXtrT/D2HmbrkZpZSAoBFgIjo5iqD/gqBZPYjzE/h4Q9As3rXgA6OgmFv
         c1/o/J8rTW+hfhlT1Vo3aWUw49uIIEwah8QjVzPwzu32QJPMszZCMlBOtdjfI4myNvkQ
         5DjraNmCi19rCEzWTxL+G1LUkuPPgPEUaPKoJDm0LymiaBs3TH1ht1kYDBlRan6v9wT0
         V2Vg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=RrovbilTXT6NPORa455l2L4h9ydSHzMqM9YAsr8j7SU=;
        b=kbm6dzmH2B0WDAmTGdxDjyRg3JTxEggPSAp5aR5MOQ1U4tPOi+23rJKJoLvU7YisZx
         Ph6Wmfbk5W/Dmdk9bcCY73DzcLP62mbuTRS5OTJSEeL8J6R2Iij5UzOYRWpDbVjrs9VD
         n/XMt//L0WQSZmzZ+HqamNYDXPls+yBFN1mbY23r8yQWuYycVAZKgucyf5TEn2ZNwEFN
         x5Tt50ha2V2oLlFmKMP+ZykqaT8dLK0ckv0RDr05OR2tBIO5gqIjcplWHD25SBsZI483
         YpmpLDy3Lwy5fDZLviO+LagGmtFMG4JC4BuYu4HNAy2A/higw/TToXeWN1HHJ18lNopN
         +QNA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=iyd0xHn4;
       spf=pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::642 as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=RrovbilTXT6NPORa455l2L4h9ydSHzMqM9YAsr8j7SU=;
        b=kqD3ByJdh6PdKb5WNZgmDIALLAuseQ9Kcnjm9PeGRWjYLuSQQsV7e5SXtij8vBRcfw
         2U6Vf8wf93G9B/aqgHhVW3ryGtYH/mddvCb0DBQghKUTO4z9R3Dnn2VmJxQ9/uvQnzco
         1ZyeL6zx8HlBj+mMRLWUZqUIgvoshLHYXZcNP+jcaiHiCQPuqIPEytSVGOHp7CUu5rKA
         Eh+Afw8YCsHNekqQR5qmIiOiORSfqlx/fD1m2GOb1MDLkgYRjvqWoq4AhQSIt7bUcf48
         tyM5JTBMablMedmAJ+JRpH6S14Z7s9bYKzvPMIvpa7uBeROuHIKk3hXzcy2MJZQ/AqGu
         3txg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=RrovbilTXT6NPORa455l2L4h9ydSHzMqM9YAsr8j7SU=;
        b=aCY4GdHDZTsG4dObKdhDqSKm6oUPksuUmy35TpWvByxEU8mbIYLtCcoXDdhzTI5uSy
         iD7BeA9WyRgFi61CoSUYpoPnWscp31poGHa6p5U/Aoyz3+dYcRq+I3MZRiNtoJUgRzuq
         D+uf9/9hDAi3KhtbWyzNffrY2zIJ7/oGwYedPAoXEi0DBSvuuD1NvlDNHcaCuS4CbE37
         ypA5TLnedYX+CY+0zuT5Qd53W5c4VqA2jHAQ6MgPRZma2lkzitjEzSWUYTTIRm3vOgqD
         N56MVMzEwcf/zMv91IcHOtZS662sQgCBlGYsFEpuywzdRtmLPA8D4fBI6xxn/xD3xgn/
         jKnw==
X-Gm-Message-State: AOAM530IGheT7gi7EX7iJPZi8mznNUu+1QmYfRM9i6Y5YRoKDpXKYev+
	vcG+5wm06VqP9pkFNSI6PxE=
X-Google-Smtp-Source: ABdhPJxP1kl/T5X52M01T21vmigOtbKAe6lili5efJpmZmkIuMfUtaVfpBz2ls7qftkW1VU86bBlsg==
X-Received: by 2002:aa7:dac5:: with SMTP id x5mr3892631eds.72.1601663307906;
        Fri, 02 Oct 2020 11:28:27 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:af96:: with SMTP id mj22ls1141240ejb.5.gmail; Fri,
 02 Oct 2020 11:28:27 -0700 (PDT)
X-Received: by 2002:a17:906:1485:: with SMTP id x5mr3648735ejc.163.1601663306265;
        Fri, 02 Oct 2020 11:28:26 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1601663306; cv=none;
        d=google.com; s=arc-20160816;
        b=o2AfgPnHPUFAogCGeGf4L3olRTqqsZ8DgeOQjG7wauByVahfl7bb/tIPcYx6rEBmXa
         9gg1/4dAyiltkGrbca/kqtzps3WDrSaKbKvVOaDzokD5otF5NwiUvthRhKn9EW2ERg8r
         DvkvPLd8i11hgfw2TiD8nyAjjKWZ20HDoTuCKmV2JczN0papPvS1rJo6dueu/qVp7SnK
         OQ29/hqttkHx+eGJaQq8+xDhJXmv665BC4DhGe4fj7fzuXa6UlXabbIPWvnLWyhapJzK
         WQwPvudwWSLR7XYaI8lEaJRlDkkoJ74ZWE3B55idK6c5j/HVOUbsPwsfr7sSZ+xPPOye
         vupw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=BsYux+2mDidOv01anJDY4ry73gJii56cZfxQL8DhjP4=;
        b=nINWafhBdJ2WUr7jI69aO/I2NoQ1utnKmA9qH+BD96/iZu+vIBhZWmluaglnEKMJn3
         +DkVvwKaKqJtTXrDhLE8N1o/n6ocTEfQ/BJKORRpH6mAp98qK8EyA/rK0BfVnO3F9+vg
         Cm/H5he/vPcVa5TenFrKMF4KfLX4q2IO5IYpTXxr+hyaN0RD0YOh14bi+GiFkk7syrf8
         grwyfYg2R8MTKMXECvmJm19GI62C+KfC5NBKlW738t8m6mm6X58nnLrZowNRyPt+Ec/t
         qgBVseJL9vjPflLXplSNvobu2J1JpTbYnolZXyPvCAtSg8hvNwAhoAXG2SN/6/fmAvbM
         uwVw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=iyd0xHn4;
       spf=pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::642 as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ej1-x642.google.com (mail-ej1-x642.google.com. [2a00:1450:4864:20::642])
        by gmr-mx.google.com with ESMTPS id a16si108868ejk.1.2020.10.02.11.28.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 02 Oct 2020 11:28:26 -0700 (PDT)
Received-SPF: pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::642 as permitted sender) client-ip=2a00:1450:4864:20::642;
Received: by mail-ej1-x642.google.com with SMTP id c22so1916294ejx.0
        for <kasan-dev@googlegroups.com>; Fri, 02 Oct 2020 11:28:26 -0700 (PDT)
X-Received: by 2002:a17:906:394:: with SMTP id b20mr3465227eja.513.1601663305597;
 Fri, 02 Oct 2020 11:28:25 -0700 (PDT)
MIME-Version: 1.0
References: <20200929133814.2834621-1-elver@google.com> <20200929133814.2834621-2-elver@google.com>
 <CAG48ez3+_K6YXoXgKBkB8AMeSQj++Mxi5u2OT--B+mJgE7Cyfg@mail.gmail.com>
 <CAG48ez1MQks2na23g_q4=ADrjMYjRjiw+9k_Wp9hwGovFzZ01A@mail.gmail.com> <CACT4Y+a3hLF1ph1fw7xVz1bQDNKL8W0s6pXe7aKm9wTNrJH3=w@mail.gmail.com>
In-Reply-To: <CACT4Y+a3hLF1ph1fw7xVz1bQDNKL8W0s6pXe7aKm9wTNrJH3=w@mail.gmail.com>
From: "'Jann Horn' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 2 Oct 2020 20:27:59 +0200
Message-ID: <CAG48ez1RYbpMFbGFB6=9Y3vVCGrMgLS3LbDdxzBfmxH6Kxddmw@mail.gmail.com>
Subject: Re: [PATCH v4 01/11] mm: add Kernel Electric-Fence infrastructure
To: Dmitry Vyukov <dvyukov@google.com>
Cc: Marco Elver <elver@google.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Alexander Potapenko <glider@google.com>, "H . Peter Anvin" <hpa@zytor.com>, 
	"Paul E . McKenney" <paulmck@kernel.org>, Andrey Konovalov <andreyknvl@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Andy Lutomirski <luto@kernel.org>, 
	Borislav Petkov <bp@alien8.de>, Catalin Marinas <catalin.marinas@arm.com>, Christoph Lameter <cl@linux.com>, 
	Dave Hansen <dave.hansen@linux.intel.com>, David Rientjes <rientjes@google.com>, 
	Eric Dumazet <edumazet@google.com>, Greg Kroah-Hartman <gregkh@linuxfoundation.org>, 
	Hillf Danton <hdanton@sina.com>, Ingo Molnar <mingo@redhat.com>, 
	Jonathan Cameron <Jonathan.Cameron@huawei.com>, Jonathan Corbet <corbet@lwn.net>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, Kees Cook <keescook@chromium.org>, 
	Mark Rutland <mark.rutland@arm.com>, Pekka Enberg <penberg@kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>, SeongJae Park <sjpark@amazon.com>, 
	Thomas Gleixner <tglx@linutronix.de>, Vlastimil Babka <vbabka@suse.cz>, Will Deacon <will@kernel.org>, 
	"the arch/x86 maintainers" <x86@kernel.org>, "open list:DOCUMENTATION" <linux-doc@vger.kernel.org>, 
	kernel list <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, Linux-MM <linux-mm@kvack.org>, 
	SeongJae Park <sjpark@amazon.de>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: jannh@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=iyd0xHn4;       spf=pass
 (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::642 as
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

On Fri, Oct 2, 2020 at 4:23 PM Dmitry Vyukov <dvyukov@google.com> wrote:
> On Fri, Oct 2, 2020 at 9:54 AM Jann Horn <jannh@google.com> wrote:
> > On Fri, Oct 2, 2020 at 8:33 AM Jann Horn <jannh@google.com> wrote:
> > > On Tue, Sep 29, 2020 at 3:38 PM Marco Elver <elver@google.com> wrote:
> > > > This adds the Kernel Electric-Fence (KFENCE) infrastructure. KFENCE is a
> > > > low-overhead sampling-based memory safety error detector of heap
> > > > use-after-free, invalid-free, and out-of-bounds access errors.
> > > >
> > > > KFENCE is designed to be enabled in production kernels, and has near
> > > > zero performance overhead. Compared to KASAN, KFENCE trades performance
> > > > for precision. The main motivation behind KFENCE's design, is that with
> > > > enough total uptime KFENCE will detect bugs in code paths not typically
> > > > exercised by non-production test workloads. One way to quickly achieve a
> > > > large enough total uptime is when the tool is deployed across a large
> > > > fleet of machines.
> > [...]
> > > > +/*
> > > > + * The pool of pages used for guard pages and objects. If supported, allocated
> > > > + * statically, so that is_kfence_address() avoids a pointer load, and simply
> > > > + * compares against a constant address. Assume that if KFENCE is compiled into
> > > > + * the kernel, it is usually enabled, and the space is to be allocated one way
> > > > + * or another.
> > > > + */
> > >
> > > If this actually brings a performance win, the proper way to do this
> > > would probably be to implement this as generic kernel infrastructure
> > > that makes the compiler emit large-offset relocations (either through
> > > compiler support or using inline asm statements that move an immediate
> > > into a register output and register the location in a special section,
> > > kinda like how e.g. static keys work) and patches them at boot time,
> > > or something like that - there are other places in the kernel where
> > > very hot code uses global pointers that are only ever written once
> > > during boot, e.g. the dentry cache of the VFS and the futex hash
> > > table. Those are probably far hotter than the kfence code.
> > >
> > > While I understand that that goes beyond the scope of this project, it
> > > might be something to work on going forward - this kind of
> > > special-case logic that turns the kernel data section into heap memory
> > > would not be needed if we had that kind of infrastructure.
> >
> > After thinking about it a bit more, I'm not even convinced that this
> > is a net positive in terms of overall performance - while it allows
> > you to avoid one level of indirection in some parts of kfence, that
> > kfence code by design only runs pretty infrequently. And to enable
> > this indirection avoidance, your x86 arch_kfence_initialize_pool() is
> > shattering potentially unrelated hugepages in the kernel data section,
> > which might increase the TLB pressure (and therefore the number of
> > memory loads that have to fall back to slow page walks) in code that
> > is much hotter than yours.
> >
> > And if this indirection is a real performance problem, that problem
> > would be many times worse in the VFS and the futex subsystem, so
> > developing a more generic framework for doing this cleanly would be
> > far more important than designing special-case code to allow kfence to
> > do this.
> >
> > And from what I've seen, a non-trivial chunk of the code in this
> > series, especially the arch/ parts, is only necessary to enable this
> > microoptimization.
> >
> > Do you have performance numbers or a description of why you believe
> > that this part of kfence is exceptionally performance-sensitive? If
> > not, it might be a good idea to remove this optimization, at least for
> > the initial version of this code. (And even if the optimization is
> > worthwhile, it might be a better idea to go for the generic version
> > immediately.)
>
> This check is very hot, it happens on every free. For every freed
> object we need to understand if it belongs to KFENCE or not.

Ah, so the path you care about does not dereference __kfence_pool, it
just compares it to the supplied pointer?


First off: The way you've written is_kfence_address(), GCC 10.2 at -O3
seems to generate *utterly* *terrible* code (and the newest clang
release isn't any better); something like this:

kfree_inefficient:
  mov rax, QWORD PTR __kfence_pool[rip]
  cmp rax, rdi
  jbe .L4
.L2:
  jmp kfree_not_kfence
.L4:
  add rax, 0x200000
  cmp rax, rdi
  jbe .L2
  jmp kfree_kfence

So pointers to the left of the region and pointers to the right of the
region will take different branches, and so if you have a mix of
objects on both sides of the kfence region, you'll get tons of branch
mispredictions for no good reason. You'll want to rewrite that check
as "unlikely(ptr - base <= SIZE)" instead of "unlikely(ptr >= base &&
ptr < base + SIZE" unless you know that all the objects will be on one
side. This would also reduce the performance impact of loading
__kfence_pool from the data section, because the branch prediction can
then speculate the branch that depends on the load properly and
doesn't have to go roll back everything that happened when the object
turns out to be on the opposite side of the kfence memory region - the
latency of the load will hopefully become almost irrelevant.



So in x86 intel assembly (assuming that we want to ensure that we only
do a single branch on the object type), the straightforward and
non-terrible version would be:


kfree_unoptimized:
  mov rax, rdi
  sub rax, QWORD PTR __kfence_pool[rip]
  cmp rax, 0x200000
  jbe 1f
  /* non-kfence case goes here */
1:
  /* kfence case goes here */


while the version you want is:


kfree_static:
  mov rax, rdi
  sub rax, OFFSET FLAT:__kfence_pool
  cmp rax, 0x200000
  jbe 1f
  jmp kfree_not_kfence
1:
  jmp kfree_kfence


If we instead use something like

#define STATIC_VARIABLE_LOAD(variable) \
({ \
  typeof(variable) value; \
  BUILD_BUG_ON(sizeof(variable) != sizeof(unsigned long)); \
  asm( \
    ".pushsection .static_variable_users\n\t" \
    ".long "  #variable " - .\n\t" \
    ".long 123f - .\n\t" /* offset to end of constant */ \
    ".popsection\n\t" \
    "movabs $0x0123456789abcdef, %0" \
    "123:\n\t" \
    :"=r"(value) \
  ); \
  value; \
})
static __always_inline bool is_kfence_address(const void *addr)
{
  return unlikely((char*)addr - STATIC_VARIABLE_LOAD(__kfence_pool) <
KFENCE_POOL_SIZE);
}

to locate the pool (which could again be normally allocated with
alloc_pages()), we'd get code like this, which is like the previous
except that we need an extra "movabs" because x86's "sub" can only use
immediates up to 32 bits:

kfree_hotpatchable_bigreloc:
  mov rax, rdi
  movabs rdx, 0x0123456789abcdef
  sub rax, rdx
  cmp rax, 0x200000
  jbe .1f
  jmp kfree_not_kfence
1:
  jmp kfree_kfence

The arch-specific part of this could probably be packaged up pretty
nicely into a generic interface. If it actually turns out to have a
performance benefit, that is.

If that one extra "movabs" is actually a problem, it would
*theoretically* be possible to get rid of that by using module_alloc()
to allocate virtual memory to which offsets from kernel text are 32
bits, and using special-cased inline asm, but we probably shouldn't do
that, because as Mark pointed out, we'd then risk getting extremely
infrequent extra bugs when drivers use phys_to_virt() on allocations
that were done through kfence. Adding new, extremely infrequent and
sporadically occurring bugs to the kernel seems like the exact
opposite of the goal of KFENCE. :P

Overall my expectation would be that the MOVABS version should
probably at worst be something like one cycle slower - it adds 5
instruction bytes (and we pay 1 cycle in the frontend per 16 bytes of
instructions, I think?) and 1 backend cycle (for the MOVABS - Agner
Fog's tables seem to say that at least on Skylake, MOVABS is 1 cycle).
But that backend cycle shouldn't even be on the critical path (and it
has a wider choice of ports than e.g. a load, and I think typical
kernel code isn't exactly highly parallelizable, so we can probably
schedule on a port that would've been free otherwise?), and I think
typical kernel code should be fairly light on the backend, so with the
MOVABS version, compared to the version with __kfence_pool in the data
section, we probably overall just pay a fraction of a cycle in
execution cost? I'm not a professional performance engineer, but this
sounds to me like the MOVABS version should probably perform roughly
as well as your version.

Anyway, I guess this is all pretty vague without actually having
concrete benchmark results. :P

See <https://godbolt.org/z/Kev9dc> for examples of actual code
generation for different options of writing this check.

> The generic framework for this already exists -- you simply create a
> global variable ;)

Yeah, except for all the arch-specific bits you then need to twiddle
with because nobody expects heap memory inside the data section...

> KFENCE needs the range to be covered by struct page's and that's what
> creates problems for arm64. But I would assume most other users don't
> need that.

Things like the big VFS dentry cache and the futex hashtable have
their size chosen at boot time, so they also can't be placed in the
data/bss section.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAG48ez1RYbpMFbGFB6%3D9Y3vVCGrMgLS3LbDdxzBfmxH6Kxddmw%40mail.gmail.com.
