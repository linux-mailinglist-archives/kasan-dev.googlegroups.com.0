Return-Path: <kasan-dev+bncBC7OBJGL2MHBBMW25X5QKGQERQSSHEY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43c.google.com (mail-pf1-x43c.google.com [IPv6:2607:f8b0:4864:20::43c])
	by mail.lfdr.de (Postfix) with ESMTPS id DAD09283F31
	for <lists+kasan-dev@lfdr.de>; Mon,  5 Oct 2020 21:00:03 +0200 (CEST)
Received: by mail-pf1-x43c.google.com with SMTP id q16sf7167414pfj.7
        for <lists+kasan-dev@lfdr.de>; Mon, 05 Oct 2020 12:00:03 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1601924402; cv=pass;
        d=google.com; s=arc-20160816;
        b=i5IfzcGt8NFA7uVJBf5QoCnb+V5Pq0TgqWvPbqq7H+rrb6eoy9z94rOU/N+5Euyuyk
         FMsQBLI6Jc5T+OF/y6q2AcYXVE3g++sSd7ya8JQNntsjPP436RcmjynHkcOQPr945OC6
         huOvyqFy6hql+AHlnH39temwMfMlYI7zBrgpqasl44JV6xTyIYMEuOpDd9NEVEem3nhi
         Jzb74JsKfzsM7IuloDnOr7fS6MX5sx+U+ivujjTUFcIuCcUyKwzBrIQ2NJGI6//96HHc
         lpez+RjNRJBpum0ggvo+PvOoZYVTruF4upAwVrHYDKxE9zzZTCSHW+6fJnuLIlnpuo4D
         ow1Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=NMM8vqdOKKq/RyH7EpeBs27t2FnyaiZfvFNVvm1Dx0E=;
        b=ElU+XlrC1Xnzx55r6mNKpFnTFda0fgcC2CcHIjkCLWWFGzOawVBer/i9VlKeknoCv6
         F/lq8fCVN9+81qoaAN9gLfhxJz4718DOYQD3cG0RhSMKr9KLB0BVl6cloe0GZ/qeyUXY
         N9msrMZWPiQN/l+v1pb2yzP82YB3fD3gEEkNdNQXvvm+VuAm+DH0Mkl9iDZwLEVlNtyp
         KOeWsP94C2Q/HumzgbmOvX8AoTAjb//fvSiT01f9nrGvrBxKbTp9psTiPbPwqNbPovy7
         ZLxY+6hgXzp23Uo/LHQaCDYS+xihAHcMtXV8L1hOwENJirr3vKtFz6TCqYlzgNiCsbyp
         z6aA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Ky1b95z9;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::241 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=NMM8vqdOKKq/RyH7EpeBs27t2FnyaiZfvFNVvm1Dx0E=;
        b=GaNJ/jAPI6XOpbn5QHpUGzVrDhjofrQ3spweg3yNXzxuSTBafZMHD5mbw3mMGn0Myx
         /ryqwZfG230nBnrg9asAaF1eHPBkZVkMZ87c53vzIFbZp24JrNONPcaSM4PGKY8JsWA1
         TmDnuhC2GVgu1O8Fm8vSGZlDlz8r/WPsxpJt5uP8LxRfzgvR9AENR5pmTMlGTbw1JbS3
         RWLKtNp2RgAmBmWTJU5JWOpmdtI2YQ1lYpRejjgWRbQKk4E83PI+76Y+Wldsr8jtRh9x
         mixSMLzdIfN462ioa7dErI+vqPf7hV0/IVoSu0zZn80j3SBaVedYNlqV5aiHGvSnL8np
         udKw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=NMM8vqdOKKq/RyH7EpeBs27t2FnyaiZfvFNVvm1Dx0E=;
        b=UPxckxC5cXfhvXlV60tCqh9lwMy5DU9t70WSk8d9Tr3JvHNsp27X3XI8ocoifS+ShJ
         VSIpsjnXux2TP1OgZCYT7BiUSeTTf25kBjQ5AdAnm8/oCNrqUIc/frNeQKoIZiWBy283
         HN9Hgsg4h+utk1hVT4MfB0vk3mnU6QcuCy7MRQhBU4p1MFipo1RBI1LegQ3Kk9HFtrfD
         CHpvODXRxLhEhBwzNhg/L6yFkxm8U35ngZiq2hzlAON56xkRO+YdaxQTtl3mbFlFSf4s
         2ojw0T/wJ2QpgIlWnY1xGicMwjK5QW6dZs1a7vt//l6HbS7lR9z7mjd3MxPwC50jiDs8
         FI8g==
X-Gm-Message-State: AOAM530sLpcrrqVuMJoxg/ByJD3+zYWFEKxDvduvw3ySEHIp0vGIGH5d
	LrEgr74kg/dxCUvQggIProE=
X-Google-Smtp-Source: ABdhPJwn2erYVl6X7Zn0nY/mxjEDFwac6cLkymanBGyPaYarAn2VEDE7R58HM7A133TIWhlbvwcD4w==
X-Received: by 2002:a17:90b:a53:: with SMTP id gw19mr837867pjb.53.1601924402506;
        Mon, 05 Oct 2020 12:00:02 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:441d:: with SMTP id r29ls3932673pga.4.gmail; Mon, 05 Oct
 2020 12:00:01 -0700 (PDT)
X-Received: by 2002:a63:3747:: with SMTP id g7mr933517pgn.190.1601924401724;
        Mon, 05 Oct 2020 12:00:01 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1601924401; cv=none;
        d=google.com; s=arc-20160816;
        b=x1ehIW2VTgl85xGScrSYJjJz1dx0KfLyS/tCTeYBSpI2OiRRsKqNcMlanjSCgNMf9K
         JIw45ql3a1QVTu0OZXsw6eMtj3ooz7oKZ8TCUCsTtm5K/ohGLb5Bq0kG1G8L5ieYQJjm
         UrykPQq+YO7yjkcicK5FtukQKIbmsr10RFSi9Zj5N4WQVwCqbOl/debC3p9dvIWDGFKz
         xSmFjDD4fcOq8ZhD6CdSbnurb2nnOFeb8LgVifKr6tXXqAfmiLWWAha3wbHSZGjc5ba0
         FINs002Y50EjTL1YjsXhkjKGJ96+ZY98yqYdiSCCKTBDHcDSajvWoIlvogUz0E9CHfRb
         p64w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=bgyVeWM2KFwaEKtxvi0k5vnLHgxboX9dQWrAwhLZ6sM=;
        b=Yo9GYDOcexbVfh2hFvU4egFAFGEQjURRwBbqBW7klHJJjydBWJo773lYN7Qymtk0Sx
         F3FgU/NifkbsL4hkPtegTPegzTlNx5+SzRzU//5mFBogUPa0Xuyjpj7e2FE0/SVePOGw
         pClwA/A8Vt9t6iKFOIAVJOpcLy3/l9ByZ2orFTQVKIySn7KyZJXZybzoecB1fq4FpbU6
         duutPD2i7TOwJPniLQHigQMsh+2bw/Cji7i1lWWy9MtAWPAfdr261kvKli4kdtr5adMU
         dQawMtrdFXFNZcphe8J8nVtZ0aated9FC8xeOihWk2Ao3N0a2PhbkMoaPX98SgoAfumv
         EJLA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Ky1b95z9;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::241 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x241.google.com (mail-oi1-x241.google.com. [2607:f8b0:4864:20::241])
        by gmr-mx.google.com with ESMTPS id t15si33383pjq.1.2020.10.05.12.00.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 05 Oct 2020 12:00:01 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::241 as permitted sender) client-ip=2607:f8b0:4864:20::241;
Received: by mail-oi1-x241.google.com with SMTP id 16so2153504oix.9
        for <kasan-dev@googlegroups.com>; Mon, 05 Oct 2020 12:00:01 -0700 (PDT)
X-Received: by 2002:a54:468f:: with SMTP id k15mr488388oic.121.1601924400739;
 Mon, 05 Oct 2020 12:00:00 -0700 (PDT)
MIME-Version: 1.0
References: <20200929133814.2834621-1-elver@google.com> <20200929133814.2834621-2-elver@google.com>
 <CAG48ez3+_K6YXoXgKBkB8AMeSQj++Mxi5u2OT--B+mJgE7Cyfg@mail.gmail.com>
 <CAG48ez1MQks2na23g_q4=ADrjMYjRjiw+9k_Wp9hwGovFzZ01A@mail.gmail.com>
 <CACT4Y+a3hLF1ph1fw7xVz1bQDNKL8W0s6pXe7aKm9wTNrJH3=w@mail.gmail.com> <CAG48ez1RYbpMFbGFB6=9Y3vVCGrMgLS3LbDdxzBfmxH6Kxddmw@mail.gmail.com>
In-Reply-To: <CAG48ez1RYbpMFbGFB6=9Y3vVCGrMgLS3LbDdxzBfmxH6Kxddmw@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 5 Oct 2020 20:59:49 +0200
Message-ID: <CANpmjNPZxvWXTnJvkuwUifM5EjPetKxTJ7ectbw_7JFoBLB4EA@mail.gmail.com>
Subject: Re: [PATCH v4 01/11] mm: add Kernel Electric-Fence infrastructure
To: Jann Horn <jannh@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>, Andrew Morton <akpm@linux-foundation.org>, 
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
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=Ky1b95z9;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::241 as
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

On Fri, 2 Oct 2020 at 20:28, Jann Horn <jannh@google.com> wrote:
[...]
> > >
> > > Do you have performance numbers or a description of why you believe
> > > that this part of kfence is exceptionally performance-sensitive? If
> > > not, it might be a good idea to remove this optimization, at least for
> > > the initial version of this code. (And even if the optimization is
> > > worthwhile, it might be a better idea to go for the generic version
> > > immediately.)
> >
> > This check is very hot, it happens on every free. For every freed
> > object we need to understand if it belongs to KFENCE or not.
>
> Ah, so the path you care about does not dereference __kfence_pool, it
> just compares it to the supplied pointer?
>
>
> First off: The way you've written is_kfence_address(), GCC 10.2 at -O3
> seems to generate *utterly* *terrible* code (and the newest clang
> release isn't any better); something like this:
>
> kfree_inefficient:
>   mov rax, QWORD PTR __kfence_pool[rip]
>   cmp rax, rdi
>   jbe .L4
> .L2:
>   jmp kfree_not_kfence
> .L4:
>   add rax, 0x200000
>   cmp rax, rdi
>   jbe .L2
>   jmp kfree_kfence
>
> So pointers to the left of the region and pointers to the right of the
> region will take different branches, and so if you have a mix of
> objects on both sides of the kfence region, you'll get tons of branch
> mispredictions for no good reason. You'll want to rewrite that check
> as "unlikely(ptr - base <= SIZE)" instead of "unlikely(ptr >= base &&
> ptr < base + SIZE" unless you know that all the objects will be on one
> side. This would also reduce the performance impact of loading
> __kfence_pool from the data section, because the branch prediction can
> then speculate the branch that depends on the load properly and
> doesn't have to go roll back everything that happened when the object
> turns out to be on the opposite side of the kfence memory region - the
> latency of the load will hopefully become almost irrelevant.

Good point, implemented that. (It's "ptr - base < SIZE" I take it.)

> So in x86 intel assembly (assuming that we want to ensure that we only
> do a single branch on the object type), the straightforward and
> non-terrible version would be:
>
>
> kfree_unoptimized:
>   mov rax, rdi
>   sub rax, QWORD PTR __kfence_pool[rip]
>   cmp rax, 0x200000
>   jbe 1f
>   /* non-kfence case goes here */
> 1:
>   /* kfence case goes here */
>
>
> while the version you want is:
>
>
> kfree_static:
>   mov rax, rdi
>   sub rax, OFFSET FLAT:__kfence_pool
>   cmp rax, 0x200000
>   jbe 1f
>   jmp kfree_not_kfence
> 1:
>   jmp kfree_kfence
>
>
> If we instead use something like
>
> #define STATIC_VARIABLE_LOAD(variable) \
> ({ \
>   typeof(variable) value; \
>   BUILD_BUG_ON(sizeof(variable) != sizeof(unsigned long)); \
>   asm( \
>     ".pushsection .static_variable_users\n\t" \
>     ".long "  #variable " - .\n\t" \
>     ".long 123f - .\n\t" /* offset to end of constant */ \
>     ".popsection\n\t" \
>     "movabs $0x0123456789abcdef, %0" \
>     "123:\n\t" \
>     :"=r"(value) \
>   ); \
>   value; \
> })
> static __always_inline bool is_kfence_address(const void *addr)
> {
>   return unlikely((char*)addr - STATIC_VARIABLE_LOAD(__kfence_pool) <
> KFENCE_POOL_SIZE);
> }
>
> to locate the pool (which could again be normally allocated with
> alloc_pages()), we'd get code like this, which is like the previous
> except that we need an extra "movabs" because x86's "sub" can only use
> immediates up to 32 bits:
>
> kfree_hotpatchable_bigreloc:
>   mov rax, rdi
>   movabs rdx, 0x0123456789abcdef
>   sub rax, rdx
>   cmp rax, 0x200000
>   jbe .1f
>   jmp kfree_not_kfence
> 1:
>   jmp kfree_kfence
>
> The arch-specific part of this could probably be packaged up pretty
> nicely into a generic interface. If it actually turns out to have a
> performance benefit, that is.

Something like this would certainly be nice, but we'll do the due
diligence and see if it's even worth it.

> If that one extra "movabs" is actually a problem, it would
> *theoretically* be possible to get rid of that by using module_alloc()
> to allocate virtual memory to which offsets from kernel text are 32
> bits, and using special-cased inline asm, but we probably shouldn't do
> that, because as Mark pointed out, we'd then risk getting extremely
> infrequent extra bugs when drivers use phys_to_virt() on allocations
> that were done through kfence. Adding new, extremely infrequent and
> sporadically occurring bugs to the kernel seems like the exact
> opposite of the goal of KFENCE. :P
>
> Overall my expectation would be that the MOVABS version should
> probably at worst be something like one cycle slower - it adds 5
> instruction bytes (and we pay 1 cycle in the frontend per 16 bytes of
> instructions, I think?) and 1 backend cycle (for the MOVABS - Agner
> Fog's tables seem to say that at least on Skylake, MOVABS is 1 cycle).
> But that backend cycle shouldn't even be on the critical path (and it
> has a wider choice of ports than e.g. a load, and I think typical
> kernel code isn't exactly highly parallelizable, so we can probably
> schedule on a port that would've been free otherwise?), and I think
> typical kernel code should be fairly light on the backend, so with the
> MOVABS version, compared to the version with __kfence_pool in the data
> section, we probably overall just pay a fraction of a cycle in
> execution cost? I'm not a professional performance engineer, but this
> sounds to me like the MOVABS version should probably perform roughly
> as well as your version.
>
> Anyway, I guess this is all pretty vague without actually having
> concrete benchmark results. :P
>
> See <https://godbolt.org/z/Kev9dc> for examples of actual code
> generation for different options of writing this check.

Thanks for the analysis!  There is also some (11 year old) prior art,
that seems to never have made it into the kernel:
https://lore.kernel.org/lkml/20090924132626.485545323@polymtl.ca/

Maybe we need to understand why that never made it.

But I think, even if we drop the static pool, a first version of
KFENCE should not depend on it.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNPZxvWXTnJvkuwUifM5EjPetKxTJ7ectbw_7JFoBLB4EA%40mail.gmail.com.
