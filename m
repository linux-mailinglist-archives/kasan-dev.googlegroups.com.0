Return-Path: <kasan-dev+bncBCQ2XPNX7EOBBYX65X6AKGQE2B5U2AY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x63b.google.com (mail-ej1-x63b.google.com [IPv6:2a00:1450:4864:20::63b])
	by mail.lfdr.de (Postfix) with ESMTPS id 6B1BA29FBA8
	for <lists+kasan-dev@lfdr.de>; Fri, 30 Oct 2020 03:50:11 +0100 (CET)
Received: by mail-ej1-x63b.google.com with SMTP id gr9sf235547ejb.19
        for <lists+kasan-dev@lfdr.de>; Thu, 29 Oct 2020 19:50:11 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1604026211; cv=pass;
        d=google.com; s=arc-20160816;
        b=yl7anHrBB5HNS8crmyGeTNGFL1rQQMDBZP0Ohw23WqiRnK9JSf0OiPPshqnTqnjnaa
         5K8T9hvteBiwZZp32G43pSiAZkfeysahCZxnLw15/iMETBCmvDiGUookgZlFvMTOoj0r
         smw5piN6fljdmyzvP3msIyFnq5bHee/x74T/2pagpxXiyLAYWp96lPpUgehLoh9HIJFs
         b8MhlAWEHCwcxrB9Y56JMpuyaR7gsxrcl2gQJkQRBRVa9a6L5OlyLD6FnzmuGxrDy2Vv
         htMizzlG2ZLezjIWazvfom6Jjhl8xnPy8L8kuJfoyvnpSwI8XKvlZw3P4B63qZ00nJFl
         VGzg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=WWgWDw1tntYNvlE2xKZ1eknuR6urskc4W2Cpg0siPoo=;
        b=YzOxZF6hJkWDgwwaof+g9xtuPljcA7LuCzbS3Q/bIkHpeXzNGwusXoa9qVaE4ZMjv0
         VEk+ghkAQGGjUCAt8J3Y9XKcnz2HQ6ugi//V8rRHP6QBMtBd4TCYmt/PBgMZfGs2T4lD
         ndeb7QzfDWk03mWdydfKSpk7/tqFDWLZJ0+UUmVVUisIQIo+5UDseXqZwGWA7zAKMh4h
         poJxa+QH0qXQhUYj8Keklgs+2ysdzAX7MN7UM9DHHIpIr88+XvMQpQDu3lE791XuLxgW
         LpNYp5RMe96hTeKBWa2KTAGnjqKoLPL7Kuo7gfBjnFk5aY+cPh8Ee+GpO9wCnMeNx1Te
         7YUA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="cI/RSXbZ";
       spf=pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::243 as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=WWgWDw1tntYNvlE2xKZ1eknuR6urskc4W2Cpg0siPoo=;
        b=CT6F+fFP6+u8X4tQAKe1AA4oKNYJ157ViB5vJgp+/UnWiK++FwYSmY1yWdIpFBzfgA
         YbMrZqzsGaAG4/ACIFAbqhW5dpbWH/lCLZYmiaqU3XWkdN/dpMA5YrsJ8NQkO2tVqYZv
         9TFAbumXizWg6FTa1FTiKCaRWH6dBlSy9+J4eP91HGPfqGZ/iH2fe1BXESdOi1oWhLaT
         idAjIORgOQU2tK2Y20SUUMmnj7itkTuSKf1MWv10MNynie6TlioxaeQOCkvGHJ2v4rOT
         3RElj5pAQAOQP2+EdhZyNDJSyPGMFisMIRFrNdI9th3YwkYe38i5/PrptlpUQIMm48Eo
         Y4+w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=WWgWDw1tntYNvlE2xKZ1eknuR6urskc4W2Cpg0siPoo=;
        b=JyhZG6+X+vBLWmUOjABE+t8aosoEQze9UYJ9Y5gqvjB+i0hQcOGCUMUSc8lz7ws+DC
         JcH2K/P3WdS1odJNBFCm1Ecoq+8BlUN3xtHwUmyp9JuuJwIJI1b+r+a/+YEwYknJHntp
         n2lwlqqjHWfXdWrUI1cjpxsNb3vR1FsGhgI21/6dL1e1c8ADIA3+527hsMnfrPb+vaPs
         o8Ucg7T1OQUwvfWDPaKetXaDUq5MHAEJSvHP7h8UxFoYzELs/ID53HQPpfiXx1dS5cQg
         AoFGy9+aPC4XQCjpfjCDInc3MRaDqyAtH6NZ7kqGJaFOjSXgFCGFaKMlviWVHh/K9KrT
         +MVw==
X-Gm-Message-State: AOAM530EKk4ZFdelyQqqtR4nKVWLBRV37yuPSNAp8Y65V3w8gNo6qRCv
	qpK2Ht245ck20HaosmZ0X84=
X-Google-Smtp-Source: ABdhPJyhZRpbeviJAs8E8nmf1imcqF47DpdKnsiv2OA3lVAwVQCKWNlcEqklUdCyRNKtvSwxV9LUGQ==
X-Received: by 2002:a17:906:348c:: with SMTP id g12mr406753ejb.422.1604026211140;
        Thu, 29 Oct 2020 19:50:11 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:1d3c:: with SMTP id dh28ls5182553edb.0.gmail; Thu,
 29 Oct 2020 19:50:08 -0700 (PDT)
X-Received: by 2002:aa7:d496:: with SMTP id b22mr50949edr.123.1604026208790;
        Thu, 29 Oct 2020 19:50:08 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1604026208; cv=none;
        d=google.com; s=arc-20160816;
        b=q+EvgX9FppGvJVg4vWvCPdXnw1/Tfygici5jWQOypmn1SYOMNGvbIJ01lEnzcVsbm3
         bkrpnZVeS9W8IyTG5KztJuf8/Dws0nzw2v2b1IV8TFyzugzQfHi76mcpLXWa53vYnIzT
         Fl3xlYoVQ04DjUlWaqq3KRB6mKfpTxfKeVMGqUJQ0D3WtB2n81g2i2Ng3e3kZDT+3cDO
         wc0a1tN7dGOlLMK5ZP3KLsctiIUb6VT2PtWzECCA+bzEQCUb0x7Pp27RjG+mTSw/OuQ3
         XoZ8CUh5aXBMKu/IQ68VYQfhXMLZ21Wj+yKbsix0TWaLz4PhGoFPhdfxqEU6sTEYf3cF
         H8Vg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=kiZ/FvhUKgnzktM7r0SIhiQ+o9jRSo0aasuFIIfF3Y4=;
        b=xosMde4T3yJJgqc0qpPvHO7n/QF61syYheNcDPnpwuNRH4C8ivgp4FLiJD+GMfCG1B
         MNXsU4MH2E4T5xArnExXtYM6/aqMnBaBRx+ZUtikXhN6KPs+TCjFyyR3ebJavXleTrKm
         c2AC1/8eG1JYF3w2OlHSaDsl1RowRTNvNbkv23r5lXgeTNcO7xaaelOj4/leFczwi+pQ
         P2+hp/JyONQT4HxUJel3C5sqpwkdMdAODlRU/L75nDy2qhHrlKMVx1vhMf3NnclWlqhf
         g+HQhEXtPaFCKJ4XjhrnZqe/EgaZ8K4RU8+z555h4Jrs3rIGQgxlQLMlLv8vTPcGzVdw
         cv6w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="cI/RSXbZ";
       spf=pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::243 as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-lj1-x243.google.com (mail-lj1-x243.google.com. [2a00:1450:4864:20::243])
        by gmr-mx.google.com with ESMTPS id n11si188749edi.1.2020.10.29.19.50.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 29 Oct 2020 19:50:08 -0700 (PDT)
Received-SPF: pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::243 as permitted sender) client-ip=2a00:1450:4864:20::243;
Received: by mail-lj1-x243.google.com with SMTP id c21so5391385ljj.0
        for <kasan-dev@googlegroups.com>; Thu, 29 Oct 2020 19:50:08 -0700 (PDT)
X-Received: by 2002:a2e:9c84:: with SMTP id x4mr96553lji.326.1604026208097;
 Thu, 29 Oct 2020 19:50:08 -0700 (PDT)
MIME-Version: 1.0
References: <20201029131649.182037-1-elver@google.com> <20201029131649.182037-6-elver@google.com>
In-Reply-To: <20201029131649.182037-6-elver@google.com>
From: "'Jann Horn' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 30 Oct 2020 03:49:41 +0100
Message-ID: <CAG48ez005N4SVKNXDL7k1C+JPiEbY7eTBJ+kL53N7g=bgWGAeQ@mail.gmail.com>
Subject: Re: [PATCH v6 5/9] mm, kfence: insert KFENCE hooks for SLUB
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
	Jonathan Corbet <corbet@lwn.net>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, joern@purestorage.com, 
	Kees Cook <keescook@chromium.org>, Mark Rutland <mark.rutland@arm.com>, 
	Pekka Enberg <penberg@kernel.org>, Peter Zijlstra <peterz@infradead.org>, 
	SeongJae Park <sjpark@amazon.com>, Thomas Gleixner <tglx@linutronix.de>, Vlastimil Babka <vbabka@suse.cz>, 
	Will Deacon <will@kernel.org>, "the arch/x86 maintainers" <x86@kernel.org>, 
	"open list:DOCUMENTATION" <linux-doc@vger.kernel.org>, kernel list <linux-kernel@vger.kernel.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, Linux-MM <linux-mm@kvack.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: jannh@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="cI/RSXbZ";       spf=pass
 (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::243 as
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

On Thu, Oct 29, 2020 at 2:17 PM Marco Elver <elver@google.com> wrote:
> Inserts KFENCE hooks into the SLUB allocator.
>
> To pass the originally requested size to KFENCE, add an argument
> 'orig_size' to slab_alloc*(). The additional argument is required to
> preserve the requested original size for kmalloc() allocations, which
> uses size classes (e.g. an allocation of 272 bytes will return an object
> of size 512). Therefore, kmem_cache::size does not represent the
> kmalloc-caller's requested size, and we must introduce the argument
> 'orig_size' to propagate the originally requested size to KFENCE.
>
> Without the originally requested size, we would not be able to detect
> out-of-bounds accesses for objects placed at the end of a KFENCE object
> page if that object is not equal to the kmalloc-size class it was
> bucketed into.
>
> When KFENCE is disabled, there is no additional overhead, since
> slab_alloc*() functions are __always_inline.
>
> Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
> Co-developed-by: Marco Elver <elver@google.com>
> Signed-off-by: Marco Elver <elver@google.com>
> Signed-off-by: Alexander Potapenko <glider@google.com>

Reviewed-by: Jann Horn <jannh@google.com>

if you fix one nit:

[...]
> diff --git a/mm/slub.c b/mm/slub.c
[...]
> @@ -2658,7 +2664,8 @@ static inline void *get_freelist(struct kmem_cache *s, struct page *page)
>   * already disabled (which is the case for bulk allocation).
>   */
>  static void *___slab_alloc(struct kmem_cache *s, gfp_t gfpflags, int node,
> -                         unsigned long addr, struct kmem_cache_cpu *c)
> +                         unsigned long addr, struct kmem_cache_cpu *c,
> +                         size_t orig_size)

orig_size is added as a new argument, but never used. (And if you
remove this argument, __slab_alloc will also not be using its
orig_size argument anymore.)



>  {
>         void *freelist;
>         struct page *page;
> @@ -2763,7 +2770,8 @@ static void *___slab_alloc(struct kmem_cache *s, gfp_t gfpflags, int node,
>   * cpu changes by refetching the per cpu area pointer.
>   */
>  static void *__slab_alloc(struct kmem_cache *s, gfp_t gfpflags, int node,
> -                         unsigned long addr, struct kmem_cache_cpu *c)
> +                         unsigned long addr, struct kmem_cache_cpu *c,
> +                         size_t orig_size)
>  {
>         void *p;
>         unsigned long flags;
> @@ -2778,7 +2786,7 @@ static void *__slab_alloc(struct kmem_cache *s, gfp_t gfpflags, int node,
>         c = this_cpu_ptr(s->cpu_slab);
>  #endif
>
> -       p = ___slab_alloc(s, gfpflags, node, addr, c);
> +       p = ___slab_alloc(s, gfpflags, node, addr, c, orig_size);
>         local_irq_restore(flags);
>         return p;
>  }

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAG48ez005N4SVKNXDL7k1C%2BJPiEbY7eTBJ%2BkL53N7g%3DbgWGAeQ%40mail.gmail.com.
