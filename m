Return-Path: <kasan-dev+bncBCQJP74GSUDRBPXHROBQMGQEMW67IMY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x437.google.com (mail-pf1-x437.google.com [IPv6:2607:f8b0:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id 5979434E4B3
	for <lists+kasan-dev@lfdr.de>; Tue, 30 Mar 2021 11:47:44 +0200 (CEST)
Received: by mail-pf1-x437.google.com with SMTP id z11sf12711002pfe.12
        for <lists+kasan-dev@lfdr.de>; Tue, 30 Mar 2021 02:47:44 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1617097663; cv=pass;
        d=google.com; s=arc-20160816;
        b=V1w/1W08GMZSQjYCwuFE4QYX9hK15zgoPIIhm2zzk6jiXSJ8YS23kCnEQXtek4S79V
         PPi58BPcMH1XAGsb822BQ+N1luzln6DUj7CE9JjHo7LTMA932ZGZAGDN036/zJYoOpVJ
         GFigpHPZ4gCh6lW6U4e3k9f1IN9p1cAIWGJU8UNd4oJ6SxfuUH4B8PGl/EgNxqOiUnxn
         5FcQH+oT87Po+sznccjXhRVjUDNAL8KETGdQZd1dIcMTsxt8tRKSrfWq/Py6jKsclomG
         tDrcHPuks/aogabLwOZnlJd4TYd3W4bDCQI43QBwtVSVRHhVOJXTS55QSCCFEDTB650P
         TYgA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=60bFrKDUH40ilJe0ogZa56r2n1NvJPd02mo1GaGz5AI=;
        b=Ei1a/vjkTu4U0A8SgiEIW43EZsf1ScBrOX/yCYZNVYKSJRoaq9pQFM/lXjoFi6dtKe
         ayTci35QV81xqab6YvXyJ9hfg2JXJh2JY+7xXVoOtPg7c3K/tAx/ue4tXwOZmVQfoQDO
         uT4xyn/5nZlVGZO7UF8QffjAuXu/YSGzFUPv2ft+mJsy4DwF7ZuNKlKZnZHB19g1zgvr
         GXJHL9FPZiBCTyzz46FRRVJf3VkPm43pHhk5LtAheFoK+vltInJpRRJQRlG3n0z1NQWD
         3YeDWzUsK7C2DA23cZ4YlJRr6MhOao25OcXqrbhnow0lraO9op4oVwLtfsmVcnsTFDgi
         WQdg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of geert.uytterhoeven@gmail.com designates 209.85.222.41 as permitted sender) smtp.mailfrom=geert.uytterhoeven@gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=60bFrKDUH40ilJe0ogZa56r2n1NvJPd02mo1GaGz5AI=;
        b=Hq0zn4LdBXWs3/xbXaQYtVeaasFRlZDKKsPV1+7wQRO75vuOB7OIZOJvc4lFUtoeYW
         NUjmXiHj2gfcbcu/Ep/JUomrgStwre3mWehNe8JyXQEI/PmzLJSQwMUfjhTp14Z38gbG
         StOhS7xF9MlyH0Y2kohIE5HUZwslnHwZNoLc3V8spP8HfBl7oFvdVYZ5Cg3vSzah1PQ8
         h3JOTBSH4m3lA34hr2Et6+mMnA8gmyIrSH45Xf4Lk/q0NnjorseXQX+peVMz0E5QTWb9
         DCfNuUu9SpYvJ8qKk/ej/Kk1rk6osiM4PCm1Exrntx+vH0X9+62TlwwwzPl+U3tgPF2U
         2Qhw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=60bFrKDUH40ilJe0ogZa56r2n1NvJPd02mo1GaGz5AI=;
        b=UDCVlUFxOQNcpHkZn6QmP+dKVAnq5aXKbHc0LrtpuV9RTflf5TA7txcKuQimzQMXJ3
         uV0WRvL1L4Ca4eeb+BROdYaNNNIbK3ngul1plcsUMQyV9VNgUne6kC2YLWVwWIVWsFMc
         TBHFz2P8WzAUJuPg3jXY/Lxa9sfRfhJVUMwjs74GxrOFymeDaml2pEG3mo7+xY/HO3GY
         dlj4syAMJGCwhAXaoG7yrqpnry1agk4SmCdcEZYePGEzuzeP9wnAG8/YykTC5gMvQACC
         J2LvhnEFI62x2A3NXyEct1yBeUWWGl4gRLEs2+AR5gN8IRP+3qe3u9d47pubDERpTZNJ
         BH1w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532tS2nacSeIEW3E4m3n7+5tjNxVtOQZfD7uVt6md2wvjjCYcrOp
	ZeI1PC12TIf8YLtFioGSppk=
X-Google-Smtp-Source: ABdhPJx4hgOpWY9aFf+t8PzweLxO6JSXQMknztE4eciXRkwRrVK7xkywCy70whuaPs/eLZ/N/zOs4Q==
X-Received: by 2002:a17:902:b709:b029:e7:49bd:6833 with SMTP id d9-20020a170902b709b02900e749bd6833mr1061089pls.57.1617097663093;
        Tue, 30 Mar 2021 02:47:43 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:a45:: with SMTP id gw5ls93553pjb.2.experimental-gmail;
 Tue, 30 Mar 2021 02:47:42 -0700 (PDT)
X-Received: by 2002:a17:902:b28b:b029:e6:375:69b0 with SMTP id u11-20020a170902b28bb02900e6037569b0mr33422332plr.25.1617097662213;
        Tue, 30 Mar 2021 02:47:42 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1617097662; cv=none;
        d=google.com; s=arc-20160816;
        b=MxYvzeaNnCAn2jA0exLuMwcjWPLTIy2OpMal275MCE1WMfIXJ+yp5U68vVsVubK/CC
         2396e9IeViTI/rzQ563ylRbnE52TuaGVO7iSjXGkrCD9JvX+6RkGESTp+rlrr+Ab4K77
         JRyCNElfaSFqeWEXD8cWMUzrIROYZg/w5FveP+rmBvcssBYv/mFnGa2sOgu8No4ZnaoY
         +i0Y/7KPGEryXcR102v8wR+DVoOBbcQVPMjjPF9+E55NsPLg3ig0lj8XH5Ysa+FTXQ07
         5ShnaN9iJME8BfXNoHdHMKzRe4BgdXcW/yn7NZ/utENDYxHfxSjjtZX7Cjz+tH3Ut14S
         fFHQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version;
        bh=8y7oZIw1YMOjEvsLWyQcxtUBXg+Hq4822w/iibJY5oM=;
        b=hwPCBlDBxi3Q3Y4M14dx6UV4ULxU/UpLAI2RjG35QcGD8Xo/VK5sznQgLzHUeW5ITL
         7KiXAT6dhuyCyGIWme8KPOASOHqxZXOpVvtfv7ejt4SRqKO5HGdRUnmzf4pg/+a60uHf
         KrzyAzOiL5zEODkXp1loHq2VTZO/yllxlJyGlQM49yCWt7Kf6YCyihgCumvK+tYkys6h
         M2f0ImTuBn9uw6jGtyv/RUgH+c0+pPGeGdOVLhx2v00MQHBDkGT/96lbfxfj6YuoCSvK
         QuxB8wfej0aI3kTEri/fvoZ3qVL+Ft41gOCGf55NpF2b+QkCRaepV9qX9yPZCVYjNWwz
         2N6g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of geert.uytterhoeven@gmail.com designates 209.85.222.41 as permitted sender) smtp.mailfrom=geert.uytterhoeven@gmail.com
Received: from mail-ua1-f41.google.com (mail-ua1-f41.google.com. [209.85.222.41])
        by gmr-mx.google.com with ESMTPS id a8si294291plp.2.2021.03.30.02.47.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 30 Mar 2021 02:47:42 -0700 (PDT)
Received-SPF: pass (google.com: domain of geert.uytterhoeven@gmail.com designates 209.85.222.41 as permitted sender) client-ip=209.85.222.41;
Received: by mail-ua1-f41.google.com with SMTP id h5so4864506uaw.0
        for <kasan-dev@googlegroups.com>; Tue, 30 Mar 2021 02:47:42 -0700 (PDT)
X-Received: by 2002:ab0:3393:: with SMTP id y19mr16748273uap.2.1617097661466;
 Tue, 30 Mar 2021 02:47:41 -0700 (PDT)
MIME-Version: 1.0
References: <20210313084505.16132-3-alex@ghiti.fr> <mhng-1a492a0c-049e-495e-8258-7513a4fa967a@palmerdabbelt-glaptop>
In-Reply-To: <mhng-1a492a0c-049e-495e-8258-7513a4fa967a@palmerdabbelt-glaptop>
From: Geert Uytterhoeven <geert@linux-m68k.org>
Date: Tue, 30 Mar 2021 11:47:30 +0200
Message-ID: <CAMuHMdXdhTUKuvJkJGUm=ESpwA6R06eKV5q6wFOJftJ1p3R7nw@mail.gmail.com>
Subject: Re: [PATCH v3 2/2] riscv: Cleanup KASAN_VMALLOC support
To: Palmer Dabbelt <palmer@dabbelt.com>
Cc: alex@ghiti.fr, Paul Walmsley <paul.walmsley@sifive.com>, 
	Albert Ou <aou@eecs.berkeley.edu>, nylon7@andestech.com, 
	Nick Hu <nickhu@andestech.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	linux-riscv <linux-riscv@lists.infradead.org>, 
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>, kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: geert@linux-m68k.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of geert.uytterhoeven@gmail.com designates 209.85.222.41
 as permitted sender) smtp.mailfrom=geert.uytterhoeven@gmail.com
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

Hi Palmer,

On Tue, Mar 30, 2021 at 7:08 AM Palmer Dabbelt <palmer@dabbelt.com> wrote:
> On Sat, 13 Mar 2021 00:45:05 PST (-0800), alex@ghiti.fr wrote:
> > When KASAN vmalloc region is populated, there is no userspace process and
> > the page table in use is swapper_pg_dir, so there is no need to read
> > SATP. Then we can use the same scheme used by kasan_populate_p*d
> > functions to go through the page table, which harmonizes the code.
> >
> > In addition, make use of set_pgd that goes through all unused page table
> > levels, contrary to p*d_populate functions, which makes this function work
> > whatever the number of page table levels.
> >
> > Signed-off-by: Alexandre Ghiti <alex@ghiti.fr>
> > Reviewed-by: Palmer Dabbelt <palmerdabbelt@google.com>
> > ---
> >  arch/riscv/mm/kasan_init.c | 59 ++++++++++++--------------------------
> >  1 file changed, 18 insertions(+), 41 deletions(-)
> >
> > diff --git a/arch/riscv/mm/kasan_init.c b/arch/riscv/mm/kasan_init.c
> > index 57bf4ae09361..c16178918239 100644
> > --- a/arch/riscv/mm/kasan_init.c
> > +++ b/arch/riscv/mm/kasan_init.c
> > @@ -11,18 +11,6 @@
> >  #include <asm/fixmap.h>
> >  #include <asm/pgalloc.h>
> >
> > -static __init void *early_alloc(size_t size, int node)
> > -{
> > -     void *ptr = memblock_alloc_try_nid(size, size,
> > -             __pa(MAX_DMA_ADDRESS), MEMBLOCK_ALLOC_ACCESSIBLE, node);
> > -
> > -     if (!ptr)
> > -             panic("%pS: Failed to allocate %zu bytes align=%zx nid=%d from=%llx\n",
> > -                     __func__, size, size, node, (u64)__pa(MAX_DMA_ADDRESS));
> > -
> > -     return ptr;
> > -}
> > -
> >  extern pgd_t early_pg_dir[PTRS_PER_PGD];
> >  asmlinkage void __init kasan_early_init(void)
> >  {
> > @@ -155,38 +143,27 @@ static void __init kasan_populate(void *start, void *end)
> >       memset(start, KASAN_SHADOW_INIT, end - start);
> >  }
> >
> > -void __init kasan_shallow_populate(void *start, void *end)
> > +static void __init kasan_shallow_populate_pgd(unsigned long vaddr, unsigned long end)
> >  {
> > -     unsigned long vaddr = (unsigned long)start & PAGE_MASK;
> > -     unsigned long vend = PAGE_ALIGN((unsigned long)end);
> > -     unsigned long pfn;
> > -     int index;
> > +     unsigned long next;
> >       void *p;
> > -     pud_t *pud_dir, *pud_k;
> > -     pgd_t *pgd_dir, *pgd_k;
> > -     p4d_t *p4d_dir, *p4d_k;
> > -
> > -     while (vaddr < vend) {
> > -             index = pgd_index(vaddr);
> > -             pfn = csr_read(CSR_SATP) & SATP_PPN;
> > -             pgd_dir = (pgd_t *)pfn_to_virt(pfn) + index;
> > -             pgd_k = init_mm.pgd + index;
> > -             pgd_dir = pgd_offset_k(vaddr);
> > -             set_pgd(pgd_dir, *pgd_k);
> > -
> > -             p4d_dir = p4d_offset(pgd_dir, vaddr);
> > -             p4d_k  = p4d_offset(pgd_k, vaddr);
> > -
> > -             vaddr = (vaddr + PUD_SIZE) & PUD_MASK;
> > -             pud_dir = pud_offset(p4d_dir, vaddr);
> > -             pud_k = pud_offset(p4d_k, vaddr);
> > -
> > -             if (pud_present(*pud_dir)) {
> > -                     p = early_alloc(PAGE_SIZE, NUMA_NO_NODE);
> > -                     pud_populate(&init_mm, pud_dir, p);
> > +     pgd_t *pgd_k = pgd_offset_k(vaddr);
> > +
> > +     do {
> > +             next = pgd_addr_end(vaddr, end);
> > +             if (pgd_page_vaddr(*pgd_k) == (unsigned long)lm_alias(kasan_early_shadow_pmd)) {
> > +                     p = memblock_alloc(PAGE_SIZE, PAGE_SIZE);
> > +                     set_pgd(pgd_k, pfn_pgd(PFN_DOWN(__pa(p)), PAGE_TABLE));
> >               }
> > -             vaddr += PAGE_SIZE;
> > -     }
> > +     } while (pgd_k++, vaddr = next, vaddr != end);
> > +}
> > +
> > +static void __init kasan_shallow_populate(void *start, void *end)
> > +{
> > +     unsigned long vaddr = (unsigned long)start & PAGE_MASK;
> > +     unsigned long vend = PAGE_ALIGN((unsigned long)end);
> > +
> > +     kasan_shallow_populate_pgd(vaddr, vend);
> >
> >       local_flush_tlb_all();
> >  }
>
> Thanks, this is on for-next.

Your for-next does not include your fixes branch, hence they now conflict,
and for-next lacks the local_flush_tlb_all().

Gr{oetje,eeting}s,

                        Geert

-- 
Geert Uytterhoeven -- There's lots of Linux beyond ia32 -- geert@linux-m68k.org

In personal conversations with technical people, I call myself a hacker. But
when I'm talking to journalists I just say "programmer" or something like that.
                                -- Linus Torvalds

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAMuHMdXdhTUKuvJkJGUm%3DESpwA6R06eKV5q6wFOJftJ1p3R7nw%40mail.gmail.com.
