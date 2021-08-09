Return-Path: <kasan-dev+bncBC7OBJGL2MHBBVM7YSEAMGQEVXI6OCI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1038.google.com (mail-pj1-x1038.google.com [IPv6:2607:f8b0:4864:20::1038])
	by mail.lfdr.de (Postfix) with ESMTPS id 8D6CE3E4490
	for <lists+kasan-dev@lfdr.de>; Mon,  9 Aug 2021 13:21:58 +0200 (CEST)
Received: by mail-pj1-x1038.google.com with SMTP id d35-20020a17090a6f26b0290178ab46154dsf1874767pjk.3
        for <lists+kasan-dev@lfdr.de>; Mon, 09 Aug 2021 04:21:58 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1628508117; cv=pass;
        d=google.com; s=arc-20160816;
        b=dz7BUXusCp6msJm6nVwV4IT3Li3o8d7lEDCEWo/bwJcHtma9DyhWvvSMkU3PmdHYvn
         wF1LR1kC7zF9h4ycoYdU2w5iKDT03AEINAkbr9uos7x5Lf2RI4y8ap8C+eumY9CIhG7l
         CCsCSqt4Ecdbk1JsDtS7Q503t1P+cBo/B0nMIsaCcQywyhkRuclxjpx1ZSqzNMsYEKc0
         UCEA7pOM6eaMzzQmwcKUDbs4g6TiyEpJV77JfSaHsTitmk/rWT+4VikA5XdAvv0CKSrM
         xnCoaVJS+PIeYOb+0tpjYGZsAbgPhLEZMsEnmBsAptI/P/zMb/KW+M8jjxn9FyY2+WIb
         8DAQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=2FbawvZVGnCTWohRosvm4O95oG1jwIPJEqjNbJ0Ae8M=;
        b=jTAOpU4niZ0ml3/wssP/1wBFKtCtfFzOFLTJkjNfVLiErwfjXXFsvNJNhFZRuslRnt
         oc2A2s3Xuo89HKyucScelrVP2oJJ2c7dIlO8gDid984ZDKSorIaVjsbCWI0dCowcNHmA
         jA8YIV+5Cd7LiBqgpP/LBuKYUQLwcSj+dUmTcfSTpeJEqVDwVxQlIh/wYhaxqS/hURkY
         FAcUUZEyQeXO9DLxlkAEP6Di+UDw3SA2pFDM60cnxTjmmw29yXfx7gaZKWSITaho2aet
         IQ4d/WI1qoEpC9fm4Aj8neb54HFHocRmC3iXhHube7aWhXGmkjtQ9GavqkvMZiTTbmIJ
         1cXQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=nTtfeLWm;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22c as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=2FbawvZVGnCTWohRosvm4O95oG1jwIPJEqjNbJ0Ae8M=;
        b=AgcbWENaJafGPX0PzdTpKD/qTNkI4vS7hgQ28HxzHujIBg6RcQU/TMgAC3R4jQpRuY
         ay17GPR2hF2dZsUo2KLsCEF54xPmkFQMDs2PngLFIXXduMduZ9Mqo7ld4CB5U0LJFyYB
         vXtZGHDezrqkVJIPdSEqF8Om2IEw31FEzNyVKp7VitZOxEv0BPSeN7Uhg75/h8PQbFSW
         cnuTb4rlNrkGc0jZxmktroKanhuIeZXmciBzMCBc15IVuNCmNbpMuR8tP3VvTLWOPHB4
         iifLg+jvJ4ONSWrf08L59fBnuTdhVPBqx9Q4kpcwtSeyhqTkWm8MdFMzFjJQE3w3Ut6n
         Yq5g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=2FbawvZVGnCTWohRosvm4O95oG1jwIPJEqjNbJ0Ae8M=;
        b=lg+JofYawWEkC4FJgfVr5vcBdnBNXMI9X8pPwJN2E5KV+XZxgEYlHfXWf7cl8z5RVF
         QhP19Mmy00TtIA7H1NDYi7U7+nwiajV2OZ8Hl9Kkr5ygb47GehW8Qm3W5dvtiBc0BxZ4
         5y7tbs8ApkhZrDfP2MmbLyPyIAkOoxWWamQcPkAG2DpH6aJlmOLZwvOwLKSdCUiNE45g
         uJXMEgqWPXh0C1SA9/vRwejpd6ad62OvrGjfMFoPVRdqcUkAYHj6f68qocK9/28uAIar
         QHdIqmSIwlTXuBBPHg88mEuIy8I4+URnnLa9Cnnf1ppLo57oze5XathMniIKA24xS7H7
         bW5A==
X-Gm-Message-State: AOAM532kBNAjJ/hEkkCX/+2oKeRbDVSVJS/ZrrfYxjEfTrqL/91cSlhG
	xJ++SeVXIlImpHhdl8u9OB8=
X-Google-Smtp-Source: ABdhPJx4b04uSti34el5EhqO7/hxfAlmhHneC1b58WcnqpLpezvrEhPnblKO5nqe1SZS9wpCzTtP6A==
X-Received: by 2002:a17:902:c204:b029:12c:3ac4:b362 with SMTP id 4-20020a170902c204b029012c3ac4b362mr5481295pll.10.1628508117150;
        Mon, 09 Aug 2021 04:21:57 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:1946:: with SMTP id s6ls6010722pfk.8.gmail; Mon, 09
 Aug 2021 04:21:56 -0700 (PDT)
X-Received: by 2002:a62:878c:0:b029:3c5:f729:ef00 with SMTP id i134-20020a62878c0000b02903c5f729ef00mr17889476pfe.43.1628508116529;
        Mon, 09 Aug 2021 04:21:56 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1628508116; cv=none;
        d=google.com; s=arc-20160816;
        b=BblCsUvR/E1xx7dccI5R1FYJD4rKmrsqEbWD7p3jb0NV1kyD3Xq256K+ACAuIKayBB
         k466lYRWePcuT4s9e9fTXsnGsUOzOKcxfNamd03z4lwIjnmOmywc/Ds0ma486oH2zV5h
         JcUgsGb8qS9RaJFy+AszHznOMSa+LIzitpy3yGwKqrrSydlp0xudNmekfs/ecQAIfWhh
         nwnuPuBZzDeuMxWhT4HcMaFM0pmyUlWwQvBJ2uBdIp399RzdfxLby9RiPnQVbi3ef87m
         0bmcwut3tkCqPZTOSLZwrDay00Wp3GxiKyR8Udpmc9E67zJXGWwL2dFZFIgvZh6yP2hQ
         Wwng==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=MkFYGolSn2w76q7qvE9Vgn56UKUzs1q54gLC/lVyUL0=;
        b=ZWdkOw6NSb3AK96xsB/rQMZXJviZsv1/R0eiUsO5zMIg8T2ezNejwxyXUg0wO3Ycdc
         CgoBbfazeeDOogUEa87wrxQfZl7wj11LO2BD5ZJKs4oH9mcIaQC5azp8VyDHwlP2InUk
         /Ib7UnkiZXAX3/thNAEH8Pcljh52qktR31rleUUALDMPgdua5nensWP0B67Swci+D4g9
         y5fhqSsykNw6chmBwx5Anz6GyQPTMBuiDNN74EXcumf1aPPYQtEQA/E61Cg2s08LDTvk
         yJl7ulQEY4y2vDZCl62mu9oWYmkBq72ybfO3Xyy2Sm+PxrDpW0QDlB34xMw5cMi4JRmC
         CMfQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=nTtfeLWm;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22c as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x22c.google.com (mail-oi1-x22c.google.com. [2607:f8b0:4864:20::22c])
        by gmr-mx.google.com with ESMTPS id i123si156872pfb.1.2021.08.09.04.21.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 09 Aug 2021 04:21:56 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22c as permitted sender) client-ip=2607:f8b0:4864:20::22c;
Received: by mail-oi1-x22c.google.com with SMTP id bj40so3388900oib.6
        for <kasan-dev@googlegroups.com>; Mon, 09 Aug 2021 04:21:56 -0700 (PDT)
X-Received: by 2002:aca:2316:: with SMTP id e22mr9967822oie.172.1628508115719;
 Mon, 09 Aug 2021 04:21:55 -0700 (PDT)
MIME-Version: 1.0
References: <20210809093750.131091-1-wangkefeng.wang@huawei.com>
 <20210809093750.131091-4-wangkefeng.wang@huawei.com> <ae15c02e-d825-dbef-1419-5b5220f826c1@huawei.com>
In-Reply-To: <ae15c02e-d825-dbef-1419-5b5220f826c1@huawei.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 9 Aug 2021 13:21:44 +0200
Message-ID: <CANpmjNOM-fzk2_q9LNLgM1wSReHWj42MxHBeDBLg8Ga5vv8HhQ@mail.gmail.com>
Subject: Re: [PATCH v3 3/3] kasan: arm64: Fix pcpu_page_first_chunk crash with KASAN_VMALLOC
To: Kefeng Wang <wangkefeng.wang@huawei.com>
Cc: will@kernel.org, catalin.marinas@arm.com, ryabinin.a.a@gmail.com, 
	andreyknvl@gmail.com, dvyukov@google.com, 
	linux-arm-kernel@lists.infradead.org, linux-kernel@vger.kernel.org, 
	kasan-dev@googlegroups.com, linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=nTtfeLWm;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22c as
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

On Mon, 9 Aug 2021 at 13:10, Kefeng Wang <wangkefeng.wang@huawei.com> wrote:
>
>
> On 2021/8/9 17:37, Kefeng Wang wrote:
> > With KASAN_VMALLOC and NEED_PER_CPU_PAGE_FIRST_CHUNK, it crashs,
> >
> > Unable to handle kernel paging request at virtual address ffff7000028f2000
> > ...
> > swapper pgtable: 64k pages, 48-bit VAs, pgdp=0000000042440000
> > [ffff7000028f2000] pgd=000000063e7c0003, p4d=000000063e7c0003, pud=000000063e7c0003, pmd=000000063e7b0003, pte=0000000000000000
> > Internal error: Oops: 96000007 [#1] PREEMPT SMP
> > Modules linked in:
> > CPU: 0 PID: 0 Comm: swapper Not tainted 5.13.0-rc4-00003-gc6e6e28f3f30-dirty #62
> > Hardware name: linux,dummy-virt (DT)
> > pstate: 200000c5 (nzCv daIF -PAN -UAO -TCO BTYPE=--)
> > pc : kasan_check_range+0x90/0x1a0
> > lr : memcpy+0x88/0xf4
> > sp : ffff80001378fe20
> > ...
> > Call trace:
> >   kasan_check_range+0x90/0x1a0
> >   pcpu_page_first_chunk+0x3f0/0x568
> >   setup_per_cpu_areas+0xb8/0x184
> >   start_kernel+0x8c/0x328
> >
> > The vm area used in vm_area_register_early() has no kasan shadow memory,
> > Let's add a new kasan_populate_early_vm_area_shadow() function to populate
> > the vm area shadow memory to fix the issue.
>
> Should add Acked-by: Marco Elver <elver@google.com> [for KASAN parts] ,

My Ack is still valid, thanks for noting.

> > Signed-off-by: Kefeng Wang <wangkefeng.wang@huawei.com>
> > ---
> >   arch/arm64/mm/kasan_init.c | 16 ++++++++++++++++
> >   include/linux/kasan.h      |  6 ++++++
> >   mm/kasan/init.c            |  5 +++++
> >   mm/vmalloc.c               |  1 +
> >   4 files changed, 28 insertions(+)
> >
> > diff --git a/arch/arm64/mm/kasan_init.c b/arch/arm64/mm/kasan_init.c
> > index 61b52a92b8b6..5b996ca4d996 100644
> > --- a/arch/arm64/mm/kasan_init.c
> > +++ b/arch/arm64/mm/kasan_init.c
> > @@ -287,6 +287,22 @@ static void __init kasan_init_depth(void)
> >       init_task.kasan_depth = 0;
> >   }
> >
> > +#ifdef CONFIG_KASAN_VMALLOC
> > +void __init kasan_populate_early_vm_area_shadow(void *start, unsigned long size)
> > +{
> > +     unsigned long shadow_start, shadow_end;
> > +
> > +     if (!is_vmalloc_or_module_addr(start))
> > +             return;
> > +
> > +     shadow_start = (unsigned long)kasan_mem_to_shadow(start);
> > +     shadow_start = ALIGN_DOWN(shadow_start, PAGE_SIZE);
> > +     shadow_end = (unsigned long)kasan_mem_to_shadow(start + size);
> > +     shadow_end = ALIGN(shadow_end, PAGE_SIZE);
> > +     kasan_map_populate(shadow_start, shadow_end, NUMA_NO_NODE);
> > +}
> > +#endif
> > +
> >   void __init kasan_init(void)
> >   {
> >       kasan_init_shadow();
> > diff --git a/include/linux/kasan.h b/include/linux/kasan.h
> > index dd874a1ee862..3f8c26d9ef82 100644
> > --- a/include/linux/kasan.h
> > +++ b/include/linux/kasan.h
> > @@ -133,6 +133,8 @@ struct kasan_cache {
> >       bool is_kmalloc;
> >   };
> >
> > +void kasan_populate_early_vm_area_shadow(void *start, unsigned long size);
> > +
> >   slab_flags_t __kasan_never_merge(void);
> >   static __always_inline slab_flags_t kasan_never_merge(void)
> >   {
> > @@ -303,6 +305,10 @@ void kasan_restore_multi_shot(bool enabled);
> >
> >   #else /* CONFIG_KASAN */
> >
> > +static inline void kasan_populate_early_vm_area_shadow(void *start,
> > +                                                    unsigned long size)
> > +{ }
> > +
> >   static inline slab_flags_t kasan_never_merge(void)
> >   {
> >       return 0;
> > diff --git a/mm/kasan/init.c b/mm/kasan/init.c
> > index cc64ed6858c6..d39577d088a1 100644
> > --- a/mm/kasan/init.c
> > +++ b/mm/kasan/init.c
> > @@ -279,6 +279,11 @@ int __ref kasan_populate_early_shadow(const void *shadow_start,
> >       return 0;
> >   }
> >
> > +void __init __weak kasan_populate_early_vm_area_shadow(void *start,
> > +                                                    unsigned long size)
> > +{
> > +}
> > +
> >   static void kasan_free_pte(pte_t *pte_start, pmd_t *pmd)
> >   {
> >       pte_t *pte;
> > diff --git a/mm/vmalloc.c b/mm/vmalloc.c
> > index 1e8fe08725b8..66a7e1ea2561 100644
> > --- a/mm/vmalloc.c
> > +++ b/mm/vmalloc.c
> > @@ -2253,6 +2253,7 @@ void __init vm_area_register_early(struct vm_struct *vm, size_t align)
> >       vm->addr = (void *)addr;
> >
> >       vm_area_add_early(vm);
> > +     kasan_populate_early_vm_area_shadow(vm->addr, vm->size);
> >   }
> >
> >   static void vmap_init_free_space(void)

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNOM-fzk2_q9LNLgM1wSReHWj42MxHBeDBLg8Ga5vv8HhQ%40mail.gmail.com.
