Return-Path: <kasan-dev+bncBCRKNY4WZECBBOVU36BQMGQEDI3EAXI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe40.google.com (mail-vs1-xe40.google.com [IPv6:2607:f8b0:4864:20::e40])
	by mail.lfdr.de (Postfix) with ESMTPS id 795BC360236
	for <lists+kasan-dev@lfdr.de>; Thu, 15 Apr 2021 08:16:28 +0200 (CEST)
Received: by mail-vs1-xe40.google.com with SMTP id h24-20020a67c1980000b029020d0246231asf2417939vsj.0
        for <lists+kasan-dev@lfdr.de>; Wed, 14 Apr 2021 23:16:28 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1618467387; cv=pass;
        d=google.com; s=arc-20160816;
        b=Vnpa5W6iKDqjEXW0pV7hR2hIOeBk9ZUKc2o2QIR8Sxdy7NtXAyLRaU5pK3tnWzrFAE
         r5/gTeKwUr0RsAo/NKyrBDIk4iG8aTrfMKb0irzizje8nDPYCwNB44RvF9Ny7ftRd0F5
         qWJ0gow9nohSIl2zeK2JaSLfNaoqUrct8nxMDtZb5skSXgxWFHhtI7gjZd7ThoL7advg
         hh5Xh2K0om20NXB5VnFmuhqg4Tb/9ppwQhm1hWM0WQM26rRvjYtkSOr5nfxaE/YHFswU
         G4BOi57Jh2LOniYz5oN3FlyC3q1T+TKaoM/LTFCW99h3JM4ZYiQ6s+aC5x4VWvbQ2a+x
         KTRQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:to:from:cc
         :in-reply-to:subject:date:sender:dkim-signature;
        bh=blUcIuvcCiGJaKbJdSwgUemOTEgQvOqc2OpwiT8/4V0=;
        b=v23+qq05ynvAcvpuBc2evZNlULSFze2wIR49Exikjbufo+mgeqTMHnp/uvdApDJZ5u
         NWFezhwRoOz4skxztvPqbpIU7gX71KXYlBbfYlLXhL3QQ/saLpXkfkL0/xicSNpHUm6S
         oO/BG3rXEINjZHb8xFjMnJZDfqbukT7RbjGag1Owwc4hcFq6B9o61mPhE+/ppzPJZ04N
         rBzR6FC8WW8FsVf2vm5Ahh99SjS4HUdjxta3cKXwP5ipS2r5H3RtEaItm5Eq2MDDdzRk
         BLij3+LnUnqAKS67MZAnRzknZKbiZweNm2TEFRfA+A8ZEVsJmatDmdB+Ug0R41AF/3Hs
         JK7g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@dabbelt-com.20150623.gappssmtp.com header.s=20150623 header.b=S2hDQvA6;
       spf=pass (google.com: domain of palmer@dabbelt.com designates 2607:f8b0:4864:20::102a as permitted sender) smtp.mailfrom=palmer@dabbelt.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:subject:in-reply-to:cc:from:to:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=blUcIuvcCiGJaKbJdSwgUemOTEgQvOqc2OpwiT8/4V0=;
        b=hofkd81Z+mdxM3MrQ3/xdGEsWbbiGBmsCp60kFWnaYzg6iYwMmjJqv1C7+4oRf9wor
         awlRiVYlOgQwkBLGOXjQDTrEh8av7zAFwgCmAs3xtsNl2QNkUrTa03UTn8XsVtFfvA2O
         kA1JEfb3jQnEuxnUEb4A2TldQZ6O/s4jSJmFjspS4vxMBkQpk8Z7DvKeGfF52/wU0UOW
         D2HzI3nggDkiHB2S8wit/ls7c5kDmCcIqnX8yRvzgBS1LNb6y476AuDbHv8bAifhiec0
         8AqYoLdDwY/VPLZxlTYwJiBzzIWH0h2KfXZ/UxVu1a1x9Fpp9lKxYIfdnx/gkuol2CuR
         xgAg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:subject:in-reply-to:cc:from:to
         :message-id:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=blUcIuvcCiGJaKbJdSwgUemOTEgQvOqc2OpwiT8/4V0=;
        b=puC+K3QLh3nR5MGLg2jMQNADQe3IDMbMpJXgmw+5uAQPNdDhjIspA/xhlNLcRwIy4E
         USjaK7Ut2qJKZyN6JSR7xI19kTjqoou/Y8QG2Wy3sSx5jhUeAlJWIPIIcKsEMSkFfP9E
         VNcC0RbLAf0g/gru2ypu5CXPhy8C4rHl2f3gDCMa40gYyy7MWzgHFQxcMCoPjNxEb8wD
         rVMq2a116++AmNquu3cV7nx+LetaXsuNBSW0eN/rEGlQHeYtOw+bKAB1ehR3dvDCXJIv
         8C9FCUfGHyilijDKm6hwukg1wzGYKQqNy6QCRToT/puXeaH3dIlLkw/BUrpC4R3WX966
         HaZQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530jQQ/krYmAPc65H/TWOx4+kE6RhKrS3YAhPIE1HB3miDp/aoxI
	0V8ELdns3WQLQiqHLBOXi4A=
X-Google-Smtp-Source: ABdhPJxKT0V4ImmxRzZpCjRXoJuHJWsA/ZtK1sEff6QhNA30mdPyjmonWcsrmg8H9/y/QwHnnhYk8g==
X-Received: by 2002:a05:6122:54:: with SMTP id q20mr702719vkn.3.1618467387176;
        Wed, 14 Apr 2021 23:16:27 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:2702:: with SMTP id n2ls708913vsn.2.gmail; Wed, 14 Apr
 2021 23:16:26 -0700 (PDT)
X-Received: by 2002:a67:4c6:: with SMTP id 189mr1091319vse.0.1618467386546;
        Wed, 14 Apr 2021 23:16:26 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1618467386; cv=none;
        d=google.com; s=arc-20160816;
        b=K/boGUqn6QL/kCbUkm161kGvsTfNQZBb9my9GONE/yGyZ/6x+/J01v8Z+z8bdg2YOu
         y43Xu9ChvwgOpGAuHxLt/s2MJK/xBTV81sn3I6+eiS6L7/n6aBjqAR2nYkvAYhucMTJA
         x/aNRHtkp4qVov8OCsH6Re5c/+tNHxf+ku2KoHH+I9nZMKjkQ1+1fKcH5i20z3sOEvRA
         ZFlTDtU0eHWlganr5eA4gN1Uj7qjE3vypwVPOtbycSOkBullTX0TeDAeRdtXxxAlfGPr
         VeivNj/DYlKDyeY0C3NGNAm4YvSEvQxS8FX4PuTKxauE5eLxJ+WHOOJpZFv7ol5fsfvQ
         R8hA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:to:from:cc
         :in-reply-to:subject:date:dkim-signature;
        bh=8aPMWJgLeOMSHDPtfmh56WRL1jMhYN833mNKhQBp9lg=;
        b=Uok1LDkokbqyC1rtThgFw2CUgsSxaYBVMz0ZEHNaOOw8PjAmZTJeqjH0MddD9P1Uen
         NgntxyAC9essSZKLUlwvFBb9U5liVh/WpkxIimIo7LB33guEKQyrxoi9INyY1i0xOx8N
         YwUU+VIJshHaEwoUCIH8Xh8RiDvUNdmjIR7IFwNXs+nq5MHL8Wc64RwX5W1xmigOoQOc
         q+zCNCRkMs8vccAfPz+9+E/dWdhvjzE+DfWDz3DHacKBS4Cu0inia4S78LSG/8BiLhB+
         90FpmyFV5gVdcuhlZJJagpZnhgvq+Q65pIacMVXI93FUfofVq4lzZXqXSZvq7PZkA04Y
         UE9g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@dabbelt-com.20150623.gappssmtp.com header.s=20150623 header.b=S2hDQvA6;
       spf=pass (google.com: domain of palmer@dabbelt.com designates 2607:f8b0:4864:20::102a as permitted sender) smtp.mailfrom=palmer@dabbelt.com
Received: from mail-pj1-x102a.google.com (mail-pj1-x102a.google.com. [2607:f8b0:4864:20::102a])
        by gmr-mx.google.com with ESMTPS id k26si98173vsq.0.2021.04.14.23.16.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 14 Apr 2021 23:16:26 -0700 (PDT)
Received-SPF: pass (google.com: domain of palmer@dabbelt.com designates 2607:f8b0:4864:20::102a as permitted sender) client-ip=2607:f8b0:4864:20::102a;
Received: by mail-pj1-x102a.google.com with SMTP id r13so7719930pjf.2
        for <kasan-dev@googlegroups.com>; Wed, 14 Apr 2021 23:16:26 -0700 (PDT)
X-Received: by 2002:a17:90a:670a:: with SMTP id n10mr2087887pjj.176.1618467385372;
        Wed, 14 Apr 2021 23:16:25 -0700 (PDT)
Received: from localhost (76-210-143-223.lightspeed.sntcca.sbcglobal.net. [76.210.143.223])
        by smtp.gmail.com with ESMTPSA id m9sm1242059pgt.65.2021.04.14.23.16.24
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 14 Apr 2021 23:16:24 -0700 (PDT)
Date: Wed, 14 Apr 2021 23:16:24 -0700 (PDT)
Subject: Re: [PATCH v3 2/2] riscv: Cleanup KASAN_VMALLOC support
In-Reply-To: <CAMuHMdXdhTUKuvJkJGUm=ESpwA6R06eKV5q6wFOJftJ1p3R7nw@mail.gmail.com>
CC: alex@ghiti.fr, Paul Walmsley <paul.walmsley@sifive.com>, aou@eecs.berkeley.edu,
  nylon7@andestech.com, nickhu@andestech.com, aryabinin@virtuozzo.com, glider@google.com,
  dvyukov@google.com, linux-riscv@lists.infradead.org, linux-kernel@vger.kernel.org,
  kasan-dev@googlegroups.com
From: Palmer Dabbelt <palmer@dabbelt.com>
To: geert@linux-m68k.org
Message-ID: <mhng-93309746-0fd6-42ec-b574-bf1ce486f34a@palmerdabbelt-glaptop>
Mime-Version: 1.0 (MHng)
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: palmer@dabbelt.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@dabbelt-com.20150623.gappssmtp.com header.s=20150623
 header.b=S2hDQvA6;       spf=pass (google.com: domain of palmer@dabbelt.com
 designates 2607:f8b0:4864:20::102a as permitted sender) smtp.mailfrom=palmer@dabbelt.com
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

On Tue, 30 Mar 2021 02:47:30 PDT (-0700), geert@linux-m68k.org wrote:
> Hi Palmer,
>
> On Tue, Mar 30, 2021 at 7:08 AM Palmer Dabbelt <palmer@dabbelt.com> wrote:
>> On Sat, 13 Mar 2021 00:45:05 PST (-0800), alex@ghiti.fr wrote:
>> > When KASAN vmalloc region is populated, there is no userspace process and
>> > the page table in use is swapper_pg_dir, so there is no need to read
>> > SATP. Then we can use the same scheme used by kasan_populate_p*d
>> > functions to go through the page table, which harmonizes the code.
>> >
>> > In addition, make use of set_pgd that goes through all unused page table
>> > levels, contrary to p*d_populate functions, which makes this function work
>> > whatever the number of page table levels.
>> >
>> > Signed-off-by: Alexandre Ghiti <alex@ghiti.fr>
>> > Reviewed-by: Palmer Dabbelt <palmerdabbelt@google.com>
>> > ---
>> >  arch/riscv/mm/kasan_init.c | 59 ++++++++++++--------------------------
>> >  1 file changed, 18 insertions(+), 41 deletions(-)
>> >
>> > diff --git a/arch/riscv/mm/kasan_init.c b/arch/riscv/mm/kasan_init.c
>> > index 57bf4ae09361..c16178918239 100644
>> > --- a/arch/riscv/mm/kasan_init.c
>> > +++ b/arch/riscv/mm/kasan_init.c
>> > @@ -11,18 +11,6 @@
>> >  #include <asm/fixmap.h>
>> >  #include <asm/pgalloc.h>
>> >
>> > -static __init void *early_alloc(size_t size, int node)
>> > -{
>> > -     void *ptr = memblock_alloc_try_nid(size, size,
>> > -             __pa(MAX_DMA_ADDRESS), MEMBLOCK_ALLOC_ACCESSIBLE, node);
>> > -
>> > -     if (!ptr)
>> > -             panic("%pS: Failed to allocate %zu bytes align=%zx nid=%d from=%llx\n",
>> > -                     __func__, size, size, node, (u64)__pa(MAX_DMA_ADDRESS));
>> > -
>> > -     return ptr;
>> > -}
>> > -
>> >  extern pgd_t early_pg_dir[PTRS_PER_PGD];
>> >  asmlinkage void __init kasan_early_init(void)
>> >  {
>> > @@ -155,38 +143,27 @@ static void __init kasan_populate(void *start, void *end)
>> >       memset(start, KASAN_SHADOW_INIT, end - start);
>> >  }
>> >
>> > -void __init kasan_shallow_populate(void *start, void *end)
>> > +static void __init kasan_shallow_populate_pgd(unsigned long vaddr, unsigned long end)
>> >  {
>> > -     unsigned long vaddr = (unsigned long)start & PAGE_MASK;
>> > -     unsigned long vend = PAGE_ALIGN((unsigned long)end);
>> > -     unsigned long pfn;
>> > -     int index;
>> > +     unsigned long next;
>> >       void *p;
>> > -     pud_t *pud_dir, *pud_k;
>> > -     pgd_t *pgd_dir, *pgd_k;
>> > -     p4d_t *p4d_dir, *p4d_k;
>> > -
>> > -     while (vaddr < vend) {
>> > -             index = pgd_index(vaddr);
>> > -             pfn = csr_read(CSR_SATP) & SATP_PPN;
>> > -             pgd_dir = (pgd_t *)pfn_to_virt(pfn) + index;
>> > -             pgd_k = init_mm.pgd + index;
>> > -             pgd_dir = pgd_offset_k(vaddr);
>> > -             set_pgd(pgd_dir, *pgd_k);
>> > -
>> > -             p4d_dir = p4d_offset(pgd_dir, vaddr);
>> > -             p4d_k  = p4d_offset(pgd_k, vaddr);
>> > -
>> > -             vaddr = (vaddr + PUD_SIZE) & PUD_MASK;
>> > -             pud_dir = pud_offset(p4d_dir, vaddr);
>> > -             pud_k = pud_offset(p4d_k, vaddr);
>> > -
>> > -             if (pud_present(*pud_dir)) {
>> > -                     p = early_alloc(PAGE_SIZE, NUMA_NO_NODE);
>> > -                     pud_populate(&init_mm, pud_dir, p);
>> > +     pgd_t *pgd_k = pgd_offset_k(vaddr);
>> > +
>> > +     do {
>> > +             next = pgd_addr_end(vaddr, end);
>> > +             if (pgd_page_vaddr(*pgd_k) == (unsigned long)lm_alias(kasan_early_shadow_pmd)) {
>> > +                     p = memblock_alloc(PAGE_SIZE, PAGE_SIZE);
>> > +                     set_pgd(pgd_k, pfn_pgd(PFN_DOWN(__pa(p)), PAGE_TABLE));
>> >               }
>> > -             vaddr += PAGE_SIZE;
>> > -     }
>> > +     } while (pgd_k++, vaddr = next, vaddr != end);
>> > +}
>> > +
>> > +static void __init kasan_shallow_populate(void *start, void *end)
>> > +{
>> > +     unsigned long vaddr = (unsigned long)start & PAGE_MASK;
>> > +     unsigned long vend = PAGE_ALIGN((unsigned long)end);
>> > +
>> > +     kasan_shallow_populate_pgd(vaddr, vend);
>> >
>> >       local_flush_tlb_all();
>> >  }
>>
>> Thanks, this is on for-next.
>
> Your for-next does not include your fixes branch, hence they now conflict,
> and for-next lacks the local_flush_tlb_all().

This came up before and I don't think we ever sorted out what the right 
thing to do is.  Right now I'm keeping for-next pinned an at early RC, 
but fast-forwarding fixes to the latest RC every time I sent a PR.  I 
don't have fixes merged back into for-next because I don't want those 
merges to show up when I send my merge window PRs.

For this one I purposefully left out the local_flush_tlb_all() whene I 
pulled in this patch, and was planning on fixing it up along with any 
other merge conflicts when I send along the PR.  It does all seem like a 
bit of a song and dance here, though, so I'm open to suggestions as to 
how to run this better -- though last time I went through that exercise 
it seemed like everyone had their own way of doing it, they all had a 
different set of issues, and I was at least familiar with this flavor of 
craziness.

I was kind of tempted to convert for-next over into a branch that only 
contains merges, though, which would make it a bit easier to merge fixes 
in.

>
> Gr{oetje,eeting}s,
>
>                         Geert

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/mhng-93309746-0fd6-42ec-b574-bf1ce486f34a%40palmerdabbelt-glaptop.
