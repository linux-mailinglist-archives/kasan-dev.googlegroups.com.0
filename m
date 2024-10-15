Return-Path: <kasan-dev+bncBAABBUN7XG4AMGQE4IXQZKA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb40.google.com (mail-yb1-xb40.google.com [IPv6:2607:f8b0:4864:20::b40])
	by mail.lfdr.de (Postfix) with ESMTPS id 17AD799E9CE
	for <lists+kasan-dev@lfdr.de>; Tue, 15 Oct 2024 14:28:03 +0200 (CEST)
Received: by mail-yb1-xb40.google.com with SMTP id 3f1490d57ef6-e292d801e59sf4871973276.0
        for <lists+kasan-dev@lfdr.de>; Tue, 15 Oct 2024 05:28:03 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1728995282; cv=pass;
        d=google.com; s=arc-20240605;
        b=XAF1mG5Cy/KYM32SIvin6k7B5eXZy66A2/oF4jhCkJJViNV3Eb1PLAFL5OJChMmAIq
         6AmCu0ggqm8sz2fwpnzHuF68mM+prz6CVosGX6ZjZc8ARmSJNxCtnQnTmR3GL4hWuROL
         fVKPwBNYERX/aQKlwV9X/JcUjitX6W95owWRjeKNTnE0mn7Q6lsXX6s0YAOQbVFE3TqL
         1W4jwy0DRCpnGfSF2njXQJ3Y4Z2MmxRQ7Gkx26EcraAN8eKSE1GZA9sYaCNEW5+gVSs2
         kF26CQpfuVElefDOUHpRD2mYL6Fy7+LKm2d0jGpT6qqXlfcXKK27ESpvyGYz4MlmtvBJ
         KQ+g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=9Um6KwyK+X2DDfRBz4DrxFhXN4TiuqJGQf9KWFp3L8s=;
        fh=R0hjJRcxRpZlwDedUe0jmBLtTmVRSlbHtIJkfHae0hA=;
        b=WNp2zJhRpeqpJKi/A3bmR2dflGI2X9ZwdzSZuoN4WUKXseYtjEuDrihmf1fXw+8uan
         gDQeNn8Mw6PRXtNmfem10tfXGrU4JhzSVqwJ0suJrBcL+MFrZY3Q3Q6nmEXXv2DajhxK
         584keUgFx9xQjAsTAvfMrPgij7U9r8fQP5zxOBzbSgyCf/a4iQ50b9UAUlsxfxfAWJzj
         8m/n9V40R8jQVbfIp/9a+UR917ZJ33v1BaFwIq9kf5Rbf9UeKQN7xzHX1i60RlgLt2UC
         OcHX0mjUM94VszV61F5e5SnLh+kF5eMPnaDcuQ8BU1t96Bvn/ZtIqyETBRX0xcVtYCHJ
         A/Dw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=DKRcuqPu;
       spf=pass (google.com: domain of chenhuacai@kernel.org designates 147.75.193.91 as permitted sender) smtp.mailfrom=chenhuacai@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1728995282; x=1729600082; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=9Um6KwyK+X2DDfRBz4DrxFhXN4TiuqJGQf9KWFp3L8s=;
        b=ZTWrYTNEU60iYJNuBXvQ2Mh00J8ZWbUqufvt2rOYdpH8wQbxUcEWltck29b57O2dP9
         dS7JF2e/HSO7VftOvadMRFrSBg01hlH0ByjZd0+5b7gylwVcuUUdbF94FRVhuLnRY7Sp
         ruCcPTSdsnqNakBcWZfO8AO57IzKNL2w8QK6KGCxjbBruy22Jde7xtyPmeZB5ItJupIm
         SFIEkgZm7xJEmovtW494P9kmuwkC8KimwYQLUG9l/DzJvciU0yoCLallYd/HRdyGKLsv
         b1SJH0MikQGJQrLlgQNQTW1vQFwcmFj78PotponGrCiR9CHm2MBGS/dYsoQHhv0MfuD9
         QSJQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1728995282; x=1729600082;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=9Um6KwyK+X2DDfRBz4DrxFhXN4TiuqJGQf9KWFp3L8s=;
        b=SPoYbbLxDNRNQtQWR98kmEWwg3g/Purui+b+njLVA9D8P0JHlJD4pBafq2jMNrswij
         PfP+SUTgleuehQaMhft/LW6qIvz0NEUd3u96pY+tEjxUQFexR4mM9qi1j4lrtx6UfC07
         Pibp2LZxz6c64ruGwwr3OPNfIueylIY8a3mW4IAAJaLKwf7GvvND1djH4o5r8djlqfyi
         hGfJMaZMoOPCfEo5CVwTiCOmuwtM6lZSAfhqnezJHUixCMNKNzfxHOivSv3nghhCYsNz
         jaecoCl4wsr9DKt5cxwgXdE7XIeQSOv9bn1hwPlQYhRc61cTadTLV0m10Kw5dv2UnobS
         OA4g==
X-Forwarded-Encrypted: i=2; AJvYcCUxTV3Iw33WmPSHOhXxHothv8mTgElHLgKf6T3+YOqjppNOgGaT8Isbw3zCBYtUG5+iqwcM4Q==@lfdr.de
X-Gm-Message-State: AOJu0YyHr+nd1hSTO8UxJGcjgfie1F1cu2bNh+vqrXTU3TZxejFMTbdI
	FZ5VZJRCFakIUUA3oW/m3PguroG5BRhEhAvGTK1p/Bxi+qRdAfW+
X-Google-Smtp-Source: AGHT+IHtisblzMMJYuAZKLLeg2Hq3truZrm2+tFSio2NlXg1vUjTDqqiU6pinkZKuk+61G/Ulw6yhw==
X-Received: by 2002:a05:6902:108e:b0:e11:45fa:e344 with SMTP id 3f1490d57ef6-e2919fe6fd2mr11059026276.43.1728995281585;
        Tue, 15 Oct 2024 05:28:01 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6902:1008:b0:e22:59c6:5d26 with SMTP id
 3f1490d57ef6-e290bb929d2ls586716276.2.-pod-prod-01-us; Tue, 15 Oct 2024
 05:28:01 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCX0qqcu13b8UKalsIx/rrj4nh/6oZl66E3XOre1Aq7F4CFca1z5IQ3iisRFruGy0Es+or2YhFAFldk=@googlegroups.com
X-Received: by 2002:a25:f605:0:b0:e26:b9f:1a3c with SMTP id 3f1490d57ef6-e2919ffb5ecmr7607851276.55.1728995280960;
        Tue, 15 Oct 2024 05:28:00 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1728995280; cv=none;
        d=google.com; s=arc-20240605;
        b=Y61OzthFdC3wS6lwLY4VvdxdEcBwYKMGMTgcvt6rIk/dsh617SrFIWL9m3CEsLilQ2
         bw02OY5DkEtqUpipPsgnoz1e+3TC4ytW9Nm8S0tGhr4sJeZXs8z5o5ptJQoovOpdh73c
         /q7ax05ElROdOLdV7WDVygdatLWijzc3Ml1zFAip9oIbS/9/nQ2VCbvP7WcbYn4fUbhs
         4KgF1JEYUoENrqcxbQovJR8+f2EaWYlbE/Zrnf4ztuSYden0o1Vn27GeFd53wFF/rJa5
         TC+B48rJaal7skeCssnbAQZI4cQIlF45z7feaBU0XSarUaoaNK6peLFW1u7SSbmDph3A
         CcRA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=m72B8Ax7Cs86MwObcwcARk1nTXi8mBNE2H4xmkM4IxM=;
        fh=9/LpfnlwTqZdYcV9WwL8+cFg/R5+JAD4mplXe2Iv7WY=;
        b=CIHFm/mG6y6TLT1UFLCvpkuk8j+TwRHSYui/jLSw3QQQ10IHcwFgWBQj9A5RAw5f4y
         hws2OeNgJBIpAHZn6CndDea8f84wRdulQNN7ne079e/svhQdV2YdARAWdHqIL4Qw29zZ
         0GIcnWr1yXnN5d5DgkPSUrMdfptmw7DnInMtC4Hn41yIm97kSCAKngDN/dokGrSCYcwe
         SREnFt7vQVSW4Y5ScgG6JBeDqeVzgIqOWxP69ocpzXLBR0IjSrbw/xiO17yTauCiT0FJ
         kj9YgiHb824mPhe/9AYHXdRyPnwyCnKnfxGuXe/DeVg0N0A99O1NAVQ6+37fD9hWcwPU
         kNWA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=DKRcuqPu;
       spf=pass (google.com: domain of chenhuacai@kernel.org designates 147.75.193.91 as permitted sender) smtp.mailfrom=chenhuacai@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from nyc.source.kernel.org (nyc.source.kernel.org. [147.75.193.91])
        by gmr-mx.google.com with ESMTPS id 3f1490d57ef6-e297292251asi8493276.1.2024.10.15.05.28.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 15 Oct 2024 05:28:00 -0700 (PDT)
Received-SPF: pass (google.com: domain of chenhuacai@kernel.org designates 147.75.193.91 as permitted sender) client-ip=147.75.193.91;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by nyc.source.kernel.org (Postfix) with ESMTP id 8913DA42570
	for <kasan-dev@googlegroups.com>; Tue, 15 Oct 2024 12:27:51 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 30ED8C4CECF
	for <kasan-dev@googlegroups.com>; Tue, 15 Oct 2024 12:28:00 +0000 (UTC)
Received: by mail-ej1-f46.google.com with SMTP id a640c23a62f3a-a9a0084f703so411458366b.3
        for <kasan-dev@googlegroups.com>; Tue, 15 Oct 2024 05:28:00 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCX97xznqcBB6hNgRFZYUkU+3vM7s9rmoTjYENIzo4lkdfCwZK1ajdzgrWe37dYKi0LValktqwEZgtE=@googlegroups.com
X-Received: by 2002:a17:907:934e:b0:a9a:26dd:16bc with SMTP id
 a640c23a62f3a-a9a34d3b5dcmr396366b.5.1728995278707; Tue, 15 Oct 2024 05:27:58
 -0700 (PDT)
MIME-Version: 1.0
References: <20241014035855.1119220-1-maobibo@loongson.cn> <20241014035855.1119220-3-maobibo@loongson.cn>
 <CAAhV-H6nkiw_eOS3jFdojJsCJOA2yiprQmaT5c=SnPhJTOyKkQ@mail.gmail.com> <e7c06bf4-897a-7060-61f9-97435d2af16e@loongson.cn>
In-Reply-To: <e7c06bf4-897a-7060-61f9-97435d2af16e@loongson.cn>
From: "'Huacai Chen' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 15 Oct 2024 20:27:46 +0800
X-Gmail-Original-Message-ID: <CAAhV-H6H=Q=1KN5q8kR3j55Ky--FRNifCT93axhqE=vNMArDaQ@mail.gmail.com>
Message-ID: <CAAhV-H6H=Q=1KN5q8kR3j55Ky--FRNifCT93axhqE=vNMArDaQ@mail.gmail.com>
Subject: Re: [PATCH v2 2/3] LoongArch: Add barrier between set_pte and memory access
To: maobibo <maobibo@loongson.cn>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Andrew Morton <akpm@linux-foundation.org>, 
	David Hildenbrand <david@redhat.com>, Barry Song <baohua@kernel.org>, loongarch@lists.linux.dev, 
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: chenhuacai@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=DKRcuqPu;       spf=pass
 (google.com: domain of chenhuacai@kernel.org designates 147.75.193.91 as
 permitted sender) smtp.mailfrom=chenhuacai@kernel.org;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Huacai Chen <chenhuacai@kernel.org>
Reply-To: Huacai Chen <chenhuacai@kernel.org>
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

On Tue, Oct 15, 2024 at 10:54=E2=80=AFAM maobibo <maobibo@loongson.cn> wrot=
e:
>
>
>
> On 2024/10/14 =E4=B8=8B=E5=8D=882:31, Huacai Chen wrote:
> > Hi, Bibo,
> >
> > On Mon, Oct 14, 2024 at 11:59=E2=80=AFAM Bibo Mao <maobibo@loongson.cn>=
 wrote:
> >>
> >> It is possible to return a spurious fault if memory is accessed
> >> right after the pte is set. For user address space, pte is set
> >> in kernel space and memory is accessed in user space, there is
> >> long time for synchronization, no barrier needed. However for
> >> kernel address space, it is possible that memory is accessed
> >> right after the pte is set.
> >>
> >> Here flush_cache_vmap/flush_cache_vmap_early is used for
> >> synchronization.
> >>
> >> Signed-off-by: Bibo Mao <maobibo@loongson.cn>
> >> ---
> >>   arch/loongarch/include/asm/cacheflush.h | 14 +++++++++++++-
> >>   1 file changed, 13 insertions(+), 1 deletion(-)
> >>
> >> diff --git a/arch/loongarch/include/asm/cacheflush.h b/arch/loongarch/=
include/asm/cacheflush.h
> >> index f8754d08a31a..53be231319ef 100644
> >> --- a/arch/loongarch/include/asm/cacheflush.h
> >> +++ b/arch/loongarch/include/asm/cacheflush.h
> >> @@ -42,12 +42,24 @@ void local_flush_icache_range(unsigned long start,=
 unsigned long end);
> >>   #define flush_cache_dup_mm(mm)                         do { } while =
(0)
> >>   #define flush_cache_range(vma, start, end)             do { } while =
(0)
> >>   #define flush_cache_page(vma, vmaddr, pfn)             do { } while =
(0)
> >> -#define flush_cache_vmap(start, end)                   do { } while (=
0)
> >>   #define flush_cache_vunmap(start, end)                 do { } while =
(0)
> >>   #define flush_icache_user_page(vma, page, addr, len)   do { } while =
(0)
> >>   #define flush_dcache_mmap_lock(mapping)                        do { =
} while (0)
> >>   #define flush_dcache_mmap_unlock(mapping)              do { } while =
(0)
> >>
> >> +/*
> >> + * It is possible for a kernel virtual mapping access to return a spu=
rious
> >> + * fault if it's accessed right after the pte is set. The page fault =
handler
> >> + * does not expect this type of fault. flush_cache_vmap is not exactl=
y the
> >> + * right place to put this, but it seems to work well enough.
> >> + */
> >> +static inline void flush_cache_vmap(unsigned long start, unsigned lon=
g end)
> >> +{
> >> +       smp_mb();
> >> +}
> >> +#define flush_cache_vmap flush_cache_vmap
> >> +#define flush_cache_vmap_early flush_cache_vmap
> >  From the history of flush_cache_vmap_early(), It seems only archs with
> > "virtual cache" (VIVT or VIPT) need this API, so LoongArch can be a
> > no-op here.
OK,  flush_cache_vmap_early() also needs smp_mb().

>
> Here is usage about flush_cache_vmap_early in file linux/mm/percpu.c,
> map the page and access it immediately. Do you think it should be noop
> on LoongArch.
>
> rc =3D __pcpu_map_pages(unit_addr, &pages[unit * unit_pages],
>                                       unit_pages);
> if (rc < 0)
>      panic("failed to map percpu area, err=3D%d\n", rc);
>      flush_cache_vmap_early(unit_addr, unit_addr + ai->unit_size);
>      /* copy static data */
>      memcpy((void *)unit_addr, __per_cpu_load, ai->static_size);
> }
>
>
> >
> > And I still think flush_cache_vunmap() should be a smp_mb(). A
> > smp_mb() in flush_cache_vmap() prevents subsequent accesses be
> > reordered before pte_set(), and a smp_mb() in flush_cache_vunmap()
> smp_mb() in flush_cache_vmap() does not prevent reorder. It is to flush
> pipeline and let page table walker HW sync with data cache.
>
> For the following example.
>    rb =3D vmap(pages, nr_meta_pages + 2 * nr_data_pages,
>                    VM_MAP | VM_USERMAP, PAGE_KERNEL);
>    if (rb) {
> <<<<<<<<<<< * the sentence if (rb) can prevent reorder. Otherwise with
> any API kmalloc/vmap/vmalloc and subsequent memory access, there will be
> reorder issu. *
>        kmemleak_not_leak(pages);
>        rb->pages =3D pages;
>        rb->nr_pages =3D nr_pages;
>        return rb;
>    }
>
> > prevents preceding accesses be reordered after pte_clear(). This
> Can you give an example about such usage about flush_cache_vunmap()? and
> we can continue to talk about it, else it is just guessing.
Since we cannot reach a consensus, and the flush_cache_* API look very
strange for this purpose (Yes, I know PowerPC does it like this, but
ARM64 doesn't). I prefer to still use the ARM64 method which means add
a dbar in set_pte(). Of course the performance will be a little worse,
but still better than the old version, and it is more robust.

I know you are very busy, so if you have no time you don't need to
send V3, I can just do a small modification on the 3rd patch.


Huacai

>
> Regards
> Bibo Mao
> > potential problem may not be seen from experiment, but it is needed in
> > theory.
> >
> > Huacai
> >
> >> +
> >>   #define cache_op(op, addr)                                          =
   \
> >>          __asm__ __volatile__(                                        =
   \
> >>          "       cacop   %0, %1                                  \n"  =
   \
> >> --
> >> 2.39.3
> >>
> >>
>
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAAhV-H6H%3DQ%3D1KN5q8kR3j55Ky--FRNifCT93axhqE%3DvNMArDaQ%40mail.=
gmail.com.
