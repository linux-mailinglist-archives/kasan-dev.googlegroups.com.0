Return-Path: <kasan-dev+bncBAABBXOFY64AMGQET4BCLDQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x739.google.com (mail-qk1-x739.google.com [IPv6:2607:f8b0:4864:20::739])
	by mail.lfdr.de (Postfix) with ESMTPS id ECE779A33BE
	for <lists+kasan-dev@lfdr.de>; Fri, 18 Oct 2024 06:23:58 +0200 (CEST)
Received: by mail-qk1-x739.google.com with SMTP id af79cd13be357-7afc3f4faaasf304727685a.0
        for <lists+kasan-dev@lfdr.de>; Thu, 17 Oct 2024 21:23:58 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1729225438; cv=pass;
        d=google.com; s=arc-20240605;
        b=KX5TDQmV7y2KOFBlyOlZ+CA05IlH/L1uqlW3OgIuYWZkRfDrLd66OefJaDdSKg6ppY
         j04kyriHL61sDBbFS6yL4gfRsGSyjxSTJv9eso7Kh0ybS8V0Qobd88fQUYb8zikxvfZW
         rSxz25pFcudlGE27Bnr6m3Ebz2ebAkDl7SXRpU85ap2t9yAs9uYGjLIBZmkN/G0NCL8A
         7S3kajbz8R98Uq0+6JopWthycI4enPRxNDvA9jPmxRiGjsyzJE6PFFWnjLhpEDNhojlN
         Q2x8Zrl4G+sMOGKLnBsGPy8fyTHcXVT6GPTXR9scK7PzYIJPmc6R6ePT9WKJTFlvCn/A
         GySQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Pe+uHazv7QVjaq3rtb1Yuvx0kQCp2mQACzv0PT9Y+5k=;
        fh=+cc+MYm+loVW0ymFdlVB5nZ/LvjfFntSSQpHDkY5J34=;
        b=iLptGsz4yJoa+keYSAqqNqMKq+2n0XHhf+qA9YFrurgvPtlhcyiUnLjw1budsY0d0U
         FXqmnGMhdUKfLi4yQBTvHDg/o0yKD6QprZyhPr1NO+PmLMaOyRUgBdTdIh4ZCkBzxz6z
         +c3aCwc+xDnxlkwVEOBmU0UQ8A89aIZzuyYL9dJpDdMi4rhCkGJOHvuAoQOXyZPgjcKa
         9VsQa+HZ+FMXWtYrCPL9c/7GZWGrIjm5eUBPaGQvNlZZ8qDUJC006YK2hzETcwpgyCbM
         I+XNRdPUDBrFZSR62m2za+wTBUEwbGKyvV46pQv37+h5OZFAfl0neDIOZgkHGYcVHlN+
         DwnA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=ZIxFjafi;
       spf=pass (google.com: domain of chenhuacai@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=chenhuacai@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1729225438; x=1729830238; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=Pe+uHazv7QVjaq3rtb1Yuvx0kQCp2mQACzv0PT9Y+5k=;
        b=JNKRG+hgc928O+kTcRWduAUvB8jUXK4sVLLjhtms6LcUYJLE78LDkBzwBpUr/gSy4X
         ynqcWYZxlxJlwov8zmsYNej09EqGc7VV6DZvTwcQhAKrR2eEFVaBuhnpfv7h0fFpsC08
         m7N8j7WL6eIPfG6Dn5lmCbWJlnMSKZGwBfARz6jk8irDQPfqxq3fkTtMC5DRrjD4tNRF
         QX6zRWxZk+JsWqPR2U0FcnwJDQeJsXt+DJj/0zJ/qr6Vpg68ST6d1qxXsCfv2ItNXu7I
         lFNLrIGYMXe2Lea28/nlbf0pBDKf94YHcXaWqLCSo3XtbEh2vsG8ey0Np0NTyZgVSqWi
         WE0g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1729225438; x=1729830238;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=Pe+uHazv7QVjaq3rtb1Yuvx0kQCp2mQACzv0PT9Y+5k=;
        b=Vc8nKGNhh6BOrdfsD6tvX7bxWniPWsWi1R3QIjgqX/H/7iX5451Afiw7d3sJRTsNJc
         7VSJc3BaWZsIpmkTMvJhIxoJDIDdQ+CNHmLjcSouV53GvwvIUl3lvKCN0MVEP8ZD7qN5
         WswQ5V/xDVT94A0n160vaEaIWHoAtQvcqVLEzj9gS+wUEoIV++VplQv7Ota5kCxU6qZF
         RvbrQjxWwxWQbLsSIAoVOFzedhrsJnYFAo/uGYJqyT4B77MsalYNi7iMW8p3nblf4NMT
         8ZYO5ebAg6U1ASdGutFcMQPTzeC1pYGy7eC2reGioPesinIH631GY0h4TZ4akcDoMsOk
         7Rtw==
X-Forwarded-Encrypted: i=2; AJvYcCVlsJypa9unXHiKLseh8J8LmAZ8NXB+fvES2/ePmU+lM2+8962sR0y1OG3iCUs1kEyhwjfvpA==@lfdr.de
X-Gm-Message-State: AOJu0YweayRsFgAiMvaprv+gH2fzyzPiawphqWLIb1PqrllUmQ7bW4m9
	FtrvMMFNAHJV+xvGgZkv80D3Q69Xxn6sGHMyBZxC+egUFBHYdEJx
X-Google-Smtp-Source: AGHT+IHfPMnouwM6lE0QWFwtSqMXoB1TvYGC/v8bgyiax96W8xIXWywMMTEk5rTYVWjJ5Dgam4DKCg==
X-Received: by 2002:a05:620a:4094:b0:79f:15ca:b782 with SMTP id af79cd13be357-7b157b7fc07mr98732685a.35.1729225437484;
        Thu, 17 Oct 2024 21:23:57 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:260d:b0:6b5:268:d754 with SMTP id
 6a1803df08f44-6cc373802a0ls3450386d6.2.-pod-prod-03-us; Thu, 17 Oct 2024
 21:23:55 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVycZ9QTVXgYtYLcnxaFBc2os12EQu9cDWJ/NTUNDT/qfwof5/jhQmNlL7W62C3zSl2UEfd92/4WwA=@googlegroups.com
X-Received: by 2002:a05:6214:31a1:b0:6cc:2de:1dbc with SMTP id 6a1803df08f44-6cde1610a96mr12989386d6.44.1729225435107;
        Thu, 17 Oct 2024 21:23:55 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1729225435; cv=none;
        d=google.com; s=arc-20240605;
        b=bZbXG9wUW6JJqLj/xenHaBqkHQsFA6qeI52WSk6DXmNgDrWtTERCTGWOvF6CcTHdmP
         tG5iCFmD5HqB5ez7GowPIBiyFnl0Qbl289Lf6NlCTWXPskvgwA4dHTa/Ds7pI8Y1mwHs
         VW5mqB4kTYufwcvk43Nmr5hx3hCrrMmTFW8V0iN1Zltcn0rezHEBAL2pzTKXcx21Z/db
         S3an6Zts00zOzwQ9Ggv96OCKNwj9bthUDB28jo1JnCswfsZyG3YQKMWhDM2UrD1o1IOM
         g2viNDmJrD+acotxHt2lFz12ZPzkpyl1FxKu1atSf9H2xLbUvRFI2MgICdiR1dUqfSLb
         LCGQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=Jj6Qji/GiZwLJhiCHjm/SCf+zhBagtHMR0HqL1vKib0=;
        fh=J1E7NeFCp+PuY1865sMuGQ8MTNcWZYVuB0R+tf4cFYg=;
        b=QEwQOe64IqngeDcB6nvk3a12Nt/nUuOTThSVpl4STnOV/TVjn7SZ/Sw6n6iqRYAxpC
         pa7REi8+VvAZU1i4Wc8osfrB1NfObjEq76gx/PhTgCDKzls3ejGz7YLesUcpnRIbS+O4
         jTJE/BC6T73Vr8oaVDApVRFwHDDiSsYkz4VGZaUj3jN0Sg7LMUY74TeZAKZQSN7amwRQ
         A6s93uEl1jm0jO8VX+wFXsy5acloRoXHy//GhkHCOzc4pKdlgjPAq8MfSp/vsPKc0wbQ
         XR4JlG0CiaF5DlEGSOLScuc+lHxUm0qQ/n+TuHbzExtJYN7E0OrHp6t+cs14kjP8UuN5
         5FPw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=ZIxFjafi;
       spf=pass (google.com: domain of chenhuacai@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=chenhuacai@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-6cde136cb98si327686d6.3.2024.10.17.21.23.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 17 Oct 2024 21:23:55 -0700 (PDT)
Received-SPF: pass (google.com: domain of chenhuacai@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id 202A65C5D90
	for <kasan-dev@googlegroups.com>; Fri, 18 Oct 2024 04:23:50 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 24322C4CED0
	for <kasan-dev@googlegroups.com>; Fri, 18 Oct 2024 04:23:54 +0000 (UTC)
Received: by mail-ej1-f52.google.com with SMTP id a640c23a62f3a-a99eb8b607aso166553966b.2
        for <kasan-dev@googlegroups.com>; Thu, 17 Oct 2024 21:23:54 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCViN9YroMPIq5nKPKDSwdBLuMzoXZ29S4pbrsW8HG1vbv2LCJ7ax5sLdT2prwvfbFQ9woh4LIuPCYA=@googlegroups.com
X-Received: by 2002:a17:906:c113:b0:a9a:1092:b10d with SMTP id
 a640c23a62f3a-a9a69b7af5dmr66882666b.33.1729225432608; Thu, 17 Oct 2024
 21:23:52 -0700 (PDT)
MIME-Version: 1.0
References: <20241014035855.1119220-1-maobibo@loongson.cn> <20241014035855.1119220-2-maobibo@loongson.cn>
 <CAAhV-H5QkULWp6fciR1Lnds0r00fUdrmj86K_wBuxd0D=RkaXQ@mail.gmail.com>
 <f3089991-fd49-8d55-9ede-62ab1555c9fa@loongson.cn> <CAAhV-H7yX6qinPL5E5tmNVpJk_xdKqFaSicUYy2k8NGM1owucw@mail.gmail.com>
 <a4c6b89e-4ffe-4486-4ccd-7ebc28734f6f@loongson.cn>
In-Reply-To: <a4c6b89e-4ffe-4486-4ccd-7ebc28734f6f@loongson.cn>
From: "'Huacai Chen' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 18 Oct 2024 12:23:39 +0800
X-Gmail-Original-Message-ID: <CAAhV-H6FkJZwa-pALUhucrU5OXxsHg+ByM+4NN0wPQgOJTqOXA@mail.gmail.com>
Message-ID: <CAAhV-H6FkJZwa-pALUhucrU5OXxsHg+ByM+4NN0wPQgOJTqOXA@mail.gmail.com>
Subject: Re: [PATCH v2 1/3] LoongArch: Set initial pte entry with PAGE_GLOBAL
 for kernel space
To: maobibo <maobibo@loongson.cn>, wuruiyang@loongson.cn
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Andrew Morton <akpm@linux-foundation.org>, 
	David Hildenbrand <david@redhat.com>, Barry Song <baohua@kernel.org>, loongarch@lists.linux.dev, 
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: chenhuacai@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=ZIxFjafi;       spf=pass
 (google.com: domain of chenhuacai@kernel.org designates 2604:1380:4641:c500::1
 as permitted sender) smtp.mailfrom=chenhuacai@kernel.org;       dmarc=pass
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

On Fri, Oct 18, 2024 at 12:16=E2=80=AFPM maobibo <maobibo@loongson.cn> wrot=
e:
>
>
>
> On 2024/10/18 =E4=B8=8B=E5=8D=8812:11, Huacai Chen wrote:
> > On Fri, Oct 18, 2024 at 11:44=E2=80=AFAM maobibo <maobibo@loongson.cn> =
wrote:
> >>
> >>
> >>
> >> On 2024/10/18 =E4=B8=8A=E5=8D=8811:14, Huacai Chen wrote:
> >>> Hi, Bibo,
> >>>
> >>> I applied this patch but drop the part of arch/loongarch/mm/kasan_ini=
t.c:
> >>> https://git.kernel.org/pub/scm/linux/kernel/git/chenhuacai/linux-loon=
gson.git/commit/?h=3Dloongarch-next&id=3D15832255e84494853f543b4c70ced50afc=
403067
> >>>
> >>> Because kernel_pte_init() should operate on page-table pages, not on
> >>> data pages. You have already handle page-table page in
> >>> mm/kasan/init.c, and if we don't drop the modification on data pages
> >>> in arch/loongarch/mm/kasan_init.c, the kernel fail to boot if KASAN i=
s
> >>> enabled.
> >>>
> >> static inline void set_pte(pte_t *ptep, pte_t pteval)
> >>    {
> >>          WRITE_ONCE(*ptep, pteval);
> >> -
> >> -       if (pte_val(pteval) & _PAGE_GLOBAL) {
> >> -               pte_t *buddy =3D ptep_buddy(ptep);
> >> -               /*
> >> -                * Make sure the buddy is global too (if it's !none,
> >> -                * it better already be global)
> >> -                */
> >> -               if (pte_none(ptep_get(buddy))) {
> >> -#ifdef CONFIG_SMP
> >> -                       /*
> >> -                        * For SMP, multiple CPUs can race, so we need
> >> -                        * to do this atomically.
> >> -                        */
> >> -                       __asm__ __volatile__(
> >> -                       __AMOR "$zero, %[global], %[buddy] \n"
> >> -                       : [buddy] "+ZB" (buddy->pte)
> >> -                       : [global] "r" (_PAGE_GLOBAL)
> >> -                       : "memory");
> >> -
> >> -                       DBAR(0b11000); /* o_wrw =3D 0b11000 */
> >> -#else /* !CONFIG_SMP */
> >> -                       WRITE_ONCE(*buddy, __pte(pte_val(ptep_get(budd=
y)) | _PAGE_GLOBAL));
> >> -#endif /* CONFIG_SMP */
> >> -               }
> >> -       }
> >> +       DBAR(0b11000); /* o_wrw =3D 0b11000 */
> >>    }
> >>
> >> No, please hold on. This issue exists about twenty years, Do we need b=
e
> >> in such a hurry now?
> >>
> >> why is DBAR(0b11000) added in set_pte()?
> > It exists before, not added by this patch. The reason is explained in
> > https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/comm=
it/?h=3Dv6.12-rc3&id=3Df93f67d06b1023313ef1662eac490e29c025c030
> why speculative accesses may cause spurious page fault in kernel space
> with PTE enabled?  speculative accesses exists anywhere, it does not
> cause spurious page fault.
Confirmed by Ruiyang Wu, and even if DBAR(0b11000) is wrong, that
means another patch's mistake, not this one. This one just keeps the
old behavior.
+CC Ruiyang Wu here.

Huacai

>
> Obvious you do not it and you write wrong patch.
>
> >
> > Huacai
> >
> >>
> >> Regards
> >> Bibo Mao
> >>> Huacai
> >>>
> >>> On Mon, Oct 14, 2024 at 11:59=E2=80=AFAM Bibo Mao <maobibo@loongson.c=
n> wrote:
> >>>>
> >>>> Unlike general architectures, there are two pages in one TLB entry
> >>>> on LoongArch system. For kernel space, it requires both two pte
> >>>> entries with PAGE_GLOBAL bit set, else HW treats it as non-global
> >>>> tlb, there will be potential problems if tlb entry for kernel space
> >>>> is not global. Such as fail to flush kernel tlb with function
> >>>> local_flush_tlb_kernel_range() which only flush tlb with global bit.
> >>>>
> >>>> With function kernel_pte_init() added, it can be used to init pte
> >>>> table when it is created for kernel address space, and the default
> >>>> initial pte value is PAGE_GLOBAL rather than zero at beginning.
> >>>>
> >>>> Kernel address space areas includes fixmap, percpu, vmalloc, kasan
> >>>> and vmemmap areas set default pte entry with PAGE_GLOBAL set.
> >>>>
> >>>> Signed-off-by: Bibo Mao <maobibo@loongson.cn>
> >>>> ---
> >>>>    arch/loongarch/include/asm/pgalloc.h | 13 +++++++++++++
> >>>>    arch/loongarch/include/asm/pgtable.h |  1 +
> >>>>    arch/loongarch/mm/init.c             |  4 +++-
> >>>>    arch/loongarch/mm/kasan_init.c       |  4 +++-
> >>>>    arch/loongarch/mm/pgtable.c          | 22 ++++++++++++++++++++++
> >>>>    include/linux/mm.h                   |  1 +
> >>>>    mm/kasan/init.c                      |  8 +++++++-
> >>>>    mm/sparse-vmemmap.c                  |  5 +++++
> >>>>    8 files changed, 55 insertions(+), 3 deletions(-)
> >>>>
> >>>> diff --git a/arch/loongarch/include/asm/pgalloc.h b/arch/loongarch/i=
nclude/asm/pgalloc.h
> >>>> index 4e2d6b7ca2ee..b2698c03dc2c 100644
> >>>> --- a/arch/loongarch/include/asm/pgalloc.h
> >>>> +++ b/arch/loongarch/include/asm/pgalloc.h
> >>>> @@ -10,8 +10,21 @@
> >>>>
> >>>>    #define __HAVE_ARCH_PMD_ALLOC_ONE
> >>>>    #define __HAVE_ARCH_PUD_ALLOC_ONE
> >>>> +#define __HAVE_ARCH_PTE_ALLOC_ONE_KERNEL
> >>>>    #include <asm-generic/pgalloc.h>
> >>>>
> >>>> +static inline pte_t *pte_alloc_one_kernel(struct mm_struct *mm)
> >>>> +{
> >>>> +       pte_t *pte;
> >>>> +
> >>>> +       pte =3D (pte_t *) __get_free_page(GFP_KERNEL);
> >>>> +       if (!pte)
> >>>> +               return NULL;
> >>>> +
> >>>> +       kernel_pte_init(pte);
> >>>> +       return pte;
> >>>> +}
> >>>> +
> >>>>    static inline void pmd_populate_kernel(struct mm_struct *mm,
> >>>>                                          pmd_t *pmd, pte_t *pte)
> >>>>    {
> >>>> diff --git a/arch/loongarch/include/asm/pgtable.h b/arch/loongarch/i=
nclude/asm/pgtable.h
> >>>> index 9965f52ef65b..22e3a8f96213 100644
> >>>> --- a/arch/loongarch/include/asm/pgtable.h
> >>>> +++ b/arch/loongarch/include/asm/pgtable.h
> >>>> @@ -269,6 +269,7 @@ extern void set_pmd_at(struct mm_struct *mm, uns=
igned long addr, pmd_t *pmdp, pm
> >>>>    extern void pgd_init(void *addr);
> >>>>    extern void pud_init(void *addr);
> >>>>    extern void pmd_init(void *addr);
> >>>> +extern void kernel_pte_init(void *addr);
> >>>>
> >>>>    /*
> >>>>     * Encode/decode swap entries and swap PTEs. Swap PTEs are all PT=
Es that
> >>>> diff --git a/arch/loongarch/mm/init.c b/arch/loongarch/mm/init.c
> >>>> index 8a87a482c8f4..9f26e933a8a3 100644
> >>>> --- a/arch/loongarch/mm/init.c
> >>>> +++ b/arch/loongarch/mm/init.c
> >>>> @@ -198,9 +198,11 @@ pte_t * __init populate_kernel_pte(unsigned lon=
g addr)
> >>>>           if (!pmd_present(pmdp_get(pmd))) {
> >>>>                   pte_t *pte;
> >>>>
> >>>> -               pte =3D memblock_alloc(PAGE_SIZE, PAGE_SIZE);
> >>>> +               pte =3D memblock_alloc_raw(PAGE_SIZE, PAGE_SIZE);
> >>>>                   if (!pte)
> >>>>                           panic("%s: Failed to allocate memory\n", _=
_func__);
> >>>> +
> >>>> +               kernel_pte_init(pte);
> >>>>                   pmd_populate_kernel(&init_mm, pmd, pte);
> >>>>           }
> >>>>
> >>>> diff --git a/arch/loongarch/mm/kasan_init.c b/arch/loongarch/mm/kasa=
n_init.c
> >>>> index 427d6b1aec09..34988573b0d5 100644
> >>>> --- a/arch/loongarch/mm/kasan_init.c
> >>>> +++ b/arch/loongarch/mm/kasan_init.c
> >>>> @@ -152,6 +152,8 @@ static void __init kasan_pte_populate(pmd_t *pmd=
p, unsigned long addr,
> >>>>                   phys_addr_t page_phys =3D early ?
> >>>>                                           __pa_symbol(kasan_early_sh=
adow_page)
> >>>>                                                 : kasan_alloc_zeroed=
_page(node);
> >>>> +               if (!early)
> >>>> +                       kernel_pte_init(__va(page_phys));
> >>>>                   next =3D addr + PAGE_SIZE;
> >>>>                   set_pte(ptep, pfn_pte(__phys_to_pfn(page_phys), PA=
GE_KERNEL));
> >>>>           } while (ptep++, addr =3D next, addr !=3D end && __pte_non=
e(early, ptep_get(ptep)));
> >>>> @@ -287,7 +289,7 @@ void __init kasan_init(void)
> >>>>                   set_pte(&kasan_early_shadow_pte[i],
> >>>>                           pfn_pte(__phys_to_pfn(__pa_symbol(kasan_ea=
rly_shadow_page)), PAGE_KERNEL_RO));
> >>>>
> >>>> -       memset(kasan_early_shadow_page, 0, PAGE_SIZE);
> >>>> +       kernel_pte_init(kasan_early_shadow_page);
> >>>>           csr_write64(__pa_symbol(swapper_pg_dir), LOONGARCH_CSR_PGD=
H);
> >>>>           local_flush_tlb_all();
> >>>>
> >>>> diff --git a/arch/loongarch/mm/pgtable.c b/arch/loongarch/mm/pgtable=
.c
> >>>> index eb6a29b491a7..228ffc1db0a3 100644
> >>>> --- a/arch/loongarch/mm/pgtable.c
> >>>> +++ b/arch/loongarch/mm/pgtable.c
> >>>> @@ -38,6 +38,28 @@ pgd_t *pgd_alloc(struct mm_struct *mm)
> >>>>    }
> >>>>    EXPORT_SYMBOL_GPL(pgd_alloc);
> >>>>
> >>>> +void kernel_pte_init(void *addr)
> >>>> +{
> >>>> +       unsigned long *p, *end;
> >>>> +       unsigned long entry;
> >>>> +
> >>>> +       entry =3D (unsigned long)_PAGE_GLOBAL;
> >>>> +       p =3D (unsigned long *)addr;
> >>>> +       end =3D p + PTRS_PER_PTE;
> >>>> +
> >>>> +       do {
> >>>> +               p[0] =3D entry;
> >>>> +               p[1] =3D entry;
> >>>> +               p[2] =3D entry;
> >>>> +               p[3] =3D entry;
> >>>> +               p[4] =3D entry;
> >>>> +               p +=3D 8;
> >>>> +               p[-3] =3D entry;
> >>>> +               p[-2] =3D entry;
> >>>> +               p[-1] =3D entry;
> >>>> +       } while (p !=3D end);
> >>>> +}
> >>>> +
> >>>>    void pgd_init(void *addr)
> >>>>    {
> >>>>           unsigned long *p, *end;
> >>>> diff --git a/include/linux/mm.h b/include/linux/mm.h
> >>>> index ecf63d2b0582..6909fe059a2c 100644
> >>>> --- a/include/linux/mm.h
> >>>> +++ b/include/linux/mm.h
> >>>> @@ -3818,6 +3818,7 @@ void *sparse_buffer_alloc(unsigned long size);
> >>>>    struct page * __populate_section_memmap(unsigned long pfn,
> >>>>                   unsigned long nr_pages, int nid, struct vmem_altma=
p *altmap,
> >>>>                   struct dev_pagemap *pgmap);
> >>>> +void kernel_pte_init(void *addr);
> >>>>    void pmd_init(void *addr);
> >>>>    void pud_init(void *addr);
> >>>>    pgd_t *vmemmap_pgd_populate(unsigned long addr, int node);
> >>>> diff --git a/mm/kasan/init.c b/mm/kasan/init.c
> >>>> index 89895f38f722..ac607c306292 100644
> >>>> --- a/mm/kasan/init.c
> >>>> +++ b/mm/kasan/init.c
> >>>> @@ -106,6 +106,10 @@ static void __ref zero_pte_populate(pmd_t *pmd,=
 unsigned long addr,
> >>>>           }
> >>>>    }
> >>>>
> >>>> +void __weak __meminit kernel_pte_init(void *addr)
> >>>> +{
> >>>> +}
> >>>> +
> >>>>    static int __ref zero_pmd_populate(pud_t *pud, unsigned long addr=
,
> >>>>                                   unsigned long end)
> >>>>    {
> >>>> @@ -126,8 +130,10 @@ static int __ref zero_pmd_populate(pud_t *pud, =
unsigned long addr,
> >>>>
> >>>>                           if (slab_is_available())
> >>>>                                   p =3D pte_alloc_one_kernel(&init_m=
m);
> >>>> -                       else
> >>>> +                       else {
> >>>>                                   p =3D early_alloc(PAGE_SIZE, NUMA_=
NO_NODE);
> >>>> +                               kernel_pte_init(p);
> >>>> +                       }
> >>>>                           if (!p)
> >>>>                                   return -ENOMEM;
> >>>>
> >>>> diff --git a/mm/sparse-vmemmap.c b/mm/sparse-vmemmap.c
> >>>> index edcc7a6b0f6f..c0388b2e959d 100644
> >>>> --- a/mm/sparse-vmemmap.c
> >>>> +++ b/mm/sparse-vmemmap.c
> >>>> @@ -184,6 +184,10 @@ static void * __meminit vmemmap_alloc_block_zer=
o(unsigned long size, int node)
> >>>>           return p;
> >>>>    }
> >>>>
> >>>> +void __weak __meminit kernel_pte_init(void *addr)
> >>>> +{
> >>>> +}
> >>>> +
> >>>>    pmd_t * __meminit vmemmap_pmd_populate(pud_t *pud, unsigned long =
addr, int node)
> >>>>    {
> >>>>           pmd_t *pmd =3D pmd_offset(pud, addr);
> >>>> @@ -191,6 +195,7 @@ pmd_t * __meminit vmemmap_pmd_populate(pud_t *pu=
d, unsigned long addr, int node)
> >>>>                   void *p =3D vmemmap_alloc_block_zero(PAGE_SIZE, no=
de);
> >>>>                   if (!p)
> >>>>                           return NULL;
> >>>> +               kernel_pte_init(p);
> >>>>                   pmd_populate_kernel(&init_mm, pmd, p);
> >>>>           }
> >>>>           return pmd;
> >>>> --
> >>>> 2.39.3
> >>>>
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
kasan-dev/CAAhV-H6FkJZwa-pALUhucrU5OXxsHg%2BByM%2B4NN0wPQgOJTqOXA%40mail.gm=
ail.com.
