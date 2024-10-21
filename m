Return-Path: <kasan-dev+bncBAABBU6S3C4AMGQEIDOPPSY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13d.google.com (mail-il1-x13d.google.com [IPv6:2607:f8b0:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id 6A93C9A6236
	for <lists+kasan-dev@lfdr.de>; Mon, 21 Oct 2024 12:13:41 +0200 (CEST)
Received: by mail-il1-x13d.google.com with SMTP id e9e14a558f8ab-3a3c4ed972bsf37173005ab.2
        for <lists+kasan-dev@lfdr.de>; Mon, 21 Oct 2024 03:13:41 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1729505620; cv=pass;
        d=google.com; s=arc-20240605;
        b=jlHqS8WEu9DVDz3I9ZLNEm4oMCCXI02vY8/gsgr/0gJPr+n7FP7vHBUep4kC17YGNk
         gngmD1LdWX7QgEut7Plhl/raU+BdsYPMS8mPdaI+9f4Uv06JBomBCE15iAlv0fH0ezmu
         ryLAdQGXy+PTa5BYAhC66gJcRKF2+nmteEd3MzHmsZcIASdacigpIMsXELjb7BRNOBkc
         0VMF7Vt6/PkfPhMKVMeajUGLTAatXkg+1nzNr5dvN0/bW6sUUrn3BCuRyQzehFtdFVf3
         7JtGeWcRhAAEiKrMwl98u6qko4BO9XLQMoaWqpfhwH7knH+Tydc3GbUvfKFB2ms47fMO
         cx4A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=7ECiX+DQeLmfZo1e3oeCLZLKOct8cBK/ypnmBO1Umo0=;
        fh=bSscEwtd0+BMukA/reuO5D9mcsoKZ/2L40zURL/4Pww=;
        b=S7Oj+zvTHLH/IDkw7oHmWydF4Tpe8Mqd4dHAF+Z1FoJksP+jqJApad4L9JDeYPWACw
         5dPBIrrVpggsfIagTnmDyhYSku1ZqrN58QaH9Xn/S/Ul1gcTyJzcb3htTyqPd6i4Rs50
         SdSV5mxPqrsBeNRt9JTo7X9VJq3pNec5k27FoiDRe/7vugmqO4vA+cboTtZ0oqVVqIcY
         /Gq9q/N4gH6T4JX3lHen6/ozzQOX0Uuw9nx2+1xG0No9jElR+qGKGqnptNT3NqH886lt
         uoEeysSQj104kfc0RoAx1S6/TX7KF/lLl+poS5jWt/aXp8NYLWLddkZQmAtu7BDAT9JR
         1B9g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=O8CVaWgK;
       spf=pass (google.com: domain of chenhuacai@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=chenhuacai@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1729505620; x=1730110420; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=7ECiX+DQeLmfZo1e3oeCLZLKOct8cBK/ypnmBO1Umo0=;
        b=XRjwiJxtMLwZeF3hHbRBfw+RXhx8sYVkd6mBGD7Y/FcaE/znRV9ddtzywQqLvvccmM
         Q3IQp0I5/BYnPDlAZl7HMqB/aKKq0AAIqdbalkDtdQneNbMT7PybBv34giBzzZ5XxXcP
         N2YP2hzSlSk4QVGCT0wFUFexV9hgMdWy38g1A+Mp14mG+UrhZD7IOir2E9Xlg70AjFPu
         NpoDfUrPQcdq0GrRESl+cdLtRdajZ/C7IXoycgDl+w5LnD1/J7ZtHdYo/NYwSTbQ+HfA
         RTyjOKQLelo+E5fv83tE42bUqr2kOpIW0fDYCCDhi1T701biUnJYqIFwYx2pIb/MYocq
         GYdw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1729505620; x=1730110420;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=7ECiX+DQeLmfZo1e3oeCLZLKOct8cBK/ypnmBO1Umo0=;
        b=n33i6BgxfhOPYEaGtrxUB0dZj1wpnHObDd1pMpCXNMGZ2g35KZ3/xczEeuNw0Of8dl
         /00LaxqK0wz6qGIl0d9rGF9nNdr0fQP1B0PjPRprNkE5NapaU18hVr126qC5gy4JMP4z
         CVF5c6391Ql7GNWpWgPA5IRzxcSRZb1xvmIgAJXXgKfk1HTdFw2XbQuHoVwTfLC+k6O6
         8Xp/VofgHiP/Le3fTeuEVeik+3S8OG5OWXMeXuq/39H6gukI0W4U2nYHDSuF8+Jrg+tw
         bTAMRLjYfFJHLbEwf9d82ulY2lUzMU1Epps7PsgbIDh4bnXUC4/Om8E6qBMOUfTDVWJF
         hrxg==
X-Forwarded-Encrypted: i=2; AJvYcCUfHk8AxO4f8A0OHDEkpJYXuyHVPRV2HVaCw26XdnyBlkS7967KyVlWGp3C/GGzFZtqeWmJQg==@lfdr.de
X-Gm-Message-State: AOJu0YyNsLJFDqRB6g8oaqUws3Bf9NUQEsaa8eLHfqIs0mXRJ1mxa6i1
	k3g/IFw8afWkuPRId9UimXpunIqUrsR4qFJ9yc/MgZBYkyguKwHR
X-Google-Smtp-Source: AGHT+IHbgYV2tjLSozUkS1wyFeEzIa/Mm8b/m+gB2nviBZ5A0r5dUkTBJk1oqpXTEkiKyfhxuZwJPw==
X-Received: by 2002:a05:6e02:1525:b0:3a3:6045:f8bb with SMTP id e9e14a558f8ab-3a3f405cd42mr94977965ab.10.1729505619747;
        Mon, 21 Oct 2024 03:13:39 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:1382:b0:3a0:b55f:cde1 with SMTP id
 e9e14a558f8ab-3a3e4a472a2ls19961015ab.0.-pod-prod-04-us; Mon, 21 Oct 2024
 03:13:39 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWJj3XXkeKYegpQMZE0mxHX7UlQ3cIN1G9DhJ5jXT90IypS/cVssHfDOoJEVsydfVWBIoFurkKCsGI=@googlegroups.com
X-Received: by 2002:a05:6e02:16cf:b0:3a3:af94:461f with SMTP id e9e14a558f8ab-3a3f4050131mr97993825ab.1.1729505618963;
        Mon, 21 Oct 2024 03:13:38 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1729505618; cv=none;
        d=google.com; s=arc-20240605;
        b=Pl01H1u52xoN+pbICevEo0jhgiLPVcJzW8u9RtuVOYxYRDr/hxymIaXWLOBDfdJ5nO
         e08aBK7YMXqgvG4ohxIVelK5dF6FoPR+3npJEyQKqiR6l+PW6YJb4lumjLNXHeHVUaYy
         pow6P5bJ1B8ZS8iBb1Xj/oc/edonT3GaFCbMQlXvUB346tvR50xyNsbEUJLP240RNLZr
         te9a1fha2zAEHfKQtmfvi7HMhfOIk2U4gAQ63ve4oE7kuuANRIVtI2FFbK2sbh4/JBJc
         NA+fX4JYdk0iVaJm1ghbRz2t49pc+Tk4LgG7PNct6XRTvpuFfZGvocDPpUvHulfZT84c
         y8LA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=mSq8UGZQ3NJRlapaTTvgYjTUniLDeiulD6xo6BZpX8U=;
        fh=zvRIe1VoiWEkuC2aHiqUDfqsE6O9i2ZlVcJUVOWa+Y4=;
        b=XlGRbPGLvE2EtojVLuG0Li4fgK2Oh7Aqd39emW8XeQNTqwRm9Ju7QsX6ohZVs9tfYw
         apOlEfwUUVFsO0lfkirvFJdHVIcSiiCoNJH5Oo6FfFtYSjB9u8hFGF7t8hZUxVIwG5vg
         Ewx+nuCPp6O83i09aQhRfEp/OT0Se9BetufvwKaM5JYFUsY5j5daS1/A1Lr+aBryc3e1
         ve3WOZ8uRkxlIkNXOhNtWlbq6sdgPVmU5r+FxRtM651oL5zCX1QxMx7WPcY++IrBCf8S
         mceY+wkyBj88Dk5QFzYbP+8EiWOG+wxsQ3mjz2bwIrVEa12ZAq15eiAVQsPIZw3GpS7T
         bbsQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=O8CVaWgK;
       spf=pass (google.com: domain of chenhuacai@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=chenhuacai@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id 41be03b00d2f7-7eaeaafd0e0si135938a12.1.2024.10.21.03.13.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 21 Oct 2024 03:13:38 -0700 (PDT)
Received-SPF: pass (google.com: domain of chenhuacai@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id AF88E5C5A60
	for <kasan-dev@googlegroups.com>; Mon, 21 Oct 2024 10:13:33 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 8E14AC4AF09
	for <kasan-dev@googlegroups.com>; Mon, 21 Oct 2024 10:13:37 +0000 (UTC)
Received: by mail-ej1-f54.google.com with SMTP id a640c23a62f3a-a99cc265e0aso622790466b.3
        for <kasan-dev@googlegroups.com>; Mon, 21 Oct 2024 03:13:37 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCX+FMi+OsZGu/5RrO4mMC6EoQRM7becrOMrpffXRYZJDg6dJHllraJMDDUm8NCQ/WanpWO9exuqcjk=@googlegroups.com
X-Received: by 2002:a17:906:478b:b0:a99:4025:82e1 with SMTP id
 a640c23a62f3a-a9a69c55c81mr1013062566b.41.1729505615843; Mon, 21 Oct 2024
 03:13:35 -0700 (PDT)
MIME-Version: 1.0
References: <20241014035855.1119220-1-maobibo@loongson.cn> <20241014035855.1119220-2-maobibo@loongson.cn>
 <CAAhV-H5QkULWp6fciR1Lnds0r00fUdrmj86K_wBuxd0D=RkaXQ@mail.gmail.com>
 <f3089991-fd49-8d55-9ede-62ab1555c9fa@loongson.cn> <CAAhV-H7yX6qinPL5E5tmNVpJk_xdKqFaSicUYy2k8NGM1owucw@mail.gmail.com>
 <a4c6b89e-4ffe-4486-4ccd-7ebc28734f6f@loongson.cn> <CAAhV-H6FkJZwa-pALUhucrU5OXxsHg+ByM+4NN0wPQgOJTqOXA@mail.gmail.com>
 <5f76ede6-e8be-c7a9-f957-479afa2fb828@loongson.cn> <CAAhV-H51W3ZRNxUjeAx52j6Tq18CEhB3_YeSH=psjAbEJUdwgg@mail.gmail.com>
 <f727e384-6989-0942-1cc8-7188f558ee39@loongson.cn>
In-Reply-To: <f727e384-6989-0942-1cc8-7188f558ee39@loongson.cn>
From: "'Huacai Chen' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 21 Oct 2024 18:13:23 +0800
X-Gmail-Original-Message-ID: <CAAhV-H5CADad2EGv0zMQrgrvpNRtBTWDoXFj=j+zXEJdy7HkAQ@mail.gmail.com>
Message-ID: <CAAhV-H5CADad2EGv0zMQrgrvpNRtBTWDoXFj=j+zXEJdy7HkAQ@mail.gmail.com>
Subject: Re: [PATCH v2 1/3] LoongArch: Set initial pte entry with PAGE_GLOBAL
 for kernel space
To: maobibo <maobibo@loongson.cn>
Cc: wuruiyang@loongson.cn, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Andrew Morton <akpm@linux-foundation.org>, David Hildenbrand <david@redhat.com>, 
	Barry Song <baohua@kernel.org>, loongarch@lists.linux.dev, linux-kernel@vger.kernel.org, 
	kasan-dev@googlegroups.com, linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: chenhuacai@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=O8CVaWgK;       spf=pass
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

On Mon, Oct 21, 2024 at 9:23=E2=80=AFAM maobibo <maobibo@loongson.cn> wrote=
:
>
>
>
> On 2024/10/18 =E4=B8=8B=E5=8D=882:32, Huacai Chen wrote:
> > On Fri, Oct 18, 2024 at 2:23=E2=80=AFPM maobibo <maobibo@loongson.cn> w=
rote:
> >>
> >>
> >>
> >> On 2024/10/18 =E4=B8=8B=E5=8D=8812:23, Huacai Chen wrote:
> >>> On Fri, Oct 18, 2024 at 12:16=E2=80=AFPM maobibo <maobibo@loongson.cn=
> wrote:
> >>>>
> >>>>
> >>>>
> >>>> On 2024/10/18 =E4=B8=8B=E5=8D=8812:11, Huacai Chen wrote:
> >>>>> On Fri, Oct 18, 2024 at 11:44=E2=80=AFAM maobibo <maobibo@loongson.=
cn> wrote:
> >>>>>>
> >>>>>>
> >>>>>>
> >>>>>> On 2024/10/18 =E4=B8=8A=E5=8D=8811:14, Huacai Chen wrote:
> >>>>>>> Hi, Bibo,
> >>>>>>>
> >>>>>>> I applied this patch but drop the part of arch/loongarch/mm/kasan=
_init.c:
> >>>>>>> https://git.kernel.org/pub/scm/linux/kernel/git/chenhuacai/linux-=
loongson.git/commit/?h=3Dloongarch-next&id=3D15832255e84494853f543b4c70ced5=
0afc403067
> >>>>>>>
> >>>>>>> Because kernel_pte_init() should operate on page-table pages, not=
 on
> >>>>>>> data pages. You have already handle page-table page in
> >>>>>>> mm/kasan/init.c, and if we don't drop the modification on data pa=
ges
> >>>>>>> in arch/loongarch/mm/kasan_init.c, the kernel fail to boot if KAS=
AN is
> >>>>>>> enabled.
> >>>>>>>
> >>>>>> static inline void set_pte(pte_t *ptep, pte_t pteval)
> >>>>>>      {
> >>>>>>            WRITE_ONCE(*ptep, pteval);
> >>>>>> -
> >>>>>> -       if (pte_val(pteval) & _PAGE_GLOBAL) {
> >>>>>> -               pte_t *buddy =3D ptep_buddy(ptep);
> >>>>>> -               /*
> >>>>>> -                * Make sure the buddy is global too (if it's !non=
e,
> >>>>>> -                * it better already be global)
> >>>>>> -                */
> >>>>>> -               if (pte_none(ptep_get(buddy))) {
> >>>>>> -#ifdef CONFIG_SMP
> >>>>>> -                       /*
> >>>>>> -                        * For SMP, multiple CPUs can race, so we =
need
> >>>>>> -                        * to do this atomically.
> >>>>>> -                        */
> >>>>>> -                       __asm__ __volatile__(
> >>>>>> -                       __AMOR "$zero, %[global], %[buddy] \n"
> >>>>>> -                       : [buddy] "+ZB" (buddy->pte)
> >>>>>> -                       : [global] "r" (_PAGE_GLOBAL)
> >>>>>> -                       : "memory");
> >>>>>> -
> >>>>>> -                       DBAR(0b11000); /* o_wrw =3D 0b11000 */
> >>>>>> -#else /* !CONFIG_SMP */
> >>>>>> -                       WRITE_ONCE(*buddy, __pte(pte_val(ptep_get(=
buddy)) | _PAGE_GLOBAL));
> >>>>>> -#endif /* CONFIG_SMP */
> >>>>>> -               }
> >>>>>> -       }
> >>>>>> +       DBAR(0b11000); /* o_wrw =3D 0b11000 */
> >>>>>>      }
> >>>>>>
> >>>>>> No, please hold on. This issue exists about twenty years, Do we ne=
ed be
> >>>>>> in such a hurry now?
> >>>>>>
> >>>>>> why is DBAR(0b11000) added in set_pte()?
> >>>>> It exists before, not added by this patch. The reason is explained =
in
> >>>>> https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/=
commit/?h=3Dv6.12-rc3&id=3Df93f67d06b1023313ef1662eac490e29c025c030
> >>>> why speculative accesses may cause spurious page fault in kernel spa=
ce
> >>>> with PTE enabled?  speculative accesses exists anywhere, it does not
> >>>> cause spurious page fault.
> >>> Confirmed by Ruiyang Wu, and even if DBAR(0b11000) is wrong, that
> >>> means another patch's mistake, not this one. This one just keeps the
> >>> old behavior.
> >>> +CC Ruiyang Wu here.
> >> Also from Ruiyang Wu, the information is that speculative accesses may
> >> insert stale TLB, however no page fault exception.
> >>
> >> So adding barrier in set_pte() does not prevent speculative accesses.
> >> And you write patch here, however do not know the actual reason?
> >>
> >> https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/com=
mit/?h=3Dv6.12-rc3&id=3Df93f67d06b1023313ef1662eac490e29c025c030
> > I have CCed Ruiyang, whether the description is correct can be judged b=
y him.
>
> There are some problems to add barrier() in set_pte():
>
> 1. There is such issue only for HW ptw enabled and kernel address space,
> is that? Also it may be two heavy to add barrier in set_pte(), comparing
> to do this in flush_cache_vmap().
So adding a barrier in set_pte() may not be the best solution for
performance, but you cannot say it is a wrong solution. And yes, we
can only care the kernel space, which is also the old behavior before
this patch, so set_pte() should be:

static inline void set_pte(pte_t *ptep, pte_t pteval)
{
        WRITE_ONCE(*ptep, pteval);
#ifdef CONFIG_SMP
        if (pte_val(pteval) & _PAGE_GLOBAL)
                DBAR(0b11000); /* o_wrw =3D 0b11000 */
#endif
}

Putting a dbar unconditionally in set_pte() is my mistake, I'm sorry for  t=
hat.

>
> 2. LoongArch is different with other other architectures, two pages are
> included in one TLB entry. If there is two consecutive page mapped and
> memory access, there will page fault for the second memory access. Such
> as:
>     addr1 =3Dpercpu_alloc(pagesize);
>     val1 =3D *(int *)addr1;
>       // With page table walk, addr1 is present and addr2 is pte_none
>       // TLB entry includes valid pte for addr1, invalid pte for addr2
>     addr2 =3Dpercpu_alloc(pagesize); // will not flush tlb in first time
>     val2 =3D *(int *)addr2;
>       // With page table walk, addr1 is present and addr2 is present also
>       // TLB entry includes valid pte for addr1, invalid pte for addr2
>     So there will be page fault when accessing address addr2
>
> There there is the same problem with user address space. By the way,
> there is HW prefetching technology, negative effective of HW prefetching
> technology will be tlb added. So there is potential page fault if memory
> is allocated and accessed in the first time.
As discussed internally, there may be three problems related to
speculative access in detail: 1) a load/store after set_pte() is
prioritized before, which can be prevented by dbar, 2) a instruction
fetch after set_pte() is prioritized before, which can be prevented by
ibar, 3) the buddy tlb problem you described here, if I understand
Ruiyang's explanation correctly this can only be prevented by the
filter in do_page_fault().

From experiments, without the patch "LoongArch: Improve hardware page
table walker", there are about 80 times of spurious page faults during
boot, and increases continually during stress tests. And after that
patch which adds a dbar to set_pte(), we cannot observe spurious page
faults anymore. Of course this doesn't mean 2) and 3) don't exist, but
we can at least say 1) is the main case. On this basis, in "LoongArch:
Improve hardware page table walker" we use a relatively cheap dbar
(compared to ibar) to prevent the main case, and add a filter to
handle 2) and 3). Such a solution is reasonable.


>
> 3. For speculative execution, if it is user address, there is eret from
> syscall. eret will rollback all speculative execution instruction. So it
> is only problem for speculative execution. And how to verify whether it
> is the problem of speculative execution or it is the problem of clause 2?
As described above, if spurious page faults still exist after adding
dbar to set_pte(), it may be a problem of clause 2 (case 3 in my
description), otherwise it is not a problem of clause 2.

At last, this patch itself is attempting to solve the concurrent
problem about _PAGE_GLOBAL, so adding pte_alloc_one_kernel() and
removing the buddy stuff in set_pte() are what it needs. However it
shouldn't touch the logic of dbar in set_pte(), whether "LoongArch:
Improve hardware page table walker" is right or wrong.


Huacai

>
> Regards
> Bibo Mao
>
>
> >
> > Huacai
> >
> >>
> >> Bibo Mao
> >>>
> >>> Huacai
> >>>
> >>>>
> >>>> Obvious you do not it and you write wrong patch.
> >>>>
> >>>>>
> >>>>> Huacai
> >>>>>
> >>>>>>
> >>>>>> Regards
> >>>>>> Bibo Mao
> >>>>>>> Huacai
> >>>>>>>
> >>>>>>> On Mon, Oct 14, 2024 at 11:59=E2=80=AFAM Bibo Mao <maobibo@loongs=
on.cn> wrote:
> >>>>>>>>
> >>>>>>>> Unlike general architectures, there are two pages in one TLB ent=
ry
> >>>>>>>> on LoongArch system. For kernel space, it requires both two pte
> >>>>>>>> entries with PAGE_GLOBAL bit set, else HW treats it as non-globa=
l
> >>>>>>>> tlb, there will be potential problems if tlb entry for kernel sp=
ace
> >>>>>>>> is not global. Such as fail to flush kernel tlb with function
> >>>>>>>> local_flush_tlb_kernel_range() which only flush tlb with global =
bit.
> >>>>>>>>
> >>>>>>>> With function kernel_pte_init() added, it can be used to init pt=
e
> >>>>>>>> table when it is created for kernel address space, and the defau=
lt
> >>>>>>>> initial pte value is PAGE_GLOBAL rather than zero at beginning.
> >>>>>>>>
> >>>>>>>> Kernel address space areas includes fixmap, percpu, vmalloc, kas=
an
> >>>>>>>> and vmemmap areas set default pte entry with PAGE_GLOBAL set.
> >>>>>>>>
> >>>>>>>> Signed-off-by: Bibo Mao <maobibo@loongson.cn>
> >>>>>>>> ---
> >>>>>>>>      arch/loongarch/include/asm/pgalloc.h | 13 +++++++++++++
> >>>>>>>>      arch/loongarch/include/asm/pgtable.h |  1 +
> >>>>>>>>      arch/loongarch/mm/init.c             |  4 +++-
> >>>>>>>>      arch/loongarch/mm/kasan_init.c       |  4 +++-
> >>>>>>>>      arch/loongarch/mm/pgtable.c          | 22 +++++++++++++++++=
+++++
> >>>>>>>>      include/linux/mm.h                   |  1 +
> >>>>>>>>      mm/kasan/init.c                      |  8 +++++++-
> >>>>>>>>      mm/sparse-vmemmap.c                  |  5 +++++
> >>>>>>>>      8 files changed, 55 insertions(+), 3 deletions(-)
> >>>>>>>>
> >>>>>>>> diff --git a/arch/loongarch/include/asm/pgalloc.h b/arch/loongar=
ch/include/asm/pgalloc.h
> >>>>>>>> index 4e2d6b7ca2ee..b2698c03dc2c 100644
> >>>>>>>> --- a/arch/loongarch/include/asm/pgalloc.h
> >>>>>>>> +++ b/arch/loongarch/include/asm/pgalloc.h
> >>>>>>>> @@ -10,8 +10,21 @@
> >>>>>>>>
> >>>>>>>>      #define __HAVE_ARCH_PMD_ALLOC_ONE
> >>>>>>>>      #define __HAVE_ARCH_PUD_ALLOC_ONE
> >>>>>>>> +#define __HAVE_ARCH_PTE_ALLOC_ONE_KERNEL
> >>>>>>>>      #include <asm-generic/pgalloc.h>
> >>>>>>>>
> >>>>>>>> +static inline pte_t *pte_alloc_one_kernel(struct mm_struct *mm)
> >>>>>>>> +{
> >>>>>>>> +       pte_t *pte;
> >>>>>>>> +
> >>>>>>>> +       pte =3D (pte_t *) __get_free_page(GFP_KERNEL);
> >>>>>>>> +       if (!pte)
> >>>>>>>> +               return NULL;
> >>>>>>>> +
> >>>>>>>> +       kernel_pte_init(pte);
> >>>>>>>> +       return pte;
> >>>>>>>> +}
> >>>>>>>> +
> >>>>>>>>      static inline void pmd_populate_kernel(struct mm_struct *mm=
,
> >>>>>>>>                                            pmd_t *pmd, pte_t *pt=
e)
> >>>>>>>>      {
> >>>>>>>> diff --git a/arch/loongarch/include/asm/pgtable.h b/arch/loongar=
ch/include/asm/pgtable.h
> >>>>>>>> index 9965f52ef65b..22e3a8f96213 100644
> >>>>>>>> --- a/arch/loongarch/include/asm/pgtable.h
> >>>>>>>> +++ b/arch/loongarch/include/asm/pgtable.h
> >>>>>>>> @@ -269,6 +269,7 @@ extern void set_pmd_at(struct mm_struct *mm,=
 unsigned long addr, pmd_t *pmdp, pm
> >>>>>>>>      extern void pgd_init(void *addr);
> >>>>>>>>      extern void pud_init(void *addr);
> >>>>>>>>      extern void pmd_init(void *addr);
> >>>>>>>> +extern void kernel_pte_init(void *addr);
> >>>>>>>>
> >>>>>>>>      /*
> >>>>>>>>       * Encode/decode swap entries and swap PTEs. Swap PTEs are =
all PTEs that
> >>>>>>>> diff --git a/arch/loongarch/mm/init.c b/arch/loongarch/mm/init.c
> >>>>>>>> index 8a87a482c8f4..9f26e933a8a3 100644
> >>>>>>>> --- a/arch/loongarch/mm/init.c
> >>>>>>>> +++ b/arch/loongarch/mm/init.c
> >>>>>>>> @@ -198,9 +198,11 @@ pte_t * __init populate_kernel_pte(unsigned=
 long addr)
> >>>>>>>>             if (!pmd_present(pmdp_get(pmd))) {
> >>>>>>>>                     pte_t *pte;
> >>>>>>>>
> >>>>>>>> -               pte =3D memblock_alloc(PAGE_SIZE, PAGE_SIZE);
> >>>>>>>> +               pte =3D memblock_alloc_raw(PAGE_SIZE, PAGE_SIZE)=
;
> >>>>>>>>                     if (!pte)
> >>>>>>>>                             panic("%s: Failed to allocate memory=
\n", __func__);
> >>>>>>>> +
> >>>>>>>> +               kernel_pte_init(pte);
> >>>>>>>>                     pmd_populate_kernel(&init_mm, pmd, pte);
> >>>>>>>>             }
> >>>>>>>>
> >>>>>>>> diff --git a/arch/loongarch/mm/kasan_init.c b/arch/loongarch/mm/=
kasan_init.c
> >>>>>>>> index 427d6b1aec09..34988573b0d5 100644
> >>>>>>>> --- a/arch/loongarch/mm/kasan_init.c
> >>>>>>>> +++ b/arch/loongarch/mm/kasan_init.c
> >>>>>>>> @@ -152,6 +152,8 @@ static void __init kasan_pte_populate(pmd_t =
*pmdp, unsigned long addr,
> >>>>>>>>                     phys_addr_t page_phys =3D early ?
> >>>>>>>>                                             __pa_symbol(kasan_ea=
rly_shadow_page)
> >>>>>>>>                                                   : kasan_alloc_=
zeroed_page(node);
> >>>>>>>> +               if (!early)
> >>>>>>>> +                       kernel_pte_init(__va(page_phys));
> >>>>>>>>                     next =3D addr + PAGE_SIZE;
> >>>>>>>>                     set_pte(ptep, pfn_pte(__phys_to_pfn(page_phy=
s), PAGE_KERNEL));
> >>>>>>>>             } while (ptep++, addr =3D next, addr !=3D end && __p=
te_none(early, ptep_get(ptep)));
> >>>>>>>> @@ -287,7 +289,7 @@ void __init kasan_init(void)
> >>>>>>>>                     set_pte(&kasan_early_shadow_pte[i],
> >>>>>>>>                             pfn_pte(__phys_to_pfn(__pa_symbol(ka=
san_early_shadow_page)), PAGE_KERNEL_RO));
> >>>>>>>>
> >>>>>>>> -       memset(kasan_early_shadow_page, 0, PAGE_SIZE);
> >>>>>>>> +       kernel_pte_init(kasan_early_shadow_page);
> >>>>>>>>             csr_write64(__pa_symbol(swapper_pg_dir), LOONGARCH_C=
SR_PGDH);
> >>>>>>>>             local_flush_tlb_all();
> >>>>>>>>
> >>>>>>>> diff --git a/arch/loongarch/mm/pgtable.c b/arch/loongarch/mm/pgt=
able.c
> >>>>>>>> index eb6a29b491a7..228ffc1db0a3 100644
> >>>>>>>> --- a/arch/loongarch/mm/pgtable.c
> >>>>>>>> +++ b/arch/loongarch/mm/pgtable.c
> >>>>>>>> @@ -38,6 +38,28 @@ pgd_t *pgd_alloc(struct mm_struct *mm)
> >>>>>>>>      }
> >>>>>>>>      EXPORT_SYMBOL_GPL(pgd_alloc);
> >>>>>>>>
> >>>>>>>> +void kernel_pte_init(void *addr)
> >>>>>>>> +{
> >>>>>>>> +       unsigned long *p, *end;
> >>>>>>>> +       unsigned long entry;
> >>>>>>>> +
> >>>>>>>> +       entry =3D (unsigned long)_PAGE_GLOBAL;
> >>>>>>>> +       p =3D (unsigned long *)addr;
> >>>>>>>> +       end =3D p + PTRS_PER_PTE;
> >>>>>>>> +
> >>>>>>>> +       do {
> >>>>>>>> +               p[0] =3D entry;
> >>>>>>>> +               p[1] =3D entry;
> >>>>>>>> +               p[2] =3D entry;
> >>>>>>>> +               p[3] =3D entry;
> >>>>>>>> +               p[4] =3D entry;
> >>>>>>>> +               p +=3D 8;
> >>>>>>>> +               p[-3] =3D entry;
> >>>>>>>> +               p[-2] =3D entry;
> >>>>>>>> +               p[-1] =3D entry;
> >>>>>>>> +       } while (p !=3D end);
> >>>>>>>> +}
> >>>>>>>> +
> >>>>>>>>      void pgd_init(void *addr)
> >>>>>>>>      {
> >>>>>>>>             unsigned long *p, *end;
> >>>>>>>> diff --git a/include/linux/mm.h b/include/linux/mm.h
> >>>>>>>> index ecf63d2b0582..6909fe059a2c 100644
> >>>>>>>> --- a/include/linux/mm.h
> >>>>>>>> +++ b/include/linux/mm.h
> >>>>>>>> @@ -3818,6 +3818,7 @@ void *sparse_buffer_alloc(unsigned long si=
ze);
> >>>>>>>>      struct page * __populate_section_memmap(unsigned long pfn,
> >>>>>>>>                     unsigned long nr_pages, int nid, struct vmem=
_altmap *altmap,
> >>>>>>>>                     struct dev_pagemap *pgmap);
> >>>>>>>> +void kernel_pte_init(void *addr);
> >>>>>>>>      void pmd_init(void *addr);
> >>>>>>>>      void pud_init(void *addr);
> >>>>>>>>      pgd_t *vmemmap_pgd_populate(unsigned long addr, int node);
> >>>>>>>> diff --git a/mm/kasan/init.c b/mm/kasan/init.c
> >>>>>>>> index 89895f38f722..ac607c306292 100644
> >>>>>>>> --- a/mm/kasan/init.c
> >>>>>>>> +++ b/mm/kasan/init.c
> >>>>>>>> @@ -106,6 +106,10 @@ static void __ref zero_pte_populate(pmd_t *=
pmd, unsigned long addr,
> >>>>>>>>             }
> >>>>>>>>      }
> >>>>>>>>
> >>>>>>>> +void __weak __meminit kernel_pte_init(void *addr)
> >>>>>>>> +{
> >>>>>>>> +}
> >>>>>>>> +
> >>>>>>>>      static int __ref zero_pmd_populate(pud_t *pud, unsigned lon=
g addr,
> >>>>>>>>                                     unsigned long end)
> >>>>>>>>      {
> >>>>>>>> @@ -126,8 +130,10 @@ static int __ref zero_pmd_populate(pud_t *p=
ud, unsigned long addr,
> >>>>>>>>
> >>>>>>>>                             if (slab_is_available())
> >>>>>>>>                                     p =3D pte_alloc_one_kernel(&=
init_mm);
> >>>>>>>> -                       else
> >>>>>>>> +                       else {
> >>>>>>>>                                     p =3D early_alloc(PAGE_SIZE,=
 NUMA_NO_NODE);
> >>>>>>>> +                               kernel_pte_init(p);
> >>>>>>>> +                       }
> >>>>>>>>                             if (!p)
> >>>>>>>>                                     return -ENOMEM;
> >>>>>>>>
> >>>>>>>> diff --git a/mm/sparse-vmemmap.c b/mm/sparse-vmemmap.c
> >>>>>>>> index edcc7a6b0f6f..c0388b2e959d 100644
> >>>>>>>> --- a/mm/sparse-vmemmap.c
> >>>>>>>> +++ b/mm/sparse-vmemmap.c
> >>>>>>>> @@ -184,6 +184,10 @@ static void * __meminit vmemmap_alloc_block=
_zero(unsigned long size, int node)
> >>>>>>>>             return p;
> >>>>>>>>      }
> >>>>>>>>
> >>>>>>>> +void __weak __meminit kernel_pte_init(void *addr)
> >>>>>>>> +{
> >>>>>>>> +}
> >>>>>>>> +
> >>>>>>>>      pmd_t * __meminit vmemmap_pmd_populate(pud_t *pud, unsigned=
 long addr, int node)
> >>>>>>>>      {
> >>>>>>>>             pmd_t *pmd =3D pmd_offset(pud, addr);
> >>>>>>>> @@ -191,6 +195,7 @@ pmd_t * __meminit vmemmap_pmd_populate(pud_t=
 *pud, unsigned long addr, int node)
> >>>>>>>>                     void *p =3D vmemmap_alloc_block_zero(PAGE_SI=
ZE, node);
> >>>>>>>>                     if (!p)
> >>>>>>>>                             return NULL;
> >>>>>>>> +               kernel_pte_init(p);
> >>>>>>>>                     pmd_populate_kernel(&init_mm, pmd, p);
> >>>>>>>>             }
> >>>>>>>>             return pmd;
> >>>>>>>> --
> >>>>>>>> 2.39.3
> >>>>>>>>
> >>>>>>
> >>>>>>
> >>>>
> >>>>
> >>
> >>
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAAhV-H5CADad2EGv0zMQrgrvpNRtBTWDoXFj%3Dj%2BzXEJdy7HkAQ%40mail.gm=
ail.com.
