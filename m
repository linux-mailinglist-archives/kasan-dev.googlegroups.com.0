Return-Path: <kasan-dev+bncBD52JJ7JXILRBX67SCRQMGQEIJGCUSI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53f.google.com (mail-pg1-x53f.google.com [IPv6:2607:f8b0:4864:20::53f])
	by mail.lfdr.de (Postfix) with ESMTPS id 10A8E705C7F
	for <lists+kasan-dev@lfdr.de>; Wed, 17 May 2023 03:37:37 +0200 (CEST)
Received: by mail-pg1-x53f.google.com with SMTP id 41be03b00d2f7-5309f234146sf88874a12.0
        for <lists+kasan-dev@lfdr.de>; Tue, 16 May 2023 18:37:36 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1684287455; cv=pass;
        d=google.com; s=arc-20160816;
        b=rbDAFWlkHJQTDkIOWH0/Ay2Wc/fhL6RKjNAphxCGpSkYzfpDu0Rna7/+vDQy2sW34u
         JbHfwa+veW+iRvgKDRJLuFbVmNFODopFz3e77WEVOK5F8BgAOFbwdYK3BDB+6+2e66eY
         p/sEVf+frNU9FqMsF/b/Kl+ysTtIJYNDGclW3W4JzfkyDPK2sDxbjTVf18v8Vs0HdScH
         0DVF+ZyKaXV+33JFhe23UvG6iIrkL1PkLkkqcBWO8gAC0TML2yUysiQXrp9u+FChFr1b
         D7bQlP6gci+56Iz667TApnuHi3mG9erZPYgErDLd1jQ+rSX6zRTAhw+4ZBb0DMQjTS6h
         7Txg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=UaycVI+RbRgrQRoNLE+BX1aW99a4YQkO+g69SwsRYoM=;
        b=saOZK8PIGH+VfhqPie44/YWPVsaCGy10Qn8KhZVkNJ8LMFFDRCYhfOEbSfEpmO+SvP
         zJ7R6xJXGYH9UGx2yvO6vlAH7F539G8eVPUdwP7vDfq+j7Jd8qWGTzWEteUxysCPexuo
         kRGmeUxItlClZdR4y6baTfuLnA+rPWhFp6MVJZvZgHtWLhrSg2eK2hbnu//MWkYzvV6h
         H7Y9/AUHk+AybqvmNUwGOZvpHKC42Mov/y71VPr4xo+tI1QqnqaxERnuev9f2eetML7+
         ISStj1HVnLNyJSVlsv/Ki6zVFvY0rGG2WScybnVEaJgfth2W0N9iDjKmLrcibr2cJ2b8
         +jvA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=bVTAd5SO;
       spf=pass (google.com: domain of pcc@google.com designates 2607:f8b0:4864:20::12d as permitted sender) smtp.mailfrom=pcc@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1684287455; x=1686879455;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=UaycVI+RbRgrQRoNLE+BX1aW99a4YQkO+g69SwsRYoM=;
        b=iV3vki/ibMrlfZB6AN/I4q5XKGE71d9Ap3KC7ad5d5SlvDE964nbvV/aAnLdAhb7pr
         QLnDByYU9jMBoRwJXaspbCOvM0+a14Tn7wPUkfIMqT34nODZTFO8D8DDdYMSaan+hFtO
         Qm2O18WboC072S0ydWEQEI1y0X7rbKHKhQfSvPkNcuPI0PtQHe/HUJ5SdaFUOgm3DI4d
         xAM8iBtQsn5JL8UafvmtaVVbqZ+pbAcGcYC0U25Ea9BS3ZDQCu+/gBTGI9Eo+ov0KYQ7
         mCnJ7MjJA/SgMQVsGMw9lgbglF3f9BxPfjn0mx73iBRer+y8VtTlnXr+kGxxy7HzFVHP
         sddw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1684287455; x=1686879455;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=UaycVI+RbRgrQRoNLE+BX1aW99a4YQkO+g69SwsRYoM=;
        b=LiOhz3zLYNfxeJdMFeDXIqo7AVfj5zfHvsbPF+13URcEBYZT02KIFn8SEPtCb5Rt9L
         0gHgwID2U1yNNSXWoQgdTGGx6gP3yoZcbk0gMczANcZI/AwVu1g7YSQBvrK8A8TkB+cx
         SXVK1/fHB//g3NXwh6DHMZv2+TzXLK15MNq3ApRl+bavgbV8RGdbfXLZXghJFFiQ2wMs
         2o27yJ/dmSpkjUeik/Xmkc5sYK/WX4FQGlIauAg2OLGkd+gzRKjVnyvHxsgjGkbm47kN
         rpOwB8e2FKJaN6hKL/Xy1CmDE5s2FwkrS4uLUiWOmbZKPxschYw67VZeop4gNpblaTOV
         RSAg==
X-Gm-Message-State: AC+VfDxsiiAsT6CSiVppKEMPy+vXf6xZjY5sV4eN5IuOi6Pa3SG8y4nH
	+1vK7biTdr6mxc/a4gfO3kY=
X-Google-Smtp-Source: ACHHUZ4Eqy3OgD9Tl/C5cz9SNytF4fDqAl7QuiyW3MFfoWJCX255vahS2Odcus6HCzk5joz+5qxTKg==
X-Received: by 2002:a63:2cd4:0:b0:52c:30f8:fb2a with SMTP id s203-20020a632cd4000000b0052c30f8fb2amr11073196pgs.9.1684287455185;
        Tue, 16 May 2023 18:37:35 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:e1cc:b0:196:751e:4f6e with SMTP id
 t12-20020a170902e1cc00b00196751e4f6els7115692pla.10.-pod-prod-gmail; Tue, 16
 May 2023 18:37:34 -0700 (PDT)
X-Received: by 2002:a17:90a:1d0c:b0:252:ad82:aeb7 with SMTP id c12-20020a17090a1d0c00b00252ad82aeb7mr17093082pjd.38.1684287454416;
        Tue, 16 May 2023 18:37:34 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1684287454; cv=none;
        d=google.com; s=arc-20160816;
        b=CSmgXFgbinzPTaiDjtsc/sJo4rPwSHa5i3LqJ0prx2wzrwE7s+1iAWBAoRJQ25A9M+
         +s6s+wKQnAYItCkgMncTWj/RU4gdcQCPAfB17MPC9dsORh+y2kIBluW7gm5e1m9ijLZE
         s/wxOYE40ZjdkzhUnbYvPMsDZIHo7hFr/GZ5Eg5FSbTRdIUx1+5mABTCKcVLnJDN+48A
         cE2KovNqdtVklJUAZ9/yQs+2yLH1Znlk4PGSUfLJVPUv/YKDNiNbX1rf/ULnx1vZ+aH+
         C7zHUXqJ41hwbTdVgtpyjQRqQzeYMkGeKmEcPhEaoLDzEpyyP4Hsmfe/ekYysJ5oYHqZ
         A6Og==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=QLugHt0XGPwYTpMjCAQObsffP9JpeGqJnJJt+CEzfkw=;
        b=fz4mEHkEzbkEmaP/dcaS+gN1GtN/RNa9sVPqOaxBvL18YulSy3qRd5kNwCvyjngWni
         ukCQtlfnsJ2BdGqUpiAErAa24FiZgYtBFuDxW1nXxN6oBOyjsSFqgaINQm7g321UYcXR
         XMt34wY6frGU7cbW+DXc327UO+rRuIcm985GWLu0pJeckoA9LAMvu3En/xeQQUriFAJN
         lTOigeQ76s3vZZYmBGKon0HJ44uo6GRO+fRAY8vvGA6NOYi1U7NqivRkDs+qvv/HUOMx
         If6ltTKjTnaKfkIkqq/jPrdmyouLrGgsT8UW+kzNgR+WIwuhvq/6Z2G7tcVM3KVNc1o4
         5voQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=bVTAd5SO;
       spf=pass (google.com: domain of pcc@google.com designates 2607:f8b0:4864:20::12d as permitted sender) smtp.mailfrom=pcc@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-il1-x12d.google.com (mail-il1-x12d.google.com. [2607:f8b0:4864:20::12d])
        by gmr-mx.google.com with ESMTPS id v6-20020a17090a4ec600b00250044dc33esi2051pjl.3.2023.05.16.18.37.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 16 May 2023 18:37:34 -0700 (PDT)
Received-SPF: pass (google.com: domain of pcc@google.com designates 2607:f8b0:4864:20::12d as permitted sender) client-ip=2607:f8b0:4864:20::12d;
Received: by mail-il1-x12d.google.com with SMTP id e9e14a558f8ab-33164ec77ccso57275ab.0
        for <kasan-dev@googlegroups.com>; Tue, 16 May 2023 18:37:34 -0700 (PDT)
X-Received: by 2002:a05:6e02:1a4a:b0:331:948c:86f3 with SMTP id
 u10-20020a056e021a4a00b00331948c86f3mr64152ilv.19.1684287453632; Tue, 16 May
 2023 18:37:33 -0700 (PDT)
MIME-Version: 1.0
References: <20230512235755.1589034-1-pcc@google.com> <20230512235755.1589034-2-pcc@google.com>
 <7471013e-4afb-e445-5985-2441155fc82c@redhat.com> <ZGJtJobLrBg3PtHm@arm.com> <91246137-a3d2-689f-8ff6-eccc0e61c8fe@redhat.com>
In-Reply-To: <91246137-a3d2-689f-8ff6-eccc0e61c8fe@redhat.com>
From: "'Peter Collingbourne' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 16 May 2023 18:37:22 -0700
Message-ID: <CAMn1gO4cbEmpDzkdN10DyaGe=2Wg4Y19-v8gHRqgQoD4Bxd+cw@mail.gmail.com>
Subject: Re: [PATCH 1/3] mm: Move arch_do_swap_page() call to before swap_free()
To: David Hildenbrand <david@redhat.com>
Cc: Catalin Marinas <catalin.marinas@arm.com>, 
	=?UTF-8?B?UXVuLXdlaSBMaW4gKOael+e+pOW0tCk=?= <Qun-wei.Lin@mediatek.com>, 
	linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, "surenb@google.com" <surenb@google.com>, 
	=?UTF-8?B?Q2hpbndlbiBDaGFuZyAo5by16Yym5paHKQ==?= <chinwen.chang@mediatek.com>, 
	"kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>, 
	=?UTF-8?B?S3Vhbi1ZaW5nIExlZSAo5p2O5Yag56mOKQ==?= <Kuan-Ying.Lee@mediatek.com>, 
	=?UTF-8?B?Q2FzcGVyIExpICjmnY7kuK3mpq4p?= <casper.li@mediatek.com>, 
	"gregkh@linuxfoundation.org" <gregkh@linuxfoundation.org>, vincenzo.frascino@arm.com, 
	Alexandru Elisei <alexandru.elisei@arm.com>, will@kernel.org, eugenis@google.com, 
	Steven Price <steven.price@arm.com>, stable@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: pcc@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20221208 header.b=bVTAd5SO;       spf=pass
 (google.com: domain of pcc@google.com designates 2607:f8b0:4864:20::12d as
 permitted sender) smtp.mailfrom=pcc@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Peter Collingbourne <pcc@google.com>
Reply-To: Peter Collingbourne <pcc@google.com>
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

On Tue, May 16, 2023 at 5:31=E2=80=AFAM David Hildenbrand <david@redhat.com=
> wrote:
>
> On 15.05.23 19:34, Catalin Marinas wrote:
> > On Sat, May 13, 2023 at 05:29:53AM +0200, David Hildenbrand wrote:
> >> On 13.05.23 01:57, Peter Collingbourne wrote:
> >>> diff --git a/mm/memory.c b/mm/memory.c
> >>> index 01a23ad48a04..83268d287ff1 100644
> >>> --- a/mm/memory.c
> >>> +++ b/mm/memory.c
> >>> @@ -3914,19 +3914,7 @@ vm_fault_t do_swap_page(struct vm_fault *vmf)
> >>>             }
> >>>     }
> >>> -   /*
> >>> -    * Remove the swap entry and conditionally try to free up the swa=
pcache.
> >>> -    * We're already holding a reference on the page but haven't mapp=
ed it
> >>> -    * yet.
> >>> -    */
> >>> -   swap_free(entry);
> >>> -   if (should_try_to_free_swap(folio, vma, vmf->flags))
> >>> -           folio_free_swap(folio);
> >>> -
> >>> -   inc_mm_counter(vma->vm_mm, MM_ANONPAGES);
> >>> -   dec_mm_counter(vma->vm_mm, MM_SWAPENTS);
> >>>     pte =3D mk_pte(page, vma->vm_page_prot);
> >>> -
> >>>     /*
> >>>      * Same logic as in do_wp_page(); however, optimize for pages tha=
t are
> >>>      * certainly not shared either because we just allocated them wit=
hout
> >>> @@ -3946,8 +3934,21 @@ vm_fault_t do_swap_page(struct vm_fault *vmf)
> >>>             pte =3D pte_mksoft_dirty(pte);
> >>>     if (pte_swp_uffd_wp(vmf->orig_pte))
> >>>             pte =3D pte_mkuffd_wp(pte);
> >>> +   arch_do_swap_page(vma->vm_mm, vma, vmf->address, pte, vmf->orig_p=
te);
> >>>     vmf->orig_pte =3D pte;
> >>> +   /*
> >>> +    * Remove the swap entry and conditionally try to free up the swa=
pcache.
> >>> +    * We're already holding a reference on the page but haven't mapp=
ed it
> >>> +    * yet.
> >>> +    */
> >>> +   swap_free(entry);
> >>> +   if (should_try_to_free_swap(folio, vma, vmf->flags))
> >>> +           folio_free_swap(folio);
> >>> +
> >>> +   inc_mm_counter(vma->vm_mm, MM_ANONPAGES);
> >>> +   dec_mm_counter(vma->vm_mm, MM_SWAPENTS);
> >>> +
> >>>     /* ksm created a completely new copy */
> >>>     if (unlikely(folio !=3D swapcache && swapcache)) {
> >>>             page_add_new_anon_rmap(page, vma, vmf->address);
> >>> @@ -3959,7 +3960,6 @@ vm_fault_t do_swap_page(struct vm_fault *vmf)
> >>>     VM_BUG_ON(!folio_test_anon(folio) ||
> >>>                     (pte_write(pte) && !PageAnonExclusive(page)));
> >>>     set_pte_at(vma->vm_mm, vmf->address, vmf->pte, pte);
> >>> -   arch_do_swap_page(vma->vm_mm, vma, vmf->address, pte, vmf->orig_p=
te);
> >>>     folio_unlock(folio);
> >>>     if (folio !=3D swapcache && swapcache) {
> >>
> >>
> >> You are moving the folio_free_swap() call after the folio_ref_count(fo=
lio)
> >> =3D=3D 1 check, which means that such (previously) swapped pages that =
are
> >> exclusive cannot be detected as exclusive.
> >>
> >> There must be a better way to handle MTE here.
> >>
> >> Where are the tags stored, how is the location identified, and when ar=
e they
> >> effectively restored right now?
> >
> > I haven't gone through Peter's patches yet but a pretty good descriptio=
n
> > of the problem is here:
> > https://lore.kernel.org/all/5050805753ac469e8d727c797c2218a9d780d434.ca=
mel@mediatek.com/.
> > I couldn't reproduce it with my swap setup but both Qun-wei and Peter
> > triggered it.
> >
> > When a tagged page is swapped out, the arm64 code stores the metadata
> > (tags) in a local xarray indexed by the swap pte. When restoring from
> > swap, the arm64 set_pte_at() checks this xarray using the old swap pte
> > and spills the tags onto the new page. Apparently something changed in
> > the kernel recently that causes swap_range_free() to be called before
> > set_pte_at(). The arm64 arch_swap_invalidate_page() frees the metadata
> > from the xarray and the subsequent set_pte_at() won't find it.
> >
> > If we have the page, the metadata can be restored before set_pte_at()
> > and I guess that's what Peter is trying to do (again, I haven't looked
> > at the details yet; leaving it for tomorrow).
>
> Thanks for the details! I was missing that we also have a hook in
> swap_range_free().
>
> >
> > Is there any other way of handling this? E.g. not release the metadata
> > in arch_swap_invalidate_page() but later in set_pte_at() once it was
> > restored. But then we may leak this metadata if there's no set_pte_at()
> > (the process mapping the swap entry died).
>
> That was my immediate thought: do we really have to hook into
> swap_range_free() at all?

As I alluded to in another reply, without the hook in
swap_range_free() I think we would either end up with a race or an
effective memory leak in the arch code that maintains the metadata for
swapped out pages, as there would be no way for the arch-specific code
to know when it is safe to free it after swapin.

> And I also wondered why we have to do this
> from set_pte_at() and not do this explicitly (maybe that's the other
> arch_* callback on the swapin path).

I don't think it's necessary, as the set_pte_at() call sites for
swapped in pages are known. I'd much rather do this via an explicit
hook at those call sites, as the existing approach of implicit
restoring seems too subtle and easy to be overlooked when refactoring,
as we have seen with this bug. In the end we only have 3 call sites
for the hook and hopefully the comments that I'm adding are sufficient
to ensure that any new swapin code should end up with a call to the
hook in the right place.

Peter

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAMn1gO4cbEmpDzkdN10DyaGe%3D2Wg4Y19-v8gHRqgQoD4Bxd%2Bcw%40mail.gm=
ail.com.
