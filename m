Return-Path: <kasan-dev+bncBD52JJ7JXILRBE7JSCRQMGQE4QIH4VQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x93d.google.com (mail-ua1-x93d.google.com [IPv6:2607:f8b0:4864:20::93d])
	by mail.lfdr.de (Postfix) with ESMTPS id 1F5D6705CB3
	for <lists+kasan-dev@lfdr.de>; Wed, 17 May 2023 03:57:41 +0200 (CEST)
Received: by mail-ua1-x93d.google.com with SMTP id a1e0cc1a2514c-783777fc49asf87639241.2
        for <lists+kasan-dev@lfdr.de>; Tue, 16 May 2023 18:57:41 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1684288660; cv=pass;
        d=google.com; s=arc-20160816;
        b=H/mveYydRCJigKhWzrfK+S77nF4GLcIes3dx1zcwv7Qup3DJ2Z3DXgAstVTutJrIgf
         vu0vQ68d/FLesMVPfKOY4KSqVYEPPIeB83ADb0bIYMLxxSRo0CRZOOpPjA142H2MCw3C
         hdKq6X/6ucMlKpOjMHeZbQP8qTa0i+P+Tq4QvlJWWVH3dxrgvgA8xxXfQvPgZ7eeonzu
         0s+o3JOYGOBD5Lo+s1OkYNAJnZVNpzVeRZeTLXfKq67vJDxPfXWQSpuwqo02CbTmZRk2
         pJOc84p/0gMG5BjrVwBsMh7v2y1LHr6+J0JfZtvGfrA3Hcx2++gJA+cXugnR5kdl1QKB
         H8iA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=irRrsLHdwn6fu9OxywzNf4oyE6kvI99oyiEeI6z06Vk=;
        b=XAzew9s3tfcTxPqmNDwrqu8RPTw5XfaCakVx7EYy2zaBNnyvrXVLNeIuIJVZxLRL5F
         6FGE3KOUcO2s/KwC5cOIxd1QxElXjqwlVMWdiTEmjkE0a2UAy2EMYNsjjjBjS0tJpSiA
         8vuDwSiLjeMfevec2SV8BJ6DXK7RR6FB4S+RV8lNEpKBMEOBkSKt+yXoT3gTpYv5OsG8
         lKaudo3TH/aRHQtt7SLCYUBtgiRGzmU+xG5GP1i3DuB7kLtG4JGOI2UWr+sBEnPr6GkU
         NBrjncnHn2sbsgkO46FKwOpQuyoHEcNoH57ZhfVIMZ4Ezo0igT9C5ySd0b3lc+r7G1PQ
         f2LQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=G2g3cTJE;
       spf=pass (google.com: domain of pcc@google.com designates 2607:f8b0:4864:20::630 as permitted sender) smtp.mailfrom=pcc@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1684288660; x=1686880660;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=irRrsLHdwn6fu9OxywzNf4oyE6kvI99oyiEeI6z06Vk=;
        b=dwX90+INWLNwk7z5XKzIWastouoG1TXXJlVUAWBaQ+vu5yHQacwDJkmcCWRiy4MzqO
         2GjKMmUUEkxv71w5besiHKCkGFX1Q8UvGwIGTNewUKWY/rNkK8n2NRU+WEGZqirYp27v
         Cpl10WfIu15c7rMJugnyBtpPjt0yvsaAoAC+2Tzw+5XakFfMNxwf4macutmrahzW+EJ3
         AqXWnGyjrbo0TMmaAgKkFB58cr2jQLcVhsFtB1riBw+ssi6HyghKY0+cCCAuGpJiLt6q
         rugZ/RzesEGRLztBl9kXzllqYj/pBdCZsX2JuVP5zOaCwjVlSryni0UC+nUR2FT/pttu
         xaaA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1684288660; x=1686880660;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=irRrsLHdwn6fu9OxywzNf4oyE6kvI99oyiEeI6z06Vk=;
        b=lSffshBzJlV6dSgpDezdNiG8pOU4lzcoFnV603u7CT7cMZlveUbtTcEhDRfEsP5WA1
         KZIYKCx4UrDbWD3CDxzdduZi1gDEEtkYUNUJVVj4nvni7yCICLvNRpXWmZOsF2dq9gcI
         hgpvE57H4lIOc9gWRt4xuluzUGfK/3OpAwJrl++l/u59HYzWPJ9VNTa42UUB0jSF1+Jp
         3iNS6j/aGnFiXw8IQjr9erHzVd9IlZ2ZZx6YQIh0qcYjqxlAe/FEgdWJWTHHeoSe0i0v
         tCmB7Ax/YU/ft9ICLoEW5q2oJ3bjdN+V4EuOtIkIPElPTLNlit33ziywuBNrpwNTAGRG
         IK8g==
X-Gm-Message-State: AC+VfDwDZevJvIk3qITTqq5yeh6zAnkxwftz0qN/stMg9NFS5w5AZ4cD
	nxJyFeI2syJUad6jKivhxo8=
X-Google-Smtp-Source: ACHHUZ5w9t4afNEte8pgv6y7tskAirt2+IrvnUzm9T+m0MxmBUW36TkDZVrGWbIGeZtbWzr69qAdIg==
X-Received: by 2002:a67:d389:0:b0:434:77ed:5cdb with SMTP id b9-20020a67d389000000b0043477ed5cdbmr21262950vsj.3.1684288659848;
        Tue, 16 May 2023 18:57:39 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1f:aaca:0:b0:456:7492:58a7 with SMTP id t193-20020a1faaca000000b00456749258a7ls812638vke.9.-pod-prod-gmail;
 Tue, 16 May 2023 18:57:39 -0700 (PDT)
X-Received: by 2002:a1f:4510:0:b0:453:4ce3:21e9 with SMTP id s16-20020a1f4510000000b004534ce321e9mr8641109vka.10.1684288659027;
        Tue, 16 May 2023 18:57:39 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1684288659; cv=none;
        d=google.com; s=arc-20160816;
        b=rE/4xFdOwWD8Cq2qyyhNN9Z6d5FhOCBzffQ1FiX7IWSqUq0yGBYDXIFrizeF+Gr+RO
         Nrl4GkPBEteZNN3bB5Oq0NxnrCQI3yB643aySmjCO09gMcz566o052FtqXvuJsaZOJMD
         2iyloblYoyN09X3f4Jtl9lgTtBbeoufKrdBZt5dj2pIwv8O+yc9LwWsO8ILVjNeExgGa
         fYWIbGoU/kkOVkPN+k2JJWyp9++GtHHq+rE5pc7sz3lk9lJ7SNwtZczTPFO0uwXuVBj/
         WbIU/u/ZZTJ5+bQY+bVJQ7oyGRwml9upo3gC/tPqxjFDnrtKsB5tJtSfkaQ5ivVeU5q2
         bAmA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=m17guDOQ12FqooxLGjI6njqGM315YV7VFvugPBs5F1U=;
        b=wiGOioarSJTJnNM2FH1MEANKRhHMztFojaKlKRkXw7pBqg5FTaTTsfKBNaeCJD+EJq
         +iDC7dfcqgqfQLAvTV7mGcduaZ5fQm4LZ73q4UtXZSe5wcbHwkuAeS7wnlwn5mBoe9XU
         7KBdi6J6Of3LkP2MAM1YCbIWtmGQOKijOq++XMOhX84Tkosq/pcq4dpgHBjP/j9aRj3b
         KOKYevt8MO2q6scFk/XIrZtgSaHKlQdy/BQHbP/lu+BWuwvTBhjTDVQRz4TfPWl0bg6x
         KR9rxOuVZY2MJ2n165y5vEKY5PYXKKIMdy9fanvIYYLce5DYK6gn5jB6DhGM4cM/F2Un
         uG/A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=G2g3cTJE;
       spf=pass (google.com: domain of pcc@google.com designates 2607:f8b0:4864:20::630 as permitted sender) smtp.mailfrom=pcc@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pl1-x630.google.com (mail-pl1-x630.google.com. [2607:f8b0:4864:20::630])
        by gmr-mx.google.com with ESMTPS id br4-20020a0561220f8400b00450e301dcc7si1903616vkb.3.2023.05.16.18.57.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 16 May 2023 18:57:39 -0700 (PDT)
Received-SPF: pass (google.com: domain of pcc@google.com designates 2607:f8b0:4864:20::630 as permitted sender) client-ip=2607:f8b0:4864:20::630;
Received: by mail-pl1-x630.google.com with SMTP id d9443c01a7336-1aaf702c3ccso36935ad.1
        for <kasan-dev@googlegroups.com>; Tue, 16 May 2023 18:57:38 -0700 (PDT)
X-Received: by 2002:a17:902:ea09:b0:1ae:513a:944d with SMTP id
 s9-20020a170902ea0900b001ae513a944dmr71548plg.8.1684288657779; Tue, 16 May
 2023 18:57:37 -0700 (PDT)
MIME-Version: 1.0
References: <20230512235755.1589034-1-pcc@google.com> <20230512235755.1589034-2-pcc@google.com>
 <7471013e-4afb-e445-5985-2441155fc82c@redhat.com> <ZGJtJobLrBg3PtHm@arm.com>
 <ZGLC0T32sgVkG5kX@google.com> <851940cd-64f1-9e59-3de9-b50701a99281@redhat.com>
In-Reply-To: <851940cd-64f1-9e59-3de9-b50701a99281@redhat.com>
From: "'Peter Collingbourne' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 16 May 2023 18:57:26 -0700
Message-ID: <CAMn1gO79e+v3ceNY0YfwrYTvU1monKWmTedXsYjtucmM7s=MVA@mail.gmail.com>
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
 header.i=@google.com header.s=20221208 header.b=G2g3cTJE;       spf=pass
 (google.com: domain of pcc@google.com designates 2607:f8b0:4864:20::630 as
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

On Tue, May 16, 2023 at 5:35=E2=80=AFAM David Hildenbrand <david@redhat.com=
> wrote:
>
> On 16.05.23 01:40, Peter Collingbourne wrote:
> > On Mon, May 15, 2023 at 06:34:30PM +0100, Catalin Marinas wrote:
> >> On Sat, May 13, 2023 at 05:29:53AM +0200, David Hildenbrand wrote:
> >>> On 13.05.23 01:57, Peter Collingbourne wrote:
> >>>> diff --git a/mm/memory.c b/mm/memory.c
> >>>> index 01a23ad48a04..83268d287ff1 100644
> >>>> --- a/mm/memory.c
> >>>> +++ b/mm/memory.c
> >>>> @@ -3914,19 +3914,7 @@ vm_fault_t do_swap_page(struct vm_fault *vmf)
> >>>>                    }
> >>>>            }
> >>>> -  /*
> >>>> -   * Remove the swap entry and conditionally try to free up the swa=
pcache.
> >>>> -   * We're already holding a reference on the page but haven't mapp=
ed it
> >>>> -   * yet.
> >>>> -   */
> >>>> -  swap_free(entry);
> >>>> -  if (should_try_to_free_swap(folio, vma, vmf->flags))
> >>>> -          folio_free_swap(folio);
> >>>> -
> >>>> -  inc_mm_counter(vma->vm_mm, MM_ANONPAGES);
> >>>> -  dec_mm_counter(vma->vm_mm, MM_SWAPENTS);
> >>>>            pte =3D mk_pte(page, vma->vm_page_prot);
> >>>> -
> >>>>            /*
> >>>>             * Same logic as in do_wp_page(); however, optimize for p=
ages that are
> >>>>             * certainly not shared either because we just allocated =
them without
> >>>> @@ -3946,8 +3934,21 @@ vm_fault_t do_swap_page(struct vm_fault *vmf)
> >>>>                    pte =3D pte_mksoft_dirty(pte);
> >>>>            if (pte_swp_uffd_wp(vmf->orig_pte))
> >>>>                    pte =3D pte_mkuffd_wp(pte);
> >>>> +  arch_do_swap_page(vma->vm_mm, vma, vmf->address, pte, vmf->orig_p=
te);
> >>>>            vmf->orig_pte =3D pte;
> >>>> +  /*
> >>>> +   * Remove the swap entry and conditionally try to free up the swa=
pcache.
> >>>> +   * We're already holding a reference on the page but haven't mapp=
ed it
> >>>> +   * yet.
> >>>> +   */
> >>>> +  swap_free(entry);
> >>>> +  if (should_try_to_free_swap(folio, vma, vmf->flags))
> >>>> +          folio_free_swap(folio);
> >>>> +
> >>>> +  inc_mm_counter(vma->vm_mm, MM_ANONPAGES);
> >>>> +  dec_mm_counter(vma->vm_mm, MM_SWAPENTS);
> >>>> +
> >>>>            /* ksm created a completely new copy */
> >>>>            if (unlikely(folio !=3D swapcache && swapcache)) {
> >>>>                    page_add_new_anon_rmap(page, vma, vmf->address);
> >>>> @@ -3959,7 +3960,6 @@ vm_fault_t do_swap_page(struct vm_fault *vmf)
> >>>>            VM_BUG_ON(!folio_test_anon(folio) ||
> >>>>                            (pte_write(pte) && !PageAnonExclusive(pag=
e)));
> >>>>            set_pte_at(vma->vm_mm, vmf->address, vmf->pte, pte);
> >>>> -  arch_do_swap_page(vma->vm_mm, vma, vmf->address, pte, vmf->orig_p=
te);
> >>>>            folio_unlock(folio);
> >>>>            if (folio !=3D swapcache && swapcache) {
> >>>
> >>>
> >>> You are moving the folio_free_swap() call after the folio_ref_count(f=
olio)
> >>> =3D=3D 1 check, which means that such (previously) swapped pages that=
 are
> >>> exclusive cannot be detected as exclusive.
> >>>
> >>> There must be a better way to handle MTE here.
> >>>
> >>> Where are the tags stored, how is the location identified, and when a=
re they
> >>> effectively restored right now?
> >>
> >> I haven't gone through Peter's patches yet but a pretty good descripti=
on
> >> of the problem is here:
> >> https://lore.kernel.org/all/5050805753ac469e8d727c797c2218a9d780d434.c=
amel@mediatek.com/.
> >> I couldn't reproduce it with my swap setup but both Qun-wei and Peter
> >> triggered it.
> >
> > In order to reproduce this bug it is necessary for the swap slot cache
> > to be disabled, which is unlikely to occur during normal operation. I
> > was only able to reproduce the bug by disabling it forcefully with the
> > following patch:
> >
> > diff --git a/mm/swap_slots.c b/mm/swap_slots.c
> > index 0bec1f705f8e0..25afba16980c7 100644
> > --- a/mm/swap_slots.c
> > +++ b/mm/swap_slots.c
> > @@ -79,7 +79,7 @@ void disable_swap_slots_cache_lock(void)
> >
> >   static void __reenable_swap_slots_cache(void)
> >   {
> > -     swap_slot_cache_enabled =3D has_usable_swap();
> > +     swap_slot_cache_enabled =3D false;
> >   }
> >
> >   void reenable_swap_slots_cache_unlock(void)
> >
> > With that I can trigger the bug on an MTE-utilizing process by running
> > a program that enumerates the process's private anonymous mappings and
> > calls process_madvise(MADV_PAGEOUT) on all of them.
> >
> >> When a tagged page is swapped out, the arm64 code stores the metadata
> >> (tags) in a local xarray indexed by the swap pte. When restoring from
> >> swap, the arm64 set_pte_at() checks this xarray using the old swap pte
> >> and spills the tags onto the new page. Apparently something changed in
> >> the kernel recently that causes swap_range_free() to be called before
> >> set_pte_at(). The arm64 arch_swap_invalidate_page() frees the metadata
> >> from the xarray and the subsequent set_pte_at() won't find it.
> >>
> >> If we have the page, the metadata can be restored before set_pte_at()
> >> and I guess that's what Peter is trying to do (again, I haven't looked
> >> at the details yet; leaving it for tomorrow).
> >>
> >> Is there any other way of handling this? E.g. not release the metadata
> >> in arch_swap_invalidate_page() but later in set_pte_at() once it was
> >> restored. But then we may leak this metadata if there's no set_pte_at(=
)
> >> (the process mapping the swap entry died).
> >
> > Another problem that I can see with this approach is that it does not
> > respect reference counts for swap entries, and it's unclear whether tha=
t
> > can be done in a non-racy fashion.
> >
> > Another approach that I considered was to move the hook to swap_readpag=
e()
> > as in the patch below (sorry, it only applies to an older version
> > of Android's android14-6.1 branch and not mainline, but you get the
> > idea). But during a stress test (running the aforementioned program tha=
t
> > calls process_madvise(MADV_PAGEOUT) in a loop during an Android "monkey=
"
> > test) I discovered the following racy use-after-free that can occur whe=
n
> > two tasks T1 and T2 concurrently restore the same page:
> >
> > T1:                  | T2:
> > arch_swap_readpage() |
> >                       | arch_swap_readpage() -> mte_restore_tags() -> x=
e_load()
> > swap_free()          |
> >                       | arch_swap_readpage() -> mte_restore_tags() -> m=
te_restore_page_tags()
> >
> > We can avoid it by taking the swap_info_struct::lock spinlock in
> > mte_restore_tags(), but it seems like it would lead to lock contention.
> >
>
> Would the idea be to fail swap_readpage() on the one that comes last,
> simply retrying to lookup the page?

The idea would be that T2's arch_swap_readpage() could potentially not
find tags if it ran after swap_free(), so T2 would produce a page
without restored tags. But that wouldn't matter, because T1 reaching
swap_free() means that T2 will follow the goto at [1] after waiting
for T1 to unlock at [2], and T2's page will be discarded.

> This might be a naive question, but how does MTE play along with shared
> anonymous pages?

It should work fine. shmem_writepage() calls swap_writepage() which
calls arch_prepare_to_swap() to write the tags. And
shmem_swapin_folio() has a call to arch_swap_restore() to restore
them.

Peter

[1] https://github.com/torvalds/linux/blob/f1fcbaa18b28dec10281551dfe6ed3a3=
ed80e3d6/mm/memory.c#L3881
[2] https://github.com/torvalds/linux/blob/f1fcbaa18b28dec10281551dfe6ed3a3=
ed80e3d6/mm/memory.c#L4006

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAMn1gO79e%2Bv3ceNY0YfwrYTvU1monKWmTedXsYjtucmM7s%3DMVA%40mail.gm=
ail.com.
