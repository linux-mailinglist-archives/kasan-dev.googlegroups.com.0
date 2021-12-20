Return-Path: <kasan-dev+bncBDW2JDUY5AORB37PQOHAMGQEB2FLHVY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa38.google.com (mail-vk1-xa38.google.com [IPv6:2607:f8b0:4864:20::a38])
	by mail.lfdr.de (Postfix) with ESMTPS id 17A5647B54D
	for <lists+kasan-dev@lfdr.de>; Mon, 20 Dec 2021 22:38:57 +0100 (CET)
Received: by mail-vk1-xa38.google.com with SMTP id v62-20020a1fac41000000b002f4c0eb8185sf1962425vke.6
        for <lists+kasan-dev@lfdr.de>; Mon, 20 Dec 2021 13:38:57 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1640036336; cv=pass;
        d=google.com; s=arc-20160816;
        b=ZwTZG9PT6tiOJTc+CWPfkTJuO/4mEWZhxYl+7UJO3CymbTegjhHxV/A556w1J5b2da
         bHZrJQDLR2K5gCKv+fGoZ0sOMwg6HNE9Rens4dFvzKpWnz7B76/RFIX/QevQ0aU4mESt
         QmY362lRoVO7ko7bk1SZuD4WkHhEMGawoy0nW8Cq4Lah+ecxeNCNpgGx2aUfoGfTWEI0
         CmbHpItv13Pl9zwkuGxV3ksAQR0npN8oYVdYez6mqk3xw7HBbqTlmOGaPXYfkVbE8i5Q
         DChqlah+7IpCC3xpAvthVhcZI1bMUNDIIA14U8eSdgIseI0jnAXxkXruq1BJtRfGYE3y
         rtLw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=ri5G91CrgX5GfEbliFVbCLCVpWNFf2pTL1nqsXBOSVk=;
        b=JCJ89RYgywbwBtMUrpATgkc28GJ96BxptFTOw5/Ifufk53aWkJ/Hv//F9ibysKLPgf
         2gParjkjbUmaS0ZGyPW64eRNh1trcQ77HZfTJfb5qkvoQCBCjbsYBC9XRLdEqPro6Pu/
         fOemPxHmWq9/SvolAlBXktg70Ov8/QXneeq1iMHbSlFk2DwUmUdBLPLerzOGfuOlYUsb
         6gtIDAx+PFJwHK2Eciwk7zqEPKk4b5HlPMQbcrw+B1oJxitDOMWaQRTyJkMhaCbl8A+u
         YF+8VtqzcMZe9XiuoKmFaxKdpahU7tJpu/bv+lSKELcL/X0zo4MSyXetpW+uD9Chcbvi
         cWCQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=UTnVYe+G;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d35 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ri5G91CrgX5GfEbliFVbCLCVpWNFf2pTL1nqsXBOSVk=;
        b=tX5a3iYGMNwh4Ac/fxycdfb+XElUSwoC61z3TWpPXyPy4XCwFhjRcTmzW0MFAu9q/h
         yBIWRWmYQB9i97r+FAaXCHuq2F+/9fbni+ZWgIxltdBU/7HVTqfJQQpfXcZga2xHb0GU
         +2A5dxuZQILQUKY7BFU+Bx/a8aOoNcampQZpJzd2CyTzm4MmW9uCymTZ/d1JEnaASgaV
         LWvdLH0KShPrwvE+aIGBfQcZwQ7Sx96z4oh4cUJ3EJofklUsQXMm0S4FXl/1GkEo9xQ3
         6ky59uVWCYhSuNHsITjdzuK1wRCn5w8gMAxJQx4xw0q1w3PoP+63ycpM0ocjHhxquch3
         b79g==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ri5G91CrgX5GfEbliFVbCLCVpWNFf2pTL1nqsXBOSVk=;
        b=fdXeouoGA69k+MEJad+WHXC2jTLjUD0BHyIINgnn00vtaAvudY3XVcsPRmUFSz0c7h
         Yhg8xLP/9MBMNgZZpQ8Gjl6tZGACOJn33UOPH5oofSbqk0nO9hjxGUJ4aWqL8agS8Jvv
         rBoZx3tzs2jF2m3iztkv8WbHdLJcJmu4wGDC9Mk4Kg/X/1LU8cn5D3oO6eitMbRjSFBe
         f+hD0g/PeU5PRPusOdOOR3dE8VpqEPsv7zgGg+ffwv6ti3hYYsaGf95IQ/+EZ91MCJCR
         HFi93lMvurAu7zM3MzLaAxIIVmS/QIbKginNSaJghFPJYzIoDKoDNd57xrx0oRU1vCzY
         dh0g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ri5G91CrgX5GfEbliFVbCLCVpWNFf2pTL1nqsXBOSVk=;
        b=Rf0MvATnyQgNUIXdw2pns2RqeG1g0sjaJ4z688m8Cu6fWDDUol1id9XZMceyrxH+H7
         dAfNmGxjOfFY7EqU8lNJjJqqiJiw7m5TbG6E2lv6OeXI7l4iOf4nUOSePXO7M5/d7wEh
         ngtKvxwX/YXOzLr5dmZ2F1lA9C+c+xeW8sPQtG/AowyLNCwBptRdO9H3f9Vm4BqwaRbZ
         GoBh/l3k1c8e2O+yX7aRk4JWqAsZypWc8P1ZE63NzNYienaXeGLGN4C6TkgWndxahSo5
         I1fPbwSe0ttH9sJbdgettVW9jYpJZNi95/yvfc/QdoNjRGmMHP64jC8/VR8D2eow7aBN
         WeOQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531YLocyntz5xsYWWkKVF6HflLuQUZLG//WxmVOVMtpmg/2A+qXL
	5lEkg48ysNcxcA/qsLw2pm0=
X-Google-Smtp-Source: ABdhPJyPi1Vd8Iv1DyOvBTR9NMKcfqCnmOdvGgfhGFe9WiJ1h9uB+QC6H7B7z4Vn45p32Se8kufWPA==
X-Received: by 2002:a05:6102:3c6:: with SMTP id n6mr24224vsq.72.1640036335828;
        Mon, 20 Dec 2021 13:38:55 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1f:2407:: with SMTP id k7ls1680193vkk.5.gmail; Mon, 20 Dec
 2021 13:38:55 -0800 (PST)
X-Received: by 2002:a1f:c9c2:: with SMTP id z185mr6589014vkf.26.1640036335286;
        Mon, 20 Dec 2021 13:38:55 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1640036335; cv=none;
        d=google.com; s=arc-20160816;
        b=zgB6eXKwx7fsTDYckhPyITOHhwcVwh51evh8/xLnPvJu/cXHzzRjXr1QZALnbwWvmR
         U0JO3DxDtoriPGMIh+ezD4UwFQJ/bkxbsns2Puq6Gr0DW1DkfM707UlEDMIypozTAKpz
         0YBDIAdlnfFyG9uuSzN/ZSHdI6YKuVAXh1Kuixi8skrDcXEz1AqHmOr6JLE8sNr+08S9
         JIghZbBXO1a+a7HsNC5k+Woq5++ejluRlh26CXqgqV+URfk4akDHHC6c6KwGHmh8FbXc
         jko1Bjg5juKtVK9nQBQBosI2ia0HUd9xjEk1/3VemusmY74tEHKwYClG/7Ew/3sZtagf
         JITQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=jXmZ+qTH7fz9THsh6sRW8Beptw0SkxxLv33cz0RQxd4=;
        b=IxNrjGcD/99jOvPQPvg5zsREnwS/In2TI1Dr50oD9q8r5xRsrt5cb46YyFFlKGYISy
         E6ta+DDOe0MxYlgnhKsdR37m2K6+0z/Zf3tDnBT6S6bootHbIrw/whb2ldQaZGoijMGP
         w+7VjefF2bNSOjAMH0LaWgSnK0ioQiWtIsGA8xjKZSubJXw0ffukg/N1TuPHPl2mqKvq
         7BDdjE+7k3A7cLc+8ykOsOhkW1udcky5NmXXaiqKiiu5xV3lRs/7Tddouu85qoMNerka
         pjrqzd04B+iWngV6S4nfn1bPbujG7fpYJKhubZVn2pPk0Xx6S0lhhW4B9VHFwlmwD0M9
         RneQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=UTnVYe+G;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d35 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-io1-xd35.google.com (mail-io1-xd35.google.com. [2607:f8b0:4864:20::d35])
        by gmr-mx.google.com with ESMTPS id q70si143621vka.0.2021.12.20.13.38.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 20 Dec 2021 13:38:55 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d35 as permitted sender) client-ip=2607:f8b0:4864:20::d35;
Received: by mail-io1-xd35.google.com with SMTP id q72so15085206iod.12
        for <kasan-dev@googlegroups.com>; Mon, 20 Dec 2021 13:38:55 -0800 (PST)
X-Received: by 2002:a05:6638:2512:: with SMTP id v18mr104863jat.22.1640036334760;
 Mon, 20 Dec 2021 13:38:54 -0800 (PST)
MIME-Version: 1.0
References: <cover.1639432170.git.andreyknvl@google.com> <d91e501aef74c5bb924cae90b469ff0dc1d56488.1639432170.git.andreyknvl@google.com>
 <YbjQNdst07JqbG0j@arm.com> <CA+fCnZftd93rARJ+xpUApimkgTsN0RRmiSVnrUMkCvdSu4-tcA@mail.gmail.com>
 <YbjwN0YlDV4hm3x6@arm.com>
In-Reply-To: <YbjwN0YlDV4hm3x6@arm.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Mon, 20 Dec 2021 22:38:43 +0100
Message-ID: <CA+fCnZfmiqpnX-754Tqes6prNccG+cMzMEteqr+Ar8gM1RTjDg@mail.gmail.com>
Subject: Re: [PATCH mm v3 25/38] kasan, vmalloc, arm64: mark vmalloc mappings
 as pgprot_tagged
To: Catalin Marinas <catalin.marinas@arm.com>
Cc: andrey.konovalov@linux.dev, Marco Elver <elver@google.com>, 
	Alexander Potapenko <glider@google.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux Memory Management List <linux-mm@kvack.org>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Will Deacon <will@kernel.org>, Mark Rutland <mark.rutland@arm.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, Peter Collingbourne <pcc@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, LKML <linux-kernel@vger.kernel.org>, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=UTnVYe+G;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d35
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Tue, Dec 14, 2021 at 8:27 PM Catalin Marinas <catalin.marinas@arm.com> wrote:
>
> On Tue, Dec 14, 2021 at 07:27:09PM +0100, Andrey Konovalov wrote:
> > On Tue, Dec 14, 2021 at 6:11 PM Catalin Marinas <catalin.marinas@arm.com> wrote:
> > > On Mon, Dec 13, 2021 at 10:54:21PM +0100, andrey.konovalov@linux.dev wrote:
> > > > diff --git a/arch/arm64/include/asm/vmalloc.h b/arch/arm64/include/asm/vmalloc.h
> > > > index b9185503feae..3d35adf365bf 100644
> > > > --- a/arch/arm64/include/asm/vmalloc.h
> > > > +++ b/arch/arm64/include/asm/vmalloc.h
> > > > @@ -25,4 +25,14 @@ static inline bool arch_vmap_pmd_supported(pgprot_t prot)
> > > >
> > > >  #endif
> > > >
> > > > +#define arch_vmalloc_pgprot_modify arch_vmalloc_pgprot_modify
> > > > +static inline pgprot_t arch_vmalloc_pgprot_modify(pgprot_t prot)
> > > > +{
> > > > +     if (IS_ENABLED(CONFIG_KASAN_HW_TAGS) &&
> > > > +                     (pgprot_val(prot) == pgprot_val(PAGE_KERNEL)))
> > > > +             prot = pgprot_tagged(prot);
> > > > +
> > > > +     return prot;
> > > > +}
> > > > +
> > > >  #endif /* _ASM_ARM64_VMALLOC_H */
> > > > diff --git a/include/linux/vmalloc.h b/include/linux/vmalloc.h
> > > > index 28becb10d013..760caeedd749 100644
> > > > --- a/include/linux/vmalloc.h
> > > > +++ b/include/linux/vmalloc.h
> > > > @@ -115,6 +115,13 @@ static inline int arch_vmap_pte_supported_shift(unsigned long size)
> > > >  }
> > > >  #endif
> > > >
> > > > +#ifndef arch_vmalloc_pgprot_modify
> > > > +static inline pgprot_t arch_vmalloc_pgprot_modify(pgprot_t prot)
> > > > +{
> > > > +     return prot;
> > > > +}
> > > > +#endif
> > > > +
> > > >  /*
> > > >   *   Highlevel APIs for driver use
> > > >   */
> > > > diff --git a/mm/vmalloc.c b/mm/vmalloc.c
> > > > index 837ed355bfc6..58bd2f7f86d7 100644
> > > > --- a/mm/vmalloc.c
> > > > +++ b/mm/vmalloc.c
> > > > @@ -3060,6 +3060,8 @@ void *__vmalloc_node_range(unsigned long size, unsigned long align,
> > > >               return NULL;
> > > >       }
> > > >
> > > > +     prot = arch_vmalloc_pgprot_modify(prot);
> > > > +
> > > >       if (vmap_allow_huge && !(vm_flags & VM_NO_HUGE_VMAP)) {
> > > >               unsigned long size_per_node;
> > >
> > > I wonder whether we could fix the prot bits in the caller instead and we
> > > won't need to worry about the exec or the module_alloc() case. Something
> > > like:
> > >
> > > diff --git a/mm/vmalloc.c b/mm/vmalloc.c
> > > index d2a00ad4e1dd..4e8c61255b92 100644
> > > --- a/mm/vmalloc.c
> > > +++ b/mm/vmalloc.c
> > > @@ -3112,7 +3112,7 @@ void *__vmalloc_node(unsigned long size, unsigned long align,
> > >                             gfp_t gfp_mask, int node, const void *caller)
> > >  {
> > >         return __vmalloc_node_range(size, align, VMALLOC_START, VMALLOC_END,
> > > -                               gfp_mask, PAGE_KERNEL, 0, node, caller);
> > > +                       gfp_mask, pgprot_hwasan(PAGE_KERNEL), 0, node, caller);
> > >  }
> > >  /*
> > >   * This is only for performance analysis of vmalloc and stress purpose.
> > > @@ -3161,7 +3161,7 @@ EXPORT_SYMBOL(vmalloc);
> > >  void *vmalloc_no_huge(unsigned long size)
> > >  {
> > >         return __vmalloc_node_range(size, 1, VMALLOC_START, VMALLOC_END,
> > > -                                   GFP_KERNEL, PAGE_KERNEL, VM_NO_HUGE_VMAP,
> > > +                                   GFP_KERNEL, pgprot_hwasan(PAGE_KERNEL), VM_NO_HUGE_VMAP,
> > >                                     NUMA_NO_NODE, __builtin_return_address(0));
> > >  }
> > >  EXPORT_SYMBOL(vmalloc_no_huge);
> > >
> > > with pgprot_hwasan() defined to pgprot_tagged() only if KASAN_HW_TAGS is
> > > enabled.
> >
> > And also change kasan_unpoison_vmalloc() to tag only if
> > pgprot_tagged() has been applied, I assume.
> >
> > Hm. Then __vmalloc_node_range() callers will never get tagged memory
> > unless requested. I suppose that's OK, most of them untag the pointer
> > anyway.
> >
> > But this won't work for SW_TAGS mode, which is also affected by the
> > exec issue and needs those kasan_reset_tag()s in module_alloc()/BPF.
> > We could invent some virtual protection bit for it and reuse
> > pgprot_hwasan(). Not sure if this would be acceptable.
>
> Ah, a pgprot_hwasan() for the sw tags is probably not acceptable as this
> requires an unnecessary pte bit. An alternative could be a GFP flag that
> gets passed only from __vmalloc_node() etc.

This will still leave the BPF JIT special case though.

So I'm leaning towards keeping my approach.

Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZfmiqpnX-754Tqes6prNccG%2BcMzMEteqr%2BAr8gM1RTjDg%40mail.gmail.com.
