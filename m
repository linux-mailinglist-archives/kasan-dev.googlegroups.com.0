Return-Path: <kasan-dev+bncBDW2JDUY5AORBCGE4OGQMGQEE644N6A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3b.google.com (mail-yb1-xb3b.google.com [IPv6:2607:f8b0:4864:20::b3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 7D8D5474AD3
	for <lists+kasan-dev@lfdr.de>; Tue, 14 Dec 2021 19:27:21 +0100 (CET)
Received: by mail-yb1-xb3b.google.com with SMTP id s189-20020a252cc6000000b005c1f206d91esf38075312ybs.14
        for <lists+kasan-dev@lfdr.de>; Tue, 14 Dec 2021 10:27:21 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1639506440; cv=pass;
        d=google.com; s=arc-20160816;
        b=Qm1UdK+OpoIrbjVJAybZwcWTETwhEQG/RmpaEfGl9y7QMadaMkgrPxUUSgpOPlmJpH
         XYdIOkvi1xLSf1TBGd3Rov7p2wZ+8iFdxq9zmjyML3BQ9ayvsy2n1ankEA5TLJjKMQhj
         T+Eo5XaUgf9gjnDE1Zoti8j+LWdrym8HWI2e1CGSx1LcohBQAYIVb9+Mar0CH0pu04Ur
         2QgjTcQ/WT4psQGPtVTcRWfiDvVMZ7H7doN+DoUtAfhi4GYJbd6+BiYQFsaU5RwEeI0X
         jBRh58r2gSF6Hrx1z9xiJHe61Ucz/PZMTBxjfgx41YAaZct+mfzcie4fYbCnXDjChunP
         bZXg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=/+A8Sqq3ve/LWqMwpQlyhnwUEXr95Fhcq4lqQhz9yEE=;
        b=hzjrx+Dm9mjMkuwD9A695riC+yOX2l2CQkpai7c2szAY8tDN6gD7dcHniGjB+3vqHZ
         6/4MhLoCpARr30OpG//B8ahS5w9veoJHmW1JOoEIXEuiVYRh1u4xYrChY4L/1GqKK8yP
         YIhRlHdTIvUGUpbt2XE+rV+ENUZz+XhUSKGa2zTW6kEQuswfmI8NRextKRXO1SCv4KaS
         3k5M4BRUR7DrLTTUpGCMCyuVEvwhWLfQdJz0gVFE3Y/7bupSmDWe35D9+NFBcVJbPnw8
         MhdXeSrQUTBLTNyEuo59mURP/TTCsfuKx6SB7e0tKPIqnvj+Fq/eDHKgwsYrEFBpSL9E
         wxbA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=g+76lc8h;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d2b as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=/+A8Sqq3ve/LWqMwpQlyhnwUEXr95Fhcq4lqQhz9yEE=;
        b=Gx6dxNcYHr1lnUO6fFd3pdzG8KnFraZD5Vr1URMauV4TZLPTMENUE0VA+n91vYxHxU
         QThm3yw7kD4YNY11h5KTbRU/Wd2gWtWmK8zW8LF23FcQiHViZYwJ9zxc69xay9/e5Oww
         vAJ8WP/nIocwRdVSH3mbc53a/bwt8PipwECoA9zp7GdzQMD5VHWiQ/Q8kPq/2OcRBMZ1
         N8gJlfPmDt0lvIMxz17ggw5U6aggXKHaSkkpJANuiKusxMVH0nB2rtuLXfMjyHzUdZlM
         4yqCxgd4tgOjYDZOWAwaZ2feCl6WZrnYGVahBh4S1e+5SeEAf5JUD3qLT3Tq3bi8bssV
         7uIw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=/+A8Sqq3ve/LWqMwpQlyhnwUEXr95Fhcq4lqQhz9yEE=;
        b=aMF/xjIItwnQFnxDXjfUo2nskUIDpu5LbRSuHD8wZNzC4x47jgImw3aqWhtCkQ7Nc0
         S/oShHKsKM5d02xaT41IRUR2XYJLHZRHYwaYfCFEXjXV82M6QGQvEo3mnN95P/Rq2T1A
         8tmDOuO1i0a1Oxgl2/eGl6XZwNdaNnNwRqnJAz8N6i83g/aOAU9FuI64Ctd4snZonVwP
         H1Hvd31kBZuWD3pH+n+O1RxulUAnMm0nKmiILbHUwxJaiR3i8dpXGsZyjF3T8sIZhSfb
         cT+LumIOV4UemAnZ2omtzTSqL5vA/HLcIYyp24ObQ0OnJ8o2mmkb9vtw8h1iPsow7ZrD
         H8+Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=/+A8Sqq3ve/LWqMwpQlyhnwUEXr95Fhcq4lqQhz9yEE=;
        b=WRNuTPFSWtC+RPGi48cKKsNWxf9SjTABboP+B+hFPTWDPqhJ+clWgoAP1BFNRgza2p
         5dTT37AZCQd8pLvMRK3RUzDcKkrqlQqa+ThYC8XFzBDRv+HkWlJh6xLw9tgu5Ex+41Vn
         qMcDE4gw7D2LYY8eGG+EyNN73ubt9/iTXu23A7iWLxN0ylB9yJs/alsV4NRH5mlSORUW
         h1yQbioIPSEy1UElr/2FsKUU/FpJfwwsegonZPf37FcnByfrpjWBFlsX0Ew2JEivnDH/
         qXSO7eA/pIkvmmXxaSuIw7VGuHYJ1Xrgo/9TzMvZG3oSTS2frlQZb+unf+6bHdQN2JxD
         3Heg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530Y4DaZRrAQB5mvOhLOFc0IT0qykGKQzvSr5QJoANEQVHGqfpk4
	4w8TYYR1YKggAPsTg9nwUaY=
X-Google-Smtp-Source: ABdhPJxGDk6w7dIQ1wFVdIt1HSG/PLn35+FNLG7zEB3J19d/D+qY/d0mwaEk4+01+2DqOFds5GOgmQ==
X-Received: by 2002:a25:3ac1:: with SMTP id h184mr706586yba.734.1639506440309;
        Tue, 14 Dec 2021 10:27:20 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:a562:: with SMTP id h89ls3400168ybi.8.gmail; Tue, 14 Dec
 2021 10:27:19 -0800 (PST)
X-Received: by 2002:a5b:d41:: with SMTP id f1mr754576ybr.447.1639506439900;
        Tue, 14 Dec 2021 10:27:19 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1639506439; cv=none;
        d=google.com; s=arc-20160816;
        b=ISHeb1MV3Sj8S6KVs801AJoDkUOV2KxmPLVOHXDUj0wA0wR2zU8QGFdY1boXGUGzIZ
         Vmyt2O49FZOsOlhgyO/pm1WT9Uz8BskzNSbKwu2MgV7ckaFT7gcxjS55GxyTrtpogag3
         tjNTYePipJA8foM8L6hv79SXT4srdtwmJviDBJ75bePid01dOHD158tetQQyeBZge/tQ
         Z6+4P9Q5dI2k8b4XWwzNQexyCFrkjqMyfSlpEgwJDK1k4Yl/jeojOx3XeFB+/NgnH4ex
         Jj7E3Tg37JMVXGdKA3wHOO2YG36p1xP9vbqzcmWVRm1gjoEVtLwY3Lmu5dfajQSE6POl
         3PXQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=yNu0JL6HpXjcm/zqB+v+1VOlm3E56pclkPSbwxcr2Ow=;
        b=KzmtzY0CKwyQE62D2sBToXrP/GTP+Ofi9o5jWE3OvGPX8t4GlrLTf6tQNxp9pwWLiD
         mEqhDenOOq40fRLxITqWT8XnzGeME+v6eVUMTFUC6eW7nL1v2DACFe0jk7cKh5eG0lbI
         /OzIIP8crKaK6DNBCI9YsIoTKDzJoqVkKo8VXA//fFlkhQWnhfFDabB6iEhkHFeu9Sk1
         au4yn0MloXQrQ5Dp64T5zTS3P0e27fMWu3aAfcSRH5ngSFinvLDdmnfqOvwxGRcmxP4A
         QMT7HNe0qqUcLtzRGhwLy8ICmwGarU60jCI/E2duVEWnGrAUlBG+Npwn7mtf9OVmSnxr
         65Ng==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=g+76lc8h;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d2b as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-io1-xd2b.google.com (mail-io1-xd2b.google.com. [2607:f8b0:4864:20::d2b])
        by gmr-mx.google.com with ESMTPS id a38si48874ybi.4.2021.12.14.10.27.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 14 Dec 2021 10:27:19 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d2b as permitted sender) client-ip=2607:f8b0:4864:20::d2b;
Received: by mail-io1-xd2b.google.com with SMTP id c3so25831121iob.6
        for <kasan-dev@googlegroups.com>; Tue, 14 Dec 2021 10:27:19 -0800 (PST)
X-Received: by 2002:a02:c04d:: with SMTP id u13mr3876471jam.524.1639506439659;
 Tue, 14 Dec 2021 10:27:19 -0800 (PST)
MIME-Version: 1.0
References: <cover.1639432170.git.andreyknvl@google.com> <d91e501aef74c5bb924cae90b469ff0dc1d56488.1639432170.git.andreyknvl@google.com>
 <YbjQNdst07JqbG0j@arm.com>
In-Reply-To: <YbjQNdst07JqbG0j@arm.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Tue, 14 Dec 2021 19:27:09 +0100
Message-ID: <CA+fCnZftd93rARJ+xpUApimkgTsN0RRmiSVnrUMkCvdSu4-tcA@mail.gmail.com>
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
 header.i=@gmail.com header.s=20210112 header.b=g+76lc8h;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d2b
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

On Tue, Dec 14, 2021 at 6:11 PM Catalin Marinas <catalin.marinas@arm.com> wrote:
>
> On Mon, Dec 13, 2021 at 10:54:21PM +0100, andrey.konovalov@linux.dev wrote:
> > diff --git a/arch/arm64/include/asm/vmalloc.h b/arch/arm64/include/asm/vmalloc.h
> > index b9185503feae..3d35adf365bf 100644
> > --- a/arch/arm64/include/asm/vmalloc.h
> > +++ b/arch/arm64/include/asm/vmalloc.h
> > @@ -25,4 +25,14 @@ static inline bool arch_vmap_pmd_supported(pgprot_t prot)
> >
> >  #endif
> >
> > +#define arch_vmalloc_pgprot_modify arch_vmalloc_pgprot_modify
> > +static inline pgprot_t arch_vmalloc_pgprot_modify(pgprot_t prot)
> > +{
> > +     if (IS_ENABLED(CONFIG_KASAN_HW_TAGS) &&
> > +                     (pgprot_val(prot) == pgprot_val(PAGE_KERNEL)))
> > +             prot = pgprot_tagged(prot);
> > +
> > +     return prot;
> > +}
> > +
> >  #endif /* _ASM_ARM64_VMALLOC_H */
> > diff --git a/include/linux/vmalloc.h b/include/linux/vmalloc.h
> > index 28becb10d013..760caeedd749 100644
> > --- a/include/linux/vmalloc.h
> > +++ b/include/linux/vmalloc.h
> > @@ -115,6 +115,13 @@ static inline int arch_vmap_pte_supported_shift(unsigned long size)
> >  }
> >  #endif
> >
> > +#ifndef arch_vmalloc_pgprot_modify
> > +static inline pgprot_t arch_vmalloc_pgprot_modify(pgprot_t prot)
> > +{
> > +     return prot;
> > +}
> > +#endif
> > +
> >  /*
> >   *   Highlevel APIs for driver use
> >   */
> > diff --git a/mm/vmalloc.c b/mm/vmalloc.c
> > index 837ed355bfc6..58bd2f7f86d7 100644
> > --- a/mm/vmalloc.c
> > +++ b/mm/vmalloc.c
> > @@ -3060,6 +3060,8 @@ void *__vmalloc_node_range(unsigned long size, unsigned long align,
> >               return NULL;
> >       }
> >
> > +     prot = arch_vmalloc_pgprot_modify(prot);
> > +
> >       if (vmap_allow_huge && !(vm_flags & VM_NO_HUGE_VMAP)) {
> >               unsigned long size_per_node;
>
> I wonder whether we could fix the prot bits in the caller instead and we
> won't need to worry about the exec or the module_alloc() case. Something
> like:
>
> diff --git a/mm/vmalloc.c b/mm/vmalloc.c
> index d2a00ad4e1dd..4e8c61255b92 100644
> --- a/mm/vmalloc.c
> +++ b/mm/vmalloc.c
> @@ -3112,7 +3112,7 @@ void *__vmalloc_node(unsigned long size, unsigned long align,
>                             gfp_t gfp_mask, int node, const void *caller)
>  {
>         return __vmalloc_node_range(size, align, VMALLOC_START, VMALLOC_END,
> -                               gfp_mask, PAGE_KERNEL, 0, node, caller);
> +                       gfp_mask, pgprot_hwasan(PAGE_KERNEL), 0, node, caller);
>  }
>  /*
>   * This is only for performance analysis of vmalloc and stress purpose.
> @@ -3161,7 +3161,7 @@ EXPORT_SYMBOL(vmalloc);
>  void *vmalloc_no_huge(unsigned long size)
>  {
>         return __vmalloc_node_range(size, 1, VMALLOC_START, VMALLOC_END,
> -                                   GFP_KERNEL, PAGE_KERNEL, VM_NO_HUGE_VMAP,
> +                                   GFP_KERNEL, pgprot_hwasan(PAGE_KERNEL), VM_NO_HUGE_VMAP,
>                                     NUMA_NO_NODE, __builtin_return_address(0));
>  }
>  EXPORT_SYMBOL(vmalloc_no_huge);
>
> with pgprot_hwasan() defined to pgprot_tagged() only if KASAN_HW_TAGS is
> enabled.

And also change kasan_unpoison_vmalloc() to tag only if
pgprot_tagged() has been applied, I assume.

Hm. Then __vmalloc_node_range() callers will never get tagged memory
unless requested. I suppose that's OK, most of them untag the pointer
anyway.

But this won't work for SW_TAGS mode, which is also affected by the
exec issue and needs those kasan_reset_tag()s in module_alloc()/BPF.
We could invent some virtual protection bit for it and reuse
pgprot_hwasan(). Not sure if this would be acceptable.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZftd93rARJ%2BxpUApimkgTsN0RRmiSVnrUMkCvdSu4-tcA%40mail.gmail.com.
