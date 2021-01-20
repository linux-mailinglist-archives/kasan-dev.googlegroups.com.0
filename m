Return-Path: <kasan-dev+bncBDDL3KWR4EBRBAW5UGAAMGQE5C5HO4Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103a.google.com (mail-pj1-x103a.google.com [IPv6:2607:f8b0:4864:20::103a])
	by mail.lfdr.de (Postfix) with ESMTPS id 67B6A2FD78B
	for <lists+kasan-dev@lfdr.de>; Wed, 20 Jan 2021 18:55:16 +0100 (CET)
Received: by mail-pj1-x103a.google.com with SMTP id o3sf3496645pju.6
        for <lists+kasan-dev@lfdr.de>; Wed, 20 Jan 2021 09:55:16 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1611165315; cv=pass;
        d=google.com; s=arc-20160816;
        b=CaiZi+luwljPnGjQ2Qzfjn0TlcrXWZN+jPMZGeqot+pdvKQBHQWuGeo8aXJ8OItz+X
         s9v0f2fBx+FE09p+Tm8GUaxZ+H4bEAhDGtMLmS3AZI5XpM+4EfEzFrimRstNHM3EXuKV
         TRMQacWuIKOfi+HwJSQkCtxHNuaxrNpo0vSGe4W8phm7GdEb2CCBZdwEbrMufe6/4okT
         UaFb62HPneVdlbPMlr8fxaQH8/L+d3Y3IalIYo5brFTiZbNM5fTXlpCl/3Nmx8hLcEnI
         f0eVLGiNouVEc1lWcYe6XbTHgepb0t9wIkkRXAzcXCebQyoLJj6EShklQQoZEvjMZTJw
         FHDQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=wFJhwdn0tlTyZUx/Eu8p8pnbgjzHzaWaqakDC81dlmw=;
        b=JwmJPS9V1jxikQsSU9GIAd4QOKVXf8xXrnAwok8vwqI544fHdnhRt0h8+ywU6qdRBO
         oBEHxsnpuBHD8HhLKJnlyg6kD9Ft1vKLiJgzfhtPMyMPtebheuVPvk2apYSj6jLkuWxA
         OQt5eenBfFAMAFlTWvX+BaiCFZNSbOPSnWpMQRdTcn8GBqy1M9/McpVjCC8mo1FcRvLM
         Q6OUWCmkcILAt7Cl7tA0ZIetqSaeFt0KecddZPTKI/k25o2TxPHbizAF4ObV7VZYonjl
         bHogfRm73G4YQE+c0ihN+5oT2ra1G6fQAbYBGjQMQ3zbzFWDrIwc6axvrDHCdmoMkK3P
         BzpA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=wFJhwdn0tlTyZUx/Eu8p8pnbgjzHzaWaqakDC81dlmw=;
        b=jXK1n8v1/R371TLIvyOrbpmo367/qwmZ8O81qo8rPoukf/E5CHMhWPBYSl3eSNBIk1
         XmZuRRsnCyTTMfseIhLGwnO3IxIyj+jC7yIsPg5amUcgBi3U2RgjleGJXx3Qtx2Y0Q9l
         LnAFL9Udi5EnatGn0D8xxxOxuBm9CY/VXK3BaxDx8W15rlu3zR6f/9Swrv1ucjBIu1Uh
         mZ/8jKe5lh0prbOCWGA2+UmEbyw3hlTpfoclJ4m4/N97iLDuLmQexGq44Ul04f4Xcuwd
         oksccfUSNSSeRTX+cvlgfnSJmpH9vshKUeldUuiJy1QHlBTdn4REk+yuxsQdBkycrIpn
         5HXQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=wFJhwdn0tlTyZUx/Eu8p8pnbgjzHzaWaqakDC81dlmw=;
        b=aC5hS5+PEtqKSwq+n6g0kCwa3mPegVNKlnCZZPO/ibHKkKWU6QSTCjiVTQRWzu9KRV
         G1D9yU3jh6ZfhdNzmWIO3WBKSvL2IDtgRmtT1ajZSGtwuU4dE+OKBSnBgnuSqIZHWRSS
         mR6EmMdec6pSlwHKC1FsIEDV9wmNTetzcgOSoY36ATiCK/5DPAG/mzh61ThLmAafBz/y
         DHzK/Tf6iYQvkr8mlNB6z9ajNARj+StgR679u6pybMvRVD3auB8Ft9gN7Ix/oHJ4Tllg
         WzkIiu3uGFbRAyT0hREEGgOi+YXHgkx6Hq8f1zjaRInjkQxjyQCOT8DMUU/RJKV015ea
         6gJw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5306JY87K4c0iXdtbvjS+DURQNA+iXFsqxEyIpuqnuTucA+lhR1t
	POFemfI72lF9d2uB2Ejt3NY=
X-Google-Smtp-Source: ABdhPJxKmYuAts7rLxIP5V7MXBawf9zeSt4KBcuw04e6p2WlLEPG8F/1ujtuoRVMN4pEiELsediNvg==
X-Received: by 2002:a63:b550:: with SMTP id u16mr4502610pgo.448.1611165314937;
        Wed, 20 Jan 2021 09:55:14 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:545e:: with SMTP id e30ls5124819pgm.4.gmail; Wed, 20 Jan
 2021 09:55:14 -0800 (PST)
X-Received: by 2002:a62:2f03:0:b029:1af:b254:d1b0 with SMTP id v3-20020a622f030000b02901afb254d1b0mr10434334pfv.5.1611165314321;
        Wed, 20 Jan 2021 09:55:14 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1611165314; cv=none;
        d=google.com; s=arc-20160816;
        b=cepk5lii881dRUf39e5/hNQWbZLx0mR3m3yhKLoxUz9KeyrZHV/+CT6eVL4pWklZrO
         k787f39ZnfpKYx4QYQ9kjZ1305iw+7eRYbnPLHwsmA3dl4R04Ds4+fPAjqgA9G2NbXc2
         vTEiaVRLHkhdgkKhIz8b+pe2bsVrKVs8emHEL4WfcjTtyZkinXSILgdJhm8iOwEQpNij
         uQvVg/+5xAiW9QYn5MbDsHzGlRTytUoIVU/NDxOvHnuAkZkzK6MCjrcZU7jh2o8xlsnq
         8bI4M8WNh+ZYRR7aeurSYv7PflfrRcyan0r9lkh9K0xm6WgbChX0Nh9+vyGwb+ZyTP6k
         UGew==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=dUcvOWXgAsQ71IWR+KWyoL/N8cnFP0if6bgYU1/RQLg=;
        b=Sv8WpMOWzmSANZu9cIIDHtsIK5oHuh3tyyI6J6P4+5niNaJcrnNpnl/bmg26LTwAyC
         EmqlT/uaar5xfhLnf8Z6hZ8y2VVFDPQwqbWg0ddlVRUvhA9gGClMp8YzgpgEoPPAKZup
         D7yYKq6d2B4fQbFO97Kdz2uNOKTttrQPoVYpjnLT/trQESH+PYp31xbv9qySXnUPYJxA
         Vj/V1laNnRDH4IDVGVqPqMuW1BDcIrrNhzpEiUGbsDDwqvmJ1FQLPQ0oo2p4ya2tU+WZ
         YhUgaKLCOv2M1qSUuz55GscOSzYFZJumtCp200Pe7mHdl2QMUQ9VxXo0AdZtI2GMCyHa
         uVCQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id c2si218740pls.4.2021.01.20.09.55.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 20 Jan 2021 09:55:14 -0800 (PST)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 6859B223DB;
	Wed, 20 Jan 2021 17:55:12 +0000 (UTC)
Date: Wed, 20 Jan 2021 17:55:09 +0000
From: Catalin Marinas <catalin.marinas@arm.com>
To: Vincenzo Frascino <vincenzo.frascino@arm.com>
Cc: Andrey Konovalov <andreyknvl@google.com>,
	LKML <linux-kernel@vger.kernel.org>,
	kasan-dev <kasan-dev@googlegroups.com>,
	Leon Romanovsky <leonro@mellanox.com>,
	Alexander Potapenko <glider@google.com>,
	Linux ARM <linux-arm-kernel@lists.infradead.org>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Dmitry Vyukov <dvyukov@google.com>
Subject: Re: [PATCH] kasan: Add explicit preconditions to kasan_report()
Message-ID: <20210120175509.GA17952@gaia>
References: <20210119172607.18400-1-vincenzo.frascino@arm.com>
 <CAAeHK+zpB6GZcAbWnmvKu5mk_HuNEaXV2OwRuSNnVjddjBqZMQ@mail.gmail.com>
 <20210119185206.GA26948@gaia>
 <418db49b-1412-85ca-909e-9cdcd9fdb089@arm.com>
 <20210120160416.GF2642@gaia>
 <6525b31a-9258-a5d1-9188-5bce68af573c@arm.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <6525b31a-9258-a5d1-9188-5bce68af573c@arm.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: catalin.marinas@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as
 permitted sender) smtp.mailfrom=cmarinas@kernel.org;       dmarc=fail (p=NONE
 sp=NONE dis=NONE) header.from=arm.com
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

On Wed, Jan 20, 2021 at 04:16:02PM +0000, Vincenzo Frascino wrote:
> On 1/20/21 4:04 PM, Catalin Marinas wrote:
> > On Tue, Jan 19, 2021 at 08:35:49PM +0000, Vincenzo Frascino wrote:
> >> On 1/19/21 6:52 PM, Catalin Marinas wrote:
> >>> On Tue, Jan 19, 2021 at 07:27:43PM +0100, Andrey Konovalov wrote:
> >>>> On Tue, Jan 19, 2021 at 6:26 PM Vincenzo Frascino
> >>>> <vincenzo.frascino@arm.com> wrote:
> >>>>>
> >>>>> With the introduction of KASAN_HW_TAGS, kasan_report() dereferences
> >>>>> the address passed as a parameter.
> >>>>>
> >>>>> Add a comment to make sure that the preconditions to the function are
> >>>>> explicitly clarified.
> >>>>>
> >>>>> Note: An invalid address (e.g. NULL pointer address) passed to the
> >>>>> function when, KASAN_HW_TAGS is enabled, leads to a kernel panic.
> >>>>>
> >>>>> Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
> >>>>> Cc: Alexander Potapenko <glider@google.com>
> >>>>> Cc: Dmitry Vyukov <dvyukov@google.com>
> >>>>> Cc: Leon Romanovsky <leonro@mellanox.com>
> >>>>> Cc: Andrey Konovalov <andreyknvl@google.com>
> >>>>> Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
> >>>>> ---
> >>>>>  mm/kasan/report.c | 11 +++++++++++
> >>>>>  1 file changed, 11 insertions(+)
> >>>>>
> >>>>> diff --git a/mm/kasan/report.c b/mm/kasan/report.c
> >>>>> index c0fb21797550..2485b585004d 100644
> >>>>> --- a/mm/kasan/report.c
> >>>>> +++ b/mm/kasan/report.c
> >>>>> @@ -403,6 +403,17 @@ static void __kasan_report(unsigned long addr, size_t size, bool is_write,
> >>>>>         end_report(&flags);
> >>>>>  }
> >>>>>
> >>>>> +/**
> >>>>> + * kasan_report - report kasan fault details
> >>>>> + * @addr: valid address of the allocation where the tag fault was detected
> >>>>> + * @size: size of the allocation where the tag fault was detected
> >>>>> + * @is_write: the instruction that caused the fault was a read or write?
> >>>>> + * @ip: pointer to the instruction that cause the fault
> >>>>> + *
> >>>>> + * Note: When CONFIG_KASAN_HW_TAGS is enabled kasan_report() dereferences
> >>>>> + * the address to access the tags, hence it must be valid at this point in
> >>>>> + * order to not cause a kernel panic.
> >>>>> + */
> >>>>
> >>>> It doesn't dereference the address, it just checks the tags, right?
> >>>>
> >>>> Ideally, kasan_report() should survive that with HW_TAGS like with the
> >>>> other modes. The reason it doesn't is probably because of a blank
> >>>> addr_has_metadata() definition for HW_TAGS in mm/kasan/kasan.h. I
> >>>> guess we should somehow check that the memory comes from page_alloc or
> >>>> kmalloc. Or otherwise make sure that it has tags. Maybe there's an arm
> >>>> instruction to check whether the memory has tags?
> >>>
> >>> There isn't an architected way to probe whether a memory location has a
> >>> VA->PA mapping. The tags are addressed by PA but you can't reach them if
> >>> you get a page fault on the VA. So we either document the kasan_report()
> >>> preconditions or, as you suggest, update addr_has_metadata() for the
> >>> HW_TAGS case. Something like:
> >>>
> >>>         return is_vmalloc_addr(virt) || virt_addr_valid(virt));
> >>>
> >>
> >> This seems not working on arm64 because according to virt_addr_valid 0 is a
> >> valid virtual address, in fact:
> >>
> >> __is_lm_address(0) == true && pfn_valid(virt_to_pfn(0)) == true.
> > 
> > Ah, so __is_lm_address(0) is true. Maybe we should improve this since
> > virt_to_pfn(0) doesn't make much sense.
> 
> How do you propose to improve it?

Check that it's actually a kernel address starting at PAGE_OFFSET. The
current __is_lm_address() check just masks out the top 12 bits but if
they were 0, this still yields a true result. Maybe extending the
current definition as:

#define __is_lm_address(addr)	((u64)(addr) >= PAGE_OFFSET && \
				 ((u64)(addr) & ~PAGE_OFFSET) < (PAGE_END - PAGE_OFFSET))

Which basically means:

#define __is_lm_address(addr)	((u64)(addr) >= PAGE_OFFSET && \
				 (u64)(addr) < PAGE_END)

I think we could write the above as:

#define __is_lm_address(addr)	(((u64)(addr) ^ PAGE_OFFSET) < (PAGE_END - PAGE_OFFSET))

This way we catch any 0 bits in the top 12 (or 16 with a 48-bit VA
configuration).

-- 
Catalin

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210120175509.GA17952%40gaia.
