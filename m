Return-Path: <kasan-dev+bncBDDL3KWR4EBRBQGZTSAAMGQE62XYC2Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x540.google.com (mail-pg1-x540.google.com [IPv6:2607:f8b0:4864:20::540])
	by mail.lfdr.de (Postfix) with ESMTPS id 4FEA72FBFA3
	for <lists+kasan-dev@lfdr.de>; Tue, 19 Jan 2021 20:02:26 +0100 (CET)
Received: by mail-pg1-x540.google.com with SMTP id 24sf16338411pgt.4
        for <lists+kasan-dev@lfdr.de>; Tue, 19 Jan 2021 11:02:26 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1611082945; cv=pass;
        d=google.com; s=arc-20160816;
        b=wAhsnqQAGb7nZaj5UDL0CMfXPjpdH1LgUcZ7SErbxHL44zIg5JhFnbzuSPwQ0nyxFJ
         BiX1nC/LTlfwoSk5Cs7j8I3iWQuwbgt/7RvvUbaR5gIOvMAdgAOas3/ZSU/4Dw4gpjcZ
         1RQKQmXZo7m3HmQtGjdZZCV90QM0KHNh/syl4G/Bu8iwW4lIYtxHtAfg3GYxKDo4Hkem
         8f5YNVhplfrxZ4iDkVFxAItwxtGr0BByNgt+FX+0r41GRsC3Efw2aL/lre3aAypoh2CK
         fX89uEKo3Deoq/kJ/5NSGip4peIsRB0+SRDd3PVvBs9kJ6ClOpTc5tEs4QEi7u7ZQnir
         DjOQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=uJs8tsHmHtvhq1Y85OYiYhAKceqLFx1QW+rBkeZ9lOg=;
        b=bxNg4VVpVJwkVOFzltFkCEwlfljvme4fpnFoDkelCyuUgLiEVh30FoNYmx48PwAaEG
         kpyuZxviYMMfr9s2rW6OJFMy+EkLNyOGW69J5H6VK/Jo1qFqeZ+CG4PeYhZNVH75ypoR
         DXGUWheqGeRaxnQwtsgt3XZ4QsDtCWXXJvk+PqBu0vCiKgTwessMkZmPtSks1WyQ0aH9
         ynfGwPVaOrGR+FD2J4OedEvC3Gw9Iio8JgcA8LvRwBDbRHT8CUC5rb+HC2HikkqAo9//
         7G/b5kuS89mnbldDd12QUoRAaru16CmahYjDrqqKT3ImRAAwotfQyUZazn+fLpbNQfuh
         EeTg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=uJs8tsHmHtvhq1Y85OYiYhAKceqLFx1QW+rBkeZ9lOg=;
        b=Ia89yAEocEaxtJg8B0LxLDA8Fagz7nWYHv9TcjGXbmc+WRbqKQ19NPrfaDX2gnC+M2
         2yupfD/Ndd6/aUz416xe88iLfj/FA4fSgdT8ljrPFi7d5MrgVF59SgAjWweF2U3/zYJc
         VE2fVfLf2oV1Xt8dKZBjePVEtThWRkeADGncUwLy+4B0KyHT6KWr1bHLahAM6Z+jBRfi
         HDzwok2Hf7RYsdb0K84Zb2ZKHyA195l6tWAd85NlBZCH9b4NjJUkoyh32Ad6uldtPYV4
         I7JCZ9IwqIKQBFC85poZ96QzyfTQ9G4BrX9+vvEKyPMFLgSIMC1B0BXhe1RD2Nc5pR18
         wv/A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=uJs8tsHmHtvhq1Y85OYiYhAKceqLFx1QW+rBkeZ9lOg=;
        b=rOgtVmdaaDe3zz0mSmBeU7PzZaLS2pDGTxzSjJ0X+tF+Xsprtr3z2nkqMoXaYM9H6f
         26p7P6EIS2/XGJAEy3qsY0johAPKpmutBIQpz2xxrtDtEi3Qd7QBciuSfGuRJfDFlHNM
         GQpf+acMeJx10URBheqrCREtdhqzZ1k/yipWK/pbivZWxqsfZPlRF8uWyRXiwXm7DTsU
         Q2Y/l8UEdHjfFqwPqc8Pm1eh4USFx/SFb0Wumqwtp+Xkb3l84DZm9K+w966w5QYkF6V4
         HiA9ch9zvMHffagSn3wz+d81ElTleFbOgZbEz2b0YUX4QlN5yDgBCQEdnW+jbUn0+N3H
         FWDg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532W1xInur91wczAxgwBp1NCWd6aoetngoVKcJUd3pqt89QXAEH/
	4su5yyO8jzn5xOcRLwRyCIg=
X-Google-Smtp-Source: ABdhPJyVSaYRxzPau5fUnd3pjLbeEBIcss2Ciw2xtdmEfG4IsQSWbo+CqzPt0arofZzLY+HG7TAaEQ==
X-Received: by 2002:a63:1446:: with SMTP id 6mr5610798pgu.313.1611082944965;
        Tue, 19 Jan 2021 11:02:24 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:5c85:: with SMTP id q127ls8242281pfb.11.gmail; Tue, 19
 Jan 2021 11:02:24 -0800 (PST)
X-Received: by 2002:a63:561f:: with SMTP id k31mr5616146pgb.275.1611082944367;
        Tue, 19 Jan 2021 11:02:24 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1611082944; cv=none;
        d=google.com; s=arc-20160816;
        b=NcsLFEXohipJ2ZxYsA2Yeph9tfnwfBb5HUSMt19R23JbFuDrLwZO9j25EumUYf5MAP
         KBeZZxqwyBJCzfXuEuIjTnwXK3mEqczNOze69ZleombS80jwijI+NetTzDNoR+iXhWVs
         tHJtOMcN5p3x6nxA7MKh/t7I0aQGSm0IViN8Ss6nu+k68PjoV9o+5svJjv0e95sK6kM3
         ok1XTom+2tM4KZi6t0DtdksbM1CjbcZJl+5vY7d5y3ma2YiA/b9bfYVh9+gyRkB0fw97
         Bxpdenj2B+NgG7yg5DwHT2G/U4uQrXvd6gChL3j3rdMfaxXXMWS8pX2ob7CTDGxmCs+K
         Qcfg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=5YAAwvX/TkEeexiSbXU6olWJGsvBDoeEyQm67mOrreQ=;
        b=kaWOgiE+a/ubyn2Lvebch/Al7l/c+VJHvxS5Vh5qvQ7ca0JSqVR9zGKeI4ww864iCm
         kH/GRpYjBQsHvdZSdXGMDTjE0tgGjQzozfX44x3p3kh3XG9s6gXZilrnUpDtDlyWK8+L
         GW251PLNOFEzVtDkJ5jxQ9s4Dzdh88akxQKTIhDHdSJLnnWA/2dLUfRYPRdNPgHrEB0N
         EM8CoXCp88MDw4UCtnFE/PsqO8ahSNQa5Zi0HnLTy/SrYvGvw8Oaea03ysbbpFCj/uFq
         x7ti54pve55vbIEzu33aDDIaufliXDIcxXLPUtA9X78b7xW05PWULq71Onz0Xgu9hw2j
         YYOA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id c3si1299877pll.0.2021.01.19.11.02.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 19 Jan 2021 11:02:24 -0800 (PST)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 547DD20706;
	Tue, 19 Jan 2021 19:02:22 +0000 (UTC)
Date: Tue, 19 Jan 2021 19:02:19 +0000
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
Message-ID: <20210119190219.GC26948@gaia>
References: <20210119172607.18400-1-vincenzo.frascino@arm.com>
 <CAAeHK+zpB6GZcAbWnmvKu5mk_HuNEaXV2OwRuSNnVjddjBqZMQ@mail.gmail.com>
 <20210119185206.GA26948@gaia>
 <e3d67672-1825-894a-db68-5709b33b4991@arm.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <e3d67672-1825-894a-db68-5709b33b4991@arm.com>
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

On Tue, Jan 19, 2021 at 07:00:57PM +0000, Vincenzo Frascino wrote:
> On 1/19/21 6:52 PM, Catalin Marinas wrote:
> > On Tue, Jan 19, 2021 at 07:27:43PM +0100, Andrey Konovalov wrote:
> >> On Tue, Jan 19, 2021 at 6:26 PM Vincenzo Frascino
> >> <vincenzo.frascino@arm.com> wrote:
> >>>
> >>> With the introduction of KASAN_HW_TAGS, kasan_report() dereferences
> >>> the address passed as a parameter.
> >>>
> >>> Add a comment to make sure that the preconditions to the function are
> >>> explicitly clarified.
> >>>
> >>> Note: An invalid address (e.g. NULL pointer address) passed to the
> >>> function when, KASAN_HW_TAGS is enabled, leads to a kernel panic.
> >>>
> >>> Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
> >>> Cc: Alexander Potapenko <glider@google.com>
> >>> Cc: Dmitry Vyukov <dvyukov@google.com>
> >>> Cc: Leon Romanovsky <leonro@mellanox.com>
> >>> Cc: Andrey Konovalov <andreyknvl@google.com>
> >>> Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
> >>> ---
> >>>  mm/kasan/report.c | 11 +++++++++++
> >>>  1 file changed, 11 insertions(+)
> >>>
> >>> diff --git a/mm/kasan/report.c b/mm/kasan/report.c
> >>> index c0fb21797550..2485b585004d 100644
> >>> --- a/mm/kasan/report.c
> >>> +++ b/mm/kasan/report.c
> >>> @@ -403,6 +403,17 @@ static void __kasan_report(unsigned long addr, size_t size, bool is_write,
> >>>         end_report(&flags);
> >>>  }
> >>>
> >>> +/**
> >>> + * kasan_report - report kasan fault details
> >>> + * @addr: valid address of the allocation where the tag fault was detected
> >>> + * @size: size of the allocation where the tag fault was detected
> >>> + * @is_write: the instruction that caused the fault was a read or write?
> >>> + * @ip: pointer to the instruction that cause the fault
> >>> + *
> >>> + * Note: When CONFIG_KASAN_HW_TAGS is enabled kasan_report() dereferences
> >>> + * the address to access the tags, hence it must be valid at this point in
> >>> + * order to not cause a kernel panic.
> >>> + */
> >>
> >> It doesn't dereference the address, it just checks the tags, right?
> >>
> >> Ideally, kasan_report() should survive that with HW_TAGS like with the
> >> other modes. The reason it doesn't is probably because of a blank
> >> addr_has_metadata() definition for HW_TAGS in mm/kasan/kasan.h. I
> >> guess we should somehow check that the memory comes from page_alloc or
> >> kmalloc. Or otherwise make sure that it has tags. Maybe there's an arm
> >> instruction to check whether the memory has tags?
> > 
> > There isn't an architected way to probe whether a memory location has a
> > VA->PA mapping. The tags are addressed by PA but you can't reach them if
> > you get a page fault on the VA. So we either document the kasan_report()
> > preconditions or, as you suggest, update addr_has_metadata() for the
> > HW_TAGS case. Something like:
> > 
> >         return is_vmalloc_addr(virt) || virt_addr_valid(virt));
> 
> Or we could have both ;)

True. Documentation doesn't hurt (well, only when it's wrong ;)).

-- 
Catalin

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210119190219.GC26948%40gaia.
