Return-Path: <kasan-dev+bncBDDL3KWR4EBRBXGUTSAAMGQEJXZGVVY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb40.google.com (mail-yb1-xb40.google.com [IPv6:2607:f8b0:4864:20::b40])
	by mail.lfdr.de (Postfix) with ESMTPS id 728B82FBF63
	for <lists+kasan-dev@lfdr.de>; Tue, 19 Jan 2021 19:52:13 +0100 (CET)
Received: by mail-yb1-xb40.google.com with SMTP id l3sf16218118ybl.17
        for <lists+kasan-dev@lfdr.de>; Tue, 19 Jan 2021 10:52:13 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1611082332; cv=pass;
        d=google.com; s=arc-20160816;
        b=csplf869eeRb8ze1d827KU/QN8QLkWhotaXFi98otKxUkVEBaOSgdjjQqn1nNHj7Ao
         L0aCCFfh6t22SYH+tOm37NR6o+ifsX2lgkpCMSXbPgsNap+66oviFBtzAcu20bQE/uNc
         6ajKM6B7X7fjY9bBannUUGuhQ4LD+M+5Ko2GFG37PumHGlMfvKfYgQ/9sn9GIPOiP1di
         4ahXO/Di1FmcYXbBJljB/BK4aABaca2G2PVCbnHaPP3zJgMVO44mu1IDMai2tiwLft8G
         vCmn/EzYu4ejv5tX4V63uqWXSibOI283DC/m1igGspfpbg43oB9Bks8rF4cJ4/jTy4EZ
         Wx3w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=nTZeXCTJQDneAYlzRbhf8NqgvObE/whOi/dJJoaaooU=;
        b=f2kDP4LM9818EG1/J8XYfTsaD3qhnCKS5QlouluLMvR+WhYegVDwJ1lNzf4O2GkM8S
         MZdwzstL8MQFs1IOWNSo4NC7TGilBQ10xf+ngfDGtcqf5OSAGoIhcwiNY1r9lH0DDDo/
         Mbn3FBC7JsK7JV9lnR3vNWUOQrye2RST93XZynR68JhKV3DeaPPsfCu2ezxI1nr0TCN5
         L4Uiz7aUn9RdniC0zSH3pLIeNW2+DJJGOB3vaveDzkXOo4zil/UOPk0kuZGGRpdLWDdN
         xvIFdnrzPppgx246gnocM9gd0RvwcOwHBEK8AydxxdDX9NBWPdVevfQ0L+lZcr6F9tJk
         yirQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=nTZeXCTJQDneAYlzRbhf8NqgvObE/whOi/dJJoaaooU=;
        b=exAssZ8zyfCC14t7z6a7wbyZQeKoevT8auJuPBvcRqmRqHaZ8TliqUYqi+LXEeWDAv
         7Mk3OYlrN7mTKQEmzQdsXBxxloPovWSeQfG7KPAO4BSTU1hss2A89b26tQDptagsdIwH
         Do09RTzY7Ng3WFkYglHEL3ULJROFQK4LBAox/KtvM2eQUezPBAhKKgIH01ZUR+PBvRXe
         s1Nnj+iXFkoAxE3IXu3QjHhDsQ0mRzpeZwlycsAy2SxYqHr1IV7hziYX+9LB3e9wDQ19
         sgIOpydLXOJUbIMiaWe0Jn01YqOHjFODXwV9xzLo4HuB2Z3Adp+mXT/VhARj5/qpGNE4
         zQKw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=nTZeXCTJQDneAYlzRbhf8NqgvObE/whOi/dJJoaaooU=;
        b=ipiarTd+uQntMhI47nS2TGxLF/UILeTxM7oF6vPZkyPn63HHh2hThBLiIU47CVQlno
         9a7t+Qylpc0YBuXTPEJTpmSXPPDvtr53iPArJoIqUIq52CIsx9DmJ4wj3WTggbW7/6IC
         1UqNWTIjKAW1QKl9XMT6C4noDXaLy58N4kWoNKXupoq7zXlSKQPQN2ZcLSMb8uPigLSd
         aIK58AIKXV2YpbHZ0AK1SnEERiqrDE8NXbWWP3Pr8Qh9td02sg919VzfbgLRihIzZVAX
         Lqza1WZaPcc+bb/8QsqK4o/Mz+LTlpUqpBgSj6MX6HwEJfwg7ra7Qro7Gi8a7Zp64aSt
         s+8Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530JWAVb1IDQo70NVulw99C0M+w9QKeBDTCW71mmVZupuiNG5kth
	seti52ZMCUgE0H1LBBEB9gc=
X-Google-Smtp-Source: ABdhPJwocpoih5kP6lEZacj/jxCLgstgLm3sjWM3OyPynylKfcUcE4KyfvsOBo4oQjyJHndzNnXBjg==
X-Received: by 2002:a25:488a:: with SMTP id v132mr8141571yba.28.1611082332478;
        Tue, 19 Jan 2021 10:52:12 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:c594:: with SMTP id v142ls10900859ybe.9.gmail; Tue, 19
 Jan 2021 10:52:12 -0800 (PST)
X-Received: by 2002:a25:9981:: with SMTP id p1mr7528529ybo.440.1611082332044;
        Tue, 19 Jan 2021 10:52:12 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1611082332; cv=none;
        d=google.com; s=arc-20160816;
        b=nagEYTuF37FixxwMWu0rzcgP2cZkDXHpuyo0Lb1TMKOE5tnsLFmrNY1g8R72rivylK
         S7vFZQs/IitnuQX8Kbq2Oyqut1M8eWH6XceWRFotOOXFETUTFCD1ZOo0gvRwFwLUSSmY
         6ijBmQbH3/op9OsWReTyaQ2SBxxaZOE+3SdJv2a8uW2dGJRqwKMWiy8pjGV0oN90hit0
         QkX2+ow4NCiQLfnC7ZJ5PCGYlZ1fsseC34QvQsCPtLzlTUTWYc47wKcFmxUdes3uO8RZ
         kVv/5OHXj1BP/I/gd2RpTVG4V52B3VWPOUrsP6NYNC+1Zi4wPRjFpphYm5EyNu7gsMMp
         emnQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=l3fxeG+ky0a7uwqJJFr/W/zvTVyD5M36N1vjkLpjA4E=;
        b=f0YxmZBpPf+kkX8FmON+gQld3H0d47s9Vq68M8KYuXpHfHPVjZC4ElcAYHQXXh+5U9
         TquEvXiu3WFJqlRwSP6FZzb7teYj/JTaaUd1ytiltyEhr+XbwgQ223rjrVIFjvsqm7Vs
         zAp+TIjTvGIIA1VlsDS2IAUopv9sjN61UvkBFp9jfzDOiUdqoJRuL8ADXaHkKj9iUbzr
         XAGBqKE9eckioEZChwB1WnOW6d2B7AyiCAXmnP1+uOcBhmZy4mXbBy0i+3GWxum8bBWh
         HuVILwL9oSmVNymlqEoZSRRBcHWm+Df/Y1NIrf9EbCw25kh5rW/9U3COL1cZ4MxBYg48
         qMRg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id k19si1925916ybj.5.2021.01.19.10.52.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 19 Jan 2021 10:52:12 -0800 (PST)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 8A55820776;
	Tue, 19 Jan 2021 18:52:09 +0000 (UTC)
Date: Tue, 19 Jan 2021 18:52:07 +0000
From: Catalin Marinas <catalin.marinas@arm.com>
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>,
	LKML <linux-kernel@vger.kernel.org>,
	kasan-dev <kasan-dev@googlegroups.com>,
	Leon Romanovsky <leonro@mellanox.com>,
	Alexander Potapenko <glider@google.com>,
	Linux ARM <linux-arm-kernel@lists.infradead.org>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Dmitry Vyukov <dvyukov@google.com>
Subject: Re: [PATCH] kasan: Add explicit preconditions to kasan_report()
Message-ID: <20210119185206.GA26948@gaia>
References: <20210119172607.18400-1-vincenzo.frascino@arm.com>
 <CAAeHK+zpB6GZcAbWnmvKu5mk_HuNEaXV2OwRuSNnVjddjBqZMQ@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CAAeHK+zpB6GZcAbWnmvKu5mk_HuNEaXV2OwRuSNnVjddjBqZMQ@mail.gmail.com>
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

On Tue, Jan 19, 2021 at 07:27:43PM +0100, Andrey Konovalov wrote:
> On Tue, Jan 19, 2021 at 6:26 PM Vincenzo Frascino
> <vincenzo.frascino@arm.com> wrote:
> >
> > With the introduction of KASAN_HW_TAGS, kasan_report() dereferences
> > the address passed as a parameter.
> >
> > Add a comment to make sure that the preconditions to the function are
> > explicitly clarified.
> >
> > Note: An invalid address (e.g. NULL pointer address) passed to the
> > function when, KASAN_HW_TAGS is enabled, leads to a kernel panic.
> >
> > Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
> > Cc: Alexander Potapenko <glider@google.com>
> > Cc: Dmitry Vyukov <dvyukov@google.com>
> > Cc: Leon Romanovsky <leonro@mellanox.com>
> > Cc: Andrey Konovalov <andreyknvl@google.com>
> > Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
> > ---
> >  mm/kasan/report.c | 11 +++++++++++
> >  1 file changed, 11 insertions(+)
> >
> > diff --git a/mm/kasan/report.c b/mm/kasan/report.c
> > index c0fb21797550..2485b585004d 100644
> > --- a/mm/kasan/report.c
> > +++ b/mm/kasan/report.c
> > @@ -403,6 +403,17 @@ static void __kasan_report(unsigned long addr, size_t size, bool is_write,
> >         end_report(&flags);
> >  }
> >
> > +/**
> > + * kasan_report - report kasan fault details
> > + * @addr: valid address of the allocation where the tag fault was detected
> > + * @size: size of the allocation where the tag fault was detected
> > + * @is_write: the instruction that caused the fault was a read or write?
> > + * @ip: pointer to the instruction that cause the fault
> > + *
> > + * Note: When CONFIG_KASAN_HW_TAGS is enabled kasan_report() dereferences
> > + * the address to access the tags, hence it must be valid at this point in
> > + * order to not cause a kernel panic.
> > + */
> 
> It doesn't dereference the address, it just checks the tags, right?
> 
> Ideally, kasan_report() should survive that with HW_TAGS like with the
> other modes. The reason it doesn't is probably because of a blank
> addr_has_metadata() definition for HW_TAGS in mm/kasan/kasan.h. I
> guess we should somehow check that the memory comes from page_alloc or
> kmalloc. Or otherwise make sure that it has tags. Maybe there's an arm
> instruction to check whether the memory has tags?

There isn't an architected way to probe whether a memory location has a
VA->PA mapping. The tags are addressed by PA but you can't reach them if
you get a page fault on the VA. So we either document the kasan_report()
preconditions or, as you suggest, update addr_has_metadata() for the
HW_TAGS case. Something like:

        return is_vmalloc_addr(virt) || virt_addr_valid(virt));

-- 
Catalin

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210119185206.GA26948%40gaia.
