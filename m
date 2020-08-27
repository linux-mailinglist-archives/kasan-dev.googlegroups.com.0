Return-Path: <kasan-dev+bncBDDL3KWR4EBRB4MCT75AKGQEDQV37XI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43f.google.com (mail-pf1-x43f.google.com [IPv6:2607:f8b0:4864:20::43f])
	by mail.lfdr.de (Postfix) with ESMTPS id 2572E2546AF
	for <lists+kasan-dev@lfdr.de>; Thu, 27 Aug 2020 16:21:40 +0200 (CEST)
Received: by mail-pf1-x43f.google.com with SMTP id y17sf6556pfp.10
        for <lists+kasan-dev@lfdr.de>; Thu, 27 Aug 2020 07:21:40 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1598538097; cv=pass;
        d=google.com; s=arc-20160816;
        b=ERhInwftgOtNS2/TGxkS6CLVx5rb/yoHZGyy/+3fgpnzKwS7jSIyqQ/nvgldDJ1qaU
         F+4nIDJG84XuCy9VpBUmuiGhcu76eJXVmQFHoJhoFkqPE8PFZ5LKa0iTCWLKCbKoMExg
         okdA8NpPH7BBRLGsnmahxFgXphTqNBckYvxgF5L5AFImCS0GpXl1NVwwfynPevTtgTQw
         GdrdDWzvqIqzzX7AJca10+NYWxGddBNffXoqnGg910DEADgKa+cXzlJ9eMpdrZG+cC09
         a4uWnWAkFMAw93ekduAEEB+mKCOR9+22rqFhYbg8LFx59WWQ+ay6xx4MMfG6MAtILS9Q
         AR+A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=Fc8dnJXhHC7cSEbSEy2PTGk9jZz3m+7alLXFzMluJ5g=;
        b=lUTg5PoCQ7H8Aa7jZJMUNLHixkr/3P2UtwhtldVNi81r6iVKCPHArD/SKC90SqwjzG
         Q+Glx2fwPWRI/cdO5hhpPUgomfgUlwn8IwRtpkg5y4NcVcKv2eSWFtXeQvtTYbqqooha
         W0TPeVctsC2v0vlhcCXInkll1okI6B+1y7LKF/GEgOsVca6LD2HP0HKAzOOrrYlGOTi/
         IWxPmn2vYVrSQKWvaCrdOYkcwisdvSA7ZzCTCULHFhSPjMJQEBpD2M8seQHss79ZrXuE
         44Kz9QbsRtc+G/cg5rlh0Y3z7/HZuFnnCDTMWtoate2sVsQl2WIvovaB622Ddo6Aon2D
         yvaw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Fc8dnJXhHC7cSEbSEy2PTGk9jZz3m+7alLXFzMluJ5g=;
        b=JQcis84qWr+trxSjFn3/q2l1I4y1j2cRVp5eC5lGfkiK09Jf5CS9tKAofFTFavIW8N
         Vwou/I8/6XNfCtgqeXiLu2MeUH0nE5cEEYvz6CS7dZ5xHR67QcbcNtOlsCtvkDgNhaKx
         Dku06gkgCHCknDyiT/rS/FYcE4yDFGqTyn+IO63R/XbJ5rO0l4FWa0QJE/weSFxxUTDj
         JqnVujFMIR9Es+Wjioo+X8QmsEbAKD4in0XX5jH4Ryf3F8QdwFiJ2ovCWxqfVXgH40mP
         PIDX19VPnS/L9szHjzxi5KHWxcUenoSrKqq6VeS4cDt0qa+zAAPxzFHfT7MYUVSYd6Ae
         4SpQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=Fc8dnJXhHC7cSEbSEy2PTGk9jZz3m+7alLXFzMluJ5g=;
        b=S826brsCcnf7X+lnmN/SnGWX1f+58M0Fqt59rBqnfVCRYV731fbWlZ5j4xOmoyV52x
         mX78EBvlpBNWUMXKqgopYylLz5lHDD4XbrUN/yi1FCUj8jqk9kVkCnxGpdd6v4dO6CGT
         8VOzHWBxuGzfc3yG6v2DrrFxkPp6Rm/F+UpeJXJXyDip2htV3P/8EgXyYFJdTLSUvNHc
         VSlJXIEWPzLbbxo/VQ8rGe5Ox1GqRZ8HrMTpeuznPVOfnctzqsfFuvdFEidFAjGjianj
         xIcJfOmhok9uz5kt7vf5M/OO5LzJLRkQK8FqE2Zonq3xEoXMlms+Btd+ZcSOE5VYlcBT
         MIQQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533AF5z6De2Qf/5i9hBhLzutyVSM6Awom9/5JbWHYzmaAvrOOL5E
	BVWYGG90nDDRp/6FRyITMZk=
X-Google-Smtp-Source: ABdhPJw5XABJuofU9vn0OGTbh0nZeAInQkylTWsqOlFD9qPhczcg7EiXRVCmAIS66PbC27OiSqgQPg==
X-Received: by 2002:a17:90b:1194:: with SMTP id gk20mr7663438pjb.54.1598538097707;
        Thu, 27 Aug 2020 07:21:37 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:bb8f:: with SMTP id m15ls1309939pls.5.gmail; Thu, 27
 Aug 2020 07:21:37 -0700 (PDT)
X-Received: by 2002:a17:90a:aa8e:: with SMTP id l14mr11704680pjq.67.1598538097130;
        Thu, 27 Aug 2020 07:21:37 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1598538097; cv=none;
        d=google.com; s=arc-20160816;
        b=R4J5ieWs3/ZB48l8gddZJ0pxqDNtp6bK1WmTdBvnhc14nqmHtqNJUAuJCIvybLeWJm
         aFiJZeZejsNhLjJl89xT9gw/WdJ0JQQWQEvru8olbALtJ7W+cQ3dFUDQ+KDJ9pOTFj0m
         VeBZTDXAEp3LsDcKYMYbyqAEVBqOBR7hoZi7139UDaR8Wj9DqifZjywF2K70U2lz3VNR
         lNKYvvk5ATsqGFflqKRGarxod67VEPt8ZIyUCToXUbFUk0Jd+rxEDCTze9fqNiSl9f7X
         xNnYgFNm0MtVhzAKGAPP5poR00rQwHRRc+o1eD4AC2Eui6ySS+3wHRvLUbBbfbaJnvT6
         SAfg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=LXQ5Q2wYP+L6HOF76OsY7XD/iVZFPOswUGdZKTUtSpo=;
        b=fymbZmYJrWT/6NaMZ8mv5XEilaIhO55Vz8QBlz+aUp0KUizNCev5nkO7PskUw91UTq
         xrvKHtnE9qTJGsl3VkoTsZEcFpW82bCsbQeb60HclIrbZNHTfzLD3JL5CLcdUdLdScby
         0nbvlUUWI8xRzwM8vtlu90dySa8pISEUlsHus7NkmzJYwNYKNYFiNdFnLn6IFWqxyR0T
         4uI/+SM39eD6WeBObRyOy1tbunneeK379kwodqeRO0x61LakZa3ODsnh/IMTAOiiXw4q
         I68JKR5nC2+CGfZUlg9LNh2/Af6g5ufubIQkYZCnz+g9oZQ/fZY3/7zOxg11Ahr4dL5Y
         xOPA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id l2si171517pfd.0.2020.08.27.07.21.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 27 Aug 2020 07:21:37 -0700 (PDT)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from gaia (unknown [46.69.195.127])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 24FEC2177B;
	Thu, 27 Aug 2020 14:21:33 +0000 (UTC)
Date: Thu, 27 Aug 2020 15:21:31 +0100
From: Catalin Marinas <catalin.marinas@arm.com>
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	kasan-dev <kasan-dev@googlegroups.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Elena Petrova <lenaptr@google.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Kevin Brodsky <kevin.brodsky@arm.com>,
	Will Deacon <will.deacon@arm.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Linux ARM <linux-arm-kernel@lists.infradead.org>,
	Linux Memory Management List <linux-mm@kvack.org>,
	LKML <linux-kernel@vger.kernel.org>
Subject: Re: [PATCH 32/35] kasan, arm64: print report from tag fault handler
Message-ID: <20200827142131.GN29264@gaia>
References: <cover.1597425745.git.andreyknvl@google.com>
 <4691d6019ef00c11007787f5190841b47ba576c4.1597425745.git.andreyknvl@google.com>
 <20200827104816.GI29264@gaia>
 <CAAeHK+zO8EJrmX5NjkKTB35eot1rDLjoqGyfoqF_quDV=VEvrQ@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CAAeHK+zO8EJrmX5NjkKTB35eot1rDLjoqGyfoqF_quDV=VEvrQ@mail.gmail.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: catalin.marinas@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as
 permitted sender) smtp.mailfrom=cmarinas@kernel.org
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

On Thu, Aug 27, 2020 at 02:34:31PM +0200, Andrey Konovalov wrote:
> On Thu, Aug 27, 2020 at 12:48 PM Catalin Marinas
> <catalin.marinas@arm.com> wrote:
> > On Fri, Aug 14, 2020 at 07:27:14PM +0200, Andrey Konovalov wrote:
> > > diff --git a/arch/arm64/mm/fault.c b/arch/arm64/mm/fault.c
> > > index c62c8ba85c0e..cf00b3942564 100644
> > > --- a/arch/arm64/mm/fault.c
> > > +++ b/arch/arm64/mm/fault.c
> > > @@ -14,6 +14,7 @@
> > >  #include <linux/mm.h>
> > >  #include <linux/hardirq.h>
> > >  #include <linux/init.h>
> > > +#include <linux/kasan.h>
> > >  #include <linux/kprobes.h>
> > >  #include <linux/uaccess.h>
> > >  #include <linux/page-flags.h>
> > > @@ -314,11 +315,19 @@ static void report_tag_fault(unsigned long addr, unsigned int esr,
> > >  {
> > >       bool is_write = ((esr & ESR_ELx_WNR) >> ESR_ELx_WNR_SHIFT) != 0;
> > >
> > > +#ifdef CONFIG_KASAN_HW_TAGS
> > > +     /*
> > > +      * SAS bits aren't set for all faults reported in EL1, so we can't
> > > +      * find out access size.
> > > +      */
> > > +     kasan_report(addr, 0, is_write, regs->pc);
> > > +#else
> > >       pr_alert("Memory Tagging Extension Fault in %pS\n", (void *)regs->pc);
> > >       pr_alert("  %s at address %lx\n", is_write ? "Write" : "Read", addr);
> > >       pr_alert("  Pointer tag: [%02x], memory tag: [%02x]\n",
> > >                       mte_get_ptr_tag(addr),
> > >                       mte_get_mem_tag((void *)addr));
> > > +#endif
> > >  }
> >
> > More dead code. So what's the point of keeping the pr_alert() introduced
> > earlier? CONFIG_KASAN_HW_TAGS is always on for in-kernel MTE. If MTE is
> > disabled, this function isn't called anyway.
> 
> I was considering that we can enable in-kernel MTE without enabling
> CONFIG_KASAN_HW_TAGS, but perhaps this isn't what we want. I'll drop
> this part in v2, but then we also need to make sure that in-kernel MTE
> is only enabled when CONFIG_KASAN_HW_TAGS is enabled. Do we need more
> ifdefs in arm64 patches when we write to MTE-related registers, or
> does this work as is?

I think the in-kernel MTE for the time being should only mean
CONFIG_KASAN_HW_TAGS, with a dependency on CONFIG_MTE. KASAN carries
some additional debugging features but if we can trim it down, we may
not need a separate in-kernel MTE option for production systems (maybe a
CONFIG_KASAN_HW_TAGS_LITE).

-- 
Catalin

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200827142131.GN29264%40gaia.
