Return-Path: <kasan-dev+bncBD6LRVPZ6YGRBJXV5KEAMGQER75FPQQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x238.google.com (mail-oi1-x238.google.com [IPv6:2607:f8b0:4864:20::238])
	by mail.lfdr.de (Postfix) with ESMTPS id 423DE3EDDCD
	for <lists+kasan-dev@lfdr.de>; Mon, 16 Aug 2021 21:21:17 +0200 (CEST)
Received: by mail-oi1-x238.google.com with SMTP id n2-20020aca40020000b029025c9037b7fasf6904358oia.14
        for <lists+kasan-dev@lfdr.de>; Mon, 16 Aug 2021 12:21:17 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1629141671; cv=pass;
        d=google.com; s=arc-20160816;
        b=LvaF6hHA68pnz6XdD+tpPUADgGo9ndBQlMgKduQu6cFqVRgnVZNmvbk28pvmwBh6KP
         iwRU7r5Uxqji6cbZgHn6DpBMd3MXbWUBSjeeh1ZqSls8tT6Z6XbrlPXFTTyF6kmbAzgm
         vobA4EhTvlzGRizqbp4PLca6puxUsHDhalPgbqeK5X1WE8oIuQSoVqsfjz/fi/w/NIMP
         2EgXHdm8PHSDSw8Zq0SKjxi7wQjQuS0Kd7r7ZWggYU0HFYoohUhaYFKJfLLmXywo85U1
         B731fy+/5ZYkU0BzCNtaCjnKebhLu6DS5Z9kkzL5ToOS81gApit/MODtz9Dsm32aax8G
         RHNw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=D/j1cew1dYCg70ramsjOPTf0bJp7c4SN0C4zXAo97RM=;
        b=nmIXuvpOJ4l0QxDj0+UmEU7DWv1OFRDnKK8TWiDCYgu8fWjnm7ArWgQnr3WHFyLb+l
         B0aTsViJJ0ofT5bIPKx8VtlcdqpMlaA9nJ45DsVd9mMO66wZz/To6so7+IIWMT+eV4gb
         I1E7/J9DUv7Gbb8kHHvWVwXyqIqG1XeIFqC2Ucu5MgHIwQrXCqmhOhl4zPT3AOl64S+F
         5SNVbrDPqNt1EthbBZIpK/jpuuhQxyVy2uljBrrEkZj4eVfvQG9lZjMYEg4TIdDaK6D7
         nq40/NWd3M1IVLLTjZalkY6MXShkRK9XUjc4CDRo4xqxbosA5Dve9wXKLSVgLiIGCiIO
         2qyw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of stern+6109fa88@netrider.rowland.org designates 192.131.102.5 as permitted sender) smtp.mailfrom=stern+6109fa88@netrider.rowland.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=D/j1cew1dYCg70ramsjOPTf0bJp7c4SN0C4zXAo97RM=;
        b=a7nmgmffWGLpAL5164GV3RHdXncZS2/BO20z7R6HK2lVlabwYtAzQALABoP/5pV5uL
         4GSFdfeAV1WOZBhY4ZyzBNGLKyOHLefFdp9OUjcEbU3sgh57MMCnP11JntoAnZqCz8Tc
         nNQSpAqYE9z8vf32tkk1ivd7y2Jv8ccTyGlA2hpwLae89yawrYK0fcsjAdPIsk+HicMX
         Imw5n/6NUUR+y1Aqfim1unzT+X8LJmZ3eJU4qj0OfI72dxqNgNAE1vdvFWqn9ZLOeMqO
         fryhLnWpr7V93UwcM+C+wYrF/xxQbTRMYXubVcBUXbmkh3N00KpdyaFCDfJUwQgEZoeg
         5glQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=D/j1cew1dYCg70ramsjOPTf0bJp7c4SN0C4zXAo97RM=;
        b=OZQx0a+8BrUdm3ITxjVnUM4kFedqO27w2Q7s86B/siFLer7YjZDx/VL1Tj+NXoI7Cq
         7jNIp629NaZ8woRKgmV+3FcEE1ga37AMWdlZLtiiaZkRWqI2vpCcSOjiwx7OlMcNTdEX
         16RFk4sxOVEeQBMhrYPGgtFmUN0xxJOwP6C9VlSzLyxH8yvp+P+srkUoAY5Va9tP07zy
         3VuP6x0Db2aZ48UnVIDfeUMO/O8Ae3omhZIOyvO1iPA1B7dNJ0/GXkPuhId6s8o67t1M
         Fd4e9YaoscMCC+WTQJPY+OBkaWoBC2x+cDQ+Yw6/xG0YYAvu/1bNi2EncwIofNoWPEm8
         rE1w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532EzWuvPkC1yaHWQich876pQgp3ZAtk9Mt3LPOmIFmaiYNecYp+
	o9XKAdgBHkJhYwMTeQOCR2c=
X-Google-Smtp-Source: ABdhPJyMZYRL9VDEb1gSw6a7oFkAOjc2XbkGus3w/wLl7BHxGKc9SPYdl4xT38ZlbY0UnuBKvdKNBw==
X-Received: by 2002:aca:ad55:: with SMTP id w82mr244040oie.45.1629141670975;
        Mon, 16 Aug 2021 12:21:10 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:68c6:: with SMTP id i6ls85822oto.4.gmail; Mon, 16 Aug
 2021 12:21:10 -0700 (PDT)
X-Received: by 2002:a05:6830:1095:: with SMTP id y21mr246904oto.144.1629141670513;
        Mon, 16 Aug 2021 12:21:10 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1629141670; cv=none;
        d=google.com; s=arc-20160816;
        b=tVCRT+mgt2BiPCwdhOVkmcBQt/RbZaDhOlR/MXKzjQQcKW8VK0A6KfXlnSJT5hoVRT
         F86Otnt5zKBWf5UOlI2Hua/eIiUJHp4VDRA6n4BsoeZdTgX0K2/MB/YhoX6lMXDiHzVz
         gfbOOukzJT2li1BJ0O9eRCWwlst7zNjpS+4FuTw2MU3rUqfc/et4KstrQUMz0a+WVS/r
         q/IXENbxfC9/rQXYxyMXkLBtLBQVPfcXNiLGIUbg6t9HZO5KYmnXjajgTk6x5m53KTf6
         w6ml606VxM0FDdhSV/aR3VK75WcjmBLbQekWMhRuMCpYQUGy5fBobsH0V9/3KbcAoZ81
         IbIA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=KrKfMPlAL29ktLBDmQei7T9bMiqspLIUw6Dy6bTE45E=;
        b=XIILpn70w86+sjiuCbN6lNOeGs+Dz3VYhegJ4GcYTV2+I0fh6d0qIa3XcZ2ELarB9C
         IIxuGiiHTzdPOO6IhtBZqapd7ieiMzMHzG90WSoGDL1uHlpNZiFHMwidGrdAGqzoPIVT
         icgRT5tfK30gr6u/MiEYOZaK/8pllQ34CIcMQXIzynW6gO3Ba2RYKosgCyjc0ML/ZOg+
         0F+bVXHExJau1wzXFBPDqpBzDgXJrr6e/uTynUshGH9TUllBV16xHKbnxvJYJl4kycq/
         8/qN4v7AE5D6pfhQK0YU+/DXt+XbeR6kiJ2rjp58p0jJDF750Eff3QNIpy6zElpUhxGZ
         FWXw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of stern+6109fa88@netrider.rowland.org designates 192.131.102.5 as permitted sender) smtp.mailfrom=stern+6109fa88@netrider.rowland.org
Received: from netrider.rowland.org (netrider.rowland.org. [192.131.102.5])
        by gmr-mx.google.com with SMTP id j26si5777ooj.0.2021.08.16.12.21.10
        for <kasan-dev@googlegroups.com>;
        Mon, 16 Aug 2021 12:21:10 -0700 (PDT)
Received-SPF: pass (google.com: domain of stern+6109fa88@netrider.rowland.org designates 192.131.102.5 as permitted sender) client-ip=192.131.102.5;
Received: (qmail 131180 invoked by uid 1000); 16 Aug 2021 15:21:09 -0400
Date: Mon, 16 Aug 2021 15:21:09 -0400
From: Alan Stern <stern@rowland.harvard.edu>
To: Marco Elver <elver@google.com>
Cc: "Paul E. McKenney" <paulmck@kernel.org>,
  Boqun Feng <boqun.feng@gmail.com>, Andrea Parri <parri.andrea@gmail.com>,
  Will Deacon <will@kernel.org>, Mark Rutland <mark.rutland@arm.com>,
  Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com,
  linux-kernel@vger.kernel.org
Subject: Re: LKMM: Read dependencies of writes ordered by dma_wmb()?
Message-ID: <20210816192109.GC121345@rowland.harvard.edu>
References: <YRo58c+JGOvec7tc@elver.google.com>
 <20210816145945.GB121345@rowland.harvard.edu>
 <YRqfJz/lpUaZpxq7@elver.google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <YRqfJz/lpUaZpxq7@elver.google.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: stern@rowland.harvard.edu
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of stern+6109fa88@netrider.rowland.org designates
 192.131.102.5 as permitted sender) smtp.mailfrom=stern+6109fa88@netrider.rowland.org
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

On Mon, Aug 16, 2021 at 07:23:51PM +0200, Marco Elver wrote:
> On Mon, Aug 16, 2021 at 10:59AM -0400, Alan Stern wrote:
> [...]
> > > One caveat is the case I'm trying to understand doesn't involve just 2
> > > CPUs but also a device. And for now, I'm assuming that dma_wmb() is as
> > > strong as smp_wmb() also wrt other CPUs (but my guess is this
> > > assumption is already too strong).
> > 
> > I'm not sure that is right.  dma_wmb affects the visibility of writes to 
> > a DMA buffer from the point of view of the device, not necessarily from 
> > the point of view of other CPUs.  At least, there doesn't seem to be any 
> > claim in memory-barriers.txt that it does so.
> 
> Thanks, I thought so.
> 
> While I could just not instrument dma_*mb() at all, because KCSAN
> obviously can't instrument what devices do, I wonder if the resulting
> reports are at all interesting.
> 
> For example, if I do not make the assumption that dma_wmb==smp_smb, and
> don't instrument dma_*mb() at all, I also get racy UAF reordered writes:
> I could imagine some architecture where dma_wmb() propagates the write
> to devices from CPU 0; but CPU 1 then does the kfree(), reallocates,
> reuses the data, but then gets its data overwritten by CPU 0.

Access ordering of devices is difficult to describe.  How do you tell a 
memory model (either a theoretical one or one embedded in code like 
KCSAN) that a particular interrupt handler routine can't be called until 
after a particular write has enabled the device to generate an IRQ?

In the case you mention, how do you tell the memory model that the code 
on CPU 1 can't run until after CPU 0 has executed a particular write, one 
which is forced by some memory barrier to occur _after_ all the potential 
overwrites its worried about?

> What would be more useful?
> 
> 1. Let the architecture decide how they want KCSAN to instrument non-smp
>    barriers, given it's underspecified. This means KCSAN would report
>    different races on different architectures, but keep the noise down.
> 
> 2. Assume the weakest possible model, where non-smp barriers just do
>    nothing wrt other CPUs.

I don't think either of those would work out very well.  The problem 
isn't how you handle the non-smp barriers; the problem is how you 
describe to the memory model the way devices behave.

...

> > > In practice, my guess is no compiler and architecture combination would
> > > allow this today; or is there an arch where it could?
> > 
> > Probably not; reordering of reads tends to take place over time 
> > scales a lot shorter than lengthy I/O operations.
> 
> Which might be an argument to make KCSAN's non-smp barrier
> instrumentation arch-dependent, because some drivers might in fact be
> written with some target architectures and their properties in mind. At
> least it would help keep the noise down, and those architecture that
> want to see such races certainly still could.
> 
> Any preferences?

I'm not a good person to ask; I have never used KCSAN.  However...

While some drivers are indeed written for particular architectures or 
systems, I doubt that they rely very heavily on the special properties of 
their target architectures/systems to avoid races.  Rather, they rely on 
the hardware to behave correctly, just as non-arch-specific drivers do.

Furthermore, the kernel tries pretty hard to factor out arch-specific 
synchronization mechanisms and related concepts into general-purpose 
abstractions (in the way that smp_mb() is generally available but is 
defined differently for different architectures, for example).  Drivers 
tend to rely on these abstractions rather than on the arch-specific 
properties directly.

In short, trying to make KCSAN's handling of device I/O into something 
arch-specific doesn't seem (to me) like a particular advantageous 
approach.  Other people are likely to have different opinions.

Alan

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210816192109.GC121345%40rowland.harvard.edu.
