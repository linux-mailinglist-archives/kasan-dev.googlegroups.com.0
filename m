Return-Path: <kasan-dev+bncBDV37XP3XYDRBTH6TGRAMGQE23ATCDA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43d.google.com (mail-wr1-x43d.google.com [IPv6:2a00:1450:4864:20::43d])
	by mail.lfdr.de (Postfix) with ESMTPS id DE44F6ECCA2
	for <lists+kasan-dev@lfdr.de>; Mon, 24 Apr 2023 15:08:29 +0200 (CEST)
Received: by mail-wr1-x43d.google.com with SMTP id ffacd0b85a97d-2fbb99cb303sf1543752f8f.1
        for <lists+kasan-dev@lfdr.de>; Mon, 24 Apr 2023 06:08:29 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1682341709; cv=pass;
        d=google.com; s=arc-20160816;
        b=kxu3wQWjvrUYd1ZTp2xr/7dAs5quVRbrCSEP/YT3Vwl9ZSWojcCQItu4FUJmbiOjwn
         DWHZWgutnVOugke/GPNhn0VFnbAfIOSCMxsp450E98182OcZw914qL342ROs2lFQV6Zs
         WQxDNUpPOjmBXPlvYwT5WpO5l4q2KVZ+GDyC6fbeSCWBGimqYhnOlxr0tFH7TVinRiKZ
         NfslBmcPHXBzr52WKPqwuLGaZ4GVpDmnFVDGnKkMWV/Yqp/dcNfFMmNuV5xd3VPLfW1c
         7qPDCw0Xjd9lHPVQLgGgBCdhshrln/3HT1uT8Xgl7cB+/AlY3srsEwkdSIHmk418uQkj
         TSbg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=wOUr8y3AS8ocbt1e5ID3zqf73aJqE0SZQHf1AfY/KtI=;
        b=whQZibVTh2bPXoRpz5X8rUcQoydljU3XLzdj4x8ozBBfkJHo4feX6FLrAnGVlVQp1w
         R6IErenBvGFazRaOzBQTIT39+UKwYNGqpIstQZbPdWkwCZQQ9Q8MHjltznZmnGj+O73u
         2WW0iLRn1n7PI6JDniGNx6bQZmWctlFWKgri7aAVEH7PWQnmWwYWVQl8leRYYLw52Qid
         VceNMyFaQED1wXCEWLXdPc6lW+R5lfRVpveRriD+tCcX8noTj10skFEV3wMa9ks8dqNm
         4Kl3++l/vxCg6jmHjJMLIWq7okRrPgZ4pzlBr2uBy2yw+aBaFuEugUNnfr4KnttVe3DY
         55aQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1682341709; x=1684933709;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=wOUr8y3AS8ocbt1e5ID3zqf73aJqE0SZQHf1AfY/KtI=;
        b=jdeSL4SkBFweBxUGpiFGhIB3C3mzDR/CK7S6CoWJDy2yb5kfpGsgpbaw77DuXjVQeu
         N76BLlavxZh+mT7wVzuejIuppjjd0+RPnZFiO61cnYT+Lwkv9aMCg6fmoDLhMYieIdRU
         l78JHM9/VZHLYoVeER2muJy0VUPggaQssLpEHOygIS9+b4mkdBdEDVfgbU+dL7lB8lpw
         QvSlxVttDphBTNfVm6USETbeHvXP/2/ti0D/w/2W9KKiiDNSoKQmkHfFaMb/HCOS1uMh
         tH7duDrwwLfypk/aQ7DaH1DjfZVKhRq3EWCWYS41hxpIyTeo50vjgdez5QHtDo9jRJb5
         C3wg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1682341709; x=1684933709;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=wOUr8y3AS8ocbt1e5ID3zqf73aJqE0SZQHf1AfY/KtI=;
        b=Hekqd7wpnz9XbzjZ+qYxZZxmcQlcM5o8K+YKUFkFcP+EkXS+LcEYOCGGZGpStVtl3H
         w7O5/+UHSXTE0gIHxfrRqLnCwQ+LyHsNsphqcRGh82p2gcj8Fbn5eHfdQdkma6kNXFRc
         I+JmiopGL/8f8quTeYDhyiyJdMNN1DImRxmVOEWQGD+eaeyqD7A1gK2Pf9quxXLaHetv
         JC22eltxHsBkn50hCFBfzlwvSYCrGQrIOw0gNeNJHpJBumVsTIPN/ATDN89LFSblxLbn
         B2/Vm0S2fwZZ4KgfDF+EoQoN+GOQcAhpVqnNDTXGn9yx6R0FnLYohd/kdHQnrkVr9vGe
         3BqQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AAQBX9cQpUx1FYwRPxijmGczs62Vp0j1SDCTU1NhRX9CCxcH/KrTvE3n
	0sZPutfWcR/VygFTjTG8iL8=
X-Google-Smtp-Source: AKy350YaLL31BYUlJ88I49HyeU4ggFNxzZf/AEKdbgeIMXdLVtMEqzmOCGLbvx6YaD3btSfeRdCPYg==
X-Received: by 2002:a5d:6607:0:b0:304:6b72:7509 with SMTP id n7-20020a5d6607000000b003046b727509mr1230938wru.7.1682341709086;
        Mon, 24 Apr 2023 06:08:29 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:470f:b0:3f1:71d2:94b5 with SMTP id
 v15-20020a05600c470f00b003f171d294b5ls5570912wmo.1.-pod-control-gmail; Mon,
 24 Apr 2023 06:08:27 -0700 (PDT)
X-Received: by 2002:a1c:7716:0:b0:3f1:70d5:1bee with SMTP id t22-20020a1c7716000000b003f170d51beemr7492846wmi.29.1682341707564;
        Mon, 24 Apr 2023 06:08:27 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1682341707; cv=none;
        d=google.com; s=arc-20160816;
        b=ish1U/aezoCkkORBXQ5Z1GlKjeNdwF6WpHTE1Srw7XzEVcCfUQIJfD1uacYSB2zh0Z
         tKbP8QLOkdX0d5Xi0JkOcUnk3nA2z4oKTfKORxk6ERw8okg7zJVVkOVraFyqEV7EglgK
         UE3oGw4WaVAu4/o03PCkwa6e3oqBWuNlU/EQlcCN/uJQdgfXU8z5bK0mXz0/H5TEZmxh
         WgF7jEdZKELGv7Kihurvh8xNDFXXclDj61m/SqatHcIM0y9iEBb3qMCWgYj/JwDLMy9f
         chPVH/EUZ7CtVdJ/6fMFTIXGFe1N4N2Wb8pBJgnlPS8GZnr+mJuTKCr5WMuyMmXHCC1W
         WPTA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date;
        bh=blJs5CltYw45WonB4J+hJ6KcXqfSB1ngnUTE5Oy7b/w=;
        b=Uzvi00IdAkue2iQTWeaYo3e3gKAQynoiDVAl68N+dL+xJ3IdqZ9HH7V6DN46WHDbt8
         ghRbOhWcD8fP1nl9qHJef+pI53A45sGmzVVEYX9l+NTcxb+ybh/epUuHf2PoZIBpoUmc
         f/wfGiisZLKxZeDOD6XZf6TGsXDLlGtA/M/tTvHNl5lzpqdJno/Pwy13lvKrPTwXE1Wm
         c6dDDeXLiYrYQMqwg+1W9JGOe9tF75N4ZC70RJdOgH+Oe8RVzdixGqyFL5uO99KlrrmK
         b8qDw9I7ObSEVtYCrV5C3y1YJncWqkCZgURUOzUGBM0gmwR/Y1Pol2RRb9bPXg1qwoj7
         5NFQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id n37-20020a05600c502500b003f189de7e3fsi595623wmr.0.2023.04.24.06.08.27
        for <kasan-dev@googlegroups.com>;
        Mon, 24 Apr 2023 06:08:27 -0700 (PDT)
Received-SPF: pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 9C1DFD75;
	Mon, 24 Apr 2023 06:09:10 -0700 (PDT)
Received: from FVFF77S0Q05N (unknown [10.57.23.164])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id A36ED3F64C;
	Mon, 24 Apr 2023 06:08:24 -0700 (PDT)
Date: Mon, 24 Apr 2023 14:08:14 +0100
From: Mark Rutland <mark.rutland@arm.com>
To: Dmitry Vyukov <dvyukov@google.com>
Cc: Youngmin Nam <youngmin.nam@samsung.com>, catalin.marinas@arm.com,
	will@kernel.org, anshuman.khandual@arm.com, broonie@kernel.org,
	alexandru.elisei@arm.com, ardb@kernel.org,
	linux-arm-kernel@lists.infradead.org, hy50.seo@samsung.com,
	andreyknvl@gmail.com, maz@kernel.org,
	kasan-dev <kasan-dev@googlegroups.com>
Subject: Re: [PATCH] arm64: set __exception_irq_entry with __irq_entry as a
 default
Message-ID: <ZEZ/Pk0wqiBJNKEN@FVFF77S0Q05N>
References: <CGME20230424003252epcas2p29758e056b4766e53c252b5927a0cb406@epcas2p2.samsung.com>
 <20230424010436.779733-1-youngmin.nam@samsung.com>
 <ZEZhftx05blmZv1T@FVFF77S0Q05N>
 <CACT4Y+bYJ=YHNMFAyWXaid8aNYyjnzkWrKyCfMumO21WntKCzw@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CACT4Y+bYJ=YHNMFAyWXaid8aNYyjnzkWrKyCfMumO21WntKCzw@mail.gmail.com>
X-Original-Sender: mark.rutland@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as
 permitted sender) smtp.mailfrom=mark.rutland@arm.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=arm.com
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

On Mon, Apr 24, 2023 at 02:09:05PM +0200, Dmitry Vyukov wrote:
> On Mon, 24 Apr 2023 at 13:01, Mark Rutland <mark.rutland@arm.com> wrote:
> >
> > On Mon, Apr 24, 2023 at 10:04:36AM +0900, Youngmin Nam wrote:
> > > filter_irq_stacks() is supposed to cut entries which are related irq entries
> > > from its call stack.
> > > And in_irqentry_text() which is called by filter_irq_stacks()
> > > uses __irqentry_text_start/end symbol to find irq entries in callstack.
> > >
> > > But it doesn't work correctly as without "CONFIG_FUNCTION_GRAPH_TRACER",
> > > arm64 kernel doesn't include gic_handle_irq which is entry point of arm64 irq
> > > between __irqentry_text_start and __irqentry_text_end as we discussed in below link.
> >
> > TBH, the __irqentry_text annotations don't make much sense, and I'd love to
> > remove them.
> >
> > The irqchip handlers are not the actual exception entry points, and we invoke a
> > fair amount of code between those and the actual IRQ handlers (e.g. to map from
> > the irq domain to the actual hander, which might involve poking chained irqchip
> > handlers), so it doesn't make much sense for the irqchip handlers to be
> > special.
> >
> > > https://lore.kernel.org/all/CACT4Y+aReMGLYua2rCLHgFpS9io5cZC04Q8GLs-uNmrn1ezxYQ@mail.gmail.com/#t
> > >
> > > This problem can makes unintentional deep call stack entries especially
> > > in KASAN enabled situation as below.
> >
> > What exactly does KASAN need here? Is this just to limit the depth of the
> > trace?
> 
> No, it's not just depth. Any uses of stack depot need stable
> repeatable traces, so that they are deduplicated well. For irq stacks
> it means removing the random part where the interrupt is delivered.
> Otherwise stack depot grows without limits and overflows.

Sure -- you want to filter out the non-deterministic context that the interrupt
was taken *from*.

> We don't need the exact entry point for this. A frame "close enough"
> may work well if there are no memory allocations/frees skipped.

With that in mind, I think what we should do is cut this at the instant we
enter the exception; for the trace below that would be el1h_64_irq. I've added
some line spacing there to make it stand out.

That would mean that we'd have three entry points that an interrupt trace might
start from:

* el1h_64_irq()
* el0t_64_irq()
* el0t_32_irq()

... so we might have three traces for a given interrupt, but the portion
between that and the irqchip handler would be deterministic, so deduplication
would only end up with three traces.

It may be useful to distinguish the three cases, since some IRQ handlers do
different things when user_mode(regs) and/or compat_user_mode(regs) are true.

> > If so, we could easily add an API to get a stacktrace up to an IRQ exception
> > boundary. IIRC we'd been asked for that in the past, and it's relatively simple
> > to implement that regardless of CONFIG_FUNCTION_GRAPH_TRACER.
> >
> > > [ 2479.383395]I[0:launcher-loader: 1719] Stack depot reached limit capacity
> > > [ 2479.383538]I[0:launcher-loader: 1719] WARNING: CPU: 0 PID: 1719 at lib/stackdepot.c:129 __stack_depot_save+0x464/0x46c
> > > [ 2479.385693]I[0:launcher-loader: 1719] pstate: 624000c5 (nZCv daIF +PAN -UAO +TCO -DIT -SSBS BTYPE=--)
> > > [ 2479.385724]I[0:launcher-loader: 1719] pc : __stack_depot_save+0x464/0x46c
> > > [ 2479.385751]I[0:launcher-loader: 1719] lr : __stack_depot_save+0x460/0x46c
> > > [ 2479.385774]I[0:launcher-loader: 1719] sp : ffffffc0080073c0
> > > [ 2479.385793]I[0:launcher-loader: 1719] x29: ffffffc0080073e0 x28: ffffffd00b78a000 x27: 0000000000000000
> > > [ 2479.385839]I[0:launcher-loader: 1719] x26: 000000000004d1dd x25: ffffff891474f000 x24: 00000000ca64d1dd
> > > [ 2479.385882]I[0:launcher-loader: 1719] x23: 0000000000000200 x22: 0000000000000220 x21: 0000000000000040
> > > [ 2479.385925]I[0:launcher-loader: 1719] x20: ffffffc008007440 x19: 0000000000000000 x18: 0000000000000000
> > > [ 2479.385969]I[0:launcher-loader: 1719] x17: 2065726568207475 x16: 000000000000005e x15: 2d2d2d2d2d2d2d20
> > > [ 2479.386013]I[0:launcher-loader: 1719] x14: 5d39313731203a72 x13: 00000000002f6b30 x12: 00000000002f6af8
> > > [ 2479.386057]I[0:launcher-loader: 1719] x11: 00000000ffffffff x10: ffffffb90aacf000 x9 : e8a74a6c16008800
> > > [ 2479.386101]I[0:launcher-loader: 1719] x8 : e8a74a6c16008800 x7 : 00000000002f6b30 x6 : 00000000002f6af8
> > > [ 2479.386145]I[0:launcher-loader: 1719] x5 : ffffffc0080070c8 x4 : ffffffd00b192380 x3 : ffffffd0092b313c
> > > [ 2479.386189]I[0:launcher-loader: 1719] x2 : 0000000000000001 x1 : 0000000000000004 x0 : 0000000000000022
> > > [ 2479.386231]I[0:launcher-loader: 1719] Call trace:
> > > [ 2479.386248]I[0:launcher-loader: 1719]  __stack_depot_save+0x464/0x46c
> > > [ 2479.386273]I[0:launcher-loader: 1719]  kasan_save_stack+0x58/0x70
> > > [ 2479.386303]I[0:launcher-loader: 1719]  save_stack_info+0x34/0x138
> > > [ 2479.386331]I[0:launcher-loader: 1719]  kasan_save_free_info+0x18/0x24
> > > [ 2479.386358]I[0:launcher-loader: 1719]  ____kasan_slab_free+0x16c/0x170
> > > [ 2479.386385]I[0:launcher-loader: 1719]  __kasan_slab_free+0x10/0x20
> > > [ 2479.386410]I[0:launcher-loader: 1719]  kmem_cache_free+0x238/0x53c
> > > [ 2479.386435]I[0:launcher-loader: 1719]  mempool_free_slab+0x1c/0x28
> > > [ 2479.386460]I[0:launcher-loader: 1719]  mempool_free+0x7c/0x1a0
> > > [ 2479.386484]I[0:launcher-loader: 1719]  bvec_free+0x34/0x80
> > > [ 2479.386514]I[0:launcher-loader: 1719]  bio_free+0x60/0x98
> > > [ 2479.386540]I[0:launcher-loader: 1719]  bio_put+0x50/0x21c
> > > [ 2479.386567]I[0:launcher-loader: 1719]  f2fs_write_end_io+0x4ac/0x4d0
> > > [ 2479.386594]I[0:launcher-loader: 1719]  bio_endio+0x2dc/0x300
> > > [ 2479.386622]I[0:launcher-loader: 1719]  __dm_io_complete+0x324/0x37c
> > > [ 2479.386650]I[0:launcher-loader: 1719]  dm_io_dec_pending+0x60/0xa4
> > > [ 2479.386676]I[0:launcher-loader: 1719]  clone_endio+0xf8/0x2f0
> > > [ 2479.386700]I[0:launcher-loader: 1719]  bio_endio+0x2dc/0x300
> > > [ 2479.386727]I[0:launcher-loader: 1719]  blk_update_request+0x258/0x63c
> > > [ 2479.386754]I[0:launcher-loader: 1719]  scsi_end_request+0x50/0x304
> > > [ 2479.386782]I[0:launcher-loader: 1719]  scsi_io_completion+0x88/0x160
> > > [ 2479.386808]I[0:launcher-loader: 1719]  scsi_finish_command+0x17c/0x194
> > > [ 2479.386833]I[0:launcher-loader: 1719]  scsi_complete+0xcc/0x158
> > > [ 2479.386859]I[0:launcher-loader: 1719]  blk_mq_complete_request+0x4c/0x5c
> > > [ 2479.386885]I[0:launcher-loader: 1719]  scsi_done_internal+0xf4/0x1e0
> > > [ 2479.386910]I[0:launcher-loader: 1719]  scsi_done+0x14/0x20
> > > [ 2479.386935]I[0:launcher-loader: 1719]  ufshcd_compl_one_cqe+0x578/0x71c
> > > [ 2479.386963]I[0:launcher-loader: 1719]  ufshcd_mcq_poll_cqe_nolock+0xc8/0x150
> > > [ 2479.386991]I[0:launcher-loader: 1719]  ufshcd_intr+0x868/0xc0c
> > > [ 2479.387017]I[0:launcher-loader: 1719]  __handle_irq_event_percpu+0xd0/0x348
> > > [ 2479.387044]I[0:launcher-loader: 1719]  handle_irq_event_percpu+0x24/0x74
> > > [ 2479.387068]I[0:launcher-loader: 1719]  handle_irq_event+0x74/0xe0
> > > [ 2479.387091]I[0:launcher-loader: 1719]  handle_fasteoi_irq+0x174/0x240
> > > [ 2479.387118]I[0:launcher-loader: 1719]  handle_irq_desc+0x7c/0x2c0
> > > [ 2479.387147]I[0:launcher-loader: 1719]  generic_handle_domain_irq+0x1c/0x28
> > > [ 2479.387174]I[0:launcher-loader: 1719]  gic_handle_irq+0x64/0x158
> > > [ 2479.387204]I[0:launcher-loader: 1719]  call_on_irq_stack+0x2c/0x54
> > > [ 2479.387231]I[0:launcher-loader: 1719]  do_interrupt_handler+0x70/0xa0
> > > [ 2479.387258]I[0:launcher-loader: 1719]  el1_interrupt+0x34/0x68
> > > [ 2479.387283]I[0:launcher-loader: 1719]  el1h_64_irq_handler+0x18/0x24
> > > [ 2479.387308]I[0:launcher-loader: 1719]  el1h_64_irq+0x68/0x6c

This is where we'd cut the trace with my suggestion.

> > > [ 2479.387332]I[0:launcher-loader: 1719]  blk_attempt_bio_merge+0x8/0x170
> > > [ 2479.387356]I[0:launcher-loader: 1719]  blk_mq_attempt_bio_merge+0x78/0x98
> > > [ 2479.387383]I[0:launcher-loader: 1719]  blk_mq_submit_bio+0x324/0xa40
> > > [ 2479.387409]I[0:launcher-loader: 1719]  __submit_bio+0x104/0x138
> > > [ 2479.387436]I[0:launcher-loader: 1719]  submit_bio_noacct_nocheck+0x1d0/0x4a0
> > > [ 2479.387462]I[0:launcher-loader: 1719]  submit_bio_noacct+0x618/0x804
> > > [ 2479.387487]I[0:launcher-loader: 1719]  submit_bio+0x164/0x180
> > > [ 2479.387511]I[0:launcher-loader: 1719]  f2fs_submit_read_bio+0xe4/0x1c4
> > > [ 2479.387537]I[0:launcher-loader: 1719]  f2fs_mpage_readpages+0x888/0xa4c
> > > [ 2479.387563]I[0:launcher-loader: 1719]  f2fs_readahead+0xd4/0x19c
> > > [ 2479.387587]I[0:launcher-loader: 1719]  read_pages+0xb0/0x4ac
> > > [ 2479.387614]I[0:launcher-loader: 1719]  page_cache_ra_unbounded+0x238/0x288
> > > [ 2479.387642]I[0:launcher-loader: 1719]  do_page_cache_ra+0x60/0x6c
> > > [ 2479.387669]I[0:launcher-loader: 1719]  page_cache_ra_order+0x318/0x364
> > > [ 2479.387695]I[0:launcher-loader: 1719]  ondemand_readahead+0x30c/0x3d8
> > > [ 2479.387722]I[0:launcher-loader: 1719]  page_cache_sync_ra+0xb4/0xc8
> > > [ 2479.387749]I[0:launcher-loader: 1719]  filemap_read+0x268/0xd24
> > > [ 2479.387777]I[0:launcher-loader: 1719]  f2fs_file_read_iter+0x1a0/0x62c
> > > [ 2479.387806]I[0:launcher-loader: 1719]  vfs_read+0x258/0x34c
> > > [ 2479.387831]I[0:launcher-loader: 1719]  ksys_pread64+0x8c/0xd0
> > > [ 2479.387857]I[0:launcher-loader: 1719]  __arm64_sys_pread64+0x48/0x54
> > > [ 2479.387881]I[0:launcher-loader: 1719]  invoke_syscall+0x58/0x158
> > > [ 2479.387909]I[0:launcher-loader: 1719]  el0_svc_common+0xf0/0x134
> > > [ 2479.387935]I[0:launcher-loader: 1719]  do_el0_svc+0x44/0x114
> > > [ 2479.387961]I[0:launcher-loader: 1719]  el0_svc+0x2c/0x80
> > > [ 2479.387985]I[0:launcher-loader: 1719]  el0t_64_sync_handler+0x48/0x114
> > > [ 2479.388010]I[0:launcher-loader: 1719]  el0t_64_sync+0x190/0x194
> > > [ 2479.388038]I[0:launcher-loader: 1719] Kernel panic - not syncing: kernel: panic_on_warn set ...

Thanks,
Mark.

> > >
> > > So let's set __exception_irq_entry with __irq_entry as a default.
> > > Applying this patch, we can see gic_hande_irq is included in Systemp.map as below.
> > >
> > > * Before
> > > ffffffc008010000 T __do_softirq
> > > ffffffc008010000 T __irqentry_text_end
> > > ffffffc008010000 T __irqentry_text_start
> > > ffffffc008010000 T __softirqentry_text_start
> > > ffffffc008010000 T _stext
> > > ffffffc00801066c T __softirqentry_text_end
> > > ffffffc008010670 T __entry_text_start
> > >
> > > * After
> > > ffffffc008010000 T __irqentry_text_start
> > > ffffffc008010000 T _stext
> > > ffffffc008010000 t gic_handle_irq
> > > ffffffc00801013c t gic_handle_irq
> > > ffffffc008010294 T __irqentry_text_end
> > > ffffffc008010298 T __do_softirq
> > > ffffffc008010298 T __softirqentry_text_start
> > > ffffffc008010904 T __softirqentry_text_end
> > > ffffffc008010908 T __entry_text_start
> > >
> > > Signed-off-by: Youngmin Nam <youngmin.nam@samsung.com>
> > > Signed-off-by: SEO HOYOUNG <hy50.seo@samsung.com>
> > > Change-Id: Iea7ff528be1c72cf50ab6aabafa77215ddb55eb2
> >
> > This change-id is meaningless upstream.
> >
> > > ---
> > >  arch/arm64/include/asm/exception.h | 5 -----
> > >  1 file changed, 5 deletions(-)
> > >
> > > diff --git a/arch/arm64/include/asm/exception.h b/arch/arm64/include/asm/exception.h
> > > index 19713d0f013b..18dbb35a337f 100644
> > > --- a/arch/arm64/include/asm/exception.h
> > > +++ b/arch/arm64/include/asm/exception.h
> > > @@ -8,16 +8,11 @@
> > >  #define __ASM_EXCEPTION_H
> > >
> > >  #include <asm/esr.h>
> > > -#include <asm/kprobes.h>
> > >  #include <asm/ptrace.h>
> > >
> > >  #include <linux/interrupt.h>
> > >
> > > -#ifdef CONFIG_FUNCTION_GRAPH_TRACER
> > >  #define __exception_irq_entry        __irq_entry
> > > -#else
> > > -#define __exception_irq_entry        __kprobes
> > > -#endif
> >
> > How does this affect ftrace and kprobes? The commit message never explained why
> > this change is safe.
> >
> > Thanks,
> > Mark.
> >
> > >
> > >  static inline unsigned long disr_to_esr(u64 disr)
> > >  {
> > > --
> > > 2.39.2
> > >

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZEZ/Pk0wqiBJNKEN%40FVFF77S0Q05N.
