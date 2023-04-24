Return-Path: <kasan-dev+bncBCMIZB7QWENRB4PCTGRAMGQEUY26WMY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53c.google.com (mail-ed1-x53c.google.com [IPv6:2a00:1450:4864:20::53c])
	by mail.lfdr.de (Postfix) with ESMTPS id 6646D6ECBCE
	for <lists+kasan-dev@lfdr.de>; Mon, 24 Apr 2023 14:09:22 +0200 (CEST)
Received: by mail-ed1-x53c.google.com with SMTP id 4fb4d7f45d1cf-5068e922bcasf3795200a12.1
        for <lists+kasan-dev@lfdr.de>; Mon, 24 Apr 2023 05:09:22 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1682338162; cv=pass;
        d=google.com; s=arc-20160816;
        b=T9XsGDn88E0dwW6KTzJHO5Y7dc+5eEzwmdlSa6U5vzRD1lY/CXFLYYKFxFnMHkFr/+
         mjK0WoNS/6F7S440c5UAcadMTI6Z4Yfflx8LT5SBekCb75LD8gMGwAAI7YqTAHYZQNq1
         izfTWlQAgVvzWyO1ea9chc0eMzeZGIx4OGwZp8/wXTy6b4nDQaBEWWoxBspNn5gaiMLK
         yEZVQGvfmgoC11NrF4Q6xiIvqrYAz5NsmaGFUtkC83EVFl2xE9zWqkpsgd1ox7aKS58g
         PHBqDbzVJoAylfJZ/QQCu3FCJh0GikYATpA8EXJty6oTJU3clgPFiBTVNmMgWP9idyzv
         k3bg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=R+U7V/SsRSIVf8Z9iPhtdnPwS2tIOlAuXIG5hX2TAus=;
        b=OkpOqPA5BZHXLkp6myNfayl5tsx5+7R0TUIqukPFJBQP8sVjp/bXTpKUWj+a2QvlbK
         s9PmGtFyhUElld4nhl/Pc8HcAlQiOuw7ANSn+mFgotp8+9aX3jII7GGoEZCxdHNZMsok
         YJiNwbf/mzNdIvlqgHgt6Kftil0ISnCEJCTikc2P6Hwn7sdW0oYIKFMRWqVGZVnbuvBQ
         N6+FKZwBkrPe3XSYW+Vjb+sJ4R0oxLW09Fa3NNIUmP8d4CjcPewI0feS3+d3yeQ7fe4s
         3gYHQMdn1wRk0/eU/N3atAlW/UbT4w0LBaUN0qnH9mklEzHiFTzml4g9wvNyWV6pQg0t
         Bwxw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=i6KBuMLW;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::132 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1682338162; x=1684930162;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=R+U7V/SsRSIVf8Z9iPhtdnPwS2tIOlAuXIG5hX2TAus=;
        b=HiEL4yEKmYzo/DhlGlNS+mBDxCinUH05V3gbG4vPmP4ha2DJljwPVd99OXxbuNoAd2
         pe63RiVgpuk6veXTLhGuOOBPRH33ivo0u+nkPAtRcly6btBne8qOs6kdcKYhJLzXJJ5I
         e19r1PKWnEd6VPlcSoSJZxFkeHtx8Mi1bIwDSlp4n3bDVotX1ALA4YUrJ7gkR80u2Fvx
         5e89/5d0m3qFPOKSAAXTrPWE7fyZy6vLHS3QHLrUY2e9LC/dIhfQwoB5duUdtNNEvtVY
         9+ZUBcaYkvqiWBTbNzXB6WFgLwmBOqbnFjH/wlgD/1sfoF+8DmsJyNnsYU6ZfjX8wi8y
         xNpg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1682338162; x=1684930162;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=R+U7V/SsRSIVf8Z9iPhtdnPwS2tIOlAuXIG5hX2TAus=;
        b=YvUe21lNoYJUUEACcTzMbCiF8b5gjjvg0GoGnF50nkO1oPQLXCXi4upcluvdeAEvOQ
         nWFbfDAdX3LvqRmXvQ6Wh/PJaJk1s6qE6mXkXhMwZ+LyRnlXds/WBY1lqlDkVCwWJ8rf
         7dHupoVe8j+CmMMbAxyXDvlqcQYd/LH1mG/Dl366122Ojs+YJ/gDQv5tXa7M+GYdGPk7
         JzvDmiURE/FrD0/lyNxLZMjzD6wivFz+hZPnZqY7JH56YNlDwCCZkcv54i2JxYtBOOB+
         q6CJPTNhS4FbfB5KeeAkpry72VOrVtyU3To6IEOiK5sXCPFTEXyx3hPSqOgTtUSK/y4G
         X3Vg==
X-Gm-Message-State: AAQBX9ezMkrT/lSqEtPy0uyUG0JsDqp+DdWIu+pIsJRmBTUdVQ3FyY65
	HhZ9ka05Wgcy8jr/xbIlsFw=
X-Google-Smtp-Source: AKy350afItcjKEkWlmUfnILJF5EHxE3NX3zjB8oVR9FCQ+NqXkKHJG1gpFOoGhR7mkND4uLXS01rBg==
X-Received: by 2002:a17:906:b147:b0:958:341c:c4e1 with SMTP id bt7-20020a170906b14700b00958341cc4e1mr2636415ejb.13.1682338161533;
        Mon, 24 Apr 2023 05:09:21 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:4402:b0:505:4cd:5bc2 with SMTP id
 y2-20020a056402440200b0050504cd5bc2ls803812eda.1.-pod-prod-gmail; Mon, 24 Apr
 2023 05:09:20 -0700 (PDT)
X-Received: by 2002:a05:6402:78b:b0:504:b30a:2298 with SMTP id d11-20020a056402078b00b00504b30a2298mr11916172edy.42.1682338160219;
        Mon, 24 Apr 2023 05:09:20 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1682338160; cv=none;
        d=google.com; s=arc-20160816;
        b=BR/Yd3/4+ES3996YhHVNB0AuTxb5fqeXiUIrLVOi4PHrD+ZIJiTYutNhOsq0oiA6UI
         HPDtFppL77Uu+EKcDzV9b5U+KC8hD+QIoZpYNLbwYIXzHQU3k+WaWHdnoJO03rP0dn24
         XSStQ54Od5tjWAf2aEcjXtfpebcFmW5XU7TyvWfJ8+ZuwPkWPoRa+UukotRpKX15ZfoU
         hBqIMKAP2AdMPfZEIvJmUiW2PxLjfzUaQ6m3nORJ+RsNcWr6YMda8SLXFqynhpsrnqkS
         UJRHTH7Xuylg+G2qibpFwgBUm/P+kEqG/xUPaCYaHbk968EaR4ZJsxc9Xj8/YVVUghVC
         dYKw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=9Zk9sr41fnri7oxNdIS0W7c2/vEMq/o0w0AOYd08HNw=;
        b=0vshwZUblXCetg65gfiKbiTAiHTFJpxorbRqwr6COIVsqgCG1gxngbFU7t2iPZio7o
         JhlJ//fEF0dxGCBCn3z5mk3KFEVdAOfwEw5fpGMoVQwVW2M/nEVPvnGT2XHIQ3Hhbrmb
         65C9fMFTNibfXzXVfitPtmG1QpFW0KsGsixeQyy83DHeFDkyY/WWMT0BpnKH0183Rjsp
         YdcoxBQIX27gZBso+gwojSY3toBWLNv195DkMIwE6ZabmrlycA5xgX6UfMpL+RJoT68T
         wVM7Ujo8yC6ftIMn2MJxKtHBeWGk8vv2CMJEoxsD9undzwcf8v9mLDPatesNG/0cHFKC
         UhRQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=i6KBuMLW;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::132 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-lf1-x132.google.com (mail-lf1-x132.google.com. [2a00:1450:4864:20::132])
        by gmr-mx.google.com with ESMTPS id n11-20020a170906378b00b009531f349d24si642005ejc.0.2023.04.24.05.09.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 24 Apr 2023 05:09:20 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::132 as permitted sender) client-ip=2a00:1450:4864:20::132;
Received: by mail-lf1-x132.google.com with SMTP id 2adb3069b0e04-4ecb7fe8fb8so11579e87.0
        for <kasan-dev@googlegroups.com>; Mon, 24 Apr 2023 05:09:20 -0700 (PDT)
X-Received: by 2002:a05:6512:ac1:b0:4ed:b131:3449 with SMTP id
 n1-20020a0565120ac100b004edb1313449mr250561lfu.7.1682338159233; Mon, 24 Apr
 2023 05:09:19 -0700 (PDT)
MIME-Version: 1.0
References: <CGME20230424003252epcas2p29758e056b4766e53c252b5927a0cb406@epcas2p2.samsung.com>
 <20230424010436.779733-1-youngmin.nam@samsung.com> <ZEZhftx05blmZv1T@FVFF77S0Q05N>
In-Reply-To: <ZEZhftx05blmZv1T@FVFF77S0Q05N>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 24 Apr 2023 14:09:05 +0200
Message-ID: <CACT4Y+bYJ=YHNMFAyWXaid8aNYyjnzkWrKyCfMumO21WntKCzw@mail.gmail.com>
Subject: Re: [PATCH] arm64: set __exception_irq_entry with __irq_entry as a default
To: Mark Rutland <mark.rutland@arm.com>
Cc: Youngmin Nam <youngmin.nam@samsung.com>, catalin.marinas@arm.com, will@kernel.org, 
	anshuman.khandual@arm.com, broonie@kernel.org, alexandru.elisei@arm.com, 
	ardb@kernel.org, linux-arm-kernel@lists.infradead.org, hy50.seo@samsung.com, 
	andreyknvl@gmail.com, maz@kernel.org, kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20221208 header.b=i6KBuMLW;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::132
 as permitted sender) smtp.mailfrom=dvyukov@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Dmitry Vyukov <dvyukov@google.com>
Reply-To: Dmitry Vyukov <dvyukov@google.com>
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

On Mon, 24 Apr 2023 at 13:01, Mark Rutland <mark.rutland@arm.com> wrote:
>
> On Mon, Apr 24, 2023 at 10:04:36AM +0900, Youngmin Nam wrote:
> > filter_irq_stacks() is supposed to cut entries which are related irq entries
> > from its call stack.
> > And in_irqentry_text() which is called by filter_irq_stacks()
> > uses __irqentry_text_start/end symbol to find irq entries in callstack.
> >
> > But it doesn't work correctly as without "CONFIG_FUNCTION_GRAPH_TRACER",
> > arm64 kernel doesn't include gic_handle_irq which is entry point of arm64 irq
> > between __irqentry_text_start and __irqentry_text_end as we discussed in below link.
>
> TBH, the __irqentry_text annotations don't make much sense, and I'd love to
> remove them.
>
> The irqchip handlers are not the actual exception entry points, and we invoke a
> fair amount of code between those and the actual IRQ handlers (e.g. to map from
> the irq domain to the actual hander, which might involve poking chained irqchip
> handlers), so it doesn't make much sense for the irqchip handlers to be
> special.
>
> > https://lore.kernel.org/all/CACT4Y+aReMGLYua2rCLHgFpS9io5cZC04Q8GLs-uNmrn1ezxYQ@mail.gmail.com/#t
> >
> > This problem can makes unintentional deep call stack entries especially
> > in KASAN enabled situation as below.
>
> What exactly does KASAN need here? Is this just to limit the depth of the
> trace?

No, it's not just depth. Any uses of stack depot need stable
repeatable traces, so that they are deduplicated well. For irq stacks
it means removing the random part where the interrupt is delivered.
Otherwise stack depot grows without limits and overflows.

We don't need the exact entry point for this. A frame "close enough"
may work well if there are no memory allocations/frees skipped.

> If so, we could easily add an API to get a stacktrace up to an IRQ exception
> boundary. IIRC we'd been asked for that in the past, and it's relatively simple
> to implement that regardless of CONFIG_FUNCTION_GRAPH_TRACER.
>
> > [ 2479.383395]I[0:launcher-loader: 1719] Stack depot reached limit capacity
> > [ 2479.383538]I[0:launcher-loader: 1719] WARNING: CPU: 0 PID: 1719 at lib/stackdepot.c:129 __stack_depot_save+0x464/0x46c
> > [ 2479.385693]I[0:launcher-loader: 1719] pstate: 624000c5 (nZCv daIF +PAN -UAO +TCO -DIT -SSBS BTYPE=--)
> > [ 2479.385724]I[0:launcher-loader: 1719] pc : __stack_depot_save+0x464/0x46c
> > [ 2479.385751]I[0:launcher-loader: 1719] lr : __stack_depot_save+0x460/0x46c
> > [ 2479.385774]I[0:launcher-loader: 1719] sp : ffffffc0080073c0
> > [ 2479.385793]I[0:launcher-loader: 1719] x29: ffffffc0080073e0 x28: ffffffd00b78a000 x27: 0000000000000000
> > [ 2479.385839]I[0:launcher-loader: 1719] x26: 000000000004d1dd x25: ffffff891474f000 x24: 00000000ca64d1dd
> > [ 2479.385882]I[0:launcher-loader: 1719] x23: 0000000000000200 x22: 0000000000000220 x21: 0000000000000040
> > [ 2479.385925]I[0:launcher-loader: 1719] x20: ffffffc008007440 x19: 0000000000000000 x18: 0000000000000000
> > [ 2479.385969]I[0:launcher-loader: 1719] x17: 2065726568207475 x16: 000000000000005e x15: 2d2d2d2d2d2d2d20
> > [ 2479.386013]I[0:launcher-loader: 1719] x14: 5d39313731203a72 x13: 00000000002f6b30 x12: 00000000002f6af8
> > [ 2479.386057]I[0:launcher-loader: 1719] x11: 00000000ffffffff x10: ffffffb90aacf000 x9 : e8a74a6c16008800
> > [ 2479.386101]I[0:launcher-loader: 1719] x8 : e8a74a6c16008800 x7 : 00000000002f6b30 x6 : 00000000002f6af8
> > [ 2479.386145]I[0:launcher-loader: 1719] x5 : ffffffc0080070c8 x4 : ffffffd00b192380 x3 : ffffffd0092b313c
> > [ 2479.386189]I[0:launcher-loader: 1719] x2 : 0000000000000001 x1 : 0000000000000004 x0 : 0000000000000022
> > [ 2479.386231]I[0:launcher-loader: 1719] Call trace:
> > [ 2479.386248]I[0:launcher-loader: 1719]  __stack_depot_save+0x464/0x46c
> > [ 2479.386273]I[0:launcher-loader: 1719]  kasan_save_stack+0x58/0x70
> > [ 2479.386303]I[0:launcher-loader: 1719]  save_stack_info+0x34/0x138
> > [ 2479.386331]I[0:launcher-loader: 1719]  kasan_save_free_info+0x18/0x24
> > [ 2479.386358]I[0:launcher-loader: 1719]  ____kasan_slab_free+0x16c/0x170
> > [ 2479.386385]I[0:launcher-loader: 1719]  __kasan_slab_free+0x10/0x20
> > [ 2479.386410]I[0:launcher-loader: 1719]  kmem_cache_free+0x238/0x53c
> > [ 2479.386435]I[0:launcher-loader: 1719]  mempool_free_slab+0x1c/0x28
> > [ 2479.386460]I[0:launcher-loader: 1719]  mempool_free+0x7c/0x1a0
> > [ 2479.386484]I[0:launcher-loader: 1719]  bvec_free+0x34/0x80
> > [ 2479.386514]I[0:launcher-loader: 1719]  bio_free+0x60/0x98
> > [ 2479.386540]I[0:launcher-loader: 1719]  bio_put+0x50/0x21c
> > [ 2479.386567]I[0:launcher-loader: 1719]  f2fs_write_end_io+0x4ac/0x4d0
> > [ 2479.386594]I[0:launcher-loader: 1719]  bio_endio+0x2dc/0x300
> > [ 2479.386622]I[0:launcher-loader: 1719]  __dm_io_complete+0x324/0x37c
> > [ 2479.386650]I[0:launcher-loader: 1719]  dm_io_dec_pending+0x60/0xa4
> > [ 2479.386676]I[0:launcher-loader: 1719]  clone_endio+0xf8/0x2f0
> > [ 2479.386700]I[0:launcher-loader: 1719]  bio_endio+0x2dc/0x300
> > [ 2479.386727]I[0:launcher-loader: 1719]  blk_update_request+0x258/0x63c
> > [ 2479.386754]I[0:launcher-loader: 1719]  scsi_end_request+0x50/0x304
> > [ 2479.386782]I[0:launcher-loader: 1719]  scsi_io_completion+0x88/0x160
> > [ 2479.386808]I[0:launcher-loader: 1719]  scsi_finish_command+0x17c/0x194
> > [ 2479.386833]I[0:launcher-loader: 1719]  scsi_complete+0xcc/0x158
> > [ 2479.386859]I[0:launcher-loader: 1719]  blk_mq_complete_request+0x4c/0x5c
> > [ 2479.386885]I[0:launcher-loader: 1719]  scsi_done_internal+0xf4/0x1e0
> > [ 2479.386910]I[0:launcher-loader: 1719]  scsi_done+0x14/0x20
> > [ 2479.386935]I[0:launcher-loader: 1719]  ufshcd_compl_one_cqe+0x578/0x71c
> > [ 2479.386963]I[0:launcher-loader: 1719]  ufshcd_mcq_poll_cqe_nolock+0xc8/0x150
> > [ 2479.386991]I[0:launcher-loader: 1719]  ufshcd_intr+0x868/0xc0c
> > [ 2479.387017]I[0:launcher-loader: 1719]  __handle_irq_event_percpu+0xd0/0x348
> > [ 2479.387044]I[0:launcher-loader: 1719]  handle_irq_event_percpu+0x24/0x74
> > [ 2479.387068]I[0:launcher-loader: 1719]  handle_irq_event+0x74/0xe0
> > [ 2479.387091]I[0:launcher-loader: 1719]  handle_fasteoi_irq+0x174/0x240
> > [ 2479.387118]I[0:launcher-loader: 1719]  handle_irq_desc+0x7c/0x2c0
> > [ 2479.387147]I[0:launcher-loader: 1719]  generic_handle_domain_irq+0x1c/0x28
> > [ 2479.387174]I[0:launcher-loader: 1719]  gic_handle_irq+0x64/0x158
> > [ 2479.387204]I[0:launcher-loader: 1719]  call_on_irq_stack+0x2c/0x54
> > [ 2479.387231]I[0:launcher-loader: 1719]  do_interrupt_handler+0x70/0xa0
> > [ 2479.387258]I[0:launcher-loader: 1719]  el1_interrupt+0x34/0x68
> > [ 2479.387283]I[0:launcher-loader: 1719]  el1h_64_irq_handler+0x18/0x24
> > [ 2479.387308]I[0:launcher-loader: 1719]  el1h_64_irq+0x68/0x6c
> > [ 2479.387332]I[0:launcher-loader: 1719]  blk_attempt_bio_merge+0x8/0x170
> > [ 2479.387356]I[0:launcher-loader: 1719]  blk_mq_attempt_bio_merge+0x78/0x98
> > [ 2479.387383]I[0:launcher-loader: 1719]  blk_mq_submit_bio+0x324/0xa40
> > [ 2479.387409]I[0:launcher-loader: 1719]  __submit_bio+0x104/0x138
> > [ 2479.387436]I[0:launcher-loader: 1719]  submit_bio_noacct_nocheck+0x1d0/0x4a0
> > [ 2479.387462]I[0:launcher-loader: 1719]  submit_bio_noacct+0x618/0x804
> > [ 2479.387487]I[0:launcher-loader: 1719]  submit_bio+0x164/0x180
> > [ 2479.387511]I[0:launcher-loader: 1719]  f2fs_submit_read_bio+0xe4/0x1c4
> > [ 2479.387537]I[0:launcher-loader: 1719]  f2fs_mpage_readpages+0x888/0xa4c
> > [ 2479.387563]I[0:launcher-loader: 1719]  f2fs_readahead+0xd4/0x19c
> > [ 2479.387587]I[0:launcher-loader: 1719]  read_pages+0xb0/0x4ac
> > [ 2479.387614]I[0:launcher-loader: 1719]  page_cache_ra_unbounded+0x238/0x288
> > [ 2479.387642]I[0:launcher-loader: 1719]  do_page_cache_ra+0x60/0x6c
> > [ 2479.387669]I[0:launcher-loader: 1719]  page_cache_ra_order+0x318/0x364
> > [ 2479.387695]I[0:launcher-loader: 1719]  ondemand_readahead+0x30c/0x3d8
> > [ 2479.387722]I[0:launcher-loader: 1719]  page_cache_sync_ra+0xb4/0xc8
> > [ 2479.387749]I[0:launcher-loader: 1719]  filemap_read+0x268/0xd24
> > [ 2479.387777]I[0:launcher-loader: 1719]  f2fs_file_read_iter+0x1a0/0x62c
> > [ 2479.387806]I[0:launcher-loader: 1719]  vfs_read+0x258/0x34c
> > [ 2479.387831]I[0:launcher-loader: 1719]  ksys_pread64+0x8c/0xd0
> > [ 2479.387857]I[0:launcher-loader: 1719]  __arm64_sys_pread64+0x48/0x54
> > [ 2479.387881]I[0:launcher-loader: 1719]  invoke_syscall+0x58/0x158
> > [ 2479.387909]I[0:launcher-loader: 1719]  el0_svc_common+0xf0/0x134
> > [ 2479.387935]I[0:launcher-loader: 1719]  do_el0_svc+0x44/0x114
> > [ 2479.387961]I[0:launcher-loader: 1719]  el0_svc+0x2c/0x80
> > [ 2479.387985]I[0:launcher-loader: 1719]  el0t_64_sync_handler+0x48/0x114
> > [ 2479.388010]I[0:launcher-loader: 1719]  el0t_64_sync+0x190/0x194
> > [ 2479.388038]I[0:launcher-loader: 1719] Kernel panic - not syncing: kernel: panic_on_warn set ...
> >
> > So let's set __exception_irq_entry with __irq_entry as a default.
> > Applying this patch, we can see gic_hande_irq is included in Systemp.map as below.
> >
> > * Before
> > ffffffc008010000 T __do_softirq
> > ffffffc008010000 T __irqentry_text_end
> > ffffffc008010000 T __irqentry_text_start
> > ffffffc008010000 T __softirqentry_text_start
> > ffffffc008010000 T _stext
> > ffffffc00801066c T __softirqentry_text_end
> > ffffffc008010670 T __entry_text_start
> >
> > * After
> > ffffffc008010000 T __irqentry_text_start
> > ffffffc008010000 T _stext
> > ffffffc008010000 t gic_handle_irq
> > ffffffc00801013c t gic_handle_irq
> > ffffffc008010294 T __irqentry_text_end
> > ffffffc008010298 T __do_softirq
> > ffffffc008010298 T __softirqentry_text_start
> > ffffffc008010904 T __softirqentry_text_end
> > ffffffc008010908 T __entry_text_start
> >
> > Signed-off-by: Youngmin Nam <youngmin.nam@samsung.com>
> > Signed-off-by: SEO HOYOUNG <hy50.seo@samsung.com>
> > Change-Id: Iea7ff528be1c72cf50ab6aabafa77215ddb55eb2
>
> This change-id is meaningless upstream.
>
> > ---
> >  arch/arm64/include/asm/exception.h | 5 -----
> >  1 file changed, 5 deletions(-)
> >
> > diff --git a/arch/arm64/include/asm/exception.h b/arch/arm64/include/asm/exception.h
> > index 19713d0f013b..18dbb35a337f 100644
> > --- a/arch/arm64/include/asm/exception.h
> > +++ b/arch/arm64/include/asm/exception.h
> > @@ -8,16 +8,11 @@
> >  #define __ASM_EXCEPTION_H
> >
> >  #include <asm/esr.h>
> > -#include <asm/kprobes.h>
> >  #include <asm/ptrace.h>
> >
> >  #include <linux/interrupt.h>
> >
> > -#ifdef CONFIG_FUNCTION_GRAPH_TRACER
> >  #define __exception_irq_entry        __irq_entry
> > -#else
> > -#define __exception_irq_entry        __kprobes
> > -#endif
>
> How does this affect ftrace and kprobes? The commit message never explained why
> this change is safe.
>
> Thanks,
> Mark.
>
> >
> >  static inline unsigned long disr_to_esr(u64 disr)
> >  {
> > --
> > 2.39.2
> >

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BbYJ%3DYHNMFAyWXaid8aNYyjnzkWrKyCfMumO21WntKCzw%40mail.gmail.com.
