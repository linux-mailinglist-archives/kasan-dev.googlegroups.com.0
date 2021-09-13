Return-Path: <kasan-dev+bncBC7OBJGL2MHBBXFC72EQMGQEKDZGO5A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1040.google.com (mail-pj1-x1040.google.com [IPv6:2607:f8b0:4864:20::1040])
	by mail.lfdr.de (Postfix) with ESMTPS id 2D6EA409B8A
	for <lists+kasan-dev@lfdr.de>; Mon, 13 Sep 2021 19:58:54 +0200 (CEST)
Received: by mail-pj1-x1040.google.com with SMTP id v9-20020a17090a778900b001883abeabf0sf5544490pjk.1
        for <lists+kasan-dev@lfdr.de>; Mon, 13 Sep 2021 10:58:54 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1631555932; cv=pass;
        d=google.com; s=arc-20160816;
        b=PEI4+frqJSSQAHC6PczhlMMLcaTHrJlQMeHz42ZP6muCNZ4SlPVaDzkOon1GfP611M
         i9AjXst/p3PjM+ZAC5nvnkSSgdR8cw3nS7kD3E/Im37QukwN20eyEOcI9NHrm9igomsr
         nD4JiNcdFhFTDIfqzoUMDQNqtL+jFgH3cWZ5JxV021lscprQIY1uIy7UMQC7z9TLf59/
         MZqsTgI6Id4bEN32udmkVLgeYjPFauv6MCQIk5NbbeU3PaJ1tCZVODOGB6sY9qOYSEBK
         VkcodlK7WZEqTv7qcbS9Ecc/F5HFJw4BY5qHVZIY6sD5LCJC01G3b6nRypl9kbbKhEod
         sRUw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=WKTqowJ+QaroMFcnnxiAJKvUXslU6eLIRpdsoeHgVlI=;
        b=EbVbCXpq08qVvL1z28JU4Q6devgTgVHkXEma+vP3Mjpmv7+acjXF+fOBTtXviRI5cA
         I/36P+oL2YSmYvUwx7prllUR3f773GE3SNzRfgSTk50N/BRP/a6dOOHwSiDSschXsv1/
         93KaB3YX1D9lWBrWrkychwuq/M36zpUW8P4b8JVpTG4bMTmHoqxdTsdvLCi1H+xihSEv
         V5dUotiyOqeFYbvmCf9UbpBZFaZNN+6NcNzodcauYJuWpTmBArixaz8M+1js4BGnubhG
         WGCs8pqjs3ZTNvv5qy8DuBNEBe+oIHgQZge1VRjb1Ed3YkP0mPl1jTH5+nAPgrsOrrop
         BZDw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=lk5a4NHg;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22c as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=WKTqowJ+QaroMFcnnxiAJKvUXslU6eLIRpdsoeHgVlI=;
        b=QIm6kYZmrLw6N4nnc5fNWuWwbJ/l8VDg9zsxrExt0QYu3fLWZQWNWV2Rg+4mWuv11G
         WhUGf4j8+E6rJprWm1iLjDunOWgnWlVCd4HSEpFroAlgqY0qAu7C8r98BgtHHc8X0l6L
         YcclfV6m0ChCWkiD25ynFUgN4hgs+8zXlPDy3bdicl6q4ayuoUniN6E5GtOlmLbnO7VX
         JcdquCgFTycEmxXgSRNaoxH24fTgandaiOSFevSFECQpm2gfDVqjMUlJgq8hVFB6Na9B
         0yOWD1yGeBTc2+ciewpo6tdHtgByxzMue/hpg20EY/ejQx6BtCfxGkEnhOTCwROaR3GD
         W7SQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=WKTqowJ+QaroMFcnnxiAJKvUXslU6eLIRpdsoeHgVlI=;
        b=zgCI0lw3si0ZJXE3dwFPn6ZlPXac40yHa9Fz3PvEgnM800afVXGraT8J9ldzl27Usu
         SOi1T6jRVAma9F8dAZyYUP8ixiRRgzLW8MaZWHmH6sR1PTxfeDHsUCuOgUUdu7JZk8f9
         NAPK9IHHjA0FRB5Ed4xrjMAfTtkhKbUkd3VV0jyedwNwBuyjehLPX5edGxQyv4YST9VZ
         3x/QkjEgCfWOq8kjNK6p2Bxg5TkMMvSe6LO6nvknc4I8uuZXK2VdypkF4laq3WIHFTI8
         RK35eScscIkDiECgcq+Bg6GibwPgw5T+53Lnqi8DZI5hnvoVimbEIa59Kc6qjzRGgBp+
         VLtw==
X-Gm-Message-State: AOAM530lbf0AEcPLOsk5plbY+EfYbVDagThnfe9UiHpZnmc1OHO9oRWb
	9RpO4AkvaorSUfAMsXDKP60=
X-Google-Smtp-Source: ABdhPJzgVjMphc55ffsPWD7oSYyBD4awVaLDgKQYuVfzAYvFwh8tDWyqNWUnxUATUjveNns/AecFMQ==
X-Received: by 2002:a17:902:e0c1:b0:13b:76f5:c3b4 with SMTP id e1-20020a170902e0c100b0013b76f5c3b4mr11317217pla.85.1631555932763;
        Mon, 13 Sep 2021 10:58:52 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:c405:: with SMTP id k5ls3796439plk.5.gmail; Mon, 13
 Sep 2021 10:58:52 -0700 (PDT)
X-Received: by 2002:a17:90a:9912:: with SMTP id b18mr885643pjp.46.1631555932068;
        Mon, 13 Sep 2021 10:58:52 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1631555932; cv=none;
        d=google.com; s=arc-20160816;
        b=IQWjd5aMvkPzlvjQanF69tYR3JJgRl41ctLDJsBsVe7tILiZk6XDqj0XF9VI1jPwlT
         YpFYac6nVhfnaI9DiW9aPjfxglOVCOfiksArE/S0uK3hQHn5mFXFKw94WVwU/VRFsG7F
         YLgAiIIV4SNznQaQ8xfN5Ubs4KHy041dcx7WEwXa1mHwAttC+K2blHzlAJzFUMaP16fe
         y7C8wkHxmOjLbqjuinuXSkWXaeE9BpuALD/oIJ2TlG958zis+ZKBNAEbiUiCGE54ckKr
         7nDLV2RF7fMiX7HC7MrUMmQKzHRzBQkpy/9GUGTxDJiyFRDjSItgcnr/jP5RLK47qnBL
         FEWA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=WYhC7SL+4as2ND/qPy+Y7r2GKb7SvMEFyVMfGu0ciwc=;
        b=B4/VFxNFno8gvd8YUGMMcjkETnNqXKge5TyfHkJhcrgDevlVvnFKFvhQyfvG69iHiN
         O0fjpY7R0Q2/v6BIW3rTQQduK+A2G68G+mcIFjGtbyVMAFL5bhor6qdTqV9jLwivTtSN
         T/BTDMonrg8n7SbTfYB8UFxt1lvQI7GaqNls1mxjbVxc6KvR2drXkkA4eIUunq3JgYK9
         EoAQMmiGifIoEVngSdwRdCsDrDiIk2ZtGOX2gxFsOqtUi4ORFgoHsTMp0m9/HBGEbnam
         OyCbBV291YYhJ0H550vVtS67C15lWmJd1gIXF4IEdyLcTYFVpZ7rBcDRinTBm5ujbtqN
         bZmA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=lk5a4NHg;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22c as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x22c.google.com (mail-oi1-x22c.google.com. [2607:f8b0:4864:20::22c])
        by gmr-mx.google.com with ESMTPS id b15si435409pfl.6.2021.09.13.10.58.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 13 Sep 2021 10:58:52 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22c as permitted sender) client-ip=2607:f8b0:4864:20::22c;
Received: by mail-oi1-x22c.google.com with SMTP id p2so15201286oif.1
        for <kasan-dev@googlegroups.com>; Mon, 13 Sep 2021 10:58:52 -0700 (PDT)
X-Received: by 2002:aca:4344:: with SMTP id q65mr8845158oia.70.1631555931531;
 Mon, 13 Sep 2021 10:58:51 -0700 (PDT)
MIME-Version: 1.0
References: <20210913112609.2651084-1-elver@google.com> <20210913112609.2651084-7-elver@google.com>
 <YT+EStsWldSp76HX@slm.duckdns.org>
In-Reply-To: <YT+EStsWldSp76HX@slm.duckdns.org>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 13 Sep 2021 19:58:39 +0200
Message-ID: <CANpmjNPA9qW8i=gHvrdMRag0kOrOJR-zCZe6tpucOB4XN8dfWQ@mail.gmail.com>
Subject: Re: [PATCH v2 6/6] workqueue, kasan: avoid alloc_pages() when
 recording stack
To: Tejun Heo <tj@kernel.org>
Cc: Andrew Morton <akpm@linux-foundation.org>, Shuah Khan <skhan@linuxfoundation.org>, 
	Lai Jiangshan <jiangshanlai@gmail.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Walter Wu <walter-zh.wu@mediatek.com>, 
	Sebastian Andrzej Siewior <bigeasy@linutronix.de>, Thomas Gleixner <tglx@linutronix.de>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vijayanand Jitta <vjitta@codeaurora.org>, 
	Vinayak Menon <vinmenon@codeaurora.org>, "Gustavo A. R. Silva" <gustavoars@kernel.org>, 
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, linux-mm@kvack.org, 
	Aleksandr Nogikh <nogikh@google.com>, Taras Madan <tarasmadan@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=lk5a4NHg;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22c as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Mon, 13 Sept 2021 at 19:03, Tejun Heo <tj@kernel.org> wrote:
>
> On Mon, Sep 13, 2021 at 01:26:09PM +0200, Marco Elver wrote:
> > While there is an increased risk of failing to insert the stack trace,
> > this is typically unlikely, especially if the same insertion had already
> > succeeded previously (stack depot hit). For frequent calls from the same
> > location, it therefore becomes extremely unlikely that
> > kasan_record_aux_stack_noalloc() fails.
> >
> > Link: https://lkml.kernel.org/r/20210902200134.25603-1-skhan@linuxfoundation.org
> > Reported-by: Shuah Khan <skhan@linuxfoundation.org>
> > Signed-off-by: Marco Elver <elver@google.com>
> > Tested-by: Shuah Khan <skhan@linuxfoundation.org>
> > Acked-by: Sebastian Andrzej Siewior <bigeasy@linutronix.de>
>
> Acked-by: Tejun Heo <tj@kernel.org>

Thanks!

> Please feel free to route with the rest of series or if you want me to take
> these through the wq tree, please let me know.

Usually KASAN & stackdepot patches go via the -mm tree. I hope the
1-line change to workqueue won't conflict with other changes pending
in the wq tree. Unless you or Andrew tells us otherwise, I assume
these will at some point appear in -mm.

Thanks,
-- Marco

> Thanks.
>
> --
> tejun

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNPA9qW8i%3DgHvrdMRag0kOrOJR-zCZe6tpucOB4XN8dfWQ%40mail.gmail.com.
