Return-Path: <kasan-dev+bncBCCMH5WKTMGRB2VXQKFAMGQEY2HDRZA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73c.google.com (mail-qk1-x73c.google.com [IPv6:2607:f8b0:4864:20::73c])
	by mail.lfdr.de (Postfix) with ESMTPS id 0EE0B40AE61
	for <lists+kasan-dev@lfdr.de>; Tue, 14 Sep 2021 14:56:12 +0200 (CEST)
Received: by mail-qk1-x73c.google.com with SMTP id t18-20020a05620a0b1200b003f8729fdd04sf46029973qkg.5
        for <lists+kasan-dev@lfdr.de>; Tue, 14 Sep 2021 05:56:12 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1631624171; cv=pass;
        d=google.com; s=arc-20160816;
        b=UPKFzufTTv4Q5kA0ixlfX7ZJnOSxv3YAIYOHKrLx0fWQrpGS1NCPmj821a4TvXB3Kj
         KiHNvtsgJKMKFntaC9IzC9NtybK2Ow8A+6D22ifnwK2+8IgxrC4sLJuvPDx21bPwR8Em
         sI2uTsWt4y9KIjNCH5TuW8cZynfgA+sH6y7/59php+msPvQEta5QHLUKqoEFsGnouTiH
         w52A9CUCkUUxv6Eh9z82wtus+qB4cFla1W16RCmO/DPrXQxjo0NP2XxlEn5QlFijRxsF
         uQBBIKy9zUEvIgmir4BB3IUoRMWw9sW7tduyemKpUdCi+si7jJEevKF1yN7q6auA+SqB
         5w/A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=y4Utb2FicmdD2Al3WDapOMGxRPOy/gbWcH1NqhZBEKc=;
        b=SZaz9l8QDgozIkSvpQXF++BYfKRmWuWsWsgH1up1NrMr7wAaRmgtbZfIcRXk75w8W2
         JGAHGVifWo8YsNfFbqpZtA+ZTHU/u8A3aIRSLPR5xd1Qp4hA4fi23v6U67u9qnb8Js6Q
         miuinbo65pQGZ+b7cldSdS9yteR/LYTRZmKiw+Bb9HIeyTx2f+R8Xilrjpcm+9YhgcYb
         B41PmXme0+giJWfJm/A7JVmP2OI6HXUhpkEuL1QasFwwKittYcYwph0Q9OiOUaPoS5A9
         8F2NFGfOyrrKP3Se6QyuwYSaZJVOtkgJcBiF3ifJKgI4bCu9x5uoO11KQlF26pnULDNq
         u4fA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=R7A0fnkx;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::836 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=y4Utb2FicmdD2Al3WDapOMGxRPOy/gbWcH1NqhZBEKc=;
        b=n2rg4P2AqnIET3JmoWhjIDoabaaDRJl0vKFjYAymkpbXgXt/OqFE1pYVtXl6psYDeo
         BoNpUKUqfd4v2taZqTCucGWnfalPBuqrmv5obllDg1fGedEmNlTXMCM3JyoPQCRiBerH
         0NX2lHHZ3qqdZ7g9IhXi5QKBWGkvPn1HvpnqsPkQQgHHMrTc7neym0n7dX73Q992rBKL
         dYLCjQnL0TRKoXQUHNsy0wAPNQP6zplfJgauir1X3XttH5eyNnOpKw9XBSqRiDIaU2py
         LqF3lrqI5BurD4VokftXxoySLtNEYAqCJzZNn7ei1QXFMyzy2cJr6UsqUdX3rwIVdxHO
         pc0w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=y4Utb2FicmdD2Al3WDapOMGxRPOy/gbWcH1NqhZBEKc=;
        b=l3cJGrEAmTG8+FUf1R3dsLWWKG8DU6Ygfs8jxR5fYVhjBU5iPVuCZI2gkyK+A7CEx/
         UpYm77rcOUIwKzcXh0zRspuTi3Ni411B0exvvTBXlH3yzxp0sGaWAPEzqSFO48sc88WK
         e7NORv1znn3RWLAYobrGNn0GgQsOMhOGHIoRdrJNl4iGxEdOxF2hvuCsDGxetRsX332a
         1KCxU4S48as0qalHDDx/BVyKZcWNv3CsHFm9OcOL0+Eggah3GjldvVXUeUboHK+tr1UG
         eSJJWmK03LGmW1UxbwTmpunFRwrbkhM7UIqSyMXbhkyjbJ7GgAAiGgDCXIo2Ba8oaZfz
         ahhA==
X-Gm-Message-State: AOAM532kyASmybHhQOHJGkCQrxKLcWwaaoMqz0R47E+3EvsGsilIX5/W
	gDzyyBhwCvQC7iVXGD1kN94=
X-Google-Smtp-Source: ABdhPJzb2Ep4Hux8nHuDjbBIGFvgjH/4i7Xoh8JlvII8zy9UEUmXfC3mGCg5njEp819UohqiJL24NA==
X-Received: by 2002:a05:6214:528:: with SMTP id x8mr5032729qvw.30.1631624170913;
        Tue, 14 Sep 2021 05:56:10 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0c:e411:: with SMTP id o17ls3543712qvl.10.gmail; Tue, 14
 Sep 2021 05:56:10 -0700 (PDT)
X-Received: by 2002:ad4:45c5:: with SMTP id v5mr5180932qvt.37.1631624170475;
        Tue, 14 Sep 2021 05:56:10 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1631624170; cv=none;
        d=google.com; s=arc-20160816;
        b=yznPltJPedl1xGJOn1m8HUo6GHSqs6jNN3u4DxRRihtJq7Z5TfGRZ4xXWKE3BvvHpE
         Gf3423w896HfXt2ovA5EDsCD/Ylbptw3Nmyw1yGimObnnd9AoY+UqVsmVm8CfFxT4edQ
         Hwhw01whuwo4wSO0gLvW4qJEKOdSv+pFsyClNeojhZC7QPAZ5HLAois/hjYg2s70Wkjy
         /wBrFg8c1F++VNSg4pE5WVxpa8mjxhW8JbN9G886rOdQP0Aq8ruz7SMnd9nfOWyWQe7n
         2DJ9RfQvwGb4C5iXDSCTx+9N0AUDIygvsL3TEXshPgdCRezgsoZ77su/ULSwTQ91jNBf
         9GAQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=473xgTZGiwHmobEJ6/SAUPmhRqqxJ35dz9Kf/VHgaaM=;
        b=cZx8JKyudPwo+MelDDSeZFgAcHXcc6pUdR20/+Ez7/YnoFN74hWS+yLSnLmYTuxrjx
         xuN8d3D/HoVRR1ZsqVaJWoxZiz7Yhhcz/0E+5F1fjecNIB4E+Vm0B+ovXRmn+SWM9+Sr
         2vdtuNT1n5aoS/dc4H2IhiaLwDz12872OTVa8ZyueEOUTxYZ8I1moLs1JLg09kLHQCvm
         o4pCdKqlAnFFfdvl7PhSWc0H2OKklTan17YFaaupTgNkWuW9qQMO9ctumHAQX32viqws
         TJHhvF0aSJmNuR0dFK6WhzCaciHxoSbrRzsS5rIiVaAQ90bYfm3LbfcSin0UQb/6J592
         pTZQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=R7A0fnkx;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::836 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x836.google.com (mail-qt1-x836.google.com. [2607:f8b0:4864:20::836])
        by gmr-mx.google.com with ESMTPS id n78si830410qkn.1.2021.09.14.05.56.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 14 Sep 2021 05:56:10 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::836 as permitted sender) client-ip=2607:f8b0:4864:20::836;
Received: by mail-qt1-x836.google.com with SMTP id m9so8413274qtk.4
        for <kasan-dev@googlegroups.com>; Tue, 14 Sep 2021 05:56:10 -0700 (PDT)
X-Received: by 2002:a05:622a:394:: with SMTP id j20mr4535974qtx.196.1631624169952;
 Tue, 14 Sep 2021 05:56:09 -0700 (PDT)
MIME-Version: 1.0
References: <20210907141307.1437816-1-elver@google.com>
In-Reply-To: <20210907141307.1437816-1-elver@google.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 14 Sep 2021 14:55:33 +0200
Message-ID: <CAG_fn=U1iSYXmd=Y7mnvAbp5wqu_D6m9VXR6ebJRRzN=VfJcxQ@mail.gmail.com>
Subject: Re: [PATCH 0/6] stackdepot, kasan, workqueue: Avoid expanding
 stackdepot slabs when holding raw_spin_lock
To: Marco Elver <elver@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Shuah Khan <skhan@linuxfoundation.org>, 
	Tejun Heo <tj@kernel.org>, Lai Jiangshan <jiangshanlai@gmail.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Walter Wu <walter-zh.wu@mediatek.com>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Vijayanand Jitta <vjitta@codeaurora.org>, Vinayak Menon <vinmenon@codeaurora.org>, 
	"Gustavo A. R. Silva" <gustavoars@kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	LKML <linux-kernel@vger.kernel.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, Aleksandr Nogikh <nogikh@google.com>, 
	Taras Madan <tarasmadan@google.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=R7A0fnkx;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::836 as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

On Tue, Sep 7, 2021 at 4:14 PM Marco Elver <elver@google.com> wrote:
>
> Shuah Khan reported [1]:
>
>  | When CONFIG_PROVE_RAW_LOCK_NESTING=3Dy and CONFIG_KASAN are enabled,
>  | kasan_record_aux_stack() runs into "BUG: Invalid wait context" when
>  | it tries to allocate memory attempting to acquire spinlock in page
>  | allocation code while holding workqueue pool raw_spinlock.
>  |
>  | There are several instances of this problem when block layer tries
>  | to __queue_work(). Call trace from one of these instances is below:
>  |
>  |     kblockd_mod_delayed_work_on()
>  |       mod_delayed_work_on()
>  |         __queue_delayed_work()
>  |           __queue_work() (rcu_read_lock, raw_spin_lock pool->lock held=
)
>  |             insert_work()
>  |               kasan_record_aux_stack()
>  |                 kasan_save_stack()
>  |                   stack_depot_save()
>  |                     alloc_pages()
>  |                       __alloc_pages()
>  |                         get_page_from_freelist()
>  |                           rm_queue()
>  |                             rm_queue_pcplist()
>  |                               local_lock_irqsave(&pagesets.lock, flags=
);
>  |                               [ BUG: Invalid wait context triggered ]
>
> [1] https://lkml.kernel.org/r/20210902200134.25603-1-skhan@linuxfoundatio=
n.org
>
> PROVE_RAW_LOCK_NESTING is pointing out that (on RT kernels) the locking
> rules are being violated. More generally, memory is being allocated from
> a non-preemptive context (raw_spin_lock'd c-s) where it is not allowed.
>
> To properly fix this, we must prevent stackdepot from replenishing its
> "stack slab" pool if memory allocations cannot be done in the current
> context: it's a bug to use either GFP_ATOMIC nor GFP_NOWAIT in certain
> non-preemptive contexts, including raw_spin_locks (see gfp.h and
> ab00db216c9c7).
>
> The only downside is that saving a stack trace may fail if: stackdepot
> runs out of space AND the same stack trace has not been recorded before.
> I expect this to be unlikely, and a simple experiment (boot the kernel)
> didn't result in any failure to record stack trace from insert_work().
>
> The series includes a few minor fixes to stackdepot that I noticed in
> preparing the series. It then introduces __stack_depot_save(), which
> exposes the option to force stackdepot to not allocate any memory.
> Finally, KASAN is changed to use the new stackdepot interface and
> provide kasan_record_aux_stack_noalloc(), which is then used by
> workqueue code.
>
> Marco Elver (6):
>   lib/stackdepot: include gfp.h
>   lib/stackdepot: remove unused function argument
>   lib/stackdepot: introduce __stack_depot_save()
>   kasan: common: provide can_alloc in kasan_save_stack()
>   kasan: generic: introduce kasan_record_aux_stack_noalloc()
>   workqueue, kasan: avoid alloc_pages() when recording stack

Acked-by: Alexander Potapenko <glider@google.com>

for the whole series.

>
>  include/linux/kasan.h      |  2 ++
>  include/linux/stackdepot.h |  6 +++++
>  kernel/workqueue.c         |  2 +-
>  lib/stackdepot.c           | 51 ++++++++++++++++++++++++++++++--------
>  mm/kasan/common.c          |  6 ++---
>  mm/kasan/generic.c         | 14 +++++++++--
>  mm/kasan/kasan.h           |  2 +-
>  7 files changed, 65 insertions(+), 18 deletions(-)
>
> --
> 2.33.0.153.gba50c8fa24-goog
>


--=20
Alexander Potapenko
Software Engineer

Google Germany GmbH
Erika-Mann-Stra=C3=9Fe, 33
80636 M=C3=BCnchen

Gesch=C3=A4ftsf=C3=BChrer: Paul Manicle, Halimah DeLaine Prado
Registergericht und -nummer: Hamburg, HRB 86891
Sitz der Gesellschaft: Hamburg

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DU1iSYXmd%3DY7mnvAbp5wqu_D6m9VXR6ebJRRzN%3DVfJcxQ%40mail.=
gmail.com.
