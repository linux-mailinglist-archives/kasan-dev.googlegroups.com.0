Return-Path: <kasan-dev+bncBCMIZB7QWENRBVWFVL6QKGQELUMXRJI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd39.google.com (mail-io1-xd39.google.com [IPv6:2607:f8b0:4864:20::d39])
	by mail.lfdr.de (Postfix) with ESMTPS id 3C1622AD8B3
	for <lists+kasan-dev@lfdr.de>; Tue, 10 Nov 2020 15:25:28 +0100 (CET)
Received: by mail-io1-xd39.google.com with SMTP id o3sf8374539iou.10
        for <lists+kasan-dev@lfdr.de>; Tue, 10 Nov 2020 06:25:28 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605018327; cv=pass;
        d=google.com; s=arc-20160816;
        b=z8A97UsFWUqJm1IfcmDrWmKjfLVbhBAQEnQRx8swxz1TIndQpq7FubSphx0PZ3MbTg
         7h1OvgV8eOkuG61/sWflXZvNMPU5DcYDF5Q+lXFPET2OtJyCkE5G18RYZuzpRNZgvmOy
         0UrkotC80NqsU1aCl2fXSRL1z6oQ+63wgOjQk2Jot70qxh11hvsao/w67MY4dfCEyhCA
         ie9Bx4l9g2/zd8U8Q1gSyeZ610M2h3E1DJYCzzWzuRYDpgIZ9zB6Qi0s2EZTQgFm5XZk
         GoVtKSDniFtuONW2j1RLupx8poebDbI6WKZW9AGR9tTJRMgm8fxXa5a0IY8d7teZyTO4
         /sOw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=GdVe9pDqqv79hhwLr0M1UFsAsxzp5MzUlK3dkK/pQl8=;
        b=yAuat8B8APJwdPz5kX/8YOg25EWqC5tgWOk/x8k7DaSEge0SFhK1yWs2k8DwQtxMBC
         NG5ezgny0lfrFHNjmS6jPvYrnTENSHvoPkg9V8p/dxYumGCVZD22FuhvWxZxhCRD39oC
         6oEskOHx/+zTAqjCB9yszZredsKAv5z5uZE28gKccYyU+pBBBBY8HNd2HJKmY5lu13OC
         Fgjc+MQ+W/h/7pD6+ZuFR2bFFWuE8tU1ZPdZ9YqULzXKyOs6IHuTyADF1hJ4fppOXHPS
         ESJ3IMsvgtm9UzJ1m1DS3d3M4E+Z2T7OYgG/GB4GzoeyHPmykG3dlgtXhuzweQR8lDm/
         AJHg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=gsorfyCV;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::742 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=GdVe9pDqqv79hhwLr0M1UFsAsxzp5MzUlK3dkK/pQl8=;
        b=cV3evWCVCH3Sf/hM+0swuYjN2HUfCcSPEgX73Amgq9BOoE7A0GjO9b+p8M6TZKa91E
         0o6hUjcCIGozBTnSBc23pDnQpTdjDohh4/WQFklAP3YCNyD3RE4CwmrYRBVwmW37gHEA
         0oBU9XhqswGFNWFL0GspPfc4ZVAacuZNXnw85nSX96fSt5MIWxkDBe1HY/3iAiJwzBfd
         f0O7lf+LxD/wv0p5KCnj/kHciJDj66eXZtBRJsi9hEr6fdKT0TabcYu8fY73XEH2CNKB
         4YLo8HTp7cIO25nnyn1cqs4Jp8g5hUVRrHdR9TeIN3inkJeWMP2C0GjEdvetu4xyFX9g
         Fnig==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=GdVe9pDqqv79hhwLr0M1UFsAsxzp5MzUlK3dkK/pQl8=;
        b=SxQTfryvd2NoaMwNFL7mO9k8NQ44K8gRQWDc82FYkfU0dAm/iWN0CUNodoZqv70zR9
         lPujMrcBXOEp+WfP6IfMPje15c2l7YW6ZPYW91WnXLDwpLIA/kNx6UoNbhmE/jxGldf1
         CCU2WJ/ubjuKplhBjYwRgoFXyGMq0GgfKCB7A5YkY5t/1O4jsqn/LiuLA7Z3WMByKtED
         Vy+Em2JiXfx/kNoO/QSxRDevcABSUZjU6IA2zwkHMa0UtFq6r0/idecwwB9qqw3gAgCU
         ddYmnt2IO9wR/+46u/y7+eWOaIUxAu8XYP4MIncAIJvBSRRSIOB3U578shY6DKTaT6jp
         ahTg==
X-Gm-Message-State: AOAM533ihK6d1sBa1ClLlee9A35CYis5dbbYXIQTF6yhmxeC3544baxa
	m80k7GwS6lT8IvUZCHsOIQw=
X-Google-Smtp-Source: ABdhPJzVtJT7HVQTUPFStc0ACAAnlQRwe8B/53Y0CDloml8s8n54Hjx3qe/gj2V0u4BC6IN6zlD/ag==
X-Received: by 2002:a92:c7c7:: with SMTP id g7mr14030195ilk.303.1605018326853;
        Tue, 10 Nov 2020 06:25:26 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:5b47:: with SMTP id p68ls2613161ilb.5.gmail; Tue, 10 Nov
 2020 06:25:26 -0800 (PST)
X-Received: by 2002:a92:290b:: with SMTP id l11mr15187328ilg.46.1605018326385;
        Tue, 10 Nov 2020 06:25:26 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605018326; cv=none;
        d=google.com; s=arc-20160816;
        b=vL+vPQKDg+7UciLqNTDodKQjfR+t567emBqGMIpBvb7rRi0HiC0qy42tiB4Y0WD+0m
         PXoD3MSC54F/MAlQpa0fGdAynRXKtePlPli/Wfl3hpcyYrN3tKRnfXxS++32WkJxOrqH
         elthBIduHMmw8iGF43ObTDPESiPc+rx+SnboZ7GmfuGxJXSK8EYvJpsaVnfE3M8kgpkJ
         C/63eC9RFlt3DGG/KihW64Xk8TtdzNfHD4VemGYTEVJHz4CZuE5c7hMpQjOWJlsj+j+z
         U3epJL5pEyxRbty4VHJwzxL9vukgMnZy/bDs6Nn93DUMnp751AwL2qpssHDg36Ozj3BV
         HMXw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=AHqYsPMnh39efaowbWE1u8lOHSCxjgXUEGEjdD/sQII=;
        b=n4P9VFEktVxY6j5YUf/hZ+j798qabsThS54+EQE+uavO2oil+OwFMXXK/8q4KKswcE
         Owrsr3AN0L9LL/bgKOgDvJK9P6PMjKp4PTjWY3iyLmwFqBZncQxoTQsPS2b0znnQmByv
         WJGg8RJleZW9d6BBZvyPN41ghqmQQ5/I8aMxbmVkYdJcclvCzNRp2khB5izN0l/fLBQr
         Df5aNUVdf+qSIHJ4ymJaFwMQWwYsfJIeRwFa4xK4xdj9wv3hfWvekT8k7+AWFiwC7qdj
         xGt1o1vS37Irb14FSISzPq7B+dY+Lg3DNX+hUkis/Tpk+WX0uIYxdg+afxzCAXWehUD7
         yM0A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=gsorfyCV;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::742 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x742.google.com (mail-qk1-x742.google.com. [2607:f8b0:4864:20::742])
        by gmr-mx.google.com with ESMTPS id l1si732947ili.0.2020.11.10.06.25.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 10 Nov 2020 06:25:26 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::742 as permitted sender) client-ip=2607:f8b0:4864:20::742;
Received: by mail-qk1-x742.google.com with SMTP id y197so11527119qkb.7
        for <kasan-dev@googlegroups.com>; Tue, 10 Nov 2020 06:25:26 -0800 (PST)
X-Received: by 2002:a37:7b44:: with SMTP id w65mr20049707qkc.350.1605018325472;
 Tue, 10 Nov 2020 06:25:25 -0800 (PST)
MIME-Version: 1.0
References: <20201110135320.3309507-1-elver@google.com>
In-Reply-To: <20201110135320.3309507-1-elver@google.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 10 Nov 2020 15:25:13 +0100
Message-ID: <CACT4Y+Y_QarAf_cCNPgRZiSEKty0eSusA1ZMuY61LoGP1RaVtg@mail.gmail.com>
Subject: Re: [PATCH] kfence: Avoid stalling work queue task without allocations
To: Marco Elver <elver@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Alexander Potapenko <glider@google.com>, 
	Jann Horn <jannh@google.com>, Mark Rutland <mark.rutland@arm.com>, 
	LKML <linux-kernel@vger.kernel.org>, Linux-MM <linux-mm@kvack.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, Anders Roxell <anders.roxell@linaro.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=gsorfyCV;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::742
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

On Tue, Nov 10, 2020 at 2:53 PM Marco Elver <elver@google.com> wrote:
>
> To toggle the allocation gates, we set up a delayed work that calls
> toggle_allocation_gate(). Here we use wait_event() to await an
> allocation and subsequently disable the static branch again. However, if
> the kernel has stopped doing allocations entirely, we'd wait
> indefinitely, and stall the worker task. This may also result in the
> appropriate warnings if CONFIG_DETECT_HUNG_TASK=y.
>
> Therefore, introduce a 1 second timeout and use wait_event_timeout(). If
> the timeout is reached, the static branch is disabled and a new delayed
> work is scheduled to try setting up an allocation at a later time.
>
> Note that, this scenario is very unlikely during normal workloads once
> the kernel has booted and user space tasks are running. It can, however,
> happen during early boot after KFENCE has been enabled, when e.g.
> running tests that do not result in any allocations.
>
> Link: https://lkml.kernel.org/r/CADYN=9J0DQhizAGB0-jz4HOBBh+05kMBXb4c0cXMS7Qi5NAJiw@mail.gmail.com
> Reported-by: Anders Roxell <anders.roxell@linaro.org>
> Signed-off-by: Marco Elver <elver@google.com>
> ---
>  mm/kfence/core.c | 6 +++++-
>  1 file changed, 5 insertions(+), 1 deletion(-)
>
> diff --git a/mm/kfence/core.c b/mm/kfence/core.c
> index 9358f42a9a9e..933b197b8634 100644
> --- a/mm/kfence/core.c
> +++ b/mm/kfence/core.c
> @@ -592,7 +592,11 @@ static void toggle_allocation_gate(struct work_struct *work)
>         /* Enable static key, and await allocation to happen. */
>         atomic_set(&allocation_gate, 0);
>         static_branch_enable(&kfence_allocation_key);
> -       wait_event(allocation_wait, atomic_read(&allocation_gate) != 0);
> +       /*
> +        * Await an allocation. Timeout after 1 second, in case the kernel stops
> +        * doing allocations, to avoid stalling this worker task for too long.
> +        */
> +       wait_event_timeout(allocation_wait, atomic_read(&allocation_gate) != 0, HZ);

I wonder what happens if we get an allocation right when the timeout fires.
Consider, another task already went to the slow path and is about to
wake this task. This task wakes on timeout and subsequently enables
static branch again. Now we can have 2 tasks on the slow path that
both will wake this task. How will it be handled? Can it lead to some
warnings or something?

>         /* Disable static key and reset timer. */
>         static_branch_disable(&kfence_allocation_key);
> --
> 2.29.2.222.g5d2a92d10f8-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BY_QarAf_cCNPgRZiSEKty0eSusA1ZMuY61LoGP1RaVtg%40mail.gmail.com.
