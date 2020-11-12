Return-Path: <kasan-dev+bncBDX4HWEMTEBRBQM6W36QKGQESBOUGVA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe3e.google.com (mail-vs1-xe3e.google.com [IPv6:2607:f8b0:4864:20::e3e])
	by mail.lfdr.de (Postfix) with ESMTPS id C19E92B0E28
	for <lists+kasan-dev@lfdr.de>; Thu, 12 Nov 2020 20:38:42 +0100 (CET)
Received: by mail-vs1-xe3e.google.com with SMTP id j206sf2136637vsd.9
        for <lists+kasan-dev@lfdr.de>; Thu, 12 Nov 2020 11:38:42 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605209921; cv=pass;
        d=google.com; s=arc-20160816;
        b=k1D7YF3sa9IMZi1rDsh1gNOWe0M/JtJWTAXAb4EbbgUcRPD8s4ql5jOuAjIFwNzA2X
         F3uKkFIPvblBMfhATAiQVMDxjakfBUNOiW00/b8ZOkA7VRccqLFFBAwDcLglTImffYIm
         vf17NuJPsOF+zPwR2vJN6huYVvuO9DZHdGkSNCQg95w8dCTYTafJIlXb58nc9MqoFzos
         xETJKJKsExBGH3AOfyY8xQZJzhIDiufppAS4mXV9kzawIunNVK4geq29raCFb01T1eOT
         M71DDspNfBEAvHwiQNhaNUGt155EOqV8Nza+6Iq5eUNdRWWf8GQ85ncI00mpqXx5QYF1
         zxJw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=p3Wj1m2Kz54u41n7FFFvt5PynTUjGcvl/rli0jIaIPY=;
        b=UX8PXMbcnoWvp6wlAxrVqI5Fp0OmRdelVbcCpVRaNyhmCxZTPy17Im7teeB1emUaSg
         YumhHOybDvWZV4sIqhmGoe27uR5gIsqNIOB1PzUFZ4zq9lckO2MsiBZqsvFsF4FEHdK0
         7VsVL8oZwBu9nCdix+w7fyEohW0smRB9iXsEPNx4TWsPA9dBAhXBapMDhX3Yd/MKxMgx
         fu+58fKTkJijLu/dL8fXzplru2Tx7Fsqkyj6w0xBl0zY5OZlPcgXP05dQmvTYHwka6qB
         cH9qlpvBl6OA/JLuAm7r2Xa4nN5815jt20D9iWhYx5nUIed5iNDkzzaeH0aR42rz4DZo
         3+Fg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=UaHMcC73;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::644 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=p3Wj1m2Kz54u41n7FFFvt5PynTUjGcvl/rli0jIaIPY=;
        b=Q8sq3aVPVRxOryn/eY2DwkTxy6sttyBLx/a2DgENQM0ZB7se6T/iBAXwv83s0FjXcR
         wue1vdGZ73U2XZoWR336VnvmbVLnOJO7/2zDRLNyTsq87UyhYFnLLt83iGW0DN2RFsBN
         zsRNbMVoK1qfcNWvvJB4T2BuS4MSH6QMAMqJtR10IdRz1GHB3p1JZ6FkoK0kEEqhOkoJ
         qDjuA37LidMiROSlNCyse9hL2Sbj1UQh1Q0d1O9qVMZWLE7N0Zmo5Md0LQxjuJ9DPAqb
         GyOQMRZhkhgHxyu/h8pW3YySiYiKzEkPsrFcZp8mMjIYRl4uVS0kD5xV/cGVW7/cgic8
         mVIw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=p3Wj1m2Kz54u41n7FFFvt5PynTUjGcvl/rli0jIaIPY=;
        b=MAMTRAUS3idRFOb1kbmkX0boz5OMJPv5Z1Mk52Jcm4MxoIJi0k1d3klrFTANQOapVU
         O8su4zyi2e8XLuy02LXLti58s4YmnzhLCgaznNCXYumnsEs6kvhKLBtbg1z8jvpoX/Gc
         QoHeGqDUikbAhFYFdCxBt0CinJRGh2W9NDVCZE6Brz7P5ZzBhajvbcKVgPJo1mC1orFT
         OiMHMUYvCPcA8/DZ3GFv1QvWIIzlXa18qg9PCeBAV1T1Nz+STh6Czt2PusBpKrRwZboG
         fdEwt5jwyHPDvEwUqPIVRnI1ZuayuMcXdnk95wvdCT4vjifdTAbJpuK5sOrqfO52Rn2W
         lAzw==
X-Gm-Message-State: AOAM531kAYLEjmUKn6b7bJeV33QhhVNuxct5hkqeLMXnsMN9RaTxJg4k
	hKx36zVL0xowsp7L+rUTwzw=
X-Google-Smtp-Source: ABdhPJy9YYAe7V6vesoyX5FPJe4dCE2J0/9kX1y/zWBTF5zUWdnAoRY9Qa03Ev+V8fVIdzr02qiS2Q==
X-Received: by 2002:a67:fb52:: with SMTP id e18mr948918vsr.30.1605209921844;
        Thu, 12 Nov 2020 11:38:41 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ab0:649:: with SMTP id f67ls306317uaf.8.gmail; Thu, 12 Nov
 2020 11:38:41 -0800 (PST)
X-Received: by 2002:ab0:6355:: with SMTP id f21mr826533uap.142.1605209921325;
        Thu, 12 Nov 2020 11:38:41 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605209921; cv=none;
        d=google.com; s=arc-20160816;
        b=ifdxiSerq2qCOrVT/2tkMaMol4RLhamjP66/Q85yK3QcNWV72ucGeMbsH4I1nR1DbY
         v9HSKlgOZ8BCRgseveznzfbdPlINOCch5EJAUk5OeImn9Qz3pK/jc82tUJhIBNr3kpdy
         s/YKIY1cXahW/sKTzMwaY9V13Q92ct/zfyXVzkBGwA7ZTeiSYbM5MHpuwLfkkw6qXY/y
         dZ8xOrKGn+uTyzU9XLgeDR2dxH1lokThs8h4XujoRhxA3ddle0DZeACpg1Y4sDdXZAC7
         lYLGlc8/7X/B2H/1Em8XA22CplK9jn07tGVI6gWrCvcWh0ojJV1eNJR2KWPCJJtuNElw
         m1Bg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=wcGaGdNjvzbWsM/1VlFfBlGElmPXvO3Myj4l26gebaE=;
        b=eYGaBFR8q8ZAod78giHnrxw/Xe+ijbmM+cvOG3fREqx1RGhE77en4w/2ZPxm1jVqjd
         VCt+EFehW1cKYjeUY6330YMEcFecXKcVzYdK2YSgccJ9hhywkps8J51OVrziFh5wICGD
         foRkeonfdFKjGZXOz6cqNAgvgJMpYu1eKUCIZbzczfqpZQWlgzEHOvH/1F82HHW5n7tq
         kvN+L5dZxXnflwmYChcSqzWS1bIgH24BkxPUhO/0KeSiKN9xvKrkAC0qnT9dQDMOmsGR
         vW3Io31rtvBR/eZ6wT1S6Dmckimly6ak3goryScdOurrbjw7i0OKlECDJAYy6lIGoI22
         hByg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=UaHMcC73;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::644 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pl1-x644.google.com (mail-pl1-x644.google.com. [2607:f8b0:4864:20::644])
        by gmr-mx.google.com with ESMTPS id m17si410068vsk.0.2020.11.12.11.38.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 12 Nov 2020 11:38:41 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::644 as permitted sender) client-ip=2607:f8b0:4864:20::644;
Received: by mail-pl1-x644.google.com with SMTP id t18so3338167plo.0
        for <kasan-dev@googlegroups.com>; Thu, 12 Nov 2020 11:38:41 -0800 (PST)
X-Received: by 2002:a17:902:bb95:b029:d7:db34:2ddb with SMTP id
 m21-20020a170902bb95b02900d7db342ddbmr742376pls.85.1605209920187; Thu, 12 Nov
 2020 11:38:40 -0800 (PST)
MIME-Version: 1.0
References: <cover.1605046662.git.andreyknvl@google.com> <7e95d4739f5617b2c1acf52f37e01f1ca83750b5.1605046662.git.andreyknvl@google.com>
 <20201112095134.GI29613@gaia>
In-Reply-To: <20201112095134.GI29613@gaia>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 12 Nov 2020 20:38:29 +0100
Message-ID: <CAAeHK+wfzSjha_M88adfSE3qiOhJcCYeaAAu3YRXHpKqAK2L4Q@mail.gmail.com>
Subject: Re: [PATCH v2 04/20] kasan, arm64: unpoison stack only with CONFIG_KASAN_STACK
To: Catalin Marinas <catalin.marinas@arm.com>
Cc: Dmitry Vyukov <dvyukov@google.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Evgenii Stepanov <eugenis@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=UaHMcC73;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::644
 as permitted sender) smtp.mailfrom=andreyknvl@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

On Thu, Nov 12, 2020 at 10:51 AM Catalin Marinas
<catalin.marinas@arm.com> wrote:
>
> On Tue, Nov 10, 2020 at 11:20:08PM +0100, Andrey Konovalov wrote:
> > There's a config option CONFIG_KASAN_STACK that has to be enabled for
> > KASAN to use stack instrumentation and perform validity checks for
> > stack variables.
> >
> > There's no need to unpoison stack when CONFIG_KASAN_STACK is not enabled.
> > Only call kasan_unpoison_task_stack[_below]() when CONFIG_KASAN_STACK is
> > enabled.
> >
> > Note, that CONFIG_KASAN_STACK is an option that is currently always
> > defined when CONFIG_KASAN is enabled, and therefore has to be tested
> > with #if instead of #ifdef.
> >
> > Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> > Link: https://linux-review.googlesource.com/id/If8a891e9fe01ea543e00b576852685afec0887e3
> > ---
> >  arch/arm64/kernel/sleep.S        |  2 +-
> >  arch/x86/kernel/acpi/wakeup_64.S |  2 +-
> >  include/linux/kasan.h            | 10 ++++++----
> >  mm/kasan/common.c                |  2 ++
> >  4 files changed, 10 insertions(+), 6 deletions(-)
> >
> > diff --git a/arch/arm64/kernel/sleep.S b/arch/arm64/kernel/sleep.S
> > index ba40d57757d6..bdadfa56b40e 100644
> > --- a/arch/arm64/kernel/sleep.S
> > +++ b/arch/arm64/kernel/sleep.S
> > @@ -133,7 +133,7 @@ SYM_FUNC_START(_cpu_resume)
> >        */
> >       bl      cpu_do_resume
> >
> > -#ifdef CONFIG_KASAN
> > +#if defined(CONFIG_KASAN) && CONFIG_KASAN_STACK
> >       mov     x0, sp
> >       bl      kasan_unpoison_task_stack_below
> >  #endif
>
> I don't understand why CONFIG_KASAN_STACK is not a bool (do you plan to
> add more values to it?) but for arm64:

I don't remember if there's an actual reason. Perhaps this is
something that can be reworked later, but I don't want to get into
this in this series.

> Acked-by: Catalin Marinas <catalin.marinas@arm.com>

Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2BwfzSjha_M88adfSE3qiOhJcCYeaAAu3YRXHpKqAK2L4Q%40mail.gmail.com.
