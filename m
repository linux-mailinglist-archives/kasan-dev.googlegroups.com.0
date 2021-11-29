Return-Path: <kasan-dev+bncBCMIZB7QWENRBQHKSGGQMGQES6VSG2I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb40.google.com (mail-yb1-xb40.google.com [IPv6:2607:f8b0:4864:20::b40])
	by mail.lfdr.de (Postfix) with ESMTPS id 5CC2F460EC5
	for <lists+kasan-dev@lfdr.de>; Mon, 29 Nov 2021 07:37:53 +0100 (CET)
Received: by mail-yb1-xb40.google.com with SMTP id k6-20020a259846000000b005fee1fd7d3fsf12777550ybo.1
        for <lists+kasan-dev@lfdr.de>; Sun, 28 Nov 2021 22:37:53 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1638167872; cv=pass;
        d=google.com; s=arc-20160816;
        b=XYajcL8CjeyVkr1gN3/2L9/rBMDLxKjb/kYhh+wbrNjMXajxznjtrlyssHSCGY4K2R
         pcETM0SJ3WrBKcKwHhtwdJDtYxeobxVR/MIBiD4L9p6wIwgK/tRS8Ibcn5XxRUnpLc88
         eKjYUrlrfKaPzuX+EBgYwofTkmxuFldZmgjeRL+2QEeVrtzjGSpgCX/dLCa1P9pE4yy4
         nAUbbn8DofNfcCu+YfEUFDmn1vdSCx4lztXpfK0T9H87J9g5dmJiJ+xRc1ATxe1Fd9k2
         hE+UiT2Rtzabk5Vo5evybeRTNY0vzf00ys//VG7pfx/9Ahsd6/2fmIay2KLigbhlWjtu
         t4Zw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=kOjK1al6TdPAhmE57H1mhS7G25TQNR9/ceJN8X4luhA=;
        b=0W1J0caZdxrPr+ejvk0GLLgFvXM8A7mTvEDPdQFGeeC+F7L/AaBXRza7J6XKvGGI3w
         DzdNvDJ2iRmJ+hspxPGrbXXNI1RinAPzTrx4pswcoXw4X60FF7GwCj5hyACuGgqmIWfk
         /IlkqyOZ3hkq7hgI4GQ1sOBnttME3u4EYT+1UN3a4NN59EUzcaCcjRikFjKQp+l2zWqR
         pIhlz8gmCwJObJkOPjwOLOoSc2FW2dP7T11i3W69Lq7Z2wcYfkvS9kGig45DirxbJidN
         hx2KeTL11DjCec2h0ojJT3H6NsOrUUSOvccJJrO1h6C394/XNnMMpfYkYigsxUjc4dT1
         qjgg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=lR+kUz1M;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::c2d as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=kOjK1al6TdPAhmE57H1mhS7G25TQNR9/ceJN8X4luhA=;
        b=G5UyRMLoYLVvv9DiQvJ6gdeMyh3YpEn2L/KRFUsZ0s7Vqt8uVMFqEjY8CZEfkzdpSY
         y391ovpsgWpLEHkKkbwCvgUiQcCQl9InGOI1eKH9BzDhGGxRRrWHsELax92HxLWc4UVh
         rOzbeQwfzRf1tJC+JFzqhaG2u8l2yoZaldrEWf45pRP/8X3puL31nZh4Dw4kDiW6m+5I
         NKNiX640AN0N7OaWjOVQ7AYebyKy+Z3wSswBN4t2DpoJzynFOACAufyUhMi/XuejwqJG
         1pSB2nCGjIEOLpKmcJVCYfa+dFRJLTIov9S79XFBzyRnJ57aSl8SaWK/+eTVTgoPNbru
         jntA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=kOjK1al6TdPAhmE57H1mhS7G25TQNR9/ceJN8X4luhA=;
        b=zZRF0BjEFXLyZ6ykVjEyX5St0ZNoTVnJqE006SFK0hEuVBb+SeaRsm0Q6gM57J6NYO
         8/X3GOLLg4BNOAakX/UW9O6VwlghNGuuRdEXTOYa5rxpjdtzPCOCx/GVwtq/UQnb1kfo
         lDZx4h+zApXAZf2t72pzSFKcFmaJeXKEs7JPcpjnVGkRhL931THONLAxqshP302bKwPf
         YPVlQkk4cWMkh+pPuPO4Rd2vlG8Ozih34jYzlRUvShcyGrEOVeFPCnUOGDrZEMPpuIC0
         Z0Wh65kE/dkuBoL0SWaGlWJXoW7pSKw7pOx7eFTbYxFe6PZ+PBrAgtuaU6Wo6puHkHoJ
         N4KA==
X-Gm-Message-State: AOAM532n1/+EQEbmi++2KYDddeeBw5da2WcZPa6lPArL5OlG7y/vOZdl
	CMeWFLkjFx4X/8wUBiM1uxg=
X-Google-Smtp-Source: ABdhPJy462YZUKQm2xaBYw1Y8vgnQg2wMnWO6j9ZDTSfGFTC0ec/NpQZqfKvW4S7No+7fOr4pqDX1w==
X-Received: by 2002:a25:cdc7:: with SMTP id d190mr5308559ybf.758.1638167872295;
        Sun, 28 Nov 2021 22:37:52 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:3857:: with SMTP id f84ls7490142yba.10.gmail; Sun, 28
 Nov 2021 22:37:51 -0800 (PST)
X-Received: by 2002:a25:3786:: with SMTP id e128mr31975307yba.123.1638167871760;
        Sun, 28 Nov 2021 22:37:51 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1638167871; cv=none;
        d=google.com; s=arc-20160816;
        b=bN/6o6FrXM7snHNuEUbpMyefvEk+JbBxMCbL3RpdhgEmGzy2MUZPQdhFXgeAnv8//O
         BijGuFwp0uIoGOYH9Klu0L1l69LICi7Z7fgqcxl/l6qowE9BXi+QQojzPT2LeReJWf+2
         y127lMslpTWEr1xVERJGzxBxpzl8AVYFeKm9v4kPpmN1G6I6aNELu7tldFiDLARpT1CL
         Wadbj81R/PG9HeR26AUrD/MrSdI7C0L+c4VudZ19846WxpzE3g6GE/8QvHr+EX8h+ogx
         iCdrJQGZCLUYVarfCuLx6xVmW/rDf2DvdPQshNTpA0KsrwawndNfcOKIRXw3TszRACic
         T8ww==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=yfLJTrqi5jUZYQEwuSAUlCXF+OleODxB0oQPX3+rjPc=;
        b=C3VAktg7QZdh9ZztuEkR4ILTrHLlmcZ17pcaKKZjj5ZIsk2R1barQ9Gp1d1nFDdHl6
         B6NnS2VCV4XxxgoPCUo0HKsOFaqAS9EHkMGVlHAAJG0H9hb4k70mWXQQ4PsFdnstKjGA
         vCXxWEvuCgq1YHoln5VQRsoqr2EvnJQK9hJXIHK6Eo8w+kuOA8pI1/wPjXzQIEjRStjB
         zWwjRN7r2IP77hLcByRitDwtRVrN71PqmfYMmbglJixCwJBOpLAuLX4Cioe7pJEri1gA
         5KoeYqUuZ1XE6/PoSny1+R4WNgybKD0ALbwqzcZDR+v9BM6BzdNalW7jv8aqVm+R5wRa
         wo+w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=lR+kUz1M;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::c2d as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oo1-xc2d.google.com (mail-oo1-xc2d.google.com. [2607:f8b0:4864:20::c2d])
        by gmr-mx.google.com with ESMTPS id a38si184618ybi.4.2021.11.28.22.37.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 28 Nov 2021 22:37:51 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::c2d as permitted sender) client-ip=2607:f8b0:4864:20::c2d;
Received: by mail-oo1-xc2d.google.com with SMTP id w5-20020a4a2745000000b002c2649b8d5fso5393145oow.10
        for <kasan-dev@googlegroups.com>; Sun, 28 Nov 2021 22:37:51 -0800 (PST)
X-Received: by 2002:a4a:96f1:: with SMTP id t46mr30240912ooi.53.1638167871113;
 Sun, 28 Nov 2021 22:37:51 -0800 (PST)
MIME-Version: 1.0
References: <CANiq72kGS0JzFkuUS9oN2_HU9f_stm1gA8v79o2pUCb7bNSe0A@mail.gmail.com>
In-Reply-To: <CANiq72kGS0JzFkuUS9oN2_HU9f_stm1gA8v79o2pUCb7bNSe0A@mail.gmail.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 29 Nov 2021 07:37:39 +0100
Message-ID: <CACT4Y+Z7bD62SkYGQH2tXV0Zx2MFojYoZzA2R+4J-CrXa6siMw@mail.gmail.com>
Subject: Re: KASAN Arm: global-out-of-bounds in load_module
To: Miguel Ojeda <miguel.ojeda.sandonis@gmail.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>
Cc: kasan-dev <kasan-dev@googlegroups.com>, linux-kernel <linux-kernel@vger.kernel.org>, 
	Linus Walleij <linus.walleij@linaro.org>, Ard Biesheuvel <ardb@kernel.org>, 
	Florian Fainelli <f.fainelli@gmail.com>, Ahmad Fatoum <a.fatoum@pengutronix.de>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=lR+kUz1M;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::c2d
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

On Sun, 28 Nov 2021 at 01:43, Miguel Ojeda
<miguel.ojeda.sandonis@gmail.com> wrote:
>
> Hi KASAN / Arm folks,
>
> I noticed in our CI that inserting and removing a module, and then
> inserting it again, e.g.:
>
>     insmod bcm2835_thermal.ko
>     rmmod bcm2835_thermal.ko
>     insmod bcm2835_thermal.ko
>
> deterministically triggers the report below in v5.16-rc2. I also tried
> it on v5.12 to see if it was a recent thing, but same story.
>
> I could find this other report from May, which may be related:
> https://lore.kernel.org/lkml/20210510202653.gjvqsxacw3hcxfvr@pengutronix.de/
>
> Cheers,
> Miguel

HI Miguel,

0xf9 is redzone for global variables:
#define KASAN_GLOBAL_REDZONE    0xF9  /* redzone for global variable */

I would assume this is caused by not clearing shadow of unloaded
modules, so that the next module loaded hits these leftover redzones.

+arm mailing list and Linus W


> BUG: KASAN: global-out-of-bounds in load_module+0x1b98/0x33b0
> Write of size 16384 at addr bf000000 by task busybox/17
>
> CPU: 0 PID: 17 Comm: busybox Not tainted 5.15.0 #7
> Hardware name: Generic DT based system
> [<c010f968>] (unwind_backtrace) from [<c010c6f8>] (show_stack+0x10/0x14)
> [<c010c6f8>] (show_stack) from [<c0210734>]
> (print_address_description+0x58/0x384)
> [<c0210734>] (print_address_description) from [<c0210cc8>]
> (kasan_report+0x168/0x1fc)
> [<c0210cc8>] (kasan_report) from [<c0211230>] (kasan_check_range+0x260/0x2a8)
> [<c0211230>] (kasan_check_range) from [<c0211c68>] (memset+0x20/0x44)
> [<c0211c68>] (memset) from [<c019d21c>] (load_module+0x1b98/0x33b0)
> [<c019d21c>] (load_module) from [<c0199f88>] (sys_init_module+0x198/0x1ac)
> [<c0199f88>] (sys_init_module) from [<c0100060>] (ret_fast_syscall+0x0/0x48)
> Exception stack(0xc113ffa8 to 0xc113fff0)
> ffa0:                   00000000 00002a98 00098038 00002a98 00081483 00093f88
> ffc0: 00000000 00002a98 00000000 00000080 00000001 b66ffef0 00081483 000815c7
> ffe0: b66ffbd8 b66ffbc8 000207f5 00011cc2
>
>
> Memory state around the buggy address:
>  bf001200: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
>  bf001280: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
> >bf001300: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 f9 f9
>                                                      ^
>  bf001380: 00 00 07 f9 f9 f9 f9 f9 00 00 00 00 00 00 00 00
>  bf001400: 00 00 f9 f9 f9 f9 f9 f9 00 00 04 f9 f9 f9 f9 f9
>
> --
> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANiq72kGS0JzFkuUS9oN2_HU9f_stm1gA8v79o2pUCb7bNSe0A%40mail.gmail.com.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BZ7bD62SkYGQH2tXV0Zx2MFojYoZzA2R%2B4J-CrXa6siMw%40mail.gmail.com.
