Return-Path: <kasan-dev+bncBCCMH5WKTMGRBOW5VL6QKGQEURVW44A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3a.google.com (mail-yb1-xb3a.google.com [IPv6:2607:f8b0:4864:20::b3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 4A8092ADA11
	for <lists+kasan-dev@lfdr.de>; Tue, 10 Nov 2020 16:16:11 +0100 (CET)
Received: by mail-yb1-xb3a.google.com with SMTP id u11sf15199582ybh.6
        for <lists+kasan-dev@lfdr.de>; Tue, 10 Nov 2020 07:16:11 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605021370; cv=pass;
        d=google.com; s=arc-20160816;
        b=jsbNEbFwFOvxSUyJlwihgUJCwE3XDEkvASqpPJC7gFpoJZCz6AKrq1oZw+fiCgYvHo
         uNo779rboYMxg47HAIUzw7z7CXki+DVi2rPxl6Hh/VZamLGFosPvz9jw+pzxTAA5nhor
         3PTGf0nXouYNvdIGniO/8KwB0Is8xzw9dxRydA7dCqWKs32j9PNcDjhV+bOuFZ7FJTsC
         L9/LFdmwVZW1iKmAyPwTuOb/I2WfARm6W2bAQsvO7B0NFmzLQixfbG9oEY74FYwY+kdu
         pJNtlqDQmf21RLTGwl+OzI6XDsYR/gD481KnzORNWZmnb4CE4tdn0XMxjoux5PC05MwL
         VIpg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=fIu9et/6pQXDPZPDUmsE63DNwdvAJPaqhzd83yAoZSQ=;
        b=Mt4EEVQ0yNVe5F4dOSgCOiWs1Do33bE6UjT7JrT0ExMcJ81DGGYKaQ/J7nVwxeiW0u
         YTFispPXeN7I51YB3g+CrJaRdPNP74+sgG0kosQ3XGl9H7n5Hr8AhcDd0MnNCDPhPVMG
         UXioiQCWfkqKfuo/MnbcEfrBbD0T0AkI8VFlbyPd5xGL8PJdaS9YsZzkoKNmXzwWSL9G
         fHEFM+hjfIguieM4F7QmiMLmpc3IGV/2D1mc52fT1ogTHEM0QQBUQ3JvqwHNavYqZvsr
         KHeDDAvjkjsr+9vfUP4RqzPnMz00nMr79CvCcpWjZ2+gcch5K4N2p3jjEIvbjLlxANm7
         3y1g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=eLw9cJt7;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::72a as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=fIu9et/6pQXDPZPDUmsE63DNwdvAJPaqhzd83yAoZSQ=;
        b=b3HHesDbRGNBraE/Xxf3hGObUr3Fa0QewBFnDw7CmzjPSXT00bVjQ6s51+FbrK59SI
         ysaOcx9oUXEKIlUmWT7N71MBJhSXdXLqaNdvY0tGl7CZw3bYvh31VpHsQRxNv/KGU6e9
         UlKKLrE9CBfcqd1GL1U6DyHGFSsSS2U4wkbYmt6iOHCgCJUxeMJgtrJPR6HICcNhdVUc
         tw1A/ekC1aAir4+gN40AbKt3yPXoNY4mxO9yJVdZ5rjnwLg/YhBLVur55d4FHrvZfBA0
         Ams0/xy2s9j7yCwa7/0ix0r6PcCuMZtV5NSp0my87J2HRbN1gYS0hnN/qtREgGKb9ZJa
         neNw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=fIu9et/6pQXDPZPDUmsE63DNwdvAJPaqhzd83yAoZSQ=;
        b=oP4xhHUt5wOllYOadSDy/hA5gpCCuLmENjrN/21KGNTRW27mC74hEcOnQ0+l59+DqO
         mmCapPw05mjrgT2OJfmOxp68M8MXHSkC8yaWyc6VCG+sE28lBHJMaT2StNwbseGPS/di
         Q0KNFfLAcNzbJLNwluhmhByij8JQZ45s3YTGm9B+45dtS2tYX6h87IxJ9z3wdYK107Mx
         W2qHZePWDYFOog3kHa+7F4neIvouLVnrdnwWpj2S7XuWFZN/lm5crMIRhYWe9VV7L63f
         WFTsx4FY4GyzRXslc2683n/S0sjNIpn1DnTInLYgg4J4fedg8KTtnNMObxXxQYgiOKxg
         352w==
X-Gm-Message-State: AOAM533fKY0eQEVsX0fenE5ps09leIPwhbnDrrBdh2Hh8vjHlIB5rHuN
	QeN3fh2rmEQM4Ntvo2/2nq4=
X-Google-Smtp-Source: ABdhPJxk5MVqRFYrCuCGEGSRMCl5eXJ6bWGJIk844CToSr9fAxtj2qhtrrSn5u+nwfB3gaHIPqEdpA==
X-Received: by 2002:a25:5884:: with SMTP id m126mr3975487ybb.342.1605021370312;
        Tue, 10 Nov 2020 07:16:10 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5b:e81:: with SMTP id z1ls6292976ybr.11.gmail; Tue, 10 Nov
 2020 07:16:09 -0800 (PST)
X-Received: by 2002:a25:4c1:: with SMTP id 184mr26928817ybe.318.1605021369826;
        Tue, 10 Nov 2020 07:16:09 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605021369; cv=none;
        d=google.com; s=arc-20160816;
        b=NDgRxJnD/dgn2EmyGwDpZuxZ3MAy8pcQ6AuKrU/b9uhC8IgybrrUGKs/62OKnInjiU
         tlXluOGWYwC5KbFlge6tefgtgZRJD18AL0xYsWSnVr8jQAAMSeKvkAN/crsMHk21rZMg
         C/Mu6mBKQNIPXWglSghrd0bKYUG2e9U3tspv6UJiKU5aIQwAcQ9YXpDs8sqXBVSob6A9
         906LfVD6vSwhQTymGwVU/7r6ZPSGz+xnQ+qk+eN6sdZnBaurslK/mGP6XWnrq4TBO/vw
         YEXPUCf6lKoCc/aIzySIe9HsV7w9F2zdY+s1S9i+aIUs7dOFCLbLemSnOVE/+7kep1/D
         ibgw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=m3w0iKuaSU+bw/4jtkiKanEyHOAhJwCjWL6TZAF1pOw=;
        b=JpgjUXFK8JVXxQMCo6/CsjymmD6VVLGos34xJoo6GxUKKuG9fFL2PkUsH8N0A/fmKv
         0yU0j/s/fg2rigLD3RzFsqJ2gB4NOfZmfHSajZECFn2n6Kli7XfmqayULC3LZdawzMc/
         +DjzWenUNx9p+rWef3qSbzyXMbdlPPJULJwslB59o5CTnD1OdF4f+dPcmLcvhYK61tOo
         rs33onjL8chQwsS3FKD6QVkyLrxy8E2fjjEi98FJFB3wS7YuV/g4XEfVMOxn+SMTDV3h
         OJWTHJf6lfuxbZfHRyWTVThIu6lH0wbkV27ADgVZg5TCKjyR9lmnR5zGYSUUgok4v1ky
         pjAg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=eLw9cJt7;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::72a as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x72a.google.com (mail-qk1-x72a.google.com. [2607:f8b0:4864:20::72a])
        by gmr-mx.google.com with ESMTPS id y4si1025898ybr.2.2020.11.10.07.16.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 10 Nov 2020 07:16:09 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::72a as permitted sender) client-ip=2607:f8b0:4864:20::72a;
Received: by mail-qk1-x72a.google.com with SMTP id v143so7190259qkb.2
        for <kasan-dev@googlegroups.com>; Tue, 10 Nov 2020 07:16:09 -0800 (PST)
X-Received: by 2002:a37:bf04:: with SMTP id p4mr20656077qkf.326.1605021369283;
 Tue, 10 Nov 2020 07:16:09 -0800 (PST)
MIME-Version: 1.0
References: <34d79b2a-1342-4d5e-8ebc-8c4fd5945f2cn@googlegroups.com> <CACT4Y+a=MGJSkzWOvCSyK1p5JaHkU7RWABOJj=SMrD+DJacieg@mail.gmail.com>
In-Reply-To: <CACT4Y+a=MGJSkzWOvCSyK1p5JaHkU7RWABOJj=SMrD+DJacieg@mail.gmail.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 10 Nov 2020 16:15:57 +0100
Message-ID: <CAG_fn=XpZOpKoKYO5xVuAFGPGLfrEpOWaR0VtQfmXRexNFsfNQ@mail.gmail.com>
Subject: Re: Continuous KMSAN reports during booting hinders PoC testing
To: Dmitry Vyukov <dvyukov@google.com>
Cc: "mudongl...@gmail.com" <mudongliangabcd@gmail.com>, kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=eLw9cJt7;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::72a as
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

Hi Dongliang,

Am I understanding right that you were running KMSAN locally?
Which version were you using for your tests? Note that there've been a
couple of rebases lately, so things might have changed.

These reports are happening while unwinding the stacks, which KMSAN
does every now and then.
I am pretty sure however, that I taught the tool to ignore such
reports (they make no sense, as stack walking always involves touching
uninitialized data on the stack).
So I'd be glad to hear more about the reproduction steps for this
issue (KMSAN version, kernel config, Clang version, QEMU boot
parameters)
I tried building KMSAN with the latest config for the crash you've
mentioned, and it booted cleanly.

Alex

On Tue, Nov 10, 2020 at 3:30 PM Dmitry Vyukov <dvyukov@google.com> wrote:
>
> On Tue, Nov 10, 2020 at 11:59 AM mudongl...@gmail.com
> <mudongliangabcd@gmail.com> wrote:
> >
> > Hi all,
> >
> > when I tried to reproduce the crash(https://syzkaller.appspot.com/bug?i=
d=3D3fc6579f907ab3449adb030e8dc65fafdb8e09e4), I found an annoying thing du=
ring booting of KMSAN-instrumented kernel image - KMSAN keeps reporting sev=
eral uninit-value issues. The issues are in the following:
> >
> > BUG: KMSAN: uninit-value in unwind_next_frame+0x519/0xf50
> > BUG: KMSAN: uninit-value in update_stack_state+0xac7/0xae0
> > BUG: KMSAN: uninit-value in __kernel_text_address+0x1b0/0x330
> > BUG: KMSAN: uninit-value in arch_stack_walk+0x374/0x3e0
> > ...
> >
> > Even after 20 minutes running, the messages are still printing and QEMU=
 is not ready. I wonder if these messages are false positives or not. And h=
ow could I successfully enter the VM and test the provided PoC?
> >
> > Best regards,
> > Dongliang Mu
>
> +kasan-dev
> does not seem to be related to syzkaller (to bcc)



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
kasan-dev/CAG_fn%3DXpZOpKoKYO5xVuAFGPGLfrEpOWaR0VtQfmXRexNFsfNQ%40mail.gmai=
l.com.
