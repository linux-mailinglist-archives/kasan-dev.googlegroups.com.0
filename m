Return-Path: <kasan-dev+bncBDE6RCFOWIARBO42WH4AKGQEMBWDLHQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x340.google.com (mail-wm1-x340.google.com [IPv6:2a00:1450:4864:20::340])
	by mail.lfdr.de (Postfix) with ESMTPS id 0A2F321D575
	for <lists+kasan-dev@lfdr.de>; Mon, 13 Jul 2020 14:02:04 +0200 (CEST)
Received: by mail-wm1-x340.google.com with SMTP id s134sf18401892wme.6
        for <lists+kasan-dev@lfdr.de>; Mon, 13 Jul 2020 05:02:04 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1594641723; cv=pass;
        d=google.com; s=arc-20160816;
        b=DDvuGd8qEKd/Jay1Z6ESI5bwrLzZucsxfDy0W7ujLVjH4Me77WSMxLLCh+kdHWS8EJ
         oyT78Oalqc57b81ZJl4FGLbjEtGM2Bdtpq+wlcvHHIt6VmBOrEy0pfiPijHRSDQwYQwX
         09cEXyPcjT45BC1JAYwGTL+1m4r71fC+PasaUwWxZ0p1ie1KBe7b/SIrpX9i/f2BTn3E
         Yr5RxvziwUKllRiQ+3VgxEv0yOzScFlPegIa2+Nh8PL0m52PtYI/aOGa0ArxzcQ2bCMc
         CQ+sWB3LQ6p9vwaNdoZrqR4GYFjiqZ7neJqbJ4Yc6tBooEk/V8EPoFBtFrk1YHtumETO
         4MZg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=h8LjFgbIdp1j34MU7Dy7+ysp6tWuN7nRYhK0UvK1NG0=;
        b=AwTJzbJH3qsSSGYttaHAq8tlypJMw0ja/ALKt7rDMaU0eHgjba7oX7ej6DVyhFsJtH
         6SIT1eYO2NudmDJqnfgBgUsol1VeETDfnBQbgJHo/jxIc8dcSoTq2i0rCQhDcNCY01MT
         P1WyESJnT0c2e0tCv/K/Z8HQrV6vSm66E+HBefDaGjnBotpYzgL57DUNAiskRX+RbqH3
         E4lSgVs+Z7x/uB4kOZ+QIVbIM5u40e/AJRcsrx/57jp13SgCfvh3Fw7iDOmn+CoixwxA
         WZ/jP5XNHNtwHStUgdgil7sMouxcvHeYK/DJTySrRHBjC9gx8/uaD276hX1hwYlmvzYc
         sipw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=AIWiWgsJ;
       spf=pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::242 as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=h8LjFgbIdp1j34MU7Dy7+ysp6tWuN7nRYhK0UvK1NG0=;
        b=ek53UzVtcTl9PG7Kms3RXE9AKckkYfVU1emmlaAdJrjO5QDGt6JEyBMsTWw9w0aaj1
         oX0QeebWLva1nH4ecbigyM32DKeZKS3u5qBsXxe5TGr0NLanWUMwsUwSuZBRBtiFRjxI
         5kCt9r/B7asLxzhWN5vxrGt2TzBSKXo/QsxxxvwHhGomIGAKq/WgRbgcs/LYPeSK0ixb
         IDkogXiqJg0Lg0BnFPis+J/8ILJ4OQhIRT3KDLrUN2mqboXM5a1IgCQHWgT7+UDJa6L/
         hdApVDIKBIuRe+2pjEiwJnQRHxf0yfOK16vTtvL1yXtsFCnn9vAnZuwOrD7EQrZmHOr/
         ieCQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=h8LjFgbIdp1j34MU7Dy7+ysp6tWuN7nRYhK0UvK1NG0=;
        b=HhceYEsBInJytYS9cv2ijI6WZ70p3QPmjwOUzwMNGV6/0vESz4QIlNF0fMNRSsbZkj
         mr9wRkaLhMgLvo3ulnZs/CCaSLcVJWdmvIl5ybBOKeQPdkcY0PTDoXtSMnVbJnZnmLDf
         e/gNP57lmwTdusgrKLe9v/HJvILdAz8er+7w1VxWxhjxobX0MRhhb8E+A7SpsKAPYOvy
         LR/HngC7MVuiFnXSgKpdLflwy62Vow3h5Y0xb9EFlEZTrKs6/ORef/5BYGDkBQXj1wjD
         UU8CaWZ9HM2dbUzKvAU2qWNnAaQ3e7ICUvaeXMlVs+mcHKueCdRPH/F2LZqxZhyYv5nL
         CI3Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533FTFz92TxEqTXG6RuDLoOyifbEe8bCkk1ajjr69ySDT0cV81qY
	z6ijYBGJcIhkbWNhP1LDaAo=
X-Google-Smtp-Source: ABdhPJwr5nx5O+vTppKdiE39W6a6YRjs2worzMe1RyBgUvTQZljAqJK8aWzPB6b4kpNGrS7sz2FZsg==
X-Received: by 2002:a1c:cc12:: with SMTP id h18mr19749446wmb.56.1594641723753;
        Mon, 13 Jul 2020 05:02:03 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:a587:: with SMTP id o129ls8380693wme.2.canary-gmail;
 Mon, 13 Jul 2020 05:02:03 -0700 (PDT)
X-Received: by 2002:a05:600c:2219:: with SMTP id z25mr19983075wml.154.1594641723325;
        Mon, 13 Jul 2020 05:02:03 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1594641723; cv=none;
        d=google.com; s=arc-20160816;
        b=pmBdkm2BNVBXCYsIbFlfq7KSdlzTxhpGJqFuT6uxkm36Z3YFTiGfh5bQoEycfbxLEM
         6BwfKRsjzTFoHK/fqka1vdKnq78aEPLI0vDbnA23QuaooG2ojET3FKlwAtqGJ/G37EUp
         i/HgB82YuJtldblby0rUqDCc59vSgv2KASzAiRyRoj/CT5FUKptjDM5JrjNzpW7ZOgUs
         GnchKqexX5zNt4A7uYtDZ3G9sqB/oSquVg155+FwP2+5Rn2sSraj6Ij41wG/qvikNe8t
         TcjhhzbCAqQcc24DRah5B/60Y17myJ2UORUQpONUxWOK81x7z0DH7E5floIAf254qxyV
         VBLQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=WGSvges6AdOOEs6ftlksvaUaKAGMEHxRCyTq1BEwdoE=;
        b=KuUaIwsjX4CH6SU/R4IZlvav/GyjIN/w8q+5bYsrIq4ao0Q1SSJfsDgRvY9OluvoIN
         14gYQQzPBivzv60qBkUdVJ8gH9NbKfknZhvu01Mfanj2eogUxHPAnX436V5c+U96xLTI
         vxz+AcGzrqW7t76D89+6w4SAeMUb7CVgF1KlFU+s81WeiS1p3WLli6hKwOrJlJesBo5g
         rpcvTY8IaWEhQAhPfzZxluODFOxY4JqhEr2uSMMY5NCmwiJsqf7Cm7ytt1iGDJX41PU0
         6oerdb3qCzFJyBdx3D1yEdhq41q0jV1ToIl+odaSBar9ow9W6Z/VXohVwTR75TK268Wv
         sBMg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=AIWiWgsJ;
       spf=pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::242 as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
Received: from mail-lj1-x242.google.com (mail-lj1-x242.google.com. [2a00:1450:4864:20::242])
        by gmr-mx.google.com with ESMTPS id u17si742968wrq.1.2020.07.13.05.02.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 13 Jul 2020 05:02:03 -0700 (PDT)
Received-SPF: pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::242 as permitted sender) client-ip=2a00:1450:4864:20::242;
Received: by mail-lj1-x242.google.com with SMTP id x9so7391452ljc.5
        for <kasan-dev@googlegroups.com>; Mon, 13 Jul 2020 05:02:03 -0700 (PDT)
X-Received: by 2002:a2e:810a:: with SMTP id d10mr42761900ljg.144.1594641722778;
 Mon, 13 Jul 2020 05:02:02 -0700 (PDT)
MIME-Version: 1.0
References: <f98a41c3-2748-4dff-970a-fd656c40e0fdo@googlegroups.com> <CAAeHK+w54UQCWupnO4P=eG9SjTPTUhN6f3GbYSV0X5jnBPDuoQ@mail.gmail.com>
In-Reply-To: <CAAeHK+w54UQCWupnO4P=eG9SjTPTUhN6f3GbYSV0X5jnBPDuoQ@mail.gmail.com>
From: Linus Walleij <linus.walleij@linaro.org>
Date: Mon, 13 Jul 2020 14:01:49 +0200
Message-ID: <CACRpkdbgAJmx0=Ly=a7Ec4xG8FypoyEDK4HRF4G5_OqVoSKOMg@mail.gmail.com>
Subject: Re: Porting kasan for arm v2 to kernel 4.14, appear crash on kasan_pte_populate
To: Andrey Konovalov <andreyknvl@google.com>
Cc: yan <hyouyan@126.com>, kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: linus.walleij@linaro.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linaro.org header.s=google header.b=AIWiWgsJ;       spf=pass
 (google.com: domain of linus.walleij@linaro.org designates
 2a00:1450:4864:20::242 as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
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

On Mon, Jul 13, 2020 at 1:13 PM Andrey Konovalov <andreyknvl@google.com> wrote:

> KASAN patches for ARM are currently on version v12 AFAICS, so try that
> instead of v2.

Yes it is here:
https://lore.kernel.org/linux-arm-kernel/20200706122447.696786-1-linus.walleij@linaro.org/

Please test this version and report back on the mailing list. I am hunting
some ghost crashes but currently my best assumption is that these happen
because the kernel image (+device tree and/or initramfs) grows so big
that they don't fit inside the first memory block, which is necessary
during boot. But I'm still debugging that.

Yours,
Linus Walleij

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACRpkdbgAJmx0%3DLy%3Da7Ec4xG8FypoyEDK4HRF4G5_OqVoSKOMg%40mail.gmail.com.
