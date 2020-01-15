Return-Path: <kasan-dev+bncBDK3TPOVRULBBM5R73YAKGQEX3MEKZA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43a.google.com (mail-wr1-x43a.google.com [IPv6:2a00:1450:4864:20::43a])
	by mail.lfdr.de (Postfix) with ESMTPS id 280F013D05E
	for <lists+kasan-dev@lfdr.de>; Wed, 15 Jan 2020 23:56:52 +0100 (CET)
Received: by mail-wr1-x43a.google.com with SMTP id r2sf8488001wrp.7
        for <lists+kasan-dev@lfdr.de>; Wed, 15 Jan 2020 14:56:52 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1579129011; cv=pass;
        d=google.com; s=arc-20160816;
        b=FiMF2777wKo4HOmJcEeSd0PRJyjgGyAw6UUVYXDtdloHBXv3akTifpH1OnjKySw4iD
         8cwVQkiPCbooDMHa7ficg7l0o84lqPF08Ge8zKDI3CxmA2qQ/0KH8Pf4Ck9zf07E7aLI
         qXtxuDczjdgXvzWEBdrgZOV7U5NFcjOmvgq1+zSYTFXZH10ys2/8EJkF1Gy0CJPOhXG1
         Pts26kLyNexA/iwqtpyeal1ftPoRlxLSM6n37tYl8B/Ow37M9w48o5JPDp4lJ99N938M
         Frll8V7MfKQ/WDlLdV7A+NPyjJq6A8OWMEjy6kWgmU6luw6qf0A0U9eLIgk2kvu1Ve6o
         dAIw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=mHkhNnrCiK2xZbmQKqNc+I0gLw6mIIcaXhlL5TCS/98=;
        b=wgUX09JbiWs5IWfLWtUpGNRvQOslqIB85Tx1+o+KKhEUQMXX7SoMlznjTigeYJOfDe
         bBK9ZNbNXNK5E6+tVj2lClQuQXM9dzKbZXUBgJ7mz5xleKpB2za+3fonHRWrXzgGG26L
         hqJR1gKTmilixNd3LmHbkNGb6GMdGXO0+IyAsynmDOh6MIbxETQ+2vpG7NkHZ8QKezCX
         MGN8j5q2IRpU9hbi0/+L9GCaznzvP2p2cFeILo4BT596Ruw2htcvWJDVB37lSA1WQ6dW
         E73iXleqQHOpiQoga/7Ji5gYDalk6Im2HZNYQT4rPRqqBHbXd5E2EyfV3avrMgkQJhWW
         8Hlg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=axDANLEv;
       spf=pass (google.com: domain of trishalfonso@google.com designates 2a00:1450:4864:20::344 as permitted sender) smtp.mailfrom=trishalfonso@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=mHkhNnrCiK2xZbmQKqNc+I0gLw6mIIcaXhlL5TCS/98=;
        b=j2BlEGXw3GKGMEgmU/4fVpH3MufccaHzxzbH2RASOePtzc7+ly/5abBJQlmrOhs+iB
         tR2vTqT3VL2hpQSKS6PdXZzhXnV5+43MI0Z8+DIVDognd0Rs/WHZjK4pQVfvESTGN11o
         ioS1XnxSD/TAq5Pji6+40/VAB3EZnBqgY7VUWG19mIRlR6oYkqkgOfxQwpX44TpFyyYo
         th2VzZEsIDHfQeQzx/J/KyxETV9h2n+aJBafbRb3vRH/agQCYzEWZerY8CiWGDnfIl3x
         SHu8UwPlWvSApndd+XM3PSHOTD/Dk4bc1jyrb8sj1EEFhOQyJu/x1+HHwFfT+0Gc2Jd3
         9EhA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=mHkhNnrCiK2xZbmQKqNc+I0gLw6mIIcaXhlL5TCS/98=;
        b=uedAGYzOvy/gRWdWQwjg2ulX1yoMSmTzPS+WvolZRK3kYwd2ke443iibFzLP9XZHp7
         UJY5dK71PXc/CBf8a42yxxrQ3gqOp9LNutHXCEwtInnbUkJKTuJzCX0CxqLJpx8cytvh
         IhIqTNz42bnJS7P7UGy3Ndopa9LOrx91usATtJq9x4zVmtAGDL2RqbxTBG3hSyaDvxYg
         mhAxe4/PCreq0F1KEBIJ4Dg9cFy58Ycnh3oW5bUoZau9B0CP3cbhovkA8yDVtNcMlHAz
         v2nbIadZgdDe/7ZRmgv8IYeIHdgVa53oDJ38Cfy0rzkLOZm9uyE8Wh4USMxDzzzYtZ/L
         i7Fg==
X-Gm-Message-State: APjAAAV4Px2VUbjahzbplfm7epgFbpae2hcP+ziP1D95FNbbhEsjvDjt
	lj6LhsfnhSm9I/LQkYHv3yM=
X-Google-Smtp-Source: APXvYqyowzP8TY4hJEqNfIbl2LcfCG4D4CQSPCAo4yyHalX3owHtvT2oJJTOMfsn9QtKsg1uTTSItQ==
X-Received: by 2002:a7b:c183:: with SMTP id y3mr2402453wmi.45.1579129011816;
        Wed, 15 Jan 2020 14:56:51 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:6912:: with SMTP id t18ls7220290wru.7.gmail; Wed, 15 Jan
 2020 14:56:51 -0800 (PST)
X-Received: by 2002:a5d:4687:: with SMTP id u7mr33329456wrq.176.1579129011274;
        Wed, 15 Jan 2020 14:56:51 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1579129011; cv=none;
        d=google.com; s=arc-20160816;
        b=vQZMoBIIBjhY9fkqi2kyNn9Ra38yf7tq5u8UItKe7On6JcaNcvasMahUpTqVsVPWVb
         pa2Zb0TQl6UTUoiiFc+CtpUmfnN+IYW0reI/8nEeUqbMHRuF9z0zd5ZvSwacLfjfsbQY
         5MFrKlaMxqNCmesG727oSNQzpV+AxJpc8MD91kIOErJikovGl5e/dox28uhJgc7ah5hL
         Dl2VKLy517Ng6Ritnlq5B3RxH7YjTw7BNMedhzBuT7WM9ExhB7As7YJ5BewM6zDkI/OR
         IvSEVVDS7/+VrCj0l352nbVpQcogh2HMWb2PCXGQqyMiPLEDE9BzydWsy1Q0814WpKhZ
         adeQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=WOruGbo3ihqEelkLm7kTR9rgnvVG+704WzoO70mY5DI=;
        b=odH/dOq2ZL+JtPFKRu91M4Ocv6+fSpHSANJqSK3yxMIKzXOYVTdgApr2vY2OidVlAQ
         BOwOenwCQkb/9MDSQ08odqcQ4UnrmhWYe/89mdx75UGUulM8+PaszJ2c1W4yxV2ODTNG
         nTudM2OyR7l92Q6stLHVBwAt2azGSl4pEqxGsZdmknlUyJEdFJMxyeCkAG4o9/xSZDq4
         Cfl8BBAPt81Ydo0RZ+JbbyHnHzw3I4QfbRttYZ3IjujDASEpJlRr6juoqXlQQACkWbkv
         YkCsptoL7zyoZ6ZxNGL/liPs7N6UEM4JqpYf4objGL+i39aD1qXedVv+JzCAy5ugeDYl
         USsA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=axDANLEv;
       spf=pass (google.com: domain of trishalfonso@google.com designates 2a00:1450:4864:20::344 as permitted sender) smtp.mailfrom=trishalfonso@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x344.google.com (mail-wm1-x344.google.com. [2a00:1450:4864:20::344])
        by gmr-mx.google.com with ESMTPS id t131si52142wmb.1.2020.01.15.14.56.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 15 Jan 2020 14:56:51 -0800 (PST)
Received-SPF: pass (google.com: domain of trishalfonso@google.com designates 2a00:1450:4864:20::344 as permitted sender) client-ip=2a00:1450:4864:20::344;
Received: by mail-wm1-x344.google.com with SMTP id d139so5839640wmd.0
        for <kasan-dev@googlegroups.com>; Wed, 15 Jan 2020 14:56:51 -0800 (PST)
X-Received: by 2002:a1c:3d07:: with SMTP id k7mr2576689wma.79.1579129010626;
 Wed, 15 Jan 2020 14:56:50 -0800 (PST)
MIME-Version: 1.0
References: <20200115182816.33892-1-trishalfonso@google.com> <dce24e66d89940c8998ccc2916e57877ccc9f6ae.camel@sipsolutions.net>
In-Reply-To: <dce24e66d89940c8998ccc2916e57877ccc9f6ae.camel@sipsolutions.net>
From: "'Patricia Alfonso' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 15 Jan 2020 14:56:39 -0800
Message-ID: <CAKFsvU+sUdGC9TXK6vkg5ZM9=f7ePe7+rh29DO+kHDzFXacx2w@mail.gmail.com>
Subject: Re: [RFC PATCH] UML: add support for KASAN under x86_64
To: Johannes Berg <johannes@sipsolutions.net>
Cc: jdike@addtoit.com, richard@nod.at, anton.ivanov@cambridgegreys.com, 
	aryabinin@virtuozzo.com, dvyukov@google.com, David Gow <davidgow@google.com>, 
	Brendan Higgins <brendanhiggins@google.com>, linux-um@lists.infradead.org, 
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: trishalfonso@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=axDANLEv;       spf=pass
 (google.com: domain of trishalfonso@google.com designates 2a00:1450:4864:20::344
 as permitted sender) smtp.mailfrom=trishalfonso@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Patricia Alfonso <trishalfonso@google.com>
Reply-To: Patricia Alfonso <trishalfonso@google.com>
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

On Wed, Jan 15, 2020 at 10:48 AM Johannes Berg
<johannes@sipsolutions.net> wrote:
> Couple questions, if you don't mind.
>
> > +#ifdef CONFIG_X86_64
> > +#define KASAN_SHADOW_SIZE 0x100000000000UL
> > +#else
> > +#error "KASAN_SHADOW_SIZE is not defined in this sub-architecture"
> > +#endif
>
> Is it even possible today to compile ARCH=um on anything but x86_64? If
> yes, perhaps the above should be
>
>         select HAVE_ARCH_KASAN if X86_64
>
> or so? I assume KASAN itself has some dependencies though, but perhaps
> ARM 64-bit or POWERPC 64-bit could possibly run into this, if not X86
> 32-bit.
>

This seems like a good idea. I'll keep the #ifdef around
KASAN_SHADOW_SIZE, but add "select HAVE_ARCH_KASAN if X86_64" as well.
This will make extending it later easier.

> > +++ b/arch/um/kernel/skas/Makefile
> > @@ -5,6 +5,12 @@
> >
> >  obj-y := clone.o mmu.o process.o syscall.o uaccess.o
> >
> > +ifdef CONFIG_UML
> > +# Do not instrument until after start_uml() because KASAN is not
> > +# initialized yet
> > +KASAN_SANITIZE       := n
> > +endif
>
> Not sure I understand this, can anything in this file even get compiled
> without CONFIG_UML?
>

You are correct; this #ifdef was unnecessary. I will remove it. Thanks!

> > +++ b/kernel/Makefile
> > @@ -32,6 +32,12 @@ KCOV_INSTRUMENT_kcov.o := n
> >  KASAN_SANITIZE_kcov.o := n
> >  CFLAGS_kcov.o := $(call cc-option, -fno-conserve-stack -fno-stack-protector)
> >
> > +ifdef CONFIG_UML
> > +# Do not istrument kasan on panic because it can be called before KASAN
>
> typo there - 'instrument'
>

Thanks for catching that!

> > +++ b/lib/Makefile
> > @@ -17,6 +17,16 @@ KCOV_INSTRUMENT_list_debug.o := n
> >  KCOV_INSTRUMENT_debugobjects.o := n
> >  KCOV_INSTRUMENT_dynamic_debug.o := n
> >
> > +# Don't sanatize
>
> typo
>

Thanks for catching this, too!

> Very cool, I look forward to trying this out! :-)
>
> Thanks,
> johannes
>

Thank you so much for the comments!

Best,
Patricia


--

Patricia Alfonso
Software Engineer
trishalfonso@google.com

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAKFsvU%2BsUdGC9TXK6vkg5ZM9%3Df7ePe7%2Brh29DO%2BkHDzFXacx2w%40mail.gmail.com.
