Return-Path: <kasan-dev+bncBCMIZB7QWENRBBE46P4QKGQEDJH6SLY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x739.google.com (mail-qk1-x739.google.com [IPv6:2607:f8b0:4864:20::739])
	by mail.lfdr.de (Postfix) with ESMTPS id 6E85E2495E9
	for <lists+kasan-dev@lfdr.de>; Wed, 19 Aug 2020 09:00:21 +0200 (CEST)
Received: by mail-qk1-x739.google.com with SMTP id c191sf14881605qkb.4
        for <lists+kasan-dev@lfdr.de>; Wed, 19 Aug 2020 00:00:21 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1597820420; cv=pass;
        d=google.com; s=arc-20160816;
        b=SX3o0yi3jVu8EUpWFI06S4w7uMezrB/HDfPwblqAaLoMvFA8txMiTDzHug6EgdIxBz
         2m/Gibh1PORg9MPKxFGk/BPNMB0tEChP7Rl60b8NZ5RQpxGmjeXtGXqVjVk3mAoO//id
         U0Pova3qR5pzbu2kETdR4hM4wE37DU7gc+Eix3CIJFJ+ERFs8dvkeNXv/DOGg4Bk8+FK
         yjmuEz6dCCLvEh525qvCvzwnNeAr0WHYE/R0EYOXOMy8RsIzbDjIg5yiXAJZFzx4b5KX
         b1h/WVn2wsyR1MgLZWCyeCTToU4gnZfxD6FHM69j5WB7ZMU/bRjrPWaZaKbyETrEvhlL
         8oSQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:to:subject:message-id:date
         :from:in-reply-to:references:mime-version:dkim-signature;
        bh=LcQUjd5j4T0BwFv3YlISZ/jT1h34De0r8ExmCAS3wxY=;
        b=t4prj0aPpbJwqF+DMpeo8eCUAm95cebzvVDklZwPbDKeHxZZ9SnhyJvaqxBr/rJhd3
         jn4q1mDD7lhKbYovL+yIhe6jV5hRVNIOtiL/cjiAakEO+qQ7nKS7Ef1RKL65IiLXfssE
         QkGeB0VdQA25C9SV40bo7vDIQt01vXZacu+6phEplgkid5SA7DhxGXF5yW0FRct660Gc
         CFrvIr0vq5W1I2jAREeoW0jblU9B/LjNtHyC6BdfpZXs2Gu0jol87a/Ayl1uLhyzsQ3n
         +xNz5l4pofzTvyvnmPZ8Nnv9oPFQW+4Si61Oo669reXG5uRQ8mdm/Uwy9+qZDrE2CTtN
         9JlQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=blixeVYY;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::843 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=LcQUjd5j4T0BwFv3YlISZ/jT1h34De0r8ExmCAS3wxY=;
        b=S1SJ7xhHP/tbUFHHvSxoPq6d93dUkWZR6byb9AC24V2Oezo4XePSM5l9AtLK75ZMW0
         P853+LJmNA0TAwk1s41dEI/1KD3RITKix14iEdKnMdkXwh+uqZSH26PcHuVzQnCbT3nI
         9trpdzYAFzU7tn6b+mnCUcxEaI3H+Qr1FsST3zesgd5iEwN4888GA3ZuhNVj3OBGIily
         I0UliGkXf7GjwLbJc4Lp7/u+mxj1OQrlgB+oBfSnn9N0ylMveQZf2QjRp5V60kHoIDDB
         Mi6DqOatzmmueax09KEWowqxHQyMFsJE4Ob5sb9YsjfPnjy9QRt/ZLJNhfHhbMdo5gAP
         8ozw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=LcQUjd5j4T0BwFv3YlISZ/jT1h34De0r8ExmCAS3wxY=;
        b=Mk/VbUn1lXVYRb1MBk5tY9mZkSkOefCJ/NJEGUwjVhUm3B8QFbPlm2dfyTExS2/0Kl
         5Q8XCelLtcWTdLYS7CpHw7dnbnFCBMlNCXkzbIlFCEz/BjA03h2n2sanaheAT5dvp/45
         85JM7K0pIu6LnO2CaRdgz6SfxK746+DH6i9CoO/omfOgtwCxrdVGaaCHc+oXtEch3gow
         NGJPzRv/lL/3RwT3IWEDc8VosraEFlS02hemcRU19jy99nG8t3Sd6VtUV/YJZ9KZ8Vl+
         BkBOUnetj9nFGvkekfLLG9+XqbTnIZ5siaqG7wguu90jk/93qLb9EG2gNBGMhb2wp5uC
         JrJg==
X-Gm-Message-State: AOAM5308N3lbstsAGgNzsBXsw4koXSWJYUjGAGO5e+S3Vr4LaeXS4Ua7
	iSVJe88KRrG7MlMcrWFClx8=
X-Google-Smtp-Source: ABdhPJxlNS8I8EEQFZF/mHDpi9tOlekrLA0uDuzVnQzRzgGAGSWpIPz0+FDA1vU1gIZciQrr43O+zQ==
X-Received: by 2002:a37:9c7:: with SMTP id 190mr19243346qkj.303.1597820420435;
        Wed, 19 Aug 2020 00:00:20 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ae9:eb0d:: with SMTP id b13ls1823523qkg.7.gmail; Wed, 19 Aug
 2020 00:00:20 -0700 (PDT)
X-Received: by 2002:a05:620a:227:: with SMTP id u7mr20408253qkm.75.1597820420082;
        Wed, 19 Aug 2020 00:00:20 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1597820420; cv=none;
        d=google.com; s=arc-20160816;
        b=JmKhzS5qcSEjuscEZ51tWhQFSDCFKBxu42ZGuYWor6nkx2fAY3DAerqUFH8/8ncvhw
         dmsjvB8nM0rcBPGnCfh8a6lXDgysmh3xv5DyjULCjM2B0tbGPqFW1K1h3A8X6G9GEflx
         fxbyyWebNDUcCBPxW3pC0egtee2m87QvrRypDsjyKLvNIQTFaKSMacAWK2Tpdhgj8wom
         nq38lLpO9/SXsmvTY9SV6YMW2orN0b+pCYTQjdgrT6FBBjwnpTFEaoxw99QJ2k+vpMxd
         2OQjM1b99ibEvkLhUnwGZ3FciK4p1FgMGwGAbYs2LVy73rb72jw+D7jNetDoFZTe/NQp
         wBAw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=to:subject:message-id:date:from:in-reply-to:references:mime-version
         :dkim-signature;
        bh=qPu5SGYcDmZ3+fLZlHbHYMnHgihGI42zIfozScgTf1E=;
        b=ni7oKwovivGwYd3Ir6QS2iygN1Oju8T29QehyFffqx7SY4OpJGT6ah2hf9tNsCOkwO
         BaLgv7pZgEPwZODEM+V5MgdNqMdOhY3tMTquHoPSuoNileJdojeNqUm79/93S41s5ElZ
         5NKB29EYdNqDlR/g9CEB70RgVClGxuUJZzxzkn8vxb8+LyAQWCNTckGifMd+zY6aIdAh
         xyJ9amrYUTrrS3u6dEn8mMoNCUSSBVkJGUpVRiOixyfO2zRGwqtX+/NOgzhfiLgVBm4b
         Nxau3chFYcfWM7SlssWLxva6sJo2PapSPsReQBpnnIZyRwVvqlU94OAalXcl0s1pc/8x
         ldpQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=blixeVYY;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::843 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x843.google.com (mail-qt1-x843.google.com. [2607:f8b0:4864:20::843])
        by gmr-mx.google.com with ESMTPS id b1si1105491qto.3.2020.08.19.00.00.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 19 Aug 2020 00:00:20 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::843 as permitted sender) client-ip=2607:f8b0:4864:20::843;
Received: by mail-qt1-x843.google.com with SMTP id e5so17055358qth.5
        for <kasan-dev@googlegroups.com>; Wed, 19 Aug 2020 00:00:20 -0700 (PDT)
X-Received: by 2002:ac8:480c:: with SMTP id g12mr21057966qtq.257.1597820419581;
 Wed, 19 Aug 2020 00:00:19 -0700 (PDT)
MIME-Version: 1.0
References: <CAJSYYSUZFTWakvGWVuw+UYdMNs40zCSQt=mszp4H=on4YaZsnA@mail.gmail.com>
 <CACT4Y+bLNzbhkJi10v4pqffaRjTsPTwNe+RmB1cjgqSdbHbGaA@mail.gmail.com>
In-Reply-To: <CACT4Y+bLNzbhkJi10v4pqffaRjTsPTwNe+RmB1cjgqSdbHbGaA@mail.gmail.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 19 Aug 2020 09:00:08 +0200
Message-ID: <CACT4Y+b5owVygQ8PNMo8OziwfPyeCZKXT+p5kVcqDq6h8b6Z7g@mail.gmail.com>
Subject: Re: Hi ! I have a question regarding the CONFIG_KASAN option.
To: V4bel <yhajug0012@gmail.com>, kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=blixeVYY;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::843
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

On Wed, Aug 19, 2020 at 8:59 AM Dmitry Vyukov <dvyukov@google.com> wrote:
>
> On Tue, Aug 18, 2020 at 9:03 PM V4bel <yhajug0012@gmail.com> wrote:
> >
> > After downloading the 5.8 version of the Linux kernel source from
> > here, I checked the .config file after doing `make defconfig` and
> > found that there was no KASAN_CONFIG option.
> >
> > These were the only options associated with KASAN :
> > ---
> > 4524 CONFIG_HAVE_ARCH_KASAN=y
> > 4525 CONFIG_HAVE_ARCH_KASAN_VMALLOC=y
> > 4526 CONFIG_CC_HAS_KASAN_GENERIC=y
> > 4527 CONFIG_KASAN_STACK=1
> > 4528 # end of Memory Debugging
> > ---
> >
> > However, in the 5.5 version of the kernel, I noticed that the
> > CONFIG_KASAN option was present. How do I configure KASAN on a newer
> > kernel like version 5.8?
> >
> > I'm just a newbie to syzkaller. I hope this email doesn't offend you.
> >
> > Thank u.
>
> +kasan-dev mailing list

Hi,

Use 'make menuconfig' and search for "KASAN", it should be there.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2Bb5owVygQ8PNMo8OziwfPyeCZKXT%2Bp5kVcqDq6h8b6Z7g%40mail.gmail.com.
