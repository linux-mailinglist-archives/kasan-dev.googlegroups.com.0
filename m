Return-Path: <kasan-dev+bncBCMIZB7QWENRBYHMWD2AKGQETUI4VLY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x338.google.com (mail-ot1-x338.google.com [IPv6:2607:f8b0:4864:20::338])
	by mail.lfdr.de (Postfix) with ESMTPS id 75FFC1A0922
	for <lists+kasan-dev@lfdr.de>; Tue,  7 Apr 2020 10:14:26 +0200 (CEST)
Received: by mail-ot1-x338.google.com with SMTP id d59sf2025437otb.5
        for <lists+kasan-dev@lfdr.de>; Tue, 07 Apr 2020 01:14:26 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1586247265; cv=pass;
        d=google.com; s=arc-20160816;
        b=SzzkjcuWhYEdCqXqeRRWNN09KhPIOAGWKvyhyOi08CnesaJoE/poHVsGNzGF/Y+2Mw
         2mXaTVGQ/b7zouRT36rcqfOwF5YD9xgVyWjiWbdYcX4Zkkj/0op3bHc2vpWB601jCpfe
         NOIOghF3ncrWgk0FoajdJVgNbvh04FBPxA5RfM04AVsqQYPA5NYaxxiDLeIfqqpYdA7T
         k/iYBrNCUp1YGxDJEfOzq1+0d/qOY8w6uQVeG4sojmCiKLdoJf0HHe4cBYS/fhTa1isU
         Ah7RzdJU6/Mzyui8QYZTAoHYiByICZ2ml/we3SsGTXkP/IRdvHq3Mn0UK2MHhVjKqkWv
         qg7A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:to:subject:message-id:date
         :from:in-reply-to:references:mime-version:dkim-signature;
        bh=NYrIJUgUOyxPAcjKszeDJzCRu+pKwie6UOlOySmBeJA=;
        b=p8q1nD+Zs+aYMQTrZODu7UO1PmmIp7eHSxYfOB9oqnlMsN+FeyrA8rGd7nU3uLHU6F
         3Pbv77OKxqvzi289lI0zjsTswOEuS6GOrv+cWubH3sfdnOXUmiTUlntI/59FpQ792RBt
         MP3OhBh0n9LL5Yq9yXKOLr+PpVBFo2Jghb+5apntzpwWIjnL4h1GvPsv9M4bo5+yFLpD
         DPZi5XqtnYA7w1CURrnG9F+3BQlqxFrCoiYD0NYrPdQRSpF8Zj3uVA47fVIz2Spzv0k3
         ZO9d/tiYiHklsOBEiEp+5H7AItlOkdMc6jj7X1Gs67E7g0C8pdmfRsEQx+Whc5y+U9IT
         K+FA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=rRsVJsde;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::841 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=NYrIJUgUOyxPAcjKszeDJzCRu+pKwie6UOlOySmBeJA=;
        b=oAXu2S0EKyDK1Vua25dF68/ZT7X6LiSdj0FI7gEnQmsaI5XF1EcpubwFMUH7k+i4OZ
         ncxgamggFLCa+Z5oXEhTBo20gnvgF58TgnMEYDvzC9ry4+IvfK/7iPK6/xTdBiDaX28o
         AFVnSdybX8VjXjrmsjULGC01Cqyb94kXd0apbvq3wbUTn+3kUSODcuTtkECVcjOmVOv2
         jh8cfmci7DDfNoq+3IFfEEHtlQMK5DGGeHlgbmG9lKYK6W0QPQNS26B2mhRqReWYAsYr
         3BDfBXtVkXQnQulxT13Nq+k3M/f6vFJ0w7TAYk7jGzalqsVbYxoCn5RKNZQeGpo4UyEr
         S0Kg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=NYrIJUgUOyxPAcjKszeDJzCRu+pKwie6UOlOySmBeJA=;
        b=P3J7MhC3XYOsw9OjCqK3I1yo3qOiaSSaw504n2HF5xlDaz7oPnJFD3oTqFg+qJa7C1
         tUgxvlJhi9hI3mZAPMkpH4JGP+e6o3DBtNZmYooJWc0Ve2XOVor3uZH787W657uaneK+
         Fi1VNGkStfX4zQrTyluo537+m1ZcZNteaOlYQJYq74BqpMQRhCJ8YEePTSBUUzFmcBFt
         5Xcox1GGCffyPOf48ODt6neQDc48wYEKCFdhiWo6njurzft//CN7L7yLZ+FyckEtir52
         rYwwdfjNyhnzh01zBUIt2NhGEuJTEPSbQ9p7BklA+RheOmJTcTGbACi3+DAy/ZvqDwIZ
         ZKIg==
X-Gm-Message-State: AGi0PuY7Q1KVCCPYOASCMtNoCvvvUfeB8MYfmUzgtfRUanLU8WQsozfd
	NlcIfaayzJWlg7f43dL+ypY=
X-Google-Smtp-Source: APiQypK314R5QQ+BIXF2tMfNIYdFogrivdMxF3jwGDCMTmQRJL7Wc7g/KFVbklcpd6eVML2KIKMKZQ==
X-Received: by 2002:a4a:e495:: with SMTP id s21mr898880oov.79.1586247264963;
        Tue, 07 Apr 2020 01:14:24 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:817:: with SMTP id 23ls1120956oty.8.gmail; Tue, 07 Apr
 2020 01:14:24 -0700 (PDT)
X-Received: by 2002:a9d:3b6:: with SMTP id f51mr621730otf.255.1586247264591;
        Tue, 07 Apr 2020 01:14:24 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1586247264; cv=none;
        d=google.com; s=arc-20160816;
        b=LhfXruNG1/kgL7xMCOOONpyz4Ga18QFMTfjSN8egH/cFY/ybx76rll2nKRbQYYvi4o
         2W/57mzzJoC1UlDM5Pw6/tQjys1sHWuHSubLF26wmn0lttghVgjX8u5hk8AE4ol5gQB8
         kFhC6PWyruQdPg6xlP0n8wv2Buho83INc6vh7JE8X4pEFEnI2KwGPXSb3ZiVHMyJBkib
         KajMm6Ut8hpQkTLRP3nqhuo70tRthAubVNDeZ3AZnKIb7sV21OIrQ4cD73sKPsiwbPJo
         Bc0xqZfOfwgZ+i/mRFe18QiXNmLljmYUt1oj90ZlPdwdrpsvbwW3oswG1qyLY8R5tjFD
         mpGg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=to:subject:message-id:date:from:in-reply-to:references:mime-version
         :dkim-signature;
        bh=lLyU5UYsmuBWEtlppCHl64/wkJhI54yj4kiiCV3tQps=;
        b=WKbttZcQXrdqtk9cVeoYZGXKqkKSxh0wXhO7vVCY/coV8my+Fl0d/S7GjGjvYkReTa
         aOKoggbcGsohpT3ihn2SZCyTlDCd2LHCtMHMZhC126ZXAC1hUOoB20EMdb+glpHUkQFY
         wR8vyNiSm2Bi9FgOmAg/6Xx0eB7NF4S6wkBSjr1NtkmM+xZ464LoL67uv8aG6cScKC3V
         XTjmyJEILZkyH0aAci60q9cns+hRPu0a+uHeGslvdHvqt/f55tIZrED3cl/PVTG+cEYe
         xvSazhOlYC+SIwbjmTxzUzAMKdOW9aEHIwZav9TWuCm5bYPU8KBogwP46whHBiwi0/dq
         0M6g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=rRsVJsde;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::841 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x841.google.com (mail-qt1-x841.google.com. [2607:f8b0:4864:20::841])
        by gmr-mx.google.com with ESMTPS id e21si174868oob.1.2020.04.07.01.14.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 07 Apr 2020 01:14:24 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::841 as permitted sender) client-ip=2607:f8b0:4864:20::841;
Received: by mail-qt1-x841.google.com with SMTP id 71so1992505qtc.12
        for <kasan-dev@googlegroups.com>; Tue, 07 Apr 2020 01:14:24 -0700 (PDT)
X-Received: by 2002:ac8:719a:: with SMTP id w26mr1068058qto.257.1586247263929;
 Tue, 07 Apr 2020 01:14:23 -0700 (PDT)
MIME-Version: 1.0
References: <78d7f888-7960-433f-9807-d703e57002bf@googlegroups.com>
In-Reply-To: <78d7f888-7960-433f-9807-d703e57002bf@googlegroups.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 7 Apr 2020 10:14:12 +0200
Message-ID: <CACT4Y+ZvX1Cs1SJppVfLXyV9F4hra=JdBaQCqBTeFX3++f48kQ@mail.gmail.com>
Subject: Re: [libfuzzer] Linker fails on finding Symbols on (Samsung) Android
 Kernel Build
To: jrw <ickyphuz@gmail.com>, kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=rRsVJsde;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::841
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

On Mon, Apr 6, 2020 at 10:48 PM jrw <ickyphuz@gmail.com> wrote:
>
> HI,
>
> i try to build a Samsung Kernel with KASAN enabled but have problems getting it compiled.
> how would you proceed from there to make it a successfull build?
> I tried several cross compilers but i always end up with the same errors.
>
> -------------------cut-------------------------------------
> /home/kerneldev/kernel/net/core/rtnetlink.c:2557: undefined reference to `__asan_alloca_poison'
> /home/kerneldev/kernel/net/core/rtnetlink.c:2558: undefined reference to `__asan_alloca_poison'
> /home/kerneldev/kernel/net/core/rtnetlink.c:2745: undefined reference to `__asan_allocas_unpoison'
> /home/kerneldev/kernel/net/core/rtnetlink.c:2745: undefined reference to `__asan_allocas_unpoison'
> /home/kerneldev/kernel/net/core/rtnetlink.c:2746: undefined reference to `__asan_allocas_unpoison'
> net/netfilter/nfnetlink.o: In function `nfnetlink_rcv_msg':
> /home/kerneldev/kernel/net/netfilter/nfnetlink.c:190: undefined reference to `__asan_alloca_poison'
> /home/kerneldev/kernel/net/netfilter/nfnetlink.c:224: undefined reference to `__asan_allocas_unpoison'
> /home/kerneldev/kernel/net/netfilter/nfnetlink.c:224: undefined reference to `__asan_allocas_unpoison'
> /home/kerneldev/kernel/net/netfilter/nfnetlink.c:225: undefined reference to `__asan_allocas_unpoison'
> net/netfilter/nfnetlink.o: In function `nfnetlink_rcv_batch':
> /home/kerneldev/kernel/net/netfilter/nfnetlink.c:407: undefined reference to `__asan_allocas_unpoison'
> /home/kerneldev/kernel/net/netfilter/nfnetlink.c:384: undefined reference to `__asan_alloca_poison'
> /home/kerneldev/kernel/net/netfilter/nfnetlink.c:454: undefined reference to `__asan_allocas_unpoison'
> net/bluetooth/smp.o: In function `aes_cmac':
> /home/kerneldev/kernel/net/bluetooth/smp.c:175: undefined reference to `__asan_alloca_poison'
> /home/kerneldev/kernel/net/bluetooth/smp.c:214: undefined reference to `__asan_allocas_unpoison'
> /home/kerneldev/kernel/net/bluetooth/smp.c:214: undefined reference to `__asan_allocas_unpoison'
> net/wireless/nl80211.o: In function `nl80211_send_wiphy':
> /home/kerneldev/kernel/net/wireless/nl80211.c:1914: undefined reference to `__asan_set_shadow_00'
> -------------------cut-------------------------------------
>
> the only thing i could find was a stackoverflow post [1] but this guy also had no solution to the problem.
>
>
> [1] https://stackoverflow.com/questions/58717275/compiling-aosp-kernel-with-kasan
>
>
> Thanks for any help!

+kasan-dev  BCC:libfuzzer

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BZvX1Cs1SJppVfLXyV9F4hra%3DJdBaQCqBTeFX3%2B%2Bf48kQ%40mail.gmail.com.
