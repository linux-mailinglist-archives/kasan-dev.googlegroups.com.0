Return-Path: <kasan-dev+bncBCMIZB7QWENRBANLSSAQMGQECVNTMCQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43e.google.com (mail-pf1-x43e.google.com [IPv6:2607:f8b0:4864:20::43e])
	by mail.lfdr.de (Postfix) with ESMTPS id D3FC331897D
	for <lists+kasan-dev@lfdr.de>; Thu, 11 Feb 2021 12:31:15 +0100 (CET)
Received: by mail-pf1-x43e.google.com with SMTP id g23sf4067429pfu.20
        for <lists+kasan-dev@lfdr.de>; Thu, 11 Feb 2021 03:31:15 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1613043074; cv=pass;
        d=google.com; s=arc-20160816;
        b=xbRXxAkE1rXaRqW4CYKDM7198pjx0F7u+ANQTbUN1pWlVuzATIyydP49qIckaPPJrz
         T8XrNLCcXbJIy7me4Y6Tcg0TT7n77dE1fuiqTylSWs+utBGgu1UwqYKxhaaSO/MduGUV
         SArbjWUk4b4TpX3igpFoaMpud3k8MvHFlOafZXgxSEwZ0WE5PMSswElirULE7rm5ubjf
         llCdk85dUbXJYE66sA2fL6Fo2qPPZITbz/v63Q+WTuBHgybSEu0X44T8Khs5miOEo62Y
         BMgwKGoTAqUDq2owPwvdo+5c5Fwl9WzNuvn/mJSBQ++z0w1ESyf7IEJ1ME86/D9fQQHQ
         ut0A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=vo1n1rvmXi2nanOPjXPqQRDDNEPdjCzZcb/oFm4q53o=;
        b=H4TeWLzK+VFqFdN6H1VmjHGcuOtwrlhvM578F0QYwdKP8YWj68Ja23BtoqpNMhv3qA
         hMyXQ1ZeWE3qi7ucKP3QRLmQ1BZJFMDBNwtDdhGtlPuAk4ZO3VUdw0pfCRNBCxVShuTv
         c81eq1eYw19yxxsHQAxrjejrCqM/GRVwLt3a3eo8eAYEVHoQhVF2UIISFCIKsrzETcj/
         mxERf/KbzqZmNTYp+GgurWPrXDKR3BbBoS/f5XjF49vXpy3NpeKth8rKbzCq9cLz74nt
         YBPKbdvrng3bvkjbTSuJ6CGPSaUY2EJe81jGpfDFWEQWCyv8xluw+1T9AWAd8ZKzPDfG
         pffA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ZI1NmsCy;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::736 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=vo1n1rvmXi2nanOPjXPqQRDDNEPdjCzZcb/oFm4q53o=;
        b=C+qQN31MPZp0DbFe+YC8ng5Ja80pWliIRXyzArMfDZPx1qUtfMdBzMBDzIOa34X1iI
         9gvKNCfhwr/wRclT0cAgpK5dst1ge3e9tgcXzsTzWnGbz4ru8gfTgwIQl7HSiTHvnk+b
         wi8fpbNsdsA18SKQ7diyPTlSvdl5X5JnJsME6EHuHScsd2K/cyh+qd5iP7YAk4AJWSzf
         yjcMbV023bFWkUC3OaDnx2c+aZoeC0SQTRrpJ7Hv8Jcw9oyHEFc7ZOjpEyzuPoHgWt+5
         UzZLf1+DTABv8Ov9nhktmrWDcyJmRywnJfH5Wc8PoFnxUauhIEsyT9oNueYNOIInhO/J
         bfPQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=vo1n1rvmXi2nanOPjXPqQRDDNEPdjCzZcb/oFm4q53o=;
        b=eioTQ4PIDP4H9cU772KGPel/Z1Tp8TOJi5wLQUCrxrIffROqER3UOzrn5yle8g8PU5
         G2n/YWWRxE5zeVatoWVHnr/qW1wKTjinsgeVrjneGibpVurJ3AGDT3yKSREFGP4LHAdW
         Z19psZ6aW4LmcqApJS40RBrnC53A5W7AaRZUMMemwCIM+hmOXe/WxeYALLpID6K9GB/n
         0WIiZZyIZF1c1KeZ000nqIwvaODCW9vpjv46ML/u8k377eBqJD8sTBvAa42cgwtsCgLo
         K9E8oR6OQh2dnMroKVxe5FW2+g58TIxH+M6YIRxvx2uzT64gR0e/P2JUYNU+gO8vuq3k
         2L5g==
X-Gm-Message-State: AOAM531EKZsNcn3S1Kx/cjGmOyDB4f1KQeqn0D19414kDyZNo6cW4wqz
	HO5HRXW1Qyn1qba6D7IRsyI=
X-Google-Smtp-Source: ABdhPJxmFF2toqa7cvnL29FPz+urm2IrnERbJON7EaU254cYauhTf2dpZFOQ6QgtoswahmEsXLKeiQ==
X-Received: by 2002:a17:90a:5d0d:: with SMTP id s13mr3510784pji.156.1613043073893;
        Thu, 11 Feb 2021 03:31:13 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:2ca:: with SMTP id b10ls960583pft.10.gmail; Thu, 11
 Feb 2021 03:31:13 -0800 (PST)
X-Received: by 2002:a63:fc54:: with SMTP id r20mr7579675pgk.167.1613043073203;
        Thu, 11 Feb 2021 03:31:13 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1613043073; cv=none;
        d=google.com; s=arc-20160816;
        b=p5sETNbLl9RijHIl9OQla0WPYFvFywlC8vpkRJA+VLsliFdhq/88vk8MANrAG+81pZ
         lGfXzt+CE8bVov40y+wLQSkXYYaExyXHCFzuVCuflUBMIYKdk4hNCkhNNdL+H7xR17D6
         vs1uWdfpIheCabuMbPS2JAUwD92zlAwp5yFUorxCPd6GPzpRU5xBt2R9ONCp3Pvzi9rp
         Z6CctQdJsKfMixXpISCHDgTlPhsYiDnFhKTRIF58SxlhUWEiMN/w7AGEF+dRTCPABwHH
         m19T4UaDKIy/Z7N3D4AwvgZiVwfr0KweJRngvCPMAuxs6EQDxnDvgfYQQDYzVs8Mbfrn
         rB9w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=M56yTOVeyVQnifUr4rpHFjusTEXuDugs/AJHv5kv2Xo=;
        b=KClMZD4PL/PGCu9fuRMjFdBCeIu/cqgq3AyP12bTwEe6dS1R7JThbBWvo2QBZ2DTr6
         QC8brtort5GdtPo4bkPPQ4AAVE8DdrZavZcoeCcYTvZIB7SWLXt4YFO4r5vcSNZFNp04
         QIKYSGI209wdaHwoaNoBfJgWP3HDN5+BTbtlOSKGg7ATv5UyfVjmAjk7Te5yHSdePiA6
         RG6UuRs4HCRSJfRsoQI7PPKDhwjij6dlCXFLhI4bS0f1nJNzDNGJriVkBio7SyXFR10m
         lsTQUX32PsXMh0/j1cTTabsLjponAE019UmByHoEB5/2fJpUTNWz6/Gjc2iIZ5ImvFjQ
         SM0A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ZI1NmsCy;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::736 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x736.google.com (mail-qk1-x736.google.com. [2607:f8b0:4864:20::736])
        by gmr-mx.google.com with ESMTPS id w1si159642pjl.3.2021.02.11.03.31.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 11 Feb 2021 03:31:13 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::736 as permitted sender) client-ip=2607:f8b0:4864:20::736;
Received: by mail-qk1-x736.google.com with SMTP id w19so4317097qki.13
        for <kasan-dev@googlegroups.com>; Thu, 11 Feb 2021 03:31:13 -0800 (PST)
X-Received: by 2002:a05:620a:49:: with SMTP id t9mr8246793qkt.231.1613043072618;
 Thu, 11 Feb 2021 03:31:12 -0800 (PST)
MIME-Version: 1.0
References: <CACV+nar9Apf15oXvwqsyd5OEX3PQ6OTxbhgG+0JRP0+iUvh_KQ@mail.gmail.com>
 <CACT4Y+Yo-HtoNrA8PL3qWYoUitt-WHgZmJ7wqh9zn01t53JL9g@mail.gmail.com>
 <CACV+naqJOptZa2e1+a9pNYP7Wh5yLwKtDSgzEz7yQaTB4uzLYQ@mail.gmail.com>
 <CACT4Y+Z51+01x_b+LTfeE2zP-w9Yt9eFOA6mdh7cVpc4BcZZLQ@mail.gmail.com>
 <CACV+naoDZiei0UR5psO05UhJXiYtgLzfBamoYNfKmOPNaBFr_g@mail.gmail.com>
 <CACT4Y+aCJOL3bQEcBNVqXWTWD5xZyB_E53_OGYB33gG+G8PLFQ@mail.gmail.com>
 <CACV+napVK9r2a61a8=bPcgAzeK+xdbg6fskBX+Aan2_b4+G5EQ@mail.gmail.com> <CACV+naq++A0btYaV8POmP8+_3BytCaGnOGDG6KmXYCfv463q1g@mail.gmail.com>
In-Reply-To: <CACV+naq++A0btYaV8POmP8+_3BytCaGnOGDG6KmXYCfv463q1g@mail.gmail.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 11 Feb 2021 12:30:58 +0100
Message-ID: <CACT4Y+bLfsCp_2s3Yb=B9p8DMGzDZsOvc=F0j5+mBpKLKnD8Vw@mail.gmail.com>
Subject: Re: reproduce data race
To: Jin Huang <andy.jinhuang@gmail.com>
Cc: kasan-dev <kasan-dev@googlegroups.com>, "Paul E. McKenney" <paulmck@kernel.org>, 
	syzkaller <syzkaller@googlegroups.com>, Marco Elver <elver@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=ZI1NmsCy;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::736
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

On Thu, Feb 11, 2021 at 10:49 AM Jin Huang <andy.jinhuang@gmail.com> wrote:
>
> Hi, Dmitry
> Still a question , for example the log I select is:
> 08:55:49 executing program 1:
> r0 = epoll_create(0x800)
> syz_io_uring_setup(0x472e, &(0x7f0000000100), &(0x7f0000ffe000/0x1000)=nil, &(0x7f0000ffc000/0x1000)=nil, &(0x7f0000000180), &(0x7f00000001c0))
> epoll_wait(r0, &(0x7f0000000000)=[{}], 0x1, 0x0)
>
> 08:55:49 executing program 2:
> r0 = syz_io_uring_setup(0x61a1, &(0x7f0000000000)={0x0, 0x4ff, 0x1, 0x0, 0x32a}, &(0x7f0000ffc000/0x2000)=nil, &(0x7f0000ffc000/0x2000)=nil, &(0x7f0000000080), &(0x7f00000000c0))
> syz_io_uring_setup(0x3243, &(0x7f0000000100)={0x0, 0xd02d, 0x20, 0x3, 0x16e, 0x0, r0}, &(0x7f0000ffc000/0x3000)=nil, &(0x7f0000ffc000/0x4000)=nil, &(0x7f0000000180), &(0x7f00000001c0))
> clone(0x22102000, 0x0, 0x0, 0x0, 0x0)
> syz_io_uring_setup(0x2fa8, &(0x7f0000000200)={0x0, 0xd1a6, 0x0, 0x1, 0xf6, 0x0, r0}, &(0x7f0000ffc000/0x2000)=nil, &(0x7f0000ffc000/0x1000)=nil, &(0x7f0000000280), &(0x7f00000002c0))
>
> Could I generate the C program to run program1 and program2 on different threads? Or I need to generate for program1 and program2 separately and merge the program source code myself?
> Since I see the -threaded option for syz-prog2c, but not sure the effect.

Such functionality does not exist now. If you need exactly that, you
need to merge yourself.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BbLfsCp_2s3Yb%3DB9p8DMGzDZsOvc%3DF0j5%2BmBpKLKnD8Vw%40mail.gmail.com.
