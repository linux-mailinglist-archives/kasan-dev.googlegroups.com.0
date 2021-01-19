Return-Path: <kasan-dev+bncBCMIZB7QWENRBUHUTKAAMGQEMZEFVZA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63d.google.com (mail-pl1-x63d.google.com [IPv6:2607:f8b0:4864:20::63d])
	by mail.lfdr.de (Postfix) with ESMTPS id 1AC1E2FB583
	for <lists+kasan-dev@lfdr.de>; Tue, 19 Jan 2021 12:00:56 +0100 (CET)
Received: by mail-pl1-x63d.google.com with SMTP id q12sf13673345plr.9
        for <lists+kasan-dev@lfdr.de>; Tue, 19 Jan 2021 03:00:56 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1611054055; cv=pass;
        d=google.com; s=arc-20160816;
        b=Z4uPCNTDL0ztMdNbFlUNnTjIvLoK0WSKY69YYIwlU/Ksp/695gm2KH1cfQo+LTNzhP
         JT5kcaPHh3+NmfEyq6gPDgUpXsWYCn+0tSFf8Q/X1t1e4TxHzqAJ1h9qLuQA7jbXeag8
         r+iUSJf4pm5Ej0f//9oQNquXPfmxrzq4yP5d7B8j/KqLaEPvvtO7pRrn6a1K+/c5F+ew
         6LDb8Dq+um+5dApa0fFSgqIN6MJ61WsU5Mozc7IyEfqF289ucsAo2xmgzMcIAsC37t1T
         s6nclnt3hBNDOlOai+zFCyCRK8K26J4xJq9+XmF/uUEB0jQvwV+v5NPyZWn/8VOkRI8/
         DGgg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=h6kJGFTwxSvIlEYxKuWhGNu8rmterBzxE64yosoyIHA=;
        b=fTfyLFh6Vcc8oKrPHyLKTnwAEuk8OJPpY7IVJVb5CCrAQLhNYyqtXByVWSomkRT2p5
         49P8g842cxmHjYaTfWmOD8jS4GqZgGTcUYZaX9NTvSllKUwCpfyMFI0vNPoLiDFaDV5b
         jbrC0/QAJOpYmmM5GY15yv1pKAvdwEiGSqxh3ryTUMP5xHKCrMi/HbfTQ4AdP/HpWnhX
         5dx3Tbl4LQGLt0LvM5ECC8FKYPcZ8Pirfh9S57HMtVObbHqgOfGz1Lv1UCaiCeoWmyFt
         Ta6Awc2fxFua8Jtt7LwAzzTqlh9EM6hsFyd+jgMvsI+JVr2H3CdCo6aJLBwQ9RO7EdGB
         pwxw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=NHprheW1;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::829 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=h6kJGFTwxSvIlEYxKuWhGNu8rmterBzxE64yosoyIHA=;
        b=I29HEEvt1HSkG2kWhPxmAR9EC8jm37E7uFjTAEdDRoZq5buKYP8JJh54qHnz3+ZkS/
         m/swZ1XmvBkTAT6csur6Ur7ERPLrW7a7CNQuli9Y25vO+LHJAzPXYKR6a/SvNy/Y/7iv
         V9+y/tPntnMPkQ8ZZlKGUAa0dpI04nnA+tmmvt24TLxyoYX9Phrea9mKCvhRWAtVvKRl
         dCQAgPezf3U+4tynMAJUjsXBItbtwAdL7FoSkmDo89an9EiVLOCBO7Xuk/TrPPcRP86t
         oWdJvYU4uicRtRvclvzfPHvnF13ojw74rXmEzcbEZd3ST/2Z4uEmntF49scpBQ0FkKJ6
         vdfw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=h6kJGFTwxSvIlEYxKuWhGNu8rmterBzxE64yosoyIHA=;
        b=YVgqr0FEyILVka04f+/0CeAVzW3iQVpto8uG7BBjlElvET5BycfkDTi0oHzG96+JLw
         LSNwC+uzqa+ZhpEqzk8+pd9Ui/CNvhxCkqZSxP9l3+WY7je6TkKHje+0F3p3lJwZ124w
         EI42ABhZX+pvkx9vtV7w8RkUW7y12xUfIvT0rDq2mUlwjVnQARukPjMUDNh8tkuVBTZS
         mKviLThXURqdWoIdeyOOCZ1VgirM4IfYlovsa+F2U170xN16sVuUFnJrqgsLeE/G+AGl
         sOy/UgNiaL4P+a5/EnuZJMCnXL5XMsbnmCjjVZEePoHnVEsrUM6A69JCjSsAfmMTEJtG
         Cr1Q==
X-Gm-Message-State: AOAM533NBv6wtEgG5n0EeA5TZXGW9xAI67juH6GqqLLOArSTMDn7YytA
	ZaMnSm44ZS37uB5TGsyaHCA=
X-Google-Smtp-Source: ABdhPJzfm+dcWQCIhYR98FEg7JqjDkzNqynx5WHDuGjI2fC0HwG9HzBaohoB8NqW1z6kswV6wisxPQ==
X-Received: by 2002:a62:2bc6:0:b029:1ae:821e:bd9d with SMTP id r189-20020a622bc60000b02901ae821ebd9dmr3867508pfr.54.1611054054785;
        Tue, 19 Jan 2021 03:00:54 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:d149:: with SMTP id c9ls7594695pgj.1.gmail; Tue, 19 Jan
 2021 02:54:08 -0800 (PST)
X-Received: by 2002:a62:604:0:b029:1b9:3f10:4722 with SMTP id 4-20020a6206040000b02901b93f104722mr3812999pfg.60.1611053648145;
        Tue, 19 Jan 2021 02:54:08 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1611053648; cv=none;
        d=google.com; s=arc-20160816;
        b=GfZ7j5uaS3qHehUq0lQw4Hurx1iy+hGW1bT/rmyq5jHVwXIaIZ+uoJQyMra4ES9Aiy
         EERYj+OLf8cuyjf4BrKiyp7kfOP5FG0eZT8drtvTqJz9UhxWRxpUn9+4IHlCYSvtxvDe
         1kmmCWnYakutzxVWjCBwa/4IDO6orUIpmgkN5AY5LKfIHZCAVXac095bBRqhSIm+pIbu
         6BeA/rQP6y50gv8dFb82rqFy3Y31W/BLQf4Roas0/n1J2Djf6aK/0PiO4mitIf/UcFz5
         CGJncuxiEvtZ0S3JpJ451ma3Uvhzr2X91grDzPejMChbjf/BqiaZmsAlnplJN2A2b4HE
         yDJg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=OPDPd2tYZD02kwk0k7Q2I/B3szupt0nc50mD7yNOA6A=;
        b=vrRlVn2hLGQGLqPYVtYO74qoetlOlQT0FQ2PA9b0vBk8964S8I0hKsC2Ax0dq06wKS
         9/45adEg3x0WRu02eixvif32zumSJlnxan253eBZLQvC3W4C5f+SbI9hFTxfHP7IUVIV
         B4ajlk/mj5DtwfftZv1urx//YdXT5TwgrULXY2eP7MlewBLIyrPQyrLtZJSbMku/VjNZ
         tin4n47t6RmQKzj5FkVhLptKc5gpIa9uMl/8YSzYNjrqzULlOkkEdQSEQzZfDZ1DDrPe
         YMzkao9SSsM0erVkqZXKu7rLQjVQKQQXyk3rjnGcQbYxiJjnCNoGOggi4gF/5/cZgpXs
         /S0A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=NHprheW1;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::829 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x829.google.com (mail-qt1-x829.google.com. [2607:f8b0:4864:20::829])
        by gmr-mx.google.com with ESMTPS id x10si36305plr.2.2021.01.19.02.54.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 19 Jan 2021 02:54:08 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::829 as permitted sender) client-ip=2607:f8b0:4864:20::829;
Received: by mail-qt1-x829.google.com with SMTP id c1so13325920qtc.1
        for <kasan-dev@googlegroups.com>; Tue, 19 Jan 2021 02:54:08 -0800 (PST)
X-Received: by 2002:aed:2f06:: with SMTP id l6mr3586426qtd.66.1611053647577;
 Tue, 19 Jan 2021 02:54:07 -0800 (PST)
MIME-Version: 1.0
References: <CACT4Y+bRe2tUzKaB_nvy6MreatTSFxogOM7ENpaje7ZbVj6T2g@mail.gmail.com>
 <CAJKOXPejytZtHL8LeD-_5qq7iXz+VUwgvdPhnANMeQCJ59b3-Q@mail.gmail.com>
 <CACT4Y+bBb8gx6doBgHM2D5AvQOSLHjzEXyymTGWcytb90bHXHg@mail.gmail.com>
 <CACRpkdb+u1zs3y5r2N=P7O0xsJerYJ3Dp9s2-=kAzw_s2AUMMw@mail.gmail.com>
 <CACT4Y+ad047xhqsd-omzHbJBRShm-1yLQogSR3+UMJDEtVJ=hw@mail.gmail.com> <CACRpkdYwT271D5o_jpubH5BXwTsgt8bH=v36rGP9HQn3sfDwMw@mail.gmail.com>
In-Reply-To: <CACRpkdYwT271D5o_jpubH5BXwTsgt8bH=v36rGP9HQn3sfDwMw@mail.gmail.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 19 Jan 2021 11:53:56 +0100
Message-ID: <CACT4Y+aEKZb9_Spe0ae0OGSSiMMOd0e_ORt28sKwCkN+x22oYw@mail.gmail.com>
Subject: Re: Arm + KASAN + syzbot
To: Linus Walleij <linus.walleij@linaro.org>
Cc: Krzysztof Kozlowski <krzk@kernel.org>, Russell King - ARM Linux <linux@armlinux.org.uk>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Hailong Liu <liu.hailong6@zte.com.cn>, Arnd Bergmann <arnd@arndb.de>, 
	kasan-dev <kasan-dev@googlegroups.com>, syzkaller <syzkaller@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=NHprheW1;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::829
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

On Tue, Jan 19, 2021 at 11:28 AM Linus Walleij <linus.walleij@linaro.org> wrote:
>
> On Tue, Jan 19, 2021 at 11:23 AM Dmitry Vyukov <dvyukov@google.com> wrote:
> > On Tue, Jan 19, 2021 at 11:17 AM Linus Walleij <linus.walleij@linaro.org> wrote:
> > > > > You could also try other QEMU machine (I don't know many of them, some
> > > > > time ago I was using exynos defconfig on smdkc210, but without KASAN).
> > > >
> > > > vexpress-a15 seems to be the most widely used and more maintained. It
> > > > works without KASAN. Is there a reason to switch to something else?
> > >
> > > Vexpress A15 is as good as any.
> > >
> > > It can however be compiled in two different ways depending on whether
> > > you use LPAE or not, and the defconfig does not use LPAE.
> > > By setting CONFIG_ARM_LPAE you more or less activate a totally
> > > different MMU on the same machine, and those are the two
> > > MMUs used by ARM32 systems, so I would test these two.
> > >
> > > The other interesting Qemu target that is and was used a lot is
> > > Versatile, versatile_defconfig. This is an older ARMv5 (ARM926EJ-S)
> > > CPU core with less memory, but the MMU should be behaving the same
> > > as vanilla Vexpress.
> >
> > That's interesting. If we have more than 1 instance in future we could
> > vary different aspects between them to get more combined coverage.
> > E.g. one could use ARM_LPAE=y while another ARM_LPAE=n.
> >
> > But let's start with 1 instance running first :)
>
> Hm I noticed that I was running in LPAE mode by default on Vexpress
> so I try non-LPAE now. Let's see what happens...

Good point. I've tried to enable CONFIG_ARM_LPAE=y in my config with
KASAN, and it did not help. No output after 8 minutes.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BaEKZb9_Spe0ae0OGSSiMMOd0e_ORt28sKwCkN%2Bx22oYw%40mail.gmail.com.
