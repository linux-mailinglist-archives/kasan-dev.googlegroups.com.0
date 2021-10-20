Return-Path: <kasan-dev+bncBDOPF7OU44DRBDHGX2FQMGQECORPUUY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x540.google.com (mail-ed1-x540.google.com [IPv6:2a00:1450:4864:20::540])
	by mail.lfdr.de (Postfix) with ESMTPS id AA2384344F7
	for <lists+kasan-dev@lfdr.de>; Wed, 20 Oct 2021 08:11:24 +0200 (CEST)
Received: by mail-ed1-x540.google.com with SMTP id g28-20020a50d0dc000000b003dae69dfe3asf19907731edf.7
        for <lists+kasan-dev@lfdr.de>; Tue, 19 Oct 2021 23:11:24 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1634710284; cv=pass;
        d=google.com; s=arc-20160816;
        b=a5rV/MZb2nEyl5FeoAp88Cq3dKszboJnYNfITc5rAM0zd478XeiGXv6KPkNsx7SU32
         IZsxLgWvmbJ++bx0ObCgDq24bfypO1PnR+kS+fKQPw+aJDlI8nuj/JTIrLb0Sab1U5Ma
         /LvfhsStaNqq7CbyGkPa/akoMves3qAfszPSgqMxTcx604ZAi6d7bBg9CQlr2Z2WhwWe
         RmQmqVVUmLnamgGfLmYFLOtRvkyoW7V9Q+ra6TzdAsKz7GBbZhlW8ZEmRtMQNk80Nabc
         1y5PTaogG/nSV9Vr1QB+lcfAPtmn7PH0O7EM+h5eCxgE3BCcYM5mi/Ak703I6lnXogIq
         AZ3A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=bkBwOxxMH1DFJ33AtLArXxDJeRaVHrYQAujH4wfl+q4=;
        b=TTO9Rr6DeeUHOKydrMhHEdNnTPOXOWc1izkX01qVKcchtR3oM0DfJ2BOOZmZDDrwVv
         ruanS/dY/Y9G07qxAb/B5K49vo76JilxhCJ9i83SuGzlPpZ7ZL6+Fd1cVcUvcb+7b9uy
         7IaDEu9A+eg94Sm7gmkIDrccTMpn2Q+vdE1AYwwm3LZlfU7kwmAR9fQvJtI05oZhKKPN
         ESrBa/XSWUFQA27PNYFwg+smVB/FldEY1s/3ciYP/Zmpb5jhzyxmpuVAFBZDAHb7OFxD
         SyBzM3sBw5mCyBijhJhb9OsoZJhoZiVeN58prZtPLOv7O7Jc6dJTW9h/Njv7zqcz+y3L
         9iKQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@canonical.com header.s=20210705 header.b="TV6/5zrA";
       spf=pass (google.com: domain of andrea.righi@canonical.com designates 185.125.188.122 as permitted sender) smtp.mailfrom=andrea.righi@canonical.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=canonical.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=bkBwOxxMH1DFJ33AtLArXxDJeRaVHrYQAujH4wfl+q4=;
        b=o25gp18+3jgCwTy2UpnMDIqQm+o/Aew78bJmUq3Frm5acOrRWxh8lAPifj0ceBltna
         5ZkJY5mkwnT5SazL2CD+h6/TCSPS/e3dVg5MQbmVO7N5k5inHOMPEFjgPHfskIuNnwKV
         v2KZLAaZIIwwvkTJxXvWboyNhoaINLFYjJd8xPMEKrMPJZKkkM9RiTGe29BH5GvuJUm5
         vmgVNViRIAM6/d/u5ZvxGH6TufRu22Bno47bGsE5fy0o1sR6ZebAlmUi/PxzFMmn7wUs
         J8lrL8eB+Y8ARbyeWvBDKtdS/LcsKZg4GGipdcK6FBmsGrz5l8aMVnrdImcPCmCsnoku
         6VKw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=bkBwOxxMH1DFJ33AtLArXxDJeRaVHrYQAujH4wfl+q4=;
        b=T1+vbL5gjIJFZYG6kdKyVfoR6yRdIfoNBNKuW8EtdxW/LmiI/CUGRfdGqzIFrlkYKW
         XLNtua3mHAIZh1EK9jRGvPrlBJ2oEHXzJaVIoXNl6r7zx25Dr1HM0ZpibhXz8/5qeFmz
         kSeo2MNk0QMXqmXOZMDUGcFpFK9eU41GR3TJzfDeE7bFYnFEk3a9iDkGsBP50LnfjnqW
         LAAuTHHk5TOKrDXSdTPS8TWVz4PHi46Ec8eHdBbnB5JQEdHfDBgsYq7rdM79nPFN02D/
         s53m0js1HXfQLwWAmIrXoCUcS4xKoSnXy7FTs34ElfAVbTF7ZdXY/SFM2t70vVmQ0+gZ
         kAUQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530D6iXPleVXPqSyl2hO1SKd5G00td6Y18gy0YbvmcEyULcZmGBw
	iW572F4ZWzuumTnRoQ6JTE4=
X-Google-Smtp-Source: ABdhPJzDGZi08DXoKr6KCCWpmqA4bUR3HAHSxMTpGICzDh/kkBuh94PJKCM4xX+h2J8FyDRCt3rAYQ==
X-Received: by 2002:a17:907:7fa8:: with SMTP id qk40mr42423654ejc.445.1634710284420;
        Tue, 19 Oct 2021 23:11:24 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:1484:: with SMTP id x4ls596675ejc.1.gmail; Tue, 19
 Oct 2021 23:11:23 -0700 (PDT)
X-Received: by 2002:a17:906:d0d8:: with SMTP id bq24mr44862462ejb.402.1634710283503;
        Tue, 19 Oct 2021 23:11:23 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1634710283; cv=none;
        d=google.com; s=arc-20160816;
        b=H/u7LouGorzd0v4nlHqIrD0t8RpnacmXs14kf5j0YpSCNEEP9ly4+Uhioz+Zo/gj1f
         WoVZvpZ/y2kVn/CIr2lo2Fu4eBLhlXzHd3XCkgh1sGqAcUNB203k3Au/RFpw0p4YSYnt
         yzeTLwTulT3cgUbS4C4nc1X1zywcIgGEM/nEVK/1uKhndbrOgKhS48pQDLnk9C31iNEB
         L5xvtb67hafWVItXbOV61VIjmyfJfKMUhJjb4baI4uMjEwdQa7HETmU8aq8/0Ac8y8pF
         VrXkYgNhCr0VM+KgTV7pAxuXdDNTwjGYMsduDNuSKwERfhlUgkxscUV0auWQ8PTNlstD
         mOfg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=1Pwbto3xzDOuj9AdmGAawkkhjI3NOhcoDznc6EjuA4E=;
        b=FjtPI8GXuq1nrgwhqk6rXkA1DX+ffnkR+zzWCGpINxEsEWENXF5y+vLmuO9qUGABuQ
         flzN0OLSm4fB2Se2fXlu2JCyClAXrcZRrD2D87bvk7oGSKlMpzynmiudwJXtnybWqF0L
         /9fRjKOpXBYAGGBOHZ7TH7HmpiL1oCp011NRsa4qv9w9tfbUF1H2fUtPMIRPCsAXQT0u
         akxPlm7Kh0i4PUIHtmfvvIfdbJNcfkoO43RVXIVyJD47bB52elQni2VH4w8jtXKVGR+W
         bgxsg+d8CF4tRM0WgmrqrQUUwFigoKNcWCHeRQ/N1bwrLOPG7xrGn2HWZCLiAlSBNkR/
         RomQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@canonical.com header.s=20210705 header.b="TV6/5zrA";
       spf=pass (google.com: domain of andrea.righi@canonical.com designates 185.125.188.122 as permitted sender) smtp.mailfrom=andrea.righi@canonical.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=canonical.com
Received: from smtp-relay-internal-0.canonical.com (smtp-relay-internal-0.canonical.com. [185.125.188.122])
        by gmr-mx.google.com with ESMTPS id s19si81411edi.1.2021.10.19.23.11.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 19 Oct 2021 23:11:23 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrea.righi@canonical.com designates 185.125.188.122 as permitted sender) client-ip=185.125.188.122;
Received: from mail-ed1-f72.google.com (mail-ed1-f72.google.com [209.85.208.72])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-relay-internal-0.canonical.com (Postfix) with ESMTPS id 297F640002
	for <kasan-dev@googlegroups.com>; Wed, 20 Oct 2021 06:11:23 +0000 (UTC)
Received: by mail-ed1-f72.google.com with SMTP id e14-20020a056402088e00b003db6ebb9526so19842532edy.22
        for <kasan-dev@googlegroups.com>; Tue, 19 Oct 2021 23:11:23 -0700 (PDT)
X-Received: by 2002:a50:9d49:: with SMTP id j9mr59027136edk.39.1634710282866;
        Tue, 19 Oct 2021 23:11:22 -0700 (PDT)
X-Received: by 2002:a50:9d49:: with SMTP id j9mr59027121edk.39.1634710282707;
        Tue, 19 Oct 2021 23:11:22 -0700 (PDT)
Received: from localhost ([2001:67c:1560:8007::aac:c1b6])
        by smtp.gmail.com with ESMTPSA id e7sm573903edz.95.2021.10.19.23.11.21
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 19 Oct 2021 23:11:22 -0700 (PDT)
Date: Wed, 20 Oct 2021 08:11:21 +0200
From: Andrea Righi <andrea.righi@canonical.com>
To: Marco Elver <elver@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>,
	Alexander Potapenko <glider@google.com>, kasan-dev@googlegroups.com,
	linux-mm@kvack.org, linux-kernel@vger.kernel.org
Subject: Re: BUG: soft lockup in __kmalloc_node() with KFENCE enabled
Message-ID: <YW+zCbaf1Xb8lBMo@arighi-desktop>
References: <CANpmjNOw--ZNyhmn-GjuqU+aH5T98HMmBoCM4z=JFvajC913Qg@mail.gmail.com>
 <YWPaZSX4WyOwilW+@arighi-desktop>
 <CANpmjNMFFFa=6toZJXqo_9hzv05zoD0aXA4D_K93rfw58cEw3w@mail.gmail.com>
 <YWPjZv7ClDOE66iI@arighi-desktop>
 <CACT4Y+b4Xmev7uLhASpHnELcteadhaXCBkkD5hO2YNP5M2451g@mail.gmail.com>
 <YWQCknwPcGlOBfUi@arighi-desktop>
 <YWQJe1ccZ72FZkLB@arighi-desktop>
 <CANpmjNNtCf+q21_5Dj49c4D__jznwFbBFrWE0LG5UnC__B+fKA@mail.gmail.com>
 <YWRNVTk9N8K0RMst@arighi-desktop>
 <CANpmjNMXNZX5QyLhXtT87ycnAhEe1upU_cL9D3+NOGKEn-gtCw@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNMXNZX5QyLhXtT87ycnAhEe1upU_cL9D3+NOGKEn-gtCw@mail.gmail.com>
X-Original-Sender: andrea.righi@canonical.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@canonical.com header.s=20210705 header.b="TV6/5zrA";       spf=pass
 (google.com: domain of andrea.righi@canonical.com designates 185.125.188.122
 as permitted sender) smtp.mailfrom=andrea.righi@canonical.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=canonical.com
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

On Wed, Oct 20, 2021 at 08:00:00AM +0200, Marco Elver wrote:
> On Mon, 11 Oct 2021 at 16:42, Andrea Righi <andrea.righi@canonical.com> wrote:
> > On Mon, Oct 11, 2021 at 12:03:52PM +0200, Marco Elver wrote:
> > > On Mon, 11 Oct 2021 at 11:53, Andrea Righi <andrea.righi@canonical.com> wrote:
> > > > On Mon, Oct 11, 2021 at 11:23:32AM +0200, Andrea Righi wrote:
> > > > ...
> > > > > > You seem to use the default 20s stall timeout. FWIW syzbot uses 160
> > > > > > secs timeout for TCG emulation to avoid false positive warnings:
> > > > > > https://github.com/google/syzkaller/blob/838e7e2cd9228583ca33c49a39aea4d863d3e36d/dashboard/config/linux/upstream-arm64-kasan.config#L509
> > > > > > There are a number of other timeouts raised as well, some as high as
> > > > > > 420 seconds.
> > > > >
> > > > > I see, I'll try with these settings and see if I can still hit the soft
> > > > > lockup messages.
> > > >
> > > > Still getting soft lockup messages even with the new timeout settings:
> > > >
> > > > [  462.663766] watchdog: BUG: soft lockup - CPU#2 stuck for 430s! [systemd-udevd:168]
> > > > [  462.755758] watchdog: BUG: soft lockup - CPU#3 stuck for 430s! [systemd-udevd:171]
> > > > [  924.663765] watchdog: BUG: soft lockup - CPU#2 stuck for 861s! [systemd-udevd:168]
> > > > [  924.755767] watchdog: BUG: soft lockup - CPU#3 stuck for 861s! [systemd-udevd:171]
> > >
> > > The lockups are expected if you're hitting the TCG bug I linked. Try
> > > to pass '-enable-kvm' to the inner qemu instance (my bad if you
> > > already have), assuming that's somehow easy to do.
> >
> > If I add '-enable-kvm' I can triggering other random panics (almost
> > immediately), like this one for example:
> 
> Just FYI: https://lkml.kernel.org/r/20211019102524.2807208-2-elver@google.com
> 
> But you can already flip that switch in your config
> (CONFIG_KFENCE_STATIC_KEYS=n), which we recommend as a default now.
> 
> As a side-effect it'd also make your QEMU TCG tests pass.

Cool! Thanks for the update!

And about the other panic that I was getting it seems to be fixed by
this one:
https://lore.kernel.org/lkml/YW6N2qXpBU3oc50q@arighi-desktop/T/#u

-Andrea

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YW%2BzCbaf1Xb8lBMo%40arighi-desktop.
