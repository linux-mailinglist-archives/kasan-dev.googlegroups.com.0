Return-Path: <kasan-dev+bncBC7OBJGL2MHBBOPBX2FQMGQEJ3S7JWY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53a.google.com (mail-pg1-x53a.google.com [IPv6:2607:f8b0:4864:20::53a])
	by mail.lfdr.de (Postfix) with ESMTPS id 2092E4344E6
	for <lists+kasan-dev@lfdr.de>; Wed, 20 Oct 2021 08:01:33 +0200 (CEST)
Received: by mail-pg1-x53a.google.com with SMTP id c2-20020a63d5020000b029023ae853b72csf12849487pgg.18
        for <lists+kasan-dev@lfdr.de>; Tue, 19 Oct 2021 23:01:33 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1634709690; cv=pass;
        d=google.com; s=arc-20160816;
        b=EaoEAYPtBH40YSUKUmLlUJqeRn/En4kgBreJnOX4LgBlR/7RjWrRlydDxSe3YFS8WL
         e1BfjLgNootQG4fjptiSm34u6QxjOtWrIm9/i6WCxelBoQTVPjzS0Ej14a5F3UjHXo1E
         mtmblBj3JVtKVnwlB+g/v2ZnFhmUA7VkYrYR4o9ZNHJCpPvLgHyZ9QxeicBdveXYrQEd
         u36uyoihK+4EnBJevIKoiVGFa7g1BxXKx+rjeIB1iX52oSr7SEE8tzGKgzTCuOPJVJ8U
         6gJIoaSEIhxfKXz0w1aI8hvisgpIHSZLqDQxLubN4MTiXbCvW0jbKAiVyKK4zigLY4+m
         OtgA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=vUHUCf2tpT5B68XJVt5MxJLwb9rOu0UiJT4K4lPEtzU=;
        b=rhTvUdZ8JPqnqiWPlHJ0ecgh1DzvPnxr2IFEIeypbKzvNr/WB9Yl8Uy4aPYPTQDYGF
         OzHWHEX896WAgykYCpy8Jg6sFT4wTEXMi10XobSCaclWfjGizHIhWxjl7XdAMLiCdug8
         7DtPqbg5BYtVwVB6jz99nh0WeX88bj20NLcc2Op6hfLs4dZz3W4B4D7l4DvaqNruyLsa
         KWnQHkjZc6B0W6W3oplJCLtDjHVehKf4dLsaEOPF9HlOkhIfkyVbcOqgPCOoOIo4irxa
         abFi5EAoP/5Pve5spY2ZWWfdS/rH6NMV7IhPDnM5Fmw8RwA6UQhc3BcVBfty0iuL22oH
         L3/A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=ZssLsRHB;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22a as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=vUHUCf2tpT5B68XJVt5MxJLwb9rOu0UiJT4K4lPEtzU=;
        b=BSskcJu0avhuq8eMr6ro2Jev7L57tGAXE/58N62MZdW7pWMHiqSR9ME7tMp9X4HMJ4
         EzkWS4cWNPAwkULq5yyDRMaHwHQn1XsuUBfFh1bKwTheXh6cCyuONB9y7+Ra+ag54V2u
         L8rcTAVKtyH0aRmpA12GOWY2IS3Vfv6k9L7nzlzMD1pugx5ybzEc96NIStLBGvyYtUlf
         6yGdGktu2aaQ2LOha30RN25WtKdz1fwRAmLdPEIyWlcufgYqnfbJ4nWdgaa8iu+pTmZS
         luYk3OJFfn81NU8g7gmupmF1qryT3M8Bk0/9XKf8gX6g721FGGMiElc+Bh+FPfRO2PDc
         UQ4A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=vUHUCf2tpT5B68XJVt5MxJLwb9rOu0UiJT4K4lPEtzU=;
        b=INJzd5bi50IxOiZTEGP+BUM7SMUt41BYPae+XbqEgi96Vsh+IyP7LMMw+YRtLJWWi6
         Nf7azrELsnku76A+r4RnyfK3GNmVwg9cVTzS1pHFycJDW/NV9PRIcLMBg2CyCsNImJLT
         +oV7XqidSZCtsaj/nHjJnHT8ExFxMwBXepwE7EjtOzIQ9t8LRFA8ZFtfIcynx6yjNY/H
         Zk2OeFu4sN8NV9zJ5vBOnqHUCdKeYXb0z9pT6vWCB4HPuwMOrWq0N7fCemPNbhItyOrM
         BGIanJpkhXct9o8Fc/NQqlpqzYDh+m58pff/Xf153V4jxkZV2idLIJK93j2TuFPSuIGM
         D4KA==
X-Gm-Message-State: AOAM531Qjkqvo7t3Nim93QiKLS3oDTriJjCF0OhDus6f3WQfU5iouLzK
	5Af/A7EJPDtYOfiYj2WxM3w=
X-Google-Smtp-Source: ABdhPJzo0RbNNxejb+DL4U/mR5T/VV7GysFAzW/WAH8+DVhyvNXI0akbwUrrkiottJehcO4u5K6w3Q==
X-Received: by 2002:a63:dd46:: with SMTP id g6mr32193080pgj.347.1634709689635;
        Tue, 19 Oct 2021 23:01:29 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:8cc2:: with SMTP id m185ls581596pfd.6.gmail; Tue, 19 Oct
 2021 23:01:29 -0700 (PDT)
X-Received: by 2002:a63:7051:: with SMTP id a17mr32317579pgn.417.1634709688955;
        Tue, 19 Oct 2021 23:01:28 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1634709688; cv=none;
        d=google.com; s=arc-20160816;
        b=j8ev9+nEK8aYGQztcB97ifepGKTC/5NrBEN5d8Xa1Pz2SvkGShwRuAmmytm6uZA+lh
         RWNFTDyj4r80cWgT5vFLJlEs4DlYp5Ut/b4+Y7Jnqjcct/jU2miZ9y7xvvSbVaTMtl8/
         yTejy5523c6gcqf6MncLI1vtcVNesZwowPFUJc9Qu2iH66ELxNt0Cm/3uf0EFXOStb4A
         0Dg72hxWpW+ZZSw8wDepWlUMDfdKJJV+QAfKSZwrTaZII8avDpFV5WRnpR1yQTqmdU6L
         3MHgaG3i8CXTeMpz+kAiLTsEEsCSZsJK7k9eVEc86hcsX7I1LhmT3Pe+AySWvKdzEnIZ
         vPzw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=IIod1o3qhCZvdW0ahsuaYBYhDgjj8nBMGLLNc7+K8Sw=;
        b=WQmnnajJlhCUtFSwY9LqXhwm8H35xELh0mYf7ah2jT4o8hf9njTEA+aBxj+PPZvS1Z
         gRrr9FpQnk0gIpExA/+p77aDdY06WWuISIZB2CNMqcwJFhPd6fuIRUPOSM8J9EQllwX/
         5Swp6Gi/chF1SGEOGzZ3W6rSIlPrf1eD1c2Kv46QQFgqP0xw4FeCbh5GzO/AEQWtLvfw
         K820502IduRMstoTVpBRnNPqYQYInO+fwKd01/5aGW2ZQ8dHHlypTVGkF/29KDM0/9f7
         WgeiuHDgSpuFh5FTfy3gmKvAyNdMg7BzIWZC7kOvtuq54jursO9dHfLedTB0SJsmiQRt
         FQZA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=ZssLsRHB;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22a as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x22a.google.com (mail-oi1-x22a.google.com. [2607:f8b0:4864:20::22a])
        by gmr-mx.google.com with ESMTPS id v8si90337plo.3.2021.10.19.23.01.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 19 Oct 2021 23:01:28 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22a as permitted sender) client-ip=2607:f8b0:4864:20::22a;
Received: by mail-oi1-x22a.google.com with SMTP id o204so8295559oih.13
        for <kasan-dev@googlegroups.com>; Tue, 19 Oct 2021 23:01:28 -0700 (PDT)
X-Received: by 2002:a05:6808:191c:: with SMTP id bf28mr7691641oib.7.1634709688231;
 Tue, 19 Oct 2021 23:01:28 -0700 (PDT)
MIME-Version: 1.0
References: <YWLwUUNuRrO7AxtM@arighi-desktop> <CANpmjNOw--ZNyhmn-GjuqU+aH5T98HMmBoCM4z=JFvajC913Qg@mail.gmail.com>
 <YWPaZSX4WyOwilW+@arighi-desktop> <CANpmjNMFFFa=6toZJXqo_9hzv05zoD0aXA4D_K93rfw58cEw3w@mail.gmail.com>
 <YWPjZv7ClDOE66iI@arighi-desktop> <CACT4Y+b4Xmev7uLhASpHnELcteadhaXCBkkD5hO2YNP5M2451g@mail.gmail.com>
 <YWQCknwPcGlOBfUi@arighi-desktop> <YWQJe1ccZ72FZkLB@arighi-desktop>
 <CANpmjNNtCf+q21_5Dj49c4D__jznwFbBFrWE0LG5UnC__B+fKA@mail.gmail.com> <YWRNVTk9N8K0RMst@arighi-desktop>
In-Reply-To: <YWRNVTk9N8K0RMst@arighi-desktop>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 20 Oct 2021 08:00:00 +0200
Message-ID: <CANpmjNMXNZX5QyLhXtT87ycnAhEe1upU_cL9D3+NOGKEn-gtCw@mail.gmail.com>
Subject: Re: BUG: soft lockup in __kmalloc_node() with KFENCE enabled
To: Andrea Righi <andrea.righi@canonical.com>
Cc: Dmitry Vyukov <dvyukov@google.com>, Alexander Potapenko <glider@google.com>, kasan-dev@googlegroups.com, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=ZssLsRHB;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22a as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Mon, 11 Oct 2021 at 16:42, Andrea Righi <andrea.righi@canonical.com> wrote:
> On Mon, Oct 11, 2021 at 12:03:52PM +0200, Marco Elver wrote:
> > On Mon, 11 Oct 2021 at 11:53, Andrea Righi <andrea.righi@canonical.com> wrote:
> > > On Mon, Oct 11, 2021 at 11:23:32AM +0200, Andrea Righi wrote:
> > > ...
> > > > > You seem to use the default 20s stall timeout. FWIW syzbot uses 160
> > > > > secs timeout for TCG emulation to avoid false positive warnings:
> > > > > https://github.com/google/syzkaller/blob/838e7e2cd9228583ca33c49a39aea4d863d3e36d/dashboard/config/linux/upstream-arm64-kasan.config#L509
> > > > > There are a number of other timeouts raised as well, some as high as
> > > > > 420 seconds.
> > > >
> > > > I see, I'll try with these settings and see if I can still hit the soft
> > > > lockup messages.
> > >
> > > Still getting soft lockup messages even with the new timeout settings:
> > >
> > > [  462.663766] watchdog: BUG: soft lockup - CPU#2 stuck for 430s! [systemd-udevd:168]
> > > [  462.755758] watchdog: BUG: soft lockup - CPU#3 stuck for 430s! [systemd-udevd:171]
> > > [  924.663765] watchdog: BUG: soft lockup - CPU#2 stuck for 861s! [systemd-udevd:168]
> > > [  924.755767] watchdog: BUG: soft lockup - CPU#3 stuck for 861s! [systemd-udevd:171]
> >
> > The lockups are expected if you're hitting the TCG bug I linked. Try
> > to pass '-enable-kvm' to the inner qemu instance (my bad if you
> > already have), assuming that's somehow easy to do.
>
> If I add '-enable-kvm' I can triggering other random panics (almost
> immediately), like this one for example:

Just FYI: https://lkml.kernel.org/r/20211019102524.2807208-2-elver@google.com

But you can already flip that switch in your config
(CONFIG_KFENCE_STATIC_KEYS=n), which we recommend as a default now.

As a side-effect it'd also make your QEMU TCG tests pass.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNMXNZX5QyLhXtT87ycnAhEe1upU_cL9D3%2BNOGKEn-gtCw%40mail.gmail.com.
