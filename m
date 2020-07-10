Return-Path: <kasan-dev+bncBC7OBJGL2MHBB7G7UH4AKGQEAH6GCYY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13e.google.com (mail-il1-x13e.google.com [IPv6:2607:f8b0:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id 50F8C21B6AC
	for <lists+kasan-dev@lfdr.de>; Fri, 10 Jul 2020 15:41:17 +0200 (CEST)
Received: by mail-il1-x13e.google.com with SMTP id s137sf3659291ilc.18
        for <lists+kasan-dev@lfdr.de>; Fri, 10 Jul 2020 06:41:17 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1594388476; cv=pass;
        d=google.com; s=arc-20160816;
        b=Do0Of2VESw+uAdgMkLNQ5C2yJ12y8hNEujkfgJLGj+b0IDafClMboqoCMsvbH0Q6Ix
         wjrejpSZ9ZxQzG+b7TuOZreGCG0yDp1J3rF+KnATJWXDxSUbnmhbDBtngw5di+WmSd8h
         8SfvAznhq2CfcLPJQi0QvZjq/tYuhJ7ZD9vwcJQ2Y55vYs64rozctECwo/eEAlrGKYT7
         VPiKisqdoLOh3laHU36ePl6uRRmytCUqncbbTeLXupHP07J/GnzVKInpUc9SjQYDokEW
         j9g9OrK3g/gzqZcKKouMa0H488NsexuIGAwwCGC1XnSoDIckepNugby7C+hzH8OfpX6t
         AUzA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=1MyoeGMksyzEWxXpRAEbJXJFY/HJnSMG1xPnyEb+GeU=;
        b=FxbmUn66Z2UWzVJDiD/Re1hg4qUDTRSEI++JcPCD9AXhvo0eRTe0d4Ca9eRgivT4gN
         jxUZmnSA0UXJrua6KS01VzBzDSIZoEHFgSw3JSzoqMA0IyFYK7AuxH0dE/sg9VvICQfd
         ZPa5+zQdu7Hf4IvmjNBrHPLyBICkgu3mXDtxwdsD7SW1ql3fa7Fu2YtFcITta+KJjOMo
         4XsXsmZfkmst91SnlIDieIfBHukYPY2aIUC2mV1jzPMF3r15hmC3iKXeFFnuiheo5xJd
         HeIhsfugEoiq8WEWD3qrKEX+N12cwe53eGyxSc9WGeEGI6fqNE8FbG03tvBMuUhUC8R0
         DALg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=NYXHJiwx;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::244 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=1MyoeGMksyzEWxXpRAEbJXJFY/HJnSMG1xPnyEb+GeU=;
        b=eae7YrdRcXTFY3SienLkIjG01uPFDrAsZsEwDMbAYuHxX3I/Fz1L/9dNv428QPNvhj
         /sJ5/KI3nC9wZbBzh+zXh1nvqleLIyDaPclEbGiyw53vQRMu96OT48gmLLMurH6ZTW5/
         Jnz7tQPPKr5sCUfztKajzOl24Jvf5n+09ISQ/EaRcWtrwYQuv3YnncNwvmW5AQhigBX4
         uzsAq9PvFl/J5YckBQYpUR2wwrzuQjiyHg3b4VlNDBi1KclP9um2nkw1U3LYig0qqjuu
         HOmLPBaldI0SdBXp2wvqNQEFipEi1evVh12PQ63lODTSQ1BiB6IpUHfQT4ITTytW24DF
         +Z+A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=1MyoeGMksyzEWxXpRAEbJXJFY/HJnSMG1xPnyEb+GeU=;
        b=PuFj2xDsfs5Si1k4LS3Dkyw65MW3OVhALeFVKC3SmWPNwX8zmNTfjmnwI2MO+2owtG
         gg9Yn3auQn23jenSjk/tD+5VvStN8QwFVLtVu85p4KRdj+HACQlbVCsD2MKaYo09y8jk
         f50fome97JKXwDJNa7NoEJ/lKhbtjq8lgeixvvAG920QnxEpT+a4eEtQCrdzaPDBaAQo
         Hm5m4tr+wU7fTMa5kroQWLgEWM6JD3Uua35EtAgW+LFGObGmFDg0EYAVlUnXWJEpK/wG
         t2S8T7T+goydXtxQioo19DzMmzI3QLGuku6FpUXesPjZYb+HxNsqa975xYyNv//hPQ+Z
         f3YQ==
X-Gm-Message-State: AOAM533vOCuJozoQjQIfhRLFpkWsETWW8dqBywTIPCJFCLVpLMNcEmn3
	YS26SObIQnn2g5mNNRpwhS0=
X-Google-Smtp-Source: ABdhPJxgj4L0j6wQmb78lVoP+tb87iLm1ivHse5qiDzElM3DRSSegCISGv57aBQ2K5fT0li+eH2mkg==
X-Received: by 2002:a05:6e02:1313:: with SMTP id g19mr48355910ilr.123.1594388476100;
        Fri, 10 Jul 2020 06:41:16 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a02:7f13:: with SMTP id r19ls1379983jac.6.gmail; Fri, 10 Jul
 2020 06:41:15 -0700 (PDT)
X-Received: by 2002:a02:2b0a:: with SMTP id h10mr1731109jaa.61.1594388475688;
        Fri, 10 Jul 2020 06:41:15 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1594388475; cv=none;
        d=google.com; s=arc-20160816;
        b=A1o4LYxtNwN6lTqSftlEHKMd18kGU20RJgRfpFMcOyXN7G81HTnKia10ejWHsXtAs/
         wjCWk+Ev+B3CDMm1f8GADE8KitsRzMFm7mLycR3QYNvrZJO4zUm3SSOL2yqxvZbNUVHR
         lMK9VE3Ed4ZnDmXgozGFlZQQ8O7PoYVHWpy+WheJ0Bk1FhNXjGe8WmnAy479R5F9WK8f
         A1b5FuK8KdX93Zd9AXhGfIDCcfbvI3Z8PPEO9dRnCaCV97RZBI7koUKMUidp5c+JJmUV
         0vhyxgXv3OT44whW4LYlaff2mI5HsLHNKrWi901v/opy5VIexkDPTXx0i+YN540mtSyJ
         4CbQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=xlkM6fWvjyM8+6a1vUdIluakrj1ZTEDNz6icLUd+W5w=;
        b=PBSMecL8+3j51ao0XFrkt7Ry7PqfQZ5re27CZXtp+32EXyDSlfFwwmrRWCN/RuD+Np
         R3VXWUE7BYUB47PJpa8Nzmb2NAJo54WEw2ZdjD2+gsgtkGZmDHD9eCQfe6PWn9aMKWHN
         XGkLMOEZv063AnCs1FWBCT7DOivJLRJjMWQZOrMI5aOTEMX7dV/euz+8GDwFmD545blK
         gHe0dmienpudrxOpIKr8m+wOBOxOq03OYhaCtU56wYi/UbiTM8iaZb4IKd3E0fKK6PYu
         XSpdtN6yDeam5OEHvLdwcE1G7rOirE85V7ZSLTHTdTVnrUlgcQziUnCSo5Kfo7iW/CeI
         o4BA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=NYXHJiwx;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::244 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x244.google.com (mail-oi1-x244.google.com. [2607:f8b0:4864:20::244])
        by gmr-mx.google.com with ESMTPS id f15si302702ilr.0.2020.07.10.06.41.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 10 Jul 2020 06:41:15 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::244 as permitted sender) client-ip=2607:f8b0:4864:20::244;
Received: by mail-oi1-x244.google.com with SMTP id t198so4797938oie.7
        for <kasan-dev@googlegroups.com>; Fri, 10 Jul 2020 06:41:15 -0700 (PDT)
X-Received: by 2002:a05:6808:6c8:: with SMTP id m8mr4268206oih.121.1594388475024;
 Fri, 10 Jul 2020 06:41:15 -0700 (PDT)
MIME-Version: 1.0
References: <000001d5824d$c8b2a060$5a17e120$@codeaurora.org>
 <CACT4Y+aAicvQ1FYyOVbhJy62F4U6R_PXr+myNghFh8PZixfYLQ@mail.gmail.com>
 <CANpmjNOx7fuLLBasdEgnOCJepeufY4zo_FijsoSg0hfVgN7Ong@mail.gmail.com>
 <002801d58271$f5d01db0$e1705910$@codeaurora.org> <CANpmjNPVK00wsrpcVPFjudpqE-4-AVnZY0Pk-WMXTtqZTMXoOw@mail.gmail.com>
 <CANpmjNM9RhZ_V7vPBLp146m_JRqajeHgRT3h3gSBz3OH4Ya_Yg@mail.gmail.com> <000801d656bb$64aada40$2e008ec0$@codeaurora.org>
In-Reply-To: <000801d656bb$64aada40$2e008ec0$@codeaurora.org>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 10 Jul 2020 15:41:03 +0200
Message-ID: <CANpmjNMEtocM7f1UG6OFTmAudcFJaa22WTc7aM=YGYn6SMY6HQ@mail.gmail.com>
Subject: Re: KCSAN Support on ARM64 Kernel
To: sgrover@codeaurora.org
Cc: Mark Rutland <mark.rutland@arm.com>, Will Deacon <will@kernel.org>, 
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=NYXHJiwx;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::244 as
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

[+Cc mailing list and other folks]

Hi Sachin,

On Fri, 10 Jul 2020 at 15:09, <sgrover@codeaurora.org> wrote:
> Are these all the KCSAN changes:
>
> https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/log/ke=
rnel/kcsan
>
> And the same are applicable for arm64?

No, those aren't all KCSAN changes, those are only the core changes.
There are other changes, but unless they were in arch/, they will
apply to arm64 of course.

The the full list of changes up to the point KCSAN was merged can be
obtained with

  git log locking-urgent-2020-06-11..locking-kcsan-2020-06-11

where both tags are on -tip
[https://git.kernel.org/pub/scm/linux/kernel/git/tip/tip.git]. Note,
in case you're trying to backport this to an older kernel, I don't
recommend it because of all the ONCE changes that happened before the
merge. If you want to try and backport, we could dig out an older
pre-ONCE-rework version. Another reason I wouldn't recommend a
backport for now is because of all the unaddressed data races, and
KCSAN generally just throwing all kinds of (potentially already fixed
in mainline) reports at you.

On mainline, you could try to just cherry-pick Mark's patch from a few
months ago to enable one of the earlier KCSAN versions on arm64:
https://git.kernel.org/pub/scm/linux/kernel/git/mark/linux.git/commit/?h=3D=
arm64/kcsan&id=3Dae1d089527027ce710e464105a73eb0db27d7875

If you want to try this, I'd recommend also validating KCSAN works
using the kcsan-test module in -next:
https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/=
kernel/kcsan/kcsan-test.c?id=3D1fe84fd4a4027a17d511a832f89ab14107650ba4

Thanks,
-- Marco

> -----Original Message-----
> From: Marco Elver <elver@google.com>
> Sent: Monday, 15 June, 2020 6:00 PM
> To: sgrover@codeaurora.org
> Cc: Dmitry Vyukov <dvyukov@google.com>; kasan-dev <kasan-dev@googlegroups=
.com>; LKML <linux-kernel@vger.kernel.org>; Paul E. McKenney <paulmck@linux=
.ibm.com>; Andrea Parri <parri.andrea@gmail.com>; Alan Stern <stern@rowland=
.harvard.edu>; Mark Rutland <mark.rutland@arm.com>; Will Deacon <will@kerne=
l.org>
> Subject: Re: KCSAN Support on ARM64 Kernel
>
> On Mon, 14 Oct 2019 at 11:31, Marco Elver <elver@google.com> wrote:
> > My plan was to send patches upstream within the month.
> [...]
> > On Mon, 14 Oct 2019 at 11:30, <sgrover@codeaurora.org> wrote:
> [...]
> > > When can we expect upstream of KCSAN on kernel mainline. Any timeline=
?
> [...]
> > > > > Can you please tell me if KCSAN is supported on ARM64 now? Can I =
just rebase the KCSAN branch on top of our let=E2=80=99s say android mainli=
ne kernel, enable the config and run syzkaller on that for finding race con=
ditions?
> [...]
> > > KCSAN does not yet have ARM64 support. Once it's upstream, I would ex=
pect that Mark's patches (from repo linked in LKML thread) will just cleanl=
y apply to enable ARM64 support.
>
> Just FYI, KCSAN is in mainline now. I believe porting it to other archite=
ctures has also become much simpler due to its reworked ONCE/atomic support=
 relying on proper compiler instrumentation instead of other tricks.
>
> Thanks,
> -- Marco
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CANpmjNMEtocM7f1UG6OFTmAudcFJaa22WTc7aM%3DYGYn6SMY6HQ%40mail.gmai=
l.com.
