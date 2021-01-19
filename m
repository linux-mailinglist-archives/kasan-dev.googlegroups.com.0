Return-Path: <kasan-dev+bncBCMIZB7QWENRBI7GTKAAMGQEJPBCRMY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf37.google.com (mail-qv1-xf37.google.com [IPv6:2607:f8b0:4864:20::f37])
	by mail.lfdr.de (Postfix) with ESMTPS id EAC4D2FB54B
	for <lists+kasan-dev@lfdr.de>; Tue, 19 Jan 2021 11:23:32 +0100 (CET)
Received: by mail-qv1-xf37.google.com with SMTP id j5sf19194264qvu.22
        for <lists+kasan-dev@lfdr.de>; Tue, 19 Jan 2021 02:23:32 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1611051812; cv=pass;
        d=google.com; s=arc-20160816;
        b=bJWC98FHRJuwGS7Pu3ba78sykLYpcGl0w1NUoq11k/uevECiDlZP6eRMOX0mScDuFb
         V7emyagTY9dgP5xiu43wfYnRjmcKpmDKC1/f7nNsAdPXj7VX5MxBA2qDpESwW6/pBfIT
         NRnJVtLlqRYAj+4SGMQtvw7ouFw+8uT8IQCTLpEj+oxm85GngeSnLBwXUQW49HUnqCY0
         WZd/KGGk7cn/4ZkjFig1VzwlQFMuVq7p5hyY2M8Bg342g6rEvg/MDrpRWNycjhgKqQTu
         wg5h7IdIOsozlt7VXD6Knl3BnBR7OJA7P5fPVa+jePoWyFdqt3o4V9TxXSVgYM8g/umq
         UQvA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=1zmsA3qxpK63dB4KvpHok80BandVkpHS5ZcBsktc0iY=;
        b=SOUdSZ2B1RGuWv/1VNNOzvQoHojxbTjUNdJDpZPBs1oK9KUi33T8iJwq88SNJ+E0H6
         tCHfVTWnIQ8/Tm2ZyDnunwKGre2Z2zrnui17O+D9PepUNY5YrMxbAm7mjE4ppdGDSpbU
         1z5px3N37tb8Odvpe1dGtlBt0ntApB9dIO7Tjj20egVb2PwPN1jC5R0QM5Yd/DALNjwO
         TkHx3k9bFcFKZli6z5/4KPd0QJFrzUWRVYHhHKr8npAeMIXgBu/5zFa9eAP0YjoqjUSu
         Ki7IEDta9THBMbsOqAxo2CDy6b8NbjQmXKs6mIjYfTDYQLU34WvVlOGW6VSlzTzW/tDU
         VZTQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=D8n9EFPD;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f31 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=1zmsA3qxpK63dB4KvpHok80BandVkpHS5ZcBsktc0iY=;
        b=JiZhv8gNgkQYzEvrta+l6OvPChKCLf3UrWdBlklWIta3Rb+FAxmxoz7cXZNuagaYXM
         y769cDEEaDUacLC1GFYoUj3UxtudGA6knS06Cu6Xqa5A1bshuJUB+eDEUGoPlCeHdKh0
         oCgy1iQ3fItgvZuOEdZHL/ONMhAEjJJMUJel6E83PHQFmjp+heKH1gT6gZIyRmwfpLXL
         YlfcvaI1IoWdusCHJL2jcsvSIdLMjBPNtLdNw9d1U0OW2rrZg9TJj2rwZvVsJ5n2cRvc
         jXPi97912a8MugBQXDKNJfoOx1Wxh19i9yEghkJFkxf+OHCgZghOppeVKdw/y5k5jnki
         n6+A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=1zmsA3qxpK63dB4KvpHok80BandVkpHS5ZcBsktc0iY=;
        b=iNRv2w2K9Akot7oWhugPMwpFXyxXjIw8jRSUxDFQtoYdTtiyjAYzGrXp/kYoH82duh
         dw2joZR+enz/bVN5AQQ7YT9uc3aNeiXrytgwsyeosJmDu8RwCZ/Q4QyQDTb8IDzqoyOD
         Iurlfa4F+89SeoBnprzZL88KLtC1tMsyIGLtMmyY0Df2ewf14P3CDZbAqL6mLrLpOdff
         gf0N6q0DsQ7BuN5WU2gXQJndYugLqgSQVaxp2KJNFr3DwqX1xTJ4UWWUfP7Os+KzBjk7
         /sKL+d1EutBXbxzrvIQqTwhRHFPoaDP/AWDxVC5iY9UeOb1MWQyxYpB3tKJi0L4DHz75
         PewQ==
X-Gm-Message-State: AOAM531vOtwUXWREmZJeRikCvZkWUvwMuqIWzGseDHQ3ZWIvu3E3bhAF
	ioBIE1eUPaimJIcmhAkMk7A=
X-Google-Smtp-Source: ABdhPJzXF9H+BIKheCtA9ZEA1YFuxSKFHg1nzi5kvaeDiqcXsLXAQ3bvXaj+fsMK28MYqo9MNMJcpQ==
X-Received: by 2002:ac8:4e51:: with SMTP id e17mr3470287qtw.121.1611051811931;
        Tue, 19 Jan 2021 02:23:31 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ae9:edd6:: with SMTP id c205ls10612023qkg.10.gmail; Tue, 19
 Jan 2021 02:23:31 -0800 (PST)
X-Received: by 2002:a37:bc81:: with SMTP id m123mr3532758qkf.191.1611051811529;
        Tue, 19 Jan 2021 02:23:31 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1611051811; cv=none;
        d=google.com; s=arc-20160816;
        b=0oAKcUQgnnJxpvk+YnuRZpD885KxS4Xt9GUNOpI6vsyxB3PC780FzwGs31NNHysFP9
         DRV+4NozLbHwZ80ahI0jG4icrFB3ezhEcYApevT8zKqshSnfQRDR75q75f9d2yd62CPF
         lE1su33a4DPo9RB20EKZUV3CPoTbEMtlSiScnQBdB0gEz9CBo2i2nS+lb5yyHKRf8A6f
         nR/esCuDguk0uPNKNloMmNGd8k0bCyiT18EIyXTza/crlFTaOjjQ+0s0nAtNxKLhSQEN
         1DvI39gnPCwcBZ0OPHoWLODWP7xbYJ6m1LAX5FRh7IB/u2IGQ8Tcmw4mnNUi0is3DlPm
         guEw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=vz/VQ319RBmHW2ubTqrtXb8KjQVHUprQsC2snjYtmQE=;
        b=nZYetTRmtCdtqHFhAnj8FZTbNDYvHralvgUpnW2q9nRvFpCzbauL6+JdU65YUeIxqS
         VBleUzHA5X18VmTTdUY2DITazQs4G6e1byqjknjonDtH5gXHjgtXZ8QxH7BK7vCd0xpi
         dIrJ03IEHVcC+Wbpx8brzn4V6NIQYmJ5kAE4rrHy3FdtwSiqg8zwY4G2zPSrrhnIU2Vp
         DhQWO2iuDo8rVHqm9yZoT4J20H9BPfIoEr/WDgBE9G1eflCPfS8DPmx53v/Lu1VvN+1r
         itvGLpIp9em/qjJOBcuiDXFd/I45CcCJ4azmZggGad2bHCFv2JJty6j1cvbitKEROSTJ
         2zTA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=D8n9EFPD;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f31 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf31.google.com (mail-qv1-xf31.google.com. [2607:f8b0:4864:20::f31])
        by gmr-mx.google.com with ESMTPS id q66si1249504qkd.3.2021.01.19.02.23.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 19 Jan 2021 02:23:31 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f31 as permitted sender) client-ip=2607:f8b0:4864:20::f31;
Received: by mail-qv1-xf31.google.com with SMTP id d11so8851665qvo.11
        for <kasan-dev@googlegroups.com>; Tue, 19 Jan 2021 02:23:31 -0800 (PST)
X-Received: by 2002:a0c:fe90:: with SMTP id d16mr3780604qvs.13.1611051811012;
 Tue, 19 Jan 2021 02:23:31 -0800 (PST)
MIME-Version: 1.0
References: <CACT4Y+bRe2tUzKaB_nvy6MreatTSFxogOM7ENpaje7ZbVj6T2g@mail.gmail.com>
 <CAJKOXPejytZtHL8LeD-_5qq7iXz+VUwgvdPhnANMeQCJ59b3-Q@mail.gmail.com>
 <CACT4Y+bBb8gx6doBgHM2D5AvQOSLHjzEXyymTGWcytb90bHXHg@mail.gmail.com> <CACRpkdb+u1zs3y5r2N=P7O0xsJerYJ3Dp9s2-=kAzw_s2AUMMw@mail.gmail.com>
In-Reply-To: <CACRpkdb+u1zs3y5r2N=P7O0xsJerYJ3Dp9s2-=kAzw_s2AUMMw@mail.gmail.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 19 Jan 2021 11:23:19 +0100
Message-ID: <CACT4Y+ad047xhqsd-omzHbJBRShm-1yLQogSR3+UMJDEtVJ=hw@mail.gmail.com>
Subject: Re: Arm + KASAN + syzbot
To: Linus Walleij <linus.walleij@linaro.org>
Cc: Krzysztof Kozlowski <krzk@kernel.org>, Russell King - ARM Linux <linux@armlinux.org.uk>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Hailong Liu <liu.hailong6@zte.com.cn>, Arnd Bergmann <arnd@arndb.de>, 
	kasan-dev <kasan-dev@googlegroups.com>, syzkaller <syzkaller@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=D8n9EFPD;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f31
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

On Tue, Jan 19, 2021 at 11:17 AM Linus Walleij <linus.walleij@linaro.org> wrote:
> > > You could also try other QEMU machine (I don't know many of them, some
> > > time ago I was using exynos defconfig on smdkc210, but without KASAN).
> >
> > vexpress-a15 seems to be the most widely used and more maintained. It
> > works without KASAN. Is there a reason to switch to something else?
>
> Vexpress A15 is as good as any.
>
> It can however be compiled in two different ways depending on whether
> you use LPAE or not, and the defconfig does not use LPAE.
> By setting CONFIG_ARM_LPAE you more or less activate a totally
> different MMU on the same machine, and those are the two
> MMUs used by ARM32 systems, so I would test these two.
>
> The other interesting Qemu target that is and was used a lot is
> Versatile, versatile_defconfig. This is an older ARMv5 (ARM926EJ-S)
> CPU core with less memory, but the MMU should be behaving the same
> as vanilla Vexpress.

That's interesting. If we have more than 1 instance in future we could
vary different aspects between them to get more combined coverage.
E.g. one could use ARM_LPAE=y while another ARM_LPAE=n.

But let's start with 1 instance running first :)

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2Bad047xhqsd-omzHbJBRShm-1yLQogSR3%2BUMJDEtVJ%3Dhw%40mail.gmail.com.
