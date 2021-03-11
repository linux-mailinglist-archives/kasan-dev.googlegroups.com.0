Return-Path: <kasan-dev+bncBCMIZB7QWENRBIVZVGBAMGQEARREXSY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3c.google.com (mail-yb1-xb3c.google.com [IPv6:2607:f8b0:4864:20::b3c])
	by mail.lfdr.de (Postfix) with ESMTPS id B20A5337BBC
	for <lists+kasan-dev@lfdr.de>; Thu, 11 Mar 2021 19:08:35 +0100 (CET)
Received: by mail-yb1-xb3c.google.com with SMTP id l10sf26780189ybt.6
        for <lists+kasan-dev@lfdr.de>; Thu, 11 Mar 2021 10:08:35 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1615486114; cv=pass;
        d=google.com; s=arc-20160816;
        b=cJkg4Hvrn4ufsUzTqI3LN/nXrcBVkt3KW+5onq7NirCB7lujoQKQiyq82C4Be/928u
         R/WcAdEdy7mv4+P5rMbH3hyLXGo+hWJeKISh6UxzHek8HPBqnlUqnvKt1ux8qF4zz6dm
         WJR+u6e4YE+9BZWGe03QnrvEpSqganfL1Ip9Q6ondVwRKF+970pvgHWUodfXr4d4t+jf
         /dnB4GihsYIpn6eiNAlGKtBmCHEgavX+OEh4t4qfxaKZIoojrnq1WPnjJ2izDqlZUMC4
         neV/rmxWAJgwKqfDJ1CHzJ0EbqdlzH9i/FW51zU9uU24ToCODu20OWm6/bP0ds1gwKRc
         z0Dg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=ufMNOJpHMHg8XwUUnXHbbymf9ppIeoaiD/dF2K0IUNE=;
        b=RTuN4gFAj1l16q4QzIdKtYh2gT6DzRoH4k3g8KBE4eVDocHGgE//LhMJztpCckveFu
         CNuLGZ+ZRlyHnlrP+k1dj5lZ4/IIsUrFWuzg3ib50elVKhi8N/wr5x22S9dUM2thdD7o
         yjOGp4vbaQjZHwSO/EMay7+g5WnPGu0aRitCEeq8kOl61Cu5a3nMjklROzmp0z3r6qh4
         x9XZ2FY2TBvOOD46HBSTPXN1ama4vPe8CHVhzq5Gvoq+gxmBA79bPUKMKvtqBqV1NaPE
         ECLIufV+Ximi/RtKDxZNVH33IsgJ8AHjz5g3qaeBEtzfENj1C72zWV3aQZ1bUiaNeRGK
         PWdw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=VldAY2mC;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::82a as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ufMNOJpHMHg8XwUUnXHbbymf9ppIeoaiD/dF2K0IUNE=;
        b=jKdok6sNya71wRGXOt7H1n767f249vEMB0ZoFj7CPTAYhOhrK7OL+81yYMTLE2KqSK
         bbZOXeLou4JHutNQEthd1XoDMq4SKT0x0UR/MyZfNWYbAqU+uXidTHkE42HTxzdDjrct
         gXDBvgwIivKqN6b2nn70d7Qq4lATvELarKoU5V7nDliDCajrfXeYdQ/Wul3i+dckx9sp
         mqpgQybsP5h9+3ajsFCkaO41LkJewVVnP7T2Itzu3F8L+jXJ+UTex2PCpnJpTPFU1U52
         ij/N07d7CKjdc3oa3qklVBHviO0z939Vud/XEVDqt43jrn+BH3IebswPFji/Y66z29Z8
         KaYQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ufMNOJpHMHg8XwUUnXHbbymf9ppIeoaiD/dF2K0IUNE=;
        b=ZIBMHdbc9Xw5dPlNCyI0epc4jo9Ce6sx1/Di1NtSdhpGIm/slsAshsN1owOA87Iytb
         8BMVfNgcoPN9gmb11bVSBuHFpDe+zdV27hfbH5UWQ7CW/g7MYouu2lN1lrC9rmZGx6TG
         2Ep2WKWX7K9a8F/e9vHGC1ZJovv3FDIYPaE3LmGLSq4BU1/dxUN+HZB5dxaTBLlmfw2O
         uQPlPfAhO14xHVkzv7uzp27HELwh+fOFmSqPJbMkJ3DcCm7EUJx8Ma4p3Z8v0Umuq0fV
         11vWxps6c2JwR5V4Y5WoRBC8NbuBwMdZUD0Or2epMJwngNJiEUV/DOrjM8ikVSV6dhkd
         vT9w==
X-Gm-Message-State: AOAM531U2KG3lzvk2YRVTtAxUSXK6rplCo4SH+H/Wp3+VJcyZ67XC7b4
	+AGAytlJpicsQ8d7MIS+L5g=
X-Google-Smtp-Source: ABdhPJwCKqWG9nW1lGFx5/bbGXwHqM1zw7AlSUW/angu4b/gXJCfzdVPDQ9BLzKKWv/3t5qM3odhSQ==
X-Received: by 2002:a25:41d0:: with SMTP id o199mr13489760yba.458.1615486114781;
        Thu, 11 Mar 2021 10:08:34 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:7343:: with SMTP id o64ls3040675ybc.8.gmail; Thu, 11 Mar
 2021 10:08:34 -0800 (PST)
X-Received: by 2002:a25:6196:: with SMTP id v144mr12593415ybb.10.1615486114313;
        Thu, 11 Mar 2021 10:08:34 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1615486114; cv=none;
        d=google.com; s=arc-20160816;
        b=Kve5ajoifu1SgxrGnkp5MnOFePl2Bc+0xcG/sOJp3Jq5Tw0XiuE0EDCkf3UUgXwST7
         H3QFBLo5Dq6/Z8VKudth1fhyw6k7wGhiTsoS2qS1JZ8blL9PMEy9aS10iDViUGCgdYfg
         hh98rEKLXpjCoUgXJFigXK37SsvnBh5ro28s1g/9pn26TScdhzeYTcLn1m/9uBqArwAI
         Cab7iL2bIsLTHmdRDiCvPjitEQ0QpGMfOBNCx49e8CKRD7EWH/Ks4DwSOPLQ1f/JT3X4
         qYFjEDcK2qOq1pOg676qL4lUxmwydkK2pPXjmXmw2FCfhmFpnuEzgDAxhzmC+Xb2ns8w
         jqxQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=qSaqu/51dOzikTJC6hE/706AesrQiouCHhdtd21Ot4o=;
        b=qgjmJMsBbObrBEMgcOlna8qk8kAkblXw9XMnGv/csH8fWA4CBPNRD9RY2dXGvgFWuZ
         keSHlGQ4kblCGmRSPGCOIwI42DCqWG30owjj86zOUqRF6kTsrU5AQijY2JFqMCsV3zro
         Mfl8dWvlgC+hnDlh+ZpQ50gkjzW32ypqx/8hl9TMGTUKIPVUp5AKAwkZVtWZEVBcrtt8
         jeM0VGhjavkKXkn0DJYRsL8q0iyNHugDJAk78BhtUJ5KILPIgJODdQVe3nv+fbt44WON
         SI66Ya1vWRhYe7dVS+LdITSU6/P+Qc6rhF3vaaVyuZ3zelPT+2+kDCHWBmCd8zYjJVB7
         yIuA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=VldAY2mC;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::82a as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x82a.google.com (mail-qt1-x82a.google.com. [2607:f8b0:4864:20::82a])
        by gmr-mx.google.com with ESMTPS id x7si259807ybm.0.2021.03.11.10.08.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 11 Mar 2021 10:08:34 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::82a as permitted sender) client-ip=2607:f8b0:4864:20::82a;
Received: by mail-qt1-x82a.google.com with SMTP id l13so1831688qtu.9
        for <kasan-dev@googlegroups.com>; Thu, 11 Mar 2021 10:08:34 -0800 (PST)
X-Received: by 2002:ac8:5847:: with SMTP id h7mr8244788qth.43.1615486113700;
 Thu, 11 Mar 2021 10:08:33 -0800 (PST)
MIME-Version: 1.0
References: <20210119123659.GJ1551@shell.armlinux.org.uk> <CACT4Y+YwiLTLcAVN7+Jp+D9VXkdTgYNpXiHfJejTANPSOpA3+A@mail.gmail.com>
 <20210119194827.GL1551@shell.armlinux.org.uk> <CACT4Y+YdJoNTqnBSELcEbcbVsKBtJfYUc7_GSXbUQfAJN3JyRg@mail.gmail.com>
 <CACRpkdYtGjkpnoJgOUO-goWFUpLDWaj+xuS67mFAK14T+KO7FQ@mail.gmail.com>
 <CACT4Y+aMn74-DZdDnUWfkTyWfuBeCn_dvzurSorn5ih_YMvXPA@mail.gmail.com>
 <CACRpkdZyfphxWqqLCHtaUqwB0eY18ZvRyUq6XYEMew=HQdzHkw@mail.gmail.com>
 <20210127101911.GL1551@shell.armlinux.org.uk> <CACT4Y+YhTGWNcZxe+W+kY4QP9m=Z8iaR5u6-hkQvjvqN4VD1Sw@mail.gmail.com>
 <CACRpkda1pJpMif6Xt2JHseYQP6NWDmwwgm9pVCPnSAoeARTT9Q@mail.gmail.com>
 <20210311140904.GJ1463@shell.armlinux.org.uk> <CAK8P3a2JkcvH=113FhWxwSFqDZmPu_hKZeF+y6k-wf-ooWYj-w@mail.gmail.com>
In-Reply-To: <CAK8P3a2JkcvH=113FhWxwSFqDZmPu_hKZeF+y6k-wf-ooWYj-w@mail.gmail.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 11 Mar 2021 19:08:22 +0100
Message-ID: <CACT4Y+Y3_aYHNxECJ7XxSRr8s=RFwKreYZak1NtuXLfV5xQ=4w@mail.gmail.com>
Subject: Re: Arm + KASAN + syzbot
To: Arnd Bergmann <arnd@arndb.de>
Cc: Russell King - ARM Linux admin <linux@armlinux.org.uk>, Linus Walleij <linus.walleij@linaro.org>, 
	Krzysztof Kozlowski <krzk@kernel.org>, syzkaller <syzkaller@googlegroups.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, Hailong Liu <liu.hailong6@zte.com.cn>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=VldAY2mC;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::82a
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

On Thu, Mar 11, 2021 at 3:55 PM Arnd Bergmann <arnd@arndb.de> wrote:
> On Thu, Mar 11, 2021 at 3:09 PM Russell King - ARM Linux admin
> <linux@armlinux.org.uk> wrote:
> > On Thu, Mar 11, 2021 at 02:55:54PM +0100, Linus Walleij wrote:
> > > On Thu, Mar 11, 2021 at 11:54 AM Dmitry Vyukov <dvyukov@google.com> wrote:
> > > > The instance has KASAN disabled because Go binaries don't run on KASAN kernel:
> > > > https://lore.kernel.org/linux-arm-kernel/CACT4Y+YdJoNTqnBSELcEbcbVsKBtJfYUc7_GSXbUQfAJN3JyRg@mail.gmail.com/
> > >
> > > I am still puzzled by this, but I still have the open question about how much
> > > memory the Go runtime really use. I am suspecting quite a lot, and the
> > > ARM32 instance isn't on par with any contemporary server or desktop
> > > when it comes to memory, it has ~2GB for a userspace program, after
> > > that bad things will happen: the machine will start thrashing.
> >
> > I believe grafana is a Go binary - I run this in a VM with only 1G
> > of memory and no swap along with apache. It's happy enough.
> >
> > USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
> > grafana   1122  0.0  5.9 920344 60484 ?        Ssl  Feb18  28:31 /usr/sbin/grafana-server --config=/etc/grafana/grafana.ini ...
> >
> > So, I suspect it's basically KASAN upsetting Go somehow that then
> > causes the memory usage to spiral out of control.
>
> I found a bug report about someone complaining that Go reserves a lot of
> virtual address space, and that this breaks an application that works
> with VMSPLIT_3G
> when changing to VMSPLIT_2G
>
> https://github.com/golang/go/issues/35677
>
> If KASAN limits the address space available to user space, there might be
> a related issue, even when there is still physical memory available.

Issue with virtual/physical memory is my current hypothesis as well
(though, not much grounded). The Go binary is also quite beefy (in
terms of code and memory consumption, but works fine w/o KASAN).
We have a long term plan to move all Go binaries out of the target,
but there is no ETA, more like a wish.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BY3_aYHNxECJ7XxSRr8s%3DRFwKreYZak1NtuXLfV5xQ%3D4w%40mail.gmail.com.
