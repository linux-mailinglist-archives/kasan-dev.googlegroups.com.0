Return-Path: <kasan-dev+bncBCMIZB7QWENRBC5DSGFQMGQEZFS6OVY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3e.google.com (mail-yb1-xb3e.google.com [IPv6:2607:f8b0:4864:20::b3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 06E9E4292B0
	for <lists+kasan-dev@lfdr.de>; Mon, 11 Oct 2021 17:00:29 +0200 (CEST)
Received: by mail-yb1-xb3e.google.com with SMTP id x16-20020a25b910000000b005b6b7f2f91csf23753283ybj.1
        for <lists+kasan-dev@lfdr.de>; Mon, 11 Oct 2021 08:00:28 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1633964428; cv=pass;
        d=google.com; s=arc-20160816;
        b=IQzWM6cF3zxWXnCQrNLUPEVpEx+5Lt2rec3DmNWiaKe5kuK1SeWcaB7/I2osUEIeKe
         VdgLfQqYx9zsmh00pDvBnks8mrgAXD2eLvHP36A97q381Iyu5HjZaMk2Inx7IyNtOM0H
         j9jPJO0qVWTdF6tIBY0HWdBJmCKZMACO9s52xd2Df+lkLQvrbbyyQmC9Qfgl+0kQW0d1
         mykwkzYQIoG3XnxY46/HvNkpI114QEKqZBewhM56vPDdJRz6S372s/Tj+KXWIb+h/eOL
         Zceil5eof1TWoYQlMABApsUKd0aN6TkbEU+dNcd/HAFbOkjURWdoWnOUXaQ3am4JJN6o
         BBSA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=LLQk0+08zmaAMGynXpgT36na6ZvoPAm/AG8YDW5XgkA=;
        b=P5sqt5ECtUKo0dCCguw6pzfTvYjr3yXTysX8kyFFB+EUCE6YgCRi4olM6sSV5sc1Jq
         Wh3Lk+5ZXUCmTW3k5jkf8Q8ItQZKXym7VLN6NgSypvLrfYCnsWsJQi97kRfYL/CqhY6m
         +MmTCmHPMEoBzMXyf37kQBW5/M5Y75PO+OnlQT0OL8Pa7C9USvVrLfgqIKP4N8DjoP8p
         J9DLWZ4ic3XrSyApIcAgILmowz4xGkYJNtN1BdAsd3ujhiCKpS8U3x9OLnxGnSzuSYSi
         8E0QjY6wwF5axTeSbu+YMmxkY2bBxGwk8gNlkalJHSMxpPLQ1c0/s+4RGXydq0RGHEgT
         V8ZQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=S1EkJWl3;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::329 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=LLQk0+08zmaAMGynXpgT36na6ZvoPAm/AG8YDW5XgkA=;
        b=NY6tqz8O6YISGojm/wP0pZ1/RNlx3PxX09bFIzztw2uZ0RjlycF/ExWw91KsizXogq
         WCm43ygZVFGXS9w/Hdy3Wec2BBeQwooWjXa9kLrTjSUs9npmshOOqfwovnMu1dCqyXA2
         gLiplSSyTS0/TP//r+5xVvfoYQ3GChCoQbi/md+0pO6LEiCPxVxjLPT87APVU8fkEQ7z
         7pBoEWNlgPHT1UaUOW8k7QwB3zmhx2CNuJhf+uysAYDuPiNP+MlbME6+DWFTl7ai+fm/
         MG6Ukm0TRe34nWyFLZq5egqEXNC5W0txny3BQmO+VbFx6pap4g49V2FpjJ9JKY9Gy6U5
         a/gg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=LLQk0+08zmaAMGynXpgT36na6ZvoPAm/AG8YDW5XgkA=;
        b=C1aiaQ7tHCISyaWiHsfDKdhjvZjTF7ezs1ZHCPz9fmoeaHpYGTkkIfQCYqn+RIzt4+
         KCxcLURCqdqB2J1zOlJQQZT4qg2lna/PZWpWeFxCI7sHNt7hLQvc8H6rf95rSyyEwCXZ
         ZIp8Mv1ZkKobQSKrmRgQfarw0vsXzqKbOXmRUgPVvYKGAzEl1tWg/H2CRHDFCWulnZdk
         28HcCQ77mSRwxLCVT3qDyNE8J9Pmbw5T25HRFOQhD1b3tYtebXzsyfCNIa+5kizfW7KL
         JsfWnkT6l0VYDtOPZUfOmx6M74TKbMlXndx3qWw5O4Kc3H5slL1KlQ3PbyIMeV8MSi1G
         Xj3g==
X-Gm-Message-State: AOAM530v2CFxWt2nXzHjq+xsaU0s4+xUfw5Wb1RFyRe4zdz90EenEqON
	ogeuNJu9N891dWe351HNLhM=
X-Google-Smtp-Source: ABdhPJxMzQUEaFiTLa0wPcjUC4QZHbky04irlDc9HVdwYDhA/bwd5j/gHpImfS474/Ko+CCfBjAE8A==
X-Received: by 2002:a5b:ecc:: with SMTP id a12mr2666530ybs.368.1633964427852;
        Mon, 11 Oct 2021 08:00:27 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:a244:: with SMTP id b62ls1619562ybi.3.gmail; Mon, 11 Oct
 2021 08:00:27 -0700 (PDT)
X-Received: by 2002:a25:14d6:: with SMTP id 205mr21436392ybu.93.1633964427373;
        Mon, 11 Oct 2021 08:00:27 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1633964427; cv=none;
        d=google.com; s=arc-20160816;
        b=EoBt07PNcPnGzTvuyvVrYEyrlsFhciFiWCbb0egfykc6pFjMjYugBU80mhNyVwjD9K
         pKXjn63tppmWhkWA6xod/OO7GlRHkNqUiMxiF1T5lFg5r6iNVfixcV/a9+RvzEY5uasI
         QAE4qK2OoQYOT+7ak7gDjWMGJNNknzWVCk0g/j1F1mij5breuvpxJKVsGnqWbCSKSAiA
         ue8bbINdg7yJsnlmk4w4MF4ARwuqFs6liTc3Hctlsh5AE4qgA5/KiGzncihcdUuKPgcA
         d8nErZ2/ctaxG1yswwv83a/xB1iyi4RvzLFcGDn9z8r+20n3/0nKktnf4gyiyFUE4Ugb
         hsTw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=2DGpeO8Luc9doQYqA/bXw4zWcqIaLqf3yim6ESEFJoU=;
        b=BGywrZyZKsh1VZbWTnNu34+xg5y2uGIoaX6uQC3jWebBvrp8l8W1xHXedAbc4XcXzQ
         jg7aUXcYR6WFEWJMTf4nCmR/JMnGfQSP5ngwZQSOeozwsJw2lPSebdzGmuLglDm6jCSn
         dxiK9UPi/9GV7SHsdeGQ1EYWLVbFrJ92KhJ+RhGksgDLsj8wczAmR0jcj77IAgqpRT5G
         +4H+vpJm2TsPC8KLoL65Bge2IcsLrz6mILm147ZpLkwjIlzlH7YxkYNa/+X0tbPFG17r
         d72IImMcSp/w3A8vTellXs2bZTddh3I8pWCMrNm3IeH8IC8zFKJHyt89kKTZc5woY8Kt
         gAFg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=S1EkJWl3;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::329 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x329.google.com (mail-ot1-x329.google.com. [2607:f8b0:4864:20::329])
        by gmr-mx.google.com with ESMTPS id t13si642253ybu.2.2021.10.11.08.00.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 11 Oct 2021 08:00:27 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::329 as permitted sender) client-ip=2607:f8b0:4864:20::329;
Received: by mail-ot1-x329.google.com with SMTP id w12-20020a056830410c00b0054e7ceecd88so4177512ott.2
        for <kasan-dev@googlegroups.com>; Mon, 11 Oct 2021 08:00:27 -0700 (PDT)
X-Received: by 2002:a05:6830:402c:: with SMTP id i12mr7413612ots.319.1633964426757;
 Mon, 11 Oct 2021 08:00:26 -0700 (PDT)
MIME-Version: 1.0
References: <YWLwUUNuRrO7AxtM@arighi-desktop> <CANpmjNOw--ZNyhmn-GjuqU+aH5T98HMmBoCM4z=JFvajC913Qg@mail.gmail.com>
 <YWPaZSX4WyOwilW+@arighi-desktop> <CANpmjNMFFFa=6toZJXqo_9hzv05zoD0aXA4D_K93rfw58cEw3w@mail.gmail.com>
 <YWPjZv7ClDOE66iI@arighi-desktop> <CACT4Y+b4Xmev7uLhASpHnELcteadhaXCBkkD5hO2YNP5M2451g@mail.gmail.com>
 <YWQCknwPcGlOBfUi@arighi-desktop> <YWQJe1ccZ72FZkLB@arighi-desktop>
 <CANpmjNNtCf+q21_5Dj49c4D__jznwFbBFrWE0LG5UnC__B+fKA@mail.gmail.com> <YWRNVTk9N8K0RMst@arighi-desktop>
In-Reply-To: <YWRNVTk9N8K0RMst@arighi-desktop>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 11 Oct 2021 17:00:15 +0200
Message-ID: <CACT4Y+bZGK75S+cyeQda-oHmeDVeownwOj2imQbPYi0dRY18+A@mail.gmail.com>
Subject: Re: BUG: soft lockup in __kmalloc_node() with KFENCE enabled
To: Andrea Righi <andrea.righi@canonical.com>
Cc: Marco Elver <elver@google.com>, Alexander Potapenko <glider@google.com>, kasan-dev@googlegroups.com, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=S1EkJWl3;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::329
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

On Mon, 11 Oct 2021 at 16:42, Andrea Righi <andrea.righi@canonical.com> wrote:
>
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
>
> [21383.189976] BUG: kernel NULL pointer dereference, address: 0000000000000098
> [21383.190633] #PF: supervisor read access in kernel mode
> [21383.191072] #PF: error_code(0x0000) - not-present page
> [21383.191529] PGD 0 P4D 0
> [21383.191771] Oops: 0000 [#1] SMP NOPTI
> [21383.192113] CPU: 0 PID: 0 Comm: swapper/0 Not tainted 5.15-rc4
> [21383.192757] Hardware name: QEMU Standard PC (Q35 + ICH9, 2009), BIOS 1.14.0-2 04/01/2014
> [21383.193414] RIP: 0010:wb_timer_fn+0x44/0x3c0
> [21383.193855] Code: 41 8b 9c 24 98 00 00 00 41 8b 94 24 b8 00 00 00 41 8b 84 24 d8 00 00 00 4d 8b 74 24 28 01 d3 01 c3 49 8b 44 24 60 48 8b 40 78 <4c> 8b b8 98 00 00 00 4d 85 f6 0f 84 c4 00 00 00 49 83 7c 24 30 00
> [21383.195366] RSP: 0018:ffffbcd140003e68 EFLAGS: 00010246
> [21383.195842] RAX: 0000000000000000 RBX: 0000000000000000 RCX: 0000000000000004
> [21383.196425] RDX: 0000000000000000 RSI: 0000000000000000 RDI: ffff9a3521f4fd80
> [21383.197010] RBP: ffffbcd140003e90 R08: 0000000000000000 R09: 0000000000000000
> [21383.197594] R10: 0000000000000004 R11: 000000000000000f R12: ffff9a34c75c4900
> [21383.198178] R13: ffff9a34c3906de0 R14: 0000000000000000 R15: ffff9a353dc18c00
> [21383.198763] FS:  0000000000000000(0000) GS:ffff9a353dc00000(0000) knlGS:0000000000000000
> [21383.199558] CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
> [21383.200212] CR2: 0000000000000098 CR3: 0000000005f54000 CR4: 00000000000006f0
> [21383.200930] Call Trace:
> [21383.201210]  <IRQ>
> [21383.201461]  ? blk_stat_free_callback_rcu+0x30/0x30
> [21383.202692]  blk_stat_timer_fn+0x138/0x140
> [21383.203180]  call_timer_fn+0x2b/0x100
> [21383.203666]  __run_timers.part.0+0x1d1/0x240
> [21383.204227]  ? kvm_clock_get_cycles+0x11/0x20
> [21383.204815]  ? ktime_get+0x3e/0xa0
> [21383.205309]  ? native_apic_msr_write+0x2c/0x30
> [21383.205914]  ? lapic_next_event+0x20/0x30
> [21383.206412]  ? clockevents_program_event+0x94/0xf0
> [21383.206873]  run_timer_softirq+0x2a/0x50
> [21383.207260]  __do_softirq+0xcb/0x26f
> [21383.207647]  irq_exit_rcu+0x8c/0xb0
> [21383.208010]  sysvec_apic_timer_interrupt+0x7c/0x90
> [21383.208464]  </IRQ>
> [21383.208713]  asm_sysvec_apic_timer_interrupt+0x12/0x20
>
> I think that systemd autotest used to use -enable-kvm, but then they
> removed it, because it was introducing too many problems in the nested
> KVM context. I'm not sure about the nature of those problems though, I
> can investigate a bit and see if I can understand what they were
> exactly.

This looks like just a plain bug in wb_timer_fn, not something related
to virtualization.
Do you have this fix?
https://syzkaller.appspot.com/bug?extid=aa0801b6b32dca9dda82

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BbZGK75S%2BcyeQda-oHmeDVeownwOj2imQbPYi0dRY18%2BA%40mail.gmail.com.
