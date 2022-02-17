Return-Path: <kasan-dev+bncBCXKTJ63SAARB7EBXKIAMGQEDNHCSUA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13b.google.com (mail-il1-x13b.google.com [IPv6:2607:f8b0:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id 56E394BA6BA
	for <lists+kasan-dev@lfdr.de>; Thu, 17 Feb 2022 18:08:14 +0100 (CET)
Received: by mail-il1-x13b.google.com with SMTP id c1-20020a928e01000000b002bec519e98fsf2333288ild.5
        for <lists+kasan-dev@lfdr.de>; Thu, 17 Feb 2022 09:08:14 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1645117693; cv=pass;
        d=google.com; s=arc-20160816;
        b=RgvX845yySoA9jjGkqTWulRrV3Z7xrqLDwHF7N1sFlsSS6/SjjYNJxkr27s9z6rMWa
         BaHWHb/cTGYUpxnL4s6Z+bdT5BkEl4JAswsSgAbU0E5XCIPrcCIT6orAngGZ3v99C1l8
         QvVIth8S93NfmYc43DiwFhn5MXcKBVXW/ZGwK1mV8tnKSgwQmyb1xI1Cj7vLYY4SZEj/
         akh9c5MqE2uv1oXc5/95m1YnMJNuRMjycbAhr6Zw2S3It12FO9bCmq41DGz+XPNnWOCF
         Ycv333CZInX7IQewkNk8QjZ1EY2G1Y8sI/TPYX9acRl/DsfDBfxkyqnAVkF72hdPoumb
         jOMA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=8/rbO3XI5RPhCiUL4UY08Ps/coZo+RJ3n7w10nsho+4=;
        b=X4rgNG2wtuTnJT1guPSQLWm5VlCUboJlGb8kAGgn8elsu3M7xmU/dxAdUpKgUEwUqy
         ZttzGrwxUkO4j27mQ3PuSDmLmWcM6ZZEQ92AAToP1m/pf1MrfgQ9XE5qBd+xccFN0pYE
         +Hc/RLw0NLyIvIhyg7wy2/1AJVWzr/c2T4RZXCeJp5JEGCqrTvaDhzMTNzrY9QC3Jbx+
         BUATxyQyZiV7YSvn0zi6+krg6WIvrSZ14L0NKyiUX7QPVb6UhDMbRuUHgbtd0GNhlTCy
         RvbeBayCoah4NxDzADl+6aksYhDzAEwvDQLZ3335Fmz3QJjq3IRKdYX2sXxucQYTYo89
         7T4Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="AQ/k55Oj";
       spf=pass (google.com: domain of nogikh@google.com designates 2607:f8b0:4864:20::d2f as permitted sender) smtp.mailfrom=nogikh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=8/rbO3XI5RPhCiUL4UY08Ps/coZo+RJ3n7w10nsho+4=;
        b=QXpCujTWWATIB1DaDGTjEocOvYRoa3KJ+i9SmtBa61ZnUCg/M0AcM0DO5SBdCZ5F+H
         C8Gd3oSBb5CAVDSM9sP4JoJmSRWh1eQfmw8LEbQhVTM3aCy8NKr87iT5oCOO7XZ4YTxQ
         jT31Yuf7D9qOik4ZFEPuaJtHUGyv/zCRLUICNPdbdv8CgcPLwpnKzSwtZ7n4NorOf7l4
         M+/VCMx/JQ7Fze52OhUyCqWeit+UgjLO/ixPFKDhz4QJLz7XqOxwGfNqYb+tsKhJFBNb
         YAVj3+MkSLo7nzVFW0OUBSdTe3BYiFqAyx7B4GPhQJ8Y0ukIVOuck0tIrIdNgMcISS/u
         5p2w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=8/rbO3XI5RPhCiUL4UY08Ps/coZo+RJ3n7w10nsho+4=;
        b=mbduluOIpZxSdEBAVVN5ubDW3DK1NRnB79jADhVmMnotrTJfzIGzOssNv0r5z8DmPX
         PRJh2kV/6m2nX9B3UtilxJ/hfcFiiY/DikzqExFfZIOjJOXbOKGc07Y5R4z0MPbCLXlf
         ATT/xAMPbdR++1TuCeTG6MD6Im8kvAbGdOBjq1fE4cuDNOZTkjN7lBQzDedwkiAINtVY
         LDZGZ/CHu0IPqgbff3h6co9Jaq6v6QSLls/0w3MzU4mShn5yRt/VLrjPHkmuwMCz1ynd
         PYuypXZMEalUySsFrWK2eWgps/lLPbnU+N//nRLwgGqNMlCVuyFjptlPegD6Om50GE+j
         LECw==
X-Gm-Message-State: AOAM530TGBVZpZA7/DveSELpqnpR8BXNhJvKhJ1smIXvfAM0QZgVA+Lg
	G8QHK21cUFG+O1ELXN4QIuA=
X-Google-Smtp-Source: ABdhPJyM9BgvfzF3TCMKS1RQGuxfAZpYZNq2j+zpSdZlgks1CxASy277OeET2p0/O2gbKWsoJh2fMA==
X-Received: by 2002:a02:b903:0:b0:30e:49cb:e65c with SMTP id v3-20020a02b903000000b0030e49cbe65cmr2467195jan.164.1645117692877;
        Thu, 17 Feb 2022 09:08:12 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:1c28:b0:2be:8de1:3172 with SMTP id
 m8-20020a056e021c2800b002be8de13172ls700899ilh.0.gmail; Thu, 17 Feb 2022
 09:08:12 -0800 (PST)
X-Received: by 2002:a92:c269:0:b0:2be:795d:abb2 with SMTP id h9-20020a92c269000000b002be795dabb2mr2662784ild.46.1645117692158;
        Thu, 17 Feb 2022 09:08:12 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1645117692; cv=none;
        d=google.com; s=arc-20160816;
        b=dIR6qeZfolDX5LGOyY61ATUhFyVyGzwvnWdcCLXByBbjZUXwKHZBskMDq4AKPHCHjD
         MSayuzw4o0xCiqpuyuZf/L7Tl3EJdOYfQhD7E1/umAOCQl/JJbhANU46w125KLE3Z8/U
         TxcaL4ikq0ANM3Z7EzzTVbjqxZyJNpSE+Z6mGm7GJl9b0X6LGInh0GzO1smBionwYEYS
         /SSA/ChtbaD4LwWoWq7ApuvxNKKbMgqxRbw/cqdgLBOo2M7+YMOuCVv8Dkgtv9wxyZl8
         kn/+E43pqBg++iD35o4HKluPCDPySZ8Won4i/IiNmOwoDDbzEUC/PdZqjC230UBOi6qb
         5STg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=M11Cv6Sf/j5dBAWER/x//EgaASJgRbtSRPsqwYtb7M4=;
        b=wFqGQwHvVJi+km3GMkzgkXIvJEEXX11V5+HePFllfNCEkPXwAMZW+oWsUwHUIGA9jH
         T8FAReEplw7ckpHtM9prDp0J2A/kqkLsIK3IwaqowHFGab7fQQTz0smK17eYaoVQRq/x
         tyS+PsdSuImG9igIX9WUHNWgfsEv+3mMJhHZJzOvweQK9aJ+fXzGS7sZQGhnk9rT7ljz
         6Z7evt7Jao1ZgYBXwMMExkhv1bUur8FPu3mUbOmneKCOIOcyjtoE4AagZSHpJTMHZiwk
         4BeSj0BMmL3T0DLim0sTWSHDfBF9zdxk8F44nsl00yOupICGYAB2Rt8PS3w0w5J6xqdS
         OkPg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="AQ/k55Oj";
       spf=pass (google.com: domain of nogikh@google.com designates 2607:f8b0:4864:20::d2f as permitted sender) smtp.mailfrom=nogikh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-io1-xd2f.google.com (mail-io1-xd2f.google.com. [2607:f8b0:4864:20::d2f])
        by gmr-mx.google.com with ESMTPS id i1si396155ilv.3.2022.02.17.09.08.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 17 Feb 2022 09:08:12 -0800 (PST)
Received-SPF: pass (google.com: domain of nogikh@google.com designates 2607:f8b0:4864:20::d2f as permitted sender) client-ip=2607:f8b0:4864:20::d2f;
Received: by mail-io1-xd2f.google.com with SMTP id h5so4458961ioj.3
        for <kasan-dev@googlegroups.com>; Thu, 17 Feb 2022 09:08:12 -0800 (PST)
X-Received: by 2002:a02:6308:0:b0:30e:7e14:848b with SMTP id
 j8-20020a026308000000b0030e7e14848bmr2446771jac.139.1645117690194; Thu, 17
 Feb 2022 09:08:10 -0800 (PST)
MIME-Version: 1.0
References: <00000000000038779505d5d8b372@google.com> <CANp29Y7WjwXwgxPrNq0XXjXPu+wGFqTreh9gry=O6aE7+cKpLQ@mail.gmail.com>
 <CA+zEjCvu76yW7zfM+qJUe+t5y23oPdzR4KDV1mOdqH8bB4GmTw@mail.gmail.com>
 <CACT4Y+arufrRgwmN66wUU+_FGxMy-sTkjMQnRN8U2H2tQuhB7A@mail.gmail.com>
 <a0769218-c84a-a1d3-71e7-aefd40bf54fe@ghiti.fr> <CANp29Y4WMhsE_-VWvNbwq18+qvb1Qc-ES80h_j_G-N_hcAnRAw@mail.gmail.com>
 <CANp29Y4ujmz901aE9oiBDx9dYWHti4-Jw=6Ewtotm6ck6MN9FQ@mail.gmail.com>
 <CACT4Y+ZvStiHLYBOcPDoAJnk8hquXwm9BgjQTv=APwh7AvgEUQ@mail.gmail.com>
 <CANp29Y56Or0V1AG7rzBfV_ZTph2Crg4JKKHiuw1kcGFFxeWqiQ@mail.gmail.com>
 <CANp29Y5+MuhKAzVxzEDb_k9voXmKWrUFx8k4wnW5=2+5enVFVA@mail.gmail.com>
 <CA+zEjCtvaT0YsxxUgnEGM+V4b5sWuCAs3=3J+Xocf580uT3t1g@mail.gmail.com> <CA+zEjCs1FEUTcM+pgV+_MZnixSO5c2hexZFxGxuCQWc2ZMQiRg@mail.gmail.com>
In-Reply-To: <CA+zEjCs1FEUTcM+pgV+_MZnixSO5c2hexZFxGxuCQWc2ZMQiRg@mail.gmail.com>
From: "'Aleksandr Nogikh' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 17 Feb 2022 18:07:59 +0100
Message-ID: <CANp29Y4rDSjrfTOxcQqwh+Qm+ocR0v6Oxr7EkFxScf+24M1tNA@mail.gmail.com>
Subject: Re: [syzbot] riscv/fixes boot error: can't ssh into the instance
To: Alexandre Ghiti <alexandre.ghiti@canonical.com>
Cc: Dmitry Vyukov <dvyukov@google.com>, Alexandre Ghiti <alex@ghiti.fr>, linux-riscv@lists.infradead.org, 
	kasan-dev <kasan-dev@googlegroups.com>, Palmer Dabbelt <palmer@dabbelt.com>, 
	syzbot <syzbot+330a558d94b58f7601be@syzkaller.appspotmail.com>, 
	LKML <linux-kernel@vger.kernel.org>, syzkaller-bugs@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: nogikh@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b="AQ/k55Oj";       spf=pass
 (google.com: domain of nogikh@google.com designates 2607:f8b0:4864:20::d2f as
 permitted sender) smtp.mailfrom=nogikh@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Aleksandr Nogikh <nogikh@google.com>
Reply-To: Aleksandr Nogikh <nogikh@google.com>
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

Hi Alex,

On Thu, Feb 17, 2022 at 5:53 PM Alexandre Ghiti
<alexandre.ghiti@canonical.com> wrote:
>
> Aleksandr,
>
> On Wed, Feb 16, 2022 at 5:58 PM Alexandre Ghiti
> <alexandre.ghiti@canonical.com> wrote:
> >
> > First, thank you for working on this.
> >
> > On Wed, Feb 16, 2022 at 5:17 PM Aleksandr Nogikh <nogikh@google.com> wrote:
> > >
> > > If I use just defconfig + DEBUG_VIRTUAL, without any KASAN, it begins
> > > to boot, but overwhelms me with tons of `virt_to_phys used for
> > > non-linear address:` errors.
> > >
> > > Like that
> > >
> > > [    2.701271] virt_to_phys used for non-linear address:
> > > 00000000b59e31b6 (0xffffffff806c2000)
> > > [    2.701727] WARNING: CPU: 0 PID: 1 at arch/riscv/mm/physaddr.c:16
> > > __virt_to_phys+0x7e/0x86
> > > [    2.702207] Modules linked in:
> > > [    2.702393] CPU: 0 PID: 1 Comm: swapper/0 Tainted: G        W
> > >   5.17.0-rc1 #1
> > > [    2.702806] Hardware name: riscv-virtio,qemu (DT)
> > > [    2.703051] epc : __virt_to_phys+0x7e/0x86
> > > [    2.703298]  ra : __virt_to_phys+0x7e/0x86
> > > [    2.703547] epc : ffffffff80008448 ra : ffffffff80008448 sp :
> > > ffff8f800021bde0
> > > [    2.703977]  gp : ffffffff80ed9b30 tp : ffffaf8001230000 t0 :
> > > ffffffff80eea56f
> > > [    2.704704]  t1 : ffffffff80eea560 t2 : 0000000000000000 s0 :
> > > ffff8f800021be00
> > > [    2.705153]  s1 : ffffffff806c2000 a0 : 000000000000004f a1 :
> > > ffffffff80e723d8
> > > [    2.705555]  a2 : 0000000000000010 a3 : fffffffffffffffe a4 :
> > > 0000000000000000
> > > [    2.706027]  a5 : 0000000000000000 a6 : 0000000000000005 a7 :
> > > ffffffffffffffff
> > > [    2.706474]  s2 : ffffffff80b80b08 s3 : 00000000000000c2 s4 :
> > > ffffffff806c2000
> > > [    2.706891]  s5 : ffffffff80edba10 s6 : ffffffff80edb960 s7 :
> > > 0000000000000001
> > > [    2.707290]  s8 : 00000000000000ff s9 : ffffffff80b80b40 s10:
> > > 00000000000000cc
> > > [    2.707689]  s11: ffffaf807e1fcf00 t3 : 0000000000000076 t4 :
> > > ffffffffffffffff
> > > [    2.708092]  t5 : 00000000000001f2 t6 : ffff8f800021bb48
> > > [    2.708433] status: 0000000000000120 badaddr: 0000000000000000
> > > cause: 0000000000000003
> > > [    2.708919] [<ffffffff8011416a>] free_reserved_area+0x72/0x19a
> > > [    2.709296] [<ffffffff80003a5a>] free_initmem+0x6c/0x7c
> > > [    2.709648] [<ffffffff805f60c8>] kernel_init+0x3a/0x10a
> > > [    2.709993] [<ffffffff80002fda>] ret_from_exception+0x0/0xc
> > > [    2.710310] ---[ end trace 0000000000000000 ]---
> > >
> >
> > I was able to reproduce this: the first one regarding init_zero_pfn is
> > legit but not wrong, I have to check when it was introduced and how to
> > fix this.
> > Regarding the huge batch that follows, at first sight, I would say
> > this is linked to my sv48 patchset but that does not seem important as
> > the address is a kernel mapping address so the use of virt_to_phys is
> > right.
> >
> > > On Wed, Feb 16, 2022 at 5:09 PM Aleksandr Nogikh <nogikh@google.com> wrote:
> > > >
> > > > On Wed, Feb 16, 2022 at 12:56 PM Dmitry Vyukov <dvyukov@google.com> wrote:
> > > > >
> > > > > On Wed, 16 Feb 2022 at 12:47, Aleksandr Nogikh <nogikh@google.com> wrote:
> > > > > >
> > > > > > On Wed, Feb 16, 2022 at 11:37 AM Aleksandr Nogikh <nogikh@google.com> wrote:
> > > > > > >
> > > > > > > Hi Alex,
> > > > > > >
> > > > > > > On Wed, Feb 16, 2022 at 5:14 AM Alexandre Ghiti <alex@ghiti.fr> wrote:
> > > > > > > >
> > > > > > > > Hi Dmitry,
> > > > > > > >
> > > > > > > > On 2/15/22 18:12, Dmitry Vyukov wrote:
> > > > > > > > > On Wed, 2 Feb 2022 at 14:18, Alexandre Ghiti
> > > > > > > > > <alexandre.ghiti@canonical.com> wrote:
> > > > > > > > >> Hi Aleksandr,
> > > > > > > > >>
> > > > > > > > >> On Wed, Feb 2, 2022 at 12:08 PM Aleksandr Nogikh <nogikh@google.com> wrote:
> > > > > > > > >>> Hello,
> > > > > > > > >>>
> > > > > > > > >>> syzbot has already not been able to fuzz its RISC-V instance for 97
> > > > > > > > >> That's a longtime, I'll take a look more regularly.
> > > > > > > > >>
> > > > > > > > >>> days now because the compiled kernel cannot boot. I bisected the issue
> > > > > > > > >>> to the following commit:
> > > > > > > > >>>
> > > > > > > > >>> commit 54c5639d8f507ebefa814f574cb6f763033a72a5
> > > > > > > > >>> Author: Alexandre Ghiti <alexandre.ghiti@canonical.com>
> > > > > > > > >>> Date:   Fri Oct 29 06:59:27 2021 +0200
> > > > > > > > >>>
> > > > > > > > >>>      riscv: Fix asan-stack clang build
> > > > > > > > >>>
> > > > > > > > >>> Apparently, the problem appears on GCC-built RISC-V kernels with KASAN
> > > > > > > > >>> enabled. In the previous message syzbot mentions
> > > > > > > > >>> "riscv64-linux-gnu-gcc (Debian 10.2.1-6) 10.2.1 20210110, GNU ld (GNU
> > > > > > > > >>> Binutils for Debian) 2.35.2", but the issue also reproduces finely on
> > > > > > > > >>> a newer GCC compiler: "riscv64-linux-gnu-gcc (Debian 11.2.0-10)
> > > > > > > > >>> 11.2.0, GNU ld (GNU Binutils for Debian) 2.37".
> > > > > > > > >>> For convenience, I also duplicate the .config file from the bot's
> > > > > > > > >>> message: https://syzkaller.appspot.com/x/.config?x=522544a2e0ef2a7d
> > > > > > > > >>>
> > > > > > > > >>> Can someone with KASAN and RISC-V expertise please take a look?
> > > > > > > > >> I'll take a look at that today.
> > > > > > > > >>
> > > > > > > > >> Thanks for reporting the issue,
> > > > > > > > >
> > > > > > > >
> > > > > > > > I took a quick look, not enough to fix it but I know the issue comes
> > > > > > > > from the inline instrumentation, I have no problem with the outline
> > > > > > > > instrumentation. I need to find some cycles to work on this, my goal is
> > > > > > > > to fix this for 5.17.
> > > > > > >
> > > > > > > Thanks for the update!
> > > > > > >
> > > > > > > Can you please share the .config with which you tested the outline
> > > > > > > instrumentation?
> > > > > > > I updated the syzbot config to use KASAN_OUTLINE instead of KASAN_INLINE,
> > > > > > > but it still does not boot :(
> > > > > > >
> > > > > > > Here's what I used:
> > > > > > > https://gist.github.com/a-nogikh/279c85c2d24f47efcc3e865c08844138
> > > > > >
> > > > > > Update: it doesn't boot with that big config, but boots if I generate
> > > > > > a simple one with KASAN_OUTLINE:
> > > > > >
> > > > > > make defconfig ARCH=riscv CROSS_COMPILE=riscv64-linux-gnu-
> > > > > > ./scripts/config -e KASAN -e KASAN_OUTLINE
> > > > > > make olddefconfig ARCH=riscv CROSS_COMPILE=riscv64-linux-gnu-
> > > > > >
> > > > > > And it indeed doesn't work if I use KASAN_INLINE.
> > > > >
> > > > > It may be an issue with code size. Full syzbot config + KASAN + KCOV
> > > > > produce hugely massive .text. It may be hitting some limitation in the
> > > > > bootloader/kernel bootstrap code.
> >
> > I took a quick glance and it traps on a KASAN address that is not
> > mapped, either because it is too soon or because the mapping failed
> > somehow.
> >
> > I'll definitely dive into that tomorrow, sorry for being slow here and
> > thanks again for all your work, that helps a lot.
> >
> > Thanks,
> >
> > Alex
> >
> > > >
> > > > I bisected the difference between the config we use on syzbot and the
> > > > simple one that was generated like I described above.
> > > > Turns out that it's the DEBUG_VIRTUAL config that makes the difference.
> > > >
> > > > make defconfig ARCH=riscv CROSS_COMPILE=riscv64-linux-gnu-
> > > > ./scripts/config -e KASAN -e KASAN_OUTLINE -e DEBUG_VIRTUAL
> > > > make olddefconfig ARCH=riscv CROSS_COMPILE=riscv64-linux-gnu-
> > > >
> > > > And the resulting kernel does not boot.
> > > > My env: the `riscv/fixes` branch, commit
> > > > 6df2a016c0c8a3d0933ef33dd192ea6606b115e3, qemu 6.2.0.
>
> I fixed a few things today: KASAN + SPARSE_VMEMMAP, DEBUG_VIRTUAL and
> maybe KASAN  + KCOV.
>
> With those small fixes, I was able to boot your large dotconfig with
> KASAN_OUTLINE, the inline version still fails, this is my next target
> :)
> I'll push that tomorrow!

Awesome, thank you very much!
Looking forward to finally seeing the instance run :)

--
Best Regards,
Aleksandr

>
> Thanks again,
>
> Alex

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANp29Y4rDSjrfTOxcQqwh%2BQm%2BocR0v6Oxr7EkFxScf%2B24M1tNA%40mail.gmail.com.
