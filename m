Return-Path: <kasan-dev+bncBDQ7NGWH7YJRBWH5YGKAMGQEA5JZADY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33c.google.com (mail-wm1-x33c.google.com [IPv6:2a00:1450:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id B1EBB535A7C
	for <lists+kasan-dev@lfdr.de>; Fri, 27 May 2022 09:33:44 +0200 (CEST)
Received: by mail-wm1-x33c.google.com with SMTP id l15-20020a05600c1d0f00b003973901d3b4sf2008892wms.2
        for <lists+kasan-dev@lfdr.de>; Fri, 27 May 2022 00:33:44 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1653636824; cv=pass;
        d=google.com; s=arc-20160816;
        b=NZyJj2MyndsrvRLKRup5nbuIs5SbIXT/kCzQ7flL3cdkgQzmTCmTvI6x7X3r1Ycrqs
         /JCtwdDkGJtpwbNRB0d10hjqpB+x4BH4WmouQNg3RI7rh80mxaPq8cE8b/mmDe4042BV
         Y9+0tcvclGt1vdjmSKBJYglpx5Kw7jlvNqZ8kLSq+xxr1DmAvMDoGYgbzAMnlJeXd/z8
         uq+pjwzIcmcRyZmhfChuf9l+qxnKgQoURcpcc+i48HALhwSZADrjtRmdpJJn4FHVDq7I
         2dIaDIglYPo+uG2i4ZAJrlIrHCxvMTw939PrwPeMe9jj7wiviyB/1WPmpZ+oozS2lH5S
         L99w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=w9YDKUZwB1zY04uYx98/lVeEia/cMfKgAwFaJIrtU7g=;
        b=zWoGgW+mN3Dt41w6uLv8j9Bigbo7R975GwZeQTeisHNNJnSMgXgEdRgEPUW2iemjde
         3hQwhQrbyScsGWwgXmSdQdha9qjg/wLtayR8kOAzhIIXPBHyiXLTCA02TYyGxYj4ywPH
         iQOHLGDLoKTbrH0iL5CU+8bJC0zcUh0X9GBLG/YpFKPVn6chjPTWmMkV/A4nZhTz1MV4
         lwsnMnldLbdYWjK1wTG5LI1fEYfZMKyhGdmrp4AKbdTiR2NG7rvyFsvBBI26Mo7ua1ZU
         EFz3d2jBXGXgtmFecBF27cWmDV7Imxw/4GNyKBakz/wwXume2Kv55K3FgY3px6Eh8bSv
         Dozw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@canonical.com header.s=20210705 header.b=XC+BG864;
       spf=pass (google.com: domain of alexandre.ghiti@canonical.com designates 185.125.188.122 as permitted sender) smtp.mailfrom=alexandre.ghiti@canonical.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=canonical.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=w9YDKUZwB1zY04uYx98/lVeEia/cMfKgAwFaJIrtU7g=;
        b=LjOJxr8RjgrY4qTaHP28I+EaZdVo7dJX/nJF12tN5E254Wi5Tkx17lfyuMyZlIk9ZQ
         rV/eDgY2Sc1GBKYKmZt/+duRUs0En7aSFnIXEYrzDnfq3jkF/HE6LJYnIxly/ztcdg7D
         lmPuoyMRmJlwmGMEC9/ILCZ6d1GTjcqxdR96pqoWFo1tXwjhHC4F/dUDfUsWPa7QKeqt
         W3BUpMJiSKjsr42ZEL7KbvL/1XpzjFm0Ma+CH3+T0YVwPWuCPLSI6jVzNzDHr0PGlYFr
         N3hkNCbl+KHaglkWzHK/Mo3zwe3kdd9LEe4OZ0nYw7Efxj9RWz/UNv7xeZeURZCfFyUQ
         q9SA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=w9YDKUZwB1zY04uYx98/lVeEia/cMfKgAwFaJIrtU7g=;
        b=76GYpjp+HtTRqHB8qz6rLpv4fybJ3ye+xNJfHJlK6x8eLiMpl+kvK9k4rqt2rflzXw
         WDiExP3XPhYZBKBcSY6pjfNnMMINxF5+TI4bW6DdJxABHIsyZUWmtKierEE978dbAZdL
         Zshf55sL0GsSprgRs5u9wR1TMiUrHEbuJYI9hHAyf8UcfZ2PUGAvTrkT4ncSXimzc9Tn
         SlekiKzprRTrh9E/KiW84fty0dV8S7fkk8ef4sMBDrh5zJMcR1y5YnQD0MFtCDej79nL
         pqUd11a2b2rEI68ootqCIV4tGH6QFic47Kpi/v4nDfcH9c6z+/QzDugZe2g0rBXIsU0G
         ebAA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533b53pLVINC7tSytUsqS6jXpOsa8o28HFF7BynY31Ab33Fj9UZj
	BztKSIkAzwq6hinh2tTDeVE=
X-Google-Smtp-Source: ABdhPJzsnV1pk3+3fnzqarU1fX+RGX5roESWt3gh3pnza6GsaYo4ys7nhkKK/O4vzFOox3DMlyx7NA==
X-Received: by 2002:adf:dfc1:0:b0:210:dc1:f387 with SMTP id q1-20020adfdfc1000000b002100dc1f387mr4809975wrn.700.1653636824351;
        Fri, 27 May 2022 00:33:44 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:144a:b0:20f:f1e7:c71c with SMTP id
 v10-20020a056000144a00b0020ff1e7c71cls16556040wrx.0.gmail; Fri, 27 May 2022
 00:33:43 -0700 (PDT)
X-Received: by 2002:a05:6000:15c1:b0:20f:c1d3:8a89 with SMTP id y1-20020a05600015c100b0020fc1d38a89mr27614335wry.287.1653636823316;
        Fri, 27 May 2022 00:33:43 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1653636823; cv=none;
        d=google.com; s=arc-20160816;
        b=x46mmJLc92TacvxU49Zj6N2UAJeWLcKzNXo/u7AxUsxoEi0fnS9kPBi7qiIJ5njp6N
         wBw877c9H770UToEJr7o14QaQJa9GykbdpKuAwsokcZhhhDFaCDob2twEVG8hY/qAPet
         /TiXAXbQm7ve/zg6mIS2iLslPm8w0lfzJlGj10e50yfcsp+bVaUAXe8FS1f2gaRD9cDO
         pLkAGhrbbIe6cm3XZBk52i9MaSICCgxQb6LPsr9JQEdL9XOkTv05ZsGvODxZXANX8KSX
         VktpHbFEwzCSrerAdfBgqPhQK7CBigLzfUcaN4Ui5HtinbvlE6MNSo/75VlsK0HLCIGv
         SHqg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=1gt57rBQUC/dMg2ypIptzesOq/kaLx2s804Le0JNYS4=;
        b=k4r+Bb46Gx336WGvCMp9RVsXn7cOSoRC7tF+dHuhAxFYrCYcY3IpqqJ76CabhATsO6
         qYF7gwquvMDVEaYU0bLqqR/8sJRxoPmQTstv2smLQEiMRWX1sJeCcb+/eH0UXbZXiA6R
         C/o9G/8OcO0vnQ/Dy4JIu16A/bcQOgaBI/DWxdA824SUEflTsQjxJBsNEqKp/RMUd8+r
         gk5vrcVZum3ZFn7dfThyqPo2lFga1rYBtDNHmiTCLO8UFDPTaxAYgjHNpcTdbOaB5L5P
         XmXy1eoyn0LN1lwNiCOhZyIrdKN8ETq7Wq/4ysH2IOJHfGdRRtuJ+xzzBqQjaMnMdUoj
         suaQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@canonical.com header.s=20210705 header.b=XC+BG864;
       spf=pass (google.com: domain of alexandre.ghiti@canonical.com designates 185.125.188.122 as permitted sender) smtp.mailfrom=alexandre.ghiti@canonical.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=canonical.com
Received: from smtp-relay-internal-0.canonical.com (smtp-relay-internal-0.canonical.com. [185.125.188.122])
        by gmr-mx.google.com with ESMTPS id m10-20020a5d6a0a000000b002100e879b18si50973wru.2.2022.05.27.00.33.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 27 May 2022 00:33:43 -0700 (PDT)
Received-SPF: pass (google.com: domain of alexandre.ghiti@canonical.com designates 185.125.188.122 as permitted sender) client-ip=185.125.188.122;
Received: from mail-ed1-f69.google.com (mail-ed1-f69.google.com [209.85.208.69])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-relay-internal-0.canonical.com (Postfix) with ESMTPS id AE2053F325
	for <kasan-dev@googlegroups.com>; Fri, 27 May 2022 07:33:42 +0000 (UTC)
Received: by mail-ed1-f69.google.com with SMTP id e3-20020a056402330300b0042b903637bbso2543282eda.3
        for <kasan-dev@googlegroups.com>; Fri, 27 May 2022 00:33:42 -0700 (PDT)
X-Received: by 2002:a17:907:7745:b0:6f3:674a:339 with SMTP id kx5-20020a170907774500b006f3674a0339mr37163399ejc.207.1653636820640;
        Fri, 27 May 2022 00:33:40 -0700 (PDT)
X-Received: by 2002:a17:907:7745:b0:6f3:674a:339 with SMTP id
 kx5-20020a170907774500b006f3674a0339mr37163376ejc.207.1653636820274; Fri, 27
 May 2022 00:33:40 -0700 (PDT)
MIME-Version: 1.0
References: <00000000000038779505d5d8b372@google.com> <CANp29Y7WjwXwgxPrNq0XXjXPu+wGFqTreh9gry=O6aE7+cKpLQ@mail.gmail.com>
 <CA+zEjCvu76yW7zfM+qJUe+t5y23oPdzR4KDV1mOdqH8bB4GmTw@mail.gmail.com>
 <CACT4Y+arufrRgwmN66wUU+_FGxMy-sTkjMQnRN8U2H2tQuhB7A@mail.gmail.com>
 <a0769218-c84a-a1d3-71e7-aefd40bf54fe@ghiti.fr> <CANp29Y4WMhsE_-VWvNbwq18+qvb1Qc-ES80h_j_G-N_hcAnRAw@mail.gmail.com>
 <CANp29Y4ujmz901aE9oiBDx9dYWHti4-Jw=6Ewtotm6ck6MN9FQ@mail.gmail.com>
 <CACT4Y+ZvStiHLYBOcPDoAJnk8hquXwm9BgjQTv=APwh7AvgEUQ@mail.gmail.com>
 <CANp29Y56Or0V1AG7rzBfV_ZTph2Crg4JKKHiuw1kcGFFxeWqiQ@mail.gmail.com>
 <CANp29Y5+MuhKAzVxzEDb_k9voXmKWrUFx8k4wnW5=2+5enVFVA@mail.gmail.com>
 <CA+zEjCtvaT0YsxxUgnEGM+V4b5sWuCAs3=3J+Xocf580uT3t1g@mail.gmail.com>
 <CA+zEjCs1FEUTcM+pgV+_MZnixSO5c2hexZFxGxuCQWc2ZMQiRg@mail.gmail.com>
 <CANp29Y4rDSjrfTOxcQqwh+Qm+ocR0v6Oxr7EkFxScf+24M1tNA@mail.gmail.com>
 <CA+zEjCtB0rTuNAJkrM2q3JQL7D-9fAXBo0Ud0w__gy9CAfo_Ag@mail.gmail.com>
 <CACT4Y+Z=3MWEhVUH3mAH150XpOmhdjsGPOHoP1nvBcBwU_sphQ@mail.gmail.com>
 <5e702296-9ce0-f1e6-dae8-cc719bc040b9@ghiti.fr> <CAOnJCULgP_-D3cY2m39k9N912Q55FS7X9JcrRVoUt0GC92tx7w@mail.gmail.com>
 <CAOnJCUKBWx+wEKaq8WOPC1j7jgn38iWcrTh4gO+FzfF-mhPkQg@mail.gmail.com>
In-Reply-To: <CAOnJCUKBWx+wEKaq8WOPC1j7jgn38iWcrTh4gO+FzfF-mhPkQg@mail.gmail.com>
From: Alexandre Ghiti <alexandre.ghiti@canonical.com>
Date: Fri, 27 May 2022 09:33:29 +0200
Message-ID: <CA+zEjCuK7NitU_tdjBo+qmhkN_qmH=NCryffb466E7ebVq0GDw@mail.gmail.com>
Subject: Re: [syzbot] riscv/fixes boot error: can't ssh into the instance
To: Atish Patra <atishp@atishpatra.org>
Cc: Alexandre Ghiti <alex@ghiti.fr>, Dmitry Vyukov <dvyukov@google.com>, 
	Aleksandr Nogikh <nogikh@google.com>, linux-riscv <linux-riscv@lists.infradead.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, Palmer Dabbelt <palmer@dabbelt.com>, 
	syzbot <syzbot+330a558d94b58f7601be@syzkaller.appspotmail.com>, 
	LKML <linux-kernel@vger.kernel.org>, syzkaller-bugs@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: alexandre.ghiti@canonical.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@canonical.com header.s=20210705 header.b=XC+BG864;       spf=pass
 (google.com: domain of alexandre.ghiti@canonical.com designates
 185.125.188.122 as permitted sender) smtp.mailfrom=alexandre.ghiti@canonical.com;
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

Hi Atish,

On Thu, May 26, 2022 at 11:02 AM Atish Patra <atishp@atishpatra.org> wrote:
>
> On Thu, May 26, 2022 at 1:11 AM Atish Patra <atishp@atishpatra.org> wrote:
> >
> > On Mon, May 16, 2022 at 5:06 AM Alexandre Ghiti <alex@ghiti.fr> wrote:
> > >
> > >
> > > On 5/12/22 13:48, Dmitry Vyukov wrote:
> > > > On Fri, 18 Feb 2022 at 14:45, Alexandre Ghiti
> > > > <alexandre.ghiti@canonical.com> wrote:
> > > >> Hi Aleksandr,
> > > >>
> > > >> On Thu, Feb 17, 2022 at 6:08 PM Aleksandr Nogikh <nogikh@google.com> wrote:
> > > >>> Hi Alex,
> > > >>>
> > > >>> On Thu, Feb 17, 2022 at 5:53 PM Alexandre Ghiti
> > > >>> <alexandre.ghiti@canonical.com> wrote:
> > > >>>> Aleksandr,
> > > >>>>
> > > >>>> On Wed, Feb 16, 2022 at 5:58 PM Alexandre Ghiti
> > > >>>> <alexandre.ghiti@canonical.com> wrote:
> > > >>>>> First, thank you for working on this.
> > > >>>>>
> > > >>>>> On Wed, Feb 16, 2022 at 5:17 PM Aleksandr Nogikh <nogikh@google.com> wrote:
> > > >>>>>> If I use just defconfig + DEBUG_VIRTUAL, without any KASAN, it begins
> > > >>>>>> to boot, but overwhelms me with tons of `virt_to_phys used for
> > > >>>>>> non-linear address:` errors.
> > > >>>>>>
> > > >>>>>> Like that
> > > >>>>>>
> > > >>>>>> [    2.701271] virt_to_phys used for non-linear address:
> > > >>>>>> 00000000b59e31b6 (0xffffffff806c2000)
> > > >>>>>> [    2.701727] WARNING: CPU: 0 PID: 1 at arch/riscv/mm/physaddr.c:16
> > > >>>>>> __virt_to_phys+0x7e/0x86
> > > >>>>>> [    2.702207] Modules linked in:
> > > >>>>>> [    2.702393] CPU: 0 PID: 1 Comm: swapper/0 Tainted: G        W
> > > >>>>>>    5.17.0-rc1 #1
> > > >>>>>> [    2.702806] Hardware name: riscv-virtio,qemu (DT)
> > > >>>>>> [    2.703051] epc : __virt_to_phys+0x7e/0x86
> > > >>>>>> [    2.703298]  ra : __virt_to_phys+0x7e/0x86
> > > >>>>>> [    2.703547] epc : ffffffff80008448 ra : ffffffff80008448 sp :
> > > >>>>>> ffff8f800021bde0
> > > >>>>>> [    2.703977]  gp : ffffffff80ed9b30 tp : ffffaf8001230000 t0 :
> > > >>>>>> ffffffff80eea56f
> > > >>>>>> [    2.704704]  t1 : ffffffff80eea560 t2 : 0000000000000000 s0 :
> > > >>>>>> ffff8f800021be00
> > > >>>>>> [    2.705153]  s1 : ffffffff806c2000 a0 : 000000000000004f a1 :
> > > >>>>>> ffffffff80e723d8
> > > >>>>>> [    2.705555]  a2 : 0000000000000010 a3 : fffffffffffffffe a4 :
> > > >>>>>> 0000000000000000
> > > >>>>>> [    2.706027]  a5 : 0000000000000000 a6 : 0000000000000005 a7 :
> > > >>>>>> ffffffffffffffff
> > > >>>>>> [    2.706474]  s2 : ffffffff80b80b08 s3 : 00000000000000c2 s4 :
> > > >>>>>> ffffffff806c2000
> > > >>>>>> [    2.706891]  s5 : ffffffff80edba10 s6 : ffffffff80edb960 s7 :
> > > >>>>>> 0000000000000001
> > > >>>>>> [    2.707290]  s8 : 00000000000000ff s9 : ffffffff80b80b40 s10:
> > > >>>>>> 00000000000000cc
> > > >>>>>> [    2.707689]  s11: ffffaf807e1fcf00 t3 : 0000000000000076 t4 :
> > > >>>>>> ffffffffffffffff
> > > >>>>>> [    2.708092]  t5 : 00000000000001f2 t6 : ffff8f800021bb48
> > > >>>>>> [    2.708433] status: 0000000000000120 badaddr: 0000000000000000
> > > >>>>>> cause: 0000000000000003
> > > >>>>>> [    2.708919] [<ffffffff8011416a>] free_reserved_area+0x72/0x19a
> > > >>>>>> [    2.709296] [<ffffffff80003a5a>] free_initmem+0x6c/0x7c
> > > >>>>>> [    2.709648] [<ffffffff805f60c8>] kernel_init+0x3a/0x10a
> > > >>>>>> [    2.709993] [<ffffffff80002fda>] ret_from_exception+0x0/0xc
> > > >>>>>> [    2.710310] ---[ end trace 0000000000000000 ]---
> > > >>>>>>
> > > >>>>> I was able to reproduce this: the first one regarding init_zero_pfn is
> > > >>>>> legit but not wrong, I have to check when it was introduced and how to
> > > >>>>> fix this.
> > > >>>>> Regarding the huge batch that follows, at first sight, I would say
> > > >>>>> this is linked to my sv48 patchset but that does not seem important as
> > > >>>>> the address is a kernel mapping address so the use of virt_to_phys is
> > > >>>>> right.
> > > >>>>>
> > > >>>>>> On Wed, Feb 16, 2022 at 5:09 PM Aleksandr Nogikh <nogikh@google.com> wrote:
> > > >>>>>>> On Wed, Feb 16, 2022 at 12:56 PM Dmitry Vyukov <dvyukov@google.com> wrote:
> > > >>>>>>>> On Wed, 16 Feb 2022 at 12:47, Aleksandr Nogikh <nogikh@google.com> wrote:
> > > >>>>>>>>> On Wed, Feb 16, 2022 at 11:37 AM Aleksandr Nogikh <nogikh@google.com> wrote:
> > > >>>>>>>>>> Hi Alex,
> > > >>>>>>>>>>
> > > >>>>>>>>>> On Wed, Feb 16, 2022 at 5:14 AM Alexandre Ghiti <alex@ghiti.fr> wrote:
> > > >>>>>>>>>>> Hi Dmitry,
> > > >>>>>>>>>>>
> > > >>>>>>>>>>> On 2/15/22 18:12, Dmitry Vyukov wrote:
> > > >>>>>>>>>>>> On Wed, 2 Feb 2022 at 14:18, Alexandre Ghiti
> > > >>>>>>>>>>>> <alexandre.ghiti@canonical.com> wrote:
> > > >>>>>>>>>>>>> Hi Aleksandr,
> > > >>>>>>>>>>>>>
> > > >>>>>>>>>>>>> On Wed, Feb 2, 2022 at 12:08 PM Aleksandr Nogikh <nogikh@google.com> wrote:
> > > >>>>>>>>>>>>>> Hello,
> > > >>>>>>>>>>>>>>
> > > >>>>>>>>>>>>>> syzbot has already not been able to fuzz its RISC-V instance for 97
> > > >>>>>>>>>>>>> That's a longtime, I'll take a look more regularly.
> > > >>>>>>>>>>>>>
> > > >>>>>>>>>>>>>> days now because the compiled kernel cannot boot. I bisected the issue
> > > >>>>>>>>>>>>>> to the following commit:
> > > >>>>>>>>>>>>>>
> > > >>>>>>>>>>>>>> commit 54c5639d8f507ebefa814f574cb6f763033a72a5
> > > >>>>>>>>>>>>>> Author: Alexandre Ghiti <alexandre.ghiti@canonical.com>
> > > >>>>>>>>>>>>>> Date:   Fri Oct 29 06:59:27 2021 +0200
> > > >>>>>>>>>>>>>>
> > > >>>>>>>>>>>>>>       riscv: Fix asan-stack clang build
> > > >>>>>>>>>>>>>>
> > > >>>>>>>>>>>>>> Apparently, the problem appears on GCC-built RISC-V kernels with KASAN
> > > >>>>>>>>>>>>>> enabled. In the previous message syzbot mentions
> > > >>>>>>>>>>>>>> "riscv64-linux-gnu-gcc (Debian 10.2.1-6) 10.2.1 20210110, GNU ld (GNU
> > > >>>>>>>>>>>>>> Binutils for Debian) 2.35.2", but the issue also reproduces finely on
> > > >>>>>>>>>>>>>> a newer GCC compiler: "riscv64-linux-gnu-gcc (Debian 11.2.0-10)
> > > >>>>>>>>>>>>>> 11.2.0, GNU ld (GNU Binutils for Debian) 2.37".
> > > >>>>>>>>>>>>>> For convenience, I also duplicate the .config file from the bot's
> > > >>>>>>>>>>>>>> message: https://syzkaller.appspot.com/x/.config?x=522544a2e0ef2a7d
> > > >>>>>>>>>>>>>>
> > > >>>>>>>>>>>>>> Can someone with KASAN and RISC-V expertise please take a look?
> > > >>>>>>>>>>>>> I'll take a look at that today.
> > > >>>>>>>>>>>>>
> > > >>>>>>>>>>>>> Thanks for reporting the issue,
> > > >>>>>>>>>>> I took a quick look, not enough to fix it but I know the issue comes
> > > >>>>>>>>>>> from the inline instrumentation, I have no problem with the outline
> > > >>>>>>>>>>> instrumentation. I need to find some cycles to work on this, my goal is
> > > >>>>>>>>>>> to fix this for 5.17.
> > > >>>>>>>>>> Thanks for the update!
> > > >>>>>>>>>>
> > > >>>>>>>>>> Can you please share the .config with which you tested the outline
> > > >>>>>>>>>> instrumentation?
> > > >>>>>>>>>> I updated the syzbot config to use KASAN_OUTLINE instead of KASAN_INLINE,
> > > >>>>>>>>>> but it still does not boot :(
> > > >>>>>>>>>>
> > > >>>>>>>>>> Here's what I used:
> > > >>>>>>>>>> https://gist.github.com/a-nogikh/279c85c2d24f47efcc3e865c08844138
> > > >>>>>>>>> Update: it doesn't boot with that big config, but boots if I generate
> > > >>>>>>>>> a simple one with KASAN_OUTLINE:
> > > >>>>>>>>>
> > > >>>>>>>>> make defconfig ARCH=riscv CROSS_COMPILE=riscv64-linux-gnu-
> > > >>>>>>>>> ./scripts/config -e KASAN -e KASAN_OUTLINE
> > > >>>>>>>>> make olddefconfig ARCH=riscv CROSS_COMPILE=riscv64-linux-gnu-
> > > >>>>>>>>>
> > > >>>>>>>>> And it indeed doesn't work if I use KASAN_INLINE.
> > > >>>>>>>> It may be an issue with code size. Full syzbot config + KASAN + KCOV
> > > >>>>>>>> produce hugely massive .text. It may be hitting some limitation in the
> > > >>>>>>>> bootloader/kernel bootstrap code.
> > > >>>>> I took a quick glance and it traps on a KASAN address that is not
> > > >>>>> mapped, either because it is too soon or because the mapping failed
> > > >>>>> somehow.
> > > >>>>>
> > > >>>>> I'll definitely dive into that tomorrow, sorry for being slow here and
> > > >>>>> thanks again for all your work, that helps a lot.
> > > >>>>>
> > > >>>>> Thanks,
> > > >>>>>
> > > >>>>> Alex
> > > >>>>>
> > > >>>>>>> I bisected the difference between the config we use on syzbot and the
> > > >>>>>>> simple one that was generated like I described above.
> > > >>>>>>> Turns out that it's the DEBUG_VIRTUAL config that makes the difference.
> > > >>>>>>>
> > > >>>>>>> make defconfig ARCH=riscv CROSS_COMPILE=riscv64-linux-gnu-
> > > >>>>>>> ./scripts/config -e KASAN -e KASAN_OUTLINE -e DEBUG_VIRTUAL
> > > >>>>>>> make olddefconfig ARCH=riscv CROSS_COMPILE=riscv64-linux-gnu-
> > > >>>>>>>
> > > >>>>>>> And the resulting kernel does not boot.
> > > >>>>>>> My env: the `riscv/fixes` branch, commit
> > > >>>>>>> 6df2a016c0c8a3d0933ef33dd192ea6606b115e3, qemu 6.2.0.
> > > >>>> I fixed a few things today: KASAN + SPARSE_VMEMMAP, DEBUG_VIRTUAL and
> > > >>>> maybe KASAN  + KCOV.
> > > >>>>
> > > >>>> With those small fixes, I was able to boot your large dotconfig with
> > > >>>> KASAN_OUTLINE, the inline version still fails, this is my next target
> > > >>>> :)
> > > >>>> I'll push that tomorrow!
> > > >>> Awesome, thank you very much!
> > > >>> Looking forward to finally seeing the instance run :)
> > > >> I sent a patchset which should fix your config with *outline* instrumentation.
> > > > Was this fix merged? The riscv instance still does not boot:
> > > > https://syzkaller.appspot.com/bug?id=5f2ff52ad42cba9f222202219baebd4e63e35127
> > >
> > >
> > > Yes it has been in Linus tree since 5.18-rc1. I'll take a look at that
> > > this week.
> > >
> >
> > Are you seeing this error or a different one ? I used the
> > syzkaller_defconfig from the patch below on v5.18.
> >
> > https://lore.kernel.org/all/20220419174952.699-1-palmer@rivosinc.com/
> >
> > [   15.076116][    T1] Mandatory Access Control activated.
> > [   15.158241][    T1] AppArmor: AppArmor Filesystem Enabled
> > [   16.150870][    T1] NET: Registered PF_INET protocol family
> > [   16.166167][    T1] IP idents hash table entries: 32768 (order: 6,
> > 262144 bytes, linear)
> > [   16.188727][    T1] Unable to handle kernel paging request at
> > virtual address ffebfffeffff2000
> > [   16.192727][    T1] Oops [#1]
> > [   16.193479][    T1] Modules linked in:
> > [   16.194687][    T1] CPU: 3 PID: 1 Comm: swapper/0 Not tainted
> > 5.18.0-00001-g37ac279268bf-dirty #9
> > [   16.196486][    T1] Hardware name: riscv-virtio,qemu (DT)
> > [   16.197836][    T1] epc : kasan_check_range+0x9e/0x14e
> > [   16.199104][    T1]  ra : memset+0x1e/0x4c
> > [   16.200091][    T1] epc : ffffffff804787e0 ra : ffffffff80478f30 sp
> > : ff600000073ffb70
> > [   16.201420][    T1]  gp : ffffffff85879e80 tp : ff600000073f0000 t0
> > : 7300000000000000
> > [   16.202762][    T1]  t1 : ffebfffeffff21ff t2 : 73746e6564692050 s0
> > : ff600000073ffba0
> > [   16.204047][    T1]  s1 : 0000000000001000 a0 : ffebfffeffff2200 a1
> > : 0000000000001000
> > [   16.205312][    T1]  a2 : 0000000000000001 a3 : ffffffff803a4f32 a4
> > : ff5ffffffff90000
> > [   16.206592][    T1]  a5 : ffebfffeffff2000 a6 : 0000004000000000 a7
> > : ff5ffffffff90fff
> > [   16.207865][    T1]  s2 : ff5ffffffff90000 s3 : 0000000000000000 s4
> > : ffffffff8467ea90
> > [   16.209134][    T1]  s5 : 0000000000000000 s6 : ff5ffffffff90000 s7
> > : 0000000000000000
> > [   16.210394][    T1]  s8 : 0000000000001000 s9 : ffffffff8587ca40
> > s10: 0000000000000004
> > [   16.211952][    T1]  s11: ffffffff858a03a0 t3 : 0000000000000000 t4
> > : 0000000000000040
> > [   16.213469][    T1]  t5 : ffebfffeffff2200 t6 : ff600000073ff738
> > [   16.214853][    T1] status: 0000000200000120 badaddr:
> > ffebfffeffff2000 cause: 000000000000000d
> > [   16.216910][    T1] Call Trace:
> > [   16.217816][    T1] [<ffffffff803a4f32>] pcpu_alloc+0x844/0x1254
> > [   16.219110][    T1] [<ffffffff803a59a0>] __alloc_percpu+0x28/0x34
> > [   16.220244][    T1] [<ffffffff8328824a>] ip_rt_init+0x17e/0x382
> > [   16.221606][    T1] [<ffffffff8328861c>] ip_init+0x18/0x30
> > [   16.222719][    T1] [<ffffffff8328a0ee>] inet_init+0x2a6/0x550
> > [   16.223863][    T1] [<ffffffff80003204>] do_one_initcall+0x130/0x7dc
> > [   16.225002][    T1] [<ffffffff83201fbc>] kernel_init_freeable+0x510/0x5b4
> > [   16.226273][    T1] [<ffffffff8319842a>] kernel_init+0x28/0x21c
> > [   16.227337][    T1] [<ffffffff80005818>] ret_from_exception+0x0/0x10
> > [   16.229910][    T1] ---[ end trace 0000000000000000 ]---
> > [   16.231880][    T1] Kernel panic - not syncing: Fatal exception
> >
> >
>
> Enabling CONFIG_KASAN_VMALLOC=y solves the issue and I am able to boot
> to the userspace.
> I have tried enabling/disabling CONFIG_VMAP_STACK as well. Both works fine.
>
> Looking at the ARM64 Kconfig, KASAN_VMALLOC is enabled if KASAN is enabled.
> This diff seems to work for me.
> diff --git a/arch/riscv/Kconfig b/arch/riscv/Kconfig
> index 00fd9c548f26..cbf0fe227c77 100644
> --- a/arch/riscv/Kconfig
> +++ b/arch/riscv/Kconfig
> @@ -122,6 +122,7 @@ config RISCV
>         select TRACE_IRQFLAGS_SUPPORT
>         select UACCESS_MEMCPY if !MMU
>         select ZONE_DMA32 if 64BIT
> +       select KASAN_VMALLOC if KASAN
>
> I am not a kasan expert so I am not sure if this is the correct fix or
> just hides the real issue. pcpu_alloc seems to use vmalloc though.

When this type of thing happens, generally this is because of an error
in the kasan page table, I'll take a look this time, sorry I did not
do this before.

Thanks for finding this,

Alex

>
> > > Thanks,
> > >
> > > Alex
> > >
> > >
> > > >
> > > >> However, as you'll see in the cover letter, I have an issue with
> > > >> another KASAN config and if you can take a look at the stacktrace and
> > > >> see if that rings a bell, that would be great.
> > > >>
> > > >> Don't hesitate next time to ping me when the riscv syzbot instance fails :)
> > > >>
> > > >> Alex
> > > >>
> > > >>
> > > >>> --
> > > >>> Best Regards,
> > > >>> Aleksandr
> > > >>>
> > > >>>> Thanks again,
> > > >>>>
> > > >>>> Alex
> > > >> --
> > > >> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> > > >> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> > > >> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BzEjCtB0rTuNAJkrM2q3JQL7D-9fAXBo0Ud0w__gy9CAfo_Ag%40mail.gmail.com.
> > >
> > > _______________________________________________
> > > linux-riscv mailing list
> > > linux-riscv@lists.infradead.org
> > > http://lists.infradead.org/mailman/listinfo/linux-riscv
> >
> >
> >
> > --
> > Regards,
> > Atish
>
>
>
> --
> Regards,
> Atish

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BzEjCuK7NitU_tdjBo%2BqmhkN_qmH%3DNCryffb466E7ebVq0GDw%40mail.gmail.com.
