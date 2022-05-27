Return-Path: <kasan-dev+bncBCMIZB7QWENRB7PVYGKAMGQEV7TAZIY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x340.google.com (mail-wm1-x340.google.com [IPv6:2a00:1450:4864:20::340])
	by mail.lfdr.de (Postfix) with ESMTPS id 30CE1535A26
	for <lists+kasan-dev@lfdr.de>; Fri, 27 May 2022 09:17:18 +0200 (CEST)
Received: by mail-wm1-x340.google.com with SMTP id u12-20020a05600c19cc00b0038ec265155fsf4330425wmq.6
        for <lists+kasan-dev@lfdr.de>; Fri, 27 May 2022 00:17:18 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1653635838; cv=pass;
        d=google.com; s=arc-20160816;
        b=ZEUxFIg1iiKTDzHUeVCaF/IQmqjSGe7cSxTKJvHoy6/ZxRonCIBc7Yt3II7C2N/9AC
         csuLdRaacrzV/j/JaHZ8SCePdFphXRT2Fq2S5g7XSSNEwGjEBliJvnMOMlnr6V7NdKdm
         iFEEr4iFz7EqbL8fJd07YN18mO6PeDF4miitTpNQOwUA2ELnhkFkfm1HVAgNOrmfhOuI
         6KQXYWCJb949j3XVkC9QfkbaSOkle8ek/5DGXDGuZK5+Q2V/adL/z45pNSk7+JnaZOKM
         BZ6h/A6elYMofWycFyH2mR///41siSgGEZZ/8oaGKLfqexvdE5UlFDghkpEF2ati6qB6
         +K3Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=IbDhhK2B3ThhQfsWG+b4i9qR+vCGlCiWPRsJqBE7k88=;
        b=Fs/UsjkLy4nyiBV1+g3kPbP+4YB54+/APg2UsOWHjDvMfMKIAvFcrNzE7lXuf1tDVQ
         625RVAo1zhkH0vhE98WLJT50g8nanG2UVPonxpJofapH3lGvnr8Y69kEWBBTIkbLWzrO
         C/+E0Rs5cthK24KjuEIc3MjoHVmF8hEfl6RNlhwt3n7X6RJiv2O5aWZmJYyxw3SFFpBJ
         BDCmEioWNvGSlWJKMi9IqrI9uW0am2VIplCpti9CzVJQ8WM3w/USVkST/OimKMmS6OjO
         3pJgBAt993+zJtBIgA1uBYalZR8pt1k6CXzBg2tyO7Cjzpows8xOLk9bBylZcFO+lE9E
         7i4Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=VJFVWclZ;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::236 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=IbDhhK2B3ThhQfsWG+b4i9qR+vCGlCiWPRsJqBE7k88=;
        b=Q/uKAqQZCvIWMwbmyDOBBdB58B97Dpci1CLTsxjmwGSZw5rfERZgA4LWb+TFEpvhH5
         7nc7m2jmDjFdvIzonEVR3hVKYblVr5i5SHEV2Okki+FPNDRAYw4WAkK0vi13XzwLJsx7
         me69LOPnuTTuX8Mg6KwNsfE89WFPZ4NMVd/UH/LlzcBWUL7//I61WmaTNJH2SqWoSfdc
         qz5Yxt1xsJitZSgIXuhVavulCYdrSslEKY2wbnza0rm10sBJBVDRTuejAnkcS/laqkN0
         PkZQu2ql8TPToavv0yFJ+Pf3NJmo8BmEUWavA9vCMS2CITUP1E8iRdovaMODP4WC0LIG
         PdOA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=IbDhhK2B3ThhQfsWG+b4i9qR+vCGlCiWPRsJqBE7k88=;
        b=ZOcfv0taRy33vyMWpeaIUgcs/4kHZbwoRRtk7LXcZHgO6DWfQaNr7nePrjd7AS0Kmw
         a4zO59lFpAbTSFrk+ZYdMmcD6exnQBRpakwVDqrS16Z5QWtTVXCz9Fa2YtLQoYUlHgca
         M733YWNgOChqGh500uv5Ks3hm9EGMDDISlBnE2Y4iL+qe1w5VdhWWbHzytQ9gw3+5L9g
         CQIpfTHBFJaFF++zTVrHI+YUX9sjaOWL4yMMC3Cuunj5ySjHFvYjKSW1fBq+kIN0EnAT
         2F1Mhx6+2d5pmAvqNaD3O7T7Ag1RrL61wnjbSScDXCpNe4isMECRXnJM14lL4FVzE70X
         wmww==
X-Gm-Message-State: AOAM533adqs3QBJPmOn8GeGCxlqlArkklq1dSx3mP0Fns/g8MtbRuLhR
	7ktQK+OuboOzHGGjoyabQ1k=
X-Google-Smtp-Source: ABdhPJxPLnyc/kAaK1HJpQ/GZXYX7aaC3OXb5eQzzB6plEy8y9aklwjTRY4Ki72dwu4eqcXPQEP+qA==
X-Received: by 2002:adf:e186:0:b0:20d:910:6481 with SMTP id az6-20020adfe186000000b0020d09106481mr34199543wrb.522.1653635837803;
        Fri, 27 May 2022 00:17:17 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:3c9c:b0:393:ef44:c49d with SMTP id
 bg28-20020a05600c3c9c00b00393ef44c49dls5487347wmb.2.canary-gmail; Fri, 27 May
 2022 00:17:16 -0700 (PDT)
X-Received: by 2002:a05:600c:21d0:b0:397:33e6:fd42 with SMTP id x16-20020a05600c21d000b0039733e6fd42mr5591817wmj.179.1653635836796;
        Fri, 27 May 2022 00:17:16 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1653635836; cv=none;
        d=google.com; s=arc-20160816;
        b=yG3Axx9esoTi635wuXXhw9KudvZB0VwD6EyJOMYvlJo9+ereUcM1U0rFEh6oAVo4im
         uqmRDl5UARyvMWaxTVKO+O9P+Y4p8s44kg66y1MlrQiI53Y7VbCFRE43FgIzD1LXCFZi
         1ze8gX+qK99iVnNvj+AgOH9f6jlv0kzfaFSIMpP2ZpZHwGXg1z/ct98eES5kNYhGvwKm
         YTwkhzu/D18u4I7UWOyUz9AJaLNKPwItMwB9/9z/WI3VwgbtA8+F4O5cW5vEWnBuAJST
         XeugcmbpfRYJWN7gHgSK8qTmPU33ZVPvR92D9ZJG3ODPyCKZcOEuTpqdHnr5K99/5d6Q
         BL1g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=voFWQv6a5xlzqv/Wy2pnyZxPR7t3qCANmzRDMt69eQM=;
        b=hsUXSqmZllgZBhvEIiQ8YC25yluuycyi+s48SGvF3y+DDuNtrU2rSeMxhm6BziF643
         A81F6wIBbLHSj/5hT1jgpFdxXU0CxzlwxRyCV2mLR7ZZQE7pMYzXrLUVvdoubkhF/rW2
         0xP/QCkqRlFIoNBYYzY/75nBYzELK6JWGIGevo+pYGtoPVAghyTodNMbEo9XooQE/W7p
         hnSzCrQ73ML0gYx1ZHAulh/oQ6jeeIuwG8xbXy+Yk5njCJFIzYb853OGaiGmkup5PvTL
         L90kJjANQJaz61sgwc/uBUNa85HcnnsAJ/PsriHyaS8JPCGzT6OdsgIyaHwcO9PoKoYk
         oxpw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=VJFVWclZ;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::236 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-lj1-x236.google.com (mail-lj1-x236.google.com. [2a00:1450:4864:20::236])
        by gmr-mx.google.com with ESMTPS id f8-20020a056000128800b0020c9eedfe67si45806wrx.3.2022.05.27.00.17.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 27 May 2022 00:17:16 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::236 as permitted sender) client-ip=2a00:1450:4864:20::236;
Received: by mail-lj1-x236.google.com with SMTP id e4so4016233ljb.13
        for <kasan-dev@googlegroups.com>; Fri, 27 May 2022 00:17:16 -0700 (PDT)
X-Received: by 2002:a05:651c:19aa:b0:253:fc5c:5e20 with SMTP id
 bx42-20020a05651c19aa00b00253fc5c5e20mr9854059ljb.465.1653635836046; Fri, 27
 May 2022 00:17:16 -0700 (PDT)
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
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 27 May 2022 09:17:04 +0200
Message-ID: <CACT4Y+aM8C6s-wcyWgoda-xfYvD=4YBKLnVavj49tPLYZBpLHg@mail.gmail.com>
Subject: Re: [syzbot] riscv/fixes boot error: can't ssh into the instance
To: Atish Patra <atishp@atishpatra.org>
Cc: Alexandre Ghiti <alex@ghiti.fr>, Alexandre Ghiti <alexandre.ghiti@canonical.com>, 
	Aleksandr Nogikh <nogikh@google.com>, linux-riscv <linux-riscv@lists.infradead.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, Palmer Dabbelt <palmer@dabbelt.com>, 
	syzbot <syzbot+330a558d94b58f7601be@syzkaller.appspotmail.com>, 
	LKML <linux-kernel@vger.kernel.org>, syzkaller-bugs@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=VJFVWclZ;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::236
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

,On Thu, 26 May 2022 at 11:02, Atish Patra <atishp@atishpatra.org> wrote:
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

Hi Atish,

Enabling KASAN_VMALLOC in syzbot config actually makes it boot for me!
It's probably good to enforce it and/or give better diagnostics and/or
fix KASAN w/o KASAN_VMALLOC, but I've sent a fix up for syzbot config
for now:
https://github.com/google/syzkaller/pull/3167
Thanks for looking into it.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BaM8C6s-wcyWgoda-xfYvD%3D4YBKLnVavj49tPLYZBpLHg%40mail.gmail.com.
