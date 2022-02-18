Return-Path: <kasan-dev+bncBCXKTJ63SAARBLEFYCIAMGQEBDIWNHQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23d.google.com (mail-oi1-x23d.google.com [IPv6:2607:f8b0:4864:20::23d])
	by mail.lfdr.de (Postfix) with ESMTPS id B04244BC138
	for <lists+kasan-dev@lfdr.de>; Fri, 18 Feb 2022 21:33:49 +0100 (CET)
Received: by mail-oi1-x23d.google.com with SMTP id k8-20020a0568080e8800b002ccac943a76sf2373490oil.15
        for <lists+kasan-dev@lfdr.de>; Fri, 18 Feb 2022 12:33:49 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1645216428; cv=pass;
        d=google.com; s=arc-20160816;
        b=naX6c3erxfsLOLkhxZ6HqUZI9trn+Ffk922mkDjAcDPOaC/Oa5tJdqonlQh92EQsT/
         7WI6rOOXkDalXPyKByJp9BtbInttelOuzRuRE5aNp1E4WGoyutZR6ET98Bp5N3J1dZBM
         4sIL/i033SSEBjlBOx3z5inctboyr9+w6eZPN/MvtmpBQ87roTHoiMHbkTqRmga9EMEY
         UyS/hrfw8bpsJXqgswbHJzq3emXShwlaNfr8OOk8cZPvOXUUJSoglqi9Ww9Rq6qSZNSl
         7KMaQF5pIu7lrFIgyyylSmN0rdpFQUfqDrZnFAFCR7TBTK4rHjrfMuEY1H0junz4mFFN
         ThXQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=pjxER8RV0xNj29JOAyVX3lSnlro1JF4+BQE2bmijA6M=;
        b=0SaD2KzqZ1+2+DH6TJrNGy8mkXJIM/DqcJHK0X386RNg3PhxkMHP5QO6ccwFqQdwni
         58XUY0G6RlZ7depKUONAfzn+QT1s7dHnrbG3gu2SRhLJWuAB4U7UUq5eZ+ezCXN5hkVV
         nPvNGy879MB/O61EhQYKcH2H1EOBD5Ptl20H+mbshS3llvRM800b5AJ4j+QOEiVjmcRF
         khuDTlSYk8yyJiQqUASEY3rroH1rmLtFW/taG6eYfQJi7y3kgAxy3sdoZlThG1TZd7AK
         mH9LLdA3J6FAH4rXHXcvSd7Fs0hxmpcoQl3sqTsrzoccaMDcekNtcaYvY+nd2t7EUNnB
         twHg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=Ckqkc00J;
       spf=pass (google.com: domain of nogikh@google.com designates 2607:f8b0:4864:20::12a as permitted sender) smtp.mailfrom=nogikh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=pjxER8RV0xNj29JOAyVX3lSnlro1JF4+BQE2bmijA6M=;
        b=IBhmABlCn5rB8A68+cCblsmvianuQOX4UO8joLeHqKK//lxFhrN+vtqf0+1r+HGO4u
         g/TFPu+11NtOtOrzn8uOHPd+Qq/LYnhrbXOl39ljec5wFMcRYgMoUkzwkOTK10qt8ozO
         +gasFbGG/C0TKShNTLL6XsiVIP+AoJMzfZapBz+m6/X1bhCNn5aKyM6Obb9r+Ggznif5
         ZaY1l3mELO+V7j2UWbUWM8b2lPifQL4nJo/yh6mTHsmIxvzoq2Ub5pJzi7UAFGcBTJuK
         aw/yeJda9+GcRqgUdCawa+tehUwAyZoaKmwthmIjSSci5nDXb7AN3I7gjsoYmBEhv+iH
         5Oww==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=pjxER8RV0xNj29JOAyVX3lSnlro1JF4+BQE2bmijA6M=;
        b=zix7KwyBgcQFC/wX+MVSNy4iGfju/quqdZt+tqUzT4WbiAJx8hE77DNT7gTw5mjR3J
         C/ehd0wLY2D/fr3s++NMURIiqJ6sgbxU0vHYI0e/yjj3QEwnK16grm8r70+uNCwsX7Js
         B3u5Y9B1QTRSbFfKZ9iEnaYnydGEgzC1PRt66QGBMErG3dw5r//HzVyWfqNBxK8+64WD
         RJSCCIzic++V7M3YBu+BrZ1AJvnNIsTTVOHjLF7KlxsfQfMlY7+1bofb4KYkdoZqmfMe
         Az1g+/4Rk2Qy+3NJRjxF+5PbnJgXHFbkLFj/74JliGo+j49kTGbUlEiCiqVedkrNA4Ao
         K35g==
X-Gm-Message-State: AOAM530H3GwKsBu4WmBYPWGr7+4E7xQDrSSjELWMOjMFOXGV142hwNBN
	IsieA3fWLaB6qOgLJZPMWPY=
X-Google-Smtp-Source: ABdhPJyzit6oF/IT7uQP3UBsM4V7JMIMmOhJOLKdEh7M5dKJnLUz1SfIhSDLSyGDn9le6O2pJWYCYw==
X-Received: by 2002:a05:6808:1693:b0:2d3:fd47:9906 with SMTP id bb19-20020a056808169300b002d3fd479906mr5770987oib.254.1645216428466;
        Fri, 18 Feb 2022 12:33:48 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:799b:b0:d2:6721:4be1 with SMTP id
 he27-20020a056870799b00b000d267214be1ls1684186oab.10.gmail; Fri, 18 Feb 2022
 12:33:48 -0800 (PST)
X-Received: by 2002:a05:6870:9616:b0:d2:d97e:9895 with SMTP id d22-20020a056870961600b000d2d97e9895mr3393600oaq.294.1645216428119;
        Fri, 18 Feb 2022 12:33:48 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1645216428; cv=none;
        d=google.com; s=arc-20160816;
        b=oVUTvLasY1cd07fhctUBS9CXsc8JDQMTMlJy9CiVF1I0wZ3dnTAlOYg4U00Jwe3C2B
         AdpFZG8RSdI/haWucsmJM3v59lq28Iik3g9IO6kKVwLv9e8RwBHq4vqKZLpKpdCxsRWL
         g57FgVSZAnatPy/2t3AmCPLBTIaqGpwid9IxfnMyK7zzgO9TTgVrMDvI5GMXaYucK6Ry
         Et4tAv4u+pU/KJ4AMhbB9CIwLieu1F/kNTfHXe42t0qdKt6gB9bdDLlLukLmPBjD5jh5
         DNAawNmma91voymUzG9WLgTUxbOZGkH8RsIrld1l1lr8bOzPWN9pgKb+2DOpa5ETLpJi
         6auA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Ezvsvchx2nUrNXjulTpQnqP/UL35iteRMo/MbI6yggw=;
        b=hAx0LCUrplLIwRVRHdlUOdfY4CUXJ3boSdBq5eDqMm8SXYu3Oq4wLN05533kqiNr2a
         oXBpzLq5YRc8v6P/fTApsQZwRMN2RYpTb+ldllUAaYGwmDLlkHiyjAkf53g676pBzRn2
         pc0Q3TRGVcCF9mkInSMBY/SpMM+sdzywriwSsZ3k/sofc+G2INW3PDHg61aEBA8pPp6K
         7UO8mmV2XmuXNcCq/HpjneFU/tEaffIwq4uqifuAlSVIBmOs9VGl1Ygsb1IPZKmaUSl/
         uHSEsV/Q3k9JX0fbzCVjko7lj+PVfZ4xPfR0bOlk+LHgfd0m8zC50Pz4k2JCauV4JyU9
         BBPg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=Ckqkc00J;
       spf=pass (google.com: domain of nogikh@google.com designates 2607:f8b0:4864:20::12a as permitted sender) smtp.mailfrom=nogikh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-il1-x12a.google.com (mail-il1-x12a.google.com. [2607:f8b0:4864:20::12a])
        by gmr-mx.google.com with ESMTPS id u28si227206otj.3.2022.02.18.12.33.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 18 Feb 2022 12:33:48 -0800 (PST)
Received-SPF: pass (google.com: domain of nogikh@google.com designates 2607:f8b0:4864:20::12a as permitted sender) client-ip=2607:f8b0:4864:20::12a;
Received: by mail-il1-x12a.google.com with SMTP id f13so5542053ilq.5
        for <kasan-dev@googlegroups.com>; Fri, 18 Feb 2022 12:33:48 -0800 (PST)
X-Received: by 2002:a05:6e02:b27:b0:2c1:a9cd:e300 with SMTP id
 e7-20020a056e020b2700b002c1a9cde300mr3069058ilu.44.1645216427582; Fri, 18 Feb
 2022 12:33:47 -0800 (PST)
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
 <CANp29Y4rDSjrfTOxcQqwh+Qm+ocR0v6Oxr7EkFxScf+24M1tNA@mail.gmail.com> <CA+zEjCtB0rTuNAJkrM2q3JQL7D-9fAXBo0Ud0w__gy9CAfo_Ag@mail.gmail.com>
In-Reply-To: <CA+zEjCtB0rTuNAJkrM2q3JQL7D-9fAXBo0Ud0w__gy9CAfo_Ag@mail.gmail.com>
From: "'Aleksandr Nogikh' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 18 Feb 2022 21:33:36 +0100
Message-ID: <CANp29Y4g5x4N174uDJNSTmtn2M-HM-Chp9S9zNtFrso-JBDayg@mail.gmail.com>
Subject: Re: [syzbot] riscv/fixes boot error: can't ssh into the instance
To: Alexandre Ghiti <alexandre.ghiti@canonical.com>
Cc: Dmitry Vyukov <dvyukov@google.com>, Alexandre Ghiti <alex@ghiti.fr>, linux-riscv@lists.infradead.org, 
	kasan-dev <kasan-dev@googlegroups.com>, Palmer Dabbelt <palmer@dabbelt.com>, 
	syzbot <syzbot+330a558d94b58f7601be@syzkaller.appspotmail.com>, 
	LKML <linux-kernel@vger.kernel.org>, syzkaller-bugs@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: nogikh@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=Ckqkc00J;       spf=pass
 (google.com: domain of nogikh@google.com designates 2607:f8b0:4864:20::12a as
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

On Fri, Feb 18, 2022 at 2:45 PM Alexandre Ghiti
<alexandre.ghiti@canonical.com> wrote:
>
> Hi Aleksandr,
>
> On Thu, Feb 17, 2022 at 6:08 PM Aleksandr Nogikh <nogikh@google.com> wrote:
> >
> > Hi Alex,
> >
> > On Thu, Feb 17, 2022 at 5:53 PM Alexandre Ghiti
> > <alexandre.ghiti@canonical.com> wrote:
> > >
> > > Aleksandr,
> > >
> > > On Wed, Feb 16, 2022 at 5:58 PM Alexandre Ghiti
> > > <alexandre.ghiti@canonical.com> wrote:
> > > >
> > > > First, thank you for working on this.
> > > >
> > > > On Wed, Feb 16, 2022 at 5:17 PM Aleksandr Nogikh <nogikh@google.com> wrote:
> > > > >
> > > > > If I use just defconfig + DEBUG_VIRTUAL, without any KASAN, it begins
> > > > > to boot, but overwhelms me with tons of `virt_to_phys used for
> > > > > non-linear address:` errors.
> > > > >
> > > > > Like that
> > > > >
> > > > > [    2.701271] virt_to_phys used for non-linear address:
> > > > > 00000000b59e31b6 (0xffffffff806c2000)
> > > > > [    2.701727] WARNING: CPU: 0 PID: 1 at arch/riscv/mm/physaddr.c:16
> > > > > __virt_to_phys+0x7e/0x86
> > > > > [    2.702207] Modules linked in:
> > > > > [    2.702393] CPU: 0 PID: 1 Comm: swapper/0 Tainted: G        W
> > > > >   5.17.0-rc1 #1
> > > > > [    2.702806] Hardware name: riscv-virtio,qemu (DT)
> > > > > [    2.703051] epc : __virt_to_phys+0x7e/0x86
> > > > > [    2.703298]  ra : __virt_to_phys+0x7e/0x86
> > > > > [    2.703547] epc : ffffffff80008448 ra : ffffffff80008448 sp :
> > > > > ffff8f800021bde0
> > > > > [    2.703977]  gp : ffffffff80ed9b30 tp : ffffaf8001230000 t0 :
> > > > > ffffffff80eea56f
> > > > > [    2.704704]  t1 : ffffffff80eea560 t2 : 0000000000000000 s0 :
> > > > > ffff8f800021be00
> > > > > [    2.705153]  s1 : ffffffff806c2000 a0 : 000000000000004f a1 :
> > > > > ffffffff80e723d8
> > > > > [    2.705555]  a2 : 0000000000000010 a3 : fffffffffffffffe a4 :
> > > > > 0000000000000000
> > > > > [    2.706027]  a5 : 0000000000000000 a6 : 0000000000000005 a7 :
> > > > > ffffffffffffffff
> > > > > [    2.706474]  s2 : ffffffff80b80b08 s3 : 00000000000000c2 s4 :
> > > > > ffffffff806c2000
> > > > > [    2.706891]  s5 : ffffffff80edba10 s6 : ffffffff80edb960 s7 :
> > > > > 0000000000000001
> > > > > [    2.707290]  s8 : 00000000000000ff s9 : ffffffff80b80b40 s10:
> > > > > 00000000000000cc
> > > > > [    2.707689]  s11: ffffaf807e1fcf00 t3 : 0000000000000076 t4 :
> > > > > ffffffffffffffff
> > > > > [    2.708092]  t5 : 00000000000001f2 t6 : ffff8f800021bb48
> > > > > [    2.708433] status: 0000000000000120 badaddr: 0000000000000000
> > > > > cause: 0000000000000003
> > > > > [    2.708919] [<ffffffff8011416a>] free_reserved_area+0x72/0x19a
> > > > > [    2.709296] [<ffffffff80003a5a>] free_initmem+0x6c/0x7c
> > > > > [    2.709648] [<ffffffff805f60c8>] kernel_init+0x3a/0x10a
> > > > > [    2.709993] [<ffffffff80002fda>] ret_from_exception+0x0/0xc
> > > > > [    2.710310] ---[ end trace 0000000000000000 ]---
> > > > >
> > > >
> > > > I was able to reproduce this: the first one regarding init_zero_pfn is
> > > > legit but not wrong, I have to check when it was introduced and how to
> > > > fix this.
> > > > Regarding the huge batch that follows, at first sight, I would say
> > > > this is linked to my sv48 patchset but that does not seem important as
> > > > the address is a kernel mapping address so the use of virt_to_phys is
> > > > right.
> > > >
> > > > > On Wed, Feb 16, 2022 at 5:09 PM Aleksandr Nogikh <nogikh@google.com> wrote:
> > > > > >
> > > > > > On Wed, Feb 16, 2022 at 12:56 PM Dmitry Vyukov <dvyukov@google.com> wrote:
> > > > > > >
> > > > > > > On Wed, 16 Feb 2022 at 12:47, Aleksandr Nogikh <nogikh@google.com> wrote:
> > > > > > > >
> > > > > > > > On Wed, Feb 16, 2022 at 11:37 AM Aleksandr Nogikh <nogikh@google.com> wrote:
> > > > > > > > >
> > > > > > > > > Hi Alex,
> > > > > > > > >
> > > > > > > > > On Wed, Feb 16, 2022 at 5:14 AM Alexandre Ghiti <alex@ghiti.fr> wrote:
> > > > > > > > > >
> > > > > > > > > > Hi Dmitry,
> > > > > > > > > >
> > > > > > > > > > On 2/15/22 18:12, Dmitry Vyukov wrote:
> > > > > > > > > > > On Wed, 2 Feb 2022 at 14:18, Alexandre Ghiti
> > > > > > > > > > > <alexandre.ghiti@canonical.com> wrote:
> > > > > > > > > > >> Hi Aleksandr,
> > > > > > > > > > >>
> > > > > > > > > > >> On Wed, Feb 2, 2022 at 12:08 PM Aleksandr Nogikh <nogikh@google.com> wrote:
> > > > > > > > > > >>> Hello,
> > > > > > > > > > >>>
> > > > > > > > > > >>> syzbot has already not been able to fuzz its RISC-V instance for 97
> > > > > > > > > > >> That's a longtime, I'll take a look more regularly.
> > > > > > > > > > >>
> > > > > > > > > > >>> days now because the compiled kernel cannot boot. I bisected the issue
> > > > > > > > > > >>> to the following commit:
> > > > > > > > > > >>>
> > > > > > > > > > >>> commit 54c5639d8f507ebefa814f574cb6f763033a72a5
> > > > > > > > > > >>> Author: Alexandre Ghiti <alexandre.ghiti@canonical.com>
> > > > > > > > > > >>> Date:   Fri Oct 29 06:59:27 2021 +0200
> > > > > > > > > > >>>
> > > > > > > > > > >>>      riscv: Fix asan-stack clang build
> > > > > > > > > > >>>
> > > > > > > > > > >>> Apparently, the problem appears on GCC-built RISC-V kernels with KASAN
> > > > > > > > > > >>> enabled. In the previous message syzbot mentions
> > > > > > > > > > >>> "riscv64-linux-gnu-gcc (Debian 10.2.1-6) 10.2.1 20210110, GNU ld (GNU
> > > > > > > > > > >>> Binutils for Debian) 2.35.2", but the issue also reproduces finely on
> > > > > > > > > > >>> a newer GCC compiler: "riscv64-linux-gnu-gcc (Debian 11.2.0-10)
> > > > > > > > > > >>> 11.2.0, GNU ld (GNU Binutils for Debian) 2.37".
> > > > > > > > > > >>> For convenience, I also duplicate the .config file from the bot's
> > > > > > > > > > >>> message: https://syzkaller.appspot.com/x/.config?x=522544a2e0ef2a7d
> > > > > > > > > > >>>
> > > > > > > > > > >>> Can someone with KASAN and RISC-V expertise please take a look?
> > > > > > > > > > >> I'll take a look at that today.
> > > > > > > > > > >>
> > > > > > > > > > >> Thanks for reporting the issue,
> > > > > > > > > > >
> > > > > > > > > >
> > > > > > > > > > I took a quick look, not enough to fix it but I know the issue comes
> > > > > > > > > > from the inline instrumentation, I have no problem with the outline
> > > > > > > > > > instrumentation. I need to find some cycles to work on this, my goal is
> > > > > > > > > > to fix this for 5.17.
> > > > > > > > >
> > > > > > > > > Thanks for the update!
> > > > > > > > >
> > > > > > > > > Can you please share the .config with which you tested the outline
> > > > > > > > > instrumentation?
> > > > > > > > > I updated the syzbot config to use KASAN_OUTLINE instead of KASAN_INLINE,
> > > > > > > > > but it still does not boot :(
> > > > > > > > >
> > > > > > > > > Here's what I used:
> > > > > > > > > https://gist.github.com/a-nogikh/279c85c2d24f47efcc3e865c08844138
> > > > > > > >
> > > > > > > > Update: it doesn't boot with that big config, but boots if I generate
> > > > > > > > a simple one with KASAN_OUTLINE:
> > > > > > > >
> > > > > > > > make defconfig ARCH=riscv CROSS_COMPILE=riscv64-linux-gnu-
> > > > > > > > ./scripts/config -e KASAN -e KASAN_OUTLINE
> > > > > > > > make olddefconfig ARCH=riscv CROSS_COMPILE=riscv64-linux-gnu-
> > > > > > > >
> > > > > > > > And it indeed doesn't work if I use KASAN_INLINE.
> > > > > > >
> > > > > > > It may be an issue with code size. Full syzbot config + KASAN + KCOV
> > > > > > > produce hugely massive .text. It may be hitting some limitation in the
> > > > > > > bootloader/kernel bootstrap code.
> > > >
> > > > I took a quick glance and it traps on a KASAN address that is not
> > > > mapped, either because it is too soon or because the mapping failed
> > > > somehow.
> > > >
> > > > I'll definitely dive into that tomorrow, sorry for being slow here and
> > > > thanks again for all your work, that helps a lot.
> > > >
> > > > Thanks,
> > > >
> > > > Alex
> > > >
> > > > > >
> > > > > > I bisected the difference between the config we use on syzbot and the
> > > > > > simple one that was generated like I described above.
> > > > > > Turns out that it's the DEBUG_VIRTUAL config that makes the difference.
> > > > > >
> > > > > > make defconfig ARCH=riscv CROSS_COMPILE=riscv64-linux-gnu-
> > > > > > ./scripts/config -e KASAN -e KASAN_OUTLINE -e DEBUG_VIRTUAL
> > > > > > make olddefconfig ARCH=riscv CROSS_COMPILE=riscv64-linux-gnu-
> > > > > >
> > > > > > And the resulting kernel does not boot.
> > > > > > My env: the `riscv/fixes` branch, commit
> > > > > > 6df2a016c0c8a3d0933ef33dd192ea6606b115e3, qemu 6.2.0.
> > >
> > > I fixed a few things today: KASAN + SPARSE_VMEMMAP, DEBUG_VIRTUAL and
> > > maybe KASAN  + KCOV.
> > >
> > > With those small fixes, I was able to boot your large dotconfig with
> > > KASAN_OUTLINE, the inline version still fails, this is my next target
> > > :)
> > > I'll push that tomorrow!
> >
> > Awesome, thank you very much!
> > Looking forward to finally seeing the instance run :)
>
> I sent a patchset which should fix your config with *outline* instrumentation.
>
> However, as you'll see in the cover letter, I have an issue with
> another KASAN config and if you can take a look at the stacktrace and
> see if that rings a bell, that would be great.
>
> Don't hesitate next time to ping me when the riscv syzbot instance fails :)
>
> Alex
>

Thank you very much for the patch series and for the update!

I'll try to take a closer look on Monday. To be honest, I don't really
have expertise in KASAN internals, so it's rather unlikely that I
could be of much help here :(

>
> >
> > --
> > Best Regards,
> > Aleksandr
> >
> > >
> > > Thanks again,
> > >
> > > Alex
>
> --
> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BzEjCtB0rTuNAJkrM2q3JQL7D-9fAXBo0Ud0w__gy9CAfo_Ag%40mail.gmail.com.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANp29Y4g5x4N174uDJNSTmtn2M-HM-Chp9S9zNtFrso-JBDayg%40mail.gmail.com.
