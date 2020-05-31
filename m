Return-Path: <kasan-dev+bncBCFLDU5RYAIRBIPQ2D3AKGQEVUB4N4I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x140.google.com (mail-lf1-x140.google.com [IPv6:2a00:1450:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id 5F29B1E9AC3
	for <lists+kasan-dev@lfdr.de>; Mon,  1 Jun 2020 01:05:06 +0200 (CEST)
Received: by mail-lf1-x140.google.com with SMTP id 74sf1513272lfa.20
        for <lists+kasan-dev@lfdr.de>; Sun, 31 May 2020 16:05:06 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1590966306; cv=pass;
        d=google.com; s=arc-20160816;
        b=IDk/EQ8Zcj7WHQx9Nr6ja9r/AxQRA7vqNsvmowvKbD26/q+y6FK2AqjrmKRS3G5/uZ
         wRdGXl/884d6JmZk3fnPITAV37pkfav8DJl9lHBhF8ULj+F9Ia03r/l+ttiYiyUzRE8I
         Dv7XoICTUbpen298HLwKwVYkCXX5Lbx7BkDCZOhcNwq/xLLMdnbFs/WMwg8f9OvzD101
         AB7fbSi0AVie4v/ynz8sooWn1ZpTQCLXD68XvYs/bYlSsA6fJ0fnVadfxXmHAkg50l2v
         DCkDv4VtXAtUK8hHcLJNhZVYN1/2qpxVVkhQCULOgHedLH3h7wgeO1BKF3qcOnLiPFeN
         7w4Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=ECMZAaRNhP02yOXOxmGJoyz19d6vMk+y48STLnYJ4OM=;
        b=gR5Y2Rx7aZxcHtD5EUrSKOXMF3c2MXwoOVoaZ7hhHxdCQBiDmFPBEywldkPb5TyO/N
         dSSa99fkylpEo7RFHBirP9H1PIdAjCp+b8oAUe/mDPCw33mK1pxKS5nQUqmGjDj4NFIA
         q7+4ZXaz8nNsTOJ7Ek5reBM1g7ArkNk0V9WmbWbQ5tHPt7sJ74iQwHt+SoJR0fFecaB7
         WuboWTTA4e/e7rMu4zNKyD4pyPxgphsPla8x/pCHW0BtLtSk90u+QHvZ4/IL0jukhK5h
         5nH61TNfcrePo5ayuc1MpsgrpbvzscwmknQ1sCIPlH0q/V7RRf94vACv6aGWmBG/5sCF
         BGhg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=dWO4dtSX;
       spf=pass (google.com: domain of venkat.rajuece@gmail.com designates 2a00:1450:4864:20::141 as permitted sender) smtp.mailfrom=venkat.rajuece@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ECMZAaRNhP02yOXOxmGJoyz19d6vMk+y48STLnYJ4OM=;
        b=Z9QBNYRzIMyOVJFtMRW14lqGA4oyQ83cNknmE650OjnbxygEUKPPXeHISmq72A2GgT
         Eb/08Qi6XmUoQXY6MeyZhjJ6Edh+Lx3r1zr+Y9qoqv0dqgio33FApYov0QmoanCArbPY
         v1pvr4Cu/F7daySUBD2d9LaSbM2vAYMNB811i6xwBhfC9LLSFNAyv4kQfDR2EzMCNwhp
         ZhpXI6WXEZnjRYEIuge+4OgiK1Ew8lWZtGWqE46k6w2Q28nPdCllX4C8KnC9879zSyQO
         tPnDTRm4K7X+gMShS0X7JW2Lb5x+CttQ0t6/O7p9GdXRdadMDpO2Oms1nKe4JnYtjbSZ
         iaVg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ECMZAaRNhP02yOXOxmGJoyz19d6vMk+y48STLnYJ4OM=;
        b=it07yWcnhjC9q9NDx/HtZxohMTnrDlM3sU82vw6bssRYCpVr/E4QauPBBVCu47O7mn
         TH8htZjyvWbNSdtRr02Y2xXKDirOTOF8FZ2qS3lpuW0BhnW66IlAyyMHHC5jdEVwNjAy
         Dy/hWKFYZSn5I6iDgT7XIfRT6TO2C5wHStnLeZ2pKFoTVvhlEeih8to2GxsJMDyP7ybK
         yPQqYfUtAJovkgyYnEdsGxrrS1OzBt8PfhJfNcmp9EVL68rbNjk2aM+UWovojk0SXz6e
         TPuPOoIC/XxtI9dfAZQV2tXLxja6l9fjzbhN4Cnc+c93Lykr4eYZMWDx9pzcTO+tudpo
         wylQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ECMZAaRNhP02yOXOxmGJoyz19d6vMk+y48STLnYJ4OM=;
        b=CaPyCVDCpWMCFQVC3/kyruW1Vv+Hnwlbk4CiH7Yp6LsYHjWvbJqp2RUgf154oMo52W
         IS8RCz42qlQEJQrFgijdaCwcGiYedRqE55huGvHzYozvU7AyoJhxleUloL2I+jCoYW0H
         nWh6cc1YQME7LOZEY4DGBgFE0rSaKKZDA2vYkYm7+wTcdhhKD113viU0Yy5Mypv8z1sD
         1ptcrkcec9fHp5Xuy3fSY5k3aWKdFO1dYbThcnMzXHdnbEXX5OUkBsi6EtMUi8GUV1QE
         +qphX8ULwJzwrvjyzXem79Kw7UjEzPKbnZQw6vty0RFeNsMYvJ7MncAQQzm86U/HC9NR
         N+qw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5300/uL64QN8qF1QnHfuMYViL9iR/syWArnA6HN+eWVHuoXrTHt9
	xxgtTnYKAnanmuOhTVXACGA=
X-Google-Smtp-Source: ABdhPJzrXoevQ2yGtkmv3cs2oVxXppEBpPjk8TMh0tSSfjNzPnQdmPucIEe+qUZGcZEJvg/b3381+w==
X-Received: by 2002:a2e:3c14:: with SMTP id j20mr9401237lja.175.1590966305768;
        Sun, 31 May 2020 16:05:05 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:4b43:: with SMTP id y64ls2035385lfa.2.gmail; Sun, 31 May
 2020 16:05:05 -0700 (PDT)
X-Received: by 2002:ac2:504e:: with SMTP id a14mr9810420lfm.30.1590966304991;
        Sun, 31 May 2020 16:05:04 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1590966304; cv=none;
        d=google.com; s=arc-20160816;
        b=kKKMlrSgvFL7KjEIxGs9Owd46iWn6vS1dLSziSxMUCDGIw/zt/hwN3PPC9HiApxrR6
         6fyP6ublxOfy/whfRnozcIhNePHUKDaFWmi89mFaFqF1c6h+izVjh0tePKwsQuYntruQ
         i4YoTm1ZeeNavl92Ug2U2uMkiODwfZw6Q9OPvPvs1Ey50dAwjetQQoIWdw7J1Tq+EK8V
         XN9FhvjuuCR7IJVJyqDFMZ7MkakXuZSemSEWANPzsPkKHdpMjhdvFSa2Lewoeep61XjW
         M4gX3ISAGS4sD9mBOQwGugxH7Q8J1/dpfKKwqtklEh7dD+vxthekc0s50CGjUCQm/XwX
         zezw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=XDh/iEms9/UhrVC+jbJz+TbNUC3uZNntimpVB7PzQEo=;
        b=0kgCde5Sh7dM0KZbeIq2X9QVr8lBA9NvYQi3XzzJlpOzUMOLpITT5PLG5VJtdCS9Dx
         vQpioUM3hSBUP5SNkf/BFxBA6icuCz8ew18q4XYSzz+OBsfu87RQ67reYTDAuyUpJNXG
         SToR/Ix0rcUObocrJDfrDxg2MqsdpJPchTrIgYKWsfWcCcGRKlsaDCGm3W532w7gZbdi
         LGe5F0HmC8MzDhikYv5aLFyVyguDIlE520pjeTL5IoU3AYnb1Vhv1nX2BMH7to38T6KR
         C4JTOOJ7u62VxqYg/Pz6zGFI/+RoTgZ/HokH3ET5sM/kfyNN/Xe9Z3Ws0PSQQ82bqN8p
         hMyA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=dWO4dtSX;
       spf=pass (google.com: domain of venkat.rajuece@gmail.com designates 2a00:1450:4864:20::141 as permitted sender) smtp.mailfrom=venkat.rajuece@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-lf1-x141.google.com (mail-lf1-x141.google.com. [2a00:1450:4864:20::141])
        by gmr-mx.google.com with ESMTPS id 14si870865lfy.1.2020.05.31.16.05.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 31 May 2020 16:05:04 -0700 (PDT)
Received-SPF: pass (google.com: domain of venkat.rajuece@gmail.com designates 2a00:1450:4864:20::141 as permitted sender) client-ip=2a00:1450:4864:20::141;
Received: by mail-lf1-x141.google.com with SMTP id h188so2856909lfd.7
        for <kasan-dev@googlegroups.com>; Sun, 31 May 2020 16:05:04 -0700 (PDT)
X-Received: by 2002:a19:86c3:: with SMTP id i186mr9835786lfd.166.1590966304588;
 Sun, 31 May 2020 16:05:04 -0700 (PDT)
MIME-Version: 1.0
References: <CA+dZkamtaXi8yr=khO+E9SKe9QBR-Z0e0kdH4DzhQdzo8o-+Eg@mail.gmail.com>
 <CACT4Y+YS5b2PokFVvw69Mfo-jjE13jGAqYmtEJQa7tVHm=CjgQ@mail.gmail.com>
 <CACRpkdZzj6MRJk3sFN+ihw8ZksZ-WF=CJNsxuazkAYPmd=Ki_Q@mail.gmail.com>
 <CA+dZkanvC+RU0DjiCz=4e+Zhy+mEux-NHX5VO5YUCkhowN4Z_g@mail.gmail.com>
 <CACRpkdZv_6RN2vt5paCDx2g9DWsKT6LZTw1+jrLZNqVrLvKQWA@mail.gmail.com>
 <CA+dZka=1cE1Zt71bH1K7ZZz0dPfB5pW11CJgzRiOwyxqnNOSJg@mail.gmail.com> <CAG_fn=WM-JNOsBXHkVEtuWzk_UZATuRVUsEins2O5sxf0tYg4Q@mail.gmail.com>
In-Reply-To: <CAG_fn=WM-JNOsBXHkVEtuWzk_UZATuRVUsEins2O5sxf0tYg4Q@mail.gmail.com>
From: Raju Sana <venkat.rajuece@gmail.com>
Date: Sun, 31 May 2020 16:04:53 -0700
Message-ID: <CA+dZkako-AaeWJ71eHHLnJVWxbCUWkrc7b9sSWZPUSLL-ty=-w@mail.gmail.com>
Subject: Re: Need help in porting KASAN for 32 bit ARM on 5.4 kernel
To: Alexander Potapenko <glider@google.com>
Cc: Linus Walleij <linus.walleij@linaro.org>, Dmitry Vyukov <dvyukov@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, Abbott Liu <liuwenliang@huawei.com>
Content-Type: multipart/alternative; boundary="0000000000006f48d305a6f9b524"
X-Original-Sender: venkat.rajuece@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=dWO4dtSX;       spf=pass
 (google.com: domain of venkat.rajuece@gmail.com designates
 2a00:1450:4864:20::141 as permitted sender) smtp.mailfrom=venkat.rajuece@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

--0000000000006f48d305a6f9b524
Content-Type: text/plain; charset="UTF-8"

Thank yo Alexander.

Here is my the virtual memory lay out when CONFIG_KASAN  is not set and
when  target is booting..


Linux version 5.4.24 (vrsana@c-vsana-linux1) (gcc version 7.5.0)


Type:         Kernel Image
     Compression:  gzip compressed
     Data Start:   0x440000e4
     Data Size:    4435209 Bytes = 4.2 MiB
     Architecture: ARM
     OS:           Linux
     Load Address: 0x41208000
     Entry Point:  0x41208000



mem auto-init: stack:off, heap alloc:off, heap free:off
[    0.000000] Memory: 902460K/922624K available (6391K kernel code, 295K
rwdata, 1908K rodata, 1024K init, 233K bss, 20164K reserved, 0K
cma-reserved, 0K highmem)
[    0.000000] Virtual kernel memory layout:
[    0.000000]     fixmap  : 0xffc00000 - 0xfff00000   (3072 kB)
[    0.000000]     vmalloc : 0xbf800000 - 0xff800000   (1024 MB)
[    0.000000]     lowmem  : 0x80000000 - 0xbf000000   (1008 MB)
[    0.000000]     pkmap   : 0x7fe00000 - 0x80000000   (   2 MB)
[    0.000000]     modules : 0x7f000000 - 0x7fe00000   (  14 MB)
[    0.000000]       .text : 0x80208000 - 0x8093de88   (7383 kB)
[    0.000000]       .init : 0x80c00000 - 0x80d00000   (1024 kB)
[    0.000000]       .data : 0x80d00000 - 0x80d49cac   ( 295 kB)
[    0.000000]        .bss : 0x80d49cac - 0x80d84430   ( 233 kB)
[    0.000000] SLUB: HWalign=64, Order=0-3, MinObjects=0, CPUs=4, Nodes=1
[    0.000000] rcu: Preemptible hierarchical RCU implementation.



And configs are

CONFIG_KASAN_SHADOW_OFFSET=0x5f000000
CONFIG_HAVE_ARCH_KASAN=y
CONFIG_CC_HAS_KASAN_GENERIC=y
CONFIG_KASAN=y
CONFIG_KASAN_GENERIC=y
CONFIG_KASAN_OUTLINE=y
# CONFIG_KASAN_INLINE is not set
CONFIG_KASAN_STACK=0
# CONFIG_TEST_KASAN is not set


I will try disabling the instrumentation and post results here.


Thanks,
Venkat Sana.




On Sun, May 31, 2020 at 1:32 AM Alexander Potapenko <glider@google.com>
wrote:

>
>
> On Sat, May 30, 2020, 21:08 Raju Sana <venkat.rajuece@gmail.com> wrote:
>
>> Thank you Walleij.
>>
>> Interestingly , if I turn off   KASAN configs,  the target is booting ..
>>  Will check more and post details here if i find any clue.
>>
>
> This could be related to e.g. KASAN shadow overlapping with .text - check
> if your section layout leaves place for the KASAN shadow memory.
> You can also try disabling the instrumentation, leaving only KASAN runtime
> part and see if that boots. If it doesn't, look closer at the
> initialization routines.
> If the kernel boots without instrumentation, wrap the compiler into a
> script that strips away KASAN flags if the file name starts with [a-z].
> This build should also boot, as it effectively disables instrumentation. If
> it does, try narrowing down the set of files for which you disable the
> instrumentation.
>
> HTH,
> Alex
>
>
>> Thanks,
>> Venkat Sana.
>>
>> On Sat, May 30, 2020 at 3:55 AM Linus Walleij <linus.walleij@linaro.org>
>> wrote:
>>
>>> On Sat, May 30, 2020 at 5:54 AM Raju Sana <venkat.rajuece@gmail.com>
>>> wrote:
>>>
>>> > I took all the patches-V9   plus one @
>>> https://lore.kernel.org/linux-arm-kernel/20200515124808.213538-1-linus.walleij@linaro.org/
>>> >
>>> >
>>> > and I  hit below  BUG ,
>>> >
>>> > void notrace cpu_init(void)
>>> > {
>>> > #ifndef CONFIG_CPU_V7M
>>> >         unsigned int cpu = smp_processor_id();
>>> >         struct stack *stk = &stacks[cpu];
>>> >
>>> >         if (cpu >= NR_CPUS) {
>>> >                 pr_crit("CPU%u: bad primary CPU number\n", cpu);
>>> >                 BUG();
>>>
>>> That's weird, I can't see why that would have anything to do with KASan.
>>> Please see if you can figure it out!
>>>
>>> Yours,
>>> Linus Walleij
>>>
>> --
>> You received this message because you are subscribed to the Google Groups
>> "kasan-dev" group.
>> To unsubscribe from this group and stop receiving emails from it, send an
>> email to kasan-dev+unsubscribe@googlegroups.com.
>> To view this discussion on the web visit
>> https://groups.google.com/d/msgid/kasan-dev/CA%2BdZka%3D1cE1Zt71bH1K7ZZz0dPfB5pW11CJgzRiOwyxqnNOSJg%40mail.gmail.com
>> <https://groups.google.com/d/msgid/kasan-dev/CA%2BdZka%3D1cE1Zt71bH1K7ZZz0dPfB5pW11CJgzRiOwyxqnNOSJg%40mail.gmail.com?utm_medium=email&utm_source=footer>
>> .
>>
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BdZkako-AaeWJ71eHHLnJVWxbCUWkrc7b9sSWZPUSLL-ty%3D-w%40mail.gmail.com.

--0000000000006f48d305a6f9b524
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<div dir=3D"ltr">Thank yo=C2=A0Alexander.<div><br></div><div>Here is my the=
 virtual memory lay out when CONFIG_KASAN=C2=A0 is not set and when=C2=A0 t=
arget is booting..</div><div><br></div><div><br></div><div>Linux version 5.=
4.24 (vrsana@c-vsana-linux1) (gcc version 7.5.0)<br></div><div><br></div><d=
iv><br></div><div>Type: =C2=A0 =C2=A0 =C2=A0 =C2=A0 Kernel Image<br>=C2=A0 =
=C2=A0 =C2=A0Compression: =C2=A0gzip compressed<br>=C2=A0 =C2=A0 =C2=A0Data=
 Start: =C2=A0 0x440000e4<br>=C2=A0 =C2=A0 =C2=A0Data Size: =C2=A0 =C2=A044=
35209 Bytes =3D 4.2 MiB<br>=C2=A0 =C2=A0 =C2=A0Architecture: ARM<br>=C2=A0 =
=C2=A0 =C2=A0OS: =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 Linux<br>=C2=A0 =C2=A0 =
=C2=A0Load Address: 0x41208000<br>=C2=A0 =C2=A0 =C2=A0Entry Point: =C2=A00x=
41208000<br></div><div><br></div><div><br></div><div>=C2=A0</div><div>mem a=
uto-init: stack:off, heap alloc:off, heap free:off<br>[ =C2=A0 =C2=A00.0000=
00] Memory: 902460K/922624K available (6391K kernel code, 295K rwdata, 1908=
K rodata, 1024K init, 233K bss, 20164K reserved, 0K cma-reserved, 0K highme=
m)<br>[ =C2=A0 =C2=A00.000000] Virtual kernel memory layout:<br>[ =C2=A0 =
=C2=A00.000000] =C2=A0 =C2=A0 fixmap =C2=A0: 0xffc00000 - 0xfff00000 =C2=A0=
 (3072 kB)<br>[ =C2=A0 =C2=A00.000000] =C2=A0 =C2=A0 vmalloc : 0xbf800000 -=
 0xff800000 =C2=A0 (1024 MB)<br>[ =C2=A0 =C2=A00.000000] =C2=A0 =C2=A0 lowm=
em =C2=A0: 0x80000000 - 0xbf000000 =C2=A0 (1008 MB)<br>[ =C2=A0 =C2=A00.000=
000] =C2=A0 =C2=A0 pkmap =C2=A0 : 0x7fe00000 - 0x80000000 =C2=A0 ( =C2=A0 2=
 MB)<br>[ =C2=A0 =C2=A00.000000] =C2=A0 =C2=A0 modules : 0x7f000000 - 0x7fe=
00000 =C2=A0 ( =C2=A014 MB)<br>[ =C2=A0 =C2=A00.000000] =C2=A0 =C2=A0 =C2=
=A0 .text : 0x80208000 - 0x8093de88 =C2=A0 (7383 kB)<br>[ =C2=A0 =C2=A00.00=
0000] =C2=A0 =C2=A0 =C2=A0 .init : 0x80c00000 - 0x80d00000 =C2=A0 (1024 kB)=
<br>[ =C2=A0 =C2=A00.000000] =C2=A0 =C2=A0 =C2=A0 .data : 0x80d00000 - 0x80=
d49cac =C2=A0 ( 295 kB)<br>[ =C2=A0 =C2=A00.000000] =C2=A0 =C2=A0 =C2=A0 =
=C2=A0.bss : 0x80d49cac - 0x80d84430 =C2=A0 ( 233 kB)<br>[ =C2=A0 =C2=A00.0=
00000] SLUB: HWalign=3D64, Order=3D0-3, MinObjects=3D0, CPUs=3D4, Nodes=3D1=
<br>[ =C2=A0 =C2=A00.000000] rcu: Preemptible hierarchical RCU implementati=
on.<br></div><div><br></div><div><br></div><div><br></div><div>And configs =
are=C2=A0</div><div><br></div><div>CONFIG_KASAN_SHADOW_OFFSET=3D0x5f000000<=
br>CONFIG_HAVE_ARCH_KASAN=3Dy<br>CONFIG_CC_HAS_KASAN_GENERIC=3Dy<br>CONFIG_=
KASAN=3Dy<br>CONFIG_KASAN_GENERIC=3Dy<br>CONFIG_KASAN_OUTLINE=3Dy<br># CONF=
IG_KASAN_INLINE is not set<br>CONFIG_KASAN_STACK=3D0<br># CONFIG_TEST_KASAN=
 is not set<br></div><div><br></div><div><br></div><div>I will try disablin=
g the instrumentation and post results here.</div><div><br></div><div><br><=
/div><div>Thanks,</div><div>Venkat Sana.</div><div><br></div><div><br></div=
><div><br></div></div><br><div class=3D"gmail_quote"><div dir=3D"ltr" class=
=3D"gmail_attr">On Sun, May 31, 2020 at 1:32 AM Alexander Potapenko &lt;<a =
href=3D"mailto:glider@google.com">glider@google.com</a>&gt; wrote:<br></div=
><blockquote class=3D"gmail_quote" style=3D"margin:0px 0px 0px 0.8ex;border=
-left:1px solid rgb(204,204,204);padding-left:1ex"><div dir=3D"auto"><div><=
br><br><div class=3D"gmail_quote"><div dir=3D"ltr" class=3D"gmail_attr">On =
Sat, May 30, 2020, 21:08 Raju Sana &lt;<a href=3D"mailto:venkat.rajuece@gma=
il.com" target=3D"_blank">venkat.rajuece@gmail.com</a>&gt; wrote:<br></div>=
<blockquote class=3D"gmail_quote" style=3D"margin:0px 0px 0px 0.8ex;border-=
left:1px solid rgb(204,204,204);padding-left:1ex"><div dir=3D"ltr"><div sty=
le=3D"padding:20px 0px 0px;font-size:0.875rem;font-family:Roboto,RobotoDraf=
t,Helvetica,Arial,sans-serif">Thank you Walleij.<br><table cellpadding=3D"0=
" style=3D"border-collapse:collapse;margin-top:0px;width:auto;font-size:0.8=
75rem;letter-spacing:0.2px;display:block"><tbody style=3D"display:block"><t=
r style=3D"height:auto;display:flex"><td style=3D"white-space:nowrap;paddin=
g:0px;vertical-align:top;width:1237.75px;line-height:20px;display:block;max=
-height:20px"><br></td></tr></tbody></table></div><div style=3D"font-family=
:Roboto,RobotoDraft,Helvetica,Arial,sans-serif;font-size:medium"><div id=3D=
"gmail-m_-5327798032743465882m_-149581390995811377gmail-:1ih" style=3D"font=
-size:0.875rem;direction:ltr;margin:8px 0px 0px;padding:0px"><div id=3D"gma=
il-m_-5327798032743465882m_-149581390995811377gmail-:1ce" style=3D"overflow=
:hidden;font-variant-numeric:normal;font-variant-east-asian:normal;font-str=
etch:normal;font-size:small;line-height:1.5;font-family:Arial,Helvetica,san=
s-serif"><div dir=3D"ltr"><div>Interestingly , if I turn off=C2=A0 =C2=A0KA=
SAN configs,=C2=A0 the target is booting ..<br></div><div>=C2=A0Will check =
more and post details here if i find any clue.</div><div></div></div></div>=
</div></div></div></blockquote></div></div><div dir=3D"auto"><br></div><div=
 dir=3D"auto">This could be related to e.g. KASAN shadow overlapping with .=
text - check if your section layout leaves place for the KASAN shadow memor=
y.</div><div dir=3D"auto">You can also try disabling the instrumentation, l=
eaving only KASAN runtime part and see if that boots. If it doesn&#39;t, lo=
ok closer at the initialization routines.</div><div dir=3D"auto">If the ker=
nel boots without instrumentation, wrap the compiler into a script that str=
ips away KASAN flags if the file name starts with [a-z]. This build should =
also boot, as it effectively disables instrumentation. If it does, try narr=
owing down the set of files for which you disable the instrumentation.</div=
><div dir=3D"auto"><br></div><div dir=3D"auto">HTH,</div><div dir=3D"auto">=
Alex</div><div dir=3D"auto"><br></div><div dir=3D"auto"><div class=3D"gmail=
_quote"><blockquote class=3D"gmail_quote" style=3D"margin:0px 0px 0px 0.8ex=
;border-left:1px solid rgb(204,204,204);padding-left:1ex"><div dir=3D"ltr">=
<div style=3D"font-family:Roboto,RobotoDraft,Helvetica,Arial,sans-serif;fon=
t-size:medium"><div id=3D"gmail-m_-5327798032743465882m_-149581390995811377=
gmail-:1ih" style=3D"font-size:0.875rem;direction:ltr;margin:8px 0px 0px;pa=
dding:0px"><div id=3D"gmail-m_-5327798032743465882m_-149581390995811377gmai=
l-:1ce" style=3D"overflow:hidden;font-variant-numeric:normal;font-variant-e=
ast-asian:normal;font-stretch:normal;font-size:small;line-height:1.5;font-f=
amily:Arial,Helvetica,sans-serif"><div dir=3D"ltr"><div><br></div><div>Than=
ks,</div><div>Venkat Sana.</div></div></div></div></div></div><br><div clas=
s=3D"gmail_quote"><div dir=3D"ltr" class=3D"gmail_attr">On Sat, May 30, 202=
0 at 3:55 AM Linus Walleij &lt;<a href=3D"mailto:linus.walleij@linaro.org" =
rel=3D"noreferrer" target=3D"_blank">linus.walleij@linaro.org</a>&gt; wrote=
:<br></div><blockquote class=3D"gmail_quote" style=3D"margin:0px 0px 0px 0.=
8ex;border-left:1px solid rgb(204,204,204);padding-left:1ex">On Sat, May 30=
, 2020 at 5:54 AM Raju Sana &lt;<a href=3D"mailto:venkat.rajuece@gmail.com"=
 rel=3D"noreferrer" target=3D"_blank">venkat.rajuece@gmail.com</a>&gt; wrot=
e:<br>
<br>
&gt; I took all the patches-V9=C2=A0 =C2=A0plus one @ <a href=3D"https://lo=
re.kernel.org/linux-arm-kernel/20200515124808.213538-1-linus.walleij@linaro=
.org/" rel=3D"noreferrer noreferrer" target=3D"_blank">https://lore.kernel.=
org/linux-arm-kernel/20200515124808.213538-1-linus.walleij@linaro.org/</a><=
br>
&gt;<br>
&gt;<br>
&gt; and I=C2=A0 hit below=C2=A0 BUG ,<br>
&gt;<br>
&gt; void notrace cpu_init(void)<br>
&gt; {<br>
&gt; #ifndef CONFIG_CPU_V7M<br>
&gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0unsigned int cpu =3D smp_processor_id=
();<br>
&gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0struct stack *stk =3D &amp;stacks[cpu=
];<br>
&gt;<br>
&gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0if (cpu &gt;=3D NR_CPUS) {<br>
&gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0pr_crit(&=
quot;CPU%u: bad primary CPU number\n&quot;, cpu);<br>
&gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0BUG();<br=
>
<br>
That&#39;s weird, I can&#39;t see why that would have anything to do with K=
ASan.<br>
Please see if you can figure it out!<br>
<br>
Yours,<br>
Linus Walleij<br>
</blockquote></div>

<p></p>

-- <br>
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br>
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com" rel=3D"no=
referrer" target=3D"_blank">kasan-dev+unsubscribe@googlegroups.com</a>.<br>
To view this discussion on the web visit <a href=3D"https://groups.google.c=
om/d/msgid/kasan-dev/CA%2BdZka%3D1cE1Zt71bH1K7ZZz0dPfB5pW11CJgzRiOwyxqnNOSJ=
g%40mail.gmail.com?utm_medium=3Demail&amp;utm_source=3Dfooter" rel=3D"noref=
errer" target=3D"_blank">https://groups.google.com/d/msgid/kasan-dev/CA%2Bd=
Zka%3D1cE1Zt71bH1K7ZZz0dPfB5pW11CJgzRiOwyxqnNOSJg%40mail.gmail.com</a>.<br>
</blockquote></div></div></div>
</blockquote></div>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion on the web visit <a href=3D"https://groups.google.c=
om/d/msgid/kasan-dev/CA%2BdZkako-AaeWJ71eHHLnJVWxbCUWkrc7b9sSWZPUSLL-ty%3D-=
w%40mail.gmail.com?utm_medium=3Demail&utm_source=3Dfooter">https://groups.g=
oogle.com/d/msgid/kasan-dev/CA%2BdZkako-AaeWJ71eHHLnJVWxbCUWkrc7b9sSWZPUSLL=
-ty%3D-w%40mail.gmail.com</a>.<br />

--0000000000006f48d305a6f9b524--
