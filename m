Return-Path: <kasan-dev+bncBCFLDU5RYAIRBOXR2D3AKGQEKWMPWAQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23c.google.com (mail-lj1-x23c.google.com [IPv6:2a00:1450:4864:20::23c])
	by mail.lfdr.de (Postfix) with ESMTPS id 237831E9AC4
	for <lists+kasan-dev@lfdr.de>; Mon,  1 Jun 2020 01:07:39 +0200 (CEST)
Received: by mail-lj1-x23c.google.com with SMTP id c22sf811954lji.19
        for <lists+kasan-dev@lfdr.de>; Sun, 31 May 2020 16:07:39 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1590966458; cv=pass;
        d=google.com; s=arc-20160816;
        b=bT2k3nTpLO1AgH8BbFEGgHUdFzxrK422OmS1obaTWlYp0BbU4lXaT9hHBC7X+7/yu0
         DXferTPRKAuB4jbRhlBpr7NF68csDgBBc+ENhTNwoPqxZm87kNnmcGbBwS/ERbOaufIX
         pv09icrIHEvUC+yB5wlKHCL+6iZFqfleLCojEDDDs38zc/1U5wtVo1pBtMoGQHj7HheE
         /H+kR2GobIMQZBrOqRKu3e+xKNqC7j/WguICPVEvN63iVI8jcDnH5EfZEfTHS3lStpLR
         4g9UKzjw924ycwf96EaRSLmBA9A+F9XiKW3lKB8ZvMlPKy9QboPjV7V2KJO2eSXxl6+a
         ApFw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=CEJt+uS6yJI+q8h7+5LLgHya7JeW48kbI+EaDwDO2zs=;
        b=JDsCcn+Plb4/2/dpxbKbBA/Olniy8haUpDvfVt5dKHnBePFSO1xwySlsDR6uPYOZW6
         YuDeA+UmicN9ou5sSndJnwLC8IEAwF9VA6XiuSkXlMk3srVcVdaCuyiYylvjDaI7jzZw
         iUjJMloAZN3ueatlwHqwG6lT3Rc78+/z/Fz7bbaHr7uvjdWmOlYeQeLqjTI2rMTaDYEs
         Vq/MYN/Z4R5X5zUcKwyeZfUyLlR3XCFpvMa/KnBCVpCEjME8EG0XFQTZw0xxiaHQaOdW
         ByZe/73ztAXSAXXgHzn56TT7mfE734isJiM/sIKCzfiEAKtPexdddPmxNZyFnCb4fWS/
         PL1w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=jG3I1Ov+;
       spf=pass (google.com: domain of venkat.rajuece@gmail.com designates 2a00:1450:4864:20::231 as permitted sender) smtp.mailfrom=venkat.rajuece@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=CEJt+uS6yJI+q8h7+5LLgHya7JeW48kbI+EaDwDO2zs=;
        b=DhBoiTssLqQB5xLyRg/mHnUDU7hsWDe8cNEm7f7M3j/djK1scueNn4KgPNkhKHT4CR
         6bLQCZRyhLDd0gbLs7CuoKNKgwsFwsBwZRYn/heglVVFgCQd4GOd/vWQ6s7l7OYeRaya
         bTpzKye413kF6+S+HNIFhzOT4lLp805gjiWvcj/tRjRMyft82DCSTKXrNHj/HUMOEORG
         99xLyu/ndWVPguxin4YGbesZnC2vneetVvYy3HKb4W8vxKxXpmtQWD21bapjaZ6iYtQp
         hnW40kMhxKhSV9rO35q15KeR7oWtUZMyj6ehy6ordFrjGF3hl4voan3u/Lfu/NScdsdR
         t88Q==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=CEJt+uS6yJI+q8h7+5LLgHya7JeW48kbI+EaDwDO2zs=;
        b=K4dvAovLwwq1Gofa5mTv0nUsQQ57PhMzQ3rt67mIB2soBT3TAUdJ14VLtHyKiVhNRB
         gwGSLsKRBPr2O1c3TR1xqq4M1295zXTjDjNtp7mZ5VhuKE45B1fA4e4EczvD8uXwbsIb
         vgfoZZdafYJo8HYJ1PqOnDN3IcKe8qEoSO30Q211fC4/WDHYqw24Y9LaRZwpCvHk2krT
         7b8bxjratVSrO9209TnKbZvT2lQ75OB3ZEDOMbmocUP8oi0j/zvXV5aM4gTT7PPkPBw1
         y0AOk8wPdAEyMs91QkinhperHmsTcl0XXaE8v42KQVaph6ERXBxEGMrl+5wewio4MTII
         H66A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=CEJt+uS6yJI+q8h7+5LLgHya7JeW48kbI+EaDwDO2zs=;
        b=Gqx9//n5kiwwwBGf1ZYxxqigpr3r2HaPXAfsblDEBs4hRmRWkx6n2aDR09FoB8fQ9Y
         dowvUWf0N9X5vC8gZmQFRjl3WD0M8qQf7w42J9OlGS731hUfI7mi8iJzN/PnfEPYt6hG
         uMPIoiQQDEsNi1yDoTUkwFn5Tm+lQW5gVRcR2ObWPUcXVWCb52bDBkKlw65Z5iC9+QEB
         wIwzFo1uF0ogdOSXkEjvCpuWeUJdjjSAPZPEz/AMEpNqhHz8LCnuDAJuvkzTSb3VzMIH
         /fOq3KnUmbU3wWgX//9eN783eUHTdDr0pA7cjngLKbg80KMT+z0LJfkdI6UYH96qTsMx
         bzWA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5333MC0lk1+5WglteRe3wO8Caf+K/X0UkQLQOyk2CLZa9ePCnWDx
	XT2n7yaVAdweLnhIRTNoFEE=
X-Google-Smtp-Source: ABdhPJwFzn4pMAHKQx4MHeknXVL2h+gDSMwndb06EdX8VTTAf/VurPMetE1Xs4IZHK+wBzYQcz25KQ==
X-Received: by 2002:a19:5d44:: with SMTP id p4mr9605079lfj.56.1590966458653;
        Sun, 31 May 2020 16:07:38 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:9a53:: with SMTP id k19ls1327180ljj.9.gmail; Sun, 31 May
 2020 16:07:37 -0700 (PDT)
X-Received: by 2002:a05:651c:38e:: with SMTP id e14mr3843179ljp.452.1590966457711;
        Sun, 31 May 2020 16:07:37 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1590966457; cv=none;
        d=google.com; s=arc-20160816;
        b=cBWHcktJU/7KhkmB2JrEc5oU4ib3ny7cp8h/sn6UEcmSEJEUMa/LXA6W6uDGAiAKa1
         JnGe16SDCniRj/7dA3aAtkPrSoidb86Eb8BbvGvvPC+nwDtHnn+PG7cXJy04YSond4Vm
         kebEr/Io3QjNW0kBt6nBPzlwKytqGTkUlJErqeIGbJxRkD6fb+mHIH19jgEU6kVd5NJC
         NekyAoJn/T0Dq2CL05x++3sIFhEU67pDe/qz+MA04icLEPcVpX4KgbKbIddH3kjn5V0Q
         unXFDxWF5gLfrm08DbY4CxlCsroWXIqnxsYElAiOfVI8nOYPZTQXXpBE24Yp2nyVgE+F
         tH8w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=a+uV5EaYzGOeu7TmljvVgUHtj9Hgvj0BqzsVmsT2kqM=;
        b=bN8Nw+FUCzqE+AYXii7s7TKfphDJ/Uw8zWgpEz5rHtTkT92EkGXqib9ojZMbpXbyTj
         gW+wALY0IAxE96WwdwbQWx827jLhopCxT3Ii4gC8Mgoxg6GTyezm+vFeqdLFyQayJmIW
         tGgIZHLPqYchZHL/RSkM1+Z55qKTSFoGY/e1G3qV2A/N9g76Wo6idV67c31W8fGZQJLj
         jkxYRxqhuXDucLFcDQ1B/IrgWcTDiDtMEIbITsKZ1P+yPbzE3bINWKuhIPqDVYntmQFz
         osgcLmuSzeuzMEwUreqqO+tu3VF3LPi72Q9w7xnh+oaX3PaHLPR7GxnG9bJOigdxMVwx
         gXjQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=jG3I1Ov+;
       spf=pass (google.com: domain of venkat.rajuece@gmail.com designates 2a00:1450:4864:20::231 as permitted sender) smtp.mailfrom=venkat.rajuece@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-lj1-x231.google.com (mail-lj1-x231.google.com. [2a00:1450:4864:20::231])
        by gmr-mx.google.com with ESMTPS id i17si473155ljj.5.2020.05.31.16.07.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 31 May 2020 16:07:37 -0700 (PDT)
Received-SPF: pass (google.com: domain of venkat.rajuece@gmail.com designates 2a00:1450:4864:20::231 as permitted sender) client-ip=2a00:1450:4864:20::231;
Received: by mail-lj1-x231.google.com with SMTP id q2so5855502ljm.10
        for <kasan-dev@googlegroups.com>; Sun, 31 May 2020 16:07:37 -0700 (PDT)
X-Received: by 2002:a2e:8953:: with SMTP id b19mr4043389ljk.187.1590966457312;
 Sun, 31 May 2020 16:07:37 -0700 (PDT)
MIME-Version: 1.0
References: <CA+dZkamtaXi8yr=khO+E9SKe9QBR-Z0e0kdH4DzhQdzo8o-+Eg@mail.gmail.com>
 <CACT4Y+YS5b2PokFVvw69Mfo-jjE13jGAqYmtEJQa7tVHm=CjgQ@mail.gmail.com>
 <CACRpkdZzj6MRJk3sFN+ihw8ZksZ-WF=CJNsxuazkAYPmd=Ki_Q@mail.gmail.com>
 <CA+dZkanvC+RU0DjiCz=4e+Zhy+mEux-NHX5VO5YUCkhowN4Z_g@mail.gmail.com>
 <CACRpkdZv_6RN2vt5paCDx2g9DWsKT6LZTw1+jrLZNqVrLvKQWA@mail.gmail.com>
 <CA+dZka=1cE1Zt71bH1K7ZZz0dPfB5pW11CJgzRiOwyxqnNOSJg@mail.gmail.com>
 <CAG_fn=WM-JNOsBXHkVEtuWzk_UZATuRVUsEins2O5sxf0tYg4Q@mail.gmail.com> <CA+dZkako-AaeWJ71eHHLnJVWxbCUWkrc7b9sSWZPUSLL-ty=-w@mail.gmail.com>
In-Reply-To: <CA+dZkako-AaeWJ71eHHLnJVWxbCUWkrc7b9sSWZPUSLL-ty=-w@mail.gmail.com>
From: Raju Sana <venkat.rajuece@gmail.com>
Date: Sun, 31 May 2020 16:07:26 -0700
Message-ID: <CA+dZkakg-PpowaqknoKcoy3RDWSNbEAqSVm01SOOYDxZKV-WOA@mail.gmail.com>
Subject: Re: Need help in porting KASAN for 32 bit ARM on 5.4 kernel
To: Alexander Potapenko <glider@google.com>
Cc: Linus Walleij <linus.walleij@linaro.org>, Dmitry Vyukov <dvyukov@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, Abbott Liu <liuwenliang@huawei.com>
Content-Type: multipart/alternative; boundary="00000000000089ab4505a6f9be65"
X-Original-Sender: venkat.rajuece@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=jG3I1Ov+;       spf=pass
 (google.com: domain of venkat.rajuece@gmail.com designates
 2a00:1450:4864:20::231 as permitted sender) smtp.mailfrom=venkat.rajuece@gmail.com;
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

--00000000000089ab4505a6f9be65
Content-Type: text/plain; charset="UTF-8"

And I am  loading image @ 0x44000000 in DDR and boot  using  "bootm
0x44000000"


Thanks,
Venkat Sana.

On Sun, May 31, 2020 at 4:04 PM Raju Sana <venkat.rajuece@gmail.com> wrote:

> Thank yo Alexander.
>
> Here is my the virtual memory lay out when CONFIG_KASAN  is not set and
> when  target is booting..
>
>
> Linux version 5.4.24 (vrsana@c-vsana-linux1) (gcc version 7.5.0)
>
>
> Type:         Kernel Image
>      Compression:  gzip compressed
>      Data Start:   0x440000e4
>      Data Size:    4435209 Bytes = 4.2 MiB
>      Architecture: ARM
>      OS:           Linux
>      Load Address: 0x41208000
>      Entry Point:  0x41208000
>
>
>
> mem auto-init: stack:off, heap alloc:off, heap free:off
> [    0.000000] Memory: 902460K/922624K available (6391K kernel code, 295K
> rwdata, 1908K rodata, 1024K init, 233K bss, 20164K reserved, 0K
> cma-reserved, 0K highmem)
> [    0.000000] Virtual kernel memory layout:
> [    0.000000]     fixmap  : 0xffc00000 - 0xfff00000   (3072 kB)
> [    0.000000]     vmalloc : 0xbf800000 - 0xff800000   (1024 MB)
> [    0.000000]     lowmem  : 0x80000000 - 0xbf000000   (1008 MB)
> [    0.000000]     pkmap   : 0x7fe00000 - 0x80000000   (   2 MB)
> [    0.000000]     modules : 0x7f000000 - 0x7fe00000   (  14 MB)
> [    0.000000]       .text : 0x80208000 - 0x8093de88   (7383 kB)
> [    0.000000]       .init : 0x80c00000 - 0x80d00000   (1024 kB)
> [    0.000000]       .data : 0x80d00000 - 0x80d49cac   ( 295 kB)
> [    0.000000]        .bss : 0x80d49cac - 0x80d84430   ( 233 kB)
> [    0.000000] SLUB: HWalign=64, Order=0-3, MinObjects=0, CPUs=4, Nodes=1
> [    0.000000] rcu: Preemptible hierarchical RCU implementation.
>
>
>
> And configs are
>
> CONFIG_KASAN_SHADOW_OFFSET=0x5f000000
> CONFIG_HAVE_ARCH_KASAN=y
> CONFIG_CC_HAS_KASAN_GENERIC=y
> CONFIG_KASAN=y
> CONFIG_KASAN_GENERIC=y
> CONFIG_KASAN_OUTLINE=y
> # CONFIG_KASAN_INLINE is not set
> CONFIG_KASAN_STACK=0
> # CONFIG_TEST_KASAN is not set
>
>
> I will try disabling the instrumentation and post results here.
>
>
> Thanks,
> Venkat Sana.
>
>
>
>
> On Sun, May 31, 2020 at 1:32 AM Alexander Potapenko <glider@google.com>
> wrote:
>
>>
>>
>> On Sat, May 30, 2020, 21:08 Raju Sana <venkat.rajuece@gmail.com> wrote:
>>
>>> Thank you Walleij.
>>>
>>> Interestingly , if I turn off   KASAN configs,  the target is booting ..
>>>  Will check more and post details here if i find any clue.
>>>
>>
>> This could be related to e.g. KASAN shadow overlapping with .text - check
>> if your section layout leaves place for the KASAN shadow memory.
>> You can also try disabling the instrumentation, leaving only KASAN
>> runtime part and see if that boots. If it doesn't, look closer at the
>> initialization routines.
>> If the kernel boots without instrumentation, wrap the compiler into a
>> script that strips away KASAN flags if the file name starts with [a-z].
>> This build should also boot, as it effectively disables instrumentation. If
>> it does, try narrowing down the set of files for which you disable the
>> instrumentation.
>>
>> HTH,
>> Alex
>>
>>
>>> Thanks,
>>> Venkat Sana.
>>>
>>> On Sat, May 30, 2020 at 3:55 AM Linus Walleij <linus.walleij@linaro.org>
>>> wrote:
>>>
>>>> On Sat, May 30, 2020 at 5:54 AM Raju Sana <venkat.rajuece@gmail.com>
>>>> wrote:
>>>>
>>>> > I took all the patches-V9   plus one @
>>>> https://lore.kernel.org/linux-arm-kernel/20200515124808.213538-1-linus.walleij@linaro.org/
>>>> >
>>>> >
>>>> > and I  hit below  BUG ,
>>>> >
>>>> > void notrace cpu_init(void)
>>>> > {
>>>> > #ifndef CONFIG_CPU_V7M
>>>> >         unsigned int cpu = smp_processor_id();
>>>> >         struct stack *stk = &stacks[cpu];
>>>> >
>>>> >         if (cpu >= NR_CPUS) {
>>>> >                 pr_crit("CPU%u: bad primary CPU number\n", cpu);
>>>> >                 BUG();
>>>>
>>>> That's weird, I can't see why that would have anything to do with KASan.
>>>> Please see if you can figure it out!
>>>>
>>>> Yours,
>>>> Linus Walleij
>>>>
>>> --
>>> You received this message because you are subscribed to the Google
>>> Groups "kasan-dev" group.
>>> To unsubscribe from this group and stop receiving emails from it, send
>>> an email to kasan-dev+unsubscribe@googlegroups.com.
>>> To view this discussion on the web visit
>>> https://groups.google.com/d/msgid/kasan-dev/CA%2BdZka%3D1cE1Zt71bH1K7ZZz0dPfB5pW11CJgzRiOwyxqnNOSJg%40mail.gmail.com
>>> <https://groups.google.com/d/msgid/kasan-dev/CA%2BdZka%3D1cE1Zt71bH1K7ZZz0dPfB5pW11CJgzRiOwyxqnNOSJg%40mail.gmail.com?utm_medium=email&utm_source=footer>
>>> .
>>>
>>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BdZkakg-PpowaqknoKcoy3RDWSNbEAqSVm01SOOYDxZKV-WOA%40mail.gmail.com.

--00000000000089ab4505a6f9be65
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<div dir=3D"ltr">And I am=C2=A0 loading image=C2=A0@ 0x44000000 in DDR and =
boot=C2=A0 using=C2=A0 &quot;bootm=C2=A0=C2=A0

0x44000000&quot;<div><br></div><div><br></div><div>Thanks,</div><div>Venkat=
 Sana.</div></div><br><div class=3D"gmail_quote"><div dir=3D"ltr" class=3D"=
gmail_attr">On Sun, May 31, 2020 at 4:04 PM Raju Sana &lt;<a href=3D"mailto=
:venkat.rajuece@gmail.com">venkat.rajuece@gmail.com</a>&gt; wrote:<br></div=
><blockquote class=3D"gmail_quote" style=3D"margin:0px 0px 0px 0.8ex;border=
-left:1px solid rgb(204,204,204);padding-left:1ex"><div dir=3D"ltr">Thank y=
o=C2=A0Alexander.<div><br></div><div>Here is my the virtual memory lay out =
when CONFIG_KASAN=C2=A0 is not set and when=C2=A0 target is booting..</div>=
<div><br></div><div><br></div><div>Linux version 5.4.24 (vrsana@c-vsana-lin=
ux1) (gcc version 7.5.0)<br></div><div><br></div><div><br></div><div>Type: =
=C2=A0 =C2=A0 =C2=A0 =C2=A0 Kernel Image<br>=C2=A0 =C2=A0 =C2=A0Compression=
: =C2=A0gzip compressed<br>=C2=A0 =C2=A0 =C2=A0Data Start: =C2=A0 0x440000e=
4<br>=C2=A0 =C2=A0 =C2=A0Data Size: =C2=A0 =C2=A04435209 Bytes =3D 4.2 MiB<=
br>=C2=A0 =C2=A0 =C2=A0Architecture: ARM<br>=C2=A0 =C2=A0 =C2=A0OS: =C2=A0 =
=C2=A0 =C2=A0 =C2=A0 =C2=A0 Linux<br>=C2=A0 =C2=A0 =C2=A0Load Address: 0x41=
208000<br>=C2=A0 =C2=A0 =C2=A0Entry Point: =C2=A00x41208000<br></div><div><=
br></div><div><br></div><div>=C2=A0</div><div>mem auto-init: stack:off, hea=
p alloc:off, heap free:off<br>[ =C2=A0 =C2=A00.000000] Memory: 902460K/9226=
24K available (6391K kernel code, 295K rwdata, 1908K rodata, 1024K init, 23=
3K bss, 20164K reserved, 0K cma-reserved, 0K highmem)<br>[ =C2=A0 =C2=A00.0=
00000] Virtual kernel memory layout:<br>[ =C2=A0 =C2=A00.000000] =C2=A0 =C2=
=A0 fixmap =C2=A0: 0xffc00000 - 0xfff00000 =C2=A0 (3072 kB)<br>[ =C2=A0 =C2=
=A00.000000] =C2=A0 =C2=A0 vmalloc : 0xbf800000 - 0xff800000 =C2=A0 (1024 M=
B)<br>[ =C2=A0 =C2=A00.000000] =C2=A0 =C2=A0 lowmem =C2=A0: 0x80000000 - 0x=
bf000000 =C2=A0 (1008 MB)<br>[ =C2=A0 =C2=A00.000000] =C2=A0 =C2=A0 pkmap =
=C2=A0 : 0x7fe00000 - 0x80000000 =C2=A0 ( =C2=A0 2 MB)<br>[ =C2=A0 =C2=A00.=
000000] =C2=A0 =C2=A0 modules : 0x7f000000 - 0x7fe00000 =C2=A0 ( =C2=A014 M=
B)<br>[ =C2=A0 =C2=A00.000000] =C2=A0 =C2=A0 =C2=A0 .text : 0x80208000 - 0x=
8093de88 =C2=A0 (7383 kB)<br>[ =C2=A0 =C2=A00.000000] =C2=A0 =C2=A0 =C2=A0 =
.init : 0x80c00000 - 0x80d00000 =C2=A0 (1024 kB)<br>[ =C2=A0 =C2=A00.000000=
] =C2=A0 =C2=A0 =C2=A0 .data : 0x80d00000 - 0x80d49cac =C2=A0 ( 295 kB)<br>=
[ =C2=A0 =C2=A00.000000] =C2=A0 =C2=A0 =C2=A0 =C2=A0.bss : 0x80d49cac - 0x8=
0d84430 =C2=A0 ( 233 kB)<br>[ =C2=A0 =C2=A00.000000] SLUB: HWalign=3D64, Or=
der=3D0-3, MinObjects=3D0, CPUs=3D4, Nodes=3D1<br>[ =C2=A0 =C2=A00.000000] =
rcu: Preemptible hierarchical RCU implementation.<br></div><div><br></div><=
div><br></div><div><br></div><div>And configs are=C2=A0</div><div><br></div=
><div>CONFIG_KASAN_SHADOW_OFFSET=3D0x5f000000<br>CONFIG_HAVE_ARCH_KASAN=3Dy=
<br>CONFIG_CC_HAS_KASAN_GENERIC=3Dy<br>CONFIG_KASAN=3Dy<br>CONFIG_KASAN_GEN=
ERIC=3Dy<br>CONFIG_KASAN_OUTLINE=3Dy<br># CONFIG_KASAN_INLINE is not set<br=
>CONFIG_KASAN_STACK=3D0<br># CONFIG_TEST_KASAN is not set<br></div><div><br=
></div><div><br></div><div>I will try disabling the instrumentation and pos=
t results here.</div><div><br></div><div><br></div><div>Thanks,</div><div>V=
enkat Sana.</div><div><br></div><div><br></div><div><br></div></div><br><di=
v class=3D"gmail_quote"><div dir=3D"ltr" class=3D"gmail_attr">On Sun, May 3=
1, 2020 at 1:32 AM Alexander Potapenko &lt;<a href=3D"mailto:glider@google.=
com" target=3D"_blank">glider@google.com</a>&gt; wrote:<br></div><blockquot=
e class=3D"gmail_quote" style=3D"margin:0px 0px 0px 0.8ex;border-left:1px s=
olid rgb(204,204,204);padding-left:1ex"><div dir=3D"auto"><div><br><br><div=
 class=3D"gmail_quote"><div dir=3D"ltr" class=3D"gmail_attr">On Sat, May 30=
, 2020, 21:08 Raju Sana &lt;<a href=3D"mailto:venkat.rajuece@gmail.com" tar=
get=3D"_blank">venkat.rajuece@gmail.com</a>&gt; wrote:<br></div><blockquote=
 class=3D"gmail_quote" style=3D"margin:0px 0px 0px 0.8ex;border-left:1px so=
lid rgb(204,204,204);padding-left:1ex"><div dir=3D"ltr"><div style=3D"paddi=
ng:20px 0px 0px;font-size:0.875rem;font-family:Roboto,RobotoDraft,Helvetica=
,Arial,sans-serif">Thank you Walleij.<br><table cellpadding=3D"0" style=3D"=
border-collapse:collapse;margin-top:0px;width:auto;font-size:0.875rem;lette=
r-spacing:0.2px;display:block"><tbody style=3D"display:block"><tr style=3D"=
height:auto;display:flex"><td style=3D"white-space:nowrap;padding:0px;verti=
cal-align:top;width:1237.75px;line-height:20px;display:block;max-height:20p=
x"><br></td></tr></tbody></table></div><div style=3D"font-family:Roboto,Rob=
otoDraft,Helvetica,Arial,sans-serif;font-size:medium"><div id=3D"gmail-m_80=
2970006006843863gmail-m_-5327798032743465882m_-149581390995811377gmail-:1ih=
" style=3D"font-size:0.875rem;direction:ltr;margin:8px 0px 0px;padding:0px"=
><div id=3D"gmail-m_802970006006843863gmail-m_-5327798032743465882m_-149581=
390995811377gmail-:1ce" style=3D"overflow:hidden;font-variant-numeric:norma=
l;font-variant-east-asian:normal;font-stretch:normal;font-size:small;line-h=
eight:1.5;font-family:Arial,Helvetica,sans-serif"><div dir=3D"ltr"><div>Int=
erestingly , if I turn off=C2=A0 =C2=A0KASAN configs,=C2=A0 the target is b=
ooting ..<br></div><div>=C2=A0Will check more and post details here if i fi=
nd any clue.</div><div></div></div></div></div></div></div></blockquote></d=
iv></div><div dir=3D"auto"><br></div><div dir=3D"auto">This could be relate=
d to e.g. KASAN shadow overlapping with .text - check if your section layou=
t leaves place for the KASAN shadow memory.</div><div dir=3D"auto">You can =
also try disabling the instrumentation, leaving only KASAN runtime part and=
 see if that boots. If it doesn&#39;t, look closer at the initialization ro=
utines.</div><div dir=3D"auto">If the kernel boots without instrumentation,=
 wrap the compiler into a script that strips away KASAN flags if the file n=
ame starts with [a-z]. This build should also boot, as it effectively disab=
les instrumentation. If it does, try narrowing down the set of files for wh=
ich you disable the instrumentation.</div><div dir=3D"auto"><br></div><div =
dir=3D"auto">HTH,</div><div dir=3D"auto">Alex</div><div dir=3D"auto"><br></=
div><div dir=3D"auto"><div class=3D"gmail_quote"><blockquote class=3D"gmail=
_quote" style=3D"margin:0px 0px 0px 0.8ex;border-left:1px solid rgb(204,204=
,204);padding-left:1ex"><div dir=3D"ltr"><div style=3D"font-family:Roboto,R=
obotoDraft,Helvetica,Arial,sans-serif;font-size:medium"><div id=3D"gmail-m_=
802970006006843863gmail-m_-5327798032743465882m_-149581390995811377gmail-:1=
ih" style=3D"font-size:0.875rem;direction:ltr;margin:8px 0px 0px;padding:0p=
x"><div id=3D"gmail-m_802970006006843863gmail-m_-5327798032743465882m_-1495=
81390995811377gmail-:1ce" style=3D"overflow:hidden;font-variant-numeric:nor=
mal;font-variant-east-asian:normal;font-stretch:normal;font-size:small;line=
-height:1.5;font-family:Arial,Helvetica,sans-serif"><div dir=3D"ltr"><div><=
br></div><div>Thanks,</div><div>Venkat Sana.</div></div></div></div></div><=
/div><br><div class=3D"gmail_quote"><div dir=3D"ltr" class=3D"gmail_attr">O=
n Sat, May 30, 2020 at 3:55 AM Linus Walleij &lt;<a href=3D"mailto:linus.wa=
lleij@linaro.org" rel=3D"noreferrer" target=3D"_blank">linus.walleij@linaro=
.org</a>&gt; wrote:<br></div><blockquote class=3D"gmail_quote" style=3D"mar=
gin:0px 0px 0px 0.8ex;border-left:1px solid rgb(204,204,204);padding-left:1=
ex">On Sat, May 30, 2020 at 5:54 AM Raju Sana &lt;<a href=3D"mailto:venkat.=
rajuece@gmail.com" rel=3D"noreferrer" target=3D"_blank">venkat.rajuece@gmai=
l.com</a>&gt; wrote:<br>
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
</blockquote></div>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion on the web visit <a href=3D"https://groups.google.c=
om/d/msgid/kasan-dev/CA%2BdZkakg-PpowaqknoKcoy3RDWSNbEAqSVm01SOOYDxZKV-WOA%=
40mail.gmail.com?utm_medium=3Demail&utm_source=3Dfooter">https://groups.goo=
gle.com/d/msgid/kasan-dev/CA%2BdZkakg-PpowaqknoKcoy3RDWSNbEAqSVm01SOOYDxZKV=
-WOA%40mail.gmail.com</a>.<br />

--00000000000089ab4505a6f9be65--
