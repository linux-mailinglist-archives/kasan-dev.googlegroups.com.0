Return-Path: <kasan-dev+bncBCU4TIPXUUFRBJFOSGHAMGQEO35DJ5Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x239.google.com (mail-oi1-x239.google.com [IPv6:2607:f8b0:4864:20::239])
	by mail.lfdr.de (Postfix) with ESMTPS id D6FAC47E1E7
	for <lists+kasan-dev@lfdr.de>; Thu, 23 Dec 2021 12:01:57 +0100 (CET)
Received: by mail-oi1-x239.google.com with SMTP id j125-20020aca3c83000000b002bc93dd9241sf2675100oia.4
        for <lists+kasan-dev@lfdr.de>; Thu, 23 Dec 2021 03:01:57 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1640257316; cv=pass;
        d=google.com; s=arc-20160816;
        b=GLewga6BfuZS786Nm5BnEpjIUCV6B2Td6zi/LI7nCCrJltlF9SqB4e0pidwyG5Pd7P
         m9/wo+adB1bT/6T/1lUtgtVulliyA+HM7KTlufc45CWLeOxc7fXpmNsZZYVQA/Hb7inO
         lfWgwLeQB0Td2C8UrcNOJBhMfSKCC19SyL73gLcIZJvjo8jkcnpfKR2Xvhw863tnTE2V
         +T4PwB0QD+wG3NcX1Iyt3edNNcyLATg4dSLjtMjU7hF5CRpSxX/TcPdy5HoqowANeEEL
         OlEBP35/6+yjUxJpKW7NdP2qAZwRtw86W7EEruOiqWbH9MzJgHdN3KqKyNuhYMqiCJTp
         aojw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=nOQ/dZkxlIIWOO4xC+ellHygzWzaLbpqTcMD7Mb9Tm4=;
        b=Bu7gdWcP7iXgcNL3V28SBHxhJ4ILPwciAnGg/pZ4KQmy57jYnm/1E3Jq84SXBVv80b
         uW1+FUwtE0ETVk4xDpUEorjygmxyvIYF63ZsbLLQxVp59uObLdz4pIYJUuYBaP+yQ+L1
         cR+rEYWqoYJjcyDvBuELBRdqIMd/aSTtVQOBPDDnCwUlqdI+w17Nep3lzMz3f5lXd4sG
         j5vitPu7T/v6L+K+v9kTGvNYSEAdLXA546oRZBJAjdqf5dGeKdhpl9IHk52PlB4RDHws
         lh+ag6GA31mk7Gy3EAPn/WqlbIVBdiHX+RegcTG3JrgWBhTc/IY5qw45YpUr402yGuST
         dBcg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=lthZXy50;
       spf=pass (google.com: domain of ardb@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=ardb@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=nOQ/dZkxlIIWOO4xC+ellHygzWzaLbpqTcMD7Mb9Tm4=;
        b=Hn2CvncFYrmC0Kjv7mRJZkBhg3UynZbERzomCb7Hs+rjnAGy/pbKijZv0jBAasbaSN
         b1DN3vrGovmHXoaNSiclziBe4rMoiyS0cn11hqAzm4kzPUNqfofeXa2GE1I8RaPdR7b0
         OFZ6uXCRdA4FcjqNO7869/deBfKaKKllGgvP94pE4NPjOWPiHvAsu0J0YFBKFQHjQI3R
         4rwpsHRvCUK5GUkB9V+Q4dg/CZuVe/tPs92m6BBEDv17fQagd5CTGN4DwmMsOJTibBaR
         qcZpOKzC6XJEKueiVVaIUeTNrOqg4fwESBwJIeQh288VD1OSEf3CaIjaERmDVd9uAb3W
         CR5w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=nOQ/dZkxlIIWOO4xC+ellHygzWzaLbpqTcMD7Mb9Tm4=;
        b=0/3u7EZDoHKdmMu3wmUY17QZfZvKQXHCCi52ToOovBb9hSb/2ioR4qD1Ed+dRzmXag
         e5QtsB0YOMjv1ahSaE/2KKq5RDAbPW5jD/BCs+Ol8l/DqP5RaWmMsS3LufQJiWhK0PK7
         2f0ntbrJz6WirQ86ho9/YANR6jBU/Gf9ZBHryvhttslFAhrs1+5mRndnk7F1ctf7nvI9
         TRFXstbIAi7ZOA+VrPiwF93iBIBkg2eZVpvg2+kw8SD3a2u/CFyl9alAMC9ePz3mjyl6
         G+4GUdeCdlIvIARY+P5nu8K5ZOVQqbRWDelm+jHiEZYS6UpKzRC2Uy03hy5i0WIBzgnq
         69nQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530SnlZ8ZIQjclECWVL4Wn/W+8Rx6Q82049jj0jzhVcRD1ZcYSsQ
	viHt5gdGTqglJswK8bv7/ro=
X-Google-Smtp-Source: ABdhPJwbDid2gxcvRHkThc1Oh7dH1Ut/qNphfiy5qLxm+iLI0Dtn2BoppipxEGNTlWD+7Fehk2crOQ==
X-Received: by 2002:aca:1303:: with SMTP id e3mr1286093oii.43.1640257316462;
        Thu, 23 Dec 2021 03:01:56 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:440b:: with SMTP id q11ls1061600otv.0.gmail; Thu,
 23 Dec 2021 03:01:56 -0800 (PST)
X-Received: by 2002:a05:6830:34a0:: with SMTP id c32mr1143891otu.379.1640257316125;
        Thu, 23 Dec 2021 03:01:56 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1640257316; cv=none;
        d=google.com; s=arc-20160816;
        b=UOEcrMctX68NQ9NWy41+Xs8N9Bb0+E7upOGpCGRiXw7u1YSM3vUcAxmTHHCii8jWJW
         6fXacLSqXIyzkXerwSp9ou3tUNUTas8YHZAHMKdgONDUVWN59yALd6y/JD/D5HhTvmJj
         MWgDZ9N0Ac0V5ESgFtBqt9GDnRBOZswWWZoc9UAAThZtUw8id09Xtz++wwRx91Fx5p0w
         TuZc2POWE/KiHk0y5RijeW2ANA39m7YIumRGkaw8FhcUPpZI7XlZ4B7hNI6EU8kxmdRv
         gPqsqHk7G9M9Er/E9J3fbUErrn9xX+6hHGOJn1FgJKasg/axohINU6CpFnQ9byMdfnj+
         ps7A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=bYu3bQrGUnXVpSn4FW+COo8ndIvddTh7n6upAFyGS2s=;
        b=DBVVPIj637OJXlRxZO1aJF8BCcsYTdE3S5voUwGJGd16w/YDINFhAowRp81dWX/TY+
         BVu2TfDUtfATVghzmvN2yJNlURw+vV1kca8g1XcyLVkphsoRExet+Iqq5AzdiIhU/+51
         W2kNdOqofBFGbzPtwH90+hRQSDaXvIZGDWcQGpa8u5zoilAxIdTPFSF7UJiQAq7zufv8
         E355TNj7u/AgOHlGd9P7ngPTOeheg8DIdB/2fqtuBwnP6QS159xdQ5E8GdiXLWa1zeX1
         SqkjfoQWEOmxU65ZebuZrI77SFV5JaWyeTd2aqMgkfGQn0GfjEBW6DIZGmGfvopSPG/k
         O3Kg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=lthZXy50;
       spf=pass (google.com: domain of ardb@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=ardb@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id l22si295958ooe.0.2021.12.23.03.01.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 23 Dec 2021 03:01:56 -0800 (PST)
Received-SPF: pass (google.com: domain of ardb@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id B9C5361E00
	for <kasan-dev@googlegroups.com>; Thu, 23 Dec 2021 11:01:55 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 316E6C36AEE
	for <kasan-dev@googlegroups.com>; Thu, 23 Dec 2021 11:01:55 +0000 (UTC)
Received: by mail-wm1-f47.google.com with SMTP id bg2-20020a05600c3c8200b0034565c2be15so5465504wmb.0
        for <kasan-dev@googlegroups.com>; Thu, 23 Dec 2021 03:01:55 -0800 (PST)
X-Received: by 2002:a1c:1f93:: with SMTP id f141mr1304483wmf.56.1640257313324;
 Thu, 23 Dec 2021 03:01:53 -0800 (PST)
MIME-Version: 1.0
References: <20211223101551.19991-1-lecopzer.chen@mediatek.com>
In-Reply-To: <20211223101551.19991-1-lecopzer.chen@mediatek.com>
From: Ard Biesheuvel <ardb@kernel.org>
Date: Thu, 23 Dec 2021 12:01:41 +0100
X-Gmail-Original-Message-ID: <CAMj1kXGL++stjcuryn8zVwMgH4F05mONoU3Kca9Ch8N2dW-_bg@mail.gmail.com>
Message-ID: <CAMj1kXGL++stjcuryn8zVwMgH4F05mONoU3Kca9Ch8N2dW-_bg@mail.gmail.com>
Subject: Re: [PATCH] ARM: module: fix MODULE_PLTS not work for KASAN
To: Lecopzer Chen <lecopzer.chen@mediatek.com>
Cc: Linux Kernel Mailing List <linux-kernel@vger.kernel.org>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, Russell King <linux@armlinux.org.uk>, 
	Abbott Liu <liuwenliang@huawei.com>, Linus Walleij <linus.walleij@linaro.org>, 
	Florian Fainelli <f.fainelli@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, yj.chiang@mediatek.com, 
	"# 3.4.x" <stable@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: ardb@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=lthZXy50;       spf=pass
 (google.com: domain of ardb@kernel.org designates 2604:1380:4641:c500::1 as
 permitted sender) smtp.mailfrom=ardb@kernel.org;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=kernel.org
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

On Thu, 23 Dec 2021 at 11:16, Lecopzer Chen <lecopzer.chen@mediatek.com> wrote:
>
> When we run out of module space address with ko insertion,
> and with MODULE_PLTS, module would turn to try to find memory
> from VMALLOC address space.
>
> Unfortunately, with KASAN enabled, VMALLOC doesn't work without
> VMALLOC_KASAN which is unimplemented in ARM.
>
> hello: loading out-of-tree module taints kernel.
> 8<--- cut here ---
>  Unable to handle kernel paging request at virtual address bd300860
>  [bd300860] *pgd=41cf1811, *pte=41cf26df, *ppte=41cf265f
>  Internal error: Oops: 80f [#1] PREEMPT SMP ARM
>  Modules linked in: hello(O+)
>  CPU: 0 PID: 89 Comm: insmod Tainted: G           O      5.16.0-rc6+ #19
>  Hardware name: Generic DT based system
>  PC is at mmioset+0x30/0xa8
>  LR is at 0x0
>  pc : [<c077ed30>]    lr : [<00000000>]    psr: 20000013
>  sp : c451fc18  ip : bd300860  fp : c451fc2c
>  r10: f18042cc  r9 : f18042d0  r8 : 00000000
>  r7 : 00000001  r6 : 00000003  r5 : 01312d00  r4 : f1804300
>  r3 : 00000000  r2 : 00262560  r1 : 00000000  r0 : bd300860
>  Flags: nzCv  IRQs on  FIQs on  Mode SVC_32  ISA ARM  Segment none
>  Control: 10c5387d  Table: 43e9406a  DAC: 00000051
>  Register r0 information: non-paged memory
>  Register r1 information: NULL pointer
>  Register r2 information: non-paged memory
>  Register r3 information: NULL pointer
>  Register r4 information: 4887-page vmalloc region starting at 0xf1802000 allocated at load_module+0x14f4/0x32a8
>  Register r5 information: non-paged memory
>  Register r6 information: non-paged memory
>  Register r7 information: non-paged memory
>  Register r8 information: NULL pointer
>  Register r9 information: 4887-page vmalloc region starting at 0xf1802000 allocated at load_module+0x14f4/0x32a8
>  Register r10 information: 4887-page vmalloc region starting at 0xf1802000 allocated at load_module+0x14f4/0x32a8
>  Register r11 information: non-slab/vmalloc memory
>  Register r12 information: non-paged memory
>  Process insmod (pid: 89, stack limit = 0xc451c000)
>  Stack: (0xc451fc18 to 0xc4520000)
>  fc00:                                                       f18041f0 c04803a4
>  fc20: c451fc44 c451fc30 c048053c c0480358 f1804030 01312cff c451fc64 c451fc48
>  fc40: c047f330 c0480500 f18040c0 c1b52ccc 00000001 c5be7700 c451fc74 c451fc68
>  fc60: f1802098 c047f300 c451fcb4 c451fc78 c026106c f180208c c4880004 00000000
>  fc80: c451fcb4 bf001000 c044ff48 c451fec0 f18040c0 00000000 c1b54cc4 00000000
>  fca0: c451fdf0 f1804268 c451fe64 c451fcb8 c0264e88 c0260d48 ffff8000 00007fff
>  fcc0: f18040c0 c025cd00 c451fd14 00000003 0157f008 f1804258 f180425c f1804174
>  fce0: f1804154 f180424c f18041f0 f180414c f1804178 f18041c0 bf0025d4 188a3fa8
>  fd00: 0000009e f1804170 f2b18000 c451ff10 c0d92e40 f180416c c451feec 00000001
>  fd20: 00000000 c451fec8 c451fe20 c451fed0 f18040cc 00000000 f17ea000 c451fdc0
>  fd40: 41b58ab3 c1387729 c0261c28 c047fb5c c451fe2c c451fd60 c0525308 c048033c
>  fd60: 188a3fb4 c3ccb090 c451fe00 c3ccb080 00000000 00000000 00016920 00000000
>  fd80: c02d0388 c047f55c c02d0388 00000000 c451fddc c451fda0 c02d0388 00000000
>  fda0: 41b58ab3 c13a72d0 c0524ff0 c1705f48 c451fdfc c451fdc0 c02d0388 c047f55c
>  fdc0: 00016920 00000000 00000003 c1bb2384 c451fdfc c3ccb080 c1bb2384 00000000
>  fde0: 00000000 00000000 00000000 00000000 c451fe1c c451fe00 c04e9d70 c1705f48
>  fe00: c1b54cc4 c1bbc71c c3ccb080 00000000 c3ccb080 00000000 00000003 c451fec0
>  fe20: c451fe64 c451fe30 c0525918 c0524ffc c451feb0 c1705f48 00000000 c1b54cc4
>  fe40: b78a3fd0 c451ff60 00000000 0157f008 00000003 c451fec0 c451ffa4 c451fe68
>  fe60: c0265480 c0261c34 c451feb0 7fffffff 00000000 00000002 00000000 c4880000
>  fe80: 41b58ab3 c138777b c02652cc c04803ec 000a0000 c451ff00 ffffff9c b6ac9f60
>  fea0: c451fed4 c1705f48 c04a4a90 b78a3fdc f17ea000 ffffff9c b6ac9f60 c0100244
>  fec0: f17ea21a f17ea300 f17ea000 00016920 f1800240 f18000ac f17fb7dc 01316000
>  fee0: 013161b0 00002590 01316250 00000000 00000000 00000000 00002580 00000029
>  ff00: 0000002a 00000013 00000000 0000000c 00000000 00000000 0157f004 c451ffb0
>  ff20: c1719be0 aed6f410 c451ff74 c451ff38 c0c4103c c0c407d0 c451ff84 c451ff48
>  ff40: 00000805 c02c8658 c1604230 c1719c30 00000805 0157f004 00000005 c451ffb0
>  ff60: c1719be0 aed6f410 c451ffac c451ff78 c0122130 c1705f48 c451ffac 0157f008
>  ff80: 00000006 0000005f 0000017b c0100244 c4880000 0000017b 00000000 c451ffa8
>  ffa0: c0100060 c02652d8 0157f008 00000006 00000003 0157f008 00000000 b6ac9f60
>  ffc0: 0157f008 00000006 0000005f 0000017b 00000000 00000000 aed85f74 00000000
>  ffe0: b6ac9cd8 b6ac9cc8 00030200 aecf2d60 a0000010 00000003 00000000 00000000
>  Backtrace:
>  [<c048034c>] (kasan_poison) from [<c048053c>] (kasan_unpoison+0x48/0x5c)
>  [<c04804f4>] (kasan_unpoison) from [<c047f330>] (__asan_register_globals+0x3c/0x64)
>   r5:01312cff r4:f1804030
>  [<c047f2f4>] (__asan_register_globals) from [<f1802098>] (_sub_I_65535_1+0x18/0xf80 [hello])
>   r7:c5be7700 r6:00000001 r5:c1b52ccc r4:f18040c0
>  [<f1802080>] (_sub_I_65535_1 [hello]) from [<c026106c>] (do_init_module+0x330/0x72c)
>  [<c0260d3c>] (do_init_module) from [<c0264e88>] (load_module+0x3260/0x32a8)
>   r10:f1804268 r9:c451fdf0 r8:00000000 r7:c1b54cc4 r6:00000000 r5:f18040c0
>   r4:c451fec0
>  [<c0261c28>] (load_module) from [<c0265480>] (sys_finit_module+0x1b4/0x1e8)
>   r10:c451fec0 r9:00000003 r8:0157f008 r7:00000000 r6:c451ff60 r5:b78a3fd0
>   r4:c1b54cc4
>  [<c02652cc>] (sys_finit_module) from [<c0100060>] (ret_fast_syscall+0x0/0x1c)
>  Exception stack(0xc451ffa8 to 0xc451fff0)
>  ffa0:                   0157f008 00000006 00000003 0157f008 00000000 b6ac9f60
>  ffc0: 0157f008 00000006 0000005f 0000017b 00000000 00000000 aed85f74 00000000
>  ffe0: b6ac9cd8 b6ac9cc8 00030200 aecf2d60
>   r10:0000017b r9:c4880000 r8:c0100244 r7:0000017b r6:0000005f r5:00000006
>   r4:0157f008
>  Code: e92d4100 e1a08001 e1a0e003 e2522040 (a8ac410a)
>  ---[ end trace df6e12843197b6f5 ]---
>
> Cc: <stable@vger.kernel.org> # 5.10+
> Fixes: 421015713b306e47af9 ("ARM: 9017/2: Enable KASan for ARM")
> Signed-off-by: Lecopzer Chen <lecopzer.chen@mediatek.com>
> ---
>  arch/arm/kernel/module.c | 2 +-
>  1 file changed, 1 insertion(+), 1 deletion(-)
>
> diff --git a/arch/arm/kernel/module.c b/arch/arm/kernel/module.c
> index beac45e89ba6..c818aba72f68 100644
> --- a/arch/arm/kernel/module.c
> +++ b/arch/arm/kernel/module.c
> @@ -46,7 +46,7 @@ void *module_alloc(unsigned long size)
>         p = __vmalloc_node_range(size, 1, MODULES_VADDR, MODULES_END,
>                                 gfp_mask, PAGE_KERNEL_EXEC, 0, NUMA_NO_NODE,
>                                 __builtin_return_address(0));
> -       if (!IS_ENABLED(CONFIG_ARM_MODULE_PLTS) || p)
> +       if (!IS_ENABLED(CONFIG_ARM_MODULE_PLTS) || IS_ENABLED(CONFIG_KASAN) || p)


Hello Lecopzer,

This is not the right place to fix this. If module PLTs are
incompatible with KAsan, they should not be selectable in Kconfig at
the same time.

But ideally, we should implement KASAN_VMALLOC for ARM as well - we
also need this for the vmap'ed stacks.


>                 return p;
>         return __vmalloc_node_range(size, 1,  VMALLOC_START, VMALLOC_END,
>                                 GFP_KERNEL, PAGE_KERNEL_EXEC, 0, NUMA_NO_NODE,

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAMj1kXGL%2B%2Bstjcuryn8zVwMgH4F05mONoU3Kca9Ch8N2dW-_bg%40mail.gmail.com.
