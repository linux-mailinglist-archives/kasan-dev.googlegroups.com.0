Return-Path: <kasan-dev+bncBC23VB5X54DBBD45ZKGAMGQEXJKPPQI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13b.google.com (mail-lf1-x13b.google.com [IPv6:2a00:1450:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id E82BF4509E8
	for <lists+kasan-dev@lfdr.de>; Mon, 15 Nov 2021 17:45:03 +0100 (CET)
Received: by mail-lf1-x13b.google.com with SMTP id f15-20020a056512228f00b004037c0ab223sf7006285lfu.16
        for <lists+kasan-dev@lfdr.de>; Mon, 15 Nov 2021 08:45:03 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1636994703; cv=pass;
        d=google.com; s=arc-20160816;
        b=STOedTttbKaDvPJONSlm2lNsodxHjc965I0nZhQ8WyUeDQNd92bgkg7oekt4WshlGL
         2jGhMXQSlc1Gg3zFpNdrVp9ZmqljU3DWb9xUD4uvQhAqSVnViKK6q9KQYXxuGi07dNL0
         EiChNSnpUqPWYkLw4SUo66PRYwRbqdCamL8IodeJmXn8VdudK1dxqm3jDMJrhFcVO4uv
         NhM8jPncvXucfnJeg7pliOIXYhoObKH+W/+hJzU/MiV63X/XouuTQ86e0Qxvcf7WGVNP
         AonE51lo36LEq0I5XmCcadCvrE/vkVOaAUkQLrSwY9zCOW1x/sX8qdkeTS0cTGF6au4I
         LUUg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=qg/u9kCv53QUdlRPvuV0oWmUxwOq9C1DYcYT/RZnpHA=;
        b=JN098CYCWGfFJQ6pDkcT6uMEORsZ8C7Ut/I0G/QysuOQLkcssM8PDYcdKIlXXrusKH
         LpTrYB5ZCMAW16lWhJCqUgtCKLrMoRRkL0p8tZFz1q8Nnfr2J2TwERPCiFnmIj19DPFz
         t6jmVpL8I2dkrPyGVIXCx388B7CKz+ZrSEf+cwFZ19WnHBaazLSHB+DD3F+6Zdgt5L8X
         g9vOyIknKOW8fPWk1AVbvCw8zmWmVYHJch+nJk8B+sq7+lqPru6IvibHlUbbPuxgVJSA
         T76VzfVBzunOtEc/OGny+uwuENb+1fTwnc2OFfoYwPvNbYRk5aWkUMARaXP5Pp5WSrkr
         Q+3Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmx.net header.s=badeba3b8450 header.b="ZNp1vsR/";
       spf=pass (google.com: domain of deller@gmx.de designates 212.227.17.21 as permitted sender) smtp.mailfrom=deller@gmx.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=gmx.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:message-id:date:mime-version:user-agent:subject
         :content-language:to:cc:references:from:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=qg/u9kCv53QUdlRPvuV0oWmUxwOq9C1DYcYT/RZnpHA=;
        b=RFCBselbfm+uek2mvjAELr9Vts7TODD03qp6LNl40UvStjmeFTmPDZDYTKv/tg7Tnp
         qtmbc+xIQ47gG9e25qQS1uJ7LcFTTeJMqkKfhqTHm7pVhjSsyhKYZ/NzYX8XM4WK1yMZ
         Zaewj8qP1pqu0VWVHQoTtHJ/m4u+f8S3JCaDX1u0LRiG3vxdk9AL6b/kQ9eK5CVvTA4m
         N/cxZ2zhhFQdV3x1lxITNkLbDWh0gdZiCUJGVO5isFu69fIVXEx2JcXv7Xjsnf9q+HcT
         J0jrZL6NmpJuP+/vtNNFHLWjF2uMP1uQGjzsKvwTVoVCo5I6r5br0IlxLoAvD0rtjHvV
         evQQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:message-id:date:mime-version:user-agent
         :subject:content-language:to:cc:references:from:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=qg/u9kCv53QUdlRPvuV0oWmUxwOq9C1DYcYT/RZnpHA=;
        b=LfQCzOS6wg5Mt+CAFYRXDqHw7v60gEeY3YdoThzyxhOu1UTqM0jULlIXPIeQaYzbYM
         abyWQpGjJBGWkke3sLwTxsP7pYX9NPT9C88kxMVvzNC7SUq5OsG/5PzdbDL3Vn2MbdRs
         lpHKen2gQHsnQgRqRek9vMQKb/NEYbJn9I8Sd5ZcUczb87b7mN/tjcKxzIs7wjjWJVIZ
         nsB0tOSvsgLhuljXYxbRkOg6qcycCWXiggTKPkRsWS4HgpjQwlRFDqiZ758HckJ/Qoin
         ACldBzx/p0+D3TrWoiYMX3QxjtYKtS57U7ufASLXyTS1Ynel4fcZp+rVf26T4O5O/guy
         5rBA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533E6x6TATKeYTkI+FT5KAMJAXitVmk4FTYBrbU2EF1sxrAVbIiR
	2azPEAZEixj57aLFySY1p5U=
X-Google-Smtp-Source: ABdhPJyjbHFf7BooMNmGc5pQuJqVxKEnblIx4aNybQRPV5QiZxo/jL+jD7SaP6vjpRSU7djWcT7VcQ==
X-Received: by 2002:a05:651c:323:: with SMTP id b3mr39877536ljp.316.1636994703406;
        Mon, 15 Nov 2021 08:45:03 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3e10:: with SMTP id i16ls196201lfv.3.gmail; Mon, 15
 Nov 2021 08:45:02 -0800 (PST)
X-Received: by 2002:a19:6b08:: with SMTP id d8mr25810lfa.39.1636994702444;
        Mon, 15 Nov 2021 08:45:02 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1636994702; cv=none;
        d=google.com; s=arc-20160816;
        b=VtXE/mJTiiLznyKidnVh+RrcSpm+JHpF1lMKCe1slubsTbEWMO2IW1TVqJ1w+ztkOB
         3ZIsAYMHjOoSDNqSLFdGEtmM8WmoGpzFfkJGv9pJmpe3EzVBBQEd8LzUwVynDzRAXFE2
         dkuLtFCEUKk/7jaHUexGIMWgfSfxKlvbFU79EzQ6cr22JdSPwkvCwWh3bsXoCx5obsUZ
         83a/XUsA2bfgiCpdMyW7QVPCFvuKNrki7OW+7zg5nVgCjNqC+nYAOyTqyAJKIVkJUZWv
         ed8xvhPQvocDVX6VZ9q0sKp0747JIfASCT4/cJivLHi+tR91JlItZUEmRPvKLq3Dw190
         IKFA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=Qj/acku42wukI1znMH8FRDwAdiCeiQKumHbNzKc8OmY=;
        b=sFbWpgYMCjCC/F+5hAvB1F0JQxt5NXN7ylVqD08z5lkMe5hDnXXdaHJ7a7XZIvFzlK
         ArHcKO16H+FQSakHQEx+RSpdLZCAAmDOAKbMFLoY9HfhUOdBy8w2yGztTyTUUJhwdbGM
         T2u/UtOO2DWPc5/8kPRlwjZ9oz3cVMGsi75Ah0mkBeqooEtn8oQFZkLErzJgf/Wd0tOf
         p+c2zunJx6IktkJCDz/Vpw9CScvWYRmi8HjriHMwJ2f/6NEeoAUmRMoa6dSpAnZVc2ds
         kTLj3zEcsHbVv/FYApSVPWlKdAENQsu2rOuMYMOf1UOfmsMHLOfWSa/tHLc8r/v0s+5Y
         Cfqw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmx.net header.s=badeba3b8450 header.b="ZNp1vsR/";
       spf=pass (google.com: domain of deller@gmx.de designates 212.227.17.21 as permitted sender) smtp.mailfrom=deller@gmx.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=gmx.de
Received: from mout.gmx.net (mout.gmx.net. [212.227.17.21])
        by gmr-mx.google.com with ESMTPS id x65si786100lff.10.2021.11.15.08.45.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 15 Nov 2021 08:45:02 -0800 (PST)
Received-SPF: pass (google.com: domain of deller@gmx.de designates 212.227.17.21 as permitted sender) client-ip=212.227.17.21;
X-UI-Sender-Class: 01bb95c1-4bf8-414a-932a-4f6e2808ef9c
Received: from [192.168.20.60] ([92.116.172.2]) by mail.gmx.net (mrgmx105
 [212.227.17.168]) with ESMTPSA (Nemesis) id 1MulmF-1mUiZj3MMl-00rlU4; Mon, 15
 Nov 2021 17:44:52 +0100
Message-ID: <fcdead1c-2e26-b8ca-9914-4b3718d8f6d4@gmx.de>
Date: Mon, 15 Nov 2021 17:44:46 +0100
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101
 Thunderbird/91.2.0
Subject: Re: Build regressions/improvements in v5.16-rc1
Content-Language: en-US
To: Geert Uytterhoeven <geert@linux-m68k.org>,
 Linux Kernel Mailing List <linux-kernel@vger.kernel.org>
Cc: Nick Terrell <terrelln@fb.com>, Rob Clark <robdclark@gmail.com>,
 "James E.J. Bottomley" <James.Bottomley@hansenpartnership.com>,
 Anton Altaparmakov <anton@tuxera.com>,
 Thomas Bogendoerfer <tsbogend@alpha.franken.de>,
 Sergio Paracuellos <sergio.paracuellos@gmail.com>,
 Herbert Xu <herbert@gondor.apana.org.au>, Joey Gouly <joey.gouly@arm.com>,
 Stan Skowronek <stan@corellium.com>, Hector Martin <marcan@marcan.st>,
 Andrey Ryabinin <ryabinin.a.a@gmail.com>,
 =?UTF-8?Q?Andr=c3=a9_Almeida?= <andrealmeid@collabora.com>,
 Peter Zijlstra <peterz@infradead.org>,
 Linux ARM <linux-arm-kernel@lists.infradead.org>,
 "open list:GPIO SUBSYSTEM" <linux-gpio@vger.kernel.org>,
 Parisc List <linux-parisc@vger.kernel.org>,
 linux-arm-msm <linux-arm-msm@vger.kernel.org>,
 DRI Development <dri-devel@lists.freedesktop.org>,
 linux-ntfs-dev@lists.sourceforge.net,
 linuxppc-dev <linuxppc-dev@lists.ozlabs.org>,
 "open list:BROADCOM NVRAM DRIVER" <linux-mips@vger.kernel.org>,
 linux-pci <linux-pci@vger.kernel.org>,
 Linux Crypto Mailing List <linux-crypto@vger.kernel.org>,
 kasan-dev <kasan-dev@googlegroups.com>
References: <20211115155105.3797527-1-geert@linux-m68k.org>
 <CAMuHMdUCsyUxaEf1Lz7+jMnur4ECwK+JoXQqmOCkRKqXdb1hTQ@mail.gmail.com>
From: Helge Deller <deller@gmx.de>
In-Reply-To: <CAMuHMdUCsyUxaEf1Lz7+jMnur4ECwK+JoXQqmOCkRKqXdb1hTQ@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Provags-ID: V03:K1:5BKtXEDuts0Z1GbTQQwbacSZ6Qy1U07fZEMQSQLpuPBBQDGFGvS
 jgmRgNw/0/YxGtzSDq/AyZLFtskYKCywXQ3lO2wtd3EGePe4Ixvqqh7DUZZeoRxCsQMl6GA
 by16J3GCpzXn/Msq8wegCjeZkFLZeq3tCjI3WXTxmaGR5bFXZPJKjDTbupJilCqt5Bs35DE
 Rw+BaHR8OgV3ewoQytQig==
X-Spam-Flag: NO
X-UI-Out-Filterresults: notjunk:1;V03:K0:b77E2Nv2HWU=:1iEuQwORGxqm+Wxgophchs
 kJUQQ6hBkiYPbKA0OD9YByp1bHssWrVkeWRGKN5pykYEH3l7dN0ijgUMSWJcN0GfQUbeMrT1b
 YaGdtm1k4/pCbjVfG0S149Z9y49SItZL4ZWtdlVE+CRAqawiC7KOmFHtqeN0Y3JmBhRIOjqfA
 uwpF6echOB0lej0vS99fwoOz3DbzQCS0D+iIZnjK/55BLHi1EdS59b+xe3FYn1MbOzW1sOTXh
 U2NPD4g+VaVZuUlI+pmHPQ4wNk3aQQ/0v2vADxHoqHF8G6ISUZLs6qLqK4AmJFA1E1A4aLtz/
 7huNRwSazAtuaLdZpRe6Qeys5FuaWNHQLsONPwXczWfhlS5ZxxU4znt96t19rKNnOB44icruu
 FpfCnxAIbKLuFgiiE4TBO4D3tcK6iDuh4gsXT/0L9E/QB26kjEtSHA3QP7ACtzqYu1Bdzxu0+
 neK0u+MJdKV7sSNcTbjG+E0D8+rAJZz5NjcCzEg57aRJ+O5YgbDkAoaLXcR3+ihlZml9NHl8I
 nyqs3iFoo+U5FZS6xEAjtRTd3kjOJpcutf95kWK5s5mTRo34ItK4k/Ad0JVdO0Qk94Gly7dd3
 EPRvkD3IvjVdIAoJ1rGqrCJLxNWP9OskTwtxtnvl4HqpjswTECMXMjjUHePuirpU/wbanGDjZ
 gLkqWwbit6L+/MF8j/WgH0uEf54Q4Ym1PEHqdoCmTAevhGPZZD49/diYSKX8c4baXWRjKyRYu
 jCjMhrQJFRiCXP70cHBPZPB5ov1LUhDv5uzdeyGBDdFbsha0M6M8zmtIj9jngXvAp7jjclHY2
 Q4keWlRsrozLDEB86NArf/fA+BNKh5UekNeLQ1k9csmoAntQei+GfSJl/SL76lPfgp0jAHfUg
 TvygG2oE3WZk43TGud0mvrvuC5RIjSTvIVbkSX5eI/GUxeqOuV5DaO80y8DDA1+oswXNTMVJ9
 VPSs3miXxGYDwZ+8z0E8DZ8Q1eG6CZDbs4b5ClRtuiPMJX76ARaXEeTlPpAffiH/ptsUKt03s
 zF15t5hKeMRpsZJ9fldqE2/ud15ANfqT6CXGMZfxXhHhIa0Hc9jQPkvTp1cVZRTJtChK318IW
 JWFtnZlRQXGilk=
X-Original-Sender: deller@gmx.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmx.net header.s=badeba3b8450 header.b="ZNp1vsR/";       spf=pass
 (google.com: domain of deller@gmx.de designates 212.227.17.21 as permitted
 sender) smtp.mailfrom=deller@gmx.de;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=gmx.de
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

On 11/15/21 17:12, Geert Uytterhoeven wrote:
> On Mon, Nov 15, 2021 at 4:54 PM Geert Uytterhoeven <geert@linux-m68k.org> wrote:
>> Below is the list of build error/warning regressions/improvements in
>> v5.16-rc1[1] compared to v5.15[2].
>>
>> Summarized:
>>   - build errors: +20/-13
>>   - build warnings: +3/-28
>>
>> Happy fixing! ;-)
>>
>> Thanks to the linux-next team for providing the build service.
>>
>> [1] http://kisskb.ellerman.id.au/kisskb/branch/linus/head/fa55b7dcdc43c1aa1ba12bca9d2dd4318c2a0dbf/ (all 90 configs)
>> [2] http://kisskb.ellerman.id.au/kisskb/branch/linus/head/8bb7eca972ad531c9b149c0a51ab43a417385813/ (all 90 configs)
>>
>>
>> *** ERRORS ***
>>
>> 20 error regressions:
>>   + /kisskb/src/arch/parisc/include/asm/jump_label.h: error: expected ':' before '__stringify':  => 33:4, 18:4
>>   + /kisskb/src/arch/parisc/include/asm/jump_label.h: error: label 'l_yes' defined but not used [-Werror=unused-label]:  => 38:1, 23:1
>
>     due to static_branch_likely() in crypto/api.c
>
> parisc-allmodconfig

fixed now in the parisc for-next git tree.


>>   + /kisskb/src/drivers/gpu/drm/msm/msm_drv.h: error: "COND" redefined [-Werror]:  => 531
>>   + /kisskb/src/lib/zstd/compress/zstd_double_fast.c: error: the frame size of 3252 bytes is larger than 1536 bytes [-Werror=frame-larger-than=]:  => 47:1
>>   + /kisskb/src/lib/zstd/compress/zstd_double_fast.c: error: the frame size of 3360 bytes is larger than 1536 bytes [-Werror=frame-larger-than=]:  => 499:1
>>   + /kisskb/src/lib/zstd/compress/zstd_double_fast.c: error: the frame size of 5344 bytes is larger than 1536 bytes [-Werror=frame-larger-than=]:  => 334:1
>>   + /kisskb/src/lib/zstd/compress/zstd_double_fast.c: error: the frame size of 5380 bytes is larger than 1536 bytes [-Werror=frame-larger-than=]:  => 354:1
>>   + /kisskb/src/lib/zstd/compress/zstd_fast.c: error: the frame size of 1824 bytes is larger than 1536 bytes [-Werror=frame-larger-than=]:  => 372:1
>>   + /kisskb/src/lib/zstd/compress/zstd_fast.c: error: the frame size of 2224 bytes is larger than 1536 bytes [-Werror=frame-larger-than=]:  => 204:1
>>   + /kisskb/src/lib/zstd/compress/zstd_fast.c: error: the frame size of 3800 bytes is larger than 1536 bytes [-Werror=frame-larger-than=]:  => 476:1
>
> parisc-allmodconfig

parisc needs much bigger frame sizes, so I'm not astonished here.
During the v5.15 cycl I increased it to 1536 (from 1280), so I'm simply tempted to
increase it this time to 4096, unless someone has a better idea....

>>   + /kisskb/src/fs/ntfs/aops.c: error: the frame size of 2240 bytes is larger than 2048 bytes [-Werror=frame-larger-than=]:  => 1311:1
>>   + /kisskb/src/fs/ntfs/aops.c: error: the frame size of 2304 bytes is larger than 2048 bytes [-Werror=frame-larger-than=]:  => 1311:1
>>   + /kisskb/src/fs/ntfs/aops.c: error: the frame size of 2320 bytes is larger than 2048 bytes [-Werror=frame-larger-than=]:  => 1311:1
>
> powerpc-allmodconfig
>
>>   + /kisskb/src/include/linux/compiler_types.h: error: call to '__compiletime_assert_366' declared with attribute error: FIELD_PREP: value too large for the field:  => 335:38
>
>     in drivers/pinctrl/pinctrl-apple-gpio.c
>
> arm64-allmodconfig (gcc8)
>
>>   + /kisskb/src/include/linux/fortify-string.h: error: call to '__read_overflow' declared with attribute error: detected read beyond size of object (1st parameter):  => 263:25, 277:17
>
>     in lib/test_kasan.c
>
> s390-all{mod,yes}config
> arm64-allmodconfig (gcc11)
>
>>   + error: modpost: "mips_cm_is64" [drivers/pci/controller/pcie-mt7621.ko] undefined!:  => N/A
>>   + error: modpost: "mips_cm_lock_other" [drivers/pci/controller/pcie-mt7621.ko] undefined!:  => N/A
>>   + error: modpost: "mips_cm_unlock_other" [drivers/pci/controller/pcie-mt7621.ko] undefined!:  => N/A
>>   + error: modpost: "mips_cpc_base" [drivers/pci/controller/pcie-mt7621.ko] undefined!:  => N/A
>>   + error: modpost: "mips_gcr_base" [drivers/pci/controller/pcie-mt7621.ko] undefined!:  => N/A
>
> mips-allmodconfig
>
>> 3 warning regressions:
>>   + <stdin>: warning: #warning syscall futex_waitv not implemented [-Wcpp]:  => 1559:2
>
> powerpc, m68k, mips, s390, parisc (and probably more)

Will someone update all of them at once?




Helge


>>   + arch/m68k/configs/multi_defconfig: warning: symbol value 'm' invalid for MCTP:  => 322
>>   + arch/m68k/configs/sun3_defconfig: warning: symbol value 'm' invalid for MCTP:  => 295
>
> Yeah, that happens when symbols are changed from tristate to bool...
> Will be fixed in 5.17-rc1, with the next defconfig refresh.
>
> Gr{oetje,eeting}s,
>
>                         Geert
>
> --
> Geert Uytterhoeven -- There's lots of Linux beyond ia32 -- geert@linux-m68k.org
>
> In personal conversations with technical people, I call myself a hacker. But
> when I'm talking to journalists I just say "programmer" or something like that.
>                                 -- Linus Torvalds
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/fcdead1c-2e26-b8ca-9914-4b3718d8f6d4%40gmx.de.
