Return-Path: <kasan-dev+bncBC23VB5X54DBBG6M2OGAMGQET3J4CPA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13d.google.com (mail-lf1-x13d.google.com [IPv6:2a00:1450:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id E809A45458A
	for <lists+kasan-dev@lfdr.de>; Wed, 17 Nov 2021 12:23:07 +0100 (CET)
Received: by mail-lf1-x13d.google.com with SMTP id b23-20020a0565120b9700b00403a044bfcdsf1221976lfv.13
        for <lists+kasan-dev@lfdr.de>; Wed, 17 Nov 2021 03:23:07 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1637148187; cv=pass;
        d=google.com; s=arc-20160816;
        b=XrZsq7tOsbdch6Ck+NTZiOMJhfI1D0h7HWcbj3mbTEboP95nuQgZO9Odoa7JvUnQbB
         wuwyCHwCr+DRVpRKQhmoMxrglIOkG/STLX4Fkgpti81DH9EsOwaUuQcnQQiubMXbG2iB
         7HSyez/bYt4II+RoqjWmh7lfVSIM9rfeGwBHfr6lhMLh5t5pSNAlvpRouLWNSZqMva6v
         tb6NOnjdtFCYyn350WP/I1h5wCzQikd/ekfEXzc2YaWJ3Arrw+F7EeW7tKXKxa+prCo+
         sq/YWP0zvd1M4f3ILbqIyY8ErI9yY0OWXGx7cMBMVB4uT1obvtOpPA3FJOsEAiL7FHp5
         UZPw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :in-reply-to:from:references:cc:to:content-language:subject
         :user-agent:mime-version:date:message-id:sender:dkim-signature;
        bh=+zSdqdtQFQqj9gBmUi3MRKpWva0BXV0CQIzZTw+GB0Q=;
        b=iF9rU9OYi83zRF3PfWSVIoPkhO5dNXGDojAMxP/4hahoCqj60keqUcfa87GbcuqrQk
         P2E6TVjkLAn7mHKDFHkF6bGaapwD6V+FoQBxaxnIYKR5wBkHkCSQnZ1cHAw0LjRqX5iH
         71HRrqWwo+AHdQfpK9HRUUSJpb7N17EBoUR2n3DNw70nTjhyHL8kpoG8P38gOjsvogeg
         3moGBinmd9uaWbd5j50m9nEFmqnFr24iFP6nKG58a85cqZr+NcLD/+6PL3V7uhCympJl
         70z2fLROQKut4IO2OqQyOwDsqkuRWBNL26boQHpIRFnBAatb269WuVi1Xbjl1c28HjjH
         BrRQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmx.net header.s=badeba3b8450 header.b="BrRmlP/G";
       spf=pass (google.com: domain of deller@gmx.de designates 212.227.15.18 as permitted sender) smtp.mailfrom=deller@gmx.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=gmx.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:message-id:date:mime-version:user-agent:subject
         :content-language:to:cc:references:from:in-reply-to
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=+zSdqdtQFQqj9gBmUi3MRKpWva0BXV0CQIzZTw+GB0Q=;
        b=Rc/8eak25i1h9/gVXN7ubtb4COcKNMPd5tM056o4JSFewhl8zceVw+lXGqtMlTVjgc
         P28/kfVeSr6AQgyIEEMH9vpELlCLm/A8bzA3qZGyM4d9cP/eWO3MXlVLneo4oU3mfc/B
         19/lMKUlIF/pYdTPe/sYL865PzfcVo/rP7Rj+zXpAzhiyfyojmkAgQXQtA/bUrXAmsTL
         eOABpyo8SaDnYnE9Pt2cGDsn9+e+kVkgQuzPvUKrDEV6SQDpByFqXNIq4/ePDRm87xJB
         DXOS056oWC225C9MlAZQCpf5o6SqXXc8CoNy6KAt1pe7LW614f/etiOkR3ZRk6L+otkh
         bQ/g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:message-id:date:mime-version:user-agent
         :subject:content-language:to:cc:references:from:in-reply-to
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=+zSdqdtQFQqj9gBmUi3MRKpWva0BXV0CQIzZTw+GB0Q=;
        b=odtdTds3VH9zzdmx48NR/iLbdzHU2MAA0vCmOB9v6M6h+hZFtXcwKKOtXESg5F9lYP
         WaGvdXbjSROe3VH2YTeUVE6kna/sqngnbrC7kpLyJhIumy41vKwsj2SlpdQN+uJANmRS
         qT8D5gJFT/duhtHmAlWyCGjoUQ52BJ8ydVGX4+Pmh9Q6p3Ia4GcCLRHjUbvDMpldjZnw
         HLJb/zLPzSyIrkZCke+f7ovSYsO60NH5GIsQ1Iyc9wKI3Y9j4MzpdEnTzBJDzx4NhxIm
         ugpc2c8DIXP6Jfiuqp69+n+BwUEgSbdZnoVy7IZUhXPCGGD5mqDk9b7EHStBGciAq5BS
         +51A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530FsziEjz2gZX5ZiS7WFRzMSGAb1Ih8zN6xaxnTOcSUzrSJWnTs
	HXQWuuOHVa47bmd0JeAmXrs=
X-Google-Smtp-Source: ABdhPJyzMWcdAM8Xyqh1Lkrfgb3+/8vy+SP/1WLxqu4gXHbuIyIGzD9tVq2OOxGUnB7Mp1QOOR6hTQ==
X-Received: by 2002:a2e:b0e1:: with SMTP id h1mr7125414ljl.343.1637148187480;
        Wed, 17 Nov 2021 03:23:07 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:8611:: with SMTP id a17ls794329lji.1.gmail; Wed, 17 Nov
 2021 03:23:06 -0800 (PST)
X-Received: by 2002:a05:651c:1787:: with SMTP id bn7mr4637638ljb.22.1637148186322;
        Wed, 17 Nov 2021 03:23:06 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1637148186; cv=none;
        d=google.com; s=arc-20160816;
        b=JK5rlsGL7EBCDJh2sToCh7ijOVL+IRkqwuszwp9xJrqPwFLJerCUquGw+AErI0pVCe
         10L3g2cbnMhepJmGg2P0Q36TrfQ2roH36JFYA+ykv2smNj7if5QCAbbn2154ciqfrc35
         edjKoI/b540A1bl6B4b1Mv1m67xB4gthnuj9cDOAbINkZiPQzRMS/Y80zLNJRl6akdmu
         ANxFttlkZ+zuhmS+DpKJiUTRkaBHXd3PbLu+JF/GK2Mnco5vWucgncL0vopKSiuVyyUl
         JluGiMBh7UcKaEBXLFwKD4lTicSGFrKPGmCCbVxwBaeK/tIV7yLyEBUAuWQN8crLpo/3
         BmOQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=DvHLkKVB9o3bd+oGlvVzLpP9LIFOhtsbe6EohRQ3A38=;
        b=bZFVpr40LmBvEaHOmG4szJyzHu4kDUo1pSPcLCom+KKXvLWWgJktRsR0JdOnoCh1iD
         2Velje4NxkwagmLDeYG1cJlLhQT+tyW20G/zrc+Xm66trnl5KWA6geZiBgcGf+J5UoKS
         ZB/DZPlguAogpPW82NYN1EXLWARDyzR6qjgxF4LKveN9sJEq1nFWP8pKDBX5hioH/uOW
         ydHiHmxG/WZQh0EahgHfQwD0dBf7DfMY5H+PzZJe7WbO8zGnwlfuwNabGXixLsb+Qo2V
         RgF+sNyKe8hDr6YmipsBJYIZs8g/Ax0kf2UhG3GcrZDSPpO/NgayfG/9nmyFH5HoTUW5
         Tg3w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmx.net header.s=badeba3b8450 header.b="BrRmlP/G";
       spf=pass (google.com: domain of deller@gmx.de designates 212.227.15.18 as permitted sender) smtp.mailfrom=deller@gmx.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=gmx.de
Received: from mout.gmx.net (mout.gmx.net. [212.227.15.18])
        by gmr-mx.google.com with ESMTPS id v25si1401459lfr.1.2021.11.17.03.23.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 17 Nov 2021 03:23:06 -0800 (PST)
Received-SPF: pass (google.com: domain of deller@gmx.de designates 212.227.15.18 as permitted sender) client-ip=212.227.15.18;
X-UI-Sender-Class: 01bb95c1-4bf8-414a-932a-4f6e2808ef9c
Received: from [192.168.20.60] ([92.116.186.76]) by mail.gmx.net (mrgmx005
 [212.227.17.190]) with ESMTPSA (Nemesis) id 1Mdeb5-1mEFOM2tNZ-00ZhYR; Wed, 17
 Nov 2021 12:22:59 +0100
Message-ID: <525f9914-04bd-2d8a-0bbf-daf2d0d2053d@gmx.de>
Date: Wed, 17 Nov 2021 12:22:21 +0100
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101
 Thunderbird/91.2.0
Subject: Re: Build regressions/improvements in v5.16-rc1
Content-Language: en-US
To: Nick Terrell <terrelln@fb.com>, Randy Dunlap <rdunlap@infradead.org>
Cc: Geert Uytterhoeven <geert@linux-m68k.org>,
 Linux Kernel Mailing List <linux-kernel@vger.kernel.org>,
 Rob Clark <robdclark@gmail.com>,
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
 "linux-ntfs-dev@lists.sourceforge.net"
 <linux-ntfs-dev@lists.sourceforge.net>,
 linuxppc-dev <linuxppc-dev@lists.ozlabs.org>,
 "open list:BROADCOM NVRAM DRIVER" <linux-mips@vger.kernel.org>,
 linux-pci <linux-pci@vger.kernel.org>,
 Linux Crypto Mailing List <linux-crypto@vger.kernel.org>,
 kasan-dev <kasan-dev@googlegroups.com>
References: <20211115155105.3797527-1-geert@linux-m68k.org>
 <CAMuHMdUCsyUxaEf1Lz7+jMnur4ECwK+JoXQqmOCkRKqXdb1hTQ@mail.gmail.com>
 <fcdead1c-2e26-b8ca-9914-4b3718d8f6d4@gmx.de>
 <480CE37B-FE60-44EE-B9D2-59A88FDFE809@fb.com>
 <78b2d093-e06c-ba04-9890-69f948bfb937@infradead.org>
 <B57193D6-1FD4-45D3-8045-8D2DE691E24E@fb.com>
From: Helge Deller <deller@gmx.de>
In-Reply-To: <B57193D6-1FD4-45D3-8045-8D2DE691E24E@fb.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Provags-ID: V03:K1:ecyVoIRPJxDu1rgYw3do9p97wWm9wU+AYBS1tvVaJ0qieCw2VM+
 F4AcfYMJ6m/o5RfywfI4addVn5UKeIySukwDZx6nGaNJwYzhtTxzP+5Y9QaJhX+4OlwpAV1
 nMwCfILf2+U0diPU2I9nlEi9f/czGOv/sIbvk3rRkJXeX3DOr1WSt6X93xYlDMTGlwHCyLR
 l+dXL+dPRpL0TjoJpT37A==
X-Spam-Flag: NO
X-UI-Out-Filterresults: notjunk:1;V03:K0:G/MV6HsODHM=:GxGTU642o4q5r5Bwlk703U
 vxYQ3KuDo6YpbOEcuglfWGzzkjMlrIx0ZlWv4JsMVqaIrnJ1r7AEdn0mG05l77wBkj9tPDp2p
 cxqkTdS0Rn8a3/aO+1h66Qc6kxo7zYE5k8wzhKYhg57qAdkipTcoDbYTRbCnwgd66capkEccM
 ninD/hUvLoeWSvRDoqj7mDSeesjpteCG2ikmPDhTRIHWTyXcduB6vwRQJADGEDklW8y85wAX2
 8V74xNrEaQisjP8JC8Mjxt9pQ89HFPW5iIeFMhqGBusMX2Qc1A/dgqLsCecHDNVdOsLIZiVmd
 ZaVJy8Y4j1gCmWXjdIK4tPA2f2F7zz0I3Vr1J6DABpXhDXWjOi2t8Vc8FVWAkhlq0GDbOEa22
 LvVPGyYOXK+zVo3NTpR2SRDD5inFdZofQgk3STxUADjWe0pADXhySizKoqI3hOiS+RCzugymz
 P013TEBW0pCuBuvtAqKPpPOVumpI1YuDb+ncGhnSEeZguPYfyEJiUT3LqBFxh2V2X/9WDi1OL
 qNNEwvJJpR2wgmPCQ/kQ3qSQwou+kAe5ZuGqjdVpjbC2+1SPL7YspRkKKCFCjlGLvlpcujvTj
 zxtITxo9yGX25rS+k4QKT7FDY+rDz9LFNYsvT3HSCPcBFodYcELgos1uLT9n1PzJIIFglJTNy
 cpq+8ki7uxvrFMqw7bsyXNJxR68GWOY013x2dDtJgKhUdBk4WQNZ/Me0K/gC1a3qgmWbxZVEH
 GtYiU9JkuGLmQpINKuY0akrnFChvA784RgR2Y+oWWX7bHsqEa0qmvePFVafGjVha3pfS3jDwL
 y23unIOpTU0uAViTehWJfapqMdY3tpQoYWYdv/SmH5afY7QhFeTXGQ8FRB1s2XKDJLBt9n3lx
 IDTZVBbDmPftiGHN4qbiC+2vCAg+1tRLbsC5sRU19gzI7dfG8Prt3dDPwiqfcixG4zTa7VAhA
 H7orwyCYt9MsOsiUyOjbPeaXA1amq+2kIKl82/FS6TVco9YcnlGYmRMIv09URP4HnnwNXA5hj
 sTan1CyZPpbhoC1X7yQVhT2hokL8Bo8TnOGfc+9A/n3r6zaF4fFADZRSvl/CYXmsCxwIXL3cV
 VuJSqXhAe0zLjg=
X-Original-Sender: deller@gmx.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmx.net header.s=badeba3b8450 header.b="BrRmlP/G";       spf=pass
 (google.com: domain of deller@gmx.de designates 212.227.15.18 as permitted
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

On 11/17/21 03:19, Nick Terrell wrote:
>
>
>> On Nov 16, 2021, at 6:05 PM, Randy Dunlap <rdunlap@infradead.org> wrote:
>>
>> On 11/16/21 5:59 PM, Nick Terrell wrote:
>>>> On Nov 15, 2021, at 8:44 AM, Helge Deller <deller@gmx.de> wrote:
>>>>
>>>> On 11/15/21 17:12, Geert Uytterhoeven wrote:
>>>>> On Mon, Nov 15, 2021 at 4:54 PM Geert Uytterhoeven <geert@linux-m68k.=
org> wrote:
>>>>>> Below is the list of build error/warning regressions/improvements in
>>>>>> v5.16-rc1[1] compared to v5.15[2].
>>>>>>
>>>>>> Summarized:
>>>>>>  - build errors: +20/-13
>>>>>>  - build warnings: +3/-28
>>>>>>
>>>>>> Happy fixing! ;-)
>>>>>>
>>>>>> Thanks to the linux-next team for providing the build service.
>>>>>>
>>>>>> [1] http://kisskb.ellerman.id.au/kisskb/branch/linus/head/fa55b7dcdc=
43c1aa1ba12bca9d2dd4318c2a0dbf/   (all 90 configs)
>>>>>> [2] http://kisskb.ellerman.id.au/kisskb/branch/linus/head/8bb7eca972=
ad531c9b149c0a51ab43a417385813/   (all 90 configs)
>>>>>>
>>>>>>
>>>>>> *** ERRORS ***
>>>>>>
>>>>>> 20 error regressions:
>>>>>>  + /kisskb/src/arch/parisc/include/asm/jump_label.h: error: expected=
 ':' before '__stringify':  =3D> 33:4, 18:4
>>>>>>  + /kisskb/src/arch/parisc/include/asm/jump_label.h: error: label 'l=
_yes' defined but not used [-Werror=3Dunused-label]:  =3D> 38:1, 23:1
>>>>>
>>>>>    due to static_branch_likely() in crypto/api.c
>>>>>
>>>>> parisc-allmodconfig
>>>>
>>>> fixed now in the parisc for-next git tree.
>>>>
>>>>
>>>>>>  + /kisskb/src/drivers/gpu/drm/msm/msm_drv.h: error: "COND" redefine=
d [-Werror]:  =3D> 531
>>>>>>  + /kisskb/src/lib/zstd/compress/zstd_double_fast.c: error: the fram=
e size of 3252 bytes is larger than 1536 bytes [-Werror=3Dframe-larger-than=
=3D]:  =3D> 47:1
>>>>>>  + /kisskb/src/lib/zstd/compress/zstd_double_fast.c: error: the fram=
e size of 3360 bytes is larger than 1536 bytes [-Werror=3Dframe-larger-than=
=3D]:  =3D> 499:1
>>>>>>  + /kisskb/src/lib/zstd/compress/zstd_double_fast.c: error: the fram=
e size of 5344 bytes is larger than 1536 bytes [-Werror=3Dframe-larger-than=
=3D]:  =3D> 334:1
>>>>>>  + /kisskb/src/lib/zstd/compress/zstd_double_fast.c: error: the fram=
e size of 5380 bytes is larger than 1536 bytes [-Werror=3Dframe-larger-than=
=3D]:  =3D> 354:1
>>>>>>  + /kisskb/src/lib/zstd/compress/zstd_fast.c: error: the frame size =
of 1824 bytes is larger than 1536 bytes [-Werror=3Dframe-larger-than=3D]:  =
=3D> 372:1
>>>>>>  + /kisskb/src/lib/zstd/compress/zstd_fast.c: error: the frame size =
of 2224 bytes is larger than 1536 bytes [-Werror=3Dframe-larger-than=3D]:  =
=3D> 204:1
>>>>>>  + /kisskb/src/lib/zstd/compress/zstd_fast.c: error: the frame size =
of 3800 bytes is larger than 1536 bytes [-Werror=3Dframe-larger-than=3D]:  =
=3D> 476:1
>>>>>
>>>>> parisc-allmodconfig
>>>>
>>>> parisc needs much bigger frame sizes, so I'm not astonished here.
>>>> During the v5.15 cycl I increased it to 1536 (from 1280), so I'm simpl=
y tempted to
>>>> increase it this time to 4096, unless someone has a better idea....
>>> This patch set should fix the zstd stack size warnings [0]. I=E2=80=99v=
e
>>> verified the fix using the same tooling: gcc-8-hppa-linux-gnu.
>>> I=E2=80=99ll send the PR to Linus tomorrow. I=E2=80=99ve been informed =
that it
>>> isn't strictly necessary to send the patches to the mailing list
>>> for bug fixes, but its already done, so I=E2=80=99ll wait and see if th=
ere
>>> is any feedback.
>>
>> IMO several (or many more) people would disagree with that.
>>
>> "strictly?"  OK, it's probably possible that almost any patch
>> could be merged without being on a mailing list, but it's not
>> desirable (except in the case of "security" patches).
>
> Good to know! Thanks for the advice, I wasn=E2=80=99t really sure what
> the best practice is for sending patches to your own tree, as I
> didn't see anything about it in the maintainer guide.

Nick, thanks a lot for your efforts to get the frame size usage down!

I've applied your patch series to the parisc for-next tree [1], so that it
gets some testing in the upstream for-next tree.
My tests so far are good, although I'm only using gcc-11.

If you don't mind, and if it doesn't generate issues for other
platforms & architectures I could submit them upstream to Linus when
I send the next pull request.

Helge

[1] https://git.kernel.org/pub/scm/linux/kernel/git/deller/parisc-linux.git=
/log/?h=3Dfor-next

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/525f9914-04bd-2d8a-0bbf-daf2d0d2053d%40gmx.de.
