Return-Path: <kasan-dev+bncBDV2D5O34IDRB7OG2GGAMGQEHJR5L6A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc39.google.com (mail-oo1-xc39.google.com [IPv6:2607:f8b0:4864:20::c39])
	by mail.lfdr.de (Postfix) with ESMTPS id A5C3B453E2A
	for <lists+kasan-dev@lfdr.de>; Wed, 17 Nov 2021 03:05:50 +0100 (CET)
Received: by mail-oo1-xc39.google.com with SMTP id k1-20020a4a8501000000b0029ac7b9dc82sf706854ooh.17
        for <lists+kasan-dev@lfdr.de>; Tue, 16 Nov 2021 18:05:50 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1637114749; cv=pass;
        d=google.com; s=arc-20160816;
        b=sbMNfUkzwLF6G5E2SCBKMzJ0WaZAM0oiwPAe451y9qi0RY6WyJPzFAd8EH1dP086mW
         rlBuCr7Gw4jPB5mfZ/0bGsOaUPrYL9eDlGf4ZVPvU21E21YS8EDID0vWUnf9bOQCPJav
         0GCchUi9KZ7iGf9MUqRrYIK/ryPIVeEwatJflGxUnKIW5OaCMsx1tgjqn/euHlEqlUqK
         f4jMR1ubAO8jH0klPypFYPWw9Cdkq6mls6QCo2rkc53XDyOs/a2oNbDYyJxEyWPk9PLP
         Bdz5MWBM1qw1y0PQjNRkbHr/JF/pe8cDavrJtw11Q4gk8SvX+iYGF+IIYV0mBeux19Is
         EzsQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :content-language:in-reply-to:mime-version:user-agent:date
         :message-id:from:references:cc:to:subject:sender:dkim-signature;
        bh=K98LV+D6osVQaQMzMAV27raCN4suAf48Z+zRkeGgIwk=;
        b=hp9B6B/+QPCmIuMwWDHvwy6cuJwpn+0vzdrBI9X/Zdx3z1nQanfe7Jz3iutS+39c1U
         NnRUhjc2OkWawZGa6TLJ0oU5OOFPBhpoo1AcP+EDlSE86CDxlwmEHKDrG08jCmTk5GoU
         ll8xyWmqaZTv1pvLRsQGkNUh2yo6s5xdsL5oEUar5Ms+PDrrXM2qMpHw8jNAwEvKaKU+
         16Z0BTw8x93RS+DLeT2FpvSwUI0QWO23GwhiCTKVDMJ7PSa3PvHpdHrHUGPjRblKt74D
         9wwUXAxcwyYvawEcxTGczKoFznnLbXRtywgd1bcxGzP2Pe3jnulBByRryPoXHCRirCzX
         pV0A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=bombadil.20210309 header.b="Adq4v/KW";
       spf=pass (google.com: best guess record for domain of rdunlap@infradead.org designates 2607:7c80:54:e::133 as permitted sender) smtp.mailfrom=rdunlap@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=K98LV+D6osVQaQMzMAV27raCN4suAf48Z+zRkeGgIwk=;
        b=Z8INkhraspxJgkwCLsCiT41yczDQx/HKX+RreXX3d2p9OUYmx+Ma8zAn52R6Is4RWh
         qpMr2NzjcYbG0/qkjDhl0efrwNX69uL41yt5jm9/ORtNZ6Dh/iteyAXIDqprhZ+5q24T
         6Mvlofh4DHI1jNo1rXpfDvwOGpMErzZ2hXiD9v2tfV6UvrNZV1Qe5xwXrr9Os75ONfoU
         YGPMbGc1dQ1DieAKr8noV8m0ET4VGy56aUgKn/tsQSMlIsDEV5dY/Px06LMmxeq/vJVy
         qi3Qkf3LqmQbf1AyQyUA3pNcvW7kPwtwlxBgsFlnNWt1/kjHqNDr08VSMY4eB6MG39YB
         zfeQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=K98LV+D6osVQaQMzMAV27raCN4suAf48Z+zRkeGgIwk=;
        b=m/TwVV/TmYTIHc9YVflSacFg04KSsi8UaqBB6SH0Q68/YQuu2jOCFpX1rAICbdszKG
         cRFYlCpaj1tyA/ZlGHws8Y4uXHEwrsut7vqOmSHpxYD6aE0nwSG0yYxc7XU3RwUWvuuu
         LBrDp4pHlpnudMkurTr5tJcWMYIOGfVfFCLQoLdRB0jBbSd6uuU1iEaYTzVHpQrgnv6S
         C1NHC3WTkiwX5Jn60DVSrh+y6P0rEcyaEGt08WSLeqx4wVR+hTXYLhuhsg2gFjZBx3UR
         Y3URko7KHKT2OLpSzo3ak2TuzFVtFBtjq/cLMLKLYRXfkPylsYRqIQsVOQhR0KMlpgPO
         PUzw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531TOzVMh/hUsylZfiPsjekbVCoVK4Ph+tju2FiQEsflydSfZ0Mp
	G4v4OSJ84QyTJPB4iGG8728=
X-Google-Smtp-Source: ABdhPJyNxaHisBS/6NITbd+qoM8KOCM1AekXsquUjSmmAOynP5pNs9gFzUDjt5XAqw+vSJ70h+KMEQ==
X-Received: by 2002:a05:6830:4d:: with SMTP id d13mr10648455otp.45.1637114749536;
        Tue, 16 Nov 2021 18:05:49 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6808:15a1:: with SMTP id t33ls2497509oiw.6.gmail; Tue,
 16 Nov 2021 18:05:49 -0800 (PST)
X-Received: by 2002:a54:4f1d:: with SMTP id e29mr57568185oiy.179.1637114749156;
        Tue, 16 Nov 2021 18:05:49 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1637114749; cv=none;
        d=google.com; s=arc-20160816;
        b=G2nfQP9Ih5Xz1xElsY/NiACv/SmVWXAOPtM9agkqNmuDEqemDw34PyNdKrgJH9yVL2
         02bUh0gVp7Yu3hLJ34mfb7YMhLfYSaDyzesUtP00bBpbX4fN6PZe711lg7i0wzPvhwto
         iuaqbw1CdX35dV4t0GpF/nY+2gMcExGIkDzDhCI5u4OLWRr1op2qyozWOTn3FQjdmbwA
         GLMHJik0vb3CbtmaWHgHaYqCaMuC7spENQUXuYF6/bEDSZw8+bID3dyz6ogUefModbAY
         d129T17IBYROutsADm5BEY/aQBnCafzVxw0LA5cTM5fpS2vB52a70kpEqffwyvEAOpZg
         tQGA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject
         :dkim-signature;
        bh=4tWYtMZGixA+wvOSftKSlvk/VgodDRuuv8NOVBgK9qA=;
        b=Ic2FYhfJ5J5LBIv7kLd65ovbS2tZQdif+LMk0/2R2j1aSKLNFGjjS/PfWlFUP4xV2a
         2vID0feYvcwgAf63COucuw2dtmm2ugtTHZxaotrJNPJQwDdVQOMo1UV9emnXn402Fde8
         fcdM00o/tXEcRx4Ji1ZfFTd/iiToRqCDcLgF7OTYI+BYxYLXigKBpIcJ8GpJ30K+nOkJ
         hF+YcxaHs/9YyvayN9liENdVwrlWnfFmtzMCVacze75BEl5wO7l9HIga/nsL8JRNHjw5
         zNf6EIbH10yawDlbfHzPYt2wK/7RKhVhbSCl3cVnlr5GF47Y9642a00W/dmWjrTy41yU
         LMMw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=bombadil.20210309 header.b="Adq4v/KW";
       spf=pass (google.com: best guess record for domain of rdunlap@infradead.org designates 2607:7c80:54:e::133 as permitted sender) smtp.mailfrom=rdunlap@infradead.org
Received: from bombadil.infradead.org (bombadil.infradead.org. [2607:7c80:54:e::133])
        by gmr-mx.google.com with ESMTPS id g64si221902oia.1.2021.11.16.18.05.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 16 Nov 2021 18:05:48 -0800 (PST)
Received-SPF: pass (google.com: best guess record for domain of rdunlap@infradead.org designates 2607:7c80:54:e::133 as permitted sender) client-ip=2607:7c80:54:e::133;
Received: from [2601:1c0:6280:3f0::aa0b]
	by bombadil.infradead.org with esmtpsa (Exim 4.94.2 #2 (Red Hat Linux))
	id 1mnAKU-0035bi-Ao; Wed, 17 Nov 2021 02:05:44 +0000
Subject: Re: Build regressions/improvements in v5.16-rc1
To: Nick Terrell <terrelln@fb.com>, Helge Deller <deller@gmx.de>
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
From: Randy Dunlap <rdunlap@infradead.org>
Message-ID: <78b2d093-e06c-ba04-9890-69f948bfb937@infradead.org>
Date: Tue, 16 Nov 2021 18:05:40 -0800
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101
 Thunderbird/78.13.0
MIME-Version: 1.0
In-Reply-To: <480CE37B-FE60-44EE-B9D2-59A88FDFE809@fb.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Language: en-US
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: rdunlap@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=bombadil.20210309 header.b="Adq4v/KW";
       spf=pass (google.com: best guess record for domain of
 rdunlap@infradead.org designates 2607:7c80:54:e::133 as permitted sender) smtp.mailfrom=rdunlap@infradead.org
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

On 11/16/21 5:59 PM, Nick Terrell wrote:
>=20
>=20
>> On Nov 15, 2021, at 8:44 AM, Helge Deller <deller@gmx.de> wrote:
>>
>> On 11/15/21 17:12, Geert Uytterhoeven wrote:
>>> On Mon, Nov 15, 2021 at 4:54 PM Geert Uytterhoeven <geert@linux-m68k.or=
g> wrote:
>>>> Below is the list of build error/warning regressions/improvements in
>>>> v5.16-rc1[1] compared to v5.15[2].
>>>>
>>>> Summarized:
>>>>   - build errors: +20/-13
>>>>   - build warnings: +3/-28
>>>>
>>>> Happy fixing! ;-)
>>>>
>>>> Thanks to the linux-next team for providing the build service.
>>>>
>>>> [1] http://kisskb.ellerman.id.au/kisskb/branch/linus/head/fa55b7dcdc43=
c1aa1ba12bca9d2dd4318c2a0dbf/  (all 90 configs)
>>>> [2] http://kisskb.ellerman.id.au/kisskb/branch/linus/head/8bb7eca972ad=
531c9b149c0a51ab43a417385813/  (all 90 configs)
>>>>
>>>>
>>>> *** ERRORS ***
>>>>
>>>> 20 error regressions:
>>>>   + /kisskb/src/arch/parisc/include/asm/jump_label.h: error: expected =
':' before '__stringify':  =3D> 33:4, 18:4
>>>>   + /kisskb/src/arch/parisc/include/asm/jump_label.h: error: label 'l_=
yes' defined but not used [-Werror=3Dunused-label]:  =3D> 38:1, 23:1
>>>
>>>     due to static_branch_likely() in crypto/api.c
>>>
>>> parisc-allmodconfig
>>
>> fixed now in the parisc for-next git tree.
>>
>>
>>>>   + /kisskb/src/drivers/gpu/drm/msm/msm_drv.h: error: "COND" redefined=
 [-Werror]:  =3D> 531
>>>>   + /kisskb/src/lib/zstd/compress/zstd_double_fast.c: error: the frame=
 size of 3252 bytes is larger than 1536 bytes [-Werror=3Dframe-larger-than=
=3D]:  =3D> 47:1
>>>>   + /kisskb/src/lib/zstd/compress/zstd_double_fast.c: error: the frame=
 size of 3360 bytes is larger than 1536 bytes [-Werror=3Dframe-larger-than=
=3D]:  =3D> 499:1
>>>>   + /kisskb/src/lib/zstd/compress/zstd_double_fast.c: error: the frame=
 size of 5344 bytes is larger than 1536 bytes [-Werror=3Dframe-larger-than=
=3D]:  =3D> 334:1
>>>>   + /kisskb/src/lib/zstd/compress/zstd_double_fast.c: error: the frame=
 size of 5380 bytes is larger than 1536 bytes [-Werror=3Dframe-larger-than=
=3D]:  =3D> 354:1
>>>>   + /kisskb/src/lib/zstd/compress/zstd_fast.c: error: the frame size o=
f 1824 bytes is larger than 1536 bytes [-Werror=3Dframe-larger-than=3D]:  =
=3D> 372:1
>>>>   + /kisskb/src/lib/zstd/compress/zstd_fast.c: error: the frame size o=
f 2224 bytes is larger than 1536 bytes [-Werror=3Dframe-larger-than=3D]:  =
=3D> 204:1
>>>>   + /kisskb/src/lib/zstd/compress/zstd_fast.c: error: the frame size o=
f 3800 bytes is larger than 1536 bytes [-Werror=3Dframe-larger-than=3D]:  =
=3D> 476:1
>>>
>>> parisc-allmodconfig
>>
>> parisc needs much bigger frame sizes, so I'm not astonished here.
>> During the v5.15 cycl I increased it to 1536 (from 1280), so I'm simply =
tempted to
>> increase it this time to 4096, unless someone has a better idea....
>=20
> This patch set should fix the zstd stack size warnings [0]. I=E2=80=99ve
> verified the fix using the same tooling: gcc-8-hppa-linux-gnu.
>=20
> I=E2=80=99ll send the PR to Linus tomorrow. I=E2=80=99ve been informed th=
at it
> isn't strictly necessary to send the patches to the mailing list
> for bug fixes, but its already done, so I=E2=80=99ll wait and see if ther=
e
> is any feedback.

IMO several (or many more) people would disagree with that.

"strictly?"  OK, it's probably possible that almost any patch
could be merged without being on a mailing list, but it's not
desirable (except in the case of "security" patches).

--=20
~Randy

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/78b2d093-e06c-ba04-9890-69f948bfb937%40infradead.org.
