Return-Path: <kasan-dev+bncBAABBY453XBQMGQE55S4ECA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3c.google.com (mail-oa1-x3c.google.com [IPv6:2001:4860:4864:20::3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 72C2FB06E75
	for <lists+kasan-dev@lfdr.de>; Wed, 16 Jul 2025 09:04:05 +0200 (CEST)
Received: by mail-oa1-x3c.google.com with SMTP id 586e51a60fabf-2ff53b48950sf2332418fac.3
        for <lists+kasan-dev@lfdr.de>; Wed, 16 Jul 2025 00:04:05 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1752649444; cv=pass;
        d=google.com; s=arc-20240605;
        b=WaozOWP3LuLyXFdI/iM40lBO2E/A51XdFUtIza4lc+1TT6VSo90TbdY1no9prDaK8U
         iZroJWep8gTxkVqaCGT+/ZXzvLAyEZ7b/LIr4JgM+QQr1h9PcEffNIZombqf7gOMTcUG
         SWqy5275ezw8OqJBoErOPuRpbxTXKYeNmIQgxxAAOiBmnH7A1tYmQJgHjUpr/y+pozm9
         rKGqdOJsxHCDJnVvG4uB7ZU/fYVRiygm1BDvuleP9xax55QtgbZuUPE2n6GcoFmUuNss
         wUWiYHkEbSrGG/EAX/gxkuDsqyLfFUwMdyvCJV2yM5BEY8myqozRU3AvFEKiL9+5AHuT
         /rzg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version
         :content-transfer-encoding:content-language:accept-language
         :in-reply-to:references:message-id:date:thread-index:thread-topic
         :subject:cc:to:from:dkim-signature;
        bh=JklZNDXiUWIl2yP3M5u2Wu9oGXwi5d9ahumVT7HcwQ0=;
        fh=iaunBNRovrlkpRXdHxjGeVEDuZ0JYQb8fSf1QEdUBZA=;
        b=PhM4ET4rR3pdafmQA4rF7vspVig+6sROyeoMX7tNFbA1QRMSeNgFd8C5eCTBnogBrQ
         jEUa3tvmlDuUrQZYKu78JWkXvUZDx6ar8mCieit5YDNjZrIozIUSlTbCq90wQLCvlG+g
         CUJqz9VWL/i+lCXlhH4Jx5e7xSlrewKiv1lbMDJV0MPulxvWg22/TsIJtwkjZBYNznY/
         tGgDqYFjd9Th2LqnTeF+hWTZUeOW//M1hMysLGwogmZmX0D+NbxXHEwhpopLXJSa9a62
         Z19bG75wbGXY3PPuc5OMJ31tlwGnDhfW+zDLoY1heGaZKWPcFauVgLyIvkL4mmLhDXiA
         sLwQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of haiyan.liu@unisoc.com designates 222.66.158.135 as permitted sender) smtp.mailfrom=haiyan.liu@unisoc.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=unisoc.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1752649444; x=1753254244; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :content-transfer-encoding:content-language:accept-language
         :in-reply-to:references:message-id:date:thread-index:thread-topic
         :subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=JklZNDXiUWIl2yP3M5u2Wu9oGXwi5d9ahumVT7HcwQ0=;
        b=uUEgQOFNsttf+ATOLA3EXJ6sEyPfK0ZSvFthz4GvtkpRPaeRBprWaFQX2ol1tLfpPN
         iQaDtdONF7YQWaBpe5IKQsN/b4UrXr8M427xbdg5ifNE985tiQwqLemopCGbt4Ba7YzZ
         nNhMG44KX/AdF0V0/i0TGWzPSVOHlid9J/cU0zfUAMCn+jsk9eZNAA/v6OA+aGS9bJp8
         07hcrAacpmR8e+tFcHzSaHcHqhiv+6meIE83cMOAl0jPn72jbrmrc+0fPcZU1NTz/t1z
         yXmFPMF2KOkA21iX11itzi05+l6HdgfuVfFmNtVWUsWsycJijTst+JjodjDMjhy06KDN
         //EA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1752649444; x=1753254244;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :content-transfer-encoding:content-language:accept-language
         :in-reply-to:references:message-id:date:thread-index:thread-topic
         :subject:cc:to:from:x-beenthere:x-gm-message-state:from:to:cc
         :subject:date:message-id:reply-to;
        bh=JklZNDXiUWIl2yP3M5u2Wu9oGXwi5d9ahumVT7HcwQ0=;
        b=vib05pUw0FgHwyiVdiZRZtJF1ZaNZz9c7rhs2vSS1s1WMe15ysqiDtvzJDmtfti0Ms
         LXpVK/IRPbue2GVc/crE37RSbJDwWJLJjUhnINlRBTv/Npb7ZrK75hYQVWHPjPGRFp76
         CxkWCKgzpI676g9UDzFxcXuSrqXUK8OoRkfIWDMgcPKkPQBW6eCfCalD2qITjrpjBact
         nqpo8T+FnnGG6Y7S1QPh7EQu1gR0yYW7cLjUg0M2XoY02QnBhmpfZNe+pOMTiVwIqlnq
         SUVkFF45xD8U0iEn/igF6idwAJMm6B5Qw73+6arXdTQsJP8jIfJW9Ofp+arPAvo8Nkbe
         nVpQ==
X-Forwarded-Encrypted: i=2; AJvYcCVtOu7oLnj9o5fqBr0Osw1J6ZVNHnkFZSfJyKhHUOojTNLTD4+qDXhAM/b3ykwj8PnFyGbSYQ==@lfdr.de
X-Gm-Message-State: AOJu0YxpfS6fZQCO6TwMFUfKOMeVJCmIkGUvts2Yph7spLhw+VU1cm0Z
	ivKWw+QuG7n/k9FcN1wo/6tV3ndgKGRFio1l0+Be3UaX+EefqMJScq5K
X-Google-Smtp-Source: AGHT+IHGU5mgRx/9uufF9xCvMGYJMsjxMVIAwEa+kKhDvw8S/SSmofNomuG0dsGmESkrGEfIsWokzQ==
X-Received: by 2002:a05:6870:d14a:b0:2e8:ec55:aafc with SMTP id 586e51a60fabf-2ffb253ef42mr1228654fac.37.1752649443651;
        Wed, 16 Jul 2025 00:04:03 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdPcFLmP+4HVoug2hdLorrAnFD46hgOfb4yFXmf9i3f7g==
Received: by 2002:a05:6871:3214:b0:2ff:8cb6:b720 with SMTP id
 586e51a60fabf-2ff8cb6ba0dls985743fac.0.-pod-prod-05-us; Wed, 16 Jul 2025
 00:04:03 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCW7q0U8cagZGzE162ljvB9o7Z9I9St+cAsNyBxm41zq9EOpkWjP24Nreq3vImr3Kla0LXH0ateFC2w=@googlegroups.com
X-Received: by 2002:a05:6808:50a4:b0:405:6b13:ca55 with SMTP id 5614622812f47-41d05c3ca63mr1198893b6e.37.1752649442913;
        Wed, 16 Jul 2025 00:04:02 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1752649442; cv=none;
        d=google.com; s=arc-20240605;
        b=VQLUS12XXg4uVDh4lMhItDXIyQ3I8x6090gdQwDqxVd0hRZcgkexuTBVdw7daTfn2S
         fnqQHKWiK+Br6mj/6EhxnMfp1pyObrV7KnPD8ctRFET4MqCO2ma29NgpT5gVcrSXsZPq
         O5+KP8N1/pgNm7TOulIcZWwjwe786OltazfPr+mL7YXIYo5rvSZzPyne/8Lu6cP8DqTM
         vgzouQXLwjbCwkk/AvZvEBLHjAw8Kx83wmONu+lkRNmrvLhSJGDhjdJd+2WTZ01uRmiM
         tp8baZa1qRgLjaNu0N6Dt0IQk4xuCIej3s4IO5QjF1l/3CiugJg4tspG/rGjIDJ/AFs4
         cSjw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:content-transfer-encoding:content-language
         :accept-language:in-reply-to:references:message-id:date:thread-index
         :thread-topic:subject:cc:to:from;
        bh=l1mCwU/UAqJpitjQKQAf0VtDhJtI7nZ/jUOaeDsPe6s=;
        fh=cuiwWX2kxqkUy0w8KZltQwvTK75tfgb0OtR8Ofc9GEc=;
        b=LihJzZqtFXvhpIMrFb/HSc4g7JUE0NV+QefVBeFO5dB2wtewbkPYEs59E/5XZ2uh9+
         xIpW00R9M6t/0Kw9pzFzLQ9f5BMLfwsh1hk07gjyCXOAFa7Nf21IYE2rSx9sYAfB5Xpa
         +jVNbSkbU1aGYec3FR+Uf9dqit/0J8P37csgc//pJf+3tr3bHwEmqv8HTa+g7Nlx2oS/
         Stxqokjep3Qt0Or26a8A6SCgN4CydLhk3qXCDc8xiJF+Z3cYbLgge+28I0x7/Ww2AxfU
         WqdYl7FEo39a1b7U2n1YG3n4Cno5TL+ZbfXW9GPfzvvJhZyyMX5l3d8nztwZpocEx72Q
         v/1A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of haiyan.liu@unisoc.com designates 222.66.158.135 as permitted sender) smtp.mailfrom=haiyan.liu@unisoc.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=unisoc.com
Received: from SHSQR01.spreadtrum.com (mx1.unisoc.com. [222.66.158.135])
        by gmr-mx.google.com with ESMTPS id 006d021491bc7-6159092ea4asi227193eaf.2.2025.07.16.00.03.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 16 Jul 2025 00:04:02 -0700 (PDT)
Received-SPF: pass (google.com: domain of haiyan.liu@unisoc.com designates 222.66.158.135 as permitted sender) client-ip=222.66.158.135;
Received: from dlp.unisoc.com ([10.29.3.86])
	by SHSQR01.spreadtrum.com with ESMTP id 56G71YUo039376;
	Wed, 16 Jul 2025 15:01:34 +0800 (+08)
	(envelope-from haiyan.liu@unisoc.com)
Received: from SHDLP.spreadtrum.com (bjmbx02.spreadtrum.com [10.0.64.8])
	by dlp.unisoc.com (SkyGuard) with ESMTPS id 4bhn176KQXz2K5mNX;
	Wed, 16 Jul 2025 14:57:15 +0800 (CST)
Received: from BJMBX01.spreadtrum.com (10.0.64.7) by BJMBX02.spreadtrum.com
 (10.0.64.8) with Microsoft SMTP Server (TLS) id 15.0.1497.48; Wed, 16 Jul
 2025 15:01:29 +0800
Received: from BJMBX01.spreadtrum.com ([fe80::54e:9a:129d:fac7]) by
 BJMBX01.spreadtrum.com ([fe80::54e:9a:129d:fac7%16]) with mapi id
 15.00.1497.048; Wed, 16 Jul 2025 15:01:29 +0800
From: =?UTF-8?B?J+WImOa1t+eHlSAoSGFpeWFuIExpdSknIHZpYSBrYXNhbi1kZXY=?= <kasan-dev@googlegroups.com>
To: Miguel Ojeda <miguel.ojeda.sandonis@gmail.com>
CC: Miguel Ojeda <ojeda@kernel.org>,
        =?utf-8?B?5ZGo5bmzIChQaW5nIFpob3UvOTAzMik=?= <Ping.Zhou1@unisoc.com>,
        =?utf-8?B?5Luj5a2Q5Li6IChaaXdlaSBEYWkp?= <Ziwei.Dai@unisoc.com>,
        =?utf-8?B?5p2o5Li95aicIChMaW5hIFlhbmcp?= <lina.yang@unisoc.com>,
        "linux-arm-kernel@lists.infradead.org"
	<linux-arm-kernel@lists.infradead.org>,
        "linux-kernel@vger.kernel.org"
	<linux-kernel@vger.kernel.org>,
        "rust-for-linux@vger.kernel.org"
	<rust-for-linux@vger.kernel.org>,
        =?utf-8?B?546L5Y+MIChTaHVhbmcgV2FuZyk=?=
	<shuang.wang@unisoc.com>,
        Andrey Ryabinin <ryabinin.a.a@gmail.com>,
        "Alexander Potapenko" <glider@google.com>,
        Andrey Konovalov
	<andreyknvl@gmail.com>,
        Dmitry Vyukov <dvyukov@google.com>,
        Vincenzo Frascino
	<vincenzo.frascino@arm.com>,
        "kasan-dev@googlegroups.com"
	<kasan-dev@googlegroups.com>,
        Greg Kroah-Hartman
	<gregkh@linuxfoundation.org>,
        =?utf-8?B?QXJ2ZSBIasO4bm5ldsOlZw==?=
	<arve@android.com>,
        Todd Kjos <tkjos@android.com>, Martijn Coenen
	<maco@android.com>,
        Joel Fernandes <joelagnelf@nvidia.com>,
        Christian Brauner
	<christian@brauner.io>,
        Carlos Llamas <cmllamas@google.com>,
        "Suren
 Baghdasaryan" <surenb@google.com>,
        Jamie Cunliffe <Jamie.Cunliffe@arm.com>,
        Catalin Marinas <catalin.marinas@arm.com>
Subject: Meet compiled kernel binaray abnormal issue while enabling generic
 kasan in kernel 6.12 with some default KBUILD_RUSTFLAGS on
Thread-Topic: Meet compiled kernel binaray abnormal issue while enabling
 generic kasan in kernel 6.12 with some default KBUILD_RUSTFLAGS on
Thread-Index: Adv0awkF3quLQs5+RfaRTr3Yr7SnUQATGr8AACy4DEAAAOVlAAAqFjnw
Date: Wed, 16 Jul 2025 07:01:29 +0000
Message-ID: <24e87f60203c443abe7549ce5c0e9e75@BJMBX01.spreadtrum.com>
References: <4c459085b9ae42bdbf99b6014952b965@BJMBX01.spreadtrum.com>
 <202507150830.56F8U908028199@SHSPAM01.spreadtrum.com>
 <c34f4f606eb04c38b64e8f3a658cd051@BJMBX01.spreadtrum.com>
 <CANiq72=v6jkOasLiem7RXe-WUSg9PkNqrZneeMOTi1pzwXuHYg@mail.gmail.com>
In-Reply-To: <CANiq72=v6jkOasLiem7RXe-WUSg9PkNqrZneeMOTi1pzwXuHYg@mail.gmail.com>
Accept-Language: zh-CN, en-US
Content-Language: zh-CN
X-MS-Has-Attach: 
X-MS-TNEF-Correlator: 
x-ms-exchange-transport-fromentityheader: Hosted
x-originating-ip: [10.0.93.65]
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
MIME-Version: 1.0
X-MAIL: SHSQR01.spreadtrum.com 56G71YUo039376
X-Original-Sender: haiyan.liu@unisoc.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of haiyan.liu@unisoc.com designates 222.66.158.135 as
 permitted sender) smtp.mailfrom=haiyan.liu@unisoc.com;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=unisoc.com
X-Original-From: =?utf-8?B?5YiY5rW354eVIChIYWl5YW4gTGl1KQ==?= <haiyan.liu@unisoc.com>
Reply-To: =?utf-8?B?5YiY5rW354eVIChIYWl5YW4gTGl1KQ==?= <haiyan.liu@unisoc.com>
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



> -----=E9=82=AE=E4=BB=B6=E5=8E=9F=E4=BB=B6-----
> =E5=8F=91=E4=BB=B6=E4=BA=BA: Miguel Ojeda <miguel.ojeda.sandonis@gmail.co=
m>
> =E5=8F=91=E9=80=81=E6=97=B6=E9=97=B4: 2025=E5=B9=B47=E6=9C=8816=E6=97=A5 =
1:51
> =E6=94=B6=E4=BB=B6=E4=BA=BA: =E5=88=98=E6=B5=B7=E7=87=95 (Haiyan Liu) <ha=
iyan.liu@unisoc.com>
> =E6=8A=84=E9=80=81: Miguel Ojeda <ojeda@kernel.org>; =E5=91=A8=E5=B9=B3 (=
Ping Zhou/9032) <Ping.Zhou1@unisoc.com>; =E4=BB=A3=E5=AD=90=E4=B8=BA (Ziwei=
 Dai)
> <Ziwei.Dai@unisoc.com>; =E6=9D=A8=E4=B8=BD=E5=A8=9C (Lina Yang) <lina.yan=
g@unisoc.com>; linux-arm-kernel@lists.infradead.org;
> linux-kernel@vger.kernel.org; rust-for-linux@vger.kernel.org; =E7=8E=8B=
=E5=8F=8C (Shuang Wang) <shuang.wang@unisoc.com>; Andrey Ryabinin
> <ryabinin.a.a@gmail.com>; Alexander Potapenko <glider@google.com>; Andrey=
 Konovalov <andreyknvl@gmail.com>; Dmitry Vyukov
> <dvyukov@google.com>; Vincenzo Frascino <vincenzo.frascino@arm.com>; kasa=
n-dev@googlegroups.com; Greg Kroah-Hartman
> <gregkh@linuxfoundation.org>; Arve Hj=C3=B8nnev=C3=A5g <arve@android.com>=
; Todd Kjos <tkjos@android.com>; Martijn Coenen
> <maco@android.com>; Joel Fernandes <joelagnelf@nvidia.com>; Christian Bra=
uner <christian@brauner.io>; Carlos Llamas
> <cmllamas@google.com>; Suren Baghdasaryan <surenb@google.com>; Jamie Cunl=
iffe <Jamie.Cunliffe@arm.com>; Catalin Marinas
> <catalin.marinas@arm.com>
> =E4=B8=BB=E9=A2=98: Re: Meet compiled kernel binaray abnormal issue while=
 enabling generic kasan in kernel 6.12 with some default KBUILD_RUSTFLAGS
> on
>=20
>=20
> =E6=B3=A8=E6=84=8F: =E8=BF=99=E5=B0=81=E9=82=AE=E4=BB=B6=E6=9D=A5=E8=87=
=AA=E4=BA=8E=E5=A4=96=E9=83=A8=E3=80=82=E9=99=A4=E9=9D=9E=E4=BD=A0=E7=A1=AE=
=E5=AE=9A=E9=82=AE=E4=BB=B6=E5=86=85=E5=AE=B9=E5=AE=89=E5=85=A8=EF=BC=8C=E5=
=90=A6=E5=88=99=E4=B8=8D=E8=A6=81=E7=82=B9=E5=87=BB=E4=BB=BB=E4=BD=95=E9=93=
=BE=E6=8E=A5=E5=92=8C=E9=99=84=E4=BB=B6=E3=80=82
> CAUTION: This email originated from outside of the organization. Do not c=
lick links or open attachments unless you recognize the sender
> and know the content is safe.
>=20
>=20
>=20
> On Tue, Jul 15, 2025 at 11:41=E2=80=AFAM =E5=88=98=E6=B5=B7=E7=87=95 (Hai=
yan Liu) <haiyan.liu@unisoc.com> wrote:
> >
> > The commit changes the fragment and diff is:
>=20
> An Android engineer should know how to handle that, but if you are report=
ing upstream, it is best to try to reproduce the issue with the
> upstream kernels (e.g. arm64 is not in 6.6.y) and provide the full kernel=
 config used.
>=20
> > Only two rust-related global variables in fmr.rs and layout.rs have thi=
s issue. Their asan.module_ctor complied binaries are wrong.
>=20
> I am not sure what you mean by `fmr.rs`. As for `layout.rs`, that is in t=
he `kernel` crate in 6.12.y -- isn't there a single `asan.module_ctor`
> per TU? Which object file are you referring to? I get the pair for my `ru=
st/kernel.o`.

  NSX:FFFFFFC0800A7C94|F800865E  asan.module_ctor:   str     x30,[x18],#0x8=
   ; x30,[x18],#8
   NSX:FFFFFFC0800A7C98|F81F0FFE                      str     x30,[sp,#-0x1=
0]!   ; x30,[sp,#-16]!
   NSX:FFFFFFC0800A7C9C|F00240A0                      adrp    x0,0xFFFFFFC0=
848BE000
   NSX:FFFFFFC0800A7CA0|911D8000                      add     x0,x0,#0x760 =
    ; x0,x0,#1888
   NSX:FFFFFFC0800A7CA4|52803D61                      mov     w1,#0x1EB    =
    ; w1,#491
   NSX:FFFFFFC0800A7CA8|94233816                      bl      0xFFFFFFC0809=
75D00   ; __asan_register_globals
   NSX:FFFFFFC0800A7CAC|F84107FE                      ldr     x30,[sp],#0x1=
0   ; x30,[sp],#16
   NSX:FFFFFFC0800A7CB0|D50323BF                      autiasp
   NSX:FFFFFFC0800A7CB4|D65F03C0                      ret
The first __asan_global struct value is=20
 ENAXI:FFFFFFC0848BE760|>FFFFFFC082EDB180 000000000000005F ........_.......
 ENAXI:FFFFFFC0848BE770| 0000000000000080 FFFFFFC0836DC431 ........1.m.....
 ENAXI:FFFFFFC0848BE780| FFFFFFC082EEC780 0000000000000000 ................
 ENAXI:FFFFFFC0848BE790| 0000000000000000 FFFFFFFFFFFFFFFF ................
The address of the global is 0xFFFFFFC082EDB180 which value is '/proc/self/=
cwd/prebuilts/rust/linux-x86/1.82.0/lib/rustlib/src/rust/library/core/src/n=
um/fmt.rs' and its viewinfo is 'vmlinux\Global\__unnamed_357'
The original size of the global is 0x5F
The name of the global is kmalloc-2k
The module name of the global is 'core.27758904ccee4c80-cgu.o'

   NSX:FFFFFFC0800A7D4C|F800865E  asan.mod.:str     x30,[x18],#0x8   ; x30,=
[x18],#8
   NSX:FFFFFFC0800A7D50|F81F0FFE            str     x30,[sp,#-0x10]!   ; x3=
0,[sp,#-16]!
   NSX:FFFFFFC0800A7D54|F00240E0            adrp    x0,0xFFFFFFC0848C6000
   NSX:FFFFFFC0800A7D58|912E8000            add     x0,x0,#0xBA0     ; x0,x=
0,#2976
   NSX:FFFFFFC0800A7D5C|52800961            mov     w1,#0x4B         ; w1,#=
75
   NSX:FFFFFFC0800A7D60|942337E8            bl      0xFFFFFFC080975D00   ; =
__asan_register_globals
   NSX:FFFFFFC0800A7D64|F84107FE            ldr     x30,[sp],#0x10   ; x30,=
[sp],#16
   NSX:FFFFFFC0800A7D68|D50323BF            autiasp
   NSX:FFFFFFC0800A7D6C|D65F03C0            ret
The second __asan_global struct value is=20
   NSD:FFFFFFC0848C6BA0|>FFFFFFC082EECA80 0000000000000020 ........ .......
   NSD:FFFFFFC0848C6BB0| 0000000000000040 FFFFFFC0836DC431 @.......1.m.....
   NSD:FFFFFFC0848C6BC0| FFFFFFC082EEDA80 0000000000000000 ................
   NSD:FFFFFFC0848C6BD0| 0000000000000000 FFFFFFFFFFFFFFFF ................
The address of the global is 0xFFFFFFC082EECA80 which value is 0 and its vi=
ewinfo is '<&usize_as_core::f..vmlinux\kernel_9a6cb9fd7c8dfd66_cgu\<&usize_=
as_core::fmt::Debug>::{vtable}'
The original size of the global is 0x20
The name of the global is kmalloc-2k
The module name of the global is 'kernel.9a6cb9fd7c8dfd66-cgu.o'

> Cheers,
> Miguel

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/2=
4e87f60203c443abe7549ce5c0e9e75%40BJMBX01.spreadtrum.com.
