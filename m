Return-Path: <kasan-dev+bncBAABB35G4HBQMGQEKCY7RZA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x639.google.com (mail-pl1-x639.google.com [IPv6:2607:f8b0:4864:20::639])
	by mail.lfdr.de (Postfix) with ESMTPS id 2882CB08274
	for <lists+kasan-dev@lfdr.de>; Thu, 17 Jul 2025 03:35:46 +0200 (CEST)
Received: by mail-pl1-x639.google.com with SMTP id d9443c01a7336-2356ce66d7csf5764725ad.1
        for <lists+kasan-dev@lfdr.de>; Wed, 16 Jul 2025 18:35:46 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1752716144; cv=pass;
        d=google.com; s=arc-20240605;
        b=d/H8aeM9Eh2zJ3QGiCr9x3YPC1+TmsPSMYE1tXMMtYKHaSmK0SQ2w2w0YawnlCKY/3
         MuCluCCVFbqwr0cUcZPuSY7e31BgBl2+ZjXH3H1CeytxKzjrbxJZrlOtPZvpZz85onVk
         5GznpG0vnTZ7sz1em3Did3spfa/z3cLRpoXRLJEN1z9PtpHLQKkIc2xXzcFbOzukBHaE
         wsM1OTPGcQrx7QpAcS5CiU5eo1WBeFtp81skza1UJ8UN4S1Ai/XS8lf/rWVasHwrckxK
         bTv5PFkCm6ziGLDcmg2ptfDaoQzAaK/leBAGCoUqcJBNtfKBpGNgkd8uqJwlYWpMfalA
         qRDQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version
         :content-transfer-encoding:content-language:accept-language
         :in-reply-to:references:message-id:date:thread-index:thread-topic
         :subject:cc:to:from:dkim-signature;
        bh=mlFNKs9Xoe2Yk2tFv8jRJzwvkOaetNa/tpC82ToDmUE=;
        fh=8gebkqGZpetLrVMwuGhZWwpsSBTuYhqSII5PK+Rawho=;
        b=k2yTXK4NxxRQNuuwc11JzqMPh0Stqaj8tMHMBTkl4MljjMTFfRr1IC9mMzlFRu3eOT
         XrG/GyQIwrfoDQbFiR1Kd8W54n1LSWbJ/s4vEZQXH/PggeIm8I/IhVtc3yifoH8/3BP/
         avpkbq3aIRBByeO9VWQZICMfL9WchNs/H6wII8WvWoKZ0Dr5EvMO5L7gcm1GijlCjlN/
         ZHa5BB9+0ZMQ/9z9cdHAJhxPN+9GDNkGms7CPZkXE2U2i3tiVfl9TQNCxfF9NFahPyUL
         JlFj6bvXmnU6CU6k2XxUbYsGgLGMvxpELE6s8qke3k8PnRZ3jt+gq+oQ1bn9LXcWyhqE
         dCVA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of haiyan.liu@unisoc.com designates 222.66.158.135 as permitted sender) smtp.mailfrom=haiyan.liu@unisoc.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=unisoc.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1752716144; x=1753320944; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :content-transfer-encoding:content-language:accept-language
         :in-reply-to:references:message-id:date:thread-index:thread-topic
         :subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=mlFNKs9Xoe2Yk2tFv8jRJzwvkOaetNa/tpC82ToDmUE=;
        b=vd+gMo0hfE4uWslZ9wmQfkpaFkEHVhpc54aBr+fF2lBmfydf1IitYDvhcnOAhKvlLX
         eH4PZmVO4bBlpxcqWQjfb5LdszxhDtvSkDtlj6Bj9t2MiH4nzydTPGXKkR5S1p6JKEMc
         D0z5aAYECTaAmyLc9XQ2+peL9cSxA+Xtjbi2CE3r+0C13P0yfr3uhczq/GMs18k1zNhj
         qC2VdODxZlVDX0Dpux72PA0HWbP+uunqJ+Lj+c1+KQ9Gpdh91aDN2jdDDe6xtM6lqoDh
         vpy07m1jEAcpZHP8CgysgTrHJ0+DisSq6Kbvf8hC85l74V9EowkTTRHxBp0zz3EisdWo
         sQhw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1752716144; x=1753320944;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :content-transfer-encoding:content-language:accept-language
         :in-reply-to:references:message-id:date:thread-index:thread-topic
         :subject:cc:to:from:x-beenthere:x-gm-message-state:from:to:cc
         :subject:date:message-id:reply-to;
        bh=mlFNKs9Xoe2Yk2tFv8jRJzwvkOaetNa/tpC82ToDmUE=;
        b=OnM6mC9/Cvicjdp8hsThx5KncBy9q4Lsf30/gV8yjaxdw7l5XDGlSJUv55GFDDNBml
         YDBd9MZNTTOUlCPDfoA/gw0VQgtB4Gnkzaz1bEVAUNTgi9ACOfqJ2AXQxG1oAyKr23ip
         lYP5cBkVElIrdU7rp/teEbj8VYitvOgks+1ssrKCkSVb7YqYgJWiYfuHEr8seouUAz1V
         CwPLyrORl0YPHc1xnCDg0sInxtfzN6UDXC+rn778trNtnNNWOP3Jdh2u8I8YfI0Bj5Ka
         aYMZ30mAgffp620UnPPelzNiMSzXaNeBN/ggi80rmwppioxzMdnqjnGPhVmyoO18TB4M
         UYKg==
X-Forwarded-Encrypted: i=2; AJvYcCVCiqPdBYGaHV7m7IkY+99ucK9n/CoaPLz8rxdMuKiaHJ/q7Vuh+ai6xbAqCZ5FBPWSraK41Q==@lfdr.de
X-Gm-Message-State: AOJu0YwHsmnuW89KD70tpnCojLTvEpVc/uxWuL7FN1s+l1CmjNMbxZs5
	6k3J1F5aHFcCSXO++PTi0E/0W+2m0QYlbYv1zjZXUfqk/yXn8PjOsfJP
X-Google-Smtp-Source: AGHT+IHRSTe1xdbGcBQ6kqxfUpx080aKxBoe8aZaikXttLtwt+LIqx1+7vMzveJYoX5AH+Iwu6KmbA==
X-Received: by 2002:a17:903:32c7:b0:235:f4f7:a633 with SMTP id d9443c01a7336-23e257364bbmr73392145ad.28.1752716144111;
        Wed, 16 Jul 2025 18:35:44 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZej04dR9rnrzBmwap9LaqFkrhXshs4PyQtaCA5iw1bygg==
Received: by 2002:a17:903:338c:b0:234:b735:dc95 with SMTP id
 d9443c01a7336-23e2edbc2acls2056115ad.2.-pod-prod-08-us; Wed, 16 Jul 2025
 18:35:42 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVH/Cw4Lbdkc6OoMeK1A4jRJJpTH/H66tC3rzeA1pFY2Kn4cRVFhDVjoECbu+1NaVbSWpv4fZTovUI=@googlegroups.com
X-Received: by 2002:a17:903:2f90:b0:23e:22dc:665c with SMTP id d9443c01a7336-23e25737dcbmr52807455ad.33.1752716142537;
        Wed, 16 Jul 2025 18:35:42 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1752716142; cv=none;
        d=google.com; s=arc-20240605;
        b=ElzHJcCTa7HgsknApiQIDoB7zezXEZeKrF1/49N9sXhH5M1e+95lSBsuyIZ2O12lZe
         7tATYcUFzSji+G2OO+CVxQ+YD/WggEmucGtS03VrpCz9O6ldljoffN3FckAZwSjw0Z9R
         Sb/ZEfWesA/uoR5BpzuEFaoZom6GqIrPqt+banfysejqt2nQDdarlHI2sapNV3eM2QMw
         PxHYLeUo5GDpnE5GjLBpaW9grmP4nP+BzC0DtDHh7dMBH1NrOMpAAX03wJ4UF9hAeT2d
         fcoZdV3b1/4Sa2+8dP8Z0nR0wRBTEcNtnKMDFATpaZ863+hF1DvgEHRPyRLcMxA83Kxa
         Vsbg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:content-transfer-encoding:content-language
         :accept-language:in-reply-to:references:message-id:date:thread-index
         :thread-topic:subject:cc:to:from;
        bh=HS3rgCTcUBGA3GSzjIn6S0hJn8+CeEs0fnd/DgJ0bjI=;
        fh=UBxxb/en1S5oSuoRsEG6kMUoYYbr6bJ8L0ujMXafzXw=;
        b=C4Eb5rQbNQ0zs4FunuvodiusBkbGvZthH5kDSlMY2lDC2pyEC7msrUls9GygptkriD
         KtGGKiwoDe26OXZiljPy3i4GrDjtE5ogrJY+6LaPVMymXdqLj7HnWNzR8bvsY3SCHLx1
         w6mDNsFoHvx3eRNNuU0yF4BiePVbHKTSfjm7uOT8wqm/Rb55wSpJYvWErtuk+gL4TbWc
         njfMuImhIiLT6dSyeGkQSpR3yQRefYE8nBcVtWKWdntPVtBzmgNVHen27QQbcxkw3vWE
         zk1co+XnO/mq/peYs73frpg7OD+OI0+PeL/iki9G5zJfrb975qE4YfhfHkYTGYs34gGv
         z7oA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of haiyan.liu@unisoc.com designates 222.66.158.135 as permitted sender) smtp.mailfrom=haiyan.liu@unisoc.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=unisoc.com
Received: from SHSQR01.spreadtrum.com ([222.66.158.135])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-23de4254d1dsi7103665ad.1.2025.07.16.18.35.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 16 Jul 2025 18:35:42 -0700 (PDT)
Received-SPF: pass (google.com: domain of haiyan.liu@unisoc.com designates 222.66.158.135 as permitted sender) client-ip=222.66.158.135;
Received: from dlp.unisoc.com ([10.29.3.86])
	by SHSQR01.spreadtrum.com with ESMTP id 56H1Yk3W030475;
	Thu, 17 Jul 2025 09:34:46 +0800 (+08)
	(envelope-from haiyan.liu@unisoc.com)
Received: from SHDLP.spreadtrum.com (bjmbx01.spreadtrum.com [10.0.64.7])
	by dlp.unisoc.com (SkyGuard) with ESMTPS id 4bjFjY62kjz2K8r7c;
	Thu, 17 Jul 2025 09:30:25 +0800 (CST)
Received: from BJMBX01.spreadtrum.com (10.0.64.7) by BJMBX01.spreadtrum.com
 (10.0.64.7) with Microsoft SMTP Server (TLS) id 15.0.1497.48; Thu, 17 Jul
 2025 09:34:43 +0800
Received: from BJMBX01.spreadtrum.com ([fe80::54e:9a:129d:fac7]) by
 BJMBX01.spreadtrum.com ([fe80::54e:9a:129d:fac7%16]) with mapi id
 15.00.1497.048; Thu, 17 Jul 2025 09:34:43 +0800
From: =?UTF-8?B?J+WImOa1t+eHlSAoSGFpeWFuIExpdSknIHZpYSBrYXNhbi1kZXY=?= <kasan-dev@googlegroups.com>
To: Carlos Llamas <cmllamas@google.com>, Alice Ryhl <aliceryhl@google.com>,
        Matthew Maurer <mmaurer@google.com>
CC: Miguel Ojeda <miguel.ojeda.sandonis@gmail.com>,
        Miguel Ojeda
	<ojeda@kernel.org>,
        =?utf-8?B?5ZGo5bmzIChQaW5nIFpob3UvOTAzMik=?=
	<Ping.Zhou1@unisoc.com>,
        =?utf-8?B?5Luj5a2Q5Li6IChaaXdlaSBEYWkp?=
	<Ziwei.Dai@unisoc.com>,
        =?utf-8?B?5p2o5Li95aicIChMaW5hIFlhbmcp?=
	<lina.yang@unisoc.com>,
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
        Suren Baghdasaryan <surenb@google.com>,
        "Jamie
 Cunliffe" <Jamie.Cunliffe@arm.com>,
        Catalin Marinas <catalin.marinas@arm.com>
Subject: =?utf-8?B?562U5aSNOiBNZWV0IGNvbXBpbGVkIGtlcm5lbCBiaW5hcmF5IGFibm9ybWFs?=
 =?utf-8?B?IGlzc3VlIHdoaWxlIGVuYWJsaW5nIGdlbmVyaWMga2FzYW4gaW4ga2VybmVs?=
 =?utf-8?Q?_6.12_with_some_default_KBUILD=5FRUSTFLAGS_on?=
Thread-Topic: Meet compiled kernel binaray abnormal issue while enabling
 generic kasan in kernel 6.12 with some default KBUILD_RUSTFLAGS on
Thread-Index: Adv0awkF3quLQs5+RfaRTr3Yr7SnUQATGr8AACy4DEAAAOVlAAAqFjnwAAlHT4AAH7HjQA==
Date: Thu, 17 Jul 2025 01:34:43 +0000
Message-ID: <7afa22cbbb85481cbb3fabb09a58bd63@BJMBX01.spreadtrum.com>
References: <4c459085b9ae42bdbf99b6014952b965@BJMBX01.spreadtrum.com>
 <202507150830.56F8U908028199@SHSPAM01.spreadtrum.com>
 <c34f4f606eb04c38b64e8f3a658cd051@BJMBX01.spreadtrum.com>
 <CANiq72=v6jkOasLiem7RXe-WUSg9PkNqrZneeMOTi1pzwXuHYg@mail.gmail.com>
 <24e87f60203c443abe7549ce5c0e9e75@BJMBX01.spreadtrum.com>
 <aHftocnJcLg64c29@google.com>
In-Reply-To: <aHftocnJcLg64c29@google.com>
Accept-Language: zh-CN, en-US
Content-Language: zh-CN
X-MS-Has-Attach: 
X-MS-TNEF-Correlator: 
x-ms-exchange-transport-fromentityheader: Hosted
x-originating-ip: [10.0.93.65]
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
MIME-Version: 1.0
X-MAIL: SHSQR01.spreadtrum.com 56H1Yk3W030475
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
> =E5=8F=91=E4=BB=B6=E4=BA=BA: Carlos Llamas <cmllamas@google.com>
> =E5=8F=91=E9=80=81=E6=97=B6=E9=97=B4: 2025=E5=B9=B47=E6=9C=8817=E6=97=A5 =
2:21
> =E6=94=B6=E4=BB=B6=E4=BA=BA: =E5=88=98=E6=B5=B7=E7=87=95 (Haiyan Liu) <ha=
iyan.liu@unisoc.com>; Alice Ryhl <aliceryhl@google.com>; Matthew Maurer <mm=
aurer@google.com>
> =E6=8A=84=E9=80=81: Miguel Ojeda <miguel.ojeda.sandonis@gmail.com>; Migue=
l Ojeda <ojeda@kernel.org>; =E5=91=A8=E5=B9=B3 (Ping Zhou/9032)
> <Ping.Zhou1@unisoc.com>; =E4=BB=A3=E5=AD=90=E4=B8=BA (Ziwei Dai) <Ziwei.D=
ai@unisoc.com>; =E6=9D=A8=E4=B8=BD=E5=A8=9C (Lina Yang) <lina.yang@unisoc.c=
om>;
> linux-arm-kernel@lists.infradead.org; linux-kernel@vger.kernel.org; rust-=
for-linux@vger.kernel.org; =E7=8E=8B=E5=8F=8C (Shuang Wang)
> <shuang.wang@unisoc.com>; Andrey Ryabinin <ryabinin.a.a@gmail.com>; Alexa=
nder Potapenko <glider@google.com>; Andrey Konovalov
> <andreyknvl@gmail.com>; Dmitry Vyukov <dvyukov@google.com>; Vincenzo Fras=
cino <vincenzo.frascino@arm.com>;
> kasan-dev@googlegroups.com; Greg Kroah-Hartman <gregkh@linuxfoundation.or=
g>; Arve Hj=C3=B8nnev=C3=A5g <arve@android.com>; Todd Kjos
> <tkjos@android.com>; Martijn Coenen <maco@android.com>; Joel Fernandes <j=
oelagnelf@nvidia.com>; Christian Brauner
> <christian@brauner.io>; Suren Baghdasaryan <surenb@google.com>; Jamie Cun=
liffe <Jamie.Cunliffe@arm.com>; Catalin Marinas
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
> On Wed, Jul 16, 2025 at 07:01:29AM +0000, =E5=88=98=E6=B5=B7=E7=87=95 (Ha=
iyan Liu) wrote:
> >
> >
> > > -----=E9=82=AE=E4=BB=B6=E5=8E=9F=E4=BB=B6-----
> > > =E5=8F=91=E4=BB=B6=E4=BA=BA: Miguel Ojeda <miguel.ojeda.sandonis@gmai=
l.com>
> > > =E5=8F=91=E9=80=81=E6=97=B6=E9=97=B4: 2025=E5=B9=B47=E6=9C=8816=E6=97=
=A5 1:51
> > > =E6=94=B6=E4=BB=B6=E4=BA=BA: =E5=88=98=E6=B5=B7=E7=87=95 (Haiyan Liu)=
 <haiyan.liu@unisoc.com>
> > > =E6=8A=84=E9=80=81: Miguel Ojeda <ojeda@kernel.org>; =E5=91=A8=E5=B9=
=B3 (Ping Zhou/9032)
> > > <Ping.Zhou1@unisoc.com>; =E4=BB=A3=E5=AD=90=E4=B8=BA (Ziwei Dai) <Ziw=
ei.Dai@unisoc.com>; =E6=9D=A8=E4=B8=BD=E5=A8=9C
> > > (Lina Yang) <lina.yang@unisoc.com>;
> > > linux-arm-kernel@lists.infradead.org;
> > > linux-kernel@vger.kernel.org; rust-for-linux@vger.kernel.org; =E7=8E=
=8B=E5=8F=8C
> > > (Shuang Wang) <shuang.wang@unisoc.com>; Andrey Ryabinin
> > > <ryabinin.a.a@gmail.com>; Alexander Potapenko <glider@google.com>;
> > > Andrey Konovalov <andreyknvl@gmail.com>; Dmitry Vyukov
> > > <dvyukov@google.com>; Vincenzo Frascino <vincenzo.frascino@arm.com>;
> > > kasan-dev@googlegroups.com; Greg Kroah-Hartman
> > > <gregkh@linuxfoundation.org>; Arve Hj=C3=B8nnev=C3=A5g <arve@android.=
com>;
> > > Todd Kjos <tkjos@android.com>; Martijn Coenen <maco@android.com>;
> > > Joel Fernandes <joelagnelf@nvidia.com>; Christian Brauner
> > > <christian@brauner.io>; Carlos Llamas <cmllamas@google.com>; Suren
> > > Baghdasaryan <surenb@google.com>; Jamie Cunliffe
> > > <Jamie.Cunliffe@arm.com>; Catalin Marinas <catalin.marinas@arm.com>
> > > =E4=B8=BB=E9=A2=98: Re: Meet compiled kernel binaray abnormal issue w=
hile enabling
> > > generic kasan in kernel 6.12 with some default KBUILD_RUSTFLAGS on
> > >
> > >
> > > =E6=B3=A8=E6=84=8F: =E8=BF=99=E5=B0=81=E9=82=AE=E4=BB=B6=E6=9D=A5=E8=
=87=AA=E4=BA=8E=E5=A4=96=E9=83=A8=E3=80=82=E9=99=A4=E9=9D=9E=E4=BD=A0=E7=A1=
=AE=E5=AE=9A=E9=82=AE=E4=BB=B6=E5=86=85=E5=AE=B9=E5=AE=89=E5=85=A8=EF=BC=8C=
=E5=90=A6=E5=88=99=E4=B8=8D=E8=A6=81=E7=82=B9=E5=87=BB=E4=BB=BB=E4=BD=95=E9=
=93=BE=E6=8E=A5=E5=92=8C=E9=99=84=E4=BB=B6=E3=80=82
> > > CAUTION: This email originated from outside of the organization. Do
> > > not click links or open attachments unless you recognize the sender a=
nd know the content is safe.
> > >
> > >
> > >
> > > On Tue, Jul 15, 2025 at 11:41=E2=80=AFAM =E5=88=98=E6=B5=B7=E7=87=95 =
(Haiyan Liu) <haiyan.liu@unisoc.com> wrote:
> > > >
> > > > The commit changes the fragment and diff is:
> > >
> > > An Android engineer should know how to handle that, but if you are
> > > reporting upstream, it is best to try to reproduce the issue with the=
 upstream kernels (e.g. arm64 is not in 6.6.y) and provide the full
> kernel config used.
> > >
> > > > Only two rust-related global variables in fmr.rs and layout.rs have=
 this issue. Their asan.module_ctor complied binaries are wrong.
> > >
> > > I am not sure what you mean by `fmr.rs`. As for `layout.rs`, that is
> > > in the `kernel` crate in 6.12.y -- isn't there a single `asan.module_=
ctor` per TU? Which object file are you referring to? I get the pair for
> my `rust/kernel.o`.
> >
> >   NSX:FFFFFFC0800A7C94|F800865E  asan.module_ctor:   str     x30,[x18],=
#0x8   ; x30,[x18],#8
> >    NSX:FFFFFFC0800A7C98|F81F0FFE                      str     x30,[sp,#=
-0x10]!   ; x30,[sp,#-16]!
> >    NSX:FFFFFFC0800A7C9C|F00240A0                      adrp    x0,0xFFFF=
FFC0848BE000
> >    NSX:FFFFFFC0800A7CA0|911D8000                      add     x0,x0,#0x=
760     ; x0,x0,#1888
> >    NSX:FFFFFFC0800A7CA4|52803D61                      mov     w1,#0x1EB=
        ; w1,#491
> >    NSX:FFFFFFC0800A7CA8|94233816                      bl      0xFFFFFFC=
080975D00   ; __asan_register_globals
> >    NSX:FFFFFFC0800A7CAC|F84107FE                      ldr     x30,[sp],=
#0x10   ; x30,[sp],#16
> >    NSX:FFFFFFC0800A7CB0|D50323BF                      autiasp
> >    NSX:FFFFFFC0800A7CB4|D65F03C0                      ret
> > The first __asan_global struct value is
> >  ENAXI:FFFFFFC0848BE760|>FFFFFFC082EDB180 000000000000005F ........_...=
....
> >  ENAXI:FFFFFFC0848BE770| 0000000000000080 FFFFFFC0836DC431 ........1.m.=
....
> >  ENAXI:FFFFFFC0848BE780| FFFFFFC082EEC780 0000000000000000 ............=
....
> >  ENAXI:FFFFFFC0848BE790| 0000000000000000 FFFFFFFFFFFFFFFF ............=
....
> > The address of the global is 0xFFFFFFC082EDB180 which value is
> '/proc/self/cwd/prebuilts/rust/linux-x86/1.82.0/lib/rustlib/src/rust/libr=
ary/core/src/num/fmt.rs' and its viewinfo is
> 'vmlinux\Global\__unnamed_357'
> > The original size of the global is 0x5F The name of the global is
> > kmalloc-2k The module name of the global is
> > 'core.27758904ccee4c80-cgu.o'
> >
> >    NSX:FFFFFFC0800A7D4C|F800865E  asan.mod.:str     x30,[x18],#0x8   ; =
x30,[x18],#8
> >    NSX:FFFFFFC0800A7D50|F81F0FFE            str     x30,[sp,#-0x10]!   =
; x30,[sp,#-16]!
> >    NSX:FFFFFFC0800A7D54|F00240E0            adrp    x0,0xFFFFFFC0848C60=
00
> >    NSX:FFFFFFC0800A7D58|912E8000            add     x0,x0,#0xBA0     ; =
x0,x0,#2976
> >    NSX:FFFFFFC0800A7D5C|52800961            mov     w1,#0x4B         ; =
w1,#75
> >    NSX:FFFFFFC0800A7D60|942337E8            bl      0xFFFFFFC080975D00 =
  ; __asan_register_globals
> >    NSX:FFFFFFC0800A7D64|F84107FE            ldr     x30,[sp],#0x10   ; =
x30,[sp],#16
> >    NSX:FFFFFFC0800A7D68|D50323BF            autiasp
> >    NSX:FFFFFFC0800A7D6C|D65F03C0            ret
> > The second __asan_global struct value is
> >    NSD:FFFFFFC0848C6BA0|>FFFFFFC082EECA80 0000000000000020 ........ ...=
....
> >    NSD:FFFFFFC0848C6BB0| 0000000000000040 FFFFFFC0836DC431 @.......1.m.=
....
> >    NSD:FFFFFFC0848C6BC0| FFFFFFC082EEDA80 0000000000000000 ............=
....
> >    NSD:FFFFFFC0848C6BD0| 0000000000000000 FFFFFFFFFFFFFFFF ............=
....
> > The address of the global is 0xFFFFFFC082EECA80 which value is 0 and it=
s viewinfo is
> '<&usize_as_core::f..vmlinux\kernel_9a6cb9fd7c8dfd66_cgu\<&usize_as_core:=
:fmt::Debug>::{vtable}'
> > The original size of the global is 0x20 The name of the global is
> > kmalloc-2k The module name of the global is
> > 'kernel.9a6cb9fd7c8dfd66-cgu.o'
> >
> > > Cheers,
> > > Miguel
>=20
> We have KASAN builds with android16-6.12 and haven't seen this issue.
> Can you share your entire config file, so we can try to reproduce?

The config file is included in the compressed file kernel_artifacts.tgz whi=
ch can get from ' http://artifactory.unisoc.com/ui/native/VERIFY_ANDROID/17=
46740/PAC/sprdroid15_sys_dev_plus_sprdroid15_vnd_dev_plus_sprdlinux6.12_ker=
nel_dev/ums9632_1h10_64only_k612-userdebug-gms/sprdlinux6.12_kernel_dev/ums=
9632_1h10_64only_k612-userdebug/' . The path is 'kernel_artifacts/ums9632_a=
rm64_kernel6.12-userdebug/kernel'.

Can you get it?

> Cc: Alice Ryhl <aliceryhl@google.com>
> Cc: Matthew Maurer <mmaurer@google.com>
>=20
> Alice, Matthew, have you seen this before?
>=20
> --
> Carlos Llamas

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/7=
afa22cbbb85481cbb3fabb09a58bd63%40BJMBX01.spreadtrum.com.
