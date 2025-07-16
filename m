Return-Path: <kasan-dev+bncBCR4POPXZYBRBKW337BQMGQEXVLWDPI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x38.google.com (mail-oa1-x38.google.com [IPv6:2001:4860:4864:20::38])
	by mail.lfdr.de (Postfix) with ESMTPS id E34FAB07CAD
	for <lists+kasan-dev@lfdr.de>; Wed, 16 Jul 2025 20:21:32 +0200 (CEST)
Received: by mail-oa1-x38.google.com with SMTP id 586e51a60fabf-2f3b98b0f9esf183333fac.0
        for <lists+kasan-dev@lfdr.de>; Wed, 16 Jul 2025 11:21:32 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1752690091; cv=pass;
        d=google.com; s=arc-20240605;
        b=jmHmmyep83eGPatMxWSbPQE+Y0CbqVbcwccRK72SGPwjbK3NBmNA8oE1/Eo1T0JEEX
         LdkFMgIdR3P8zkg8rdW6j5kXD09WYqOhbKV8YaAvjIYGbL8S68U8lB4L7jAvKxz2GduN
         PQlDgT1AuBqjM9Fr0cgU9awC3psvvZJamqlpfxjEKbSd5hKFYyaoJXDicwW1IjUqhIM2
         ZkSzh0CzSj5FIFz3fO3c9GN/OnI4Vd1C2Ff+hIfxDLnBT3zzUrRNpx3k/pbf2jUNmZgN
         tYWAteNxt/IR0SwYqfvRSlNWi0PzrFkqcbMJmnmlr3yOHJk/2ecXvf/q/T71RPcLlQEP
         UzHA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:dkim-signature;
        bh=LF0kvws+e7FX4fMc/nxEUbA4q2WZvX41utvS2aKHA+U=;
        fh=id3sYmGnijtfILLcIJSROCQcOJ8HxO540EQ5IlDcKRc=;
        b=YXOLHqLzwaZj14vB8Zb6Tv/YZ023zDLOv3sLeAv/Y3PDRE0Lvr7BZX/4l0yXqYaXaG
         e/shfxxM5UsW/yZarwNdrkf4B3i0mS0JsX845UtmDBgFB9y+tf+F/luCX1gSg3hj2p3Y
         QVBfWCi14h9JcgjQYnEaiS8/K45JMrOY8BBSjGbaDiTQb4hiyqt3PyBR8PqRj62Rv3Tn
         inZJMhpZ3HAej9Nnz1RQiEhO85zcdDyc4ZZlEg+liT+Prvcu+xW8Io2LdvuE8rNuL0fL
         zCHfUeECfQAicYck9MqlNVSwJ64P9jYC22Od75/DwzPZoWRgLmhSPQota93ar2DL+X1g
         Ghpg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=GfcpDp6g;
       spf=pass (google.com: domain of cmllamas@google.com designates 2607:f8b0:4864:20::630 as permitted sender) smtp.mailfrom=cmllamas@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1752690091; x=1753294891; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:from:to:cc:subject
         :date:message-id:reply-to;
        bh=LF0kvws+e7FX4fMc/nxEUbA4q2WZvX41utvS2aKHA+U=;
        b=ufoPFUQHZAn/7v07km7dFw9h1LKYr6M96pNZAyn/BE2BnwUVq15D6NEk74eC4eIdNH
         N6RjZfCY6YWu0zKRiWKaJrr2LgBAJRBZoJGMXPvAG6mVKAp/6dypp1xpPoqP5rSde1+5
         WeSpVOLAM/R2O7ZQbveIXP9ZuSTlGIqpHqH7ATF6fGRN9gHm+bATuRTYbhhEPd1K6sId
         S0nYZxaY+pRaS4VBKro9pHlvZdqc2kGCuoe3dWu7Nv9jB0ZQ1ixKjFxszaQifoe4MtgP
         yqxYV8eTfEQndA9at3i0MBMltXidoig5WDQ9orM2W7a2G2dGZTOP/FyMH/JDegRg2Xwj
         ++9Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1752690091; x=1753294891;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=LF0kvws+e7FX4fMc/nxEUbA4q2WZvX41utvS2aKHA+U=;
        b=pNGI73qEAwLyb8N8adT+NQfWWEE2wFa5/EBV3Ggww9CrW8wpFoAjUzETUl7POknW8i
         Jla3Y8LzUxmjbDRHOrbzmaHS1isUMKOYp+GhgUqJhZvBBB4sF1kUoqyyvTkMJlDRHJC6
         uIr5tFPtlaUnI7+U9ovCb2zbit4f7vXu/k0wczoQRolMuKXs7izQxtn1z++izwzc9O9u
         6RaIDDaWmjRKSwjF04F2MgCZFJoDRsOEZ/wWMr2PvObn2JzHudhMbWlhvTfMtJJjgpKZ
         UagJQ25FtWo+CKg0KK+wDb9lTBTiHBsUNcellmgWxxPAn6HKWSG2zn4FXmtT7E2rMuli
         8wnQ==
X-Forwarded-Encrypted: i=2; AJvYcCXu/+XVpes+Tg/L8NnFhFc/TI7nSu2yR9OGFjygJ0v94Leke0vzWVVOgR7RkO1IGY4mFwlTDw==@lfdr.de
X-Gm-Message-State: AOJu0Yx7GUp00QsPRdpqOx31cAhVfMppKYrAL8Hxebd4QTsY5SoIDDk1
	HOAB3GWGoJ5pN8XY51jJMMtPJXjhLuuthJ37UIPAYeTgQ40vF/5xyVyT
X-Google-Smtp-Source: AGHT+IF3wZSzIFMrcrl3JhrLz9KRSUpd5aWfPs3WwwKPK6/MsNUPNIOS9ZB50UMJLtu5OrL5agFpmQ==
X-Received: by 2002:a05:6871:4d4:b0:2ff:9280:83db with SMTP id 586e51a60fabf-2ffaf22eacamr3695752fac.6.1752690090995;
        Wed, 16 Jul 2025 11:21:30 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZe4GMV9MH735xweefCLJZfIQn/CRZ58m3nM/8B46ryf9A==
Received: by 2002:a05:6870:1098:b0:2ff:8cdd:54b9 with SMTP id
 586e51a60fabf-2ffca94ff47ls65706fac.1.-pod-prod-02-us; Wed, 16 Jul 2025
 11:21:30 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXiXsqRKCRyZu9DFlZ3EsISO4BZ6RIf5zcJf8konij+aHNVzbV6zzCniZwRjtcelDuGMAEq0eTtJ9w=@googlegroups.com
X-Received: by 2002:a05:6808:6f81:b0:40d:547d:397 with SMTP id 5614622812f47-41cefb184ebmr2957054b6e.23.1752690089920;
        Wed, 16 Jul 2025 11:21:29 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1752690089; cv=none;
        d=google.com; s=arc-20240605;
        b=QeYe+dUK+tZGydFhcthg5nt3EG8ZyhceWinXfLJemVFL3WFV5vw19c6/ANKE9WiEQZ
         79vPrEyQnZEVaDhz4WvpbimJ814j6VUEdekimkWu+pB3G3Yllc6wOAonDZC35xNwZ39B
         sXgQBwvNXtwtMj60LdWQkquGSGJ67Q33b9R8aDbQZF4ycqvQhRjxLaZtKrpk4emoQhVZ
         d7u2j9JnO3lpbRtRX1oEUZgACsiQq+M7K01FqFkgYEYy/JrKhBTBmpBt17+Oa82LvLRF
         VUZstms+8P/CE/NqI/TQEPCyIHEbhY1umzTKDF/akm2xTd+5TjmFV3bNWGuGE8vxz5NI
         QR8g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=XqYy+Dz+71twI0him0hUjZk/6GLWJWbYmCSfdczxwFc=;
        fh=UKIjBYEJxbK/FDzWMfU890+sKkMbMQXfaVruKDVkHJo=;
        b=RpXQFswaK5cIcVWUexsW6uRi8y2qCXXRlL6d3M7BFwFmPnQXnElwcVGDczT2m65n9M
         z7ClmvBRWQkmOR1uPVDVIaCbHw8JM2rtAC6KqdKtbzx0FECZSmGBrdbqnemte5xmlJQw
         J18Zhrz+iMdI/hD7yzNT4yWuZu0CR1vkEo+KXbs3kXP5qfBrTuhCJ0qVxLmf6DEqwwWQ
         UOfxfFlV9ztTMV1Jf3tVxsbJyNyN91X/xcMtCiIwJWmat8ATBxdU77wQCUS76bIoJMjD
         MbS78mr4krFuyRYvmsrmTsJDGHhI6hg98hKTa5rI8Przah+LTJ0p0R4Y39EuJmnMhgff
         s7nA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=GfcpDp6g;
       spf=pass (google.com: domain of cmllamas@google.com designates 2607:f8b0:4864:20::630 as permitted sender) smtp.mailfrom=cmllamas@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pl1-x630.google.com (mail-pl1-x630.google.com. [2607:f8b0:4864:20::630])
        by gmr-mx.google.com with ESMTPS id 5614622812f47-41cfa50c87csi117715b6e.2.2025.07.16.11.21.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 16 Jul 2025 11:21:29 -0700 (PDT)
Received-SPF: pass (google.com: domain of cmllamas@google.com designates 2607:f8b0:4864:20::630 as permitted sender) client-ip=2607:f8b0:4864:20::630;
Received: by mail-pl1-x630.google.com with SMTP id d9443c01a7336-237f18108d2so28425ad.0
        for <kasan-dev@googlegroups.com>; Wed, 16 Jul 2025 11:21:29 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXiG2l/P+azGjBKghE4o+sXW1bQ2vd+oVjemBTXeTJUdtk00bA9DHigQt7fsKNK5MYyy2daN5zNFXk=@googlegroups.com
X-Gm-Gg: ASbGncv9evbSbSQY/+ogNWEP2T8ppGpjm55eN//BDC86Dcota9BknQTPk2/CAJqRi7D
	phQXCoHXa0JVlaTcpTL0VZP+FrHpQHWwH3Y0y/io1lYmwiKaM+gb8tfQzAl7YiewlRbLdFLSmaf
	D2loWWwnm3MW2eDoM6LBYWY+W/+VycPf/YWQ3wazUCebu7b6kKjVBewyfERxXtDrKjyHgUAVOqx
	+mNLr6g0e85Yg1Ju1e3w6CwoJ6fQBw9ZkGjZA0Lzd89Skb/YDt/qc4xBIFcgpfGU9xTfBJYnKyK
	20lB13pNK4V09AGEmxCW16cZCjk+Aic92f1NwywYHsvvkL9LNXYSfxiRAam2u6OYC7ncxR/T16f
	OPCPIeOG+wbLoCnCtVfYhQzJUUafPl7+JBmM3Q6i5Li9wypuuYyy7X4ncv9cVXT8=
X-Received: by 2002:a17:903:3b8e:b0:231:ddc9:7b82 with SMTP id d9443c01a7336-23e2ffdd014mr186685ad.13.1752690088747;
        Wed, 16 Jul 2025 11:21:28 -0700 (PDT)
Received: from google.com (135.228.125.34.bc.googleusercontent.com. [34.125.228.135])
        by smtp.gmail.com with ESMTPSA id 98e67ed59e1d1-31ca786eac1sm1153352a91.48.2025.07.16.11.21.25
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 16 Jul 2025 11:21:27 -0700 (PDT)
Date: Wed, 16 Jul 2025 18:21:21 +0000
From: "'Carlos Llamas' via kasan-dev" <kasan-dev@googlegroups.com>
To: =?utf-8?B?5YiY5rW354eVIChIYWl5YW4gTGl1KQ==?= <haiyan.liu@unisoc.com>,
	Alice Ryhl <aliceryhl@google.com>,
	Matthew Maurer <mmaurer@google.com>
Cc: Miguel Ojeda <miguel.ojeda.sandonis@gmail.com>,
	Miguel Ojeda <ojeda@kernel.org>,
	=?utf-8?B?5ZGo5bmzIChQaW5nIFpob3UvOTAzMik=?= <Ping.Zhou1@unisoc.com>,
	=?utf-8?B?5Luj5a2Q5Li6IChaaXdlaSBEYWkp?= <Ziwei.Dai@unisoc.com>,
	=?utf-8?B?5p2o5Li95aicIChMaW5hIFlhbmcp?= <lina.yang@unisoc.com>,
	"linux-arm-kernel@lists.infradead.org" <linux-arm-kernel@lists.infradead.org>,
	"linux-kernel@vger.kernel.org" <linux-kernel@vger.kernel.org>,
	"rust-for-linux@vger.kernel.org" <rust-for-linux@vger.kernel.org>,
	=?utf-8?B?546L5Y+MIChTaHVhbmcgV2FuZyk=?= <shuang.wang@unisoc.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	"kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>,
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
	Arve =?iso-8859-1?B?SGr4bm5lduVn?= <arve@android.com>,
	Todd Kjos <tkjos@android.com>, Martijn Coenen <maco@android.com>,
	Joel Fernandes <joelagnelf@nvidia.com>,
	Christian Brauner <christian@brauner.io>,
	Suren Baghdasaryan <surenb@google.com>,
	Jamie Cunliffe <Jamie.Cunliffe@arm.com>,
	Catalin Marinas <catalin.marinas@arm.com>
Subject: Re: Meet compiled kernel binaray abnormal issue while enabling
 generic kasan in kernel 6.12 with some default KBUILD_RUSTFLAGS on
Message-ID: <aHftocnJcLg64c29@google.com>
References: <4c459085b9ae42bdbf99b6014952b965@BJMBX01.spreadtrum.com>
 <202507150830.56F8U908028199@SHSPAM01.spreadtrum.com>
 <c34f4f606eb04c38b64e8f3a658cd051@BJMBX01.spreadtrum.com>
 <CANiq72=v6jkOasLiem7RXe-WUSg9PkNqrZneeMOTi1pzwXuHYg@mail.gmail.com>
 <24e87f60203c443abe7549ce5c0e9e75@BJMBX01.spreadtrum.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <24e87f60203c443abe7549ce5c0e9e75@BJMBX01.spreadtrum.com>
X-Original-Sender: cmllamas@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=GfcpDp6g;       spf=pass
 (google.com: domain of cmllamas@google.com designates 2607:f8b0:4864:20::630
 as permitted sender) smtp.mailfrom=cmllamas@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
X-Original-From: Carlos Llamas <cmllamas@google.com>
Reply-To: Carlos Llamas <cmllamas@google.com>
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

On Wed, Jul 16, 2025 at 07:01:29AM +0000, =E5=88=98=E6=B5=B7=E7=87=95 (Haiy=
an Liu) wrote:
>=20
>=20
> > -----=E9=82=AE=E4=BB=B6=E5=8E=9F=E4=BB=B6-----
> > =E5=8F=91=E4=BB=B6=E4=BA=BA: Miguel Ojeda <miguel.ojeda.sandonis@gmail.=
com>
> > =E5=8F=91=E9=80=81=E6=97=B6=E9=97=B4: 2025=E5=B9=B47=E6=9C=8816=E6=97=
=A5 1:51
> > =E6=94=B6=E4=BB=B6=E4=BA=BA: =E5=88=98=E6=B5=B7=E7=87=95 (Haiyan Liu) <=
haiyan.liu@unisoc.com>
> > =E6=8A=84=E9=80=81: Miguel Ojeda <ojeda@kernel.org>; =E5=91=A8=E5=B9=B3=
 (Ping Zhou/9032) <Ping.Zhou1@unisoc.com>; =E4=BB=A3=E5=AD=90=E4=B8=BA (Ziw=
ei Dai)
> > <Ziwei.Dai@unisoc.com>; =E6=9D=A8=E4=B8=BD=E5=A8=9C (Lina Yang) <lina.y=
ang@unisoc.com>; linux-arm-kernel@lists.infradead.org;
> > linux-kernel@vger.kernel.org; rust-for-linux@vger.kernel.org; =E7=8E=8B=
=E5=8F=8C (Shuang Wang) <shuang.wang@unisoc.com>; Andrey Ryabinin
> > <ryabinin.a.a@gmail.com>; Alexander Potapenko <glider@google.com>; Andr=
ey Konovalov <andreyknvl@gmail.com>; Dmitry Vyukov
> > <dvyukov@google.com>; Vincenzo Frascino <vincenzo.frascino@arm.com>; ka=
san-dev@googlegroups.com; Greg Kroah-Hartman
> > <gregkh@linuxfoundation.org>; Arve Hj=C3=B8nnev=C3=A5g <arve@android.co=
m>; Todd Kjos <tkjos@android.com>; Martijn Coenen
> > <maco@android.com>; Joel Fernandes <joelagnelf@nvidia.com>; Christian B=
rauner <christian@brauner.io>; Carlos Llamas
> > <cmllamas@google.com>; Suren Baghdasaryan <surenb@google.com>; Jamie Cu=
nliffe <Jamie.Cunliffe@arm.com>; Catalin Marinas
> > <catalin.marinas@arm.com>
> > =E4=B8=BB=E9=A2=98: Re: Meet compiled kernel binaray abnormal issue whi=
le enabling generic kasan in kernel 6.12 with some default KBUILD_RUSTFLAGS
> > on
> >=20
> >=20
> > =E6=B3=A8=E6=84=8F: =E8=BF=99=E5=B0=81=E9=82=AE=E4=BB=B6=E6=9D=A5=E8=87=
=AA=E4=BA=8E=E5=A4=96=E9=83=A8=E3=80=82=E9=99=A4=E9=9D=9E=E4=BD=A0=E7=A1=AE=
=E5=AE=9A=E9=82=AE=E4=BB=B6=E5=86=85=E5=AE=B9=E5=AE=89=E5=85=A8=EF=BC=8C=E5=
=90=A6=E5=88=99=E4=B8=8D=E8=A6=81=E7=82=B9=E5=87=BB=E4=BB=BB=E4=BD=95=E9=93=
=BE=E6=8E=A5=E5=92=8C=E9=99=84=E4=BB=B6=E3=80=82
> > CAUTION: This email originated from outside of the organization. Do not=
 click links or open attachments unless you recognize the sender
> > and know the content is safe.
> >=20
> >=20
> >=20
> > On Tue, Jul 15, 2025 at 11:41=E2=80=AFAM =E5=88=98=E6=B5=B7=E7=87=95 (H=
aiyan Liu) <haiyan.liu@unisoc.com> wrote:
> > >
> > > The commit changes the fragment and diff is:
> >=20
> > An Android engineer should know how to handle that, but if you are repo=
rting upstream, it is best to try to reproduce the issue with the
> > upstream kernels (e.g. arm64 is not in 6.6.y) and provide the full kern=
el config used.
> >=20
> > > Only two rust-related global variables in fmr.rs and layout.rs have t=
his issue. Their asan.module_ctor complied binaries are wrong.
> >=20
> > I am not sure what you mean by `fmr.rs`. As for `layout.rs`, that is in=
 the `kernel` crate in 6.12.y -- isn't there a single `asan.module_ctor`
> > per TU? Which object file are you referring to? I get the pair for my `=
rust/kernel.o`.
>=20
>   NSX:FFFFFFC0800A7C94|F800865E  asan.module_ctor:   str     x30,[x18],#0=
x8   ; x30,[x18],#8
>    NSX:FFFFFFC0800A7C98|F81F0FFE                      str     x30,[sp,#-0=
x10]!   ; x30,[sp,#-16]!
>    NSX:FFFFFFC0800A7C9C|F00240A0                      adrp    x0,0xFFFFFF=
C0848BE000
>    NSX:FFFFFFC0800A7CA0|911D8000                      add     x0,x0,#0x76=
0     ; x0,x0,#1888
>    NSX:FFFFFFC0800A7CA4|52803D61                      mov     w1,#0x1EB  =
      ; w1,#491
>    NSX:FFFFFFC0800A7CA8|94233816                      bl      0xFFFFFFC08=
0975D00   ; __asan_register_globals
>    NSX:FFFFFFC0800A7CAC|F84107FE                      ldr     x30,[sp],#0=
x10   ; x30,[sp],#16
>    NSX:FFFFFFC0800A7CB0|D50323BF                      autiasp
>    NSX:FFFFFFC0800A7CB4|D65F03C0                      ret
> The first __asan_global struct value is=20
>  ENAXI:FFFFFFC0848BE760|>FFFFFFC082EDB180 000000000000005F ........_.....=
..
>  ENAXI:FFFFFFC0848BE770| 0000000000000080 FFFFFFC0836DC431 ........1.m...=
..
>  ENAXI:FFFFFFC0848BE780| FFFFFFC082EEC780 0000000000000000 ..............=
..
>  ENAXI:FFFFFFC0848BE790| 0000000000000000 FFFFFFFFFFFFFFFF ..............=
..
> The address of the global is 0xFFFFFFC082EDB180 which value is '/proc/sel=
f/cwd/prebuilts/rust/linux-x86/1.82.0/lib/rustlib/src/rust/library/core/src=
/num/fmt.rs' and its viewinfo is 'vmlinux\Global\__unnamed_357'
> The original size of the global is 0x5F
> The name of the global is kmalloc-2k
> The module name of the global is 'core.27758904ccee4c80-cgu.o'
>=20
>    NSX:FFFFFFC0800A7D4C|F800865E  asan.mod.:str     x30,[x18],#0x8   ; x3=
0,[x18],#8
>    NSX:FFFFFFC0800A7D50|F81F0FFE            str     x30,[sp,#-0x10]!   ; =
x30,[sp,#-16]!
>    NSX:FFFFFFC0800A7D54|F00240E0            adrp    x0,0xFFFFFFC0848C6000
>    NSX:FFFFFFC0800A7D58|912E8000            add     x0,x0,#0xBA0     ; x0=
,x0,#2976
>    NSX:FFFFFFC0800A7D5C|52800961            mov     w1,#0x4B         ; w1=
,#75
>    NSX:FFFFFFC0800A7D60|942337E8            bl      0xFFFFFFC080975D00   =
; __asan_register_globals
>    NSX:FFFFFFC0800A7D64|F84107FE            ldr     x30,[sp],#0x10   ; x3=
0,[sp],#16
>    NSX:FFFFFFC0800A7D68|D50323BF            autiasp
>    NSX:FFFFFFC0800A7D6C|D65F03C0            ret
> The second __asan_global struct value is=20
>    NSD:FFFFFFC0848C6BA0|>FFFFFFC082EECA80 0000000000000020 ........ .....=
..
>    NSD:FFFFFFC0848C6BB0| 0000000000000040 FFFFFFC0836DC431 @.......1.m...=
..
>    NSD:FFFFFFC0848C6BC0| FFFFFFC082EEDA80 0000000000000000 ..............=
..
>    NSD:FFFFFFC0848C6BD0| 0000000000000000 FFFFFFFFFFFFFFFF ..............=
..
> The address of the global is 0xFFFFFFC082EECA80 which value is 0 and its =
viewinfo is '<&usize_as_core::f..vmlinux\kernel_9a6cb9fd7c8dfd66_cgu\<&usiz=
e_as_core::fmt::Debug>::{vtable}'
> The original size of the global is 0x20
> The name of the global is kmalloc-2k
> The module name of the global is 'kernel.9a6cb9fd7c8dfd66-cgu.o'
>=20
> > Cheers,
> > Miguel

We have KASAN builds with android16-6.12 and haven't seen this issue.
Can you share your entire config file, so we can try to reproduce?

Cc: Alice Ryhl <aliceryhl@google.com>
Cc: Matthew Maurer <mmaurer@google.com>

Alice, Matthew, have you seen this before?

--
Carlos Llamas

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/a=
HftocnJcLg64c29%40google.com.
