Return-Path: <kasan-dev+bncBCG5FM426MMRBGEN4DBQMGQE2ZJ673I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33e.google.com (mail-wm1-x33e.google.com [IPv6:2a00:1450:4864:20::33e])
	by mail.lfdr.de (Postfix) with ESMTPS id B331FB07E8C
	for <lists+kasan-dev@lfdr.de>; Wed, 16 Jul 2025 22:07:54 +0200 (CEST)
Received: by mail-wm1-x33e.google.com with SMTP id 5b1f17b1804b1-4561c67daebsf848975e9.1
        for <lists+kasan-dev@lfdr.de>; Wed, 16 Jul 2025 13:07:54 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1752696474; cv=pass;
        d=google.com; s=arc-20240605;
        b=KX0bDXmLw4yky4S0sdHt1biHSpmuTeOLJmHavXxGJOLaS2merB774FjVB33/plhKOU
         V7TIMWjt9A5yFvpuFyIZkG7FNhKF1HWoqvblxkC2sk25OSVTbGTPvb3uCTghbupHDevr
         KQmHDDoIB2Y3lZKHYt4DT9z41i8NFH1T2ROh1Gq96Wy5lP9QDnx3sxA8YcgB6UX6DLd/
         wmUq9GuQALNyimYHNxYYxJvg40apK5qvvT2Qc8hbVzkaJ3o1Fc6EJr5XOy4gniI0JBJh
         GPE8B0IMPZo7dY+PnvGwCygCWQDy3Gl9iWmf8VBvzOPGBASTjfh8Ytnld0xC3g5+YpTk
         WTHg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=nPR7ZnaL6UXhKAKBNqln2k7wr53jbfkbiFY8BjAYCuA=;
        fh=0BG/8PHaAJ4Rqz7g65w3IjrxfRlzr2y00UrZVF9VMl8=;
        b=QMVvbIbqoO05WRYIPa1VS7C+8fiLQoAvrYOTLwdGO0RXnACMO8hZmQL42CJuD9coIe
         iM92v+rI2coKwh5NrfTSiPuS36746DXuHf0aM8HAC1PhKIowqfuJy3UdAY4N2z3nhqX8
         a29gE3u2zQLP4lmhX09Q9vhlNPGHeC1rTGhd+uPr9e2xcIU7yoYRe3d4hh3NhfyZcj05
         LzPOqixyxsT1pIIfxJP3DM9Y7G/W0+YL2fnUPgJkgSkko7F/qWEB/4wbMeYd0RclKtxo
         yW7Rsg5eLh8/dJaNcZRdhvfVAVrelNqwMO4yL83k/1en/Ayg3mpCoHiRsT19+lFyY9Yf
         kEeQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=iVNbGYj3;
       spf=pass (google.com: domain of aliceryhl@google.com designates 2a00:1450:4864:20::430 as permitted sender) smtp.mailfrom=aliceryhl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1752696474; x=1753301274; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=nPR7ZnaL6UXhKAKBNqln2k7wr53jbfkbiFY8BjAYCuA=;
        b=i7NgsYU2LXR9Rk/y7m5xsuiB6UjN20PvAOhX0BFNX8RYgOc8EHjC3/VYdkMCxcze56
         hu5kId0INtH3iimwMi7fg6CLIQWV98acGYL/RR5cw5/AmGxHRhJngiDXlICXPO9Sw/5f
         APQ4Pwyu5vHOZ2UFT4nTgRtOsDr9U/APXz/a51ygeZDxibTPQypJx23kjdqjZnt+GpQb
         hIejScWFPHAnIDwDzlBg7aII35ylrG2bQPA+yKhYfsBzM8MNH8nMQGmhKIipCNdvqB6t
         4H555/AaedaKFYHyOW5sSNlebsZAloJ6w1XXFG91BV5KerthLENzOwdO/Ly4XmffgcHe
         O2JA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1752696474; x=1753301274;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=nPR7ZnaL6UXhKAKBNqln2k7wr53jbfkbiFY8BjAYCuA=;
        b=gCJpppAws/ZocBhdSfxzrWXl4/iAonf5z9I03Qu5WaHu4wdcVIBGljgA+3CdT9Q1pY
         YODVRe7snPEMJUCGC4r+qiOHsXq08CdW06rloWjd2CtvyEs8on1pEMf5ri4wXasvWmVe
         fFt7Q+RQz4dTIWAUeyQov05bzNP8OyqmtbNc1CTsusVCDpAu+va4C1w8qmJQFl5QpMwO
         frYiNqZHzppObY38X6FEZMOCtDu3NiX3byHLgReMP/Hee2tBo+saJZS89VHsu9UF+p5d
         dQLJBjQPTQuuQ/Ep5Cip41fLe/PMCQlmZBOcXlWA5ZiHXdvmDMSeevlYNx9cAl478Vgp
         NBrA==
X-Forwarded-Encrypted: i=2; AJvYcCUoiPj5pC1B9Y35c7JlUn7SJI1WimxhpXQYnRXz7ey1awWAQjn7NdWcIjT7H7HP+PvMJ8hKDQ==@lfdr.de
X-Gm-Message-State: AOJu0YzNXuHXlet4K9WqptUh+7Q8zOMEhBw5YRxtaJbRXGhqG2gdSs8J
	VBrnoD2NKwMkWChFvx1+SERMx9pS/Ou/zq03TUu2GNhoNNtImAHvLopt
X-Google-Smtp-Source: AGHT+IFsnZ+4EJiyFlL384+aTZUShAZp7tcL/VhkNzXCrq3YBDn5RW3X6OW9agy4VHFN3MuxRJ71aQ==
X-Received: by 2002:a05:600c:1ca4:b0:453:7713:476c with SMTP id 5b1f17b1804b1-4563477d563mr5895585e9.2.1752696473810;
        Wed, 16 Jul 2025 13:07:53 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfMVVQNmL0TMwSq0TdWffOtrZ2zhsdopx+4wrfU3XH/kQ==
Received: by 2002:a05:600c:8b2b:b0:456:2981:2aa with SMTP id
 5b1f17b1804b1-456340bf504ls1019035e9.0.-pod-prod-00-eu; Wed, 16 Jul 2025
 13:07:50 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCX4TJSHVxwpCxkdMPH5eI6oA8NQYe8cUh8GOA0XYJcVxl/QoWeYJxRVm9w5OANNY6E80KAeu0+jOxs=@googlegroups.com
X-Received: by 2002:a05:600c:37c8:b0:456:942:b162 with SMTP id 5b1f17b1804b1-456349c7cccmr4981535e9.11.1752696470365;
        Wed, 16 Jul 2025 13:07:50 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1752696470; cv=none;
        d=google.com; s=arc-20240605;
        b=bHr8OIAod4MAozYlcm36R+tgoPuObit4nUxFnx11JqEgTyj6LGdp1wTrAEVJpSuORw
         x5aFfEf6c++rJje2xKtVUYxfitIWirAqWX+1oIzU0HMROMzCdDpfeEBiFhoA8Z83nalE
         /0SXdd4yDTSbz3oMIRZUHpJvSoiEjG/scQhFiyx8YDpM84q2bHluFODpV+f6ow0XtCbN
         MHEPp8VgPw4X1f8q65wtlXnYtM7PNW1TQZ9BS0JxUEMailex2ABsS6n2ifJmO2nEbcXl
         BfkJRRkJUIEyuozR8xAQRPcaNmtMF0EuXUxPr9gRJhmG5mySfj7/WPJGzmdk80p4iTJY
         lVxA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=3YboiOBuuzvpNMxiBuKPw6BD6c8PklI5nO1wrPxXt8c=;
        fh=/ApH8qn3qOv++vFys0jOiifQFatModiHAaIb+azHtME=;
        b=ESngoEOwpgj/HagUqIHuW7wObXx6ufy61skrwsZO+n0PeJ2nXP5Np0uNOfme0benpL
         SpBQ+izR8uQI3PVLFTGdXluxK3oyXSqWMo4os9RDf9dcP4ZOJ1oS9C9y4O+aAqamyb2O
         9EjUBrpSpobeUZsuWB3YHG33NQRydRfPf964we8/Jh/Vyt28QFygPYHkwVZiWuDG332c
         JVN/TgGLVgo/eoDRyv5StrSlmQX48s1H9sOuOMDg2zD+C1Xt7Sf3R+397tZ8bB3O89DS
         GJHk7cIe/F0MCnGA3s4qq3bkVIhUqiJCJovr0FxmynIsZ72NHHlMz+CBmiCTlCus+516
         MxCQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=iVNbGYj3;
       spf=pass (google.com: domain of aliceryhl@google.com designates 2a00:1450:4864:20::430 as permitted sender) smtp.mailfrom=aliceryhl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x430.google.com (mail-wr1-x430.google.com. [2a00:1450:4864:20::430])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-45627898572si1791925e9.1.2025.07.16.13.07.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 16 Jul 2025 13:07:50 -0700 (PDT)
Received-SPF: pass (google.com: domain of aliceryhl@google.com designates 2a00:1450:4864:20::430 as permitted sender) client-ip=2a00:1450:4864:20::430;
Received: by mail-wr1-x430.google.com with SMTP id ffacd0b85a97d-3a54700a463so149267f8f.1
        for <kasan-dev@googlegroups.com>; Wed, 16 Jul 2025 13:07:50 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWYTacjMNNYqYXnErdUeJaK/FNbyZkcw98WYICHN706sQfAalvVlKh40FmfypmxBYoluiULV7q5wBo=@googlegroups.com
X-Gm-Gg: ASbGncsd2SEX8Zb6AuIkXxQlsOyXUV0k1UFqmlZLcCfaATHJ/4x6wXN2CrqtOH468sS
	lhf/i9bk/EP2wlJZYeCjZE++l3iPVv6sZv2Dlg8Xceb64S1HYw+emWbgB4ufZ0Wg5GxMb33x+eI
	sl5SSfpVY7tg1zA5FagqLf8VRDS0g+dsB3BSIDFZpCiqsFEYT7q8EcLOgv65AZ+wKn4toX963R2
	c3gnUsH
X-Received: by 2002:adf:e195:0:b0:3a5:3993:3427 with SMTP id
 ffacd0b85a97d-3b613adaaa6mr439027f8f.26.1752696469798; Wed, 16 Jul 2025
 13:07:49 -0700 (PDT)
MIME-Version: 1.0
References: <4c459085b9ae42bdbf99b6014952b965@BJMBX01.spreadtrum.com>
 <202507150830.56F8U908028199@SHSPAM01.spreadtrum.com> <c34f4f606eb04c38b64e8f3a658cd051@BJMBX01.spreadtrum.com>
 <CANiq72=v6jkOasLiem7RXe-WUSg9PkNqrZneeMOTi1pzwXuHYg@mail.gmail.com>
 <24e87f60203c443abe7549ce5c0e9e75@BJMBX01.spreadtrum.com> <aHftocnJcLg64c29@google.com>
In-Reply-To: <aHftocnJcLg64c29@google.com>
From: "'Alice Ryhl' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 16 Jul 2025 22:07:37 +0200
X-Gm-Features: Ac12FXwaBbCKoAemQb9xmWXTf5_wpyVeFFPscMtfQR5YlmbyXhCuUwBZR_A4iZs
Message-ID: <CAH5fLgiiZE_mFhB4J+G7-Jdz46+d-5NP15npjn2_H7DgSAynxw@mail.gmail.com>
Subject: Re: Meet compiled kernel binaray abnormal issue while enabling
 generic kasan in kernel 6.12 with some default KBUILD_RUSTFLAGS on
To: Carlos Llamas <cmllamas@google.com>
Cc: =?UTF-8?B?5YiY5rW354eVIChIYWl5YW4gTGl1KQ==?= <haiyan.liu@unisoc.com>, 
	Matthew Maurer <mmaurer@google.com>, Miguel Ojeda <miguel.ojeda.sandonis@gmail.com>, 
	Miguel Ojeda <ojeda@kernel.org>, =?UTF-8?B?5ZGo5bmzIChQaW5nIFpob3UvOTAzMik=?= <Ping.Zhou1@unisoc.com>, 
	=?UTF-8?B?5Luj5a2Q5Li6IChaaXdlaSBEYWkp?= <Ziwei.Dai@unisoc.com>, 
	=?UTF-8?B?5p2o5Li95aicIChMaW5hIFlhbmcp?= <lina.yang@unisoc.com>, 
	"linux-arm-kernel@lists.infradead.org" <linux-arm-kernel@lists.infradead.org>, 
	"linux-kernel@vger.kernel.org" <linux-kernel@vger.kernel.org>, 
	"rust-for-linux@vger.kernel.org" <rust-for-linux@vger.kernel.org>, 
	=?UTF-8?B?546L5Y+MIChTaHVhbmcgV2FuZyk=?= <shuang.wang@unisoc.com>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	"kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>, =?UTF-8?B?QXJ2ZSBIasO4bm5ldsOlZw==?= <arve@android.com>, 
	Todd Kjos <tkjos@android.com>, Martijn Coenen <maco@android.com>, 
	Joel Fernandes <joelagnelf@nvidia.com>, Christian Brauner <christian@brauner.io>, 
	Suren Baghdasaryan <surenb@google.com>, Jamie Cunliffe <Jamie.Cunliffe@arm.com>, 
	Catalin Marinas <catalin.marinas@arm.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: aliceryhl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=iVNbGYj3;       spf=pass
 (google.com: domain of aliceryhl@google.com designates 2a00:1450:4864:20::430
 as permitted sender) smtp.mailfrom=aliceryhl@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
X-Original-From: Alice Ryhl <aliceryhl@google.com>
Reply-To: Alice Ryhl <aliceryhl@google.com>
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

On Wed, Jul 16, 2025 at 8:21=E2=80=AFPM Carlos Llamas <cmllamas@google.com>=
 wrote:
>
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
=B3 (Ping Zhou/9032) <Ping.Zhou1@unisoc.com>; =E4=BB=A3=E5=AD=90=E4=B8=BA (=
Ziwei Dai)
> > > <Ziwei.Dai@unisoc.com>; =E6=9D=A8=E4=B8=BD=E5=A8=9C (Lina Yang) <lina=
.yang@unisoc.com>; linux-arm-kernel@lists.infradead.org;
> > > linux-kernel@vger.kernel.org; rust-for-linux@vger.kernel.org; =E7=8E=
=8B=E5=8F=8C (Shuang Wang) <shuang.wang@unisoc.com>; Andrey Ryabinin
> > > <ryabinin.a.a@gmail.com>; Alexander Potapenko <glider@google.com>; An=
drey Konovalov <andreyknvl@gmail.com>; Dmitry Vyukov
> > > <dvyukov@google.com>; Vincenzo Frascino <vincenzo.frascino@arm.com>; =
kasan-dev@googlegroups.com; Greg Kroah-Hartman
> > > <gregkh@linuxfoundation.org>; Arve Hj=C3=B8nnev=C3=A5g <arve@android.=
com>; Todd Kjos <tkjos@android.com>; Martijn Coenen
> > > <maco@android.com>; Joel Fernandes <joelagnelf@nvidia.com>; Christian=
 Brauner <christian@brauner.io>; Carlos Llamas
> > > <cmllamas@google.com>; Suren Baghdasaryan <surenb@google.com>; Jamie =
Cunliffe <Jamie.Cunliffe@arm.com>; Catalin Marinas
> > > <catalin.marinas@arm.com>
> > > =E4=B8=BB=E9=A2=98: Re: Meet compiled kernel binaray abnormal issue w=
hile enabling generic kasan in kernel 6.12 with some default KBUILD_RUSTFLA=
GS
> > > on
> > >
> > >
> > > =E6=B3=A8=E6=84=8F: =E8=BF=99=E5=B0=81=E9=82=AE=E4=BB=B6=E6=9D=A5=E8=
=87=AA=E4=BA=8E=E5=A4=96=E9=83=A8=E3=80=82=E9=99=A4=E9=9D=9E=E4=BD=A0=E7=A1=
=AE=E5=AE=9A=E9=82=AE=E4=BB=B6=E5=86=85=E5=AE=B9=E5=AE=89=E5=85=A8=EF=BC=8C=
=E5=90=A6=E5=88=99=E4=B8=8D=E8=A6=81=E7=82=B9=E5=87=BB=E4=BB=BB=E4=BD=95=E9=
=93=BE=E6=8E=A5=E5=92=8C=E9=99=84=E4=BB=B6=E3=80=82
> > > CAUTION: This email originated from outside of the organization. Do n=
ot click links or open attachments unless you recognize the sender
> > > and know the content is safe.
> > >
> > >
> > >
> > > On Tue, Jul 15, 2025 at 11:41=E2=80=AFAM =E5=88=98=E6=B5=B7=E7=87=95 =
(Haiyan Liu) <haiyan.liu@unisoc.com> wrote:
> > > >
> > > > The commit changes the fragment and diff is:
> > >
> > > An Android engineer should know how to handle that, but if you are re=
porting upstream, it is best to try to reproduce the issue with the
> > > upstream kernels (e.g. arm64 is not in 6.6.y) and provide the full ke=
rnel config used.
> > >
> > > > Only two rust-related global variables in fmr.rs and layout.rs have=
 this issue. Their asan.module_ctor complied binaries are wrong.
> > >
> > > I am not sure what you mean by `fmr.rs`. As for `layout.rs`, that is =
in the `kernel` crate in 6.12.y -- isn't there a single `asan.module_ctor`
> > > per TU? Which object file are you referring to? I get the pair for my=
 `rust/kernel.o`.
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
> > The address of the global is 0xFFFFFFC082EDB180 which value is '/proc/s=
elf/cwd/prebuilts/rust/linux-x86/1.82.0/lib/rustlib/src/rust/library/core/s=
rc/num/fmt.rs' and its viewinfo is 'vmlinux\Global\__unnamed_357'
> > The original size of the global is 0x5F
> > The name of the global is kmalloc-2k
> > The module name of the global is 'core.27758904ccee4c80-cgu.o'
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
s viewinfo is '<&usize_as_core::f..vmlinux\kernel_9a6cb9fd7c8dfd66_cgu\<&us=
ize_as_core::fmt::Debug>::{vtable}'
> > The original size of the global is 0x20
> > The name of the global is kmalloc-2k
> > The module name of the global is 'kernel.9a6cb9fd7c8dfd66-cgu.o'
> >
> > > Cheers,
> > > Miguel
>
> We have KASAN builds with android16-6.12 and haven't seen this issue.
> Can you share your entire config file, so we can try to reproduce?
>
> Cc: Alice Ryhl <aliceryhl@google.com>
> Cc: Matthew Maurer <mmaurer@google.com>
>
> Alice, Matthew, have you seen this before?

No, this doesn't ring any bells for me. I guess we need to see a full
config so we can try and reproduce ourselves.

Alice

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
AH5fLgiiZE_mFhB4J%2BG7-Jdz46%2Bd-5NP15npjn2_H7DgSAynxw%40mail.gmail.com.
