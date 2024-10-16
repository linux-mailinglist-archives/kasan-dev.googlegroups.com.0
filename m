Return-Path: <kasan-dev+bncBC65ZG75XIPRBYP7X24AMGQEOXWMZMI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x537.google.com (mail-ed1-x537.google.com [IPv6:2a00:1450:4864:20::537])
	by mail.lfdr.de (Postfix) with ESMTPS id 08D899A0B70
	for <lists+kasan-dev@lfdr.de>; Wed, 16 Oct 2024 15:30:12 +0200 (CEST)
Received: by mail-ed1-x537.google.com with SMTP id 4fb4d7f45d1cf-5c944a37d09sf4584147a12.0
        for <lists+kasan-dev@lfdr.de>; Wed, 16 Oct 2024 06:30:12 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1729085411; cv=pass;
        d=google.com; s=arc-20240605;
        b=XTJUpflmXHVcZ5NQ0BRw9TDT0o3Ibe7u7GLeT+zsguvjq9LXu4nTxQ1JtbN/CCLyEm
         vMG6ZwZtSlwmhZbbxkN8PVZ8einrbYJbzXTATOeu+zr3k5sMAXuJKtNYROuosDY/fjII
         oYQFOHaLOHMRygqEowThpCSDlMrJc26ZPMrd9l6Rp9XT2hRGVP0EcngCMJE4g9QJAcV8
         4+zmWdFEJQXRqfd3Onyomn0PnkH3wBNAr5/yG7nVeo6X8ntYqFoXj423mru7Vqr7pqKL
         HtaBdw7+OcY6qcUXn3IZRU2+ZjEehk8YD9hmqMQvoKqKyVAslOEH+dFtSEnJPblk2WVq
         nA8w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=NzbGs581rvU4IHFHjVYDsLYGdHIVwEfcfNOBoYuVo0o=;
        fh=C+4114Yvi4sS4Y3STbXibEwUJbWamY7LF6Ux19zAFiY=;
        b=RR7EPg/P6APSHUIGzQ9Itg87koDKOs4Xc59PHXV9v86lflDEW7xaKjrPFZ0U+DWUot
         Jda9+Xp85Jcfvfeq5K47yvxmbjCEPr0UOT1RibMVjKEWcQ96R6jYje9OHvIeKCsCz+W8
         OosUaQMsSLDHDeI57fY/7d0ajt9eHlI4GF8f3+NInacIr0gj7nlH2lp7Ox8mKrC55ssX
         HfaQuZVGW45SNuzPZ5ZWZTq9OXSQ/eWABN9+P/08fBZR/Y5IvdaVFNup43xJaUZw3HBx
         +ttOa1usj1sDzJvWbJjNA8cStVVnj3e8Tm645/d6rQxy6c/PA2yWH+OwET8WstnIfYNq
         wwug==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=fhkMIQkY;
       spf=pass (google.com: domain of dan.carpenter@linaro.org designates 2a00:1450:4864:20::62f as permitted sender) smtp.mailfrom=dan.carpenter@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1729085411; x=1729690211; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=NzbGs581rvU4IHFHjVYDsLYGdHIVwEfcfNOBoYuVo0o=;
        b=wwW6AUNPta6P6k5J+jQh2QHij4m99hHIVcVlsIhmtMGIivEh36wSrDIyfKGilCzRJl
         8hHSGVA4EZtOe1abXggvLvXYaj9wACvDM199DScaAw3adbqIFmqMaTQUc6nNSUkNxyzu
         N6INsYYHSWXhAAD1CIRCx+TvKg2qgtbloYSGjab9wgPHXOG51jMmeSEGshKukjB+8qoX
         GmmUOiLu+6RRBxtYL2qOhtTnUTflxekTgxJHGTjAOebG6bFnE7JKTS2GFDCUyYviUvP6
         uyDLPusBIgrSLth2BnoCWYRi/JpbNf6g33zb6o8dVTnRN5gt4pGM2DSWdIfqY9toe7On
         z8Zw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1729085411; x=1729690211;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=NzbGs581rvU4IHFHjVYDsLYGdHIVwEfcfNOBoYuVo0o=;
        b=CU5XU+g2CD/oxyxW6g0y2qE5bmwHIzGfM0SxOJPY2KF7rlHIrGSEOS5QqfGInWPVDJ
         XFdPON+Zlz3k2AnUrkwFeKvRiY2x3dhbOrstbrMzxrTSW8w5iPWx6yW0KZLNGltxwJRf
         cKXe8e8XViTMbX0OcB/UD8ikCOnGlgA06O9hX3frXE/S4icoaoGIbKVGlzB2JVXrUaB5
         nB+kYZlGsSR6TMJY77FotRrTOSrH97uVDSEEFjl2MbgbezkLU+ei0q+oksu4yJplRW3/
         5ai0LFqTsxJNdyfgEyqbXf0odsDrXKTNoUaT/3VF96WBXyLF41NUJRowfXvCl5gxbrYd
         d8Vw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVWIHXECy8wFjA20jShJ5r4ACzIToJCguaLG5NWQlSCFTerZALHjApexC9dLwKeKWfFR0YNgQ==@lfdr.de
X-Gm-Message-State: AOJu0Yz7NJHUVc0/I8Lw5xMK2DqP/FiezpE6ZfQbDK8Jjvqd2QWxVWou
	5Us5fB4eK2zcKyr20ZvEX9aAy6GRSrlMt7G6vkeIudvcLuvWbfT/
X-Google-Smtp-Source: AGHT+IEd97nXAE9nVe0WmnODBbC0MnpN2BS4xHMUpCQozxMCc62JhJnWb1QbsXt/UOSBL395mHJLeQ==
X-Received: by 2002:a05:6402:1ec8:b0:5c4:666f:d0c9 with SMTP id 4fb4d7f45d1cf-5c95ac4e47cmr11852532a12.24.1729085409913;
        Wed, 16 Oct 2024 06:30:09 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:40d3:b0:5c4:6c19:f74f with SMTP id
 4fb4d7f45d1cf-5c9949ca844ls124242a12.2.-pod-prod-04-eu; Wed, 16 Oct 2024
 06:30:07 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCULEJkRLKMBXS3EX7ZQcUrfcAU0BfQQb2FCcacsvqyIshK/NwWSxBEu6dss10Qv+fDSDduWybnhxXc=@googlegroups.com
X-Received: by 2002:a17:907:9342:b0:a99:4ebc:82d4 with SMTP id a640c23a62f3a-a99e3ea59c7mr1474243066b.55.1729085407266;
        Wed, 16 Oct 2024 06:30:07 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1729085407; cv=none;
        d=google.com; s=arc-20240605;
        b=LYyjfiF7Pj1SfUmcX9THteAECn3treBaWUs6R/ka/KhRMcTlbiK8PgtCfZflU2yQzl
         uYFSpku1tNxCT2HnkFQY3PPU/5F4iGTlCEqMaYzVZk40tMy9H3+2B3Xe4CdCRNHRWFvC
         xw/IFrXyNtfdBuncYipK6mwFMbWkbT4xB542zHdlAgxIIRKwhsK2kah3wzIuYOtGl6PK
         ggUF8M8LmQOQcE28/GF+JeWMN+EXA908L/VRCGrRrRIEZmmOPKP7nB0pVpAExyq0vxEg
         5QF3/901NG2x4Q7qpz1lnn6MUyOYds8t9KH/VFFn722+FmnWlpUeNXBw7iDkpIRgUg7N
         tGFQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=Ao59t5O1QyBE9ZTbCp+/84/h0y2L5JOpOVIMa+Mgf5E=;
        fh=iWoYDnMX5sRfjPUpil8RxTtbydh0kOF0Yz8J8zYQ8Rc=;
        b=KdRMpNsIr8llbjjkY5QRl/VGc/4v3Mm5+2ksh//n51/vMOltCThILSC5gbzIOSSnM6
         PcW9GUlqbGXjYZLNPzO0QLIknJN7V5jlzRNSJvio/AytbOqKAEg2SPS7+Wx10jvNP/Fl
         peQqr+c/xZ++/IL5O0tZ+opUuk2jZaF2Aef0HCNrWF0JdeLBKFV7XCgECe4iZ25n0fAZ
         eWejmc4paZXKvqRyTX2WBbyJXFG9N7Ke77q3jEFi3h5+3ZszuEuY1YQHB9oV3c78xMRR
         XoKza7BHGbKxOQlYo8a/p2J/QsFKfY4AbvV0iUBFer8zJzzW1/dec5XnCLVjodqd2dOh
         wxLA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=fhkMIQkY;
       spf=pass (google.com: domain of dan.carpenter@linaro.org designates 2a00:1450:4864:20::62f as permitted sender) smtp.mailfrom=dan.carpenter@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org;
       dara=pass header.i=@googlegroups.com
Received: from mail-ej1-x62f.google.com (mail-ej1-x62f.google.com. [2a00:1450:4864:20::62f])
        by gmr-mx.google.com with ESMTPS id a640c23a62f3a-a9a29541676si5296166b.0.2024.10.16.06.30.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 16 Oct 2024 06:30:07 -0700 (PDT)
Received-SPF: pass (google.com: domain of dan.carpenter@linaro.org designates 2a00:1450:4864:20::62f as permitted sender) client-ip=2a00:1450:4864:20::62f;
Received: by mail-ej1-x62f.google.com with SMTP id a640c23a62f3a-a9a26a5d6bfso321116066b.1
        for <kasan-dev@googlegroups.com>; Wed, 16 Oct 2024 06:30:07 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXbva/ZjrpLdFQG6UbwNoCDG1T3EFDDPg0sRaUt/vOroO8cmV9XNuJ9GFMYvshxARnFssbW+uFI2TA=@googlegroups.com
X-Received: by 2002:a17:907:9727:b0:a99:59c6:3265 with SMTP id a640c23a62f3a-a99e3b20c0bmr1419373166b.9.1729085406838;
        Wed, 16 Oct 2024 06:30:06 -0700 (PDT)
Received: from localhost ([196.207.164.177])
        by smtp.gmail.com with ESMTPSA id a640c23a62f3a-a9a298176a6sm187043066b.135.2024.10.16.06.30.05
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 16 Oct 2024 06:30:06 -0700 (PDT)
Date: Wed, 16 Oct 2024 16:30:02 +0300
From: Dan Carpenter <dan.carpenter@linaro.org>
To: Marco Elver <elver@google.com>
Cc: Dongliang Mu <mudongliangabcd@gmail.com>,
	Haoyang Liu <tttturtleruss@hust.edu.cn>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Jonathan Corbet <corbet@lwn.net>,
	hust-os-kernel-patches@googlegroups.com, kasan-dev@googlegroups.com,
	workflows@vger.kernel.org, linux-doc@vger.kernel.org,
	linux-kernel@vger.kernel.org
Subject: Re: [PATCH] docs/dev-tools: fix a typo
Message-ID: <c19c79ea-a535-48da-8f13-ae0ff135bbbe@stanley.mountain>
References: <20241015140159.8082-1-tttturtleruss@hust.edu.cn>
 <CAD-N9QWdqPaZSh=Xi_CWcKyNmxCS0WOteAtRvwHLZf16fab3eQ@mail.gmail.com>
 <CANpmjNOg=+Y-E0ozJbOoxOzOcayYnZkC0JGtuz4AOQQNmjSUuQ@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <CANpmjNOg=+Y-E0ozJbOoxOzOcayYnZkC0JGtuz4AOQQNmjSUuQ@mail.gmail.com>
X-Original-Sender: dan.carpenter@linaro.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linaro.org header.s=google header.b=fhkMIQkY;       spf=pass
 (google.com: domain of dan.carpenter@linaro.org designates
 2a00:1450:4864:20::62f as permitted sender) smtp.mailfrom=dan.carpenter@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org;
       dara=pass header.i=@googlegroups.com
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

On Tue, Oct 15, 2024 at 04:32:27PM +0200, 'Marco Elver' via HUST OS Kernel =
Contribution wrote:
> On Tue, 15 Oct 2024 at 16:11, Dongliang Mu <mudongliangabcd@gmail.com> wr=
ote:
> >
> > On Tue, Oct 15, 2024 at 10:09=E2=80=AFPM Haoyang Liu <tttturtleruss@hus=
t.edu.cn> wrote:
> > >
> > > fix a typo in dev-tools/kmsan.rst
> > >
> > > Signed-off-by: Haoyang Liu <tttturtleruss@hust.edu.cn>
> > > ---
> > >  Documentation/dev-tools/kmsan.rst | 2 +-
> > >  1 file changed, 1 insertion(+), 1 deletion(-)
> > >
> > > diff --git a/Documentation/dev-tools/kmsan.rst b/Documentation/dev-to=
ols/kmsan.rst
> > > index 6a48d96c5c85..0dc668b183f6 100644
> > > --- a/Documentation/dev-tools/kmsan.rst
> > > +++ b/Documentation/dev-tools/kmsan.rst
> > > @@ -133,7 +133,7 @@ KMSAN shadow memory
> > >  -------------------
> > >
> > >  KMSAN associates a metadata byte (also called shadow byte) with ever=
y byte of
> > > -kernel memory. A bit in the shadow byte is set iff the corresponding=
 bit of the
> > > +kernel memory. A bit in the shadow byte is set if the corresponding =
bit of the
> >
> > This is not a typo. iff is if and only if
>=20
> +1
>=20
> https://en.wikipedia.org/wiki/If_and_only_if
>=20

Does "iff" really add anything over regular "if"?  I would have thought the
"only if" could be assumed in this case.  Or if it's really necessary then =
we
could spell it out.

regards,
dan carpenter

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/c19c79ea-a535-48da-8f13-ae0ff135bbbe%40stanley.mountain.
