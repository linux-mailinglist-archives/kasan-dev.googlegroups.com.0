Return-Path: <kasan-dev+bncBDYZDG4VSMIRBY7U3KOQMGQEPTKKH5Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x238.google.com (mail-lj1-x238.google.com [IPv6:2a00:1450:4864:20::238])
	by mail.lfdr.de (Postfix) with ESMTPS id 6661D65EA3A
	for <lists+kasan-dev@lfdr.de>; Thu,  5 Jan 2023 12:54:12 +0100 (CET)
Received: by mail-lj1-x238.google.com with SMTP id v4-20020a2e9f44000000b0027fd0c48981sf5259058ljk.3
        for <lists+kasan-dev@lfdr.de>; Thu, 05 Jan 2023 03:54:12 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1672919651; cv=pass;
        d=google.com; s=arc-20160816;
        b=oBGCYacOk75W5Xr5wNtruKb8ut2leINGzcXfuUv5gYZeT85EpgxRNvjylIwnGlWKWE
         4pNhj4AYlvcr4+D3kPWcTMpyAg7M1ZsFBS55+S3WgUKumaDVa8GQs2Tt/xLfJO/OTlMY
         xyXyZp/N5X2szC3975KHodtPbSVmtW403JsdGOehbplKjVKdxzW0DBp9ZoA/sxvju8gy
         INX+rX/7VE2Kr84o8KU7hbHpQRcQXcthW4A9+wS2BqLe1yerRTXE0a6rkKVdU0cSV5lV
         +bpOi4e1gBEl3a4WEI/SmInXtq3qh8qSozYpOKUSK2XcNeU88sE4HwV/D/k3aj5rJpku
         /zWg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:mail-followup-to:message-id:subject:cc:to:from:date
         :sender:dkim-signature;
        bh=uAo/h9ZZGaXcmnUiPKEJXEDDbYocWrz3BIWOpHE6iOI=;
        b=cIDzwVP1wtjfAgNGMspJYACB2WeS4XgWDKSyt4iX1HW1sElnXYCOV5ILw8jIl12NDw
         4oF0kwFzw6NvXEQIHZp4AoR0ZJf+JqjTkfUYJPOnXkVLB20K9hqPfeJGxsVM22aj4zeW
         PV/w65y1I3wjuR0zcmOQ7xWPsWqZ8Xyf/Mkd9S0YhPNXadlzeBbqimOQbxiR29gdYBP1
         ZyFy96/FqST5FNQ92gMEk+CaI9PNfFQZDnvrDnGzQFBMjaWZSy0AbTCaPuKKt01Mz3Ll
         JabY6hiXMnyW8NKym8vlYQ1y7Qn/NO4pNXoVo2nSR275SZatmnWBF2C3PvNjUNcAdD3n
         7GcQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ffwll.ch header.s=google header.b=d20voggv;
       spf=neutral (google.com: 2a00:1450:4864:20::335 is neither permitted nor denied by best guess record for domain of daniel@ffwll.ch) smtp.mailfrom=daniel@ffwll.ch
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:mail-followup-to
         :message-id:subject:cc:to:from:date:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=uAo/h9ZZGaXcmnUiPKEJXEDDbYocWrz3BIWOpHE6iOI=;
        b=I/E2h+X8iRhcDIyFmAWxA68OrSgUqAT9WS77onVp8Ay1X9c9tws9BiQSsoI8egxU0u
         My9wgyqXMswJGzFX1W/mZNqYVBTjgtyhTEyre+uG9mF0rukkDCdr5DSHa+El27Lov09C
         Oxq6pydIyIpSF72TAmHlZf4bL0s4u6AcfXOTQZe7NZs0H2tJsFMqrdQqVb+of8If0+YB
         1BRj222FStWEf4Tf+yv60kabLbyho8x0+ZhUmMihqhzA4w80mpfgfelA+QxFNPtdajYV
         DBfm2mIIlxn6MixJmYVaP7b3AXMS0xPNFnBLjJsks3j0NvUXG+UkCTUfU+ONPcPHAxqJ
         goWA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:mail-followup-to:message-id:subject:cc:to:from:date
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=uAo/h9ZZGaXcmnUiPKEJXEDDbYocWrz3BIWOpHE6iOI=;
        b=fIoCCh1zbo7Kjw95r72zCUVjFWmIaZS3UR6QchpaKrLgLCslx+DXhGCa+67bDklgja
         1BwdOj7/w8MnvAjV2mwfkm8IB0naybCO6bJMbRSEQvN0RvcNcaKj5YH8gJld46iNM9ql
         GybymdkHK4bTQzLwpN0V8W36gFKRhnrz+0jVLzp9+BEwsnco3U/awRSM6BfeWqEFWJBK
         uNZjMFv2ldgI3iBqWqNkOh9eqtMgTSi46bGpt7zgjlyuAWvU8K2jNKvKWZIZtrmjCGps
         LbZXPZL4H4dyD/PMege5bqkpbs/gVxEj9QtofZCU0NEFoH+Smy8y3V7g57FxlNao3bIk
         8PQQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2krEfhn5gn9YqGv8RrMn0Cl7sXKKJXcox5zp/t8d0uR7o+UV5uL7
	IzjtQiHDeDctLqwArZ55qks=
X-Google-Smtp-Source: AMrXdXtncRG8/PWTLnGpMuLfgakDVEs8b5XSqkJWeqf/eSfuwfRtC38GKN2C5JiR+gryo9vkAua6Zw==
X-Received: by 2002:a2e:b5ca:0:b0:27f:ed4d:7feb with SMTP id g10-20020a2eb5ca000000b0027fed4d7febmr1328459ljn.1.1672919651587;
        Thu, 05 Jan 2023 03:54:11 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:1182:b0:4b5:3cdf:5a65 with SMTP id
 g2-20020a056512118200b004b53cdf5a65ls2158425lfr.2.-pod-prod-gmail; Thu, 05
 Jan 2023 03:54:10 -0800 (PST)
X-Received: by 2002:a05:6512:2591:b0:4b5:7dd6:4df0 with SMTP id bf17-20020a056512259100b004b57dd64df0mr14479985lfb.32.1672919650237;
        Thu, 05 Jan 2023 03:54:10 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1672919650; cv=none;
        d=google.com; s=arc-20160816;
        b=pkP53qMDjHonH+CXbpcjv4kxx64/FHVoCn1uEkdErJuegC9apiEaWXXwAaKOI+nO3F
         Vl676EUswMzlUrGz1OjcPovxLwxE5B9fltDXYhEXmHiiDHzNmnqNgxIhWAh5wD3uWIS8
         cdKiYG8taYGmbztWe7+KobPeCqYcKJb3cBltqlIhU82GOJ/tDpxIahJ4JRjd28rRlaru
         VSwI8YNmSARw2aWaoKpakRLyVzmGSBYhf/488wVvmS9DATP0UMvRD4rq1FIndSH82WdU
         RF/mMWGfYi5Sg1h0SZ1JVaHruck47pxi/k+UQEQkjop/F1lqp+sQmmx0i5o68kPRwCHw
         U1Rw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:mail-followup-to:message-id:subject:cc:to
         :from:date:dkim-signature;
        bh=6MBIVunY5Es/Vsno0Ti7SjeLYrcFtxWJO9vkWYEimAw=;
        b=Odto6Hu61Xy45CwCjkIr7hBkPARTIGMKyxkaC7r81w46DnxgGT0Cx0GRHYlaHWkAfv
         ZgMpym6/yvFBvAYv+fPf7Dwg7cjECWn2iARuaVWr/6ogOmTi4YSLLYfySrK6Les8PLAS
         +SO5eS1FtngP4n/x4ubr8Qr1ZBt+9q8X8zpes3sd1WgBIQHtVXs64p8VKvNTJAWMnKIM
         wKHUxfrreiGvxPcBptIZrJhVOQotFq5r/jRFEpKedLsvjVV3IyyF06f4f/4ocjNb9QIy
         nWZk6IOz8QdxPvMqsLRMT3hA1NVsGyJ1sNdQPE5t733exHb2iyOtSaR2DeiezTzDdGwI
         Gxig==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ffwll.ch header.s=google header.b=d20voggv;
       spf=neutral (google.com: 2a00:1450:4864:20::335 is neither permitted nor denied by best guess record for domain of daniel@ffwll.ch) smtp.mailfrom=daniel@ffwll.ch
Received: from mail-wm1-x335.google.com (mail-wm1-x335.google.com. [2a00:1450:4864:20::335])
        by gmr-mx.google.com with ESMTPS id v17-20020ac258f1000000b004cb0f0982f3si882899lfo.4.2023.01.05.03.54.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 05 Jan 2023 03:54:10 -0800 (PST)
Received-SPF: neutral (google.com: 2a00:1450:4864:20::335 is neither permitted nor denied by best guess record for domain of daniel@ffwll.ch) client-ip=2a00:1450:4864:20::335;
Received: by mail-wm1-x335.google.com with SMTP id ay2-20020a05600c1e0200b003d22e3e796dso1135423wmb.0
        for <kasan-dev@googlegroups.com>; Thu, 05 Jan 2023 03:54:10 -0800 (PST)
X-Received: by 2002:a05:600c:54c6:b0:3d3:4ead:bb07 with SMTP id iw6-20020a05600c54c600b003d34eadbb07mr35857240wmb.5.1672919649608;
        Thu, 05 Jan 2023 03:54:09 -0800 (PST)
Received: from phenom.ffwll.local ([2a02:168:57f4:0:efd0:b9e5:5ae6:c2fa])
        by smtp.gmail.com with ESMTPSA id o11-20020a05600c4fcb00b003c6f3f6675bsm2374456wmq.26.2023.01.05.03.54.08
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 05 Jan 2023 03:54:08 -0800 (PST)
Date: Thu, 5 Jan 2023 12:54:06 +0100
From: Daniel Vetter <daniel@ffwll.ch>
To: Alexander Potapenko <glider@google.com>
Cc: Tetsuo Handa <penguin-kernel@i-love.sakura.ne.jp>,
	Geert Uytterhoeven <geert@linux-m68k.org>,
	Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>,
	kasan-dev <kasan-dev@googlegroups.com>,
	Daniel Vetter <daniel@ffwll.ch>, Helge Deller <deller@gmx.de>,
	Linux Fbdev development list <linux-fbdev@vger.kernel.org>,
	DRI <dri-devel@lists.freedesktop.org>,
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>
Subject: Re: [PATCH] fbcon: Use kzalloc() in fbcon_prepare_logo()
Message-ID: <Y7a6XkCNTkxxGMNC@phenom.ffwll.local>
Mail-Followup-To: Alexander Potapenko <glider@google.com>,
	Tetsuo Handa <penguin-kernel@i-love.sakura.ne.jp>,
	Geert Uytterhoeven <geert@linux-m68k.org>,
	Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>,
	kasan-dev <kasan-dev@googlegroups.com>,
	Helge Deller <deller@gmx.de>,
	Linux Fbdev development list <linux-fbdev@vger.kernel.org>,
	DRI <dri-devel@lists.freedesktop.org>,
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>
References: <cad03d25-0ea0-32c4-8173-fd1895314bce@I-love.SAKURA.ne.jp>
 <CAMuHMdUH4CU9EfoirSxjivg08FDimtstn7hizemzyQzYeq6b6g@mail.gmail.com>
 <86bdfea2-7125-2e54-c2c0-920f28ff80ce@I-love.SAKURA.ne.jp>
 <CAG_fn=VJrJDNSea6DksLt5uBe_sDu0+8Ofg+ifscOyDdMKj3XQ@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <CAG_fn=VJrJDNSea6DksLt5uBe_sDu0+8Ofg+ifscOyDdMKj3XQ@mail.gmail.com>
X-Operating-System: Linux phenom 5.19.0-2-amd64
X-Original-Sender: daniel@ffwll.ch
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ffwll.ch header.s=google header.b=d20voggv;       spf=neutral
 (google.com: 2a00:1450:4864:20::335 is neither permitted nor denied by best
 guess record for domain of daniel@ffwll.ch) smtp.mailfrom=daniel@ffwll.ch
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

On Fri, Dec 16, 2022 at 04:52:14PM +0100, Alexander Potapenko wrote:
> On Fri, Dec 16, 2022 at 3:03 PM Tetsuo Handa
> <penguin-kernel@i-love.sakura.ne.jp> wrote:
> >
> > On 2022/12/15 18:36, Geert Uytterhoeven wrote:
> > > The next line is:
> > >
> > >         scr_memsetw(save, erase, array3_size(logo_lines, new_cols, 2)=
);
> > >
> > > So how can this turn out to be uninitialized later below?
> > >
> > >         scr_memcpyw(q, save, array3_size(logo_lines, new_cols, 2));
> > >
> > > What am I missing?
> >
> > Good catch. It turned out that this was a KMSAN problem (i.e. a false p=
ositive report).
> >
> > On x86_64, scr_memsetw() is implemented as
> >
> >         static inline void scr_memsetw(u16 *s, u16 c, unsigned int coun=
t)
> >         {
> >                 memset16(s, c, count / 2);
> >         }
> >
> > and memset16() is implemented as
> >
> >         static inline void *memset16(uint16_t *s, uint16_t v, size_t n)
> >         {
> >                 long d0, d1;
> >                 asm volatile("rep\n\t"
> >                              "stosw"
> >                              : "=3D&c" (d0), "=3D&D" (d1)
> >                              : "a" (v), "1" (s), "0" (n)
> >                              : "memory");
> >                 return s;
> >         }
> >
> > . Plain memset() in arch/x86/include/asm/string_64.h is redirected to _=
_msan_memset()
> > but memsetXX() are not redirected to __msan_memsetXX(). That is, memory=
 initialization
> > via memsetXX() results in KMSAN's shadow memory being not updated.
> >
> > KMSAN folks, how should we fix this problem?
> > Redirect assembly-implemented memset16(size) to memset(size*2) if KMSAN=
 is enabled?
> >
>=20
> I think the easiest way to fix it would be disable memsetXX asm
> implementations by something like:
>=20
> -------------------------------------------------------------------------=
------------------------
> diff --git a/arch/x86/include/asm/string_64.h b/arch/x86/include/asm/stri=
ng_64.h
> index 888731ccf1f67..5fb330150a7d1 100644
> --- a/arch/x86/include/asm/string_64.h
> +++ b/arch/x86/include/asm/string_64.h
> @@ -33,6 +33,7 @@ void *memset(void *s, int c, size_t n);
>  #endif
>  void *__memset(void *s, int c, size_t n);
>=20
> +#if !defined(__SANITIZE_MEMORY__)
>  #define __HAVE_ARCH_MEMSET16
>  static inline void *memset16(uint16_t *s, uint16_t v, size_t n)
>  {
> @@ -68,6 +69,7 @@ static inline void *memset64(uint64_t *s, uint64_t
> v, size_t n)
>                      : "memory");
>         return s;
>  }
> +#endif

So ... what should I do here? Can someone please send me a revert or patch
to apply. I don't think I should do this, since I already tossed my credit
for not looking at stuff carefully enough into the wind :-)
-Daniel

>=20
>  #define __HAVE_ARCH_MEMMOVE
>  #if defined(__SANITIZE_MEMORY__) && defined(__NO_FORTIFY)
> -------------------------------------------------------------------------=
------------------------
>=20
> This way we'll just pick the existing C implementations instead of
> reinventing them.
>=20
>=20
> --=20
> Alexander Potapenko
> Software Engineer
>=20
> Google Germany GmbH
> Erika-Mann-Stra=C3=9Fe, 33
> 80636 M=C3=BCnchen
>=20
> Gesch=C3=A4ftsf=C3=BChrer: Paul Manicle, Liana Sebastian
> Registergericht und -nummer: Hamburg, HRB 86891
> Sitz der Gesellschaft: Hamburg

--=20
Daniel Vetter
Software Engineer, Intel Corporation
http://blog.ffwll.ch

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/Y7a6XkCNTkxxGMNC%40phenom.ffwll.local.
