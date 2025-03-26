Return-Path: <kasan-dev+bncBCQ2XPNX7EOBB467SG7QMGQEM3SRPEI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x339.google.com (mail-wm1-x339.google.com [IPv6:2a00:1450:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id 64827A720B2
	for <lists+kasan-dev@lfdr.de>; Wed, 26 Mar 2025 22:21:57 +0100 (CET)
Received: by mail-wm1-x339.google.com with SMTP id 5b1f17b1804b1-43d733063cdsf2488305e9.0
        for <lists+kasan-dev@lfdr.de>; Wed, 26 Mar 2025 14:21:57 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1743024117; cv=pass;
        d=google.com; s=arc-20240605;
        b=Eu64UByggBwvWTdSshAKB329aUhEJ9+w5I+jkMuDoHfnzzwHrT+VCR6ItJcJtkXC4O
         pv9YtI/F7ici8RZMhivIIXHnYgawOIn3jGclikJBlmA3ekrs8r7wIUKKx66Qm8TtQwae
         4pqXstwYYN7LtbhFUlf0iOU2RJKG9b7ddMzM92rE1no4hMmfhr3meNOlB4w8GxGGju7E
         +TgkxcSiecvK508pKjwB+7lV+FQpvaVZKxQds7WPfAUVba2YCQLpg4AT6aLoUOhGl7Zb
         NN/jHbt4w4iuk/iXOxpKoRQhjDFMECtg0Lg4aVbrrB9ZsMUmITpk/hWOM+oAz6zBZXUA
         p9Cg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=WOJ46E0SjQR7zK7VmgWdQhCMHBWYFQG0cUk1346hRhs=;
        fh=I2eku8PiKKUJ/R0Nfxlw14I9RYHdYS2fjLbHSvzaLlA=;
        b=dDYjTXiQqI7PrhkJ7kgJK6bEwUHvpcy6ebiNGKL+BhPMiGELiB9PwSTUh5ScTqIMuf
         jn4FMNEEe0Enft5A4vTcpcw4y3cvlPK011A734rRwze/RrD/gL+6XEHit5Hxmrjr1m8U
         0HrehVqVf0S17P0qs+uPUNrCJ5TzACc7Ts50aoenBdhSlHnTS4YkM2IYeHg/bRJ3J3iX
         RQKshFrtmtfGDR/Maj0E9SWRWu7mhLLOcqQfdQC5WWrCD/3JxEAokLXE108o3LOuWGpH
         hpmM85XPrf3jCORh4kFlHPY3ji9JbHCSIH0TpX07LK77GWZ32Rh/RM193IOZGYJO7+T/
         ql5A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=ZoQTdIFX;
       spf=pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::52f as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1743024117; x=1743628917; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=WOJ46E0SjQR7zK7VmgWdQhCMHBWYFQG0cUk1346hRhs=;
        b=rz91+8h4wt5GLo2SF9HLmQVrRInwYO0LY8bS7Mfb954HhHfF+Ef9RfK0EQSTroxGLo
         oLz51iser4NC1Dka+VM1sE3sUTjYUPqtTAFLRZr+kkUJc8UqAB/eesWLEshvQChj6ugF
         Yo9ReuwnAGBk0H6NlH+G1bHjG3efVgKWc8OgXqy5OyFPuT7yO9U/q4pRwMAgYY6ELojx
         PwS/gURKVwajDgpX10FjtSSFOdiuQ26ngaOoEJRRhySOzJ5bKBNxvRuC2oSLena8PwRh
         V/8kWScxEIiocc8M1jZ2lOVlYWtegcmUmL11HpaaAJKqYsZsNBniJ8R5V2CR06BMI0J5
         M2XQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1743024117; x=1743628917;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=WOJ46E0SjQR7zK7VmgWdQhCMHBWYFQG0cUk1346hRhs=;
        b=oGesRUWIUla5GNl1o5NWAe11wOhRAaHXPJ/OX4vo7eAkA+v4C4NvEJ95jseRWeozap
         /Gg3S6xVPb/mBGs1G7LHOcTxeaAXSX5WqyZcc5qZqModCQ/Qhm1USVft59XbXxIzl78r
         e3jmPiZMV76lmrAVa+/O65Ps4FxR/mtxvM+tg4mj5soy2eAgE+D60DdwLuGXqu1wpPCl
         l0ok6ztWwM62WGek6yHtJyCjPv5i/DWw0KYQXzVphBEQias7YCH6gQ7zAFwm9kDpJ4NU
         c+PVvXK8LTMX0+WrT0WeBw7/NepSdr+rX5bA81cbEF0Mci453Wb2qu4G2y7K5+aAdL7h
         QTDA==
X-Forwarded-Encrypted: i=2; AJvYcCW/FxA7C2TH58g6ZMXFzj8s5azJVIEXKe2QKHlu1/hOL4fUQ37yAVy3FGNtnSR2cfoj/co2Ng==@lfdr.de
X-Gm-Message-State: AOJu0Yx7wBfkuzdQ0DUF2r9XKF6gIFvAZtBNJMEX/0ji5jPmBLN2yzys
	x6yO/WUjq/9XVXRM9CxaFxvdxKPpKuqeDvery8oYscQWSg59McGN
X-Google-Smtp-Source: AGHT+IEBY7eMI4LGo7X0pdq81zS8PW5afSCbkxFueK2a/RVbmzE/G4Vbw0pRDIgpMlEszCqreur9hA==
X-Received: by 2002:a05:600c:c15:b0:43d:745a:5a50 with SMTP id 5b1f17b1804b1-43d85066317mr10306215e9.19.1743024116184;
        Wed, 26 Mar 2025 14:21:56 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARLLPALHXHTbOJo/Raicr7/I/W4hHj9ZiEG2T7qAyuRTFTXSpA==
Received: by 2002:a05:600c:578a:b0:43c:e3ef:1646 with SMTP id
 5b1f17b1804b1-43d84e4c6cals1120895e9.0.-pod-prod-02-eu; Wed, 26 Mar 2025
 14:21:54 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWus3CAViiIYDnfkwAHfivZ6yL4g+Uz9tJTxlXwvTpg9tyuVQOqjsGa4NYsJht3dLkuRD8QaJvzqH8=@googlegroups.com
X-Received: by 2002:a5d:47af:0:b0:38f:6287:6474 with SMTP id ffacd0b85a97d-39ad1743b5amr703233f8f.15.1743024113677;
        Wed, 26 Mar 2025 14:21:53 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1743024113; cv=none;
        d=google.com; s=arc-20240605;
        b=BMasHXtVWvul+1S7ME+qcWuoM8ezE2frpQU5mp18qBnk5Vu4YechcA26ZSaYhOYx5f
         w27NbL/K6xuG49uomIHe8eKr0P8SDBX7LFVd5OeQ3AcaC2fVz6t6HXa0O04uMTrnerKx
         xK29soF/L1jzc9TXDF+BN7pbbgwDcpjwXDmF1pa1AY81Ud69pshUCFeAafj4012R02Ra
         Rqiz1FGiHbwMC3AIWN4R0ZaVRkpfdiHgungUcMuMYodpdkXF4DRh+mw7sxGCROwgGeGC
         YZ7J9ENp4Anlx9qYFpaVCG4hLQ6tPjV6658fJli36BLr6Vb/80ZnuQJ3KaBrAoeA39mk
         3y4w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=FxMIaxzdKd25j5BobKFtyp9BpbbkbtzKIEHTHbqVE8I=;
        fh=pW8MW/236FnhquMQ0zwwxZ3qyHuHPDHf9NwsNguvOLM=;
        b=Bv7jazns0APiGlg8AdBYiasi/5ONeJpao6qqecfY2SHXwCvSfiF4lcQPg2w2sLcnWB
         8/cOgqibcf0co3M13Q8o15GkrtLWSmxqJj8ZT07n7UT3X1OZueRsTkkqOAPuasr51cg7
         jJ+xnn0WduJgU+qElIjQVshAaIzOeSrU6V/tvmrVpTykkp3Ol04KA2LXclwc2p+3JBoS
         SWlcIpjTWfhK6WXFiz11z4ISb9TWcvarFS+Xul/K1onWpCHjrps9pBxvfSZApN2plZcq
         UFfhygmsZ1GLKN3nC3/GUlHtGUIEdDHuOItheIK0CSuemT/DXLz4Xle6B8oHCK1AMF1r
         ujpw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=ZoQTdIFX;
       spf=pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::52f as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ed1-x52f.google.com (mail-ed1-x52f.google.com. [2a00:1450:4864:20::52f])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-3997f929bd9si248156f8f.0.2025.03.26.14.21.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 26 Mar 2025 14:21:53 -0700 (PDT)
Received-SPF: pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::52f as permitted sender) client-ip=2a00:1450:4864:20::52f;
Received: by mail-ed1-x52f.google.com with SMTP id 4fb4d7f45d1cf-5dbfc122b82so3500a12.0
        for <kasan-dev@googlegroups.com>; Wed, 26 Mar 2025 14:21:53 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUX+fLCpI17iIpQ06hFsk2OqnCk/8tDzHxBsFf0K0cWyHvFhgdcezMErs9+D3HJEH5eMRBAx0KB01w=@googlegroups.com
X-Gm-Gg: ASbGnctiSDgzsLsl1OORmkNB83VpXG4AMEt5FvDMKgpD/joWy+DlvQaAMAO/twrkAzu
	+8okdh/CagzUW3Gcy5ITVMMVD2xu3blpfcBc0XRxbrv6m+te+5DK6TFgSNux+dd6s2d7p47Z4OX
	pBNldS2UFWGb70TpML1J2gfqDP+ZjWCxfRqHhL8XWJeEbIcpKUa0QiHcI=
X-Received: by 2002:aa7:d688:0:b0:5e4:afad:9a83 with SMTP id
 4fb4d7f45d1cf-5edaa299a33mr12983a12.2.1743024112866; Wed, 26 Mar 2025
 14:21:52 -0700 (PDT)
MIME-Version: 1.0
References: <20250325-kcsan-rwonce-v1-1-36b3833a66ae@google.com>
 <20250326203926.GA10484@ax162> <CAG48ez05PsJ3-JUBUMrM=zd5aMJ_ZQT4mhavgnCbXTYvxFPOhQ@mail.gmail.com>
In-Reply-To: <CAG48ez05PsJ3-JUBUMrM=zd5aMJ_ZQT4mhavgnCbXTYvxFPOhQ@mail.gmail.com>
From: "'Jann Horn' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 26 Mar 2025 22:21:16 +0100
X-Gm-Features: AQ5f1JquhTVerEmqgNAhgQCsPngLTzI4uGjqymw9DsbgV3pWRPJXXIrAKOz8bcU
Message-ID: <CAG48ez3uh48VZCVO3JD3uv9k5kZBHahr3dAita4hkHsLqyyA9w@mail.gmail.com>
Subject: Re: [PATCH] rwonce: handle KCSAN like KASAN in read_word_at_a_time()
To: Nathan Chancellor <nathan@kernel.org>, Arnd Bergmann <arnd@arndb.de>
Cc: Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com, 
	linux-arch@vger.kernel.org, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: jannh@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=ZoQTdIFX;       spf=pass
 (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::52f as
 permitted sender) smtp.mailfrom=jannh@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
X-Original-From: Jann Horn <jannh@google.com>
Reply-To: Jann Horn <jannh@google.com>
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

On Wed, Mar 26, 2025 at 9:44=E2=80=AFPM Jann Horn <jannh@google.com> wrote:
> On Wed, Mar 26, 2025 at 9:39=E2=80=AFPM Nathan Chancellor <nathan@kernel.=
org> wrote:
> > On Tue, Mar 25, 2025 at 05:01:34PM +0100, Jann Horn wrote:
> > > Also, since this read can be racy by design, we should technically do
> > > READ_ONCE(), so add that.
> > >
> > > Fixes: dfd402a4c4ba ("kcsan: Add Kernel Concurrency Sanitizer infrast=
ructure")
> > > Signed-off-by: Jann Horn <jannh@google.com>
> > ...
> > > diff --git a/include/asm-generic/rwonce.h b/include/asm-generic/rwonc=
e.h
> > > index 8d0a6280e982..e9f2b84d2338 100644
> > > --- a/include/asm-generic/rwonce.h
> > > +++ b/include/asm-generic/rwonce.h
> > > @@ -79,11 +79,14 @@ unsigned long __read_once_word_nocheck(const void=
 *addr)
> > >       (typeof(x))__read_once_word_nocheck(&(x));                     =
 \
> > >  })
> > >
> > > -static __no_kasan_or_inline
> > > +static __no_sanitize_or_inline
> > >  unsigned long read_word_at_a_time(const void *addr)
> > >  {
> > > +     /* open-coded instrument_read(addr, 1) */
> > >       kasan_check_read(addr, 1);
> > > -     return *(unsigned long *)addr;
> > > +     kcsan_check_read(addr, 1);
> > > +
> > > +     return READ_ONCE(*(unsigned long *)addr);
> >
> > I bisected a boot hang that I see on arm64 with LTO enabled to this
> > change as commit ece69af2ede1 ("rwonce: handle KCSAN like KASAN in
> > read_word_at_a_time()") in -next. With LTO, READ_ONCE() gets upgraded t=
o
> > ldar / ldapr, which requires an aligned address to access, but
> > read_word_at_a_time() can be called with an unaligned address. I
> > confirmed this should be the root cause by removing the READ_ONCE()
> > added above or removing the selects of DCACHE_WORD_ACCESS and
> > HAVE_EFFICIENT_UNALIGNED_ACCESS in arch/arm64/Kconfig, which avoids
> > the crash.
>
> Oh, bleeeh. Thanks for figuring that out. I guess that means we should
> remove that READ_ONCE() again to un-break the build. I'll send a patch
> in a bit...

I sent a patch at
<https://lore.kernel.org/all/20250326-rwaat-fix-v1-1-600f411eaf23@google.co=
m/>.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
AG48ez3uh48VZCVO3JD3uv9k5kZBHahr3dAita4hkHsLqyyA9w%40mail.gmail.com.
