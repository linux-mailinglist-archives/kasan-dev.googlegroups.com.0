Return-Path: <kasan-dev+bncBC7OBJGL2MHBBCEYZH7AKGQEQMTBCTA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa39.google.com (mail-vk1-xa39.google.com [IPv6:2607:f8b0:4864:20::a39])
	by mail.lfdr.de (Postfix) with ESMTPS id 2EC4B2D61B7
	for <lists+kasan-dev@lfdr.de>; Thu, 10 Dec 2020 17:25:48 +0100 (CET)
Received: by mail-vk1-xa39.google.com with SMTP id b4sf2574704vkg.10
        for <lists+kasan-dev@lfdr.de>; Thu, 10 Dec 2020 08:25:48 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1607617547; cv=pass;
        d=google.com; s=arc-20160816;
        b=f1lcGmcpOym5y97413nf9wXu8d4QJIgwIGapCOnC3uABgrNq2DLw3tSNcS+BW28XWt
         XEVq8v4O5JwOgtqBCvtYRDA2ZlPialED3KD9cojXw5YPa02Y+S8MihUP/43lg42YMc3C
         mzKhfuH4wMNUBn6K24LDtn56rVNPuNGlWePwysIlpf96ryPGJmknbpjnz2jyOXlVKGTH
         DJcwx/Z2z20Kz1l2etjn7vU6Fq0qeCKUg/mXTyy3Bf12zQQJ1H314TYeYxCoPgT7/tia
         ZCRDW90fJDwD+4zLuIyFFsmwKqPFFnDPtNFkeAU5wkQnoZse1xZX78y9dOtUaeSrKX3M
         lI4Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=FaAnC+lzPDrk/wSh5Rq0eyNafhXcPwHJ+M4jzjgTIO4=;
        b=f5Dm+2j1UpSTYPVP5heqQT2xDYL90S/B9ZuGLZvj4njO6N2mR62B7Tj/UtfCXoE//0
         06ewuFB+3z7GbX2tA5EOaymE/e6UmzJiIwPbo6Ohs4h8t4p00nyVdLRJEN9STru3mSaz
         7hD9UBYybOM7nzHfgo8IrzvAQXwXgcELVnQfbL59JtMyR+NVhXXOY835/yLEPNySVVVQ
         dChT56duCwCw5JobEtjm+E12tJ3x5yGjF2bJPsnu3vM3IqC/DAEgyX77iSZdf+eRW0zo
         P6JUQ4KK6CKRxeQlSr4yEbvNrV0KkWO8VpbwzWt4EkJF/lVF47SvHJJ79o/Pngen/mRh
         6A7A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=dqrF4PCX;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::343 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=FaAnC+lzPDrk/wSh5Rq0eyNafhXcPwHJ+M4jzjgTIO4=;
        b=aIbs9nKjZs4o7gF7F6NmdqsAxFrnSDhj0rduBH4hGKbIa1lW3cGCK3Q6axftlIHxLZ
         ODridt18Pokn6WfL5GPMtiY3vNtAo22CKeJaAaTWy82qnqO8ymHVTGSzjHT8vVt/E+ZL
         Tt0zqwY+B1X5HjxHfo4/9M5X9svuvjNYQ7WrqCQjh8Pa8vLTkh6NNcyeX6rwL1vdqCmR
         XJHOKvoCVhJi/7elOxyl4/CWmTnmV0WVCDnGQs/SKyCLO/2qk2HMvORF4FruK+cQ8yGl
         mW5Rxp/M8iI3aiwycCtdYMo5+YGEAJpvO7D0LYCkqDt/Jg4D5m0vuSIAh2HXIb2kxGpX
         fEsw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=FaAnC+lzPDrk/wSh5Rq0eyNafhXcPwHJ+M4jzjgTIO4=;
        b=QXRCh9MLMZkpnRomrSInIBK0/1Nb49PyFSFOM6XchJqwX7ZtvBisdXYgRD9WhcreCk
         OjM3FZfHquv2Mpd8rhB4BH3UoSL7TLrVwjvQUO6FGd2rk1QfZVvUhcgMvOwLxfYYjRxb
         dwW2UeGOXjrhkW4HoWIoHx6EhQXJfA1MbvkKUuZ3P1h8HAyUnrJCMhjg/c1CQOo0Gc8R
         SqfbvVi3x1d+R3XUtnr/yp0k1JFcSKUqPt2B5wuSQZWlJOqX9HVQG4djD4sp5TaUDsL1
         zrjK3Dbdo2boKzcXNH37bepPgxpkBwW/SZ5xVSnhsgNZQM5h7KGVs5PEeTOdMCfYSU5/
         Nbiw==
X-Gm-Message-State: AOAM530FrmVdfsgGTnokq8mqWpyBK2TKR2O/WrrRL72F7di7PN6rovWC
	zAJSXNHhTQbMFoh0IhLDp/I=
X-Google-Smtp-Source: ABdhPJxCiEUUzzmtA33mnW/5ZgVS1d7Ig61r458Yzh4i/MX6/8oY5zXgQU+CjwkHgGEBmEDJlsfQng==
X-Received: by 2002:a67:f3ce:: with SMTP id j14mr9646144vsn.26.1607617545136;
        Thu, 10 Dec 2020 08:25:45 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:320c:: with SMTP id y12ls711994vsy.4.gmail; Thu, 10 Dec
 2020 08:25:44 -0800 (PST)
X-Received: by 2002:a67:30c1:: with SMTP id w184mr9452474vsw.13.1607617544513;
        Thu, 10 Dec 2020 08:25:44 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1607617544; cv=none;
        d=google.com; s=arc-20160816;
        b=ne8PFeUFkcEo7zFrBSkJCJ67x1nANoGKq1VL8bzsHsoVDWgRkMkbzkNYtbG+w9NFgW
         a7HnnYC/ALDeXFiAr3jVzp4YfgCETo59c1qZZvOyzQQxrJPLNZ8X9l8QtLZ1fgrEHavY
         gOo0Y1tK7EDKZKtvbrsuUMfU6SgcCA6as+rzEjUhm0QFqxMajlUiy55rc6NTwnt1yZKm
         b5m/LqR2tDJeIWHcmVrnoaD1S97NijCs34QvyGTUeYjLrargh3doZwd+Gfblt4Cz+M3S
         HXdFRcyD8CHrFLn/sKi3dADAKokfCX6Szgwm7XVxjnsr4UvWhXHu2bFJXy0Incsahp8a
         STDw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=qIX8H1T5vlOhy5P+c3dep3UC5lsSHIUYZ7wdp/u5aJM=;
        b=ac5s657s8+GLGYE5qkpI6BJ2Ee2iJsxaGSTXjIRPVMb8hZS6XRMOcWH6sF6OXJpndH
         X6KL0yIYX72TtApCwQuwHmTpTp5dP1/xSakfw7bvxtyFdHnS9d1wbLrLkFUskW5lwPx/
         obipS9QcQzLdpBt8XBreIFgqBAoNFTaMV78gnk30H7hCM0yDqgLW0d61WjNbOBL7drCu
         BPKQ6FrraPPyGaYFepL4oQ4nxGJakb93zm1+DGXNXtse2q4C1cMYJtl9KdCLyN2d7TdD
         8rcFDspNudc72dkRFWl4XaSdsi9YM1uaIZDtzOE4owLpCbXEcot6+vT84o36iYQDS5ok
         e9rw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=dqrF4PCX;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::343 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x343.google.com (mail-ot1-x343.google.com. [2607:f8b0:4864:20::343])
        by gmr-mx.google.com with ESMTPS id r18si402035vsk.1.2020.12.10.08.25.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 10 Dec 2020 08:25:44 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::343 as permitted sender) client-ip=2607:f8b0:4864:20::343;
Received: by mail-ot1-x343.google.com with SMTP id o11so5404660ote.4
        for <kasan-dev@googlegroups.com>; Thu, 10 Dec 2020 08:25:44 -0800 (PST)
X-Received: by 2002:a9d:7cc8:: with SMTP id r8mr6466658otn.233.1607617542402;
 Thu, 10 Dec 2020 08:25:42 -0800 (PST)
MIME-Version: 1.0
References: <20201201152017.3576951-1-elver@google.com> <CAKwvOdkcv=FES2CXfoY+AFcvg_rbPd2Nk8sEwXNBJqXL4wQGBg@mail.gmail.com>
 <CANpmjNOUHdANKQ6EZEzgbVg0+jqWgBEAuoLQxpzQJkstv6fxBg@mail.gmail.com>
 <CANpmjNOdJZUm1apuEHZz_KYJTEoRU6FVxMwZUrMar021hTd5Cg@mail.gmail.com> <CANiq72kwZtBn-YtWhZmewVNXNbjEXwqeWSpU1iLx45TNoLLOUg@mail.gmail.com>
In-Reply-To: <CANiq72kwZtBn-YtWhZmewVNXNbjEXwqeWSpU1iLx45TNoLLOUg@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 10 Dec 2020 17:25:30 +0100
Message-ID: <CANpmjNN3akp+Npf6tqJR44kn=85WpkRh89Z4BQtBh0nGJEiGEQ@mail.gmail.com>
Subject: Re: [PATCH] genksyms: Ignore module scoped _Static_assert()
To: Miguel Ojeda <miguel.ojeda.sandonis@gmail.com>
Cc: Nick Desaulniers <ndesaulniers@google.com>, LKML <linux-kernel@vger.kernel.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, Masahiro Yamada <masahiroy@kernel.org>, 
	Joe Perches <joe@perches.com>, Greg Kroah-Hartman <gregkh@linuxfoundation.org>, 
	Richard Henderson <richard.henderson@linaro.org>, Andrew Morton <akpm@linux-foundation.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=dqrF4PCX;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::343 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Thu, 10 Dec 2020 at 14:29, Miguel Ojeda
<miguel.ojeda.sandonis@gmail.com> wrote:
> On Thu, Dec 10, 2020 at 11:35 AM Marco Elver <elver@google.com> wrote:
> >
> > It looks like there's no clear MAINTAINER for this. :-/
> > It'd still be good to fix this for 5.11.
>
> Richard seems to be the author, not sure if he picks patches (CC'd).
>
> I guess Masahiro or akpm (Cc'd) would be two options; otherwise, I
> could pick it up through compiler attributes (stretching the
> definition...).

Thanks for the info. I did find that there's an alternative patch to
fix _Static_assert() with genksyms that was sent 3 days after mine
(it's simpler, but might miss cases). I've responded there (
https://lkml.kernel.org/r/X9JI5KpWoo23wkRg@elver.google.com ).

Now we have some choice. I'd argue for this patch, because it's not
doing preprocessor workarounds, but in the end I won't make that call.
:-)

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNN3akp%2BNpf6tqJR44kn%3D85WpkRh89Z4BQtBh0nGJEiGEQ%40mail.gmail.com.
