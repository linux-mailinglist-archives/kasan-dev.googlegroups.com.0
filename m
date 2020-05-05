Return-Path: <kasan-dev+bncBC7OBJGL2MHBBV52Y32QKGQE2AVRMTA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3e.google.com (mail-oo1-xc3e.google.com [IPv6:2607:f8b0:4864:20::c3e])
	by mail.lfdr.de (Postfix) with ESMTPS id B12A01C5E5E
	for <lists+kasan-dev@lfdr.de>; Tue,  5 May 2020 19:07:36 +0200 (CEST)
Received: by mail-oo1-xc3e.google.com with SMTP id s185sf2138850oos.11
        for <lists+kasan-dev@lfdr.de>; Tue, 05 May 2020 10:07:36 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1588698455; cv=pass;
        d=google.com; s=arc-20160816;
        b=Y2bjTo1mOO0FoWTBH+jDU8Nh6wnmqGhI7tejIp3GU6PLAXHpFGavNjd9NnbKVP5g2F
         rKFYGs/dIK2zSYb002/Iu6bMTArab17k6v0jDjPKGt896moBawDyn8zr+XbuxUnrOgLE
         en4ZLBi78T+7RxEBUWH4dfL0U8gOL9JF3claAhNk2G/O5acVrpvLDP8FLLU1mlolVKOr
         zgFPTJgarkdWv+J/Z/XUC9MTIx0TbXOSj8KYDQDrrf1BI+1rG8Hswpej29QNChLzmkun
         FgRtdOnwXRX4dJQrnfNIzNuQ4ePidrTJ8FlgMa8uirCX0C4Ri+nV28Do/+Yq9RPJL9g6
         XgAQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=comY+Ne/GDpE3nALlYB587II8Fr0riJpyrZdg9arH88=;
        b=GFLNz7s06Y4VcaEdLdvFaHmRemtCufDrQBq9kum9LmVUwXHGaDQEa4FoukWkF/1hq/
         LDuWRfVKOQ3EOGT2g0wOGtsDRqQ5pjbuwZ3VOYTT6MjGV4rAPpx4CvwYGlo8fFFCt9hp
         qUnkmKNOaMyTBFngxhrHg6YLsPu+AjvantDT49SrnqK3kvoLkGM1mRA5dw4RcsAc+HNc
         dLrLhn9q2GGZ8jYtNqM92lne0PDhbcf4akk2N+bYF5zmfdl3MmE6Cu1JTN0vvj8y7MRV
         RPG84goF5q1L05tlqTMuJCooHql6UIa8d48OUJmDp7h3eRPQVHO7wWz2eNBMqVyaM4Xn
         o1Rw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=AgMhYAYI;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::242 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=comY+Ne/GDpE3nALlYB587II8Fr0riJpyrZdg9arH88=;
        b=gR++bNYLI1+4stn8e7LVrqf1zvJLq4dPG0GNclYa8Bau+6kEddG880mBoytYTshdcd
         0rUVy3s3EGnovS35DrSSfcMAOdQU1xscaZL0h0IwPBQTW8J4Y8ARPhrbDwA2rasOD1EL
         z+BGcbz1+slaDioJj9D2iI5pvyI2BPbF/RrE1cLnSW2ImORlbtnRdf0oSuCaxzNpMoZF
         JJ9jZus2Pit+jpmY3L7a04oL1oyL4DVAG9RTx2ALw1wtxRsLzK0zLy7t8RLonKz14Srx
         4zljcpwdaVdRIwP0yfXKAro494s3f2jjUof9Xpx+3mOXenENLq0FlsEi3p4tF5Hc8ojl
         URmw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=comY+Ne/GDpE3nALlYB587II8Fr0riJpyrZdg9arH88=;
        b=tyN6CfHVPjY48jVPoIgMPdxmaV63aallWstOdJHB1x7RQOC3bYMvWD4tNIDUND366j
         cysM7dPjOYOqJOIWzEBqb+DJPgG5Ro9F82HfErYXWVmqoAoukEh56vaIBnX9BOaNEeAa
         B/bN98RFg+SamMOBS8stLyE6dvQILGpCwK3ARoUDW1Sg4ml6GLpmkp58x1HAyNxItAd0
         dy7m+8u//aD24BU8tEBI6ndQ/e8G/QAZLWrV/O2m3MLrvlE/LODonkz5x0taLDSGjAhs
         U9lJbQYiMjAMIONwJssbwJEJ+nM2uZQlC5WiY47i7b9iIs4vRmZNxjVGUdLIQ4/tVhIX
         f7sA==
X-Gm-Message-State: AGi0PuYxacS2vqMjbtt2MvcuX4Pp3hQh9YcKilHT0nFVhnTDLBtazSC6
	chbIzXVaXyg6ETZbFgZ3jpk=
X-Google-Smtp-Source: APiQypLzOMqnQJr4TgOj9FLPtQIhaNdxIVX2sdEmVXdMmaqiT32eUUZ5bsOhrwkeQWZY0c60fCKfRQ==
X-Received: by 2002:aca:ccc6:: with SMTP id c189mr3205539oig.161.1588698455644;
        Tue, 05 May 2020 10:07:35 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:363:: with SMTP id 90ls805857otv.6.gmail; Tue, 05 May
 2020 10:07:35 -0700 (PDT)
X-Received: by 2002:a05:6830:12:: with SMTP id c18mr3109813otp.363.1588698455094;
        Tue, 05 May 2020 10:07:35 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1588698455; cv=none;
        d=google.com; s=arc-20160816;
        b=0lInV2KkINN3dFB0XGhFePQCcAX/5MsXBPN0EUg4ztArxncRP/+slnti/6uYrRwONQ
         QnPgW+bWeoDtU3OsSjaggLh6ZFExrb4t+BZ50JLVqmlV5Sf9V1xmj9oMS7mVCA9V+MkP
         wJqxQ7vJw9fwOU9fBEU+NQCMKEhFcr5rIyGAs7yhPpuJv6y1Waym1ecQj1Rno26Iu+Sh
         XsFyO2FF4pgPIU1v9Qe+1DZ3ikBjGA95ljhEiR4K5mLBHuebjK/DHxs1BMvOY9JAUyiB
         hJibXHf7P4ZAR6+fKkw4rjsb9YUVHDKXPhryn/qWv2f14hatOXrZzk9TbcDw7iOX+nVb
         zcEw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=SwCBEJLwe7+6OV63AZ4GOUwDgwYhujIY1KxrxYevf8k=;
        b=PhUy0zgqGX8wLu5bPWZy6aVvaqhdra+qmQ+psseOXCQkrAq2dVnVX4M2toJ5ynyKME
         TzjzFcu1DSjYfpV7T2D1nUIXE2JXcL5c5vOm4fVBThxsLdzTLkIoh25Msae4XegNjY3k
         Ysx09DKd0BYMvr+KbhJ0Y+gTVMegrI9w76p9xKizekGl+AKtSw9USokzOO8jxiRoiiV4
         hX/gxYnTo37mZlZ99xpeZFQ12MgJv8wgssVbsBAwRX7Wenc+oMNYsN5VpoguUh5wJ61t
         OI2boa5f8IdE71pZvlc5ozYElQOlM0oReI8QRSypBo5TT1z1NcdhSoKGJ77aRY48S+lN
         S0tg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=AgMhYAYI;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::242 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x242.google.com (mail-oi1-x242.google.com. [2607:f8b0:4864:20::242])
        by gmr-mx.google.com with ESMTPS id f139si228630oig.5.2020.05.05.10.07.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 05 May 2020 10:07:35 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::242 as permitted sender) client-ip=2607:f8b0:4864:20::242;
Received: by mail-oi1-x242.google.com with SMTP id b18so313424oic.6
        for <kasan-dev@googlegroups.com>; Tue, 05 May 2020 10:07:35 -0700 (PDT)
X-Received: by 2002:aca:c646:: with SMTP id w67mr3335582oif.70.1588698454453;
 Tue, 05 May 2020 10:07:34 -0700 (PDT)
MIME-Version: 1.0
References: <20200505142341.1096942-1-arnd@arndb.de> <CANpmjNMtGy6YK8zuqf0dmkykZMt=qkxkZrZNEKde1nbw84ZLkg@mail.gmail.com>
 <CACT4Y+Zpp=+JJedhMpunuUh832eJFu+af-r8631Ar0kE2nv72A@mail.gmail.com>
 <CAK8P3a23XzLhZQNuFbeQhaSNru1abPwXV_mXR_P6N6Dvxm6jFw@mail.gmail.com>
 <CANpmjNOE+GUG7O=WaJKQg6rdUOn+YMBhdS8enNWkD_8mdtaSBQ@mail.gmail.com> <CAK8P3a36w+QFqik_sHS3T5+_DZ7XP9Y5BYqT72pnjC67T9Sn3Q@mail.gmail.com>
In-Reply-To: <CAK8P3a36w+QFqik_sHS3T5+_DZ7XP9Y5BYqT72pnjC67T9Sn3Q@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 5 May 2020 19:07:22 +0200
Message-ID: <CANpmjNPCZ2r9V7t50_yy+F_-roBWJdiQWgmvvcqTFxzdzOwKhg@mail.gmail.com>
Subject: Re: [PATCH] ubsan, kcsan: don't combine sanitizer with kcov
To: Arnd Bergmann <arnd@arndb.de>
Cc: Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Kees Cook <keescook@chromium.org>, Andrey Konovalov <andreyknvl@google.com>, 
	"Paul E. McKenney" <paulmck@kernel.org>, Ingo Molnar <mingo@kernel.org>, 
	Andrew Morton <akpm@linux-foundation.org>, Greg Kroah-Hartman <gregkh@linuxfoundation.org>, 
	Stephen Rothwell <sfr@canb.auug.org.au>, Thomas Gleixner <tglx@linutronix.de>, 
	kasan-dev <kasan-dev@googlegroups.com>, LKML <linux-kernel@vger.kernel.org>, 
	clang-built-linux <clang-built-linux@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=AgMhYAYI;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::242 as
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

On Tue, 5 May 2020 at 17:29, Arnd Bergmann <arnd@arndb.de> wrote:
>
> On Tue, May 5, 2020 at 5:20 PM 'Marco Elver' via Clang Built Linux
> <clang-built-linux@googlegroups.com> wrote:
>
> > > --- a/lib/Kconfig.kcsan
> > > +++ b/lib/Kconfig.kcsan
> > > @@ -5,7 +5,7 @@ config HAVE_ARCH_KCSAN
> > >
> > >  menuconfig KCSAN
> > >         bool "KCSAN: dynamic data race detector"
> > > -       depends on HAVE_ARCH_KCSAN && DEBUG_KERNEL && !KASAN && !KCOV
> > > +       depends on HAVE_ARCH_KCSAN && DEBUG_KERNEL && !KASAN && !(KCOV
> > > && CC_IS_CLANG)
> >
> > I wonder if we can just add this:  depends on !(KCOV &&
> > !$(cc-option,-Werror -fsanitize=thread -fsanitize-coverage=trace-pc))
> >
> > Similarly for UBSAN.
> >
> > That way, once Clang supports this combination, we don't need another
> > patch to fix it.
>
> Good idea. It probably get a little more complicated because kcov uses
> different flags depending on other options:
>
> kcov-flags-$(CONFIG_CC_HAS_SANCOV_TRACE_PC)     += -fsanitize-coverage=trace-pc
> kcov-flags-$(CONFIG_KCOV_ENABLE_COMPARISONS)    += -fsanitize-coverage=trace-cmp
> kcov-flags-$(CONFIG_GCC_PLUGIN_SANCOV)          +=
> -fplugin=$(objtree)/scripts/gcc-plugins/sancov_plugin.so
>
> Do you have any preference on whether we should make KCSAN or KCOV
> conditional in this case? It may be easier to move the compiletime check
> into CONFIG_KCOV_ENABLE_COMPARISONS and
> CONFIG_CC_HAS_SANCOV_TRACE_PC.

Whichever is easier. I think if we have a config that tries to set
both, but then one gets silently disabled, it likely already breaks
the usecase. It'd be nice if there was a way to warn about only one
being selected so that a developer can then go back and choose the one
they're most interested in (or change compiler).

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNPCZ2r9V7t50_yy%2BF_-roBWJdiQWgmvvcqTFxzdzOwKhg%40mail.gmail.com.
