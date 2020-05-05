Return-Path: <kasan-dev+bncBDEKVJM7XAHRBSUMY32QKGQERX7HDHI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x63d.google.com (mail-ej1-x63d.google.com [IPv6:2a00:1450:4864:20::63d])
	by mail.lfdr.de (Postfix) with ESMTPS id EB2B71C5B27
	for <lists+kasan-dev@lfdr.de>; Tue,  5 May 2020 17:29:14 +0200 (CEST)
Received: by mail-ej1-x63d.google.com with SMTP id dx16sf1451504ejb.10
        for <lists+kasan-dev@lfdr.de>; Tue, 05 May 2020 08:29:14 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1588692554; cv=pass;
        d=google.com; s=arc-20160816;
        b=ZPu2NGejr7NxMGGZJQtgd0lmko+MxxdBBd6h9ZA7TybqFPpwaJ15athElAVWpoFItv
         4cJ6B4KnxCpV6GJ02e1cwJkpriy9w9gD8X0ofDyt/iWXSC/0xQC6V/3/GxplKiVVeWPt
         QHeLU4ugS5Wt4DVOWOqDmEutE+BSGEcIGi0SWwazMfV/JH5rubehZLNsCeRUt8jhtUTK
         Y/zjluQQdy7qVxoX0ywS+9a8t8QR45GyXXWzx/EHDxTMcmRz60Zj1BPoU0F8nEXzj7ks
         op93WhjosIzEmJJ3rhXLmi5l6id4r19fZy63feqEqCd/qBYf4YErdrbUOTRYMVlvqCwG
         z0rQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=ZCb1ORZjB+7TTIJ45utgGF4Yw0jyDHLP11714Vbyoe0=;
        b=wYPvscABMBKtqKP68lR1mj1jyD+1ubel1q27H7f/PjJkg0pVgi5AhG3zFbKawuvmhP
         F32vA9CGlCgQBPMix9AXmKOLL1d8SxpjisV6FCeAK/OA9s2XJkUL8dbfv7Z4CqDIuYz2
         8YrJLwlfM/8WqsOr/ZeHkrvOH4SCe/RVNB523Rn0AaHWWwLtyhdJI72vbE7l43kKncMM
         I/r5gsSPAtObKL2/iT9u9UYWiy0o5bFtsgHDARe2unFVw0rYFa+aMZLdAwv8RaYVQagE
         vCt63gFnxiMv8+YzLacS6Biv2tOwCFpKBr0P51qDwBWItfYYIUUDpg3CB+9wrfnLMiIw
         BWkQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=neutral (google.com: 217.72.192.73 is neither permitted nor denied by best guess record for domain of arnd@arndb.de) smtp.mailfrom=arnd@arndb.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ZCb1ORZjB+7TTIJ45utgGF4Yw0jyDHLP11714Vbyoe0=;
        b=SU9xfTEJQWBE3YRLR6E5OSSBFYA494ZA/h+24sYYvPdCJDbY+O/GmfrGZ3+MU0s1gh
         PV3NmbMnfKkqwGbtIriH2Yecm80yvd7B+1LC+TwC1i3Mvz9Vp+UB/1HYGrxbYDFT2nO3
         tJtndoV8grwtX23bA6kemqAqRL/AUL846FraQs5Qi2xGtNxywWc65qgG1Ye3ZwdkU2J3
         qOdq+8upvt9gqGqMVEQDqLmgBwHsDuGwZJNR9et1xRoegH7sdKNv0nER71ZIVeXxGgHR
         KCkdrXuz7BiP8bBQT5yvX9hAywH6+P5HnMyXdjncGCIYkF5lUAYMUF8ZdbbbuvIU9s++
         WbnQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ZCb1ORZjB+7TTIJ45utgGF4Yw0jyDHLP11714Vbyoe0=;
        b=kQ0OXKgKQ51+FlPS/JRoKp7wKUvksTJlZs3+TBLWmimjrgNJnlPnBexGU/opD6ai9h
         OEeuAT5S15rBO9PcHHAYMW74z13xjaXS6jwNJdb3zu8d2HcDqQN2Hfe75b9S8RAnMb9O
         uTWVTJZ1Z5XIWW0YKLVTBGEn7hh9Q4ubiKd1jV176SQ6ubaqQxcymyqdOxBKLFdXc2Sc
         UZD6b281E2Fx34iHtMKC5bm7yWMaH4CmGthGHD52divFryHMh4Yg69N3EhO/AwhcP5vg
         /2791zGArLGfnMe6D28I9Yjb+BDe2ixEnJ9P/dv3zpkf3KHqLwtzSp5BJIoNHPzPOsc4
         NN8Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AGi0PuYhlvLjsrkWUqaGUPP0z4V78RiPSR8Mh1rc2xQ+tBwi7zHXWcaO
	/ZiWF8BdGjLS0EBHnuIZW8k=
X-Google-Smtp-Source: APiQypKAasugKrYzd0z0f6vsXM9+C5bFyRW6WEp/G98p9WeA1BsHNvuj6mElPmpoS48ksSdugrBbzw==
X-Received: by 2002:a05:6402:379:: with SMTP id s25mr3275122edw.69.1588692554597;
        Tue, 05 May 2020 08:29:14 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:1a58:: with SMTP id bf24ls1426257edb.2.gmail; Tue,
 05 May 2020 08:29:14 -0700 (PDT)
X-Received: by 2002:aa7:c38a:: with SMTP id k10mr3210707edq.74.1588692554038;
        Tue, 05 May 2020 08:29:14 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1588692554; cv=none;
        d=google.com; s=arc-20160816;
        b=rZvLhvjp4uVhzgT4mkM3I94EpnPyQcsm1qpoW2Pr7CxHYC2e431mar53H650zgtTcF
         XUCBh9Uontuk18JEweMSPsvQFN31hLcphIfbLd2bQEWpT7GiLjxDrQl4kjh6O7PvtyEG
         lYVnRqKIrE2r60lUIcLah8ko2QiQEbYceZQgCTHdF6A0ecG049fw26PO7j3DHTGFmAfn
         Mp5TcdtAK96iPkePrLhs3L6EIdhzL+ruw5DC7HnjtK6UsufI8Vdg6ZMgHEq8RwuZ0pSL
         OKJ6rlWPkiWDruSt1gF939nxakECdafxC8miBdGNbkAam3OYQ4nb7FtdR5FhLwfLZiiL
         AHbA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version;
        bh=mLTAfVYvu6D9H2Ch2Co82pMdxfAUJOTBn9LCzwwrSCU=;
        b=FC5qI63YJSWnXvMpLnx9l8e8RbHSN5wplF2YzLLVpIfK2StwFRXo/gEKO1/Bxi6xGP
         0kj+aRxHJR1ETo56HYyswDGHfWqAdxcSv2iQghtgbyyOVIUkH5zvCHXF/Qw8KzscjRA8
         k15t7scHN7frqjxY7nkzoKcCAq7uS00RWG8WgNjI6EkhVnwhXqjfJQvxXhFPKqofFtt0
         Kz5/x7jNBAjtIyHFmCSgjn7nhj5R2iPLQZ8HcNqIS/bIo+GkUWmPIHlu8gTSQDL+y1Cm
         JYYRgHGqF7hTj8LQYCfNJkjCVg8TPnR7yVkie1MZUWPg7ALP6/WfEcsmIU+Ms40UNcL8
         SWmQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=neutral (google.com: 217.72.192.73 is neither permitted nor denied by best guess record for domain of arnd@arndb.de) smtp.mailfrom=arnd@arndb.de
Received: from mout.kundenserver.de (mout.kundenserver.de. [217.72.192.73])
        by gmr-mx.google.com with ESMTPS id by3si52347ejc.0.2020.05.05.08.29.13
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 05 May 2020 08:29:14 -0700 (PDT)
Received-SPF: neutral (google.com: 217.72.192.73 is neither permitted nor denied by best guess record for domain of arnd@arndb.de) client-ip=217.72.192.73;
Received: from mail-qk1-f180.google.com ([209.85.222.180]) by
 mrelayeu.kundenserver.de (mreue108 [212.227.15.145]) with ESMTPSA (Nemesis)
 id 1MqrwN-1ijEdM1lWz-00mqDp; Tue, 05 May 2020 17:29:13 +0200
Received: by mail-qk1-f180.google.com with SMTP id i14so2643084qka.10;
        Tue, 05 May 2020 08:29:13 -0700 (PDT)
X-Received: by 2002:a37:aa82:: with SMTP id t124mr3905009qke.3.1588692552175;
 Tue, 05 May 2020 08:29:12 -0700 (PDT)
MIME-Version: 1.0
References: <20200505142341.1096942-1-arnd@arndb.de> <CANpmjNMtGy6YK8zuqf0dmkykZMt=qkxkZrZNEKde1nbw84ZLkg@mail.gmail.com>
 <CACT4Y+Zpp=+JJedhMpunuUh832eJFu+af-r8631Ar0kE2nv72A@mail.gmail.com>
 <CAK8P3a23XzLhZQNuFbeQhaSNru1abPwXV_mXR_P6N6Dvxm6jFw@mail.gmail.com> <CANpmjNOE+GUG7O=WaJKQg6rdUOn+YMBhdS8enNWkD_8mdtaSBQ@mail.gmail.com>
In-Reply-To: <CANpmjNOE+GUG7O=WaJKQg6rdUOn+YMBhdS8enNWkD_8mdtaSBQ@mail.gmail.com>
From: Arnd Bergmann <arnd@arndb.de>
Date: Tue, 5 May 2020 17:28:55 +0200
X-Gmail-Original-Message-ID: <CAK8P3a36w+QFqik_sHS3T5+_DZ7XP9Y5BYqT72pnjC67T9Sn3Q@mail.gmail.com>
Message-ID: <CAK8P3a36w+QFqik_sHS3T5+_DZ7XP9Y5BYqT72pnjC67T9Sn3Q@mail.gmail.com>
Subject: Re: [PATCH] ubsan, kcsan: don't combine sanitizer with kcov
To: Marco Elver <elver@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Kees Cook <keescook@chromium.org>, Andrey Konovalov <andreyknvl@google.com>, 
	"Paul E. McKenney" <paulmck@kernel.org>, Ingo Molnar <mingo@kernel.org>, 
	Andrew Morton <akpm@linux-foundation.org>, Greg Kroah-Hartman <gregkh@linuxfoundation.org>, 
	Stephen Rothwell <sfr@canb.auug.org.au>, Thomas Gleixner <tglx@linutronix.de>, 
	kasan-dev <kasan-dev@googlegroups.com>, LKML <linux-kernel@vger.kernel.org>, 
	clang-built-linux <clang-built-linux@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Provags-ID: V03:K1:yXPjj7RSTHy8nvPh0sjlznjQGUgILFaAll8TjnoW91chldM8MJQ
 RMhhLijyMrp8sdGgF+1PyI0+sdkzQ0LD4fBBwDy+JrBQbirFD6Ki719H4loB5LEeYHuXXUV
 5GVl6b0dxqM5OyN/K0q+Rz4lOQXGspgT41wG7jEu1mQUqBae2+tkWdWJjh9cQXj/NfqnBBg
 zvTNm+6Tb+DCbDFAailsA==
X-Spam-Flag: NO
X-UI-Out-Filterresults: notjunk:1;V03:K0:4tNF2IvDNKo=:MRazf2aTsNfc+hGbcGVL93
 4WNC7klZLZY7ZIWUeVLBnNA3LsjX9MocBRo8JxVEgAGsmFifn9j96TbKRrdK18+09O9DqBsPZ
 UIcPMazEbIsqE1YZvK1FptzPhmeeSu7tHEhUhywJjhGe38GBN9ylXUg5z3cA0nAiN4vDMXeeu
 kcaZQF7lhhThWvBcr5owmd/vXUWyeqcxuX3MAHFj4h/DKVAnuIbMe9xF/pl5JxehvSko7mcwI
 6zX68q1QMoon8+/tYXvcMzGDhBHmXVw40RchLJE8uqQhjmraGiMs747B6b1YxvtOqYwVuzyK9
 GLIH5rIY/522l4lmAoHeo0WoAIcfaH91kcdUPZ0LPrVUw+YqWJVbX/DkaAVwKee7lNIdecfVa
 5ChSVNnLmz8QegwTK/1EV7xbQVJzC2IYQA8p7/EU5MC5Rav4OnsF43+/rIIey3lz+1pjh+cx1
 pxpcQH2YlRh2wSQ5bwgzIiyot0iTZ7GFMBvjQXvYPtg+8WsZKkUodXeT4Mw4YPaPog8NCv4OF
 okl6lTmlk9LqT8/027qOFC1ORkIgawNRdGZ7oakGpMS9ylm57RT92X1lS1Z14PyXHeTh7iQ33
 b9otO9XfBovv2wY7xTdoMjG1sFkp3WkJGEM00CSC4Gac3OKQP8PMphbssY8JCdM+sTsy5R8pW
 VvPlWIpGLYrHos/WkhekE/h2YADB+6prLSufD4JRlGYItWWf+0kFPJm/wdQMbyv1BTMq7SSt5
 dhOgkTApVyzQ3QY06QGJUpPQSbpkcU6X2J3lJNW64xbUdiH9Mavx6oZjoE8eefZpJaSy5ceyl
 eWKj+E1E/nFGBC/PdpiebGEET+d/12U6OAaGf3UYFljFxquBpA=
X-Original-Sender: arnd@arndb.de
X-Original-Authentication-Results: gmr-mx.google.com;       spf=neutral
 (google.com: 217.72.192.73 is neither permitted nor denied by best guess
 record for domain of arnd@arndb.de) smtp.mailfrom=arnd@arndb.de
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

On Tue, May 5, 2020 at 5:20 PM 'Marco Elver' via Clang Built Linux
<clang-built-linux@googlegroups.com> wrote:

> > --- a/lib/Kconfig.kcsan
> > +++ b/lib/Kconfig.kcsan
> > @@ -5,7 +5,7 @@ config HAVE_ARCH_KCSAN
> >
> >  menuconfig KCSAN
> >         bool "KCSAN: dynamic data race detector"
> > -       depends on HAVE_ARCH_KCSAN && DEBUG_KERNEL && !KASAN && !KCOV
> > +       depends on HAVE_ARCH_KCSAN && DEBUG_KERNEL && !KASAN && !(KCOV
> > && CC_IS_CLANG)
>
> I wonder if we can just add this:  depends on !(KCOV &&
> !$(cc-option,-Werror -fsanitize=thread -fsanitize-coverage=trace-pc))
>
> Similarly for UBSAN.
>
> That way, once Clang supports this combination, we don't need another
> patch to fix it.

Good idea. It probably get a little more complicated because kcov uses
different flags depending on other options:

kcov-flags-$(CONFIG_CC_HAS_SANCOV_TRACE_PC)     += -fsanitize-coverage=trace-pc
kcov-flags-$(CONFIG_KCOV_ENABLE_COMPARISONS)    += -fsanitize-coverage=trace-cmp
kcov-flags-$(CONFIG_GCC_PLUGIN_SANCOV)          +=
-fplugin=$(objtree)/scripts/gcc-plugins/sancov_plugin.so

Do you have any preference on whether we should make KCSAN or KCOV
conditional in this case? It may be easier to move the compiletime check
into CONFIG_KCOV_ENABLE_COMPARISONS and
CONFIG_CC_HAS_SANCOV_TRACE_PC.

      Arnd

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAK8P3a36w%2BQFqik_sHS3T5%2B_DZ7XP9Y5BYqT72pnjC67T9Sn3Q%40mail.gmail.com.
