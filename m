Return-Path: <kasan-dev+bncBCMIZB7QWENRBR4LW72AKGQE5NQVG7I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd40.google.com (mail-io1-xd40.google.com [IPv6:2607:f8b0:4864:20::d40])
	by mail.lfdr.de (Postfix) with ESMTPS id 06EEB1A222A
	for <lists+kasan-dev@lfdr.de>; Wed,  8 Apr 2020 14:38:33 +0200 (CEST)
Received: by mail-io1-xd40.google.com with SMTP id n15sf5950536iog.8
        for <lists+kasan-dev@lfdr.de>; Wed, 08 Apr 2020 05:38:32 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1586349511; cv=pass;
        d=google.com; s=arc-20160816;
        b=tgXQzDgXYNY/HaglTPsMPniOFayQ3AKuo+kpv5kq83YX0yLkFogOdgcKyP75L1MLZD
         LLHA4llB34JdHm8MUh+to9+gM2KTtxJQlw3Bp/IqpqgtTpH9y/wKjR0wIsQ6dg2XSqUz
         I8zRhedVTO2+/KRBFHsPWj4jWAFyafozaEElmNLc3AB2xXtvfy5pxpCo4BrQU+p0s1jX
         OsH2dbPXv0wKVeCovcjNoRrcR2KGlRyfU+9BdkeNjxWoFhGGdauaht4mycOBQORfu0GQ
         K0ndzKQ8OnOLSKF7ku385umHAd2Oy0bSThRpHDbGYcTqn3tNTPLw9TPByXkOOz0kw8bo
         zh6g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=1zK74G9G70jkky6wXheL9zcEBCS58654ERoBuOzErcs=;
        b=E51zPymO3hSLYUW6Qs6hnMP/tX3btBLL8+RqzUZmBHoBVCdz8F2m3G+IeuW0LaJdYJ
         nOjRgYrMvuolVMTZPjIxweZ59BWZApWTGMsb7p3ifiFKZxK/4FJy2ZjaGngukEJiZvKB
         0+myV/8EqeS2OthuAJz763GpGsgtFh1PcDDxyMSRkC307XRrKAUfzOixjOs5/Tpst1jF
         vXI7B5Dl7H8eWseQtoZ+hZDP3W7pbuPUYuW7KFgL1eA86d4sMWEpEWNUt++FC6q5S53M
         QQC4tnxFfAiPwm2JxfY9eqU/aZO+Unvuqm2INmtDSwJF286d9mDB8in57QYxhj6XSB7R
         PJSQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=aoGUbSax;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f44 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=1zK74G9G70jkky6wXheL9zcEBCS58654ERoBuOzErcs=;
        b=YUCF4ShG9E9s76kE3UvKKyDMW5sQ4WQc2go/4/HSzGYcxLOa1mSgSsixxNieaPrCTE
         D7crnLl8xkH2oUyCvv0cWobfJiozkqE/+/6WvEvPNTIcp5rflIIArew2ZBuOK0U100EM
         hrkBg7owH0N8ZWM52p/HtHY9N7cWH7hABsW0Oy3eK2QfgEI27qBJb2As475Jc3RxMuPQ
         EAEguR49JlqwPEBqBxqch350CplSeYve2LaK5S+maUWGoilKAfwpipr5zoJCiOQhWTnP
         YRpKAiEZUp11js9IH2O8+LK9W3Xg6S9g7l01i+9VPDl6TmsDiRMNQLt6EmnLPonPFjuQ
         kckg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=1zK74G9G70jkky6wXheL9zcEBCS58654ERoBuOzErcs=;
        b=L6uARPW7SpJZW7ZxgC6WXBATyOb2caoP21fJnRvFAukkXwY8SVJLqzU4Zfn6vaPlLx
         oZAU+W/X8+EI0+BWWXpIrJXaqJnAEITi4N+tyARdb8P15J9+YaCOw6R3R+139f/TWBuS
         73z9jggE0As5TXAJek6pEQMKhKX2lp2e56cuWcTHIKfRHRacNrcCIl5bVlMG1vKMH8JF
         Z9UbUnUttrzBWqnpr2e8vtQdljz0jUiVUp21S6aerrbdE1FmMimqjutm7TqTIR1XrFcV
         4LLhh1YYBjd01u8F/BNbEBC3ynW/UGhUpoABcDBhJTmH1DQnLVoW/GFGfl1+N9GB2qzI
         WVyg==
X-Gm-Message-State: AGi0PuY6hDKISFlWOwT7i97Thx30F8zczpqlxLedrf41029bK4/K1/R5
	yuEzt3hxRR14eRQ+IsmNBbc=
X-Google-Smtp-Source: APiQypLkGIIsA9huoosOniIKO9WoRPX6WJTTjehetVxXmgFqFVL0WZpN/fJIdZgfgU0aQXYbEfqVbw==
X-Received: by 2002:a92:d18b:: with SMTP id z11mr7703642ilz.76.1586349511580;
        Wed, 08 Apr 2020 05:38:31 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a02:ba01:: with SMTP id z1ls1307688jan.7.gmail; Wed, 08 Apr
 2020 05:38:31 -0700 (PDT)
X-Received: by 2002:a02:205:: with SMTP id 5mr6341569jau.78.1586349511269;
        Wed, 08 Apr 2020 05:38:31 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1586349511; cv=none;
        d=google.com; s=arc-20160816;
        b=bG9oB0VYCewnAPft0K9J2DxxAAELmQy4PMNNiVtvVEN45lK7pJYiERx3EfoI9IFZXX
         YWOnJNeVvNdV6eO6QHimPMGAgvUIvEujtCXjE22CWavj2PppS69FJO1x5pUncCUQK9He
         bD025PnO9E0c6cM5UoEG0KcsoX/oP2yWZSD4MrbqIg9aRWudHPRtluBNrC4e4hk0vxh7
         lAyHJDOji/VGDX6XkkHKbfgEBERW068upau1z6+JLkdRisAjSYg4sIU1P+w4blI/IE34
         /zeycDpkn83czzuBLhHfdxLG9BmotVy3PQuGQMVxOJj9uWkwmNZTD4wFxbkHFSIop1aU
         sI+w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=GaX+h4JmWtvUrkKPghwKODfVGkAZ+p/06TMC68HLdYE=;
        b=Gh/7WdQcay4miw+icnrVuvO4MYAKWzicAftOh5aDis3eGviaaZ0q1u7TZXWprQugkd
         mCpAw6sdLqX9HUXXqo2CmZvg3JZ4hu94JYjI+dSluysfZa2YqJaFVs0kANtHSEHLIxUy
         6OJ7RuPWVuGAXuC+Ahb26Gwy/jDMJK6N/57tDazcxqq/W8sj0gihNX+Z4x12PYzqf9b5
         PKfIkVSYQKbJsvMfN4xe0jh66uwu83pDh6vLTx5CVFYKD/j3wKP46Z2GAbddyS32WtmN
         S4S6A0u4rFWeTyy/tDTK2w/Zwy8+0VWptNx9vduH5K6lWu4EfxR7j1qq/LJcoxrz6rIb
         PjuQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=aoGUbSax;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f44 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf44.google.com (mail-qv1-xf44.google.com. [2607:f8b0:4864:20::f44])
        by gmr-mx.google.com with ESMTPS id u9si89805iln.5.2020.04.08.05.38.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 08 Apr 2020 05:38:31 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f44 as permitted sender) client-ip=2607:f8b0:4864:20::f44;
Received: by mail-qv1-xf44.google.com with SMTP id k9so2794726qvw.7
        for <kasan-dev@googlegroups.com>; Wed, 08 Apr 2020 05:38:31 -0700 (PDT)
X-Received: by 2002:ad4:5051:: with SMTP id m17mr7380034qvq.122.1586349510379;
 Wed, 08 Apr 2020 05:38:30 -0700 (PDT)
MIME-Version: 1.0
References: <78d7f888-7960-433f-9807-d703e57002bf@googlegroups.com>
 <CACT4Y+ZvX1Cs1SJppVfLXyV9F4hra=JdBaQCqBTeFX3++f48kQ@mail.gmail.com>
 <CACT4Y+abK5o34h_rks7HMivmVigTG3CM9X93MOt9d7B6dxY_9w@mail.gmail.com>
 <CABDgRhumwQxxpQDmGq6=zf9Xi4DY4tM=_kOdbf=SFvfPYMNYrQ@mail.gmail.com>
 <CACT4Y+aqy0MgJntoKPcjoxnyH3w4n0UW5yxFJX-prm-Zgqn+0g@mail.gmail.com> <fe8bfc10-2d1c-4f47-9f11-df4d3c77a7d7@googlegroups.com>
In-Reply-To: <fe8bfc10-2d1c-4f47-9f11-df4d3c77a7d7@googlegroups.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 8 Apr 2020 14:38:18 +0200
Message-ID: <CACT4Y+ZNfHQRP9NJE3LP+8Q9UOutDPs+Oa8wYEA-dhWi-6qU9w@mail.gmail.com>
Subject: Re: [libfuzzer] Linker fails on finding Symbols on (Samsung) Android
 Kernel Build
To: Johannes Wagner <ickyphuz@gmail.com>
Cc: kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=aoGUbSax;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f44
 as permitted sender) smtp.mailfrom=dvyukov@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Dmitry Vyukov <dvyukov@google.com>
Reply-To: Dmitry Vyukov <dvyukov@google.com>
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

Check if you have EXPORT_SYMBOL for that function. That what would
cause linker failures for modules.

On Wed, Apr 8, 2020 at 1:30 PM Johannes Wagner <ickyphuz@gmail.com> wrote:
>
>
>> >> It looks like you have an old kernel and a new compiler.
>> >> You either need to backport KASAN patches for stack support, or take
>> >> an older compiler maybe, or maybe disabling KASAN stack
>> >> instrumentation will help.
>
>
> Thanks for the Pointers Dmitry,
>
> i backported the commits from your suggestion in another thread [1], and it resolved a lot of issues except for the symbol
> '__asan_set_shadow_00'
>
> which is like the others defined in the mm/kasan/kasan.c and exportet in mm/kasan/kasan.h file.
> i tought maybe the macro fails because of the 00 so i also tried expanding this macro myself. but did also not work.
> may it be a missing/missplaced import?
> CONFIG_KASAN_STACK=0
> did not lead to a successful build as well as using older compiler toolchains.
>
> [1] https://groups.google.com/d/msg/kasan-dev/xXmG0cnIkaI/LQ9o0BmjAgAJ
>
> attached the whole remaining error:
>   MODPOST vmlinux.o
> WARNING: modpost: Found 2 section mismatch(es).
> To see full details build your kernel with:
> 'make CONFIG_DEBUG_SECTION_MISMATCH=y'
> drivers/misc/modem_v1/modem_main.o: In function `modem_probe':
> /home/kerneldev/kernel/drivers/misc/modem_v1/modem_main.c:1103: undefined reference to `__asan_set_shadow_00'
> drivers/net/wireless/broadcom/bcmdhd_100_15/wl_cfgvendor.o: In function `wl_cfgvendor_send_nan_event':
> /home/kerneldev/kernel/drivers/net/wireless/broadcom/bcmdhd_100_15/wl_cfgvendor.c:5475: undefined reference to `__asan_set_shadow_00'
> drivers/net/usb/r8152.o: In function `rtl8152_up':
> /home/kerneldev/kernel/drivers/net/usb/r8152.c:5466: undefined reference to `__asan_set_shadow_00'
> drivers/net/usb/r8152.o: In function `r8153_init':
> /home/kerneldev/kernel/drivers/net/usb/r8152.c:5953: undefined reference to `__asan_set_shadow_00'
> drivers/net/usb/r8152.o: In function `rtl8153_up':
> /home/kerneldev/kernel/drivers/net/usb/r8152.c:5495: undefined reference to `__asan_set_shadow_00'
> drivers/net/usb/r8152.o:/home/kerneldev/kernel/drivers/net/usb/r8152.c:5093: more undefined references to `__asan_set_shadow_00' follow
> Makefile:1142: recipe for target 'vmlinux' failed
> make: *** [vmlinux] Error 1
>
> --
> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/fe8bfc10-2d1c-4f47-9f11-df4d3c77a7d7%40googlegroups.com.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BZNfHQRP9NJE3LP%2B8Q9UOutDPs%2BOa8wYEA-dhWi-6qU9w%40mail.gmail.com.
