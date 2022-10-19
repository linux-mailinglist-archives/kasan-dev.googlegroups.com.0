Return-Path: <kasan-dev+bncBCCMH5WKTMGRBAGVYCNAMGQEIBHBKHY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3c.google.com (mail-qv1-xf3c.google.com [IPv6:2607:f8b0:4864:20::f3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 27E55604DBD
	for <lists+kasan-dev@lfdr.de>; Wed, 19 Oct 2022 18:49:06 +0200 (CEST)
Received: by mail-qv1-xf3c.google.com with SMTP id jn13-20020ad45ded000000b004b1d055fbc7sf10929728qvb.2
        for <lists+kasan-dev@lfdr.de>; Wed, 19 Oct 2022 09:49:06 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1666198145; cv=pass;
        d=google.com; s=arc-20160816;
        b=O7jxVqPwBkCkX+N43e1/oqKHVLoMGh2d4pd1I+z11mLAGdghvPBdKdkNau82qXzTJl
         rVtFb1l0HKDzdOuM7qp+WjAc6uhnTIyDFRS5DMNBDJhv/dqy7P0kCaxFa2jEfoYcAqMG
         I2zWPMdWBZblHyWMuyAnOEtuuxyX6ZPhTPm4WGgtu3nyqhYe4dSr1VtOgmfziTdcmxSw
         HvyzExjBlClqDEHUTKwcbJLfawhRhzuppN2xSYDqNI6+XFIxjZFM7d7v84scKsMX5PMo
         LYZiav7vgtLADRY7yTCLTM0yZ2FTeA0cicrrnMgUvu7sGSHGZRbxDyG0VFGxoaPYODYo
         ihqw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=+iWP4pKL2bRZq+3xlArjmTN8sZlip7x6MhQHZ4SjJ/A=;
        b=XYuVxZKiruIPNVPEVT7JDc4oJnP7aLZgYLUrJ2P1aWwfitxMhZxrxozc5pF+x19NQ5
         QbCqn0QokhbyPHvUHzrzbv5fTf4oj6Mg/zV9bsp2vRV0V0wA5vtpuJKp1eQukO7DWXkX
         PYnqoF4+VcB5nlJJw1j0iPvDPkx3wnp7nU1V4rIMChvMIscX5wEAiInHvMrCU37ED0BF
         phuzTq4hvzvwHD/IyZJVhbWhuizpRH7aPEykHXxc4DkTkDu70ySM/wJr1QxZMDvyqES1
         OA3wPr6PRpINj5HGqBK9WloxpjsCiQnZCtqlcrtmbxi1JyaqcwUSohBLo7uSvo98o4gU
         +M5w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=epFsZjbP;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::b31 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=+iWP4pKL2bRZq+3xlArjmTN8sZlip7x6MhQHZ4SjJ/A=;
        b=o6brwSFSMdxiu9h7wHCHs9P7+xYe8sMGMGi8FdJh/zurkt3NBQvn/3IUdCWFmh66ta
         ySXDG5a4sCyTAbH2aOrNWcOnr0aIiSH14Mw8sEy7mxNwzGMu7/s1ab0G7k3AnfAGMC8n
         Wukbnmzq2QxfiiSjyRRETP4klTtOi09m4V1z9NabTTa2zlw6nb6cSl+astshnkNKXfYo
         sOk7Yog5nmhlSd7JezTx+MaGU9abb3lfiUQ2VAEu42D+zW65+CndcnTn4gLqEOpxhtcq
         K04ZBU/HSlELPfe1h/ZN9lepv5+6xm3KJ4mslOXJkbmPUVscmgHhLGXj2TfH2yfJOyhE
         Qpsw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-gm-message-state:from:to:cc
         :subject:date:message-id:reply-to;
        bh=+iWP4pKL2bRZq+3xlArjmTN8sZlip7x6MhQHZ4SjJ/A=;
        b=KTj3iWKonhr3heuPlBIPD2eqoPbQDpktOZR71ZGCTAiTNNsXWpErv78nW7IGRVTQim
         DQ9UpUgd1XPW7DaYsxy/CfVa3UBQ6ODc69Mu/hV1Nakde2T4YeExcbBFkqEDBihOh1AQ
         IH532BJSMrrZMWhR1H8GPXQ/7yq4G8RZVTGSw45kk6aUNBIdTY15qF463GzCKydp2Sc4
         AFM/pCIlMEGCccQV/Qzjq3njMg9ZnAB68w89WnTVCpUHjWeB6kXpIR+HS5jgkG2OIt/P
         52XS6tLFbtBMOynxYZs7YmrFl5LXxwdCovARVrEzpGpy/VDYiAeLUwn1zrSuUTtbHm1C
         DoMw==
X-Gm-Message-State: ACrzQf2SvjFPa40YtEhsDFZQtnC2D2xJ+YbCnPk1W5+DVVt6Vuq2T7Rz
	SAkoRzw7wTMvoweJBOF2Hqg=
X-Google-Smtp-Source: AMsMyM5ymLsaAxZPHdOaZwmPiCN1OuByVq/23S7Wew+k0KFOQI2j+3m1YIY1IFBnrZ7Qqp0daX96lg==
X-Received: by 2002:ac8:4d5b:0:b0:39c:b6d2:b631 with SMTP id x27-20020ac84d5b000000b0039cb6d2b631mr7246548qtv.487.1666198144980;
        Wed, 19 Oct 2022 09:49:04 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0c:f0c3:0:b0:4ad:3c6e:9c05 with SMTP id d3-20020a0cf0c3000000b004ad3c6e9c05ls8938011qvl.11.-pod-prod-gmail;
 Wed, 19 Oct 2022 09:49:04 -0700 (PDT)
X-Received: by 2002:a0c:f349:0:b0:4b1:a0f5:4a2f with SMTP id e9-20020a0cf349000000b004b1a0f54a2fmr7344024qvm.112.1666198144465;
        Wed, 19 Oct 2022 09:49:04 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1666198144; cv=none;
        d=google.com; s=arc-20160816;
        b=f/VZ0lVvId20cDyqneMqpUQitFgh9cDfJJnjpEzWXjyLyZykhcC+wizTkBqyTeGBFO
         TDXNRAhYZIxlCu3Nb2wU7dzEuPt2fHeIWZPqn6uz3jJoRc1YJ/y0DgBEMTy6mV4kLDJs
         62g+WyzgEIwEXM86E9U4eDcuRXhQ4DTftDAYarUA6d+3B1ycoO3DUkI1ym7meG3gUiM8
         qVcprQJJZvfe3h6rAR4P2QYHHqKXG+sgT/V3fVwKc3f4fC9hA1y7gvJSWHB0qMs8t+no
         wS7oecv1Esha+Cj+zVNFaYVD6lRWvxvFoJethsa/daWvrbkb8OEjJI+IibxOg11DdZ1z
         xUNQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=z9ZfzDpEuznz7JDO0MpUy4J66NH5NE0QVJuq6p+mpt0=;
        b=ubDe5Co1vMg7ZDV7dhVjeoPbzmEtv++vgiwf3v0TtdOxEz96/5FxNM5/uxYYhDNGh2
         ovK3BW7WIgQLh0uX5o4Disn36c8sg+FvpIdmnYcpAdufIm2kBFAI3HgY2BRFKgjO3yMQ
         P8k9jK5M7y/0jGAiFjxtsbuAU2llnZwr21toBigCqTsw3g9iuZSYidYUQgoNKL4VDJoY
         DeAzKpslGg1j2BXKebftK5Uy4ciL/wbZx7glWofA6wtQjIftkDQ8R/lJwYfy1kKQItrp
         BCOXFENBWxJwrVIWfBfq1eG2cXAuboldLbiKmqtjBkZuwCf3GX/sb654G1W8FKmqBvud
         dlsA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=epFsZjbP;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::b31 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb31.google.com (mail-yb1-xb31.google.com. [2607:f8b0:4864:20::b31])
        by gmr-mx.google.com with ESMTPS id 17-20020a05620a071100b006eea4b5abb0si680108qkc.0.2022.10.19.09.49.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 19 Oct 2022 09:49:04 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::b31 as permitted sender) client-ip=2607:f8b0:4864:20::b31;
Received: by mail-yb1-xb31.google.com with SMTP id f205so10401000yba.2
        for <kasan-dev@googlegroups.com>; Wed, 19 Oct 2022 09:49:04 -0700 (PDT)
X-Received: by 2002:a25:9d0a:0:b0:6bc:2641:19d4 with SMTP id
 i10-20020a259d0a000000b006bc264119d4mr7252756ybp.388.1666198143952; Wed, 19
 Oct 2022 09:49:03 -0700 (PDT)
MIME-Version: 1.0
References: <Y1AZr01X1wvg5Klu@dev-arch.thelio-3990X>
In-Reply-To: <Y1AZr01X1wvg5Klu@dev-arch.thelio-3990X>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 19 Oct 2022 09:48:27 -0700
Message-ID: <CAG_fn=WYnfNHC3S1S=mCTKTnzL=UuH7Oz4W3HjsTXEQUtjrxtw@mail.gmail.com>
Subject: Re: -Wmacro-redefined in include/linux/fortify-string.h
To: Nathan Chancellor <nathan@kernel.org>
Cc: Kees Cook <keescook@chromium.org>, Andrew Morton <akpm@linux-foundation.org>, 
	linux-hardening@vger.kernel.org, linux-kernel@vger.kernel.org, 
	llvm@lists.linux.dev, kasan-dev@googlegroups.com, linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=epFsZjbP;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::b31 as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

On Wed, Oct 19, 2022 at 8:37 AM Nathan Chancellor <nathan@kernel.org> wrote=
:
>
> Hi all,
>
> I am seeing the following set of warnings when building an x86_64
> configuration that has CONFIG_FORTIFY_SOURCE=3Dy and CONFIG_KMSAN=3Dy:

I was also looking into this issue recently, because people start
running into it: https://github.com/google/kmsan/issues/89

I have a solution that redefines __underlying_memXXX to __msan_memXXX
under __SANITIZE_MEMORY__ in fortify-string.h and skips `#define
memXXX __msan_memXXX` in string_64.h, making KMSAN kinda work with
FORTIFY_SOURCE.
Dunno if that's necessary though: KMSAN is a debugging tool anyway,
and supporting it in fortify-string.h sounds excessive.

So I'm fine with disabling FORTIFY_STRING under KMSAN, unless someone objec=
ts.

>   In file included from scripts/mod/devicetable-offsets.c:3:
>   In file included from ./include/linux/mod_devicetable.h:13:
>   In file included from ./include/linux/uuid.h:12:
>   In file included from ./include/linux/string.h:253:
>   ./include/linux/fortify-string.h:496:9: error: 'memcpy' macro redefined=
 [-Werror,-Wmacro-redefined]
>   #define memcpy(p, q, s)  __fortify_memcpy_chk(p, q, s,                 =
 \
>           ^
>   ./arch/x86/include/asm/string_64.h:17:9: note: previous definition is h=
ere
>   #define memcpy __msan_memcpy
>           ^
>   In file included from scripts/mod/devicetable-offsets.c:3:
>   In file included from ./include/linux/mod_devicetable.h:13:
>   In file included from ./include/linux/uuid.h:12:
>   In file included from ./include/linux/string.h:253:
>   ./include/linux/fortify-string.h:500:9: error: 'memmove' macro redefine=
d [-Werror,-Wmacro-redefined]
>   #define memmove(p, q, s)  __fortify_memcpy_chk(p, q, s,                =
 \
>           ^
>   ./arch/x86/include/asm/string_64.h:73:9: note: previous definition is h=
ere
>   #define memmove __msan_memmove
>           ^
>   2 errors generated.
>
> I can see that commit ff901d80fff6 ("x86: kmsan: use __msan_ string
> functions where possible.") appears to include a fix up for this warning
> with memset() but not memcpy() or memmove(). If I apply a similar fix up
> like so:
>
> diff --git a/include/linux/fortify-string.h b/include/linux/fortify-strin=
g.h
> index 4029fe368a4f..718ee17b31e3 100644
> --- a/include/linux/fortify-string.h
> +++ b/include/linux/fortify-string.h
> @@ -493,6 +493,7 @@ __FORTIFY_INLINE bool fortify_memcpy_chk(__kernel_siz=
e_t size,
>   * __struct_size() vs __member_size() must be captured here to avoid
>   * evaluating argument side-effects further into the macro layers.
>   */
> +#ifndef CONFIG_KMSAN
>  #define memcpy(p, q, s)  __fortify_memcpy_chk(p, q, s,                 \
>                 __struct_size(p), __struct_size(q),                     \
>                 __member_size(p), __member_size(q),                     \
> @@ -501,6 +502,7 @@ __FORTIFY_INLINE bool fortify_memcpy_chk(__kernel_siz=
e_t size,
>                 __struct_size(p), __struct_size(q),                     \
>                 __member_size(p), __member_size(q),                     \
>                 memmove)
> +#endif
>
>  extern void *__real_memscan(void *, int, __kernel_size_t) __RENAME(memsc=
an);
>  __FORTIFY_INLINE void *memscan(void * const POS0 p, int c, __kernel_size=
_t size)
>
> Then the instances of -Wmacro-redefined disappear but the fortify tests
> no longer pass for somewhat obvious reasons:
>
>   warning: unsafe memcpy() usage lacked '__read_overflow2' symbol in lib/=
test_fortify/read_overflow2-memcpy.c
>   warning: unsafe memmove() usage lacked '__read_overflow2' symbol in lib=
/test_fortify/read_overflow2-memmove.c
>   warning: unsafe memcpy() usage lacked '__read_overflow2_field' symbol i=
n lib/test_fortify/read_overflow2_field-memcpy.c
>   warning: unsafe memmove() usage lacked '__read_overflow2_field' symbol =
in lib/test_fortify/read_overflow2_field-memmove.c
>   warning: unsafe memcpy() usage lacked '__write_overflow' symbol in lib/=
test_fortify/write_overflow-memcpy.c
>   warning: unsafe memmove() usage lacked '__write_overflow' symbol in lib=
/test_fortify/write_overflow-memmove.c
>   warning: unsafe memset() usage lacked '__write_overflow' symbol in lib/=
test_fortify/write_overflow-memset.c
>   warning: unsafe memcpy() usage lacked '__write_overflow_field' symbol i=
n lib/test_fortify/write_overflow_field-memcpy.c
>   warning: unsafe memmove() usage lacked '__write_overflow_field' symbol =
in lib/test_fortify/write_overflow_field-memmove.c
>   warning: unsafe memset() usage lacked '__write_overflow_field' symbol i=
n lib/test_fortify/write_overflow_field-memset.c
>
> Should CONFIG_KMSAN depend on CONFIG_FORTIFY_SOURCE=3Dn like so? It seems
> like the two features are incompatible if I am reading ff901d80fff6
> correctly.
>
> diff --git a/lib/Kconfig.kmsan b/lib/Kconfig.kmsan
> index b2489dd6503f..6a681621e3c5 100644
> --- a/lib/Kconfig.kmsan
> +++ b/lib/Kconfig.kmsan
> @@ -11,7 +11,7 @@ config HAVE_KMSAN_COMPILER
>  config KMSAN
>         bool "KMSAN: detector of uninitialized values use"
>         depends on HAVE_ARCH_KMSAN && HAVE_KMSAN_COMPILER
> -       depends on SLUB && DEBUG_KERNEL && !KASAN && !KCSAN
> +       depends on SLUB && DEBUG_KERNEL && !KASAN && !KCSAN && !FORTIFY_S=
OURCE
>         select STACKDEPOT
>         select STACKDEPOT_ALWAYS_INIT
>         help
>
> or is there a different obvious fix that I am missing?
>
> Cheers,
> Nathan



--
Alexander Potapenko
Software Engineer

Google Germany GmbH
Erika-Mann-Stra=C3=9Fe, 33
80636 M=C3=BCnchen

Gesch=C3=A4ftsf=C3=BChrer: Paul Manicle, Liana Sebastian
Registergericht und -nummer: Hamburg, HRB 86891
Sitz der Gesellschaft: Hamburg

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DWYnfNHC3S1S%3DmCTKTnzL%3DUuH7Oz4W3HjsTXEQUtjrxtw%40mail.=
gmail.com.
