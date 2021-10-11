Return-Path: <kasan-dev+bncBCT6537ZTEKRBUHCSCFQMGQEXEZZ67A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x140.google.com (mail-lf1-x140.google.com [IPv6:2a00:1450:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id 86B5D428D3E
	for <lists+kasan-dev@lfdr.de>; Mon, 11 Oct 2021 14:42:57 +0200 (CEST)
Received: by mail-lf1-x140.google.com with SMTP id c6-20020a05651200c600b003fc6d39efa4sf12671784lfp.12
        for <lists+kasan-dev@lfdr.de>; Mon, 11 Oct 2021 05:42:57 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1633956177; cv=pass;
        d=google.com; s=arc-20160816;
        b=RVuWRYSgovgkR7dhRtNTqdmCU7Ukgs/xkAmWL0sdlmuixK4BNEvvIuDnkN7HnEbBXs
         v8q0UkyI5Db6gN714M1p56h86PRCtAFK16R2qibMbGaoeUC/cVboL3Eu1p2PUPtRn+X0
         IWZ5x6oV3xPk48UD+qDKdztdiZfcSw1Vs00wT6N/aPFcQzK0Z1t3Wtt91DpfUAxMjWRz
         ooowUVevMYSHARMSw1IjjQnpGheTxgiR97BDXA2J2VYbnVfo/+BA4HvXt4eh1V6cSu1u
         zOVY6PgkgI9nEWDeMaimhJV5XG/bvuhX5o9f4wGhppnAMJikJBWWW3rk1MSkAxtU26P9
         UeFQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=89Fam4Q8IkxB32/W4PnOrtkjpJK46PAyUK5Q+JA9c2Q=;
        b=mxX39ynAn2HmQIZA+jX39dyan+tBtR5DCpgwCD6gEi4/nWVhqVHR6LdBPS2yAFTvG5
         Q2rNmiidr+kZrcUtA6gN+dqbRBJW9Ni5tXMesbFH1z4XjsfkoDhLFojHlVCHb1rkjM9p
         aoN8jD8jrfosGZtw6VvbN9muBB8waeU7B8JG7M5uVMEluoK+9ROPCi7muwaoa7C5kctO
         cz9pc9ATDQe24XGGwFx9nilhi+kBpDeJU0B5GIz0fCqQnO98lyynLOW3y8GtKd4FVn9L
         QY5iBaSUtZ3rofae65I/cQ6UjnbHLXZOrdyZc5hjAgLyIveatX3wSVg4UEEIwYra7/EG
         ck7g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=xLAEEpeg;
       spf=pass (google.com: domain of naresh.kamboju@linaro.org designates 2a00:1450:4864:20::52b as permitted sender) smtp.mailfrom=naresh.kamboju@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=89Fam4Q8IkxB32/W4PnOrtkjpJK46PAyUK5Q+JA9c2Q=;
        b=IB7Z40xB68rIZ0nrTyAQcftOAZq04IUPiaHSzrnX7ZmcLKKQvwvZ6t7lL2TwwLpqn4
         yKEEY942OByhZ3ShD1wHm8/dCtjRP7NsB5sv4Qhz0xMRM6LcRuHtsEVDWzPDnzbCMViI
         H8G3n2Z2yfMfISHjASqBm8GjjP19BVrjDZGE5vLgivMxMmNO2X+/IdGdfEndZX37KKUw
         EsvL4KdOZpc49f0KbwpbHUo9K4bgZPqkotzyn6vMwur9F1L0cm13ABbPivzihdQvPzAw
         quxedDHpAGKb0ZCwTjw142VS1ANa2bOzxtzKhoI3Xq4U2NDnIF9NcyhJNxWHknQEVyib
         6Fsg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=89Fam4Q8IkxB32/W4PnOrtkjpJK46PAyUK5Q+JA9c2Q=;
        b=IYl0LvkH4N3KcxcozspfmmY7XO15YOF3dGF+yNpUNhJcqXaMv8PDWa0kbAGCUC6YEq
         kVeAYJ9qRIJORxksYGRG6o8k7FDj5uW7cPmr2Wdv6k+BDrzPM7EIMd3J3z6LNMUBb9Dx
         cbVXbUoYnUDQnF0NuvMX6vV5WCrx7hWARioVA37uZCgq3Kj7dCyvVW5OLjrczsOl5DeA
         r3+uc5QW7CVPf34MY0u+xvigR2Vp0yvxNYKkBWHpAbDkbcNxlsgO0g6gXdId61xWmGJD
         6YN/4ycqvekDLx+WRSKpgvwKFe1khxkZytkyQHZKKPh8Lwrhyir0iXT36yeHoUN3CBeQ
         UzFw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533AzU2NfwQVO3azMkF1rRjH7+s4OJ61Wc5/ccQXzmHo+sFl6yR5
	2YYOBLGn1rd4zIWUXTOcIvY=
X-Google-Smtp-Source: ABdhPJzzP0hMK64ZZoIcI3h1Ju49M7ZrTXogHv2Z3NbGckUq9KgimSTN5LpAoTSPqjZcN/WJ71RjhA==
X-Received: by 2002:a05:6512:202a:: with SMTP id s10mr2477053lfs.560.1633956177091;
        Mon, 11 Oct 2021 05:42:57 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:3901:: with SMTP id g1ls581711lja.2.gmail; Mon, 11 Oct
 2021 05:42:56 -0700 (PDT)
X-Received: by 2002:a2e:8799:: with SMTP id n25mr23704591lji.174.1633956176097;
        Mon, 11 Oct 2021 05:42:56 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1633956176; cv=none;
        d=google.com; s=arc-20160816;
        b=nmna7ZB3UZDysqx7gpjE6sNSw0ke7Svc6dMfevA6wAfYiQ6mmBBygeivQ9R0Y7Qz4m
         5RgjDOqkF9zIy4y1D9YnHmrl/AmfcHjna+j2gYw93uWXqN9LQOwpXxfSUdYzFh8smpZO
         CEyYgeVlNTjsXPmDlaa06fze+0ZN2uuGmsSopAvPPZYQcGbYmeygxfbH1hdDSYK7z56z
         9pMh/sMcn7imyWpIWlWgW2NPrhGMBHwGqxrok86EewzzlU9CbP3KI8hb4z2H3mZm5Vm+
         fBBDeTm1uz7sXNZMAov3ZlKE1MTDfM96AflZUHJb8OCvnxXFq1+8diIkHKHUEJNP9XJy
         L76A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=aH+daMH8/JBhYD/VNld/K3vNCe4mWktvAcObPC4aWG4=;
        b=cIGLsoza2yjxyidKyPD7P01tfxgFTqTluakDEbAmAhen6d1jGu3ZZlrAPqYTP2w8tL
         EwEFaZKRIP/6Txkg7+W0B6M6hWkXVSPaUjFttYN+oMrMD2sQqwh9QHmj0DDp6UR0oPo8
         L4yMKgEir0v43gjBi3FPQeEWjulz90xaEFlxbXxg+gLkOOvSgAIZxP8M3CeO2mItAa9F
         Cpb/weD98Evl1I7aQs59IjBUz1tDF9emyV9QTyrlH0tpWS8F50Qjxr+CtOrt3DzFNaMR
         tjamUiycgwq04wgndZxSIKfSl9lEMBgdOM1LB+Ymhz1CFI35gDkOI0ThDnG996ATZSyR
         mweg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=xLAEEpeg;
       spf=pass (google.com: domain of naresh.kamboju@linaro.org designates 2a00:1450:4864:20::52b as permitted sender) smtp.mailfrom=naresh.kamboju@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
Received: from mail-ed1-x52b.google.com (mail-ed1-x52b.google.com. [2a00:1450:4864:20::52b])
        by gmr-mx.google.com with ESMTPS id h4si391221lft.8.2021.10.11.05.42.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 11 Oct 2021 05:42:56 -0700 (PDT)
Received-SPF: pass (google.com: domain of naresh.kamboju@linaro.org designates 2a00:1450:4864:20::52b as permitted sender) client-ip=2a00:1450:4864:20::52b;
Received: by mail-ed1-x52b.google.com with SMTP id z20so67139535edc.13
        for <kasan-dev@googlegroups.com>; Mon, 11 Oct 2021 05:42:55 -0700 (PDT)
X-Received: by 2002:a50:9993:: with SMTP id m19mr40386265edb.357.1633956175595;
 Mon, 11 Oct 2021 05:42:55 -0700 (PDT)
MIME-Version: 1.0
References: <CA+G9fYv1Vbc-Y_czipb-z1bG=9axE4R1BztKGqWz-yy=+Wcsqw@mail.gmail.com>
In-Reply-To: <CA+G9fYv1Vbc-Y_czipb-z1bG=9axE4R1BztKGqWz-yy=+Wcsqw@mail.gmail.com>
From: Naresh Kamboju <naresh.kamboju@linaro.org>
Date: Mon, 11 Oct 2021 18:12:44 +0530
Message-ID: <CA+G9fYtD2EFu7-j1wPLCiu2yVpZb_wObXXXebKNSW5o4gh9vgA@mail.gmail.com>
Subject: Re: mm/kasan/init.c:282:20: error: redefinition of 'kasan_populate_early_vm_area_shadow'
To: Linux-Next Mailing List <linux-next@vger.kernel.org>, open list <linux-kernel@vger.kernel.org>, 
	linux-mm <linux-mm@kvack.org>, kasan-dev <kasan-dev@googlegroups.com>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Stephen Rothwell <sfr@canb.auug.org.au>, Andrew Morton <akpm@linux-foundation.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: naresh.kamboju@linaro.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linaro.org header.s=google header.b=xLAEEpeg;       spf=pass
 (google.com: domain of naresh.kamboju@linaro.org designates
 2a00:1450:4864:20::52b as permitted sender) smtp.mailfrom=naresh.kamboju@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
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

+ Andrew Morton <akpm@linux-foundation.org>

On Mon, 11 Oct 2021 at 17:08, Naresh Kamboju <naresh.kamboju@linaro.org> wrote:
>
> Regression found on x86_64 gcc-11 built with KASAN enabled.
> Following build warnings / errors reported on linux next 20211011.
>
> metadata:
>     git_describe: next-20211011
>     git_repo: https://gitlab.com/Linaro/lkft/mirrors/next/linux-next
>     git_short_log: d3134eb5de85 (\"Add linux-next specific files for 20211011\")
>     target_arch: x86_64
>     toolchain: gcc-11
>
> build error :
> --------------
> mm/kasan/init.c:282:20: error: redefinition of
> 'kasan_populate_early_vm_area_shadow'
>   282 | void __init __weak kasan_populate_early_vm_area_shadow(void *start,
>       |                    ^~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
> In file included from include/linux/mm.h:34,
>                  from include/linux/memblock.h:13,
>                  from mm/kasan/init.c:9:
> include/linux/kasan.h:463:20: note: previous definition of
> 'kasan_populate_early_vm_area_shadow' with type 'void(void *, long
> unsigned int)'
>   463 | static inline void kasan_populate_early_vm_area_shadow(void *start,
>       |                    ^~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
> make[3]: *** [scripts/Makefile.build:288: mm/kasan/init.o] Error 1
> make[3]: Target '__build' not remade because of errors.
>
>
> Reported-by: Linux Kernel Functional Testing <lkft@linaro.org>
>
> build link:
> -----------
> https://builds.tuxbuild.com/1zLv2snHfZN8QV01yA9MB8NhUZt/build.log
>
> build config:
> -------------
> https://builds.tuxbuild.com/1zLv2snHfZN8QV01yA9MB8NhUZt/config
>
> # To install tuxmake on your system globally
> # sudo pip3 install -U tuxmake
> tuxmake --runtime podman --target-arch x86_64 --toolchain gcc-11
> --kconfig defconfig --kconfig-add
> https://builds.tuxbuild.com/1zLv2snHfZN8QV01yA9MB8NhUZt/config
>
> --
> Linaro LKFT
> https://lkft.linaro.org

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BG9fYtD2EFu7-j1wPLCiu2yVpZb_wObXXXebKNSW5o4gh9vgA%40mail.gmail.com.
