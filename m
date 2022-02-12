Return-Path: <kasan-dev+bncBDE6RCFOWIARBCWMUCIAMGQEOMLSTAA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83e.google.com (mail-qt1-x83e.google.com [IPv6:2607:f8b0:4864:20::83e])
	by mail.lfdr.de (Postfix) with ESMTPS id 97E714B3836
	for <lists+kasan-dev@lfdr.de>; Sat, 12 Feb 2022 22:26:35 +0100 (CET)
Received: by mail-qt1-x83e.google.com with SMTP id l15-20020ac84ccf000000b002cf9424cfa5sf9402111qtv.7
        for <lists+kasan-dev@lfdr.de>; Sat, 12 Feb 2022 13:26:35 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1644701194; cv=pass;
        d=google.com; s=arc-20160816;
        b=hRAa+MUhezhHDE7QU0VHqKP7LgUgZZRqspsYJ0nTNnb4sxXeuRXCVkaTMzVsdus7BU
         jq/Cnicp70PD3pTrSMumObvO2XMflKpAVzOqPiLBA6yiKjctnguwT/yPy3S77lfqZIie
         JKmEpdUEU9rslUkQsJGqP06J+mykbZvpKcu5RCZy1gvwASQ1C61aTfrMAcjqgEK9xlMd
         eqnmgxiMUjyTMMAUBpzdoc7FUhkMhqrD3laAgn2hX2D2wxPPcU3aQ6iE4MHIs3wAhNWW
         rwT7QS/8JIrQVrxQjotbEv9HLcQ/G7aSeXnfdTFJ/a13f2q+lKe2FYWC6JJtxkwo+4/U
         UaPw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=VBb/wulbvkAaUZDKpjmNJu5daCx8ucfB09ub33YCID8=;
        b=TXp8AOQnYYE+mEk3VEoOtvWMgOtygeaiHp9MXkdwoibbrY9f5ioS+jeyIrTj+VooQN
         PJQYCpQHItQ2lucae8pkLZJGkR5wRKh1DDu/7pzE1iukxthcgkTIeq6yJMOTLLWRt+c0
         +LD/JlOTG5qMPEKUpHBY5OdEzMrcdPyN85oli5J9bu9S5G2Ee6pf+/nHzBfQz0/LzwfX
         w8eqOBUVaMO38BT/pt7YPXOFy+9vFaA665onSgP9qW1Rlum0y3qjT4SIrYF5sNDd0TPA
         YroaHwix79uV7N+cGosQ/Dc3uJdvZ7HBqG0caWpP3OFSnyA0wsNeGVq3QW0x3ecadv/Z
         f/rA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=YOy7lPzP;
       spf=pass (google.com: domain of linus.walleij@linaro.org designates 2607:f8b0:4864:20::b2d as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=VBb/wulbvkAaUZDKpjmNJu5daCx8ucfB09ub33YCID8=;
        b=hHMc3PHPOcHNYUQb68eOcWrb8YO5/YN+5GU/D5bELIh3hrtp02eeUnHOKC43A1mJAs
         ElxRUFvgfb1J+QqqVoDS07cOzMCFLGfeBApVk/qsoKZ3Myp82vUjK72mAPQ1Vv1liIpJ
         +S3dgjg2YL1l0Q/xRZ/ycHuVMXdsuqTOfhgeTaTRGTIYXFXZahh1lzoGsdNTU0C4+E/B
         Pfs8nod/xJYAohL3wXBH5j6ntRYkSQezJD3rCVQNcgHDorcOLYcawQDGmQoQFKLBAsXj
         gKHRcWMXoPQG7GImBUn4iUOHKq33g00D6Vqyilkpk11P7MXM5DqESM/9oE9INkAQVjR0
         cM0w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=VBb/wulbvkAaUZDKpjmNJu5daCx8ucfB09ub33YCID8=;
        b=oUJ+21O0rZVp+6p2VaPA3i2KlWMEpp7oPTO0PiN8zzekjZS8xznp2qgdZ+ZMzdFazs
         6z7pjc6p7VTJY0P0zQQgsh1XMFdL3lv4rx/7MEyu443hcfo/jyyv8GLcN9XIp7NpyzlS
         ZlrWATp7Tsln5bf8mdS0GW9k9sGsR1nK/yMv2CIDBgRzy+aU0aGXJgO5ghs82vl0tnRg
         SLboFraR5oJhMK19rENpaCGBsCtnvJVfdcUvYOmNyc817z0xz0OLw4UIAeKwanVcF8IJ
         ayFR3vMfiTbhiGpubAenwPUxkqplQd6GDLo8nTH/0z5zWFMPZS5w2X10jXfFpN8KHkxI
         HxPw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533WD/sza8GTVe5DDb+TndSBNQin04cAgRtCerBO7lWYLFN06hD5
	MOJfWFQ1hMA1O2FWjXI0DeA=
X-Google-Smtp-Source: ABdhPJxtMkm9dFVtNK4+n8MhQP+64z90tZrtxdIND5FQQLLsXlCjMXYzCEyeW1nPQt7IA6epXH0nmw==
X-Received: by 2002:a05:620a:d95:: with SMTP id q21mr3938437qkl.384.1644701194399;
        Sat, 12 Feb 2022 13:26:34 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ad4:4029:: with SMTP id q9ls1191800qvp.0.gmail; Sat, 12 Feb
 2022 13:26:33 -0800 (PST)
X-Received: by 2002:a05:6214:b66:: with SMTP id ey6mr5145226qvb.131.1644701193943;
        Sat, 12 Feb 2022 13:26:33 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1644701193; cv=none;
        d=google.com; s=arc-20160816;
        b=ziz5Ae/iKv8+vqzrdVDy+L5KFC58TPQDPWtcOTKZYV5En/TfH8m0QS0pQPcBdj6Hgf
         tw1ixIToRuc7LZrzr9giBoBZV10uDyjftAVpW5pQyUwrT2KqAt6oi+ypl6Ytnz+A8BlM
         cCMZfPsuOVMQ/mTPB3ssSW4ErU1gS/z1Kix1ya+ghMtOrsiYBlN0l4i2Sdy4EAQfLJ34
         DWPKhgVa4ipb4cV+pTlEFc4q1c5FBwo47ofYxc7O0SBfHG0SWxIyQ3ob9SN33oOUXoFb
         2SHtInWZGm077QqFbszTRMIR5iFWBc6JTzAZtZpP09GZBZMuEuxpQFLC0uWtHT4RPDIr
         dauQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=ziBy4m282LSVlv+vy1G9xp+F8+soJK7oajWOwPn3S1I=;
        b=mwqD/HQtM8AEuZjqENVNS6fryacPp5JlZrWci4S0IoZH0ItM87ARSRIrR90ay/CIoi
         bXcmSCGivz2Db4ScxVM9dcB+pm3dZE+/ln7M0WIOylSm39q+qG9wFACOwnpH3jNzkm70
         so7JKS8T4SavfQ88BDbqQ/cYebdjNx/y+I2y054VYZmnFBeWzzh+Pr1Lq69uc7/EPZrg
         u5rml7kaDCkcPKZGNZFlV9nTfqW9X6AMSxL4ThVMAZ8wl9Yhs6h2ssWWA7GIM4DCY9ID
         inCNXiZJXBsub9tezViQ/S6QAXJsgzD9ofPu721IVdxU5RFW4eAn6V+a/+I1BcLagP6e
         wm1A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=YOy7lPzP;
       spf=pass (google.com: domain of linus.walleij@linaro.org designates 2607:f8b0:4864:20::b2d as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
Received: from mail-yb1-xb2d.google.com (mail-yb1-xb2d.google.com. [2607:f8b0:4864:20::b2d])
        by gmr-mx.google.com with ESMTPS id 3si1186191qkr.2.2022.02.12.13.26.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 12 Feb 2022 13:26:33 -0800 (PST)
Received-SPF: pass (google.com: domain of linus.walleij@linaro.org designates 2607:f8b0:4864:20::b2d as permitted sender) client-ip=2607:f8b0:4864:20::b2d;
Received: by mail-yb1-xb2d.google.com with SMTP id p19so35143634ybc.6
        for <kasan-dev@googlegroups.com>; Sat, 12 Feb 2022 13:26:33 -0800 (PST)
X-Received: by 2002:a05:6902:247:: with SMTP id k7mr6803041ybs.322.1644701193652;
 Sat, 12 Feb 2022 13:26:33 -0800 (PST)
MIME-Version: 1.0
References: <20220212074747.10849-1-lecopzer.chen@mediatek.com> <20220212074747.10849-2-lecopzer.chen@mediatek.com>
In-Reply-To: <20220212074747.10849-2-lecopzer.chen@mediatek.com>
From: Linus Walleij <linus.walleij@linaro.org>
Date: Sat, 12 Feb 2022 22:26:21 +0100
Message-ID: <CACRpkdYDg3saLpfHg=R1kYpnC_BBNgBbe7un-B4e8bgDYPq1Fg@mail.gmail.com>
Subject: Re: [PATCH v2 1/2] arm: kasan: support CONFIG_KASAN_VMALLOC
To: Lecopzer Chen <lecopzer.chen@mediatek.com>
Cc: linux-arm-kernel@lists.infradead.org, linux-kernel@vger.kernel.org, 
	andreyknvl@gmail.com, anshuman.khandual@arm.com, ardb@kernel.org, 
	arnd@arndb.de, dvyukov@google.com, geert+renesas@glider.be, glider@google.com, 
	kasan-dev@googlegroups.com, linux@armlinux.org.uk, lukas.bulwahn@gmail.com, 
	mark.rutland@arm.com, masahiroy@kernel.org, matthias.bgg@gmail.com, 
	rmk+kernel@armlinux.org.uk, ryabinin.a.a@gmail.com, yj.chiang@mediatek.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: linus.walleij@linaro.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linaro.org header.s=google header.b=YOy7lPzP;       spf=pass
 (google.com: domain of linus.walleij@linaro.org designates
 2607:f8b0:4864:20::b2d as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
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

Hi Lecopzer,

thanks for working on this! I need this support too.

On Sat, Feb 12, 2022 at 8:47 AM Lecopzer Chen
<lecopzer.chen@mediatek.com> wrote:

> Simply make shadow of vmalloc area mapped on demand.
>
> This can fix ARM_MODULE_PLTS with KASAN and provide first step
> to support CONFIG_VMAP_STACK in ARM.
>
> Signed-off-by: Lecopzer Chen <lecopzer.chen@mediatek.com>

(...)

> -       kasan_populate_early_shadow(kasan_mem_to_shadow((void *)VMALLOC_START),
> +       if (!IS_ENABLED(CONFIG_KASAN_VMALLOC))
> +               kasan_populate_early_shadow(kasan_mem_to_shadow((void *)VMALLOC_START),
> +                                           kasan_mem_to_shadow((void *)VMALLOC_END));
> +
> +       kasan_populate_early_shadow(kasan_mem_to_shadow((void *)VMALLOC_END),
>                                     kasan_mem_to_shadow((void *)-1UL) + 1);

Where is this actually mapped?

Can you print out where
kasan_mem_to_shadow((void *)VMALLOC_START)
kasan_mem_to_shadow((void *)VMALLOC_END)
as well as KASAN_SHADOW_START and KASAN_SHADOW_END
points?

When I looked into this getting the shadow memory between
KASAN_SHADOW_START and KASAN_SHADOW_END
seemed like the big problem since this is static, so how is Kasan
solving this now?

Please patch the picture in
include/asm/kasan_def.h
and the info in
Documentation/arm/memory.rst
so it clearly reflects where VMALLOC is shadowed.

Yours,
Linus Walleij

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACRpkdYDg3saLpfHg%3DR1kYpnC_BBNgBbe7un-B4e8bgDYPq1Fg%40mail.gmail.com.
