Return-Path: <kasan-dev+bncBCT6537ZTEKRBBUAST6QKGQEV75GYUY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x138.google.com (mail-lf1-x138.google.com [IPv6:2a00:1450:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id 3AFA52A90B0
	for <lists+kasan-dev@lfdr.de>; Fri,  6 Nov 2020 08:49:27 +0100 (CET)
Received: by mail-lf1-x138.google.com with SMTP id s10sf196393lfi.15
        for <lists+kasan-dev@lfdr.de>; Thu, 05 Nov 2020 23:49:27 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1604648966; cv=pass;
        d=google.com; s=arc-20160816;
        b=um6oMDuWpPXWDr1JIEA/b0kd7bgLut/3/8a7Ur8HEKxJlEUAdzkNJaK4aeb7Ho4iSJ
         bLEe4v/EqKtVniP8wHfb1T6rIfsaWs6mTEp3PaH2gDfCzK8zMXsPixDb2mQ6sJNvZP5C
         1QgaTtk8drmOfAf23yXCdUr1as5+fwcstPCpi50IHKU89TewBR28gCyHmmCm2pF9ofPv
         2z8dKmevrgk19cd3aYkUU47FGz0rx4PUrty+T1r0S7YlyYc4yqNgKcxUNsDyQ+/BiMgo
         MWx+J4tgMktt1knCye40st3wGE9xK1p4BPYhS2g0izcckrAJcWmoxIrKc6NyNcOB5Rlw
         mROg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=qNJcwNVmd/17Vk2E0PQwj0loj0ODiQGQE6JXxTyvIUk=;
        b=0XuMl5DrjMMmwsJFaU7++wpw1ZHquMbo3ShnHtSZlNhRhGYvOF5LsUt63wYU052IyD
         TkTc8u7O++oCAoQobhkGJzxB4R+kGs0SUV7c9PNFDZYXQA7fFJMsTeuTXbENi8c4B8Ex
         ze01wwIRrDBbVlDlBxG59SjMeg3JVuUP0hkyZDHI+ecXF61Lcpqfk5ZnQ5N8FGKhQS7Q
         7pFLrlf5O/gj+THebw+iZyw0sjHatlqPOkBeStQ07fLahmLV6PH94uL/y/g0/t6phVzm
         Dls/w8OZEIzvRJjg8lI2k8mPQvF4SBoT6U/MXe18Q9I8qdbagObm0VpE3ocabHdLS6JN
         oOoA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=mj7Hy0x0;
       spf=pass (google.com: domain of naresh.kamboju@linaro.org designates 2a00:1450:4864:20::641 as permitted sender) smtp.mailfrom=naresh.kamboju@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=qNJcwNVmd/17Vk2E0PQwj0loj0ODiQGQE6JXxTyvIUk=;
        b=mlhDKxioJBC3kMYT3SLsCVUAfD/iTxJX0wbmVb8liivwGCe6l5TQFr+sWlKHEafmZA
         f9cVaDtMMoKQh8ijT/lED0Gv7l4Bn0B7PlZzDa+c8gJigImVvn06gB54tQADGZb7ZGgK
         SL3hJZIMduIWgUxcwQdq5bmcCGpt8lTfddt9K3OTtR+L41aJ/RNcXJrKmc1L5g+tm8ib
         gjBWoIO/5MyUUKUbVbpBeaZRSwBmHBb7S1iS/hrS+j80uBz6WpUMUhbGy3u2iFXOlQOA
         +GcxagRsi98XOqU1rFAk6BSlNsxZEK36dojyQizJZ673kttOg72f8AeiI6zIsTEtOZZ5
         vUyQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=qNJcwNVmd/17Vk2E0PQwj0loj0ODiQGQE6JXxTyvIUk=;
        b=MXjUXgebqyeWt9m1Fih7j7JLr9KAi/bClfAOckGP/AiN/HDfjG4/NJpFmavcrFOP0z
         Wup3dNGeu+D+a/CXFvc3WEQZx5GWFc2DDOj192Dl54DEKHfWcIIzxQe5yQFKItfYMFZ3
         Pkvfi+vYFh9FeCY4Z1AIXsoOSqY3d8Mop1SMu0iVkZs/e70QwSWD8vUR/NnRrfs5cIR5
         tJNBWHxBL8GJhArXjPBmFO2PefJJ1d0sqZ+NzSG+nKZ8OjkBIi04CaXOJW6BshfapEfe
         GSQrvXOG1zkwbqU1hJOF95pYNB7XAECkQ1/DFmlLvsd9UrGuEd0ixdMK6v3lHpz0RQrk
         SvkQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533LDPu/CQ6BIODEMzFjRM7iSFxhpHpkYnaQt02GPC4WNM0tZmDt
	jclC6QJYumisdTqrTIgvajE=
X-Google-Smtp-Source: ABdhPJw4hJj/xLHcQCltK5zRhenfrWwT/G1UME/T0XcrAx0tkBpAlMBdxS2IzdiENzyJB3V6OKBsYQ==
X-Received: by 2002:a2e:998b:: with SMTP id w11mr298388lji.146.1604648966785;
        Thu, 05 Nov 2020 23:49:26 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:9b9a:: with SMTP id z26ls82699lji.7.gmail; Thu, 05 Nov
 2020 23:49:25 -0800 (PST)
X-Received: by 2002:a05:651c:1248:: with SMTP id h8mr87495ljh.410.1604648965681;
        Thu, 05 Nov 2020 23:49:25 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1604648965; cv=none;
        d=google.com; s=arc-20160816;
        b=xLgeICkyxS6rpo7dzpMu4G+SQm6lXrBoRPmfA3/9nKUFV7mrsn5EcWAcbTLHGQOAuB
         64KOVy5gvpzakUORluX9HoF/WLgMowFZu7PpAEFkwieiXSRB/WlGg/LS/mf6TPUnizkF
         ZLKzjiGeDisEi1CXYNuss/hru43r0N8WRvnSJwtzuhfpeu9lrOOmvC3+d3BA7YOsxpKq
         nd3tvAcx+6fjcSbj5tMoYRBsa3S8H29vLxC7MZJaeiUPjDQmq+9xUuYXnAcyB1Sy8qBb
         2KtTTrnMT1xvWzsAgMZ+QP4ZiFRcJy5w+bLnhdVYaEwei8BItF2DADmU94Fj8krNxjSN
         MyKg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Jjc7vxJ+kNZjLh3qkBHMLjHb5L9dL8FqV47EXnVphz8=;
        b=V3q9Nv+VQrpeuhWnINNYoJHs/6RVl/x8Or3BgKV/zskW6bML+bpttpJyftPRlmRt9p
         Jufp14eYDxDFRQLE9FtWoMj7YgWQEuyN9VTz5qjuh0/5RkeR0GUgPnkyiz7eP15qDJbK
         j8oP3iFOi7cfKXkGm11m539zfH0GicJhXngJw1uVUqZlE2hakoaT9nUkpuFo+FFpmtC7
         uVeGyohwaFizKLw3VFFgiBrhROg4L/AQd/4y9ImSdkJnCZ6yiMm3EUC3cTSVMfj0ljEd
         4mo90OdgXxLg0YpnE4yLVgMoKEX5jegTbIr3mNo9rU/eUldQQfH0ddLB/2RT5X8BBaFX
         qDwQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=mj7Hy0x0;
       spf=pass (google.com: domain of naresh.kamboju@linaro.org designates 2a00:1450:4864:20::641 as permitted sender) smtp.mailfrom=naresh.kamboju@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
Received: from mail-ej1-x641.google.com (mail-ej1-x641.google.com. [2a00:1450:4864:20::641])
        by gmr-mx.google.com with ESMTPS id q4si16739lji.7.2020.11.05.23.49.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 05 Nov 2020 23:49:25 -0800 (PST)
Received-SPF: pass (google.com: domain of naresh.kamboju@linaro.org designates 2a00:1450:4864:20::641 as permitted sender) client-ip=2a00:1450:4864:20::641;
Received: by mail-ej1-x641.google.com with SMTP id o23so582123ejn.11
        for <kasan-dev@googlegroups.com>; Thu, 05 Nov 2020 23:49:25 -0800 (PST)
X-Received: by 2002:a17:906:6987:: with SMTP id i7mr877544ejr.18.1604648965186;
 Thu, 05 Nov 2020 23:49:25 -0800 (PST)
MIME-Version: 1.0
References: <20201019084140.4532-1-linus.walleij@linaro.org> <20201019084140.4532-3-linus.walleij@linaro.org>
In-Reply-To: <20201019084140.4532-3-linus.walleij@linaro.org>
From: Naresh Kamboju <naresh.kamboju@linaro.org>
Date: Fri, 6 Nov 2020 13:19:14 +0530
Message-ID: <CA+G9fYvfL8QqFkNDK69KBBnougtJb5dj6LTy=xmhBz33fjssgQ@mail.gmail.com>
Subject: Re: [PATCH 2/5 v16] ARM: Replace string mem* functions for KASan
To: Linus Walleij <linus.walleij@linaro.org>, 
	Linux-Next Mailing List <linux-next@vger.kernel.org>
Cc: Florian Fainelli <f.fainelli@gmail.com>, Abbott Liu <liuwenliang@huawei.com>, 
	Russell King <linux@armlinux.org.uk>, Ard Biesheuvel <ardb@kernel.org>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Mike Rapoport <rppt@linux.ibm.com>, 
	Ahmad Fatoum <a.fatoum@pengutronix.de>, Arnd Bergmann <arnd@arndb.de>, 
	kasan-dev <kasan-dev@googlegroups.com>, Alexander Potapenko <glider@google.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, Dmitry Vyukov <dvyukov@google.com>, 
	Stephen Rothwell <sfr@canb.auug.org.au>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: naresh.kamboju@linaro.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linaro.org header.s=google header.b=mj7Hy0x0;       spf=pass
 (google.com: domain of naresh.kamboju@linaro.org designates
 2a00:1450:4864:20::641 as permitted sender) smtp.mailfrom=naresh.kamboju@linaro.org;
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

On Mon, 19 Oct 2020 at 14:14, Linus Walleij <linus.walleij@linaro.org> wrote:
>
> From: Andrey Ryabinin <aryabinin@virtuozzo.com>
>
> Functions like memset()/memmove()/memcpy() do a lot of memory
> accesses.
>
> If a bad pointer is passed to one of these functions it is important
> to catch this. Compiler instrumentation cannot do this since these
> functions are written in assembly.
>
> KASan replaces these memory functions with instrumented variants.
>
> The original functions are declared as weak symbols so that
> the strong definitions in mm/kasan/kasan.c can replace them.
>
> The original functions have aliases with a '__' prefix in their
> name, so we can call the non-instrumented variant if needed.
>
> We must use __memcpy()/__memset() in place of memcpy()/memset()
> when we copy .data to RAM and when we clear .bss, because
> kasan_early_init cannot be called before the initialization of
> .data and .bss.
>
> For the kernel compression and EFI libstub's custom string
> libraries we need a special quirk: even if these are built
> without KASan enabled, they rely on the global headers for their
> custom string libraries, which means that e.g. memcpy()
> will be defined to __memcpy() and we get link failures.
> Since these implementations are written i C rather than
> assembly we use e.g. __alias(memcpy) to redirected any
> users back to the local implementation.
>
> Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
> Cc: Alexander Potapenko <glider@google.com>
> Cc: Dmitry Vyukov <dvyukov@google.com>
> Cc: kasan-dev@googlegroups.com
> Reviewed-by: Ard Biesheuvel <ardb@kernel.org>
> Tested-by: Ard Biesheuvel <ardb@kernel.org> # QEMU/KVM/mach-virt/LPAE/8G
> Tested-by: Florian Fainelli <f.fainelli@gmail.com> # Brahma SoCs
> Tested-by: Ahmad Fatoum <a.fatoum@pengutronix.de> # i.MX6Q
> Reported-by: Russell King - ARM Linux <linux@armlinux.org.uk>
> Signed-off-by: Ahmad Fatoum <a.fatoum@pengutronix.de>
> Signed-off-by: Abbott Liu <liuwenliang@huawei.com>
> Signed-off-by: Florian Fainelli <f.fainelli@gmail.com>
> Signed-off-by: Linus Walleij <linus.walleij@linaro.org>
> ---
> ChangeLog v15->v16:
> - Fold in Ahmad Fatoum's fixup for fortify
> - Collect Florian's Tested-by
> - Resend with the other patches
> ChangeLog v14->v15:
> - Resend with the other patches
> ChangeLog v13->v14:
> - Resend with the other patches
> ChangeLog v12->v13:
> - Rebase on kernel v5.9-rc1
> ChangeLog v11->v12:
> - Resend with the other changes.
> ChangeLog v10->v11:
> - Resend with the other changes.
> ChangeLog v9->v10:
> - Rebase on v5.8-rc1
> ChangeLog v8->v9:
> - Collect Ard's tags.
> ChangeLog v7->v8:
> - Use the less invasive version of handling the global redefines
>   of the string functions in the decompressor: __alias() the
>   functions locally in the library.
> - Put in some more comments so readers of the code knows what
>   is going on.
> ChangeLog v6->v7:
> - Move the hacks around __SANITIZE_ADDRESS__ into this file
> - Edit the commit message
> - Rebase on the other v2 patches
> ---
>  arch/arm/boot/compressed/string.c | 19 +++++++++++++++++++
>  arch/arm/include/asm/string.h     | 26 ++++++++++++++++++++++++++
>  arch/arm/kernel/head-common.S     |  4 ++--
>  arch/arm/lib/memcpy.S             |  3 +++
>  arch/arm/lib/memmove.S            |  5 ++++-
>  arch/arm/lib/memset.S             |  3 +++
>  6 files changed, 57 insertions(+), 3 deletions(-)
>
> diff --git a/arch/arm/boot/compressed/string.c b/arch/arm/boot/compressed/string.c
> index ade5079bebbf..8c0fa276d994 100644
> --- a/arch/arm/boot/compressed/string.c
> +++ b/arch/arm/boot/compressed/string.c
> @@ -7,6 +7,25 @@
>
>  #include <linux/string.h>
>
> +/*
> + * The decompressor is built without KASan but uses the same redirects as the
> + * rest of the kernel when CONFIG_KASAN is enabled, defining e.g. memcpy()
> + * to __memcpy() but since we are not linking with the main kernel string
> + * library in the decompressor, that will lead to link failures.
> + *
> + * Undefine KASan's versions, define the wrapped functions and alias them to
> + * the right names so that when e.g. __memcpy() appear in the code, it will
> + * still be linked to this local version of memcpy().
> + */
> +#ifdef CONFIG_KASAN
> +#undef memcpy
> +#undef memmove
> +#undef memset
> +void *__memcpy(void *__dest, __const void *__src, size_t __n) __alias(memcpy);
> +void *__memmove(void *__dest, __const void *__src, size_t count) __alias(memmove);
> +void *__memset(void *s, int c, size_t count) __alias(memset);
> +#endif
> +
>  void *memcpy(void *__dest, __const void *__src, size_t __n)

arm KASAN build failure noticed on linux next 20201106 tag.
gcc: 9.x

Build error:
---------------
arch/arm/boot/compressed/string.c:24:1: error: attribute 'alias'
argument not a string
   24 | void *__memcpy(void *__dest, __const void *__src, size_t __n)
__alias(memcpy);
      | ^~~~
arch/arm/boot/compressed/string.c:25:1: error: attribute 'alias'
argument not a string
   25 | void *__memmove(void *__dest, __const void *__src, size_t
count) __alias(memmove);
      | ^~~~
arch/arm/boot/compressed/string.c:26:1: error: attribute 'alias'
argument not a string
   26 | void *__memset(void *s, int c, size_t count) __alias(memset);
      | ^~~~

Reported-by: Naresh Kamboju <naresh.kamboju@linaro.org>

Build details link,
https://builds.tuxbuild.com/1juBs4tXRA6Cwhd1Qnhh4vzCtDx/

-- 
Linaro LKFT
https://lkft.linaro.org

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BG9fYvfL8QqFkNDK69KBBnougtJb5dj6LTy%3DxmhBz33fjssgQ%40mail.gmail.com.
