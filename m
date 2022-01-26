Return-Path: <kasan-dev+bncBCMIZB7QWENRB54NY2HQMGQE3UWUXQA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53e.google.com (mail-pg1-x53e.google.com [IPv6:2607:f8b0:4864:20::53e])
	by mail.lfdr.de (Postfix) with ESMTPS id 96B1449D0E6
	for <lists+kasan-dev@lfdr.de>; Wed, 26 Jan 2022 18:38:01 +0100 (CET)
Received: by mail-pg1-x53e.google.com with SMTP id u24-20020a656718000000b0035e911d79edsf52683pgf.1
        for <lists+kasan-dev@lfdr.de>; Wed, 26 Jan 2022 09:38:01 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1643218680; cv=pass;
        d=google.com; s=arc-20160816;
        b=dGAKO7oRhkMp2o9lFu1/ilMEnDQTYrRsHz1XEr9Q/9fi3TiezmKQAKsjydsHn2bRVu
         rBAKPP2EULyuV44qzyPxOP2YiXxb42x91Pi5AC/WLNuHxZWO1S4AjwNXpW+RVXi04hdA
         lDGCvCwszTfl+sNwM4/4nPP8imRQ5WwSEUWN2sY+efvp/IWZxeN47X3GUqn9PPNkO1Du
         N447iY6PcayDRYh3uM1PKZiFEltTZbCt0yJT1aEAMUCisI/N011x1sRj+ZMxWNIXdUHt
         XvLccmXcKSD6yQlOtC4Y27SlWvdybXZ5gInWp/hHL4GvJI5ps4XTGTf5JSeKI1v5W/m/
         +aOg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=rGtLGPA8cpARgo7f4Fm9NDLg+Pe38uctE6376h7wtW8=;
        b=Jx6rie9guFHVusqgoHK0F0d7/MIRYwA+dxLxr2IPc71AfwbUmsIL9bU6GjEulwb2D7
         tUvhBX+9EhJfAjXOlqMRIQAGSNZwCDXHpnkHvLUFxAGq/RT00P9x0/59WVOHZgr63Ox/
         FfGojvaeP5plH/+b+WWPFVl5zYd1WfchR7ijBjlMisW/8SdpIGDXoOo7AKkJGqXr8aLE
         3Poz/atn9ngNn6I87Ffv58ASyoUCZ7++7zEsZddJa8cYt2yuC0jaQiiNxkLKxhsoVChq
         W7dMsTYxdE3/vs/vaGro1fkW3Hz9b9mJp1ohJuKzSho/GShlWjmQofiRQxsZE2y/5X24
         GZ6A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=GXosuorl;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::22d as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=rGtLGPA8cpARgo7f4Fm9NDLg+Pe38uctE6376h7wtW8=;
        b=JU9WRm8ORyGPm7/b/Y1IHxid4ROl3PdzI5Qe55OaQSPuPNIQI0fSCFGVWrty32JnCD
         hmCzF2IUr83P/TnCqcG1RXdiqcyOnisNTyyaPaQvtEK2RpD2znzWPLfyflPVOAYJG+pz
         kOUa4+/DPNHj5eZ6vwzFnS0uN6w7fU0JwB/KF4G6GQZcNCZMdjHPIp9YzMMaGb8yR3jc
         fazlPT/ooeSVcTaEI5yYaOnKeuUNcgs3PS6tXsBSu6c6mPPUuiRR8zMlkLIxGMznFgBF
         QTbNPz0am7oC1f7WEJQsZz4hpWoSsXNcuJLnWvGkMcBQwZ8qf3NKfMsl6MhRkpqrFE4h
         j+2g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=rGtLGPA8cpARgo7f4Fm9NDLg+Pe38uctE6376h7wtW8=;
        b=X5Ivl6fv62GsR7KFUYe5To0qGtV59SZ7pML5ZBAVHsjqhhPVGeyHnTj3pD+NkaMGiZ
         jph8+ErSBitVczJeuQJs5Fefi2VDpcFdSDIGrc0OnkgkUw2rpZVF0q11yGp3Mx4J6kCP
         9E8pruGYlk5q1Lx8SvaYdXkiZ3279KPhk48DYKtSVGwWAvL9sfQvDRczSHalQfSaAhd8
         z/BIHWHWCkqxW19iuP4IwQQSS2wxNf5Iz/mcG7d0/pFiy5eG9eJ1x7nldUmYpNUF1C/Y
         tMViZZ7hox1sqP8Xm5oPFYK/mtbMrd1ykyWc7H4SefzBmZaoUlqLR6C+gaEd11AnT0Bw
         HafA==
X-Gm-Message-State: AOAM531wjTjyTHRkTHrOPzgd3k0v90LzpWM01gIZ2Gkq3AtwnLuk3qkT
	oTyQw8n4xT5583FKb0a18S4=
X-Google-Smtp-Source: ABdhPJwNuESAgYT3KnhxgXi6huUESMWN3X9SoQq8h/TzUybt4I9+4CE7lkDTr8un0cukyNC5V0hiEw==
X-Received: by 2002:a17:903:1c4:: with SMTP id e4mr39359plh.75.1643218680087;
        Wed, 26 Jan 2022 09:38:00 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:1887:: with SMTP id x7ls1023098pfh.5.gmail; Wed, 26
 Jan 2022 09:37:59 -0800 (PST)
X-Received: by 2002:a63:6b42:: with SMTP id g63mr19247462pgc.345.1643218679483;
        Wed, 26 Jan 2022 09:37:59 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1643218679; cv=none;
        d=google.com; s=arc-20160816;
        b=ioaW0UYEJGUwOKNdOC8onRdS7DTYLUymOvGkBRfeTQkiweZS+SFE0r1+ASUrJK2veD
         iEPYyuG6QSQPV/SXRCR2hkUa+aBnNn9AulOr1pTsRB+GhOkYi9Bkc0lVfk9P1eGlcKKR
         RMOJqw9UsvitT6zHAO2wwuPTjEIU2NaqC8WHuvsZ7Ey2KZXtIXVgQyU8wBDG/zt6Bp0B
         WYcvvTDbiz5tzBf8OpJ0kx/XYI1zG0Z99rptdDEf7uHSK97aaar+D4yCO+4/Yz9rl7Ea
         p5zxb0x1Gl8dRutJrBdmddWq9on2eJEj7kNq5DAWNPl8qdut3SXnrLO3tVHcefIg8wtb
         VaNw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=iIrTw8i7dKztJOX/sYlGyAZ9lt8KfEmb4oiF+8tim90=;
        b=yI1bH4bOr1yghucSX2LNoOf2OyICEm5Jbnkq2u5+IqssNgDKGMyCXDTDrUw8opBxyh
         qwE85/dAOZ+31kNmcCwEIiUVjJ/utJ3aD6IIi8W+xrPRz0IrJGwGbwGAfaR1YSlhjghU
         cF7yALmF0N2CyLSQ/6dES/ju9tSpwIAN+rco4wV5EMIv8ZIYoohHer7V5MDWGfUQTj1N
         POmbbxIplpwOJlvIWZuo0gYIVkdt1IKxPzJEL15F6YYumjs20Lka9iSI6OGz/E4CPfmx
         G75sLllxce6IkzBO/CSwY0rWoxhXRSRwMwS2ttGT5SGcVvy2dAjhWpcQBcuzloBd3DzD
         yQbg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=GXosuorl;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::22d as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x22d.google.com (mail-oi1-x22d.google.com. [2607:f8b0:4864:20::22d])
        by gmr-mx.google.com with ESMTPS id t15si1055549plg.8.2022.01.26.09.37.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 26 Jan 2022 09:37:59 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::22d as permitted sender) client-ip=2607:f8b0:4864:20::22d;
Received: by mail-oi1-x22d.google.com with SMTP id bb37so1014365oib.1
        for <kasan-dev@googlegroups.com>; Wed, 26 Jan 2022 09:37:59 -0800 (PST)
X-Received: by 2002:a05:6808:152b:: with SMTP id u43mr4233444oiw.307.1643218678694;
 Wed, 26 Jan 2022 09:37:58 -0800 (PST)
MIME-Version: 1.0
References: <20220126171232.2599547-1-jannh@google.com>
In-Reply-To: <20220126171232.2599547-1-jannh@google.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 26 Jan 2022 18:37:47 +0100
Message-ID: <CACT4Y+b8ty07hAANzktksbbe5HdDM=jm6TSYLKawctpBmPfatw@mail.gmail.com>
Subject: Re: [PATCH] x86/csum: Add KASAN/KCSAN instrumentation
To: Jann Horn <jannh@google.com>
Cc: Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>, 
	Dave Hansen <dave.hansen@linux.intel.com>, x86@kernel.org, 
	"H. Peter Anvin" <hpa@zytor.com>, linux-kernel@vger.kernel.org, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, kasan-dev@googlegroups.com, 
	Eric Dumazet <edumazet@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=GXosuorl;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::22d
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

On Wed, 26 Jan 2022 at 18:13, Jann Horn <jannh@google.com> wrote:
>
> In the optimized X86 version of the copy-with-checksum helpers, use
> instrument_*() before accessing buffers from assembly code so that KASAN
> and KCSAN don't have blind spots there.
>
> Signed-off-by: Jann Horn <jannh@google.com>
> ---
>  arch/x86/lib/csum-partial_64.c  | 3 +++
>  arch/x86/lib/csum-wrappers_64.c | 9 +++++++++
>  2 files changed, 12 insertions(+)
>
> diff --git a/arch/x86/lib/csum-partial_64.c b/arch/x86/lib/csum-partial_64.c
> index 1f8a8f895173..8b0c353cd212 100644
> --- a/arch/x86/lib/csum-partial_64.c
> +++ b/arch/x86/lib/csum-partial_64.c
> @@ -8,6 +8,7 @@
>
>  #include <linux/compiler.h>
>  #include <linux/export.h>
> +#include <linux/instrumented.h>
>  #include <asm/checksum.h>
>  #include <asm/word-at-a-time.h>
>
> @@ -37,6 +38,8 @@ __wsum csum_partial(const void *buff, int len, __wsum sum)
>         u64 temp64 = (__force u64)sum;
>         unsigned odd, result;
>
> +       instrument_read(buff, len);
> +
>         odd = 1 & (unsigned long) buff;
>         if (unlikely(odd)) {
>                 if (unlikely(len == 0))
> diff --git a/arch/x86/lib/csum-wrappers_64.c b/arch/x86/lib/csum-wrappers_64.c
> index 189344924a2b..087f3c4cb89f 100644
> --- a/arch/x86/lib/csum-wrappers_64.c
> +++ b/arch/x86/lib/csum-wrappers_64.c
> @@ -6,6 +6,8 @@
>   */
>  #include <asm/checksum.h>
>  #include <linux/export.h>
> +#include <linux/in6.h>
> +#include <linux/instrumented.h>
>  #include <linux/uaccess.h>
>  #include <asm/smap.h>
>
> @@ -26,6 +28,7 @@ csum_and_copy_from_user(const void __user *src, void *dst, int len)
>         __wsum sum;
>
>         might_sleep();
> +       instrument_write(dst, len);
>         if (!user_access_begin(src, len))
>                 return 0;
>         sum = csum_partial_copy_generic((__force const void *)src, dst, len);
> @@ -51,6 +54,7 @@ csum_and_copy_to_user(const void *src, void __user *dst, int len)
>         __wsum sum;
>
>         might_sleep();
> +       instrument_read(src, len);

Nice!

Can these potentially be called with KERNEL_DS as in some compat
syscalls? If so it's better to use instrument_copy_to/from_user.
Or probably it's better to use them anyway b/c we also want to know
about user accesses for uaccess logging and maybe other things.



>         if (!user_access_begin(dst, len))
>                 return 0;
>         sum = csum_partial_copy_generic(src, (void __force *)dst, len);
> @@ -71,6 +75,8 @@ EXPORT_SYMBOL(csum_and_copy_to_user);
>  __wsum
>  csum_partial_copy_nocheck(const void *src, void *dst, int len)
>  {
> +       instrument_write(dst, len);
> +       instrument_read(src, len);
>         return csum_partial_copy_generic(src, dst, len);
>  }
>  EXPORT_SYMBOL(csum_partial_copy_nocheck);
> @@ -81,6 +87,9 @@ __sum16 csum_ipv6_magic(const struct in6_addr *saddr,
>  {
>         __u64 rest, sum64;
>
> +       instrument_read(saddr, sizeof(*saddr));
> +       instrument_read(daddr, sizeof(*daddr));
> +
>         rest = (__force __u64)htonl(len) + (__force __u64)htons(proto) +
>                 (__force __u64)sum;
>
>
> base-commit: 0280e3c58f92b2fe0e8fbbdf8d386449168de4a8
> --
> 2.35.0.rc0.227.g00780c9af4-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2Bb8ty07hAANzktksbbe5HdDM%3Djm6TSYLKawctpBmPfatw%40mail.gmail.com.
