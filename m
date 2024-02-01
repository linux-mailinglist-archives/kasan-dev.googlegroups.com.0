Return-Path: <kasan-dev+bncBC7OBJGL2MHBBFFY5WWQMGQESIGOFJI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x439.google.com (mail-pf1-x439.google.com [IPv6:2607:f8b0:4864:20::439])
	by mail.lfdr.de (Postfix) with ESMTPS id B3C1984532A
	for <lists+kasan-dev@lfdr.de>; Thu,  1 Feb 2024 09:53:42 +0100 (CET)
Received: by mail-pf1-x439.google.com with SMTP id d2e1a72fcca58-6de0aabeef3sf654060b3a.0
        for <lists+kasan-dev@lfdr.de>; Thu, 01 Feb 2024 00:53:42 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1706777621; cv=pass;
        d=google.com; s=arc-20160816;
        b=hzLgG9+g0cZJdYnLruKkiptSaYkSJicwSX8KKUWGa555f2sozlTz4/WFhmq2tbMVmw
         V/RAIxYWmR3hEkKFUAmDCNNwf7OaUQfpmClwJKVNV6mcapKsmLOYNC9cqfrC0siJ2obF
         6gJMxrXVuGDjGt1aQHBe7/6oQs7mgjMZEn4P9Y3tKGhtGnf2NnRVkczcAGFV2YuVQa4k
         JwYp7IHRneU6HCisudp3MQJKI7sds6+4hCFXw6iYCL/M4ctium4i+/L8pOkkdFUFLs4L
         KrhuHFbsKu38Bb5DuMuu6B7XbRXImCMN4U/3BSu8gmnMAuO/rMQKTLWOp7lzkKR1Jom+
         hmSQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=3rVfpGVMKcHQ+Pz1l+4Z0DTw1yDBU155v1QPWqdBOy8=;
        fh=8TyBmIkc8BHeP5Pz1GYSQ+oNjLn9219YiEplPYrwY2I=;
        b=xapMXv1t7hFfue/i5oJyBPq95+1Ln8a+LClwuEdBpDYEJk2+NK11LgJB4JikQzHqSH
         6X9xB2wdpK1LL2DTt2ww11pzF6oVcrLkfDVZ2K4wzVnCO2rf5arUHmDNRqgioklhAm+1
         DkYbqr3K3avUvcWybXhwvJmgClV1zX4C+g6VbJnGm2eKYdMn6xLh9di3V1rLqLPTNDsP
         K0KhvzQqBLial4X7U/caCLvmuRgPj82MTp9wjQPiapAeVgvP1aB20xSm6JlRmiJgMh7O
         H5gC9DqDC2VsF76cPQpWoAIEkB4I9A+a7eOsnWKL0WUfsIrNQLopHqrBY8LRAjIiZGDd
         itQg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="nU4/cpgE";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::930 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1706777621; x=1707382421; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=3rVfpGVMKcHQ+Pz1l+4Z0DTw1yDBU155v1QPWqdBOy8=;
        b=aZNMfxZ/wWVN5Tb+bAXqKxjKP8dl+OWTVP3ChN6EHo4lPpLrRWvALY9YMEZq+VH68J
         i1A5HXrNnaveDHBBMDf7ellSllhTYWP5zaoU9JHygA7vAd3nJy6kIZC3NcOm06ChNAD5
         d8BkubK7TKyaSfNw50qEzQGn8+5loQdxzPQThbqesqqx/uGKrak2lM2iUJ/JfEF+PmhV
         3h42QvOEHSSsWT2rXPKDj/3N6DCJ9xMAiXRYmJle9QGIFIZwKF+5tBuaGn8rEC1mW65D
         L/sD32B0ztYMshr0QQVNKOfYrnwj/5yJRzv4PmCC7pToYqaoAUCppx2jZDX+Az5jWiLT
         O1FQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1706777621; x=1707382421;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=3rVfpGVMKcHQ+Pz1l+4Z0DTw1yDBU155v1QPWqdBOy8=;
        b=hEfyO4sUjdVfyil4CVA6D9ddPH/WGrSSdHgp7TRoI/9kGrawiQr42btchR1IfPVspt
         oJzWX/j5K2Nepc9WCX502uWCbKmoyO28nLaSGGkJ2XuOGujUofH6DaS4ii3WNFfEBoJG
         Wr7tDHcWMzkan4G8Nz23+AGlPwNb5ko6L/NAD6aL5x51IGFkZ92waMPqNhN3u4hr+T3a
         fh3Wbw++tnhmON9abhtR43aGjEW4TpWaEyvD1FZT51s+sGTSd5Qw3hSxIrp2x4DXUu30
         eDcp6CJ/Vc03EZRmCn1JQgn8tzHF8/gAguPUx001UivSQJetSDTeuMEpO74H62JdC2cJ
         Kvpg==
X-Gm-Message-State: AOJu0YwStKmJ5FIWZm6SXcjR2bl3hEjCFPA1+aobsnuUAYgtM4TMdHET
	LI1aqa7JzdGPwNlvUwB5SL+oOglhX2aPytUi/CQ/1z/Zh1pnJ1/f
X-Google-Smtp-Source: AGHT+IFmluH3/7ItKFaz1R4mXYULxsGmWFuSfwODJTubGDqjsPrpt6S1rPxRt/TgykYhWj/eCyJIZg==
X-Received: by 2002:a05:6a20:d488:b0:19e:3a9f:f900 with SMTP id im8-20020a056a20d48800b0019e3a9ff900mr3703346pzb.1.1706777620795;
        Thu, 01 Feb 2024 00:53:40 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:9e3:b0:296:e78:744e with SMTP id 90-20020a17090a09e300b002960e78744els417800pjo.0.-pod-prod-06-us;
 Thu, 01 Feb 2024 00:53:39 -0800 (PST)
X-Received: by 2002:a17:90b:4b0d:b0:296:1e69:6f4f with SMTP id lx13-20020a17090b4b0d00b002961e696f4fmr327833pjb.11.1706777619269;
        Thu, 01 Feb 2024 00:53:39 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1706777619; cv=none;
        d=google.com; s=arc-20160816;
        b=ZazCP5bYP0jRzGVOf6C1Ik9Yfg/5oJ0OF38jLKJvtSACmNgUDc6NHK54t860UwYh8H
         RKQ4IyxNgVf1MpAo7HFELzYueYclt2rpZgTkrwoudlorEhmAP5/HPxRLANrmVRDoOxJG
         zoRk4XoSl/fHdiSJiubsFLrC6RhuU6IirqXtrmVtKiNd9EgQp1Wl9EXaoAZppfpDku/7
         wwNU2KoMPn6ARdckg5m6xoWuKdpkOAbet8NhSoKICZJGPo5fWquHplprcl4BBeIbiW6x
         QTeDEW0jS2FXTXNDSyv0hJnF8gto5FwLzRgfvKiEY7RbVxIWfefp94uANnD/ykztTzzN
         CY6A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=9X/QBAjvJKlfeOxD/oXT29ra0R70AXdnTz+IJPfF+Ec=;
        fh=8TyBmIkc8BHeP5Pz1GYSQ+oNjLn9219YiEplPYrwY2I=;
        b=eJw+huqmxQLLxjFtM6iENhLMr51iNeeDznCJwnIeoV6T/9ei4R5+l/c8pEXdY50m6e
         yrUkDebg88Babejizpie46nzGwk+gPJ7Eoyg7oOQa0ZwpHBZizp1lZl3AjM976IHHXy9
         PPOFLf2ka4nDg80cG5cC/Uz+PLMzMxm56zt/0xR0DJSxrasBnpvJkWG0hcN4vEYdIHPp
         Bo9/z/iAQm/Hp9SKalfZkZKHuAnNqkNKmJLeVPDcZGLXizeusY9kdXdoCfq5Mna8rpwA
         /Pkls+xGZHvcAcvCvO4s9nyimM0G2VxWb5Kv7wqDvvSQvNCk7Nbe8b26/iOlU7hbWsyo
         r0qw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="nU4/cpgE";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::930 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Forwarded-Encrypted: i=0; AJvYcCWUTGzbx1ughK66hJq7XvXTbDkkW7UDBGo/k68WcnDuewbs3HL1ltsxpfxVnAkY1A1PHZyDB9gYevoObHxBSYWe9PPpWT7LJGkMjg==
Received: from mail-ua1-x930.google.com (mail-ua1-x930.google.com. [2607:f8b0:4864:20::930])
        by gmr-mx.google.com with ESMTPS id na18-20020a17090b4c1200b00296206fa75bsi12934pjb.0.2024.02.01.00.53.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 01 Feb 2024 00:53:39 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::930 as permitted sender) client-ip=2607:f8b0:4864:20::930;
Received: by mail-ua1-x930.google.com with SMTP id a1e0cc1a2514c-7d60ee03b54so274085241.2
        for <kasan-dev@googlegroups.com>; Thu, 01 Feb 2024 00:53:39 -0800 (PST)
X-Received: by 2002:a05:6102:364:b0:46b:29df:6977 with SMTP id
 f4-20020a056102036400b0046b29df6977mr4054423vsa.10.1706777618171; Thu, 01 Feb
 2024 00:53:38 -0800 (PST)
MIME-Version: 1.0
References: <20240201083259.1734865-1-elver@google.com>
In-Reply-To: <20240201083259.1734865-1-elver@google.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 1 Feb 2024 09:52:59 +0100
Message-ID: <CANpmjNNtLMX8cB-YS_u3TWq-v=2XFDwhQKi+SCoXKKSZf39qaw@mail.gmail.com>
Subject: Re: [PATCH -mm] stackdepot: do not use flex_array_size() in memcpy()
To: elver@google.com, Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Konovalov <andreyknvl@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vlastimil Babka <vbabka@suse.cz>, linux-kernel@vger.kernel.org, 
	linux-mm@kvack.org, kasan-dev@googlegroups.com, 
	Stephen Rothwell <sfr@canb.auug.org.au>, "Gustavo A . R . Silva" <gustavoars@kernel.org>, 
	Kees Cook <keescook@chromium.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b="nU4/cpgE";       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::930 as
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

On Thu, 1 Feb 2024 at 09:35, Marco Elver <elver@google.com> wrote:
>
> Since 113a61863ecb ("Makefile: Enable -Wstringop-overflow globally")
> string overflow checking is enabled by default. Unfortunately the
> compiler still isn't smart enough to always see that the size will never
> overflow.
>
> Specifically, in stackdepot, we have this before memcpy()'ing a
> stacktrace:
>
>   if (nr_entries > CONFIG_STACKDEPOT_MAX_FRAMES)
>         nr_entries = CONFIG_STACKDEPOT_MAX_FRAMES;
>   ...
>   memcpy(stack->entries, entries, flex_array_size(stack, entries, nr_entries));
>
> Where 'entries' is an array of unsigned long, and STACKDEPOT_MAX_FRAMES
> is 64 by default (configurable up to 256), thus the maximum size in
> bytes (on 32-bit) would be 1024. For some reason the compiler (GCC
> 13.2.0) assumes that an overflow may be possible and flex_array_size()
> can return SIZE_MAX (4294967295 on 32-bit), resulting in this warning:
>
>  In function 'depot_alloc_stack',
>      inlined from 'stack_depot_save_flags' at lib/stackdepot.c:688:4:
>  arch/x86/include/asm/string_32.h:150:25: error: '__builtin_memcpy' specified bound 4294967295 exceeds maximum object size 2147483647 [-Werror=stringop-overflow=]
>    150 | #define memcpy(t, f, n) __builtin_memcpy(t, f, n)
>        |                         ^~~~~~~~~~~~~~~~~~~~~~~~~
>  lib/stackdepot.c:459:9: note: in expansion of macro 'memcpy'
>    459 |         memcpy(stack->entries, entries, flex_array_size(stack, entries, nr_entries));
>        |         ^~~~~~
>  cc1: all warnings being treated as errors
>
> Silence the false positive warning by inlining the multiplication
> ourselves.
>
> Link: https://lore.kernel.org/all/20240201135747.18eca98e@canb.auug.org.au/
> Fixes: d869d3fb362c ("stackdepot: use variable size records for non-evictable entries")
> Reported-by: Stephen Rothwell <sfr@canb.auug.org.au>
> Signed-off-by: Marco Elver <elver@google.com>
> Cc: Gustavo A. R. Silva <gustavoars@kernel.org>
> Cc: Kees Cook <keescook@chromium.org>
> ---
>  lib/stackdepot.c | 2 +-
>  1 file changed, 1 insertion(+), 1 deletion(-)
>
> diff --git a/lib/stackdepot.c b/lib/stackdepot.c
> index 8f3b2c84ec2d..e6047f58ad62 100644
> --- a/lib/stackdepot.c
> +++ b/lib/stackdepot.c
> @@ -456,7 +456,7 @@ depot_alloc_stack(unsigned long *entries, int nr_entries, u32 hash, depot_flags_

Sigh, switching this 'int nr_entries' to 'unsigned int' also fixes it
- please disregard this patch.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNtLMX8cB-YS_u3TWq-v%3D2XFDwhQKi%2BSCoXKKSZf39qaw%40mail.gmail.com.
