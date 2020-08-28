Return-Path: <kasan-dev+bncBDX4HWEMTEBRBY6EUP5AKGQETLQM33A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63b.google.com (mail-pl1-x63b.google.com [IPv6:2607:f8b0:4864:20::63b])
	by mail.lfdr.de (Postfix) with ESMTPS id CCF1F2558EC
	for <lists+kasan-dev@lfdr.de>; Fri, 28 Aug 2020 12:54:28 +0200 (CEST)
Received: by mail-pl1-x63b.google.com with SMTP id bg5sf484249plb.18
        for <lists+kasan-dev@lfdr.de>; Fri, 28 Aug 2020 03:54:28 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1598612067; cv=pass;
        d=google.com; s=arc-20160816;
        b=m1T2mkdUKRADEayjxhARX4vY8wH1woXwJjD13hyqWHC5ZDMQ5dbxEda3+P0F9v+q+d
         sMtougSkq6E9azsSIYvIkMmr7N5hPEKuBJ1LYbOWKvRmYObHug9dY4AplLDWNMi0z0if
         rPYThGlrzlgxG+iFXC5q33T3bQWolFpYlqOW0Eo9gbbIpm9rVy5kEpYg1WpFWZFiEyNI
         GnaqtIKV1Zl2pJyGUMIJ4IiHpgpNPXOuisGzXLXWYQyYBdXWC9fBDD4R+mk4GOGYyjNC
         Hg5bOYSxO5I0fnF3G/Tr+6mcrOQjA8JVvIYqpbUGGaAq6wsZoaNWyJhDNA7U3hw4E1Ae
         li5w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=Egz1rHqpDQXI8JHZZVTxL1JMy/upGFqrX4ywXrQed7A=;
        b=OLyG2JcjZHOtT0RAHbaMLb+UZDhwg2YPKKpXL8Y/W/AubZFpw+ScW1JfkGFnmh2gnf
         g04pU1GkeihNGQshXzM6QSDBk5iDo6QzqyKb7Lc+VRLJbHe0fsrXzyHaV0PABq1LKQD/
         lOGNrnAPBK64KzhK/16O5i4tDPkloYCa1rSpN2zk9Qv0G3UjhYV++AoCHIOKYGZ4pHEP
         9NeQPms7Sw56nfFQ/RsGan8uSMoDzRjUVdkysSxn7oi9AfNUSafU6+HHNOUoeg2P3VdY
         2Elt5ie5PQ/3P+C/BDDq+bG3ZiiezeY1nd8Q5tG7Vk6ySSWzIlVGmWQflkwwHgPX+ppf
         fMHA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=FwSk+QOE;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::542 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Egz1rHqpDQXI8JHZZVTxL1JMy/upGFqrX4ywXrQed7A=;
        b=iDYjeJYZvid1KBvgA5v9+0gSBj0znVFmakETT7IhyRXYlywM9dqRbjZ2srjJ6u+kRo
         zFAY/VA5KCyQiZkz/rk6dpJyuz4W1i8FW8I+ZPFTU1KnvRQI7DB3ixAhGUlAO4ZJqAJb
         vfuznyV+7YOhlYp7qF7nqEmUYOROB9wClwZCsVS2jdQGGxObYbDC0uOMh86MUhX21zs7
         DRFi/GY6iM3oIesFtIsIaDEMEFrBVV7f39/kgbiau6aPM7T1kasL00SHXJE9VhlkJjxm
         /1tuUpSmmGNINYYOYdCgA2sBaak5nq+M8nUa6pzDdv8sTdlfdjc1Mal60yNa28V7Jfc0
         oTFA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Egz1rHqpDQXI8JHZZVTxL1JMy/upGFqrX4ywXrQed7A=;
        b=RW7sh+VYp2ASYt3z3o0hCC2XAd5CbMvf3FUzKm99cvo0Se6EcCi/lwb3txl2bjylG3
         tNvDKU4TQzzyfNDeNgFROQqJKJoiTMWsbwmfokc1P7pADgnjq3nQU68VUrs0IGB44N2t
         ev0JSMsInA1k1osw37VqIF7/byuCPow0HHANYthnByyeItXxBE6hQ85Iagi//bLonTG3
         PUeVENx54mBlQOToVpHWY6v7MpiZYHpnJIAU3ug9HNGS8gqLxrI04zOyFFfRIif2MQPf
         zoQgcV37i64YBFJH+PtZGDvnR2YxkfB5xmQCmltEtpjswkAmCewtwQEjbZ5LU4EJb/wO
         vkWQ==
X-Gm-Message-State: AOAM5309T9oySXxMmsnVitzk3vM2m7bQgi8pu6aWKZFfX2WyKhg7Ps2Q
	MYTvKjbAtbItEDqG3zzB2Hw=
X-Google-Smtp-Source: ABdhPJy09UDvl8gHb8ZLdqDSEON+1P862AB+PQEEacg1eXYw4zbLe8E6kunWQK1oH4O7cphj5JkvtQ==
X-Received: by 2002:a17:902:7247:: with SMTP id c7mr845014pll.273.1598612067358;
        Fri, 28 Aug 2020 03:54:27 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:f158:: with SMTP id o24ls220518pgk.4.gmail; Fri, 28 Aug
 2020 03:54:26 -0700 (PDT)
X-Received: by 2002:a63:1748:: with SMTP id 8mr836342pgx.207.1598612066838;
        Fri, 28 Aug 2020 03:54:26 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1598612066; cv=none;
        d=google.com; s=arc-20160816;
        b=THYRSpkOsfwymLXMu0F0O4Wk/TBYWn+PB8tQ1v26ugjD2gubJaiF25jrwbwamUcUrV
         TMilcJtw9hMB8RmGFB9M4qPDSK0IQHB9Rz1y9841tn2WHtZkau1Q6+5R8cD3lhvWz2Lb
         NlidNAPzuS0owW3XGcuBXUZhnc8cQdoDnJ2zCT5kxd6cdAFOQlrsYYFcK+bkPyLLH6VK
         7cDOLtOJ2mwRR97FCtFf/PKh8NFh4fFyqfsoTT8RaRX8Ruydy8qIPrlLR3Y60aHOoogC
         EM1/n2syBvlBsJdnikubyO9c5EocP/JaSUN0szcDQisjKrYjKiYtJwfTFhHyQByceODl
         NVfg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=fhcvo1n+CsYdI8OH67mOVUpzZUMHRybLogH+vvrmtQs=;
        b=aNIcuwRgztZj6m+FhQ/8PZ3p1a8yuP3WZlFf9+C1jXi/HMvux/apLdkLtNyLzec5FT
         m4z4DAD18dPDqCjQn9RluKZWqpTsJ9Vl6f5CCTdfMGepmPwLj9Kn5OZDNAI/3kMZiYZF
         jNKg+dd12rR9b2wzlC2LHmNhzbXATl7Dcb2DdaIRwRCKiDlEVcjonN+vRfe0kUk0y7aM
         QzGLg76v6RVA/XkGP3z2NXMIW2OYFMKj9WY++4dxcyuoD54ukHTTzGltiY/yHPiJ5eSQ
         QkQLab5VI+CjrdVcvZcjheSeP54tSGZalHykIoXFrZOpRESLRSeJd/B9sLh9Fspj+tuE
         hSYg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=FwSk+QOE;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::542 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pg1-x542.google.com (mail-pg1-x542.google.com. [2607:f8b0:4864:20::542])
        by gmr-mx.google.com with ESMTPS id bx14si34298pjb.3.2020.08.28.03.54.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 28 Aug 2020 03:54:26 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::542 as permitted sender) client-ip=2607:f8b0:4864:20::542;
Received: by mail-pg1-x542.google.com with SMTP id g29so288084pgl.2
        for <kasan-dev@googlegroups.com>; Fri, 28 Aug 2020 03:54:26 -0700 (PDT)
X-Received: by 2002:aa7:8c0f:: with SMTP id c15mr784835pfd.135.1598612066279;
 Fri, 28 Aug 2020 03:54:26 -0700 (PDT)
MIME-Version: 1.0
References: <20200826201420.3414123-1-ndesaulniers@google.com>
 <20200826214228.GB1005132@ubuntu-n2-xlarge-x86> <20200827190217.GA3610840@elver.google.com>
In-Reply-To: <20200827190217.GA3610840@elver.google.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 28 Aug 2020 12:54:15 +0200
Message-ID: <CAAeHK+zyjKWrSU-udVuqLN1i2c0bxNTMVirGjaRfXN=opn6spw@mail.gmail.com>
Subject: Re: [PATCH] compiler-clang: add build check for clang 10.0.1
To: Marco Elver <elver@google.com>
Cc: Nick Desaulniers <ndesaulniers@google.com>, Nathan Chancellor <natechancellor@gmail.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Sedat Dilek <sedat.dilek@gmail.com>, 
	Miguel Ojeda <miguel.ojeda.sandonis@gmail.com>, Kees Cook <keescook@chromium.org>, 
	"Paul E. McKenney" <paulmck@kernel.org>, "Peter Zijlstra (Intel)" <peterz@infradead.org>, 
	Randy Dunlap <rdunlap@infradead.org>, Ingo Molnar <mingo@kernel.org>, 
	Sami Tolvanen <samitolvanen@google.com>, LKML <linux-kernel@vger.kernel.org>, 
	clang-built-linux <clang-built-linux@googlegroups.com>, kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=FwSk+QOE;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::542
 as permitted sender) smtp.mailfrom=andreyknvl@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

On Thu, Aug 27, 2020 at 9:02 PM Marco Elver <elver@google.com> wrote:
>
> On Wed, Aug 26, 2020 at 02:42PM -0700, Nathan Chancellor wrote:
> > On Wed, Aug 26, 2020 at 01:14:19PM -0700, Nick Desaulniers wrote:
> > > During Plumbers 2020, we voted to just support the latest release of
> > > Clang for now.  Add a compile time check for this.
> > >
> > > Older clang's may work, but we will likely drop workarounds for older
> > > versions.
> >
> > I think this part of the commit message is a little wishy-washy. If we
> > are breaking the build for clang < 10.0.1, we are not saying "may work",
> > we are saying "won't work". Because of this, we should take the
> > opportunity to clean up behind us and revert/remove parts of:
> >
> > 87e0d4f0f37f ("kbuild: disable clang's default use of -fmerge-all-constants")
> > b0fe66cf0950 ("ARM: 8905/1: Emit __gnu_mcount_nc when using Clang 10.0.0 or newer")
> > b9249cba25a5 ("arm64: bti: Require clang >= 10.0.1 for in-kernel BTI support")
> > 3acf4be23528 ("arm64: vdso: Fix compilation with clang older than 8")
> >
> > This could be a series or a part of this commit, I do not have a
> > strong preference. If we are not going to clean up behind us, this
> > should be a warning and not an error.
>
> There are also some other documentation that would go stale. We probably
> have to change KASAN docs to look something like the below.
>
> I wish we could also remove the "but detection of out-of-bounds accesses
> for global variables is only supported since Clang 11", but Clang 10 is
> a vast improvement so I'm not complaining. :-)
>
> Acked-by: Marco Elver <elver@google.com>
>
> Thanks,
> -- Marco
>
> ------ >8 ------
>
> From 13d03b55c69dec813d94c1481dcb294971f164ef Mon Sep 17 00:00:00 2001
> From: Marco Elver <elver@google.com>
> Date: Thu, 27 Aug 2020 20:56:34 +0200
> Subject: [PATCH] kasan: Remove mentions of unsupported Clang versions
>
> Since the kernel now requires at least Clang 10.0.1, remove any mention
> of old Clang versions and simplify the documentation.
>
> Signed-off-by: Marco Elver <elver@google.com>
> ---
>  Documentation/dev-tools/kasan.rst | 4 ++--
>  lib/Kconfig.kasan                 | 9 ++++-----
>  2 files changed, 6 insertions(+), 7 deletions(-)
>
> diff --git a/Documentation/dev-tools/kasan.rst b/Documentation/dev-tools/kasan.rst
> index 38fd5681fade..4abc84b1798c 100644
> --- a/Documentation/dev-tools/kasan.rst
> +++ b/Documentation/dev-tools/kasan.rst
> @@ -13,10 +13,10 @@ KASAN uses compile-time instrumentation to insert validity checks before every
>  memory access, and therefore requires a compiler version that supports that.
>
>  Generic KASAN is supported in both GCC and Clang. With GCC it requires version
> -8.3.0 or later. With Clang it requires version 7.0.0 or later, but detection of
> +8.3.0 or later. Any supported Clang version is compatible, but detection of
>  out-of-bounds accesses for global variables is only supported since Clang 11.
>
> -Tag-based KASAN is only supported in Clang and requires version 7.0.0 or later.
> +Tag-based KASAN is only supported in Clang.
>
>  Currently generic KASAN is supported for the x86_64, arm64, xtensa, s390 and
>  riscv architectures, and tag-based KASAN is supported only for arm64.
> diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
> index 047b53dbfd58..033a5bc67ac4 100644
> --- a/lib/Kconfig.kasan
> +++ b/lib/Kconfig.kasan
> @@ -54,9 +54,9 @@ config KASAN_GENERIC
>           Enables generic KASAN mode.
>
>           This mode is supported in both GCC and Clang. With GCC it requires
> -         version 8.3.0 or later. With Clang it requires version 7.0.0 or
> -         later, but detection of out-of-bounds accesses for global variables
> -         is supported only since Clang 11.
> +         version 8.3.0 or later. Any supported Clang version is compatible,
> +         but detection of out-of-bounds accesses for global variables is
> +         supported only since Clang 11.
>
>           This mode consumes about 1/8th of available memory at kernel start
>           and introduces an overhead of ~x1.5 for the rest of the allocations.
> @@ -78,8 +78,7 @@ config KASAN_SW_TAGS
>           Enables software tag-based KASAN mode.
>
>           This mode requires Top Byte Ignore support by the CPU and therefore
> -         is only supported for arm64. This mode requires Clang version 7.0.0
> -         or later.
> +         is only supported for arm64. This mode requires Clang.
>
>           This mode consumes about 1/16th of available memory at kernel start
>           and introduces an overhead of ~20% for the rest of the allocations.
> --
> 2.28.0.297.g1956fa8f8d-goog
>

Reviewed-by: Andrey Konovalov <andreyknvl@google.com>

Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2BzyjKWrSU-udVuqLN1i2c0bxNTMVirGjaRfXN%3Dopn6spw%40mail.gmail.com.
