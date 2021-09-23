Return-Path: <kasan-dev+bncBC7OBJGL2MHBBYVDWGFAMGQELRKKFWQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1038.google.com (mail-pj1-x1038.google.com [IPv6:2607:f8b0:4864:20::1038])
	by mail.lfdr.de (Postfix) with ESMTPS id EA3D1415BBF
	for <lists+kasan-dev@lfdr.de>; Thu, 23 Sep 2021 12:07:31 +0200 (CEST)
Received: by mail-pj1-x1038.google.com with SMTP id n3-20020a17090a394300b0019765b9bd7bsf3690216pjf.8
        for <lists+kasan-dev@lfdr.de>; Thu, 23 Sep 2021 03:07:31 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1632391650; cv=pass;
        d=google.com; s=arc-20160816;
        b=utM1s399+qfdYtVkbAXJ+wM47ykkcBWDr4l/MXildHU8QNt3ufmYi7iqO/VuzxPte6
         WHmeH+lPwUMkzGwz34OaWVa83IkNmJ/lvmHAANpshQMYAUqPhkD9QHDqkXhkraH79GYk
         3GfbW5R6Ixy3VHMlN+oMSfQb0Kl3ozW0+ZGWn7KZr8GOv7Z/TbrLpV6HpwmrfU5uTh0S
         HjbuhaaUww1w7hlZdpp2P5rQig0xnN2AickQDeKOUv0feydbGDz1u7WMZKr1hElGC8Tz
         0p79TKKxYNEAUmkGbP6LErKjWuoyDY8EqI0wYmMkGOHI0t79dlDMvahJ/8hjbDd0eFhl
         tFRA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=VGeUBXtV09VFNq5pQGiVRl9Pf0eXolMNPSygLSu6QZY=;
        b=N0v+W0dEJrTZrVosrP1u8qajGHIwmjV4AJQzHOQb3pot3fwry5Kh95wbpqV76Y9tKx
         mnn+aZ8kuqdZSBguKIPJBWSRaV5Dn+Z3Yy4uMP1601Ne7RW9E8Q4cEm3DNh9Fl/yO8n9
         R2zf3CYZFVlr/VlMeKrCqtdxSWj3IEVjzKuTVtVRMtBIUpNs1DA+nQrufZbiFCfJvdP0
         cqRqhkiFIgqTiZUt+zXjWHlaGsaIb8MZ8JVa061ywqmlXYa5PdCZuNq5BLZEuVzvqWOH
         TsUdt2+l5Y1rk0v11mzYaamCjlnNCrlMYT2J6y6NB0l8MMsVgS+nGLz8svPyq0qGiwZz
         kIgw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=gx9iJmpV;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::334 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=VGeUBXtV09VFNq5pQGiVRl9Pf0eXolMNPSygLSu6QZY=;
        b=BrmQnbtaFonbRzeUlPtN1Y4Pfcr7E+EGHZm+5EdKKIiqFU0WJkjBAGb7uW/IEgWC7r
         uD+oyPaGEodgxLCqbVutIVyrlii2vj4HogcHHHPkGvJS/aYxd7yQCvEwCfM4LpGTyUmK
         DwDR919t5g2UlkWIOiX3K746ZxprUWw4Zd4JEiyTLYyvHSSxvxda7mSFHHfiUYZ2RP8t
         leejfC3gdwZqn4UPQVoDtqHoAbSMPlWgMyLbLGgLNxlxhWd1hgRiKtdVq6m6fxD4ZU2m
         pd24nJ2p8MNBz/ZFoZivDI96xLFh1U018ekTC+ayfAwLB6bNF/k+1B3xwrZw0+uNFoC4
         Ho+w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=VGeUBXtV09VFNq5pQGiVRl9Pf0eXolMNPSygLSu6QZY=;
        b=PCOzgA+/7zOcFSZ78Iewi2YrocjytztfHkij2ayqJOmOQGslgonH4GH3ZL7rXo7Le0
         1EIdmvRQr4Rw6Ydh3n5nYy5PKr43JgxTYCeqO6fD/EBNcwPy3Y+/fW3hGV4hA9NnfaYT
         Cwy4F6qfKTU5HuOPUbgmJC4EnX11SknCY9wlurARmklyLnYy8ojT8xYTeohvqQVh6Q9h
         pihPHEgmR/aKiD4CFy/DTfW5dNMW3tiWP1J298dKpEg4WAFZFX+kc7E0uG9/W/K9e93N
         28k3yFxgd/acV8gBpWOS+bn0IKps9R22SMcgR6FJZs96Ke1fUjvKuJsvnMbScvUHgvh5
         0RcQ==
X-Gm-Message-State: AOAM532wvM93aEahoo4X2S8NfHmWSN84lyQMf7dLMYqfFmRPIc13Ylxs
	YPiQpbX+S9pMkWn5gF9Y76Q=
X-Google-Smtp-Source: ABdhPJwxJuILLFdijPvQy01D+LEk7CPXtz1BmAxr3PjdOkK0mpjmIoyKPYES38Ql4vY9eeepRh755Q==
X-Received: by 2002:a63:3483:: with SMTP id b125mr3433297pga.35.1632391650630;
        Thu, 23 Sep 2021 03:07:30 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:7f82:: with SMTP id a124ls2048227pfd.2.gmail; Thu, 23
 Sep 2021 03:07:30 -0700 (PDT)
X-Received: by 2002:a63:5c51:: with SMTP id n17mr3428892pgm.376.1632391650076;
        Thu, 23 Sep 2021 03:07:30 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1632391650; cv=none;
        d=google.com; s=arc-20160816;
        b=XW+uIQUDUz8DFGNQkUGT6tDxH77GIbDGtSDBIVXKsKXdvJeoJlhYWS3HCLWckoSVwp
         /ao5zzNVBqLy51zqykYYIE+ehL2F5GqCTJkXwpJRXNevdarzqrxyYxKtjSRBfDc/CWdy
         wzrGyootiVdVBGYwQEg7dR5oDLQE6u4kenA9ddnzknLxpsFJNdgNlrWGGwtwVMqkl8nX
         2OpqsW1f+a0pD9bnizaPXT2Xws0lcpEtDfJKm9UQfJcXpd62eFzNNxKbuo6ib8J3CU63
         Kmf/63UIz/gGyOSHINkFwn4+oyRADuU+jnd+IAc513Ofzbc+lvCYgPmhbP69ZQHMg3rv
         c1lw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=PGizDeLzRGbblNybKFZtNPTDc7twErSudSG0K9dzTyI=;
        b=WpB6pr5foVLw5Z9AXbauqq4BrEtGhTDgsVYtWawcSXVK8dLe9CxSWgawo5GmNLF8nX
         R2Yxmavgr6iRwEzpSFdjjFRymGYgNzGZhLY9dz/7OIy7YqnV2FeOoOxKVZMPDozz7yTu
         Vtwqh7uch1pv8oejHOSVTvsu4T86PiqNs/NmCzRD3E82usKe7cQ2XKQCmICs/ftXld6l
         4rPjUBHRtxugtOpb/J6sjfQJPoR/qpyqshD1tA/C6hJl1l4IqB7tjP947Nj4otTRTKN/
         BrXjEWPcw/dSfj+lHrx5x6w4kSaA2oVnP2ejC2GPySnJb13JlKdmybwNeNxrDHfAjj0v
         f+nw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=gx9iJmpV;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::334 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x334.google.com (mail-ot1-x334.google.com. [2607:f8b0:4864:20::334])
        by gmr-mx.google.com with ESMTPS id m11si3274pll.4.2021.09.23.03.07.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 23 Sep 2021 03:07:30 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::334 as permitted sender) client-ip=2607:f8b0:4864:20::334;
Received: by mail-ot1-x334.google.com with SMTP id 77-20020a9d0ed3000000b00546e10e6699so7856979otj.2
        for <kasan-dev@googlegroups.com>; Thu, 23 Sep 2021 03:07:30 -0700 (PDT)
X-Received: by 2002:a9d:135:: with SMTP id 50mr3469525otu.295.1632391649222;
 Thu, 23 Sep 2021 03:07:29 -0700 (PDT)
MIME-Version: 1.0
References: <20210922205525.570068-1-nathan@kernel.org>
In-Reply-To: <20210922205525.570068-1-nathan@kernel.org>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 23 Sep 2021 12:07:17 +0200
Message-ID: <CANpmjNNqgUSbiPHOpD8z5JAv2aiujxAMiO4siymYdU6zpid_2g@mail.gmail.com>
Subject: Re: [PATCH] kasan: Always respect CONFIG_KASAN_STACK
To: Nathan Chancellor <nathan@kernel.org>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Nick Desaulniers <ndesaulniers@google.com>, Arnd Bergmann <arnd@arndb.de>, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, llvm@lists.linux.dev, 
	linux-riscv <linux-riscv@lists.infradead.org>, Paul Walmsley <paul.walmsley@sifive.com>, 
	Palmer Dabbelt <palmer@dabbelt.com>, Albert Ou <aou@eecs.berkeley.edu>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=gx9iJmpV;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::334 as
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

On Wed, 22 Sept 2021 at 22:55, Nathan Chancellor <nathan@kernel.org> wrote:
> Currently, the asan-stack parameter is only passed along if
> CFLAGS_KASAN_SHADOW is not empty, which requires KASAN_SHADOW_OFFSET to
> be defined in Kconfig so that the value can be checked. In RISC-V's
> case, KASAN_SHADOW_OFFSET is not defined in Kconfig, which means that
> asan-stack does not get disabled with clang even when CONFIG_KASAN_STACK
> is disabled, resulting in large stack warnings with allmodconfig:
>
> drivers/video/fbdev/omap2/omapfb/displays/panel-lgphilips-lb035q02.c:117:12:
> error: stack frame size (14400) exceeds limit (2048) in function
> 'lb035q02_connect' [-Werror,-Wframe-larger-than]
> static int lb035q02_connect(struct omap_dss_device *dssdev)
>            ^
> 1 error generated.
>
> Ensure that the value of CONFIG_KASAN_STACK is always passed along to
> the compiler so that these warnings do not happen when
> CONFIG_KASAN_STACK is disabled.
>
> Link: https://github.com/ClangBuiltLinux/linux/issues/1453
> References: 6baec880d7a5 ("kasan: turn off asan-stack for clang-8 and earlier")
> Signed-off-by: Nathan Chancellor <nathan@kernel.org>

Reviewed-by: Marco Elver <elver@google.com>

[ Which tree are you planning to take it through? ]

Note, arch/riscv/include/asm/kasan.h mentions KASAN_SHADOW_OFFSET in
comment (copied from arm64). Did RISC-V just forget to copy over the
Kconfig option?


> ---
>  scripts/Makefile.kasan | 3 ++-
>  1 file changed, 2 insertions(+), 1 deletion(-)
>
> diff --git a/scripts/Makefile.kasan b/scripts/Makefile.kasan
> index 801c415bac59..b9e94c5e7097 100644
> --- a/scripts/Makefile.kasan
> +++ b/scripts/Makefile.kasan
> @@ -33,10 +33,11 @@ else
>         CFLAGS_KASAN := $(CFLAGS_KASAN_SHADOW) \
>          $(call cc-param,asan-globals=1) \
>          $(call cc-param,asan-instrumentation-with-call-threshold=$(call_threshold)) \
> -        $(call cc-param,asan-stack=$(stack_enable)) \
>          $(call cc-param,asan-instrument-allocas=1)
>  endif
>
> +CFLAGS_KASAN += $(call cc-param,asan-stack=$(stack_enable))
> +
>  endif # CONFIG_KASAN_GENERIC
>
>  ifdef CONFIG_KASAN_SW_TAGS
>
> base-commit: 4057525736b159bd456732d11270af2cc49ec21f
> --
> 2.33.0.514.g99c99ed825
>
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNqgUSbiPHOpD8z5JAv2aiujxAMiO4siymYdU6zpid_2g%40mail.gmail.com.
