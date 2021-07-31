Return-Path: <kasan-dev+bncBC7OBJGL2MHBBM5GSSEAMGQEAU2I22Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103d.google.com (mail-pj1-x103d.google.com [IPv6:2607:f8b0:4864:20::103d])
	by mail.lfdr.de (Postfix) with ESMTPS id 726573DC542
	for <lists+kasan-dev@lfdr.de>; Sat, 31 Jul 2021 11:09:09 +0200 (CEST)
Received: by mail-pj1-x103d.google.com with SMTP id j22-20020a17090a7e96b0290175fc969950sf16047831pjl.4
        for <lists+kasan-dev@lfdr.de>; Sat, 31 Jul 2021 02:09:09 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1627722548; cv=pass;
        d=google.com; s=arc-20160816;
        b=fXocyA2yeTp94Ve/J2K4jsDs9DWmLc1j2xbJO75LNxqY5CSj7I+pMkW5UnKYW/AerB
         QDt64fcaikr5SadoZOOpfXyObPwGPI4zZcVpOaTtDRm0Bm0yyY+ryeIetD8oQtQMbn7O
         yLnHl9aNfPosTKPwhOpjdjgv/ZInHdRmdoS7L2CW2AmqXPHQ6JHlZEUzpPmqS8Z8nnFd
         mrJenUYJNAPkR4Zq0oP8n9vo8uoXbK+OfkRlbMMeOM3p51i1bEI0UM1S5kckCWQ4TyYJ
         ayJyS96DMLKSE4aAE8i1RuzKLZpFUpy4bZStzyLXaq7PfJJodIJUsM77aJ/gASRkfise
         Likw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=TGpJDtZ6KCGzNvc67nIQjs5iubw4iSFBx7w+VsgzKZQ=;
        b=LenepCK42SupPF/Gnn/PPOD2Ep7EaETeyQGhucP07xLhjfhzkfRLBJi15lg7eJHPny
         4MXUij+DJOInIGiXZAo/xYbyAuzq8vURe1e0bqmh2jalMuplR4Lr2jTwV6ygHugabvb3
         /jeuGzki19fT0IAGox8h9AXlcgutEyhO7HItVbxC5EoakSBfPuiE/lzn9wJfxMkeXvj+
         GOIVx737b1zJS1Wo241jOS6YhPQjZbBj/b1GEb0zare+iFCk8cgHfyJBpmseFaHUezwE
         mo8xw01rYSHkyPAoJiESqqvMWWNpeMi6xr5NOiEIKTd7V2xizCyp4r10L9599mnsyxq5
         tEUw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Gp8ddgcS;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32d as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=TGpJDtZ6KCGzNvc67nIQjs5iubw4iSFBx7w+VsgzKZQ=;
        b=iAi21RPYBLno3pA5nwf3M7rYScKHlolyElpciIA035NwqauXAZJFZv7QoEcc7a+n/n
         9bo6XVgAQ3ZvCYcYh0eexbT/EmqWOwZdSQfKsrNvfI8zf32dtCV6gQQpEMLvy1yI7UHZ
         OLf/JyKKNn9x/VqBVIPjokATWSeX1NemiREAPN5CvH19kcEZcsNjqe2fzep3aPXXOiiR
         onqPLYh7I3cQKIOcuKOO7jpZzF6EN33LAGGcEQM+vqJWMXPocXZpqIfdCywqZRCIguD/
         qas6akVMz3ZXchpAKF+GDIjvtbyTZrUtwACTdRMChvGYU+806kVSaa/QWIa4XBcr1RMn
         fOZw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=TGpJDtZ6KCGzNvc67nIQjs5iubw4iSFBx7w+VsgzKZQ=;
        b=jYCuN7XLY1MUoNy9K0gvaRb2jinsVfVA1DwJXcSlolu+zW+psKb2B9vL27oNW6/vHJ
         RJlScv4iu/DI9ZVzJDo+uz85HuhdHQJpIBV9T0WtfLt2JGSKSuHfnnxJWqe9j8ubdn9B
         Kkj8VJzJgXH//+RFRE0qdo63ZCRok5qYSi0/iLaWMjFS1KqdxbHNtjjcZ6CWFYYs8eOa
         yOV6fwGzq5FK8cuqXBTaAZZhNQBPM5uoIT0b7Z2P89QN+DnUcS2RudEaE2PAIB2ZVJXa
         8oHlA9o9LA/Azfc/mKTeRq6QBi//wBl5DOkSfomcqnqveX2c22ewzc8RiWpR2h3aHmTV
         df2g==
X-Gm-Message-State: AOAM530PEy/OfB3IttbrXMrsqahhHpGLj50pKb1Gpo3u9Ga1rU/sdpJV
	moUdC7jhcS1cbAeW2GbSAb4=
X-Google-Smtp-Source: ABdhPJw4NLieOanjTztHqKsQZti4eYnRewYsOIW/7MWKcWqYnpxXprzc+nNEhkTJ+jpynt6HQRNt9Q==
X-Received: by 2002:a17:90a:b10b:: with SMTP id z11mr7483624pjq.181.1627722548013;
        Sat, 31 Jul 2021 02:09:08 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:815:: with SMTP id m21ls1576406pfk.1.gmail; Sat, 31
 Jul 2021 02:09:07 -0700 (PDT)
X-Received: by 2002:aa7:8550:0:b029:32b:963f:f53b with SMTP id y16-20020aa785500000b029032b963ff53bmr7104569pfn.0.1627722547404;
        Sat, 31 Jul 2021 02:09:07 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1627722547; cv=none;
        d=google.com; s=arc-20160816;
        b=yT1LLM3heR77zgbavU6P/VhxcJbChl288f/8pSvGcnBnYWkRvopl4gjxVtG4/vegJU
         mIgJ5C4gILOLfwcw9XXKMRLljY/EXZVXcHZQ6QVzXX363cxViwoIS3/dw5KRveNNsJ+t
         bcxpNM5aFiTEDSqssP8Nuy2cZGZki4yjfKV1IW9zmycqn3XP6BQUhRJxDmUR9cHSmCX8
         ts44hftwIRIfdyOslfE8cvDBPAce9g4Semfe+FVgvSnMXWq6bK3bVislMFX4nPHJj8HU
         0r/Cl0hL0pnyEnw+la+q8CwXxReeX/kl0hJU3fLwrtpj2GPGCZStDzROLFHtIEVUV1EI
         Tbkg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=vaAWrkzE49kpA8JCIiCiOMwaEcjf5J0qZweefCaV6Js=;
        b=ZLT2VBgNTQ/D2AI3qG/Qy1uBfkdUre3AZ24tk3CIVNdsLKUnC5UPzSzc0UwHJQHYQn
         7uPrZo0T3j9iNCUXguusA2sCZM+FtQr6zdDvh70dqd9ISD6xGnUKsbeDLYSJNiL3gjS8
         6UiVRAnc3neSd7QDEzAUbg18rcb8qhnjeuPxkORVWqTDfW4ZXKeyKcAQ1oNmVhmi4xcM
         5JvQf7iIWKtCAge+FbHHv3auO6XZjdMlrM6F+VxbFGlVVuZFsti1LdDaja2oGU16Z5/k
         ievQCBvAVFTeSsYL3iv5iQLudf2r5PCCzuXL6W5pCjCBb7fGovsJwrjmF4TbtsHKScnG
         U9Hw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Gp8ddgcS;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32d as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x32d.google.com (mail-ot1-x32d.google.com. [2607:f8b0:4864:20::32d])
        by gmr-mx.google.com with ESMTPS id c9si230689pfr.5.2021.07.31.02.09.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 31 Jul 2021 02:09:07 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32d as permitted sender) client-ip=2607:f8b0:4864:20::32d;
Received: by mail-ot1-x32d.google.com with SMTP id o2-20020a9d22020000b0290462f0ab0800so12197078ota.11
        for <kasan-dev@googlegroups.com>; Sat, 31 Jul 2021 02:09:07 -0700 (PDT)
X-Received: by 2002:a05:6830:23a7:: with SMTP id m7mr5218486ots.17.1627722546365;
 Sat, 31 Jul 2021 02:09:06 -0700 (PDT)
MIME-Version: 1.0
References: <20210730223815.1382706-1-nathan@kernel.org> <20210731023107.1932981-1-nathan@kernel.org>
In-Reply-To: <20210731023107.1932981-1-nathan@kernel.org>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Sat, 31 Jul 2021 11:08:54 +0200
Message-ID: <CANpmjNMJR7A5FyPLuK+mWLKjZ7z4qJfygXWFpsADxicYE=Kx=g@mail.gmail.com>
Subject: Re: [PATCH v2] vmlinux.lds.h: Handle clang's module.{c,d}tor sections
To: Nathan Chancellor <nathan@kernel.org>
Cc: Kees Cook <keescook@chromium.org>, Arnd Bergmann <arnd@arndb.de>, 
	Nick Desaulniers <ndesaulniers@google.com>, Fangrui Song <maskray@google.com>, linux-arch@vger.kernel.org, 
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, 
	clang-built-linux@googlegroups.com, stable@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=Gp8ddgcS;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32d as
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

On Sat, 31 Jul 2021 at 04:33, Nathan Chancellor <nathan@kernel.org> wrote:
> A recent change in LLVM causes module_{c,d}tor sections to appear when
> CONFIG_K{A,C}SAN are enabled, which results in orphan section warnings
> because these are not handled anywhere:
>
> ld.lld: warning: arch/x86/pci/built-in.a(legacy.o):(.text.asan.module_ctor) is being placed in '.text.asan.module_ctor'
> ld.lld: warning: arch/x86/pci/built-in.a(legacy.o):(.text.asan.module_dtor) is being placed in '.text.asan.module_dtor'
> ld.lld: warning: arch/x86/pci/built-in.a(legacy.o):(.text.tsan.module_ctor) is being placed in '.text.tsan.module_ctor'
>
> Fangrui explains: "the function asan.module_ctor has the SHF_GNU_RETAIN
> flag, so it is in a separate section even with -fno-function-sections
> (default)".
>
> Place them in the TEXT_TEXT section so that these technologies continue
> to work with the newer compiler versions. All of the KASAN and KCSAN
> KUnit tests continue to pass after this change.
>
> Cc: stable@vger.kernel.org
> Link: https://github.com/ClangBuiltLinux/linux/issues/1432
> Link: https://github.com/llvm/llvm-project/commit/7b789562244ee941b7bf2cefeb3fc08a59a01865
> Signed-off-by: Nathan Chancellor <nathan@kernel.org>

Acked-by: Marco Elver <elver@google.com>

For KASAN module_ctors are very much required to support detecting
globals out-of-bounds: https://reviews.llvm.org/D81390
For KASAN the test would have revealed that at the latest.

KCSAN does not yet have much use for the module_ctors, but it may
change in future, so keeping them all was the right call.

Thanks,
-- Marco

> ---
>
> v1 -> v2:
>
> * Fix inclusion of .text.tsan.* (Nick)
>
> * Drop .text.asan as it does not exist plus it would be handled by a
>   different line (Fangrui)
>
> * Add Fangrui's explanation about why the LLVM commit caused these
>   sections to appear.
>
>  include/asm-generic/vmlinux.lds.h | 1 +
>  1 file changed, 1 insertion(+)
>
> diff --git a/include/asm-generic/vmlinux.lds.h b/include/asm-generic/vmlinux.lds.h
> index 17325416e2de..62669b36a772 100644
> --- a/include/asm-generic/vmlinux.lds.h
> +++ b/include/asm-generic/vmlinux.lds.h
> @@ -586,6 +586,7 @@
>                 NOINSTR_TEXT                                            \
>                 *(.text..refcount)                                      \
>                 *(.ref.text)                                            \
> +               *(.text.asan.* .text.tsan.*)                            \
>                 TEXT_CFI_JT                                             \
>         MEM_KEEP(init.text*)                                            \
>         MEM_KEEP(exit.text*)                                            \
>
> base-commit: 4669e13cd67f8532be12815ed3d37e775a9bdc16
> --
> 2.32.0.264.g75ae10bc75
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNMJR7A5FyPLuK%2BmWLKjZ7z4qJfygXWFpsADxicYE%3DKx%3Dg%40mail.gmail.com.
