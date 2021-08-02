Return-Path: <kasan-dev+bncBDYJPJO25UGBBJOAUCEAMGQEUVEXWOI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43d.google.com (mail-wr1-x43d.google.com [IPv6:2a00:1450:4864:20::43d])
	by mail.lfdr.de (Postfix) with ESMTPS id 561CC3DDDDB
	for <lists+kasan-dev@lfdr.de>; Mon,  2 Aug 2021 18:41:10 +0200 (CEST)
Received: by mail-wr1-x43d.google.com with SMTP id c5-20020adfed850000b02901537ecbecc6sf6621511wro.19
        for <lists+kasan-dev@lfdr.de>; Mon, 02 Aug 2021 09:41:10 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1627922470; cv=pass;
        d=google.com; s=arc-20160816;
        b=Ftk3kYwDFmQZb/XGzvT2KDU9ObmddwBc3bJ0Ph/o1LD2T3J5vjKMQVNV8cL7npzyFX
         oyciCjBZnOf8mxytKgD7Yw380fPtWUTZBKJgj49ZrX+lpG4WX1tt0ZuxRXvlhgrwPG0g
         hdIxS61tqtGi6NTep1u6efpo9iVScKFiuLtwYnDES4fvsUxc0jgJf5y1cweF+gv8OuRf
         gPzX44o+x9ETtHUyYN04jhYpGZQEBdwOnKMRY92bP0ezIalInki3ElO+dSwEFp8oKyWM
         cQldLnqSEIwhUby7OWipXByHEQc5ld7oMbIrC700qFu7Iq42DnxNqRmsrfI7xGpDIVi8
         QDVg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=I3A7x/TDpLv5h56BeyCZpLoTghGPveKJh3ARm9n63n4=;
        b=XWDmT9dDS7SYdB8z21I2e+s4z8LdWLm4r9sZRDRBa9FVQWFTIMOa6wb7tqWDtFk1RJ
         5RyMCQKPf6zykbI85KFgyK4QOOxT6dIeOH53Gpw1cQR3lzeXQ44/go4CLeOYqriwR9t6
         FfLK+fDsN7Jcil1Wya4ESRzGeZQzhJ+55rRJtzfWDX3Zk1Yl2jrPCzgrJVtHOA7CrMn3
         vXMq4e4k9YmDK7jEFJ1FbQO/STvrbqgrYI0SbuAdGLlVfGmA//60D9X4mxwXz+KNt8Hh
         pD0cb1j6LQa4pbCnE0CYw4jVpR02MfeSsbkFyHnRRTW42qQxPqEoHDxwTAts4Dntbz+x
         QItA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Iqhh7BSh;
       spf=pass (google.com: domain of ndesaulniers@google.com designates 2a00:1450:4864:20::133 as permitted sender) smtp.mailfrom=ndesaulniers@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=I3A7x/TDpLv5h56BeyCZpLoTghGPveKJh3ARm9n63n4=;
        b=RsKmcnx5gfqaLRqRG1mFpisfpZxhbBUdUVShmpALyTVMPFVVJrEWffL/kOewX3lkU1
         4ssIK99AVokh6IU6oMtvfpuYfoGYlGoaaWIvHhNYalUuSKuPTeq8h8oKocuwVUHdKUUs
         acrmg2N0gn/YUAup5HuweisnwbfdACGE6iVXKd5++WB43v0U/2oYhFRk+a3lCrubovT9
         gK0Z3HXNB6PJkax/7a8BhfLs1MyTkbkkh999P0Qp7bp676JNNfAz/lcWuQblpBW5s+16
         tGu99TDKoZ1B5NZQhW/nvi6HB07HRqah45llvTfpDi6eIx4JCnc+XARVrcVSOuO91EJQ
         Dx2w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=I3A7x/TDpLv5h56BeyCZpLoTghGPveKJh3ARm9n63n4=;
        b=oTmchKBiMTnPoxgjBhlBOWRHsf4Ym19JgqRyBqgxe0/oiecV7CVkqREI5T4IUF+q41
         XOPOjplsby9I0bgD7tEKplJGRXKrSBzeDbQkDI8SVzXLuZ15HfxCCVipYsXAJboE8FNR
         6tQcIw7oul8wXy14Usonhx9hnkaZYTRMGAjQsSQq4wL3njz4JvIxPIbuYdm4fMZaXHcV
         C98wxL+7JZmZIbaJV8BO8lGgPGf3GfUzdrnOu5Sy87v0XTHPZwWHMU5jxx8ZTsKSmBzY
         RIfeMkeqNjyA+mZSGMdoGFn9MvbcnzNp7zkLOqKQnyzUY/uK8wQBqdNOWAVnIh9kXF4m
         NrPA==
X-Gm-Message-State: AOAM533GDrGF9aU2a6EOVA3Uc0SCx9CacrS2k6RBpSa5ZV4CHmRYdb58
	UBI+6985MXyDnuaAI90PwBk=
X-Google-Smtp-Source: ABdhPJzdHFyqvkvWaMTiDhZHmSYVskmO2pv9EHSwk1HybGNR1QR/R0v4CZ1tmDWnSZlsi63F3XdM/w==
X-Received: by 2002:a5d:620d:: with SMTP id y13mr18646102wru.45.1627922470105;
        Mon, 02 Aug 2021 09:41:10 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:7fc3:: with SMTP id a186ls5314975wmd.3.gmail; Mon, 02
 Aug 2021 09:41:09 -0700 (PDT)
X-Received: by 2002:a05:600c:219:: with SMTP id 25mr17911066wmi.49.1627922469237;
        Mon, 02 Aug 2021 09:41:09 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1627922469; cv=none;
        d=google.com; s=arc-20160816;
        b=fuw0IYLwzcWufvbiuTNhyx9ORlsWI7K34RozdpuZ4KOeLu74SbO/DBAx6WgBuhroKt
         QEq+ly17qQ5NZFf/INDw7TC7nOtCSR+k9MXwgangiLuPyr4A9o/xtE4TWN9g8Ut8PAJB
         DORIWWnmvCDVztq2I70fDZAs1yiDsMllsxUr4WTj7qqVh8Jyeg4AnBKt9gWXbd3ZaNqm
         mSbYYH/bq/s4EHhLWSMy5Lq+8IZajQIUTatgQr3BraThoAcVjmKXpnsRfcMpH+Ga74Wz
         XkTAQxcB7H7fGJOGK7XcF4ChgcXk27N3tEEbqiJOAydmuWWqoJWs3VLfs3hve5bQfx0R
         fcFg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Mpn7PG82ctGVboEylkUCiZGj+PBEuHBMPwSjZySIC0s=;
        b=PRp1sGEh+ZsKutV/KaR0viRbxTcYurXmU1HId23f43hD9FqQKV7Cw4r4Ni3SWgNJhQ
         55BoxKXnJNfUWlgLJYYobdlc99ADX6ycT1ANr+IkzCB7ANNjFClejP+L+526RiL4tnKu
         NVs0UNE2JSpfCUg2Lcz4qSt83/E3yVu3/Yp8ot+sJNoTon23AbxEqWR/bvvqLNEBUPjb
         DXnszkcC7n4ITUkyQsRDqV94367xTDt6HnaSOFwOs/0Is4a6Lhv9dvR+/YaRmS1tBIE8
         TUElnT34AfYR4/PQRa7fpEHJYXrdxWiuduhFleoMpUUI7R9RAgEnUS7EiQJiwYGlR2zU
         jq8g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Iqhh7BSh;
       spf=pass (google.com: domain of ndesaulniers@google.com designates 2a00:1450:4864:20::133 as permitted sender) smtp.mailfrom=ndesaulniers@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-lf1-x133.google.com (mail-lf1-x133.google.com. [2a00:1450:4864:20::133])
        by gmr-mx.google.com with ESMTPS id l16si684670wrp.2.2021.08.02.09.41.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 02 Aug 2021 09:41:09 -0700 (PDT)
Received-SPF: pass (google.com: domain of ndesaulniers@google.com designates 2a00:1450:4864:20::133 as permitted sender) client-ip=2a00:1450:4864:20::133;
Received: by mail-lf1-x133.google.com with SMTP id x8so21487383lfe.3
        for <kasan-dev@googlegroups.com>; Mon, 02 Aug 2021 09:41:09 -0700 (PDT)
X-Received: by 2002:ac2:4ac6:: with SMTP id m6mr13931061lfp.73.1627922468420;
 Mon, 02 Aug 2021 09:41:08 -0700 (PDT)
MIME-Version: 1.0
References: <20210730223815.1382706-1-nathan@kernel.org> <20210731023107.1932981-1-nathan@kernel.org>
In-Reply-To: <20210731023107.1932981-1-nathan@kernel.org>
From: "'Nick Desaulniers' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 2 Aug 2021 09:40:56 -0700
Message-ID: <CAKwvOdk3xPjqidz=wmxuRjkSR0Q51Lygg1kkC1tn8vZWWc9NOA@mail.gmail.com>
Subject: Re: [PATCH v2] vmlinux.lds.h: Handle clang's module.{c,d}tor sections
To: Nathan Chancellor <nathan@kernel.org>
Cc: Kees Cook <keescook@chromium.org>, Arnd Bergmann <arnd@arndb.de>, 
	Fangrui Song <maskray@google.com>, Marco Elver <elver@google.com>, linux-arch@vger.kernel.org, 
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, 
	clang-built-linux@googlegroups.com, stable@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: ndesaulniers@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=Iqhh7BSh;       spf=pass
 (google.com: domain of ndesaulniers@google.com designates 2a00:1450:4864:20::133
 as permitted sender) smtp.mailfrom=ndesaulniers@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Nick Desaulniers <ndesaulniers@google.com>
Reply-To: Nick Desaulniers <ndesaulniers@google.com>
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

On Fri, Jul 30, 2021 at 7:33 PM Nathan Chancellor <nathan@kernel.org> wrote:
>
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

Reviewed-by: Nick Desaulniers <ndesaulniers@google.com>

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
Thanks,
~Nick Desaulniers

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAKwvOdk3xPjqidz%3DwmxuRjkSR0Q51Lygg1kkC1tn8vZWWc9NOA%40mail.gmail.com.
