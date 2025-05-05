Return-Path: <kasan-dev+bncBCLM76FUZ4IBBKEB4TAAMGQEOPPH4PA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd40.google.com (mail-io1-xd40.google.com [IPv6:2607:f8b0:4864:20::d40])
	by mail.lfdr.de (Postfix) with ESMTPS id A806BAA9B4D
	for <lists+kasan-dev@lfdr.de>; Mon,  5 May 2025 20:17:15 +0200 (CEST)
Received: by mail-io1-xd40.google.com with SMTP id ca18e2360f4ac-85e4f920dacsf388655239f.2
        for <lists+kasan-dev@lfdr.de>; Mon, 05 May 2025 11:17:15 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1746469034; cv=pass;
        d=google.com; s=arc-20240605;
        b=E36vlAe6JjYe02vlcB9TlzK9CneX7hXgect6Wjo2KcCooBwnYIz3HS6ry0DpdHAX9q
         yKY/o3FNjzIX6GdgybVIGLy6WstNC1G3z22sJ3XQOuG/V1vg0WXaL9tyge+5XPK0unnU
         B0MB/BC0KtcQPDpfdD6YnJCHFNcP8LkquaURlShUC5n+OlvDzGITLbT/U/hNWIwPo963
         z5l/OuUVMV5GrE1j9eK6skWPoZaPZfwhspdEuAChDT3V/7K5lkoGw/jNgshXUtb38+P4
         Ht1YF8ZSF55vFObnGbhqGJcNqfUjlMpFZxJ2WgMYCmcQqYI8S0/a0NGUN+sF9Fur+xDx
         Cj7g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=vfuGyHVJmEGVeyyKWVd01vGfpbFQsTDrJlIP1bIBfDA=;
        fh=HudAb7JZmiFfAxQKgghwGEkO092ABF10+135CfNPoyo=;
        b=eT6aSn8J3n9fMb0FNAhm/fX/ONRy+Vl689g+XzbCRopT776yhRkoO0fYbWYnEBKBOh
         CNwjw7eNKmtOscIi4l17IrqFI2C7S2cH/p9Pe8xMydyrpbwnfYqtbrk7wiKwPbqgJSIW
         5KgEWNtA6kzyQ6vir4yVykZnAzR6zQi0jkZWe+l9dKEtIZyLlLvNX4n0FR0nKMXdSo7o
         Z/K4zX5M3HxNSTPA1U43i4mWYyI7Ca9h5zbToRcCXYanc/1+i1CIxbBit/KLGc2XWkbS
         +Nd6+jyPjLkc0D36jORDgWaFJ/Ng5OKhsks1wuAm+9KPQgLFeyrFG0AvlZRdU1WAN/y/
         3+Lg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=mnPCIWLY;
       spf=pass (google.com: domain of justinstitt@google.com designates 2607:f8b0:4864:20::e2d as permitted sender) smtp.mailfrom=justinstitt@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1746469034; x=1747073834; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=vfuGyHVJmEGVeyyKWVd01vGfpbFQsTDrJlIP1bIBfDA=;
        b=imv45snvTOEu39b9uUFsqsxfV7QbkIubc6rjRP0JOAlRZb3lVkRanixMzDoxd5HiKx
         rJxqA0dq3omkuLP9dg3FfcXFQBOhjjqpRvVJ2+2oD9muwoycrE73hLijgYlO4ZKoYrPY
         IyNrM9uFZ56wOmefwU5f3zKLchwDOkolShptFJMIrB5Ov914sDgBm+dhfc8youLGt9GH
         38B6Pe6Xke/zEl7WgUMR1z3qeRDI7PsI3L8PGEQAspiRSW4w/najSILn3uSIIFql+Zy3
         w/mI57dbyRL/hjNVq+jfJk31jDiDG5zY64Rdc+DAAb7v7B3jmV8Roxs69NO3xJCjTciI
         IqXw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1746469034; x=1747073834;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=vfuGyHVJmEGVeyyKWVd01vGfpbFQsTDrJlIP1bIBfDA=;
        b=Gxvg96VcHV75LA5cosRW8EW10wtmYTODP0UTNw5HhbSm4wN3gX06/jSRrVpof1zB1O
         sAY4PGNwyXhIad/O/SrwBI7t2q6FRTqrThBd6jMMp6jzImX1EPa0mA/ddkJxB0r5dyZA
         IsFsCAKm4F1XA2WzD9nKpkoxzttOkgeTaoajCsnhPqNffeiuRYBisFnuKziqUfG3XqMW
         9uT1V9roqqcAgIXhheDq98CAOeIzKHkLmK0H5NeWLOCJOTiTuf4soIXRe4xkQVYM+jJO
         Y2P86Tl7X6R+wxMSHeOYN32Puh5KTy7TkTR29sdyPjxiuDZaP4QtEmCXmFhj2BENhwgY
         5aXg==
X-Forwarded-Encrypted: i=2; AJvYcCWX6qB/cywfLqHfRxbE7763EtiwPyUVzzsiyr3XfbtwTNvzSQI+S1jsUSWfhu07DR2XCaXhzA==@lfdr.de
X-Gm-Message-State: AOJu0YwvQiGjWvJaovntFMZssjZ3Bz436LhlWzmuvzuBB/NXYynIIYLM
	5GwgcgeXpgXGtD2FvHZEOpQW4EdeI3PIXpJGKfTQGtBtWsowLPdN
X-Google-Smtp-Source: AGHT+IHkEBYrCAZgerOr2t/HA6XAWgrffXrtnj2Q26cdJGCahBvYGzYvOUbDFzz0lWaGmaq0/iNsdQ==
X-Received: by 2002:a05:6e02:198e:b0:3d2:6768:c4fa with SMTP id e9e14a558f8ab-3da5b3493f0mr82795445ab.21.1746469033174;
        Mon, 05 May 2025 11:17:13 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AVT/gBGMuesm582ZLR0xjJ9qlqHll65RaNy1OR4M7smJRs0LdA==
Received: by 2002:a05:6e02:16c5:b0:3d8:b690:4e94 with SMTP id
 e9e14a558f8ab-3d96e714729ls8808535ab.0.-pod-prod-09-us; Mon, 05 May 2025
 11:17:12 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUXq5yOswWHnldzyE8yjzkiMVCyvETkw+vFhn1X6utOS7c9hCIWqnlgbaBQrBZkMbqNZFJVc/Y5QcQ=@googlegroups.com
X-Received: by 2002:a05:6e02:1f81:b0:3d8:2197:1aa0 with SMTP id e9e14a558f8ab-3da5b2a2e28mr74131155ab.11.1746469032182;
        Mon, 05 May 2025 11:17:12 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1746469032; cv=none;
        d=google.com; s=arc-20240605;
        b=DQcvyxY45pSPJnpTbY1JWpu7pELy2RnZsQJh1wg8N6SU3WfA+TLcrgQvddO7cF78Zm
         Ff+XlfgB7dQByclGVZlv3GoJCPglcA0S+YNGdlKTVPwuNZSH6h/V494Sxqm9wZXEKTXY
         LoHfZ+Sk+Kh1YZucjR1EGbQlgbXfMXPc1NcNSHMtUQj9ESdxXeNVMFwI0oQC4lZANluY
         0fSKRw1NvZayUOPCRFQRP2LjniedQa86zfCTHH+0pf1653jHzhMGM5XBfQvGC5YE9orY
         fUlrU6x40igo+vhbxPm+ZVmmP05bzUXpiKlPJCsJRII5URaf1qGeBQNZlu84nuMwIKsl
         Ox3w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=6RdDSV3C1kkoxQpJwSli9pdvJprdzRDcGLg/gY+ewYo=;
        fh=2Ph0Ozmf8VeIogJZR0zunyO94QCofYHmhNmQ/c3CkWc=;
        b=VE6ehOJTYKDo7mruvisEvuaEcJzmAe6ysS6FBIl56HnuZu2fc3ei/fYsmbjaHENPOh
         bsGvLREm8X9GHCT/Xwv7v26r3ptxwT6N5l3j3Ih4Q4ZOmmQkPme/1gllXiruuj0hIvME
         mgQRNhyXLepLJbG5ShJrSczKuvF++isIwGyi0lKt/GRggCqXbuICHIERkLFngvW38uDs
         rHrx8/iPaussiUFTojQzMNBy0w0e7xHULf38pAr6FC5rVTz6RhvQYZVaUhFYC43VSvQB
         EegKxolLagKLqXBDbeZRjEs2EqVLIiL1dQHchxC8+FcjHYtDT9hY/MALyLPkzFtx9tso
         +M2A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=mnPCIWLY;
       spf=pass (google.com: domain of justinstitt@google.com designates 2607:f8b0:4864:20::e2d as permitted sender) smtp.mailfrom=justinstitt@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-vs1-xe2d.google.com (mail-vs1-xe2d.google.com. [2607:f8b0:4864:20::e2d])
        by gmr-mx.google.com with ESMTPS id 8926c6da1cb9f-4f88a9e6c80si258452173.4.2025.05.05.11.17.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 05 May 2025 11:17:12 -0700 (PDT)
Received-SPF: pass (google.com: domain of justinstitt@google.com designates 2607:f8b0:4864:20::e2d as permitted sender) client-ip=2607:f8b0:4864:20::e2d;
Received: by mail-vs1-xe2d.google.com with SMTP id ada2fe7eead31-4c32f1f7801so1329736137.2
        for <kasan-dev@googlegroups.com>; Mon, 05 May 2025 11:17:12 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVIvxZzZZ5aLnikSmA9oc98BHGuhQhZYGpv4lKUL02L5GrUQzLzISKJQ0oRRidVT/iPZxvgtMH4KuU=@googlegroups.com
X-Gm-Gg: ASbGncuzF3V1vAgkj30dQwCGJr+L/JKedYxPg2+6CVYe2PAZ2lbTxx6bQwK004KPG2z
	4hN6aNTBQnphMmHiDh73s8fGUUrnkILySpK0ppiBTfacCIffWN5UcA3PtUmzOyOwfozl17BxEdc
	30G51IxucTUCZ1kCWltEZX
X-Received: by 2002:a05:6102:158d:b0:4c4:dead:59ab with SMTP id
 ada2fe7eead31-4db14781447mr4073359137.5.1746469031346; Mon, 05 May 2025
 11:17:11 -0700 (PDT)
MIME-Version: 1.0
References: <20250503184001.make.594-kees@kernel.org> <20250503184623.2572355-3-kees@kernel.org>
In-Reply-To: <20250503184623.2572355-3-kees@kernel.org>
From: "'Justin Stitt' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 5 May 2025 11:16:58 -0700
X-Gm-Features: ATxdqUG-8XZR84SCa_hy8LufhE4gnWyYrv86WHg4i3ik94ojF9GAbNyF1NZH5uE
Message-ID: <CAFhGd8rGJcveDn4g1nS=tURe-uT1+PFm2EQeWpUrH_oy763yFg@mail.gmail.com>
Subject: Re: [PATCH v3 3/3] integer-wrap: Force full rebuild when .scl file changes
To: Kees Cook <kees@kernel.org>
Cc: Masahiro Yamada <masahiroy@kernel.org>, Nathan Chancellor <nathan@kernel.org>, 
	Nicolas Schier <nicolas.schier@linux.dev>, Marco Elver <elver@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	linux-kbuild@vger.kernel.org, kasan-dev@googlegroups.com, 
	linux-hardening@vger.kernel.org, Petr Pavlu <petr.pavlu@suse.com>, 
	Sebastian Andrzej Siewior <bigeasy@linutronix.de>, Nick Desaulniers <nick.desaulniers+lkml@gmail.com>, 
	Bill Wendling <morbo@google.com>, linux-kernel@vger.kernel.org, llvm@lists.linux.dev
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: justinstitt@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=mnPCIWLY;       spf=pass
 (google.com: domain of justinstitt@google.com designates 2607:f8b0:4864:20::e2d
 as permitted sender) smtp.mailfrom=justinstitt@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
X-Original-From: Justin Stitt <justinstitt@google.com>
Reply-To: Justin Stitt <justinstitt@google.com>
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

On Sat, May 3, 2025 at 11:46=E2=80=AFAM Kees Cook <kees@kernel.org> wrote:
>
> Since the integer wrapping sanitizer's behavior depends on its associated
> .scl file, we must force a full rebuild if the file changes. If not,
> instrumentation may differ between targets based on when they were built.
>
> Generate a new header file, integer-wrap.h, any time the Clang .scl
> file changes. Include the header file in compiler-version.h when its
> associated feature name, INTEGER_WRAP, is defined. This will be picked
> up by fixdep and force rebuilds where needed.
>
> Signed-off-by: Kees Cook <kees@kernel.org>
> ---
> Cc: Masahiro Yamada <masahiroy@kernel.org>
> Cc: Justin Stitt <justinstitt@google.com>
> Cc: Nathan Chancellor <nathan@kernel.org>
> Cc: Nicolas Schier <nicolas.schier@linux.dev>
> Cc: Marco Elver <elver@google.com>
> Cc: Andrey Konovalov <andreyknvl@gmail.com>
> Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>
> Cc: <linux-kbuild@vger.kernel.org>
> Cc: <kasan-dev@googlegroups.com>
> Cc: <linux-hardening@vger.kernel.org>
> ---
>  include/linux/compiler-version.h | 3 +++
>  scripts/Makefile.ubsan           | 1 +
>  scripts/basic/Makefile           | 5 +++++
>  3 files changed, 9 insertions(+)
>
> diff --git a/include/linux/compiler-version.h b/include/linux/compiler-ve=
rsion.h
> index 69b29b400ce2..187e749f9e79 100644
> --- a/include/linux/compiler-version.h
> +++ b/include/linux/compiler-version.h
> @@ -19,3 +19,6 @@
>  #ifdef RANDSTRUCT
>  #include <generated/randstruct_hash.h>
>  #endif
> +#ifdef INTEGER_WRAP
> +#include <generated/integer-wrap.h>
> +#endif
> diff --git a/scripts/Makefile.ubsan b/scripts/Makefile.ubsan
> index 9e35198edbf0..653f7117819c 100644
> --- a/scripts/Makefile.ubsan
> +++ b/scripts/Makefile.ubsan
> @@ -15,6 +15,7 @@ ubsan-cflags-$(CONFIG_UBSAN_TRAP)             +=3D $(ca=
ll cc-option,-fsanitize-trap=3Dundefined
>  export CFLAGS_UBSAN :=3D $(ubsan-cflags-y)
>
>  ubsan-integer-wrap-cflags-$(CONFIG_UBSAN_INTEGER_WRAP)     +=3D  \
> +       -DINTEGER_WRAP                                          \
>         -fsanitize-undefined-ignore-overflow-pattern=3Dall        \
>         -fsanitize=3Dsigned-integer-overflow                      \
>         -fsanitize=3Dunsigned-integer-overflow                    \
> diff --git a/scripts/basic/Makefile b/scripts/basic/Makefile
> index dd289a6725ac..fb8e2c38fbc7 100644
> --- a/scripts/basic/Makefile
> +++ b/scripts/basic/Makefile
> @@ -14,3 +14,8 @@ cmd_create_randstruct_seed =3D \
>  $(obj)/randstruct.seed: $(gen-randstruct-seed) FORCE
>         $(call if_changed,create_randstruct_seed)
>  always-$(CONFIG_RANDSTRUCT) +=3D randstruct.seed
> +
> +# integer-wrap: if the .scl file changes, we need to do a full rebuild.
> +$(obj)/../../include/generated/integer-wrap.h: $(srctree)/scripts/intege=
r-wrap-ignore.scl FORCE
> +       $(call if_changed,touch)
> +always-$(CONFIG_UBSAN_INTEGER_WRAP) +=3D ../../include/generated/integer=
-wrap.h

I'm not sure how this fake header stuff works to ensure builds deps
are tracked properly but we do need scl files to be considered as part
of complete builds, so:

Acked-by: Justin Stitt <justinstitt@google.com>

> --
> 2.34.1
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
AFhGd8rGJcveDn4g1nS%3DtURe-uT1%2BPFm2EQeWpUrH_oy763yFg%40mail.gmail.com.
