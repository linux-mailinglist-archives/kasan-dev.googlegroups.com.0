Return-Path: <kasan-dev+bncBC7OBJGL2MHBBPOE6LAAMGQEG26QV7A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3b.google.com (mail-qv1-xf3b.google.com [IPv6:2607:f8b0:4864:20::f3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 54CCEAAF9BE
	for <lists+kasan-dev@lfdr.de>; Thu,  8 May 2025 14:23:39 +0200 (CEST)
Received: by mail-qv1-xf3b.google.com with SMTP id 6a1803df08f44-6f53d2613easf19023526d6.0
        for <lists+kasan-dev@lfdr.de>; Thu, 08 May 2025 05:23:39 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1746707018; cv=pass;
        d=google.com; s=arc-20240605;
        b=Xbz+kMIkEvt20FYJHyOcJ/TV/9CWSSQ/MUgeOyByo2dDPONtgmrJE4zS7J55Z9Tifx
         iELJmt6FThrYI4tcfWem+IgckL0UD5TXmmrjofTVo/5PPU1Fx2mjiHcWVum15rIZ5ZHo
         yEIoh7xFbNxJjoWQU0Re+/39ov8z5yxkYEBeRIc5Js3sQR3pBFbxc/gZi6jfYo8ncVkf
         vjAAQSEpLJJ1n1DhPB97oskVI0rCc3i0e++TN5b/S25hPDOGhuFYid7QaYmF7O1Rw6NP
         KOh3+bOjbsLKYSbPKq1dKgp7WAdfQWxTzLdOOn/oU8RXsw9Fvc44E+DDUgL7jLWuF6mJ
         mHww==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=k/LMHUuzwnJ8IntowahS5/4CbC6zRK6OGcHGfPZdWes=;
        fh=9wEjj2AbPuhItYgYtlUwRSuIfI3Z9KZYj0YZLkyeiHQ=;
        b=PRwczL7DmtoJuPUX1Jrrc9Dpu9qVndvWQ+GGQ5PnkfqPPhNCTM9xVI3ngDEdad6lhZ
         8ccYuRYIzje4LLo5wAhgyIDUdhZq0QBjrF8+LaJS4FIKHtQpM8zuGCNfKjcf8loypV8Z
         BBIVcIZ/JWeX/RCzPnY0EYsJVClUwVYqDO857hB8ZpXJ4FtST15GbUOxO2CG8IxmDYQ7
         PRS8n2VDV8YSoh/OUIvtiGQbvI2G0CTLPBGdvcke1HOHuvcatUI9lI41c1PxZdhbQj7F
         c6gjviyS2yQhImFbE2+fEtvjQyIKFXEU3txwZsVlE8SOQ75Jy2ZRkPYgH9LCVWfOt2J4
         CcHw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=V5pYwqoW;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::52d as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1746707018; x=1747311818; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=k/LMHUuzwnJ8IntowahS5/4CbC6zRK6OGcHGfPZdWes=;
        b=Li0+NXhhUfsznMytgkEpOjwZVeyocPxKJgo4SGQR0Bv/SGjsmZFETKwkqTzlIJzRFh
         SJIRlPzfXxjg90XvkpcY+rWmEWy1RsTSSNe3/fAvXUrxCAQs4loN0weNerYA296Egmid
         1wkFcIWvVTkrsCF/u0h8kCVSuNxNxaMbA9+rSUKbDMh4d7DUCT/lTolI5GSgab4d0/lS
         U9jQUSo3sojR8fylJzPlxwIhdeEeRcTNcIhn1OMiJw4uTDBpgMG41X7SCuRz9ChU+Xnz
         9/62Kt1d3X2jh/Rr5sRCEyW0Dnv9TvUiiYb2sNoH61tbsav4Ycr82j/p4mvDkNxmP3Ac
         0ocQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1746707018; x=1747311818;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=k/LMHUuzwnJ8IntowahS5/4CbC6zRK6OGcHGfPZdWes=;
        b=ZI8bgb08k+b9HJ9qtxbH1mLG18+U8ba3+h4jYfuS5hpQQhnSROIOncjTTHUDR9b4/A
         mDp61vjUo1U5/BktPs0m8ygT0AW3LF/RtNpr9hAkvCD8YleRKdo8BQiZUnulZeQfNzrX
         7aZlym1eTttN+7UsYygRtSTPH8mz1+X5JXAUuGWeZnSkSmp6x0W21ZOYV/jF/ddurQJb
         ZVyKYj7s+SQ+8pTkYUZK8kabkaUgm4sYPD6WMf4RYAJ9A4Ercrs/HgHUGiotUvtp209e
         mbKl5cifS0iprBZCkakplCeYq3uVW3tFDCmgky0apDdKDnnNgg3ITbZjftsgnBG+YWRE
         oU1A==
X-Forwarded-Encrypted: i=2; AJvYcCXBULvLX2qEzzxlDJnfNfrbgQjKdYNedU3245i3GXO7QgygirLG2b+BthQAbS9KMPI1n1l4Ng==@lfdr.de
X-Gm-Message-State: AOJu0YyVmoDO9J9Vph+9BaqgVam72BJG1stCNSJgatAJe2/itRS9vQAX
	DL2KO2n4pICvXPcb+IHfUMdQSs2F+cfa5zh1FqONdVr8wAD58ne0
X-Google-Smtp-Source: AGHT+IEDanMqsHE8kaF+0jX3a/iaZifR9BFO3eKfqwwD2DdJhlqBBQIiy4mo700Ih9AZ3u/qVMcRHA==
X-Received: by 2002:a05:6214:500e:b0:6e5:a0fc:f65d with SMTP id 6a1803df08f44-6f54ba4cda2mr44987736d6.10.1746707006113;
        Thu, 08 May 2025 05:23:26 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AVT/gBEaMt46JG6dFpPHVapUSCz8RRck1FKbXG2LlJR634jd8w==
Received: by 2002:ad4:559c:0:b0:6f4:c306:37dd with SMTP id 6a1803df08f44-6f54b538be8ls3488156d6.2.-pod-prod-00-us;
 Thu, 08 May 2025 05:23:25 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWGFLNG4I/bKhsbTDrBXj2pnHfkm7zvuQv7x1c7i+UORMP07XDxcBtqyK5Yf8wbnO/OTHdMq6op16U=@googlegroups.com
X-Received: by 2002:a05:6122:c8:b0:523:eb47:2884 with SMTP id 71dfb90a1353d-52c44437f67mr2023082e0c.6.1746707005010;
        Thu, 08 May 2025 05:23:25 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1746707005; cv=none;
        d=google.com; s=arc-20240605;
        b=CRKPSQ7YoXXRFjRkfzAp4oR8cP05bEbcBDkUg1DbvxwXw0mJf7ziLaULFd8snzjxuz
         WGXPUzt0gnQ+e+lZ5TVYv0SK7hHHyy5VMxefnkOvzqfwHKGI3sxb2M6SE1UCrVgwGpwM
         N3WC4AAHqBm2jvI7tBte6qbJFIrBlYaxH6+k3SsNoTOkqp1mGBJV5chCX22pfM2CLom1
         bo8MYmYrjXDYJbxB0a2AvHqWJxsQ/VYZVfMijPkE6yAzrqxWCJ1NFfSp9qLfovtIsNvf
         GHYp4J1+TeraiC3I/b4qU/SCUXWViSuUoqX2tNzI22bF0xN4/6SgWb8Yh792lIxco2vY
         S1Ag==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=YHzGR2TH3f5PkiaDuIeNupqLtaLoSxh32TBcttsiE58=;
        fh=BQFO37rYq5ZWb/xRBge9ftUeEZuIs+WU7u5sp4Lvrw8=;
        b=BRqN0fBFF7tLIsY4g1vhmoKwY3FKHIMKgqYA7rqoU+EWH+E2WCgMihpFuUmX58XjTZ
         Et6e3CC8gFblICO0kl+CmNADvxxzFqDSVDJQ7Qjp0d9qEHsQYXDJEQLVsOJ0o5iwP+CO
         exD49MiVOEDo72uObgc/Jbz9u5qxCSaozvLRJQc3cyWnxK5ESyiCZ25fAA97oxbKX+f0
         +WEIz8HhAbLBrJa0rJ5mALg3ztCni8NUrpP0yYKu8LDxddA2y5PiDDjYUKpbP8F2TMJB
         8pxsWh17HYxkwQv1fPHkQwMaN2zCFkxYILVr0/lD96YxMnpS0EL4SwzP1MNCulCpVcEL
         B2GA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=V5pYwqoW;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::52d as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pg1-x52d.google.com (mail-pg1-x52d.google.com. [2607:f8b0:4864:20::52d])
        by gmr-mx.google.com with ESMTPS id 71dfb90a1353d-52ae4184697si284027e0c.5.2025.05.08.05.23.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 08 May 2025 05:23:24 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::52d as permitted sender) client-ip=2607:f8b0:4864:20::52d;
Received: by mail-pg1-x52d.google.com with SMTP id 41be03b00d2f7-b1fcb97d209so1841974a12.1
        for <kasan-dev@googlegroups.com>; Thu, 08 May 2025 05:23:24 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVrD/le90c7XfC5OlVwtCXQPIwjA4v6xKZH70omzultMDidCZVtacj7fygdi9hPlwq30CTr/Esd9yw=@googlegroups.com
X-Gm-Gg: ASbGnctSns84N6+1A6w76LUXnbtaTHu2z/yp1qeFJ4r871Hxgrh6S/BD+AnXt55wdK2
	wGY7Uut5VqMxvNZCI7BCjGPXON1gHME6RryUhxDL0wFyuKp1YVqptmTVotT/+v1TfHox3HG6w/a
	VqbsV+9b8k5HgU0E17D8ckv/U5TLgwIIqU1HCvYJp/HK7CboMuQ3K3joR92FonG9g=
X-Received: by 2002:a17:90b:4b8c:b0:2fa:1d9f:c80 with SMTP id
 98e67ed59e1d1-30adbf6d05amr4939913a91.17.1746707003520; Thu, 08 May 2025
 05:23:23 -0700 (PDT)
MIME-Version: 1.0
References: <20250507180852.work.231-kees@kernel.org> <20250507181615.1947159-2-kees@kernel.org>
In-Reply-To: <20250507181615.1947159-2-kees@kernel.org>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 8 May 2025 14:22:47 +0200
X-Gm-Features: ATxdqUHttH2gHvJKzLvMz7fkEuSC2xFFktBrniyRJYj71k93n_Rm8LTTobDJ7fU
Message-ID: <CANpmjNPcYPvnQzMT3p+Vc2=EiEbR1WnykUEjuYc0bH2HOFi6HQ@mail.gmail.com>
Subject: Re: [PATCH 2/8] init.h: Disable sanitizer coverage for __init and __head
To: Kees Cook <kees@kernel.org>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Aleksandr Nogikh <nogikh@google.com>
Cc: Arnd Bergmann <arnd@arndb.de>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Thomas Gleixner <tglx@linutronix.de>, 
	Ingo Molnar <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>, 
	Dave Hansen <dave.hansen@linux.intel.com>, x86@kernel.org, 
	"H. Peter Anvin" <hpa@zytor.com>, Ard Biesheuvel <ardb@kernel.org>, 
	"Kirill A. Shutemov" <kirill.shutemov@linux.intel.com>, Hou Wenlong <houwenlong.hwl@antgroup.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Masahiro Yamada <masahiroy@kernel.org>, 
	"Peter Zijlstra (Intel)" <peterz@infradead.org>, Luis Chamberlain <mcgrof@kernel.org>, 
	Sami Tolvanen <samitolvanen@google.com>, Christophe Leroy <christophe.leroy@csgroup.eu>, 
	kasan-dev@googlegroups.com, "Gustavo A. R. Silva" <gustavoars@kernel.org>, 
	Christoph Hellwig <hch@lst.de>, Nathan Chancellor <nathan@kernel.org>, 
	Nicolas Schier <nicolas.schier@linux.dev>, 
	Nick Desaulniers <nick.desaulniers+lkml@gmail.com>, Bill Wendling <morbo@google.com>, 
	Justin Stitt <justinstitt@google.com>, linux-kernel@vger.kernel.org, 
	linux-doc@vger.kernel.org, linux-arm-kernel@lists.infradead.org, 
	kvmarm@lists.linux.dev, linux-riscv@lists.infradead.org, 
	linux-s390@vger.kernel.org, linux-efi@vger.kernel.org, 
	linux-hardening@vger.kernel.org, linux-kbuild@vger.kernel.org, 
	linux-security-module@vger.kernel.org, linux-kselftest@vger.kernel.org, 
	sparclinux@vger.kernel.org, llvm@lists.linux.dev, 
	syzkaller <syzkaller@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=V5pYwqoW;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::52d as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
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

+Cc KCOV maintainers

On Wed, 7 May 2025 at 20:16, Kees Cook <kees@kernel.org> wrote:
>
> While __noinstr already contained __no_sanitize_coverage, it needs to
> be added to __init and __head section markings to support the Clang
> implementation of CONFIG_STACKLEAK. This is to make sure the stack depth
> tracking callback is not executed in unsupported contexts.
>
> The other sanitizer coverage options (trace-pc and trace-cmp) aren't
> needed in __head nor __init either ("We are interested in code coverage
> as a function of a syscall inputs"[1]), so this appears safe to disable
> for them as well.

@ Dmitry, Aleksandr - Will this produce some unwanted side-effects for
syzbot? I also think it's safe, but just double checking.

> Link: https://web.git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/kernel/kcov.c?h=v6.14#n179 [1]
> Signed-off-by: Kees Cook <kees@kernel.org>

Acked-by: Marco Elver <elver@google.com>

> ---
> Cc: Marco Elver <elver@google.com>
> Cc: Andrey Konovalov <andreyknvl@gmail.com>
> Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>
> Cc: Thomas Gleixner <tglx@linutronix.de>
> Cc: Ingo Molnar <mingo@redhat.com>
> Cc: Borislav Petkov <bp@alien8.de>
> Cc: Dave Hansen <dave.hansen@linux.intel.com>
> Cc: <x86@kernel.org>
> Cc: "H. Peter Anvin" <hpa@zytor.com>
> Cc: Ard Biesheuvel <ardb@kernel.org>
> Cc: "Kirill A. Shutemov" <kirill.shutemov@linux.intel.com>
> Cc: Hou Wenlong <houwenlong.hwl@antgroup.com>
> Cc: Andrew Morton <akpm@linux-foundation.org>
> Cc: Masahiro Yamada <masahiroy@kernel.org>
> Cc: "Peter Zijlstra (Intel)" <peterz@infradead.org>
> Cc: Luis Chamberlain <mcgrof@kernel.org>
> Cc: Sami Tolvanen <samitolvanen@google.com>
> Cc: Arnd Bergmann <arnd@arndb.de>
> Cc: Christophe Leroy <christophe.leroy@csgroup.eu>
> Cc: <kasan-dev@googlegroups.com>
> ---
>  arch/x86/include/asm/init.h | 2 +-
>  include/linux/init.h        | 4 +++-
>  2 files changed, 4 insertions(+), 2 deletions(-)
>
> diff --git a/arch/x86/include/asm/init.h b/arch/x86/include/asm/init.h
> index 8b1b1abcef15..6bfdaeddbae8 100644
> --- a/arch/x86/include/asm/init.h
> +++ b/arch/x86/include/asm/init.h
> @@ -5,7 +5,7 @@
>  #if defined(CONFIG_CC_IS_CLANG) && CONFIG_CLANG_VERSION < 170000
>  #define __head __section(".head.text") __no_sanitize_undefined __no_stack_protector
>  #else
> -#define __head __section(".head.text") __no_sanitize_undefined
> +#define __head __section(".head.text") __no_sanitize_undefined __no_sanitize_coverage
>  #endif
>
>  struct x86_mapping_info {
> diff --git a/include/linux/init.h b/include/linux/init.h
> index ee1309473bc6..c65a050d52a7 100644
> --- a/include/linux/init.h
> +++ b/include/linux/init.h
> @@ -49,7 +49,9 @@
>
>  /* These are for everybody (although not all archs will actually
>     discard it in modules) */
> -#define __init         __section(".init.text") __cold  __latent_entropy __noinitretpoline
> +#define __init         __section(".init.text") __cold __latent_entropy \
> +                                               __noinitretpoline       \
> +                                               __no_sanitize_coverage
>  #define __initdata     __section(".init.data")
>  #define __initconst    __section(".init.rodata")
>  #define __exitdata     __section(".exit.data")
> --
> 2.34.1
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNPcYPvnQzMT3p%2BVc2%3DEiEbR1WnykUEjuYc0bH2HOFi6HQ%40mail.gmail.com.
