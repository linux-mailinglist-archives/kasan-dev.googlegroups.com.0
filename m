Return-Path: <kasan-dev+bncBCMIZB7QWENRBOGF6LAAMGQE3IT2BNA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x439.google.com (mail-wr1-x439.google.com [IPv6:2a00:1450:4864:20::439])
	by mail.lfdr.de (Postfix) with ESMTPS id 6AA65AAF9C9
	for <lists+kasan-dev@lfdr.de>; Thu,  8 May 2025 14:25:39 +0200 (CEST)
Received: by mail-wr1-x439.google.com with SMTP id ffacd0b85a97d-3a07a867a4dsf505005f8f.3
        for <lists+kasan-dev@lfdr.de>; Thu, 08 May 2025 05:25:39 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1746707129; cv=pass;
        d=google.com; s=arc-20240605;
        b=UZHXwmmPKepQu+IQRQI2R6ZoMoAYolVD7xOd/oKHmlPIHgFLtO1xSTDtNga5TuKaYd
         NQmRqwHxPV3CO30G4itJIXo2jHYWSLSlYcnqFDHf0hPiJvE0GHSsL4n7N8NXzPhUuUZO
         1BjhPo3fm8s7EJmN1G7P0KQYw5BF9rAICzxutKfnvhDwEOQay9zxFit2YyPQc3hH+8rF
         Z0oX1yB/HSelFIt3XLOiSqp+xqpT+hN56eXuzN1x4pgYoGo2FuRxYpmb7oWtkuOfoPZ6
         qVED2YE78iWQSUqCeiNEo24rKFJLkkq1BGXGqH2XoUPwj6kk8o19KjhZY/j6PxJi5gsI
         MO7g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=AP2gGiIXe8QsWKYVNSjbJnVlB0AG2xGPq5c/QXKqON0=;
        fh=+AfAuS5Mulx46xy9c9UcBgFcGhFFJk5uMnTJ8H2NdwY=;
        b=NbH8O5wvsqvvckaDiAzx6YVNW+OulfF/cl/QRYle1INX1JcGhVL7jQiF4OLoQHWKBX
         3AJn2N+ZlsN0b3/FT/auaJh0zafVc3qyBxWz67EHyS3/QtLiYenAXtNwXD5Je6PAipfw
         vfILKyTa0Uw0QZyLTeGwt70SH6EE5tjS+Mqqx/QygaAJzVF4X5cAD9z/WAvIY5al7kP2
         JP/tNfEQ7gCOcnIm1y46sd999EBLMJhbFBgPqyAvnpAAYJeNr49Lwp7EncbnTBRq+llO
         +mZFFmBmwM6xrcznDU2cYWBJM2ESHWtKrxfPTPnUmV4P7G7bfmkUSfM/N7kAY55KdKwf
         XvHQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=XaDgTLSP;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::233 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1746707129; x=1747311929; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=AP2gGiIXe8QsWKYVNSjbJnVlB0AG2xGPq5c/QXKqON0=;
        b=Km1nkwYMHOCNZSoH3fcrDBhVl5at6/YE7rmz4gqYO3YLcTfEhYBk2tc80vvML6RmLz
         pKCtoyKf41+eOmrw2BWdd9/F/vK/Yo69gWonFPT8Mn91t6iobJ7pzUJ21y355m4yLaQJ
         SJ0qcmT55iV6s8Tbigpd08z0OAeP2wOj1VGk7LBy1Xp82m3UD/Adhgk9Horeb/lpnrjC
         Dc7ZHOjz3dwd0wJulnHh7r8OhCTUOVBoKKtHjsrhsVFraA1DDUnP+QWqyuagP4z0SzGn
         KApRu8b4+/KJ2EoPFR9fyCrlTs42Ay53Jg1brrEJb+xw8uemsQYVZcvA7lJBw+QH2itv
         biHA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1746707129; x=1747311929;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=AP2gGiIXe8QsWKYVNSjbJnVlB0AG2xGPq5c/QXKqON0=;
        b=W85OovwLHBiBlYiaMXJQOWk45USvHzgrcE9vWVADByLVNg1bRDKE1znZg3/gF4hv6s
         V3gAf9dIt7molb1a61zw64uRlE2vkKSFsBg6TDGLSf/S9HOgZIeuyCS3BZzT8E/F/bPh
         5E7geTW4b63D/OJt/MOeFvI/RzzCOoXTS4W1RCxzZXXwd+44xXUf/pvQuFxdqQtO/3qy
         59JMGks7cJKKafnRSPbhQMWoV4xUMjfilANeDd2yuhzN+XMSCdn2wTsrktGxKGTWgUyD
         qH3jI1KDlDhP5Vi2LKWcIbfGgFOjSge+tlceQRn1Y50ID50zw23iw3m4EqWECsIG0dmv
         Ek4g==
X-Forwarded-Encrypted: i=2; AJvYcCWkSyoLDqNYrxwOBaI/tNgVTq5K2oeF0B9acZ3OHXkIc/pqe4xPBqxSwE7EikbZMQECvN/3qA==@lfdr.de
X-Gm-Message-State: AOJu0YxgGbbIFF4bLGq8mUlxBs1Qwv7x6RqMaOHtzUO7u8XE8nMiD5GR
	IQp4wkdUKWfJ6gInIxENbdQbb+e1zC/FJlDTa2fTyhP2Pxf796Kj
X-Google-Smtp-Source: AGHT+IF6sD40JtrPRokYeVu+o1kdIhTdkCTRDVWkhd+fy09LA4gzLP4UTSGfSEUUR+nW5zYh7/73Rw==
X-Received: by 2002:a5d:648d:0:b0:39c:268e:ae04 with SMTP id ffacd0b85a97d-3a0b9ffe08amr2280309f8f.0.1746707129266;
        Thu, 08 May 2025 05:25:29 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AVT/gBEU09cK5O6y69e7AT+/h9DVmrMLwFoDBC8jhb/Y6OZJ7Q==
Received: by 2002:a05:6000:401e:b0:3a0:8119:6f33 with SMTP id
 ffacd0b85a97d-3a0b96e8f2fls461672f8f.1.-pod-prod-07-eu; Thu, 08 May 2025
 05:25:27 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUzPiqDNGFet6sWGdhg0muixLHS8mtJFxC8yxMZU8f+ZDReUZ2I5p2ciNvs0ZbT5uBPx1Fa7Ee2dt0=@googlegroups.com
X-Received: by 2002:a5d:4a4a:0:b0:3a1:a96c:9b90 with SMTP id ffacd0b85a97d-3a1a96c9e66mr475228f8f.46.1746707126691;
        Thu, 08 May 2025 05:25:26 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1746707126; cv=none;
        d=google.com; s=arc-20240605;
        b=WAzid1iiZAp+arlFtln4zwScq3BOcN7REdLenkq41o8HbawjdCeWpVP+eFXIFPO/Wh
         yEeXvFj603RfksTaNiNblhOC0CHTPbWQ9NKPlZL7BVUJhKDq86t3GbIVnIqkQpZfrhnv
         JVh+QnLu1gqQV/q9DlwqhXRLWIYmJqraY06pJ/nGdxQSgrqJb5zy1QE8rcmYDgdne7qo
         /+nAbR3Nq8DHMGIOtwp8Rz64XUEd46K0P9RuiSqH/Kxp8dHykbsbZgFX9zCgZh6EiMvZ
         TDpk7V3zQHy3+wJJwMIsEqBxLw8Efs0+sJHo67cC8VaeflgsQL2Zgej0CdtHBhWUf43d
         R82g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=SGXUIdTFQac7mJFRH+e+84EpMzV6neC01o/VEUKascg=;
        fh=UPyeY45Y7R1plZ8IbpsGZCQ8FokCZpwI5kmPBHJJM0Q=;
        b=VeOX2FTWpMjq1p7nWwNmuV7oisqiAlLocUJmtW/qoUq0sV8e9+BNnhkNEsQZH1YAyc
         uUHHNLiWNgOFVQBvGJVgtxtLyyu2GjGCQiJcCGAMK6hy+/UJj8Ncrb1OWjFOWwokXgo1
         YexEuEn0/eaWG+OTPrc8nKDNzUkLA24X9LWCSpDpN6xhrqChq1UJUL5frS9sM32jA+he
         4EDu6n1LMBYjYiT05r0RfbM+Z3T1KUXksRUQLV2z1o5uGxsXLf1V+Y5Uh9R0xbweWjmj
         aOHC9KBQnVTFxOBOak56wquIisEd490CkvtFzq776KR4+rHvTo3TtURbXa07Pvd5WUZq
         KQuA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=XaDgTLSP;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::233 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-lj1-x233.google.com (mail-lj1-x233.google.com. [2a00:1450:4864:20::233])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-441d11a9570si3056935e9.0.2025.05.08.05.25.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 08 May 2025 05:25:26 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::233 as permitted sender) client-ip=2a00:1450:4864:20::233;
Received: by mail-lj1-x233.google.com with SMTP id 38308e7fff4ca-31062172698so9762071fa.0
        for <kasan-dev@googlegroups.com>; Thu, 08 May 2025 05:25:26 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXwANt3nHM/DTWAV25c3so3ZBCoV64DvtRno9qhyZU6IMUXJ5yu9W9uHG4J+ARu8c2Y1zA+7Tk4S5M=@googlegroups.com
X-Gm-Gg: ASbGnctdut3rV9ZhLZnVzauroL7onOP+j54y53zbPOUlmVVMVbVPFsMyBZAyUr6hMcB
	XMDQTu/3Nwg+s2fj/36Ijgjapz8UOuLDZkZ/4IUn/I+R3eN1anv6bQTLaFfClixrs/sQ/rk9Edg
	deMcMsR/prxWCkL22FthC6joLqSlOXjAU8UGj5cJURw0vHxvysPX8B
X-Received: by 2002:a05:651c:b11:b0:30b:f006:3f5 with SMTP id
 38308e7fff4ca-326b87dacdfmr7793251fa.15.1746707125568; Thu, 08 May 2025
 05:25:25 -0700 (PDT)
MIME-Version: 1.0
References: <20250507180852.work.231-kees@kernel.org> <20250507181615.1947159-2-kees@kernel.org>
 <CANpmjNPcYPvnQzMT3p+Vc2=EiEbR1WnykUEjuYc0bH2HOFi6HQ@mail.gmail.com>
In-Reply-To: <CANpmjNPcYPvnQzMT3p+Vc2=EiEbR1WnykUEjuYc0bH2HOFi6HQ@mail.gmail.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 8 May 2025 14:25:13 +0200
X-Gm-Features: ATxdqUEOMWVMkXbvXQaHqruZq4t8-pmXFLrRyvMg5ohXOpGrzDC1z300bwlcEE0
Message-ID: <CACT4Y+betRmieWEHBdEf=gOLhWiNVRH5CSDeN6ykBtoP1GrzLA@mail.gmail.com>
Subject: Re: [PATCH 2/8] init.h: Disable sanitizer coverage for __init and __head
To: Marco Elver <elver@google.com>
Cc: Kees Cook <kees@kernel.org>, Alexander Potapenko <glider@google.com>, 
	Aleksandr Nogikh <nogikh@google.com>, Arnd Bergmann <arnd@arndb.de>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>, 
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
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=XaDgTLSP;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::233
 as permitted sender) smtp.mailfrom=dvyukov@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
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

On Thu, 8 May 2025 at 14:23, Marco Elver <elver@google.com> wrote:
>
> +Cc KCOV maintainers
>
> On Wed, 7 May 2025 at 20:16, Kees Cook <kees@kernel.org> wrote:
> >
> > While __noinstr already contained __no_sanitize_coverage, it needs to
> > be added to __init and __head section markings to support the Clang
> > implementation of CONFIG_STACKLEAK. This is to make sure the stack depth
> > tracking callback is not executed in unsupported contexts.
> >
> > The other sanitizer coverage options (trace-pc and trace-cmp) aren't
> > needed in __head nor __init either ("We are interested in code coverage
> > as a function of a syscall inputs"[1]), so this appears safe to disable
> > for them as well.
>
> @ Dmitry, Aleksandr - Will this produce some unwanted side-effects for
> syzbot? I also think it's safe, but just double checking.

I do not see any problems with this.

> > Link: https://web.git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/kernel/kcov.c?h=v6.14#n179 [1]
> > Signed-off-by: Kees Cook <kees@kernel.org>
>
> Acked-by: Marco Elver <elver@google.com>
>
> > ---
> > Cc: Marco Elver <elver@google.com>
> > Cc: Andrey Konovalov <andreyknvl@gmail.com>
> > Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>
> > Cc: Thomas Gleixner <tglx@linutronix.de>
> > Cc: Ingo Molnar <mingo@redhat.com>
> > Cc: Borislav Petkov <bp@alien8.de>
> > Cc: Dave Hansen <dave.hansen@linux.intel.com>
> > Cc: <x86@kernel.org>
> > Cc: "H. Peter Anvin" <hpa@zytor.com>
> > Cc: Ard Biesheuvel <ardb@kernel.org>
> > Cc: "Kirill A. Shutemov" <kirill.shutemov@linux.intel.com>
> > Cc: Hou Wenlong <houwenlong.hwl@antgroup.com>
> > Cc: Andrew Morton <akpm@linux-foundation.org>
> > Cc: Masahiro Yamada <masahiroy@kernel.org>
> > Cc: "Peter Zijlstra (Intel)" <peterz@infradead.org>
> > Cc: Luis Chamberlain <mcgrof@kernel.org>
> > Cc: Sami Tolvanen <samitolvanen@google.com>
> > Cc: Arnd Bergmann <arnd@arndb.de>
> > Cc: Christophe Leroy <christophe.leroy@csgroup.eu>
> > Cc: <kasan-dev@googlegroups.com>
> > ---
> >  arch/x86/include/asm/init.h | 2 +-
> >  include/linux/init.h        | 4 +++-
> >  2 files changed, 4 insertions(+), 2 deletions(-)
> >
> > diff --git a/arch/x86/include/asm/init.h b/arch/x86/include/asm/init.h
> > index 8b1b1abcef15..6bfdaeddbae8 100644
> > --- a/arch/x86/include/asm/init.h
> > +++ b/arch/x86/include/asm/init.h
> > @@ -5,7 +5,7 @@
> >  #if defined(CONFIG_CC_IS_CLANG) && CONFIG_CLANG_VERSION < 170000
> >  #define __head __section(".head.text") __no_sanitize_undefined __no_stack_protector
> >  #else
> > -#define __head __section(".head.text") __no_sanitize_undefined
> > +#define __head __section(".head.text") __no_sanitize_undefined __no_sanitize_coverage
> >  #endif
> >
> >  struct x86_mapping_info {
> > diff --git a/include/linux/init.h b/include/linux/init.h
> > index ee1309473bc6..c65a050d52a7 100644
> > --- a/include/linux/init.h
> > +++ b/include/linux/init.h
> > @@ -49,7 +49,9 @@
> >
> >  /* These are for everybody (although not all archs will actually
> >     discard it in modules) */
> > -#define __init         __section(".init.text") __cold  __latent_entropy __noinitretpoline
> > +#define __init         __section(".init.text") __cold __latent_entropy \
> > +                                               __noinitretpoline       \
> > +                                               __no_sanitize_coverage
> >  #define __initdata     __section(".init.data")
> >  #define __initconst    __section(".init.rodata")
> >  #define __exitdata     __section(".exit.data")
> > --
> > 2.34.1
> >

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BbetRmieWEHBdEf%3DgOLhWiNVRH5CSDeN6ykBtoP1GrzLA%40mail.gmail.com.
