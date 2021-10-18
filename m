Return-Path: <kasan-dev+bncBCXO5E6EQQFBB55IW6FQMGQEHAUFA6A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x237.google.com (mail-oi1-x237.google.com [IPv6:2607:f8b0:4864:20::237])
	by mail.lfdr.de (Postfix) with ESMTPS id DFA2243282F
	for <lists+kasan-dev@lfdr.de>; Mon, 18 Oct 2021 22:09:28 +0200 (CEST)
Received: by mail-oi1-x237.google.com with SMTP id w14-20020aca300e000000b00298f5f9f031sf555617oiw.14
        for <lists+kasan-dev@lfdr.de>; Mon, 18 Oct 2021 13:09:28 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1634587768; cv=pass;
        d=google.com; s=arc-20160816;
        b=shH/LFACE52wwqHyiIT+ahD8uUJghX1LthdK/N0OJOcmfI7i4Iz4sZW85avnD5Mlwk
         gi5VTflvv+VGilNgYeC7Jg0l5NS0MxKSjyZWWlaJSBhuqDNZjaUBvTrRphyI0PZWfQGo
         vw9JptqK9qtUVMknFEhiA9k0VBylfaTjjKt8lO8z6Qb3/LIZSD5JXgxue/neJBtIddYE
         u1G8jQ2q9n34ABAKhuEC5GyJsnisHH6H/tuPWG7vUjAlYx4DEeMVlPJDJXuO//YM9db7
         3S1m5Q54PQ7pf4NqhlrcEOSWoG7y83XH5dPaVvTSjCTtv8cGAsj0lgcRoWVFkRj7Ts0V
         ZuoQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=MOAcm5iQlc/4k5EXUv0BGl9foseWxcTz1fYvnSFIVeI=;
        b=nZpWRXedgroTJQWp84Msf/Pdy/m6tCUn6Zkh3gWyGRwSGTVgzVzzfsJMSFrLNI1OeM
         Ae1M61JphX5tgsIVGmUfCpOU/vVwxV/h4wtR3ZxCwJtR05GeudE69w5hSbNRaivuMvdb
         k5VqEz48C6f3Mhmo75T7tXcdJ/0hjkUnGkZdwmqUJg/V9K3XS0kv9UvF77mGPHtIkxUW
         o7Y49LJwwPfp2tQs4QQ5qMyl4DLYqeIR5vVjXzuR12JPiqgVAXQ8ofbhb9P0NbH5S7Oe
         LEeVqwQj0PleLs6fzkLDZbEjmbosheRN7/t7QQvx1Vvm8f9cwdhirIinHDhsPKoJTC90
         zSqA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=dz7ITajD;
       spf=pass (google.com: domain of arnd@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=arnd@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=MOAcm5iQlc/4k5EXUv0BGl9foseWxcTz1fYvnSFIVeI=;
        b=mn3AEk+Wtx0yGJbDAyvoEkWLoSXu2Vd32pMn+Rs83lJ6v1H/UDDMYQGCo3k4IXop0/
         sKv7szKGh8orEN68DU1OjG6PWHCrGnTWZaeNhGKSunHMRpv/rdAXAH77eDqG3mtDIhIh
         k+ATlHAHvQXAUa8NMSudrUMGIACgQSi/SfSDE8b16sQfN54yCZ10GFtr6Lh3m8bZG0ns
         rFL6mmdl+1H1DOiAhec/XxtIpNjUPi5Jy/spWpou28fAkdSVEcwWm7XSTuG0gPcBSe7x
         dE24sdtmtu3n1+28Un1/lyzIZlzmd2I4cceVnnWcpZI4o3RT0bFL92SuthF6xYj6ORKl
         ACcg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=MOAcm5iQlc/4k5EXUv0BGl9foseWxcTz1fYvnSFIVeI=;
        b=fiqURuS2gQoZ2Ctdr9dcx+69M2+FGfL1U0oHA6bV1eSU8fyTU5vWi0EoJM1OQe0SUA
         IrFj+brs5Q9tj3Qzzf681cnIQzK/t+MjvVZ33oVRa7K025nwrlREcl+xPaWXa/XjmUPp
         Ci3OIOySIcumSB2hgrEmr7ryZ+OL48c2TUNFeK6HFekhdXfRoJJmx3qXaLC0hq0A+pTA
         KENqnQdH6b9xBxXM06t7Fvcsq1/FVOrHXQ3lJZyWFjZHcJZzp8MRrFgARPHh/o+kTAlD
         WynVHVuDSDONofnVCVQTwJQRiWCR7nomX6T3yZ8MCRe9NOqoL2LB+rHUwlhSfVlTR+YP
         yojA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532OR2HmS6JXGjMYEIzwkJcBj8lJOab38kGtMEFNHnbqec0mh+8g
	b0Ep3DFV9HLYJdmWDgBFVhs=
X-Google-Smtp-Source: ABdhPJzLjl5Danc3B71bgmCdI70IqD2KMx9DrO+NElfQYFBtrM29a4KlObtVgyhZN7KqynUp2ag6LA==
X-Received: by 2002:a4a:e292:: with SMTP id k18mr1468928oot.80.1634587767834;
        Mon, 18 Oct 2021 13:09:27 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:ad53:: with SMTP id w80ls4708994oie.7.gmail; Mon, 18 Oct
 2021 13:09:27 -0700 (PDT)
X-Received: by 2002:aca:d98a:: with SMTP id q132mr815826oig.13.1634587767432;
        Mon, 18 Oct 2021 13:09:27 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1634587767; cv=none;
        d=google.com; s=arc-20160816;
        b=fLJQHgk5lzniL3cPN0nb9h29vW/t3eG6o6nWlOY+I5uZyit2zkezrpuyjKit5xDdgQ
         +9df0RmbcGQLG0jemuUXYG7moRUxC+t7t8xh2oCnnj9oSgYlI3T3GTW7oxEkdFVqBGyo
         7zRDQmi4HVgVuAJGtBSj92e3Ts/bmjzcAl51yoA12IgoFny79VR6ZpoWQVotCUVa5sXW
         nPtr8SUyFI79oURGYXO7xEGAAAhupx/47mCZmssj+cabrwmDseFpodbbwlvKMmXf4yIF
         rNHHGuIJ+XchNNidmMjdXjwwNB9WD7n0rkguKd3Pp5yl5Bd0CNyu/2QM7idh6K0AQ/5b
         Dlpw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=pd8u+ZDzk8BlGfUixSzB7lCbznQ9iL75zxyd6Vop+Bg=;
        b=N+tlo+JCLqnbdfrYpGNMDa+TEf9+tzQDYQDOfvH7zxKs0V2gqSAzOz6tSriodihrIp
         Zqo3yKf5Bq8DGaXevsubpW/AluwFT2GbhwYrIA3KlES8mTSl5TKQyh/6JACzRi9N1Vzw
         Nr4PrhkmRJzH6pBqN16AWEnjwG/S7i3x5lMm/lLbRD/wx8i9yyvkx44Nkz+ha2jKCb9+
         yPgWX+zdSAPS1SnJCmb156yUIdcCDsWkHnc40CIZFUDWVuZl3j7LDUYcbQoOkTKRLMj3
         TZG78PkdKQdHp4UBGQtmYRbNKPLgtsVDilPAC+cIw8pBcChyQtTaTnpVXwzoYwJUe8ck
         QWWQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=dz7ITajD;
       spf=pass (google.com: domain of arnd@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=arnd@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id l14si123020ooe.0.2021.10.18.13.09.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 18 Oct 2021 13:09:27 -0700 (PDT)
Received-SPF: pass (google.com: domain of arnd@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id A267461212
	for <kasan-dev@googlegroups.com>; Mon, 18 Oct 2021 20:09:26 +0000 (UTC)
Received: by mail-wm1-f44.google.com with SMTP id o24so2350968wms.0
        for <kasan-dev@googlegroups.com>; Mon, 18 Oct 2021 13:09:26 -0700 (PDT)
X-Received: by 2002:a05:600c:1548:: with SMTP id f8mr1129122wmg.35.1634587765086;
 Mon, 18 Oct 2021 13:09:25 -0700 (PDT)
MIME-Version: 1.0
References: <20211013150025.2875883-1-arnd@kernel.org> <20211013150025.2875883-2-arnd@kernel.org>
 <202110181247.8F53380@keescook>
In-Reply-To: <202110181247.8F53380@keescook>
From: Arnd Bergmann <arnd@kernel.org>
Date: Mon, 18 Oct 2021 22:09:09 +0200
X-Gmail-Original-Message-ID: <CAK8P3a2wO+diAvRXtZKq+z84sfson6GhxgL9gpBG_BP4h5bSQA@mail.gmail.com>
Message-ID: <CAK8P3a2wO+diAvRXtZKq+z84sfson6GhxgL9gpBG_BP4h5bSQA@mail.gmail.com>
Subject: Re: [PATCH 2/2] kasan: use fortified strings for hwaddress sanitizer
To: Kees Cook <keescook@chromium.org>
Cc: linux-hardening@vger.kernel.org, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Arnd Bergmann <arnd@arndb.de>, Nathan Chancellor <nathan@kernel.org>, 
	Nick Desaulniers <ndesaulniers@google.com>, Miguel Ojeda <ojeda@kernel.org>, 
	Sami Tolvanen <samitolvanen@google.com>, Marco Elver <elver@google.com>, 
	Masahiro Yamada <masahiroy@kernel.org>, Ard Biesheuvel <ardb@kernel.org>, 
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>, llvm@lists.linux.dev
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: arnd@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=dz7ITajD;       spf=pass
 (google.com: domain of arnd@kernel.org designates 198.145.29.99 as permitted
 sender) smtp.mailfrom=arnd@kernel.org;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=kernel.org
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

On Mon, Oct 18, 2021 at 9:57 PM Kees Cook <keescook@chromium.org> wrote:
>
> On Wed, Oct 13, 2021 at 05:00:06PM +0200, Arnd Bergmann wrote:
> > From: Arnd Bergmann <arnd@arndb.de>
> >
> > GCC has separate macros for -fsanitize=kernel-address and
> > -fsanitize=kernel-hwaddress, and the check in the arm64 string.h
> > gets this wrong, which leads to string functions not getting
> > fortified with gcc. The newly added tests find this:
> >
> > warning: unsafe memchr() usage lacked '__read_overflow' warning in /git/arm-soc/lib/test_fortify/read_overflow-memchr.c
> > warning: unsafe memchr_inv() usage lacked '__read_overflow' symbol in /git/arm-soc/lib/test_fortify/read_overflow-memchr_inv.c
> > warning: unsafe memcmp() usage lacked '__read_overflow' warning in /git/arm-soc/lib/test_fortify/read_overflow-memcmp.c
> > warning: unsafe memscan() usage lacked '__read_overflow' symbol in /git/arm-soc/lib/test_fortify/read_overflow-memscan.c
> > warning: unsafe memcmp() usage lacked '__read_overflow2' warning in /git/arm-soc/lib/test_fortify/read_overflow2-memcmp.c
> > warning: unsafe memcpy() usage lacked '__read_overflow2' symbol in /git/arm-soc/lib/test_fortify/read_overflow2-memcpy.c
> > warning: unsafe memmove() usage lacked '__read_overflow2' symbol in /git/arm-soc/lib/test_fortify/read_overflow2-memmove.c
> > warning: unsafe memcpy() usage lacked '__write_overflow' symbol in /git/arm-soc/lib/test_fortify/write_overflow-memcpy.c
> > warning: unsafe memmove() usage lacked '__write_overflow' symbol in /git/arm-soc/lib/test_fortify/write_overflow-memmove.c
> > warning: unsafe memset() usage lacked '__write_overflow' symbol in /git/arm-soc/lib/test_fortify/write_overflow-memset.c
> > warning: unsafe strcpy() usage lacked '__write_overflow' symbol in /git/arm-soc/lib/test_fortify/write_overflow-strcpy-lit.c
> > warning: unsafe strcpy() usage lacked '__write_overflow' symbol in /git/arm-soc/lib/test_fortify/write_overflow-strcpy.c
> > warning: unsafe strlcpy() usage lacked '__write_overflow' symbol in /git/arm-soc/lib/test_fortify/write_overflow-strlcpy-src.c
> > warning: unsafe strlcpy() usage lacked '__write_overflow' symbol in /git/arm-soc/lib/test_fortify/write_overflow-strlcpy.c
> > warning: unsafe strncpy() usage lacked '__write_overflow' symbol in /git/arm-soc/lib/test_fortify/write_overflow-strncpy-src.c
> > warning: unsafe strncpy() usage lacked '__write_overflow' symbol in /git/arm-soc/lib/test_fortify/write_overflow-strncpy.c
> > warning: unsafe strscpy() usage lacked '__write_overflow' symbol in /git/arm-soc/lib/test_fortify/write_overflow-strscpy.c
> >
>
> What is the build config that trips these warnings?

It's a randconfig build, I've uploaded one .config to
https://pastebin.com/raw/4TKB9mhs,
but I have other ones if you can't reproduce with that one.

> In trying to understand this, I see in arch/arm64/include/asm/string.h:
>
> #if (defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)) && \
>         !defined(__SANITIZE_ADDRESS__)
>
> other architectures (like arm32) do:
>
> #if defined(CONFIG_KASAN) && !defined(__SANITIZE_ADDRESS__)

Yes, that is exactly the thing that goes wrong. With clang, __SANITIZE_ADDRESS__
gets set here, but gcc sets __SANITIZE_HWADDRESS__ instead
for CONFIG_KASAN_SW_TAGS, so the condition is always true.

> > Add a workaround to include/linux/compiler_types.h so we always
> > define __SANITIZE_ADDRESS__ for either mode, as we already do
> > for clang.
>
> Where is the clang work-around? (Or is this a statement that clang,
> under -fsanitize=kernel-hwaddress, already sets __SANITIZE_ADDRESS__ by
> default?

I mean this snippet:

#if __has_feature(address_sanitizer) || __has_feature(hwaddress_sanitizer)
/* Emulate GCC's __SANITIZE_ADDRESS__ flag */
#define __SANITIZE_ADDRESS__
#endif

Without that, clang sets neither __SANITIZE_ADDRESS__ nor
__SANITIZE_HWADDRESS__

> > diff --git a/include/linux/compiler_types.h b/include/linux/compiler_types.h
> > index aad6f6408bfa..2f2776fffefe 100644
> > --- a/include/linux/compiler_types.h
> > +++ b/include/linux/compiler_types.h
> > @@ -178,6 +178,13 @@ struct ftrace_likely_data {
> >   */
> >  #define noinline_for_stack noinline
> >
> > +/*
> > + * Treat __SANITIZE_HWADDRESS__ the same as __SANITIZE_ADDRESS__ in the kernel
> > + */
> > +#ifdef __SANITIZE_HWADDRESS__
> > +#define __SANITIZE_ADDRESS__
> > +#endif
>
> Should this go into compiler-gcc.h instead?

Yes, that might be clearer, but the effect is the same, as no other
compiler defines
those macros.

       Arnd

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAK8P3a2wO%2BdiAvRXtZKq%2Bz84sfson6GhxgL9gpBG_BP4h5bSQA%40mail.gmail.com.
