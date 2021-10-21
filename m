Return-Path: <kasan-dev+bncBCF5XGNWYQBRBH6QYSFQMGQEGRIOJOQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x740.google.com (mail-qk1-x740.google.com [IPv6:2607:f8b0:4864:20::740])
	by mail.lfdr.de (Postfix) with ESMTPS id D9DEC435D28
	for <lists+kasan-dev@lfdr.de>; Thu, 21 Oct 2021 10:43:12 +0200 (CEST)
Received: by mail-qk1-x740.google.com with SMTP id f12-20020a05620a15ac00b0046007dbd2a7sf4276836qkk.3
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Oct 2021 01:43:12 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1634805791; cv=pass;
        d=google.com; s=arc-20160816;
        b=PM1Uqc4VavbhwHh5Z3yI33X8326GiADCdby2MFFNX+MX3fY5/ZgIyJy7j/wdFn+cX6
         iON/+RLJkiWDjygvHWskJYx89wEbGDZspHCfAhcm/FgZaSRSGi6+XVbs3lSQ4D1rXbY9
         JeTgXJ3W/i/Dh6R2bm3ULCNEdAuIs4dvFnQfNkN+JgbKn46uVG4OxbstbVd/PSPmJ84r
         sRelLTDVkLrEVR70/Cy1AYTrlZ7w6tAmXmrNtdJ7ErTowXVGWtT6ofXfoyDBsqxE97YL
         MbPk1uZLTWAWXE49ei73crgAQ25KM75Rm3LeA5oBpJKPQt4DjTLHVzV7cZbUo9J9PJdl
         +GiQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=FjWubWDSC9DhX6MykuMJ5m6rnLxT5qz4Lp3z0QqrzKo=;
        b=Jwv86zDZplXwHl9pAeZyNRzzv9cJJy12lYuLTxwg6zA9/pZo4RHltYUvv0MAybBGjv
         d6uMOcGOOi1FeyrCRmvLBvFwZx3v9P6kiSfCcIX2jGF+sOUxqb2XHTkA2AgPIeTfr7Xf
         944uCX5DSGKCFnKRNY5sLJ+AQKLrsh5YjHmKhPKQKQI6bKE0RhC5313W1FeGKFrTSq5l
         JXssOhPdaS2viG+BifEE/H/vdsb4a6vBQyizADxIyNDfL72PxWCdGTx0OioZ/PUI3vzM
         VQ+MvVTRjYgGNwHpTmhh5AMnwjnr62qt9b1FQ4G25GM0j+01kDqaIUdF1d4/I85fS+33
         ZiuA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b="T6xp/4rR";
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::102c as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=FjWubWDSC9DhX6MykuMJ5m6rnLxT5qz4Lp3z0QqrzKo=;
        b=Tqcu7mDelaa1BGEK2ohmClJfBE2SvZZx6kmqnMb4aNUxelb47ejaD6l0JzEe743Y2Y
         9gDwIE9yngvYkMK061BUHkupgKXVtdaKS4NdyJc97ZBmH3zmSdLlQ326Z2BDcAuAvtWm
         oX4/wDmSzdnkmBZdgu3UhomZ6VjPdDAbXD0t0MGqYzIzFO3KGwodTmhKl9ECdcql96SF
         8llNVyozvBLwLVgSp4zQZFmKQGmZCkZWczj76kZlzRzUqFpWw62e0NYHZBnqune1lczh
         baFfNWJIl5OBTxcCpsLT8rbmBupuM71c5TXrokd3JdfY37XYNRg4boG/dJVQGVhczm+s
         JDYw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=FjWubWDSC9DhX6MykuMJ5m6rnLxT5qz4Lp3z0QqrzKo=;
        b=xp9xY7u6/Ef98vLcZAXyy7UFFgDhUhpd9ZgxTWBo3xEstSoAlraU73zp7eKmgLz1Fv
         95tbftduAUbiLVQrLCFncgDHmOdLnA2ufa3LJ9wusLA/Wpbo+PgAMUFs6mVVfb3y6VPz
         tkK1vMU3H3QJf2CE/WhUPhfiIOwDEZB268punqUkowFTY1A/4207AhgWgheJjsctw1tE
         vbJzjcKDI1Hw/JG2H/axVodMgoAWuZWx6JeWl9L4iPgasZDjojQoiO8sFVUpNukYCp0L
         ZSoxJlEJghs1c5fGD0kQ+HtXunEnfntM5/MQYmNpsW/T1gpBWGsc5K/tbcTk1v7twnR3
         jbrg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533ffvTaqaM0vvex6ebWFjZ8pKT2OPeF8uFk31zyfz1SpDa/aPTI
	BG+DSUKaLZtawDja0X+mXSs=
X-Google-Smtp-Source: ABdhPJz3zvFE4GCgPNcAMydZ1ZpV/RIrmnifQZ4em2oogpGWH1yP2ZcnaheTxb7rNEf8UXhZoDd6Lw==
X-Received: by 2002:a05:622a:1807:: with SMTP id t7mr4586601qtc.140.1634805791683;
        Thu, 21 Oct 2021 01:43:11 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:1805:: with SMTP id o5ls125075qvw.9.gmail; Thu, 21
 Oct 2021 01:43:11 -0700 (PDT)
X-Received: by 2002:ad4:45f0:: with SMTP id q16mr3912752qvu.4.1634805791188;
        Thu, 21 Oct 2021 01:43:11 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1634805791; cv=none;
        d=google.com; s=arc-20160816;
        b=b+fh1uGjJSLKM8Gb9UABR8ab8uvW5IUuRu0kLsppC7RorVr9/d3wnD7jodMwXwqqnp
         ZOpqkN75EuPDv4tQgzHnSahMVog6IsK5XUPDrG7A9dUnxck9OlaCm/pkmuOqdtLmunA4
         fNa858amWe2PtUQLBSsNMlO+I9aOTQ6IV9IlWZfVOXgYgg0k64jMOsRLIx9wKHMa08nZ
         aQ+fnJMad4NRitJterirXsBE2TCzZXrTTOntmuu99rA/R5CiH9tto+IPGVmLvBUaHO8g
         EDr8hIXs7269caip93RvRqIb3S1tucHGHRxDnA+uMTkOlExwhYJo8wyPXICt++0HqDWu
         ov/Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=SJY6DwBxYVl+QUdSNsoZifHerg6QBwwY0i9CzwdxMWE=;
        b=PG0TIY43YNCu9ahhN0KEHaQfaHeWAnrmMe3Ag3f3kyEcCAkGXd0iwM0zp1DU3Jcacn
         MdluMXW54ZDAlM8t0E68jXHa3ioV9GjhNNY2RUbfudX+rGLTFhCZESpB+aqt/kI9Iz3N
         i3+ugDdXV3h7NP3kuQfZ18hJ193zEKhUQnR4InBBsMorcz9NHC4+IdoLiK6vN/xYvbXg
         6j2q6K2kI/Xgxc0Z8xyWpgIHWwNbJaFrersWUnjMsToom8m5WOWGdW01oJnXOnv2ZnjV
         j8QdSU44EGKHagq3cBdMY9fF6nSrZA/4TzUQq9i8uGKPO9+k+cX+0rjPJwqkkll/z99T
         zg/Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b="T6xp/4rR";
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::102c as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-pj1-x102c.google.com (mail-pj1-x102c.google.com. [2607:f8b0:4864:20::102c])
        by gmr-mx.google.com with ESMTPS id s15si36443qkp.3.2021.10.21.01.43.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 21 Oct 2021 01:43:11 -0700 (PDT)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::102c as permitted sender) client-ip=2607:f8b0:4864:20::102c;
Received: by mail-pj1-x102c.google.com with SMTP id t5-20020a17090a4e4500b001a0a284fcc2so2580053pjl.2
        for <kasan-dev@googlegroups.com>; Thu, 21 Oct 2021 01:43:11 -0700 (PDT)
X-Received: by 2002:a17:90b:4f88:: with SMTP id qe8mr4919558pjb.223.1634805790444;
        Thu, 21 Oct 2021 01:43:10 -0700 (PDT)
Received: from www.outflux.net (smtp.outflux.net. [198.145.64.163])
        by smtp.gmail.com with ESMTPSA id d71sm4494239pga.67.2021.10.21.01.43.10
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 21 Oct 2021 01:43:10 -0700 (PDT)
Date: Thu, 21 Oct 2021 01:43:09 -0700
From: Kees Cook <keescook@chromium.org>
To: Marco Elver <elver@google.com>
Cc: Miguel Ojeda <ojeda@kernel.org>, Arnd Bergmann <arnd@arndb.de>,
	Nathan Chancellor <nathan@kernel.org>,
	Nick Desaulniers <ndesaulniers@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Will Deacon <will@kernel.org>,
	Arvind Sankar <nivedita@alum.mit.edu>,
	Masahiro Yamada <masahiroy@kernel.org>, llvm@lists.linux.dev,
	Ard Biesheuvel <ardb@kernel.org>,
	Luc Van Oostenryck <luc.vanoostenryck@gmail.com>,
	linux-kernel@vger.kernel.org, linux-hardening@vger.kernel.org,
	Andrey Konovalov <andreyknvl@gmail.com>,
	kasan-dev <kasan-dev@googlegroups.com>
Subject: Re: [PATCH] compiler-gcc.h: Define __SANITIZE_ADDRESS__ under
 hwaddress sanitizer
Message-ID: <202110210141.18C98C4@keescook>
References: <20211020200039.170424-1-keescook@chromium.org>
 <CANpmjNMPaLpw_FoMzmShLSEBNq_Cn6t86tO_FiYLR2eD001=4Q@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNMPaLpw_FoMzmShLSEBNq_Cn6t86tO_FiYLR2eD001=4Q@mail.gmail.com>
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b="T6xp/4rR";       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::102c
 as permitted sender) smtp.mailfrom=keescook@chromium.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=chromium.org
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

On Thu, Oct 21, 2021 at 08:00:00AM +0200, Marco Elver wrote:
> On Wed, 20 Oct 2021 at 22:00, Kees Cook <keescook@chromium.org> wrote:
> > When Clang is using the hwaddress sanitizer, it sets __SANITIZE_ADDRESS__
> > explicitly:
> >
> >  #if __has_feature(address_sanitizer) || __has_feature(hwaddress_sanitizer)
> >  /* Emulate GCC's __SANITIZE_ADDRESS__ flag */
> >  #define __SANITIZE_ADDRESS__
> >  #endif
> 
> Hmm, the comment is a little inaccurate if hwaddress sanitizer is on,
> but I certainly wouldn't want compiler-clang.h to start emulating gcc
> here and start defining __SANITIZE_HWADDRESS__ if the places where we
> check it are the same as __SANITIZE_ADDRESS__. So this patch is the
> right approach.

Yeah, I agree. I think that was Arnd's thinking as well.

> 
> > Once hwaddress sanitizer was added to GCC, however, a separate define
> > was created, __SANITIZE_HWADDRESS__. The kernel is expecting to find
> > __SANITIZE_ADDRESS__ in either case, though, and the existing string
> > macros break on supported architectures:
> >
> >  #if (defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)) && \
> >           !defined(__SANITIZE_ADDRESS__)
> >
> > where as other architectures (like arm32) have no idea about hwaddress
> > sanitizer and just check for __SANITIZE_ADDRESS__:
> >
> >  #if defined(CONFIG_KASAN) && !defined(__SANITIZE_ADDRESS__)
> 
> arm32 doesn't support KASAN_SW_TAGS, so I think the bit about arm32 is
> irrelevant.

Right -- I had just picked an example.

> Only arm64 can, and the reason that arm64 doesn't check against
> "defined(CONFIG_KASAN)" is because we also have KASAN_HW_TAGS (no
> compiler instrumentation).
> 
> > This would lead to compiler foritfy self-test warnings when building
> > with CONFIG_KASAN_SW_TAGS=y:
> >
> > warning: unsafe memmove() usage lacked '__read_overflow2' symbol in lib/test_fortify/read_overflow2-memmove.c
> > warning: unsafe memcpy() usage lacked '__write_overflow' symbol in lib/test_fortify/write_overflow-memcpy.c
> > ...
> >
> > Sort this out by also defining __SANITIZE_ADDRESS__ in GCC under the
> > hwaddress sanitizer.
> >
> > Suggested-by: Arnd Bergmann <arnd@arndb.de>
> > Cc: Nathan Chancellor <nathan@kernel.org>
> > Cc: Nick Desaulniers <ndesaulniers@google.com>
> > Cc: Miguel Ojeda <ojeda@kernel.org>
> > Cc: Andrew Morton <akpm@linux-foundation.org>
> > Cc: Marco Elver <elver@google.com>
> > Cc: Will Deacon <will@kernel.org>
> > Cc: Arvind Sankar <nivedita@alum.mit.edu>
> > Cc: Masahiro Yamada <masahiroy@kernel.org>
> > Cc: llvm@lists.linux.dev
> > Signed-off-by: Kees Cook <keescook@chromium.org>
> 
> Other than that,
> 
>   Reviewed-by: Marco Elver <elver@google.com>

Thanks! (Oh, BTW, it seems "b4" won't include your Reviewed-by: tag if
it is indented like this.)

-Kees

-- 
Kees Cook

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/202110210141.18C98C4%40keescook.
