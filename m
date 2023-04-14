Return-Path: <kasan-dev+bncBD4NDKWHQYDRBIP54WQQMGQEDF4QP6Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23f.google.com (mail-oi1-x23f.google.com [IPv6:2607:f8b0:4864:20::23f])
	by mail.lfdr.de (Postfix) with ESMTPS id D6C786E2840
	for <lists+kasan-dev@lfdr.de>; Fri, 14 Apr 2023 18:26:10 +0200 (CEST)
Received: by mail-oi1-x23f.google.com with SMTP id o205-20020acad7d6000000b0038b3b839a9fsf9187703oig.14
        for <lists+kasan-dev@lfdr.de>; Fri, 14 Apr 2023 09:26:10 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1681489569; cv=pass;
        d=google.com; s=arc-20160816;
        b=xwPbxLwO3bRCARrplJ9t9npWbNPloGkJ6JDfHwbDQH/qI9LPHy0JKBAHVuboOUe+P8
         uTKh5sJ36PHIbNyMIXfm+Tv69nFoZ0A9ElWB2mBqUYEq9AecT/rVxSiu+EuMwFW4975V
         6laIRgvpjcmVyqp7M6JYV7yzfhH6YpWW0jiakzQLEYCeIvsMgYmLFJbw0MFK3xYWbgjk
         Enn4c4oMmXziOaoVkY6Y0qoVxohF6DwKJ2GIxCtnqgPq4F44P5qXnEd9ueWkI9BehZaw
         0rLGvZKa7vHMMPX7Sfacr7JbgQPib5Y9pCOThRpqGdD6/bOCI3dMaSzfRBYsfTtRMF+d
         a3Kg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=tEptB0iWm1FR4DnJoq7q0pN7g/4+uAPzxgq8+271+nc=;
        b=NdV57j+7L4vPydBWfKwXH+mxNghvefQ5CYCa9Vh9aVZfTPy1P71ajN66LhvNFhmSqf
         Ai5JnVu4Yig9evcqkxaY7AHPylQETxudHjqUOVhROAfT1lN+Gg901dIbdy6n01KhIvXZ
         9g+dq2VZYAAOwEaDNutjovU96juJWF81k5TJfl1sO+ICAAjtCWBjcjbYqRqdzs5R6bLY
         t+Xixv7juSn9HTGhJ+6dwG7jZGUIt+sLg4vIkrVkPGflJJAyjYEY/keZFlEJjcD5EHPW
         UNKi2RZTlgJCIQPsyy9/+N0pqq7UbuSB3YKUtCoY/aiUzhWs9pXlVlmyUgqBNdU/set0
         rmCw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="j3qAa/tC";
       spf=pass (google.com: domain of nathan@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=nathan@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1681489569; x=1684081569;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=tEptB0iWm1FR4DnJoq7q0pN7g/4+uAPzxgq8+271+nc=;
        b=WDFHQAMo2W9mi+n+p40DTamjLqU3GpHUgfizJxOM7DBz99O0A2zgVLeipCWe1pt3Dh
         DeHOIXuWBbfVv6caYjWy9k5exmrqTtjbtuhhIEa9UicHpAs/fLkwD1h6F0Fx44s7238u
         YpsXOTR0xlVOZe8troyH6DUdqNAqc09gnnoGZMxG69C9khdg70IqMfESjRAhEH2qks12
         gL6Sb7EXtsT+8nzeYl6AbJu6OFTGp7MB9FAcNXzgRx0Oz/GYjSa0+rzvxqi7vWmVAk7P
         Tq9imefztaWLnabAPLlSltguL/SInLyL5841a80C1wvBAW1QaT90MeosPqdX40S2eV5U
         PZZw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1681489569; x=1684081569;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=tEptB0iWm1FR4DnJoq7q0pN7g/4+uAPzxgq8+271+nc=;
        b=cVrz/NVZCOly3D77DB2XfuVZVSpVNjGYrC8kxqOJaKU6MNlawNFOpsmVE+Z90mtMcb
         xz59xJWriIgyOW9MgFabfbXnrIKgD9yA36ew0tNj+nBBgRWQFuJrQ9hUcOaL19dvaON/
         SOF97HsopUFQXMt/hE0LCXj4U4oGI/R4MvQ6oEQ8zc3VV94pA5JtDt+JuxVOOCbig2xy
         P4lu8JSsDosQCHELrNzKpI4fTw9jNE4k8d4/nvF3K6d7CQ5VyMe8V/a4pHDK8rjVNTOP
         3ffiblkIg+aa4y/v8Qqlj9iQMwpeHY4Vqjg7gywXDkwEv22SjahfuWNW1mFSuHVGEYuA
         3X2A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AAQBX9cLAkH10bKLGoMmlgU9WxLmL0nGHvdCuuIhEMCb6fzi7dzJdDD6
	wIgz9eq2nXJYnPRbWSLFZCc=
X-Google-Smtp-Source: AKy350Ybh8DgeH9OlngP8rnN8Qtr3kdLLXhQKL8RZwgcLVYuycQkampWcvSrJqwXE1uD/Zgy1cX16Q==
X-Received: by 2002:a05:6830:18f6:b0:69f:573:6113 with SMTP id d22-20020a05683018f600b0069f05736113mr1672571otf.2.1681489569319;
        Fri, 14 Apr 2023 09:26:09 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6871:8701:b0:184:23f5:48cc with SMTP id
 tc1-20020a056871870100b0018423f548ccls8557236oab.2.-pod-prod-gmail; Fri, 14
 Apr 2023 09:26:08 -0700 (PDT)
X-Received: by 2002:a05:6870:c227:b0:177:b6ed:a154 with SMTP id z39-20020a056870c22700b00177b6eda154mr4690404oae.34.1681489568840;
        Fri, 14 Apr 2023 09:26:08 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1681489568; cv=none;
        d=google.com; s=arc-20160816;
        b=Pq6sqf2nd9lqN/kRBdz6HQvklC6IRc8Ldj+ayMZ9kyLCis+PAIZUzHNp5uLLNz9Qja
         wy+T/LCrAyhR4VzDoYU/AMFbYTX70qKNoBtntVWNE4z70YhObE4rrywrHpsu0xIDJcE0
         uaVIMZsI3W/lr4NfZcaubGL4yab8rB9jeEoCGuHtMIGEytadDWcG0SQBCq3mwGlmSZ0Q
         h2njgES1DtxVO/KGI69CVKV8ce6IAmdB9wSERNFJDOuOpYqPg1Jl2WMirC2CSk/SCY9N
         JGzCSvRwfbHiVVfnzBPZsrvRrzwz+n312Iwabns1hDD165MQyjH9Hiy0ALnR7zaILvIq
         QPyA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=eEc8Fm/wm0VKS1K1UBuz5uetd7KCRftJswDSiYhnE4g=;
        b=j7+NPJqHFcEW5S+EoSa7U/YaJ8UCXJ5OMdRdUbPZovslGeZtZs0limROeyA438pWbQ
         Dg/Tq+NcGxH2W8WtpjJEWt0uVYPlWm0QeVX6QpGYGOLpFEjQ//61slbtsqgX7W3WZXqK
         PIZiZ3kyLd3fKKr8yDUdcn+TmuMlzBb27NjYa5zC1kcNnFA5uDVV9bFAkIX1Gh2ppid4
         8+337OQ0pyCB7Tnu+V6xC4AjaEBtGLFhkujW0DZvW5PJOfDJh4k12WcNiZU3M40u+4qy
         XhBZRwFL0RHuYyQ/UxnWqEWOEKrye36vJDTC5qbUDGLx6T0STtwxSk6glg49q9yHW8yY
         zJpg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="j3qAa/tC";
       spf=pass (google.com: domain of nathan@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=nathan@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id lq8-20020a0568708dc800b0018423c84676si388382oab.1.2023.04.14.09.26.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 14 Apr 2023 09:26:08 -0700 (PDT)
Received-SPF: pass (google.com: domain of nathan@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id 94638648DC;
	Fri, 14 Apr 2023 16:26:08 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id B7B58C433D2;
	Fri, 14 Apr 2023 16:26:06 +0000 (UTC)
Date: Fri, 14 Apr 2023 09:26:05 -0700
From: Nathan Chancellor <nathan@kernel.org>
To: Arnd Bergmann <arnd@kernel.org>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Masahiro Yamada <masahiroy@kernel.org>,
	Nick Desaulniers <ndesaulniers@google.com>,
	Marco Elver <elver@google.com>, Arnd Bergmann <arnd@arndb.de>,
	Nicolas Schier <nicolas@fjasle.eu>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Tom Rix <trix@redhat.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Michael Ellerman <mpe@ellerman.id.au>,
	"Peter Zijlstra (Intel)" <peterz@infradead.org>,
	linux-kbuild@vger.kernel.org, kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org, llvm@lists.linux.dev
Subject: Re: [PATCH] kasan: remove hwasan-kernel-mem-intrinsic-prefix=1 for
 clang-14
Message-ID: <20230414162605.GA2161385@dev-arch.thelio-3990X>
References: <20230414082943.1341757-1-arnd@kernel.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20230414082943.1341757-1-arnd@kernel.org>
X-Original-Sender: nathan@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b="j3qAa/tC";       spf=pass
 (google.com: domain of nathan@kernel.org designates 139.178.84.217 as
 permitted sender) smtp.mailfrom=nathan@kernel.org;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=kernel.org
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

On Fri, Apr 14, 2023 at 10:29:27AM +0200, Arnd Bergmann wrote:
> From: Arnd Bergmann <arnd@arndb.de>
> 
> Unknown -mllvm options don't cause an error to be returned by clang, so
> the cc-option helper adds the unknown hwasan-kernel-mem-intrinsic-prefix=1
> flag to CFLAGS with compilers that are new enough for hwasan but too

Hmmm, how did a change like commit 0e1aa5b62160 ("kcsan: Restrict
supported compilers") work if cc-option does not work with unknown
'-mllvm' flags (or did it)? That definitely seems like a problem, as I
see a few different places where '-mllvm' options are used with
cc-option. I guess I will leave that up to the sanitizer folks to
comment on that further, one small comment below.

> old for this option. This causes a rather unreadable build failure:
> 
> fixdep: error opening file: scripts/mod/.empty.o.d: No such file or directory
> make[4]: *** [/home/arnd/arm-soc/scripts/Makefile.build:252: scripts/mod/empty.o] Error 2
> fixdep: error opening file: scripts/mod/.devicetable-offsets.s.d: No such file or directory
> make[4]: *** [/home/arnd/arm-soc/scripts/Makefile.build:114: scripts/mod/devicetable-offsets.s] Error 2
> 
> Add a version check to only allow this option with clang-15, gcc-13
> or later versions.
> 
> Fixes: 51287dcb00cc ("kasan: emit different calls for instrumentable memintrinsics")
> Signed-off-by: Arnd Bergmann <arnd@arndb.de>
> ---
> There is probably a better way to do this than to add version checks,
> but I could not figure it out.
> ---
>  scripts/Makefile.kasan | 5 +++++
>  1 file changed, 5 insertions(+)
> 
> diff --git a/scripts/Makefile.kasan b/scripts/Makefile.kasan
> index c186110ffa20..2cea0592e343 100644
> --- a/scripts/Makefile.kasan
> +++ b/scripts/Makefile.kasan
> @@ -69,7 +69,12 @@ CFLAGS_KASAN := -fsanitize=kernel-hwaddress \
>  		$(instrumentation_flags)
>  
>  # Instrument memcpy/memset/memmove calls by using instrumented __hwasan_mem*().
> +ifeq ($(call clang-min-version, 150000),y)
>  CFLAGS_KASAN += $(call cc-param,hwasan-kernel-mem-intrinsic-prefix=1)
> +endif
> +ifeq ($(call gcc-min-version, 130000),y)
> +CFLAGS_KASAN += $(call cc-param,hwasan-kernel-mem-intrinsic-prefix=1)
> +endif

I do not think you need to duplicate this block, I think

  ifeq ($(call clang-min-version, 150000)$(call gcc-min-version, 130000),y)
  CFLAGS_KASAN += $(call cc-param,hwasan-kernel-mem-intrinsic-prefix=1)
  endif

would work, as only one of those conditions can be true at a time.

Cheers,
Nathan

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230414162605.GA2161385%40dev-arch.thelio-3990X.
