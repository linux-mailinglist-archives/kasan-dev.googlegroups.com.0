Return-Path: <kasan-dev+bncBD4NDKWHQYDRBUGJ42QQMGQEMNUM3RA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x37.google.com (mail-oa1-x37.google.com [IPv6:2001:4860:4864:20::37])
	by mail.lfdr.de (Postfix) with ESMTPS id E73BD6E2A70
	for <lists+kasan-dev@lfdr.de>; Fri, 14 Apr 2023 21:09:05 +0200 (CEST)
Received: by mail-oa1-x37.google.com with SMTP id 586e51a60fabf-1877be818e6sf4249313fac.22
        for <lists+kasan-dev@lfdr.de>; Fri, 14 Apr 2023 12:09:05 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1681499344; cv=pass;
        d=google.com; s=arc-20160816;
        b=Etzc9J8ZVP0TM9QFDPHJqXL3XOLrAYsBhBVJ6wKW+kUl7urjQOrGAarzoHHziWd94z
         q4V+/ErbjVsaGHySr0s4KanTSh+R6QxdF2QhKM3LiRyBICqqj2MT7Rdg/fRscR5lT96M
         qh5iZjW8MPXSJ7SsTH8IdCYhPHP9fJ6thw/myflEAtt4k21351ndS8o0eRyfDeQ7x6NU
         8ZJXAiiCtErs8EMyuhSzM9FzHt2mixLgEredpIVLBXx04HragcjN2hnH6q98ogjpg4bB
         EfXSscoD1EkQhr4j874vVejL3Pfxu0x3tAr4Ue2Jmw7Zqn8bLtEz9Z/m1jUQ8fdIWvnY
         J4gg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=XEmFLLgk5zjXsZWpcz9HibDy1Gz3adwIvTl2/ESwwB4=;
        b=bi3sSIkt9Dsr8NjcQhUP9u4OMcXExQsZCvXUeg94BSN/FNUfWd74wf6G5E61I2cXnV
         qzVuPq1w2SSRt3SlGAIMm8GZx3gCfE/DcRkZR/D8OgJplcvPRiYxvccU+5RmVKdNNQTo
         m60GltgP4h1lDWhMgqDFGMM0Ag3NKtxyXINjVCuYLCqTtlPQ2lzSPvzjPhKnTeP7nyMP
         TeLXfLalHolRrjEthRkOA8/cdCntq61362leUykWoBkPUAuu6JbzjovmvcCslcevaZKy
         5LNBNsWX5nlh1CnURVhxT1Xm5f9HfgF1/EO2VaLEg/yVlm79QkSVswLADt11rC0//GrZ
         EKTg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="d7NqpW/j";
       spf=pass (google.com: domain of nathan@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=nathan@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1681499344; x=1684091344;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=XEmFLLgk5zjXsZWpcz9HibDy1Gz3adwIvTl2/ESwwB4=;
        b=G1FsuLnLRYvb1pLLVuuTui6sXWoy6fLQEZEBl6IyGVcjTG/rmajW/J27beQnYbiRZI
         V47TDM6h3dqPV1jhIApyY+/RDdfz3Ri2AAxIn0Jb867jjeuKgI4w9ZyGlnRP7LUCbqCV
         VSrBwC8KTq4r8zfC5MvL/W33MmfGUA4QX/nKWpMt5u5hlgkgRylU4fUUYo8Wvp84EN3R
         StXREQbOGf4jT2CaJqpDSwik508accXObHXOs3Q6tdaFHhn0K1fYDd4+BbMY9CTokAzM
         iwyYrb9eKtLtcIG06JJ6AdQpbW4cHw/dpydS8+QMujSCvR5jTOjT4YcRtjflK7CHEavv
         l4fg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1681499344; x=1684091344;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=XEmFLLgk5zjXsZWpcz9HibDy1Gz3adwIvTl2/ESwwB4=;
        b=FUZUtYlT2WeUgHYZGPkhXW+qw2fz5uLt+i/iC6SKgWBOBlurhp+KcjcGj5NA/9gHMt
         JHW2W/kXiDoepiMtdqSrdU9fRHsuZac41Io2RkvI4Kjb9iJ3TVhQB1bfPCX/qWH5yda1
         ZegmO+GKpL69i3BsajAUiaRVrccLX59P4LxeurC93ax9Ov6OWF8dDgWICDuv/NLNBViy
         Ixw844ZOPLqVxbOUKNDPWMTPQlXUTLc1Xuw9kvEO36U83ZmNcr2JQwM7DgN8gp87A0DH
         C/9MbGTvLLtC20XPcQ6//q09pda1w+uFpsKVzAzI5cD6S8790eF94rUU5AGZGOB7AcMR
         qxQQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AAQBX9fZlzaFKJNsp0MYj+6loZXwgw5uzr1Fpsq5jXgYaAUwhLkYhlvN
	e0iaIegBZmohQkHCEtzZCuU=
X-Google-Smtp-Source: AKy350apEYjdhyAnDbsj2wVOjJRkxqLogMSoYUOq3dVfdFzA7fbmYQP4etyM99xYfqWm26lI1QK/og==
X-Received: by 2002:a05:6871:71e:b0:17a:b31c:9e1e with SMTP id f30-20020a056871071e00b0017ab31c9e1emr3346988oap.1.1681499344388;
        Fri, 14 Apr 2023 12:09:04 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:6502:b0:6a4:1521:9df3 with SMTP id
 cm2-20020a056830650200b006a415219df3ls1764942otb.1.-pod-prod-gmail; Fri, 14
 Apr 2023 12:09:04 -0700 (PDT)
X-Received: by 2002:a9d:7507:0:b0:69f:4bb:199f with SMTP id r7-20020a9d7507000000b0069f04bb199fmr3050771otk.23.1681499343923;
        Fri, 14 Apr 2023 12:09:03 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1681499343; cv=none;
        d=google.com; s=arc-20160816;
        b=m5FWlkz1jZOo5RB/OE6kPeMOaQ6r9bKYCkQYejcJ4aJkkVVrY/lvzlF/Qk8URPYyXj
         JIxIzHVMQh1Oz5i8R7gUH3NdGtE5VYG6JzowjQINL1r419UXigzWxZrv6OrUImr5idyy
         xAz+dNTiZC5NVZy0g8Ias5XWb8DarX+9TWphIgtFSHnHMR8RW5In8D2F+gQnDwFG38xA
         55WT7Ud+qbTiwLM4ATqMu47xHvrIySHJ/IVRtlFmtrSWlrGiBfVvD2InANtDHRQZGSbN
         oiGtE5SUJrT7Jk2k/VzT++4h/tPcHYfpMiUjl36JyPuXhb5JMTZNSbWz0I+y4Gq3WlT9
         7tbA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=G8SvSIlTZSEKBVP1VHKzBYghgNS+3SNFw7w5pBhPymw=;
        b=zD6tNZCe/SLznT1mli7KKpRv0qibqOnomS+3kYILhyLgauNuJ7CQVto5Wls5pC4Ne0
         jJy2xFE6h7U7mMIMIiBJqC5O+Qqok0auKy7KEQVCSxM2Tmb2t929NGiPYFgti6MzChRe
         /dHuPZOL3LDw2xPimtq3EyVEXKp3VamN+dp4CAtUagRQDnDjb4UcjhbN9DcHyS1xDcMF
         DRb+MZoTKeGfSy36/ehhNogIHvaF1GQL8jV7PWa9LIjWSHcxEoDmt5DvN+fpUgH1QftV
         OcXOh8281S7pGpqrW5xf7w9tZO9+6GyXL4w1mUeaBsLfvpTFZEZlaACo8eB55yCdBPLC
         BgGw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="d7NqpW/j";
       spf=pass (google.com: domain of nathan@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=nathan@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id bk19-20020a056830369300b006a12b6325c7si822260otb.4.2023.04.14.12.09.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 14 Apr 2023 12:09:03 -0700 (PDT)
Received-SPF: pass (google.com: domain of nathan@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id B0B2561861;
	Fri, 14 Apr 2023 19:09:03 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 0FDBBC433EF;
	Fri, 14 Apr 2023 19:09:01 +0000 (UTC)
Date: Fri, 14 Apr 2023 12:09:00 -0700
From: Nathan Chancellor <nathan@kernel.org>
To: Arnd Bergmann <arnd@arndb.de>
Cc: Arnd Bergmann <arnd@kernel.org>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Masahiro Yamada <masahiroy@kernel.org>,
	Nick Desaulniers <ndesaulniers@google.com>,
	Marco Elver <elver@google.com>, Nicolas Schier <nicolas@fjasle.eu>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Tom Rix <trix@redhat.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Michael Ellerman <mpe@ellerman.id.au>,
	Peter Zijlstra <peterz@infradead.org>, linux-kbuild@vger.kernel.org,
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org,
	llvm@lists.linux.dev
Subject: Re: [PATCH] kasan: remove hwasan-kernel-mem-intrinsic-prefix=1 for
 clang-14
Message-ID: <20230414190900.GA1277152@dev-arch.thelio-3990X>
References: <20230414082943.1341757-1-arnd@kernel.org>
 <20230414162605.GA2161385@dev-arch.thelio-3990X>
 <24ebf857-b70d-4d94-8870-e41b91649dd1@app.fastmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <24ebf857-b70d-4d94-8870-e41b91649dd1@app.fastmail.com>
X-Original-Sender: nathan@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b="d7NqpW/j";       spf=pass
 (google.com: domain of nathan@kernel.org designates 2604:1380:4641:c500::1 as
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

On Fri, Apr 14, 2023 at 08:53:49PM +0200, Arnd Bergmann wrote:
> On Fri, Apr 14, 2023, at 18:26, Nathan Chancellor wrote:
> > On Fri, Apr 14, 2023 at 10:29:27AM +0200, Arnd Bergmann wrote:
> >> From: Arnd Bergmann <arnd@arndb.de>
> >> 
> >> Unknown -mllvm options don't cause an error to be returned by clang, so
> >> the cc-option helper adds the unknown hwasan-kernel-mem-intrinsic-prefix=1
> >> flag to CFLAGS with compilers that are new enough for hwasan but too
> >
> > Hmmm, how did a change like commit 0e1aa5b62160 ("kcsan: Restrict
> > supported compilers") work if cc-option does not work with unknown
> > '-mllvm' flags (or did it)? That definitely seems like a problem, as I
> > see a few different places where '-mllvm' options are used with
> > cc-option. I guess I will leave that up to the sanitizer folks to
> > comment on that further, one small comment below.
> 
> That one adds both "-fsanitize=thread" and "-mllvm
> -tsan-distinguish-volatile=1". If the first one is missing in the
> compiler, neither will be set. If only the second one fails, I assume
> you'd get the same result I see with hwasan-kernel-mem-intrinsic-prefix=1.

I did not look close enough but it turns out that this check is always
true for the versions of clang that the kernel currently supports, so it
could not fail even if '-mllvm' flag checking worked.

$ git grep tsan-distinguish-volatile llvmorg-11.0.0
llvmorg-11.0.0:llvm/lib/Transforms/Instrumentation/ThreadSanitizer.cpp:    "tsan-distinguish-volatile", cl::init(false),
llvmorg-11.0.0:llvm/test/Instrumentation/ThreadSanitizer/volatile.ll:; RUN: opt < %s -tsan -tsan-distinguish-volatile -S | FileCheck %s

At the time of the Linux change though, we did not have a minimum
supported version, so that check was necessary. I wonder if LLVM
regressed with regards to '-mllvm' flag checking at some point...

> >>  # Instrument memcpy/memset/memmove calls by using instrumented __hwasan_mem*().
> >> +ifeq ($(call clang-min-version, 150000),y)
> >>  CFLAGS_KASAN += $(call cc-param,hwasan-kernel-mem-intrinsic-prefix=1)
> >> +endif
> >> +ifeq ($(call gcc-min-version, 130000),y)
> >> +CFLAGS_KASAN += $(call cc-param,hwasan-kernel-mem-intrinsic-prefix=1)
> >> +endif
> >
> > I do not think you need to duplicate this block, I think
> >
> >   ifeq ($(call clang-min-version, 150000)$(call gcc-min-version, 130000),y)
> >   CFLAGS_KASAN += $(call cc-param,hwasan-kernel-mem-intrinsic-prefix=1)
> >   endif
> >
> > would work, as only one of those conditions can be true at a time.
> 
> Are you sure that clang-min-version evaluates to an empty string
> rather than "n" or something else? I haven't found a documentation
> that says anything about it other than it returning "y" if the condition
> is true.

Yes, see the test-ge and test-gt macros in scripts/Kbuild.include, they
will only ever print the empty string or 'y'.

Cheers,
Nathan

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230414190900.GA1277152%40dev-arch.thelio-3990X.
