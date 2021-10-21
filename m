Return-Path: <kasan-dev+bncBC7OBJGL2MHBBKEEYSFQMGQEVNJ2MGY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23e.google.com (mail-oi1-x23e.google.com [IPv6:2607:f8b0:4864:20::23e])
	by mail.lfdr.de (Postfix) with ESMTPS id BDC43435A8F
	for <lists+kasan-dev@lfdr.de>; Thu, 21 Oct 2021 08:01:14 +0200 (CEST)
Received: by mail-oi1-x23e.google.com with SMTP id w3-20020acadf03000000b00299926760basf928813oig.20
        for <lists+kasan-dev@lfdr.de>; Wed, 20 Oct 2021 23:01:14 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1634796072; cv=pass;
        d=google.com; s=arc-20160816;
        b=vv3suBRu8pILczOVMnvmjA0SJ+nZEo2/9cvG8q/fqZ4EXMuokAcG1CPN9MZhpBJXkx
         YJo56SHyH02dRutm3sq5oXjq/z8dBkA1iy3NsUM6SBJFrK38Gq4FzVPNx23YCyd7Hl9f
         +3KNspsRfJiPuQGSaB8RDgrq3l3MNqyRtmvtHOAOcTgP6lACGTLPaHp8qQRDprK0oe2T
         2G9UMH27DlBhgySqXkZeqY5/bnhWSWVVZVFbkDvZsuX9GMQX9srR35PyvG/8FSBp8DLw
         LvwDX0smC+zZ5qdSvRhN8wt6kTMv/ABErV56azeodFoeM0rfukqfirbOTdjg5NDy9Yvt
         G87A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=SlJjtXWfrvqjbRNWvqxyz/mgDNVkRzMNAOqAxU9XhSA=;
        b=vd7OYy7tR1wcR/c+Sb2x375uiSRGAtVCBTb+DV8OtnuFY5O3vIk36R2g2mrnhm8KAc
         ivPXYInt/0xfvx2y4iS92IHCnIN+wOTx3DWN2PNY+SJZH/vGAmdoevGMMsGOAWhop6Eu
         zXl9lkH0hzFVqju3CIFSq8upuEk80xHQV9yD4U1Nn+2eFbxT+Z7/hzq8VvFnSFUtKOzS
         csZb1DFIGAEEtVmwF2ua7zjzyUlGdMEzkLaPt3oGaPvRv5ymC7Xwb59N0Q+RyR91RaHX
         YMiGmO048o9mk7T2b89g0zLLTqa2PSU5NhA0b9mc/rA4fcjdmFycRyApxR+4Osf3rKhd
         uoMA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="tHM/UYL4";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22e as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=SlJjtXWfrvqjbRNWvqxyz/mgDNVkRzMNAOqAxU9XhSA=;
        b=OecN+Jjcgzh/XWZrIVxYM5xf5+9SL/RVqEgRX6siQC04FzQ/LBR4ptCxDmoYzVaWe2
         dHVZ9O44Tz2staKVPt8IVPqkZu3FLDCSNlErfYrrjt4sJGx4oFyaRd1di3lwq0cYqCEm
         kStlvOppryXOvE72hB0DX+nRKv8OMH3jq8CKRIjL44u9nVirws15ToitItc9M3Agg4Bg
         LVr8mVDWUdmwsVVP2nCmL3gvlQtX1Dq1yAGiMjlyfg+9a8SvaEJqNiBisQ5xfqFtIOF7
         mViSgoQTLOKyj/49PDVkNnOo1UyT+1Pd+p3CwMUnMUxCMH1TJGOJJKBe0oO+GWLa9Nij
         NdJg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=SlJjtXWfrvqjbRNWvqxyz/mgDNVkRzMNAOqAxU9XhSA=;
        b=NdkL1w4UDUh8GH/SCcWgsYfL5QU/cq1wu3HRiVNicDsxOvGeHWFD3LSwyX+Tr6Wacr
         somMesfWL+hTAuOVVSQMiJ86LvAeFyCH6JyuHc46PutW3/pj9OlbzFta6kJPhafxur6j
         S0qJ2EVEZ+QtfqDokU3PrONRjH3ny0akLQ2+g/AlyM1RmNmLIfwAs1CASvzP5hYYL9ud
         qzpR9XjFjxJZzrsngjdFkcpIqNAXgUWTpQhhNtMjWpFfOusZt3gO74JJUgkKbabqqQTu
         jopzQ8tlQdk83G22DT/CEDqkI6JOLSycOQJbpaeaNHAbk186YIaQdfoOshfoNZJ4Q1aN
         Vozw==
X-Gm-Message-State: AOAM5339P22AJFGOYovTtrPZfYA0cNmuMg5CuQ3Ic2uy2nCR+mm9ahC8
	54DR2tYe+n01o9UoOvNOOtQ=
X-Google-Smtp-Source: ABdhPJzFMUXPZNZODB4UStNhQHdkkRHH8Qi/qs5+DqEY3oR8xxLco/ePh0yE2jo9hqjHl/Hq619wRw==
X-Received: by 2002:a05:6808:8f2:: with SMTP id d18mr2767465oic.90.1634796072323;
        Wed, 20 Oct 2021 23:01:12 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:356:: with SMTP id h22ls1364202ote.5.gmail; Wed, 20
 Oct 2021 23:01:12 -0700 (PDT)
X-Received: by 2002:a9d:12b2:: with SMTP id g47mr3044491otg.227.1634796071869;
        Wed, 20 Oct 2021 23:01:11 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1634796071; cv=none;
        d=google.com; s=arc-20160816;
        b=t8EZtxM48bzYbPcxdeIVlMLJ//Ite1W4TzLRJ4S8RCTcJPAZHBZlGYvRz89o+px+qt
         Q8e0jjLul46qIgWBYe5g4dTNNGLAhq0daZRattVha8W1xLqAiweBeqwv5UjuzFQlrDy9
         NBS1I932oYa1P/+VuVOuKCEUhm1XmMCWGvy5I2aDOYej1nh5nukcY+cfwzKOon6WfKss
         /rXOvFcFHEqq3PbB2uLt0B/veQu0xCV9aMb7JbROxV3o4xyqE8plvZDHzLgZNzPI++Ew
         SigQ59aeaHLAEf9iaLEL8ualzuaVgsgM9WaktKzJ9BDEq/2tmNh6g1qi9v0mkrZfx9Vc
         bNSw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=xTVsi87T0lDEPgn8Tsk62laBFA4FkXChR4d7SeUQje8=;
        b=aYoj6Euu0VAVraWV4Vsvhk+v2uxBN38Fr+noX0JUo4ypdYmOuWghhxXGt3S4q2ttvl
         5laHHg5UMiQyaxVz6WHBb3QhA6cQEmTH1rVALkZ6J/QXZXfcBN7Ld9J0OjwUnJKMwgiA
         12FZNUh+nrrE0uUZVgN5L7OrCrPsarP2DLb//yZ4XNrRdZc9bX+zqgnsRpokxYe8EE0f
         YOeno3z6boZguEHU/qR/Ziqn5oL5GRLatZ2oesCGmhMQucRt8EMHn9B1pUULtHzZ9xPt
         gROM/LQ7Z8BhFtDmiCPQTnzWu8QN7T+MIdBp4WsBwX4mCVfAI7W9ePJL/kZArMzOH4tu
         bjwg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="tHM/UYL4";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22e as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x22e.google.com (mail-oi1-x22e.google.com. [2607:f8b0:4864:20::22e])
        by gmr-mx.google.com with ESMTPS id r130si277929oig.2.2021.10.20.23.01.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 20 Oct 2021 23:01:11 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22e as permitted sender) client-ip=2607:f8b0:4864:20::22e;
Received: by mail-oi1-x22e.google.com with SMTP id r6so12504904oiw.2
        for <kasan-dev@googlegroups.com>; Wed, 20 Oct 2021 23:01:11 -0700 (PDT)
X-Received: by 2002:a05:6808:118c:: with SMTP id j12mr2641330oil.65.1634796071409;
 Wed, 20 Oct 2021 23:01:11 -0700 (PDT)
MIME-Version: 1.0
References: <20211020200039.170424-1-keescook@chromium.org>
In-Reply-To: <20211020200039.170424-1-keescook@chromium.org>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 21 Oct 2021 08:00:00 +0200
Message-ID: <CANpmjNMPaLpw_FoMzmShLSEBNq_Cn6t86tO_FiYLR2eD001=4Q@mail.gmail.com>
Subject: Re: [PATCH] compiler-gcc.h: Define __SANITIZE_ADDRESS__ under
 hwaddress sanitizer
To: Kees Cook <keescook@chromium.org>
Cc: Miguel Ojeda <ojeda@kernel.org>, Arnd Bergmann <arnd@arndb.de>, 
	Nathan Chancellor <nathan@kernel.org>, Nick Desaulniers <ndesaulniers@google.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Will Deacon <will@kernel.org>, 
	Arvind Sankar <nivedita@alum.mit.edu>, Masahiro Yamada <masahiroy@kernel.org>, llvm@lists.linux.dev, 
	Ard Biesheuvel <ardb@kernel.org>, Luc Van Oostenryck <luc.vanoostenryck@gmail.com>, 
	linux-kernel@vger.kernel.org, linux-hardening@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@gmail.com>, kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b="tHM/UYL4";       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22e as
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

On Wed, 20 Oct 2021 at 22:00, Kees Cook <keescook@chromium.org> wrote:
> When Clang is using the hwaddress sanitizer, it sets __SANITIZE_ADDRESS__
> explicitly:
>
>  #if __has_feature(address_sanitizer) || __has_feature(hwaddress_sanitizer)
>  /* Emulate GCC's __SANITIZE_ADDRESS__ flag */
>  #define __SANITIZE_ADDRESS__
>  #endif

Hmm, the comment is a little inaccurate if hwaddress sanitizer is on,
but I certainly wouldn't want compiler-clang.h to start emulating gcc
here and start defining __SANITIZE_HWADDRESS__ if the places where we
check it are the same as __SANITIZE_ADDRESS__. So this patch is the
right approach.

> Once hwaddress sanitizer was added to GCC, however, a separate define
> was created, __SANITIZE_HWADDRESS__. The kernel is expecting to find
> __SANITIZE_ADDRESS__ in either case, though, and the existing string
> macros break on supported architectures:
>
>  #if (defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)) && \
>           !defined(__SANITIZE_ADDRESS__)
>
> where as other architectures (like arm32) have no idea about hwaddress
> sanitizer and just check for __SANITIZE_ADDRESS__:
>
>  #if defined(CONFIG_KASAN) && !defined(__SANITIZE_ADDRESS__)

arm32 doesn't support KASAN_SW_TAGS, so I think the bit about arm32 is
irrelevant.

Only arm64 can, and the reason that arm64 doesn't check against
"defined(CONFIG_KASAN)" is because we also have KASAN_HW_TAGS (no
compiler instrumentation).

> This would lead to compiler foritfy self-test warnings when building
> with CONFIG_KASAN_SW_TAGS=y:
>
> warning: unsafe memmove() usage lacked '__read_overflow2' symbol in lib/test_fortify/read_overflow2-memmove.c
> warning: unsafe memcpy() usage lacked '__write_overflow' symbol in lib/test_fortify/write_overflow-memcpy.c
> ...
>
> Sort this out by also defining __SANITIZE_ADDRESS__ in GCC under the
> hwaddress sanitizer.
>
> Suggested-by: Arnd Bergmann <arnd@arndb.de>
> Cc: Nathan Chancellor <nathan@kernel.org>
> Cc: Nick Desaulniers <ndesaulniers@google.com>
> Cc: Miguel Ojeda <ojeda@kernel.org>
> Cc: Andrew Morton <akpm@linux-foundation.org>
> Cc: Marco Elver <elver@google.com>
> Cc: Will Deacon <will@kernel.org>
> Cc: Arvind Sankar <nivedita@alum.mit.edu>
> Cc: Masahiro Yamada <masahiroy@kernel.org>
> Cc: llvm@lists.linux.dev
> Signed-off-by: Kees Cook <keescook@chromium.org>

Other than that,

  Reviewed-by: Marco Elver <elver@google.com>

Thanks!

> ---
> I'm intending to take this via my overflow series, since that is what introduces
> the compile-test regression tests (which found this legitimate bug). :)
>
> -Kees
> ---
>  include/linux/compiler-gcc.h | 8 ++++++++
>  1 file changed, 8 insertions(+)
>
> diff --git a/include/linux/compiler-gcc.h b/include/linux/compiler-gcc.h
> index 6f24eb8c5dda..ccbbd31b3aae 100644
> --- a/include/linux/compiler-gcc.h
> +++ b/include/linux/compiler-gcc.h
> @@ -121,6 +121,14 @@
>  #define __no_sanitize_coverage
>  #endif
>
> +/*
> + * Treat __SANITIZE_HWADDRESS__ the same as __SANITIZE_ADDRESS__ in the kernel,
> + * matching the defines used by Clang.
> + */
> +#ifdef __SANITIZE_HWADDRESS__
> +#define __SANITIZE_ADDRESS__
> +#endif
> +
>  /*
>   * Turn individual warnings and errors on and off locally, depending
>   * on version.
> --
> 2.30.2
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNMPaLpw_FoMzmShLSEBNq_Cn6t86tO_FiYLR2eD001%3D4Q%40mail.gmail.com.
