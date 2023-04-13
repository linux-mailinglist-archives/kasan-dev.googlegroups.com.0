Return-Path: <kasan-dev+bncBDDL3KWR4EBRBU444CQQMGQEOUHUUXI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3d.google.com (mail-oa1-x3d.google.com [IPv6:2001:4860:4864:20::3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 0D6736E0FBC
	for <lists+kasan-dev@lfdr.de>; Thu, 13 Apr 2023 16:14:45 +0200 (CEST)
Received: by mail-oa1-x3d.google.com with SMTP id 586e51a60fabf-1842e8a9b8bsf8056085fac.16
        for <lists+kasan-dev@lfdr.de>; Thu, 13 Apr 2023 07:14:44 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1681395283; cv=pass;
        d=google.com; s=arc-20160816;
        b=k6c6i3t5m7LVoKch2/lpzeMuZgTBJoSx4k+nG9rkJc4E3r7E4HnDhffjlqEe9usFOW
         ArroIdQFBiG1lEMm/EWsW/3ZXcswaJtZsCbD37V9N2rpkbr7ANckMiwXrd82cMWlU8SL
         ZuatiSM9nhjYp8ctNw/ZuIQkTUZFD213B8Mjxl+ClBOd6MjOAYYPBTdEHeBVcZT5ZeQQ
         B/xHmcwBUdXv+NysQpH7LwAllEbJCkhDYWZr+IeGJ2g28SDJh4BQCKdn7qQLmEx9uHUN
         n/Wi+GwxB5XFcfDaa4tEmFzvtAr5j5IcSrWsoaHgFQiOU0WiSSgYS9B5U4Pkk2P45VnA
         iC4g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=lslDEVfUOOIsB6hs/8vrRbGBwo5M8mcpNdyGrwWIr7E=;
        b=EBo4joeXyRiwUDGFk6ik1WY2F5LvtANtc0N09VVR8bscFXkFCkHlLk5CMrKPxmyQ8l
         6E6855csWdQp3OE0wGxwvvNyomuF9smsPw9mQHye3SOVc/rM0g/J/hffXxarxSzyWv6O
         JpH2/z6bCGh/dCP6xP57cIoOH6w34aey0ZXsZZ68Bnt/R0rBV1X9jx856TQMToENAcs0
         TEbw8ucm0W0w6g2tSakyuYDzTlbTooUzohk/h0WJU/kRKTH6QxrWawMHwLJadCJlA5qy
         X5toakOtVreg72NisEdY+ltA79jLaazU2QhuqeeJ0UaNrZBCyT53vk9V2rMgpqpzjh67
         /S/A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1681395283; x=1683987283;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=lslDEVfUOOIsB6hs/8vrRbGBwo5M8mcpNdyGrwWIr7E=;
        b=dU30fJ6mUNceXBSjR9q+lePQk3Q+PWH/cQfMHTIstGg9GGrtWgfmLavTpCZ1vxbnlD
         fYfBDnUGE7i81TVQpQ5Fs3EKJ85MpNRgOo+bMdFQneSaj8KAm/hk4JL5vugLoGUBBSy/
         xkbHlF73S/Hm0g9lyzAeHb0yPCiDYkJ7YMNwi2GyRa5kmeR5YP2cPm4adJu8He39InI5
         bxrXQxasPAnyfApwWKXa/zRSu/a2o0qNAtYCJgS2NAePVS5dV9pZ1GPonzHCjZofpeTF
         dtkGIqRP1F4v84JlvM+B1/Fg0rSG+KzofeFkpSDG04ZoHergR4GXoFa/UvUh44Hv4AUZ
         OQ2Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1681395283; x=1683987283;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=lslDEVfUOOIsB6hs/8vrRbGBwo5M8mcpNdyGrwWIr7E=;
        b=feY3xGkEY7UMEoGxZmlTck2IFgq//Z/riMfMarF6ub6kWxpQAXXbc5rjaW8Ctu6prF
         2LVfkF1X29Wu23A7bF95lZYA25+AmVlU3Af70Km/adDm6Jp3efKNE1aTxO7dYCx4wiDe
         plLAQuiOHOKuKC0keT3VbqPY6Wuo8VWCOW0mlbMw0DgZE9cUScnPe6madFeRhd8UkNru
         11z+S3ZL/2cn8w2l4TmQkwfHWcDcagHUDS2Y4pq7WT+mkBA2J/Qa3YOHEXIMO8nG52OX
         dgnsGWQ0kjg9IUoqicfWWWY70u2EZharHeMACAwnVeJrFBGmkJLVayh8a4xuvICuElod
         zIYQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AAQBX9dSFMkys1UsAUXLl1tbH6f6oQ1VB4/z2AWeOQv1Fb6RZC3R+oJ+
	jzMjHkqas2nmP3/mriHeLDI=
X-Google-Smtp-Source: AKy350am9vj/VyFWpqmu5Z7qvmquU5LyYRKyeI6/MKvaxKaVjrPwQinONBrC3BA6yio+AprKtpuO9w==
X-Received: by 2002:a05:6870:2e0e:b0:187:7524:9a8d with SMTP id oi14-20020a0568702e0e00b0018775249a8dmr2432275oab.4.1681395283691;
        Thu, 13 Apr 2023 07:14:43 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:631b:b0:69f:7d7b:d8f6 with SMTP id
 cg27-20020a056830631b00b0069f7d7bd8f6ls7311300otb.4.-pod-prod-gmail; Thu, 13
 Apr 2023 07:14:43 -0700 (PDT)
X-Received: by 2002:a05:6830:1d43:b0:69f:8f44:88fc with SMTP id p3-20020a0568301d4300b0069f8f4488fcmr1122283oth.2.1681395283179;
        Thu, 13 Apr 2023 07:14:43 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1681395283; cv=none;
        d=google.com; s=arc-20160816;
        b=Y2SFXpmoDocUyQ76yGYmqIE/x4TxqyllNNwSCa1Mf6lVw5GtmSW9/z36eam59wFGOz
         WmbU5R8hdAUttu1yRO8wJFqvwU25XxrLXBNuLxZxLvrGpvp5v8v+RaDn2vqbxingyCnF
         upEF6qZ/LHbx4Qqlb1My+NTXICTRyVU+4camjg1POP9/9Z0ee6zWJOgWHWPvSAq6q/4z
         dVEsVD2rv+0nFfM8M3W1sLeXUBG8M0X/6oJnNywlJJ8pNLfYywc7mvvAyBo/jiPN51pC
         QMomOAYPEB8ZTmrKwU7s/1aziOiRJ8lI7o1d59UyRRbkUF7sLkeRxLJ+bpr4mKOD2i4D
         zijQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date;
        bh=K8Xp8/10Q92bDICwHbvc86vpZdIufpZjmPKC79E8wAE=;
        b=mY7L2BmCln2dD58uO9DioH64svtEF8VWamgr2ojd1o7j5T/dFU8f0SAygcoX202CAF
         MSZWgPl+Dhfh+4remBL++Q0Z5XmnaoVFEeLzW/wGJm3DvQyq8S3xvW13CZ4uYLgafqUR
         uJFiJjy+yPVeOX+Gy2dQ4uCRPznqC22YbOmJQYsYffCM8pCOe0AEFg2egd+oFcDcILrt
         bPCI2dmb78OXCdUVNNFNKhgUez+NnL2E4TUwkS3KAkP29zH8tdf6MCeR1qvrczz5o8Te
         eLF5Of+xqn/FTOOUEipKwhp3nAKDSe4lAnzRcPrncec0tLIOMEVKPZ5ZpVnOQ3vVb0Dj
         Ke2g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id bk19-20020a056830369300b006a12b6325c7si204437otb.4.2023.04.13.07.14.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 13 Apr 2023 07:14:43 -0700 (PDT)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id 652DD63EE0;
	Thu, 13 Apr 2023 14:14:42 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 76A3DC433EF;
	Thu, 13 Apr 2023 14:14:37 +0000 (UTC)
Date: Thu, 13 Apr 2023 15:14:34 +0100
From: Catalin Marinas <catalin.marinas@arm.com>
To: Marco Elver <elver@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>,
	Peter Zijlstra <peterz@infradead.org>,
	Jakub Jelinek <jakub@redhat.com>, linux-toolchains@vger.kernel.org,
	Alexander Potapenko <glider@google.com>,
	Thomas Gleixner <tglx@linutronix.de>,
	Ingo Molnar <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>,
	Dave Hansen <dave.hansen@linux.intel.com>, x86@kernel.org,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Nathan Chancellor <nathan@kernel.org>,
	Nick Desaulniers <ndesaulniers@google.com>,
	Nicolas Schier <nicolas@fjasle.eu>,
	Kees Cook <keescook@chromium.org>, linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com, linux-mm@kvack.org,
	linux-kbuild@vger.kernel.org, linux-hardening@vger.kernel.org,
	Linux Kernel Functional Testing <lkft@linaro.org>,
	Naresh Kamboju <naresh.kamboju@linaro.org>
Subject: Re: [PATCH v5 1/4] kasan: Emit different calls for instrumentable
 memintrinsics
Message-ID: <ZDgOSp30Ec00u8wP@arm.com>
References: <20230224085942.1791837-1-elver@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20230224085942.1791837-1-elver@google.com>
X-Original-Sender: catalin.marinas@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of cmarinas@kernel.org designates 2604:1380:4641:c500::1
 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;       dmarc=fail
 (p=NONE sp=NONE dis=NONE) header.from=arm.com
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

Hi Marco,

On Fri, Feb 24, 2023 at 09:59:39AM +0100, Marco Elver wrote:
> Clang 15 provides an option to prefix memcpy/memset/memmove calls with
> __asan_/__hwasan_ in instrumented functions: https://reviews.llvm.org/D122724
> 
> GCC will add support in future:
> https://gcc.gnu.org/bugzilla/show_bug.cgi?id=108777
> 
> Use it to regain KASAN instrumentation of memcpy/memset/memmove on
> architectures that require noinstr to be really free from instrumented
> mem*() functions (all GENERIC_ENTRY architectures).
> 
> Fixes: 69d4c0d32186 ("entry, kasan, x86: Disallow overriding mem*() functions")
> Signed-off-by: Marco Elver <elver@google.com>
> Acked-by: Peter Zijlstra (Intel) <peterz@infradead.org>
> Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>
> Tested-by: Linux Kernel Functional Testing <lkft@linaro.org>
> Tested-by: Naresh Kamboju <naresh.kamboju@linaro.org>
[...]
> diff --git a/scripts/Makefile.kasan b/scripts/Makefile.kasan
> index b9e94c5e7097..fa9f836f8039 100644
> --- a/scripts/Makefile.kasan
> +++ b/scripts/Makefile.kasan
> @@ -38,6 +38,11 @@ endif
>  
>  CFLAGS_KASAN += $(call cc-param,asan-stack=$(stack_enable))
>  
> +# Instrument memcpy/memset/memmove calls by using instrumented __asan_mem*()
> +# instead. With compilers that don't support this option, compiler-inserted
> +# memintrinsics won't be checked by KASAN on GENERIC_ENTRY architectures.
> +CFLAGS_KASAN += $(call cc-param,asan-kernel-mem-intrinsic-prefix=1)
> +
>  endif # CONFIG_KASAN_GENERIC
>  
>  ifdef CONFIG_KASAN_SW_TAGS
> @@ -54,6 +59,9 @@ CFLAGS_KASAN := -fsanitize=kernel-hwaddress \
>  		$(call cc-param,hwasan-inline-all-checks=0) \
>  		$(instrumentation_flags)
>  
> +# Instrument memcpy/memset/memmove calls by using instrumented __hwasan_mem*().
> +CFLAGS_KASAN += $(call cc-param,hwasan-kernel-mem-intrinsic-prefix=1)

This patch breaks the arm64 kernel builds with KASAN_SW_TAGS enabled and
clang prior to version 15. Those prior clang versions don't like the
'-mllvm -hwasan-kernel-mem-intrinsic-prefix=1' option, end up printing
the help text instead of generating the object.

Do we need some combination of cc-option and cc-param? Or at least
disable this instrumentation if earlier clang versions are used.

It's already in mainline as commit
51287dcb00cc715c27bf6a6b4dbd431621c5b65a.

Thanks.

-- 
Catalin

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZDgOSp30Ec00u8wP%40arm.com.
