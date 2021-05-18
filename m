Return-Path: <kasan-dev+bncBDDL3KWR4EBRBDX2R6CQMGQECQWGPEQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x638.google.com (mail-pl1-x638.google.com [IPv6:2607:f8b0:4864:20::638])
	by mail.lfdr.de (Postfix) with ESMTPS id A88A2387EA4
	for <lists+kasan-dev@lfdr.de>; Tue, 18 May 2021 19:44:48 +0200 (CEST)
Received: by mail-pl1-x638.google.com with SMTP id t2-20020a170902b202b02900ec9b8c34b6sf4215174plr.15
        for <lists+kasan-dev@lfdr.de>; Tue, 18 May 2021 10:44:48 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1621359887; cv=pass;
        d=google.com; s=arc-20160816;
        b=qP1AztmK4+saVfhcCC4fzVghyjLB4n2c8EX5k00/BUKNnku7DZG3ikdIcxbGVxhVWk
         CTSUsAhH1xiJM7WKDkZyipR3ZvmGp8zGfYNpKrcX+EutHCyz1HaI5ADYZzznOBnZXumW
         ++QIZSkUI1tY97QCnT4umdcJ/X2kjoEm8N9rI4bnIApH97xknHLfwNWqdO3neEYxFyYu
         ScyioA0YVa4Gl2tL417IdAb4Bjv2JJSLEZM28Th7GJSCLjYKxXDTCO2AUV5lVx6ba6ht
         6qQ+OSNQ6YWcZDLfnh3Kjrt6CaEq1Uzl6C/D4kMVQiDpDxd1L+fGF/X1qizibysXEudh
         XJzA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=4gLdenzjjdnQZC+Bk39JL98am3ixKGA7sX+Gyy24ah4=;
        b=fSpO5YvM7VWhE2MclyBIEe/UZA0aJLlRi/4ceXyQuWsixjX7QiSjJGTX7fg+MIBMFp
         2dU8LxAbGRAEghBAIIRfJNSpmkqZzoQBUReY0o1RbPtxn5u7IeNH4vN3c+FirsYodMLU
         wZZ/yJae8rUJVXG5SNheDGNuGu6ezpqreCMgEwSz5CO07iZi4sUpIOh1hflSmPCwWQ/K
         FXAk+rxvBbELAq6b01N2r4iaRmzBOMJN2zpwWZXjjFtnnLlBbT/vKE7hsMcDs7lJwKJ5
         pbBcdVqiSYOAzpEQueZGCbW6rzrBN1xVuvBXVwGB6QON0aFM+gMyI2OV8EAoWbwAAqMY
         401g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=4gLdenzjjdnQZC+Bk39JL98am3ixKGA7sX+Gyy24ah4=;
        b=BzldsXrgElXgE3Ingr++SazyzvchOIDcN5zsPxPT4Fga1CJwlGu2wuKreyLBXXLweV
         Tqp9m6DhgZX8Q437cv937UYivcnLdeMXyAjILOAEvqSuOk/1QjmA/PX1OGHYnmeX21PQ
         DXkDYhHpGKLJQKeITLDah8TR2lq02TKoLEycbMfTI7Bvqwy3bQE/btx43JBtqP3k8Flb
         lQC3p5oL8fbCuOIbHAqgKdllc4XZ9haoVszgKo3IldowiJdS/38eEqrF2EWicfkizuAa
         vf4NOcdx/jYth5a0ACk9PF8ulV0mirAZFGpfpUAqupo+R65RFtJTCJnQjddBAY54iyXf
         o6IA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=4gLdenzjjdnQZC+Bk39JL98am3ixKGA7sX+Gyy24ah4=;
        b=fxmBHX/fvGnCIh8pQt2Ajhp++/n+K4J7UJRlhtzwWXxHoG5jTZWffHt4+wysbixodB
         evPTu5DR/GPw4UOnmiEPyXxb8XtmbtC+8H1YHr9zKoadBxjE78DXvNvzuXYz1zUN3WWJ
         a7S91bKbvSvl5amf2yuNpfrcy0qyfyUlZhc8gk5oW7NcL8oTMxi3u63Azi/J1oCio/sN
         w8H/2vEHrb8htiUnmfASceDQA6nevAjEHmnx500hOLCV3PdGg7ARmfcrOqCYqWkhoGnc
         qFB9cjey3p7z1PHUNUUUATPxPn5Rk95+vgFqMQfMmZAUV/0B01/Z7AEwnToknZ1F64qc
         3iDQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531VYHzqLCM7ic1fB12aJE6pm/5ndxSJNdCtuY6ZLOSMGVWAXmkK
	qPUauhCCaq9+hJZklgd+DjA=
X-Google-Smtp-Source: ABdhPJwbKkRUZMH3OtCHt1yfyvilSMkNnsWu/N4yvVLdI9XFyL6RzvimPUWFhTuMlkktAPGHLk9+Ug==
X-Received: by 2002:a17:90a:cc05:: with SMTP id b5mr6728641pju.6.1621359887028;
        Tue, 18 May 2021 10:44:47 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:314b:: with SMTP id x72ls9633352pgx.0.gmail; Tue, 18 May
 2021 10:44:46 -0700 (PDT)
X-Received: by 2002:aa7:87cd:0:b029:2dd:6873:513c with SMTP id i13-20020aa787cd0000b02902dd6873513cmr6310359pfo.71.1621359886403;
        Tue, 18 May 2021 10:44:46 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1621359886; cv=none;
        d=google.com; s=arc-20160816;
        b=az+Jl/pQeqv8A/unJ3uyrCruiR3+JZ2M6YaQT/11Zc3eirpw1pO5ApSttYjZnHm+0F
         i7aSaz2ORv126emnFNvG8qztnP7rKmx/ti0aHYIQsOQtSnF6T2i3WWixmpQ3tMAWFzFX
         ZApz3J6ImQLI4JfS2oUIAbPArusdAmOgL+uhNk988pmjsbRt/yvW/7uUTrg/poO50bo6
         babGR94Ag8DJDG/29HDrBcBW955SriYR7DUSHF+CmB+Cvq7NMHwM9WeuNtZuAk6lr4z5
         8IZTIbSmvF5cZjTE//b4FU0y456sh6oMrTQ/SWNDNluPc073cP3enDyIzSop4TPJz1zD
         190g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=wuxPTrK9DOhkzhVCi+qYhkm91DwVqK/O8iAsvQU2f9w=;
        b=mXj8mdMCX+UBUjz0rOQwNIs9+VGYGh165luTGHdNxZ7/bf03owprQ6KS2Toe0tMzyt
         ZadXSf7oj0CA5W7pwRP/NsCqtUgGfvyQw58U23l1gW/A6KPnxYcckItcpaYJ6vlfNRE8
         3yU+0/opHGKLDlXM0ov1Jq7OWd6HarorP8r0+/QC7S89B5njpWM/h14PCqJU75KE7ckW
         gDCPPn7mxIsvn29JKa5GggnQjzG7g4sun6EdPRw2O1n/z/0E6w3K7g0rTztFIiaiaWIz
         aT/Aj2he/6hne1/ZrCFqFFbDiQ871+fzCOhuAHZx6cRvB85ooFJqOGcBieeTTcG4ABmO
         Ickw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id u24si1652012plq.4.2021.05.18.10.44.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 18 May 2021 10:44:46 -0700 (PDT)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 4302A611AC;
	Tue, 18 May 2021 17:44:44 +0000 (UTC)
Date: Tue, 18 May 2021 18:44:41 +0100
From: Catalin Marinas <catalin.marinas@arm.com>
To: Evgenii Stepanov <eugenis@google.com>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>, Will Deacon <will@kernel.org>,
	Steven Price <steven.price@arm.com>,
	Peter Collingbourne <pcc@google.com>, kasan-dev@googlegroups.com,
	linux-arm-kernel@lists.infradead.org, linux-kernel@vger.kernel.org
Subject: Re: [PATCH v3] kasan: speed up mte_set_mem_tag_range
Message-ID: <20210518174439.GA28491@arm.com>
References: <20210517235546.3038875-1-eugenis@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20210517235546.3038875-1-eugenis@google.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: catalin.marinas@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as
 permitted sender) smtp.mailfrom=cmarinas@kernel.org;       dmarc=fail (p=NONE
 sp=NONE dis=NONE) header.from=arm.com
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

On Mon, May 17, 2021 at 04:55:46PM -0700, Evgenii Stepanov wrote:
> Use DC GVA / DC GZVA to speed up KASan memory tagging in HW tags mode.
> 
> The first cacheline is always tagged using STG/STZG even if the address is
> cacheline-aligned, as benchmarks show it is faster than a conditional
> branch.
[...]
> diff --git a/arch/arm64/include/asm/mte-kasan.h b/arch/arm64/include/asm/mte-kasan.h
> index ddd4d17cf9a0..e29a0e2ab35c 100644
> --- a/arch/arm64/include/asm/mte-kasan.h
> +++ b/arch/arm64/include/asm/mte-kasan.h
> @@ -48,45 +48,7 @@ static inline u8 mte_get_random_tag(void)
>  	return mte_get_ptr_tag(addr);
>  }
>  
> -/*
> - * Assign allocation tags for a region of memory based on the pointer tag.
> - * Note: The address must be non-NULL and MTE_GRANULE_SIZE aligned and
> - * size must be non-zero and MTE_GRANULE_SIZE aligned.
> - */
> -static inline void mte_set_mem_tag_range(void *addr, size_t size,
> -						u8 tag, bool init)

With commit 2cb34276427a ("arm64: kasan: simplify and inline MTE
functions") you wanted this inlined for performance. Does this not
matter much that it's now out of line?

> diff --git a/arch/arm64/lib/Makefile b/arch/arm64/lib/Makefile
> index d31e1169d9b8..c06ada79a437 100644
> --- a/arch/arm64/lib/Makefile
> +++ b/arch/arm64/lib/Makefile
> @@ -18,3 +18,5 @@ obj-$(CONFIG_CRC32) += crc32.o
>  obj-$(CONFIG_FUNCTION_ERROR_INJECTION) += error-inject.o
>  
>  obj-$(CONFIG_ARM64_MTE) += mte.o
> +
> +obj-$(CONFIG_KASAN_HW_TAGS) += mte-kasan.o
> diff --git a/arch/arm64/lib/mte-kasan.S b/arch/arm64/lib/mte-kasan.S
> new file mode 100644
> index 000000000000..9f6975e2af60
> --- /dev/null
> +++ b/arch/arm64/lib/mte-kasan.S
> @@ -0,0 +1,63 @@
> +/* SPDX-License-Identifier: GPL-2.0-only */
> +/*
> + * Copyright (C) 2021 Google Inc.
> + */
> +#include <linux/const.h>
> +#include <linux/linkage.h>
> +
> +#include <asm/mte-def.h>
> +
> +	.arch	armv8.5-a+memtag
> +
> +	.macro  __set_mem_tag_range, stg, gva, start, size, linesize, tmp1, tmp2, tmp3
> +	add	\tmp3, \start, \size
> +	cmp	\size, \linesize, lsl #1
> +	b.lt	.Lsmtr3_\@

We could do with some comments here. Why the lsl #1? I think I get it
but it would be good to make this more readable.

It may be easier if you placed it in a file on its own (as it is now but
with a less generic file name) and use a few .req instead of the tmpX.
You can use the macro args only for the stg/gva.

> +
> +	sub	\tmp1, \linesize, #1
> +	bic	\tmp2, \tmp3, \tmp1
> +	orr	\tmp1, \start, \tmp1
> +
> +.Lsmtr1_\@:
> +	\stg	\start, [\start], #MTE_GRANULE_SIZE
> +	cmp	\start, \tmp1
> +	b.lt	.Lsmtr1_\@
> +
> +.Lsmtr2_\@:
> +	dc	\gva, \start
> +	add	\start, \start, \linesize
> +	cmp	\start, \tmp2
> +	b.lt	.Lsmtr2_\@
> +
> +.Lsmtr3_\@:
> +	cmp	\start, \tmp3
> +	b.ge	.Lsmtr4_\@
> +	\stg	\start, [\start], #MTE_GRANULE_SIZE
> +	b	.Lsmtr3_\@
> +.Lsmtr4_\@:
> +	.endm

If we want to get the best performance out of this, we should look at
the memset implementation and do something similar. In principle it's
not that far from a memzero, though depending on the microarchitecture
it may behave slightly differently.

Anyway, before that I wonder if we wrote all this in C + inline asm
(three while loops or maybe two and some goto), what's the performance
difference? It has the advantage of being easier to maintain even if we
used some C macros to generate gva/gzva variants.

-- 
Catalin

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210518174439.GA28491%40arm.com.
