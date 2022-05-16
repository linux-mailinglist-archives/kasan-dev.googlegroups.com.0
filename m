Return-Path: <kasan-dev+bncBDBK55H2UQKRBOUJROKAMGQETXV6H5Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x138.google.com (mail-lf1-x138.google.com [IPv6:2a00:1450:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id B30C5529301
	for <lists+kasan-dev@lfdr.de>; Mon, 16 May 2022 23:40:11 +0200 (CEST)
Received: by mail-lf1-x138.google.com with SMTP id c15-20020a056512238f00b00473a118e7a7sf6975502lfv.18
        for <lists+kasan-dev@lfdr.de>; Mon, 16 May 2022 14:40:11 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1652737211; cv=pass;
        d=google.com; s=arc-20160816;
        b=1Ln4LtWE8smKoAQZIiutSNqUIqjdw0tP2Pn//xKm18sM+dN29i4PZrQuBdu2ik5gUr
         mTJ2F7Wu5Ze9pcbTKnzstEGFGxTYAUScV840ByAade8+Mao4rQkCx6QoPsa8exG/dO94
         KFOG5mLEalZeQHofuJd3lodY+O9ZLYakjEFnR9CJpvctaT9v4yXQtY5jimfb/2a9CqFs
         fJ5G5HJJIP7t9h8ILkzm/YzKX/uNxjZtwnDFG2icHCxEcf3UACabYDg1YgUVrf+y70rM
         Qd1zuVF0OR4nMZQlIbVwN+Effz5lWLpge2JMpQ1NAwcIpDdpVmSB1B9dvi2k4TTDGsKr
         yVaQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=Dlcqeyj1l6i9q/eUgVo1TE0WjM2fBWT6MenJP/lrqkk=;
        b=XKQUGfgtKwSfkUraGNefKWQu94nkBlxwpM4vJFFYPQdyuZbDtBD/TwKE3GrD521VtJ
         uWOD63qRZD+HUcnyaa9KYYJP+YfXZzgOxxbgQMFnHI6BUa5t1N0GzO2ml3fHj6Qf4jcg
         LLzCJ61/XqD3oJsfTI2Z+ciCPjl/mgdwKKIaSgDZftIsMlTRsiDV1nQflu3ITPRHlDiG
         VNwwrNFXRNnpDyxOFrbY2gGcLS8GTaiPu5rYd8IvDYWG7zVtXJcD5h28oMbU5wJm+JLx
         CncSHqkm201bbJGD5zudmzt5Ml/XiM4ylTR6Wu9+DAyPE1ecGY0JYYEdItvyFUm2FqSj
         3kew==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=OlCozzdR;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Dlcqeyj1l6i9q/eUgVo1TE0WjM2fBWT6MenJP/lrqkk=;
        b=aQQonJ0gFVMvYVSdO7d94ztMj3qBbrjf7kGJLaQNBNTHZmzDX3Taq0NQZgsA9UyVZk
         fOTPpJWxWzp//snVFyZDpg70v7RDIXSp6Fr9CCSXofZiphaR/r0x13b7JKl8Ula/dBd0
         SwF4CxD1t7ajqcEFrVWuuBoQ4nlkgARVOyYXF1x+SsgVJ62+PIlLWQVVY6hYGZWulgY/
         frvdVa27ZRUMUHY0Xcd36n/pexsRvf+V/ROX+EmJuDwnCYnxt/VwsNCy15beufli6wnr
         lGeMDLHc9/ghbh9FO3so70Q4KzwaeD05YU/bT5Nz4V1a6OFwwMQMSnJU/P77FU6lZepP
         gtVw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=Dlcqeyj1l6i9q/eUgVo1TE0WjM2fBWT6MenJP/lrqkk=;
        b=robcLQ8LRrDXq1hTlET8WYGGua6Azag0Ts0fQKeBffe+PCDWOa1aL+pUI1Ah3dOqps
         TAr4Jqc4sAHudOg8jUIIrBq3Or7G3VfNbfN4Ta9YZL0M6j2v0lv6R3Mm4me/NeLoNqYv
         g+iM0mj6KcEoE3/ZSNmhUfLJkXF7szp4SWZfDXYs+/V1AZiJ+xxB9JLoEgDnNKYRPPVK
         f/skahyejqeMqs5MA4xZ1q9rGptmZAHgw1c8ZtE1g5EiZwES80lpa3kJTz7qShWXohT4
         9w5tASi92saFjBSLQFNDFsmldrGk21ADM06AcBiCyqogKv/mLiiGqJAI62q3hi7iPNsJ
         oEag==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530ot2u7KCqYd8BylRVgOqONmwZGW27s6OBUoq2EZF9Mh0SUDBUH
	k/85pENnS8u22+Xv2OFIDSk=
X-Google-Smtp-Source: ABdhPJzLzWopEzrbmA1GlfyYRSj1wBNjOVYlvmWwEHF/zmZnPXQJDHzzGqqgEScgd9tJJ0tK8qKC6A==
X-Received: by 2002:a05:6512:1112:b0:473:a15b:fdf3 with SMTP id l18-20020a056512111200b00473a15bfdf3mr14002769lfg.155.1652737211068;
        Mon, 16 May 2022 14:40:11 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:bf11:0:b0:24a:fdc1:7af4 with SMTP id c17-20020a2ebf11000000b0024afdc17af4ls2715764ljr.1.gmail;
 Mon, 16 May 2022 14:40:09 -0700 (PDT)
X-Received: by 2002:a2e:a482:0:b0:253:b79f:2d87 with SMTP id h2-20020a2ea482000000b00253b79f2d87mr73609lji.498.1652737209522;
        Mon, 16 May 2022 14:40:09 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1652737209; cv=none;
        d=google.com; s=arc-20160816;
        b=ZnVpnv6PRgWPk2AzejKFcVCEVsYSv5WlX1emgMtcwc4t1LV0XD2HVr/daNaOKTbMGn
         nZecSdk6P8cwFkKjtSoCkjCSKPGWgo5lRGvAwKj0HVJFLSESnH/qTx4OPwfVLxfWSY8L
         hVmiKAh3BSqiPkda20bY6NetUXED+JReWbY7oFBIHTkgEL0XVu0SXIghBCmN4G9X6v3b
         gnIzOO8Y0JSyGBMm8BZyeINiUdl286yCMotbJUV4W2LIdwSrNzq7zEeUwpWdvxPlp76C
         Uck77tx2rS4SJQkg5D19BmuIcd56PRgJ2RoyiS+rC0VcGF+jfxZsc/6gp1eh2UcPPtxS
         pJNQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=aCb2HiewM12GOnx9FEdB6E4pX5NJT/HZCa9UT6fkVvk=;
        b=SQ6jsm1S0dUDWz0ja58+GP00ekyZzQcYqk6x/Nps/8kmop+ii11aTH39JJyibh0KjZ
         3xyCR1SWPKbMVWm0cElQZl+heZHDkzxpz+SrQrRb2TjW5od4lOpgufeeMB3LEnwd0/qz
         aqe3vaSAjayN/kPKpbTaEyF8LJg9/zPj8itxyISrFLi579cW5jY1oF/2HYhq7QudRRJT
         wzCgcHyGhNOrXjV1hBC7pHu20my851EZ+wraN21Md/vMjdh8IC/D/vis5jOxqafIGLOh
         KB/W8cF3ezErXSl2iLEuO8UfzNA0BeQh8bd9vijekE4N2fTB9LvAVXRflwiodjsDtJVz
         agRg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=OlCozzdR;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from desiato.infradead.org (desiato.infradead.org. [2001:8b0:10b:1:d65d:64ff:fe57:4e05])
        by gmr-mx.google.com with ESMTPS id x11-20020a2ea7cb000000b0024e33a076e7si369366ljp.2.2022.05.16.14.40.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 16 May 2022 14:40:09 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as permitted sender) client-ip=2001:8b0:10b:1:d65d:64ff:fe57:4e05;
Received: from j217100.upc-j.chello.nl ([24.132.217.100] helo=worktop.programming.kicks-ass.net)
	by desiato.infradead.org with esmtpsa (Exim 4.94.2 #2 (Red Hat Linux))
	id 1nqiRj-00120Q-1i; Mon, 16 May 2022 21:40:07 +0000
Received: by worktop.programming.kicks-ass.net (Postfix, from userid 1000)
	id 05E44980DCC; Mon, 16 May 2022 23:40:06 +0200 (CEST)
Date: Mon, 16 May 2022 23:40:05 +0200
From: Peter Zijlstra <peterz@infradead.org>
To: Nathan Chancellor <nathan@kernel.org>
Cc: Josh Poimboeuf <jpoimboe@kernel.org>,
	Nick Desaulniers <ndesaulniers@google.com>, llvm@lists.linux.dev,
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com
Subject: Re: objtool "no non-local symbols" error with tip of tree LLVM
Message-ID: <20220516214005.GQ76023@worktop.programming.kicks-ass.net>
References: <YoK4U9RgQ9N+HhXJ@dev-arch.thelio-3990X>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <YoK4U9RgQ9N+HhXJ@dev-arch.thelio-3990X>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=desiato.20200630 header.b=OlCozzdR;
       spf=pass (google.com: best guess record for domain of
 peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as
 permitted sender) smtp.mailfrom=peterz@infradead.org
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

On Mon, May 16, 2022 at 01:47:15PM -0700, Nathan Chancellor wrote:
> Hi Josh and Peter,
> 
> After a recent change in LLVM [1], I see warnings (errors?) from objtool
> when building x86_64 allmodconfig on 5.15 and 5.17:
> 
>   $ make -skj"$(nproc)" KCONFIG_ALLCONFIG=<(echo CONFIG_WERROR) LLVM=1 allmodconfig all
>   ...
>   mm/highmem.o: warning: objtool: no non-local symbols !?
>   mm/highmem.o: warning: objtool: gelf_update_symshndx: invalid section index
>   make[2]: *** [scripts/Makefile.build:288: mm/highmem.o] Error 255
>   ...
>   security/tomoyo/load_policy.o: warning: objtool: no non-local symbols !?
>   security/tomoyo/load_policy.o: warning: objtool: gelf_update_symshndx: invalid section index
>   make[3]: *** [scripts/Makefile.build:288: security/tomoyo/load_policy.o] Error 255
>   ...
> 
> I don't see the same errors on x86_64 allmodconfig on mainline so I
> bisected the 5.17 branch and came upon commit 4abff6d48dbc ("objtool:
> Fix code relocs vs weak symbols"). I wanted to see what 5.17 might be
> missing and came to commit ed53a0d97192 ("x86/alternative: Use
> .ibt_endbr_seal to seal indirect calls") in mainline, which I think just
> hides the issue for allmodconfig. I can reproduce this problem with a
> more selective set of config values on mainline:
> 
>   $ make -skj"$(nproc)" LLVM=1 defconfig
> 
>   $ scripts/config -e KASAN -e SECURITY_TOMOYO -e SECURITY_TOMOYO_OMIT_USERSPACE_LOADER
> 
>   $ make -skj"$(nproc)" LLVM=1 olddefconfig security/tomoyo/load_policy.o
>   security/tomoyo/load_policy.o: warning: objtool: no non-local symbols !?
>   security/tomoyo/load_policy.o: warning: objtool: gelf_update_symshndx: invalid section index
>   make[3]: *** [scripts/Makefile.build:288: security/tomoyo/load_policy.o] Error 255
>   ...
> 
> Looking at the object file, the '.text.asan.module_ctor' section has
> disappeared.
> 
> Before:
> 
>   $ llvm-nm -S security/tomoyo/load_policy.o
>   0000000000000000 0000000000000001 t asan.module_ctor
> 
>   $ llvm-readelf -s security/tomoyo/load_policy.o
> 
>   Symbol table '.symtab' contains 4 entries:
>      Num:    Value          Size Type    Bind   Vis       Ndx Name
>        0: 0000000000000000     0 NOTYPE  LOCAL  DEFAULT   UND
>        1: 0000000000000000     0 FILE    LOCAL  DEFAULT   ABS load_policy.c
>        2: 0000000000000000     0 SECTION LOCAL  DEFAULT     3 .text.asan.module_ctor
>        3: 0000000000000000     1 FUNC    LOCAL  DEFAULT     3 asan.module_ctor
> 
> After:
> 
>   $ llvm-nm -S security/tomoyo/load_policy.o
>   0000000000000000 0000000000000001 t asan.module_ctor
> 
>   $ llvm-readelf -s security/tomoyo/load_policy.o
> 
>   Symbol table '.symtab' contains 3 entries:
>      Num:    Value          Size Type    Bind   Vis       Ndx Name
>        0: 0000000000000000     0 NOTYPE  LOCAL  DEFAULT   UND
>        1: 0000000000000000     0 FILE    LOCAL  DEFAULT   ABS load_policy.c
>        2: 0000000000000000     1 FUNC    LOCAL  DEFAULT     3 asan.module_ctor
> 

The problem seems to be that we need to add a local symbols because LLVM
helpfully stripped all unused section symbols.

The way we do that, is by moving a the first non-local symbol to the
end, thereby creating a hole where we can insert a new local symbol.
Because ELF very helpfully mandates that local symbols must come before
non-local symbols and keeps the symbols index of the first non-local in
sh_info.

Thing is, the above object files don't appear to have a non-local symbol
so the swizzle thing isn't needed, and apparently the value in sh_info
isn't valid either.

Does something simple like this work? If not, I'll try and reproduce
tomorrow, it shouldn't be too hard to fix.

diff --git a/tools/objtool/elf.c b/tools/objtool/elf.c
index 583a3ec987b5..baabf38a2a11 100644
--- a/tools/objtool/elf.c
+++ b/tools/objtool/elf.c
@@ -618,8 +618,7 @@ static int elf_move_global_symbol(struct elf *elf, struct section *symtab,
 
 	sym = find_symbol_by_index(elf, first_non_local);
 	if (!sym) {
-		WARN("no non-local symbols !?");
-		return first_non_local;
+		return symtab->sh.sh_size / sizeof(sym->sym);
 	}
 
 	s = elf_getscn(elf->elf, symtab->idx);

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220516214005.GQ76023%40worktop.programming.kicks-ass.net.
