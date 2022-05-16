Return-Path: <kasan-dev+bncBD4NDKWHQYDRBWVJROKAMGQEL37OFRQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x40.google.com (mail-oa1-x40.google.com [IPv6:2001:4860:4864:20::40])
	by mail.lfdr.de (Postfix) with ESMTPS id 8F9435293C9
	for <lists+kasan-dev@lfdr.de>; Tue, 17 May 2022 00:48:59 +0200 (CEST)
Received: by mail-oa1-x40.google.com with SMTP id 586e51a60fabf-ee13d04a02sf10310072fac.3
        for <lists+kasan-dev@lfdr.de>; Mon, 16 May 2022 15:48:59 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1652741338; cv=pass;
        d=google.com; s=arc-20160816;
        b=o6/VyjzGzTyWWE2ObPqhoLOBnYa5Micue5h3aZ4tTwf7khXtzDhxsApkMdDjWMkY4g
         lp2GWQf26/mI+hR5253NemhYFzHj6DvNK3HCofpth2bgd0JrKtWaeWzsUpg0SiMtXq/g
         iLNvaxrW23UTRPu1o986idSyGZloYQb4fSlOEm9yoIiXbSy7ToAXUp7HQO69o4GknD3H
         Ae9XTk2qYQ31rkDx5rBkPdzzaNHcCJQTLeNK7db1lZAOHmrB7a8Ysgmvv1rqKkb7PxqL
         ke4W0ag9KAlqu8T/bwXIyatAU7kj5bZ3+GE45Jyz0cP13oiTaNNAfkg2ZKUC7grFgKYo
         4e+w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=C2Ryj2p7mufE6Pnvyn2Bv4lmp4Cyv04CB6SWEh+5y/c=;
        b=X0LzMOXJ3KI/wp2WLadc0krXZy1iduvvlHOrJd3w+ZcZTTmCf6PfQrhFpys0lUqsRl
         TaXQtxzvsel00XkXLTTOc98OySDeBximmQSp0JoUWtq8Rkb9UiI3mg2FhTe5RLHl45jC
         tIoiYTq0cIJ/NuaECfBvVB87ByOtSVhJltLQUSBn+pCodCufRJ3fDsNFXdxo9Bb9FImv
         +47Sj3zBZJcSri7THm/UoA6QaMSdI65XlkASn4hiafoegADCrmZ78tF5qBb4dkrEwEGs
         qEJZlnQ+oW0wlJ/HysqhOLzhS17KrKVhW/4jG3gH/+X7wWjYOnGizaDirlKmWySAXLu6
         H7AA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=tWnzV72+;
       spf=pass (google.com: domain of nathan@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=nathan@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=C2Ryj2p7mufE6Pnvyn2Bv4lmp4Cyv04CB6SWEh+5y/c=;
        b=imiAUqJ0HSDtEP9YMe/wVMGdOC0acG43o4Hc53meb2pV/xWs/IcE4oWe1wjj7LwRlQ
         WA0RGi45BwumhLlOhHLNgYkxPy8q/4pICjEtT0Mj0xKpNWxxumZcXP3ZSazK6FSnAM7t
         ejei6XDNI3VXq4d0/0vSQjg9GA1hInyyOBMfmJ00SfEosw04+/F1Xcu27E52q4178lZ1
         czXSnsaLgRBZops87zjudZ5XU/IK5cRgFdxS5BWnHwsfh1fjVr6TLhFyGBTpUhGDYkmh
         9XflxxYwab+MXWnUbR2f26hr5WBzcAScpKM+Ud3fqUH9aCxSiDL31DUfrL1W4eMW/pri
         IPow==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=C2Ryj2p7mufE6Pnvyn2Bv4lmp4Cyv04CB6SWEh+5y/c=;
        b=Rpfa3qzFDi1d6jvLJCHVPCa+0BExrWGMKxF/G2U4NCdkiGBXaC8FpU4iPpXjs9NJHV
         f/lkKx+gtkbnJiri7lXwJtyGYf8hEMe7iOd61/NwJjqEVqaYAMrpGSf/YeWBI0xW9bu3
         PFsypJAN363sQC53r0t/m0dtmtaiUv/7w/yvRetFgA+erXXpqGyKACIT2AVNPqRMzHx/
         f7xlM4CbJE8e4ouMrNgqggpOvDNJs7rP0dKQw1b3uzGraw0XgQjAuoYICLFkTbOTDhJS
         MnQV63kxMBhD5r6tMfN46gOR8uRoEZ6zIgssoHwvr87Ns4Qo081xjlm0kZB6OQB+j37s
         RwGg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533NCEECxaz2Py4RgaVp/bOyRbbp8L7kx5Jier+cAo71qmqFxeRI
	h4D46BB4xQcVyxhZCAtAb3I=
X-Google-Smtp-Source: ABdhPJyPQOoWv9tF5Z3LS4Jc9BdKciI7kloSKHACq8y+3n8hoAhfRz0Wc50TL5oX2sdnqRA5Z0R8qw==
X-Received: by 2002:a05:6870:231b:b0:db:a2b3:cff7 with SMTP id w27-20020a056870231b00b000dba2b3cff7mr16166637oao.244.1652741338334;
        Mon, 16 May 2022 15:48:58 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6808:1703:b0:322:76c2:8923 with SMTP id
 bc3-20020a056808170300b0032276c28923ls6344654oib.9.gmail; Mon, 16 May 2022
 15:48:58 -0700 (PDT)
X-Received: by 2002:a05:6808:ec7:b0:322:2bcc:42c2 with SMTP id q7-20020a0568080ec700b003222bcc42c2mr14562430oiv.168.1652741337968;
        Mon, 16 May 2022 15:48:57 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1652741337; cv=none;
        d=google.com; s=arc-20160816;
        b=CmBsmTuGLWrZTdV1VgdQv0iwNBOZ4VJdc0THh1V6fCWYMmt9ZPD4Xc77VgCDg0DVDv
         YCY0eqNcv3WvQGTucof3zEVfjHJwdLfk046WAZV18I5RDEaFUyz5viNuyublddJvcwgx
         1y9BomvShQL33w1ydt0Wle2AGO2FNcAcvuQwpnEIjeJn8wGO3rBwYbNE6psYb0I3dMl5
         9uSiqFY5geNiGVL4DXsjA0WOO+PcfCO8xAs0qJK57/eZUzgNo4zEthruGyBL9bgNXZXe
         dw/Qr5AcVSXdyXtieGs9YaD8QcD0WOMuWcu4nbTZUzZl5K1yxWEX9vjViRciG69CV7lu
         niDQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=WPP3vgGzAne++4UwguxPW7uB+dAusGVUMl4zlsh8pCk=;
        b=kpblFAgNXQguHGsYzZHBga3cxIm6IfKydAuxIg8kZXjlvC4iDThMOCJYU7yJrcNltc
         2Vo7LyzePr1IpnCtCZcbNteiGOlXhx0XsMND6BKnAjKei1EjQXFBCBVAd0/gRIydATrb
         ij3c2sqXtPVqeOD2GgJde3GJ2e4tB7a/lpv1b7yMruSrSpAwfQryqCgfVn3aFPmU69Av
         AciSXO5H/fFoh4RkdpMa1hVaCUF/M13u4BIDHOFV2cx1M9W6qkdhFs3eTlFhwwVnmpiv
         Jq8BEFl99RNrBYhBSYfR9zr15q8QbgU7HOExb4aovpgi9TOQoJ2CS1ygXQCOsA7SvfwI
         wJyg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=tWnzV72+;
       spf=pass (google.com: domain of nathan@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=nathan@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id el40-20020a056870f6a800b000e2f2a83479si1397531oab.1.2022.05.16.15.48.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 16 May 2022 15:48:57 -0700 (PDT)
Received-SPF: pass (google.com: domain of nathan@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id B541960B6C;
	Mon, 16 May 2022 22:48:57 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id BE8A5C385B8;
	Mon, 16 May 2022 22:48:56 +0000 (UTC)
Date: Mon, 16 May 2022 15:48:55 -0700
From: Nathan Chancellor <nathan@kernel.org>
To: Peter Zijlstra <peterz@infradead.org>
Cc: Josh Poimboeuf <jpoimboe@kernel.org>,
	Nick Desaulniers <ndesaulniers@google.com>, llvm@lists.linux.dev,
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com
Subject: Re: objtool "no non-local symbols" error with tip of tree LLVM
Message-ID: <YoLU10rW+EZCDEfI@dev-arch.thelio-3990X>
References: <YoK4U9RgQ9N+HhXJ@dev-arch.thelio-3990X>
 <20220516214005.GQ76023@worktop.programming.kicks-ass.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20220516214005.GQ76023@worktop.programming.kicks-ass.net>
X-Original-Sender: nathan@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=tWnzV72+;       spf=pass
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

On Mon, May 16, 2022 at 11:40:05PM +0200, Peter Zijlstra wrote:
> On Mon, May 16, 2022 at 01:47:15PM -0700, Nathan Chancellor wrote:
> > Hi Josh and Peter,
> > 
> > After a recent change in LLVM [1], I see warnings (errors?) from objtool
> > when building x86_64 allmodconfig on 5.15 and 5.17:
> > 
> >   $ make -skj"$(nproc)" KCONFIG_ALLCONFIG=<(echo CONFIG_WERROR) LLVM=1 allmodconfig all
> >   ...
> >   mm/highmem.o: warning: objtool: no non-local symbols !?
> >   mm/highmem.o: warning: objtool: gelf_update_symshndx: invalid section index
> >   make[2]: *** [scripts/Makefile.build:288: mm/highmem.o] Error 255
> >   ...
> >   security/tomoyo/load_policy.o: warning: objtool: no non-local symbols !?
> >   security/tomoyo/load_policy.o: warning: objtool: gelf_update_symshndx: invalid section index
> >   make[3]: *** [scripts/Makefile.build:288: security/tomoyo/load_policy.o] Error 255
> >   ...
> > 
> > I don't see the same errors on x86_64 allmodconfig on mainline so I
> > bisected the 5.17 branch and came upon commit 4abff6d48dbc ("objtool:
> > Fix code relocs vs weak symbols"). I wanted to see what 5.17 might be
> > missing and came to commit ed53a0d97192 ("x86/alternative: Use
> > .ibt_endbr_seal to seal indirect calls") in mainline, which I think just
> > hides the issue for allmodconfig. I can reproduce this problem with a
> > more selective set of config values on mainline:
> > 
> >   $ make -skj"$(nproc)" LLVM=1 defconfig
> > 
> >   $ scripts/config -e KASAN -e SECURITY_TOMOYO -e SECURITY_TOMOYO_OMIT_USERSPACE_LOADER
> > 
> >   $ make -skj"$(nproc)" LLVM=1 olddefconfig security/tomoyo/load_policy.o
> >   security/tomoyo/load_policy.o: warning: objtool: no non-local symbols !?
> >   security/tomoyo/load_policy.o: warning: objtool: gelf_update_symshndx: invalid section index
> >   make[3]: *** [scripts/Makefile.build:288: security/tomoyo/load_policy.o] Error 255
> >   ...
> > 
> > Looking at the object file, the '.text.asan.module_ctor' section has
> > disappeared.
> > 
> > Before:
> > 
> >   $ llvm-nm -S security/tomoyo/load_policy.o
> >   0000000000000000 0000000000000001 t asan.module_ctor
> > 
> >   $ llvm-readelf -s security/tomoyo/load_policy.o
> > 
> >   Symbol table '.symtab' contains 4 entries:
> >      Num:    Value          Size Type    Bind   Vis       Ndx Name
> >        0: 0000000000000000     0 NOTYPE  LOCAL  DEFAULT   UND
> >        1: 0000000000000000     0 FILE    LOCAL  DEFAULT   ABS load_policy.c
> >        2: 0000000000000000     0 SECTION LOCAL  DEFAULT     3 .text.asan.module_ctor
> >        3: 0000000000000000     1 FUNC    LOCAL  DEFAULT     3 asan.module_ctor
> > 
> > After:
> > 
> >   $ llvm-nm -S security/tomoyo/load_policy.o
> >   0000000000000000 0000000000000001 t asan.module_ctor
> > 
> >   $ llvm-readelf -s security/tomoyo/load_policy.o
> > 
> >   Symbol table '.symtab' contains 3 entries:
> >      Num:    Value          Size Type    Bind   Vis       Ndx Name
> >        0: 0000000000000000     0 NOTYPE  LOCAL  DEFAULT   UND
> >        1: 0000000000000000     0 FILE    LOCAL  DEFAULT   ABS load_policy.c
> >        2: 0000000000000000     1 FUNC    LOCAL  DEFAULT     3 asan.module_ctor
> > 
> 
> The problem seems to be that we need to add a local symbols because LLVM
> helpfully stripped all unused section symbols.
> 
> The way we do that, is by moving a the first non-local symbol to the
> end, thereby creating a hole where we can insert a new local symbol.
> Because ELF very helpfully mandates that local symbols must come before
> non-local symbols and keeps the symbols index of the first non-local in
> sh_info.
> 
> Thing is, the above object files don't appear to have a non-local symbol
> so the swizzle thing isn't needed, and apparently the value in sh_info
> isn't valid either.
> 
> Does something simple like this work? If not, I'll try and reproduce
> tomorrow, it shouldn't be too hard to fix.

That diff obviously gets rid of the "no non-local symbols" message but I
still see the "invalid section index" message. I'll be offline tomorrow
but if you have issues reproducing it, I'll be happy to help on
Wednesday. At the time I am writing this, apt.llvm.org packages have not
been updated to include that LLVM change I mentioned; hopefully they
will be soon.

Thanks for the quick response!
Nathan

> diff --git a/tools/objtool/elf.c b/tools/objtool/elf.c
> index 583a3ec987b5..baabf38a2a11 100644
> --- a/tools/objtool/elf.c
> +++ b/tools/objtool/elf.c
> @@ -618,8 +618,7 @@ static int elf_move_global_symbol(struct elf *elf, struct section *symtab,
>  
>  	sym = find_symbol_by_index(elf, first_non_local);
>  	if (!sym) {
> -		WARN("no non-local symbols !?");
> -		return first_non_local;
> +		return symtab->sh.sh_size / sizeof(sym->sym);
>  	}
>  
>  	s = elf_getscn(elf->elf, symtab->idx);
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YoLU10rW%2BEZCDEfI%40dev-arch.thelio-3990X.
