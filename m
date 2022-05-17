Return-Path: <kasan-dev+bncBD4NDKWHQYDRBE66R6KAMGQEWP3N7II@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x63e.google.com (mail-ej1-x63e.google.com [IPv6:2a00:1450:4864:20::63e])
	by mail.lfdr.de (Postfix) with ESMTPS id DF78352AB3D
	for <lists+kasan-dev@lfdr.de>; Tue, 17 May 2022 20:53:27 +0200 (CEST)
Received: by mail-ej1-x63e.google.com with SMTP id ga27-20020a1709070c1b00b006f43c161da4sf7810118ejc.7
        for <lists+kasan-dev@lfdr.de>; Tue, 17 May 2022 11:53:27 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1652813587; cv=pass;
        d=google.com; s=arc-20160816;
        b=C/tutgJMncPhQsvuFDhxdvR+VLrIQwjihncrRPH7hhoWg3iSUpwC2MCOlVVKuqAZ/P
         cep9X3CX4uguOsvTqHZN6J1UXR6nCyIXdC9sky+G1rsPe7s6/0/dgn+RwExXtU86E/bw
         YTa4uS4r7o5B6Qdxi7wbYxZLTQoGCZTxMMnwpA99EnjSt71IUpaAYrXGfhdCcJMiDuym
         fwCO2SWhDp8+wVtCTOp0cUJR7cT07ORA4Vdxxuew1VBnpOv2Y4486dYzfmOsmX7Eewvx
         miXzLKFtft1P76z8xJB8lAClM8xlWtXzkZfd/S21jlOzEF/74kT67xz2b61QvMArwvMy
         97Zg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=75TVE93ON0Y6GnKXYpNsxq+70ybG3XJac/b58s40nVo=;
        b=JQGxoU2BIpSQWcaKCfYB6pyTMhMrOH6DaDSskNxXqV/xJJ2b6DpkVrFzncvtoB6TmO
         smBcc1uvjbGZYWvwCAh+4uM8OJ8Ex5AH3StB3nDT9kZf0LaFOw/I7dN4/325fJZPXpJp
         Q5TOp/jstXoPigLku1dT0RRqPKVsZ/F/WcnAPrrJD2kxVFx3M9zuiS0k+STH4gy+gRFu
         Pct6ArmqOWy0WOcxI0P46W6VvuVxsvI0tKm8uf8tk8WkQz8+nxfeY9AQw1jAXskwr2s2
         f6MmR5u2eJmSRE3IlGOPcZt0ybu4ioTN5waexTHoN5mrx9FpSW1Ya5yKUxpJZ9KhohAi
         g7hA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=nn3siSFS;
       spf=pass (google.com: domain of nathan@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=nathan@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=75TVE93ON0Y6GnKXYpNsxq+70ybG3XJac/b58s40nVo=;
        b=bXQ7sIo0GuS+hAJ+qEN097dmf2C4qtmRhvgF8NMalP9kCzwOgn9s2Phg9OfEC+a7x+
         n2C2KBZsiFPfAZ17ZwiotXuUKJ/dF8qlHxhsy//vXr2lVYN5qEuYFHrFQwSb1xgBtDgX
         rPduqFPwqdl4KU67+QHJ8N+WjyRlYTqcBlaHGwzz03H5cbHJQ+11Tl2Lde5HBG/29jUd
         5IvIKAoQUNkRzgo1zg4rZoavcFY9N7k0x0xlfx07tRvt3A6qcUF4zNOSpbrowXBV+ANc
         WLDMvPVc7C7Vm1xi7G9jBhG2fV53DA48yg1i8BzWmssAQG7JU/fwk8azOKwlZY4MX2bw
         TaNg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=75TVE93ON0Y6GnKXYpNsxq+70ybG3XJac/b58s40nVo=;
        b=eHsonYnbtcTYODYRrum4TymZlCZn1yT65L0fGP4rZ0L69jioG6kR1lUaAUHMZ1kS8M
         WCo5plG2cnONcaw692ai7IJzrcjxyADLY9Y1LCMaMbkcoms6JJL6wPhnCXVFT4XgkBFW
         siJZcKGohwS21bhFHg2HLrAHgKgqPjD+wBBHsrg/6n6Z4chXTn8/I+PpguP0XirA1a7L
         TGkTurdZpYG4YV5Xau/AVtf6qLLEi4CVwG7ZyAsUrBtfVcQUmODhOMm82hr8LblkrBaW
         9uJb5V98xLtiHQPDV9ICXvrduzz6U0D3DOrgmbtTOlJ/KoV58RhEm8RnM4gYyKZ/AC81
         ou1Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531GgcSFkyWMu1DR8uYp5sKbYsKmt4Srk8f6MXOfaX/2QUDN8o1l
	4brl7jDkOmpEdMhFYfQchpQ=
X-Google-Smtp-Source: ABdhPJwHSUq/suFRr3IfmrLQTVM7jE39S4vqZY2bScjg3v7HnSqTucl4yYXSjhUnQ69m99wXk3Zheg==
X-Received: by 2002:a17:907:215b:b0:6f4:d91c:ef53 with SMTP id rk27-20020a170907215b00b006f4d91cef53mr20454987ejb.175.1652813587482;
        Tue, 17 May 2022 11:53:07 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:907:8a10:b0:6f4:91cc:ac07 with SMTP id
 sc16-20020a1709078a1000b006f491ccac07ls1465817ejc.0.gmail; Tue, 17 May 2022
 11:53:06 -0700 (PDT)
X-Received: by 2002:a17:907:1b28:b0:6f0:836:89b0 with SMTP id mp40-20020a1709071b2800b006f0083689b0mr20251382ejc.379.1652813586441;
        Tue, 17 May 2022 11:53:06 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1652813586; cv=none;
        d=google.com; s=arc-20160816;
        b=bTwvfSsGxDGNNuoiOjvrRAFylT7iQuZw7svNZArKDRwbsotXwoJfxYciZlAOA7nj0t
         K5n1d0dfNykbHLeuTfP8Cp/GZ+g3daJuZneQhwmI61Nks3pOiezCasHCLmCfSjb8I/mP
         bN2OPCQXEyxXTpCWleqPXkatVe/BQ3tCiIec1ds7c9R+vS0yf9+ohr1l4WK6tDiQvKKZ
         mHHrAqzWUoCeqWHdBx0PlL3dAX6lkhd8ofMlOK4AQ3iCQfRcgxNGK8O2yz8eVO8aT+uT
         pXpK+ZIyUEbMZ9ec9ZidX4zCHJD/QhKb1QzlQnOH80JKskH0ugBgSsj2kSFTC82+iyeP
         59jA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=7ql2S5UkfchxmzkMsoSjgsPgVXHBYrRN3Pc0CjgdGZc=;
        b=Boekugwm/Mym7uHsvy5T1LZu0cFemzI4+QcfTM9XIyPDl+SthkYRYI7rtx1AY+03nJ
         D68IAxI5GVdP9FqkFMolBedGecbtkGjXbHNpCw2VWMhHPZcugk76ywsEkFeqYv1KN0zw
         6y3aooTaFLxmDRMrfA6/IgtoX/rKTEkHId8LOsf11iTN8cZhXx7cNpfomAYlgoxR5jFq
         yJghphMV8XrLRspc06z7rNmUugg4JYU6LhbM+5+pViGge1OkoG+yikbroszhuWsz44SW
         OrckiteBrk5yL6+zf+0iYulCsb6rSrFVEDu+GMsUN657N4HBBf/EgcEFstokByCsMyA4
         b46Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=nn3siSFS;
       spf=pass (google.com: domain of nathan@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=nathan@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from ams.source.kernel.org (ams.source.kernel.org. [2604:1380:4601:e00::1])
        by gmr-mx.google.com with ESMTPS id rv14-20020a17090710ce00b006f4639cc02dsi3286ejb.2.2022.05.17.11.53.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 17 May 2022 11:53:06 -0700 (PDT)
Received-SPF: pass (google.com: domain of nathan@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) client-ip=2604:1380:4601:e00::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ams.source.kernel.org (Postfix) with ESMTPS id 2DF49B81B92;
	Tue, 17 May 2022 18:53:06 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 727CEC385B8;
	Tue, 17 May 2022 18:53:04 +0000 (UTC)
Date: Tue, 17 May 2022 11:53:02 -0700
From: Nathan Chancellor <nathan@kernel.org>
To: Peter Zijlstra <peterz@infradead.org>
Cc: Josh Poimboeuf <jpoimboe@kernel.org>,
	Nick Desaulniers <ndesaulniers@google.com>, llvm@lists.linux.dev,
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com
Subject: Re: objtool "no non-local symbols" error with tip of tree LLVM
Message-ID: <YoPvDn0Nb2fBtJCs@dev-arch.thelio-3990X>
References: <YoK4U9RgQ9N+HhXJ@dev-arch.thelio-3990X>
 <20220516214005.GQ76023@worktop.programming.kicks-ass.net>
 <YoPAZ6JfsF0LrQNc@hirez.programming.kicks-ass.net>
 <YoPCTEYjoPqE4ZxB@hirez.programming.kicks-ass.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <YoPCTEYjoPqE4ZxB@hirez.programming.kicks-ass.net>
X-Original-Sender: nathan@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=nn3siSFS;       spf=pass
 (google.com: domain of nathan@kernel.org designates 2604:1380:4601:e00::1 as
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

On Tue, May 17, 2022 at 05:42:04PM +0200, Peter Zijlstra wrote:
> On Tue, May 17, 2022 at 05:33:59PM +0200, Peter Zijlstra wrote:
> > On Mon, May 16, 2022 at 11:40:06PM +0200, Peter Zijlstra wrote:
> > > Does something simple like this work? If not, I'll try and reproduce
> > > tomorrow, it shouldn't be too hard to fix.
> > 
> > Oh, man, I so shouldn't have said that :/
> > 
> > I have something that almost works, except it now mightly upsets
> > modpost.
> > 
> > I'm not entirely sure how the old code worked as well as it did. Oh
> > well, I'll get it sorted.
> 
> Pff, it's been a *long* day.. here this works.

Thanks a lot for the quick fix! It resolves the error I see on 5.17 and
I don't see any new issues on mainline.

Tested-by: Nathan Chancellor <nathan@kernel.org>

> ---
>  tools/objtool/elf.c | 191 ++++++++++++++++++++++++++++++++++------------------
>  1 file changed, 125 insertions(+), 66 deletions(-)
> 
> diff --git a/tools/objtool/elf.c b/tools/objtool/elf.c
> index ebf2ba5755c1..a9c3e27527de 100644
> --- a/tools/objtool/elf.c
> +++ b/tools/objtool/elf.c
> @@ -600,24 +600,24 @@ static void elf_dirty_reloc_sym(struct elf *elf, struct symbol *sym)
>  }
>  
>  /*
> - * Move the first global symbol, as per sh_info, into a new, higher symbol
> - * index. This fees up the shndx for a new local symbol.
> + * The libelf API is terrible; gelf_update_sym*() takes a data block relative
> + * index value. As such, iterate the data blocks and adjust index until it fits.
> + *
> + * If no data block is found, allow adding a new data block provided the index
> + * is only one past the end.
>   */
> -static int elf_move_global_symbol(struct elf *elf, struct section *symtab,
> -				  struct section *symtab_shndx)
> +static int elf_update_symbol(struct elf *elf, struct section *symtab,
> +			     struct section *symtab_shndx, struct symbol *sym)
>  {
> -	Elf_Data *data, *shndx_data = NULL;
> -	Elf32_Word first_non_local;
> -	struct symbol *sym;
> -	Elf_Scn *s;
> +	Elf_Data *symtab_data = NULL, *shndx_data = NULL;
> +	Elf32_Word shndx = sym->sec->idx;
> +	Elf_Scn *s, *t = NULL;
> +	int size, idx = sym->idx;
>  
> -	first_non_local = symtab->sh.sh_info;
> -
> -	sym = find_symbol_by_index(elf, first_non_local);
> -	if (!sym) {
> -		WARN("no non-local symbols !?");
> -		return first_non_local;
> -	}
> +	if (elf->ehdr.e_ident[EI_CLASS] == ELFCLASS32)
> +		size = sizeof(Elf32_Sym);
> +	else
> +		size = sizeof(Elf64_Sym);
>  
>  	s = elf_getscn(elf->elf, symtab->idx);
>  	if (!s) {
> @@ -625,79 +625,120 @@ static int elf_move_global_symbol(struct elf *elf, struct section *symtab,
>  		return -1;
>  	}
>  
> -	data = elf_newdata(s);
> -	if (!data) {
> -		WARN_ELF("elf_newdata");
> -		return -1;
> +	if (symtab_shndx) {
> +		t = elf_getscn(elf->elf, symtab_shndx->idx);
> +		if (!t) {
> +			WARN_ELF("elf_getscn");
> +			return -1;
> +		}
>  	}
>  
> -	data->d_buf = &sym->sym;
> -	data->d_size = sizeof(sym->sym);
> -	data->d_align = 1;
> -	data->d_type = ELF_T_SYM;
> +	for (;;) {
> +		symtab_data = elf_getdata(s, symtab_data);
> +		if (t)
> +			shndx_data = elf_getdata(t, shndx_data);
>  
> -	sym->idx = symtab->sh.sh_size / sizeof(sym->sym);
> -	elf_dirty_reloc_sym(elf, sym);
> +		if (!symtab_data) {
> +			if (!idx) {
> +				void *buf;
>  
> -	symtab->sh.sh_info += 1;
> -	symtab->sh.sh_size += data->d_size;
> -	symtab->changed = true;
> +				symtab_data = elf_newdata(s);
> +				if (t)
> +					shndx_data = elf_newdata(t);
>  
> -	if (symtab_shndx) {
> -		s = elf_getscn(elf->elf, symtab_shndx->idx);
> -		if (!s) {
> -			WARN_ELF("elf_getscn");
> +				buf = calloc(1, size);
> +				if (!buf) {
> +					WARN("malloc");
> +					return -1;
> +				}
> +
> +				symtab_data->d_buf = buf;
> +				symtab_data->d_size = size;
> +				symtab_data->d_align = 1;
> +				symtab_data->d_type = ELF_T_SYM;
> +
> +				symtab->sh.sh_size += size;
> +				symtab->changed = true;
> +
> +				if (t) {
> +					shndx_data->d_buf = &sym->sec->idx;
> +					shndx_data->d_size = sizeof(Elf32_Word);
> +					shndx_data->d_align = 4;
> +					shndx_data->d_type = ELF_T_WORD;
> +
> +					symtab_shndx->sh.sh_size += 4;
> +					symtab_shndx->changed = true;
> +				}
> +
> +				break;
> +			}
> +
> +			WARN("index out of range");
>  			return -1;
>  		}
>  
> -		shndx_data = elf_newdata(s);
> -		if (!shndx_data) {
> -			WARN_ELF("elf_newshndx_data");
> +		if (!symtab_data->d_size) {
> +			WARN("zero size data");
>  			return -1;
>  		}
>  
> -		shndx_data->d_buf = &sym->sec->idx;
> -		shndx_data->d_size = sizeof(Elf32_Word);
> -		shndx_data->d_align = 4;
> -		shndx_data->d_type = ELF_T_WORD;
> +		if (idx * size < symtab_data->d_size)
> +			break;
>  
> -		symtab_shndx->sh.sh_size += 4;
> -		symtab_shndx->changed = true;
> +		idx -= symtab_data->d_size / size;
>  	}
>  
> -	return first_non_local;
> +	if (idx < 0) {
> +		WARN("negative index");
> +		return -1;
> +	}
> +
> +	if (shndx >= SHN_UNDEF && shndx < SHN_LORESERVE) {
> +		sym->sym.st_shndx = shndx;
> +		if (!shndx_data)
> +			shndx = 0;
> +	} else {
> +		sym->sym.st_shndx = SHN_XINDEX;
> +		if (!shndx_data) {
> +			WARN("no .symtab_shndx");
> +			return -1;
> +		}
> +	}
> +
> +	if (!gelf_update_symshndx(symtab_data, shndx_data, idx, &sym->sym, shndx)) {
> +		WARN_ELF("gelf_update_symshndx");
> +		return -1;
> +	}
> +
> +	return 0;
>  }
>  
>  static struct symbol *
>  elf_create_section_symbol(struct elf *elf, struct section *sec)
>  {
>  	struct section *symtab, *symtab_shndx;
> -	Elf_Data *shndx_data = NULL;
> -	struct symbol *sym;
> -	Elf32_Word shndx;
> +	Elf32_Word first_non_local, new;
> +	struct symbol *sym, *old;
> +	int size;
> +
> +	if (elf->ehdr.e_ident[EI_CLASS] == ELFCLASS32)
> +		size = sizeof(Elf32_Sym);
> +	else
> +		size = sizeof(Elf64_Sym);
>  
>  	symtab = find_section_by_name(elf, ".symtab");
>  	if (symtab) {
>  		symtab_shndx = find_section_by_name(elf, ".symtab_shndx");
> -		if (symtab_shndx)
> -			shndx_data = symtab_shndx->data;
>  	} else {
>  		WARN("no .symtab");
>  		return NULL;
>  	}
>  
> -	sym = malloc(sizeof(*sym));
> +	sym = calloc(1, sizeof(*sym));
>  	if (!sym) {
>  		perror("malloc");
>  		return NULL;
>  	}
> -	memset(sym, 0, sizeof(*sym));
> -
> -	sym->idx = elf_move_global_symbol(elf, symtab, symtab_shndx);
> -	if (sym->idx < 0) {
> -		WARN("elf_move_global_symbol");
> -		return NULL;
> -	}
>  
>  	sym->name = sec->name;
>  	sym->sec = sec;
> @@ -707,24 +748,42 @@ elf_create_section_symbol(struct elf *elf, struct section *sec)
>  	// st_other 0
>  	// st_value 0
>  	// st_size 0
> -	shndx = sec->idx;
> -	if (shndx >= SHN_UNDEF && shndx < SHN_LORESERVE) {
> -		sym->sym.st_shndx = shndx;
> -		if (!shndx_data)
> -			shndx = 0;
> -	} else {
> -		sym->sym.st_shndx = SHN_XINDEX;
> -		if (!shndx_data) {
> -			WARN("no .symtab_shndx");
> +
> +	new = symtab->sh.sh_size / size;
> +
> +	/*
> +	 * Move the first global symbol, as per sh_info, into a new, higher
> +	 * symbol index. This fees up a spot for a new local symbol.
> +	 */
> +	first_non_local = symtab->sh.sh_info;
> +	old = find_symbol_by_index(elf, first_non_local);
> +	if (old) {
> +		old->idx = new;
> +
> +		hlist_del(&old->hash);
> +		elf_hash_add(symbol, &old->hash, old->idx);
> +
> +		elf_dirty_reloc_sym(elf, old);
> +
> +		if (elf_update_symbol(elf, symtab, symtab_shndx, old)) {
> +			WARN("elf_update_symbol move");
>  			return NULL;
>  		}
> +
> +		new = first_non_local;
>  	}
>  
> -	if (!gelf_update_symshndx(symtab->data, shndx_data, sym->idx, &sym->sym, shndx)) {
> -		WARN_ELF("gelf_update_symshndx");
> +	sym->idx = new;
> +	if (elf_update_symbol(elf, symtab, symtab_shndx, sym)) {
> +		WARN("elf_update_symbol");
>  		return NULL;
>  	}
>  
> +	/*
> +	 * Either way, we added a LOCAL symbol.
> +	 */
> +	symtab->sh.sh_info += 1;
> +
>  	elf_add_symbol(elf, sym);
>  
>  	return sym;

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YoPvDn0Nb2fBtJCs%40dev-arch.thelio-3990X.
