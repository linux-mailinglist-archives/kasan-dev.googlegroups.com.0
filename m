Return-Path: <kasan-dev+bncBAABBUUVSGKAMGQEX2V4CEI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33e.google.com (mail-wm1-x33e.google.com [IPv6:2a00:1450:4864:20::33e])
	by mail.lfdr.de (Postfix) with ESMTPS id A664052AFE0
	for <lists+kasan-dev@lfdr.de>; Wed, 18 May 2022 03:24:34 +0200 (CEST)
Received: by mail-wm1-x33e.google.com with SMTP id q128-20020a1c4386000000b003942fe15835sf300016wma.6
        for <lists+kasan-dev@lfdr.de>; Tue, 17 May 2022 18:24:34 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1652837074; cv=pass;
        d=google.com; s=arc-20160816;
        b=U6d8i97iDP1wB0F445LbeCqeQiXr6tizWWZg/gqIVYYByw3E0BGJSi5j3IP3j5WhR3
         CWQt0ADmxsL45RYvU1Y3ifvfHwvOEFk2t5MLHhoc2ou/skOhZ49a5hqTAvLbddKW7iOQ
         u+HwZ1Y//HwLN61YoxNDWd/qDur1Hx+wXrkgmvkaNDVL8k937ABa9XuE94UNTGlNUnFi
         tn28Oc9QwA4DGIGVxunl/BIhYNGYd9mJ3csTKhwuJ3mPOw/c3xxxlfH1nQArT1G+3rlm
         alf7l7hbdwGMaQ1HagcQ9V/uUY4Hkkr+qrCvqTVjlwEb66tUowdNVWFGwZWqF1HzY5/z
         w40A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=H/m+vkAZMTj57eFu7PLVxWJeeEQN5Uyw0xmnjJUrotc=;
        b=etvFbUdiFVP/KWfCf07FZIs9++WS5yxWpIwbQ13I27YsyJYEPDHCpGzXuuusWrZ7Zo
         6EPw5Bng+LXtwUDlSdN0LZNcFwILlNTkoEXo4zT6+aamFF9RAZhfUof7R1w7Sr72auWy
         9Oji/P3uzqELW6aEpDznyYAdsqNpkL2KP59EreokGwLU9jwM5nFRW9T0mmNdWtiohysm
         DKXiNxX/mIvC7sWrEBcr/5cx5m1V30oH6W6w3TiLPGenu/GW7FnhMPf46bbRh2xITyJ9
         DIPWHuMdw56dDDi3UmrrsJAqLUgSGsD+Ck+5b4J4dLfnAVHpZ3qM+DX2z2d3o0YmGC0a
         KOkA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=i1QiMPVK;
       spf=pass (google.com: domain of jpoimboe@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=jpoimboe@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=H/m+vkAZMTj57eFu7PLVxWJeeEQN5Uyw0xmnjJUrotc=;
        b=bEmL6jodxTDms029ggdqmbYg/D81vM7ghcd/FmaEYP85MjIpH0x0ztZf2N5q+mnOgp
         w83JvPyvldVMZp1MxjJmNeOLXz0SzCsBJlcqJXDKlhTIMMqft1zpAmaGGM5ylQqFzLlP
         QMO4+7wymFqB80L77MqllawSlET1dLCAViiOADIj0AoNyp2JAz7xVfEwwmTs9Jlmqmvb
         SEFzrMQw8qbNb5FGmkorYejJ+jS5i8vAK3ZkBIU0YDlECKQLyj9irtvosUiyHghtqBVC
         nT+I27ir8x00svVd5jJLDjLt6ozdjILzC0JyHjY3ihUwFEwXcQWrehV3ecnA+1Lim1e4
         oZVQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=H/m+vkAZMTj57eFu7PLVxWJeeEQN5Uyw0xmnjJUrotc=;
        b=wJIlSxs//uc8uRx7Z0FOT6kd96thkvmkm577LsEJyxRAUzCsqcR4m2e/0br4xDFdKI
         2mBUj3xiqLIkVFnEle2T0wu0wgvfMC3wsUMSLwRyPBlDq4DickWbMluMttLAiW4deDki
         FaoCk4SzJ08dGec7OsFfv7ehpNo77y6gv/JAk9Y8i6headXzPSvMi7JNoJU5+gdNUUlE
         U9VcScx2I1JbWwLgz1lB0cM+eef3JKA99I7AxKTWLW35shpgErs7N4Jgd+ho+KbGxBkB
         aPrZ6e6eSD5wYNgGFHB4ikYvZ3/IBcApEgiESR99xxUh3L454ObHnOZHrLWkTsdP+H5B
         x3Pg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532UBmLXSX8hUEf6PyRMRpFk6oEZ9/8p/wg1K6Tv3e9rYztppTYx
	+UukwqWlhiZNuOzAJGm/4O4=
X-Google-Smtp-Source: ABdhPJznwLzcDbb+VXfx0lGRZpbzChauR9NaKYy6rmcNXdCsx0jWq3dPS5Yt+PufZw8bddwW4wEjcQ==
X-Received: by 2002:a05:6000:188f:b0:20c:5a1c:b7c with SMTP id a15-20020a056000188f00b0020c5a1c0b7cmr21110050wri.65.1652837074277;
        Tue, 17 May 2022 18:24:34 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:6d84:0:b0:20c:7b09:42a4 with SMTP id l4-20020a5d6d84000000b0020c7b0942a4ls5191134wrs.2.gmail;
 Tue, 17 May 2022 18:24:33 -0700 (PDT)
X-Received: by 2002:adf:f682:0:b0:20d:116f:2e05 with SMTP id v2-20020adff682000000b0020d116f2e05mr7661167wrp.169.1652837073493;
        Tue, 17 May 2022 18:24:33 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1652837073; cv=none;
        d=google.com; s=arc-20160816;
        b=j+zKYnpvVCC9jq3eDSUdys6RX9NCaI4RbSLOjpwtrtYgT26SU8NnweglblqaQxQ7Yv
         e7MCCB9KoN6njB2RA4uebp9IHbshTxajOzzvTSo809Cddmp3a691TIMdYjh6mKpt6CNq
         MgZawYSLh4zMiCav75txXqYEy6APJoLPvomObF/jnweLUwmdSP1/4KApJEuM9hTJa6Gg
         d0lluwH4oOV/kszvWA5XTUTj9pVQ3mKhaYplbEVmo6QFiV7aenX8LNUBOwXjsa2VgnNe
         VLCZambWigmWSuBule2jEh+OsM3D/IvJHiglyhHo379iUWjCLwGDT3LnF1M1xqasIKNf
         iq8Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=DIaqC3CYuJoRP7b4v1Khxj9y1BHqTNwvRtrDpyOc5V8=;
        b=FLm/CZ7TmT4B/okXcv0dWIYLMEMFAmootxEsyC1CvU+63vDS5KYvBwIOJGbpLSv4FR
         wfh4Bhpq8Ig/9M9WOeGl7vbx5DH39MlB61IIWI1QLeo8hF6N/iub2eFr45yPZkWvYSAf
         CFOp5gMnycJfzfkcHXhj8EACIu7yIh21hwUaOCr7SiCkvB7hIgM8WL+EFoweeoaun9BQ
         gO2Te1g5OwbejgF2pf2LpfhV+kTfsVbKUh1fMXJR2H25+Lvd/ka4GEbIjEx0r/ZJnK7B
         LaOwREo6K8V5QzYOxAOrycOkVcjaCAf4BWAt8kA8sj5DhIQUVZWtK4x1Fo5OAUmeRvf4
         3mVg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=i1QiMPVK;
       spf=pass (google.com: domain of jpoimboe@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=jpoimboe@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from ams.source.kernel.org (ams.source.kernel.org. [2604:1380:4601:e00::1])
        by gmr-mx.google.com with ESMTPS id t20-20020a0560001a5400b0020d12fa10dcsi29735wry.2.2022.05.17.18.24.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 17 May 2022 18:24:33 -0700 (PDT)
Received-SPF: pass (google.com: domain of jpoimboe@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) client-ip=2604:1380:4601:e00::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ams.source.kernel.org (Postfix) with ESMTPS id 2864AB81BE5;
	Wed, 18 May 2022 01:24:33 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 84F43C385B8;
	Wed, 18 May 2022 01:24:31 +0000 (UTC)
Date: Tue, 17 May 2022 18:24:29 -0700
From: Josh Poimboeuf <jpoimboe@kernel.org>
To: Peter Zijlstra <peterz@infradead.org>
Cc: Nathan Chancellor <nathan@kernel.org>,
	Nick Desaulniers <ndesaulniers@google.com>, llvm@lists.linux.dev,
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com
Subject: Re: objtool "no non-local symbols" error with tip of tree LLVM
Message-ID: <20220518012429.4zqzarvwsraxivux@treble>
References: <YoK4U9RgQ9N+HhXJ@dev-arch.thelio-3990X>
 <20220516214005.GQ76023@worktop.programming.kicks-ass.net>
 <YoPAZ6JfsF0LrQNc@hirez.programming.kicks-ass.net>
 <YoPCTEYjoPqE4ZxB@hirez.programming.kicks-ass.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <YoPCTEYjoPqE4ZxB@hirez.programming.kicks-ass.net>
X-Original-Sender: jpoimboe@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=i1QiMPVK;       spf=pass
 (google.com: domain of jpoimboe@kernel.org designates 2604:1380:4601:e00::1
 as permitted sender) smtp.mailfrom=jpoimboe@kernel.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=kernel.org
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

I'm confused by whatever this is doing, how is !symtab_data possible,
i.e. why would symtab not have data?

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

This should probably be called 'entsize' and I think you can just get it
from symtab->sh.sh_entsize.

> +	/*
> +	 * Either way, we added a LOCAL symbol.
> +	 */
> +	symtab->sh.sh_info += 1;
> +
>  	elf_add_symbol(elf, sym);

Not sure if it matters here, but elf_add_symbol() doesn't set sym->alias
and sym->pv_target, and both of those are unconditionally initialized in
read_symbols().  Should elf_add_symbol() be changed to initialize them?

-- 
Josh

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220518012429.4zqzarvwsraxivux%40treble.
