Return-Path: <kasan-dev+bncBAABBN55TGKAMGQEASS5TLI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x63d.google.com (mail-ej1-x63d.google.com [IPv6:2a00:1450:4864:20::63d])
	by mail.lfdr.de (Postfix) with ESMTPS id C618D52D72C
	for <lists+kasan-dev@lfdr.de>; Thu, 19 May 2022 17:13:59 +0200 (CEST)
Received: by mail-ej1-x63d.google.com with SMTP id qw30-20020a1709066a1e00b006f45e7f44b0sf2725293ejc.5
        for <lists+kasan-dev@lfdr.de>; Thu, 19 May 2022 08:13:59 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1652973239; cv=pass;
        d=google.com; s=arc-20160816;
        b=R+QlsblnUYJjsdLGX+k3H/YSKtDSDzoMSlQChlGlntP5A73wZAdsmiB1ArnGPBrMb2
         yFfs3DXzbpSTvE2UJ0XjxMv1ZxGNkVhRh0Fly8wIOjg0XI5+hLHHiDd24u7OsCC33FhM
         r2+SO7wgbUo9R9YosI26xjKe0ga0Owe2VoyWRYNCpkMd9ZUCshoEAzMp7jrEPt2+Ayfx
         K4Ek74t99vqWXbwbzfuoQT54lh6RkmW3N6dQaI5wwboKVqZFb3ifg0e5Vyqm6zdz3Gt8
         P+WfwWMP6pLYha+SaAiQgPxc4PdQGWSNECKY+idpqHl1rpOlwDJ6C9yh0kYy1513B+kw
         NZKQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=mbHVZTHwgawjYbKkJR1zWigCDBtzi4yajNwsLany83o=;
        b=bxpQfDUhpq3hxqFW7ypEXZfD38HDgu557hcep30X2XiqASM1V/L68hbZma9MrjA3po
         k9XTVynvSvXidByQ0XoN6LYNsAnx8ktzwGNLNnlsRBCVyHVsjTxOJ4uP9Gib3BR1dlSb
         QJecbvOAiapGwgHVm/SIU5H7Fu3No4zwP0XQmTB/WH/s5ORljj9+AOOyEOcA6AoA0NI/
         geQ9o+zrBl0ZprKN67QstrdtQQYJWNgcl5z8+i9ttxsSEQFTniPctGfoJaQkjc/yYcDL
         +raEoyceqHR+PDLcYiDFfKj5emmHgLyYfKZjaM+yGBI8R10ecvqxiLwZXMyiR6mUNd7M
         eT4w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=JyruuCxe;
       spf=pass (google.com: domain of jpoimboe@kernel.org designates 145.40.68.75 as permitted sender) smtp.mailfrom=jpoimboe@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=mbHVZTHwgawjYbKkJR1zWigCDBtzi4yajNwsLany83o=;
        b=UjP7xJEDrefwIg0SFQpeCq8f4cXkuGPvi61hMQ2onMxVT/yjrPhpvyDjofnZP2j6F2
         ZiAFLdi8st5NRdXUcpGjO84yAq4NIvVd5wVmwgUHTxjaDtRNGggv+PqffBpNHtkmTY6P
         9yHdFtgqN6VxLHUOCHT5HPglMS3ksgjovYa1bCiOFACGh3Nsz0xxpvr3+7RefQKSA3/s
         BxIyDaG2iAAnB0bRMXRXQr8LACzdW0qmBQjm2VwVyh0IkEHFl5SCwJzGu9KSXKgCmQOI
         R1sPVW20IoyV+MKtRzjhOV0shQ6FjMpVkFMQ/FecC7Y/yptB66/c3cnTJWe6uWhUR6Uj
         xm7A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=mbHVZTHwgawjYbKkJR1zWigCDBtzi4yajNwsLany83o=;
        b=iogjhkjSYhX6JiUdAJfc2V5FJoOpaHjUNp7aoDbZ/HkFDP+L/O7jRXNnB0FjuMwOYk
         m/evQjA/6fNpFeSfjr4MuezWVm0Mm6Scf2WfTmY1gODDnEs2WWM6pUk8H7PqNis0Ybtq
         eAy9k1InDQVk/U1fEgK/A+Zglo/rDXlozMDZ52CRXMV29wh/CF0Om9dgO/U/DTO5u8f2
         tzSPZ3Jf93hiVTRNnd7JyWLGedjlRzTCrhg0nWJeZ/WIj4icocgLBq7PL7BK4bC5TGx6
         dFgbk7dP7rKyXMynp6JNBlcuS2W7XGs57yZ5Dzo5iD+k42BwnBVAb88AWqNWQ3TYBjqq
         H6xA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531eHORcRbsZydr8RWRg/w0fsLUpABQGJmzLSU19iPMdeo+xCTak
	WzevqnuiMJW4I9TtyL29ivs=
X-Google-Smtp-Source: ABdhPJyjReOJAwj6ZBhexgfOlcgTEaoAat7e7hZbkY33RGX09NLvoZETbL5UblEAddfzINLMj3cwYw==
X-Received: by 2002:a17:907:6d17:b0:6f4:6b6e:32da with SMTP id sa23-20020a1709076d1700b006f46b6e32damr4978945ejc.301.1652973239423;
        Thu, 19 May 2022 08:13:59 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:907:6e09:b0:6f3:ead4:abc6 with SMTP id
 sd9-20020a1709076e0900b006f3ead4abc6ls1098185ejc.5.gmail; Thu, 19 May 2022
 08:13:58 -0700 (PDT)
X-Received: by 2002:a17:907:90cf:b0:6f4:346f:f771 with SMTP id gk15-20020a17090790cf00b006f4346ff771mr4646429ejb.574.1652973238673;
        Thu, 19 May 2022 08:13:58 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1652973238; cv=none;
        d=google.com; s=arc-20160816;
        b=mL0qU/Ak6aDY2FaxEMhxGd/71sXOhd88B89x0CL3mS6oq6j58m1oHJD63Z1bGbWeab
         DUAeVX2SkLjSuPly7xFHf1VHezZcAE+ezUVaUV4j4do2GvcpFEwuSWjtYKyUK10OJfzf
         kAyJesWD15+xUPUiAitknsoUaQoHNIsgSv173Gr0/bKQLR+cLKk3WjxEGmzcl7Q7CiuC
         LZR6hnKpGvyZSNpm9Y+sSnno54jvBrquLr60hiptxHTcWsjNpe8h+NPKSw8EeYyfFQqG
         meHvVzZXdMT9q9Sy588sHfUua+vm8Wue6rAr9DpGncqIzXRK99J0d6gZCvZP408spPzW
         073Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=gmrTB+E7fsxtmn6zRIVnAQjboifqEL8Zstos0Mtx1Ro=;
        b=LPcDEsvV2Ueqk8lL/bl6U+xNsR8Wrn5LrBvbE0qm8jAsOx1kgYflHM9HDztI237izx
         NSfSKwPGCT5V3dkHd54To9JU97l3AiilSHFuphWFLdvtZ8oHwsgvtsTR3/zex186Uvvd
         ntZvSyvqWeZQXEb7H/KaHtz3d31E1QuAosnNTAFw3TVagdLTD6ui2jmlZ+vRW306YAzP
         rsFI5J70a1B2YqO5IE9p8jByhyw+0/IqxMCRUz6OwVA76c+yoLM9v3Jfwo2D57YLYAFH
         zUGK4wdXfH1HU2UOKKXJwmtc/HAV2gGbWnzJ/YY9eRXxrnSNQ5ISAiH33NG4XakYdyy+
         8Ejg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=JyruuCxe;
       spf=pass (google.com: domain of jpoimboe@kernel.org designates 145.40.68.75 as permitted sender) smtp.mailfrom=jpoimboe@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from ams.source.kernel.org (ams.source.kernel.org. [145.40.68.75])
        by gmr-mx.google.com with ESMTPS id d10-20020a50cd4a000000b00418d53b44b8si325731edj.0.2022.05.19.08.13.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 19 May 2022 08:13:58 -0700 (PDT)
Received-SPF: pass (google.com: domain of jpoimboe@kernel.org designates 145.40.68.75 as permitted sender) client-ip=145.40.68.75;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ams.source.kernel.org (Postfix) with ESMTPS id 6603CB82520;
	Thu, 19 May 2022 15:13:58 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id EDF83C385AA;
	Thu, 19 May 2022 15:13:56 +0000 (UTC)
Date: Thu, 19 May 2022 08:13:55 -0700
From: Josh Poimboeuf <jpoimboe@kernel.org>
To: Peter Zijlstra <peterz@infradead.org>
Cc: Nathan Chancellor <nathan@kernel.org>,
	Nick Desaulniers <ndesaulniers@google.com>, llvm@lists.linux.dev,
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com
Subject: Re: [PATCH v2] objtool: Fix symbol creation
Message-ID: <20220519151355.x7j3xmkelpakw4gx@treble>
References: <YoK4U9RgQ9N+HhXJ@dev-arch.thelio-3990X>
 <20220516214005.GQ76023@worktop.programming.kicks-ass.net>
 <YoPAZ6JfsF0LrQNc@hirez.programming.kicks-ass.net>
 <YoPCTEYjoPqE4ZxB@hirez.programming.kicks-ass.net>
 <20220518012429.4zqzarvwsraxivux@treble>
 <20220518074152.GB10117@worktop.programming.kicks-ass.net>
 <20220518173604.7gcrjjum6fo2m2ub@treble>
 <YoVuxKGkt0IQ0yjb@hirez.programming.kicks-ass.net>
 <20220519090029.GA6479@worktop.programming.kicks-ass.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20220519090029.GA6479@worktop.programming.kicks-ass.net>
X-Original-Sender: jpoimboe@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=JyruuCxe;       spf=pass
 (google.com: domain of jpoimboe@kernel.org designates 145.40.68.75 as
 permitted sender) smtp.mailfrom=jpoimboe@kernel.org;       dmarc=pass (p=NONE
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

On Thu, May 19, 2022 at 11:00:29AM +0200, Peter Zijlstra wrote:
> Subject: objtool: Fix symbol creation
> From: Peter Zijlstra <peterz@infradead.org>
> Date: Tue, 17 May 2022 17:42:04 +0200
> 
> Nathan reported objtool failing with the following messages:
> 
>   warning: objtool: no non-local symbols !?
>   warning: objtool: gelf_update_symshndx: invalid section index
> 
> The problem is due to commit 4abff6d48dbc ("objtool: Fix code relocs
> vs weak symbols") failing to consider the case where an object would
> have no non-local symbols.
> 
> The problem that commit tries to address is adding a STB_LOCAL symbol
> to the symbol table in light of the ELF spec's requirement that:
> 
>   In each symbol table, all symbols with STB_LOCAL binding preced the
>   weak and global symbols.  As ``Sections'' above describes, a symbol
>   table section's sh_info section header member holds the symbol table
>   index for the first non-local symbol.
> 
> The approach taken is to find this first non-local symbol, move that
> to the end and then re-use the freed spot to insert a new local symbol
> and increment sh_info.
> 
> Except it never considered the case of object files without global
> symbols and got a whole bunch of details wrong -- so many in fact that
> it is a wonder it ever worked :/
> 
> Specifically:
> 
>  - It failed to re-hash the symbol on the new index, so a subsequent
>    find_symbol_by_index() would not find it at the new location and a
>    query for the old location would now return a non-deterministic
>    choice between the old and new symbol.
> 
>  - It failed to appreciate that the GElf wrappers are not a valid disk
>    format (it works because GElf is basically Elf64 and we only
>    support x86_64 atm.)
> 
>  - It failed to fully appreciate how horrible the libelf API really is
>    and got the gelf_update_symshndx() call pretty much completely
>    wrong; with the direct consequence that if inserting a second
>    STB_LOCAL symbol would require moving the same STB_GLOBAL symbol
>    again it would completely come unstuck.
> 
> Write a new elf_update_symbol() function that wraps all the magic
> required to update or create a new symbol at a given index.
> 
> Specifically, gelf_update_sym*() require an @ndx argument that is
> relative to the @data argument; this means you have to manually
> iterate the section data descriptor list and update @ndx.
> 
> Fixes: 4abff6d48dbc ("objtool: Fix code relocs vs weak symbols")
> Reported-by: Nathan Chancellor <nathan@kernel.org>
> Signed-off-by: Peter Zijlstra (Intel) <peterz@infradead.org>
> Tested-by: Nathan Chancellor <nathan@kernel.org>

Acked-by: Josh Poimboeuf <jpoimboe@kernel.org>

-- 
Josh

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220519151355.x7j3xmkelpakw4gx%40treble.
