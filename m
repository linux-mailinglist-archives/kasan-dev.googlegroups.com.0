Return-Path: <kasan-dev+bncBCRJ7M4BUUBBBEVKX2PQMGQEHJITYYA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x137.google.com (mail-il1-x137.google.com [IPv6:2607:f8b0:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id 0D03969AE71
	for <lists+kasan-dev@lfdr.de>; Fri, 17 Feb 2023 15:54:12 +0100 (CET)
Received: by mail-il1-x137.google.com with SMTP id z8-20020a056e0217c800b003157134a9fbsf396784ilu.2
        for <lists+kasan-dev@lfdr.de>; Fri, 17 Feb 2023 06:54:11 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1676645650; cv=pass;
        d=google.com; s=arc-20160816;
        b=h3LGqqvUgL5FnEYhxEKcd4rto0QPSjoE0zLrLsLOvG8uVGy0mVLHsZb23NNQ8zOHj/
         Xved9EA82jPGTULzyRDmT+5sU/uKaJ4IDWfGFjgVPdAOazke9SmkgFQ1YgCZ16hv8XCs
         t7fm/NklGQ1ke5dkQ1KvXr+dNWUueFkqGT2lCTPBEZNQ6/f6KDIy4oH6FztC9SzNG7f8
         szhhDlcD92aitj5ObmihFuKVdhCaeFv7VFQ3+rnjDDYzviaSvylZd/LJEjyhbkKIQgMW
         EP8DL99wh8dYzWUrmLEvfZ6Rzmxo0NfGSzhtVARP8Oy5RVLioKQLA6khMpiCf/Au4Is0
         cJWQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :mime-version:message-id:date:references:in-reply-to:subject:cc:to
         :from:sender:dkim-signature;
        bh=gAga1lG0jt4mmzHoHbzVqx7hC4ujHIOFek/GXriTOYk=;
        b=tmupYzetDk+TSXYF3AzvTzlLWKQ8Lp/C79W+bfYUpf8SaupIuOaEu5umx0LWLShJh7
         1PztaYJgRGSBzDBue6yfM6TvS3pUzpucfbqjEGiUJL4vhztv5yszlgEEWaELdh6ZJJv+
         4V7L8k0Ka1TnbeN22HemOpQSYVjAQ+hQ5XP/gbUcHCjgK7Ol0O9pZ3gqqetGhrL8X3Rq
         K5R35e27nT29zConXN8IokJ8NWpwp5sI+GQi3SUUChhEEo14Tn+gaGr+Z76eCJnO2AM4
         PKxnJMRCv9wGAW+H2drrpATKpj8HjanEPBvTntMFW2w5KKlU7/mUXVmDciX3psVg9C9Y
         toaw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=UY7NL9L8;
       spf=pass (google.com: domain of bjorn@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=bjorn@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:mime-version:message-id
         :date:references:in-reply-to:subject:cc:to:from:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=gAga1lG0jt4mmzHoHbzVqx7hC4ujHIOFek/GXriTOYk=;
        b=n6fwbLIFlpepyP60OCwLa3WxB+AkZa4EwSUyCseRGoMXYkDnZ1M9iTjUfPH3+A6bZB
         BXO4EpRm6hM9+A8U6gKwDrTuphtgaSA8WfceTMqAZMdzm5l9oITYPfjMlhRrie83qPAZ
         J+BUDJyvNnpKemFC49cC/lSjN3RZusMkakdYOjsfZOnqcmmXJCvyOLzjWoYUheTdDWyT
         XqpoJNdEOKUryknJNMPSbF1bncVdGZNatR+oBIw9/jY7Au2wL5yNzQzLLBUUJNNM56hc
         VGoKO2xsBK5ajpLzWCCBsaITAunjdpgS6uh6qRoGcr00qOTPLut8jvY8GUWECdDJQ3kG
         AzpA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:message-id:date:references
         :in-reply-to:subject:cc:to:from:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=gAga1lG0jt4mmzHoHbzVqx7hC4ujHIOFek/GXriTOYk=;
        b=aT3dPRXdcKPbwwVHeoyP/rEKBMF5ndnMgs++Mzbs8NPLchBtGzQpzSnpx4+gYXWO6S
         eoKasrkufqCK2YBjq/KQXhKPOuXke8DpQ3AbRC1Iy51Izu+3ehPanLuYyWWfq4Sp5uz+
         TSdsaWU/JjlkQ9/rx6zFjMDCVawF6c/j6WwojmSplBvZL59YaD7q9DjaeK4INjOrA9ip
         XItY/mk/rJclWf4adU8dkZTndgVIsCMBXx9gXrGXrrjmdaRJA0bRklWK1kmEHgWEAEZi
         CW9qr6P9RG2n/6TJSfck9+mvrApf1gzWU9QOQUDXuSr43UvtuPpTDun1DUtFa/FtH1FY
         LmIQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKWUbCtTvsy4O1vnefPiA0KKZRMwNjhuwdnbTPY28nPRN8QPhy5h
	ZJ9PORdRoc84Q3MF2WiGk5g=
X-Google-Smtp-Source: AK7set8xMhsQy9R12BMPptwyToufmM92fbxdtsva2UZ1Saq5giqwuwuys1wXuDhzj2iw6PTQ/LsoUg==
X-Received: by 2002:a05:6602:4253:b0:744:4f75:25a4 with SMTP id cc19-20020a056602425300b007444f7525a4mr1755495iob.83.1676645650572;
        Fri, 17 Feb 2023 06:54:10 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:d8c1:0:b0:314:1891:45e5 with SMTP id l1-20020a92d8c1000000b00314189145e5ls236502ilo.5.-pod-prod-gmail;
 Fri, 17 Feb 2023 06:54:10 -0800 (PST)
X-Received: by 2002:a05:6e02:16c8:b0:316:67be:1ba1 with SMTP id 8-20020a056e0216c800b0031667be1ba1mr1473636ilx.31.1676645650070;
        Fri, 17 Feb 2023 06:54:10 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1676645650; cv=none;
        d=google.com; s=arc-20160816;
        b=W2lxj3voAIFHFdAQkJfBxq5LdRdO03V2ag++aOoL/R01vRYIyzTvXCpOJxtiLqKc2K
         /ddzK6qihZ768Zm7cQ0TcRUZ1SdM1QC1vH+mE2aYe1FtCE34xcioDtZex1v1SbXc1Xp9
         WXqF/9eUyZfg/HuOwfbfy81g1k/1qVqn4Jtdc/H0eSyDb/+Yq219BBB+T2hWgBqw+JM/
         kRQPEMIi6cK2aZLCNFS/2F73dpr5bEPwz/AKHR1kiiZhMPZ52u3ySXi0yqPGEu0fsM6Z
         wslk2JPe9w3A9T3dWG4nKsjDlaMsmWLIKKzE/C5LZwScgLQaONGtIaxGd3tmqQlty8+F
         ou5A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:references
         :in-reply-to:subject:cc:to:from:dkim-signature;
        bh=kHrX4kEHu9MfpWYXYkB7/29bdcAKE84WxAcYwxfMGJ8=;
        b=hLhPS+5QeNaZUb9YCwDZuUQPbsEE+Dujq42FxlsU1s9qpp21hxfUFjUOSyVa65shJh
         q5qvG1EWSBXl9ID54y6lx7tEKPJtHh7CDQ573CDvT4XYQ29adPPUz7KbaRUKTwoyDusQ
         uUy7iHAQc/NViz/UPjssrNvC7Z8Pc6BAyAtvE7PNSI5eO3lArRocvJt9M9R0IprORhCF
         fZ7nUy/OmT6GSAQZmdz/K88ModeKjNdAuqliHxwWpXJJHOVIL5TvV5nAgXOueudglk3x
         F+VSQKljovdOgSe1kMgdPIxtpRL8/Wr2ZZ01Cj5QzfbQclxa5DZTzekVbN50EQqMoP2F
         JwrQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=UY7NL9L8;
       spf=pass (google.com: domain of bjorn@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=bjorn@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id z17-20020a056638215100b003c515d28d6asi218519jaj.3.2023.02.17.06.54.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 17 Feb 2023 06:54:09 -0800 (PST)
Received-SPF: pass (google.com: domain of bjorn@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id 9EC5461C7A;
	Fri, 17 Feb 2023 14:54:09 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id B500EC433EF;
	Fri, 17 Feb 2023 14:54:08 +0000 (UTC)
From: =?utf-8?B?QmrDtnJuIFTDtnBlbA==?= <bjorn@kernel.org>
To: Alexandre Ghiti <alexghiti@rivosinc.com>, Paul Walmsley
 <paul.walmsley@sifive.com>, Palmer Dabbelt <palmer@dabbelt.com>, Albert Ou
 <aou@eecs.berkeley.edu>, Andrey Ryabinin <ryabinin.a.a@gmail.com>,
 Alexander Potapenko <glider@google.com>, Andrey Konovalov
 <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, Vincenzo
 Frascino <vincenzo.frascino@arm.com>, Ard Biesheuvel <ardb@kernel.org>,
 Conor Dooley <conor@kernel.org>, linux-riscv@lists.infradead.org,
 linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
 linux-efi@vger.kernel.org
Cc: Alexandre Ghiti <alexghiti@rivosinc.com>
Subject: Re: [PATCH v4 2/6] riscv: Rework kasan population functions
In-Reply-To: <20230203075232.274282-3-alexghiti@rivosinc.com>
References: <20230203075232.274282-1-alexghiti@rivosinc.com>
 <20230203075232.274282-3-alexghiti@rivosinc.com>
Date: Fri, 17 Feb 2023 15:54:06 +0100
Message-ID: <87lekwmjg1.fsf@all.your.base.are.belong.to.us>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: bjorn@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=UY7NL9L8;       spf=pass
 (google.com: domain of bjorn@kernel.org designates 2604:1380:4641:c500::1 as
 permitted sender) smtp.mailfrom=bjorn@kernel.org;       dmarc=pass (p=NONE
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

Alexandre Ghiti <alexghiti@rivosinc.com> writes:

> Our previous kasan population implementation used to have the final kasan
> shadow region mapped with kasan_early_shadow_page, because we did not cle=
an
> the early mapping and then we had to populate the kasan region "in-place"
> which made the code cumbersome.
>
> So now we clear the early mapping, establish a temporary mapping while we
> populate the kasan shadow region with just the kernel regions that will
> be used.
>
> This new version uses the "generic" way of going through a page table
> that may be folded at runtime (avoid the XXX_next macros).
>
> It was tested with outline instrumentation on an Ubuntu kernel
> configuration successfully.
>
> Signed-off-by: Alexandre Ghiti <alexghiti@rivosinc.com>

(One minor nit, that can be addressed later.)

Reviewed-by: Bj=C3=B6rn T=C3=B6pel <bjorn@rivosinc.com>

>  arch/riscv/mm/kasan_init.c | 361 +++++++++++++++++++------------------
>  1 file changed, 183 insertions(+), 178 deletions(-)


> @@ -482,7 +437,37 @@ static void __init kasan_shallow_populate(void *star=
t, void *end)
>  	unsigned long vend =3D PAGE_ALIGN((unsigned long)end);
> =20
>  	kasan_shallow_populate_pgd(vaddr, vend);
> -	local_flush_tlb_all();
> +}
> +
> +static void create_tmp_mapping(void)
> +{
> +	void *ptr;
> +	p4d_t *base_p4d;
> +
> +	/*
> +	 * We need to clean the early mapping: this is hard to achieve "in-plac=
e",
> +	 * so install a temporary mapping like arm64 and x86 do.
> +	 */
> +	memcpy(tmp_pg_dir, swapper_pg_dir, sizeof(pgd_t) * PTRS_PER_PGD);
> +
> +	/* Copy the last p4d since it is shared with the kernel mapping. */
> +	if (pgtable_l5_enabled) {
> +		ptr =3D (p4d_t *)pgd_page_vaddr(*pgd_offset_k(KASAN_SHADOW_END));
> +		memcpy(tmp_p4d, ptr, sizeof(p4d_t) * PTRS_PER_P4D);
> +		set_pgd(&tmp_pg_dir[pgd_index(KASAN_SHADOW_END)],
> +			pfn_pgd(PFN_DOWN(__pa(tmp_p4d)), PAGE_TABLE));
> +		base_p4d =3D tmp_p4d;
> +	} else {
> +		base_p4d =3D (p4d_t *)tmp_pg_dir;
> +	}
> +
> +	/* Copy the last pud since it is shared with the kernel mapping. */
> +	if (pgtable_l4_enabled) {
> +		ptr =3D (pud_t *)p4d_page_vaddr(*(base_p4d + p4d_index(KASAN_SHADOW_EN=
D)));
> +		memcpy(tmp_pud, ptr, sizeof(pud_t) * PTRS_PER_PUD);
> +		set_p4d(&base_p4d[p4d_index(KASAN_SHADOW_END)],
> +			pfn_p4d(PFN_DOWN(__pa(tmp_pud)), PAGE_TABLE));
> +	}
>  }
> =20
>  void __init kasan_init(void)
> @@ -490,10 +475,27 @@ void __init kasan_init(void)
>  	phys_addr_t p_start, p_end;
>  	u64 i;
> =20
> -	if (IS_ENABLED(CONFIG_KASAN_VMALLOC))
> +	create_tmp_mapping();
> +	csr_write(CSR_SATP, PFN_DOWN(__pa(tmp_pg_dir)) | satp_mode);

Nit: Maybe add a comment, why the sfence.vma is *not* required here. I
tripped over it.


Bj=C3=B6rn

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/87lekwmjg1.fsf%40all.your.base.are.belong.to.us.
