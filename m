Return-Path: <kasan-dev+bncBCG7TL6TWUIRBTMTT2JQMGQENXUP5PQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x337.google.com (mail-wm1-x337.google.com [IPv6:2a00:1450:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id C702F50F082
	for <lists+kasan-dev@lfdr.de>; Tue, 26 Apr 2022 07:57:33 +0200 (CEST)
Received: by mail-wm1-x337.google.com with SMTP id az19-20020a05600c601300b003914ac8efb8sf425434wmb.2
        for <lists+kasan-dev@lfdr.de>; Mon, 25 Apr 2022 22:57:33 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1650952653; cv=pass;
        d=google.com; s=arc-20160816;
        b=yrmA/lNYpdF3kM8Udmxoh16+bKJ7jn7HEs+31lkM7A1aaNXuwIOg7DKgf12Qic6cgM
         10gQSo+yH8Th7lRYk7nVN5Y8oyZJ8X1eu/GLG8eaMo/foGDryggqjLwuyimKKDMxE04m
         O0Q/anVyAFgE4nHYLxzCKyEw4Am7nYu2CIwuJi063rd3yaSb6r2Pxzh4Cj6CxF+pXUd3
         v1ZfDcfJU2MAqc5em39e8PKg+lfAXsx7mmnE/TRd2bl2M5WCwDvYgpXp1pLhXv1HVoM8
         4uFvzeIUISF8p1GPo8IN3DASP1ysSVkZWKgNpfT7gwV+NSpP+Bm0ewZUwSYmb5VIZgDc
         zluQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=HH2J3AlHPXWn/x+3PoELYHzMGeUb57kaQVY7nBsmxI4=;
        b=ZCNnUU5p95jVqPsTWuZDVlyC9gUjmr1900Z7hwPi8o63aNFp6Gk4e1pFk9SDRZwZIr
         nOdKCzdr71ecaLeTbBuXC4OhncqTgj3SD/LY8mffNzmCa8eShWUqvRbWfxXT0bZM9Qsn
         xepBz3jL1T3ToeYm1i6ujvSw6+eQBRG8uUOdrN9bYbf27mrq+aemGz3nXXEDKfD+vAp3
         8VOljqI1U9Ds9X/fTffUuoUK5BsqTVrHJde9jrhe1S5iydFCyznczSSBsyH0472BXtGV
         V9A0lIYJ+BHWUD/lqgD00e1977s6Ndrq8yoe32tr//uGT5BziQzhHyVUggS6+mPJtF28
         4cAg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass (test mode) header.i=@ics.forth.gr header.s=av header.b=gTsKG8h0;
       spf=pass (google.com: domain of mick@ics.forth.gr designates 139.91.1.2 as permitted sender) smtp.mailfrom=mick@ics.forth.gr;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=ics.forth.gr
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:message-id:date:mime-version:user-agent:subject
         :content-language:to:references:from:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=HH2J3AlHPXWn/x+3PoELYHzMGeUb57kaQVY7nBsmxI4=;
        b=hRrLFf22kP2u3fXP1cM3CoAsrZtC1st/ohUfZK1z3rvOLg8wWdfWfJyjCUxoj92hS+
         8K2ocskp3FuGWbyqcoG9OY1eXL40ocJO+We+/OfHjk4kA7KCleHzQCLjyTdCZajleo90
         U/HpOz0L89TDysKODBLG6tzMgqlyD6J/m1pvG5q4YGKoY5AtBiMTh8tYW9NNynHMxXyK
         WiqC61jMmMiZHNJ4qLaBy+lm/v4WnbjxqyVMJki4PtdrooyK8kORBB2uShQC4JDx9JKQ
         ne26GJH0uUUn4lOAtR0hoXfMMQ2b9ocxPMZqExdI20eQcSRa4qZVnwiEn4KF9go8FWtb
         o7lQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:message-id:date:mime-version:user-agent
         :subject:content-language:to:references:from:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=HH2J3AlHPXWn/x+3PoELYHzMGeUb57kaQVY7nBsmxI4=;
        b=UH18fFoJHHeCPcVr59TP5Nv4i0cUKU2LXcJN7/PAt/nCchueCFFAlwxMpFu6XBWUH2
         ZquccGrwEff02YLcrSmy13NJB2JGy2OFURhQnQ8x1M/1GD94PbJLePOfsKJpjgXul1Bl
         yUPE1cLMM3Vkb15nnQbMu8SJ3fyUF/4dBCRZc8241KRpdad+8Q00iI6wP79/HuG3QG6O
         9t4nL/gCUvB5dNblxUKvQjVPAPEV1tDdlvdGEDgXROId1j/+zRdMt8r5A5hi+nzfhmCd
         crK7SICbVHw2T7WwuCxV7QlpAmP2zOAXqT/GJMhctDSbcX1e4tO3UJ5cg/TufQrMOk/M
         4avg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533oh8XgYuuDIYw5czweKLADv9TOSRlv2a1SqETOWXSCLmfTnXsA
	p2Et7/stGGv3tn57WlEScdE=
X-Google-Smtp-Source: ABdhPJx442ac3PGdtUrGYIGyTOpRXx53AFkCYG24O+3tQhud71LKAJbAdHJXKviruF4E+bN4wqiCSQ==
X-Received: by 2002:a05:600c:22d2:b0:393:f4be:ea1f with SMTP id 18-20020a05600c22d200b00393f4beea1fmr1943855wmg.51.1650952653425;
        Mon, 25 Apr 2022 22:57:33 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:1447:b0:20a:dc13:2578 with SMTP id
 v7-20020a056000144700b0020adc132578ls340147wrx.1.gmail; Mon, 25 Apr 2022
 22:57:32 -0700 (PDT)
X-Received: by 2002:adf:ec08:0:b0:20a:d39d:6ab6 with SMTP id x8-20020adfec08000000b0020ad39d6ab6mr11240909wrn.442.1650952652219;
        Mon, 25 Apr 2022 22:57:32 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1650952652; cv=none;
        d=google.com; s=arc-20160816;
        b=JF94ptZ3nhvzn2O7/SnSqBIYWqKsLoUlHfOLYXD8ditBvUiiqzmWwZgwrBPPkLrHWw
         tdk3qf0etOxk4zKE4luCpejVH12piQuwovZq6yOxIN7+CcYiaEnNHIxr7hdbsTLtpR5Q
         JVf0NSf6WuDECqQpVdFCZl1R9aW8rlnXphh81ux9yrjJeFckmzOJEbG4o6MzN0YAKetA
         Isl6GGPIBfkuMJkZbu758guDf+TOI6GLxjDzOEzR5ECRremDQRg+VYuDA990rvFdjIy0
         5d/FieKQPvRCun4mb3cC7RnqnFoziyjWYh5rr3QEEDSh7hoQfcPiPpByb0zZkEN+X089
         VdWg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=CSX5HYMpGPTmA7bcNj4BIyo3lCOgWDW3hqhIRdTxhTA=;
        b=JyIZEEaOwkk7g1BGxjNnCHmhnSpwsSO0XkH61Qw/f0jO2A9dFxX3+oTARg7d22FX+t
         A2TjHclyQabSGoVWDgdxyWdK7XpaV+PVZ4rYMM8BhnAodeSTJoUcqNjn64bJuVY1xAGU
         W9LMlMqPi5odfhpigvmm9TtdklryR9RGXswrdMps1kV6JtqWXl1JucQ6DbtfNI1DdVAx
         A8M/Sx5R/vaslB+7uNLXqg71Vc7p2J/lXeEO+r2uEINy76AkfsWoC+vVsOomgBetZlhr
         vVZdrvrxYHj3FxTgsCPDAIlJND+/GvUJCsOox3F/4vWlNWj7b/1DYHaE/7PKeQs/YbWW
         s0GA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass (test mode) header.i=@ics.forth.gr header.s=av header.b=gTsKG8h0;
       spf=pass (google.com: domain of mick@ics.forth.gr designates 139.91.1.2 as permitted sender) smtp.mailfrom=mick@ics.forth.gr;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=ics.forth.gr
Received: from mailgate.ics.forth.gr (mailgate.ics.forth.gr. [139.91.1.2])
        by gmr-mx.google.com with ESMTPS id x20-20020a05600c21d400b0038c73e87e1asi107908wmj.0.2022.04.25.22.57.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 25 Apr 2022 22:57:32 -0700 (PDT)
Received-SPF: pass (google.com: domain of mick@ics.forth.gr designates 139.91.1.2 as permitted sender) client-ip=139.91.1.2;
Received: from av3.ics.forth.gr (av3in.ics.forth.gr [139.91.1.77])
	by mailgate.ics.forth.gr (8.15.2/ICS-FORTH/V10-1.8-GATE) with ESMTP id 23Q5vV19063353
	for <kasan-dev@googlegroups.com>; Tue, 26 Apr 2022 08:57:31 +0300 (EEST)
X-AuditID: 8b5b014d-f2ab27000000641e-1f-626789c58245
Received: from enigma.ics.forth.gr (enigma.ics.forth.gr [139.91.151.35])
	by av3.ics.forth.gr (Symantec Messaging Gateway) with SMTP id C3.C0.25630.5C987626; Tue, 26 Apr 2022 08:57:25 +0300 (EEST)
X-ICS-AUTH-INFO: Authenticated user: mick at ics.forth.gr
Message-ID: <ff85cdc4-b1e3-06a3-19fc-a7e1acf99d40@ics.forth.gr>
Date: Tue, 26 Apr 2022 08:57:19 +0300
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101
 Thunderbird/91.7.0
Subject: Re: [PATCH v3 07/13] riscv: Implement sv48 support
Content-Language: el-en
To: Alexandre Ghiti <alexandre.ghiti@canonical.com>,
        Jonathan Corbet <corbet@lwn.net>,
        Paul Walmsley <paul.walmsley@sifive.com>,
        Palmer Dabbelt <palmer@dabbelt.com>, Albert Ou <aou@eecs.berkeley.edu>,
        Zong Li <zong.li@sifive.com>, Anup Patel <anup@brainfault.org>,
        Atish Patra <Atish.Patra@rivosinc.com>, Christoph Hellwig <hch@lst.de>,
        Andrey Ryabinin <ryabinin.a.a@gmail.com>,
        Alexander Potapenko <glider@google.com>,
        Andrey Konovalov <andreyknvl@gmail.com>,
        Dmitry Vyukov <dvyukov@google.com>, Ard Biesheuvel <ardb@kernel.org>,
        Arnd Bergmann <arnd@arndb.de>, Kees Cook <keescook@chromium.org>,
        Guo Ren <guoren@linux.alibaba.com>,
        Heinrich Schuchardt <heinrich.schuchardt@canonical.com>,
        Mayuresh Chitale <mchitale@ventanamicro.com>,
        panqinglin2020@iscas.ac.cn, linux-doc@vger.kernel.org,
        linux-riscv@lists.infradead.org, linux-kernel@vger.kernel.org,
        kasan-dev@googlegroups.com, linux-efi@vger.kernel.org,
        linux-arch@vger.kernel.org
References: <20211206104657.433304-1-alexandre.ghiti@canonical.com>
 <20211206104657.433304-8-alexandre.ghiti@canonical.com>
From: Nick Kossifidis <mick@ics.forth.gr>
In-Reply-To: <20211206104657.433304-8-alexandre.ghiti@canonical.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Brightmail-Tracker: H4sIAAAAAAAAA02Rf0yMcRzH973n6Xmezo5vV/jKsF0MISw/vtTC2HpMfi3ze+Oqx/VL9HQ1
	vx3ydN1hV6R5dPTjSsVC59JdIlnESlcNpd24MnNNhAiN0cXWf6993p/3+/3ZPgwhf0n6MjEJ
	ao5PUMYrKCmp35btN6suXRUx5+a5QFyWb/fA/RnZNE7t/eCBLQMijX/0fQT4V+ZDGuutWgK/
	qUkD2OAUaJz2qZrAjzptJC65WifB9mPtNC5++0qCG/S7sdb2lcR5gonEgvMlwK22HApXfEml
	cFZ9F4ldracIfPlTL4UFcRR+ZLlF4F7HRWqpLzvwMxOwWQMNJCtqTlPsRU0zyb53uUj2gbaP
	Zq2ig2Zzy5PZOxmPKfZupRmw5aXpFGt1LmLNpqNsVbuGYgvOnPVg28TN67y3SoOjuPiYFI6f
	HbJTGv3678F7NfJ9TelGWgNKR+qAJ4PgPNR2wkDpgJSRwzqAclL7wJCwCJk/u8hBlsElqKtM
	oAeZhFNQY3kHMTT3Qo8vvHHvjIabUZEty83eMAjdtJjdOQQci2wtOslggQ+sYVB9r9EdJIeH
	kenJOzdTcDq63HL/r5lhPOEKlP5NPeRdgHQW3b+cSeh2Tw5hAKPEYdXisApxmEUcZskFZCmA
	ypTAgJjIpIBde3h1dICKLwfu94PVlaDD3BNQCyQMqAWIIRQ+sqwpuyLksijl/gMcv2cHnxzP
	JdWC8QypGCuj326KkEOVUs3Fcdxejv+vShhPX40ERDqrT9pvREQvb6yyLR7Zlg8tE88fmqCI
	LNqy9nl/Siq89O1glDT8Wr598tQSR2PIVB+bv/lHN0z0exrkLxRKqrbLuaYKXWhlact0LdR3
	tJnzjBmGLV1SU0H1jnFHRqwpenB//k/HEiGxInZOdzOZ2KrqDj/F+7vCus9Vh60MNlQCB0Gk
	5RbeE7zM9jFN1lDvS2vHnS0JWv9bMiK3+Pv+1/mynuvqbGeB/vO7muCBhNiqkMS40ECDX/8R
	r9irB7XWmZ2zjM9ySmQ+T6c9+74hLlJV1t5wRedYMSNPWmesCd8YVhy7bKewynQ32WPiws4X
	25ufK3+tmly/5rhYOLu/RUEmRSvn+hN8kvIP4RAOL20DAAA=
X-Original-Sender: mick@ics.forth.gr
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass (test
 mode) header.i=@ics.forth.gr header.s=av header.b=gTsKG8h0;       spf=pass
 (google.com: domain of mick@ics.forth.gr designates 139.91.1.2 as permitted
 sender) smtp.mailfrom=mick@ics.forth.gr;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=ics.forth.gr
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

Hello Alex,

On 12/6/21 12:46, Alexandre Ghiti wrote:
> 
> +#ifdef CONFIG_64BIT
> +static void __init disable_pgtable_l4(void)
> +{
> +	pgtable_l4_enabled = false;
> +	kernel_map.page_offset = PAGE_OFFSET_L3;
> +	satp_mode = SATP_MODE_39;
> +}
> +
> +/*
> + * There is a simple way to determine if 4-level is supported by the
> + * underlying hardware: establish 1:1 mapping in 4-level page table mode
> + * then read SATP to see if the configuration was taken into account
> + * meaning sv48 is supported.
> + */
> +static __init void set_satp_mode(void)
> +{
> +	u64 identity_satp, hw_satp;
> +	uintptr_t set_satp_mode_pmd;
> +
> +	set_satp_mode_pmd = ((unsigned long)set_satp_mode) & PMD_MASK;
> +	create_pgd_mapping(early_pg_dir,
> +			   set_satp_mode_pmd, (uintptr_t)early_pud,
> +			   PGDIR_SIZE, PAGE_TABLE);
> +	create_pud_mapping(early_pud,
> +			   set_satp_mode_pmd, (uintptr_t)early_pmd,
> +			   PUD_SIZE, PAGE_TABLE);
> +	/* Handle the case where set_satp_mode straddles 2 PMDs */
> +	create_pmd_mapping(early_pmd,
> +			   set_satp_mode_pmd, set_satp_mode_pmd,
> +			   PMD_SIZE, PAGE_KERNEL_EXEC);
> +	create_pmd_mapping(early_pmd,
> +			   set_satp_mode_pmd + PMD_SIZE,
> +			   set_satp_mode_pmd + PMD_SIZE,
> +			   PMD_SIZE, PAGE_KERNEL_EXEC);
> +
> +	identity_satp = PFN_DOWN((uintptr_t)&early_pg_dir) | satp_mode;
> +
> +	local_flush_tlb_all();
> +	csr_write(CSR_SATP, identity_satp);
> +	hw_satp = csr_swap(CSR_SATP, 0ULL);
> +	local_flush_tlb_all();
> +
> +	if (hw_satp != identity_satp)
> +		disable_pgtable_l4();
> +
> +	memset(early_pg_dir, 0, PAGE_SIZE);
> +	memset(early_pud, 0, PAGE_SIZE);
> +	memset(early_pmd, 0, PAGE_SIZE);
> +}
> +#endif
> +

When doing the 1:1 mapping you don't take into account the limitation 
that all bits above 47 need to have the same value as bit 47. If the 
kernel exists at a high physical address with bit 47 set the 
corresponding virtual address will be invalid, resulting an instruction 
fetch fault as the privilege spec mandates. We verified this bug on our 
prototype. I suggest we re-write this in assembly and do a proper satp 
switch like we do on head.S, so that we don't need the 1:1 mapping and 
we also have a way to recover in case this fails.

Regards,
Nick

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ff85cdc4-b1e3-06a3-19fc-a7e1acf99d40%40ics.forth.gr.
