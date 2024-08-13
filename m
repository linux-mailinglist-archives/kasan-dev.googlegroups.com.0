Return-Path: <kasan-dev+bncBC7PZX4C3UKBBO7D5S2QMGQEFZGUURQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13a.google.com (mail-lf1-x13a.google.com [IPv6:2a00:1450:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id B1BF0950228
	for <lists+kasan-dev@lfdr.de>; Tue, 13 Aug 2024 12:13:17 +0200 (CEST)
Received: by mail-lf1-x13a.google.com with SMTP id 2adb3069b0e04-52efc9f200asf5268667e87.2
        for <lists+kasan-dev@lfdr.de>; Tue, 13 Aug 2024 03:13:17 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1723543997; cv=pass;
        d=google.com; s=arc-20160816;
        b=pMmeOTfCQxbgVG3sdcGX2aJFJyft11GI2MNG3NUOzUGz+i0ssrn3oqqGfh6YU3JWg0
         cmphxLnl7org1AExuRrVPgCOoiOiu4U3R6Fkm8IesPq7yB040s9w1AGjduwQ6kN3GTn5
         OjlPJ8+dMeUM0ZnLEKcg5Lg17KLvG+PRVbYnQd4w+FeqNcAnwoppFQ4hE4HKA8VDMucg
         pN0O9pHhB27vN7MUjotWhbr33dwvUNozfar/cDQ2e6mF3/htFwKp6C0VsztOf/qPtB2U
         I8Z2TNFw/GsAVXjflUL/1Q96KM1+2b8cI2h9O/g5xQA3wnkI0FNAjrmArEcVqcmxSgwm
         qvrA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=Y9lGVjwBjjQ7uJF60O4ZaBGqXTpX0qK5sbkqmiKo46w=;
        fh=wQbHTL50NqNjS2Vr9UUpsUpRMjbYMsZF3mrH2xLms0s=;
        b=KY//uSrHxuHtCR+nMoAz8NX8gWrE4kf7U2+WiUV/KWOCCSeC97u5cWBkYp0Wu3d8yR
         6ZfkofKVnRykGEYI7k60srQ8HGn3xazy2uJknpZ7A9QFxjaXuznsAeIgWbmDbi60J+L1
         XT2V18V9QoEoAoyE/ZDl/Vl+kMj1BlKSS/523RkzUzw+Q+zVtrpDAP5VarngFmjbv52X
         LUN6rSX5FEgtBGBIJVYYvUDPZkK6u3NCMFAMQZ+nE16NXiTPwcMEvbuVw7Ny/sdHTIgC
         OEzbmWk9lvBycTlwqpXUebKN8+vCyUfe53FFjpGcyFHvJnihYX2erFjFMmFaX59blpPP
         jnWA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of alex@ghiti.fr designates 2001:4b98:dc4:8::229 as permitted sender) smtp.mailfrom=alex@ghiti.fr
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1723543997; x=1724148797; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=Y9lGVjwBjjQ7uJF60O4ZaBGqXTpX0qK5sbkqmiKo46w=;
        b=iVFifjvCKO0bOwf0wpwmOjqXyiizqOl76Hff3GqV6GVZVM6J/aTVpbG/34ToGTg+X2
         bBRgrVRw2AcUhEUI0JX5CdFjoBGLHv4d+RoiN6mVEN7IonujXR1cJpOz50LOCy1iIvvR
         ilToZdCWi38zUF5uL3Ktt8z1AK5xinuF4Tn1qmdMVBuCRAHJoM/jgAgkJlO3eCnSh4fy
         eRTojJxIkeIQqf3ucCltnUEn/nGReDwm5b1poKx3ciQqKhLcumqqt8wPF1vtVmH/eKt/
         9hNEBBfJqjhqQSdFJ9dOzoH1Qf5f2Z1ibMD8zD98Tnojtr78nW/OYyvCc+n6qGGik4Ip
         YDzQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1723543997; x=1724148797;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=Y9lGVjwBjjQ7uJF60O4ZaBGqXTpX0qK5sbkqmiKo46w=;
        b=KhafKopzsw+xBFdloUJaVGBH7uSeHFSFKCcIzcy04be+nOXqilGBUq7Fhd/Cvd3Sax
         eJIzkzEbN1odnqHFb6QJSw+IAJtYpazKYSiMbZCKI4AK2XuWjlDoeFuwfqu1oYwGnrMk
         9gNaRJL5n0dwctZAEuT15GO0jXGXY/JkXNScrSxMLFh4W/plswNklt1UgQC18lcxqKjl
         lNYqERnArSa9dBwJiuscSvEZttAVULexu0goPuM7hNtIWPRW0vEU4F/sWxAr7RSYtMoN
         alyDD6S8PYf7DWZTSm9ae1Bq8IPt7C+KlRBBUhNOIUM9iGgNPpZ016jCmVtN60y5382p
         29vA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUCpkraFhD8pvS4DIxEQ2zWL7UVuuJCAJUrPFlciGi9cccQPDNjVEpMHOfGXAeKPT9Ys/5hZSvo8iP5C61wb894uUA5NK+FBw==
X-Gm-Message-State: AOJu0YwgrzSnbgJk3ZDBN4mQF62VqfUf7rq4ddKK2U6I0QTQLqxyxhOe
	I8FGnuCsUHXMK4LOa2aaonGsgS4To7luN5gkoDLEf1WMjnMEkzyG
X-Google-Smtp-Source: AGHT+IG7Zay9/3/IewXd9BiNRDZf+Rmk9N0kwBjV+/nf7l1xA4VNN0mbSL2KbsCdWs3+QC81kEHKDA==
X-Received: by 2002:a05:6512:12d3:b0:52d:b226:9428 with SMTP id 2adb3069b0e04-532136483demr2352870e87.6.1723543996057;
        Tue, 13 Aug 2024 03:13:16 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:45d0:b0:421:7e41:1867 with SMTP id
 5b1f17b1804b1-42909097c2bls25383475e9.0.-pod-prod-08-eu; Tue, 13 Aug 2024
 03:13:14 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXTUh0IvXD7W3k4Wv/oncyl6MAFxPCe3V9qYDcrLz2Ip8+ML2yzb7YuL0C+leqGjhZ0gfDJKl+2lpc7j4BEgqQEuQgnSSQ/iPnKvA==
X-Received: by 2002:a05:600c:4713:b0:427:abed:3602 with SMTP id 5b1f17b1804b1-429d486febdmr23551145e9.24.1723543993835;
        Tue, 13 Aug 2024 03:13:13 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1723543993; cv=none;
        d=google.com; s=arc-20160816;
        b=VZ6I4jtzAq3bPnxNM8n+Kr0PH/c29jDDjFagjPTPA0CvO0r/lADQENa7IRkQZ+ilec
         cSlXw4GTd+5friqfNXXsibE/5vfRHVW7Dt635arHM9DDvDYSFWPdMxN0JPyIlu0YsRpS
         ZMur9PdUFot3mYTbRS1smQi6enn3i9mt2hqeeNwxI0uFgodsMycKeKzcSYV+F1NLRacE
         G0AzCF1vD9g89YSK5UYfvXbXFD7uAyU5OOxSHfLtehkN/dTsquuJyWxsbNE4PV4NLWh0
         tQlJh0RBwe8ii6hUYXVjj867XIO1ZvCZeXZnfBoJA03nAbi5E96ivbzJg1asnC9rn6EO
         rtZg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id;
        bh=mgHJmGolVXWRjhLGM7Cz4xwas5huheeBlTowlivzmY8=;
        fh=PlrXXiljIqn5FFku5uz3XLLiXAFcGGd/MpVQIupLlEU=;
        b=WoKuh3NjYf0vvT4IIqZ9czDrh4lK3XtzEWi/eTV8m1dYMGUjdhVVL1SU4NznU5OhQ8
         oN+8fCZqZnooQdLHEYcCaKMF2bvo3JFgYVI1gz8Cc0kTo+B14/M2XDqX4TPXapaRt5xZ
         SMROJb4NkgRjCf+a/hprKhOIHg0OV6hvcKp0oxkvPg/7YuqclpgQNyQqZ35Yjxq6lCOi
         rBKdpG7pVgXJOXJ8QVgtYXKUS+q37RsSRn5/FH0OE6c/Ajz529DfCVGdHqK/UAtGDXab
         ZrEIxaYDczJXKWkv55eQOFvwr2qm4bv8FrtzjJ49RnaAm5tpzouoMlx28W89sN/lY/WE
         skiA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of alex@ghiti.fr designates 2001:4b98:dc4:8::229 as permitted sender) smtp.mailfrom=alex@ghiti.fr
Received: from relay9-d.mail.gandi.net (relay9-d.mail.gandi.net. [2001:4b98:dc4:8::229])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-429c772b33fsi1450815e9.1.2024.08.13.03.13.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Tue, 13 Aug 2024 03:13:13 -0700 (PDT)
Received-SPF: pass (google.com: domain of alex@ghiti.fr designates 2001:4b98:dc4:8::229 as permitted sender) client-ip=2001:4b98:dc4:8::229;
Received: by mail.gandi.net (Postfix) with ESMTPSA id B2980FF803;
	Tue, 13 Aug 2024 10:13:10 +0000 (UTC)
Message-ID: <4fe4a8a0-b5ac-4c52-ac9f-210c59a5d2f2@ghiti.fr>
Date: Tue, 13 Aug 2024 12:13:10 +0200
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v2 03/10] riscv: Add CSR definitions for pointer masking
Content-Language: en-US
To: Samuel Holland <samuel.holland@sifive.com>,
 Palmer Dabbelt <palmer@dabbelt.com>, linux-riscv@lists.infradead.org
Cc: devicetree@vger.kernel.org, Catalin Marinas <catalin.marinas@arm.com>,
 linux-kernel@vger.kernel.org, Anup Patel <anup@brainfault.org>,
 Conor Dooley <conor@kernel.org>, kasan-dev@googlegroups.com,
 Atish Patra <atishp@atishpatra.org>, Evgenii Stepanov <eugenis@google.com>,
 Krzysztof Kozlowski <krzysztof.kozlowski+dt@linaro.org>,
 Rob Herring <robh+dt@kernel.org>,
 "Kirill A . Shutemov" <kirill.shutemov@linux.intel.com>
References: <20240625210933.1620802-1-samuel.holland@sifive.com>
 <20240625210933.1620802-4-samuel.holland@sifive.com>
From: Alexandre Ghiti <alex@ghiti.fr>
In-Reply-To: <20240625210933.1620802-4-samuel.holland@sifive.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-GND-Sasl: alex@ghiti.fr
X-Original-Sender: alex@ghiti.fr
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of alex@ghiti.fr designates 2001:4b98:dc4:8::229 as
 permitted sender) smtp.mailfrom=alex@ghiti.fr
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


On 25/06/2024 23:09, Samuel Holland wrote:
> Pointer masking is controlled via a two-bit PMM field, which appears in
> various CSRs depending on which extensions are implemented. Smmpm adds
> the field to mseccfg; Smnpm adds the field to menvcfg; Ssnpm adds the
> field to senvcfg. If the H extension is implemented, Ssnpm also defines
> henvcfg.PMM and hstatus.HUPMM.
>
> Signed-off-by: Samuel Holland <samuel.holland@sifive.com>
> ---
>
> Changes in v2:
>   - Use the correct name for the hstatus.HUPMM field
>
>   arch/riscv/include/asm/csr.h | 16 ++++++++++++++++
>   1 file changed, 16 insertions(+)
>
> diff --git a/arch/riscv/include/asm/csr.h b/arch/riscv/include/asm/csr.h
> index 25966995da04..5c0c0d574f63 100644
> --- a/arch/riscv/include/asm/csr.h
> +++ b/arch/riscv/include/asm/csr.h
> @@ -119,6 +119,10 @@
>   
>   /* HSTATUS flags */
>   #ifdef CONFIG_64BIT
> +#define HSTATUS_HUPMM		_AC(0x3000000000000, UL)
> +#define HSTATUS_HUPMM_PMLEN_0	_AC(0x0000000000000, UL)
> +#define HSTATUS_HUPMM_PMLEN_7	_AC(0x2000000000000, UL)
> +#define HSTATUS_HUPMM_PMLEN_16	_AC(0x3000000000000, UL)
>   #define HSTATUS_VSXL		_AC(0x300000000, UL)
>   #define HSTATUS_VSXL_SHIFT	32
>   #endif
> @@ -195,6 +199,10 @@
>   /* xENVCFG flags */
>   #define ENVCFG_STCE			(_AC(1, ULL) << 63)
>   #define ENVCFG_PBMTE			(_AC(1, ULL) << 62)
> +#define ENVCFG_PMM			_AC(0x300000000, ULL)
> +#define ENVCFG_PMM_PMLEN_0		_AC(0x000000000, ULL)
> +#define ENVCFG_PMM_PMLEN_7		_AC(0x200000000, ULL)
> +#define ENVCFG_PMM_PMLEN_16		_AC(0x300000000, ULL)


Nit: the other ENVCFG_XX use (_AC(Y, ULL) << Z)


>   #define ENVCFG_CBZE			(_AC(1, UL) << 7)
>   #define ENVCFG_CBCFE			(_AC(1, UL) << 6)
>   #define ENVCFG_CBIE_SHIFT		4
> @@ -216,6 +224,12 @@
>   #define SMSTATEEN0_SSTATEEN0_SHIFT	63
>   #define SMSTATEEN0_SSTATEEN0		(_ULL(1) << SMSTATEEN0_SSTATEEN0_SHIFT)
>   
> +/* mseccfg bits */
> +#define MSECCFG_PMM			ENVCFG_PMM
> +#define MSECCFG_PMM_PMLEN_0		ENVCFG_PMM_PMLEN_0
> +#define MSECCFG_PMM_PMLEN_7		ENVCFG_PMM_PMLEN_7
> +#define MSECCFG_PMM_PMLEN_16		ENVCFG_PMM_PMLEN_16
> +
>   /* symbolic CSR names: */
>   #define CSR_CYCLE		0xc00
>   #define CSR_TIME		0xc01
> @@ -382,6 +396,8 @@
>   #define CSR_MIP			0x344
>   #define CSR_PMPCFG0		0x3a0
>   #define CSR_PMPADDR0		0x3b0
> +#define CSR_MSECCFG		0x747
> +#define CSR_MSECCFGH		0x757
>   #define CSR_MVENDORID		0xf11
>   #define CSR_MARCHID		0xf12
>   #define CSR_MIMPID		0xf13

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/4fe4a8a0-b5ac-4c52-ac9f-210c59a5d2f2%40ghiti.fr.
