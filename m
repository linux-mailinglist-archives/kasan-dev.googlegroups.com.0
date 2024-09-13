Return-Path: <kasan-dev+bncBDHJX64K2UNBB25ER23QMGQER53UPHQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1039.google.com (mail-pj1-x1039.google.com [IPv6:2607:f8b0:4864:20::1039])
	by mail.lfdr.de (Postfix) with ESMTPS id 9AC8D97764E
	for <lists+kasan-dev@lfdr.de>; Fri, 13 Sep 2024 03:16:29 +0200 (CEST)
Received: by mail-pj1-x1039.google.com with SMTP id 98e67ed59e1d1-2db24468f94sf1613942a91.1
        for <lists+kasan-dev@lfdr.de>; Thu, 12 Sep 2024 18:16:29 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1726190188; cv=pass;
        d=google.com; s=arc-20240605;
        b=GzWJv2muTQJvOWEH68caDF/hBcMfk9CTBanXEM2fo8nDifMMsc9tKCR/ItMKWzMG3/
         4FAtwGY7ADlK5j9o738TTKT24TRwxRvazeDh2xusfL007+qqwuSPFlSVUHN2T0/Vhzzc
         qY3LBMoV0ZocfEIH82PpezpDXAO/3Wv+IUzfQAI+l8lOtZGIdEJr8RbgcJzVNGBuUluo
         FcoEOaLeNVEjNzPkO37OQEv/JTlwCF0Z1qg7L9nq5x0//kY2HnncdW3RFK8W7XQMz9Jh
         WNUdcXU+nEVfw/BqinkNkR6Rpg78mS1VNxOyCXNldZN2x/M83ylHibzr8qWmFxRPh1F+
         E38Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=zLtf7aiEDG1wqXrvF2YgvNZjAQU/vOGjCpsZA79f9VQ=;
        fh=tzESlM93bzhQooFjfVnhOwkKKjkpcQUK8c57UPqOKTE=;
        b=QtD1/oRjakhAcYRKVJfwoVZ3M0NkLMKLh3/yA5M2Dfjdmuc4RpQu62iyh6WEe5w9wH
         dhFw1omH/y00Xxu4Vr8z2KmhbYfZr5VNtADGlwM2cHXdWLnzfffj/aRRgSqRCbMF1dec
         qTjAYqE+9q7qtm838kKREAFzzMBTCPiR3yFYcsYAKeyfeIs6R/Xsj2ymXUIoC4TmrEDn
         UUmcYsCLhbnPGwRpZ0HuAMEHJlwdME/XsU/t6cSLm+mrtTCl1r7jdpRZVeDb/k5W9gM7
         WNdGEnMcw2N2nAYm5f/IxV3Je3j9ON2xOHp0lIxzLP4M3qmpb7W+iA7SylGdj6NDRguB
         ZqtQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@rivosinc-com.20230601.gappssmtp.com header.s=20230601 header.b=hfxNf0hW;
       spf=pass (google.com: domain of charlie@rivosinc.com designates 2607:f8b0:4864:20::633 as permitted sender) smtp.mailfrom=charlie@rivosinc.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1726190188; x=1726794988; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=zLtf7aiEDG1wqXrvF2YgvNZjAQU/vOGjCpsZA79f9VQ=;
        b=nkYfplV1YuIlxqsfDQIhFXy+N2s4zjsBRULVGHx13CYJ8+uEJ7wPoO7Tky4IpOut7M
         vP3zYE0WuG70BCj5ZKt1VYfZYFqWI4SVk93TcSZyxWbx8f1bI9aCtWMmOM8cr2ZUznym
         Ch1EnN52MG9fWNMEo7+jA7TBeKSILEmuOz1vo1yWWhISo9wRlnE1JZjGveEKt+Z9imSt
         U7pNk+KpQCSFy9FJAjD0LcEYGVvY1tQsOSIBTPtnVX8uzBK9x1ysLRPQ+BZ9XFggtPax
         s0z66NSXUORDng4Bc2tGc0Iye5bBXFYfkUW2oWK6X2xjkyLHsgUEmp8dRCj/X+cRFOsO
         W9DQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1726190188; x=1726794988;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=zLtf7aiEDG1wqXrvF2YgvNZjAQU/vOGjCpsZA79f9VQ=;
        b=MwkdynkSjNYkW29GAItUHTOPdc7nZM2iKcvuCjyypTdOtCaX/Fvv4DEd9uKBPTBoVN
         L6Z49jJOWs6hw0z9t4hbtPNr4cvQk6DxNh099ZJP7Q8Iies3t0iaE5CCUdvAz1FMSGuU
         Ro5bK5l5UPGC3SP6Tu2/X0M26zdeUrKT6uvsy5l0IXiPkJVSgQbatUCjPNmDIZ0EE5ZB
         7P8r1qz/wPIlwTHoybCnPOx3pOPNCv0sKVhv29cEv8yrAgE3nIm+1ifyok3xPorO1IPV
         Oiyr6YauiKlk8R9f+jlf4FW5i4x3BXKS2sl3L3BRKuaqKTE+UNh4XfLcu2addEBj3sim
         AQTw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXNDgZAxaEjUbLmpi2a+Qfp3c56DfhC7pgIZA1UXoWeW68KrqR3JWMKLiTVFwWp4h6bIif+Mg==@lfdr.de
X-Gm-Message-State: AOJu0YzsCVJ2pWZl/mYoOnLJgEG1Lenws2j1o8zHFuKUqqkYSMOXW+Cf
	7VyZhaSBWnH6fM3bxfDfe71sjr8Pa+7wPaVCaPPs+cTWoF/vCwVW
X-Google-Smtp-Source: AGHT+IG6uFQ/RPyvQtFyewODkrdYO5303xV5KMgaQMAVYxXSCiAVnk17NbYblC6XBMMLprXLfWm6AQ==
X-Received: by 2002:a17:90a:68c7:b0:2d3:dca0:89b7 with SMTP id 98e67ed59e1d1-2db9ff79bc8mr4386793a91.3.1726190187779;
        Thu, 12 Sep 2024 18:16:27 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:17cb:b0:2cb:57a2:d478 with SMTP id
 98e67ed59e1d1-2db9f63b0cfls955473a91.1.-pod-prod-01-us; Thu, 12 Sep 2024
 18:16:26 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXs98yM0mTYfKGJtf9ynK95Bs0dj4XOH89ib8u2jACZs5KOhJSDgag1OvTuYB4Cdg2f2Vod/Nl3ZO4=@googlegroups.com
X-Received: by 2002:a05:6a20:c799:b0:1cc:b22d:979f with SMTP id adf61e73a8af0-1cf75e79807mr6490760637.4.1726190186634;
        Thu, 12 Sep 2024 18:16:26 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1726190186; cv=none;
        d=google.com; s=arc-20240605;
        b=LSvKvSnjFT5T05m59mDOrKvDppFGznwNy24VdQcJuyffhzhn9LQS8vjsgxI+R78ktJ
         lw2xItQVd8HsXHB6dqoKS0qlJJd720cOea0kYjQzCXcW0a7SXKixF0QID6LgfJM63KUP
         jxy5mposkBqY92uXavoEwT95uO4h+4W0k9N36bDpygCKLZ9MteVpYS0QRDwb29iWSpUU
         bMg6rEtouaUWh/TpLjJX5TcouWyqPG4Rg5esXdslehOUw7a42RwCb/kZOgBN5UPa9PUD
         glW+m71lvXIPf39MGelXMUGrUTfj7X1DnP6T7biwVJOXNPdgzv0gJ1mcZ+TipL4dtu/Q
         mSVg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=CGdN0gxzpmFovSXXc4PPR7wb1goaAH/sxNtRx0azomw=;
        fh=iyqJbKs3IXD3BhOhVQzAF56t1s3+WQCCdepn2fmSLeA=;
        b=A/V5r6N5djmqJyH91tj/3f8yIGJggAZ1plpoDdHQ6ZNc8GEndt+foAeO0mNIPWY47x
         pwToXLuZZ/kb+CI8GTViomy0TUGAijUm1rWxjIhkLXc3BtPB9782CYHnNvivZEkhWFmy
         7awQpLglLa4AqKL8zIGnDHpXqcZgCjH29jc71iVxNeg/OCdfsOKN4OYqw0Vh8QmRJYWL
         8vSNKQbuva7MaOSAKJ9BLc6e8BetVijhmHweoujXYdxUmL6Dp7uBU8HPHANHft/ZORkA
         VKIwhwDmrm+j6PIL8PJA9hkg5gMGwaIyrnnEvYXERxKs8Tm/KrqSR54mzWhiDKqUyk0J
         9MmQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@rivosinc-com.20230601.gappssmtp.com header.s=20230601 header.b=hfxNf0hW;
       spf=pass (google.com: domain of charlie@rivosinc.com designates 2607:f8b0:4864:20::633 as permitted sender) smtp.mailfrom=charlie@rivosinc.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pl1-x633.google.com (mail-pl1-x633.google.com. [2607:f8b0:4864:20::633])
        by gmr-mx.google.com with ESMTPS id 41be03b00d2f7-7db1fad0f73si176978a12.0.2024.09.12.18.16.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 12 Sep 2024 18:16:26 -0700 (PDT)
Received-SPF: pass (google.com: domain of charlie@rivosinc.com designates 2607:f8b0:4864:20::633 as permitted sender) client-ip=2607:f8b0:4864:20::633;
Received: by mail-pl1-x633.google.com with SMTP id d9443c01a7336-2068acc8b98so14978685ad.3
        for <kasan-dev@googlegroups.com>; Thu, 12 Sep 2024 18:16:26 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVFIze5OkXf3f5oF1TQNE6gNwPbxB9FbYL1QvXCtMEj4wPwIhg4KF28LHlZQ9x9SEM39rwLy+Zi9TQ=@googlegroups.com
X-Received: by 2002:a17:903:249:b0:206:8eec:c087 with SMTP id d9443c01a7336-2076e354d05mr65687755ad.16.1726190185980;
        Thu, 12 Sep 2024 18:16:25 -0700 (PDT)
Received: from ghost ([50.145.13.30])
        by smtp.gmail.com with ESMTPSA id 98e67ed59e1d1-2dbb9c98f1fsm382550a91.20.2024.09.12.18.16.23
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 12 Sep 2024 18:16:24 -0700 (PDT)
Date: Thu, 12 Sep 2024 18:16:20 -0700
From: Charlie Jenkins <charlie@rivosinc.com>
To: Samuel Holland <samuel.holland@sifive.com>
Cc: Palmer Dabbelt <palmer@dabbelt.com>, linux-riscv@lists.infradead.org,
	devicetree@vger.kernel.org,
	Catalin Marinas <catalin.marinas@arm.com>,
	linux-kernel@vger.kernel.org, Anup Patel <anup@brainfault.org>,
	Conor Dooley <conor@kernel.org>, kasan-dev@googlegroups.com,
	Atish Patra <atishp@atishpatra.org>,
	Evgenii Stepanov <eugenis@google.com>,
	Krzysztof Kozlowski <krzysztof.kozlowski+dt@linaro.org>,
	Rob Herring <robh+dt@kernel.org>,
	"Kirill A . Shutemov" <kirill.shutemov@linux.intel.com>
Subject: Re: [PATCH v4 03/10] riscv: Add CSR definitions for pointer masking
Message-ID: <ZuOSZPJLBUeoTMA9@ghost>
References: <20240829010151.2813377-1-samuel.holland@sifive.com>
 <20240829010151.2813377-4-samuel.holland@sifive.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20240829010151.2813377-4-samuel.holland@sifive.com>
X-Original-Sender: charlie@rivosinc.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@rivosinc-com.20230601.gappssmtp.com header.s=20230601
 header.b=hfxNf0hW;       spf=pass (google.com: domain of charlie@rivosinc.com
 designates 2607:f8b0:4864:20::633 as permitted sender) smtp.mailfrom=charlie@rivosinc.com;
       dara=pass header.i=@googlegroups.com
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

On Wed, Aug 28, 2024 at 06:01:25PM -0700, Samuel Holland wrote:
> Pointer masking is controlled via a two-bit PMM field, which appears in
> various CSRs depending on which extensions are implemented. Smmpm adds
> the field to mseccfg; Smnpm adds the field to menvcfg; Ssnpm adds the
> field to senvcfg. If the H extension is implemented, Ssnpm also defines
> henvcfg.PMM and hstatus.HUPMM.
> 
> Signed-off-by: Samuel Holland <samuel.holland@sifive.com>

Reviewed-by: Charlie Jenkins <charlie@rivosinc.com>

> ---
> 
> (no changes since v3)
> 
> Changes in v3:
>  - Use shifts instead of large numbers in ENVCFG_PMM* macro definitions
> 
> Changes in v2:
>  - Use the correct name for the hstatus.HUPMM field
> 
>  arch/riscv/include/asm/csr.h | 16 ++++++++++++++++
>  1 file changed, 16 insertions(+)
> 
> diff --git a/arch/riscv/include/asm/csr.h b/arch/riscv/include/asm/csr.h
> index 25966995da04..fe5d4eb9adea 100644
> --- a/arch/riscv/include/asm/csr.h
> +++ b/arch/riscv/include/asm/csr.h
> @@ -119,6 +119,10 @@
>  
>  /* HSTATUS flags */
>  #ifdef CONFIG_64BIT
> +#define HSTATUS_HUPMM		_AC(0x3000000000000, UL)
> +#define HSTATUS_HUPMM_PMLEN_0	_AC(0x0000000000000, UL)
> +#define HSTATUS_HUPMM_PMLEN_7	_AC(0x2000000000000, UL)
> +#define HSTATUS_HUPMM_PMLEN_16	_AC(0x3000000000000, UL)
>  #define HSTATUS_VSXL		_AC(0x300000000, UL)
>  #define HSTATUS_VSXL_SHIFT	32
>  #endif
> @@ -195,6 +199,10 @@
>  /* xENVCFG flags */
>  #define ENVCFG_STCE			(_AC(1, ULL) << 63)
>  #define ENVCFG_PBMTE			(_AC(1, ULL) << 62)
> +#define ENVCFG_PMM			(_AC(0x3, ULL) << 32)
> +#define ENVCFG_PMM_PMLEN_0		(_AC(0x0, ULL) << 32)
> +#define ENVCFG_PMM_PMLEN_7		(_AC(0x2, ULL) << 32)
> +#define ENVCFG_PMM_PMLEN_16		(_AC(0x3, ULL) << 32)
>  #define ENVCFG_CBZE			(_AC(1, UL) << 7)
>  #define ENVCFG_CBCFE			(_AC(1, UL) << 6)
>  #define ENVCFG_CBIE_SHIFT		4
> @@ -216,6 +224,12 @@
>  #define SMSTATEEN0_SSTATEEN0_SHIFT	63
>  #define SMSTATEEN0_SSTATEEN0		(_ULL(1) << SMSTATEEN0_SSTATEEN0_SHIFT)
>  
> +/* mseccfg bits */
> +#define MSECCFG_PMM			ENVCFG_PMM
> +#define MSECCFG_PMM_PMLEN_0		ENVCFG_PMM_PMLEN_0
> +#define MSECCFG_PMM_PMLEN_7		ENVCFG_PMM_PMLEN_7
> +#define MSECCFG_PMM_PMLEN_16		ENVCFG_PMM_PMLEN_16
> +
>  /* symbolic CSR names: */
>  #define CSR_CYCLE		0xc00
>  #define CSR_TIME		0xc01
> @@ -382,6 +396,8 @@
>  #define CSR_MIP			0x344
>  #define CSR_PMPCFG0		0x3a0
>  #define CSR_PMPADDR0		0x3b0
> +#define CSR_MSECCFG		0x747
> +#define CSR_MSECCFGH		0x757
>  #define CSR_MVENDORID		0xf11
>  #define CSR_MARCHID		0xf12
>  #define CSR_MIMPID		0xf13
> -- 
> 2.45.1
> 
> 
> _______________________________________________
> linux-riscv mailing list
> linux-riscv@lists.infradead.org
> http://lists.infradead.org/mailman/listinfo/linux-riscv

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZuOSZPJLBUeoTMA9%40ghost.
