Return-Path: <kasan-dev+bncBDHJX64K2UNBBQ5BR23QMGQEUWNT6CA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x537.google.com (mail-pg1-x537.google.com [IPv6:2607:f8b0:4864:20::537])
	by mail.lfdr.de (Postfix) with ESMTPS id 80263977640
	for <lists+kasan-dev@lfdr.de>; Fri, 13 Sep 2024 03:09:25 +0200 (CEST)
Received: by mail-pg1-x537.google.com with SMTP id 41be03b00d2f7-72c1d0fafb3sf1264824a12.2
        for <lists+kasan-dev@lfdr.de>; Thu, 12 Sep 2024 18:09:25 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1726189763; cv=pass;
        d=google.com; s=arc-20240605;
        b=CSjCmAvjvWGKmgdg98I7t+yLy8A+vvH+g5JJoFduEW2U7SBJrvKp41v8luZU62l2dN
         LBpK3xuf3Yxzjjwayv3Tv6N9C453/EgKsG6vbcaJBPHQ47nOhaXDp1by0jnGMxtsL6Dw
         VbeHTcccykzgAKVvGr72Xf8pEwUpYVxf8XFOvjV+2+uPQRJuD/tkyfIZewvX46AU+nkg
         0zDrsafll/2LOEv0QtkGesKmftDnvBaumvxPVZl7wANEEfx9T9962hHzJNFGkRkMwiGJ
         TeAgxkCGdKNRat38xK39mPhnphmmo26Rm+GEFekxrWD00QGz5MsKHdbA4JamxUr7Wv8J
         dSSg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=oT4FAt8OuGPGoUs64qTdnZw7f+Xd1czJp6U/TPxgglg=;
        fh=6dIChmk9iF9sWER61IU9JPc3p7DFmjtadfxEO9D45uA=;
        b=Dr3K73EInKt9sF+UCBpH+uMSb8D2obvlHULmlyM/u5Wo8f5v9w3iR9hXQW2amTYNwM
         GcqMsrfKIiQsye8STBDADE7PFpb1eLHzVkOYsvy7C/v2qDQTpmHjhpZbQvU/nqu8Qj2p
         wpyOUER3OdGosyy2EaDJYss4FqYt176gHrb7O3QqJ+OKfYXGFqNm8XM//ZSGiNx/3s/E
         ZkGJD5a/HA6H8ggP3l607Wlav6UAflufEg0mfTs/I9YZ/CQebXRvEGl76q06MX45yEWV
         cwgOl+D018bcJJVA90tuWoK2becITDVUYZEkna6NCssupWVxrLPt56RnuBzAbwXRdoTt
         RLuQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@rivosinc-com.20230601.gappssmtp.com header.s=20230601 header.b="EUZkv0R/";
       spf=pass (google.com: domain of charlie@rivosinc.com designates 2607:f8b0:4864:20::102f as permitted sender) smtp.mailfrom=charlie@rivosinc.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1726189763; x=1726794563; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=oT4FAt8OuGPGoUs64qTdnZw7f+Xd1czJp6U/TPxgglg=;
        b=fBJww+MJBxdLQ5X+z6BQ1gGY/RgO/dPzsXCZO8yuGxLhxqZNHRsjay2Lo2Vp56Wf1N
         UkshSqwdlSNbklNzGJNVBi9/y/Vhzuyy2G9A9FDVQW1xUf2K62I87Sk8qFRsomM/7zUH
         R7r+tUIyC9KGqvLaDJtjpLU+pVUte0b69OWymdKvyCKA2MgVdrhgHGL77jqJGp3qnDFO
         0TmUZE9OEpe+3mUU0r2WIOVyKfiudp46HU3GRWAFHnBz0aLyHkAoYF2zxQTaMUfAbTjv
         P5dyOGQ1WIAQHcuSNqc+cjPl+Mjny7glIFt+rtskRNVbcz34YV0M/1rHvjB77V+puwAy
         EPCw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1726189763; x=1726794563;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=oT4FAt8OuGPGoUs64qTdnZw7f+Xd1czJp6U/TPxgglg=;
        b=FAvswUpkjC5bPKqoxLUNeaQQf32BPktATNEFpx3vjuEW4g5jG9DKKxha34kC8/k8b6
         2062P70uC059UezaG3Ahvv0MWV3jI6FcSyu+zC/OMJKoI9lYy4Opjme916zDwAjJZYva
         4JIpxjJaGTwfYXp0+9rx8WGeVJy6uQtEPSBP5j63sadBIozhhLI0Kib2FGnu5ZfgtPko
         527lQD1MvIfoJ0xZJP7jKJFz6NrY2KW+wvv5mgOKs1M5ByLBkO0IBtPKwd6uiI3RzRDp
         QK37z9LtXtT0sv+DTx/XcA1KdgqBdi4o/d4Er3c3vjCN91XRhbRg8u4UpvO4yT3joTJS
         bT7A==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXhxZ8YCJW81/u5IJYSq/cNpJxg41ZrDgjYjbb4bJRki9pI8L2NZi2QjFGd/Xq+1Gz1VCf/Hw==@lfdr.de
X-Gm-Message-State: AOJu0Yw+UQwLFret0EddSJqKNxsO8q0R+/MFwtKiPh2RTqdV9H0Tbd4e
	OpJgEwCHaKzstoLEeJH/vLh/VIVCGCfGW11LXonBzdnk4jw0520D
X-Google-Smtp-Source: AGHT+IGNhjg/FOldujCOJ/dR5KO8d9cEw60UX0KzN8xgd7dP3JdUsRfcICR3o5gtCCD5oCsTCt5geg==
X-Received: by 2002:a05:6a21:3a87:b0:1c4:c1cd:a29d with SMTP id adf61e73a8af0-1cf75efe978mr6788305637.28.1726189763294;
        Thu, 12 Sep 2024 18:09:23 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:1490:b0:70d:2505:8479 with SMTP id
 d2e1a72fcca58-71925852c03ls1324251b3a.0.-pod-prod-09-us; Thu, 12 Sep 2024
 18:09:22 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWVqxn8tl7TqHMPQKGr32+iPTcLs9qRdneUK1z/vfs4+LL+Yday1WbQ9Mw0Dzdbh+WNurPaq8c4tP0=@googlegroups.com
X-Received: by 2002:a05:6a00:3e09:b0:718:9625:cca0 with SMTP id d2e1a72fcca58-7192607f43bmr7785100b3a.7.1726189762059;
        Thu, 12 Sep 2024 18:09:22 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1726189762; cv=none;
        d=google.com; s=arc-20240605;
        b=DofCrN4Hjc5y6E+5U5AW8GfUhiOpsxhFJCD2hKfHVioq1ZxSg8hZvwBMipUnVIuyNc
         j3kZxGnY+RSBs8fkh9iXlJ40MSHLp0eQ6ySttm3EhfSA5QGlb7vR79ToeZ7kpdt1r31r
         eCM+NUyau7VAtYaGC3YZcRXaaJc8o9QnPM3gHN7MVnSIkE/bWR9fhtJd19FZ6fi2S8pz
         HxOWEhJpYjngqfmSZ2SlIfUL2bnqnklNG2342HxJxAKjMDrmjVZwKkS+Cb+rji5oav9l
         S6nnu7s+X8f+I4hfoggie9qrbSr915dPPzqag5vWA9xiERd1DM1ISsB8u9JdnfbS/wVH
         kg5g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=BBOQBRMmgRWLHrkPWadCkqX7dsfwA7uumaxy52Rb4Ds=;
        fh=4Cjeknm2HBaZt4PvSAFZAx4PGvt24oTHtoEF2bNADU0=;
        b=GeD9RarwWIZlTG3/niB3F8YfdPLhsseVhbYzeVyvXV1kywcnS6Gx6LMwqGgyrReel3
         kjHoWBYiZ9WmiiBZe8auu9e+T0+7cK6Z4BUuEiG3xb2++qZU8Jnpp09xhXB1Fjj7JOKN
         oJYTQXDbO/U/zjEfNEK0iQf7KXLygkSVPO3LDgfJdK+gb9ShjtKJLact6IEZJz33aXZc
         dIT/dReJNy8HFBpbmeMe79JxREYouwt9fIiKttAnuVzwUk+1Jepe2o6A9dOFtl+YGC3m
         gUhwuyhOx6c28KC0AzV18GmoSzXYdP77m1kj4PpI4WRc0K31MwUcLPG+bg69kac0Lu9+
         y2Sw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@rivosinc-com.20230601.gappssmtp.com header.s=20230601 header.b="EUZkv0R/";
       spf=pass (google.com: domain of charlie@rivosinc.com designates 2607:f8b0:4864:20::102f as permitted sender) smtp.mailfrom=charlie@rivosinc.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pj1-x102f.google.com (mail-pj1-x102f.google.com. [2607:f8b0:4864:20::102f])
        by gmr-mx.google.com with ESMTPS id d2e1a72fcca58-71908e9cab0si410478b3a.0.2024.09.12.18.09.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 12 Sep 2024 18:09:22 -0700 (PDT)
Received-SPF: pass (google.com: domain of charlie@rivosinc.com designates 2607:f8b0:4864:20::102f as permitted sender) client-ip=2607:f8b0:4864:20::102f;
Received: by mail-pj1-x102f.google.com with SMTP id 98e67ed59e1d1-2d8a7c50607so1121370a91.1
        for <kasan-dev@googlegroups.com>; Thu, 12 Sep 2024 18:09:22 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWSr7PGtz2cE9VhALA6BinfKU40/FexDBubCpzIdhHODNIkVAO9LvQWF0Kg+YFCGBz4GLe8A+5BwdE=@googlegroups.com
X-Received: by 2002:a17:90a:d507:b0:2d3:b8d6:d041 with SMTP id 98e67ed59e1d1-2dba0064f94mr5074427a91.32.1726189761464;
        Thu, 12 Sep 2024 18:09:21 -0700 (PDT)
Received: from ghost ([50.145.13.30])
        by smtp.gmail.com with ESMTPSA id 98e67ed59e1d1-2dbb9ccc836sm374464a91.25.2024.09.12.18.09.20
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 12 Sep 2024 18:09:20 -0700 (PDT)
Date: Thu, 12 Sep 2024 18:09:18 -0700
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
Subject: Re: [PATCH v4 02/10] riscv: Add ISA extension parsing for pointer
 masking
Message-ID: <ZuOQvmjywvvmo4Hd@ghost>
References: <20240829010151.2813377-1-samuel.holland@sifive.com>
 <20240829010151.2813377-3-samuel.holland@sifive.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20240829010151.2813377-3-samuel.holland@sifive.com>
X-Original-Sender: charlie@rivosinc.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@rivosinc-com.20230601.gappssmtp.com header.s=20230601
 header.b="EUZkv0R/";       spf=pass (google.com: domain of
 charlie@rivosinc.com designates 2607:f8b0:4864:20::102f as permitted sender)
 smtp.mailfrom=charlie@rivosinc.com;       dara=pass header.i=@googlegroups.com
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

On Wed, Aug 28, 2024 at 06:01:24PM -0700, Samuel Holland wrote:
> The RISC-V Pointer Masking specification defines three extensions:
> Smmpm, Smnpm, and Ssnpm. Add support for parsing each of them. The
> specific extension which provides pointer masking support to userspace
> (Supm) depends on the kernel's privilege mode, so provide a macro to
> abstract this selection.
> 
> Smmpm implies the existence of the mseccfg CSR. As it is the only user
> of this CSR so far, there is no need for an Xlinuxmseccfg extension.
> 
> Signed-off-by: Samuel Holland <samuel.holland@sifive.com>

Reviewed-by: Charlie Jenkins <charlie@rivosinc.com>

> ---
> 
> (no changes since v3)
> 
> Changes in v3:
>  - Rebase on riscv/for-next (ISA extension list conflicts)
>  - Remove RISCV_ISA_EXT_SxPM, which was not used anywhere
> 
> Changes in v2:
>  - Provide macros for the extension affecting the kernel and userspace
> 
>  arch/riscv/include/asm/hwcap.h | 5 +++++
>  arch/riscv/kernel/cpufeature.c | 3 +++
>  2 files changed, 8 insertions(+)
> 
> diff --git a/arch/riscv/include/asm/hwcap.h b/arch/riscv/include/asm/hwcap.h
> index 5a0bd27fd11a..aff21c6fc9b6 100644
> --- a/arch/riscv/include/asm/hwcap.h
> +++ b/arch/riscv/include/asm/hwcap.h
> @@ -92,6 +92,9 @@
>  #define RISCV_ISA_EXT_ZCF		83
>  #define RISCV_ISA_EXT_ZCMOP		84
>  #define RISCV_ISA_EXT_ZAWRS		85
> +#define RISCV_ISA_EXT_SMMPM		86
> +#define RISCV_ISA_EXT_SMNPM		87
> +#define RISCV_ISA_EXT_SSNPM		88
>  
>  #define RISCV_ISA_EXT_XLINUXENVCFG	127
>  
> @@ -100,8 +103,10 @@
>  
>  #ifdef CONFIG_RISCV_M_MODE
>  #define RISCV_ISA_EXT_SxAIA		RISCV_ISA_EXT_SMAIA
> +#define RISCV_ISA_EXT_SUPM		RISCV_ISA_EXT_SMNPM
>  #else
>  #define RISCV_ISA_EXT_SxAIA		RISCV_ISA_EXT_SSAIA
> +#define RISCV_ISA_EXT_SUPM		RISCV_ISA_EXT_SSNPM
>  #endif
>  
>  #endif /* _ASM_RISCV_HWCAP_H */
> diff --git a/arch/riscv/kernel/cpufeature.c b/arch/riscv/kernel/cpufeature.c
> index b3b9735cb19a..ba3dc16e14dc 100644
> --- a/arch/riscv/kernel/cpufeature.c
> +++ b/arch/riscv/kernel/cpufeature.c
> @@ -377,9 +377,12 @@ const struct riscv_isa_ext_data riscv_isa_ext[] = {
>  	__RISCV_ISA_EXT_BUNDLE(zvksg, riscv_zvksg_bundled_exts),
>  	__RISCV_ISA_EXT_DATA(zvkt, RISCV_ISA_EXT_ZVKT),
>  	__RISCV_ISA_EXT_DATA(smaia, RISCV_ISA_EXT_SMAIA),
> +	__RISCV_ISA_EXT_DATA(smmpm, RISCV_ISA_EXT_SMMPM),
> +	__RISCV_ISA_EXT_SUPERSET(smnpm, RISCV_ISA_EXT_SMNPM, riscv_xlinuxenvcfg_exts),
>  	__RISCV_ISA_EXT_DATA(smstateen, RISCV_ISA_EXT_SMSTATEEN),
>  	__RISCV_ISA_EXT_DATA(ssaia, RISCV_ISA_EXT_SSAIA),
>  	__RISCV_ISA_EXT_DATA(sscofpmf, RISCV_ISA_EXT_SSCOFPMF),
> +	__RISCV_ISA_EXT_SUPERSET(ssnpm, RISCV_ISA_EXT_SSNPM, riscv_xlinuxenvcfg_exts),
>  	__RISCV_ISA_EXT_DATA(sstc, RISCV_ISA_EXT_SSTC),
>  	__RISCV_ISA_EXT_DATA(svinval, RISCV_ISA_EXT_SVINVAL),
>  	__RISCV_ISA_EXT_DATA(svnapot, RISCV_ISA_EXT_SVNAPOT),
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZuOQvmjywvvmo4Hd%40ghost.
