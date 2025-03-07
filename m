Return-Path: <kasan-dev+bncBCLM76FUZ4IBB2X2VW7AMGQEOHIZVWY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63b.google.com (mail-pl1-x63b.google.com [IPv6:2607:f8b0:4864:20::63b])
	by mail.lfdr.de (Postfix) with ESMTPS id 07609A575D3
	for <lists+kasan-dev@lfdr.de>; Sat,  8 Mar 2025 00:12:48 +0100 (CET)
Received: by mail-pl1-x63b.google.com with SMTP id d9443c01a7336-22379af38e0sf39060325ad.2
        for <lists+kasan-dev@lfdr.de>; Fri, 07 Mar 2025 15:12:47 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1741389163; cv=pass;
        d=google.com; s=arc-20240605;
        b=lpXK97ympe3Mk2U7DhD6C5vMSw/AM3oOwNdV4z3SNUxnEhxI+VcqtkXQbgBxsrgxPq
         ZTBau526FDDr5yBD9mkldEHnpRBYDA8/FCdDY0buqDAMzdSYeEGe04latpAOh/33E/X9
         uTiDQ2H4ZjGOZyJWryLNwBWYah2gxrVAGgf6eHHnAGlHem8T5G5fS79dCPdtjmenUKDU
         WDBzKBId4o9GnPNDl4jO6oa2x716uiUXf7X9j4yTTh1SCH2roz6BlTtFdJ8GoYx6bDLf
         y2r9sPNtpjDCFCWSeQ9cpPwV8z8ORatL5mBuQaHMigCyoMOkGF72+RAAk0aqzMJ32X9+
         wK6A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=D1VvAIMjtnrINJsqk6Aa+mYzZRn2es2zAV3y4zG/Wzk=;
        fh=LRuut1KKc2Tjb4U86C37zh//5EBYgE/cKKFrloa90i0=;
        b=e7AmM8eDkjsqeU8+KcdHTptpOb2TQXSQKMdCk3yoSWILCr4BvPHrCo5UdqOD2h7x5+
         AiYvyi3oTrsiTlX0BVv0VqK/IElu0Kn8LW0fllw2TmN2AFtjx6jOn98415hDXYngvOOY
         cs8Wy54kW/DcpT8QFcDKKFkrnJQFGqIhRGjygw0H1ED4EYuoV5aMR96V1uM6UgyCg0SP
         TyuD+HIzz6opvIFSXPuLQ4UTkOgqS3uSQ153G4nDfCa9fDj/IO4EJiyb0UDUdWID81VQ
         CnjyD2zFYNOhb9dNhCdeWHUZjv9be6Zg3zYPBypJdp/QH1UVid+CFFRDuSNvuXBHc4jk
         p5JQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=ndRXU9f0;
       spf=pass (google.com: domain of justinstitt@google.com designates 2607:f8b0:4864:20::d29 as permitted sender) smtp.mailfrom=justinstitt@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1741389163; x=1741993963; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=D1VvAIMjtnrINJsqk6Aa+mYzZRn2es2zAV3y4zG/Wzk=;
        b=BuZ9lxFcuCLhWJK6QYsJI3r3GXmvlTqsvrwRrzOta2GB7ZGt0sBmdqP3Ffizd7XHX/
         vAuvRaJVhf6xw7EvUUwx5AejYYfGPKSKJxT1dSfxtVjAia3loGWrUic+Xz7iVA9oTljE
         +UWgufSei78winB+MrVkxq2uRNbnUm95yeQtQyRWD7egP0pVzwlm0RwmbWKtssOh0adQ
         9FTOGmEWyGOKSUv4UE+Uvvud32nCa9ui23utL2SM0+sOtqaIvHPis/tuRPnFDcDBDyOn
         UP39q5ABXD8AH4sNNwUwOwf7JIj8wORZcacaDxwIJWE9Ey7qfjoHh0/0zgFm7/21St4Z
         PNkA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1741389163; x=1741993963;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=D1VvAIMjtnrINJsqk6Aa+mYzZRn2es2zAV3y4zG/Wzk=;
        b=KgYXS6aDet9gkwfqb+O8RnffqZPvJ+8+aa+JJsJPf9DRZqgeAFdenvUvZZzPBBs0p3
         hi9VJEWlxL40ALYzl16yt0gKfJkNXwlRUK2I7JHTiupbym2AebD/ylLq2EW0NVvAcrZw
         8FY445ZNnxU9G3MY75M8tEo3LeyURnWRCMuQ6JYK5q8oTZpdjD1BCr1Me1QrtUiz014l
         vkHdBP7jHLzY+IbSh60Ne5TDio7cUJ7gJLHsYpMz9T738kGQA+zWq2udCGkSkYtWvRD6
         CfBX1KXantxZVNDAcvhFqs9oUK6ZD2utrtwl/4h8BnBMcD8bd+YSHTGjYuR1rVRgNbME
         1cVA==
X-Forwarded-Encrypted: i=2; AJvYcCXeawfjPUcwELQaxJwopyNZXttRDDbvwRJp6r0MR5FN7dwN393KUjeU1rAUYWoSpVk692LE/A==@lfdr.de
X-Gm-Message-State: AOJu0YzQPb0pSUlOD7CTDGkqKUA/8YuSVlicOojsSwsaJ4TgN4+QM6A8
	h24AV4klc3hTJbK+PTxQwn3kcoIGckSFWhAR4iAuYtlEJUd6FHxT
X-Google-Smtp-Source: AGHT+IEaPrqHQ68yR/lut9rJjzVbuxvyhuv9Nksswfh0MwLqSxMpaw2GBJggguzouCjOYmkI1qGdVA==
X-Received: by 2002:a05:6a00:2e9b:b0:736:5da1:d344 with SMTP id d2e1a72fcca58-736aab160c6mr9109718b3a.24.1741389163118;
        Fri, 07 Mar 2025 15:12:43 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVHE/GUXW98qkPaao3tR1WM/6V5tj4RkvAdT6P0iMlr4HA==
Received: by 2002:aa7:9990:0:b0:736:b1e7:af81 with SMTP id d2e1a72fcca58-736b1e7b474ls1023013b3a.0.-pod-prod-01-us;
 Fri, 07 Mar 2025 15:12:42 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVD+QzSSudQLZFVsLaS5/REDoIEHOw6x3BBpRwHCaPY8VW9ica8SFe4JQyh0djWAV62lK3bywL2Vak=@googlegroups.com
X-Received: by 2002:a05:6a20:9150:b0:1f3:32ee:b2f4 with SMTP id adf61e73a8af0-1f544aedadcmr9850658637.12.1741389161755;
        Fri, 07 Mar 2025 15:12:41 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1741389161; cv=none;
        d=google.com; s=arc-20240605;
        b=cLf768/t2rAycC7sRkt5Gj1SUxagOHfHII77zGiyd/HccdWeNcII6yKH9hUTN8sghz
         iEB56nc1jMCxDnoeIl0tXjTxgvcf1/SI0UgSz+QCgI4gWheU+9xUu6vqeerDegkEUoJC
         FdwrOSd7jt33SqIvO4HydGXK3uuyD1R/6uIvTUV0eNF1E+YTtsyIW4yiPmfeHNzdn5DG
         3EQkDEn3tsLUKTFJXLizifnY8bRHbNQHUmyMnD3Egdm6dlpYfdoKC1MVQPvSaoMk0t/1
         gKdo81pNRFHpjI2GxnAAZvagi549sfLMdfnTx48qdMTfny+yFozBfERk7vyNxuOc/MHU
         8TTg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=rWk7dXPmdm5yCaIaVrSCJTIdKCaoNn8ysMEwHD+DXFk=;
        fh=qIoCSqJcCoZ8cFLI2kTXAsS5KoxozajZVQNfVYZNQ2o=;
        b=HAThT43j4/N0t7L+c/ar/F2wd+jnG7e+DsdxPafgRrKvf8Or2WJ5elbKFwBe7y8vrJ
         buVJbfwe9/UxaBoJ7+koT3GiUkN2+lYglTSmjlcj2ulcYM5iv7GzJd6JE/2Zm8fiX2s5
         0TMV7U3CD4qBa5Tk8hSlFU/U03rAosSsgUzhR+sYBIRtFLeGXI4nIHtwUYN6Jw57kf+w
         zdddjFDQOzEwvtwBINxuiLQptAymoDTDB7LFObsUWcTvGNvx7G+XUkh18Wrlx0juvxDR
         mBFB6cRqFM7F/3zGVJMjCOG4wqtrmExR9v0B+i8Q/k5P9gC3AKapkBkw7yRDADbd3Yq0
         I8HA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=ndRXU9f0;
       spf=pass (google.com: domain of justinstitt@google.com designates 2607:f8b0:4864:20::d29 as permitted sender) smtp.mailfrom=justinstitt@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-io1-xd29.google.com (mail-io1-xd29.google.com. [2607:f8b0:4864:20::d29])
        by gmr-mx.google.com with ESMTPS id 41be03b00d2f7-af281279d14si198662a12.5.2025.03.07.15.12.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 07 Mar 2025 15:12:41 -0800 (PST)
Received-SPF: pass (google.com: domain of justinstitt@google.com designates 2607:f8b0:4864:20::d29 as permitted sender) client-ip=2607:f8b0:4864:20::d29;
Received: by mail-io1-xd29.google.com with SMTP id ca18e2360f4ac-855184b6473so164018939f.2
        for <kasan-dev@googlegroups.com>; Fri, 07 Mar 2025 15:12:41 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCWIlYfI2v6ismIb2snKZlIYjN9sIkjcSQrwXK4LfClERpXAp3hfTwJ+CuDJeljYskw/P4nLmczH5x0=@googlegroups.com
X-Gm-Gg: ASbGncug4j6kSU+a8FpHeaYW6dOV+TSVwqJ73ug35bWxfrtH78GmDFd0Ns79xoCNkI9
	MT2AXQcSrGQU+c+h3LSJEd8IXT+4e7SxYy9VyY6SPaM3dQpip7WcHkm1K/og4smhfH/xZXlyyrj
	1h3zFAurrPR5hKHnjJYWhKq/+vJJLroJXTnA0VhV5AGlQr3x8NRhU/x2iddTaOjMFx7tQYkR3oA
	RKrM+gXEN0BsBtWSpeGexBjlQ45j9XFy6mcbcGoJtIYENiFwZFbgtZfsQqK91wVUEU5rjB+NZGg
	dLOit5CD6xQRe5oy4+qbarg+/RFLrk7p5dsn/RHcN15nlNDEf0SngdX/9f4IUIEz0xLL0p6sfuG
	FkXo3lk1X
X-Received: by 2002:a05:6602:c8a:b0:85a:eff8:4ce0 with SMTP id ca18e2360f4ac-85b1cf7fbb6mr661020739f.1.1741389161258;
        Fri, 07 Mar 2025 15:12:41 -0800 (PST)
Received: from google.com (26.80.59.108.bc.googleusercontent.com. [108.59.80.26])
        by smtp.gmail.com with ESMTPSA id 8926c6da1cb9f-4f216f55378sm681019173.109.2025.03.07.15.12.40
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 07 Mar 2025 15:12:40 -0800 (PST)
Date: Fri, 7 Mar 2025 15:12:35 -0800
From: "'Justin Stitt' via kasan-dev" <kasan-dev@googlegroups.com>
To: Kees Cook <kees@kernel.org>
Cc: "Gustavo A. R. Silva" <gustavoars@kernel.org>, 
	Masahiro Yamada <masahiroy@kernel.org>, Nathan Chancellor <nathan@kernel.org>, 
	Nicolas Schier <nicolas@fjasle.eu>, Marco Elver <elver@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	linux-kbuild@vger.kernel.org, kasan-dev@googlegroups.com, linux-hardening@vger.kernel.org, 
	Andrew Morton <akpm@linux-foundation.org>, Miguel Ojeda <ojeda@kernel.org>, 
	Nick Desaulniers <ndesaulniers@google.com>, Hao Luo <haoluo@google.com>, 
	Przemek Kitszel <przemyslaw.kitszel@intel.com>, Bill Wendling <morbo@google.com>, 
	Jakub Kicinski <kuba@kernel.org>, Tony Ambardar <tony.ambardar@gmail.com>, 
	Alexander Potapenko <glider@google.com>, Jan Hendrik Farr <kernel@jfarr.cc>, 
	Alexander Lobakin <aleksander.lobakin@intel.com>, linux-kernel@vger.kernel.org, llvm@lists.linux.dev
Subject: Re: [PATCH 2/3] ubsan/overflow: Enable pattern exclusions
Message-ID: <yduqbthmtpc5e2n4u73ofbp326chk3qdkgdiyrgmwcbhgeqceq@yybbkifwt4zk>
References: <20250307040948.work.791-kees@kernel.org>
 <20250307041914.937329-2-kees@kernel.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250307041914.937329-2-kees@kernel.org>
X-Original-Sender: justinstitt@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=ndRXU9f0;       spf=pass
 (google.com: domain of justinstitt@google.com designates 2607:f8b0:4864:20::d29
 as permitted sender) smtp.mailfrom=justinstitt@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
X-Original-From: Justin Stitt <justinstitt@google.com>
Reply-To: Justin Stitt <justinstitt@google.com>
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

Hi,

On Thu, Mar 06, 2025 at 08:19:10PM -0800, Kees Cook wrote:
> To make integer wrap-around mitigation actually useful, the associated
> sanitizers must not instrument cases where the wrap-around is explicitly
> defined (e.g. "-2UL"), being tested for (e.g. "if (a + b < a)"), or
> where it has no impact on code flow (e.g. "while (var--)"). Enable
> pattern exclusions for the integer wrap sanitizers.
> 
> Signed-off-by: Kees Cook <kees@kernel.org>
> ---
> Cc: Justin Stitt <justinstitt@google.com>
> Cc: "Gustavo A. R. Silva" <gustavoars@kernel.org>
> Cc: Masahiro Yamada <masahiroy@kernel.org>
> Cc: Nathan Chancellor <nathan@kernel.org>
> Cc: Nicolas Schier <nicolas@fjasle.eu>
> Cc: Marco Elver <elver@google.com>
> Cc: Andrey Konovalov <andreyknvl@gmail.com>
> Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>
> Cc: linux-kbuild@vger.kernel.org
> Cc: kasan-dev@googlegroups.com
> Cc: linux-hardening@vger.kernel.org
> ---
>  lib/Kconfig.ubsan      | 1 +
>  scripts/Makefile.ubsan | 1 +
>  2 files changed, 2 insertions(+)
> 
> diff --git a/lib/Kconfig.ubsan b/lib/Kconfig.ubsan
> index 63e5622010e0..888c2e72c586 100644
> --- a/lib/Kconfig.ubsan
> +++ b/lib/Kconfig.ubsan
> @@ -120,6 +120,7 @@ config UBSAN_INTEGER_WRAP
>  	bool "Perform checking for integer arithmetic wrap-around"
>  	default UBSAN
>  	depends on !COMPILE_TEST
> +	depends on $(cc-option,-fsanitize-undefined-ignore-overflow-pattern=all)

This option group "all" may be expanded in the future, e.g., negations
of unsigned integers (not just unsigned integer literals). As these are
deliberately designed for the kernel, I think we will want them anyways.
So, all is good.

>  	depends on $(cc-option,-fsanitize=signed-integer-overflow)
>  	depends on $(cc-option,-fsanitize=unsigned-integer-overflow)
>  	depends on $(cc-option,-fsanitize=implicit-signed-integer-truncation)
> diff --git a/scripts/Makefile.ubsan b/scripts/Makefile.ubsan
> index 4fad9afed24c..233379c193a7 100644
> --- a/scripts/Makefile.ubsan
> +++ b/scripts/Makefile.ubsan
> @@ -15,6 +15,7 @@ ubsan-cflags-$(CONFIG_UBSAN_TRAP)		+= $(call cc-option,-fsanitize-trap=undefined
>  export CFLAGS_UBSAN := $(ubsan-cflags-y)
>  
>  ubsan-integer-wrap-cflags-$(CONFIG_UBSAN_INTEGER_WRAP)     +=	\
> +	-fsanitize-undefined-ignore-overflow-pattern=all	\
>  	-fsanitize=signed-integer-overflow			\
>  	-fsanitize=unsigned-integer-overflow			\
>  	-fsanitize=implicit-signed-integer-truncation		\
> -- 
> 2.34.1
> 

Reviewed-by: Justin Stitt <justinstitt@google.com>

Justin

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/yduqbthmtpc5e2n4u73ofbp326chk3qdkgdiyrgmwcbhgeqceq%40yybbkifwt4zk.
