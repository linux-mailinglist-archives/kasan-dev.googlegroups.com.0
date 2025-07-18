Return-Path: <kasan-dev+bncBC7IXAMWVUGBBGMK5HBQMGQE66WTPPQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63b.google.com (mail-pl1-x63b.google.com [IPv6:2607:f8b0:4864:20::63b])
	by mail.lfdr.de (Postfix) with ESMTPS id AEF9DB0A4A2
	for <lists+kasan-dev@lfdr.de>; Fri, 18 Jul 2025 14:59:07 +0200 (CEST)
Received: by mail-pl1-x63b.google.com with SMTP id d9443c01a7336-2356ce55d33sf34515365ad.0
        for <lists+kasan-dev@lfdr.de>; Fri, 18 Jul 2025 05:59:07 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1752843546; cv=pass;
        d=google.com; s=arc-20240605;
        b=eoP/aZNAT0Rcjdl/Qsruah78CuHkjlzlIod5raPLUgeFf6gPgPZpc1GuRwhXbK7ZzR
         fTmCmQBgHg/mZdlNI3/Vz3FJcupGPX6Nn3UUiNZqV5O8RqKGJIG0HIM8Ip35iElC+pR7
         azqe14HmG6UKVnWMbnePbXM8NWNaaVbvPl1ogxd2gd3Lk5NgKrlkkRYRK1bcnwq9CWaX
         2shFHai4Fi5XSiBdH/Enj4GpYcl5LbT+Sdw1W9zMZpmMP7Mj2WOoOLSvs+6vxmoAbXIU
         RcuND69c+O1/3MFKS4dPGav3PKr0+urcM7PxBCmJS5ng3m7cWzIQ5VqP96QaeSRTr+VE
         gbTg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=LpDSYqmgVIbpYt8mu9TVnbeY03NS6qahiv7/gzCWENs=;
        fh=9m/ul4nfnms3erdR8z1nxaprlS+IujPGwMHhl7fEk/A=;
        b=A3B27MZyB0X6rLXXs64LLNeob0+pggga/jVn6xZxyJ3VqNsr5oEQWLtLNVhQDBKXbp
         KIS9iNGndo7Cm32h3ij6cI/HihlMizAequ03I+AlW2MKxcJi1Ul/RbrrQiYc8MhAVlFG
         MjoSWWaWmz2YTxw6sUIdSeBKAPi9Cw+SP9bSYJ6nuvYpQ+zCk/cIWqtYVeoh2nXMFMRO
         E2miJ5w8iYpzC5iGjSQlTrmaj8Y+LhA5INcefznUUhMBrr/y5ZGhI3UK79tN8P9DXibU
         5P8GJbkYpK5q4RFlJnDALcxVgQrdiYUUGPl7qXg4YFXMWfWj0f7P7bV0zdg12ghPniKS
         y6nQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ti.com header.s=ti-com-17Q1 header.b=OHanrKrF;
       spf=pass (google.com: domain of nm@ti.com designates 198.47.19.246 as permitted sender) smtp.mailfrom=nm@ti.com;
       dmarc=pass (p=QUARANTINE sp=NONE dis=NONE) header.from=ti.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1752843546; x=1753448346; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=LpDSYqmgVIbpYt8mu9TVnbeY03NS6qahiv7/gzCWENs=;
        b=E+ptwGJBL0m7vUhfo8YC01NgprHWXdkqvbKTW+/kSPIEFaaPEsIJ3DujgKY5l0G2KU
         HmgRjh30bPs4pMkJokryTk9ydwAuqxe2MS0iu0VAFPmlLH7dPcdWYVgV3jny8tAbCGk6
         bwK0kwpVIi1v/5R3om8/a6agIBaecYKlH7HY9eXuvOD9ibXSRtL2x4UCyBTPATjP59m5
         sXGfrhrorzYpsNzyBkM6tgpZNUzpXgxkXEAp2v7yUo9VA+fkxu4i7KJguzgVU07qXeHM
         NxiFTPgp881Vip4m9A9aRs1MifKMuQ1FuiTXOzxlqWQSyfObpcSZs5xI/oNAT6CFsASJ
         MiwQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1752843546; x=1753448346;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=LpDSYqmgVIbpYt8mu9TVnbeY03NS6qahiv7/gzCWENs=;
        b=fDDtDz5fqzo97/1ivUDzD8vf2xACWH3iw1zWxabu5LwEpzmxaSO2VbChYEwGtHmiRj
         9Yclzu8dOGJInXSGYTTqIdqLR1Ja+mt7CDHlx7MieHeDCX8MutTiQxGiweyaTgnZt7iO
         t/6rSISx5YOYHzlNp3sw6iRCbNar2ekxOLXVuwcWAew9rnWan9yVhSoUwY6+qwFeqGoy
         CEwY3a2Jozc1L5A1ATXDGPUw/1qxmAu+/U0QT+kS9ixDpesMynG+48nBlpb/2K6EXcmT
         xzDTroEUfP/Ip54A76+JZRCIPgIUpnEm1xFlW6dHjWEzmMcztOc/WRFNMrHiFcd+h8CR
         E1cg==
X-Forwarded-Encrypted: i=2; AJvYcCV4d71EHBSzytOM9uDPrwxkIUQxYsJYGhj/PlZyfXg9B5LQKGJ+7K6RPYe6q05Rkiub2QznnA==@lfdr.de
X-Gm-Message-State: AOJu0YwGpJ2sZVtekfG63mGHjUcPI6o4SWndKJrJ3vYyAoRriPCtgKch
	f5UXh9LT9HB9g2TPZjmsCSOuo6as8W4IKcvRJvOFpaVCrQqjSLEtDZ6F
X-Google-Smtp-Source: AGHT+IFcVcJmaWGq1FOT5xvl0f0LPgf84fcSqUgrgxAs8PgR+JRbttzZ870Ytaz1aYOEg7RUqkJztQ==
X-Received: by 2002:a17:903:46c8:b0:235:5a9:976f with SMTP id d9443c01a7336-23e30338031mr123985775ad.24.1752843545837;
        Fri, 18 Jul 2025 05:59:05 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdow5fLXUJVGXNk2An4EEmzPgfoJ5p6VIfUBdZLRn9K1A==
Received: by 2002:a17:903:13cc:b0:234:d1d3:ca2 with SMTP id
 d9443c01a7336-23e2ecf5cdels15538075ad.1.-pod-prod-03-us; Fri, 18 Jul 2025
 05:59:04 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUYDmuB5Hit4abSc/K7e+/PV+O1GafTolntShLZ47gE81gUeQjMWGNIreB965TlIavd/lfEdKrHzY4=@googlegroups.com
X-Received: by 2002:a17:903:3c2c:b0:234:c8f6:1b17 with SMTP id d9443c01a7336-23e3035f29bmr121277395ad.38.1752843544364;
        Fri, 18 Jul 2025 05:59:04 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1752843544; cv=none;
        d=google.com; s=arc-20240605;
        b=WDHC6mERio2En1mBke7uuGubK4dIyeVQH4HYSOFmq4kZR64IWKdgYs5pcCEoQAFVxO
         PAuQW5/5U90PgbiFGian2gIJuHEMjOLtiCqVN+oFioOizbRNwJKFXNKzttyz6V7rYoWc
         fXJMi5v0vv9iev7dnsnlqj3rnDDzPPT9pDf/t9qnVrjUZBG2PikQ5RD3nulsjv3RFKxb
         tN3Vy2rknTe6ISvSG4JW3ymmJgtuzx0zp7RNNK2bcyQGl39Qnb5e50tEBPAqjGvxYe1c
         eAyVTBtK7uAH4r5brRVWjCeC6tF+UlKMi9bs3sueSNt3TnbHvp0HZQCrf8PeniDZb+wt
         +y/Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=yUsTOiGa3kRqTBNBK7IpA6+SLe5En1zTCsg3sQMTpbs=;
        fh=UqBNHHBdXTkNJXdvdGGeSSZ5Mb6SNOvrs6iDE1ZNko4=;
        b=df+3KwNdyjkW14L+hCNQTxam4EgD5GUc72pheKJLgUNJUqwPKNICCDnsxhdTriTf4R
         rQuYyb4Ur46Wy2bftqyJMXjyOLDPes43HhvCKe+byx8E2yEyABtFoQvlNp5UMMb+X6fJ
         n/u0KqGphcNJqjFm8innQBqf4DGsfL/fV3kod/Rt5/dD3Gflf0D6TfrDQED+JDRY7PGn
         rJ7++WKdQSO+3iflCuUzhWv3Ze61MhTi3rxU72afm4Hl/F0W0NBg4cvE+Z9n4xKCs96I
         zmesLBJxVA54joOYnEVA7mQKwzyJgf0aa5Bf6Mrt/6CtG0e7VDP2Vh6BOk/0blEUQwqA
         XCqQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ti.com header.s=ti-com-17Q1 header.b=OHanrKrF;
       spf=pass (google.com: domain of nm@ti.com designates 198.47.19.246 as permitted sender) smtp.mailfrom=nm@ti.com;
       dmarc=pass (p=QUARANTINE sp=NONE dis=NONE) header.from=ti.com
Received: from fllvem-ot04.ext.ti.com (fllvem-ot04.ext.ti.com. [198.47.19.246])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-23e3b6a4f2csi735105ad.6.2025.07.18.05.59.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 18 Jul 2025 05:59:04 -0700 (PDT)
Received-SPF: pass (google.com: domain of nm@ti.com designates 198.47.19.246 as permitted sender) client-ip=198.47.19.246;
Received: from lelvem-sh02.itg.ti.com ([10.180.78.226])
	by fllvem-ot04.ext.ti.com (8.15.2/8.15.2) with ESMTP id 56ICwse5714132;
	Fri, 18 Jul 2025 07:58:54 -0500
Received: from DLEE114.ent.ti.com (dlee114.ent.ti.com [157.170.170.25])
	by lelvem-sh02.itg.ti.com (8.18.1/8.18.1) with ESMTPS id 56ICwsg43508025
	(version=TLSv1.2 cipher=ECDHE-RSA-AES128-SHA256 bits=128 verify=FAIL);
	Fri, 18 Jul 2025 07:58:54 -0500
Received: from DLEE115.ent.ti.com (157.170.170.26) by DLEE114.ent.ti.com
 (157.170.170.25) with Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256_P256) id 15.1.2507.55; Fri, 18
 Jul 2025 07:58:53 -0500
Received: from lelvem-mr06.itg.ti.com (10.180.75.8) by DLEE115.ent.ti.com
 (157.170.170.26) with Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256_P256) id 15.1.2507.55 via
 Frontend Transport; Fri, 18 Jul 2025 07:58:53 -0500
Received: from localhost (uda0133052.dhcp.ti.com [128.247.81.232])
	by lelvem-mr06.itg.ti.com (8.18.1/8.18.1) with ESMTP id 56ICwraF3541832;
	Fri, 18 Jul 2025 07:58:53 -0500
Date: Fri, 18 Jul 2025 07:58:53 -0500
From: "'Nishanth Menon' via kasan-dev" <kasan-dev@googlegroups.com>
To: Kees Cook <kees@kernel.org>
CC: Arnd Bergmann <arnd@arndb.de>, Russell King <linux@armlinux.org.uk>,
        Daniel Lezcano <daniel.lezcano@linaro.org>,
        Thomas Gleixner
	<tglx@linutronix.de>,
        Santosh Shilimkar <ssantosh@kernel.org>, Lee Jones
	<lee@kernel.org>,
        Allison Randal <allison@lohutok.net>,
        Greg Kroah-Hartman
	<gregkh@linuxfoundation.org>,
        <linux-arm-kernel@lists.infradead.org>,
        Ingo
 Molnar <mingo@kernel.org>,
        "Gustavo A. R. Silva" <gustavoars@kernel.org>,
        Christoph Hellwig <hch@lst.de>,
        Andrey Konovalov <andreyknvl@gmail.com>,
        Andrey Ryabinin <ryabinin.a.a@gmail.com>,
        Ard Biesheuvel <ardb@kernel.org>,
        Masahiro Yamada <masahiroy@kernel.org>,
        Nathan Chancellor
	<nathan@kernel.org>,
        Nicolas Schier <nicolas.schier@linux.dev>,
        Nick
 Desaulniers <nick.desaulniers+lkml@gmail.com>,
        Bill Wendling
	<morbo@google.com>,
        Justin Stitt <justinstitt@google.com>, <linux-kernel@vger.kernel.org>,
        <x86@kernel.org>, <kasan-dev@googlegroups.com>,
        <linux-doc@vger.kernel.org>, <kvmarm@lists.linux.dev>,
        <linux-riscv@lists.infradead.org>, <linux-s390@vger.kernel.org>,
        <linux-efi@vger.kernel.org>, <linux-hardening@vger.kernel.org>,
        <linux-kbuild@vger.kernel.org>,
        <linux-security-module@vger.kernel.org>,
        <linux-kselftest@vger.kernel.org>, <sparclinux@vger.kernel.org>,
        <llvm@lists.linux.dev>
Subject: Re: [PATCH v3 05/13] arm: Handle KCOV __init vs inline mismatches
Message-ID: <20250718125853.75g4nv2dnbkklud6@leggings>
References: <20250717231756.make.423-kees@kernel.org>
 <20250717232519.2984886-5-kees@kernel.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250717232519.2984886-5-kees@kernel.org>
X-C2ProcessedOrg: 333ef613-75bf-4e12-a4b1-8e3623f5dcea
X-Original-Sender: nm@ti.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ti.com header.s=ti-com-17Q1 header.b=OHanrKrF;       spf=pass
 (google.com: domain of nm@ti.com designates 198.47.19.246 as permitted
 sender) smtp.mailfrom=nm@ti.com;       dmarc=pass (p=QUARANTINE sp=NONE
 dis=NONE) header.from=ti.com
X-Original-From: Nishanth Menon <nm@ti.com>
Reply-To: Nishanth Menon <nm@ti.com>
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

On 16:25-20250717, Kees Cook wrote:
> When KCOV is enabled all functions get instrumented, unless
> the __no_sanitize_coverage attribute is used. To prepare for
> __no_sanitize_coverage being applied to __init functions, we have to
> handle differences in how GCC's inline optimizations get resolved. For
> arm this exposed several places where __init annotations were missing
> but ended up being "accidentally correct". Fix these cases and force
> several functions to be inline with __always_inline.
> 

[..]

> diff --git a/drivers/soc/ti/pm33xx.c b/drivers/soc/ti/pm33xx.c
> index dfdff186c805..dc52a2197d24 100644
> --- a/drivers/soc/ti/pm33xx.c
> +++ b/drivers/soc/ti/pm33xx.c
> @@ -145,7 +145,7 @@ static int am33xx_do_sram_idle(u32 wfi_flags)
>  	return pm_ops->cpu_suspend(am33xx_do_wfi_sram, wfi_flags);
>  }
>  
> -static int __init am43xx_map_gic(void)
> +static int am43xx_map_gic(void)
>  {
>  	gic_dist_base = ioremap(AM43XX_GIC_DIST_BASE, SZ_4K);

Reviewed-by: Nishanth Menon <nm@ti.com>

-- 
Regards,
Nishanth Menon
Key (0xDDB5849D1736249D) / Fingerprint: F8A2 8693 54EB 8232 17A3  1A34 DDB5 849D 1736 249D
https://ti.com/opensource

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250718125853.75g4nv2dnbkklud6%40leggings.
