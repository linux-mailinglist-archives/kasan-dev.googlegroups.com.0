Return-Path: <kasan-dev+bncBCP4ZTXNRIFBBSWSYTXQKGQEDVP4Y4Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x140.google.com (mail-lf1-x140.google.com [IPv6:2a00:1450:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id 0C69311BA6E
	for <lists+kasan-dev@lfdr.de>; Wed, 11 Dec 2019 18:37:15 +0100 (CET)
Received: by mail-lf1-x140.google.com with SMTP id t3sf3306439lfp.15
        for <lists+kasan-dev@lfdr.de>; Wed, 11 Dec 2019 09:37:15 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1576085834; cv=pass;
        d=google.com; s=arc-20160816;
        b=iYl9HSv3cPeJColm90PEPjGpFGHPjaBx4mBRroZgqF6/F+E8495XTzl6sMvGR3M6Ux
         CFDdykCdCl5tTQRfYF01vWDRT1jhUuf/Lgmtk8s1mt2aH4bPXnyP74s7wgNEpoZY51WI
         jjTGksExNUg4tW1H5q5AOJXyTSklSTiI+Z+LTvlfme/TYIHZUbTNTXdepqofrnFpkeUL
         Jq0Uj5rlwirdZs0+rj6j9ag/JndB+SxuJdkDHvlOgMFdG9p4RnJdTW2j99N4T8jFVbeP
         L0415REJZPQ3uMm9TGlLLeRJXgN6QZPm8yhawITq5N3xBeMz5CNErV1cXrUfFDIbJ6wq
         T/6A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=8oNwaOZPgDxqV/21/5wsybr9T5l63JqUmO9kEJ0gcy8=;
        b=t0r0vRW5S5FlA10XcK+m/ssEe9GCQ8sogqTcqOLUoFeVb88f06sKFb8ofQGgyG5aat
         OGf3m8qkkaCYFmOTV84ABKLw7xeZa5nkZUF0cE79AjkqSqC1gGQdGSPtcU/d2dfdQ0E2
         2jVk+MlQyPoyiK9fYvgVRFj6895K64PERQ3D2FxgY94Tb8SS9hJX1fVTRpY5vAynML0W
         VKAiLyTE+v+ogr66H6Nig+pHchvIyDagb8h/fCaM7luMmXIuEmyTayofh6MCcLchlKEa
         gmplAmInECpNO1U8X9skuAmBIF6bDTu1i63rweBcHk1/Bxp5ml1p6nKiE4tYai5rPAId
         xs7Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@alien8.de header.s=dkim header.b=j3MRlnLT;
       spf=pass (google.com: domain of bp@alien8.de designates 2a01:4f8:190:11c2::b:1457 as permitted sender) smtp.mailfrom=bp@alien8.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=alien8.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=8oNwaOZPgDxqV/21/5wsybr9T5l63JqUmO9kEJ0gcy8=;
        b=Fz8QIA1iO9I7mladVmb1pRc4NT+dqYTntCGLD7ZwF335j9wuK8hmQUpoHMDabp6DdQ
         t4dRytepFc7rVgXwqkhZHUrASzAJOBK0rfjIis8RQ5cU0ThPG35DAu+TbeWbv/wEk9fG
         6aRHIHJgamjMKL5CfEgaEGSS3zNxIuvoSIhwo5QRTGCrSeWnhh4ng9nPl0yH9l6usDX8
         HfjdgexRcOJraNNVvDyBDsOSxGgPkgzFirHSUx91znzeUu2l1654XU5V5m06HpLSFp6h
         BNIC6ZuzZ4NhOFy+O2bPAnZZBWzcdu80yp2JUTPPI4AznNSLoj3Mm5hDHWlPj7b+rVUw
         2JLQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=8oNwaOZPgDxqV/21/5wsybr9T5l63JqUmO9kEJ0gcy8=;
        b=iLaiuQ627T+1J64HFJqT0FA5KxIWKhGPodnkRfcWSkw9mjsxF5gpykprQY/CYnj8rP
         zfBM+S/TrWI3UX0RxYAkHhTMSuG1xDQToXgCkaAVlLXgfU8a2YoI/LOYf4h5cJJxNqxO
         BqCGA+VCPhZbpAhbife8dsDO6PVq60cXV2AG5m9oBIDJTrqgfmncj++OFtFFdEgpzF8S
         wLMYAsQ0aPhDhaA9xH7x1ppI01lTwY9PIYZyL4wfu+6QlDrL9Z0oJBhZ3SFZgCDGIJJf
         okEBAbdyCUkHpRNTcDAMKWSCAsGzkxM2XuBa+iAVxbYCIBV/C5rvtFOILPlgHXTebvc0
         R6JA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAWgfKbtWo/Wq8C9LtpoLVlVUoSg6MH8ydk5oOVyYgDqhkGiUAZc
	lvKvYGnUPo1HbU3NQW+yiXw=
X-Google-Smtp-Source: APXvYqyYSEB8mLsYglYHAJWBNC05cPj1Cyye4A/i4jN6m6TmOOcpqFyR6T7CP8bHQGP87Kci6/EIlA==
X-Received: by 2002:a19:5212:: with SMTP id m18mr2991788lfb.7.1576085834569;
        Wed, 11 Dec 2019 09:37:14 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:3a07:: with SMTP id h7ls422776lja.3.gmail; Wed, 11 Dec
 2019 09:37:14 -0800 (PST)
X-Received: by 2002:a05:651c:1b5:: with SMTP id c21mr3088788ljn.115.1576085833999;
        Wed, 11 Dec 2019 09:37:13 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1576085833; cv=none;
        d=google.com; s=arc-20160816;
        b=IaL1mfGGHfUhuxNkYgPSkkjPsgT2LUJJspPx7SU5+y6ronSQAmiOt0tidxcUCQGYW7
         HV0n1wiE5ydp1Gq1P9fWT0qMHNcer1kZ8WWBcW/ZMW6F+069eIWeVmnyZsB+6ZkjtgMu
         DaNMHtw4AhvJBmbwgFNlpFNGTnAnduao5SIde1rW4C9u5GLo1A1U4vu+yJvVSnDKQMAQ
         zEAY4tEpKAgX6eSTAXf6aSiDMMGeuy+RnZTeak00k3p38wgERsg8KbXFocmvk0FbDbG6
         /OAeTD3k/asOlTacEPZIS7DO3GcUeqXKmjTB+V86mNglFQP6ULCEtj7xtVO7hPEm3Awa
         Z+Fg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=/fQSVH4e2kOh1ufr5QULeFyUccGwjWVFvNcXOqos5bc=;
        b=0mPDLGjlobUlpdJaao6PgXqypqXbdFrN4IBtjKAPPC+ip2MiDjh1ayVtI33PD6f14l
         oxM32K40L+DVh/vKCCBIQK7/KDwk7B65IFnSA7FGfYtS+HJVztvS9bNAGYXAd4hdLbGA
         RIxnmRsC1hb1pdTop1bh7YPPYBI5cWVNEHkwg9oV3nCA3OtCepG3JVDNihh9DJTfEBX1
         q3R67zbG1QsnFMLZ/DlO3J7PnBrOC5604Ni9D4XzVPex6GjdCL5uy+TPGGi4OF+aLzVx
         A2NnoifXY5VOq7kmb0iT2qJro/If96f9PrObc7+z7jmOi4WzdP/GjRxJf2EBnuU/whnQ
         VZng==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@alien8.de header.s=dkim header.b=j3MRlnLT;
       spf=pass (google.com: domain of bp@alien8.de designates 2a01:4f8:190:11c2::b:1457 as permitted sender) smtp.mailfrom=bp@alien8.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=alien8.de
Received: from mail.skyhub.de (mail.skyhub.de. [2a01:4f8:190:11c2::b:1457])
        by gmr-mx.google.com with ESMTPS id a26si85578ljn.1.2019.12.11.09.37.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 11 Dec 2019 09:37:13 -0800 (PST)
Received-SPF: pass (google.com: domain of bp@alien8.de designates 2a01:4f8:190:11c2::b:1457 as permitted sender) client-ip=2a01:4f8:190:11c2::b:1457;
Received: from zn.tnic (p200300EC2F094900329C23FFFEA6A903.dip0.t-ipconnect.de [IPv6:2003:ec:2f09:4900:329c:23ff:fea6:a903])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.skyhub.de (SuperMail on ZX Spectrum 128k) with ESMTPSA id 17A371EC0591;
	Wed, 11 Dec 2019 18:37:13 +0100 (CET)
Date: Wed, 11 Dec 2019 18:37:12 +0100
From: Borislav Petkov <bp@alien8.de>
To: Jann Horn <jannh@google.com>
Cc: Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@redhat.com>,
	"H. Peter Anvin" <hpa@zytor.com>, x86@kernel.org,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>,
	Andy Lutomirski <luto@kernel.org>,
	Sean Christopherson <sean.j.christopherson@intel.com>
Subject: Re: [PATCH v6 4/4] x86/kasan: Print original address on #GP
Message-ID: <20191211173711.GF14821@zn.tnic>
References: <20191209143120.60100-1-jannh@google.com>
 <20191209143120.60100-4-jannh@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20191209143120.60100-4-jannh@google.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: bp@alien8.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@alien8.de header.s=dkim header.b=j3MRlnLT;       spf=pass
 (google.com: domain of bp@alien8.de designates 2a01:4f8:190:11c2::b:1457 as
 permitted sender) smtp.mailfrom=bp@alien8.de;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=alien8.de
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

On Mon, Dec 09, 2019 at 03:31:20PM +0100, Jann Horn wrote:
>  arch/x86/kernel/traps.c     | 12 ++++++++++-
>  arch/x86/mm/kasan_init_64.c | 21 -------------------
>  include/linux/kasan.h       |  6 ++++++
>  mm/kasan/report.c           | 40 +++++++++++++++++++++++++++++++++++++
>  4 files changed, 57 insertions(+), 22 deletions(-)

I need a KASAN person ACK here, I'd guess.

> diff --git a/arch/x86/kernel/traps.c b/arch/x86/kernel/traps.c
> index c8b4ae6aed5b..7813592b4fb3 100644
> --- a/arch/x86/kernel/traps.c
> +++ b/arch/x86/kernel/traps.c
> @@ -37,6 +37,7 @@
>  #include <linux/mm.h>
>  #include <linux/smp.h>
>  #include <linux/io.h>
> +#include <linux/kasan.h>
>  #include <asm/stacktrace.h>
>  #include <asm/processor.h>
>  #include <asm/debugreg.h>
> @@ -589,6 +590,8 @@ do_general_protection(struct pt_regs *regs, long error_code)
>  	if (!user_mode(regs)) {
>  		enum kernel_gp_hint hint = GP_NO_HINT;
>  		unsigned long gp_addr;
> +		unsigned long flags;
> +		int sig;
>  
>  		if (fixup_exception(regs, X86_TRAP_GP, error_code, 0))
>  			return;
> @@ -621,7 +624,14 @@ do_general_protection(struct pt_regs *regs, long error_code)
>  				 "maybe for address",
>  				 gp_addr);
>  
> -		die(desc, regs, error_code);
> +		flags = oops_begin();
> +		sig = SIGSEGV;
> +		__die_header(desc, regs, error_code);
> +		if (hint == GP_NON_CANONICAL)
> +			kasan_non_canonical_hook(gp_addr);
> +		if (__die_body(desc, regs, error_code))
> +			sig = 0;
> +		oops_end(flags, regs, sig);

Instead of opencoding it like this, can we add a

	die_addr(desc, regs, error_code, gp_addr);

to arch/x86/kernel/dumpstack.c and call it from here:

	if (hint != GP_NON_CANONICAL)
		gp_addr = 0;

	die_addr(desc, regs, error_code, gp_addr);

This way you won't need to pass down to die_addr() the hint too - you
code into gp_addr whether it was non-canonical or not.

The

+       if (addr < KASAN_SHADOW_OFFSET)
+               return;

check in kasan_non_canonical_hook() would then catch it when addr == 0.

Hmmm?

-- 
Regards/Gruss,
    Boris.

https://people.kernel.org/tglx/notes-about-netiquette

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191211173711.GF14821%40zn.tnic.
