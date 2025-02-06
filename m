Return-Path: <kasan-dev+bncBD22BAF5REGBB34RSC6QMGQEVBRG77I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33f.google.com (mail-wm1-x33f.google.com [IPv6:2a00:1450:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id E1837A29E1A
	for <lists+kasan-dev@lfdr.de>; Thu,  6 Feb 2025 01:57:21 +0100 (CET)
Received: by mail-wm1-x33f.google.com with SMTP id 5b1f17b1804b1-4362f893bfasf1723545e9.1
        for <lists+kasan-dev@lfdr.de>; Wed, 05 Feb 2025 16:57:21 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1738803441; cv=pass;
        d=google.com; s=arc-20240605;
        b=SzkRhXOkd5pecLPhX7g37eI2cypp3Fb91I2xPEkd27hhr9/4/LNZuo0uk3WyaT6H/D
         JEm50X8RvKBMH+dTlkcxPGDrDwA2KTli7jUDQpvJXaIZ4JXYRMChz0GHUdGRmE35xbD1
         1GjdYHSOwQMaNOn/QCxqC2DaUL4ocz6X87Eo/R7w4QVtgyI8GXGKrQpDxcsc7HO8tBjK
         OFGzkWHQ2X5/5E+bAnsEzn0f17uJwwxvMkx6xbiCSEkWCzS7DVut43GCvcy9+NwEKwXI
         D4BFWulzx7z0+DZtAhZYkM1w/LQuuaF5zkiuEyYukr4fjJRYiLmRioMfiwJ23pnZvJsM
         k65w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:autocrypt
         :content-language:from:references:cc:to:subject:user-agent
         :mime-version:date:message-id:sender:dkim-signature;
        bh=VQDOOI3zJlu17mAVv7Uaf0oB8K+C/392BngCEDTPDxQ=;
        fh=RtT8fnzLXnKpRm5urtb13k3X+uMsInOLT/gHfaC0OnA=;
        b=kcNzCsR4FV+8W0PCov7Y0ObfmTXeTWNEgecKbF0k3iqWckwR2TeziA/szSsX4NpZs4
         25ReC1/gG9Y1kUcT4zTQrrubBfHk225FVpVNgjmDhqudWCcqD8MrqM8DRdeOuGrDN4Da
         5//QocQVUFs2AQxrl5cvSr/rl9kwu+R7/TXb0R3AEgZ8KWwqtJMTXAasHwAqCxe728Cz
         cVxDXUJgnpEsbnF5RkP3CLhpxC1Kmc3pA2mBUgwYNP+CBy4UHekmDi4wkpSkUhrrIlys
         CUcKa4BrZkiHtuKJYvD1bUU4G5TSXYMLMLN+4apOAQgytZZ9pVxomB9WEnouu7CnT6o0
         b8Xg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=QqOOxwD2;
       spf=pass (google.com: domain of dave.hansen@intel.com designates 192.198.163.13 as permitted sender) smtp.mailfrom=dave.hansen@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1738803441; x=1739408241; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:autocrypt:content-language:from
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=VQDOOI3zJlu17mAVv7Uaf0oB8K+C/392BngCEDTPDxQ=;
        b=a0I92POgya5Er6N1jvInYCLokW+Gf+vlu8T9agIJP/YJmhEXjHAWpV1570iee6WSEW
         os4mkaERD5OjiE6Ymx6IxvMdm54H1H/gzQXKqpaI4mPKfwUgX7X8Mk3ROzpiFXINPXc/
         C0Xoa6j325adyl7csDGF87Ab1sApfv2l8HKXUNZiJ0UgGZ/pUDYOglPFBMgFoTUHls/Z
         o8NKzyy7fUBNnV7yob2X7ijSsWFP7t7gOyFchdwBhw5sVPGZlFSOa1kwdjaAFPG+Sn5A
         0Qavnp0+tI2YD5n5iiYx0eTpDPeihH1tHAkHKh9F0+UsIBugkfBeo6wQ7gttSropsAAn
         rYZQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1738803441; x=1739408241;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :autocrypt:content-language:from:references:cc:to:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=VQDOOI3zJlu17mAVv7Uaf0oB8K+C/392BngCEDTPDxQ=;
        b=wMmZoqNEaeURzPOKmHNP7GhDS2dUv6u8+0W9x/Pu5cvQT2V3c3S1ZAgKgkpQRbzcJ0
         5KcQ1E2eMrYcYEqFMNpTX5AHPpnPc7n3uSlfZOWM6G/FPIEWgVjABUqQnve+fZLYIQV0
         0RbS1siXQi8VthhioDYPY4brr1XBcT1Eg3v/SFJd9hNgqX0yKbzcsrUWZ953810J7O6O
         WwoUUtXI26UBU3YsWyMPmzBW8ChiB01vL5bK5LtVQszTjijoFwtksePUfL25A1und2Dw
         iJhFtY3rI+rSGcghYmV83I4RH25y0ZJ/1ic8eyge5QtgUPuK3ylZ2GpJuoKYI3lpRtst
         +iJA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXdCiZRINvxajddUFTbvDW+grPh5/X1yUduC7eJy/8p3AqAE4kfBi5hqlcPzveNCqiIu/9udQ==@lfdr.de
X-Gm-Message-State: AOJu0YxomxfxQR+2FZo+PRg3UNPoPW0SuuFgryQQulPTxUeEpQwA6ggJ
	wq6RtFEGiDY9qlZkaGH1FoHKhtBfjUYfVxXJVlDB4UwPgYY6dIWn
X-Google-Smtp-Source: AGHT+IFmi66RL0k0FD+49Uk3aCPaayIgqrreavwydV3LNReO8rA1yKJzyVQwwl70J1p5jwg9zAujSg==
X-Received: by 2002:a05:600c:4ecb:b0:434:a91e:c709 with SMTP id 5b1f17b1804b1-4390d5a3a1amr36910105e9.28.1738803439847;
        Wed, 05 Feb 2025 16:57:19 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:a385:0:b0:385:ee3e:ab95 with SMTP id ffacd0b85a97d-38dbad334e4ls161828f8f.0.-pod-prod-08-eu;
 Wed, 05 Feb 2025 16:57:17 -0800 (PST)
X-Received: by 2002:a05:6000:4020:b0:38c:5c1d:2862 with SMTP id ffacd0b85a97d-38db485eeb6mr3437802f8f.1.1738803437550;
        Wed, 05 Feb 2025 16:57:17 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1738803437; cv=none;
        d=google.com; s=arc-20240605;
        b=O1yuXG8IOF6URFeWeedjb1FAhGCHTE/ZKqk8AWshqCGJCvcfyWxA0d3QGN6gV6LgTO
         h8/6f09Md/i2YI6a3skyTXKvJs5HiPiV3pee06rurpV9bSex2UDUWIL8pfqw/iphszQu
         5jKK/QIk55k898D//KFfkBpe8l+zy7j6cxfXKTJVqNbFF9djitVxyenskXBL6F3vKSDT
         jodBp3AjfIVU7K1xWihQv8EzVSY+4bu92BttOIwTs+T5n8x6i77OIKZlWB2JIsSdhYqQ
         MBT/qqm9X4wwLxuy4rWiV9LJQCQnJleg/A54j7/NU+5K7Yo50qxKkWVHkDKqb1hnBe40
         hMlw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:autocrypt:content-language
         :from:references:cc:to:subject:user-agent:mime-version:date
         :message-id:dkim-signature;
        bh=/nvvAJjOy6QT4xML0BO6OwwyY5TsvLMtVksm23H0hhg=;
        fh=pea/EP8u7fyMC120xZif1wUujoEc2vgihBUBKrtJ1F8=;
        b=bzgpaYGrm6xjexWkV9q5LvSsJuoiu0YsDaIlkfhvwkfWQ+iChOTcvGl4vBmMzoA3O5
         wZ73qRxxNYa+51OFPHde63haIlOy0kXgw2coCYZffpTb0EShXRK2AFprv+zEB3DH4HoY
         /kthNwt1Q/nJ5EmMUyIwb2EslFbWNXOWoHIxK1TcFju4Muro8edSrk8Ye0E+N7xocnld
         7sVJNokRZ7wkAFZjhTPsnGoirm2JHbw+NNV/1PE0mZMt1l+0RBTOtht4VdT/Duw1/0Fz
         fcYlydW/xWH+G/uaHDWxsoW6TX04znVqfKfxLvAwB1qdgsiNVR+Coy2OwAcU07pCbR4L
         KXwg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=QqOOxwD2;
       spf=pass (google.com: domain of dave.hansen@intel.com designates 192.198.163.13 as permitted sender) smtp.mailfrom=dave.hansen@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [192.198.163.13])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-38dbde1c789si5195f8f.5.2025.02.05.16.57.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Wed, 05 Feb 2025 16:57:17 -0800 (PST)
Received-SPF: pass (google.com: domain of dave.hansen@intel.com designates 192.198.163.13 as permitted sender) client-ip=192.198.163.13;
X-CSE-ConnectionGUID: w2BPhPyQQ0yIjdrlNjLycw==
X-CSE-MsgGUID: adJKknpDSEKDgFKikqnRZw==
X-IronPort-AV: E=McAfee;i="6700,10204,11336"; a="42231260"
X-IronPort-AV: E=Sophos;i="6.13,263,1732608000"; 
   d="scan'208";a="42231260"
Received: from fmviesa007.fm.intel.com ([10.60.135.147])
  by fmvoesa107.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 05 Feb 2025 16:57:15 -0800
X-CSE-ConnectionGUID: Ij/bjUBYSeCrQkzss4lIxg==
X-CSE-MsgGUID: H5HXzbVLQDq891KmmFx/mQ==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.13,263,1732608000"; 
   d="scan'208";a="110966239"
Received: from aschofie-mobl2.amr.corp.intel.com (HELO [10.125.110.153]) ([10.125.110.153])
  by fmviesa007-auth.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 05 Feb 2025 16:57:13 -0800
Message-ID: <c344dfaa-7e79-498f-89d7-44631140d0f4@intel.com>
Date: Wed, 5 Feb 2025 16:57:15 -0800
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH 08/15] x86: Physical address comparisons in fill_p*d/pte
To: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>, luto@kernel.org,
 xin@zytor.com, kirill.shutemov@linux.intel.com, palmer@dabbelt.com,
 tj@kernel.org, andreyknvl@gmail.com, brgerst@gmail.com, ardb@kernel.org,
 dave.hansen@linux.intel.com, jgross@suse.com, will@kernel.org,
 akpm@linux-foundation.org, arnd@arndb.de, corbet@lwn.net,
 dvyukov@google.com, richard.weiyang@gmail.com, ytcoode@gmail.com,
 tglx@linutronix.de, hpa@zytor.com, seanjc@google.com,
 paul.walmsley@sifive.com, aou@eecs.berkeley.edu, justinstitt@google.com,
 jason.andryuk@amd.com, glider@google.com, ubizjak@gmail.com,
 jannh@google.com, bhe@redhat.com, vincenzo.frascino@arm.com,
 rafael.j.wysocki@intel.com, ndesaulniers@google.com, mingo@redhat.com,
 catalin.marinas@arm.com, junichi.nomura@nec.com, nathan@kernel.org,
 ryabinin.a.a@gmail.com, dennis@kernel.org, bp@alien8.de,
 kevinloughlin@google.com, morbo@google.com, dan.j.williams@intel.com,
 julian.stecklina@cyberus-technology.de, peterz@infradead.org, cl@linux.com,
 kees@kernel.org
Cc: kasan-dev@googlegroups.com, x86@kernel.org,
 linux-arm-kernel@lists.infradead.org, linux-riscv@lists.infradead.org,
 linux-kernel@vger.kernel.org, linux-mm@kvack.org, llvm@lists.linux.dev,
 linux-doc@vger.kernel.org
References: <cover.1738686764.git.maciej.wieczor-retman@intel.com>
 <2c2a71ec844db597f30754dd79faf87c9de0b21f.1738686764.git.maciej.wieczor-retman@intel.com>
From: Dave Hansen <dave.hansen@intel.com>
Content-Language: en-US
Autocrypt: addr=dave.hansen@intel.com; keydata=
 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
In-Reply-To: <2c2a71ec844db597f30754dd79faf87c9de0b21f.1738686764.git.maciej.wieczor-retman@intel.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dave.hansen@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=QqOOxwD2;       spf=pass
 (google.com: domain of dave.hansen@intel.com designates 192.198.163.13 as
 permitted sender) smtp.mailfrom=dave.hansen@intel.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=intel.com
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

On 2/4/25 09:33, Maciej Wieczor-Retman wrote:
> @@ -287,7 +287,7 @@ static pte_t *fill_pte(pmd_t *pmd, unsigned long vaddr)
>  	if (pmd_none(*pmd)) {
>  		pte_t *pte = (pte_t *) spp_getpage();
>  		pmd_populate_kernel(&init_mm, pmd, pte);
> -		if (pte != pte_offset_kernel(pmd, 0))
> +		if (__pa(pte) != __pa(pte_offset_kernel(pmd, 0)))
>  			printk(KERN_ERR "PAGETABLE BUG #03!\n");
>  	}
>  	return pte_offset_kernel(pmd, vaddr);

Maciej, could you do a quick check on this and make sure that it doesn't
hurt code generation on current kernels?

pte_offset_kernel() has an internal __va() so this ends up logically
being something like:

-	if (     pte  !=      __va(pmd))
+	if (__pa(pte) != __pa(__va(pmd)))

The __pa() and __va() obviously logically cancel each other out in the
new version. But if the compiler for whatever reason can't figure this
out we might end up with worse code.

If it generates crummy code we might want to do this differently like
avoiding pte_offset_kernel() and adding some other helper that's more
direct and to the point.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/c344dfaa-7e79-498f-89d7-44631140d0f4%40intel.com.
