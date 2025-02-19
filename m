Return-Path: <kasan-dev+bncBDW2JDUY5AORBJ6T3G6QMGQEYS4L2MA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23c.google.com (mail-lj1-x23c.google.com [IPv6:2a00:1450:4864:20::23c])
	by mail.lfdr.de (Postfix) with ESMTPS id 6EB31A3CD93
	for <lists+kasan-dev@lfdr.de>; Thu, 20 Feb 2025 00:30:50 +0100 (CET)
Received: by mail-lj1-x23c.google.com with SMTP id 38308e7fff4ca-30a2b657372sf1644501fa.2
        for <lists+kasan-dev@lfdr.de>; Wed, 19 Feb 2025 15:30:50 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1740007849; cv=pass;
        d=google.com; s=arc-20240605;
        b=ChQROLHCAagYxIYs2s520o6DdgsyLUEgnze1BJCbknkS7hc8gox8VuIrn3owFu7HkN
         IJUUiP5T9NLJF97AnKKEvBU8juMnrGBTTOFbkMzPMWCYdlLUUlshvsoH8JflfrD+dPd8
         yH2UcWDxDuADdETwgZ8HOJ+iqJMcBF7ZxmFc93v3NNS6vXYd8OStK9/SlO8/IelBUo4r
         lmxFiwI3r3ncS7Ru3r2bzdM6lVDywT/T3WwnCzlYRot+3UTzzd6WUMQ0QO6Pw+s9s0UM
         TvvfE4Ex/fyM5j0QnDCjeIMriOEdCFbG0UvI8b5/S8jp2jEu43wVItOPxrhGHsp7smC2
         CrRQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=4sRPQir5lzxjaN0KriUstdjcXOVlAK7HWFkgNdo6Hc0=;
        fh=puzihvFMEsflZp9KOFo/0q5sLIHQldmT6HsLAsKeyQI=;
        b=QfKKFZ+NkeeEEZY/smo/w82d9BYJYeSOg+xJbk9RIJ4RobCyJF5rHeQi6SK0F7phVY
         P0YoPxadP7xqmTDiNK08eu9nXT+5j/qzI9s8u40X/a49clzDw5OoYzNSfrrptHChm/C1
         latR8xRijq5/6T3sgqCMfeKn9mATfAMYpd0zWJeRpfHUSknFjTbLKxOaaYlPYIu6JOi+
         jrmRmzAWHWHRymUNjPyf5KtjYzMED2RSxpV8pKVhcfVWSTNe8l3UJSed85QrOYa6HwtT
         cBKN/Y33uSvtEntL+HGW8XnH0DJSvABTAlD8Of4qUoTrSSemrpqndnYfxsqAZg19Nc3x
         y9QQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="S/42uYSB";
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::433 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1740007849; x=1740612649; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=4sRPQir5lzxjaN0KriUstdjcXOVlAK7HWFkgNdo6Hc0=;
        b=p7ZIS0wB3YirqKQCq0EaNSITBdEZVtGgIr+0JGLVXvzd40CgQv+QajSZ0qPewlz5Ws
         TubKvGPDD6fs/lrUVV4wxochegDkjUR6pYzvk4MyMeS4+btQUUgbLuZ0t968U6k40c0y
         m0MS2n6r6o/BEoQp0gMWVWGpVwlbNdx/taR3QnHHzdJFSGyI0L9oG/beqmLi3pDW8eqx
         HdagjgpOFQlISSNnjOpk9XZs5fuHS+DvAyV2930avtIKKJ3tvpnYVlPoAtf3vTYyPG+e
         5mZ1f7eG5qJmY7Yd2UqOmSFnb+sD+d5s/K8BOO0ExKaEc6JoxpI5WgGpLkamBAlLe7ZI
         psxA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1740007849; x=1740612649; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=4sRPQir5lzxjaN0KriUstdjcXOVlAK7HWFkgNdo6Hc0=;
        b=fxb7d9NwW8B9KWON9PDTYqQiTrNVjlitvXIZ//DD06e6750mVd5e+z0fG1ueOGv8fH
         R3z4RqrIym69eENsOuIcKFYKZEktc/LYq9NIfvC7G+GE1jX2dcN6cPqNnL+coQ8073ej
         siGnNjtusoLKu1paJCkNFxNQMHipol6Or9uN2nDM0+fqL5UuOFA3JvmmTFVPns7+9aDn
         NmDohCL4jMZTMZWJoJqGzki8PjYcFCDPN51JvzliPdZIAkhS6opTXHcvctu04ZK+UUzj
         b1WLUti4TQRSK2uDas1afKGAZafMpZFYoIxK2l54gkjkakx9qZJUMO6n2t6AGEkzOgkd
         HzVw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1740007849; x=1740612649;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=4sRPQir5lzxjaN0KriUstdjcXOVlAK7HWFkgNdo6Hc0=;
        b=G3+/HzSwaaa2N9EDLeiy0Wv5dKdPyTQvJmxUqqlcYNurJ6BqkCqqopRyZKNtZ6sLD+
         lfsHcnl9oVab1R91QbST7H2/0cqgGRnCy2uaZz4Tmd3qsXcEP8RiimyHJ6+2dtFIcf1b
         Q0eFvHLlBGJtyE4tWnq06bXNfg25V9UeF5sPUwU1bynW8SJcd6FNTAGD0emLUKZFITtN
         3a1vt4QKRCsSXaZU4fu9/LZHZFLfzHuuk0Q1Gamz+bY0zdiCh5gOgkh9PSTSyxVK4Vme
         6fOkMFJ+N/7mrw1raHenBK15MV85X3Lk52bXf0LoFwPa0e5vwhLWwzpZHJYj3Lk76kYV
         LwhQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCV2ltYemAF4LLT/8S/N3j/U+lS9qFYDQPUJIFZNPEGb9l7M0p0aTjhY/23z1r8U2+DS2uQgXw==@lfdr.de
X-Gm-Message-State: AOJu0YznbCDx5ThfBk/PFhdjz5tDE1LXwl64zA7KIrYyWHFEl9KwlZUg
	uC8G6DPXvwztVree1yDRIuhN+c2gkcR76jq2cxzvm1+fCdE8bU2t
X-Google-Smtp-Source: AGHT+IE7SHjnu72dr21ODetfh29Tldw93YT+EYQdupymYqw0xhILvwOv+FN85oDZ4t5VD0FCKkNriw==
X-Received: by 2002:a2e:3611:0:b0:300:5c57:526b with SMTP id 38308e7fff4ca-30927a473fcmr58478211fa.11.1740007848210;
        Wed, 19 Feb 2025 15:30:48 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVFCHTwLSXJTlwC/Ks1Q5ST+uidjWCzUatI4naFg2pNT9Q==
Received: by 2002:a2e:be9f:0:b0:30a:2608:c739 with SMTP id 38308e7fff4ca-30a4ffcb045ls899351fa.1.-pod-prod-06-eu;
 Wed, 19 Feb 2025 15:30:45 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCX/HWpDU5JP1FLLuZc3jkb9MqxqtGOQJjO5lAJ2gqULonzSz/r2c98UugNDiE8GaRKAwkNSQ8BTnvE=@googlegroups.com
X-Received: by 2002:ac2:4e06:0:b0:544:11cf:10c1 with SMTP id 2adb3069b0e04-5452fe580a8mr6264294e87.30.1740007845555;
        Wed, 19 Feb 2025 15:30:45 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1740007845; cv=none;
        d=google.com; s=arc-20240605;
        b=T79SylPCcJ1T60VNKv5er007f8a6qkDbYB/NRfIBPLsEXOXlaGy2wBZOwvbouTkknm
         OSXBP0gsV+6+EmxiOKfDUNRWGcJ090xknHigjX/LEVKhxcugUKXVKWQWNAhdiiNH/ZtX
         vXnxUFZjAF6mjKRUifBxHb7frNGNlSUMsyG3Js/RFxIBrv0zOkgXomejF1nayZIduV/x
         Ab4wi7hWRwJPmrh7XW+zOyZ3jGu9fw7UHDzc+EpIhxfLEtMP4bjeF2JWcrMmzazh2hSR
         B4NqRG/vkJUEVz5Wdq7IyFoqbGB5UCB3nGTScoi76XFVRvfqSr3IAPzbrWeHlzMdLpZu
         ifVg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=iyvyq2lJRxuQLrIeQSGTnuwykD7l8YgAhKyJ7T0zXzs=;
        fh=K0M3pvwNPP7QcUJpd5Q6JgvsJLFL16qr9PVAGTJMuK4=;
        b=FaZ2XIK+1uSWWcAeoFZWvBHTqIxtz0iHR0XzmZ/jqiRvvCl01iK5kdd8f/JFPlayBr
         AUGb90+0wAhp7ATQ5u12TA/+RHBsS/q23qbSOIMmiolujgBkLMtgIgiGi7qq9mXbFcw6
         JSGJJo1WmvZAPMsik9/e5NzRyf4unqPbG31IpWlcJQyhAV8iXLZFlHexSPiofTVAyzyN
         VSITNkZ7OHJ3TI2jHb+zRjwhSTj0F0bWGa0a5RmyegdQY+3IUEhDMD1m38rfD9UjhI1h
         mF6fj1vwfTou5Pbe6i4jkNZ3TqFN4kerc5I8TEYWn5CP213aTinU56UUjMfoHtlYcJWF
         PjJg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="S/42uYSB";
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::433 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x433.google.com (mail-wr1-x433.google.com. [2a00:1450:4864:20::433])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-54526ecd5b4si136845e87.6.2025.02.19.15.30.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 19 Feb 2025 15:30:45 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::433 as permitted sender) client-ip=2a00:1450:4864:20::433;
Received: by mail-wr1-x433.google.com with SMTP id ffacd0b85a97d-38f26a82d1dso168808f8f.2
        for <kasan-dev@googlegroups.com>; Wed, 19 Feb 2025 15:30:45 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCUK5GOw8F3rI4SPjKJ+nDwJhfMRXyancVaafTJyPnDaXSVPpDTo1VP4zh5zyXRlF/Jd1nB1zuDnrU0=@googlegroups.com
X-Gm-Gg: ASbGncuNfRGWOnH0g2rjXPLu5OwNi6O+jStgckYjbFJInncdE6RHWsP1ZiA8NJAEi8y
	tmd9cSVtAkD41R/IYcVzGuCEJsndSiV4bKKyPH/flsVV5hSPg26T/LsQhHfYZftPdIjdatNjyO8
	c=
X-Received: by 2002:a5d:64e6:0:b0:38d:e092:3ced with SMTP id
 ffacd0b85a97d-38f33f1193cmr15640895f8f.7.1740007845049; Wed, 19 Feb 2025
 15:30:45 -0800 (PST)
MIME-Version: 1.0
References: <cover.1739866028.git.maciej.wieczor-retman@intel.com> <7099fb189737db12ab5ace5794080458d7a14638.1739866028.git.maciej.wieczor-retman@intel.com>
In-Reply-To: <7099fb189737db12ab5ace5794080458d7a14638.1739866028.git.maciej.wieczor-retman@intel.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Thu, 20 Feb 2025 00:30:34 +0100
X-Gm-Features: AWEUYZn8UfE_qbgWwdI_ZYXhFInJYUvvOaq2gnq6N0Mq2Y5hHq0QKSqyoBFpmX4
Message-ID: <CA+fCnZf16dzSjOLSeWXMaJLUR-b9x9_CY0JunaRaet_O_XNcsQ@mail.gmail.com>
Subject: Re: [PATCH v2 06/14] x86: Add arch specific kasan functions
To: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
Cc: kees@kernel.org, julian.stecklina@cyberus-technology.de, 
	kevinloughlin@google.com, peterz@infradead.org, tglx@linutronix.de, 
	justinstitt@google.com, catalin.marinas@arm.com, wangkefeng.wang@huawei.com, 
	bhe@redhat.com, ryabinin.a.a@gmail.com, kirill.shutemov@linux.intel.com, 
	will@kernel.org, ardb@kernel.org, jason.andryuk@amd.com, 
	dave.hansen@linux.intel.com, pasha.tatashin@soleen.com, 
	ndesaulniers@google.com, guoweikang.kernel@gmail.com, dwmw@amazon.co.uk, 
	mark.rutland@arm.com, broonie@kernel.org, apopple@nvidia.com, bp@alien8.de, 
	rppt@kernel.org, kaleshsingh@google.com, richard.weiyang@gmail.com, 
	luto@kernel.org, glider@google.com, pankaj.gupta@amd.com, 
	pawan.kumar.gupta@linux.intel.com, kuan-ying.lee@canonical.com, 
	tony.luck@intel.com, tj@kernel.org, jgross@suse.com, dvyukov@google.com, 
	baohua@kernel.org, samuel.holland@sifive.com, dennis@kernel.org, 
	akpm@linux-foundation.org, thomas.weissschuh@linutronix.de, surenb@google.com, 
	kbingham@kernel.org, ankita@nvidia.com, nathan@kernel.org, ziy@nvidia.com, 
	xin@zytor.com, rafael.j.wysocki@intel.com, andriy.shevchenko@linux.intel.com, 
	cl@linux.com, jhubbard@nvidia.com, hpa@zytor.com, 
	scott@os.amperecomputing.com, david@redhat.com, jan.kiszka@siemens.com, 
	vincenzo.frascino@arm.com, corbet@lwn.net, maz@kernel.org, mingo@redhat.com, 
	arnd@arndb.de, ytcoode@gmail.com, xur@google.com, morbo@google.com, 
	thiago.bauermann@linaro.org, linux-doc@vger.kernel.org, 
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	llvm@lists.linux.dev, linux-mm@kvack.org, 
	linux-arm-kernel@lists.infradead.org, x86@kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b="S/42uYSB";       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::433
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
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

On Tue, Feb 18, 2025 at 9:18=E2=80=AFAM Maciej Wieczor-Retman
<maciej.wieczor-retman@intel.com> wrote:
>
> KASAN's software tag-based mode needs multiple macros/functions to
> handle tag and pointer interactions - mainly to set and retrieve tags
> from the top bits of a pointer.
>
> Mimic functions currently used by arm64 but change the tag's position to
> bits [60:57] in the pointer.
>
> Signed-off-by: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
> ---
>  arch/x86/include/asm/kasan.h | 32 ++++++++++++++++++++++++++++++--
>  1 file changed, 30 insertions(+), 2 deletions(-)
>
> diff --git a/arch/x86/include/asm/kasan.h b/arch/x86/include/asm/kasan.h
> index de75306b932e..8829337a75fa 100644
> --- a/arch/x86/include/asm/kasan.h
> +++ b/arch/x86/include/asm/kasan.h
> @@ -3,6 +3,8 @@
>  #define _ASM_X86_KASAN_H
>
>  #include <linux/const.h>
> +#include <linux/kasan-tags.h>
> +#include <linux/types.h>
>  #define KASAN_SHADOW_OFFSET _AC(CONFIG_KASAN_SHADOW_OFFSET, UL)
>  #define KASAN_SHADOW_SCALE_SHIFT 3
>
> @@ -24,8 +26,33 @@
>                                                   KASAN_SHADOW_SCALE_SHIF=
T)))
>
>  #ifndef __ASSEMBLY__
> +#include <linux/bitops.h>
> +#include <linux/bitfield.h>
> +#include <linux/bits.h>
> +
> +#define arch_kasan_set_tag(addr, tag)  __tag_set(addr, tag)

But __tag_set is defined below. I think these need to be reordered.

> +#define arch_kasan_reset_tag(addr)     __tag_reset(addr)
> +#define arch_kasan_get_tag(addr)       __tag_get(addr)
> +
> +#ifdef CONFIG_KASAN_SW_TAGS
> +
> +#define __tag_shifted(tag)             FIELD_PREP(GENMASK_ULL(60, 57), t=
ag)
> +#define __tag_reset(addr)              (sign_extend64((u64)(addr), 56))
> +#define __tag_get(addr)                        ((u8)FIELD_GET(GENMASK_UL=
L(60, 57), (u64)addr))
> +#else
> +#define __tag_shifted(tag)             0UL
> +#define __tag_reset(addr)              (addr)
> +#define __tag_get(addr)                        0
> +#endif /* CONFIG_KASAN_SW_TAGS */
>
>  #ifdef CONFIG_KASAN
> +
> +static inline const void *__tag_set(const void *addr, u8 tag)

A bit weird that __tag_set is defined under CONFIG_KASAN:
CONFIG_KASAN_SW_TAGS (or no condition, like on arm64) would make more
sense.


> +{
> +       u64 __addr =3D (u64)addr & ~__tag_shifted(KASAN_TAG_KERNEL);
> +       return (const void *)(__addr | __tag_shifted(tag));
> +}
> +
>  void __init kasan_early_init(void);
>  void __init kasan_init(void);
>  void __init kasan_populate_shadow_for_vaddr(void *va, size_t size, int n=
id);
> @@ -34,8 +61,9 @@ static inline void kasan_early_init(void) { }
>  static inline void kasan_init(void) { }
>  static inline void kasan_populate_shadow_for_vaddr(void *va, size_t size=
,
>                                                    int nid) { }
> -#endif
>
> -#endif
> +#endif /* CONFIG_KASAN */
> +
> +#endif /* __ASSEMBLY__ */
>
>  #endif
> --
> 2.47.1
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
A%2BfCnZf16dzSjOLSeWXMaJLUR-b9x9_CY0JunaRaet_O_XNcsQ%40mail.gmail.com.
