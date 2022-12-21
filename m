Return-Path: <kasan-dev+bncBDCLJAGETYJBBS5FRSOQMGQELRNUU7Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3f.google.com (mail-yb1-xb3f.google.com [IPv6:2607:f8b0:4864:20::b3f])
	by mail.lfdr.de (Postfix) with ESMTPS id A640C653227
	for <lists+kasan-dev@lfdr.de>; Wed, 21 Dec 2022 15:06:04 +0100 (CET)
Received: by mail-yb1-xb3f.google.com with SMTP id n197-20020a25d6ce000000b00702558fba96sf17697560ybg.0
        for <lists+kasan-dev@lfdr.de>; Wed, 21 Dec 2022 06:06:04 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1671631563; cv=pass;
        d=google.com; s=arc-20160816;
        b=LOXXgWE/b/28pAwf7HQTPBfRFJEGRUfaAAY8NzhW2g/thqcwwoLozBOdOAg0qKIZf+
         in5vkPhqdez270WrJIBwC0m7ynndw+CyO7GV715PkeUShou4iRy+dF1iVU+mrcXNFs15
         GwFKXbNWZTEWHTekIBWG3s3zPanejYy3VbSm2GJd4GjzFkAd4gCkVqa+iXlMyioCoCs2
         D7GZEdOjBGishztL1oNQslpm0ng04Idm/sYu1PT9vED9ctrw/29G6WOgjeaVMLN0N8zd
         mpl3xy2m56QPCN0nk4uXLg0VSm5poVATvuJqGi66MWDTVtNKTOCskxNgizcPQVbFO2Uc
         NHig==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=g/IX/NNgWlOFJxfIdtjuRseXNSvXOPYNIUan6OviEOk=;
        b=Dq6Yqb3xkZ8dR6qbRa8P2At5FmyCrteJqYdwK4OnXn00N6l3r7fwmcl+RDrG3Ui3k6
         p59i74/mw5jFI/1yww35QQ9heqG/G64vUgOAM6CUxH/Egi6b6g5MSva8tEIOZXCutNOo
         D9ceQSOXuqsUiGTSasi3O8M+SEi43RFKMDamGvRmmYW+P3y/05VWsjmGvFXd+nyjwS2F
         hEPHB0abvEijVTHdGn1vmJEXz/YU7YqEHkuewM1Hv7dar9XFE7kycCaBB6zWAyUM6nxf
         hmoHQ8GKU1ZwS4fdeKSbTnZ8W5q/73T/Vy35tH+0FBoYBAoc/oRxhSuX/yE8vMouOghb
         PnpQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=GcqohY7r;
       spf=pass (google.com: domain of conor@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=conor@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=g/IX/NNgWlOFJxfIdtjuRseXNSvXOPYNIUan6OviEOk=;
        b=tNaMni2H+kR4IbAx5XX5uC+56x0/YmJ/njdsF5l5PdBjTQFGhdVhfgQV2Pc+JvAYAD
         mpLEl275CpcLrBHe1x0bskNCsp8g+3cdlI5e6tYjGWbCUOzqRFPPOrsG/2MmVhcKf+4i
         KiSPQGR0x4MKdwR3pwx62+KdoqRXgueQXq6b+NRImaVsSMLS+X9SaeTwhk11soAoHJA6
         VDkldjVric9KYOvo9fsYrS/n5Kuy+1SXBg2t5H64x+asweJUkmKFl7RMj+1Gq35XnKZD
         tGHBBPSomyKtf4TfEx8XMUAchTVDZqaAVX7SvOeIFR1nVLTuSGpS669UefcP0sfzzYdN
         vDug==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=g/IX/NNgWlOFJxfIdtjuRseXNSvXOPYNIUan6OviEOk=;
        b=iArrACiHWzIDejz6SFmO6uNLgXaEicVJLlAa7pcRYIZ0lOwZRlEW4mvEE4u+2nlcsF
         8UZjAUte7CUHjynVi8kQ7adE1UDh0mVr+Xbk95omuaowvn5GYLrf8AbuC0+62j3Xmk07
         xvJ4Ibz9o+t0w5g8kwktRpdUgC1p+TEdXXc6lxsdjUkSbXJBlHR7Bf5jvB42117bnriA
         CnJsO+Lxpe9FV6+W/ZAKc8bxXGkspy7KXemFMGeFwSaLlEWiZvbxAtS5GmpTtZJ/wApn
         BHFqUQy3HOfvzanR9LjEj7RTVaTx0YTFIzqTOs8ojvnBPTJ1IywGIArNHbOGKD+dUZNm
         x0YA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2kqiwOcE9rJDzFi6Mjj5nU2MYCUCtgZnfRj+FrBQ6MLfHBu9OTov
	Rtno+hvpQU5VdI3iqqXEdsQ=
X-Google-Smtp-Source: AMrXdXsGN+qpjWEWGre7dXZVkxS7ISlVdotzteMLhAhwxpVdtHlWgyFf628bNvYg+rfnUFbsC724kQ==
X-Received: by 2002:a25:ce42:0:b0:6f8:bc5d:b4be with SMTP id x63-20020a25ce42000000b006f8bc5db4bemr214244ybe.556.1671631563391;
        Wed, 21 Dec 2022 06:06:03 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:690c:b83:b0:3fe:c52c:dd9a with SMTP id
 ck3-20020a05690c0b8300b003fec52cdd9als9028071ywb.4.-pod-prod-gmail; Wed, 21
 Dec 2022 06:06:02 -0800 (PST)
X-Received: by 2002:a05:7500:3913:b0:ee:2c27:b091 with SMTP id ln19-20020a057500391300b000ee2c27b091mr917896gab.18.1671631562469;
        Wed, 21 Dec 2022 06:06:02 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1671631562; cv=none;
        d=google.com; s=arc-20160816;
        b=aT9YpOJ97oxO67CQN6IcseqneQ/Wg9stP79Ql+Fiu9hMF+a/Me+5NHS0GwkOo7Rggz
         /DaNU9UJJW7u19oP/NTY/YLG6Wo1UCdPFc1ZbfRFKYcBHhhTrY/N64YMlhFnHxPieL8e
         TVSxQz3NrPQAgnbn6PwKWmffIJP+V3F7xXyHU6XzdYlL6uCdmMpK/7+4fOXJMVw9qLr4
         LIW/Fmy+aac5phWCWS40MYfcSugV3o9N3OTHsGZujvM3JftVkENwUiJpND58hF9Ormq9
         rV9If8iY0wTsBZW0dgspNlLYmbS9L+vY3bzpnYOOEgh+nRKoy7u5d+4e8Li0K9aQ91eq
         FBxg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=f3048GHMNqqwo5UDYtM1MnIL0/ox+Tiwb0izR5voNM8=;
        b=OvgqjhYRV4q6muOHVHgWssCJNtF4rE0XS4IcRRJQ2/xnbiQINyCHP9ts7hxZd20XpB
         ZZ9BR64938TndIiQT2sIjCqK5JU4qcBGvdi9zO4/8flnBBoE6FxLX93L7Q9IjGXaPwHS
         NQCE528Fv82BxEjYyYASfDbHDiT2hnpwcExIZyfKk1NA1wAnL/xjgU3W8Pk8EZfCxbvq
         n/MQv/C+u1WOLemObQd9TTFOLpY/K9JxWGD1H/Om4hBbEU3rhNwu4hnl0Ytq61OPBRpw
         rVh5DZHPbpYr5DX+SOHcg40lfdQDha2XrMLjEiPqXN0vVoQdIUZct2u82cB8LOWDbeYP
         bxrg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=GcqohY7r;
       spf=pass (google.com: domain of conor@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=conor@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id a21-20020a05620a067500b00704abc4c5bdsi155288qkh.3.2022.12.21.06.06.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 21 Dec 2022 06:06:02 -0800 (PST)
Received-SPF: pass (google.com: domain of conor@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id 2634C617DA;
	Wed, 21 Dec 2022 14:06:02 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id C664EC433D2;
	Wed, 21 Dec 2022 14:05:58 +0000 (UTC)
Date: Wed, 21 Dec 2022 14:05:56 +0000
From: Conor Dooley <conor@kernel.org>
To: Alexandre Ghiti <alexghiti@rivosinc.com>
Cc: Paul Walmsley <paul.walmsley@sifive.com>,
	Palmer Dabbelt <palmer@dabbelt.com>,
	Albert Ou <aou@eecs.berkeley.edu>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Ard Biesheuvel <ardb@kernel.org>, linux-riscv@lists.infradead.org,
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
	linux-efi@vger.kernel.org
Subject: Re: [PATCH 4/6] riscv: Fix EFI stub usage of KASAN instrumented
 string functions
Message-ID: <Y6MSxBaJU7JqfkJO@spud>
References: <20221216162141.1701255-1-alexghiti@rivosinc.com>
 <20221216162141.1701255-5-alexghiti@rivosinc.com>
MIME-Version: 1.0
Content-Type: multipart/signed; micalg=pgp-sha256;
	protocol="application/pgp-signature"; boundary="4Z+roZAZIwENsN21"
Content-Disposition: inline
In-Reply-To: <20221216162141.1701255-5-alexghiti@rivosinc.com>
X-Original-Sender: conor@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=GcqohY7r;       spf=pass
 (google.com: domain of conor@kernel.org designates 2604:1380:4641:c500::1 as
 permitted sender) smtp.mailfrom=conor@kernel.org;       dmarc=pass (p=NONE
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


--4Z+roZAZIwENsN21
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline

Hey Alex!

On Fri, Dec 16, 2022 at 05:21:39PM +0100, Alexandre Ghiti wrote:
> The EFI stub must not use any KASAN instrumented code as the kernel
> proper did not initialize the thread pointer and the mapping for the
> KASAN shadow region.
> 
> Avoid using generic string functions by copying stub dependencies from
> lib/string.c to drivers/firmware/efi/libstub/string.c as RISC-V does
> not implement architecture-specific versions of those functions.

To the unaware among us, how does this interact with Heiko's custom
functions for bitmanip extensions? Is this diametrically opposed to
that, or does it actually help avoid having to have special handling
for the efi stub?

Also, checkpatch seems to be rather unhappy with you here:
https://gist.github.com/conor-pwbot/e5b4c8f2c3b88b4a8fcab4df437613e2

Thanks,
Conor.

> 
> Signed-off-by: Alexandre Ghiti <alexghiti@rivosinc.com>
> ---
>  arch/riscv/kernel/image-vars.h        |   8 --
>  drivers/firmware/efi/libstub/Makefile |   7 +-
>  drivers/firmware/efi/libstub/string.c | 133 ++++++++++++++++++++++++++
>  3 files changed, 137 insertions(+), 11 deletions(-)
> 
> diff --git a/arch/riscv/kernel/image-vars.h b/arch/riscv/kernel/image-vars.h
> index d6e5f739905e..15616155008c 100644
> --- a/arch/riscv/kernel/image-vars.h
> +++ b/arch/riscv/kernel/image-vars.h
> @@ -23,14 +23,6 @@
>   * linked at. The routines below are all implemented in assembler in a
>   * position independent manner
>   */
> -__efistub_memcmp		= memcmp;
> -__efistub_memchr		= memchr;
> -__efistub_strlen		= strlen;
> -__efistub_strnlen		= strnlen;
> -__efistub_strcmp		= strcmp;
> -__efistub_strncmp		= strncmp;
> -__efistub_strrchr		= strrchr;
> -
>  __efistub__start		= _start;
>  __efistub__start_kernel		= _start_kernel;
>  __efistub__end			= _end;
> diff --git a/drivers/firmware/efi/libstub/Makefile b/drivers/firmware/efi/libstub/Makefile
> index b1601aad7e1a..031d2268bab5 100644
> --- a/drivers/firmware/efi/libstub/Makefile
> +++ b/drivers/firmware/efi/libstub/Makefile
> @@ -130,9 +130,10 @@ STUBCOPY_RELOC-$(CONFIG_ARM)	:= R_ARM_ABS
>  # also means that we need to be extra careful to make sure that the stub does
>  # not rely on any absolute symbol references, considering that the virtual
>  # kernel mapping that the linker uses is not active yet when the stub is
> -# executing. So build all C dependencies of the EFI stub into libstub, and do
> -# a verification pass to see if any absolute relocations exist in any of the
> -# object files.
> +# executing. In addition, we need to make sure that the stub does not use KASAN
> +# instrumented code like the generic string functions. So build all C
> +# dependencies of the EFI stub into libstub, and do a verification pass to see
> +# if any absolute relocations exist in any of the object files.
>  #
>  STUBCOPY_FLAGS-$(CONFIG_ARM64)	+= --prefix-alloc-sections=.init \
>  				   --prefix-symbols=__efistub_
> diff --git a/drivers/firmware/efi/libstub/string.c b/drivers/firmware/efi/libstub/string.c
> index 5d13e43869ee..5154ae6e7f10 100644
> --- a/drivers/firmware/efi/libstub/string.c
> +++ b/drivers/firmware/efi/libstub/string.c
> @@ -113,3 +113,136 @@ long simple_strtol(const char *cp, char **endp, unsigned int base)
>  
>  	return simple_strtoull(cp, endp, base);
>  }
> +
> +#ifndef __HAVE_ARCH_STRLEN
> +/**
> + * strlen - Find the length of a string
> + * @s: The string to be sized
> + */
> +size_t strlen(const char *s)
> +{
> +	const char *sc;
> +
> +	for (sc = s; *sc != '\0'; ++sc)
> +		/* nothing */;
> +	return sc - s;
> +}
> +EXPORT_SYMBOL(strlen);
> +#endif
> +
> +#ifndef __HAVE_ARCH_STRNLEN
> +/**
> + * strnlen - Find the length of a length-limited string
> + * @s: The string to be sized
> + * @count: The maximum number of bytes to search
> + */
> +size_t strnlen(const char *s, size_t count)
> +{
> +	const char *sc;
> +
> +	for (sc = s; count-- && *sc != '\0'; ++sc)
> +		/* nothing */;
> +	return sc - s;
> +}
> +EXPORT_SYMBOL(strnlen);
> +#endif
> +
> +#ifndef __HAVE_ARCH_STRCMP
> +/**
> + * strcmp - Compare two strings
> + * @cs: One string
> + * @ct: Another string
> + */
> +int strcmp(const char *cs, const char *ct)
> +{
> +	unsigned char c1, c2;
> +
> +	while (1) {
> +		c1 = *cs++;
> +		c2 = *ct++;
> +		if (c1 != c2)
> +			return c1 < c2 ? -1 : 1;
> +		if (!c1)
> +			break;
> +	}
> +	return 0;
> +}
> +EXPORT_SYMBOL(strcmp);
> +#endif
> +
> +#ifndef __HAVE_ARCH_STRRCHR
> +/**
> + * strrchr - Find the last occurrence of a character in a string
> + * @s: The string to be searched
> + * @c: The character to search for
> + */
> +char *strrchr(const char *s, int c)
> +{
> +	const char *last = NULL;
> +	do {
> +		if (*s == (char)c)
> +			last = s;
> +	} while (*s++);
> +	return (char *)last;
> +}
> +EXPORT_SYMBOL(strrchr);
> +#endif
> +
> +#ifndef __HAVE_ARCH_MEMCMP
> +/**
> + * memcmp - Compare two areas of memory
> + * @cs: One area of memory
> + * @ct: Another area of memory
> + * @count: The size of the area.
> + */
> +#undef memcmp
> +__visible int memcmp(const void *cs, const void *ct, size_t count)
> +{
> +	const unsigned char *su1, *su2;
> +	int res = 0;
> +
> +#ifdef CONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS
> +	if (count >= sizeof(unsigned long)) {
> +		const unsigned long *u1 = cs;
> +		const unsigned long *u2 = ct;
> +		do {
> +			if (get_unaligned(u1) != get_unaligned(u2))
> +				break;
> +			u1++;
> +			u2++;
> +			count -= sizeof(unsigned long);
> +		} while (count >= sizeof(unsigned long));
> +		cs = u1;
> +		ct = u2;
> +	}
> +#endif
> +	for (su1 = cs, su2 = ct; 0 < count; ++su1, ++su2, count--)
> +		if ((res = *su1 - *su2) != 0)
> +			break;
> +	return res;
> +}
> +EXPORT_SYMBOL(memcmp);
> +#endif
> +
> +#ifndef __HAVE_ARCH_MEMCHR
> +/**
> + * memchr - Find a character in an area of memory.
> + * @s: The memory area
> + * @c: The byte to search for
> + * @n: The size of the area.
> + *
> + * returns the address of the first occurrence of @c, or %NULL
> + * if @c is not found
> + */
> +void *memchr(const void *s, int c, size_t n)
> +{
> +	const unsigned char *p = s;
> +	while (n-- != 0) {
> +		if ((unsigned char)c == *p++) {
> +			return (void *)(p - 1);
> +		}
> +	}
> +	return NULL;
> +}
> +EXPORT_SYMBOL(memchr);
> +#endif
> -- 
> 2.37.2
> 
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Y6MSxBaJU7JqfkJO%40spud.

--4Z+roZAZIwENsN21
Content-Type: application/pgp-signature; name="signature.asc"

-----BEGIN PGP SIGNATURE-----

iHUEABYIAB0WIQRh246EGq/8RLhDjO14tDGHoIJi0gUCY6MSxAAKCRB4tDGHoIJi
0mbXAQCRub/h9CpyhAdOvFd4J3KWAuVL1MSqel/xv3XN0/rcygEArnRj9dMQHuyO
H7c87rEJ3F7mm/BJEC6mELfAmNm85QY=
=2eUj
-----END PGP SIGNATURE-----

--4Z+roZAZIwENsN21--
