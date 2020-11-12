Return-Path: <kasan-dev+bncBDDL3KWR4EBRBQ4FWT6QKGQE726L3QY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe3c.google.com (mail-vs1-xe3c.google.com [IPv6:2607:f8b0:4864:20::e3c])
	by mail.lfdr.de (Postfix) with ESMTPS id AFD4A2B0213
	for <lists+kasan-dev@lfdr.de>; Thu, 12 Nov 2020 10:39:16 +0100 (CET)
Received: by mail-vs1-xe3c.google.com with SMTP id v17sf1543475vsq.19
        for <lists+kasan-dev@lfdr.de>; Thu, 12 Nov 2020 01:39:16 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605173955; cv=pass;
        d=google.com; s=arc-20160816;
        b=Ko6wjFdFp36dXhij4keKZxRZ2ZmRMpFhhwzRrjsf3twXPvhONyChiqtB1HuOE1e8G8
         DV+Hw0BDk/X0pOA8+I5CQe/G29DjW//4EHTlvjZtk8DYk0JsgEQrZyExzo5BGKq88QQ3
         wT1lEezByKNit+qpcoYA9c4jb5JyadU5bh1x8aBmf6n7sRf+nLfWwYL+ZZ1Tk6CGFutD
         RBk94luk98460EjmI9e0hIzrAfruszhf/TjIuD3yvDyOKMcr3BQSda/5uaP4Ke04fBNJ
         DUP6ndqEmTvIyZa9j5sMyd36qpSG2UOkoWGkr3I43l71RLmO9gcAqIz/lvWAQ5bd3rKj
         EnzQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=RX5Ma/7tF0EExedj486Ud/tS8g6AkTKhlBzMStPtBfE=;
        b=wgrUFvRGNQTkPbuuNjD+IUsNI+AHb0fUy+HT+Wvuvd/3aKsfzuu9WUdj5bGgZxiivt
         dXlhfzvQo99S6joaeP4W276Tj90rq0JM8JfN4eqhHf8tmoQ5mHz+IKdyr7weq3Bn3v1V
         XSA5SmXtWB4Rwe0MqA8PNlHW5ph5G2DAeTLkS5frzJYFVXpJbgj8+mH3kY4rPZWQ7QtT
         qBVPntaW5Dvj4ajwE0lQe/f3rSy78QkhSbD3VVAGbyxawYw7sOOVyV1CkejLTC086Y09
         gLifnK1Y+1VlFRQZVT1OQHyeIUvF54uSBLchrtx4x/kOEc1i+66yr287pmxMIMMjstvR
         c4tQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=RX5Ma/7tF0EExedj486Ud/tS8g6AkTKhlBzMStPtBfE=;
        b=hoN57r0cpk5+Qw5XgV1DJ22esKXvMucZx3hvtpshtAoOb0C9NZiYIo5litNDivoAqd
         nZdwsLOt3bz1s1TYJLI4bBaBGo35PUweyqtPQBbfLQ7dY1QmoH8Se2aRAz1FCMUme848
         kHyqo56M9zmDu7P7hsmSGWge3+QcVjEI9GpWmTyYGCrzqP8Y2znTujO4F84moqLRe5Vk
         RkJmtDnAFsXkgRHoId8LPOy12zSy7iotIe4LZWxB0KKETIwX7dzET7hyGr50068J4vlp
         cDM/Oq79nDAgFEpB8tJXfImGQXkCmeoVzkfJcCsM0oENl3SeMAswlrH1ZAjHMPygg+tj
         zQ4w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=RX5Ma/7tF0EExedj486Ud/tS8g6AkTKhlBzMStPtBfE=;
        b=TK2fSshNao21JlTShV3zppGwqiyPER8MKzpVVw2jJRoOSHhp9fl03mgCdmTbmFGwnm
         WApFZNveC5iq+yBZgyxkTQ65oYp1dC+3NJzdaykBXR6KdTaBbr61IOlIA3oJR5qVmg6t
         aosKYoc1tVM0H6spRQJBduDZ69zLZK5ERHOFDiZ+yx0Z2hf0UD9ZdYMirvKjl+qrYacM
         Zm4wabtxO3jpLv1aIKv2JLo4wH2lvSKDK3WuDaZ7h8NEDkvhHJOmj7kOwKijzluk98dS
         9oqyqDTXXoCYJdxuv7/p5TumGoLSM1Ii7zOtjHxrEx0Ohajc0UkHlqj4ITEc9Rapdmy1
         I2vQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530ro0cT/zuL6+hPpQ2ArscehplI90oTwGiRa04QuO2nnZzkZrzR
	MdHTOXSESbYhywuQWdSIWGM=
X-Google-Smtp-Source: ABdhPJwikDuhm3d6gCI91AmnpJBpAtbtOShiDfW/Yz76EcCM8QmugQlmrlsupLGZm3MaKSKuPSWPvQ==
X-Received: by 2002:a67:ee46:: with SMTP id g6mr18936261vsp.30.1605173955816;
        Thu, 12 Nov 2020 01:39:15 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6102:22fb:: with SMTP id b27ls342989vsh.1.gmail; Thu, 12
 Nov 2020 01:39:15 -0800 (PST)
X-Received: by 2002:a67:e918:: with SMTP id c24mr18263752vso.55.1605173955366;
        Thu, 12 Nov 2020 01:39:15 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605173955; cv=none;
        d=google.com; s=arc-20160816;
        b=NHHv6xV/smiEsp4Vi+zFL1Ea/mjzfkseJOFKC0CUnd6XdsOXjIL/z7YYOSkboQp9v6
         6Q5QsAT5u4WoNR0Zmx+Pd4YGkYPcfkJK3I+NkdAOBoK4diV6SK1yBQUly+5PC4YiZQsd
         XyLxLZaGgZ7eRyn4aanaHJVIHuOCl4PS3rrAlULlsv/jGd2VBfP+Kp1+94D/oI8SLRcI
         a6cPE/8TrDR20HPweyQIhLzG16uuxk9hk6RaYPGHnOXod6o7K/B8lffXBjuqbXymmaK3
         MYgUqdqRTETTYkDwx4XzNxDNQpatm9xetj7XWHCLPHTZXXANaVPQsf2hm4kA9+Tp48N2
         CdNg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=jHN7D25KIg0wEnwzgkH76PlhJNOt2MxwdLne1M+JMe0=;
        b=M33SRIq9SxA/GIqSKC2LYGErfc8fIMTda4u4AAIAPINiOWbFc6F0JIfeDKjh45vF41
         5AM4ivQcBckWPIpFumu/xiXRpqEKxMLnJa6jo+DL+2l6S7L8T6HOvUKMrEwr2+WH+fL/
         3iJeZ6tJD0Y0S889nMn+eAIArn9x0/BM6FizkhG2oTXNeA5hCheueTugvllsQq8E/sTX
         IRxwy3HgMvkvq+3BxsYO1+tjZG8yH4DXpKF6xygkowwGZWeQeAVXjrOKQwgGTeREb/T7
         yKzNFH8ybqAEDqpjC6nVnXDqTepDhV1DqMcY++l3ozo0QbV5iqHUOq4SNeSUd7P9+LV4
         ljNg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id p17si367179vki.0.2020.11.12.01.39.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 12 Nov 2020 01:39:15 -0800 (PST)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from gaia (unknown [2.26.170.190])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 9041221D40;
	Thu, 12 Nov 2020 09:39:11 +0000 (UTC)
Date: Thu, 12 Nov 2020 09:39:09 +0000
From: Catalin Marinas <catalin.marinas@arm.com>
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Will Deacon <will.deacon@arm.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Kevin Brodsky <kevin.brodsky@arm.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org,
	linux-mm@kvack.org, linux-kernel@vger.kernel.org
Subject: Re: [PATCH v9 32/44] arm64: mte: Switch GCR_EL1 in kernel entry and
 exit
Message-ID: <20201112093908.GE29613@gaia>
References: <cover.1605046192.git.andreyknvl@google.com>
 <25401c15dc19c7b672771f5b49a208d6e77bfeb5.1605046192.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <25401c15dc19c7b672771f5b49a208d6e77bfeb5.1605046192.git.andreyknvl@google.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: catalin.marinas@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as
 permitted sender) smtp.mailfrom=cmarinas@kernel.org;       dmarc=fail (p=NONE
 sp=NONE dis=NONE) header.from=arm.com
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

On Tue, Nov 10, 2020 at 11:10:29PM +0100, Andrey Konovalov wrote:
> diff --git a/arch/arm64/kernel/mte.c b/arch/arm64/kernel/mte.c
> index 664c968dc43c..dbda6598c19d 100644
> --- a/arch/arm64/kernel/mte.c
> +++ b/arch/arm64/kernel/mte.c
> @@ -129,6 +131,26 @@ void *mte_set_mem_tag_range(void *addr, size_t size, u8 tag)
>  	return ptr;
>  }
>  
> +void mte_init_tags(u64 max_tag)
> +{
> +	static bool gcr_kernel_excl_initialized = false;
> +
> +	if (!gcr_kernel_excl_initialized) {
> +		/*
> +		 * The format of the tags in KASAN is 0xFF and in MTE is 0xF.
> +		 * This conversion extracts an MTE tag from a KASAN tag.
> +		 */
> +		u64 incl = GENMASK(FIELD_GET(MTE_TAG_MASK >> MTE_TAG_SHIFT,
> +					     max_tag), 0);
> +
> +		gcr_kernel_excl = ~incl & SYS_GCR_EL1_EXCL_MASK;
> +		gcr_kernel_excl_initialized = true;
> +	}
> +
> +	/* Enable the kernel exclude mask for random tags generation. */
> +	write_sysreg_s(SYS_GCR_EL1_RRND | gcr_kernel_excl, SYS_GCR_EL1);
> +}

I don't think this function belongs to this patch. There is an earlier
patch that talks about mte_init_tags() but no trace of it until this
patch.

-- 
Catalin

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201112093908.GE29613%40gaia.
