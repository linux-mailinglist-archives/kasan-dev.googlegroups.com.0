Return-Path: <kasan-dev+bncBCSL7B6LWYHBB34M7PBQMGQEAHNXKOA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53a.google.com (mail-ed1-x53a.google.com [IPv6:2a00:1450:4864:20::53a])
	by mail.lfdr.de (Postfix) with ESMTPS id 00653B0CD66
	for <lists+kasan-dev@lfdr.de>; Tue, 22 Jul 2025 01:00:00 +0200 (CEST)
Received: by mail-ed1-x53a.google.com with SMTP id 4fb4d7f45d1cf-60c4f7964c4sf3472519a12.1
        for <lists+kasan-dev@lfdr.de>; Mon, 21 Jul 2025 16:00:00 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1753138800; cv=pass;
        d=google.com; s=arc-20240605;
        b=EtsxKPpq/FRt15scKWZK9JYGgDAhD83KdNWdd47MnxzZJYmHOEfbTHy3iCVlCHg+X9
         naAaskra8BCLG8hyOaeAqcA9Nm2vp0JaenZXcO1N5O8x9k3cP44mTrOOpa3PEzC2amCy
         a4vU8GedNEtC/1E9SDR0M6sh2n1tPQOmn2y9zYxG8hrdu6guhtwunng7DvpzIarNR96I
         Fa/oMPr9sJ5mqEmJTlHC5IqAC2iyizqJkWlOWF6YKw4gHFDdqK5EqkRi74EMKSq0YM+G
         lRZbvKaAB9m4ie3O5Kzok7hfPR51sW2LyEQdKv8r9hcbV//fdvleOZDp8gcf2TsSnBHZ
         VEjw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature:dkim-signature;
        bh=jUynlAN6F4QNaShk8qXc64M8LUus/FCKuM4w/xHJojk=;
        fh=1ueVBa3e/t5ufdt8TviYBaMQFrRcu7wnSlmi/LmetfA=;
        b=dHk8VkEgZIKPAF25q7GRG8p4YHQwwZxzvXWzbSabRd7E+cD77bBkIAONcYYk4iO7zQ
         cynGZhKQV/Q8jELufhpyF5DX+ya2KkbgonFo8SsyOiyXdRuU82MOVXfVciW5lczpN1Z1
         5vwpnq5GPcAnNmTySabfIUjjYCpyWDcaqamW3ySuWR9XzkdiS/xRrwfHQvKrD/0bGuoH
         4u0Nm3whLyGmlV4TTAaUPzzgd0xnsoX6y2sqSvxX5TEVtZ5v+2Z72VsRMIBhLZxfKWs2
         Kn0Oql0pDBTVeERa5ILDjqf4UKU/qCxlDYZQ3fC2qI3hhLc/f1tcLZWuKc/dKWR3CSC/
         +c8g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=bBxSmrml;
       spf=pass (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::636 as permitted sender) smtp.mailfrom=ryabinin.a.a@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1753138800; x=1753743600; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:content-language:references:cc
         :to:subject:user-agent:mime-version:date:message-id:sender:from:to
         :cc:subject:date:message-id:reply-to;
        bh=jUynlAN6F4QNaShk8qXc64M8LUus/FCKuM4w/xHJojk=;
        b=npOKHLBCAa2/DgdUZDhsD+buUEM8cYx89SH5L/Tc8DUhAuHTEYeXmUEMXJVUm2yeBF
         vq2GtM5A8tviyVL4U5ECZ5nLItkdywZeHXMscFL4Jty14+SEbdAM/6jSvGBGnEDD9xEv
         J6dJZnhyXl11zJgW6vsMLqOdFolbK0/Eu6g36K5tpDeWrl1R1SSitzJ3M9Bh7Yvk7Chx
         J99KtqX9o3Wita9n4evmdgYVS9B+VK25gyy05LTZhl+RSbT7X+4dETAMMmYGGuIiy0nz
         KR179CDZWpAfoOkPQK8Pc7X7ItmJnu42t6yrZsDbUFGeDqmx/eWDcKmFj9DJxvlm9apz
         59+Q==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1753138800; x=1753743600; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:content-language:references:cc
         :to:subject:user-agent:mime-version:date:message-id:from:to:cc
         :subject:date:message-id:reply-to;
        bh=jUynlAN6F4QNaShk8qXc64M8LUus/FCKuM4w/xHJojk=;
        b=eFfTyAuHfb6bk5JnNZ3yDjXDxiulmr9BKGiQ1DeYQT2WqGT678jza/udZCEFsEDztU
         1ZBI6myyRi4AGdGcdhcN47QVtSY4in0oc7g1xgIl5vNaTnanhFL2MN1YcSulRNDOEv67
         GtUf8lW36/4YrDcOni0eX9XIT/fce6xlW50O+ogi0xNdaMoRV+cV3r/VhtSXQh2nBpr2
         b7jrJVsCOC1e1QEUg9ecdUyVAE/oKIUm2k0U4sodgp01RNl73dOHPLplmCdPr2JNC1sM
         VEjRJLxVY9osfzMYI69yaBn5lYYJc0DL+0W05YDMB7zLBjar4u6FkLgSj0IukTToqMXf
         JXpw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1753138800; x=1753743600;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:content-language:references:cc:to:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=jUynlAN6F4QNaShk8qXc64M8LUus/FCKuM4w/xHJojk=;
        b=hnxk1hOgbsfSTYm3Sk0E7wMZLJpXvWj+6zH9KMl+a3A1GI1EnikE4/9HKtJoXmkMJv
         aAawL2/w1O21XNx8To7sf/w9zMIgg4+E6QARIvCuAmdLmyT7pIU1uqDGeMrCLIB68YWs
         vnr1hTtvbk/Gd9OiR9HIYJyntjHJ0oHk4/2VgRasCHcXfDT9vQJXGaz/kEHybjGHx+xy
         GEb8XqKFR0nPC889LvEHyNPzn2LnL+rGinEjY8uPL5DrBxS9OKnu3G6JPPmxZkqG/+sr
         WmCgBzcSkn0Gb2AWHeqaPVyYcBo0TYSzAHVazNSe48shAY26+mqFrMeOYEsOlJql78nJ
         uKCg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXcL8E0caY2hRIfoAbjFcwm8JWid4V5MDCWz4ODXwGD0VD3p8ntat8VL8/qtVha3LqLSJoiEA==@lfdr.de
X-Gm-Message-State: AOJu0YzfQSL3FuzaxefeD0/e+N9KF0hM36BlcEH6ICMp6B6p79QBZezF
	1lfo+yJOjaGpZJ+2KV1Ko9LgjvntU8SPBaJefwWEfGt/ftRCcNr+HdCC
X-Google-Smtp-Source: AGHT+IE8glf++bKAO2DPzpYQZXKtHNu8FoD9UiVXEbhO9Xt/2rODm/Uiq5m135MWLMmreqCl5eYdCw==
X-Received: by 2002:a05:6402:50c7:b0:60e:9e2:585f with SMTP id 4fb4d7f45d1cf-61285bfe050mr20221985a12.27.1753138800200;
        Mon, 21 Jul 2025 16:00:00 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZclErcjI90Rx3cIG8wL7QcTPi2FHsU9V37wKmZh7GXngA==
Received: by 2002:a05:6402:4604:b0:612:b6aa:7835 with SMTP id
 4fb4d7f45d1cf-612b6aa8124ls3078954a12.2.-pod-prod-09-eu; Mon, 21 Jul 2025
 15:59:57 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXd33xlg++D7S2C1NT4E6TsyCdK6i7xX+0qU9Ri/FeHVDhqtiHBMHNZ2OQwYL9RbKPOj7WPxuNVFDo=@googlegroups.com
X-Received: by 2002:a05:6402:520f:b0:607:6619:1092 with SMTP id 4fb4d7f45d1cf-61285978650mr21726533a12.13.1753138796930;
        Mon, 21 Jul 2025 15:59:56 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1753138796; cv=none;
        d=google.com; s=arc-20240605;
        b=VRpKAunz4aXtGLp/vjWxNaIRFJCVoACxdFuT0Ae+VB9KNCv0yaYmz3RLqB0gsXH3Bm
         /kSjvWz/PWRLkGF3IlNAUFOMGl51sRa2ThmS+kTxCtqLcmVLEIsNASNIb4bea60Au+iX
         KZqRDbWTzmfHNekVumpy2wY0ifLMa5135hlZ81Nk8tEMKb1ZldU+2MdurBTSW4FOaYoo
         2OQTCVaNrEZj3rwP+tLEMfieO/Yy7wbEnnVc/GBH0kgVbvRhdE6Rej1NApYWWBlYyUAc
         Km271bR8MDd+BVJBWgmaXREI8+LVaBcFGlQ0ZAQPq2LWlEv4iJNTsbjRCpvgz0c33Kx2
         l3/A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=k6qH8mhMJUNtpiP5ZkZtwmZQrunIQJlcyvnjoj0lgTw=;
        fh=7qHmSQqHZFOTNlOYS997aPt1GLDgpWHlIGVDNiD5aRA=;
        b=Rj4gtYv9enL0kS66YKoU8KGqoi7emXLF1NNqvIxCpbYHGMUVVT4wPeEMz24zAEmDzS
         ld/wmm41GCNLyXkZPQXutPbATdeE7kIsMyChD3dl3Fk8JRKZibzNprSvNkcYhPbFV7va
         JknW/IRC/ZAUOzJmaKXGI8tPnkYvLTegKtJSzmKXCLNGzHphADoKKCpoylolpFo1xrko
         apbn/rjT7XkUSZQ+YFKloGhI1o9Njo3xwdc/nhedugQ/J2XAKr6YuIlz/OMW3bPWPuR/
         LmMGKa/05fV3Gchp9JLXzp7l6hMT6u5sSnN4py3edDgAbvwwGwJHSiLmwrma8l3gBPt6
         YloA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=bBxSmrml;
       spf=pass (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::636 as permitted sender) smtp.mailfrom=ryabinin.a.a@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ej1-x636.google.com (mail-ej1-x636.google.com. [2a00:1450:4864:20::636])
        by gmr-mx.google.com with ESMTPS id 4fb4d7f45d1cf-612c8f83372si213311a12.2.2025.07.21.15.59.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 21 Jul 2025 15:59:56 -0700 (PDT)
Received-SPF: pass (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::636 as permitted sender) client-ip=2a00:1450:4864:20::636;
Received: by mail-ej1-x636.google.com with SMTP id a640c23a62f3a-ae34f43be56so98184266b.2
        for <kasan-dev@googlegroups.com>; Mon, 21 Jul 2025 15:59:56 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVCf5W1ZAqCHIMnjg9kF2DW32+hBsOq7l7hJp4EfxqCHpKKXui9S+WDx8jWOnC45fAQT7PcU2Nozxk=@googlegroups.com
X-Gm-Gg: ASbGncvH8WoWZvefHNZNXYkyqqisbmFWoQ7kK/+RRyhW7w+bMmIKCHvOPZAfgS+sh2u
	ldG2tB1MBd44DDu9faYGhg3EdEdFjlrhaeyMUJ4E6IDFBoDwDgC9XPRCcwVBFoRn/F07diEHFpB
	8RqkFi9b3MKB+YukUjD0KetLibmvKLWZKWmh7OqzQ+Dc/wiHkMcyZyz4D91Flz7jJELAjEjCIw5
	Y6TjpdqybyaYZzHdtkWALssM/dWW2N1Gz5l+HYsIkdljyzAKEEJ6+E65DmLvgqqCWfKsm5kPmDt
	S+KPwI99RJ9LbJYKvf/dtvMLKjUkNNpanmdFpHVudUeTlZGmaq8vZDRhuhOt4Xq84gjl+pXjpBN
	AdrHj0qlJuepgDafTZvrCC2Qpb9a7WpmIQnA2jHoq/q3WY7LwiTUfAVpNzFRvXFHXTwIsTz9x+B
	hEzXU=
X-Received: by 2002:a05:6402:3582:b0:612:b0d9:3969 with SMTP id 4fb4d7f45d1cf-612b0d93f03mr5896841a12.8.1753138796402;
        Mon, 21 Jul 2025 15:59:56 -0700 (PDT)
Received: from [192.168.0.18] (cable-94-189-142-142.dynamic.sbb.rs. [94.189.142.142])
        by smtp.gmail.com with ESMTPSA id 4fb4d7f45d1cf-612c8f543ddsm5962670a12.30.2025.07.21.15.59.53
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 21 Jul 2025 15:59:55 -0700 (PDT)
Message-ID: <bc47c08b-fbc7-4954-8e81-c22bce654556@gmail.com>
Date: Tue, 22 Jul 2025 00:59:34 +0200
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v3 01/12] lib/kasan: introduce CONFIG_ARCH_DEFER_KASAN
 option
To: Sabyrzhan Tasbolatov <snovitoll@gmail.com>, hca@linux.ibm.com,
 christophe.leroy@csgroup.eu, andreyknvl@gmail.com, agordeev@linux.ibm.com,
 akpm@linux-foundation.org
Cc: glider@google.com, dvyukov@google.com, kasan-dev@googlegroups.com,
 linux-kernel@vger.kernel.org, loongarch@lists.linux.dev,
 linuxppc-dev@lists.ozlabs.org, linux-riscv@lists.infradead.org,
 linux-s390@vger.kernel.org, linux-um@lists.infradead.org, linux-mm@kvack.org
References: <20250717142732.292822-1-snovitoll@gmail.com>
 <20250717142732.292822-2-snovitoll@gmail.com>
Content-Language: en-US
From: Andrey Ryabinin <ryabinin.a.a@gmail.com>
In-Reply-To: <20250717142732.292822-2-snovitoll@gmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: Ryabinin.A.A@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=bBxSmrml;       spf=pass
 (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::636
 as permitted sender) smtp.mailfrom=ryabinin.a.a@gmail.com;       dmarc=pass
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



On 7/17/25 4:27 PM, Sabyrzhan Tasbolatov wrote:
> Introduce CONFIG_ARCH_DEFER_KASAN to identify architectures that need
> to defer KASAN initialization until shadow memory is properly set up.
> 
> Some architectures (like PowerPC with radix MMU) need to set up their
> shadow memory mappings before KASAN can be safely enabled, while others
> (like s390, x86, arm) can enable KASAN much earlier or even from the
> beginning.
> 
> This option allows us to:
> 1. Use static keys only where needed (avoiding overhead)
> 2. Use compile-time constants for arch that don't need runtime checks
> 3. Maintain optimal performance for both scenarios
> 
> Architectures that need deferred KASAN should select this option.
> Architectures that can enable KASAN early will get compile-time
> optimizations instead of runtime checks.
> 
> Closes: https://bugzilla.kernel.org/show_bug.cgi?id=217049
> Signed-off-by: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
> ---
> Changes in v3:
> - Introduced CONFIG_ARCH_DEFER_KASAN to control static key usage
> ---
>  lib/Kconfig.kasan | 8 ++++++++
>  1 file changed, 8 insertions(+)
> 
> diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
> index f82889a830f..38456560c85 100644
> --- a/lib/Kconfig.kasan
> +++ b/lib/Kconfig.kasan
> @@ -19,6 +19,14 @@ config ARCH_DISABLE_KASAN_INLINE
>  	  Disables both inline and stack instrumentation. Selected by
>  	  architectures that do not support these instrumentation types.
>  
> +config ARCH_DEFER_KASAN
> +	bool
> +	help
> +	  Architectures should select this if they need to defer KASAN
> +	  initialization until shadow memory is properly set up. This
> +	  enables runtime control via static keys. Otherwise, KASAN uses
> +	  compile-time constants for better performance.
> +
>  config CC_HAS_KASAN_GENERIC
>  	def_bool $(cc-option, -fsanitize=kernel-address)
>  

This needs to be merged with the next patch where this option at least has some users.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/bc47c08b-fbc7-4954-8e81-c22bce654556%40gmail.com.
