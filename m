Return-Path: <kasan-dev+bncBDDL3KWR4EBRBKE3T35AKGQEMKF7FNI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83c.google.com (mail-qt1-x83c.google.com [IPv6:2607:f8b0:4864:20::83c])
	by mail.lfdr.de (Postfix) with ESMTPS id 925602543EA
	for <lists+kasan-dev@lfdr.de>; Thu, 27 Aug 2020 12:40:41 +0200 (CEST)
Received: by mail-qt1-x83c.google.com with SMTP id f11sf4264274qtj.10
        for <lists+kasan-dev@lfdr.de>; Thu, 27 Aug 2020 03:40:41 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1598524840; cv=pass;
        d=google.com; s=arc-20160816;
        b=Sah63/EQDkuoLmMl5K/4w5ZpoGm7lNEGg8WnV8G5zW3zx2kQYe3nWDZXk8IJMOu6lX
         9cGzYlJpT8FheyakwW/Uqz1h38WB6qKv0pBTnUXijY9z+oWgqOydjSeg31kCeBld2edZ
         4tHWZGELcDuwHzFbwt1YuZdDT0m4t05xdQBU/6kd0Qo1BIvHuT5bAfdT8+Uo/HyqGMSD
         Fx+dsLfs90avKOo+UZeRtNQM6aO8flCWL2bcLd6S4wHHRE3/P8qkG6naTOxplU1p2Jch
         TiIujoLBRYkgFudSq89fKhnj03gpCm5ixClvu3f1JK8u17uFCtIVW9Jdxqq+Uoi2BeJT
         ev1g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=b+avOvWddjU2RKMqXNEZgUrzZdHDP1vFRHlRLXohaKc=;
        b=e64rszj5VqWKzQ6yTYuK9zg9CDOpxpKvHyNe2vvd6VlwInUO+frEI97ydmaLNV9+Y2
         Nw8zqiugJ9APW6i6zdJhHly/fuLj53aPGI1YJCAjVLvuYh75Vf2m4DwBmn+yhHuBcRUl
         VK8t8cFTTtpr/87slKUQtAQdJoBPP2hwVJ9ek2rHkCsNXHtrJsbh63fqxu+NvRRNZQjD
         6CvDWFkcjV+yh1ZNoJPl8XXnURn7mcHuW5g0DX3e5IKaFWCDScs8EAbs0LVrsIKAy2+r
         vCdhhC1NYyIrwQvBwuuzt98svyZcgMUYnogEUlOnZUiBGFG9Asww3USGttfE+nkAJQsv
         VKqQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=b+avOvWddjU2RKMqXNEZgUrzZdHDP1vFRHlRLXohaKc=;
        b=KuqVa5aZcz8pkovM6OIZu0le2gijGajRMY0eTYdBDJLma7ikIGVZTfOYErTV5/qjRA
         LE8ZuI37GTmnl18lMhASfnY9J1p7+RmVsw+spILGXaSK9QhfCmkRYNuxokZ87Y4CHw/n
         ITQq/diKfMzQ2+zCN05156mAr6uBXZ41ulo8oYntXh7Pou0FN2VryxrPiDkOHMsWzpHn
         DlI7lBXT+n3UiKeWBkiPbeRW6FVVBGi3Jx0gOzRGNCTck7yp3wtEAR8VUUtBdrv3Xxch
         9RZLw4vKv2S6xD3D3QLrsEtZ1ChaNPj0emMSniBiL2ueJ2ZeZ256mnFed7oSt1G0bgQM
         2r1A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=b+avOvWddjU2RKMqXNEZgUrzZdHDP1vFRHlRLXohaKc=;
        b=tvRiVy5SfnSUrtjtYv5jvXhtRZ6BY1GLM2T9nFmOVjgYPCWngUiXqbIcnTlVM9BKzS
         wNw9Ans/h6i6SQtb5RiUnQoiz9yHZnabe11+4YiA/bAGHtjejxg8yxSEvY0zlhv5uMpx
         Yj2WuZyhQH2dr2mqcPuvdXEQQAl5z9BZyZFXLpLqze+Br+LFop6lvIRe60F7+9vqP6tq
         nJC5GaRHJfTUixOeXROO1WrLREECMTeINvcxTVtjgksgkiF0o+MdkHI0wOQlGorQBuRX
         lQuPnc3F0gTvXtw87WXQf9MbTYD/x4XGOZVHeP36N++F4iwwNOalHXJY6f8/UPgVxoTl
         zpXQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533b3Ar4RWUNHt2MOqHX4oBB0qzpJhNxMM9ufinjhXzbchTlLA9U
	LTkH6IP+JYomDiZHESk3qgI=
X-Google-Smtp-Source: ABdhPJzHhaTo2bZp41qY6Er/n/gsSoMhj7lRoJZOKrKK2DHVTdFb5LHWQqHGI9xykGpAo01m2FxaUw==
X-Received: by 2002:ac8:794f:: with SMTP id r15mr18109909qtt.383.1598524840578;
        Thu, 27 Aug 2020 03:40:40 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a37:683:: with SMTP id 125ls765859qkg.8.gmail; Thu, 27 Aug
 2020 03:40:40 -0700 (PDT)
X-Received: by 2002:a37:8043:: with SMTP id b64mr13223497qkd.396.1598524840182;
        Thu, 27 Aug 2020 03:40:40 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1598524840; cv=none;
        d=google.com; s=arc-20160816;
        b=u+nW8YvNrIHjJmDvlDQRueIVWzISDMpwkYhwaVp3tYZceXsP6NIeAEZ7Os9wuukG/s
         QGgFrEsWPwRHlWwOyciqn1Hm7MOjqj24q2WbernJyNfh348A9s5wH71DuoxrtASgT4iP
         ZxGP4wDEh0x3db2ytoIfRAdHIJtNgb6AJI0hCaqyZB/ewEO0EvPGoCK1K/JaKpV/AaFk
         3W7ZQpYtVTcCmYJneXmKK2Z1+PxSX+1M9+zEfOnBMnamn3u9sYRBmw0gsE1xiZW7fNjw
         eQWIW144HWB1YpgOkgillCXwGCWv9/YWp6sP+eDP80x9zRhBEE9uJmigeHPyOrz3NRSU
         lQXw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=BGHQkw60dDek5FzubTjIX8aaNnynknokQW/JhP+PkVU=;
        b=xiz4aijlsv0dGk5Z/p3keVydnBN1dd873FRrYiBOoxuo2/Ii3HK8QItF8Pz42E41+2
         P2yILjck0yL3k3Sn6rcPkNWeoayKVOumkZyv6GBZggjksxGa71Wcl8XlYP9N7Kim3hVA
         4jBgPFsgU84/5KTHsLZ2Hbbx4KNQIn8UKPYNOIcXGZ2jnOJ6+MpH5i4valNTEGKK9rYQ
         kvqAN2z12FgAF887/izH0tuKEm8n2Ggmw6U7d424Wsyi+qsr3dXWeMe84+4R7KBt4VZW
         BWnLriqONXgum1SUmiGvPrAXUoUtcptdWgVLHQ6iKn7XNygw0mki4UIA5Opboe+ANO6g
         thOg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id m13si80993qtn.0.2020.08.27.03.40.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 27 Aug 2020 03:40:40 -0700 (PDT)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from gaia (unknown [46.69.195.127])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id A6A2122B40;
	Thu, 27 Aug 2020 10:40:36 +0000 (UTC)
Date: Thu, 27 Aug 2020 11:40:34 +0100
From: Catalin Marinas <catalin.marinas@arm.com>
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	kasan-dev@googlegroups.com,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Elena Petrova <lenaptr@google.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Kevin Brodsky <kevin.brodsky@arm.com>,
	Will Deacon <will.deacon@arm.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org
Subject: Re: [PATCH 26/35] kasan, arm64: Enable TBI EL1
Message-ID: <20200827104033.GF29264@gaia>
References: <cover.1597425745.git.andreyknvl@google.com>
 <518da1e5169a4e343caa3c37feed5ad551b77a34.1597425745.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <518da1e5169a4e343caa3c37feed5ad551b77a34.1597425745.git.andreyknvl@google.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: catalin.marinas@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as
 permitted sender) smtp.mailfrom=cmarinas@kernel.org
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

On Fri, Aug 14, 2020 at 07:27:08PM +0200, Andrey Konovalov wrote:
> diff --git a/arch/arm64/mm/proc.S b/arch/arm64/mm/proc.S
> index 152d74f2cc9c..6880ddaa5144 100644
> --- a/arch/arm64/mm/proc.S
> +++ b/arch/arm64/mm/proc.S
> @@ -38,7 +38,7 @@
>  /* PTWs cacheable, inner/outer WBWA */
>  #define TCR_CACHE_FLAGS	TCR_IRGN_WBWA | TCR_ORGN_WBWA
>  
> -#ifdef CONFIG_KASAN_SW_TAGS
> +#if defined(CONFIG_KASAN_SW_TAGS) || defined(CONFIG_KASAN_HW_TAGS)
>  #define TCR_KASAN_FLAGS TCR_TBI1
>  #else
>  #define TCR_KASAN_FLAGS 0

I prefer to turn TBI1 on only if MTE is present. So on top of the v8
user series, just do this in __cpu_setup.

-- 
Catalin

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200827104033.GF29264%40gaia.
