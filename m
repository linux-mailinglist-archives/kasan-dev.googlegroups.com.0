Return-Path: <kasan-dev+bncBDDL3KWR4EBRBXG3ROJQMGQEOHLIF4Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x240.google.com (mail-lj1-x240.google.com [IPv6:2a00:1450:4864:20::240])
	by mail.lfdr.de (Postfix) with ESMTPS id 9C7B850BF4A
	for <lists+kasan-dev@lfdr.de>; Fri, 22 Apr 2022 20:03:09 +0200 (CEST)
Received: by mail-lj1-x240.google.com with SMTP id v1-20020a2e2f01000000b0024da499933dsf2619661ljv.19
        for <lists+kasan-dev@lfdr.de>; Fri, 22 Apr 2022 11:03:09 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1650650589; cv=pass;
        d=google.com; s=arc-20160816;
        b=aGXNMCtqoboGAIreFOUYWTxnOOJnqqhKjtCRhUdil9z5Cs31SYZ2BwmK+Cshlc84Wl
         ZyqhfhaLNWnI1oKD4plBcD1aa4D/9pahhLc4RMSst33759q8eYhE42cdyLdUpb4uzAUr
         GJDw4lgfwFDvtOcQony4km+PqCqFLUfaze1eGMzEP51odbCCsAumUdolyPchboKf+E7v
         qRTW73/cfL9tI0md4lTDOsMyenI1UGJrmvmSS2JUYFIYOXVwzYLyFu258WU1XM5ZNY/y
         UdYlCgck/a7GtvvEuTPHkQX/R2Vdldec84w9hI57Vp+HPAQF1tbSTWeqLVUp49msRauS
         YtXA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=jZ845V58m5P6LnLE4F7xh9wy6oOiMgeAjXB1aLz01dA=;
        b=tQ8u93ktWlR9oCV1wi7/OVzt/088EtMWCzs9kT60kXzP2jLlTOhxmv35Pzb0qYzlcC
         XiIrlvy1bWoQUoVsf+srJlao35G+j81BXKGFAIIRglkEL1rHMJlh7PKtOFVepUaIYRBm
         2q595rAUwVE+ONz3CHuqXG9SrN6pgM+xzu0Bqo69KNFhWAF6aC+ou5J1V4QpgcF4/MJ+
         kDgqKUwF0m7rUNYbfE1VkFyIEhJ38uQX8FLx3ZPFHSw7Y6NDseMvJkOebBB+ip8nv7Nw
         BTEyARqdOk9axM6pGjB5G1k8Vikf8YR1cHw5j/9LtQp37hLNWRdksKgSL1gpeMuu1+1Y
         4nKw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=jZ845V58m5P6LnLE4F7xh9wy6oOiMgeAjXB1aLz01dA=;
        b=SWG0qoE+7UX7qC6qioMNvlT3wdI82870FQUi5KjIvRC957MLL/aZWCV/U6CTIXU17F
         PntqTvAc9Q4LtXnHG/7jbxd5NFsJUIoJFnG2JgV6KnIj241Utp4KzM0t7ofBdkufcH2U
         TF4NFgzGcbjA56MbeZ33OK1KopzjubPDaU+8ggWZ4eT6L/x3n7g41gvQEcPT4QGzTI+h
         r63akTFdWlK+5Kf61JPjda9clcScIZfA6G6yF4oHftTOcVgUWuPWAxp2vgR5TSxMg9q/
         9TRgdOEFVYrsjXttysFFhypkBZac+NCUIaKZM7Xjz9fGKUthzFHdMSWzUJqp0OPalttS
         3xzQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=jZ845V58m5P6LnLE4F7xh9wy6oOiMgeAjXB1aLz01dA=;
        b=4mkRyTi7dx2869LNgfLa7ZTQfLJ38zaVLPkLiGbOa1QRax+81zxF6y1tUPyDfnF7XF
         jyoY3gcEQH+zMDoZ4iRMbg/aGJ7M5+NtP/eNvFjbXFsGu6dA37HCz0STkPjivmj6z3zE
         OTjTJ5H6jDTO/KaoLgE98PRpiDNe/VtVJaXdPrsqnLC90CS1SB4UE5WZlkZogP+QzDH8
         wwuGTMVgBmrIR1XTh0hxfMyVP4HOmCKllD7c4evmDF8QONXZQqdSyS8HbV6QMhPbXHYr
         5Su+tYCk/PtiOx2WxuUK7juuvOpssvfZUDTe/Z4HdzQauFTcWVlDtWPpKj0otUKrpAWn
         wHTA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530ALJ5v0XPAM2AIc/NuMnbGcujyEwDSkYofyAJH61M9cjG8ft87
	59THL02VPb2xylHfDrpyoTk=
X-Google-Smtp-Source: ABdhPJwf6A53uvZ7Kbm6WFTXAGNixCI5X3FF7VZ5IV4YIOf/Xyd1GHcsFdS/TvIYq/TEEvz+5O306A==
X-Received: by 2002:a05:651c:887:b0:247:f630:d069 with SMTP id d7-20020a05651c088700b00247f630d069mr3580227ljq.514.1650650588983;
        Fri, 22 Apr 2022 11:03:08 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:2815:b0:471:b373:9bb9 with SMTP id
 cf21-20020a056512281500b00471b3739bb9ls3235428lfb.3.gmail; Fri, 22 Apr 2022
 11:03:07 -0700 (PDT)
X-Received: by 2002:a05:6512:3fa0:b0:465:760:f6ad with SMTP id x32-20020a0565123fa000b004650760f6admr3829180lfa.187.1650650587178;
        Fri, 22 Apr 2022 11:03:07 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1650650587; cv=none;
        d=google.com; s=arc-20160816;
        b=mErS0YTlL7RUuorY9eTIPUa/SvyWq+o0VUvokYmf5NJobxjHZemN0jmDg4f5C+v4Q0
         bf57Y7K3dSyEjYWQJSJ2fyU6LFrFJ8bJZDF5/cgHA/DYexJoU26WcNOpNdMc8j5zdXnE
         giOc0WYoEos0huaVqKKLCYZ4hTkRRi3cYlayqscPBsem/aAXuo7hQkrI5EaZN42U9YxK
         jF4CpuSTyXbKqW17fmGjaoOYXVSlFE5ExabKeNaEmllbglFxoYTo2PuFLGsbMrJ5PIU9
         fBRnmnRhC8/YdZQBmiAWV2EdkAFkZIew7Rvx8xPBAF1X5n+wjvpppz2QdWLmFx35Pbli
         83tg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date;
        bh=dsDtCCme8HJtyk4HzU69xTajIHj6Y4Ohs4kn+li3/IE=;
        b=YEh3iMJ8Od8Oa3IYHL1iytZ9N2SesfWguCpq42xUSnS13lh84J1wWGPW39ms1nRdh7
         gI30jDy+HRrQRHfpqX3o0A4OZ1Y/9EMnAlSd9SaqwJBSVJCiBHvqXbDxouI8hO5mDhLV
         Kpob9+D4REifAKNDjVu/dXQxxsBADIc82fYCzffy4QF/HPGFvhEKjYqIP/UKdsFRQLuK
         dhJrPkfJC9+HHsPmxNhKz9kQfsyXitsoAxk/3IsuWUD2eLoiRxCScABsUZyI1R/WBuPC
         fi1YnEWa8SmUNmw8Wr1VxN62i0R6jJzRfbfkvMpAbuv+l/IgQqaOUEEYsY8KVQXp7Y4D
         z/ow==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from ams.source.kernel.org (ams.source.kernel.org. [2604:1380:4601:e00::1])
        by gmr-mx.google.com with ESMTPS id c12-20020a2ebf0c000000b0024c7f087105si369347ljr.8.2022.04.22.11.03.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 22 Apr 2022 11:03:07 -0700 (PDT)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) client-ip=2604:1380:4601:e00::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ams.source.kernel.org (Postfix) with ESMTPS id 8413EB83215;
	Fri, 22 Apr 2022 18:03:06 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id F166FC385A0;
	Fri, 22 Apr 2022 18:03:01 +0000 (UTC)
Date: Fri, 22 Apr 2022 19:02:58 +0100
From: Catalin Marinas <catalin.marinas@arm.com>
To: Peter Collingbourne <pcc@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Hyeonggon Yoo <42.hyeyoo@gmail.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Linux ARM <linux-arm-kernel@lists.infradead.org>,
	Linux Memory Management List <linux-mm@kvack.org>,
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>,
	vbabka@suse.cz, penberg@kernel.org, roman.gushchin@linux.dev,
	iamjoonsoo.kim@lge.com, rientjes@google.com,
	Herbert Xu <herbert@gondor.apana.org.au>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	kasan-dev <kasan-dev@googlegroups.com>,
	Eric Biederman <ebiederm@xmission.com>,
	Kees Cook <keescook@chromium.org>
Subject: Re: [PATCH v2] mm: make minimum slab alignment a runtime property
Message-ID: <YmLt0s/KdSJlSSPk@arm.com>
References: <20220421211549.3884453-1-pcc@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20220421211549.3884453-1-pcc@google.com>
X-Original-Sender: catalin.marinas@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of cmarinas@kernel.org designates 2604:1380:4601:e00::1
 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;       dmarc=fail
 (p=NONE sp=NONE dis=NONE) header.from=arm.com
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

On Thu, Apr 21, 2022 at 02:15:48PM -0700, Peter Collingbourne wrote:
> diff --git a/include/linux/slab.h b/include/linux/slab.h
> index 373b3ef99f4e..80e517593372 100644
> --- a/include/linux/slab.h
> +++ b/include/linux/slab.h
> @@ -201,21 +201,33 @@ void kmem_dump_obj(void *object);
>  #endif
>  
>  /*
> - * Setting ARCH_SLAB_MINALIGN in arch headers allows a different alignment.
> + * Setting ARCH_SLAB_MIN_MINALIGN in arch headers allows a different alignment.
>   * Intended for arches that get misalignment faults even for 64 bit integer
>   * aligned buffers.
>   */
> -#ifndef ARCH_SLAB_MINALIGN
> -#define ARCH_SLAB_MINALIGN __alignof__(unsigned long long)
> +#ifndef ARCH_SLAB_MIN_MINALIGN
> +#define ARCH_SLAB_MIN_MINALIGN __alignof__(unsigned long long)
> +#endif

Sorry, only a drive-by comment, I'll look at the arm64 parts next week.
I've seen it mentioned in the first version, what's the point of MIN_MIN
and not just MIN?

-- 
Catalin

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YmLt0s/KdSJlSSPk%40arm.com.
