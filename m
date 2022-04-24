Return-Path: <kasan-dev+bncBDH7RNXZVMORBSWDS2JQMGQE3YCFJLY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3e.google.com (mail-io1-xd3e.google.com [IPv6:2607:f8b0:4864:20::d3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 6AB4550D4C5
	for <lists+kasan-dev@lfdr.de>; Sun, 24 Apr 2022 21:15:23 +0200 (CEST)
Received: by mail-io1-xd3e.google.com with SMTP id r17-20020a0566022b9100b00654b99e71dbsf10020482iov.3
        for <lists+kasan-dev@lfdr.de>; Sun, 24 Apr 2022 12:15:23 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1650827722; cv=pass;
        d=google.com; s=arc-20160816;
        b=RqBnO91427U3HtG031Qum+Aj2vi6o9jiGuWc9PH8um9PDzas0YzlGoLmqI7705ozV7
         5owohGqGUbR+CoylXHFi8/Ue4mjLNDsmwvu/5hoDonXXdB+u7rAEwAy24yrtO+6czUp3
         SEOsEPOrfVUA1oOBBwEQc8Dka6plQ5lB6HkOLbjcDxv19VgMKryqQXFEaico+RUrPWOT
         db7fLcaYNDTKUR9qhQvXdcu7hKCMaVmqBW7d+kp71y37zrB+usOo4Cweqiq7M3UW1aHo
         gwh4lFDy+DEPW4J+FJSqGb5j0BIseRG67OLWOmP43YQXv7UU7OImkzhdOqx4rfcHsyW3
         C3fw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :message-id:in-reply-to:subject:cc:to:from:date:dkim-signature;
        bh=MZs8ozGZJnvIPcITMWzFY8mly+P27TElSCA4HIgLdZs=;
        b=yQwFLB6s/Gf3rsv6M5XhNq7KmuzUlrslKNM1dFE0JHbGQQcRKFr3PSG0VcMk0oEL0r
         wfaazbgZCf5myTrXdn83nS4nXU2IgBS7wwG2NAktxiVpJ1ccGM/gA38MryWoHipTF4Cs
         Q3z45FpeOTYeQw/36fhCPVOScLzz7bFbBPDjXnVG3dq0TkmToRx9oNGMiJoDyNOOV70u
         mZV6gldhV98FyHdnHiOn0L/oia1odmZx9IWWWVMY7GQJ2o9ZvWsE5erg7vetP7Nj1Imw
         0j6DYxYHXxP/3/hgF1r2acwnS6uJy6n340UkRK7Lra2jYvat6y/JtS9WV19ByIoQJTyk
         +7pQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=Wo51Oxn2;
       spf=pass (google.com: domain of rientjes@google.com designates 2607:f8b0:4864:20::635 as permitted sender) smtp.mailfrom=rientjes@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:from:to:cc:subject:in-reply-to:message-id:references
         :mime-version:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=MZs8ozGZJnvIPcITMWzFY8mly+P27TElSCA4HIgLdZs=;
        b=Pk6oN6StSftAl0hD5lZ0HpXC/t7/LERvEuz7M18JRikeNPqdQwFNWDSKDepSGnkeuL
         o6QOt36qcw6o1y3cKRWtAYyF90O+V/cc0n4iy1w1Z8Iee2QQ8BoLd3sxYl8+y7fqIcq2
         Ia+zJJad4Hs49pC8sNeCTFlbAOC3KPSOCrN43bf/LAIiBmdouZ4YmvY3jUF1IDuEb5f1
         d5FbY7/m2EiqKwW8aA2sqNi+2q/295g0QJ15/WoTufB9R6177pLurWMX44+Bcw2z14zt
         weMi3seGr/9XKKdnCyZ3L236AZpQZQMq0Z3WW36ioR6k8wAldJWsdyWd2PapYKvH0J9Z
         3rFw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:from:to:cc:subject:in-reply-to:message-id
         :references:mime-version:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=MZs8ozGZJnvIPcITMWzFY8mly+P27TElSCA4HIgLdZs=;
        b=3KYkiWB4IgoE+2idd2YsbqDx5Z6aYSQQdtzshOOAPJ0gVeCTVOaAmrPw5dln0svFFF
         UXkAePAVUw0logzBhtlB1J8QzXP58Ld1w6hnHqPvtm4sF77Kq+neR246WC0LzeD/veAl
         qZSUEI5MzI/RatfZRk5bbK/0dlDfmYErx8c29o+1qXScj8Wo2eFjR4DTJ/ROxqjbChep
         iA4N/dvCBDh/+HRq0UMqbyElCEoFMEkzVlPi5EpkduCclN6V9LKtz5XASFD/7ulRLU4Y
         iP/Q4NfISnv8sd24aQOnHtKkvPxAuFeAOMV5DyY4ZCo759msg6GsGymqgpP2phMq0Cp2
         /tkg==
X-Gm-Message-State: AOAM531PAfXi58HnGCI+1jtwqqw0JQQSHDVqK8hS/nLDtVVk8jc1z9KJ
	6u6fWYUN9npOavmedrFixpA=
X-Google-Smtp-Source: ABdhPJzX2ca6jE9ANG6+0YrnpYghcrByDpoYUrrWSFztOLGjpry1W40MJiPpQxIEFGZpcm34rk8FDQ==
X-Received: by 2002:a05:6602:2b0d:b0:649:b2f:6290 with SMTP id p13-20020a0566022b0d00b006490b2f6290mr6069403iov.94.1650827722077;
        Sun, 24 Apr 2022 12:15:22 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6638:3720:b0:32a:ad88:c33f with SMTP id
 k32-20020a056638372000b0032aad88c33fls2003535jav.10.gmail; Sun, 24 Apr 2022
 12:15:21 -0700 (PDT)
X-Received: by 2002:a05:6638:dce:b0:32a:e5e6:a98b with SMTP id m14-20020a0566380dce00b0032ae5e6a98bmr1372253jaj.307.1650827721302;
        Sun, 24 Apr 2022 12:15:21 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1650827721; cv=none;
        d=google.com; s=arc-20160816;
        b=nxbQMJ9VY8DiuIiusTeAYeW/vIkYIe6gRTwA4ixFQEYJ2RuH3yaeQnBSHouGI3pvXO
         VTAs5IJvEM6ObraRTgF5MySMpKQTRxjZJ2DfzK/4MiJ+l9lgCzgswOkIM9/bAkwMrqqW
         zq7AT7iPPxo8ksFol0bRoBdYtKDS41BdqkIUo0jlpRcXb4JgGSdVGsVD6uv8FSk5S/Vt
         LhKV25M3XeAw5U/SZiEwmcYd7hx0uop5R1K+TaLaOfBEaJ/t0/+M8e3Zm7u8QstTg2Gu
         IYheXYvLTDPmiIEnr6YiCptYOj5dYJd4deO2GEewWYGjPJ3iA3ovr9/jECVkMUl4igwS
         v4fg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:message-id:in-reply-to:subject:cc:to:from
         :date:dkim-signature;
        bh=jsx4mhumyN262gUb7FrEPxMNx1chS7GsJEszWuM5D/A=;
        b=TaMG8gv1gYtmuZ1e3Sr9H5o95fDcBjZ8WNrbwRrhzLgZ8FdL7WZgzrY4KzeA5Vec60
         ccJOQurU7ts1A19BnEics4B6PlkY8Ri/udXHZMYCpVUDDX04FBrz0C2+lEDl3xZT3J3b
         GlJOmF4lsbGgWOZWmaQE6hS8R9LiOWHXb9QVg8Sen11y4eCNcdy1O2PSF4Bf6V1StWsh
         X0VKSkv1n3NwgEKP3PnewV063kZi4RGAPrIS4rCU6AkRjI6NaiKEibCwl6peEK23TE4A
         5ygc6582j3DrkHaFa5NcyRSjVMoFyAEBcEQGCru6wkesOXopCsBi3niNmiz++NvzxecW
         AJSw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=Wo51Oxn2;
       spf=pass (google.com: domain of rientjes@google.com designates 2607:f8b0:4864:20::635 as permitted sender) smtp.mailfrom=rientjes@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pl1-x635.google.com (mail-pl1-x635.google.com. [2607:f8b0:4864:20::635])
        by gmr-mx.google.com with ESMTPS id i15-20020a023b4f000000b0032660e40519si822714jaf.5.2022.04.24.12.15.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 24 Apr 2022 12:15:21 -0700 (PDT)
Received-SPF: pass (google.com: domain of rientjes@google.com designates 2607:f8b0:4864:20::635 as permitted sender) client-ip=2607:f8b0:4864:20::635;
Received: by mail-pl1-x635.google.com with SMTP id k4so10872033plk.7
        for <kasan-dev@googlegroups.com>; Sun, 24 Apr 2022 12:15:21 -0700 (PDT)
X-Received: by 2002:a17:90b:1e49:b0:1d2:9d82:8bb1 with SMTP id pi9-20020a17090b1e4900b001d29d828bb1mr27937373pjb.226.1650827720436;
        Sun, 24 Apr 2022 12:15:20 -0700 (PDT)
Received: from [2620:15c:29:204:d4fc:f95c:4d79:861f] ([2620:15c:29:204:d4fc:f95c:4d79:861f])
        by smtp.gmail.com with ESMTPSA id c9-20020a63a409000000b0039912d50806sm7313352pgf.87.2022.04.24.12.15.19
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sun, 24 Apr 2022 12:15:20 -0700 (PDT)
Date: Sun, 24 Apr 2022 12:15:19 -0700 (PDT)
From: "'David Rientjes' via kasan-dev" <kasan-dev@googlegroups.com>
To: Peter Collingbourne <pcc@google.com>
cc: Andrey Konovalov <andreyknvl@gmail.com>, 
    Hyeonggon Yoo <42.hyeyoo@gmail.com>, 
    Andrew Morton <akpm@linux-foundation.org>, 
    Catalin Marinas <catalin.marinas@arm.com>, 
    Linux ARM <linux-arm-kernel@lists.infradead.org>, 
    Linux Memory Management List <linux-mm@kvack.org>, 
    Linux Kernel Mailing List <linux-kernel@vger.kernel.org>, vbabka@suse.cz, 
    penberg@kernel.org, roman.gushchin@linux.dev, iamjoonsoo.kim@lge.com, 
    Herbert Xu <herbert@gondor.apana.org.au>, 
    Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
    Alexander Potapenko <glider@google.com>, 
    Dmitry Vyukov <dvyukov@google.com>, kasan-dev <kasan-dev@googlegroups.com>, 
    Eric Biederman <ebiederm@xmission.com>, Kees Cook <keescook@chromium.org>
Subject: Re: [PATCH v3] mm: make minimum slab alignment a runtime property
In-Reply-To: <20220422201830.288018-1-pcc@google.com>
Message-ID: <5cb2b96c-4f5e-d278-534a-d9e1ea989cf@google.com>
References: <20220422201830.288018-1-pcc@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: rientjes@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=Wo51Oxn2;       spf=pass
 (google.com: domain of rientjes@google.com designates 2607:f8b0:4864:20::635
 as permitted sender) smtp.mailfrom=rientjes@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: David Rientjes <rientjes@google.com>
Reply-To: David Rientjes <rientjes@google.com>
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

On Fri, 22 Apr 2022, Peter Collingbourne wrote:

> When CONFIG_KASAN_HW_TAGS is enabled we currently increase the minimum
> slab alignment to 16. This happens even if MTE is not supported in
> hardware or disabled via kasan=off, which creates an unnecessary
> memory overhead in those cases. Eliminate this overhead by making
> the minimum slab alignment a runtime property and only aligning to
> 16 if KASAN is enabled at runtime.
> 
> On a DragonBoard 845c (non-MTE hardware) with a kernel built with
> CONFIG_KASAN_HW_TAGS, waiting for quiescence after a full Android
> boot I see the following Slab measurements in /proc/meminfo (median
> of 3 reboots):
> 
> Before: 169020 kB
> After:  167304 kB
> 
> Link: https://linux-review.googlesource.com/id/I752e725179b43b144153f4b6f584ceb646473ead
> Signed-off-by: Peter Collingbourne <pcc@google.com>
> Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>

Acked-by: David Rientjes <rientjes@google.com>

The command line options are described by 
Documentation/dev-tools/kasan.rst but it doesn't look like a update is 
necessary.  I think the assumption today is that if we're using kasan=off 
then we aren't doing the alignment.

I do wonder why kasan=off is not at least mentioned in 
Documentation/admin-guide/kernel-parameters.txt and perhaps for all other 
kasan options point the reader to Documentation/dev-tools/kasan.rst.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/5cb2b96c-4f5e-d278-534a-d9e1ea989cf%40google.com.
