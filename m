Return-Path: <kasan-dev+bncBDDL3KWR4EBRBNPB3X5AKGQEZRZ76OI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43b.google.com (mail-pf1-x43b.google.com [IPv6:2607:f8b0:4864:20::43b])
	by mail.lfdr.de (Postfix) with ESMTPS id 78BB62610FE
	for <lists+kasan-dev@lfdr.de>; Tue,  8 Sep 2020 13:53:27 +0200 (CEST)
Received: by mail-pf1-x43b.google.com with SMTP id o21sf10327137pfd.14
        for <lists+kasan-dev@lfdr.de>; Tue, 08 Sep 2020 04:53:27 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1599566005; cv=pass;
        d=google.com; s=arc-20160816;
        b=qMBVLDDJiOaV3kPA+WZBrBS4AjZTYE84OTnNIotq+CMkb9PWQkRAW7hsFSLNIFSlsG
         KRwAe4u6+EnpAJNbrmISv/NBFqsGFtG+a3m8hTw4y5fhFVmOutlE+4q0t1aoZuN1XY3s
         lbc5T0t9WDCe8AT5FowO6B4dd60VCjJ/QED2oM8jjaRbQZxh9ntjCnaq323mCeMG3RBF
         n83ni563a8Ma+0lDDuth2WlllbFlfN/Z8ZDnPqj0gEq7HeOreBSTbHqcTn0Wj5UmCJcm
         6iRk+7O07o9vmf77g38nwNZpya/KvSs+l+cR2zkcE/tVhy3oP9d0mUb4NittPzKLvEel
         8dig==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=4zS630L+9LIgecxDLHMNqNkzyS4eMJFJrqUtnAT82r8=;
        b=ockji7osbe6FeybOfsULfZQoEMeueupVZJMQAl2lLluUc5BhoVvsaNhAmkiXTgiGzk
         garUDvnVlLCtaCQVMAXaCp256B478GVkFWRiMN9JUZ3VBqRB1pe+YnQMOI6BdFwaTbnW
         skB/ETOWQbj/XVMq3XNSmHy6guqSms5rFkfvrgR1cgKQcSV4tmBWB5KfmVOwLhCJWOwn
         B+lKS0IvOS1EQXC0i09D2tP1GH02izab/sqR0GqNnGPc6A/mUAt4+noUoIWDIfb2mZO7
         aeEeLk/tQFaUMIXDtJZDS3mA9kcEXfcLqDJPWhFihxKhOZyNrcVFHS5JlQfwwrOGU+kn
         kB6w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=4zS630L+9LIgecxDLHMNqNkzyS4eMJFJrqUtnAT82r8=;
        b=Zpd8t+QnPg+/fn1+6X+dsbPvTyW7k0JvanWkilX/R5hHQ1yFA+IJ7rg2TBC3oj3Z27
         D8fk65QaqQhKNsFdOmHsFAPztDJTn6o/tA0dyetstK6gD3beG3W1tcTs/lwYtDllfEKH
         E2g9sqcPk33tFREh/4M5LJyQthRmXDlm6srvomUtk6p+KDYx9b9y54mUGlEw8GRJC8+e
         5/WpuXFJzZI/RPZJSGRexEQoJxJOMBYfBg9YMHTAExmngEcyOuE5JxJIwYyM1z2Fsyed
         fz2rhhlvYGI2iGAe0kaJkO0+CDhWDqLRC9ldOPY1wb6D1zGRIlN6+ESh7GDZHerO3I3K
         U72w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=4zS630L+9LIgecxDLHMNqNkzyS4eMJFJrqUtnAT82r8=;
        b=QEdZKsvFhzNGlpMykgixNrzQvuOcNBYrtDWNoOjLbhf8cLcFmbHHL32hjjKZcPqv1D
         LFxA2kgJWLseZ7pGIvdMJoC+72KAi8uyWdPBYO6RLxjsbJAVwVsjT+uAgt47GdMAjroy
         DFrDL7F2a6FQCvaeIudwILgZpWyZk9TO5K9M+L+9TlpHcMOLa9idQWWsHRv1QGsx1ePg
         gE/3Gou961dujWo1ZRb5pUwIWXAl2fwDCgMZlp4E0WtJOgqsKpHQ6H1aTK2G12K9Pr9m
         DGS3ghU8diSNv1VINSVUQD+sXsifcar7xL0OevbbDNLKe1Co1sJ0be8cgGEjnepjMX+i
         fwkg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531ZPp9xW1dkScptMuQUGyRi+Vwn0woXvYjaduAr4jBtiECJrwDM
	peNcy5tJxsEnSxQshpWpnMg=
X-Google-Smtp-Source: ABdhPJzgsSAAtuq0iBlFPJAOVL/gO8yqfnUCODu4QCESp3meqjHItU0NwuJ+B3uQtj/OSI5TSeAOlg==
X-Received: by 2002:a17:902:aa85:b029:d0:cbe1:e70d with SMTP id d5-20020a170902aa85b02900d0cbe1e70dmr882372plr.27.1599566005523;
        Tue, 08 Sep 2020 04:53:25 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:b20f:: with SMTP id t15ls3356159plr.1.gmail; Tue, 08
 Sep 2020 04:53:24 -0700 (PDT)
X-Received: by 2002:a17:90a:ed8e:: with SMTP id k14mr3733449pjy.178.1599566004780;
        Tue, 08 Sep 2020 04:53:24 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1599566004; cv=none;
        d=google.com; s=arc-20160816;
        b=cDx6aHZMR+QDi4Q7uGcJHsr0wxDD75/Nd2Pg/dbIawSg2pGlUz6/V/+9FC+0FR/q/R
         1MQH62Enb0atKvBI4KZiEnqQOYy0GodjKiO3XRj4Xlen6skAcnC/uXWmG1/81QhaDKWp
         cVFGLSkd42GPxpJ/re6s68nPC12U01yYAKtq4JtuJ7XmzFO4S8QSResjF0mMpSJ72ZUi
         Jrj7LevZujpMzDfggbwHMD424bvyKjQDECDQG7TiPrfCRlHGHYQwzGHHB9vPKgT0kBww
         eufFkXUlLkclRFKYYv8wBFMmb+AsOtTWVQjdpie1m2oXbG7GrmIjCdEEjxYwa38+urlq
         ABzQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=MukDDcTk0t8gRSa5UChtEit31NBYV2k24mRLiLxB6DA=;
        b=wNRZHrZlC5uqDV4TOk4QJvnqAWEb7A/pTBWyFyEIvRa8/W+k/Y4cg8Bw2DeNnsa2Bt
         KcRlSswQzMAhzzwQVqrOS7AgmNdze6YYd90Ef3AnrPODQNJwZFtkkS4nszMLILy+PZ2s
         yC+VoaK5DqEAMZxB2BptxUlP9t+nNiD0XFhPCZZ53CNNXLpi8VECChlYWRc5v2WPizNh
         91AtkIXkBAthJYFdyHkvwjA9VJuHNY7lQL6x6MOePBcxlv+z7rvmWA5/V/ChoUs/4Y5t
         0GpNx3gTnivEPBYiS5j5mULyiDx2m0Dn/YP+UAfKrmxFNmnGBEW2Q7zFqi3pS5ocbjNC
         kWrg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id w136si651373pff.3.2020.09.08.04.53.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 08 Sep 2020 04:53:24 -0700 (PDT)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from gaia (unknown [46.69.195.48])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id AB9932067C;
	Tue,  8 Sep 2020 11:53:19 +0000 (UTC)
Date: Tue, 8 Sep 2020 12:53:17 +0100
From: Catalin Marinas <catalin.marinas@arm.com>
To: Marco Elver <elver@google.com>
Cc: glider@google.com, akpm@linux-foundation.org, cl@linux.com,
	rientjes@google.com, iamjoonsoo.kim@lge.com, mark.rutland@arm.com,
	penberg@kernel.org, hpa@zytor.com, paulmck@kernel.org,
	andreyknvl@google.com, aryabinin@virtuozzo.com, luto@kernel.org,
	bp@alien8.de, dave.hansen@linux.intel.com, dvyukov@google.com,
	edumazet@google.com, gregkh@linuxfoundation.org, mingo@redhat.com,
	jannh@google.com, corbet@lwn.net, keescook@chromium.org,
	peterz@infradead.org, cai@lca.pw, tglx@linutronix.de,
	will@kernel.org, x86@kernel.org, linux-doc@vger.kernel.org,
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
	linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org
Subject: Re: [PATCH RFC 07/10] kfence, kmemleak: make KFENCE compatible with
 KMEMLEAK
Message-ID: <20200908115316.GD25591@gaia>
References: <20200907134055.2878499-1-elver@google.com>
 <20200907134055.2878499-8-elver@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20200907134055.2878499-8-elver@google.com>
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

On Mon, Sep 07, 2020 at 03:40:52PM +0200, Marco Elver wrote:
> From: Alexander Potapenko <glider@google.com>
> 
> Add compatibility with KMEMLEAK, by making KMEMLEAK aware of the KFENCE
> memory pool. This allows building debug kernels with both enabled, which
> also helped in debugging KFENCE.
> 
> Co-developed-by: Marco Elver <elver@google.com>
> Signed-off-by: Marco Elver <elver@google.com>
> Signed-off-by: Alexander Potapenko <glider@google.com>
> ---
>  mm/kmemleak.c | 11 +++++++++++
>  1 file changed, 11 insertions(+)
> 
> diff --git a/mm/kmemleak.c b/mm/kmemleak.c
> index 5e252d91eb14..2809c25c0a88 100644
> --- a/mm/kmemleak.c
> +++ b/mm/kmemleak.c
> @@ -97,6 +97,7 @@
>  #include <linux/atomic.h>
>  
>  #include <linux/kasan.h>
> +#include <linux/kfence.h>
>  #include <linux/kmemleak.h>
>  #include <linux/memory_hotplug.h>
>  
> @@ -1946,8 +1947,18 @@ void __init kmemleak_init(void)
>  	/* register the data/bss sections */
>  	create_object((unsigned long)_sdata, _edata - _sdata,
>  		      KMEMLEAK_GREY, GFP_ATOMIC);
> +#if defined(CONFIG_KFENCE) && defined(CONFIG_HAVE_ARCH_KFENCE_STATIC_POOL)
> +	/* KFENCE objects are located in .bss, which may confuse kmemleak. Skip them. */
> +	create_object((unsigned long)__bss_start, __kfence_pool - __bss_start,
> +		      KMEMLEAK_GREY, GFP_ATOMIC);
> +	create_object((unsigned long)__kfence_pool + KFENCE_POOL_SIZE,
> +		      __bss_stop - (__kfence_pool + KFENCE_POOL_SIZE),
> +		      KMEMLEAK_GREY, GFP_ATOMIC);
> +#else
>  	create_object((unsigned long)__bss_start, __bss_stop - __bss_start,
>  		      KMEMLEAK_GREY, GFP_ATOMIC);
> +#endif

Could you instead do:

#if defined(CONFIG_KFENCE) && defined(CONFIG_HAVE_ARCH_KFENCE_STATIC_POOL)
	delete_object_part((unsigned long)__kfence_pool, KFENCE_POOL_SIZE);
#endif

-- 
Catalin

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200908115316.GD25591%40gaia.
