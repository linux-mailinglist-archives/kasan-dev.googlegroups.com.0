Return-Path: <kasan-dev+bncBCP4ZTXNRIFBBWO3T33AKGQEOQACH4I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x439.google.com (mail-wr1-x439.google.com [IPv6:2a00:1450:4864:20::439])
	by mail.lfdr.de (Postfix) with ESMTPS id E057E1DE4D0
	for <lists+kasan-dev@lfdr.de>; Fri, 22 May 2020 12:47:53 +0200 (CEST)
Received: by mail-wr1-x439.google.com with SMTP id e14sf4210062wrv.11
        for <lists+kasan-dev@lfdr.de>; Fri, 22 May 2020 03:47:53 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1590144473; cv=pass;
        d=google.com; s=arc-20160816;
        b=zkZEGJ7DvMWSVg1/yiLs6Vqj/+l5Y8eNgrrUS12AAuqbWcdAgUMG4gmExYTaPrD7jE
         b77X5vHbMEabLmMgjCgm72dHBQOqxyewT+kYg7E/07kH01gl0hVil4jbQWRkH0W7azD2
         dmqCdWEcju92Q6eand81tv/nXewoD3P27YyCkR3hewAdIyWhqPcU1mPpjmxQaNlfzxVv
         BAcmTq3npYCCMTMTyVZOU20hzmS30jZzY1F+lkzuL1hVTptN3AeH5LvEc/oLhijGC3gp
         2cg7yKuL0TNZLci0urT9klpaq2FDCsFMMaDc3bqCu2axi98m52ZkbgxGUwspnmoiBVN8
         I1rw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=F3HWlz+r6i9HM8LzRShWZKYMh4nv/AdGVMyp2S5MxDM=;
        b=zABHMetru9Ll31Ye9zZBMjf20vRDwBMfEyh7jhmwJ1rcPZcSiCkTWI0NX5nd5KMzgZ
         Ii+1H53AqL+cfBsjDt/MUot7xlm6tWeJdbKfxyQrfV0LOJMSwc4LIgvYB982EdvIuH+t
         TYqJ80Mq2aMkpI0m+L9HaEEeYA1y17T5/qBGzWJ2i4W+UASPCM3DEqbwTwbSzW5pP6cW
         nmEPGtszCnRIv+YAjjuLczzbRHkzyZeSgGMA/9bfJLrOE3HonuRttKZKnKMYr/6wlhiA
         TmCj0uIScyZUtpFckIHw4RDFv2gqU6g/zpgtbW+qawzfRYBBXWVXtiMX5bvG1VpHOMt/
         v0LQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@alien8.de header.s=dkim header.b=jUCEzp3E;
       spf=pass (google.com: domain of bp@alien8.de designates 5.9.137.197 as permitted sender) smtp.mailfrom=bp@alien8.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=alien8.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=F3HWlz+r6i9HM8LzRShWZKYMh4nv/AdGVMyp2S5MxDM=;
        b=QHu1DQp3GZvB0Dj1KEhoitN+Ve4LRr+KuyTRwtNPn8NNkEUUYXZbcJQBQ1jmRzdeAq
         CjN2nyHUKl9lEJk/4jWQ2FM4IipGLZ+RiVt7l5zWOF5z7kYNWLFjHRXGbwZ7arYDuGB7
         I/dkL6JypZDtc8OcRoaR6fz+zTDRE23leFgsLzfpOxg25WChCbzvOM2HQ/r8/b4DXrxZ
         5W2IacKKrrtq/gK1DpmKi+PfP2RylKZHz4/mqNY+xkl6sbZzje2XGEBlhTUiQZNwzsoN
         0NVcQzYVEey4IgNopl2jnp9KVTXgV1Zx4DX3j7BAw2utZRbwuykKt3M4EjxjWjoip0EN
         Rgww==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=F3HWlz+r6i9HM8LzRShWZKYMh4nv/AdGVMyp2S5MxDM=;
        b=GNPxMn/V4lLE4JZaCJVtWKG7sIBq1k2HQfK38zHVfNssB3zSY+PLn4iiuRshsXcxzx
         bAwMw0ZXj7JqdJfnH/dcEG5ZBHI/JQU7K5glAXHZuVZ+Nl9PGoDxjCQhXEOpocKAbt99
         2+p9rMXYYkCpmnXKt5Bt+QBmGTcfpix7QNQM1UJ0TLvh0rZqo3uQ0HAb21sjpRNMWSw4
         /KQSpZIdxy+54i9Sdfha4iDvV1NuIDpST8UrV9Y3zq8D9QdLMaLAROXF5bXk+//lWVFY
         pGw5ocnlNwvvjxdS1nZKgUi3O9Ty8odmjHD6VxUztfse9lW+yKWN2i/qHIa1jMil6blt
         3CyQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530nSuTyz5FZU2eeWxN9Z8OLqgQD1wGVT4MszCnm7P3uDcIyqPM9
	MHH48/O/emeUWlnBpfhoCRA=
X-Google-Smtp-Source: ABdhPJwCFDw4iG9ztjodUdgKX2fmW7zbk9XBg0P9CUWEoHfKYoluxp/n2ZavB0tDU3gSJIcDp04pmA==
X-Received: by 2002:a1c:46c1:: with SMTP id t184mr13866901wma.185.1590144473618;
        Fri, 22 May 2020 03:47:53 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:9e15:: with SMTP id h21ls528676wme.0.canary-gmail; Fri,
 22 May 2020 03:47:53 -0700 (PDT)
X-Received: by 2002:a7b:cbc5:: with SMTP id n5mr12985839wmi.110.1590144473123;
        Fri, 22 May 2020 03:47:53 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1590144473; cv=none;
        d=google.com; s=arc-20160816;
        b=XXvoIKz5xgPsRUC1wVTvS0SOTCiejmvpPvcFGJMjtyqTi36tVCzAvAYLl/h1+9czWP
         vEe5ZPENRpMXwZL9iLX5jXSnsnKQZoLpPrO4rpgmOJNXOmPZPndQ0ZLOJhmtIs+nbaWr
         lnCK/+GrYhPq3ztL/TghfEWB6X4UlYBZVZWrsuKKGEoAuiATN6M8jxNS+Z/M7EfPL3UC
         ZTopQsN2PX8UPRwMP0nRQI7kRxgwSmKx83+4NaCK1Y/WbZd2mu0QxSZxPoh/oeEftVLW
         yl37Cb5PWmRMS8iwcOfixT5JHeZLC71clKmzA4d6FbloZnZkGqlOfSi31HgXbIkZqntM
         iCaA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=U2u6tNLsMLNzMWM2MweWWtY4enccp4IwxfFDf0b0Msg=;
        b=P0y7jyfX2If3XPtvIQxIfXsvS/CUgAfsljGzudWNRg9MkDBV+mKFS3Fmj7+9OpzkE6
         o19ez0YYwnuAlzmVblBXnTaeIWdc1lID8CxJ0uV9jiPM1zgujVAiooJmwMlqQEBbk+z9
         lYJO6l7Ep9KDrP49tXoI+bmp8QTqMHmZmXxwwBPBsL91dx4Eu2Tp4tJ1BJqGDBXksWnG
         Cnrduy4nMUT2gt12+2CjhMp1ScU252AJPE/nSE2y7+1xvDskEk8M56YXA/8TojNzhJqL
         rQPTY5fCmDjnNC0PrFdJtk7Nb4FtEbihLXtRA3EfeKpybyr1RuLjqSfwku2yIsKBS1j3
         bSHA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@alien8.de header.s=dkim header.b=jUCEzp3E;
       spf=pass (google.com: domain of bp@alien8.de designates 5.9.137.197 as permitted sender) smtp.mailfrom=bp@alien8.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=alien8.de
Received: from mail.skyhub.de (mail.skyhub.de. [5.9.137.197])
        by gmr-mx.google.com with ESMTPS id v11si428634wrp.5.2020.05.22.03.47.53
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 22 May 2020 03:47:53 -0700 (PDT)
Received-SPF: pass (google.com: domain of bp@alien8.de designates 5.9.137.197 as permitted sender) client-ip=5.9.137.197;
Received: from zn.tnic (p200300ec2f0d490039ac3da161697ee8.dip0.t-ipconnect.de [IPv6:2003:ec:2f0d:4900:39ac:3da1:6169:7ee8])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.skyhub.de (SuperMail on ZX Spectrum 128k) with ESMTPSA id 9CD9D1EC02B2;
	Fri, 22 May 2020 12:47:52 +0200 (CEST)
Date: Fri, 22 May 2020 12:47:47 +0200
From: Borislav Petkov <bp@alien8.de>
To: Marco Elver <elver@google.com>
Cc: "Paul E. McKenney" <paulmck@kernel.org>,
	Dmitry Vyukov <dvyukov@google.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@google.com>,
	kasan-dev <kasan-dev@googlegroups.com>,
	LKML <linux-kernel@vger.kernel.org>,
	Thomas Gleixner <tglx@linutronix.de>,
	Ingo Molnar <mingo@kernel.org>,
	Peter Zijlstra <peterz@infradead.org>,
	Will Deacon <will@kernel.org>,
	clang-built-linux <clang-built-linux@googlegroups.com>
Subject: Re: [PATCH -tip v3 03/11] kcsan: Support distinguishing volatile
 accesses
Message-ID: <20200522104747.GD28750@zn.tnic>
References: <20200521142047.169334-1-elver@google.com>
 <20200521142047.169334-4-elver@google.com>
 <20200522102630.GC28750@zn.tnic>
 <CANpmjNM=aHuTWFk45j8BwRFoTQxc-ovghjfwQr5m4K3kVP8r0w@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNM=aHuTWFk45j8BwRFoTQxc-ovghjfwQr5m4K3kVP8r0w@mail.gmail.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: bp@alien8.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@alien8.de header.s=dkim header.b=jUCEzp3E;       spf=pass
 (google.com: domain of bp@alien8.de designates 5.9.137.197 as permitted
 sender) smtp.mailfrom=bp@alien8.de;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=alien8.de
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

On Fri, May 22, 2020 at 12:34:00PM +0200, Marco Elver wrote:
> Yeah, my patch for GCC is still pending. But we probably need more
> fixes for GCC, before we can re-enable it.
>
> We restrict supported compilers later in the series:
> https://lore.kernel.org/lkml/20200521142047.169334-7-elver@google.com/

Yah, tglx just pointed me to it. I'll move 6/11 up in the series.

Just a tip for the future: the idea is to have the kernel build
successfully at each patch so that bisection doesn't break.

Thx.

-- 
Regards/Gruss,
    Boris.

https://people.kernel.org/tglx/notes-about-netiquette

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200522104747.GD28750%40zn.tnic.
