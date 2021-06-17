Return-Path: <kasan-dev+bncBD6MT7EH5AARBDVFVSDAMGQEXFAS3XQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13d.google.com (mail-lf1-x13d.google.com [IPv6:2a00:1450:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id 2B1433AAF64
	for <lists+kasan-dev@lfdr.de>; Thu, 17 Jun 2021 11:14:55 +0200 (CEST)
Received: by mail-lf1-x13d.google.com with SMTP id d20-20020a0565123214b02902ee335ffed2sf1748886lfe.16
        for <lists+kasan-dev@lfdr.de>; Thu, 17 Jun 2021 02:14:55 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1623921294; cv=pass;
        d=google.com; s=arc-20160816;
        b=qDtOF0YjbIFx8Ac8vEIBGX1rIJf/nO8+iwGfD5NdJfYJkGZAETYZqVYWxgqOp2yTb8
         TQQFvmybp2+pMEmoMSuMOmPqf/cWvUtAEdXbFn/zHKtF09rnLaRE01+mpMjkM0LuBkMw
         KJfVRmEeGaO9bfKzq0NRVmVeOvk7cXu3lKYqD8Qht3eQ1AZ3Htwv/DMMxqILrt1OWcyX
         hW/mvnzsoY1qb1kYUp43EZFjn9jP1+hh5Kg03NhZmdi1RWCqsyYQ4iw8ihlLJkH4R8B/
         Aou/df6msTHpVqMPCbDYZxQ4TAe4TdKtpmKOOwdE4eZ6pRWJvgYAnYoRF3Ldk82t075G
         84Eg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:user-agent:message-id
         :in-reply-to:date:references:subject:cc:to:from:sender
         :dkim-signature;
        bh=Y646Hu4RncvOtxsbgL0WIdmQyY9ikg9mGQAJRjx6XvU=;
        b=D1dBpvbzcdbgNJxTxPC6QwGWUn/qFKuusNfYL5TQ1AS3xk11J/aDiVqoo4CqMba7X5
         CyL0hY8FGxK6f45NI4IL07lmPIml9hrA4U8h7nplrckq5+Qr6I0JNPRQnT7w86/YzrBl
         PS3yEu6RRN5+YzKSvHZkDQnJyUqTl5D1n0kQouaA1P9KCmlIucq5FUtKCsghvyERYqFn
         eWEpZNgVwrfmXwX97z1PEkcsn9u/NR2kAISOrWMAbAxAg1879ivVDZoL7O02hvj3mL0J
         Tr++6UsRQkr41J2cnouQFl1L2nuFTT5+VOvlQIEsamjpiP9oRMhAaervS9+2tS8ildi+
         Oelg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of whitebox@nefkom.net designates 212.18.0.9 as permitted sender) smtp.mailfrom=whitebox@nefkom.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:references:date:in-reply-to:message-id
         :user-agent:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Y646Hu4RncvOtxsbgL0WIdmQyY9ikg9mGQAJRjx6XvU=;
        b=i0ZgJmPDyHJf6aRoYrT8jqqB690t9Qjj5Jqh5AXnSJ7fwGsVp+0RnwtwsnTtVWUo/4
         TeL5zsAdOvyxWRrM6VIXGZptQG2QIg/Hk7Efu/TRXn86DqdJTPihWEBulM1VKRz2zbK6
         NhTys522P8hsDVZH9qtj6jie2Lb82o2DI0oBVP6Exmpl4+ieZEiQ3YFoZArlAexIyZbX
         M+1BfXohaNzoX7dYjzIbLXzhquqIWa1oZX4nLjwfWr2t3ieimJa4x+VNojPL4MUzBHar
         IT7wrfBr+RDL4zpMueUpJp3KYN5cTNj+3T8VD0mdEkpbnqMLgUF6ueTHFB2U0Qup6428
         /w6A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:references:date
         :in-reply-to:message-id:user-agent:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Y646Hu4RncvOtxsbgL0WIdmQyY9ikg9mGQAJRjx6XvU=;
        b=lomlbiq6YoG6FMV6smskXn7ACdzFb0Zyk6QOl5srmMnjwLHQ8kmRM1txZphxxkZJu4
         l7+iGmv2kdfNsd3EOV3Tuk32TlT3um7mj9gvO3xlaGwUPhaFONuHTrMgB3dHocl9bkkx
         gSN2uvuObk8HuBHzsj3soemixpUYF2vnTu+eetvKqQwESZFfwtm3R2mmj9Uev1IDlVil
         0VMzO5WcLtlHckYj5g+seKdEN5vqOZOVbw276BjN2SJMY9L1NjKqIuVvFOp8aoGdfPld
         a9p0ahUEZ374GhJ4lYw3tQ5JHtf2XJ1ozHROuLrVtPuUJKAQjnt5y9F+gFU0QFFLG32q
         ocCA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530fvMpy4KJ0Hpffe2fgI49ds1v5MskwSB74u/BC+CX6HLEnZvrA
	NrGK+KtmCnls3caFSw1tUV4=
X-Google-Smtp-Source: ABdhPJwgLVCfCnVGnyOuGpm5mSkFAsK7uRRK8SH8CyOuUoMNsZ8NvhbM/ckiGqSnrYAX+OH+d4/eZw==
X-Received: by 2002:a2e:b4a4:: with SMTP id q4mr3843055ljm.30.1623921294695;
        Thu, 17 Jun 2021 02:14:54 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3f94:: with SMTP id x20ls2399531lfa.0.gmail; Thu,
 17 Jun 2021 02:14:53 -0700 (PDT)
X-Received: by 2002:a05:6512:3ea:: with SMTP id n10mr3245056lfq.178.1623921293406;
        Thu, 17 Jun 2021 02:14:53 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1623921293; cv=none;
        d=google.com; s=arc-20160816;
        b=mC4h1KAezwkTv/kJjAiHLVQPAIw1aQWBYv13wBkREDxy1AtbW8TRJnvSnbhxfZlnSq
         gdd+ke3dlT2IjCU9ib3H1lGZLzAgkRiv0P2Fl3T9+qLDj0/+VqJZhaNk9up9exNfmwHO
         Fxmrip3ZUCT7XtIk7uHOBfVsdA5ZsjTDJOnW93K9Wb19cQ14MgR0mjoERS91949vJEJt
         7/0RHelxoUt4XQEdKexahiia3EIz13Ate83xmqJWqLKpxcbmcJYk0tzzYWZMOt+7HNQt
         yNazTLjPDkoA9OkcxPlu5Xkt1GVHor2cbwzEWOOfd+svsTqEdk0LyBQj8TZWuIOVNqZQ
         /3+Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:user-agent:message-id:in-reply-to:date:references
         :subject:cc:to:from;
        bh=qu7i3hhdP1ganGMmgtZmYgVjw9RAQQJZn5VnIIczNeg=;
        b=EkjMHgqbVOWGQa/RTjjUI4bqz6bzxwcu5HL8Mn3BOXTJMFYi6H6Z8y+gQ3t3/aABF6
         eVG0pEDjJEQLSu2hWjnkHC1aQBaaJK1id3Y6RPEZxMQ3GWXiOT067pyvRB60vuCdnZmc
         QShrgzunApsOyHr5wmYtuu6hZ0hDcqj3WieVKszJRdCa+RBPitjxrrrsWzLsQ6hh9Khs
         fQeYdiU6E9XGdxhaeoIXtOwZvOw+MN9oKUoNoxFuvSMC0mzOPBbbTXym6+vtBGBNxDRS
         eVNGZkQZ6r8NEtbzhduIIaZ5nS2iu/v09aLDQCq44cIJhQoqkSoBVscHyvPHt+m3C2qx
         R6sA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of whitebox@nefkom.net designates 212.18.0.9 as permitted sender) smtp.mailfrom=whitebox@nefkom.net
Received: from mail-out.m-online.net (mail-out.m-online.net. [212.18.0.9])
        by gmr-mx.google.com with ESMTPS id b12si175290lfb.9.2021.06.17.02.14.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 17 Jun 2021 02:14:53 -0700 (PDT)
Received-SPF: pass (google.com: domain of whitebox@nefkom.net designates 212.18.0.9 as permitted sender) client-ip=212.18.0.9;
Received: from frontend01.mail.m-online.net (unknown [192.168.8.182])
	by mail-out.m-online.net (Postfix) with ESMTP id 4G5GbZ5gHmz1r5TD;
	Thu, 17 Jun 2021 11:14:50 +0200 (CEST)
Received: from localhost (dynscan1.mnet-online.de [192.168.6.70])
	by mail.m-online.net (Postfix) with ESMTP id 4G5GbZ3rnkz1qr3h;
	Thu, 17 Jun 2021 11:14:50 +0200 (CEST)
X-Virus-Scanned: amavisd-new at mnet-online.de
Received: from mail.mnet-online.de ([192.168.8.182])
	by localhost (dynscan1.mail.m-online.net [192.168.6.70]) (amavisd-new, port 10024)
	with ESMTP id BNoJzHI3K9ck; Thu, 17 Jun 2021 11:14:49 +0200 (CEST)
X-Auth-Info: +G38n7BK4v8zE2k4U0K1yd1apNmkNM93lb9wmBJEqzJxi4lUTiCAnYN6Jt0+IEcd
Received: from igel.home (ppp-46-244-187-91.dynamic.mnet-online.de [46.244.187.91])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.mnet-online.de (Postfix) with ESMTPSA;
	Thu, 17 Jun 2021 11:14:49 +0200 (CEST)
Received: by igel.home (Postfix, from userid 1000)
	id B037F2C3784; Thu, 17 Jun 2021 11:14:48 +0200 (CEST)
From: Andreas Schwab <schwab@linux-m68k.org>
To: Palmer Dabbelt <palmer@dabbelt.com>
Cc: linux@roeck-us.net,  alex@ghiti.fr,  corbet@lwn.net,  Paul Walmsley
 <paul.walmsley@sifive.com>,  aou@eecs.berkeley.edu,  Arnd Bergmann
 <arnd@arndb.de>,  aryabinin@virtuozzo.com,  glider@google.com,
  dvyukov@google.com,  linux-doc@vger.kernel.org,
  linux-riscv@lists.infradead.org,  linux-kernel@vger.kernel.org,
  kasan-dev@googlegroups.com,  linux-arch@vger.kernel.org,
  linux-mm@kvack.org
Subject: Re: [PATCH v5 1/3] riscv: Move kernel mapping outside of linear
 mapping
References: <20210611110019.GA579376@roeck-us.net>
	<mhng-569bbfda-00d0-4c1f-9a88-69021f258f7e@palmerdabbelt-glaptop>
X-Yow: I will establish the first SHOPPING MALL in NUTLEY, New Jersey...
Date: Thu, 17 Jun 2021 11:14:48 +0200
In-Reply-To: <mhng-569bbfda-00d0-4c1f-9a88-69021f258f7e@palmerdabbelt-glaptop>
	(Palmer Dabbelt's message of "Wed, 16 Jun 2021 19:58:41 -0700 (PDT)")
Message-ID: <87czskonsn.fsf@igel.home>
User-Agent: Gnus/5.13 (Gnus v5.13) Emacs/27.2 (gnu/linux)
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: schwab@linux-m68k.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of whitebox@nefkom.net designates 212.18.0.9 as permitted
 sender) smtp.mailfrom=whitebox@nefkom.net
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

On Jun 16 2021, Palmer Dabbelt wrote:

> This seems a long way off from defconfig.  It's entirly possible I'm
> missing something, but at least CONFIG_SOC_VIRT is jumping out as 
> something that's disabled in the SUSE config but enabled upstream.

None of the SOC configs are really needed, they are just convenience.
They can even be harmful, if they force a config to y if m is actually
wanted.  Which is what happens with SOC_VIRT, which forces
RTC_DRV_GOLDFISH to y.

Andreas.

-- 
Andreas Schwab, schwab@linux-m68k.org
GPG Key fingerprint = 7578 EB47 D4E5 4D69 2510  2552 DF73 E780 A9DA AEC1
"And now for something completely different."

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/87czskonsn.fsf%40igel.home.
