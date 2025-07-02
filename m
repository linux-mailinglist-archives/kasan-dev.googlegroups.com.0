Return-Path: <kasan-dev+bncBCSL7B6LWYHBBIFJSXBQMGQE7PXGUDY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x239.google.com (mail-lj1-x239.google.com [IPv6:2a00:1450:4864:20::239])
	by mail.lfdr.de (Postfix) with ESMTPS id C6FCFAF5D8F
	for <lists+kasan-dev@lfdr.de>; Wed,  2 Jul 2025 17:47:59 +0200 (CEST)
Received: by mail-lj1-x239.google.com with SMTP id 38308e7fff4ca-32b3a3c5cd0sf33561391fa.3
        for <lists+kasan-dev@lfdr.de>; Wed, 02 Jul 2025 08:47:59 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1751471266; cv=pass;
        d=google.com; s=arc-20240605;
        b=J0wRs7Da3rBJkKbHPzjY0C0oFbkOmOkpP+EYpNnYf/z1QXz4Wmm7QxBahjWKwQzygV
         tnRrRAEVuXCAaGSwegBJm3aqcZXNE76FR4p4D58gGT/EH+oJYvPWwT3jjzRaNO8gCeKQ
         PqjC4gCXqM/jS4V44qFtOI9klFTmggW/aI23lyg9PqAInTFmtMRC4fJE2F/0oiHl/afy
         tY6ebqvikw2Da8chCevZYWTLoRdgQHFMSeIHilQo6E3LqeqfETSmiHt3cM+o0ZmCYeIp
         mw9ouGjJQJDrIXDu9GY7Y21ckSyCc/UxfJbB+i5/uGVJGeUR2AFBMMKpsBImXageKcUJ
         whsA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature:dkim-signature;
        bh=v0JBYXMiQyGAM+TGtU08HwpoUJSWcHQMkK+FaH9dhMo=;
        fh=Z1fGRBjEjvOZE4fnRZI2TBjpEyfG1QEPUsFz+/gbSlE=;
        b=Jfo2EgiEG86invljr2fox2NYSW7BKieAv5FNAp/o9FW+9L54+XyKr98/agdlq8KMlS
         amYKFy4Yj38Vxdq5lVUb5U7ir4Gl1rqoumSQjC5xQlZVnXMVVbwS5V4WJxknEMlrCzFB
         3JIRhms8jZHZsALyysTstHRsvkFD7/TiIHDSEAUkTUzR940MOk9PL1PVF2NTP2mRclx0
         +aKLqd04+0VstKVpcEVi7SiBFTs27HQ6mKoHkQGfe7CcdpNyVON9RzAEkbgrs3Yq+/bo
         ByXAmtQO96yT/zi8s5n2MsWjRGWoAhtOl7R8xhIyQEMHZvraI4RsP14VW8w5zdxRuGg9
         uaiw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=a6QVILlU;
       spf=pass (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::132 as permitted sender) smtp.mailfrom=ryabinin.a.a@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1751471266; x=1752076066; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:content-language:references:cc
         :to:subject:user-agent:mime-version:date:message-id:sender:from:to
         :cc:subject:date:message-id:reply-to;
        bh=v0JBYXMiQyGAM+TGtU08HwpoUJSWcHQMkK+FaH9dhMo=;
        b=dZcJkT0nL3ZkVR1nCJq/d9/0aN9lZhKk4myIwx/AvSWz3HOdXZ3xn2Pg/S4Ucl929H
         J6AXcnCfXPslU1WH6chtxldkAX9/Ph4HAv/Mp/Z88Ynf3v/67bH7W5DMGL0A9ZGqkInK
         uDx3N35UUmFyI6b3iakMTEMgQcjax4ZLsBpdCBi4lkcQWtEBHXAbdDgMVZm7OuiE+ETV
         Ce8OE9ZmMALD8062eVaXJvR70RAd8huuebWIN1PMbpaXqoc9nLlO5b3NSNHfWz/oM9+g
         7NZGVYDox/QOQReU2GQ5yadXs5PnaObcHMNxMqS96m4Pu9L533J5ZFIBGQUcRkYqoGwC
         XYPg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1751471266; x=1752076066; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:content-language:references:cc
         :to:subject:user-agent:mime-version:date:message-id:from:to:cc
         :subject:date:message-id:reply-to;
        bh=v0JBYXMiQyGAM+TGtU08HwpoUJSWcHQMkK+FaH9dhMo=;
        b=GR7zSAa9vX8KNa04Jub74Iby7RLph88O3f1f37HAWDvHiNtQ8pDGf3s+g/Na1M9IFQ
         0Uag3F7bThAx6fAbY5CNbMDtJrT79v0oyTng6pDE3saNieuYCa+5uLhCodLSojQrCGGr
         XjbUiBW2/KLpB7ryL8lcWcAV32ZQxZUDr9ZGwO9N10v30ncLxVWnQDu5wRB+dtrBuwJF
         7D9YYiIf43gtCzhtSLjdhXzLmHL0zWRySNHLQWKg62d07kjoimqsPteIFeG4pWGlg2s6
         YdpYHIqjmYlRwe/5eKbR6Mlr87EoPH4J6mrtmqjY+PXJWjWbs+1BHnESHiwI7XMhPy+S
         seDw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1751471266; x=1752076066;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:content-language:references:cc:to:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=v0JBYXMiQyGAM+TGtU08HwpoUJSWcHQMkK+FaH9dhMo=;
        b=UvdfScP3npqtZP5ZYo9ogKSlSwOHZIzhz7nN1tkGXd4t1qhwMmM7chXdxdHk3TPclZ
         ic7K1v6b0f4YISTgyGLSJX9TuLcuFxsgpGRNN0HEWtiDtvdqSAmDujCFQostlNl/43PO
         IXkmhixLkmlrn308qEZkXYGHSRW8SqdRVVMHL2qYEfUakaWQeUVTmqVwuXbkeduU+oyr
         qLAgOWrr1g1vhKqF0JcQzZ6EVMim1mBchNPlbRkF3UQucIWw1nUUzL/1Ribzzb4p4veM
         apQSr3CXcJAtK3WF4HNYFCMo4cQTXyyPQoi4fTIrUaDBTuLu8JwtM8+nSF30Rd2fusW9
         C2UA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWtIw/4dRuVN9jfyKlpfFdc4HE+fp8Sw1uYs/M+8c5RUGfv+C2h1J/xZ35FxiezW1VAhb/TjA==@lfdr.de
X-Gm-Message-State: AOJu0Yzf2EIp7uEBS8O82p3vz0lTiJn5UUoM/pp7r5o1lH06BCXqiU2H
	xRVQivqjBjew987fyGVUrCnQaEMxXwox/qQEVGln+1XuNkONrpeZsiht
X-Google-Smtp-Source: AGHT+IEuzuHgms90IZSvaVz+GbUOJT9XcDp7k7uF+5mb1C9COMNnJOvcmx0tflu2YE5dGOzA0e0sgw==
X-Received: by 2002:a05:6512:6c1:b0:550:e4a2:e0e0 with SMTP id 2adb3069b0e04-5562834a0b5mr1389553e87.44.1751471265183;
        Wed, 02 Jul 2025 08:47:45 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfMsg4A111gwY6XUhrOawZfLII8lIjvZRBxT0M8mXCdeg==
Received: by 2002:a05:651c:1488:b0:32a:6e73:cf7e with SMTP id
 38308e7fff4ca-32df407bffdls4424521fa.2.-pod-prod-03-eu; Wed, 02 Jul 2025
 08:47:41 -0700 (PDT)
X-Received: by 2002:a05:6512:3045:b0:553:2418:8c0c with SMTP id 2adb3069b0e04-55628376cc1mr1365917e87.57.1751471261300;
        Wed, 02 Jul 2025 08:47:41 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1751471261; cv=none;
        d=google.com; s=arc-20240605;
        b=GG+4rej6FaAz1LXbTF244JSvWnjT47K3VVyfCr7nwW31sQdT+954ouEjzsDv+oH/pl
         IrrTs+g87khVKi8A3nDBYtnn6RXJW/y4BmtBdVCfkHWpIdjLw+1hBvZRoSyNFZtqi98O
         VRzlXSmI0QPggE8qf6ZtyZkUmfwWyiIFgAZGaraHGActvHikmzt0vb/6mlqBNtAoS+eH
         KcP0pIH9pgdSM3c9fYaYVSZAF1Ftv4p/CNjD6egG7hvBnc6zejRC1nTfenahkgJ5gSS+
         aZWuibvTNDsVPxBzi23B6kM4ACjcbT6dPCOzgNHPnNBUtqLT0aYj2QEc3vY99TMiaAZt
         9eEA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=dg0qjgsbd25kQ2WMiX3ztjtV7rTNZWqsHlNRU5eCd2k=;
        fh=matp1tidYE1pIFBAITmNTSCqnAqZyB+Jo/BIIU/GFIM=;
        b=BiaePT1exbLGrHe5l1yv45ufrjHwqJ4ZQCsIGL4fShgTc7R9sm5wBb9emw4tYmIWe8
         9g7aRaENabGCzeN5/bv/roErB5S4OnikXl6sn8YTE2WHvtR441gFsGINM0koz2Q5fu1m
         Mi6m9qey6nGOQg3FdTvLVEpKJQu1nEDBH6Yowp4xa1LqdzzFmlmd3qcDrCbUyO36vfR8
         /uUNF5y7Uf0kAKaYDA0OJD+T5hk6e3Hsot5Fntk0g3OFHGWrESAf7Oo6fapw1jTcbCUW
         vwIX0zkK2pwxDyO6sS9DaeHPISKdMBzfpumGyZeoyEtnIj6efeHClGWHw1H+urNeNEO8
         wJ/w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=a6QVILlU;
       spf=pass (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::132 as permitted sender) smtp.mailfrom=ryabinin.a.a@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-lf1-x132.google.com (mail-lf1-x132.google.com. [2a00:1450:4864:20::132])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-5550b29d2e6si656075e87.8.2025.07.02.08.47.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 02 Jul 2025 08:47:41 -0700 (PDT)
Received-SPF: pass (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::132 as permitted sender) client-ip=2a00:1450:4864:20::132;
Received: by mail-lf1-x132.google.com with SMTP id 2adb3069b0e04-553aba2f99eso883606e87.3
        for <kasan-dev@googlegroups.com>; Wed, 02 Jul 2025 08:47:41 -0700 (PDT)
X-Gm-Gg: ASbGnctPzb84EioO+Blx1edaHIrHzcCXq7RhLqGgINVIo5OyjVXj56pkaF6nK9b5F6K
	vx8gAVWpBm07VSgY83rg+7C0qpafljSYI2qMRWQr6XqK99isFA8T8dyzfRfx2qCy/JCUjOkgaiK
	4vLRH/IQ1qCT0L35H9qFSpT0/Vxq+DUKbEOQzyzQ4NszRj0D+c5YCwWXI9jb4nwt+KU+coincZQ
	CtQudX3ee3t9vn7YJriQZMjznP3BA4vd4/VeA67B5ObbeXxzCDS2KskvF8VfAGLy61RAIaTn8kJ
	vBCM1x6iPCTe0YMIlsCkvSFjbmWhA+fJ1RU7diEbL2vjkBhZCNhIBEpqxQeen5rZ07u/poBRef4
	Vuao=
X-Received: by 2002:a05:6512:3191:b0:553:6514:669e with SMTP id 2adb3069b0e04-556282950d5mr421178e87.14.1751471260535;
        Wed, 02 Jul 2025 08:47:40 -0700 (PDT)
Received: from [10.214.35.248] ([80.93.240.68])
        by smtp.gmail.com with ESMTPSA id 2adb3069b0e04-5550b2eec3dsm2160750e87.242.2025.07.02.08.47.39
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 02 Jul 2025 08:47:40 -0700 (PDT)
Message-ID: <4599f645-f79c-4cce-b686-494428bb9e2a@gmail.com>
Date: Wed, 2 Jul 2025 17:46:23 +0200
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH] kasan: don't call find_vm_area() in in_interrupt() for
 possible deadlock
To: Yeoreum Yun <yeoreum.yun@arm.com>, glider@google.com,
 andreyknvl@gmail.com, dvyukov@google.com, vincenzo.frascino@arm.com,
 akpm@linux-foundation.org, bigeasy@linutronix.de, clrkwllms@kernel.org,
 rostedt@goodmis.org, byungchul@sk.com, max.byungchul.park@gmail.com
Cc: kasan-dev@googlegroups.com, linux-mm@kvack.org,
 linux-kernel@vger.kernel.org, linux-rt-devel@lists.linux.dev, nd@arm.com,
 Yunseong Kim <ysk@kzalloc.com>
References: <20250701203545.216719-1-yeoreum.yun@arm.com>
Content-Language: en-US
From: Andrey Ryabinin <ryabinin.a.a@gmail.com>
In-Reply-To: <20250701203545.216719-1-yeoreum.yun@arm.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: Ryabinin.A.A@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=a6QVILlU;       spf=pass
 (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::132
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



On 7/1/25 10:35 PM, Yeoreum Yun wrote:

FYI some of email addresses in CC look corrupted, e.g. "kpm@linux-foundation.org", "nd@arm.com"

> In below senario, kasan causes deadlock while reporting vm area informaion:
> 
> CPU0                                CPU1
> vmalloc();
>  alloc_vmap_area();
>   spin_lock(&vn->busy.lock)
>                                     spin_lock_bh(&some_lock);
>    <interrupt occurs>
>    <in softirq>
>    spin_lock(&some_lock);
>                                     <access invalid address>
>                                     kasan_report();
>                                      print_report();
>                                       print_address_description();
>                                        kasan_find_vm_area();
>                                         find_vm_area();
>                                          spin_lock(&vn->busy.lock) // deadlock!
> 
...

> diff --git a/mm/kasan/report.c b/mm/kasan/report.c
> index 8357e1a33699..61c590e8005e 100644
> --- a/mm/kasan/report.c
> +++ b/mm/kasan/report.c
> @@ -387,7 +387,7 @@ static inline struct vm_struct *kasan_find_vm_area(void *addr)
>  	static DEFINE_WAIT_OVERRIDE_MAP(vmalloc_map, LD_WAIT_SLEEP);
>  	struct vm_struct *va;
> 
> -	if (IS_ENABLED(CONFIG_PREEMPT_RT))
> +	if (IS_ENABLED(CONFIG_PREEMPT_RT) || in_interrupt())

in_interrupt() returns true if BH disabled, so this indeed should avoid the deadlock.
However, it seems we have similar problem with 'spin_lock_irq[save](&some_lock)' case and
in_interrupt() check doesn't fix it.

And adding irqs_disabled() check wouldn't make sense because print_report() always
 runs with irqs disabled.

I see no obvious way to fix this rather than remove find_vm_area() call completely and just
print less info.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/4599f645-f79c-4cce-b686-494428bb9e2a%40gmail.com.
