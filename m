Return-Path: <kasan-dev+bncBC7M5BFO7YCRBRMERWDAMGQE4CIMEWI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe3e.google.com (mail-vs1-xe3e.google.com [IPv6:2607:f8b0:4864:20::e3e])
	by mail.lfdr.de (Postfix) with ESMTPS id F031A3A40BC
	for <lists+kasan-dev@lfdr.de>; Fri, 11 Jun 2021 13:00:22 +0200 (CEST)
Received: by mail-vs1-xe3e.google.com with SMTP id d195-20020a6768cc0000b029026761c5b34asf60581vsc.20
        for <lists+kasan-dev@lfdr.de>; Fri, 11 Jun 2021 04:00:22 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1623409222; cv=pass;
        d=google.com; s=arc-20160816;
        b=dvTT/uJT4Kn+Sng8Mhd60lMZpahLseXlxYKZooMiwa62yqTca9LD74u9JLlWV1JQ6J
         Sg3HV6UsYfU0YgmqGUEhY6eIgUCb0BF45fegHtRariLSXx/jPLSojfJBa6HePyT3qqRg
         Ekdem5RwENgYiPRngGdJtsQwnpeCccG60/M5NQudKj5Zxc1BPacknSgvNO2NlhO8hrEw
         Ei4mWHqWbgfZ/yXK8m2NZEYkSA5p5ywS8jdM+FI+JW5NuAXwRvB7WKthf0WWbZAWODc7
         DcwWccA2NoW5jPJoi0MMKtr3K/3nFB5+SQDhOPeenOGAO5Awo8B4Ru5FmCNAURGKIrpP
         ZLPw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=GJlCUws6Siqh1pec6a+L8iK6jD9RKsU0pQAnqjJxYLo=;
        b=cyw7PD+xTCVITDD1Ezs8+8ZI0u6MgS9sudlJMccfExoyFA/3DVMwEfzWVMF+rU9DFt
         uUD7/XfmL3dSUfsvz9ZSbNV4w+pYdXnY1r4/RjC42CKp886QquxFcFPFCGhpH1uqnXVj
         UOYYpK1z8zrqCCD+93PTne1wVmJ8+m9WEX7qf7BdZ+QtzjI7W+YIq112+T8I/NjyV84L
         qlKu3EYbqSoLeo2MIfm6l71/U2IFR3c+H9cdq+iZLi3RDpNOQn25x0pkUfXyxWRFp16x
         uBnM3GTctJ9R23A3TUxWzoc7TohUdLEv5z7SlBDWWmNs+svJi0v4+TVE0SA7fEFBURaP
         7eBQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b="Buh9x/rv";
       spf=pass (google.com: domain of groeck7@gmail.com designates 2607:f8b0:4864:20::22a as permitted sender) smtp.mailfrom=groeck7@gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=GJlCUws6Siqh1pec6a+L8iK6jD9RKsU0pQAnqjJxYLo=;
        b=YJ/1FMFaQbEUzGn6s0/uUOBhWPfjuYrpHcf48Pu+EyxVCxAPLJXKNRkKf2q7DrowAa
         CpJ1Yfipc4J5WgMk2jvG/KZ2WHh4MWnbHRekI7nAmwp4xP1qXvg5/1MO3NwaKJPJBBbf
         KtHHpqa2s1crM5bAAtcYCMzZZIvCFIiuL/HUsGQscKFfJHcVcSbUxeMggvYZNVb4ahlZ
         Tivp+bEvLTg/uRB9PJU2rAVblxro68NWgspic6FOdypbpVecOHHTCgnmz9dropck8BIF
         89mRWiJi+EGtCYicBfx4kNsJmPPMn30HucY9XIAfpJ7dsEv+Qv5kN7qCOi2mxMNA1wFs
         sZaQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=GJlCUws6Siqh1pec6a+L8iK6jD9RKsU0pQAnqjJxYLo=;
        b=bWyBvDKjg7V+lcV7TON7hoJBZvtRynjjQlTj364lD6VjWgt0PCap3Vm+bjBCSYM0wK
         dnDABfP5CqCNx3qqzJSi4uQAScv3pEwdL4ZaJ4rd/BCloiwmvpHSHdBIdG/11uNVqUDy
         y8vcutZdnxk2Kq2w3wxjtBVR0lic1MlwZndM/oBw9Q0WFROAPTwxfKHSePICiKn/neC+
         00QEAByVixkocRBW6QGFGAKsMC44ZhahX3LVK8RH3oWj9XdyqzQnBR5qrR7ga3xaBZR1
         3kUlDDSdtqXWYmJnUoRNiht7jhYsvTGGOxKHjYjG6yK3zQHT8yBLJqieSKYQjjmjrFFI
         bfUw==
X-Gm-Message-State: AOAM530RxbklDe82afOoomhLdiIExFH4l43jripltIpwTuNjWBdyb2HL
	7fZdxhaGx3wYPwEeYz451vg=
X-Google-Smtp-Source: ABdhPJy/aFxN8ehlxzqrqjsCtJc3RmM/kpFcDymz9/ymEKmsSREpbxRyQrXg+MXE+pmMfrlLCk08xg==
X-Received: by 2002:ab0:60c5:: with SMTP id g5mr2108903uam.5.1623409221990;
        Fri, 11 Jun 2021 04:00:21 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ab0:66c7:: with SMTP id d7ls1416991uaq.0.gmail; Fri, 11 Jun
 2021 04:00:21 -0700 (PDT)
X-Received: by 2002:ab0:4ac3:: with SMTP id t3mr2103011uae.10.1623409221442;
        Fri, 11 Jun 2021 04:00:21 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1623409221; cv=none;
        d=google.com; s=arc-20160816;
        b=tlGs7qvLfqoI0ZL1YyRZNgCAB1tglI5pxOvVBGAIufdifX8+YdTgSvxnNNUwmIBxAe
         WzMCmIzDHACpum6lIP297BBwbMg/mJj2MxPWupIukDbe6zCMC01wJuGKWpY3jik8hgY3
         GEYfRU8HK+3vOcifcWDRbDTFxpSNO3OaDwusciO/KXpU4TVS2hgpiOUQObc2swi6UCen
         N/kzONzhZBJW7QndSuW8aDjQftjpIGKLiVpWHPH++B5ddhmBj+KE0gHVRwrpuLGdcPxQ
         mdWY3klWCBqCpANcZHYbRmDTOdGtU4UwEwt/g/Wu9DfvzAoAtKhCXAPQnDKXVCdSF8AT
         LA+w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:sender:dkim-signature;
        bh=QJ/vQZOVwDNIecKs4rsjKD7AQHx1NJ2yzEFPPDK+J9o=;
        b=0I753kAwZBbmyChvZRerU4RrqboHy+1dXfbAkliAWDKPz+FaOoFgEnJ5amIWO9+HMZ
         MCEbyMgZzKrUZDrRuOXqydXBNtGNMH5VgDkCDZglcrAu/WVrao3I1r1Pc/DB2ccAkMYo
         UmLteTQmvWXB1hMxlS89Tx5aceFbWDY4dJ/vosIp46ufiBHRMFN99jhmidGgdCFg+zEk
         hlAL2ADLoxRNji+i6U4bGpDPxCkhlIhByvJULkyTJjrfChP6GSJTMNURZJX5sAqwwn3Z
         ozQGPeYjMBfG0fLNIq6Bsv+s1e3J/pd8kUFTuIFICkFJ+se0BYFPpCnGXlnfBQKAm8gP
         RCUg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b="Buh9x/rv";
       spf=pass (google.com: domain of groeck7@gmail.com designates 2607:f8b0:4864:20::22a as permitted sender) smtp.mailfrom=groeck7@gmail.com
Received: from mail-oi1-x22a.google.com (mail-oi1-x22a.google.com. [2607:f8b0:4864:20::22a])
        by gmr-mx.google.com with ESMTPS id t1si431904vsr.1.2021.06.11.04.00.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 11 Jun 2021 04:00:21 -0700 (PDT)
Received-SPF: pass (google.com: domain of groeck7@gmail.com designates 2607:f8b0:4864:20::22a as permitted sender) client-ip=2607:f8b0:4864:20::22a;
Received: by mail-oi1-x22a.google.com with SMTP id q10so1158262oij.5
        for <kasan-dev@googlegroups.com>; Fri, 11 Jun 2021 04:00:21 -0700 (PDT)
X-Received: by 2002:aca:c441:: with SMTP id u62mr12904876oif.31.1623409220901;
        Fri, 11 Jun 2021 04:00:20 -0700 (PDT)
Received: from localhost ([2600:1700:e321:62f0:329c:23ff:fee3:9d7c])
        by smtp.gmail.com with ESMTPSA id q1sm1101652oog.46.2021.06.11.04.00.19
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 11 Jun 2021 04:00:20 -0700 (PDT)
Sender: Guenter Roeck <groeck7@gmail.com>
Date: Fri, 11 Jun 2021 04:00:19 -0700
From: Guenter Roeck <linux@roeck-us.net>
To: Andreas Schwab <schwab@linux-m68k.org>
Cc: Alex Ghiti <alex@ghiti.fr>, Palmer Dabbelt <palmer@dabbelt.com>,
	corbet@lwn.net, Paul Walmsley <paul.walmsley@sifive.com>,
	aou@eecs.berkeley.edu, Arnd Bergmann <arnd@arndb.de>,
	aryabinin@virtuozzo.com, glider@google.com, dvyukov@google.com,
	linux-doc@vger.kernel.org, linux-riscv@lists.infradead.org,
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
	linux-arch@vger.kernel.org, linux-mm@kvack.org
Subject: Re: [PATCH v5 1/3] riscv: Move kernel mapping outside of linear
 mapping
Message-ID: <20210611110019.GA579376@roeck-us.net>
References: <mhng-90fff6bd-5a70-4927-98c1-a515a7448e71@palmerdabbelt-glaptop>
 <76353fc0-f734-db47-0d0c-f0f379763aa0@ghiti.fr>
 <a58c4616-572f-4a0b-2ce9-fd00735843be@ghiti.fr>
 <7b647da1-b3aa-287f-7ca8-3b44c5661cb8@ghiti.fr>
 <87fsxphdx0.fsf@igel.home>
 <20210610171025.GA3861769@roeck-us.net>
 <87bl8dhcfp.fsf@igel.home>
 <20210610172035.GA3862815@roeck-us.net>
 <877dj1hbmc.fsf@igel.home>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <877dj1hbmc.fsf@igel.home>
X-Original-Sender: linux@roeck-us.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b="Buh9x/rv";       spf=pass
 (google.com: domain of groeck7@gmail.com designates 2607:f8b0:4864:20::22a as
 permitted sender) smtp.mailfrom=groeck7@gmail.com
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

On Thu, Jun 10, 2021 at 07:29:15PM +0200, Andreas Schwab wrote:
> On Jun 10 2021, Guenter Roeck wrote:
> 
> > On Thu, Jun 10, 2021 at 07:11:38PM +0200, Andreas Schwab wrote:
> >> On Jun 10 2021, Guenter Roeck wrote:
> >> 
> >> > On Thu, Jun 10, 2021 at 06:39:39PM +0200, Andreas Schwab wrote:
> >> >> On Apr 18 2021, Alex Ghiti wrote:
> >> >> 
> >> >> > To sum up, there are 3 patches that fix this series:
> >> >> >
> >> >> > https://patchwork.kernel.org/project/linux-riscv/patch/20210415110426.2238-1-alex@ghiti.fr/
> >> >> >
> >> >> > https://patchwork.kernel.org/project/linux-riscv/patch/20210417172159.32085-1-alex@ghiti.fr/
> >> >> >
> >> >> > https://patchwork.kernel.org/project/linux-riscv/patch/20210418112856.15078-1-alex@ghiti.fr/
> >> >> 
> >> >> Has this been fixed yet?  Booting is still broken here.
> >> >> 
> >> >
> >> > In -next ?
> >> 
> >> No, -rc5.
> >> 
> > Booting v5.13-rc5 in qemu works for me for riscv32 and riscv64,
> > but of course that doesn't mean much. Just wondering, not knowing
> > the context - did you provide details ?
> 
> Does that work for you:
> 
> https://github.com/openSUSE/kernel-source/blob/master/config/riscv64/default
> 

That isn't an upstream kernel configuration; it looks like includes suse
patches. But, yes, it does crash almost immediately if I build an upstream
kernel based on it and try to run that kernel in qemu. I did not try to
track it down further; after all, it might just be that the configuration
is inappropriate for use with qemu. But the configuration isn't really
what I had asked.

Guenter

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210611110019.GA579376%40roeck-us.net.
