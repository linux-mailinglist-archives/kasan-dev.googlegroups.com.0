Return-Path: <kasan-dev+bncBCT4XGV33UIBBRU7XKXAMGQEURPUVIY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x638.google.com (mail-pl1-x638.google.com [IPv6:2607:f8b0:4864:20::638])
	by mail.lfdr.de (Postfix) with ESMTPS id B3B8D857083
	for <lists+kasan-dev@lfdr.de>; Thu, 15 Feb 2024 23:27:20 +0100 (CET)
Received: by mail-pl1-x638.google.com with SMTP id d9443c01a7336-1d4a87da75dsf14088615ad.1
        for <lists+kasan-dev@lfdr.de>; Thu, 15 Feb 2024 14:27:20 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708036039; cv=pass;
        d=google.com; s=arc-20160816;
        b=UQlV60S+bHIBtzfsTehVkr3dbVdSdTMyrz+K6KPk5UNDx+PS3Fx/M2u6oISgnpq0Aj
         QL7/wayp6oL+qFefKbeoob2Wa5OT+CDPIku9qLP5K3bVL5a7HkS+UrcfMxU4+yPDOydw
         7w0XoooK7l2R8Z7vR/zKa6iuOInLoRQlPmmHajpaYGWY4PmyXQ65yvCpuIhipT0q4wCT
         2nL38b84yhjh4Oz05+HWU04fIMEQrOHbL9nUa1kHIwtUJ33LQusaOFZvAv1r4KsDMr0Z
         yzbKpUVtaJ/qXIMBgGZytxcf/gwpaJ4AKyq9eLmU1Wa1BQ1VaKWcCG2f1Vh7FtYIb2Jh
         Rz0A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=3ICCJ9lDsvtS7e7RYVMrno9k9LA5eQunYbIxBwvrnFg=;
        fh=XDCeJ4k45sfVqQGO1CjdE51izHlIEWlQ7KxSQp3JW3o=;
        b=q8WWB9cIJ6oBpSQwTVpPjdTBGA88JVsHBsIQHblXrRjODwqECZ4zLOPBhkdWimpFnZ
         J69S8Vwj1pzhgI1ahjAeVhOxS+dXN9zQs/HE/QXFn8a7kgrncFtc/f3Y8WrLkaUVzz30
         AVtRvWAHYO/cxtvEM5T+QIP6egONAv/AnSJiSGIfMXUIfEEjcmGAidkC433k3qF9eh53
         oxaFMKKOsGY1gzMAG9s0Kb0ZZSL4iHdxmcx495LIRrXeezT0ukD6PrLDcP7uCH/sBjdh
         Q0GDOsra2rn6ASgWTsxcRVwAQTRMjLu+8kax1CmoIf3U8Iz3vm/t8+HiUTZj3tsKkFIv
         GPIw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=aBCxM7a4;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708036039; x=1708640839; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=3ICCJ9lDsvtS7e7RYVMrno9k9LA5eQunYbIxBwvrnFg=;
        b=UA+CaukebteUT375hnAofQTLeMBzg+xNhDTVOACRdRyFNcIaEWldDLR4AhqEKv1Z2O
         NQn0uZx8knpfPfyRit7C1NrcvzvhVHSzb2RuqXch+DoGdugkx/6LRK5ZVHgbVxh4INrl
         hpfUKFmNShoKhoMBNjRORgPGaIiSrDgoSKArYjcVfcsxOpfD95NaD0YUCFGY9Or+mI6T
         AcyWLeE6/hsO3W4pI43gx9qCXJQ9KlefE7sq7PCXFC+8mQMG/NwvN2qnlu+X+oUoW0i0
         rSBmGkgP5q66SoppLyRRtN2RnlYUCWoCrGsqBQi5nXcgEJSWcUe1qTJYqh2qCgIUt304
         3iWQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708036039; x=1708640839;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:subject:cc:to:from:date
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=3ICCJ9lDsvtS7e7RYVMrno9k9LA5eQunYbIxBwvrnFg=;
        b=sWOJMg4LgXioNhHmAjII7povafVRuGUSSGAKxuRAYKGVumgAyHd6cEf7K3rGKXfuHE
         v0uQRbzBnHxtpSnONitlj9S/PIExIC3NaG2YwVjPMkDsT2YVUu0YHS9iv0fXDAf2ux4L
         34sxaTEi6TcUk5VEn8zvrVsOFxpzfXTgFOj1keIPutQoX0zLTv7za1qeC0O8BOacx2nP
         E4ihXMInmK1pA/DscB2op8akuC8i6YKP151mmPAnuqoNYa0dlZaSwvuz4jk/7SAAGGg1
         JHPTEZzbqrvtfndM3H9sKHLG2dNupxOIklRefhKgE/Moemkun7jVskIlVZqo7DFYJtIN
         sM2Q==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCX6AEaclQRjSpj3KJvXwDpfPZRUF2BuMMg4MTmNbjwfsc9zX09HJoVeRGRjWNzCZb+bemUmynfO+/SaDSsC5Dghgo9Z7VnXfg==
X-Gm-Message-State: AOJu0Yzkucf0RwVupPguatX9p1smoonsroQY7UYawQwOX/eWrJ37Kt6V
	hWrOiwZ2TjpfVioFYEHmdBBLal8t0U6SYW98g4feQzDhkoouL3PN
X-Google-Smtp-Source: AGHT+IFaVt/gygQkDTUFBcK+hOkD/odFW2r5beOoQ6NnwB27m18IsjGm3ALbDNuk1Jf2IWIThnemkA==
X-Received: by 2002:a17:903:26ce:b0:1db:730c:c07f with SMTP id jg14-20020a17090326ce00b001db730cc07fmr2717003plb.18.1708036039051;
        Thu, 15 Feb 2024 14:27:19 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:dac2:b0:1db:969c:f2f with SMTP id
 q2-20020a170902dac200b001db969c0f2fls157157plx.2.-pod-prod-05-us; Thu, 15 Feb
 2024 14:27:17 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXIognLtw4ognn3DRp1Cdq8jBRFmOT0+zQ0vbk6+L3tPEEEW2qLJQ6LEyTCd9W7l6xecp1T8t2GYNwm4oUo+95BWeVuhGrlzfMvhw==
X-Received: by 2002:a17:902:ce83:b0:1d9:3b9e:dc08 with SMTP id f3-20020a170902ce8300b001d93b9edc08mr3990326plg.20.1708036037683;
        Thu, 15 Feb 2024 14:27:17 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1708036037; cv=none;
        d=google.com; s=arc-20160816;
        b=tUVDP80XMk9SJPXrSvzU8Ha290TwgplFtjjgRyLvLqEahD8xoyODKOuXoOMwjXpcSr
         MPMEZssPvIieEZ1zrYQe1z+wTyQpHrVgBEi0ynQiX+4awUHqnj28lUkByB1tNDe69yBK
         oys91SRN6V8lxSR9gzhkhiyF+b9oz1S34Btt5iko1LMw3nC9GYUT1DMM/sFOFkTruWm3
         PACsN7rLnowUuI5xTXwdpMXlUbfoDx7sDSyfvTh9ypIAyFdVzTPQgDbjcFLQtt5afCAj
         E+i1hfRbSdkmfjL+xMUAErSX+U0sMncxpe7Wkc5pQwFaDc6vcJc5hoLJkyqTDNziGNXa
         kLUQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=U9bIaFK7ZMovwwn9NotAsqZyNreQFeAohy95yTtJVDw=;
        fh=g8mz3ECiXsrkOXFrbl+E274ZAGdbU0O0UTXp8AFJRgA=;
        b=p/y+Z6cRR/GZnLXS9feww9Suf919tDosJL4wvEGOyW5T1g7aVljQbvYs3iQWoIceE+
         GfdUJHtZBwwQSvdOkHxv6CFPYrk2DYACIaZxoqbY19jS4Fioo6YZwXLJ54XrSqEXAIzg
         jxKXz2Ru4k2mGUp9HCKT4gna8rBXXZfvn0VbofD82M3wX0D7T5yRPL6+myvbTTnNl5Xy
         NYsa1bfRVC+8WVzflrJcc6bV2EBqOeTKpwNbLEZmP4YvkHuCF10IUw5f/rEycTqHq1RU
         t0GBnZaAOpSgSusir5Sgwm9ABrelUXN1UqVOByZru8pnD8FDLTSlP6EaLlDMP5iSNlC9
         DoOg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=aBCxM7a4;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id f7-20020a170902ce8700b001d8cea8344bsi124614plg.7.2024.02.15.14.27.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 15 Feb 2024 14:27:17 -0800 (PST)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id E822F61E57;
	Thu, 15 Feb 2024 22:27:16 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 459FAC433C7;
	Thu, 15 Feb 2024 22:27:16 +0000 (UTC)
Date: Thu, 15 Feb 2024 14:27:15 -0800
From: Andrew Morton <akpm@linux-foundation.org>
To: Juntong Deng <juntong.deng@outlook.com>
Cc: ryabinin.a.a@gmail.com, glider@google.com, andreyknvl@gmail.com,
 dvyukov@google.com, vincenzo.frascino@arm.com, kasan-dev@googlegroups.com,
 linux-mm@kvack.org, linux-kernel@vger.kernel.org
Subject: Re: [PATCH] kasan: Increase the number of bits to shift when
 recording extra timestamps
Message-Id: <20240215142715.9c9e2c5295d90cc9c7cac4dc@linux-foundation.org>
In-Reply-To: <AM6PR03MB58481629F2F28CE007412139994D2@AM6PR03MB5848.eurprd03.prod.outlook.com>
References: <AM6PR03MB58481629F2F28CE007412139994D2@AM6PR03MB5848.eurprd03.prod.outlook.com>
X-Mailer: Sylpheed 3.8.0beta1 (GTK+ 2.24.33; x86_64-pc-linux-gnu)
Mime-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b=aBCxM7a4;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates
 139.178.84.217 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
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

On Thu, 15 Feb 2024 18:39:55 +0000 Juntong Deng <juntong.deng@outlook.com> wrote:

> Fix the mistake before,

This is rather imprecise ;)

I shall add to the changelog:

Fixes: 5d4c6ac94694 ("kasan: record and report more information")

> I thought printk only display 99999 seconds
> at max, but actually printk can display larger number of seconds.
> 
> So increase the number of bits to shift when recording the extra
> timestamp (44 bits), without affecting the precision, shift it right by
> 9 bits, discarding all bits that do not affect the microsecond part
> (nanoseconds will not be shown).
> 
> Currently the maximum time that can be displayed is 9007199.254740s,
> because
> 
> 11111111111111111111111111111111111111111111 (44 bits) << 9
> = 11111111111111111111111111111111111111111111000000000
> = 9007199.254740

Another important thing to always changelog is the effect of the
bug/shortcoming upon our users.  So that

a) others can decide whether the issue is serious enough to justify
   backporting the fix into earlier Long Term Stable kernels and 

b) people who maintain other kernel trees (of whom there are many)
   are better able to determine whether this patch is likely to address
   a report which they have received from their customers.

Because 99999 seconds is a very long time, I am assuming that the
effect of this upon our users is basically zero, so I shall not be
adding

Cc: <stable@vger.kernel.org>

to this patch's changelog.


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240215142715.9c9e2c5295d90cc9c7cac4dc%40linux-foundation.org.
