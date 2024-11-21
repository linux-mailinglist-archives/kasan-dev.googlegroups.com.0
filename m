Return-Path: <kasan-dev+bncBC7OBJGL2MHBB6X37S4QMGQEYGTR4AI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3d.google.com (mail-oo1-xc3d.google.com [IPv6:2607:f8b0:4864:20::c3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 12C2C9D4E3E
	for <lists+kasan-dev@lfdr.de>; Thu, 21 Nov 2024 15:04:44 +0100 (CET)
Received: by mail-oo1-xc3d.google.com with SMTP id 006d021491bc7-5eb832f845bsf671762eaf.3
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Nov 2024 06:04:44 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1732197882; cv=pass;
        d=google.com; s=arc-20240605;
        b=c5IeiujS4KofLs36XbPc55I23aU6nPrSV7cVsz1UBQltesr4D+Pc0ZRJan/8kSy62P
         /MpfjQYPd5DyfzYXt/Pu5sde/XIF50jhjNWuTw1Uhi1JxsGM0+cXMHfQiCoDe5U2Jc0s
         0oFPgdzMdjXocY+VKxp+6llXnnRN5ikWZQahOO1Cgthhp0nj5M1vCmuCUzXLTXzs/6ut
         ibwdqtqvUIWf3eo60qKT4NmwcqILF3EU+FrGsxottlqvxYTHaq0tM/dip3Sd45Bhz0Oc
         p8MfPQ2X5l4OnrBqwN0ioFKBBoeYnwjGhLv194Qg30mJh/rHk0puQJL3nwZ4nUS9fKg/
         JHCA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=Hb1It5aJb4XaRA/gqRjIShm4ozBID5tELGuMmhY5+3s=;
        fh=OypfN5GttcTzn28NvJFaYw6GHqRassmu2xs0BHmj4DY=;
        b=ebUIiu56PUEdI1ACuCM71/5xHW4TDzCl90XNfi4WOnK3ds2qqoASj3P+cM4yhYc0IO
         b3d2NrO8XzcRzceinzZ0qrLUhA0U18qUVwRkRMxb1eJv10VWo3+7oT3H/7c6hQS3g0hP
         o7qzbIFQkoOhv1ExoRaFLWkQ7xaUNJRXeOLL5cjNBEtei2aq2gug8vEGTaoikcSbKZZE
         Zu9JWn/0iaI+mkLjxwMPE2BSdffAHfZINDXxQ2EJ+OxmTR79RqTmz7cLRusb3vsLNPpz
         QB8gyhcxSZPFFGRzrxOIMAFjHQZBckbww2oNcMOhAxY/rJ0S2Fkpyycv/p1PozNfdlrx
         LamQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=2wW+WUr9;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::631 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1732197882; x=1732802682; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=Hb1It5aJb4XaRA/gqRjIShm4ozBID5tELGuMmhY5+3s=;
        b=C08gZkoxSSyYR8zUcesIzwtNkoxetYSfoezMLPpy+DfFfr8wOHx/Tg/OJcwPaJ29CF
         KUP18iRnuZq+Sisp2oMImpK3giwINTQqD4CwB4KOSRli7ffGMt4cNETDblUPm/TYllsA
         y6VlL3liu51Cj7U6zHeUG1MvzYTuXWvCgLiNjL8n8sSAp3Yo/PV1ux7SoKwpaAaRIUwI
         ag3P9aKAxL40r/Uovn5V2vEhFFuvkeTCXjFye7HcNerEMOuO+Jt4PEz6JEDDxUEwg/dy
         HmHqwBMGp6TsMbSmH/3r5tfAyqt/BvnLDFNaq4Nvwo51jwN/NMZcmGUSjfYm958psg0k
         OkWw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1732197882; x=1732802682;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Hb1It5aJb4XaRA/gqRjIShm4ozBID5tELGuMmhY5+3s=;
        b=oHivf3ColOb0+VfbyZuMqmWStAz4Ia2VvPjacF+CcHohKb5TR8uSEFElOdBlCttezh
         PdVhS5WyBq+BeuzZfTiKsd6ZNIqSKMtT1FgLF16z+gV53I/Ma4EFcOb4k2iNh864oLEm
         8SMgEZ56ZnFm0NWC33g4schn2UjMnsXTYWFv2nHTVeBi2eXSKlWMqE5U2rw2qNMEk4v7
         l0kUvzOouTVen1f3NIj3vYWpZLkc55SXKb2Vm9Q6/deFOn6K+er9SpALuPOt1T9zgXhl
         Vg8garOsehrvMNgm3oqz1/TCwkUc4AXsYMZql7Zm+03WTxj0DdFKZWedCtabLgoj4SY0
         3ywg==
X-Forwarded-Encrypted: i=2; AJvYcCXAw7Bba9n6zX7w8a57pSJSx4bcv3TtNOUCSBgRYlLnuxonQWLg7Ad6658E7P6jkEPbT4ZfVQ==@lfdr.de
X-Gm-Message-State: AOJu0YzuMk/1FhVbNvQZEYQ2tZ21Fq2cPUCA+jOuD2JT9ZUkyYWvMKPb
	sCkO5XV2Rr3YY+ZhvQHjkVcaNalk48yVKdxFSiJRVjfIf2fIa2NB
X-Google-Smtp-Source: AGHT+IGi9HimFaWoEO6uwPsmvFnmgjA3WQ2kMkQFrs2IxT4vllWhpyalDBps7DPPq+l/gwffW9p3qg==
X-Received: by 2002:a05:6871:4396:b0:296:e698:3227 with SMTP id 586e51a60fabf-296e6987712mr5995112fac.36.1732197882506;
        Thu, 21 Nov 2024 06:04:42 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6871:c687:b0:296:ff2b:4d15 with SMTP id
 586e51a60fabf-296ff2bc099ls493551fac.0.-pod-prod-05-us; Thu, 21 Nov 2024
 06:04:41 -0800 (PST)
X-Received: by 2002:a05:6808:f86:b0:3e3:982c:ebf9 with SMTP id 5614622812f47-3e7eb6b8c10mr7787659b6e.5.1732197881472;
        Thu, 21 Nov 2024 06:04:41 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1732197881; cv=none;
        d=google.com; s=arc-20240605;
        b=TV0JeDBY6ICOwAhxW28+0CpNf96Xfc4Zsnc/J9oTAQ9BdncD4QWBlLYxtwrFXroqZy
         66qKLiUu7Hi8IwdFkcacF5aWQkUPvAdcX3CKyAYCwgHysj4oW8ZflFoDwBt6XqwqbEpX
         d5omc8bPfc/NxZ4ArR8/d1HFbjRxI1g/XdJkH4fTBwRzj/RT/7VrojNoPkMgPHazWx9Z
         GcB7PQWLWp7DuSAXYXDyVThK7x6DlUAnz2DQ1Efgo4EYOk2oK9mIRnwqAuRjGRhFRECF
         Wg7DfI2k+9OZP/8dYcmiI105L2bKETYiYFLNcCuxdxxxYnS+owTLvbz6mIJTbnqJPCck
         BPZg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=erYszWFZrBQKpbjQBaOkAS2iZzKQfgGkvxtVuHmI+d8=;
        fh=RFwShgq0QJL05RiZt0A5CLRXZAsP1H30PcBFDXZjC9k=;
        b=XE+WVQIAd2/npIYZldJaaE46gzmFta/D9lBPfesgvHZWtBKZhixjQcTew4lYNhZPVQ
         L/Eog6dgwX/znSgbvIdyrnbwDKs5y/3E4Oqq2mzTErIZurApJoMvrqYT1GR2C+PagnDa
         uABnXCsYM1dFAuiyhm/66sizfoVq4ZVG1iwpBFh/TWWm+nxYudPXKNLbpez1M21YP1ph
         s2oVmeBHgpZ0cQHPDnfhr1TgvyIOO8T35+wDJC+Lxy+o/zd9jj1EdTCpoKZqHCvtiQQn
         l0y2g46VVoNxxSSFZ+kD0lU2KDn1k1csGbBQF2jpmHFjf85jnJa0TWcXojxid+dNoGiF
         4OwQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=2wW+WUr9;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::631 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pl1-x631.google.com (mail-pl1-x631.google.com. [2607:f8b0:4864:20::631])
        by gmr-mx.google.com with ESMTPS id 5614622812f47-3e7bcdaf42fsi700449b6e.4.2024.11.21.06.04.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 21 Nov 2024 06:04:41 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::631 as permitted sender) client-ip=2607:f8b0:4864:20::631;
Received: by mail-pl1-x631.google.com with SMTP id d9443c01a7336-2127d4140bbso9061845ad.1
        for <kasan-dev@googlegroups.com>; Thu, 21 Nov 2024 06:04:41 -0800 (PST)
X-Gm-Gg: ASbGncuUFgwN+JHhpt7xCuyjRzuu21BBe0XND7aFVwG3KL2qg7qCzd75gOT23+A9SVK
	e9FavcauBc/IUsziJIhI3/pwUHaXTTxZcbw9uSa2AhnjK8V3uEpzXXQCqmlAG9g==
X-Received: by 2002:a17:902:ce88:b0:211:e4c4:a565 with SMTP id
 d9443c01a7336-2126a380daemr77451495ad.7.1732197880349; Thu, 21 Nov 2024
 06:04:40 -0800 (PST)
MIME-Version: 1.0
References: <20241121135834.103015-1-andriy.shevchenko@linux.intel.com>
In-Reply-To: <20241121135834.103015-1-andriy.shevchenko@linux.intel.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 21 Nov 2024 15:04:04 +0100
Message-ID: <CANpmjNNzFykVmjM+P_1JWc=39cf7LPuYsp0ds0_HQBCzR+xOvQ@mail.gmail.com>
Subject: Re: [PATCH v1 1/1] kcsan: debugfs: Use krealloc_array() to replace krealloc()
To: Andy Shevchenko <andriy.shevchenko@linux.intel.com>
Cc: kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	Dmitry Vyukov <dvyukov@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=2wW+WUr9;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::631 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Thu, 21 Nov 2024 at 14:58, Andy Shevchenko
<andriy.shevchenko@linux.intel.com> wrote:
>
> Use krealloc_array() to replace krealloc() with multiplication.
> krealloc_array() has multiply overflow check, which will be safer.
>
> Signed-off-by: Andy Shevchenko <andriy.shevchenko@linux.intel.com>

Reviewed-by: Marco Elver <elver@google.com>

Do you have a tree to take this through? Otherwise I'll take it.

> ---
>  kernel/kcsan/debugfs.c | 6 +++---
>  1 file changed, 3 insertions(+), 3 deletions(-)
>
> diff --git a/kernel/kcsan/debugfs.c b/kernel/kcsan/debugfs.c
> index 53b21ae30e00..be7051d0e7f4 100644
> --- a/kernel/kcsan/debugfs.c
> +++ b/kernel/kcsan/debugfs.c
> @@ -166,10 +166,10 @@ static ssize_t insert_report_filterlist(const char *func)
>         } else if (report_filterlist.used == report_filterlist.size) {
>                 /* resize filterlist */
>                 size_t new_size = report_filterlist.size * 2;
> -               unsigned long *new_addrs =
> -                       krealloc(report_filterlist.addrs,
> -                                new_size * sizeof(unsigned long), GFP_ATOMIC);
> +               unsigned long *new_addrs;
>
> +               new_addrs = krealloc_array(report_filterlist.addrs,
> +                                          new_size, sizeof(*new_addrs), GFP_ATOMIC);
>                 if (new_addrs == NULL) {
>                         /* leave filterlist itself untouched */
>                         ret = -ENOMEM;
> --
> 2.43.0.rc1.1336.g36b5255a03ac
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNzFykVmjM%2BP_1JWc%3D39cf7LPuYsp0ds0_HQBCzR%2BxOvQ%40mail.gmail.com.
