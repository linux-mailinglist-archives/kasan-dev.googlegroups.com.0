Return-Path: <kasan-dev+bncBCT4XGV33UIBBOWW5LFAMGQET65BX3Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc37.google.com (mail-oo1-xc37.google.com [IPv6:2607:f8b0:4864:20::c37])
	by mail.lfdr.de (Postfix) with ESMTPS id EA032CF12CC
	for <lists+kasan-dev@lfdr.de>; Sun, 04 Jan 2026 19:02:35 +0100 (CET)
Received: by mail-oo1-xc37.google.com with SMTP id 006d021491bc7-656b3efc41asf22408596eaf.3
        for <lists+kasan-dev@lfdr.de>; Sun, 04 Jan 2026 10:02:35 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1767549754; cv=pass;
        d=google.com; s=arc-20240605;
        b=E8bLEuUjKsif/vrfJhnzSCHVN5d/igAgrnkX3FVd5puSOo2yagYVW1TkgedrlJC/41
         sMoFx7s3r97PmxS58X81UYL85vzMS6xJ/52ogO24OsrfLC1n0kdke9R0fYW+o8TgzK/g
         eDWTf3fvX22nPR8wiVULRGrtnQC0g7biu9QKJ/9sROP0RDPlzPT+Zhji3GcQUMaRMTVN
         dkhrre8I2hxXllRN9tFYTLBQbaIvgglkHWFCsxV5ySvamocKH1tFp5nsl3yLi/qRpHWx
         l8IUvt51U2Fcbz6SooyZ/lNjFq2QWT93i9ITq8Q84V7If9zOEUQ/VvfP3+tUsOJtaOhc
         /3Ng==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=ofE5SP1BNyG5b6ujgX+M0HJodibY3pxWfi8cRlPVzR4=;
        fh=ECgytw0nDnm1Zx2i1+glJR3c6xBFRHpk3dxFbP6DXPw=;
        b=FlN7O1l3Dw8sb1UT6Jx1ft3BBKgpT3Uo8gNVV4JzfttyNKGXdQmst1FtaAYSJxPs8V
         okf+Hrm4J0XLkfNorNVpUxhIDeUdFpuW3T8gEEnJU7ne6Zlxr+5d1uC7nplXufb+ccy5
         7KIQAy3zbQkEahGmwdWatG4ORFU9BmExowi0ajMQ4IAuc0hC0RjvXePRaDLwUn9Km9ub
         DTxkJ46x5I1Dc35C0EDZE8kh6VQHUsV6QqkPm2fIWBfPgaiweqsMEO9/r0B+m/FXE4g1
         sSw51/qzl/gpbIJ29SxmbAjRKDsua2Db6k+sH+MNUOOrHPFuPEo4Ug3O0NiYiym2M4Gs
         Cb9w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=LpJQM6ho;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1767549754; x=1768154554; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=ofE5SP1BNyG5b6ujgX+M0HJodibY3pxWfi8cRlPVzR4=;
        b=T6uRu42T6K9byzxAP3klUk2CnNuguW0z6aZyLsr411KmOIZCL6S1UjbsmI/BSN1VPE
         AeYgRQKRuPBL6Ov7kz75IVmLqq/JeEvuV5vQeyKYjg0PIzPbj8Hho1uk0XK4Y89oa6TN
         H9LC0iEwqj6xuCQw6o98wbLTRWEGR6kEImP+pRtQgsomVw78TtHFmL1CwJwPmgc/FfPq
         zDMPJXMY6JsHHemLxglUhn5HNl2cxqL+3RGfcnpu+0EJMztpzfMeoja9MGXDUCpgVnR7
         SQyDdhtPDyJiYgq55nfXF2/fJPUsNZ9TWDrXQqiq//hGf43Wcaa7dBKp0sMxj/pvbqGj
         jmCw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1767549754; x=1768154554;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:subject:cc:to:from:date
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=ofE5SP1BNyG5b6ujgX+M0HJodibY3pxWfi8cRlPVzR4=;
        b=FPm1SBdLZYG+SVGxMRPhlcTWEQQbsn97WckTZUpZn3QXyysQMFcSACEplrH015NJih
         xL9/IJZlTu2bBQHVxLR5F5rLaEfnS6uoakaX5jyug7V8vMnXfA73cFHnvlQmGDeqFP+J
         QriXdqDqf605YALjwPH71wrYVPA70LCet2t1vtZtbLnJnas7d21UKqs+JXclq4WRSqLq
         lmS3lqizHxf7zR/OZAmq8bHr5Et4P24jt2a7zV49FTZl7UA5fegNBPGNmBPwv+IibYbY
         5IFqo2Utv2ypjOEPazLWKr9Vszrn3Lov5OyijN55R1M3hDceu4zp+a1mU2pAFaZ7UNs2
         9Pgg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCX+XfGuFzKT5bnmOLs9vFJ44FcElmLy3K+4e56PC3brPXaTiW8gaAYAzVBo589qKTzIk72VyQ==@lfdr.de
X-Gm-Message-State: AOJu0YzaZWEd3DxtZFGhOBVdZcTtCzODGg1N5KUWyNmZHisHX0GmPx6s
	SWstc40xV5QdL62oZRvCprCrGykKp1Ds25sDq8R5wEv6kgtuRC8+W+vy
X-Google-Smtp-Source: AGHT+IHByzPE8y5Cx/axG1+QRWSc0y6FbmPlyjZxt2n1eIN0EJfCBy8VV1zjoablXfDo32uXaDrVzA==
X-Received: by 2002:a4a:e245:0:b0:65c:fa23:2cf7 with SMTP id 006d021491bc7-65d0eae0c61mr15861900eaf.65.1767549754280;
        Sun, 04 Jan 2026 10:02:34 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWbCzZ+sefdN9jk+vvtotm8B3psAyoXG1bw3LeBY9C8/sg=="
Received: by 2002:a05:6820:290f:b0:65c:f424:26a4 with SMTP id
 006d021491bc7-65cf4242993ls8728755eaf.2.-pod-prod-01-us; Sun, 04 Jan 2026
 10:02:33 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUvGlVzF277sk/tWlDj7WS5eSN6kKxFIi0pympl2QdeQn+e2evKph9ZMXxF7OBPZPwLYmfnCvJf3S8=@googlegroups.com
X-Received: by 2002:a05:6820:f028:b0:65b:32b4:83f9 with SMTP id 006d021491bc7-65d0e99c365mr22448398eaf.20.1767549753291;
        Sun, 04 Jan 2026 10:02:33 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1767549753; cv=none;
        d=google.com; s=arc-20240605;
        b=J3X9eaoZ8y1hy6wsTE5btA4F60NiRaZPBxQiPlaYD+/ewtBn4geLy2TWw9TVCxnOSy
         DMyU0C4Uv3AwLenbJzJoyT7HL213GnZcYGl7ouGCJEicCRQkMly9UIrSOV3dIb259Lw+
         SqBHgEwOLMyNZFCiuKdfYqLsv2qgm57VBjrfZLOc60eK0EXAmu7j/UC4aZp6h3BQVkE1
         JRXx0u6+L3z6Doh54SSDwlV/neUFr0kw0IiJt6YxVf0H0rPwOlrty1E3/+/52MHRNpyw
         Hz0jAAf7Df95KK8KTRCxTPPfQEY8PlmuulYa3tRgNWTAHh9/2y7Ri8rotGCXnTKewOET
         Ezfg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=sukNPMtSOV0nXMIev4sNjkhuhRsCMj+n/zxVIAKDb54=;
        fh=6Y6xXjqpl0NhvkaLOlHFnNnS3yXmB4gxkqe9uW5F/ys=;
        b=YXgACByFDI7/+nMfFykwB3U//v1a9kfqaDre86CWUJGjVJwJ4pWaoqufoZW7tAwNpH
         w4Eyrwb/Jvv5hVOe1xZY8FwUnUagTG6PuDe5+YyhOugFgYJ5YQJPDeSEaVPCIEksLZHd
         wppAyeHlTlR4L8aPcIkI6/GjAKva/prkWfvZDxPa4tX/81aVqrGCmkijfB8d0SQE3VO8
         MtOAt9sngWgFWwHZEpHCROIhofP/C5bXKn0gjWkX7GjnKGje+QMxVAvX8/GEM7uOj2Hm
         yj5Kx0euGzbexivAQy06OeT+uTb/8bco0y8M7fWj4cbLg1+RbyRzMiOUrSsXEwq8jpKs
         jydw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=LpJQM6ho;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from tor.source.kernel.org (tor.source.kernel.org. [2600:3c04:e001:324:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id 586e51a60fabf-3fdaa8dd1f1si958558fac.1.2026.01.04.10.02.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sun, 04 Jan 2026 10:02:32 -0800 (PST)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) client-ip=2600:3c04:e001:324:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by tor.source.kernel.org (Postfix) with ESMTP id 2E3A460010;
	Sun,  4 Jan 2026 18:02:32 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 95EADC19423;
	Sun,  4 Jan 2026 18:02:31 +0000 (UTC)
Date: Sun, 4 Jan 2026 10:02:30 -0800
From: Andrew Morton <akpm@linux-foundation.org>
To: Ryan Roberts <ryan.roberts@arm.com>
Cc: Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>,
 Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com,
 linux-mm@kvack.org, linux-kernel@vger.kernel.org, stable@vger.kernel.org
Subject: Re: [PATCH v1] mm: kmsan: Fix poisoning of high-order non-compound
 pages
Message-Id: <20260104100230.09abd1beaca2123d174022b2@linux-foundation.org>
In-Reply-To: <20260104134348.3544298-1-ryan.roberts@arm.com>
References: <20260104134348.3544298-1-ryan.roberts@arm.com>
X-Mailer: Sylpheed 3.8.0beta1 (GTK+ 2.24.33; x86_64-pc-linux-gnu)
Mime-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b=LpJQM6ho;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates
 2600:3c04:e001:324:0:1991:8:25 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
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

On Sun,  4 Jan 2026 13:43:47 +0000 Ryan Roberts <ryan.roberts@arm.com> wrote:

> kmsan_free_page() is called by the page allocator's free_pages_prepare()
> during page freeing. It's job is to poison all the memory covered by the
> page. It can be called with an order-0 page, a compound high-order page
> or a non-compound high-order page. But page_size() only works for
> order-0 and compound pages. For a non-compound high-order page it will
> incorrectly return PAGE_SIZE.
> 
> The implication is that the tail pages of a high-order non-compound page
> do not get poisoned at free, so any invalid access while they are free
> could go unnoticed. It looks like the pages will be poisoned again at
> allocaiton time, so that would bookend the window.
> 
> Fix this by using the order parameter to calculate the size.
> 
> Fixes: b073d7f8aee4 ("mm: kmsan: maintain KMSAN metadata for page operations")
> Cc: stable@vger.kernel.org
> Signed-off-by: Ryan Roberts <ryan.roberts@arm.com>
> ---
> 
> Hi,
> 
> I noticed this during code review, so perhaps I've just misunderstood the intent
> of the code.
>
> I don't have the means to compile and run on x86 with KMSAN enabled though, so
> punting this out hoping someone might be able to validate/test. I guess there is
> a small chance this could lead to KMSAN finding some new issues?

We'll see, I'll park this in mm-new to get it a little testing, see if
anything is shaken out.  If all looks good and if the KMSAN maintainers
are OK with it I'll later move the patch into mm-hotfixes for more
expedited upstreaming.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20260104100230.09abd1beaca2123d174022b2%40linux-foundation.org.
