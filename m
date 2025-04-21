Return-Path: <kasan-dev+bncBDCPL7WX3MKBBDHSTLAAMGQEQB5LE4Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x38.google.com (mail-oa1-x38.google.com [IPv6:2001:4860:4864:20::38])
	by mail.lfdr.de (Postfix) with ESMTPS id 4F03EA957F3
	for <lists+kasan-dev@lfdr.de>; Mon, 21 Apr 2025 23:30:54 +0200 (CEST)
Received: by mail-oa1-x38.google.com with SMTP id 586e51a60fabf-2cc760e316dsf3200683fac.2
        for <lists+kasan-dev@lfdr.de>; Mon, 21 Apr 2025 14:30:54 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1745271053; cv=pass;
        d=google.com; s=arc-20240605;
        b=WJbScjnVLdXEvco+WFHydmDLV7GydTduS5T3qCRcYbAr3++OgmzKTh2AoixjwjUBFQ
         /2Ylo8L9LRHM1E7XP2j2Qo5f8SEE302QJ2cHibUIOGpxYN1fmCbaWhUMPbPeLKvId/GG
         nuoyjdeoCTAE9F1RqVVEl11/lAjRphn7u3ICkWRC1bCjBw0DnSxcIhNsMFSA4Si5vpkl
         2TiYy4MaXe0bKQWC0yJQGwkVqbeBGSPcsFtW9jsjwlbKsK/V+yB1mHfm0GUZ9Q9FK7I7
         kQeO8lXYX7vWdR/rPyO6e0tKeHNPVuAicBIjf2ylEXC1s+BcY7AI599n3QxnIU3iSbki
         h7ww==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=ieSDq0YlC6Fq7K6EdVgID77HvwFZstSx4R9nK4MuNJU=;
        fh=6O28iSEaiRz/IBDG9UOCqz8mtHX6tIX//RohvvBavD8=;
        b=O/nynqQGWnqMZ7qccY0SmwtvXSUB2plbuZBSbPNXniit+D5ILhI5d9rEITC04BlHXp
         oth38dEC1gH9E6MutaXXleM+zG+CIdSMubzubF6ZoY6rrTYAFHyqHJSt0S1PxcqbKZNO
         NU11fdnamzsbVsfdfKLmEqiVOsmPMiLheuGXaa8XRMpD7brf/3seISo8ay2cFkYPWGdI
         udTHo0+LSz7aIoX8IryRSWQNxfC3aeF7Cc/Ob3oeAPEOd55RybZUUF6W6XeJ90LVclvm
         NR2Q3dWWQ+FNyW8uEvZLYMmA6azjOBWcC8zzDmL5WeE/KwnR2JGCYs1KkuYFhLfReEAU
         fJ5g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=ovisxryp;
       spf=pass (google.com: domain of kees@kernel.org designates 147.75.193.91 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1745271053; x=1745875853; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=ieSDq0YlC6Fq7K6EdVgID77HvwFZstSx4R9nK4MuNJU=;
        b=RuFlSx1J15qFfjkcPmPE+noyCrENPddQqdcuBU4eNiquPTqobBVS+BlODEeItNoR+n
         0Fp1mlYXsCTYIGo+gABoLLsY02nXNpZx3vg7bMU2dwZzeaSBfAqsaHFOWWYAc7kr7B1E
         amHmInOzvN/Imb0sjiaREzN/WCLCUEiXgFbeEVjOS0fqoZ2MtL8xNCoE/6OTdadDyrw0
         7mlhtWkCm0pu65wkT0FDfgwu4vZetxAg1rdB8i7Sf16Vd1CuORXolookezjTnO7VwS1E
         rXKxFbqQNhJNIxbsyzS+aIrizgdcMm18XjyL5tPOajuFuKKaNGCdTv0z0yFyUsHEalhq
         yHuQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1745271053; x=1745875853;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=ieSDq0YlC6Fq7K6EdVgID77HvwFZstSx4R9nK4MuNJU=;
        b=mV+lbxde2/WipCbmIQRBfG2WL59oGWZgIZJjo4kjhRugCmiweSWOgj/+xPfFdYQpJ8
         iKfIYK/2DRvb5KX45zqq3dPOc+tkPanLS0egrPjXQvDKpMfeuOB9dWmfZpSO74U1KhvK
         tfd7UUEdG32TNxG8zuOXHnpSnUZ7FRDcodpS1AxnLNE4c8Jo151bjJEJ243rLuZbYsE0
         z6Q53c9Kys6JNeyizxi05ca6pKgrTjSJrrijqO2pRMrlMs9SRxfYrjlVLIqgysFij02B
         YPB4hHPXip/c1GRnMVS6+NQtM6/fqJbndiDfKqpeZL3c9bl5Ev6Zrnhri6SuKbgdBt91
         f24Q==
X-Forwarded-Encrypted: i=2; AJvYcCWVz/0zDwP2y8f8O16pDW+GPD/cMQSKizbUaQ0qs6nvQj5qRjyTPBPKhwhwq7UkYgYIHXSz5w==@lfdr.de
X-Gm-Message-State: AOJu0YxhQACfQK8Ast0vbtDmFybA3QYBuqABal7es2sYqvhikUGG5ENh
	aPXLk3klsKV/iIcmiW5xTJxEiRL+r3O9Ot7UpniLAd7OiyiqWU2G
X-Google-Smtp-Source: AGHT+IGv9BPpXN18qUGi9C9zfoHL/Cu4uTkcrIg+c+9hBSTz203bdOY+IRX23ubwo9oLruoIPKKCcQ==
X-Received: by 2002:a05:6870:4f17:b0:296:bbc8:4a82 with SMTP id 586e51a60fabf-2d526dba5cemr8267493fac.27.1745271052778;
        Mon, 21 Apr 2025 14:30:52 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARLLPAIqCbyKIx0OPPFb1jqTjFCIAtVgCgljEtPcl57X0QROgQ==
Received: by 2002:a05:6871:788d:b0:2c2:33d9:946e with SMTP id
 586e51a60fabf-2d4ebf02eb1ls2148142fac.1.-pod-prod-08-us; Mon, 21 Apr 2025
 14:30:51 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUy3fPmaactpAf0GGykHd2M1DhRnunCP2wp3tnlpIyifwlZJVuPdTcW0DwfhgoC5JQaW8l+Mjdzyzw=@googlegroups.com
X-Received: by 2002:a05:6830:2808:b0:72b:98f8:5c82 with SMTP id 46e09a7af769-730062fce93mr10102117a34.21.1745271050985;
        Mon, 21 Apr 2025 14:30:50 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1745271050; cv=none;
        d=google.com; s=arc-20240605;
        b=fLDB5D7/UbAWNDhOVhvB/6gu5Pm+ZLFg+b5ImCIL71vedfX6PeE5kv1jsDmdAaLglk
         DWJ0IpVvP7vkF04PX3xRbkN5g88YrIM1qMlxF+0BN5jUZKBw0qdnoFLzx4hIrFQ11cA7
         TqOYPP+6BQuo+cu5PDjDpcfBJP3FL7Rr0EaJL0mwyiqZth7eVKCd7NNw1KPbay8bX8jF
         qP5j45meDZRzhVIPTZ6S88Ue57KAaTzmtvQblHhtLawwqfEEwXWTFvA0XxH1JdvXI8JO
         6wUjdeAR/N6F5oWZy/Nh2FUehHuAJFvduDifM03fb2T5iqcAgjjlI77yHt9xDB12X9CL
         5iOw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=OBx4Bw3gQhoFLy0yr/uU/+Zqe6fazjtvUpxjOm7/fGI=;
        fh=DSUAhTut8j1syPQnhQ/Vq0eFgShcr+yMepw1+N290Eg=;
        b=XBrZQr7NLodMZMDi+2bXGe34UKul1j2rFGqLIrjlxChuxHbtv0UhvgS4KziadpCR4m
         HH19D/wbET2HDLPjSAEKnmnhfFGUrpWAu+wt/UN/PvhYkm95Hy19KyiG0Z5s6NVvgt50
         QOjibNXfB+kXmAi8HGJ/9W03bSu/iVqJTvHzKmNU+T4XqCni8BWo8eLoRTGOJg+E5NIS
         MSJZrHIfQVSOzSwfdmaMFk8RPZ5KNiXhi/WDfPJmDNw6hh1YwXy41bMTpEB1hWPSna8n
         8yq5Z36H8BXzv6yFktg2NiwwzsKmBMLVB14hwA96+bdOl6ilqYP44R0N+FsM62P8BoL6
         VooQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=ovisxryp;
       spf=pass (google.com: domain of kees@kernel.org designates 147.75.193.91 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from nyc.source.kernel.org (nyc.source.kernel.org. [147.75.193.91])
        by gmr-mx.google.com with ESMTPS id 46e09a7af769-73004873696si274186a34.3.2025.04.21.14.30.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 21 Apr 2025 14:30:50 -0700 (PDT)
Received-SPF: pass (google.com: domain of kees@kernel.org designates 147.75.193.91 as permitted sender) client-ip=147.75.193.91;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by nyc.source.kernel.org (Postfix) with ESMTP id 1FB5EA439C5;
	Mon, 21 Apr 2025 21:25:22 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id B85EFC4CEE4;
	Mon, 21 Apr 2025 21:30:49 +0000 (UTC)
From: "'Kees Cook' via kasan-dev" <kasan-dev@googlegroups.com>
To: Christoph Hellwig <hch@lst.de>,
	Kees Cook <kees@kernel.org>
Cc: Masahiro Yamada <masahiroy@kernel.org>,
	Andrew Morton <akpm@linux-foundation.org>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Nathan Chancellor <nathan@kernel.org>,
	Nicolas Schier <nicolas.schier@linux.dev>,
	Nick Desaulniers <nick.desaulniers+lkml@gmail.com>,
	Bill Wendling <morbo@google.com>,
	Justin Stitt <justinstitt@google.com>,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	linux-kbuild@vger.kernel.org,
	llvm@lists.linux.dev,
	linux-kernel@vger.kernel.org,
	linux-hardening@vger.kernel.org
Subject: Re: [PATCH] kbuild: Switch from -Wvla to -Wvla-larger-than=0
Date: Mon, 21 Apr 2025 14:30:41 -0700
Message-Id: <174527103909.545282.5440977919378383304.b4-ty@kernel.org>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <20250418213235.work.532-kees@kernel.org>
References: <20250418213235.work.532-kees@kernel.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: kees@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=ovisxryp;       spf=pass
 (google.com: domain of kees@kernel.org designates 147.75.193.91 as permitted
 sender) smtp.mailfrom=kees@kernel.org;       dmarc=pass (p=QUARANTINE
 sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Kees Cook <kees@kernel.org>
Reply-To: Kees Cook <kees@kernel.org>
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

On Fri, 18 Apr 2025 14:32:39 -0700, Kees Cook wrote:
> Variable Length Arrays (VLAs) on the stack must not be used in the kernel.
> Function parameter VLAs[1] should be usable, but -Wvla will warn for
> those. For example, this will produce a warning but it is not using a
> stack VLA:
> 
>     int something(size_t n, int array[n]) { ...
> 
> [...]

Applied to for-next/hardening, thanks!

[1/1] kbuild: Switch from -Wvla to -Wvla-larger-than=0
      https://git.kernel.org/kees/c/9c2cfa10444c

Take care,

-- 
Kees Cook

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/174527103909.545282.5440977919378383304.b4-ty%40kernel.org.
