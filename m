Return-Path: <kasan-dev+bncBC7OBJGL2MHBBWNL3D5QKGQECNJVHMQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33c.google.com (mail-wm1-x33c.google.com [IPv6:2a00:1450:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id 45C052805C3
	for <lists+kasan-dev@lfdr.de>; Thu,  1 Oct 2020 19:46:02 +0200 (CEST)
Received: by mail-wm1-x33c.google.com with SMTP id r10sf1485941wmh.0
        for <lists+kasan-dev@lfdr.de>; Thu, 01 Oct 2020 10:46:02 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1601574362; cv=pass;
        d=google.com; s=arc-20160816;
        b=TsRFLtGpBnjoSZk1kTWhrGIL8XGdIqZupKgS61icc5mhXbVpZqLi5QZTMRcHu310OV
         KxT3RTONGoj4HNqksneeOIqN2DLz/bONoxAtgwIarBEWDbFXXK1tsbRM59SrST0AH66T
         cYPhoxkKPzNrUN/6K0cQIlN0KaCm8uPDI3DHpF6CaFmlzVCKQchSOLmVjft31uYDOW+I
         77jroKKOBxM6sEIbSTJjJKNNsGhTIi6Xshre/3Vn20El47sm+FpxM8CoQg1G9CR6asnS
         By542Tynyijj+zkvmqa/WwYsJZN4NADKGEXmmej00zB84yeElcsRDLD/DAgluVJgzUya
         qiqw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=GQK+VTaTYQR0jMXF7TY+mgQG7HPb0QPT4bMF2U7Mpo4=;
        b=RoIzyVGVZZfVVJPuzoRAfhFl5rxstA5kBIhDOD63mZAr//w14n6OFV2QRdpIAY+wEx
         K3PCPX3AqFdxSXKhw5s8zDQgv2oO7F+S9LlfZy1glvJl7OPTtlhchPs/Msqwz6AKNYuN
         euqvW0F9N2BLeopfXDwap74YrO6zbOxA60PGpilr5XkaO4a+bLaakHcBjDLMXEtsF3eF
         4kAXPzZ6+aVHx5++jdphEj2Nv7pHYiCWt1+pSd0znS6pNtvAWzhW/156nffm1k14CWPL
         /fz83NfcLcvsU0QLyRthtXrHVK4K34J3nYrd6u98kKZf969VBfZXtqXvGGWAt/JlLtFd
         u1eQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=T3AeyqU7;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::441 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=GQK+VTaTYQR0jMXF7TY+mgQG7HPb0QPT4bMF2U7Mpo4=;
        b=WtbYEGqANXdRvJBunM7vChfmFr0u3QQYZ7LDGwda2kz7SmoCBw/OBp+Ei2m/mxJmDX
         p3MzNPbeiXm7CnOAMSElVT1Pp/pBiFikzakVTMpod+ktcKWjy1K+6lfJU2G7mkNuR8E2
         cKIwO49+1rxe/I28HZjEXJqRTFhRXTY+9zU6GtGF4YTDvRAkUL8h18go3ezkrN4GcKyJ
         eEU1MZjerp54UgIaPBQmKjpF6Nv/wTnBkYt7lAH3wFpYrR5h+7Cm9vbrQKLKunxMsd2A
         VRt724+ya3XTuPJRok5/bHvLEnm/zRwKTGCVT1lESHoDcVi5L2CIg4TMUdFh5UXXaQa3
         sIMA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=GQK+VTaTYQR0jMXF7TY+mgQG7HPb0QPT4bMF2U7Mpo4=;
        b=OgEl/IyV/af09m7kyKRKSTlqD2xrSYtFoC/kHi87gHQwFaT0PjYL51RuFj/pN0bNco
         vsAAgy68K/MvZfg3vkuwitc/PlE8noXjKT9qjtrXCmBatCav1Z6p7QLe6rqUVfyV87xb
         4xkP77Z3QcAXeWswEzp3fRLotu1J7IDiuQkwJVCNql/pujop6+g37ZICifafMDfFugd0
         zBJuYd/WFWjNWWvN6jM3y9xFcSrsKMK726zkdlPS8QzDJpE3j+7B7MLEojtXHqkXYt5+
         dQPBq21wI1pU98njTb2Hd1t9PVgwappnhus/KGp7ckY+hi2Vinw9WAEwRC3yqYlvA069
         01hg==
X-Gm-Message-State: AOAM532eR53uk++pp5yeZd4pH/rOArMmcxCjwrOY3j+0UhMXoACi8czU
	2NklNj3l56vmF1bWEiJCBo4=
X-Google-Smtp-Source: ABdhPJxwHLpgHzNzB4ISF4hlubztcpxIxpS29Jo549JJFNSbpp226pC3f/8oL3EbpQmlodjUK9GqvA==
X-Received: by 2002:a1c:7c1a:: with SMTP id x26mr1228922wmc.112.1601574361976;
        Thu, 01 Oct 2020 10:46:01 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:9e53:: with SMTP id h80ls3293258wme.1.canary-gmail; Thu,
 01 Oct 2020 10:46:01 -0700 (PDT)
X-Received: by 2002:a1c:7f8b:: with SMTP id a133mr1200569wmd.155.1601574361044;
        Thu, 01 Oct 2020 10:46:01 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1601574361; cv=none;
        d=google.com; s=arc-20160816;
        b=mSxOnOFHRpxHkmwrrtGh9Baqb3lw4CWVqgBTdFQuuBXn9IXufMwZlTJnFwiJP85PtA
         GbEdVHhGrvwP8avubNAS5mp4HOagord02ySkGUycafuTgi/nxl72CcTTWTNK1t6LfKAm
         PZY59rvmDGKOgskBMcKjXW37Z5m+oRvDCA3hJvrCBpVhTFI5txpSjvpOQa6KJytfPl4w
         QeOScaB3lC6zBCKP5O72t5QWMHmhRYgdqXue5qi6DpRvRG3uPp16dhg9OoBHtlKNEACt
         vAZQhgfQfmsOI9cqifJu8IIleZtJxqFyXByKgYP2VUIVIs7VTFHT0s6G34U6Wgi87FHS
         xd9A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=4X89ICg6LS0dHFVQkSUqAoV+hQlz/eq43PpADvUh29Q=;
        b=RCQMaF5Uz7ddKJWSr5gL1T8FWnwAhpE5cDUG6kTN7h7ebFL2IaraRwQ+MNS8FUUtn8
         Ch5lGKBJA7FbLVFF4x7YUiuWEfGc8+0n2oNQDoLh/KH1lbiRCdWk9j1iJ08Z+jHMMFic
         8YGMJvXVnTiKf0iUpzEa9Cj2gXup5eCd29IZ1zXEjf2Y4p7U5eEqXrkLZ/ZKSDZHr3yI
         kk51/eG+E4XtIWsMXbjcpJR171IhsjWLsrHA8ChNB9zEZ1qAMV6z99KiUg1BU42ArP4e
         sQ7O6BqfFBCT2pHo1LSnf0lRxb/C9z+nb06IMgr2U0zO15nLxXUbzP8Cwz1E6z8VGTJh
         9+AA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=T3AeyqU7;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::441 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x441.google.com (mail-wr1-x441.google.com. [2a00:1450:4864:20::441])
        by gmr-mx.google.com with ESMTPS id b1si19750wmj.1.2020.10.01.10.46.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 01 Oct 2020 10:46:01 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::441 as permitted sender) client-ip=2a00:1450:4864:20::441;
Received: by mail-wr1-x441.google.com with SMTP id e16so6812329wrm.2
        for <kasan-dev@googlegroups.com>; Thu, 01 Oct 2020 10:46:01 -0700 (PDT)
X-Received: by 2002:a5d:634e:: with SMTP id b14mr9870455wrw.190.1601574360526;
        Thu, 01 Oct 2020 10:46:00 -0700 (PDT)
Received: from elver.google.com ([100.105.32.75])
        by smtp.gmail.com with ESMTPSA id k6sm888277wmf.30.2020.10.01.10.45.59
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 01 Oct 2020 10:45:59 -0700 (PDT)
Date: Thu, 1 Oct 2020 19:45:54 +0200
From: elver via kasan-dev <kasan-dev@googlegroups.com>
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	kasan-dev@googlegroups.com,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Elena Petrova <lenaptr@google.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Kevin Brodsky <kevin.brodsky@arm.com>,
	Will Deacon <will.deacon@arm.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org
Subject: Re: [PATCH v3 17/39] kasan: rename print_shadow_for_address to
 print_memory_metadata
Message-ID: <20201001174554.GM4162920@elver.google.com>
References: <cover.1600987622.git.andreyknvl@google.com>
 <8580d4945df57614053084eee8f318edb64712d3.1600987622.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <8580d4945df57614053084eee8f318edb64712d3.1600987622.git.andreyknvl@google.com>
User-Agent: Mutt/1.14.5 (2020-06-23)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=T3AeyqU7;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::441 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: elver@google.com
Reply-To: elver@google.com
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

On Fri, Sep 25, 2020 at 12:50AM +0200, Andrey Konovalov wrote:
> This is a preparatory commit for the upcoming addition of a new hardware
> tag-based (MTE-based) KASAN mode.
> 
> Hardware tag-based KASAN won't be using shadow memory, but will reuse
> this function. Rename "shadow" to implementation-neutral "metadata".
> 
> No functional changes.
> 
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>

Reviewed-by: Marco Elver <elver@google.com>

> ---
> Change-Id: I18397dddbed6bc6d365ddcaf063a83948e1150a5
> ---
>  mm/kasan/report.c | 6 +++---
>  1 file changed, 3 insertions(+), 3 deletions(-)
> 
> diff --git a/mm/kasan/report.c b/mm/kasan/report.c
> index 145b966f8f4d..9e4d539d62f4 100644
> --- a/mm/kasan/report.c
> +++ b/mm/kasan/report.c
> @@ -250,7 +250,7 @@ static int shadow_pointer_offset(const void *row, const void *shadow)
>  		(shadow - row) / SHADOW_BYTES_PER_BLOCK + 1;
>  }
>  
> -static void print_shadow_for_address(const void *addr)
> +static void print_memory_metadata(const void *addr)
>  {
>  	int i;
>  	const void *shadow = kasan_mem_to_shadow(addr);
> @@ -311,7 +311,7 @@ void kasan_report_invalid_free(void *object, unsigned long ip)
>  	pr_err("\n");
>  	print_address_description(object, tag);
>  	pr_err("\n");
> -	print_shadow_for_address(object);
> +	print_memory_metadata(object);
>  	end_report(&flags);
>  }
>  
> @@ -347,7 +347,7 @@ static void __kasan_report(unsigned long addr, size_t size, bool is_write,
>  	if (addr_has_metadata(untagged_addr)) {
>  		print_address_description(untagged_addr, get_tag(tagged_addr));
>  		pr_err("\n");
> -		print_shadow_for_address(info.first_bad_addr);
> +		print_memory_metadata(info.first_bad_addr);
>  	} else {
>  		dump_stack();
>  	}
> -- 
> 2.28.0.681.g6f77f65b4e-goog
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201001174554.GM4162920%40elver.google.com.
