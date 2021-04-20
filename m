Return-Path: <kasan-dev+bncBDFJHU6GRMBBBU5M7GBQMGQERSWP5IQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x640.google.com (mail-ej1-x640.google.com [IPv6:2a00:1450:4864:20::640])
	by mail.lfdr.de (Postfix) with ESMTPS id 8C98D365140
	for <lists+kasan-dev@lfdr.de>; Tue, 20 Apr 2021 06:19:31 +0200 (CEST)
Received: by mail-ej1-x640.google.com with SMTP id z6-20020a17090665c6b02903700252d1ccsf4288969ejn.10
        for <lists+kasan-dev@lfdr.de>; Mon, 19 Apr 2021 21:19:31 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1618892371; cv=pass;
        d=google.com; s=arc-20160816;
        b=b1nJ4lt64r4tWpqsl7dzYyakIZze45BXIiXKM93D02uxDNkSEBUa+QNmMs18OFnuNn
         7rswTRVZTWT3Gxk5QPbMaqombKPHEvFG6uKPf2ik7dxWebaQdS3WOxdf2vJBdUJU/cQA
         lx56SuKXamDFpDk6vAVUrsV5SDFgGN6yI/stHBGRku+L7qYws64BqQz6iHh8TJaLETZ8
         MOKtoPfl1I6j4d7d67DonrKrb/9Xyqh7pVerRDcuTUF/FuMvWYEHm6fmLmXDiP8uFy9K
         Fsi7eArh5Fr2XHuW5GEzEiKHaWRvHJjQ45m0LRRT8EvDQ5K+CNPFZcnQKLjRsKugF8Od
         MMOQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=4eilVF/ayyrQh1jw7R5aDCgEoRQTWjgy1ZUK+m1NwLY=;
        b=vfzplVoNTfAwv5uI6aTd69zHJg6xGd1fIYe2UrkdfZ4NgxdwzhSUHe2/tYpMcEtkih
         hXWBIeJ/B17fQmVTVHrp7Fa5tZcqtLp+MMV9BfG5+06ANMvwNpjB8ni9B5iVjuQF7OIp
         v4x9JLcGQYnSui50R4nGBLKu2uyxUz66ccueZSi9gHAKoR+So8jfMkQCvcoT+o/SUY9K
         NEnrxm1hyXAFCEYmdfsDgZmU6yT5QX8CGN/g6UUXEMN+68jAWP56YZTtK1/jKc+5Vm0s
         54trVA4FzvOiLK6xRyRjolBgH1orPbHgvMjpXVBuZ38AfHWBVWFUTc+lLwBCTaaScuid
         4PJA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@brainfault-org.20150623.gappssmtp.com header.s=20150623 header.b=zPHU77GK;
       spf=neutral (google.com: 2a00:1450:4864:20::434 is neither permitted nor denied by best guess record for domain of anup@brainfault.org) smtp.mailfrom=anup@brainfault.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=4eilVF/ayyrQh1jw7R5aDCgEoRQTWjgy1ZUK+m1NwLY=;
        b=IDYVGVsLS2bSUZwkCYZ7fny1BD6PfOcgE8/b/eAUOjHvRK3t2TfwSJEF7hAKSS9Rrg
         QyVeCBPHIz5d0QV+N4X4QsM/2s4uNQxE0rOPck3/qEhToxodsMey9u9pZVG5Q8/IPEb2
         kBl6fyLphoLCiA+XPXR70f6Gt+o2Ouk5vY1PaoLLwsYM31g59xWVSV+PzHrBikwKXVbX
         p/VatXYT8HgrXMVTmxIM4hPycsNyJ9yH1bks+n/sSMZOE/24zLTQJoRcYNTXWaUyCUEB
         Is9fm+ZUnPo6hRvxf3yJoiQxwmTJACmMKG7Y76dbx+9geZiuJeuVTFCgeZlZiJOo3S3b
         j6tA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=4eilVF/ayyrQh1jw7R5aDCgEoRQTWjgy1ZUK+m1NwLY=;
        b=lNLxTG1Fo7bfxsTVy99nlS8x6iw3eRGqCu9CAgiHOi9sRgGTS8rCipjrhYbKbGH1lt
         a8v8hbR7XXD02aBN55t2ZqXXgjZl7/T8MQ37M1WuEpvh9bNQW6xh3qmUBldsZXJSXYGV
         pVSOGNQByv30Oer8L8oeyWkXp1DrP8QWMb0VYpOFiHjMglO2mSRVqJwCP3Cj+ugPrdii
         8zmcwHwbCqhW7uTtATHIZa6A2oHGXpGQ/rvsm4ZzzD03gTrh1bvT3WIr2Fu1fzPG8t+y
         f5Eq/OEFwuwuh06c+q8UELTPQZWtqiMu3h+Ed4uuoQi/nE2+r/Rca/dfc7qMsA/i1HPN
         lr+w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531jkU2h4lZguSLaW4aYhy42TKBYPvd/GVlLIcV0s4tbsqCquT0d
	xq/xFyT8cOO6pxH5iX0kKi4=
X-Google-Smtp-Source: ABdhPJzmm7BjMd8k0guvoRyaKXpGbs8LiQHzD8N1x1/dOF9Jg1Dv5KpE4DShz+FFHQLNr7bRQZ+xBQ==
X-Received: by 2002:a17:907:6192:: with SMTP id mt18mr25892679ejc.530.1618892371306;
        Mon, 19 Apr 2021 21:19:31 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:907:97c9:: with SMTP id js9ls7226272ejc.10.gmail; Mon,
 19 Apr 2021 21:19:30 -0700 (PDT)
X-Received: by 2002:a17:906:3749:: with SMTP id e9mr16066100ejc.247.1618892370451;
        Mon, 19 Apr 2021 21:19:30 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1618892370; cv=none;
        d=google.com; s=arc-20160816;
        b=TvA5kXHwpHNin4MCeCOz3zr70KXNZ+cL3Jwg0uluJN0FkJjv75BZe4ADI3OMkZXG8g
         D70t0Y9+P8NHfSian6cOwzb3Bw/Z9sxfB+kci9IvqEVS6c8XXgyrzJZJyrxNxXxdT+Qb
         l7wqRMR7UBHs9ethrgwqzIy1lMMtu/i1h43YtiKtZ3aXro/ToMpiSppHlWtmBzMts9/G
         2Jhsiy9eFmhHP8Q76B4cwVsR/i7DawxZ1i5JPckSCXK9uv2wahyOmbh/LyaiIFTN+xTD
         R389kTmYN16DTqBNe7OAhEjt5ueSEGJy8U2ExaD7QmJMbz9BqBa4koxyMoYRHW9KK34V
         AHig==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=6tOKXOtetoB5l502f6CwFsHmwD7mexR6F47nan+OthU=;
        b=YuOhjOUTP9VpT/Cw0uqFF7E5g3DEPv7NoZmLAWA9Yav/X5JLk9Y7GVg3di729s9SEN
         yF/Cz79wyPVzKURX5VcAFVwcxwIVhLYex2KpQ3PC9Cl82i+qQV5WIQ3/3SbMDv3zkX9G
         G5sQVwf5cY8CPKybYSRcyKl7pvTjB03cFyyHvz/Z99WqLOFgHBodFKhGTJz0sTxDKK06
         efPUCrNvp72m2WRuhmWdV5xUoCCD6vp+T+NiBi7aLEFns/J3ymlfnFIyIrRxy2nw1gYJ
         vPMRtYCz6vWJ5pAtb7FkuKdwdlewTnbDzpFFdS61FKhbNzgC4Q/RVRhFdMHSB1EGCOGj
         1u2A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@brainfault-org.20150623.gappssmtp.com header.s=20150623 header.b=zPHU77GK;
       spf=neutral (google.com: 2a00:1450:4864:20::434 is neither permitted nor denied by best guess record for domain of anup@brainfault.org) smtp.mailfrom=anup@brainfault.org
Received: from mail-wr1-x434.google.com (mail-wr1-x434.google.com. [2a00:1450:4864:20::434])
        by gmr-mx.google.com with ESMTPS id h1si1057768edw.3.2021.04.19.21.19.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 19 Apr 2021 21:19:30 -0700 (PDT)
Received-SPF: neutral (google.com: 2a00:1450:4864:20::434 is neither permitted nor denied by best guess record for domain of anup@brainfault.org) client-ip=2a00:1450:4864:20::434;
Received: by mail-wr1-x434.google.com with SMTP id h4so27075620wrt.12
        for <kasan-dev@googlegroups.com>; Mon, 19 Apr 2021 21:19:30 -0700 (PDT)
X-Received: by 2002:adf:dfc2:: with SMTP id q2mr17850344wrn.128.1618892370130;
 Mon, 19 Apr 2021 21:19:30 -0700 (PDT)
MIME-Version: 1.0
References: <20210418112856.15078-1-alex@ghiti.fr>
In-Reply-To: <20210418112856.15078-1-alex@ghiti.fr>
From: Anup Patel <anup@brainfault.org>
Date: Tue, 20 Apr 2021 09:49:18 +0530
Message-ID: <CAAhSdy3csxeTiXgf8eKnRYhD7BM1LDLPddrn527AkA_-fiEGkw@mail.gmail.com>
Subject: Re: [PATCH] riscv: Remove 32b kernel mapping from page table dump
To: Alexandre Ghiti <alex@ghiti.fr>
Cc: Jonathan Corbet <corbet@lwn.net>, Paul Walmsley <paul.walmsley@sifive.com>, 
	Palmer Dabbelt <palmer@dabbelt.com>, Albert Ou <aou@eecs.berkeley.edu>, 
	Arnd Bergmann <arnd@arndb.de>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, linux-doc@vger.kernel.org, 
	linux-riscv <linux-riscv@lists.infradead.org>, 
	"linux-kernel@vger.kernel.org List" <linux-kernel@vger.kernel.org>, kasan-dev@googlegroups.com, 
	linux-arch <linux-arch@vger.kernel.org>, 
	Linux Memory Management List <linux-mm@kvack.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: anup@brainfault.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@brainfault-org.20150623.gappssmtp.com header.s=20150623
 header.b=zPHU77GK;       spf=neutral (google.com: 2a00:1450:4864:20::434 is
 neither permitted nor denied by best guess record for domain of
 anup@brainfault.org) smtp.mailfrom=anup@brainfault.org
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

On Sun, Apr 18, 2021 at 4:59 PM Alexandre Ghiti <alex@ghiti.fr> wrote:
>
> The 32b kernel mapping lies in the linear mapping, there is no point in
> printing its address in page table dump, so remove this leftover that
> comes from moving the kernel mapping outside the linear mapping for 64b
> kernel.
>
> Fixes: e9efb21fe352 ("riscv: Prepare ptdump for vm layout dynamic addresses")
> Signed-off-by: Alexandre Ghiti <alex@ghiti.fr>

Looks good to me.

Reviewed-by: Anup Patel <anup@brainfault.org>

Regards,
Anup

> ---
>  arch/riscv/mm/ptdump.c | 6 +++---
>  1 file changed, 3 insertions(+), 3 deletions(-)
>
> diff --git a/arch/riscv/mm/ptdump.c b/arch/riscv/mm/ptdump.c
> index 0aba4421115c..a4ed4bdbbfde 100644
> --- a/arch/riscv/mm/ptdump.c
> +++ b/arch/riscv/mm/ptdump.c
> @@ -76,8 +76,8 @@ enum address_markers_idx {
>         PAGE_OFFSET_NR,
>  #ifdef CONFIG_64BIT
>         MODULES_MAPPING_NR,
> -#endif
>         KERNEL_MAPPING_NR,
> +#endif
>         END_OF_SPACE_NR
>  };
>
> @@ -99,8 +99,8 @@ static struct addr_marker address_markers[] = {
>         {0, "Linear mapping"},
>  #ifdef CONFIG_64BIT
>         {0, "Modules mapping"},
> -#endif
>         {0, "Kernel mapping (kernel, BPF)"},
> +#endif
>         {-1, NULL},
>  };
>
> @@ -379,8 +379,8 @@ static int ptdump_init(void)
>         address_markers[PAGE_OFFSET_NR].start_address = PAGE_OFFSET;
>  #ifdef CONFIG_64BIT
>         address_markers[MODULES_MAPPING_NR].start_address = MODULES_VADDR;
> -#endif
>         address_markers[KERNEL_MAPPING_NR].start_address = kernel_virt_addr;
> +#endif
>
>         kernel_ptd_info.base_addr = KERN_VIRT_START;
>
> --
> 2.20.1
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAhSdy3csxeTiXgf8eKnRYhD7BM1LDLPddrn527AkA_-fiEGkw%40mail.gmail.com.
