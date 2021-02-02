Return-Path: <kasan-dev+bncBDDL3KWR4EBRBT7F4WAAMGQERP64FTI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53e.google.com (mail-pg1-x53e.google.com [IPv6:2607:f8b0:4864:20::53e])
	by mail.lfdr.de (Postfix) with ESMTPS id 0659F30C40F
	for <lists+kasan-dev@lfdr.de>; Tue,  2 Feb 2021 16:42:09 +0100 (CET)
Received: by mail-pg1-x53e.google.com with SMTP id 139sf14365127pgd.11
        for <lists+kasan-dev@lfdr.de>; Tue, 02 Feb 2021 07:42:08 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1612280527; cv=pass;
        d=google.com; s=arc-20160816;
        b=wqd7sp1y1tlg8oUjbKb1DkGNt8WxUaJ/I3CVGcVDAz+r8ik1tiGrVCLGOTyN5KhsLZ
         tY1gMhz4O1NbSFvKg3Mfh0hVgrue3cSUlEijmgBIZggALvAkDNnMUMz4T66AAMmyvyhh
         NWSARNCHwAlWzTMIHEW7vLatuDQZl1Hbdhc6lOB4aqnGmK8t/fFyL+vtWMJYus+5tcZ8
         P4B0pjcY1qO6bGQCcvoVzutYM4iw+IAS38zocYs8t2jNsioy6L09WDI1DXJlKxYOpF6l
         RHJMJ0dYBZw8AsmWCZvOAVRaqT59hciznQDw21ROLp2ooqxibdVkUuC5chRR67aeSgYW
         xosA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=rvUchGRycM7+CFAqU2oniKnl0ULoVv5LKudHl7j8hyY=;
        b=UeyItEM/xNmFsxneHMcJihO/mKssvkmgo5k3LVdklkgCfnQFn5YgMERvax5q9vUsIn
         Z0EGgae2WnHlQK1/C0EPWrhu8CkAuDzHU2MzUhhU5bkC48kQg/7WInoxf4STgLBpbIck
         /rEoSmsf7bnFMdNdVkocyPKcs8jgFf5Gi5Bf3FEHunvIujePSXVcuin+rdCpih8VOcu8
         GU5Ew3QpfJM3sVgHFtKtjhLa8ZUS9BtnVtdzyP6T1BITtWqoC85hZh1Alm77kQ05HlUP
         kOBIRUunYIHGiZ3GYSzKkK5GdS7VmdI4JmVFBHhF27wLY0qLEikA+Y1zGgKXhYbPYGtX
         zcBQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=rvUchGRycM7+CFAqU2oniKnl0ULoVv5LKudHl7j8hyY=;
        b=jKH0osfIki0M2WzbRDjUGdjfLcR2pKBy9IsRxGZAIco6VfDSSp9LEXBiNEjOc/897B
         x9JF6wvwrKGdwaDdOIvskIXAqzjjM0fs9irOUikXVFy4EfeKi42+c2DAdrhZNI4qRkMZ
         AQhWeOc2G5sSuPTdLBFsyci2yjMI/KEaJrDdeNewcX2TO9gmxde+TpHx+tQvq1tN7zHw
         u1Xo0bOctDvbc01t611tkv6oEMHwy5QKvCJRZ+MKHOb95qO59biExLEE9snzkhIC04hI
         YYDFNLTGrxsNXWZAbS5Q44UXC6btqJTmS0w1CxQ8tInoWZa26gFuU8C/aEX1EyKR+hwq
         sc2g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=rvUchGRycM7+CFAqU2oniKnl0ULoVv5LKudHl7j8hyY=;
        b=cSVOHOewXpWGWooEJlvvajBtNCaUo4fP41HdxWRv9L8OWw4GwUj6PA/DMGagL5TPv6
         esweP2H+p+/GZ64/+fyBUDSD4s7+DMtmKNtj2h6KVzo5Cp+jW+JhTnk4uOJQ1Out8YjN
         zcVqUlGTogwjEG1h2oigMhpdwBuYn2tlFH9fUTtCwslMh5VrnCeGdhS5MF66/yGgbNGr
         BWCSVAsDZNDf/kQF3ukQIikJMpshHgbAzdQsmhXuKZk+D0qRMwxM6KhegqVa4KJx9KkM
         2ub+2/T/1Ly4ScwWSMk/SBP9+0NZqYV9tFT7mOT5eFQUFtVmh/vjL5mODEIU6yvxLbX+
         yUSg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533OQw/JiTrq87Ji2cuzue40Mv+i6PD98CxBWWaq6u213TmyV3Tx
	lwN1uFnskbWTA6bYza5ZUZE=
X-Google-Smtp-Source: ABdhPJxnPIDdv+3Q1gMZ6UA/NGALjUBS2/ILXL+eaYgDIeXhAQprF6IV1lN8rWp5F8U4cnVtLlHmPQ==
X-Received: by 2002:a05:6a00:2127:b029:1bb:b6de:c875 with SMTP id n7-20020a056a002127b02901bbb6dec875mr21783610pfj.72.1612280527610;
        Tue, 02 Feb 2021 07:42:07 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:c406:: with SMTP id k6ls10314060plk.11.gmail; Tue,
 02 Feb 2021 07:42:07 -0800 (PST)
X-Received: by 2002:a17:90a:bd01:: with SMTP id y1mr4938872pjr.165.1612280526926;
        Tue, 02 Feb 2021 07:42:06 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1612280526; cv=none;
        d=google.com; s=arc-20160816;
        b=Bdigm0bu+fk01VFZp45zvphpipOTOB7T1dme6ZUOc4fk0IBsgO1zi2WT2wtBfSjykG
         gcyGXBAEFUUd2ddZztNsg580VGfugKB89DBJYqnFaXgyrySB3Z2lE1xGbBXK0tg3d1XG
         J/yvjkwBgOssg4QVirgOwiHX8a09vGVvUDwOa1lw4ucgc6rN9Si+DRfCRORgttgjBXfI
         ZK8x+wyJxTCd7ZjPWTU0srGTF+gkXbDGg8rQYyvF4sDbwbBn0cTNrxm9wD/W1nS0mLKM
         7h4xJDF8sKKt8cu5kT49uyHsQsfn/eviSUx184+hQG3Pi6JUFRr+FTc/xNjvNi9yloQw
         YE+Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=HRMHSeSB4EsKMZWQxXI/w1Azj1+afQ0bxrhrIMhv1dM=;
        b=iT6PUJWVL+b5PuhV1x4HZltWhCYVwAdv3cz76h4VweQlX7Jd9Fj7vm0CZVvngt2UFK
         IptulNlNRUVDYRjvyWNKx/N/pVpu0WaGtDOaY+07UKViKP9KzxB5BRuM5nuFZNfyHOZm
         VCkx1pLrpdJksEqCo31P+SZNW7Icsp4kkpRiISi8ZyF0fHgz7bAgTz6psNrSza+Bi2zs
         zC4q/lE0iv9TR8wMQXF1WdtZc7IJ16Pgq7fQQm12S+mqktOhZQHe7yt54fa9ZK03WPP0
         ssiwuFguLKHiB+emcf4vZQUDwvUSCzu463iByvyb4iU7Z9jp5SUXPmUaXFW+vwhm4o7W
         c0YA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id i23si227369pjl.3.2021.02.02.07.42.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 02 Feb 2021 07:42:06 -0800 (PST)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id F04BF64F4B;
	Tue,  2 Feb 2021 15:42:03 +0000 (UTC)
Date: Tue, 2 Feb 2021 15:42:01 +0000
From: Catalin Marinas <catalin.marinas@arm.com>
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Will Deacon <will.deacon@arm.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Peter Collingbourne <pcc@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Kevin Brodsky <kevin.brodsky@arm.com>, kasan-dev@googlegroups.com,
	linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org
Subject: Re: [PATCH 10/12] arm64: kasan: simplify and inline MTE functions
Message-ID: <20210202154200.GC26895@gaia>
References: <cover.1612208222.git.andreyknvl@google.com>
 <17d6bef698d193f5fe0d8baee0e232a351e23a32.1612208222.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <17d6bef698d193f5fe0d8baee0e232a351e23a32.1612208222.git.andreyknvl@google.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: catalin.marinas@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as
 permitted sender) smtp.mailfrom=cmarinas@kernel.org;       dmarc=fail (p=NONE
 sp=NONE dis=NONE) header.from=arm.com
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

On Mon, Feb 01, 2021 at 08:43:34PM +0100, Andrey Konovalov wrote:
> +/*
> + * Assign allocation tags for a region of memory based on the pointer tag.
> + * Note: The address must be non-NULL and MTE_GRANULE_SIZE aligned and
> + * size must be non-zero and MTE_GRANULE_SIZE aligned.
> + */

OK, so we rely on the caller to sanity-check the range. Fine by me but I
can see (un)poison_range() only doing this for the size. Do we guarantee
that the start address is aligned?

> +static __always_inline void mte_set_mem_tag_range(void *addr, size_t size, u8 tag)
> +{
> +	u64 curr, end;
> +
> +	if (!size)
> +		return;
> +
> +	curr = (u64)__tag_set(addr, tag);
> +	end = curr + size;
> +
> +	do {
> +		/*
> +		 * 'asm volatile' is required to prevent the compiler to move
> +		 * the statement outside of the loop.
> +		 */
> +		asm volatile(__MTE_PREAMBLE "stg %0, [%0]"
> +			     :
> +			     : "r" (curr)
> +			     : "memory");
> +
> +		curr += MTE_GRANULE_SIZE;
> +	} while (curr != end);
> +}
>  
>  void mte_enable_kernel_sync(void);
>  void mte_enable_kernel_async(void);
> @@ -47,10 +95,12 @@ static inline u8 mte_get_mem_tag(void *addr)
>  {
>  	return 0xFF;
>  }
> +
>  static inline u8 mte_get_random_tag(void)
>  {
>  	return 0xFF;
>  }
> +
>  static inline void *mte_set_mem_tag_range(void *addr, size_t size, u8 tag)

This function used to return a pointer and that's what the dummy static
inline does here. However, the new mte_set_mem_tag_range() doesn't
return anything. We should have consistency between the two (the new
static void definition is fine by me).

Otherwise the patch looks fine.

Reviewed-by: Catalin Marinas <catalin.marinas@arm.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210202154200.GC26895%40gaia.
