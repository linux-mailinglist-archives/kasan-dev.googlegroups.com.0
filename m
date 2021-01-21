Return-Path: <kasan-dev+bncBDX4HWEMTEBRBXXPU2AAMGQEJMXYD4A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x237.google.com (mail-oi1-x237.google.com [IPv6:2607:f8b0:4864:20::237])
	by mail.lfdr.de (Postfix) with ESMTPS id AADCC2FF1AA
	for <lists+kasan-dev@lfdr.de>; Thu, 21 Jan 2021 18:20:31 +0100 (CET)
Received: by mail-oi1-x237.google.com with SMTP id t21sf597988oif.16
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Jan 2021 09:20:31 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1611249630; cv=pass;
        d=google.com; s=arc-20160816;
        b=ba6eHqmIeBW9m05xphyOqZDCLWdginV54tMUGHgJdRm3rgPDSFVVq+Wpg7WywT0aTC
         ec1y1wnkjORm1hp8CpRy41Nc2Xp9Qb36St9m98SeTf7CIHN9FqfmrPGBcpLMVvURDeRE
         bYaYVgg5/hRb7QW3XyAsN3+w5CGNgFN+E2Du3y9LENLHKWqxE8090/VII+NqZxcXwUed
         buR4KaZM37hqaCyaptTnUe0rogjFzWB8Tz7+33xnjmqpmL7mcCeErsER8zLPPlHXutir
         W7yLN63gkxwGMdErGPKmF2maAbu550oL0goG7yOW8qPIqjUWbU0C37vuycOIuN/tAUns
         Y3zA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=ID9BRb3NX6O8zhbSEd/oI3jm0j3Mnn8pVAC5+YNc6so=;
        b=YtHGxXIMT9MhOYOKdcyqBZ3MK8AYHagRHL6cEqG8mp6bCnflfB/PRryQAHGwR7ckmh
         NS50+e3705b9ATKkMWYZqOiI+bm45thavSk/B7L+r9lX9xJGzRmKZWeDFl56JFFKFjoW
         s25hRCYVRg8RQAYGM1nNlNLc5krxhlETfxx1gce25u/afFzQV9w9fQbDR+fWYQd1klB6
         FKWtE54MWiYr8rwkqWF+ofoTVVPWAh248H3vZEuMojFAuXsVkSAX6DR04Inj291EUEfT
         y+nMfeHaPPU2ihACJ3BBmLYShOmBVe1tuMb4DvKiy60m9WfVt4COX3Z1aVFvQCCbpoXi
         /A+A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=sPQS8E+8;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::62c as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ID9BRb3NX6O8zhbSEd/oI3jm0j3Mnn8pVAC5+YNc6so=;
        b=aG0YGTb1JUiNyA4RiyAX6CgUNbMglAwAxTmPSuLNa/aOdjO+ZABfeOwnqZCjUVL7k2
         00uUjdT7XdsirSGkg9YV1n+rpOXvHRRNiUpziD6nIikForXgeZ8eKKPx0RfLc5+Ajjt7
         mDkPcEFVZ/mTwxLvsuAqXySohTPMrRUlTgNNpElpZroycB0M1zNiKafNPb+gBJW3GN9i
         azzveDwgd1f3Xyh/VcyvJNBeAnzcJbUIwNDNTSGBXN8oe7PJZ3wYLXgU7JAkkN8oCjCd
         TM26b6Gj3weEiZcHpiGVAPrgDzMPL3G/RmVwXuYK03CSe7jW4ZLGESpUdwT3b0CYkJIL
         cr/A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ID9BRb3NX6O8zhbSEd/oI3jm0j3Mnn8pVAC5+YNc6so=;
        b=SOTnmxQxudh/qSRL9lnoI69GyZ6aJdUA8NYVNs8FT4SXIetCgiOzotwE3dt2G4W0hz
         EJHaW2piIenG3KRqBqw/3Frsqpyhmtf4Pag2JPq65Ma9Rrf9ZuvPg+DclEeDtUJK2QHM
         heUeJrbwHfv6FQpIo0uFPeX74mKqPDUed2zJF14CHxolCxX/6SFX3F8pTVESflSc2xI8
         iANbYpj13jhHyx3vfHz22g9n4/MO1cBDpAg6yLNNqYOUTlO0uCjywFc61ssgSiMF98wy
         9Ctcc+3/najGYA4uzPdQ9WZFJtHidOzeYKhyRbWmmpPcB1kcCjSHhdITmJgJ7dsTZCyy
         Lsuw==
X-Gm-Message-State: AOAM5313df73oIfvfzPDMJZ4fA4WRyrX3k/kbYDMYhr3FnU7vFO4PfYr
	EQFTHqB1an5yQvwSjM9au60=
X-Google-Smtp-Source: ABdhPJyHH/3jfM/M47hkzG/7BJr+s4LtzWYBW9T/KR4yJcAlscZARhHyk85XrncTaTbZzuy6mi6uiw==
X-Received: by 2002:a4a:5703:: with SMTP id u3mr523981ooa.58.1611249630677;
        Thu, 21 Jan 2021 09:20:30 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:1391:: with SMTP id d17ls105862otq.2.gmail; Thu, 21
 Jan 2021 09:20:30 -0800 (PST)
X-Received: by 2002:a05:6830:2152:: with SMTP id r18mr111912otd.296.1611249630244;
        Thu, 21 Jan 2021 09:20:30 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1611249630; cv=none;
        d=google.com; s=arc-20160816;
        b=aZCB7Sbf3ktyqcvV3ppFAQRuNk8S9+m4xkb1FBhnkOHL98bmhQGG+L1A5QWvCra2+5
         Y7AuDstpRgNtYC6ym+QzzfIjZ/Q8N/aSYarwDyVmrt4SLF/SVV3K0ONITPjX8ht+1PUD
         /M+7rSKmXP1iXlNTBvgYVs6kSdQsO6y7Kx2QikUWASgA+6mOqG5UrhEvk0hVVqXNG30/
         tAnOtQjSZObC4pQlmjJHJWB5TrUoJ0Y+UeY7Kz921w6kE4G7lrflEZlkCmaGUx2vwQ+S
         Rxyx71+225Rt1cw2IDmEssSuKwoh+EgBRg9GUYQbsPKRPUT/CAn8oTraVyUQw9X48+FI
         Varw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=42oikTOcG3h7qaAKgY5xG16dol6URHxOGjSC7f21gjU=;
        b=sGuxAEEp6/hLFTejKnTaiwPJqcxjgEG8uixQf/M9UQGq0cnaC0NjL4nMYCScyFvIEn
         vmL47PaBJhp5YyfieWYLsRd+u/5DsTTIavP3+5F7MXXJyf+iBAD6fNSxmu3RUFgftNbQ
         zHxuEXmZldf7QPwpfc0ke+FKMrsq5nUtZOeQ03FkAp07ooQKWY4z+ueLoj4Rg39c7WzC
         ZFZso0nVK1WoUsW8IKs2cvdUXDnn9FiS60bulo99xcuilnErtgcQ+B+AqcovGRlVltpM
         haZB14GA0aE52H6TCkVVuwCOvRzYbkqCpcCkf5zar012m1L+UB8eGbynn2xdYeDwDS+o
         ZXqQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=sPQS8E+8;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::62c as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pl1-x62c.google.com (mail-pl1-x62c.google.com. [2607:f8b0:4864:20::62c])
        by gmr-mx.google.com with ESMTPS id e6si154582oie.2.2021.01.21.09.20.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 21 Jan 2021 09:20:30 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::62c as permitted sender) client-ip=2607:f8b0:4864:20::62c;
Received: by mail-pl1-x62c.google.com with SMTP id t6so1669953plq.1
        for <kasan-dev@googlegroups.com>; Thu, 21 Jan 2021 09:20:30 -0800 (PST)
X-Received: by 2002:a17:903:31d1:b029:de:8361:739b with SMTP id
 v17-20020a17090331d1b02900de8361739bmr658090ple.85.1611249629456; Thu, 21 Jan
 2021 09:20:29 -0800 (PST)
MIME-Version: 1.0
References: <20210121131956.23246-1-vincenzo.frascino@arm.com> <20210121131956.23246-3-vincenzo.frascino@arm.com>
In-Reply-To: <20210121131956.23246-3-vincenzo.frascino@arm.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 21 Jan 2021 18:20:17 +0100
Message-ID: <CAAeHK+yCq+p-D8C+LgHUSkuGZmZscJPTan9p6GT8GoUAVdnOqA@mail.gmail.com>
Subject: Re: [PATCH v2 2/2] kasan: Add explicit preconditions to kasan_report()
To: Vincenzo Frascino <vincenzo.frascino@arm.com>
Cc: Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	LKML <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Leon Romanovsky <leonro@mellanox.com>, 
	Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will@kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=sPQS8E+8;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::62c
 as permitted sender) smtp.mailfrom=andreyknvl@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

On Thu, Jan 21, 2021 at 2:20 PM Vincenzo Frascino
<vincenzo.frascino@arm.com> wrote:
>
> With the introduction of KASAN_HW_TAGS, kasan_report() dereferences
> the address passed as a parameter.
>
> Add a comment to make sure that the preconditions to the function are
> explicitly clarified.
>
> Note: An invalid address (e.g. NULL) passed to the function when,
> KASAN_HW_TAGS is enabled, leads to a kernel panic.
>
> Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
> Cc: Alexander Potapenko <glider@google.com>
> Cc: Dmitry Vyukov <dvyukov@google.com>
> Cc: Leon Romanovsky <leonro@mellanox.com>
> Cc: Andrey Konovalov <andreyknvl@google.com>
> Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
> ---
>  mm/kasan/kasan.h  | 2 +-
>  mm/kasan/report.c | 7 +++++++
>  2 files changed, 8 insertions(+), 1 deletion(-)
>
> diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> index cc4d9e1d49b1..8c706e7652f2 100644
> --- a/mm/kasan/kasan.h
> +++ b/mm/kasan/kasan.h
> @@ -209,7 +209,7 @@ bool check_memory_region(unsigned long addr, size_t size, bool write,
>
>  static inline bool addr_has_metadata(const void *addr)
>  {
> -       return true;
> +       return (is_vmalloc_addr(addr) || virt_addr_valid(addr));
>  }
>
>  #endif /* CONFIG_KASAN_GENERIC || CONFIG_KASAN_SW_TAGS */
> diff --git a/mm/kasan/report.c b/mm/kasan/report.c
> index c0fb21797550..8b690091cb37 100644
> --- a/mm/kasan/report.c
> +++ b/mm/kasan/report.c
> @@ -403,6 +403,13 @@ static void __kasan_report(unsigned long addr, size_t size, bool is_write,
>         end_report(&flags);
>  }
>
> +/**
> + * kasan_report - report kasan fault details

print a report about a bad memory access detected by KASAN

> + * @addr: valid address of the allocation where the tag fault was detected

address of the bad access

> + * @size: size of the allocation where the tag fault was detected

size of the bad access

> + * @is_write: the instruction that caused the fault was a read or write?

whether the bad access is a write or a read

(no question mark at the end)

> + * @ip: pointer to the instruction that cause the fault

instruction pointer for the accessibility check or the bad access itself

> + */

And please move this to include/kasan/kasan.h.

>  bool kasan_report(unsigned long addr, size_t size, bool is_write,
>                         unsigned long ip)
>  {
> --
> 2.30.0
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2ByCq%2Bp-D8C%2BLgHUSkuGZmZscJPTan9p6GT8GoUAVdnOqA%40mail.gmail.com.
