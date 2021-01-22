Return-Path: <kasan-dev+bncBDX4HWEMTEBRBU7RVOAAMGQEBUGCWSQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23c.google.com (mail-oi1-x23c.google.com [IPv6:2607:f8b0:4864:20::23c])
	by mail.lfdr.de (Postfix) with ESMTPS id 80795300845
	for <lists+kasan-dev@lfdr.de>; Fri, 22 Jan 2021 17:09:56 +0100 (CET)
Received: by mail-oi1-x23c.google.com with SMTP id t21sf1794810oif.16
        for <lists+kasan-dev@lfdr.de>; Fri, 22 Jan 2021 08:09:56 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1611331795; cv=pass;
        d=google.com; s=arc-20160816;
        b=yRNb53LDp6Lj8aufQXNhb2BLdBD2LSHbYtG9F2foTY/g35CNcAr+qQrQXvkhe2rRkD
         vMQo0qBVaXlLWHQl/zUFEV81oQgobDe6vTuRJmr3CMYcIqsL/kdkPveSM5JV3ARLeq/i
         S9L27vkWxP8G9KARABmAAMsh1kok2Vlycu+VhwBB+extDIerjIoEcai9AGwIfq0+96sn
         a2bRdfpdDBUX+MMvWk4+qiCUNILojeAP4bJj8OK0RMRltyVtbZM6vU3LmjTNMoEcLVtZ
         Ix6/CGBWRJJ4M0Hecdq9+O/spJYJgpVeu4m1uw7sKYrVq/5aSgHRwyuSRWHOKxXFCYjp
         XjEA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=0X17vU4HAT7JcMjToKk2NVhjA+9DOcxQtjcRwr0AtHI=;
        b=qvKvqipGoWSAjQf4PC1RkVIGRCSaaNoziZPtJG0ozqMJFYTXQVY84RyGPw/i+EQxk9
         sHXF2sAYHfIRIO0d58jfVUXBAJdaAKySWOEaQnFvoxpYUV57QLlgbocMzoJEYkS+BnIq
         hd9Q/9RhgAnr7Rb3Pwf58+dYeX7zXZkIzfqOTNqJalU66Pi1Z3JTgRW+1hHY4JIfXpWU
         Ncy1RjI2zmE5p4LqslC+kURsrgjgPBCDwERbHE9DqR7OBDz2AzX33ugIA5NO5qFy03Mz
         XCpjqbioylGf7FeevFRpMm7ZRikoxGltnBcZ0UTveKlPb3PXpc8GT39xPf0cuoO/iglf
         5xMw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="ohn/q1od";
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::62c as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=0X17vU4HAT7JcMjToKk2NVhjA+9DOcxQtjcRwr0AtHI=;
        b=lDEk7hG6an+FbOLlx3GXoW5gS1r4szGss6z3CNUjl57U5cExS1r9MF13ZRxXOpmwk5
         Hea0devEpdR/KOOLau2YfXUh7lRcZACYP0udqxKhbNbUyJkV2En3LfQwPyCHU9jq5/+N
         drYbatUA2J+MmWqhfVZqPtu34joduvwN+Fvr9uv43IP8ikoK/nUkWPI4yKxEYx88gCqp
         rWR9bSyvQrFw0bdGihgn4YWzrsZ2LwyDQyZhOiJZl8CUN8zKfk64Q3tPjJvBAlW4Ftat
         pTQHbukosIWU5WonDgm5oGIth7fcy8nGepOLiCgH12Ws4MVijP9ovT5vvmIe/sOnUxXc
         i9LQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=0X17vU4HAT7JcMjToKk2NVhjA+9DOcxQtjcRwr0AtHI=;
        b=WrzuTIChrS7HmRhqU8/BfyHa+DGv9FQ0gzz4p7h7OVgioz8QL2MA3fa+4U0g+iuC18
         eRP8e5aUurK6K88hjBeyiI597tHCJSZR51G20HbWVXvDHrV1b+wLim93z8Oj2aaBwXl4
         kIrEXHxSyTRExRlkX4WY2dHBTuXeomEyFY4t/p2X6ISVDebePTYSqzA8YNPEb9yHJTcY
         ALvyoNBClIx5kHnD1V6qpcFd/VDFPM2teXIEW0/iY9jIr+etLW3DRVKwOx1A3bm1Q+/s
         3hmEIHkvVUXgaed2V7rW81i0kukpAjKdGHBq8Swt6CfQX8mnVVLj1TUqPMSfFv297pap
         IEfQ==
X-Gm-Message-State: AOAM532qoqqbg8VCoIU9lQUZ/xR4JCsmc4yjj4Xw2/uDWzT7c9lSSM99
	A3fBYb+P7yZJe4h6Pu4iknw=
X-Google-Smtp-Source: ABdhPJywOy8xNLEmRJf00sjXGRk56TYWPCsp6fJ4x6WV0TvJFoprZLe1OcQKxONycCGj6EF3vEF/aQ==
X-Received: by 2002:aca:56c8:: with SMTP id k191mr3757821oib.12.1611331795567;
        Fri, 22 Jan 2021 08:09:55 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:504c:: with SMTP id e73ls1595566oib.9.gmail; Fri, 22 Jan
 2021 08:09:55 -0800 (PST)
X-Received: by 2002:a54:4489:: with SMTP id v9mr3877370oiv.154.1611331795268;
        Fri, 22 Jan 2021 08:09:55 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1611331795; cv=none;
        d=google.com; s=arc-20160816;
        b=Tt3KHua+D/5tdaogZFO3XlZwe1CB7fzdMuF3bf+fqlb5vYArJWrY0631IPqTC6wUaS
         ogipsZ+7UYlJlD4qDcnxf24jgDejTjDg7DetAozAuHtfaQUym1RnM88cvBEQ6OuPxDEy
         T9THQOG3/O7w0/dYNn+G8maphm/R8GZqViuFrowzWY9mgUaNwOTQ+yNcvPY2/zgmPBz1
         AReFyBymb/j2jlaRdbfR6W7+Grzui40WtNHqQoIoC54gBEiHg99j3DGhGc64Sb5HRDRw
         d5lvkedFnz+KX7NNYVGiB+QjOTmt4hx3ViotHcWoLrKHIANxC3ukl8xTuFOXq1XpuFsD
         Lz+Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=wVquU/fnEPX2P2H0t7db3gVL7KbgnWZmVefN2ofYxhw=;
        b=HmDFuzMjooFn9is8lfLttAUhviJWzK4tZ8BavXBNApRLa8TYhxesbBxczHJMMJfoX8
         C/ZArKzoQhf9OjS4YeDzFDh48SEZecjCazSR+EL1013ESvH7nQ6mRJYOmvZOQ2Q3xTxa
         KGiX+dqDHCahQrntIoD6vSldu/yFH72ppNljx2WkUXcoA5BLz1jdKfs9eK1m4OnnljFz
         Jk80xR1r4zkJQU85duBTWM2voLw+ZvbUEdQFVA53rKGyDFe2ry2QffOpugOYJJq9Sm1n
         EjM8Jkug8EvMttSB4UstW2djQoJ1x16aWr2jBApi7CHnR+lWa6iu0IKni8AQSTdTl01P
         UH+g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="ohn/q1od";
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::62c as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pl1-x62c.google.com (mail-pl1-x62c.google.com. [2607:f8b0:4864:20::62c])
        by gmr-mx.google.com with ESMTPS id s126si433043ooa.0.2021.01.22.08.09.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 22 Jan 2021 08:09:55 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::62c as permitted sender) client-ip=2607:f8b0:4864:20::62c;
Received: by mail-pl1-x62c.google.com with SMTP id r4so3441159pls.11
        for <kasan-dev@googlegroups.com>; Fri, 22 Jan 2021 08:09:55 -0800 (PST)
X-Received: by 2002:a17:902:ff06:b029:de:362c:bd0b with SMTP id
 f6-20020a170902ff06b02900de362cbd0bmr5282054plj.13.1611331794468; Fri, 22 Jan
 2021 08:09:54 -0800 (PST)
MIME-Version: 1.0
References: <20210122155642.23187-1-vincenzo.frascino@arm.com> <20210122155642.23187-4-vincenzo.frascino@arm.com>
In-Reply-To: <20210122155642.23187-4-vincenzo.frascino@arm.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 22 Jan 2021 17:09:43 +0100
Message-ID: <CAAeHK+wzgy8UFBMzRFKUchSekURm3rkaJsOLe=VSE9D-6BAtvg@mail.gmail.com>
Subject: Re: [PATCH v4 3/3] kasan: Make addr_has_metadata() return true for
 valid addresses
To: Vincenzo Frascino <vincenzo.frascino@arm.com>
Cc: Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	LKML <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Leon Romanovsky <leonro@mellanox.com>, 
	Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will@kernel.org>, 
	Mark Rutland <mark.rutland@arm.com>, "Paul E . McKenney" <paulmck@kernel.org>, 
	Naresh Kamboju <naresh.kamboju@linaro.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="ohn/q1od";       spf=pass
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

On Fri, Jan 22, 2021 at 4:57 PM Vincenzo Frascino
<vincenzo.frascino@arm.com> wrote:
>
> Currently, addr_has_metadata() returns true for every address.
> An invalid address (e.g. NULL) passed to the function when,
> KASAN_HW_TAGS is enabled, leads to a kernel panic.
>
> Make addr_has_metadata() return true for valid addresses only.
>
> Note: KASAN_HW_TAGS support for vmalloc will be added with a future
> patch.
>
> Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
> Cc: Alexander Potapenko <glider@google.com>
> Cc: Dmitry Vyukov <dvyukov@google.com>
> Cc: Leon Romanovsky <leonro@mellanox.com>
> Cc: Andrey Konovalov <andreyknvl@google.com>
> Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
> ---
>  mm/kasan/kasan.h | 2 +-
>  1 file changed, 1 insertion(+), 1 deletion(-)
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
> --
> 2.30.0
>

Reviewed-by: Andrey Konovalov <andreyknvl@google.com>

Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2Bwzgy8UFBMzRFKUchSekURm3rkaJsOLe%3DVSE9D-6BAtvg%40mail.gmail.com.
