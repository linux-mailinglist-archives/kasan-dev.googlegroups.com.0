Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBHOYXKAAMGQEKXDWVUA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3e.google.com (mail-io1-xd3e.google.com [IPv6:2607:f8b0:4864:20::d3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 259D330244D
	for <lists+kasan-dev@lfdr.de>; Mon, 25 Jan 2021 12:31:42 +0100 (CET)
Received: by mail-io1-xd3e.google.com with SMTP id z24sf18415289iot.16
        for <lists+kasan-dev@lfdr.de>; Mon, 25 Jan 2021 03:31:42 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1611574301; cv=pass;
        d=google.com; s=arc-20160816;
        b=dsP2CGerkxHwlQtRY4aPIoxdU1PMas1BRj4nhXkVSaWA8U12gOSF1JXJmpYbjwZ+ns
         df1p0lzY0aB7tUPy7lwGiZvP/nv48tCwtbU5qQ+Ffwanc8EpJg9vusR/hZ62Otsz0xcc
         JsT+qslri+HjQvEWjISGNKEA3R/ggOVoGhMOauQxoVpVhKkxvwyNvng2Al8wSJQS4J6K
         BU+NfA9KVhswZ4MvzEbDN2klY/bFLvN6fIhrOLo0RidgLi8OvXDk9E+5Xg5qGG1/omxX
         z0rKyJakKDxM1l1YK4Ocg6e1jZpBEJK/Eh8cpLbyd3GZj6wdzhkSYB1vm1C2JZFIqyH7
         +N2g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=gCWd3rFE8xk70CLUBdLsQHhFSW/Lo6Hv4TQYSV+nyf8=;
        b=OLeJsH7RSwz1WBqjLvHtcjW7gd/DbY9GIFBwr9XgjGx8Cpcviu5OVqJzg6jpPx5Vqr
         D1eEFKhSINX5lKbIodeQPEC1S3V0R6S2fX3pqy3+A2Fh/qP+ZxgzyDEsGclJivB/Kxw2
         wRCiVyWWRc2Dy4gFAXj/EECA6wvk+87aDL9RhSFZO4N0xBSm6c8s1gFz0NfXYd43KOqd
         Kzkzk6ISUKAPWduTqDelQI7avsIlsrqanz1AWHNMJ4Qoi8UFeCmxItFVItSLv6KjSPWI
         izWT93axdPPdiwaq6wrh/on8fu77RNc9tw7348KUGSnE8kxVYC3xtb7fMQ638XAY+2eN
         7l/Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=gCWd3rFE8xk70CLUBdLsQHhFSW/Lo6Hv4TQYSV+nyf8=;
        b=NcXx58afSwXUXPB0yVljB3juNZpz8HJyZGaQdlu9Cn39EzOHuebc01rbY3Uf2YYH2X
         CkeHXYF65prfUGBbnkeQjudpGGob9RneDYkke8sunqfMMkxbLSObk3HCZR0Pnlz2i7d7
         PLGYXSs5ydIFAEMX0Lj+tmBTGqnajVrjBNcsnZ+y+4HHMJ8Ka7LzlNgjNgwPUZJimCJ1
         tw5PD8wrZETTlRWx4/LdyERHsslFDBETn/+69u94bBE5grrQgi/j0O4xaZgmFfKdrZAu
         eJ2obTWNEEfOKMbnK8pwqdijtht20OEHZFFzt8HINm6eYr0ajm/4txsUXfgdxqslMntJ
         vKHA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=gCWd3rFE8xk70CLUBdLsQHhFSW/Lo6Hv4TQYSV+nyf8=;
        b=e4KyRZ+xeci9anjjX6zN2loTDRGQeioFJ3tH5SPn/0CsFytBiEi7lcFf76cxEiWVbg
         g13s6V6t/q8qC/Ob9ntuQXyzqsJDNZWPflfLzlePucVNv/BEZM2uo3G8lqXkz82jMGsa
         l6M2IvGog4MLH8pepCPKthkaU4KFuJSgUTpw59zU4g/d65JHh7DCG2euZfFhqj9ssPDU
         sw4wq+Tgs8id1za6h2vyVGlEmcM7bq3PMwL+yrf8WE7m7DLtvDGNmfe0OVDhFhXxna9r
         AffDqkjJ3nM3qckUy+SenQrbdvC2TGDzYrTuvv5zHYGXi0nNnA5WSFZGbzottWjOYd32
         N/Kw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533gp4dxwkD63f1xM42awACmZzZQ6OT4KrJHlkev9zqokZSbtnKU
	eVFYM1/tlS90KJAJoWgy4FA=
X-Google-Smtp-Source: ABdhPJyXwU4YzH/ke23ltgSd8lNYsY8a9o1qBIyJH+PMOKRYwMOgBJoB5kvq1SJ9nadRbntrVaIitw==
X-Received: by 2002:a92:c9ca:: with SMTP id k10mr99079ilq.291.1611574301195;
        Mon, 25 Jan 2021 03:31:41 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a6b:1445:: with SMTP id 66ls1732603iou.11.gmail; Mon, 25 Jan
 2021 03:31:40 -0800 (PST)
X-Received: by 2002:a5d:9302:: with SMTP id l2mr24868ion.172.1611574300940;
        Mon, 25 Jan 2021 03:31:40 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1611574300; cv=none;
        d=google.com; s=arc-20160816;
        b=l3dlQeMpQfHSJVBAjBmfggFcAD+Qox46FsnljSEaQR7tDnhYcTN00ccU6CBV6h79U0
         +u4tvsP0oLoXLU+uWwg/8mNkWCeNVraMXkhxyOIR297YmyGiLij3RYGzstqXgjjiCBsr
         f68uXHXhcjPJaGzPIntyrN2T+KmVqziimBkPr85s7dMUBc5D0DMnohSh4H0/EBsaXYMI
         w6rVgbCKKkL8qrIhNFdPpdHlG8Jr8bsZ8Pfy0baMniW664hOmbiKHfxbvU2+RwnG3isa
         DtR9nwtFtk/LfygtcDoy7OL3LzgxUTTitoTAjIFR78giCw6iU52bvXciOFR8nf6DzEta
         CRQA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=fvvgjlqzoOOSHFtaJ0Ke4t8QiMPU1hpLf0ADmJUR4Ow=;
        b=yDXf2WvWZsWtM7Ljqt+pZ90DGPoI6txdH3EEk72r+J9kSlXyUoV9LnxOxV5Bg55JnJ
         ZNlBO4hCoTPnWTdAW3QYRIglHG3scQ4czHkNIYzMzlrUbq2uEalqqxgDo5T5lXoWGYvw
         iPtsaN24Z8C76wxb3R872BecnpUgB80g4qUSSxtqTU6r9eLs1OvfoM5VLy9WO1WgwYxR
         XLuQ14HT8JAoZh+Z8DCw1dLk5LWz+rq5GWLcbFiIzDlu86Gb2ygX3JguqAVcL/Gz7SqL
         4D5NAcfHB+ClYpOsZqO08KL9JnX4FAdFnPkfR/Ew7efE1jd90Wb5NF6EpNN6yZjpIvO0
         ZWDg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id o7si857322ilu.0.2021.01.25.03.31.40
        for <kasan-dev@googlegroups.com>;
        Mon, 25 Jan 2021 03:31:40 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 3C32EED1;
	Mon, 25 Jan 2021 03:31:40 -0800 (PST)
Received: from [10.37.8.33] (unknown [10.37.8.33])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 25E963F66E;
	Mon, 25 Jan 2021 03:31:38 -0800 (PST)
Subject: Re: [PATCH] kasan: export kasan_poison
To: Arnd Bergmann <arnd@kernel.org>, Andrey Ryabinin
 <aryabinin@virtuozzo.com>, Andrew Morton <akpm@linux-foundation.org>,
 Stephen Rothwell <sfr@canb.auug.org.au>,
 Andrey Konovalov <andreyknvl@google.com>, Marco Elver <elver@google.com>,
 Alexander Potapenko <glider@google.com>
Cc: Arnd Bergmann <arnd@arndb.de>, Dmitry Vyukov <dvyukov@google.com>,
 Walter Wu <walter-zh.wu@mediatek.com>, kasan-dev@googlegroups.com,
 linux-mm@kvack.org, linux-kernel@vger.kernel.org
References: <20210125112831.2156212-1-arnd@kernel.org>
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
Message-ID: <d15786d7-b7cd-86ae-adac-5a581e683be1@arm.com>
Date: Mon, 25 Jan 2021 11:35:31 +0000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.10.0
MIME-Version: 1.0
In-Reply-To: <20210125112831.2156212-1-arnd@kernel.org>
Content-Type: text/plain; charset="UTF-8"
Content-Language: en-US
X-Original-Sender: vincenzo.frascino@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172
 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
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



On 1/25/21 11:28 AM, Arnd Bergmann wrote:
> From: Arnd Bergmann <arnd@arndb.de>
> 
> The unit test module fails to build after adding a reference
> to kasan_poison:
> 
> ERROR: modpost: "kasan_poison" [lib/test_kasan.ko] undefined!
> 
> Export this symbol to make it available to loadable modules.
> 
> Fixes: b9b322c2bba9 ("kasan: add match-all tag tests")
> Signed-off-by: Arnd Bergmann <arnd@arndb.de>

Thanks I just stumbled on the same issue ;)

Reviewed-by: Vincenzo Frascino <vincenzo.frascino@arm.com>

> ---
>  mm/kasan/shadow.c | 1 +
>  1 file changed, 1 insertion(+)
> 
> diff --git a/mm/kasan/shadow.c b/mm/kasan/shadow.c
> index de6b3f074742..32e7a5c148e6 100644
> --- a/mm/kasan/shadow.c
> +++ b/mm/kasan/shadow.c
> @@ -94,6 +94,7 @@ void kasan_poison(const void *address, size_t size, u8 value)
>  
>  	__memset(shadow_start, value, shadow_end - shadow_start);
>  }
> +EXPORT_SYMBOL_GPL(kasan_poison);
>  
>  void kasan_unpoison(const void *address, size_t size)
>  {
> 

-- 
Regards,
Vincenzo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/d15786d7-b7cd-86ae-adac-5a581e683be1%40arm.com.
