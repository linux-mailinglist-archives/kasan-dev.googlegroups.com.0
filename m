Return-Path: <kasan-dev+bncBDH7RNXZVMORBVNS5GXAMGQER2FYEVA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x637.google.com (mail-pl1-x637.google.com [IPv6:2607:f8b0:4864:20::637])
	by mail.lfdr.de (Postfix) with ESMTPS id 1C3BE8627A1
	for <lists+kasan-dev@lfdr.de>; Sat, 24 Feb 2024 22:02:15 +0100 (CET)
Received: by mail-pl1-x637.google.com with SMTP id d9443c01a7336-1dc0e27ea7dsf1594845ad.1
        for <lists+kasan-dev@lfdr.de>; Sat, 24 Feb 2024 13:02:15 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708808533; cv=pass;
        d=google.com; s=arc-20160816;
        b=BSZri5b+MrQH8wzV3j2Oc/1k6pXNolexxhD5LVULaSyPWgOpdKrAX1s9ekSlJMg2qd
         47Rj7xQ7Y9C1mD0i3lpJSM6EXJpvtiXonAgOiiadX2WjLj9u6HYFWwobWALG6tD22OsM
         uX1BFM8bslRkwiyL6xEnEEj5Wknb26aKtE6UIEh/Q75uWrQ4n/WUFQu0K1m/BrM++U+e
         xJ1d3goKIzuN6a7Au040TEo0cyDNDFjhx7jqz2rdtjGxbTaibYOGvTPWaGcQVg7e+9VC
         TFU9zm85VxjdFCOQ8LnZEsPPURHLPMGWW+tlwzHLckbC0rERorROYkKhIlhoQvOIb4Af
         1tRw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :message-id:in-reply-to:subject:cc:to:from:date:dkim-signature;
        bh=8bAWSLBP3xSIbJkCvDhOpXjuJejqt0zdAky0+FnnzkE=;
        fh=VRHd6S5/GgNh7i+dB/ajC7PcDiSQAsWyKUgjY8/oqNI=;
        b=fgdamm/yYzprZTM/McQPBBeOU3nESS5Wqz2ArUtN08dZSOEPqs/j/smQ/H/XQRwGo6
         0NHhgHQPp/IQTBepz0fYVuHJQgmBZ+6r+r0veVVVkiIZLZC+VJFJ/3keu0LruwE4JABj
         OJNQe6mjRWOWuuqG02r98Aof9shoFcHuvs7tLe3kHBKetJIg6hcFpSLCsi9UjBVbMtqK
         pEZkDFUBffjreli7n6GZZmkL3KqrHoEqcvJZQ3ydrrbZ44FZyAYfEMj9VHQVWMTwtLmj
         7HyIRG4uDSyIhrg7yrYHkfN9snkr6l6mIsMe9R6gFJ7tBla5xxrLhy6DX5ueEzO1QOVg
         JZkA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=YhdwmmB4;
       spf=pass (google.com: domain of rientjes@google.com designates 2607:f8b0:4864:20::62e as permitted sender) smtp.mailfrom=rientjes@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708808533; x=1709413333; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:message-id:in-reply-to:subject:cc:to:from:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=8bAWSLBP3xSIbJkCvDhOpXjuJejqt0zdAky0+FnnzkE=;
        b=aPQmkrwcCyjYzrgZYALxlwTOYp52TJqjliYGoV20wjvi/FokpCHEo1uFJ/tqYeI22i
         ZoO9latHfDt1t8NqkTbK9Z9r2k1DkgWMSsxbr9TTJvOfRChzYqU5/bnCHspDSZ/ql4Ch
         bKGkTGu5IltAzodtmTH7YKJkZwtEk4eFtNmx5TycwbsjUaWTe+4wnJkdNy8iIy0pk7hg
         X226+Ep2DYVOTyZ6VSQftnghC6b5ALu8jM3pmJKfYzL5zKMcZToKNGDVipqG6mCHj8Et
         GCk7TR4R4tJSqEkh1Fyfiaw9HGIB3/WAbg1ec4WWS1KezSbkVH31JWHB6mYlFZU6Fnow
         nC3Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708808533; x=1709413333;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:message-id:in-reply-to:subject:cc:to:from:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=8bAWSLBP3xSIbJkCvDhOpXjuJejqt0zdAky0+FnnzkE=;
        b=oGGsmb0fKajidsXZIL2ae+6+se/kxYMnyWNLeqgeDiosYmIxOaeP/GRAWY15F9+vyQ
         RZzBypPsvsYheKDFalw/JBzUXI8uiGOF8uJ1DpYFBUr9tHMKu7Ysy0W96906BpBbd6uU
         SuA0JMyRHyCg/EwlxynI/Rri//pcEx+52BZIyiyF3I8fmrEXWelwzXfVY8tzQOJ3XbBE
         66OEm7Fqtn2ScBNV39s6Nyb1ZR9pvxkLrY6GrZoaTW+0opNlUSkDU6t4GQ3SF0BNnbvK
         lQxqB/mg7AgoQSGElHqn4u4DFTKHhpHcF/ZSe/6rdiDak2FXOpE0zh+R28IIUyphSIB/
         CqQg==
X-Forwarded-Encrypted: i=2; AJvYcCWbavM7MpUIPF1Zdc1yIPPDLFc0ixY5fiQOCpszRHvGQLh/EcQ5Z+Y6yApflhibCuIc/zNICexUm/EQgoESONvCyGXulzALbg==
X-Gm-Message-State: AOJu0YxMeJTUpqPsvWcmZD+A8m2UF52HuS45H/z62jurH0J3irSJREbj
	H2ei+IcKSlvKUn1eS1G82sePjIlvaCRycLaVfYmeFFDU4maNHXAO
X-Google-Smtp-Source: AGHT+IFZLWhSjY5DqpzPoFr3t0L8AwId7eEBTjc8T7p/d67AzpaERfcNoDdHLBuHno15wqs6CIeYKw==
X-Received: by 2002:a17:903:a08:b0:1dc:941f:3065 with SMTP id mm8-20020a1709030a0800b001dc941f3065mr626plb.20.1708808533622;
        Sat, 24 Feb 2024 13:02:13 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:1d15:b0:6e5:a6f:8474 with SMTP id
 a21-20020a056a001d1500b006e50a6f8474ls19268pfx.1.-pod-prod-08-us; Sat, 24 Feb
 2024 13:02:12 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXfbMeH4e62rUpkvy4aMFEpGxF5KBKiv1cu3pBGV99g00AC4Cs4Mu2LAndwsrpvh0Q4hxjxAw4eVzcm1EylID5QVbMEnaZF0jb9AA==
X-Received: by 2002:a05:6a00:3c8b:b0:6e3:fe0b:527 with SMTP id lm11-20020a056a003c8b00b006e3fe0b0527mr4884500pfb.30.1708808532175;
        Sat, 24 Feb 2024 13:02:12 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1708808532; cv=none;
        d=google.com; s=arc-20160816;
        b=NAEEYAWOO5SSLPMmowUSGDObVyyVprmpRKH7QZPXQksLVEPUV0s88rye623PY9rkI0
         28fbKIpGvPnbhtIXnG4r9a/yYNwlu2VkgW6o7VClHXDuXQuffWhIBE9Pk5ohhp/cCSo/
         pQsCpTeVC46EPy5EaqOyAChlk2nXpGr3k81G9VvPmc5IJI8zDiSS6bAZsoPP8aZoLlZT
         s4JH2yWOqQ0LB/0ShxaxmZBZclWwqNFRD5FL9riFwAwMj0T46MajRIQDb299rIYU/zD+
         j5GW9bOk8rRBtBj6aDJ7lWHjullI6t1SSmtDPrC2p/X0CyY6HxSLViR1TSoTe4jy9KuB
         /MHA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:message-id:in-reply-to:subject:cc:to:from
         :date:dkim-signature;
        bh=ePcRftl5sVDiYzrpHJ3u0w2CefDD/b0RFj0UwX8i7Ys=;
        fh=dBzPefGfKtN93TrxR7Zh9DY3uQULqTMBVBUjDrItxA8=;
        b=xAUF8d5yHM29rSyYXEp8MEGM6YfMB+vdL2KYjJCI6hVr8oc98kSqvw/L6TV718HQ3j
         jCN2RiX6NmDD2sCKban9DX4OQ/INgjOLxa6u7ks32uiff3+R9sJVCipvBlMjHI/uRx6C
         gYTcfA2UfcZ8GtL2R8/3pktzNuhMA/05vYtKdRFHHbaCMEiAmhr4OAeloqIje5jjxloO
         C9Sig3Fl02cCOGf2/+6e/kIIaKrA2q3OJq5RkXr9cP5kwCYBkOJv9lw3bbuQr78P8Bxp
         1mgIN7cBU+3ctniggX4KGRr9ifBrt1rfkmrQnNcT/tfav68wjfwIbNF7nvNVGs20WolZ
         wsZA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=YhdwmmB4;
       spf=pass (google.com: domain of rientjes@google.com designates 2607:f8b0:4864:20::62e as permitted sender) smtp.mailfrom=rientjes@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pl1-x62e.google.com (mail-pl1-x62e.google.com. [2607:f8b0:4864:20::62e])
        by gmr-mx.google.com with ESMTPS id p31-20020a635b1f000000b005dc13d8277dsi49116pgb.2.2024.02.24.13.02.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 24 Feb 2024 13:02:12 -0800 (PST)
Received-SPF: pass (google.com: domain of rientjes@google.com designates 2607:f8b0:4864:20::62e as permitted sender) client-ip=2607:f8b0:4864:20::62e;
Received: by mail-pl1-x62e.google.com with SMTP id d9443c01a7336-1dbe7e51f91so84255ad.1
        for <kasan-dev@googlegroups.com>; Sat, 24 Feb 2024 13:02:12 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCV7QrvuKD02Duh542afaKsuilmitr2ze3pTOpT+yHx1UDX9KKwicIXugtsAEaYAayYS+Qi3o1JlFx6BdL3pqYABI7/3uWl3vX+z/w==
X-Received: by 2002:a17:902:d203:b0:1d9:907f:635a with SMTP id t3-20020a170902d20300b001d9907f635amr183529ply.13.1708808531154;
        Sat, 24 Feb 2024 13:02:11 -0800 (PST)
Received: from [2620:0:1008:15:ce41:1384:fbb2:c9bc] ([2620:0:1008:15:ce41:1384:fbb2:c9bc])
        by smtp.gmail.com with ESMTPSA id r32-20020a632060000000b005d30550f954sm1474292pgm.31.2024.02.24.13.02.10
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sat, 24 Feb 2024 13:02:10 -0800 (PST)
Date: Sat, 24 Feb 2024 13:02:09 -0800 (PST)
From: "'David Rientjes' via kasan-dev" <kasan-dev@googlegroups.com>
To: Vlastimil Babka <vbabka@suse.cz>
cc: Christoph Lameter <cl@linux.com>, Pekka Enberg <penberg@kernel.org>, 
    Joonsoo Kim <iamjoonsoo.kim@lge.com>, 
    Andrew Morton <akpm@linux-foundation.org>, 
    Roman Gushchin <roman.gushchin@linux.dev>, 
    Hyeonggon Yoo <42.hyeyoo@gmail.com>, 
    Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
    Alexander Potapenko <glider@google.com>, 
    Andrey Konovalov <andreyknvl@gmail.com>, 
    Dmitry Vyukov <dvyukov@google.com>, 
    Vincenzo Frascino <vincenzo.frascino@arm.com>, 
    Zheng Yejian <zhengyejian1@huawei.com>, 
    Xiongwei Song <xiongwei.song@windriver.com>, 
    Chengming Zhou <chengming.zhou@linux.dev>, linux-mm@kvack.org, 
    linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com
Subject: Re: [PATCH v2 2/3] mm, slab: use an enum to define SLAB_ cache
 creation flags
In-Reply-To: <20240223-slab-cleanup-flags-v2-2-02f1753e8303@suse.cz>
Message-ID: <9e2e6912-5778-2e34-5f63-3ccaebdbe576@google.com>
References: <20240223-slab-cleanup-flags-v2-0-02f1753e8303@suse.cz> <20240223-slab-cleanup-flags-v2-2-02f1753e8303@suse.cz>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: rientjes@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=YhdwmmB4;       spf=pass
 (google.com: domain of rientjes@google.com designates 2607:f8b0:4864:20::62e
 as permitted sender) smtp.mailfrom=rientjes@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: David Rientjes <rientjes@google.com>
Reply-To: David Rientjes <rientjes@google.com>
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

On Fri, 23 Feb 2024, Vlastimil Babka wrote:

> The values of SLAB_ cache creation flags are defined by hand, which is
> tedious and error-prone. Use an enum to assign the bit number and a
> __SLAB_FLAG_BIT() macro to #define the final flags.
> 
> This renumbers the flag values, which is OK as they are only used
> internally.
> 
> Also define a __SLAB_FLAG_UNUSED macro to assign value to flags disabled
> by their respective config options in a unified and sparse-friendly way.
> 
> Reviewed-and-tested-by: Xiongwei Song <xiongwei.song@windriver.com>
> Reviewed-by: Chengming Zhou <chengming.zhou@linux.dev>
> Reviewed-by: Roman Gushchin <roman.gushchin@linux.dev>
> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>

Acked-by: David Rientjes <rientjes@google.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/9e2e6912-5778-2e34-5f63-3ccaebdbe576%40google.com.
