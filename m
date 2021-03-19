Return-Path: <kasan-dev+bncBDDL3KWR4EBRBO6E2OBAMGQEJGYYSFQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63b.google.com (mail-pl1-x63b.google.com [IPv6:2607:f8b0:4864:20::63b])
	by mail.lfdr.de (Postfix) with ESMTPS id 1E788342386
	for <lists+kasan-dev@lfdr.de>; Fri, 19 Mar 2021 18:41:17 +0100 (CET)
Received: by mail-pl1-x63b.google.com with SMTP id u5sf21517279plg.2
        for <lists+kasan-dev@lfdr.de>; Fri, 19 Mar 2021 10:41:17 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1616175675; cv=pass;
        d=google.com; s=arc-20160816;
        b=fNObOlBpWg1CPpQnOwGn5BuPGb3Yv+/XFQbkNyerp9gAyRlC6zaOWpoj0kRr/n47CF
         dN8/MyemqW9rb7zs1oNvjIVxFyvd94XjSu8i9LLFMn4JV6EYzjc0PPPTIU3UBk/BMCbP
         9in6FPRoTh14d4IeSCh2vS1DeH0ghDaLyYXIdZSEuGtq+hZL4UUyRx34LH7yLwBSWtwz
         9ccSdB+EuvxQ7mZtJQuU1mh+85VrNvkAnAwjCS63Niwr95ixYxGKqDKfyZOkQckFKiAH
         zDW7UWmEKv/AJVMzPF9jRCQtCvE0hbkF1z7fifgZILc3kztDvi0Nu2Jn/wW52YakT3PL
         m0Uw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=vw4Cn1B49wHVQb8AT0MF3vSRgxneSC4jxpenb2brYPw=;
        b=iixdYv6cFCfsZIl54/uifyiM+l0OMJBbex9eWmPRrqanqy6mG5rM1+CmV7zjm9L6vL
         RwWanSSQB9/SxS7jyZgrV39s5gD3YVk/FkAH/0TLNLv3L18trgkVRfBUbcKQL1uFxy4N
         NAINioc9oKpSrXwfig7UDcKcCJRBcYGL8uh3+fE4Z0sp/EY93/xS729g3Y05ctK37oIH
         yEj7uYdF7kMshbGhQ4HS3IxBBjGnPA6cbFwWRUUQFA+EwEa/XrkhRtve+97tUXYuZ+9S
         zi8SvfAuMGGddxQ5kj3D5GWfilh16mhA6dHEXVDQDpQ6mPWmQzXQM8kA1zDpnnbwNiOs
         m3Qg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=vw4Cn1B49wHVQb8AT0MF3vSRgxneSC4jxpenb2brYPw=;
        b=NM9MRnf82V5DrOGFHwyRBNvEQVOYa6R0lWbUZEJHPTYr5S6pHTJWKF22AcJB0BWxjx
         GhD41xuI0CodZDFgv6R8J4txCvFQsH3fWAySKU9OcDT5+mVZ8CTuNzEB43sghDZEVAbl
         GuEOSeUck4hfQI/eLuzb+yHYuzyzBmqQtIJg3L3vG/sljbi/4+qFtUxTdJKI0KH96KEi
         TzMm1b/vWjyQv5k0Jw4QSAJmf3pX76LjjsNMWScfF2gtaymPSFh5KP0qbR4WlhwtTN23
         gKtfWB9cxFiSeFO2pm1KGbusDa2o3f5gLB8iUlX/OoVShnoWsE8XRFBlaml5mp1RDKE0
         MkIQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=vw4Cn1B49wHVQb8AT0MF3vSRgxneSC4jxpenb2brYPw=;
        b=RjHQO9Uq5Wm2/1NcG96iH7h9f3EBcUcFxYbinMlzKGifXDMlqGzRw2LPMjOwEej8AO
         0aMk9tmz4t+f1D/kI1b5DuK952lU1znvvEsQWd2lh7KwWLaNESVDqYwm2PMKk+JzYrKX
         dt8WWyJUJorE9LRcaU3Eg+zOP65NUmtZRdhKEbKNj/gExXY6+sl5d75uWeSbyYB3866H
         RhvURhSsAnF+Ss0owMmjki/tHNj2GUn4mQwPFEmvpwDiphZQmX24Z2yNqhZZ05SwW6R8
         L8ejbEunXPAlZFVC2BXQWMagr383rT724kAI7WVqwqFXMH5lEUkfVIP4sQb6HQUTArmr
         hpig==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531Ob1Y0ZPWIJKurb2cIGPBnfWiOfHATnKiVAgVqXuKpybkOfpp0
	WYDnt8ccKCCnpQf6kn4YwiM=
X-Google-Smtp-Source: ABdhPJyC/orHc2IIlM5pgOuv2jY8LQGMMc2mooQdiD6UPo1d4lCbdYMPed8Kp7ccrl5+odyRRz0ERw==
X-Received: by 2002:a17:90a:3902:: with SMTP id y2mr10906470pjb.202.1616175675356;
        Fri, 19 Mar 2021 10:41:15 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:7246:: with SMTP id c6ls3234190pll.4.gmail; Fri, 19
 Mar 2021 10:41:14 -0700 (PDT)
X-Received: by 2002:a17:902:e54c:b029:e5:e7cf:d746 with SMTP id n12-20020a170902e54cb02900e5e7cfd746mr15569350plf.56.1616175674689;
        Fri, 19 Mar 2021 10:41:14 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1616175674; cv=none;
        d=google.com; s=arc-20160816;
        b=CvpxpEgohrZLcM8Uylv+NygHaOPlf5cKE9/5SRnm/vxwG23wEJzza3xTIqol5z3S6b
         ULRcLNigSr5aaM6DKJIDq0X3kWx3pJDb1MNqHUGK1546jmdipNjJ1Mg+QgZlBRGsqiBA
         gTwbTSJp2zrO3/8pRTXNienipX2TqbjEgOBgv+KAkWaAiezlI+zwq5RWpJ+APXvSoOYl
         PPBilfEhTUMLxFc2nZNui+2w+QsXEzG+XjVkeG3UuKGIduuBA52yotmjcQghBl2j+avG
         Zx43e5AM9jhDxWGiurdeAzN5U+U/KS0nwGn7Hrk/GPZBqttFxjj1dIjwjSGUDcoWs7+8
         lq/A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=GMGwhmsxHmLoKmaL66rRWhwajK/tyE+ZOo0YJ8PRsZ8=;
        b=eknfzUz4KIOiuUY0B7m6iUioZCba1Q4xVK267o/izh1Phxe4aIBFgiWw72vq/t4H98
         PAdkZukkUIeM9oUoJRmBsWXKGDfciRuOQBzeH94uzw8NMgQ2eXnTzbG4vfVCjdurZK6K
         arS/Ap7hrd/9FoQ2G7cQ6CYccdRkfEQjdqiXvgx+NWRfioAc8dW1Zrf6EihiAQEJMXxb
         soXA5Ocgjl/mhry40ADeO5Q583FFtTZTtyfA1AQjJKp0OExAvXfbz/JAXb7+6ljg/jM7
         1HFNjyqydGRSVcN/Ty1xkpUZUwYF9k193PYwNsaQFpiL648uXJa5osQgwagTk1cY2Q5k
         oUcg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id d2si205347pfr.4.2021.03.19.10.41.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 19 Mar 2021 10:41:14 -0700 (PDT)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id E8E2661925;
	Fri, 19 Mar 2021 17:41:10 +0000 (UTC)
Date: Fri, 19 Mar 2021 17:41:08 +0000
From: Catalin Marinas <catalin.marinas@arm.com>
To: Lecopzer Chen <lecopzer.chen@mediatek.com>
Cc: linux-kernel@vger.kernel.org, linux-mm@kvack.org,
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org,
	will@kernel.org, dan.j.williams@intel.com, aryabinin@virtuozzo.com,
	glider@google.com, dvyukov@google.com, akpm@linux-foundation.org,
	linux-mediatek@lists.infradead.org, yj.chiang@mediatek.com,
	ardb@kernel.org, andreyknvl@google.com, broonie@kernel.org,
	linux@roeck-us.net, rppt@kernel.org, tyhicks@linux.microsoft.com,
	robin.murphy@arm.com, vincenzo.frascino@arm.com,
	gustavoars@kernel.org, lecopzer@gmail.com
Subject: Re: [PATCH v3 0/5] arm64: kasan: support CONFIG_KASAN_VMALLOC
Message-ID: <20210319174108.GD6832@arm.com>
References: <20210206083552.24394-1-lecopzer.chen@mediatek.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20210206083552.24394-1-lecopzer.chen@mediatek.com>
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

Hi Lecopzer,

On Sat, Feb 06, 2021 at 04:35:47PM +0800, Lecopzer Chen wrote:
> Linux supports KAsan for VMALLOC since commit 3c5c3cfb9ef4da9
> ("kasan: support backing vmalloc space with real shadow memory")
> 
> Acroding to how x86 ported it [1], they early allocated p4d and pgd,
> but in arm64 I just simulate how KAsan supports MODULES_VADDR in arm64
> by not to populate the vmalloc area except for kimg address.

Do you plan an update to a newer kernel like 5.12-rc3?

> Signed-off-by: Lecopzer Chen <lecopzer.chen@mediatek.com>
> Acked-by: Andrey Konovalov <andreyknvl@google.com>
> Tested-by: Andrey Konovalov <andreyknvl@google.com>
> Tested-by: Ard Biesheuvel <ardb@kernel.org>

You could move these to individual patches rather than the cover letter,
assuming that they still stand after the changes you've made. Also note
that Andrey K no longer has the @google.com email address if you cc him
on future patches (replace it with @gmail.com).

Thanks.

-- 
Catalin

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210319174108.GD6832%40arm.com.
