Return-Path: <kasan-dev+bncBDV37XP3XYDRBG4EXSAAMGQE4WLFD7Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x237.google.com (mail-oi1-x237.google.com [IPv6:2607:f8b0:4864:20::237])
	by mail.lfdr.de (Postfix) with ESMTPS id 93A40302911
	for <lists+kasan-dev@lfdr.de>; Mon, 25 Jan 2021 18:38:36 +0100 (CET)
Received: by mail-oi1-x237.google.com with SMTP id l13sf5739857oil.20
        for <lists+kasan-dev@lfdr.de>; Mon, 25 Jan 2021 09:38:36 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1611596315; cv=pass;
        d=google.com; s=arc-20160816;
        b=uRNKoASDXdJgj4imY5mGD9LSj5Xx64Wd41hLKPEFFAHTqby5dncdI9dAh/WNFRwCSV
         +wSWHyl+rAW+o3HqpujCKhFGKl+mlNpeAEPcU+bkZRRLy8PzrIKHKglb7198mG8Pr+Xe
         MMtKd23ltwW8CTvrfBOSczlgWm8hTfKVXeVqwfUK3Ridxf/olksfK5yzjSaAMXMqBIPZ
         jq7wNn4OD9+wPXDhXSeoZSqMogDmYr+DaUxdWz+q4WOHM14yyP3pLGMQEVHvmXtnyLqj
         Zu3RRKzZUw2kMsJwmHp9j7jIpLjBRzmgYeL3XC0lenmYUNfxQPZO6Il1o+E5H2p+h8XS
         RAsQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=ROyP17qIcVVY9nQE+U6Y3nMG67+iboNsg/9bvV0mnUU=;
        b=U5IeZhE6xgRpdoSSpo4yzzhAHpnI7HGmFf7poQDUSUfo6R8SeOI+7us4ghmabe4k7K
         1Hu7F0/7uaBT3gA6pcdE0sGaHNuVhQ743ZiAWyYCZ090dFLm8hKPUUin/5SaUrLAYfri
         d025O8OV8yIlijdLkVh7ERDgyDeqzMjkobwfl0/WvwFF8PrXov/K775gd8KFYoJKV+0q
         UmCahhEq/Pi+7yu2gHGchXi4Y7Vi4HFDTftSNHkvo91eo5ZOKodb1ahZ2hiGhdUMvoM3
         20AQeQKn8PK3EzV8lXCsyeoS7NuSaIWcrowMdIBp+3tt7dFBa75wmWkwKho5Za8MZTo2
         x+Vw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=ROyP17qIcVVY9nQE+U6Y3nMG67+iboNsg/9bvV0mnUU=;
        b=gUxGMZeHbmdSvp6jtmdhNAIgFOqZ6eBCC38vG6k1wkre/WvrmbHEwWgStIlul4/FhS
         U5kECG9KH2LBGg7Fi6QdbIppVb30PgR3bTvD1jpRJ5CtcjmJfh+uCidoVsACGw3QH7UT
         nQ0Xnb4U3FftLL6+TkZ6Tg+hwnY9GJ+f1jOuz7oePlqS3dh/7hdDKrAKZFKPKTeraZE9
         L9BUoOev91lSQ0AERrjf4o3Mj3G4ZooiRBZdw6ap4KFiQvz6K0VPlrPOjEdGuuaLnkeB
         mdB3oyGNG+ZL9w+cDK/aoyrF5EvpDEtkPVm2RCqkJO9ekKLlxX37MrBbAuOVXy49KNWM
         4kjw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=ROyP17qIcVVY9nQE+U6Y3nMG67+iboNsg/9bvV0mnUU=;
        b=nDnMPZO/8iojklpeFEbbxUebAx+l+8NCaR6AM1XPVlFOHoIF0SdNeeVo3DjkskodT3
         5lBKC2N/ac4d5j6O3P6HsY9Bu+RaGa3zJZTe/FfhEUS/RKo9jxYB6M5t0PYWMIquvYfb
         tkqPj2nVxhhPLsRgxnkK5Vg9HszYnqDDmnyZ8HUIbNzj0IK/Q8HTKdFQzao/+EiKowU7
         MreY17vnH0s/P+I7ng97s+zMCSzaTEUDIsWWrV5lJy9/dWh8Zm9FA2v1jHlD783d/cC0
         RpXp3iZqnl8JN6nSHV7MqrZ+YeajW5Lv2N4a7LASL5iX20cawuka/tRsiiYJeKupjd2s
         mYTA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531U7OwZJnkYVpSwVM8014APCKu642vkmLOpSr4wArTeHsSQDbr5
	qhzApXbrh3+zOZ4E8nHRYio=
X-Google-Smtp-Source: ABdhPJwE5SpUO/eIhznhWN5Mlisl6/VH0HPxiZJehV8fKMWv390M89QvIGgPj11HMFVTCtI9pUuZRw==
X-Received: by 2002:a9d:6a1:: with SMTP id 30mr1200161otx.242.1611596315617;
        Mon, 25 Jan 2021 09:38:35 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:1105:: with SMTP id 5ls1091796oir.7.gmail; Mon, 25 Jan
 2021 09:38:35 -0800 (PST)
X-Received: by 2002:aca:eac1:: with SMTP id i184mr806467oih.43.1611596315107;
        Mon, 25 Jan 2021 09:38:35 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1611596315; cv=none;
        d=google.com; s=arc-20160816;
        b=vlprOILWV+Dc6uOlZfHqeHNFvWRnhgDnEQdKzYNPpQy99ceXcCHJHZcoYARdIjpzy/
         UVtggyzqcgJFrtFJPhwsNVTKB8rtt7uxAbcj+B0aIm3WZK1NVElB/Tbb5NXLk1c3PNQD
         79rx5tZm6Hfisnp8HRLUrtSlvCUQ85AMWh47DFqr/d9PfLj5Bor/BaVCB9aTWHlz+0Nd
         61bl3mFNTGrPrRW8tPFq4rY+TFO5X+32nT19RmRHnUVE1u4EInOdt2BCdFUlqE6Z3XhR
         0ASzH3dsLD4NmMhsq6afARFcUd1MF0PYPMMb1Ort7aHjaHzXCdbM0oKXaIekDw7xKIYo
         CPwA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date;
        bh=TGzE9dPa8Y0bUsnkneEXRlouOO1uwi0jc0tuInEhNZA=;
        b=h3BieLnqyKkw5rOcM+osaBvE8QWJTq8AWh+U7VxY6qTNuaqb5BFDINdl0Gg7Im65ls
         ETDQ0gXe/Heck2KUWd3uhcbOU7AxwVANqjkYB3ajfv+FY49KGBYh6iH3iNVowmCI5e0Z
         LtfGFW/uyDTYoTbsk83DVFmzD/+GIPixlkx0Up4yqaq4NcKtoO1Kn4iLySO4c7qcKvOv
         YXy8+NJkLVqnbx4VV+0HJLcobXBoqrDIjnHuKOANvLk9US8lrdleF6X7ooup9ZVKvLC9
         UsJawLxOEuvUJqj8pqnKOfSB+MC0hyn0lO4RA2nrODZbX6AXsBW3J6QanfdPJjsILOjY
         HFqw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id j1si128959oob.0.2021.01.25.09.38.35
        for <kasan-dev@googlegroups.com>;
        Mon, 25 Jan 2021 09:38:35 -0800 (PST)
Received-SPF: pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id DB78E1063;
	Mon, 25 Jan 2021 09:38:34 -0800 (PST)
Received: from C02TD0UTHF1T.local (unknown [10.57.45.22])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 021DC3F68F;
	Mon, 25 Jan 2021 09:38:31 -0800 (PST)
Date: Mon, 25 Jan 2021 17:38:29 +0000
From: Mark Rutland <mark.rutland@arm.com>
To: Catalin Marinas <catalin.marinas@arm.com>
Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>,
	linux-arm-kernel@lists.infradead.org, linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Leon Romanovsky <leonro@mellanox.com>,
	Andrey Konovalov <andreyknvl@google.com>,
	Will Deacon <will@kernel.org>,
	"Paul E . McKenney" <paulmck@kernel.org>,
	Naresh Kamboju <naresh.kamboju@linaro.org>
Subject: Re: [PATCH v4 1/3] arm64: Improve kernel address detection of
 __is_lm_address()
Message-ID: <20210125173829.GB4565@C02TD0UTHF1T.local>
References: <20210122155642.23187-1-vincenzo.frascino@arm.com>
 <20210122155642.23187-2-vincenzo.frascino@arm.com>
 <20210125130204.GA4565@C02TD0UTHF1T.local>
 <ddc0f9e2-f63e-9c34-f0a4-067d1c5d63b8@arm.com>
 <20210125145911.GG25360@gaia>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20210125145911.GG25360@gaia>
X-Original-Sender: mark.rutland@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as
 permitted sender) smtp.mailfrom=mark.rutland@arm.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=arm.com
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

On Mon, Jan 25, 2021 at 02:59:12PM +0000, Catalin Marinas wrote:
> On Mon, Jan 25, 2021 at 02:36:34PM +0000, Vincenzo Frascino wrote:
> > On 1/25/21 1:02 PM, Mark Rutland wrote:
> > > On Fri, Jan 22, 2021 at 03:56:40PM +0000, Vincenzo Frascino wrote:
> > > This patch itself looks fine, but it's not going to backport very far,
> > > so I suspect we might need to write a preparatory patch that adds an
> > > explicit range check to virt_addr_valid() which can be trivially
> > > backported.
> > 
> > I checked the old releases and I agree this is not back-portable as it stands.
> > I propose therefore to add a preparatory patch with the check below:
> > 
> > #define __is_ttrb1_address(addr)	((u64)(addr) >= PAGE_OFFSET && \
> > 
> > If it works for you I am happy to take care of it and post a new version of my
> > patches.
> 
> I'm not entirely sure we need a preparatory patch. IIUC (it needs
> checking), virt_addr_valid() was fine until 5.4, broken by commit
> 14c127c957c1 ("arm64: mm: Flip kernel VA space").

Ah, so it was; thanks for digging into the history!

> Will addressed the
> flip case in 68dd8ef32162 ("arm64: memory: Fix virt_addr_valid() using
> __is_lm_address()") but this broke the <PAGE_OFFSET case. So in 5.4 a
> NULL address is considered valid.
> 
> Ard's commit f4693c2716b3 ("arm64: mm: extend linear region for 52-bit
> VA configurations") changed the test to no longer rely on va_bits but
> did not change the broken semantics.
> 
> If Ard's change plus the fix proposed in this test works on 5.4, I'd say
> we just merge this patch with the corresponding Cc stable and Fixes tags
> and tweak it slightly when doing the backports as it wouldn't apply
> cleanly. IOW, I wouldn't add another check to virt_addr_valid() as we
> did not need one prior to 5.4.

That makes sense to me; sorry for the noise!

Thanks,
Mark.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210125173829.GB4565%40C02TD0UTHF1T.local.
