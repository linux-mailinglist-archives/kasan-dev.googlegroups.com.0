Return-Path: <kasan-dev+bncBDDL3KWR4EBRBDODSD6QKGQE2WRRPMA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x539.google.com (mail-pg1-x539.google.com [IPv6:2607:f8b0:4864:20::539])
	by mail.lfdr.de (Postfix) with ESMTPS id A2E552A82E0
	for <lists+kasan-dev@lfdr.de>; Thu,  5 Nov 2020 17:00:14 +0100 (CET)
Received: by mail-pg1-x539.google.com with SMTP id 33sf1510500pgt.9
        for <lists+kasan-dev@lfdr.de>; Thu, 05 Nov 2020 08:00:14 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1604592013; cv=pass;
        d=google.com; s=arc-20160816;
        b=0/Uuhm8xAjPa3OKwvwDknXo3v5B08j6NP2xQQJzsXqepkm4djYTIRpQnbidOTIDKhL
         FXB3/m4K4fpKxQZWStxRsNTyoujYu6BTMlW4HDk2h37q9qppSlYu+uzq0Gr+TS+PRU3k
         qVwrWQ/2/wE/5Fbg4QXbDGPd202Kc/owM0UA5yqkFQUYCU4HGiW33S02JY3yTBFtU3X7
         FO5OVFg86fBndtJJfQiXgrQRB8tLt83oKaaJkmkuyyuZ1FOF4mcblMjEjlAk9Mzv8fF2
         WjIBAATuDj3DcV1C1DCqW4N5fvfpq2P85vNuFfhp4/9voun9NqeN6IH76aG4HN7GnhnK
         btdA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=tnrF6Q7q9X8mZuIjWc46DO2TQx4ck4OkMHbcTNvPyGA=;
        b=oRoXy/BE6IE+khjMV1uzh0LQMcS6wCcpn3T4W/yqKmXYitow7q+o+sN6Ml43mZOJ4E
         xfNVX5TAjSE1C4KJHuTV1I5U+0Lt/bZwdE2fzDELd1TqxwD5ju/ZONd6D27j1da8qJde
         E+o9AbmJ5OZU0Mpk4uMy64qH6LTboNKgKa4MbMuzherQzvY8kWroYoh4cqU7ZzKevvFF
         kfqbq+BzgRNjHHlXfzEvsVA3Aj/rR8pbgPO7XuCRtdRsp9HJ/BUnqF99zcGXsdnqHyVI
         eVDv0ddd7FGPtkdGGuiwcLHhxXM00d9DyhkRzLOXbu12jVdUR6WRYTXpGq18aUiRclze
         cSnA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=tnrF6Q7q9X8mZuIjWc46DO2TQx4ck4OkMHbcTNvPyGA=;
        b=oQu16Dqv5PEVpihnObLsET6gjcPk9lbpu5ErTyUVZoGpnJM5ijgj+7IR5/lr0E4wWj
         KkPrA6V6JqRl3iq7Go/O5V3f3NPR2OuFKF8W1bocMHmUhiryl6DEf3SZ7u4XcG5Vel4S
         s8rBITmpPBAITOSY4PvIV6zCvhN9xjEujbVn5ZtbBIvIzfRxffi/CryRkhdqoMlgWYEN
         V/s0QWIy3oETT51NhyugMv0mgdbrrB1rAeJirHRkp1kmXK/cl6hJkSIAadIHxjvbAv6Q
         qfCb2a5NeqQvuln69hFQsUdyeSikf20LNfH5OxdusitMfhI/YQiZPdzkp7mDETxC3gVD
         C4nw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=tnrF6Q7q9X8mZuIjWc46DO2TQx4ck4OkMHbcTNvPyGA=;
        b=DQzhlrkEklHCY8iWhisT6X1Lb/M3aTHxbMrJvgn6gCgpAJ21Ub+UfUzfZgGsgafpGo
         jc1tVNSE0FVDf88LT7idRjdjHofLggnTyK90CbU1yceosyRnI1hnd3mmEzPj0baE31mM
         9rNHuBnwlDzYBHna+QstVQHA58+FZ+g9/+bU+J4mPyFwvXt44HEeBJ0cXzgmN2tSxY20
         l+CO9KJQQKP8GJhyOBmYWLD83wSYZvj8dDwkFW8BIFPvjSkuaGUl0AAq8gW4Uk9OP/Au
         lzN1hKP88Waz73W2Rq+4RfErvyPz18y1/mtzW0ZL7SI5DOFAQXAgVVMSBPa9RkPFDo2Z
         AkNg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532XAOBtc1M6hZK+DdheL9IQ7meF8xo5WvfhndVTixhrpTnf9Liu
	Lbk9FgR/hutHEqrdJHWqlgg=
X-Google-Smtp-Source: ABdhPJyEvQ1nlBYIH8l6zNlYu39/TC3tX0rXlNOWV/zICeJJItQrOyUEfX6IuOcxrcFOdh7s4yyCiw==
X-Received: by 2002:a63:6484:: with SMTP id y126mr3083786pgb.320.1604592013270;
        Thu, 05 Nov 2020 08:00:13 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:8d98:: with SMTP id v24ls920201plo.4.gmail; Thu, 05
 Nov 2020 08:00:12 -0800 (PST)
X-Received: by 2002:a17:902:9f85:b029:d6:e802:75b0 with SMTP id g5-20020a1709029f85b02900d6e80275b0mr3106371plq.29.1604592012648;
        Thu, 05 Nov 2020 08:00:12 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1604592012; cv=none;
        d=google.com; s=arc-20160816;
        b=MMYgum/wMZwUbI42gTR99db1cXasJyRu+tUkqCMuKwd2H7lWr+AzrjqlvRSA0lZKM7
         hSweH3TyBO2MXEwQ+3dt3Zzd2nN2P8S3aKoFAvzvuPvhh/fMF9nSfow5Scgo3urP0+oE
         c9qZyuAwXEX2zWcjiv5bqF88L81NBCuVWOoYXUV+Csp2qXLuMVN0rouDEyiU67l/y1PO
         jq2L7QOUr3sxoC2om9B92K6eI9Mt72LWuvxVJzm/ln61KNL6S2U+5+4v/hDy/SBjKdEz
         LgXmn96Fi6geLMiAZHQDhhWgLxmZmeISVMQL7suQCnrpFEUaBDdZBkQMTGj8uSOpIneq
         ezcA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=+cg8N50Dvt+5vPPeg1KN8X41MfH4Lx6IOlQ1hGnWtDg=;
        b=x7dXuWQlWWBZulPvitRi220x/bU7KdYPPjEMAzsaOXWmWuXViwQ1fMeZF+G0xrvsRs
         mQE8kN+dRsHF796MouiDGtncbsFKUmhGtix/o9rzCc5Hs0KISw+EPaPZ6rEtoQRSRqQw
         950bWD9xZ9sUPLz95Dm3YRQEvb/2OO75neHQ6zrWOM8plZ1BZkkf/DKehYMdMCw2O/hk
         fEfJ0lCEoCQ42xZbzejVTqsGtZHA0OwlVc2cWosfyE0I4O+1MJOl7FsoaqzW5HyXXp6u
         tGY/I1Ub4pLg/JSpRW15K96joLX6Xjp/843sSbPYtW7VcdG3ujnkxNRQ9Bb9KzY8CsMb
         F4MQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id cc22si121193pjb.0.2020.11.05.08.00.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 05 Nov 2020 08:00:12 -0800 (PST)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from gaia (unknown [2.26.170.190])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 96C752087D;
	Thu,  5 Nov 2020 16:00:08 +0000 (UTC)
Date: Thu, 5 Nov 2020 16:00:05 +0000
From: Catalin Marinas <catalin.marinas@arm.com>
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Will Deacon <will.deacon@arm.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Kevin Brodsky <kevin.brodsky@arm.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org,
	linux-mm@kvack.org, linux-kernel@vger.kernel.org
Subject: Re: [PATCH v8 18/43] kasan, arm64: rename kasan_init_tags and mark
 as __init
Message-ID: <20201105160004.GC30030@gaia>
References: <cover.1604531793.git.andreyknvl@google.com>
 <f931d074bccbdf96ad91a34392d009fece081f59.1604531793.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <f931d074bccbdf96ad91a34392d009fece081f59.1604531793.git.andreyknvl@google.com>
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

On Thu, Nov 05, 2020 at 12:18:33AM +0100, Andrey Konovalov wrote:
> Rename kasan_init_tags() to kasan_init_sw_tags() as the upcoming hardware
> tag-based KASAN mode will have its own initialization routine.
> Also similarly to kasan_init() mark kasan_init_tags() as __init.
> 
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

Reviewed-by: Catalin Marinas <catalin.marinas@arm.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201105160004.GC30030%40gaia.
