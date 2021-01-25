Return-Path: <kasan-dev+bncBDDL3KWR4EBRBRNZXOAAMGQEH2K4F4Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x639.google.com (mail-pl1-x639.google.com [IPv6:2607:f8b0:4864:20::639])
	by mail.lfdr.de (Postfix) with ESMTPS id 2A419302693
	for <lists+kasan-dev@lfdr.de>; Mon, 25 Jan 2021 15:59:19 +0100 (CET)
Received: by mail-pl1-x639.google.com with SMTP id v19sf7752313plg.1
        for <lists+kasan-dev@lfdr.de>; Mon, 25 Jan 2021 06:59:19 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1611586758; cv=pass;
        d=google.com; s=arc-20160816;
        b=mlkoI3c6B86UwiXFcWj9d9yM/2vPv2ixshRAtRLgnJacOihJtEkGU1Jqr7YEPNUO7h
         zKnpqmnAvCN4zN0BaWov5zN7lP1NUrY6vmpkEEXXxBxYA9yMrPw4fwcZc5sdCVFCRODE
         yS2/dukRrkMWAb2VH+TXXbfuXI6wigpt6G1Fj6EUkqnQDCIfK9T3i2O70xXag48o46vw
         3RyYIHTMuCMTt67toqMTPXvLFhI9OYF+67h3RrH0qvodzlapaaUIoBiHfrb0hhAkkD7h
         gmN1QT79dy34ovug6soB19S5vjhe0S+vZ+Mzf5WbJ8YCxfv0Z6va4rp45rD7/ABTmKzn
         L0ww==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=myISSpzGPcY2fIsfeMasHKcq/oR/N6AujyQ5Eb3rPWI=;
        b=i1lVU6v3EyIRJYTpyI/YpI7ENYR+KjE0uMThYyu6sEQnwhgIMCm7X2oZdhaIiR7STv
         +PtVhD5scNAx4s9taclflQ6vhDBOJOBcoWxBaetTtv5iWXmzDF38+qBRhZBK8osJEy1Z
         hzG3DFwu/mlfBrPErBmslCMvuBNzaCGQlwE5Mygalq9ATGsMWloJfBzmeugG4DYSTiqe
         bnQrTM3cIMhFTl7Gn3bonZw1Gc1YYKC/cprY8Bde6tt1DfV0V+/Bf+UhJqI3HRpMdEAS
         Rn/IHcSL142OclIvDRhQMBFf2cMIo6T8I5hCAW2yllvTwS63ytaMiZZfEtq6cBxKQTkL
         Dpww==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=myISSpzGPcY2fIsfeMasHKcq/oR/N6AujyQ5Eb3rPWI=;
        b=qyYTx3G0VAXdL9oJpQwK0XVX5sgmLmrEFuJDVW/CgAw22NtM30iqho44JGtbaPLRyM
         I3y8WULGRcAun7xQ6nlF5cWgPJl92xP+2zwiuwpUVPAG48POUeZ3N5PDLDJvZKJz2XKj
         kopU5xLgeHyA+I5X9xJ5dll+DFMi/76KPcFChVD3BJ9adRTfzbQ1F+dn71aiZDXpaqEr
         1C/L1lPbWHTXKgWBua9XybZZICfIldjtTA8Hg+F8jyC440TIsqVvjlXO3FVMIjMx71Hg
         DUlVd+4DU98wH+fnWPSb/rLJFVZIvKiaFAFdXXNkSIG3gzdRGPGtXKEnJPaHFYLOlGwq
         YgyQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=myISSpzGPcY2fIsfeMasHKcq/oR/N6AujyQ5Eb3rPWI=;
        b=EKI+5o0PT9pALl0bhkbBnhIkcNuUNRx/o69wQesx3LOOY6wdU70IKgg/5EOcEzSP3C
         rCXUEbya904NTIJ/+OlTFiBSeLOKIRvzmrvIpg3DkMZz5KMm738/iDIWrSyeii9GvXSe
         DObNDfaLr8LxqcZN6lVVIe2QYck2pnTALjefqVsGk8jGn+fpi3UZbR0FviiAnKhjXfrY
         aPcnhY+31uuVZEqP8eplkmYa41Yh7K5kvY9w4vqsP6rpAukghX1WGKfzkbBdfy7bYnfv
         8oQRtqQcMQlraPYOcfmFhERubp5E5nsMZAY+lNtAAcfscmvLTb8WDFqmznc7qnPvINu8
         e7ug==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532XJkIC7ejlvrIFiUdREBQsdmcgN3A7s4W+6Kc+y/TjRDNy0Fu1
	pPj6FjAhNyn1gT5BYiBqK+k=
X-Google-Smtp-Source: ABdhPJwXfXd1E1+4987ovysZHIprvKSm1ZBoHuLV05LRR+eMDw76l3o54PLVv6xPnEa5Swgt9LpMPA==
X-Received: by 2002:a17:90a:f181:: with SMTP id bv1mr579897pjb.57.1611586757915;
        Mon, 25 Jan 2021 06:59:17 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:cd09:: with SMTP id i9ls1631663pgg.10.gmail; Mon, 25 Jan
 2021 06:59:17 -0800 (PST)
X-Received: by 2002:a65:6547:: with SMTP id a7mr1022405pgw.50.1611586757256;
        Mon, 25 Jan 2021 06:59:17 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1611586757; cv=none;
        d=google.com; s=arc-20160816;
        b=d2dzb5yFI+58UNbOULxqTlPy4KkPrasN/hcsfk7BKRsumiRgcHZTK7hEgIZQv3P9SD
         QpkPvYPjtJ7Ho0N405cglWnchmkzfdoZpmT3BWyQFWeOkIkZ4h1M2BuLYdmvxsYf/e3U
         RfFO+NbsG5lDZ6zMTiys1IDXCaqXsueNG502NzEkMUgODj4YM5GNiX10IWKQuetF2S4B
         D37sxtk4jojWHiTMTkW3hzffGShRuaQAkdBa/2UjGd0RMjeBfKQ2vUcZXjIXNH5LzEFF
         MIfOMJQ3uwLsNn6MKdVYaOWLI6tUCOu6Wuskdr2wbYlF58HzvWDj1p6rqhBS9pyUsHeW
         v3Sw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=Ag+PXq6nUYIEjcLESALYvCOEM7BnCVGTBCLmDzSDsLk=;
        b=WUUBeb9VbpryYDigvOkD4Ss4uyZ3DHJGQSwZCq7JX/cZ94lGGne5YpwsyUHokxckha
         LScLKpKxm8EzM8mTubQ20GaqDTajU2Np8Tbt4JrpRM5BmTDdT5A57Cyuxm3qUeEAR233
         qoZhIOk8+H0vlzcsOQn+ZfbfASmCuISbOD502IOoH68xwbMnEm6Epg892dU2j2j7XaEt
         Xy/Gir/7lGV3EqGWt1rVKaCR228e9TXwUrM/R6oPYJyzZoeyCoDpf/3SHIQukEEW4IDM
         YOZ3qeaCGk5h2prTPxXPWMn7QQUlaEQ6+/ugg/N6WL4JdBRQ2lFI2+uCXaR9vTi3m7fC
         1/zw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id n3si327952plx.5.2021.01.25.06.59.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 25 Jan 2021 06:59:17 -0800 (PST)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id E1BA622ADF;
	Mon, 25 Jan 2021 14:59:14 +0000 (UTC)
Date: Mon, 25 Jan 2021 14:59:12 +0000
From: Catalin Marinas <catalin.marinas@arm.com>
To: Vincenzo Frascino <vincenzo.frascino@arm.com>
Cc: Mark Rutland <mark.rutland@arm.com>,
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
Message-ID: <20210125145911.GG25360@gaia>
References: <20210122155642.23187-1-vincenzo.frascino@arm.com>
 <20210122155642.23187-2-vincenzo.frascino@arm.com>
 <20210125130204.GA4565@C02TD0UTHF1T.local>
 <ddc0f9e2-f63e-9c34-f0a4-067d1c5d63b8@arm.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <ddc0f9e2-f63e-9c34-f0a4-067d1c5d63b8@arm.com>
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

On Mon, Jan 25, 2021 at 02:36:34PM +0000, Vincenzo Frascino wrote:
> On 1/25/21 1:02 PM, Mark Rutland wrote:
> > On Fri, Jan 22, 2021 at 03:56:40PM +0000, Vincenzo Frascino wrote:
> >> Currently, the __is_lm_address() check just masks out the top 12 bits
> >> of the address, but if they are 0, it still yields a true result.
> >> This has as a side effect that virt_addr_valid() returns true even for
> >> invalid virtual addresses (e.g. 0x0).
> >>
> >> Improve the detection checking that it's actually a kernel address
> >> starting at PAGE_OFFSET.
> >>
> >> Cc: Catalin Marinas <catalin.marinas@arm.com>
> >> Cc: Will Deacon <will@kernel.org>
> >> Suggested-by: Catalin Marinas <catalin.marinas@arm.com>
> >> Reviewed-by: Catalin Marinas <catalin.marinas@arm.com>
> >> Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
> > 
> > Looking around, it seems that there are some existing uses of
> > virt_addr_valid() that expect it to reject addresses outside of the
> > TTBR1 range. For example, check_mem_type() in drivers/tee/optee/call.c.
> > 
> > Given that, I think we need something that's easy to backport to stable.
> > 
> 
> I agree, I started looking at it this morning and I found cases even in the main
> allocators (slub and page_alloc) either then the one you mentioned.
> 
> > This patch itself looks fine, but it's not going to backport very far,
> > so I suspect we might need to write a preparatory patch that adds an
> > explicit range check to virt_addr_valid() which can be trivially
> > backported.
> > 
> 
> I checked the old releases and I agree this is not back-portable as it stands.
> I propose therefore to add a preparatory patch with the check below:
> 
> #define __is_ttrb1_address(addr)	((u64)(addr) >= PAGE_OFFSET && \
> 					(u64)(addr) < PAGE_END)
> 
> If it works for you I am happy to take care of it and post a new version of my
> patches.

I'm not entirely sure we need a preparatory patch. IIUC (it needs
checking), virt_addr_valid() was fine until 5.4, broken by commit
14c127c957c1 ("arm64: mm: Flip kernel VA space"). Will addressed the
flip case in 68dd8ef32162 ("arm64: memory: Fix virt_addr_valid() using
__is_lm_address()") but this broke the <PAGE_OFFSET case. So in 5.4 a
NULL address is considered valid.

Ard's commit f4693c2716b3 ("arm64: mm: extend linear region for 52-bit
VA configurations") changed the test to no longer rely on va_bits but
did not change the broken semantics.

If Ard's change plus the fix proposed in this test works on 5.4, I'd say
we just merge this patch with the corresponding Cc stable and Fixes tags
and tweak it slightly when doing the backports as it wouldn't apply
cleanly. IOW, I wouldn't add another check to virt_addr_valid() as we
did not need one prior to 5.4.

-- 
Catalin

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210125145911.GG25360%40gaia.
