Return-Path: <kasan-dev+bncBDDL3KWR4EBRBIEMYCAAMGQESH4NNNQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x937.google.com (mail-ua1-x937.google.com [IPv6:2607:f8b0:4864:20::937])
	by mail.lfdr.de (Postfix) with ESMTPS id BF0BC303C87
	for <lists+kasan-dev@lfdr.de>; Tue, 26 Jan 2021 13:08:01 +0100 (CET)
Received: by mail-ua1-x937.google.com with SMTP id a33sf6087527uae.7
        for <lists+kasan-dev@lfdr.de>; Tue, 26 Jan 2021 04:08:01 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1611662880; cv=pass;
        d=google.com; s=arc-20160816;
        b=DOwZbdrpScS6zTgZJgsIBGyVyy60BSrthN7xjbGKMgDWe1u60usq5MDnK91y+EQpyu
         qFGRsHx9Y+uORYbip1hemD2P+4UbToNkeR1stm0NqZyE86ko0JCxR66vnKTmzXM7lWHq
         zeb2odJtOQxOfbgXFTYcbTOalMCuwrs3g9q6IsDEXSFA+nxrtncr5s9ZJTPQ0naPx5B5
         i0dbpzxvx0cs38C4yvtGyMLm+/QsVF09FazvGmUYxu2QpxcvailT/NHNWW+68AIEzvI1
         KWUKcPPSfzI9QU18Pfjrz7oMI+6xV1FmYs39ioV/oGCZ/HquG/0WY4Th/7XVU/goLflQ
         q4Lw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=9V8H1AkRHgnpjgSxvpaf5496mXPwWVgR9zdY9yzGl2w=;
        b=v4BiLkDgYLIkkY+L4zkcWbweWdwsAmviH55MQA1SttgtqrFPnb2ZURcncxxCXUvSm4
         QPhPKA1jObP+86L6aKf37JkqDdpH2eVrWNdZ9oxDLmwZa2t3qrIAf2Oyn51tvC/pLwZh
         Pa5WMl++ns6vexlFVEeGmxvhLSGAQYSUrHK6UmjumakiIggWVSy2V7fXRJBCP1wwYr5s
         tFZ5yF3z8nHahiA9JtSZ8JfDdvApOn8oLFGB40QaG4xyIbV1WHelG4zAo4QuZpo8bD4q
         kVfCezFlw/KRXug5afKVxUnOSED52GvxcKL3wSFilVRHqQgB4TUH8+yx3bJoCOTGbAtO
         Ei9w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=9V8H1AkRHgnpjgSxvpaf5496mXPwWVgR9zdY9yzGl2w=;
        b=soxmZv0qyH/6B74XxA4Lz5L5OcPnTxtmsI4CabnUGd90DXf1JdlT1yp/3cczCZs45r
         Q10gBd1Uf3mBtnAbms9r3wjtvV9hkNtDQjxNpEnn3Yst1GRIunFW9kdDD3afD8wrwOaq
         QuMNqPnBpn769we2lcfyXIVZ3oaIoHFYxynrkxWlwug7l2DyZlgOoOfP5UdrH9hV2GPj
         MAC3EErZINpcW7vv/0cMcFg3hOZH6IaFD0k5ndp5QU9Q77tScEuU+ykGkUQckusPqfpG
         oPTSG8XowudRpenF03XaaxEIWfmesYvGA5CRtfhbc6XO2B1Q/2OcggLOMJDRUp26rjbe
         i7iQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=9V8H1AkRHgnpjgSxvpaf5496mXPwWVgR9zdY9yzGl2w=;
        b=Y+MtV08jrlkmdTNIMaUUJNE7G+2DBolmsx1J3Tbpbj44c+oTVPL5fxehOLR/TwKztq
         VxNoejs6jktwBB4kekd91Y0qB0glld5vkY8ty0uC1nVRvfXqbou9NajRc33DK0nx3/iO
         49gO0L+lrLS+soojoXmfotHGReaPHgaOz114h7tILCey4MDgupP2/Syng18Opse66TYW
         nCGiY2odi4w3ntWNP5TJsVk7QRrLbFaiI4Bmhh6U/jZjtFELCeHzs2i4/g9U1PRheOy5
         sSBSdmIQdVR40x7M2Ol3CkUEWKI8Z11SpQGP9hfJCGQnaQbTQpA2cN+y5Xz/ZWvPdYXu
         N+lw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531Hx1LTgcq/LFddzTG9sbF45py0D4/6IsyMx7ZXNpSC3O46gpSE
	GgGSb7gfl4NVg4qTbcPxY8M=
X-Google-Smtp-Source: ABdhPJzuzsFgAjCY+Lvk++RQ+ENmM2cMWRmzL7jHfBfPQrlJUImrOiamyb85N+v9CJCPYLN1OWmS3A==
X-Received: by 2002:a05:6102:2e5:: with SMTP id j5mr4010951vsj.29.1611662880553;
        Tue, 26 Jan 2021 04:08:00 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:f898:: with SMTP id h24ls1322937vso.5.gmail; Tue, 26 Jan
 2021 04:08:00 -0800 (PST)
X-Received: by 2002:a05:6102:808:: with SMTP id g8mr3989318vsb.0.1611662880067;
        Tue, 26 Jan 2021 04:08:00 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1611662880; cv=none;
        d=google.com; s=arc-20160816;
        b=fcwHv1UK0qYONhVdaHlJLYpzXsGBjE1TaZZq1hlVHDzbGSx3N61/w9U23mmwUfU7pT
         W2Rz14oEti7r3F0uup9OY0tw9UkkqtOIFtMzsyUj+qCjr+6+yyCZ3oeaH2tfvEapw7Ag
         oDn/qHUARosUbIIBU8yJA6FRAWOGaPR/2bHvihtzJLNeiR0EXHMFlz40/tA+rFf3p6XZ
         HWDFE4T3wBKDitC4cWNBHpxSv/fBqC/lobZ1FbrbaQbv1vMZTMu/yEBu8MyAkkIXyUJO
         iktLejW+6hGzZHptjGjA2BzWib3Eb6Z8XUtiqJ1KaSDJtDbn1SAeSieln5po/vDwuNMk
         W8vg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=ueq3rn1PbMNwpcO9slrRU4bozjlE03RKRKgjAo2kfQ4=;
        b=JaWQeWg5Ota5dVFXkQvqFrTg5Txu2EZEXY+ZokXW4Rw/VkOotWC2V6CUkMfG+BW1sO
         VauzOxiULKlSZPZgAL2XAfBDGtgoAIX327nSxlEzvUlXQ0jgoY85JzeYMomUdJADKyKe
         6fwy2K9vd6KW48HJn6ezPZQ83n0lN2/o8kdRp94GCLwjEVqiC8BYbsnX085vwkwZCv5/
         unfBogYVLR0u9O7+DCxoNxy2osagz1hL5y/6OjO5axyFmugCMDU4iDF+Yhmtx8ckNF34
         zqJUTS1Mw7ZjB3CJ/NvkFstORCQkpO1KL+pUb8v0uwB4f9UCmFWcfGgNh/oJQVjmtcpR
         KSvQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id e11si1103046vkp.4.2021.01.26.04.07.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 26 Jan 2021 04:08:00 -0800 (PST)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id D34212311D;
	Tue, 26 Jan 2021 12:07:56 +0000 (UTC)
Date: Tue, 26 Jan 2021 12:07:54 +0000
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
Message-ID: <20210126120754.GB20158@gaia>
References: <20210122155642.23187-1-vincenzo.frascino@arm.com>
 <20210122155642.23187-2-vincenzo.frascino@arm.com>
 <20210125130204.GA4565@C02TD0UTHF1T.local>
 <ddc0f9e2-f63e-9c34-f0a4-067d1c5d63b8@arm.com>
 <20210125145911.GG25360@gaia>
 <4bd1c01b-613c-787f-4363-c55a071f14ae@arm.com>
 <20210125175630.GK25360@gaia>
 <62348cb4-0b2e-e17a-d930-8d41dc4200d3@arm.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <62348cb4-0b2e-e17a-d930-8d41dc4200d3@arm.com>
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

On Tue, Jan 26, 2021 at 11:58:13AM +0000, Vincenzo Frascino wrote:
> On 1/25/21 5:56 PM, Catalin Marinas wrote:
> > On Mon, Jan 25, 2021 at 04:09:57PM +0000, Vincenzo Frascino wrote:
> >> On 1/25/21 2:59 PM, Catalin Marinas wrote:
> >>> On Mon, Jan 25, 2021 at 02:36:34PM +0000, Vincenzo Frascino wrote:
> >>>> On 1/25/21 1:02 PM, Mark Rutland wrote:
> >>>>> On Fri, Jan 22, 2021 at 03:56:40PM +0000, Vincenzo Frascino wrote:
> >>>>>> Currently, the __is_lm_address() check just masks out the top 12 bits
> >>>>>> of the address, but if they are 0, it still yields a true result.
> >>>>>> This has as a side effect that virt_addr_valid() returns true even for
> >>>>>> invalid virtual addresses (e.g. 0x0).
> >>>>>>
> >>>>>> Improve the detection checking that it's actually a kernel address
> >>>>>> starting at PAGE_OFFSET.
> >>>>>>
> >>>>>> Cc: Catalin Marinas <catalin.marinas@arm.com>
> >>>>>> Cc: Will Deacon <will@kernel.org>
> >>>>>> Suggested-by: Catalin Marinas <catalin.marinas@arm.com>
> >>>>>> Reviewed-by: Catalin Marinas <catalin.marinas@arm.com>
> >>>>>> Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
> >>>>>
> >>>>> Looking around, it seems that there are some existing uses of
> >>>>> virt_addr_valid() that expect it to reject addresses outside of the
> >>>>> TTBR1 range. For example, check_mem_type() in drivers/tee/optee/call.c.
> >>>>>
> >>>>> Given that, I think we need something that's easy to backport to stable.
> >>>>>
> >>>>
> >>>> I agree, I started looking at it this morning and I found cases even in the main
> >>>> allocators (slub and page_alloc) either then the one you mentioned.
> >>>>
> >>>>> This patch itself looks fine, but it's not going to backport very far,
> >>>>> so I suspect we might need to write a preparatory patch that adds an
> >>>>> explicit range check to virt_addr_valid() which can be trivially
> >>>>> backported.
> >>>>>
> >>>>
> >>>> I checked the old releases and I agree this is not back-portable as it stands.
> >>>> I propose therefore to add a preparatory patch with the check below:
> >>>>
> >>>> #define __is_ttrb1_address(addr)	((u64)(addr) >= PAGE_OFFSET && \
> >>>> 					(u64)(addr) < PAGE_END)
> >>>>
> >>>> If it works for you I am happy to take care of it and post a new version of my
> >>>> patches.
> >>>
> >>> I'm not entirely sure we need a preparatory patch. IIUC (it needs
> >>> checking), virt_addr_valid() was fine until 5.4, broken by commit
> >>> 14c127c957c1 ("arm64: mm: Flip kernel VA space"). Will addressed the
> >>> flip case in 68dd8ef32162 ("arm64: memory: Fix virt_addr_valid() using
> >>> __is_lm_address()") but this broke the <PAGE_OFFSET case. So in 5.4 a
> >>> NULL address is considered valid.
> >>>
> >>> Ard's commit f4693c2716b3 ("arm64: mm: extend linear region for 52-bit
> >>> VA configurations") changed the test to no longer rely on va_bits but
> >>> did not change the broken semantics.
> >>>
> >>> If Ard's change plus the fix proposed in this test works on 5.4, I'd say
> >>> we just merge this patch with the corresponding Cc stable and Fixes tags
> >>> and tweak it slightly when doing the backports as it wouldn't apply
> >>> cleanly. IOW, I wouldn't add another check to virt_addr_valid() as we
> >>> did not need one prior to 5.4.
> >>
> >> Thank you for the detailed analysis. I checked on 5.4 and it seems that Ard
> >> patch (not a clean backport) plus my proposed fix works correctly and solves the
> >> issue.
> > 
> > I didn't mean the backport of the whole commit f4693c2716b3 as it
> > probably has other dependencies, just the __is_lm_address() change in
> > that patch.
> 
> Then call it preparatory patch ;)

It's preparatory only for the stable backports, not for current
mainline. But I'd rather change the upstream patch when backporting to
apply cleanly, no need for a preparatory stable patch.

-- 
Catalin

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210126120754.GB20158%40gaia.
