Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBH4NYCAAMGQEKYQQGWQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83d.google.com (mail-qt1-x83d.google.com [IPv6:2607:f8b0:4864:20::83d])
	by mail.lfdr.de (Postfix) with ESMTPS id D9E19303C95
	for <lists+kasan-dev@lfdr.de>; Tue, 26 Jan 2021 13:10:08 +0100 (CET)
Received: by mail-qt1-x83d.google.com with SMTP id j14sf9111451qtv.3
        for <lists+kasan-dev@lfdr.de>; Tue, 26 Jan 2021 04:10:08 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1611663007; cv=pass;
        d=google.com; s=arc-20160816;
        b=hRA7SHHtM46iMelz3pSJjUt5OITmgK3HsZiGMrtBBrfq0JirJg2nXeoxmTPwNgMu9M
         p3IHn6y4fEdKxYvxCHaN84JI9ZhYoPWglvL/vY8Y+QctrQ5es6wyF669SpH64ZOYjQpH
         ohfB6+ghEU7cdSk7V5JYwedVXul+YC5RRfej/dP5/PTn0uQsiJQlxJJFKHICpnexH9mP
         pqrX8T4es6C6Dse5grKhVYKBihH2fmCvVi3gn+kEzoQmeCfDb3VAUpcs2g9VFLb5nQGZ
         an48+5jjveQht0+4Pt2btkABbR+bTxQREuhdrghMNdrr7QVw5yQdhj4zK8DTCuv8aZra
         x6xA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=quAtQZin99W7Eyx/uq/fX784DPyVLq6cvs39r0c9+3U=;
        b=otOTHgMNxrKsmIwqREesRCuSTxEhK5bk0EHJeE5WuV43RBiSVzra5fD69n029xix84
         oVULyEdYIEE2LC88UgcSRUYmYk3fSeV7gx7RV3yXAeIejjHQXr+fN6tw2+jrcF+vEqjP
         72TPSyW7J7NVkXBiWWwHNV2cUMUpWXeBO7xIVDk924layki6GN+g+LDbu/piwGrOBuxi
         daCuK0ZQ7L0nq6NKggiQteQxGiAIKkKN8ONGyBsR5OjynGolc9+Bw8okQhhz/RQWyVAy
         2goJSQj6CImBsd2F4Z0LINPgEKl4bajG/YZ9i4dKXC1AItmMtIRCFYqCJm653YoOe2+a
         iLYQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=quAtQZin99W7Eyx/uq/fX784DPyVLq6cvs39r0c9+3U=;
        b=kQGK5lPgCmvJBLlpaySckBzCy0Q0jLJf1VQcaYQTISzvMhmddHAsjcUGUOvDKRCSQa
         KOXgTdwcwgUlC0CoBBXE/fWDyoIzmoNSBWEELG47Y9M74GbntfMzvw4BZTRYJR+VYLfT
         /HX7QRydya/s+IvcizwsU2PXiBQL+fNM2GHwDd57P7uoSIOag/Czlv4P7GSrZJIIvk5A
         LtQm2UO7xJhfs9YGULFvhYpKl3uTwaMFuzrpUI1Hq2zPG0/q99FioDiWNUzdsz5cs1uk
         ezGeTSw6XqXGTxZrd0tEkMVG9n7BdAnF5Xii4mzaq+/lYRAJXOf/D1ypmWkD3YYpoDDS
         hTRg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=quAtQZin99W7Eyx/uq/fX784DPyVLq6cvs39r0c9+3U=;
        b=LsVCy7Bar+nacx18rbpiM3YRWaMxbxSzNcbMTVGoDeTUfe4vOvUJ2YMPCv8Zuv/kFe
         1a1qI6TpjCqHSyMnTMroHci++HIk8K1o3n1Jd42eJh79B4EMDn2X1d6qaLQZMpo8Hx/p
         66OLxS7Q4goFcEW2jf5V+F9hQZ5OsiuzL47v8VzTnv33I+Is9c0iWNjhxkzj2wTbPOiX
         kC1YuwFbyOQhon3Phv7XjOpb75islYSxznihWEtq2H7m/odGD8z0nceFRQml39EjTrVy
         g8OiKxNHeGyNFwRpQrGzx39LnIfBkRr4deOks3Nptkg+KWbYRkBqqVdhNT9k2yPwQb7U
         eTLA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533vcGqLEP/JKbHAnEsk5esMsmBJutPv9Q0VSNAAOV+LF1/Lxsup
	xwWg464dbK/ictiDqPmpjxY=
X-Google-Smtp-Source: ABdhPJzfEwTHl9zrmVO9yPS0Whrj7prkiSrmyW4YNUpAXeboO+dx2AFilIWeDoYy8XksJC3uLYK7vg==
X-Received: by 2002:a05:6214:b33:: with SMTP id w19mr5007737qvj.35.1611663007418;
        Tue, 26 Jan 2021 04:10:07 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a37:4644:: with SMTP id t65ls8398748qka.5.gmail; Tue, 26 Jan
 2021 04:10:07 -0800 (PST)
X-Received: by 2002:a05:620a:8cb:: with SMTP id z11mr5178435qkz.411.1611663006978;
        Tue, 26 Jan 2021 04:10:06 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1611663006; cv=none;
        d=google.com; s=arc-20160816;
        b=PkR3NJvazfrQfkKOLgdJCYFirNaIBUe0ZfqOAyv8Qn73npP9OaIPekDA8AkoLhBLsA
         Qj+Fsr3kWgp1YOvyzlReydhcI+BgfrzIHPmHtqf/MmHYP0fqS1yPBtbfsgznJwgMcFHV
         mONu5Mq2Jw6CnGWFFR31hBUVzY5xrfuYvH5j+jxvIE7SYrWd48U9QP1H7HU8BPQO2gLP
         v813Q2QuZde3VrhLF3fOvQHqXrHWt+L+aen8uPidgUJb++Z98OZZemuCA1HLe5qaQwE/
         i3+wX2VX1iMstkIfVWU5g9JPqGOP++WpoOLHbd0WrGOZRgC4vxQL2PBdrLWNVQHA7HBE
         745A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=tMRhdIpnXnY3Ee/HM7dA2sCQnWT7UdmeoRJrbgNnSlA=;
        b=Di093e7D8CQhVraziAD/e0Wt9nqSiyjRpO6XPLo9x9QZdGhj6+ai75fq1lRzQYSv3+
         sJS0cLDwyyce3Y66G0CB9nCPVmeWB9iDetdh+tEhnWuxzLnMMP6bvK0muQsdYCzchy9v
         c0B7cAiEQ5Vt6KZUaynAv1b5TjJlMigJ/rFumm6J/s4acsIneB8kl4m9tIJu8qHhn7Pn
         SyScEWpoIxPObbn13AdHbEKkEm0kNYOo5cSwqg1hpIThCtjga9WbseQt2cW4LcOISqGO
         dTfaFsNHvrbltSPZYyFMZ2ly5tfeIM3+mzYQN55I2mLTX0EwmvpPQiLGSqVkcLQw92Uz
         KNWw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id n6si339711qkg.7.2021.01.26.04.10.06
        for <kasan-dev@googlegroups.com>;
        Tue, 26 Jan 2021 04:10:06 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 21C2B101E;
	Tue, 26 Jan 2021 04:10:06 -0800 (PST)
Received: from [10.37.12.25] (unknown [10.37.12.25])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id D90C53F66B;
	Tue, 26 Jan 2021 04:10:03 -0800 (PST)
Subject: Re: [PATCH v4 1/3] arm64: Improve kernel address detection of
 __is_lm_address()
To: Catalin Marinas <catalin.marinas@arm.com>
Cc: Mark Rutland <mark.rutland@arm.com>,
 linux-arm-kernel@lists.infradead.org, linux-kernel@vger.kernel.org,
 kasan-dev@googlegroups.com, Andrey Ryabinin <aryabinin@virtuozzo.com>,
 Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>,
 Leon Romanovsky <leonro@mellanox.com>,
 Andrey Konovalov <andreyknvl@google.com>, Will Deacon <will@kernel.org>,
 "Paul E . McKenney" <paulmck@kernel.org>,
 Naresh Kamboju <naresh.kamboju@linaro.org>
References: <20210122155642.23187-1-vincenzo.frascino@arm.com>
 <20210122155642.23187-2-vincenzo.frascino@arm.com>
 <20210125130204.GA4565@C02TD0UTHF1T.local>
 <ddc0f9e2-f63e-9c34-f0a4-067d1c5d63b8@arm.com> <20210125145911.GG25360@gaia>
 <4bd1c01b-613c-787f-4363-c55a071f14ae@arm.com> <20210125175630.GK25360@gaia>
 <62348cb4-0b2e-e17a-d930-8d41dc4200d3@arm.com> <20210126120754.GB20158@gaia>
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
Message-ID: <e368874c-667e-0989-5a5c-f74f107cc03c@arm.com>
Date: Tue, 26 Jan 2021 12:13:57 +0000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.10.0
MIME-Version: 1.0
In-Reply-To: <20210126120754.GB20158@gaia>
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



On 1/26/21 12:07 PM, Catalin Marinas wrote:
> On Tue, Jan 26, 2021 at 11:58:13AM +0000, Vincenzo Frascino wrote:
>> On 1/25/21 5:56 PM, Catalin Marinas wrote:
>>> On Mon, Jan 25, 2021 at 04:09:57PM +0000, Vincenzo Frascino wrote:
>>>> On 1/25/21 2:59 PM, Catalin Marinas wrote:
>>>>> On Mon, Jan 25, 2021 at 02:36:34PM +0000, Vincenzo Frascino wrote:
>>>>>> On 1/25/21 1:02 PM, Mark Rutland wrote:
>>>>>>> On Fri, Jan 22, 2021 at 03:56:40PM +0000, Vincenzo Frascino wrote:
>>>>>>>> Currently, the __is_lm_address() check just masks out the top 12 bits
>>>>>>>> of the address, but if they are 0, it still yields a true result.
>>>>>>>> This has as a side effect that virt_addr_valid() returns true even for
>>>>>>>> invalid virtual addresses (e.g. 0x0).
>>>>>>>>
>>>>>>>> Improve the detection checking that it's actually a kernel address
>>>>>>>> starting at PAGE_OFFSET.
>>>>>>>>
>>>>>>>> Cc: Catalin Marinas <catalin.marinas@arm.com>
>>>>>>>> Cc: Will Deacon <will@kernel.org>
>>>>>>>> Suggested-by: Catalin Marinas <catalin.marinas@arm.com>
>>>>>>>> Reviewed-by: Catalin Marinas <catalin.marinas@arm.com>
>>>>>>>> Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
>>>>>>>
>>>>>>> Looking around, it seems that there are some existing uses of
>>>>>>> virt_addr_valid() that expect it to reject addresses outside of the
>>>>>>> TTBR1 range. For example, check_mem_type() in drivers/tee/optee/call.c.
>>>>>>>
>>>>>>> Given that, I think we need something that's easy to backport to stable.
>>>>>>>
>>>>>>
>>>>>> I agree, I started looking at it this morning and I found cases even in the main
>>>>>> allocators (slub and page_alloc) either then the one you mentioned.
>>>>>>
>>>>>>> This patch itself looks fine, but it's not going to backport very far,
>>>>>>> so I suspect we might need to write a preparatory patch that adds an
>>>>>>> explicit range check to virt_addr_valid() which can be trivially
>>>>>>> backported.
>>>>>>>
>>>>>>
>>>>>> I checked the old releases and I agree this is not back-portable as it stands.
>>>>>> I propose therefore to add a preparatory patch with the check below:
>>>>>>
>>>>>> #define __is_ttrb1_address(addr)	((u64)(addr) >= PAGE_OFFSET && \
>>>>>> 					(u64)(addr) < PAGE_END)
>>>>>>
>>>>>> If it works for you I am happy to take care of it and post a new version of my
>>>>>> patches.
>>>>>
>>>>> I'm not entirely sure we need a preparatory patch. IIUC (it needs
>>>>> checking), virt_addr_valid() was fine until 5.4, broken by commit
>>>>> 14c127c957c1 ("arm64: mm: Flip kernel VA space"). Will addressed the
>>>>> flip case in 68dd8ef32162 ("arm64: memory: Fix virt_addr_valid() using
>>>>> __is_lm_address()") but this broke the <PAGE_OFFSET case. So in 5.4 a
>>>>> NULL address is considered valid.
>>>>>
>>>>> Ard's commit f4693c2716b3 ("arm64: mm: extend linear region for 52-bit
>>>>> VA configurations") changed the test to no longer rely on va_bits but
>>>>> did not change the broken semantics.
>>>>>
>>>>> If Ard's change plus the fix proposed in this test works on 5.4, I'd say
>>>>> we just merge this patch with the corresponding Cc stable and Fixes tags
>>>>> and tweak it slightly when doing the backports as it wouldn't apply
>>>>> cleanly. IOW, I wouldn't add another check to virt_addr_valid() as we
>>>>> did not need one prior to 5.4.
>>>>
>>>> Thank you for the detailed analysis. I checked on 5.4 and it seems that Ard
>>>> patch (not a clean backport) plus my proposed fix works correctly and solves the
>>>> issue.
>>>
>>> I didn't mean the backport of the whole commit f4693c2716b3 as it
>>> probably has other dependencies, just the __is_lm_address() change in
>>> that patch.
>>
>> Then call it preparatory patch ;)
> 
> It's preparatory only for the stable backports, not for current
> mainline. But I'd rather change the upstream patch when backporting to
> apply cleanly, no need for a preparatory stable patch.
> 

Thanks for the clarification.

-- 
Regards,
Vincenzo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/e368874c-667e-0989-5a5c-f74f107cc03c%40arm.com.
