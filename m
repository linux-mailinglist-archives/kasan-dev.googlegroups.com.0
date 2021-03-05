Return-Path: <kasan-dev+bncBDDL3KWR4EBRB367RGBAMGQEGECQ72A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13f.google.com (mail-il1-x13f.google.com [IPv6:2607:f8b0:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id E821432F1D2
	for <lists+kasan-dev@lfdr.de>; Fri,  5 Mar 2021 18:52:48 +0100 (CET)
Received: by mail-il1-x13f.google.com with SMTP id j5sf2367416ila.13
        for <lists+kasan-dev@lfdr.de>; Fri, 05 Mar 2021 09:52:48 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1614966768; cv=pass;
        d=google.com; s=arc-20160816;
        b=t3xXt15V6gTMJha8T3qZaEGuLfHLlodTmn2TKpHoVqo84MSHmgfUJcY3CoBC0rBclC
         dxEMXxaIb7f4Ecd2KDROxqAG6SBGGHoA6DKwgi2G6dqzse5uflSY2+dHh+J+aYQrYsx2
         bEvd/oJt7FSfa1YCwrJIWNF0o270MHjy2mLdQqNcq5moDtqmVlR/1VuryXnIJSQJD0F+
         OMEJ6Ixynpti635BcveVj+B24F6277C8J9YFDdCkfzFk4ojvhvDtSi4sPPpqWV/kGtAe
         BN9O+FdRN5oqPyO8w4Quo37ugOgq48FUGFPCDZ9F2eEnUCKfPXq4Pmq2+K5SbsDkbr0L
         vhVg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=7rS50J5uFdpfN5RWheoWKw6+BvT0M4AsHTFIb6orBf8=;
        b=Cm03TvowfPYFrbuVDDmXdDoM1nIdeOd5A0OtkIC6VC5VFA4zW0qWyeIA27bymU1ETW
         RLLh3H65ZqyHW5JRil+X+0WnZQrKlu7YrnxcDxTT8u2EsQhNO0Sj2vPxmxd2dq29MQmw
         jeYRD7v2QB+5ZPRQeKR3UKG6Pz97it5RXb5kKhr7y2w1MsV9lgXk9tttUVzQ2r4f0fcc
         b+JE2iLBtfjcAgdw8KL/vTXsPYYCL6SV/cdaToG8AoaZNVYP8xoqLe2oOWrDMO7xgF55
         geZ1+eqQIl5i1ixk9j3Jy5GNPgN9ly81PzD6oG7yltjo0xBcWBeWSkzWJ9INGWN5IJZ7
         ktCw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=7rS50J5uFdpfN5RWheoWKw6+BvT0M4AsHTFIb6orBf8=;
        b=KvYVbqgv389vJdrbRfnkc0Sbguo7sLb369RejnT2iJbFeledIuXZvfvbTaHWRoXh8q
         Nc/0nNoSgI3sfnoRZJ0o4SW3oyCO/DCURjSXQmW1h++TC0SJfWEnDrF9o51ysYE3/Jvj
         qyMkaZ35cyhkbXKT2QFWLMkwNEW/I1PaxCI5iiHETu4/hdZBYGALg3qwkr3FXcK6h9bl
         HpKwlUF4YQMDCqJmnWNRkjWZPaomeztiNnxS8AwRd/A6RgvMnZ7Ur32lXBSCpMbqy/V0
         eehZnhFldm+xykN1azlU0DYMq/KBTjNFcSWPnSKB8z+Mm+p220uoqUGFTebq/dwhvT6Q
         zXLg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=7rS50J5uFdpfN5RWheoWKw6+BvT0M4AsHTFIb6orBf8=;
        b=qIGqF1Eqqr6OA9rSN+nGzV4FX26BU2zAgGp1fTu+jQ8x82bA9XyH5GzqlyighYbxz2
         Pt7GRRgqqqH4AZGM2okhH+10EaNVOpRj24UdIRY1Rwxi30gPzpL6+o9SUGAlhiOQEhkG
         PkG29RESoZRNN3tKsvBkRZqvCu4EUOaFn5j0z+FZtwe2Ei78w78eOhnuKF6oVImJtV9N
         1ERtxBnlL32QAx91TB1OjONMEcTuQYP8WgDsqrAX6o4ccL0/T/am2XWN2MPYUduapV+k
         6mPdDMsbVX+aLMnruxhyplwhbs4K+RxyUor88HnecRUA1zhqD8FlJqcv7Zg8HWIkt/fi
         GQRw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532Mmmo5CcCqJ4k59OieB5OIwkUUS+EBiD+xQAB5Bt9TPQlWHlNP
	m21p8h/61SenwX7P0bPzQuY=
X-Google-Smtp-Source: ABdhPJwze4mz5Fa9/fmaXVNVcflPAr3ux1XfqTRPJnJIRhlyVi+9h8gqg6LpOiAKJU/usNDY0bwrHQ==
X-Received: by 2002:a05:6e02:1b84:: with SMTP id h4mr9575668ili.196.1614966768005;
        Fri, 05 Mar 2021 09:52:48 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6638:1687:: with SMTP id f7ls1492242jat.11.gmail; Fri,
 05 Mar 2021 09:52:47 -0800 (PST)
X-Received: by 2002:a02:7f8c:: with SMTP id r134mr11045372jac.95.1614966767705;
        Fri, 05 Mar 2021 09:52:47 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1614966767; cv=none;
        d=google.com; s=arc-20160816;
        b=WH2AhUUFNodzSZcaJeUMFT/ONkVXVe2KmxsT9ywt8aWD998zrViNoLzT3BiUr+E4Jp
         RS6YT194UndQmknmcIXSqej48IHYcn+yjkXQXqc+jJlc7Qh2hPEtQlMr5QGSe5R5k2gs
         sQ5w2jkcaRJcwbcZCV0Hhq2jzXYY5seSjx9g/TW4S/OtkltFDisbyzgarKd7mZ3gnmnX
         2v2HsVKG2b1hyiHtLCgA9RPv4ISDH4rKuIfP9v9MnIes01Spod8kc1Tg0IQ0TDowgxE1
         3Cj6NP5a89ZXvVsUiA9626NkTJBg5rllTaFe54/gQqkbJ49LWaSzNE9cNCRFmTVOGCIn
         6ksQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=6Sbw+GGQXXAF2VI1JJNGpqDCSNO52X85wahadvAI05Q=;
        b=DameA1TzXIyk7ieGh/+oAo8jdoYkdzEtGxUx13JdQgHfoX3eyKIcxDko5Gx0fL3DLj
         +/6X2FfaWrJOg05A/TRE+aq8FiW1zX7+GbLASUg9jbn5OWUsszcIAAyxEUn8wMEuc+wR
         hWdBB88QsyPTLYo7y7A2YyMl8XQXwr9ddErlpIvdRB2XH58WDFJeLiSdojFIzc6GPX2d
         Jz6ZqLDTQNd3Hm3qOzH7pBzY0oxr6VqEjnUkt8LU6OsrpS3GxLHUvS9wsrSBYofpkpis
         NK7H4KiT715i2oVRrhPjuW+yWOlpXW1pyOCXVa4ByFsdwcfBVFGOsttVPWdacLij8aWE
         I4AQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id r19si213539iov.3.2021.03.05.09.52.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 05 Mar 2021 09:52:47 -0800 (PST)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id B7D49650A3;
	Fri,  5 Mar 2021 17:52:45 +0000 (UTC)
Date: Fri, 5 Mar 2021 17:52:43 +0000
From: Catalin Marinas <catalin.marinas@arm.com>
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Linux ARM <linux-arm-kernel@lists.infradead.org>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	kasan-dev <kasan-dev@googlegroups.com>,
	Will Deacon <will@kernel.org>
Subject: Re: arm64 KASAN_HW_TAGS panic on non-MTE hardware on 5.12-rc1
Message-ID: <20210305175243.GH23855@arm.com>
References: <20210305171108.GD23855@arm.com>
 <CAAeHK+yuxANLmtO_hyd0Kg4DpHh2TLmyMQEXP58V8mLoj0vtvg@mail.gmail.com>
 <20210305175124.GG23855@arm.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20210305175124.GG23855@arm.com>
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

On Fri, Mar 05, 2021 at 05:51:26PM +0000, Catalin Marinas wrote:
> On Fri, Mar 05, 2021 at 06:27:45PM +0100, Andrey Konovalov wrote:
> > On Fri, Mar 5, 2021 at 6:11 PM Catalin Marinas <catalin.marinas@arm.com> wrote:
> > > Enabling CONFIG_KASAN_HW_TAGS and running the resulting kernel on
> > > non-MTE hardware panics with an undefined STG instruction from
> > > mte_set_mem_tag_range():
> > >
> > > ./scripts/faddr2line vmlinux kasan_unpoison_task_stack+0x18/0x40
> > > kasan_unpoison_task_stack+0x18/0x40:
> > > mte_set_mem_tag_range at arch/arm64/include/asm/mte-kasan.h:71
> > > (inlined by) mte_set_mem_tag_range at arch/arm64/include/asm/mte-kasan.h:56
> > > (inlined by) kasan_unpoison at mm/kasan/kasan.h:363
> > > (inlined by) kasan_unpoison_task_stack at mm/kasan/common.c:72
> > 
> > This is weird. kasan_unpoison_task_stack() is only defined when
> > CONFIG_KASAN_STACK is enabled, which shouldn't be enablable for
> > HW_TAGS.
> 
> CONFIG_KASAN=y
> # CONFIG_KASAN_GENERIC is not set
> CONFIG_KASAN_HW_TAGS=y
> CONFIG_KASAN_STACK=1

From Kconfig:

config KASAN_STACK
	int
	default 1 if KASAN_STACK_ENABLE || CC_IS_GCC
	default 0

and I use gcc.

-- 
Catalin

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210305175243.GH23855%40arm.com.
