Return-Path: <kasan-dev+bncBDDL3KWR4EBRBVEMXSAAMGQEJ47JHFY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83c.google.com (mail-qt1-x83c.google.com [IPv6:2607:f8b0:4864:20::83c])
	by mail.lfdr.de (Postfix) with ESMTPS id 76F24302965
	for <lists+kasan-dev@lfdr.de>; Mon, 25 Jan 2021 18:56:37 +0100 (CET)
Received: by mail-qt1-x83c.google.com with SMTP id z19sf7738943qtv.20
        for <lists+kasan-dev@lfdr.de>; Mon, 25 Jan 2021 09:56:37 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1611597396; cv=pass;
        d=google.com; s=arc-20160816;
        b=ZYmeKJqHI9a9r1K+nu3OG5GOyrkluz5zN1+tQKIrUK7Dvv2WkqIJpuR0M5Kxf+UaNK
         HtGKmTV70mYCp8X2klQYcLMgBBDUTGxnl+mgvE7gf/z/21d31sxJGss/POa8pBh64rbB
         VAEsckfjxPWMuo7SDTxQVYWj8TX6RjGy4kmkyf4Qu+f8DlaH4Yy1yxa1rYrExZ36RhH9
         spzR9As9S7C9PJfBAC7CpbJXRPqM9Yc8FFiDR7cCgudFtxX0VxngI7u/aiJnyieJally
         bBcinMCs5tPfsny0ryEKcnAvjuKY5N+H8OMMT3FNpQO6+cFNZqwb23TqQQQVPg5VOkmL
         RNcw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=Vmddx3ShxZ6Zi2Kr1UQSbmfNextsryJMdHnpf9919kQ=;
        b=ipGGw2TQVlSlZM4VzVf8ydxLMdImy7PvP0IIrtPbV3D6Q1UaCH9FHxrJ+Esfwcehf3
         g4bXy0U7277L6q8AxlekQ20mvrvs/4M2QRO6LVJVYHVT2AH9T1TrW4fCEuZrqIHEhk//
         JkjCZn0XjWQrlinEPrOuNQj59FuwcZPogyj3tVHKHvTX/UcZlHEE1ydNVYlYWs1zKo2M
         OjpR8SjUqubeSdAL06HTX9fUwfwiJOlYjfHff0X7bmU3eQoFT+tFg/5E49AFHwtsGlMI
         b0vIocGCVLbs+8VYKgUUob7orWJWyugqqixyuaeeOh4PIfKWM6x4q40kIKA+w2tyNdMw
         8oSw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Vmddx3ShxZ6Zi2Kr1UQSbmfNextsryJMdHnpf9919kQ=;
        b=dzChD1STskf7aeuP/rYqhZSdQcpOMK6FClqoVLnJbHi6J5tb0i8J/dmneKXZ4B3EZN
         odcotpuEsFonBBtYtNdDYJcxUskQpqCS7CvGKdKnHnOGdLNnyuSyHdv1ZVRnn9UFCGQA
         u4mrwTIEn6dvw6Pg+uPAgaTdWl+RldWzJHEHfLMvT6JAMQnAkRt6CUuLg9uG9BlN05fR
         H4JwisuTDzVg3ziU3VEvy2IqZ64I639mVb5KEZaFj4Mo6HAlibBMiEMLHjFdGpnszk91
         rIL5v80YvHGmalNxZHB1ujcAHughu9bYomDuwLaH8KVEDZESszKFWrM64Oe22oFJzYGO
         NZRg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=Vmddx3ShxZ6Zi2Kr1UQSbmfNextsryJMdHnpf9919kQ=;
        b=FG5K6S6stoBhujx+HDsVZ3/WkOgycWgqkyWXgeBIZLNyr3cGzTFTrEszAkCbzD0i4W
         Q1u43gBNsGYuZ6h7C6tB1BJCUI0Pv45n9xBvmGCMijvwrj2eMurTU7Ycrk4aGA0rBWMQ
         vzZLkL28XDgFe5EC4ydlJ4lm+QFTuXjWqHviJnvHmsKuEYuvEHT+okqBi1ciRUf9Nhcz
         dvt4Lt5jZRl9X5s3YNdpTHiBYrRGKsmVqhi8QXLLCji7l+E6Pnz8ekOhtcFJaBgsS1GW
         KEj45TBPh4tyMYlvdv1rZLpO8l2pEzTUfB8YkPpFguBJnB8LqDPY9zNujk3kK+ls+0zD
         0heA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531QUgBEIzBvvSZ4+sGLUKNpsdSOWImQoKKUEG6O384jtviL4KPY
	7DlPmBQJCfR4FHrn2IX3mJA=
X-Google-Smtp-Source: ABdhPJyi1MuaBGH2HveIzXmXBH86K5zDhxMIsJG4knkLMKzhqjxscmpqNaelN/ePuaiU0mmT0AMF4g==
X-Received: by 2002:ac8:4e25:: with SMTP id d5mr1561748qtw.275.1611597396553;
        Mon, 25 Jan 2021 09:56:36 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:620a:248f:: with SMTP id i15ls2980715qkn.11.gmail; Mon,
 25 Jan 2021 09:56:36 -0800 (PST)
X-Received: by 2002:a37:7003:: with SMTP id l3mr1923174qkc.467.1611597396118;
        Mon, 25 Jan 2021 09:56:36 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1611597396; cv=none;
        d=google.com; s=arc-20160816;
        b=VMGDpgicw8ja0kucU3c+mIfPSRXvuaa8XAWDxJijIUvY4UVcaScDFeuYuhNAR/njBW
         fC6lV8TWe1xUP+oHG4J7AFwDjm/4aa9vTO+9Z+OWo9/Wydd7c1N/QV+ulyzGmYruQX9u
         2sDpYcTNk1CXJzxNComdZqjfCLAXq3SbaBCc9aCJV78op5UkOAksqKKJVFMl0/1X+MWB
         GFTAyK2qNO7XSYQY+HXIqCZru9gxNkvP4Q27E7zZZ0TTIKduJHHPRniLdJ/tsznwm78R
         JQ0+c8tE+jtQOypw3c00IBw1Q6FIC2qBTrYK1HaS+i2630jrqGcT/MnxkHQGYvaBaNW4
         wG0A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=FdrflyQmQDp+xQWRehWkIHiLecyKw0KP8U/GBTa0xjg=;
        b=Cs2YNYgtqQ7c2/QylpK4/FSoovyctMAYsLBL4qYV/zljQI5HZfwukzmW8+DVXGPJej
         5YHc6xmRQT4VtVa+LoVHMLbhlDve/2Wb9zZwI3x/UF4avkNSHo8Ss8rMWLIqQdp+Ifam
         imUDsgvOI2NAFtnsEaaTUsDHruksE6af86EOHdKPCyJb1/SHbVTEusgzM4sI7icHj8JA
         ScwMrQ37rljA5HO2vrAH88JrRcQQGJNS2/ZsswxPKWNM5VFvtR6XsFUjKhsddUa6K72q
         dMrR+gVKoThsxAI6DRMfiAuGcsUZtu6XdQW05ZQLNDa/TjuDq+gpKZeTRHZY2AopOSpo
         Xpdw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id f10si149189qko.5.2021.01.25.09.56.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 25 Jan 2021 09:56:36 -0800 (PST)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 426B622583;
	Mon, 25 Jan 2021 17:56:33 +0000 (UTC)
Date: Mon, 25 Jan 2021 17:56:30 +0000
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
Message-ID: <20210125175630.GK25360@gaia>
References: <20210122155642.23187-1-vincenzo.frascino@arm.com>
 <20210122155642.23187-2-vincenzo.frascino@arm.com>
 <20210125130204.GA4565@C02TD0UTHF1T.local>
 <ddc0f9e2-f63e-9c34-f0a4-067d1c5d63b8@arm.com>
 <20210125145911.GG25360@gaia>
 <4bd1c01b-613c-787f-4363-c55a071f14ae@arm.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <4bd1c01b-613c-787f-4363-c55a071f14ae@arm.com>
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

On Mon, Jan 25, 2021 at 04:09:57PM +0000, Vincenzo Frascino wrote:
> On 1/25/21 2:59 PM, Catalin Marinas wrote:
> > On Mon, Jan 25, 2021 at 02:36:34PM +0000, Vincenzo Frascino wrote:
> >> On 1/25/21 1:02 PM, Mark Rutland wrote:
> >>> On Fri, Jan 22, 2021 at 03:56:40PM +0000, Vincenzo Frascino wrote:
> >>>> Currently, the __is_lm_address() check just masks out the top 12 bits
> >>>> of the address, but if they are 0, it still yields a true result.
> >>>> This has as a side effect that virt_addr_valid() returns true even for
> >>>> invalid virtual addresses (e.g. 0x0).
> >>>>
> >>>> Improve the detection checking that it's actually a kernel address
> >>>> starting at PAGE_OFFSET.
> >>>>
> >>>> Cc: Catalin Marinas <catalin.marinas@arm.com>
> >>>> Cc: Will Deacon <will@kernel.org>
> >>>> Suggested-by: Catalin Marinas <catalin.marinas@arm.com>
> >>>> Reviewed-by: Catalin Marinas <catalin.marinas@arm.com>
> >>>> Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
> >>>
> >>> Looking around, it seems that there are some existing uses of
> >>> virt_addr_valid() that expect it to reject addresses outside of the
> >>> TTBR1 range. For example, check_mem_type() in drivers/tee/optee/call.c.
> >>>
> >>> Given that, I think we need something that's easy to backport to stable.
> >>>
> >>
> >> I agree, I started looking at it this morning and I found cases even in the main
> >> allocators (slub and page_alloc) either then the one you mentioned.
> >>
> >>> This patch itself looks fine, but it's not going to backport very far,
> >>> so I suspect we might need to write a preparatory patch that adds an
> >>> explicit range check to virt_addr_valid() which can be trivially
> >>> backported.
> >>>
> >>
> >> I checked the old releases and I agree this is not back-portable as it stands.
> >> I propose therefore to add a preparatory patch with the check below:
> >>
> >> #define __is_ttrb1_address(addr)	((u64)(addr) >= PAGE_OFFSET && \
> >> 					(u64)(addr) < PAGE_END)
> >>
> >> If it works for you I am happy to take care of it and post a new version of my
> >> patches.
> > 
> > I'm not entirely sure we need a preparatory patch. IIUC (it needs
> > checking), virt_addr_valid() was fine until 5.4, broken by commit
> > 14c127c957c1 ("arm64: mm: Flip kernel VA space"). Will addressed the
> > flip case in 68dd8ef32162 ("arm64: memory: Fix virt_addr_valid() using
> > __is_lm_address()") but this broke the <PAGE_OFFSET case. So in 5.4 a
> > NULL address is considered valid.
> > 
> > Ard's commit f4693c2716b3 ("arm64: mm: extend linear region for 52-bit
> > VA configurations") changed the test to no longer rely on va_bits but
> > did not change the broken semantics.
> > 
> > If Ard's change plus the fix proposed in this test works on 5.4, I'd say
> > we just merge this patch with the corresponding Cc stable and Fixes tags
> > and tweak it slightly when doing the backports as it wouldn't apply
> > cleanly. IOW, I wouldn't add another check to virt_addr_valid() as we
> > did not need one prior to 5.4.
> 
> Thank you for the detailed analysis. I checked on 5.4 and it seems that Ard
> patch (not a clean backport) plus my proposed fix works correctly and solves the
> issue.

I didn't mean the backport of the whole commit f4693c2716b3 as it
probably has other dependencies, just the __is_lm_address() change in
that patch.

> Tomorrow I will post a new version of the series that includes what you are
> suggesting.

Please post the __is_lm_address() fix separately from the kasan patches.
I'll pick it up as a fix via the arm64 tree. The kasan change can go in
5.12 since it's not currently broken but I'll leave the decision with
Andrey.

-- 
Catalin

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210125175630.GK25360%40gaia.
