Return-Path: <kasan-dev+bncBDDL3KWR4EBRBLVKSWCQMGQE4NUA35I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13e.google.com (mail-il1-x13e.google.com [IPv6:2607:f8b0:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id 6169D38951B
	for <lists+kasan-dev@lfdr.de>; Wed, 19 May 2021 20:13:03 +0200 (CEST)
Received: by mail-il1-x13e.google.com with SMTP id s15-20020a92cc0f0000b02901bd280c0102sf2600954ilp.17
        for <lists+kasan-dev@lfdr.de>; Wed, 19 May 2021 11:13:03 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1621447982; cv=pass;
        d=google.com; s=arc-20160816;
        b=h2mcRF/g9cOT/FtdfZqocmG25RpJKtGCDZOjBLPg+sZZD8MDSErnxHtm1QsBj1F3VZ
         KAQKoQ2loKyGW0IPgqgkO66SUngLDCIILy6/LP9gKTdWaSPJs+Q+VQjC2yTw50wEWe6j
         gv5OJ8Bo3u69cLdfUOetIYssqhBkwY8CrH+YZmed+4C8NmWVor48qe/NJMrrgbqscFNw
         TlSRSr8hEGCscfKMpjFH4p8kkwavUZ1DZC/4jqkgqNka1CluyGmawFMEsTEwV6y9T0YC
         qZ8tZyho/d0kyAdpdm3ZJx5ViGqEXzWvYsbwtAjr6wmh+k2Wq4fxJ+KgNkvM3Tf7+191
         0ZNA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=7+JDPl2pxgpmR4iympR7CkBT8xgYg2fQDgu/YucaOU8=;
        b=t45sRXI9hxrKXoJX7V6GufHbyEgEKLma5eCExF1UvP89QIyREONcTES6ZqfCjlDsJI
         V2HPt+bhDCVn38V9ouKNFpZX/j9IHycO5o4mv4gF/AgjJ6KJIwlb+6QPwssjVE6Dc55L
         caXK0UW3d7cL2z895fw9NtzdTYz4GbwBlXMaRDg/0OjJXNiRMuguWjTwmeSq4bYcnXr8
         0cG8AXAAWsOXLGoM6C9deYTz9AXquRftqjg3VAdS2whX4X290nlh9wZIPUCRVdhJuyFJ
         SIbfFQ+6tGyhiP8QIIdRrEPV/rcXIysnJ1EeZ3w/Zf3MbucX2xGVmaYT6Ksupt4WMQWe
         CtCg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=7+JDPl2pxgpmR4iympR7CkBT8xgYg2fQDgu/YucaOU8=;
        b=mkOlFAvkF2wAHm8mx88QNPvPh5mfohbDkI3OyD/pt+7hfBIbvliJSPIg0MNVl6hotx
         QHfpe3mGIRql47z9/fZ7sQt6mBPpUZnyLzujdQd3++NUPmCeWwsmw51oij8UktJWm/E8
         +ajhpETCaenD5Obh4nUI02SCsL/5HvMRN4lAfRyhWKNSfOVHAnqd0yZee7762goeQ0Wk
         ZnBYQjGIleqVRhb/EDTlhCJsKJGtlxUIKi6aQ1G5FoN/C0uzyocoBmdMbFk2uVVU9s9c
         N7d/WGbLJR5KwkrjkWi0RwuDBLIgD4K1awGFxR3cQuV1dB5dJuWJduiu7ZO0Qc5uVheN
         Gg+g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=7+JDPl2pxgpmR4iympR7CkBT8xgYg2fQDgu/YucaOU8=;
        b=BukIN+TjvtLukWNDxOgo1iWtu4WJHAizoQ/hYi8m2N//WI4rtm8OcmfMGb1MQPfJHV
         yHcKZVaYsNIzbYqfALNJ5bK5FgDSfJovPdUpkTo0dSmzxgRLdhdUACIsm/qnxAcIQfIS
         jeH5SOFXnC5HG9oZta9pdJb9hOt0JMrJqVHsqjVfygdJ5x25ZVhzsIST3puiWUVPaFkd
         yOnwWeLcFCnI4UedOA791DTtjSf4yMwWyFU0dB4FzmoxwrH1kkl86xvcLS+6iuaMKIC1
         946JEo5kLnBXa+6uH34y+6D1EGcJtJE4MLBUOpRXQlhaPcQQaY2Ayh9wcknPdyhaJTdt
         WmCw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533hYxOul1DmBQNoDzLKKMOSDhx5kXlBBY2/AuIfVs8l5CXcme/1
	BB/wgJkdciI4vBJyAk35v+Q=
X-Google-Smtp-Source: ABdhPJzHPNwZyMaW22x+bT2UJv8Z/GzIvTQ7ih1J20MM9AdYCOVRiEeGyXDhw4HDjm9VyynZfByOXw==
X-Received: by 2002:a02:a10f:: with SMTP id f15mr245403jag.124.1621447982393;
        Wed, 19 May 2021 11:13:02 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6602:1506:: with SMTP id g6ls16341iow.9.gmail; Wed, 19
 May 2021 11:13:02 -0700 (PDT)
X-Received: by 2002:a5e:9e4a:: with SMTP id j10mr847329ioq.52.1621447981965;
        Wed, 19 May 2021 11:13:01 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1621447981; cv=none;
        d=google.com; s=arc-20160816;
        b=pVtjJ4T7V/izHtm34o2wEnjYRUDxcAwHeyHhdeBSmXHh1eDVvM6Yu7w7BkmsuA5BXN
         YeJw0hb1BLqURh3iUxJpXnUczoEUx0Al1lXXdytRuEcwLg48FZe1J+B8jE9ye78C8Uii
         eh9Qz7+7btPVLA+2nrcWIJHLwWnHXkJeHiiASxMzcjdXkDWlnwlXBr2TZDdYa8LKbYeI
         OLU+iWnebpf1N18p4XXAQz5KTYlyHlIKTCX7Nfhmb9l6BY8I1G/FuAk4NN/yRg0IkOjr
         1P3aATck2OE2AY1DUJEdfthJDZBRQMPAbRRRlpYgHqO/Tce8bBExYYnvkAGyMMULrCKw
         XAIA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=46gq6Y9W8CzFkwjoy9hWLKn2qwp7R+ob1Xtw/3ebtAo=;
        b=OpwX5I8UBA5TAhfR16zjT1K9x2s9kNphpF4JLiJW3JChaLnuVdfZNLb0oCTUqfmTFN
         MXj/j6OwgbuU+37ZQSpYUAU1LeZFhyVKPdBfzfut7T3kCrYeN/AB1MnXSMgC6Zq+d2bF
         jwc11GFvn+C+/Vn8Xj90wxSJ5WQtRm58XJsCPxwKeKu6sj1U+ksrbLoRqIH/MplzymPc
         PjInJI+iXjSTMwJwhhzyVhhQh0Ws4o5/kx6hlpcb66TpbkzMDYYdPAYXFUphalWbERUu
         d7OlqtayAyE/LSj8intA54Jwbq1UEy3N4p4LJVlDiJ7MmPwHlOUdScBgbTMtSzlebE+q
         w8mg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id z2si31569ilo.2.2021.05.19.11.13.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 19 May 2021 11:13:01 -0700 (PDT)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 91AD4611BF;
	Wed, 19 May 2021 18:12:59 +0000 (UTC)
Date: Wed, 19 May 2021 19:12:57 +0100
From: Catalin Marinas <catalin.marinas@arm.com>
To: Peter Collingbourne <pcc@google.com>
Cc: Evgenii Stepanov <eugenis@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>, Will Deacon <will@kernel.org>,
	Steven Price <steven.price@arm.com>,
	kasan-dev <kasan-dev@googlegroups.com>,
	Linux ARM <linux-arm-kernel@lists.infradead.org>,
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>
Subject: Re: [PATCH v3] kasan: speed up mte_set_mem_tag_range
Message-ID: <20210519181225.GF21619@arm.com>
References: <20210517235546.3038875-1-eugenis@google.com>
 <20210518174439.GA28491@arm.com>
 <CAMn1gO5TmJZ4M4EyQ60VMc2-acUZSYkaB9M0C9kOv_dXQe54Ug@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CAMn1gO5TmJZ4M4EyQ60VMc2-acUZSYkaB9M0C9kOv_dXQe54Ug@mail.gmail.com>
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

On Tue, May 18, 2021 at 11:11:52AM -0700, Peter Collingbourne wrote:
> On Tue, May 18, 2021 at 10:44 AM Catalin Marinas
> <catalin.marinas@arm.com> wrote:
> > If we want to get the best performance out of this, we should look at
> > the memset implementation and do something similar. In principle it's
> > not that far from a memzero, though depending on the microarchitecture
> > it may behave slightly differently.
> 
> For Scudo I compared our storeTags implementation linked above against
> __mtag_tag_zero_region from the arm-optimized-routines repository
> (which I think is basically an improved version of that memset
> implementation rewritten to use STG and DC GZVA), and our
> implementation performed better on the hardware that we have access
> to.

That's the advantage of having hardware early ;).

> > Anyway, before that I wonder if we wrote all this in C + inline asm
> > (three while loops or maybe two and some goto), what's the performance
> > difference? It has the advantage of being easier to maintain even if we
> > used some C macros to generate gva/gzva variants.
> 
> I'm not sure I agree that it will be easier to maintain. Due to the
> number of "unusual" instructions required here it seems more readable
> to have the code in pure assembly than to require readers to switch
> contexts between C and asm. If we did move it to inline asm then I
> think it should basically be a large blob of asm like the Scudo code
> that I linked.

I was definitely not thinking of a big asm block, that's even less
readable than separate .S file. It's more like adding dedicated macros
for single STG or DC GVA uses and using them in while loops.

Anyway, let's see a better commented .S implementation first. Given that
tagging is very sensitive to the performance of this function, we'd
probably benefit from a (few percent I suspect) perf improvement with
the hand-coded assembly.

-- 
Catalin

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210519181225.GF21619%40arm.com.
