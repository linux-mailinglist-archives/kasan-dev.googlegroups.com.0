Return-Path: <kasan-dev+bncBC7OBJGL2MHBBHGNUP5AKGQEGK4KPHY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x339.google.com (mail-wm1-x339.google.com [IPv6:2a00:1450:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id 74AAF25592B
	for <lists+kasan-dev@lfdr.de>; Fri, 28 Aug 2020 13:12:29 +0200 (CEST)
Received: by mail-wm1-x339.google.com with SMTP id d22sf240124wmd.2
        for <lists+kasan-dev@lfdr.de>; Fri, 28 Aug 2020 04:12:29 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1598613149; cv=pass;
        d=google.com; s=arc-20160816;
        b=BuPZz8ce07l+GYulf+FqSC2KrE+500zKZEnt3XmbyvM5j0sOAMiyuy0UzVwmY9ITIf
         dZEdl/lE5suROmahRvsH7KyFiG3JL+Y15J6O7GdW6qg0Jcx6QV/xuK7JNLBglxf3FMIW
         BQ3PH+uTQOV4F01TP+t+5CXdlCEBmSTppxTijp1rPwrpOUQxAgaoze187UNbg51lMQeE
         xK7c0D9QqDx47DIOjhrMKKbaDHr2UzRthqy20YEC+swPQoyN0A6Z0rEU/ZznSMPNftuI
         E5dKYp+0nNAcyn7NHDNCxzp+XShTeP/NvR0Qa6vGavL3EraCyZiDyWneOhzW9fYM3cIq
         r/UQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=MNdowdlThVWrigNcyD5uT1THaFyZFFuIA2pMmIDuI28=;
        b=RyGbDnnfsaeLwXzSuFk0Prf1GYpYQi4rOAusPW3EDNjBvCyShErtQkT/RFsSRTDe1h
         bzuvcsx0H3DYehmFlkeobkkkJzU3bKCAom6fKiCoP5gXe3xcynKm+QGqEfIUTwe1DuRw
         kF6l+GOb24frfyGFiff/g+qzGJ1GPE+y3Gmpy56OE7HhkcTWrt3W8a7pv2oQIwE9p/d+
         OU+YNPArWm31c+ilSpnU0JRfPF11hpwx0iomwpFdcyPfFLe1a9uggiueShRaCvu0ateJ
         F0IuKZCgH+Yc46QeUJIC+Fjt8y245RfjHWhZW15hAbGuvV+l10BfrzOPNGUYjICyDNfp
         h4IQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=PjUoFCsQ;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::343 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=MNdowdlThVWrigNcyD5uT1THaFyZFFuIA2pMmIDuI28=;
        b=qCCx0HobxEz1zE31RZWpL24dbEhxZb2NouDVulm+JgMBNKW28WKVOCXCix1WZjHW+U
         z32QtkDISYg8AS5cl6n+ZrTDgOh4An7FAFhF4uguR9wgVAEJ63VLy9n0iVJQX95/4rxO
         MtwBWEBufkbzLOVewzjZ52a9SazQwIPPgz+LDDjA05+07Zq2xXJAMGqeylPGs7WmiOA0
         eqTyzBcP7//Izoti3eKZ9PddJYEn590PqAajkfM/1eBj89dBARZk/xsizu6G8fKyD68h
         u2DCFyRgm46TSKlMMsHTMbM2bQQbLH9o5GNdEGCslRcp3BLLNsKQmilEF7M2OWcN8GdU
         RzlQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=MNdowdlThVWrigNcyD5uT1THaFyZFFuIA2pMmIDuI28=;
        b=JpeOcY6VZxt2UbslWf5j7ylvOQI4ULNdmLeUQYILpGSxGNF4wNLszfAomJIC7lyCnw
         flksJoiRj13DA2OndxBMW4tNzrNuIpdvR+QyVzrsDM5Oav0nodZ19tlopEuy3RufkJ5o
         g5aREpI0hJspnpoxHl68t4JYekxTbOEgScf8MEJBbgilmqjb4L2cmk9901BtLOfegJ8U
         pmcBO621MdF95ruX1nUCod7jrA2G+hqppXQF8kY5GbEzkNogWVXEbKeRskEXhcBq9uOx
         UFpH9X2a/VkBbAFOM6YVeeyH29vna3nHwT0B1ABHqi2Q8v62VMnRlpip8Sm5pvB5S/4A
         54WQ==
X-Gm-Message-State: AOAM533WGo/6UiR84WTqU5ZgHCV+Q1SQYundoZXayAhC5b8Np5jf4GQG
	Xb7+tTzEmpeDwePgmQHPiKI=
X-Google-Smtp-Source: ABdhPJx8JPaNbWE4Sd3fXThKchBfn4Y/gqSwXuz/DV967RnrWsV4Oh28SAK4vckBiMKvE//ejgU7TQ==
X-Received: by 2002:adf:c64d:: with SMTP id u13mr1110992wrg.114.1598613149140;
        Fri, 28 Aug 2020 04:12:29 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a7b:cf07:: with SMTP id l7ls405787wmg.3.canary-gmail; Fri,
 28 Aug 2020 04:12:28 -0700 (PDT)
X-Received: by 2002:a1c:1bc2:: with SMTP id b185mr1211986wmb.168.1598613148406;
        Fri, 28 Aug 2020 04:12:28 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1598613148; cv=none;
        d=google.com; s=arc-20160816;
        b=DlyrF91RftMNlQibmeXZw8vreWnAEGdenmAx7jzFijM4ErBS8dfj1Km9pEik3DOAgO
         yc6ivZ4wPMHcFSykk2ndt4Cr1kIH/q22/rmBwHKvSbznwXoz5CHNHnzTYJ3Kn51X384M
         r8FKPfxpOdg/HFiUh+cJzBZHVqXKcUJpciQSBUfjplC52uFqzkKfAbxSGGcyhMDKhVks
         18MMdJqcuIHWxCQu9ioegshZSOG2gyE+1LBPPGcGP5ncUFVu8gRX9QMgiIDo154p3njb
         /58R0zvMTJfbpx6susQTSjfbekuwEFvZLtl9fwJjPeq9ikP8j1tjv5FDNh9341s6PFNo
         h4+w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=+4JiaYoS0HndrreBr2XTvIDvJUjGSip4KNY5rXBxq20=;
        b=zwEGmucfuzrjNQjzk7Zzdav4QuR3bpL3X3cEA2AJiqCyLo1PmI/EQ1hfxdz3Ccjsze
         r7iOq4z9qEqf8neoEulHvNBjKpFLHqZOUOmLwFasuncRsm4k0RmLTcmhBguio6gmQjuN
         ZHhwzshAYu80cenkxlE5QhHY0ktyw6aAKBAXMw3Y9JiEJsslXHR/ED9L1bgOxuMLhLQ/
         AqpEuv4FkBMCk4RuPqgKsXuu/7jkyTBBtuOeUOLwkPmBN2FeyfoBNLOL8hy51hZJIaBo
         /EYN4o1pmIwjJR6JhaAqYZ7tZ+38eM7r2TX1H7dujYt7CTq8zkz1vI32q3kpARmiZRLZ
         knVw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=PjUoFCsQ;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::343 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x343.google.com (mail-wm1-x343.google.com. [2a00:1450:4864:20::343])
        by gmr-mx.google.com with ESMTPS id 92si19484wre.0.2020.08.28.04.12.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 28 Aug 2020 04:12:28 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::343 as permitted sender) client-ip=2a00:1450:4864:20::343;
Received: by mail-wm1-x343.google.com with SMTP id q9so567555wmj.2
        for <kasan-dev@googlegroups.com>; Fri, 28 Aug 2020 04:12:28 -0700 (PDT)
X-Received: by 2002:a1c:ed0e:: with SMTP id l14mr1090553wmh.140.1598613147805;
        Fri, 28 Aug 2020 04:12:27 -0700 (PDT)
Received: from elver.google.com ([100.105.32.75])
        by smtp.gmail.com with ESMTPSA id o128sm1639658wmo.39.2020.08.28.04.12.26
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 28 Aug 2020 04:12:26 -0700 (PDT)
Date: Fri, 28 Aug 2020 13:12:21 +0200
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	kasan-dev@googlegroups.com,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Elena Petrova <lenaptr@google.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Kevin Brodsky <kevin.brodsky@arm.com>,
	Will Deacon <will.deacon@arm.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org
Subject: Re: [PATCH 35/35] kasan: add documentation for hardware tag-based
 mode
Message-ID: <20200828111221.GA185387@elver.google.com>
References: <cover.1597425745.git.andreyknvl@google.com>
 <5d0f3c0ee55c58ffa9f58bdea6fa6bf4f6f973a4.1597425745.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <5d0f3c0ee55c58ffa9f58bdea6fa6bf4f6f973a4.1597425745.git.andreyknvl@google.com>
User-Agent: Mutt/1.14.4 (2020-06-18)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=PjUoFCsQ;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::343 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Fri, Aug 14, 2020 at 07:27PM +0200, Andrey Konovalov wrote:
> Add documentation for hardware tag-based KASAN mode and also add some
> clarifications for software tag-based mode.
> 
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> ---
>  Documentation/dev-tools/kasan.rst | 73 +++++++++++++++++++++----------
>  1 file changed, 51 insertions(+), 22 deletions(-)
> 
> diff --git a/Documentation/dev-tools/kasan.rst b/Documentation/dev-tools/kasan.rst
> index a3030fc6afe5..aeed89d6eaf5 100644
[...]  
> -Tag-based KASAN uses the Top Byte Ignore (TBI) feature of modern arm64 CPUs to
> -store a pointer tag in the top byte of kernel pointers. Like generic KASAN it
> -uses shadow memory to store memory tags associated with each 16-byte memory
> -cell (therefore it dedicates 1/16th of the kernel memory for shadow memory).
> +Software tag-based KASAN uses the Top Byte Ignore (TBI) feature of modern arm64
> +CPUs to store a pointer tag in the top byte of kernel pointers. Like generic
> +KASAN it uses shadow memory to store memory tags associated with each 16-byte
> +memory cell (therefore it dedicates 1/16th of the kernel memory for shadow
> +memory).

It might be helpful to be more specific vs. saying "modern arm64 CPUs".
Does the "modern" qualifier suggest not all arm64 CPUs support the
feature?  (HW tag-based KASAN below is specific, and mentions ARMv8.5.)

> +On each memory allocation software tag-based KASAN generates a random tag, tags
> +the allocated memory with this tag, and embeds this tag into the returned
> +pointer.
>  
> -On each memory allocation tag-based KASAN generates a random tag, tags the
> -allocated memory with this tag, and embeds this tag into the returned pointer.
>  Software tag-based KASAN uses compile-time instrumentation to insert checks
>  before each memory access. These checks make sure that tag of the memory that
>  is being accessed is equal to tag of the pointer that is used to access this
> -memory. In case of a tag mismatch tag-based KASAN prints a bug report.
> +memory. In case of a tag mismatch software tag-based KASAN prints a bug report.
>  
>  Software tag-based KASAN also has two instrumentation modes (outline, that
>  emits callbacks to check memory accesses; and inline, that performs the shadow
> @@ -215,9 +222,31 @@ simply printed from the function that performs the access check. With inline
>  instrumentation a brk instruction is emitted by the compiler, and a dedicated
>  brk handler is used to print bug reports.
>  
> -A potential expansion of this mode is a hardware tag-based mode, which would
> -use hardware memory tagging support instead of compiler instrumentation and
> -manual shadow memory manipulation.
> +Software tag-based KASAN uses 0xFF as a match-all pointer tag (accesses aren't
> +checked).
> +
> +Software tag-based KASAN currently only supports tagging of slab memory.
> +
> +Hardware tag-based KASAN
> +~~~~~~~~~~~~~~~~~~~~~~~~
> +
> +Hardware tag-based KASAN is similar to the software mode in concept, but uses
> +hardware memory tagging support instead of compiler instrumentation and
> +shadow memory.
> +
> +Hardware tag-based KASAN is based on both arm64 Memory Tagging Extension (MTE)
> +introduced in ARMv8.5 Instruction Set Architecture, and Top Byte Ignore (TBI).

Is there anything inherently tying tag-based KASAN to arm64? I guess if
some other architecture supports MTE, they just have to touch arch/,
right?

You could reword to say that "Hardware tag-based KASAN is currently only
supported on the ARM64 architecture.

On the ARM64 architecture, tag-based KASAN is based on both ..."

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200828111221.GA185387%40elver.google.com.
