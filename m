Return-Path: <kasan-dev+bncBDX4HWEMTEBRBT6PRKAQMGQEWCQPZJY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43f.google.com (mail-pf1-x43f.google.com [IPv6:2607:f8b0:4864:20::43f])
	by mail.lfdr.de (Postfix) with ESMTPS id 8A480315285
	for <lists+kasan-dev@lfdr.de>; Tue,  9 Feb 2021 16:18:40 +0100 (CET)
Received: by mail-pf1-x43f.google.com with SMTP id u124sf13004173pfb.0
        for <lists+kasan-dev@lfdr.de>; Tue, 09 Feb 2021 07:18:40 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1612883919; cv=pass;
        d=google.com; s=arc-20160816;
        b=u1VK4wWAMr9fr1FoviWPUrElmOVkjhDyrHRvPQcj+H4Km1vylojW3D8f99wbixua7f
         e+8mg/7sVY/wqJ7YLzIP4u8jsIUfpzeQmqxgC33YFv2XBBIwP2EnzVO5Yc2Rw19cFzwk
         ACX/mw4XIXjq6u1+i8iRe2t9wCkEDRyXjwI2zisIUWWKP2aujikew/mJU80D3INHacrJ
         FjpLPq5TY+GrxGKA2Bgqj0yjlGF8TgkiiKDibqG4gE0GOg5CugDNNJIlYpPcoPy4J8AU
         6V7C9Bt5xw6lV31dnErL5DfJ81ra7/gfXZNVSi3z7vr5qMhhUwr+JagRUCGCKo+bUzE5
         Agyw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=TV9YMLv86sdzua/PDgJ1JUAcpCaVoHu1+zMcsCSJ2Ek=;
        b=KR5704zuCfWjFE4VD5yjzFYg8YQPQ361s9nGbcQzr8a/RyNyogIywhpqAMkuE7crcl
         /Xvxe0HM3Cv/Cd9vITwJHRNjdy5MDPFSjxwvZtUuCkuCFpO9ATI31RoKoq88vKhp5q1Q
         bdM//Ds5nDhGfQkqsJ6Lyuh5H86yYC7KL1mZ6XQ33EoGoNCgzhAXsmenO6rdKUl0rL/y
         gDJZS+mlPnmh4whGPEp6I4soKSkvEQoXw+7W6KY0CuV3+P79i1/Ukc7FayFeXIEQfgnt
         MTQFJINx3jTNCQQP7HbdsNKjY10oBy59xKnNgKdgyVNyQ33h3gVZfaOQB886YvSQoJJ6
         ZQWA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=bvzxM6Qp;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::52f as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=TV9YMLv86sdzua/PDgJ1JUAcpCaVoHu1+zMcsCSJ2Ek=;
        b=d3KenxKph7jbqgMXa4sOP753naBXUWkEdbopXc1xcrNhn5gQBndVop9eC9l1g7cU6j
         kYXGtLHfv3oK2WEI3GPVRnRcSbqaLVxPFMF18z4ajcZR23Mti+sqxZNOxLxIO/7MztLo
         fKdNvwKlDCfvOkctV/mn1TgvI3VLWu0PUbwprMVnYZKlqSsbs6XOLZJDEZJMNxErMx6d
         vjhXee5KezoMOKQ8rMRj2dduXYKenT8xAcL36lMi9vVYSZY7NtTIaBftqymT+UZA5CAQ
         iqzLeDT6k2GuGnc47HHT79d/X7axoHINRLKLo6CDHa16wTtPuZT4+7m9sJzeh21tAZ1y
         0x6w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=TV9YMLv86sdzua/PDgJ1JUAcpCaVoHu1+zMcsCSJ2Ek=;
        b=Ry+1FMQFVftZQFYHOJA6XNt+PpTrpMTBv9aBTwTKbigh3a/8gG6Zck9K9yWKlyKOKO
         rLBEwKyw4IXRzEq0mvx/7ucf8hnLV1A8Y86Yx8qD82pWOgOS6LcyqYbZ1Py94JViW1Jx
         O31grZ6uJ1WMq9OyPFk6MQ34rQRWtau1M2alUUpJ9gj4WsRugPJrntQIlFUSekQfdqak
         vaDIo1BOQQYYN8GDYhQNZti9TIRLGlMES/2Dl2VWLlEJv+LZXnmSb7DDT30uVuGTNppW
         9r4bNfjxVad9kZof527thjh2BufgVjMj7ka6p8IIV8AmSpPgeFOfk4oSOjD0LGydbT0B
         8TgQ==
X-Gm-Message-State: AOAM531VOf832jPtqj93PA9y65h52SgZra17jLpE1gLWpohcK2ZyVp0R
	NWY+U8MLP5Wc54Dj1nAYtsM=
X-Google-Smtp-Source: ABdhPJxZd/uf4MmzHkp1VqWP4F8r4USDAYXW6CYTirDg22WQmhiRfGcmYTeLqACgAC3TYkGZpzodLQ==
X-Received: by 2002:a63:1b22:: with SMTP id b34mr22023475pgb.337.1612883919299;
        Tue, 09 Feb 2021 07:18:39 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:ba17:: with SMTP id s23ls1638436pjr.3.canary-gmail;
 Tue, 09 Feb 2021 07:18:38 -0800 (PST)
X-Received: by 2002:a17:90a:a88:: with SMTP id 8mr4461804pjw.120.1612883918639;
        Tue, 09 Feb 2021 07:18:38 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1612883918; cv=none;
        d=google.com; s=arc-20160816;
        b=rOxfYnq8yyKg+16xF7DNbxPnhFDG969+ljKD1HcQc1arN5zLO88De6V1IOR2QbwAFD
         Z6lbtkqmZGgRIOXAJPrQiqHJmVV0lOYlAG9HClrB0EZtIlcpa3ap/Y32RP3AyagA7cBe
         v0nCbxb3PsEEh7D57qGExRKAtPHsl3rKdD994GVeoAsPMz+mDOnsUlUj4Rymh2CXYYhQ
         XRul7MjQ/heNsvwC/kz7BAbHhRd+ih+KjwPo05+Eb9fCVfjKIDWnHHwuVzmxM6ObP4F4
         w2v4sPh24r3O2mWdnBlm2YBiJ68TLoogQ8QFOcrKARwEs5oUSof7X9tsLFDID6dkcIL5
         BF7Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=G8z+fvqZU/74uT7CiRrXKR/wJqmxTaOLawIi73kIU2s=;
        b=zDZweSdJBAkhqFyTTbdJtoWpa7Stca1m0xJdWG0Dbsu/O3z6tYXEXXuUYnZ5pv5lty
         XNmhSTkT7IN0Xj7effIF7iLDRzHiygW0Qi0W++wJsha8FeZ7HGdb7xwIlXJ7q9NOv6JV
         EH+39eHFbzsPAtM/X8xhMOQX2R4l8bMGfOE3+zmWZnLuGiDlFA678fQ1mTGARXolHEi7
         knx8JLfezhJWvOZaG5qay5crr2lT9OkaLFFkrGbMKpvcYzIdAGx4uEyCieFPDsGtH7pQ
         7zYiLkVJ21pv7SWPt5ZrS8/8wmGO99/uRpY8joN7db+I4OrM0YeKznOhhdEY81TZYE2z
         or8g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=bvzxM6Qp;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::52f as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pg1-x52f.google.com (mail-pg1-x52f.google.com. [2607:f8b0:4864:20::52f])
        by gmr-mx.google.com with ESMTPS id i23si137385pjl.3.2021.02.09.07.18.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 09 Feb 2021 07:18:38 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::52f as permitted sender) client-ip=2607:f8b0:4864:20::52f;
Received: by mail-pg1-x52f.google.com with SMTP id b21so12632816pgk.7
        for <kasan-dev@googlegroups.com>; Tue, 09 Feb 2021 07:18:38 -0800 (PST)
X-Received: by 2002:a63:a0d:: with SMTP id 13mr10387786pgk.130.1612883918125;
 Tue, 09 Feb 2021 07:18:38 -0800 (PST)
MIME-Version: 1.0
References: <cover.1612538932.git.andreyknvl@google.com> <068ab897dc5e73d4a8d7c919b84339216c2f99da.1612538932.git.andreyknvl@google.com>
 <20210208174247.GA1500382@infradead.org>
In-Reply-To: <20210208174247.GA1500382@infradead.org>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 9 Feb 2021 16:18:26 +0100
Message-ID: <CAAeHK+yn9ggY5FmwROMZU-q+hQEMgUcqTAo_v=_aFaVhfd6VHw@mail.gmail.com>
Subject: Re: [PATCH v2 12/12] arm64: kasan: export MTE symbols for KASAN tests
To: Christoph Hellwig <hch@infradead.org>
Cc: Andrew Morton <akpm@linux-foundation.org>, Catalin Marinas <catalin.marinas@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, Will Deacon <will.deacon@arm.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Peter Collingbourne <pcc@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=bvzxM6Qp;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::52f
 as permitted sender) smtp.mailfrom=andreyknvl@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

On Mon, Feb 8, 2021 at 6:42 PM Christoph Hellwig <hch@infradead.org> wrote:
>
> On Fri, Feb 05, 2021 at 04:39:13PM +0100, Andrey Konovalov wrote:
> > Export mte_enable_kernel_sync() and mte_set_report_once() to fix:
> >
> > ERROR: modpost: "mte_enable_kernel_sync" [lib/test_kasan.ko] undefined!
> > ERROR: modpost: "mte_set_report_once" [lib/test_kasan.ko] undefined!
>
> Please put this under an ifdef for the testing option that pull the
> symbols in.

Sure. I'll send this change as a fix-up patch instead of resending the
whole series.

Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2Byn9ggY5FmwROMZU-q%2BhQEMgUcqTAo_v%3D_aFaVhfd6VHw%40mail.gmail.com.
