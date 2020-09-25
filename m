Return-Path: <kasan-dev+bncBDAMN6NI5EERBWPMXH5QKGQEMY4BKMY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x439.google.com (mail-wr1-x439.google.com [IPv6:2a00:1450:4864:20::439])
	by mail.lfdr.de (Postfix) with ESMTPS id 4ED4D27946F
	for <lists+kasan-dev@lfdr.de>; Sat, 26 Sep 2020 00:59:38 +0200 (CEST)
Received: by mail-wr1-x439.google.com with SMTP id a12sf1659585wrg.13
        for <lists+kasan-dev@lfdr.de>; Fri, 25 Sep 2020 15:59:38 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1601074778; cv=pass;
        d=google.com; s=arc-20160816;
        b=ub4+RN+WFFktbfapsBlUpzYBxpqc3EmXceAAWUHBufLTjUV7tJz2fXXhcMfvbgnmzu
         eb7hlXGF/6zJ3ivDv9Zl+ddxxcYdGQ+XauOBTy+WZwLYpJ0WsqeZvHI5PhCOQxMoWRtJ
         GtoghA3vCz2pDURASWxV/FNx14NaJmuwCdnozwzqz+f/GKaye/iNal8hYaQqctD/WQK7
         CrCShJ8zl8CgEqIxJKa3oa67P/SLJF06qjpTCCXwFVpyJy3l0K3+IOF7ZyvIcTTopbev
         qsgBERgHwVTZ6VHqF6VRvaf0nOLz7WFDqodJftUDsOiPHdXAB5saSUt5lHE0x7GdxsHb
         uOWw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :references:in-reply-to:subject:cc:to:from:sender:dkim-signature;
        bh=8V0nPewya+ww726HG4pF88yp8ZyN/619FY03I08LU8Y=;
        b=jr1EsVoRMo8J5y0TbHHdP06txD7xxSPI7dV81iTuZdUlNrzhiUf1uJQ6DHJxZPhE16
         Jt8mfpKLLWFa2mkT/e/sH55lP/u1oLNqm5tgNaknJRCyInniwGR9hbczFweFW+zyIIeY
         vfYPOjLrQXK3VM5XMdD84jrIpnld5dgIafdtL9YYP9/V1WzDF1yJJUuDKZ1H4jJqg0h3
         YiKXAbom7FRVriUa1ozj0agWVMzyEiuN5OfOCdzyMOh7QCz6YEfoS+gnjl/UIapMFhN7
         ewRhSzsFe6IPDCbb8qfn7Fm+ehqA0qSNOVMXraZSLKdU2pCa3t5CgUZTRWJ9iVn19vGa
         0fhA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=i68A1tT8;
       dkim=neutral (no key) header.i=@linutronix.de;
       spf=pass (google.com: domain of tglx@linutronix.de designates 193.142.43.55 as permitted sender) smtp.mailfrom=tglx@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:in-reply-to:references:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=8V0nPewya+ww726HG4pF88yp8ZyN/619FY03I08LU8Y=;
        b=Il9l9xbHmP4OHm2Jzn453x//umS4WQM6WSi4vTsYLgSZURar30D9OduHy60V3Onh1F
         1aF5tRSIWPGIMk7C6wUdCaxP+OYILLiF5x26JsY5TqnZFbBRRUeSglfK5pkBVqB/MAWT
         vnD37JQkE3/Cj5e0OqcXlKcgagOFdYuESIrZl5+kdPq01ltYJXPzoxT9p345XVpG1V+G
         ZZHF3DHCI1VAro2ufg/qEMo2Q6LT6XlS1fNi4ab/op2sdJY1iNkrl5eRb6j5+31s9y7H
         C1WVwCa2YofZq6fb8X770M3ZNN4ioD/k2G6+Qeb9805Yow4wIKoNX94N4ix6M0l0Hrxj
         CMSA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:in-reply-to:references
         :date:message-id:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=8V0nPewya+ww726HG4pF88yp8ZyN/619FY03I08LU8Y=;
        b=uiaUrBCkwuNjDsoKuMveGT/bYnMjTDWq14MDTHm+M4r18XAki0rgNmYfLOrlAgclgH
         9xA7v9zmT0dojGJUqAIk14pGkKNkUdeOzZb9rVzzdjKz3Q8Y6RhhPfOFsvReS1byZxC7
         WL0RODe4eBRS4t/C7Dr9YGcyZb30sah88fX6PNxeSwRrWCxRYPZt79hCZKpnC0hXKCAO
         OCuIHaGfYN84899J46eI9/DcsSmUh/ZuLGzQG5UrF0UHPCQRYO+P/DdIXEifRm6coEsd
         x0c9uGaQTpuSyf5FLzvkus0jOq2BodVBfprsNp9w8foPdwf0wcbuGps2c4e+tuE2+7ye
         atzg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531H9q92lcfmIggtXpRYq5iruv927YIkf/WprYAfs3vlOuNPnF9z
	fqj9xbJP6VyErMWiZz3rni8=
X-Google-Smtp-Source: ABdhPJwNrnrVKcNX+Oah2hi/DQzpCDpdKnSUcyzphc9+oyb423pI+bMhvPlPqmLVHoTXBedyl7iqIw==
X-Received: by 2002:a1c:3985:: with SMTP id g127mr852742wma.32.1601074778059;
        Fri, 25 Sep 2020 15:59:38 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:1b86:: with SMTP id b128ls223997wmb.3.canary-gmail; Fri,
 25 Sep 2020 15:59:37 -0700 (PDT)
X-Received: by 2002:a05:600c:20b:: with SMTP id 11mr770627wmi.147.1601074777117;
        Fri, 25 Sep 2020 15:59:37 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1601074777; cv=none;
        d=google.com; s=arc-20160816;
        b=rxdzntiByvLydgrHg8gys/4pV3dSw3KJzoDJU0sGSXxs2jGtTyJGhycVF/WpbklGVQ
         Pq4+IuCi7lBgaJW605ZVs+ARsHiHyuobxGJ9SQtK7/zR5sLibhKM4q/4PdVm6YeVURXz
         5gGcpdNTzdB5JXTH1hLXuk9CLZWbVFaz1xW0Gdt75rGoOuMxd8HThGx4NrbzD0LFsYSq
         ngUJIaU2jv/E4TqYJghYq2YWhaGs9074jq5cQ4BpuDpnKQ+Bwk1jlSRZQvdn6fo/bEhx
         USRO/AeeRwIteHWtftmHwaEDbdJHL4E48xQaOVza6hDH6J/SW8vqk0By9f6P1KDQArNW
         iiKw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:references:in-reply-to:subject:cc:to
         :dkim-signature:dkim-signature:from;
        bh=xNfIywwa8zLp7Ze2sUjIPjT6qUcXBaqd2I3y05VFQpk=;
        b=cqGV6TMxmxS/2hk1g5Vs6GLSdJkQhDosvJS5QQOSFyHkx5TFWAIkukCoMztUuME8HH
         k2IHlwU9BWo+WkKx7f4RPjTS2WjP9qx/cn6uSEdpttRdXOh3puEGOq6Es7H8H7I2ZpRn
         nWZOSKy5n5ERM2eywc7093tJt50yhEuWFDwy6QnnEXinp/Vi9o2vsok72zNxKaxyMxB0
         Qo5ROToT1yUtCh0+q5rQH+KJzQVu3HhOUA3OAznuygoboHKuica9R09YYb4wMIfCBFqZ
         4FvT6AoAeszaiaJzISr2p3zqbXpSsIaPmsvarX674XpKt+5SXXuULtIdzEdBkramKUtT
         t9aA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=i68A1tT8;
       dkim=neutral (no key) header.i=@linutronix.de;
       spf=pass (google.com: domain of tglx@linutronix.de designates 193.142.43.55 as permitted sender) smtp.mailfrom=tglx@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
Received: from galois.linutronix.de (Galois.linutronix.de. [193.142.43.55])
        by gmr-mx.google.com with ESMTPS id s192si10178wme.1.2020.09.25.15.59.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 25 Sep 2020 15:59:37 -0700 (PDT)
Received-SPF: pass (google.com: domain of tglx@linutronix.de designates 193.142.43.55 as permitted sender) client-ip=193.142.43.55;
From: Thomas Gleixner <tglx@linutronix.de>
To: Walter Wu <walter-zh.wu@mediatek.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, John Stultz <john.stultz@linaro.org>, Stephen Boyd <sboyd@kernel.org>, Marco Elver <elver@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, Andrey Konovalov <andreyknvl@google.com>, Matthias Brugger <matthias.bgg@gmail.com>, kasan-dev@googlegroups.com, linux-mm@kvack.org, linux-kernel@vger.kernel.org, linux-arm-kernel@lists.infradead.org, wsd_upstream <wsd_upstream@mediatek.com>, linux-mediatek@lists.infradead.org
Subject: Re: [PATCH v4 1/6] timer: kasan: record timer stack
In-Reply-To: <1601025346.2255.2.camel@mtksdccf07>
References: <20200924040335.30934-1-walter-zh.wu@mediatek.com> <87h7rm97js.fsf@nanos.tec.linutronix.de> <1601018323.28162.4.camel@mtksdccf07> <87lfgyutf8.fsf@nanos.tec.linutronix.de> <1601025346.2255.2.camel@mtksdccf07>
Date: Sat, 26 Sep 2020 00:59:35 +0200
Message-ID: <87wo0htqco.fsf@nanos.tec.linutronix.de>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: tglx@linutronix.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linutronix.de header.s=2020 header.b=i68A1tT8;       dkim=neutral
 (no key) header.i=@linutronix.de;       spf=pass (google.com: domain of
 tglx@linutronix.de designates 193.142.43.55 as permitted sender)
 smtp.mailfrom=tglx@linutronix.de;       dmarc=pass (p=NONE sp=QUARANTINE
 dis=NONE) header.from=linutronix.de
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

On Fri, Sep 25 2020 at 17:15, Walter Wu wrote:
> On Fri, 2020-09-25 at 10:55 +0200, Thomas Gleixner wrote:
>> > We don't want to replace DEBUG_OBJECTS_TIMERS with this patches, only
>> > hope to use low overhead(compare with DEBUG_OBJECTS_TIMERS) to debug
>> 
>> KASAN has lower overhead than DEBUG_OBJECTS_TIMERS? Maybe in a different
>> universe.
>> 
> I mean KASAN + our patch vs KASAN + DEBUG_OBJECTS_TIMERS. The front one
> have the information to the original caller and help to debug. It is
> smaller overhead than the one behind.

For ONE specific problem related to timers and you have still not shown
a single useful debug output where this information helps to debug
anything.

> I agree your saying, so that I need to find out a use case to explain to
> you.

Indeed.

Thanks,

        tglx

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/87wo0htqco.fsf%40nanos.tec.linutronix.de.
