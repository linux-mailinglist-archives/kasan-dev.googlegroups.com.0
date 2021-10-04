Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBGGD5SFAMGQETPGCZ7I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33d.google.com (mail-wm1-x33d.google.com [IPv6:2a00:1450:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id D73584212F6
	for <lists+kasan-dev@lfdr.de>; Mon,  4 Oct 2021 17:45:28 +0200 (CEST)
Received: by mail-wm1-x33d.google.com with SMTP id 200-20020a1c00d1000000b0030b3dce20e1sf10157475wma.0
        for <lists+kasan-dev@lfdr.de>; Mon, 04 Oct 2021 08:45:28 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1633362328; cv=pass;
        d=google.com; s=arc-20160816;
        b=sXdQip7ItQp85smXuIX1OeZ5iOsYXBs+IzqJPl2obM+/gWEsWLKdRrcsNKnz6BL3+d
         qDMZf2aRhufGkCQ7X53N3p0tzWGP2N0XBezqyaG8xidcHe2dZJU8XzCOqiOBiWq9/9ne
         2Aty0PBVgfKD/yXv8VxdDPjjiOy8qGjaXoSjVDTg13d3O894ZuILAbPLo13wbldJtGu0
         NyJvwiheJvA0ZDsyFsdTJpfnb2bUuHEtszrOFvFrITEM+6peie4VnyruDNMtsrz93Cfk
         D5paXzi+RvlXvomN+KO2UcPsDZPcvbyGbcoKlgZGjxJDKT4uPGXHYEgkrpWMpmfKd9Ks
         248A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=hbu8p3DXGA9j3tgeRioZ76GT1zwgrA3Fqsl0dJPnDes=;
        b=KBOW0rmCxDqtR/UD6ZbF0WScbuUSLk8H/YeNt+etGtFUDP/R4HvbvTIG8QaHNx0/TO
         JmkQc/SkqJXN/lqo/Z8hcxid86DW8fcpJfuATdlg/IrRFVQhOxblRjuWuZbYltGhvcPY
         B0f7q7rCqzA4yRJ7N3HAI3nPExfdQ/P8l8ZQsOwz7XNbrOV0vcWIgGLVfHph9tZ6dRov
         k5kXZi5X754Bl62N3n53AB1e9I1dlcf2q3izE2+FDCrjJoNbYbthKAgoFtOCvXHawFui
         Amzpu3nlRObVPZ9sHUsq5SaL2d2rAY4pVCvDxjjRDoBpfbNR5/yzTl3+1YZ8GINsVTm4
         7ffQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=hbu8p3DXGA9j3tgeRioZ76GT1zwgrA3Fqsl0dJPnDes=;
        b=RBGdxfUcBn7LgzYxD9ybWEqtDcU6yWKWl6epVWfJ5bM5UfltXCNwnRWW5GEQJsx4rD
         MT6RBqreUkjHrf90Rw5arksr+kp/JWrg1hToevXqtQuUi/rWM3PlaB69SBSnoBaQschl
         UOMgzeJMmfh6pEBUhzlKJlWrDbrr24SSHe0XrwAUw6tFcmYvxONqJ4pWfHhRasWFdjiq
         t9WvWDvPqEJld+psFpAhtslMZfjaVSfjZFkVBCl6oQv4ssnBH2lz6Pbz2qbLHJVIQv5/
         3OsY6tboNDrjJRrobjuHaMEdPcAMAsC7LLKEyyKe4F/tqqVRMgZut9+sbWv5pOwXWuUQ
         WIbw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=hbu8p3DXGA9j3tgeRioZ76GT1zwgrA3Fqsl0dJPnDes=;
        b=ZSc20oK2YOoGHyDczGNVIw17z0IMbLzHEyaHB4m9ibx6dr3N2vTz9B3Mk7VPAqYt0h
         zYxTeQvC0YuNpz3IwHyUbfyRhunOfL8lQfBFvSj0UuuaFWE3yBiD+nm+rVQq8U8GuLXz
         YGa9by4PlsRXMmuTcFC0M80ce+UG29RwHbv9XOAnEa2y6Wu9er1qYJbkToeZQ33H49D+
         TYIJ5LAWlT/WkGIOVhA4domrdmmhuV+K4imq8plp6mNtMqo5NNZVBfZ1m0kHs4gPGq7g
         ZVZd3aJ2wwVbZRuKdY28pcqsPuWkD01bV9cvYdYbEBM7s5wQ8PT+iS9uFftmCJ4MSh2V
         z/rw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530w9CqHHtPAXOlfYcmf+XAuIVY6RoI1KzeQl7MNHQR06DFyWmsd
	1Cm5bYARADMxfIPfq3tlZXg=
X-Google-Smtp-Source: ABdhPJz4jS40GLpGEMQPJbFQbWl9cbYhdbGNRHtUBpWQXuV7cEZsE55fXPwaiLCtNp5gH1vgyDZO+A==
X-Received: by 2002:a1c:44c:: with SMTP id 73mr5320012wme.45.1633362328551;
        Mon, 04 Oct 2021 08:45:28 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:3b8f:: with SMTP id n15ls10063370wms.1.canary-gmail;
 Mon, 04 Oct 2021 08:45:27 -0700 (PDT)
X-Received: by 2002:a1c:2c2:: with SMTP id 185mr1304511wmc.85.1633362327652;
        Mon, 04 Oct 2021 08:45:27 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1633362327; cv=none;
        d=google.com; s=arc-20160816;
        b=L/0ms1lZTFAFKnBp6OVukcaJ0Ej16Lo45fE/4jW+NLYoQ0JV22Z/vi4wEmYPKpxk3b
         YofsWZYhKHjlzoZAjtqIlXzeZvn4OJ0wPnUbncKOUsCt8n+ZVNV+sB8tkQuHBrCNZHCG
         p91uLzSgMzo805ZWWJiz4rpajzNH3ltGyXXS6J7rLXu3/C7dLR9eKjogquauiCziKfrf
         PxTmW9WbQZlcVKpHf5gCLeaLfvLaPV8zBlLOUaQDVjpKx4UuIzdnEFBz0LW0DVAUhcb+
         BsKf91VJ4WWb8kNqvJKFQvmrr7BK3GDEaZRvARrpluBm6igrb7F7ELgL57TghvicdHeZ
         ZP+A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=zmok7DJGNyyA7oV6TEKsjzIASAjhXJvdxSESYfEt63U=;
        b=EFZtoWtzNT7fedtCVoe3PdKhAQwUbyca1TiMmcaMh1bJEl8bSX46D6agKEa9//vlJX
         F59mlbK4ot+ZUmA++JazKka0ebIoYq/V6bL//yHJlxRsjfJZ0m1EuMOBxZq2LMRMKCgI
         xRWS/d8F7BePVcpLGPcJy1fwZJ5WdKXnQkdadijpuaMXx16K+hZYWw+sZH4Lsw/gqycq
         qtBtj9bSeeSO0bH+JpydxQldWbeYcwtMHkQPCSGMaLfr9o/57fh2QK2bhjx1dTpgoJi0
         /jgTLTSf9svofIhARs16NrMR48FYNaES/3gh6mp3i3LyRQfmBrHMZeF+xfSCbMgaXh4a
         42MA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id d1si507033wrf.1.2021.10.04.08.45.27
        for <kasan-dev@googlegroups.com>;
        Mon, 04 Oct 2021 08:45:27 -0700 (PDT)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id E436FD6E;
	Mon,  4 Oct 2021 08:45:26 -0700 (PDT)
Received: from [10.57.53.1] (unknown [10.57.53.1])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 6701A3F70D;
	Mon,  4 Oct 2021 08:45:24 -0700 (PDT)
Subject: Re: [PATCH 5/5] kasan: Extend KASAN mode kernel parameter
To: Andrey Konovalov <andreyknvl@gmail.com>
Cc: Marco Elver <elver@google.com>,
 Linux ARM <linux-arm-kernel@lists.infradead.org>,
 LKML <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>,
 Andrew Morton <akpm@linux-foundation.org>,
 Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will@kernel.org>,
 Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin
 <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>,
 Evgenii Stepanov <eugenis@google.com>,
 Branislav Rankov <Branislav.Rankov@arm.com>,
 Lorenzo Pieralisi <lorenzo.pieralisi@arm.com>
References: <20210913081424.48613-1-vincenzo.frascino@arm.com>
 <20210913081424.48613-6-vincenzo.frascino@arm.com>
 <CANpmjNN5atO1u6+Y71EiEvr9V8+WhdOGzC_8gvviac+BDkP+sA@mail.gmail.com>
 <f789ede2-3fa2-8a50-3d82-8b2dc2f12386@arm.com>
 <CA+fCnZe-gogW1yMuiHhXmKXTsmfkb+-iWp1Vf9K6ZY9madtxfw@mail.gmail.com>
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
Message-ID: <3e6a5797-4690-ea54-c14b-75d6ca58e744@arm.com>
Date: Mon, 4 Oct 2021 17:45:41 +0200
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.10.0
MIME-Version: 1.0
In-Reply-To: <CA+fCnZe-gogW1yMuiHhXmKXTsmfkb+-iWp1Vf9K6ZY9madtxfw@mail.gmail.com>
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

Hi Andrey,

On 10/3/21 7:16 PM, Andrey Konovalov wrote:
> Hi Vincenzo,
> 
> Up till now, the code assumes that not having the async mode enabled
> means that the sync mode is enabled. There are two callers to
> kasan_async_mode_enabled(): lib/test_kasan.c and mm/kasan/report.c.
> Assuming tests support will be added later, at least the second one
> should be adjusted.
> 
> Maybe we should rename kasan_async_mode_enabled() to
> kasan_async_fault_possible(), make it return true for both async and
> asymm modes, and use that in mm/kasan/report.c. And also add
> kasan_sync_fault_possible() returning true for sync and asymm, and use
> that in lib/test_kasan.c. (However, it seems that the tests don't work
> with async faults right now.)
> 

It is ok by me, I will add the changes you are mentioning in v2.

> Thanks!

-- 
Regards,
Vincenzo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/3e6a5797-4690-ea54-c14b-75d6ca58e744%40arm.com.
