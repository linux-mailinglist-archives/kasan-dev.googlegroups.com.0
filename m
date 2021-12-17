Return-Path: <kasan-dev+bncBDDL3KWR4EBRB3FI6KGQMGQEGMHYGPY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33e.google.com (mail-wm1-x33e.google.com [IPv6:2a00:1450:4864:20::33e])
	by mail.lfdr.de (Postfix) with ESMTPS id D6760478C97
	for <lists+kasan-dev@lfdr.de>; Fri, 17 Dec 2021 14:45:16 +0100 (CET)
Received: by mail-wm1-x33e.google.com with SMTP id 144-20020a1c0496000000b003305ac0e03asf2960017wme.8
        for <lists+kasan-dev@lfdr.de>; Fri, 17 Dec 2021 05:45:16 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1639748716; cv=pass;
        d=google.com; s=arc-20160816;
        b=iTipDEB1C5oz8eIxlh9B/d3qUIP/GKZFTMrRhud14CK2JaDKKATE2sudqS2jECuT3G
         ZGjwZ3Ra5NU5WTiUx50aWnIwQMJoZ/3eLOeSInbIvAom1mZbHxsB5x3rvenBwow5+ky2
         m9GwEOaup9rDdZ5mg/q8HZq6m6DiAAZLGds3/Y64hEwYgLtlI0r3qoGx0OfJFjIJhGig
         8xZ3ntVRz9UTEsUZRvj85+odzTdOQbkOhkENyog239/TPfk7dJ0qTwVXqajEtYJAmH2/
         HarcvjJB6kc+EXBlZuq+8u5RnVOBdSps80NGHOyGn8uVxJOye05pMs4c/drWN0A/EQp9
         0Mcg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=HMT4fRuvBbvIbWXdCesldlcZ9RPRax/cP5ZoXHSB27w=;
        b=mENn3/++66K0VTnFWoYIB4u8oNflPIae9Balq/s4R+fMZZrBbimjWq4xYCxRi547fY
         br7RsWDVcLAnDx0i/t1V95BGBdKCPsR2IsAtj9CHOzcc8BX6jSI1G6hZAVqDPLxRrdvy
         kqcOCzEa1f0jgbp01o+HhiJ8NY9JpkUArVQABtmKFPdXh/JyCRUrhodIAatzz3+NAjsU
         MF/p9r2cLr3va8DaBL7PPKi51AIveLLD6JRxHu2pe1fNALRDuOdflqvoELZx+YmSJC4c
         PJw7xR0bHmC5FJMLw8S5HTRirOqlEARcl7L1VO+1aUIrv85jA6edwAi0NaAO0aCqY5/0
         /BNA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=HMT4fRuvBbvIbWXdCesldlcZ9RPRax/cP5ZoXHSB27w=;
        b=CWWePwAdwLtaf3mbd984xmUp72mvpFB58i41im5A6jqmV6v3kzCllvyXEbxicPgj7P
         4I433QJRD+heQZH57hRLiXT1P8Oqq/xhEnKRcVOD37YfrPBjzbyH5cSNCP4Bn8zOZ3WL
         IO29A4ezePJcoHO/FuC93GR94Iu/H22A4cnlK3yZKO/leAn23IF2038LCwwTd+CRdtvm
         sXck+aLBqGZh1jpHgjhJ5xJb78k7s6mNdHITt4z2c3CHQLtTeybAwzry53kuOpmAX7io
         qKjrsXW1ZA9NS5AHadU7CBwZ/CmA7lhBfWQExPe1e9H9lejgEFlf8Cjva0dg9nOpgYeU
         UstA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=HMT4fRuvBbvIbWXdCesldlcZ9RPRax/cP5ZoXHSB27w=;
        b=sGqafJb0YHTdVOhu/uICwoILNwb7PetqEinISg7jwNuzu86bhabPzR+k1M/2+nh2yP
         avR5s7c+7NebzfEkuBfkTqe4EhCh/1mScp6H/9I/DfPsxIQzevaKnewnWQ80JtxqBgR+
         qhPjAQN7IaGBBjkr/i7vcbIGPetyB2qxgzV9anCcT7cY80v9ocot72S41tNZGUh+saig
         DN5uvXncB3oklQlm4Ld6uUvHxIrcHdicZrvUIY+OXP6CY/1CG1PMHjXEdeTrTx+uTt1x
         HgyGf5r44rNXBB3P3E2n4OhkNvhVjTJZtIXRJXPkJ8wqD11AcUT2vB2bzI0vvXb5oMob
         y1Kg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533GGuedIGf5tudRoipZTLjFLMg+9VLQM+imNr9ARPRpDrksyRpR
	bhfLUY7cPD6OkUvrK/3oQc0=
X-Google-Smtp-Source: ABdhPJxin70eknbvDGn//8Hw2qgGKTtiJ9sOWeG73p6LxN5dB6YmoFkaM937zU298+WmQstdDRJYEg==
X-Received: by 2002:a5d:4bcf:: with SMTP id l15mr2704794wrt.618.1639748716463;
        Fri, 17 Dec 2021 05:45:16 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:3b56:: with SMTP id i83ls138323wma.0.canary-gmail; Fri,
 17 Dec 2021 05:45:15 -0800 (PST)
X-Received: by 2002:a1c:90:: with SMTP id 138mr9775542wma.27.1639748715510;
        Fri, 17 Dec 2021 05:45:15 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1639748715; cv=none;
        d=google.com; s=arc-20160816;
        b=SiZZ3M2fg2uOcqBgh9HKTCcgruO0Xe1aq+hhf0dCHmuPQbfknc8fDXxU3xjbzI0nNX
         tgsCp8+hsxA2UHoIN8Jyhz8v3VqjUe14al2HvUqNXCjaBRQ+/TDnckop3h9Tp7ZERs55
         t+NSo9K+C6xUYyKB0Bh6v+YUD1pZ2kQ3xBkl5Q0Hp6AXzvkjH4z2gBiuEuupq/n2jg/C
         fzR4TUFqzOrvlj8fmQNRKJGV496kTc1aJZm+Ru0pZ3ST/5kQMQKgabIMUgHFb2UnfHg4
         Ws9WGLEf4wYeTtGJod5ikjaKzXcbl1WCPd+MRAjzEf4ywe0EsDK9ratUaECvfUrQxoKd
         PYLA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date;
        bh=aoYqu+a9CUYRmef3DoH9cSz7a581S6szXhlOS6VaXG8=;
        b=rmtygHODiiiBpZ8/IhQ7xefhujlPKy0kvMdv8v4elS/rh54lUqkf2jjiQL4I3EQ3CB
         8XdDO/RRfxurFIbPCyFW5FlzFUwUQDOr+27UpIp28S6FR4ioYuSpOFDvkgtkkEY8/CWn
         DYKqmSIail/XTG3oBG2PADSxftOYXV9/ItBl9gSIvS/1r/CLOiGlzMDURvxpoDm06tZK
         m4IfBUQneZWwAay68VJpwM6kbMq735jQDPj69naXgJiEIVawMEzSNClCnRr28GTysw6X
         M9PoZCRicKhdQkX0YJ0ErvbVvZcnt8gsrcaiFT9Ib6Ydlp8e5pLSzD3mVHi4AJaRzPYO
         PBRw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id g9si459945wrm.3.2021.12.17.05.45.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 17 Dec 2021 05:45:15 -0800 (PST)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id 4E03D62210;
	Fri, 17 Dec 2021 13:45:14 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id D017FC36AE7;
	Fri, 17 Dec 2021 13:45:10 +0000 (UTC)
Date: Fri, 17 Dec 2021 13:45:07 +0000
From: Catalin Marinas <catalin.marinas@arm.com>
To: andrey.konovalov@linux.dev
Cc: Marco Elver <elver@google.com>, Alexander Potapenko <glider@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com, linux-mm@kvack.org,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Will Deacon <will@kernel.org>, Mark Rutland <mark.rutland@arm.com>,
	linux-arm-kernel@lists.infradead.org,
	Peter Collingbourne <pcc@google.com>,
	Evgenii Stepanov <eugenis@google.com>, linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: Re: [PATCH mm v3 31/38] kasan, arm64: don't tag executable vmalloc
 allocations
Message-ID: <YbyUY/A1G+7SmdRo@arm.com>
References: <cover.1639432170.git.andreyknvl@google.com>
 <4a5ec956a2666c1f967c9789534a8ac4d4fe26f9.1639432170.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <4a5ec956a2666c1f967c9789534a8ac4d4fe26f9.1639432170.git.andreyknvl@google.com>
X-Original-Sender: catalin.marinas@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of cmarinas@kernel.org designates 139.178.84.217 as
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

On Mon, Dec 13, 2021 at 10:54:27PM +0100, andrey.konovalov@linux.dev wrote:
> From: Andrey Konovalov <andreyknvl@google.com>
> 
> Besides asking vmalloc memory to be executable via the prot argument
> of __vmalloc_node_range() (see the previous patch), the kernel can skip
> that bit and instead mark memory as executable via set_memory_x().
> 
> Once tag-based KASAN modes start tagging vmalloc allocations, executing
> code from such allocations will lead to the PC register getting a tag,
> which is not tolerated by the kernel.
> 
> Generic kernel code typically allocates memory via module_alloc() if
> it intends to mark memory as executable. (On arm64 module_alloc()
> uses __vmalloc_node_range() without setting the executable bit).
> 
> Thus, reset pointer tags of pointers returned from module_alloc().
> 
> However, on arm64 there's an exception: the eBPF subsystem. Instead of
> using module_alloc(), it uses vmalloc() (via bpf_jit_alloc_exec())
> to allocate its JIT region.
> 
> Thus, reset pointer tags of pointers returned from bpf_jit_alloc_exec().
> 
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

Acked-by: Catalin Marinas <catalin.marinas@arm.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YbyUY/A1G%2B7SmdRo%40arm.com.
