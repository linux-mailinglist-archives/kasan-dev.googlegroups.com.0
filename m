Return-Path: <kasan-dev+bncBCAIHYNQQ4IRBLEBZKNQMGQEWNLBDSY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23d.google.com (mail-oi1-x23d.google.com [IPv6:2607:f8b0:4864:20::23d])
	by mail.lfdr.de (Postfix) with ESMTPS id 14BC5628789
	for <lists+kasan-dev@lfdr.de>; Mon, 14 Nov 2022 18:53:50 +0100 (CET)
Received: by mail-oi1-x23d.google.com with SMTP id a5-20020aca1a05000000b00359de30f06dsf3610169oia.7
        for <lists+kasan-dev@lfdr.de>; Mon, 14 Nov 2022 09:53:50 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1668448428; cv=pass;
        d=google.com; s=arc-20160816;
        b=iSEjtnhdx/FxViarHGPl8nPa49Ap5cWGbpp22lC3gsiAVCVeNWrNdfOHpfv1myUjYU
         txGLFxkKZahNq79OtyFcV24w4tXwEA9ktsjensZLNblw64VoszacGEqQqbU1TV2TiNgu
         iLorOrViHIAvpVcIfFlVSAffZkeYn8KR9H94vN8RQc34HAxBP9gAQ5J4UmfEVkrvAwu6
         w66KPtf14u/ZHovWcKjDILj3RpVGwBkP9ePFFnmOL+P9s0AerppUOPP2XKJmlJTjEqZh
         ST8jvdEkMjwZelaaGIuNWTRRw/qTtAWp2rJugKdpoCHusVQe0nOr5u7y/vxu4Cqr2V+U
         VXAw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=zx2dFUjLIHtnbuQLS4evme9siJ97ASM0pVzR03MY2nQ=;
        b=TMeuX+pGv43k8PukWG41bu0eWDXRY2C5wpzUuRtIko5xn+H9CvaoVv5QfKIbnBKWux
         QWUUbGod+Lr2wrdMgIdGXA0tHRHQTDjMuBBtjf54skKWKB5PV9mK8vu/kBGYqhBLr2Ha
         FJMcCNbH3Tc/OZVvnScSBC7ymgLVO9DAcdFVJ5fK/5/a+/ID2ShX9HmMykv8dM3I05nM
         zhZto/CmQFUy1QJepln5E3bsPVr9n9KUgMPLpThQopG7fqQ0NObuf/9ev0ZaCaqhiTsL
         1ldCLhxmOTri52bmuiey6W1T2S2MejcHxJah3+KoRu5PI15YeO7EMVsSJpU1SPqFEyRs
         W3Mg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="hqx/0/7R";
       spf=pass (google.com: domain of seanjc@google.com designates 2607:f8b0:4864:20::532 as permitted sender) smtp.mailfrom=seanjc@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=zx2dFUjLIHtnbuQLS4evme9siJ97ASM0pVzR03MY2nQ=;
        b=ipBCop5v75jlMe5C++YSd9A5dANs9iVzpkQj0plvsfkI6EbAWu9GYDSa9V5TVre1QV
         aiVoL+B/lzZN1j4udpSltPPI1oQizVz0Z2cHTDvSy9GJ3LTHJG4axR5eRvVLTKURKv7h
         YPIgxiT8yxITn2v37hA8psFyhJojT4m5dO5jyhBx11zL2vCnat4BKRaReWGJFvtFfRsM
         Ar3mwwgwUAmLeFiCdkEZ8wz6TvBITCi8PaG5PkheNqteXsKj8hAFJ+7/gkcJqcBHaU1y
         EYo04/lP9nxoNPvhJq97CvlQUnQ28MAOxzkqoDc8/bA1Drp6zhgznZRGvzXv4haZcq6t
         VAgA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=zx2dFUjLIHtnbuQLS4evme9siJ97ASM0pVzR03MY2nQ=;
        b=jSbgc7C+41X1x6164J1BRvnkY8ecSIPLHxD2zxSTjMTcm2vSxK4/Le15lJ4ZhDUz7/
         5H0HJZemc+u5iyOFCM9jRtS02225+kM24AXqix5RwVr/XmnK7VYcrTkdw/osxI527CFW
         PPx7JnHLohsnwVjGa0kbEWMkSXD58/zUQYWdYKMjxoFvwq8dOQ9LNlDWmz9ouWMJIAu9
         vRGFpJgkITug0Pi9W1NMLxAsR2QCXvhx6mOJUnszDep6UKUcOmUhbIPLI6BIpRFc2oDw
         j6sEc3Q5vP6GELvcE1wBWjLJ1HWeqhg4UbduOnPPBLUlZHQtecWpHOGqt1DyThVlE+St
         jKJA==
X-Gm-Message-State: ANoB5ploqVDQmuoYHINktxZpUghc9p07MvoU6i0NecxkcRPhGLMdEy5V
	RpO4p/rQlBZ71Oz7EoBZKkA=
X-Google-Smtp-Source: AA0mqf5m1itVsz7zD7yUYmJY6AgHnxj2a7pIgnWeRVkIWXhysokdAq7a0bofoV6crQPBMybKkd94XQ==
X-Received: by 2002:a05:6870:3a2e:b0:132:c8d7:c29f with SMTP id du46-20020a0568703a2e00b00132c8d7c29fmr7589524oab.7.1668448428674;
        Mon, 14 Nov 2022 09:53:48 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:5c3:0:b0:35a:9ab0:cca9 with SMTP id 186-20020aca05c3000000b0035a9ab0cca9ls3610873oif.7.-pod-prod-gmail;
 Mon, 14 Nov 2022 09:53:48 -0800 (PST)
X-Received: by 2002:a05:6808:204:b0:35a:2c4c:32f8 with SMTP id l4-20020a056808020400b0035a2c4c32f8mr6246112oie.163.1668448428142;
        Mon, 14 Nov 2022 09:53:48 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1668448428; cv=none;
        d=google.com; s=arc-20160816;
        b=uqb6xMX0jrmd9MZHMHHTweWveV8FbjL2uT9qVFdJlf4aaBUeWIY28Kacf7uZ5Yh7a5
         rLR5ZM5qKdgM8IFmYb/bVlwsu0qe9tne4vXdQ2FuCB5Vqo+PwzaP8T/hXz1QKCR0FIug
         aO8fjNY+K4VuzHnOW0f/DNpYgH5WVbxU4ZpBqqv/Yve3PtvN2ZiFHOL7O3mo2Tjub82U
         wzveomwkHEDJlmYtIe9HtAn5OW1hVFVcyj0qcsy8Lr8UxVvfjjQMndbVKQ3cgoIA40a+
         lu1ZmATxxezjUNZZuIFPf1ZMAmjcMWoLAmTaASWMiGesviWAFhKqm7momRbs84BbZWk7
         8Gyg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=knbOKZDiFpA41kgl5NgFlIeuBQLx4K+3AhrI93TxZQE=;
        b=JC9/QP0FzADkjugBDZOxgvs03yHz7C4C0qjvqowkmbOO77IMhzrka1eqnv5/6E412L
         cvgEoVOlhkvdvSDwTCGCNExeEuBv/m3Qj8j0BsuS3q3rgBv0Z4ZZcq0N3vy0yUFW6A83
         mPRKhdukJlwYBrIQW3oLI3eA3dWhGfc/x9jA2VfqKZx/eFC+MBhAq4AzL8MwgfQrmfXK
         LXrrugbW/n46LNYRvC1lklFfQKgL73cutozNGAG+VCsNTFEgVw6m8Cu4L6vx9+lOTkbi
         ff96uXWDqV5z9CokU5pncNz+nd6sr4E+WWGzEwhVsmtGUEmjNRWi+iQpQwUCkjkSbZnA
         lFSA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="hqx/0/7R";
       spf=pass (google.com: domain of seanjc@google.com designates 2607:f8b0:4864:20::532 as permitted sender) smtp.mailfrom=seanjc@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pg1-x532.google.com (mail-pg1-x532.google.com. [2607:f8b0:4864:20::532])
        by gmr-mx.google.com with ESMTPS id c132-20020acab38a000000b00359c478fb51si578365oif.0.2022.11.14.09.53.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 14 Nov 2022 09:53:48 -0800 (PST)
Received-SPF: pass (google.com: domain of seanjc@google.com designates 2607:f8b0:4864:20::532 as permitted sender) client-ip=2607:f8b0:4864:20::532;
Received: by mail-pg1-x532.google.com with SMTP id n17so3251236pgh.9
        for <kasan-dev@googlegroups.com>; Mon, 14 Nov 2022 09:53:48 -0800 (PST)
X-Received: by 2002:a63:1720:0:b0:46f:f93b:ddc8 with SMTP id x32-20020a631720000000b0046ff93bddc8mr12199883pgl.389.1668448427350;
        Mon, 14 Nov 2022 09:53:47 -0800 (PST)
Received: from google.com (7.104.168.34.bc.googleusercontent.com. [34.168.104.7])
        by smtp.gmail.com with ESMTPSA id x2-20020a170902b40200b0018685257c0dsm7763635plr.58.2022.11.14.09.53.46
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 14 Nov 2022 09:53:46 -0800 (PST)
Date: Mon, 14 Nov 2022 17:53:43 +0000
From: "'Sean Christopherson' via kasan-dev" <kasan-dev@googlegroups.com>
To: Peter Zijlstra <peterz@infradead.org>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Dave Hansen <dave.hansen@linux.intel.com>,
	Andy Lutomirski <luto@kernel.org>,
	Thomas Gleixner <tglx@linutronix.de>,
	Ingo Molnar <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>,
	x86@kernel.org, "H. Peter Anvin" <hpa@zytor.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
	syzbot+ffb4f000dc2872c93f62@syzkaller.appspotmail.com,
	syzbot+8cdd16fd5a6c0565e227@syzkaller.appspotmail.com
Subject: Re: [PATCH v2 5/5] x86/kasan: Populate shadow for shared chunk of
 the CPU entry area
Message-ID: <Y3KAp+yNQ54IKvTn@google.com>
References: <20221110203504.1985010-1-seanjc@google.com>
 <20221110203504.1985010-6-seanjc@google.com>
 <3b7a841d-bbbd-6018-556f-d2414a5f02b2@gmail.com>
 <Y3Ja33LyShqjvmQZ@hirez.programming.kicks-ass.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <Y3Ja33LyShqjvmQZ@hirez.programming.kicks-ass.net>
X-Original-Sender: seanjc@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b="hqx/0/7R";       spf=pass
 (google.com: domain of seanjc@google.com designates 2607:f8b0:4864:20::532 as
 permitted sender) smtp.mailfrom=seanjc@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Sean Christopherson <seanjc@google.com>
Reply-To: Sean Christopherson <seanjc@google.com>
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

On Mon, Nov 14, 2022, Peter Zijlstra wrote:
> On Mon, Nov 14, 2022 at 05:44:00PM +0300, Andrey Ryabinin wrote:
> > Going back kasan_populate_shadow() seems like safer and easier choice.
> > The only disadvantage of it that we might waste 1 page, which is not
> > much compared to the KASAN memory overhead.
> 
> So the below delta?
> 
> ---
> --- a/arch/x86/mm/kasan_init_64.c
> +++ b/arch/x86/mm/kasan_init_64.c
> @@ -388,7 +388,7 @@ void __init kasan_init(void)
>  	shadow_cea_end = kasan_mem_to_shadow_align_up(CPU_ENTRY_AREA_BASE +
>  						      CPU_ENTRY_AREA_MAP_SIZE);
>  
> -	kasan_populate_early_shadow(
> +	kasan_populate_shadow(
>  		kasan_mem_to_shadow((void *)PAGE_OFFSET + MAXMEM),
>  		kasan_mem_to_shadow((void *)VMALLOC_START));

Wrong one, that's the existing mapping.  To get back to v1:

diff --git a/arch/x86/mm/kasan_init_64.c b/arch/x86/mm/kasan_init_64.c
index af82046348a0..0302491d799d 100644
--- a/arch/x86/mm/kasan_init_64.c
+++ b/arch/x86/mm/kasan_init_64.c
@@ -416,8 +416,8 @@ void __init kasan_init(void)
         * area is randomly placed somewhere in the 512GiB range and mapping
         * the entire 512GiB range is prohibitively expensive.
         */
-       kasan_populate_early_shadow((void *)shadow_cea_begin,
-                                   (void *)shadow_cea_per_cpu_begin);
+       kasan_populate_shadow(shadow_cea_begin,
+                             shadow_cea_per_cpu_begin, 0);
 
        kasan_populate_early_shadow((void *)shadow_cea_end,
                        kasan_mem_to_shadow((void *)__START_KERNEL_map));

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Y3KAp%2ByNQ54IKvTn%40google.com.
