Return-Path: <kasan-dev+bncBDBK55H2UQKRBU7OZKNQMGQECJMM5SQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33d.google.com (mail-wm1-x33d.google.com [IPv6:2a00:1450:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id 278E6628B92
	for <lists+kasan-dev@lfdr.de>; Mon, 14 Nov 2022 22:47:00 +0100 (CET)
Received: by mail-wm1-x33d.google.com with SMTP id bg25-20020a05600c3c9900b003cf3ed7e27bsf7335200wmb.4
        for <lists+kasan-dev@lfdr.de>; Mon, 14 Nov 2022 13:47:00 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1668462419; cv=pass;
        d=google.com; s=arc-20160816;
        b=TrxjiXG5JTab9PlksYoRrzbeLGQGyQEd1re/igasoUSoEtbZ+Bn7VyapydlrIBvAMQ
         9/t7NxJSiMUtvCOPX+JHmYgnUIZwXui4JjOmokwdyAYHtggukPlNRQN7b7mgr6m3fTTE
         FQBk+TOXqskXcygEWGnXn5amO8pHKlWmrm4Zm+HuHFvVhu9tCEpFayyfaXZc2G8Y8uwK
         GDTXME12MOl1sEXGXIh7RcUz8/Y8QvJI5iTpB9uuSw58p/U7k2YSIno32k/9MV+cmAI7
         RxMxL1dPZUVO5567bYne9fHChxLq/j/oRoHx8kqQfHTrAe162mAQcf46dszAEuDHrCJu
         penA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=mej6cfVLk0tn0/h2g288wk3g6mEXI0mywIubmKc4RJo=;
        b=PxFqV8RCgyTNvwI/ZzJRUSBgB9+eQ/QF7WqikwXBk5X+HsDWTRoYkbfaN1/b8lAkfH
         sISw9TliH7eqFq3X5Z1gYcGi4qQqVAqp3shPYOiNZbyxBd6jWxc0zqiEcTSHjRj55Ksk
         MT7ptvq8jKDWSkBY9EzLe1GQ/9EEHHDtv0zY9PPt9f8rsy2XMy+2vuuiQ/f9+Icn6MSt
         yNyu36ATEZGU2h59CFrn4/uqLurJyc8yw3OyIhet2O3OunCwF/RGZArXoNInl/ubthlk
         xHdMs8cJgJraU1/jTgEjHxpSzwrUWAYDMhqVW2xem9aaHrEJQfwrg/jCH36hTX3g88st
         Yq8g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=Mt3AqQMk;
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=mej6cfVLk0tn0/h2g288wk3g6mEXI0mywIubmKc4RJo=;
        b=RoK2L1VDNs4qkeNHcnGYI9Gs+iksBEGr1abtUNJGpiZWpC/YAT+74VyR7ogWYw9KKz
         1WBWWon30d+EyjEIMi3sbtBFKB8BmoL/n7AXBkjg2czRKFV+NJhke8vnwwY+J+aGBL4t
         XMsjh5SMUdk73m0M0upktSyqBUf1z40ihlxT9wld/HE4EPhzpykYb/XrNmPiY0shbBw2
         DJg7Oo0ZkBgDE7DF497uoEtilPKPohootT2jnpRvRbn8gjlbgzKs/hAz29zwYA3IQR7B
         lpvqKk/BJDJrvkgr3ZR16/ecc7X4aC01LleOYMevnxRnUn04V/WqgsZWiGq5EFOdALPa
         E+YQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=mej6cfVLk0tn0/h2g288wk3g6mEXI0mywIubmKc4RJo=;
        b=cWK19Pq6ZZMoDajIwn42R5QslJGplRQIF9WUYEcaUuBdl4CB85WLSoHsItiUISRXv9
         +W3CoeceGAPPIatwzzc+s1oaxfyko8diQEEAgvnZ6xULuNWKHBpvX0+niDF3ozVTEldG
         0HL4KAueIsPyeLHq21ErTSOXMA+X6MD/Rt4y0SAwCAzix/asPeMncwHJgTXhmFTy4Siu
         nfWR+al2YMIkCOX/I3QO+P1xVRTfjrcKiokuMpuEF+M0GDgoUUkZbKGbueQI4ubiSWxU
         pH1N9tapIvIZrRbTPXpbaUoaZ3vvBoHQ6QiOYJ4cdja+CHMpuJaT7Eb9aTOBhVVaCyeG
         ASZg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANoB5pmn+dtSy+oH31rNVdjJAZu3tFrT1aYZy5XwDRCpa/Pm6rXHje0i
	veggEYjXMv/IUfNfmuUxZes=
X-Google-Smtp-Source: AA0mqf7wXx9XPzYW29V9GF1jxTJXLK3dT/3uJmaoobVdPIomccfnf4hV7Pl91XSiMNypFDOPC1egsw==
X-Received: by 2002:a05:600c:448a:b0:3cf:6182:a458 with SMTP id e10-20020a05600c448a00b003cf6182a458mr9329797wmo.70.1668462419554;
        Mon, 14 Nov 2022 13:46:59 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:602a:b0:3cf:9be3:73dd with SMTP id
 az42-20020a05600c602a00b003cf9be373ddls7726090wmb.3.-pod-canary-gmail; Mon,
 14 Nov 2022 13:46:58 -0800 (PST)
X-Received: by 2002:a05:600c:1e86:b0:3cf:5657:3791 with SMTP id be6-20020a05600c1e8600b003cf56573791mr9440979wmb.34.1668462418357;
        Mon, 14 Nov 2022 13:46:58 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1668462418; cv=none;
        d=google.com; s=arc-20160816;
        b=rf3/Ot0ZFLjyezoZb9GoXiyVRzu8K6XOMlzbQuJVeksLpSKU+J21R2Nrgz2/XjCmE5
         ygbTvCJe/y2T4HwgGYgW0luqUvLvkEv4iTGqDCTpzUuljm6Zv4h82DDHbW8JyIxX0kck
         Bq/R/Sf9SUNl3gwruPKSv9q/DcfrSmxDGp3b9p52FXQ8tjUAsSg2PfaOJnFWwZq4SRni
         7laHccZ+5NU2S+wO8ei8hTuuE1WmyA8SJZ+RexErD86ggBaMlY6d0Ra+a/t8o3fRO82Y
         yEbTi8MpZ/IgnzRZ2UIUdKd9f369WEJ7u0S8DSo0EA9J/5+9BVm6Tfz4QvaVV2Y4JLgJ
         9WHA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=zR+/p7R1t4TzeOU8mz6hY5ameEwAhb4NtsNQ0xjhUD8=;
        b=pDI2yFSSAg8aDg1w9cX2RaFUecpEUee+THC84gyeyONvh8yzSP3euvZpdAidv6/nrq
         1HH+8V+uVGmnBJyQcB7YsRn7R+YgQ3RsGYOjRqPXx421xBllLBftq1Xjf6DpbSLXVzxc
         KkwiDibeFCv8kaPD8HRJXztm3fESIZepSPU1qhsAYDCIx4F6q8BxnYDSvAoLgRNmvRYT
         eFCYF2Zm8HqlS+frv1371zKOMv2XO2HtB7hkWnZ7CgsyWIFvT4nM96u92wNaRCnCDdgN
         5WnbDHgiLUsB6pCIQ03a3HIsIRqFzKLONVNu8lfpwyKmRq9hXQSAhjiUTPLyk1gAiItM
         yEhQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=Mt3AqQMk;
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
Received: from casper.infradead.org (casper.infradead.org. [2001:8b0:10b:1236::1])
        by gmr-mx.google.com with ESMTPS id co7-20020a0560000a0700b0023677081f0esi356496wrb.7.2022.11.14.13.46.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 14 Nov 2022 13:46:58 -0800 (PST)
Received-SPF: none (google.com: infradead.org does not designate permitted sender hosts) client-ip=2001:8b0:10b:1236::1;
Received: from j130084.upc-j.chello.nl ([24.132.130.84] helo=noisy.programming.kicks-ass.net)
	by casper.infradead.org with esmtpsa (Exim 4.94.2 #2 (Red Hat Linux))
	id 1ouhI9-00Fo7J-44; Mon, 14 Nov 2022 21:46:57 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id 9EE67300422;
	Mon, 14 Nov 2022 22:46:49 +0100 (CET)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 1000)
	id 8BA352C777C44; Mon, 14 Nov 2022 22:46:49 +0100 (CET)
Date: Mon, 14 Nov 2022 22:46:49 +0100
From: Peter Zijlstra <peterz@infradead.org>
To: Sean Christopherson <seanjc@google.com>
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
Message-ID: <Y3K3SVOMvGMteAtd@hirez.programming.kicks-ass.net>
References: <20221110203504.1985010-1-seanjc@google.com>
 <20221110203504.1985010-6-seanjc@google.com>
 <3b7a841d-bbbd-6018-556f-d2414a5f02b2@gmail.com>
 <Y3Ja33LyShqjvmQZ@hirez.programming.kicks-ass.net>
 <Y3KAp+yNQ54IKvTn@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <Y3KAp+yNQ54IKvTn@google.com>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=casper.20170209 header.b=Mt3AqQMk;
       spf=none (google.com: infradead.org does not designate permitted sender
 hosts) smtp.mailfrom=peterz@infradead.org
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

On Mon, Nov 14, 2022 at 05:53:43PM +0000, Sean Christopherson wrote:

> Wrong one, that's the existing mapping.  To get back to v1:
> 
> diff --git a/arch/x86/mm/kasan_init_64.c b/arch/x86/mm/kasan_init_64.c
> index af82046348a0..0302491d799d 100644
> --- a/arch/x86/mm/kasan_init_64.c
> +++ b/arch/x86/mm/kasan_init_64.c
> @@ -416,8 +416,8 @@ void __init kasan_init(void)
>          * area is randomly placed somewhere in the 512GiB range and mapping
>          * the entire 512GiB range is prohibitively expensive.
>          */
> -       kasan_populate_early_shadow((void *)shadow_cea_begin,
> -                                   (void *)shadow_cea_per_cpu_begin);
> +       kasan_populate_shadow(shadow_cea_begin,
> +                             shadow_cea_per_cpu_begin, 0);
>  
>         kasan_populate_early_shadow((void *)shadow_cea_end,
>                         kasan_mem_to_shadow((void *)__START_KERNEL_map));

OK. It now looks like so:

  https://git.kernel.org/pub/scm/linux/kernel/git/peterz/queue.git/commit/?h=x86/mm&id=14ca169feec3cb442ef4d322f8f65ba360f42784

If the robots don't hate on it because I fat fingered it or seomthing
stupid, I'll go push it out tomorrow.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Y3K3SVOMvGMteAtd%40hirez.programming.kicks-ass.net.
