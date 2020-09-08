Return-Path: <kasan-dev+bncBDWLZXP6ZEPRBDWK335AKGQEGWNYUVI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43c.google.com (mail-wr1-x43c.google.com [IPv6:2a00:1450:4864:20::43c])
	by mail.lfdr.de (Postfix) with ESMTPS id 6DFEE2613A0
	for <lists+kasan-dev@lfdr.de>; Tue,  8 Sep 2020 17:36:47 +0200 (CEST)
Received: by mail-wr1-x43c.google.com with SMTP id y3sf7097543wrl.21
        for <lists+kasan-dev@lfdr.de>; Tue, 08 Sep 2020 08:36:47 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1599579407; cv=pass;
        d=google.com; s=arc-20160816;
        b=Y2B9JrPdvcovU3mhweAbqJRBAyovB4Exw1l4tqCM0kh+33Y1n5Wb0HRBIhmc+SZYLZ
         wFv95FZqfDOmw9/Jjm9/gCrInRTTnmWMv33Rn4I2h9qMSU6Ymp7y5nUU27QepdJYadps
         2rvFEzgvyFH7ZaL9m4C/G5gbnquNAnnpLr/R2Xkfqn8jTINGiw6kt2lOf/AsCy2Ir4g+
         js0xWaUkUtZTNHyWPAQZ7tiwsA+lAvrTBgD/j+7drfp/gpPkfWtyDFo17/IUGms2nSVY
         0zu923I7Srz+4w/F5tPA60JoZ2OElXcT8gOBN3pWNRXb+dDETkkd5oUnuruJJjRKRcll
         kF0g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=Zwye+id7/A2jACzUGn3Yw1Vnarmj7B+/TvTIM5ZbrDI=;
        b=Ah4R4wvgMvssA50rsPp6bAf8Tj1LSk3fOCIvBQTj3ix+tfaxS9UF33l/uiTeC6N9Pz
         olBYkUBg3b07weOt28j32NnorRvJ93OHZd4nqTP90QVhl+7Ot1izxODohsMjjRYH5XOA
         YTluvHzDcN2z3pDIqdbwb2WFdjE6gOjTn3tMEUs/kj7bt8QXbUjQSvj25cIn206qOHtJ
         zo09t+Zna/nsbgk3DQQGsAgPLunvnOE8xcpBbNZ0NckcGBVflz2A2Ur08W1Ss0c1JQJf
         ccf3rwxecIV5Wswdgzc8IMbqAr1zgoGCeb6GyBxygzV8Ig374LfE0E3cFDklV70mvfKv
         wJQA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.15 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Zwye+id7/A2jACzUGn3Yw1Vnarmj7B+/TvTIM5ZbrDI=;
        b=PbbVr7qCx8pbTT9m+JBZoNaRfOauyJyn5nON4i2xc8QNNnh+TKff5B1V0WAh+eKNX3
         Ije/ff2AKnHws7nwECu51E+rbvlTNItMhxuRijj/5rILRX9R991zN6reDph6gIM/yNkx
         sm2ASwbXYjxCMAKIX1QKDu2b2t6Ep2KnohzN8zpja1DT03hd4guW94Du6dqz5pxaMgFV
         2YWn5OxYe0K6XMgIhENi82vdxQfuYt0z4lUSv24rVjB/b+l9CNyLLqP8IEDq8IrW6Ocw
         fVyn/L57IAjTwhZu933i5i79DbuhHY5pgZfb1l5Rb5EuI32MjJz8Pmr2xnDbd9nf2SBS
         NI/w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=Zwye+id7/A2jACzUGn3Yw1Vnarmj7B+/TvTIM5ZbrDI=;
        b=O5M4c+SwOlxyqNTHsRSeR5PJWCynu9cSk0CzhS5fbSeegjcI7rMka8azPCfXPWh4Ay
         OFq+PNyrLoFeN/sjRgP5V9i/plCil6bb0hiCtcG3sfHoRvQDHweuJBgyDDmQamupUY4i
         TSlTou7LZXc+rKfZzag4T3FEG+SriO1HMq+xd9Q5nja9HPE2qTD9OCu69IryVhKkvXye
         +5kL5H1JisUnquo5VwHEMDTWf9VGFgkXY2yFnfJ0zCoL8hF5GSLAXNxXPnh98jTS9lBW
         X1lLcu1/4XU2koODipaOq34+pkeY3bvsFSzyC1gHYsnI+1/LevKdt5VD/RNX+/G/9XJt
         M4gA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531JG18XdEiTsIwObVisjet5gqTG3BKpV5ntTPHrZFBOI/Y7wQ8a
	gmQfAjQfhDXgddj8caqprFw=
X-Google-Smtp-Source: ABdhPJzSkWoY3+OCaOsAVjUjz2Eu9kLkilo5ESRKQVQcPkJjnWHjufok9CR0BCzwhAt6E7To7Y04Hw==
X-Received: by 2002:a1c:5641:: with SMTP id k62mr123001wmb.13.1599579407204;
        Tue, 08 Sep 2020 08:36:47 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:8:: with SMTP id h8ls14362970wrx.3.gmail; Tue, 08
 Sep 2020 08:36:46 -0700 (PDT)
X-Received: by 2002:adf:ef48:: with SMTP id c8mr227757wrp.370.1599579406442;
        Tue, 08 Sep 2020 08:36:46 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1599579406; cv=none;
        d=google.com; s=arc-20160816;
        b=KH2hMOs/syXI9Nr1kysmhEaID1KhVF+9nzPSR82EMKTu/c/Pueak12UDpVIZPFeD3W
         /Q4Bajsm1m3cTegfpnhxpKdX/8rKlntd8dvR1y4w4IzTkwmxFPpaN9bsdw/i/8V3sn08
         +/z7hdOt5reowObK3bhzpwChMXBUtNabbgLrP052fSB2cb5gKMLoCGhiMaz78WJHRuFS
         fxZ5Z5UUhQh+VLDEOZ32gDds2V1SPt6J/6Di+6ECxDK8v7q+CQ51gZnYdy4XVza2U8Ul
         FnO4nVsXSI2KyTpsc9lIqoetomLeSheVaff33/n2FbDSNRmkvJDZjMWIy1QgbGzk6HNB
         tdDw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=8wE0CzrgbTyqHj2xQ7gRx6sWNlQGfQxpSKP0DswOy04=;
        b=cpzHEv5vt5oQ3dkOpNmPVCiBn5LYxIvM/Q1kgQYJTQTmNHRzd73W1Ixk57WJ8n9kkd
         mkNXrqdTxTYuoMI8QeTZc0szZKPPifIFH15hsKM6kZ4br6TqHnSw3cJEQmEZleMj4CHf
         2kpkEt71F2u7ZXtsqAIuhuE7WyduyWDyqDdQl3FXR/EuimHmThX63+d4CS3w20AL9VXG
         I3a20KgYGXDeZwsLLtUIpai7rcYzq8/AL1ZjYSoVHKbx/nOgJbzd5oQbYEfDTeZ1RUGk
         5KNKK4WoR/WVwecL27MldhuBj6I4ykf/eIohZeclmY3EpUpFBMkHs/MqlWIF4L3K5Vaz
         8yiw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.15 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from mx2.suse.de (mx2.suse.de. [195.135.220.15])
        by gmr-mx.google.com with ESMTPS id w2si627331wrr.5.2020.09.08.08.36.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 08 Sep 2020 08:36:46 -0700 (PDT)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.220.15 as permitted sender) client-ip=195.135.220.15;
X-Virus-Scanned: by amavisd-new at test-mx.suse.de
Received: from relay2.suse.de (unknown [195.135.221.27])
	by mx2.suse.de (Postfix) with ESMTP id A93B9AC26;
	Tue,  8 Sep 2020 15:36:46 +0000 (UTC)
Subject: Re: [PATCH RFC 00/10] KFENCE: A low-overhead sampling-based memory
 safety error detector
To: Marco Elver <elver@google.com>, Dave Hansen <dave.hansen@intel.com>
Cc: glider@google.com, akpm@linux-foundation.org, catalin.marinas@arm.com,
 cl@linux.com, rientjes@google.com, iamjoonsoo.kim@lge.com,
 mark.rutland@arm.com, penberg@kernel.org, hpa@zytor.com, paulmck@kernel.org,
 andreyknvl@google.com, aryabinin@virtuozzo.com, luto@kernel.org,
 bp@alien8.de, dave.hansen@linux.intel.com, dvyukov@google.com,
 edumazet@google.com, gregkh@linuxfoundation.org, mingo@redhat.com,
 jannh@google.com, corbet@lwn.net, keescook@chromium.org,
 peterz@infradead.org, cai@lca.pw, tglx@linutronix.de, will@kernel.org,
 x86@kernel.org, linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org,
 kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org,
 linux-mm@kvack.org
References: <20200907134055.2878499-1-elver@google.com>
 <e399d8d5-03c2-3c13-2a43-3bb8e842c55a@intel.com>
 <20200908153102.GB61807@elver.google.com>
From: Vlastimil Babka <vbabka@suse.cz>
Message-ID: <feb73053-17a6-8b43-5b2b-51a813e81622@suse.cz>
Date: Tue, 8 Sep 2020 17:36:44 +0200
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.11.0
MIME-Version: 1.0
In-Reply-To: <20200908153102.GB61807@elver.google.com>
Content-Type: text/plain; charset="UTF-8"
Content-Language: en-US
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of vbabka@suse.cz designates 195.135.220.15 as permitted
 sender) smtp.mailfrom=vbabka@suse.cz
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

On 9/8/20 5:31 PM, Marco Elver wrote:
>> 
>> How much memory overhead does this end up having?  I know it depends on
>> the object size and so forth.  But, could you give some real-world
>> examples of memory consumption?  Also, what's the worst case?  Say I
>> have a ton of worst-case-sized (32b) slab objects.  Will I notice?
> 
> KFENCE objects are limited (default 255). If we exhaust KFENCE's memory
> pool, no more KFENCE allocations will occur.
> Documentation/dev-tools/kfence.rst gives a formula to calculate the
> KFENCE pool size:
> 
> 	The total memory dedicated to the KFENCE memory pool can be computed as::
> 
> 	    ( #objects + 1 ) * 2 * PAGE_SIZE
> 
> 	Using the default config, and assuming a page size of 4 KiB, results in
> 	dedicating 2 MiB to the KFENCE memory pool.
> 
> Does that clarify this point? Or anything else that could help clarify
> this?

Hmm did you observe that with this limit, a long-running system would eventually
converge to KFENCE memory pool being filled with long-aged objects, so there
would be no space to sample new ones?

> Thanks,
> -- Marco
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/feb73053-17a6-8b43-5b2b-51a813e81622%40suse.cz.
