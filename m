Return-Path: <kasan-dev+bncBDWLZXP6ZEPRBOM533VQKGQEUJM2WFA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x239.google.com (mail-lj1-x239.google.com [IPv6:2a00:1450:4864:20::239])
	by mail.lfdr.de (Postfix) with ESMTPS id 7AD5DAE988
	for <lists+kasan-dev@lfdr.de>; Tue, 10 Sep 2019 13:53:30 +0200 (CEST)
Received: by mail-lj1-x239.google.com with SMTP id s2sf1633553ljm.6
        for <lists+kasan-dev@lfdr.de>; Tue, 10 Sep 2019 04:53:30 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1568116410; cv=pass;
        d=google.com; s=arc-20160816;
        b=0xxpLlLLPxqxNxymZCHVTSyQgYUdCBc0SjUFpQSRCZ0Ex7FHiLCOYKXEjmH7me6dFE
         31oZC4Qlv34D/ugSccsFAdR3uR8lCSSyXcBEeY7oHDV/iX7HpRG6ZztaoaIurIUaSd6i
         AkzcTD18iBRWUjy0S1lcMWnwFaltttEsvciXOAdJNDwvYb5vV1c5D2+wJ7mEGKaH/hvt
         G+aZNreXx21NlIWLcDazdpMLnc0cpJFtT9k6n+OygM9KvDBiYyw39sWfgkZYuu4D1DNw
         VmC/QrTa71zsZNL0eXzHom5QgKFu6xpEaGKMj33/SO4OKdD8eu8jooQFOJ8EGR+bqlnJ
         Nc5g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=5XlsmQn90P51+QGoROG6YgJfrLBSA6mhUGz3i42osAU=;
        b=r7FaZ7a8qjuSRtzdFBATv5ve8f2RA8p1P1CLKJXJJbiYUG7cRyav4gf8/6NKzINurU
         a7GdtTR5QVExyq7l9SaygxFCqbRFXNj1fpxJHNJ00yA1C1hMKRkITDExrFrQIo1SSIli
         Mb8ztaQRKufgJU7wMvg6qXbx43+OBUPdR0riJWnQMFneyWLgaKepgvKzc+ctgbqVY0gN
         ZUddgr+b+btZxt8HRAWTuX5mRiFdBLfzZXgXOUyIpNFnD+F3/wze/03xEv8Q105Kuzrp
         oWAl9RDWICt+HzzEXGTlryoDmI0ZnOjAbOa3JNPqc68ygnuzbB7dRMLfOeJGfAM1+TEB
         t1FQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.15 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=5XlsmQn90P51+QGoROG6YgJfrLBSA6mhUGz3i42osAU=;
        b=R7P2m7mQH07WqH4pMDlxs+43J1tGnImQECTOZ5AmP4MBjHdnsV6uGt32h/2Ks8m9Bm
         JpzT9BYqB1XS2iqq14FuYyv1JmNo4+uvbMLKc5i0+77XOi3Ypxkva1FrynuM5o1m8FLq
         8BNOce2O0dKUfh3zycWsUSGZzqTlzaFJ6xHWPvuAsq5/2vz5/DbC2/GIIjBIPmbRdZuZ
         nTIS+D+QBso9VzRzjdLuZpguyOs2L2S/sleET0Osw5JWtC1q1XJ+AQQZbm06MDybIwI+
         eOfAwtLDWOjqaFQU+x/xqX401V3/7IPJLZNydFCMZ88Ooe5ytYalMLnVFSNcjj2zeqtG
         jvIg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=5XlsmQn90P51+QGoROG6YgJfrLBSA6mhUGz3i42osAU=;
        b=e4JsG7DHHXPKob/ATFCETgQ5Ag2a/kBg1kFH26J6WJRnoD35f8jUOBLUAniqMNBH+h
         ja+sOLZ5VOFyVSDlagd8dtqq2g2nrIKi4EpGxBi6cpAUbm7mS/12yDuwL0c5uwczZ34A
         F1+voFnGWPnOZsGK6TNuSkLIcVEBkwbxKL10lN5SrtL+r6iybWuyoV9iMJ6jrslHtMXV
         GLuzxFQKhUd5FYnuBH2TUGrghLmwCG+FRKu9EnaJkpl19MPFUDmxsCVTI/aJC4jGcput
         gF1/FAnq5oQDBQUiGppUwbmkqD+LB336RehaCparsg4CipnPsB48dGj9+RtOQclmZGWV
         sEcw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAUS0EWm222FSipoXG5PVaYgVAM/7TxWP2AMbwD2ylptWdd3BokN
	p793dR99/lVcNh9kZ3muC+A=
X-Google-Smtp-Source: APXvYqwzMF33znQbbzMAEI+dVjAK0oePf2IpUADWSWTMreNdTKFl9j3KJwtPQvVetowO33Ap2CHLmQ==
X-Received: by 2002:a2e:3a01:: with SMTP id h1mr1860982lja.171.1568116410104;
        Tue, 10 Sep 2019 04:53:30 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:5f55:: with SMTP id a21ls1689721lfj.0.gmail; Tue, 10 Sep
 2019 04:53:29 -0700 (PDT)
X-Received: by 2002:a19:5f55:: with SMTP id a21mr20874025lfj.56.1568116408989;
        Tue, 10 Sep 2019 04:53:28 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1568116408; cv=none;
        d=google.com; s=arc-20160816;
        b=J3o/VAQje0AexFWPKSRuK9nHeMihQV9hp9+hyFcYrww8emBcpmMHL+SHHi/p4sYVjm
         OIU++MZr9UNg12EeA8gvsMk3xnS9xDF3+r64spLpJEY49rGXAGKS/LEVGrcaRiazsyg6
         4ieaZIGJGjHq4GVkY5Yexk9z1YMOxF2t/ov9JWkWc83nk0ztsPEOvPaYUG1AfXwfXwE4
         vAwY25qzQ6M8sll04CF6M8eblq7Htj9gFitdKLdwNLQXWCGtKfvn8OdtY7qvB9i6yc3E
         Vy3l7zYP/wh2f7AyR71YIvp0lacgjhVxIAi2hulcxPVRKkuQpxNl1ocufboJdsRyqtxO
         f9CQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=CbX2FEkadAat3q38Tu9TxNfnJGJ6eiN4NhilyOmYsh8=;
        b=anRAunBw2OhFCnKslec9KubzYDz/RoML+DqjnVTTX31YNfcvWpKthn3gfD0lLYYOJL
         ZEAku1a2qrL1ncNDWz9DiCGA/Vsh2DhAHIelIgHt8/0zU78nNyRZF0ECM81lw9xFoZTQ
         nJho7/+7SX/O7VTG/Fgx/zcrKEo/BFhFi+o+uwun9vFIKhd2EP/OfsIRJF4bSfAO8SGu
         uIpbn2vfJBsdJbJKDFX61keuE0W89jObRdZwxG3ApOHQGn9rz5daMPOuHj2FCdDF4rns
         vognp6nzp8jq4GGTh1yx15jhetS/g1TeZsDpkFzBzw4Nq5YJ83ECqh+VfFZ7TAUnrshS
         AQCQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.15 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from mx1.suse.de (mx2.suse.de. [195.135.220.15])
        by gmr-mx.google.com with ESMTPS id q26si881391ljj.2.2019.09.10.04.53.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 10 Sep 2019 04:53:28 -0700 (PDT)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.220.15 as permitted sender) client-ip=195.135.220.15;
X-Virus-Scanned: by amavisd-new at test-mx.suse.de
Received: from relay2.suse.de (unknown [195.135.220.254])
	by mx1.suse.de (Postfix) with ESMTP id 82DF2B061;
	Tue, 10 Sep 2019 11:53:26 +0000 (UTC)
Subject: Re: [PATCH v2 0/2] mm/kasan: dump alloc/free stack for page allocator
To: Andrey Ryabinin <aryabinin@virtuozzo.com>, walter-zh.wu@mediatek.com,
 Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>,
 Matthias Brugger <matthias.bgg@gmail.com>,
 Andrew Morton <akpm@linux-foundation.org>,
 Martin Schwidefsky <schwidefsky@de.ibm.com>, Will Deacon <will@kernel.org>,
 Andrey Konovalov <andreyknvl@google.com>, Arnd Bergmann <arnd@arndb.de>,
 Thomas Gleixner <tglx@linutronix.de>, Michal Hocko <mhocko@kernel.org>,
 Qian Cai <cai@lca.pw>
Cc: linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
 linux-mm@kvack.org, linux-arm-kernel@lists.infradead.org,
 linux-mediatek@lists.infradead.org, wsd_upstream@mediatek.com
References: <20190909082412.24356-1-walter-zh.wu@mediatek.com>
 <d53d88df-d9a4-c126-32a8-4baeb0645a2c@suse.cz>
 <a7863965-90ab-5dae-65e7-8f68f4b4beb5@virtuozzo.com>
From: Vlastimil Babka <vbabka@suse.cz>
Message-ID: <4faedb4d-f16c-1917-9eaa-b0f9c169fa50@suse.cz>
Date: Tue, 10 Sep 2019 13:53:23 +0200
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101
 Thunderbird/60.8.0
MIME-Version: 1.0
In-Reply-To: <a7863965-90ab-5dae-65e7-8f68f4b4beb5@virtuozzo.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
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

On 9/10/19 12:50 PM, Andrey Ryabinin wrote:
> 
> 
> For slab objects we memorize both alloc and free stacks. You'll never know in advance what information will be usefull
> to fix an issue, so it usually better to provide more information. I don't think we should do anything different for pages.

Exactly, thanks.

> Given that we already have the page_owner responsible for providing alloc/free stacks for pages, all that we should in KASAN do is to
> enable the feature by default. Free stack saving should be decoupled from debug_pagealloc into separate option so that it can be enabled
> by KASAN and/or debug_pagealloc.

Right. Walter, can you do it that way, or should I?

Thanks,
Vlastimil

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/4faedb4d-f16c-1917-9eaa-b0f9c169fa50%40suse.cz.
