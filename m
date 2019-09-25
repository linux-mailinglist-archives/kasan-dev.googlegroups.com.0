Return-Path: <kasan-dev+bncBC5L5P75YUERBWHMVTWAKGQEPXXYYCI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x240.google.com (mail-lj1-x240.google.com [IPv6:2a00:1450:4864:20::240])
	by mail.lfdr.de (Postfix) with ESMTPS id B55C2BDB45
	for <lists+kasan-dev@lfdr.de>; Wed, 25 Sep 2019 11:41:44 +0200 (CEST)
Received: by mail-lj1-x240.google.com with SMTP id w26sf1414652ljh.9
        for <lists+kasan-dev@lfdr.de>; Wed, 25 Sep 2019 02:41:44 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1569404504; cv=pass;
        d=google.com; s=arc-20160816;
        b=WzB94n3tLQa0FYzzX5bSwKzUg6ghBmtmYSvmpScAMdEkzx0i6s+CgNNv0qikWQEHWI
         40eVnM3jHmBkqt9SoBxSOcILDYtBAbiJRwhz21MTW1MObKakrtu/cw5I2O5nrjk8tb2k
         eN5hPhm0tUymy1TKTbSmoM0GF8JBJWrYYC3Fs3pimPXf+CrJuhVx/or5rZdLOulB/H1G
         Pg26hJZjGzXQEXM6doniHmgjjveMqw42VAOElWZsF2je53gRT/m/8gErqQhMAAFeMFdI
         Ya7qIYZ21eKLwQ31Qfsqjck9uoSzAsk5wCciaMX1xAwF6IykvhakaeH/xPjgsiaKG81y
         fCPw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=XJ9fa7V1EG0r/rHi6uBv0ZrfwP0Msu5dhohq8FmiQ3Q=;
        b=hqEEyfA37EZdQCjX3IGcgzt+gtlofoo22RbkHCVjchBV36GMYsE/2jl1aYIgIrh3ne
         KryOSpgeDyTfLeQkPnyOoEg6vQ6thVmFNFl9RihOLeL+6lQ2O+A3r1A1ONh850Akmpgu
         4UdNYjFoW3a71Fj/X3VvgTK0SmGIyFnnA/IAtrXzP3chjkWM+kZ1pSObHJP6aG+iJYKO
         EFwX+7xSCsc9g0WJUTb7cXN9zYUrPjUQXWOPV3JTLfNkV/ZSEwjj10gPnUsbKJAi3+Ff
         tICQ0ehRytj4mSuVAXDd6X49+DJoqwa0o9sb9KNMgQxCRXytTV1Bjy4yNpvstYPwr9M8
         dBBg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as permitted sender) smtp.mailfrom=aryabinin@virtuozzo.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=virtuozzo.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=XJ9fa7V1EG0r/rHi6uBv0ZrfwP0Msu5dhohq8FmiQ3Q=;
        b=CohgwnF6zrl6m2+ryKA4ryimgRQDbRd7giuuuxWdqbErGtQm8hMZB3FYLlrgXAEEMu
         xTOBVEmKB9oG7HdVKApS5sqmOguucW0CuLn+l+6wrhFU6t+p463cJyfV2Tthxvxd7htE
         RlkuiZwbKIzTUF611VwxoVZ4nysBw56EzbedCIZ8qhC06gDMOriAGauK1wCrpFP78yEE
         Chp8P9LdgNADiM127rEsNM0qEelgy3RxQsMgNJet6s1s1EnpGDzYOxzduoaW2fr0TvVw
         Mwj9BpwsbTcGy356FjXUel7STfd9sr/8xtiO87SoyQnyJNwiR+Oz3mG25LkaRI82A9HW
         JFTA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=XJ9fa7V1EG0r/rHi6uBv0ZrfwP0Msu5dhohq8FmiQ3Q=;
        b=Qd78pWFhKTr6eGB3WWNpF4I/mtKdhmN8VMjKNHD3B8AHvqtdf9Wa2WQ2z4UW822G/c
         1cv9pHElzcbpy9ttYU+8q2r9tUY8aT2RwlrRbhm6loQDMSaUVdWZj85sT2320YJ5AOHl
         ocUA9Lbo4MGqSWTN1kXyyNzEcsEH6bovRSYy+ho7D7ezTrVzI0F+2Cv5+sH5mK1+kEJs
         fDr5xBgUHjkqzlq5fy5K0dE0x6NH+GpmcDXfzihRPnrcup28DXwM73K2uARIF/HJVM4q
         WtO9KuF/x/uFgyaLlKc6GcvKDRybKPJGAEDocw2Oldzyz+OwdIOGwq59bExfnQatTP+7
         lMnw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVfbB64cMu/5LaKj7xzh32aKcRzZ6WHCD2guNgM13+UITlZ3cax
	NPlCLKaTDXztlf1l/wVJ2Zw=
X-Google-Smtp-Source: APXvYqxH1nNHj9ZT/qNNs23ZPzUbZudXiREm6httc3QDrwuCSmFKofPl1jKPRHGeqw0GnPO7XXzG1w==
X-Received: by 2002:a19:488f:: with SMTP id v137mr5053691lfa.26.1569404504202;
        Wed, 25 Sep 2019 02:41:44 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:4892:: with SMTP id x18ls563206lfc.11.gmail; Wed, 25 Sep
 2019 02:41:43 -0700 (PDT)
X-Received: by 2002:ac2:414b:: with SMTP id c11mr5041150lfi.159.1569404503738;
        Wed, 25 Sep 2019 02:41:43 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1569404503; cv=none;
        d=google.com; s=arc-20160816;
        b=WAhVS1wR8XhhOdV4HYJdJ86i7F0CuyMxART3/Z9SiZSrmMh1L3F5GTTPwHiNtKKAiK
         iK79QGRa6zkonrlrwU8ZjqHGIr8lnumKKLuEUu80vUBuWAaQl7oUmHHPTmKp4oTBNMJn
         mSQsMLv4oZg93gdXjCSj1Nsj5Vt88KJ4C7v2hHotTnAvhuvIaQi0eG3ATZ2dHe3/iZnT
         B3ij7SrOP6+JAEzIxvn1EpbcdzriC2UhCPEvn1tkHDOhuNhSrobLaDedcBjx+SnxwE/C
         jvfyaiWjljwkZPzjTRpEMA9Ej1x/iNiX6sqXNgF86NE6QFryq6bNqgWpCKxTKDHHcGYe
         jhNw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=Nhe7NUbWgud4/Y+EZ2OcAp6F8sA7viV5FJOT9ovpuNQ=;
        b=kkuscSkQAro0UQGihQIv1VRFWx9hDy+9wy0Xoj3NyIrI2WSNN68WrxLCAZZYKMxzGf
         DxCIgI/LJKYGaLgwMcEN+XC4FTx/UEdaV4vOlaIPKol7d5Zt+lD3nCtD4yqiMoK6qIQV
         dVgToLngI4jqspLqzrWjWH6jz2rlLU8YVAuqZNw2vq7ojEIDOdlvKamGPlXUbmiRMgo0
         4087t7BKitg+4xZMJrG03+ow4gzvHk94EH+Q/8Kb0aQWvnT1fmUUBsqp21mSF5FZSsrW
         mya7e8un004lcE6I6j+yu0d/nRESHK5FEHKKIA2B6OJL8nEPz1j8LZPNzHlRGfkyX5cN
         Ns+w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as permitted sender) smtp.mailfrom=aryabinin@virtuozzo.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=virtuozzo.com
Received: from relay.sw.ru (relay.sw.ru. [185.231.240.75])
        by gmr-mx.google.com with ESMTPS id k24si312532lji.3.2019.09.25.02.41.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 25 Sep 2019 02:41:43 -0700 (PDT)
Received-SPF: pass (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as permitted sender) client-ip=185.231.240.75;
Received: from [172.16.25.5]
	by relay.sw.ru with esmtp (Exim 4.92.2)
	(envelope-from <aryabinin@virtuozzo.com>)
	id 1iD3ne-0004yL-1n; Wed, 25 Sep 2019 12:41:30 +0300
Subject: Re: [PATCH] mm, debug, kasan: save and dump freeing stack trace for
 kasan
To: Vlastimil Babka <vbabka@suse.cz>, Walter Wu <walter-zh.wu@mediatek.com>
Cc: Qian Cai <cai@lca.pw>, Alexander Potapenko <glider@google.com>,
 Dmitry Vyukov <dvyukov@google.com>, Matthias Brugger
 <matthias.bgg@gmail.com>, Andrew Morton <akpm@linux-foundation.org>,
 Martin Schwidefsky <schwidefsky@de.ibm.com>,
 Andrey Konovalov <andreyknvl@google.com>, Arnd Bergmann <arnd@arndb.de>,
 linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
 linux-mm@kvack.org, linux-arm-kernel@lists.infradead.org,
 linux-mediatek@lists.infradead.org, wsd_upstream@mediatek.com
References: <20190911083921.4158-1-walter-zh.wu@mediatek.com>
 <5E358F4B-552C-4542-9655-E01C7B754F14@lca.pw>
 <c4d2518f-4813-c941-6f47-73897f420517@suse.cz>
 <1568297308.19040.5.camel@mtksdccf07>
 <613f9f23-c7f0-871f-fe13-930c35ef3105@suse.cz>
 <79fede05-735b-8477-c273-f34db93fd72b@virtuozzo.com>
 <6d58ce86-b2a4-40af-bf40-c604b457d086@suse.cz>
 <4e76e7ce-1d61-524a-622b-663c01d19707@virtuozzo.com>
 <d98bf550-367d-0744-025a-52307248ec82@suse.cz>
From: Andrey Ryabinin <aryabinin@virtuozzo.com>
Message-ID: <28e076ed-d4c2-c29d-f0cb-b976e8c0725a@virtuozzo.com>
Date: Wed, 25 Sep 2019 12:41:18 +0300
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101
 Thunderbird/60.9.0
MIME-Version: 1.0
In-Reply-To: <d98bf550-367d-0744-025a-52307248ec82@suse.cz>
Content-Type: text/plain; charset="UTF-8"
Content-Language: en-US
X-Original-Sender: aryabinin@virtuozzo.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as
 permitted sender) smtp.mailfrom=aryabinin@virtuozzo.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=virtuozzo.com
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



On 9/23/19 11:20 AM, Vlastimil Babka wrote:
> On 9/16/19 5:57 PM, Andrey Ryabinin wrote:
>> I'd rather keep all logic in one place, i.e. "if (!page_owner_disabled && (IS_ENABLED(CONFIG_KASAN) || debug_pagealloc_enabled())"
>> With this no changes in early_debug_pagealloc() required and CONFIG_DEBUG_PAGEALLOC_ENABLE_DEFAULT=y should also work correctly.
> 
> OK.
> 
> ----8<----
> 
> From 7437c43f02682fdde5680fa83e87029f7529e222 Mon Sep 17 00:00:00 2001
> From: Vlastimil Babka <vbabka@suse.cz>
> Date: Mon, 16 Sep 2019 11:28:19 +0200
> Subject: [PATCH] mm, debug, kasan: save and dump freeing stack trace for kasan
> 
> The commit "mm, page_owner, debug_pagealloc: save and dump freeing stack trace"
> enhanced page_owner to also store freeing stack trace, when debug_pagealloc is
> also enabled. KASAN would also like to do this [1] to improve error reports to
> debug e.g. UAF issues. This patch therefore introduces a helper config option
> PAGE_OWNER_FREE_STACK, which is enabled when PAGE_OWNER and either of
> DEBUG_PAGEALLOC or KASAN is enabled. Boot-time, the free stack saving is
> enabled when booting a KASAN kernel with page_owner=on, or non-KASAN kernel
> with debug_pagealloc=on and page_owner=on.
> 
> [1] https://bugzilla.kernel.org/show_bug.cgi?id=203967
> 
> Suggested-by: Dmitry Vyukov <dvyukov@google.com>
> Suggested-by: Walter Wu <walter-zh.wu@mediatek.com>
> Suggested-by: Andrey Ryabinin <aryabinin@virtuozzo.com>
> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
> ---

Reviewed-by: Andrey Ryabinin <aryabinin@virtuozzo.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/28e076ed-d4c2-c29d-f0cb-b976e8c0725a%40virtuozzo.com.
