Return-Path: <kasan-dev+bncBDWLZXP6ZEPRB6F6ZXWAKGQESZLF2TY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x137.google.com (mail-lf1-x137.google.com [IPv6:2a00:1450:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id 99430C36CC
	for <lists+kasan-dev@lfdr.de>; Tue,  1 Oct 2019 16:15:20 +0200 (CEST)
Received: by mail-lf1-x137.google.com with SMTP id g21sf2766358lfb.6
        for <lists+kasan-dev@lfdr.de>; Tue, 01 Oct 2019 07:15:20 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1569939320; cv=pass;
        d=google.com; s=arc-20160816;
        b=u9UmfQBytWJ9v5su7XXI5Vhnj4UIGuTH85Z/sfnRSVRBEA1EdZzJl8khZ2B+Yse/6S
         qD/MiYxag+M7yGPpgae4Sos864pTciJcb6c5swWe9UPhrlkPEdrG8kKf2C8LHuIG/ExG
         sByL2tayOfB8fagyOUee+YC8+CoFnGM5COCR1tPtS/qBEpFF5M5OwM1M4/u31QmH3wVu
         /1pvRGfHEVHKbe4OG7X7Pn2kMUqP8VK3waKcQiWpDZPd5d5DzbzfOM6evRK+njLdi2R+
         QjfAcfss09SL4snIbSeD8hM4g4w+WD8y2+w4x00bILt5Sas7wvFMuRSHRkwP6r59C5nH
         5n0g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:autocrypt:from:references
         :cc:to:subject:sender:dkim-signature;
        bh=fZS4pWs1JvyZxO6IkhQSggEbq4ErmL/T6rDA7Pw6tbA=;
        b=HjTDwosjeNuHeBHw/9CE2ye7rEqtCmis5okyaHSH4Tt1hdhoHcQ3WXOH7qtnp9t/5g
         2/AfRkgaTkfARx2DSvn9CjWNMf7m/TwSLXQRD6n7hQ02c0JUp2P/1PRXQvu3KyPPVcKW
         ssKP3iiNOa8iQRn2WuIGhjWB4+/u6TNsPqZnnTi0HgxjPLgtKKe+o9ljAKvOuGHe//+/
         pSz7CrUi89rdzsV2wA1MlxYGY5tV4eq1g2RqA1aeEa7L5G75emZqjKw5B2FM9VQRxxZy
         O4oOsJG5fWBG0BMHxRfU0IkGzYy11fF7uJIja+B1r1S0M5HQWp78+bXyPbpt/fKCbNQ6
         ZFYw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.15 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:autocrypt:message-id:date
         :user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=fZS4pWs1JvyZxO6IkhQSggEbq4ErmL/T6rDA7Pw6tbA=;
        b=eCcVrPfIXn16JiwH/VoAK4vaRtvKtd0ToFIx9JGghh5yWNG+Y/A0gKtYA7QbuAj9Ov
         R6ulaKQ+pu4EoMqyRKtRoaS5UPtAeiH+1AbBE0q019lvC9ZdfbmUhsEuR8W2W4KYU7yo
         pr7jOwqPIuOYygLpBOChDiuW3RwSbvL3eQRIhNJgksKLOCJzDEYO//t2K7XEXO7/czJs
         gYoPMULkqHNzJvHipGR4dtDDsbwXuAgU2BamNX6nOE1OxIb42hXkooObhROo5g8TdyAX
         ts+IzS3uWko2a7t0njqJTX2pTas120KJDQOW9Ox8xUwPvBSIvPXqbE1FK+iNzTC3u2zz
         0Idw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:autocrypt
         :message-id:date:user-agent:mime-version:in-reply-to
         :content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=fZS4pWs1JvyZxO6IkhQSggEbq4ErmL/T6rDA7Pw6tbA=;
        b=AkbCF/a1/QfP2k00mCX/EuCoKyg/IaFaMU10ouJtRzrD4zPQNyQcYjbR2NnF4YVzLW
         nvf8A9GDXJQ6ziKJM0i8WQY9QTSAChnTpod42eFiukEL7w3lkz3m/ksl2nv6ocQS16F9
         LjshZ+mXC0dnG8aEeXLFV5jnfzpiz9heVQHpwOt6dz4GP15Hm0FZqYnqj3SH28D/EZZm
         KqnKFaz4uxAmu7PwtIw1OK+4rGYJn9LkpECQsI42hI3MpC2+NzSWvuz4qkOU7e7nffnt
         +EOKFTQxaKtrjBGXJck72NHBF4ScyFka5fads8+0Mw9ZvEc7tUXyg2njF4A08TAZk8cU
         ASBQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAWjppW8SuJGHKPv9dfPkd2QC8Zyv72aDIKhrjwnBIsptLDCRs5p
	iJBMbA3UeNl/MqDrAln9vnA=
X-Google-Smtp-Source: APXvYqyY1SsECsvV8wwb4Mao73hoGcWo2FGOE4IL3iVyqjCHsSeLbH9LuHb4jvfrdXIdaZhuysm8Zg==
X-Received: by 2002:ac2:4551:: with SMTP id j17mr14847845lfm.81.1569939320229;
        Tue, 01 Oct 2019 07:15:20 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:651a:: with SMTP id z26ls2051675ljb.2.gmail; Tue, 01 Oct
 2019 07:15:19 -0700 (PDT)
X-Received: by 2002:a2e:894b:: with SMTP id b11mr11891797ljk.152.1569939319483;
        Tue, 01 Oct 2019 07:15:19 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1569939319; cv=none;
        d=google.com; s=arc-20160816;
        b=JEaOr8Gn06XE91VF6c4s0Bw7YLCTfQJ5X0mh3mTHlELXPu29EAopk5C0fOzrq8AtOL
         98aqKpigfa1FYVoN63Dm+oYBA8c7WC4yunjMktrJyI8RC6SMIHoxF5G+0NxcDC9c1qLN
         PWWP5MHTaJjqoQQ+tP5U4YyQH3U5jn8WrgCe0W7BEbqnQjJVndzWLmjVNVZUTVVWvIX4
         oLvUuNhoiSkICQtVshg89ugm1jPp7pdDL3TalYNOYBo1/7wrboViaBW5jTphgc213XSQ
         DkRE+E8/ViVq9Ank6kHYU/dPjPW4VS4i+5Y7Jnk3qtgg6MLX8WKsmKl9kvCfQuB7NgM3
         6+FQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:autocrypt:from:references:cc:to:subject;
        bh=sP/FObRXUarIadu0goQbFpsIpMGxJhjoU2j5rsnuDg4=;
        b=z0dRPF/bez0hhqy9R+pOwAIBMBWwZ3vODDqMKnQg9sRIq91OuSVCGeDwDMwfIFR9pR
         6tzG/zca3H99sHHEyDTzGz2jHxXXNTbPA/caxmv/SbTUPEIft4804cYYu0kX+eiw0ayV
         WxORi6fGudQv6InHJYaV/8uKbD00dvdM3gv3HZkTrEjjrP/mDXrKalNDJk0YY8S4w8+W
         4H+X0FulJeWDJEal0jqRKmajlvJL4YkXWMrmBkwt6b7iqfFs1rzRlawUaNzuHJYVjUp7
         +JoIVY65VXWVLM0rBQbzBVgCwaxeTyHjmS3DWo3DBJUD58g5PEmn5hQcTbR6vdwThPwG
         Caww==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.15 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from mx1.suse.de (mx2.suse.de. [195.135.220.15])
        by gmr-mx.google.com with ESMTPS id q25si763063ljg.5.2019.10.01.07.15.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 01 Oct 2019 07:15:18 -0700 (PDT)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.220.15 as permitted sender) client-ip=195.135.220.15;
X-Virus-Scanned: by amavisd-new at test-mx.suse.de
Received: from relay2.suse.de (unknown [195.135.220.254])
	by mx1.suse.de (Postfix) with ESMTP id D0019AFC3;
	Tue,  1 Oct 2019 14:15:17 +0000 (UTC)
Subject: Re: [PATCH v2 2/3] mm, page_owner: decouple freeing stack trace from
 debug_pagealloc
To: Qian Cai <cai@lca.pw>, "Kirill A. Shutemov" <kirill@shutemov.name>
Cc: Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org,
 linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
 "Kirill A. Shutemov" <kirill.shutemov@linux.intel.com>,
 Matthew Wilcox <willy@infradead.org>,
 Mel Gorman <mgorman@techsingularity.net>, Michal Hocko <mhocko@kernel.org>,
 Dmitry Vyukov <dvyukov@google.com>, Walter Wu <walter-zh.wu@mediatek.com>,
 Andrey Ryabinin <aryabinin@virtuozzo.com>
References: <eccee04f-a56e-6f6f-01c6-e94d94bba4c5@suse.cz>
 <731C4866-DF28-4C96-8EEE-5F22359501FE@lca.pw>
 <218f6fa7-a91e-4630-12ea-52abb6762d55@suse.cz>
 <20191001115114.gnala74q3ydreuii@box> <1569932788.5576.247.camel@lca.pw>
 <626cd04e-513c-a50b-6787-d79690964088@suse.cz>
 <cb02d61c-eeb1-9875-185d-d3dd0e0b2424@suse.cz>
 <1569935890.5576.255.camel@lca.pw>
From: Vlastimil Babka <vbabka@suse.cz>
Autocrypt: addr=vbabka@suse.cz; prefer-encrypt=mutual; keydata=
 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
Message-ID: <cbbb78bd-4719-b9f4-ea5b-0b74675bfce7@suse.cz>
Date: Tue, 1 Oct 2019 16:15:17 +0200
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.1.0
MIME-Version: 1.0
In-Reply-To: <1569935890.5576.255.camel@lca.pw>
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

On 10/1/19 3:18 PM, Qian Cai wrote:
> On Tue, 2019-10-01 at 14:35 +0200, Vlastimil Babka wrote:
>> On 10/1/19 2:32 PM, Vlastimil Babka wrote:
>>
>> Or suggest how to replace page_owner=on with something else (page_owner=full?)
>> and I can change that. But I don't want to implement a variant where we store only
>> the freeing stack, though.
> 
> I don't know why you think it is a variant. It sounds to me it is a natural
> extension that belongs to page_owner=on that it could always store freeing stack
> to help with debugging. Then, it could make implementation easier without all
> those different  combinations you mentioned in the patch description that could
> confuse anyone.
> 
> If someone complains about the overhead introduced to the existing page_owner=on
> users, then I think we should have some number to prove that say how much
> overhead there by storing freeing stack in page_owner=on, 10%, 50%?

I'll wait a few days for these overhead objections and if there are none I will
post a version that removes the parameter and stores freeing stack unconditionally.
 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/cbbb78bd-4719-b9f4-ea5b-0b74675bfce7%40suse.cz.
