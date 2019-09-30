Return-Path: <kasan-dev+bncBDWLZXP6ZEPRBCXOZHWAKGQE3X3U3EY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43e.google.com (mail-wr1-x43e.google.com [IPv6:2a00:1450:4864:20::43e])
	by mail.lfdr.de (Postfix) with ESMTPS id B2459C28F9
	for <lists+kasan-dev@lfdr.de>; Mon, 30 Sep 2019 23:43:38 +0200 (CEST)
Received: by mail-wr1-x43e.google.com with SMTP id v13sf5045400wrq.23
        for <lists+kasan-dev@lfdr.de>; Mon, 30 Sep 2019 14:43:38 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1569879818; cv=pass;
        d=google.com; s=arc-20160816;
        b=snnXAFl3HE+I3vzncEeWa+8oT15QU85XymvfOmQOyAmd+zCMDS+ijWt/ecTM1bCnHW
         k49ru+MVwKIzNTC2lEshvb++fPD45Rqv/d1k67TKr7ydNO18Vv80wB2QxjcL01zbpuRc
         gxRojCFkdfR7cK01rsnDEQr2+e2qPY7fAKjrOzoAf+W0QWOXzu4hrZxBZBTluM1sZmIU
         Ra/tvRQkwMHu6iXYeo5Jtked94wn28ePXYwVWtjfnQXiYo6plKu3kl4SbjH2ae70snwc
         GfcuXpCX7CWY0B3ISoZVclVyQCaH8PuIDP9yvQzL8zW1qDDiVu6jUv/ONoaWDBOEsxCN
         Oy/Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:autocrypt:from:references
         :cc:to:subject:sender:dkim-signature;
        bh=CZ4iZCgPBNAyYzk8xGXuqHN0lZOoWrr1W2tI8V7MlSQ=;
        b=A6OTjTIaZRYsSGdui0wqy5PIluu5jx9vLNsrUY8Jo7orHbd14Uwi4oOpJhQyrVotWh
         hgG1NnyTpgU5korMpfpL1bVXA93S2+9Uc7x4r8saZwyW5gHLpQ7MvEdZD7v/cudfuysh
         wEVp7JlCeBSe8PlwdCootAGKA85XKHyTUNJRWA3hXVco+mPZ+28eZ+KyUTBVA/Nq5gMx
         B+OZFwB/pbk8mi1IEihJi0Uigma9m87UCiGd44F0So+pU4n7n2bgAIrzNLj7mUynEDrs
         NRAzQs0gfTYxpxjnrmtUO1Z7JQfOZBeDR4L7ZtwFVxFgPxvTvP4lB3oLo3X9vwDAhKHL
         dyCg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.15 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:autocrypt:message-id:date
         :user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=CZ4iZCgPBNAyYzk8xGXuqHN0lZOoWrr1W2tI8V7MlSQ=;
        b=BRu7ZJedxZdUqxfw/i+Nd+YDn3lavVK3SjDRX21thOU6+0eyiIAd53MUqGll38RPoS
         CFT+ISuEY12/nHAck/+ixUB1LGdPdHv3MtqiYLlFCFt+DcQVIBNW8wTWIP2KWYy9TRcF
         QYtZ1Tb+DCbFaNEswAczwhfUKYpayxO1n8EnJcR8BrfwSxtWSBlxiiKAjyGZbksBceAI
         gfez3G/X+taF8Qk9/0rj/rbDVViw5GlA6ZkjyEfqpfNkqUVuV4htna3B/l3cJgCpn5O8
         7ZTr1g3YYLd9nFhoZ5+FsdEwH/LXfijmvj83aSfZ1y7SA3lc+haiD0jsmWVuGaL5UIv2
         ojQg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:autocrypt
         :message-id:date:user-agent:mime-version:in-reply-to
         :content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=CZ4iZCgPBNAyYzk8xGXuqHN0lZOoWrr1W2tI8V7MlSQ=;
        b=HHsvjOvsI76zywYJ7YK02wV5/hSzqJi+FEG06eroDtLj0d3/AsqbgnhPSHN7EJ3cta
         pXlxrama+XVFf6cTBlWvg6s1vmVs4vdg0SBMZ21lBqAgRksSWnbM1JH+CvKklV64NacZ
         gxQYstqCixTEw7unbqKID1vxUzH88p+Paic9yLGmunGD428Ygq+JkHbVQOLMEvNgmWBU
         QOJ2NHlXHP0e7knADR/LaQBrFBeDnHiueJJRvf8YdYFso/JsGSDPXKznHhw+ssXmGHcu
         Fbfrv7s7mlIdzeHcNWo2J+nx/STWaxb201My12Lw1K/iiPD4mAmeFfWuMddRZB2+7Fl2
         +4zQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAXTPYulFP77bpzKmPPlejRtgMw2UJmSglczG1oHgEw9+iQu5Y2c
	c+5La+3n9A9c2PJ6GnZQXCY=
X-Google-Smtp-Source: APXvYqxDFTM/rw08pV1yv1+C61hjYhBcyLfxQxeyjh3cOqMoJpUYB4oUJbdQ0BBdl32GOzYC6vwAyQ==
X-Received: by 2002:adf:f212:: with SMTP id p18mr15935269wro.340.1569879818416;
        Mon, 30 Sep 2019 14:43:38 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:630e:: with SMTP id i14ls3450266wru.16.gmail; Mon, 30
 Sep 2019 14:43:37 -0700 (PDT)
X-Received: by 2002:a5d:4144:: with SMTP id c4mr14329670wrq.138.1569879817831;
        Mon, 30 Sep 2019 14:43:37 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1569879817; cv=none;
        d=google.com; s=arc-20160816;
        b=VMiQmfH2qwJndDwhkQh6MQTAhyzMozT3zDG6ps6zCQJ+LAXi7ZoWFCycsAC5FBVXuh
         lk+7l0DwG1uwouZZAclDK23N1P7iPFK0z8BsySEO2iIlHGsfty+6lVu5rihy12LU+n1Z
         xAY83aoHaRhdcT6kJUtTFwUbK+FneUTNMcQCAdh9/avdYkVKFpvm3xQ7gFZVnd+ZMipK
         DayyEoh3shbpLdkMd1DiK+0S4jevkvvE4pLBuBPjj0YwfOJ1O5BstlyLvvnUbOrmdR8U
         fLA0BpC/Ex7K2zPreveB8TMhAOK0iURkc57X2h+jCMtp86Ex2yEuCNd/WY3ycRY2A15b
         mRZw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:autocrypt:from:references:cc:to:subject;
        bh=pe03Yz3khxaEuv2nU/XEZJT8EbxE/Z+CSTyJ2Ewf5WY=;
        b=RbrmE+FDZdeFF7ejbYtuBQMF62tOXHEvJ7MYfNYrcnjM3BnrnzXtlxMgxGMqhYhyG/
         r96DAUydLA9axnd/lA6eZVygMlL3qek2bud7gdZGf3SlLpmpHXPna3hYbQY5NN7Du2XV
         3dwuUr25sMteyG3fR/eul1toC2MnLcpqDBOERMq1L2tGXSrdq51bBn8e2dudmELTiYQ4
         Hzj36agV6Ej/zJybnmATT935BQo/c/XW647FseaNY/reKlgr/0zhHaN89L7gwH5QUOcI
         48eP5YeZH7qaCj3pzoWQs41d6Uq+wD1w5RnxvD9O2SU07Se7iMoxaNlpNgIeNHZ3xSan
         s0dA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.15 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from mx1.suse.de (mx2.suse.de. [195.135.220.15])
        by gmr-mx.google.com with ESMTPS id i21si54408wml.4.2019.09.30.14.43.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 30 Sep 2019 14:43:37 -0700 (PDT)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.220.15 as permitted sender) client-ip=195.135.220.15;
X-Virus-Scanned: by amavisd-new at test-mx.suse.de
Received: from relay2.suse.de (unknown [195.135.220.254])
	by mx1.suse.de (Postfix) with ESMTP id 9ED34B192;
	Mon, 30 Sep 2019 21:43:34 +0000 (UTC)
Subject: Re: [PATCH v2 2/3] mm, page_owner: decouple freeing stack trace from
 debug_pagealloc
To: Qian Cai <cai@lca.pw>, Andrew Morton <akpm@linux-foundation.org>
Cc: linux-mm@kvack.org, linux-kernel@vger.kernel.org,
 kasan-dev@googlegroups.com,
 "Kirill A. Shutemov" <kirill.shutemov@linux.intel.com>,
 Matthew Wilcox <willy@infradead.org>,
 Mel Gorman <mgorman@techsingularity.net>, Michal Hocko <mhocko@kernel.org>,
 Dmitry Vyukov <dvyukov@google.com>, Walter Wu <walter-zh.wu@mediatek.com>,
 Andrey Ryabinin <aryabinin@virtuozzo.com>
References: <20190930122916.14969-1-vbabka@suse.cz>
 <20190930122916.14969-3-vbabka@suse.cz> <1569847787.5576.244.camel@lca.pw>
From: Vlastimil Babka <vbabka@suse.cz>
Autocrypt: addr=vbabka@suse.cz; prefer-encrypt=mutual; keydata=
 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
Message-ID: <eccee04f-a56e-6f6f-01c6-e94d94bba4c5@suse.cz>
Date: Mon, 30 Sep 2019 23:39:34 +0200
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.1.0
MIME-Version: 1.0
In-Reply-To: <1569847787.5576.244.camel@lca.pw>
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

On 9/30/19 2:49 PM, Qian Cai wrote:
>> --- a/Documentation/admin-guide/kernel-parameters.txt
>> +++ b/Documentation/admin-guide/kernel-parameters.txt
>> @@ -3237,6 +3237,14 @@
>>  			we can turn it on.
>>  			on: enable the feature
>>  
>> +	page_owner_free=
>> +			[KNL] When enabled together with page_owner, store also
>> +			the stack of who frees a page, for error page dump
>> +			purposes. This is also implicitly enabled by
>> +			debug_pagealloc=on or KASAN, so only page_owner=on is
>> +			sufficient in those cases.
>> +			on: enable the feature
>> +
> 
> If users are willing to set page_owner=on, what prevent them from enabling KASAN
> as well? That way, we don't need this additional parameter.

Well, my use case is shipping production kernels with CONFIG_PAGE_OWNER
and CONFIG_DEBUG_PAGEALLOC enabled, and instructing users to boot-time
enable only for troubleshooting a crash or memory leak, without a need
to install a debug kernel. Things like static keys and page_ext
allocations makes this possible without CPU and memory overhead when not
boot-time enabled. I don't know too much about KASAN internals, but I
assume it's not possible to use it that way on production kernels yet?

> I read that KASAN
> supposes to be semi-production use ready, so the overhead is relatively low.
> There is even a choice to have KASAN_SW_TAGS on arm64 to work better with small
> devices.


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/eccee04f-a56e-6f6f-01c6-e94d94bba4c5%40suse.cz.
