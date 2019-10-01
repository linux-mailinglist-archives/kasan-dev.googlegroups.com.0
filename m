Return-Path: <kasan-dev+bncBDWLZXP6ZEPRBBMQZXWAKGQEZZ6KI2Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53d.google.com (mail-ed1-x53d.google.com [IPv6:2a00:1450:4864:20::53d])
	by mail.lfdr.de (Postfix) with ESMTPS id 83D0EC3456
	for <lists+kasan-dev@lfdr.de>; Tue,  1 Oct 2019 14:35:17 +0200 (CEST)
Received: by mail-ed1-x53d.google.com with SMTP id o92sf8537432edb.9
        for <lists+kasan-dev@lfdr.de>; Tue, 01 Oct 2019 05:35:17 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1569933317; cv=pass;
        d=google.com; s=arc-20160816;
        b=XthtpHwdJnr4VbRZuH7OeE5815HvpPKkZd/k6doXSUUJyH0UunAZKbedo1TOL3Fi4v
         Mzdb4luGrd8eRs7JeBUfxp+e0r1g/QIpVZCY+PkVpsLUlXqz+cTYPCSixpstqrhuCgbJ
         8fAF9MTv6btCtlFopfU6yGEYJrFr8pXJbW2jrElxG+aL0x5Mv7VBdj0rAteNKyo10tD6
         ztXD5nxP4YnopeaRqknj5ZuyIpprIkSQasFfHOOnbCmdejyPZZEPurTGIMAJX71YHc9X
         XtwC8SVRWhgYn1Y072/TTeSc5j1fBftvJuLhu1m3lWagyydPzae7iMZlSlZYtXcr8MfU
         DY+Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:autocrypt:references:cc:to
         :from:subject:sender:dkim-signature;
        bh=QzITK2zgQatx6S/UfgtqifaV2gYHncsIIYDNy6hsUD8=;
        b=zvMMewtghYNe6hrNkmUceQ1oMtW53bk+Rgk0fBClePrBIKCd9fTEsasEPSj7TP4zTq
         U2I5cKtFPBe2PSISQbD80ksFs0WD3oj8TzdioCbfSkriQ1XOZW5PwUdQPJAxyowTxEOP
         gPfT1zQi03Fq2MErGX6cRVHySDlyl/deNwU3swAm8Qh9oWCWtczNfXrs1+UaR+DY64wR
         g8P7kFyrWVIU/Dzu24rSM8WX+1JK3ZOXVrbKlqzcirag7b61p+2d9hSw4D+/BaUAXCoQ
         JB98VxYC58BVcF6BqHx/4pAi4ycYdRj2AkOcXoaKH8XccP4Wqj3FVZMmOms+opVoGOWb
         dTFQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.15 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:from:to:cc:references:autocrypt:message-id:date
         :user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=QzITK2zgQatx6S/UfgtqifaV2gYHncsIIYDNy6hsUD8=;
        b=lrCaCZBi+S3lw8NBMVXyhDei50JwszwBDYh5r0WmUEGhk1l7r4Qietf5T0Kg3kwuUj
         CFCPfbrZxfKBljsSTz7Pj8a7dRTe9MN+eFueIHVy4JJNTkXaQbancIhiR0SgayTLA6wA
         /b1ZOyRuZCbaikXgAOxTAWVTT6rxXRY+O0j6sEsa2CXzR8O+OAIZJG5P1L8cV/x6OWoi
         5fRbPWzApBSbU7vUg/wUta5qPl3lhgKAKmwQ04H0AX0oe13D7/rTEKm9nq42W6eSSfaT
         uKc8Tx36+iCRK/edKoh2zEJrrIOuJDLvijr8hTlRbTmR91iZjD5LQ1TAOqrth86wcGHj
         ufVg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:from:to:cc:references:autocrypt
         :message-id:date:user-agent:mime-version:in-reply-to
         :content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=QzITK2zgQatx6S/UfgtqifaV2gYHncsIIYDNy6hsUD8=;
        b=ih12ORfvod/N8r65/pNkHN3Xi3nWT9nDg8i7EWXHTYxiFHBFpCk63MuQp4tGztC+pv
         iO9cFwHTLIkoDUSxM8Il6ATAPhXIlZcupWDfkzThM1GcTQXwI+olo7qpxS2ezEfIJdYR
         /kXzGGdaAhTqEsV1zsqlp9fJcPXlhmsnl3zqc0m+y9Hl2scz/0axMsERYtEp/5QVVKWE
         1o7/OvKtvRDDouPjAtX6UQrQB1XqDZ8VYe9ddBFwKGWKjJmJrIlf5dnxWTluHAUHxBjR
         m3UMgdLF/w3RzY7xjCeTVf+DswcEeL76Uqq2E5LR0hmbl3HmOx4zyls5bNcUQahAShMp
         ioag==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAWSEqWVAU1ns9HeWfk2XJh7KRb9H71hRrqWgBdu3/4n3BKiWBWp
	Z4JXwU2+IFX04xUMypgNd4A=
X-Google-Smtp-Source: APXvYqw8zUT7GXRUSYVjFS7KlN9jz4wqvY6EEoZVKBkVsDEbzIlSfKC78aERmHJXhsuX2kn5Gf2/aw==
X-Received: by 2002:a50:8a9d:: with SMTP id j29mr25846180edj.283.1569933317194;
        Tue, 01 Oct 2019 05:35:17 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:daca:: with SMTP id x10ls3103737eds.13.gmail; Tue, 01
 Oct 2019 05:35:16 -0700 (PDT)
X-Received: by 2002:a50:99d5:: with SMTP id n21mr25380358edb.50.1569933316565;
        Tue, 01 Oct 2019 05:35:16 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1569933316; cv=none;
        d=google.com; s=arc-20160816;
        b=YZ1Tly7IjK+1xa5lvv5aanqi5J9RrpB+bGN6SswX0OinxKwGiDO+4l5unPiEGXbA3C
         /U219RI6TSslvB/SBeELJTLYDrkDi6soZ8pn7gxTL+wA4GvBfCcPLakEdARt7PSz0Iq/
         ijxxn2wYbivwIqV2VdEHoSFDyOHl32+4iU8XxrGUphGS4vEiajdYGJlGaPScCQIT7FXK
         NOL/R6+G0vJSX+69QSDflEBMIyI5ho4+iw/G+Te5AMZm5jSSpG0u2sNBo18OOEt3lPLN
         A4Y31aRCzQ3muV5zaJPb5IX9bST+tKt5fSL9A9NqtoAxYOZy3a8snQnLMt+WQmazN+q3
         x0iw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:autocrypt:references:cc:to:from:subject;
        bh=LfVFN5D/RRiLUvukMrVKTPLiaHqSkKvurNc6N1EFHwo=;
        b=rVxH1nb2WORj3JO34nmCkIkCcbDoR2Ncb4KKyzJqIw6x0R2UdPu+l6cDGeKjGUFQUB
         kBKbggg1WiarLouJmDYPfsvoyR84cD2jp0ThuwGVE/tjYUImKTyypbcaX4tStlgnir7U
         mkirW6tTqbag8t3RaiCbPt4NcJ+B+nacoDoj3/6zpzM9ukcCIFI2PxPYTQswI3o8ixP9
         +tRUN1SI7n5XK7lCxWdLhzr7C/LklvlgkDak23h0/TRV8c+iFFYeQRoS93easfP8oSdq
         w6atEzHYD/y4IWa6VogML/DQxu3Vf8IPs57j5xkCwIoL0RuPUyxxCotwidFNFcp+FgtJ
         STPw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.15 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from mx1.suse.de (mx2.suse.de. [195.135.220.15])
        by gmr-mx.google.com with ESMTPS id q8si800506edn.5.2019.10.01.05.35.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 01 Oct 2019 05:35:16 -0700 (PDT)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.220.15 as permitted sender) client-ip=195.135.220.15;
X-Virus-Scanned: by amavisd-new at test-mx.suse.de
Received: from relay2.suse.de (unknown [195.135.220.254])
	by mx1.suse.de (Postfix) with ESMTP id 40015AB89;
	Tue,  1 Oct 2019 12:35:16 +0000 (UTC)
Subject: Re: [PATCH v2 2/3] mm, page_owner: decouple freeing stack trace from
 debug_pagealloc
From: Vlastimil Babka <vbabka@suse.cz>
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
Autocrypt: addr=vbabka@suse.cz; prefer-encrypt=mutual; keydata=
 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
Message-ID: <cb02d61c-eeb1-9875-185d-d3dd0e0b2424@suse.cz>
Date: Tue, 1 Oct 2019 14:35:15 +0200
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.1.0
MIME-Version: 1.0
In-Reply-To: <626cd04e-513c-a50b-6787-d79690964088@suse.cz>
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

On 10/1/19 2:32 PM, Vlastimil Babka wrote:
> On 10/1/19 2:26 PM, Qian Cai wrote:
>> On Tue, 2019-10-01 at 14:51 +0300, Kirill A. Shutemov wrote:
>>> On Tue, Oct 01, 2019 at 10:07:44AM +0200, Vlastimil Babka wrote:
>>>> On 10/1/19 1:49 AM, Qian Cai wrote:
>>>
>>> DEBUG_PAGEALLOC is much more intrusive debug option. Not all architectures
>>> support it in an efficient way. Some require hibernation.
>>>
>>> I don't see a reason to tie these two option together.
>>
>> Make sense. How about page_owner=on will have page_owner_free=on by default?
>> That way we don't need the extra parameter.
>  
> There were others that didn't want that overhead (memory+cpu) always. So the
> last version is as flexible as we can get, IMHO, before approaching bikeshed
> territory. It's just another parameter.

Or suggest how to replace page_owner=on with something else (page_owner=full?)
and I can change that. But I don't want to implement a variant where we store only
the freeing stack, though.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/cb02d61c-eeb1-9875-185d-d3dd0e0b2424%40suse.cz.
