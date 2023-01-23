Return-Path: <kasan-dev+bncBC32535MUICBBCGIXGPAMGQEPUKOZFY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x1140.google.com (mail-yw1-x1140.google.com [IPv6:2607:f8b0:4864:20::1140])
	by mail.lfdr.de (Postfix) with ESMTPS id 09F2D677958
	for <lists+kasan-dev@lfdr.de>; Mon, 23 Jan 2023 11:40:10 +0100 (CET)
Received: by mail-yw1-x1140.google.com with SMTP id 00721157ae682-4b34cf67fb6sf114816217b3.6
        for <lists+kasan-dev@lfdr.de>; Mon, 23 Jan 2023 02:40:09 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1674470409; cv=pass;
        d=google.com; s=arc-20160816;
        b=wzWzFwqzgXJLyAsAlJWOoRnFe5KeRNSiQWTgDe+b1mIdbrGulSx+wFmRTgqQdiPcq1
         iP7yhNNhRhmJllhocKeFHstiGBb4baogp/70MUB8N8tSqMfx2XdffjG37nTYfgCO4Nst
         +U45w/slE2/zc11T9xqc6yEdyUr1RNUsLZgyKEtq3AKwOSKvDQ8KJBF6r2UoHNKKCiuJ
         pLUhsFnB5R+lkaZNEBoGbVlQAJNiz92rlVer7bsNRa65ynS6cyNcRfWdyjYgSeStAeVh
         ZTqhyYA2kmyszsoj7DFJK5+2XBT0y2E/V7S2N/2SvMNEaN0Hok5IJ9TWbnO+w9JMWL0B
         aeiA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :organization:from:references:cc:to:subject:user-agent:mime-version
         :date:message-id:sender:dkim-signature;
        bh=wKJZI44u63AcWMPkILu8LohDkjqn6LAKpWWvupEobfE=;
        b=XdCi1tCdfw2By66uUGDmsLIGpFbuXHcBSQwZ+kjayGFJVzVvM0l1fIa7R3PX7p1h2I
         GbobENm9FGL64cagmjxWSMW1uU1tV8f4NgNBeBENfVO+Wkr34L5t+95V3+rhHcDtfVdB
         XfRHXhkCD7sTrWKXPo1iiv6MDurP6UWTQssLCDUuSWHYPKdt8JgLO27JDmewJ8LjxL8Z
         q4ymaxRrPwFqSW+cniEZLuhirI5yq8hSvjZnZhxTyDO0/I+dcuaXqU5tDJXJp2BwNtX0
         9BKvZV7Ktb8F58opgktLQ9vn5XA1qwZV2l5JnhlRTsc117zGgO0Cw8Uf8XiLtACcOULo
         T4ng==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b="dPsAz/FB";
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-language:in-reply-to:organization:from
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=wKJZI44u63AcWMPkILu8LohDkjqn6LAKpWWvupEobfE=;
        b=C7so0CwB7xGOKLA+RdCB6V9WNtdPLFazXzNcnjeCM8fOUdwvlN0yxwObdAFXeTeJGE
         SSX8smwvtTgATl9TTTWlTzgyNMsWEfIkNujh4R0Z9nUHGgerb14w30xCC9UjgbmkQcvO
         0BLmTS+7bhkbUvRBUH1AKd6Di0NeYba7LE8n5UO0fMS8Nczh15h11wlqC/NAHceXK8Lh
         BN9E8557pqrHRAcz3yISm76evwiosYVSXKGPAVevs9IJ+6N4boY4YM8E0ZGxt0nJqUpL
         6eDH3yrFXMJo791uldTY40VBwDC+Zv6lqHWCO0eEMabmw0lvWWXSU0uziSLfaOQjIKq9
         quvg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-language:in-reply-to:organization:from:references:cc:to
         :subject:user-agent:mime-version:date:message-id:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=wKJZI44u63AcWMPkILu8LohDkjqn6LAKpWWvupEobfE=;
        b=Y1Gjpx36Fu0uldtH9POo/2MjO+81G9I6mmcVExkrNrI5N08/ci/hfuxu8VaHttNOJI
         kUpognFAQvRtWGOL/p7ssi+WvkGIsqIKOKDNfqV/H/i8p6+liw/uxPi+TfG1zkXtmyp/
         o6vbK8EvP0lfOWMnUgfJl+UUOpkI/hy3Pj8oZg8LNiNY8PEA26nSS+3F8ZBabpkvWY1r
         gjgErXMG3BnobdV7PSoPg9UITsRRsp2dQHtr7Is5JN95RZxbxYGBziOKP7Z9n/lysy4h
         OsDx5VZfjppB7R2ihtMcgmEdmF2vrx/GWWpyXkS3yknXThK5r+sz5/e2Jq3Qgn66pjQ1
         o4yA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2koeCR0eIqROPx51iFjZa4jjOwol8OdzYPauJObPJm+y8KMeetiL
	sx8UU1ebd3vX+/kR4DaEW5Y=
X-Google-Smtp-Source: AMrXdXs4MEVYySjEEc2NLD3GWRljIXwKq40tp1GYXPasuIFVn/l1H5xvmW2Cc/URvtglwaexZzSLMQ==
X-Received: by 2002:a05:690c:92:b0:391:fccf:db48 with SMTP id be18-20020a05690c009200b00391fccfdb48mr3585444ywb.257.1674470408760;
        Mon, 23 Jan 2023 02:40:08 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:7e81:0:b0:800:9981:2fa4 with SMTP id z123-20020a257e81000000b0080099812fa4ls4839586ybc.3.-pod-prod-gmail;
 Mon, 23 Jan 2023 02:40:08 -0800 (PST)
X-Received: by 2002:a5b:5c1:0:b0:784:5b4d:69d4 with SMTP id w1-20020a5b05c1000000b007845b4d69d4mr12484128ybp.7.1674470408141;
        Mon, 23 Jan 2023 02:40:08 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1674470408; cv=none;
        d=google.com; s=arc-20160816;
        b=F4kWtslBvAFLrrpnfUCG9PfaRZCu37t8K7Hi9JdPqZS8gfsasMIxYsL/wq6HJXzmQL
         vrPdLdUEseSiutQyQu9Gtw7jLL1R7D+7gL9AiZJic54D772OKx+lRjjicADnQ2I81wWt
         pSwr0lLn2vY1x1TaK/egpGeDBSu81bT4bwKIiSyCKoSrUmZmmxlXu7ozGnA79JG56X8U
         0OHCHTjiFubKBUcVaI0n9DYHEmhjEI2iHjx0wAsz3kLjLh5QAvC/FTKdNA/Tcg/AuLWp
         ih1UuAMF7+E92QGEXJ6niTfL2xvzPHbNhLUZM+JWmgIzQNgBsAARI1JtGZQjwqoSbmoY
         j/Og==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:organization
         :from:references:cc:to:subject:user-agent:mime-version:date
         :message-id:dkim-signature;
        bh=K1A7NI5KvtrB71d9uH3sQ7HmbeBB6x6yn0qDOltJNbo=;
        b=epRVAY+wo7IVOR2GiOFQcm0dMUl0EJJKDhRrTcLIGGIYx6G9BptxVPFf3PPMtRO4oX
         ZMdDkhz6dcJE+2e5O37dTbiBc62+iR3/ooqHpviDLN6E8GbUvyZQfNJbk72L0oSPlUhP
         Ak3DbW+416GyusQoYWdbuB3XXa0k1NzRVUItrSMilpPs5myxlwaPt8nCjGwg1RebPwGE
         unXOSZ5Yys+WxNTzCKARA/lTHKka0XV3IGviZg7qT4/EsfoOeBeYUXtT+tE88cetmxYH
         E6ditudVDRcwsPN+z/19LBopZ6k79bONPwf3YIQ7NKJ+i8XY8zfhsOOrQWm6Ri4Xlnq8
         3PKQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b="dPsAz/FB";
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id o134-20020a25738c000000b008032606ec55si788979ybc.0.2023.01.23.02.40.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 23 Jan 2023 02:40:08 -0800 (PST)
Received-SPF: pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mail-wm1-f70.google.com (mail-wm1-f70.google.com
 [209.85.128.70]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.3, cipher=TLS_AES_128_GCM_SHA256) id
 us-mta-640-qCtaq7L9NfOH3tLtJDOrhw-1; Mon, 23 Jan 2023 05:35:11 -0500
X-MC-Unique: qCtaq7L9NfOH3tLtJDOrhw-1
Received: by mail-wm1-f70.google.com with SMTP id m10-20020a05600c3b0a00b003dafe7451deso7286894wms.4
        for <kasan-dev@googlegroups.com>; Mon, 23 Jan 2023 02:35:11 -0800 (PST)
X-Received: by 2002:a05:600c:224b:b0:3d2:640:c4e5 with SMTP id a11-20020a05600c224b00b003d20640c4e5mr23515766wmm.8.1674470110083;
        Mon, 23 Jan 2023 02:35:10 -0800 (PST)
X-Received: by 2002:a05:600c:224b:b0:3d2:640:c4e5 with SMTP id a11-20020a05600c224b00b003d20640c4e5mr23515749wmm.8.1674470109822;
        Mon, 23 Jan 2023 02:35:09 -0800 (PST)
Received: from ?IPV6:2003:cb:c704:1100:65a0:c03a:142a:f914? (p200300cbc704110065a0c03a142af914.dip0.t-ipconnect.de. [2003:cb:c704:1100:65a0:c03a:142a:f914])
        by smtp.gmail.com with ESMTPSA id bi13-20020a05600c3d8d00b003daf98d7e35sm10196203wmb.14.2023.01.23.02.35.08
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 23 Jan 2023 02:35:09 -0800 (PST)
Message-ID: <cb40d3a9-39bb-474b-fd65-f0ee08a27967@redhat.com>
Date: Mon, 23 Jan 2023 11:35:08 +0100
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101
 Thunderbird/102.6.0
Subject: Re: [PATCH 02/10] mm: remove __vfree
To: Christoph Hellwig <hch@lst.de>, Andrew Morton
 <akpm@linux-foundation.org>, Uladzislau Rezki <urezki@gmail.com>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>,
 Alexander Potapenko <glider@google.com>,
 Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>,
 Vincenzo Frascino <vincenzo.frascino@arm.com>, kasan-dev@googlegroups.com,
 linux-mm@kvack.org
References: <20230121071051.1143058-1-hch@lst.de>
 <20230121071051.1143058-3-hch@lst.de>
From: David Hildenbrand <david@redhat.com>
Organization: Red Hat
In-Reply-To: <20230121071051.1143058-3-hch@lst.de>
X-Mimecast-Spam-Score: 0
X-Mimecast-Originator: redhat.com
Content-Language: en-US
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b="dPsAz/FB";
       spf=pass (google.com: domain of david@redhat.com designates
 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
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

On 21.01.23 08:10, Christoph Hellwig wrote:
> __vfree is a subset of vfree that just skips a few checks, and which is
> only used by vfree and an error cleanup path.  Fold __vfree into vfree
> and switch the only other caller to call vfree() instead.
> 
> Signed-off-by: Christoph Hellwig <hch@lst.de>
> Reviewed-by: Uladzislau Rezki (Sony) <urezki@gmail.com>
> ---

Reviewed-by: David Hildenbrand <david@redhat.com>

-- 
Thanks,

David / dhildenb

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/cb40d3a9-39bb-474b-fd65-f0ee08a27967%40redhat.com.
