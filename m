Return-Path: <kasan-dev+bncBC32535MUICBBJX7TSRQMGQEXMOOZ2Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43f.google.com (mail-wr1-x43f.google.com [IPv6:2a00:1450:4864:20::43f])
	by mail.lfdr.de (Postfix) with ESMTPS id ADA577092E2
	for <lists+kasan-dev@lfdr.de>; Fri, 19 May 2023 11:21:43 +0200 (CEST)
Received: by mail-wr1-x43f.google.com with SMTP id ffacd0b85a97d-3078df8ae31sf2074685f8f.0
        for <lists+kasan-dev@lfdr.de>; Fri, 19 May 2023 02:21:43 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1684488103; cv=pass;
        d=google.com; s=arc-20160816;
        b=NAwnOqhT5mgo/DkD+AxpOjFX7UtJoNeydRpvMJZseKf0Lzjlwy88MZjHGvg2AHVeo8
         ZjytIPhBjSU9RFrtADRtM4lZDdYFHrld3QevDayW1kMJdE+V0VICT4lTWCivYvhllUCB
         3MMwsOTOuQrCbph8pmjO1vx3R/5FFFQ69W6Fekw7YRzClanjUrEYxR7uREM202ndHS2i
         3lzaxB7zIOEE9N3StgxACl5oF5tfKGbrRyQOWuQdmw5/aT6JZfjbY4tnNVbGIpDmCU+6
         CFtZMm670lTxlBAPAnoJ4hkpSby1NdONuK+9Ia3NQnTGGzHXyLILxywk1/Xt8yog6h7+
         aFsw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :subject:organization:from:references:cc:to:user-agent:mime-version
         :date:message-id:sender:dkim-signature;
        bh=w3RZbcernFOVvZCnU9yXJgNJ/uAhB5yssua62LdR6Ag=;
        b=ie1eL2GBo9qcbzExSKHATK9N6O51W9WYAz2FICXKZptEbVRFCb5OPDmFO6S3oWakUQ
         fJHoUOLbvCs0yeMC8bE5aNiiT8GizxsCA/fPw/BCNJu/e2hPeCtszPaPsUhyftnW90xE
         WX0D13SE+VkWHZMYIpPfiqqqWHv8JgVcS6RjRg3yAnSScbzyKDnHQd1P/EnfJGU55PeF
         r17i1kPO+FCqUJJdgxjrc4FW6chFt52uvswrg94YjxgmNvTXnbMNxp0v5DAd5iyFTNib
         r0LZU23rhdJZITGMJ3eYttjnvttf5K/fcpg1sIS3zcJ0Cxf17OBx2ZZFX7x2KNFFJHda
         a/BQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=W1CH98en;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1684488103; x=1687080103;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-language:in-reply-to:subject:organization
         :from:references:cc:to:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=w3RZbcernFOVvZCnU9yXJgNJ/uAhB5yssua62LdR6Ag=;
        b=jmMO89LfUPhm/PUphBFMXxar0r2MnI3iJu5em8mnhhS4avEIEdeDjVAiYDas0/Vcjq
         LDsVOYC4o8k5YtYyoOU9sRr4xsrVbRvz1ExkMQKnYzFGF1Nbyzg04LTD+N62sud9PpO+
         eJk+rlxFwnScQ6DMqVPM6rFP6BQvkxMxd9/MtXNtR6fWvFpNjfY1OBJBoTCZic5n+XQs
         ry3LvtcpufZjG52Tpxc+laoJbpOqolozi1iP8NdnZNszMjh1EdWqs+InFha810zdDFGQ
         TjAnnAT+xREX8q/MiSaBmzDJE7VLSLsl9sJ/d45KLKzNqtyJ16AphGmjlRfhHP2WH/kc
         21HA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1684488103; x=1687080103;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-language:in-reply-to:subject:organization:from:references
         :cc:to:user-agent:mime-version:date:message-id:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=w3RZbcernFOVvZCnU9yXJgNJ/uAhB5yssua62LdR6Ag=;
        b=TlSECsbsvGONnbDQ7zdd7AFapnwpBKHmoDga/+lQZjluAJiXZ63SOreXqkLYFd8PNX
         +tgx+9D1KbHL/02SDT7KVpRCciA3IrJbWn61YKJ1gCL7T7P74YaBaYc5ZclIlUxr15RW
         5Q/rgwnyXs8q7XUFG8QJ4aJJBUQWNTXrVhH72EVfg40JAj9X7JR9K6O4YfIuw71/hS2F
         2fDVtZAvv2e+gJSqqglVtjSBTqAl9twVTwDHwQ3aUCJhWpGCJhAL/34dk+XrPTSMr3E3
         A/uUqDXSRBvoeuLUK+ZMtHNk2U7gsMmjfxYiUo5JQevJFHXfW3MTpKkaUsQOW38mBnUt
         dGPQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AC+VfDz8SZyRmi4BONrzsQz9SdTHckQ9AUxC+bognmdSgOCu/emFAlUA
	37RtlQ2sMJRFtxfOIcy7Foo=
X-Google-Smtp-Source: ACHHUZ7m4z34XDEPd58AvSizlHpCODBmIsDvp0sLxY1CTqPe0h50Bavd2Kbq8KhuS+XcJKQee0Prpw==
X-Received: by 2002:a05:6000:148:b0:306:2869:a33b with SMTP id r8-20020a056000014800b003062869a33bmr303940wrx.2.1684488102539;
        Fri, 19 May 2023 02:21:42 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:602:b0:306:46b5:557f with SMTP id
 bn2-20020a056000060200b0030646b5557fls1008600wrb.1.-pod-prod-06-eu; Fri, 19
 May 2023 02:21:41 -0700 (PDT)
X-Received: by 2002:adf:ecc5:0:b0:309:38af:91c6 with SMTP id s5-20020adfecc5000000b0030938af91c6mr963344wro.68.1684488101043;
        Fri, 19 May 2023 02:21:41 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1684488101; cv=none;
        d=google.com; s=arc-20160816;
        b=MIkCz9LtQhwVWZheFV0NlyzQBwyF3xAj70KJoPXFCRTVi/tHTLjvFuPcIScIeEYGub
         I0IqPOO5jYyWanckwjNIbLGtJDqBHSTZA4WKIqEWHQtcJGtPfMWqlHzn6X9sSvIPzSWr
         ceuCPKEQQXN16RSxOtNjb97B2OTW3SZBZDVDyoX30e1x01tiPCkAJhgdqOkDCNmwckce
         Lk8JcBrDrwnQNcCbxKLQWY+AF7yD4VgW50DpNwx3y7yNtKcWmeov2Rajamd69EhbyU9e
         Z4/8UWvQvNf3Cq4wzNEYK0satQP3BtvEG/5B4hv/7t3eE+fwZUivuS7QDD+0ZKEFOFtp
         n/rQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:subject
         :organization:from:references:cc:to:user-agent:mime-version:date
         :message-id:dkim-signature;
        bh=TWFb7su+l+wO5tmP1uJaxoMrwLD0GIgYT9evuWTAj54=;
        b=H7BTmbhi8RcB4zSp2DKQ2zEzsy0IQi2aRcWA5nBE3RQlq8oJkYn5vTTRfhfy4iV3qL
         b9ZtnhKkdn5J4/jfJKD2fHkdR10nCqjsjh18pNHrkRc3JkOGGf7XcQiOQJoZ4qaJVo/e
         BzQAxgb+4zVK1ahHsfUrGCKUhbr+FQHNq3lgJDA/WjBnBPLw5ZchPkstjMlTjHj3POqC
         Dz+S+8UXNFe6SB/yVlPs2N9GiF6Z+FrKs20uv5iOckFUCEm6fds8GtvM5AU1XporUdUu
         oAWyPXFJihT3BKbO7WV6dQ7rIvwMBwO3FE56KbOxiGNAtw7UajSg1PJNHIzp8EsDFzYz
         xtAQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=W1CH98en;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.133.124])
        by gmr-mx.google.com with ESMTPS id ay2-20020a5d6f02000000b003062fa1b7a0si294001wrb.2.2023.05.19.02.21.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 19 May 2023 02:21:41 -0700 (PDT)
Received-SPF: pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) client-ip=170.10.133.124;
Received: from mail-wm1-f71.google.com (mail-wm1-f71.google.com
 [209.85.128.71]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384) id
 us-mta-538-c6Px4HGQOJCgXTthGGpvDw-1; Fri, 19 May 2023 05:21:38 -0400
X-MC-Unique: c6Px4HGQOJCgXTthGGpvDw-1
Received: by mail-wm1-f71.google.com with SMTP id 5b1f17b1804b1-3f41ce0a69fso11467425e9.1
        for <kasan-dev@googlegroups.com>; Fri, 19 May 2023 02:21:38 -0700 (PDT)
X-Received: by 2002:a1c:f20b:0:b0:3f4:16bc:bd1b with SMTP id s11-20020a1cf20b000000b003f416bcbd1bmr778349wmc.39.1684488097707;
        Fri, 19 May 2023 02:21:37 -0700 (PDT)
X-Received: by 2002:a1c:f20b:0:b0:3f4:16bc:bd1b with SMTP id s11-20020a1cf20b000000b003f416bcbd1bmr778313wmc.39.1684488097347;
        Fri, 19 May 2023 02:21:37 -0700 (PDT)
Received: from ?IPV6:2003:cb:c722:9d00:7421:54d8:9227:a3e8? (p200300cbc7229d00742154d89227a3e8.dip0.t-ipconnect.de. [2003:cb:c722:9d00:7421:54d8:9227:a3e8])
        by smtp.gmail.com with ESMTPSA id m16-20020a7bce10000000b003f435652aaesm1753343wmc.11.2023.05.19.02.21.36
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 19 May 2023 02:21:36 -0700 (PDT)
Message-ID: <80f45fec-3e91-c7b3-7fb4-1aa9355c627a@redhat.com>
Date: Fri, 19 May 2023 11:21:35 +0200
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101
 Thunderbird/102.10.0
To: Peter Collingbourne <pcc@google.com>
Cc: Catalin Marinas <catalin.marinas@arm.com>,
 =?UTF-8?B?UXVuLXdlaSBMaW4gKOael+e+pOW0tCk=?= <Qun-wei.Lin@mediatek.com>,
 linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org,
 linux-kernel@vger.kernel.org, "surenb@google.com" <surenb@google.com>,
 =?UTF-8?B?Q2hpbndlbiBDaGFuZyAo5by16Yym5paHKQ==?=
 <chinwen.chang@mediatek.com>,
 "kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>,
 =?UTF-8?B?S3Vhbi1ZaW5nIExlZSAo5p2O5Yag56mOKQ==?=
 <Kuan-Ying.Lee@mediatek.com>, =?UTF-8?B?Q2FzcGVyIExpICjmnY7kuK3mpq4p?=
 <casper.li@mediatek.com>,
 "gregkh@linuxfoundation.org" <gregkh@linuxfoundation.org>,
 vincenzo.frascino@arm.com, Alexandru Elisei <alexandru.elisei@arm.com>,
 will@kernel.org, eugenis@google.com, Steven Price <steven.price@arm.com>,
 stable@vger.kernel.org
References: <20230512235755.1589034-1-pcc@google.com>
 <20230512235755.1589034-2-pcc@google.com>
 <7471013e-4afb-e445-5985-2441155fc82c@redhat.com> <ZGJtJobLrBg3PtHm@arm.com>
 <ZGLC0T32sgVkG5kX@google.com>
 <851940cd-64f1-9e59-3de9-b50701a99281@redhat.com>
 <CAMn1gO79e+v3ceNY0YfwrYTvU1monKWmTedXsYjtucmM7s=MVA@mail.gmail.com>
 <c9f1fc7c-62a2-4768-7992-52e34ec36d0f@redhat.com>
 <CAMn1gO7t0S7CmeU=59Lq10N0WvrKebM=W91W7sa+SQoG13Uppw@mail.gmail.com>
From: David Hildenbrand <david@redhat.com>
Organization: Red Hat
Subject: Re: [PATCH 1/3] mm: Move arch_do_swap_page() call to before
 swap_free()
In-Reply-To: <CAMn1gO7t0S7CmeU=59Lq10N0WvrKebM=W91W7sa+SQoG13Uppw@mail.gmail.com>
X-Mimecast-Spam-Score: 0
X-Mimecast-Originator: redhat.com
Content-Language: en-US
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=W1CH98en;
       spf=pass (google.com: domain of david@redhat.com designates
 170.10.133.124 as permitted sender) smtp.mailfrom=david@redhat.com;
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

>> Sorry, I meant actual anonymous memory pages, not shmem. Like, anonymous
>> pages that are COW-shared due to fork() or KSM.
>>
>> How does MTE, in general, interact with that? Assume one process ends up
>> modifying the tags ... and the page is COW-shared with a different
>> process that should not observe these tag modifications.
> 
> Tag modifications cause write faults if the page is read-only, so for
> COW shared pages we would end up copying the page in the usual way,
> which on arm64 would copy the tags as well via the copy_highpage hook
> (see arch/arm64/mm/copypage.c).

Oh, that makes sense, thanks for pointing that out!

... and I can spot that KSM also checks the tag when de-duplicating: 
pages_identical() ends up calling memcmp_pages(), which knows how to 
deal with tags.

Interestingly, calc_checksum() does not seem to care about tags. But 
that simply implies that pages with the same content have same checksum, 
independent of the tag. And pages_identical() is the single source of truth.

-- 
Thanks,

David / dhildenb

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/80f45fec-3e91-c7b3-7fb4-1aa9355c627a%40redhat.com.
