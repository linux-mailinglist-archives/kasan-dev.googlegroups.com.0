Return-Path: <kasan-dev+bncBC32535MUICBBNWLXGPAMGQE7SSRUQY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x1138.google.com (mail-yw1-x1138.google.com [IPv6:2607:f8b0:4864:20::1138])
	by mail.lfdr.de (Postfix) with ESMTPS id 1811B677978
	for <lists+kasan-dev@lfdr.de>; Mon, 23 Jan 2023 11:47:20 +0100 (CET)
Received: by mail-yw1-x1138.google.com with SMTP id 00721157ae682-4de8261cc86sf116360657b3.13
        for <lists+kasan-dev@lfdr.de>; Mon, 23 Jan 2023 02:47:20 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1674470839; cv=pass;
        d=google.com; s=arc-20160816;
        b=ucNbW7P1v3pE20v5R3FLeN1PoPuyHXSkgUj3IY2vjEnQBGzK5hUKbtnjYH5KJni+W1
         2YhKDUE4+pcMGAwK8pRHzI3JDMPb0RsIVdBkhjOJ4uoLpU1aadJe4oyNQGaxZ3Q+cWT8
         zBK32xDlTHWP9KZrxtGYMBqwFaAjsg7kDfNAKREv5QpP7tTCApaYTMP/t+ZsXniE1fEI
         cuZfYlw16LzkCZaGdL06R12IGTOsmsdpYXSPE0XyirujlSmo6rEGQo4FIqqCSYQjxVT8
         LiWAmzqmoJs8toyX6FqWNdk0XObNa5U9wo7Uc/PoCMoN21aB2Y4VfG/WIeUes8y0ub8g
         9r+g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :organization:from:references:cc:to:subject:user-agent:mime-version
         :date:message-id:sender:dkim-signature;
        bh=uxbVk/eICqZEF43Jz1bfp7YdCYvOY247wUakecOTx6E=;
        b=ZPx9d8kdtTgJz4JnSnXhK1NwYRhRw3/17TpGxNV0m2D8jpd/Q1zxaGhWDQGKq1y4Gr
         WeIe+/Qbx+dRr/UlEPy1C9qwukjYLF+xppZlXAJIlafFCvgMs/5hwGlPX3HEjdAdKBfr
         oDBTwUg1hAEvoS68sBahSMmsNSobma982+oLbQuP003IeuIrc7vtzeOaUq8UZOVWpUdK
         KAUmcoK11aWZl0W2qEyAQWb9Jo9MlfAGjBHMEFlcL0pBurlNiXBR0OVahJnOJvq2lguj
         R1c016MD35fPpeD4y0xforkftlMft/DhhAlsJk7lV3igxkR6YTOTuxsd0y2tnUSjyP/X
         DRJw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=GoPwvA+f;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-language:in-reply-to:organization:from
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=uxbVk/eICqZEF43Jz1bfp7YdCYvOY247wUakecOTx6E=;
        b=AZNzltmbUyKdSN9S+tDRiwpw1DzDb71fpfn7WAq2fWlM0UROMpjUI3DYHTM7qz1Deh
         CGprQE86xoGzxpTakrQS1FdT43++B4nQhxsyz2cIFKmlltFqXQoFCm1P1+S7I6JbAi3X
         w+9OoUW957jwBczqcypYMAQ8MxgIGE1XcFV6wFQ2irJrha8pLywJGuC4I9xy3vbr8MWg
         cYCap9LPPOqYxRkjQrNLBrQRDl5iIjWW1FVsOOwe/zetMjd6kByBylK3xuzdgRxKqpQ8
         bQ1UUZMXrXOnMgxZ38jKLIo9IjcHGfovXnDneYinztvCfu4Kk+iCTEbmdqT2RC2qaNGJ
         n2GQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-language:in-reply-to:organization:from:references:cc:to
         :subject:user-agent:mime-version:date:message-id:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=uxbVk/eICqZEF43Jz1bfp7YdCYvOY247wUakecOTx6E=;
        b=wkwd3af44ZnpJZ67ik4W8pgVZ/GtU6RJ7Wxit6tuG0RnL4j9rHWUtA+viuetjFC9LJ
         8kEDzj8MLjLpmLAyu0a7/hqDl8ZFyVIE9cWk+LXjg8zSuxEwouFOlk0b4D+7vtc3g7mn
         ut/86hkYJPf7Xx20/HKz+MV/gBxOtNbDY3+gxTAxC/P5rT+5G8zdD9TCuj/tDU/ySMJT
         Yjy9+qWBTH5K4P1Tcf0cK405H8zu7YObf4yeZukYM1bGeDtdWXitueBEq7eofByzUpUS
         sfSmU9vGY/zSIjFUDOqWTLKe6CvSG9anQz4bMTP30eO+7WvPazqdmHt8A810RhD1Pk6Q
         0Clw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2ko67agMUVJmkXlXzKZfA5o514b2Bw6b+0Hzl8j1h60BIQ11SsiR
	+rQ5s63iPsRVVPRatTTghw8=
X-Google-Smtp-Source: AMrXdXuD1LJSLgPxj1/HGE89L+cBSoz4Vo1g4VT8URcNNyIY5X9TCo96c+5zZO0gMFrGeRNOtgTBdQ==
X-Received: by 2002:a25:abf1:0:b0:7b1:6d58:1718 with SMTP id v104-20020a25abf1000000b007b16d581718mr2913563ybi.390.1674470839007;
        Mon, 23 Jan 2023 02:47:19 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:2b44:0:b0:7ba:b53e:630f with SMTP id r65-20020a252b44000000b007bab53e630fls6299776ybr.9.-pod-prod-gmail;
 Mon, 23 Jan 2023 02:47:18 -0800 (PST)
X-Received: by 2002:a25:3793:0:b0:802:a2ef:ebc8 with SMTP id e141-20020a253793000000b00802a2efebc8mr6237040yba.32.1674470838446;
        Mon, 23 Jan 2023 02:47:18 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1674470838; cv=none;
        d=google.com; s=arc-20160816;
        b=IGq3ow8sK1fTq7QR57SQ1udAbmqxCSvduX4HTOttiLgEWuqqrvccl9x7fOiP2ZeLub
         bBOC3SQWjBIVQ0TWq7XyZazAudfHHPcNZ9gupP1NwjRxOm+d52sNXOP0gs4/WJCg2LHk
         UclFOkIevpLH5VSNJbZ4BTmgXdZkrQGcfaWhnzIySI7FeoLU0k4MuVsMH0yMfe4vRO5K
         5+3qytRpjSTDKUkJBVQ4kT2CJUZlXhVsMHC/w6uaU2OMCXwFWGVD9HBM/B8xawx/5qSc
         bmpt9GNDlJAbRQdIqkT64IXHgGXLUSMAiq/Dh7SJGO/G+VzFWCUk18d7KJiyh5riYe0b
         qM0A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:organization
         :from:references:cc:to:subject:user-agent:mime-version:date
         :message-id:dkim-signature;
        bh=jMF0QVRZokxUQ8ZE9nonkCqJFyuhJkD9MJ3BAKy/inU=;
        b=ZLCauzGecRqm9hwQBDsjCuq8dVU8CtUBLVHOAen1s5KWMP5VC/tP7xULgTA1XRODm9
         qExuKt2XK3yBxp+IPIwVU7046tsqVK6BEhDBz/r+E5k0Bve1x2QSu1y+ensNhgwry1oR
         G0Wfj9IMPe1yPXIX1ckhiNKgAg50/L6hziKLZD0b317fFOdlM54funeW+ifRPWFc/Yo5
         FBYBqYsYkTt1NkAfR8EOSXqufVSWZRp8R05R+vuZbjt7piuhp/9PkGUYFy3k7nxtscsj
         2EogJ+xa6gyZ84GZooGek9oQG4grA3NWKNHr1i3b+1Ge9E89KjrsRt/j+SN2uYfQ/7zk
         6+LQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=GoPwvA+f;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id o134-20020a25738c000000b008032606ec55si791335ybc.0.2023.01.23.02.47.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 23 Jan 2023 02:47:18 -0800 (PST)
Received-SPF: pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mail-wm1-f70.google.com (mail-wm1-f70.google.com
 [209.85.128.70]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.3, cipher=TLS_AES_128_GCM_SHA256) id
 us-mta-399-OIUn71AXO22v4D5pwa-yjA-1; Mon, 23 Jan 2023 05:47:14 -0500
X-MC-Unique: OIUn71AXO22v4D5pwa-yjA-1
Received: by mail-wm1-f70.google.com with SMTP id 9-20020a05600c228900b003daf72fc827so7285835wmf.9
        for <kasan-dev@googlegroups.com>; Mon, 23 Jan 2023 02:47:13 -0800 (PST)
X-Received: by 2002:a05:600c:4e93:b0:3db:d3f:a91f with SMTP id f19-20020a05600c4e9300b003db0d3fa91fmr21266542wmq.23.1674470832953;
        Mon, 23 Jan 2023 02:47:12 -0800 (PST)
X-Received: by 2002:a05:600c:4e93:b0:3db:d3f:a91f with SMTP id f19-20020a05600c4e9300b003db0d3fa91fmr21266521wmq.23.1674470832654;
        Mon, 23 Jan 2023 02:47:12 -0800 (PST)
Received: from ?IPV6:2003:cb:c704:1100:65a0:c03a:142a:f914? (p200300cbc704110065a0c03a142af914.dip0.t-ipconnect.de. [2003:cb:c704:1100:65a0:c03a:142a:f914])
        by smtp.gmail.com with ESMTPSA id w12-20020a05600c474c00b003db2b81660esm10574251wmo.21.2023.01.23.02.47.11
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 23 Jan 2023 02:47:12 -0800 (PST)
Message-ID: <1eb74709-94fd-25d8-651a-065f0382768a@redhat.com>
Date: Mon, 23 Jan 2023 11:47:11 +0100
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101
 Thunderbird/102.6.0
Subject: Re: [PATCH 09/10] mm: split __vunmap
To: Christoph Hellwig <hch@lst.de>, Andrew Morton
 <akpm@linux-foundation.org>, Uladzislau Rezki <urezki@gmail.com>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>,
 Alexander Potapenko <glider@google.com>,
 Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>,
 Vincenzo Frascino <vincenzo.frascino@arm.com>, kasan-dev@googlegroups.com,
 linux-mm@kvack.org
References: <20230121071051.1143058-1-hch@lst.de>
 <20230121071051.1143058-10-hch@lst.de>
From: David Hildenbrand <david@redhat.com>
Organization: Red Hat
In-Reply-To: <20230121071051.1143058-10-hch@lst.de>
X-Mimecast-Spam-Score: 0
X-Mimecast-Originator: redhat.com
Content-Language: en-US
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=GoPwvA+f;
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
> vunmap only needs to find and free the vmap_area and vm_strut, so open

s/vm_strut/vm_struct/

> code that there and merge the rest of the code into vfree.
> 
> Signed-off-by: Christoph Hellwig <hch@lst.de>
> ---

Reviewed-by: David Hildenbrand <david@redhat.com>


-- 
Thanks,

David / dhildenb

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1eb74709-94fd-25d8-651a-065f0382768a%40redhat.com.
