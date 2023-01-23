Return-Path: <kasan-dev+bncBC32535MUICBBAWHXGPAMGQENWSACLA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33f.google.com (mail-ot1-x33f.google.com [IPv6:2607:f8b0:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id 34EF367794F
	for <lists+kasan-dev@lfdr.de>; Mon, 23 Jan 2023 11:37:56 +0100 (CET)
Received: by mail-ot1-x33f.google.com with SMTP id c13-20020a9d784d000000b006866230a44asf6164053otm.15
        for <lists+kasan-dev@lfdr.de>; Mon, 23 Jan 2023 02:37:56 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1674470274; cv=pass;
        d=google.com; s=arc-20160816;
        b=AzQEvlYzv7tzXKxZeq+zRbMzuJnmBZ3k0Q+40NskOWOS/WK1wZhaTiz224J54YvK5K
         8MrUw+Q4wMTPTMnQFncic7P3eb9dnF6iOjZh8C6qdLjB7WsCtPQSPJLSOqaI2xhPMOfp
         rzSd1Uwn3oFCesLaDQcJO486JfvPUplSO4ikv4W/8TwFYdQP73UnXxutC0Jm9xX259Cj
         O9RgJszg91/SOacy+9GY95WFYJBw6if+4fRQ/u4GJYpgnJDrd2qPeFC07LywqRgsWRJ6
         6LeAygIYaFDUNdoITOD1V+7IxKrvrQPmmaKLKllOT0gxg9CjUp2chqPju3lQ5mAuO0zV
         BjYA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :organization:from:references:cc:to:subject:user-agent:mime-version
         :date:message-id:sender:dkim-signature;
        bh=xCgXhNKjpghDN+nl+xtANMKmO4t2fWWzkxrMOojTJWs=;
        b=M30G5z/brEHkNxWyL/RtSLk9XpelhtCOL6yvVFH3CneqZbZOLY4B5rB7m1btTyO1l+
         pX0caMr81c2PGHvvB4N62ixboZ4B2nT19VQN+GIOAGkk4e3PW8NjMIjYbyudZ1MvirPT
         QRrT2DVln/ed0ssvps0b9Oe5kM/ZSWAyXJhQslMD7FDjSd7euUaYySx+qHQiWE9mLILc
         o2vEMuQjSQAeAsQXoup+djn72qrWrpl8o8pmnmbQZC3TKTVDsLVd0xBEmTIky2n3+o1z
         ic1NhUylx+D1weXBun1gHslctcORgo3vrcTRsC54A4/iIPPRaGujnbD310gxw3HOol7F
         saJA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=BjI4QO3+;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-language:in-reply-to:organization:from
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=xCgXhNKjpghDN+nl+xtANMKmO4t2fWWzkxrMOojTJWs=;
        b=fr0ai5OGbhYulGbNOUIAHQ2fQkklRCyWRHyYbjh8geKXPRVHhOTWXf5yXtZLLmfKEk
         r2BoSkvh8gH1BN04/Pg6nP85bfSNzlxXbouV9BBDr2i78Dt2PGKRDSNXppA0wUzh57Ki
         pGVSDECa5yEVTTzC3egB6Jo9uhi9L3dm7lBLJ6aWl8U8+hk5gtulLJhbmAugCP/7e5ii
         ouMUEOPYSWvqZxJJdQN/9IpQCRx4KUAMmfKF/R2aQq561YP0pu3qAWMDZCJgIJxVbqzo
         GnGHpJOOdJ0U4GZvm0temEjHkBnm3DhUzxg6dD7hbiM0f0moEtT2PQFjlhqTw4s0lb1L
         dLgQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-language:in-reply-to:organization:from:references:cc:to
         :subject:user-agent:mime-version:date:message-id:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=xCgXhNKjpghDN+nl+xtANMKmO4t2fWWzkxrMOojTJWs=;
        b=nyBvxVpmC1id+pI1yia7/9LXTg5CUGnxtXDX0QivGPNzi79S4ZPJZ0qkf1emoVBth4
         lhiZmxXUFJLMFXnfuHe2vNUlZwCp0BD3CVLs8/5Wt9XxFI3bAm8VbRW1Pg2yCAP5nnkV
         MGLlerdZoXFKQm7mp26yvyLKGdNe3TfsECzbHrQH2qXOI2b1AUHQyPS5uSvcXQqwGSgt
         ecvXvrMhSUuCCckRnUX7v6jH7Bjw94mytVrwuR1c4ns5WowZQ0NpUcOM1fHmx6pH+Cvu
         OYDAWVpcpWoSefkwhBa/hC8eifFhxQ59sChTXf/QOp/2cWiBeN+se7lUsm1NXCzKHJBo
         WdIg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2kpYg+zO1upj+S3fvR0R2qV9M9eI9vjG3JZ4mUnqSxxKKNfw9N4o
	w8QzcccUZSM6LaCBlMjSq70=
X-Google-Smtp-Source: AMrXdXupLlEP2eglLtRNDJJ3Kz0KVLkTFllo+7kBPpHzz4Ye2vnfnFDq083npFVVmW+W6cwq6a0L+g==
X-Received: by 2002:a05:6870:6693:b0:15b:b957:7a9f with SMTP id ge19-20020a056870669300b0015bb9577a9fmr1357048oab.142.1674470274554;
        Mon, 23 Jan 2023 02:37:54 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:c8a2:b0:14c:767d:db2e with SMTP id
 er34-20020a056870c8a200b0014c767ddb2els4502862oab.4.-pod-prod-gmail; Mon, 23
 Jan 2023 02:37:54 -0800 (PST)
X-Received: by 2002:a05:6870:6a91:b0:15f:1ce8:896a with SMTP id mv17-20020a0568706a9100b0015f1ce8896amr12551516oab.3.1674470274102;
        Mon, 23 Jan 2023 02:37:54 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1674470274; cv=none;
        d=google.com; s=arc-20160816;
        b=lPb8rDq7IfUXI1sSjihqSRYy7VgqVR/866rgzXLPaFyxAEVoxTuuUF7Sb/l/dpwfNH
         zqbSdjMbnLqNGlt/91mtYpu3zTI7bMoyKH9vaEcdRJA+/XHB5LD/fDTbJy9m19EeJDl7
         Nhrh5eFWAjwUU2fxQ+XHdK3xZvAG67n8hA54nSA6Otd5+5TKcAjSjCQJncfkwuEbWofb
         VopQX9jpl0nmt6THEf/BhVa/2jVSnBq3TTNTssE2lJnUTwwlW4kMWBdLBNpzkWl+j9d+
         Ww5hIYhlGUDcLjGjfxkehTJwbqgD5xIsKZ4sTubdV+peASvWVsAFhOyPrXAI+i5teI+j
         Y/AA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:organization
         :from:references:cc:to:subject:user-agent:mime-version:date
         :message-id:dkim-signature;
        bh=Hggo02qDkslvw58GKMXOQy4JhLVANdK1lmYjKFYerek=;
        b=bjGALGI6VKj/vIfWaI5HzMhBRW3MEFfqU96bMW1f07qWfF+MhHxLNq+VaS/aJGaJV3
         glb3ryphBD79kJr4HY51G94Yfef1sy6anNn77pjjtr2kHWKq2Lw2vyeYqlrDH4q7zNUF
         7Bgx5gPpAqM0v2U2XWYgPyXGDWpbGG3m5w1p8/7JqJKU+/wJA5YWFk3QJWkuZccjG+Ws
         tB4K4CQJ085AFqI1ANDvQMJq/CP6i8DpwE2p012qDhLAnjNp4sOJ3el7M2UquLT6hSZ8
         RpZOzBm6UO4TWnIsqJGMumQYDpAmRFK665zPAJDgGYn4wuD3l1j8PvWX9ngDWfPHlknd
         Q6Vg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=BjI4QO3+;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id o2-20020aca5a02000000b0036bbb25d978si2010935oib.3.2023.01.23.02.37.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 23 Jan 2023 02:37:54 -0800 (PST)
Received-SPF: pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mail-wm1-f72.google.com (mail-wm1-f72.google.com
 [209.85.128.72]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.3, cipher=TLS_AES_128_GCM_SHA256) id
 us-mta-383-iHlBXiwONQqXOY1W1jyBDQ-1; Mon, 23 Jan 2023 05:37:52 -0500
X-MC-Unique: iHlBXiwONQqXOY1W1jyBDQ-1
Received: by mail-wm1-f72.google.com with SMTP id k34-20020a05600c1ca200b003db30c3ed63so5413410wms.2
        for <kasan-dev@googlegroups.com>; Mon, 23 Jan 2023 02:37:52 -0800 (PST)
X-Received: by 2002:a05:600c:920:b0:3da:22a6:7b6b with SMTP id m32-20020a05600c092000b003da22a67b6bmr23571312wmp.13.1674470271238;
        Mon, 23 Jan 2023 02:37:51 -0800 (PST)
X-Received: by 2002:a05:600c:920:b0:3da:22a6:7b6b with SMTP id m32-20020a05600c092000b003da22a67b6bmr23571296wmp.13.1674470270931;
        Mon, 23 Jan 2023 02:37:50 -0800 (PST)
Received: from ?IPV6:2003:cb:c704:1100:65a0:c03a:142a:f914? (p200300cbc704110065a0c03a142af914.dip0.t-ipconnect.de. [2003:cb:c704:1100:65a0:c03a:142a:f914])
        by smtp.gmail.com with ESMTPSA id h20-20020a1ccc14000000b003dafbd859a6sm10055905wmb.43.2023.01.23.02.37.49
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 23 Jan 2023 02:37:50 -0800 (PST)
Message-ID: <1a3ef082-d307-ee09-299f-47eda3515369@redhat.com>
Date: Mon, 23 Jan 2023 11:37:46 +0100
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101
 Thunderbird/102.6.0
Subject: Re: [PATCH 04/10] mm: move vmalloc_init and free_work down in
 vmalloc.c
To: Christoph Hellwig <hch@lst.de>, Andrew Morton
 <akpm@linux-foundation.org>, Uladzislau Rezki <urezki@gmail.com>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>,
 Alexander Potapenko <glider@google.com>,
 Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>,
 Vincenzo Frascino <vincenzo.frascino@arm.com>, kasan-dev@googlegroups.com,
 linux-mm@kvack.org
References: <20230121071051.1143058-1-hch@lst.de>
 <20230121071051.1143058-5-hch@lst.de>
From: David Hildenbrand <david@redhat.com>
Organization: Red Hat
In-Reply-To: <20230121071051.1143058-5-hch@lst.de>
X-Mimecast-Spam-Score: 0
X-Mimecast-Originator: redhat.com
Content-Language: en-US
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=BjI4QO3+;
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
> Move these two functions around a bit to avoid forward declarations.
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1a3ef082-d307-ee09-299f-47eda3515369%40redhat.com.
