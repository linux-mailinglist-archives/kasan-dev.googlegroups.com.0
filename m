Return-Path: <kasan-dev+bncBDWLZXP6ZEPRB5WWX2SQMGQEDZEQBYY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x337.google.com (mail-wm1-x337.google.com [IPv6:2a00:1450:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id CC91C751A2D
	for <lists+kasan-dev@lfdr.de>; Thu, 13 Jul 2023 09:44:55 +0200 (CEST)
Received: by mail-wm1-x337.google.com with SMTP id 5b1f17b1804b1-3fc0627eafbsf1661115e9.0
        for <lists+kasan-dev@lfdr.de>; Thu, 13 Jul 2023 00:44:55 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1689234295; cv=pass;
        d=google.com; s=arc-20160816;
        b=QkBGQeBTpF7eT7YxmweGiyosehrEXnywUIByjuOKw4N4rtcSZ06uPw+ZYU9tnaFVQL
         0tU7tEFXjncL/cbL7yOfUVWkL8Fp2RdmBfxk80anjMddGV3/fZHlnhuKKUuiCvoIc2lW
         oT3gHKU63vQXwtOSrvfki6Y10lPFcEZ0ncuGRCuMBn+jP3XcYnfYFd/iDSK2yXQzdxvj
         9XKIA1ykSJBRi8XkyZ/h3eiNhMFWZ6JU2lV/5kLd4mIJ1ff2D63MxoBYXHDqMsg2IgzB
         Sh1F45/clFCeVT5kVDmyJTH7iNaPvBL2lSS3f9GBMsygLIUUr3vtyy2v0m4JApLUVlFu
         PNng==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=Q2R8prWY6ntYxKu4Y7FtOGmt3vdwDL5av5vFPN5YoFU=;
        fh=PPWkH+iUfuDwOmlGGtHQPuvY83dV6tgEN0MbVWy+fBg=;
        b=lbNPcNpDVaOPEQx0rg8TBovQgTP93Nl4U8fIT5qE3omxoQrNo8i5wfaclk6iS3/R1L
         18K1saAicCCTTD+jQvXY0GEowrvnkOvwk5ytcHXKaMASyC6GrJiTulhmTlppAYemDEXa
         YkZrh2oZMTLZi2x75pYUTvzjpvQSIh+NVgVkSb+fQsxMZq/B5HSb2fgtwvWOCpdIZKLv
         ZFe0yacWQ43C+niSafb37Wc25na7eU176Lqv0Ubj2NYNtxFTouw1/wRyxsN0rtVLl/nj
         AIL5pw+fg9yRusoNR0al5Jqv0kkpmLRJVN+HJSY5wlNMtahmyrF6I8COt9tHXIIyVJkq
         haZA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=zBJPqBqy;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.28 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1689234295; x=1691826295;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=Q2R8prWY6ntYxKu4Y7FtOGmt3vdwDL5av5vFPN5YoFU=;
        b=krIag0qSuZMxgl+F7BpI/09Ge8sBrBC8nMrnao0fFg5EKsCgZ+J4iZRfJIVdYDGpUH
         84FR9G/epQUnwV+656st/W7MHjUsOw4ssBdz6faAc4klWRmXf1JgDDIeLilxW0GI0+og
         kxsZRfO73kijNQ8v7lvnN/er8dp6ikFAhE4JH7OS8QpOZrNQerztlCBVhqjo3SF38lzw
         I/H87KtKL4znaUA3FPaJTvx2FHJklge+ekTyxgqxqXmGXjAOfHSty/qp8C32a5dkxCnW
         ohp7mYyFwC4KC/5kj6Y5V4YYKWnGjwjp+duK0viPbeMmzsmvVRWUYcPeEl7k5kUh9yKA
         NvwQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1689234295; x=1691826295;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=Q2R8prWY6ntYxKu4Y7FtOGmt3vdwDL5av5vFPN5YoFU=;
        b=Gxs864q7d3sxfkzOGJFzI1wP7LrR9S788uGFxvYCxjOIPP8BFu1YVRxV+3j4+jCXMT
         n5VtELFMks8WSkg9rn9f4DJkrdHvbxyyZNx+x7Nk01tTMPXyE58hax/RY7M/L5wF0Xlh
         uVNeGvnzNc+l8Vo+PRv8GuCy2WnU8TNI8PcAhSCJ0cXzYR8EK9So/bM6hE9p//inrxRl
         m7kKWfx2/YId2u2iilQlnvwOmV2fgnv0gXNniaU4kBB+rw3bUTFLBQ29+VGbWHBSq5ko
         QN/tUgG2NEPEfCjTpWACRp/FIbuAqfphsHzqmQJriyhBJFNLTMnrPXWNueB9KsmdWnI4
         bxkw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ABy/qLaqGFk92Ilno2Oe61dpRmtrZNgKxuv5OQRg2WWD5nMG/mIZS0Rj
	C1adCNHEMOBMXiNLCsH12bc=
X-Google-Smtp-Source: APBJJlH1o2nE1YCNsfoAyLMAPakieBP4ronG3WvMcid90deqaq2cc0RIRjWWQrDX/geYA5G8SDGwbw==
X-Received: by 2002:a1c:7514:0:b0:3fc:180:6463 with SMTP id o20-20020a1c7514000000b003fc01806463mr824171wmc.7.1689234294659;
        Thu, 13 Jul 2023 00:44:54 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:c18:b0:3fc:1365:b57f with SMTP id
 fm24-20020a05600c0c1800b003fc1365b57fls82630wmb.2.-pod-prod-00-eu; Thu, 13
 Jul 2023 00:44:53 -0700 (PDT)
X-Received: by 2002:a05:600c:3d88:b0:3f7:ecdf:ab2d with SMTP id bi8-20020a05600c3d8800b003f7ecdfab2dmr3170672wmb.20.1689234293227;
        Thu, 13 Jul 2023 00:44:53 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1689234293; cv=none;
        d=google.com; s=arc-20160816;
        b=sEgJvSSsrdxPrXJMKQiO8H79Lzy1XIeyBmxNi5UUMnWWEhJqHkAj6LcNjr+S3gYN6V
         C5wWn3CGHDnMkLP9SUdhj2wjbk0mDwPHFoxG8EcwT0veHHWeCvQcYhWxtka3UZ2h2Q6U
         t8VyOshy0lkyMhpauZ7HZuyEcXCPHts89lxvLcsHynwC2YgFndVn5Udfy35zwMQm9DLo
         Ew9L5LM0wAY8rk9Bfpb39d3lvNktDkGj9EFhAlPSs9aXZWWuCzpelOcca3IW/RnjlkWT
         Bw0439Uy72F2RvYC+dsF5qU8hlcHOeZPJg1rKW460G/JIKplB27JWYSrqkLrx00o41fs
         M9NA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature;
        bh=DKzxp2+bTU0RvBuftCWUrTE4tMrCxaPuXQY51bUYZiM=;
        fh=PPWkH+iUfuDwOmlGGtHQPuvY83dV6tgEN0MbVWy+fBg=;
        b=U2OuTTZf/kasRp17X7p6OUgApnxFrK3zofzTAMyJImvjnJBebO8cWzAA9Td5JC6Ya4
         nIy9YxDXMwVMDbGFOQd/PJhTuSI7pfSC65eRO2WO5LAfvCAG3wkw7kotJOUG8o0ufeaC
         1WRLlGGzK2xCCwG2g3183HMKqXhEcqw7a5pB+NpK1pB5QZ3bashv0oUhKSQoCdZL7KX7
         k9cirtky7WB0Wu8IEYBKq3ugtqsmjzGJIG5A64oNQ5xYHvn2RZUH1JSsrT49R3uQD8Y8
         2K3bzA7YnLYmlUiYFx4IhPnnG4Z8R6d85b2S/4ip9ojR8/jyQ49HIXMPteKP2pW2ZAgG
         jaPA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=zBJPqBqy;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.28 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [195.135.220.28])
        by gmr-mx.google.com with ESMTPS id p22-20020a05600c1d9600b003facc8c7725si1060509wms.0.2023.07.13.00.44.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 13 Jul 2023 00:44:53 -0700 (PDT)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.220.28 as permitted sender) client-ip=195.135.220.28;
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id D125721E4E;
	Thu, 13 Jul 2023 07:44:52 +0000 (UTC)
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by imap2.suse-dmz.suse.de (Postfix) with ESMTPS id 8C6BA133D6;
	Thu, 13 Jul 2023 07:44:52 +0000 (UTC)
Received: from dovecot-director2.suse.de ([192.168.254.65])
	by imap2.suse-dmz.suse.de with ESMTPSA
	id 9qF4IXSrr2QVFgAAMHmgww
	(envelope-from <vbabka@suse.cz>); Thu, 13 Jul 2023 07:44:52 +0000
Message-ID: <b18ca2ce-5ebc-1a38-bb9d-a8bb9070cdb1@suse.cz>
Date: Thu, 13 Jul 2023 09:44:52 +0200
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101
 Thunderbird/102.13.0
Subject: Re: [PATCH 2/2] mm/slub: remove freelist_dereference()
Content-Language: en-US
To: Kees Cook <keescook@chromium.org>
Cc: Christoph Lameter <cl@linux.com>, David Rientjes <rientjes@google.com>,
 Pekka Enberg <penberg@kernel.org>, Joonsoo Kim <iamjoonsoo.kim@lge.com>,
 Hyeonggon Yoo <42.hyeyoo@gmail.com>,
 Roman Gushchin <roman.gushchin@linux.dev>, linux-mm@kvack.org,
 patches@lists.linux.dev, linux-kernel@vger.kernel.org,
 Matteo Rizzo <matteorizzo@google.com>, Jann Horn <jannh@google.com>,
 Andrey Konovalov <andreyknvl@google.com>, Marco Elver <elver@google.com>,
 Alexander Potapenko <glider@google.com>, kasan-dev@googlegroups.com,
 linux-hardening@vger.kernel.org
References: <20230711134623.12695-3-vbabka@suse.cz>
 <20230711134623.12695-4-vbabka@suse.cz> <202307110917.DEED145F0@keescook>
From: Vlastimil Babka <vbabka@suse.cz>
In-Reply-To: <202307110917.DEED145F0@keescook>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=zBJPqBqy;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519;       spf=pass
 (google.com: domain of vbabka@suse.cz designates 195.135.220.28 as permitted
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

On 7/11/23 18:21, Kees Cook wrote:
> On Tue, Jul 11, 2023 at 03:46:25PM +0200, Vlastimil Babka wrote:
>>  
>>  #ifndef CONFIG_SLUB_TINY
>> -- 
>> 2.41.0
>> 
> 
> I like reducing the complexity here, but I find dropping the "object"
> reassignment makes this a bit harder to read. What about:

Alright.

> 	object = kasan_reset_tag(object);
> 	unsigned long ptr_addr = (unsigned long)object + s->offset;
> 	freeptr_t p = *(freeptr_t *)(ptr_addr);

Are we really so benevolent with declaration-after-statement now? :)

> 	return freelist_ptr_decode(s, p, ptr_addr);
> 
> ?
> 
> They're the same result, so either way:
> 
> Acked-by: Kees Cook <keescook@chromium.org>
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/b18ca2ce-5ebc-1a38-bb9d-a8bb9070cdb1%40suse.cz.
