Return-Path: <kasan-dev+bncBDCZTXNV3YCBBOEHQL7QKGQELJZEU2I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-f57.google.com (mail-oo1-f57.google.com [209.85.161.57])
	by mail.lfdr.de (Postfix) with ESMTPS id 66DBF2DFB6C
	for <lists+kasan-dev@lfdr.de>; Mon, 21 Dec 2020 12:15:05 +0100 (CET)
Received: by mail-oo1-f57.google.com with SMTP id o15sf3657542oov.22
        for <lists+kasan-dev@lfdr.de>; Mon, 21 Dec 2020 03:15:05 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1608549304; cv=pass;
        d=google.com; s=arc-20160816;
        b=S6+SYl4xf2Gs50R0hI8aEHG2T0iuFYQ83DZlnvwqpACMvf/ay85EDHxG0tZn/wFqUC
         ZDyzXQKJtV6c3RqbQSfcX5yUIUxEHlJyuKuN/B0ZnFzMnnWKZaZysVeR5Ro8ndjl2ZjT
         k7pM7nxxAbxqkVUeHsymVMoVyrvvZkG+gfxmkIgp29q4HtOHsJNSJB/E2J6OghVa0ghm
         6OlGeHgAEhYJHwBaiohnX7/bAGzEio6oEeX3zRXcRbP7TxsNAhpSmKA0aCBO8vMu0nUP
         T2ypWSGOiTeglb07eNfHhtGf6wm1uR43DI7bJ6wjN29Yiv5ezGP2tpjZyAmjo8LLcmny
         K70Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:references:cc:to:from
         :subject:dmarc-filter:sender;
        bh=9P6w8vfaRXZdbK0Yus3cqzrW9mAbYj2jcU+ewxvihRc=;
        b=bZnzN9DWyb9k6bKnhezwlaDGD4ngROijA7S/Emscj0kjxV5/hMHHReZBymP10vj0or
         Hpfci+5YBsFLqzecan/MgSb/nv8lERVpQrRRu+YGKglQfIkEaDkfchOeORXBl+ftvN8Z
         BSBgxcHSufbZyRYliLfGRwJB8+11rbKvlJOv75BI1NUAnGwKDDBUDMTzGr/zSiWx1uPR
         ypA9I80nn1JAA8L65xqQA88LaMh9ReoZuc9SsbHZsAEKoaf7Q4AFIQ7V/JdvueHfJNap
         PTb6OHkDr8iurv00vFKlK04rPiAzqJGeL3azmun9s5HHhdlnSSrNUIfAgf+4tigKJm+/
         Kc3Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@mg.codeaurora.org header.s=smtp header.b=xgkCDIig;
       spf=pass (google.com: domain of bounce+2683c2.be9e4a-kasan-dev=googlegroups.com@mg.codeaurora.org designates 198.61.254.31 as permitted sender) smtp.mailfrom="bounce+2683c2.be9e4a-kasan-dev=googlegroups.com@mg.codeaurora.org"
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:dmarc-filter:subject:from:to:cc
         :references:message-id:date:user-agent:mime-version:in-reply-to
         :content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=9P6w8vfaRXZdbK0Yus3cqzrW9mAbYj2jcU+ewxvihRc=;
        b=G4tkOAIKclgo2tr2y6XygEdWAfz+bP3MGA6Hx17s5/55gfzbBwAnf9fI0xZLMQ8Aw7
         5Z7wQFE+dNi50x9H37mOZGTJ4f2PMEETnSZ8HlPZUv5xYsKjeG16LAEh0HFp0GM9QjR5
         0n7LgcviUWe7vyn20MTk9IAFJSQfcdgznWlJMPjwshL6Gz3hN35P7dGWyO1hIoQe6zzU
         CT6JOBrYfE35vZWXwNTFinKumVB9SVNcG+XL5Wskq8pMABNOWtOFOcMDlWw1XBydsbIv
         OdWG5lBJngFwWdeM7HrbUafYqAl4HtfIy1pdMGpQNIqBYo61eVXvUn4A8aId5Tr6q4cd
         O9iA==
X-Gm-Message-State: AOAM533zl2iSt/EDiEkTiM9ainbV9lTD+YyF+RrymIns3OpypeMH2Q1Y
	Jc7M64bAPQLiFrDqyOUD/EQ=
X-Google-Smtp-Source: ABdhPJymXB4Rrdl7Dm/V/jROaRrc8hng7LSeBBBTqHstaZqrptj3wjAhDBNELEOe1V+rijXoBGhiQw==
X-Received: by 2002:aca:1917:: with SMTP id l23mr10645430oii.64.1608549304263;
        Mon, 21 Dec 2020 03:15:04 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:b1c5:: with SMTP id j5ls296724ooo.11.gmail; Mon, 21 Dec
 2020 03:15:04 -0800 (PST)
X-Received: by 2002:a4a:3791:: with SMTP id r139mr11047914oor.87.1608549303943;
        Mon, 21 Dec 2020 03:15:03 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1608549303; cv=none;
        d=google.com; s=arc-20160816;
        b=Qgx6XOadp/1qc2KFb0JfIRwQbcRfcJwyuyxRKWqHPyT9KEXycatnfLiMiu6kTXzVtL
         a3t5PYyd4Ac8hTFBCVwpiZayU8cUB4eaoFNdzqqV0v8+leYrHWJkGrDeqpBkJZUffwVg
         Rp7CCv1DxmldLWC8Acw4akU+3u5aIuKKihQzefOpwLrZgkr1AygzC/9wdXyKr+2kOQWH
         AzdMvGDUp20gFw7bzAkaup/CVKOyC6J99O2VKw312UBSUsGnjKcLcfVTxVEVlXa6VrVY
         tDShlvHSYzLWAyRNsPj8Ctn/zr7LeBq+wi4PhOVWWO9Ouyq471qruJvfe1pYa2fyqVNn
         rGNg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:references:cc:to:from:subject
         :dmarc-filter:sender:dkim-signature;
        bh=Y4CbVjRa9PKJTQWOMPwKVt5xzYyrbkTeQUsDXoEzPFU=;
        b=aJ0vvrFbDniZDHp5ZVu1sqLWEAqBeS8DpmqdnRHdhmcfsUziCLDZSNd8CAuMyuaeFf
         J/bu90bWF2A8/OupbB1cfbMRRQgunc5q2VcdrsPv+22s+oowAnIqavK7PdTCe0D/1LqW
         mIKSLhgw+F6nuP0CluebOWKD1vys6yZ76rsl7lM2wZKJC5TBmMa5gHtrXzjM7c+33wTW
         oLYIyGt3/cXHsL6E4A3WfYqKt+yX3Y3N8NHYXpitcjjwcTi23B2uWohZvH8MA8ce+Gp4
         +uK8wTJ0BKG4Rrion9oHUu6hNO7zQ+oxGA1h0KxR0bBwXVUiqQh8Nr7PJpNF3z2gvCOT
         5Phg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@mg.codeaurora.org header.s=smtp header.b=xgkCDIig;
       spf=pass (google.com: domain of bounce+2683c2.be9e4a-kasan-dev=googlegroups.com@mg.codeaurora.org designates 198.61.254.31 as permitted sender) smtp.mailfrom="bounce+2683c2.be9e4a-kasan-dev=googlegroups.com@mg.codeaurora.org"
Received: from so254-31.mailgun.net (so254-31.mailgun.net. [198.61.254.31])
        by gmr-mx.google.com with UTF8SMTPS id v23si1842686otn.0.2020.12.21.03.15.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 21 Dec 2020 03:15:03 -0800 (PST)
Received-SPF: pass (google.com: domain of bounce+2683c2.be9e4a-kasan-dev=googlegroups.com@mg.codeaurora.org designates 198.61.254.31 as permitted sender) client-ip=198.61.254.31;
X-Mailgun-Sending-Ip: 198.61.254.31
X-Mailgun-Sid: WyIyNmQ1NiIsICJrYXNhbi1kZXZAZ29vZ2xlZ3JvdXBzLmNvbSIsICJiZTllNGEiXQ==
Received: from smtp.codeaurora.org
 (ec2-35-166-182-171.us-west-2.compute.amazonaws.com [35.166.182.171]) by
 smtp-out-n06.prod.us-east-1.postgun.com with SMTP id
 5fe083ab0564dfefcdd1f9ae (version=TLS1.2,
 cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256); Mon, 21 Dec 2020 11:14:51
 GMT
Sender: vjitta=codeaurora.org@mg.codeaurora.org
Received: by smtp.codeaurora.org (Postfix, from userid 1001)
	id 55F59C43462; Mon, 21 Dec 2020 11:14:50 +0000 (UTC)
X-Spam-Checker-Version: SpamAssassin 3.4.0 (2014-02-07) on
	aws-us-west-2-caf-mail-1.web.codeaurora.org
X-Spam-Level: 
X-Spam-Status: No, score=-4.1 required=2.0 tests=ALL_TRUSTED,BAYES_00,
	NICE_REPLY_A,SPF_FAIL,URIBL_BLOCKED autolearn=unavailable autolearn_force=no
	version=3.4.0
Received: from [192.168.0.100] (unknown [182.18.191.136])
	(using TLSv1.2 with cipher ECDHE-RSA-AES128-GCM-SHA256 (128/128 bits))
	(No client certificate requested)
	(Authenticated sender: vjitta)
	by smtp.codeaurora.org (Postfix) with ESMTPSA id D2058C433C6;
	Mon, 21 Dec 2020 11:14:44 +0000 (UTC)
DMARC-Filter: OpenDMARC Filter v1.3.2 smtp.codeaurora.org D2058C433C6
Subject: Re: [PATCH v3] lib: stackdepot: Add support to configure
 STACK_HASH_SIZE
From: Vijayanand Jitta <vjitta@codeaurora.org>
To: Alexander Potapenko <glider@google.com>
Cc: Minchan Kim <minchan@kernel.org>,
 Vincenzo Frascino <vincenzo.frascino@arm.com>, dan.j.williams@intel.com,
 broonie@kernel.org, Masami Hiramatsu <mhiramat@kernel.org>,
 LKML <linux-kernel@vger.kernel.org>,
 Andrew Morton <akpm@linux-foundation.org>,
 Andrey Konovalov <andreyknvl@google.com>, qcai@redhat.com,
 ylal@codeaurora.org, vinmenon@codeaurora.org,
 kasan-dev <kasan-dev@googlegroups.com>
References: <1607576401-25609-1-git-send-email-vjitta@codeaurora.org>
 <CAG_fn=VKsrYx+YOGPnZw_Q5t6Fx7B59FSUuphj7Ou+DDFKQ+8Q@mail.gmail.com>
 <77e98f0b-c9c3-9380-9a57-ff1cd4022502@codeaurora.org>
 <CAG_fn=WbN6unD3ASkLUcEmZvALOj=dvC0yp6CcJFkV+3mmhwxw@mail.gmail.com>
 <6cc89f7b-bf40-2fd3-96ce-2a02d7535c91@codeaurora.org>
 <CAG_fn=VOHag5AUwFbOj_cV+7RDAk8UnjjqEtv2xmkSDb_iTYcQ@mail.gmail.com>
 <255400db-67d5-7f42-8dcb-9a440e006b9d@codeaurora.org>
 <f901afa5-7c46-ceba-2ae9-6186afdd99c0@codeaurora.org>
 <CAG_fn=UjJQP_gfDm3eJTPY371QTwyDJKXBCN2gs4DvnLP2pbyQ@mail.gmail.com>
 <7f2e171f-fa44-ef96-6cc6-14e615e3e457@codeaurora.org>
 <CAG_fn=VihkHLx7nHRrzQRuHeL-UYRezcyGLDQMJY+d1O5AkJfA@mail.gmail.com>
 <601d4b1a-8526-f7ad-d0f3-305894682109@codeaurora.org>
 <CAG_fn=V8e8y1fbOaYUD5SfDSQ9+Tc3r7w6ZSoJ-ZNFJvvq-Aeg@mail.gmail.com>
 <9e0d2c07-af1f-a1d3-fb0d-dbf2ae669f96@codeaurora.org>
 <CAG_fn=UXQUGiDqmChqD-xX-yF5Jp+7K+oHwKPrO9DZL-zW_4KQ@mail.gmail.com>
 <48df48fe-dc36-83a4-1c11-e9d0cf230372@codeaurora.org>
Message-ID: <6110a26b-dc87-b6f9-e679-aa60917403de@codeaurora.org>
Date: Mon, 21 Dec 2020 16:44:36 +0530
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:78.0) Gecko/20100101
 Thunderbird/78.5.1
MIME-Version: 1.0
In-Reply-To: <48df48fe-dc36-83a4-1c11-e9d0cf230372@codeaurora.org>
Content-Type: text/plain; charset="UTF-8"
Content-Language: en-GB
X-Original-Sender: vjitta@codeaurora.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@mg.codeaurora.org header.s=smtp header.b=xgkCDIig;       spf=pass
 (google.com: domain of bounce+2683c2.be9e4a-kasan-dev=googlegroups.com@mg.codeaurora.org
 designates 198.61.254.31 as permitted sender) smtp.mailfrom="bounce+2683c2.be9e4a-kasan-dev=googlegroups.com@mg.codeaurora.org"
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



On 12/18/2020 2:10 PM, Vijayanand Jitta wrote:
> 
> 
> On 12/17/2020 4:24 PM, Alexander Potapenko wrote:
>>>> Can you provide an example of a use case in which the user wants to
>>>> use the stack depot of a smaller size without disabling it completely,
>>>> and that size cannot be configured statically?
>>>> As far as I understand, for the page owner example you gave it's
>>>> sufficient to provide a switch that can disable the stack depot if
>>>> page_owner=off.
>>>>
>>> There are two use cases here,
>>>
>>> 1. We don't want to consume memory when page_owner=off ,boolean flag
>>> would work here.
>>>
>>> 2. We would want to enable page_owner on low ram devices but we don't
>>> want stack depot to consume 8 MB of memory, so for this case we would
>>> need a configurable stack_hash_size so that we can still use page_owner
>>> with lower memory consumption.
>>>
>>> So, a configurable stack_hash_size would work for both these use cases,
>>> we can set it to '0' for first case and set the required size for the
>>> second case.
>>
>> Will a combined solution with a boolean boot-time flag and a static
>> CONFIG_STACKDEPOT_HASH_SIZE work for these cases?
>> I suppose low-memory devices have a separate kernel config anyway?
>>
> 
> Yes, the combined solution will also work but i think having a single
> run time config is simpler instead of having two things to configure.
> 

To add to it we started of with a CONFIG first, after the comments from
Minchan (https://lkml.org/lkml/2020/11/3/2121) we decided to switch to
run time param.

Quoting Minchan's comments below:

"
1. When we don't use page_owner, we don't want to waste any memory for
stackdepot hash array.
2. When we use page_owner, we want to have reasonable stackdeport hash array

With this configuration, it couldn't meet since we always need to
reserve a reasonable size for the array.
Can't we make the hash size as a kernel parameter?
With it, we could use it like this.

1. page_owner=off, stackdepot_stack_hash=0 -> no more wasted memory
when we don't use page_owner
2. page_owner=on, stackdepot_stack_hash=8M -> reasonable hash size
when we use page_owner.
"

Thanks,
Vijay
>> My concern is that exposing yet another knob to users won't really
>> solve their problems, because the hash size alone doesn't give enough
>> control over stackdepot memory footprint (we also have stack_slabs,
>> which may get way bigger than 8Mb).
>>
> 
> True, stack_slabs can consume more memory but they consume most only
> when stack depot is used as they are allocated in stack_depot_save path.
> when stack depot is not used they consume 8192 * sizeof(void) bytes at
> max. So nothing much we can do here since static allocation is not much
> and memory consumption depends up on stack depot usage, unlike
> stack_hash_table where 8mb is preallocated.
> 

-- 
QUALCOMM INDIA, on behalf of Qualcomm Innovation Center, Inc. is a
member of Code Aurora Forum, hosted by The Linux Foundation

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/6110a26b-dc87-b6f9-e679-aa60917403de%40codeaurora.org.
