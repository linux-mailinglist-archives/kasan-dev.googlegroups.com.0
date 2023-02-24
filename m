Return-Path: <kasan-dev+bncBDR5N7WPRQGRBCNG4SPQMGQEWUE3AWQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3d.google.com (mail-oo1-xc3d.google.com [IPv6:2607:f8b0:4864:20::c3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 0F4A86A2273
	for <lists+kasan-dev@lfdr.de>; Fri, 24 Feb 2023 20:42:04 +0100 (CET)
Received: by mail-oo1-xc3d.google.com with SMTP id e8-20020a056820060800b005174a86ea9csf79106oow.23
        for <lists+kasan-dev@lfdr.de>; Fri, 24 Feb 2023 11:42:03 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1677267721; cv=pass;
        d=google.com; s=arc-20160816;
        b=Oi+mbyE9Bomxc45jRCFal51zySPDjeQsB1vqP4MHXf/4Ie+K1fK2N9x++MeVpPamu9
         kil78AjVxtfny+Qhd64f2X6fblIvJvU3TkCr8ye3H8f21hZURUzkW6SNTm0NPPo7z393
         xnbwOfP71sLwqiocMgvtrnK1A/pbrRviHt6hto3SXrfkHYGDVyU4TYJWQ+ae6eBwVVAs
         vBTN9yOTVkJw+ZHdUUTkvIjqtszWyBcPiPla9zvpTRSJEXBOdBnAgiDcipkQCLZiuDJE
         22gAamRCbFbpGyMCFXhDHVqDkhVEE2+YLw/5OyErArzo7OQZZ79lSTfr8dNqu1Erxie2
         E1sg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=4gVNIelw7W3YV3R3X3qQ5XJgiRBKQLejvbieu5DQNgQ=;
        b=ceJisoIdJzQj7GqVML9MBxbHW9ZJJqnfQQdngBYqPY1mSrxtguHKYFsAaLi4GoryPj
         geNfrNTjjU/YfNMyuz1KRk+mDLMkOAbgdDH80MyoAP4smlt7x1gyCizIx9hu/i5JuqsD
         VLIJsvMQviCl6qn04lKeeFmHsEeLj8pk/2CkebUDCb/skGGq2VV32WOuoBWwG5G+Lm6I
         JYSzdT9unJMKUHBoSsWo4u3AF2av6iJCF3eDgAmcIPyOGyfAlmPtVDEKTG22uyAEeZi+
         QDj+toQkGlhPu+U/dTV4Gi7orsP/SoY//XiHXUwKu1+tT66uQyCFGavnMlpX67Dx535a
         4MQA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel-dk.20210112.gappssmtp.com header.s=20210112 header.b=8W3znN4b;
       spf=pass (google.com: domain of axboe@kernel.dk designates 2607:f8b0:4864:20::52b as permitted sender) smtp.mailfrom=axboe@kernel.dk
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=4gVNIelw7W3YV3R3X3qQ5XJgiRBKQLejvbieu5DQNgQ=;
        b=H3qEuIzv3zJt0yjXNBTji7qdC1orPsnLd+6e6vjAN67lb0Cz80u1eGN8CpOZ8XSIc7
         SlZqU+B7ubaSJSeW6/nLE68b8c7SyYn7JemvHwTDbuBu7CQ+4em5E7Iaj3bo6gnyjudq
         62+/u8keKhXWAN6/tu5VseI96R7KFR3Yqr9i5WS9DwhqABbA3wzZlzuq2T273yqo1DBh
         7Tg1G5bQae/qrBO285b1/OZJV2pXf3fBk7xZ++lTOnAFiJpi4oOSPKe34D2Rez5r/Tj3
         1l2NDVH0E9dFCVuQSMok/xRsMRvjpzNMCWfIswocKjcI2P/mWMw9yVORKWscM7BCyHxD
         jAag==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=4gVNIelw7W3YV3R3X3qQ5XJgiRBKQLejvbieu5DQNgQ=;
        b=dS/w27DcBfafYRmo95Tqu8JZyRljnLk5XWn9org3vxIjIvJxHZgiu8tUuroC8bqlmL
         6r8SEXx3dU5K/QbEjQkBGFDok2JGOIqssMm1dZcSKbfo+mTGQexP0pzTamd5YcR32An9
         1eZH6nykUjjB8f1LZ9JPyXot2izsK5sqBpq6Tm5YE0oc0pxx49qxdmNB9eqvPvuV5WHu
         3/7TaFg+f+JSWo1+28MIJD2ns0ow1mCYV1VqJ9w1d1OqVr7xPOF3KA4oi6ZW6AbkCv2t
         Z6MP4JnjQJCP/BUPNJtobLXNN65LB260GBj1JtWDOdhWoaT3RGhe1xycvb03WbckAYik
         ojIA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKVD3MjBEtr9ObMLy+eZTCu4DcpLjFYVEeXOkxsg+P5p8ajzgiEe
	GpPl3pxckL6h1X8qW011hu4=
X-Google-Smtp-Source: AK7set/e7uNsMFZFP41Rzp/jygMm69CQxSGLQ9wUOGDJJWmMCZUXtYBeggblO/hQTzQ5p/O0jxavmw==
X-Received: by 2002:a05:6870:1a98:b0:172:3aea:ecaa with SMTP id ef24-20020a0568701a9800b001723aeaecaamr1382719oab.9.1677267721184;
        Fri, 24 Feb 2023 11:42:01 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:2c95:b0:16d:faf8:7383 with SMTP id
 oh21-20020a0568702c9500b0016dfaf87383ls1549949oab.8.-pod-prod-gmail; Fri, 24
 Feb 2023 11:42:00 -0800 (PST)
X-Received: by 2002:a05:6870:b486:b0:172:8ae4:af53 with SMTP id y6-20020a056870b48600b001728ae4af53mr3722026oap.21.1677267720762;
        Fri, 24 Feb 2023 11:42:00 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1677267720; cv=none;
        d=google.com; s=arc-20160816;
        b=BQtROngEd/rBtCC6RqBWn12Bob/PpMBp1YvGuokUZYmcU/vXPacEE+Xp7saSlLVk7S
         qP6rUb/NR9nVNj5+F5INd2Nk+S28Y8nb3Gs7Lr4+Xk8L98XF5QXKOUuBtrDeBeDxsZgy
         r9gbNm/tNMPOfF6MttlInYsqvwRwqHveU2y0yxdBB/Uz8FJnJMA5eAEzqG9TI59grm0f
         uQoK03nL2smpe30x1MxnfI0zKUgrAkpyiYupSXX5AmnjRHmWCiQd70QKyBehHMQdxKHo
         9qJ8/g0+y2scLdMAug0w2qtBnim0ZM6vl5vsNbcDjOA7KQ3S9hpNKR3CsuJlzc3THfSZ
         nCtA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=ijgekmVB2QKb1HH14nlyibdFD+y7KoE1WivpnqCwi0o=;
        b=lCrEEps85X9KYTY1zNLrYAq/SyCm0a/2Yh+JcKFs6umNxgGJxfM0CPZ8OvY9uWMyFF
         PyxmilWhQAZOCvre1iTwM1zWlfzg26fyYvfUkieroUf3Ur6aZkGOScTjGhXxpdcVnbM4
         lexoaT8knCfR/zps4skEWbQTlCT/PQLhCMJgqjj1cU0FPeeScS3paZpxlBrJ53MtH7xV
         fzfwFJzYVEwsy8ADRV+FYv+t6gPePHFA8XbjZ7YBuBq77zUvGPVo59Uds4ugGJwJ/NrV
         4ZgDhD8lX067YUB7Bh1M2DEE5/kEiL2NB19O3HncgzfB1rsNSi8a57Vr8pPiPRUIaunJ
         UPFQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel-dk.20210112.gappssmtp.com header.s=20210112 header.b=8W3znN4b;
       spf=pass (google.com: domain of axboe@kernel.dk designates 2607:f8b0:4864:20::52b as permitted sender) smtp.mailfrom=axboe@kernel.dk
Received: from mail-pg1-x52b.google.com (mail-pg1-x52b.google.com. [2607:f8b0:4864:20::52b])
        by gmr-mx.google.com with ESMTPS id bf37-20020a056808192500b0038409c2d352si11521oib.2.2023.02.24.11.42.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 24 Feb 2023 11:42:00 -0800 (PST)
Received-SPF: pass (google.com: domain of axboe@kernel.dk designates 2607:f8b0:4864:20::52b as permitted sender) client-ip=2607:f8b0:4864:20::52b;
Received: by mail-pg1-x52b.google.com with SMTP id bn17so167233pgb.10
        for <kasan-dev@googlegroups.com>; Fri, 24 Feb 2023 11:42:00 -0800 (PST)
X-Received: by 2002:aa7:9841:0:b0:5e2:3086:f977 with SMTP id n1-20020aa79841000000b005e23086f977mr3868360pfq.2.1677267720030;
        Fri, 24 Feb 2023 11:42:00 -0800 (PST)
Received: from [192.168.1.136] ([198.8.77.157])
        by smtp.gmail.com with ESMTPSA id k10-20020aa7820a000000b005d791692727sm5044111pfi.191.2023.02.24.11.41.58
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 24 Feb 2023 11:41:59 -0800 (PST)
Message-ID: <6673f9e6-fa00-b929-02c1-5e0f293dfa0a@kernel.dk>
Date: Fri, 24 Feb 2023 12:41:58 -0700
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux aarch64; rv:102.0) Gecko/20100101
 Thunderbird/102.7.2
Subject: Re: [PATCH v3 1/2] io_uring: Move from hlist to io_wq_work_node
Content-Language: en-US
To: Gabriel Krisman Bertazi <krisman@suse.de>
Cc: Breno Leitao <leitao@debian.org>, asml.silence@gmail.com,
 io-uring@vger.kernel.org, linux-kernel@vger.kernel.org, gustavold@meta.com,
 leit@meta.com, kasan-dev@googlegroups.com
References: <20230223164353.2839177-1-leitao@debian.org>
 <20230223164353.2839177-2-leitao@debian.org> <87wn48ryri.fsf@suse.de>
 <8404f520-2ef7-b556-08f6-5829a2225647@kernel.dk> <87mt52syls.fsf@suse.de>
From: Jens Axboe <axboe@kernel.dk>
In-Reply-To: <87mt52syls.fsf@suse.de>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: axboe@kernel.dk
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel-dk.20210112.gappssmtp.com header.s=20210112
 header.b=8W3znN4b;       spf=pass (google.com: domain of axboe@kernel.dk
 designates 2607:f8b0:4864:20::52b as permitted sender) smtp.mailfrom=axboe@kernel.dk
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

On 2/24/23 11:32?AM, Gabriel Krisman Bertazi wrote:
> Jens Axboe <axboe@kernel.dk> writes:
> 
>> On 2/23/23 12:02?PM, Gabriel Krisman Bertazi wrote:
>>> Breno Leitao <leitao@debian.org> writes:
>>>
>>>> Having cache entries linked using the hlist format brings no benefit, and
>>>> also requires an unnecessary extra pointer address per cache entry.
>>>>
>>>> Use the internal io_wq_work_node single-linked list for the internal
>>>> alloc caches (async_msghdr and async_poll)
>>>>
>>>> This is required to be able to use KASAN on cache entries, since we do
>>>> not need to touch unused (and poisoned) cache entries when adding more
>>>> entries to the list.
>>>>
>>>
>>> Looking at this patch, I wonder if it could go in the opposite direction
>>> instead, and drop io_wq_work_node entirely in favor of list_head. :)
>>>
>>> Do we gain anything other than avoiding the backpointer with a custom
>>> linked implementation, instead of using the interface available in
>>> list.h, that developers know how to use and has other features like
>>> poisoning and extra debug checks?
>>
>> list_head is twice as big, that's the main motivation. This impacts
>> memory usage (obviously), but also caches when adding/removing
>> entries.
> 
> Right. But this is true all around the kernel.  Many (Most?)  places
> that use list_head don't even need to touch list_head->prev.  And
> list_head is usually embedded in larger structures where the cost of
> the extra pointer is insignificant.  I suspect the memory
> footprint shouldn't really be the problem.

I may be in the minority here in caring deeply about even little details
in terms of memory foot print and how many cachelines we touch... Eg if
we can embed 8 bytes rather than 16, then why not? Particularly for
cases where we may have a lot of these structures.

But it's of course always a tradeoff.

> This specific patch is extending io_wq_work_node to io_cache_entry,
> where the increased size will not matter.  In fact, for the cached
> structures, the cache layout and memory footprint don't even seem to
> change, as io_cache_entry is already in a union larger than itself, that
> is not crossing cachelines, (io_async_msghdr, async_poll).

True, for the caching case, the member size doesn't matter. At least
immediately. Sometimes things are shuffled around and optimized further,
and then you may need to find 8 bytes to avoid bloating the struct.

> The other structures currently embedding struct io_work_node are
> io_kiocb (216 bytes long, per request) and io_ring_ctx (1472 bytes long,
> per ring). so it is not like we are saving a lot of memory with a single
> linked list. A more compact cache line still makes sense, though, but I
> think the only case (if any) where there might be any gain is io_kiocb?

Yeah, the ring is already pretty big. It is still handled in cachelines
for the bits that matter, so nice to keep them as small for the
sections. Maybe bumping it will waste an extra cacheline. Or, more
commonly, later additions now end up bumping into the next cacheline
rather than still fitting.

> I don't severely oppose this patch, of course. But I think it'd be worth
> killing io_uring/slist.h entirely in the future instead of adding more
> users.  I intend to give that approach a try, if there's a way to keep
> the size of io_kiocb.

At least it's consistent within io_uring, which also means something.
I'd be fine with taking a look at such a patch, but let's please keep it
outside the scope of this change.

-- 
Jens Axboe

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/6673f9e6-fa00-b929-02c1-5e0f293dfa0a%40kernel.dk.
