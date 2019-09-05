Return-Path: <kasan-dev+bncBDWLZXP6ZEPRBUUCYPVQKGQEICVD5HQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x337.google.com (mail-wm1-x337.google.com [IPv6:2a00:1450:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id 91DDFA9C85
	for <lists+kasan-dev@lfdr.de>; Thu,  5 Sep 2019 10:03:30 +0200 (CEST)
Received: by mail-wm1-x337.google.com with SMTP id c6sf207598wmc.1
        for <lists+kasan-dev@lfdr.de>; Thu, 05 Sep 2019 01:03:30 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1567670610; cv=pass;
        d=google.com; s=arc-20160816;
        b=OE/aVNwJzWnU6d3G5+fpVTFoX2SVkM7amptmlDGfE70rVTnnCNEhx93gceOWQmIJsi
         6W3OcCCCJ1Mn0OXR87mQjaOxkrGA0PLMcqwCpB2gcvIf6E/qfmdtj3fK0gldrclU1tbf
         i34nbFT6nRMX3Tho8pBv8G4BjpZX+mGKO7Llvcq2qdZg9M2JAa/+m12LCA/CKnorezdw
         z094mLdJAaspX0qHQjBAmVkyWKwsbKoCzJ9kNOPqyaNge+EvXI8/32Qzc+PvMSiBd/l1
         Iu1a+d3rSveU6Fb2XlR5J34BpPRqo/q5yvhMmFafW48gfCasA7L1luNgCUtIj6rNatfD
         49Jw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:autocrypt:openpgp:from
         :references:cc:to:subject:sender:dkim-signature;
        bh=sZkbpn4p1E+xe4sAcl2Rw3HLI/C88e+e66Q73mTuAU4=;
        b=yxkW7JQFiIQcyJXwTw8n1OQ3DtYpPXaUBBhHJk6zhFI9jBpri3ppgQVqezjo1MkkRq
         yX6pGLiEkV1O+mvzAYVxEB2gymQrCyYXU02bs/1IQmNU7aLjzg7rRSPIjfGZRakj1nmj
         lzjfsQDgtw/MayqdomXCeqbdeu7t0z3xy8QpKgBbPwZHbi5ackkAAqylUmoi1ohNHyY5
         VIxGD1dipwScFINmzmeM4Vh5uaYLpeCPC6w7bUjYHK0MsFg0MCpj3+hc7OTzBHtnHUrP
         wqjM7D8i+l+or406Au2+VwNjG8p84S1L7qQcTo6oqmNeCvm+rtji8fT3ZO/GpWT7avE9
         NY+A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.15 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:openpgp:autocrypt:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=sZkbpn4p1E+xe4sAcl2Rw3HLI/C88e+e66Q73mTuAU4=;
        b=THWXxyD51zCcHgfbLYAwkaQfNPwcsYBK1FaV3AZXsqseNIcvIX57SL7z864GzYlcfA
         V73FekWqA/TUSxMkjxsEHlPLS9eCiUMRpGhqaFkL6Fhn4qFguRUqlh7yCRn1+gMQ9uf6
         ectNFpTA9WnmHl7EFDWSQcUbixD7RRptS90auIjLeRmem9AKp7oFHZJcn61vMC21fb48
         E36shBVMTGtd9p/1cDh+F5LBSbfB/TQ9KBJXJHY4+Sju4c6cbt7wgK+DLGQdAeMUDQst
         3d7/vMkloUt0Rx81iJ8aJA+PE26r1NgFOY2V1ru1PApkzbIcEOJe11c67iv1vfzvISjJ
         YciA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:openpgp
         :autocrypt:message-id:date:user-agent:mime-version:in-reply-to
         :content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=sZkbpn4p1E+xe4sAcl2Rw3HLI/C88e+e66Q73mTuAU4=;
        b=CcSqt1+zo+o9T+wOeU4TfIK9kjkjCHjSlO5YSlUix/nyw+NUZmCPPMGjMR/crjQy1y
         BIWw2WWqLBCW6+Gr3pmPEcF75oCo1mzMCeHlu3x+GL7LktMjCDoIT/A8MDZf9R78QLxw
         V26C7ubjDr8QGraVmsmRMxCvXUZmGrZkP1ui5KwfXQ5thW9RDPA4fjfV1WHj6QC9ZEry
         7aC7I+sy4YUgPx6teqD/SLax5nIB8OT1bszcOXUlt8MPBPNkYsRGR3tfmnyv7crbAzDX
         W+2JGD8Sny1GEp/Y14a2oscdphLb2ixxjoh1prftlPeWosdiK9pw44gyiG2fAhmhiISc
         pqDQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVVGX4xQxLgfo8BG9V3lpGHZIhfJMzR5GeVWUueMweh9pcg2O5V
	nhdRzDaaCVMPDnGnb/N5yBY=
X-Google-Smtp-Source: APXvYqyrMH68oyaxcssp2lew0/jCJ/HK2aJjteYOys9RaDCq0+B9Mgc1NgJEXQr64DEyP2hL/k1ezw==
X-Received: by 2002:adf:eccd:: with SMTP id s13mr1466605wro.288.1567670610290;
        Thu, 05 Sep 2019 01:03:30 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:63d0:: with SMTP id c16ls328600wrw.3.gmail; Thu, 05 Sep
 2019 01:03:29 -0700 (PDT)
X-Received: by 2002:adf:dc0f:: with SMTP id t15mr1550648wri.258.1567670609620;
        Thu, 05 Sep 2019 01:03:29 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1567670609; cv=none;
        d=google.com; s=arc-20160816;
        b=Dwam5VQ2ThtsW/O9zkrp8adfWOMcnEMRGSIQBZdNZDRvpXXvcoIgvhDYSXCJAeoGbk
         GSuyZM8BOvK8DY/0KzVdCurdKDv8UH7s/MDNqFK0GE/ysb/U+id86ArW1x8QsOldD6PY
         LNqpQfa7wwhnMk74Fu6IYOwyQphisbFB1GgbU7W3D9wmLysa3dWg5KWyECbXWqiL548w
         X/CBx5xrkZfxQJFiDN7iBwy3EnlTgF+wAmrzjoueJDm0vE3G4PCJZfg7dLorPfmk5CV4
         ZVSJRNFNZU7og/szojvswZIq9I0v508L7hRuR4C30iy3xE+YSZjsbUaCV+Dq21KUYAUF
         Ji4w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:autocrypt:openpgp:from:references:cc:to
         :subject;
        bh=12RQbACE8MwjAU37t633+GA/Dc0vLZWl5qlaRsRQpKA=;
        b=t5C4vrvfZNnzK19qZtwQ3krtPviILt4btGz4por3516O+EDppJt2psZ4CFAZrbiH1m
         qo4C2JkAjx3hIkZJGSjs2zyGMoGds1f4Zz3x6lP9Nbk/NGl6z/Hl6zNGCjR2A4iHQtgf
         vldZcz/xos0A3iJJD3mP698/MqwnV6USzU0DTvSXbGDvjfrTaeHtx71BjQRpB8jnuW1/
         hCUhZiaU5o5eScjF3QXmJDkjXFtE9flvW7AvU60qWCWiUVqoxdmv61gqsQvfMRNPvdhV
         wNSUdX5Vd/5SHAE7H1tq96UtEtkpbb/sSFL9gnDFfmAPgIj/fHu4acrc8NMGRHDzRjlC
         aNKg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.15 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from mx1.suse.de (mx2.suse.de. [195.135.220.15])
        by gmr-mx.google.com with ESMTPS id x13si328979wmk.0.2019.09.05.01.03.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 05 Sep 2019 01:03:29 -0700 (PDT)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.220.15 as permitted sender) client-ip=195.135.220.15;
X-Virus-Scanned: by amavisd-new at test-mx.suse.de
Received: from relay2.suse.de (unknown [195.135.220.254])
	by mx1.suse.de (Postfix) with ESMTP id CBEA8AD6B;
	Thu,  5 Sep 2019 08:03:28 +0000 (UTC)
Subject: Re: [PATCH 1/2] mm/kasan: dump alloc/free stack for page allocator
To: Walter Wu <walter-zh.wu@mediatek.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>,
 Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>,
 Matthias Brugger <matthias.bgg@gmail.com>,
 Andrew Morton <akpm@linux-foundation.org>,
 Martin Schwidefsky <schwidefsky@de.ibm.com>, Arnd Bergmann <arnd@arndb.de>,
 kasan-dev@googlegroups.com, linux-mm@kvack.org,
 linux-kernel@vger.kernel.org, linux-arm-kernel@lists.infradead.org,
 linux-mediatek@lists.infradead.org, wsd_upstream@mediatek.com
References: <20190904065133.20268-1-walter-zh.wu@mediatek.com>
 <401064ae-279d-bef3-a8d5-0fe155d0886d@suse.cz>
 <1567605965.32522.14.camel@mtksdccf07>
 <7998e8f1-e5e2-da84-ea1f-33e696015dce@suse.cz>
 <1567607063.32522.24.camel@mtksdccf07>
From: Vlastimil Babka <vbabka@suse.cz>
Openpgp: preference=signencrypt
Autocrypt: addr=vbabka@suse.cz; prefer-encrypt=mutual; keydata=
 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
Message-ID: <99913463-0e2c-7dab-c1eb-8b9e149b3ee3@suse.cz>
Date: Thu, 5 Sep 2019 10:03:28 +0200
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101
 Thunderbird/60.8.0
MIME-Version: 1.0
In-Reply-To: <1567607063.32522.24.camel@mtksdccf07>
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

On 9/4/19 4:24 PM, Walter Wu wrote:
> On Wed, 2019-09-04 at 16:13 +0200, Vlastimil Babka wrote:
>> On 9/4/19 4:06 PM, Walter Wu wrote:
>>
>> The THP fix is not required for the rest of the series, it was even merged to
>> mainline separately.
>>
>>> And It looks like something is different, because we only need last
>>> stack of page, so it can decrease memory overhead.
>>
>> That would save you depot_stack_handle_t (which is u32) per page. I guess that's
>> nothing compared to KASAN overhead?
>>
> If we can use less memory, we can achieve what we want. Why not?

In my experience to solve some UAFs, it's important to know not only the
freeing stack, but also the allocating stack. Do they make sense together,
or not? In some cases, even longer history of alloc/free would be nice :)

Also by simply recording the free stack in the existing depot handle,
you might confuse existing page_owner file consumers, who won't know
that this is a freeing stack.

All that just doesn't seem to justify saving an u32 per page.

> Thanks.
> Walter
> 
> 
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/99913463-0e2c-7dab-c1eb-8b9e149b3ee3%40suse.cz.
