Return-Path: <kasan-dev+bncBD2ZJZWL7ICRBMX3YOUAMGQE65VNWJY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13e.google.com (mail-lf1-x13e.google.com [IPv6:2a00:1450:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id 731F77ACEB4
	for <lists+kasan-dev@lfdr.de>; Mon, 25 Sep 2023 05:25:40 +0200 (CEST)
Received: by mail-lf1-x13e.google.com with SMTP id 2adb3069b0e04-502d58d14besf7256460e87.0
        for <lists+kasan-dev@lfdr.de>; Sun, 24 Sep 2023 20:25:40 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1695612339; cv=pass;
        d=google.com; s=arc-20160816;
        b=qqd9+4wcAVP0kAeYGYyWqEAerFRnBKZgkC9UHEi7EuSRIDf8yyKoo0NzDw83TkRidm
         WsUD2Tx6Yt0DKGLzOXcCtvIBMbw7gAlNDQN+cizlNyKwREojDU+vSH/VnuarqRMb8HMK
         NbJofLaWEyj2PHK85LCXHYP8JflfQh2DkErssyNZpaUdSxzbteNSlyXrpQRuEpwabZIm
         +t2676qERetVQRmLoDvFonU/qGWkU6ZgRbrc5/keaDH8QCN/vCWvEYQlH82STBusMNyG
         nTN4TnaxulFI4IJyoUp+5Y4f3tEDlyqNhWmTrV0kbf6hUMgPu9e1jjsUAeXmhr4D8d4x
         fK4g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :in-reply-to:from:content-language:references:cc:to:subject
         :mime-version:date:message-id:sender:dkim-signature;
        bh=RtSn5mjhabAI/EEEJXaZTyqplnN7QYdmIs9q1DoLIn4=;
        fh=IJF5Y8jB+Ub6tuPMQWVWq5unMOvTBnwzLNd5hXnx8ro=;
        b=pd3IT8FGVyh8FkMY0rvPJECgSfUuLCY6f6XK34LVtLslQ1l1Egk9/R1bOUHHTI757y
         xt4NTCRMX5AyCQHpR3t78lUlay34DvXF67ND1d8fFTrW7mnrFz2x0mxT/eNzUG/NwJnt
         TSyY7nR0c9viBxfNw02bwtdwbbSu7gCUF4OmZMZoOtuFO//nwP5WjeWntFsnY5pTrkGB
         dN1GhbZIbl6g3WODDHTu48d4ENy1UX2R4OhRZHPt8pYbLjweNg9JYgLStUUq+0rHxCyE
         JBkPBq4e7KIh3LgB2NAQs7j9khK6TDndiVUBseGszOd+urIW7sC2r5P/QnBLjgRPA+Av
         gAyw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=vKoj5PBK;
       spf=pass (google.com: domain of yajun.deng@linux.dev designates 91.218.175.190 as permitted sender) smtp.mailfrom=yajun.deng@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1695612339; x=1696217139; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:in-reply-to:from
         :content-language:references:cc:to:subject:mime-version:date
         :message-id:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=RtSn5mjhabAI/EEEJXaZTyqplnN7QYdmIs9q1DoLIn4=;
        b=CnVZZkMEix4uWVfWukUoGAW7c62CgEysKYGW3+fuFaVQMOs1aId1jqsAAx9RhYoR3Y
         EJYD6gCPWu3buFLMjGn10Udm+t9JOEaDYBXs4GyXH5YyRNulWECBWX+yFLB1dIEsnxRr
         s/+3RJJ+9gR3XkHB1Z3yCJ4HMl7/XO7EKj4TR8/ST6VMsiJA25ukuz0GKZiC3wFsUnIh
         wV8oF3cPvbItNhQb0DG67y+RW+JHbTP+CHczbP12qWOuAkTMyC55qKXpapA2gSm5G2do
         GzpmCE0bWco6E2i4ftfXS251lYeeIGDd6yPnfSKWgARBacYQgrc94LRtuw0hhTww/zTu
         f16g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1695612339; x=1696217139;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:mime-version:date:message-id:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=RtSn5mjhabAI/EEEJXaZTyqplnN7QYdmIs9q1DoLIn4=;
        b=dC25hYYht4DFMYjU3kjW2agLSVe+C4cuvB0/fxN0PY4+klSawYeYceWRjxeBVVJHc2
         ZlKXe0tMTV6jkEZTjb/Ln+5QPAdDMb7N+sn/DKZbpErpo1t2F7SvG92kVnqKpcH298il
         z+z9gsETsDo5JMOaXUUTc/8/OHBFLvm4cAsw72RN6dmQZOfJ+D91fZrgM20JDUUt4oMQ
         XNDZRoXcvAJ9zNNuLISKUTAfI3PWha4qRz+dnoOzFKSrZwjMml6gZCXZO70YPtE8FNJd
         nuxRLwuQjVH+lGFdFDG/6y9srL1LUkZoI16V+4TQWlLjYDQ3LYyvD8J0fO7SutZsDWu0
         8iDA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yw9X0ZH3yBCCa5VgS93Gxn6z2RTx2j0rZ5y8kck4r7UbQ1dFUwU
	UBDG3CpyQDJnDSfckFjsogU=
X-Google-Smtp-Source: AGHT+IFStwlVEL+T9a+/VNeyoK1iXE2jyagbPtY2TlfA0OPTxGjsLR/Ems5F59empLxfwO31w4r/lQ==
X-Received: by 2002:a19:7b06:0:b0:4ff:8f76:677f with SMTP id w6-20020a197b06000000b004ff8f76677fmr3446929lfc.67.1695612338576;
        Sun, 24 Sep 2023 20:25:38 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:3803:0:b0:4f9:5599:26a with SMTP id f3-20020a193803000000b004f95599026als1539455lfa.2.-pod-prod-08-eu;
 Sun, 24 Sep 2023 20:25:36 -0700 (PDT)
X-Received: by 2002:a05:6512:1090:b0:4fe:2f8a:457e with SMTP id j16-20020a056512109000b004fe2f8a457emr5366177lfg.43.1695612336378;
        Sun, 24 Sep 2023 20:25:36 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1695612336; cv=none;
        d=google.com; s=arc-20160816;
        b=EhFJFHvQmPSffBuhb+ztH8BszYgnb7pByOvaj+dz/kUQcJKDtbhpDckbFVQzhlS9WJ
         ftBjf5HmNgtymh4M0Rpbpr7ozxtnSXoyzFHqagB+q87o+CAZeCIxMdhiJe/NXvN5JNf9
         KgQtJiLyXym1XDX26zhthjMWlN8QMnXqI5CvxzFjoKGC0tHgJphkZZ4M89NK8dieAC5z
         OQSPCRD4/+oSCFKc6DBa2nC7H04Sap5AT9uUyupl/PxQhGsLMVH5nLDs6g++e8L9xEyK
         4MgcwcVaQL/c7TPwhB067zyx76otFPhCBrtOhv+PT0pOMjmaCCspcixew1ofGCpqMZQN
         9HWA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:mime-version:date:dkim-signature
         :message-id;
        bh=m6vPV8LMOzVMcoIBD4Pznx00zoA77Ft1Xl6It5vC6EA=;
        fh=IJF5Y8jB+Ub6tuPMQWVWq5unMOvTBnwzLNd5hXnx8ro=;
        b=R9L7DRAR1z1mFvYSlbuU1oDAfgrg3VvQ4ogEA7RFyT28ibvE+6uHVxYViBWT6sDwnW
         5vME3rGvxhX/s3y21UMX5hw6kUcVHI3lqH80fbx/fauAHlayxy03FFBuEzXVMdPzy8L/
         iFXBw8cqcenzs61Acto6okhwzYlR2nSB+WVdyBzgPE3ibh25d9J+oKWktiB/KA7Hphvp
         7JdG9NLci4SJouR2EX2aJ+Xpkv7WEHIwosF78y9RWT23StMFDASuvR72ammp0j4/burZ
         +H5J75q9zfNtH2P0YFM2VUx8ieuOuVQ6yCGAToMh+8ypbh9x4DEalJaDsz/bm7A2PxKi
         uk/g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=vKoj5PBK;
       spf=pass (google.com: domain of yajun.deng@linux.dev designates 91.218.175.190 as permitted sender) smtp.mailfrom=yajun.deng@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-190.mta0.migadu.com (out-190.mta0.migadu.com. [91.218.175.190])
        by gmr-mx.google.com with ESMTPS id d7-20020a056512368700b004ff9d6b6cb0si525840lfs.2.2023.09.24.20.25.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sun, 24 Sep 2023 20:25:36 -0700 (PDT)
Received-SPF: pass (google.com: domain of yajun.deng@linux.dev designates 91.218.175.190 as permitted sender) client-ip=91.218.175.190;
Message-ID: <798ddb57-ba09-e337-01b3-c80711f1e277@linux.dev>
Date: Mon, 25 Sep 2023 11:23:03 +0800
MIME-Version: 1.0
Subject: Re: [PATCH 1/4] mm: pass set_count and set_reserved to
 __init_single_page
To: Mike Rapoport <rppt@kernel.org>, David Hildenbrand <david@redhat.com>
Cc: Matthew Wilcox <willy@infradead.org>, akpm@linux-foundation.org,
 mike.kravetz@oracle.com, muchun.song@linux.dev, glider@google.com,
 elver@google.com, dvyukov@google.com, osalvador@suse.de, linux-mm@kvack.org,
 linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com
References: <20230922070923.355656-1-yajun.deng@linux.dev>
 <20230922070923.355656-2-yajun.deng@linux.dev>
 <ZQ1Gg533lODfqvWd@casper.infradead.org>
 <2ed9a6c5-bd36-9b9b-7022-34e7ae894f3a@redhat.com>
 <20230922080831.GH3303@kernel.org>
Content-Language: en-US
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: Yajun Deng <yajun.deng@linux.dev>
In-Reply-To: <20230922080831.GH3303@kernel.org>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Transfer-Encoding: quoted-printable
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: yajun.deng@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=vKoj5PBK;       spf=pass
 (google.com: domain of yajun.deng@linux.dev designates 91.218.175.190 as
 permitted sender) smtp.mailfrom=yajun.deng@linux.dev;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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


On 2023/9/22 16:08, Mike Rapoport wrote:
> On Fri, Sep 22, 2023 at 09:48:59AM +0200, David Hildenbrand wrote:
>> On 22.09.23 09:47, Matthew Wilcox wrote:
>>> On Fri, Sep 22, 2023 at 03:09:20PM +0800, Yajun Deng wrote:
>>>> -		__init_single_page(page, pfn, zone, nid);
>>>> +		__init_single_page(page, pfn, zone, nid, true, false);
>>> So Linus has just had a big rant about not doing bool flags to
>>> functions.  And in particular _multiple_ bool flags to functions.
>>>
>>> ie this should be:
>>>
>>> #define INIT_PAGE_COUNT		(1 << 0)
>>> #define INIT_PAGE_RESERVED	(1 << 1)
>>>
>>> 		__init_single_page(page, pfn, zone, nid, INIT_PAGE_COUNT);
>>>
>>> or something similar.
>>>
>>> I have no judgement on the merits of this patch so far.  Do you have
>>> performance numbers for each of these patches?  Some of them seem quite
>>> unlikely to actually help, at least on a machine which is constrained
>>> by cacheline fetches.
>> The last patch contains
>>
>> before:
>> node 0 deferred pages initialised in 78ms
>>
>> after:
>> node 0 deferred pages initialised in 72ms
>>
>> Not earth-shattering :D Maybe with much bigger machines relevant?
> Patch 3 contains
>
> The following data was tested on an x86 machine with 190GB of RAM.
>
> before:
> free_low_memory_core_early()    342ms
>
> after:
> free_low_memory_core_early()    286ms
>
> Which is more impressive, but still I'm not convinced that it's worth the
> added complexity and potential subtle bugs.
>
I will send v2.=C2=A0 It will be simpler and safer.
>> --=20
>> Cheers,
>>
>> David / dhildenb
>>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/798ddb57-ba09-e337-01b3-c80711f1e277%40linux.dev.
