Return-Path: <kasan-dev+bncBC32535MUICBBNOPYGMAMGQE7PJTQSI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x37.google.com (mail-oa1-x37.google.com [IPv6:2001:4860:4864:20::37])
	by mail.lfdr.de (Postfix) with ESMTPS id 06EE25A9189
	for <lists+kasan-dev@lfdr.de>; Thu,  1 Sep 2022 10:05:11 +0200 (CEST)
Received: by mail-oa1-x37.google.com with SMTP id 586e51a60fabf-11ebd51653fsf4561586fac.13
        for <lists+kasan-dev@lfdr.de>; Thu, 01 Sep 2022 01:05:10 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662019509; cv=pass;
        d=google.com; s=arc-20160816;
        b=E7xrTJnfC0xUKLlq993wMYV9ok0summamk8IsuVODlHysm+QY4oYB91VuZ7VAVJz/f
         4K6RE4KKfC/ZOOj7TiAcpi83y4T2zmnhHsUBV9bZkl+sko6OKYNt6v/VRYDA0YxXVO+8
         /aMkTM3IaEkQDX9TKC2FPGcNYaeA0G3GdJ4peJdQCi2mlBQEDUMervH+ZTAT+QBgaVSU
         Kfrxq7PYx2Khyie+sik/Uicoe18mWsZcK6D6YpOaWrXOgKAMwMPJkHxC1VJYGSw2pA9J
         UUqmdDrDHfO/qwXsbLGMHudB+PN+LNf3gYglsPl4NeC3hOLOb4TvqjxVQhPrAZdC2U7g
         IgJQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :subject:organization:from:references:cc:to:user-agent:mime-version
         :date:message-id:sender:dkim-signature;
        bh=fTfNON5AP6bGR0xrkxC3ju2ksz7XMbOsZgn5do8vNT4=;
        b=X9Psi1s41o6JwOVgUrDasqrX4nuTSJsLwCJMNurc17dMuO7uVnDyPWyvFKvUH/hQAt
         iGvMuKruDQ2UHWSgZ0CcbP9V8tnw+Odp0bG7/fLRzLQDLXCu+Srckw0RwlUtuFzR5zmv
         jzSYgEBQVh8LjiXR4R/eyDwYV6VFjMan63WkofJD7mPzRln88k5vqKmhTrGfVEuvCBz2
         xap92u5Rqzi9+fD3SCjnRaDPvlZ11bi9avUmnnfu1JBesk4GGyh39XPmgJocl2UVFeFe
         Q4YDF6Jk9q/i3Kznmarty+3+q/H7OEfEHHDhBEbgUe9VjPnbBUbPZ/kA/CbooXiwQYyw
         rzOg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=dEXbCdf+;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-language:in-reply-to:subject:organization
         :from:references:cc:to:user-agent:mime-version:date:message-id
         :sender:from:to:cc;
        bh=fTfNON5AP6bGR0xrkxC3ju2ksz7XMbOsZgn5do8vNT4=;
        b=JBkXq8b6ifTjdT71YRfdhTd1XxKudV6qOKZ36nnDwTeGxWSpdVwdOO5MGm1KmnrK44
         o5KxbH8n+jb4VobY23TfVV8043gffCl14wuQausbh3/EyB0xzvRelGBj3+gMJ9G8mZhR
         D8Tz2H3PeGbC2fFjxOSyvKD0LeA6I9sw5Ynv6nuUjsv92OqElrptsfJ6PRO/2qtKjLpE
         ywdFQq4aUjSp/YgtyzsWrR/Ygsf9SvBnHa/UYQxmJ6vJJw+P4FIUqj+U8KKmw/oy4kaX
         Cd/1PxG/qu12btVQOQnTo9qVBDTJH4JSi1FfSulX2sPxJPv3lJBwFPYWK/A1+OujFclv
         18hQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-language:in-reply-to:subject:organization:from:references
         :cc:to:user-agent:mime-version:date:message-id:x-gm-message-state
         :sender:from:to:cc;
        bh=fTfNON5AP6bGR0xrkxC3ju2ksz7XMbOsZgn5do8vNT4=;
        b=L+30Ag80GE4sF/rHGGdzr2msHQGAPKvHz8Mrwu+TiwPNZVLYk39A+1QEmM8fvndAjt
         4UmJDwOfVnE2vSUeWQrBiDXP6KH7BMOJCivNJ4rdo37RHI7GkSABBnRrAdWf/fBFaf12
         f58bf1OF9gbdFr20Kqx2Z4+i3OzhjR/0AagcpEB49SMPf73XopiQHPti+gJEpUWnkVqa
         KRapxjMmOxNjI3auyy086Ua7Uxoa0ZE7aSRq8bIvNnjeo2unZNFz1YXb3DdkRpPCSiyU
         zYvi1mA65dCq2mypz3rs0kkFx7P9+2Ny2FqRI7nLMUZrJVnlhHN/BFP6ipO8yhb1hrQv
         QBUw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo1tKrfKYwKOfDj3wwUnC9pnGsfA0Y1fQ5/uOjB+wvJBAK6j8BrS
	AcIlxQLj5Ia74ofRIyxFrh8=
X-Google-Smtp-Source: AA6agR6ZsAur796qOaKpjJfw1QPtVdD4Z5VR87zpW4TvXwfjSoIVN8bltnatzXk9uwRg9kitbhi1Yg==
X-Received: by 2002:a05:6808:1442:b0:344:a466:83ff with SMTP id x2-20020a056808144200b00344a46683ffmr3057670oiv.204.1662019509524;
        Thu, 01 Sep 2022 01:05:09 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:6087:b0:637:18f0:d52 with SMTP id
 by7-20020a056830608700b0063718f00d52ls279285otb.8.-pod-prod-gmail; Thu, 01
 Sep 2022 01:05:09 -0700 (PDT)
X-Received: by 2002:a9d:f43:0:b0:638:c3c4:73ee with SMTP id 61-20020a9d0f43000000b00638c3c473eemr11398408ott.186.1662019508967;
        Thu, 01 Sep 2022 01:05:08 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662019508; cv=none;
        d=google.com; s=arc-20160816;
        b=ziHO2DRxTjSZIUtqj9nPFbU1UvLhLGOrpdFYkTrtI7nnPtlPTLhJlwS95QcqCsjZuB
         HIatyT+BwfR4aTFtaKELuv1QuSyKLGnFH8+nAwB98ElC/95dM6freuCXysu9Az8F72Bk
         UwKWCuColPyA3t2F93Z8VCVRjJPEnbuYBQHh8r9VXM6xAf9nO3y0VFuqUnaxkorU1q6l
         TD1GymAZcgy6Yk22JI8I8IohG1oIrdYJnU5+pn6C8UMmUpFRqvXnqmZ/Cs6JNI17VnNf
         7w/jOgXUpmyg4WkO5HRufp7RxPuiE5Ztgr24WrgsdHqXBdJ+2bIKhobnjwZ1Ti16+x7T
         U9EQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:subject
         :organization:from:references:cc:to:user-agent:mime-version:date
         :message-id:dkim-signature;
        bh=fAYRQilXBeVPqddsxUYpdqrwWan1aH9ZFdN7uQibkcg=;
        b=KmlY3lDLmbBYZceNK5CR6EJ6xP95COblz1Hx8/0fWE8yGrOhk15ZD6WYFDXp5rXlbb
         08oGeF+53+EaUZ41U7wiYBqjuEGmscc5oCvygHTLTR+i1FgUJPiGgxRbhFHbXa7UpQAl
         I/dg1RUkrgoYFXR8UPTqoefcI0ff1l5YyyLp6XCS0B0mATrswTfcjOUoRzln6wEJyX/t
         zqawlzu6Bo0om2REpBa6ybkxtqceH6o31RDYiBPnaBc0U83Pn4R2ldxIxYi+VVCmjJg+
         gq/rzgeE/HLsTCqaMajVFYWKDzt0tZpv6uPoh52w9LTCUHG2hX7ZfidEPPkvO6dB4fbl
         fYZQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=dEXbCdf+;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id z42-20020a056870462a00b0011c14eefa66si1920951oao.5.2022.09.01.01.05.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 01 Sep 2022 01:05:08 -0700 (PDT)
Received-SPF: pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mail-wr1-f70.google.com (mail-wr1-f70.google.com
 [209.85.221.70]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.3, cipher=TLS_AES_128_GCM_SHA256) id
 us-mta-517-7UXUKYwrP4Wz6zbaVPo9hw-1; Thu, 01 Sep 2022 04:05:07 -0400
X-MC-Unique: 7UXUKYwrP4Wz6zbaVPo9hw-1
Received: by mail-wr1-f70.google.com with SMTP id h16-20020adfaa90000000b00226e36cc014so1493138wrc.8
        for <kasan-dev@googlegroups.com>; Thu, 01 Sep 2022 01:05:07 -0700 (PDT)
X-Received: by 2002:a05:6000:1e02:b0:226:f21c:e192 with SMTP id bj2-20020a0560001e0200b00226f21ce192mr2042360wrb.7.1662019506244;
        Thu, 01 Sep 2022 01:05:06 -0700 (PDT)
X-Received: by 2002:a05:6000:1e02:b0:226:f21c:e192 with SMTP id bj2-20020a0560001e0200b00226f21ce192mr2042345wrb.7.1662019505980;
        Thu, 01 Sep 2022 01:05:05 -0700 (PDT)
Received: from ?IPV6:2003:cb:c707:9e00:fec0:7e96:15cb:742? (p200300cbc7079e00fec07e9615cb0742.dip0.t-ipconnect.de. [2003:cb:c707:9e00:fec0:7e96:15cb:742])
        by smtp.gmail.com with ESMTPSA id b8-20020adff908000000b00223a50b1be8sm14023827wrr.50.2022.09.01.01.05.03
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 01 Sep 2022 01:05:05 -0700 (PDT)
Message-ID: <404e947a-e1b2-0fae-8b4f-6f2e3ba6328d@redhat.com>
Date: Thu, 1 Sep 2022 10:05:03 +0200
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101
 Thunderbird/91.12.0
To: Kent Overstreet <kent.overstreet@linux.dev>,
 Michal Hocko <mhocko@suse.com>
Cc: Mel Gorman <mgorman@suse.de>, Peter Zijlstra <peterz@infradead.org>,
 Suren Baghdasaryan <surenb@google.com>, akpm@linux-foundation.org,
 vbabka@suse.cz, hannes@cmpxchg.org, roman.gushchin@linux.dev,
 dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com,
 void@manifault.com, juri.lelli@redhat.com, ldufour@linux.ibm.com,
 peterx@redhat.com, axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org,
 nathan@kernel.org, changbin.du@intel.com, ytcoode@gmail.com,
 vincent.guittot@linaro.org, dietmar.eggemann@arm.com, rostedt@goodmis.org,
 bsegall@google.com, bristot@redhat.com, vschneid@redhat.com, cl@linux.com,
 penberg@kernel.org, iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com,
 glider@google.com, elver@google.com, dvyukov@google.com,
 shakeelb@google.com, songmuchun@bytedance.com, arnd@arndb.de,
 jbaron@akamai.com, rientjes@google.com, minchan@google.com,
 kaleshsingh@google.com, kernel-team@android.com, linux-mm@kvack.org,
 iommu@lists.linux.dev, kasan-dev@googlegroups.com, io-uring@vger.kernel.org,
 linux-arch@vger.kernel.org, xen-devel@lists.xenproject.org,
 linux-bcache@vger.kernel.org, linux-modules@vger.kernel.org,
 linux-kernel@vger.kernel.org
References: <20220830214919.53220-1-surenb@google.com>
 <Yw8P8xZ4zqu121xL@hirez.programming.kicks-ass.net>
 <20220831084230.3ti3vitrzhzsu3fs@moria.home.lan>
 <20220831101948.f3etturccmp5ovkl@suse.de> <Yw88RFuBgc7yFYxA@dhcp22.suse.cz>
 <20220831190154.qdlsxfamans3ya5j@moria.home.lan>
From: David Hildenbrand <david@redhat.com>
Organization: Red Hat
Subject: Re: [RFC PATCH 00/30] Code tagging framework and applications
In-Reply-To: <20220831190154.qdlsxfamans3ya5j@moria.home.lan>
X-Mimecast-Spam-Score: 0
X-Mimecast-Originator: redhat.com
Content-Language: en-US
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=dEXbCdf+;
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

On 31.08.22 21:01, Kent Overstreet wrote:
> On Wed, Aug 31, 2022 at 12:47:32PM +0200, Michal Hocko wrote:
>> On Wed 31-08-22 11:19:48, Mel Gorman wrote:
>>> Whatever asking for an explanation as to why equivalent functionality
>>> cannot not be created from ftrace/kprobe/eBPF/whatever is reasonable.
>>
>> Fully agreed and this is especially true for a change this size
>> 77 files changed, 3406 insertions(+), 703 deletions(-)
> 
> In the case of memory allocation accounting, you flat cannot do this with ftrace
> - you could maybe do a janky version that isn't fully accurate, much slower,
> more complicated for the developer to understand and debug and more complicated
> for the end user.
> 
> But please, I invite anyone who's actually been doing this with ftrace to
> demonstrate otherwise.
> 
> Ftrace just isn't the right tool for the job here - we're talking about adding
> per callsite accounting to some of the fastest fast paths in the kernel.
> 
> And the size of the changes for memory allocation accounting are much more
> reasonable:
>  33 files changed, 623 insertions(+), 99 deletions(-)
> 
> The code tagging library should exist anyways, it's been open coded half a dozen
> times in the kernel already.

Hi Kent,

independent of the other discussions, if it's open coded already, does
it make sense to factor that already-open-coded part out independently
of the remainder of the full series here?

[I didn't immediately spot if this series also attempts already to
replace that open-coded part]

-- 
Thanks,

David / dhildenb

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/404e947a-e1b2-0fae-8b4f-6f2e3ba6328d%40redhat.com.
