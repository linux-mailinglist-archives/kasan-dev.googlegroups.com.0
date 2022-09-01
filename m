Return-Path: <kasan-dev+bncBC32535MUICBBJEVYOMAMGQEVEH6DWA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd40.google.com (mail-io1-xd40.google.com [IPv6:2607:f8b0:4864:20::d40])
	by mail.lfdr.de (Postfix) with ESMTPS id 52B965A9B33
	for <lists+kasan-dev@lfdr.de>; Thu,  1 Sep 2022 17:07:18 +0200 (CEST)
Received: by mail-io1-xd40.google.com with SMTP id t18-20020a5d8852000000b0068832d2b28esf10774105ios.2
        for <lists+kasan-dev@lfdr.de>; Thu, 01 Sep 2022 08:07:18 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662044836; cv=pass;
        d=google.com; s=arc-20160816;
        b=XlU+R7XpxrRZ4+Ubby2FeJ/5GCSJo5nQr+B7o/y9vtDQBPiBXYOtB/QAVMk5yIMbzd
         DoMqicc+/KRQHIywoljViR/SaXNRsdgdifKgjUr5OMoBPjVvvmhDhGvvLz3Pf4aCDo+1
         B5tq9RRShmmF5WIo3N+uNLPAsiNZZqirxDfwE7fUOO+b7JzsoFRS1ELitmjSdGKqmvwf
         3spP1I1G4l+b7dtejHZncbQlrFsPZzxsFUdVY3Is/7B37GXrD26LtphNxmjOlgymY3sA
         zN8vfSV8NyZGei1+kBaKvZbUwR58PD0cTiHotyVrF9H0gyJ3lEyhTUy+ksWRnzYq6xHy
         aYoQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :subject:organization:from:references:cc:to:user-agent:mime-version
         :date:message-id:sender:dkim-signature;
        bh=5uFERhCyXpuXeG1C3nNHWsx12xfWAvNHKlsXsg2nS/0=;
        b=Z1TM/Ggzp3IEbhsRRzbXKnQugRuD6CRRzJ+OHbzZ/7fcfL6owM6QEA0MRe35ewQH3b
         S5H0IoU1Z7OcDk6IKe9qXd8YA56uiu/q8bVECNyZSfQwEJ/4VqBhut2/K7V+h2Uz7lBL
         jHcjLdOuStcoTq5kOJChwSn9O0MovuhqcK0R1TfQdJsXD759PFbIkVty8SxwkOy5xKSq
         +Y4AgpgjkVMSDlwgYkMnI5iy/QlQCt17lImNrqWZdAvRGT/iEhJW3Y6IELsmoyWHy48h
         g9fDdGYs7kK97qC2ONrc9auzqbzqirXh4M4jlrroje8P6FX6zS8Q/oLOy0Dqh1ktzuAm
         COUQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=ZNTLBe2L;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-language:in-reply-to:subject:organization
         :from:references:cc:to:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date;
        bh=5uFERhCyXpuXeG1C3nNHWsx12xfWAvNHKlsXsg2nS/0=;
        b=WdKqYpCoa1Zac+1g1u2Vc8ZF2z1kBZ1IHGak8YX0Dn2TKcA90N31UgsbGNfMsZHfmP
         mY3MwiERtSshDuPAXJMCtAc9qRRDjGQcJuAL8xL8Jf8933TjbOt42kxNlEeWq3CKjHkH
         6wCZJQS6OcCWt4XPR+FyTbIHH63Bmly9uox3gShrDVKGgJVZX9D4lytKC/26iuboxOKY
         AoG45SHYKHWa3TxMXG20BPeBAy7f7noXuA/sPNW7vF+q5QSEXwYABIVXG4eTGf7GsSCd
         VYxriX88F+u8EKOped2gbyV/T1HYa9RHJnZWGZ/4MQZ3UarpDdPndZcfm6gCDK9FMqXZ
         TFKA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-language:in-reply-to:subject:organization:from:references
         :cc:to:user-agent:mime-version:date:message-id:x-gm-message-state
         :sender:from:to:cc:subject:date;
        bh=5uFERhCyXpuXeG1C3nNHWsx12xfWAvNHKlsXsg2nS/0=;
        b=XeJh6tCCfqk8OP1Dz2LALLvv3cryvDSbWYRDlTZyc025KfkHQLLLOF6OeqjrA61DhG
         95PcxKAKx2aVeBtqw/E3wed30XNWtLxz8mnn5B8i5JdfQ0YrA9FCwnb88XSpnvNErHuW
         J2lMFxROv0cx1iuSWNyRgj8H0LhLBxLbtWpo3atkGifr+HRTKPNECqoCBlPVxobEIGY3
         2b6aZDZq98hoogQFBqY4k30vR/1Jp6mW95Jc33JDmsIefot/05G9JhUSF7iPVEoOCU76
         u78sb0DxEnKEXI20iTERDMFSTIL5pnupKb3y/MYcTKXxofFWdSz3imDcGSMb3f6R1Dd7
         H5eA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo1uf8ZoOG/BsNoajMtN82GNpALEC+yrlg3+TuwIvf2tV+wqfAIO
	E0DWnBk9dvlEs38409AXJF4=
X-Google-Smtp-Source: AA6agR6lp/ewka8BvNfr/iyo0WfyDyrZKDfGQHOaYqhqWSDvkVRaGvqPAiJK1wD5mft+cURXAljYdw==
X-Received: by 2002:a05:6e02:156b:b0:2e9:a556:80fd with SMTP id k11-20020a056e02156b00b002e9a55680fdmr15692417ilu.44.1662044836783;
        Thu, 01 Sep 2022 08:07:16 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a02:95cb:0:b0:34c:dcb:a180 with SMTP id b69-20020a0295cb000000b0034c0dcba180ls547087jai.4.-pod-prod-gmail;
 Thu, 01 Sep 2022 08:07:16 -0700 (PDT)
X-Received: by 2002:a05:6638:22cf:b0:34a:11b6:2636 with SMTP id j15-20020a05663822cf00b0034a11b62636mr16774173jat.80.1662044836283;
        Thu, 01 Sep 2022 08:07:16 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662044836; cv=none;
        d=google.com; s=arc-20160816;
        b=j85SftcBdTk6TPo3UwwMo+HSmaFe0vYCOWzgC3v0zzIW4jVRlxfY3nUmSJKd7657Io
         ZG0URAE0x+K5nGYOBnLYK3iE/2vG1z0macdqanKzM+OjkqHq5RGapZKXv+nl7CQE5QYN
         LekJpAK1lOI9CogMulzwucqqpQND6LKUdx7/BLIheDN9x41kIzIGO6xheOALb3UD4cfd
         Bb0BkixmhyFKfFvm6SzjVjzauXSJybRejLeHlWldS8TuAfyyMEo9YG0UaiwGt4BA2c6q
         xJgX8RlK609rOoqZECeGlMl5SjMe1/Jo00w/3R04ct3lW4SDYFY3Ptm9dtb4Afh5l5B6
         SvEw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:subject
         :organization:from:references:cc:to:user-agent:mime-version:date
         :message-id:dkim-signature;
        bh=n51zgqgBl470PB0vgcZT4BRIRHbxoQSrqhNCiStba2E=;
        b=o4hgPy4qL7uuNms2SJ40tk+V8v86jupekA3VzUNxk+N61Cz8WjCI66ZR7XouLs8FJd
         SIcNrwIwX4eXbnk2YNf4mhO0PUd7O/xsQwkG2WPgi5d/19WaxlSXaXuhJQiA1qkNLUB+
         N5IpJLVLx20Aq5VTn3C5GhJqACSplCQ52VjQsfBn6eq0Yi4GKOS4GSdaZONJrroLk7Cv
         PYg8R3EwwDPDOxLDXONcnZfFBFWC2rsyaOoTh2nuMcfzunSrLbgCsJ0HzXAlYY+KQkSe
         h3Dzo4LzLI1yusDxk4lFhKeBpnkGkSb2dNNAFqdDlbPVDT0rQWtRLuXpMabl2J5/C+16
         gACg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=ZNTLBe2L;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id t5-20020a02c485000000b0034c14f88c60si132049jam.1.2022.09.01.08.07.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 01 Sep 2022 08:07:16 -0700 (PDT)
Received-SPF: pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mail-wr1-f72.google.com (mail-wr1-f72.google.com
 [209.85.221.72]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.3, cipher=TLS_AES_128_GCM_SHA256) id
 us-mta-259-DNa7JAkYP3uqp-oIc6hVww-1; Thu, 01 Sep 2022 11:07:13 -0400
X-MC-Unique: DNa7JAkYP3uqp-oIc6hVww-1
Received: by mail-wr1-f72.google.com with SMTP id o3-20020adfa103000000b0022514e8e99bso3162049wro.19
        for <kasan-dev@googlegroups.com>; Thu, 01 Sep 2022 08:07:13 -0700 (PDT)
X-Received: by 2002:a7b:ce13:0:b0:3a6:34f8:e21d with SMTP id m19-20020a7bce13000000b003a634f8e21dmr5628117wmc.22.1662044831141;
        Thu, 01 Sep 2022 08:07:11 -0700 (PDT)
X-Received: by 2002:a7b:ce13:0:b0:3a6:34f8:e21d with SMTP id m19-20020a7bce13000000b003a634f8e21dmr5628080wmc.22.1662044830813;
        Thu, 01 Sep 2022 08:07:10 -0700 (PDT)
Received: from ?IPV6:2003:cb:c707:9e00:fec0:7e96:15cb:742? (p200300cbc7079e00fec07e9615cb0742.dip0.t-ipconnect.de. [2003:cb:c707:9e00:fec0:7e96:15cb:742])
        by smtp.gmail.com with ESMTPSA id a6-20020a5d4d46000000b00226dedf1ab7sm9303786wru.76.2022.09.01.08.07.07
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 01 Sep 2022 08:07:09 -0700 (PDT)
Message-ID: <78e55029-0eaf-b4b3-7e86-1086b97c60c6@redhat.com>
Date: Thu, 1 Sep 2022 17:07:06 +0200
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101
 Thunderbird/91.12.0
To: Kent Overstreet <kent.overstreet@linux.dev>
Cc: Michal Hocko <mhocko@suse.com>, Mel Gorman <mgorman@suse.de>,
 Peter Zijlstra <peterz@infradead.org>, Suren Baghdasaryan
 <surenb@google.com>, akpm@linux-foundation.org, vbabka@suse.cz,
 hannes@cmpxchg.org, roman.gushchin@linux.dev, dave@stgolabs.net,
 willy@infradead.org, liam.howlett@oracle.com, void@manifault.com,
 juri.lelli@redhat.com, ldufour@linux.ibm.com, peterx@redhat.com,
 axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org, nathan@kernel.org,
 changbin.du@intel.com, ytcoode@gmail.com, vincent.guittot@linaro.org,
 dietmar.eggemann@arm.com, rostedt@goodmis.org, bsegall@google.com,
 bristot@redhat.com, vschneid@redhat.com, cl@linux.com, penberg@kernel.org,
 iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com, glider@google.com,
 elver@google.com, dvyukov@google.com, shakeelb@google.com,
 songmuchun@bytedance.com, arnd@arndb.de, jbaron@akamai.com,
 rientjes@google.com, minchan@google.com, kaleshsingh@google.com,
 kernel-team@android.com, linux-mm@kvack.org, iommu@lists.linux.dev,
 kasan-dev@googlegroups.com, io-uring@vger.kernel.org,
 linux-arch@vger.kernel.org, xen-devel@lists.xenproject.org,
 linux-bcache@vger.kernel.org, linux-modules@vger.kernel.org,
 linux-kernel@vger.kernel.org
References: <20220830214919.53220-1-surenb@google.com>
 <Yw8P8xZ4zqu121xL@hirez.programming.kicks-ass.net>
 <20220831084230.3ti3vitrzhzsu3fs@moria.home.lan>
 <20220831101948.f3etturccmp5ovkl@suse.de> <Yw88RFuBgc7yFYxA@dhcp22.suse.cz>
 <20220831190154.qdlsxfamans3ya5j@moria.home.lan>
 <404e947a-e1b2-0fae-8b4f-6f2e3ba6328d@redhat.com>
 <20220901142345.agkfp2d5lijdp6pt@moria.home.lan>
From: David Hildenbrand <david@redhat.com>
Organization: Red Hat
Subject: Re: [RFC PATCH 00/30] Code tagging framework and applications
In-Reply-To: <20220901142345.agkfp2d5lijdp6pt@moria.home.lan>
X-Mimecast-Spam-Score: 0
X-Mimecast-Originator: redhat.com
Content-Language: en-US
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=ZNTLBe2L;
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

On 01.09.22 16:23, Kent Overstreet wrote:
> On Thu, Sep 01, 2022 at 10:05:03AM +0200, David Hildenbrand wrote:
>> On 31.08.22 21:01, Kent Overstreet wrote:
>>> On Wed, Aug 31, 2022 at 12:47:32PM +0200, Michal Hocko wrote:
>>>> On Wed 31-08-22 11:19:48, Mel Gorman wrote:
>>>>> Whatever asking for an explanation as to why equivalent functionality
>>>>> cannot not be created from ftrace/kprobe/eBPF/whatever is reasonable.
>>>>
>>>> Fully agreed and this is especially true for a change this size
>>>> 77 files changed, 3406 insertions(+), 703 deletions(-)
>>>
>>> In the case of memory allocation accounting, you flat cannot do this with ftrace
>>> - you could maybe do a janky version that isn't fully accurate, much slower,
>>> more complicated for the developer to understand and debug and more complicated
>>> for the end user.
>>>
>>> But please, I invite anyone who's actually been doing this with ftrace to
>>> demonstrate otherwise.
>>>
>>> Ftrace just isn't the right tool for the job here - we're talking about adding
>>> per callsite accounting to some of the fastest fast paths in the kernel.
>>>
>>> And the size of the changes for memory allocation accounting are much more
>>> reasonable:
>>>  33 files changed, 623 insertions(+), 99 deletions(-)
>>>
>>> The code tagging library should exist anyways, it's been open coded half a dozen
>>> times in the kernel already.
>>
>> Hi Kent,
>>
>> independent of the other discussions, if it's open coded already, does
>> it make sense to factor that already-open-coded part out independently
>> of the remainder of the full series here?
> 
> It's discussed in the cover letter, that is exactly how the patch series is
> structured.

Skimming over the patches (that I was CCed on) and skimming over the
cover letter, I got the impression that everything after patch 7 is
introducing something new instead of refactoring something out.

>  
>> [I didn't immediately spot if this series also attempts already to
>> replace that open-coded part]
> 
> Uh huh.
> 
> Honestly, some days it feels like lkml is just as bad as slashdot, with people
> wanting to get in their two cents without actually reading...

... and of course you had to reply like that. I should just have learned
from my last upstream experience with you and kept you on my spam list.

Thanks, bye

-- 
Thanks,

David / dhildenb

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/78e55029-0eaf-b4b3-7e86-1086b97c60c6%40redhat.com.
