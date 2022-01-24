Return-Path: <kasan-dev+bncBAABB5UYXKHQMGQE7WJ7EMA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103a.google.com (mail-pj1-x103a.google.com [IPv6:2607:f8b0:4864:20::103a])
	by mail.lfdr.de (Postfix) with ESMTPS id 5166C497DE1
	for <lists+kasan-dev@lfdr.de>; Mon, 24 Jan 2022 12:24:40 +0100 (CET)
Received: by mail-pj1-x103a.google.com with SMTP id m2-20020a17090ade0200b001b51cbdfd9esf7857290pjv.6
        for <lists+kasan-dev@lfdr.de>; Mon, 24 Jan 2022 03:24:40 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1643023478; cv=pass;
        d=google.com; s=arc-20160816;
        b=N2sCsJAKh77b9qhx04NaggVSWr21p34TF2xVDgsPa4CrTWKAMybVtHTTSbc9GKyRlC
         WkARA/gdr8vWrlMFYDQo0mzfEHm7WG0t5C9cnxWASoGOb3FK/mv5evd7BZMyIIxits/6
         EnXsHhnKrmbyJUAjsStCMts0iD7T0Me6v8b6R4ezV+QYyuceZNuaCPG/ssBbqXM6cltp
         2Kg8c5M3rDN64faAKCbpG7vH0KELQprDkgziW34MUQ3wOwvXsPxra+9I37h89o9/IU27
         R9f9TRjPIdTJSrJE4wsgawp50bv70wXcJIf8Id2DnBHX6fXvL5NIfYs0zahurVJ7soOF
         c4Hg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to:from
         :references:cc:to:content-language:subject:user-agent:mime-version
         :date:message-id:dkim-signature;
        bh=sxJBn7t+2ZfFqi+9ui1N7pnKj7Aq9ZSzuZutQXI34/0=;
        b=e1LvPZDpy9JYmzJE3VS2isWQpp2ZRUQ1E4sCWJA15ZGAwdVeMQMBkm26YgXUxeepzS
         z43c9Y+D8LRo8V7jbOuHwAsR2ZfZTST0Ym5JbSuwBO41iKlGWwViPFyTGuYpVUUAk4du
         sXDSjxC7p5pLQFlenEVIsJj56tC1k2+mFi8KaWEjbCQ71lJtjYZCuTnMLrAiDvBhfsJk
         RTzNCrQJ3sh2VmN3XZtmVl5YAJJjCIgkR6xglB+x2RA0QIIXu92aIf1K29ZVuQlPE07G
         RyTWfIJYtwenc/M6kVq7/QMJY+ooKf3FDofJzn3UQGjWT+4Qh8uPxMIGeW3Oh4rMuuF9
         p40w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of liupeng256@huawei.com designates 45.249.212.255 as permitted sender) smtp.mailfrom=liupeng256@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=message-id:date:mime-version:user-agent:subject:content-language:to
         :cc:references:from:in-reply-to:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=sxJBn7t+2ZfFqi+9ui1N7pnKj7Aq9ZSzuZutQXI34/0=;
        b=Tpi9z7GXVtzVspaIUD7CTmkdzssRUQBCsj4YuXWTfJdEzKKPogPMAjSmnkIvYn6cXz
         tfnjC0hAKoYlFqzEjxMjVbAnrY/Vt3/FKipHOfps7A0mbZQ/MmVXgdqQZVJvb3tZMMCw
         Ntx/Lvl9WhnOdjYEeQFYak6+fol3v/mabFGoIFI718a4ZU6L65s2uoqsFYHWOp/gwwzR
         fJTXCNDYJWYMVUzlg5Ujoj7/CUQllYYq2HxJDQeTqBFIZsHJT5Ulh6IgNbYNwFyy6Yys
         KNviHJUmoY09TcGVax5/sy/M/8GuK+vLMZ41pF5j0W+M7IKC8d3HeQ90PpJeD6PJpZAR
         6IyA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:message-id:date:mime-version:user-agent:subject
         :content-language:to:cc:references:from:in-reply-to
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=sxJBn7t+2ZfFqi+9ui1N7pnKj7Aq9ZSzuZutQXI34/0=;
        b=DkuSvAqy4FhQq7euUMBJMKWCQnH18K2wAD4VxmabTgxI7eVTVOQHywMbd7j5+uFnj1
         cF4Sg1nzleybFqDdBNsDHfVX7vE63KwUuSqHrmfIiAzHtpLkOlCljgMwcxN2neXz3+17
         3dYARoJvPBS+H7QJaA4/d/dMNlvuNN1h71J5MBBoFfVuN+V15Ugj5vapN/9z+aosEGv/
         WM6ll4rQSkHTbMEN6C3fKzArBGD7OcorbnvCsCWvMXsghr4hgkGyPRIF9gJfsRMcINNm
         hDBTkNGN7nKkNrQkwu/BS2taLFEQOVqWyMdLTwSqZdJkiOcHQawRcwh9hodKSHAmLDfI
         JCgw==
X-Gm-Message-State: AOAM5305pgRN2+ubA4Jv7WTePsc2XWPkg7L3K5IUTeaBmvh0LCsYVwY8
	Nfv29+VgGg/vTep7i0XnIzc=
X-Google-Smtp-Source: ABdhPJzJ6GM6U01/4dk1a3RwZxMTl/ifuEYTFbvjflkMOsyMY10vlxr/GtGutPUmmyN/HTBlyHnJQw==
X-Received: by 2002:a63:3c59:: with SMTP id i25mr11713467pgn.582.1643023478527;
        Mon, 24 Jan 2022 03:24:38 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:130c:: with SMTP id j12ls6649134pfu.2.gmail; Mon,
 24 Jan 2022 03:24:38 -0800 (PST)
X-Received: by 2002:a63:cc48:: with SMTP id q8mr11167828pgi.474.1643023478043;
        Mon, 24 Jan 2022 03:24:38 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1643023478; cv=none;
        d=google.com; s=arc-20160816;
        b=bQ0OwgkVIQ1ttaa15tN4AZFB1fTOsTX01CJIhKBrQ9zVaZny0yEhfVxXCY0nmDQIxX
         zAghrMswxG3gtCObOidtwhBF3j5yNWx5dnfkdKVPMdx07iEf3ndVPq1bWSGPf1Ljzm/M
         3+OYInXrsjvC49wYWwJGOjvEtsStAd3DIX2bFAnuz1nNag/HGcdCeavVAj+T6J4mDgj8
         me505v/hpd+uyX+NQ1bUIH46MLa0ty3ZA20l+NYWKjknOInHeYtCPvoEaTIlap9kRT6L
         gYhr806d+pXAXIQwJ+HGsd+o8MVWEgiyZl+LNSDRiaYWV46LJEKozSorItKZ0rfTIJYk
         yIPw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:from:references:cc:to:content-language:subject
         :user-agent:mime-version:date:message-id;
        bh=HLM/on/p1cO8f3kzjTCdrIfwx8+/NJWlQGzXImVxPP8=;
        b=E7vyxGsY4SeTRRVj8MeVBqMvFtkA+VpBpHwyCaFjN0L0GHEYql2o10+NOiSHRmV2CO
         Dwu2thURzYu1BcA11Wc5BaR+bPhgBGEbW27Lo1HzKrQpsF1pl98x0vc/yGZv48HH8Wt3
         J29ZKXzYBEHZtsQnSsGQNYwVlGc9SO5sSWvgAN/3wjpWmZlEFfXrtKh3QJzWzonO/k0L
         N8ZMPioXuQ9hFUfVd246waQalBvbreciDBtyrLFwAUqSPWVdInofRnQas0HkrRDrxA08
         MzsQ9yT0E94kbYWE1sYseEPngTKg6OLZDaospt0LSyHgV1rMkXYufz/uixyJK5BpCRos
         HA3w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of liupeng256@huawei.com designates 45.249.212.255 as permitted sender) smtp.mailfrom=liupeng256@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
Received: from szxga08-in.huawei.com (szxga08-in.huawei.com. [45.249.212.255])
        by gmr-mx.google.com with ESMTPS id r5si661511pgv.0.2022.01.24.03.24.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 24 Jan 2022 03:24:38 -0800 (PST)
Received-SPF: pass (google.com: domain of liupeng256@huawei.com designates 45.249.212.255 as permitted sender) client-ip=45.249.212.255;
Received: from kwepemi100021.china.huawei.com (unknown [172.30.72.56])
	by szxga08-in.huawei.com (SkyGuard) with ESMTP id 4Jj6wq6MYbz1FCsg;
	Mon, 24 Jan 2022 19:20:43 +0800 (CST)
Received: from kwepemm600017.china.huawei.com (7.193.23.234) by
 kwepemi100021.china.huawei.com (7.221.188.223) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2308.21; Mon, 24 Jan 2022 19:24:35 +0800
Received: from [10.174.179.19] (10.174.179.19) by
 kwepemm600017.china.huawei.com (7.193.23.234) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2308.21; Mon, 24 Jan 2022 19:24:34 +0800
Content-Type: multipart/alternative;
	boundary="------------g9HgE5kgaFA4bYG2xfKP1vsZ"
Message-ID: <6eb16a68-9a56-7aea-3dd6-bd719a9ce700@huawei.com>
Date: Mon, 24 Jan 2022 19:24:33 +0800
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:91.0) Gecko/20100101
 Thunderbird/91.3.2
Subject: Re: [PATCH RFC 1/3] kfence: Add a module parameter to adjust kfence
 objects
Content-Language: en-US
To: Marco Elver <elver@google.com>
CC: <glider@google.com>, <dvyukov@google.com>, <corbet@lwn.net>,
	<sumit.semwal@linaro.org>, <christian.koenig@amd.com>,
	<akpm@linux-foundation.org>, <kasan-dev@googlegroups.com>,
	<linux-doc@vger.kernel.org>, <linux-kernel@vger.kernel.org>,
	<linaro-mm-sig@lists.linaro.org>, <linux-mm@kvack.org>
References: <20220124025205.329752-1-liupeng256@huawei.com>
 <20220124025205.329752-2-liupeng256@huawei.com>
 <Ye5hKItk3j7arjaI@elver.google.com>
From: "'liupeng (DM)' via kasan-dev" <kasan-dev@googlegroups.com>
In-Reply-To: <Ye5hKItk3j7arjaI@elver.google.com>
X-Originating-IP: [10.174.179.19]
X-ClientProxiedBy: dggems703-chm.china.huawei.com (10.3.19.180) To
 kwepemm600017.china.huawei.com (7.193.23.234)
X-CFilter-Loop: Reflected
X-Original-Sender: liupeng256@huawei.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of liupeng256@huawei.com designates 45.249.212.255 as
 permitted sender) smtp.mailfrom=liupeng256@huawei.com;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
X-Original-From: "liupeng (DM)" <liupeng256@huawei.com>
Reply-To: "liupeng (DM)" <liupeng256@huawei.com>
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

--------------g9HgE5kgaFA4bYG2xfKP1vsZ
Content-Type: text/plain; charset="UTF-8"; format=flowed


On 2022/1/24 16:19, Marco Elver wrote:
> On Mon, Jan 24, 2022 at 02:52AM +0000, Peng Liu wrote:
>> KFENCE is designed to be enabled in production kernels, but it can
>> be also useful in some debug situations. For machines with limited
>> memory and CPU resources, KASAN is really hard to run. Fortunately,
> If these are arm64 based machines, see if CONFIG_KASAN_SW_TAGS works for
> you. In future, we believe that CONFIG_KASAN_HW_TAGS will be suitable
> for a variety of scenarios, including debugging scenarios of resource
> constrained environments.

Thank you for your good suggestion, we will try it.

>> KFENCE can be a suitable candidate. For KFENCE running on a single
>> machine, the possibility of discovering existed bugs will increase
>> as the increasing of KFENCE objects, but this will cost more memory.
>> In order to balance the possibility of discovering existed bugs and
>> memory cost, KFENCE objects need to be adjusted according to memory
>> resources for a compiled kernel Image. Add a module parameter to
>> adjust KFENCE objects will make kfence to use in different machines
>> with the same kernel Image.
>>
>> In short, the following reasons motivate us to add this parameter.
>> 1) In some debug situations, this will make kfence flexible.
>> 2) For some production machines with different memory and CPU size,
>> this will reduce the kernel-Image-version burden.
> [...]
>> This patch (of 3):
> [ Note for future: No need to add "This patch (of X)" usually -- this is
>    added by maintainers if deemed appropriate, and usually includes the
>    cover letter. ]
>
>> The most important motivation of this patch series is to make
>> KFENCE easy-to-use in business situations.
>>
>> Signed-off-by: Peng Liu<liupeng256@huawei.com>
>> ---
>>   Documentation/dev-tools/kfence.rst |  14 ++--
>>   include/linux/kfence.h             |   3 +-
>>   mm/kfence/core.c                   | 108 ++++++++++++++++++++++++-----
>>   mm/kfence/kfence.h                 |   2 +-
>>   mm/kfence/kfence_test.c            |   2 +-
>>   5 files changed, 103 insertions(+), 26 deletions(-)
> [...]
>> diff --git a/include/linux/kfence.h b/include/linux/kfence.h
>> index 4b5e3679a72c..aec4f6b247b5 100644
>> --- a/include/linux/kfence.h
>> +++ b/include/linux/kfence.h
>> @@ -17,12 +17,13 @@
>>   #include <linux/atomic.h>
>>   #include <linux/static_key.h>
>>   
>> +extern unsigned long kfence_num_objects;
>>   /*
>>    * We allocate an even number of pages, as it simplifies calculations to map
>>    * address to metadata indices; effectively, the very first page serves as an
>>    * extended guard page, but otherwise has no special purpose.
>>    */
>> -#define KFENCE_POOL_SIZE ((CONFIG_KFENCE_NUM_OBJECTS + 1) * 2 * PAGE_SIZE)
>> +#define KFENCE_POOL_SIZE ((kfence_num_objects + 1) * 2 * PAGE_SIZE)
>>   extern char *__kfence_pool;
> I appreciate the effort, but you could have gotten a quicker answer if
> you had first sent us an email to ask why adjustable number of objects
> hasn't been done before. Because if it was trivial, we would have
> already done it.
>
> What you've done is turned KFENCE_POOL_SIZE into a function instead of a
> constant (it still being ALL_CAPS is now also misleading).
>
> This is important here:
>
> 	/**
> 	 * is_kfence_address() - check if an address belongs to KFENCE pool
> 	 * @addr: address to check
> 	 *
> 	 * Return: true or false depending on whether the address is within the KFENCE
> 	 * object range.
> 	 *
> 	 * KFENCE objects live in a separate page range and are not to be intermixed
> 	 * with regular heap objects (e.g. KFENCE objects must never be added to the
> 	 * allocator freelists). Failing to do so may and will result in heap
> 	 * corruptions, therefore is_kfence_address() must be used to check whether
> 	 * an object requires specific handling.
> 	 *
> 	 * Note: This function may be used in fast-paths, and is performance critical.
> 	 * Future changes should take this into account; for instance, we want to avoid
> 	 * introducing another load and therefore need to keep KFENCE_POOL_SIZE a
> 	 * constant (until immediate patching support is added to the kernel).
> 	 */
> 	static __always_inline bool is_kfence_address(const void *addr)
> 	{
> 		/*
> 		 * The __kfence_pool != NULL check is required to deal with the case
> 		 * where __kfence_pool == NULL && addr < KFENCE_POOL_SIZE. Keep it in
> 		 * the slow-path after the range-check!
> 		 */
> 		return unlikely((unsigned long)((char *)addr - __kfence_pool) < KFENCE_POOL_SIZE && __kfence_pool);
> 	}
>
> Unfortunately I think you missed the "Note".
>
> Which means that ultimately your patch adds another LOAD to the fast
> path, which is not an acceptable trade-off.
>
> This would mean your change would require benchmarking, but it'd also
> mean we and everyone else would have to re-benchmark _all_ systems where
> we've deployed KFENCE.
>
> I think the only reasonable way forward is if you add immediate patching
> support to the kernel as the "Note" suggests.

May you give us more details about "immediate patching"?

>
> In the meantime, while not a single kernel imagine, we've found that
> debug scenarios usually are best served with a custom debug kernel, as
> there are other debug features that are only Kconfig configurable. Thus,
> having a special debug kernel just configure KFENCE differently
> shouldn't be an issue in the majority of cases.
>
> Should this answer not be satisfying for you, the recently added feature
> skipping already covered allocations (configurable via
> kfence.skip_covered_thresh) alleviates some of the issue of a smaller
> pool with a very low sample interval (viz. high sample rate).
>
> The main thing to watch out for is KFENCE's actual sample rate vs
> intended sample rate (per kfence.sample_interval). If you monitor
> /sys/kernel/debug/kfence/stats, you can compute the actual sample rate.
> If the actual sample rate becomes significantly lower than the intended
> rate, only then does it make sense to increase the pool size. My
> suggestion for you is therefore to run some experiments, while adjusting
> kfence.sample_interval and kfence.skip_covered_thresh until you reach a
> sample rate that is close to intended.
>
> Thanks,
> -- Marco
> .

Thank you for your patient suggestions, it's actually helpful and inspired.
We have integrated your latest work "skipping already covered allocations",
and will do more experiments about KFENCE. Finally, we really hope you can
give us more introductions about "immediate patching".

Thanks,
-- Peng Liu
.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/6eb16a68-9a56-7aea-3dd6-bd719a9ce700%40huawei.com.

--------------g9HgE5kgaFA4bYG2xfKP1vsZ
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<html>
  <head>
    <meta http-equiv=3D"Content-Type" content=3D"text/html; charset=3DUTF-8=
">
  </head>
  <body>
    <p><br>
    </p>
    <div class=3D"moz-cite-prefix">On 2022/1/24 16:19, Marco Elver wrote:<b=
r>
    </div>
    <blockquote type=3D"cite" cite=3D"mid:Ye5hKItk3j7arjaI@elver.google.com=
">
      <pre class=3D"moz-quote-pre" wrap=3D"">On Mon, Jan 24, 2022 at 02:52A=
M +0000, Peng Liu wrote:
</pre>
      <blockquote type=3D"cite">
        <pre class=3D"moz-quote-pre" wrap=3D"">KFENCE is designed to be ena=
bled in production kernels, but it can
be also useful in some debug situations. For machines with limited
memory and CPU resources, KASAN is really hard to run. Fortunately,
</pre>
      </blockquote>
      <pre class=3D"moz-quote-pre" wrap=3D"">
If these are arm64 based machines, see if CONFIG_KASAN_SW_TAGS works for
you. In future, we believe that CONFIG_KASAN_HW_TAGS will be suitable
for a variety of scenarios, including debugging scenarios of resource
constrained environments.
</pre>
    </blockquote>
    <pre class=3D"moz-quote-pre" wrap=3D"">Thank you for your good suggesti=
on, we will try it.
</pre>
    <blockquote type=3D"cite" cite=3D"mid:Ye5hKItk3j7arjaI@elver.google.com=
">
      <pre class=3D"moz-quote-pre" wrap=3D"">
</pre>
      <blockquote type=3D"cite">
        <pre class=3D"moz-quote-pre" wrap=3D"">KFENCE can be a suitable can=
didate. For KFENCE running on a single
machine, the possibility of discovering existed bugs will increase
as the increasing of KFENCE objects, but this will cost more memory.
In order to balance the possibility of discovering existed bugs and
memory cost, KFENCE objects need to be adjusted according to memory
resources for a compiled kernel Image. Add a module parameter to
adjust KFENCE objects will make kfence to use in different machines
with the same kernel Image.

In short, the following reasons motivate us to add this parameter.
1) In some debug situations, this will make kfence flexible.
2) For some production machines with different memory and CPU size,
this will reduce the kernel-Image-version burden.
</pre>
      </blockquote>
      <pre class=3D"moz-quote-pre" wrap=3D"">[...]
</pre>
      <blockquote type=3D"cite">
        <pre class=3D"moz-quote-pre" wrap=3D"">This patch (of 3):
</pre>
      </blockquote>
      <pre class=3D"moz-quote-pre" wrap=3D"">
[ Note for future: No need to add "This patch (of X)" usually -- this is
  added by maintainers if deemed appropriate, and usually includes the
  cover letter. ]

</pre>
      <blockquote type=3D"cite">
        <pre class=3D"moz-quote-pre" wrap=3D"">The most important motivatio=
n of this patch series is to make
KFENCE easy-to-use in business situations.

Signed-off-by: Peng Liu <a class=3D"moz-txt-link-rfc2396E" href=3D"mailto:l=
iupeng256@huawei.com">&lt;liupeng256@huawei.com&gt;</a>
---
 Documentation/dev-tools/kfence.rst |  14 ++--
 include/linux/kfence.h             |   3 +-
 mm/kfence/core.c                   | 108 ++++++++++++++++++++++++-----
 mm/kfence/kfence.h                 |   2 +-
 mm/kfence/kfence_test.c            |   2 +-
 5 files changed, 103 insertions(+), 26 deletions(-)
</pre>
      </blockquote>
      <pre class=3D"moz-quote-pre" wrap=3D"">[...] =20
</pre>
      <blockquote type=3D"cite">
        <pre class=3D"moz-quote-pre" wrap=3D"">diff --git a/include/linux/k=
fence.h b/include/linux/kfence.h
index 4b5e3679a72c..aec4f6b247b5 100644
--- a/include/linux/kfence.h
+++ b/include/linux/kfence.h
@@ -17,12 +17,13 @@
 #include &lt;linux/atomic.h&gt;
 #include &lt;linux/static_key.h&gt;
=20
+extern unsigned long kfence_num_objects;
 /*
  * We allocate an even number of pages, as it simplifies calculations to m=
ap
  * address to metadata indices; effectively, the very first page serves as=
 an
  * extended guard page, but otherwise has no special purpose.
  */
-#define KFENCE_POOL_SIZE ((CONFIG_KFENCE_NUM_OBJECTS + 1) * 2 * PAGE_SIZE)
+#define KFENCE_POOL_SIZE ((kfence_num_objects + 1) * 2 * PAGE_SIZE)
 extern char *__kfence_pool;
</pre>
      </blockquote>
      <pre class=3D"moz-quote-pre" wrap=3D"">
I appreciate the effort, but you could have gotten a quicker answer if
you had first sent us an email to ask why adjustable number of objects
hasn't been done before. Because if it was trivial, we would have
already done it.

What you've done is turned KFENCE_POOL_SIZE into a function instead of a
constant (it still being ALL_CAPS is now also misleading).

This is important here:

	/**
	 * is_kfence_address() - check if an address belongs to KFENCE pool
	 * @addr: address to check
	 *
	 * Return: true or false depending on whether the address is within the KF=
ENCE
	 * object range.
	 *
	 * KFENCE objects live in a separate page range and are not to be intermix=
ed
	 * with regular heap objects (e.g. KFENCE objects must never be added to t=
he
	 * allocator freelists). Failing to do so may and will result in heap
	 * corruptions, therefore is_kfence_address() must be used to check whethe=
r
	 * an object requires specific handling.
	 *
	 * Note: This function may be used in fast-paths, and is performance criti=
cal.
	 * Future changes should take this into account; for instance, we want to =
avoid
	 * introducing another load and therefore need to keep KFENCE_POOL_SIZE a
	 * constant (until immediate patching support is added to the kernel).
	 */
	static __always_inline bool is_kfence_address(const void *addr)
	{
		/*
		 * The __kfence_pool !=3D NULL check is required to deal with the case
		 * where __kfence_pool =3D=3D NULL &amp;&amp; addr &lt; KFENCE_POOL_SIZE.=
 Keep it in
		 * the slow-path after the range-check!
		 */
		return unlikely((unsigned long)((char *)addr - __kfence_pool) &lt; KFENCE=
_POOL_SIZE &amp;&amp; __kfence_pool);
	}

Unfortunately I think you missed the "Note".

Which means that ultimately your patch adds another LOAD to the fast
path, which is not an acceptable trade-off.

This would mean your change would require benchmarking, but it'd also
mean we and everyone else would have to re-benchmark _all_ systems where
we've deployed KFENCE.

I think the only reasonable way forward is if you add immediate patching
support to the kernel as the "Note" suggests.</pre>
    </blockquote>
    <pre>May you give us more details about "immediate patching"?
</pre>
    <blockquote type=3D"cite" cite=3D"mid:Ye5hKItk3j7arjaI@elver.google.com=
">
      <pre class=3D"moz-quote-pre" wrap=3D"">

In the meantime, while not a single kernel imagine, we've found that
debug scenarios usually are best served with a custom debug kernel, as
there are other debug features that are only Kconfig configurable. Thus,
having a special debug kernel just configure KFENCE differently
shouldn't be an issue in the majority of cases.

Should this answer not be satisfying for you, the recently added feature
skipping already covered allocations (configurable via
kfence.skip_covered_thresh) alleviates some of the issue of a smaller
pool with a very low sample interval (viz. high sample rate).

The main thing to watch out for is KFENCE's actual sample rate vs
intended sample rate (per kfence.sample_interval). If you monitor
/sys/kernel/debug/kfence/stats, you can compute the actual sample rate.
If the actual sample rate becomes significantly lower than the intended
rate, only then does it make sense to increase the pool size. My
suggestion for you is therefore to run some experiments, while adjusting
kfence.sample_interval and kfence.skip_covered_thresh until you reach a
sample rate that is close to intended.

Thanks,
-- Marco
.</pre>
    </blockquote>
    <pre class=3D"moz-quote-pre" wrap=3D"">Thank you for your patient sugge=
stions, it's actually helpful and inspired.=20
We have integrated your latest work "skipping already covered allocations",
and will do more experiments about KFENCE. Finally, we really hope you can
give us more introductions about "immediate patching".

Thanks,
-- Peng Liu
.
</pre>
  </body>
</html>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion on the web visit <a href=3D"https://groups.google.c=
om/d/msgid/kasan-dev/6eb16a68-9a56-7aea-3dd6-bd719a9ce700%40huawei.com?utm_=
medium=3Demail&utm_source=3Dfooter">https://groups.google.com/d/msgid/kasan=
-dev/6eb16a68-9a56-7aea-3dd6-bd719a9ce700%40huawei.com</a>.<br />

--------------g9HgE5kgaFA4bYG2xfKP1vsZ--
