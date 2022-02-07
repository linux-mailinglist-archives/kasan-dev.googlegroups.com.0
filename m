Return-Path: <kasan-dev+bncBAABBG7KQGIAMGQEBDJLLDI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103c.google.com (mail-pj1-x103c.google.com [IPv6:2607:f8b0:4864:20::103c])
	by mail.lfdr.de (Postfix) with ESMTPS id F006B4AB31A
	for <lists+kasan-dev@lfdr.de>; Mon,  7 Feb 2022 02:25:48 +0100 (CET)
Received: by mail-pj1-x103c.google.com with SMTP id a15-20020a17090ad80f00b001b8a1e1da50sf2612523pjv.6
        for <lists+kasan-dev@lfdr.de>; Sun, 06 Feb 2022 17:25:48 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1644197147; cv=pass;
        d=google.com; s=arc-20160816;
        b=t+HeCxw5NtJ6oS+U5d6jJ7j5EL5hAyb4ZDMiK3VPdP29eEcUmBIYnqqWzhhUp9w72b
         xjMl7aulVz08EWqNYIUzvYsAsK6ZYTSoPBqwJ+w/ouRNPNSTzCZv1azftvG+6NkA0p1g
         rr1I9I/MOHBVDPnPsS5hEX8f54OanGDTE60Txho6kXWK9Ws3KQ65plEmAcyZwbheh3l0
         0qplpLy7if52yDGFQW1dA4WIp3ci3OsB0pL3gHoh99VCy7capHXObVQbIFykYjzveM9D
         Lk4okFDQadG1bWS5HVrzsyNjN6tFyzl1EON0nsMEu9HLsa4m3psyRThBcQC9xYHmuLSs
         LIqw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to:from
         :references:cc:to:content-language:subject:user-agent:mime-version
         :date:message-id:dkim-signature;
        bh=rt23JC6BnRvexaFG4c/YUK/LD1Z86bBBQECeiqZ4rKk=;
        b=AFGB/Og0ofiY8icoCyZcHn4sZTHNo+BkL3xICNYACwb9jBHozRBH2YqCamCUcWvS8+
         uIRwSDJ09IN9Dc87YHPLmU1ceF/vheY76LXL4iWDunEyg/2AjZLGOBLs0/Dam5Ve9nJ1
         qiS9+9dfs4G6aG7nPsm1OLigp8M28ia6PhLXYS+Ov5Tl3hPT5aHXrSv5ey9mk1Gc0+gg
         7s3WR5vkmtd+Qi3QfSwbgBO052nzW9Y1EpfrCDDx8gGEcQT5sJdMHcLPGTH3pKS/YghZ
         tuGj6pSN1eV0gfjvpFBNjVaLrlKSGw9Cr0GtVnLj29HLrFhcikQacJULi9j/SuXtEzUI
         3gqw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of liupeng256@huawei.com designates 45.249.212.187 as permitted sender) smtp.mailfrom=liupeng256@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=message-id:date:mime-version:user-agent:subject:content-language:to
         :cc:references:from:in-reply-to:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=rt23JC6BnRvexaFG4c/YUK/LD1Z86bBBQECeiqZ4rKk=;
        b=ShYBTSqIJU4f2UB9zSYSfSV0846gdsnxE/0v5oQSwg/YpCsA4Rfbjgg5t7EQJV7Rd2
         QITm9Nc+F7BABz7x3gKoTGuOAnTz3k1QncqgESRkVWO394kBfBrOoSb/vSsrxu5J9dsl
         FKxwkrgGv6oM871XrnMVcAL47aJdFqXFVpTiOgKRjKJMlo5aMHABBJsegWYkLuiZ5UTV
         puJbjagt27bwIa56D7A8z8KRpSM3vXq7HBf8fM3I9/KZdCsWVlV7zDUa7nBFP2Iebm0B
         W7MtoJS7Vt/BEi4RqBtT2Bm0/JDCYZ70y4VBdTSEOjBqkM9kXxI1nuWRpf7WxDY1P0rQ
         sEEQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:message-id:date:mime-version:user-agent:subject
         :content-language:to:cc:references:from:in-reply-to
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=rt23JC6BnRvexaFG4c/YUK/LD1Z86bBBQECeiqZ4rKk=;
        b=BbOEh5IxxRFwsdyNOkUoEjigm0Oez2gii2M2sHXJd+vMbJELkihUclKrp/3AOOCv0q
         /i2BX565D+xxum0zoCu7wJCrDWoxwouEXOR3eMnEHRpP90tIVgqL57cFU6L7zDAH/UKr
         aCMALMBTjoW7wapJV3ukoiLOWlvOZvi4+KrNjvP6KwpL22G9EYPtEsQeUY6Zc9L75ni/
         8WuZgOKdfXxvwO7RJ4YP2bROrcgixp2xwRJexPwt0OLRhlgamphWOS+Wx6iqm7kB0VCl
         qvYEN8rBA00Q9PaDkh/akFemIRErsW5EiU/MH5TcRlPcgYAIupJkiWeNdds8gVdAx+v/
         SN9g==
X-Gm-Message-State: AOAM530uEu6h/4ltvWFkBhyiaoIJJluolS2ELMWxulDUgdtit+ToZfm4
	x/inrurq+P0Rx0Rdb1tjfnM=
X-Google-Smtp-Source: ABdhPJzLH89cTUxV/LLT+DBfWIBnLoYW8aPeGEPE+A3DOfLZbCsJwD5WSfAFmRtKKcnNCzxUci7eqw==
X-Received: by 2002:a17:90b:3b4c:: with SMTP id ot12mr11541453pjb.107.1644197147506;
        Sun, 06 Feb 2022 17:25:47 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:165e:: with SMTP id 30ls2536273pgw.7.gmail; Sun, 06 Feb
 2022 17:25:47 -0800 (PST)
X-Received: by 2002:a05:6a00:1a53:: with SMTP id h19mr13469967pfv.65.1644197146962;
        Sun, 06 Feb 2022 17:25:46 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1644197146; cv=none;
        d=google.com; s=arc-20160816;
        b=Zr3B4t7pYGBb5FfkqSrd9dePAkMRTttaRJLXHmLktCdL/25dEb08FrkTrthQIYwIqH
         ZEjDjyUkRObv/CI6oiNsUkhYReeVBZ+uWH7lsgLGadoF2j0ME+aVEbXFiZzV5tCuFw6J
         oj2QXuQ3o/B5ddjvxTHLv1YWmdAUZciRSIPlNZWAXG5C/43B86BOiaReiWhMviXqjC2N
         gaqNXzzcklzI/Y181ZsqSQ2CCTGWmP0spFLw+cxhsK2LPgMsE2uhWAv/zG/4HjJJ6Wvf
         xxe6Ebk+Ocr8O8GdFy8qLMmXcdVGWhdjJlITaSxiarbBvayc+Gno51XxU06KtfDmseid
         yb+Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:from:references:cc:to:content-language:subject
         :user-agent:mime-version:date:message-id;
        bh=lGez0+OHLAA6rLLt7nZtl17Sy9rY2AV5IPFDjD78GPE=;
        b=HKw2fxY4u6DFXWuDKeyg3S2GeSL9AbrnTjItwbnQKGZqHBLtVVbpxx+dySR7v+bSvl
         SPHgFclOqUzg9j9jtO6Jk0R7PPG7hcCLqE19lRHHPPvzxVZtQFMIUnwRGgt0LLXFrgWR
         OtgP56EjSy2pL9mYm2xl4z7zFqUUc97yWHVLR7B0/kSV3MZcQ5HMYgpEm5RCOTCW2wLy
         ePHz687DNu6rMlE+hSOeIuzdF5OqLMREeNVQjT65v3IkjOwb+Mu/xqloOweaLzrzecpN
         rCPlnxaogi8zKIti4GV8Tx8InBZ5SV0jJW0tEuj9GiY5iFPlbH2luaDMm6MHG/IBFdsR
         ud1g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of liupeng256@huawei.com designates 45.249.212.187 as permitted sender) smtp.mailfrom=liupeng256@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
Received: from szxga01-in.huawei.com (szxga01-in.huawei.com. [45.249.212.187])
        by gmr-mx.google.com with ESMTPS id lf4si87650pjb.0.2022.02.06.17.25.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sun, 06 Feb 2022 17:25:46 -0800 (PST)
Received-SPF: pass (google.com: domain of liupeng256@huawei.com designates 45.249.212.187 as permitted sender) client-ip=45.249.212.187;
Received: from kwepemi500020.china.huawei.com (unknown [172.30.72.57])
	by szxga01-in.huawei.com (SkyGuard) with ESMTP id 4JsT2j5gTZzcck1;
	Mon,  7 Feb 2022 09:24:45 +0800 (CST)
Received: from kwepemm600017.china.huawei.com (7.193.23.234) by
 kwepemi500020.china.huawei.com (7.221.188.8) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2308.21; Mon, 7 Feb 2022 09:25:44 +0800
Received: from [10.174.179.19] (10.174.179.19) by
 kwepemm600017.china.huawei.com (7.193.23.234) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2308.21; Mon, 7 Feb 2022 09:25:43 +0800
Content-Type: multipart/alternative;
	boundary="------------WBwpaL1IxONE0il5bX100oVb"
Message-ID: <1d0b0a51-8376-db19-2634-036e66692d02@huawei.com>
Date: Mon, 7 Feb 2022 09:25:42 +0800
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:91.0) Gecko/20100101
 Thunderbird/91.3.2
Subject: Re: [PATCH v2] kfence: Make test case compatible with run time set
 sample interval
Content-Language: en-US
To: Marco Elver <elver@google.com>
CC: <glider@google.com>, <dvyukov@google.com>, <corbet@lwn.net>,
	<sumit.semwal@linaro.org>, <christian.koenig@amd.com>,
	<akpm@linux-foundation.org>, <kasan-dev@googlegroups.com>,
	<linux-doc@vger.kernel.org>, <linux-kernel@vger.kernel.org>,
	<linaro-mm-sig@lists.linaro.org>, <linux-mm@kvack.org>
References: <20220128015752.931256-1-liupeng256@huawei.com>
 <CANpmjNP+J-Ztz_sov0LPXS8nGCf-2oJFs0OJp1LQMBeaL00CBQ@mail.gmail.com>
From: "'liupeng (DM)' via kasan-dev" <kasan-dev@googlegroups.com>
In-Reply-To: <CANpmjNP+J-Ztz_sov0LPXS8nGCf-2oJFs0OJp1LQMBeaL00CBQ@mail.gmail.com>
X-Originating-IP: [10.174.179.19]
X-ClientProxiedBy: dggems706-chm.china.huawei.com (10.3.19.183) To
 kwepemm600017.china.huawei.com (7.193.23.234)
X-CFilter-Loop: Reflected
X-Original-Sender: liupeng256@huawei.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of liupeng256@huawei.com designates 45.249.212.187 as
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

--------------WBwpaL1IxONE0il5bX100oVb
Content-Type: text/plain; charset="UTF-8"; format=flowed


On 2022/1/28 17:49, Marco Elver wrote:
> On Fri, 28 Jan 2022 at 02:41, Peng Liu<liupeng256@huawei.com>  wrote:
>> The parameter kfence_sample_interval can be set via boot parameter
>> and late shell command, which is convenient for automatical tests
> s/automatical/automated/
>
>> and KFENCE parameter optimation. However, KFENCE test case just use
> s/optimation/optimization/
>
>> compile time CONFIG_KFENCE_SAMPLE_INTERVAL, this will make KFENCE
>> test case not run as user desired. This patch will make KFENCE test
>> case compatible with run-time-set sample interval.
> I'm not too particular about it, but "This patch" is usually bad style:
> https://www.kernel.org/doc/html/latest/process/submitting-patches.html#describe-your-changes

I'm sorry for the "bad style", and I will carefully revise later.

>> v1->v2:
>> - Use EXPORT_SYMBOL_GPL replace EXPORT_SYMBOL
> Changelog is usually placed after '---', because it's mostly redundant
> once committed. Often maintainers include a "Link" to the original
> patch which then has history and discussion.
>
>> Signed-off-by: Peng Liu<liupeng256@huawei.com>
> Reviewed-by: Marco Elver<elver@google.com>
>
>
>> ---
>>   include/linux/kfence.h  | 2 ++
>>   mm/kfence/core.c        | 3 ++-
>>   mm/kfence/kfence_test.c | 8 ++++----
>>   3 files changed, 8 insertions(+), 5 deletions(-)
>>
>> diff --git a/include/linux/kfence.h b/include/linux/kfence.h
>> index 4b5e3679a72c..f49e64222628 100644
>> --- a/include/linux/kfence.h
>> +++ b/include/linux/kfence.h
>> @@ -17,6 +17,8 @@
>>   #include <linux/atomic.h>
>>   #include <linux/static_key.h>
>>
>> +extern unsigned long kfence_sample_interval;
>> +
>>   /*
>>    * We allocate an even number of pages, as it simplifies calculations to map
>>    * address to metadata indices; effectively, the very first page serves as an
>> diff --git a/mm/kfence/core.c b/mm/kfence/core.c
>> index 5ad40e3add45..13128fa13062 100644
>> --- a/mm/kfence/core.c
>> +++ b/mm/kfence/core.c
>> @@ -47,7 +47,8 @@
>>
>>   static bool kfence_enabled __read_mostly;
>>
>> -static unsigned long kfence_sample_interval __read_mostly = CONFIG_KFENCE_SAMPLE_INTERVAL;
>> +unsigned long kfence_sample_interval __read_mostly = CONFIG_KFENCE_SAMPLE_INTERVAL;
>> +EXPORT_SYMBOL_GPL(kfence_sample_interval); /* Export for test modules. */
>>
>>   #ifdef MODULE_PARAM_PREFIX
>>   #undef MODULE_PARAM_PREFIX
>> diff --git a/mm/kfence/kfence_test.c b/mm/kfence/kfence_test.c
>> index a22b1af85577..50dbb815a2a8 100644
>> --- a/mm/kfence/kfence_test.c
>> +++ b/mm/kfence/kfence_test.c
>> @@ -268,13 +268,13 @@ static void *test_alloc(struct kunit *test, size_t size, gfp_t gfp, enum allocat
>>           * 100x the sample interval should be more than enough to ensure we get
>>           * a KFENCE allocation eventually.
>>           */
>> -       timeout = jiffies + msecs_to_jiffies(100 * CONFIG_KFENCE_SAMPLE_INTERVAL);
>> +       timeout = jiffies + msecs_to_jiffies(100 * kfence_sample_interval);
>>          /*
>>           * Especially for non-preemption kernels, ensure the allocation-gate
>>           * timer can catch up: after @resched_after, every failed allocation
>>           * attempt yields, to ensure the allocation-gate timer is scheduled.
>>           */
>> -       resched_after = jiffies + msecs_to_jiffies(CONFIG_KFENCE_SAMPLE_INTERVAL);
>> +       resched_after = jiffies + msecs_to_jiffies(kfence_sample_interval);
>>          do {
>>                  if (test_cache)
>>                          alloc = kmem_cache_alloc(test_cache, gfp);
>> @@ -608,7 +608,7 @@ static void test_gfpzero(struct kunit *test)
>>          int i;
>>
>>          /* Skip if we think it'd take too long. */
>> -       KFENCE_TEST_REQUIRES(test, CONFIG_KFENCE_SAMPLE_INTERVAL <= 100);
>> +       KFENCE_TEST_REQUIRES(test, kfence_sample_interval <= 100);
>>
>>          setup_test_cache(test, size, 0, NULL);
>>          buf1 = test_alloc(test, size, GFP_KERNEL, ALLOCATE_ANY);
>> @@ -739,7 +739,7 @@ static void test_memcache_alloc_bulk(struct kunit *test)
>>           * 100x the sample interval should be more than enough to ensure we get
>>           * a KFENCE allocation eventually.
>>           */
>> -       timeout = jiffies + msecs_to_jiffies(100 * CONFIG_KFENCE_SAMPLE_INTERVAL);
>> +       timeout = jiffies + msecs_to_jiffies(100 * kfence_sample_interval);
>>          do {
>>                  void *objects[100];
>>                  int i, num = kmem_cache_alloc_bulk(test_cache, GFP_ATOMIC, ARRAY_SIZE(objects),
>> --
>> 2.18.0.huawei.25
>>
> .

I'm sorry for the latency due to the spring festival. Thank you for your advice,
and I will send a revised patch later.

Thanks,
-- Peng Liu

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1d0b0a51-8376-db19-2634-036e66692d02%40huawei.com.

--------------WBwpaL1IxONE0il5bX100oVb
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
    <div class=3D"moz-cite-prefix">On 2022/1/28 17:49, Marco Elver wrote:<b=
r>
    </div>
    <blockquote type=3D"cite"
cite=3D"mid:CANpmjNP+J-Ztz_sov0LPXS8nGCf-2oJFs0OJp1LQMBeaL00CBQ@mail.gmail.=
com">
      <pre class=3D"moz-quote-pre" wrap=3D"">On Fri, 28 Jan 2022 at 02:41, =
Peng Liu <a class=3D"moz-txt-link-rfc2396E" href=3D"mailto:liupeng256@huawe=
i.com">&lt;liupeng256@huawei.com&gt;</a> wrote:
</pre>
      <blockquote type=3D"cite">
        <pre class=3D"moz-quote-pre" wrap=3D"">The parameter kfence_sample_=
interval can be set via boot parameter
and late shell command, which is convenient for automatical tests
</pre>
      </blockquote>
      <pre class=3D"moz-quote-pre" wrap=3D"">
s/automatical/automated/

</pre>
      <blockquote type=3D"cite">
        <pre class=3D"moz-quote-pre" wrap=3D"">and KFENCE parameter optimat=
ion. However, KFENCE test case just use
</pre>
      </blockquote>
      <pre class=3D"moz-quote-pre" wrap=3D"">
s/optimation/optimization/

</pre>
      <blockquote type=3D"cite">
        <pre class=3D"moz-quote-pre" wrap=3D"">compile time CONFIG_KFENCE_S=
AMPLE_INTERVAL, this will make KFENCE
test case not run as user desired. This patch will make KFENCE test
case compatible with run-time-set sample interval.
</pre>
      </blockquote>
      <pre class=3D"moz-quote-pre" wrap=3D"">
I'm not too particular about it, but "This patch" is usually bad style:
<a class=3D"moz-txt-link-freetext" href=3D"https://www.kernel.org/doc/html/=
latest/process/submitting-patches.html#describe-your-changes">https://www.k=
ernel.org/doc/html/latest/process/submitting-patches.html#describe-your-cha=
nges</a>
</pre>
    </blockquote>
    <pre>I'm sorry for the "bad style", and I will carefully revise later.
</pre>
    <blockquote type=3D"cite"
cite=3D"mid:CANpmjNP+J-Ztz_sov0LPXS8nGCf-2oJFs0OJp1LQMBeaL00CBQ@mail.gmail.=
com">
      <pre class=3D"moz-quote-pre" wrap=3D"">
</pre>
      <blockquote type=3D"cite">
        <pre class=3D"moz-quote-pre" wrap=3D"">v1-&gt;v2:
- Use EXPORT_SYMBOL_GPL replace EXPORT_SYMBOL
</pre>
      </blockquote>
      <pre class=3D"moz-quote-pre" wrap=3D"">
Changelog is usually placed after '---', because it's mostly redundant
once committed. Often maintainers include a "Link" to the original
patch which then has history and discussion.

</pre>
      <blockquote type=3D"cite">
        <pre class=3D"moz-quote-pre" wrap=3D"">Signed-off-by: Peng Liu <a c=
lass=3D"moz-txt-link-rfc2396E" href=3D"mailto:liupeng256@huawei.com">&lt;li=
upeng256@huawei.com&gt;</a>
</pre>
      </blockquote>
      <pre class=3D"moz-quote-pre" wrap=3D"">
Reviewed-by: Marco Elver <a class=3D"moz-txt-link-rfc2396E" href=3D"mailto:=
elver@google.com">&lt;elver@google.com&gt;</a>


</pre>
      <blockquote type=3D"cite">
        <pre class=3D"moz-quote-pre" wrap=3D"">---
 include/linux/kfence.h  | 2 ++
 mm/kfence/core.c        | 3 ++-
 mm/kfence/kfence_test.c | 8 ++++----
 3 files changed, 8 insertions(+), 5 deletions(-)

diff --git a/include/linux/kfence.h b/include/linux/kfence.h
index 4b5e3679a72c..f49e64222628 100644
--- a/include/linux/kfence.h
+++ b/include/linux/kfence.h
@@ -17,6 +17,8 @@
 #include &lt;linux/atomic.h&gt;
 #include &lt;linux/static_key.h&gt;

+extern unsigned long kfence_sample_interval;
+
 /*
  * We allocate an even number of pages, as it simplifies calculations to m=
ap
  * address to metadata indices; effectively, the very first page serves as=
 an
diff --git a/mm/kfence/core.c b/mm/kfence/core.c
index 5ad40e3add45..13128fa13062 100644
--- a/mm/kfence/core.c
+++ b/mm/kfence/core.c
@@ -47,7 +47,8 @@

 static bool kfence_enabled __read_mostly;

-static unsigned long kfence_sample_interval __read_mostly =3D CONFIG_KFENC=
E_SAMPLE_INTERVAL;
+unsigned long kfence_sample_interval __read_mostly =3D CONFIG_KFENCE_SAMPL=
E_INTERVAL;
+EXPORT_SYMBOL_GPL(kfence_sample_interval); /* Export for test modules. */

 #ifdef MODULE_PARAM_PREFIX
 #undef MODULE_PARAM_PREFIX
diff --git a/mm/kfence/kfence_test.c b/mm/kfence/kfence_test.c
index a22b1af85577..50dbb815a2a8 100644
--- a/mm/kfence/kfence_test.c
+++ b/mm/kfence/kfence_test.c
@@ -268,13 +268,13 @@ static void *test_alloc(struct kunit *test, size_t si=
ze, gfp_t gfp, enum allocat
         * 100x the sample interval should be more than enough to ensure we=
 get
         * a KFENCE allocation eventually.
         */
-       timeout =3D jiffies + msecs_to_jiffies(100 * CONFIG_KFENCE_SAMPLE_I=
NTERVAL);
+       timeout =3D jiffies + msecs_to_jiffies(100 * kfence_sample_interval=
);
        /*
         * Especially for non-preemption kernels, ensure the allocation-gat=
e
         * timer can catch up: after @resched_after, every failed allocatio=
n
         * attempt yields, to ensure the allocation-gate timer is scheduled=
.
         */
-       resched_after =3D jiffies + msecs_to_jiffies(CONFIG_KFENCE_SAMPLE_I=
NTERVAL);
+       resched_after =3D jiffies + msecs_to_jiffies(kfence_sample_interval=
);
        do {
                if (test_cache)
                        alloc =3D kmem_cache_alloc(test_cache, gfp);
@@ -608,7 +608,7 @@ static void test_gfpzero(struct kunit *test)
        int i;

        /* Skip if we think it'd take too long. */
-       KFENCE_TEST_REQUIRES(test, CONFIG_KFENCE_SAMPLE_INTERVAL &lt;=3D 10=
0);
+       KFENCE_TEST_REQUIRES(test, kfence_sample_interval &lt;=3D 100);

        setup_test_cache(test, size, 0, NULL);
        buf1 =3D test_alloc(test, size, GFP_KERNEL, ALLOCATE_ANY);
@@ -739,7 +739,7 @@ static void test_memcache_alloc_bulk(struct kunit *test=
)
         * 100x the sample interval should be more than enough to ensure we=
 get
         * a KFENCE allocation eventually.
         */
-       timeout =3D jiffies + msecs_to_jiffies(100 * CONFIG_KFENCE_SAMPLE_I=
NTERVAL);
+       timeout =3D jiffies + msecs_to_jiffies(100 * kfence_sample_interval=
);
        do {
                void *objects[100];
                int i, num =3D kmem_cache_alloc_bulk(test_cache, GFP_ATOMIC=
, ARRAY_SIZE(objects),
--
2.18.0.huawei.25

</pre>
      </blockquote>
      <pre class=3D"moz-quote-pre" wrap=3D"">.</pre>
    </blockquote>
    <pre>I'm sorry for the latency due to the spring festival. Thank you fo=
r your advice,
and I will send a revised patch later.

Thanks,
-- Peng Liu</pre>
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
om/d/msgid/kasan-dev/1d0b0a51-8376-db19-2634-036e66692d02%40huawei.com?utm_=
medium=3Demail&utm_source=3Dfooter">https://groups.google.com/d/msgid/kasan=
-dev/1d0b0a51-8376-db19-2634-036e66692d02%40huawei.com</a>.<br />

--------------WBwpaL1IxONE0il5bX100oVb--
