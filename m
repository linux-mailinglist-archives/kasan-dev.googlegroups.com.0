Return-Path: <kasan-dev+bncBDV2D5O34IDRBQN3VCXQMGQEUBOJEVQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x37.google.com (mail-oa1-x37.google.com [IPv6:2001:4860:4864:20::37])
	by mail.lfdr.de (Postfix) with ESMTPS id B86D38757D7
	for <lists+kasan-dev@lfdr.de>; Thu,  7 Mar 2024 21:04:20 +0100 (CET)
Received: by mail-oa1-x37.google.com with SMTP id 586e51a60fabf-221853c8f28sf722306fac.2
        for <lists+kasan-dev@lfdr.de>; Thu, 07 Mar 2024 12:04:20 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1709841859; cv=pass;
        d=google.com; s=arc-20160816;
        b=btGP44YCnTH5q9QHYKEAk6OEzNWY/uDAthGGmxA84YiTEZGmhwuagNj/TTrqPigkVo
         75CEb4VjbVJhj5nS21i0p2yNYnf12ooP+C16zZsPs7h5YiXE6sY+qjy7JKELH6c41gGl
         IZ7eatvJ7bY6UsrJc6z9ANNR2USqT7K2lEoQ0EE9B8WSymx/TWYWofokYnqRljPrJL2P
         SD6KXraWx2tx3/kRo/n8xiI/26S656oYBcP6DX7m75xPI64znUY5HPpVtodDImebxS5p
         xMoXMQPPpVMIYTRUCPu2Fiwnp846MvxDu1KnTuMahrEe8pDJyZepZbScWkgkyn08kqE7
         eFWw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=DCGD6AxUJAIAzWpDAFcqfQW6j5eNpgnen9Xv0e2GATI=;
        fh=KnPQLVL5SyBARpzeUtZpwPT3/6RNWD1Lj0LCKtM7jvk=;
        b=EuKH5i2t7LyFhZPg5wfI7MbqtoMSQBhBExKu7cj8xQOZV/NlhGIzm/PZ9vc6L1Uc5t
         g6XYh+Oc1NqgCs8Npzn5Bcl2S7Mucu45nt5uI/8NQtD6Cp0kBRgvsBcx7FzZOUDGUyxc
         T9Tfm5IXkx1Xh32aEZZwc4/nvwVC94gDwo3rv3SVBeQ6rhncVFr/tR6eQVSD24/GcYWf
         qnVg1/0kdsHouZ2wlyuij5CompeojRXG5JYOxwkZ8e7cqplq8seJxODkH6xl0XdU3d5k
         0lcr+66MkeUdnO26+8YnTvFbWrXVnP0e56zgx2aDjJJp1Cm6/yQyPAvOLpmjKuhN0Ido
         MCcA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=bombadil.20210309 header.b=0zkhqM1U;
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=rdunlap@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1709841859; x=1710446659; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=DCGD6AxUJAIAzWpDAFcqfQW6j5eNpgnen9Xv0e2GATI=;
        b=AdFLubOBn2Ou/5tuE1XMJzdAsrnJXPIyjD1yIt96FsE+IkNcYj9xYXBprhltb+8XLm
         1pyEAb0oyRS6x27/lhAiRlOn7x+pO9N4F53+rAq80UC5cZPt9sBiyF4Ajkg6iREaGMiv
         dJASNimfkqZirlC8tNUJnwGLYGt6tUJ+E97TyFHWD91FQzUSrbNuJW+FP1ilqoe2f+Vf
         20PmDkRorA9WTgIhEygZtwDRAHS/VTdQUEWJo7zkJOUmCYr01wWrbTmP/H7o49W7yHW2
         76BBSQEi6W/m3WlxHLxrdegb9mStzCpkpFhK1jLn0jx3dlzrtkAMHZ84Mojon7fqWpor
         32uQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1709841859; x=1710446659;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=DCGD6AxUJAIAzWpDAFcqfQW6j5eNpgnen9Xv0e2GATI=;
        b=OPkzSxCU46p9XTXHIptHmjX2dklj0UWbT6FY6eHjt5dC8QHZG4SAP/d1m1MMjyvMEk
         kxSmjQSdvvzVYNubZTlo3Shl3R20YxfkJSaaKHOTrYQybKR/WAq3mFmObAQrFfDmpf5f
         B2lzI0T4qGn28BcY0tJdadBV1wOEu1ARrC/LU2YXYU+Tz/G7qZma9HK7l69WmvtRf2SO
         P7Q2f6q5dREKUpEodvP5yJfMPqph2w6H0dUoe+CkYyNq5p5Q2ZNb86YFzuSoUIB20oa7
         QKDTioT4VvKe/yaTHmwu5z0hP5AR6+QpRD8c9ZPswxUjPaDZEBsCl1om6InBghiUSc8D
         GGWw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXW5LhgWK+DNEnmPjPRRUFEARq7FV+q4PgKq+QebbBgW1RO9uAPytPWR7ETBJc+dalc0DNk6N0DEqzVGVNTQSTDsD6DjV16Wg==
X-Gm-Message-State: AOJu0YwMYXXlgzPF72hD3O6UMqTENV65c+hnOw9xVavzDBB5+mP8Udeo
	dhh54u2uiLgaEmWaK7oTfKMssYwJfb7aOq/CBO+GfgSqo+8YaStO
X-Google-Smtp-Source: AGHT+IF7417dLOb9AFpKux80wGRFphiL96eqkYHuO+HbRsg74O3hREbU4Q5k8Ch5D3+tWfXpDVOFNQ==
X-Received: by 2002:a05:6871:782:b0:21e:e5db:7964 with SMTP id o2-20020a056871078200b0021ee5db7964mr930368oap.23.1709841857835;
        Thu, 07 Mar 2024 12:04:17 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6871:e406:b0:21e:4aab:bcf4 with SMTP id
 py6-20020a056871e40600b0021e4aabbcf4ls1341524oac.2.-pod-prod-09-us; Thu, 07
 Mar 2024 12:04:16 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXR6jkgc3oAL/rdVPcAZTOH4WJVo+Ef4OTgOIsrqd5t0IoPG2P1NWOlLnHRp6MRrlYACaW5Hubb9HzBZvbPVE2V/HRHqBk2pwD3lw==
X-Received: by 2002:a05:6871:5225:b0:21e:7c86:6656 with SMTP id ht37-20020a056871522500b0021e7c866656mr1025204oac.29.1709841856493;
        Thu, 07 Mar 2024 12:04:16 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1709841856; cv=none;
        d=google.com; s=arc-20160816;
        b=bhXka2EKY2pBD9HYdCO0UHCJJ+mBVYt8cCSYvwutW9E8DxF8cxMkroWFoR/Ddfv0eg
         U4wj8KixP6HRDm4h0l4P5NSAjccvjU0CUVevfOSjg2RHMekmZN1NeFGic5lDBFiUwwKt
         M+uMMUX7LpK5GASG2fggFv/lzfzEzg7CIUMPEJrV46ZiYBAJq3LqgEIPkeqLrC7g2aSt
         OtS7SFnWfDInhQ+F2ws83m0jVIGvGfVwTLuGsOs0njFcT9oqxS4IREpiK8xqm1AeKvs/
         4fUp19x3kUqK4Qlq4ZcWoeqE09x7QxxWOvr19zddzXVDvKMWhVQc4YtFrkjQz2che6iR
         1TZA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=SaP0wPXWBZG8b4HRDLlDNgk7gu+I9jcLT+KulgNLYzI=;
        fh=wZkqNn3blphv3zn9bC3my1ToEv0pV0bcwiJQ7Un3s0U=;
        b=LYbZQstT1+wmwnZSVaZ9XtyQzOvi/5e7DK93x9X6wHSV0aZxL4eNDGYDhEg1BwT8lG
         wvgsbCQgG+TiK0Va+sXtvJcGJupu7coj5f7pGv9nxHremdxdo6pYGwzn/rTKPLagC2Zz
         lFzZE7tAwLFnAXrEPuX8cBuzEYqYTraWbJKc9EbqG3mqKPeh/rDpATFM+31r7z1oovWh
         YbyMY72m3HzNz/g7zQkxfCb8F0J3+rwopQIFe8VO8FSHtxjMF2SNfkJF/7B1ZR0z9Guu
         5RPhM8mjghF4bvEoNbv1rG5qKoDIv06ES6JafkUjVpjV+hBTmm23VEh1S0zFnlXEnQvg
         UBHw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=bombadil.20210309 header.b=0zkhqM1U;
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=rdunlap@infradead.org
Received: from bombadil.infradead.org (bombadil.infradead.org. [2607:7c80:54:3::133])
        by gmr-mx.google.com with ESMTPS id c12-20020ac5ca0c000000b004c027d19fd3si1004216vkm.5.2024.03.07.12.04.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 07 Mar 2024 12:04:16 -0800 (PST)
Received-SPF: none (google.com: infradead.org does not designate permitted sender hosts) client-ip=2607:7c80:54:3::133;
Received: from [50.53.50.0] (helo=[192.168.254.15])
	by bombadil.infradead.org with esmtpsa (Exim 4.97.1 #2 (Red Hat Linux))
	id 1riJy9-00000006C66-0IYm;
	Thu, 07 Mar 2024 20:03:57 +0000
Message-ID: <f12e83ef-5881-4df8-87ae-86f8ca5a6ab4@infradead.org>
Date: Thu, 7 Mar 2024 12:03:54 -0800
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v5 37/37] memprofiling: Documentation
Content-Language: en-US
To: Kent Overstreet <kent.overstreet@linux.dev>
Cc: Suren Baghdasaryan <surenb@google.com>, akpm@linux-foundation.org,
 mhocko@suse.com, vbabka@suse.cz, hannes@cmpxchg.org,
 roman.gushchin@linux.dev, mgorman@suse.de, dave@stgolabs.net,
 willy@infradead.org, liam.howlett@oracle.com,
 penguin-kernel@i-love.sakura.ne.jp, corbet@lwn.net, void@manifault.com,
 peterz@infradead.org, juri.lelli@redhat.com, catalin.marinas@arm.com,
 will@kernel.org, arnd@arndb.de, tglx@linutronix.de, mingo@redhat.com,
 dave.hansen@linux.intel.com, x86@kernel.org, peterx@redhat.com,
 david@redhat.com, axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org,
 nathan@kernel.org, dennis@kernel.org, jhubbard@nvidia.com, tj@kernel.org,
 muchun.song@linux.dev, rppt@kernel.org, paulmck@kernel.org,
 pasha.tatashin@soleen.com, yosryahmed@google.com, yuzhao@google.com,
 dhowells@redhat.com, hughd@google.com, andreyknvl@gmail.com,
 keescook@chromium.org, ndesaulniers@google.com, vvvvvv@google.com,
 gregkh@linuxfoundation.org, ebiggers@google.com, ytcoode@gmail.com,
 vincent.guittot@linaro.org, dietmar.eggemann@arm.com, rostedt@goodmis.org,
 bsegall@google.com, bristot@redhat.com, vschneid@redhat.com, cl@linux.com,
 penberg@kernel.org, iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com,
 glider@google.com, elver@google.com, dvyukov@google.com,
 shakeelb@google.com, songmuchun@bytedance.com, jbaron@akamai.com,
 aliceryhl@google.com, rientjes@google.com, minchan@google.com,
 kaleshsingh@google.com, kernel-team@android.com, linux-doc@vger.kernel.org,
 linux-kernel@vger.kernel.org, iommu@lists.linux.dev,
 linux-arch@vger.kernel.org, linux-fsdevel@vger.kernel.org,
 linux-mm@kvack.org, linux-modules@vger.kernel.org,
 kasan-dev@googlegroups.com, cgroups@vger.kernel.org
References: <20240306182440.2003814-1-surenb@google.com>
 <20240306182440.2003814-38-surenb@google.com>
 <10a95079-86e4-41bf-8e82-e387936c437d@infradead.org>
 <hsyclfp3ketwzkebjjrucpb56gmalixdgl6uld3oym3rvssyar@fmjlbpdkrczv>
From: Randy Dunlap <rdunlap@infradead.org>
In-Reply-To: <hsyclfp3ketwzkebjjrucpb56gmalixdgl6uld3oym3rvssyar@fmjlbpdkrczv>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: rdunlap@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=bombadil.20210309 header.b=0zkhqM1U;
       spf=none (google.com: infradead.org does not designate permitted sender
 hosts) smtp.mailfrom=rdunlap@infradead.org
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



On 3/7/24 10:17, Kent Overstreet wrote:
> On Wed, Mar 06, 2024 at 07:18:57PM -0800, Randy Dunlap wrote:
>> Hi,
>> This includes some editing suggestions and some doc build fixes.
>>
>>

[snip]

>>> +===================
>>> +Theory of operation
>>> +===================
>>> +
>>> +Memory allocation profiling builds off of code tagging, which is a library for
>>> +declaring static structs (that typcially describe a file and line number in
>>
>>                                   typically
>>
>>> +some way, hence code tagging) and then finding and operating on them at runtime
>>
>>                                                                         at runtime,
>>
>>> +- i.e. iterating over them to print them in debugfs/procfs.
>>
>>   i.e., iterating
> 
> i.e. latin id est, that is: grammatically my version is fine
> 

Some of my web search hits say that a comma is required after "i.e.".
At least one of them says that it is optional.
And one says that it is not required in British English.

But writing it with "that is":


hence code tagging) and then finding and operating on them at runtime
- that is iterating over them to print them in debugfs/procfs.

is not good IMO. But it's your document.


-- 
#Randy

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/f12e83ef-5881-4df8-87ae-86f8ca5a6ab4%40infradead.org.
