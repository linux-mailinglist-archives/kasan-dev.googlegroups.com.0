Return-Path: <kasan-dev+bncBC32535MUICBBJ45W6YAMGQENVO5QMA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73c.google.com (mail-qk1-x73c.google.com [IPv6:2607:f8b0:4864:20::73c])
	by mail.lfdr.de (Postfix) with ESMTPS id 8AC2D897B06
	for <lists+kasan-dev@lfdr.de>; Wed,  3 Apr 2024 23:48:25 +0200 (CEST)
Received: by mail-qk1-x73c.google.com with SMTP id af79cd13be357-78a6dd7a9e7sf30853485a.2
        for <lists+kasan-dev@lfdr.de>; Wed, 03 Apr 2024 14:48:25 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1712180904; cv=pass;
        d=google.com; s=arc-20160816;
        b=i4p12hiqjkaC5p5tnvVfI78UBfviEtrTn5nQNxq89whoWBAkzJ7d1rqEWLxY0r94Sl
         xuAHn1n0bKcMxP+2pVrUV4GbDR3xTdtqLoQ5UZ/dsQMQrVdIdylBTybrkhrEhfnTkTY/
         8W1mKx2wB/3bhUQtaayf02clEBPYHz0yzH+4ITJYfETLB6tjhoAlRSoRZx21MDsDln6+
         p1NH5DZEkzzB3HFHDkYH7Sp7ktBTojNf+tN3qCsiMBj5atsNPO3SvuUcsUpuZ5dw/7up
         roK1/n77VIafz0YDAYLzdu4OPmAeHr85fPah9Nq0/Ca2dajw6s7WrjT3HDzChhGyqXSk
         EECQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :organization:autocrypt:from:references:cc:to:subject:user-agent
         :mime-version:date:message-id:sender:dkim-signature;
        bh=X4kAEWC/ZTmi2p4PZ7az0cK6GY0M4pOoVXtgG1HKxpc=;
        fh=HQcy3blLjwh1asc3XSXx5hxSWQcUgP7M9MWiUPujug0=;
        b=vh6R/PE6Z62Blwc3kpQhVOiaX2VVw4IAIbKi5GC69IxHKt9SmT+Was4dtftogyxsbd
         N0khL5jDvYgqU291678/Lvuer5Vf7CuOBLqfM0CRpGwX5wz/zfQ0cDwYIa+Tnm/S1YiC
         60G76eo+aXiGb3yIoX9mLciXX3N53cyajLZWruREiaHQZxY+RjmXpsoOBZUMgIuhzBG4
         Bg1JlzZDHwiZl5TTNIkh2ym0mTbBIPwEEOS4fmllMTickR6OmCYsbaLjmqHyBvuO1Xk4
         yCviJR6Yj/+bwviQv05ovDMw65RB5eNXtJ17o9gHbMdZOAc6XzDXpk6ZaSDVnGq3vWUg
         t7Xg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=SxPsjq6F;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1712180904; x=1712785704; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-language:in-reply-to:organization
         :autocrypt:from:references:cc:to:subject:user-agent:mime-version
         :date:message-id:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=X4kAEWC/ZTmi2p4PZ7az0cK6GY0M4pOoVXtgG1HKxpc=;
        b=PWPpT/3jrv9tYEDTBm6l0/2gHuNJ0xuYuZHhiSDmzILl4hUS1Rhj1FsxmudqaRIYG4
         RT7eWqSkjfeghdr09OMpJ5jOb6DzMH9KdWwS7YJ3fq315Odw636Cd3OaI8gfp6/c3MfR
         Gug82XZS8xsRTGyiwMmiJ1rwZlbLR4AT/bUVYuo6jBXGnQyJuLn2wbrz2pOXCGmAIp3y
         01qceK6R7xrcPvaofXvvfxNwvE13WjIzayWRUGxnHrmWJ8TlXZzFOxLzywmuHe7oGqvA
         vKC7hE4YrrtZISvKpZQVCyY7DNpmLybhLO0J6AflDfxZVwTtaXrZdHLh+/jhkpXoxw/A
         2tig==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1712180904; x=1712785704;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-language:in-reply-to:organization:autocrypt:from:references
         :cc:to:subject:user-agent:mime-version:date:message-id:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=X4kAEWC/ZTmi2p4PZ7az0cK6GY0M4pOoVXtgG1HKxpc=;
        b=SSZYS/VqYxwuLYY9liqa+dztWv+DpGCo1T3zKcmuQAUyts3lRa3tfJ6Q8FvNgH8P0U
         fNpmDoN53bTm2M1J/ypRUArLInaubrZ9C+mI7+O8DbOt9KRwahJ1piS6FtWZ8zoVg7qT
         zbO6fqi3l9tPy2VzYfdVK89fT5i5cfgDu+es6o76qcHMHk07Ac5U6rn8wf4tQ/t4sFhn
         GW+GDH6rRZ0VjruenZ2eR7vhDvRa3kM1uIHIMcBklfD9ZFyRKSONrNLI/RcV1tZbmD5y
         P4Y55DU2ubWLGR7k3EZ0aymQ1O3wP8DDrQAxDvJYsYUgfbAdT15h5LeApq3Gj7L0EYBF
         ubTg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWgje8E1CyhPpuOkhwQu1s22eupoCgq6uh3Q5wTvCjEWFwYNCbv6FF0Wi5ew/plmcktbjnatpyclnNr2L9De86WqebSTDDuAg==
X-Gm-Message-State: AOJu0YwVigm+jxxbErOFHqjxKeJIU6tcrZDeqY0aNIHemz4QxVjRtyrD
	OVsZAaJSQlPzaVNqbL+RhWqJHc0Ek3jLuey78g506lueHp/e9MIKVlo=
X-Google-Smtp-Source: AGHT+IGdnSHLNn0DSuL5FMtzeQfKG9wryLwZtrjYdyNuPiYN5IQVlmvy9cJ+KnxoypiFcaAjQ8TTdQ==
X-Received: by 2002:a05:6214:2261:b0:699:2f15:d694 with SMTP id gs1-20020a056214226100b006992f15d694mr519394qvb.28.1712180904141;
        Wed, 03 Apr 2024 14:48:24 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:e8a:b0:698:ecf4:6ea5 with SMTP id
 hf10-20020a0562140e8a00b00698ecf46ea5ls399365qvb.2.-pod-prod-06-us; Wed, 03
 Apr 2024 14:48:23 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVhebwgmXnnaoetQUtTCl0afEEwkGYRkLfATfmi3J9EwQtxorZvtDnf6i3tLHnGHzWerIgrZDr3OONOIYpDVQnaBS9OafgZ11jQMQ==
X-Received: by 2002:a05:6122:251c:b0:4da:9a90:a6f2 with SMTP id cl28-20020a056122251c00b004da9a90a6f2mr679068vkb.10.1712180902567;
        Wed, 03 Apr 2024 14:48:22 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1712180902; cv=none;
        d=google.com; s=arc-20160816;
        b=QMW2cV3eBoEphpNJJEVJmFr6k9iEZT/p1fWArMEtVjtFL88zt4oUqRGK1cY2UswJHO
         rlAqdDHhirrV42HOHDe9aMLRObBJtNNbHUPE00If54+zBhwHgLNUZil4OSPA6JuBadZ1
         1MwbRbTBXExOGpTqKCDEqJNUt9L2M9yCC+OzgmzNDT9mjDI3/b4oBLbjjRD7fqRhs+Ys
         Fxx/thxEfo1VIkyPm/sAIW+aGrwWauyH4lecoDENmzP4duENIv/yfAUgvjkYfz+TJ9vc
         z7S0rrZA/Pu6o69KOmeI6O3kxBzbOfO5dhkG0uS/WrzeQTIz0XScU3N2FkiXoUvc7rbn
         +XOQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:organization
         :autocrypt:from:references:cc:to:subject:user-agent:mime-version
         :date:message-id:dkim-signature;
        bh=LM3COUWIzPT7dnAZypNco51j1yiA/TG+7IxlzkxR5z4=;
        fh=A88/c9avSU/nTjdM/0sXmLutLlcHtDbmGCToX4egYFw=;
        b=WdTJpHoxmYpZgQjSpX5bJ6JmarF3zBKF1WfBF1GDHM4RtZhAIQubcLl0ePUg3KviMH
         z+PyC9ItinHSfx380zzSVDoztHTFaq7BrmUuBMit53WrtqJXdZE30FWXFjO8G5l02kWh
         zlV1HUgTuySSHE+cD9R22AQobIldyw8MZfMSIVBzXYMOpCMkxSGEk69UiR3Cy/O4QbK/
         cGYwgkZAgVsHFeu0gbF6X0VBbreBMnYpgBOzY99L6Ru39VUizYB0jf45OYpo4EwHAAxS
         oNEsHKRwFzA1PEbVHF7beTwbMQvx1snnudkRHwCJiyofzrgL0PQXvfT3Lk+KFi0dmj+1
         ZCtw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=SxPsjq6F;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id ce31-20020a056122411f00b004d32e96f356si674955vkb.4.2024.04.03.14.48.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 03 Apr 2024 14:48:22 -0700 (PDT)
Received-SPF: pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mail-wr1-f71.google.com (mail-wr1-f71.google.com
 [209.85.221.71]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384) id
 us-mta-59-iHtRN8sRNhSoiRE4TnOBog-1; Wed, 03 Apr 2024 17:48:17 -0400
X-MC-Unique: iHtRN8sRNhSoiRE4TnOBog-1
Received: by mail-wr1-f71.google.com with SMTP id ffacd0b85a97d-3435b7d65efso162432f8f.1
        for <kasan-dev@googlegroups.com>; Wed, 03 Apr 2024 14:48:17 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWu+3tixBa+RSsM0CA7dGigHBVJsjHB6/uFH+64qba+LEyW9MGNMu7pQHB354UNnSzIaWoHJapVCITAMwEhmG/Vg1fMZDcraaSFsQ==
X-Received: by 2002:adf:f58e:0:b0:343:6ffe:7a64 with SMTP id f14-20020adff58e000000b003436ffe7a64mr563199wro.59.1712180896599;
        Wed, 03 Apr 2024 14:48:16 -0700 (PDT)
X-Received: by 2002:adf:f58e:0:b0:343:6ffe:7a64 with SMTP id f14-20020adff58e000000b003436ffe7a64mr563157wro.59.1712180896166;
        Wed, 03 Apr 2024 14:48:16 -0700 (PDT)
Received: from ?IPV6:2003:cb:c73b:3100:2d28:e0b7:1254:b2f6? (p200300cbc73b31002d28e0b71254b2f6.dip0.t-ipconnect.de. [2003:cb:c73b:3100:2d28:e0b7:1254:b2f6])
        by smtp.gmail.com with ESMTPSA id bx6-20020a5d5b06000000b00341e67a7a90sm18519899wrb.19.2024.04.03.14.48.13
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 03 Apr 2024 14:48:15 -0700 (PDT)
Message-ID: <9e2d09f8-2234-42f3-8481-87bbd9ad4def@redhat.com>
Date: Wed, 3 Apr 2024 23:48:12 +0200
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v6 01/37] fix missing vmalloc.h includes
To: Kent Overstreet <kent.overstreet@linux.dev>,
 Nathan Chancellor <nathan@kernel.org>
Cc: Suren Baghdasaryan <surenb@google.com>, akpm@linux-foundation.org,
 mhocko@suse.com, vbabka@suse.cz, hannes@cmpxchg.org,
 roman.gushchin@linux.dev, mgorman@suse.de, dave@stgolabs.net,
 willy@infradead.org, liam.howlett@oracle.com,
 penguin-kernel@i-love.sakura.ne.jp, corbet@lwn.net, void@manifault.com,
 peterz@infradead.org, juri.lelli@redhat.com, catalin.marinas@arm.com,
 will@kernel.org, arnd@arndb.de, tglx@linutronix.de, mingo@redhat.com,
 dave.hansen@linux.intel.com, x86@kernel.org, peterx@redhat.com,
 axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org, dennis@kernel.org,
 jhubbard@nvidia.com, tj@kernel.org, muchun.song@linux.dev, rppt@kernel.org,
 paulmck@kernel.org, pasha.tatashin@soleen.com, yosryahmed@google.com,
 yuzhao@google.com, dhowells@redhat.com, hughd@google.com,
 andreyknvl@gmail.com, keescook@chromium.org, ndesaulniers@google.com,
 vvvvvv@google.com, gregkh@linuxfoundation.org, ebiggers@google.com,
 ytcoode@gmail.com, vincent.guittot@linaro.org, dietmar.eggemann@arm.com,
 rostedt@goodmis.org, bsegall@google.com, bristot@redhat.com,
 vschneid@redhat.com, cl@linux.com, penberg@kernel.org,
 iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com, glider@google.com,
 elver@google.com, dvyukov@google.com, songmuchun@bytedance.com,
 jbaron@akamai.com, aliceryhl@google.com, rientjes@google.com,
 minchan@google.com, kaleshsingh@google.com, kernel-team@android.com,
 linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org,
 iommu@lists.linux.dev, linux-arch@vger.kernel.org,
 linux-fsdevel@vger.kernel.org, linux-mm@kvack.org,
 linux-modules@vger.kernel.org, kasan-dev@googlegroups.com,
 cgroups@vger.kernel.org
References: <20240321163705.3067592-1-surenb@google.com>
 <20240321163705.3067592-2-surenb@google.com>
 <20240403211240.GA307137@dev-arch.thelio-3990X>
 <4qk7f3ra5lrqhtvmipmacgzo5qwnugrfxn5dd3j4wubzwqvmv4@vzdhpalbmob3>
From: David Hildenbrand <david@redhat.com>
Autocrypt: addr=david@redhat.com; keydata=
 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
 WNyWQQ==
Organization: Red Hat
In-Reply-To: <4qk7f3ra5lrqhtvmipmacgzo5qwnugrfxn5dd3j4wubzwqvmv4@vzdhpalbmob3>
X-Mimecast-Spam-Score: 0
X-Mimecast-Originator: redhat.com
Content-Language: en-US
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=SxPsjq6F;
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

On 03.04.24 23:41, Kent Overstreet wrote:
> On Wed, Apr 03, 2024 at 02:12:40PM -0700, Nathan Chancellor wrote:
>> On Thu, Mar 21, 2024 at 09:36:23AM -0700, Suren Baghdasaryan wrote:
>>> From: Kent Overstreet <kent.overstreet@linux.dev>
>>>
>>> The next patch drops vmalloc.h from a system header in order to fix
>>> a circular dependency; this adds it to all the files that were pulling
>>> it in implicitly.
>>>
>>> Signed-off-by: Kent Overstreet <kent.overstreet@linux.dev>
>>> Signed-off-by: Suren Baghdasaryan <surenb@google.com>
>>> Reviewed-by: Pasha Tatashin <pasha.tatashin@soleen.com>
>>
>> I bisected an error that I see when building ARCH=loongarch allmodconfig
>> to commit 302519d9e80a ("asm-generic/io.h: kill vmalloc.h dependency")
>> in -next, which tells me that this patch likely needs to contain
>> something along the following lines, as LoongArch was getting
>> include/linux/sizes.h transitively through the vmalloc.h include in
>> include/asm-generic/io.h.
> 
> gcc doesn't appear to be packaged for loongarch for debian (most other
> cross compilers are), so that's going to make it hard for me to test
> anything...

The latest cross-compilers from Arnd [1] include a 13.2.0 one for 
loongarch64 that works for me. Just in case you haven't heard of Arnds 
work before and want to give it a shot.

[1] https://mirrors.edge.kernel.org/pub/tools/crosstool/

-- 
Cheers,

David / dhildenb

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/9e2d09f8-2234-42f3-8481-87bbd9ad4def%40redhat.com.
