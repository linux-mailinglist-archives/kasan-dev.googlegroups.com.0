Return-Path: <kasan-dev+bncBC5NR65V5ACBBKOGZKYAMGQEWFHSFEA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x140.google.com (mail-lf1-x140.google.com [IPv6:2a00:1450:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id 32C7389B250
	for <lists+kasan-dev@lfdr.de>; Sun,  7 Apr 2024 15:44:11 +0200 (CEST)
Received: by mail-lf1-x140.google.com with SMTP id 2adb3069b0e04-516da5d2043sf1109675e87.3
        for <lists+kasan-dev@lfdr.de>; Sun, 07 Apr 2024 06:44:11 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1712497450; cv=pass;
        d=google.com; s=arc-20160816;
        b=p0UXGBmXYmZjheRK7QbNCNOms/rkOIcijyyMLjHSoU/EKAeRT4Dge4VXBOFYN6qAtj
         Ze4IAyJQj9zzLjNfwl7cFCJiWDHpZZXpEjTMlcS06EioLTWRv62+/SBcvYN0s2zphUYl
         A6HIMZPvP8gF2AT3lGgG5C+UdyQAZbCCe0JgeHM0P2FW5fZNDGX5+bGeAVXH197zjVmj
         8DcUxcfGkJa2nreIz9IfhBSDXqAGXQUsf6XAddO7PiwEbkDgFhiyodk2Cmt9rPC7XjUZ
         XKvpjOQBPkOCdJPfomrz1YKMokcin1dbKV5MdL/kUiaygzp03VqgCD3jia+0iUqvQRvj
         xH2w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature:dkim-signature;
        bh=z/rIh4QnTQjwRNCxGmVOlXpHG4FDiES1m+Gfe7WWHss=;
        fh=S/2L1sRhnzclfOy97buovAxyucxPQDvT7wWcy8d4MyQ=;
        b=Waoi7xtZRY1CLlCX46uppzzrQzUEdWPrBYDledATVqLvhtLC7RBcg21RQxmukZeZgz
         J/1TzHAl25PRTzxgmFmTHc2sgEtsYvSQTHAEdcGi3kw5q6v8EpuYPUWdxO3hNqwZ0W2M
         movvYvLMi2PHyrT2gosP308+cozHvffkmou+vIZTbuAYHzk4afYnLnm7G2unOUq3zQjM
         Z64oj2c8E1Bbe+8cP6FemAG7z60xv12v9xHhr2wZiXlI6hDHXgVHH8xfrwEUtK9h2WdO
         zFueQ9N8+dUZ0KA3OqCqAMQexBTjtaFTzR4J5Uio/59QbA3EjO4N1tEYQ7Ws82rhiY6m
         se/A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=CUIIblOM;
       spf=pass (google.com: domain of klarasmodin@gmail.com designates 2a00:1450:4864:20::12d as permitted sender) smtp.mailfrom=klarasmodin@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1712497450; x=1713102250; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:content-language:references:cc
         :to:subject:user-agent:mime-version:date:message-id:sender:from:to
         :cc:subject:date:message-id:reply-to;
        bh=z/rIh4QnTQjwRNCxGmVOlXpHG4FDiES1m+Gfe7WWHss=;
        b=iSDWPkKPWVhh7vGjF2XPNn65DwWouR+1+YsPzKwBsCynCZU8SZsAkCPxSoyLqBO/O+
         pzx3lTaOwYz9Sgcn0mIixKxkSlqDQNxFuvQEKBtNQrJYQUUBrTfHaH+4zHQ8GUWDX0V1
         vD5+cDtfG2oMIc4x96Qx5meAXJPQDYVteRNCzzWbRqqjuJQMOiszXVWnf+9Jf7KG8rGz
         0EhNTmT2YGsXCUT/va76F+BkI99DJZXSLLEOzOOpVIPTC3iB4+VB0wncE6fsr82rzVb4
         V3egKKaHeoAATN4QFFjwx77VLjUkI4d9ozl76gl/6WXqSEh0DQ3DeHilc86/1I9+yMsF
         hgaQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1712497450; x=1713102250; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:content-language:references:cc
         :to:subject:user-agent:mime-version:date:message-id:from:to:cc
         :subject:date:message-id:reply-to;
        bh=z/rIh4QnTQjwRNCxGmVOlXpHG4FDiES1m+Gfe7WWHss=;
        b=PSGuBF7j+/I7BMrnkpJFtl/Mqs4A0kepsxF5aWJAOLNY61X342Cw7d+wTm0VmGZjVU
         QqXOtPEwz4XN3FDQDEsPxJDZRYJWsqtfABIdac0Yc5QUPxBKJmqIZVoqwhQ80jAtKnq7
         AcWdhqZofPAbcq6lxUr7JYkc8EGOBmgLyocsseVnH4L0PKuiQEUD6dR2e6nEp2Lpbfry
         sjNgqN2X7yzKD7Ltnyb0ydmXm47Qoyfnp/2j92qTqw4fUuvmMtdnEEpVnSUaRJ+M5faa
         5SxVLO54PujuwFuvRVow5noXRQ4DiXjr7A+NOPTGvFXftTU8LnmSrqa5wTgpLcemno2d
         XjcA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1712497450; x=1713102250;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:content-language:references:cc:to:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=z/rIh4QnTQjwRNCxGmVOlXpHG4FDiES1m+Gfe7WWHss=;
        b=ZEPdUjvvn38ZFDb/oW74HPzDxXsR/xWrDS7SUt8UXQ9UW0DnbXX7O/XpScaPt2e9wZ
         9wvoCZbzuWTXlW7nyyTCfQtrOvXuu1BigLAMUEDZgc+kxoU02U72p5GK23AgXuBAnRd8
         vsTwQfWNj+OWrhrEMoKyLjO6nSe+YL9/UKL91stno2+O52I2rNpswPZV0abIKZAsGv2B
         nRmjQIgDpViWvSqJjq/lEDfhws0mhaokBvVPJzV/U7DbuUk3Tk46HEFu8wjZSP6/l2Gd
         VzST/kBt/3NVAgEDRu5OxRsTkCxz96m9V2x7Bm+VPISdIIK0BBXN6eYFNtktz2fzp07x
         6Mqw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWdelSujiwo1ViUz5PU3ufh7zADvI5nKGE5wV8sla5u4NSzdv8eu6YOCMzFxs82li2qAArsA+RW/VK3ik7PSiAbiFrqIF4Qug==
X-Gm-Message-State: AOJu0Yz8ZHwUH13aKMBGH+K6CIJmlLln7BkN40TzwXRS2F8kOslc4wHV
	3O/VU0hIbded1aargN9XqeAmiyn+L1MOUqG6qWzeFM5hyyhKvKrP
X-Google-Smtp-Source: AGHT+IEinNe2dsfGUzUDkEQgaSRgMEvlGKQrnI+qK/qzwXZYxZn97nGZk4s2vPais36sjQAtrOPVRQ==
X-Received: by 2002:a05:6512:b8e:b0:513:cc18:d4c6 with SMTP id b14-20020a0565120b8e00b00513cc18d4c6mr6729533lfv.41.1712497449266;
        Sun, 07 Apr 2024 06:44:09 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:7512:0:b0:516:be08:884 with SMTP id y18-20020a197512000000b00516be080884ls85290lfe.0.-pod-prod-05-eu;
 Sun, 07 Apr 2024 06:44:07 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUFg/EdpDc/byfSH5XFxWRM4x3+yv9OV07MDxdFXbbYGNJ72ktd9Xw7qT+KA0AliOp0wPsk8RtoSCaGGiKgNAM4tRclbPW9uybjXg==
X-Received: by 2002:a2e:b162:0:b0:2d8:75df:6163 with SMTP id a2-20020a2eb162000000b002d875df6163mr3317597ljm.17.1712497447250;
        Sun, 07 Apr 2024 06:44:07 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1712497447; cv=none;
        d=google.com; s=arc-20160816;
        b=IZ89HfY98JT/ezxkyMzS+XDJ5U8DdTMKcGmTB94GlVmK4U6DzVleZgjyI2LfQWPq5U
         nKDyCquYQAu24P/tiIaxlx775frfbViUb5gZsnHjdKwgcc+43I5tPWMUgwaiNx6pNTcl
         AMDWfTAk2YUnpFp9B4pHjaH5K9H2uLO4kJb1okPTQCQLnSDsFzrRPJkaDS8ZzrDRSBmO
         fPJjpUFeNByCaphUJ7zzc3UvKNrMWEtw/9ZAk7aWaxXf4EYZeWZt7L5WAX+g7hxnkVhv
         Lqk2x7SBHqeB4JlsWXUZVI1JJTJHgdi2dxZ3QsHaw0qsAFn5sLTHFW5r/cIm4xF8A2So
         +amQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=vMqdQCAzDlHOX8MsoDGfkIgox0Bxd5XntMdzXg60cqY=;
        fh=XwExqUXUxrRPgRxphna7FSZ6lco6A2lJGzx3UWHUoYQ=;
        b=SChSsgAOtopWGPrnOhNa1GwPymkPvdCzYxLcpkhNLbK0mfUQobBAf5z/bsfROVaZcs
         PXNDWHubAbiXix0r9c3LqTTjfJmO1FgnYzL+RDHA0SzWTejKl6E05j16J2q8kszlBB/3
         ZxpEtM0SoeBMhMwD8UmxWpZ14rHR3SfuMhGNVfnNgl3NlGtCeAzXN4UzHkHejGHhvi8u
         1uV1YA3ALyam9sUTP1lTECqROgDT44jo7/jROXuX2PJZypGcCTHYr7gw4qmijx4sRl8B
         9LMRmIzX1WmyZfAorDsAY+kVrikYwNjwELg07MDyQ/FCAFak93UYpLHYawZvL4g/iWEG
         RaRw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=CUIIblOM;
       spf=pass (google.com: domain of klarasmodin@gmail.com designates 2a00:1450:4864:20::12d as permitted sender) smtp.mailfrom=klarasmodin@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-lf1-x12d.google.com (mail-lf1-x12d.google.com. [2a00:1450:4864:20::12d])
        by gmr-mx.google.com with ESMTPS id b3-20020a2e9883000000b002d85301f1dfsi141861ljj.2.2024.04.07.06.44.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 07 Apr 2024 06:44:07 -0700 (PDT)
Received-SPF: pass (google.com: domain of klarasmodin@gmail.com designates 2a00:1450:4864:20::12d as permitted sender) client-ip=2a00:1450:4864:20::12d;
Received: by mail-lf1-x12d.google.com with SMTP id 2adb3069b0e04-51381021af1so5731649e87.0
        for <kasan-dev@googlegroups.com>; Sun, 07 Apr 2024 06:44:07 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCX9xz2Yvs2F0Auzj0OtW7kwtbIlc9/V8sN1009WEpyj6yhDYn3LEWuFhNY6sW0r8Y4YoflZBliX1S5MnKvp7bS4EtP0u85cCgtO7g==
X-Received: by 2002:a19:ee19:0:b0:516:cc2f:41d4 with SMTP id g25-20020a19ee19000000b00516cc2f41d4mr5209382lfb.25.1712497446573;
        Sun, 07 Apr 2024 06:44:06 -0700 (PDT)
Received: from ?IPV6:2001:678:a5c:1202:2659:d6e4:5d55:b864? (soda.int.kasm.eu. [2001:678:a5c:1202:2659:d6e4:5d55:b864])
        by smtp.gmail.com with ESMTPSA id n5-20020a056512310500b00516cd482c44sm799770lfb.198.2024.04.07.06.44.04
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 07 Apr 2024 06:44:06 -0700 (PDT)
Message-ID: <acfdf9d8-630b-41d1-9ae0-b3b6442df82c@gmail.com>
Date: Sun, 7 Apr 2024 15:44:03 +0200
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v6 13/37] lib: add allocation tagging support for memory
 allocation profiling
To: Kent Overstreet <kent.overstreet@linux.dev>
Cc: Suren Baghdasaryan <surenb@google.com>, akpm@linux-foundation.org,
 mhocko@suse.com, vbabka@suse.cz, hannes@cmpxchg.org,
 roman.gushchin@linux.dev, mgorman@suse.de, dave@stgolabs.net,
 willy@infradead.org, liam.howlett@oracle.com,
 penguin-kernel@i-love.sakura.ne.jp, corbet@lwn.net, void@manifault.com,
 "Peter Zijlstra (Intel)" <peterz@infradead.org>, juri.lelli@redhat.com,
 catalin.marinas@arm.com, will@kernel.org, arnd@arndb.de, tglx@linutronix.de,
 mingo@redhat.com, dave.hansen@linux.intel.com, x86@kernel.org,
 peterx@redhat.com, david@redhat.com, axboe@kernel.dk, mcgrof@kernel.org,
 masahiroy@kernel.org, Nathan Chancellor <nathan@kernel.org>,
 dennis@kernel.org, jhubbard@nvidia.com, tj@kernel.org,
 muchun.song@linux.dev, rppt@kernel.org, paulmck@kernel.org,
 pasha.tatashin@soleen.com, yosryahmed@google.com, yuzhao@google.com,
 David Howells <dhowells@redhat.com>, hughd@google.com, andreyknvl@gmail.com,
 keescook@chromium.org, ndesaulniers@google.com, vvvvvv@google.com,
 gregkh@linuxfoundation.org, ebiggers@google.com, ytcoode@gmail.com,
 vincent.guittot@linaro.org, dietmar.eggemann@arm.com, rostedt@goodmis.org,
 bsegall@google.com, bristot@redhat.com, vschneid@redhat.com, cl@linux.com,
 penberg@kernel.org, iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com,
 glider@google.com, elver@google.com, dvyukov@google.com,
 songmuchun@bytedance.com, jbaron@akamai.com, aliceryhl@google.com,
 rientjes@google.com, minchan@google.com, kaleshsingh@google.com,
 kernel-team@android.com, linux-doc@vger.kernel.org,
 linux-kernel@vger.kernel.org, iommu@lists.linux.dev,
 linux-arch@vger.kernel.org, linux-fsdevel@vger.kernel.org,
 linux-mm@kvack.org, linux-modules@vger.kernel.org,
 kasan-dev@googlegroups.com, cgroups@vger.kernel.org
References: <6b8149f3-80e6-413c-abcb-1925ecda9d8c@gmail.com>
 <76nf3dl4cqptqv5oh54njnp4rizot7bej32fufjjtreizzcw3w@rkbjbgujk6pk>
Content-Language: en-US, sv-SE
From: Klara Modin <klarasmodin@gmail.com>
In-Reply-To: <76nf3dl4cqptqv5oh54njnp4rizot7bej32fufjjtreizzcw3w@rkbjbgujk6pk>
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: klarasmodin@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=CUIIblOM;       spf=pass
 (google.com: domain of klarasmodin@gmail.com designates 2a00:1450:4864:20::12d
 as permitted sender) smtp.mailfrom=klarasmodin@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On 2024-04-06 23:47, Kent Overstreet wrote:
> On Fri, Apr 05, 2024 at 03:54:45PM +0200, Klara Modin wrote:
>> Hi,
>>
>> On 2024-03-21 17:36, Suren Baghdasaryan wrote:
>>> Introduce CONFIG_MEM_ALLOC_PROFILING which provides definitions to easily
>>> instrument memory allocators. It registers an "alloc_tags" codetag type
>>> with /proc/allocinfo interface to output allocation tag information when
>>> the feature is enabled.
>>> CONFIG_MEM_ALLOC_PROFILING_DEBUG is provided for debugging the memory
>>> allocation profiling instrumentation.
>>> Memory allocation profiling can be enabled or disabled at runtime using
>>> /proc/sys/vm/mem_profiling sysctl when CONFIG_MEM_ALLOC_PROFILING_DEBUG=n.
>>> CONFIG_MEM_ALLOC_PROFILING_ENABLED_BY_DEFAULT enables memory allocation
>>> profiling by default.
>>>
>>> Signed-off-by: Suren Baghdasaryan <surenb@google.com>
>>> Co-developed-by: Kent Overstreet <kent.overstreet@linux.dev>
>>> Signed-off-by: Kent Overstreet <kent.overstreet@linux.dev>
>>
>> With this commit (9e2dcefa791e9d14006b360fba3455510fd3325d in
>> next-20240404), randconfig with KCONFIG_SEED=0xE6264236 fails to build
>> with the attached error. The following patch fixes the build error for me,
>> but I don't know if it's correct.
> 
> Looks good - if you sound out an official patch I'll ack it.
> 

I gave it a try and sent out a patch [1]. This is my first time doing 
that and it's likely not without mistakes.

1. 
https://lore.kernel.org/lkml/20240407133252.173636-1-klarasmodin@gmail.com/T/#u

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/acfdf9d8-630b-41d1-9ae0-b3b6442df82c%40gmail.com.
