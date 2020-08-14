Return-Path: <kasan-dev+bncBCS37NMQ3YHBBFPX3P4QKGQE2XXTUEA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x439.google.com (mail-wr1-x439.google.com [IPv6:2a00:1450:4864:20::439])
	by mail.lfdr.de (Postfix) with ESMTPS id 98EF1244F6C
	for <lists+kasan-dev@lfdr.de>; Fri, 14 Aug 2020 23:01:10 +0200 (CEST)
Received: by mail-wr1-x439.google.com with SMTP id e14sf3747889wrr.7
        for <lists+kasan-dev@lfdr.de>; Fri, 14 Aug 2020 14:01:10 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1597438869; cv=pass;
        d=google.com; s=arc-20160816;
        b=M0+XaF7Jlnt0J3dZXPzQHc4IQzNbR25ExDtXpFMdMp7EfANDQTMfcHw9v4kmy7Sysf
         W55cBAyRsKFmDztoPNmS84RDppLxAdKOGc8R8QJfJlY98PyCUZiXIRv495H08qReNM2v
         ZouW5gjwm4c6d5s1Kaa9AYOs0A6+inDFq59YkftpuKtxt9oDMSMcClXjwyV7DHNXyf8W
         IaZNHYSOEmxZ+iMBiNEmPSyDD4/aqCt7qN+cXUd+c7G86CvJ2cK1Z0MOt8xTA8wD/LXk
         uWRNVyRKegrVQ1w6hEogC80lk2MUxPfbUSpq0atbv788opmS0ofUAhdE2+Ccmk8mwQrX
         qfGQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:autocrypt:from:references
         :cc:to:subject:reply-to:sender:dkim-signature;
        bh=D1ilQvYJOxhIu+UkX7us7PyFgoLaCBs4wWx+X8aBeJg=;
        b=R3dGfFPQG6LNMl+VKrhdI5umH96eQQDZ1CI814VX3dmwuWDZTBUUvoSr8fK3r+kBm+
         n3y+n3qWEVe1JTnCfIzOm9Z3fKQvgD+4FhzgJICxRH6/oO05UcgHsKOF9Qi/GGI999Du
         ZSIyvAGBXxz40yaHCVcx6tlDlplkhaobIiyIinpTYdGm2foIT7YoRoL3r2A38f6Fq03O
         KU3jnvCWVeY7SP8NhpdTGUT9X5+zpHT8Okev/vD11PiNA2fVOER47h3Jwl8U8rGfEWY3
         az/sfuROYklYmIkaPCLvmM8WQEAzELMcmZK47lmTJNO2M2XG4XL2z+mEPCdq0RZNHlKJ
         BIgg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of a13xp0p0v88@gmail.com designates 209.85.221.66 as permitted sender) smtp.mailfrom=a13xp0p0v88@gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:reply-to:subject:to:cc:references:from:autocrypt:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=D1ilQvYJOxhIu+UkX7us7PyFgoLaCBs4wWx+X8aBeJg=;
        b=kqKoi5rQz/PadktqSJK+gpm2/6DCtqh41SaPlrnMOkJxXyaezvh3JsX4AVRSJPkEF0
         AHOkth482ovU/qNgzn8XUVEGW5ksHhcW4V9KTCvA/VrtSUNFDZL912PGW4Ph3HFBCPO8
         Ra9rtQd37EcNq5WCQGvXPU5d1IY6Q5OBWUVwrlV6mdPENXPo5LGHeQUuC6N+/v/if6dS
         PePUYTO/q8IC0P5V4TrENjNJa/OoDZwgMH9Mk7pMhcq1NYeIBeYEelSc4ai6BNVhYFY3
         PKJoSJ5hWWuyKSn7TBpDAsjwTG7ldIu/dwibZts5XI2LzkvSF0KGI+iywG64Au5Ogmyz
         znmw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:reply-to:subject:to:cc:references:from
         :autocrypt:message-id:date:user-agent:mime-version:in-reply-to
         :content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=D1ilQvYJOxhIu+UkX7us7PyFgoLaCBs4wWx+X8aBeJg=;
        b=fk8Gw2G9NDrE9PptrbxyWX5wFv/csKx48jYpSqd96wtwY23oYS1VI5ZLyT6g7Uek3E
         ed4sZm6grYBO5wxjRVE7RUz4Xts6v2Zni1gF1bcWBMRDNGXYwPDhO+bisvNxtOxWJk8p
         +rTOli666kug9MyobmIZkvA5Hn402SeoEym0hByezAFzxcLN9xR0FN9rVn2HcxbuTyx5
         WAdfWPEQmTi23hB7JMd0ZeXo5Ah5CD/bQLsThoDGHopnx1IEc4tvIo8Sznz4inRjpxpr
         o1F1EZqguI4tw9FnUS0k/95WGuWAH9tEL51R71kfX72hn8N2BXVaV3DGz6D/Ggb5PzqS
         FUxA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531wasDRprJvhceokXK51Qf+iGY9OaPjc5lWboMd8BFRK/7aCynY
	m9EKMubGtPyt0uaJT8I3pEE=
X-Google-Smtp-Source: ABdhPJw30I/HFv7NIVXJ/aMim3RRAxJ62jxvt2IuRhHbPa1bBgZa2g9yb4M9LOQiVbH6+4fdopHJfw==
X-Received: by 2002:a7b:c197:: with SMTP id y23mr4226060wmi.165.1597438869324;
        Fri, 14 Aug 2020 14:01:09 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:e78f:: with SMTP id n15ls66930wrm.1.gmail; Fri, 14 Aug
 2020 14:01:08 -0700 (PDT)
X-Received: by 2002:adf:b312:: with SMTP id j18mr4343743wrd.142.1597438868877;
        Fri, 14 Aug 2020 14:01:08 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1597438868; cv=none;
        d=google.com; s=arc-20160816;
        b=YxnuPEcDGuWxUprrBOOL1Df+IBHqpsgOWNpbN0bxb9YifMIIIELs1GKhWgJ4KwF/ek
         sZBOEdF3pbkYSPhXleuzhMMCKWpsAF4q+mseDjfzyZZjCXBxkeVhL9oRSqyJqZUnNwgp
         PTPciIWMcNBHhg14lJ5KYeUUvAEfm1bptcR826OOmSZ8dJABf6BnIJFdv5C+21y+9d8A
         d9gZjuY4dhei6JAqI368+l2bFxJrjqRQbF6dTwBK6HzASV7IVgFSapbs6KAPC6fdSa3j
         um2Ry3mj5HJzrcxqhZIhcFNnyVutdvNDs2Qx0CpiPOvHlEjR1a26ZRTceP2R4+m4FiYE
         9dzw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:autocrypt:from:references:cc:to:subject
         :reply-to;
        bh=pG3PD5q7lYnvp9GuLkcW6/Z3cuMbx52ESrO1Q4ZBpJ0=;
        b=AB8w53aKaU70q9ivrQAzyjAO3n1Nf3l093lzkBmGMuikQXAW4oHVjEFZMpBjQaL2zl
         i3QzOV72z6TL4puTqhvs/O7Zvme0oqq5mvIqcpHlAzZxV2Ab37xOfiSYhWsFq73TDKH8
         /SEPoUngyqHH0BjMc/Bnolxbtp6d+aMhLubyEX8gETvJaoan61MzNOneIsUXulf0WFYO
         vt4HeG6P+c/KB3WnRdTGyoY4Hm9cDKAl41vzsT/uMn2cYjiJfk52qIU61ejR5TT6aaGn
         FATUvWTSifJZLcVTKylCeBeLMe0eJcmOWz3/b4hl9pLraJpF4Ra3Y+WxB0+icfZ6o6J2
         2SfA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of a13xp0p0v88@gmail.com designates 209.85.221.66 as permitted sender) smtp.mailfrom=a13xp0p0v88@gmail.com
Received: from mail-wr1-f66.google.com (mail-wr1-f66.google.com. [209.85.221.66])
        by gmr-mx.google.com with ESMTPS id j83si944417wmj.0.2020.08.14.14.01.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 14 Aug 2020 14:01:08 -0700 (PDT)
Received-SPF: pass (google.com: domain of a13xp0p0v88@gmail.com designates 209.85.221.66 as permitted sender) client-ip=209.85.221.66;
Received: by mail-wr1-f66.google.com with SMTP id p20so9470625wrf.0
        for <kasan-dev@googlegroups.com>; Fri, 14 Aug 2020 14:01:08 -0700 (PDT)
X-Received: by 2002:a5d:6646:: with SMTP id f6mr4180198wrw.155.1597438868343;
        Fri, 14 Aug 2020 14:01:08 -0700 (PDT)
Received: from [10.9.0.18] ([185.248.161.177])
        by smtp.gmail.com with ESMTPSA id r11sm17017268wrw.78.2020.08.14.14.01.04
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 14 Aug 2020 14:01:07 -0700 (PDT)
Reply-To: alex.popov@linux.com
Subject: Re: [PATCH RFC 0/2] Break heap spraying needed for exploiting
 use-after-free
To: Kees Cook <keescook@chromium.org>, Jann Horn <jannh@google.com>,
 Will Deacon <will@kernel.org>, Andrey Ryabinin <aryabinin@virtuozzo.com>,
 Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>,
 Christoph Lameter <cl@linux.com>, Pekka Enberg <penberg@kernel.org>,
 David Rientjes <rientjes@google.com>, Joonsoo Kim <iamjoonsoo.kim@lge.com>,
 Andrew Morton <akpm@linux-foundation.org>,
 Masahiro Yamada <masahiroy@kernel.org>,
 Masami Hiramatsu <mhiramat@kernel.org>, Steven Rostedt
 <rostedt@goodmis.org>, Peter Zijlstra <peterz@infradead.org>,
 Krzysztof Kozlowski <krzk@kernel.org>,
 Patrick Bellasi <patrick.bellasi@arm.com>,
 David Howells <dhowells@redhat.com>, Eric Biederman <ebiederm@xmission.com>,
 Johannes Weiner <hannes@cmpxchg.org>, Laura Abbott <labbott@redhat.com>,
 Arnd Bergmann <arnd@arndb.de>,
 Greg Kroah-Hartman <gregkh@linuxfoundation.org>, kasan-dev@googlegroups.com,
 linux-mm@kvack.org, kernel-hardening@lists.openwall.com,
 linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>,
 Alexander Popov <alex.popov@linux.com>
Cc: notify@kernel.org
References: <20200813151922.1093791-1-alex.popov@linux.com>
From: Alexander Popov <alex.popov@linux.com>
Autocrypt: addr=alex.popov@linux.com; prefer-encrypt=mutual; keydata=
 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
 j3lCqPk=
Message-ID: <4bc8bb86-613b-1217-6804-cb21a3356bff@linux.com>
Date: Sat, 15 Aug 2020 00:01:03 +0300
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.10.0
MIME-Version: 1.0
In-Reply-To: <20200813151922.1093791-1-alex.popov@linux.com>
Content-Type: text/plain; charset="UTF-8"
Content-Language: en-US
X-Original-Sender: a13xp0p0v88@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of a13xp0p0v88@gmail.com designates 209.85.221.66 as
 permitted sender) smtp.mailfrom=a13xp0p0v88@gmail.com
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

On 13.08.2020 18:19, Alexander Popov wrote:
> Hello everyone! Requesting for your comments.
> 
> Use-after-free vulnerabilities in the Linux kernel are very popular for
> exploitation. A few examples:
>  https://googleprojectzero.blogspot.com/2018/09/a-cache-invalidation-bug-in-linux.html
>  https://googleprojectzero.blogspot.com/2019/11/bad-binder-android-in-wild-exploit.html?m=1
>  https://a13xp0p0v.github.io/2020/02/15/CVE-2019-18683.html
> 
> Use-after-free exploits usually employ heap spraying technique.
> Generally it aims to put controlled bytes at a predetermined memory
> location on the heap. Heap spraying for exploiting use-after-free in
> the Linux kernel relies on the fact that on kmalloc(), the slab allocator
> returns the address of the memory that was recently freed. So allocating
> a kernel object with the same size and controlled contents allows
> overwriting the vulnerable freed object.
> 
> I've found an easy way to break heap spraying for use-after-free
> exploitation. I simply extracted slab freelist quarantine from KASAN
> functionality and called it CONFIG_SLAB_QUARANTINE. Please see patch 1.
> 
> If this feature is enabled, freed allocations are stored in the quarantine
> and can't be instantly reallocated and overwritten by the exploit
> performing heap spraying.
> 
> In patch 2 you can see the lkdtm test showing how CONFIG_SLAB_QUARANTINE
> prevents immediate reallocation of a freed heap object.
> 
> I tested this patch series both for CONFIG_SLUB and CONFIG_SLAB.
> 
> CONFIG_SLAB_QUARANTINE disabled:
>   # echo HEAP_SPRAY > /sys/kernel/debug/provoke-crash/DIRECT
>   lkdtm: Performing direct entry HEAP_SPRAY
>   lkdtm: Performing heap spraying...
>   lkdtm: attempt 0: spray alloc addr 00000000f8699c7d vs freed addr 00000000f8699c7d
>   lkdtm: freed addr is reallocated!
>   lkdtm: FAIL! Heap spraying succeed :(
> 
> CONFIG_SLAB_QUARANTINE enabled:
>   # echo HEAP_SPRAY > /sys/kernel/debug/provoke-crash/DIRECT
>   lkdtm: Performing direct entry HEAP_SPRAY
>   lkdtm: Performing heap spraying...
>   lkdtm: attempt 0: spray alloc addr 000000009cafb63f vs freed addr 00000000173cce94
>   lkdtm: attempt 1: spray alloc addr 000000003096911f vs freed addr 00000000173cce94
>   lkdtm: attempt 2: spray alloc addr 00000000da60d755 vs freed addr 00000000173cce94
>   lkdtm: attempt 3: spray alloc addr 000000000b415070 vs freed addr 00000000173cce94
>   ...
>   lkdtm: attempt 126: spray alloc addr 00000000e80ef807 vs freed addr 00000000173cce94
>   lkdtm: attempt 127: spray alloc addr 00000000398fe535 vs freed addr 00000000173cce94
>   lkdtm: OK! Heap spraying hasn't succeed :)
> 
> I did a brief performance evaluation of this feature.
> 
> 1. Memory consumption. KASAN quarantine uses 1/32 of the memory.
> CONFIG_SLAB_QUARANTINE disabled:
>   # free -m
>                 total        used        free      shared  buff/cache   available
>   Mem:           1987          39        1862          10          86        1907
>   Swap:             0           0           0
> CONFIG_SLAB_QUARANTINE enabled:
>   # free -m
>                 total        used        free      shared  buff/cache   available
>   Mem:           1987         140        1760          10          87        1805
>   Swap:             0           0           0
> 
> 2. Performance penalty. I used `hackbench -s 256 -l 200 -g 15 -f 25 -P`.
> CONFIG_SLAB_QUARANTINE disabled (x86_64, CONFIG_SLUB):
>   Times: 3.088, 3.103, 3.068, 3.103, 3.107
>   Mean: 3.0938
>   Standard deviation: 0.0144
> CONFIG_SLAB_QUARANTINE enabled (x86_64, CONFIG_SLUB):
>   Times: 3.303, 3.329, 3.356, 3.314, 3.292
>   Mean: 3.3188 (+7.3%)
>   Standard deviation: 0.0223
> 
> I would appreciate your feedback!

While waiting for the feedback on these RFC patches, I compiled a list of topics
for further research:

 - Possible ways to overwrite a quarantined heap object by making a large amount
of allocations (with/without freeing them)

 - How init_on_free=1 affects heap spraying on a system with the heap quarantine

 - How releasing batches of quarantine objects right away affects heap spraying
reliability

 - Heap spraying on multi-core systems with the heap quarantine

 - More precise performance evaluation

 - Possible ways to improve the security properties and performance results
(KASAN quarantine has some interesting settings)

Best regards,
Alexander

> Alexander Popov (2):
>   mm: Extract SLAB_QUARANTINE from KASAN
>   lkdtm: Add heap spraying test
> 
>  drivers/misc/lkdtm/core.c  |   1 +
>  drivers/misc/lkdtm/heap.c  |  40 ++++++++++++++
>  drivers/misc/lkdtm/lkdtm.h |   1 +
>  include/linux/kasan.h      | 107 ++++++++++++++++++++-----------------
>  include/linux/slab_def.h   |   2 +-
>  include/linux/slub_def.h   |   2 +-
>  init/Kconfig               |  11 ++++
>  mm/Makefile                |   3 +-
>  mm/kasan/Makefile          |   2 +
>  mm/kasan/kasan.h           |  75 +++++++++++++-------------
>  mm/kasan/quarantine.c      |   2 +
>  mm/kasan/slab_quarantine.c |  99 ++++++++++++++++++++++++++++++++++
>  mm/slub.c                  |   2 +-
>  13 files changed, 258 insertions(+), 89 deletions(-)
>  create mode 100644 mm/kasan/slab_quarantine.c
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/4bc8bb86-613b-1217-6804-cb21a3356bff%40linux.com.
