Return-Path: <kasan-dev+bncBC7OBJGL2MHBBB6PUSWQMGQEXSYDM2I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x938.google.com (mail-ua1-x938.google.com [IPv6:2607:f8b0:4864:20::938])
	by mail.lfdr.de (Postfix) with ESMTPS id A2E55831A91
	for <lists+kasan-dev@lfdr.de>; Thu, 18 Jan 2024 14:28:40 +0100 (CET)
Received: by mail-ua1-x938.google.com with SMTP id a1e0cc1a2514c-7d0aca89b4bsf1510438241.1
        for <lists+kasan-dev@lfdr.de>; Thu, 18 Jan 2024 05:28:40 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1705584519; cv=pass;
        d=google.com; s=arc-20160816;
        b=oxkHidDWsHbbaXAhIZuMKv/OciRN7xwAEBLTIFGBfQQ84T7R/biKtcaK+eFKurmpHS
         CHXt0p1G7urkYUSr82uLnfT/vMpEurZrOXPOC5Hb4xV0aTWvnd+ptsO1rNMBKfOxJSLm
         /86epYI2X5ZDQQurFcUeS8eFY2E+LjQV+p1uxWWZzmOo58WwFCCsiAPeGo69gFjGIVBC
         J7QJoU38ONDZEzGhDyR+ZJdzg5aJdxU39blEKW6z3EL94833CMAluMBqMvrYS9GzGIF1
         zka2nObjQWkG2HezNE2ilezy7yUGtOl15fnepLBD8PYbCIcVKnT+ihy0TWt3vO9aAIap
         cmdw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=0wQ4QlnULRraLV3GVh7sgt8Oro2uowsnKeOJFGEey/w=;
        fh=HxySodumoCiF33ZjhHfI/MbRuE1Mpc2GF5AfDRN+S90=;
        b=tQXuo0LoV0xrnlVJ2dk5eCAofh0S4G0x01AuYonCF1fZSfLx1MeMdcbqFUMeol8fcj
         fOULxsFlYfiPmtPaHJccIoWq+oaOIRUKmzdaCbZl5CU+OUvkCMyo84FZXkg53Y5PDxiX
         AaZFn/ys8zWI2MkRihUhDV+Xzl/zsGhz9WOqwhrzbzlzi7a5S4ikrHK5r1wLFB0eqB6i
         xRPUoYU4+MeLJUQ5OGo/JZqOv8UDw4QYvRhMOVvwYcAthsn9hC/yHzdZhX2QTpZ/HNAX
         2vGHCGhtB9uM7cCPdLCdJq9Enm0viKKRkGzZQEXY2GgI8mryZtjcANhZ9hX6ojCHWNNK
         mJXA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="NKnI/MHR";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::a32 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1705584519; x=1706189319; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=0wQ4QlnULRraLV3GVh7sgt8Oro2uowsnKeOJFGEey/w=;
        b=YvOFs2p7Kr8WjhmlAFwFCnUNx1hKBdozgwoJM4iZ3MJb+jjKuxUkk8pH3CsQf1DTVP
         QWwMYwJCQLxFaiv8iKJFg2jcW4p7ob4rv728sRMaBHOx3rmJU3O4D7SlLxEoZFYZXP3M
         2QDp0vhg7UN1CPIdvLHN098YnDG0FIdWYlOYhzZBlE5vjHcx10cVXyzGGPKDOU+6rr1K
         AFY0BzUBbQZg97Aq3LwQ/+MfPBgKFglXfD/xNdZ3Smdvc6wsDRbCWySQQTDD6GsPCZBx
         kIkyPP6Q1tISm8mCujNbOUO56KQXiv+dg+2kk1Qz3dexrcoWNI2pxxQ1VHVdveCw1cxl
         eWbA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1705584519; x=1706189319;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=0wQ4QlnULRraLV3GVh7sgt8Oro2uowsnKeOJFGEey/w=;
        b=nwazpGhHlYlMPVSUuSHXGldCX4jysNHsmy/5NUBu8SyyGpBAHkozQI5ojep1IQJq71
         mNp4hF1wbau09FxIVf5b3SVf3TINkR7CaXPsm5gRviLi++8osefpoJKZTyvZx4aOUGHR
         xIFwZEPjPzna89t2xfKeZLvTBUfyYIJxRLVL6gpPzaJUniZVbcgPaaZyf7NfXRhaNIz9
         UeOXnEgrN9EsvWePGrTnOdLw/Qa/abKioCQ6Xfq/rFXZwa/n2dGF6/FRDB8R02o5RBwD
         thBOvXQBF2meFdFOWzD+Pra78UL//Q/nsql1Y9HQ+BtKh+jrt3OOiyee+lR7XdynXn3n
         QpVw==
X-Gm-Message-State: AOJu0YznNjUcDwyGRvg/IB0kcEKioT09/7tHvCUJF3nyUUdEs/zifS4C
	uJtbt8nuKx3/BhlYSJ94huL+ofohPuHeeQoXnFUG58X3GkU8iwAG
X-Google-Smtp-Source: AGHT+IH8+vO3DgsyfVKJ4EJ+0bwu5NYJrCckkGP9ve4WAwuALwF9bC8MEFeQQgTUpetkS5AuvpgL4A==
X-Received: by 2002:a05:6122:31a9:b0:4b8:2179:3a98 with SMTP id ch41-20020a05612231a900b004b821793a98mr657023vkb.12.1705584519297;
        Thu, 18 Jan 2024 05:28:39 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:48c:b0:67f:476:d152 with SMTP id
 pt12-20020a056214048c00b0067f0476d152ls4932674qvb.0.-pod-prod-04-us; Thu, 18
 Jan 2024 05:28:38 -0800 (PST)
X-Received: by 2002:a05:6122:17a1:b0:4b6:d49f:c228 with SMTP id o33-20020a05612217a100b004b6d49fc228mr671460vkf.26.1705584518610;
        Thu, 18 Jan 2024 05:28:38 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1705584518; cv=none;
        d=google.com; s=arc-20160816;
        b=TnUs59I3Kdc/9Og0VI5MznY0KmpsXOoVhQXrNOEFryaSKGnZaxlj9nqOcLhy968qUi
         imN6pZKH6lrVpMH14RZZxZZgoEAo44m3AIStrKrCAlMcfvW9jd8qGi6AcoCct3j23zgP
         2P0C32xzPdA7u30wJCZVzzCKQNfNkPbMNY12b76J1SvaJZTNAM+7n6LTTSrFN6EqhRKf
         /TzGSvVjbkzchzxX5vB6JOq3W6KvwDVYpUINg9mvOeMB2LEceYhGZ2KtrgwTcV9CdbDU
         TakzDP5qG9COFLuQbUWS4M/S2mSd+6W7d80nEPCp2/aqJApHLiRsQkYz12BGvTysPN0W
         EuEA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=MEsDDpNSu2lCDsHRoNgjF4HiSiukKKXSzyfx5Mkvc6o=;
        fh=HxySodumoCiF33ZjhHfI/MbRuE1Mpc2GF5AfDRN+S90=;
        b=sas3y6e3H+poWKXxegU6MsMhApn+c30O+TWMLQd4wGHJc9Z7mHMJz+xcC2ZkfzUcfY
         v+kfMOij6b9IQoWCxJeKHZvmrpYYKbl4bqJoBk1ZS3UKcypywi+B+GAUxwJ9tOMEi1D4
         OaQHjP1tBdY8xW1GRTcUC06eOGQ4OqIOL5YNL0hQl36WEcw/6Hyv3jPzHZikpeBLwmlG
         nmT4N7MhFrLwhmjRd3rAhBqlKKZr/5vK6r9pOA7Fxd66Hc76QK0RoLBK6FkcOOgcDTCM
         nU1xA+s6SRiuOFPrIJdyGL4i9JhOAaK2Cpqs6UMePpW48kWL9QlL8eXsPcR69+V3A/04
         oBRQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="NKnI/MHR";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::a32 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-vk1-xa32.google.com (mail-vk1-xa32.google.com. [2607:f8b0:4864:20::a32])
        by gmr-mx.google.com with ESMTPS id n64-20020a1fd643000000b004b2e6e4330asi1916417vkg.1.2024.01.18.05.28.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 18 Jan 2024 05:28:38 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::a32 as permitted sender) client-ip=2607:f8b0:4864:20::a32;
Received: by mail-vk1-xa32.google.com with SMTP id 71dfb90a1353d-4baf7b0a002so156560e0c.1
        for <kasan-dev@googlegroups.com>; Thu, 18 Jan 2024 05:28:38 -0800 (PST)
X-Received: by 2002:a05:6122:a02:b0:4b7:40fe:3114 with SMTP id
 2-20020a0561220a0200b004b740fe3114mr654124vkn.2.1705584518179; Thu, 18 Jan
 2024 05:28:38 -0800 (PST)
MIME-Version: 1.0
References: <20240118124109.37324-1-lizhe.67@bytedance.com>
In-Reply-To: <20240118124109.37324-1-lizhe.67@bytedance.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 18 Jan 2024 14:28:00 +0100
Message-ID: <CANpmjNOnxvGNtApe50vyAZLmoNbEpLeMiKHXRuRABkn6nhEQWA@mail.gmail.com>
Subject: Re: [RFC 0/2] kasan: introduce mem track feature
To: lizhe.67@bytedance.com
Cc: ryabinin.a.a@gmail.com, glider@google.com, andreyknvl@gmail.com, 
	dvyukov@google.com, vincenzo.frascino@arm.com, akpm@linux-foundation.org, 
	kasan-dev@googlegroups.com, linux-mm@kvack.org, lizefan.x@bytedance.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b="NKnI/MHR";       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::a32 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Thu, 18 Jan 2024 at 13:41, lizhe.67 via kasan-dev
<kasan-dev@googlegroups.com> wrote:
>
> From: Li Zhe <lizhe.67@bytedance.com>
>
> 1. Problem
> ==========
> KASAN is a tools for detecting memory bugs like out-of-bounds and
> use-after-free. In Generic KASAN mode, it use shadow memory to record
> the accessible information of the memory. After we allocate a memory
> from kernel, the shadow memory corresponding to this memory will be
> marked as accessible.
> In our daily development, memory problems often occur. If a task
> accidentally modifies memory that does not belong to itself but has
> been allocated, some strange phenomena may occur. This kind of problem
> brings a lot of trouble to our development, and unluckily, this kind of
> problem cannot be captured by KASAN. This is because as long as the
> accessible information in shadow memory shows that the corresponding
> memory can be accessed, KASAN considers the memory access to be legal.
>
> 2. Solution
> ===========
> We solve this problem by introducing mem track feature base on KASAN
> with Generic KASAN mode. In the current kernel implementation, we use
> bits 0-2 of each shadow memory byte to store how many bytes in the 8
> byte memory corresponding to the shadow memory byte can be accessed.
> When a 8-byte-memory is inaccessible, the highest bit of its
> corresponding shadow memory value is 1. Therefore, the key idea is that
> we can use the currently unused four bits 3-6 in the shadow memory to
> record relevant track information. Which means, we can use one bit to
> track 2 bytes of memory. If the track bit of the shadow mem corresponding
> to a certain memory is 1, it means that the corresponding 2-byte memory
> is tracked. By adding this check logic to KASAN's callback function, we
> can use KASAN's ability to capture allocated memory corruption.

Note: "track" is already an overloaded word with KASAN, meaning some
allocation/free stack trace info + CPU id, task etc.

> 3. Simple usage
> ===========
> The first step is to mark the memory as tracked after the allocation is
> completed.
> The second step is to remove the tracked mark of the memory before the
> legal access process and re-mark the memory as tracked after finishing
> the legal access process.

It took me several readings to understand what problem you're actually
trying to solve. AFAIK, you're trying to add custom poison/unpoison
functions.

From what I can tell this is duplicating functionality: it is
perfectly legal to poison and unpoison memory while it is already
allocated. I think it used to be the case the kasan_poison/unpoison()
were API functions, but since tag-based KASAN modes this was changed
to hide the complexity here.

But you could simply expose a simpler variant of kasan_{un,}poison,
e.g. kasan_poison/unpoison_custom(). You'd have to introduce another
type (see where KASAN_PAGE_FREE, KASAN_SLAB_FREE is defined) to
distinguish this custom type from other poisoned memory.

Obviously it would be invalid to kasan_poison_custom() memory that is
already poisoned, because that would discard the pre-existing poison
type.

With that design, I believe it would also work for the inline version
of KASAN and not just outline version.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNOnxvGNtApe50vyAZLmoNbEpLeMiKHXRuRABkn6nhEQWA%40mail.gmail.com.
