Return-Path: <kasan-dev+bncBC32535MUICBBF4IXOAQMGQEX4MTRSA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x339.google.com (mail-ot1-x339.google.com [IPv6:2607:f8b0:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id 5394331F03C
	for <lists+kasan-dev@lfdr.de>; Thu, 18 Feb 2021 20:46:32 +0100 (CET)
Received: by mail-ot1-x339.google.com with SMTP id v24sf898017ott.17
        for <lists+kasan-dev@lfdr.de>; Thu, 18 Feb 2021 11:46:32 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1613677591; cv=pass;
        d=google.com; s=arc-20160816;
        b=yAPMbTUwUHfWW/9iIgA2+N2TTlKb0+auHqFhSqighDKfUgglnKUYrjpb/CBVKyCFAs
         9eXkvjK80mYfV/ddQpvykbpMK2GOUavQMA/B2OKSbiOCCbcveSbJTHsbOAeHRpZ6bKkk
         VWUr4XRQo2oTtqvzqwNJTfEEcS6/7rqJZnnj5m4U3rnB7X8CVcgtitgRrD5JH3NTeyLD
         6QP4+mYp2WcoU/LLo1SKX5WXx21ctF/B92+WPnnGfvbJ9MBOkYhu6Al02IQAQpHMLQke
         WOXlBu8ml3NKw8/DLcxN+bFc61efxyIcpLy5/Cm7Yo40TwpcW7b0ZaoljYlqr9ffBjMF
         PeSw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:organization:from
         :references:cc:to:subject:sender:dkim-signature;
        bh=GijCOqers0SVzGL60Vz1aoOR+5sRRAkH0mHCBUmQfiY=;
        b=e60MEWqh0gxsOkk4HasXStXmIKpsgxO2/S8Kh6Stxuuf7a5iYQgh+Ul1bgzTL74ouq
         THS71fyBNdQ8UDB+5DR8PoJ30Qzr2Sae7Yteokd3qAWDPxoOoVmLMQMwhbp9khVzbaIB
         dll6orZe9x9WbbZcNmeWYhZf+kw6SGbtUDKUzpids2DJIhZRUsc1l2kWQlbzOW19YUH3
         sE6ndaRrdVD01wVD/V6WXTkB9SuVpyzfXTj3/eMzeYKIEkUe+d9JDtzKxAbhHDpSSwPS
         62/8Fz9VHE/Zq41Vy4wCMePzqBlqnVtNhPYRODQWdDWM1apKQc7py5uTMsNadRHMEDl6
         m7Ow==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=MK360Jwk;
       spf=pass (google.com: domain of david@redhat.com designates 216.205.24.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:organization:message-id:date
         :user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=GijCOqers0SVzGL60Vz1aoOR+5sRRAkH0mHCBUmQfiY=;
        b=HOn11YCoAAuW9vTlDby63yha20F12BGtAFduTIrSQwhFNK3T/fsq1kk17ZTVQmwFay
         wa2B08wFYri2sFojUFuXnlcSODc2jfhTwS4INPZ+amF4+bwEo2C23gFCSpQD/JIDTxEW
         glxcixdxa0Rl9RUB74hS/dvwCgGNBaOL5G7TCmU0zX+Yn1YHhtzMJP2FcMeYVbYwZVvD
         eVZ/QqWMYrw/0vt73QXeEnOy3l7caQEehJ2eJqjcRhS3JgEltZ32evNHWw8P429oHmoU
         GefdOwd8jtoCJOAmvU1fSbHSiZH4oodpQcNAtdPaoLwKf6aN3a4CbRowzNw3LTx/SJca
         aUMQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from
         :organization:message-id:date:user-agent:mime-version:in-reply-to
         :content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=GijCOqers0SVzGL60Vz1aoOR+5sRRAkH0mHCBUmQfiY=;
        b=ceMle/hFDSKGOGXNbGcyZSL1dHBkGa/BF+TLfK1s+bz1mCU2LfKG8oOB0w3jms9ri1
         gv17Q1zaOYlOFaC6GnDQoYXQ35iXX3+y5qj37uegH6n2bwu6MYnxZ+cvpHgdbiUUO86F
         I52TQZOKmErF9sSGo1RNaalXiYy+ib6TF8q8HGfo2VBh9frJs4ANoy6CTXtO6vU0vWVd
         sR3YLgwSSKBBLfu0FKprlbxYHVRu2B4TG0/Tltr5kODvj/IhLicjAl9RRQ3Yw5LPGbDc
         7Qw/AiG9xgSN+KXQZsVfs2Lzj/4Lk8P6XhjG+G4VAny7I01McB8KkijiJeCIYO1dFUkf
         4ExA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5304xZNEsdLgdBTz4COijvWGURsx0q6abAuXjJZh23a5E7oG8RC8
	Vwh9LGLuJSKwJ5JG2d57Gj0=
X-Google-Smtp-Source: ABdhPJx8UxkHmQicyrHFyBD3ZGEKgi/v8aWE/05bczKtMNuOjs4Zvf40xqVagr4Va/+pg9Sq4y3R9A==
X-Received: by 2002:a05:6808:bce:: with SMTP id o14mr3857807oik.104.1613677591192;
        Thu, 18 Feb 2021 11:46:31 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:19f8:: with SMTP id t24ls1646914ott.11.gmail; Thu,
 18 Feb 2021 11:46:30 -0800 (PST)
X-Received: by 2002:a05:6830:1088:: with SMTP id y8mr3986209oto.372.1613677590833;
        Thu, 18 Feb 2021 11:46:30 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1613677590; cv=none;
        d=google.com; s=arc-20160816;
        b=P/uME/l7r7sT63m8sIOB4E87gG6Vk5G9iUS9nYBWRjBHrkXiZxV493fo40p9cmCKWR
         icJ+xLtDiaZH4SqYqbmbEWO70rBTiD6nge3jn5N9HHyKy1mlNozm+wj7rlCG3Ed97Vde
         DA7iNF9MCMZjl70JjK+Cp2+qqLRfcEzt61gCzezXNJa3CQbObe7Q3hNMcduywraU5RRg
         lg8IuoGCOS40TH9xiY9Wo4BhXGjISLbGYd9qvJOYhdFoWwrv6/3F1ucjfo5DOpIy00Do
         N6vra9nT7VFT2VTPF4BBMopz1RLFzW0M12eEqRVHHiOWsA676i7dqu1C3TyXjDw174Kc
         6b9w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:organization:from:references:cc:to
         :subject:dkim-signature;
        bh=+ZmGAzUC+8dwc8omdud3uVAWf0zcvuutIq5VHsAV4q0=;
        b=esrwcAj2Ox0hr3TjSTuL/aSZIWy/tl2H2xSEAj9gy6VHzOTtHY2Q0vKLd500UDOdVz
         Ro4EKZu0qkj5SB3AA7RKSrHBERceShaQsG4KEWlhiSzHqKqFpVR2O76zLp1IACabWuA6
         0bN1QVPQm1Z7dHZ763HN/56uSsHNIBKN49/cMnSxpTl9ElsP8ieYVz1iu3rDuoX/uQYF
         R4K8kEamu9K66vqSWRCXJqzv5pdukao6Ug26NS4RkKOG2gQbMjQqf+fBDD+A7eVm4ogF
         REDp1nnNy9n6o/9sIevEKoy/06DXomZHt9VjCw8wxhm7C+Kl8DOX8izseJI9exmQT+e8
         IsAg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=MK360Jwk;
       spf=pass (google.com: domain of david@redhat.com designates 216.205.24.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [216.205.24.124])
        by gmr-mx.google.com with ESMTPS id z1si439815otm.3.2021.02.18.11.46.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 18 Feb 2021 11:46:30 -0800 (PST)
Received-SPF: pass (google.com: domain of david@redhat.com designates 216.205.24.124 as permitted sender) client-ip=216.205.24.124;
Received: from mimecast-mx01.redhat.com (mimecast-mx01.redhat.com
 [209.132.183.4]) (Using TLS) by relay.mimecast.com with ESMTP id
 us-mta-601-55MMnnLmMF2NSFx3LYxoGg-1; Thu, 18 Feb 2021 14:46:25 -0500
X-MC-Unique: 55MMnnLmMF2NSFx3LYxoGg-1
Received: from smtp.corp.redhat.com (int-mx07.intmail.prod.int.phx2.redhat.com [10.5.11.22])
	(using TLSv1.2 with cipher AECDH-AES256-SHA (256/256 bits))
	(No client certificate requested)
	by mimecast-mx01.redhat.com (Postfix) with ESMTPS id B8721C297;
	Thu, 18 Feb 2021 19:46:22 +0000 (UTC)
Received: from [10.36.114.59] (ovpn-114-59.ams2.redhat.com [10.36.114.59])
	by smtp.corp.redhat.com (Postfix) with ESMTP id AB0E410016DB;
	Thu, 18 Feb 2021 19:46:18 +0000 (UTC)
Subject: Re: [PATCH] mm, kasan: don't poison boot memory
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>,
 Catalin Marinas <catalin.marinas@arm.com>,
 Vincenzo Frascino <vincenzo.frascino@arm.com>,
 Dmitry Vyukov <dvyukov@google.com>,
 George Kennedy <george.kennedy@oracle.com>,
 Konrad Rzeszutek Wilk <konrad@darnok.org>, Will Deacon
 <will.deacon@arm.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>,
 Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>,
 Peter Collingbourne <pcc@google.com>, Evgenii Stepanov <eugenis@google.com>,
 Branislav Rankov <Branislav.Rankov@arm.com>,
 Kevin Brodsky <kevin.brodsky@arm.com>, Christoph Hellwig
 <hch@infradead.org>, kasan-dev <kasan-dev@googlegroups.com>,
 Linux ARM <linux-arm-kernel@lists.infradead.org>,
 Linux Memory Management List <linux-mm@kvack.org>,
 LKML <linux-kernel@vger.kernel.org>
References: <487751e1ccec8fcd32e25a06ce000617e96d7ae1.1613595269.git.andreyknvl@google.com>
 <e58cbb53-5f5b-42ae-54a0-e3e1b76ad271@redhat.com>
 <CAAeHK+x2OwXXR-ci9Z+g=O6ZivM+LegxwkrpTqJLy2AZ9iW7-g@mail.gmail.com>
From: David Hildenbrand <david@redhat.com>
Organization: Red Hat GmbH
Message-ID: <509c1c80-bb2c-0c5c-ffa3-939ca40d2646@redhat.com>
Date: Thu, 18 Feb 2021 20:46:17 +0100
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101
 Thunderbird/78.7.0
MIME-Version: 1.0
In-Reply-To: <CAAeHK+x2OwXXR-ci9Z+g=O6ZivM+LegxwkrpTqJLy2AZ9iW7-g@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Language: en-US
X-Scanned-By: MIMEDefang 2.84 on 10.5.11.22
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=MK360Jwk;
       spf=pass (google.com: domain of david@redhat.com designates
 216.205.24.124 as permitted sender) smtp.mailfrom=david@redhat.com;
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

On 18.02.21 20:40, Andrey Konovalov wrote:
> On Thu, Feb 18, 2021 at 9:55 AM David Hildenbrand <david@redhat.com> wrote:
>>
>> On 17.02.21 21:56, Andrey Konovalov wrote:
>>> During boot, all non-reserved memblock memory is exposed to the buddy
>>> allocator. Poisoning all that memory with KASAN lengthens boot time,
>>> especially on systems with large amount of RAM. This patch makes
>>> page_alloc to not call kasan_free_pages() on all new memory.
>>>
>>> __free_pages_core() is used when exposing fresh memory during system
>>> boot and when onlining memory during hotplug. This patch adds a new
>>> FPI_SKIP_KASAN_POISON flag and passes it to __free_pages_ok() through
>>> free_pages_prepare() from __free_pages_core().
>>>
>>> This has little impact on KASAN memory tracking.
>>>
>>> Assuming that there are no references to newly exposed pages before they
>>> are ever allocated, there won't be any intended (but buggy) accesses to
>>> that memory that KASAN would normally detect.
>>>
>>> However, with this patch, KASAN stops detecting wild and large
>>> out-of-bounds accesses that happen to land on a fresh memory page that
>>> was never allocated. This is taken as an acceptable trade-off.
>>>
>>> All memory allocated normally when the boot is over keeps getting
>>> poisoned as usual.
>>>
>>> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
>>> Change-Id: Iae6b1e4bb8216955ffc14af255a7eaaa6f35324d
>>
>> Not sure this is the right thing to do, see
>>
>> https://lkml.kernel.org/r/bcf8925d-0949-3fe1-baa8-cc536c529860@oracle.com
>>
>> Reversing the order in which memory gets allocated + used during boot
>> (in a patch by me) might have revealed an invalid memory access during boot.
>>
>> I suspect that that issue would no longer get detected with your patch,
>> as the invalid memory access would simply not get detected. Now, I
>> cannot prove that :)
> 
> This looks like a good example.
> 
> Ok, what we can do is:
> 
> 1. For KASAN_GENERIC: leave everything as is to be able to detect
> these boot-time bugs.
> 
> 2. For KASAN_SW_TAGS: remove boot-time poisoning via
> kasan_free_pages(), but use the "invalid" tag as the default shadow
> value. The end result should be the same: bad accesses will be
> detected. For unallocated memory as it has the default "invalid" tag,
> and for allocated memory as it's poisoned properly when
> allocated/freed.
> 
> 3. For KASAN_HW_TAGS: just remove boot-time poisoning via
> kasan_free_pages(). As the memory tags have a random unspecified
> value, we'll still have a 15/16 chance to detect a memory corruption.
> 
> This also makes sense from the performance perspective: KASAN_GENERIC
> isn't meant to be running in production, so having a larger perf
> impact is acceptable. The other two modes will be faster.

Sounds in principle sane to me.

Side note: I am not sure if anybody runs KASAN in production. Memory is 
expensive. Feel free to prove me wrong, I'd be very interest in actual 
users.

-- 
Thanks,

David / dhildenb

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/509c1c80-bb2c-0c5c-ffa3-939ca40d2646%40redhat.com.
