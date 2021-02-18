Return-Path: <kasan-dev+bncBC32535MUICBB56WXCAQMGQEALPX2VQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43f.google.com (mail-pf1-x43f.google.com [IPv6:2607:f8b0:4864:20::43f])
	by mail.lfdr.de (Postfix) with ESMTPS id E86CA31E7B1
	for <lists+kasan-dev@lfdr.de>; Thu, 18 Feb 2021 09:55:20 +0100 (CET)
Received: by mail-pf1-x43f.google.com with SMTP id q187sf1011472pfc.7
        for <lists+kasan-dev@lfdr.de>; Thu, 18 Feb 2021 00:55:20 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1613638519; cv=pass;
        d=google.com; s=arc-20160816;
        b=J8r7LLCx86MG9iHKqDDSMifyc1IBD9mXbCO6DLqeXlsASBdZf8frPtdhku0EyamWVn
         GH+A7n28Nj8pjzoblNId8E4cYEoG4RbOa2sseLTrBL6R4+4EOO46fQEDwsnqrsuB5aOF
         tg9nvDCKWpjh4KJYrRI10DT1pw3qmQbgi+FCRMwZsAJXrx4FfRxuKBNAfv62ZA9Pikzr
         SfuCQBmadb+/fJXh8Rt4XeSRQ+A6Hw6P6KL4XM4kzcX14PxHp5joBGUWyoUhttAxLCFT
         nmokfNnHgd8gQpyUTdYYmFcImC2JQOyX0ElBncuxa4YPGxUxp/Jed1Ah5AqvAWVBDx0y
         +jLw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:organization:from
         :references:cc:to:subject:sender:dkim-signature;
        bh=cxtGPJ+zgb4S+FPieEeruB/S8AUw9OK4U3Tmg9uL/Zw=;
        b=TUGfIwTQMwIKAwoRloRy/TvNs7wAINTPDZAUxlC7AU06+9GrLBWa3Pfb4sY2Yx3j27
         9qRerEK31fv81MkMvBkbHL5P/o/purGUZHmJLfp6xEw3fklbSWn69Qcm4uvhXUWlQwb3
         Ajwqkb2puXvS0LMhYXglhi6TWbF2pwWX4iZIu7IY3AZUnTJ4xW+BI+snYe0rLunAZ2CB
         3FtiAwiwjwICYt4w2ZQooFpLJIdcAkD+oEBz3XzxBPnmM4ez0mdUaqCfk1nhzBsuJwWs
         37i42K3qpDVbY3XGPx+8zFyv9ZPyODt6BTNaWRTITamGbaOXx29sd2dr8+W85PRKgudx
         lIoA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=MLxzsSEV;
       spf=pass (google.com: domain of david@redhat.com designates 63.128.21.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:organization:message-id:date
         :user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=cxtGPJ+zgb4S+FPieEeruB/S8AUw9OK4U3Tmg9uL/Zw=;
        b=N/4jq14YUR5bKhFPbXaUjcXrU/bepo691iUZ0PcvpHeY2RNsgQYvQnN0bmo7jMO7ou
         xRYJ6AutgYE1CbvD4+yBk4UXp6p1IInkopyajkwm9JjoNsSCPGdMyhrug/wE1hVc+4Sw
         aSYSMpQbp/JjfFME3lM2GNAvnMHaLLCORJ79ww8EVCJWc7QE3T2wFjIOfqb8j+vRuyyS
         qNOpH7rcTGNXxFlINhz2RC+AOxhFpEzzPlm8Pbp0wnFUSlMGSKrNxem8DLVb+AgOn00D
         43Ia0DBCnkhnWAboduhULRbQfwdGeE6VM62TUlOu1ENwjgux800TPO4HaJorUFto3O++
         4Fmg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from
         :organization:message-id:date:user-agent:mime-version:in-reply-to
         :content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=cxtGPJ+zgb4S+FPieEeruB/S8AUw9OK4U3Tmg9uL/Zw=;
        b=WhdXdMW9dYLt+XGDC0NyFtPHidvAdV2jnBUUsOlP1R1bd0qWQdANagS77kvlk7oXgp
         xnhyLz1Ep/tvzbu4or8wDEgrSstol1ehgW5J6+lxkOSUlXjrnOBUJfmRw0D+A5T8enfG
         OfFwfr4RExK+gfiZEaJgjn7GMiujvhBSKTFr6XCYsUMoPvJWuFqVX9YZRgdgGerLHR+G
         BYau3YFFBMy7qATxV0NVfPM1SiUz+VYIK5e6xGaVtfloPPZcUE4Ds8T+RuK/FuJxWyI0
         rrn4Vh8sKbhdqFlQc6t+fD1DNk5q+krsNGQ0/iz1C3R7xE7LPzu1IesQgsXGRhNMRXQ/
         CYKg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533+faAhVfnizSLWG2Ck9u9zHesX5O9bpNRgcYkxbli467DESFYD
	GZNEwx3e8oEMC+IfYYJlwVc=
X-Google-Smtp-Source: ABdhPJz23hEOIIA7cxfS8fzB+bJyua1peZ8N2SiBtGEd0YLtxb+jFu9v8Y2Xxzxoaly+tJOKWBgkoA==
X-Received: by 2002:a17:90b:4c43:: with SMTP id np3mr476648pjb.33.1613638519694;
        Thu, 18 Feb 2021 00:55:19 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:4b8f:: with SMTP id lr15ls2902297pjb.3.gmail; Thu,
 18 Feb 2021 00:55:19 -0800 (PST)
X-Received: by 2002:a17:90a:f492:: with SMTP id bx18mr3141039pjb.53.1613638518971;
        Thu, 18 Feb 2021 00:55:18 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1613638518; cv=none;
        d=google.com; s=arc-20160816;
        b=hBdA42ItSV1R9FsohUS8aN6K5SWaPMvxYheChcX/ayB+wDIYP/QGKJN+YkYk0WVuj5
         WK+tuCMFXnx+S9dd4aojfPEv6OSCXwqYFwtXQCT8cVnPsOPO1e/nrpAW4vzBX9FJ3HZt
         pZZi2PxZmUSQQMzLWaDQlgwDN70gFXqC5GT03lYBoflK/ME2NW7chZEsfRoQ3HmM72lf
         AcYmOC+jiZs6jp533H4AB2srumzHShoJtUILRuWFBEyawl1Za2uMgK7tD83H0/NYA8CC
         0hSWUms9Suk0WGJkpcIH8pCDjZeoBkl5fVLf5jGt3aZuPaLq/fC59aCclrNgpZPT/MiE
         cmfQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:organization:from:references:cc:to
         :subject:dkim-signature;
        bh=XKvhMYbPeIfjBqzilW6MTKDEALceHhOMd9Ttih7NUzc=;
        b=TPbthWW8hb+RGxwLoHyomImozH8fmlasamgHRsyMeZQ4C8SyVtuzVjO5D7KLiHhTp9
         y8zpQHIgeAXdt2/0Amx85cBhZyRlgzktoQY3SY3lNKffn01g50SwDiQJ4pDBP34LvYsY
         fFqgf2Vq9gr0d3HIrg0e79+Y2C7SMwxHRA5zNsZtpeVSoN0SADckrW6/XqWvn+vfQ8BI
         vGDcd6GYRC14m38rVAS9YufqO/bDTnxEglmmHkpqYXT1+AKby5fFSIADDdEYcbjfoPGM
         2JE3dvGMzjT8fgq1ZSkEwJ7NLr6nisTiv3yNOKikpYSvRH6pw/lDuZCL8MFRubkUp7Uw
         2/iQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=MLxzsSEV;
       spf=pass (google.com: domain of david@redhat.com designates 63.128.21.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [63.128.21.124])
        by gmr-mx.google.com with ESMTPS id z13si476458pju.1.2021.02.18.00.55.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 18 Feb 2021 00:55:18 -0800 (PST)
Received-SPF: pass (google.com: domain of david@redhat.com designates 63.128.21.124 as permitted sender) client-ip=63.128.21.124;
Received: from mimecast-mx01.redhat.com (mimecast-mx01.redhat.com
 [209.132.183.4]) (Using TLS) by relay.mimecast.com with ESMTP id
 us-mta-558-Q0uAD2YWMX25mfx7NX_YEw-1; Thu, 18 Feb 2021 03:55:15 -0500
X-MC-Unique: Q0uAD2YWMX25mfx7NX_YEw-1
Received: from smtp.corp.redhat.com (int-mx03.intmail.prod.int.phx2.redhat.com [10.5.11.13])
	(using TLSv1.2 with cipher AECDH-AES256-SHA (256/256 bits))
	(No client certificate requested)
	by mimecast-mx01.redhat.com (Postfix) with ESMTPS id 0A5146EE20;
	Thu, 18 Feb 2021 08:55:13 +0000 (UTC)
Received: from [10.36.114.59] (ovpn-114-59.ams2.redhat.com [10.36.114.59])
	by smtp.corp.redhat.com (Postfix) with ESMTP id ADBD96E407;
	Thu, 18 Feb 2021 08:55:08 +0000 (UTC)
Subject: Re: [PATCH] mm, kasan: don't poison boot memory
To: Andrey Konovalov <andreyknvl@google.com>,
 Andrew Morton <akpm@linux-foundation.org>,
 Catalin Marinas <catalin.marinas@arm.com>,
 Vincenzo Frascino <vincenzo.frascino@arm.com>,
 Dmitry Vyukov <dvyukov@google.com>,
 George Kennedy <george.kennedy@oracle.com>,
 Konrad Rzeszutek Wilk <konrad@darnok.org>
Cc: Will Deacon <will.deacon@arm.com>, Dmitry Vyukov <dvyukov@google.com>,
 Andrey Ryabinin <aryabinin@virtuozzo.com>,
 Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>,
 Peter Collingbourne <pcc@google.com>, Evgenii Stepanov <eugenis@google.com>,
 Branislav Rankov <Branislav.Rankov@arm.com>,
 Kevin Brodsky <kevin.brodsky@arm.com>, Christoph Hellwig
 <hch@infradead.org>, kasan-dev@googlegroups.com,
 linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org,
 linux-kernel@vger.kernel.org
References: <487751e1ccec8fcd32e25a06ce000617e96d7ae1.1613595269.git.andreyknvl@google.com>
From: David Hildenbrand <david@redhat.com>
Organization: Red Hat GmbH
Message-ID: <e58cbb53-5f5b-42ae-54a0-e3e1b76ad271@redhat.com>
Date: Thu, 18 Feb 2021 09:55:07 +0100
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101
 Thunderbird/78.7.0
MIME-Version: 1.0
In-Reply-To: <487751e1ccec8fcd32e25a06ce000617e96d7ae1.1613595269.git.andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Language: en-US
X-Scanned-By: MIMEDefang 2.79 on 10.5.11.13
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=MLxzsSEV;
       spf=pass (google.com: domain of david@redhat.com designates
 63.128.21.124 as permitted sender) smtp.mailfrom=david@redhat.com;
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

On 17.02.21 21:56, Andrey Konovalov wrote:
> During boot, all non-reserved memblock memory is exposed to the buddy
> allocator. Poisoning all that memory with KASAN lengthens boot time,
> especially on systems with large amount of RAM. This patch makes
> page_alloc to not call kasan_free_pages() on all new memory.
> 
> __free_pages_core() is used when exposing fresh memory during system
> boot and when onlining memory during hotplug. This patch adds a new
> FPI_SKIP_KASAN_POISON flag and passes it to __free_pages_ok() through
> free_pages_prepare() from __free_pages_core().
> 
> This has little impact on KASAN memory tracking.
> 
> Assuming that there are no references to newly exposed pages before they
> are ever allocated, there won't be any intended (but buggy) accesses to
> that memory that KASAN would normally detect.
> 
> However, with this patch, KASAN stops detecting wild and large
> out-of-bounds accesses that happen to land on a fresh memory page that
> was never allocated. This is taken as an acceptable trade-off.
> 
> All memory allocated normally when the boot is over keeps getting
> poisoned as usual.
> 
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> Change-Id: Iae6b1e4bb8216955ffc14af255a7eaaa6f35324d

Not sure this is the right thing to do, see

https://lkml.kernel.org/r/bcf8925d-0949-3fe1-baa8-cc536c529860@oracle.com

Reversing the order in which memory gets allocated + used during boot 
(in a patch by me) might have revealed an invalid memory access during boot.

I suspect that that issue would no longer get detected with your patch, 
as the invalid memory access would simply not get detected. Now, I 
cannot prove that :)

-- 
Thanks,

David / dhildenb

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/e58cbb53-5f5b-42ae-54a0-e3e1b76ad271%40redhat.com.
