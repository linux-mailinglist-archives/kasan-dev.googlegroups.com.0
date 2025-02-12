Return-Path: <kasan-dev+bncBCPILY4NUAFBB2OQV66QMGQEF3SHZFY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1039.google.com (mail-pj1-x1039.google.com [IPv6:2607:f8b0:4864:20::1039])
	by mail.lfdr.de (Postfix) with ESMTPS id 48DADA31A4B
	for <lists+kasan-dev@lfdr.de>; Wed, 12 Feb 2025 01:16:44 +0100 (CET)
Received: by mail-pj1-x1039.google.com with SMTP id 98e67ed59e1d1-2fa2e61c187sf626816a91.0
        for <lists+kasan-dev@lfdr.de>; Tue, 11 Feb 2025 16:16:44 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1739319402; cv=pass;
        d=google.com; s=arc-20240605;
        b=YrCx1qp+3mfy+3oatjRqbutQCa+EROgdRi2LCYmgAKNhSLjtjQcAIsneZgu1ArOdaW
         7/F8dI25EFEpI+ScebpVPFxR3SszcO+ZDSDcV7aIpLuzURsCIl9A7yO4/hectPRj0F3S
         90UgndhXni9KskPNF5InL82cuTSnr/rOFyCGc0xXWwTJX3ZY/TLhKBUELh4dhdU3rTJU
         CreTy66/0fBoF1c3KdmHP2rIERhp7fXKLyjt3Nr6DFtS8WLqj+x44KetmNs450m7zvxz
         yZDaud36zr3Pnik5RFm1ssC9KYhiV/C5z4kR1jspUzVoNJl0mg5mm15YRKuSZSs5WnPu
         Mu4Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :from:sender:dkim-signature;
        bh=F/z17Atzx5DwG2CfnhTVrehwwujTbna6OX6hiv7tJFU=;
        fh=wld6vDBHTDekt0tqeC5dYdWkE2+Inj24Bjzh8kty8v0=;
        b=J/aUyzyG4FMgZuWEcp6bdosV0LDLPdHH2azyB7lKaK6MNW89nnGv4GeuUmbBd7PRwW
         ulNC0Bs8gKKtQHfxvzwhHzjVTtSKCbrV3ecE53sdKbkkhkDw+QQclDfixmzupN57Lm8G
         dBGgLLft0rYG/eNTOapKGCjcK5M7lX2yaem3SNbY/78Hiw65kNZY+iUx4iq7puv0IfLU
         j9Whu7Ip9Pf/lXCLEnSXSth03gV+zYOCqkBwSyeJmins65S1XcJP6PxL4lhQCVM8EnB+
         HEiIP46jMdEJcpXM4zPKSppGZPWyZ5n3vqOguoy3pYtvQBfM7evNr3+OE3xz9mPikDh+
         /H3A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=e6jtlIz0;
       spf=pass (google.com: domain of llong@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=llong@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1739319402; x=1739924202; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-language:in-reply-to:references:cc:to
         :subject:user-agent:mime-version:date:message-id:from:sender:from:to
         :cc:subject:date:message-id:reply-to;
        bh=F/z17Atzx5DwG2CfnhTVrehwwujTbna6OX6hiv7tJFU=;
        b=EtZaaDJ4PXyaFODZ468nVEYZeB+YQqbLXeea8MwAKzwScKFN/m1XLnXuboIskSVCV+
         Hhu7zRVjdmVcVtLKEWc5TfjeMYGosPofP9uEQr0cI4xCKDDInbVqSMK0MzZ39Cr3FXO5
         o9YE2W/u7Q3kjIk+mYrpJB8lEsI624Fbhi2fhzRXFdmy2U0Ilcm72G3XwEM3tIKuYaWj
         /dU4ao2fudUcmaBLxHAvR+hiS3N1CYpi2qcZsllT4iLbTXmvVSiDY8g4ZDqTCL9pktRa
         e+V/oIskTfpFC8gOqTRnq1id7IcUMGBbZP5sH4ev6xSlwa2W+oi5x5AidPtMfK5mdq4A
         VuKg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1739319402; x=1739924202;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-language:in-reply-to:references:cc:to:subject:user-agent
         :mime-version:date:message-id:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=F/z17Atzx5DwG2CfnhTVrehwwujTbna6OX6hiv7tJFU=;
        b=aISEUnB42aQwKYk7DRzSZ/GLovgEnnjpSDfwFQxxDFYS9IXi8mHqIIbGkfyCV3qfHB
         wXV8fOYBqFoB8P7c96zNEnb8+c7Ib8wdBLv5mFxCzbET+DVpNwzyH+qqWHX5zrEPBoxD
         R7CS47IKHW6JdmF4/TRczNIgpEP3dN9LBeM2d7OtZ+gGa2dfatzz4cLS1uKFWFcxA+Rk
         MDGKw8M3hxAKyDBFGfZWewKFMh1Plf/PZJabMEezG05K9SmVLaxhQk0fje2As//LdNVM
         IDs5q5c7x3WP2xdmL3VXjr47/tlkCS5SqLwn+Cx7PqvsVqowp6pdTfP8l4PWll++bhdW
         2A9A==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVhNnStnS5hh05SbFG5Kv1GmKGjrwjylAiLBKNcaus8VPJ/5wGRzSwSJLLtbylhsKUC6VYOLQ==@lfdr.de
X-Gm-Message-State: AOJu0YycVkNRjkeaBz1LQCIVP1z9rI8gpZeLKsZj9vO/6BVkO3kEGIvO
	vwFbp+D41LFJnFFnd1AASiibO5FGpTpBG+l71Mv+DL1Tx0q9wRz2
X-Google-Smtp-Source: AGHT+IHN21hTM+o0xpkTgapfzYDImCD4H84lnBRpCdzPibeyyRxYo78ljZILfHqhDr19Uveb8q8mLg==
X-Received: by 2002:a17:90b:3d4c:b0:2e2:c2b0:d03e with SMTP id 98e67ed59e1d1-2fbf5c0d985mr1643724a91.5.1739319402220;
        Tue, 11 Feb 2025 16:16:42 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:53ce:b0:2fa:2eec:8898 with SMTP id
 98e67ed59e1d1-2fbf2e9788bls254964a91.0.-pod-prod-00-us; Tue, 11 Feb 2025
 16:16:41 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCX0zC7kx8FlVQKAWWXiZoUR2rJhLahdgq0WO0fEZiCJohZ0UIu8qbAQg+CV20eERKqVgBNsC51K/Po=@googlegroups.com
X-Received: by 2002:a17:90b:5408:b0:2ee:8cbb:de28 with SMTP id 98e67ed59e1d1-2fbf5c237c4mr1920294a91.8.1739319400940;
        Tue, 11 Feb 2025 16:16:40 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1739319400; cv=none;
        d=google.com; s=arc-20240605;
        b=M0F5l/x8nrKqmPQu7POSJ5dZaPqXdc5AtLe4NZUZTK2sPPjkI5S8QWmZJtborWc928
         NMYuWVKMHZiOEXCl3tbEY1vc24zqkfrmW26MSNpRnfHO8EkBJtRIPZOajYVudxXcAHdc
         skbWTlDMMmZRHDbcwcKDMhwIOUqIkNK1KyG72AC/1yBhADellgdTht0VWdrESz0boQ7y
         ZYGViYwRu44irEWf/QscUF/rNpG62eMNGCxrAFyEiM5Xr07Q5mpTk76Qa0MQgZfXfUP4
         IhPJbvgQe6vJuQ+tUC4LWO6KEuEdHjrNn08uPz3Xobqssg5YjgYM9dvRPFnIaX9Cd/uY
         6mCQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:content-language:in-reply-to:references
         :cc:to:subject:user-agent:mime-version:date:message-id:from
         :dkim-signature;
        bh=Aw447gaPb7zNMocf3h4BtDlt/qfajgVcEdNoBnnrQDw=;
        fh=kenH5qW/Bz93p52OzO1b4CgcQgU0OhjGZpu3uDw1jYY=;
        b=R6rbZ49BUKBp/RGUL7DHKraT+UPk6NRG/N8ASAygNdhUHZIxA2NU2d++C+rBnTYakP
         TdlYoDmh20lfZDuJh36IcEXBQi9eIVCChEjvr0XW+60hPARAWZoOM1oF+ss4m0qFOUd/
         tMprhfNwJgWzXy1ELQAYG2QfEOebGnQ2FsLIHxMd1O9cvB6e1L0+nxusziD5wjvHVVyY
         7sSBY5YrN6zhSkdUJ1/IgApCy1txicz2WzMJEqAuHR3vJnCzYdhH2bcluqdQrP5ojWul
         Lv6WBoRna+dLwgE/JjR+1pEtNKJ8DxFcuNaUUdMpEedwdOXtDSLSg/IGc1okO5qnrT9w
         JLdw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=e6jtlIz0;
       spf=pass (google.com: domain of llong@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=llong@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.133.124])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-2faa4aebb95si239373a91.0.2025.02.11.16.16.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 11 Feb 2025 16:16:40 -0800 (PST)
Received-SPF: pass (google.com: domain of llong@redhat.com designates 170.10.133.124 as permitted sender) client-ip=170.10.133.124;
Received: from mail-qk1-f199.google.com (mail-qk1-f199.google.com
 [209.85.222.199]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384) id
 us-mta-472-400m1l4sPjGA_t_xa3rwdQ-1; Tue, 11 Feb 2025 19:16:38 -0500
X-MC-Unique: 400m1l4sPjGA_t_xa3rwdQ-1
X-Mimecast-MFC-AGG-ID: 400m1l4sPjGA_t_xa3rwdQ
Received: by mail-qk1-f199.google.com with SMTP id af79cd13be357-7c057344597so55554085a.1
        for <kasan-dev@googlegroups.com>; Tue, 11 Feb 2025 16:16:38 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCUVH8wtIuBCVCPGGo5IeVJOOxHYaTCgqcoJzaueTLYpGDid3IKZMfhKdP/lERNSYUEyiJ2TSjyGMhY=@googlegroups.com
X-Gm-Gg: ASbGnctqL765w7nbTJYmKdwaG/fQA0ZmEEWNP6/9IlHJyih5gTvhO9caEihN+1Zy1kV
	Z9y8sK/vVoVVw8ESy5SU0PUjq9f0PqglgJikXJxSbFP++p5vcmZz3pnDe/mN/G6Y8mYIsSacc2A
	EgcHRVp4ab84GriQMAsLwhL+V+kwevnANmS2eyt4x7TakMv1EQnDNICkOBj0iQ+biUzyLJFhowV
	OQ5oq9o3EjzyXfNkQ7wELQV9XWiGmkYd8bb/lQbowYMzPm0jZyphIomsMrU9+xvpPsck2THpUZx
	EzXib1Eu+NcN+k8ym5ecSG0b7qJOig+HELmkaAuiZvWX/LvH
X-Received: by 2002:a05:620a:24d4:b0:7b6:fdb9:197e with SMTP id af79cd13be357-7c07025941dmr154537885a.8.1739319398119;
        Tue, 11 Feb 2025 16:16:38 -0800 (PST)
X-Received: by 2002:a05:620a:24d4:b0:7b6:fdb9:197e with SMTP id af79cd13be357-7c07025941dmr154535485a.8.1739319397850;
        Tue, 11 Feb 2025 16:16:37 -0800 (PST)
Received: from ?IPV6:2601:188:c100:5710:627d:9ff:fe85:9ade? ([2601:188:c100:5710:627d:9ff:fe85:9ade])
        by smtp.gmail.com with ESMTPSA id af79cd13be357-7c0728eb208sm3484785a.99.2025.02.11.16.16.36
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 11 Feb 2025 16:16:36 -0800 (PST)
From: Waiman Long <llong@redhat.com>
Message-ID: <6b6c1245-f6ee-4af7-b463-e8b6da60c661@redhat.com>
Date: Tue, 11 Feb 2025 19:16:34 -0500
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH] kasan: Don't call find_vm_area() in RT kernel
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>,
 Alexander Potapenko <glider@google.com>,
 Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>,
 Vincenzo Frascino <vincenzo.frascino@arm.com>,
 Sebastian Andrzej Siewior <bigeasy@linutronix.de>,
 Clark Williams <clrkwllms@kernel.org>, Steven Rostedt <rostedt@goodmis.org>,
 kasan-dev@googlegroups.com, linux-mm@kvack.org,
 linux-kernel@vger.kernel.org, linux-rt-devel@lists.linux.dev,
 Nico Pache <npache@redhat.com>
References: <20250211160750.1301353-1-longman@redhat.com>
 <20250211145730.5ff45281943b5b044208372c@linux-foundation.org>
In-Reply-To: <20250211145730.5ff45281943b5b044208372c@linux-foundation.org>
X-Mimecast-Spam-Score: 0
X-Mimecast-MFC-PROC-ID: US3nuAdQGsXaMj3ig0YN0uemOLdGzbA0PlYQjDAUYPk_1739319398
X-Mimecast-Originator: redhat.com
Content-Language: en-US
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: llong@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=e6jtlIz0;
       spf=pass (google.com: domain of llong@redhat.com designates
 170.10.133.124 as permitted sender) smtp.mailfrom=llong@redhat.com;
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


On 2/11/25 5:57 PM, Andrew Morton wrote:
> On Tue, 11 Feb 2025 11:07:50 -0500 Waiman Long <longman@redhat.com> wrote:
>
>> The following bug report appeared with a test run in a RT debug kernel.
>>
>> [ 3359.353842] BUG: sleeping function called from invalid context at kernel/locking/spinlock_rt.c:48
>> [ 3359.353848] in_atomic(): 1, irqs_disabled(): 1, non_block: 0, pid: 140605, name: kunit_try_catch
>> [ 3359.353853] preempt_count: 1, expected: 0
>>    :
>> [ 3359.353933] Call trace:
>>    :
>> [ 3359.353955]  rt_spin_lock+0x70/0x140
>> [ 3359.353959]  find_vmap_area+0x84/0x168
>> [ 3359.353963]  find_vm_area+0x1c/0x50
>> [ 3359.353966]  print_address_description.constprop.0+0x2a0/0x320
>> [ 3359.353972]  print_report+0x108/0x1f8
>> [ 3359.353976]  kasan_report+0x90/0xc8
>> [ 3359.353980]  __asan_load1+0x60/0x70
>>
>> The print_address_description() is run with a raw_spinlock_t acquired
>> and interrupt disabled. The find_vm_area() function needs to acquire
>> a spinlock_t which becomes a sleeping lock in the RT kernel. IOW,
>> we can't call find_vm_area() in a RT kernel. Fix this bug report
>> by skipping the find_vm_area() call in this case and just print out
>> the address as is.
>>
>> For !RT kernel, follow the example set in commit 0cce06ba859a
>> ("debugobjects,locking: Annotate debug_object_fill_pool() wait type
>> violation") and use DEFINE_WAIT_OVERRIDE_MAP() to avoid a spinlock_t
>> inside raw_spinlock_t warning.
>>
> Thanks.  I added it and shall await review from the KASAN developers.
>
> I'm thinking we add
>
> Fixes: c056a364e954 ("kasan: print virtual mapping info in reports")
> Cc: <stable@vger.kernel.org>
>
> but c056a364e954 is 3 years old and I don't think we care about -rt in
> such old kernels.  Thoughts?

The KASAN report_lock was changed to a raw_spinlock_t in v6.13 kernel 
with commit e30a0361b851 ("kasan: make report_lock a raw spinlock") to 
fix a similar RT problem. The report_lock is acquired before calling 
print_address_description(). Before commit e30a0361b851, this 
find_vm_area() is a secondary issue. We may consider commit e30a0361b851 
isn't complete and this is a fix for that.

The DEFINE_WAIT_OVERRIDE_MAP() macro was introduced in v6.4. So this 
patch cannot be backported to a version earlier than that unless commit 
0cce06ba859a is there.

Cheers,
Longman


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/6b6c1245-f6ee-4af7-b463-e8b6da60c661%40redhat.com.
