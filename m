Return-Path: <kasan-dev+bncBCPILY4NUAFBBU6AWW6QMGQEVB6PXJA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x139.google.com (mail-il1-x139.google.com [IPv6:2607:f8b0:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id 38A50A335B4
	for <lists+kasan-dev@lfdr.de>; Thu, 13 Feb 2025 04:00:37 +0100 (CET)
Received: by mail-il1-x139.google.com with SMTP id e9e14a558f8ab-3ce7a0ec1easf2819055ab.0
        for <lists+kasan-dev@lfdr.de>; Wed, 12 Feb 2025 19:00:37 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1739415636; cv=pass;
        d=google.com; s=arc-20240605;
        b=D20FxnvDHCtnAKZNP236qidx00F+KTqS4uzwjYC8pGCyuThMh+yWt27QF9WmXAohAJ
         zBxLw9JQwFtCR/oIR13rrxVUthFUZ3wncDIFJwcKLbI1FU5kLdIJkOKI8QZggcawel6t
         hKc+LTspOYaIPjMKE1EqOZbj3qLtwUncz3n9u4ZnLET4QS7ya+N+cIwIRNS+McqKHwko
         H7qpmneQdubx/TYsjKc5pyb8pi+qD/WrsQcAFhHxSmXs+Pk1SDgbRHPUdCpaoC292OPL
         oEPnWhqGppespePKMNdE9gSVTcgX6PQghMUxMvu4MtoxbSfOOW0GTu5zPij8hJGZuzSH
         d47g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :content-language:in-reply-to:references:cc:to:subject:user-agent
         :mime-version:date:message-id:from:sender:dkim-signature;
        bh=uOwxBh0IXvNYwyN/8KWpYGCmtQwYyLmFFmFVMeKxruA=;
        fh=k31xqrZIVwjm5XULPFiy+7fQ6JHqJEHMrIR7yIVK9kc=;
        b=KqI0wMNqdssXdFAnlQi6vV5YoEM9q2YtRkDkSmcz6yLScKVrsQN7DDUTpacjVTceq2
         uFFDPJnCKy1eP6FIwV7DUyhS6WikFP3VjS5Zf9J9AnuAKcnV/CLj9DmNeX7lxTgBAY0f
         7rcdf24DdI2a/QJrV3ab+l39hJ9U9fXyq17PbTzHOm8iMimzKcxCjprdqwGaIQyta73w
         9hLeyuhcwmF+09lTs4WKzt7lnBNm1lO55i/gugiw/bl3TWsAr0BzaO+HC11CtA6DxGXI
         4QPiylR4DgrOy6XTvINNakQz7WyPn2RvKeU8FDunr3jOYMqgIXLFNdkj8cvVejU1WDj2
         hk9g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=bD7FURvg;
       spf=pass (google.com: domain of llong@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=llong@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1739415636; x=1740020436; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:content-language
         :in-reply-to:references:cc:to:subject:user-agent:mime-version:date
         :message-id:from:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=uOwxBh0IXvNYwyN/8KWpYGCmtQwYyLmFFmFVMeKxruA=;
        b=f5+naXz3uRnJKS2Tlot20sPMBxPV320sN1z7ev+m6u0lTlslYW/QuF+l0no6vwqGYu
         HGju4td4WzadZa7+y6A19nFXbZ3QgSOS50HhArjquVViEBqIJgvfMWPRRa0StIpSOmts
         AXAzRXOg/YcgBYDJGOQNKV8PIA1KGEZ7te2Ineg/RTV750it5pKaTLNJz80msAkijHG2
         OJoceUCnCLudjT5uu/mRLRQnTUIKEfsaMP5q82HLqvUnRDxq8y4ePwUbAKTb+A3E5vz/
         dgRDJ9FGuK8MzgxYOgDh8mm2wvTz1hDE27zgmPgokJ6DCBatIDWZh6UlL+KqjvE4irIy
         iepg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1739415636; x=1740020436;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:content-language:in-reply-to:references
         :cc:to:subject:user-agent:mime-version:date:message-id:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=uOwxBh0IXvNYwyN/8KWpYGCmtQwYyLmFFmFVMeKxruA=;
        b=XSx8my6bJsAJhU/WsBeJtJXoOieirJxgzMAy7d7If0MA4D/Pe836cUhMYCeyeWUOGl
         Era7PjFHXyWEqjlKIyVJqyjS1H46NxS5ASISdRG2ItzuuaeWu9QQXOHkkcRAsUmykppp
         4kHLf+NlIqfJvBiO5maicw+RevZ3KiOBgrJI3CdG0Pb+BKlFLh6omhNV1U8tiQKxFOX3
         gnGCh7f5BwUjHX0W9DI8rsgqsvXXeAt9obJNglIFe6AR2NY+7XxxFD8JKb6WnmllMVwK
         V6DzUBreY+w50EpkO8MFnaqni+O85Dd75687vu5DwW8wKFkbjgaVj9X461eX0TFZCMSF
         C1dw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVj5TdZuVGSrGoci8X5e8W3zDXA43mwbY8K8xFTf9JX61Ry6RGcqDKWBOWiT8h7JNSMQB5nBA==@lfdr.de
X-Gm-Message-State: AOJu0Yw4FqpdMTAiappRtIaCnUiA0anpVAtNo3DImZ11K+3jUChjTrur
	GKZIOGxRwbobwoK+RZkWV5K/SKkC+PEEj1BG1PxwtPhhT63bJu08
X-Google-Smtp-Source: AGHT+IGwjaR7nDVtfhkN9LhVN/568GodjyO2p/okfN7oZhX4rZzu+SY1BqpTLvsCQofgNmNWmX61fA==
X-Received: by 2002:a05:6e02:1a2a:b0:3cf:fd90:946a with SMTP id e9e14a558f8ab-3d18c235c47mr14601285ab.10.1739415635654;
        Wed, 12 Feb 2025 19:00:35 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVHqm7bABJ3bTCeiNiW1h9w3V3nLUMU/PvHAothWwBq54w==
Received: by 2002:a05:6e02:1342:b0:3d0:45cd:cd1a with SMTP id
 e9e14a558f8ab-3d18c39bd63ls1757445ab.2.-pod-prod-06-us; Wed, 12 Feb 2025
 19:00:34 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVuMN50wFHeDgyLzP1y5cGYPKSulXT6hIf3altAuCXusLnxSRNrJ/8MWbp0gxiTAWOBr9k4GrVj9FM=@googlegroups.com
X-Received: by 2002:a05:6e02:3889:b0:3d1:79ec:bef2 with SMTP id e9e14a558f8ab-3d18c22b107mr15090455ab.6.1739415634527;
        Wed, 12 Feb 2025 19:00:34 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1739415634; cv=none;
        d=google.com; s=arc-20240605;
        b=gcfdDSkNlMq6EEwtz8r6YGinc4IfTLRLAfNEOFIKpJWNxJQgZa0Hy77kdD7ew9W9yi
         oRpDSocBaby6090lqkdSxtA5C3ZUsHnEAB+YxKxJYLolq+QFzHKzh9zJAKPLJaN8D2hU
         r5o6Ospx3/n8qoUFC0Y1NYqIZbV4QRKaOAPC3Q7r42U07VXhxc4m9GFUQWSaT7WIIqPI
         hZE91GQxFD9l58thFEX3lTsX82+ZAxctDjMDKBuogvcU/o3PgmQmOHBbwkhmvtmoPo6F
         bK5Z67JZvdyfNDIrdI/O7adMCiAPE4EPEieGWoymMWJSRHv6iSuPN8GPKQtty11o/Sgt
         fsvg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:content-language:in-reply-to:references
         :cc:to:subject:user-agent:mime-version:date:message-id:from
         :dkim-signature;
        bh=OWwww+9wjYnmYiIoosHtl2D22JscWljOY5A6wHcnvOU=;
        fh=02IjkJGjd7ddFZw19RXlI3SlfBmELNiFjD29eg2gGHU=;
        b=fusYhtwvdhEIEPtBdqhoLNBjv5ZnTMJCpU9YsvmgxEZ3pDDDG65CHzXr4wit9LvAY0
         4pGbpW1jHZ6+ENkxgK41w8FVnl+57NVbqgLDJf9VeqpDNQJr+pgxOOxljuBDnc3+7gXt
         R9MxTE0748XTzHyNIx5vHggALoXqRbwIw3GQUWn/2sbz7bF0Ifc9fv2G8bea+UbVXM4q
         jG4ofMVHmyPMvzrLR9BsQYDLiJxxqNUKR/wwY5BNi3FmSJBxikSMAeq9Jm2/UJ90Qgls
         z44oQUOxc5+NxKuDpi+nwqIHx5JsTtfeO4uYM4kfYUiosxR12k9jGu9crZcBdkReRWeB
         wjZQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=bD7FURvg;
       spf=pass (google.com: domain of llong@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=llong@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id e9e14a558f8ab-3d18f877a97si208245ab.0.2025.02.12.19.00.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 12 Feb 2025 19:00:34 -0800 (PST)
Received-SPF: pass (google.com: domain of llong@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mail-qk1-f199.google.com (mail-qk1-f199.google.com
 [209.85.222.199]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384) id
 us-mta-637-7otGFbzMObq3Bi3lxBapjA-1; Wed, 12 Feb 2025 22:00:32 -0500
X-MC-Unique: 7otGFbzMObq3Bi3lxBapjA-1
X-Mimecast-MFC-AGG-ID: 7otGFbzMObq3Bi3lxBapjA
Received: by mail-qk1-f199.google.com with SMTP id af79cd13be357-7c05b5fe52bso90496285a.3
        for <kasan-dev@googlegroups.com>; Wed, 12 Feb 2025 19:00:32 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCXXf2ygFqOeGccZ6BkpvTPfJlSw/QD1208UDDLPmQDRIQeRFlROrIHHRvIS63RuEI2Bs9tF75L1rkY=@googlegroups.com
X-Gm-Gg: ASbGnct6UIl/ORfDYDjLvaf2BLLB6TXSYxDw7HzXFBP8bb5O4AxVlfhzGbzUkuRvdHW
	IM0uA7Yy8RhM4tOTDKLGmcwTOMKvX8rmcSCF+QU4cBV9ZTUfYcTIoBceFSF4rVb8uPPv0QvfFwg
	kK45h7fLIjF9jpHajHjLpTATpJB+TK4ej0U+zZjiafN0OsuXkQ0FFwhy5eJ6W8racTTophRolIw
	Vrlhd1aJeif4Z0wYy8riNxTnK1btV2rTCO1fjAOABOaMuhG7M9hzRvvHko1a0+6Frzr2sziCeSW
	1YDa/AJ52vDtIi3KHb4njDt3nLy6NKI3DFPUOlJKbof5Abhc
X-Received: by 2002:a05:620a:4154:b0:7b6:e47a:8e1d with SMTP id af79cd13be357-7c07a14eca8mr288912685a.31.1739415631946;
        Wed, 12 Feb 2025 19:00:31 -0800 (PST)
X-Received: by 2002:a05:620a:4154:b0:7b6:e47a:8e1d with SMTP id af79cd13be357-7c07a14eca8mr288908485a.31.1739415631630;
        Wed, 12 Feb 2025 19:00:31 -0800 (PST)
Received: from ?IPV6:2601:188:c100:5710:627d:9ff:fe85:9ade? ([2601:188:c100:5710:627d:9ff:fe85:9ade])
        by smtp.gmail.com with ESMTPSA id af79cd13be357-7c07c608269sm26919485a.31.2025.02.12.19.00.30
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 12 Feb 2025 19:00:31 -0800 (PST)
From: Waiman Long <llong@redhat.com>
Message-ID: <b9fdff48-da6a-4190-addb-acb948ea9ad7@redhat.com>
Date: Wed, 12 Feb 2025 22:00:29 -0500
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v2] kasan: Don't call find_vm_area() in RT kernel
To: Andrey Konovalov <andreyknvl@gmail.com>,
 Peter Zijlstra <peterz@infradead.org>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>,
 Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>,
 Vincenzo Frascino <vincenzo.frascino@arm.com>,
 Andrew Morton <akpm@linux-foundation.org>,
 Sebastian Andrzej Siewior <bigeasy@linutronix.de>,
 Clark Williams <clrkwllms@kernel.org>, Steven Rostedt <rostedt@goodmis.org>,
 kasan-dev@googlegroups.com, linux-mm@kvack.org,
 linux-kernel@vger.kernel.org, linux-rt-devel@lists.linux.dev,
 Nico Pache <npache@redhat.com>
References: <20250212162151.1599059-1-longman@redhat.com>
 <CA+fCnZdbW1Y8gsMhMtKxYZz3W6+CeovOVsi+DZbWsFTE2VNPbA@mail.gmail.com>
In-Reply-To: <CA+fCnZdbW1Y8gsMhMtKxYZz3W6+CeovOVsi+DZbWsFTE2VNPbA@mail.gmail.com>
X-Mimecast-Spam-Score: 0
X-Mimecast-MFC-PROC-ID: sHNkP6iMG8HNVbEf0fuq72TwnxWfTnXcNDGbqlpPAtI_1739415632
X-Mimecast-Originator: redhat.com
Content-Language: en-US
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: llong@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=bD7FURvg;
       spf=pass (google.com: domain of llong@redhat.com designates
 170.10.129.124 as permitted sender) smtp.mailfrom=llong@redhat.com;
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

On 2/12/25 8:48 PM, Andrey Konovalov wrote:
> On Wed, Feb 12, 2025 at 5:22=E2=80=AFPM Waiman Long <longman@redhat.com> =
wrote:
>> The following bug report appeared with a test run in a RT debug kernel.
>>
>> [ 3359.353842] BUG: sleeping function called from invalid context at ker=
nel/locking/spinlock_rt.c:48
>> [ 3359.353848] in_atomic(): 1, irqs_disabled(): 1, non_block: 0, pid: 14=
0605, name: kunit_try_catch
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
>> Commit e30a0361b851 ("kasan: make report_lock a raw spinlock")
>> changes report_lock to a raw_spinlock_t to avoid a similar RT problem.
>> The print_address_description() function is called with report_lock
>> acquired and interrupt disabled.  However, the find_vm_area() function
>> still needs to acquire a spinlock_t which becomes a sleeping lock in
>> the RT kernel. IOW, we can't call find_vm_area() in a RT kernel and
>> changing report_lock to a raw_spinlock_t is not enough to completely
>> solve this RT kernel problem.
>>
>> Fix this bug report by skipping the find_vm_area() call in this case
>> and just print out the address as is.
>>
>> For !RT kernel, follow the example set in commit 0cce06ba859a
>> ("debugobjects,locking: Annotate debug_object_fill_pool() wait type
>> violation") and use DEFINE_WAIT_OVERRIDE_MAP() to avoid a spinlock_t
>> inside raw_spinlock_t warning.
> Would it be possible to get lockdep to allow taking spinlock_t inside
> raw_spinlock_t instead of annotating the callers for the !RT case? Or
> is this a rare thing for this to be allowed on !RT?

Lockdep currently issues warnings for taking spinlock_t inside=20
raw_spinlock_t because it is not allowed in RT. Test coverage of RT=20
kernels is likely less than !RT kernel and so less bug of this kind will=20
be caught. By making !RT doing the same check, we increase coverage.=20
However, we do allow override in the !RT case, but it has to be done on=20
a case-by-case basis.

Currently we only do that for debugging code, not the code that will be=20
used in production kernel yet.

Cheers,
Longman

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/b=
9fdff48-da6a-4190-addb-acb948ea9ad7%40redhat.com.
