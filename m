Return-Path: <kasan-dev+bncBCPILY4NUAFBBMW2ZK6QMGQES3XBQJY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63d.google.com (mail-pl1-x63d.google.com [IPv6:2607:f8b0:4864:20::63d])
	by mail.lfdr.de (Postfix) with ESMTPS id 1ED9BA37A13
	for <lists+kasan-dev@lfdr.de>; Mon, 17 Feb 2025 04:29:57 +0100 (CET)
Received: by mail-pl1-x63d.google.com with SMTP id d9443c01a7336-220d8aa893dsf54585465ad.3
        for <lists+kasan-dev@lfdr.de>; Sun, 16 Feb 2025 19:29:57 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1739762995; cv=pass;
        d=google.com; s=arc-20240605;
        b=c6WnsNGGxcUw1AM/Bq1UOF9oR/ZjpmcWeUeDMIQsyoFN/45dfqCmJG5/cnaBN4X9L8
         TdTfgrAOhxI7GL0oDhpVIJUIZBi9c4Wq8l5PBYyuLfM4yXkYzhcCPq2lFbbt7ZvbTq9R
         R4g7fItj//bBwVMKGcvmuiblXeNS4N77h3ai4uZUzK/MyKoXcnPgqq3EKYz4ryhnYJDA
         Cd4HoqlWVSz41NPF8AJ9f6BbyqQVXS0cAnp5fbCgNQjGADnQGfaBegRDG1JaXjF9HFW0
         mvmC7PlvHhlMX6Mmq1SHP7L8oLnuxX5AuI68Zl0N0mWmv1Npx/GLBgMStXluxtJFyJvF
         5YUg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :content-language:in-reply-to:references:cc:to:subject:user-agent
         :mime-version:date:message-id:from:sender:dkim-signature;
        bh=wccduZ5zJcmrhElUQvinOgM8weXeeC/Tn869AoDxcSY=;
        fh=1c2p2AOYPai4NSFJw1xlWpTUycKAOkH9dcnUiG+5Jhw=;
        b=YbA1E4PyjnIquqzj2WD5mRlzqkPsR2/2CHlK7Qc/0VGbWwvuj79JBQjWJsUftYwKPM
         749RCBal3E8gyHHZ/ZaMsceKnVxkqWNnHp0N14eaImW/JTZrKYXxsvVhu9eUckC3sWwy
         dFfoswCox4xTJN8lUM+kVuFOhbVTNjwtEYBxqODdUwiu2UJKk5e7sQhrtn4pyKbeQ748
         9hJS8JHEAODBzM6MQqT1gAkwp1zQLQuqMUwkeVvFW3QkHv5BS7v+zMg+9B+SoOpnU5q1
         0pi2I7RDiypQgccFdDa9wnLrYowHpFKW4yN3Ue+FqlvX4de9P1XxO3vOR2PZwVakzWkA
         pX1Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=E0tBJOOT;
       spf=pass (google.com: domain of llong@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=llong@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1739762995; x=1740367795; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:content-language
         :in-reply-to:references:cc:to:subject:user-agent:mime-version:date
         :message-id:from:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=wccduZ5zJcmrhElUQvinOgM8weXeeC/Tn869AoDxcSY=;
        b=V/uxxLj1l8X9BGSWlhZxoQVymR9cXZrVtkQO7d2tkUbLiWlW+KrhreBIiyORlUu5sO
         a8WnqnwxqgKPE3w2a6hjln0ZKfD1QS1CeY347h/s5y8emz8jI5LuqNf6DAlTqpZZdwq+
         WIn9utBBqUjfgI37HQwdtJFUnGuuzOofCL8ppVzSekSLCpAE1tNhwXCMqCluFIsl5iBw
         qZAZj2pxyaqb0gdUiAr/rkj42XphT7DHL3DTar8/jXFq88uyUfY+sbNDK6OxLGOyB730
         6+QawC/TF2BapwEPW9MsphPxxEdkYsZjL613pl4fvOEJZvGGtDKnPunsL2DJh+SmFatY
         PTEw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1739762995; x=1740367795;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:content-language:in-reply-to:references
         :cc:to:subject:user-agent:mime-version:date:message-id:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=wccduZ5zJcmrhElUQvinOgM8weXeeC/Tn869AoDxcSY=;
        b=SktX3LjezEC4qpxT8kXbmz+t6I/JzgA5QQaM69v30hM+jIRd3XLFIig+rni7dDXa7N
         8EcHTR6nkRmJwcPupFcQDwfGasvxlOr3ZFUYIbWi81CMvHgNGTPc7F9yUyseqyNtLaRc
         rY/KGzoAnV7e26sKQCM3blYjIYpQ3VpscagkAt4VERBN12yzyAHv1CvLgKZVUrKcpGNY
         Q8Qash++kySSwWHtrlo0gLDvp/Jkelbfkmz1xeKr7cUHWHxcl48nz2cFdfxyLUmK8HPG
         E6NdQAZ25EdXt+mQGntkIN1Cc8XUIVksZmk9T+aNXMEnLMYQU3fUT7eUXTluOURBOsM1
         6qhQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWStmTmprV/SzeEZckAETsg34MVrjVZtlWaDeEDtZnOmzxDKQN2e1mSKq73zakw7mENnlLGkg==@lfdr.de
X-Gm-Message-State: AOJu0YzklWKLhJDCmJLlDteJ8RKFRwtETahFDTSdh80qRlwF59wVDR5V
	fyrARj/X+KGAp3aoJMc8ZfoFla+Ojm7CLW1UlaLteL/6OwXoDCWd
X-Google-Smtp-Source: AGHT+IGDI1zQdy1LmCZGJn8GnW0WOEiwlvWSoD931GUnf8zVYhRecXKk84PbnPdTHLz1Dv0KIC3UZQ==
X-Received: by 2002:a17:902:e545:b0:21f:6dbf:1850 with SMTP id d9443c01a7336-221040bd704mr139208505ad.40.1739762995080;
        Sun, 16 Feb 2025 19:29:55 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVF9wGhgO8amaRoEpojZ5QfZQZd+cvUkK6IHOLDSZ5uj0g==
Received: by 2002:a17:90a:f990:b0:2ef:91e1:29f3 with SMTP id
 98e67ed59e1d1-2fc0d5b3908ls3997101a91.0.-pod-prod-04-us; Sun, 16 Feb 2025
 19:29:54 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXknzGxJUFHLxZSYwtnNc2HRafYgJlN/UlaAAwh7tcucH0LO4DxzisO+5huud05+N6NVLVB7mTX04I=@googlegroups.com
X-Received: by 2002:a17:90b:2789:b0:2f4:434d:c7f0 with SMTP id 98e67ed59e1d1-2fc40f1060bmr14767433a91.12.1739762993837;
        Sun, 16 Feb 2025 19:29:53 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1739762993; cv=none;
        d=google.com; s=arc-20240605;
        b=dIYHsZgIPElvLQ7X8lFlXrubcoeTMsSypMf/99ZcnmR4dKO63ZFZGE/suR5pBU+/fu
         YkKUcUlQ7vladcOx609Sc+HRVOx4paDoF2uFvqUQc52eAR9ivfzxVrrwI+3/RD5k90ZE
         CeyROMJfy/mzPwZ9HCANXh+z241Da/onfmAhep2cAxv0ay9hV9Yzxlt3L1ZqrDSCWOBS
         vrZFUTfA0TkhHDydgnlx0e8p6LGbkTyqAJ8Ih8HItYDlS7OcYYl3Uotp04Zu6/IUFINX
         75eZNHugjk2Dx6ulBuEQUc7u1MwYKWmCAaXVU+37Yo1mOnj5QHyAFMqbMwajAS4pIwtw
         0slQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:content-language:in-reply-to:references
         :cc:to:subject:user-agent:mime-version:date:message-id:from
         :dkim-signature;
        bh=rWjuYHFq2b/x6u1PpE5bTN0UtHhvs4sXiLszKZ360YY=;
        fh=1gxHTDubl3Yi0VwLv6PT5rJdD42/cQhz52IlpX7fx/0=;
        b=Lo7P/cgkTpBR2M8PV9ZjUcylAS6wU3+4Y1hZh/1uA2emcvrBK/St2Szzw07ENoGV/N
         GIUFLT6TKTgw0fA+Zm1xXFvl2/WhhNuS1Ek18oFVanLSJ7TbA3L+06YMS2OwmBxNxRBS
         JzxUieKn3hs5G/VTnTmZh/NsOqLTYspjwg+BplNqRu9L7HumYbCdJc9gXX9csK5Rxvl6
         vh3NrbrP+icJTieCgVITORdoPBV/6Ll6GFswJxbnXLEi9imhlosn2k2le+P68ps59PCS
         TKDd6kBWUaTpVoIcuwvjH1WALmqTtjnrXUqFeXhaYupJoKrODanD2b46zFz9BlzWRkXc
         uBCw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=E0tBJOOT;
       spf=pass (google.com: domain of llong@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=llong@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.133.124])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-2fbf9811472si485873a91.1.2025.02.16.19.29.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sun, 16 Feb 2025 19:29:53 -0800 (PST)
Received-SPF: pass (google.com: domain of llong@redhat.com designates 170.10.133.124 as permitted sender) client-ip=170.10.133.124;
Received: from mail-qt1-f197.google.com (mail-qt1-f197.google.com
 [209.85.160.197]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384) id
 us-mta-378-Bm6vh6XeNY2weZg11ODLeA-1; Sun, 16 Feb 2025 22:29:50 -0500
X-MC-Unique: Bm6vh6XeNY2weZg11ODLeA-1
X-Mimecast-MFC-AGG-ID: Bm6vh6XeNY2weZg11ODLeA_1739762990
Received: by mail-qt1-f197.google.com with SMTP id d75a77b69052e-471ba1f5b25so148161641cf.0
        for <kasan-dev@googlegroups.com>; Sun, 16 Feb 2025 19:29:50 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCXnrUUHz5PhEV6ZWBuI9a59PSM60ITTlj8o+E0Qs3Tr9hTLtN5mGhD/y37Gymhsw0O9S+TewMTpAQQ=@googlegroups.com
X-Gm-Gg: ASbGncs/7oe+CC81lOg96+AuRCyn2oCEMNefQ2Q5SmPt/mQM/m1q0GADb3nL2hVl8TN
	8S8dv+hSLLQ4kyyC+EhkKSUOsduAn/rzxSZKws/20WZlxCr4tSsDTYY8E0VHD0PGUUqC2fLyo/X
	KWDDCIry/Wpm9okiCM5bmMYRmLRqhD+SFCtTt7eKGBSKTvlKAz5GbGpdfPGNHWdOrnZQXqoi8IY
	eNRDy49QHeNzWqIcyIITiTiACiWO8hOQ2Xk/zfNayRho7q6+qOoZxYeh+VIDXiWA1XMehp9sQpL
	AZt2QJdhAiUNhCy0xy+QN1eCJXNBpEXMlEZ7+KViv5lpRNMQ
X-Received: by 2002:a05:622a:189a:b0:45d:8be9:b0e6 with SMTP id d75a77b69052e-471dbea2921mr114809121cf.43.1739762990398;
        Sun, 16 Feb 2025 19:29:50 -0800 (PST)
X-Received: by 2002:a05:622a:189a:b0:45d:8be9:b0e6 with SMTP id d75a77b69052e-471dbea2921mr114808981cf.43.1739762990094;
        Sun, 16 Feb 2025 19:29:50 -0800 (PST)
Received: from ?IPV6:2601:188:c100:5710:627d:9ff:fe85:9ade? ([2601:188:c100:5710:627d:9ff:fe85:9ade])
        by smtp.gmail.com with ESMTPSA id d75a77b69052e-471f1e866f4sm5639761cf.33.2025.02.16.19.29.48
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 16 Feb 2025 19:29:49 -0800 (PST)
From: Waiman Long <llong@redhat.com>
Message-ID: <b278ffc5-74af-46cf-be67-ff778d96c85f@redhat.com>
Date: Sun, 16 Feb 2025 22:29:47 -0500
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
X-Mimecast-MFC-PROC-ID: FualtvS2aYmU6T6vcMXmcFXUhGjBCdoscy_9FEWqb_k_1739762990
X-Mimecast-Originator: redhat.com
Content-Language: en-US
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: llong@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=E0tBJOOT;
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
>
>> Fixes: e30a0361b851 ("kasan: make report_lock a raw spinlock")
>> Signed-off-by: Waiman Long <longman@redhat.com>
>> ---
>>   mm/kasan/report.c | 47 ++++++++++++++++++++++++++++++++++-------------
>>   1 file changed, 34 insertions(+), 13 deletions(-)
>>
>>   [v2] Encapsulate the change into a new
>>        kasan_print_vmalloc_info_ret_page() helper
>>
>> diff --git a/mm/kasan/report.c b/mm/kasan/report.c
>> index 3fe77a360f1c..9580ac3f3203 100644
>> --- a/mm/kasan/report.c
>> +++ b/mm/kasan/report.c
>> @@ -370,6 +370,38 @@ static inline bool init_task_stack_addr(const void =
*addr)
>>                          sizeof(init_thread_union.stack));
>>   }
>>
>> +/*
>> + * RT kernel cannot call find_vm_area() in atomic context. For !RT kern=
el,
>> + * prevent spinlock_t inside raw_spinlock_t warning by raising wait-typ=
e
>> + * to WAIT_SLEEP.
>> + *
>> + * Return: page pointer or NULL
>> + */
>> +static inline struct page *kasan_print_vmalloc_info_ret_page(void *addr=
)
> No need for the kasan_ prefix: this is a static function. (Also the
> _ret_* suffix is something I've never seen before in the kernel
> context, but I don't mind it.)

Sorry for missing that. Yes, I can remove the prefix. Will post a v3.

Cheers,
Longman

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/b=
278ffc5-74af-46cf-be67-ff778d96c85f%40redhat.com.
