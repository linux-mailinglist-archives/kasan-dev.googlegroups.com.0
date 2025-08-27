Return-Path: <kasan-dev+bncBAABBIMGXPCQMGQEWIKGH6Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf39.google.com (mail-qv1-xf39.google.com [IPv6:2607:f8b0:4864:20::f39])
	by mail.lfdr.de (Postfix) with ESMTPS id D84DCB37DF1
	for <lists+kasan-dev@lfdr.de>; Wed, 27 Aug 2025 10:34:42 +0200 (CEST)
Received: by mail-qv1-xf39.google.com with SMTP id 6a1803df08f44-70d989082a1sf104734126d6.2
        for <lists+kasan-dev@lfdr.de>; Wed, 27 Aug 2025 01:34:42 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756283681; cv=pass;
        d=google.com; s=arc-20240605;
        b=UyuV8hIpm240dlEWSKiqOMuT7vkAon4ADkCv76KZpXKdwjJ8C0Mct9j0AOmRQLyWw6
         5D6btKEhSRrblhttuZMLJpJ06Ev8cVoVK3bVSVQmxdiYta3xNnsE1LwyXNotj2j7oXij
         yqcONflQYllGmwXxeZjgG5zbU0FQEND+5jH3qMBG96ibDmLWnSq6DdpenOHJGBVzGViL
         dLS6Hgqse9zj5vTKbUfbdYQtv69sBzxr5e8XRwlu3AVASfahE/KYdC0NL3RrXyfejYnf
         sXw4So1MRU9yWr5ZwMEqeFjNtn4AKJJsvBWotE5EHkOfdM3r8f7ymO+8wo8XlBlL747k
         D4lw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to:from
         :content-language:references:cc:to:subject:user-agent:mime-version
         :date:message-id:dkim-signature;
        bh=MISDuJTMTLc7Y+x4ZuEkuU7xbhF+joQiePJkVnLfG8Y=;
        fh=A/oLInpLG4EcUC9/G+vRAglTv/tpyAt4LBfH3uOFrWU=;
        b=lO0555tNfSi+W9K/53wuctypnDoGfkyj5+yyrmk9r1GSWuI7XtFkOFpWG2+5oPGc24
         Lw3gxfFChtlfny34jRqKVZ2/aE23A+4T3EA25K0EEbYmHA6vjLdbT0rqx90AvtCIGgfY
         0V7ZKxmY0HkdMFCvJps4D4xBX2ymkfEZPCcYeY8lVYszKg6hWKTCPQYfo8pyOuJ+jN/g
         hayGBouGk3C+LHxwku6td96wahgu0XDovkPHnS9eFEEaewqh3sRrRwM3vdEGJWrCsirT
         i6OTgs4NfJFOHIAnSechHhxUzx8uCNpqzDuaIqqMCYUfgqV9FtPgySTlpJ8tKnMizs8D
         R36w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of gongruiqi1@huawei.com designates 45.249.212.188 as permitted sender) smtp.mailfrom=gongruiqi1@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756283681; x=1756888481; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:content-language:references:cc:to:subject:user-agent
         :mime-version:date:message-id:from:to:cc:subject:date:message-id
         :reply-to;
        bh=MISDuJTMTLc7Y+x4ZuEkuU7xbhF+joQiePJkVnLfG8Y=;
        b=HZ7XX+4W+6dd038Xw0iNI9VxlgvxDuekDzQOgswlVRd9S6DF+nF8rI+qmDv1aSz3lC
         LqBXf7wTfsEFCCbjb64Dc4NWE4LN8LInALXXX8vqjKC94oNKMCffmIDb0EGMMIuHMsy6
         ghG9iurakGJpJCYRr+nIgsfKP1sKvQSfRbcDp4rh1/gxvDllIf0/et0ymtk7SxrpJtTn
         tFbUohYriHkIr1fM11aavcXgq82MZiOLksmK2rsyqWVl0RLMEocfRybdH8uykfCpv8ss
         SkJU6ElHrOOMhe8jyps9+kwwP/pDePW5ibeac38YgL4MtuvSjPR9AuP4QtmMr4GBlpZm
         zNWQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756283681; x=1756888481;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:content-language:references:cc:to:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:from:to
         :cc:subject:date:message-id:reply-to;
        bh=MISDuJTMTLc7Y+x4ZuEkuU7xbhF+joQiePJkVnLfG8Y=;
        b=Iv3SXbcQxYMjMMTievCYWsQgLUe8+Ui4xllGTU+ZxbN0CX184WUteKwz+B5pcYLW29
         RmoM948NDZLaJpgt4uwldQTt5ZclFsK12p29KcHbsdwXu4t3l1Hl8K6TRDHzeyXZzicO
         +0H9pUytPFdltiwHfFa+efq/xdPFHN5hhfUQxMsOJc7JVtD2L2DqGztQKLNcj0NNsoek
         OaI350mjITz8ZezIaiY7W5sYX5GK2/I8wAfSjaaLmyYLWsPVtUE6w8r2FOnT0JKVa+ya
         kXU6qLumzlAvHZ6u/mu9839L0IUaXNaEj+t37wdzJ0HwtLS82rahVV39kvr3CygK/0u+
         ZiIw==
X-Forwarded-Encrypted: i=2; AJvYcCVYbd048vrY6VVw/vnzJwiNF99SoUYmN+i5ShlRT64OtGGekPbRUzK6Umxh7UQfWLNHgkBpYg==@lfdr.de
X-Gm-Message-State: AOJu0YyWn1ndfwt0iYIxh8sT1Wp3B6GF4t3jg5oBLH/MuS8w89IqKKf6
	34/n+szU9UdoTZha8NTZKmLN7jD5vmBE8n9Xn2dRI/YmdZN99y8/FsTt
X-Google-Smtp-Source: AGHT+IGUZWr4YuDke+fVuMaTolH4u7kh2/DJORhj4Gu9I8ERd69qsS3nYBSbfVXOvbc4pES8RGZOxQ==
X-Received: by 2002:a05:6214:2528:b0:70d:955e:567b with SMTP id 6a1803df08f44-70d971e8505mr190094536d6.33.1756283681472;
        Wed, 27 Aug 2025 01:34:41 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZf18HVGzLTuPgn1D1rXHHsaaC0IUCA9FWaHSfBMwGoB4Q==
Received: by 2002:a05:6214:29e7:b0:70d:e7ba:ea21 with SMTP id
 6a1803df08f44-70de7baee29ls1365986d6.1.-pod-prod-09-us; Wed, 27 Aug 2025
 01:34:40 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCU4rQEM5GEvAq1XqrbXv7ADUV+wcKNn/u00slUf3own53z9P9NbRgDtf8rWczNjIaZsEZgCSL/CoGE=@googlegroups.com
X-Received: by 2002:a05:6122:8c9:b0:530:7ab8:49ab with SMTP id 71dfb90a1353d-53c8a0d1923mr5833689e0c.0.1756283680022;
        Wed, 27 Aug 2025 01:34:40 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756283680; cv=none;
        d=google.com; s=arc-20240605;
        b=S2zXOWUh3QQZ6kerAx2hXA+FmzSdA3P9pYk/b6mYySZF1n6cEvoIzBwNuqfnRW0Cud
         IRs7EQuaSKGzsXdZd5CkZbW4Plp/h6YhahxcBtexVS+sLD5JwdvU3lsMYm/esdMW/dhg
         EUVhJskUV+8OKAXFp6iE3oTtx/PV7tNzQRFrnE/dnuPeLeLnIIlSmnq6+ACJIrN8ZLFo
         NSjLSA7O2Q7XyAtM1h3b8rD4E0O36j2TtLzsiqfNc3oxKQMhhAgrpPggjwwsOKRb/t6s
         5T5XhVB/WJFr93uV5M1LY9JmA2AfzvAR3C/J+8oV60IKUnEG/Y/K6g2C7stciAumoQ06
         W1zA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id;
        bh=JzkLrI8sqeFJUFJANuhx098MDlg2CjKbPr6/Bv0iHz4=;
        fh=uiVSDUgguTDAikDUF5ZB42yPyKHaL/67rtFFz0DtZ6Q=;
        b=h+QhQFZTnvhcqTAOAsSVruwuKi+2PdpT6/cFjj5bEUhUZUqFm/P2jgEobY+e5bCHtd
         INUW5DdxOnakdF/BNzbuVDOqzu3u8qweq3Hcp2gkuHvXNcu4QxvVcTDr+xhBzDKJJrn8
         id+GjDVcNKhu0kbMZgpq746Z7Skpr6fPt5f+Np5TlKRqCyMNvfv2UvHvhoqrDR3o+a3g
         ptIrnWNHjAah8YqDYv9mqcrAWsXyz8GhcRqPdzH8nK83L9XIMvSmTufNSGw9y9IW/uld
         BxkA9ayyQTVaeC6KgzAR6UfK59Pnrj6BzFoEl7XGjYqQIE+GjH6okd/W0chhnVpDgWF3
         zOZw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of gongruiqi1@huawei.com designates 45.249.212.188 as permitted sender) smtp.mailfrom=gongruiqi1@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
Received: from szxga02-in.huawei.com (szxga02-in.huawei.com. [45.249.212.188])
        by gmr-mx.google.com with ESMTPS id 71dfb90a1353d-5442d7d114asi96522e0c.1.2025.08.27.01.34.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 27 Aug 2025 01:34:40 -0700 (PDT)
Received-SPF: pass (google.com: domain of gongruiqi1@huawei.com designates 45.249.212.188 as permitted sender) client-ip=45.249.212.188;
Received: from mail.maildlp.com (unknown [172.19.88.105])
	by szxga02-in.huawei.com (SkyGuard) with ESMTP id 4cBd492l4szFrnD;
	Wed, 27 Aug 2025 16:29:29 +0800 (CST)
Received: from kwepemk100018.china.huawei.com (unknown [7.202.194.66])
	by mail.maildlp.com (Postfix) with ESMTPS id 8E97814011F;
	Wed, 27 Aug 2025 16:34:05 +0800 (CST)
Received: from [10.67.110.48] (10.67.110.48) by kwepemk100018.china.huawei.com
 (7.202.194.66) with Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.2.1544.11; Wed, 27 Aug
 2025 16:34:04 +0800
Message-ID: <0f718809-9efc-44a3-b45e-a0297f456f7d@huawei.com>
Date: Wed, 27 Aug 2025 16:34:04 +0800
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH RFC] slab: support for compiler-assisted type-based slab
 cache partitioning
To: Marco Elver <elver@google.com>
CC: <linux-kernel@vger.kernel.org>, <kasan-dev@googlegroups.com>, "Gustavo A.
 R. Silva" <gustavoars@kernel.org>, "Liam R. Howlett"
	<Liam.Howlett@oracle.com>, Alexander Potapenko <glider@google.com>, Andrew
 Morton <akpm@linux-foundation.org>, Andrey Konovalov <andreyknvl@gmail.com>,
	David Hildenbrand <david@redhat.com>, David Rientjes <rientjes@google.com>,
	Dmitry Vyukov <dvyukov@google.com>, Florent Revest <revest@google.com>, Harry
 Yoo <harry.yoo@oracle.com>, Jann Horn <jannh@google.com>, Kees Cook
	<kees@kernel.org>, Lorenzo Stoakes <lorenzo.stoakes@oracle.com>, Matteo Rizzo
	<matteorizzo@google.com>, Michal Hocko <mhocko@suse.com>, Mike Rapoport
	<rppt@kernel.org>, Nathan Chancellor <nathan@kernel.org>, Roman Gushchin
	<roman.gushchin@linux.dev>, Suren Baghdasaryan <surenb@google.com>, Vlastimil
 Babka <vbabka@suse.cz>, <linux-hardening@vger.kernel.org>,
	<linux-mm@kvack.org>
References: <20250825154505.1558444-1-elver@google.com>
 <97dca868-dc8a-422a-aa47-ce2bb739e640@huawei.com>
 <CANpmjNMkU1gaKEa_QAb0Zc+h3P=Yviwr7j0vSuZgv8NHfDbw_A@mail.gmail.com>
Content-Language: en-US
From: "'GONG Ruiqi' via kasan-dev" <kasan-dev@googlegroups.com>
In-Reply-To: <CANpmjNMkU1gaKEa_QAb0Zc+h3P=Yviwr7j0vSuZgv8NHfDbw_A@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Originating-IP: [10.67.110.48]
X-ClientProxiedBy: kwepems200001.china.huawei.com (7.221.188.67) To
 kwepemk100018.china.huawei.com (7.202.194.66)
X-Original-Sender: gongruiqi1@huawei.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of gongruiqi1@huawei.com designates 45.249.212.188 as
 permitted sender) smtp.mailfrom=gongruiqi1@huawei.com;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
X-Original-From: GONG Ruiqi <gongruiqi1@huawei.com>
Reply-To: GONG Ruiqi <gongruiqi1@huawei.com>
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



On 8/26/2025 7:01 PM, Marco Elver wrote:
> On Tue, 26 Aug 2025 at 06:59, GONG Ruiqi <gongruiqi1@huawei.com> wrote:
>> On 8/25/2025 11:44 PM, Marco Elver wrote:
>>> ...
>>>
>>> Introduce a new mode, TYPED_KMALLOC_CACHES, which leverages Clang's
>>> "allocation tokens" via __builtin_alloc_token_infer [1].
>>>
>>> This mechanism allows the compiler to pass a token ID derived from the
>>> allocation's type to the allocator. The compiler performs best-effort
>>> type inference, and recognizes idioms such as kmalloc(sizeof(T), ...).
>>> Unlike RANDOM_KMALLOC_CACHES, this mode deterministically assigns a slab
>>> cache to an allocation of type T, regardless of allocation site.
>>>
>>> Clang's default token ID calculation is described as [1]:
>>>
>>>    TypeHashPointerSplit: This mode assigns a token ID based on the hash
>>>    of the allocated type's name, where the top half ID-space is reserved
>>>    for types that contain pointers and the bottom half for types that do
>>>    not contain pointers.
>>
>> Is a type's token id always the same across different builds? Or somehow
>> predictable? If so, the attacker could probably find out all types that
>> end up with the same id, and use some of them to exploit the buggy one.
> 
> Yes, it's meant to be deterministic and predictable. I guess this is
> the same question regarding randomness, for which it's unclear if it
> strengthens or weakens the mitigation. As I wrote elsewhere:
> 
>> Irrespective of the top/bottom split, one of the key properties to
>> retain is that allocations of type T are predictably assigned a slab
>> cache. This means that even if a pointer-containing object of type T
>> is vulnerable, yet the pointer within T is useless for exploitation,
>> the difficulty of getting to a sensitive object S is still increased
>> by the fact that S is unlikely to be co-located. If we were to
>> introduce more randomness, we increase the probability that S will be
>> co-located with T, which is counter-intuitive to me.

I'm interested in such topic. Let's discuss multiple situations here.

If S doesn't contains a pointer member, then your pointer-containing
object isolation completely separates S against T. No problem, and
nothing to do with randomness.

If S does, then whether they co-locate is completely based on the token
algorithm, which has two problems: 1. The result is deterministic and so
can be known by everyone including the attacker, so the attacker could
analyze the code and try to find out an S suitable for being exploited.
And 2. once such T & S exist, we can't interfere in the algorithm, and
the defense fails for all builds (of the same or nearby kernel versions
at least).

Here I think randomness could help: its value is not just about
separating things based on probability, but more about blinding the
attacker. In this scenario, with randomness we could let the attacker
unable to find out the suitable S, so they couldn't exploit it even
though such S & T exist. As you mentioned (somewhere else), the attacker
might still be able to "take off the eye mask" and locate S & T by some
other methods, e.g. analyzing the resource information at runtime, but
that's not randomness to blame. We could do something else about that
(e.g. show less for random-candidate slab caches), and that's another story.

> 
> I think we can reason either way, and I grant you this is rather ambiguous.
> 
> But the definitive point that was made to me from various security
> researchers that inspired this technique is that the most useful thing
> we can do is separate pointer-containing objects from
> non-pointer-containing objects (in absence of slab per type, which is
> likely too costly in the common case).

Isolating pointer-containing objects is the key point indeed. And for me
it's orthogonal with randomness, and they can be combined to achieve
better hardening solutions.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/0f718809-9efc-44a3-b45e-a0297f456f7d%40huawei.com.
