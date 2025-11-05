Return-Path: <kasan-dev+bncBAABB4OSVTEAMGQERDRCPPY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x139.google.com (mail-il1-x139.google.com [IPv6:2607:f8b0:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id 6B4F3C35220
	for <lists+kasan-dev@lfdr.de>; Wed, 05 Nov 2025 11:39:47 +0100 (CET)
Received: by mail-il1-x139.google.com with SMTP id e9e14a558f8ab-4330bc0373bsf45209055ab.0
        for <lists+kasan-dev@lfdr.de>; Wed, 05 Nov 2025 02:39:47 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1762339186; cv=pass;
        d=google.com; s=arc-20240605;
        b=A+7H6NYqCy3uxU3gllKo3VSs+UqTGZA9ErSrVygMGvrr6KjcZpm13RpN1lsH8XoTyh
         7obcYY31tdY0mdPFKpiNL3Dh2nt5H40VsiJatXs3qiB0rBW4RnHL7VFy49MG5KlLn6A9
         d9plZ0VUwwj+RBvq1uEbJkTT0iVt0tG1GD7Fg/hXkrE3BHGdz71tPY597xm05c8s11vA
         3PTBjFQIfKlt1Fkqx0FcdqkgaoTdoOXKUmcl3F6mgeEMWc1z9ye6SyO/nJ773EZlWjEH
         4NXkHl0/nc4ZgjMuMyGQTwnYrHSYQDxspzlrkDLltmiGD2F7DOhnl4xW3tUjpC2hcTly
         2KCg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :mime-version:feedback-id:references:in-reply-to:message-id:subject
         :cc:from:to:date:dkim-signature;
        bh=Vzdp337VGlRvFmZpXYt3V2QS8u0M5OEM4R9La0hOAFY=;
        fh=fwtkQNTQX+8xQxXD4Mn7/ixZvumJOrQZBuSl+AUpcek=;
        b=B6ZTTd0x/2VRQT3QVttOqVgKHbLZCjopLewkl4q7om2tIK6XjZ6n0Oi6A/wFfidVHG
         Lwpvvp3PxHB5vZ1UDCEOmnY1udCXu/D23kbDpfa0faSYbL50WK/C0pLz7R0PjLSFeH9n
         Fct7i0zO3ASbVnNDoavtNv/ynPnf9IGOlGn6ajo614sV04VIOfxAN6/JfnUf/TN4Sdil
         +zSOs7u224cBbT2KiQIfhyRieh7fwAY1op2k+6YMyzXgvBtU1K7LZM0R5bbczKV2VMyi
         HE5yB5Tum1P4EPc2J8LGabJsNuSM7w5JKIeUsrizlnQ4yj3eOerzSSL4UDEXqH0EJ147
         L7/w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b=SXTGtxux;
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 109.224.244.17 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1762339186; x=1762943986; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:feedback-id:references
         :in-reply-to:message-id:subject:cc:from:to:date:from:to:cc:subject
         :date:message-id:reply-to;
        bh=Vzdp337VGlRvFmZpXYt3V2QS8u0M5OEM4R9La0hOAFY=;
        b=nNRJeCsZH07I3jy0y9X6Tl6z4TZIOleWAQlL8W1MnsvajOnnhpdZDgVgf7KuEiJnme
         BvwjKiD3LGhRjKIvrlR/xYCE9KEOhwQbQCePHSxhPtZscnMqRGCjSADOO05FYcnyd9Lt
         hx073R25meKD4s+CAfJoEX3xdoZ0cK6mvtD3qylcC7NAC0sGXWgW6EvcGJz4V8c9C0Xy
         xmYOPlbcKNau8wmKQBMOQ5MyvClRC2NRQPeMC87jNCmjYiUqZfz7BGEIdrWOCzfXZ1sj
         nlma1Q+QoZpR8sDar1ThW6aPiS+y0ynelhIN/Gaps8HkM/UFyvcRWxDsoAfjg6B4SpTe
         IPeg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1762339186; x=1762943986;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:feedback-id:references
         :in-reply-to:message-id:subject:cc:from:to:date:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=Vzdp337VGlRvFmZpXYt3V2QS8u0M5OEM4R9La0hOAFY=;
        b=UceugdlCfTedK6tp3hBy6KfkIGFyWPYmK7zL417WFiqThAIy229ysKRFuGI4uBat7A
         +S+fTKWmkV+AgVTuA3kChFJ7Hn447/1+aK2rMvTjthgWXt/ENUY0vGBrPX/lkaVJZiD2
         ScgvfcSq5W/vafAZlR7cNqwl6kdVnoCk4JCYOP01sy/KAj0yD+v7d6BiB7IeLkzLL6YY
         /aJ4NZWc2xG5bP9+YGVxmWsmkI+zXBKxHvqLlw6C8yqa0WsQPJmeO0TFKKSjgIzZj74L
         ssPeXe+YpOIMhrze4wYe9pVG4ZdqrSWFjZSUvpM5wHND1kWxEXhVzmhX8PDWoZXVHITj
         lwXQ==
X-Forwarded-Encrypted: i=2; AJvYcCWr1/1R2m5xWGYd/ihzpAspbp3DOQZUUnfPwNpNs98C6rTW+qyY8IaHL2nqrBoTecDqjeW8AQ==@lfdr.de
X-Gm-Message-State: AOJu0YwmXKCylarqgYU43iQHHxXp8a9g9apmTwSVS6mjDf0OxW8I1fMj
	dmP6ZuBh/1bhkj9xZknymaYKYXM5wtHCl1liLwvbvbiHi7fghkSdTbvT
X-Google-Smtp-Source: AGHT+IFZVoikJCDAIq0tOiOi5e+Ypyv78Y8SmgJNi/c2NxoZgr/Kuky2zHxesJ3Tu1qb9sT7MdWJ2w==
X-Received: by 2002:a05:6e02:218e:b0:433:23ba:2d84 with SMTP id e9e14a558f8ab-433407bd2admr36252955ab.17.1762339185584;
        Wed, 05 Nov 2025 02:39:45 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+Yf1Iz/xEgUhHOgjeGXQdRGyjv9ZoFI9+1zBRI71soBFg=="
Received: by 2002:a05:6e02:2284:b0:433:23c0:78a4 with SMTP id
 e9e14a558f8ab-43323c07907ls24205635ab.0.-pod-prod-09-us; Wed, 05 Nov 2025
 02:39:44 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCU1SEi4uA19ZdT0GEXy5/ZiMzhLK9QV4iKoU/JDWNGEQB5fVn1G9AmFwz+EHcwOS3YV18V868aUCik=@googlegroups.com
X-Received: by 2002:a05:6e02:1606:b0:433:305c:17af with SMTP id e9e14a558f8ab-43340759956mr36549415ab.3.1762339184747;
        Wed, 05 Nov 2025 02:39:44 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1762339184; cv=none;
        d=google.com; s=arc-20240605;
        b=Bg2jGvccZdkfQbY9YL0BW+JdxOo7JJPtLQN1YXGuWilT1cF44fx6z2Y9dlRU+z+I6r
         +TSr8etQeAuV+4RAl6JUrOH3ksz1EsArhqi8m1MZqoJyRxdwZa7nV1kUzajQ1r7jEPUc
         OCYFvr72aDWhAZKrnrhngccdsHalkY8Mnie4xKQNeButtvucrZSj2/X60owrCdvngtG5
         q19E1Ptt1IlWBBM3EyRd5Rr9xJ7KhZ/be8zbQ+o6yj/g8FNKXp1+S8JVqDRaL7y2s1qf
         kiVf3bpHtHBUyTrn2x6ybyNZuM+lI2je15ELhR56NqjZV4dKQpsBzE3TDjZQu2KOyPaS
         pXeA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:feedback-id:references
         :in-reply-to:message-id:subject:cc:from:to:date:dkim-signature;
        bh=fZU25+bCLq4D6+jp/5EA8hJsFqIIvHsWyKp0ucrZ3c0=;
        fh=Cvpzw1/aPXEbuHCPyG4yq36mGL8iCdye5fDQMtauQ/k=;
        b=iqW9GibeaPzOL0VvWxaXIGbWcQVB5ZmDV4yVlmVdTBZk/c6oGUlUGde/rocq4GQQpL
         4qqc3rjJe2z1m7VPhgfI5XnqkxWWayKrBjFBU3GtK40o3l+NldqRa8lz+cqQx6Ukaynz
         mpoAHjCvrpcAvQ2wZYjdoMXbp41Z/id5sSLSJkzk+/YxxksnP3RyJzrEJNMRF1bcXosa
         t/1BYSQfhfOdcTpXHDXRA2vR0EcHs3uXkObNegDs+Aw636lOrMMbb4KuHd70NQfVz77A
         GdywA5+w2KLMbns0oYFP8uP/8aG7NFq+KQTlGsqlibo4JJyGmGVe4psVS7PFpf+NvNlb
         5tHA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b=SXTGtxux;
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 109.224.244.17 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
Received: from mail-24417.protonmail.ch (mail-24417.protonmail.ch. [109.224.244.17])
        by gmr-mx.google.com with ESMTPS id e9e14a558f8ab-4334bf8abc0si211795ab.0.2025.11.05.02.39.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 05 Nov 2025 02:39:44 -0800 (PST)
Received-SPF: pass (google.com: domain of m.wieczorretman@pm.me designates 109.224.244.17 as permitted sender) client-ip=109.224.244.17;
Date: Wed, 05 Nov 2025 10:39:37 +0000
To: Andrey Konovalov <andreyknvl@gmail.com>
From: "'Maciej Wieczor-Retman' via kasan-dev" <kasan-dev@googlegroups.com>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, Andrew Morton <akpm@linux-foundation.org>, Uladzislau Rezki <urezki@gmail.com>, Marco Elver <elver@google.com>, stable@vger.kernel.org, Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>, Baoquan He <bhe@redhat.com>, kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, linux-mm@kvack.org
Subject: Re: [PATCH v1 1/2] kasan: Unpoison pcpu chunks with base address tag
Message-ID: <uhjap3ppoeglldgbu7wtsz57dqmtbntwfssnqfbsnkebni2mdm@7i67d3zoxqbe>
In-Reply-To: <CA+fCnZefD8F7rMu3-M4uDTbWR5R8y7qfLzjrB34sK3bz4di03g@mail.gmail.com>
References: <cover.1762267022.git.m.wieczorretman@pm.me> <821677dd824d003cc5b7a77891db4723e23518ea.1762267022.git.m.wieczorretman@pm.me> <CA+fCnZefD8F7rMu3-M4uDTbWR5R8y7qfLzjrB34sK3bz4di03g@mail.gmail.com>
Feedback-ID: 164464600:user:proton
X-Pm-Message-ID: c3c3d40e79cb1f13113d2e16d176828d0dc0a69a
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: m.wieczorretman@pm.me
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@pm.me header.s=protonmail3 header.b=SXTGtxux;       spf=pass
 (google.com: domain of m.wieczorretman@pm.me designates 109.224.244.17 as
 permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
X-Original-From: Maciej Wieczor-Retman <m.wieczorretman@pm.me>
Reply-To: Maciej Wieczor-Retman <m.wieczorretman@pm.me>
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

On 2025-11-05 at 02:12:49 +0100, Andrey Konovalov wrote:
>On Tue, Nov 4, 2025 at 3:49=E2=80=AFPM Maciej Wieczor-Retman
><m.wieczorretman@pm.me> wrote:
>>
>> From: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
>>
>> A KASAN tag mismatch, possibly causing a kernel panic, can be observed
>> on systems with a tag-based KASAN enabled and with multiple NUMA nodes.
>> It was reported on arm64 and reproduced on x86. It can be explained in
>> the following points:
>>
>>         1. There can be more than one virtual memory chunk.
>>         2. Chunk's base address has a tag.
>>         3. The base address points at the first chunk and thus inherits
>>            the tag of the first chunk.
>>         4. The subsequent chunks will be accessed with the tag from the
>>            first chunk.
>>         5. Thus, the subsequent chunks need to have their tag set to
>>            match that of the first chunk.
>>
>> Refactor code by moving it into a helper in preparation for the actual
>> fix.
>>
>> Fixes: 1d96320f8d53 ("kasan, vmalloc: add vmalloc tagging for SW_TAGS")
>> Cc: <stable@vger.kernel.org> # 6.1+
>> Signed-off-by: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
>> Tested-by: Baoquan He <bhe@redhat.com>
>> ---
>> Changelog v1 (after splitting of from the KASAN series):
>> - Rewrite first paragraph of the patch message to point at the user
>>   impact of the issue.
>> - Move helper to common.c so it can be compiled in all KASAN modes.
...
>> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
>> index d4c14359feaf..c63544a98c24 100644
>> --- a/mm/kasan/common.c
>> +++ b/mm/kasan/common.c
>> @@ -28,6 +28,7 @@
>>  #include <linux/string.h>
>>  #include <linux/types.h>
>>  #include <linux/bug.h>
>> +#include <linux/vmalloc.h>
>>
>>  #include "kasan.h"
>>  #include "../slab.h"
>> @@ -582,3 +583,13 @@ bool __kasan_check_byte(const void *address, unsign=
ed long ip)
>>         }
>>         return true;
>>  }
>> +
>> +void __kasan_unpoison_vmap_areas(struct vm_struct **vms, int nr_vms)
>> +{
>> +       int area;
>> +
>> +       for (area =3D 0 ; area < nr_vms ; area++) {
>> +               kasan_poison(vms[area]->addr, vms[area]->size,
>> +                            arch_kasan_get_tag(vms[area]->addr), false)=
;
>
>The patch description says this patch is a refactoring, but the patch
>changes the logic of the code.
>
>We don't call __kasan_unpoison_vmalloc() anymore and don't perform all
>the related checks. This might be OK, assuming the checks always
>succeed/fail, but this needs to be explained (note that there two
>versions of __kasan_unpoison_vmalloc() with different checks).
>
>And also we don't assign a random tag anymore - we should.

Thanks for the pointers, I'll revise the two versions and make it an actual
refactor.

>Also, you can just use get/set_tag(), no need to use the arch_ version
>(and in the following patch too).

Thanks :)

--=20
Kind regards
Maciej Wiecz=C3=B3r-Retman

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/u=
hjap3ppoeglldgbu7wtsz57dqmtbntwfssnqfbsnkebni2mdm%407i67d3zoxqbe.
