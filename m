Return-Path: <kasan-dev+bncBAABBRHCVTEAMGQEGOQYOQQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x337.google.com (mail-wm1-x337.google.com [IPv6:2a00:1450:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id 8CC2DC354CF
	for <lists+kasan-dev@lfdr.de>; Wed, 05 Nov 2025 12:13:15 +0100 (CET)
Received: by mail-wm1-x337.google.com with SMTP id 5b1f17b1804b1-46e39567579sf35701685e9.0
        for <lists+kasan-dev@lfdr.de>; Wed, 05 Nov 2025 03:13:15 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1762341189; cv=pass;
        d=google.com; s=arc-20240605;
        b=VRP3plbWIA7SQvIcybfbNrI0/taAbc+SLqK4mQ64CzewNWr0vD/cKJepfMDxI7ePTj
         /c+JaWqyaics+1GOODc+JImjR/DEJZ6PLCys6vBSwLqJ7OhOF/XqWpF+XoNdFKrxNWaP
         JVAr9BapqdOlyEsKl+ulp9Mf3h0m13ZmkcTxjyjwgs/8ZrszahRYIAUvTm3NRctuy8ey
         OGmTOTD2vMaO0z9FUn61VKjnf9FKXYmWnB37/ugtuRjqB4glJhkaQUJV23duXcY0oUzK
         MAAgmC7dA51WqgpCbggsTqcEqDXlduPYrLVHyxErcP8PRfm4qIMOk34WPxymRP8momib
         cJKQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :mime-version:feedback-id:references:in-reply-to:message-id:subject
         :cc:from:to:date:dkim-signature;
        bh=k4ESG9qw2o5R5NA1ZVwLmot6D2Psb+2M6IuWXIaa0/M=;
        fh=ckp6koxTjNLMfLxaZjiBj0JsqaaqvRvdKk7SRkmGy6U=;
        b=Z8tPDfwon0AbKvmyhEbvhLnxdTYi1uPpJrF5T+UgBh/nvceXSJQh7HjC63oFGQWNAM
         exupwFWJfMO5AgXKEZexBpeAJ59o6GS9MIJGojGjgog7w8K/Hc/BCOe5d++20hwKWaLM
         QQ+pehZQzfY33VOW7LOjj3tW/wUYjpWzy7Z7vAfySUeYcInPh5q0Hsay749o0n2Zj/Od
         A0b8WpmS29Xe9z8u/mGAhjH0xf41tkcV9MazqHqXZSyjjUdO4d16E41tt9KJur+nwwTl
         AMi2l42rx6BWzQr1Mc4VanlYWYQvWmrn5kmyViG4WKJiMXsR/bjdMxEANVrg2aJglyQx
         7HKw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b=IynIMTyr;
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 79.135.106.30 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1762341189; x=1762945989; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:feedback-id:references
         :in-reply-to:message-id:subject:cc:from:to:date:from:to:cc:subject
         :date:message-id:reply-to;
        bh=k4ESG9qw2o5R5NA1ZVwLmot6D2Psb+2M6IuWXIaa0/M=;
        b=tz+OmToZt7lB/FBVgUVdtAiBSqyLfZTMKq4y3phExsgRo5Ueyr3vQ5MRQAQQSb2J9P
         XjbCbdRISJD/efAJzEfLsaKukkQwRV3BSYSzugvLSkDoz083WY/VtwZptPiU0iCcBlM+
         fJEWge24KEL35L8TbJoanXI6U+5v7izXtpdLVGLSNheBT4FiIn6cxIH7Hb1DoVC7qO3N
         0l4GBI4nmXgC1ta1NoezFeZ6Ee768hghJ7vQITlMaEhNe2plQHs19VoMf5yyqjY4J025
         CqSnoXbRKOd8MrQHiveBJQyVmxrLakFb1L/W8enH9dbzQ7qATeDp21+wY38EeaBxD90u
         rzZg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1762341189; x=1762945989;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:feedback-id:references
         :in-reply-to:message-id:subject:cc:from:to:date:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=k4ESG9qw2o5R5NA1ZVwLmot6D2Psb+2M6IuWXIaa0/M=;
        b=lBna/sEX2Wq2sdzD/RGdQagwCM1dpjTUFZWyrQU+XXGpNRVKLyai/NyW3GQaGQXIqy
         o0IqWJRkoqnLGbvldSiMLerQJNadp2RBHo0+WyThEeVAYhjp/PsOn7Tu/jZnKfXz9aqM
         X4oMkPct1ZtaG8OZdTAMK9SYvfa0n5hC73Do6JaKToQpItcdquMGcwtuu8HDJz4nt+xf
         fWMonLn7CulslsWkIRNBx3RqRSBdTdWRfjR4lhd1T/K/WtP3+5H9eOknOloLfypHcXMc
         R4rxeW2EP/c8aFFiJHg/wH1eV/2mLlmOUzvtrijDKxW1n7WiSStqgnF/WSFliguxfiBt
         ZveA==
X-Forwarded-Encrypted: i=2; AJvYcCXvnRq+vhzdIyUyluFQpnesuLhfLJdETVOHn6VXRkN2O434+tUbsIZDEtXx+AotBUiaB/sq8g==@lfdr.de
X-Gm-Message-State: AOJu0Yx0zLJl2w6J7qHLrVfXcFX+19qL3PGvXlzpVG0Ybw9luqFkPRkF
	NTjr8sIb2TewC692dBk5Mx6TXyNsoHtwtK160S+j3FZ4glOlEyCoaBgX
X-Google-Smtp-Source: AGHT+IGAxcWVmO8FD0NdUIZYH38DO3phgED9hlk6CpYLKp5jP+Y3Lx5hEob25x5LZcWaVUtqupE8Zw==
X-Received: by 2002:a05:600c:1382:b0:46f:d682:3c3d with SMTP id 5b1f17b1804b1-4775cdc726dmr21582915e9.13.1762341188974;
        Wed, 05 Nov 2025 03:13:08 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+Y8xXqYJrbW08DLTsZnTmXHfESqxvlU03eVb9GasFe8vA=="
Received: by 2002:a05:600c:468c:b0:477:5e4a:eca7 with SMTP id
 5b1f17b1804b1-47760fc27b9ls548865e9.0.-pod-prod-08-eu; Wed, 05 Nov 2025
 03:13:07 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUID7CxpLxmsrQBcvQK141DA9BNFqODMCi/2tzlerc2mPMnyeWCywmmA4MSkdn5Zl3fPcaD3qj6pRc=@googlegroups.com
X-Received: by 2002:a05:600c:34d0:b0:471:6f4:601f with SMTP id 5b1f17b1804b1-4775cdf54aemr24191465e9.19.1762341186996;
        Wed, 05 Nov 2025 03:13:06 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1762341186; cv=none;
        d=google.com; s=arc-20240605;
        b=gXLVUplrg5vyRAZR+vJogkQEmQfVkdGxPpOBNeMtIfxh8VN3bRDIkNaET8gu/C+p4V
         gm4pwQS+cxPLx4WvTj8UwuXyWp0tmHsDWl7rva8ZnNIYZiIFQgX/eeQ7f9IFdHKL0fCr
         WOgZyIKOn1xETXxn2/Q54VAalo4Qcjhyz+Pjag+tmfAeJuxWpSyW8SFVUPDvsTCJQRkF
         eZnzNuxHp/dX8g1MOueUyDfp2eGASTGmlqn/to+E1rBWe4DtkYDyVEwv17MiFMD5JdVx
         wetnFkSTy51qMwGdg5JgFMP8im5saEWgeoeUy2cMqSHIqf0ybJf6TOfUz+k/KdjaTKAy
         v8Cg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:feedback-id:references
         :in-reply-to:message-id:subject:cc:from:to:date:dkim-signature;
        bh=MhOL772gDQt3HjlEW0CKt9Wxom0RYSxrQeQWZ+rjImo=;
        fh=rgZHhg1emZNSc6VpJ5ZqW4472tedhmvncr7Y07ng0Zo=;
        b=Xi4RkmfIMWZEX++yr9h1j8TnUut9Xgcdr2lCp5ZmhmLccejLfumiwc41G8H7n44/o9
         YWiKdFOQlUBWLDDjv8QCzdpzAodBDTbyoOcVm4Xni27c6ab+w0GwGQgDaWoMrAPG8jZi
         eRS9ujzWXflgrtrQprr9OZ8OGICV9EBzJCPZvx5eoA73UEftVd6xB6VjOtm4VogZ3WQD
         kX2zsirmxO9ZPtZJEBCGTGwDVyt/OdZBFO5mvaSqol33ZXmOx9xDbr/ChuLCWvZ5ssfq
         9cXYAEUeNJNregZaEsys32Ytlce68f3ZSGiqNYQu6FBhE5bM0PTtFGUX4daJQptFfySx
         o31Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b=IynIMTyr;
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 79.135.106.30 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
Received: from mail-10630.protonmail.ch (mail-10630.protonmail.ch. [79.135.106.30])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-4775cdc9533si158975e9.2.2025.11.05.03.13.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 05 Nov 2025 03:13:06 -0800 (PST)
Received-SPF: pass (google.com: domain of m.wieczorretman@pm.me designates 79.135.106.30 as permitted sender) client-ip=79.135.106.30;
Date: Wed, 05 Nov 2025 11:13:00 +0000
To: Andrey Konovalov <andreyknvl@gmail.com>
From: "'Maciej Wieczor-Retman' via kasan-dev" <kasan-dev@googlegroups.com>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, Andrew Morton <akpm@linux-foundation.org>, Marco Elver <elver@google.com>, stable@vger.kernel.org, Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>, Baoquan He <bhe@redhat.com>, kasan-dev@googlegroups.com, linux-mm@kvack.org, linux-kernel@vger.kernel.org
Subject: Re: [PATCH v1 2/2] kasan: Unpoison vms[area] addresses with a common tag
Message-ID: <cc4xh64s47ftujtp76hizmjqaczbgpzvmpbtzjtya2tuqyc75x@3obiajea2eem>
In-Reply-To: <CA+fCnZdUMTQNq=hgn8KbNwv2+LsRqoZ_R0CK0uWnjB41nHzvyg@mail.gmail.com>
References: <cover.1762267022.git.m.wieczorretman@pm.me> <cf8fe0ffcdbf54e06d9df26c8473b123c4065f02.1762267022.git.m.wieczorretman@pm.me> <CA+fCnZdUMTQNq=hgn8KbNwv2+LsRqoZ_R0CK0uWnjB41nHzvyg@mail.gmail.com>
Feedback-ID: 164464600:user:proton
X-Pm-Message-ID: 9bc93b4823ad8fa97869a332ca0a7f37c2bec3e2
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: m.wieczorretman@pm.me
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@pm.me header.s=protonmail3 header.b=IynIMTyr;       spf=pass
 (google.com: domain of m.wieczorretman@pm.me designates 79.135.106.30 as
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

On 2025-11-05 at 02:13:22 +0100, Andrey Konovalov wrote:
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
>> Unpoison all vm_structs after allocating them for the percpu allocator.
>> Use the same tag to resolve the pcpu chunk address mismatch.
>>
>> Fixes: 1d96320f8d53 ("kasan, vmalloc: add vmalloc tagging for SW_TAGS")
>> Cc: <stable@vger.kernel.org> # 6.1+
>> Signed-off-by: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
>> Tested-by: Baoquan He <bhe@redhat.com>
>> ---
>> Changelog v1 (after splitting of from the KASAN series):
>> - Rewrite the patch message to point at the user impact of the issue.
>> - Move helper to common.c so it can be compiled in all KASAN modes.
>>
>>  mm/kasan/common.c | 10 +++++++++-
>>  1 file changed, 9 insertions(+), 1 deletion(-)
>>
>> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
>> index c63544a98c24..a6bbc68984cd 100644
>> --- a/mm/kasan/common.c
>> +++ b/mm/kasan/common.c
>> @@ -584,12 +584,20 @@ bool __kasan_check_byte(const void *address, unsig=
ned long ip)
>>         return true;
>>  }
>>
>> +/*
>> + * A tag mismatch happens when calculating per-cpu chunk addresses, bec=
ause
>> + * they all inherit the tag from vms[0]->addr, even when nr_vms is bigg=
er
>> + * than 1. This is a problem because all the vms[]->addr come from sepa=
rate
>> + * allocations and have different tags so while the calculated address =
is
>> + * correct the tag isn't.
>> + */
>>  void __kasan_unpoison_vmap_areas(struct vm_struct **vms, int nr_vms)
>>  {
>>         int area;
>>
>>         for (area =3D 0 ; area < nr_vms ; area++) {
>>                 kasan_poison(vms[area]->addr, vms[area]->size,
>> -                            arch_kasan_get_tag(vms[area]->addr), false)=
;
>> +                            arch_kasan_get_tag(vms[0]->addr), false);
>> +               arch_kasan_set_tag(vms[area]->addr, arch_kasan_get_tag(v=
ms[0]->addr));
>
>set_tag() does not set the tag in place, its return value needs to be assi=
gned.

Right, not sure how I missed that

>
>So if this patch fixes the issue, there's something off (is
>vms[area]->addr never used for area !=3D 0)?

Maybe there is something off with my tests then. I'll try to run them in a
couple of different environments.

--=20
Kind regards
Maciej Wiecz=C3=B3r-Retman

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/c=
c4xh64s47ftujtp76hizmjqaczbgpzvmpbtzjtya2tuqyc75x%403obiajea2eem.
