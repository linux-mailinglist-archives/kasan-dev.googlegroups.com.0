Return-Path: <kasan-dev+bncBAABBTWIYHEQMGQEE6GADSA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33f.google.com (mail-wm1-x33f.google.com [IPv6:2a00:1450:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id D5159C9FED0
	for <lists+kasan-dev@lfdr.de>; Wed, 03 Dec 2025 17:24:47 +0100 (CET)
Received: by mail-wm1-x33f.google.com with SMTP id 5b1f17b1804b1-4775f51ce36sf52412385e9.1
        for <lists+kasan-dev@lfdr.de>; Wed, 03 Dec 2025 08:24:47 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1764779087; cv=pass;
        d=google.com; s=arc-20240605;
        b=XMJRY/TgpZ/Kl0Qx4KJ+Kcb16EJzMUAvkbI+FCmaVTkw2w2W5pbKZXEk0at79gS/sG
         g+x50M7JN+6fngIT+ayQaW63wZZGHlStXHrSA784MSsTOjVLlBOcv320uu9W4GRNx7s+
         JH5GbeTto+rHs33iQVtrjJnB1ef95PWEfXzqF5hX7h9oLODz0r40hU1cyNTWcejg6Wsh
         b4YDNhSgFCEzyyDKjzJHyTN2q9KIaAEEQZHYPgTVFhYU/lzTwQba23dpv8DWRobGnRao
         ym6PUgalS/HDE4ip0az5WymFZm+oRTsVOJB+tudnfnPI3VkyvZ2xLhxwRzwwruXmGyeA
         B5JQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :mime-version:feedback-id:references:in-reply-to:message-id:subject
         :cc:from:to:date:dkim-signature;
        bh=Q7b6herwthvWJxo7k1OeZTv550r1WqBkyHZgbkmPvSg=;
        fh=Q+gf+EQJVLMntOH4sRViZt9k//Oasl8C+bZ6iLHSXjo=;
        b=PTHpgSlZJ/j4UsUjns16rSPGQ4HF0Zg5yBR9Fl+l58EGBc/XIWmzztgW4Lx1gJOq0l
         5hKwQ+HxNW+ZQVvtr++3r6SGTv/NHCVYCgRb9mcd16nRjTmnx6OhM55TYNIZdIdO8F48
         8LiMndqelPuFl7azvxawNJ1D1OsrwtOkNJEYB5OBJsUWZEEyzl/jdCbZrq/8RFaT7M1F
         RBGfrsHDWspCCml9yQUH6lgF4Y9LHcIHlsPNffm78H/yXIuzimmqNPVC4KZMNJRmHLEE
         ujFliBw1AFDr95qBc9+ZxZU07ncwnXjtkSjUHzYlNgunufjBw5atTMPSxb6BpIcR19ch
         gZ7w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b=lEgqJXRZ;
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 79.135.106.31 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1764779087; x=1765383887; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:feedback-id:references
         :in-reply-to:message-id:subject:cc:from:to:date:from:to:cc:subject
         :date:message-id:reply-to;
        bh=Q7b6herwthvWJxo7k1OeZTv550r1WqBkyHZgbkmPvSg=;
        b=c7I92yS0xzFBq3dnpqBRbW6gpOyUuF8c9Plyco26afx1yjjsb90y29OlWcaqfMdPL+
         YqYwVS1D9CgAnJSb2hnK6DeMg4Dz+EpZ2ERCe+EGUW7v2GzEKHNrsVPYFOKfN44aGlJq
         krt9w0vu7p+YZw3PfnglYIn6Oc+e2Em2t5yJOLiXcTZqnVoazMCrfRBPibKxeH7VOvf9
         xuZo2mfaglU9GrZR7h7gjFO/zAhxCFX26MA8+yIX+LL1RRKFZcWFFW1gxF2i5cc+zned
         4SBj3KGPkv2EQ8DjueCRN8Rhzp8CzJWehPfKyfRkfgD/6zP9zD9Oa476MZT4heu5H2+e
         QFhg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1764779087; x=1765383887;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:feedback-id:references
         :in-reply-to:message-id:subject:cc:from:to:date:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=Q7b6herwthvWJxo7k1OeZTv550r1WqBkyHZgbkmPvSg=;
        b=RtZsGQiLV7vHiz8RyR5HEBl/gJzu9aEztiZ7Es6UrKjzjyu6dNTvLL+4zC1u1w76gC
         1FdMulJFKy6BKJUHGHI9snDSpMSdC5O0aXA5q6nC4KwEXnJ20dIe3+qL0nn4pPZaChAY
         NggES8UUFRDR5Aw22N42dVcUXO2WG6uiL49+R8QUehGsvH9NcBBUFQIFFSuuGZJ74UJu
         Cl16VTMZOvZZ9QAHm/xXoF0j23pf3gUEwWF8X9vO5/uXuLd8z0xVWTIzpU5AIYoyYS06
         t9B/kw0AbHpVLOtam+ruk4k3aae5QWDDMkUj0zbB0UZnA/cjWfrNY4iXyVlVr0Pocdno
         au1w==
X-Forwarded-Encrypted: i=2; AJvYcCVXQue+PdZPkI0xuY3ZTCYZVqk93Ft0WCuzV7FF7BBSdqA8r/uVN15aNic+/Ro8yzyR6iXpMA==@lfdr.de
X-Gm-Message-State: AOJu0Yz4s5tP1VH8O49RQehvRVXTOPmad92FLaPVU0Fb2Fni4M+PS/dW
	UuVix3teUR2K99Nb3+GRRIonDhSQLDzp/iywUOrt/TNQRU0iwoYeOKji
X-Google-Smtp-Source: AGHT+IH0aWVIITvondhfWWsXJ7CgI4/7U4SD/OMwXhxcx4xhPSyU8/fGEkByrX2WgBwmHWSM3E1lvA==
X-Received: by 2002:a05:6000:2c07:b0:42b:3ed2:c079 with SMTP id ffacd0b85a97d-42f731a2fccmr3364863f8f.48.1764779087043;
        Wed, 03 Dec 2025 08:24:47 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+YImBdLftxDjrjUExZqvdX9skcIdAZMchd39rJkflWoeA=="
Received: by 2002:a5d:64c7:0:b0:426:fc42:689f with SMTP id ffacd0b85a97d-42e1b4ac228ls4831290f8f.2.-pod-prod-05-eu;
 Wed, 03 Dec 2025 08:24:45 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCW25tNCdk04O4I00xVY1/ghtF3t5YvirRTMZ67NTGUmL5SWV2RWl3db8Mhzj7RE8u/r4IURdEcbHWk=@googlegroups.com
X-Received: by 2002:a05:6000:40cc:b0:42b:2e39:6d58 with SMTP id ffacd0b85a97d-42f731bc534mr2857666f8f.51.1764779084936;
        Wed, 03 Dec 2025 08:24:44 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1764779084; cv=none;
        d=google.com; s=arc-20240605;
        b=jhNGQYlbDoEJH6WQaKPTCOR8wazLC/Pzn4j3/vEw5m6ZqEeV/7yBo1o3nPzbjOImXe
         /17K50XZrv0FdQSXnS/pVonA+uVDqFBN5PyTaNeMU3MClUWbyI//I/d8m7wuXd7qpg04
         s7v4d5QwT5WtX0xca/5d9PE8VTS0rRz9KGCUOoIWLosq10v8H5fAwp3FAAruMNEJivwN
         flYyuRgGd+3HEOVOOKNAsg/W2k01JfOBPajhOXPWPMybEp87OAlmW7ubknUpzfP8oEy6
         5kSqb3wHqA8NpMKUnr5GGzu3wUHGDopx+M82ESzmS0B5GvK33/JtgHjxHwX0G8qKBn44
         zJZg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:feedback-id:references
         :in-reply-to:message-id:subject:cc:from:to:date:dkim-signature;
        bh=uYhB0X4kqL3Bw7rIqDJ1oTSdN5flbXlU0EovctUC5cg=;
        fh=QzcK2Dcdv6K6M4pd0fn+L+4VbdC8Fq6FyGZNcuDHObw=;
        b=BzdomXVk9vkX0EvKwvxu78DBNdMJwDrz3MSYpNnU7T2bseFoXWz2frMDqgG/ZxYTZH
         JwaZq8Sp9Mj+j+q0yljnAv46gZVt/O+yzzFjrcGGZNwvwUdBG8gk6lMdSWBMo7+0LTw4
         tVf3M5csZnMslCsmx8R3WRcSv02JHbPJ8FfhMISdgvJWGst5HjMOZY6UXBcCifyxszV0
         Lh3hOFbivlZsxXlMNQNsqrQwwNNR015r1bCDt4Kftbr4OGeu+kH/5na9GWVIf+XlS2WT
         hlo+cM2R3UY9kVxTnvsa7usudff4HKhZhs6PGWFbTVsooRJA6tIQUk1OtqYJswA+EHZT
         Qydg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b=lEgqJXRZ;
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 79.135.106.31 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
Received: from mail-10631.protonmail.ch (mail-10631.protonmail.ch. [79.135.106.31])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-42e1c5d1ce6si236639f8f.2.2025.12.03.08.24.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 03 Dec 2025 08:24:44 -0800 (PST)
Received-SPF: pass (google.com: domain of m.wieczorretman@pm.me designates 79.135.106.31 as permitted sender) client-ip=79.135.106.31;
Date: Wed, 03 Dec 2025 16:24:36 +0000
To: Andrey Konovalov <andreyknvl@gmail.com>
From: =?UTF-8?Q?=27Maciej_Wiecz=C3=B3r=2DRetman=27_via_kasan=2Ddev?= <kasan-dev@googlegroups.com>
Cc: jiayuan.chen@linux.dev, Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, Andrew Morton <akpm@linux-foundation.org>, Marco Elver <elver@google.com>, stable@vger.kernel.org, Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>, kasan-dev@googlegroups.com, linux-mm@kvack.org, linux-kernel@vger.kernel.org
Subject: Re: [PATCH v2 2/2] kasan: Unpoison vms[area] addresses with a common tag
Message-ID: <phrugqbctcakjmy2jhea56k5kwqszuua646cxfj4afrj5wk4wg@gdji4pf7kzhz>
In-Reply-To: <CA+fCnZdzBdC4hdjOLa5U_9g=MhhBfNW24n+gHpYNqW8taY_Vzg@mail.gmail.com>
References: <cover.1764685296.git.m.wieczorretman@pm.me> <325c5fa1043408f1afe94abab202cde9878240c5.1764685296.git.m.wieczorretman@pm.me> <CA+fCnZdzBdC4hdjOLa5U_9g=MhhBfNW24n+gHpYNqW8taY_Vzg@mail.gmail.com>
Feedback-ID: 164464600:user:proton
X-Pm-Message-ID: 4ee2cb0b262a61c236058e955b9c6d1886736ca1
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: m.wieczorretman@pm.me
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@pm.me header.s=protonmail3 header.b=lEgqJXRZ;       spf=pass
 (google.com: domain of m.wieczorretman@pm.me designates 79.135.106.31 as
 permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
X-Original-From: =?utf-8?Q?Maciej_Wiecz=C3=B3r-Retman?= <m.wieczorretman@pm.me>
Reply-To: =?utf-8?Q?Maciej_Wiecz=C3=B3r-Retman?= <m.wieczorretman@pm.me>
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

On 2025-12-03 at 16:53:01 +0100, Andrey Konovalov wrote:
>On Tue, Dec 2, 2025 at 3:29=E2=80=AFPM Maciej Wieczor-Retman
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
>> Use the modified __kasan_unpoison_vmalloc() to pass the tag of the first
>> vm_struct's address when vm_structs are unpoisoned in
>> pcpu_get_vm_areas(). Assigning a common tag resolves the pcpu chunk
>> address mismatch.
>>
>> Fixes: 1d96320f8d53 ("kasan, vmalloc: add vmalloc tagging for SW_TAGS")
>> Cc: <stable@vger.kernel.org> # 6.1+
>> Signed-off-by: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
>> ---
>> Changelog v2:
>> - Revise the whole patch to match the fixed refactorization from the
>>   first patch.
>>
>> Changelog v1:
>> - Rewrite the patch message to point at the user impact of the issue.
>> - Move helper to common.c so it can be compiled in all KASAN modes.
>>
>>  mm/kasan/common.c  |  3 ++-
>>  mm/kasan/hw_tags.c | 12 ++++++++----
>>  mm/kasan/shadow.c  | 15 +++++++++++----
>>  3 files changed, 21 insertions(+), 9 deletions(-)
>>
>> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
>> index 7884ea7d13f9..e5a867a5670b 100644
>> --- a/mm/kasan/common.c
>> +++ b/mm/kasan/common.c
>> @@ -591,11 +591,12 @@ void kasan_unpoison_vmap_areas(struct vm_struct **=
vms, int nr_vms,
>>         unsigned long size;
>>         void *addr;
>>         int area;
>> +       u8 tag =3D get_tag(vms[0]->addr);
>>
>>         for (area =3D 0 ; area < nr_vms ; area++) {
>>                 size =3D vms[area]->size;
>>                 addr =3D vms[area]->addr;
>> -               vms[area]->addr =3D __kasan_unpoison_vmap_areas(addr, si=
ze, flags);
>> +               vms[area]->addr =3D __kasan_unpoison_vmap_areas(addr, si=
ze, flags, tag);
>
>I'm thinking what you can do here is:
>
>vms[area]->addr =3D set_tag(addr, tag);
>__kasan_unpoison_vmalloc(addr, size, flags | KASAN_VMALLOC_KEEP_TAG);


I noticed that something like this wouldn't work once I started trying
to rebase my work onto Jiayuan's. The line:
+       u8 tag =3D get_tag(vms[0]->addr);
is wrong and should be
+       u8 tag =3D kasan_random_tag();
I was sure the vms[0]->addr was already tagged (I recall checking this
so I'm not sure if something changed or my previous check was wrong) but
the problem here is that vms[0]->addr, vms[1]->addr ... were unpoisoned
with random addresses, specifically different random addresses. So then
later in the pcpu chunk code vms[1] related pointers would get the tag
from vms[0]->addr.

So I think we still need a separate way to do __kasan_unpoison_vmalloc
with a specific tag.

>
>This is with the assumption that Jiayuan's patch is changed to add
>KASAN_VMALLOC_KEEP_TAG to kasan_vmalloc_flags_t.
>
>Then you should not need that extra __kasan_random_unpoison_vmalloc helper=
.

I already rewrote the patch rebased onto Jiayuan's patch. I was able to
ditch the __kasan_random_unpoison_vmalloc but I needed to add
__kasan_unpoison_vrealloc - so I can pass the tag of the start pointer
to __kasan_unpoison_vmalloc. I was hoping to post it today/tomorrow so
Jiayuan can check my changes don't break his solution. I'm just waiting
to check it compiles against all the fun kernel configs.

--=20
kind regards
Maciej Wiecz=C3=B3r-Retman

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/p=
hrugqbctcakjmy2jhea56k5kwqszuua646cxfj4afrj5wk4wg%40gdji4pf7kzhz.
