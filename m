Return-Path: <kasan-dev+bncBC32535MUICBBBFWV63QMGQE7C4MNBA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3b.google.com (mail-yb1-xb3b.google.com [IPv6:2607:f8b0:4864:20::b3b])
	by mail.lfdr.de (Postfix) with ESMTPS id C5BA497C586
	for <lists+kasan-dev@lfdr.de>; Thu, 19 Sep 2024 10:04:21 +0200 (CEST)
Received: by mail-yb1-xb3b.google.com with SMTP id 3f1490d57ef6-e1d46cee0b0sf911831276.2
        for <lists+kasan-dev@lfdr.de>; Thu, 19 Sep 2024 01:04:21 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1726733060; cv=pass;
        d=google.com; s=arc-20240605;
        b=P9C+UQ2J1XdtM/G832HnegDYEpLfrUGwpYf9eThFFPCJSqy/beg1cglXluxDx7+NFr
         uXQW/sJ+fC6cjFLvlUoCPNWOoGXhjsr3P/WYuIg7mZyotnbo57M49jk8mVi0ADajVb0t
         Du3/ncUx67q7/CYVm6rRrnQqc9xYLqkhmnbHmJYXXu0HQYM0Kc7pEBcvRMPCb6ZKe6k0
         7n7nKTiCOFzC9H/8rN/SEcuV3YAkR3MjVvVTzq9rnUqbA4RQNShMzG6ftpjtYf42S2V6
         3WTxp0ZozDVyqoMSMMK3n9dDPqWJcZG+649KxbfYQ6SX6gIBQzS/DXhKIYfgWS6xWgw0
         82/A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :content-language:in-reply-to:organization:autocrypt:from:references
         :cc:to:subject:user-agent:mime-version:date:message-id:sender
         :dkim-signature;
        bh=vqToOQDUZAkI/rJYjQwHMeGyG6O7b7YDCqKK3ASuow4=;
        fh=z7f7TCyHmGlC11Eyu+0sN5YKhEN/ShLgatPZncRt+uk=;
        b=DE+i6sLWcGQVEoSRplOY9pnNMY9oxMbMwkjZ1WHPRw0/yMiV0HVA9VHfFokf7pLyYo
         IfihWEyL8Om6ocOFfM0XHO74OqfmYwf0o2Em7LxHXwyKPJzy71qgpkjIB7gWmef/5CTe
         RfGQHz/sj+q/M2KTzg/yiNHYPdwLllqXqnGI4MK6s5fpyQu+tLr5LL4ViIdzFoZolWWd
         yIJKtlJ2YPWjNkLcXREXcXC2nrDG7PnVXGo4KBw4PzyUpjBTuSHLh7+d+4vKMG25+t8D
         J4wpRg1bt6IgASbV8LtLVw4cyb2kC+fXcF7AcfTvsXh/A3AnP81dFJQEPCKrGv8776HE
         U9lA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=imzFfkGq;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1726733060; x=1727337860; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:content-language
         :in-reply-to:organization:autocrypt:from:references:cc:to:subject
         :user-agent:mime-version:date:message-id:sender:from:to:cc:subject
         :date:message-id:reply-to;
        bh=vqToOQDUZAkI/rJYjQwHMeGyG6O7b7YDCqKK3ASuow4=;
        b=thTvg69htuwIl5pPFp6AZboByQ8JqVXjojfykeuRjfFrbVgT5W8xMufeaaUpRaBpNV
         MG6OKdjLOEiBcCceLC8Hi7EVflaX+d9nYC7N7itCDEp/M08lA5Qe2MXMzHuEBCxNW1hS
         y8p4EyO7My0T6yU5NbzoO5d8ya+aepFbN4nXlPEQLUu0N9Trw4GbBcZBFiEcJyIT9i+4
         ID+FRxhaIK6KPqvaVrgbzLgx+S47Nitz5P+xb+Jgwz7bzvi6d3PDxFdRc9ervHYpaa1d
         SZIfc4tTDeQglGeHl6Z0631ybKt07hwXglfninDG6j2CMujVbrMp6D7qRJk96M9pnxc+
         o7oQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1726733060; x=1727337860;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:content-language:in-reply-to:organization
         :autocrypt:from:references:cc:to:subject:user-agent:mime-version
         :date:message-id:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=vqToOQDUZAkI/rJYjQwHMeGyG6O7b7YDCqKK3ASuow4=;
        b=qwHNiG2w1VH+dulJUel3y8tzYQPivyrMnxMCECKoH+SfwyE5jki6RybriU8k8A9SWW
         dkto97z3CW0cxzQHHXTem48puTYT7jWyYfs63ZhAkRbscOqw2XpezhfbDv4QfbKXD3eB
         m2BbUGFHvoqnmuM65LKQJ7NRzrnCbJL5g2jpZi4N3VSFcjXlj25jWNDuHjR4byGlGIml
         sbFAaKHuhZP0cb6p0YgR/iYzpuKIUJ8zhK0Hs0871F3Bm6UcpxMPRB17tDXx9Ga6I04E
         KfSNscJ5s8+qe9WB72rZE1wnWET182a/acmYJTUdGbCxRHLLSEbTuJC/h/JFUSVh7A2v
         XDcQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWMhE2LizgflyXjsEqkeFKihFAClbgKRP+LR+T5QvhPkijcMpfxAVFGdUIG4IdoT88OwF8RgQ==@lfdr.de
X-Gm-Message-State: AOJu0Yz1ADxVEEz/VXikPg0Q1X/qFE8FPobN3yuV4zoWOAMhO+Klk5WJ
	lJnkveibzMI6wyYmAZGeytJyOo+r02TKGNDzlLOZhnkKM6cSUU0M
X-Google-Smtp-Source: AGHT+IFrclRk1ZW8lZ2VsTfhKw2jdRIlPvrh6rDNsr5yk9hB1Rv5dt5UrWYskdV995wNpgn4CI646Q==
X-Received: by 2002:a05:6902:1145:b0:e1f:e985:f729 with SMTP id 3f1490d57ef6-e1fe985f8bfmr15245143276.1.1726733060633;
        Thu, 19 Sep 2024 01:04:20 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6902:2b91:b0:e1d:a081:e017 with SMTP id
 3f1490d57ef6-e2027e971a5ls594578276.2.-pod-prod-09-us; Thu, 19 Sep 2024
 01:04:19 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUjesYovZebz1+HE4fWet3/S4kVMfGFrYUXNU08EkxYXPBTSpzS+t0rPxE8hBrCEIBI38m7eeJJiY0=@googlegroups.com
X-Received: by 2002:a05:6902:15cc:b0:e11:386a:142c with SMTP id 3f1490d57ef6-e1d9db929e5mr21090856276.5.1726733059815;
        Thu, 19 Sep 2024 01:04:19 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1726733059; cv=none;
        d=google.com; s=arc-20240605;
        b=exul1Gz3IeXP8KO5QaHNFpJ8i8Ee3HTwYCYUTifN5RkA8eZptOzAg6GqGmV8lqr8EY
         ns+Yy8FB403W5aOMH0t1L2/KyJduJCDdv4O81QUcJRHckP3FLZe/3KNaOZ4HvYFydjaN
         9+ucK2BqZKuhMKE7JEYfNJ0SIuIDG20SSgaKfJLOuaklPpWaXvKWx09v19vtmfyG+MPf
         /531Z4pkPpyHhSiESscjk0VrMubsJr1lS2rgU17o0GuoccLTChY388nmEH/dOWLDzXei
         2+z4UskUhZ1+AwavrVtVT+9D5pfAF5wmnEOfFIlpKr0G4hRy7ZLNUac1ZBjlrz1fHxU4
         szGA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:content-language:in-reply-to:organization
         :autocrypt:from:references:cc:to:subject:user-agent:mime-version
         :date:message-id:dkim-signature;
        bh=4DpbblgkcMhjIC/ykM3FWmmeoOS60M6M8pYscao/Qy0=;
        fh=DEW18D1o5M3Dnn/GgJzIeQSlBUwGQaMzj1DGvicLzb8=;
        b=gBCSssyQZ16C3ZhM3MvbVxPVwZJspwp5IvWAzAIzAoudg6BStocgeZkVHjhe3GgGC4
         9zRtxDgSxmcthWSbo4HuISzu1MtBBA7PVuLy35KP+oHnNbJ5Df6jFfJ26dJMLJOTxu5A
         KO0CaWEdJtlIYvFhywKL6jpLeTuFmXfq1JsEznxQn3q4CXSN07+Fvyl7y3Y8MZY1GKVh
         IBh6NJmHJieRS4sule3i4EBJZMBQF9ZDJWYE4hSay2TtDB4Ab0jE5e4EXPsE2n2Jvw3d
         ocXOMoHQ8qF/6L9g83e33CmchPopIBpottg8mfq7Ma99X+eZMhnOmdTCA8zjMltY2Xvd
         ZUyQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=imzFfkGq;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id 3f1490d57ef6-e1dc13c8f59si691092276.4.2024.09.19.01.04.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 19 Sep 2024 01:04:19 -0700 (PDT)
Received-SPF: pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mail-wr1-f72.google.com (mail-wr1-f72.google.com
 [209.85.221.72]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384) id
 us-mta-147-huoA9qGcMYeLDFyGNhf01Q-1; Thu, 19 Sep 2024 04:04:18 -0400
X-MC-Unique: huoA9qGcMYeLDFyGNhf01Q-1
Received: by mail-wr1-f72.google.com with SMTP id ffacd0b85a97d-378929f1a4eso291123f8f.1
        for <kasan-dev@googlegroups.com>; Thu, 19 Sep 2024 01:04:17 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWNtQ3lcU2gagVAMfsHbZcvgNyYzEdIQ0pk60es2cKwz70Ah29HVmSKLJZuiBj76/r26Ss+ArnjG88=@googlegroups.com
X-Received: by 2002:a5d:6551:0:b0:374:c64d:5379 with SMTP id ffacd0b85a97d-378c2d11728mr15031507f8f.27.1726733056747;
        Thu, 19 Sep 2024 01:04:16 -0700 (PDT)
X-Received: by 2002:a5d:6551:0:b0:374:c64d:5379 with SMTP id ffacd0b85a97d-378c2d11728mr15031486f8f.27.1726733056259;
        Thu, 19 Sep 2024 01:04:16 -0700 (PDT)
Received: from [10.131.4.59] ([83.68.141.146])
        by smtp.gmail.com with ESMTPSA id ffacd0b85a97d-378e73f62bfsm14404103f8f.51.2024.09.19.01.04.13
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 19 Sep 2024 01:04:14 -0700 (PDT)
Message-ID: <d32136d4-94ab-432a-89ae-5f41935404ff@redhat.com>
Date: Thu, 19 Sep 2024 10:04:15 +0200
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH V2 3/7] mm: Use ptep_get() for accessing PTE entries
To: Anshuman Khandual <anshuman.khandual@arm.com>, linux-mm@kvack.org
Cc: Andrew Morton <akpm@linux-foundation.org>,
 Ryan Roberts <ryan.roberts@arm.com>, "Mike Rapoport (IBM)"
 <rppt@kernel.org>, Arnd Bergmann <arnd@arndb.de>, x86@kernel.org,
 linux-m68k@lists.linux-m68k.org, linux-fsdevel@vger.kernel.org,
 kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org,
 linux-perf-users@vger.kernel.org
References: <20240917073117.1531207-1-anshuman.khandual@arm.com>
 <20240917073117.1531207-4-anshuman.khandual@arm.com>
 <f9a7ebb4-3d7c-403e-b818-29a6a3b12adc@redhat.com>
 <8cafe140-35cf-4e9d-8218-dfbfc156ca69@arm.com>
From: David Hildenbrand <david@redhat.com>
Autocrypt: addr=david@redhat.com; keydata=
 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
 WNyWQQ==
Organization: Red Hat
In-Reply-To: <8cafe140-35cf-4e9d-8218-dfbfc156ca69@arm.com>
X-Mimecast-Spam-Score: 0
X-Mimecast-Originator: redhat.com
Content-Language: en-US
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=imzFfkGq;
       spf=pass (google.com: domain of david@redhat.com designates
 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
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

On 18.09.24 08:32, Anshuman Khandual wrote:
>=20
>=20
> On 9/17/24 15:58, David Hildenbrand wrote:
>> On 17.09.24 09:31, Anshuman Khandual wrote:
>>> Convert PTE accesses via ptep_get() helper that defaults as READ_ONCE()=
 but
>>> also provides the platform an opportunity to override when required. Th=
is
>>> stores read page table entry value in a local variable which can be use=
d in
>>> multiple instances there after. This helps in avoiding multiple memory =
load
>>> operations as well possible race conditions.
>>>
>>
>> Please make it clearer in the subject+description that this really only =
involves set_pte_safe().
>=20
> I will update the commit message with some thing like this.
>=20
> mm: Use ptep_get() in set_pte_safe()
>=20
> This converts PTE accesses in set_pte_safe() via ptep_get() helper which
> defaults as READ_ONCE() but also provides the platform an opportunity to
> override when required. This stores read page table entry value in a loca=
l
> variable which can be used in multiple instances there after. This helps
> in avoiding multiple memory load operations as well as some possible race
> conditions.
>=20
>>
>>
>>> Cc: Andrew Morton <akpm@linux-foundation.org>
>>> Cc: David Hildenbrand <david@redhat.com>
>>> Cc: Ryan Roberts <ryan.roberts@arm.com>
>>> Cc: "Mike Rapoport (IBM)" <rppt@kernel.org>
>>> Cc: linux-mm@kvack.org
>>> Cc: linux-kernel@vger.kernel.org
>>> Signed-off-by: Anshuman Khandual <anshuman.khandual@arm.com>
>>> ---
>>>  =C2=A0 include/linux/pgtable.h | 3 ++-
>>>  =C2=A0 1 file changed, 2 insertions(+), 1 deletion(-)
>>>
>>> diff --git a/include/linux/pgtable.h b/include/linux/pgtable.h
>>> index 2a6a3cccfc36..547eeae8c43f 100644
>>> --- a/include/linux/pgtable.h
>>> +++ b/include/linux/pgtable.h
>>> @@ -1060,7 +1060,8 @@ static inline int pgd_same(pgd_t pgd_a, pgd_t pgd=
_b)
>>>  =C2=A0=C2=A0 */
>>>  =C2=A0 #define set_pte_safe(ptep, pte) \
>>>  =C2=A0 ({ \
>>> -=C2=A0=C2=A0=C2=A0 WARN_ON_ONCE(pte_present(*ptep) && !pte_same(*ptep,=
 pte)); \
>>> +=C2=A0=C2=A0=C2=A0 pte_t __old =3D ptep_get(ptep); \
>>> +=C2=A0=C2=A0=C2=A0 WARN_ON_ONCE(pte_present(__old) && !pte_same(__old,=
 pte)); \
>>>  =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 set_pte(ptep, pte); \
>>>  =C2=A0 })
>>>   =20
>>
>> I don't think this is necessary. PTE present cannot flip concurrently, t=
hat's the whole reason of the "safe" part after all.
>=20
> Which is not necessary ? Converting de-references to ptep_get() OR cachin=
g
> the page table read value in a local variable ? ptep_get() conversion als=
o
> serves the purpose providing an opportunity for platform to override.

Which arch override are you thinking of where this change here would=20
make a real difference? Would it even make a difference with cont-pte on=20
arm?

>=20
>>
>> Can we just move these weird set_pte/pmd_safe() stuff to x86 init code a=
nd be done with it? Then it's also clear *where* it is getting used and for=
 which reason.
>>
> set_pte/pmd_safe() can be moved to x86 platform - as that is currently th=
e
> sole user for these helpers. But because set_pgd_safe() gets used in risc=
v
> platform, just wondering would it be worth moving only the pte/pmd helper=
s
> but not the pgd one ?

My take would be just to move them where they are used, and possibly=20
even inlining them.

The point is that it's absolutely underdocumented what "_safe" is=20
supposed to be here, and I don't really see the reason to have this in=20
common code (making the common API more complicated).

--=20
Cheers,

David / dhildenb

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/d32136d4-94ab-432a-89ae-5f41935404ff%40redhat.com.
