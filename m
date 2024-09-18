Return-Path: <kasan-dev+bncBDGZVRMH6UCRBF7IVG3QMGQEJ3Z3LEQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53b.google.com (mail-pg1-x53b.google.com [IPv6:2607:f8b0:4864:20::53b])
	by mail.lfdr.de (Postfix) with ESMTPS id 8CA0397B7F8
	for <lists+kasan-dev@lfdr.de>; Wed, 18 Sep 2024 08:32:58 +0200 (CEST)
Received: by mail-pg1-x53b.google.com with SMTP id 41be03b00d2f7-7d4f9974c64sf5470952a12.1
        for <lists+kasan-dev@lfdr.de>; Tue, 17 Sep 2024 23:32:58 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1726641176; cv=pass;
        d=google.com; s=arc-20240605;
        b=gAJKCRQ9Wwj7uo5HuSREm0/7hIoGXGuQ2GRaxTLfPx1QCMgpRAQLt8xEjXCZiRgox8
         RtTHfU+r2mpWtw90yATB/FKunKZQVlg8Y0gPMp/uPjHcqlKO6oub1ooiAXc1EILvK6+P
         b3W45quo4DqTlXL1rMkJiipwS2urTLjKfDeyG6BwxvBztf6ufSUWgPqpHBv/6Jd0Hpsq
         PRLDmOybAVQJKYe54OggdxPnZV2Qp39J6LWaAoAFGtnJJxpW7Wbuoq/L27vHh888Lryj
         dAgsOULxj1IohaHa48Y8hYSfe3bz2QooglUUPihp/0gIcc4z/NOc98u8gsQOGbDJs2B7
         CSPg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :in-reply-to:from:content-language:references:cc:to:subject
         :user-agent:mime-version:date:message-id:sender:dkim-signature;
        bh=JasdtpPY4Ik0Gd8cuJ3f9kbZy5Qayyv1+M/LLvZw/Xo=;
        fh=Wqmack0cQO4+2M8sWB9+eIzYQOhdSeYm7WoPlnO96rc=;
        b=JO0Y5epjNPmee1K1tC3hJOY1plYGhENdow4/WHA5TAs94ZeUFuGMlVyow9el/j6jAx
         jVWFV2yY6l4AuNc69TSKo13+/et4gN07AI7DkTBzA5eXwcp1Zrz2yXMLCriJ8mU5X9tu
         sNl6DoN1WPrbQP/9dSXi9sDfcWNqD03cOigggMtzFKnM/ZO45yW25YuOq2xyaiIwTxrx
         tUg/YrXWTrW+55DMI/8wPYtgRQJ0a23m7j8P+ZbK0l1eivxaDRTPfil9EgDdM3ejIRLQ
         wfm72Xcd6Nnd/rxJlMRA7M6b5F5xR/+wQeHVoje2bOWH4P07TislpOxkH5hp4UTaxxsC
         SfFg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of anshuman.khandual@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=anshuman.khandual@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1726641176; x=1727245976; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:in-reply-to:from
         :content-language:references:cc:to:subject:user-agent:mime-version
         :date:message-id:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=JasdtpPY4Ik0Gd8cuJ3f9kbZy5Qayyv1+M/LLvZw/Xo=;
        b=CIJ2/Gre28EslqPex/1jEUlvSXXGJsl1oH0jVq+VKKgd93cROGFd3s3eQJQcBXjNAz
         yZU/kMS4QkASUyU5qq2wG3WxZhXhjjIc59UYaPFvQ8rV+61XWEIDLI7F9BMLyIdwMgKl
         dX/GX9AWAeBsyWP+/iQLLBP6t1VqljjlZVgwwqWBMh1NUzqtkHwsqxSIOcBtD6Ci8YpS
         5JOfE1vDyxnXfWpqO1lc5Bv9hajY+8o6jGxVJofRx7tNG3uXNtfSGZO7oeG9oBaAfTyE
         Uwx8cB6/3URf5Ef09t+Te9/XF1rj85qmyRHCLFCbdYN/3M6FBQpisz5l7dMZUwnZHpnr
         bwug==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1726641176; x=1727245976;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=JasdtpPY4Ik0Gd8cuJ3f9kbZy5Qayyv1+M/LLvZw/Xo=;
        b=w0H4HN3QZIx9Ru8hvz+J4GR5XP85Lm6t9MTR8agfnX2wAOnZqfT73NyQ9j+k8eSGCR
         jDL8DOBgpIXgLjBd8JPg4nqHYlkFNpuDQ00ahDzqiP06swP6sXjxkW9zYMvdRBB7aAS/
         nlguPlelinzGtj6V9B6mEdk7dzKK1Y+EO3zc9mVKX73HNaEiN3FSbC4zUpYjA8pH/Idc
         b3uu00aYHxlw0GMFLoBx11vzPNJRb2hEaDfVmi5f3tVWT8paOykSjEb9kc+7LfYtDXFT
         NJVeu+HqnXLixk6NaxpO3cdDpPI8UubDdueB2K94/OfxEyJybgPoJKu8PVBLVxvG839d
         rTRw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUTogkDTMGfArFx8sfa9BIdnehGFLiQP7fEDTXVegs7aq6gadynz2f3JW/rJ1OULSajvqb8Iw==@lfdr.de
X-Gm-Message-State: AOJu0YzxsMHtxk3ANfj1CSxlLyrzzg7oTNHxq/o3wi39vN8M1aHAKXHC
	Beks7mUzFpWygkCkqmw6zaRkD/aiB0gYp5Bl58q98jORUa2be0Df
X-Google-Smtp-Source: AGHT+IGBhHMdjmxowHbCsPM84bip4rEnjBhyk/Ywa91uMOoZpc+EdxjL7GzeoTcJuVGOAq1JJArbww==
X-Received: by 2002:a05:6a21:38f:b0:1d2:bbf2:d8a5 with SMTP id adf61e73a8af0-1d2bbf2dc0emr17312730637.31.1726641175848;
        Tue, 17 Sep 2024 23:32:55 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:3993:b0:706:6f90:b106 with SMTP id
 d2e1a72fcca58-719258568d0ls5619668b3a.0.-pod-prod-07-us; Tue, 17 Sep 2024
 23:32:53 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXlVAgN8+MkaX6jHTjiMv3lqrY86Cqon/Gf9wMl8MVXES6aWGXPesMJ12MXDCDBynPov66GGI72AOA=@googlegroups.com
X-Received: by 2002:a05:6a00:2401:b0:718:dd53:70db with SMTP id d2e1a72fcca58-7192606c438mr33265776b3a.11.1726641173256;
        Tue, 17 Sep 2024 23:32:53 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1726641173; cv=none;
        d=google.com; s=arc-20240605;
        b=FcgMdARA+zq9Amvx+SxR2BeK6g78cYEjWHM2kPnajfp54y0btOg1/SFU96UuAZYFXZ
         unZ/1Sq1yMyf6spRhpFlYTANzGTs3Bf3ypHRIgZugg+Aon8JJ8Ve95WBmim/pIYj6bRM
         OUPiUhpkcTlDaOh50Diy7LnwQWpp4JVtRGGpPoNLPEmTJyo9EFVoRlhu3CH/jxl7WwxA
         rn2LW7/I2xhy7yrU/TO/bdAAJpkDQjsxzylxnHDr6yhIU2oqSz+gtYyIveQPYNkgv+z2
         9qxt+kKNqaFRAlgXCi7USf2cJg3W8RR3Lv2sJGHFCTapcfrJz2/3bhTgrc7890fVrwaA
         J7Dw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id;
        bh=nHnVnZ6ms0RN4dMuYwGT8eaXSM6M7zW4lUqDXt0YbYs=;
        fh=6gg0ght8wldm0GlcQKu2mojnASHp4ZVfvdboFPG5SJw=;
        b=e0F58YB8M+T0j7Fwyucr0Y9AjwQeRLZI+KOgkSUxBWjjVbGnxTdS5LDXLT0wP8XOjh
         qwU1HjY7DGYamgOFBbGzSLgnJSbWMMOLS197cZnlwvtByVRjG03fVtd15TasCKOdsKNI
         KX4Y/hK8JgTDqB6jVJnxYHPHcXfirlDnya+lMl1vbZ9VeU0f8alu1mGcmtffsdyMVZnF
         KAwQsm+fzrdZHnF2vXiC8XsHDotUqXIuLyIfrGhZg74X6vaomQZkC9pe5SQRmJ0x7iwM
         zb/OjIiaIkBqbqAzVyUxQNjfU4eL88eiTExES4jSby4MMkzIJjqNowrXIAYijs3d3qyA
         +mYQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of anshuman.khandual@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=anshuman.khandual@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id d2e1a72fcca58-71944a992f4si356473b3a.1.2024.09.17.23.32.52
        for <kasan-dev@googlegroups.com>;
        Tue, 17 Sep 2024 23:32:52 -0700 (PDT)
Received-SPF: pass (google.com: domain of anshuman.khandual@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 36FB4FEC;
	Tue, 17 Sep 2024 23:33:21 -0700 (PDT)
Received: from [10.162.16.84] (a077893.blr.arm.com [10.162.16.84])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 4E5633F64C;
	Tue, 17 Sep 2024 23:32:48 -0700 (PDT)
Message-ID: <8cafe140-35cf-4e9d-8218-dfbfc156ca69@arm.com>
Date: Wed, 18 Sep 2024 12:02:45 +0530
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH V2 3/7] mm: Use ptep_get() for accessing PTE entries
To: David Hildenbrand <david@redhat.com>, linux-mm@kvack.org
Cc: Andrew Morton <akpm@linux-foundation.org>,
 Ryan Roberts <ryan.roberts@arm.com>, "Mike Rapoport (IBM)"
 <rppt@kernel.org>, Arnd Bergmann <arnd@arndb.de>, x86@kernel.org,
 linux-m68k@lists.linux-m68k.org, linux-fsdevel@vger.kernel.org,
 kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org,
 linux-perf-users@vger.kernel.org
References: <20240917073117.1531207-1-anshuman.khandual@arm.com>
 <20240917073117.1531207-4-anshuman.khandual@arm.com>
 <f9a7ebb4-3d7c-403e-b818-29a6a3b12adc@redhat.com>
Content-Language: en-US
From: Anshuman Khandual <anshuman.khandual@arm.com>
In-Reply-To: <f9a7ebb4-3d7c-403e-b818-29a6a3b12adc@redhat.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: anshuman.khandual@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of anshuman.khandual@arm.com designates 217.140.110.172
 as permitted sender) smtp.mailfrom=anshuman.khandual@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
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



On 9/17/24 15:58, David Hildenbrand wrote:
> On 17.09.24 09:31, Anshuman Khandual wrote:
>> Convert PTE accesses via ptep_get() helper that defaults as READ_ONCE() =
but
>> also provides the platform an opportunity to override when required. Thi=
s
>> stores read page table entry value in a local variable which can be used=
 in
>> multiple instances there after. This helps in avoiding multiple memory l=
oad
>> operations as well possible race conditions.
>>
>=20
> Please make it clearer in the subject+description that this really only i=
nvolves set_pte_safe().

I will update the commit message with some thing like this.

mm: Use ptep_get() in set_pte_safe()

This converts PTE accesses in set_pte_safe() via ptep_get() helper which
defaults as READ_ONCE() but also provides the platform an opportunity to
override when required. This stores read page table entry value in a local
variable which can be used in multiple instances there after. This helps
in avoiding multiple memory load operations as well as some possible race
conditions.

>=20
>=20
>> Cc: Andrew Morton <akpm@linux-foundation.org>
>> Cc: David Hildenbrand <david@redhat.com>
>> Cc: Ryan Roberts <ryan.roberts@arm.com>
>> Cc: "Mike Rapoport (IBM)" <rppt@kernel.org>
>> Cc: linux-mm@kvack.org
>> Cc: linux-kernel@vger.kernel.org
>> Signed-off-by: Anshuman Khandual <anshuman.khandual@arm.com>
>> ---
>> =C2=A0 include/linux/pgtable.h | 3 ++-
>> =C2=A0 1 file changed, 2 insertions(+), 1 deletion(-)
>>
>> diff --git a/include/linux/pgtable.h b/include/linux/pgtable.h
>> index 2a6a3cccfc36..547eeae8c43f 100644
>> --- a/include/linux/pgtable.h
>> +++ b/include/linux/pgtable.h
>> @@ -1060,7 +1060,8 @@ static inline int pgd_same(pgd_t pgd_a, pgd_t pgd_=
b)
>> =C2=A0=C2=A0 */
>> =C2=A0 #define set_pte_safe(ptep, pte) \
>> =C2=A0 ({ \
>> -=C2=A0=C2=A0=C2=A0 WARN_ON_ONCE(pte_present(*ptep) && !pte_same(*ptep, =
pte)); \
>> +=C2=A0=C2=A0=C2=A0 pte_t __old =3D ptep_get(ptep); \
>> +=C2=A0=C2=A0=C2=A0 WARN_ON_ONCE(pte_present(__old) && !pte_same(__old, =
pte)); \
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 set_pte(ptep, pte); \
>> =C2=A0 })
>> =C2=A0=20
>=20
> I don't think this is necessary. PTE present cannot flip concurrently, th=
at's the whole reason of the "safe" part after all.

Which is not necessary ? Converting de-references to ptep_get() OR caching
the page table read value in a local variable ? ptep_get() conversion also
serves the purpose providing an opportunity for platform to override.

>=20
> Can we just move these weird set_pte/pmd_safe() stuff to x86 init code an=
d be done with it? Then it's also clear *where* it is getting used and for =
which reason.
>=20
set_pte/pmd_safe() can be moved to x86 platform - as that is currently the
sole user for these helpers. But because set_pgd_safe() gets used in riscv
platform, just wondering would it be worth moving only the pte/pmd helpers
but not the pgd one ?

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/8cafe140-35cf-4e9d-8218-dfbfc156ca69%40arm.com.
