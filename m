Return-Path: <kasan-dev+bncBC447XVYUEMRBEE4USCAMGQEBJGOE7A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x140.google.com (mail-lf1-x140.google.com [IPv6:2a00:1450:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id 9B75B36D313
	for <lists+kasan-dev@lfdr.de>; Wed, 28 Apr 2021 09:26:09 +0200 (CEST)
Received: by mail-lf1-x140.google.com with SMTP id q4-20020a19df440000b02901bbaf9c6220sf2950066lfj.6
        for <lists+kasan-dev@lfdr.de>; Wed, 28 Apr 2021 00:26:09 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1619594769; cv=pass;
        d=google.com; s=arc-20160816;
        b=SzeimfJ1X4liGU64P7TbTNWTdreEQneiUgOmp/wjJ1v1keXni35LPY+0oD9JIq1DKQ
         7yjsGsYoQb1ztC6sp2HF0jW3Nu8Urru6uo13jCqKnDkp6PJuoaJtb/UtfiIxArSqp8UB
         CSOeismBzX3YYfAaIgVbxoUmt4FCirT7PfV7gV2n2FrF3n9VGq5PyHixyh+7NvHvntEn
         fuA6J9YcmmX+yMUSI4QGNL/WzPzJSHZBM/hrjHATjKglydxo1yppNhsjCCtNyB5Fgwlo
         wI0aomCIblWUW5bOnZ3rzORAK/+/C6Meumh9O8nf0qBmlsC71l+za4UpB3wVrnsupMr3
         JBfQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :content-language:in-reply-to:mime-version:user-agent:date
         :message-id:from:references:cc:to:subject:sender:dkim-signature;
        bh=ftZgjMjJ/LTGUS21JscQ15OGvUiSLW0rj1ykZOzi4L4=;
        b=bQBOMAuJNi6zY/sXlGj42A3dJtBqoQeixbQl988KpXWXsJUwIi4tnk9tMXmnVrB2a3
         FMfAcS0rcXoO+UhIAbrtlf05kudmdTv7XlwYYc1VDzC3DZ8kvcd5bWTAoWyDj/3BO9gE
         4sYuoxXJgMHwdbXNB6cRKxAQAvLWvk7P7BVKi2uYW1rd/oAcIae26Mjgsx0CasgXNDZq
         zPU08MiSjMysUpBV97yEfhXke0gohp6AKXxPcg73Mv+DYMUxQ5ah3CmeiLoKp59F+H+m
         USTZ9+2nWXhMvJn+AZOhyS0oQaB705A/meME6TIF25UvhDqsiUG9hCNDipVzJlnAQos9
         S0Xg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=neutral (google.com: 217.70.178.230 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) smtp.mailfrom=alex@ghiti.fr
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ftZgjMjJ/LTGUS21JscQ15OGvUiSLW0rj1ykZOzi4L4=;
        b=IjMq3lhG4JkX0l5FCP6VGOKwTLw21ADrOpaS2fd4R1TgzV/Lj+bhZOj5HX24Dz/N2c
         gMyncwR6IkWymeI6F+TDYZ/3TdPHGvXaKPaPhDyYK8WycmUYogQycIEzVsKpiA/tQlPl
         9E0rbpVFK3loHz3+3k0Zdcibo1zNAe0qNMtB8pPQ3NjSUqdzfrDVm+9dDaNUwa+5gv8A
         +oBWWh6WDbWJWpCiop7uIR/3mhXd31zbfbBeWrTPsncrWdm5wwBGd9cddOjZ6S0Go+gi
         EEKo0jlrxIdQ+68mwKr1wXeHCe5BueZFYZ+roAgvnL3h5l4XNxI6u3RrdA/xlWBkTLZj
         s+Lw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ftZgjMjJ/LTGUS21JscQ15OGvUiSLW0rj1ykZOzi4L4=;
        b=nWVB/g4+X4ZQlPren9ooNobYOiotYAVSBT/MBdjQHWp+wruaXX5PvBWzzn/D6IC4xl
         z2XN7A2AFdwZp4zKeVDBD+yIVUWCWhJ3CQLj1w/mCh4bMjrgvUfc0kvoXPKV9aE2ryKb
         iwCFAvCG6PUIAC2NwUoobqfj25dwxAf+ZOn8CEtbO5o6pqLlxY9L7eS0LShKCODBA1oa
         UIavlTTXoD778+tM06pRuhbMprupV3fDgjk+EcA1qbINpWRDxg6ZmHok3lu/sCsY633X
         FSH64Nr4dKFjxGM5/smPzZ0RVb5tVD7qbpHNpdxyNTCavlqoDWZxR3BU4NfTtuMIekOk
         4JIw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531dndXC/DlCntP3F1YNVCOz2XhvF8ztoH3Gei6IRlPeT+KULcNg
	yHQkXkecOrVMeM5mvUcPVWc=
X-Google-Smtp-Source: ABdhPJxpjM75e8wyyGmGvpBJoT7MemzYyHyhz5boVLcXi8hrRtMdeCXHGUgMpBvTnTDmWD5NrweT5A==
X-Received: by 2002:ac2:4a91:: with SMTP id l17mr19351257lfp.397.1619594769189;
        Wed, 28 Apr 2021 00:26:09 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:9b88:: with SMTP id z8ls7440484lji.2.gmail; Wed, 28 Apr
 2021 00:26:08 -0700 (PDT)
X-Received: by 2002:a2e:8189:: with SMTP id e9mr19152007ljg.22.1619594768129;
        Wed, 28 Apr 2021 00:26:08 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1619594768; cv=none;
        d=google.com; s=arc-20160816;
        b=U9zlNjKLi+ctXsIvoj6U/rQbzNhcNp1rMycLxLqIMmihs1kZg7vQFtjUbKFOPkjU1g
         ojR5FirMhAwXE3AFWBj0zRNijzGsePIEE5zNd+6uiU0xWHVAIECQhFFZeNGRlg+xCQ+3
         GDmL4c/t6rCZ+To58wmJQ56pqfOCf9TgMKTMUkDcEa4vu5SPATH+22Orbwu2nPldFVsP
         kQezZh3qvohL+CwFjtCIT6UiHyOPCvuhjBZc230vOvChe0PfsITbov4mb5H+/5lvbvdO
         b6gGaKtCkXTTCJgOpid+mMwj4+PlyDCMLuxT57VryttODg00SENgOKnl5/hxZ0Hwon3M
         RnJg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=TM3MLp65499hHGiMocNpxl8i6ouKKivsOfe7ydtxibI=;
        b=d2cQTqk/Tdkyq2nG/Z2hxpkXum7SfC9GHObEpzVSbEu6hVtGj0ue6hKI9TnBAsaCZn
         GVk4+Ce7YwG21/a8gB7WqSDS2bQqHHlVBZh2eYj7AFP7CurRVwtavOQYLirZ7BHj7YNv
         c7D4dRGDyj36JUcG+6CyuzO3SxQS9MGHEUPFLSyPulMswoQPiT9gSQpQMHVXohsi5Uz1
         KBofAQVtx8ZIL2VuanAHbz81BFv1Fzcys1Io2t9aFlZGxzDu78b2cXEImXPl0LdFL7sj
         ksR6Gnt608pDAS6fKNFHzHN+lOt/iLb4f2Afek17NaI/61+IVX3FEo6sRF6l6FXk3sZI
         gy4w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=neutral (google.com: 217.70.178.230 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) smtp.mailfrom=alex@ghiti.fr
Received: from relay10.mail.gandi.net (relay10.mail.gandi.net. [217.70.178.230])
        by gmr-mx.google.com with ESMTPS id a36si968587ljq.5.2021.04.28.00.26.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Wed, 28 Apr 2021 00:26:07 -0700 (PDT)
Received-SPF: neutral (google.com: 217.70.178.230 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) client-ip=217.70.178.230;
Received: from [192.168.1.100] (lfbn-lyo-1-457-219.w2-7.abo.wanadoo.fr [2.7.49.219])
	(Authenticated sender: alex@ghiti.fr)
	by relay10.mail.gandi.net (Postfix) with ESMTPSA id 90F6624000F;
	Wed, 28 Apr 2021 07:26:03 +0000 (UTC)
Subject: Re: [PATCH] riscv: Remove 32b kernel mapping from page table dump
To: Anup Patel <anup@brainfault.org>, Palmer Dabbelt <palmer@dabbelt.com>
Cc: Jonathan Corbet <corbet@lwn.net>, Paul Walmsley
 <paul.walmsley@sifive.com>, Palmer Dabbelt <palmer@dabbelt.com>,
 Albert Ou <aou@eecs.berkeley.edu>, Arnd Bergmann <arnd@arndb.de>,
 Andrey Ryabinin <aryabinin@virtuozzo.com>,
 Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>,
 linux-doc@vger.kernel.org, linux-riscv <linux-riscv@lists.infradead.org>,
 "linux-kernel@vger.kernel.org List" <linux-kernel@vger.kernel.org>,
 kasan-dev@googlegroups.com, linux-arch <linux-arch@vger.kernel.org>,
 Linux Memory Management List <linux-mm@kvack.org>
References: <20210418112856.15078-1-alex@ghiti.fr>
 <CAAhSdy3csxeTiXgf8eKnRYhD7BM1LDLPddrn527AkA_-fiEGkw@mail.gmail.com>
From: Alex Ghiti <alex@ghiti.fr>
Message-ID: <16cd2359-2453-8184-cf96-2c02800abe8a@ghiti.fr>
Date: Wed, 28 Apr 2021 03:26:02 -0400
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101
 Thunderbird/78.10.0
MIME-Version: 1.0
In-Reply-To: <CAAhSdy3csxeTiXgf8eKnRYhD7BM1LDLPddrn527AkA_-fiEGkw@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Language: fr
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: alex@ghiti.fr
X-Original-Authentication-Results: gmr-mx.google.com;       spf=neutral
 (google.com: 217.70.178.230 is neither permitted nor denied by best guess
 record for domain of alex@ghiti.fr) smtp.mailfrom=alex@ghiti.fr
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

Hi Palmer,

Le 4/20/21 =C3=A0 12:19 AM, Anup Patel a =C3=A9crit=C2=A0:
> On Sun, Apr 18, 2021 at 4:59 PM Alexandre Ghiti <alex@ghiti.fr> wrote:
>>
>> The 32b kernel mapping lies in the linear mapping, there is no point in
>> printing its address in page table dump, so remove this leftover that
>> comes from moving the kernel mapping outside the linear mapping for 64b
>> kernel.
>>
>> Fixes: e9efb21fe352 ("riscv: Prepare ptdump for vm layout dynamic addres=
ses")
>> Signed-off-by: Alexandre Ghiti <alex@ghiti.fr>
>=20
> Looks good to me.
>=20
> Reviewed-by: Anup Patel <anup@brainfault.org>
>=20
> Regards,
> Anup
>=20
>> ---
>>   arch/riscv/mm/ptdump.c | 6 +++---
>>   1 file changed, 3 insertions(+), 3 deletions(-)
>>
>> diff --git a/arch/riscv/mm/ptdump.c b/arch/riscv/mm/ptdump.c
>> index 0aba4421115c..a4ed4bdbbfde 100644
>> --- a/arch/riscv/mm/ptdump.c
>> +++ b/arch/riscv/mm/ptdump.c
>> @@ -76,8 +76,8 @@ enum address_markers_idx {
>>          PAGE_OFFSET_NR,
>>   #ifdef CONFIG_64BIT
>>          MODULES_MAPPING_NR,
>> -#endif
>>          KERNEL_MAPPING_NR,
>> +#endif
>>          END_OF_SPACE_NR
>>   };
>>
>> @@ -99,8 +99,8 @@ static struct addr_marker address_markers[] =3D {
>>          {0, "Linear mapping"},
>>   #ifdef CONFIG_64BIT
>>          {0, "Modules mapping"},
>> -#endif
>>          {0, "Kernel mapping (kernel, BPF)"},
>> +#endif
>>          {-1, NULL},
>>   };
>>
>> @@ -379,8 +379,8 @@ static int ptdump_init(void)
>>          address_markers[PAGE_OFFSET_NR].start_address =3D PAGE_OFFSET;
>>   #ifdef CONFIG_64BIT
>>          address_markers[MODULES_MAPPING_NR].start_address =3D MODULES_V=
ADDR;
>> -#endif
>>          address_markers[KERNEL_MAPPING_NR].start_address =3D kernel_vir=
t_addr;
>> +#endif
>>
>>          kernel_ptd_info.base_addr =3D KERN_VIRT_START;
>>
>> --
>> 2.20.1
>>

Do you think you can take this patch too on for-next?

Thanks,

Alex

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/16cd2359-2453-8184-cf96-2c02800abe8a%40ghiti.fr.
