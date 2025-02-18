Return-Path: <kasan-dev+bncBAABBVPI2G6QMGQEYVAVIHI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc39.google.com (mail-oo1-xc39.google.com [IPv6:2607:f8b0:4864:20::c39])
	by mail.lfdr.de (Postfix) with ESMTPS id DC5B4A39B75
	for <lists+kasan-dev@lfdr.de>; Tue, 18 Feb 2025 12:51:50 +0100 (CET)
Received: by mail-oo1-xc39.google.com with SMTP id 006d021491bc7-5f8d5e499a5sf3703829eaf.2
        for <lists+kasan-dev@lfdr.de>; Tue, 18 Feb 2025 03:51:50 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1739879509; cv=pass;
        d=google.com; s=arc-20240605;
        b=f1wAzBqRmprDt4phWANSdHov6PiFSq5H1+5WA1bxgmhzEouki3T0/t5x/nT/C4X5cv
         fbqbV9fEm2M2swRxS3w17ltNMNxN6Pq84UhQQhUOyZaUzTFkzfuGcAkphDL9pkGTfpyc
         WzJsRHFBVCU+MJLa21PWgH9P0DXm4gfUIE2JA8bAUNuu2Ni40kwMADByzqsl+cEGW6NI
         RRhf1ugmzoCRp93kmCmBLWkxOcQLD1RduHxXJOqFTXRVh06LPkeq9Gy+Vnz6W/N9eIK+
         NUoZbkinkWKdPuy7lNRTKrJX7qM6OnHmmkAjfiKaTvb9Oh2RsbBas4qr6etTOuT753ma
         oLGA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :in-reply-to:from:references:cc:to:subject:user-agent:mime-version
         :date:message-id:dkim-signature;
        bh=mwInjlYid9xqUnQm7dFm/kO4z7jafOaExoHrKVkI158=;
        fh=QQ9Rd1dPpKqEsRfaoT/8YTbJZeSS7TaJ4pniEgAsnqw=;
        b=FqtDdw5eJXlYbfb3E1JU43satvzOtldfkG4wwFLok8JkxXYesvZZSlsP+kqzeFqvbC
         eL84QQt5XJcxT1e+8bRRR9Ot2RRi5oxb++b75wGsb/8kZdiP7/Pnk2ScTyne1gUc94ho
         zkQ/QvDRAEj9PyxcaLkqP6/nLhtfxt/yrnEMFV37Bht/7SGto3UeGVdLJgUYgg5c8wCO
         6C515HTiYEfBcB23NukI+WhvH3+kroDHF+C7ewjiBbOfEYm1wFf+0UDUn9sxY4hqiIbS
         LsTTlroEf1qEVocB08WcI9sCquv1luNjyML/Sjl5jvH+j+KPguvx1W6U4wW1O00TTk0F
         mQrg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of tongtiangen@huawei.com designates 45.249.212.189 as permitted sender) smtp.mailfrom=tongtiangen@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1739879509; x=1740484309; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:from:references:cc:to:subject
         :user-agent:mime-version:date:message-id:from:to:cc:subject:date
         :message-id:reply-to;
        bh=mwInjlYid9xqUnQm7dFm/kO4z7jafOaExoHrKVkI158=;
        b=QjciJb2wK/6cScoJ6q607lrr5lbLKr3X7J3thWA/OjS2cvwjXQqCb+798IMzQvV3c1
         R+F/zBWNO8sKju2rst33vY38JFaxXeLRMHzPxvnds8oxn6zumpoxxenZ3LGc7zHWEuB1
         rvRqgVXk1g8B0UcPiY0OfZ6HcgNteC0LZw2UFqtygW38EiOeoabnMcyVx/ABXM5CqRRE
         qaUvL2faDRpienpXaE8vdckhc7bJ9CyOdNivnWkN385MngJoZJefc7G9nyXYHmwE8+wC
         NnOHAbkJA/4GyAqeNjV9PhuwOHge5K8X/wTdy+N7xXYeLSUC1EyN71i3yIYuNswnb0jf
         /yUQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1739879509; x=1740484309;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:from:references:cc:to:subject
         :user-agent:mime-version:date:message-id:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=mwInjlYid9xqUnQm7dFm/kO4z7jafOaExoHrKVkI158=;
        b=G51mIgw6qvwcqXJAlIRO21ZCYyXuVZAIJc19hqg5BfLz50aLtz0O1feWp4OVJyZ2Kh
         xusCCSK4p2r5p4Y1FG+I6cHaHSQ9EwbRacmKq3KKq9mkah3BkZiiST4vHAtIoX8tUuzX
         QfgmWbW7slwzhJUw167lvLBEceYvLXp/tFicmCmUNHatzcfeqfaG7Vc29yRB1xbwOEXN
         +mjKRp5gV5CUbJnaP8ZfUckqYslzxPO74XKPnCRwW23JnRvQxIio+UrWCyqalg82ySwq
         /m8oBg267L0zEPmLjjQDqLGgC5u8bAA9Q7HQ0D/0itlVQ2k/oxCV0ZnwFY8bqPMN20nG
         83QA==
X-Forwarded-Encrypted: i=2; AJvYcCVSWxX1xw3r83/sJfDAuzGExV3kW9ce5q6JNKB+n7/AZcdJtsgEoClhcpUmNbYqVudCV0NIOw==@lfdr.de
X-Gm-Message-State: AOJu0YzLksm+1VlhQKoUGpd2+uHRyEWw2dnUUDXExbjI6A3Nk/cFYxI1
	WvK0tLfkFwzE8vOvVN1cPplH2ibPapunT9hNr+gbE6xlQxvMeYt9
X-Google-Smtp-Source: AGHT+IHlDRRRJmSwvDiCqcFJJsiKFTNcKemhLqRnzmYgGKTGJxb40/WueNDU1XXAyO2u4gAWrJrXuA==
X-Received: by 2002:a05:6820:1e86:b0:5fc:b489:6cec with SMTP id 006d021491bc7-5fcc5668e24mr7722080eaf.2.1739879509573;
        Tue, 18 Feb 2025 03:51:49 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVEFL0jlP2fsxrKDTode3tvuY6mRVZchRc4ns/vY7vatfA==
Received: by 2002:a4a:ce91:0:b0:5fc:ad75:34cd with SMTP id 006d021491bc7-5fcaf9725cfls2179030eaf.2.-pod-prod-08-us;
 Tue, 18 Feb 2025 03:51:49 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXl2pkL6CXbuGvIj33zzhRXb2b/lMEmmGEkSdn0gCdz3LFtkaxwZaDOQ5GgnR6D9pqnSpVwyPlg+ag=@googlegroups.com
X-Received: by 2002:a05:6830:6d0a:b0:727:ec1:73ab with SMTP id 46e09a7af769-727120b92aemr9082398a34.19.1739879508874;
        Tue, 18 Feb 2025 03:51:48 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1739879508; cv=none;
        d=google.com; s=arc-20240605;
        b=fnmRgNybOeJKMzv52KJdu0wVDwGd59XQ4eJ7jNcb0p/23+aNHXQeZsml8Uq0nNNUtg
         D7EDo8NShzUsCxCP1MWpeCP7EAddT0A2ouL6fIyUHMd2z9mFgcLdA7//MKxQxsxdJCJh
         +50hdmrK5urx5GVHsEKLfkvoiZqf6MgWnfAQNqQLRXhizR05YYZNAPbGCG+9tP9TivIC
         Cu2eUkJjp1E1oXUswzCIXBUYMEWG7D0kEvktU2WCPHJ4o8Lg2sd9y6Q6dLVpkZCq28UU
         FMcVuCZ+uwb7gmhFoTWnt6BCq/fr9s51FM3CSsU8TuWZcQdNvddNrnfel/ImVflcUMfl
         ZooQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to:subject
         :user-agent:mime-version:date:message-id;
        bh=QmDB2s0hgiezmOzzPHSZXy+cZE0dzTWlpWB06SQm1SU=;
        fh=RzQbsIRJIGcsOahvYzttPrzbIb6n8kVsMKDOWJddbjk=;
        b=RFrv6zbU2fOfHXxEtlSS9A908perhIATY/Q9MvSiSFaZHmQ0FwmMl5XEAG+NLSwMt6
         vZsVdXJVITY7dXq8J0iuBVo4AUVx7sbdJ+wO72gB0wpNCO5T0tosJKG/zweT5NPpLGVa
         wPJUl85Gajwg7Nl7lukFHHvROGHzyyrOTmfWyYmOiiQTehzWDy/w+kP4ZGi7cBQo/DkX
         aauZp1rV0Eqxweop7LJdt5rXJFM07vWoHACUDNZx87YAdhrdMBSFf+bfHmpB7Vj9e1aa
         MV59/u/YTZ/cJ5PUCq/uWn32g3Ds8dVn33ARmgluBPP58jcJ2NRQ65ixIzqf5WYARvcd
         sDxw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of tongtiangen@huawei.com designates 45.249.212.189 as permitted sender) smtp.mailfrom=tongtiangen@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
Received: from szxga03-in.huawei.com (szxga03-in.huawei.com. [45.249.212.189])
        by gmr-mx.google.com with ESMTPS id 006d021491bc7-5fceaad3f38si108328eaf.1.2025.02.18.03.51.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 18 Feb 2025 03:51:48 -0800 (PST)
Received-SPF: pass (google.com: domain of tongtiangen@huawei.com designates 45.249.212.189 as permitted sender) client-ip=45.249.212.189;
Received: from mail.maildlp.com (unknown [172.19.163.174])
	by szxga03-in.huawei.com (SkyGuard) with ESMTP id 4YxyT969VDzTjWs;
	Tue, 18 Feb 2025 19:48:13 +0800 (CST)
Received: from kwepemk500005.china.huawei.com (unknown [7.202.194.90])
	by mail.maildlp.com (Postfix) with ESMTPS id 6C7E4140361;
	Tue, 18 Feb 2025 19:51:13 +0800 (CST)
Received: from [10.174.179.234] (10.174.179.234) by
 kwepemk500005.china.huawei.com (7.202.194.90) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.2.1544.11; Tue, 18 Feb 2025 19:51:11 +0800
Message-ID: <3b181285-2ff3-b77a-867b-725f38ea86d3@huawei.com>
Date: Tue, 18 Feb 2025 19:51:10 +0800
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:91.0) Gecko/20100101
 Thunderbird/91.8.0
Subject: Re: [PATCH v13 4/5] arm64: support copy_mc_[user]_highpage()
To: Catalin Marinas <catalin.marinas@arm.com>
CC: Mark Rutland <mark.rutland@arm.com>, Jonathan Cameron
	<Jonathan.Cameron@huawei.com>, Mauro Carvalho Chehab
	<mchehab+huawei@kernel.org>, Will Deacon <will@kernel.org>, Andrew Morton
	<akpm@linux-foundation.org>, James Morse <james.morse@arm.com>, Robin Murphy
	<robin.murphy@arm.com>, Andrey Konovalov <andreyknvl@gmail.com>, Dmitry
 Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Michael Ellerman <mpe@ellerman.id.au>, Nicholas Piggin <npiggin@gmail.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko
	<glider@google.com>, Christophe Leroy <christophe.leroy@csgroup.eu>, Aneesh
 Kumar K.V <aneesh.kumar@kernel.org>, "Naveen N. Rao"
	<naveen.n.rao@linux.ibm.com>, Thomas Gleixner <tglx@linutronix.de>, Ingo
 Molnar <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>, Dave Hansen
	<dave.hansen@linux.intel.com>, <x86@kernel.org>, "H. Peter Anvin"
	<hpa@zytor.com>, Madhavan Srinivasan <maddy@linux.ibm.com>,
	<linux-arm-kernel@lists.infradead.org>, <linux-mm@kvack.org>,
	<linuxppc-dev@lists.ozlabs.org>, <linux-kernel@vger.kernel.org>,
	<kasan-dev@googlegroups.com>, <wangkefeng.wang@huawei.com>, Guohanjun
	<guohanjun@huawei.com>
References: <20241209024257.3618492-1-tongtiangen@huawei.com>
 <20241209024257.3618492-5-tongtiangen@huawei.com> <Z6zWSXzKctkpyH7-@arm.com>
 <69955002-c3b1-459d-9b42-8d07475c3fd3@huawei.com> <Z698SFVqHjpGeGC0@arm.com>
 <e1d2affb-5c6b-00b5-8209-34bbca36f96b@huawei.com> <Z7NN5Pa-c5PtIbcF@arm.com>
From: "'Tong Tiangen' via kasan-dev" <kasan-dev@googlegroups.com>
In-Reply-To: <Z7NN5Pa-c5PtIbcF@arm.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Transfer-Encoding: quoted-printable
X-Originating-IP: [10.174.179.234]
X-ClientProxiedBy: dggems705-chm.china.huawei.com (10.3.19.182) To
 kwepemk500005.china.huawei.com (7.202.194.90)
X-Original-Sender: tongtiangen@huawei.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of tongtiangen@huawei.com designates 45.249.212.189 as
 permitted sender) smtp.mailfrom=tongtiangen@huawei.com;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
X-Original-From: Tong Tiangen <tongtiangen@huawei.com>
Reply-To: Tong Tiangen <tongtiangen@huawei.com>
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



=E5=9C=A8 2025/2/17 22:55, Catalin Marinas =E5=86=99=E9=81=93:
> On Mon, Feb 17, 2025 at 04:07:49PM +0800, Tong Tiangen wrote:
>> =E5=9C=A8 2025/2/15 1:24, Catalin Marinas =E5=86=99=E9=81=93:
>>> On Fri, Feb 14, 2025 at 10:49:01AM +0800, Tong Tiangen wrote:
>>>> =E5=9C=A8 2025/2/13 1:11, Catalin Marinas =E5=86=99=E9=81=93:
>>>>> On Mon, Dec 09, 2024 at 10:42:56AM +0800, Tong Tiangen wrote:
>>>>>> Currently, many scenarios that can tolerate memory errors when copyi=
ng page
>>>>>> have been supported in the kernel[1~5], all of which are implemented=
 by
>>>>>> copy_mc_[user]_highpage(). arm64 should also support this mechanism.
>>>>>>
>>>>>> Due to mte, arm64 needs to have its own copy_mc_[user]_highpage()
>>>>>> architecture implementation, macros __HAVE_ARCH_COPY_MC_HIGHPAGE and
>>>>>> __HAVE_ARCH_COPY_MC_USER_HIGHPAGE have been added to control it.
>>>>>>
>>>>>> Add new helper copy_mc_page() which provide a page copy implementati=
on with
>>>>>> hardware memory error safe. The code logic of copy_mc_page() is the =
same as
>>>>>> copy_page(), the main difference is that the ldp insn of copy_mc_pag=
e()
>>>>>> contains the fixup type EX_TYPE_KACCESS_ERR_ZERO_MEM_ERR, therefore,=
 the
>>>>>> main logic is extracted to copy_page_template.S. In addition, the fi=
xup of
>>>>>> MOPS insn is not considered at present.
>>>>>
>>>>> Could we not add the exception table entry permanently but ignore the
>>>>> exception table entry if it's not on the do_sea() path? That would sa=
ve
>>>>> some code duplication.
>>>>
>>>> I'm sorry, I didn't catch your point, that the do_sea() and non do_sea=
()
>>>> paths use different exception tables?
>>>
>>> No, they would have the same exception table, only that we'd interpret
>>> it differently depending on whether it's a SEA error or not. Or rather
>>> ignore the exception table altogether for non-SEA errors.
>>
>> You mean to use the same exception type (EX_TYPE_KACCESS_ERR_ZERO) and
>> then do different processing on SEA errors and non-SEA errors, right?
>=20
> Right.

Ok, now we have the same understanding.

>=20
>> If so, some instructions of copy_page() did not add to the exception
>> table will be added to the exception table, and the original logic will
>> be affected.
>>
>> For example, if an instruction is not added to the exception table, the
>> instruction will panic when it triggers a non-SEA error. If this
>> instruction is added to the exception table because of SEA processing,
>> and then a non-SEA error is triggered, should we fix it?
>=20
> No, we shouldn't fix it. The exception table entries have a type
> associated. For a non-SEA error, we preserve the original behaviour even
> if we find a SEA-specific entry in the exception table. You already need
> such logic even if you duplicate the code for configurations where you
> have MC enabled.


So we need another way to distinguish the different processing of the
same exception type on SEA and non-SEA path.

For example, using strcut exception_table_entry.data, the disadvantage
is that it occupies the future expansion space of data.

I still think it's better to use methods like copy_from_user.S and
copy_to_user.S calling copy_template.S, and the duplicate code in
copy_template.S.

Thanks,
Tong.

>=20

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/3=
b181285-2ff3-b77a-867b-725f38ea86d3%40huawei.com.
