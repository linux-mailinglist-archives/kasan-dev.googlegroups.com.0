Return-Path: <kasan-dev+bncBAABBE754OWQMGQEMTQJQJY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb40.google.com (mail-yb1-xb40.google.com [IPv6:2607:f8b0:4864:20::b40])
	by mail.lfdr.de (Postfix) with ESMTPS id AE45884266E
	for <lists+kasan-dev@lfdr.de>; Tue, 30 Jan 2024 14:50:12 +0100 (CET)
Received: by mail-yb1-xb40.google.com with SMTP id 3f1490d57ef6-dc221ed88d9sf6499148276.3
        for <lists+kasan-dev@lfdr.de>; Tue, 30 Jan 2024 05:50:12 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1706622611; cv=pass;
        d=google.com; s=arc-20160816;
        b=xUVbdb/jncLCi7gfMvg2gkCwGmxIkk7kRf7crKp2bvBUI1oj4hDVy85z5cfcEwgYpO
         36XEbh9+oN9OTdtu/B5lClpTUh17WoQfSHvm78iWEelcFeosxDr8P3fM3/NlrIJH7SxB
         xSab3idwURKPwTwML9Xa5IpBrwDi7UeUHiavIJtUvhFAmDuQT7NrGN3eB1PMgs9N6JA4
         CMhSebgvyFF2ldDiOKjyP1ttPM++zsH7fzzZ44LMC6nKb0jTC0T9aox+J4MuQcfwdlK/
         eUlQR4oVbvpqJB7JEoNrnAnqKCVNpIyPqYOONbIW+xw6X5WaLgZr7OXdzQDpWcutXdf+
         UUdw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :in-reply-to:from:references:cc:to:subject:user-agent:mime-version
         :date:message-id:dkim-signature;
        bh=zu16dtn/4BL2tx7baxyjc/sYKvacJEHTY91D6N02I6E=;
        fh=oQg1EX8JIjao8bdPjdbl5g1OmYhLsn/ofyzX6C2cS+w=;
        b=ISXL7Bq5YPlgxzMH9IBv7bD2vWuKF5ldfHZMcldb0+zkgB3tuAhf7UKJqTc57ZWGC6
         kI4enb8GK00x+nmKA+pVaDrLgktvy7+G9Q9erU3U9EllCnhetbJcKNF28fH2DbX20BS4
         kJeBTeyAosAYHRg0b3E8Mv444Socjq67AgYUGbWaNM4Xj8SGvLkixJLmH2fx9xJCkq6L
         82IwB1il51RDurG5+K63iQjTNnbjh5guyx/1h2H+B3SJrh3MZpPdXZkU2vJEtdvETiIK
         chzRSi13blEy6KfIem8JrUjzYVBav5zUp9QjFZkJcDZRY9tI4eZSFrJ6wUpPpChqA+1h
         /7HA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of tongtiangen@huawei.com designates 45.249.212.189 as permitted sender) smtp.mailfrom=tongtiangen@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1706622611; x=1707227411; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:from:references:cc:to:subject
         :user-agent:mime-version:date:message-id:from:to:cc:subject:date
         :message-id:reply-to;
        bh=zu16dtn/4BL2tx7baxyjc/sYKvacJEHTY91D6N02I6E=;
        b=Az9gVcmyfCdgv1PUhXnDx8Zn7m68vDvqoeXwBOkpbOcgGMTjaKIX5b5HHa1KQMpYuG
         BhZNVxl4GfQDrYwSXtPn5JbZHLRs5WsCOBit1F9909UTkthtiIJ/PKQlgS0Et9Ug/R/q
         3y7PPodYdYGF5Fgr+e6Xy7d9FkTDTa/pmr4au0FBwqJ3n1VbnzeHwaiXgybpvwc4Bo81
         NDpYRKuw+2+ITnX5pN8zDgXGRY41cPG8kQk6jUbC+/eWPEuWNDccz1bdID0nZmPP92Ia
         V/A2WjQ6veit0ua418EH+iRJ6rzTVtSmkQaN0mv84fdgfT82HGFdcwrnuLI+Ghhk5dGi
         z6Lg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1706622611; x=1707227411;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:from:references:cc:to:subject
         :user-agent:mime-version:date:message-id:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=zu16dtn/4BL2tx7baxyjc/sYKvacJEHTY91D6N02I6E=;
        b=rGQHL/9HrmqwUEOK9/AYMY3P/8GKdH7AJzlqAuELaMbBAvxB3zi+vKicjxBjqyCyzS
         2jraLMGQ4mJKGeEPdRAUUOnX80YnFc13BiW9rGC0ssa8TEFsVcbho7aNavB36tZkULsz
         31sr2RvoVenlvcvOJH2h0+5vSO9/I+Glx7ntorcvWYqWia9b3T8GBkbQbfXMo7R88gGM
         alSVgZ7zwX3hyi3mw/o7XDkCb3o2Yc7xxbt3yoGpfsPLU8bTyH03wpjwMy/RdM7JoR7e
         ZZpxUEfuXgix4d7BIyxzHc85sJUMRyu/uu/DXRR92lsEz052fMErDvZJ2Kecylf7Kx9H
         UANA==
X-Gm-Message-State: AOJu0YxpKg6tZo9U7MXCzj2IbzBWzfnjvmOfQZ2TAQ3hIbyXd9gL4Pxm
	Heu64M9I5u0/4fGQc0rh0GTRvHFvvs4CoaMQfvEidOcY8AzBsh73
X-Google-Smtp-Source: AGHT+IFwfaylfcgGRlJcarC63z4MrfkGUIKpDdiGh6RAq2XWCZbxFdoAR6bPI7KN6LqitkW0FJG/Sw==
X-Received: by 2002:a25:9701:0:b0:dc2:5274:fd3a with SMTP id d1-20020a259701000000b00dc25274fd3amr6606156ybo.23.1706622611468;
        Tue, 30 Jan 2024 05:50:11 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6902:1206:b0:dc2:252d:7373 with SMTP id
 s6-20020a056902120600b00dc2252d7373ls237035ybu.2.-pod-prod-04-us; Tue, 30 Jan
 2024 05:50:10 -0800 (PST)
X-Received: by 2002:a67:bc1a:0:b0:46a:fdbb:6330 with SMTP id t26-20020a67bc1a000000b0046afdbb6330mr4417909vsn.28.1706622610390;
        Tue, 30 Jan 2024 05:50:10 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1706622610; cv=none;
        d=google.com; s=arc-20160816;
        b=Nop+wqJLGi4GrWiXtUED2ISA+Vf7sYXaB6xRM5IHpLHdT4WNtuQZK9WC5vceA5g9lJ
         GCQlKhX4fpgYOGYgzLBfeBpkWu4wxU/rQ020Lrs3l3FTzat4ZTWN9+1VYA6FhDpvz3eM
         vSz3d8CkVn74yrATPHDQtG+qDktRCbWU3qpc7w9DKqrT0Fr3Au9F4XKcgLLsRXPyV7DZ
         ZO0kOziU+FY6jPwvyQPXWTA+OkYamyrx4lAckw2og/F+BgCm/Bq428pkIfIvJc/2VasR
         d0XWebDp08LGF9YEZWb/wfjXd+ZhWMiwtzPdJ8ZaK3kC8m1qgbNGDmqtqUsHY9QKPLje
         Ghag==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to:subject
         :user-agent:mime-version:date:message-id;
        bh=njswFhihU4wIPtsqNIy1RukC7FY6gDJc/TLv8heQN00=;
        fh=oQg1EX8JIjao8bdPjdbl5g1OmYhLsn/ofyzX6C2cS+w=;
        b=XFGXaK2rhuaXRWpYKB3kE4q88KhpY0hBrl7X8EPFrXr/25A+x3Y7r+zSvBw6qwFy3V
         KdsZQGhv8xIVdbmaD3c1fhHRmklH0OOtAuhPk0OuUZdOjmPAG5mdisw/MkHh1ASOUgI5
         GFV5nrcU/qxWLaU0t4j1gfo+MpQZ/Xgg9vLx3W26GQQPdHauzcni1p+EmHjZ6fHPnRb8
         xC2cprtFpn/bPtBT+PJHvwX/nyQCw9BSq9Onffg45hkF+SHyOlF/Tknu/8sRhPNmqGqf
         Gx87l9hSzvHZuNxZdjxe27oPQC9DVsGve2yZ0u/EsxfDGzC5MSnTzli434y9ufwV4Gti
         5rpQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of tongtiangen@huawei.com designates 45.249.212.189 as permitted sender) smtp.mailfrom=tongtiangen@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
X-Forwarded-Encrypted: i=0; AJvYcCVQQvPQTSZyqZYgdhSSj/sHD4VwAALNdj3TxohV7YiKsYdNS2WC90smzwAY+kYS4eyqkBzCV3cSCTgkXQGh8GCmqHqd7fT5Z3V+ug==
Received: from szxga03-in.huawei.com (szxga03-in.huawei.com. [45.249.212.189])
        by gmr-mx.google.com with ESMTPS id x10-20020a05610207aa00b0046af7afacbfsi713292vsg.2.2024.01.30.05.50.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 30 Jan 2024 05:50:10 -0800 (PST)
Received-SPF: pass (google.com: domain of tongtiangen@huawei.com designates 45.249.212.189 as permitted sender) client-ip=45.249.212.189;
Received: from mail.maildlp.com (unknown [172.19.88.194])
	by szxga03-in.huawei.com (SkyGuard) with ESMTP id 4TPRNM5yv9zJpQM;
	Tue, 30 Jan 2024 21:49:07 +0800 (CST)
Received: from kwepemm600017.china.huawei.com (unknown [7.193.23.234])
	by mail.maildlp.com (Postfix) with ESMTPS id 454CD1400FF;
	Tue, 30 Jan 2024 21:50:07 +0800 (CST)
Received: from [10.174.179.234] (10.174.179.234) by
 kwepemm600017.china.huawei.com (7.193.23.234) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2507.35; Tue, 30 Jan 2024 21:50:05 +0800
Message-ID: <5227661e-da3b-6cff-37c5-5ddb7825e7b8@huawei.com>
Date: Tue, 30 Jan 2024 21:50:04 +0800
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:91.0) Gecko/20100101
 Thunderbird/91.8.0
Subject: Re: [PATCH v10 5/6] arm64: support copy_mc_[user]_highpage()
To: Mark Rutland <mark.rutland@arm.com>
CC: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will@kernel.org>,
	James Morse <james.morse@arm.com>, Robin Murphy <robin.murphy@arm.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko
	<glider@google.com>, Alexander Viro <viro@zeniv.linux.org.uk>, Andrey
 Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Andrew Morton
	<akpm@linux-foundation.org>, Michael Ellerman <mpe@ellerman.id.au>, Nicholas
 Piggin <npiggin@gmail.com>, Christophe Leroy <christophe.leroy@csgroup.eu>,
	Aneesh Kumar K.V <aneesh.kumar@kernel.org>, "Naveen N. Rao"
	<naveen.n.rao@linux.ibm.com>, Thomas Gleixner <tglx@linutronix.de>, Ingo
 Molnar <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>, Dave Hansen
	<dave.hansen@linux.intel.com>, <x86@kernel.org>, "H. Peter Anvin"
	<hpa@zytor.com>, <linux-arm-kernel@lists.infradead.org>,
	<linux-mm@kvack.org>, <linuxppc-dev@lists.ozlabs.org>,
	<linux-kernel@vger.kernel.org>, <kasan-dev@googlegroups.com>,
	<wangkefeng.wang@huawei.com>, Guohanjun <guohanjun@huawei.com>
References: <20240129134652.4004931-1-tongtiangen@huawei.com>
 <20240129134652.4004931-6-tongtiangen@huawei.com>
 <ZbjP_19VCYmtsGcg@FVFF77S0Q05N>
From: "'Tong Tiangen' via kasan-dev" <kasan-dev@googlegroups.com>
In-Reply-To: <ZbjP_19VCYmtsGcg@FVFF77S0Q05N>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Transfer-Encoding: quoted-printable
X-Originating-IP: [10.174.179.234]
X-ClientProxiedBy: dggems704-chm.china.huawei.com (10.3.19.181) To
 kwepemm600017.china.huawei.com (7.193.23.234)
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



=E5=9C=A8 2024/1/30 18:31, Mark Rutland =E5=86=99=E9=81=93:
> On Mon, Jan 29, 2024 at 09:46:51PM +0800, Tong Tiangen wrote:
>> Currently, many scenarios that can tolerate memory errors when copying p=
age
>> have been supported in the kernel[1][2][3], all of which are implemented=
 by
>> copy_mc_[user]_highpage(). arm64 should also support this mechanism.
>>
>> Due to mte, arm64 needs to have its own copy_mc_[user]_highpage()
>> architecture implementation, macros __HAVE_ARCH_COPY_MC_HIGHPAGE and
>> __HAVE_ARCH_COPY_MC_USER_HIGHPAGE have been added to control it.
>>
>> Add new helper copy_mc_page() which provide a page copy implementation w=
ith
>> machine check safe. The copy_mc_page() in copy_mc_page.S is largely borr=
ows
>> from copy_page() in copy_page.S and the main difference is copy_mc_page(=
)
>> add extable entry to every load/store insn to support machine check safe=
.
>>
>> Add new extable type EX_TYPE_COPY_MC_PAGE_ERR_ZERO which used in
>> copy_mc_page().
>>
>> [1]a873dfe1032a ("mm, hwpoison: try to recover from copy-on write faults=
")
>> [2]5f2500b93cc9 ("mm/khugepaged: recover from poisoned anonymous memory"=
)
>> [3]6b970599e807 ("mm: hwpoison: support recovery from ksm_might_need_to_=
copy()")
>>
>> Signed-off-by: Tong Tiangen <tongtiangen@huawei.com>
>> ---
>>   arch/arm64/include/asm/asm-extable.h | 15 ++++++
>>   arch/arm64/include/asm/assembler.h   |  4 ++
>>   arch/arm64/include/asm/mte.h         |  5 ++
>>   arch/arm64/include/asm/page.h        | 10 ++++
>>   arch/arm64/lib/Makefile              |  2 +
>>   arch/arm64/lib/copy_mc_page.S        | 78 ++++++++++++++++++++++++++++
>>   arch/arm64/lib/mte.S                 | 27 ++++++++++
>>   arch/arm64/mm/copypage.c             | 66 ++++++++++++++++++++---
>>   arch/arm64/mm/extable.c              |  7 +--
>>   include/linux/highmem.h              |  8 +++
>>   10 files changed, 213 insertions(+), 9 deletions(-)
>>   create mode 100644 arch/arm64/lib/copy_mc_page.S
>>
>> diff --git a/arch/arm64/include/asm/asm-extable.h b/arch/arm64/include/a=
sm/asm-extable.h
>> index 980d1dd8e1a3..819044fefbe7 100644
>> --- a/arch/arm64/include/asm/asm-extable.h
>> +++ b/arch/arm64/include/asm/asm-extable.h
>> @@ -10,6 +10,7 @@
>>   #define EX_TYPE_UACCESS_ERR_ZERO	2
>>   #define EX_TYPE_KACCESS_ERR_ZERO	3
>>   #define EX_TYPE_LOAD_UNALIGNED_ZEROPAD	4
>> +#define EX_TYPE_COPY_MC_PAGE_ERR_ZERO	5
>>  =20
>>   /* Data fields for EX_TYPE_UACCESS_ERR_ZERO */
>>   #define EX_DATA_REG_ERR_SHIFT	0
>> @@ -51,6 +52,16 @@
>>   #define _ASM_EXTABLE_UACCESS(insn, fixup)				\
>>   	_ASM_EXTABLE_UACCESS_ERR_ZERO(insn, fixup, wzr, wzr)
>>  =20
>> +#define _ASM_EXTABLE_COPY_MC_PAGE_ERR_ZERO(insn, fixup, err, zero)	\
>> +	__ASM_EXTABLE_RAW(insn, fixup, 					\
>> +			  EX_TYPE_COPY_MC_PAGE_ERR_ZERO,		\
>> +			  (						\
>> +			    EX_DATA_REG(ERR, err) |			\
>> +			    EX_DATA_REG(ZERO, zero)			\
>> +			  ))
>> +
>> +#define _ASM_EXTABLE_COPY_MC_PAGE(insn, fixup)				\
>> +	_ASM_EXTABLE_COPY_MC_PAGE_ERR_ZERO(insn, fixup, wzr, wzr)
>>   /*
>>    * Create an exception table entry for uaccess `insn`, which will bran=
ch to `fixup`
>>    * when an unhandled fault is taken.
>> @@ -59,6 +70,10 @@
>>   	_ASM_EXTABLE_UACCESS(\insn, \fixup)
>>   	.endm
>>  =20
>> +	.macro          _asm_extable_copy_mc_page, insn, fixup
>> +	_ASM_EXTABLE_COPY_MC_PAGE(\insn, \fixup)
>> +	.endm
>> +
>=20
> This should share a common EX_TYPE_ with the other "kaccess where memory =
error
> is handled but other faults are fatal" cases.

OK, reasonable.
>=20
>>   /*
>>    * Create an exception table entry for `insn` if `fixup` is provided. =
Otherwise
>>    * do nothing.
>> diff --git a/arch/arm64/include/asm/assembler.h b/arch/arm64/include/asm=
/assembler.h
>> index 513787e43329..e1d8ce155878 100644
>> --- a/arch/arm64/include/asm/assembler.h
>> +++ b/arch/arm64/include/asm/assembler.h
>> @@ -154,6 +154,10 @@ lr	.req	x30		// link register
>>   #define CPU_LE(code...) code
>>   #endif
>>  =20
>> +#define CPY_MC(l, x...)		\
>> +9999:   x;			\
>> +	_asm_extable_copy_mc_page    9999b, l
>> +
>>   /*
>>    * Define a macro that constructs a 64-bit value by concatenating two
>>    * 32-bit registers. Note that on big endian systems the order of the
>> diff --git a/arch/arm64/include/asm/mte.h b/arch/arm64/include/asm/mte.h
>> index 91fbd5c8a391..9cdded082dd4 100644
>> --- a/arch/arm64/include/asm/mte.h
>> +++ b/arch/arm64/include/asm/mte.h
>> @@ -92,6 +92,7 @@ static inline bool try_page_mte_tagging(struct page *p=
age)
>>   void mte_zero_clear_page_tags(void *addr);
>>   void mte_sync_tags(pte_t pte, unsigned int nr_pages);
>>   void mte_copy_page_tags(void *kto, const void *kfrom);
>> +int mte_copy_mc_page_tags(void *kto, const void *kfrom);
>>   void mte_thread_init_user(void);
>>   void mte_thread_switch(struct task_struct *next);
>>   void mte_cpu_setup(void);
>> @@ -128,6 +129,10 @@ static inline void mte_sync_tags(pte_t pte, unsigne=
d int nr_pages)
>>   static inline void mte_copy_page_tags(void *kto, const void *kfrom)
>>   {
>>   }
>> +static inline int mte_copy_mc_page_tags(void *kto, const void *kfrom)
>> +{
>> +	return 0;
>> +}
>>   static inline void mte_thread_init_user(void)
>>   {
>>   }
>> diff --git a/arch/arm64/include/asm/page.h b/arch/arm64/include/asm/page=
.h
>> index 2312e6ee595f..304cc86b8a10 100644
>> --- a/arch/arm64/include/asm/page.h
>> +++ b/arch/arm64/include/asm/page.h
>> @@ -29,6 +29,16 @@ void copy_user_highpage(struct page *to, struct page =
*from,
>>   void copy_highpage(struct page *to, struct page *from);
>>   #define __HAVE_ARCH_COPY_HIGHPAGE
>>  =20
>> +#ifdef CONFIG_ARCH_HAS_COPY_MC
>> +int copy_mc_page(void *to, const void *from);
>> +int copy_mc_highpage(struct page *to, struct page *from);
>> +#define __HAVE_ARCH_COPY_MC_HIGHPAGE
>> +
>> +int copy_mc_user_highpage(struct page *to, struct page *from,
>> +		unsigned long vaddr, struct vm_area_struct *vma);
>> +#define __HAVE_ARCH_COPY_MC_USER_HIGHPAGE
>> +#endif
>> +
>>   struct folio *vma_alloc_zeroed_movable_folio(struct vm_area_struct *vm=
a,
>>   						unsigned long vaddr);
>>   #define vma_alloc_zeroed_movable_folio vma_alloc_zeroed_movable_folio
>> diff --git a/arch/arm64/lib/Makefile b/arch/arm64/lib/Makefile
>> index 29490be2546b..a2fd865b816d 100644
>> --- a/arch/arm64/lib/Makefile
>> +++ b/arch/arm64/lib/Makefile
>> @@ -15,6 +15,8 @@ endif
>>  =20
>>   lib-$(CONFIG_ARCH_HAS_UACCESS_FLUSHCACHE) +=3D uaccess_flushcache.o
>>  =20
>> +lib-$(CONFIG_ARCH_HAS_COPY_MC) +=3D copy_mc_page.o
>> +
>>   obj-$(CONFIG_CRC32) +=3D crc32.o
>>  =20
>>   obj-$(CONFIG_FUNCTION_ERROR_INJECTION) +=3D error-inject.o
>> diff --git a/arch/arm64/lib/copy_mc_page.S b/arch/arm64/lib/copy_mc_page=
.S
>> new file mode 100644
>> index 000000000000..524534d26d86
>> --- /dev/null
>> +++ b/arch/arm64/lib/copy_mc_page.S
>> @@ -0,0 +1,78 @@
>> +/* SPDX-License-Identifier: GPL-2.0-only */
>> +/*
>> + * Copyright (C) 2012 ARM Ltd.
>> + */
>> +
>> +#include <linux/linkage.h>
>> +#include <linux/const.h>
>> +#include <asm/assembler.h>
>> +#include <asm/page.h>
>> +#include <asm/cpufeature.h>
>> +#include <asm/alternative.h>
>> +#include <asm/asm-extable.h>
>> +
>> +/*
>> + * Copy a page from src to dest (both are page aligned) with machine ch=
eck
>> + *
>> + * Parameters:
>> + *	x0 - dest
>> + *	x1 - src
>> + * Returns:
>> + * 	x0 - Return 0 if copy success, or -EFAULT if anything goes wrong
>> + *	     while copying.
>> + */
>> +SYM_FUNC_START(__pi_copy_mc_page)
>> +CPY_MC(9998f, ldp	x2, x3, [x1])
>> +CPY_MC(9998f, ldp	x4, x5, [x1, #16])
>> +CPY_MC(9998f, ldp	x6, x7, [x1, #32])
>> +CPY_MC(9998f, ldp	x8, x9, [x1, #48])
>> +CPY_MC(9998f, ldp	x10, x11, [x1, #64])
>> +CPY_MC(9998f, ldp	x12, x13, [x1, #80])
>> +CPY_MC(9998f, ldp	x14, x15, [x1, #96])
>> +CPY_MC(9998f, ldp	x16, x17, [x1, #112])
>> +
>> +	add	x0, x0, #256
>> +	add	x1, x1, #128
>> +1:
>> +	tst	x0, #(PAGE_SIZE - 1)
>> +
>> +CPY_MC(9998f, stnp	x2, x3, [x0, #-256])
>> +CPY_MC(9998f, ldp	x2, x3, [x1])
>> +CPY_MC(9998f, stnp	x4, x5, [x0, #16 - 256])
>> +CPY_MC(9998f, ldp	x4, x5, [x1, #16])
>> +CPY_MC(9998f, stnp	x6, x7, [x0, #32 - 256])
>> +CPY_MC(9998f, ldp	x6, x7, [x1, #32])
>> +CPY_MC(9998f, stnp	x8, x9, [x0, #48 - 256])
>> +CPY_MC(9998f, ldp	x8, x9, [x1, #48])
>> +CPY_MC(9998f, stnp	x10, x11, [x0, #64 - 256])
>> +CPY_MC(9998f, ldp	x10, x11, [x1, #64])
>> +CPY_MC(9998f, stnp	x12, x13, [x0, #80 - 256])
>> +CPY_MC(9998f, ldp	x12, x13, [x1, #80])
>> +CPY_MC(9998f, stnp	x14, x15, [x0, #96 - 256])
>> +CPY_MC(9998f, ldp	x14, x15, [x1, #96])
>> +CPY_MC(9998f, stnp	x16, x17, [x0, #112 - 256])
>> +CPY_MC(9998f, ldp	x16, x17, [x1, #112])
>> +
>> +	add	x0, x0, #128
>> +	add	x1, x1, #128
>> +
>> +	b.ne	1b
>> +
>> +CPY_MC(9998f, stnp	x2, x3, [x0, #-256])
>> +CPY_MC(9998f, stnp	x4, x5, [x0, #16 - 256])
>> +CPY_MC(9998f, stnp	x6, x7, [x0, #32 - 256])
>> +CPY_MC(9998f, stnp	x8, x9, [x0, #48 - 256])
>> +CPY_MC(9998f, stnp	x10, x11, [x0, #64 - 256])
>> +CPY_MC(9998f, stnp	x12, x13, [x0, #80 - 256])
>> +CPY_MC(9998f, stnp	x14, x15, [x0, #96 - 256])
>> +CPY_MC(9998f, stnp	x16, x17, [x0, #112 - 256])
>> +
>> +	mov x0, #0
>> +	ret
>> +
>> +9998:	mov x0, #-EFAULT
>> +	ret
>> +
>> +SYM_FUNC_END(__pi_copy_mc_page)
>> +SYM_FUNC_ALIAS(copy_mc_page, __pi_copy_mc_page)
>> +EXPORT_SYMBOL(copy_mc_page)
>=20
> This is a duplicate of the existing copy_page logic; it should be refacto=
red
> such that the logic can be shared.

OK, I'll think about how to do it.

>=20
>> diff --git a/arch/arm64/lib/mte.S b/arch/arm64/lib/mte.S
>> index 5018ac03b6bf..2b748e83f6cf 100644
>> --- a/arch/arm64/lib/mte.S
>> +++ b/arch/arm64/lib/mte.S
>> @@ -80,6 +80,33 @@ SYM_FUNC_START(mte_copy_page_tags)
>>   	ret
>>   SYM_FUNC_END(mte_copy_page_tags)
>>  =20
>> +/*
>> + * Copy the tags from the source page to the destination one wiht machi=
ne check safe
>> + *   x0 - address of the destination page
>> + *   x1 - address of the source page
>> + * Returns:
>> + *   x0 - Return 0 if copy success, or
>> + *        -EFAULT if anything goes wrong while copying.
>> + */
>> +SYM_FUNC_START(mte_copy_mc_page_tags)
>> +	mov	x2, x0
>> +	mov	x3, x1
>> +	multitag_transfer_size x5, x6
>> +1:
>> +CPY_MC(2f, ldgm	x4, [x3])
>> +CPY_MC(2f, stgm	x4, [x2])
>> +	add	x2, x2, x5
>> +	add	x3, x3, x5
>> +	tst	x2, #(PAGE_SIZE - 1)
>> +	b.ne	1b
>> +
>> +	mov x0, #0
>> +	ret
>> +
>> +2:	mov x0, #-EFAULT
>> +	ret
>> +SYM_FUNC_END(mte_copy_mc_page_tags)
>> +
>>   /*
>>    * Read tags from a user buffer (one tag per byte) and set the corresp=
onding
>>    * tags at the given kernel address. Used by PTRACE_POKEMTETAGS.
>> diff --git a/arch/arm64/mm/copypage.c b/arch/arm64/mm/copypage.c
>> index a7bb20055ce0..9765e40cde6c 100644
>> --- a/arch/arm64/mm/copypage.c
>> +++ b/arch/arm64/mm/copypage.c
>> @@ -14,6 +14,25 @@
>>   #include <asm/cpufeature.h>
>>   #include <asm/mte.h>
>>  =20
>> +static int do_mte(struct page *to, struct page *from, void *kto, void *=
kfrom, bool mc)
>> +{
>> +	int ret =3D 0;
>> +
>> +	if (system_supports_mte() && page_mte_tagged(from)) {
>> +		/* It's a new page, shouldn't have been tagged yet */
>> +		WARN_ON_ONCE(!try_page_mte_tagging(to));
>> +		if (mc)
>> +			ret =3D mte_copy_mc_page_tags(kto, kfrom);
>> +		else
>> +			mte_copy_page_tags(kto, kfrom);
>> +
>> +		if (!ret)
>> +			set_page_mte_tagged(to);
>> +	}
>> +
>> +	return ret;
>> +}
>=20
> The boolean 'mc' argument makes this painful to read, and I don't think i=
t's
> necessary to have this helper anyway.
>=20
> It'd be clearer to have this expanded inline in the callers, e.g.
>=20
> 	// in copy_highpage(), as-is today
> 	if (system_supports_mte() && page_mte_tagged(from)) {
> 		/* It's a new page, shouldn't have been tagged yet */
> 		WARN_ON_ONCE(!try_page_mte_tagging(to));
> 		mte_copy_page_tags(kto, kfrom);
> 		set_page_mte_tagged(to);
> 	}
>=20
> 	// in copy_mc_highpage()
> 	if (system_supports_mte() && page_mte_tagged(from)) {
> 		/* It's a new page, shouldn't have been tagged yet */
> 		WARN_ON_ONCE(!try_page_mte_tagging(to));
> 		ret =3D mte_copy_mc_page_tags(kto, kfrom);
> 		if (ret)
> 			return -EFAULT;
> 		set_page_mte_tagged(to);
> 	}

OK,  follow this idea in the next version.

>=20
> Mark.
>=20
>> +
>>   void copy_highpage(struct page *to, struct page *from)
>>   {
>>   	void *kto =3D page_address(to);
>> @@ -24,12 +43,7 @@ void copy_highpage(struct page *to, struct page *from=
)
>>   	if (kasan_hw_tags_enabled())
>>   		page_kasan_tag_reset(to);
>>  =20
>> -	if (system_supports_mte() && page_mte_tagged(from)) {
>> -		/* It's a new page, shouldn't have been tagged yet */
>> -		WARN_ON_ONCE(!try_page_mte_tagging(to));
>> -		mte_copy_page_tags(kto, kfrom);
>> -		set_page_mte_tagged(to);
>> -	}
>> +	do_mte(to, from, kto, kfrom, false);
>>   }
>>   EXPORT_SYMBOL(copy_highpage);
>>  =20
>> @@ -40,3 +54,43 @@ void copy_user_highpage(struct page *to, struct page =
*from,
>>   	flush_dcache_page(to);
>>   }
>>   EXPORT_SYMBOL_GPL(copy_user_highpage);
>> +
>> +#ifdef CONFIG_ARCH_HAS_COPY_MC
>> +/*
>> + * Return -EFAULT if anything goes wrong while copying page or mte.
>> + */
>> +int copy_mc_highpage(struct page *to, struct page *from)
>> +{
>> +	void *kto =3D page_address(to);
>> +	void *kfrom =3D page_address(from);
>> +	int ret;
>> +
>> +	ret =3D copy_mc_page(kto, kfrom);
>> +	if (ret)
>> +		return -EFAULT;
>> +
>> +	if (kasan_hw_tags_enabled())
>> +		page_kasan_tag_reset(to);
>> +
>> +	ret =3D do_mte(to, from, kto, kfrom, true);
>> +	if (ret)
>> +		return -EFAULT;
>> +
>> +	return 0;
>> +}
>> +EXPORT_SYMBOL(copy_mc_highpage);
>> +
>> +int copy_mc_user_highpage(struct page *to, struct page *from,
>> +			unsigned long vaddr, struct vm_area_struct *vma)
>> +{
>> +	int ret;
>> +
>> +	ret =3D copy_mc_highpage(to, from);
>> +
>> +	if (!ret)
>> +		flush_dcache_page(to);
>> +
>> +	return ret;
>> +}
>> +EXPORT_SYMBOL_GPL(copy_mc_user_highpage);
>> +#endif
>> diff --git a/arch/arm64/mm/extable.c b/arch/arm64/mm/extable.c
>> index 28ec35e3d210..bdc81518d207 100644
>> --- a/arch/arm64/mm/extable.c
>> +++ b/arch/arm64/mm/extable.c
>> @@ -16,7 +16,7 @@ get_ex_fixup(const struct exception_table_entry *ex)
>>   	return ((unsigned long)&ex->fixup + ex->fixup);
>>   }
>>  =20
>> -static bool ex_handler_uaccess_err_zero(const struct exception_table_en=
try *ex,
>> +static bool ex_handler_fixup_err_zero(const struct exception_table_entr=
y *ex,
>>   					struct pt_regs *regs)
>>   {
>>   	int reg_err =3D FIELD_GET(EX_DATA_REG_ERR, ex->data);
>> @@ -69,7 +69,7 @@ bool fixup_exception(struct pt_regs *regs)
>>   		return ex_handler_bpf(ex, regs);
>>   	case EX_TYPE_UACCESS_ERR_ZERO:
>>   	case EX_TYPE_KACCESS_ERR_ZERO:
>> -		return ex_handler_uaccess_err_zero(ex, regs);
>> +		return ex_handler_fixup_err_zero(ex, regs);
>>   	case EX_TYPE_LOAD_UNALIGNED_ZEROPAD:
>>   		return ex_handler_load_unaligned_zeropad(ex, regs);
>>   	}
>> @@ -87,7 +87,8 @@ bool fixup_exception_mc(struct pt_regs *regs)
>>  =20
>>   	switch (ex->type) {
>>   	case EX_TYPE_UACCESS_ERR_ZERO:
>> -		return ex_handler_uaccess_err_zero(ex, regs);
>> +	case EX_TYPE_COPY_MC_PAGE_ERR_ZERO:
>> +		return ex_handler_fixup_err_zero(ex, regs);
>>   	}
>>  =20
>>   	return false;
>> diff --git a/include/linux/highmem.h b/include/linux/highmem.h
>> index c5ca1a1fc4f5..a42470ca42f2 100644
>> --- a/include/linux/highmem.h
>> +++ b/include/linux/highmem.h
>> @@ -332,6 +332,7 @@ static inline void copy_highpage(struct page *to, st=
ruct page *from)
>>   #endif
>>  =20
>>   #ifdef copy_mc_to_kernel
>> +#ifndef __HAVE_ARCH_COPY_MC_USER_HIGHPAGE
>>   /*
>>    * If architecture supports machine check exception handling, define t=
he
>>    * #MC versions of copy_user_highpage and copy_highpage. They copy a m=
emory
>> @@ -354,7 +355,9 @@ static inline int copy_mc_user_highpage(struct page =
*to, struct page *from,
>>  =20
>>   	return ret ? -EFAULT : 0;
>>   }
>> +#endif
>>  =20
>> +#ifndef __HAVE_ARCH_COPY_MC_HIGHPAGE
>>   static inline int copy_mc_highpage(struct page *to, struct page *from)
>>   {
>>   	unsigned long ret;
>> @@ -370,20 +373,25 @@ static inline int copy_mc_highpage(struct page *to=
, struct page *from)
>>  =20
>>   	return ret ? -EFAULT : 0;
>>   }
>> +#endif
>>   #else
>> +#ifndef __HAVE_ARCH_COPY_MC_USER_HIGHPAGE
>>   static inline int copy_mc_user_highpage(struct page *to, struct page *=
from,
>>   					unsigned long vaddr, struct vm_area_struct *vma)
>>   {
>>   	copy_user_highpage(to, from, vaddr, vma);
>>   	return 0;
>>   }
>> +#endif
>>  =20
>> +#ifndef __HAVE_ARCH_COPY_MC_HIGHPAGE
>>   static inline int copy_mc_highpage(struct page *to, struct page *from)
>>   {
>>   	copy_highpage(to, from);
>>   	return 0;
>>   }
>>   #endif
>> +#endif
>>  =20
>>   static inline void memcpy_page(struct page *dst_page, size_t dst_off,
>>   			       struct page *src_page, size_t src_off,
>> --=20
>> 2.25.1
>>
> .

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/5227661e-da3b-6cff-37c5-5ddb7825e7b8%40huawei.com.
