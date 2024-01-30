Return-Path: <kasan-dev+bncBAABBG5M4OWQMGQEBG7LXEY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83c.google.com (mail-qt1-x83c.google.com [IPv6:2607:f8b0:4864:20::83c])
	by mail.lfdr.de (Postfix) with ESMTPS id 9483184220C
	for <lists+kasan-dev@lfdr.de>; Tue, 30 Jan 2024 11:57:32 +0100 (CET)
Received: by mail-qt1-x83c.google.com with SMTP id d75a77b69052e-42a8a7d7ec2sf220651cf.1
        for <lists+kasan-dev@lfdr.de>; Tue, 30 Jan 2024 02:57:32 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1706612251; cv=pass;
        d=google.com; s=arc-20160816;
        b=gbtgQc01mPtZoxs/oQkgjF+APbhuXzqJzUl6qhZVOikzGKlHshuapJsX+8Dc691loP
         40YJwgvey9srQBLIroIDkNJpkhZMnrZNom/6MZeac3sWuzx4opoZ0DwnxcRZk8a+XmKa
         3rUvl6/T82PDZ7inFi8ME5IQkjlY1zq3lUlcia9h+sdiEkhqp6cLn0dBmpJsh5idmx6z
         di9S8+Zio0QLJ9bmEOJCqddGZ8e41z8+2BpW26FwrzZprjYckDRWFcg2OpBVGeCtdxuQ
         IdM1MwZ5JBErQtYJSkA32n6vlu3B1Pp3XNw2XLLGOe68vXMlumLcifJkwVrEBkiIeYQo
         9pKg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :in-reply-to:from:references:cc:to:subject:user-agent:mime-version
         :date:message-id:dkim-signature;
        bh=D1eKiamVYLtWmEtXcn4GFh6IdDg7vfJ2fe03SMaP++E=;
        fh=/F39bVl75IFcIjds/FCPxnSNxd1K/bth980dDO3wGX8=;
        b=Lg9iiogsn6bdXMzT67+fDr76yqvKjjGuAR8s8hui649K38j5jc15WxO5sdI1MQKxos
         X8KfAdMcSTfJ0M4sH1u++unvVNVBxByHJViDpJjsayQuHI8u7xa3upldDOUgfYvj37DA
         54acKxMZosGxFDyjuvvdWBwUDqIBbFlNutocJ0AAl5et4q+CfAXuRo2MNgWHPUmgf/Lh
         5LKxQDZfXv08nKg+7GuVwt3+my2OA6jzKGAH07gQ2ZATxlG1w1WlZXGKR0vo8w/bDN6j
         1RJJYiLrHXOj5GhVuvwfIeelEpcpjfitrvttLApAuz1sAV49RcSYCD4H+MX8/n2MCJSN
         B0YA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of tongtiangen@huawei.com designates 45.249.212.190 as permitted sender) smtp.mailfrom=tongtiangen@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1706612251; x=1707217051; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:from:references:cc:to:subject
         :user-agent:mime-version:date:message-id:from:to:cc:subject:date
         :message-id:reply-to;
        bh=D1eKiamVYLtWmEtXcn4GFh6IdDg7vfJ2fe03SMaP++E=;
        b=ZcmQ1QRzC8RDDCqzOwZ0v+rId0b+LmDzeORV/1ho1cSrZIShL7WAPAnIA6x9oZ+dUm
         7wOPGz1cS4+uNaJsbhL8HtAxNrcm9g7ch4s3RLaHedOJrmw+cHLHLtgI8HI0ztBNnAp1
         fg5hWwXZSGrJkuyozAYrlclN577bs/x18M/fK5+dX1obG/p+9C19q6+gf3LXrVUZCpqn
         79oS8yP3nv57zQY0QhzzzQlSiRMjSKdbNd+sR4NiMTiZ2SWshCR0UXYyJEZtFrW4rVZM
         c6rqWITwDB4/LnE82E+kqM1Sl7C5DmQhFZ4hIMQRunbcBjzaVPsCWp39HMViWArZysCS
         SvBQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1706612251; x=1707217051;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:from:references:cc:to:subject
         :user-agent:mime-version:date:message-id:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=D1eKiamVYLtWmEtXcn4GFh6IdDg7vfJ2fe03SMaP++E=;
        b=DKTvTaUfbQfjyLjIl/wpYpDFCI5wQ9KDZybdmuWrl4p5Cu+RzErNIKHa/+GujpLX4u
         BTQCWwXkV9Qv/pTRG+a/jrQRAaPl2KnJQjjsKhhj8pLGZUG5WxlDZY6F/yhFvohjw9Uw
         vXTgI0wXx6tG5yXoCeohAmCZfXPR/aI+XYoEMzInsnVWnGLkdUUNkAjLSbssaArJYT5L
         1bK2UbuU8UtMjJJid43akhzXs2Uvi9q/DR2OnyXz3+mS6XfHp9VoG0nL8dQkxlQROSdP
         Vcl1WlG/QsVQg9mqlsrZd8sxBVwU/p855aYSsQ96I3qyppdg2M3xbahauCHw0tCDDVnr
         zP2Q==
X-Gm-Message-State: AOJu0YylrCYMLhXL8b6KWBXpBFCb9y+m9TCcBzK98tdTzhFtQv/0u1Jp
	69rAONO5PwL0qP5fukWgWkCURuSmMSVDX+gaG1mHQfkLrkzFVnAz
X-Google-Smtp-Source: AGHT+IEb4GLemZyTUaPaRJHSYGTi/7nMOYg9dnogHhSaX8qGq8EyrU6bpggqc6BNEv98pKpPfaiBSg==
X-Received: by 2002:a05:622a:2a85:b0:42a:b2b8:cddb with SMTP id kf5-20020a05622a2a8500b0042ab2b8cddbmr211047qtb.8.1706612251386;
        Tue, 30 Jan 2024 02:57:31 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:14f2:b0:68c:5c2d:cae9 with SMTP id
 k18-20020a05621414f200b0068c5c2dcae9ls1317167qvw.2.-pod-prod-05-us; Tue, 30
 Jan 2024 02:57:30 -0800 (PST)
X-Received: by 2002:a05:6214:2aac:b0:68c:4fac:930e with SMTP id js12-20020a0562142aac00b0068c4fac930emr3585807qvb.54.1706612250775;
        Tue, 30 Jan 2024 02:57:30 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1706612250; cv=none;
        d=google.com; s=arc-20160816;
        b=B66IFdqvIlEKge7/FhquEWgWx6rOYQXX5Iue7tSSDknn01d3yzgTdd6hpgCAo4xrUx
         todJiHfSsCnrRyiJG4gauGXiqTrzRaPWE2lNF1bkvY/XLwVT6jaXQrxdUnVw1GNYuiyE
         mJeLs2Pdr306R2v/qcFcppM5FrKeCl8Yhw2C3IyyglKXRtvGfUjAY9fXdGVzEAqT5Od2
         wtEpddGgw2RhejIzSl0nwXb9ihGTOBYP4V+LaGLUyLHArCpD5+MH682Z+oknL8A2zj51
         6zW5iN+qlcq2JGnrhFgLB68JcppdGriyjvCu4BB5Xme3UC2irWTb3NytEDwAPActucuF
         OPDw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to:subject
         :user-agent:mime-version:date:message-id;
        bh=5ODNVrnxRJ55NbfSqy1yNJWkW9Y1TOLtL1d3W7l0QpM=;
        fh=/F39bVl75IFcIjds/FCPxnSNxd1K/bth980dDO3wGX8=;
        b=R0OasMNf6pPyuhgncZKoDPauiaFkIJuA4COPWmC/qsXLhTPQdENZXxDJwEVuWitdOv
         ctos27iixNHAkKSh+ir32mooo2Yh4Qmx2/poH2anc1zJVGU5kYpVzajH0A8ZQkDXWFYc
         7ikpDCwfh9eh4G/2ryxPcnfzjGnv0Lg1rdfNspU9NPLt/X9hmWXZzQdEdFTW4iZkWZu0
         NChK8AJ9kdDe98JrT2NFMt11x5I9IO6RVSy9WEKMS9SM9/cZRvrJA3jml9f+cQD6P1ZA
         4nU6AwszuaNkeNFbzRo3AJlbGa2YqAYZTqYXKZaucVXaIBzLPzWFSnc++R1opWe2UtiA
         qRLw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of tongtiangen@huawei.com designates 45.249.212.190 as permitted sender) smtp.mailfrom=tongtiangen@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
X-Forwarded-Encrypted: i=0; AJvYcCUYtirWZG6YXT5YgsGJlgnz6FVpIAl9nXoS3iuIgmgX1t9JfL7TRtCIVc4U0rXEFRwCL0h4wK1AFRqp0bVKkn3ZWtwQqECC4ORl9Q==
Received: from szxga04-in.huawei.com (szxga04-in.huawei.com. [45.249.212.190])
        by gmr-mx.google.com with ESMTPS id kd8-20020a056214400800b006834973abd0si593423qvb.6.2024.01.30.02.57.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 30 Jan 2024 02:57:30 -0800 (PST)
Received-SPF: pass (google.com: domain of tongtiangen@huawei.com designates 45.249.212.190 as permitted sender) client-ip=45.249.212.190;
Received: from mail.maildlp.com (unknown [172.19.162.112])
	by szxga04-in.huawei.com (SkyGuard) with ESMTP id 4TPMXB10ljz29krw;
	Tue, 30 Jan 2024 18:55:38 +0800 (CST)
Received: from kwepemm600017.china.huawei.com (unknown [7.193.23.234])
	by mail.maildlp.com (Postfix) with ESMTPS id AB70B1404D7;
	Tue, 30 Jan 2024 18:57:27 +0800 (CST)
Received: from [10.174.179.234] (10.174.179.234) by
 kwepemm600017.china.huawei.com (7.193.23.234) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2507.35; Tue, 30 Jan 2024 18:57:25 +0800
Message-ID: <eb78caf9-ac03-1030-4e32-b614e73c0f62@huawei.com>
Date: Tue, 30 Jan 2024 18:57:24 +0800
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:91.0) Gecko/20100101
 Thunderbird/91.8.0
Subject: Re: [PATCH v10 2/6] arm64: add support for machine check error safe
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
 <20240129134652.4004931-3-tongtiangen@huawei.com>
 <ZbflpQV7aVry0qPz@FVFF77S0Q05N>
From: "'Tong Tiangen' via kasan-dev" <kasan-dev@googlegroups.com>
In-Reply-To: <ZbflpQV7aVry0qPz@FVFF77S0Q05N>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Transfer-Encoding: quoted-printable
X-Originating-IP: [10.174.179.234]
X-ClientProxiedBy: dggems703-chm.china.huawei.com (10.3.19.180) To
 kwepemm600017.china.huawei.com (7.193.23.234)
X-Original-Sender: tongtiangen@huawei.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of tongtiangen@huawei.com designates 45.249.212.190 as
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



=E5=9C=A8 2024/1/30 1:51, Mark Rutland =E5=86=99=E9=81=93:
> On Mon, Jan 29, 2024 at 09:46:48PM +0800, Tong Tiangen wrote:
>> For the arm64 kernel, when it processes hardware memory errors for
>> synchronize notifications(do_sea()), if the errors is consumed within th=
e
>> kernel, the current processing is panic. However, it is not optimal.
>>
>> Take uaccess for example, if the uaccess operation fails due to memory
>> error, only the user process will be affected. Killing the user process =
and
>> isolating the corrupt page is a better choice.
>>
>> This patch only enable machine error check framework and adds an excepti=
on
>> fixup before the kernel panic in do_sea().
>>
>> Signed-off-by: Tong Tiangen <tongtiangen@huawei.com>
>> ---
>>   arch/arm64/Kconfig               |  1 +
>>   arch/arm64/include/asm/extable.h |  1 +
>>   arch/arm64/mm/extable.c          | 16 ++++++++++++++++
>>   arch/arm64/mm/fault.c            | 29 ++++++++++++++++++++++++++++-
>>   4 files changed, 46 insertions(+), 1 deletion(-)
>>
>> diff --git a/arch/arm64/Kconfig b/arch/arm64/Kconfig
>> index aa7c1d435139..2cc34b5e7abb 100644
>> --- a/arch/arm64/Kconfig
>> +++ b/arch/arm64/Kconfig
>> @@ -20,6 +20,7 @@ config ARM64
>>   	select ARCH_ENABLE_SPLIT_PMD_PTLOCK if PGTABLE_LEVELS > 2
>>   	select ARCH_ENABLE_THP_MIGRATION if TRANSPARENT_HUGEPAGE
>>   	select ARCH_HAS_CACHE_LINE_SIZE
>> +	select ARCH_HAS_COPY_MC if ACPI_APEI_GHES
>>   	select ARCH_HAS_CURRENT_STACK_POINTER
>>   	select ARCH_HAS_DEBUG_VIRTUAL
>>   	select ARCH_HAS_DEBUG_VM_PGTABLE
>> diff --git a/arch/arm64/include/asm/extable.h b/arch/arm64/include/asm/e=
xtable.h
>> index 72b0e71cc3de..f80ebd0addfd 100644
>> --- a/arch/arm64/include/asm/extable.h
>> +++ b/arch/arm64/include/asm/extable.h
>> @@ -46,4 +46,5 @@ bool ex_handler_bpf(const struct exception_table_entry=
 *ex,
>>   #endif /* !CONFIG_BPF_JIT */
>>  =20
>>   bool fixup_exception(struct pt_regs *regs);
>> +bool fixup_exception_mc(struct pt_regs *regs);
>>   #endif
>> diff --git a/arch/arm64/mm/extable.c b/arch/arm64/mm/extable.c
>> index 228d681a8715..478e639f8680 100644
>> --- a/arch/arm64/mm/extable.c
>> +++ b/arch/arm64/mm/extable.c
>> @@ -76,3 +76,19 @@ bool fixup_exception(struct pt_regs *regs)
>>  =20
>>   	BUG();
>>   }
>> +
>> +bool fixup_exception_mc(struct pt_regs *regs)
>=20
> Can we please replace 'mc' with something like 'memory_error' ?
>=20
> There's no "machine check" on arm64, and 'mc' is opaque regardless.

OK, It's more appropriate to use "memory_error" on arm64.

>=20
>> +{
>> +	const struct exception_table_entry *ex;
>> +
>> +	ex =3D search_exception_tables(instruction_pointer(regs));
>> +	if (!ex)
>> +		return false;
>> +
>> +	/*
>> +	 * This is not complete, More Machine check safe extable type can
>> +	 * be processed here.
>> +	 */
>> +
>> +	return false;
>> +}
>=20
> As with my comment on the subsequenty patch, I'd much prefer that we hand=
le
> EX_TYPE_UACCESS_ERR_ZERO from the outset.

OK, In the next version, the two patches will be merged.

>=20
>=20
>=20
>> diff --git a/arch/arm64/mm/fault.c b/arch/arm64/mm/fault.c
>> index 55f6455a8284..312932dc100b 100644
>> --- a/arch/arm64/mm/fault.c
>> +++ b/arch/arm64/mm/fault.c
>> @@ -730,6 +730,31 @@ static int do_bad(unsigned long far, unsigned long =
esr, struct pt_regs *regs)
>>   	return 1; /* "fault" */
>>   }
>>  =20
>> +static bool arm64_do_kernel_sea(unsigned long addr, unsigned int esr,
>> +				     struct pt_regs *regs, int sig, int code)
>> +{
>> +	if (!IS_ENABLED(CONFIG_ARCH_HAS_COPY_MC))
>> +		return false;
>> +
>> +	if (user_mode(regs))
>> +		return false;
>=20
> This function is called "arm64_do_kernel_sea"; surely the caller should *=
never*
> call this for a SEA taken from user mode?

In do_sea(), the processing logic is as follows:
   do_sea()
   {
     [...]
     if (user_mode(regs) && apei_claim_sea(regs) =3D=3D 0) {
        return 0;
     }
     [...]
     //[1]
     if (!arm64_do_kernel_sea()) {
        arm64_notify_die();
     }
   }

[1] user_mode() is still possible to go here,If user_mode() goes here,
  it indicates that the impact caused by the memory error cannot be
  processed correctly by apei_claim_sea().


In this case, only arm64_notify_die() can be used, This also maintains
the original logic of user_mode()'s processing.

>=20
>> +
>> +	if (apei_claim_sea(regs) < 0)
>> +		return false;
>> +
>> +	if (!fixup_exception_mc(regs))
>> +		return false;
>> +
>> +	if (current->flags & PF_KTHREAD)
>> +		return true;
>=20
> I think this needs a comment; why do we allow kthreads to go on, yet kill=
 user
> threads? What about helper threads (e.g. for io_uring)?

If a memroy error occurs in the kernel thread, the problem is more
serious than that of the user thread. As a result, related kernel
functions, such as khugepaged, cannot run properly. kernel panic should
be a better choice at this time.

Therefore, the processing scope of this framework is limited to the user=20
  thread.

>=20
>> +
>> +	set_thread_esr(0, esr);
>=20
> Why do we set the ESR to 0?

The purpose is to reuse the logic of arm64_notify_die() and set the=20
following parameters before sending signals to users:
   current->thread.fault_address =3D 0;
   current->thread.fault_code =3D err;

I looked at the git log and found that the logic was added by this
commit:


9141300a5884 =EF=BC=88=E2=80=9Carm64: Provide read/write fault information =
in compat=20
signal handlers=E2=80=9D=EF=BC=89

According to the description of commit message, the purpose seems to be
for aarch32.

Many thanks.
Tong.


>=20
> Mark.
>=20
>> +	arm64_force_sig_fault(sig, code, addr,
>> +		"Uncorrected memory error on access to user memory\n");
>> +
>> +	return true;
>> +}
>> +
>>   static int do_sea(unsigned long far, unsigned long esr, struct pt_regs=
 *regs)
>>   {
>>   	const struct fault_info *inf;
>> @@ -755,7 +780,9 @@ static int do_sea(unsigned long far, unsigned long e=
sr, struct pt_regs *regs)
>>   		 */
>>   		siaddr  =3D untagged_addr(far);
>>   	}
>> -	arm64_notify_die(inf->name, regs, inf->sig, inf->code, siaddr, esr);
>> +
>> +	if (!arm64_do_kernel_sea(siaddr, esr, regs, inf->sig, inf->code))
>> +		arm64_notify_die(inf->name, regs, inf->sig, inf->code, siaddr, esr);
>>  =20
>>   	return 0;
>>   }
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
kasan-dev/eb78caf9-ac03-1030-4e32-b614e73c0f62%40huawei.com.
