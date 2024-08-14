Return-Path: <kasan-dev+bncBCMIFTP47IJBBMFU6G2QMGQEWYWAXFA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb40.google.com (mail-yb1-xb40.google.com [IPv6:2607:f8b0:4864:20::b40])
	by mail.lfdr.de (Postfix) with ESMTPS id 4F349951535
	for <lists+kasan-dev@lfdr.de>; Wed, 14 Aug 2024 09:18:10 +0200 (CEST)
Received: by mail-yb1-xb40.google.com with SMTP id 3f1490d57ef6-e035949cc4esf12026023276.1
        for <lists+kasan-dev@lfdr.de>; Wed, 14 Aug 2024 00:18:10 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1723619889; cv=pass;
        d=google.com; s=arc-20160816;
        b=krM8C8SoEC/K1ZiFeyDDtqYy9+OWadsmxYNdMXd7SlsqoMKKnhQAK/ViaW45vLH0jb
         D5gOEE5+ht69w0RFPeBSyKrIi0wj7VsicHALOQcuWqzBHToMvZW/rW/Jmi1JV8vIs1ze
         T7R7rsMFRhWU4g0pFdTlav0IhGVFvCDupIPlGlEbylk/2ONt7yjH9UrndqW0OXo+qb0S
         nTM35+8Yru96KLoofM3X1rUs2e8e/oAoOsR18iiCMXcKmmcdotvQ4iH9CXfVbxeOJORN
         FnM+xXnBiPAnMooPUdpq3dkxw8/EhMQU+r7cAm25fi6JIMp1d1uEFAjXWQFQTYV0vpra
         lBAA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :in-reply-to:from:content-language:references:cc:to:subject
         :user-agent:mime-version:date:message-id:dkim-signature;
        bh=vfqYSV3IcFxuftCpE6ZNfhkgDd7RJ/METaxZBENyaW4=;
        fh=PcQrPjMyceOB+LJ5a123AWbYNYPkKLMkxi+xpVGh8ww=;
        b=vTs5RcDbsJmqg7CP8Wt60GIJYIyRctj9V0UivjeGwiGHj05rov78HrNCm/Zq5hnxhM
         HYKGKR/IQ5W4JWvA9jhWAgwPZFy+Wx33hWsBOeUOhchotK+VmAf0r+4ZNKvGjCKahIZY
         dMwcV0VeAza7DN/ysliXIXMjpF00JTkuS1BRNltcPfZpedf2Y1EAB2f2C4wOJHvXzqRV
         KIPXhGD0ZMfW+q29iA8OSNxwrfw6ZkeZ7So4mJl9dCRbdr9zWOtTOA2GaBuarzcitxZf
         KJYbbU6YWCD5oVorYBGB1TeWQb2Zk5+9K7gwZjXpTRcKtuhmxI6dvXxoPpAPmuUe51rp
         kxYQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@sifive.com header.s=google header.b=nXECFcI7;
       spf=pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::730 as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=sifive.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1723619889; x=1724224689; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :from:to:cc:subject:date:message-id:reply-to;
        bh=vfqYSV3IcFxuftCpE6ZNfhkgDd7RJ/METaxZBENyaW4=;
        b=f81rmUi5atFF44+Eeqtv+8m9H5Gmn4R2qi02x7kv9ZY7dt/JgoYPR1QTheDhLELZx8
         cVMRUWUw5Fe6ejwxbcksoJ7ui/jYrYT/YM5Y3RjxKHLleBl9fe0k8dPGmGRVNX2u5ffx
         ZIUZttMm63pSSlx1jFjzMhdMdIHuQ5DCte+EIWeIwoTTVyo+yQvGUAsgjjwoH7PMK6vA
         ZupsWxD0CutLQqQKYBlt/48TX0QDipN2mvwiDjK9v/FaI5w9PR1FMs7zuAQ375MIcIkZ
         YBHHBc2QS9CwiRzOHz/5UyegvDkg0hw7Qx5am3YPt2p6RgyDPRdKJelTiIw48miT6tFj
         s3QA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1723619889; x=1724224689;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=vfqYSV3IcFxuftCpE6ZNfhkgDd7RJ/METaxZBENyaW4=;
        b=SLelL1iWJQHM5+yrGcG8b9In/VkGen1oj4Jijd7whBm9ZRkzWeZILp1T0weheRk2jZ
         LLqqGbuDpt4wTmYOvpdhWFPG4NdFV1wcz34odkgyuSXdkn/uz+2G5Fi7DV9tVggVfWOs
         4UK4UEREy2FP8woGg+lEku/O0GA83bpwWh5ipopEUpiCC/+epC8sttJq4/QKbW3yZT5T
         Nesh9osHl++DbuxCtwMREXB8KgvT+Pu3DEEqHTeUqENAmBjGKiC3+/+prpnUf+XF4NCX
         WdBDHQV8AtIzcSXeaZ4VhoUv60nmzbBZCSmTk+W2zymPEVeVNt+tepkG/s72zsMdCUQ+
         Y8vg==
X-Forwarded-Encrypted: i=2; AJvYcCWN76dvxMfzhOrS7ElgAL74c1IcZWzok97dwoHcrRPZU5skvsBjhkWKgXruy4bW/PgrHZVlxJbKBaAPXjmWSA75yBD7gzvGjg==
X-Gm-Message-State: AOJu0YwqpAkKUuyYOWL6AST7ch/AU3RO99nSBhaCRmNwedZhuDzbNxSj
	GOWmfF6Gc8XzY2a/MpcKNDVcrvJXM4gd3NVS11msbxWeSbc9tPpj
X-Google-Smtp-Source: AGHT+IHq4ml8P3yyx47ViXrl2x87pGejbIp+mEP321S3m9J74HcjzWH2Hwn6fcS2G3Ln4xMZuNMqFg==
X-Received: by 2002:a05:6902:2306:b0:e0e:4171:aee6 with SMTP id 3f1490d57ef6-e1155b85bffmr1852923276.42.1723619888944;
        Wed, 14 Aug 2024 00:18:08 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:5813:0:b0:447:ed03:aa4b with SMTP id d75a77b69052e-451d12f6c25ls100965201cf.2.-pod-prod-09-us;
 Wed, 14 Aug 2024 00:18:08 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUnQnbpW+5/AqJP2BmpfLnieIS3/cqo9j4qO3OxzekTJI0C3q07jvALkYD8p7i8wd1C7GvJO8JBV/PWDTMDtlKvyplo1lY7zHHtcw==
X-Received: by 2002:a05:6122:1d51:b0:4f6:ad2d:c867 with SMTP id 71dfb90a1353d-4fad221ac88mr2673420e0c.12.1723619888059;
        Wed, 14 Aug 2024 00:18:08 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1723619888; cv=none;
        d=google.com; s=arc-20160816;
        b=IjCu5yBvk/8BXSXdKfxRwlrGdrySO2Fnv7y2EnNz71pMDoEV9IXBkRRuptnR+7WfLY
         SFSMcWhLNpLtqb+Wy6ReHcqHT0nJRrLkFvLza9znxVdkFTB9+SnFzC75PMRCqOKSGHIG
         FEUGcRGILVyqpE1G8cgFTRBOJbgAl7mrDgCoSj/io4zIG3n2m+Jwed9zwKgMqkZMVY8q
         wJtgMPUrJi08zNarWWmgo7mNUx5p6tNxPEdlb77EwSxQkbtO4pGLg4o6MRgoAWyzUoV0
         PuVedzYKLHTMfF7Wy0Ydk8Y+fffBMvd2RGVWE3tC56EpCEN3qzDnhiTZpHRr9xIb4YEA
         wrFw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=RP1GFNJ9F5O2M+ikaXwAnDD9dagu3njbGJDnJ0WlSno=;
        fh=LOJJoR3Jk0I67xEw8QmCHv0TMYTivl7n6lbEE8v+CJ0=;
        b=UeJoFZcHqG2rkMVL8FphsTMODyzCxtDTGUCSqDA1oRLHmXXKxrNW3SDiTwdtlVDEUN
         oPHDxi+ue0qq6QhrTVXlSVTCEFt/icSnHKiXssMX7KD9QgKCU4lj5T8/cmNFcH+b6/vj
         vxGEODtX8ZrCd3hmOk3gqfFelJTAGxQ3AhwDmBg7wM1aJflTsLEsL3mc7eV7qTWS7J8y
         1ahY8syn4XeBuGVJtcqrEXow8dnijsNRPp/8Ukqtcw7oplvJJ7p3ZCihFfCjYO4cz4cc
         3AunqzsFzNqdfA6CnHQeKGAX2XqBDHA0+b7boJF7AMm/olyUYzoZOo6jhfWdk6S5CAZj
         o2fA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@sifive.com header.s=google header.b=nXECFcI7;
       spf=pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::730 as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=sifive.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qk1-x730.google.com (mail-qk1-x730.google.com. [2607:f8b0:4864:20::730])
        by gmr-mx.google.com with ESMTPS id 71dfb90a1353d-4f91f1193e8si329151e0c.0.2024.08.14.00.18.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 14 Aug 2024 00:18:08 -0700 (PDT)
Received-SPF: pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::730 as permitted sender) client-ip=2607:f8b0:4864:20::730;
Received: by mail-qk1-x730.google.com with SMTP id af79cd13be357-7a1d0dc869bso377673085a.2
        for <kasan-dev@googlegroups.com>; Wed, 14 Aug 2024 00:18:08 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXXfTAqKrvncgi3dKV+ttActiMzwTQBt2Ih4+M5CzER8mj5kj7cfLsYMtujr5NiQvauQUIZs3VnZDe1jOCmCHCl7DyK9WJOgq/C+g==
X-Received: by 2002:a05:622a:4e0d:b0:453:5eeb:4e79 with SMTP id d75a77b69052e-4535eeb4ff8mr10211141cf.6.1723619887463;
        Wed, 14 Aug 2024 00:18:07 -0700 (PDT)
Received: from [100.64.0.1] ([147.124.94.167])
        by smtp.gmail.com with ESMTPSA id d75a77b69052e-4531c26edb1sm38367841cf.76.2024.08.14.00.18.05
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 14 Aug 2024 00:18:07 -0700 (PDT)
Message-ID: <6859c9db-1d15-4d05-bb0e-1add2a594864@sifive.com>
Date: Wed, 14 Aug 2024 02:18:04 -0500
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v2 05/10] riscv: Add support for the tagged address ABI
To: Alexandre Ghiti <alex@ghiti.fr>, Palmer Dabbelt <palmer@dabbelt.com>,
 linux-riscv@lists.infradead.org
Cc: devicetree@vger.kernel.org, Catalin Marinas <catalin.marinas@arm.com>,
 linux-kernel@vger.kernel.org, Anup Patel <anup@brainfault.org>,
 Conor Dooley <conor@kernel.org>, kasan-dev@googlegroups.com,
 Atish Patra <atishp@atishpatra.org>, Evgenii Stepanov <eugenis@google.com>,
 Krzysztof Kozlowski <krzysztof.kozlowski+dt@linaro.org>,
 Rob Herring <robh+dt@kernel.org>,
 "Kirill A . Shutemov" <kirill.shutemov@linux.intel.com>
References: <20240625210933.1620802-1-samuel.holland@sifive.com>
 <20240625210933.1620802-6-samuel.holland@sifive.com>
 <1faba7e8-903d-40f5-8285-1b309d7b9410@ghiti.fr>
Content-Language: en-US
From: "'Samuel Holland' via kasan-dev" <kasan-dev@googlegroups.com>
In-Reply-To: <1faba7e8-903d-40f5-8285-1b309d7b9410@ghiti.fr>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: samuel.holland@sifive.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@sifive.com header.s=google header.b=nXECFcI7;       spf=pass
 (google.com: domain of samuel.holland@sifive.com designates
 2607:f8b0:4864:20::730 as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=sifive.com;
       dara=pass header.i=@googlegroups.com
X-Original-From: Samuel Holland <samuel.holland@sifive.com>
Reply-To: Samuel Holland <samuel.holland@sifive.com>
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

Hi Alex,

On 2024-08-13 6:35 AM, Alexandre Ghiti wrote:
> Hi Samuel,
>=20
> On 25/06/2024 23:09, Samuel Holland wrote:
>> When pointer masking is enabled for userspace, the kernel can accept
>> tagged pointers as arguments to some system calls. Allow this by
>> untagging the pointers in access_ok() and the uaccess routines. The
>> uaccess routines must peform untagging in software because U-mode and
>> S-mode have entirely separate pointer masking configurations. In fact,
>> hardware may not even implement pointer masking for S-mode.
>=20
>=20
> Would it make sense to have a fast path when S-mode and U-mode PMLENs are=
 equal?

I don't think so? Different userspace processes can have different PMLEN va=
lues,
including PMLEN=3D=3D0, so it wouldn't be possible to patch out the untaggi=
ng
operation based on PMLEN. (It's already skipped with a static branch if the
hardware doesn't support pointer masking). The untagging sequence is only 4
instructions (3 with pmlen in struct thread_info):

 746:   41023603                ld      a2,1040(tp) current->mm
 74a:   46064603                lbu     a2,1120(a2) current->mm->context.pm=
len
 74e:   00c51533                sll     a0,a0,a2
 752:   40c55533                sra     a0,a0,a2

so I'm not sure how to make this faster.

>> Since the number of tag bits is variable, untagged_addr_remote() needs
>> to know what PMLEN to use for the remote mm. Therefore, the pointer
>> masking mode must be the same for all threads sharing an mm. Enforce
>> this with a lock flag in the mm context, as x86 does for LAM.The flag ge=
ts
>> reset in init_new_context() during fork(), as the new mm is no
>> longer multithreaded.
>>
>> Unlike x86, untagged_addr() gets pmlen from struct thread_info instead
>> of a percpu variable, as this both avoids context switch overhead and
>> loads the value more efficiently.
>>
>> Signed-off-by: Samuel Holland <samuel.holland@sifive.com>
>> ---
>>
>> Changes in v2:
>> =C2=A0 - Implement untagged_addr_remote()
>> =C2=A0 - Restrict PMLEN changes once a process is multithreaded
>>
>> =C2=A0 arch/riscv/include/asm/mmu.h=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0 |=C2=A0 7 +++
>> =C2=A0 arch/riscv/include/asm/mmu_context.h |=C2=A0 6 +++
>> =C2=A0 arch/riscv/include/asm/thread_info.h |=C2=A0 3 ++
>> =C2=A0 arch/riscv/include/asm/uaccess.h=C2=A0=C2=A0=C2=A0=C2=A0 | 58 +++=
++++++++++++++++++--
>> =C2=A0 arch/riscv/kernel/process.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0 | 69 +++++++++++++++++++++++++++-
>> =C2=A0 5 files changed, 136 insertions(+), 7 deletions(-)
>>
>> diff --git a/arch/riscv/include/asm/mmu.h b/arch/riscv/include/asm/mmu.h
>> index 947fd60f9051..361a9623f8c8 100644
>> --- a/arch/riscv/include/asm/mmu.h
>> +++ b/arch/riscv/include/asm/mmu.h
>> @@ -26,8 +26,15 @@ typedef struct {
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 unsigned long exec_fdpic_loadmap;
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 unsigned long interp_fdpic_loadmap;
>> =C2=A0 #endif
>> +#ifdef CONFIG_RISCV_ISA_POINTER_MASKING
>> +=C2=A0=C2=A0=C2=A0 unsigned long flags;
>> +=C2=A0=C2=A0=C2=A0 u8 pmlen;
>> +#endif
>> =C2=A0 } mm_context_t;
>> =C2=A0 +/* Lock the pointer masking mode because this mm is multithreade=
d */
>> +#define MM_CONTEXT_LOCK_PMLEN=C2=A0=C2=A0=C2=A0 0
>> +
>> =C2=A0 #define cntx2asid(cntx)=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
 ((cntx) & SATP_ASID_MASK)
>> =C2=A0 #define cntx2version(cntx)=C2=A0=C2=A0=C2=A0 ((cntx) & ~SATP_ASID=
_MASK)
>> =C2=A0 diff --git a/arch/riscv/include/asm/mmu_context.h
>> b/arch/riscv/include/asm/mmu_context.h
>> index 7030837adc1a..62a9f76cf257 100644
>> --- a/arch/riscv/include/asm/mmu_context.h
>> +++ b/arch/riscv/include/asm/mmu_context.h
>> @@ -20,6 +20,9 @@ void switch_mm(struct mm_struct *prev, struct mm_struc=
t *next,
>> =C2=A0 static inline void activate_mm(struct mm_struct *prev,
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 struct mm_struct *next)
>> =C2=A0 {
>> +#ifdef CONFIG_RISCV_ISA_POINTER_MASKING
>> +=C2=A0=C2=A0=C2=A0 next->context.pmlen =3D 0;
>> +#endif
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 switch_mm(prev, next, NULL);
>> =C2=A0 }
>> =C2=A0 @@ -29,6 +32,9 @@ static inline int init_new_context(struct task_=
struct *tsk,
>> =C2=A0 {
>> =C2=A0 #ifdef CONFIG_MMU
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 atomic_long_set(&mm->context.id, 0);
>> +#endif
>> +#ifdef CONFIG_RISCV_ISA_POINTER_MASKING
>> +=C2=A0=C2=A0=C2=A0 clear_bit(MM_CONTEXT_LOCK_PMLEN, &mm->context.flags)=
;
>> =C2=A0 #endif
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 return 0;
>> =C2=A0 }
>> diff --git a/arch/riscv/include/asm/thread_info.h
>> b/arch/riscv/include/asm/thread_info.h
>> index 5d473343634b..cd355f8a550f 100644
>> --- a/arch/riscv/include/asm/thread_info.h
>> +++ b/arch/riscv/include/asm/thread_info.h
>> @@ -60,6 +60,9 @@ struct thread_info {
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 void=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 *scs_base;
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 void=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 *scs_sp;
>> =C2=A0 #endif
>> +#ifdef CONFIG_RISCV_ISA_POINTER_MASKING
>> +=C2=A0=C2=A0=C2=A0 u8=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0 pmlen;
>> +#endif
>> =C2=A0 };
>> =C2=A0 =C2=A0 #ifdef CONFIG_SHADOW_CALL_STACK
>> diff --git a/arch/riscv/include/asm/uaccess.h b/arch/riscv/include/asm/u=
access.h
>> index 72ec1d9bd3f3..153495997bc1 100644
>> --- a/arch/riscv/include/asm/uaccess.h
>> +++ b/arch/riscv/include/asm/uaccess.h
>> @@ -9,8 +9,56 @@
>> =C2=A0 #define _ASM_RISCV_UACCESS_H
>> =C2=A0 =C2=A0 #include <asm/asm-extable.h>
>> +#include <asm/cpufeature.h>
>> =C2=A0 #include <asm/pgtable.h>=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0 /* for TASK_SIZE */
>> =C2=A0 +#ifdef CONFIG_RISCV_ISA_POINTER_MASKING
>> +static inline unsigned long __untagged_addr(unsigned long addr)
>> +{
>> +=C2=A0=C2=A0=C2=A0 if (riscv_has_extension_unlikely(RISCV_ISA_EXT_SUPM)=
) {
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 u8 pmlen =3D current->thread=
_info.pmlen;
>=20
>=20
> Why don't we use mm->pmlen? I don't see the need to introduce this variab=
le that
> mirrors what is in mm already but I may be missing something.

Only that caching the value in struct thread_info saves an instruction/cach=
e
line load from the pointer chasing. current->mm is likely to be hot anyway,=
 so
it probably doesn't make too much difference. I will simplify this in v3.

Regards,
Samuel

>> +
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 /* Virtual addresses are sig=
n-extended; physical addresses are
>> zero-extended. */
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 if (IS_ENABLED(CONFIG_MMU))
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 retu=
rn (long)(addr << pmlen) >> pmlen;
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 else
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 retu=
rn (addr << pmlen) >> pmlen;
>> +=C2=A0=C2=A0=C2=A0 }
>> +
>> +=C2=A0=C2=A0=C2=A0 return addr;
>> +}
>> +
>> +#define untagged_addr(addr) ({=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0 \
>> +=C2=A0=C2=A0=C2=A0 unsigned long __addr =3D (__force unsigned long)(add=
r);=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 \
>> +=C2=A0=C2=A0=C2=A0 (__force __typeof__(addr))__untagged_addr(__addr);=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 \
>> +})
>> +
>> +static inline unsigned long __untagged_addr_remote(struct mm_struct *mm=
,
>> unsigned long addr)
>> +{
>> +=C2=A0=C2=A0=C2=A0 if (riscv_has_extension_unlikely(RISCV_ISA_EXT_SUPM)=
) {
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 u8 pmlen =3D mm->context.pml=
en;
>> +
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 /* Virtual addresses are sig=
n-extended; physical addresses are
>> zero-extended. */
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 if (IS_ENABLED(CONFIG_MMU))
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 retu=
rn (long)(addr << pmlen) >> pmlen;
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 else
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 retu=
rn (addr << pmlen) >> pmlen;
>> +=C2=A0=C2=A0=C2=A0 }
>> +
>> +=C2=A0=C2=A0=C2=A0 return addr;
>> +}
>> +
>> +#define untagged_addr_remote(mm, addr) ({=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 \
>> +=C2=A0=C2=A0=C2=A0 unsigned long __addr =3D (__force unsigned long)(add=
r);=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 \
>> +=C2=A0=C2=A0=C2=A0 mmap_assert_locked(mm);=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 \
>> +=C2=A0=C2=A0=C2=A0 (__force __typeof__(addr))__untagged_addr_remote(mm,=
 __addr);=C2=A0=C2=A0=C2=A0 \
>> +})
>> +
>> +#define access_ok(addr, size) likely(__access_ok(untagged_addr(addr), s=
ize))
>> +#else
>> +#define untagged_addr(addr) (addr)
>> +#endif
>> +
>> =C2=A0 /*
>> =C2=A0=C2=A0 * User space memory access functions
>> =C2=A0=C2=A0 */
>> @@ -130,7 +178,7 @@ do {=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 \
>> =C2=A0=C2=A0 */
>> =C2=A0 #define __get_user(x, ptr)=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
 \
>> =C2=A0 ({=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 \
>> -=C2=A0=C2=A0=C2=A0 const __typeof__(*(ptr)) __user *__gu_ptr =3D (ptr);=
=C2=A0=C2=A0=C2=A0 \
>> +=C2=A0=C2=A0=C2=A0 const __typeof__(*(ptr)) __user *__gu_ptr =3D untagg=
ed_addr(ptr); \
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 long __gu_err =3D 0;=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0 \
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 \
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 __chk_user_ptr(__gu_ptr);=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
 \
>> @@ -246,7 +294,7 @@ do {=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 \
>> =C2=A0=C2=A0 */
>> =C2=A0 #define __put_user(x, ptr)=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
 \
>> =C2=A0 ({=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 \
>> -=C2=A0=C2=A0=C2=A0 __typeof__(*(ptr)) __user *__gu_ptr =3D (ptr);=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 \
>> +=C2=A0=C2=A0=C2=A0 __typeof__(*(ptr)) __user *__gu_ptr =3D untagged_add=
r(ptr); \
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 __typeof__(*__gu_ptr) __val =3D (x);=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 \
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 long __pu_err =3D 0;=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0 \
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 \
>> @@ -293,13 +341,13 @@ unsigned long __must_check __asm_copy_from_user(vo=
id *to,
>> =C2=A0 static inline unsigned long
>> =C2=A0 raw_copy_from_user(void *to, const void __user *from, unsigned lo=
ng n)
>> =C2=A0 {
>> -=C2=A0=C2=A0=C2=A0 return __asm_copy_from_user(to, from, n);
>> +=C2=A0=C2=A0=C2=A0 return __asm_copy_from_user(to, untagged_addr(from),=
 n);
>> =C2=A0 }
>> =C2=A0 =C2=A0 static inline unsigned long
>> =C2=A0 raw_copy_to_user(void __user *to, const void *from, unsigned long=
 n)
>> =C2=A0 {
>> -=C2=A0=C2=A0=C2=A0 return __asm_copy_to_user(to, from, n);
>> +=C2=A0=C2=A0=C2=A0 return __asm_copy_to_user(untagged_addr(to), from, n=
);
>> =C2=A0 }
>> =C2=A0 =C2=A0 extern long strncpy_from_user(char *dest, const char __use=
r *src, long
>> count);
>> @@ -314,7 +362,7 @@ unsigned long __must_check clear_user(void __user *t=
o,
>> unsigned long n)
>> =C2=A0 {
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 might_fault();
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 return access_ok(to, n) ?
>> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 __clear_user(to, n) : n;
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 __clear_user(untagged_addr(t=
o), n) : n;
>> =C2=A0 }
>> =C2=A0 =C2=A0 #define __get_kernel_nofault(dst, src, type, err_label)=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 \
>> diff --git a/arch/riscv/kernel/process.c b/arch/riscv/kernel/process.c
>> index dec5ccc44697..7bd445dade92 100644
>> --- a/arch/riscv/kernel/process.c
>> +++ b/arch/riscv/kernel/process.c
>> @@ -173,8 +173,10 @@ void flush_thread(void)
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 clear_tsk_thread_flag(current, TIF_RISCV_=
V_DEFER_RESTORE);
>> =C2=A0 #endif
>> =C2=A0 #ifdef CONFIG_RISCV_ISA_POINTER_MASKING
>> -=C2=A0=C2=A0=C2=A0 if (riscv_has_extension_unlikely(RISCV_ISA_EXT_SUPM)=
)
>> +=C2=A0=C2=A0=C2=A0 if (riscv_has_extension_unlikely(RISCV_ISA_EXT_SUPM)=
) {
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 envcfg_update_bit=
s(current, ENVCFG_PMM, ENVCFG_PMM_PMLEN_0);
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 current->thread_info.pmlen =
=3D 0;
>> +=C2=A0=C2=A0=C2=A0 }
>> =C2=A0 #endif
>> =C2=A0 }
>> =C2=A0 @@ -204,6 +206,12 @@ int copy_thread(struct task_struct *p, const=
 struct
>> kernel_clone_args *args)
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 unsigned long tls =3D args->tls;
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 struct pt_regs *childregs =3D task_pt_reg=
s(p);
>> =C2=A0 +#ifdef CONFIG_RISCV_ISA_POINTER_MASKING
>> +=C2=A0=C2=A0=C2=A0 /* Ensure all threads in this mm have the same point=
er masking mode. */
>> +=C2=A0=C2=A0=C2=A0 if (p->mm && (clone_flags & CLONE_VM))
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 set_bit(MM_CONTEXT_LOCK_PMLE=
N, &p->mm->context.flags);
>> +#endif
>> +
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 memset(&p->thread.s, 0, sizeof(p->thread.=
s));
>> =C2=A0 =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 /* p->thread holds context to be r=
estored by __switch_to() */
>> @@ -243,10 +251,16 @@ void __init arch_task_cache_init(void)
>> =C2=A0 static bool have_user_pmlen_7;
>> =C2=A0 static bool have_user_pmlen_16;
>> =C2=A0 +/*
>> + * Control the relaxed ABI allowing tagged user addresses into the kern=
el.
>> + */
>> +static unsigned int tagged_addr_disabled;
>> +
>> =C2=A0 long set_tagged_addr_ctrl(struct task_struct *task, unsigned long=
 arg)
>> =C2=A0 {
>> -=C2=A0=C2=A0=C2=A0 unsigned long valid_mask =3D PR_PMLEN_MASK;
>> +=C2=A0=C2=A0=C2=A0 unsigned long valid_mask =3D PR_PMLEN_MASK | PR_TAGG=
ED_ADDR_ENABLE;
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 struct thread_info *ti =3D task_thread_in=
fo(task);
>> +=C2=A0=C2=A0=C2=A0 struct mm_struct *mm =3D task->mm;
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 unsigned long pmm;
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 u8 pmlen;
>> =C2=A0 @@ -277,6 +291,14 @@ long set_tagged_addr_ctrl(struct task_struct=
 *task,
>> unsigned long arg)
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0 return -EINVAL;
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 }
>> =C2=A0 +=C2=A0=C2=A0=C2=A0 /*
>> +=C2=A0=C2=A0=C2=A0=C2=A0 * Do not allow the enabling of the tagged addr=
ess ABI if globally
>> +=C2=A0=C2=A0=C2=A0=C2=A0 * disabled via sysctl abi.tagged_addr_disabled=
, if pointer masking
>> +=C2=A0=C2=A0=C2=A0=C2=A0 * is disabled for userspace.
>> +=C2=A0=C2=A0=C2=A0=C2=A0 */
>> +=C2=A0=C2=A0=C2=A0 if (arg & PR_TAGGED_ADDR_ENABLE && (tagged_addr_disa=
bled || !pmlen))
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 return -EINVAL;
>> +
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 if (pmlen =3D=3D 7)
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 pmm =3D ENVCFG_PM=
M_PMLEN_7;
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 else if (pmlen =3D=3D 16)
>> @@ -284,7 +306,22 @@ long set_tagged_addr_ctrl(struct task_struct *task,
>> unsigned long arg)
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 else
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 pmm =3D ENVCFG_PM=
M_PMLEN_0;
>> =C2=A0 +=C2=A0=C2=A0=C2=A0 if (!(arg & PR_TAGGED_ADDR_ENABLE))
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 pmlen =3D 0;
>> +
>> +=C2=A0=C2=A0=C2=A0 if (mmap_write_lock_killable(mm))
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 return -EINTR;
>> +
>> +=C2=A0=C2=A0=C2=A0 if (test_bit(MM_CONTEXT_LOCK_PMLEN, &mm->context.fla=
gs) &&
>> mm->context.pmlen !=3D pmlen) {
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 mmap_write_unlock(mm);
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 return -EBUSY;
>> +=C2=A0=C2=A0=C2=A0 }
>> +
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 envcfg_update_bits(task, ENVCFG_PMM, pmm)=
;
>> +=C2=A0=C2=A0=C2=A0 task->mm->context.pmlen =3D pmlen;
>> +=C2=A0=C2=A0=C2=A0 task->thread_info.pmlen =3D pmlen;
>> +
>> +=C2=A0=C2=A0=C2=A0 mmap_write_unlock(mm);
>> =C2=A0 =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 return 0;
>> =C2=A0 }
>> @@ -297,6 +334,13 @@ long get_tagged_addr_ctrl(struct task_struct *task)
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 if (is_compat_thread(ti))
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 return -EINVAL;
>> =C2=A0 +=C2=A0=C2=A0=C2=A0 if (task->thread_info.pmlen)
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 ret =3D PR_TAGGED_ADDR_ENABL=
E;
>> +
>> +=C2=A0=C2=A0=C2=A0 /*
>> +=C2=A0=C2=A0=C2=A0=C2=A0 * The task's pmlen is only set if the tagged a=
ddress ABI is enabled,
>> +=C2=A0=C2=A0=C2=A0=C2=A0 * so the effective PMLEN must be extracted fro=
m envcfg.PMM.
>> +=C2=A0=C2=A0=C2=A0=C2=A0 */
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 switch (task->thread.envcfg & ENVCFG_PMM)=
 {
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 case ENVCFG_PMM_PMLEN_7:
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 ret |=3D FIELD_PR=
EP(PR_PMLEN_MASK, 7);
>> @@ -315,6 +359,24 @@ static bool try_to_set_pmm(unsigned long value)
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 return (csr_read_clear(CSR_ENVCFG, ENVCFG=
_PMM) & ENVCFG_PMM) =3D=3D value;
>> =C2=A0 }
>> =C2=A0 +/*
>> + * Global sysctl to disable the tagged user addresses support. This con=
trol
>> + * only prevents the tagged address ABI enabling via prctl() and does n=
ot
>> + * disable it for tasks that already opted in to the relaxed ABI.
>> + */
>> +
>> +static struct ctl_table tagged_addr_sysctl_table[] =3D {
>> +=C2=A0=C2=A0=C2=A0 {
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 .procname=C2=A0=C2=A0=C2=A0 =
=3D "tagged_addr_disabled",
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 .mode=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0 =3D 0644,
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 .data=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0 =3D &tagged_addr_disabled,
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 .maxlen=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0 =3D sizeof(int),
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 .proc_handler=C2=A0=C2=A0=C2=
=A0 =3D proc_dointvec_minmax,
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 .extra1=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0 =3D SYSCTL_ZERO,
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 .extra2=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0 =3D SYSCTL_ONE,
>> +=C2=A0=C2=A0=C2=A0 },
>> +};
>> +
>> =C2=A0 static int __init tagged_addr_init(void)
>> =C2=A0 {
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 if (!riscv_has_extension_unlikely(RISCV_I=
SA_EXT_SUPM))
>> @@ -328,6 +390,9 @@ static int __init tagged_addr_init(void)
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 have_user_pmlen_7 =3D try_to_set_pmm(ENVC=
FG_PMM_PMLEN_7);
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 have_user_pmlen_16 =3D try_to_set_pmm(ENV=
CFG_PMM_PMLEN_16);
>> =C2=A0 +=C2=A0=C2=A0=C2=A0 if (!register_sysctl("abi", tagged_addr_sysct=
l_table))
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 return -EINVAL;
>> +
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 return 0;
>> =C2=A0 }
>> =C2=A0 core_initcall(tagged_addr_init);

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/6859c9db-1d15-4d05-bb0e-1add2a594864%40sifive.com.
