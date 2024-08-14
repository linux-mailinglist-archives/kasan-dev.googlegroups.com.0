Return-Path: <kasan-dev+bncBC7PZX4C3UKBBBUL6S2QMGQEOY373IQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33a.google.com (mail-wm1-x33a.google.com [IPv6:2a00:1450:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id 348F49522A9
	for <lists+kasan-dev@lfdr.de>; Wed, 14 Aug 2024 21:29:12 +0200 (CEST)
Received: by mail-wm1-x33a.google.com with SMTP id 5b1f17b1804b1-4281ca9f4dbsf582305e9.0
        for <lists+kasan-dev@lfdr.de>; Wed, 14 Aug 2024 12:29:12 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1723663752; cv=pass;
        d=google.com; s=arc-20160816;
        b=ydzbs3A++mBGzg5iTw529q86c6BIgEqj+D0oDTXF9Xd03YCHaH4iNGgPUwY/qeQV9R
         YIUXNjo3ZEbb5j33soaHmoG/p2JhXewS2pojmyJgIvR8nlOR1Vs5A43DMg3bMaxgQ1d1
         AfosisEImVhRNPB09IyGwIgiTko3AhtVXz+ZYAd3+qQb01VBAbe7xI3iwJY9wsebkR4T
         ph06DSZ/Jsk568a26GXgO0ohLJGDFG/suYW9Jxm0sOXFoE+Dgi/vDekON2/pqu4Zxxjl
         Y6Tg6qR4BGjxG+KQ9WddGVhe/YpZIDtFOBgNCTWTXAvpYxccm3G4UwiCWCul1WsXAM+4
         50DA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :in-reply-to:from:references:cc:to:content-language:subject
         :user-agent:mime-version:date:message-id:sender:dkim-signature;
        bh=LNZNby16vvmxtArdGQ07zk57A1xNhLvjNwhJTwrQasc=;
        fh=B1TKPnj2sGUkRIxZjAEnRrM5hVCIekR2e/u+4z8LYi0=;
        b=RgsTW40QeIgkAEYAvFtFzv+9qTsytZkxihodCAG+ptmZjAhesUChBvH8YXkpb1iSbn
         b2Mgs7fbOuYWw/h6ezm5+TiDAOmBcojBJJcCX5jjXlKN3mym4Ej7OdCfeEA9phX5mi8p
         FRTjJ3eBlxLx3AEU+6PtuQwkLlPZvKKLZfvExB0+wbiF2cw3fg33iGujilF2uhe4ldA/
         RvaVIL81972gLT/zYZA36uDcI8tDLGwF6Q5MHOMN9g2WC5fTFrR8gp7MZAM/cs0Osvwh
         Cfx6BIPFPDFQwSJfad1HnvID/ZUpiGw17WFZHXLwr16QEqLo7efupS8IqZnD/K3hTCOR
         wR+A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of alex@ghiti.fr designates 217.70.183.198 as permitted sender) smtp.mailfrom=alex@ghiti.fr
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1723663752; x=1724268552; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:in-reply-to:from
         :references:cc:to:content-language:subject:user-agent:mime-version
         :date:message-id:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=LNZNby16vvmxtArdGQ07zk57A1xNhLvjNwhJTwrQasc=;
        b=e0IC1uVjkJAKx5/8qxb2VWqEdLpSh1Xvvu9+JttgOdP4a81AmZJXGXBj1IC2jerLYR
         Ir6xfiAutcx6E3mDQLZqxQuVsc3wOkyXS6DMhikWU/nS64yGUA5W3lQ/oHxbEPF5ei18
         Hq16YpMAcOoF7qoR6G5vlFI8Kz17zqbx4NOdwLp4kOo3CQeSzOhZ3J/Y/ZYVNFC0mW0Z
         c6N28HK0TTS9plTEfuDJjaaT/0k51sUPl2ResGiSArHWV6hvkYFvVv6BuU9xGlItjMT0
         3RvE3t41iaShzKbDayDNbS9mABKvdvQN7MQBeSm5rFgNxmRNQupP6Sje1tHb8UeHbbxQ
         dOWg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1723663752; x=1724268552;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=LNZNby16vvmxtArdGQ07zk57A1xNhLvjNwhJTwrQasc=;
        b=Ok2rf91XjBs7pNvIlY1Vzm43YoGbdSLgF5Ngx82p655hVyLjgCBZI3hU3HWPAYtEDj
         4g932p/8epzcc93EmVPNNk6eZrIVx5mFypU8kDpoGrgF2fg6k9jMA5mOUOf6EZJ3Hhlq
         rJWAL7IOya/kOJ+UmvU1DW3UXZbTddi0Uzf7of9hL5tg98DsIf7osI4hJfDcWVk/5y6j
         ZST8GwsR5XrmF2XcxzZ69SRI+lpFR4aVDtXhraJOiQ9v4oIF1enrnsZltAOZWy/we6fP
         MEodkNuVwCT7WkIf5c91or2V8Q4zoO7CSPLqovyZAx77PMLvvQXRtLj8eNjOXOyF8Huj
         L8Eg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCV1QdSPxHOKqCoIIZnvhH5ybvP+TDKuJ5ANhJj7zKkjcvk2u/rBGkn8tuQTf5fy0pESdj9s6Je4nEfvvJ7vD5dQA1vHiuR0Bw==
X-Gm-Message-State: AOJu0YzeNV1po+koSCJybSK5QDaNg6fJncrv/JYGmo4BGwVpqu8BZbIe
	HeKfo+sLiTkioo5uDpqwL4joYMcstqfvDgqALlfBLmzw5zeNsqsZ
X-Google-Smtp-Source: AGHT+IHli7IFxwsbhy7T/6LRBQ2Xc03Yzk7Ms/a4qHVUhnRcQtyYNZ1VR3tcGwFr3vfgfu6qah6q9Q==
X-Received: by 2002:a05:600c:5254:b0:428:18d9:9963 with SMTP id 5b1f17b1804b1-429dd23d838mr26483665e9.22.1723663751081;
        Wed, 14 Aug 2024 12:29:11 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:5128:b0:426:73d7:f1f5 with SMTP id
 5b1f17b1804b1-429e23dbe9dls647075e9.1.-pod-prod-07-eu; Wed, 14 Aug 2024
 12:29:09 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXhDpUUGtbwY+Mv0dbkwH8UXaDS+cc95XJgTL++tNLVq5/aPgzxH/5pnZWnyF+MZyJCI1H9/IvVxnlnDA8j62w1eE3Ouvial4RpMA==
X-Received: by 2002:a05:600c:3491:b0:426:6e9a:7a1c with SMTP id 5b1f17b1804b1-429dd25f5eamr24906725e9.25.1723663748984;
        Wed, 14 Aug 2024 12:29:08 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1723663748; cv=none;
        d=google.com; s=arc-20160816;
        b=wOZf797ON2EXRa6YeXSZeM0mtf3JFhWrSNeXt1AyCXZn+bdMy9zhZYflhTAny9xP9q
         iRQNsiYHQ06WlhjNjSC3JT7pO/DHEUkzp+C5+G7WMHqLdzx7zaWM/bUfBZNmWSzufc22
         prXXJS6A5piYW97utHcTeiwOKtPAJnyYLD3l3PEqpfcF6tpc5UGLsB8yJn8mbC0zAwIh
         YNFhQcpzcY+/wl6GZkft2huLHImO1b3+Fv+FmBiCB6bDHPUnwtKLv4GtPWgWHs6Rcgdl
         CpxISxJkcA/G0rIWNvmbDi+248914LtQbMmHInJ+LmVxQ+l+dHbdKJlzICFsV8o83RB9
         QoZw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id;
        bh=t89M9C78U/pqtw65i1+Gs0ywZDznnjrKvAAkzG21N74=;
        fh=PlrXXiljIqn5FFku5uz3XLLiXAFcGGd/MpVQIupLlEU=;
        b=pTUb13aDojp3SjaZw6Uqj7Cur9QmcfQNe6WoN0Fz/2F4ZTcyJbekw5F8sL/gXlNkK4
         JxfoX54ziz443qrY91KWEuLxw1EXsxasIKvMJBnt7gt3iLear5+8LkjH556spRRVqh0n
         d5eN0tbKHd37vx1Y3NipufRGA2kjcm1zD9T+Ly+81cKK1HGCgaYN3CLS5VYXpwv0dUZv
         UPloz2G9MzlZDgipfUiWsRbhxF0UHh0SkxOIT0rKc5ntM1wWGLoCfEIfnAdVo/9kGS5w
         b0SPZQM4vVLvaSI6FfUDhxJ8IK8hYLIKo1bm7IAJoiZJ23EsnLMW10M1MlI+ZppSUR+n
         TF3Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of alex@ghiti.fr designates 217.70.183.198 as permitted sender) smtp.mailfrom=alex@ghiti.fr
Received: from relay6-d.mail.gandi.net (relay6-d.mail.gandi.net. [217.70.183.198])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-429ded32a44si474435e9.1.2024.08.14.12.29.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Wed, 14 Aug 2024 12:29:08 -0700 (PDT)
Received-SPF: pass (google.com: domain of alex@ghiti.fr designates 217.70.183.198 as permitted sender) client-ip=217.70.183.198;
Received: by mail.gandi.net (Postfix) with ESMTPSA id 5F76CC0005;
	Wed, 14 Aug 2024 19:29:06 +0000 (UTC)
Message-ID: <05eb614b-f4fc-4154-96b3-a30e5adc789f@ghiti.fr>
Date: Wed, 14 Aug 2024 21:29:05 +0200
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v3 05/10] riscv: Add support for the tagged address ABI
Content-Language: en-US
To: Samuel Holland <samuel.holland@sifive.com>,
 Palmer Dabbelt <palmer@dabbelt.com>, linux-riscv@lists.infradead.org
Cc: devicetree@vger.kernel.org, Catalin Marinas <catalin.marinas@arm.com>,
 linux-kernel@vger.kernel.org, Anup Patel <anup@brainfault.org>,
 Conor Dooley <conor@kernel.org>, kasan-dev@googlegroups.com,
 Atish Patra <atishp@atishpatra.org>, Evgenii Stepanov <eugenis@google.com>,
 Krzysztof Kozlowski <krzysztof.kozlowski+dt@linaro.org>,
 Rob Herring <robh+dt@kernel.org>,
 "Kirill A . Shutemov" <kirill.shutemov@linux.intel.com>
References: <20240814081437.956855-1-samuel.holland@sifive.com>
 <20240814081437.956855-6-samuel.holland@sifive.com>
 <35e8386f-854a-48d5-8c03-7a53f8ca3292@ghiti.fr>
 <044b77fe-fd17-4c01-934a-80d63822fb3f@sifive.com>
From: Alexandre Ghiti <alex@ghiti.fr>
In-Reply-To: <044b77fe-fd17-4c01-934a-80d63822fb3f@sifive.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Transfer-Encoding: quoted-printable
X-GND-Sasl: alex@ghiti.fr
X-Original-Sender: alex@ghiti.fr
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of alex@ghiti.fr designates 217.70.183.198 as permitted
 sender) smtp.mailfrom=alex@ghiti.fr
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


On 14/08/2024 18:14, Samuel Holland wrote:
> Hi Alex,
>
> On 2024-08-14 10:10 AM, Alexandre Ghiti wrote:
>> On 14/08/2024 10:13, Samuel Holland wrote:
>>> When pointer masking is enabled for userspace, the kernel can accept
>>> tagged pointers as arguments to some system calls. Allow this by
>>> untagging the pointers in access_ok() and the uaccess routines. The
>>> uaccess routines must peform untagging in software because U-mode and
>>> S-mode have entirely separate pointer masking configurations. In fact,
>>> hardware may not even implement pointer masking for S-mode.
>>>
>>> Since the number of tag bits is variable, untagged_addr_remote() needs
>>> to know what PMLEN to use for the remote mm. Therefore, the pointer
>>> masking mode must be the same for all threads sharing an mm. Enforce
>>> this with a lock flag in the mm context, as x86 does for LAM. The flag
>>> gets reset in init_new_context() during fork(), as the new mm is no
>>> longer multithreaded.
>>>
>>> Signed-off-by: Samuel Holland <samuel.holland@sifive.com>
>>> ---
>>>
>>> Changes in v3:
>>>  =C2=A0 - Use IS_ENABLED instead of #ifdef when possible
>>>  =C2=A0 - Implement mm_untag_mask()
>>>  =C2=A0 - Remove pmlen from struct thread_info (now only in mm_context_=
t)
>>>
>>> Changes in v2:
>>>  =C2=A0 - Implement untagged_addr_remote()
>>>  =C2=A0 - Restrict PMLEN changes once a process is multithreaded
>>>
>>>  =C2=A0 arch/riscv/include/asm/mmu.h=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0 |=C2=A0 7 +++
>>>  =C2=A0 arch/riscv/include/asm/mmu_context.h | 13 +++++
>>>  =C2=A0 arch/riscv/include/asm/uaccess.h=C2=A0=C2=A0=C2=A0=C2=A0 | 58 +=
+++++++++++++++++++--
>>>  =C2=A0 arch/riscv/kernel/process.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0 | 73 ++++++++++++++++++++++++++--
>>>  =C2=A0 4 files changed, 141 insertions(+), 10 deletions(-)
>>>
>>> diff --git a/arch/riscv/include/asm/mmu.h b/arch/riscv/include/asm/mmu.=
h
>>> index c9e03e9da3dc..1cc90465d75b 100644
>>> --- a/arch/riscv/include/asm/mmu.h
>>> +++ b/arch/riscv/include/asm/mmu.h
>>> @@ -25,9 +25,16 @@ typedef struct {
>>>  =C2=A0 #ifdef CONFIG_BINFMT_ELF_FDPIC
>>>  =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 unsigned long exec_fdpic_loadmap;
>>>  =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 unsigned long interp_fdpic_loadmap;
>>> +#endif
>>> +=C2=A0=C2=A0=C2=A0 unsigned long flags;
>>> +#ifdef CONFIG_RISCV_ISA_SUPM
>>> +=C2=A0=C2=A0=C2=A0 u8 pmlen;
>>>  =C2=A0 #endif
>>>  =C2=A0 } mm_context_t;
>>>  =C2=A0 +/* Lock the pointer masking mode because this mm is multithrea=
ded */
>>> +#define MM_CONTEXT_LOCK_PMLEN=C2=A0=C2=A0=C2=A0 0
>>> +
>>>  =C2=A0 #define cntx2asid(cntx)=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0 ((cntx) & SATP_ASID_MASK)
>>>  =C2=A0 #define cntx2version(cntx)=C2=A0=C2=A0=C2=A0 ((cntx) & ~SATP_AS=
ID_MASK)
>>>  =C2=A0 diff --git a/arch/riscv/include/asm/mmu_context.h
>>> b/arch/riscv/include/asm/mmu_context.h
>>> index 7030837adc1a..8c4bc49a3a0f 100644
>>> --- a/arch/riscv/include/asm/mmu_context.h
>>> +++ b/arch/riscv/include/asm/mmu_context.h
>>> @@ -20,6 +20,9 @@ void switch_mm(struct mm_struct *prev, struct mm_stru=
ct *next,
>>>  =C2=A0 static inline void activate_mm(struct mm_struct *prev,
>>>  =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 struct mm_struct *next)
>>>  =C2=A0 {
>>> +#ifdef CONFIG_RISCV_ISA_SUPM
>>> +=C2=A0=C2=A0=C2=A0 next->context.pmlen =3D 0;
>>> +#endif
>>>  =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 switch_mm(prev, next, NULL);
>>>  =C2=A0 }
>>>  =C2=A0 @@ -30,11 +33,21 @@ static inline int init_new_context(struct t=
ask_struct *tsk,
>>>  =C2=A0 #ifdef CONFIG_MMU
>>>  =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 atomic_long_set(&mm->context.id, 0);
>>>  =C2=A0 #endif
>>> +=C2=A0=C2=A0=C2=A0 if (IS_ENABLED(CONFIG_RISCV_ISA_SUPM))
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 clear_bit(MM_CONTEXT_LOCK_P=
MLEN, &mm->context.flags);
>>>  =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 return 0;
>>>  =C2=A0 }
>>>  =C2=A0 =C2=A0 DECLARE_STATIC_KEY_FALSE(use_asid_allocator);
>>>  =C2=A0 +#ifdef CONFIG_RISCV_ISA_SUPM
>>> +#define mm_untag_mask mm_untag_mask
>>> +static inline unsigned long mm_untag_mask(struct mm_struct *mm)
>>> +{
>>> +=C2=A0=C2=A0=C2=A0 return -1UL >> mm->context.pmlen;
>>> +}
>>> +#endif
>>> +
>>>  =C2=A0 #include <asm-generic/mmu_context.h>
>>>  =C2=A0 =C2=A0 #endif /* _ASM_RISCV_MMU_CONTEXT_H */
>>> diff --git a/arch/riscv/include/asm/uaccess.h b/arch/riscv/include/asm/=
uaccess.h
>>> index 72ec1d9bd3f3..6416559232a2 100644
>>> --- a/arch/riscv/include/asm/uaccess.h
>>> +++ b/arch/riscv/include/asm/uaccess.h
>>> @@ -9,8 +9,56 @@
>>>  =C2=A0 #define _ASM_RISCV_UACCESS_H
>>>  =C2=A0 =C2=A0 #include <asm/asm-extable.h>
>>> +#include <asm/cpufeature.h>
>>>  =C2=A0 #include <asm/pgtable.h>=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0 /* for TASK_SIZE */
>>>  =C2=A0 +#ifdef CONFIG_RISCV_ISA_SUPM
>>> +static inline unsigned long __untagged_addr(unsigned long addr)
>>> +{
>>> +=C2=A0=C2=A0=C2=A0 if (riscv_has_extension_unlikely(RISCV_ISA_EXT_SUPM=
)) {
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 u8 pmlen =3D current->mm->c=
ontext.pmlen;
>>> +
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 /* Virtual addresses are si=
gn-extended; physical addresses are
>>> zero-extended. */
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 if (IS_ENABLED(CONFIG_MMU))
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 ret=
urn (long)(addr << pmlen) >> pmlen;
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 else
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 ret=
urn (addr << pmlen) >> pmlen;
>>> +=C2=A0=C2=A0=C2=A0 }
>>> +
>>> +=C2=A0=C2=A0=C2=A0 return addr;
>>> +}
>>> +
>>> +#define untagged_addr(addr) ({=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0 \
>>> +=C2=A0=C2=A0=C2=A0 unsigned long __addr =3D (__force unsigned long)(ad=
dr);=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 \
>>> +=C2=A0=C2=A0=C2=A0 (__force __typeof__(addr))__untagged_addr(__addr);=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 \
>>> +})
>>> +
>>> +static inline unsigned long __untagged_addr_remote(struct mm_struct *m=
m,
>>> unsigned long addr)
>>> +{
>>> +=C2=A0=C2=A0=C2=A0 if (riscv_has_extension_unlikely(RISCV_ISA_EXT_SUPM=
)) {
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 u8 pmlen =3D mm->context.pm=
len;
>>> +
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 /* Virtual addresses are si=
gn-extended; physical addresses are
>>> zero-extended. */
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 if (IS_ENABLED(CONFIG_MMU))
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 ret=
urn (long)(addr << pmlen) >> pmlen;
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 else
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 ret=
urn (addr << pmlen) >> pmlen;
>>> +=C2=A0=C2=A0=C2=A0 }
>>> +
>>> +=C2=A0=C2=A0=C2=A0 return addr;
>>> +}
>>
>> I should have mentioned that in v2: now that you removed the thread_info=
 pmlen
>> field, __untagged_addr_remote() and __untagged_addr() are almost the sam=
e, can
>> you merge them?
> I can merge them, but this places the load of current->mm outside the sta=
tic
> branch. If you think that is okay, then I'll merge them for v4.


I think it's ok, it's not a big overhead :)

Thanks,

Alex


> Regards,
> Samuel
>
>>> +
>>> +#define untagged_addr_remote(mm, addr) ({=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 \
>>> +=C2=A0=C2=A0=C2=A0 unsigned long __addr =3D (__force unsigned long)(ad=
dr);=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 \
>>> +=C2=A0=C2=A0=C2=A0 mmap_assert_locked(mm);=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 \
>>> +=C2=A0=C2=A0=C2=A0 (__force __typeof__(addr))__untagged_addr_remote(mm=
, __addr);=C2=A0=C2=A0=C2=A0 \
>>> +})
>>> +
>>> +#define access_ok(addr, size) likely(__access_ok(untagged_addr(addr), =
size))
>>> +#else
>>> +#define untagged_addr(addr) (addr)
>>> +#endif
>>> +
>>>  =C2=A0 /*
>>>  =C2=A0=C2=A0 * User space memory access functions
>>>  =C2=A0=C2=A0 */
>>> @@ -130,7 +178,7 @@ do {=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 \
>>>  =C2=A0=C2=A0 */
>>>  =C2=A0 #define __get_user(x, ptr)=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0 \
>>>  =C2=A0 ({=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 \
>>> -=C2=A0=C2=A0=C2=A0 const __typeof__(*(ptr)) __user *__gu_ptr =3D (ptr)=
;=C2=A0=C2=A0=C2=A0 \
>>> +=C2=A0=C2=A0=C2=A0 const __typeof__(*(ptr)) __user *__gu_ptr =3D untag=
ged_addr(ptr); \
>>>  =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 long __gu_err =3D 0;=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0 \
>>>  =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 \
>>>  =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 __chk_user_ptr(__gu_ptr);=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0 \
>>> @@ -246,7 +294,7 @@ do {=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 \
>>>  =C2=A0=C2=A0 */
>>>  =C2=A0 #define __put_user(x, ptr)=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0 \
>>>  =C2=A0 ({=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 \
>>> -=C2=A0=C2=A0=C2=A0 __typeof__(*(ptr)) __user *__gu_ptr =3D (ptr);=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 \
>>> +=C2=A0=C2=A0=C2=A0 __typeof__(*(ptr)) __user *__gu_ptr =3D untagged_ad=
dr(ptr); \
>>>  =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 __typeof__(*__gu_ptr) __val =3D (x);=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 \
>>>  =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 long __pu_err =3D 0;=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0 \
>>>  =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 \
>>> @@ -293,13 +341,13 @@ unsigned long __must_check __asm_copy_from_user(v=
oid *to,
>>>  =C2=A0 static inline unsigned long
>>>  =C2=A0 raw_copy_from_user(void *to, const void __user *from, unsigned =
long n)
>>>  =C2=A0 {
>>> -=C2=A0=C2=A0=C2=A0 return __asm_copy_from_user(to, from, n);
>>> +=C2=A0=C2=A0=C2=A0 return __asm_copy_from_user(to, untagged_addr(from)=
, n);
>>>  =C2=A0 }
>>>  =C2=A0 =C2=A0 static inline unsigned long
>>>  =C2=A0 raw_copy_to_user(void __user *to, const void *from, unsigned lo=
ng n)
>>>  =C2=A0 {
>>> -=C2=A0=C2=A0=C2=A0 return __asm_copy_to_user(to, from, n);
>>> +=C2=A0=C2=A0=C2=A0 return __asm_copy_to_user(untagged_addr(to), from, =
n);
>>>  =C2=A0 }
>>>  =C2=A0 =C2=A0 extern long strncpy_from_user(char *dest, const char __u=
ser *src, long
>>> count);
>>> @@ -314,7 +362,7 @@ unsigned long __must_check clear_user(void __user *=
to,
>>> unsigned long n)
>>>  =C2=A0 {
>>>  =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 might_fault();
>>>  =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 return access_ok(to, n) ?
>>> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 __clear_user(to, n) : n;
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 __clear_user(untagged_addr(=
to), n) : n;
>>>  =C2=A0 }
>>>  =C2=A0 =C2=A0 #define __get_kernel_nofault(dst, src, type, err_label)=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 \
>>> diff --git a/arch/riscv/kernel/process.c b/arch/riscv/kernel/process.c
>>> index 1280a7c4a412..f4d8e5c3bb84 100644
>>> --- a/arch/riscv/kernel/process.c
>>> +++ b/arch/riscv/kernel/process.c
>>> @@ -203,6 +203,10 @@ int copy_thread(struct task_struct *p, const struc=
t
>>> kernel_clone_args *args)
>>>  =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 unsigned long tls =3D args->tls;
>>>  =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 struct pt_regs *childregs =3D task_pt_r=
egs(p);
>>>  =C2=A0 +=C2=A0=C2=A0=C2=A0 /* Ensure all threads in this mm have the s=
ame pointer masking mode. */
>>> +=C2=A0=C2=A0=C2=A0 if (IS_ENABLED(CONFIG_RISCV_ISA_SUPM) && p->mm && (=
clone_flags & CLONE_VM))
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 set_bit(MM_CONTEXT_LOCK_PML=
EN, &p->mm->context.flags);
>>> +
>>>  =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 memset(&p->thread.s, 0, sizeof(p->threa=
d.s));
>>>  =C2=A0 =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 /* p->thread holds context to be=
 restored by __switch_to() */
>>> @@ -248,10 +252,16 @@ enum {
>>>  =C2=A0 static bool have_user_pmlen_7;
>>>  =C2=A0 static bool have_user_pmlen_16;
>>>  =C2=A0 +/*
>>> + * Control the relaxed ABI allowing tagged user addresses into the ker=
nel.
>>> + */
>>> +static unsigned int tagged_addr_disabled;
>>> +
>>>  =C2=A0 long set_tagged_addr_ctrl(struct task_struct *task, unsigned lo=
ng arg)
>>>  =C2=A0 {
>>> -=C2=A0=C2=A0=C2=A0 unsigned long valid_mask =3D PR_PMLEN_MASK;
>>> +=C2=A0=C2=A0=C2=A0 unsigned long valid_mask =3D PR_PMLEN_MASK | PR_TAG=
GED_ADDR_ENABLE;
>>>  =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 struct thread_info *ti =3D task_thread_=
info(task);
>>> +=C2=A0=C2=A0=C2=A0 struct mm_struct *mm =3D task->mm;
>>>  =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 unsigned long pmm;
>>>  =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 u8 pmlen;
>>>  =C2=A0 @@ -266,16 +276,41 @@ long set_tagged_addr_ctrl(struct task_str=
uct *task,
>>> unsigned long arg)
>>>  =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 * in case choosing a larger PMLEN=
 has a performance impact.
>>>  =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 */
>>>  =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 pmlen =3D FIELD_GET(PR_PMLEN_MASK, arg)=
;
>>> -=C2=A0=C2=A0=C2=A0 if (pmlen =3D=3D PMLEN_0)
>>> +=C2=A0=C2=A0=C2=A0 if (pmlen =3D=3D PMLEN_0) {
>>>  =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 pmm =3D ENVCFG_=
PMM_PMLEN_0;
>>> -=C2=A0=C2=A0=C2=A0 else if (pmlen <=3D PMLEN_7 && have_user_pmlen_7)
>>> +=C2=A0=C2=A0=C2=A0 } else if (pmlen <=3D PMLEN_7 && have_user_pmlen_7)=
 {
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 pmlen =3D PMLEN_7;
>>>  =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 pmm =3D ENVCFG_=
PMM_PMLEN_7;
>>> -=C2=A0=C2=A0=C2=A0 else if (pmlen <=3D PMLEN_16 && have_user_pmlen_16)
>>> +=C2=A0=C2=A0=C2=A0 } else if (pmlen <=3D PMLEN_16 && have_user_pmlen_1=
6) {
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 pmlen =3D PMLEN_16;
>>>  =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 pmm =3D ENVCFG_=
PMM_PMLEN_16;
>>> -=C2=A0=C2=A0=C2=A0 else
>>> +=C2=A0=C2=A0=C2=A0 } else {
>>>  =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 return -EINVAL;
>>> +=C2=A0=C2=A0=C2=A0 }
>>> +
>>> +=C2=A0=C2=A0=C2=A0 /*
>>> +=C2=A0=C2=A0=C2=A0=C2=A0 * Do not allow the enabling of the tagged add=
ress ABI if globally
>>> +=C2=A0=C2=A0=C2=A0=C2=A0 * disabled via sysctl abi.tagged_addr_disable=
d, if pointer masking
>>> +=C2=A0=C2=A0=C2=A0=C2=A0 * is disabled for userspace.
>>> +=C2=A0=C2=A0=C2=A0=C2=A0 */
>>> +=C2=A0=C2=A0=C2=A0 if (arg & PR_TAGGED_ADDR_ENABLE && (tagged_addr_dis=
abled || !pmlen))
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 return -EINVAL;
>>> +
>>> +=C2=A0=C2=A0=C2=A0 if (!(arg & PR_TAGGED_ADDR_ENABLE))
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 pmlen =3D PMLEN_0;
>>> +
>>> +=C2=A0=C2=A0=C2=A0 if (mmap_write_lock_killable(mm))
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 return -EINTR;
>>> +
>>> +=C2=A0=C2=A0=C2=A0 if (test_bit(MM_CONTEXT_LOCK_PMLEN, &mm->context.fl=
ags) &&
>>> mm->context.pmlen !=3D pmlen) {
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 mmap_write_unlock(mm);
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 return -EBUSY;
>>> +=C2=A0=C2=A0=C2=A0 }
>>>  =C2=A0 =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 envcfg_update_bits(task, ENVCFG_=
PMM, pmm);
>>> +=C2=A0=C2=A0=C2=A0 mm->context.pmlen =3D pmlen;
>>> +
>>> +=C2=A0=C2=A0=C2=A0 mmap_write_unlock(mm);
>>>  =C2=A0 =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 return 0;
>>>  =C2=A0 }
>>> @@ -288,6 +323,10 @@ long get_tagged_addr_ctrl(struct task_struct *task=
)
>>>  =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 if (is_compat_thread(ti))
>>>  =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 return -EINVAL;
>>>  =C2=A0 +=C2=A0=C2=A0=C2=A0 /*
>>> +=C2=A0=C2=A0=C2=A0=C2=A0 * The mm context's pmlen is set only when the=
 tagged address ABI is
>>> +=C2=A0=C2=A0=C2=A0=C2=A0 * enabled, so the effective PMLEN must be ext=
racted from envcfg.PMM.
>>> +=C2=A0=C2=A0=C2=A0=C2=A0 */
>>>  =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 switch (task->thread.envcfg & ENVCFG_PM=
M) {
>>>  =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 case ENVCFG_PMM_PMLEN_7:
>>>  =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 ret =3D FIELD_P=
REP(PR_PMLEN_MASK, PMLEN_7);
>>> @@ -297,6 +336,9 @@ long get_tagged_addr_ctrl(struct task_struct *task)
>>>  =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 break;
>>>  =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 }
>>>  =C2=A0 +=C2=A0=C2=A0=C2=A0 if (task->mm->context.pmlen)
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 ret |=3D PR_TAGGED_ADDR_ENA=
BLE;
>>> +
>>>  =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 return ret;
>>>  =C2=A0 }
>>>  =C2=A0 @@ -306,6 +348,24 @@ static bool try_to_set_pmm(unsigned long v=
alue)
>>>  =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 return (csr_read_clear(CSR_ENVCFG, ENVC=
FG_PMM) & ENVCFG_PMM) =3D=3D value;
>>>  =C2=A0 }
>>>  =C2=A0 +/*
>>> + * Global sysctl to disable the tagged user addresses support. This co=
ntrol
>>> + * only prevents the tagged address ABI enabling via prctl() and does =
not
>>> + * disable it for tasks that already opted in to the relaxed ABI.
>>> + */
>>> +
>>> +static struct ctl_table tagged_addr_sysctl_table[] =3D {
>>> +=C2=A0=C2=A0=C2=A0 {
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 .procname=C2=A0=C2=A0=C2=A0=
 =3D "tagged_addr_disabled",
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 .mode=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0 =3D 0644,
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 .data=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0 =3D &tagged_addr_disabled,
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 .maxlen=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0 =3D sizeof(int),
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 .proc_handler=C2=A0=C2=A0=
=C2=A0 =3D proc_dointvec_minmax,
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 .extra1=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0 =3D SYSCTL_ZERO,
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 .extra2=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0 =3D SYSCTL_ONE,
>>> +=C2=A0=C2=A0=C2=A0 },
>>> +};
>>> +
>>>  =C2=A0 static int __init tagged_addr_init(void)
>>>  =C2=A0 {
>>>  =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 if (!riscv_has_extension_unlikely(RISCV=
_ISA_EXT_SUPM))
>>> @@ -319,6 +379,9 @@ static int __init tagged_addr_init(void)
>>>  =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 have_user_pmlen_7 =3D try_to_set_pmm(EN=
VCFG_PMM_PMLEN_7);
>>>  =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 have_user_pmlen_16 =3D try_to_set_pmm(E=
NVCFG_PMM_PMLEN_16);
>>>  =C2=A0 +=C2=A0=C2=A0=C2=A0 if (!register_sysctl("abi", tagged_addr_sys=
ctl_table))
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 return -EINVAL;
>>> +
>>>  =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 return 0;
>>>  =C2=A0 }
>>>  =C2=A0 core_initcall(tagged_addr_init);
>
> _______________________________________________
> linux-riscv mailing list
> linux-riscv@lists.infradead.org
> http://lists.infradead.org/mailman/listinfo/linux-riscv

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/05eb614b-f4fc-4154-96b3-a30e5adc789f%40ghiti.fr.
