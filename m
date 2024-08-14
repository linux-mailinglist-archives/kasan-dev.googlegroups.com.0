Return-Path: <kasan-dev+bncBCMIFTP47IJBBY5P6O2QMGQEI5DVI4Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3f.google.com (mail-oa1-x3f.google.com [IPv6:2001:4860:4864:20::3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 9E3A0951F91
	for <lists+kasan-dev@lfdr.de>; Wed, 14 Aug 2024 18:14:28 +0200 (CEST)
Received: by mail-oa1-x3f.google.com with SMTP id 586e51a60fabf-26103a95b34sf53360fac.3
        for <lists+kasan-dev@lfdr.de>; Wed, 14 Aug 2024 09:14:28 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1723652067; cv=pass;
        d=google.com; s=arc-20160816;
        b=j0XcjekXYTJQYvfvbqZKLvjPiXavBhF/2besmLoqc5Pw81vRV0+TnzHiOfKfdLGudf
         ELxk7vj+wNxdq8o0lGJ0iHaR10h1torVMMso9n9bqvZBACD/t15mm5cWB+ZJ6I01i0/i
         Yq4QoluH75UBW+3M+yDeV5REcYDB83XqM3m2JufEiuMqv+4Nz5XnVnqejmO/Th0nOE6l
         0QoC7hHPhbvNTU40DKZr3FZtwqINsd6PvltMlRXp3I+hbLa+yreGNM7SCNWTBdvsvyr6
         0gAF01R2yj7KTfWnRZFdaENIkvdfNHIM+iXPe7WGqPq+JJDe+jHYKbqUaHHY1ic/WgHl
         g3NQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :in-reply-to:from:content-language:references:cc:to:subject
         :user-agent:mime-version:date:message-id:dkim-signature;
        bh=tvbcFrpdwYENG2U9k5eQwMPc1RE8AYzE/KV2+fTytgM=;
        fh=7g57KmjiHmWIstjsIjFNUhxaEy/BkHEBqQqGa0IcVI8=;
        b=asAV97DPt2LKc+NpYgvSCk9WqhDtET5Q15X+CwLGPqGrCSdTN1X/yLKn7x05Qs1Aq6
         ol0QnVk4+HETD4ixcc6HbEUVviBvx5FEWfRv+Wf2QrcUhKv90epHBtNDQ2MMhjYE7zPM
         Rk8xm7RXhwKojXbrk9dm2mJteGSnHD9m9k0zKunaUAxuDaIcL166VaSch8rF+YT+kDEx
         DTirXDepJQKhCXkRCOzCFEzjBlApWgvqghAMQ+IWy2gFrDaMLTlh28FU6cESVZHXprvV
         J7eKJAfnvmRCVvwcu4Z7nNPKvHsTpFroZPVRmYl7XCY8cRntxIALd9oP6u9zgsiCotWz
         5umg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@sifive.com header.s=google header.b=Fgqg03NJ;
       spf=pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::d2b as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=sifive.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1723652067; x=1724256867; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :from:to:cc:subject:date:message-id:reply-to;
        bh=tvbcFrpdwYENG2U9k5eQwMPc1RE8AYzE/KV2+fTytgM=;
        b=DthT1nHEQsGoGhAu6eGK+1GfqAJFYidfs/2Oq+N7OilOzRRDTecJIbp2UvI4RbYNAV
         3pQv3O1rRAOCdnJ2RzOkHj55t2prWWMRFPiVYuXWqojKq71aRX4jIhv8lgUWTtiRP+B6
         psYkt3enBrgikMfmh+fWYg447vJ4eMEqXxIijhDQrlpQmtp1p+8HHhg9j1/vPkB3Qyae
         +deQTyIRzd3UqYHvoqMt0Q6oqi8f1apIRcWQe9pzqZ2Duu+/J1v9nJ90Fhsy8xeao0xQ
         8Km88knfhIxq8YFPkxeLEE6rBs/t9ossVPz3/X9UAVjsJ2IIYnX1yZQb2O36EXGZi1SU
         i4+w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1723652067; x=1724256867;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=tvbcFrpdwYENG2U9k5eQwMPc1RE8AYzE/KV2+fTytgM=;
        b=YEgkI/Gy/EOILdE1QXsrMjO9xVYEH366c84JIrAQ3OF+uiR3c8jMZFP73QJruIl79i
         0KkcBzzxrcm2lnHpIfEO8dsb9l1FDMAbQ400ozUXau5are5TJ40MkJ1Te68mrYZA6T5V
         GfUpaBk049VkTTz0i9QzNLvaUA+vAfrF6UhmAq9TketjSSYNEC4WIbRikYUzkCy8PlHH
         BRahgqo1Qpdg2iVmADucL2HLyHLXTQ8B3knCCinpo9eyAaurLLUeVB8M2eDqfyVG0JoV
         xXyqUmTzHVfzoJKp2wwNmzBkOEfAtU9e+IkINzGA3oUSvvoXjHyIqwiDOwo1H8LdDIK7
         2BdQ==
X-Forwarded-Encrypted: i=2; AJvYcCVw4f1r6+JHfBfbsoNdSEshC21WnVDV+Tl5SOJphbJpCxu1gL9pfKykuPaxwgpi6b9uSDNru9iOUOv5NQthf6LZ/LxjAfvvYQ==
X-Gm-Message-State: AOJu0YwlmaR7H/Ag1KW5aiJHxWKPTrsOQhPztYsa4wg4jenBo/h8aus7
	qThKCYMwyJM46SnZ/HWZtkW8Wr5XpIp4gfRoCGb4XdbOm77Uu7D4
X-Google-Smtp-Source: AGHT+IGE1H/399VKgrL/mVW6gsaWYPGkrAT0fXqPQS/pw507OK8HxJZULxBVl7aGqKuiaB99XiTCBA==
X-Received: by 2002:a05:6870:8188:b0:260:f50e:923e with SMTP id 586e51a60fabf-26fe5c28e71mr3415793fac.37.1723652067159;
        Wed, 14 Aug 2024 09:14:27 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6871:4419:b0:250:a95c:3b4d with SMTP id
 586e51a60fabf-26fff407e67ls46329fac.1.-pod-prod-03-us; Wed, 14 Aug 2024
 09:14:26 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXp+fVG9mR7Lsd9dzzuv2AlDGvvOcGnpPfeKP2MbtpwnDWIVe1J927PbEQHVKUzW7xHEVM8C+zuDvUrHVHqJEGpqxgcPkUJBK3wlg==
X-Received: by 2002:a05:6870:5252:b0:25e:24b:e662 with SMTP id 586e51a60fabf-26fe5c28fffmr4107481fac.34.1723652066327;
        Wed, 14 Aug 2024 09:14:26 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1723652066; cv=none;
        d=google.com; s=arc-20160816;
        b=leLgyCAT2H8XbsM6yomZA9b62clY1kfFIDLyE438GPGTzh4Fezna26MHJiIrz+LVV8
         /oAU7ZFOyFBdzp36Occp6uqNNkHaRv+uzzvtwNakexJU7vq05v20ys8fVnuBiLDRO8/0
         cca/ggQdY08A0ELx5z8Jw4HwB/p4xIILObrEAG0064m3BumZN5ToSCBKo3Tq/8AHN7XD
         M+ISA5aPM5GHhHLFh30hPyC6x+LQa8vCN57DaO0oU7pCe5IcIgUjJurcCWLUPllATOmr
         6Vn5VtDbY1r5KOH9crycU3KdYeW/njf6LEW6uLl1tTBxM2BXye3mAlM8/DnKbZU7IBCy
         okag==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=rXV+YKI1ELuOkMaqAD9XBTtYzGZmQcby+BNTgX8XJuE=;
        fh=cuAmdIR2SSIC3HlVnMW63Fc2jTLEfQcWkbOFsQziYOU=;
        b=qOS2D7GjqHoeq12KcxgWvwEOvtJu84tUaW56JekLG009DUdKSAVHKZa76KDf7bPgR6
         fgSEkXyKL7kqZX17BgjwSKO3vDTBYH8mJaAV62MqCCAJrqGsA5DGkPFs3Fgs78h1jYea
         HAmI43+eFay3UuPOjxRpP1sCvI2+jEvk+xwqFWWal+bSNMLqIFqtJAygUBIgUFjbswCk
         +pqqxxiO4XHv169ibhIyoHHWd7l/OEEy/zZWTm959JqomDt0IsOqi69ruTKTNStQiSQd
         H9HFUQCB41hfL7Dl3OAWHi37eSiJEsTciJJZln0KnoLILTYb9+1IQRIlJDMgGR6+qeaH
         ITmg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@sifive.com header.s=google header.b=Fgqg03NJ;
       spf=pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::d2b as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=sifive.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-io1-xd2b.google.com (mail-io1-xd2b.google.com. [2607:f8b0:4864:20::d2b])
        by gmr-mx.google.com with ESMTPS id 46e09a7af769-70c7b81c19bsi366496a34.2.2024.08.14.09.14.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 14 Aug 2024 09:14:26 -0700 (PDT)
Received-SPF: pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::d2b as permitted sender) client-ip=2607:f8b0:4864:20::d2b;
Received: by mail-io1-xd2b.google.com with SMTP id ca18e2360f4ac-81f96eaa02aso5341539f.2
        for <kasan-dev@googlegroups.com>; Wed, 14 Aug 2024 09:14:26 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVOt8hZ7Jbn3DlKfR+mjiDZJvhYXsd+uWYGfqdlbQ+/IJxEWnvqV7FTsn+hj8nSnFCuLW5uNT+L4Xh/cd+PeHpp9st5/GhmGBQnhQ==
X-Received: by 2002:a05:6602:148d:b0:813:f74:e6e6 with SMTP id ca18e2360f4ac-824dadf75femr426971839f.15.1723652065623;
        Wed, 14 Aug 2024 09:14:25 -0700 (PDT)
Received: from [100.64.0.1] ([147.124.94.167])
        by smtp.gmail.com with ESMTPSA id 8926c6da1cb9f-4ca76a330f7sm3340857173.145.2024.08.14.09.14.24
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 14 Aug 2024 09:14:25 -0700 (PDT)
Message-ID: <044b77fe-fd17-4c01-934a-80d63822fb3f@sifive.com>
Date: Wed, 14 Aug 2024 11:14:23 -0500
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v3 05/10] riscv: Add support for the tagged address ABI
To: Alexandre Ghiti <alex@ghiti.fr>, Palmer Dabbelt <palmer@dabbelt.com>,
 linux-riscv@lists.infradead.org
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
Content-Language: en-US
From: "'Samuel Holland' via kasan-dev" <kasan-dev@googlegroups.com>
In-Reply-To: <35e8386f-854a-48d5-8c03-7a53f8ca3292@ghiti.fr>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: samuel.holland@sifive.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@sifive.com header.s=google header.b=Fgqg03NJ;       spf=pass
 (google.com: domain of samuel.holland@sifive.com designates
 2607:f8b0:4864:20::d2b as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
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

On 2024-08-14 10:10 AM, Alexandre Ghiti wrote:
> On 14/08/2024 10:13, Samuel Holland wrote:
>> When pointer masking is enabled for userspace, the kernel can accept
>> tagged pointers as arguments to some system calls. Allow this by
>> untagging the pointers in access_ok() and the uaccess routines. The
>> uaccess routines must peform untagging in software because U-mode and
>> S-mode have entirely separate pointer masking configurations. In fact,
>> hardware may not even implement pointer masking for S-mode.
>>
>> Since the number of tag bits is variable, untagged_addr_remote() needs
>> to know what PMLEN to use for the remote mm. Therefore, the pointer
>> masking mode must be the same for all threads sharing an mm. Enforce
>> this with a lock flag in the mm context, as x86 does for LAM. The flag
>> gets reset in init_new_context() during fork(), as the new mm is no
>> longer multithreaded.
>>
>> Signed-off-by: Samuel Holland <samuel.holland@sifive.com>
>> ---
>>
>> Changes in v3:
>> =C2=A0 - Use IS_ENABLED instead of #ifdef when possible
>> =C2=A0 - Implement mm_untag_mask()
>> =C2=A0 - Remove pmlen from struct thread_info (now only in mm_context_t)
>>
>> Changes in v2:
>> =C2=A0 - Implement untagged_addr_remote()
>> =C2=A0 - Restrict PMLEN changes once a process is multithreaded
>>
>> =C2=A0 arch/riscv/include/asm/mmu.h=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0 |=C2=A0 7 +++
>> =C2=A0 arch/riscv/include/asm/mmu_context.h | 13 +++++
>> =C2=A0 arch/riscv/include/asm/uaccess.h=C2=A0=C2=A0=C2=A0=C2=A0 | 58 +++=
+++++++++++++++++--
>> =C2=A0 arch/riscv/kernel/process.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0 | 73 ++++++++++++++++++++++++++--
>> =C2=A0 4 files changed, 141 insertions(+), 10 deletions(-)
>>
>> diff --git a/arch/riscv/include/asm/mmu.h b/arch/riscv/include/asm/mmu.h
>> index c9e03e9da3dc..1cc90465d75b 100644
>> --- a/arch/riscv/include/asm/mmu.h
>> +++ b/arch/riscv/include/asm/mmu.h
>> @@ -25,9 +25,16 @@ typedef struct {
>> =C2=A0 #ifdef CONFIG_BINFMT_ELF_FDPIC
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 unsigned long exec_fdpic_loadmap;
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 unsigned long interp_fdpic_loadmap;
>> +#endif
>> +=C2=A0=C2=A0=C2=A0 unsigned long flags;
>> +#ifdef CONFIG_RISCV_ISA_SUPM
>> +=C2=A0=C2=A0=C2=A0 u8 pmlen;
>> =C2=A0 #endif
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
>> index 7030837adc1a..8c4bc49a3a0f 100644
>> --- a/arch/riscv/include/asm/mmu_context.h
>> +++ b/arch/riscv/include/asm/mmu_context.h
>> @@ -20,6 +20,9 @@ void switch_mm(struct mm_struct *prev, struct mm_struc=
t *next,
>> =C2=A0 static inline void activate_mm(struct mm_struct *prev,
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 struct mm_struct *next)
>> =C2=A0 {
>> +#ifdef CONFIG_RISCV_ISA_SUPM
>> +=C2=A0=C2=A0=C2=A0 next->context.pmlen =3D 0;
>> +#endif
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 switch_mm(prev, next, NULL);
>> =C2=A0 }
>> =C2=A0 @@ -30,11 +33,21 @@ static inline int init_new_context(struct tas=
k_struct *tsk,
>> =C2=A0 #ifdef CONFIG_MMU
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 atomic_long_set(&mm->context.id, 0);
>> =C2=A0 #endif
>> +=C2=A0=C2=A0=C2=A0 if (IS_ENABLED(CONFIG_RISCV_ISA_SUPM))
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 clear_bit(MM_CONTEXT_LOCK_PM=
LEN, &mm->context.flags);
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 return 0;
>> =C2=A0 }
>> =C2=A0 =C2=A0 DECLARE_STATIC_KEY_FALSE(use_asid_allocator);
>> =C2=A0 +#ifdef CONFIG_RISCV_ISA_SUPM
>> +#define mm_untag_mask mm_untag_mask
>> +static inline unsigned long mm_untag_mask(struct mm_struct *mm)
>> +{
>> +=C2=A0=C2=A0=C2=A0 return -1UL >> mm->context.pmlen;
>> +}
>> +#endif
>> +
>> =C2=A0 #include <asm-generic/mmu_context.h>
>> =C2=A0 =C2=A0 #endif /* _ASM_RISCV_MMU_CONTEXT_H */
>> diff --git a/arch/riscv/include/asm/uaccess.h b/arch/riscv/include/asm/u=
access.h
>> index 72ec1d9bd3f3..6416559232a2 100644
>> --- a/arch/riscv/include/asm/uaccess.h
>> +++ b/arch/riscv/include/asm/uaccess.h
>> @@ -9,8 +9,56 @@
>> =C2=A0 #define _ASM_RISCV_UACCESS_H
>> =C2=A0 =C2=A0 #include <asm/asm-extable.h>
>> +#include <asm/cpufeature.h>
>> =C2=A0 #include <asm/pgtable.h>=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0 /* for TASK_SIZE */
>> =C2=A0 +#ifdef CONFIG_RISCV_ISA_SUPM
>> +static inline unsigned long __untagged_addr(unsigned long addr)
>> +{
>> +=C2=A0=C2=A0=C2=A0 if (riscv_has_extension_unlikely(RISCV_ISA_EXT_SUPM)=
) {
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 u8 pmlen =3D current->mm->co=
ntext.pmlen;
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
>=20
>=20
> I should have mentioned that in v2: now that you removed the thread_info =
pmlen
> field, __untagged_addr_remote() and __untagged_addr() are almost the same=
, can
> you merge them?

I can merge them, but this places the load of current->mm outside the stati=
c
branch. If you think that is okay, then I'll merge them for v4.

Regards,
Samuel

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
>> index 1280a7c4a412..f4d8e5c3bb84 100644
>> --- a/arch/riscv/kernel/process.c
>> +++ b/arch/riscv/kernel/process.c
>> @@ -203,6 +203,10 @@ int copy_thread(struct task_struct *p, const struct
>> kernel_clone_args *args)
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 unsigned long tls =3D args->tls;
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 struct pt_regs *childregs =3D task_pt_reg=
s(p);
>> =C2=A0 +=C2=A0=C2=A0=C2=A0 /* Ensure all threads in this mm have the sam=
e pointer masking mode. */
>> +=C2=A0=C2=A0=C2=A0 if (IS_ENABLED(CONFIG_RISCV_ISA_SUPM) && p->mm && (c=
lone_flags & CLONE_VM))
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 set_bit(MM_CONTEXT_LOCK_PMLE=
N, &p->mm->context.flags);
>> +
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 memset(&p->thread.s, 0, sizeof(p->thread.=
s));
>> =C2=A0 =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 /* p->thread holds context to be r=
estored by __switch_to() */
>> @@ -248,10 +252,16 @@ enum {
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
>> =C2=A0 @@ -266,16 +276,41 @@ long set_tagged_addr_ctrl(struct task_struc=
t *task,
>> unsigned long arg)
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 * in case choosing a larger PMLEN h=
as a performance impact.
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 */
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 pmlen =3D FIELD_GET(PR_PMLEN_MASK, arg);
>> -=C2=A0=C2=A0=C2=A0 if (pmlen =3D=3D PMLEN_0)
>> +=C2=A0=C2=A0=C2=A0 if (pmlen =3D=3D PMLEN_0) {
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 pmm =3D ENVCFG_PM=
M_PMLEN_0;
>> -=C2=A0=C2=A0=C2=A0 else if (pmlen <=3D PMLEN_7 && have_user_pmlen_7)
>> +=C2=A0=C2=A0=C2=A0 } else if (pmlen <=3D PMLEN_7 && have_user_pmlen_7) =
{
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 pmlen =3D PMLEN_7;
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 pmm =3D ENVCFG_PM=
M_PMLEN_7;
>> -=C2=A0=C2=A0=C2=A0 else if (pmlen <=3D PMLEN_16 && have_user_pmlen_16)
>> +=C2=A0=C2=A0=C2=A0 } else if (pmlen <=3D PMLEN_16 && have_user_pmlen_16=
) {
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 pmlen =3D PMLEN_16;
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 pmm =3D ENVCFG_PM=
M_PMLEN_16;
>> -=C2=A0=C2=A0=C2=A0 else
>> +=C2=A0=C2=A0=C2=A0 } else {
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 return -EINVAL;
>> +=C2=A0=C2=A0=C2=A0 }
>> +
>> +=C2=A0=C2=A0=C2=A0 /*
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
>> +=C2=A0=C2=A0=C2=A0 if (!(arg & PR_TAGGED_ADDR_ENABLE))
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 pmlen =3D PMLEN_0;
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
>> =C2=A0 =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 envcfg_update_bits(task, ENVCFG_PM=
M, pmm);
>> +=C2=A0=C2=A0=C2=A0 mm->context.pmlen =3D pmlen;
>> +
>> +=C2=A0=C2=A0=C2=A0 mmap_write_unlock(mm);
>> =C2=A0 =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 return 0;
>> =C2=A0 }
>> @@ -288,6 +323,10 @@ long get_tagged_addr_ctrl(struct task_struct *task)
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 if (is_compat_thread(ti))
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 return -EINVAL;
>> =C2=A0 +=C2=A0=C2=A0=C2=A0 /*
>> +=C2=A0=C2=A0=C2=A0=C2=A0 * The mm context's pmlen is set only when the =
tagged address ABI is
>> +=C2=A0=C2=A0=C2=A0=C2=A0 * enabled, so the effective PMLEN must be extr=
acted from envcfg.PMM.
>> +=C2=A0=C2=A0=C2=A0=C2=A0 */
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 switch (task->thread.envcfg & ENVCFG_PMM)=
 {
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 case ENVCFG_PMM_PMLEN_7:
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 ret =3D FIELD_PRE=
P(PR_PMLEN_MASK, PMLEN_7);
>> @@ -297,6 +336,9 @@ long get_tagged_addr_ctrl(struct task_struct *task)
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 break;
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 }
>> =C2=A0 +=C2=A0=C2=A0=C2=A0 if (task->mm->context.pmlen)
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 ret |=3D PR_TAGGED_ADDR_ENAB=
LE;
>> +
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 return ret;
>> =C2=A0 }
>> =C2=A0 @@ -306,6 +348,24 @@ static bool try_to_set_pmm(unsigned long val=
ue)
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
>> @@ -319,6 +379,9 @@ static int __init tagged_addr_init(void)
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
kasan-dev/044b77fe-fd17-4c01-934a-80d63822fb3f%40sifive.com.
