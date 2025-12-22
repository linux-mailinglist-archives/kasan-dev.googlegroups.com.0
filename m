Return-Path: <kasan-dev+bncBAABBXFCUTFAMGQEDEB2XGQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63e.google.com (mail-pl1-x63e.google.com [IPv6:2607:f8b0:4864:20::63e])
	by mail.lfdr.de (Postfix) with ESMTPS id 50569CD558F
	for <lists+kasan-dev@lfdr.de>; Mon, 22 Dec 2025 10:37:34 +0100 (CET)
Received: by mail-pl1-x63e.google.com with SMTP id d9443c01a7336-29da1ea0b97sf105486715ad.3
        for <lists+kasan-dev@lfdr.de>; Mon, 22 Dec 2025 01:37:34 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1766396252; cv=pass;
        d=google.com; s=arc-20240605;
        b=FvC60dh2zcpe2b4UpBjw8StxVO1NxQXbf3r9XFYMaLTXE1+xUOPk/O/2lY2kGnNOUV
         giiKKaXjDC7kSYhFyBXwy6spxrcuYOvTnC+irPxua++xL9yt/S1p1sKIraryUQ1kThjB
         ui1Y6lEvvyLSVAVrloYl5byAg4u1hIXlfOeYa4JWXZTtXO31EFIO9qDGufCiFsc9U6ut
         MvjovFy67Gfly3uMIwx8U9dAywdusx+rcCickAZe2/JKVrh3NhjP8GHOA7Rr8ytmmtlU
         VvOGfXuSqr0OEEaDGby7LzYikXig4dISIyQzrQt5IwppVH/3FHw+Dx54FRvXFGS+nw/+
         uG0A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :in-reply-to:from:content-language:references:cc:to:subject
         :user-agent:mime-version:date:message-id:sender:dkim-signature;
        bh=3R7VwZ3bWyTXNmvxkVomP7kAsNYLq12/ec67rfBbiYg=;
        fh=H1LRtXpqB+JYrF4lo48KP0aDTcIMxMPhZ3wvpIhQb68=;
        b=PqM4Cv2LvUXLBI4dhc1Go+QK7vcGaKcLNcC3ddjD7qmjjnm+9SDrtMNRAGm/5LqWQC
         CMle6o426IcwYLDDbC+loBoyXrifRfiH8L7u15obz/uC58DpqNWQSFbOdVcaxaJR0Mon
         +HAnReinLZI8gVpJak4vNZJCmI44oIlgkM2kpfNhRRkq/OLeDYOrwdTeY9mdKEBbAY7C
         6mw08hDS4+9FeTkKQvxu+UMcGs6LtFMkWJmoPcRfP4e/6y0+O/1lG2rUYp5VNxqdtqXK
         s0Hgqm22z46+5S9VVizfhtxxKc2PSGg3e6k6aT861Mq80VQdhqcJicnADxeGpC5d/w4Y
         pEUQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of lienze@kylinos.cn designates 124.126.103.232 as permitted sender) smtp.mailfrom=lienze@kylinos.cn
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1766396252; x=1767001052; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:in-reply-to:from
         :content-language:references:cc:to:subject:user-agent:mime-version
         :date:message-id:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=3R7VwZ3bWyTXNmvxkVomP7kAsNYLq12/ec67rfBbiYg=;
        b=dmKuUBZCj1oZxJiIVH5TXL1x7dfuvzY6xbqFhDCRhaSse2z6cQ/k52yl1gwqlaxWq6
         dP7t4Ai0hwAxE9zXi4d+R8kPFUCcCsUUxv+S4Td3rLoInSaUs+gYulR+IR0urVYU2I5A
         KABzsr0fYsK78lWA9gH5hUEutDLrgxiTKb4mri7TnHMiwd8EFWY+BXlym/ihMcAvD1Lf
         Sxr9oDYN34KrGaxZ5mSBeCuGq6qzUbyckowmnDJDv4nJCuycrjI//dH4Z7jzA1krdXZn
         oNqFz4ZRBlu/S5XCiBjAUsCNldSJ+aZxjnlWZQUhQUbJYGFK11GySZdLiHcA4PJMcY+o
         YiZg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1766396252; x=1767001052;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=3R7VwZ3bWyTXNmvxkVomP7kAsNYLq12/ec67rfBbiYg=;
        b=iNiWxS/w8GlEyKBtD9UcZ/PPcwffbjzZ7Gl+wl4VdZNilwXiEi6c4hk2J5dJdYpx3J
         sdfj5AXJLU6Ae11+QVodAjtVmNe+aMGEWOMUl2/W4y2F2gVwQ+zmSpSaVxklKqRFOMlQ
         LIrB/9m6tITLfu/7Evrz2LLpBiUFPptEK4WGyj+osRW2nEQksXiBT1cZvBI+lL6qim3r
         UJMIODFbn5a8h249n4yNC9fdvBvyBtws3yhNCjCShSoDB9DisgPdBAVNr5Yap1Ah7l6r
         cqYaiEM6QHZNcPKgYDYe63IfcIibHYK0kGsWCDCGQFiq4c0n8ffGOqoMTSU62XysDTZi
         Vnqw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVrcWL10xUsdMBDP+TTFOi7x/8h8u7FlRrfIVCol/4h805Nw4+LIVS96umLDIifvWwF1jbDWQ==@lfdr.de
X-Gm-Message-State: AOJu0Yworvb5Puczpxz47KCL4VqMbVf9W1JUP7bmL6HaCBcd7OcYXiUR
	QaqsUZQS91CQFV1nyr36nYOs3S1hxFlYw59FSyzeGniHGglEg54pM89y
X-Google-Smtp-Source: AGHT+IGrkqP/e2qkTzRvMDKaBp0UjMybML25EZ/PwRrODyVZ7UrCWE5QiVP3qclvEvT5NA02UuQDzQ==
X-Received: by 2002:a05:6a20:7489:b0:366:14ac:e1e7 with SMTP id adf61e73a8af0-376ab6d2a8fmr10458669637.77.1766396252522;
        Mon, 22 Dec 2025 01:37:32 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWYnWJ7ogAEc98nOJnFI0GHXao6urskftTsC63p07ctDiA=="
Received: by 2002:a17:90b:5288:b0:340:d06d:7e42 with SMTP id
 98e67ed59e1d1-34abccaec2bls12209017a91.2.-pod-prod-06-us; Mon, 22 Dec 2025
 01:37:31 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVC8gZKQnhCQ7Qr2UKiYfY0d+fosZMwyQJVbWSRPDCw2LQbCh0lFFppVSg+PYaIv2a4Jvwf+rxXcKM=@googlegroups.com
X-Received: by 2002:a05:6a20:94c7:b0:35d:c68e:1b08 with SMTP id adf61e73a8af0-376aaaf67f5mr10120361637.53.1766396251182;
        Mon, 22 Dec 2025 01:37:31 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1766396251; cv=none;
        d=google.com; s=arc-20240605;
        b=OKEt4lzf7N7qxf5HXcwQeBvKxsEhph88+VrGiz0RW7bzAAEevNVbliIM6rFg7jAtmp
         dFb6DZdX+Cq4SqqzCMN2qCrAtsvaayXcDmjfXmDf0zCRrR8CnlYLz0lUypfDzi4VDCwa
         Do9ItSx3AZvHl0rVpsdvJxonrB1dyQ3k9GXhFpSzbEOTAMol/anZtj/xFXGuVdMNq67n
         k/f2wLwDgodKDlpSibwI6hP5NFlZieet6TOiCvdRopzngRVu3CkUqz/guKX+U3xxxHVl
         Mlt0+RQRG7ibcHeVNFdV90WnK7b7iotYkyboI9uwh+pqP8fGjAaopBVXrt9YnDkiTwQ4
         FuUQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id;
        bh=8aimI8FiNIO7ZgQp7ZWhdgpnUgUlmkdtRi5vbPLo3vA=;
        fh=lco16A81y41nmYjl13SnRrZ8BqBPyTyssTDvWyMHasM=;
        b=eB4eY2SWXyw7gXVukXaL7u4sMUNCuUo+qEcis7tGsZgc1/Sr3r1efqiICES5v7dUOM
         grxfyEcKa2OxpEeVr0Lu6IKven5dfS9OO5m0xw2tc6sJiCVW/3TdzxnQlxvKPnzH8QEt
         k9ZxAl/D5wDjWjgUp0oA3zTLs97c3bacUo9RAES/lL+4OwZZjL8qQnOKqjIjAuf3io7I
         vJ11nfZIb8MS3guaoHoVK+zuP+fSLPAF24WSV6uvQd8AF/jzfiGc1wQ7+5LsMwbZJjEK
         0+awIeUrZNKZRUSugs4Ba4BToGHQz40yM6glvdZFnEhrWv2VuIXL3cTHxfJcS8XSzm7X
         Yl2g==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of lienze@kylinos.cn designates 124.126.103.232 as permitted sender) smtp.mailfrom=lienze@kylinos.cn
Received: from mailgw.kylinos.cn (mailgw.kylinos.cn. [124.126.103.232])
        by gmr-mx.google.com with ESMTPS id 41be03b00d2f7-c1e7bb66b95si319138a12.3.2025.12.22.01.37.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 22 Dec 2025 01:37:30 -0800 (PST)
Received-SPF: pass (google.com: domain of lienze@kylinos.cn designates 124.126.103.232 as permitted sender) client-ip=124.126.103.232;
X-UUID: d11e6e98df1911f0a38c85956e01ac42-20251222
X-CID-P-RULE: Release_Ham
X-CID-O-INFO: VERSION:1.3.6,REQID:de4d8268-dc8d-48f1-805e-f682d3a06cd1,IP:10,U
	RL:0,TC:0,Content:0,EDM:0,RT:0,SF:-5,FILE:0,BULK:0,RULE:Release_Ham,ACTION
	:release,TS:5
X-CID-INFO: VERSION:1.3.6,REQID:de4d8268-dc8d-48f1-805e-f682d3a06cd1,IP:10,URL
	:0,TC:0,Content:0,EDM:0,RT:0,SF:-5,FILE:0,BULK:0,RULE:Release_Ham,ACTION:r
	elease,TS:5
X-CID-META: VersionHash:a9d874c,CLOUDID:ccaa6ce40de7d863f75bdf900ecd0ee9,BulkI
	D:251219101318D8IDDZQS,BulkQuantity:6,Recheck:0,SF:17|19|38|64|66|78|80|81
	|82|83|102|127|841|898,TC:nil,Content:0|15|50,EDM:-3,IP:-2,URL:0,File:nil,
	RT:nil,Bulk:40,QS:nil,BEC:nil,COL:0,OSI:0,OSA:0,AV:0,LES:1,SPR:NO,DKR:0,DK
	P:0,BRR:0,BRE:0,ARC:0
X-CID-BVR: 2,SSN|SDN
X-CID-BAS: 2,SSN|SDN,0,_
X-CID-FACTOR: TF_CID_SPAM_SNR,TF_CID_SPAM_FAS,TF_CID_SPAM_FSD
X-CID-RHF: D41D8CD98F00B204E9800998ECF8427E
X-UUID: d11e6e98df1911f0a38c85956e01ac42-20251222
X-User: lienze@kylinos.cn
Received: from [192.168.31.182] [(183.242.174.20)] by mailgw.kylinos.cn
	(envelope-from <lienze@kylinos.cn>)
	(Generic MTA with TLSv1.3 TLS_AES_128_GCM_SHA256 128/128)
	with ESMTP id 1610835472; Mon, 22 Dec 2025 17:37:22 +0800
Message-ID: <44d4cf82-982c-455b-85c1-138e8c37cc8f@kylinos.cn>
Date: Mon, 22 Dec 2025 17:37:19 +0800
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v2 1/2] LoongArch: kfence: avoid use
 CONFIG_KFENCE_NUM_OBJECTS
To: yuanlinyu <yuanlinyu@honor.com>, Huacai Chen <chenhuacai@kernel.org>
Cc: Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>,
 Dmitry Vyukov <dvyukov@google.com>, Andrew Morton
 <akpm@linux-foundation.org>, WANG Xuerui <kernel@xen0n.name>,
 "kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>,
 "linux-mm@kvack.org" <linux-mm@kvack.org>,
 "loongarch@lists.linux.dev" <loongarch@lists.linux.dev>,
 "linux-kernel@vger.kernel.org" <linux-kernel@vger.kernel.org>,
 "enze.li@gmx.com" <enze.li@gmx.com>
References: <20251218063916.1433615-1-yuanlinyu@honor.com>
 <20251218063916.1433615-2-yuanlinyu@honor.com>
 <CAAhV-H5n_3Ndk5yRm=S-9WktD9xivVF8-JLaycV8JB-pVuybbA@mail.gmail.com>
 <b2e84054-bf3b-4a1a-b946-bd024f341512@kylinos.cn>
 <ab69f5a942824394af6010f75a06c5f7@honor.com>
Content-Language: en-US
From: Enze Li <lienze@kylinos.cn>
In-Reply-To: <ab69f5a942824394af6010f75a06c5f7@honor.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: lienze@kylinos.cn
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of lienze@kylinos.cn designates 124.126.103.232 as
 permitted sender) smtp.mailfrom=lienze@kylinos.cn
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

On 12/22/25 5:16 PM, yuanlinyu wrote:
>> From: Enze Li <lienze@kylinos.cn>
>> Sent: Saturday, December 20, 2025 1:44 PM
>> To: Huacai Chen <chenhuacai@kernel.org>; yuanlinyu <yuanlinyu@honor.com>
>> Cc: Alexander Potapenko <glider@google.com>; Marco Elver
>> <elver@google.com>; Dmitry Vyukov <dvyukov@google.com>; Andrew Morton
>> <akpm@linux-foundation.org>; WANG Xuerui <kernel@xen0n.name>;
>> kasan-dev@googlegroups.com; linux-mm@kvack.org; loongarch@lists.linux.de=
v;
>> linux-kernel@vger.kernel.org; enze.li@gmx.com
>> Subject: Re: [PATCH v2 1/2] LoongArch: kfence: avoid use
>> CONFIG_KFENCE_NUM_OBJECTS
>>
>> On 2025/12/19 10:13, Huacai Chen wrote:
>>> Hi, Enze,
>>>
>>> On Thu, Dec 18, 2025 at 2:39=E2=80=AFPM yuan linyu <yuanlinyu@honor.com=
> wrote:
>>>>
>>>> use common kfence macro KFENCE_POOL_SIZE for KFENCE_AREA_SIZE
>>>> definition
>>>>
>>>> Signed-off-by: yuan linyu <yuanlinyu@honor.com>
>>>> ---
>>>>  arch/loongarch/include/asm/pgtable.h | 3 ++-
>>>>  1 file changed, 2 insertions(+), 1 deletion(-)
>>>>
>>>> diff --git a/arch/loongarch/include/asm/pgtable.h
>>>> b/arch/loongarch/include/asm/pgtable.h
>>>> index f41a648a3d9e..e9966c9f844f 100644
>>>> --- a/arch/loongarch/include/asm/pgtable.h
>>>> +++ b/arch/loongarch/include/asm/pgtable.h
>>>> @@ -10,6 +10,7 @@
>>>>  #define _ASM_PGTABLE_H
>>>>
>>>>  #include <linux/compiler.h>
>>>> +#include <linux/kfence.h>
>>>>  #include <asm/addrspace.h>
>>>>  #include <asm/asm.h>
>>>>  #include <asm/page.h>
>>>> @@ -96,7 +97,7 @@ extern unsigned long empty_zero_page[PAGE_SIZE /
>> sizeof(unsigned long)];
>>>>  #define MODULES_END    (MODULES_VADDR + SZ_256M)
>>>>
>>>>  #ifdef CONFIG_KFENCE
>>>> -#define KFENCE_AREA_SIZE       (((CONFIG_KFENCE_NUM_OBJECTS + 1)
>> * 2 + 2) * PAGE_SIZE)
>>>> +#define KFENCE_AREA_SIZE       (KFENCE_POOL_SIZE + (2 *
>> PAGE_SIZE))
>>> Can you remember why you didn't use KFENCE_POOL_SIZE at the first place=
?
>>
>> I don't recall the exact reason off the top of my head, but I believe it=
 was due to
>> complex dependency issues with the header files where KFENCE_POOL_SIZE i=
s
>> defined.  To avoid those complications, we likely opted to use
>> KFENCE_NUM_OBJECTS directly.
>>
>> I checked out the code at commit
>> (6ad3df56bb199134800933df2afcd7df3b03ef33 "LoongArch: Add KFENCE
>> (Kernel
>> Electric-Fence) support") and encountered the following errors when comp=
iling
>> with this patch applied.
>>
>> 8<------------------------------------------------------
>>   CC      arch/loongarch/kernel/asm-offsets.s
>> In file included from ./arch/loongarch/include/asm/pgtable.h:13,
>>                  from ./include/linux/pgtable.h:6,
>>                  from ./include/linux/mm.h:29,
>>                  from arch/loongarch/kernel/asm-offsets.c:9:
>> ./include/linux/kfence.h:93:35: warning: 'struct kmem_cache' declared in=
side
>> parameter list will n ot be visible outside of this definition or declar=
ation
>>    93 | void kfence_shutdown_cache(struct kmem_cache *s);
>>       |                                   ^~~~~~~~~~
>> ./include/linux/kfence.h:99:29: warning: 'struct kmem_cache' declared in=
side
>> parameter list will n ot be visible outside of this definition or declar=
ation
>>    99 | void *__kfence_alloc(struct kmem_cache *s, size_t size, gfp_t fl=
ags);
>>       |                             ^~~~~~~~~~
>> ./include/linux/kfence.h:117:50: warning: 'struct kmem_cache' declared i=
nside
>> parameter list will not be visible outside of this definition or declara=
tion
>>   117 | static __always_inline void *kfence_alloc(struct kmem_cache *s, =
size_t
>> size, gfp_t flags)
>>       |
>> ^~~~~~~~~~
>> ./include/linux/kfence.h: In function 'kfence_alloc':
>> ./include/linux/kfence.h:128:31: error: passing argument 1 of '__kfence_=
alloc'
>> from incompatible p ointer type [-Wincompatible-pointer-types]
>>   128 |         return __kfence_alloc(s, size, flags);
>>       |                               ^
>>       |                               |
>>       |                               struct kmem_cache *
>> ./include/linux/kfence.h:99:41: note: expected 'struct kmem_cache *' but
>> argument is of type 'stru ct kmem_cache *'
>>    99 | void *__kfence_alloc(struct kmem_cache *s, size_t size, gfp_t fl=
ags);
>>       |                      ~~~~~~~~~~~~~~~~~~~^
>> ------------------------------------------------------>8
>>
>> Similarly, after applying this patch to the latest code
>> (dd9b004b7ff3289fb7bae35130c0a5c0537266af "Merge tag 'trace-v6.19-rc1'")
>> from the master branch of the Linux repository and enabling KFENCE, I
>> encountered the following compilation errors.
>>
>> 8<------------------------------------------------------
>>   CC      arch/loongarch/kernel/asm-offsets.s
>> In file included from ./arch/loongarch/include/asm/pgtable.h:13,
>>                  from ./include/linux/pgtable.h:6,
>>                  from ./include/linux/mm.h:31,
>>                  from arch/loongarch/kernel/asm-offsets.c:11:
>> ./include/linux/kfence.h:97:35: warning: 'struct kmem_cache' declared in=
side
>> parameter list will n ot be visible outside of this definition or declar=
ation
>>    97 | void kfence_shutdown_cache(struct kmem_cache *s);
>>       |                                   ^~~~~~~~~~
>> ./include/linux/kfence.h:103:29: warning: 'struct kmem_cache' declared i=
nside
>> parameter list will not be visible outside of this definition or declara=
tion
>>   103 | void *__kfence_alloc(struct kmem_cache *s, size_t size, gfp_t fl=
ags);
>>       |                             ^~~~~~~~~~
>> ./include/linux/kfence.h:121:50: warning: 'struct kmem_cache' declared i=
nside
>> parameter list will not be visible outside of this definition or declara=
tion
>>   121 | static __always_inline void *kfence_alloc(struct kmem_cache *s, =
size_t
>> size, gfp_t flags)
>>       |
>> ^~~~~~~~~~
>> ./include/linux/kfence.h: In function 'kfence_alloc':
>> ./include/linux/kfence.h:132:31: error: passing argument 1 of '__kfence_=
alloc'
>> from incompatible p ointer type [-Wincompatible-pointer-types]
>>   132 |         return __kfence_alloc(s, size, flags);
>>       |                               ^
>>       |                               |
>>       |                               struct kmem_cache *
>> ./include/linux/kfence.h:103:41: note: expected 'struct kmem_cache *'
>> but argument is of type 'str
>> uct kmem_cache *'
>>   103 | void *__kfence_alloc(struct kmem_cache *s, size_t size, gfp_t fl=
ags);
>>       |                      ~~~~~~~~~~~~~~~~~~~^
>> ------------------------------------------------------>8
>>
>> So, this patch currently runs into compilation issues.  linyu probably d=
idn't have
>> KFENCE enabled when compiling locally, which is why this error was misse=
d.
>> You can enable it as follows:
>>
>>   Kernel hacking
>>     Memory Debugging
>>       [*] KFENCE: low-overhead sampling-based memory safety
>=20
> Hi Enze,
>=20
> Sorry only test on arm64.
>=20
> Could you help fix the compile issue and provide a correct change ?
>=20
> Or I need sometime to resolve the issue.
>=20

Thanks for pointing out this issue.  I've taken a look at the
compilation problem you mentioned.  Based on my current understanding,
the header dependencies are quite complex, and I couldn't find a
straightforward fix without potentially affecting other parts of the
codebase.

Given the risk of introducing broader compilation errors, I think it
might be safer to hold off on using the KFENCE_POOL_SIZE macro for now,
unless there's a clear and safe path forward that I might have missed.
I'm happy to discuss this further if you have any insights or suggestions.

Thanks,
Enze



--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/4=
4d4cf82-982c-455b-85c1-138e8c37cc8f%40kylinos.cn.
