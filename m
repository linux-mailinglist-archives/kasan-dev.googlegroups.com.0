Return-Path: <kasan-dev+bncBAABBIHPTDFAMGQEVST6TGI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-dl1-x123b.google.com (mail-dl1-x123b.google.com [IPv6:2607:f8b0:4864:20::123b])
	by mail.lfdr.de (Postfix) with ESMTPS id 03971CD2832
	for <lists+kasan-dev@lfdr.de>; Sat, 20 Dec 2025 06:44:03 +0100 (CET)
Received: by mail-dl1-x123b.google.com with SMTP id a92af1059eb24-11bd7a827fdsf6033105c88.1
        for <lists+kasan-dev@lfdr.de>; Fri, 19 Dec 2025 21:44:02 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1766209441; cv=pass;
        d=google.com; s=arc-20240605;
        b=RR++GxWRMmHYR2iqkuD0sqLejRphXK0ZT9Bxl6ElEkDAwNp7KhlLwmxeqQarZmONQD
         yNA88FoMj6tWXsvL9DETAByqTWwPkw+PghZZuqU7ULJLjmOEY3xM+6aFCCKWxpo9PiT2
         JmPpM6Xmlr9iyLBUdmkgC/0j1FuZ0V9curdF0ZsiE8vHSXtBjN90W56tfzv7ylyul1p3
         FMqdGirS3qIE2LzbfSY81Zdz8HWaYewyovQwHpqoZ+EueRycJ68lM83ZGwRzYk78hTbK
         9ghw01+zJVJulLSsNxunlIugdiQUrhNjCmiiCh2fcXdfoNKdcHG3ppHCU/D3xd9bzW6G
         XWFQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :in-reply-to:from:content-language:references:cc:to:subject
         :user-agent:mime-version:date:message-id:sender:dkim-signature;
        bh=ATQS7R/23fcuu47Rz45sfrjsL0HyIX0QJqwNTEerdco=;
        fh=I5inNmal/bjst6CSUtaVFx/8liG5peA8F7Z+iXhLKw8=;
        b=c/TWjJehc6aDQh7zQAgQyKvmHfwdfhCIxovqcybWNFB+ni7pDIXEsc8t//AbCBl0fc
         7iweCkcejOH1Ml3DN/cOTCVu2E0Wm5YXHdKst2ScEMnUsC9C2ECZKLJhwQyzLQVjULrD
         WX3VP0pJQaHzLBsR214WlkMHXQ4telF2a8CcnKYSs/ZkO4koacz1VVYZMLArro5BK8Jd
         iovfLeMy7g0JHARaXj1HaKbyGS/9gRMpqcmUZEAxtKwixmVPwYaQLy3Ab2yFsqTNFk+E
         G41u8IwrHnv/6eoYTcwexYQcK+hiVzMEPM6roRemnPMyIUPBCb9lXwDvMi0yOT/FDZX3
         huvQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of lienze@kylinos.cn designates 124.126.103.232 as permitted sender) smtp.mailfrom=lienze@kylinos.cn
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1766209441; x=1766814241; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:in-reply-to:from
         :content-language:references:cc:to:subject:user-agent:mime-version
         :date:message-id:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=ATQS7R/23fcuu47Rz45sfrjsL0HyIX0QJqwNTEerdco=;
        b=OcLEBiC2+DHwMQjE/qPrivIcH4nDladPK+O5qVXNAY0aw/+x9FRFXfRg5+YeoqZXKA
         MMdSza3isybvNgTNz9XVruruiZ+mAp67BsaPLU70ICpHzW8o8F0L9q4wfY+WDqrfSEv+
         RF20A4L/Q5Bv7DNLuIQOFPnCU3sa/0EhemB54W8EaVYilV2p/RS4eCtfaYGe2HH+cz6Z
         Ocv+tb/fficeHgTutSMdDIugiQMgthmQ9rcbs6gdkWnO+BFUP5/O64bBacB6i0biei7j
         cFqrqA2eQ+vVPdmVG35eoW6QILQcDKw3FRbiUI6UHKUKOr/U45311CXxtJD70xk6gP2t
         TyHQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1766209441; x=1766814241;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=ATQS7R/23fcuu47Rz45sfrjsL0HyIX0QJqwNTEerdco=;
        b=a4ZqoPGETUtQbZ4dxvbg9VmO0HlY1ARrWJ5z2mQivNxCWTSIZVluLShd+ZgxCX0NV9
         AlCcrO//pon45Wl9zt5zCUsbP3q1KyNyrqyJoJp03jsOxBnMoIvdvKRS2DhKRfLzV21O
         FfFgRcdZE25ZcExodLLNm/sfSvITS9XzklySBXHPFhtoZc+BWt+8J0n9bN1leKvslfsU
         gGQ+yZsRO7swIiFIasrCy++Id+Wx5IU5pCQoJzMUOa6pl56EKCdk0i8KnRiXCaHmV6Fb
         2Q8chvKxbqVWcMrSKcj1Ej8kjdvLp9fxS0i85LuKcKSFkrPdUvx200SXiNoD7wFHCbQe
         NRDQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCV56FSzny/zdX6reTmkqZMUkNP0BbVgZKwunwPMVATMMXPLL3wz8YnsDcWkv+er2ChNGoXj7g==@lfdr.de
X-Gm-Message-State: AOJu0YyL/1YbDAY3rE2zt+GEUnxvyuf9B+YJdiv8NcSE/cpw1izTaj50
	8SmcDMeo06OfqxEgtzNXLKRrsSwHyztWyeMFNLG5o3z/pZhVhNu0+lEl
X-Google-Smtp-Source: AGHT+IFMH3jFP9bIo2j+RsZTQATX2vXjp7DY/M2M86KCSMWuYjsnPBdKzxC214gtXXZBfrSy+YUGLQ==
X-Received: by 2002:a05:701b:240d:b0:11d:fc25:af63 with SMTP id a92af1059eb24-1206194371emr6990975c88.11.1766209440974;
        Fri, 19 Dec 2025 21:44:00 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWZ4sWpnqbIoYuRanHgd4MFc0MD8htYchzObI3ptDdhs8A=="
Received: by 2002:a05:7022:a82:b0:11b:519:e611 with SMTP id
 a92af1059eb24-11f33ef5722ls4581672c88.1.-pod-prod-00-us-canary; Fri, 19 Dec
 2025 21:44:00 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXC7w1rq46R4WSduhnkaxtbt71X8vwzi9K/Qq6DAF8hXuhDYiB9HBvSbMg/+wMD1/gRVlr9Iza9N0Q=@googlegroups.com
X-Received: by 2002:a05:7022:608a:b0:11b:a8e3:847b with SMTP id a92af1059eb24-12171a685cbmr5327021c88.5.1766209439606;
        Fri, 19 Dec 2025 21:43:59 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1766209439; cv=none;
        d=google.com; s=arc-20240605;
        b=KGP5j86sMmB0U1kmPSuiAVn6sOF/Fz+zrmbCYH2/cOn76/noMDBCBk4cjA1XHxyMbz
         DGkj3x+Hp2mLBcxiEl6VhrbAr+cdZT+1iffx4d8Uso6fpM0dJ4WbGoX+geRsoC4Zcj5o
         O14sxKqBh3nCCDbyQNWBDzGfaNz4SbC2/Gfcgfj36JlEhbq7f6egoEKZFl4kxR72ojiO
         1Nd6sft+QF2LHB5Hx9HFpCUMXYPVcQd7a5SXs987iCEpzpPtIZ3qQoARl2oag0+zmEHh
         up56Z459plihb+Lp2NtXgt3MdvW/dPMEeoMqtuSqZzq04qtJO5Z/APvn1YdNQaTr3G0A
         CDZA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id;
        bh=7okOQ6xSw3cIWjhsylDeT146yAKFlCiQ/V+Z3H0RxOo=;
        fh=u8lAEqT4Kk7QhZj3ikBdgfp/d2bcpscK8WaWAUtKmM0=;
        b=i+MmX6GpMn4ORjaNIUSu+hb5p4H2AVReUyK9UIbj8puPy4S2RpXee79/BvEFbXuiwp
         fWBQu7jQKofMXWL2IVDAibPVVnZUX5Qz61JE4D+vq3DcprtszSzTa/SJjBVr1bRIc1TA
         zHtJa4CEtNXZpoYtVHD0azZmC7bC0Y6qUVit9JILxBIoLQ9LUc+8ykbsTou1UCoV9pzq
         a51sDnatXCaiLtSWXY9sqB+L44Oh6EGYT9M+KIEgkcFRXXqJNM100Owa5xfvzPb+7MkK
         3ZR9Z+6P12aKnfav9EaY1p2KQ5eJjGmvhD7IHn0rTkfZ7r0rfSpws6Eyr+mlFgZoiL2x
         owUQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of lienze@kylinos.cn designates 124.126.103.232 as permitted sender) smtp.mailfrom=lienze@kylinos.cn
Received: from mailgw.kylinos.cn (mailgw.kylinos.cn. [124.126.103.232])
        by gmr-mx.google.com with ESMTPS id a92af1059eb24-121724c83bfsi42113c88.2.2025.12.19.21.43.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 19 Dec 2025 21:43:58 -0800 (PST)
Received-SPF: pass (google.com: domain of lienze@kylinos.cn designates 124.126.103.232 as permitted sender) client-ip=124.126.103.232;
X-UUID: db8d1ab4dd6611f0a38c85956e01ac42-20251220
X-CID-P-RULE: Release_Ham
X-CID-O-INFO: VERSION:1.3.6,REQID:51651edb-493c-41a1-801f-dabd13d97b87,IP:10,U
	RL:0,TC:0,Content:0,EDM:0,RT:0,SF:-5,FILE:0,BULK:0,RULE:Release_Ham,ACTION
	:release,TS:5
X-CID-INFO: VERSION:1.3.6,REQID:51651edb-493c-41a1-801f-dabd13d97b87,IP:10,URL
	:0,TC:0,Content:0,EDM:0,RT:0,SF:-5,FILE:0,BULK:0,RULE:Release_Ham,ACTION:r
	elease,TS:5
X-CID-META: VersionHash:a9d874c,CLOUDID:ff1733cf03d1e39fa358ca7d4eb7e3f6,BulkI
	D:251219101318D8IDDZQS,BulkQuantity:2,Recheck:0,SF:17|19|38|64|66|78|80|81
	|82|83|102|127|841|898,TC:nil,Content:0|15|50,EDM:-3,IP:-2,URL:0,File:nil,
	RT:nil,Bulk:40,QS:nil,BEC:nil,COL:0,OSI:0,OSA:0,AV:0,LES:1,SPR:NO,DKR:0,DK
	P:0,BRR:0,BRE:0,ARC:0
X-CID-BVR: 2,SSN|SDN
X-CID-BAS: 2,SSN|SDN,0,_
X-CID-FACTOR: TF_CID_SPAM_FAS,TF_CID_SPAM_FSD,TF_CID_SPAM_SNR
X-CID-RHF: D41D8CD98F00B204E9800998ECF8427E
X-UUID: db8d1ab4dd6611f0a38c85956e01ac42-20251220
X-User: lienze@kylinos.cn
Received: from [192.168.3.106] [(61.48.209.219)] by mailgw.kylinos.cn
	(envelope-from <lienze@kylinos.cn>)
	(Generic MTA with TLSv1.3 TLS_AES_128_GCM_SHA256 128/128)
	with ESMTP id 1618505666; Sat, 20 Dec 2025 13:43:48 +0800
Message-ID: <b2e84054-bf3b-4a1a-b946-bd024f341512@kylinos.cn>
Date: Sat, 20 Dec 2025 13:43:46 +0800
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v2 1/2] LoongArch: kfence: avoid use
 CONFIG_KFENCE_NUM_OBJECTS
To: Huacai Chen <chenhuacai@kernel.org>, yuan linyu <yuanlinyu@honor.com>
Cc: Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>,
 Dmitry Vyukov <dvyukov@google.com>, Andrew Morton
 <akpm@linux-foundation.org>, WANG Xuerui <kernel@xen0n.name>,
 kasan-dev@googlegroups.com, linux-mm@kvack.org, loongarch@lists.linux.dev,
 linux-kernel@vger.kernel.org, enze.li@gmx.com
References: <20251218063916.1433615-1-yuanlinyu@honor.com>
 <20251218063916.1433615-2-yuanlinyu@honor.com>
 <CAAhV-H5n_3Ndk5yRm=S-9WktD9xivVF8-JLaycV8JB-pVuybbA@mail.gmail.com>
Content-Language: en-US
From: Enze Li <lienze@kylinos.cn>
In-Reply-To: <CAAhV-H5n_3Ndk5yRm=S-9WktD9xivVF8-JLaycV8JB-pVuybbA@mail.gmail.com>
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

On 2025/12/19 10:13, Huacai Chen wrote:
> Hi, Enze,
>=20
> On Thu, Dec 18, 2025 at 2:39=E2=80=AFPM yuan linyu <yuanlinyu@honor.com> =
wrote:
>>
>> use common kfence macro KFENCE_POOL_SIZE for KFENCE_AREA_SIZE definition
>>
>> Signed-off-by: yuan linyu <yuanlinyu@honor.com>
>> ---
>>  arch/loongarch/include/asm/pgtable.h | 3 ++-
>>  1 file changed, 2 insertions(+), 1 deletion(-)
>>
>> diff --git a/arch/loongarch/include/asm/pgtable.h b/arch/loongarch/inclu=
de/asm/pgtable.h
>> index f41a648a3d9e..e9966c9f844f 100644
>> --- a/arch/loongarch/include/asm/pgtable.h
>> +++ b/arch/loongarch/include/asm/pgtable.h
>> @@ -10,6 +10,7 @@
>>  #define _ASM_PGTABLE_H
>>
>>  #include <linux/compiler.h>
>> +#include <linux/kfence.h>
>>  #include <asm/addrspace.h>
>>  #include <asm/asm.h>
>>  #include <asm/page.h>
>> @@ -96,7 +97,7 @@ extern unsigned long empty_zero_page[PAGE_SIZE / sizeo=
f(unsigned long)];
>>  #define MODULES_END    (MODULES_VADDR + SZ_256M)
>>
>>  #ifdef CONFIG_KFENCE
>> -#define KFENCE_AREA_SIZE       (((CONFIG_KFENCE_NUM_OBJECTS + 1) * 2 + =
2) * PAGE_SIZE)
>> +#define KFENCE_AREA_SIZE       (KFENCE_POOL_SIZE + (2 * PAGE_SIZE))
> Can you remember why you didn't use KFENCE_POOL_SIZE at the first place?

I don't recall the exact reason off the top of my head, but I believe it
was due to complex dependency issues with the header files where
KFENCE_POOL_SIZE is defined.  To avoid those complications, we likely
opted to use KFENCE_NUM_OBJECTS directly.

I checked out the code at commit
(6ad3df56bb199134800933df2afcd7df3b03ef33 "LoongArch: Add KFENCE (Kernel
Electric-Fence) support") and encountered the following errors when
compiling with this patch applied.

8<------------------------------------------------------
  CC      arch/loongarch/kernel/asm-offsets.s
In file included from ./arch/loongarch/include/asm/pgtable.h:13,
                 from ./include/linux/pgtable.h:6,
                 from ./include/linux/mm.h:29,
                 from arch/loongarch/kernel/asm-offsets.c:9:
./include/linux/kfence.h:93:35: warning: 'struct kmem_cache' declared
inside parameter list will n
ot be visible outside of this definition or declaration
   93 | void kfence_shutdown_cache(struct kmem_cache *s);
      |                                   ^~~~~~~~~~
./include/linux/kfence.h:99:29: warning: 'struct kmem_cache' declared
inside parameter list will n
ot be visible outside of this definition or declaration
   99 | void *__kfence_alloc(struct kmem_cache *s, size_t size, gfp_t
flags);
      |                             ^~~~~~~~~~
./include/linux/kfence.h:117:50: warning: 'struct kmem_cache' declared
inside parameter list will
not be visible outside of this definition or declaration
  117 | static __always_inline void *kfence_alloc(struct kmem_cache *s,
size_t size, gfp_t flags)
      |                                                  ^~~~~~~~~~
./include/linux/kfence.h: In function 'kfence_alloc':
./include/linux/kfence.h:128:31: error: passing argument 1 of
'__kfence_alloc' from incompatible p
ointer type [-Wincompatible-pointer-types]
  128 |         return __kfence_alloc(s, size, flags);
      |                               ^
      |                               |
      |                               struct kmem_cache *
./include/linux/kfence.h:99:41: note: expected 'struct kmem_cache *' but
argument is of type 'stru
ct kmem_cache *'
   99 | void *__kfence_alloc(struct kmem_cache *s, size_t size, gfp_t
flags);
      |                      ~~~~~~~~~~~~~~~~~~~^
------------------------------------------------------>8

Similarly, after applying this patch to the latest code
(dd9b004b7ff3289fb7bae35130c0a5c0537266af "Merge tag 'trace-v6.19-rc1'")
from the master branch of the Linux repository and enabling KFENCE, I
encountered the following compilation errors.

8<------------------------------------------------------
  CC      arch/loongarch/kernel/asm-offsets.s
In file included from ./arch/loongarch/include/asm/pgtable.h:13,
                 from ./include/linux/pgtable.h:6,
                 from ./include/linux/mm.h:31,
                 from arch/loongarch/kernel/asm-offsets.c:11:
./include/linux/kfence.h:97:35: warning: 'struct kmem_cache' declared
inside parameter list will n
ot be visible outside of this definition or declaration
   97 | void kfence_shutdown_cache(struct kmem_cache *s);
      |                                   ^~~~~~~~~~
./include/linux/kfence.h:103:29: warning: 'struct kmem_cache' declared
inside parameter list will
not be visible outside of this definition or declaration
  103 | void *__kfence_alloc(struct kmem_cache *s, size_t size, gfp_t
flags);
      |                             ^~~~~~~~~~
./include/linux/kfence.h:121:50: warning: 'struct kmem_cache' declared
inside parameter list will
not be visible outside of this definition or declaration
  121 | static __always_inline void *kfence_alloc(struct kmem_cache *s,
size_t size, gfp_t flags)
      |                                                  ^~~~~~~~~~
./include/linux/kfence.h: In function 'kfence_alloc':
./include/linux/kfence.h:132:31: error: passing argument 1 of
'__kfence_alloc' from incompatible p
ointer type [-Wincompatible-pointer-types]
  132 |         return __kfence_alloc(s, size, flags);
      |                               ^
      |                               |
      |                               struct kmem_cache *
./include/linux/kfence.h:103:41: note: expected 'struct kmem_cache *'
but argument is of type 'str
uct kmem_cache *'
  103 | void *__kfence_alloc(struct kmem_cache *s, size_t size, gfp_t
flags);
      |                      ~~~~~~~~~~~~~~~~~~~^
------------------------------------------------------>8

So, this patch currently runs into compilation issues.  linyu probably
didn't have KFENCE enabled when compiling locally, which is why this
error was missed.  You can enable it as follows:

  Kernel hacking
    Memory Debugging
      [*] KFENCE: low-overhead sampling-based memory safety

Thanks,
Enze

<...>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/b=
2e84054-bf3b-4a1a-b946-bd024f341512%40kylinos.cn.
