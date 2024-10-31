Return-Path: <kasan-dev+bncBAABBHNRRO4QMGQE4VSXC4A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103f.google.com (mail-pj1-x103f.google.com [IPv6:2607:f8b0:4864:20::103f])
	by mail.lfdr.de (Postfix) with ESMTPS id 445B59B717A
	for <lists+kasan-dev@lfdr.de>; Thu, 31 Oct 2024 02:08:47 +0100 (CET)
Received: by mail-pj1-x103f.google.com with SMTP id 98e67ed59e1d1-2e3984f50c3sf512219a91.1
        for <lists+kasan-dev@lfdr.de>; Wed, 30 Oct 2024 18:08:47 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1730336926; cv=pass;
        d=google.com; s=arc-20240605;
        b=JFv9VhkvrXw0sHgTm4e9v0ZWuGh5pJASXTwggIu854S6iyPQ3DfmqcSODqeZRKdArK
         IZVzbumlmANmA8Y/0OpXbVwML/vmBdm92fgPcmciVMn4VF7w0i37uwtUAhflj7nmN2bx
         cDsW3KZHvucJQUnUF/CK9f6baY4kkJG2zSG+ayKopJw+yDALO/D5k9hoaA5LaLyTu717
         z7kdY9naoE60YD3OlHQsbFCXOumxLqSWenndH6LfpSoWQRXGjCzkVWSjAXUJ13yQsdSG
         1wdioP4JsgnSnUNt5yQXZ7QG25iqg0MDK0eI0JKev8Km35Hg3R9b6au2dhI/1nUlJE6D
         9upg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :content-language:in-reply-to:mime-version:user-agent:date
         :message-id:from:references:cc:to:subject:sender:dkim-signature;
        bh=t6TUvayOgDdj5GsFHQyMbyAnuhWx6iL20wy74IiDKow=;
        fh=6SsxxS5ma9mPHDQe+eqnWWvSIKiCl1Cf0wiR+jl2xn8=;
        b=B4MtFEzbgUTQyT44q5wENTeafF3BkcmC5f2cduQyrSR0B8SqdI55WdEYzFa51hC0Aq
         3hTRsmH++iK2X/EiHQ/rXbr+O2eyzNSqgi2YWsSmTj09xO/0RCqa2s5Sok6HHH3zPrXx
         BCMYbiHG7+9IEckQ78twiSvKSRQnNX8Wj1ZjkrEgcZkC6IJXL5MD9QZOxXnLahEkpqLb
         480pk1D76BlQgGtPLEkHbvLdSZhdAKa+YxFpNBek/sGIdFhgzb/0wSs/C/eCy0OuCy9/
         Rjp7KfOv3bnWlmnV0lDpGtkDbRCz1+g+WOJ6VZvf/xR1e/NCqUuTt1an4T8ZOXjKdz3R
         OZ+A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of maobibo@loongson.cn designates 114.242.206.163 as permitted sender) smtp.mailfrom=maobibo@loongson.cn
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1730336926; x=1730941726; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:content-language
         :in-reply-to:mime-version:user-agent:date:message-id:from:references
         :cc:to:subject:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=t6TUvayOgDdj5GsFHQyMbyAnuhWx6iL20wy74IiDKow=;
        b=pkXsl9A11xek4fGXckXfJ4VbY/BmIvBY5C5PXzZp1CVDdRRdXAixubvV5eKAwbLbIJ
         /HoLQ0gobuRhpsqf16fJQFSHuswT+//cI/V+TA85nswNUPFuX4FRlfQM2f3mZp2Fq900
         oHDEOwOeASoXK/b7vQyM424R/A1nzUB65P3AHTPWvbC0cU5zRNEXRfVHQSIey7ei5Mkd
         E4E+QJrZwd9BvfTVjFpjyaPQCDq6SYoaMmNLVYfJjSiTLHeXafiO29ylUtST7S8kuB05
         GvkqTDofwxdQuEUXPRJj8TMv+uNIOS6o7JN3XXQ72ZSsB702hmDeg6qvWn3B0/dyx3KI
         iQWQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1730336926; x=1730941726;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=t6TUvayOgDdj5GsFHQyMbyAnuhWx6iL20wy74IiDKow=;
        b=mdXj7qGEnGHrFCjeIa1LXrsI5ARB4QHSvaUQeordwz91ZVCNQ66yX9FpMko1lUTAn+
         7ffgmYxSPiajcOhjk6yr0STkGVcBNlenL3cTjbRRrKwEQ6aEEblquD9uQM4gpIbDxnRV
         V0CABTUsELFGF/vN83isRS5dFnlzAm/I5enHB1SLALuGWdXnpl1YqE+x7YMyVmLXPVly
         POWzlKC0Kzh7wJRHeA67ukSDEIUJz0BvX+lDo2gqcjQi+XUMD4pw64s9l+qi3oslfK8N
         hY0liCX7wPslFAn1tIaPj6807YkKJMNw59IE10PAlRalokVUbb0wvR10IkQqtRXA2uuO
         O0rQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCX1bZnXzNWZGOA+jewBPQFMz99/+L4wOvpuF6y6VGUTwulpvHFYMxGgGMZZz49xmp9ldxnZww==@lfdr.de
X-Gm-Message-State: AOJu0Yz894n+pfp08qtwShEG8EEDwUih0Rj4JgfcCQxoEX+YuczBUkSt
	/u1nO3bPJvalhp5QCIAMdg2PCKuEREOPjwbeq3aMfm9PIBCxxmxy
X-Google-Smtp-Source: AGHT+IGZVG8nxobpxSRE9OIvEFiX5n26gWIPOmnByh3yildIh1FS+huN0btyT5B0N7B+kpCeg1QEDw==
X-Received: by 2002:a17:90a:9e3:b0:2e2:b6c2:2ae with SMTP id 98e67ed59e1d1-2e8f11d5677mr19426629a91.36.1730336925711;
        Wed, 30 Oct 2024 18:08:45 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:4b09:b0:2cb:5bad:6b1a with SMTP id
 98e67ed59e1d1-2e93abf5832ls432792a91.0.-pod-prod-05-us; Wed, 30 Oct 2024
 18:08:44 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXZwKuf5V1sYmh1ssFhOCYUF0iQOqMZjXSU5GfsopyxNlSMdLI4XzXjdy5PFjYsSVbqUAjqM7czKSA=@googlegroups.com
X-Received: by 2002:a17:90a:6b0f:b0:2e2:de27:db08 with SMTP id 98e67ed59e1d1-2e8f1082165mr20001550a91.23.1730336924434;
        Wed, 30 Oct 2024 18:08:44 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1730336924; cv=none;
        d=google.com; s=arc-20240605;
        b=bzyeREFZmjuyWLJrm00R0qYrWKcNyctENAW7/5hISGZPdvhRt6ugYPl3qpM0BEYiSA
         OVjhqAWP9XNLfshVXt8HtED7t0WHIQJd8+UPWcZbGKph98FIAaPboBVQBfN4BNEu0CKN
         kYF3h+KUTqD5t4UzsPDR61AmrQT7FJ3J6yt4vE6RTSbZc4LZNtcO5McKjt9CtnlXz35J
         342ciKuF5WmamGUgj5ZeL/gxzxMGf5bm2pJoJVXY7CNePIWdN57dDaL+G7UqPo8WrXxG
         5MBYTdgIPWW3Lvpdd15gi+qh7d0dCUrTU4bvFujqu/zUCNT8Wrj//3AkheALJK5MckZz
         +Y1Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=U2satVl/EjUt6b8eaeOcoyCBMnxPkPLjVdch8TDZcEA=;
        fh=5xgLpFcXZ4hTOkdNAXGqgT6NYQAC4Yqjwqix8eJpci8=;
        b=cjYZsCJFbIX3G3a+24qB0reWu6P3yONt2yoLuywmpTsqKQkZgoSQbm6dvaur1U0+8K
         EESs2z+mm3zf9FTdKQNLBd7/NHzLv4W8n6hHstoqeQcwY7DJlzUUkTi9vQYjBoFJ3pFD
         CnSdxSe+5BW3AsPVlfDBB698Gr6yWSm3XX0OuDQ9hVVHFQeVfDlBZTyDQ1ZSiGDiCUy9
         ahqB1QLEfUN9bh4QU3p3wCXG76wE0NfwyfkaEMmYBvqlccalVcVCgmKbkUM6l6xZ5etw
         ziKehOlwD5YKWT3hqAJvtTWzCeEmlDKfO546T8XLOJpcnMIkZRItkIfdEH7eUGvlqOfG
         vCeQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of maobibo@loongson.cn designates 114.242.206.163 as permitted sender) smtp.mailfrom=maobibo@loongson.cn
Received: from mail.loongson.cn (mail.loongson.cn. [114.242.206.163])
        by gmr-mx.google.com with ESMTP id 98e67ed59e1d1-2e9201995fbsi424189a91.0.2024.10.30.18.08.43
        for <kasan-dev@googlegroups.com>;
        Wed, 30 Oct 2024 18:08:44 -0700 (PDT)
Received-SPF: pass (google.com: domain of maobibo@loongson.cn designates 114.242.206.163 as permitted sender) client-ip=114.242.206.163;
Received: from loongson.cn (unknown [10.20.42.62])
	by gateway (Coremail) with SMTP id _____8DxDeOZ2CJn2t4fAA--.65262S3;
	Thu, 31 Oct 2024 09:08:41 +0800 (CST)
Received: from [10.20.42.62] (unknown [10.20.42.62])
	by front1 (Coremail) with SMTP id qMiowMAxreCX2CJn3b8rAA--.6898S3;
	Thu, 31 Oct 2024 09:08:41 +0800 (CST)
Subject: Re: [PATCH v2] mm: define general function pXd_init()
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Huacai Chen <chenhuacai@kernel.org>,
 Thomas Bogendoerfer <tsbogend@alpha.franken.de>,
 Andrey Ryabinin <ryabinin.a.a@gmail.com>, loongarch@lists.linux.dev,
 linux-kernel@vger.kernel.org, linux-mips@vger.kernel.org,
 linux-mm@kvack.org, kasan-dev@googlegroups.com,
 Alexander Potapenko <glider@google.com>,
 Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>,
 Vincenzo Frascino <vincenzo.frascino@arm.com>,
 WANG Xuerui <kernel@xen0n.name>
References: <20241030063905.2434824-1-maobibo@loongson.cn>
 <20241030164123.ff63a1c0e7666ad1a4f8944e@linux-foundation.org>
From: maobibo <maobibo@loongson.cn>
Message-ID: <836c4d86-3b93-06fc-8ac1-6f636a244753@loongson.cn>
Date: Thu, 31 Oct 2024 09:08:13 +0800
User-Agent: Mozilla/5.0 (X11; Linux loongarch64; rv:68.0) Gecko/20100101
 Thunderbird/68.7.0
MIME-Version: 1.0
In-Reply-To: <20241030164123.ff63a1c0e7666ad1a4f8944e@linux-foundation.org>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Language: en-US
Content-Transfer-Encoding: quoted-printable
X-CM-TRANSID: qMiowMAxreCX2CJn3b8rAA--.6898S3
X-CM-SenderInfo: xpdruxter6z05rqj20fqof0/
X-Coremail-Antispam: 1Uk129KBj9xXoWrKry7ZrykuF13CF18Cry5KFX_yoWfXFg_W3
	Z7Zws5u3ykGay2gFWqkry5Cr4UGayrJF4vyw1UWr92k3s3tr45Jws0gFyfXrs09Fs2vr9x
	uayvvan8Zrn8WosvyTuYvTs0mTUanT9S1TB71UUUUUDqnTZGkaVYY2UrUUUUj1kv1TuYvT
	s0mT0YCTnIWjqI5I8CrVACY4xI64kE6c02F40Ex7xfYxn0WfASr-VFAUDa7-sFnT9fnUUI
	cSsGvfJTRUUUbxxYFVCjjxCrM7AC8VAFwI0_Jr0_Gr1l1xkIjI8I6I8E6xAIw20EY4v20x
	vaj40_Wr0E3s1l1IIY67AEw4v_Jrv_JF1l8cAvFVAK0II2c7xJM28CjxkF64kEwVA0rcxS
	w2x7M28EF7xvwVC0I7IYx2IY67AKxVWUCVW8JwA2z4x0Y4vE2Ix0cI8IcVCY1x0267AKxV
	W8JVWxJwA2z4x0Y4vEx4A2jsIE14v26r4j6F4UM28EF7xvwVC2z280aVCY1x0267AKxVW8
	JVW8Jr1le2I262IYc4CY6c8Ij28IcVAaY2xG8wAqjxCEc2xF0cIa020Ex4CE44I27wAqx4
	xG64xvF2IEw4CE5I8CrVC2j2WlYx0E2Ix0cI8IcVAFwI0_Jrv_JF1lYx0Ex4A2jsIE14v2
	6r1j6r4UMcvjeVCFs4IE7xkEbVWUJVW8JwACjcxG0xvEwIxGrwCYjI0SjxkI62AI1cAE67
	vIY487MxAIw28IcxkI7VAKI48JMxC20s026xCaFVCjc4AY6r1j6r4UMI8I3I0E5I8CrVAF
	wI0_Jr0_Jr4lx2IqxVCjr7xvwVAFwI0_JrI_JrWlx4CE17CEb7AF67AKxVWUtVW8ZwCIc4
	0Y0x0EwIxGrwCI42IY6xIIjxv20xvE14v26r1j6r1xMIIF0xvE2Ix0cI8IcVCY1x0267AK
	xVWUJVW8JwCI42IY6xAIw20EY4v20xvaj40_Jr0_JF4lIxAIcVC2z280aVAFwI0_Jr0_Gr
	1lIxAIcVC2z280aVCY1x0267AKxVWUJVW8JbIYCTnIWIevJa73UjIFyTuYvjxU7_MaUUUU
	U
X-Original-Sender: maobibo@loongson.cn
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of maobibo@loongson.cn designates 114.242.206.163 as
 permitted sender) smtp.mailfrom=maobibo@loongson.cn
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



On 2024/10/31 =E4=B8=8A=E5=8D=887:41, Andrew Morton wrote:
> On Wed, 30 Oct 2024 14:39:05 +0800 Bibo Mao <maobibo@loongson.cn> wrote:
>=20
>> --- a/arch/loongarch/include/asm/pgtable.h
>> +++ b/arch/loongarch/include/asm/pgtable.h
>> @@ -267,8 +267,11 @@ extern void set_pmd_at(struct mm_struct *mm, unsign=
ed long addr, pmd_t *pmdp, pm
>>    * Initialize a new pgd / pud / pmd table with invalid pointers.
>>    */
>>   extern void pgd_init(void *addr);
>> +#define pud_init pud_init
>>   extern void pud_init(void *addr);
>> +#define pmd_init pmd_init
>>   extern void pmd_init(void *addr);
>> +#define kernel_pte_init kernel_pte_init
>>   extern void kernel_pte_init(void *addr);
>=20
> Nitlet: don't we usually put the #define *after* the definition?
>=20
> void foo(void);
> #define foo() foo()
yes, it should be so. Will modify it in next version.

Regards
Bibo Mao
>=20
> ?
>=20
>=20

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/8=
36c4d86-3b93-06fc-8ac1-6f636a244753%40loongson.cn.
