Return-Path: <kasan-dev+bncBAABBCNVROQQMGQE4APGEBQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33f.google.com (mail-ot1-x33f.google.com [IPv6:2607:f8b0:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id 7476F6CBED0
	for <lists+kasan-dev@lfdr.de>; Tue, 28 Mar 2023 14:16:10 +0200 (CEST)
Received: by mail-ot1-x33f.google.com with SMTP id o3-20020a9d7183000000b00697e5dc461bsf1028495otj.7
        for <lists+kasan-dev@lfdr.de>; Tue, 28 Mar 2023 05:16:10 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1680005769; cv=pass;
        d=google.com; s=arc-20160816;
        b=w0H3tQGMhkGVnd4Y+VGZgzSm1EvlynmnfNfumVSWpy7RjF4Cq40KeSEG7WX/l1YQws
         PqDkc/grPIuvdr3Qe/fBBH8/OjWzkyYfeCB/h/32R4GpY9/LtY60BICPXhlRhoQFNzgI
         lU32nTwQjNowEy1YESfisF12GoPZzcxEswySpvSPEwAkTLPGh2AVuspkmSUX25HzaMPl
         yVQCNzf62j7dGD12+giMOws8Kr737jlgvAfoTRSMWgIQQVb0UuxHa/5aK9uklj35CWPU
         zmJDgi2TtPGbQoj7mhVpbtbp6KulIF2jK1B3THnpc/NGrwztFbjK79dIOEPNX3z0TjNz
         PlHw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :content-language:in-reply-to:mime-version:user-agent:date
         :message-id:from:references:cc:to:subject:sender:dkim-signature;
        bh=iPJOLyPwMcU2QgmrAui/uRT1rUH8wFKDQkrJf/cIj2w=;
        b=l/yrEn01oNa05vkhqOx6bkQUj4pHnZZ1KngTtb04JAUSIjPq1/utDGsXOWosiVFMLR
         r8FYlVyPGz0pUGFGvtpOoeh0fDx5ZkClzG2kaN6RVhX6hE1DlX5i3phe+YiMBfIkYiiC
         CwNbPq1F32Hc/09qWwlpy8y/LRz8M6KNVXSQ8HyyQjjXT9b7B03QOC/D0jRJC1UCtLfD
         W5rMJPxpbgVZVyhszXZxs0r68ij2KilZRi5GL4j64liZoych0HXGyJdbNN/sbX8MEgJR
         Ficwn0A/soQCnDqBCmDGDkQfG9yqfYhJxOwbbOWHo5PGN4npXlm41dhMHsOWWJHwX0y/
         4GfQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of zhangqing@loongson.cn designates 114.242.206.163 as permitted sender) smtp.mailfrom=zhangqing@loongson.cn
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112; t=1680005769;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:content-language
         :in-reply-to:mime-version:user-agent:date:message-id:from:references
         :cc:to:subject:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=iPJOLyPwMcU2QgmrAui/uRT1rUH8wFKDQkrJf/cIj2w=;
        b=hBKGhLUdZc5yW3211XpsrNRpVSA58/zEugpwxkoNBUtyv/adbxO2dOYpmfWFXE6ONH
         NOofm3CSP365W1KNqQPnhKQbwq+DGGS/PWfegdSG5FMZ16E9o71aGoGDj7G+LWW0USxp
         IwalYU6CphxtNBJNLkKbK3/j+fau7g2DqYPTpOHrU0f7qZyZn5edrR3FthKnS48NqszM
         /ZNoFbgVpCIFU9Q4VIIaCFok8gtPzwOaGQl4FbAjf+RmHvKiKdnBGjjKVx+PUKLasBx6
         vuiCXXM20qUseCfeSlmoq2h6uEKTIx0rgLcklOm50DnKs7IgEd1k8FIk5jlyrnA0BMgV
         sxdQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1680005769;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=iPJOLyPwMcU2QgmrAui/uRT1rUH8wFKDQkrJf/cIj2w=;
        b=pCroky3mvWnWqtcjgAQQMTYh7V8r2+vtpeAbo52BOviaFn2cLnUcNMlLWnXQAMEOP5
         BNuEylHRhqepMoZcYkbkjGi7yp11JijWQipwD6JpbNfrlxMCKs5PQ7tHeGc58JIOdp+m
         qNVzAZyNJJ9dkU8nefElrxj9g+yTM3/xTrwBgCOLudQdLkGOt+lwvRJXj3KBkv2DhQfF
         wnitngbafNcuA7+pop9lFvwPKQtEdNpw8F8gxY9lkl2SOIG20som8DBQhmRjP90iKknb
         UQrUd5g+ZHZ3v/xXoUZz9sw1v2ofci0d3a2THfgZ5J046GjB3ZZvtyQUhOqb2eARjoQ5
         fEXQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKUF55jE2nNzmUP5OyHC+ASnoBnuoxVi6p25U027pgS+eSGlA187
	xx7VGcSFMQihIE/UugrbKOQ=
X-Google-Smtp-Source: AK7set8IgIkbQPrjojPlfepU1t9Gi//X123t/GWlDcGwu3eMWMXt71LN/yiwFUoF6J3m1S2rveIV+A==
X-Received: by 2002:a4a:d119:0:b0:53b:4e0a:6714 with SMTP id k25-20020a4ad119000000b0053b4e0a6714mr5024109oor.0.1680005769348;
        Tue, 28 Mar 2023 05:16:09 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6871:589:b0:179:4735:e363 with SMTP id
 u9-20020a056871058900b001794735e363ls3679176oan.8.-pod-prod-gmail; Tue, 28
 Mar 2023 05:16:09 -0700 (PDT)
X-Received: by 2002:a05:6870:c1d2:b0:17f:238e:b20d with SMTP id i18-20020a056870c1d200b0017f238eb20dmr4918162oad.9.1680005768952;
        Tue, 28 Mar 2023 05:16:08 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1680005768; cv=none;
        d=google.com; s=arc-20160816;
        b=kp3x1F+mxHYmJte/KEbWlUhILoeD4dMxc5BVjtJh5xOC9PObmoahFARWAxL5WUegX9
         mhLjbGod9Js/iA8lqKpF2jhPCdCRV/FEfr/7lXws6Qugr5luPVy4JGgfLngah47IcjYV
         l7zNiMO4iYY+WH6di9Vo/ddqon9eRDCoQ4MW38yZmDsipGJ8Rq3/qwkooOBUNYKI4N15
         GVZKplhuHrd7cBPfrkC0dCRhSoDV42e7i/kol+JuN3ZyxK6D3RM1y6Rqt0HFcG2NGLKW
         oB2qKbYf52q8hHL8EAwDpF/SZurDLhELBZz3v81tuYgWzitk6fz9CINg6QsR2lX3lyoY
         GKCw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=t4nkZrvjBo+pqMwr4yUTaJ7nlD/nD4XCVCxtsOY7fyU=;
        b=vIJRKz3bGtCoSoXkZ3GpgMMcYZgGzcpD4z5oM0gs61e2ErSw4X0Lw/lQHwjQXLbkit
         EkFV702FjEXEX1L0DbYVaBBasbKvg/zTrtp5pxMahQyuUZ1xvz+5uOAM9gOqCnOWuLUZ
         511PpxaPpv5jXK/730EAoeRKXFkPyc1xvwvUuqaUjOZUR2PCOiJciwqa5u/C87s1kK5r
         bc+xWj8mrLTahqIxezNCDZXKrAHjpmJnuOF0ERzJdzrH7XYKWlAAZtMgZn7W9SobHMH2
         H9DaiQNLDrs05Ppspej3h7SHYGy3dzGPkgBKqN7iEBVKb74WDLJJ/hGZ7bKq0Hz2Sq2P
         1Yog==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of zhangqing@loongson.cn designates 114.242.206.163 as permitted sender) smtp.mailfrom=zhangqing@loongson.cn
Received: from loongson.cn (mail.loongson.cn. [114.242.206.163])
        by gmr-mx.google.com with ESMTP id bx12-20020a056830600c00b006986b65f551si4177551otb.1.2023.03.28.05.16.07
        for <kasan-dev@googlegroups.com>;
        Tue, 28 Mar 2023 05:16:08 -0700 (PDT)
Received-SPF: pass (google.com: domain of zhangqing@loongson.cn designates 114.242.206.163 as permitted sender) client-ip=114.242.206.163;
Received: from loongson.cn (unknown [113.200.148.30])
	by gateway (Coremail) with SMTP id _____8Bxfdpn2iJkchYTAA--.17964S3;
	Tue, 28 Mar 2023 20:15:35 +0800 (CST)
Received: from [10.130.0.102] (unknown [113.200.148.30])
	by localhost.localdomain (Coremail) with SMTP id AQAAf8Dxjb5l2iJkMWQPAA--.35747S3;
	Tue, 28 Mar 2023 20:15:35 +0800 (CST)
Subject: Re: [PATCH] LoongArch: Add kernel address sanitizer support
To: Xi Ruoyao <xry111@xry111.site>, Andrey Ryabinin <ryabinin.a.a@gmail.com>,
 Jonathan Corbet <corbet@lwn.net>, Huacai Chen <chenhuacai@kernel.org>,
 Andrew Morton <akpm@linux-foundation.org>
Cc: Alexander Potapenko <glider@google.com>,
 Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>,
 Vincenzo Frascino <vincenzo.frascino@arm.com>,
 WANG Xuerui <kernel@xen0n.name>, Jiaxun Yang <jiaxun.yang@flygoat.com>,
 kasan-dev@googlegroups.com, linux-doc@vger.kernel.org, linux-mm@kvack.org,
 loongarch@lists.linux.dev, linux-kernel@vger.kernel.org,
 linux-hardening@vger.kernel.org
References: <20230328111714.2056-1-zhangqing@loongson.cn>
 <9817aaa043e9f0ed964bd523773447bd64f6e2c0.camel@xry111.site>
From: Qing Zhang <zhangqing@loongson.cn>
Message-ID: <1c231587-3b70-22ab-d554-ebe3de407909@loongson.cn>
Date: Tue, 28 Mar 2023 20:15:33 +0800
User-Agent: Mozilla/5.0 (X11; Linux mips64; rv:68.0) Gecko/20100101
 Thunderbird/68.7.0
MIME-Version: 1.0
In-Reply-To: <9817aaa043e9f0ed964bd523773447bd64f6e2c0.camel@xry111.site>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Language: en-US
Content-Transfer-Encoding: quoted-printable
X-CM-TRANSID: AQAAf8Dxjb5l2iJkMWQPAA--.35747S3
X-CM-SenderInfo: x2kd0wptlqwqxorr0wxvrqhubq/
X-Coremail-Antispam: 1Uk129KBjvJXoW7ArWDtw4rur15Gr1DuF1Dtrb_yoW8ZF4kpr
	ykJF15JrWrAr18Jr1qqw1DZryUXw1qq3W5Gr1DJFyrZw17Aryjgr4DXr1qgr1Dtr40gr15
	Jr1UtF12vw1UJr7anT9S1TB71UUUUUDqnTZGkaVYY2UrUUUUj1kv1TuYvTs0mT0YCTnIWj
	qI5I8CrVACY4xI64kE6c02F40Ex7xfYxn0WfASr-VFAUDa7-sFnT9fnUUIcSsGvfJTRUUU
	bakYFVCjjxCrM7AC8VAFwI0_Jr0_Gr1l1xkIjI8I6I8E6xAIw20EY4v20xvaj40_Wr0E3s
	1l1IIY67AEw4v_Jrv_JF1l8cAvFVAK0II2c7xJM28CjxkF64kEwVA0rcxSw2x7M28EF7xv
	wVC0I7IYx2IY67AKxVW8JVW5JwA2z4x0Y4vE2Ix0cI8IcVCY1x0267AKxVW8JVWxJwA2z4
	x0Y4vEx4A2jsIE14v26r4UJVWxJr1l84ACjcxK6I8E87Iv6xkF7I0E14v26F4UJVW0owAS
	0I0E0xvYzxvE52x082IY62kv0487Mc804VCY07AIYIkI8VC2zVCFFI0UMc02F40EFcxC0V
	AKzVAqx4xG6I80ewAv7VC0I7IYx2IY67AKxVWUXVWUAwAv7VC2z280aVAFwI0_Gr0_Cr1l
	Ox8S6xCaFVCjc4AY6r1j6r4UM4x0Y48IcVAKI48JMxk0xIA0c2IEe2xFo4CEbIxvr21l42
	xK82IYc2Ij64vIr41l4I8I3I0E4IkC6x0Yz7v_Jr0_Gr1l4IxYO2xFxVAFwI0_GFv_Wryl
	x2IqxVAqx4xG67AKxVWUJVWUGwC20s026x8GjcxK67AKxVWUGVWUWwC2zVAF1VAY17CE14
	v26r4a6rW5MIIYrxkI7VAKI48JMIIF0xvE2Ix0cI8IcVAFwI0_Jr0_JF4lIxAIcVC0I7IY
	x2IY6xkF7I0E14v26r1j6r4UMIIF0xvE42xK8VAvwI8IcIk0rVWUJVWUCwCI42IY6I8E87
	Iv67AKxVW8JVWxJwCI42IY6I8E87Iv6xkF7I0E14v26r4j6r4UJbIYCTnIWIevJa73UjIF
	yTuYvjxUcVc_UUUUU
X-Original-Sender: zhangqing@loongson.cn
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of zhangqing@loongson.cn designates 114.242.206.163 as
 permitted sender) smtp.mailfrom=zhangqing@loongson.cn
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

Hi, Ruoyao

On 2023/3/28 =E4=B8=8B=E5=8D=887:39, Xi Ruoyao wrote:
> On Tue, 2023-03-28 at 19:17 +0800, Qing Zhang wrote:
>=20
> /* snip */
>=20
>=20
>> -void * __init relocate_kernel(void)
>> +unsigned long __init relocate_kernel(void)
>=20
> Why we must modify relocate_kernel for KASAN?

When the CONFIG_RANDOMIZE_BASE is enabled, the kernel will be updated to=20
a random new address.
Kasan needs to call kasan_early_init before start_kernel.
There are two situations:
1> After enabling CONFIG_RELOCATABLE, call kasan_early_init.
2> After CONFIG_RELOCATABLE is not enabled, call kasan_early_init.

In order to prevent code redundancy and semantic problems caused by=20
calling kasan_early_init (before jr a0) at the old PC.

Thanks,
-Qing
>=20
>>  =C2=A0{
>>  =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0unsigned long kernel_le=
ngth;
>>  =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0unsigned long random_of=
fset =3D 0;
>>  =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0void *location_new =3D =
_text; /* Default to original kernel start */
>> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0void *kernel_entry =3D start_=
kernel; /* Default to original kernel entry point */
>>  =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0char *cmdline =3D early=
_ioremap(fw_arg1, COMMAND_LINE_SIZE); /* Boot command line is passed in fw_=
arg1 */
>>  =20
>>  =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0strscpy(boot_command_li=
ne, cmdline, COMMAND_LINE_SIZE);
>> @@ -190,9 +189,6 @@ void * __init relocate_kernel(void)
>>  =20
>>  =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0reloc_offset +=3D random_offset;
>>  =20
>> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0/* Return the new kernel's entry point */
>> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0kernel_entry =3D RELOCATED_KASLR(start_kernel);
>> -
>>  =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0/* The current thread is now within the relocate=
d kernel */
>>  =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0__current_thread_info =3D RELOCATED_KASLR(__curr=
ent_thread_info);
>>  =20
>> @@ -204,7 +200,7 @@ void * __init relocate_kernel(void)
>>  =20
>>  =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0relocate_absolute(rando=
m_offset);
>>  =20
>> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return kernel_entry;
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return random_offset;
>=20

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/1c231587-3b70-22ab-d554-ebe3de407909%40loongson.cn.
