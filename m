Return-Path: <kasan-dev+bncBAABBO5YR2QQMGQEMJZHORI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3f.google.com (mail-oa1-x3f.google.com [IPv6:2001:4860:4864:20::3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 28E906CCFBE
	for <lists+kasan-dev@lfdr.de>; Wed, 29 Mar 2023 04:02:37 +0200 (CEST)
Received: by mail-oa1-x3f.google.com with SMTP id 586e51a60fabf-17714741d9dsf7503434fac.4
        for <lists+kasan-dev@lfdr.de>; Tue, 28 Mar 2023 19:02:37 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1680055355; cv=pass;
        d=google.com; s=arc-20160816;
        b=usueM29TAJTr6PBbAZcBoDNOXz0NqRaxrxq7u1hipQ061EVb2mCHPAlMs9Bk48/2pr
         lrCkJHdRTojLuyigVIKsuPbVuw0f9o7noxQkJTsJz1ZbNU1k5i+lxK/jtp9BJxLWZNHK
         4E5EiJ6abyxU/ii78aSLqw68ZqoeEG6sCt37mHcPZzWNjfY8ld+qFf4dzJcl6eoQTmcj
         K0yGhlfHDlkS7Q+W+eRfUmX+aDfiA5CFMUM1yQUdUaZ/W5K/xaNIzk/LdRW0sXE/D73t
         anUyolUsjAsCYvlTQLLd9gHBzK0aMKr5Li5TLqKAU9KhaSud9ILP8SzaJ8S/+G7tnZsH
         ZsAw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :content-language:in-reply-to:mime-version:user-agent:date
         :message-id:from:references:cc:to:subject:sender:dkim-signature;
        bh=+xj8IvKewCqbJSA/oD4ywnWsn9fhQh/DHjukxANA6vs=;
        b=GzJd+h/tnnL6nKLUddpFoPf2oBftB4joPYjCToibe+oEX4PusV6xebaBlzrY85G5z0
         Q3cIqsTjGcySKr6t4FApU6luV6VXXFtYoYhbIZfzAYD3GFX0HWssnZ56fPHXB4O4xnZ5
         P0ESIpyniYQYjw5QqsuheJSFOhV0jyUbHXJUryRUBHDtvL2c9fmBz1kryNbD8tFHsOId
         HWL2ht5jggidxo+rrCN8vY5qv1NQnE/PSxYSMMPFnDynAvv9oyvpLhBrKTmUSx9iPJzI
         jNnCrAMiWlvgNQxLd0rtDc/fEWYTsPiuQMOonaedW6Sp+mnfRBK1dMhQV7kx/zc+FOoH
         hiHA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of zhangqing@loongson.cn designates 114.242.206.163 as permitted sender) smtp.mailfrom=zhangqing@loongson.cn
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112; t=1680055355;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:content-language
         :in-reply-to:mime-version:user-agent:date:message-id:from:references
         :cc:to:subject:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=+xj8IvKewCqbJSA/oD4ywnWsn9fhQh/DHjukxANA6vs=;
        b=YEiV+8g70saV0UyaLwPuPCCfyxyisGpYOzJtysPYHEBKfgyzAq0ACmaa6gakUHGT3+
         YDpbGOPIZcHefr2oGHYbiIFlQ6jcFB/vTELFs+z1bb71XC44O4ywWzy6KuyjlGZgdoDt
         1Ll9G/ScBoIPhzTCOMBIOzkB+4krEzU0hWhlUZ+cG9BPdtpyQx7VmElUZX2TGi51btd5
         WorD0HIstq9tAPWRJDlWqoTRwhimPie/Rqqka5re7evPZ4LfhXHSh4dTR0BWZ0oaCaqr
         H9LhXBqV/rqUMpTnmGB6vo+f2fOUKUXvmlYp9D/2oEctUgjDvm5EdmRCNG+84GSwAotJ
         NWtQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1680055355;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=+xj8IvKewCqbJSA/oD4ywnWsn9fhQh/DHjukxANA6vs=;
        b=axPghi5ktK6koCipbz8/KL8NE/ihwc0mE1HW1eAYwg6S60ZfQ3mlNQR9v0qaP89AyX
         eTNzG2w+KluKdrhTaqjz13ASBx/SkM/YJ2c+ikHpfNrVd+jJFd05BIGExWFiL87PBpep
         rlV6Zsrc2erNvsxsHwitOeMwAzkIo/xNGWhjUEFfQb3YJV2fsJiwOX6kAW/S/CuacTP2
         VnUEIpb3Lorq+LXyVLl6LHn6xLE41WQiILayi975AAtIqQ1I2onNVPuirbO6mitAGs5X
         jJcERU9lOiIOUN8qTtNc7jE7oWWTMQ1GaP+WjL5jpeYSTY4fm25tc2sCwB3KzLclIIjN
         KiMg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AAQBX9fihuzr9dtBTAptamgaibgMbV5JcYKDmp9dzBkE4cJxBquRi89v
	BiGk4q+iAq8yybnibG0OteU=
X-Google-Smtp-Source: AK7set/u1FaMmoqWekrHgBy7XXlDTd7XoZFljZNNg/lED9A8tILGFIz+IBqeZnFyPrJfgoc+KcnQaw==
X-Received: by 2002:a05:6870:f901:b0:17a:dcce:86bf with SMTP id ao1-20020a056870f90100b0017adcce86bfmr6534410oac.8.1680055355649;
        Tue, 28 Mar 2023 19:02:35 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:d108:0:b0:53b:545d:9cb2 with SMTP id k8-20020a4ad108000000b0053b545d9cb2ls579650oor.6.-pod-prod-gmail;
 Tue, 28 Mar 2023 19:02:35 -0700 (PDT)
X-Received: by 2002:a4a:2c86:0:b0:53b:5510:9594 with SMTP id o128-20020a4a2c86000000b0053b55109594mr9425930ooo.1.1680055355104;
        Tue, 28 Mar 2023 19:02:35 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1680055355; cv=none;
        d=google.com; s=arc-20160816;
        b=JYMyMu36dibGQ63ykL9Mte5tI0SDnz//yIWlREJDk5vkkFSjGm44B2ptIgT6UnnrQ2
         t0amff0oFkTxpfSeJVg5oszY2Y8n9Uy/aOqrNhygrWEhpY4lyOuQsfU/jEsDLIOxqEck
         Gt+fb6r236fjFrMNHLX4XS+i9mEc/CqmPpzkrstQAZENX1bsz+9OrhtBOIJEoMaCSUHn
         MmBrcSOOk5Yj6xchcWGWo4TAqlQqarPyWYEY2Fm1KBL0dKhbq8nrHUGybbee9YVhznET
         sBEJiPSYiqztlyaqsqJFEkPDuoeQB3YE0Q57LUIiAIXXdBVjCt7+e8SC2X8G6kajpdK8
         MrbQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=n0kv0SLrudmaBn80mc0pCccSKOLtnDG3O0At1e+cebk=;
        b=Xta4JKdG78XOQ5Nq7TmTtEmg/T7DhxROlx79ygHQUTPKUN5odHT2Vp5F13+UYk76Xi
         iY0YBIsyghFlIHgnufIM2dRPB5vIvd82fRUbAEg0WPcOlMTa0eRU6bYYORQqqa3JOb/7
         6eIlAX8IafCdHF2iVfVjozGAUj4Smbtk3sHW56GaNxS+r7Re7GCQqagl5Jv3hPr+8zX6
         57dIH2tWztoHpNlIfjkwL9reGC9LOsdLONV8wb1EVs2VGKl2LAYArQzmMi5ecwsM0vvz
         lKkU727t+xxbhJutmbPOlnyyi0mIVpqoF5+TJCNzTWj8UxrwNmW01+oiR26OqiP41TaB
         DjKA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of zhangqing@loongson.cn designates 114.242.206.163 as permitted sender) smtp.mailfrom=zhangqing@loongson.cn
Received: from loongson.cn (mail.loongson.cn. [114.242.206.163])
        by gmr-mx.google.com with ESMTP id h7-20020a4ab447000000b00525240a102asi768335ooo.1.2023.03.28.19.02.34
        for <kasan-dev@googlegroups.com>;
        Tue, 28 Mar 2023 19:02:35 -0700 (PDT)
Received-SPF: pass (google.com: domain of zhangqing@loongson.cn designates 114.242.206.163 as permitted sender) client-ip=114.242.206.163;
Received: from loongson.cn (unknown [113.200.148.30])
	by gateway (Coremail) with SMTP id _____8CxhdgZnCNkjnsTAA--.30250S3;
	Wed, 29 Mar 2023 10:02:01 +0800 (CST)
Received: from [10.130.0.102] (unknown [113.200.148.30])
	by localhost.localdomain (Coremail) with SMTP id AQAAf8CxPL4XnCNkIQQQAA--.12984S3;
	Wed, 29 Mar 2023 10:02:01 +0800 (CST)
Subject: Re: [PATCH] LoongArch: Add kernel address sanitizer support
To: Huacai Chen <chenhuacai@kernel.org>
Cc: Xi Ruoyao <xry111@xry111.site>, Andrey Ryabinin <ryabinin.a.a@gmail.com>,
 Jonathan Corbet <corbet@lwn.net>, Andrew Morton <akpm@linux-foundation.org>,
 Alexander Potapenko <glider@google.com>,
 Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>,
 Vincenzo Frascino <vincenzo.frascino@arm.com>,
 WANG Xuerui <kernel@xen0n.name>, Jiaxun Yang <jiaxun.yang@flygoat.com>,
 kasan-dev@googlegroups.com, linux-doc@vger.kernel.org, linux-mm@kvack.org,
 loongarch@lists.linux.dev, linux-kernel@vger.kernel.org,
 linux-hardening@vger.kernel.org
References: <20230328111714.2056-1-zhangqing@loongson.cn>
 <9817aaa043e9f0ed964bd523773447bd64f6e2c0.camel@xry111.site>
 <1c231587-3b70-22ab-d554-ebe3de407909@loongson.cn>
 <CAAhV-H5APsBxC8nNa81t3HXum1EU1hOj4S6UC7xLHD7_BCJd7g@mail.gmail.com>
From: Qing Zhang <zhangqing@loongson.cn>
Message-ID: <9a6f11a3-d01c-e0c9-a4f3-47db25ce02f3@loongson.cn>
Date: Wed, 29 Mar 2023 10:01:59 +0800
User-Agent: Mozilla/5.0 (X11; Linux mips64; rv:68.0) Gecko/20100101
 Thunderbird/68.7.0
MIME-Version: 1.0
In-Reply-To: <CAAhV-H5APsBxC8nNa81t3HXum1EU1hOj4S6UC7xLHD7_BCJd7g@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Language: en-US
Content-Transfer-Encoding: quoted-printable
X-CM-TRANSID: AQAAf8CxPL4XnCNkIQQQAA--.12984S3
X-CM-SenderInfo: x2kd0wptlqwqxorr0wxvrqhubq/
X-Coremail-Antispam: 1Uk129KBjvJXoW7uF43ur1UArykKF4xtw43Wrg_yoW8tw4Upr
	y8GF4rtw48Jr40vrs2q34Duryjv3Z2qw1agr4DK34rZ3sF9F98Kr4DWr13uF929r1j9F4Y
	vFWrtFWa934UJaDanT9S1TB71UUUUUDqnTZGkaVYY2UrUUUUj1kv1TuYvTs0mT0YCTnIWj
	qI5I8CrVACY4xI64kE6c02F40Ex7xfYxn0WfASr-VFAUDa7-sFnT9fnUUIcSsGvfJTRUUU
	bxkYFVCjjxCrM7AC8VAFwI0_Jr0_Gr1l1xkIjI8I6I8E6xAIw20EY4v20xvaj40_Wr0E3s
	1l1IIY67AEw4v_Jrv_JF1l8cAvFVAK0II2c7xJM28CjxkF64kEwVA0rcxSw2x7M28EF7xv
	wVC0I7IYx2IY67AKxVWUCVW8JwA2z4x0Y4vE2Ix0cI8IcVCY1x0267AKxVW8JVWxJwA2z4
	x0Y4vEx4A2jsIE14v26F4j6r4UJwA2z4x0Y4vEx4A2jsIEc7CjxVAFwI0_Gr0_Gr1UM2AI
	xVAIcxkEcVAq07x20xvEncxIr21l57IF6xkI12xvs2x26I8E6xACxx1l5I8CrVACY4xI64
	kE6c02F40Ex7xfMcIj6xIIjxv20xvE14v26r1Y6r17McIj6I8E87Iv67AKxVWUJVW8JwAm
	72CE4IkC6x0Yz7v_Jr0_Gr1lF7xvr2IY64vIr41lc7I2V7IY0VAS07AlzVAYIcxG8wCF04
	k20xvY0x0EwIxGrwCFx2IqxVCFs4IE7xkEbVWUJVW8JwC20s026c02F40E14v26r1j6r18
	MI8I3I0E7480Y4vE14v26r106r1rMI8E67AF67kF1VAFwI0_GFv_WrylIxkGc2Ij64vIr4
	1lIxAIcVC0I7IYx2IY67AKxVWUJVWUCwCI42IY6xIIjxv20xvEc7CjxVAFwI0_Jr0_Gr1l
	IxAIcVCF04k26cxKx2IYs7xG6r1j6r1xMIIF0xvEx4A2jsIE14v26r1j6r4UMIIF0xvEx4
	A2jsIEc7CjxVAFwI0_Jr0_GrUvcSsGvfC2KfnxnUUI43ZEXa7IU8zwZ7UUUUU==
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

Hi, Huacai

On 2023/3/29 =E4=B8=8A=E5=8D=888:22, Huacai Chen wrote:
> On Tue, Mar 28, 2023 at 8:15=E2=80=AFPM Qing Zhang <zhangqing@loongson.cn=
> wrote:
>>
>> Hi, Ruoyao
>>
>> On 2023/3/28 =E4=B8=8B=E5=8D=887:39, Xi Ruoyao wrote:
>>> On Tue, 2023-03-28 at 19:17 +0800, Qing Zhang wrote:
>>>
>>> /* snip */
>>>
>>>
>>>> -void * __init relocate_kernel(void)
>>>> +unsigned long __init relocate_kernel(void)
>>>
>>> Why we must modify relocate_kernel for KASAN?
>>
>> When the CONFIG_RANDOMIZE_BASE is enabled, the kernel will be updated to
>> a random new address.
>> Kasan needs to call kasan_early_init before start_kernel.
>> There are two situations:
>> 1> After enabling CONFIG_RELOCATABLE, call kasan_early_init.
>> 2> After CONFIG_RELOCATABLE is not enabled, call kasan_early_init.
>>
>> In order to prevent code redundancy and semantic problems caused by
>> calling kasan_early_init (before jr a0) at the old PC.
> In my opinion, you can call kasan_early_init before relocate_kernel in
> head.S, then no redundancy.
>=20
It has no effect now, but kasan_early_init generally maps everything to
a single page of zeroes in kasan area, if placed
Before relocate_kernel, when the kernel was relocated, I worried that
there were changes other than the memory layout.

Thanks,
- Qing
> Huacai
>>
>> Thanks,
>> -Qing
>>>
>>>>    {
>>>>           unsigned long kernel_length;
>>>>           unsigned long random_offset =3D 0;
>>>>           void *location_new =3D _text; /* Default to original kernel =
start */
>>>> -       void *kernel_entry =3D start_kernel; /* Default to original ke=
rnel entry point */
>>>>           char *cmdline =3D early_ioremap(fw_arg1, COMMAND_LINE_SIZE);=
 /* Boot command line is passed in fw_arg1 */
>>>>
>>>>           strscpy(boot_command_line, cmdline, COMMAND_LINE_SIZE);
>>>> @@ -190,9 +189,6 @@ void * __init relocate_kernel(void)
>>>>
>>>>                   reloc_offset +=3D random_offset;
>>>>
>>>> -               /* Return the new kernel's entry point */
>>>> -               kernel_entry =3D RELOCATED_KASLR(start_kernel);
>>>> -
>>>>                   /* The current thread is now within the relocated ke=
rnel */
>>>>                   __current_thread_info =3D RELOCATED_KASLR(__current_=
thread_info);
>>>>
>>>> @@ -204,7 +200,7 @@ void * __init relocate_kernel(void)
>>>>
>>>>           relocate_absolute(random_offset);
>>>>
>>>> -       return kernel_entry;
>>>> +       return random_offset;
>>>
>>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/9a6f11a3-d01c-e0c9-a4f3-47db25ce02f3%40loongson.cn.
