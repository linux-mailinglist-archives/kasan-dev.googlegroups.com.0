Return-Path: <kasan-dev+bncBCRKFI7J2AJRBXNHYSDQMGQEA5SS5RI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3d.google.com (mail-io1-xd3d.google.com [IPv6:2607:f8b0:4864:20::d3d])
	by mail.lfdr.de (Postfix) with ESMTPS id A4E653CB1C5
	for <lists+kasan-dev@lfdr.de>; Fri, 16 Jul 2021 07:06:38 +0200 (CEST)
Received: by mail-io1-xd3d.google.com with SMTP id b136-20020a6bb28e0000b0290520c8d13420sf5212611iof.19
        for <lists+kasan-dev@lfdr.de>; Thu, 15 Jul 2021 22:06:38 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1626411997; cv=pass;
        d=google.com; s=arc-20160816;
        b=ylx9OL7V+3b/C4nL6dJdzzYwlICjne4AePj1WhAXUx6oqkzgoQCD05yApJcVk9pkFD
         1YJIszfKfimKe2W0+TGtil8XKfS8+cTY0UiZpED06JPqRM0bYHU4snPfBwUaRRTM2w8l
         eWH92qnAqVbo2nhiinouEqSh5fvuQrtgnAwZ83iVuwON5Nv2jfqlk6x4PilaiFiBaQwu
         FkakxoYBH+VO9ygKl/E8tprMfas1xpjHbR6QVbgDYOD+3VBkM7pagyRoYwOqA16JO/Ml
         LIOTu4Or2rN6l+2EWhHZuSJRxfGDZBCmC9u6OMlsvukZgi1drPVtXysWvSkbfX2X4LWY
         qnJg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:references:cc:to:from
         :subject:sender:dkim-signature;
        bh=D7CeQHQymhUf7Wh7IZ/o+/HLgBlxfG4k4LQn+dGc1r0=;
        b=pfY4UwKy/7/RVnM49sIYYRvDaeAw5H00k5xwdQCYd37IVxCpuhpCBii/2hd0TKL8jW
         /DS2itsYZAzEGE+S4Kfq5r+HBeZzZYOyzTF+/3encl3cHignk+3MZYE3S+KPaYnJgJlw
         t1ajSfncxPP2PufQXnbusFvez8E+6Ilj5LDqV5Hos/3PHETwjnKQa+L36ufcUrUDlJES
         KPpHANgj1CDeciCQ0o2kW9yAmLXQRDWOTxnz54pFh0qnoEo78KwaRvyhfcSwyv+iJP5Y
         cQI8dN/ynMWJK+uwupEb1YbP+7Z6xlf+bG3rmQuFppbjsLYM1DGMWwINoTcJ1P4baI8m
         lYEw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.187 as permitted sender) smtp.mailfrom=wangkefeng.wang@huawei.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=huawei.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:from:to:cc:references:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=D7CeQHQymhUf7Wh7IZ/o+/HLgBlxfG4k4LQn+dGc1r0=;
        b=jQ5CLYMcpSWozYqL/lf3Jbba/khoWBdNUxl1u3RBvFQ9OnGBtmI18G/jVfMWW7jFpp
         Zu7dpPhh71gsD61+1eWnAt1qf7BF6S+d/HItLDazCM+7hvTNW6bqyivmMGRptOILEp4E
         Ib0uL8kSNi2Vsnp75vxJyRP/MWvgjT+Ay7oBdKWJTKBPLwnWb0Bocgj8R/mYMEOvxOhS
         O4XhBEaM7D5UDH+NjzwFIoXTepgT9ecZg0Z6tanLUzg3xOuw3hr4L67PQYjJaDgJe3UG
         iO8DewraTEVKlcPUJxUMSevIsJDOQ8ermgSHCQVnc4ZzOIDXEe5oK5r9xj6wRksnQX3P
         /7kg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:from:to:cc:references:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=D7CeQHQymhUf7Wh7IZ/o+/HLgBlxfG4k4LQn+dGc1r0=;
        b=p0xKO5HtE1wj5lTkcd7qBTx6xi96TpSAEh2DtA0VpDavcBb3cJyWy86lwRkHRPbiJT
         KoOeQUqB8apXleN/JVN3b2P6gPvdb86F2mUuVjSwspmFvbBQfp9a0kwXe6bYvZvMdsLA
         F3BXpE3T4CUBKRJJNf6DeZza2mbaRBDZ8rjVzj+kzDY6Hdjfg6LXAFIi1ev8oJKLSuHU
         yVJfBlprR+FgUqTQR92lEtZDSzOcXLaHHvYBaPbdM6Sf7uHihDf55Tw6llNaeDUKkywO
         CelYpR2KCERADJ7/64Go1WxUos4SFWHcazFFFcj6RAvCiwvsPV2CI8UNHqOolrSpX4Kn
         fVZQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533Uuy21pCRiQdtCf+dW+9BqVk17l4/vqZjSUYB/ZVwOpnZCFvQV
	zvEnxM6ou50b5dDAPqlm/Fs=
X-Google-Smtp-Source: ABdhPJyL8uTUZg8T5QT0yg0l3p0WeG83b8/sxv/QjRkbYxfZWlqrDVfHMFejvT9A2aSMqXNua5W7ZQ==
X-Received: by 2002:a6b:ba02:: with SMTP id k2mr1495606iof.164.1626411997396;
        Thu, 15 Jul 2021 22:06:37 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6638:141:: with SMTP id y1ls1506686jao.2.gmail; Thu, 15
 Jul 2021 22:06:37 -0700 (PDT)
X-Received: by 2002:a02:3b26:: with SMTP id c38mr7421181jaa.12.1626411996971;
        Thu, 15 Jul 2021 22:06:36 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1626411996; cv=none;
        d=google.com; s=arc-20160816;
        b=byuuRykGS+qZcg8PpQfy/u0m2e3wN0q27DI1CUqJ8NgpWRBZrZUiWdgmiP94h4N3KJ
         V1JHalTub5oYxDdYauFvNUsMD1QiPpbikUhSwkclqXMFxCq7iDLLkO9pBBcN7Mi7n7i4
         xwrHvW8ibkzZt0ozwpO1sHi2a7S+Rpt9hbdW7oZeDgBqNVkSW0oa9oOlZ+c2EZUj7hyq
         2zv2RJedvkL5uNm7/ruitDnDC66d6JcfGLhBeLZ+ui2IsK6fzIRYPv3NFD2rNkkcjVaA
         6KuiNsX+PKRXykgKdJAyUxwkR3e9KZWOF03xxFPGor8Pi6mpWdTz1DPFf4I32lRt+Tux
         294Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-language:in-reply-to:mime-version:user-agent:date
         :message-id:references:cc:to:from:subject;
        bh=0izPBpwc9iUzIprHgX8GFGHz35+lJaRPBhxpUjezHQY=;
        b=x11pjPtWjUfZjTp9FF0JgKRiQVpK2QixmXBdtsJtaJiswpkHYT3G8ZX3lZ6W2PSrqF
         BxD2YUjDpyPwfnZHlOp8oPcjFFaMct3vN8+qr3r1qjZ+e0k0a/Mf6iatHa9FHFiNQiEM
         jkWTVEHbOVxoQxbuIg3MAWTcNRX6b2Cw9gRXA0imS3dTygS0Q3xnLE0m8yI0jBASDZLB
         gSiECITg2ZlKx6zIohgvfanVG2JeEWc5bbKtBUkJNVqxZtBKn7SYgFMBevvRIt1spyDn
         91/QvV+pgGt+8EJc7A+4HbO4+VsxVM7atfyzEtqhc4NA9aMCDSq0jW5c9zFiMiQXYFUi
         EWKg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.187 as permitted sender) smtp.mailfrom=wangkefeng.wang@huawei.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=huawei.com
Received: from szxga01-in.huawei.com (szxga01-in.huawei.com. [45.249.212.187])
        by gmr-mx.google.com with ESMTPS id b11si13116iln.5.2021.07.15.22.06.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 15 Jul 2021 22:06:36 -0700 (PDT)
Received-SPF: pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.187 as permitted sender) client-ip=45.249.212.187;
Received: from dggemv703-chm.china.huawei.com (unknown [172.30.72.55])
	by szxga01-in.huawei.com (SkyGuard) with ESMTP id 4GQzb952ZJzYcvF;
	Fri, 16 Jul 2021 13:00:53 +0800 (CST)
Received: from dggpemm500001.china.huawei.com (7.185.36.107) by
 dggemv703-chm.china.huawei.com (10.3.19.46) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2176.2; Fri, 16 Jul 2021 13:06:33 +0800
Received: from [10.174.177.243] (10.174.177.243) by
 dggpemm500001.china.huawei.com (7.185.36.107) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2176.2; Fri, 16 Jul 2021 13:06:33 +0800
Subject: Re: [PATCH -next 3/3] kasan: arm64: Fix pcpu_page_first_chunk crash
 with KASAN_VMALLOC
From: Kefeng Wang <wangkefeng.wang@huawei.com>
To: Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>
CC: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will@kernel.org>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Andrey Konovalov
	<andreyknvl@gmail.com>, <linux-arm-kernel@lists.infradead.org>,
	<linux-kernel@vger.kernel.org>, <kasan-dev@googlegroups.com>,
	<linux-mm@kvack.org>, Daniel Axtens <dja@axtens.net>
References: <20210705111453.164230-1-wangkefeng.wang@huawei.com>
 <20210705111453.164230-4-wangkefeng.wang@huawei.com>
 <YOMfcE7V7lSE3N/z@elver.google.com>
 <089f5187-9a4d-72dc-1767-8130434bfb3a@huawei.com>
Message-ID: <5f760f6c-dcbd-b28a-2116-a2fb233fc534@huawei.com>
Date: Fri, 16 Jul 2021 13:06:32 +0800
User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64; rv:60.0) Gecko/20100101
 Thunderbird/60.7.0
MIME-Version: 1.0
In-Reply-To: <089f5187-9a4d-72dc-1767-8130434bfb3a@huawei.com>
Content-Type: multipart/alternative;
	boundary="------------FB17C0B34F7D9467DE6387C5"
Content-Language: en-US
X-Originating-IP: [10.174.177.243]
X-ClientProxiedBy: dggems701-chm.china.huawei.com (10.3.19.178) To
 dggpemm500001.china.huawei.com (7.185.36.107)
X-CFilter-Loop: Reflected
X-Original-Sender: wangkefeng.wang@huawei.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.187
 as permitted sender) smtp.mailfrom=wangkefeng.wang@huawei.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=huawei.com
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

--------------FB17C0B34F7D9467DE6387C5
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Transfer-Encoding: quoted-printable

Hi Marco and Dmitry, any comments about the following replay, thanks.

On 2021/7/6 12:07, Kefeng Wang wrote:
>
> Hi Marco and Dmitry,
>
> On 2021/7/5 23:04, Marco Elver wrote:
>> On Mon, Jul 05, 2021 at 07:14PM +0800, Kefeng Wang wrote:
>> [...]
>>> +#ifdef CONFIG_KASAN_VMALLOC
>>> +void __init __weak kasan_populate_early_vm_area_shadow(void *start,
>>> +						       unsigned long size)
>> This should probably not be __weak, otherwise you now have 2 __weak
>> functions.
> Indeed, forget it.
>>> +{
>>> +	unsigned long shadow_start, shadow_end;
>>> +
>>> +	if (!is_vmalloc_or_module_addr(start))
>>> +		return;
>>> +
>>> +	shadow_start =3D (unsigned long)kasan_mem_to_shadow(start);
>>> +	shadow_start =3D ALIGN_DOWN(shadow_start, PAGE_SIZE);
>>> +	shadow_end =3D (unsigned long)kasan_mem_to_shadow(start + size);
>>> +	shadow_end =3D ALIGN(shadow_end, PAGE_SIZE);
>>> +	kasan_map_populate(shadow_start, shadow_end,
>>> +			   early_pfn_to_nid(virt_to_pfn(start)));
>>> +}
>>> +#endif
>> This function looks quite generic -- would any of this also apply to
>> other architectures? I see that ppc and sparc at least also define
>> CONFIG_NEED_PER_CPU_PAGE_FIRST_CHUNK.
>
> I can't try ppc/sparc, but only ppc support KASAN_VMALLOC,
>
> I check the x86, it supports CONFIG_NEED_PER_CPU_PAGE_FIRST_CHUNK,
>
> looks this issue is existing on x86 and ppc.
>
>>>   void __init kasan_init(void)
>>>   {
>>>   	kasan_init_shadow();
>>> diff --git a/include/linux/kasan.h b/include/linux/kasan.h
>>> index 5310e217bd74..79d3895b0240 100644
>>> --- a/include/linux/kasan.h
>>> +++ b/include/linux/kasan.h
>>> @@ -49,6 +49,8 @@ extern p4d_t kasan_early_shadow_p4d[MAX_PTRS_PER_P4D]=
;
>>>   int kasan_populate_early_shadow(const void *shadow_start,
>>>   				const void *shadow_end);
>>>  =20
>>> +void kasan_populate_early_vm_area_shadow(void *start, unsigned long si=
ze);
>>> +
>>>   static inline void *kasan_mem_to_shadow(const void *addr)
>>>   {
>>>   	return (void *)((unsigned long)addr >> KASAN_SHADOW_SCALE_SHIFT)
>>> diff --git a/mm/kasan/init.c b/mm/kasan/init.c
>>> index cc64ed6858c6..d39577d088a1 100644
>>> --- a/mm/kasan/init.c
>>> +++ b/mm/kasan/init.c
>>> @@ -279,6 +279,11 @@ int __ref kasan_populate_early_shadow(const void *=
shadow_start,
>>>   	return 0;
>>>   }
>>>  =20
>>> +void __init __weak kasan_populate_early_vm_area_shadow(void *start,
>>> +						       unsigned long size)
>>> +{
>>> +}
>> I'm just wondering if this could be a generic function, perhaps with an
>> appropriate IS_ENABLED() check of a generic Kconfig option
>> (CONFIG_NEED_PER_CPU_PAGE_FIRST_CHUNK ?) to short-circuit it, if it's
>> not only an arm64 problem.
>
> kasan_map_populate() is arm64 special function, and the x86 has kasan_sha=
llow_populate_pgds(),
> ppc has kasan_init_shadow_page_tables(), so look those ARCHs should do th=
e same way like ARM64,
>
> Here we can't use kasan_populate_early_shadow(), this functions will make=
 the early shadow maps
> everything to a single page of zeroes=EF=BC=88kasan_early_shadow_page), a=
nd set it pte_wrprotect, see
> zero_pte_populate(), right?
>
> Also I try this, it crashs on ARM64 when change kasan_map_populate() to k=
asan_populate_early_shadow(),
>
> Unable to handle kernel write to read-only memory at virtual address ffff=
700002938000
> ...
> Call trace:
>   __memset+0x16c/0x1c0
>   kasan_unpoison+0x34/0x6c
>   kasan_unpoison_vmalloc+0x2c/0x3c
>   __get_vm_area_node.constprop.0+0x13c/0x240
>   __vmalloc_node_range+0xf4/0x4f0
>   __vmalloc_node+0x80/0x9c
>   init_IRQ+0xe8/0x130
>   start_kernel+0x188/0x360
>   __primary_switched+0xc0/0xc8
>
>
>> But I haven't looked much further, so would appeal to you to either
>> confirm or reject this idea.
>>
>> Thanks,
>> -- Marco
>> .
>>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/5f760f6c-dcbd-b28a-2116-a2fb233fc534%40huawei.com.

--------------FB17C0B34F7D9467DE6387C5
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<html>
  <head>
    <meta http-equiv=3D"Content-Type" content=3D"text/html; charset=3DUTF-8=
">
  </head>
  <body text=3D"#000000" bgcolor=3D"#FFFFFF">
    <p>Hi Marco and Dmitry, any comments about the following replay,
      thanks.<br>
    </p>
    <div class=3D"moz-cite-prefix">On 2021/7/6 12:07, Kefeng Wang wrote:<br=
>
    </div>
    <blockquote type=3D"cite"
      cite=3D"mid:089f5187-9a4d-72dc-1767-8130434bfb3a@huawei.com">
      <meta http-equiv=3D"Content-Type" content=3D"text/html; charset=3DUTF=
-8">
      <p>Hi Marco and Dmitry,<br>
      </p>
      <div class=3D"moz-cite-prefix">On 2021/7/5 23:04, Marco Elver wrote:<=
br>
      </div>
      <blockquote type=3D"cite"
        cite=3D"mid:YOMfcE7V7lSE3N%2Fz@elver.google.com">
        <pre class=3D"moz-quote-pre" wrap=3D"">On Mon, Jul 05, 2021 at 07:1=
4PM +0800, Kefeng Wang wrote:
[...]
</pre>
        <blockquote type=3D"cite">
          <pre class=3D"moz-quote-pre" wrap=3D"">+#ifdef CONFIG_KASAN_VMALL=
OC
+void __init __weak kasan_populate_early_vm_area_shadow(void *start,
+						       unsigned long size)
</pre>
        </blockquote>
        <pre class=3D"moz-quote-pre" wrap=3D"">This should probably not be =
__weak, otherwise you now have 2 __weak
functions.</pre>
      </blockquote>
      Indeed, forget it.<br>
      <blockquote type=3D"cite"
        cite=3D"mid:YOMfcE7V7lSE3N%2Fz@elver.google.com">
        <blockquote type=3D"cite">
          <pre class=3D"moz-quote-pre" wrap=3D"">+{
+	unsigned long shadow_start, shadow_end;
+
+	if (!is_vmalloc_or_module_addr(start))
+		return;
+
+	shadow_start =3D (unsigned long)kasan_mem_to_shadow(start);
+	shadow_start =3D ALIGN_DOWN(shadow_start, PAGE_SIZE);
+	shadow_end =3D (unsigned long)kasan_mem_to_shadow(start + size);
+	shadow_end =3D ALIGN(shadow_end, PAGE_SIZE);
+	kasan_map_populate(shadow_start, shadow_end,
+			   early_pfn_to_nid(virt_to_pfn(start)));
+}
+#endif
</pre>
        </blockquote>
        <pre class=3D"moz-quote-pre" wrap=3D"">This function looks quite ge=
neric -- would any of this also apply to
other architectures? I see that ppc and sparc at least also define
CONFIG_NEED_PER_CPU_PAGE_FIRST_CHUNK.</pre>
      </blockquote>
      <p>I can't try ppc/sparc, but only ppc support KASAN_VMALLOC,</p>
      <p>I check the x86, it supports
        CONFIG_NEED_PER_CPU_PAGE_FIRST_CHUNK,</p>
      <p>looks this issue is existing on x86 and ppc.<br>
      </p>
      <blockquote type=3D"cite"
        cite=3D"mid:YOMfcE7V7lSE3N%2Fz@elver.google.com">
        <blockquote type=3D"cite">
          <pre class=3D"moz-quote-pre" wrap=3D""> void __init kasan_init(vo=
id)
 {
 	kasan_init_shadow();
diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index 5310e217bd74..79d3895b0240 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -49,6 +49,8 @@ extern p4d_t kasan_early_shadow_p4d[MAX_PTRS_PER_P4D];
 int kasan_populate_early_shadow(const void *shadow_start,
 				const void *shadow_end);
=20
+void kasan_populate_early_vm_area_shadow(void *start, unsigned long size);
+
 static inline void *kasan_mem_to_shadow(const void *addr)
 {
 	return (void *)((unsigned long)addr &gt;&gt; KASAN_SHADOW_SCALE_SHIFT)
diff --git a/mm/kasan/init.c b/mm/kasan/init.c
index cc64ed6858c6..d39577d088a1 100644
--- a/mm/kasan/init.c
+++ b/mm/kasan/init.c
@@ -279,6 +279,11 @@ int __ref kasan_populate_early_shadow(const void *shad=
ow_start,
 	return 0;
 }
=20
+void __init __weak kasan_populate_early_vm_area_shadow(void *start,
+						       unsigned long size)
+{
+}
</pre>
        </blockquote>
        <pre class=3D"moz-quote-pre" wrap=3D"">I'm just wondering if this c=
ould be a generic function, perhaps with an
appropriate IS_ENABLED() check of a generic Kconfig option
(CONFIG_NEED_PER_CPU_PAGE_FIRST_CHUNK ?) to short-circuit it, if it's
not only an arm64 problem.</pre>
      </blockquote>
      <br>
      <pre class=3D"moz-quote-pre" wrap=3D"">kasan_map_populate() is arm64 =
special function, and the x86 has kasan_shallow_populate_pgds(),
ppc has kasan_init_shadow_page_tables(), so look those ARCHs should do the =
same way like ARM64,

Here we can't use kasan_populate_early_shadow(), this functions will make t=
he early shadow maps
everything to a single page of zeroes=EF=BC=88<span class=3D"curline">kasan=
_early_shadow_page</span>), and set it pte_wrprotect, see
zero_pte_populate(), right?=20

Also I try this, it crashs on ARM64 when change kasan_map_populate() to kas=
an_populate_early_shadow(),

Unable to handle kernel write to read-only memory at virtual address ffff70=
0002938000
...
Call trace:
 __memset+0x16c/0x1c0
 kasan_unpoison+0x34/0x6c
 kasan_unpoison_vmalloc+0x2c/0x3c
 __get_vm_area_node.constprop.0+0x13c/0x240
 __vmalloc_node_range+0xf4/0x4f0
 __vmalloc_node+0x80/0x9c
 init_IRQ+0xe8/0x130
 start_kernel+0x188/0x360
 __primary_switched+0xc0/0xc8


</pre>
      <blockquote type=3D"cite"
        cite=3D"mid:YOMfcE7V7lSE3N%2Fz@elver.google.com">
        <pre class=3D"moz-quote-pre" wrap=3D"">But I haven't looked much fu=
rther, so would appeal to you to either
confirm or reject this idea.

Thanks,
-- Marco
.

</pre>
      </blockquote>
    </blockquote>
  </body>
</html>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion on the web visit <a href=3D"https://groups.google.c=
om/d/msgid/kasan-dev/5f760f6c-dcbd-b28a-2116-a2fb233fc534%40huawei.com?utm_=
medium=3Demail&utm_source=3Dfooter">https://groups.google.com/d/msgid/kasan=
-dev/5f760f6c-dcbd-b28a-2116-a2fb233fc534%40huawei.com</a>.<br />

--------------FB17C0B34F7D9467DE6387C5--
