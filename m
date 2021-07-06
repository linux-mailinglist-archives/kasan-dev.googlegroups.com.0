Return-Path: <kasan-dev+bncBCRKFI7J2AJRBFVOR6DQMGQEXFHNPEQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x338.google.com (mail-ot1-x338.google.com [IPv6:2607:f8b0:4864:20::338])
	by mail.lfdr.de (Postfix) with ESMTPS id 65F383BC526
	for <lists+kasan-dev@lfdr.de>; Tue,  6 Jul 2021 06:07:51 +0200 (CEST)
Received: by mail-ot1-x338.google.com with SMTP id v13-20020a0568301bcdb02904a7501488c8sf1837422ota.4
        for <lists+kasan-dev@lfdr.de>; Mon, 05 Jul 2021 21:07:51 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1625544470; cv=pass;
        d=google.com; s=arc-20160816;
        b=j4GdgBMgTjEJRu9A4tdLCgNJBdVoHR+EwLLN83gOz1LV9yr2+h/1NPVKJgJSDrJdvI
         bVZHYrcWxRSMYZPGu3/gdIXAOZ5GN2hpNtysVbpaaGSHuEgyGWhXFvX5I48uilTnu68V
         pdZ8CnldI0B4xdDoW6zEqq6HUehbngKJO+XUDxzPSm752ySbc66fdBEg6T4ZVKYL4V3G
         IyB1nMQzKQiS3WsJ+Kluuw+8uM28QTzpM9d9QlgmzA4HMLPwtA5/04j+wDqnZZBFdDyE
         sM6dIth5Ds/QZd/+WDIYRme8H2NvmYiWrukiUkG8s2R4jUJWqdsfZxmeSAC3BFaECFQB
         8Sgw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=z6+D2Cxhd4ofk26WuO77gAnsKCcaV2/Oi7yCWzbf7Tc=;
        b=Myt/LmS6Qc2I6CgF12AjD6UEefm2UiIxY+iG09ahr/p4mZMTrqzDspljBwGPG2+ViB
         EnF/aDgFHyevFBS9hDHHrH/PLdS61HH2+22FsOZySDT3/F9o+pTOndNxTmke7O3FusYd
         5yyqIrS7B3jXEnNHXQ3Gm9bTxSLCCvROQaYbl28wTpuFjqyg1n3ekLNMoF2JIqWrkfQ7
         ygnVa91okyTSPInnNe0CHnZB2YqNXzJV+Bm378yuR0IIkTSOGjRCU9CYfjTPLQHDTnUZ
         Wamo+cjNtxrvMQ8vVCt81SQRwzk3NkE7xaQD6+DDVVY+3voBadR4rzV94y0jtFWZUSIp
         o7IQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.255 as permitted sender) smtp.mailfrom=wangkefeng.wang@huawei.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=huawei.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=z6+D2Cxhd4ofk26WuO77gAnsKCcaV2/Oi7yCWzbf7Tc=;
        b=qeSlUzTdPWUe/5j5Yekkvt4X34CXeNMoicEqcgT2x2keTtZlQL2gJELidKb+Olv5l1
         xWehzxsM/n7gNMg+UDjkdD1CcBm2HlbpFEOoQ/WBr9TODPuIzgyAzg2hytTdwvlN+tX7
         90AaJYVoxWob7p5DSXHEmMAZyc2hZq5vGnk5W4GzSV0Cue3Tfeo42Y6E2F2MdEau0doW
         l0I6hNI2mlGtWYZD8st7gGYPldIqxU2c1Clx2gEw9UdbkvJAQOjcIYiKjwu+XQGjneot
         Y1gj4vQbrot9aekKOCsu33tH5VVzqQREGv7FU4Zd8POcCx58obQfw53Evi5vEdADCRLi
         Eh9Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=z6+D2Cxhd4ofk26WuO77gAnsKCcaV2/Oi7yCWzbf7Tc=;
        b=r27GJt21mJpxSV2ZnielkDGw57KmIzs/vNy/5bb4erkw9ORfH5rVnNZXtyE2HtIKo0
         V//NeZcVnsZpmdAtin7WsLW/pIgvzG40pc/rnYjn58yeSXV1hpM1cyGrAcWOvCqSA5fI
         +uCoUu2vDpo2OxwwRdPMtdV3cHWAltNY6ZS14BaRH6trMLLCvlquPLiXFs+bFkJUmOIw
         hDHbcqx2bWlF6hV10lr5VHdv8PFwoIPkhM3MOjsjmlVfSAbzjRycXhsIW0chv94MWVXY
         G/h/CgWmgPvHkv9RBa4EYsUu5kiNIMjDqJn9Z4JTxf0b1TKO0XzN+10fVo22qufU07K5
         UDqQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531e7JRwAzhxOe7qW0bas8g2biIp1cRl0WO557Z4aqQHJGoVuhzQ
	1KYP9FDQ2e4rgnaNli625ig=
X-Google-Smtp-Source: ABdhPJyjQBdxVyq8VyCfleCUbXdqXgtWz2KbW5uMyN9BkZenaiCisJ0H22wx4HE0NfyMpJdeTbzf2g==
X-Received: by 2002:a9d:4d84:: with SMTP id u4mr13088615otk.285.1625544470397;
        Mon, 05 Jul 2021 21:07:50 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:6d1a:: with SMTP id o26ls7237095otp.2.gmail; Mon, 05 Jul
 2021 21:07:50 -0700 (PDT)
X-Received: by 2002:a9d:1ea5:: with SMTP id n34mr13531033otn.340.1625544470056;
        Mon, 05 Jul 2021 21:07:50 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1625544470; cv=none;
        d=google.com; s=arc-20160816;
        b=xhHOCV1dSZxzvyolTUFwmbhdEcCqBSLjaEEVi7Q0ELNkOxeDr5sldywc1g0Wzrzp7J
         ud/85uPIUdjhizX5jVbEsYQgLV3mR3PDCcyiaREZCthSXAIUZPXi1bylGJCg6dlxCmmB
         DTPIliUWTtLlNWVM8t9+cSJXymRRdWt5bhTNxlWtWiaFwfiimPS4Nvf6D+iq72iCPXvW
         0OyixGrZJJpROvgPGMhn65+jlBiAhgErSRRXvfbc1bZ+Nn7AMDBXlkl+B6oa5+Ux9gcm
         GyQqVHQakFeyenZERBwIivG/D/x14DURIUN13S8rfNrlnnF71lz9Er+8m9eAcqcbD120
         rLsA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-language:in-reply-to:mime-version:user-agent:date
         :message-id:from:references:cc:to:subject;
        bh=10Nz7IEzXtV6vP8CjByRCnomo5njfzfBZcr3wNhtI2Y=;
        b=l30xIgUckk/eZS3Qq6Fa1at1FoqFVYqw9wC10fKZMgx9yQJ2+fyUEglmmAz8xe7ZJ/
         STN6pojmWmnqG/1nfFFPCj2EbPP0QgxDWu+VHiXODeWDzG7kmta/s0t98kQMR5ayWn67
         eCtQhCYUUank2gwhknahiQv00nULAF2/fPwq8N6Yl4YDI8apoNdOUIdKU/iRrFMROrby
         4WhgkcVHdBkIixo84SP64vGieLwaah0JTIW0iWomtdm7ezfIm/yiSgAhVOfcZbL7rnv9
         IqjnR9JpVazjN5z05OSQfTAeKa2mSQhcRs2ls6DbS1F4PUCYugQK19VTSBwKl6wlv1sX
         oWuw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.255 as permitted sender) smtp.mailfrom=wangkefeng.wang@huawei.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=huawei.com
Received: from szxga08-in.huawei.com (szxga08-in.huawei.com. [45.249.212.255])
        by gmr-mx.google.com with ESMTPS id w23si1248340oti.4.2021.07.05.21.07.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 05 Jul 2021 21:07:50 -0700 (PDT)
Received-SPF: pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.255 as permitted sender) client-ip=45.249.212.255;
Received: from dggemv711-chm.china.huawei.com (unknown [172.30.72.54])
	by szxga08-in.huawei.com (SkyGuard) with ESMTP id 4GJpmD4fXzz1CFhF;
	Tue,  6 Jul 2021 12:02:20 +0800 (CST)
Received: from dggpemm500001.china.huawei.com (7.185.36.107) by
 dggemv711-chm.china.huawei.com (10.1.198.66) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2176.2; Tue, 6 Jul 2021 12:07:43 +0800
Received: from [10.174.177.243] (10.174.177.243) by
 dggpemm500001.china.huawei.com (7.185.36.107) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2176.2; Tue, 6 Jul 2021 12:07:42 +0800
Subject: Re: [PATCH -next 3/3] kasan: arm64: Fix pcpu_page_first_chunk crash
 with KASAN_VMALLOC
To: Marco Elver <elver@google.com>
CC: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will@kernel.org>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Andrey Konovalov
	<andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>,
	<linux-arm-kernel@lists.infradead.org>, <linux-kernel@vger.kernel.org>,
	<kasan-dev@googlegroups.com>, <linux-mm@kvack.org>, Daniel Axtens
	<dja@axtens.net>
References: <20210705111453.164230-1-wangkefeng.wang@huawei.com>
 <20210705111453.164230-4-wangkefeng.wang@huawei.com>
 <YOMfcE7V7lSE3N/z@elver.google.com>
From: Kefeng Wang <wangkefeng.wang@huawei.com>
Message-ID: <089f5187-9a4d-72dc-1767-8130434bfb3a@huawei.com>
Date: Tue, 6 Jul 2021 12:07:42 +0800
User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64; rv:60.0) Gecko/20100101
 Thunderbird/60.7.0
MIME-Version: 1.0
In-Reply-To: <YOMfcE7V7lSE3N/z@elver.google.com>
Content-Type: multipart/alternative;
	boundary="------------A272B108B4C815A0D985895D"
Content-Language: en-US
X-Originating-IP: [10.174.177.243]
X-ClientProxiedBy: dggems704-chm.china.huawei.com (10.3.19.181) To
 dggpemm500001.china.huawei.com (7.185.36.107)
X-CFilter-Loop: Reflected
X-Original-Sender: wangkefeng.wang@huawei.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.255
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

--------------A272B108B4C815A0D985895D
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Transfer-Encoding: quoted-printable

Hi Marco and Dmitry,

On 2021/7/5 23:04, Marco Elver wrote:
> On Mon, Jul 05, 2021 at 07:14PM +0800, Kefeng Wang wrote:
> [...]
>> +#ifdef CONFIG_KASAN_VMALLOC
>> +void __init __weak kasan_populate_early_vm_area_shadow(void *start,
>> +						       unsigned long size)
> This should probably not be __weak, otherwise you now have 2 __weak
> functions.
Indeed, forget it.
>
>> +{
>> +	unsigned long shadow_start, shadow_end;
>> +
>> +	if (!is_vmalloc_or_module_addr(start))
>> +		return;
>> +
>> +	shadow_start =3D (unsigned long)kasan_mem_to_shadow(start);
>> +	shadow_start =3D ALIGN_DOWN(shadow_start, PAGE_SIZE);
>> +	shadow_end =3D (unsigned long)kasan_mem_to_shadow(start + size);
>> +	shadow_end =3D ALIGN(shadow_end, PAGE_SIZE);
>> +	kasan_map_populate(shadow_start, shadow_end,
>> +			   early_pfn_to_nid(virt_to_pfn(start)));
>> +}
>> +#endif
> This function looks quite generic -- would any of this also apply to
> other architectures? I see that ppc and sparc at least also define
> CONFIG_NEED_PER_CPU_PAGE_FIRST_CHUNK.

I can't try ppc/sparc, but only ppc support KASAN_VMALLOC,

I check the x86, it supports CONFIG_NEED_PER_CPU_PAGE_FIRST_CHUNK,

looks this issue is existing on x86 and ppc.

>
>>   void __init kasan_init(void)
>>   {
>>   	kasan_init_shadow();
>> diff --git a/include/linux/kasan.h b/include/linux/kasan.h
>> index 5310e217bd74..79d3895b0240 100644
>> --- a/include/linux/kasan.h
>> +++ b/include/linux/kasan.h
>> @@ -49,6 +49,8 @@ extern p4d_t kasan_early_shadow_p4d[MAX_PTRS_PER_P4D];
>>   int kasan_populate_early_shadow(const void *shadow_start,
>>   				const void *shadow_end);
>>  =20
>> +void kasan_populate_early_vm_area_shadow(void *start, unsigned long siz=
e);
>> +
>>   static inline void *kasan_mem_to_shadow(const void *addr)
>>   {
>>   	return (void *)((unsigned long)addr >> KASAN_SHADOW_SCALE_SHIFT)
>> diff --git a/mm/kasan/init.c b/mm/kasan/init.c
>> index cc64ed6858c6..d39577d088a1 100644
>> --- a/mm/kasan/init.c
>> +++ b/mm/kasan/init.c
>> @@ -279,6 +279,11 @@ int __ref kasan_populate_early_shadow(const void *s=
hadow_start,
>>   	return 0;
>>   }
>>  =20
>> +void __init __weak kasan_populate_early_vm_area_shadow(void *start,
>> +						       unsigned long size)
>> +{
>> +}
> I'm just wondering if this could be a generic function, perhaps with an
> appropriate IS_ENABLED() check of a generic Kconfig option
> (CONFIG_NEED_PER_CPU_PAGE_FIRST_CHUNK ?) to short-circuit it, if it's
> not only an arm64 problem.

kasan_map_populate() is arm64 special function, and the x86 has kasan_shall=
ow_populate_pgds(),
ppc has kasan_init_shadow_page_tables(), so look those ARCHs should do the =
same way like ARM64,

Here we can't use kasan_populate_early_shadow(), this functions will make t=
he early shadow maps
everything to a single page of zeroes=EF=BC=88kasan_early_shadow_page), and=
 set it pte_wrprotect, see
zero_pte_populate(), right?

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


>
> But I haven't looked much further, so would appeal to you to either
> confirm or reject this idea.
>
> Thanks,
> -- Marco
> .
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/089f5187-9a4d-72dc-1767-8130434bfb3a%40huawei.com.

--------------A272B108B4C815A0D985895D
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<html>
  <head>
    <meta http-equiv=3D"Content-Type" content=3D"text/html; charset=3DUTF-8=
">
  </head>
  <body text=3D"#000000" bgcolor=3D"#FFFFFF">
    <p>Hi Marco and Dmitry,<br>
    </p>
    <div class=3D"moz-cite-prefix">On 2021/7/5 23:04, Marco Elver wrote:<br=
>
    </div>
    <blockquote type=3D"cite"
      cite=3D"mid:YOMfcE7V7lSE3N%2Fz@elver.google.com">
      <pre class=3D"moz-quote-pre" wrap=3D"">On Mon, Jul 05, 2021 at 07:14P=
M +0800, Kefeng Wang wrote:
[...]
</pre>
      <blockquote type=3D"cite">
        <pre class=3D"moz-quote-pre" wrap=3D"">+#ifdef CONFIG_KASAN_VMALLOC
+void __init __weak kasan_populate_early_vm_area_shadow(void *start,
+						       unsigned long size)
</pre>
      </blockquote>
      <pre class=3D"moz-quote-pre" wrap=3D"">
This should probably not be __weak, otherwise you now have 2 __weak
functions.</pre>
    </blockquote>
    Indeed, forget it.<br>
    <blockquote type=3D"cite"
      cite=3D"mid:YOMfcE7V7lSE3N%2Fz@elver.google.com">
      <pre class=3D"moz-quote-pre" wrap=3D"">

</pre>
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
      <pre class=3D"moz-quote-pre" wrap=3D"">
This function looks quite generic -- would any of this also apply to
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
      <pre class=3D"moz-quote-pre" wrap=3D"">

</pre>
      <blockquote type=3D"cite">
        <pre class=3D"moz-quote-pre" wrap=3D""> void __init kasan_init(void=
)
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
      <pre class=3D"moz-quote-pre" wrap=3D"">
I'm just wondering if this could be a generic function, perhaps with an
appropriate IS_ENABLED() check of a generic Kconfig option
(CONFIG_NEED_PER_CPU_PAGE_FIRST_CHUNK ?) to short-circuit it, if it's
not only an arm64 problem.</pre>
    </blockquote>
    <br>
    <pre class=3D"moz-quote-pre" wrap=3D"">kasan_map_populate() is arm64 sp=
ecial function, and the x86 has kasan_shallow_populate_pgds(),
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
      <pre class=3D"moz-quote-pre" wrap=3D"">

But I haven't looked much further, so would appeal to you to either
confirm or reject this idea.

Thanks,
-- Marco
.

</pre>
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
om/d/msgid/kasan-dev/089f5187-9a4d-72dc-1767-8130434bfb3a%40huawei.com?utm_=
medium=3Demail&utm_source=3Dfooter">https://groups.google.com/d/msgid/kasan=
-dev/089f5187-9a4d-72dc-1767-8130434bfb3a%40huawei.com</a>.<br />

--------------A272B108B4C815A0D985895D--
