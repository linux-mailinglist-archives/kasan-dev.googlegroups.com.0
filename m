Return-Path: <kasan-dev+bncBAABBGNCSSQQMGQEOLKZA6A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103b.google.com (mail-pj1-x103b.google.com [IPv6:2607:f8b0:4864:20::103b])
	by mail.lfdr.de (Postfix) with ESMTPS id 8386F6CFA35
	for <lists+kasan-dev@lfdr.de>; Thu, 30 Mar 2023 06:33:31 +0200 (CEST)
Received: by mail-pj1-x103b.google.com with SMTP id cp21-20020a17090afb9500b0023c061f2bd0sf8670340pjb.5
        for <lists+kasan-dev@lfdr.de>; Wed, 29 Mar 2023 21:33:31 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1680150809; cv=pass;
        d=google.com; s=arc-20160816;
        b=sr0+yrYMjgn2zH0CEJJe1+C3/KiuI6kdpe4ywz3JOj2TxEVwqst8aLWKbQf336E9Ph
         HESr1zMNVShx4KIokkqwzOmG5zhn9Lf9cOuBcvXwWx/6mW5VUIuwep/fUvU4XAjvvj5O
         A6NnxUtc13zSKooVwJTJ7P32kOOSy0/U0sUzi5d6X4Qxmg1K5PJB1+b5/vh0zGLvI/na
         sT4AMxMfNXnVgdbIGV405oAFykazQZbU+6n0PqPZDI9tuFu6IeUumfzmBb+OncBvlzuh
         YTZqyvrEYJHTnulV2qXeBAgWSbqOwv8X/Qu4Qq7He9XRs0vtyqPXmnH39NR4cpEsMzET
         7hcw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :content-language:in-reply-to:mime-version:user-agent:date
         :message-id:from:references:cc:to:subject:sender:dkim-signature;
        bh=BUVXCA2YDztiPH1a3YGAbEUTAfKguiesmaT5N2K1pVU=;
        b=MtiQpbPIc/Y5MdNsZVHPq7bNvtiseijIToCBaYlTvXSOUPRl/AcGEX4RL8KE0+UucY
         jB7SRyIKtGi6ZGoJoqNJmNaZMM3a1kzumCxQV6TiPnVloVgK2ly5GN5U2ZMob9FaPfaK
         IseQHqZwaM/C3iVgZFISluYSS/Ck6a6VhXd07Y3iAracZKXCtRnMtXF0sU7W3o+6+HwV
         RqTML/OazOXWXICXAb/bJDXvFxUwOcVR82sProLKlx/WsRAOnJJmFh7SCqGFDjWaZT+M
         eZgcAmGiZ2d5/OPCGwbnx/yFrCe2YQZ0+7ovINOOenBKPPLq89BU3P/IzmnCXBfmA8yZ
         A+bA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of zhangqing@loongson.cn designates 114.242.206.163 as permitted sender) smtp.mailfrom=zhangqing@loongson.cn
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112; t=1680150809;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:content-language
         :in-reply-to:mime-version:user-agent:date:message-id:from:references
         :cc:to:subject:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=BUVXCA2YDztiPH1a3YGAbEUTAfKguiesmaT5N2K1pVU=;
        b=sQiQ5jzkuiSWwkwHPAC78l5ys10rKEY7C2IeWvBjiKn7KxV4HzqaHM1+F7o1fqzdoX
         YEgmfoNTOooGvd6ifNmcik9mPLBkCpBsMuz0/3xRd1JOhHBraN0ZtZVrHAiSEWmfyaHQ
         wf0b6++w6Xp+I/NCRJJDviCVw3FdmIXALkqodYvquHGq3gBeRyYwl0V74UyiVFk1el/d
         /FkY7wonOnEH/vnvLB0Qw5SBtVA7xPgIQDHFK0At/GWaIFtMX4J7oDbKfia6KS56wRus
         X62QGhHj1mspA9Ie6NEd4wPLPbIEjcmAw2shFuPtZ60+1AikzU8BCuanmSRKswHFYxGF
         GAgQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1680150809;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=BUVXCA2YDztiPH1a3YGAbEUTAfKguiesmaT5N2K1pVU=;
        b=lrMEkkUoK81GzL6xu3+DDsVu7pBTGhtTzmeJseVDuM3ezW4JEWy8hyVAoUFbQSyOdh
         cjp+tUPAuRPTzvNcWdlGYQnAzHv6IUSeO2dnHeXr8deTAWESDVCBguBdzk39Fbmz4CyY
         sPOEVdcABgUBz1W8ugr/CQFVMZABj0NSSKgsrd2N57EbyR63HAk7zBsyFy8ZkVTqps5K
         yai10hMD0nf8yEXDQRPvEkJ8BCBodJMMoAG/pGTn8H1O8KsPPc5T3bUl2jAkgKLqGobf
         xxja97HnwI5/nvyIqpBYlp0nYLMwlvExcSzIz2J8QaG61fXp+Xjl/wasLCu+aGue32BE
         9f/A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AAQBX9ePqxLnBzeO09zPLNNrzRw4qBZDeNgdxQVoonNQQEdOtBZZCYoW
	K4vCHVbsgtnNEzmXL0/cIoY=
X-Google-Smtp-Source: AKy350bAxGubCyhoePKtjvIspJvDpxn6ysFSB/AOvMkn0Qn9pU06IeykeL7bajkqcyCgq1Zrg4kFLQ==
X-Received: by 2002:a05:6a00:2185:b0:623:8990:470a with SMTP id h5-20020a056a00218500b006238990470amr10657986pfi.4.1680150809386;
        Wed, 29 Mar 2023 21:33:29 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:903:2843:b0:194:d87a:ffa6 with SMTP id
 kq3-20020a170903284300b00194d87affa6ls835339plb.1.-pod-prod-gmail; Wed, 29
 Mar 2023 21:33:28 -0700 (PDT)
X-Received: by 2002:a17:90b:1a88:b0:237:50b6:9843 with SMTP id ng8-20020a17090b1a8800b0023750b69843mr4757650pjb.0.1680150808689;
        Wed, 29 Mar 2023 21:33:28 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1680150808; cv=none;
        d=google.com; s=arc-20160816;
        b=pIhNxDh+aWgmJ1BqDbTrDTlAmAgKaOWy0vhK+Cgq2E+3OVsQLIh04k+xOwCIifKTn3
         kSAMX2BiFlOkfQkrkAvFjwSDslix7SqFn9126dVK/RraK3CeXQLzU17z6nDhgdbU9A3n
         nSw5WVDudFoN+8Oqtu81DBY4cRtj/7hxeTaMcDvqBDLYSg/noY3t7hzQkPzyRpEY2JwN
         tDzT1OYZHy514Pzrc2riGg9aYWSJE2NTztPtMGhiT45ccx0iYiS7YaXTesATrwk0ov5Z
         AD1Ch4NmvwDOeIoeThFf/pMkdbIw38na5RJFhOhbV+sPHzx5yv6ri0VcB1EHa2a7N39c
         GhoQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=7v9P1XQ2IsfaOpFQO1XMCg59C4NbmctoVAztoQeGuiI=;
        b=k3QJ5KBRARjUDKaFrrXZL80mQzPSoD6RQFE6psS3qykNsYnPCFtoxTpMaKlzP2cHvh
         fpXE71aCuy6lX6KNwZJbqsultaZCsY8dR8FPcJYnrhPreOycE/8dqkFMlICYgp6v1Aq+
         KmTvR7ssELisKm6htY7+nUTOOJ72VLfOULMroZu+/8/7/uN3Upy9j4xFWzvOAbwGr1WE
         ZyHnHQ1mZpwn7Rqav0ndr+Od8HaV7beVCI6DSZV+VQ0olzLHZHBbZWOrS36NXJem/Fi9
         IB/SjFDlekAC0XTpGMwFEMdV3WNv4izf13ijnubHw8iSlchLjOvGyCAPS3jF/Fgf3wjU
         l3zg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of zhangqing@loongson.cn designates 114.242.206.163 as permitted sender) smtp.mailfrom=zhangqing@loongson.cn
Received: from loongson.cn (mail.loongson.cn. [114.242.206.163])
        by gmr-mx.google.com with ESMTP id o9-20020a17090ac08900b002405490a573si161086pjs.0.2023.03.29.21.33.27
        for <kasan-dev@googlegroups.com>;
        Wed, 29 Mar 2023 21:33:28 -0700 (PDT)
Received-SPF: pass (google.com: domain of zhangqing@loongson.cn designates 114.242.206.163 as permitted sender) client-ip=114.242.206.163;
Received: from loongson.cn (unknown [113.200.148.30])
	by gateway (Coremail) with SMTP id _____8AxYeX4ECVkjjcUAA--.31308S3;
	Thu, 30 Mar 2023 12:32:56 +0800 (CST)
Received: from [10.130.0.102] (unknown [113.200.148.30])
	by localhost.localdomain (Coremail) with SMTP id AQAAf8CxLuT1ECVkA_oQAA--.48468S3;
	Thu, 30 Mar 2023 12:32:55 +0800 (CST)
Subject: Re: [PATCH] LoongArch: Add kernel address sanitizer support
To: Andrey Konovalov <andreyknvl@gmail.com>
Cc: Jonathan Corbet <corbet@lwn.net>, Huacai Chen <chenhuacai@kernel.org>,
 Andrew Morton <akpm@linux-foundation.org>,
 Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>,
 Vincenzo Frascino <vincenzo.frascino@arm.com>,
 WANG Xuerui <kernel@xen0n.name>, Jiaxun Yang <jiaxun.yang@flygoat.com>,
 kasan-dev@googlegroups.com, linux-doc@vger.kernel.org, linux-mm@kvack.org,
 loongarch@lists.linux.dev, linux-kernel@vger.kernel.org,
 linux-hardening@vger.kernel.org, Andrey Ryabinin <ryabinin.a.a@gmail.com>
References: <20230328111714.2056-1-zhangqing@loongson.cn>
 <CA+fCnZevgYh7CzJ9gOWJ80SwY4Y9w8UO2ZiFAXEnAhQhFgrffA@mail.gmail.com>
 <dccfbff3-7bad-de33-4d96-248bdff44a8b@loongson.cn>
 <CA+fCnZddt50+10SZ+hZRKBudsmMF0W9XpsDG6=58p1ot62LjXQ@mail.gmail.com>
From: Qing Zhang <zhangqing@loongson.cn>
Message-ID: <2360000f-7292-9da8-d6b5-94b125c5f2b0@loongson.cn>
Date: Thu, 30 Mar 2023 12:32:53 +0800
User-Agent: Mozilla/5.0 (X11; Linux mips64; rv:68.0) Gecko/20100101
 Thunderbird/68.7.0
MIME-Version: 1.0
In-Reply-To: <CA+fCnZddt50+10SZ+hZRKBudsmMF0W9XpsDG6=58p1ot62LjXQ@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Language: en-US
Content-Transfer-Encoding: quoted-printable
X-CM-TRANSID: AQAAf8CxLuT1ECVkA_oQAA--.48468S3
X-CM-SenderInfo: x2kd0wptlqwqxorr0wxvrqhubq/
X-Coremail-Antispam: 1Uk129KBjvJXoWrKF4xGryxJF48Aw18Ww4UJwb_yoW8Jr4rpa
	40kF95trsYyFn2vwn2kw1rtryjyF1fury3WFn8Kw1Fya4Y9Fy8KF1rGa4rCFykXrWxGw1Y
	vwnFyasxJr4UAaDanT9S1TB71UUUUUDqnTZGkaVYY2UrUUUUj1kv1TuYvTs0mT0YCTnIWj
	qI5I8CrVACY4xI64kE6c02F40Ex7xfYxn0WfASr-VFAUDa7-sFnT9fnUUIcSsGvfJTRUUU
	bIxYFVCjjxCrM7AC8VAFwI0_Jr0_Gr1l1xkIjI8I6I8E6xAIw20EY4v20xvaj40_Wr0E3s
	1l1IIY67AEw4v_Jrv_JF1l8cAvFVAK0II2c7xJM28CjxkF64kEwVA0rcxSw2x7M28EF7xv
	wVC0I7IYx2IY67AKxVWUCVW8JwA2z4x0Y4vE2Ix0cI8IcVCY1x0267AKxVW8JVWxJwA2z4
	x0Y4vEx4A2jsIE14v26r4UJVWxJr1l84ACjcxK6I8E87Iv6xkF7I0E14v26r4UJVWxJr1l
	e2I262IYc4CY6c8Ij28IcVAaY2xG8wAqjxCEc2xF0cIa020Ex4CE44I27wAqx4xG64xvF2
	IEw4CE5I8CrVC2j2WlYx0E2Ix0cI8IcVAFwI0_Jrv_JF1lYx0Ex4A2jsIE14v26r4j6F4U
	McvjeVCFs4IE7xkEbVWUJVW8JwACjcxG0xvEwIxGrwCYjI0SjxkI62AI1cAE67vIY487Mx
	AIw28IcxkI7VAKI48JMxC20s026xCaFVCjc4AY6r1j6r4UMI8I3I0E5I8CrVAFwI0_Jr0_
	Jr4lx2IqxVCjr7xvwVAFwI0_JrI_JrWlx4CE17CEb7AF67AKxVW8ZVWrXwCIc40Y0x0EwI
	xGrwCI42IY6xIIjxv20xvE14v26r1j6r1xMIIF0xvE2Ix0cI8IcVCY1x0267AKxVWUJVW8
	JwCI42IY6xAIw20EY4v20xvaj40_Jr0_JF4lIxAIcVC2z280aVAFwI0_Gr0_Cr1lIxAIcV
	C2z280aVCY1x0267AKxVW8JVW8JrUvcSsGvfC2KfnxnUUI43ZEXa7IU8vApUUUUUU==
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



On 2023/3/30 =E4=B8=8A=E5=8D=8810:55, Andrey Konovalov wrote:
> On Thu, Mar 30, 2023 at 4:06=E2=80=AFAM Qing Zhang <zhangqing@loongson.cn=
> wrote:
>>
>>> But I don't think you need this check here at all: addr_has_metadata
>>> already checks that shadow exists.
>>>
>> On LongArch, there's a lot of holes between different segments, so kasan
>> shadow area is some different type of memory that we concatenate, we
>> can't use if (unlikely((void *)addr <
>> kasan_shadow_to_mem((void *)KASAN_SHADOW_START))) to determine the
>> validity, and in arch/loongarch/include/asm/kasan.h I construct invalid
>> NULL.
>=20
> I get that, but you already added a special case for
> __HAVE_ARCH_SHADOW_MAP to addr_has_metadata, so you can just call it?
>=20
ok, all the changes are going to be in v2.

Thanks,
-Qing
>> This is because in pagetable_init on loongarch/mips, we populate pmd/pud
>> with invalid_pmd_table/invalid_pud_table,
>=20
> I see. Please add this into the patch description for v2.
>=20
>> So pmd_init/pud_init(p) is required, perhaps we define them as __weak in
>> mm/kasan/init.c, like mm/sparse-vmemmap.c.
>=20
> Yes, this makes sense to do, so that KASAN doesn't depend on
> definitions from sparse-vmemmap.c.
>=20
> Thank you!
>=20

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/2360000f-7292-9da8-d6b5-94b125c5f2b0%40loongson.cn.
