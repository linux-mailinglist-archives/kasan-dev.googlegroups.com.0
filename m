Return-Path: <kasan-dev+bncBAABBTHIW67QMGQEC6VTSOA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83f.google.com (mail-qt1-x83f.google.com [IPv6:2607:f8b0:4864:20::83f])
	by mail.lfdr.de (Postfix) with ESMTPS id 184ADA79A00
	for <lists+kasan-dev@lfdr.de>; Thu,  3 Apr 2025 04:37:02 +0200 (CEST)
Received: by mail-qt1-x83f.google.com with SMTP id d75a77b69052e-4768a1420b6sf6978731cf.1
        for <lists+kasan-dev@lfdr.de>; Wed, 02 Apr 2025 19:37:02 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1743647821; cv=pass;
        d=google.com; s=arc-20240605;
        b=JvCd909RF38YYKtH+NMq5LGQj/o30p53tyN8+MjIz56GVGuvkCbqSO1EG5CEACE85F
         lzqd305bBTMcyYCa1gvwux3fy2sR22a1xDz93sfMaES3oscCHmtphQvwYWCWFW3tjoIz
         I0mgLCLTPD6bZ2J4+HF6clnk1UKZw5v23KbfJb0V4fHw6wLYKOr3qwFKv3RZKnA4N83C
         rvEDJSeUlQMeKNMoAIR0zIdNCK/qHze6+wU1+QaqDJySHuoPfwuA535x3tzexetqQpEl
         mfzk8eCMTtTtWv7GIup6FKE5er0BXimrPPgUiaDeQ+ysdeKL3LjWP2NLI+PVv694aPVe
         Oa1g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :in-reply-to:from:references:cc:to:subject:user-agent:mime-version
         :date:message-id:dkim-signature;
        bh=pPV7YFFUaP09Pf4nzVaK4zwpiTpWhuFvcZYk5pWo3lA=;
        fh=nNAYocCp8hVPCEyxl/55UN/+hjboum3SO4w8CCg63E0=;
        b=dMSirelLUyv/id3mxbyKQgbkWUi4gnaqHBzN14Hg9uzqGBSqkTNfTWXowXufVxAQVK
         wFgcnEJPWDUCtSK9s+qGSDxvaCidz7fH+O0i9ZVpjk28jP+Y1Hnjpb2LhtzMVOUdAdmp
         GRJqQMNia9NJHjm48qKKpVyKbpNhod3E2t6N1v96AIqO6TXlOYMfMwga0OPg5u+yG+eh
         w/6e0rbQ35rufI0PrWKOpcTjo6xO2sozQvwJ0t6SXPkgsRIleiQXyovHWXINAszgBozW
         bbPMsRnTdJ/Ym0x/Wbupt84B6+X/WRVXiFyuvvANR/Za+BBOWVvM/zhrTOhKJHkl+n4i
         bbtw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of tongtiangen@huawei.com designates 45.249.212.255 as permitted sender) smtp.mailfrom=tongtiangen@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1743647821; x=1744252621; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:from:references:cc:to:subject
         :user-agent:mime-version:date:message-id:from:to:cc:subject:date
         :message-id:reply-to;
        bh=pPV7YFFUaP09Pf4nzVaK4zwpiTpWhuFvcZYk5pWo3lA=;
        b=C1PcXr45N8xhCP/TKi+vbfMkAkkaXATd9k8UBKHd6UYirf21XrFpNiL9YrRHnK68bT
         zPxlo/bXLzrFStLxTEItwjy+z4qq3rOLCymc8p80FKuyYEpqb6ITlBvJra9HIu5uFdb+
         GGe+2PB7flRj9aAd8G/rCKbDUelOoW18D/MCUfL02XiKTXxu1Np3mLnI5lHHzAiwgx3C
         Waj0jSVyrnZZROSWZsHeqTLS8IYx5BmE6AvBWZPdl+LVjTekNQxCHMCZHXTI3yz8uyF7
         GzzRfdGtp04qaeSd53U1+684zebg0Cmqpt0WzRMx/B0xNxQHvF+r+wBwmjSRwp692NyL
         dbLg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1743647821; x=1744252621;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:from:references:cc:to:subject
         :user-agent:mime-version:date:message-id:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=pPV7YFFUaP09Pf4nzVaK4zwpiTpWhuFvcZYk5pWo3lA=;
        b=pK/WRb48lWrTpvT6w6nZ/jGTUXb43ALCRM+8kuOuTki3E70kTFBj0tMlUKprKRONgS
         9ToyIeDFt7Es8oysPWG5STR/Qu0nmUUKZEQdXflhzG8EIn+LXERKz3y3fR2uJ2XVmozi
         PP75+uOZUcojHsyFEwYas22W5NlYSG2mgk40ls518MGbUZdSYLdssTb0S9mAoNFdX5dQ
         KVkwsrKaqAOmv0cwF+KaqIBvZ+k+Rqcb2vhvBd/zcTa29Hze15/WJ/pzUxuJuU7pWRCi
         vkLDsNz9Xrnf8G2Id0F4t4nknk6PDa44iRdNaTcJ0a6p9prvHenU3HfxOAtB78MCl8Ev
         pEJw==
X-Forwarded-Encrypted: i=2; AJvYcCX9feizBk2xQjGZDTNBL9bGrx2P+AMz97gEDAaFe5iby79E0bcP1HUt5ItfnHCzSx5YNIhavg==@lfdr.de
X-Gm-Message-State: AOJu0YyI6KxFXxyN9pd/ajpLl3lm83b+jV9K0CfrSk7xrRr4CzlcRsDu
	7lyS5G6+g0HiBu2eVft9Lza5pIZMKE7uxpXxkeON+VvsmOIYr+Th
X-Google-Smtp-Source: AGHT+IHQHbZSTh1wbEN/jwY1aQRQP2y5kqGyXK9YaDvz0qK2iISYkJxxCGuCb+qjxpIOkKm34oGglg==
X-Received: by 2002:a05:622a:1445:b0:476:7c7b:5dce with SMTP id d75a77b69052e-47909f58442mr66843151cf.9.1743647820619;
        Wed, 02 Apr 2025 19:37:00 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARLLPAKamFynEwebI3HfCxurPIptvnqPkl7/TZEBjnCaEUtkcQ==
Received: by 2002:a05:622a:68c3:b0:476:7e35:1ce7 with SMTP id
 d75a77b69052e-4791615a0a4ls6879991cf.0.-pod-prod-03-us; Wed, 02 Apr 2025
 19:37:00 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVteKVgDegaS8ZhuIqzwKwFHCKVBEk6X3Pu9FKOEhUBdvI7wwyeWTX25MMSnK/vdhQ4+EUUrRLup3E=@googlegroups.com
X-Received: by 2002:ac8:7dcf:0:b0:476:afd2:5b6f with SMTP id d75a77b69052e-47909fb197fmr64857901cf.29.1743647819844;
        Wed, 02 Apr 2025 19:36:59 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1743647819; cv=none;
        d=google.com; s=arc-20240605;
        b=RWnCudEubqsXDKP9C1JMfIkJ1D0hFbGNzlKaiMZo5NMBQobu0bGV1wj4FSm3QoJygj
         Dphjw8O1SjEUbVPELIBm3On8RYubz2ZDqMjArrnVjAW35m5u7a6jE2N3CrRECRbF99GN
         0c6n+gT1EF5dnVEdSIy8klSo1sJ39imzxL+I4Ur4tghBu7gSpb2qlkY5bA6uOzSHBnHY
         BoAMCATfRACWSfubT0p7aLCl+uTOMK/ognBoIE8AxUkQv+CnrK/nOVq2aWhhqnJKp7mZ
         3XtevbXindMAew45SAG6r71QP+nDPI+nbQv9QzoMSatjWKkFCJlQifT2PMsNYMT+QdNC
         FDRQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to:subject
         :user-agent:mime-version:date:message-id;
        bh=XZv1gSCoqPkSvuRo5CdsTOUa2UhovNSLORAb5XIYnJ4=;
        fh=odEzHQSpxsvaEy2xGaL7yQk6k8wlREYj5HZ1d/G5syA=;
        b=BlGMTOCtE9GzIlHQB4+Tshenf/PoSaak3W37HOMbC6HbQD7YuwrAIJuFbyI7fQUvf1
         5PJGNTWOjsD4yla7/wlpxWi3F9JrUdagNwkmbsiMFMmGwmDPYXQFPGORwRSqxuBRAmY8
         HL7mYuyatCTepCLN4LEjrOsmGiNQbFYaa+Xs4ltIW1ZGLrFFDbwPNpHQYcepOIOVtk28
         akGyunqXMlAGP5ZXFTf+4PVcteNQrkeXteC2l188tlMbwwI3uoGGWKJKR/Dfsv1yf5a9
         XRKu1/to64V50+plVFETo7w5ySN382cuGC+AxTMMcOlfGHmHw2ZfHyDNMUf6nD4647So
         6ctA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of tongtiangen@huawei.com designates 45.249.212.255 as permitted sender) smtp.mailfrom=tongtiangen@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
Received: from szxga08-in.huawei.com (szxga08-in.huawei.com. [45.249.212.255])
        by gmr-mx.google.com with ESMTPS id d75a77b69052e-4791aef8058si146591cf.0.2025.04.02.19.36.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 02 Apr 2025 19:36:59 -0700 (PDT)
Received-SPF: pass (google.com: domain of tongtiangen@huawei.com designates 45.249.212.255 as permitted sender) client-ip=45.249.212.255;
Received: from mail.maildlp.com (unknown [172.19.88.194])
	by szxga08-in.huawei.com (SkyGuard) with ESMTP id 4ZSm842dzTz1d0rb;
	Thu,  3 Apr 2025 10:36:20 +0800 (CST)
Received: from kwepemk500005.china.huawei.com (unknown [7.202.194.90])
	by mail.maildlp.com (Postfix) with ESMTPS id D73ED140383;
	Thu,  3 Apr 2025 10:36:52 +0800 (CST)
Received: from [10.174.179.234] (10.174.179.234) by
 kwepemk500005.china.huawei.com (7.202.194.90) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.2.1544.11; Thu, 3 Apr 2025 10:36:50 +0800
Message-ID: <78f82bf6-ec47-6b10-7c05-2189cc262f13@huawei.com>
Date: Thu, 3 Apr 2025 10:36:49 +0800
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:91.0) Gecko/20100101
 Thunderbird/91.8.0
Subject: Re: [PATCH v13 2/5] arm64: add support for ARCH_HAS_COPY_MC
To: Yeoreum Yun <yeoreum.yun@arm.com>
CC: Catalin Marinas <catalin.marinas@arm.com>, Mark Rutland
	<mark.rutland@arm.com>, Jonathan Cameron <Jonathan.Cameron@huawei.com>, Mauro
 Carvalho Chehab <mchehab+huawei@kernel.org>, Will Deacon <will@kernel.org>,
	Andrew Morton <akpm@linux-foundation.org>, James Morse <james.morse@arm.com>,
	Robin Murphy <robin.murphy@arm.com>, Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino
	<vincenzo.frascino@arm.com>, Michael Ellerman <mpe@ellerman.id.au>, Nicholas
 Piggin <npiggin@gmail.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>, Christophe Leroy
	<christophe.leroy@csgroup.eu>, Aneesh Kumar K.V <aneesh.kumar@kernel.org>,
	"Naveen N. Rao" <naveen.n.rao@linux.ibm.com>, Thomas Gleixner
	<tglx@linutronix.de>, Ingo Molnar <mingo@redhat.com>, Borislav Petkov
	<bp@alien8.de>, Dave Hansen <dave.hansen@linux.intel.com>, <x86@kernel.org>,
	"H. Peter Anvin" <hpa@zytor.com>, Madhavan Srinivasan <maddy@linux.ibm.com>,
	<linux-arm-kernel@lists.infradead.org>, <linux-mm@kvack.org>,
	<linuxppc-dev@lists.ozlabs.org>, <linux-kernel@vger.kernel.org>,
	<kasan-dev@googlegroups.com>, <wangkefeng.wang@huawei.com>, Guohanjun
	<guohanjun@huawei.com>
References: <20241209024257.3618492-1-tongtiangen@huawei.com>
 <20241209024257.3618492-3-tongtiangen@huawei.com> <Z6zKfvxKnRlyNzkX@arm.com>
 <df40840d-e860-397d-60bd-02f4b2d0b433@huawei.com>
 <Z+bXE7UNWFLEfhQC@e129823.arm.com>
From: "'Tong Tiangen' via kasan-dev" <kasan-dev@googlegroups.com>
In-Reply-To: <Z+bXE7UNWFLEfhQC@e129823.arm.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Transfer-Encoding: quoted-printable
X-Originating-IP: [10.174.179.234]
X-ClientProxiedBy: dggems701-chm.china.huawei.com (10.3.19.178) To
 kwepemk500005.china.huawei.com (7.202.194.90)
X-Original-Sender: tongtiangen@huawei.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of tongtiangen@huawei.com designates 45.249.212.255 as
 permitted sender) smtp.mailfrom=tongtiangen@huawei.com;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
X-Original-From: Tong Tiangen <tongtiangen@huawei.com>
Reply-To: Tong Tiangen <tongtiangen@huawei.com>
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



=E5=9C=A8 2025/3/29 1:06, Yeoreum Yun =E5=86=99=E9=81=93:
> Hi,
>=20
>>
>>
>> =E5=9C=A8 2025/2/13 0:21, Catalin Marinas =E5=86=99=E9=81=93:
>>> (catching up with old threads)
>>>
>>> On Mon, Dec 09, 2024 at 10:42:54AM +0800, Tong Tiangen wrote:
>>>> For the arm64 kernel, when it processes hardware memory errors for
>>>> synchronize notifications(do_sea()), if the errors is consumed within =
the
>>>> kernel, the current processing is panic. However, it is not optimal.
>>>>
>>>> Take copy_from/to_user for example, If ld* triggers a memory error, ev=
en in
>>>> kernel mode, only the associated process is affected. Killing the user
>>>> process and isolating the corrupt page is a better choice.
>>>
>>> I agree that killing the user process and isolating the page is a bette=
r
>>> choice but I don't see how the latter happens after this patch. Which
>>> page would be isolated?
>>
>> The SEA is triggered when the page with hardware error is read. After
>> that, the page is isolated in memory_failure() (mf). The processing of
>> mf is mentioned in the comments of do_sea().
>>
>> /*
>>   * APEI claimed this as a firmware-first notification.
>>   * Some processing deferred to task_work before ret_to_user().
>>   */
>>
>> Some processing include mf.
>>
>>>
>>>> Add new fixup type EX_TYPE_KACCESS_ERR_ZERO_MEM_ERR to identify insn
>>>> that can recover from memory errors triggered by access to kernel memo=
ry,
>>>> and this fixup type is used in __arch_copy_to_user(), This make the re=
gular
>>>> copy_to_user() will handle kernel memory errors.
>>>
>>> Is the assumption that the error on accessing kernel memory is
>>> transient? There's no way to isolate the kernel page and also no point
>>> in isolating the destination page either.
>>
>> Yes, it's transient, the kernel page in mf can't be isolated, the
>> transient access (ld) of this kernel page is currently expected to kill
>> the user-mode process to avoid error spread.
>=20
> I'm not sure about how this works.
> IIUC, the memory_failure() wouldn't kill any process if page which
> raises sea is kernel page (because this wasn't mapped).

right.

>=20
> But, to mark the kernel page as posision, I think it also need to call
> apei_claim_sea() in !user_mode().
> What about calling the apei_claim_sea() when fix_exception_me()
> successed only in !user_mode() case?

This was discussed with Mark in V12:
https://lore.kernel.org/lkml/20240528085915.1955987-3-tongtiangen@huawei.co=
m/

Sorry for didn't catch your reply in time:)

Thanks,
Tong.

>=20
> Thanks.
>>
>> The SEA processes synchronization errors. Only hardware errors on the
>> source page can be detected (Through synchronous ld insn) and processed.
>> The destination page cannot be processed.
>>
>>>
>>
> .

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/7=
8f82bf6-ec47-6b10-7c05-2189cc262f13%40huawei.com.
