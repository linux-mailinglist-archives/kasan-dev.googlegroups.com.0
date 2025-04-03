Return-Path: <kasan-dev+bncBAABB3PNW67QMGQENSXRDYQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3a.google.com (mail-qv1-xf3a.google.com [IPv6:2607:f8b0:4864:20::f3a])
	by mail.lfdr.de (Postfix) with ESMTPS id C22C9A79A1E
	for <lists+kasan-dev@lfdr.de>; Thu,  3 Apr 2025 04:48:14 +0200 (CEST)
Received: by mail-qv1-xf3a.google.com with SMTP id 6a1803df08f44-6eeffdba0e2sf9507986d6.2
        for <lists+kasan-dev@lfdr.de>; Wed, 02 Apr 2025 19:48:14 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1743648493; cv=pass;
        d=google.com; s=arc-20240605;
        b=SS80lG8VhLLyXgcL2B+MB0turxy4uJOOLjppYOInC3Tn2SYxYf1DAudX6opy5Bws/X
         YrBGeJQyVpj9IFwGiPy7BCFawL+/l0FF2aBEFRizdPFaam0DqiDkHDtS1xwzR+diBFJJ
         WRxUbUQux3MNxyolGwWfvC8ejCLnxg7qKaV+T//QJsfvdYFGiRNHb4P1SKnZyP0qvs+n
         tEp4ymV9uC4gMHZjnMlHjSnCD+QY440XD/aWvlgBK94WBWmB7O9aRgtWqugSLjws1rrz
         vgO+zZsuUKKXyx+DK3VUt4t8FoEty4axuEiMLRzSX2PwwYj7MlxYus3u2szFxJK7wQaZ
         Vs8A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :in-reply-to:from:references:cc:to:subject:user-agent:mime-version
         :date:message-id:dkim-signature;
        bh=vuu4xlHYjBqCoOaz1S0pYlFzamonx+KMjOcj5H7zKks=;
        fh=x9/Kx1Dw3qJc1CUON5vv/a+ErkLZ4CElE6vc77g5p5o=;
        b=Tu0YY74tYCrQNnVRhDW5Tv3ZKicHIpAPtZyo3cqCfN5MAHxCW8oM4RvHpQsmxvpEEd
         cq5MxgFxtXKlsIz/FqX3lyWlmwiWJb60b+DumEG0pQmH2R/R+Q25Cx7GntUKzYAawVXP
         2Y0bYgnanYbAbKJCIENmMrmuqklc0YAOnN00h0iS6K7u2M5Tcs/kd/KwYlZMHf/EYBHu
         2n5etd6sI3kwsdiIPX+oeT4rmp5IqkWv/WxuPVeK/6ukKmr2IDw0RJB446CajwfCl5re
         GJZ7LNTfDMoZoW989ca5owRREdgYyiAx8S4/zivLdjCy9E//5vqYxbwtMAlyAvytQuDC
         VsHA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of tongtiangen@huawei.com designates 45.249.212.189 as permitted sender) smtp.mailfrom=tongtiangen@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1743648493; x=1744253293; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:from:references:cc:to:subject
         :user-agent:mime-version:date:message-id:from:to:cc:subject:date
         :message-id:reply-to;
        bh=vuu4xlHYjBqCoOaz1S0pYlFzamonx+KMjOcj5H7zKks=;
        b=ifO3Q/wymz7FEqECeFguHMuwGf9vmH1qRiNSRRDYbflUHoSvvT0Q60f+CLT7vODcmL
         B/Zx78JER6zEt2KGo/g4SIT3TgI011+Ca7rnYVZyTk6FseCCoPdiiqKwKKvqy8utpqxD
         94NDCXz5dpbZhLkjdK03BwxSAlJMx+yyofsk4SvggRpdMLIAEwi77VFyUxibFwxDH+6T
         0398LdLnMY1rYV8lHHoUFx/57b3RZD8ecjy5NRDV569OKkL5BQ6iZWvI67Xr4uSFo6w4
         /2H3UAkaW+4L8Sv9agEoTlQ1hCC5HROOT7K6OhwIK66HCJfYYFvx7WCHsb75ZPkgXmxN
         8g2g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1743648493; x=1744253293;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:from:references:cc:to:subject
         :user-agent:mime-version:date:message-id:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=vuu4xlHYjBqCoOaz1S0pYlFzamonx+KMjOcj5H7zKks=;
        b=tUcYhBzISsJaBvBOwo7vM0hhK4AOq5HKu64pjy9ZVEaTyHhMjDeMGnsBJgT6A0R8Ak
         OKX5HRH3vkfjpqoTchOaP1w4LFhaPqBckIerl7D7XNw0gpIJoQWI9UyfQOOxDVDupn3Q
         jG/KKoncvWg1B5bl7TdKc7yJpEp1omd7CgI3Kld8tdIZ/pT1ecazWI7dDGOR/MBnkz1R
         eTwGH1CPrr1iRQ4jOAsarp9yitk9ZETkyXCGC5VbSXd/aV/hlXJxDcHajXXsKljzSQNx
         lU8rKtAnYWnjea+gubHo5OFMtcUOAf+FKLXTVwnALNw+bLvgF904gC4kZCRg9C6a7GGw
         rJww==
X-Forwarded-Encrypted: i=2; AJvYcCUZe0i+XogBk0ZwKT7fjbX0k17JfQTqPauYRN2sbBiasqQM2yy13RIeBRcQ5NuI8A/sI7v1ig==@lfdr.de
X-Gm-Message-State: AOJu0YxUpZjtAmOrPCYVfuG0c/wbow8k6DS/J42Sj4tgtpPr172PMNAe
	dToeIhZGUHP2veh7/2M2mUtfLiPMdAooQRLwgXHXAnLD5Uk/zLpo
X-Google-Smtp-Source: AGHT+IFjKH2qGz+C9+1ECa0nnwTPhbEc5nB9NKU5m5ajoBcPpUEtZnT3GNUAcTlM7sZo2qGE34kyqg==
X-Received: by 2002:a05:6214:da7:b0:6cb:ee08:c1e8 with SMTP id 6a1803df08f44-6eed624eedbmr279479006d6.23.1743648493437;
        Wed, 02 Apr 2025 19:48:13 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARLLPAIezb1RB/rx4IqYurVeXitH4bgLV5+XPHa26i5KOdPA+A==
Received: by 2002:a05:6214:4381:b0:6e8:f3c7:337d with SMTP id
 6a1803df08f44-6ef0bd6f1c0ls10405726d6.0.-pod-prod-09-us; Wed, 02 Apr 2025
 19:48:12 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXv41OYa4LYEefHtWoKiTtq2D8DnlbCd7eJEJOsKEo0YlAT1aaGApbN8likCwM0CgxqtV8D4lsyDwg=@googlegroups.com
X-Received: by 2002:a05:620a:404d:b0:7c5:6e5d:301d with SMTP id af79cd13be357-7c6862e57c3mr2624142885a.1.1743648492683;
        Wed, 02 Apr 2025 19:48:12 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1743648492; cv=none;
        d=google.com; s=arc-20240605;
        b=Yp6LE0F9AHLMIdGrHXOWnhmpj4sitXZO6uiJoIpUMQXglH/zV/jOOua0Hx/zZabAdW
         GjeJ+Gb8dXY83rwe8mDQVBjxWNesbqX+rWEgbemAko+rC7q/Ymy4g5HUSs2xFdXzSqiM
         vmsnWTI3r0ceHVZYpGHuqKWnDTkMQHnUuYP/e+77ZF76JhZuuu7PqV2y7ury9GbcChnO
         7oUcDl6cSHg6cz6jVC5C+XYq+5U1rMiX1TR3gqSWAgoi/VG5J1EywqX2PpKhiZ3dsJw2
         qf45AOhja6qEisd6P8L7swDnu0R/be91MWqMg7lsJPFGvIWyTp4ru3E8UwlkTFDzT/B0
         z1Ng==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to:subject
         :user-agent:mime-version:date:message-id;
        bh=If1ZsNgrBBDERc1MRA+MXXmaA+so/oBkFX2K0q6MNvI=;
        fh=1y/CY89gPecoyn0XwogOk3uRHcKNTP0J2T0aOfHSHCc=;
        b=OoyA7niTdYo6GBp4fo+NRqcy/HoTujFwxW7fmGbN9uKXdAz4+uan+V0z6qUnqVtMFp
         9o6GZZQlzu6ybKW+S4Y/2Xfp5d+JlrUrPdusYclIQwpoYDSyyBJyS4amIwvLP/48HULJ
         63rokD2/touzH9ehZU0ptTblIEX1DcX6pklI1v59WgMtVgajhQv74mldoJAD3PVE1lUO
         6xDRTfrkeWdc0+36YPRjCZ/rsPOzlJkgPlaD87d6yT52fZOje/pLRLFzO8FGlzJ/kbjw
         vf5lcA9U8g/23fUhKEQuCZwmRVJX7O6mnImgjUDoOnPVJzHU4mByQytvVbMfX85AzJty
         AWWQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of tongtiangen@huawei.com designates 45.249.212.189 as permitted sender) smtp.mailfrom=tongtiangen@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
Received: from szxga03-in.huawei.com (szxga03-in.huawei.com. [45.249.212.189])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-6ef0f122098si160676d6.8.2025.04.02.19.48.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 02 Apr 2025 19:48:12 -0700 (PDT)
Received-SPF: pass (google.com: domain of tongtiangen@huawei.com designates 45.249.212.189 as permitted sender) client-ip=45.249.212.189;
Received: from mail.maildlp.com (unknown [172.19.163.252])
	by szxga03-in.huawei.com (SkyGuard) with ESMTP id 4ZSmKq0chQzHrDQ;
	Thu,  3 Apr 2025 10:44:47 +0800 (CST)
Received: from kwepemk500005.china.huawei.com (unknown [7.202.194.90])
	by mail.maildlp.com (Postfix) with ESMTPS id B33E31800EB;
	Thu,  3 Apr 2025 10:48:07 +0800 (CST)
Received: from [10.174.179.234] (10.174.179.234) by
 kwepemk500005.china.huawei.com (7.202.194.90) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.2.1544.11; Thu, 3 Apr 2025 10:48:05 +0800
Message-ID: <82bf1b64-d887-c50b-17b1-2de978896d44@huawei.com>
Date: Thu, 3 Apr 2025 10:48:04 +0800
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:91.0) Gecko/20100101
 Thunderbird/91.8.0
Subject: Re: [PATCH v13 2/5] arm64: add support for ARCH_HAS_COPY_MC
To: "Luck, Tony" <tony.luck@intel.com>
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
 <Z-GOKgBNxKWQ21w4@agluck-desk3>
From: "'Tong Tiangen' via kasan-dev" <kasan-dev@googlegroups.com>
In-Reply-To: <Z-GOKgBNxKWQ21w4@agluck-desk3>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Transfer-Encoding: quoted-printable
X-Originating-IP: [10.174.179.234]
X-ClientProxiedBy: dggems705-chm.china.huawei.com (10.3.19.182) To
 kwepemk500005.china.huawei.com (7.202.194.90)
X-Original-Sender: tongtiangen@huawei.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of tongtiangen@huawei.com designates 45.249.212.189 as
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



=E5=9C=A8 2025/3/25 0:54, Luck, Tony =E5=86=99=E9=81=93:
> On Fri, Feb 14, 2025 at 09:44:02AM +0800, Tong Tiangen wrote:
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
>>
>>
>> The SEA processes synchronization errors. Only hardware errors on the
>> source page can be detected (Through synchronous ld insn) and processed.
>> The destination page cannot be processed.
>=20
> I've considered the copy_to_user() case as only partially fixable. There
> are lots of cases to consider:
>=20
> 1) Many places where drivers copy to user in ioctl(2) calls.
>     Killing the application solves the immediate problem, but if
>     the problem with kernel memory is not transient, then you
>     may run into it again.
>=20
> 2) Copy from Linux page cache to user for a read(2) system call.
>     This one is a candidate for recovery. Might need help from the
>     file system code. If the kernel page is a clean copy of data in
>     the file system, then drop this page and re-read from storage
>     into a new page. Then resume the copy_to_user().
>     If the page is modified, then need some file system action to
>     somehow mark this range of addresses in the file as lost forever.
>     First step in tackling this case is identifying that the source
>     address is a page cache page.
>=20
> 3) Probably many other places where the kernel copies to user for
>     other system calls. Would need to look at these on a case by case
>     basis. Likely most have the same issue as ioctl(2) above.

1) 3)
Yes, in extreme cases, user-mode processes may be killed all the time.
The hardware error that repeatedly triggered in the same page, in this
case, firmware maybe report a fatal error, if yes, this problem can be
solved.

2)
This is indeed a workaround, somewhat complex, but it seems worthwhile
to avoid kernel panic.

Sorry for didn't catch your reply in time:)

Thanks,
Tong.

>=20
> -Tony
>=20
> .

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/8=
2bf1b64-d887-c50b-17b1-2de978896d44%40huawei.com.
