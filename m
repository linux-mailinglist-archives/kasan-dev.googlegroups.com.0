Return-Path: <kasan-dev+bncBAABBXO4ZO6QMGQE2TYMJUQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x838.google.com (mail-qt1-x838.google.com [IPv6:2607:f8b0:4864:20::838])
	by mail.lfdr.de (Postfix) with ESMTPS id 5067AA37CC4
	for <lists+kasan-dev@lfdr.de>; Mon, 17 Feb 2025 09:07:58 +0100 (CET)
Received: by mail-qt1-x838.google.com with SMTP id d75a77b69052e-471d95e196asf22553931cf.2
        for <lists+kasan-dev@lfdr.de>; Mon, 17 Feb 2025 00:07:58 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1739779677; cv=pass;
        d=google.com; s=arc-20240605;
        b=hjvyGABWpV2e3i37KzlIPnGrgIXaq7K83M4i6xG3YZHV5VtnSSUg+7M9U0ewlXOt7j
         EAP84xNh9Q9XZELxtvMMrGiDU/yEcqFrFCjvpqD04uVrDke565+7ZPF2VKde19LblnRO
         7itwvjuucm/6EK8VnlIYYFfRmqBWLI12kLnis7pjw6lvDwglr2xt70+2gafZa1Wx/UVJ
         /774LKfdAg28df1nW4XaRVbBKt+JxiDBzSvz2RsKn53s1VHGbbhQnZkPhKXoBOVsstd0
         MHEiiacH+wFMjKfbZZbuL7sPjqyiyPO3Skr2xSvhmCS89FKXnjV4d/LYcsbS6MeztE8f
         sfAg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :in-reply-to:from:references:cc:to:subject:user-agent:mime-version
         :date:message-id:dkim-signature;
        bh=XbjZRLYGxVV+QduNQ2rOuwwKzH5MmfWqt1BmZWWwJ+E=;
        fh=gdre72xx9U0zXWEIMcb5cvNN0rViAgbI7clRGsRaxUg=;
        b=YguiQuoQaOnkBMbOoQQ7oHnR6BCaHHcI3cbz/KvcNm6sL2OBiD/vfo2I7JXim+nGGK
         yNvuSdK5Y71YhG07IV9SrQg6SvmpGSz/mbKskzgGBoubGSZAN/EAJrIoZzR5vBpXPY8D
         4ByySwxy/N/QqUPaqKFYcEVL8WpCLqzB1YyWCUNT9KnWRJgDsy7dku4J4O+/xRmaD5/P
         jIHywRIxA7pmI8tNLEGi0zpN30YtKhH0/Pm8Xrrjx1a6I2I6/Vv7af2uMfH87iPARaBb
         kvgDXWjav8zIHpHFNiqOXPVCH4WmHMZAnU52YP+Hvg/RiA+vhmAF87mbXMye9kNxtmv9
         8/pQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of tongtiangen@huawei.com designates 45.249.212.190 as permitted sender) smtp.mailfrom=tongtiangen@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1739779677; x=1740384477; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:from:references:cc:to:subject
         :user-agent:mime-version:date:message-id:from:to:cc:subject:date
         :message-id:reply-to;
        bh=XbjZRLYGxVV+QduNQ2rOuwwKzH5MmfWqt1BmZWWwJ+E=;
        b=KvwqKz8azrQTAgEmORXPgbqlCYq6Ig1Re+EpMjmHT0pht/deiv7y25t4M0pabZc0mw
         ShaPytAv4TSHDozgCNo1GSC7ZtElugKn/+oZbpluh3hWqWYKah7BPvhtZ9lJ1YpbzBlr
         2fO+WZyU5SYpoOHrjTrMPXm+8oLFTd5EA/BJRdO2n2TJa57+P0lra+qhhdt0AZWyNHcV
         tXKCtMy21YGX0a0zcNoTJhkLsynLYc/yCCYn8iDBYfymk/7wAONh4CacNGgNF25eUsk8
         pgGzx44GfgZk3ziJ98BM8kb2E/zNDAZ5I3p1p+Kxm1PphnpJbYlHAn0IhYaDQjxCyL2B
         +mzQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1739779677; x=1740384477;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:from:references:cc:to:subject
         :user-agent:mime-version:date:message-id:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=XbjZRLYGxVV+QduNQ2rOuwwKzH5MmfWqt1BmZWWwJ+E=;
        b=q5YjTbf9vvULMrzUQ4vv/Tcnz4aknNIvuFLCDp6lN9Z1tS9W6fs61i7aFOR+wCzG4M
         QOSNG1V6TGW8ZiC6fEDAByt9PrUrUMyEwDkxWANnSFPVPVb4XvC3fLLXE6CvtwMvxzNT
         KB5QAw2dxNRH0e15wbppMSGq1cc68RbWu9iWYrgBH4wefxqUodtJaa3WGcQTIGwHE1em
         PSnNdrFqxPNFjyvaAu/pEfaqURver+B7W5QMrYDviTermgPmEcxsUToqWopvCVSpcYGB
         S1ggLT1+IqEXw7m/4K57qTevb3wDMxx4UViw57lTb9QuVB9wpQLLFVymYkJoRbIX9JwN
         kM4w==
X-Forwarded-Encrypted: i=2; AJvYcCVUidBk4aDqqcbz/whTAjkL9qvaM7f6sJJJ9hIQGI7TWLqlenp1jUlz2m2YIbihqVBebA3njw==@lfdr.de
X-Gm-Message-State: AOJu0Yzdyt5XBw3lKirX1Z9aWKtYeSpt5wq8pd90IeCxx86qAoWjTger
	6WqM3VNZjJebGW75B7Y+PIdnPai3La1HjSKxL1b/nDiZalGONBR2
X-Google-Smtp-Source: AGHT+IGfUqkG0c8vXFbb2kyCp+ScRMZHx8QgxqO8vJtWD4i3CygZ28CSYm1kfxTU+1afMADZpPZXIA==
X-Received: by 2002:ac8:7fc1:0:b0:471:d976:5678 with SMTP id d75a77b69052e-471dbd21f7fmr114717381cf.19.1739779677313;
        Mon, 17 Feb 2025 00:07:57 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVGz5W7MEKmeOCTxyOorDY8P7CViePon7SAKBw8UowqGAg==
Received: by 2002:ac8:74d6:0:b0:471:9d85:a0c5 with SMTP id d75a77b69052e-471bf2595ccls60920711cf.2.-pod-prod-08-us;
 Mon, 17 Feb 2025 00:07:56 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVuZbhAw6poKGqCueq32xl7RJDyEAqeVnlv4IFgBtbzE5iuCZwsz80x67EyNP8hjpDuODi5pic5Vzs=@googlegroups.com
X-Received: by 2002:a05:6122:2701:b0:520:6773:e5bf with SMTP id 71dfb90a1353d-5209da6c034mr2454611e0c.1.1739779676294;
        Mon, 17 Feb 2025 00:07:56 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1739779676; cv=none;
        d=google.com; s=arc-20240605;
        b=h2R7TVk8JwGNQZ0vHjSXOB3capauEppqEISw3hjbQhVsqDrtj33He8Mo99/0Q+Iscz
         Kk9aQeUXXI/p2bWrJwnHGr7YN8pTd6W0ntKTfY5sI2LputfrE56Xq1/Z255OHJ4ErRs2
         5Elog0YJ1FpejGw9ypJTGkuSoEGMEMp1JsNE+Sx/vf/lQ+15+5JOQCDTxVviHMq9l3Fa
         QRXijF47vXgrnnd34LcMCtO4Gj1qGSQi72qf/PQZb3/rcUgwdJLCpCH05PcPu9ZhHwsL
         Wm0Ub9c9GR+8L6tLPD0kqNtnTl1cdf0EyvhE1cFNtaBd3f/KW1iVFrApTD+mS30qN7y7
         baMg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to:subject
         :user-agent:mime-version:date:message-id;
        bh=qcLmadiNH84yKe/L4JYojk3Qejz7s9KQF2cXf3WqfYU=;
        fh=RzQbsIRJIGcsOahvYzttPrzbIb6n8kVsMKDOWJddbjk=;
        b=Y2nCGt3krMeQG2zheq3e9Lq7qzHhpjvpe58rxa3bTuFnRkRqxYjV95Z5k4lk4EViub
         XnrbWWrWX6RnTl2GbDU6phZDU37d/CUdJqpaI7FmfAdlnuPNa0HzjFEAvagUxd0Jc8W0
         4PuKASHuw8Qq8C1LiLxCOTNMuybh9MRlS4qCtY2/A+Jsp3mas4Bapmapwq6si0H9AMab
         Il+6bgigMAX5NSHpvLzgtqQDylusJsm+vQkoKE3gMkxJXWk0owzRRxxmZ+A6V8EjjBOj
         v7K6TWBf6todkU0Ohf6e4YYODDX5UmCBHt9B1tHp2r+VKGTJrm+LYDQPVcGmeDJl3fab
         QfNw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of tongtiangen@huawei.com designates 45.249.212.190 as permitted sender) smtp.mailfrom=tongtiangen@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
Received: from szxga04-in.huawei.com (szxga04-in.huawei.com. [45.249.212.190])
        by gmr-mx.google.com with ESMTPS id 71dfb90a1353d-5207aa6ef0bsi419577e0c.2.2025.02.17.00.07.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 17 Feb 2025 00:07:56 -0800 (PST)
Received-SPF: pass (google.com: domain of tongtiangen@huawei.com designates 45.249.212.190 as permitted sender) client-ip=45.249.212.190;
Received: from mail.maildlp.com (unknown [172.19.163.17])
	by szxga04-in.huawei.com (SkyGuard) with ESMTP id 4YxFXw2mFXz2JYY6;
	Mon, 17 Feb 2025 16:04:00 +0800 (CST)
Received: from kwepemk500005.china.huawei.com (unknown [7.202.194.90])
	by mail.maildlp.com (Postfix) with ESMTPS id 765EE1A0188;
	Mon, 17 Feb 2025 16:07:52 +0800 (CST)
Received: from [10.174.179.234] (10.174.179.234) by
 kwepemk500005.china.huawei.com (7.202.194.90) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.2.1544.11; Mon, 17 Feb 2025 16:07:50 +0800
Message-ID: <e1d2affb-5c6b-00b5-8209-34bbca36f96b@huawei.com>
Date: Mon, 17 Feb 2025 16:07:49 +0800
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:91.0) Gecko/20100101
 Thunderbird/91.8.0
Subject: Re: [PATCH v13 4/5] arm64: support copy_mc_[user]_highpage()
To: Catalin Marinas <catalin.marinas@arm.com>
CC: Mark Rutland <mark.rutland@arm.com>, Jonathan Cameron
	<Jonathan.Cameron@huawei.com>, Mauro Carvalho Chehab
	<mchehab+huawei@kernel.org>, Will Deacon <will@kernel.org>, Andrew Morton
	<akpm@linux-foundation.org>, James Morse <james.morse@arm.com>, Robin Murphy
	<robin.murphy@arm.com>, Andrey Konovalov <andreyknvl@gmail.com>, Dmitry
 Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Michael Ellerman <mpe@ellerman.id.au>, Nicholas Piggin <npiggin@gmail.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko
	<glider@google.com>, Christophe Leroy <christophe.leroy@csgroup.eu>, Aneesh
 Kumar K.V <aneesh.kumar@kernel.org>, "Naveen N. Rao"
	<naveen.n.rao@linux.ibm.com>, Thomas Gleixner <tglx@linutronix.de>, Ingo
 Molnar <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>, Dave Hansen
	<dave.hansen@linux.intel.com>, <x86@kernel.org>, "H. Peter Anvin"
	<hpa@zytor.com>, Madhavan Srinivasan <maddy@linux.ibm.com>,
	<linux-arm-kernel@lists.infradead.org>, <linux-mm@kvack.org>,
	<linuxppc-dev@lists.ozlabs.org>, <linux-kernel@vger.kernel.org>,
	<kasan-dev@googlegroups.com>, <wangkefeng.wang@huawei.com>, Guohanjun
	<guohanjun@huawei.com>
References: <20241209024257.3618492-1-tongtiangen@huawei.com>
 <20241209024257.3618492-5-tongtiangen@huawei.com> <Z6zWSXzKctkpyH7-@arm.com>
 <69955002-c3b1-459d-9b42-8d07475c3fd3@huawei.com> <Z698SFVqHjpGeGC0@arm.com>
From: "'Tong Tiangen' via kasan-dev" <kasan-dev@googlegroups.com>
In-Reply-To: <Z698SFVqHjpGeGC0@arm.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Transfer-Encoding: quoted-printable
X-Originating-IP: [10.174.179.234]
X-ClientProxiedBy: dggems706-chm.china.huawei.com (10.3.19.183) To
 kwepemk500005.china.huawei.com (7.202.194.90)
X-Original-Sender: tongtiangen@huawei.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of tongtiangen@huawei.com designates 45.249.212.190 as
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



=E5=9C=A8 2025/2/15 1:24, Catalin Marinas =E5=86=99=E9=81=93:
> On Fri, Feb 14, 2025 at 10:49:01AM +0800, Tong Tiangen wrote:
>> =E5=9C=A8 2025/2/13 1:11, Catalin Marinas =E5=86=99=E9=81=93:
>>> On Mon, Dec 09, 2024 at 10:42:56AM +0800, Tong Tiangen wrote:
>>>> Currently, many scenarios that can tolerate memory errors when copying=
 page
>>>> have been supported in the kernel[1~5], all of which are implemented b=
y
>>>> copy_mc_[user]_highpage(). arm64 should also support this mechanism.
>>>>
>>>> Due to mte, arm64 needs to have its own copy_mc_[user]_highpage()
>>>> architecture implementation, macros __HAVE_ARCH_COPY_MC_HIGHPAGE and
>>>> __HAVE_ARCH_COPY_MC_USER_HIGHPAGE have been added to control it.
>>>>
>>>> Add new helper copy_mc_page() which provide a page copy implementation=
 with
>>>> hardware memory error safe. The code logic of copy_mc_page() is the sa=
me as
>>>> copy_page(), the main difference is that the ldp insn of copy_mc_page(=
)
>>>> contains the fixup type EX_TYPE_KACCESS_ERR_ZERO_MEM_ERR, therefore, t=
he
>>>> main logic is extracted to copy_page_template.S. In addition, the fixu=
p of
>>>> MOPS insn is not considered at present.
>>>
>>> Could we not add the exception table entry permanently but ignore the
>>> exception table entry if it's not on the do_sea() path? That would save
>>> some code duplication.
>>
>> I'm sorry, I didn't catch your point, that the do_sea() and non do_sea()
>> paths use different exception tables?
>=20
> No, they would have the same exception table, only that we'd interpret
> it differently depending on whether it's a SEA error or not. Or rather
> ignore the exception table altogether for non-SEA errors.

You mean to use the same exception type (EX_TYPE_KACCESS_ERR_ZERO) and
then do different processing on SEA errors and non-SEA errors, right?

If so, some instructions of copy_page() did not add to the exception
table will be added to the exception table, and the original logic will
be affected.

For example, if an instruction is not added to the exception table, the
instruction will panic when it triggers a non-SEA error. If this
instruction is added to the exception table because of SEA processing,
and then a non-SEA error is triggered, should we fix it?

Thanks,
Tong.

>=20
>> My understanding is that the
>> exception table entry problem is fine. After all, the search is
>> performed only after a fault trigger. Code duplication can be solved by
>> extracting repeated logic to a public file.
>=20
> If the new exception table entries are only taken into account for SEA
> errors, why do we need a duplicate copy_mc_page() function generated?
> Isn't the copy_page() and copy_mc_page() code identical (except for the
> additional labels to jump to for the exception)?
>=20

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/e=
1d2affb-5c6b-00b5-8209-34bbca36f96b%40huawei.com.
