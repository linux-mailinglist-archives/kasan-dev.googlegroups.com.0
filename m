Return-Path: <kasan-dev+bncBAABBHPCXK6QMGQEZLRVBUY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x140.google.com (mail-il1-x140.google.com [IPv6:2607:f8b0:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id E5C41A35518
	for <lists+kasan-dev@lfdr.de>; Fri, 14 Feb 2025 03:57:34 +0100 (CET)
Received: by mail-il1-x140.google.com with SMTP id e9e14a558f8ab-3d060cfe752sf8870165ab.2
        for <lists+kasan-dev@lfdr.de>; Thu, 13 Feb 2025 18:57:34 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1739501853; cv=pass;
        d=google.com; s=arc-20240605;
        b=BYoIKNsNZyv+h9eiZ+3m9Zzt1L2YhcvgXxxS9dSpy3OEum0xX2Oc7GE0v5zgyEUzWR
         EY0BdDj1AJJ0OWrFd0ku35oQd/t8Ig+TQpKltD+LY9IkRgpURoSE8i+aqF5dFOFfRZqg
         FETUonfczD2XuTTPNC+FYf6Cy3iKM2aBfkyMi6m1fB1bQWvRhusJeuVzPwwN82ffrqs+
         GAnvNK2CC6vuyoflx9dLvZtQ/CU0G/xfv1RuHcCIwaNarAizThxZCWQyA4ShivCGdmLq
         peUhJfL7BqRqIBX1rBYIdYwDHybvwT50RF60pPTgJpuUvwwCsJvnBDToWtzn9O8wWwUo
         k5oQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :in-reply-to:from:references:cc:to:subject:user-agent:mime-version
         :date:message-id:dkim-signature;
        bh=DToQhKExfqg8mAaiZstwbJrto55WroTSoVR27VhmfZM=;
        fh=dM7/12qiHcRduXzkkBiSRkIvVbs90cdroi+ZPQTE5go=;
        b=a03X0Z0ASmjVj0CF3c85MkWYR0EdmY76ZsyyUQBDe+ltAzCrpuVpF0LQmuVlwMIBdr
         2hcXcAQ4zHfC22UqqgN3VkB9/I3na0J+pAxDCko7UOs5dYLE0KRbj+bXgeHdeLkXVmuw
         ONib+UPSXQZbIp/oTPyJUw7wP7Aq88a9OeXaauP4yQFk2/b+e50w2MFJaYzIyrqTWj34
         rZ4fEBSUg/tRyIKEXX8sRIAp9QWUJ5ubw80P2w/7SlFB/Al2eBTboM9cPVXYHPvf6Drx
         zkK0KUOJxtu0ncybso7nWhx1EqsP3RYgYGj4NKAZY+Kl8u0E9H3ez3KfISoBRDG4P2OA
         lDxQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of tongtiangen@huawei.com designates 45.249.212.190 as permitted sender) smtp.mailfrom=tongtiangen@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1739501853; x=1740106653; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:from:references:cc:to:subject
         :user-agent:mime-version:date:message-id:from:to:cc:subject:date
         :message-id:reply-to;
        bh=DToQhKExfqg8mAaiZstwbJrto55WroTSoVR27VhmfZM=;
        b=tFw8XCs/FQP+Iiq69ZqKAm4jwADl5SUMlwZtMunYqoHa7S4fIsR0R1I1CoGPbovwDn
         orccveqwRdOZ3KSB7SHqwUeXrit8eF5poxSQT5Kbn1Y8xgKS7hm6p/RGAnjzocRbIDQa
         QJOrN+TuOum6bV/imGH9bYEVxqVuQaTtU1clWuLmB/KTs9Z22K4S9MN6z6VDHOvppNPe
         QoCPtHAfZuuf1JKsfV9uhLE7KY3yAE+DRXgzXvhGJUjT6BhTb2u+kJqMVEL+f8vvzcRO
         vGrdHFxhuvqFAk8qI+FEoUBLIEs+3kpypbdPahZrM4x/p5qJseEtfrPYG5STrEZgExdE
         KBcw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1739501853; x=1740106653;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:from:references:cc:to:subject
         :user-agent:mime-version:date:message-id:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=DToQhKExfqg8mAaiZstwbJrto55WroTSoVR27VhmfZM=;
        b=riYfJxpDhQUW5pcAjpLIHJuJo1JS+BthGXxv/lgcpHHu/JJ8EqIA2i9j/S5XXA5G0h
         lDoIUiqhHDDdtt7eZMFcl62hHX4D+kk7ckNdwhwsTF0zzn0n4xbYNgbxC0SNuE4JYsK9
         JXEBLdx23prbu1sBUKq+hvQjboR01t9tlysKzkZNoxMa5iypgk5fJrrT2iIbGcv3nPnW
         BKYv5GwakyxSWwS/OzLa/nvHLjyCMmo4vvEsZB6O8hLFGCu4J/HUZsBxXEXJxd/vJ81W
         TIYDnzuo6G0s4aIUAsVwvVBFj6Z3hjjjZZn8MJGT22BNhWmCPkTpnD7mGF341XWst1nS
         0gkA==
X-Forwarded-Encrypted: i=2; AJvYcCXBm6+DFwafDcCRvNggeD+qSeVyeGDaUFjVeRnCocNSnK8sCcXt4a5YrUOajOfxd+HTTX3s2g==@lfdr.de
X-Gm-Message-State: AOJu0Yy2SIOxEZH2jqptdztKNmZGZpbR7lxmmpBzmte4yepZI4cKrCOD
	Prys4dJ0Ebus7fwMOChfTrE+/D/T2MxX8ZdWGp9jospWR+EedlOH
X-Google-Smtp-Source: AGHT+IG8V2YayA+rhLWqsd51AROySMX0G2sKtjI42JuAoB6rdCR7dbh3XfnBI9UzHH8yx+dKhr89Yw==
X-Received: by 2002:a05:6e02:156a:b0:3d0:2b88:116c with SMTP id e9e14a558f8ab-3d17bf46074mr74093045ab.10.1739501853316;
        Thu, 13 Feb 2025 18:57:33 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVEkaTtf5qbhtGzNhu77+C0Jc2LYLuQdSHdMZkChxIS7cQ==
Received: by 2002:a92:cecc:0:b0:3a8:12af:5924 with SMTP id e9e14a558f8ab-3d18c247e42ls5349785ab.0.-pod-prod-03-us;
 Thu, 13 Feb 2025 18:57:32 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVmudpbhrHAntOJprc3AhVpi2zY9v003HKqOixMgyzDEKGDkymvGciR37idbdMZG0//1ypv7LQttLI=@googlegroups.com
X-Received: by 2002:a05:6602:4c0f:b0:84a:78ff:1247 with SMTP id ca18e2360f4ac-85555daed93mr911599339f.9.1739501852445;
        Thu, 13 Feb 2025 18:57:32 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1739501852; cv=none;
        d=google.com; s=arc-20240605;
        b=lMzm8im4SaruzldFH63eUm9Fs0S5lWB+pYZuQMmMdXjFOGAeYuf5t6jGl55HsJitkY
         7fhhwfuVKAiXp/E9CH7TH2VyahnEPi12/jOfnftZtod9kJDEBvG3bwEa61HWdQm0azJv
         jgjo7YoROaijbpIo0JHPPGFYs3Rx64yf5eC2mcknr5W+jDtcEBH0KFwlNVbpmIkrnp7w
         dKn3qklXGHFjnReGG+DN8pSmvt1QMQcR5VfgJWTU6y0Ia9+WeCGUKakjG2yk4Bm40vKl
         dAMFO17NgpDHI+RM+6MqmIpzqCI9ZHxq1esv/4oj4NccOaXrarq6Ca8zh9iAIBzjnj4+
         tSgQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to:subject
         :user-agent:mime-version:date:message-id;
        bh=dAco+YwYPEGkt4T/RB6q+1KKzbs6hySE2tC8jKn0Axo=;
        fh=RzQbsIRJIGcsOahvYzttPrzbIb6n8kVsMKDOWJddbjk=;
        b=V1708fviirAusO9pd0V62u1TA4sT/3hqgeyKHgnGEEd+uoMVl0CCXXAQMk/hG/g3F5
         dK3PDh9Q+rrJMvuKRfXAeTxhsHd3bdX7owMxUWqQ/6C06FpJDM+vTVGa+pNELNdCMFVz
         SXpR4qfx2fWEuVygWWW5P6sLHLtFbPynNzeroHKdoonaAr70+8SqlFior2MxbhuUrRgc
         j7Erdrzr102e3oLtwF+yQo0d9WEw5PFsaxz9kFLLSAr8j8hBlwBQkvYYfGJYEHWBC5Lg
         lJt55fWX4KBQ6CiWwSOgIWpd6CTGSLvGGifzHnFxlwCVLDcruAIWUYCVRRxlO1HwXD5E
         AxHA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of tongtiangen@huawei.com designates 45.249.212.190 as permitted sender) smtp.mailfrom=tongtiangen@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
Received: from szxga04-in.huawei.com (szxga04-in.huawei.com. [45.249.212.190])
        by gmr-mx.google.com with ESMTPS id ca18e2360f4ac-85566f0409csi11765239f.3.2025.02.13.18.57.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 13 Feb 2025 18:57:32 -0800 (PST)
Received-SPF: pass (google.com: domain of tongtiangen@huawei.com designates 45.249.212.190 as permitted sender) client-ip=45.249.212.190;
Received: from mail.maildlp.com (unknown [172.19.88.163])
	by szxga04-in.huawei.com (SkyGuard) with ESMTP id 4YvGpC5pGcz2FdSY;
	Fri, 14 Feb 2025 10:53:39 +0800 (CST)
Received: from kwepemk500005.china.huawei.com (unknown [7.202.194.90])
	by mail.maildlp.com (Postfix) with ESMTPS id CA35F180044;
	Fri, 14 Feb 2025 10:57:27 +0800 (CST)
Received: from [10.174.179.234] (10.174.179.234) by
 kwepemk500005.china.huawei.com (7.202.194.90) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.2.1544.11; Fri, 14 Feb 2025 10:57:25 +0800
Message-ID: <ed9cfe20-98a6-64de-66cf-43b536035ae3@huawei.com>
Date: Fri, 14 Feb 2025 10:57:24 +0800
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:91.0) Gecko/20100101
 Thunderbird/91.8.0
Subject: Re: [PATCH v13 5/5] arm64: introduce copy_mc_to_kernel()
 implementation
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
 <20241209024257.3618492-6-tongtiangen@huawei.com> <Z6zX3Ro60sMH7C13@arm.com>
From: "'Tong Tiangen' via kasan-dev" <kasan-dev@googlegroups.com>
In-Reply-To: <Z6zX3Ro60sMH7C13@arm.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Transfer-Encoding: quoted-printable
X-Originating-IP: [10.174.179.234]
X-ClientProxiedBy: dggems703-chm.china.huawei.com (10.3.19.180) To
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



=E5=9C=A8 2025/2/13 1:18, Catalin Marinas =E5=86=99=E9=81=93:
> On Mon, Dec 09, 2024 at 10:42:57AM +0800, Tong Tiangen wrote:
>> The copy_mc_to_kernel() helper is memory copy implementation that handle=
s
>> source exceptions. It can be used in memory copy scenarios that tolerate
>> hardware memory errors(e.g: pmem_read/dax_copy_to_iter).
>>
>> Currently, only x86 and ppc support this helper, Add this for ARM64 as
>> well, if ARCH_HAS_COPY_MC is defined, by implementing copy_mc_to_kernel(=
)
>> and memcpy_mc() functions.
>>
>> Because there is no caller-saved GPR is available for saving "bytes not
>> copied" in memcpy(), the memcpy_mc() is referenced to the implementation
>> of copy_from_user(). In addition, the fixup of MOPS insn is not consider=
ed
>> at present.
>=20
> Same question as on the previous patch, can we not avoid the memcpy()
> duplication if the only difference is entries in the exception table?
> IIUC in patch 2 fixup_exception() even ignores the new type. The error
> must come on the do_sea() path.

As I said in commit message, it is not normalized with the memcpy()
because of the lack of GPR. If there is no GPR shortage problem, we can
extract the common code of memcpy_mc() and memcpy()=EF=BC=8CThe unextracted
code is using different exception table entries.

Thanks,
Tong.

>=20

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/e=
d9cfe20-98a6-64de-66cf-43b536035ae3%40huawei.com.
