Return-Path: <kasan-dev+bncBCXLBLOA7IGBBJPZXTXQKGQEKONXSZY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x337.google.com (mail-wm1-x337.google.com [IPv6:2a00:1450:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id E2C5F118085
	for <lists+kasan-dev@lfdr.de>; Tue, 10 Dec 2019 07:35:17 +0100 (CET)
Received: by mail-wm1-x337.google.com with SMTP id y125sf502234wmg.1
        for <lists+kasan-dev@lfdr.de>; Mon, 09 Dec 2019 22:35:17 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1575959717; cv=pass;
        d=google.com; s=arc-20160816;
        b=OcCIE/7EawMKRQu5tMFquRYFrcXHmwMqyyrGCN6RmbFxhDavoYmX0cAdsknqjk6Yqh
         3TfLYRwJpa5ijsreukSG3P4ktKHYxh3QMfPh8q0PiYQg39JJgV34D2bQs3//gjxoAOZV
         9PFX/cZze4xQ7b98Zy9rX06eW3VoBEsvea83S8zYnj45T6NrxQTnTxxfITxWSRVQFxBn
         GbVnFxLWZiaw6bZ5yABpaTsJ1tC9O4GCsfmPep238PjJG/W1Fd+PZt170r78Hg5GjUgp
         7Vf2+CDN1hD6ekD8O5XNAcLBevp9mqr2sCyT2kAwOO6Vr5bmJB2k6ErLLQffOdj5cVax
         tmHA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :content-language:in-reply-to:mime-version:user-agent:date
         :message-id:from:references:to:subject:sender:dkim-signature;
        bh=Yj55StfoOuGG1LGrpOdu0hV+lrxbOByWEWabiN6SY6E=;
        b=jDtjcgnvocBrYx1+JcvyW4AM9UVOfBJXZ7eWQb9q5XbLDWYEh2XcTZrfsv5bKe1fnE
         JQVTrmm1Nj1FK8Wy2ddf/0eB6DZj7Z2Udt5bp47y7Cd6SDa+c8iXwRGIuBX8kjU3Mewc
         2MXKGSYyLsD4ajpHc+OwsuhOMIm3ZlI/aDHTl2V5kBpTZmh5kZ0Gk9IVLXmp5Xcoohbm
         nz3Q5TV5qiOo5zeML0+4eCu4JVS1uOr+aIwc7yHxdkZ3dQBIbbRElwvAvHgum7Naj9zu
         TnUt31yui9/SjVCbxghAjKnG6xpf7pr648sXg03B6dMkb13Xm6mEQEPZjbfmY4pLk4JP
         Sx8Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@c-s.fr header.s=mail header.b=FnZPC6Pa;
       spf=pass (google.com: domain of christophe.leroy@c-s.fr designates 93.17.236.30 as permitted sender) smtp.mailfrom=christophe.leroy@c-s.fr
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Yj55StfoOuGG1LGrpOdu0hV+lrxbOByWEWabiN6SY6E=;
        b=NQfKYiISywxPS4GoTFjws1Uz4yuEz9wWvp84ErBcw50V7YmQSI5/1SSuQtUvdDfEUB
         Nxwi0Fygla5joiqzK4Ck5F1sKH/fKD8wjrF1mKKs8CPiEbO5xQHdZHk0GAl8NnX59qvM
         hyq5TiFdUogtmPfDGqvziGLSwNCVTFuEx26JTqpZYszss19qQpD1koRvWw5lgbVHip2Y
         v3MnsmfavXVgX4+m6cvrCwSggtMkpeLu0opyKlcLUbnS5pJpyBjJbHH02ErvuLLwAeXz
         LSXCRv2PJfkqo5mUywDK6uk8PCzJ4E/j27uRYQZ8mSG7j9fRkZe1Z4S0OiUwhV3Z+wmB
         58aQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Yj55StfoOuGG1LGrpOdu0hV+lrxbOByWEWabiN6SY6E=;
        b=XCwRiGMROzfdMSk0roDtQfshR/xNHfRWPEjc5mPTzk3DaL+kh88sQbSTV1mSa3EzVX
         5id1gAg7ECWmaRaqk/3YOG+r6F8okU1T7bSYI6u9nGmMy4kzNbxRPZnqmMcIRri0Ipqc
         V10DJEpekA2K9NWHRkJ5+33LwATKyeWPrXBXV7l7qlbInRWR3EpzmCiE9pwyueGiG7Gz
         FAfmHg9V3Q9rG3qfgmoVQjzZ/+N+NGjrpszw3vf4ln8n944skDVrBTYIbN7x0qLrXqh3
         1gSpIY+dPxE4mdSbTdz53o5DGWZSpqBOW7w8bgaadlT2HYQT00kwof3M0y/5zXFCZm4/
         bnZg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVNNsInuwp4tTDjhUKSS9pn16/m6PO+EDvRM/LXl+OTN84JYdQJ
	DGahu7C2s2kyHNiI4cUcweE=
X-Google-Smtp-Source: APXvYqz/wIqm23XyLL8Tws+PsiKXr9wkX8e+vcsvOyRsnBPYXUkWS3IZhxsXxQ7b4LO40N8ZvyV1Lg==
X-Received: by 2002:adf:ea4f:: with SMTP id j15mr1185010wrn.356.1575959717609;
        Mon, 09 Dec 2019 22:35:17 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:6385:: with SMTP id x127ls329409wmb.2.gmail; Mon, 09 Dec
 2019 22:35:17 -0800 (PST)
X-Received: by 2002:a7b:c5d9:: with SMTP id n25mr3315295wmk.8.1575959717111;
        Mon, 09 Dec 2019 22:35:17 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1575959717; cv=none;
        d=google.com; s=arc-20160816;
        b=fR6KAjBjU39//IHW8cJGMW9MOIsidrd3Wmy/fxbXc9xis1+U/lRoRtIkatVIN1mLgV
         Mo9ihW8Tc28BLHDPBoc3eucETXn3t6Rf/OtKTihD9563DmXomiJn5dNWggbIoHjClHHs
         4c7fKv3jA9vjUdI8soBeOCs2PhcaoBfpmnPovNy7g7nmHaxrDTON9Rysar86lnkp1r5M
         Htjkq4Ga5D9DyYumJhRuE1dJevang2UrZku4a6E0mAz9Lc/2LLYstMIpMys46kOCJhEf
         1IBgLPxTGYIn8J8MW05wciBYhmuEO+szX4nPRJfgwyUohxLLSeozMa/4/DXigXghGyQb
         Lt5A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:to:subject
         :dkim-signature;
        bh=EUHakfQZwNjDyNpMu0Q8JwdIe7wmUpTzbd0Lye8z+SQ=;
        b=dox8vIzYi1lLbqx2gi3KNHlSZpMGcmvObWhOR+zybDqwX9LXivI+2he7hlYyUhqNqy
         +u8woTTno4UkzteFXcewRtWvgTPkQwB5bWlR+jw0ufGODzV7Bj5J0WcSMj719vMgyf0V
         VDAvp/fyZDLYCQurHAKgq77tNPHzT+rLdvpwoHgnpXZb7MCn8rvN7MzyIkFRdH+fiP9Q
         dD5xRcBJDAVL+Xvpow8RVFf31dZfSeK1joLFNZNZhuQWtuhtiGfrDldwj5QCRIT6K36D
         vOk+Zh4sB+qWqDLmjakP3lhIfy39aU9zBCHhJ5iLS1cHiuprXu3ZrWOTIpeQAR+qakk7
         XuTQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@c-s.fr header.s=mail header.b=FnZPC6Pa;
       spf=pass (google.com: domain of christophe.leroy@c-s.fr designates 93.17.236.30 as permitted sender) smtp.mailfrom=christophe.leroy@c-s.fr
Received: from pegase1.c-s.fr (pegase1.c-s.fr. [93.17.236.30])
        by gmr-mx.google.com with ESMTPS id g3si55841wrw.5.2019.12.09.22.35.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 09 Dec 2019 22:35:17 -0800 (PST)
Received-SPF: pass (google.com: domain of christophe.leroy@c-s.fr designates 93.17.236.30 as permitted sender) client-ip=93.17.236.30;
Received: from localhost (mailhub1-ext [192.168.12.233])
	by localhost (Postfix) with ESMTP id 47X9Kb5hrrz9vBmx;
	Tue, 10 Dec 2019 07:35:15 +0100 (CET)
X-Virus-Scanned: Debian amavisd-new at c-s.fr
Received: from pegase1.c-s.fr ([192.168.12.234])
	by localhost (pegase1.c-s.fr [192.168.12.234]) (amavisd-new, port 10024)
	with ESMTP id mLr7XqX7TPBB; Tue, 10 Dec 2019 07:35:15 +0100 (CET)
Received: from messagerie.si.c-s.fr (messagerie.si.c-s.fr [192.168.25.192])
	by pegase1.c-s.fr (Postfix) with ESMTP id 47X9Kb4HChz9vBmv;
	Tue, 10 Dec 2019 07:35:15 +0100 (CET)
Received: from localhost (localhost [127.0.0.1])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id 6EFD58B802;
	Tue, 10 Dec 2019 07:35:16 +0100 (CET)
X-Virus-Scanned: amavisd-new at c-s.fr
Received: from messagerie.si.c-s.fr ([127.0.0.1])
	by localhost (messagerie.si.c-s.fr [127.0.0.1]) (amavisd-new, port 10023)
	with ESMTP id qPcjq3_4_bHw; Tue, 10 Dec 2019 07:35:16 +0100 (CET)
Received: from [192.168.4.90] (unknown [192.168.4.90])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id BCADD8B754;
	Tue, 10 Dec 2019 07:35:15 +0100 (CET)
Subject: Re: [PATCH v2 1/4] mm: define MAX_PTRS_PER_{PTE,PMD,PUD}
To: Daniel Axtens <dja@axtens.net>, linux-kernel@vger.kernel.org,
 linux-mm@kvack.org, linuxppc-dev@lists.ozlabs.org,
 linux-s390@vger.kernel.org, linux-xtensa@linux-xtensa.org,
 linux-arch@vger.kernel.org, linux-arm-kernel@lists.infradead.org,
 kasan-dev@googlegroups.com, aneesh.kumar@linux.ibm.com, bsingharora@gmail.com
References: <20191210044714.27265-1-dja@axtens.net>
 <20191210044714.27265-2-dja@axtens.net>
From: Christophe Leroy <christophe.leroy@c-s.fr>
Message-ID: <80f340f2-0323-8092-7e6d-c93b26fb7cf7@c-s.fr>
Date: Tue, 10 Dec 2019 07:35:15 +0100
User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64; rv:60.0) Gecko/20100101
 Thunderbird/60.9.1
MIME-Version: 1.0
In-Reply-To: <20191210044714.27265-2-dja@axtens.net>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Language: fr
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: christophe.leroy@c-s.fr
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@c-s.fr header.s=mail header.b=FnZPC6Pa;       spf=pass (google.com:
 domain of christophe.leroy@c-s.fr designates 93.17.236.30 as permitted
 sender) smtp.mailfrom=christophe.leroy@c-s.fr
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



Le 10/12/2019 =C3=A0 05:47, Daniel Axtens a =C3=A9crit=C2=A0:
> powerpc has boot-time configurable PTRS_PER_PTE, PMD and PUD. The
> values are selected based on the MMU under which the kernel is
> booted. This is much like how 4 vs 5-level paging on x86_64 leads to
> boot-time configurable PTRS_PER_P4D.
>=20
> So far, this hasn't leaked out of arch/powerpc. But with KASAN, we
> have static arrays based on PTRS_PER_*, so for powerpc support must
> provide constant upper bounds for generic code.
>=20
> Define MAX_PTRS_PER_{PTE,PMD,PUD} for this purpose.
>=20
> I have configured these constants:
>   - in asm-generic headers
>   - on arches that implement KASAN: x86, s390, arm64, xtensa and powerpc

I think we shoud avoid spreading default values all over the place when=20
all arches but one uses the default.

I would drop this patch 1, squash the powerpc part of it in the last=20
patch, and define defaults in patch 2, see my comments there.

>=20
> I haven't wired up any other arches just yet - there is no user of
> the constants outside of the KASAN code I add in the next patch, so
> missing the constants on arches that don't support KASAN shouldn't
> break anything.
>=20
> Suggested-by: Christophe Leroy <christophe.leroy@c-s.fr>
> Signed-off-by: Daniel Axtens <dja@axtens.net>
> ---
>   arch/arm64/include/asm/pgtable-hwdef.h       | 3 +++
>   arch/powerpc/include/asm/book3s/64/hash.h    | 4 ++++
>   arch/powerpc/include/asm/book3s/64/pgtable.h | 7 +++++++
>   arch/powerpc/include/asm/book3s/64/radix.h   | 5 +++++
>   arch/s390/include/asm/pgtable.h              | 3 +++
>   arch/x86/include/asm/pgtable_types.h         | 5 +++++
>   arch/xtensa/include/asm/pgtable.h            | 1 +
>   include/asm-generic/pgtable-nop4d-hack.h     | 9 +++++----
>   include/asm-generic/pgtable-nopmd.h          | 9 +++++----
>   include/asm-generic/pgtable-nopud.h          | 9 +++++----
>   10 files changed, 43 insertions(+), 12 deletions(-)
>=20

Christophe

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/80f340f2-0323-8092-7e6d-c93b26fb7cf7%40c-s.fr.
