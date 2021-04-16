Return-Path: <kasan-dev+bncBCRKNY4WZECBB6HY42BQMGQE3USHLNY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x237.google.com (mail-oi1-x237.google.com [IPv6:2607:f8b0:4864:20::237])
	by mail.lfdr.de (Postfix) with ESMTPS id 726953625B4
	for <lists+kasan-dev@lfdr.de>; Fri, 16 Apr 2021 18:34:01 +0200 (CEST)
Received: by mail-oi1-x237.google.com with SMTP id n128-20020aca59860000b0290159ccfcbd31sf9626369oib.10
        for <lists+kasan-dev@lfdr.de>; Fri, 16 Apr 2021 09:34:01 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1618590840; cv=pass;
        d=google.com; s=arc-20160816;
        b=zrSTHIjhiyrCUus9T7USmW7kkAI/1u1Bz5csmcRJT7Sk74MVmINRq7b0VKsocwYFUF
         PQV+ukmO44d/Q5phW9V2KQfraYiv4Ta8/GkCgbrHGrwWNTyo+t7wUltRlvMapxFl4xTg
         wFa2vedC8AeMpL7dukl2b4TfdmKpiRuNC+ANPRe5g8cwN/UIFTgW9dcWU/Z7EFPjRwAf
         CNTTpXctrWFvdgva1A95B0qRb9FRCFJu0Ek8Z5+v1jMo8OY4LmOmvY8MvMsBIpL4PAl8
         io3YB2Ldk7VlOsKcJY4UyJqCMoS0e4kGyKuGsOgAc/my+r3mSj9wRzu7Jh7NiNNNnZe4
         qduw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :mime-version:message-id:to:from:cc:in-reply-to:subject:date:sender
         :dkim-signature;
        bh=E2uaS4FH3gi2xPMeZCATdAREwJCT2dqc1EjJGvLeYQY=;
        b=ofZRMWyC4ZMu23nThF2b7EuPqJp12/IRYRr7EziabX/Fe4U+kw1QheyK7+yUrRAbYC
         +0iXa+ld73DigDnFwWM/8PftkD2fQ2wskCoXfOnDG/EQRg6Xv/tzovKj6pEpN63ViMFb
         jwSN1LI6GkRQd4CZ2TsYdkdgJPYw+29FAFnkUsJi82UnVJTwlxSPfCdS5Zs2mW9MQqKA
         0m04ZbIdwIQ7UkWq969sywXZr3b9bJGJKtHDRl/j4PVKDDPkZhU0t/2zWfkLLRXKkglk
         IkwUCyk0obxluIbJzRhF4fxvOAkw4ZnYQm3a9YHyF4c9A5DApsFpwR4RNGt6oUUOylc5
         I8Nw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@dabbelt-com.20150623.gappssmtp.com header.s=20150623 header.b=maRGpOFY;
       spf=pass (google.com: domain of palmer@dabbelt.com designates 2607:f8b0:4864:20::435 as permitted sender) smtp.mailfrom=palmer@dabbelt.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:subject:in-reply-to:cc:from:to:message-id:mime-version
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=E2uaS4FH3gi2xPMeZCATdAREwJCT2dqc1EjJGvLeYQY=;
        b=DP9mvRuRwNIauPIhroecjvHMLwBEKkiLsSih8yrlitE+mZ+Eb47PMYFmQCp967ZESO
         A0xyHFXWFTikl+IiD0fnE1FTSU2GYTxnMOAVhBvYj2xXO8/REXW4/2wbmwZBsNAOSsEr
         0/YGpemu3MBnowS9lo9ZXZ//z0Fi6mOCpHcyiwYvvUBhPrLLjGxUZbZxyYd2766RIzYN
         QmsUALhEJoOqUJiPG8pOfp6/G9+zp0neLf0Zh555czRlX8eYwCJIez6ZS7cI1tzHdkcE
         uZoY754fm7nYOnyD6V5kdFiDcereyzJGaBb3WeXvw7i5po8u68cOKAr3mUA0l7GFuw7o
         fEbQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:subject:in-reply-to:cc:from:to
         :message-id:mime-version:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=E2uaS4FH3gi2xPMeZCATdAREwJCT2dqc1EjJGvLeYQY=;
        b=Y/f5McJELpeWEE0LdoeAtuQr7vaYfftCbD87fmBCBPFGNE4uSHgomgNK21+BjXGpwN
         5NnGeoDmKFNVA3cm2DMP8wddEYitwUuDrl5uuozFLSO9iuC0XXAmqeivGap+Ebz9/418
         PpQAYPJYGSM8tw+QwaHdZmNx/8gC9X1GzRL0RFy9zrSdTy35cUqJAUjnMkMmG4WukCpK
         X1Ek+YAyjHKN1EyXtGTrKNZQqkPvSF03r2ekjxzvQWePZpRi5ao2r93uwx/tux/GeBxW
         JoiGjs5Ye1ZYhxEBd8KtL8aQTcp/YQeLLnsclBBM/cu3A1M/B0Undx1yDBTBnwoozbsx
         VTCQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532r8ylOy0NSyvsaWFh72WQQI0MqTIJZxlwFQCRAFX/AdF274H/k
	0g7Z17+n6vZb2QjWD2P+IH0=
X-Google-Smtp-Source: ABdhPJwJsYTUe+m7aYjYQXtuh6h56RujOso3C5giXr18KkRNgaOv1tv0TH9gLEiHqsnN6JKFCerQbQ==
X-Received: by 2002:aca:4d47:: with SMTP id a68mr6799131oib.42.1618590840409;
        Fri, 16 Apr 2021 09:34:00 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:6a0a:: with SMTP id g10ls2494915otn.11.gmail; Fri, 16
 Apr 2021 09:34:00 -0700 (PDT)
X-Received: by 2002:a9d:2f04:: with SMTP id h4mr4504106otb.364.1618590840036;
        Fri, 16 Apr 2021 09:34:00 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1618590840; cv=none;
        d=google.com; s=arc-20160816;
        b=bHTkay2l/HvuJm/1N1ZuXNNYWTou637ilV5tCWZ8F8ry+Sff2VH+//r5DnGt3dB3fE
         oTYpwj9/Czc5aRK3DffJOiXi5JXCf6SanMTUyMydQDdpjmFyYFdEbB7epxVEI57nIRJi
         PAH0yRnnchQmu2Pmf86qaeFgX6IcucbbHPsRfFtwqOxfqc9h0YddZdnMkEbjCKby3/EV
         /Nx55hnMk1YHUoGt8xepK7QY3OSBj5GkewTJT+Q4Q9ovrkETONmX8dJwgmdujmvXXSwy
         ON6pkvL/tHa7KNx4nSLtQKyH8KtEyLGzsRvloYsDLKVdFkiGO+xH8EmEb1HRCx46UH2F
         LNoA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:to:from:cc
         :in-reply-to:subject:date:dkim-signature;
        bh=z2OC1cEMuhrClU6NrKEbwSpdwK0Wyx5ycssXYh5zYaY=;
        b=DU4kuTnyUZiZ+jP5BLvvXhkoahbRu7VQqJG6qNDrtN9bKxn+iXWnuItzC5NEnqBRMK
         KV1663tc7BzDFosKr2drDzB5/eVKudig4ApyAr8SFSRDpq1T+eEAJDl4SCCoG37Vt/ty
         YY3giuHyEck8q17bmVlwkqFnYix51D++PzkPMQ3VQj4f/wU+ZrF1HartA0OHviU2G9c+
         37RCAOp36Lbuel6rqeESSnEfZQrO4tC3bbUMcNb82ZxyEuKcv9JvOa9RDCs7nIC/O4oA
         q5K1XjoZx1D4H5JL2e6Hs3gqyTV1+Z/pdz00hBcginmpjxF9FcTRvkdgKekggNT+2x/n
         iJWA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@dabbelt-com.20150623.gappssmtp.com header.s=20150623 header.b=maRGpOFY;
       spf=pass (google.com: domain of palmer@dabbelt.com designates 2607:f8b0:4864:20::435 as permitted sender) smtp.mailfrom=palmer@dabbelt.com
Received: from mail-pf1-x435.google.com (mail-pf1-x435.google.com. [2607:f8b0:4864:20::435])
        by gmr-mx.google.com with ESMTPS id a7si29978oiw.3.2021.04.16.09.33.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 16 Apr 2021 09:33:59 -0700 (PDT)
Received-SPF: pass (google.com: domain of palmer@dabbelt.com designates 2607:f8b0:4864:20::435 as permitted sender) client-ip=2607:f8b0:4864:20::435;
Received: by mail-pf1-x435.google.com with SMTP id o123so18694687pfb.4
        for <kasan-dev@googlegroups.com>; Fri, 16 Apr 2021 09:33:59 -0700 (PDT)
X-Received: by 2002:a63:570e:: with SMTP id l14mr8746668pgb.159.1618590839027;
        Fri, 16 Apr 2021 09:33:59 -0700 (PDT)
Received: from localhost (76-210-143-223.lightspeed.sntcca.sbcglobal.net. [76.210.143.223])
        by smtp.gmail.com with ESMTPSA id b7sm5760468pgs.62.2021.04.16.09.33.58
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 16 Apr 2021 09:33:58 -0700 (PDT)
Date: Fri, 16 Apr 2021 09:33:58 -0700 (PDT)
Subject: Re: [PATCH] riscv: Protect kernel linear mapping only if CONFIG_STRICT_KERNEL_RWX is set
In-Reply-To: <f659c498-a273-f249-a81b-cab1ed1ba2bb@ghiti.fr>
CC: anup@brainfault.org, corbet@lwn.net, Paul Walmsley <paul.walmsley@sifive.com>,
  aou@eecs.berkeley.edu, Arnd Bergmann <arnd@arndb.de>, aryabinin@virtuozzo.com, glider@google.com,
  dvyukov@google.com, linux-doc@vger.kernel.org, linux-riscv@lists.infradead.org,
  linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, linux-arch@vger.kernel.org, linux-mm@kvack.org
From: Palmer Dabbelt <palmer@dabbelt.com>
To: alex@ghiti.fr
Message-ID: <mhng-9ab3280b-4523-4892-9f9a-338f55df8108@palmerdabbelt-glaptop>
Mime-Version: 1.0 (MHng)
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: palmer@dabbelt.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@dabbelt-com.20150623.gappssmtp.com header.s=20150623
 header.b=maRGpOFY;       spf=pass (google.com: domain of palmer@dabbelt.com
 designates 2607:f8b0:4864:20::435 as permitted sender) smtp.mailfrom=palmer@dabbelt.com
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

On Fri, 16 Apr 2021 03:47:19 PDT (-0700), alex@ghiti.fr wrote:
> Hi Anup,
>
> Le 4/16/21 =C3=A0 6:41 AM, Anup Patel a =C3=A9crit=C2=A0:
>> On Thu, Apr 15, 2021 at 4:34 PM Alexandre Ghiti <alex@ghiti.fr> wrote:
>>>
>>> If CONFIG_STRICT_KERNEL_RWX is not set, we cannot set different permiss=
ions
>>> to the kernel data and text sections, so make sure it is defined before
>>> trying to protect the kernel linear mapping.
>>>
>>> Signed-off-by: Alexandre Ghiti <alex@ghiti.fr>
>>
>> Maybe you should add "Fixes:" tag in commit tag ?
>
> Yes you're right I should have done that. Maybe Palmer will squash it as
> it just entered for-next?

Ya, I'll do it.  My testing box was just tied up last night for the rc8=20
PR, so I threw this on for-next to get the buildbots to take a look. =20
It's a bit too late to take something for this week, as I try to be=20
pretty conservative this late in the cycle.  There's another kprobes fix=20
on the list so if we end up with an rc8 I might send this along with=20
that, otherwise this'll just go onto for-next before the linear map=20
changes that exercise the bug.

You're more than welcome to just dig up the fixes tag and reply, my=20
scripts pull all tags from replies (just like Revieweb-by).  Otherwise=20
I'll do it myself, most people don't really post Fixes tags that=20
accurately so I go through it for pretty much everything anyway.

Thanks for sorting this out so quickly!

>
>>
>> Otherwise it looks good.
>>
>> Reviewed-by: Anup Patel <anup@brainfault.org>
>
> Thank you!
>
> Alex
>
>>
>> Regards,
>> Anup
>>
>>> ---
>>>   arch/riscv/kernel/setup.c | 8 ++++----
>>>   1 file changed, 4 insertions(+), 4 deletions(-)
>>>
>>> diff --git a/arch/riscv/kernel/setup.c b/arch/riscv/kernel/setup.c
>>> index 626003bb5fca..ab394d173cd4 100644
>>> --- a/arch/riscv/kernel/setup.c
>>> +++ b/arch/riscv/kernel/setup.c
>>> @@ -264,12 +264,12 @@ void __init setup_arch(char **cmdline_p)
>>>
>>>          sbi_init();
>>>
>>> -       if (IS_ENABLED(CONFIG_STRICT_KERNEL_RWX))
>>> +       if (IS_ENABLED(CONFIG_STRICT_KERNEL_RWX)) {
>>>                  protect_kernel_text_data();
>>> -
>>> -#if defined(CONFIG_64BIT) && defined(CONFIG_MMU)
>>> -       protect_kernel_linear_mapping_text_rodata();
>>> +#ifdef CONFIG_64BIT
>>> +               protect_kernel_linear_mapping_text_rodata();
>>>   #endif
>>> +       }
>>>
>>>   #ifdef CONFIG_SWIOTLB
>>>          swiotlb_init(1);
>>> --
>>> 2.20.1
>>>
>>
>> _______________________________________________
>> linux-riscv mailing list
>> linux-riscv@lists.infradead.org
>> http://lists.infradead.org/mailman/listinfo/linux-riscv
>>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/mhng-9ab3280b-4523-4892-9f9a-338f55df8108%40palmerdabbelt-glaptop=
.
