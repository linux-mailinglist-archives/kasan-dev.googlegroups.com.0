Return-Path: <kasan-dev+bncBCRKNY4WZECBBC4A76KQMGQEAIJEHUI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63c.google.com (mail-pl1-x63c.google.com [IPv6:2607:f8b0:4864:20::63c])
	by mail.lfdr.de (Postfix) with ESMTPS id BA1C9563E0C
	for <lists+kasan-dev@lfdr.de>; Sat,  2 Jul 2022 05:48:29 +0200 (CEST)
Received: by mail-pl1-x63c.google.com with SMTP id jg5-20020a17090326c500b0016a020648bcsf2343634plb.19
        for <lists+kasan-dev@lfdr.de>; Fri, 01 Jul 2022 20:48:29 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1656733708; cv=pass;
        d=google.com; s=arc-20160816;
        b=fgqsePQJoEag8ucGP6RJAb1Bl222wAzvDDyeSYEncecKq4YtO2nmkTY3s2cw1Wlc+o
         ugNPvG2JLfsDj3WwUv9d5L6w/gOni6s+KJK06duMEtD6W9I8T2zsX8xEJfAxUD5ZS8Hd
         njE+T4eUOM9zRkkiFL94Ze1BVYBKPZqdsnX5vlA6wninQ45GNVjHfjmHMwh3i1Gv0jQL
         X5Ol8okq4crzntE0azdlv5gatGEX9xxmYnPpK6Y+wDQq67ZU/OagqZUxPsZRB34KbFlm
         mx6Xpv4QpYgoPj/24uZ6aXOw5+4P1sCbJ2LlUzDnGp6pvS2xZYMi/1Yq9/LiKx7MuVGF
         0mnQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:to:from:cc
         :in-reply-to:subject:date:sender:dkim-signature;
        bh=pWKUTrqDE5FQ4I4CcyGCeaZC0e+rWmxi4Irazb/WT9E=;
        b=tZAhXnvs8EOmd72petUUiP3QZST0YGQ+La1QZRVrBzWfEECv5cH+Eh3OqDlPOQywCg
         6BG3n4UJuBZgXhIMhLuSzU9zzcIvYnIgKhi2pdhp6xQA7/wQyIimiN8T9oJe2ARNurEi
         tCF/JQHoQWigPjnjGifEvs5sIvv1Irfec0Rdw/ToZrB/qWIuQFCwOfEy/l87s/QfOn1P
         Fv7ZxmdO9fsijILZhhO3cXyH2tG6BN4Xp7TTWakVXPMEj2ufZ9LBAS/pfe83NMAkSGAD
         rbOsmHxS+VDvWQq95LDn0xEs9x+yeWvxCGeZhHe9GQ4HzXzODVUzbSXeK1F8YemUYknK
         0JbA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@dabbelt-com.20210112.gappssmtp.com header.s=20210112 header.b=hk8vWE4A;
       spf=pass (google.com: domain of palmer@dabbelt.com designates 2607:f8b0:4864:20::52b as permitted sender) smtp.mailfrom=palmer@dabbelt.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:subject:in-reply-to:cc:from:to:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=pWKUTrqDE5FQ4I4CcyGCeaZC0e+rWmxi4Irazb/WT9E=;
        b=qt59FFlzqgK16LkydfAIuTuc4QYx9YlC/SZR82mzsWBjGJotfwtSgLp8gli9P9xuu9
         KVlepZobzratfAjYtBwAhuaqE2X0awjNo5uONQFhZZ6W86ZtjHhN3X0WOAQSVtGYxGIS
         X2ExM4nqhlakNPz+CQTcquRXYHnGeGEXZMdElCgQt3cYdk3eSsuO5U3rUat8OwmAoymS
         aMfPu21oCQd/cZOF+XwpooZmaMEUkDnv70ik3TmqS8uOjy5EvpS95GYefdWzf8njXKIp
         uIlkETkrWiyc8oq+Bh/mxzwvCvPCj5ld838avkOnRXkxkn+O+Iia21vPbmzukC7NkDB6
         jKNg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:subject:in-reply-to:cc:from:to
         :message-id:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=pWKUTrqDE5FQ4I4CcyGCeaZC0e+rWmxi4Irazb/WT9E=;
        b=JwzXLYe6mUkU7bNO6medtkIKIEuiytTHZ9XGP1Sy2xuQuxWDv2iRBwnVoAPZUCRCXh
         3LBS/oZwBuFFslpxZJ4Ptpo1H1zNBW9fCKlNFGow+4yCXU6WdTEITXeVYCGZRAWZa951
         k4WswGELlbAcrC6w313NoTxzfUtjNPWmLX2a2lwfEUXj80VeHHVBp2UKQuVooWKvmm89
         i7aZ3e1Db5F0tq1BWjomA3CRe0Qa6sXRvdIlFqGMNczHZK1T1hByaUg0lsGMLVUec2RO
         YWUxHfxobyS7z+8r9f8Ms7gGoBvkuMz5f3xZLVv+8MoeXcUaFaMZbW7o5pyn/A0OgTug
         BSXQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AJIora/6N4xHVefrQA4qT5bKvAqb9Oo0illmtf8rs8+cVn6j5tfFHfKy
	bVvhT3dm+Mcau2EjiCWc60M=
X-Google-Smtp-Source: AGRyM1u2T1h2c9DZv/jD7mVZTjr/fmUPKWmyiysEKBNxZMU7tSj4+aJmB1/34rjnAcMW7CqoW74NPA==
X-Received: by 2002:a63:6e44:0:b0:40c:73a7:b6c9 with SMTP id j65-20020a636e44000000b0040c73a7b6c9mr15048708pgc.285.1656733707840;
        Fri, 01 Jul 2022 20:48:27 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:9729:0:b0:525:141d:2ab7 with SMTP id k9-20020aa79729000000b00525141d2ab7ls16612273pfg.1.gmail;
 Fri, 01 Jul 2022 20:48:27 -0700 (PDT)
X-Received: by 2002:a65:6406:0:b0:40d:f426:b644 with SMTP id a6-20020a656406000000b0040df426b644mr14635332pgv.289.1656733707155;
        Fri, 01 Jul 2022 20:48:27 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1656733707; cv=none;
        d=google.com; s=arc-20160816;
        b=iQE6HsTbkOUSbYDw+XjKfnxNDi7ScmxEs5gwiq1bzu97K2ypCgEw+GUUj6mJJ2wEa8
         uGFz+qmiE0BVaZKuteVyb354kLdvjWI8wBhfg9fUsBCUMS4r8D+mAKhu/U7BuCg8d78Z
         h62N5wHegwGFRvs2+ywvzhCOZOO+EqcQgDN8phQGdKC1XO/zS3mTBF1w/HeRjP48dLJS
         aCpL/rRuB3q4ToEjonfxIqgTcyx7IJccxQ6FfxJ6khLuC3BAmbVmfvqDvodcbutbNhLt
         khBBuyDpWrkrFWs/zoISfhv1P9WOSU9nopQDvT1OpL9uqREdQdRbSHv9KsnCEmByPACr
         nbpg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:to:from:cc
         :in-reply-to:subject:date:dkim-signature;
        bh=E+a0fSglUmSzLtUA/HQMDcrrUZQr3oJWl2+1+N37CIA=;
        b=CTnRXXNHNdQ0WWTffX6mcm6XEY3c37Yod8IHDLcV17Xn2A4E2xzSkk/vHvZkLtkDOE
         1s8kMKCzXczzmLV2wkw+WFqvB6caFQf717FM/Z1g1Ami82l+YHNwbsvaU5f9o8WFUIfJ
         IFvOa1W9Scfd3P8a4c4J12Q1fd62VmixrfKQ0pug9skJaQxbeoOBzIFrA9KNecVAJaL8
         WQXEkSkGIm50tVESsR0GtmMfTWxd2rAN1poUd1Vu9besDoXGBvLk6wjRCRC3kSBTRhX5
         8i17/Yo+u4gMw+oRY3G4IJZZ66mfb8h7Vg6MpvdMvg5mZWYUoeqb90dKe4qf7KGui140
         I9lg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@dabbelt-com.20210112.gappssmtp.com header.s=20210112 header.b=hk8vWE4A;
       spf=pass (google.com: domain of palmer@dabbelt.com designates 2607:f8b0:4864:20::52b as permitted sender) smtp.mailfrom=palmer@dabbelt.com
Received: from mail-pg1-x52b.google.com (mail-pg1-x52b.google.com. [2607:f8b0:4864:20::52b])
        by gmr-mx.google.com with ESMTPS id p14-20020a170902780e00b00168f5a4563esi647854pll.13.2022.07.01.20.48.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 01 Jul 2022 20:48:27 -0700 (PDT)
Received-SPF: pass (google.com: domain of palmer@dabbelt.com designates 2607:f8b0:4864:20::52b as permitted sender) client-ip=2607:f8b0:4864:20::52b;
Received: by mail-pg1-x52b.google.com with SMTP id o18so2904050pgu.9
        for <kasan-dev@googlegroups.com>; Fri, 01 Jul 2022 20:48:27 -0700 (PDT)
X-Received: by 2002:a63:3e47:0:b0:40c:f2dd:bc4 with SMTP id l68-20020a633e47000000b0040cf2dd0bc4mr14694749pga.47.1656733706454;
        Fri, 01 Jul 2022 20:48:26 -0700 (PDT)
Received: from localhost (76-210-143-223.lightspeed.sntcca.sbcglobal.net. [76.210.143.223])
        by smtp.gmail.com with ESMTPSA id w17-20020aa78591000000b0051b9ac5a377sm16419846pfn.213.2022.07.01.20.48.25
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 01 Jul 2022 20:48:25 -0700 (PDT)
Date: Fri, 01 Jul 2022 20:48:25 -0700 (PDT)
Subject: Re: [PATCH v4 0/2] use static key to optimize pgtable_l4_enabled
In-Reply-To: <CAAhSdy0mkwacNMVa_jFZmZ+NRPBa1TpKUQGpzr6Z9_wfoq1R4g@mail.gmail.com>
CC: jszhang@kernel.org, Paul Walmsley <paul.walmsley@sifive.com>,
  aou@eecs.berkeley.edu, ryabinin.a.a@gmail.com, glider@google.com, andreyknvl@gmail.com,
  dvyukov@google.com, vincenzo.frascino@arm.com, alexandre.ghiti@canonical.com,
  Atish Patra <atishp@rivosinc.com>, linux-riscv@lists.infradead.org, linux-kernel@vger.kernel.org,
  kasan-dev@googlegroups.com
From: Palmer Dabbelt <palmer@dabbelt.com>
To: anup@brainfault.org
Message-ID: <mhng-17913c13-57bd-42f9-9136-b4eb9632253c@palmer-mbp2014>
Mime-Version: 1.0 (MHng)
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: palmer@dabbelt.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@dabbelt-com.20210112.gappssmtp.com header.s=20210112
 header.b=hk8vWE4A;       spf=pass (google.com: domain of palmer@dabbelt.com
 designates 2607:f8b0:4864:20::52b as permitted sender) smtp.mailfrom=palmer@dabbelt.com
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

On Sat, 25 Jun 2022 21:33:07 PDT (-0700), anup@brainfault.org wrote:
> On Sat, May 21, 2022 at 8:13 PM Jisheng Zhang <jszhang@kernel.org> wrote:
>>
>> The pgtable_l4|[l5]_enabled check sits at hot code path, performance
>> is impacted a lot. Since pgtable_l4|[l5]_enabled isn't changed after
>> boot, so static key can be used to solve the performance issue[1].
>>
>> An unified way static key was introduced in [2], but it only targets
>> riscv isa extension. We dunno whether SV48 and SV57 will be considered
>> as isa extension, so the unified solution isn't used for
>> pgtable_l4[l5]_enabled now.
>>
>> patch1 fixes a NULL pointer deference if static key is used a bit earlier.
>> patch2 uses the static key to optimize pgtable_l4|[l5]_enabled.
>>
>> [1] http://lists.infradead.org/pipermail/linux-riscv/2021-December/011164.html
>> [2] https://lore.kernel.org/linux-riscv/20220517184453.3558-1-jszhang@kernel.org/T/#t
>>
>> Since v3:
>>  - fix W=1 call to undeclared function 'static_branch_likely' error
>>
>> Since v2:
>>  - move the W=1 warning fix to a separate patch
>>  - move the unified way to use static key to a new patch series.
>>
>> Since v1:
>>  - Add a W=1 warning fix
>>  - Fix W=1 error
>>  - Based on v5.18-rcN, since SV57 support is added, so convert
>>    pgtable_l5_enabled as well.
>>
>>
>>
>> Jisheng Zhang (2):
>>   riscv: move sbi_init() earlier before jump_label_init()
>>   riscv: turn pgtable_l4|[l5]_enabled to static key for RV64
>
> I have tested both these patches on QEMU RV64 and RV32.
>
> Tested-by: Anup Patel <anup@brainfault.org>
>
> Thanks,
> Anup

Thanks for testing these.  Unfortunatly they're failing for me under my 
kasan+sparsemem-vmemmap config, which looks like a defconfig with

    CONFIG_KASAN=y
    # CONFIG_FLATMEM_MANUAL is not set
    CONFIG_SPARSEMEM_MANUAL=y
    CONFIG_SPARSEMEM=y
    # CONFIG_SPARSEMEM_VMEMMAP is not set

Nothing's really jumping out and I'm not sure that's a super compelling 
configuration, but IIRC it's found a handful of issues before so I'm not 
sure it's sane to just toss it.

I've put this all on the riscv-pgtable_static_key branch of 
kernel.org/palmer/linux .  If nobody has the time to look then I'll try 
and give it another shot, but I'm pretty buried right now so happy to 
have the help.

>
>>
>>  arch/riscv/include/asm/pgalloc.h    | 16 ++++----
>>  arch/riscv/include/asm/pgtable-32.h |  3 ++
>>  arch/riscv/include/asm/pgtable-64.h | 60 ++++++++++++++++++---------
>>  arch/riscv/include/asm/pgtable.h    |  5 +--
>>  arch/riscv/kernel/cpu.c             |  4 +-
>>  arch/riscv/kernel/setup.c           |  2 +-
>>  arch/riscv/mm/init.c                | 64 ++++++++++++++++++-----------
>>  arch/riscv/mm/kasan_init.c          | 16 ++++----
>>  8 files changed, 104 insertions(+), 66 deletions(-)
>>
>> --
>> 2.34.1
>>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/mhng-17913c13-57bd-42f9-9136-b4eb9632253c%40palmer-mbp2014.
