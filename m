Return-Path: <kasan-dev+bncBDS6NZUJ6ILRBCUP2C4QMGQE2ON7JII@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43d.google.com (mail-pf1-x43d.google.com [IPv6:2607:f8b0:4864:20::43d])
	by mail.lfdr.de (Postfix) with ESMTPS id 0BBF89C66F7
	for <lists+kasan-dev@lfdr.de>; Wed, 13 Nov 2024 02:57:33 +0100 (CET)
Received: by mail-pf1-x43d.google.com with SMTP id d2e1a72fcca58-71e578061ffsf7504544b3a.1
        for <lists+kasan-dev@lfdr.de>; Tue, 12 Nov 2024 17:57:32 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1731463051; cv=pass;
        d=google.com; s=arc-20240605;
        b=ltuk/EoLuKZ4BErT4B4JoYKfTfPeDr4XcuMr5DwQnKxFoert36lOcfVdDFxL5Cz/hX
         pAVF/Q3+pUSTFZWLq0qx47XDoOPoLtZDYIGKXFH7dDsnNzLlavL5CpMGVzJjKzEUFObv
         42Zf2v7g3DCmiJ9nwJoGAjAbL6s2gjx2DH7bGv0yfCyCo9cPkA4uwfJQGR1otkyBBsfD
         9Kdo8rstG3elOyJ7W7VvwqYwjPsbFH8ZFoaFvxyoyYWGFHiOM8/hzuLTc0Z+LTa4qqPF
         9Yt3Dzp2/ZBhtw4v9lLJD3XBnwOcq1iR/HlYkBo7F6AZyG3V81dQo8gzhs9kgxL6xksm
         o+qA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:references:message-id:date
         :in-reply-to:subject:cc:to:from:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=waZMO3XlvuT2oOVymHA0Cc04NqBW4KwTWPRtHOTaj74=;
        fh=yX/pCojV/NDWNYiO1fJ6yEwAT01khtfSFH2Fq7rKhT8=;
        b=N9zYgA33N7xs30eZeBKeZ1KEF7mrSXQidqu8Kzqo8uObc/kqL6i2lkplSboJTNm9pc
         I+p5KUQ7wpVisnAVgVK6wxn4ZYr3DwaDrDdDm6f74AsxJwGUw9kJ/FfT3H8P+rp2+2Ps
         /CQrLj8z32gN1X/6fbzImGTf9aHVV+nWRrJtHWb5UJIBAwBUdr9W96cjXCbI1mR1iroh
         hSvY0Gxst69eMDYU/FB4idSalZQoqeTe8YZ9arnRbfU4rK8exsbBqyIYlKxVjsPimWxM
         clgEIyAf29OTFoX1nFCnwizsX6oahFLZQfY9EPDVNIQNNVfbg5Hfh7jB7xTCKEM8Vl+3
         sE4g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="m/k9rAMk";
       spf=pass (google.com: domain of ritesh.list@gmail.com designates 2607:f8b0:4864:20::629 as permitted sender) smtp.mailfrom=ritesh.list@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1731463051; x=1732067851; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:references:message-id:date:in-reply-to:subject:cc
         :to:from:mime-version:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=waZMO3XlvuT2oOVymHA0Cc04NqBW4KwTWPRtHOTaj74=;
        b=BZ/oFFY91R1ynaJmMuZLsMo9TdXupztcxaG3ifdnzRetvbFO5gSIQhlPBzKeEjwhmJ
         aHHWTa8+4Sw5/PSlFMqt6EydPa8oB1JBTbUel5DLt4rqaoCaeCZaXzA1vMi+btNgEEXV
         7nT6D3aMivCqLz7mPL+8hw7W6JjHgjKQYPlH/vWHeHuGjCM2CYyiDIergNFtHeFePLxI
         WQGGHUkvk0lGHcUoZCsYll5ho10X81E9Avx//+wRk/uX50xPsX52zPtYwSgkb48vXOie
         hWzc812QwbwG220AGrOXUJoKcpE/xqAoYSWYBK2a2Q86ctic7IjvtCpergylpG9z6UcV
         NhrA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1731463051; x=1732067851; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:references:message-id:date:in-reply-to:subject:cc
         :to:from:mime-version:from:to:cc:subject:date:message-id:reply-to;
        bh=waZMO3XlvuT2oOVymHA0Cc04NqBW4KwTWPRtHOTaj74=;
        b=GKYuvPtFAq0RlFL01Yr8TWIZnq4GUlK4WxOZi3tJpeSKTNiFyVaJrkrsNviKSsNSHm
         nODh7oo+GO0khZju1lMikCtWGR35j3ha1JDmYyv7KScCJ9Zmt5SkALOqYObevUohy6pB
         VDFgj5S8m9wmvC+1nmU/FACQBknaOFI9oAndg2o6Wv9UQnpStHtwAcOG5X7oH7ek12vY
         6g6edtPZA3+osMq5XNQnBvfxkbLX9LTvaC/QE8apvil8DBxyVMmUqbb3KYDlfoHuLBr+
         X2SoZpBEJby4qveGx74M2+hwmwISzEiYsHNQMYiukmqMka3bNXaE8MYpmNirBwRn+/mR
         RXXg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1731463051; x=1732067851;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:references
         :message-id:date:in-reply-to:subject:cc:to:from:x-beenthere
         :mime-version:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=waZMO3XlvuT2oOVymHA0Cc04NqBW4KwTWPRtHOTaj74=;
        b=SWnJLqiY3JlsV3nj9xGqmy/jyZiphIl4YPGPVXeyAmJSonBZpF5BhE8CGAvabf+nSn
         1ZlBEUauUflvK0i0QzqE6Ks/HmJ4+DrW8PrZWorszP3fApQBzBJV6aIcZN8Mr6UfzrJ0
         ZOGKiRSfOBCQP9lzwjPUduVrkr9vgNGNTYqa41tv7hpl44SZ1ut7f2y1ACJv8GwM5rR4
         JPrFk3tuJDFC7TFXvzi0z/4G9JrLiMXDsD/36ORffUR645xlUMpuOaEVXxl/CYEKCS/o
         mioP9l8BDw1Wm3UkTcws5/fNPW82zJQd9BV90LwYR5ZfJuaxr1UzA0qm3IaKb/2AtKMr
         qSzQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCW3LGDcm0Sg/o6uKLiNKtuV2OTJX20Cygddl1ZePFw5hQCCs4XKQGbTF4nd+KrjK5uysA5oiw==@lfdr.de
X-Gm-Message-State: AOJu0YxEOpZSYNFRlQlI/XW5qAwFioIyLhbiZy9tMk3gOLTw93vC1gZP
	PMQC/BdeWeAY9WVPLYTAUUzBkEBCI7ExreqPZYAQYRnBliPTJdGG
X-Google-Smtp-Source: AGHT+IGJAKOjcy7Mfmc2KpxVw8Ga+rP11uhWMFXFGUJp+HXToV3KNGy+DOS0Fwux6fzOxj7TQwaBjg==
X-Received: by 2002:a05:6a20:12cd:b0:1db:d869:9204 with SMTP id adf61e73a8af0-1dc5f8ed379mr6790168637.11.1731463050696;
        Tue, 12 Nov 2024 17:57:30 -0800 (PST)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:21c5:b0:71e:6bae:d427 with SMTP id
 d2e1a72fcca58-7240360fff4ls5747008b3a.2.-pod-prod-01-us; Tue, 12 Nov 2024
 17:57:29 -0800 (PST)
X-Received: by 2002:a05:6a21:6da1:b0:1dc:1:3e28 with SMTP id adf61e73a8af0-1dc5f9a3e94mr5981483637.40.1731463049179;
        Tue, 12 Nov 2024 17:57:29 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1731463049; cv=none;
        d=google.com; s=arc-20240605;
        b=K1eKISCiwet21UN70s6i+9Eo94WqlZq3O0d3RexFMmkLiJANu2iuld5QCDn+WYrPyD
         YsgSETYG+EPvTEESWEd0K1SloaM4eRO3RGOE63EojbicoqWFeP3q64238WlWDVIz7I4t
         ungc534KvUw0O2euLEXA0dhvAN7QsbF+nnRDXAQmQatN1T+syduRYAn+wTzobo83f5f9
         4DLfugTt4Z8fCvO3R5qz3VBfWaPXOraV0QQ/5W5AUbe4RVvEaJLpGxgA++KXZSZpJX3G
         /wE8vU2EHenIh9l19F6FEoVXN541jLZeJrcHo7NgDEhZiUfS9hy64/lJ0Jtlgo4VPOe3
         B4VA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=references:message-id:date:in-reply-to:subject:cc:to:from
         :dkim-signature;
        bh=N61dRP0zCZ5yj3jghYT9YKlYmR07EvPApdhNG3AAtvE=;
        fh=o2q3cxMGnSepf8Tfx6KN7UhvGy5kn4PyvJxmyvqi0Ss=;
        b=h8No+8xphXruaLu+BGNF+xlgSHlyY82MVPFDfEj7bffjxFt05UECWUUV0p/TjzuoJS
         0UusfcIIBa7XTKI8HAupcKfK2ApjyD80kV/z/EN51gduXn0lkj7VekLuc9bdJqpLZ28r
         L1HFG8DUpwJxLskQA/SBEeOJBT9OUaxKd6z88j9jYSRthTr2RBs41oLPLnnFsAwk+7Z5
         jAHsxShO5AiAG6kFmcC1ds1QOqJyaimlnYABrV1z65fEU6vqkSffWTG3AWc4QbN0FX7p
         Ze/bQnqxv0iz/rvaThSsf4+Hwiw3x5VUniYdQ3Nmg3blE7uZdGLXGrITtVSBYE6ZWR+c
         FodA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="m/k9rAMk";
       spf=pass (google.com: domain of ritesh.list@gmail.com designates 2607:f8b0:4864:20::629 as permitted sender) smtp.mailfrom=ritesh.list@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pl1-x629.google.com (mail-pl1-x629.google.com. [2607:f8b0:4864:20::629])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-2e9f3f6a6e2si20132a91.2.2024.11.12.17.57.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 12 Nov 2024 17:57:29 -0800 (PST)
Received-SPF: pass (google.com: domain of ritesh.list@gmail.com designates 2607:f8b0:4864:20::629 as permitted sender) client-ip=2607:f8b0:4864:20::629;
Received: by mail-pl1-x629.google.com with SMTP id d9443c01a7336-2118dfe6042so29777175ad.2
        for <kasan-dev@googlegroups.com>; Tue, 12 Nov 2024 17:57:29 -0800 (PST)
X-Received: by 2002:a17:902:d2cf:b0:20b:6a57:bf3a with SMTP id d9443c01a7336-211ab90a59emr66341285ad.1.1731463048726;
        Tue, 12 Nov 2024 17:57:28 -0800 (PST)
Received: from dw-tp ([171.76.87.84])
        by smtp.gmail.com with ESMTPSA id d9443c01a7336-21177e6c352sm101286045ad.253.2024.11.12.17.57.24
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 12 Nov 2024 17:57:28 -0800 (PST)
From: Ritesh Harjani (IBM) <ritesh.list@gmail.com>
To: Marco Elver <elver@google.com>
Cc: kasan-dev@googlegroups.com, linuxppc-dev@lists.ozlabs.org, linux-mm@kvack.org, Dmitry Vyukov <dvyukov@google.com>, Alexander Potapenko <glider@google.com>, Heiko Carstens <hca@linux.ibm.com>, Nirjhar Roy <nirjhar@linux.ibm.com>, Andrew Morton <akpm@linux-foundation.org>
Subject: Re: [PATCH v3] mm/kfence: Add a new kunit test test_use_after_free_read_nofault()
In-Reply-To: <CANpmjNPQtAMbF2BZbUVOL+Sx2+VSOwxgxzXR8yFvDBH4Euu7Ew@mail.gmail.com>
Date: Wed, 13 Nov 2024 07:26:26 +0530
Message-ID: <87frnvnbg5.fsf@gmail.com>
References: <210e561f7845697a32de44b643393890f180069f.1729272697.git.ritesh.list@gmail.com> <CANpmjNPQtAMbF2BZbUVOL+Sx2+VSOwxgxzXR8yFvDBH4Euu7Ew@mail.gmail.com>
X-Original-Sender: ritesh.list@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b="m/k9rAMk";       spf=pass
 (google.com: domain of ritesh.list@gmail.com designates 2607:f8b0:4864:20::629
 as permitted sender) smtp.mailfrom=ritesh.list@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
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

Marco Elver <elver@google.com> writes:

> On Fri, 18 Oct 2024 at 19:46, Ritesh Harjani (IBM)
> <ritesh.list@gmail.com> wrote:
>>
>> From: Nirjhar Roy <nirjhar@linux.ibm.com>
>>
>> Faults from copy_from_kernel_nofault() needs to be handled by fixup
>> table and should not be handled by kfence. Otherwise while reading
>> /proc/kcore which uses copy_from_kernel_nofault(), kfence can generate
>> false negatives. This can happen when /proc/kcore ends up reading an
>> unmapped address from kfence pool.
>>
>> Let's add a testcase to cover this case.
>>
>> Co-developed-by: Ritesh Harjani (IBM) <ritesh.list@gmail.com>
>> Signed-off-by: Nirjhar Roy <nirjhar@linux.ibm.com>
>> Signed-off-by: Ritesh Harjani (IBM) <ritesh.list@gmail.com>
>> ---
>>
>> Will be nice if we can get some feedback on this.
>
> There was some discussion recently how sanitizers should behave around
> these nofault helpers when accessing invalid memory (including freed
> memory):
> https://lore.kernel.org/all/CANpmjNMAVFzqnCZhEity9cjiqQ9CVN1X7qeeeAp_6yKjwKo8iw@mail.gmail.com/
>
> It should be similar for KFENCE, i.e. no report should be generated.
> Definitely a good thing to test.
>
> Tested-by: Marco Elver <elver@google.com>
> Reviewed-by: Marco Elver <elver@google.com>
>

Gentle ping. Is this going into -next?

-ritesh

>> v2 -> v3:
>> =========
>> 1. Separated out this kfence kunit test from the larger powerpc+kfence+v3 series.
>> 2. Dropped RFC tag
>>
>> [v2]: https://lore.kernel.org/linuxppc-dev/cover.1728954719.git.ritesh.list@gmail.com
>> [powerpc+kfence+v3]: https://lore.kernel.org/linuxppc-dev/cover.1729271995.git.ritesh.list@gmail.com
>>
>>  mm/kfence/kfence_test.c | 17 +++++++++++++++++
>>  1 file changed, 17 insertions(+)
>>
>> diff --git a/mm/kfence/kfence_test.c b/mm/kfence/kfence_test.c
>> index 00fd17285285..f65fb182466d 100644
>> --- a/mm/kfence/kfence_test.c
>> +++ b/mm/kfence/kfence_test.c
>> @@ -383,6 +383,22 @@ static void test_use_after_free_read(struct kunit *test)
>>         KUNIT_EXPECT_TRUE(test, report_matches(&expect));
>>  }
>>
>> +static void test_use_after_free_read_nofault(struct kunit *test)
>> +{
>> +       const size_t size = 32;
>> +       char *addr;
>> +       char dst;
>> +       int ret;
>> +
>> +       setup_test_cache(test, size, 0, NULL);
>> +       addr = test_alloc(test, size, GFP_KERNEL, ALLOCATE_ANY);
>> +       test_free(addr);
>> +       /* Use after free with *_nofault() */
>> +       ret = copy_from_kernel_nofault(&dst, addr, 1);
>> +       KUNIT_EXPECT_EQ(test, ret, -EFAULT);
>> +       KUNIT_EXPECT_FALSE(test, report_available());
>> +}
>> +
>>  static void test_double_free(struct kunit *test)
>>  {
>>         const size_t size = 32;
>> @@ -780,6 +796,7 @@ static struct kunit_case kfence_test_cases[] = {
>>         KFENCE_KUNIT_CASE(test_out_of_bounds_read),
>>         KFENCE_KUNIT_CASE(test_out_of_bounds_write),
>>         KFENCE_KUNIT_CASE(test_use_after_free_read),
>> +       KFENCE_KUNIT_CASE(test_use_after_free_read_nofault),
>>         KFENCE_KUNIT_CASE(test_double_free),
>>         KFENCE_KUNIT_CASE(test_invalid_addr_free),
>>         KFENCE_KUNIT_CASE(test_corruption),
>> --
>> 2.46.0
>>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/87frnvnbg5.fsf%40gmail.com.
