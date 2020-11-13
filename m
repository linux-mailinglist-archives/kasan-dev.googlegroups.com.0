Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBI7DXH6QKGQETHXTANI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x437.google.com (mail-pf1-x437.google.com [IPv6:2607:f8b0:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id ACDFD2B1A38
	for <lists+kasan-dev@lfdr.de>; Fri, 13 Nov 2020 12:44:36 +0100 (CET)
Received: by mail-pf1-x437.google.com with SMTP id 23sf6404724pfp.21
        for <lists+kasan-dev@lfdr.de>; Fri, 13 Nov 2020 03:44:36 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605267875; cv=pass;
        d=google.com; s=arc-20160816;
        b=0qOFR35y6G8VwVQUq5R/02QPYGVIYrfKde0F9UFYvuZDbofK3ATGANUjShqdZX2QBd
         LlbEnP3j8YGmzAjxLONpx6IZDBHGfAQYDafD3TBagEj8jBb7ONReJJhKDlGDgagyzC6u
         Ht41ri558xCtEdhRx/1exw54JPL2cTUsg3fH5ePPkxaNMNkeltTbeXRH7NXX+5qdUHYD
         iZlbf/TLS/V9aDX8L8iarwfVossWm7k7dp4zCW71X2Z6aGBCbv9KCFQS2NX+gen2KCbz
         PMNfVHrqAPhPit41cmRqNfYvZxOtKzaCUYMU4iSI4unHICxpdzrxJWge52db+yV7BU6h
         Gcaw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=aI1WDjfXWo6OS7EYemxccrhikNz36osL0xzpFK87EQU=;
        b=oHZyX+ueiX28bpEuaKglpqS398h19uy5XfgXHhqkDsT3kzLhsMk8ZwHuyx9as64zNT
         Jz4AA6SGtG3HqkBLo6ZBRcr8myNcGhzQmwTAmcd5PYyBZvoggWAmnLKJ8ofiWddsbTiW
         lF/nlQwx+6BfODnAMoC4TkgDzpcXcvZb0eWzH/ja9OX/27ADjt0+lvFlGoeiGlvoeRsm
         ZMFrqH3QxZPKRL5Jmi3RjG25Csriz4yawSEtqsj0fjMQNcdkUV54yed++h43IvrLwVK0
         w29zdvDNQBF5NUvLPNShh+Ox+A+qCjuyW6yaNM2tDN53cb/8DOWOsLS4Ka2GVJYFDLcv
         SuLw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=aI1WDjfXWo6OS7EYemxccrhikNz36osL0xzpFK87EQU=;
        b=UQGB6qjKTeKEymzazRtz6cV86iDOisqnucrTEepy67w4lIt4T6J2MUN67PCh0xF8Mm
         NfO4VCqI8YcSVaI2tE88+XrHKLMf4xHoTxUuJIPHs1B9j85omYitICjQguIZ2E3YWDxM
         Sz8IEQJvKVAVweag2FVvLtvuYr1fQZVVy2h8nS6AvE3llD+sNxmPAnM0+agYXMuLXnmG
         O6i+gzZ17g9b0hNjHPaZH23dLCY5NKkaCEbuAJE61ZI02B/OqnU6uZEH8DXM+5zXiPa0
         SzmE1xs6wbp/aeU21f/G9G4/kojWMmibJ2C9cqycrSuSfiaebTwcQGoIByyTmqQXKQ2O
         8ndA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=aI1WDjfXWo6OS7EYemxccrhikNz36osL0xzpFK87EQU=;
        b=eEOpfRfV9rUawwvH2oPuMiU132pYQrMGZXS2zdI2PYZgxSJVWTlh6BiRcWyKPuqO0L
         cnl6RauCoMDr00Il9h1uvjY/FsyV9uYOSvGGkMz7Bo/6iEsG6QIu0fvT9DalZGGJSg/H
         uv/cxI4AE8nIJ+X+e2Mn1EjMCtUT0NzNy9m9O9HSQnGbcFiOoCP2djye8/AQmsEBe1zs
         EC9nkXjjpFpcaw3pXLVV/lIOt3CAAc8l/ZFOvNnUdHopk8NMU4LXNZwD+uzImSQMKTEP
         pQsyAhh94n22DKV5tZPcrqB55AO4YoqcWlX4PzZelHL3b67S+Ms+naRegolFrFnFt1J8
         hJmg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532I0J24rZ9JgCOi+huhYTNcA1tXCnRQKATe+wRQMxI+9IYXewVL
	dXWbZqvm0CastsvsDSsk+i0=
X-Google-Smtp-Source: ABdhPJz7m37/qfkXdmLwmhzpbWX9p3A+w5dl5La7/uLTaqyPctaBFA+NCGQ3SXIxVTkVU4/UoQp/PA==
X-Received: by 2002:a17:90a:c085:: with SMTP id o5mr2722595pjs.18.1605267875278;
        Fri, 13 Nov 2020 03:44:35 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:989e:: with SMTP id r30ls19849pfl.2.gmail; Fri, 13 Nov
 2020 03:44:34 -0800 (PST)
X-Received: by 2002:a62:75c6:0:b029:18a:d510:ff60 with SMTP id q189-20020a6275c60000b029018ad510ff60mr1715479pfc.35.1605267874770;
        Fri, 13 Nov 2020 03:44:34 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605267874; cv=none;
        d=google.com; s=arc-20160816;
        b=DTIy4kwTGmjLlU5paGHAoGtD7476P6GYu2LzxAkXXGa4V3SqznUrF4X75ezWsW6dY/
         qjdEoWhc84ago9JR9LFbBsMu+UX1ZnTy0zMfaIRl7SCKH3rQq/72tYoXXsXp1g3Owj81
         PHqOHAP7xCHwpPt3renZIyq8gOd3CS7XNTkIjBv2aL80agwEUMyXh5Yber/mFfdCveXh
         RFoAOfXbmj9h3Eq/XRQjuZ7DhbsmhvKRjfgWQhrr2fi7MC0tNKEXRlLIkS0c4VdgF3wl
         WVlImyz0DN7b8SJu07HUNsHF/O8reTqbxbaT9ymQ/VKVHqLJMl863ebXE0v/YjUp5jXb
         BRqg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=VCsldN7DyuMTxmcSQXLknDOtES9cxWD4/zlQnq/hwsI=;
        b=Ngu81qSq2ALDVZe/CdAN8Nt+MyxMZLtLMFLhhc9nkBnXs/srFLLktbcJYcvHRupxju
         YTOtUqiRx7iZCUK27kfIx3eGCx9QmRoj7iR1lAt/rzRZ8vy+uIs8aPfwWk+7VXGIfnlZ
         rj+d0lXEa8FUlB2CaG3lfOWdDSaR+tDMf47J3PrKomGW2BN8kQE181sbd3F6ia1L/jsG
         avle9Mz2fRWEL2qNJujXpnUOohTAJ7D63I8Fp4IlvRIJpIHcaf53kZt6JVgjEyOu+1Wx
         POWRefdzw5PF2bC6dokxapAbfZPY4WMFeVFacWagvvOS6+mPIBA8qpSgG3j55NP8+Nj8
         nmZQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id x6si428440plv.3.2020.11.13.03.44.34
        for <kasan-dev@googlegroups.com>;
        Fri, 13 Nov 2020 03:44:34 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id C0C6914BF;
	Fri, 13 Nov 2020 03:44:33 -0800 (PST)
Received: from [10.37.12.45] (unknown [10.37.12.45])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id D532F3F6CF;
	Fri, 13 Nov 2020 03:44:30 -0800 (PST)
Subject: Re: [PATCH v9 44/44] kselftest/arm64: Check GCR_EL1 after context
 switch
To: Alexander Potapenko <glider@google.com>,
 Andrey Konovalov <andreyknvl@google.com>
Cc: Catalin Marinas <catalin.marinas@arm.com>,
 Will Deacon <will.deacon@arm.com>, Dmitry Vyukov <dvyukov@google.com>,
 Andrey Ryabinin <aryabinin@virtuozzo.com>, Marco Elver <elver@google.com>,
 Evgenii Stepanov <eugenis@google.com>,
 Branislav Rankov <Branislav.Rankov@arm.com>,
 Kevin Brodsky <kevin.brodsky@arm.com>,
 Andrew Morton <akpm@linux-foundation.org>,
 kasan-dev <kasan-dev@googlegroups.com>,
 Linux ARM <linux-arm-kernel@lists.infradead.org>,
 Linux Memory Management List <linux-mm@kvack.org>,
 LKML <linux-kernel@vger.kernel.org>
References: <cover.1605046192.git.andreyknvl@google.com>
 <bd6825832c0cb376fc68ad61ffec6d829401ed0e.1605046192.git.andreyknvl@google.com>
 <CAG_fn=XpB5ZQagAm6bqR1z+6hWdmk_shH0x8ShAx0qpmjMsp5Q@mail.gmail.com>
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
Message-ID: <a83f3883-cef8-ec88-0411-d9638dd4b4ae@arm.com>
Date: Fri, 13 Nov 2020 11:47:35 +0000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.10.0
MIME-Version: 1.0
In-Reply-To: <CAG_fn=XpB5ZQagAm6bqR1z+6hWdmk_shH0x8ShAx0qpmjMsp5Q@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
Content-Language: en-US
X-Original-Sender: vincenzo.frascino@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172
 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
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

Hi Alexander,

thank you for the review.

On 11/12/20 3:59 PM, Alexander Potapenko wrote:
> On Tue, Nov 10, 2020 at 11:12 PM Andrey Konovalov <andreyknvl@google.com> wrote:
>>
>> From: Vincenzo Frascino <vincenzo.frascino@arm.com>
>>
>> This test is specific to MTE and verifies that the GCR_EL1 register
>> is context switched correctly.
>>
>> It spawn 1024 processes and each process spawns 5 threads. Each thread
> 
> Nit: "spawns"
> 

I will fix it in the next iteration.

> 
>> +       srand(time(NULL) ^ (pid << 16) ^ (tid << 16));
>> +
>> +       prctl_tag_mask = rand() % 0xffff;
> 
> Nit: if you want values between 0 and 0xffff you probably want to use
> bitwise AND.
> 

The main goal here is to have a good probability of having a different setting
to the GCR_EL1 register. Hence the difference in between 0xffff and 0xffff-1 is
negligible. Anyway I agree that we should aim to cover all the possible
combinations.

> 
>> +
>> +int execute_test(pid_t pid)
>> +{
>> +       pthread_t thread_id[MAX_THREADS];
>> +       int thread_data[MAX_THREADS];
>> +
>> +       for (int i = 0; i < MAX_THREADS; i++)
>> +               pthread_create(&thread_id[i], NULL,
>> +                              execute_thread, (void *)&pid);
> 
> It might be simpler to call getpid() in execute_thread() instead.
> 

Yes it might, but I would like to avoid another syscall if I can.

>> +int mte_gcr_fork_test()
>> +{
>> +       pid_t pid[NUM_ITERATIONS];
>> +       int results[NUM_ITERATIONS];
>> +       pid_t cpid;
>> +       int res;
>> +
>> +       for (int i = 0; i < NUM_ITERATIONS; i++) {
>> +               pid[i] = fork();
>> +
>> +               if (pid[i] == 0) {
> 
> pid[i] isn't used anywhere else. Did you want to keep the pids to
> ensure that all children finished the work?
> If not, we can probably go with a scalar here.
> 

Yes, I agree, I had some debug code making use of it, but I removed it in the end.

> 
>> +       for (int i = 0; i < NUM_ITERATIONS; i++) {
>> +               wait(&res);
>> +
>> +               if(WIFEXITED(res))
>> +                       results[i] = WEXITSTATUS(res);
>> +               else
>> +                       --i;
> 
> Won't we get stuck in this loop if fork() returns -1 for one of the processes?
> 

Yes I agree, I forgot to check a condition. We should abort the test in such a
case returning KSFT_FAIL directly.

>> +       }
>> +
>> +       for (int i = 0; i < NUM_ITERATIONS; i++)
>> +               if (results[i] == KSFT_FAIL)
>> +                       return KSFT_FAIL;
>> +
>> +       return KSFT_PASS;
>> +}
>> +
> 
> 

-- 
Regards,
Vincenzo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/a83f3883-cef8-ec88-0411-d9638dd4b4ae%40arm.com.
