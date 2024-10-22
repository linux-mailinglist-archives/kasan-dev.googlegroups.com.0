Return-Path: <kasan-dev+bncBDS6NZUJ6ILRBCF53S4AMGQEA5WBZYQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x1137.google.com (mail-yw1-x1137.google.com [IPv6:2607:f8b0:4864:20::1137])
	by mail.lfdr.de (Postfix) with ESMTPS id DC4549A972E
	for <lists+kasan-dev@lfdr.de>; Tue, 22 Oct 2024 05:39:55 +0200 (CEST)
Received: by mail-yw1-x1137.google.com with SMTP id 00721157ae682-6e35a643200sf106764687b3.0
        for <lists+kasan-dev@lfdr.de>; Mon, 21 Oct 2024 20:39:55 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1729568392; cv=pass;
        d=google.com; s=arc-20240605;
        b=Wg/u1AVAsaCg/RIZ6KxiXly8d+HqevOeJS83gsCIMOvgKWCYDH5iu0MB5LYdH2cJ6Z
         B+1230O1howeqi+kuuBgn1tyf3fI5+OvdzjSLj3KUcm6tWciGRYL3r86XpTkKhlEihxe
         8Xzcqqw4B4ApjHvJhpPN66ADLzZZA27PT6UmNjRTQZCge5gMgHLoHhrNDIwCWjbejd/0
         nGsHJ85DiOMb4W8MuBbm1WIrnS3hX+Sb8lQfShtrcF2/f2UEIwULkFSLstR0tEfSIax8
         yUgiiR0bJr7lwu6TsPWKnsFMEG+RvIx/4siKWq99Z+bnMLgzpS7Y3sAJp//3LuxR1/F8
         Lyqg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:references:message-id:date
         :in-reply-to:subject:cc:to:from:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=QPoH/NYL70xWY8zAgGkldBxlmWS/5iYIXAnb2LZ88Eg=;
        fh=iR5kbRU/ZQycjsW12U/RIlK363tVCtiXjwLaLeJx7Nw=;
        b=jV6M7atGJaAPokhPljm8s11gBrw7E9ERUV9C3dIdXtinNRISISoX302e5A8HbEbPpu
         Fo7INbCqV+xkfTEYpIGaS/uaUyEw7M7dRxzMjaVj6+jX7eTu2t1DydITP8wXdY2SZ/ev
         /vIkd4beLUJgdgmvtaHgChSogLxuCN/bJBd0XfsvujtAlG8Orxbyy7XnXdRreZKzSV82
         iaiKn6ppkcD8d898A8pyW43isqR1vHoyrrD0Krvb8HjsbblYHR8r9bnB1swP+anidsiz
         J6x6Hmc28AAfNq0k2RHUEUzSVX49nL+Q9yi3spSX68u/9exIQ+FVsTv+TM4z5iT6YOu8
         CS3A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=Zk9DXRfi;
       spf=pass (google.com: domain of ritesh.list@gmail.com designates 2607:f8b0:4864:20::1036 as permitted sender) smtp.mailfrom=ritesh.list@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1729568392; x=1730173192; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:references:message-id:date:in-reply-to:subject:cc
         :to:from:mime-version:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=QPoH/NYL70xWY8zAgGkldBxlmWS/5iYIXAnb2LZ88Eg=;
        b=IcxezewoDUTOJ780JBGkEDkm4j9Cy08Bw5GRSn36wJsEBMXCZwFTwTTT9trt0wMLCV
         kuOK0CeZIdRFGSvRC5l4hovlzeoR7Czmn2C2HCe5tGpN7hwzqM0cPdfVjwpDL/78NnTe
         45qytdQaP5NbRfOdH19VHuGWSs6Hpm2XFPmrKdHfPMJL+GVrIUOHPuKesvpXRFjoEByS
         NCf9hVEekPnGuNsKM/47EqA0MA3gGSupRniUuqTf/t7MsAzJ7L9dXPnZA0XW4q+ep7z0
         +AXZHHb2VfbtuMcIZAYqxGqNJEWShAi4hnuQPMMJWqf8Q0WkwH/1x+JfszyC7VDyUIrE
         wXfQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1729568392; x=1730173192; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:references:message-id:date:in-reply-to:subject:cc
         :to:from:mime-version:from:to:cc:subject:date:message-id:reply-to;
        bh=QPoH/NYL70xWY8zAgGkldBxlmWS/5iYIXAnb2LZ88Eg=;
        b=ngQp92EoJ6bqkGhSITaZ1H+Ds02yzoprJ/7+Tpvmz+4ab1xnqy6nu+tP6BTJ2Uk+6S
         1wj1RPybS1e+YJfFH5oz0LiXQrQfohKCT+9VOT+BC/s/a4WMp11YlApxHrUrMa/Dk6x6
         CXTFoNJhsuZBlL3Ap+qMTMyAuq38IZ3GujDMrt68GHyg2gA0yOFQc1v02dyb6AKcSLv5
         2DD6KJICuG7KEOGDyNt3uBLSOfQgmMic9Y2Yz2rPrPUKWnQs90cFu7Q/hO+UjDMvraRN
         Ae8CGXMqqP9W009ociRwSV+SZWNntMvoWKu6jbqUQ/iLl9w5LFaTM23QQ6jefEq0lFr8
         DrQA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1729568392; x=1730173192;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:references
         :message-id:date:in-reply-to:subject:cc:to:from:x-beenthere
         :mime-version:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=QPoH/NYL70xWY8zAgGkldBxlmWS/5iYIXAnb2LZ88Eg=;
        b=vu/SS+l8gr9SUzqcH0i5STpH7eV/G3I+df+ScwMadY0/RO1sk/ot63bBNYlar+Zk4X
         wG6FoxAtWf/y0d97YRdvWyH28gfVV2qnIUWod3X+pvFgb6np5X+dehIlxueZUf+SkR7Z
         561xShPe7CXpNIAns6/oorYEgPnmDCAGPtprVxPslR5HTPr8YlfB1/QQQh8gHXrCgwsW
         rWiR0FMnapnt+3khuXvTMklumnAcLK8z6nKSTdozv+AuJL+76AxCpKqHOVJdq2eHmxKO
         6GQPxkSt7Q0GeQAwk2wmxFKvqV3/4nCgC67skDK2FzbwnllY55Q33vp47eSDsre8mhfn
         0Fyg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUs9X9DZm69vOx4DJsyb1ZfL9SnxCQ1Fpb5xWQk4tjHNwL4MQtpRtsFUgboj35cb7npEpXkUQ==@lfdr.de
X-Gm-Message-State: AOJu0YxDyGE9jjR8q+eKfYX2Tkzv8JRL7O8hWAElrQbz+CDkxQwYR55c
	fb9cHqC07rTIt4FCAaM0zN1oD4MxvIytZwMO41pnjHMbwO+6JJhe
X-Google-Smtp-Source: AGHT+IEZpMWggOmAum9g/gJxFNf68c6uTZI/vdwNCrYZpSld4ysQBOh6upbhcG+w4tu6gcBB0cTT1Q==
X-Received: by 2002:a05:6902:1183:b0:e2b:b9bf:fe5b with SMTP id 3f1490d57ef6-e2e2715ba74mr1338344276.8.1729568392219;
        Mon, 21 Oct 2024 20:39:52 -0700 (PDT)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6902:726:b0:e20:db8:7862 with SMTP id
 3f1490d57ef6-e2b9ce27e08ls1162138276.2.-pod-prod-02-us; Mon, 21 Oct 2024
 20:39:51 -0700 (PDT)
X-Received: by 2002:a05:6902:84a:b0:e2b:dd34:9a50 with SMTP id 3f1490d57ef6-e2e2715b4e9mr1243520276.5.1729568391383;
        Mon, 21 Oct 2024 20:39:51 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1729568391; cv=none;
        d=google.com; s=arc-20240605;
        b=MZ3F//cH3Al9HcpobGOh5ZphofNuJ1HLgt5LpIN24v8XzDZKFBYFU9ySntTVjIO6Ad
         mFlxqc3l8wQ+s8nfqY/WpgHOZB6/DIVo1BL2NDMnkH4OTzig3nOr4emg5VQVqUZqgMH/
         1dcH99vVfDyoC3rdLsONoLnyZ0kqNtrPZCLEFSPg5mdBw3Y5wpGIhz/puVzzq2720/HM
         sGOBWpmxeTZxBhantY8CvRG6BPC8Als6/nD31X1HP6f8Srm3hsbKGViI2YFHO0micLkS
         cjN7wMELsSyjOZhF1UR5mdM3FOcQBoxkw47ShES/uNyTqpYGMfPDLqyTcCZlAfAyW9By
         cXQg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=references:message-id:date:in-reply-to:subject:cc:to:from
         :dkim-signature;
        bh=spsaMZsKCVaR6klXBbr2ISPdVYP/2QLSe1/E8O7xM2w=;
        fh=GYTHnapjXWiWsMEl7CemZZUcaEMFZyiOFJ0yPGoMTFM=;
        b=UDn9PxQlJ1Hm1WdLZ+5uv0bRPQ0jeQYmillWAr41lqcX/an+Axrvhc/jGSwdTr7p7j
         AHJjKPpsdG8NYfHFtQZrHFakLvl4kvoaW1cSjWlhqrOTzzAM+DtQBd6TmBDXkOLUY4YU
         4kTcVBlodV5IEwy5TJeRXrrfZKqppBERDd6RnVzLj5qpxwsmXdlRt3FmUszxNLej+Rf0
         OAKP1c/eq4plqAFF5qTtmvJ5ijtWAXsjf/Wpdb+PJQOKNvnMpjlz0gB/ueUrtzNc11+z
         KcA6VaLJLWF+OF1VyvxHVj30e8XhnLet+1R5H62c8cWoa8CWFvVqBZuV4++M08MiQX0C
         5d4w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=Zk9DXRfi;
       spf=pass (google.com: domain of ritesh.list@gmail.com designates 2607:f8b0:4864:20::1036 as permitted sender) smtp.mailfrom=ritesh.list@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pj1-x1036.google.com (mail-pj1-x1036.google.com. [2607:f8b0:4864:20::1036])
        by gmr-mx.google.com with ESMTPS id 3f1490d57ef6-e2bdcb24a18si202730276.4.2024.10.21.20.39.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 21 Oct 2024 20:39:51 -0700 (PDT)
Received-SPF: pass (google.com: domain of ritesh.list@gmail.com designates 2607:f8b0:4864:20::1036 as permitted sender) client-ip=2607:f8b0:4864:20::1036;
Received: by mail-pj1-x1036.google.com with SMTP id 98e67ed59e1d1-2e3fca72a41so3415000a91.1
        for <kasan-dev@googlegroups.com>; Mon, 21 Oct 2024 20:39:51 -0700 (PDT)
X-Received: by 2002:a17:90a:ac1:b0:2e5:e43a:1413 with SMTP id 98e67ed59e1d1-2e5e43a16dcmr348166a91.9.1729568390362;
        Mon, 21 Oct 2024 20:39:50 -0700 (PDT)
Received: from dw-tp ([171.76.85.20])
        by smtp.gmail.com with ESMTPSA id 98e67ed59e1d1-2e5ad25cb7asm4873339a91.9.2024.10.21.20.39.45
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 21 Oct 2024 20:39:49 -0700 (PDT)
From: Ritesh Harjani (IBM) <ritesh.list@gmail.com>
To: Michael Ellerman <mpe@ellerman.id.au>, linuxppc-dev@lists.ozlabs.org
Cc: kasan-dev@googlegroups.com, linux-mm@kvack.org, Marco Elver <elver@google.com>, Alexander Potapenko <glider@google.com>, Heiko
 Carstens <hca@linux.ibm.com>, Nicholas Piggin <npiggin@gmail.com>, Madhavan Srinivasan <maddy@linux.ibm.com>, Christophe Leroy <christophe.leroy@csgroup.eu>, Hari Bathini <hbathini@linux.ibm.com>, "Aneesh Kumar K . V" <aneesh.kumar@kernel.org>, Donet Tom <donettom@linux.vnet.ibm.com>, Pavithra Prakash <pavrampu@linux.vnet.ibm.com>, LKML <linux-kernel@vger.kernel.org>, Disha Goel <disgoel@linux.ibm.com>
Subject: Re: [PATCH v3 01/12] powerpc: mm/fault: Fix kfence page fault reporting
In-Reply-To: <87plnsoo2y.fsf@mail.lhotse>
Date: Tue, 22 Oct 2024 08:39:05 +0530
Message-ID: <87o73cygtq.fsf@gmail.com>
References: <cover.1729271995.git.ritesh.list@gmail.com> <a411788081d50e3b136c6270471e35aba3dfafa3.1729271995.git.ritesh.list@gmail.com> <87plnsoo2y.fsf@mail.lhotse>
X-Original-Sender: ritesh.list@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=Zk9DXRfi;       spf=pass
 (google.com: domain of ritesh.list@gmail.com designates 2607:f8b0:4864:20::1036
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

Michael Ellerman <mpe@ellerman.id.au> writes:

> Hi Ritesh,
>
> "Ritesh Harjani (IBM)" <ritesh.list@gmail.com> writes:
>> copy_from_kernel_nofault() can be called when doing read of /proc/kcore.
>> /proc/kcore can have some unmapped kfence objects which when read via
>> copy_from_kernel_nofault() can cause page faults. Since *_nofault()
>> functions define their own fixup table for handling fault, use that
>> instead of asking kfence to handle such faults.
>>
>> Hence we search the exception tables for the nip which generated the
>> fault. If there is an entry then we let the fixup table handler handle the
>> page fault by returning an error from within ___do_page_fault().
>>
>> This can be easily triggered if someone tries to do dd from /proc/kcore.
>> dd if=/proc/kcore of=/dev/null bs=1M
>>
>> <some example false negatives>
>> ===============================
>> BUG: KFENCE: invalid read in copy_from_kernel_nofault+0xb0/0x1c8
>> Invalid read at 0x000000004f749d2e:
>>  copy_from_kernel_nofault+0xb0/0x1c8
>>  0xc0000000057f7950
>>  read_kcore_iter+0x41c/0x9ac
>>  proc_reg_read_iter+0xe4/0x16c
>>  vfs_read+0x2e4/0x3b0
>>  ksys_read+0x88/0x154
>>  system_call_exception+0x124/0x340
>>  system_call_common+0x160/0x2c4
>
> I haven't been able to reproduce this. Can you give some more details on
> the exact machine/kernel-config/setup where you saw this?

w/o this patch I am able to hit this on book3s64 with both Radix and
Hash. I believe these configs should do the job. We should be able to
reproduce it on qemu and/or LPAR or baremetal.

root-> cat .out-ppc/.config |grep -i KFENCE
CONFIG_HAVE_ARCH_KFENCE=y
CONFIG_KFENCE=y
CONFIG_KFENCE_SAMPLE_INTERVAL=100
CONFIG_KFENCE_NUM_OBJECTS=255
# CONFIG_KFENCE_DEFERRABLE is not set
# CONFIG_KFENCE_STATIC_KEYS is not set
CONFIG_KFENCE_STRESS_TEST_FAULTS=0
CONFIG_KFENCE_KUNIT_TEST=y

root-> cat .out-ppc/.config |grep -i KCORE
CONFIG_PROC_KCORE=y

root-> cat .out-ppc/.config |grep -i KUNIT
CONFIG_KFENCE_KUNIT_TEST=y
CONFIG_KUNIT=y
CONFIG_KUNIT_DEFAULT_ENABLED=y


Then doing running dd like below can hit the issue. Maybe let it run for
few mins and see?

~ # dd if=/proc/kcore of=/dev/null bs=1M

Otherwise running this kfence kunit test also can reproduce the same
bug [1]. Above configs have kfence kunit config shown as well which will
run during boot time itself.

[1]: https://lore.kernel.org/linuxppc-dev/210e561f7845697a32de44b643393890f180069f.1729272697.git.ritesh.list@gmail.com/

Note: This was originally reported internally in which the tester was
doing - perf test 'Object code reading'  [2]
[2]: https://github.com/torvalds/linux/blob/master/tools/perf/tests/code-reading.c#L737

Thanks for looking into this. Let me know if this helped.

-ritesh

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/87o73cygtq.fsf%40gmail.com.
