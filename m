Return-Path: <kasan-dev+bncBCMIZB7QWENRBRFGXCWQMGQEOO7TSCA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23f.google.com (mail-lj1-x23f.google.com [IPv6:2a00:1450:4864:20::23f])
	by mail.lfdr.de (Postfix) with ESMTPS id 11AEA835B5A
	for <lists+kasan-dev@lfdr.de>; Mon, 22 Jan 2024 08:03:34 +0100 (CET)
Received: by mail-lj1-x23f.google.com with SMTP id 38308e7fff4ca-2cddb0a053asf1920761fa.1
        for <lists+kasan-dev@lfdr.de>; Sun, 21 Jan 2024 23:03:34 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1705907013; cv=pass;
        d=google.com; s=arc-20160816;
        b=0OlmqrnWkJZ7I+t+05QC8oyctlB5h038l+T+dLp5tFTFCUjAukbE7GRwXIIke2xPx5
         OJf5Ma6W/GUKAin/6rPFUAkpVSZ10fCq8MytBCMlMCn6WA4BiWk58dEf4VU5cL6IMA2s
         l86Y5a6nSiWb1B9RKP+aj/nypqKiU7LZNViWVASZ8vprnL1wI+ekdU8iGt8rD4pTpuW+
         ggVonPnz24+k1DdrbVCX/FSlXt4rjaSBRSuDrb6BFdwmb9MvIiHovwJ4UP/9vkpDzlRP
         r0jh4ijAQ3173n8wyLx1nP8qEanZ1T5uoVsF//lfmlg8oBRXytau9137LYNrEBkqyRj5
         Tifg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=Ov0Uo2s4T6tf08ocG3oBJqExCf0ncrrXrecGIHI1Ozs=;
        fh=T8LC/J6AOjdBKq0VjZ9f3dYg0l5V0b6SGk/njn0kl/U=;
        b=J2XqhHhHFf+URKMiTRlPCmkirJ7P/cvqtEtFWho/gIJJpUQAbGhjrfQN6JlUJJHVFY
         CnoUvmB0lh6x2yzIobsq9/ui1Oc0ifPF+rw0ba88EoFbQPx/4L91ELaM2FSUQqXwYXVC
         rf0xQ/i4X89iRBuWfx7ovGsqG1sYh4SHBC1fI3bkJPwB/8lHX+SYvVXj5Pcf0hCeTnDi
         JVarzEJ3Qh8Y2LWeag9ADWGO5UBCT8+bsxN3SnNcsjRb2rHEbYlCJDiuMo6lWoVmUEEz
         7c6ijE80dN2ZEeIUitv+TG44kIbSKXTGnVUURZjAaKV+4oSTmtgI7nEcBKmYciBXb1ds
         O1FA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=ctEGXfKa;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::529 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1705907013; x=1706511813; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=Ov0Uo2s4T6tf08ocG3oBJqExCf0ncrrXrecGIHI1Ozs=;
        b=h9cNSh6syMOf4QZDbnfflHIk9Cm+bFeg3PRSoXBbDRHHxd2nipJ9VS/wY0oG5Q9EmW
         siTfg71GjW47mXLxSaV+hVj1bOIa5U7V1q1OrDhImbWFxF3eC0UbcuwlhCvz246ZkeF5
         T6tDFXyzG4Jr95lEbbIWTqtKOeWhKLSmNCHhpZbhpPzxfSq6fOYevwRycaAOTEi+Yt8b
         WMXNePNWznMyly9mumbxq4O81IMHLqrhnM7vtWL6iXfaC9rCot40yCt4SJZlepkoiJAB
         PzSDrt6iYw8j7vYtjdHosOPeJp7BQdh4pQLekuyVjJ1rRadnU06uUkdM3P/6GBeSlTfA
         9YPQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1705907013; x=1706511813;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Ov0Uo2s4T6tf08ocG3oBJqExCf0ncrrXrecGIHI1Ozs=;
        b=OIdNBPZjCQDR5WuBzXYNs0QDW0eaxmeQ2uh/rDr9F2e4BIDm4Uzd7MOS8y/J4tLHNG
         TG/nKd6OrSxQpwmavxtUC10ffny/moE9XseZH3M45JNJ6Lufmc0uM+EmVOJLTusWqnxp
         UPfAvNKmbq/dHtK8Qh2Z+hD39pKtPhI3C9MMfPZ0D+P2KUxDCWGR3mlTe9YVsrw3HDvt
         IG8xOrIHGn0t3/ZJPtEUsw/hUn6cw81TFfpLT2e4cn6KWjTL0iocOQBC6evjOYYsiSSP
         ibosbmVmSFA3aExzs1c3VvnkM47qamtihsA+AJ5DzWt6z+Zv5Gh05Wg0L1FnbqsBKf3W
         /c1g==
X-Gm-Message-State: AOJu0YwaOUGE2eYWgNtXeI6rUZRPpF3d0hH4vUQ61EIN2Z1BECUQCTl7
	XKEOWnWb2zkwp/Beih+i7FMFJJq1qqajCMjRY3Haae5MyrBiTt1G
X-Google-Smtp-Source: AGHT+IF6yaSIkUPUHd+GoNyiIgjwTWUx/9RHG+Ea9YkkSldLInO8V713lCOeVP3M8iyt/S3vqISoKQ==
X-Received: by 2002:a2e:a99a:0:b0:2ce:aa0c:8217 with SMTP id x26-20020a2ea99a000000b002ceaa0c8217mr1498189ljq.4.1705907013021;
        Sun, 21 Jan 2024 23:03:33 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:a7c9:0:b0:2cc:e70b:1d80 with SMTP id x9-20020a2ea7c9000000b002cce70b1d80ls1569032ljp.1.-pod-prod-08-eu;
 Sun, 21 Jan 2024 23:03:31 -0800 (PST)
X-Received: by 2002:ac2:490f:0:b0:50e:7c9c:8ead with SMTP id n15-20020ac2490f000000b0050e7c9c8eadmr580910lfi.277.1705907011056;
        Sun, 21 Jan 2024 23:03:31 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1705907011; cv=none;
        d=google.com; s=arc-20160816;
        b=VsiSB1bT+jCzDCKOteyfZ6HkvaPBo9zR9NmUwGGMdsn4bIg/+uXFoXvDVIlPiosZcg
         EaymwjJqzlDvQ/mQ2LARG69a/C8GOQ8hyE0huTXHwZ5I2Nk9801yr+up+5yuWvZ1X20X
         wnTIwSP8rMiLCjxFeZW8yn17dhRQ9+Gcw6m9ZkoQYyMIoivspj7LWIzS3cLohXnqERWv
         Z6CBd37geTnE5NSRiONK634ynBQOjMxFMKN6CuRJqwfygQCi6Y4lauuUpTaMY2BUhK9p
         nCkI3CoozvTZ5nYRwis1irxAPMXpCDxjjyyuUKt135MNCZnpY4a3jwrzihggIZ3Z4/dp
         NKmg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=pXLsqGupBVyqTRGsAFhb8TjHLWoEu5WlfLnEzzOFFR0=;
        fh=T8LC/J6AOjdBKq0VjZ9f3dYg0l5V0b6SGk/njn0kl/U=;
        b=hSeGPzoTkcAe9U9R/dDr1RfrzTEWpKYZkebGAxeljBkabgy9MA0eIz/VgnxODdIafd
         kbAKPRhjRUpWcQDYG2s3MfQOIaUZhR9vgZ9/mCPAb5I3BmfbCS5E82++QKymnUYZqQNN
         obh84E9P6akhwNTg+ndyeUrr28YjW+oJ7MpJoEdlvwf8iIUZRONRXCVZLHC6OKm2Dh/t
         NERDz5SZP+6tZVwJKduWhMBfz8joKK7phPIfP7eNK1ZKGUIOdqA8VpI2gycczfRMc/xF
         izaXteLlkB68nBHjVHTfLzIb01Etxcz3gaj25tJiUf+4a0kj/R2VAHqx6gGkeFLjEiPg
         A0Uw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=ctEGXfKa;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::529 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x529.google.com (mail-ed1-x529.google.com. [2a00:1450:4864:20::529])
        by gmr-mx.google.com with ESMTPS id u20-20020a05651206d400b0050e7af6a9a0si357151lff.10.2024.01.21.23.03.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 21 Jan 2024 23:03:31 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::529 as permitted sender) client-ip=2a00:1450:4864:20::529;
Received: by mail-ed1-x529.google.com with SMTP id 4fb4d7f45d1cf-55a6a4339c7so8086a12.1
        for <kasan-dev@googlegroups.com>; Sun, 21 Jan 2024 23:03:31 -0800 (PST)
X-Received: by 2002:a05:6402:1c93:b0:55a:7f4e:1d62 with SMTP id
 cy19-20020a0564021c9300b0055a7f4e1d62mr181758edb.4.1705907010220; Sun, 21 Jan
 2024 23:03:30 -0800 (PST)
MIME-Version: 1.0
References: <CACT4Y+Y8_7f7xxdkEdEMhqHZE5Nru2MMp9=hX6QU6PtdmXU32g@mail.gmail.com>
 <20240122062640.27194-1-lizhe.67@bytedance.com>
In-Reply-To: <20240122062640.27194-1-lizhe.67@bytedance.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 22 Jan 2024 08:03:17 +0100
Message-ID: <CACT4Y+Z=djX7aHcsj48_FGAOTyCEe31RbS=SNzxYa27kvyNXKw@mail.gmail.com>
Subject: Re: [RFC 0/2] kasan: introduce mem track feature
To: lizhe.67@bytedance.com
Cc: akpm@linux-foundation.org, andreyknvl@gmail.com, glider@google.com, 
	kasan-dev@googlegroups.com, linux-mm@kvack.org, lizefan.x@bytedance.com, 
	ryabinin.a.a@gmail.com, vincenzo.frascino@arm.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=ctEGXfKa;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::529
 as permitted sender) smtp.mailfrom=dvyukov@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Dmitry Vyukov <dvyukov@google.com>
Reply-To: Dmitry Vyukov <dvyukov@google.com>
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

On Mon, 22 Jan 2024 at 07:26, <lizhe.67@bytedance.com> wrote:
> >> From: Li Zhe <lizhe.67@bytedance.com>
> >>
> >> 1. Problem
> >> ==========
> >> KASAN is a tools for detecting memory bugs like out-of-bounds and
> >> use-after-free. In Generic KASAN mode, it use shadow memory to record
> >> the accessible information of the memory. After we allocate a memory
> >> from kernel, the shadow memory corresponding to this memory will be
> >> marked as accessible.
> >> In our daily development, memory problems often occur. If a task
> >> accidentally modifies memory that does not belong to itself but has
> >> been allocated, some strange phenomena may occur. This kind of problem
> >> brings a lot of trouble to our development, and unluckily, this kind of
> >> problem cannot be captured by KASAN. This is because as long as the
> >> accessible information in shadow memory shows that the corresponding
> >> memory can be accessed, KASAN considers the memory access to be legal.
> >>
> >> 2. Solution
> >> ===========
> >> We solve this problem by introducing mem track feature base on KASAN
> >> with Generic KASAN mode. In the current kernel implementation, we use
> >> bits 0-2 of each shadow memory byte to store how many bytes in the 8
> >> byte memory corresponding to the shadow memory byte can be accessed.
> >> When a 8-byte-memory is inaccessible, the highest bit of its
> >> corresponding shadow memory value is 1. Therefore, the key idea is that
> >> we can use the currently unused four bits 3-6 in the shadow memory to
> >> record relevant track information. Which means, we can use one bit to
> >> track 2 bytes of memory. If the track bit of the shadow mem corresponding
> >> to a certain memory is 1, it means that the corresponding 2-byte memory
> >> is tracked. By adding this check logic to KASAN's callback function, we
> >> can use KASAN's ability to capture allocated memory corruption.
> >>
> >> 3. Simple usage
> >> ===========
> >> The first step is to mark the memory as tracked after the allocation is
> >> completed.
> >> The second step is to remove the tracked mark of the memory before the
> >> legal access process and re-mark the memory as tracked after finishing
> >> the legal access process.
> >
> >KASAN already has a notion of memory poisoning/unpoisoning.
> >See kasan_unpoison_range function. We don't export kasan_poison_range,
> >but if you do local debuggng, you can export it locally.
>
> Thank you for your review!
>
> For example, for a 100-byte variable, I may only want to monitor certain
> two bytes (byte 3 and 4) in it. According to my understanding,
> kasan_poison/unpoison() can not detect the middle bytes individually. So I
> don't think function kasan_poison_range() can do what I want.

That's something to note in the description/comments.

How many ranges do you intend to protect this way?
If that's not too many, then a better option would be to poison these
ranges normally and store ranges that a thread can access currently on
a side.
This will give both 1-byte precision, filtering for reads/writes
separately and better diagnostics.


> >> The first patch completes the implementation of the mem track, and the
> >> second patch provides an interface for using this facility, as well as
> >> a testcase for the interface.
> >>
> >> Li Zhe (2):
> >>   kasan: introduce mem track feature base on kasan
> >>   kasan: add mem track interface and its test cases
> >>
> >>  include/linux/kasan.h        |   5 +
> >>  lib/Kconfig.kasan            |   9 +
> >>  mm/kasan/generic.c           | 437 +++++++++++++++++++++++++++++++++--
> >>  mm/kasan/kasan_test_module.c |  26 +++
> >>  mm/kasan/report_generic.c    |   6 +
> >>  5 files changed, 467 insertions(+), 16 deletions(-)

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BZ%3DdjX7aHcsj48_FGAOTyCEe31RbS%3DSNzxYa27kvyNXKw%40mail.gmail.com.
