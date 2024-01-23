Return-Path: <kasan-dev+bncBD55D5XYUAJBB5NYXWWQMGQEXZAZKNA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc39.google.com (mail-oo1-xc39.google.com [IPv6:2607:f8b0:4864:20::c39])
	by mail.lfdr.de (Postfix) with ESMTPS id C702783874D
	for <lists+kasan-dev@lfdr.de>; Tue, 23 Jan 2024 07:28:06 +0100 (CET)
Received: by mail-oo1-xc39.google.com with SMTP id 006d021491bc7-598b8e2b2bfsf5527334eaf.2
        for <lists+kasan-dev@lfdr.de>; Mon, 22 Jan 2024 22:28:06 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1705991285; cv=pass;
        d=google.com; s=arc-20160816;
        b=hjVNww41GJ+F3K10Rcn9YFZJpvqyQl77mG7w63h+On8awrz356/4uxquZcb50/mPR8
         aaTv4BdtE2FA7PjOewKhC5zDi7CUfcuI9Wx9+P+Dvy7qxW/HMMvlD8HCMt4okPrYDPxM
         Zf1Vg2zuyeAUxG3FNrcekD3l5bH1zmcgh0SZfulx4b+rsoSKH7mQ90Nm1sJp9gzSIr1P
         6Br4stwUzuijQNdDgVaCuGdWWPcHeIMvQJng3dNQEn6hV5bDSfSxrNH2okNPhH84upnP
         +yRhwbvwVia3Cw6VNSuE1n/OQlkg/SD6LOoSKTCvrQGimEipuWyZtNSV0E1YJvPjOKS9
         Kk7w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=Jqq4JdjQAgDUI7Ve3a0t3sxjH4W8e+dqwyLGxyz18zI=;
        fh=SEusk3VrpAPEL476d74p9TaaJo2Qv4hbhNeH8r876T0=;
        b=fpdUWiW7cyaELnVFaVMTLaRSqeHWT6YoEYWuI1fWTSA3jYetUjOjBXldLVZEZJDsze
         GZGFoRs9vBYiDbLbZyFRBRK/SCDPII1CyqAteR2erkNb4nS0McQfOqNOJaB+xPd3auLJ
         vE7Yf55d/4Tlbk3qRzvatN3fprCZ+BE6z9z85cW9lBupPhfumvc6ylw4+Id9GmZJai/b
         ra9/jTTkkDh1k/S06UuC7AgnEFO6C2NFk+O6sjSfqRHFgnl85HkLMqsVE1MQzK4CBTgX
         9Uqp+M/PQADiADmeHrjzi8Yb8/Klvc1PEtTOsIX2Stu/swYC6YnVAtRGDr+gyszDgMFV
         9tHg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@bytedance.com header.s=google header.b=VVekPsvm;
       spf=pass (google.com: domain of lizhe.67@bytedance.com designates 2607:f8b0:4864:20::1036 as permitted sender) smtp.mailfrom=lizhe.67@bytedance.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=bytedance.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1705991285; x=1706596085; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=Jqq4JdjQAgDUI7Ve3a0t3sxjH4W8e+dqwyLGxyz18zI=;
        b=OG2hZNPhtL70XsNh5f8WXlMs6NyRM15M32L792LDmHVJv905W7c0wWlStsdwQWEdRy
         jFfQAQkQHcLITVPRVuQC7+CGnRjL61hJHagXV1y9Rqi4Mf3RptL1WT0eJ+n1FBkJS3IW
         KURRWLMhXUMyFsbRSABLTw4IyI/LrjDJCk6t4Uc355xFmqMqP9a/Dfi56t43zv+D2+7j
         v23dS9A0ZGaVuOUKFSPk+yMmPrZApEVYbCrqRSdGVkxEBjEkQgT87u+A/FHpvXklZ/69
         HJZllM+ENYUpd2bmYE3vuKG9Ic3MhDyPZfllETOFvJjxk0bzbJijgKvnwJLQGLstsbo5
         SDlw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1705991285; x=1706596085;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Jqq4JdjQAgDUI7Ve3a0t3sxjH4W8e+dqwyLGxyz18zI=;
        b=iqcDDBXsCCyOVJTtsG7MWN31YEiHFwaVxPuyffVo27KxdWJquxUI17RERqfWl7qfWj
         gSt4OdcSBoQyvRUoX26ufn3ft0YS8cfhZrY7fI46AmqEeXYsCZGYBSXWuMzhigUkfzzP
         3Za4OVPJdnWQ0ydfuwdSnqaXKWY0t+uNT+jJTWmSAhV4XDozeBuku9g0SlHD0M/Vlsuh
         6lfsqyLpJkrLcZMxpD/4O85VgsW6F84qbSRO6xd++VBia3io60tv4+IrbdUHU2APC4kN
         IPXDGMJfSnif9deCnVlmXO2UxUxG5fmMH8rrABp1Tocc2h9/UuCnhPCnJJwFV2xJQNAB
         nH4g==
X-Gm-Message-State: AOJu0YzpCa819M6NQ4vvbArVlzQZK6bOb+Bvt+KDgmJwun/zkT3lET/i
	yojSNpjNC3Gx2824gtkvXyzWVU5aQ6M8s8+U0GkRdvEf6hz0D8a0
X-Google-Smtp-Source: AGHT+IGPtwwZ+3lClOQ3u9uu5psuhLDtF5p3qLfhc1naUb7rmFl9z/DImHJDrJ5paAzgeWF05WkARA==
X-Received: by 2002:a4a:b142:0:b0:598:ab21:17be with SMTP id e2-20020a4ab142000000b00598ab2117bemr2972251ooo.6.1705991285340;
        Mon, 22 Jan 2024 22:28:05 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:55d7:0:b0:599:668b:99ce with SMTP id e206-20020a4a55d7000000b00599668b99cels2813446oob.1.-pod-prod-07-us;
 Mon, 22 Jan 2024 22:28:04 -0800 (PST)
X-Received: by 2002:a9d:6f16:0:b0:6dd:fcbe:3cf with SMTP id n22-20020a9d6f16000000b006ddfcbe03cfmr6653672otq.8.1705991284615;
        Mon, 22 Jan 2024 22:28:04 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1705991284; cv=none;
        d=google.com; s=arc-20160816;
        b=cZ1VMSG8h1zrVIf2BVze8LVwwIN/Q5HUr2Gp4CIUsdlNtHTAwO7KdIqJx8gcfy/FhM
         ifFi+thLnLRDiTiocveSmjdsiTdnujlmJilGkvdL4vOX+EnmOLPvl8BLikEFIPz5syB0
         9MxT8nEuvj2He8d4qjqhb4E6SE7aAsZfYnhOAK1v/R+Ruu7bOduXmyWVGBeBHHep4uvc
         zXKp7Uwrcx2CtzjMySKIjfB65jL0kplP2rWuvrR9C4/Ia5sOUal5l7FRsnUxNoDtTJpf
         W+Uk9a3JkVGva7VClfPL7GIRJesZ6i39zOB4WlJQwr5gHgpIgRTM/kbgotrTpwlhYiDb
         Uf+Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=wiLvfLf4OGeDGMn4ocLXudOpmwX+r0wZE0fc2HKgdsY=;
        fh=SEusk3VrpAPEL476d74p9TaaJo2Qv4hbhNeH8r876T0=;
        b=sBZzwhhq3flZvvY70h4J5T/68Qb5ouZbUXw5IXiyZOXUE4YjYkAu6qXd+Fu1JypD/Y
         n5OWwSLshRfpECz2dFQdkML/eYHHIra4daegoXty7g00bzHQwR40Wimq9WVuAEUNF2ul
         cfepjZLh9iEPdFlJ6wekdm22R43zYN1WbF0VmUcJdRRzd40YJTs+ZToSQYnPDAJKkZk8
         3PXkYewYpawNhD4krr3cBwtdiFDl59DyVMJuYqphsF7f/vbFjPgbkIhn/GqgF8mwxPx1
         94vrXCIySdvOb5oJC7lqnzzsUEUJ21YLJ+SxJ1DcOKCsqAoWzTmEQqbTm2iFbCxt5+d8
         498w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@bytedance.com header.s=google header.b=VVekPsvm;
       spf=pass (google.com: domain of lizhe.67@bytedance.com designates 2607:f8b0:4864:20::1036 as permitted sender) smtp.mailfrom=lizhe.67@bytedance.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=bytedance.com
Received: from mail-pj1-x1036.google.com (mail-pj1-x1036.google.com. [2607:f8b0:4864:20::1036])
        by gmr-mx.google.com with ESMTPS id w16-20020a9d70d0000000b006e0e2259787si415041otj.5.2024.01.22.22.28.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 22 Jan 2024 22:28:04 -0800 (PST)
Received-SPF: pass (google.com: domain of lizhe.67@bytedance.com designates 2607:f8b0:4864:20::1036 as permitted sender) client-ip=2607:f8b0:4864:20::1036;
Received: by mail-pj1-x1036.google.com with SMTP id 98e67ed59e1d1-2909a632e40so991259a91.0
        for <kasan-dev@googlegroups.com>; Mon, 22 Jan 2024 22:28:04 -0800 (PST)
X-Received: by 2002:a17:90a:86:b0:290:cef3:822a with SMTP id a6-20020a17090a008600b00290cef3822amr350946pja.90.1705991283601;
        Mon, 22 Jan 2024 22:28:03 -0800 (PST)
Received: from GQ6QX3JCW2.bytedance.net ([203.208.189.7])
        by smtp.gmail.com with ESMTPSA id pl3-20020a17090b268300b002909eb075dasm3502608pjb.8.2024.01.22.22.27.59
        (version=TLS1_3 cipher=TLS_CHACHA20_POLY1305_SHA256 bits=256/256);
        Mon, 22 Jan 2024 22:28:03 -0800 (PST)
From: "lizhe.67 via kasan-dev" <kasan-dev@googlegroups.com>
To: dvyukov@google.com
Cc: akpm@linux-foundation.org,
	andreyknvl@gmail.com,
	glider@google.com,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	lizefan.x@bytedance.com,
	lizhe.67@bytedance.com,
	ryabinin.a.a@gmail.com,
	vincenzo.frascino@arm.com
Subject: Re: [RFC 0/2] kasan: introduce mem track feature
Date: Tue, 23 Jan 2024 14:27:56 +0800
Message-ID: <20240123062756.87505-1-lizhe.67@bytedance.com>
X-Mailer: git-send-email 2.43.0
In-Reply-To: <CACT4Y+Z=djX7aHcsj48_FGAOTyCEe31RbS=SNzxYa27kvyNXKw@mail.gmail.com>
References: <CACT4Y+Z=djX7aHcsj48_FGAOTyCEe31RbS=SNzxYa27kvyNXKw@mail.gmail.com>
MIME-Version: 1.0
X-Original-Sender: lizhe.67@bytedance.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@bytedance.com header.s=google header.b=VVekPsvm;       spf=pass
 (google.com: domain of lizhe.67@bytedance.com designates 2607:f8b0:4864:20::1036
 as permitted sender) smtp.mailfrom=lizhe.67@bytedance.com;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=bytedance.com
X-Original-From: lizhe.67@bytedance.com
Reply-To: lizhe.67@bytedance.com
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

On Mon, 22 Jan 2024 08:03:17, dvyukov@google.com wrote:
>> >> From: Li Zhe <lizhe.67@bytedance.com>
>> >>
>> >> 1. Problem
>> >> ==========
>> >> KASAN is a tools for detecting memory bugs like out-of-bounds and
>> >> use-after-free. In Generic KASAN mode, it use shadow memory to record
>> >> the accessible information of the memory. After we allocate a memory
>> >> from kernel, the shadow memory corresponding to this memory will be
>> >> marked as accessible.
>> >> In our daily development, memory problems often occur. If a task
>> >> accidentally modifies memory that does not belong to itself but has
>> >> been allocated, some strange phenomena may occur. This kind of problem
>> >> brings a lot of trouble to our development, and unluckily, this kind of
>> >> problem cannot be captured by KASAN. This is because as long as the
>> >> accessible information in shadow memory shows that the corresponding
>> >> memory can be accessed, KASAN considers the memory access to be legal.
>> >>
>> >> 2. Solution
>> >> ===========
>> >> We solve this problem by introducing mem track feature base on KASAN
>> >> with Generic KASAN mode. In the current kernel implementation, we use
>> >> bits 0-2 of each shadow memory byte to store how many bytes in the 8
>> >> byte memory corresponding to the shadow memory byte can be accessed.
>> >> When a 8-byte-memory is inaccessible, the highest bit of its
>> >> corresponding shadow memory value is 1. Therefore, the key idea is that
>> >> we can use the currently unused four bits 3-6 in the shadow memory to
>> >> record relevant track information. Which means, we can use one bit to
>> >> track 2 bytes of memory. If the track bit of the shadow mem corresponding
>> >> to a certain memory is 1, it means that the corresponding 2-byte memory
>> >> is tracked. By adding this check logic to KASAN's callback function, we
>> >> can use KASAN's ability to capture allocated memory corruption.
>> >>
>> >> 3. Simple usage
>> >> ===========
>> >> The first step is to mark the memory as tracked after the allocation is
>> >> completed.
>> >> The second step is to remove the tracked mark of the memory before the
>> >> legal access process and re-mark the memory as tracked after finishing
>> >> the legal access process.
>> >
>> >KASAN already has a notion of memory poisoning/unpoisoning.
>> >See kasan_unpoison_range function. We don't export kasan_poison_range,
>> >but if you do local debuggng, you can export it locally.
>>
>> Thank you for your review!
>>
>> For example, for a 100-byte variable, I may only want to monitor certain
>> two bytes (byte 3 and 4) in it. According to my understanding,
>> kasan_poison/unpoison() can not detect the middle bytes individually. So I
>> don't think function kasan_poison_range() can do what I want.
>
>That's something to note in the description/comments.
>
>How many ranges do you intend to protect this way?
>If that's not too many, then a better option would be to poison these
>ranges normally and store ranges that a thread can access currently on
>a side.
>This will give both 1-byte precision, filtering for reads/writes
>separately and better diagnostics.

OK I will find a better method to solve this problem.

Thank you!
>
>> >> The first patch completes the implementation of the mem track, and the
>> >> second patch provides an interface for using this facility, as well as
>> >> a testcase for the interface.
>> >>
>> >> Li Zhe (2):
>> >>   kasan: introduce mem track feature base on kasan
>> >>   kasan: add mem track interface and its test cases
>> >>
>> >>  include/linux/kasan.h        |   5 +
>> >>  lib/Kconfig.kasan            |   9 +
>> >>  mm/kasan/generic.c           | 437 +++++++++++++++++++++++++++++++++--
>> >>  mm/kasan/kasan_test_module.c |  26 +++
>> >>  mm/kasan/report_generic.c    |   6 +
>> >>  5 files changed, 467 insertions(+), 16 deletions(-)

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240123062756.87505-1-lizhe.67%40bytedance.com.
