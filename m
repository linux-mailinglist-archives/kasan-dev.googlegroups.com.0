Return-Path: <kasan-dev+bncBD55D5XYUAJBBKUVXCWQMGQEVVQ5LXA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3b.google.com (mail-yb1-xb3b.google.com [IPv6:2607:f8b0:4864:20::b3b])
	by mail.lfdr.de (Postfix) with ESMTPS id D8FCC835AF8
	for <lists+kasan-dev@lfdr.de>; Mon, 22 Jan 2024 07:26:51 +0100 (CET)
Received: by mail-yb1-xb3b.google.com with SMTP id 3f1490d57ef6-dc365b303absf77201276.3
        for <lists+kasan-dev@lfdr.de>; Sun, 21 Jan 2024 22:26:51 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1705904810; cv=pass;
        d=google.com; s=arc-20160816;
        b=B0+1Inp32tqtxKdPFwh9x6fsp0nXt8FmBXjwzz1qtoSInRiRN76wgIhcIqh+aiKOah
         HaYAb3igbbQoPLZFtURl8U/un5BvqkDFN93CMH8ZTdHCWWvVe9860A+zROmAHCW8ICdX
         xja+g019aoXV8R7z/h5M+Go7LL3iLSpLnzUep8nRcZ5XfJ+fbo48lgV3fk/RJk3YnLL3
         LnAU8xcvl7GdsUxvcAXFog34nKAGpfVlY0ydh8D1f7Ui2/I2oeO/fhsl8bfTcTCOQfle
         st98VCbxIQWlYW6y7dSMrw2tjR5e1UcZvdV9qmaWYb00RIh4h9oAIQDymw/lXTdlmZI7
         VUsQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=EU/PMRCdPueA0xauNbqFa/Rxd17Gd6oOqb4kTfKdQCs=;
        fh=SEusk3VrpAPEL476d74p9TaaJo2Qv4hbhNeH8r876T0=;
        b=Dqukwch8afT8JTVAYaFbX28ZZLYe0Lm/Fh/vXYGzD1l9eI+vwF9VYuQ7XE7P4i58eR
         NPklJPOGcMarM+l0T36+bXnMjV0WXcq2VxmA6dghtyhfcFTEiCGSYMLiZO3orTwF77WL
         sHHcJqcqntOgzMBIstNC+eud7EQWvLzItUF/LdW2P0Tmou4pdfrFwtvuHnFbBbkalAYD
         3yTFnTemvl436UqCo70lyFPCBkCz6AFg8do1hKTCWQfD9bJ68RGNfzz8LXZF3uawlT1G
         7LyboXt97GQ2fugbEU1lquEyeXaTfB1zRlXsVj8BqTP/77AbRxpowZgHsjouZvhiWj0Z
         btJw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@bytedance.com header.s=google header.b=eRufEri8;
       spf=pass (google.com: domain of lizhe.67@bytedance.com designates 2607:f8b0:4864:20::632 as permitted sender) smtp.mailfrom=lizhe.67@bytedance.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=bytedance.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1705904810; x=1706509610; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=EU/PMRCdPueA0xauNbqFa/Rxd17Gd6oOqb4kTfKdQCs=;
        b=Wt/sYu2eS8ujGu+CK/5Y4M6gxByAj83i9Cyj+7T78OzfBpJCTIsjbyDItv6FdXk0Rg
         W243MZU2Ysnkf0LpjAhiAINRta9xYJ4wXmQsqsLMVRehDmHV0fG0REIoL6E6X0AN2oea
         zoAYwZsY5Dry/zqIlYFYevwtFBxNT/rLzhqos4giEfWqolombQ+tK5BbDscnMcEsaPIy
         H7s45ziWv2GQygLmXk7O8enbitrYJD9AktlzSwM0QrA7v3bTS6pDNcqf/Q1mZzf5pEmu
         Qu9x0NsozntbP+ksBBMBQnmQFwkvzAqK6Nn4sNL347llw3cDMzXXv+1fhVN6tvFFgUQk
         YePQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1705904810; x=1706509610;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=EU/PMRCdPueA0xauNbqFa/Rxd17Gd6oOqb4kTfKdQCs=;
        b=GNrokna74+P1EEyL3e0r6Xo4XV+e+hM1a+f7QJIb9DUG4l8xAOUs7qgwToDsiprWJi
         bMDCLjzQL1aovZGT4KihdC965dhbN8Jpp8YzI8kAm+iIowfj67P05uqHx1Tm0wo11K41
         Ahuu/9suTm74O1xRNBkCY3SsrY4OJhRNHm57Ni+8NOIjPH9WyTKN6aWjjM9lStSOC24C
         P+tY5oXBNZqHRx+FIk6lp7ePM8+gM2Bt+009A6uVZsyHB5tfnlvxQZS/lT60o7a4t7mA
         rwY5Tyi7FbTy706Dm7kHZUZb3aT/wTAWyrPglxWg4nRIin8rawNNbf74P2okBOxgfCGf
         8tUA==
X-Gm-Message-State: AOJu0YxNGPL5GO5DEqYr6Aa9vftEIrkN2yebtR11TLRdyr8trjFNTEl9
	f7ZkZ4dU43/zJro/bKbuzGnwy9wuccpETcbX4bHgRZMzg3E3lVd9
X-Google-Smtp-Source: AGHT+IEfHLbTykC3aUZ3TBwrEtamwHOF4QlJEYx7ifEqzIwyi0ZWZmlWdHYp0pVdP8lut3lTg5JQbg==
X-Received: by 2002:a25:b01:0:b0:dc2:5199:eef9 with SMTP id 1-20020a250b01000000b00dc25199eef9mr1282919ybl.91.1705904810442;
        Sun, 21 Jan 2024 22:26:50 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6902:726:b0:dc2:2e01:4ff7 with SMTP id
 l6-20020a056902072600b00dc22e014ff7ls1147656ybt.0.-pod-prod-03-us; Sun, 21
 Jan 2024 22:26:49 -0800 (PST)
X-Received: by 2002:a25:aa4a:0:b0:dc2:2e4e:d36c with SMTP id s68-20020a25aa4a000000b00dc22e4ed36cmr1017277ybi.37.1705904809636;
        Sun, 21 Jan 2024 22:26:49 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1705904809; cv=none;
        d=google.com; s=arc-20160816;
        b=fEis8FlTqULwICVyRfjr05QtMtL9v93CWBVSVLPagrz/jmhqPVaYbUGjs7zQm4Ohs/
         4VSkYGEK6fa1ws/kZTmUxoIuiLAPJP1JLJ72JaP/xIrSoFB/TLfhIwfV3f4vO1FFxJmO
         iXZQnYO5+CnnRBdaK04N9XIyGMW287RlaYB4x3Wi53X8z0cwSIxjrUJCoBRPo6X0nW4Q
         A/3wxvcA9ywmemtAH7f4tMIpwmDmDikpFWGyohf1XaDkaYyPqqwErY1RJ3ZRviiVJRQw
         e5IZ3tHhIJ/kSKspaIBocmBBWgkZoi2kvJbdje7QmTMOk44kVHDwLnjQYJs9z/NpVKoV
         efJg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=kN38l1cvAhWonQGb6RjWFKqADiWrIYUoHb0QXErC2kU=;
        fh=SEusk3VrpAPEL476d74p9TaaJo2Qv4hbhNeH8r876T0=;
        b=cRIHRmL9TTZ4OxLSDJT8VXfW5gXRReIq5UM7tST26Ti+LxMRtX6TeJ35DDOtsXgOoV
         eC3fT9v1eqEMsQ/GeGTcdRo/2CXLIsJghw8OmXMjCy0D7adRGGsJpOtf5x/B8COYYxes
         wMUPr2opWhZfOQ4E8EnDysKqrZwvtvmDZoOqEol84BxYn3WlKg4nhlIK7J5nD6FHKGln
         tMgRN4rMG7uUpCqB5Dw1czY3uCdf6qU2ZKa9YyOOSh6mW5DXnjUuoIC//pcpNgHeQuL+
         RxPxWwhCpEi5IMqD2z8gYuGctiIRZ2FV1J/235n8MMIjdPuDaof6RPheoAoCs6s9z70H
         CNZg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@bytedance.com header.s=google header.b=eRufEri8;
       spf=pass (google.com: domain of lizhe.67@bytedance.com designates 2607:f8b0:4864:20::632 as permitted sender) smtp.mailfrom=lizhe.67@bytedance.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=bytedance.com
Received: from mail-pl1-x632.google.com (mail-pl1-x632.google.com. [2607:f8b0:4864:20::632])
        by gmr-mx.google.com with ESMTPS id v137-20020a252f8f000000b00dc265f87529si455727ybv.0.2024.01.21.22.26.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 21 Jan 2024 22:26:49 -0800 (PST)
Received-SPF: pass (google.com: domain of lizhe.67@bytedance.com designates 2607:f8b0:4864:20::632 as permitted sender) client-ip=2607:f8b0:4864:20::632;
Received: by mail-pl1-x632.google.com with SMTP id d9443c01a7336-1d711d7a940so23461245ad.1
        for <kasan-dev@googlegroups.com>; Sun, 21 Jan 2024 22:26:49 -0800 (PST)
X-Received: by 2002:a17:902:d582:b0:1d7:3962:4ce5 with SMTP id k2-20020a170902d58200b001d739624ce5mr2752880plh.67.1705904808816;
        Sun, 21 Jan 2024 22:26:48 -0800 (PST)
Received: from GQ6QX3JCW2.bytedance.net ([203.208.189.13])
        by smtp.gmail.com with ESMTPSA id s9-20020a170902988900b001d756c73a45sm860651plp.62.2024.01.21.22.26.44
        (version=TLS1_3 cipher=TLS_CHACHA20_POLY1305_SHA256 bits=256/256);
        Sun, 21 Jan 2024 22:26:48 -0800 (PST)
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
Date: Mon, 22 Jan 2024 14:26:40 +0800
Message-ID: <20240122062640.27194-1-lizhe.67@bytedance.com>
X-Mailer: git-send-email 2.43.0
In-Reply-To: <CACT4Y+Y8_7f7xxdkEdEMhqHZE5Nru2MMp9=hX6QU6PtdmXU32g@mail.gmail.com>
References: <CACT4Y+Y8_7f7xxdkEdEMhqHZE5Nru2MMp9=hX6QU6PtdmXU32g@mail.gmail.com>
MIME-Version: 1.0
X-Original-Sender: lizhe.67@bytedance.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@bytedance.com header.s=google header.b=eRufEri8;       spf=pass
 (google.com: domain of lizhe.67@bytedance.com designates 2607:f8b0:4864:20::632
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

On Mon, 22 Jan 2024 05:49:29 dvyukov@google.com wrote:
>>
>> From: Li Zhe <lizhe.67@bytedance.com>
>>
>> 1. Problem
>> ==========
>> KASAN is a tools for detecting memory bugs like out-of-bounds and
>> use-after-free. In Generic KASAN mode, it use shadow memory to record
>> the accessible information of the memory. After we allocate a memory
>> from kernel, the shadow memory corresponding to this memory will be
>> marked as accessible.
>> In our daily development, memory problems often occur. If a task
>> accidentally modifies memory that does not belong to itself but has
>> been allocated, some strange phenomena may occur. This kind of problem
>> brings a lot of trouble to our development, and unluckily, this kind of
>> problem cannot be captured by KASAN. This is because as long as the
>> accessible information in shadow memory shows that the corresponding
>> memory can be accessed, KASAN considers the memory access to be legal.
>>
>> 2. Solution
>> ===========
>> We solve this problem by introducing mem track feature base on KASAN
>> with Generic KASAN mode. In the current kernel implementation, we use
>> bits 0-2 of each shadow memory byte to store how many bytes in the 8
>> byte memory corresponding to the shadow memory byte can be accessed.
>> When a 8-byte-memory is inaccessible, the highest bit of its
>> corresponding shadow memory value is 1. Therefore, the key idea is that
>> we can use the currently unused four bits 3-6 in the shadow memory to
>> record relevant track information. Which means, we can use one bit to
>> track 2 bytes of memory. If the track bit of the shadow mem corresponding
>> to a certain memory is 1, it means that the corresponding 2-byte memory
>> is tracked. By adding this check logic to KASAN's callback function, we
>> can use KASAN's ability to capture allocated memory corruption.
>>
>> 3. Simple usage
>> ===========
>> The first step is to mark the memory as tracked after the allocation is
>> completed.
>> The second step is to remove the tracked mark of the memory before the
>> legal access process and re-mark the memory as tracked after finishing
>> the legal access process.
>
>KASAN already has a notion of memory poisoning/unpoisoning.
>See kasan_unpoison_range function. We don't export kasan_poison_range,
>but if you do local debuggng, you can export it locally.

Thank you for your review!

For example, for a 100-byte variable, I may only want to monitor certain
two bytes (byte 3 and 4) in it. According to my understanding,
kasan_poison/unpoison() can not detect the middle bytes individually. So I
don't think function kasan_poison_range() can do what I want.

>
>> The first patch completes the implementation of the mem track, and the
>> second patch provides an interface for using this facility, as well as
>> a testcase for the interface.
>>
>> Li Zhe (2):
>>   kasan: introduce mem track feature base on kasan
>>   kasan: add mem track interface and its test cases
>>
>>  include/linux/kasan.h        |   5 +
>>  lib/Kconfig.kasan            |   9 +
>>  mm/kasan/generic.c           | 437 +++++++++++++++++++++++++++++++++--
>>  mm/kasan/kasan_test_module.c |  26 +++
>>  mm/kasan/report_generic.c    |   6 +
>>  5 files changed, 467 insertions(+), 16 deletions(-)

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240122062640.27194-1-lizhe.67%40bytedance.com.
