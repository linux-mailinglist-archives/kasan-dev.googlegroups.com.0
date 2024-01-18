Return-Path: <kasan-dev+bncBD55D5XYUAJBB7HLUSWQMGQEROAXYOY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x440.google.com (mail-pf1-x440.google.com [IPv6:2607:f8b0:4864:20::440])
	by mail.lfdr.de (Postfix) with ESMTPS id 6E12B831B5C
	for <lists+kasan-dev@lfdr.de>; Thu, 18 Jan 2024 15:30:22 +0100 (CET)
Received: by mail-pf1-x440.google.com with SMTP id d2e1a72fcca58-6da0d1d6674sf14536701b3a.1
        for <lists+kasan-dev@lfdr.de>; Thu, 18 Jan 2024 06:30:22 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1705588221; cv=pass;
        d=google.com; s=arc-20160816;
        b=vnBkv5f4zabaERTKuG1ZeLi79qelWXl1P9oARQGy9G7XZFe9Gpa46tPkVERrTL6m2w
         DaBfFhgJ0SQO3aMsFmeTZZ7wFB0VRU34LvPLYja3g80snqxNJXG1yDDbYvGyhmrHLj3V
         QxQ7t+7CC4sfk1wmXkXMQ6ji644blQZEK/4B+Gxq61IvokMk/BBfqAg6qg3SUtI7Qn3/
         l5yS7hOzxToPKVZX+gZCW7yXKvTdxb3siFMYWObD9fh7wYgiTRDKQ3DK2/OD61doOA/3
         jHl6H4fXYm2UqHcyFaYba7fvSQrbv5Vep1+jocQowjQCAQxbPFRdx3wPT1BdfD6CRahe
         jsVw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=b2BmiE7/e501fTQA0qInKdnHFgam3K/xJ30Ubx1Mq8E=;
        fh=QCxZqGCt8UVcZnra71mX8wr/fexkJiddsR4O2uJUGz8=;
        b=F5AgNPnYwvTp0rgeQFW4A6SXilF1XlzekGSyN3ko2Tqfk1913n2East/P91TrQrOxM
         8IyZ4nsskIwdwex4+1fmfInYJJfD4GmaxgR26BhpTy2TNADpetLExT7UOowuw53LFbsq
         sbajOFDVV7R97P98FuvPQrJ5Mx0DcHJZXfNziYLVWiMoK+02NYkc/2VuHwaUdnkdU3lX
         9PjVRlJouZmExzY8TfqV9Ds1YHaRz4/1xe5aw03kU4Xn6DsxKFZ6IV+Bqv5ItJEwlzsz
         neQwXDp5gazLicmQpP87BGGtFc/ex5mQgnj/o/rpVzZ46K48uKufpqGrXtKVzC7lGNvF
         9qKQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@bytedance.com header.s=google header.b=IeNlM7Ke;
       spf=pass (google.com: domain of lizhe.67@bytedance.com designates 2607:f8b0:4864:20::62c as permitted sender) smtp.mailfrom=lizhe.67@bytedance.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=bytedance.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1705588221; x=1706193021; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=b2BmiE7/e501fTQA0qInKdnHFgam3K/xJ30Ubx1Mq8E=;
        b=h7diY2GdVQCMJ6QflvTDUHSjq1sHaHNz95FrTPwrlHsVszOH5d9Wy5ILk0omO2NxDX
         RLXkiCgUIfRtXaAD6JqmwoKCB1KYeAsm3VKknhWpk4bRxhXqbekuFs/QG6LU1yDHPHai
         2/bJqx9QCoBV4+Snq7ax787x9RVbblEMmLou1n/8dinDofuGKcKYJ+K6eg3/0F1yLc0t
         kyLxWu9LGqZ8pXoxsYhHajvrmhYoGLOJF6y51fHDhMKn2qNYQFboiJ8gqcuAl3Axa8/V
         pzrJgUGvjs5ZtD5wDNokT1i8nGLY5Yh1xsDt2rKPKzSdI86zW1aX8lcIxxpb74xNtizU
         Hazw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1705588221; x=1706193021;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=b2BmiE7/e501fTQA0qInKdnHFgam3K/xJ30Ubx1Mq8E=;
        b=eqioq83RR2sGQd32zUZpF5iJkTUxCxlZ+0iKe975fVsTtVWRHBvq4FXCHAl8ngH93q
         yk/zifRcxtaeqwkkSXndue7YLfxFQqt/fR7tKSEBjuiHePIcHysy9uAT78NTeGiGReAn
         Dk0gGabPTni2KtFJvvtQoggZ2coz6RLUwhuvQ9sZNPhLX7se9UWCYf4fwNcW865w4PE0
         iAwjLepSTSVEwiLj5cAoC77NtBEw+OXZETJMuRFx3KwaDlmr/UUt8AnyavnqvykUiOkQ
         xge6Z+dsQ4jV0rzGVZSSbm5TSZ4BDVX56JJPKxFe98qZngiLeDRdTV9CYU6Y5P1niE+U
         xE1A==
X-Gm-Message-State: AOJu0YyeAaOpoajoaYD50u82p1fSLhcP1DiEv6XP1XMgStMTbb9wv+Vp
	j+3rLczP/k1pCwnd/2PufIyIgVuqQ2vajBIGILgDMRvpJjL+Y53y
X-Google-Smtp-Source: AGHT+IH288IeOFpX8O3Ea6ynjA++yJz1I5qOAVJOSqQwfvKXkAw/dg+/FhPKu1GvG+r9rm/9+vY1Zw==
X-Received: by 2002:a05:6a21:6d90:b0:199:87dc:4f0a with SMTP id wl16-20020a056a216d9000b0019987dc4f0amr1018398pzb.95.1705588220763;
        Thu, 18 Jan 2024 06:30:20 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:3105:b0:290:108:3d8d with SMTP id
 gc5-20020a17090b310500b0029001083d8dls1050626pjb.0.-pod-prod-03-us; Thu, 18
 Jan 2024 06:30:19 -0800 (PST)
X-Received: by 2002:a17:90a:1f85:b0:28f:fbf7:c3f8 with SMTP id x5-20020a17090a1f8500b0028ffbf7c3f8mr828364pja.80.1705588219649;
        Thu, 18 Jan 2024 06:30:19 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1705588219; cv=none;
        d=google.com; s=arc-20160816;
        b=Wvw9e7TafHk75OjT75KUXU6rm84rNPVR+nFN6+VBYgjBE6zmZH1jBzf3y9aLWlrzAU
         MOwyoqwfactvQ8AgnYH0QU2hRb2A2OIJ0KDnhTz4dQZqiOZ4hCztK4XqUqtsuD0ctm5E
         elFj9qgyUHvyRaWFNFBzTIv+gf9NaPSk1j1CksEub7sTmzKTIjmEbP5I/cQuguxfBKA/
         j2Ek2x5vWx+FV9jsyPLiACstNrLPoVq/yEpezCuUwx0rLL8Z5dt18XzTnk8ClDKvNqWk
         xoEH9LPTT5UwlrSAqAXhb/vfiyFm1wIGE7wwQsY4LcaVY5ZKbEixHq7CrDS2vYWY87af
         wRjQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=N3C5sTiWMzIfhZ6qTPUb3ie9E/4j8GA/fiWbUnWQwt0=;
        fh=QCxZqGCt8UVcZnra71mX8wr/fexkJiddsR4O2uJUGz8=;
        b=wnXggoGQYaxzrlBg1KwekqEV6fzkA/yWAtH89NAJo2dKlPsf4wDBthFV0k67iwGBs+
         YxM2vD8OWkcDSTEmY/I8XoCEgpMiwY0Lu2slwSHci6BaMwHafoF35Drl0eBarH+llYDL
         rMNGyGkWyc2lUBGTq86vKKDekN2I2j8BsBYRd8JpVmt5zl3ALabL4VEQgLhkpfs89oM5
         +lVTPWhZT0ntUYgas8tAVqxhjdJAUDJ3WkJ7u7pi7rhyThftYxAfU93WhRkyGdV78UOH
         xSp5DeZz0+xZEB9SEiH/LrTesj8F3TkQIdX6Qctt1mKzbMPIYTaN3srtI9YfR3mYbyo/
         zcZA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@bytedance.com header.s=google header.b=IeNlM7Ke;
       spf=pass (google.com: domain of lizhe.67@bytedance.com designates 2607:f8b0:4864:20::62c as permitted sender) smtp.mailfrom=lizhe.67@bytedance.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=bytedance.com
Received: from mail-pl1-x62c.google.com (mail-pl1-x62c.google.com. [2607:f8b0:4864:20::62c])
        by gmr-mx.google.com with ESMTPS id c10-20020a17090a8d0a00b0028e7b76091csi135881pjo.3.2024.01.18.06.30.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 18 Jan 2024 06:30:19 -0800 (PST)
Received-SPF: pass (google.com: domain of lizhe.67@bytedance.com designates 2607:f8b0:4864:20::62c as permitted sender) client-ip=2607:f8b0:4864:20::62c;
Received: by mail-pl1-x62c.google.com with SMTP id d9443c01a7336-1d480c6342dso93401785ad.2
        for <kasan-dev@googlegroups.com>; Thu, 18 Jan 2024 06:30:19 -0800 (PST)
X-Received: by 2002:a17:902:9a42:b0:1d5:9983:bf74 with SMTP id x2-20020a1709029a4200b001d59983bf74mr774348plv.105.1705588219253;
        Thu, 18 Jan 2024 06:30:19 -0800 (PST)
Received: from GQ6QX3JCW2.bytedance.net ([203.208.189.11])
        by smtp.gmail.com with ESMTPSA id mf3-20020a170902fc8300b001d6f0e6095fsm1466233plb.197.2024.01.18.06.30.14
        (version=TLS1_3 cipher=TLS_CHACHA20_POLY1305_SHA256 bits=256/256);
        Thu, 18 Jan 2024 06:30:18 -0800 (PST)
From: "lizhe.67 via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com
Cc: akpm@linux-foundation.org,
	andreyknvl@gmail.com,
	dvyukov@google.com,
	glider@google.com,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	lizefan.x@bytedance.com,
	lizhe.67@bytedance.com,
	ryabinin.a.a@gmail.com,
	vincenzo.frascino@arm.com
Subject: Re: [RFC 0/2] kasan: introduce mem track feature
Date: Thu, 18 Jan 2024 22:30:10 +0800
Message-ID: <20240118143010.43614-1-lizhe.67@bytedance.com>
X-Mailer: git-send-email 2.43.0
In-Reply-To: <CANpmjNOnxvGNtApe50vyAZLmoNbEpLeMiKHXRuRABkn6nhEQWA@mail.gmail.com>
References: <CANpmjNOnxvGNtApe50vyAZLmoNbEpLeMiKHXRuRABkn6nhEQWA@mail.gmail.com>
MIME-Version: 1.0
X-Original-Sender: lizhe.67@bytedance.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@bytedance.com header.s=google header.b=IeNlM7Ke;       spf=pass
 (google.com: domain of lizhe.67@bytedance.com designates 2607:f8b0:4864:20::62c
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

On Thu, 18 Jan 2024 14:28:00, elver@google.com wrote:
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
>
>Note: "track" is already an overloaded word with KASAN, meaning some
>allocation/free stack trace info + CPU id, task etc.

Thanks for the reminder, I will change it to another name in the v2 patch.

>> 3. Simple usage
>> ===========
>> The first step is to mark the memory as tracked after the allocation is
>> completed.
>> The second step is to remove the tracked mark of the memory before the
>> legal access process and re-mark the memory as tracked after finishing
>> the legal access process.
>
>It took me several readings to understand what problem you're actually
>trying to solve. AFAIK, you're trying to add custom poison/unpoison
>functions.
>
>From what I can tell this is duplicating functionality: it is
>perfectly legal to poison and unpoison memory while it is already
>allocated. I think it used to be the case the kasan_poison/unpoison()
>were API functions, but since tag-based KASAN modes this was changed
>to hide the complexity here.
>
>But you could simply expose a simpler variant of kasan_{un,}poison,
>e.g. kasan_poison/unpoison_custom(). You'd have to introduce another
>type (see where KASAN_PAGE_FREE, KASAN_SLAB_FREE is defined) to
>distinguish this custom type from other poisoned memory.
>
>Obviously it would be invalid to kasan_poison_custom() memory that is
>already poisoned, because that would discard the pre-existing poison
>type.
>
>With that design, I believe it would also work for the inline version
>of KASAN and not just outline version.

Thank you for your review!

Yes I am trying to add custom poison/unpoison functions which can monitor
memory in a fine-grained manner, and not affect the original functionality
of kasan. For example, for a 100-byte variable, I may only want to monitor
certain two bytes (byte 3 and 4) in it. According to my understanding,
kasan_poison/unpoison() can not detect the middle bytes individually. So I
don't think function kasan_poison/unpoison() can do what I want.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240118143010.43614-1-lizhe.67%40bytedance.com.
