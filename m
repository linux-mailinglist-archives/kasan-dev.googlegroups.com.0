Return-Path: <kasan-dev+bncBC5L5P75YUERB2NVUTXAKGQESN34WEQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13c.google.com (mail-lf1-x13c.google.com [IPv6:2a00:1450:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id C851BF6FAA
	for <lists+kasan-dev@lfdr.de>; Mon, 11 Nov 2019 09:25:13 +0100 (CET)
Received: by mail-lf1-x13c.google.com with SMTP id r127sf615583lff.1
        for <lists+kasan-dev@lfdr.de>; Mon, 11 Nov 2019 00:25:13 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1573460713; cv=pass;
        d=google.com; s=arc-20160816;
        b=ymVCcB/T/Lz0e4vmw2oWlDlhHEKx6ENfaI2xfSU2iKWxOXZVATvxCoW+4QGWDgziX1
         WJURhZZ3CvGMpNXuEOd8fjDH+yfSbRxxqUzIFqRqtD5Ai7BEdzpVDAn1pUjN+ddk6TlP
         u1dicMNVdPmf8jn6RYF62/aPem1faJV+vTjSZErJTWWbXgNonNTOYd+lIGYGOep6uWST
         lgWjRfJamBrh57GO/kqqWUkfw3w2+MeAjEOzxcvljK/Hj9twd70RVjRPAh+zLlGvk/J8
         KER5otBncGjQ6vwCZ5FyJJ1PbzbGiPy7m42rBaBPKHU8plV9SASw2Cc/t3l3LdC3zSvL
         HAlA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=LNd06KoVaYOmq0VT9wQ0L+VFJ5LmoZ4VwCySrts1feY=;
        b=0FrxiW1AH6b8TUkUCATW3u2RrNIzqgehN4sypfZy7CGUY7xrRoeYVaBz3o0moSDsJk
         V6VeeRaTDfolKLTiCWpxNMPfqqBN3bvICFXX0KJAtrymzp1+PKI+qA/aK8g/trhyaH72
         2bQTDm4V0a3gHZh+fBoDo6hyDoc0aKZ6D40w2q8uD6zqh3LqQri8XMP3g93bGra2HSQY
         v2kZnORBvzZVHgds7FRyd4g693XRxfBagMO9eI1qd9gR8MgFvNBqMhnJWOpsHj/ccqiB
         d5Gop9VPu5p5H+UPFGLTp7lbVTuYR5lULeQ5ON0OFgSqt0c+mZ3oRPyvmF/B9tJ4K+o1
         09yA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as permitted sender) smtp.mailfrom=aryabinin@virtuozzo.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=virtuozzo.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=LNd06KoVaYOmq0VT9wQ0L+VFJ5LmoZ4VwCySrts1feY=;
        b=SX3+nUebTfjsJyBoqT8srXtsgR9mOS2Du0C/w4c78tBoBdS0OAkanVCJmimzbbUV0u
         cqFdCvei/l80TjfvxgZr0sYSn3kaMByLHKtI1P2WkJP//cyioymFF+yIVcAkqRUk/yo9
         W+DmV+XVjgRi5c/+nAYGdtwK+utyybQq3Ul1sT4SRxnisK00t7YsMDQi8jOpNvjpJgxf
         To3qWqDSPft5etpgtuZ6mgqFIvbl9EK4SkvzUzjrBKUY6a8HsX7GakL/nkKaCALgJZwy
         haBlCKqOphjaPe2HRJQgWbH2Hbc3ELyAUclrpsY140KmeMSFRvtDTPuoJFk1s3UU3Z/b
         eNSw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=LNd06KoVaYOmq0VT9wQ0L+VFJ5LmoZ4VwCySrts1feY=;
        b=D13JPYEVu9U5nq6mHP+H3Jm08mvY0KnfDNQmzNK/MbcqHERTM4cyDW+d5X2AZ58bV9
         qauU6oUpvdDx1cAGbjYOLwc/SqFzMSblaaqGLo3x+60oDyeYsUA9d0FWlp2FK/JnyO8T
         cluKXPKccMml5S3zGt+lQzPMsEeOKhlzD+GlSTJtWcZ/2ux2Sg/skmjcTDSm0ZprZHrc
         N+RQIv4YfRlMuSjd2gAdXuG6rrZ2UI8rz90IJktcP0CKIUDugAQYGCVL0d5N3Uu/8yoJ
         7ZiahgwMk4I7VSHimRhgCls5Ot3v1/RFm1vvgc8CgaqAs/01p7qb07716E8Qc3Fena8x
         mhxA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAXb3NntOupHrBRdRc/svT4DaEHabi7XmelqRlHqPdoM7iNqkKDW
	ZC9Hu+AYLvfVz4ZaOMbO2g4=
X-Google-Smtp-Source: APXvYqyWiltKXTpIaT45201qto3qz/EMeU4uaepynAqtb9I7NTkz1/MuvNOVHtaZoLWvQLcbYseZ5A==
X-Received: by 2002:a2e:95c5:: with SMTP id y5mr15614646ljh.184.1573460713327;
        Mon, 11 Nov 2019 00:25:13 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:51b6:: with SMTP id f22ls25769lfk.6.gmail; Mon, 11 Nov
 2019 00:25:12 -0800 (PST)
X-Received: by 2002:ac2:5090:: with SMTP id f16mr2999048lfm.115.1573460712783;
        Mon, 11 Nov 2019 00:25:12 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1573460712; cv=none;
        d=google.com; s=arc-20160816;
        b=bCWZGp+Pqy3YZUWsNIb0gQ0xr0jbmlUIagfTFYTL9UzWRVxGjLbVfVQ4ybPWZcbo+N
         b9mJRUbuogCN4Cyg3uYthY4IYVJURXvYZsolhSB86lRCg6c5DhEGjcVnU+ue4jGvGELq
         OInVhOhKMW28jM0t4h9M1MMV9pcn6gamFs7z2oL5OMIBMHsaH9MautIy1Co+3XEEY/Pj
         KwYSL4hprRdzcuoEDZFMXNIQ7JILn7O68Do0BsVZG2iRqXuGgBb6d2seCzP/q1qdJGPw
         sD3zxmP10dg1z8Ij8N8eQXQp9EPd7M+RD8qRbQYwGbeXxTFk5ZIEX2nQoqA8K4j6x2DG
         3AGA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=Nt3MKERF0kAHPpilsOcZ66FJpLhSTeFXXMcT5u+jJ+w=;
        b=beSz9ZhpxGlmzYLvMhlTqEPs+PGfpNDk8wkTILqto+FnIoKT/BzC8DX2Y78RrckSaB
         Smie1do6/+ksb9pwEzxpyr7rvkNQVigZDcC4c4PiL5RxrY0OaLFuC4fNjM2a4wUvMnH2
         gZrTxQ9IXGIoJzbkbfQnwAJs2RIWljwprFaFfyh4RoZUJuscie0m5QHqFIiNQ5R0t8Fh
         OXP7Qt50WEiX1UD+MoVDkEIHdmKTNhPbyKCjU2Hm8H/Zly6pXB+M2Q7dpa3h+D2bmeUu
         KIhq/fdHn+3Y0izpNJQa+rjSy5Dv3YyBP70YdR5UDfuw3tHbzPd9nKBzi10MbpRXwq6w
         xyrQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as permitted sender) smtp.mailfrom=aryabinin@virtuozzo.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=virtuozzo.com
Received: from relay.sw.ru (relay.sw.ru. [185.231.240.75])
        by gmr-mx.google.com with ESMTPS id z18si1336049lfh.1.2019.11.11.00.25.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 11 Nov 2019 00:25:12 -0800 (PST)
Received-SPF: pass (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as permitted sender) client-ip=185.231.240.75;
Received: from [172.16.25.5]
	by relay.sw.ru with esmtp (Exim 4.92.3)
	(envelope-from <aryabinin@virtuozzo.com>)
	id 1iU50L-00018h-TL; Mon, 11 Nov 2019 11:24:58 +0300
Subject: Re: [PATCH v3 1/2] kasan: detect negative size in memory operation
 function
To: Dmitry Vyukov <dvyukov@google.com>
Cc: Walter Wu <walter-zh.wu@mediatek.com>,
 Alexander Potapenko <glider@google.com>,
 Matthias Brugger <matthias.bgg@gmail.com>,
 kasan-dev <kasan-dev@googlegroups.com>, Linux-MM <linux-mm@kvack.org>,
 LKML <linux-kernel@vger.kernel.org>,
 Linux ARM <linux-arm-kernel@lists.infradead.org>,
 wsd_upstream <wsd_upstream@mediatek.com>
References: <20191104020519.27988-1-walter-zh.wu@mediatek.com>
 <34bf9c08-d2f2-a6c6-1dbe-29b1456d8284@virtuozzo.com>
 <CACT4Y+bfGrJemwyMVqd2Kt19mF2i=3GwXRKHP0qGJaT_5OhSCA@mail.gmail.com>
From: Andrey Ryabinin <aryabinin@virtuozzo.com>
Message-ID: <20df03c5-e733-98b0-84e9-8d52ddce5c98@virtuozzo.com>
Date: Mon, 11 Nov 2019 11:24:36 +0300
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101
 Thunderbird/60.9.0
MIME-Version: 1.0
In-Reply-To: <CACT4Y+bfGrJemwyMVqd2Kt19mF2i=3GwXRKHP0qGJaT_5OhSCA@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
Content-Language: en-US
X-Original-Sender: aryabinin@virtuozzo.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as
 permitted sender) smtp.mailfrom=aryabinin@virtuozzo.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=virtuozzo.com
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



On 11/11/19 10:57 AM, Dmitry Vyukov wrote:
> On Fri, Nov 8, 2019 at 11:32 PM Andrey Ryabinin <aryabinin@virtuozzo.com> wrote:

>>> diff --git a/mm/kasan/generic_report.c b/mm/kasan/generic_report.c
>>> index 36c645939bc9..52a92c7db697 100644
>>> --- a/mm/kasan/generic_report.c
>>> +++ b/mm/kasan/generic_report.c
>>> @@ -107,6 +107,24 @@ static const char *get_wild_bug_type(struct kasan_access_info *info)
>>>
>>>  const char *get_bug_type(struct kasan_access_info *info)
>>>  {
>>> +     /*
>>> +      * If access_size is negative numbers, then it has three reasons
>>> +      * to be defined as heap-out-of-bounds bug type.
>>> +      * 1) Casting negative numbers to size_t would indeed turn up as
>>> +      *    a large size_t and its value will be larger than ULONG_MAX/2,
>>> +      *    so that this can qualify as out-of-bounds.
>>> +      * 2) If KASAN has new bug type and user-space passes negative size,
>>> +      *    then there are duplicate reports. So don't produce new bug type
>>> +      *    in order to prevent duplicate reports by some systems
>>> +      *    (e.g. syzbot) to report the same bug twice.
>>> +      * 3) When size is negative numbers, it may be passed from user-space.
>>> +      *    So we always print heap-out-of-bounds in order to prevent that
>>> +      *    kernel-space and user-space have the same bug but have duplicate
>>> +      *    reports.
>>> +      */
>>
>> Completely fail to understand 2) and 3). 2) talks something about *NOT* producing new bug
>> type, but at the same time you code actually does that.
>> 3) says something about user-space which have nothing to do with kasan.
> 
> The idea was to use one of the existing bug titles so that syzbot does
> not produce 2 versions for OOBs where size is user-controlled. We
> don't know if it's overflow from heap, global or stack, but heap is
> the most common bug, so saying heap overflow will reduce chances of
> producing duplicates the most.
> But for all of this to work we do need to use one of the existing bug titles.

The "heap-out-of-bounds" is not one of the existing bug titles.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20df03c5-e733-98b0-84e9-8d52ddce5c98%40virtuozzo.com.
