Return-Path: <kasan-dev+bncBCR6PUHQH4IJRZ6CWIDBUBD34IBQG@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83a.google.com (mail-qt1-x83a.google.com [IPv6:2607:f8b0:4864:20::83a])
	by mail.lfdr.de (Postfix) with ESMTPS id 2D6CD8CE80D
	for <lists+kasan-dev@lfdr.de>; Fri, 24 May 2024 17:34:50 +0200 (CEST)
Received: by mail-qt1-x83a.google.com with SMTP id d75a77b69052e-43fb7e2b63asf3045891cf.3
        for <lists+kasan-dev@lfdr.de>; Fri, 24 May 2024 08:34:50 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1716564889; cv=pass;
        d=google.com; s=arc-20160816;
        b=KZ1Z3oGYweXsF1Nf1NkuHq9U/qcBR+jRowHNGDvOlByKh5zu0sHJsIFmjzsfJeDW9S
         dO3/gKWUlDlQkcdKYzVquJNm3pZAnJC9HKT4AuwjNuxgjl7AMF6Tos6CESf3ZQ0txq/I
         WfUVRZOXaKQ50kKocAfdYaoHe8hwpRsh7UA4xX3/aHVGj6FrudaQUm97d+n5RqMLGSl6
         x5XSfO4BicmiyFS7nDJyqXkxWu7MIM6HsIacDRWyoUHHWjJngENl5gG1EWYLnyMHJRCX
         AClpWa1fvWJyYdeLsIQSmWCWebKhnXDZTt1PoNoMym6W2CFacj5PHMRec69tAE4qAlm0
         yG/w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-language:from
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=hVaiBXJkszVlmpezN7ihlEpqQ8v6ASthJbd8IWeVL98=;
        fh=x49RBGG5YK8wh4dvwNjDLjD4tQTXWPsWb+c5yYpfKqA=;
        b=I+MGOen4cOsMKuvgHWa9Gq+UfVwdjyZkLM1xEEq52XKL95S/DNGp7zg7I+o3wM626V
         6gToGMdgRkCr25cf3ILdK5g9L809IP79hil6E8I0zOOlzSNlxdtnj5mllI6tzQyEsq4U
         1Z7cHaoKBVaoquFXd+A/DRtcGH/4H+DweoEF2WtnxzrK4Yo0Nqx6GzCvpTy4WsbLXs6h
         lEKFD2zdzAzC3l5zlfXqR3Gznu65/WcVieQrUUXSATR7QqhB9KcW8VEyaYYiQf1+Fijq
         h34qH0ziZuNhUpRatBOpLc8kriii2M7jLKAmCLk3N/Y6eRqgfPPZMqSxQ0LxFHhIfcnv
         9rpw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@efficios.com header.s=smtpout1 header.b=OpuW54cR;
       spf=pass (google.com: domain of mathieu.desnoyers@efficios.com designates 2607:5300:203:b2ee::31e5 as permitted sender) smtp.mailfrom=mathieu.desnoyers@efficios.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=efficios.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1716564889; x=1717169689; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-language:from:references:cc
         :to:subject:user-agent:mime-version:date:message-id:sender:from:to
         :cc:subject:date:message-id:reply-to;
        bh=hVaiBXJkszVlmpezN7ihlEpqQ8v6ASthJbd8IWeVL98=;
        b=e2yzbks61PQ6OAa7/xaKONzTS+FKTCsxjG0MqBFB3341T4UiCR420udlSEgvRpipRD
         2EIm1K2UGHxLEyzWuDnc7yT8sgqH3DKZKm9PfPjfrzvkwb2D5yrZqlQN0kw+KZfcjQEH
         9KGnryLDZmtDbtuZkRFTO2lC96LBOpyYfm4szFlghEpA8C7uuwevxCkoWUDb3OfjJQUK
         2mtkBPbWImFpRgEBq3nEjI9SYbZd/XEkvBZrrzXT0yjTKQIHF1ZVTKejVVW+TAUr0SEg
         IALdMZWiTetFD6opgknF+sHjsFXjMDTwU/EdaVK1YCoXfIrEeZ9iq+JxEBIKUQChwJZ6
         Amug==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1716564889; x=1717169689;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-language:from:references:cc:to:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=hVaiBXJkszVlmpezN7ihlEpqQ8v6ASthJbd8IWeVL98=;
        b=gR4CeAM+w24mgEg/splH/KIhJR/lO7heZ82E55DXGoN4Ufe6Fnq/HeRmTkvGbk0ozu
         rU1DHVwy5leugAy2th/ZEBc8dy89xxUTDO0wugQ35nVrTfCXKX4jA+Dehh8C2OB8EJSh
         vjDucNFrYev1xvPpK53wMOuGZlqtHyIrrrnHt0pKXHJYBYTacnMuB5lJwLfXAQE3+zb1
         NeLG/X+QXfv+SIeleGbudavAwEqfvZMouUm5YENL+CElT+S28CVPvLaSFDqkHDYmQfLT
         chvn/izsp+h0RtJXXL6dyI1aXwp6ERjkbClBY//yHixkIBoyGLXp5ZXaCxiXw/zPs2ki
         GiIA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUI6JSwBPc4hCKJ7BriMdBAgnj9TJjCRR6QG1WlYvqavXt4/MZioJpweEN7jD6OCykfcVLxPXDXt8oDJ8EyX9JEXS6tT4jHKQ==
X-Gm-Message-State: AOJu0Yyp/5kun3eR2/ji5/unwx8seYIzHoEKMB66DwnETFi38LKTtiCb
	/gbCWpj4vvDN7Ps9NBl2cBQ4zalD+t45SRZI5v36LV/flq7tB0XG
X-Google-Smtp-Source: AGHT+IGxWIBJSB5KMJ7EJn2kDnFnKqVgCflr83HM7Yi6ojg/4Svw3T6fcDlcsvizBMDJ8pUj6NFsdQ==
X-Received: by 2002:ac8:7f06:0:b0:43a:f9ea:1fbd with SMTP id d75a77b69052e-43fb0e5486fmr27745391cf.18.1716564888661;
        Fri, 24 May 2024 08:34:48 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:622a:241:b0:43a:bd70:3310 with SMTP id
 d75a77b69052e-43fb1e735d1ls8389131cf.0.-pod-prod-03-us; Fri, 24 May 2024
 08:34:47 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUAmdX7TXTEhjNJ3dsORxnw/Yl8FN71cOB60i+hy+8qkgwBvS6/dEaRHtmyb/u1DNN/I2RzwCnNqAd7Plj4U2VJnOme4TEu1xhctA==
X-Received: by 2002:ac8:59cf:0:b0:43a:b542:d1dd with SMTP id d75a77b69052e-43fb0e804demr26017371cf.36.1716564887378;
        Fri, 24 May 2024 08:34:47 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1716564887; cv=none;
        d=google.com; s=arc-20160816;
        b=t8yZMM1vspOPzAIYoidB1KiBTbSc1iZQbeMMlMlqrv/b00Irm4rsvTMGGdgni0niuF
         RC1a9UJDvM8arn3lTBMWWiHFuu9hTRDeWGYi7SGVdSpGTE8CPetmMVg5k1sv24gnen+r
         CXr7eVsyNT13r7WUm2nc+YdbdTO8ezBKObnpgsmIbSePUuMW6kQPwTvLNpBESrHIx5UA
         wfP/HgJwHx8TiRe02HO/oX3ZTwVWOk2bf9tHiFri3gZb4Zjc2ULJERdIwFD5KunkyNIG
         C5dmy60OS7MzXwpSLIK6w9Y+i3V6n1pz770uvoEE4+nLyi1vBmn6mWmwVNeu5d+NiGGS
         6yWQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:content-language:from
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=I8jr1DPEmhNdFb5LfECMvGDJ7GS+7KFhaC/ClQpxlRI=;
        fh=1rwarnBK5lKkIS5wPP901k5vFabioac5KyOvP020e/k=;
        b=Zd7Mi9naEKPQ8xag5XG/+7zHbwYWsA0XWMgdhgaKWfEnrNRRbSBkB/kGeiBdfVPqZu
         4leFDh058e7q0OhvMrdMpKZLyJVa+Sl8P+ByoYWJXBVOzyuh6ID3vZeqh7BJ2JxfUcbf
         UjLWr76N4y0vCIv3M2/gyM5d4dBgfUq02fF4rYbCuu5l5hm27qo1+n8eLAJfU7atZ91c
         +KLPC47baUBuvjE4rQudJR7Uw4cmU660fdrns9kJRNPLoZXC+TQ877ywFnWZYDTTluRU
         6PByLWrlD9yqLPMocmljCeAHpv0bm4PY6iHkJD75zjXwV/vQuce3T/GPoUAtOhtMt3MN
         SL9Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@efficios.com header.s=smtpout1 header.b=OpuW54cR;
       spf=pass (google.com: domain of mathieu.desnoyers@efficios.com designates 2607:5300:203:b2ee::31e5 as permitted sender) smtp.mailfrom=mathieu.desnoyers@efficios.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=efficios.com
Received: from smtpout.efficios.com (smtpout.efficios.com. [2607:5300:203:b2ee::31e5])
        by gmr-mx.google.com with ESMTPS id d75a77b69052e-43fb15ee0fcsi1542961cf.0.2024.05.24.08.34.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 24 May 2024 08:34:47 -0700 (PDT)
Received-SPF: pass (google.com: domain of mathieu.desnoyers@efficios.com designates 2607:5300:203:b2ee::31e5 as permitted sender) client-ip=2607:5300:203:b2ee::31e5;
Received: from [172.16.0.134] (192-222-143-198.qc.cable.ebox.net [192.222.143.198])
	by smtpout.efficios.com (Postfix) with ESMTPSA id 4Vm8HB0VZNz1174;
	Fri, 24 May 2024 11:34:46 -0400 (EDT)
Message-ID: <944d79b5-177d-43ea-a130-25bd62fc787f@efficios.com>
Date: Fri, 24 May 2024 11:35:21 -0400
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: Use of zero-length arrays in bcachefs structures inner fields
To: Kent Overstreet <kent.overstreet@linux.dev>
Cc: Brian Foster <bfoster@redhat.com>, Kees Cook <keescook@chromium.org>,
 linux-kernel <linux-kernel@vger.kernel.org>, linux-bcachefs@vger.kernel.org,
 Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>,
 Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com,
 Nathan Chancellor <nathan@kernel.org>,
 Nick Desaulniers <ndesaulniers@google.com>, Bill Wendling
 <morbo@google.com>, Justin Stitt <justinstitt@google.com>,
 llvm@lists.linux.dev
References: <986294ee-8bb1-4bf4-9f23-2bc25dbad561@efficios.com>
 <vu7w6if47tv3kwnbbbsdchu3wpsbkqlvlkvewtvjx5hkq57fya@rgl6bp33eizt>
From: Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
Content-Language: en-US
In-Reply-To: <vu7w6if47tv3kwnbbbsdchu3wpsbkqlvlkvewtvjx5hkq57fya@rgl6bp33eizt>
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: mathieu.desnoyers@efficios.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@efficios.com header.s=smtpout1 header.b=OpuW54cR;       spf=pass
 (google.com: domain of mathieu.desnoyers@efficios.com designates
 2607:5300:203:b2ee::31e5 as permitted sender) smtp.mailfrom=mathieu.desnoyers@efficios.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=efficios.com
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

[ Adding clang/llvm and KMSAN maintainers/reviewers in CC. ]

On 2024-05-24 11:28, Kent Overstreet wrote:
> On Thu, May 23, 2024 at 01:53:42PM -0400, Mathieu Desnoyers wrote:
>> Hi Kent,
>>
>> Looking around in the bcachefs code for possible causes of this KMSAN
>> bug report:
>>
>> https://lore.kernel.org/lkml/000000000000fd5e7006191f78dc@google.com/
>>
>> I notice the following pattern in the bcachefs structures: zero-length
>> arrays members are inserted in structures (not always at the end),
>> seemingly to achieve a result similar to what could be done with a
>> union:
>>
>> fs/bcachefs/bcachefs_format.h:
>>
>> struct bkey_packed {
>>          __u64           _data[0];
>>
>>          /* Size of combined key and value, in u64s */
>>          __u8            u64s;
>> [...]
>> };
>>
>> likewise:
>>
>> struct bkey_i {
>>          __u64                   _data[0];
>>
>>          struct bkey     k;
>>          struct bch_val  v;
>> };
>>
>> (and there are many more examples of this pattern in bcachefs)
>>
>> AFAIK, the C11 standard states that array declarator constant expression
>>
>> Effectively, we can verify that this code triggers an undefined behavior
>> with:
>>
>> #include <stdio.h>
>>
>> struct z {
>>          int x[0];
>>          int y;
>>          int z;
>> } __attribute__((packed));
>>
>> int main(void)
>> {
>>          struct z a;
>>
>>          a.y = 1;
>>          printf("%d\n", a.x[0]);
>> }
>> delimited by [ ] shall have a value greater than zero.
> 
> Yet another example of the C people going absolutely nutty with
> everything being undefined. Look, this isn't ok, we need to get work
> done, and I've already wasted entirely too much time on ZLA vs. flex
> array member nonsense.
> 
> There's a bunch of legit uses for zero length arrays, and your example,
> where we're not even _assigning_ to x, is just batshit. Someone needs to
> get his head examined.
> 
>> So I wonder if the issue reported by KMSAN could be caused by this
>> pattern ?
> 
> Possibly; the KMSAN errors I've been looking at do look suspicious. But
> it sounds like we need a real fix that involves defining proper
> semantics, not compiler folks giving up and saying 'aiee!'.
> 
> IOW, clang/KMSAN are broken if they simply choke on a zero length array
> being present.

-- 
Mathieu Desnoyers
EfficiOS Inc.
https://www.efficios.com

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/944d79b5-177d-43ea-a130-25bd62fc787f%40efficios.com.
