Return-Path: <kasan-dev+bncBCSL7B6LWYHBB5EV7PBQMGQEFGRFZVY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x538.google.com (mail-ed1-x538.google.com [IPv6:2a00:1450:4864:20::538])
	by mail.lfdr.de (Postfix) with ESMTPS id CEF66B0CDAA
	for <lists+kasan-dev@lfdr.de>; Tue, 22 Jul 2025 01:19:17 +0200 (CEST)
Received: by mail-ed1-x538.google.com with SMTP id 4fb4d7f45d1cf-612b23a8064sf4570071a12.0
        for <lists+kasan-dev@lfdr.de>; Mon, 21 Jul 2025 16:19:17 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1753139957; cv=pass;
        d=google.com; s=arc-20240605;
        b=bgHl+cvPSMXDMK5gQbPR4de5sXEf3VJOTRgTm22iOaE1V4pO1+jrt1XTizgjWfNtJg
         QYT88jMJ2N7ovOmDDTf7bqqmEK7MW6O5VH3vle1tqM/h4KzMb6odsc2Gm2X11nFyKgIP
         GY5nR34rDy20c0pSAYppDDVf36q44kKtjqgYItrv33KAfBqLNhrxP3QGraUfS90RhU1I
         yaeo6fXHqK4CmPZ2Fxnpb0u+rMUdBWrvKcNpUto3m/0gV/4OpVj50MuZ2u7PTFtC4qin
         ULDVkUT0U8YkBEIwLHB1ALuPlFdXFaGTZCYACDX1fINap52m6dgT7M0rutjih5JjIF8q
         9YyA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature:dkim-signature;
        bh=nTzEV35lRowKacXuYDfviw7z2P8evdutHs4nOZr1b3M=;
        fh=dwyXu5lJzJqFUcsmFScQ6V4LTVqPkeN7lpgZWVZ/udg=;
        b=ZASLTk43p92pl7r1j7BpDwzNKsMIrmK/xwKSA1aLN38cPAN92A4bfE083TuPBMD5Wb
         ysXlHOdc2St34DV6snmzThep7QoXUZFyMcW7x8pOuOOK0YptZJYuPaXpUlpMxMBni33a
         jED/gV3kNEKCzwQK3PNU3nax7Q9fxjQNTB09MrOUlqFFqEY9Yi7ni/3khsjB9WxW9vqA
         4+jRAcu1NJOozkbP20itbjNTciE+wFlL8H21t8thDk+yIoPZOLh2y/HteH/Q0/Vses2L
         wT0A0cBHSKPJp1mxgQqxoy7quW+3y/rrNDzASmEB2XxBpIJewYOCBK6V8AvjlulepO8k
         U5Bw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="juIzD/gb";
       spf=pass (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::631 as permitted sender) smtp.mailfrom=ryabinin.a.a@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1753139957; x=1753744757; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:content-language:references:cc
         :to:subject:user-agent:mime-version:date:message-id:sender:from:to
         :cc:subject:date:message-id:reply-to;
        bh=nTzEV35lRowKacXuYDfviw7z2P8evdutHs4nOZr1b3M=;
        b=laEPYKLsLhimsSwIgjp8h5NRzvvyyKrAx4IXAEhjh34sczWfNfiUVrhDQXoFKKuVVS
         c6JlIlmW8SdssmAT3jj0vMCk2YaJb0IPD72t9kHEG9MQLyXSdPYCeOSqX+Wr3ubm4P3r
         0WR5d+IW3UqsWVPdkCNfxNOA3TlGIEdXIA8xIaI+WxIORFq3PMJ5o7YLjzt3ls8JDoTh
         DpxlVPCvqiZWW2RvQ0zd2LPPt0T+td0VixCiKqY/kbbhgBuzZAJvRhNAUALzpSKk6yuD
         GNkUORJsg4QXAVpvtOcFIDo5ikZsrO0ikLtMpMjyOuDIXcjU6p2I0b7kortG61mhYFCt
         JS2g==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1753139957; x=1753744757; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:content-language:references:cc
         :to:subject:user-agent:mime-version:date:message-id:from:to:cc
         :subject:date:message-id:reply-to;
        bh=nTzEV35lRowKacXuYDfviw7z2P8evdutHs4nOZr1b3M=;
        b=AmU+IQKHDAR+UeGM5DWSGmpSSOXH0bNaQhK4Viyp9xMYMHPDMNv3A4QAEjoOO5B3h5
         4F0TE4rhpa46Q1Eubdlyc9P9J5glR4nwAfHifb2ylFEdWsBooAQs/2Ecd1KQAV9nbEki
         PVwdZSDdhQGm1VIWVMJaD4bBZotd8LLivAMhg12RkNSYNVPgSuc4mFuw+IaXCmwA+x/w
         ie8X6nT792tLVoA5rWj94yjiXwNUtVYD5az57JxWlmbOJZR9DAUGBPyWxHtgePDspoGc
         wrNSTmo9G3Wt2v5tarUnQqu29dnFqD7wQZqrBTf6doLRvyTNi7GbIrzu7IDEUVLFfbBJ
         P3NQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1753139957; x=1753744757;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:content-language:references:cc:to:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=nTzEV35lRowKacXuYDfviw7z2P8evdutHs4nOZr1b3M=;
        b=EUvttEm8/n2vxU2w9VFZ2JJjUxs/Bw5F7Z9XAHpaAlGDOwViweTsgsj2I3Nc95f059
         6qCmrqY/crgZPRStUEBbUWyECs0bbCc3gocsW9X0j0utAVjV0T7PbxsX31MeUMzPHaTP
         A3TRSIEkgPF672wt0wQLGwPA2DhJHw8ecgNZ2v+kIlXWZmXsxnIEuE5Kljkktyr8DRvq
         w3mwAD1Cb7Uaf6eZisftc7MkhJ5zorOA+UDhNehDq6ExqjyqPOS4xyEkm40f1luAqhzQ
         /9VkGe+eIlAH0NWdLrMnOopYZIV6/+J927tUgGJ+CTz9cq2r7isDR8Qx6UwYnlwgfNk1
         ucYA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUriUT54FDVXl0heGMilmjbpHp7iOaRf4itT4mpcpv/TQui/gm6svugEiBWntd/3/+CNNliWg==@lfdr.de
X-Gm-Message-State: AOJu0Yyqf7NrWhff8U2BLkVKC0Rf4zO2oJsHiPM6QEZJT1qs6hCS9/Wo
	zWIICL7M+T5ciflT6V0pUhOrJsyDKSc+NNjLZIkfQX8p64HvUwTEO+Xx
X-Google-Smtp-Source: AGHT+IHGYNW6ojWYMJc2IB4VpQmShMDutK9elQb0JgnMyZH3nl6a8mFe9pgYwQrhjosoCbWUoQSVgA==
X-Received: by 2002:a05:6402:5186:b0:612:25f9:df47 with SMTP id 4fb4d7f45d1cf-61281f2424emr21000913a12.2.1753139957003;
        Mon, 21 Jul 2025 16:19:17 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcAfswBHuENxQjHpBQUHKY8rmPBe4GRNdWXv37rrbXW5A==
Received: by 2002:a05:6402:430b:b0:609:b887:d889 with SMTP id
 4fb4d7f45d1cf-6129fe38a9cls3753685a12.0.-pod-prod-01-eu; Mon, 21 Jul 2025
 16:19:14 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXQkJMUXNeo+YMHY633VnS22NlyiB24EuZ0S/+I6tTfO4KW0nfCafV3/P1/4Vak3xq6z1ooA3D+6c8=@googlegroups.com
X-Received: by 2002:a50:9f44:0:b0:602:e002:9602 with SMTP id 4fb4d7f45d1cf-612825e9696mr15913559a12.22.1753139953926;
        Mon, 21 Jul 2025 16:19:13 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1753139953; cv=none;
        d=google.com; s=arc-20240605;
        b=bUTNhnE78wcenx8vbz+bRFvjr722egJ1GK8/5BJ7GT8Q5uaHaczjrBPUsyNWgjuXWW
         CRjhRPp2AnusiUZu8qFg57mmULYN7XKio6mmcoavw9FjkTNB+xwm9W+ROblCzjwuLmKF
         IKStYqkuOsq4gq7+Zfn89wxndXQfemCrJXe6FF0HeKbI+WMkTKIRfQjPHWS0oAC2+YRE
         cY0+EzMKTwmH23/1d0rgttVaD8jMgW7NhEWXz150bsxjxjggxYjr5HTQQENsYAk9y4tK
         RIui2JoY60521V4taOwseQ7sOdubowllKfozzri3g/o6KHQlOFfp3jVTTBPVr8EegRqr
         b03g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=k7uUxr86UctpR4wo5BHRFyvrfjd8nsrpfmZh9G1fUjI=;
        fh=x+7I5swDK+3yFvTNKuIrp5xHuCVTZQGXLvgJ9vV7q2w=;
        b=bA+eRsw8VcFGaERjzcfxPS0tw6WHtEsSU/qmvhfnMMcRyQ6dYWl9iD5bMYj15hPrcM
         JFKrGl4Yjp26nth1vYqXWMRgxsQiJw3F45aR5iM9y4QQ14iAY1w+lAqMwbWi73Ra4PIx
         PjMxRLxHCrnDTl/9fclglaULUnf9FY6LySD0sRVr4KCGqI31VgYltU/Etlf/gvsCx7wO
         sCJqLPR/fBC5t8i9/UPfL1U+zWBPmvXRrHvYyrfGRbc4HLrImlAyM+2pWyaCLO+qgjY0
         7WYDXs2KUMTWLsdSDpcHsbUroGdI3t0S6V36D2gpdl4iYkvpaGjOYhhBYeHp0KGT3K2C
         j99g==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="juIzD/gb";
       spf=pass (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::631 as permitted sender) smtp.mailfrom=ryabinin.a.a@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ej1-x631.google.com (mail-ej1-x631.google.com. [2a00:1450:4864:20::631])
        by gmr-mx.google.com with ESMTPS id 4fb4d7f45d1cf-612c9170b7esi220687a12.5.2025.07.21.16.19.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 21 Jul 2025 16:19:13 -0700 (PDT)
Received-SPF: pass (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::631 as permitted sender) client-ip=2a00:1450:4864:20::631;
Received: by mail-ej1-x631.google.com with SMTP id a640c23a62f3a-ae0e0e464ecso5163366b.3
        for <kasan-dev@googlegroups.com>; Mon, 21 Jul 2025 16:19:13 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXC1e/fmVmDn5dm7l85UfO7d9bRWx2GoWuFZTzoPhvqL//d4LBv5Cz0NpiCVNuSHNwxOwcO0PZKwfo=@googlegroups.com
X-Gm-Gg: ASbGncvmqnysDvb0wzrmBD0tTJoXC9e+BCKkSyq8JrNdx6Cl+fZ8WIj6FXrrOeNqjlh
	eo7id6GoQ5TOzGd9CylGcAIgM2RsdzjWdg/TejfaBn2aW7qlpNDwyVgdAbZ6sio9hjiVHWgTyWY
	Em9L9y/EnUCfaP/3nJgr5kZwsEpINWZIwwFOYwiVVHffGI005fgtq0kTyWczjxFqa/y2EcSDNS7
	NKkg08UX6SSozoPgsuMvPm3W9cFI7dbCVHSQ0NiMfSlalaYMwh/iXQV6sZjaqJfYNldQRklbGNx
	LjEuYvJqexn/0uaHx3MbJtdO3U1ZskEFuOFiuGu/+l6djjlCTxWAvBGKjuRB1ca042XxMs6k7Hy
	gGtidxmAyZ/jgbamzLQmh1a/QnJsX5rRz9mK+UqB4UlYHVZWb5fCIB/HmnulCX6BlBpQb
X-Received: by 2002:a17:907:706:b0:ad8:8200:ecf7 with SMTP id a640c23a62f3a-ae9c99aa29fmr821747766b.4.1753139953227;
        Mon, 21 Jul 2025 16:19:13 -0700 (PDT)
Received: from [192.168.0.18] (cable-94-189-142-142.dynamic.sbb.rs. [94.189.142.142])
        by smtp.gmail.com with ESMTPSA id a640c23a62f3a-aec6ca7ea53sm757005366b.133.2025.07.21.16.19.11
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 21 Jul 2025 16:19:12 -0700 (PDT)
Message-ID: <a1bc7a9d-817d-49cc-b7f1-79a900090136@gmail.com>
Date: Tue, 22 Jul 2025 01:18:52 +0200
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v3 01/12] lib/kasan: introduce CONFIG_ARCH_DEFER_KASAN
 option
To: Andrew Morton <akpm@linux-foundation.org>,
 Sabyrzhan Tasbolatov <snovitoll@gmail.com>
Cc: hca@linux.ibm.com, christophe.leroy@csgroup.eu, andreyknvl@gmail.com,
 agordeev@linux.ibm.com, glider@google.com, dvyukov@google.com,
 kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org,
 loongarch@lists.linux.dev, linuxppc-dev@lists.ozlabs.org,
 linux-riscv@lists.infradead.org, linux-s390@vger.kernel.org,
 linux-um@lists.infradead.org, linux-mm@kvack.org
References: <20250717142732.292822-1-snovitoll@gmail.com>
 <20250717142732.292822-2-snovitoll@gmail.com>
 <20250717151048.bb6124bea54a31cd2b41faaf@linux-foundation.org>
Content-Language: en-US
From: Andrey Ryabinin <ryabinin.a.a@gmail.com>
In-Reply-To: <20250717151048.bb6124bea54a31cd2b41faaf@linux-foundation.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: Ryabinin.A.A@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b="juIzD/gb";       spf=pass
 (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::631
 as permitted sender) smtp.mailfrom=ryabinin.a.a@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
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



On 7/18/25 12:10 AM, Andrew Morton wrote:
> On Thu, 17 Jul 2025 19:27:21 +0500 Sabyrzhan Tasbolatov <snovitoll@gmail.com> wrote:
> 
>> Introduce CONFIG_ARCH_DEFER_KASAN to identify architectures that need
>> to defer KASAN initialization until shadow memory is properly set up.
>>
>> Some architectures (like PowerPC with radix MMU) need to set up their
>> shadow memory mappings before KASAN can be safely enabled, while others
>> (like s390, x86, arm) can enable KASAN much earlier or even from the
>> beginning.
>>
>> This option allows us to:
>> 1. Use static keys only where needed (avoiding overhead)
>> 2. Use compile-time constants for arch that don't need runtime checks
>> 3. Maintain optimal performance for both scenarios
>>
>> Architectures that need deferred KASAN should select this option.
>> Architectures that can enable KASAN early will get compile-time
>> optimizations instead of runtime checks.
> 
> Looks nice and appears quite mature.  I'm reluctant to add it to mm.git
> during -rc6, especially given the lack of formal review and ack tags.
> 
> But but but, that's what the mm-new branch is for.  I guess I'll add it
> to get some additional exposure, but whether I'll advance it into
> mm-unstable/linux-next for this cycle is unclear.
> 
> What do you (and others) think?

After looking a bit, it breaks UM and probably LoongArch too.
I'd say it needs more work and not ready even for mm-new.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/a1bc7a9d-817d-49cc-b7f1-79a900090136%40gmail.com.
