Return-Path: <kasan-dev+bncBC7OBJGL2MHBBLXEUL7AKGQESAEWCMI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x437.google.com (mail-pf1-x437.google.com [IPv6:2607:f8b0:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id 6577A2CD2AB
	for <lists+kasan-dev@lfdr.de>; Thu,  3 Dec 2020 10:38:56 +0100 (CET)
Received: by mail-pf1-x437.google.com with SMTP id p5sf1015266pfb.14
        for <lists+kasan-dev@lfdr.de>; Thu, 03 Dec 2020 01:38:56 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1606988334; cv=pass;
        d=google.com; s=arc-20160816;
        b=iaSdHXbC+FPWU940yUbGwHyHQ7w3B13K6fl6LdBDGzjgd5DBHmPevdESGRuTiD7CGa
         Rh9xCxCkCGKU6QPKHcpi4BuYXMIKK4VBLNXgc/Z2hKzGjpqfRm20tpjZYSx3z2GA1Wxz
         /+SX9wQBI5PeT1OrA9+zv8pmyWs2mzWoGmt6jn+qIQppiIEGo68YQlsvVdOMb8WXjWYW
         84p29yISySdS/2Tn2dKqhrRNg1ZU9+fXHMAttR8Fy3uMd3cGY361gEcZHSvmKH5xjHMp
         rd5xN2CJR9gi42nkZlcIhZ2bYf+r0tS/q/NU2ceYzen2iSoiBVrHq04sEADcutHH83V5
         y7cg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=Z7DecPIXcLWFrXeiHuDBRLNHFswvcGOMAFhCqGngajc=;
        b=SFqTW4C5iq95hccY40kmYqNWi/rA8looI6vE+RiHJZCpeZNtpqBAThVuz4+i0lmnHX
         CgJ2CMdcxwB2mJlbGPP2WEbnVsyuM8xGFZgdvNf3Obyo9PBJNFoaJvGOj12l1UMvXj/d
         vt5I0q6FG704z+ATzMcQXnHyv3oDB44eNgRVSJaj+MYrYWEIfdShoa9UnII0J1rga13a
         j1ik/L/dkyPn5rpeXFN0tM4nEJBRsiXMWhPpEA0mQqz870WESR1lmezDR/4vkw1Q1f1Q
         /uZBUjLh/4hUP4eVf/gsZwXNYjnLF+h4GTHpUKMCEosCdvSAQ2Zg9NcRdu3J2/fqBGpR
         3++w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=m1hJYiBM;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22c as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Z7DecPIXcLWFrXeiHuDBRLNHFswvcGOMAFhCqGngajc=;
        b=JueChugVWVO6eMpQ8UpwLG3FQQORMzaTDsup5TZRIKVoOhuoCZug2W2zLa5YA2eDgC
         Tn+pND4RzFY8MmBXwcwDOPOFbJVW+RvaA3Rq52+6TZ/1o3lPTyApGkYF/bRrgf6EhJWm
         krWl2qQasflvPOirnOvVcG8bBqnCcEl5mfnZez34f6yN1gwlG9Jvw718YTGjzIr5ZAQ5
         HiIbBiYVJDCADA6r2n5jXYZxLd+7cjAhFqSC7i0TofHC+m17flrWqdhCDyS5aZekvxud
         +P6vWbj68QHVBjuyCeSVMJBvp7Dv6ygrYoQVkuLD8o5SURswfuTU9fWjTDhcJE8HoQDe
         zEeQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Z7DecPIXcLWFrXeiHuDBRLNHFswvcGOMAFhCqGngajc=;
        b=WiMqgzByjrbt3qjeT8/8c88ZBec+wkqwlTCrL7GSDihD7tT2M1DaNczUPK+VdfhbNq
         BmPq+V/uRnNgQr9uoqd0FrOZYUYFudU5s1GtJ4oleMmgmKPALBozLNV/GDt5N1DvyMHE
         rd77dAfk8bUl7O7tP9Ek1mkyQiGMVie1cQZh2nwGHZkmBW6ev2lM1qnIbWDbjTHNWd9N
         0KX972kYdcL92gY7tmb7h6O/06fGNL5u9R7BOox9ippHtGzm9/LoU5mWx+1VQnY/gyim
         UN/UqvjqJlekGKnhjd1P5IXWFugxbJ86s6ucZn7sIkEs/Vx95qXiLW690QEoMbf+3pGH
         og2g==
X-Gm-Message-State: AOAM530uaE4NsNPf2kYU/9hG8IGRnZlImViDoIxJnkAktFOIYS69I1eE
	HZuZw6H2A7HkxsGZD0R3QFw=
X-Google-Smtp-Source: ABdhPJx8wxtVf39AEJ/a/RKfxlFqiv6yGtLKXZpox/qe+5oxz/qbKB6F2/+u8ON/CJK2ai40kbRIDg==
X-Received: by 2002:a17:902:8b89:b029:d6:df6e:54df with SMTP id ay9-20020a1709028b89b02900d6df6e54dfmr2323831plb.0.1606988334549;
        Thu, 03 Dec 2020 01:38:54 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:7e93:: with SMTP id z141ls2082392pfc.7.gmail; Thu, 03
 Dec 2020 01:38:54 -0800 (PST)
X-Received: by 2002:a62:3:0:b029:160:d92:2680 with SMTP id 3-20020a6200030000b02901600d922680mr2470375pfa.44.1606988333952;
        Thu, 03 Dec 2020 01:38:53 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1606988333; cv=none;
        d=google.com; s=arc-20160816;
        b=jxg8CCwgtGyXX0PnTVdE4N6IkwP5gbR14F9nWpTe57wf/KqW+dHcT7JLAXBgMKm6aG
         ixIZ8G74GY4rnvL38WGopWvDtFZ6eDSDEeXYsY7Q9ZN/ZEaWNpzzapmE9nThFOA/IgrY
         OXDMjN98bZlCkEVvGaMeGlV4v2vXxj4rAh2jL4PxRDqj5gONFmTFJKbI7Wutxz2ckdpA
         1+NPcHiIgC8lNRQjhdvo+9A7eFHm8ZP/Av3Ukq4rxoQcLCV+w6CcoLoYPvRFuMQ5CxfH
         e1HfwvgcTuUC3j5FOJlZt29XaBCvKAh1zSwbEKUoyiJF+7nJy374NLKZ+FnkEmpwSSeB
         pJFA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=vZfTja25g8D62Xo+siAH+79zWUPG/zGsEVDA9zi5GOU=;
        b=VFRFdg5V3bGlBfFu2tPVg309cKS0edS4J6A2LR0CxPPvLoP/dOHmJL1rNOQT4NG7JA
         h7gr9Sdjwz/7L9cT8O3sEGRSxGzcc3+9fB5heR7BP3wM2m/fgsJVeqssbSyT4mybobGo
         PDrzuVdRKXErLZINBIWfT4pzz0XDgBtV+VkROVhS8UWbo4Yg3nXzQWw5fT7buBLzQIW+
         r7dDROe2BI6T8CamCBd2ekwCI3UIAM913GslDe5oMLRZKumLnG4oTEu5qVaMdjNt1t2m
         0UoLV4gsAG0R24fIF8SksikZZuM8gxVYrsie+1wMyvFZebNTO3SuhjKPxLq0YdObrSRd
         b5pA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=m1hJYiBM;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22c as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x22c.google.com (mail-oi1-x22c.google.com. [2607:f8b0:4864:20::22c])
        by gmr-mx.google.com with ESMTPS id q32si36391pja.2.2020.12.03.01.38.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 03 Dec 2020 01:38:53 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22c as permitted sender) client-ip=2607:f8b0:4864:20::22c;
Received: by mail-oi1-x22c.google.com with SMTP id f11so1533785oij.6
        for <kasan-dev@googlegroups.com>; Thu, 03 Dec 2020 01:38:53 -0800 (PST)
X-Received: by 2002:aca:3192:: with SMTP id x140mr1306222oix.172.1606988333102;
 Thu, 03 Dec 2020 01:38:53 -0800 (PST)
MIME-Version: 1.0
References: <CAD-N9QXFwPPZC0t1662foXgHh6_KEFpGGB01hWWryBL=ZsBs0A@mail.gmail.com>
 <20201202124600.GA4037382@elver.google.com> <db967ee9-01c7-4baf-a53f-dedbdf170cc7n@googlegroups.com>
In-Reply-To: <db967ee9-01c7-4baf-a53f-dedbdf170cc7n@googlegroups.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 3 Dec 2020 10:38:41 +0100
Message-ID: <CANpmjNPsr=v6pHahjHGpifWC-FRuPqWu3vVT7i76MGBC6KBarg@mail.gmail.com>
Subject: Re: Any cases to prove KCSAN can catch underlying data races that
 lead to kernel crashes?
To: "mudongl...@gmail.com" <mudongliangabcd@gmail.com>
Cc: kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=m1hJYiBM;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22c as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Thu, 3 Dec 2020 at 02:46, mudongl...@gmail.com
<mudongliangabcd@gmail.com> wrote:
[...]
>> Clearly, data races are defined at the programming-language level and do
>> not necessarily imply kernel crashes. Firstly, let's define the
>> following 3 concurrency bug classes:
>>
>> A. Data race, where failure due to current compilers is unlikely
>> (supposedly "benign"); merely marking the accesses
>> appropriately is sufficient. Finding a crash for these will
>> require a miscompilation, but otherwise look "benign" at the
>> C-language level.
>>
>> B. Race-condition bugs where the bug manifests as a data race,
>> too -- simply marking things doesn't fix the problem. These
>> are the types of bugs where a data race would point out a
>> more severe issue.
>>
>> C. Race-condition bugs where the bug never manifests as a data
>> race. An example of these might be 2 threads that acquire the
>> necessary locks, yet some interleaving of them still results
>> in a bug (e.g. because the logic inside the critical sections
>> is buggy). These are harder to detect with KCSAN as-is, and
>> require using ASSERT_EXCLUSIVE_ACCESS() or
>> ASSERT_EXCLUSIVE_WRITER() in the right place. See
>> https://lwn.net/Articles/816854/.
>>
>> One problem currently is that the kernel has quite a lot type-(A)
>> reports if we run KCSAN, which makes it harder to identify bugs of type
>> (B) and (C). My wish for the future is that we can get to a place, where
>> the kernel has almost no unintentional (A) issues, so that we primarily
>> find (B) and (C) bugs.
>>
>
> Quick question here. I found that there is still a sanitizer for concurrency bug called Kernel Thread Sanitizer. For the above types, what's its detection capability compared with KCSAN?

KTSAN also only detects data races as-is, i.e. no change compared to
KCSAN. Only KCSAN could currently help detect (C) because it supports
ASSERT_EXCLUSIVE*(), but it could theoretically be added to any race
detector.

Also see the "Alternative approaches" section in
https://lwn.net/Articles/816854/.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNPsr%3Dv6pHahjHGpifWC-FRuPqWu3vVT7i76MGBC6KBarg%40mail.gmail.com.
