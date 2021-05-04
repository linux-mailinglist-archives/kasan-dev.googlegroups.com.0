Return-Path: <kasan-dev+bncBCV4DBW44YLRB56SYWCAMGQEQI3FUHI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53b.google.com (mail-pg1-x53b.google.com [IPv6:2607:f8b0:4864:20::53b])
	by mail.lfdr.de (Postfix) with ESMTPS id 5757E372D02
	for <lists+kasan-dev@lfdr.de>; Tue,  4 May 2021 17:34:17 +0200 (CEST)
Received: by mail-pg1-x53b.google.com with SMTP id m36-20020a634c640000b02901fbb60ec3a6sf5399805pgl.15
        for <lists+kasan-dev@lfdr.de>; Tue, 04 May 2021 08:34:17 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1620142455; cv=pass;
        d=google.com; s=arc-20160816;
        b=WR9lYG/PFv/3BD3nOnnPSDH7mi1d1ki2+KnzTKyYBWKePtNmNtzMXi2r9j2nvXAOba
         9DGuubyZGrKfcQA+77icqRdwKI1PTQy0Wobu6+xZeLNOcLLElkZyD9XV3gTyAIPJksHX
         jMmx60I6aGozpgaAmaYOuxnsUyg2L51cgPw1UIkMjrw4L+na2O0k3obGmaKLEb/iOFMe
         cQUs1CJgpBBBIvY3lpwQmpXB6Mr+CqOgQSw9eDCw2eKhNXSWTultO1eG4TQxHS/eZ5aF
         kaa3sf+1L8qpxaKI4QSSEWyBkc4W7y7mT3DVKgK9vHWZo/ehp7fMw/jcNo1ZO7AfJC0c
         ZsiA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:ironport-sdr:ironport-sdr:sender:dkim-signature;
        bh=dGxCn2uI97gVWf3b/Lf8t0XdZzTA10Rk7F9FymzA7q8=;
        b=DKHKUe5VGCUyErRYahn3w90gXY0TT7rL9Xr4BsGHu8TBxufDd6v2V1PhbSCMG18lyD
         2jp1yzZ2ej45mjWrcY58mAuvsznKdjuTJWBRPK3amkYAD7wad/UBZbs4Lrr2yIfdcmzU
         UfnN4QG21wNfkLzRgAQCRcRvQVbOd2Vkj/v0LiRkKH2nTAf1NilPQy7y0V+QagYoDF2Y
         mW/bd8Hi/Mi9vDQn0qBlQRSbrK+veVHZt+qAkQIPiIvcxKqFVC5XfowM5Odi0CMc7IAU
         SIQkg+WOJknBwwrHIdwj5nCCDdCAkLcjv6/nFId3+LgsdL7KPmATAdfqQMkaNALWLh6X
         3Q5Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: best guess record for domain of ak@linux.intel.com designates 192.55.52.151 as permitted sender) smtp.mailfrom=ak@linux.intel.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:ironport-sdr:ironport-sdr:subject:to:cc:references:from
         :message-id:date:user-agent:mime-version:in-reply-to
         :content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=dGxCn2uI97gVWf3b/Lf8t0XdZzTA10Rk7F9FymzA7q8=;
        b=Uz2LtZbi9+cu6DB09W1yqmcWC/HOlvlASAvNXaUN26Rgj51MPUjna3RBuVc1ByPR46
         9ln66NSyv5sMTZgRPdeAC9h24eH8jhXPFVXSAxcu6woRlrO7dvZxAzNtLsOZ243cCVrY
         wxU5lO3ZUy8H5WZ6PsPuSEUxfPyVxakP9jutD8KDGoppIg6NK+quecdNQy8edzb/gOiz
         0NyyD+/iVkwn3E5kqz4fn5HHRS8uRwm/OaSgkx48pi4YLiAV8wkjfPGHOuFJ9K4Y4mrF
         8dz7/yEqdoVy09EP9VPHM8TdEg15dWaxjKmou4NF2GGgj76rOtpQQXSZfTczwrU7T8+N
         VF7w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:ironport-sdr:ironport-sdr:subject:to:cc
         :references:from:message-id:date:user-agent:mime-version:in-reply-to
         :content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=dGxCn2uI97gVWf3b/Lf8t0XdZzTA10Rk7F9FymzA7q8=;
        b=LsMmdFC7h/e9qyCd2I3ld87x/5qQw5+FAwIDsD0wbrsl2YXyJp6wvoeWnuZxTFkB/K
         +pUL++PspaY/TWXHRXamy4v+FNcLEiAm9Xf1UDkeNL0zLeWobATk2M9nkE4wcofsTElG
         Wh5kn3Erqufc8/fTdKHE6auO7Ant5Jgp9qyhvCWoMjNxPsHDaEAwwp0E7fiFoUq6P2uu
         uqlCQ60V1BpMXBZnMqo/y3pfbtDIn5/WuLN9rBtP9Mo40UhEcco7ZE3i82tx5mP1HeKS
         mr8MlTzZpSqBwjohZrVfzCtpcFd3WrYbi5JC0HNl6S5/1PAMUYmJgRK7U4WuuWJxpQQ1
         38Ig==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533i15kWn4TRjeKD/OgwaJs81Lg/vizaEQ09DRzgcx3OBchKcWny
	PiCzR7wMOCC5HsYqgfBbhck=
X-Google-Smtp-Source: ABdhPJw/H77nWZqFK7iNkejmA55+DXPgnRlpGju2YPLzhOILLiAT+McU6mS/XZaxeH0tKVG2v7//tg==
X-Received: by 2002:a17:90a:fd95:: with SMTP id cx21mr5665257pjb.137.1620142455701;
        Tue, 04 May 2021 08:34:15 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:8d0:: with SMTP id s16ls6971632pfu.3.gmail; Tue, 04
 May 2021 08:34:15 -0700 (PDT)
X-Received: by 2002:a05:6a00:ccc:b029:276:93c:6a1d with SMTP id b12-20020a056a000cccb0290276093c6a1dmr24213392pfv.58.1620142455170;
        Tue, 04 May 2021 08:34:15 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1620142455; cv=none;
        d=google.com; s=arc-20160816;
        b=vGiH4lBTPYKzWLIx6TgUcm8WYbgDT/WMyo/MgWQBqg4l3s8/sft7TWslyX5+NH+w0R
         gBvMb0sMjpYf9FL8bvTOwdnQTsVSBsUGcYz1MNr847h6++OUx06dbeHZx/H78iAYNDrh
         z4SRqHBXmILvE06Ms3sSsygqb5WrwioBMc/17jcPSSyzShIbT0KZ/LQpuCKA7PASysXA
         1NbKC8162tEJajGxRVQjJKeNCrEczbjlFCqW9RexkkpB8XWI1KmMAeEHsygPFtS8mi8X
         pZjVSe7uOqO27Fth5x8ZzLuevm0qgkuplCfCfFY0b3fOMnl0tH3aJWSpNm6tqkOKGgSb
         awwA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-language:content-transfer-encoding:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject
         :ironport-sdr:ironport-sdr;
        bh=mwRenKfGJJHfnAoX0BXRpZhEKJBEZaUP54rKTetvENA=;
        b=Y0PMyXZY8injJncVKtRqNYzvoPk7Be0vPZaS7W0obyXWUsE7x2lSbEzz4ZHYhUZtdO
         kU6gSSPIa1q7/a8aepL+4v6bUucLGBIf+8HfeG9zHuvT0t3RCA4K3Q/S4IBAE4iFCP3x
         ZAmN8mtxb306klYAueKV9hcg7K5kJ4M8mcx7Cp454Ai4JsHnxoWMYrvuLCVZxc+zxmK7
         QyoeDRpJYgDcITAZn36ystj8P4OFgJ4Dh8Ko04LUZCTrIZjdJEifjDmKdE0w6zw5tUX2
         iejAvmlF1f0Bb/eTwqGqXVYU3Owi6uV1cK2lRtUgEXFm2f4hzNmU73WKefp53tp+VLao
         wApA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: best guess record for domain of ak@linux.intel.com designates 192.55.52.151 as permitted sender) smtp.mailfrom=ak@linux.intel.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mga17.intel.com (mga17.intel.com. [192.55.52.151])
        by gmr-mx.google.com with ESMTPS id t19si344821pjq.3.2021.05.04.08.34.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 04 May 2021 08:34:15 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of ak@linux.intel.com designates 192.55.52.151 as permitted sender) client-ip=192.55.52.151;
IronPort-SDR: I8GEop+WdGjtQ+o+JAV3WuETQ29v13ERco+V5iB082PS7oLG89kZnTSZxwjCWJHSMgwt0qQ75A
 rG7K0gJWXw1Q==
X-IronPort-AV: E=McAfee;i="6200,9189,9974"; a="178218869"
X-IronPort-AV: E=Sophos;i="5.82,272,1613462400"; 
   d="scan'208";a="178218869"
Received: from fmsmga002.fm.intel.com ([10.253.24.26])
  by fmsmga107.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 04 May 2021 08:34:14 -0700
IronPort-SDR: KulzZHe3YtLAXjSxtUelZ9opEwFO35+T05pzWl2uTlqinDA3g9oZjpQ2dAIs4byJZf/Ps938c7
 Y9T5F6dxvtNA==
X-IronPort-AV: E=Sophos;i="5.82,272,1613462400"; 
   d="scan'208";a="463271730"
Received: from akleen-mobl1.amr.corp.intel.com (HELO [10.209.47.237]) ([10.209.47.237])
  by fmsmga002-auth.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 04 May 2021 08:34:13 -0700
Subject: Re: [PATCH] stackdepot: Use a raw spinlock in stack depot
To: Dmitry Vyukov <dvyukov@google.com>
Cc: LKML <linux-kernel@vger.kernel.org>,
 Andrey Ryabinin <ryabinin.a.a@gmail.com>,
 Alexander Potapenko <glider@google.com>,
 Andrey Konovalov <andreyknvl@gmail.com>,
 Peter Zijlstra <peterz@infradead.org>,
 Andrew Morton <akpm@linux-foundation.org>,
 kasan-dev <kasan-dev@googlegroups.com>
References: <20210504024358.894950-1-ak@linux.intel.com>
 <CACT4Y+a5g5JeLJFPJEUxPFbMLXGkYEAJkK3MBctnn7UA-iTkXA@mail.gmail.com>
From: Andi Kleen <ak@linux.intel.com>
Message-ID: <77634a8e-74ab-4e95-530e-c2c46db8baa7@linux.intel.com>
Date: Tue, 4 May 2021 08:34:13 -0700
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:78.0) Gecko/20100101
 Thunderbird/78.10.0
MIME-Version: 1.0
In-Reply-To: <CACT4Y+a5g5JeLJFPJEUxPFbMLXGkYEAJkK3MBctnn7UA-iTkXA@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Language: en-US
X-Original-Sender: ak@linux.intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: best guess record for domain of ak@linux.intel.com designates
 192.55.52.151 as permitted sender) smtp.mailfrom=ak@linux.intel.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=intel.com
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


> So why is this a false positive that we just need to silence?
> I see LOCKDEP is saying we are doing something wrong, and your
> description just describes how we are doing something wrong :)
> If this is a special false positive case, it would be good to have a
> comment on DEFINE_RAW_SPINLOCK explaining why we are using it.
>
> I wonder why we never saw this on syzbot. Is it an RT kernel or some
> other special config?

This happened in a special configuration that triggered ACPI errors at 
boot time.

It's probably not something that is normally executed, as well as syzbot is

probably not exercising bootup anyways.

> A similar issue was discussed recently for RT kernel:
> https://groups.google.com/g/kasan-dev/c/MyHh8ov-ciU/m/nahiuqFLAQAJ
> And I think it may be fixable in the same way -- make stackdepot not
> allocate in contexts where it's not OK to allocate.


Yes that's a good idea. I've seen also other errors about the allocator 
triggered

by stack depot being in the wrong context. Probably doing that would be 
the right

fix. But I actually tried to switch depot to GFP_ATOMIC allocations 
(from GFP_NOWAIT),

but it didn't help, so I'm not fully sure what needs to be changed.

-Andi


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/77634a8e-74ab-4e95-530e-c2c46db8baa7%40linux.intel.com.
