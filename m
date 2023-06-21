Return-Path: <kasan-dev+bncBCAP7WGUVIKBBHMIZSSAMGQEI6ZEPRA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa3e.google.com (mail-vk1-xa3e.google.com [IPv6:2607:f8b0:4864:20::a3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 2A4EE738634
	for <lists+kasan-dev@lfdr.de>; Wed, 21 Jun 2023 16:07:27 +0200 (CEST)
Received: by mail-vk1-xa3e.google.com with SMTP id 71dfb90a1353d-471b2649508sf1166879e0c.1
        for <lists+kasan-dev@lfdr.de>; Wed, 21 Jun 2023 07:07:27 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1687356445; cv=pass;
        d=google.com; s=arc-20160816;
        b=F5nyJ35ZmACqWeyTc95KZbEBEy+2RQut4wxbmOqJW/QFpcgMesK3u4Rrr8/GKZ7k0i
         aqq16KDuC5Uv8HeQTFssD9A2HBdEoif7JIhHj7KbiersXSFdmTo47y7F9BfNPxLtigxW
         Gg0ZIW0y6+b9+1EzgOOq6zpya7obCXVf7mT0Yyjb09W1+hDOyKgENcWlAXRWEv04/btk
         Dzi8pKCmxRgJ5xzDtJJYaMn8pGD+syhAk9JLv9OlLPwZ+NWFp+6DlFhlzTUe61QDm9lU
         9B0F8Ol2uomeTYAlQcukimctL1HJQFd0nrowhxAe8D8oZ0k5JDsFrLJUNtDKublU9eHe
         hJ/Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=oRyXN8H9kQ9JYeND9HOO1d+LxJeapapAJUZETwzsEJg=;
        b=N082sEQH6zAlhjd0V5deDLBc0SO+/peIpvkDUeUMe0q+/hWI2XrSW3TOqMAPNWBi0J
         HpUgfBc8WSwRPXPp/NhsmiKaR8B6y8niZQ8kZDRjnEMPta3d31jUyJPSYrS91/tjjWTk
         h9jmFJdPO+5ZIgbKWJ0cdARcomGci+Nm60Tt++/kc/Iym6lVl0QWqSBLhT9m730H2Kda
         FO4LK9mMdO2q/+bnl6t/ird4R9TRnuCpBTxkmXceD5a+LLzZu26qMM8oS9lmYkKd78Cc
         cIFQ1uGDPCwb0B+JGm4j6S/v0GP3p63UezsK7gFFvnzwDXe2T9bHXV2Sk2YBwZcJYyyB
         Xpkg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=none (google.com: i-love.sakura.ne.jp does not designate permitted sender hosts) smtp.mailfrom=penguin-kernel@i-love.sakura.ne.jp
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1687356445; x=1689948445;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=oRyXN8H9kQ9JYeND9HOO1d+LxJeapapAJUZETwzsEJg=;
        b=iaSzCJarnedYexD0E1laviykWhawT0khwblnsNQvDSFyzDnc0x5KmFIaSRAtAzV2mE
         EdMWCrtbh31OCKhVl7V3sJ9AkfSCi54zwftn3O6PjeiFKu0OA1UrPPB/wZMjbWspOc6q
         Ken0+1X03BdiIArRBL/VvdqG2MmZnOpOQsoo1QjIZ2fsbsxCSTj6GzHtKk0yM4P678gl
         Zw7dlN0Y953dMv+eh+48X7n7SOUCBu5TMeLRopw6N8FrDhB3+NTHElrsBFnpTa4XI7dX
         zRiAzpSTMeUd+fOEp8jzXRACRoUCPv5bg+sgZkLOlGtffZM3JZh4oJz2IUZh7CHp8Bl5
         ixew==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1687356445; x=1689948445;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=oRyXN8H9kQ9JYeND9HOO1d+LxJeapapAJUZETwzsEJg=;
        b=AznEwKohTE0hi8bFcWNghgz+/aJ5/9jMUG5slG47KmtfLdQY3mW/ev0GYbbaSddh4c
         MF4Mm00QA81DELN9bh6lj9Ei6+4I6gGauYsJnkJ3zSSvmbVPhrkIeIrg/XR2kE11Ntvp
         t5v0QT4qHIXI/rHyUpjbc0AnXNqAj2nvWIIjkzD9lWjpfVZ0j4SFEz4Wh3FZdcD6AMei
         vYbV1QlJmdFBdlxwDRFrZcyCI4hQGasycEa8c11TNMmTxk5Hd3O3sOX91OJ11tiaq44J
         iz5N8PK5YdkcdE4zBL0jXHOt4tefMG4+7LcnZRCz9aNkXX99Vgt1DHL4WzNv/3ICKXSC
         GYkA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AC+VfDyfvsfoSEeIqwEcC3HpeAdrMILkLIG51c+YtoxGxF1+8IdTZ4MA
	ty0MTWuRljJPqwVIii27Enc=
X-Google-Smtp-Source: ACHHUZ5hT+3NWA3AJyFGvU2V8UiFcxAhFHRjm5hFUIthwx+xRgmNgkmy+ZRfAAGRIY0437chXRcyhQ==
X-Received: by 2002:a1f:3d57:0:b0:471:5506:2d85 with SMTP id k84-20020a1f3d57000000b0047155062d85mr5235300vka.5.1687356445652;
        Wed, 21 Jun 2023 07:07:25 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ad4:4baf:0:b0:626:3bf3:c6c1 with SMTP id i15-20020ad44baf000000b006263bf3c6c1ls4118302qvw.1.-pod-prod-09-us;
 Wed, 21 Jun 2023 07:07:24 -0700 (PDT)
X-Received: by 2002:a1f:4801:0:b0:471:cfa1:5065 with SMTP id v1-20020a1f4801000000b00471cfa15065mr3400736vka.3.1687356444065;
        Wed, 21 Jun 2023 07:07:24 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1687356444; cv=none;
        d=google.com; s=arc-20160816;
        b=Nr9DU6UIHDelQhOqR2oMlPyjCqD33xGbS9vm2E+xzC7mfet+6VTQrZM/sAEz+1vdCj
         /6hOU62+YqMkB8zgIVTtNFisT2BB7Ogzi7tKgFH1ACO9QMq1uZxTXc1NjpS6s0FpM6F6
         A/udN9wxQ/s/s3zCcY5nCFtAllgCvTML468ZYxJhrPEGnP341xNqMyCnC4oNj6pcgr+K
         1s+GLWHSgrVGCFxSnS66vo+HohobYNQJEqx1iGYrt3BF3gIZlh1yOe1+wavF0uXQaIQD
         X6zZ1Dljh1iRJ85NSTmAI4qqJB8DzyPM1KyyKQSPc9ZBjLXCrzpY8pfUuR4RFyHygTUj
         0mYw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id;
        bh=RSMQ3lxQasolpoKNN11oNzx11rJvmxMmW9tHIGaOx6E=;
        b=BxlAZc96FiV3ViGi+rCA7Ux4vE03YndoElt+Xc1zlgNIt2/Bm1VYLmMXpLGjrsoN+Y
         PJOXJST7tVx8eUcf77/524u9BtBy5XLnzm14+Wm7ZlDi2PIa8QPdh+quqMcUAaXs+Lq4
         T7v+7bAxO3TLTci+gNt/zkPH9gfYc1QA8T6VpDujGoWKdbX1fb/9bDO8Rvpj0uWx9mv3
         61qAmAWDDchwXddAXqxnPzV0ADOTn5N3IGqaZN+DKKIVWPZAcO2vQfJqn51J2z1angK1
         ryheLRHJzMUj0srVzy6B0dz1VwI4tAAYQWBe70hJlwv/X57TKjPD1GCvePwFfnC4Ot47
         QjNg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=none (google.com: i-love.sakura.ne.jp does not designate permitted sender hosts) smtp.mailfrom=penguin-kernel@i-love.sakura.ne.jp
Received: from www262.sakura.ne.jp (www262.sakura.ne.jp. [202.181.97.72])
        by gmr-mx.google.com with ESMTPS id 199-20020a1f17d0000000b004718773c562si578374vkx.5.2023.06.21.07.07.23
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 21 Jun 2023 07:07:23 -0700 (PDT)
Received-SPF: none (google.com: i-love.sakura.ne.jp does not designate permitted sender hosts) client-ip=202.181.97.72;
Received: from fsav313.sakura.ne.jp (fsav313.sakura.ne.jp [153.120.85.144])
	by www262.sakura.ne.jp (8.15.2/8.15.2) with ESMTP id 35LE79i6080261;
	Wed, 21 Jun 2023 23:07:09 +0900 (JST)
	(envelope-from penguin-kernel@I-love.SAKURA.ne.jp)
Received: from www262.sakura.ne.jp (202.181.97.72)
 by fsav313.sakura.ne.jp (F-Secure/fsigk_smtp/550/fsav313.sakura.ne.jp);
 Wed, 21 Jun 2023 23:07:09 +0900 (JST)
X-Virus-Status: clean(F-Secure/fsigk_smtp/550/fsav313.sakura.ne.jp)
Received: from [192.168.1.6] (M106072142033.v4.enabler.ne.jp [106.72.142.33])
	(authenticated bits=0)
	by www262.sakura.ne.jp (8.15.2/8.15.2) with ESMTPSA id 35LE785S080258
	(version=TLSv1.2 cipher=AES256-GCM-SHA384 bits=256 verify=NO);
	Wed, 21 Jun 2023 23:07:09 +0900 (JST)
	(envelope-from penguin-kernel@I-love.SAKURA.ne.jp)
Message-ID: <34aab39f-10c0-bb72-832b-d44a8ef96c2e@I-love.SAKURA.ne.jp>
Date: Wed, 21 Jun 2023 23:07:07 +0900
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101
 Thunderbird/102.12.0
Subject: Re: [PATCH v3] lib/stackdepot: fix gfp flags manipulation in
 __stack_depot_save()
Content-Language: en-US
To: Alexander Potapenko <glider@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>,
        "Huang, Ying" <ying.huang@intel.com>,
        syzbot <syzbot+ece2915262061d6e0ac1@syzkaller.appspotmail.com>,
        syzkaller-bugs@googlegroups.com,
        Mel Gorman <mgorman@techsingularity.net>,
        Vlastimil Babka <vbabka@suse.cz>,
        Andrey Konovalov <andreyknvl@gmail.com>,
        Dmitry Vyukov <dvyukov@google.com>,
        Andrey Ryabinin
 <ryabinin.a.a@gmail.com>,
        Vincenzo Frascino <vincenzo.frascino@arm.com>,
        Marco Elver <elver@google.com>, kasan-dev <kasan-dev@googlegroups.com>,
        linux-mm <linux-mm@kvack.org>
References: <000000000000cef3a005fc1bcc80@google.com>
 <ecba318b-7452-92d0-4a2f-2f6c9255f771@I-love.SAKURA.ne.jp>
 <ca8e3803-4757-358e-dcf2-4824213a9d2c@I-love.SAKURA.ne.jp>
 <656cb4f5-998b-c8d7-3c61-c2d37aa90f9a@I-love.SAKURA.ne.jp>
 <87353gx7wd.fsf@yhuang6-desk2.ccr.corp.intel.com>
 <CAG_fn=UTTbkGeOX0teGcNOeobtgV=mfGOefZpV-NTN4Ouus7xA@mail.gmail.com>
 <20230609153124.11905393c03660369f4f5997@linux-foundation.org>
 <19d6c965-a9cf-16a5-6537-a02823d67c0a@I-love.SAKURA.ne.jp>
 <CAG_fn=XBBVBj9VcFkirMNj9sQOHvx2Q12o9esDkgPB0BP33DKg@mail.gmail.com>
From: Tetsuo Handa <penguin-kernel@I-love.SAKURA.ne.jp>
In-Reply-To: <CAG_fn=XBBVBj9VcFkirMNj9sQOHvx2Q12o9esDkgPB0BP33DKg@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: penguin-kernel@i-love.sakura.ne.jp
X-Original-Authentication-Results: gmr-mx.google.com;       spf=none
 (google.com: i-love.sakura.ne.jp does not designate permitted sender hosts) smtp.mailfrom=penguin-kernel@i-love.sakura.ne.jp
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

On 2023/06/21 21:56, Alexander Potapenko wrote:
>> But why is __stack_depot_save()
>>   trying to mask gfp flags supplied by the caller?
>>
>>   I guess that __stack_depot_save() tried to be as robust as possible. But
>>   __stack_depot_save() is a debugging function where all callers have to
>>   be able to survive allocation failures.
> 
> This, but also the allocation should not deadlock.
> E.g. KMSAN can call __stack_depot_save() from almost any function in
> the kernel, so we'd better avoid heavyweight memory reclaiming,
> because that in turn may call __stack_depot_save() again.

Then, isn't "[PATCH] kasan,kmsan: remove __GFP_KSWAPD_RECLAIM usage from
kasan/kmsan" the better fix?



>>   Allocation for order-2 might stall if GFP_NOFS or GFP_NOIO is supplied
>>   by the caller, despite the caller might have passed GFP_NOFS or GFP_NOIO
>>   for doing order-0 allocation.
> 
> What if the caller passed GFP_NOFS to avoid calling back into FS, and
> discarding that flag would result in a recursion?
> Same for GFP_NOIO.

Excuse me, but "alloc_flags &= ~__GFP_NOFAIL;" will not discard flags in
GFP_NOFS / GFP_NOIO ?



>>   Generally speaking, I feel that doing order-2 allocation from
>>   __stack_depot_save() with gfp flags supplied by the caller is an
>>   unexpected behavior for the callers. We might want to use only order-0
>>   allocation, and/or stop using gfp flags supplied by the caller...
> 
> Right now stackdepot allows the following list of flags: __GFP_HIGH,
> __GFP_KSWAPD_RECLAIM, __GFP_DIRECT_RECLAIM, __GFP_IO, __GFP_FS.
> We could restrict it further to __GFP_HIGH | __GFP_DIRECT_RECLAIM to
> be on the safe side - plus allow __GFP_NORETRY and
> __GFP_RETRY_MAYFAIL.

I feel that making such change is killing more than needed; there is
no need to discard __GFP_KSWAPD_RECLAIM when GFP_KERNEL is given.

"[PATCH] kasan,kmsan: remove __GFP_KSWAPD_RECLAIM usage from kasan/kmsan"
looks the better.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/34aab39f-10c0-bb72-832b-d44a8ef96c2e%40I-love.SAKURA.ne.jp.
