Return-Path: <kasan-dev+bncBAABB7MTUGIQMGQEU2SIGGQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1040.google.com (mail-pj1-x1040.google.com [IPv6:2607:f8b0:4864:20::1040])
	by mail.lfdr.de (Postfix) with ESMTPS id 143544D2903
	for <lists+kasan-dev@lfdr.de>; Wed,  9 Mar 2022 07:32:31 +0100 (CET)
Received: by mail-pj1-x1040.google.com with SMTP id s20-20020a17090ad49400b001bf481fae01sf2286116pju.1
        for <lists+kasan-dev@lfdr.de>; Tue, 08 Mar 2022 22:32:31 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1646807549; cv=pass;
        d=google.com; s=arc-20160816;
        b=RDmayC63mvjmTUttEZ8efLAXqjVFBU1Y+CZlyWDdWCzi9h3wyaqZPfw2WG47fvdsZk
         y1WB9WbiZFUPSe2vFXsWvnRKXJSa7D61ruN5t+wioglYey1TLeEuyU0xYT3+WtALrJ4+
         nXB3n6iaj5Od4A9167K9InZ65S0bDLQXrWCsqZm80c9kqiOttPj4RSyZ4F4t/A2Ggo84
         CuvVpU7/NGI80wgiLwn1saZ3e6P8KkVY94PiRXhWR7q/63fruRMaEIkC4ZDZIwBHQxwy
         Qe9OcJsBp7abq3Tfi42O3OHc2Ol+eSpkbSpAHby/1LEq7KtpPRN+cqutIRa15saEWhNK
         P8vg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to:from
         :references:cc:to:content-language:subject:user-agent:mime-version
         :date:message-id:dkim-signature;
        bh=TQNfuq99GYfd31zYYj3OO7JKertUxfu+/lDG/HpYin4=;
        b=rgJJ0bY5C9Yzx3aOD4kfdGMLDWDAckec+hf0Zh2L+Z9TiVjZDLmbW1DOcPIsFaehbc
         /TqP25iq3ilfZvE2sSsa8Kg4obRJLt1ZLE4Rfm0DelO4pa2ZInaFbB7GPhm7tbDIjBJk
         13/lgpb1vKY0j71P9Y7nAKxTabzb7Pq0YC2AbHQMU7G2g8eYZsw2esw/h4Fa3zgAEKJw
         UXHI90QE1GvEqWKienFvC0lVtb6j8DKfvq8paj4ofItb5UmwLSAIoGCrAxQA8v9SGwai
         q1ctgC/++NSYVTlkoeQiCuT2GyF18fo5g0ZoxbV9F+avXQQE7nKQ1RMROrAmGvE9UrmQ
         T2aw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of liupeng256@huawei.com designates 45.249.212.188 as permitted sender) smtp.mailfrom=liupeng256@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=message-id:date:mime-version:user-agent:subject:content-language:to
         :cc:references:from:in-reply-to:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=TQNfuq99GYfd31zYYj3OO7JKertUxfu+/lDG/HpYin4=;
        b=QRMlfjl2e7csdnkJjMCndSQAQm5v9S/vDiLHbayKxW3uGjoNlNbusWkJotNKge/Q18
         OoFZNMokqCbSZ1v+RLvu5G6pESXQfs528QSmUtUPHVduuPo2iRIiiKfgeft211Enmi6k
         Ge/ZAPXcSgn63Nr1bHf+FNeBvpnZp1uNRbeBRph9o/2lZZI7AxZ/+YbfISv2mmF0DdUJ
         NG2xjP8HDWY/2M945DiY+kJbpvt7WbCd6xiqwNpZ0rs8IFamuEzAJ9hPMTX27DaFFNLc
         E2wZDl1GKvWsAlwsIlqKhHBrr8GlEej7ung4HEnf+NuIK/yrvQ5Aw7RzDj07XTWxcrTb
         iKTw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:message-id:date:mime-version:user-agent:subject
         :content-language:to:cc:references:from:in-reply-to
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=TQNfuq99GYfd31zYYj3OO7JKertUxfu+/lDG/HpYin4=;
        b=PoKTt1QwNpqR54+L+XVYrIxLGfqWRlv8al3bxC0fx08dhFR4Z6zI95X0w2bEAlvd0/
         8KRiH7Z6lX0hc/kPbGJ0nMiiWMgC7HzJQ7gRB+GLV9Pz3MDVxMalbWm4/remI2JCQ5OA
         bQesxU5ZYiHjQZA2EfbNVrodCbrpBwNpbwWwIwL4s0cPtpr4+8gEfs4FOqom4vsvBB+a
         UPV8RwVGvjlVgNh2gVcM5+/rjAjiQ5VQCzclFgkySj6LHzzKnf+tWa7l20MQddlqSD9F
         IpdPl7B+9CC5lPOTfyB3Ny/hKik62ZXP8+tIbn6lUxuawek2NGo3Z76u9Ew12oQiTHyv
         77dw==
X-Gm-Message-State: AOAM530E3Uo+4x1TdI3+boQ31SuqGIAusoJI1sZnKGAYG4rtRHv2kzdJ
	A3j6AzPEDU/px8KLHHDk3JQ=
X-Google-Smtp-Source: ABdhPJzBquOJcOL3ksU59nCsPw+pgaGRnrD5zXsJLjYYPb4bD1EORmZndFDxtHdxEhHtFWHbcZcHSA==
X-Received: by 2002:a63:535a:0:b0:373:d239:7c7d with SMTP id t26-20020a63535a000000b00373d2397c7dmr16623273pgl.483.1646807549779;
        Tue, 08 Mar 2022 22:32:29 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:318c:0:b0:37c:926d:3fc3 with SMTP id x134-20020a63318c000000b0037c926d3fc3ls509401pgx.8.gmail;
 Tue, 08 Mar 2022 22:32:29 -0800 (PST)
X-Received: by 2002:a63:874a:0:b0:37c:7fb0:9600 with SMTP id i71-20020a63874a000000b0037c7fb09600mr17250525pge.424.1646807549189;
        Tue, 08 Mar 2022 22:32:29 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1646807549; cv=none;
        d=google.com; s=arc-20160816;
        b=1KVbDzmjokruopWMaRg91zIht1CElypRawJMv/5yK81iETkcqEFog/IxZrg69ctvyT
         o1vqJG59mno5V/nzbN8g7xm5D9aSOswx1X/nD8znTMLRnrOtfmy4MlBHAYFeK8imXWIs
         SUj5oeoZe4YlPr9ixiHZGipQVymKFXHLqQZb8i0cj3GG2XiNdyUEPn4fNkdFDEcp11Hr
         eE5rxDxGv11cX/O7pVUxKmWFYJCi+HC2YJfa96BmLmzIwuS8Cu0qtqg5h5jLNXzAvN4K
         +yxA7oqOcmMi22dNkyUhoXWqN1598iSs0YfST60SWQtkhTUldNfw78FKfXjTdqHcUICk
         6+qw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id;
        bh=N+TrD5xhySEJC9/iPPbS019T/L4LKM0GDKoNNKHjJ1Q=;
        b=GAiBZgp5Hyj032lv5m4O4T+ET7QEZlfXfIVhX+lgseeEriO3sl2L7y0i1jlc6CoPOW
         WQBxPKPZec5OkBrUPBu4KYncMpGwq+wGWR8R7Y3ItpGGdgQKjBPVFjhOvT0qYSmlQJ8y
         +ZwiIVzvWpdBqkJPf3CKVTeNf7Ai+4eI1QzYh9T7Q51NkDFITttVpqn0tgVsr+U77kiu
         2XnA7PyaJUf3g6avCks9gSDRN6c1bdo7h8QjHE2EKhdqd8QLBAD9KSIS4mJpSI73tf4q
         4zRUFxD0IwGkzPf7Ghsua1Cwupr/R0PtpoRTCdcJz9RMLRasknFyu9j/Fgy0Cn9DJqF2
         p8Yg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of liupeng256@huawei.com designates 45.249.212.188 as permitted sender) smtp.mailfrom=liupeng256@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
Received: from szxga02-in.huawei.com (szxga02-in.huawei.com. [45.249.212.188])
        by gmr-mx.google.com with ESMTPS id o60-20020a17090a0a4200b001bfaa457ad2si52239pjo.3.2022.03.08.22.32.28
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 08 Mar 2022 22:32:29 -0800 (PST)
Received-SPF: pass (google.com: domain of liupeng256@huawei.com designates 45.249.212.188 as permitted sender) client-ip=45.249.212.188;
Received: from kwepemi100020.china.huawei.com (unknown [172.30.72.55])
	by szxga02-in.huawei.com (SkyGuard) with ESMTP id 4KD2P539QGzBrhQ;
	Wed,  9 Mar 2022 14:30:01 +0800 (CST)
Received: from kwepemm600017.china.huawei.com (7.193.23.234) by
 kwepemi100020.china.huawei.com (7.221.188.48) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2375.18; Wed, 9 Mar 2022 14:31:56 +0800
Received: from [10.174.179.19] (10.174.179.19) by
 kwepemm600017.china.huawei.com (7.193.23.234) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2308.21; Wed, 9 Mar 2022 14:31:55 +0800
Message-ID: <0423ef8e-bfd0-3a4b-78a5-17dc621660d2@huawei.com>
Date: Wed, 9 Mar 2022 14:31:54 +0800
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:91.0) Gecko/20100101
 Thunderbird/91.3.2
Subject: Re: [PATCH 2/3] kunit: make kunit_test_timeout compatible with
 comment
Content-Language: en-US
To: Marco Elver <elver@google.com>
CC: <brendanhiggins@google.com>, <glider@google.com>, <dvyukov@google.com>,
	<akpm@linux-foundation.org>, <linux-kselftest@vger.kernel.org>,
	<kunit-dev@googlegroups.com>, <linux-kernel@vger.kernel.org>,
	<kasan-dev@googlegroups.com>, <linux-mm@kvack.org>,
	<wangkefeng.wang@huawei.com>
References: <20220309014705.1265861-1-liupeng256@huawei.com>
 <20220309014705.1265861-3-liupeng256@huawei.com>
 <CANpmjNOU+M1ZaRTMPMCFE7pm8JXLKsWcMpMAsDmJXZUga3N7=A@mail.gmail.com>
From: "'liupeng (DM)' via kasan-dev" <kasan-dev@googlegroups.com>
In-Reply-To: <CANpmjNOU+M1ZaRTMPMCFE7pm8JXLKsWcMpMAsDmJXZUga3N7=A@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Originating-IP: [10.174.179.19]
X-ClientProxiedBy: dggems706-chm.china.huawei.com (10.3.19.183) To
 kwepemm600017.china.huawei.com (7.193.23.234)
X-CFilter-Loop: Reflected
X-Original-Sender: liupeng256@huawei.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of liupeng256@huawei.com designates 45.249.212.188 as
 permitted sender) smtp.mailfrom=liupeng256@huawei.com;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
X-Original-From: "liupeng (DM)" <liupeng256@huawei.com>
Reply-To: "liupeng (DM)" <liupeng256@huawei.com>
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

Thank you for your advice.

On 2022/3/9 14:03, Marco Elver wrote:
> On Wed, 9 Mar 2022 at 02:29, 'Peng Liu' via kasan-dev
> <kasan-dev@googlegroups.com> wrote:
>> In function kunit_test_timeout, it is declared "300 * MSEC_PER_SEC"
>> represent 5min. However, it is wrong when dealing with arm64 whose
>> default HZ = 250, or some other situations. Use msecs_to_jiffies to
>> fix this, and kunit_test_timeout will work as desired.
>>
>> Signed-off-by: Peng Liu <liupeng256@huawei.com>
> Does this need a:
>
> Fixes: 5f3e06208920 ("kunit: test: add support for test abort")
>
> ?

Yes, I will add this description.

>> ---
>>   lib/kunit/try-catch.c | 2 +-
>>   1 file changed, 1 insertion(+), 1 deletion(-)
>>
>> diff --git a/lib/kunit/try-catch.c b/lib/kunit/try-catch.c
>> index 6b3d4db94077..f7825991d576 100644
>> --- a/lib/kunit/try-catch.c
>> +++ b/lib/kunit/try-catch.c
>> @@ -52,7 +52,7 @@ static unsigned long kunit_test_timeout(void)
>>           * If tests timeout due to exceeding sysctl_hung_task_timeout_secs,
>>           * the task will be killed and an oops generated.
>>           */
>> -       return 300 * MSEC_PER_SEC; /* 5 min */
>> +       return 300 * msecs_to_jiffies(MSEC_PER_SEC); /* 5 min */
> Why not just "300 * HZ" ?

Because I have seen patch

df3c30f6e904 ("staging: lustre: replace direct HZ access with kernel APIs").

Here, both "msecs_to_jiffies(MSEC_PER_SEC)" and "300 * HZ" is ok for me.

>>   }
>>
>>   void kunit_try_catch_run(struct kunit_try_catch *try_catch, void *context)
>> --
>> 2.18.0.huawei.25
>>
>> --
>> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
>> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
>> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220309014705.1265861-3-liupeng256%40huawei.com.
> .

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/0423ef8e-bfd0-3a4b-78a5-17dc621660d2%40huawei.com.
