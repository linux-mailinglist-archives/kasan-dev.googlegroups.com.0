Return-Path: <kasan-dev+bncBC7OBJGL2MHBBVHXUGIQMGQEQTHKZ6Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3a.google.com (mail-io1-xd3a.google.com [IPv6:2607:f8b0:4864:20::d3a])
	by mail.lfdr.de (Postfix) with ESMTPS id D837D4D2CBF
	for <lists+kasan-dev@lfdr.de>; Wed,  9 Mar 2022 11:05:09 +0100 (CET)
Received: by mail-io1-xd3a.google.com with SMTP id 24-20020a5d9c18000000b0064075f4edbdsf1363859ioe.19
        for <lists+kasan-dev@lfdr.de>; Wed, 09 Mar 2022 02:05:09 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1646820308; cv=pass;
        d=google.com; s=arc-20160816;
        b=szmLsNl1Dd2FfHxaRaEgUDahu7S49I0/jq9NnaYMdLLBtnl72s4+rVMN1vBqpVSrgG
         1Saqixm30rjstZT0w68d3BtzwDjXu6QTS0D3cpNTiZOFolQENL2GUCrCRNTuGGCB6Nkg
         wdH3iea7wQBypO9lTBiIPd2lIrPG67KtORSzUP7n7XW+oU9zCKC4uxz6LpLjCSVsxVyW
         /ItNQsjR6ZRBCAx08626os4PGQVnHsYS1PR8Ett1eMAZb6CEl6I1InhlZyQYPQiwstoI
         JQO8OlQuL0Ryb1Q9ahY6KUPLw9v9jWr0xhXDoM6NO4yo8FtutI8DDxVIqykaazU1dA6h
         A9Pg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=LCb9Qxxs4KMlopcV8n/1s5RNp0i5Rq+fL4orzfBKr0s=;
        b=gC/2TAIONyqL3riPeyfreQaUaUkBKv2+dVlNfvHmnltAwS0h8jwgPKKYhgk28iz5ye
         XZikrC531p01kEXpBv7QrhB4tLRdJC65aEM4mvZq2iONMcEkdURPKd8BRLM9S0bpqM91
         QVjQij2XKapHKTDzubjstfXb7nu89WEnbpzZpYXp67subey6SFGXIpbWGEXVANZO2Dde
         VFFl/6O9THEWmWK8Q2hOxJ7zVyCiD7f/NI35c3Safj2KV78Y6ZBy6mqUwUpqq/lHJ1C5
         y6KPqeUMzsjbQ7qW7gaXdpny9FeEHh8+HqjUGtjtKkINqorEEipcuUg9mj6mveglsz+a
         4dww==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=kIGAA3FT;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1136 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=LCb9Qxxs4KMlopcV8n/1s5RNp0i5Rq+fL4orzfBKr0s=;
        b=Xcef8TrhvhyKTzb44aUQx51X1CyHw6uXXWQ5vDvVgUTAzVy65LTJFYzU4KHyZ33UK3
         ZITsrXbBzuklo1PgITVwlyNu/s1FFt+sr1/wgEf7BVZYAU0Z+E620PwkpVftKl4hPLSd
         Lm88EiibWkq/yIXfjodAFFsofqIKU/k9I3iK8S+tKX+AM0zS09R3W5mRnq4i7/n/3Un9
         qtLw0tXPwk/XklMcJ6GZEAp0STSH0y8rgd6nPV8OO8y0QpU78w/oOtX8RohNcn71IrUP
         ibkWGwicPDOWH0LEm+mgYQ7SMfjsyaxvC6en/aUkEHZwBLR8RinOAQtK//ZzDvFfUBUD
         DxFg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=LCb9Qxxs4KMlopcV8n/1s5RNp0i5Rq+fL4orzfBKr0s=;
        b=dY5/LM78lNxvgLe+ZyBDiQvvual3r2ZPPfABjB00pT32wrT8+uMGpRnD5IU5icshI3
         XgjIuaEpVwTzKL0CeqjatA+kiS5qjo/un8Oo+rHcCV8yc30aaM8zXtPO7MilmHuB7eHe
         cQspg7b6MANbNUTJOFxsDGcNLqZwRuBfz2O5bRKIlqj8c+7CjLua01PUu6jY8MwQON+S
         nPZz5IVGQHkhQndROqktSY0qmAIfpmwAbD6RC/Yo2sWcRTfMrioU7rAdbLiQr4uCHtN1
         R+/QmBVu0f/lGmBC5HygEIyFaPTH/d6PdEviD0O0lxdEvxZrjQd8ok2W3OlSRFSxtxY0
         LBuA==
X-Gm-Message-State: AOAM532J62vtqcwzARyy4XyCD5+N75xzdCC5JYIf9A3fvL6UTFVfc4EV
	Jd6xOKU1ViW00/kmmFgSblI=
X-Google-Smtp-Source: ABdhPJxJJ9NXc2C5p+aaGyvhJqfTSNDmyjHr2ECJ5O956F977j88e0kPsfv0kEVJK3XXNWMPQxBzxQ==
X-Received: by 2002:a05:6e02:1a06:b0:2c6:73d6:7ad9 with SMTP id s6-20020a056e021a0600b002c673d67ad9mr581109ild.74.1646820308697;
        Wed, 09 Mar 2022 02:05:08 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:de4a:0:b0:2c6:1570:ca65 with SMTP id e10-20020a92de4a000000b002c61570ca65ls260486ilr.11.gmail;
 Wed, 09 Mar 2022 02:05:08 -0800 (PST)
X-Received: by 2002:a92:511:0:b0:2c2:c40b:fe85 with SMTP id q17-20020a920511000000b002c2c40bfe85mr19605569ile.163.1646820308296;
        Wed, 09 Mar 2022 02:05:08 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1646820308; cv=none;
        d=google.com; s=arc-20160816;
        b=d4rMYnFSvJSNvLWiVBjUZwJmKEC4TK/30waOqiwucy9XPka4GPWBXpewJQkHaX/Z2J
         TRUzkw53+rsVEI0jlpCLV1bXQ2Ono5N2svG9BodSMRPJTjE8vOIEuMB52d8MIKdZoPwq
         Osqu5oyp8R9SDce2mtRKK6674W9zXlZZ69kZ7j//AD+Idygc8vw9IqS3bhJ6ZOLtuGH7
         s2b4b+bxzqGF/r45GixSGd0VsjrsCWo2D98c9zqWEZDISlgBK5rn1PHOcVQasaLHc3wY
         ZlAqLP8KmnKJhUm6fpDMMeTdCSG3+M8OmIuQ334belwzis5PC4ft29aOAtB/QEumqHfV
         zocQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=3ts1/JyZlYWr+VS9x1U6wWLuWTL/1XWXl7pSXJy75es=;
        b=LZXIcuSY//XeOWa/4vPNj3lJmfBB54ylfQ7GKuZcQU7UqOwrZSzddGKQVg2en+xgkb
         VYFQtoyLYeuTAs69vksMdIhtfKjUleUc07KGW441vpTjFi8vWcDgT8vgjIlJoAKGxqwN
         AOoZTIXFyuESVirpQd7gVJA3KYDC+av80JxHiUf7Q/jMrjmNb7oqI+nl+YNcYr1UmeVL
         6TmOUv7WnPMOvBhTzxdAPophEuABIoLLrwGPiCrdSqH0brqWZTWbmXeb9ug8MRwiTBlI
         C24/FVoadlgg2uEwQ8V0eiL2nW1EhNUVkOoi/jr4D3GDfMOSFZhvHYjhAuqAXAzF60GV
         37oA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=kIGAA3FT;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1136 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x1136.google.com (mail-yw1-x1136.google.com. [2607:f8b0:4864:20::1136])
        by gmr-mx.google.com with ESMTPS id f8-20020a926a08000000b002bfacb964cdsi69615ilc.0.2022.03.09.02.05.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 09 Mar 2022 02:05:08 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1136 as permitted sender) client-ip=2607:f8b0:4864:20::1136;
Received: by mail-yw1-x1136.google.com with SMTP id 00721157ae682-2d6d0cb5da4so16552767b3.10
        for <kasan-dev@googlegroups.com>; Wed, 09 Mar 2022 02:05:08 -0800 (PST)
X-Received: by 2002:a81:9ad7:0:b0:2db:f000:32e7 with SMTP id
 r206-20020a819ad7000000b002dbf00032e7mr16235265ywg.412.1646820307524; Wed, 09
 Mar 2022 02:05:07 -0800 (PST)
MIME-Version: 1.0
References: <20220309083753.1561921-1-liupeng256@huawei.com> <20220309083753.1561921-3-liupeng256@huawei.com>
In-Reply-To: <20220309083753.1561921-3-liupeng256@huawei.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 9 Mar 2022 11:04:30 +0100
Message-ID: <CANpmjNP1gekyBke9x5EV_wWQd8j4aA4nTqh5bg2w3fkNfmvXJA@mail.gmail.com>
Subject: Re: [PATCH v2 2/3] kunit: make kunit_test_timeout compatible with comment
To: Peng Liu <liupeng256@huawei.com>
Cc: brendanhiggins@google.com, glider@google.com, dvyukov@google.com, 
	akpm@linux-foundation.org, linux-kselftest@vger.kernel.org, 
	kunit-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	kasan-dev@googlegroups.com, linux-mm@kvack.org, wangkefeng.wang@huawei.com, 
	Daniel Latypov <dlatypov@google.com>, David Gow <davidgow@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=kIGAA3FT;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1136 as
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

On Wed, 9 Mar 2022 at 09:19, 'Peng Liu' via kasan-dev
<kasan-dev@googlegroups.com> wrote:
>
> In function kunit_test_timeout, it is declared "300 * MSEC_PER_SEC"
> represent 5min. However, it is wrong when dealing with arm64 whose
> default HZ = 250, or some other situations. Use msecs_to_jiffies to
> fix this, and kunit_test_timeout will work as desired.
>
> Fixes: 5f3e06208920 ("kunit: test: add support for test abort")
> Signed-off-by: Peng Liu <liupeng256@huawei.com>

Reviewed-by: Marco Elver <elver@google.com>

+Cc more KUnit folks.

> ---
>  lib/kunit/try-catch.c | 2 +-
>  1 file changed, 1 insertion(+), 1 deletion(-)
>
> diff --git a/lib/kunit/try-catch.c b/lib/kunit/try-catch.c
> index 6b3d4db94077..f7825991d576 100644
> --- a/lib/kunit/try-catch.c
> +++ b/lib/kunit/try-catch.c
> @@ -52,7 +52,7 @@ static unsigned long kunit_test_timeout(void)
>          * If tests timeout due to exceeding sysctl_hung_task_timeout_secs,
>          * the task will be killed and an oops generated.
>          */
> -       return 300 * MSEC_PER_SEC; /* 5 min */
> +       return 300 * msecs_to_jiffies(MSEC_PER_SEC); /* 5 min */
>  }
>
>  void kunit_try_catch_run(struct kunit_try_catch *try_catch, void *context)
> --
> 2.18.0.huawei.25
>
> --
> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220309083753.1561921-3-liupeng256%40huawei.com.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNP1gekyBke9x5EV_wWQd8j4aA4nTqh5bg2w3fkNfmvXJA%40mail.gmail.com.
