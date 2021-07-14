Return-Path: <kasan-dev+bncBC7OBJGL2MHBB4FBXODQMGQEYHBIUQI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc38.google.com (mail-oo1-xc38.google.com [IPv6:2607:f8b0:4864:20::c38])
	by mail.lfdr.de (Postfix) with ESMTPS id 83B843C8421
	for <lists+kasan-dev@lfdr.de>; Wed, 14 Jul 2021 13:56:33 +0200 (CEST)
Received: by mail-oo1-xc38.google.com with SMTP id g4-20020a4adc840000b029025e89d69142sf1504048oou.8
        for <lists+kasan-dev@lfdr.de>; Wed, 14 Jul 2021 04:56:33 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1626263792; cv=pass;
        d=google.com; s=arc-20160816;
        b=OQ3bjTJYOys75cq+BURwpK6wiqHqfqqWRdjz3HFMbMX8eK5AZ0Uj5SQMiPSkCwVFKU
         7lAWozJV5Ki8KGN+SDBq7tBAA6QnwhK9loLhwIOztUh/fu7QJlQuSTLcabX48Yf+/PFK
         IUpSud17DVEB0VvFORwndC9sbeoRVd+jd+RzocjCVwJAYLS6VEtyox7pI7kPe7UfxWeW
         HsBvv9TbEn6y9LMt1lVaUUkIAcIKEOu8gQjnkyBogMWbRm7ewL1/hwxW5qNTAqWr1zF4
         /Bk4f9xskmaL3ocrh3K5dRnOEh8PhQkg4brWJ6YB4tF51qFyHQWHTkag9Qydb059m37m
         99VA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=5UeZD2Q6M9sE4t5/l34fDz0TtrtOxKpNapy+kU1Q4rk=;
        b=ZmC7bLOrTrA4izNCvkz35EHH31D/WLWDSKutC7b6TgacWnubghvfVEfrlkBuXskFqI
         7MpqtaZfxOOPWWTRYY+iKGNhkBmvfo9NyrmQ0FiK4IPVSJqM1jhK6+3+XhCzTGfDQ78k
         xVgwzJ6+3FWm8ikN+V2uhHu9gHBfZHwoUc0qDtgXv7mylT3AEYEKmjt/wI09pZ73qvVa
         +STu/O/VXmeM+1327MLqRvSkeukbibtmcPU7wpvqlqFs+ZB8h6Vr9rYcQbHNlXkVjpaI
         +QbqHIyas/YfkFITu7b2hxMuC62PN6SamRJo2zDb3AtfqKYU4JaaLLHOmlLFyh2heoNG
         alfQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=VkTKir8E;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32b as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=5UeZD2Q6M9sE4t5/l34fDz0TtrtOxKpNapy+kU1Q4rk=;
        b=JcKwZbvwJizYbBOfEzXmLXwjRnzK5wpG32Fr3KcsFCoMeTRBpgxIvORWMagVYQR7cC
         /6Ih41LoWB8rjiAljXHa0zJPMUtC32+skBqXZADznmXlFG4znUxkG8gwCEvfVo18JucI
         T0BYZSj8fQnCKOWh0YX9b0MP/ijoq4NoVPewE9tMcH5D8NW1nSx+xJGeGDvdIivduG6w
         U7gCWFmsPZUAhY1LGhMxBrIXyB3euc/0uu907OSDc4YKV1sl5OtG2Go5JHgwLciPRxDN
         oXJ29SX0DwoKH5oGLpFm/K8lYpE/BbHhy4MKQhwtrGWF3vtFYvwYpi6sLAVM7Z+LBj4P
         vgjw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=5UeZD2Q6M9sE4t5/l34fDz0TtrtOxKpNapy+kU1Q4rk=;
        b=nlow1+TIsiwviLikNaMbYIQx4oy/6LWjk+RlISlackRI8CHEUretWANx9Rhsrdlvez
         Ckff/YQNEtZp2G5lcWwv1GmzNI8kD/HSNo66Ns+ymBDwqe5TLJ6C3Ialq7Vv1j+prhg7
         zWoe+7sLGM1fIFk9kEQ31egxpxm6k+CXX8PIAmLpi65j7uREbHuKwBimMfoF8gbKvAWH
         Gpez7BBZ7lNdJGJdBZb1xL/jE0EzUatgo6Q08/Ct/92f6lDCFp4K701Zo5FkeKg9Ph5w
         lzffgfXJeq8VN1XUgnvZY4lOYF0SF+aEMqJfAFpoYFRQgMSAwvfb/KQjJGO4DahgbRHm
         jgDg==
X-Gm-Message-State: AOAM531ty88vjAp5N0r7PhlXLlJtS4iRBqpStTEVFFbe4NuN4ASBiAjo
	rJLVMTXkScJ0lkdo7JcxMYc=
X-Google-Smtp-Source: ABdhPJx3v06OxOLmIk4LycDTV0jp3PCAH9iojszDVHrX8IGcF8T3vt2CNcZ4Z0dWBd9w4iNphV/GUg==
X-Received: by 2002:a9d:2cf:: with SMTP id 73mr7768167otl.314.1626263792412;
        Wed, 14 Jul 2021 04:56:32 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:5903:: with SMTP id n3ls780680oib.6.gmail; Wed, 14 Jul
 2021 04:56:32 -0700 (PDT)
X-Received: by 2002:aca:d406:: with SMTP id l6mr2491593oig.7.1626263792062;
        Wed, 14 Jul 2021 04:56:32 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1626263792; cv=none;
        d=google.com; s=arc-20160816;
        b=FBE766IoRhQYh++IKrr7sY+CzA1uijQwG/CIIHYfhuK8NefrvcUgbPYICe/xmyO77Q
         Ldbje7pmx8JzoLvjtrmmp0rliJRSqQTH6CyOwMdrq2JH86hJu89NYqVjNBiJ6oMZmej2
         uXjE3K1N3vVe14QZ15uKoDtxI1MXrpXQuhmI0QKX6Fci5ZxUDdTn5jBFk0BwNNQrv6Wk
         Vv2pPa3J2w4vDwPPlbZJi+RXnutUARiaE46rklpahTYPcG9YYm9lF/tjt/UilfPTgloj
         B+Sk9UY7pAHZ7llKqzeduQ31EireYBs4EgVNEeqW8tZfqGdr4Y2gVRibzEQYPyA0V5Y3
         +QVg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=9kEHUnMl2y/OZhBEqOnjX/XYWWhDHxeGf8k78fKCVaE=;
        b=rz/H7BtFiKiwl1NsZhhFk8oakq8Id7rn2VdPc88eCrDy7EtOTGus7Ck12lfpG9AXuB
         QMdPizmPOsxWj1l2bj7a1yYbM6UZprSf9EWd5uBC4o91PyIr5qtUq/FE7MmXyVuM0Yee
         FLZHe1o/vBHFE0tTePZhyMUfFUW0bWJLgGPrs4Iq49wAy63d3jOIh9HxGlDQG5wxIyro
         2gv5xNHc08Rn8rAFiDjbe3p24+zbLOA8wml9ciwohe0wfaga4Q8qpUrkRVJn21TrGNzc
         eVaR8sb5MVZf4bS5YiCJ+R6qZuWg/gl71zzsGaBdRniW+QY3L5vkuMyexTN2xixtunMQ
         jXMQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=VkTKir8E;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32b as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x32b.google.com (mail-ot1-x32b.google.com. [2607:f8b0:4864:20::32b])
        by gmr-mx.google.com with ESMTPS id y70si158713oie.3.2021.07.14.04.56.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 14 Jul 2021 04:56:32 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32b as permitted sender) client-ip=2607:f8b0:4864:20::32b;
Received: by mail-ot1-x32b.google.com with SMTP id i12-20020a05683033ecb02903346fa0f74dso2139741otu.10
        for <kasan-dev@googlegroups.com>; Wed, 14 Jul 2021 04:56:32 -0700 (PDT)
X-Received: by 2002:a05:6830:905:: with SMTP id v5mr7884304ott.17.1626263791564;
 Wed, 14 Jul 2021 04:56:31 -0700 (PDT)
MIME-Version: 1.0
References: <20210714113140.2949995-1-o451686892@gmail.com>
In-Reply-To: <20210714113140.2949995-1-o451686892@gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 14 Jul 2021 13:56:20 +0200
Message-ID: <CANpmjNMe+wyuFLJ0nOk-4Sr57GgBf6VuHa3hmsVUZYJ1gjuC5A@mail.gmail.com>
Subject: Re: [PATCH] kfence: defer kfence_test_init to ensure that kunit
 debugfs is created
To: Weizhao Ouyang <o451686892@gmail.com>
Cc: glider@google.com, dvyukov@google.com, akpm@linux-foundation.org, 
	kasan-dev@googlegroups.com, linux-mm@kvack.org, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=VkTKir8E;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32b as
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

On Wed, 14 Jul 2021 at 13:31, Weizhao Ouyang <o451686892@gmail.com> wrote:
> kfence_test_init and kunit_init both use the same level late_initcall,
> which means if kfence_test_init linked ahead of kunit_init,
> kfence_test_init will get a NULL debugfs_rootdir as parent dentry,
> then kfence_test_init and kfence_debugfs_init both create a debugfs
> node named "kfence" under debugfs_mount->mnt_root, and it will throw
> out "debugfs: Directory 'kfence' with parent '/' already present!" with
> EEXIST. So kfence_test_init should be deferred.
>
> Signed-off-by: Weizhao Ouyang <o451686892@gmail.com>

Tested-by: Marco Elver <elver@google.com>

Thank you.

> ---
>  mm/kfence/kfence_test.c | 2 +-
>  1 file changed, 1 insertion(+), 1 deletion(-)
>
> diff --git a/mm/kfence/kfence_test.c b/mm/kfence/kfence_test.c
> index 7f24b9bcb2ec..942cbc16ad26 100644
> --- a/mm/kfence/kfence_test.c
> +++ b/mm/kfence/kfence_test.c
> @@ -852,7 +852,7 @@ static void kfence_test_exit(void)
>         tracepoint_synchronize_unregister();
>  }
>
> -late_initcall(kfence_test_init);
> +late_initcall_sync(kfence_test_init);
>  module_exit(kfence_test_exit);
>
>  MODULE_LICENSE("GPL v2");
> --
> 2.30.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNMe%2BwyuFLJ0nOk-4Sr57GgBf6VuHa3hmsVUZYJ1gjuC5A%40mail.gmail.com.
