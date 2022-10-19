Return-Path: <kasan-dev+bncBDW2JDUY5AORBJNJYGNAMGQEOPWD4YQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3e.google.com (mail-yb1-xb3e.google.com [IPv6:2607:f8b0:4864:20::b3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 1F82C6050B3
	for <lists+kasan-dev@lfdr.de>; Wed, 19 Oct 2022 21:48:55 +0200 (CEST)
Received: by mail-yb1-xb3e.google.com with SMTP id a2-20020a5b0002000000b006b48689da76sf17193765ybp.16
        for <lists+kasan-dev@lfdr.de>; Wed, 19 Oct 2022 12:48:55 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1666208934; cv=pass;
        d=google.com; s=arc-20160816;
        b=Xw26IKqhKwrz6T1EgzelNdkMXmOAs2m6TFbCUEbh6YoQcuAC68BYu5zczWOeLq8HsT
         gQFY9/gwmKCQmfJdfH2MJVBaqmq7Iz8nz4asd+c7VKenckaq5nVFbbQqfytfDrj8FNW0
         jm5t7PiiUyiEyEmD9cFb+hIn4i0lwS7Bx/YSEB5HKGrGtYxLSrxZLKPouZObC1e/GxrF
         d/Pj9oI3XLw9RF+H4ZYeZwePkPrF2894BWv4vxXblNhd3f3byu81Y8U/G07000a47WBe
         NlY6tOgmxQkmBA6sDXmgCoWRBS6wtbhSiIDLV4pMPIvm9HheeAiw+ovHj4Lu+T1EM8lI
         yimA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=LQAyz3pTL+qt+iI4ri/9a/rcrq5omCsMnmwH4+wGKvQ=;
        b=YbV+c+Mh3d780r6RWBEI3Yp3XBB9GiZyvI0B1M7ZwY4ws1cjS+X3kDx6VbowBV6C2X
         sxQE5ysDAKeJtLEXhyHTPcy7eM5i+D5suoGRR6diAIYqUj/xqYIKd7L3v7mmWsvtgD/K
         ENNe2gpyR5btTN4nR2ajDB+pTwTeUcbbWfi38lJWXiB949ER2ztOnvopnDAMKF4v89vx
         1gkAo3pkqSV1gQznJxavT2viclrXUTCIVlH0ryrnMBNIm0Bk9iFr02DViNUmfovo2/G3
         2PpffItdu69y7RPt646LvE9crUnYqoilBAw4pMGUJzXMLm4x0dAfoBgTbZcSkNU2NWvU
         dWZA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=ox4rhvjt;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::72e as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=LQAyz3pTL+qt+iI4ri/9a/rcrq5omCsMnmwH4+wGKvQ=;
        b=WzhtEHPsl6ke5lIn6QinoK3JPSgwanpgNV5ic3KJ7ivhYkUg4KCIx2WnAWffgUeMx7
         yYdPsQpamReZ7DWcKfLgi6+u6tloY5gqBRWahYqjrUudy/+qxPKcLqBkyXqz4BqH4aAj
         yWCq2konxFambhg4q/fJuAdu7y4BWcY9GGKv5bNnHeMyZQlNTivyjjPPSBVziAYDuvqi
         zS3F6mfc6amhJcpQ/gbqzY1ak07atK7nqilR/e8puVpdFmwptEaMMRbPT4JhLiDWq2zF
         FhC34TrH4pFy086Pac59ovVcaKCtdjZMhk9rmLWhy369I4QYmI3/6AbdquWiezpFWjdQ
         afVQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:from:to:cc:subject:date:message-id:reply-to;
        bh=LQAyz3pTL+qt+iI4ri/9a/rcrq5omCsMnmwH4+wGKvQ=;
        b=otoh8yipLMb8qomCeX/+eiRYEJ8sdZLsSWCFmQ0PZdB4uXguHYxHlp1l4U3KhiT/rw
         L9kx3/dL+++dKxOIXqY9af7ckWlu32BHW3TGDUlPNtCIRw2Az9Fa0PquH+s5VoCVb26K
         XZvDvnWgBhzrOoSQIze3rMsIJfYIb5Joggb1WDXuoxzHNHw/V8ZyuswiaMYQqz6OwVYQ
         BmSxVneK3JGxEfzygJYN07tQ6xvYYjfC7vciHtWwitKFls7T9PLSV6zCJUjv6XuAjw7N
         1m5ekokcsE+GhITjxCJRtYdSrEdL/5js5XhrFZN1zTm3jGkIdFUqHwzLGkCyCIfppMtT
         +uxQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=LQAyz3pTL+qt+iI4ri/9a/rcrq5omCsMnmwH4+wGKvQ=;
        b=PNcGQWqXIz+dvZUXKUHs1G/PIfHubKjiSofRyzZVaCV9G3IWAiPipiH/ob/E+1lacM
         oFSjCeQpdUkMUkXmhP79QBj2Sk1cz41+Nt6dT6paSQMvVlAzVwtGbjJReRweIKi8pWbJ
         HqdXZuRYdQNdGS6OcReGGQaJTphpWT7mumqmEeXGDLxpQm9UMJzg4iXZgpveS/BtxpFj
         RkXhvM112uAg964ZnJx2gyJQEDLmIu3XszrxElvdjIXkCjgpyoXsn0caESt32CfcVN1O
         r7j6LwhMZPRcnkelcSwsbaH+qlzkGj+Aom4q2oH07JT4PeHY/O2VD98iP+H5GwJo9JBN
         7geA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf2EqdR9WGwdUFDNEyhy/7NTWaZN2I6uCNbp1GHHCKZY+nt5wc+R
	ex/IXBt6RJp6XdsrFZmbB9Q=
X-Google-Smtp-Source: AMsMyM41CAa/liGAfxj7QleBFfnouBuZmARoJCqYtUPzUz8dD3kgQERZewFVAOIy0AUPDB5A+GispA==
X-Received: by 2002:a05:6902:13cc:b0:6a1:a42f:ec2a with SMTP id y12-20020a05690213cc00b006a1a42fec2amr8663137ybu.215.1666208934036;
        Wed, 19 Oct 2022 12:48:54 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:6903:0:b0:6bd:b0a5:a153 with SMTP id e3-20020a256903000000b006bdb0a5a153ls9239992ybc.1.-pod-prod-gmail;
 Wed, 19 Oct 2022 12:48:53 -0700 (PDT)
X-Received: by 2002:a25:9ac6:0:b0:6ca:d6:15e6 with SMTP id t6-20020a259ac6000000b006ca00d615e6mr2826272ybo.420.1666208933443;
        Wed, 19 Oct 2022 12:48:53 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1666208933; cv=none;
        d=google.com; s=arc-20160816;
        b=qqMh8sjurRNf4aC0RmarR2hb74hsePxQOmtEnxABgwUHr3yQkX27xhfPBJBYSh5CRV
         DfBTKFPWL32LKg54CyTIcw/PaRtFK5sE/+FYs0d6BPMtpMrLhrBKlXI2x8sFzI8DQSfn
         SZpWevsneb6pFexY4sK2WVxeOfbtAnpb2o/lY24o/hBMUKt+aFs6/03dIEGgAN69EgQ2
         xk0+ZkkvdDhxGGRD8pUrR6neLE10dh0sIdoKy849Yy79Pj0ts+TSGHTXKMo9cxdh+zkJ
         HoAx1E6rAxpLq9sBogdTHsgIADEqIwuvcpQvhA2wP8+2z3kjjOX2uSvQQJGGH6Gsoa+H
         D0Pg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=cXqWYGSUyr7OrNHL1T/x/7EkjfHttBM4QCa4eRu5CdE=;
        b=pdWx44c9kBk/4KaIb5hPi1R7268q8AipvvfQwPXBdLy65biMY8MDsS6ODkxeTy3XOY
         fnsiMUscEvFlOWvt9xyuBcGGPxnSBVyCgiqHPC3S26QbHUaJm80Im5cP0ASK74TB+S5l
         U866TxQtaXFQItb4V7I9G5TGXOJGzaf50cMayhtqFHlxzGUu0qSjMQaU3rLnBl1vhx2v
         LYZ+rsR9sQ+NRWZ/zmVwh9z+wRWPbMCwynbsWek9sUeU7asNUTzT32H5dye+HJgg3aVs
         DIfmDCTDTaR8I/XbqYuX5VE4ZRmEjnFmumuH+EnFGVJCGtEt3ie1Kn/jWYUxY7TJOz34
         6inA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=ox4rhvjt;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::72e as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-qk1-x72e.google.com (mail-qk1-x72e.google.com. [2607:f8b0:4864:20::72e])
        by gmr-mx.google.com with ESMTPS id s187-20020a2577c4000000b006be3d17ff2asi1045914ybc.1.2022.10.19.12.48.53
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 19 Oct 2022 12:48:53 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::72e as permitted sender) client-ip=2607:f8b0:4864:20::72e;
Received: by mail-qk1-x72e.google.com with SMTP id j21so11433805qkk.9;
        Wed, 19 Oct 2022 12:48:53 -0700 (PDT)
X-Received: by 2002:a05:620a:d94:b0:6bc:5a8c:3168 with SMTP id
 q20-20020a05620a0d9400b006bc5a8c3168mr6743224qkl.56.1666208933104; Wed, 19
 Oct 2022 12:48:53 -0700 (PDT)
MIME-Version: 1.0
References: <20221019085747.3810920-1-davidgow@google.com> <CA+fCnZdPwjThjY7fd7vBkMzS1eFXySR2AKrDK8weJ3p25fzS3g@mail.gmail.com>
 <CABVgOSmP1A4d_-SNrWg7VruxpKj3SZz=Bzb2Xebd=EXw1imXyA@mail.gmail.com>
In-Reply-To: <CABVgOSmP1A4d_-SNrWg7VruxpKj3SZz=Bzb2Xebd=EXw1imXyA@mail.gmail.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Wed, 19 Oct 2022 21:48:42 +0200
Message-ID: <CA+fCnZcea7UrA11HyRB80WgrUXMtEkK0AjdxEN=H-pMuWBhQyQ@mail.gmail.com>
Subject: Re: [PATCH] kasan: Enable KUnit integration whenever CONFIG_KUNIT is enabled
To: David Gow <davidgow@google.com>
Cc: Andrey Konovalov <andreyknvl@google.com>, Alexander Potapenko <glider@google.com>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	kasan-dev@googlegroups.com, linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Daniel Latypov <dlatypov@google.com>, Brendan Higgins <brendanhiggins@google.com>, 
	linux-kselftest@vger.kernel.org, kunit-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=ox4rhvjt;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::72e
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Wed, Oct 19, 2022 at 5:06 PM David Gow <davidgow@google.com> wrote:
>
> > How does KUnit detect a KASAN failure for other tests than the KASAN
> > ones? I thought this was only implemented for KASAN tests. At least, I
> > don't see any code querying kunit_kasan_status outside of KASAN tests.
>
> Yeah, there aren't any other tests which set up a "kasan_status"
> resource to expect specific failures, but we still want the fallback
> call to kunit_set_failure() so that any test which causes a KASAN
> report will fail:
> https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/mm/kasan/report.c#n130

Ah, right. Thanks for the explanation!

> > I'm currently switching KASAN tests from using KUnit resources to
> > console tracepoints [1], and those patches will be in conflict with
> > yours.
>
> Ah, sorry -- I'd seen these go past, and totally forgot about them! I
> think all we really want to keep is the ability to fail tests if a
> KASAN report occurs. The tricky bit is then disabling that for the
> KASAN tests, so that they can have "expected" failures.

I wonder what's the best solution to support this, assuming KASAN
tests are switched to using tracepoints... I guess we could still keep
the per-task KUnit flag, and only use it for non-KASAN tests. However,
they will still suffer from the same issue tracepoints solve for KASAN
tests: if a bug is triggered in a context other than the current task,
the test will succeed.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZcea7UrA11HyRB80WgrUXMtEkK0AjdxEN%3DH-pMuWBhQyQ%40mail.gmail.com.
