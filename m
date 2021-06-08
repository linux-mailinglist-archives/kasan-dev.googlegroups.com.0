Return-Path: <kasan-dev+bncBCA2BG6MWAHBBWV776CQMGQEMBD23WY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3d.google.com (mail-yb1-xb3d.google.com [IPv6:2607:f8b0:4864:20::b3d])
	by mail.lfdr.de (Postfix) with ESMTPS id C1F1E3A05AC
	for <lists+kasan-dev@lfdr.de>; Tue,  8 Jun 2021 23:23:39 +0200 (CEST)
Received: by mail-yb1-xb3d.google.com with SMTP id m194-20020a2526cb0000b02905375d41acd7sf28636947ybm.22
        for <lists+kasan-dev@lfdr.de>; Tue, 08 Jun 2021 14:23:39 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1623187419; cv=pass;
        d=google.com; s=arc-20160816;
        b=n/F2k1227IEDnXCH7vOJy45e4CufyMfj5ICk1J4/4QroC4xlYVrCpCSXNK+8guCE+L
         jjn3uSJgKGYw+Vw4Mhj6Mg8P64CPJAi4Ikf9s5C9LYFG9K1V3RPoZ4WSdYqgqloTLKAO
         jUg0Bs03CPUL4DW9frLg81ioPRxT6oiQl1pEhV+2kmNIHZUZfYkGZBab+ReQCCKDhYGv
         Od0+2QINdl2rpc9zjlQMS0V5NpTluK1HGGIBZ+kOB13mvOY+gUvABj9CnZO3eCNppY8J
         8l7OJbFUpKQu1JXl8wOWjfdx1EW8v4fz7X8QvXB3UCl9Lg13gwPUey7H58KyZ5ao3Xn1
         GRxw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=tLbSZ1XxjQxnfE+UxIC8epTgXJcUZF6hVZRl4VPj2Zc=;
        b=b+OHD7REoDmvevTdIwqOUShI2H9Qqx/pNfv+Vc1EfWq7GXyoBaSErk14dm6JXWb0b1
         g7I4/8A/3nhTqNrTBgodPaJDG8LGjBo/HIwUhBjOUsXUVvrGgt/DYmOGk9J4J6I1dY4C
         uKWQs0S26/jfTyPRjp1RqsDniCFErtkowYszr9ewLd9lJmsQh6tlltKwYN5cZe0S6KY5
         EY5LYBjPcKmmKoGIQXfDNdLN4lZLvaMZpaWwe23sfzM7lgTyBpdK67PeEnaD3jPv0Cmh
         shsoA/qzcbRG9wiQeqVgRd1dZpd8xi3K4oAHzkGDNiAnyukAOn1DVaat5GOeALkksOF0
         uY5Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=TkmNukdd;
       spf=pass (google.com: domain of brendanhiggins@google.com designates 2607:f8b0:4864:20::529 as permitted sender) smtp.mailfrom=brendanhiggins@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=tLbSZ1XxjQxnfE+UxIC8epTgXJcUZF6hVZRl4VPj2Zc=;
        b=h5Vg1BBtvkPXk/QNopmkFXX2/yyFl+6UaIt51WJCBodD5pO/KkLMx4qdsRxYl1u1QO
         z3BswmyXYJES8FmsKb+qgvGokzDVFMBH/fI65XsFMUC7rHSr7sMlkvRuYr1kKCx0x+uK
         sP9+kwplEbenkqiihw1/BSsKUvPW1eUiz4a6bBO96TNg6T9ydm1Mx5es2f2P7U1TK8+U
         yL0wEbsdeBN4yUV4t0Zvtmf0lM1o9JPq2CeiDDulkaeQET+leu6DIzH1S7jqMOCJ2TXU
         XpkBOhl2FXWUsBXYDjsvBv/bbYuztE2WTet828Coz4tWDw9FY/mTHj2oQOcZoZTn23O8
         Otnw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=tLbSZ1XxjQxnfE+UxIC8epTgXJcUZF6hVZRl4VPj2Zc=;
        b=a+qSwYNrxX3gxcpQU66kaEsX9Lyec660tjHVjPvUpV9CAW5RygLASYHXqTafYMq19k
         KKTweKPkIjVWzZfZNKd0KhI+B4SFBJHpjux0ryy/DChaYyd4dlVJL8BvVhBHdG4aw89u
         1EKQp+Cj4qmnTqjYwJrBgdv7wjfbabPL4NzQVE5Ph0X0vyqH1BZv1NSMmcGXbKSnf9b9
         3jqBDLcK56i0kKVODVdTQognZRNKzQHZmJyxhHaaS6eGCGAvvbiutY/s/TWJLg2ymDSu
         dpXps9iGZge7VJbHLHjIRlcoZk7iBpJlJANqmJLqfqab858NHCrDvYJQxaP7uMlpX+XH
         knGg==
X-Gm-Message-State: AOAM530qKX71g2+oi1/4jTc58acuLQeEqW95xZpcl5LojH3eybPHkeeP
	F11OrY9b2P0n80WsYpkVKCA=
X-Google-Smtp-Source: ABdhPJzQnBRjtXv2M09n2e1rhADpuHMsXhFfrJMwqtDwxIKtDAt9hcJtDCeaD8KZWHICLSpzMwgxTg==
X-Received: by 2002:a25:1988:: with SMTP id 130mr36759719ybz.458.1623187418808;
        Tue, 08 Jun 2021 14:23:38 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:3c6:: with SMTP id 189ls147433ybd.8.gmail; Tue, 08 Jun
 2021 14:23:38 -0700 (PDT)
X-Received: by 2002:a25:1988:: with SMTP id 130mr36759683ybz.458.1623187418420;
        Tue, 08 Jun 2021 14:23:38 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1623187418; cv=none;
        d=google.com; s=arc-20160816;
        b=RV/4QANFyYrlKMdf6dcoyVSdVRVFQul44WQWI51cvf8zsNzWZgyuLcB87i+9O/4hb8
         9T14qqccj0ZSApFkj+roIUresTxF27OHX7xxSDedX694nVBeI+gLc2vUbjytULG5l65h
         d1XeTa0lI3ThRyoV6kiljUWGcHjScSCOhusuEgK18/9k6PbqDDkgTfeIZr/5Q2Y9IcnL
         eUhCPYO09o3yfYRS01leNhzRGfNxS+O/9M4mWPU4+QQPjPxEKwFIYSLnQAKR2SIHlZ0K
         b8apiOuGNUzHMNSP7IBQYCexGQihxtm4RFIhrMBSfDQ8EdUF1MA8HYd6twPyN/FP/tZ9
         1KdA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=fwY6vzlCqExbU7ohOZltUzd/GYI1ox+DIPkINKqAaqw=;
        b=FF9fBr1YT5Fo3DRXrwQGAlQSJINAQjZhFmtR5bnCdbz+ywOu+DL2GAP4XPFCOS4Jul
         Di8ilBUqu1qdkAz2EDa1Np8knBiHJH7uQyoq6qXHSGOqLVSFsAtlQX3T1FOwGpU5VVfC
         ZBe6fEnWmSseciL6LC6JQu0AZ6q+ivtVR3UJJ4bPsWLe69xvRQAPt/Sk1894MXEt0j5a
         bNd+p4Xjv5l0dvWRAmroGv2e7o038rCAHogFsRuozkPzC2nLbZhM4tu1jqobyMCSnYfV
         bkn2//ThE+wMTHcqwLdCEKdB1U7F4fQ5CaFW/pwXR14qgREqnowQ6UC3A/b7XgCTb0+c
         5cuQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=TkmNukdd;
       spf=pass (google.com: domain of brendanhiggins@google.com designates 2607:f8b0:4864:20::529 as permitted sender) smtp.mailfrom=brendanhiggins@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pg1-x529.google.com (mail-pg1-x529.google.com. [2607:f8b0:4864:20::529])
        by gmr-mx.google.com with ESMTPS id r9si2418137ybb.1.2021.06.08.14.23.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 08 Jun 2021 14:23:38 -0700 (PDT)
Received-SPF: pass (google.com: domain of brendanhiggins@google.com designates 2607:f8b0:4864:20::529 as permitted sender) client-ip=2607:f8b0:4864:20::529;
Received: by mail-pg1-x529.google.com with SMTP id o9so14775836pgd.2
        for <kasan-dev@googlegroups.com>; Tue, 08 Jun 2021 14:23:38 -0700 (PDT)
X-Received: by 2002:a05:6a00:1893:b029:2ec:a754:570e with SMTP id
 x19-20020a056a001893b02902eca754570emr1708673pfh.38.1623187417561; Tue, 08
 Jun 2021 14:23:37 -0700 (PDT)
MIME-Version: 1.0
References: <20210608064852.609327-1-davidgow@google.com> <20210608065128.610640-1-davidgow@google.com>
In-Reply-To: <20210608065128.610640-1-davidgow@google.com>
From: "'Brendan Higgins' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 8 Jun 2021 14:23:26 -0700
Message-ID: <CAFd5g441kq9KsmeFr_OgbexShN-rJRzrh97kxxYRmC7Yvt+g-w@mail.gmail.com>
Subject: Re: [PATCH v3 4/4] kasan: test: make use of kunit_skip()
To: David Gow <davidgow@google.com>
Cc: Alan Maguire <alan.maguire@oracle.com>, Marco Elver <elver@google.com>, 
	Daniel Latypov <dlatypov@google.com>, Shuah Khan <skhan@linuxfoundation.org>, 
	KUnit Development <kunit-dev@googlegroups.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	"open list:KERNEL SELFTEST FRAMEWORK" <linux-kselftest@vger.kernel.org>, 
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>, Andrey Konovalov <andreyknvl@gmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: brendanhiggins@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=TkmNukdd;       spf=pass
 (google.com: domain of brendanhiggins@google.com designates
 2607:f8b0:4864:20::529 as permitted sender) smtp.mailfrom=brendanhiggins@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Brendan Higgins <brendanhiggins@google.com>
Reply-To: Brendan Higgins <brendanhiggins@google.com>
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

On Mon, Jun 7, 2021 at 11:51 PM David Gow <davidgow@google.com> wrote:
>
> From: Marco Elver <elver@google.com>
>
> Make use of the recently added kunit_skip() to skip tests, as it permits
> TAP parsers to recognize if a test was deliberately skipped.
>
> Signed-off-by: Marco Elver <elver@google.com>
> Signed-off-by: David Gow <davidgow@google.com>
> Reviewed-by: Daniel Latypov <dlatypov@google.com>
> Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>

Reviewed-by: Brendan Higgins <brendanhiggins@google.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAFd5g441kq9KsmeFr_OgbexShN-rJRzrh97kxxYRmC7Yvt%2Bg-w%40mail.gmail.com.
