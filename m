Return-Path: <kasan-dev+bncBCCMH5WKTMGRBXFW6X7QKGQEYAI4ARY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3b.google.com (mail-qv1-xf3b.google.com [IPv6:2607:f8b0:4864:20::f3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 1608B2F29D7
	for <lists+kasan-dev@lfdr.de>; Tue, 12 Jan 2021 09:18:37 +0100 (CET)
Received: by mail-qv1-xf3b.google.com with SMTP id l7sf1012721qvp.15
        for <lists+kasan-dev@lfdr.de>; Tue, 12 Jan 2021 00:18:37 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610439516; cv=pass;
        d=google.com; s=arc-20160816;
        b=Egyv4R6I7bZdATYaO38Ru+CNTDxq52L3G4nhowX0LCJ2gUbf2NMfzIT4SVDrf9XyNt
         OK8L95WEPZWEgibfV4CQZ1W4+cBmtJZNgaisZxeXPfO5zizwDiXSlLpIPeTIOnm3Xmqw
         JqBv0W8PSKFUNvC9vax0QDzrqcGpi6HJzl26xge8bYmM8f98P93H20bdXNUooPjO+Zg6
         /sOm7rsUylog5RqORYeNbMtiQ2EUGi+wzCvbwun6rKNeEYEkd0ulNj9Pc3WjSquJYQhr
         3eb6D18xGQMZXO5woepZlBPjV9Y7rA9nqdjBg1lH+RmgJUbb3Cjg+l0t8rdT6X95RXaJ
         D7Gw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=jgRQ2Vhp0S62t2ypE8LJ0ZyV29vk4AOi+twlB6ECO8E=;
        b=WDumnISM3hSh08Lw03lAxkHkU+V7FxRLztdxNgB0GsAKb+CxYwy4RkYSpHx0s3h1GC
         +TIDUEkBgjGE5TwHBPuCFY5n5/C7WK2RgD3bMDcg3hmZ4humD7feLyXXdZHAdAqqKCv6
         Wp5h3r6UebpD3vrNNc8FykRpR7UpkBrMWjA7pAYaCgqVS58I9V2shZ86aXAWKu7xtUvI
         vDSRfmT0skhVHQZI2NUWGPis63cjbQx/DacOH6TuFPeQYM2ygwq14+nPT2/CHnltvrNM
         SSHZ27kJCUwEtna0wq74rjl9d0oCgiHvjm/JCnNZ3FvFbQIUNIH+HZUK+HCQzaxnBRvb
         9cUA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=vUtmN33h;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::82a as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=jgRQ2Vhp0S62t2ypE8LJ0ZyV29vk4AOi+twlB6ECO8E=;
        b=RdMY8XdP10zcfre/+dvfMch2XcXNP/zxUgT+gDjch9tGVfk0RpsO0llekdCLXt2Pbz
         Jfa5d0zqxX1M9crHOU/JSYWjlEzTO4jFWk+3wXqzRtnSdrTecD03XUzW6NselIC29Rck
         wy0BSsC9xBxsg/6tXHoUPlmZX8Hiwp3xK2VlQaHPHOZbwI+pG29FAKP2RDN3Hg2i1uRN
         b4NjIT5Ak4VRn2p01AcNIxi0zvp3dB8OXpI54V8hgqjdVIvhJAXRzFyrO3BnE76dW6NU
         L7evi0Tth0vv6uofAKe5d4H4JfcNUPiXkdCnfuAdlnLbkrSF283Ceatx4WI96XGcadEA
         HoKA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=jgRQ2Vhp0S62t2ypE8LJ0ZyV29vk4AOi+twlB6ECO8E=;
        b=R4uaw/isYOZ6mdW30KPzwaXPBsfMehj5K2H3ppC3fC+EDBm07+SEOa5M/GM7tYjgV/
         KRXHqI8OJOCfoeDM5K9Mo2i1QOG5pPRLgr2YbUPKmrYybk0w7ju8kJ84sPkJ/zxGViJ3
         yzlWGhA7XLHw2cmBQ66KSjZX6sPdyX5Z7zLK64irfZXjHFCDx3XwGTUfIfQ7datMrpt5
         gM5CpEdp5VOA/lJyOtZs4/yorBEPMGHRIfXgH/u1Crl2WBF5j+3h3/6MxrgB15b0fH+J
         5/2+80QD32bJnEsneDEtAnY5qVqMa4y7s5SxGS17Jhgg2V6uceVImkuQyoPkfl7XXpwI
         dpvg==
X-Gm-Message-State: AOAM531TPS6jk1SoMA/7zv2cZz8k9cvRKIMJV2BxpQrL+klYzleiigWK
	X6V6PIHXskC5yQ5kJPSfUQk=
X-Google-Smtp-Source: ABdhPJyUklqVEmEDNZ1Z9zXKSogMe0wPe6nukPYGA67qCBxQlka548K/uSxHEPgz3HoX+Zje8RWtJw==
X-Received: by 2002:ac8:758a:: with SMTP id s10mr3434660qtq.40.1610439516171;
        Tue, 12 Jan 2021 00:18:36 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:3824:: with SMTP id q33ls902263qtb.2.gmail; Tue, 12 Jan
 2021 00:18:35 -0800 (PST)
X-Received: by 2002:ac8:71d9:: with SMTP id i25mr3441480qtp.89.1610439515772;
        Tue, 12 Jan 2021 00:18:35 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610439515; cv=none;
        d=google.com; s=arc-20160816;
        b=ZF7k+a1TnG7KIXZgWf5kmLoOwVX/fDPo5iknmFP6++A/3woaj2eOVMWpAXxSKx2m60
         6wqRmXMwQf3VhpoO5ckJIKpjzX/iwnhbxuoTvZTTgiAratNNf1kP2iMGf2UgBOfw1Iu9
         FkxgRm+cDMLeJ3D5yg/c2MnwqkQ5LKp0P1WWQ8znHG66nF/BEpk8JBZlKjBtjCOXEtLC
         l/yq9VntbLK1Jf0IIn18biyQY0AeT61BDstdmKMNHxVfCumYcRAP661irmqhrXV0xUR1
         k7CartINT7PZu3zZaP7tOnbHfaMOItMTJ166egp79sVaTsZ2KGAtzuVorktpUEH36xyz
         SE2Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=2O4oVCcY5rd2IeP/z10VBhkIJpOFPjzFWez+q+L4HJw=;
        b=jWzOyToCc7htqF2Z3RSNyrjsuldgmQVsyYGCmfYD8vuwGfq/JJ2OgjJCqH/YNTZGZv
         sr2Zx183nm1+oGPlkyo/ywKxgFKsPGiM9JqNSldZCt7R1Q6KWmlnh5iwuSNwYcA79NFx
         aqhuDGhLpW3WFn2O4WPfXj+SztisapTu+Eh5v/r9XyamtE7JKqcXkqjuh9UgvzBjM0Ju
         fOkcYH5XfRUtGi4AerG9MJekggAg9wsw3eFCofAA9r86zGcDPpjfFopr146R3lmw3Ye+
         tuNio5rhpe2oCG8380Iwq2APL+Nhu9jtx9K6eDfT5AcbGiKIpXiVhJbuZbKl0LqEcb5R
         83wQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=vUtmN33h;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::82a as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x82a.google.com (mail-qt1-x82a.google.com. [2607:f8b0:4864:20::82a])
        by gmr-mx.google.com with ESMTPS id n20si137740qta.1.2021.01.12.00.18.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 12 Jan 2021 00:18:35 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::82a as permitted sender) client-ip=2607:f8b0:4864:20::82a;
Received: by mail-qt1-x82a.google.com with SMTP id a6so1056214qtw.6
        for <kasan-dev@googlegroups.com>; Tue, 12 Jan 2021 00:18:35 -0800 (PST)
X-Received: by 2002:ac8:7512:: with SMTP id u18mr3452445qtq.300.1610439515331;
 Tue, 12 Jan 2021 00:18:35 -0800 (PST)
MIME-Version: 1.0
References: <cover.1609871239.git.andreyknvl@google.com> <a37dab02f89ad93cc986a87866da74fb8be1850d.1609871239.git.andreyknvl@google.com>
In-Reply-To: <a37dab02f89ad93cc986a87866da74fb8be1850d.1609871239.git.andreyknvl@google.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 12 Jan 2021 09:18:24 +0100
Message-ID: <CAG_fn=Uqp6dt5VGF8Dt6FeQzDgcEbVY8fs+5+wyMp2d1Z98sEw@mail.gmail.com>
Subject: Re: [PATCH 07/11] kasan: add compiler barriers to KUNIT_EXPECT_KASAN_FAIL
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Marco Elver <elver@google.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Will Deacon <will.deacon@arm.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Evgenii Stepanov <eugenis@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=vUtmN33h;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::82a as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

On Tue, Jan 5, 2021 at 7:28 PM Andrey Konovalov <andreyknvl@google.com> wrote:
>
> It might not be obvious to the compiler that the expression must be
> executed between writing and reading to fail_data. In this case, the
> compiler might reorder or optimize away some of the accesses, and
> the tests will fail.

Have you seen this happen in practice?
Are these accesses to fail_data that are optimized (in which case we
could make it volatile), or some part of the expression?
Note that compiler barriers won't probably help against removing
memory accesses, they only prevent reordering.

> +       barrier();                                              \
>         expression;                                             \
> +       barrier();                                              \

The need for barriers is not obvious to the reader, so a comment in
the code clarifying that would be nice.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAG_fn%3DUqp6dt5VGF8Dt6FeQzDgcEbVY8fs%2B5%2BwyMp2d1Z98sEw%40mail.gmail.com.
