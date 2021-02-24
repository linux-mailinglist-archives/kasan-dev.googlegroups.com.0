Return-Path: <kasan-dev+bncBCT4XGV33UIBBIFH3GAQMGQEDZAHEEA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103a.google.com (mail-pj1-x103a.google.com [IPv6:2607:f8b0:4864:20::103a])
	by mail.lfdr.de (Postfix) with ESMTPS id 2BFE3323DEF
	for <lists+kasan-dev@lfdr.de>; Wed, 24 Feb 2021 14:24:50 +0100 (CET)
Received: by mail-pj1-x103a.google.com with SMTP id oc2sf1948887pjb.5
        for <lists+kasan-dev@lfdr.de>; Wed, 24 Feb 2021 05:24:50 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1614173089; cv=pass;
        d=google.com; s=arc-20160816;
        b=hRiVX2ShF6i+nJcIlSU4jPUTmtlU4GIWBmgcVIgb4Hp/owrKYUOn5igdfWFPUnSBjr
         up6oe6x4mhzKcfxrcWi2gNjas2zgW1A+3e1+lt7njsGoHdZpDukkxTyoEXsgiRGmcIrq
         e38u7Po2BTqd++ci1tA0TutxH+C9r0vppkM1ZjTVhN4HHHGKWCgeGQQH9OGMfY4qMJe0
         E13ALUkjSwakzoiCotfGIJo9PudA4bL3P0nv+ExgR7aulwd15dZya6VoWrtqct68crVo
         ZTb4Yp2tuJ5PKOCi21oN2al9IAgpXRbtqIML1QzjhmI9CLTptGDK+f2imhIvLC+50BND
         uYDQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=G1Gz3A6Kcmj4aH2SgQRzC8MNtyo0Qty9EF6rPCdDv3E=;
        b=ROdu2PGLWe0lTNo0H0XZV4GKzpLh9uc6zIqOuN4KIG25+bjQBq4dHm+cWa8nJ2LX3l
         bVphY5whqPuNfdx68zbC4fIWWd1ExkE7fc9+ahZQFpA/7FhfQ1hPqP64KqKSJGwANOow
         dJvYnk2NVL0CE2nYr5rKSdIw6xrKjS7+BfOi1qmuGJhBbToPB6FExuen5qrTrv6o6tbJ
         79x06Hqv9PLOrzNZ8mqOOnpPtvRinf66Fbon3LntJlFluLzScgAh0YVT564IQMr8llzw
         0d0EiwXtVQh4JY4rqfCQ0wcaMy/hBn8BRTdWyQrdNoRuFhx/gaqfxyaxq1VZOzwFpwHd
         mx/g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=y5XGl0eo;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=G1Gz3A6Kcmj4aH2SgQRzC8MNtyo0Qty9EF6rPCdDv3E=;
        b=Vve0tUKDMjCcaK8q2ccUg3dK13i9y8yoM1tPs/ErHnTS1KSDnoNlpVRkgICiFjgNpZ
         m+FAkRNFgTz6vEoswgkAKz9/T2qoORRhO0sCYA16jw92arsWlBJkOM24Bl/16rvxA/1g
         rdoI6a6LZ9FYqjiWpO7DRyyFJ6JAdyYdHgZhYGnBJnjJ30O4v+r6X0Nm9yFL/iDWVDKu
         1/HzsPeBh1tL8LQqmi8CM/T//Sci4h+m2BddGvRSOQpJxHS65eDyJmaa+Fb5IBReEz+h
         jczUFGWYV5LShriJnDoUSNeSeEEaHxzNnCmu4tXFJgI8eVyqVMCykNcZi83ytZZZdp4n
         5u+g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=G1Gz3A6Kcmj4aH2SgQRzC8MNtyo0Qty9EF6rPCdDv3E=;
        b=QMtVtyeTQX2Z0FXHmu5ZjswT5TDEGzYUoVyPIT/oKxJwpFnXmYRuUESHLN5Xe8n3Hm
         vJyZjXCQAazSBACer0aFFsG7MamWf9VYhwalOMFVqRH575hRO/I3lno+jr4QTqEujj0L
         9HafMGECKCPLDX27qpaJ1GvDIGw6uF9Un410sbQGE7lC8+nuVwhEdd614D2TDlO16WKo
         FsIhL4TaqZoTs22det/OIMBBwRMJNVSQ5BXCbbwosTETWIKzgrXHFkVRhwhjht4lvmnw
         qmFAqU3kaWbw3qyfj0xNr9cCdH4GnZmp/7jw46/+4GGvrU7BplGnXaFPHtxY88mIe1Gn
         kb1w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533noCSPCimpPa5tVBwQoYSZqiQgKDbmormYC4MxS1dwT+Bqbb9o
	3GgnYsoJHyNthhofGl/Tu/8=
X-Google-Smtp-Source: ABdhPJzkiBMwZRI18qvy9SalRpwuKmji3v7NteMmHITXc/rd4thcYIAPaGAuhJq0I2v8jiWCphjcGg==
X-Received: by 2002:a05:6a00:1a46:b029:1d5:9acd:798c with SMTP id h6-20020a056a001a46b02901d59acd798cmr7322243pfv.25.1614173088845;
        Wed, 24 Feb 2021 05:24:48 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:1790:: with SMTP id 138ls752265pfx.5.gmail; Wed, 24 Feb
 2021 05:24:48 -0800 (PST)
X-Received: by 2002:a63:f921:: with SMTP id h33mr15893231pgi.419.1614173088170;
        Wed, 24 Feb 2021 05:24:48 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1614173088; cv=none;
        d=google.com; s=arc-20160816;
        b=DsSJSRuh8wYiIAet3DRdOznqPyaeFLuTzfrxXLT7tGLxxTK4Z9f3MWx6tcjT4KCIE9
         r9DAWpEeCQfb/ufmyB3hOKHeoG7QXr4yAqKB320GkUCeb4KwvsEQZnvKSfi5OQLZDs3g
         LB1vP9GgwHy3m+1H2dewS6fFBz23H6amu1wrKEwFokInogUtZ59yY+tGwm5WBiajUswD
         sG4qiGCuqEtpRKENsqJEiGLOqGf5DeAD5Agh+OAjRvdHlkmC1q6cGm3JzK3arbY+oMj8
         g+jgEdQh90IvLz2q3FTdPwxDZLvgSLyCa/8kNLY7AwxHMwk+RvBX6YNRb53J3Pkcvbrs
         iBAA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=Wmxu3reOQwAi3u/fr5ZVcgUNjSRp8lDsu3DHunBruBM=;
        b=tUA5d9FH2g4qsgUWAZmcLf5n/KXVf77O05cQFhQd65ed65pjrhe6vqmEn2phzSn0Qh
         Q6qUtnwBweIg9OCPnd6LQxgmpiQkbLQhIZpTrRAZzFyQVxCBpGjB8+OLKQpsMRRNw+n6
         umDUP4bz/eWJfgTeyA17VB8oi1wldQZOXtkS6Q64ZduPCmFipz3SftRUFKieToe1Nk5Q
         D3mK9TNmpV0eeDQzMTsL5rzTv4U32oTLP6eRsMkMVOlkBWk1N2n6pJHQSUQ4OeVkgk5F
         +bRysRhLBp0rJ+QLr7RWTqTDc1wGVgm+HnnWsKqXZUxGFZQ9oNsLWxMQfCUUUca4OH8u
         bD4g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=y5XGl0eo;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id f11si88425plo.4.2021.02.24.05.24.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 24 Feb 2021 05:24:48 -0800 (PST)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 50CC364E02;
	Wed, 24 Feb 2021 13:24:47 +0000 (UTC)
Date: Wed, 24 Feb 2021 05:24:46 -0800
From: Andrew Morton <akpm@linux-foundation.org>
To: Marco Elver <elver@google.com>
Cc: Andrey Konovalov <andreyknvl@google.com>, Dmitry Vyukov
 <dvyukov@google.com>, Alexander Potapenko <glider@google.com>, kasan-dev
 <kasan-dev@googlegroups.com>
Subject: Re: [patch 21/78] kasan: split out shadow.c from common.c
Message-Id: <20210224052446.937f0b5314beaf658d579089@linux-foundation.org>
In-Reply-To: <CANpmjNO0ODGVfH2Vbeu-gY=6CuAGSE=O3MKe96QX_-N0qZ+G-Q@mail.gmail.com>
References: <20201218140046.497484741326828e5b5d46ec@linux-foundation.org>
	<20201218220233.pgX0nYYVt%akpm@linux-foundation.org>
	<X91JLZhrXYaLzoB8@elver.google.com>
	<20201218171327.180140338d183b41a962742d@linux-foundation.org>
	<CANpmjNO0ODGVfH2Vbeu-gY=6CuAGSE=O3MKe96QX_-N0qZ+G-Q@mail.gmail.com>
X-Mailer: Sylpheed 3.5.1 (GTK+ 2.24.31; x86_64-pc-linux-gnu)
Mime-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b=y5XGl0eo;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates
 198.145.29.99 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
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

On Wed, 24 Feb 2021 14:19:38 +0100 Marco Elver <elver@google.com> wrote:

> Hi Andrew,
> 
> On Sat, 19 Dec 2020 at 02:13, Andrew Morton <akpm@linux-foundation.org> wrote:
> [...]
> > Yes, kfence came in fairly late and seems a bit fresh.  I was planning
> > on holding it off until next cycle.
> 
> We were wondering if KFENCE will be sent for 5.12. If there is
> anything we can help with, or help clarify, please do let us know.
> 

Yes, I plan to send kfence to Linus this time.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210224052446.937f0b5314beaf658d579089%40linux-foundation.org.
