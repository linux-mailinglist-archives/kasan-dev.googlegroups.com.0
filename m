Return-Path: <kasan-dev+bncBCT4XGV33UIBBKNUVT6QKGQEUOOCRBA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd40.google.com (mail-io1-xd40.google.com [IPv6:2607:f8b0:4864:20::d40])
	by mail.lfdr.de (Postfix) with ESMTPS id B98772AE3C1
	for <lists+kasan-dev@lfdr.de>; Tue, 10 Nov 2020 23:54:34 +0100 (CET)
Received: by mail-io1-xd40.google.com with SMTP id q126sf97480iof.3
        for <lists+kasan-dev@lfdr.de>; Tue, 10 Nov 2020 14:54:34 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605048873; cv=pass;
        d=google.com; s=arc-20160816;
        b=ENdiJLw4LI3AyAGjjtkI5iXxS9odrHv1k7LH23O1JcZkOL/CNMWkKiCdKYTfJV2LLh
         uBWAAKJiuexZpTeFGJDHa7ZmAq2KPD8K9aJeGodeWnmUghtCBxaNX0LG16cW3gKWXlh6
         H1YLqITXqv8oao2L/2xasg96ZOAtXaWaT6GzSPixIQMKA1XtAYXAoUW6k2q5Eh9jZFzm
         gN+TkSR30Rzg0/Or5gk1CbiRaslkUJjf6RAVlvIF6scWDI9Raocn8O/eJ9GfrCQb+4rP
         kceWkXD8w9PEeJmOMtrdww+Q3BfQRNTP2z9BZ34daS1Oxb03Q8Gfy/mNKzMy/ngFiSQf
         E8vg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=YMTWgb9+jKmc5PNEABUhu3ImgIjK+bN4frfgBDd4LE4=;
        b=V5ByZOvi4nFYeYNUEKTwPO+FpnapQX6HZZ1ohipDQPA5cINYViAJPGeUjg4snifTvb
         et6/JATWe84bCk7B5IddzSXDcS5vBJbG4n4ctU0PDl3UrLvZYXx81GM1JO2Qr7QQK+47
         3MJgtCHTXkd/3OpuRzjUVUSjmhaC1KWauo7vg817lbPUK995kAsXtmogpT+McIO7XNQm
         EmgygpugxGU5kZGpAuOuRMPWmRTsC1k7etoYShusKKsHZdKyWemWmw+kyeymP6A/zYpJ
         Ikkv4D3kyjOYswrT8WOpx+mzLzezI1k3hFlGiUSh3qZmxaxZwzGx3YkVpooUPoXGiERS
         VBXw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=PMMtGRTi;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=YMTWgb9+jKmc5PNEABUhu3ImgIjK+bN4frfgBDd4LE4=;
        b=D/sbRbq57jiqe0v6vIXh8f+lNmhHJbH4ywBGovVJHDw5LUWr5eWSAc8dH9Ec6ETf2c
         LOux3jaD1viUnj+kxIM0ApGSSLPRUqLGLC2Eiz8FCElyoJ+KNcSZG5+mTlK6DRB0t+/u
         LfPwVgYAwM17Gmh7GrQKk+5PVI6Wlzgc71HsKdM/v4VbgRB8FRha+AR2Q8NeUAuYihWO
         XJEGMI8LB9iBV7HGDrp0sBxPmkW42DagDLpCBxL7RvNdR9zNvwVq4IUfMCyV+S78Upss
         tfmscB4bAlo80g+bsLcSuZ/YWTABD+XLRQbSRviWMCCXu2ITVP5EoLStw7aN09odQoi0
         NJWw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=YMTWgb9+jKmc5PNEABUhu3ImgIjK+bN4frfgBDd4LE4=;
        b=KLVsS7wRehh4Y+l2Vh+ZiJsLV2oOJxio4fJSQyoOM6wQLk6LI5SbxC5yhfZV6JS2Em
         hI1YkQ+oT61Yci3XGGQl7dJuFvvNPEU6gbTjP6l+y3y7k2QC3PjDIqsADmvdDulcxVfB
         9bwGnhSpG/g8r1M8kCcfISvmIPDI4XJ8CvSCNWYDsChW7hn8M1E7oiMGSffDy6fOIAyh
         EhmDHsvvTIlCdAL8GeJCH16OqYLc26TtId4dkspJ/y4o3MRbb+qpVYSOP2AZsUMjSqcV
         1Sme//VANMl/OEGqrLFC/O5OegiUpJY8YhpYHvZXFeqAW1/HJip6drfHu/oEDsVEyay0
         3xAg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5322/1Jdd8Efkb3oTlUQyWTWomcuazovdMvDotubW2FtlQZAcxQW
	7AufjwotHSM/vjqYu9ZJD7o=
X-Google-Smtp-Source: ABdhPJwk5plMGUUdoXAGGIW9HMcQPICDMBJUf3HbY/7YPmaQ9lNAmFjM68Z5PGENNnIssKfs3l0sXQ==
X-Received: by 2002:a05:6e02:c:: with SMTP id h12mr16969408ilr.177.1605048873738;
        Tue, 10 Nov 2020 14:54:33 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6638:12d0:: with SMTP id v16ls937471jas.11.gmail; Tue,
 10 Nov 2020 14:54:33 -0800 (PST)
X-Received: by 2002:a02:5b09:: with SMTP id g9mr16617253jab.89.1605048873281;
        Tue, 10 Nov 2020 14:54:33 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605048873; cv=none;
        d=google.com; s=arc-20160816;
        b=pkLGlt91Mmf6ryUFoTXF9feAUhuEUpP4AVPcA13LRNE5pEU1/91NUpzc/moV7fZn9r
         +q9Fi3tDuke7weAwPHU71BSNeT7NF16N4Hoca81vRDjddvPcW4KQsbvgUx6RbMrCPuTo
         QkuJuQlL1rpyan22m+0N8IOBXkZvqoXlCnf3hs//iSSEtd9XkwFw0gIqnNHUThaA1Ook
         UmV4DK1XWjbfKZqD7wagIexH/Zvg/AUEmVxSbOJsh5BbNO9pqgfX9hHpGt0/SIcNvFQy
         kEUtyahZ08lNcDnR+jBJ9MKM4a9aAncQQTOZcmOQao9MfCEOjw6ZZ6U0BKPq7cqtrw+d
         77nA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=ay6OUX+Z0iHjbVfftWaP3bf4xNqQ4mM5s/xfUTqYiqU=;
        b=zfyUfuD4uNbCmaEYLqmD0w8qBjYBP40Y1h19/gv0kBHIsHNLCKtVSuzj6mA7b5gZVq
         B5RP4vhYm8xfMBUrUhxPSQ/Evi9EAFnH3sCEhjLnxcl9egeNTkIWwtykCWlmXCf530/n
         z7j4Zm3RmSJkrYp8rcb5GE/Am3YiBmoFfHFwHs88AbmuJ93KTnhfgyU9Y6uKyi7wGQIR
         m5oYVqGXisdvIjAmm9SXJ/U2fdPamGRKHljrYQeV0Ntdblctf2s8wCEdiBAJywSidcuj
         NxuzNRX3nIt6ZjOw+4T8s5wH52xLvrkFxc+y5XYGu6qiq8ni7Kz1qCU6GyFSyqDs8E+G
         NaBQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=PMMtGRTi;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id y16si12215ilk.4.2020.11.10.14.54.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 10 Nov 2020 14:54:33 -0800 (PST)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from localhost.localdomain (c-73-231-172-41.hsd1.ca.comcast.net [73.231.172.41])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 1C691205CA;
	Tue, 10 Nov 2020 22:54:31 +0000 (UTC)
Date: Tue, 10 Nov 2020 14:54:30 -0800
From: Andrew Morton <akpm@linux-foundation.org>
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon
 <will.deacon@arm.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>,
 Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin
 <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, Marco
 Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>, Branislav
 Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>,
 kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org,
 linux-mm@kvack.org, linux-kernel@vger.kernel.org
Subject: Re: [PATCH v9 00/44] kasan: add hardware tag-based mode for arm64
Message-Id: <20201110145430.e15cb0e0d51498d961206be9@linux-foundation.org>
In-Reply-To: <cover.1605046192.git.andreyknvl@google.com>
References: <cover.1605046192.git.andreyknvl@google.com>
X-Mailer: Sylpheed 3.5.1 (GTK+ 2.24.31; x86_64-pc-linux-gnu)
Mime-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=PMMtGRTi;       spf=pass
 (google.com: domain of akpm@linux-foundation.org designates 198.145.29.99 as
 permitted sender) smtp.mailfrom=akpm@linux-foundation.org
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

On Tue, 10 Nov 2020 23:09:57 +0100 Andrey Konovalov <andreyknvl@google.com> wrote:

> This patchset adds a new hardware tag-based mode to KASAN [1]. The new mode
> is similar to the existing software tag-based KASAN, but relies on arm64
> Memory Tagging Extension (MTE) [2] to perform memory and pointer tagging
> (instead of shadow memory and compiler instrumentation).

I have that all merged up on top of linux-next.  Numerous minor
conflicts, mainly in arch/arm/Kconfig.  Also the changes in
https://lkml.kernel.org/r/20201103175841.3495947-7-elver@google.com had
to be fed into "kasan: split out shadow.c from common.c".

I staged it after linux-next to provide visibility into potentially
conflicting changes in the arm tree as things move forward.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201110145430.e15cb0e0d51498d961206be9%40linux-foundation.org.
