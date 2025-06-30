Return-Path: <kasan-dev+bncBDBK55H2UQKRBTEFRHBQMGQEAZZ5RHI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23e.google.com (mail-lj1-x23e.google.com [IPv6:2a00:1450:4864:20::23e])
	by mail.lfdr.de (Postfix) with ESMTPS id B1928AED63C
	for <lists+kasan-dev@lfdr.de>; Mon, 30 Jun 2025 09:54:56 +0200 (CEST)
Received: by mail-lj1-x23e.google.com with SMTP id 38308e7fff4ca-32b43616ba0sf17005911fa.0
        for <lists+kasan-dev@lfdr.de>; Mon, 30 Jun 2025 00:54:56 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1751270093; cv=pass;
        d=google.com; s=arc-20240605;
        b=J4DEj7Z8Mwq3lL4rDVfpaUdSvXMQdlHc6HQvEJYrod74qds9piUTf2WYFnS2A092Vc
         xulYCFn6BeK60nl5CW6ZTQ3fjb7JO1qD3xHz/4wG0B8YOpR3u7tU+uB2A6U3GDmA4BKh
         Wf+mDLWtZUCxUg3g0+Eni5Dfq7Dzn202RYFrzN9i9Kxx97RdxcDFbLlNX6TVdMxGQe3c
         JutOXDoCeuBI+cxI+NkaTO+PNX2wLBt5f74vxqi+7cu55yOS/zASwexxyLvR6Xee08ca
         1StA6z773wCASHI4OhRFLhPI9bf9myfN1vwhwL7UL/fhLjBaT/4Jmvh73wQaWhW1t9gh
         p7Jg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=RhGUYljAM4Qnx5rLvBfZNds/K7RwvVOGBeUU6MpBu4o=;
        fh=vlcOQkQnTV76T55axyOUilEjZjl7V4behcHQJWCrsjg=;
        b=MO/EnWLvYJNtejk7vC41opAaPOi+HkZCjfRZqlqzv1HRbJT4sasnzgNnA5jdcWln53
         KfDTYnX/gQ1z2m9vkxjF1kDgjygk5Qrzno7zWaA1j6rFk8WjPAsG2WDmRqiUsw3AxjiC
         y/JmNuDupf0w6Zt+wtPOP7HpCCG+sWlx1TurHdwhQ8X9g90OMY3eWWhdRi2jPMK47/EL
         cm1LWPUyPxi2HU1w1x6K1I9zGCzRQD/Lz4IlMrMXNqWCCq67rPCvluvb+dxTm7hSKhXt
         Fxq1NszHZYGUwnqQvXHApMfP5czZFUUtL6QnZI4sCJsF2HNhzDeN8b/77wAvO+vrJE18
         /w0w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=mv4r+kdT;
       spf=none (google.com: peterz@infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1751270093; x=1751874893; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=RhGUYljAM4Qnx5rLvBfZNds/K7RwvVOGBeUU6MpBu4o=;
        b=R7Da4+lGyaoF/yfa2MhofJFv7pUnJX2hqkBRG4x47mYPXIziM8fJ4WFaWFG1T4KgcH
         r5qNcKYGca5Cpw7ogFVUQulxaYqrnGMcJvUQvzIFGj3+eBLxrt7q+Ob2yYvhylhqU7ul
         ti/Aejman/H29eQmOdAT2DvxK8v5ewIZJuDTMWimB6/g3YoO3V5DZpan0F5cWWC3y62k
         4p9EtSCMLZpX6VIxZJo3C6AXCHhvvCvHPjID+ksB3L5HU/5FQVy1ca5jkcXC6qHZcFXt
         sKBL0YbqjgURSQmRzlT5iTwYLXUnfm6j4SeHlw/nfco3YANazjkILU6sOh3x7tphoiDa
         X2Og==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1751270093; x=1751874893;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=RhGUYljAM4Qnx5rLvBfZNds/K7RwvVOGBeUU6MpBu4o=;
        b=OF3OHP9g/OLRSUDZs2PS8+1sjtkZ2S+JKiEsUU2FgRid7M83JIJnrQsN1DsAwgnjRj
         iBxLfo8atrdknMTNke43rOn8/ft3xNdibQ1ubfYdjvztsNbdZSGBlT/ZUGC5aCXoAgUS
         oHypOxXayrk71o4P8t1oyfA7ih5yh7GQzBbR84PUa4R0barllU6ysxkDF+wu9y2oLY1d
         o+KZ15pX0heDDGvWypPAHqhSsRkEdHmT4mkegkuZ5IHTJKsVneNxxmek4RtRY3Q0rJmh
         dI2H/pg3hOausjTRZ7gpS1yObjAfW6+eLt+9xaLfSpgtHnDoMmm767KfoxPKQM3rIvPw
         wYlA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWMJYNoUozlZAqOmWz3NxPcFH5oAIsnLVT2Y2yXGYbjo9UXDV0QYRjpddJuFB/ImFhU/0IvRw==@lfdr.de
X-Gm-Message-State: AOJu0YwV5RYjRWCao8wE0Gh0U/64YgE4giNrwOWvXb9TH1CtnYEKGDCn
	u8YoTdM1BN9a9av5NHLyKjhIJKFoTN/MNjiHB8QP3/ksKSd/uW/a0YZO
X-Google-Smtp-Source: AGHT+IGMAZppI1oAlA2cQVXXaYrWJgXW3/HXh1dKcmgckCtEDU6RIOSa1t884ouJRLaRrDknZBbWfQ==
X-Received: by 2002:a2e:be9a:0:b0:326:cf84:63c4 with SMTP id 38308e7fff4ca-32cdc708aa9mr43664641fa.1.1751270093022;
        Mon, 30 Jun 2025 00:54:53 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZd/lFRAj02BLhVVbCulN1ZzF9HaCl611EnekhGM63+rWQ==
Received: by 2002:a2e:9681:0:b0:32a:7f90:fd84 with SMTP id 38308e7fff4ca-32cd03d8cedls7629881fa.2.-pod-prod-00-eu;
 Mon, 30 Jun 2025 00:54:50 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUAkr4iEKVrmBYJuKthQKhzxlK4AhKYQv0yNzmBtjimKTpHrHmc09Nlz7yIXfW6i6p55z2r6y0dFCQ=@googlegroups.com
X-Received: by 2002:a05:651c:4098:b0:30b:b78e:c445 with SMTP id 38308e7fff4ca-32cdc7f8390mr19749271fa.17.1751270089641;
        Mon, 30 Jun 2025 00:54:49 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1751270089; cv=none;
        d=google.com; s=arc-20240605;
        b=hdKYb85cC6BMzJ0GPuilOPkbM2Pb18ib5uvWG4pRo4sQu5yTPJFWEsxl255RDtt5Yc
         TkikS8Yjg6+2N0oBeqWTKqTg0t+YqxMz5QWLUMmvMYxXbbuRvvbG5q9S8ZmVhYqWdqsf
         nutztV4oXvsnrRyg/24jI1wKNGjLesC6jygwVS830az5KDJruVqMaZd2zJgR3XXq787D
         wnl0lXZ6o3HJMqw4bd+dhPTd4eXAJDlH8RSN3NQyv7GkE20ynkXWlI8+H9w32cSg3/my
         G2rq0yHnG0ugmdSQXBJ85R916XDQeLmSvM2ZABS3FK+KsJIstk6hnTWy109wOv2Gq5RJ
         cjpw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=k4wd26zsMwoAGUvYXBkWmVvkFxqrPlCdo7gexf345Gk=;
        fh=Ek1jAUi3GNl8SEwqAncxOvAsWJOejJFeI61Czi5lJC4=;
        b=NOE1O4ZR6WThG5XX079a2VGpzqsa2E8iNTRDaQxKVp73GG4fvSDlBa15WaY8l3cQX/
         XZtx+r9O5bTk/JqhQRPdHU6rH22Cl4DyxvYpkC6TphOE7NHhWENIAxe00QQD/9eYJyuk
         Cr4OxcZACExCkBhDoQyP4J3jrmM6HyAFuMy+wIPpXqFy9Km+fUdcml+62LzabMPRy9zb
         SDvZBDzNgzaGlnKMnaJqwSLuEIbA4qA02EAiIfaeyOIItMNB2qvgKhuV2T2U76Rof6fT
         4JU2AFIFypaFfbGvl1rshGBoIHUayZo5n6YKlw4V8IItfB7omhZBxpbLOAoqfkKrcngz
         epKA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=mv4r+kdT;
       spf=none (google.com: peterz@infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
Received: from desiato.infradead.org (desiato.infradead.org. [2001:8b0:10b:1:d65d:64ff:fe57:4e05])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-32cd2ed04fesi4019261fa.6.2025.06.30.00.54.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 30 Jun 2025 00:54:49 -0700 (PDT)
Received-SPF: none (google.com: peterz@infradead.org does not designate permitted sender hosts) client-ip=2001:8b0:10b:1:d65d:64ff:fe57:4e05;
Received: from 77-249-17-252.cable.dynamic.v4.ziggo.nl ([77.249.17.252] helo=noisy.programming.kicks-ass.net)
	by desiato.infradead.org with esmtpsa (Exim 4.98.2 #2 (Red Hat Linux))
	id 1uW9Lj-00000006k8v-1aNm;
	Mon, 30 Jun 2025 07:54:47 +0000
Received: by noisy.programming.kicks-ass.net (Postfix, from userid 1000)
	id E7032300158; Mon, 30 Jun 2025 09:54:46 +0200 (CEST)
Date: Mon, 30 Jun 2025 09:54:46 +0200
From: Peter Zijlstra <peterz@infradead.org>
To: Alexander Potapenko <glider@google.com>
Cc: quic_jiangenj@quicinc.com, linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com, Aleksandr Nogikh <nogikh@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Borislav Petkov <bp@alien8.de>,
	Dave Hansen <dave.hansen@linux.intel.com>,
	Dmitry Vyukov <dvyukov@google.com>, Ingo Molnar <mingo@redhat.com>,
	Josh Poimboeuf <jpoimboe@kernel.org>,
	Marco Elver <elver@google.com>,
	Thomas Gleixner <tglx@linutronix.de>
Subject: Re: [PATCH v2 08/11] kcov: add ioctl(KCOV_UNIQUE_ENABLE)
Message-ID: <20250630075446.GI1613200@noisy.programming.kicks-ass.net>
References: <20250626134158.3385080-1-glider@google.com>
 <20250626134158.3385080-9-glider@google.com>
 <20250627082730.GS1613200@noisy.programming.kicks-ass.net>
 <CAG_fn=Utve6zTW9kxwVbqpbQTRMtJPbvtyV3QkQ3yuinizF44Q@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CAG_fn=Utve6zTW9kxwVbqpbQTRMtJPbvtyV3QkQ3yuinizF44Q@mail.gmail.com>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=desiato.20200630 header.b=mv4r+kdT;
       spf=none (google.com: peterz@infradead.org does not designate permitted
 sender hosts) smtp.mailfrom=peterz@infradead.org
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

On Fri, Jun 27, 2025 at 03:58:59PM +0200, Alexander Potapenko wrote:

> There are two modes, -fsanitize-coverage=edge and
> -fsanitize-coverage=bb, with edge being the default one.

Thanks for the details!

> > Also, dynamic edges are very hard to allocate guard variables for, while
> > target guards are trivial, even in the face of dynamic edges.
> 
> All edges are known statically, because they are within the same
> function - calls between functions are not considered edges.

Oooh, that simplifies things a bit.

I suppose that even in the case of computed gotos you can create these
intermediate thunks because you have the whole thing at compile time
(not that there are a lot of those in the kernel).

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250630075446.GI1613200%40noisy.programming.kicks-ass.net.
