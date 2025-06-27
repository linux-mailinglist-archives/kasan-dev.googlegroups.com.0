Return-Path: <kasan-dev+bncBDBK55H2UQKRB6FL7HBAMGQEXXBRLGI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13b.google.com (mail-lf1-x13b.google.com [IPv6:2a00:1450:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id 98E96AEB14E
	for <lists+kasan-dev@lfdr.de>; Fri, 27 Jun 2025 10:27:40 +0200 (CEST)
Received: by mail-lf1-x13b.google.com with SMTP id 2adb3069b0e04-553cff91724sf961075e87.2
        for <lists+kasan-dev@lfdr.de>; Fri, 27 Jun 2025 01:27:40 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1751012857; cv=pass;
        d=google.com; s=arc-20240605;
        b=MJwC2njevUjCfL7zaWftsQtln+YsIUN4vS214FnmWagvWXa8MyxRpX9l4W8dreBvqP
         SGG7/KZ1Fv1nCNIAsr6QdhyVB3r1TnXKp1bpoPsH3sWSZzNQQycyq+yDDNaixmL35BqA
         EuPahhiOBPr1uWgZN+3KxGGq2Fu61HqiQEdCGT/ZTILwuRyOCZ4zvukANA51NdaFIooM
         qgEQnYMFG5rB5KzB9QUxJZD2QZkU3NEv8NJRkwfguqv8OYB5lmla5ejrqR6w6aBzeDnQ
         JXSkbpHHcVIZBi2GO3cjCALsA0ONTP6vP3I7ru/adLcDmQlm2fyGFxVYuECgsuVGBkZd
         LY8g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=CHjmUXrEYhdWBNRrEO2PcvsEt7tjc0va6cPIdzlM0SA=;
        fh=ypZqurykT0woA/ht9MggxoF+HeKqB4HGfIphcXb3g6Y=;
        b=VgSNol1rb91DQnOLPGKTlCjsrM8JATfLeaPy2og/7RQbTtlKeliyVJsJWtCWWRhLJ0
         trFML66iQBD4e/pX5bzaZsebjDxwPytNdTNsFnNCBcMfmV6qE09Mb3sUTL0dxgyzMPB2
         ehjKNDit/g0vMcI4Q1llYgFdt5vWpXICqMswwsQRSBC4LQ74/xC+xcvdJyn1Cb5pps0x
         hgtmwazkzjZ/IHMziJfq5tt83Y+6l2WAR8q+u8k8Wx483XsmvT9jh9veR/Kckg1gSzlN
         jEyArZw7d15JqWc9AdH+DZifiUxAMqeo6mdINDhltjSZrKt0gpWUFJzvhp/+xnXVuzaK
         FpQw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=bxAB4rB8;
       spf=none (google.com: peterz@infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1751012857; x=1751617657; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=CHjmUXrEYhdWBNRrEO2PcvsEt7tjc0va6cPIdzlM0SA=;
        b=jYYkaZtEKKGnfD6l0PH5MK4aIaVkqGwvivUoyUXOrGCTC2qOA3tfBRM+CmZUzcTBvz
         DZY3bBV/eFsFD2anLhU8YgpyB7xKnDt3/yfWYUrO6MpNREeZ2s8Mc3xNfAfE99K4ZVOK
         PgxeS5hwHkLPxTL/1MvKqilQVIG+3RA5hJtH5vb6cR5ucZuSr2mfDXRcRshV2IsEwFcN
         ihXCAYnaCWtYt3crMA4JzDSB+Mu7QPQH1Jj+FGZCGmtmWwYRVW24lYjtuct6FSSUqbdk
         W6SqJaCwyF2CUP+LNxeLT6qXXl4cbDQMVyPRT9ffkB0Z89fCtr1TG/qSqmhLJ4sp67HN
         Br1A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1751012857; x=1751617657;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=CHjmUXrEYhdWBNRrEO2PcvsEt7tjc0va6cPIdzlM0SA=;
        b=ClTYj0+72YxII985q9mOiPLur9C+WQs8RpsrcqnBdiFvMKvsg3ViILAo78ISTy8fL8
         bwl0/U8L1+gvsVaKnVjeB6u8cvQQEkx3E59ccaoZSKqfBekZiB0eCK+BJiww2FmJj9I0
         UXdWtLJtWXedV8kdZrFTiVdLF3+Rhkn2JyEKYvS0zMirKjxu8v13GO0yXMDb8xRc5NIs
         fsDXHnHK9dqwcz8mQ6RuJV0E3/RkIP4yD/diK+loOtM0Yp1OmgJcxVzJPLHSMQUGFTha
         GfjN2+VeLrS/4xC1rG7tDiu2A06I3zY028jUMAcDvuKXEMyp4AOmZhOCaN7b8IOonIxr
         vf7Q==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXfQjQJRzmyNbuE5inyVIjw0YLQvR+YrcIrvvDg3cVxii/CqwZWbumjc/o2cme0KP6s7Gu3Nw==@lfdr.de
X-Gm-Message-State: AOJu0YwDa/+6CzUNkCiQ2bxO5LJbUipeOMv+RW8kTac445VSGIDs0kCe
	UwABggtGRvGF0/3g5yPgrK1HGLslCa38ChNZhE850l/FU7uU4Nmpx02T
X-Google-Smtp-Source: AGHT+IF+hXUXPZJRIZKjv3HJFMxHzSkCwS09GqueZD4QsdZ73iGbOqNxBLIh7VkFf7dhOiack5wg1g==
X-Received: by 2002:ac2:4c55:0:b0:553:ceed:c85f with SMTP id 2adb3069b0e04-5550b85b1b8mr787893e87.21.1751012857223;
        Fri, 27 Jun 2025 01:27:37 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZe4SiIwh2FbSYPjVz7XdqxOkxYs5vPcmNDhQaEs8lGLOQ==
Received: by 2002:a19:6441:0:b0:553:542a:d0ef with SMTP id 2adb3069b0e04-55502e302dels442946e87.2.-pod-prod-09-eu;
 Fri, 27 Jun 2025 01:27:34 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXaESTNFUBxNyTP0K8ushC/mGjKQhCSKUoeO0uyocyqCKxkQ3nZ7uZiBGA0NSakLAyD3CydtIieR1M=@googlegroups.com
X-Received: by 2002:a05:6512:3c92:b0:553:2154:7bda with SMTP id 2adb3069b0e04-5550b8d0c30mr805500e87.38.1751012853871;
        Fri, 27 Jun 2025 01:27:33 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1751012853; cv=none;
        d=google.com; s=arc-20240605;
        b=PYHR/vGuExqxKlKYF2Gj6SX80xLUI9TOE5p+TV2mnnoUbjEUXqn9MwODBHGXw9kGsq
         QGKjyDXKZenZ+J+/LPJUPtU4rIwF9s79JwjLIgErn7CgRA/uyiFh79JVulQX9i/8fV3C
         U+aas+aICh3AQQGeQ0qJ18qLasdZ5Kus0szxZsCm/Z5XkdjePB8W3ZhKqFA69PJdg9Xb
         cx0mNBCYGWB6iMwORXF0PuG+T+FlbWZUT0AN6iWror+x810WpfqEvDgm9TJ1RlBvwls0
         nUq7DjeCSbL43m/mXupSq1KVyUMqk9nH3SGfJO+hy6IvrKn3bWpqumXbZDZ16zepPuiG
         2HyQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=UUuri5ffyS/Mgik1WbOq5F0obfwWWCtPFTBMnttn1ek=;
        fh=Ek1jAUi3GNl8SEwqAncxOvAsWJOejJFeI61Czi5lJC4=;
        b=PeAkYnLqSuAe0fEcQsC84W5/f5UzOjrYDE/guzNzttNK1N7npsJzFeRx6vbrGZW7hc
         3j0LUpVjNqSdzcwSKwPI7wSkia4NdnTi9QpHJ2QRAgp2AKh9TysWfYxF2rBc6OQGMPSi
         XCkCsCCW8dBdEt7k5nhnv2bbcubWT48Qp08g9IK6HX7b4DQNBsXi1LerTut/iUQrknHp
         omCT3Rn2vN89trRpVb5+2gQx9KKcmgeN4nUO66CjByP2XgvSm8UrOoOKsO7PyhciBneL
         Y1R+p7k0VCqkm7XQSAxdOJjDyAEaYZVrm3Qtca1NwD9uxVkJpo5XIBWF/do3hXtdT5fY
         bKXg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=bxAB4rB8;
       spf=none (google.com: peterz@infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
Received: from desiato.infradead.org (desiato.infradead.org. [2001:8b0:10b:1:d65d:64ff:fe57:4e05])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-5550b29d2e6si90055e87.8.2025.06.27.01.27.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 27 Jun 2025 01:27:33 -0700 (PDT)
Received-SPF: none (google.com: peterz@infradead.org does not designate permitted sender hosts) client-ip=2001:8b0:10b:1:d65d:64ff:fe57:4e05;
Received: from 77-249-17-252.cable.dynamic.v4.ziggo.nl ([77.249.17.252] helo=noisy.programming.kicks-ass.net)
	by desiato.infradead.org with esmtpsa (Exim 4.98.2 #2 (Red Hat Linux))
	id 1uV4Ql-00000006HAG-0I1e;
	Fri, 27 Jun 2025 08:27:31 +0000
Received: by noisy.programming.kicks-ass.net (Postfix, from userid 1000)
	id 9E70F300222; Fri, 27 Jun 2025 10:27:30 +0200 (CEST)
Date: Fri, 27 Jun 2025 10:27:30 +0200
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
Message-ID: <20250627082730.GS1613200@noisy.programming.kicks-ass.net>
References: <20250626134158.3385080-1-glider@google.com>
 <20250626134158.3385080-9-glider@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250626134158.3385080-9-glider@google.com>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=desiato.20200630 header.b=bxAB4rB8;
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

On Thu, Jun 26, 2025 at 03:41:55PM +0200, Alexander Potapenko wrote:
> ioctl(KCOV_UNIQUE_ENABLE) enables collection of deduplicated coverage
> in the presence of CONFIG_KCOV_ENABLE_GUARDS.
> 
> The buffer shared with the userspace is divided in two parts, one holding
> a bitmap, and the other one being the trace. The single parameter of
> ioctl(KCOV_UNIQUE_ENABLE) determines the number of words used for the
> bitmap.
> 
> Each __sanitizer_cov_trace_pc_guard() instrumentation hook receives a
> pointer to a unique guard variable. Upon the first call of each hook,
> the guard variable is initialized with a unique integer, which is used to
> map those hooks to bits in the bitmap. In the new coverage collection mode,
> the kernel first checks whether the bit corresponding to a particular hook
> is set, and then, if it is not, the PC is written into the trace buffer,
> and the bit is set.

I am somewhat confused; the clang documentation states that every edge
will have a guard variable.

So if I have code like:

foo:	Jcc	foobar
...
bar:	Jcc	foobar
...
foobar:

Then we get two guard variables for the one foobar target?

But from a coverage PoV you don't particularly care about the edges; you
only care you hit the instruction. Combined with the naming of the hook:
'trace_pc_guard', which reads to me like: program-counter guard, suggesting
the guard is in fact per PC or target node, not per edge.

So which is it?

Also, dynamic edges are very hard to allocate guard variables for, while
target guards are trivial, even in the face of dynamic edges.

A further consideration is that the number of edges can vastly outnumber
the number of nodes, again suggesting that node guards might be better.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250627082730.GS1613200%40noisy.programming.kicks-ass.net.
