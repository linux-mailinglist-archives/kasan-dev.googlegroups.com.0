Return-Path: <kasan-dev+bncBD3JNNMDTMEBBBHITG6QMGQE3TXXFBA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x837.google.com (mail-qt1-x837.google.com [IPv6:2607:f8b0:4864:20::837])
	by mail.lfdr.de (Postfix) with ESMTPS id 729D1A2CE8E
	for <lists+kasan-dev@lfdr.de>; Fri,  7 Feb 2025 21:58:46 +0100 (CET)
Received: by mail-qt1-x837.google.com with SMTP id d75a77b69052e-467b19b5641sf48806901cf.3
        for <lists+kasan-dev@lfdr.de>; Fri, 07 Feb 2025 12:58:46 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1738961925; cv=pass;
        d=google.com; s=arc-20240605;
        b=JWPijFCqsuCMFFz2u/iYZz6olgzZxkqqy8ctJqJZc3LKa/zeeTxB1MnlvtJJo0Gc1B
         4OWjkA22uwpSRANz9r8JL+74QHZ3VXc1s4jOl4/fBQcN6dNOqOeGW2abbXzLGqQWRDF2
         wdMBItcFbX/bUQEL1RZYrSPgs11QqM3vEE6/9mP7JMeYOAR1qLgownXh3W2lg7esoyyn
         GPQrJf1eF5NceCh28EbhgbyyvOy5j/HPj0UBzkrFpiUlZq3p4QnGt2gUbceuV2YdyEMH
         eeEhD6tCp/e7aGTBFa7kvpedFn8/HRzxxicOdwJNnhFCf1cokNhDlwQUKIw+E1SJHE8b
         0ccQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to:from
         :content-language:references:cc:to:subject:user-agent:mime-version
         :date:message-id:dkim-signature;
        bh=sWaj3EvL6nzeVvZNQY6et5d1qhVtdIy22DntWIpuaeg=;
        fh=FUR7Scuwl1Ftl4pAYSGSWiR5NZJNtLiHYpYR0paXqlI=;
        b=lh1ev80cGxSFCCWxArMUH9T7gJm11h0gowUgZYs47FTnWqq3QzAo5OO9NXSL7LDf5r
         J08KMRvTbNJduJL6mGCosk1HS6VMhLfQb4hKhT9S87NNeBXFuvok9gr3rX1fkmnrO8d/
         GGcW/75mWkva8VJ8/GRFY3JjLKT7+lBzsPKCr5W4h2jQ/jBYu/gCDgIO0G2WkyD5havv
         Y0xFGzakl/O2LN/0KnMzwcYFUbiHpc6+ogmydzNdAhEM+DVVn/OufqQCQ2gMV3osNhFz
         CxsReeYla2HY4rwffmkTvqNPvjjFM/6HrQ9K+bsywzCyK70WMeUkmrMNrMnC881LffTx
         a14A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@acm.org header.s=mr01 header.b=VacKsLnk;
       spf=pass (google.com: domain of bvanassche@acm.org designates 199.89.1.12 as permitted sender) smtp.mailfrom=bvanassche@acm.org;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=acm.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1738961925; x=1739566725; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:content-language:references:cc:to:subject:user-agent
         :mime-version:date:message-id:from:to:cc:subject:date:message-id
         :reply-to;
        bh=sWaj3EvL6nzeVvZNQY6et5d1qhVtdIy22DntWIpuaeg=;
        b=Mfeqd9hISMJUTlb1jc1XvinC6uzGDwLO/uAPY/2NKl8uUDrO5ri86t0i8NY6CAHCY6
         +Z4w6rFUin3ot/Llk36/Y+xKaUQtMUlajQy8ZcQRgzAN7qKVM0+KtwYUzz+jO13PlnHB
         kVgi526fOOcLy7M5/TLT28poO3SCtr4MQta3Awlwdgx+RD6D/UVr9We2KvaQBE3z+Aay
         /Bxm1ZC68g3tawh5yk4kc1vHprC225wiFi11EBOCgJhGT9xETIghviF7l+pIjHPNIAHA
         ND3mQUsGgJBjayVvG68oIIhidax3c56feOMGJhs9vknfTMVy5yI1GEros0kn8BkyTeRS
         eSog==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1738961925; x=1739566725;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:content-language:references:cc:to:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:from:to
         :cc:subject:date:message-id:reply-to;
        bh=sWaj3EvL6nzeVvZNQY6et5d1qhVtdIy22DntWIpuaeg=;
        b=AV88pkxDnxVOjWaS57+qTL7OQEeoJCMApZCL438+qzWgksapeKXHX5GiPyTSJDNHeM
         BQyy+TeYE00zLCMHCXJi2apxfrk2wHdaDXbvAuQ5rxlU1qDXcWPOVnqVuW6+c3XifiyB
         wyiXYgF8T/dDyBjaYl/zXmhL5A7XT/N2Y0gMqhMAdyPMfoJUJRQJf0T4pQ+UwHr5G4Gk
         nBgNmzZAPRNNIdXQXpW4yyeba9nDQUSVEJRz7dV97kM+6/DzlV+pT+qANk6yO3t4ccu1
         2V72y8J8+u35YHYtjnDJypZmU3h6I7fZ6ylKHmTyQEoiBEu8z/jWCiQgSTbhWn19wjh+
         Yp7w==
X-Forwarded-Encrypted: i=2; AJvYcCUhqj1kiocsLfkfeIi62dPneaNJdrwBa47IiHMgdooWmFHrTo+LXraUhxgxBmZ+uPb72DGgaQ==@lfdr.de
X-Gm-Message-State: AOJu0YzrH/mFFPMUQHgRekGSfpsouy84AABjydioeCuWyfAgOqZAEjJ1
	g8veaa5kryQlnGupPIA2Rs+SEahNcVe9AAf3l8XlW3WF0kuyrs5H
X-Google-Smtp-Source: AGHT+IEoIDdhwffBceVF3qjSo5/HIu9hEvnhRxGBe/wc4sqrRqE+6oDGs6jXUK1msgxcQukaanNPrw==
X-Received: by 2002:a05:622a:180a:b0:467:5d5d:fabf with SMTP id d75a77b69052e-47167a24a29mr67366001cf.25.1738961925123;
        Fri, 07 Feb 2025 12:58:45 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h=AT6nird81Zk1Pvw+I6j5Tr+T6n9Y08UEKlS3qqerSCo4k5TLkQ==
Received: by 2002:a05:622a:8030:b0:467:77d8:69e7 with SMTP id
 d75a77b69052e-47167d1c2dcls22428581cf.2.-pod-prod-05-us; Fri, 07 Feb 2025
 12:58:42 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUPnPzyT6F8NaeX+AYrMCFUPdf3lOCFhu5TcgHXTCJ1MLYCfDsgVlnK99bIUFwyv9Io6Gh+MrGN78k=@googlegroups.com
X-Received: by 2002:a05:6122:894:b0:516:18cd:c1fc with SMTP id 71dfb90a1353d-51f2e27d367mr4634847e0c.8.1738961922752;
        Fri, 07 Feb 2025 12:58:42 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1738961922; cv=none;
        d=google.com; s=arc-20240605;
        b=XbJJtc7dJZ9nXIvxeMoKXsjKN1rmUY11yunrebbFFQ+oK1gdJzimNQUi+zb0GCWuV7
         krX1V+9kmq0SzTiUU7Hxb1hn/Cd+gYp9f2l5T1UG8/Z9b8GM7ArouRTjqubqEQfwqVgI
         s1COoxJizjl4C6MF6lNvXbAlQrROqzDslFzDysQFl+RKrqdfxdoFW6/jOuqDyp3XqHhm
         tKu9TyIzrgxt3lE14ideCXyen0lgxd37PIWJG1RQdD2hGNLdT9OxCavCZdJyZNoNAwWm
         EzycpLmWKkJ81qYrY2H3dXd0ySjT30jWQ/j8Wxw7n+1z1+8ePMen4mSqwASeaTLR3WCQ
         T7ww==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=cPoTgIZpKmlByO7NU1gC7bDaucVwG90zqII2j1CUOIQ=;
        fh=8QubMepRJEWEQbqCmCvo8ef2bBzOC7PsvwQ+ormX8jI=;
        b=IORxnsrlRcYF7kB83kk+j8QeKQXCMQN/uS9dzW3fX84idkCR4tG5okX8rSGB1sK8b7
         OfC0RRZfpiuRmNv6Ok9pxGW1Hg5LqUoB3aqisOpoHYpfuaRkGgA2yKHFQuiKVaPQ5f/e
         UcWRHeLXUfGFlA4PvN+N7sfcnrwHbrhFG68BLbe2AYbqWz+td/KDlrhB12IEMoJBV59U
         3OyOzB4nRaJPryVtA7ucQ3e5vNE/NFjWL/jqx6WaGC/kndeiaXh2VQ1DQYlZ+gRz8zLU
         ywm5rjoTtnxSIS+FIYRUf1MW8wygfwXw3iwiwNyvrNnrx4xj5oLsib6502Cj9MlDroFk
         H0pg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@acm.org header.s=mr01 header.b=VacKsLnk;
       spf=pass (google.com: domain of bvanassche@acm.org designates 199.89.1.12 as permitted sender) smtp.mailfrom=bvanassche@acm.org;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=acm.org
Received: from 009.lax.mailroute.net (009.lax.mailroute.net. [199.89.1.12])
        by gmr-mx.google.com with ESMTPS id 71dfb90a1353d-51f2288e254si186395e0c.4.2025.02.07.12.58.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 07 Feb 2025 12:58:42 -0800 (PST)
Received-SPF: pass (google.com: domain of bvanassche@acm.org designates 199.89.1.12 as permitted sender) client-ip=199.89.1.12;
Received: from localhost (localhost [127.0.0.1])
	by 009.lax.mailroute.net (Postfix) with ESMTP id 4YqRCP5bPRzlgTwQ;
	Fri,  7 Feb 2025 20:58:41 +0000 (UTC)
X-Virus-Scanned: by MailRoute
Received: from 009.lax.mailroute.net ([127.0.0.1])
 by localhost (009.lax [127.0.0.1]) (mroute_mailscanner, port 10029) with LMTP
 id Wva0VBNH7R1P; Fri,  7 Feb 2025 20:58:30 +0000 (UTC)
Received: from [100.66.154.22] (unknown [104.135.204.82])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	(Authenticated sender: bvanassche@acm.org)
	by 009.lax.mailroute.net (Postfix) with ESMTPSA id 4YqRC05LwRzlgTwF;
	Fri,  7 Feb 2025 20:58:20 +0000 (UTC)
Message-ID: <38bde2a3-762d-49ed-a2a6-ac3bd698bedc@acm.org>
Date: Fri, 7 Feb 2025 12:58:20 -0800
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH RFC 11/24] locking/mutex: Support Clang's capability
 analysis
To: Peter Zijlstra <peterz@infradead.org>, Marco Elver <elver@google.com>
Cc: "Paul E. McKenney" <paulmck@kernel.org>,
 Alexander Potapenko <glider@google.com>, Bill Wendling <morbo@google.com>,
 Boqun Feng <boqun.feng@gmail.com>, Dmitry Vyukov <dvyukov@google.com>,
 Frederic Weisbecker <frederic@kernel.org>,
 Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
 Ingo Molnar <mingo@kernel.org>, Jann Horn <jannh@google.com>,
 Joel Fernandes <joel@joelfernandes.org>, Jonathan Corbet <corbet@lwn.net>,
 Josh Triplett <josh@joshtriplett.org>, Justin Stitt
 <justinstitt@google.com>, Kees Cook <kees@kernel.org>,
 Mark Rutland <mark.rutland@arm.com>,
 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>,
 Miguel Ojeda <ojeda@kernel.org>, Nathan Chancellor <nathan@kernel.org>,
 Neeraj Upadhyay <neeraj.upadhyay@kernel.org>,
 Nick Desaulniers <ndesaulniers@google.com>,
 Steven Rostedt <rostedt@goodmis.org>, Thomas Gleixner <tglx@linutronix.de>,
 Uladzislau Rezki <urezki@gmail.com>, Waiman Long <longman@redhat.com>,
 Will Deacon <will@kernel.org>, kasan-dev@googlegroups.com,
 linux-kernel@vger.kernel.org, llvm@lists.linux.dev, rcu@vger.kernel.org,
 linux-crypto@vger.kernel.org
References: <20250206181711.1902989-1-elver@google.com>
 <20250206181711.1902989-12-elver@google.com>
 <20250207083119.GV7145@noisy.programming.kicks-ass.net>
Content-Language: en-US
From: "'Bart Van Assche' via kasan-dev" <kasan-dev@googlegroups.com>
In-Reply-To: <20250207083119.GV7145@noisy.programming.kicks-ass.net>
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: bvanassche@acm.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@acm.org header.s=mr01 header.b=VacKsLnk;       spf=pass
 (google.com: domain of bvanassche@acm.org designates 199.89.1.12 as permitted
 sender) smtp.mailfrom=bvanassche@acm.org;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=acm.org
X-Original-From: Bart Van Assche <bvanassche@acm.org>
Reply-To: Bart Van Assche <bvanassche@acm.org>
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

On 2/7/25 12:31 AM, Peter Zijlstra wrote:
> Can we please fix up all the existing __cond_lock() code too?

It would be great to get rid of __cond_lock().

In the description of commit 4a557a5d1a61 ("sparse: introduce
conditional lock acquire function attribute") I found the following
URL: 
https://lore.kernel.org/all/CAHk-=wjZfO9hGqJ2_hGQG3U_XzSh9_XaXze=HgPdvJbgrvASfA@mail.gmail.com/

That URL points at an e-mail from Linus Torvalds with a patch for sparse
that implements support for __cond_acquires(). It seems to me that the
sparse patch has never been applied to the sparse code base (the git URL
for sparse is available at https://sparse.docs.kernel.org/en/latest/).
Additionally, the most recent commit to the sparse code base is from
more than a year ago (see also 
https://git.kernel.org/pub/scm/devel/sparse/sparse.git/).

In other words, switching from __cond_lock() to __cond_acquires()
probably will make sparse report more "context imbalance" warnings.

If this is a concern to anyone, please speak up.

Thanks,

Bart.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/38bde2a3-762d-49ed-a2a6-ac3bd698bedc%40acm.org.
