Return-Path: <kasan-dev+bncBD4NDKWHQYDRBY4KWHDAMGQEP5SJEJY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x440.google.com (mail-pf1-x440.google.com [IPv6:2607:f8b0:4864:20::440])
	by mail.lfdr.de (Postfix) with ESMTPS id C3EF0B864F1
	for <lists+kasan-dev@lfdr.de>; Thu, 18 Sep 2025 19:46:19 +0200 (CEST)
Received: by mail-pf1-x440.google.com with SMTP id d2e1a72fcca58-77d4d4bb1bdsf686799b3a.1
        for <lists+kasan-dev@lfdr.de>; Thu, 18 Sep 2025 10:46:19 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758217572; cv=pass;
        d=google.com; s=arc-20240605;
        b=ctlcdVIm1MzE85cJ7wIxLlXohQxk7BkeLBV3NatzTRyFT5vW2FO/qWdU8XDiF0H+zo
         f2RozwGOOM3GpRaF5//mQS0cigaHb9PVu5tYKGfPPHo1ZYCHltqQYt+RANHvKCz76FPY
         wCXKX4Wm3nVaDV4bIpVWLyTsqDamdjt7DwITGpwF+dMsCmZXisByO5MGWu/ygKC6dQ0C
         hvCmqLTO/oaACUPtPVqr2bfR8LMi+jtLfRjTyaqQoQfHvkYE9ECMmJPkDbK6eK5BBquU
         XJy6DWVKEO22AK83urlKEc12wno49RXCi3+vh6SQLD2r0UQW38njRvwsNSWM11baMdhU
         tZyg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=k1AnEOJuk5YLrAThWy0XiMkN3aPDP6l5qAb9Q9mL5aY=;
        fh=sGtISGS3XFhENTrYAe0h1SOwEQuP1GjLi00hWp+Gu1k=;
        b=KbVuLEZNvDUSUkd0YIh90QAf/8pTNuT/5LXRmcem+bqm1SVsdlGAmXBL4HKDPf7zWy
         qR6gvvNemoof16kJEtytL+/vveWH13Ie5VnJo9fWkMSNk5sd0f8/d2uVr//lF0PEtoVn
         3HmeHfWh/klznwQSgKGjPWCIvVvxmH/FZ2TvjiqPX6qZzePzG9R1nDiz3FTLdjtZMYH0
         AvtRCVq1tI3/0P1Jlwu3BBAAgYbXmPsGtf+06ms9O9E6lZBCDXuoLo+IFFr2QEVVQIBb
         zGM8yPWeg2F3pbv6I4ukz2Yjlhe3AVTBC7G0QoXKuPw/2L6qfA3Dkl25hb6W15a0hqlU
         NvFA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=i6Kqz0C2;
       spf=pass (google.com: domain of nathan@kernel.org designates 172.105.4.254 as permitted sender) smtp.mailfrom=nathan@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758217572; x=1758822372; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=k1AnEOJuk5YLrAThWy0XiMkN3aPDP6l5qAb9Q9mL5aY=;
        b=veOUHa9ZMtcKUpSswcXG9SWCN3oxgzoTC7HUv7zVBj1czoOGdJozv+0lwWKMwD/nV5
         jJAgSuk3F9KCOXCjcdNThVwdv4BLecAfMnkRcZqlICTEtBZ7D9JlM52bxd9IgghyEMbs
         2hSgVhD5voxTKts2wIvktfw7dfpvZJIDyQC+scB0OG0MJkOvaF3DlU8mwfCLXvMbTlwz
         5qzB3zzq/H5lMu8Lw2aUq98f1c2GlCvrdWvibK1qN9xojVnCeDaahlPzLvqpCXMRWLYG
         qgOEMNKO5+MEzY0JRBE5Y2BOjtvyv8+XiKdqymNNNUwPjV+bSwRFJvHXCpWDjlLaUAPY
         hgVw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758217572; x=1758822372;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=k1AnEOJuk5YLrAThWy0XiMkN3aPDP6l5qAb9Q9mL5aY=;
        b=FlPPbchzw/aHulILs+x6gCL/bjH4GwyRVdJsu65g0y2JzxTiy1wKHmqEihVheHAsdi
         iyKfz2HlZaHgJLFMLAvYq/y9oO2rslMkoyDsEG6aBGxvYwYmKxTA3hmEhOlO8jWf3kkV
         smRZFK8aGFp6/b6IjAEWLUe9yfNw8XaqDDyQ77dDwZfpSW/JG12+3LiPsFMvQsdp6kf2
         NksZuagQ62tvTQ2sUaM0VFzMSrGVrWTRKx0prY9PDe/9b/2enmyxjwGtZKcsjlomPn8H
         vRtHYPNWkm3I8R/wg9VueQwqSELR0Xi0jV+doh/BmC1ZjhVwgJu0OiQzTP4iRvq2xPJD
         W6jQ==
X-Forwarded-Encrypted: i=2; AJvYcCVHVhwZEkhnRPvrFXavuYkHiy6y2fGlGr/gufYeaTGtbIG9ndbpyOcybH6zFerlPZnNc8jl7Q==@lfdr.de
X-Gm-Message-State: AOJu0YwkgWnO5B0VhWMr6FHXdw9QTR6rYvTKBCZUhhT9zlIGpGQEMPsY
	mDSX8VjpIU4tuyXzcMyB5AilieDrAwFLqMkP0VH9c063YFRfIAHgWE6t
X-Google-Smtp-Source: AGHT+IEiA6Hsty1G5zyPZWbFQahp7pMyhfATtedMEmvMNprWMHj/nn9L3sPdizZxTQ7ed639bPTImw==
X-Received: by 2002:a05:6a20:7f9e:b0:245:fdeb:d26b with SMTP id adf61e73a8af0-2925e23aaa3mr676010637.15.1758217571455;
        Thu, 18 Sep 2025 10:46:11 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd7diwLJqGnQmhHNgwISRmDVs9Wq//EqiFV+4E7QAzQt3A==
Received: by 2002:a05:6a00:2e13:b0:776:1836:507f with SMTP id
 d2e1a72fcca58-77d15456bf6ls1516361b3a.2.-pod-prod-01-us; Thu, 18 Sep 2025
 10:46:10 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWxPwT/ZHQ/VQXCVfzY2llO+MgfDW5Eo+1SAvld8z0apt9/3+2viLPtQF7BnCVyRhjiaUkfS7BPfyo=@googlegroups.com
X-Received: by 2002:a05:6a20:6a24:b0:24e:7336:dac2 with SMTP id adf61e73a8af0-2926e378a00mr626782637.29.1758217570072;
        Thu, 18 Sep 2025 10:46:10 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1758217570; cv=none;
        d=google.com; s=arc-20240605;
        b=TMSnsUPIfaNj3tKmjFssfqIKdV1jZl7BcYu8Nu9kPeB/I1tw2SMSyBl/VMyFUKu0tP
         7C11UvMBTvo2fj1wqq7H/JCJg25U9zCCVOXOpLL+nlvcxMhbokU2/G3mF11OycUx/8Fg
         fA+dWm8v8V6TgduBErw0RIjiwcc/4aPFcmQ7rS0VfjCeVqAdpJw/Rps9ptPfkgozEGii
         KIp82iIlB0vud4r+GtNY/CQPKRbH3lBv0ylXu7v86vMJ9vWe0By2iidfjZCP8qWEB98H
         Ue+aNiQO3u3ZXSeaKjWz7xgXx6oOVLzaYFH9gaxST38WpRnAZQN4OnQcQeHTX/34kIhD
         hhqA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=x/AjRTzvm1reEs20/D20PYYLijiuc65vTR2O4HLHfPk=;
        fh=EZQyiKzrwShLjgJBhvT4NkPajKdgpWMgXK79y+fD56s=;
        b=hFBlokSSkHWxDh8f1E6zvR5KnhldCFHBNZFFKQxHmimf0gav7dRlWjMV6BwKrrMazR
         cS2qQpjSdFP+84NWyZt86guRUyjRED5UAxZ3SLjwR2veRt+N63+NL8BXiy39OPS1Ympg
         iiabxQbqn5B5tuX/UXSpwmb82rV9wWxzn99pCGEzZdbLrKZYh4cMM0xvoE3s9DEdi/c0
         QQAPjytcUzt6oDbMqF1Di/8E4xVN7P2UYyj10jpyLF8LiPGnk+YnZbDBHHIp0/d0kow9
         jTgI5BifwTFZgz5BD+8SqQdawHI9U4CqXCZTVliulqbWygNpkbcs/D0SXI8kijv7c8c4
         DqHg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=i6Kqz0C2;
       spf=pass (google.com: domain of nathan@kernel.org designates 172.105.4.254 as permitted sender) smtp.mailfrom=nathan@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from tor.source.kernel.org (tor.source.kernel.org. [172.105.4.254])
        by gmr-mx.google.com with ESMTPS id 41be03b00d2f7-b55161c213bsi17772a12.5.2025.09.18.10.46.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 18 Sep 2025 10:46:10 -0700 (PDT)
Received-SPF: pass (google.com: domain of nathan@kernel.org designates 172.105.4.254 as permitted sender) client-ip=172.105.4.254;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by tor.source.kernel.org (Postfix) with ESMTP id B231060207;
	Thu, 18 Sep 2025 17:46:08 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id A6C0AC4CEE7;
	Thu, 18 Sep 2025 17:45:58 +0000 (UTC)
Date: Thu, 18 Sep 2025 10:45:55 -0700
From: "'Nathan Chancellor' via kasan-dev" <kasan-dev@googlegroups.com>
To: Christoph Hellwig <hch@lst.de>
Cc: Marco Elver <elver@google.com>, Peter Zijlstra <peterz@infradead.org>,
	Boqun Feng <boqun.feng@gmail.com>, Ingo Molnar <mingo@kernel.org>,
	Will Deacon <will@kernel.org>,
	"David S. Miller" <davem@davemloft.net>,
	Luc Van Oostenryck <luc.vanoostenryck@gmail.com>,
	"Paul E. McKenney" <paulmck@kernel.org>,
	Alexander Potapenko <glider@google.com>,
	Arnd Bergmann <arnd@arndb.de>, Bart Van Assche <bvanassche@acm.org>,
	Bill Wendling <morbo@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Eric Dumazet <edumazet@google.com>,
	Frederic Weisbecker <frederic@kernel.org>,
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
	Herbert Xu <herbert@gondor.apana.org.au>,
	Ian Rogers <irogers@google.com>, Jann Horn <jannh@google.com>,
	Joel Fernandes <joelagnelf@nvidia.com>,
	Jonathan Corbet <corbet@lwn.net>,
	Josh Triplett <josh@joshtriplett.org>,
	Justin Stitt <justinstitt@google.com>, Kees Cook <kees@kernel.org>,
	Kentaro Takeda <takedakn@nttdata.co.jp>,
	Lukas Bulwahn <lukas.bulwahn@gmail.com>,
	Mark Rutland <mark.rutland@arm.com>,
	Mathieu Desnoyers <mathieu.desnoyers@efficios.com>,
	Miguel Ojeda <ojeda@kernel.org>,
	Neeraj Upadhyay <neeraj.upadhyay@kernel.org>,
	Nick Desaulniers <nick.desaulniers+lkml@gmail.com>,
	Steven Rostedt <rostedt@goodmis.org>,
	Tetsuo Handa <penguin-kernel@i-love.sakura.ne.jp>,
	Thomas Gleixner <tglx@linutronix.de>, Thomas Graf <tgraf@suug.ch>,
	Uladzislau Rezki <urezki@gmail.com>,
	Waiman Long <longman@redhat.com>, kasan-dev@googlegroups.com,
	linux-crypto@vger.kernel.org, linux-doc@vger.kernel.org,
	linux-kbuild@vger.kernel.org, linux-kernel@vger.kernel.org,
	linux-mm@kvack.org, linux-security-module@vger.kernel.org,
	linux-sparse@vger.kernel.org, llvm@lists.linux.dev,
	rcu@vger.kernel.org
Subject: Re: [PATCH v3 00/35] Compiler-Based Capability- and Locking-Analysis
Message-ID: <20250918174555.GA3366400@ax162>
References: <20250918140451.1289454-1-elver@google.com>
 <20250918141511.GA30263@lst.de>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250918141511.GA30263@lst.de>
X-Original-Sender: nathan@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=i6Kqz0C2;       spf=pass
 (google.com: domain of nathan@kernel.org designates 172.105.4.254 as
 permitted sender) smtp.mailfrom=nathan@kernel.org;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Nathan Chancellor <nathan@kernel.org>
Reply-To: Nathan Chancellor <nathan@kernel.org>
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

On Thu, Sep 18, 2025 at 04:15:11PM +0200, Christoph Hellwig wrote:
> On Thu, Sep 18, 2025 at 03:59:11PM +0200, Marco Elver wrote:
> > A Clang version that supports `-Wthread-safety-pointer` and the new
> > alias-analysis of capability pointers is required (from this version
> > onwards):
> > 
> > 	https://github.com/llvm/llvm-project/commit/b4c98fcbe1504841203e610c351a3227f36c92a4 [3]
> 
> There's no chance to make say x86 pre-built binaries for that available?

I can use my existing kernel.org LLVM [1] build infrastructure to
generate prebuilt x86 binaries. Just give me a bit to build and upload
them. You may not be the only developer or maintainer who may want to
play with this.

[1]: https://kernel.org/pub/tools/llvm/

Cheers,
Nathan

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250918174555.GA3366400%40ax162.
