Return-Path: <kasan-dev+bncBDBK55H2UQKRBAEVRW4QMGQENFXSIYA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33c.google.com (mail-wm1-x33c.google.com [IPv6:2a00:1450:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id 154049B7727
	for <lists+kasan-dev@lfdr.de>; Thu, 31 Oct 2024 10:14:42 +0100 (CET)
Received: by mail-wm1-x33c.google.com with SMTP id 5b1f17b1804b1-4315af466d9sf4809665e9.3
        for <lists+kasan-dev@lfdr.de>; Thu, 31 Oct 2024 02:14:42 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1730366081; cv=pass;
        d=google.com; s=arc-20240605;
        b=GUbZ069qUZyRIIXDDdQHaAjV7gMyrcr8yBoDStH6GU55L3vustky8TeAM3pvikzLeO
         KMjWFjPLE20dt39kfKSblvEX9URIz2Q8xX1nNOVWBMbG+YSl7FpQOuEU9VangM0t+FMD
         4/UtDdcotCRN4G5WG8mOUPz3yj/eREZj+aTgLDxDV46IedP/7UfIeKKWyGLx9HoZzzwG
         irNoAa15Wvw0GPLEG/MiKNd9CqFfcXbw3Z+5WNKuz3Hm6vPiKyjpv04kfA7lXwDNBTue
         jxHP7Z0NPYaSowMYiqqinkgW+dlRrKC7+9d33Pup1+ppa/7VFaZquvvZpD3M/+4dBO2S
         yF1Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=HJNtOf5y4OXQHJ8laExfws6Chy1Sse3ULvrwz/FqvR0=;
        fh=9IyvtVGcSE2mBTev6v1Ebu8xQ79h+LeGt/6aS9tg8GU=;
        b=LA78tUBE7JldAD5Rm+KOVKavmoHTuAtTT9b2FUa1rnv5R9U1dJMtqhgNcWuO8dpSMF
         GHoQ99QoKKVNOpdGb2VMgxYcph50bzlI8mTIHkZVu1OhhmnFpxlZ+EqPeBbs9dDgNG+I
         qYnDIqOWZo/nLO6PpUXCfCxIYv1tJFVS8syauyYIUPUZs7cFsn2eOftKycL1mnCpQJv4
         cltZK63YQB1Po26+KST70xy0hMez9xzB3PTIThbKnBLBQfHmRUkSkc44kjsrfYfscLbY
         WnG6GjzI/ed6vpwEk9MRlDXVIsPhJ+fYpuvvBWrACMKGcNZGjPHAjXNMRzKYSPqenYou
         5pTA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b="aOezHW/H";
       spf=none (google.com: peterz@infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1730366081; x=1730970881; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=HJNtOf5y4OXQHJ8laExfws6Chy1Sse3ULvrwz/FqvR0=;
        b=czLa/luXFiz3PekGPpeaFkn4+MNfuhheIiOF/rY/Lf4U+E+dAPqvJoyAm7EKrsY1xh
         8am5Z4KX/DpuHeaMNIZFTSWjLMXJMGpcZkRepF6I1efaa4RcW9P9zGiFYkXK2FkernH0
         sfxIqGrc+M8ySSDz/LEB5p9sXaV0ywwTJELYTRPWrT2dTwO89YaA9L/8ZTgWo+sOBC88
         m/YLrP/SoRsOhJ+tBy/5PKC59HSrJE5qoTdJbOgcfASvLxeZqQg1I0TkE0vTBsSOtwLO
         iEo9ECB4yALnV5Ng/J23/GZ79Na7Wuv7x0Nn4WI2mBRc1TyGc4K1Ku3PAfwuIrneH3ma
         uhuQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1730366081; x=1730970881;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=HJNtOf5y4OXQHJ8laExfws6Chy1Sse3ULvrwz/FqvR0=;
        b=PyCTh0i5BpfMj9gdlIHp5gozysQuc259Efk12DioEapCJRcY2mV26P/tieBHc3TzSQ
         JIKLMOCKcgbO9YdT8fKc3GMoJIFjAbqXLbX4V5nuI+C96rmyDWL/Ojj+nYLZuBslqS92
         5Xkvh+w/oTIDscEZkXp8R1WVFVQTWyYuSZeHsfDI6lXCqlI1wackz3Oi5zfqwsGzN78S
         vjMpSkZwRgzucPk31fLifpQjtvi6Wn1QzUc3Yn+ucePX41OxkzdITdbTr9pGD72F2vM8
         oIZhocTH2aIEWE+zhYTMb7WkHgoc4lmslsRqmiRro367rIIAFidvZog26kBqXQyfN9T+
         c0+Q==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVGt9Ji3MlSdJv3CHdoQ2Tv5l7ZUbRk110nlr0NKDGBmAxMFD3Wbn9sA2CjnFhr2PyqCjHC0g==@lfdr.de
X-Gm-Message-State: AOJu0YzkvhM2Fwk8N+KQl/m+l2cqGZscG4aXALLkmkqOHfh8qQn7FGWS
	l/hgowDeKpFkwsK2dw0p94xVgp0V5J+0l5bNzfF4I7zfX1l1kFPF
X-Google-Smtp-Source: AGHT+IHCPsr5idHBcorpElVIGhm2dviKx9/RMfgKBHGlS8doqFhAuCuOgvxAx6fYKoOc2CHU/UxnkQ==
X-Received: by 2002:a05:600c:1d1d:b0:431:5f8c:ccbd with SMTP id 5b1f17b1804b1-4319ac6e802mr147004615e9.4.1730366081081;
        Thu, 31 Oct 2024 02:14:41 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:1548:b0:42c:b037:5fba with SMTP id
 5b1f17b1804b1-4327b81959fls3914275e9.2.-pod-prod-06-eu; Thu, 31 Oct 2024
 02:14:38 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWwBPHcWG1FN3apLY2Mbqn3j1jIEc21BXRLmCXhVMzbCJ5nUTPhTYwotO7XSR1DVXblN5AQfJmOwRk=@googlegroups.com
X-Received: by 2002:a05:600c:1d1d:b0:431:5f8c:ccbd with SMTP id 5b1f17b1804b1-4319ac6e802mr147003125e9.4.1730366078496;
        Thu, 31 Oct 2024 02:14:38 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1730366078; cv=none;
        d=google.com; s=arc-20240605;
        b=cS/v09z0T7euNGf5U8ddzWtM/lyArZE8vRjlX6ujmwzfqBUWx/kCSf/Qbh+HZG1PCL
         Yosx51G1XbVZ5a3C4GXFSsyz324Xv/dSNZf6mefrd6pcAUSrYYYnsa8iES3L6cWPsGxk
         xh7+vZ/aH6Toe2+PNLtbaFaBNQzGnymejKTFupouj7U0EmidOEG1FE66HPu4ed/hJyRi
         mClKzPgpFvESlWt9+D3O28RUk56ZIdcKE1R16IcY9xB12I4X2Dk3DQb6IwXS+FdUwBgV
         mbW0acLu0cQm9D7uvlPTV4xMbHsyCBk/f00SQDqIILz/hLcSWC2tyFs7kEsWlXbbN7/B
         c4vA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=5SSyFa+5fRE7r71i50SZ7aNSuBFW0EYeDmfmLllFtgs=;
        fh=rsYLeNn3EhqnY/ERv90DXt1NYQkHGuhFKomDG1eXtr4=;
        b=koCIj0IP87Bq0H+1pa1thKcgpI0Q3sSfJsY8EENhBFlj2eU9mBRUyX6dicGr8QKAlU
         ZoGh80mzFSCDBqFGPiw1yRICGoGyqlYrFBJf5iGk5YOsauqaidZri7BWX0wfSXw2UQiA
         iSeDGdlP84AZyiptgSrZHKfytSIReZtCod9UAOESL4EB6Z814wb6/h2IBVt6dUFLJG0o
         yhQOS+YEkYc4FGEe9jmCtuyEVErV/9lBQ9gcoslFLo/sOyk9dNlLGy9fU6gpGVjViwJX
         /motJtbPuqQuKSvvlQ1zKLop+BzEcgJDTYexKo7s8JSWHpDuYrVnlgsNQqOUu6oU5eIm
         V6aw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b="aOezHW/H";
       spf=none (google.com: peterz@infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
Received: from casper.infradead.org (casper.infradead.org. [2001:8b0:10b:1236::1])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-431b43a99dbsi4291105e9.0.2024.10.31.02.14.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 31 Oct 2024 02:14:38 -0700 (PDT)
Received-SPF: none (google.com: peterz@infradead.org does not designate permitted sender hosts) client-ip=2001:8b0:10b:1236::1;
Received: from j130084.upc-j.chello.nl ([24.132.130.84] helo=noisy.programming.kicks-ass.net)
	by casper.infradead.org with esmtpsa (Exim 4.98 #2 (Red Hat Linux))
	id 1t6RGG-0000000EWJe-3FXE;
	Thu, 31 Oct 2024 09:14:37 +0000
Received: by noisy.programming.kicks-ass.net (Postfix, from userid 1000)
	id 11A24300599; Thu, 31 Oct 2024 10:14:37 +0100 (CET)
Date: Thu, 31 Oct 2024 10:14:37 +0100
From: Peter Zijlstra <peterz@infradead.org>
To: Marco Elver <elver@google.com>
Cc: Ingo Molnar <mingo@redhat.com>, Will Deacon <will@kernel.org>,
	Waiman Long <longman@redhat.com>, Boqun Feng <boqun.feng@gmail.com>,
	"Paul E. McKenney" <paulmck@kernel.org>,
	Thomas Gleixner <tglx@linutronix.de>,
	Mark Rutland <mark.rutland@arm.com>,
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org,
	Alexander Potapenko <glider@google.com>
Subject: Re: [PATCH] kcsan, seqlock: Support seqcount_latch_t
Message-ID: <20241031091437.GV9767@noisy.programming.kicks-ass.net>
References: <20241029083658.1096492-1-elver@google.com>
 <20241029114937.GT14555@noisy.programming.kicks-ass.net>
 <CANpmjNPyXGRTWHhycVuEXdDfe7MoN19MeztdQaSOJkzqhCD69Q@mail.gmail.com>
 <20241029134641.GR9767@noisy.programming.kicks-ass.net>
 <ZyFKUU1LpFfLrVXb@elver.google.com>
 <20241030204815.GQ14555@noisy.programming.kicks-ass.net>
 <CANpmjNNsDG7J=ZsuA40opV1b3xKMF0P8P3yCsufowJCRegGa7w@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNNsDG7J=ZsuA40opV1b3xKMF0P8P3yCsufowJCRegGa7w@mail.gmail.com>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=casper.20170209 header.b="aOezHW/H";
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

On Thu, Oct 31, 2024 at 08:00:00AM +0100, Marco Elver wrote:
> Looks good.
> 
> Let me try to assemble the pieces into a patch. (Your SOB will be
> needed - either now or later.)

Feel free to add:

Signed-off-by: Peter Zijlstra (Intel) <peterz@infradead.org>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20241031091437.GV9767%40noisy.programming.kicks-ass.net.
