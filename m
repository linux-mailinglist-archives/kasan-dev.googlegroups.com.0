Return-Path: <kasan-dev+bncBDBK55H2UQKRBV6NU64QMGQEZRLUWII@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x340.google.com (mail-wm1-x340.google.com [IPv6:2a00:1450:4864:20::340])
	by mail.lfdr.de (Postfix) with ESMTPS id 0876C9BC951
	for <lists+kasan-dev@lfdr.de>; Tue,  5 Nov 2024 10:35:21 +0100 (CET)
Received: by mail-wm1-x340.google.com with SMTP id 5b1f17b1804b1-43151e4ef43sf36926065e9.3
        for <lists+kasan-dev@lfdr.de>; Tue, 05 Nov 2024 01:35:21 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1730799320; cv=pass;
        d=google.com; s=arc-20240605;
        b=juoF6NzCEs2nRS/r2Sq97ugQ3t8v16SpvA3QRixVqy9PJ4Fb+r190LhFiGeK8WtE7C
         NR1kCgeK6gKW8oAQBl+5sX0PkrYO2nvMByWfhA9ick+alFhvlMpi/Hd8SKeRcJ9WO70g
         ItmH8Gq7eNSheK72TfK1CP+qW7iHUR4TqMdFQ9pe4SBZ//REdVtf19JxRmot1/pA95i+
         uSiyVUll4CnEXaYq3OPhtf3OX2s/7PR2rMFeB+90G53xjgWB6/pfCYla8OQbV0ZAAdW3
         eRVe6EJ7jNdc40PPL7WozZ1ktwrOjpqXSN72O4UNlBNwmDDSw1vR19l937ARtbSSrdpz
         NSiA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=so2fVyvp8KAak/hwn4yfYSaN9Wmd5IX7movhMH00Y3Y=;
        fh=Wr12STVoAOIHLvlPRWZsrv2KnTNBfedt0X+OAfDTw2w=;
        b=efuUR6GrYtTZWhAsD9/Q5R3mJXUOiF75Pu5bHyFB0+tXsgH00yoRu1bka/RaHTgh/e
         19IU2hZdmUvBftUA0L27UaNNxd7zpPPNR8LXtEN84Ejra1zRER0or/ae7DseyrzHfoQj
         XF20Bg1Ic9Z9SdoXdt8Lcel+WNnNWpLqpym8bZDiHH2ofwUwX+95ujxH+OufRvvjensL
         hj9OXOpbbsHCmy+TXxoxQzIOUgyy2t0VkOSczAWIu2d6igpwhHeoKj0wI49Ie9MT+Idl
         BimLsOGvdPojbl2IOYiRtMqucx45GJI+0qphTFggDUFCko0Zta+fBM86bxNPV4j3aBx5
         ESjw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=Y153kTmV;
       spf=none (google.com: peterz@infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1730799320; x=1731404120; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=so2fVyvp8KAak/hwn4yfYSaN9Wmd5IX7movhMH00Y3Y=;
        b=B7TlKPNMAHNL2b0AZwFRXXQWMAI5QV/lYvpsO9GxyvKmNwjNSMKW4RJLzydi8tSYQk
         tKNVSswQSFCa2UQBgXaFj++hhI+TPH04gpVSCkr5EkNvBxewDMSowcRLEpVol89lDShf
         iSI6SSZFISKP6c6mSrt5SyryDfsOYliSy1jNODtOXeq7g7aS3CIiehFljkbkfxMZ1isb
         y0IaSAAF7SjbSYEic59L3uQGT+fMH3zkUjpfDgjOm8R+pyCDk6AjKQ9mUS4z93UGGDmQ
         APG+pWaTFbjICacHLI4VtOXuH3saipradYpjGEBlXvbylSucnWrL7toN74zK4ZJwf42F
         YutA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1730799320; x=1731404120;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=so2fVyvp8KAak/hwn4yfYSaN9Wmd5IX7movhMH00Y3Y=;
        b=jjLZ+x4ofRcpEm0LYqYtfAAReo48rAmRLAt28bguC9+j5JAJnRL1NwW+7hhrUeEGIC
         ZXLGpegmQm5oikyMXUz2FJB2/GG9UH08KL+1+w6r1y/t8mWGHTb6UV91/e0gTn90Gylr
         mT4zvvJ/b+vhO8MkY9zG651O9J7RMtFmBNwOm75llAQ6nZEUh0OiSEUObeF95jJorkSL
         dtvWt5c1Z3Yf3Mg5nrMZuCYrO5WuMGILYn/i1b3lBju868jlRZI5ALpFjuyBiYAIGzQT
         VSHaKmOeZr9H4oDbReqLH5YU7eiyZFOndah/BE1CmLunNlcTT3MKhfZ07otH2j0e+wPj
         LS0w==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXBinFbh27ObeMXYNOeTujBFyLaEej7htvaBQi2PDaRu/IlFgsKC1NWoWRKtCAsUcW+TnpVFQ==@lfdr.de
X-Gm-Message-State: AOJu0YxZk4Lmv592wUubR1OgFPw++MSaX4OHJisUu425dfxlJn5UjqrD
	RnUA0aJe3xXLiYiosMvvCCsTIans52LltLbE4JXZKjbNr+9iAR6C
X-Google-Smtp-Source: AGHT+IFBt7eNU1nzVJOrLngLkjLMZLRObNPB/eykAy/FJzg3cE+efyKJtErHhuT6i9LdNTvKEPW1Yg==
X-Received: by 2002:a05:600c:1c04:b0:431:5bf2:2d4 with SMTP id 5b1f17b1804b1-4327b8000efmr172959185e9.29.1730799319762;
        Tue, 05 Nov 2024 01:35:19 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:3c82:b0:430:5356:ac93 with SMTP id
 5b1f17b1804b1-4327b6dabf5ls922325e9.0.-pod-prod-03-eu; Tue, 05 Nov 2024
 01:35:17 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUYHoUjleZWfL+n33Y1ZjvTuufNIb3OHEToJhr2pcuOm4pigK2JNGnGNVHJt2ivxhIxlkiQZcipQ5U=@googlegroups.com
X-Received: by 2002:a05:600c:1ca7:b0:42c:bb96:340e with SMTP id 5b1f17b1804b1-4327b8011aamr185380185e9.31.1730799317296;
        Tue, 05 Nov 2024 01:35:17 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1730799317; cv=none;
        d=google.com; s=arc-20240605;
        b=RiPJRB4jscd5LGzMaTcYM6trZQM9C4EpAw8uWIZ51DDK/f/KWEB+qTKIPV9sNPZviF
         v6Kdg9y0MAM88lI5iUijcLYmgi4bGJ5YFZZZf7S7bT21YXicWvxrLSQh574AC9ajb0q9
         1CXcucGA3kb5IuQsyUquKkIJXc9ZGPi4XxyHUhjMhz/TSvOsX8hH0vX/flAgKHUewwTV
         KeZFrBN7nVgle5D9VDiSH/RkGJCdOdB2GqzxP5xFx0jKsaYIT4Quf6uyyLCb3mQVcbIV
         s5NTALwFOBH1l4Sp/D/Mbx6qQfC+j9XIn847R0XlPHzcq4aNEUGNcxWtqee5FabhKozx
         HCCg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=FRaK+l/7iIYfosK4LCr3DExnL+BzEF6OlZuBLjXKDJc=;
        fh=q22nnqEYxLaZ5p13IaefHl8mMeMIQGs3udPudinbBQ4=;
        b=AtgWjwbifDo6DM2vO+9RTmrkiJUpvtcUatfoG4zzw1ss3f4D+ema1VOzmZuiDuD3Jw
         WQ3tJ7jY0qKEAAhixd2i1l/N82Z5wDHk/mnXjAkYvyyeFnkSid0zwXTRVkI8NfkRR4Is
         8WUjPFMNWEg7PkKLDDPFjVCzWjA6ozDNims9Fz+mZJnTtDRP/idzrTxudLmkOYIOTL9i
         TXBhAB/CsxibtkH1NutWARclYCjt5hRla15lm01hHcgoQtpPM/V1Y/nnCllsx/L4uyUF
         saYq5W3YIfPX+yaV6EdQ0tDp8S+1ycyauyU2qEBkCO/CRE8QIc6ZuxYQvpSHUJulTMqx
         xLiw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=Y153kTmV;
       spf=none (google.com: peterz@infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
Received: from casper.infradead.org (casper.infradead.org. [2001:8b0:10b:1236::1])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-432a3688807si422875e9.1.2024.11.05.01.35.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 05 Nov 2024 01:35:17 -0800 (PST)
Received-SPF: none (google.com: peterz@infradead.org does not designate permitted sender hosts) client-ip=2001:8b0:10b:1236::1;
Received: from j130084.upc-j.chello.nl ([24.132.130.84] helo=noisy.programming.kicks-ass.net)
	by casper.infradead.org with esmtpsa (Exim 4.98 #2 (Red Hat Linux))
	id 1t8Fxz-00000002OBt-3yDk;
	Tue, 05 Nov 2024 09:35:16 +0000
Received: by noisy.programming.kicks-ass.net (Postfix, from userid 1000)
	id 3958B30083E; Tue,  5 Nov 2024 10:35:16 +0100 (CET)
Date: Tue, 5 Nov 2024 10:35:16 +0100
From: Peter Zijlstra <peterz@infradead.org>
To: Marco Elver <elver@google.com>
Cc: Ingo Molnar <mingo@redhat.com>, Will Deacon <will@kernel.org>,
	Waiman Long <longman@redhat.com>, Boqun Feng <boqun.feng@gmail.com>,
	"Paul E. McKenney" <paulmck@kernel.org>,
	Thomas Gleixner <tglx@linutronix.de>,
	Mark Rutland <mark.rutland@arm.com>,
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org
Subject: Re: [PATCH v2 2/5] time/sched_clock: Broaden sched_clock()'s
 instrumentation coverage
Message-ID: <20241105093516.GB10375@noisy.programming.kicks-ass.net>
References: <20241104161910.780003-1-elver@google.com>
 <20241104161910.780003-3-elver@google.com>
 <CANpmjNNBo6SvESFxo6Kk2v4_HOa=CeAVR_unTJvQEP8UZQG6gg@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNNBo6SvESFxo6Kk2v4_HOa=CeAVR_unTJvQEP8UZQG6gg@mail.gmail.com>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=casper.20170209 header.b=Y153kTmV;
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

On Tue, Nov 05, 2024 at 10:22:51AM +0100, Marco Elver wrote:
> Oops, typo'd the commit message:
> 
> On Mon, 4 Nov 2024 at 17:19, Marco Elver <elver@google.com> wrote:
> >
> > Most of sched_clock()'s implementation is ineligible for instrumentation
> > due to relying on sched_clock_noinstr().
> >
> > Split the implementation off into an __always_inline function
> > __sched_clock(), which is then used by the noinstr and instrumentable
> > version, to allow more of sched_clock() to be covered by various
> > instrumentation.
> >
> > This will allow instrumentation with the various sanitizers (KASAN,
> > KCSAN, KMSAN, UBSAN). For KCSAN, we know that raw seqcount_latch usage
> > without annotations will result in false positive reports: tell it that
> > all of __sched_clock() is "atomic" for the latch writer; later changes
> 
> s/writer/reader/
> 
> > in this series will take care of the readers.
> 
> s/readers/writers/
> 
> ... might be less confusing. If you apply, kindly fix up the commit
> message, so that future people will be less confused. The code comment
> is correct.

So done. Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20241105093516.GB10375%40noisy.programming.kicks-ass.net.
