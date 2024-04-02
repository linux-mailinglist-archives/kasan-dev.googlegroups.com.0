Return-Path: <kasan-dev+bncBDAMN6NI5EERB2FZWCYAMGQEHBXWH6Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x439.google.com (mail-wr1-x439.google.com [IPv6:2a00:1450:4864:20::439])
	by mail.lfdr.de (Postfix) with ESMTPS id 063E4895799
	for <lists+kasan-dev@lfdr.de>; Tue,  2 Apr 2024 16:57:46 +0200 (CEST)
Received: by mail-wr1-x439.google.com with SMTP id ffacd0b85a97d-34370ba40f3sf309596f8f.2
        for <lists+kasan-dev@lfdr.de>; Tue, 02 Apr 2024 07:57:46 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1712069865; cv=pass;
        d=google.com; s=arc-20160816;
        b=zz9wBLottgVENC5g6kpCorpD8g4xPjmwbCjePLZCDN26LNhuddpBdkqDHT+r1M3hCN
         o6YDFpFotKTL0b3bcwXgNNJrWACtVgWM8eyp5cy9su2Vnt5LtmD59yNcEMIKCcFMFB+I
         eLp0fej47Z2sBjzjTJhilwh4KpN2Ih9Zib1M3kZeEAH9lalhuwQFvt8OlTqOHzEdNNvl
         /fbrlOff0GihzO4ckDFtkjza/Td/2DByT9v4FDaXUdJ6CBYsCHWSnZUpYtKymittcSHE
         SXT6xArZZkLD/7QCK4pRqQLsmVWBIRxhEdJmYpYGEo16qghwbvjf+cIOW4I9Zl5tR45x
         lERg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :references:in-reply-to:subject:cc:to:from:sender:dkim-signature;
        bh=/TsurdjLvHdpK7cCToW2XAyGC5MO0iQxI9QuojPept0=;
        fh=3KN5Z7SAVscIxBV/o7BIgQOv6QptKn+HJcFFH/SA1yc=;
        b=r6lUZnQ+0gRVynD/hh131FWnUdwGPc7A1ZMSj2jq2q5BneNyJU/pcK3vHZkVQ5kDLt
         DVjhQ02eIotctmhlpgecxjK4c5jDpNe2W9VvZtx/Qjn0EyPsoncfRQS/7oPCjmh8wSML
         B3/ujcoaTGX4zWzLdDeudlWjZMSYE1bG6E9TciPdTrB/ii9DHfQrPzlRmIIt78xue2Gd
         L2Ny8NKiTaLmBWtw6xN/tGDlsQwAu+Qelrrf8KttEYs9xu0AJnYlf31w+ysYFUnMJ4P4
         XSKBRv2KoU38MZc1TbnDk+SenlK1qUhBX4rUGBheeubQbkxGqefTgpnDgu4n07iOOCyq
         PQ/w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=qtcSN0Ml;
       dkim=neutral (no key) header.i=@linutronix.de header.s=2020e;
       spf=pass (google.com: domain of tglx@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) smtp.mailfrom=tglx@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1712069865; x=1712674665; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:references
         :in-reply-to:subject:cc:to:from:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=/TsurdjLvHdpK7cCToW2XAyGC5MO0iQxI9QuojPept0=;
        b=JHWHvO6BHdbGKeT69rltRUz3aDQuknhjYHULfkSoCCKJMb9I9PKgf9e0HQix7p/UFJ
         X+djSooagV8ucwNX+5qrlJ3htgoPAt6gKZxZ6NN05P4Mmaj7EzlrgoEAldt9gwnaxgjt
         lxIaUArkX+dassMaIBMPYU0H49SGO+q7a6R/c+fhQ5/dim27PhcWT6RdNB6cW5VVEkns
         PaeMXSWCK6qFAyIa7LK+xpQXEwKr5ffRIsggInDcI2e6yciTrmMtP6kOXlvg7mLCMzBM
         i5HQTNa78Wj7gJTbzf2SfPeXOHG1tKdCQ9qYEqovqTAAKy2V7MQ8e7Z8iJfxLkTiZIVt
         3p0g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1712069865; x=1712674665;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:references:in-reply-to:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=/TsurdjLvHdpK7cCToW2XAyGC5MO0iQxI9QuojPept0=;
        b=w+xHnD4lyFeqtOb8wA3xKJ9inoEqCoB0DhP7TDThr0yi7APSuQD5coYbdfAqePhtTc
         bp8P7HLFzgttCPWi6M+v1AZtlX+zXQA+pszFhR0tkOU2l+0W6qSdj1HLYypfvxg2p/b7
         ecbg/dkUwf9cOfR5gMTCXjAzbbbzOilmk9BprYiUFNmvCXxSdj2wKhX8fxxUDrHpVmU1
         OH/xby+G/bFaCjEUUWNl4dBJvBn+KVsqNcJaFT7NsQbEc0NlHDqEOdQlzxoRQnLVGKxM
         v2SsKMRZ2lE+xmQC3kJwLC8PQ7uG4iJNeOjMVNs7UhOxmn3h4iLjTGoZqzmhBcLXDx78
         Wabg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXzPUOSQFr83W3ddnQ1YEMMzdICq2pqMlkbjCNYJKZCiY0P+unkggVF4WMUeW7y3WhHZI1kIIkkFxdzRXio8+mMwoJXWU2J/A==
X-Gm-Message-State: AOJu0YxUVirP6qyL8nh4X7g3wcO29vQ3KphZ5LqRKdg9y2hMKAKfNu5+
	bLnnGYer4TK64AkBHH8+wJA8swXrvT5r1rvimAHOhyLndRd1weKo
X-Google-Smtp-Source: AGHT+IGAyFpUpLoNGmpF14DPmJ5+Dt6o2fZ4fjoexBrSyybteOOiC5LU2j/RrkShWXVyTDzzq7ZTMg==
X-Received: by 2002:a05:6000:b89:b0:343:69b5:1124 with SMTP id dl9-20020a0560000b8900b0034369b51124mr1420776wrb.31.1712069864767;
        Tue, 02 Apr 2024 07:57:44 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:4047:0:b0:33e:79da:bf8a with SMTP id w7-20020a5d4047000000b0033e79dabf8als28716wrp.1.-pod-prod-04-eu;
 Tue, 02 Apr 2024 07:57:43 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWBSuspR/0yj7Va88k9LcWUWT9iphluO02R3Dy8YqKULneELuzkY7DNG7WwfQujDjAYDqAT0yuD2gRIJNimuM14GM1byTD779WSxg==
X-Received: by 2002:a5d:508f:0:b0:343:3021:68ec with SMTP id a15-20020a5d508f000000b00343302168ecmr7423872wrt.36.1712069863040;
        Tue, 02 Apr 2024 07:57:43 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1712069863; cv=none;
        d=google.com; s=arc-20160816;
        b=E/5qbx7wrEf8jH69WGrO6p9FxR4qZHRi/65rwFEd6oGBL507630bd2JS0Leo7C1HgJ
         E2wdgzrMGIE97s5VajoNe3sk8SlVRVVJxWN1ldtwoYmvipi0TwNfAVLB40++pJfuMuye
         YveSqBtEqcx9htQGjGrbGrh4VDa66SUEVbFBsmIj8FSiVrJpQcBe/DVBpjGh2Ho46NrD
         mcRCik+RwI9+iZg/ilM4j4PeFl4llsQBSUct8EPA8Z9nq5t1V6P5Tb4wFsmAl6fQyAOo
         n3GMMOTfgl8dNnqWDub/dyrGSSyAdg7bbiX2jo1AwbvxA18y2VSXslLSfkT8bilkTCuC
         p0/A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:references:in-reply-to:subject:cc:to
         :dkim-signature:dkim-signature:from;
        bh=NIf2A5XgT+mSuLeFeNcerJGYHIuW/buAb+x1UGGwSvc=;
        fh=pjFj63LxWakGj73bVhHC9If5ytzaRnUATrFS4Q5gDE0=;
        b=L51AI7P/96Ye+6549zPwnkXOmlj3HpwpwCTCLsxW698QLyinmlbYDXtZMHJoX75QOI
         wWUoIlkueSbtoeIbhvTMQ9GVTPdVp5w8Gi32YqOfU7GGug7UGVwtSUcG1aCjmZXEzWEO
         N+rWyiKRc0ci+MieJdLK3zgsImqxc8bXjxf/zTRzwNVt4u4ukRKprYHhWQx6RmZdu9fq
         uvc5xXtTZZ1++qHry3bEOigCXZXyg1ud8eRy/c94Hn7RYfeBqeKGEdpuQ5lKWm9n4HtT
         7/7mbD4OvD0sIYzhXtBGOkJB4xD5LasGPrQ4PiAmMzVhl/BkQe5b3+oHqfg1PgujLVfc
         vjWA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=qtcSN0Ml;
       dkim=neutral (no key) header.i=@linutronix.de header.s=2020e;
       spf=pass (google.com: domain of tglx@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) smtp.mailfrom=tglx@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
Received: from galois.linutronix.de (Galois.linutronix.de. [2a0a:51c0:0:12e:550::1])
        by gmr-mx.google.com with ESMTPS id j15-20020adff00f000000b00341c9bc6836si375546wro.3.2024.04.02.07.57.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 02 Apr 2024 07:57:42 -0700 (PDT)
Received-SPF: pass (google.com: domain of tglx@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) client-ip=2a0a:51c0:0:12e:550::1;
From: Thomas Gleixner <tglx@linutronix.de>
To: John Stultz <jstultz@google.com>, Marco Elver <elver@google.com>
Cc: Peter Zijlstra <peterz@infradead.org>, Ingo Molnar <mingo@kernel.org>,
 Oleg Nesterov <oleg@redhat.com>, "Eric W. Biederman"
 <ebiederm@xmission.com>, linux-kernel@vger.kernel.org,
 linux-kselftest@vger.kernel.org, Dmitry Vyukov <dvyukov@google.com>,
 kasan-dev@googlegroups.com, Edward Liaw <edliaw@google.com>, Carlos Llamas
 <cmllamas@google.com>, Greg Kroah-Hartman <gregkh@linuxfoundation.org>
Subject: Re: [PATCH v6 1/2] posix-timers: Prefer delivery of signals to the
 current thread
In-Reply-To: <CANDhNCqBGnAr_MSBhQxWo+-8YnPPggxoVL32zVrDB+NcoKXVPQ@mail.gmail.com>
References: <20230316123028.2890338-1-elver@google.com>
 <CANDhNCqBGnAr_MSBhQxWo+-8YnPPggxoVL32zVrDB+NcoKXVPQ@mail.gmail.com>
Date: Tue, 02 Apr 2024 16:57:42 +0200
Message-ID: <87frw3dd7d.ffs@tglx>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: tglx@linutronix.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linutronix.de header.s=2020 header.b=qtcSN0Ml;       dkim=neutral
 (no key) header.i=@linutronix.de header.s=2020e;       spf=pass (google.com:
 domain of tglx@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted
 sender) smtp.mailfrom=tglx@linutronix.de;       dmarc=pass (p=NONE
 sp=QUARANTINE dis=NONE) header.from=linutronix.de
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

On Mon, Apr 01 2024 at 13:17, John Stultz wrote:
> Apologies for drudging up this old thread.
> I wanted to ask if anyone had objections to including this in the -stable trees?
>
> After this and the follow-on patch e797203fb3ba
> ("selftests/timers/posix_timers: Test delivery of signals across
> threads") landed, folks testing older kernels with the latest
> selftests started to see the new test checking for this behavior to
> stall.  Thomas did submit an adjustment to the test here to avoid the
> stall: https://lore.kernel.org/lkml/20230606142031.071059989@linutronix.de/,
> but it didn't seem to land, however that would just result in the test
> failing instead of hanging.

Thanks for reminding me about this series. I completely forgot about it.

> This change does seem to cherry-pick cleanly back to at least
> stable/linux-5.10.y cleanly, so it looks simple to pull this change
> back. But I wanted to make sure there wasn't anything subtle I was
> missing before sending patches.

This test in particular exercises new functionality/behaviour, which
really has no business to be backported into stable just to make the
relevant test usable on older kernels.

Why would testing with latest tests against an older kernel be valid per
se?

Thanks,

        tglx

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/87frw3dd7d.ffs%40tglx.
