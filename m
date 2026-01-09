Return-Path: <kasan-dev+bncBD3JNNMDTMEBBFXFQXFQMGQEVCZFRQQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x738.google.com (mail-qk1-x738.google.com [IPv6:2607:f8b0:4864:20::738])
	by mail.lfdr.de (Postfix) with ESMTPS id BC367D0C4C6
	for <lists+kasan-dev@lfdr.de>; Fri, 09 Jan 2026 22:26:58 +0100 (CET)
Received: by mail-qk1-x738.google.com with SMTP id af79cd13be357-8b6a9c80038sf511304485a.2
        for <lists+kasan-dev@lfdr.de>; Fri, 09 Jan 2026 13:26:58 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1767994007; cv=pass;
        d=google.com; s=arc-20240605;
        b=X4xjbraYJ1Nu1GWCiiIbBxGhYUzSD1crSnFcvyHFLKAje+uCCq3fysC3LPAEuL5tUW
         +BPpMT//1BWz1wE/N6fhFyNAbRidCa4HwvN0fzyIw5+ZT3e5a7gi7tcX5jW98SV0UO+J
         0HbdpualE6230/jCpoCIYrUQo442TlhjARNXKKhUWHFvBl/OMiSL3Nt00mjnOZOrmXO4
         SYSfGlji7nAn2fsDox4ylgYgm0tCr4Li5rEIayEucAeld/3iUiak/Q4IJkZZw0NxT6Et
         CWToQfRQN3zKTWXfzfr4H0Vpo4Q+jzTiMiMJ5qTCc4IYDoypvlPooQD8u/v0jbQ1n4Y7
         utLg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to:from
         :content-language:references:cc:to:subject:user-agent:mime-version
         :date:message-id:dkim-signature;
        bh=vXfqUNqfDpHsHEk2HxKhWSrFEtRSlixCupTDFnzd+30=;
        fh=xbLxAXhyjlrgH1TCgqxBC2QCu4nlncjPcjqvNFxbOh0=;
        b=a6MH1PvgDYB6GHD9ZGWrC+xJ0ZvdJnSOZ53c8hwOycAYXGRcCblbE+CemOKue5nb+N
         rqfne/Fc0dzeHsDizs2u0sbQ/tzv8fKcciZSxgEG1Wstjr7/WkZBMgSK8GBdDwkx5Wk8
         ZEOKLCWDgoYWRjLsiJbjYw/mYl48elRa7jo646CUZFstHlgoy3C7ESaBcK0ZhCgn8WOY
         soLnNyC53BYwKGN2JbGiaVCZwUtiDpKjkBKO3JXZEmNSxttmYYf2hyh3NUea+mzIkKgI
         h6SJI6rIEi7EV0On+cE+MZm0GYAdhFhy3MVF0qUIIqBG6ZszZYDvxWKfV+pyNrjF+3w0
         BV6Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@acm.org header.s=mr01 header.b="UQJCMP5/";
       spf=pass (google.com: domain of bvanassche@acm.org designates 199.89.1.16 as permitted sender) smtp.mailfrom=bvanassche@acm.org;
       dmarc=pass (p=REJECT sp=QUARANTINE dis=NONE) header.from=acm.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1767994007; x=1768598807; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:content-language:references:cc:to:subject:user-agent
         :mime-version:date:message-id:from:to:cc:subject:date:message-id
         :reply-to;
        bh=vXfqUNqfDpHsHEk2HxKhWSrFEtRSlixCupTDFnzd+30=;
        b=Xx7Jkx94XhlygkH2JSjvgW/J830JierYQh4bafZie5EJTFT0HPHX2Udg0Te2UwdwSC
         mNpeX6Lz4VVo3CmGsolFOOjr+0zbeQsfoBkidSShi0qH82usGeiETUeXbFLnS3YohiF+
         O1m3PpZCt6/eoQr/Vy+5NcovQsRCSbMCjzPxj9lLYghBzNyqm4RJ8LtlnM/gLpLYNGC6
         fYzAHBf4NA/Z6/wbbhQ1pxykh1P3JXNByTQ0RhHKKwbdPeTpE2hCVg6wBq2EL6KYDOd4
         Q0DATpBRzOyXUykfjMATsezdJOjtj1TiFsRpsOv9H00rt+kPnhVOepzx71C1riUQRG7i
         QFlQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1767994007; x=1768598807;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:content-language:references:cc:to:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:from:to
         :cc:subject:date:message-id:reply-to;
        bh=vXfqUNqfDpHsHEk2HxKhWSrFEtRSlixCupTDFnzd+30=;
        b=J6Oxcy4PE3i5ZG+ZPXwGZNKcVG7Qc4cKDFNU1takHCncbo4FZzj0s3RSWh71K8F7Na
         M/PVmjgG8ikh3Yr+rh2sdh43dKIb3OtKc6M1dbwYF3XXA+Ed0t52F6ubXVFjG1KctRR6
         AuCIlL/sojHM0zBhzI72KQmnViFxslZKeDs/RW3t+25Y0ymYrrO7CDPVSG6wEv6Snpsq
         rZ6idE6lf162M5Oz0re6ojhlajB3QQ6RT4PLH+yvDZd3PIpJHGF8+AvcKKijl4efrmyy
         lqb9eNhbx7FNrqxjheXupBt5MmAl3CbHvcsBV3V50XYdQoai7rOJHGiWHm2u8XJLDHhx
         yeBw==
X-Forwarded-Encrypted: i=2; AJvYcCXQq6tHnYlNebfSjrLdZpsLuxUK9lKx1JudMu8+6cWv8GtKjiIjIAu8WsOQaJ/B96TBtcAUhA==@lfdr.de
X-Gm-Message-State: AOJu0YyCCTn6AY678pBy0ZSw07rVJqxTWiN1v2jkMZZkIkWYKsNlpR3S
	qzfLrSH49uV6IQgjbn4CwAn44CQGY36l+wzYv5sPTqKjmAiVeVhYt91p
X-Google-Smtp-Source: AGHT+IHz5qKhRyxsdqlCaB+v+hBZwwi8tYmwQWiDTRhJX5tF6YM/2LqJJMscIJfUZY3OzkMi2ZENVg==
X-Received: by 2002:a05:620a:172b:b0:8b2:e9b7:5606 with SMTP id af79cd13be357-8c3893fb0e7mr1542245385a.76.1767994007205;
        Fri, 09 Jan 2026 13:26:47 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+GOL4D9pHX5pDxVO798l6qEVfalyS4TdiRJ4CwQdLPY3Q=="
Received: by 2002:a05:6214:212e:b0:888:3ab3:a46f with SMTP id
 6a1803df08f44-89075557aebls81093286d6.0.-pod-prod-08-us; Fri, 09 Jan 2026
 13:26:46 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUMn8BhuxBcUA8kYendSoDkBMbOjPkc+tg0WjJmh9KsPIupUHPfkK/2Mik0DArG06WBH1qPZkNnq+w=@googlegroups.com
X-Received: by 2002:a05:6214:590f:b0:888:3d1e:f95 with SMTP id 6a1803df08f44-8908426ac55mr153996686d6.32.1767994006301;
        Fri, 09 Jan 2026 13:26:46 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1767994006; cv=none;
        d=google.com; s=arc-20240605;
        b=ZIBqKmSSY/brJsJQpVrel8Sgt16icGXI11WKHlA6YJizFx17f3OMIpb6VcmkO5a151
         V54mUw3xbWArAoThQyTR7Nkx7uFqeDkIyV1dx8uFR7Eqn2YSDCUi2+ymz74oTnSNjABN
         k3X5XUKGL+N33GnA2Pgrco6QRM/3kkfe7BtAMeUKcw8OBx05TBaMO+kGUxvjvF4y4EjD
         cQdUrzfLA6iMJVJRHUhHqwwFBeTIADdcpFOPhCqVGem9vmAOtg1YP/gAM849wc9AeSFj
         lvFd9m0rasdZAVZ7fiaD/X5iGrrZc7HJmHK0PxYzLbMKZb41tmCHDkBdl8hp2ullKXma
         HG/A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=kVqxi06fhKwoZgXTNpFdWEZ/nlKbofAaMwqmPcPl6V4=;
        fh=/v3hOSl/qtfgtGzEW7sQH8QpnyMSTiDr7tCuJZRgb4M=;
        b=UViFG6mjNy4hA5htTuEpqduD9p/zKNKv2gKSEBhlB1sr1E1Ra3ovdv+NvGg4HDuql2
         N46mT5exdfkFZFmz338IRU5cjtnBr5AaXqT76OMfGCg4/vsUApjgi6O6+3o1GFPFhbrS
         epUkp1fuPCpVugKrmUQefVRlSNPr0yjrhOS7dnXI5AsSxgUbAyVtZWMh8gDX9MJ19B5H
         iuRB/MCdQ4aBAYsrHbOZJAoKPZTB5iVlLBy9Iiw/AtvsqiEC+swmcEwC4Wz+Pn8R4d85
         2OcQAGmVYx930NsN5ebkoAaX7LvWKh5P/m/p5af4/rQRH38bKDcz3gIFPPL5i5gjF8Dt
         zeYA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@acm.org header.s=mr01 header.b="UQJCMP5/";
       spf=pass (google.com: domain of bvanassche@acm.org designates 199.89.1.16 as permitted sender) smtp.mailfrom=bvanassche@acm.org;
       dmarc=pass (p=REJECT sp=QUARANTINE dis=NONE) header.from=acm.org
Received: from 013.lax.mailroute.net (013.lax.mailroute.net. [199.89.1.16])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-89082ce8f3dsi3064946d6.6.2026.01.09.13.26.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 09 Jan 2026 13:26:46 -0800 (PST)
Received-SPF: pass (google.com: domain of bvanassche@acm.org designates 199.89.1.16 as permitted sender) client-ip=199.89.1.16;
Received: from localhost (localhost [127.0.0.1])
	by 013.lax.mailroute.net (Postfix) with ESMTP id 4dnvwj1rSVzlsqj1;
	Fri,  9 Jan 2026 21:26:45 +0000 (UTC)
X-Virus-Scanned: by MailRoute
Received: from 013.lax.mailroute.net ([127.0.0.1])
 by localhost (013.lax [127.0.0.1]) (mroute_mailscanner, port 10029) with LMTP
 id 4NnprJS4L2Lu; Fri,  9 Jan 2026 21:26:37 +0000 (UTC)
Received: from [100.119.48.131] (unknown [104.135.180.219])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	(Authenticated sender: bvanassche@acm.org)
	by 013.lax.mailroute.net (Postfix) with ESMTPSA id 4dnvwJ0Q9kzm10Bh;
	Fri,  9 Jan 2026 21:26:23 +0000 (UTC)
Message-ID: <8143ab09-fd9b-4615-8afb-7ee10e073c51@acm.org>
Date: Fri, 9 Jan 2026 13:26:23 -0800
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v5 20/36] locking/ww_mutex: Support Clang's context
 analysis
To: Maarten Lankhorst <maarten.lankhorst@linux.intel.com>
Cc: Marco Elver <elver@google.com>, Peter Zijlstra <peterz@infradead.org>,
 Boqun Feng <boqun.feng@gmail.com>, Ingo Molnar <mingo@kernel.org>,
 Will Deacon <will@kernel.org>, "David S. Miller" <davem@davemloft.net>,
 Luc Van Oostenryck <luc.vanoostenryck@gmail.com>,
 Chris Li <sparse@chrisli.org>, "Paul E. McKenney" <paulmck@kernel.org>,
 Alexander Potapenko <glider@google.com>, Arnd Bergmann <arnd@arndb.de>,
 Christoph Hellwig <hch@lst.de>, Dmitry Vyukov <dvyukov@google.com>,
 Eric Dumazet <edumazet@google.com>, Frederic Weisbecker
 <frederic@kernel.org>, Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
 Herbert Xu <herbert@gondor.apana.org.au>, Ian Rogers <irogers@google.com>,
 Jann Horn <jannh@google.com>, Joel Fernandes <joelagnelf@nvidia.com>,
 Johannes Berg <johannes.berg@intel.com>, Jonathan Corbet <corbet@lwn.net>,
 Josh Triplett <josh@joshtriplett.org>, Justin Stitt
 <justinstitt@google.com>, Kees Cook <kees@kernel.org>,
 Kentaro Takeda <takedakn@nttdata.co.jp>,
 Lukas Bulwahn <lukas.bulwahn@gmail.com>, Mark Rutland
 <mark.rutland@arm.com>, Mathieu Desnoyers <mathieu.desnoyers@efficios.com>,
 Miguel Ojeda <ojeda@kernel.org>, Nathan Chancellor <nathan@kernel.org>,
 Neeraj Upadhyay <neeraj.upadhyay@kernel.org>,
 Nick Desaulniers <nick.desaulniers+lkml@gmail.com>,
 Steven Rostedt <rostedt@goodmis.org>,
 Tetsuo Handa <penguin-kernel@i-love.sakura.ne.jp>,
 Thomas Gleixner <tglx@linutronix.de>, Thomas Graf <tgraf@suug.ch>,
 Uladzislau Rezki <urezki@gmail.com>, Waiman Long <longman@redhat.com>,
 kasan-dev@googlegroups.com, linux-crypto@vger.kernel.org,
 linux-doc@vger.kernel.org, linux-kbuild@vger.kernel.org,
 linux-kernel@vger.kernel.org, linux-mm@kvack.org,
 linux-security-module@vger.kernel.org, linux-sparse@vger.kernel.org,
 linux-wireless@vger.kernel.org, llvm@lists.linux.dev, rcu@vger.kernel.org
References: <20251219154418.3592607-1-elver@google.com>
 <20251219154418.3592607-21-elver@google.com>
 <05c77ca1-7618-43c5-b259-d89741808479@acm.org>
 <aWFt6hcLaCjQQu2c@elver.google.com>
Content-Language: en-US
From: "'Bart Van Assche' via kasan-dev" <kasan-dev@googlegroups.com>
In-Reply-To: <aWFt6hcLaCjQQu2c@elver.google.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: bvanassche@acm.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@acm.org header.s=mr01 header.b="UQJCMP5/";       spf=pass
 (google.com: domain of bvanassche@acm.org designates 199.89.1.16 as permitted
 sender) smtp.mailfrom=bvanassche@acm.org;       dmarc=pass (p=REJECT
 sp=QUARANTINE dis=NONE) header.from=acm.org
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

(+Maarten)

On 1/9/26 2:06 PM, Marco Elver wrote:
> If there's 1 out of N ww_mutex users that missed ww_acquire_done()
> there's a good chance that 1 case is wrong.

$ git grep -w ww_acquire_done '**c'|wc -l
11
$ git grep -w ww_acquire_fini '**c'|wc -l
33

The above statistics show that there are more cases where
ww_acquire_done() is not called rather than cases where
ww_acquire_done() is called.

Maarten, since you introduced the ww_mutex code, do you perhaps prefer
that calling ww_acquire_done() is optional or rather that all users that
do not call ww_acquire_done() are modified such that they call
ww_acquire_done()? The full email conversation is available here:
https://lore.kernel.org/all/20251219154418.3592607-1-elver@google.com/

Thanks,

Bart.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/8143ab09-fd9b-4615-8afb-7ee10e073c51%40acm.org.
