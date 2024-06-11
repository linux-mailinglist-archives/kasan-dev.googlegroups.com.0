Return-Path: <kasan-dev+bncBC7OBJGL2MHBBCVNUCZQMGQEDXXJQKY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23f.google.com (mail-lj1-x23f.google.com [IPv6:2a00:1450:4864:20::23f])
	by mail.lfdr.de (Postfix) with ESMTPS id 818AD9037A9
	for <lists+kasan-dev@lfdr.de>; Tue, 11 Jun 2024 11:19:08 +0200 (CEST)
Received: by mail-lj1-x23f.google.com with SMTP id 38308e7fff4ca-2ebe9c0ac47sf15890931fa.0
        for <lists+kasan-dev@lfdr.de>; Tue, 11 Jun 2024 02:19:08 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718097548; cv=pass;
        d=google.com; s=arc-20160816;
        b=Qv6FR+iToAWN+u8E6dCMX+R0hTuS9XWPoeRWJuh9mdqIVb/oEXRNB5DeNQWvQ3XASS
         S4/6vuMFS2G30NPvudD/31QhocA4pus+wtnMv8Z5KoIDqYqP0GrwuxvE8dEQqm3PD9PH
         GYtxWL2X4hhKD3czsPfUkApX/SxpjAS8bUZRKpdNZ9AGcJYfAZfW8hJDjfni6bVZg9nv
         KQd3g3cw9o+DwA2wJtzOAJA5ZKcSzbQoI3yQSkN5FbUvVN5bfG8xHMwesVpABnaCcVDI
         9iGzMr2w5YpGDyehnDrWu2VQmxVvbbVPj4aR1PItHoZMmqIL1MwhZmaWwDCPrkPlGKSW
         M9Vw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=B+j0aMGN6yf18Qm0nnFqr2hqXmVkOI2mzImfXqR281s=;
        fh=rnn0+86hS3uN5XMQieugGIc7l0r+Z+oRAtgQtKph93M=;
        b=KeksdIRyEEI9U96O29FyuA8OfpKbqxWBCnrodzcWb0kkPQr/fg4lJ8DzONwSf/Ri8S
         rBgPcg34f3LtAzwRGbSlPu5oeNQMfoe1PF/gwr2DmtP35AF7haiGjC0NWbaBvuqq5yY8
         HTyI+LPvGEEysGb0Sh7E0weVaGgZ2Hwlghi5ETJoQvhLJd3RnznfGIE4yd48+Jfoh+qN
         G5/ttL6Xbb5iauNStSb36lKJBinLWDHP0dix0anxv8ZEzbGYvKDPkQusIWKXxdKjVWO1
         3/+Vj0bb062HPvkgoeY0emSvZ3hDAwIGY5kGaWIaddyg5/svKOofuC/LjpZ8Wc1QYYxW
         CAtQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="GsF1S/0j";
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::42c as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718097548; x=1718702348; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=B+j0aMGN6yf18Qm0nnFqr2hqXmVkOI2mzImfXqR281s=;
        b=GxJt/MALyTTa11+qN0eTLP+GXhgjldlz/7T/WAc/DrFAUVel3wqepcLRvPfIXLBx9+
         4+LXbrPBbl5bIR4+KKhD7xViWlT/NCGEBEEpgoBsSzJUR/bzxo6RVMTuRCagZLxDZ+xm
         NoQq4Db2WW7jKvMFoWr0ynSka4AvCO32MoXjWhC/MY1C1YWVO+N5CYNJV2/apMo2IqWZ
         ZPj70xCDXFvIcG3yTA7RHbsxwQn+w0OrGjmWDWm5Vcs6+cgqDFT47mPQqd7WMh8L+WdM
         ncwrwU0N1VtQKaCCQSy7vX+fPbVfg4+Y4S9rixAwQnzVKMX6vjt7SoGE5XvAO3QrPfc+
         ma/Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718097548; x=1718702348;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:x-beenthere:x-gm-message-state:from:to:cc
         :subject:date:message-id:reply-to;
        bh=B+j0aMGN6yf18Qm0nnFqr2hqXmVkOI2mzImfXqR281s=;
        b=RqELWPwEpWXX/Juyjtjg0ZKpwgmsdq42JiVDQKMy9xUIUmcyGmzzIWNqba7lfu+JLz
         H0c8gmZWX2tPRR3i9naiD5Q5VkWGT/5lolklkq02NBHE2z2OHAAl59g1l9bwkHqgCv8u
         cfVzuFklFQy2luu6MGcaQhi6YL1GCZ+OtU0yYXeA1JnODcf53lZNQwzE2oynxIQIB6iQ
         U34ZWgiOPmng2qU++PSn+nXW8WjlBxsyhMltJ2LNeoeB+mgSam7EFs+zW2tqInc+sRtd
         U1R1quyoDrwj1zX2ckNhgtXN7F74vhzwAj7YVlHHHqiSKjOxbzm1OjIhBhpFiY+ja+Bp
         yXpQ==
X-Forwarded-Encrypted: i=2; AJvYcCXshT5x/CzIGXw2/ozt/7R179D0uA3CGflpc236SDaYNLWmPF/qOjXB7hWhUnEJQD5BDfb1S58nGJB0hEuAdL2GJasY5rro+Q==
X-Gm-Message-State: AOJu0YwynRSBfqtgJJCSpfd+/13c0g/HtREyIgTzdobfbTvhXOm6boQ+
	ybN3QwYErvHF8QgWGapfpN5suZFje0ateUKGXJPpQUn8TkiAW2ek
X-Google-Smtp-Source: AGHT+IGjAXu80Oy1H+4ocsqxciS2UKFyi/XnD/MiZB77aq8UwSo2Rlr94fGms5G8mxSE0WrVaXzgqw==
X-Received: by 2002:a2e:bc09:0:b0:2eb:dd68:b50e with SMTP id 38308e7fff4ca-2ebdd68b860mr60880081fa.9.1718097546818;
        Tue, 11 Jun 2024 02:19:06 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:5492:b0:421:7d7f:c621 with SMTP id
 5b1f17b1804b1-4217d7fc899ls16235275e9.1.-pod-prod-05-eu; Tue, 11 Jun 2024
 02:19:04 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXrwfhlTwMkyIa39Lvbqy3+qx2GGXd8JtQ+VC1T7I/ILvsSDK4XPJHVomJGMDWf0BtdA8IlULxXd12yxCk57PKx6PhYwOsL16hlMg==
X-Received: by 2002:a05:600c:3508:b0:421:3d5c:8cbf with SMTP id 5b1f17b1804b1-42164a2b159mr116938935e9.32.1718097544627;
        Tue, 11 Jun 2024 02:19:04 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718097544; cv=none;
        d=google.com; s=arc-20160816;
        b=R4ApiGXeGRJ8OciJ0BR4VBeVaBI6OMLmjYduEd+UQOg8pC/E6TokM+eLY1rbcahKy6
         1N3PKQR3/q0MV0mAmVCpX/KaU+5PKcpqVz1sj/zKd4Rwdh6NMjWeMFJNfN4R2e1OUrZA
         yl/VaHMl7LKGQBxHkG5nSh3ZiKaY0ap3y4+mKffgTPvc2KEIkr82NwljIGrU3BZY2GKW
         spE2hpxCZ44YP7GJme6m+Rr85Zxi6fc40VxAO+ZIRGpx0NFS4Zg4CIhLmjVpA1ccmq9F
         SOFDa5TsfXOeVAC9B96fcoBvFraJt0ivjCEiHxIVEVCgiL1aEvAp1QQ19TjEko7Xan+9
         iTlw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=ps2N1Am+eO68AysV/PVFcrJRz34VjfFRtWBoGRzfhpw=;
        fh=Z8Teiv0G4rfFgTrSzmWjIwI+sSbKyhqPwFjO2xLCjYA=;
        b=C8q1MVhCzXeYNZxqKeXbivj3x5G30M958ysajbgl5XgohxY4VqykQoCuR/Ij9rw2K8
         2lR4+C3bfvti2QH/fsEVIohLKR6/+OhFDvR/4QqIpQAM7+VnHEE3/MSHmQG5T/gBinYa
         S5iLXfv9QtriLYlu0UtPHndo3hz1L+Hwjdi+Ea4vhEJWPoaLxSX9Tnt+d1DVANyPvdis
         vSCHDt0y+VBya5yvYdlZeTi7STz1AF3q9NoeBJh/jAGm0Rp3K/tqYBWhIT1CgsopwUfG
         hQu1o8JawDQOcGXxTeH5kmwBGuDF5XBAv76Xeb3UfSTZ1IwBV3C5l7RaNvZO4WeZ2Saj
         0T3A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="GsF1S/0j";
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::42c as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x42c.google.com (mail-wr1-x42c.google.com. [2a00:1450:4864:20::42c])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-4225b0921d5si745165e9.1.2024.06.11.02.19.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 11 Jun 2024 02:19:04 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::42c as permitted sender) client-ip=2a00:1450:4864:20::42c;
Received: by mail-wr1-x42c.google.com with SMTP id ffacd0b85a97d-35f225ac23bso1941168f8f.0
        for <kasan-dev@googlegroups.com>; Tue, 11 Jun 2024 02:19:04 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXPEGSC/ZO1ItCAbLRE83KNP8LmlQW1PaMCgEOYizinqZ5bQiWDNCy65Tc8fSH7fXwyZhxALMeYl9QFyWRLLmxlFYNxoC4AWF5NEQ==
X-Received: by 2002:a5d:634d:0:b0:35f:1d3b:4f7e with SMTP id ffacd0b85a97d-35f1d3b5004mr5003652f8f.26.1718097543845;
        Tue, 11 Jun 2024 02:19:03 -0700 (PDT)
Received: from elver.google.com ([2a00:79e0:9c:201:7a2:184:b13b:60d8])
        by smtp.gmail.com with ESMTPSA id ffacd0b85a97d-35f1e20664esm6703606f8f.52.2024.06.11.02.19.02
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 11 Jun 2024 02:19:03 -0700 (PDT)
Date: Tue, 11 Jun 2024 11:18:57 +0200
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: Marco Elver <elver@google.com>
Cc: peterz@infradead.org, alexander.shishkin@linux.intel.com,
	acme@kernel.org, mingo@redhat.com, jolsa@redhat.com,
	mark.rutland@arm.com, namhyung@kernel.org, tglx@linutronix.de,
	glider@google.com, viro@zeniv.linux.org.uk, arnd@arndb.de,
	christian@brauner.io, dvyukov@google.com, jannh@google.com,
	axboe@kernel.dk, mascasa@google.com, pcc@google.com,
	irogers@google.com, oleg@redhat.com, kasan-dev@googlegroups.com,
	linux-arch@vger.kernel.org, linux-fsdevel@vger.kernel.org,
	linux-kernel@vger.kernel.org, x86@kernel.org,
	linux-kselftest@vger.kernel.org
Subject: Re: [PATCH v4 00/10] Add support for synchronous signals on perf
 events
Message-ID: <ZmgWgcf3x-vQYCon@elver.google.com>
References: <20210408103605.1676875-1-elver@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20210408103605.1676875-1-elver@google.com>
User-Agent: Mutt/2.2.12 (2023-09-09)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b="GsF1S/0j";       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::42c as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Thu, Apr 08, 2021 at 12:35PM +0200, Marco Elver wrote:
[...]
> Motivation and Example Uses
> ---------------------------
> 
> 1. 	Our immediate motivation is low-overhead sampling-based race
> 	detection for user space [1]. By using perf_event_open() at
> 	process initialization, we can create hardware
> 	breakpoint/watchpoint events that are propagated automatically
> 	to all threads in a process. As far as we are aware, today no
> 	existing kernel facility (such as ptrace) allows us to set up
> 	process-wide watchpoints with minimal overheads (that are
> 	comparable to mprotect() of whole pages).
> 
> 2.	Other low-overhead error detectors that rely on detecting
> 	accesses to certain memory locations or code, process-wide and
> 	also only in a specific set of subtasks or threads.
> 
> [1] https://llvm.org/devmtg/2020-09/slides/Morehouse-GWP-Tsan.pdf
> 
> Other ideas for use-cases we found interesting, but should only
> illustrate the range of potential to further motivate the utility (we're
> sure there are more):
> 
> 3.	Code hot patching without full stop-the-world. Specifically, by
> 	setting a code breakpoint to entry to the patched routine, then
> 	send signals to threads and check that they are not in the
> 	routine, but without stopping them further. If any of the
> 	threads will enter the routine, it will receive SIGTRAP and
> 	pause.
> 
> 4.	Safepoints without mprotect(). Some Java implementations use
> 	"load from a known memory location" as a safepoint. When threads
> 	need to be stopped, the page containing the location is
> 	mprotect()ed and threads get a signal. This could be replaced with
> 	a watchpoint, which does not require a whole page nor DTLB
> 	shootdowns.
> 
> 5.	Threads receiving signals on performance events to
> 	throttle/unthrottle themselves.
> 
> 6.	Tracking data flow globally.

For future reference:

I often wonder what happened to some new kernel feature, and how people
are using it. I'm guessing there must be other users of "synchronous
signals on perf events" somewhere by now (?), but the reason the whole
thing started was because points #1 and #2 above.

Now 3 years later we were able to open source a framework that does #1
and #2 and more: https://github.com/google/gwpsan - "A framework for
low-overhead sampling-based dynamic binary instrumentation, designed for
implementing various bug detectors (also called "sanitizers") suitable
for production uses. GWPSan does not modify the executed code, but
instead performs dynamic analysis from signal handlers."

Documentation is sparse, it's still in development, and probably has
numerous sharp corners right now...

That being said, the code demonstrates how low-overhead "process-wide
synchronous event handling" thanks to perf events can be used to
implement crazier things outside the realm of performance profiling.

Thanks!

-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZmgWgcf3x-vQYCon%40elver.google.com.
