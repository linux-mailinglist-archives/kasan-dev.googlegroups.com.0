Return-Path: <kasan-dev+bncBCV5TUXXRUIBBMPBX6CAMGQEDWCQ6XA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43f.google.com (mail-wr1-x43f.google.com [IPv6:2a00:1450:4864:20::43f])
	by mail.lfdr.de (Postfix) with ESMTPS id 2117937155A
	for <lists+kasan-dev@lfdr.de>; Mon,  3 May 2021 14:46:42 +0200 (CEST)
Received: by mail-wr1-x43f.google.com with SMTP id t5-20020adfb7c50000b029010dd0bb24cfsf3226907wre.2
        for <lists+kasan-dev@lfdr.de>; Mon, 03 May 2021 05:46:42 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1620046001; cv=pass;
        d=google.com; s=arc-20160816;
        b=IhQ+qP6CZY2XqLNJx/0NvYzSbMCjbGZ6Q6CgL8+5keKZk5DxDvsWyfrxa+B6Uevaay
         c+6+pPiEaBv0TAHQffHPmcNdgZc59wLyqNFdfMkDaEnnuK2LlmwPDpVR0CYdUno11FKk
         XqvKp6Sd2EtsI/UUbAWgDiBXRzV+vEmjKGMS6MNh0FF2TKq1SJXrFs0YyLCOUQ0FpZ9l
         wvLmfdSixTTsma/raVbGIBQArGDeftw2kqnR9gDANZ1Mt8u4top7QMIf+MlKqNotNKZc
         HdnENW5S42dJGiufZUhCcxfsSJW7g+2W0URPwVp2HhrrsU8mK2AlEt7G7ir0lkexL1rK
         BAvA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=Zodz70Qybjv1qsOeRGx++Y3uoQrbgU9226kTp8c6iPo=;
        b=MmE0DagF8C2qG/VmqW8lZzashBnh4HrRX2Ce9UWPaD9/fyqTok3vDMV13sn0+IbaK+
         d38uMNZWYJLkOpvETAJPiDXDSbBhqBEBwe9/l2HhDa25DAnhb6AvS6NKDvg/llOVy2F+
         NKoLbU6IKk99R3bOdKz0e7TVxlIYYPH9FF1kWPZoLpFVvqrg+4NpkiJXgHHEITMb3o1F
         U73uzSS4UQSzB3WIxSUSdDnxx6ko8CwWU5edIcLx5hFe7/iuRl3OiioO8+RDkD3dLu9L
         kisvlJJLEj0WgGhRNFfsJBzjq9goyHwj3sMH0kxACt/h4qVBPztu/M4Xv6WTsOJdV2N3
         pwqw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=XumoXk4r;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Zodz70Qybjv1qsOeRGx++Y3uoQrbgU9226kTp8c6iPo=;
        b=YmlsOqRfzce8ZNZ3srmKy6nHwxf45MCWK9ZOcVxx0rdGuqoQ8arbQBvUfZ9pqkb/L8
         GA34/GBPJ4n7RWS/vy+UvcF0Wmdxxm/uKNM/4vBagZIVuk8Hx3yIqn7evixXS0EyBZbS
         PBAQtyjyVsqW1Y/UI/SntVtAuaYlbt9dyaw0NYo9nMWII+GEu96wFwpiP9ubxL2wQivi
         5hDkQ06oQIrzO4yJowBnyRmcZiHVy5/E2KuG1aMKh3kwuWAYnQ2Qs76l9R4w6x7766bN
         /U9/PHbFCwp0H9ZAFUff6WUIkKoXNADJdJvHHvzw1ECZFj+1mtBEzoToWhtOESlZv0ZQ
         qW2w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=Zodz70Qybjv1qsOeRGx++Y3uoQrbgU9226kTp8c6iPo=;
        b=DgGM8GukxStGziDokS6cpKKTzG2Lk+QATVuxayY5h+6QdGLKXnNQRTzlFemhrSDmTd
         N1ewSh6Bu0yoVYQRC7Owb/2e0KQblCRMZXWuH1qbt1oVeyoQEASI8RT+Lvd1SZopicbm
         dODze4upBCguFvyIsrQhTWjaJnE4fD56HIuTCwyt0Xuz3SpuBQPAoWM+K4Mrpd+150Yj
         DAKOXzJsSU7l6k6OOYzbcShwu1p4qdFHlMwMeYaMj9wReSh20D/+YaavtTtN83oBUsuN
         t1W4huHZ6xZ/ihR0ywuuqxL4FbyX8HGIwGwfYGFpYHrY5/D0Gn63NLjnxHlNmprTc2Yg
         jq+g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530fPGNFdNmDOD0H5BQLitKbddaLNpngGOTSfbbBVKbHT0C4ge2X
	5iX0Ey5Ij+YGvQchEa9jESs=
X-Google-Smtp-Source: ABdhPJxhZr9bbjFN6edtN9xPKNvWmvM7+oB/nRZ2gcGHo1O3d+42IpPP2vV+PEZ/TxFPuyikLhOoJg==
X-Received: by 2002:a1c:35c6:: with SMTP id c189mr31481863wma.127.1620046001900;
        Mon, 03 May 2021 05:46:41 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:6da1:: with SMTP id u1ls1039766wrs.1.gmail; Mon, 03 May
 2021 05:46:41 -0700 (PDT)
X-Received: by 2002:a5d:408f:: with SMTP id o15mr23945530wrp.89.1620046001144;
        Mon, 03 May 2021 05:46:41 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1620046001; cv=none;
        d=google.com; s=arc-20160816;
        b=Xu5Puozx7aAPLVbISKCUnIhILLw9lxynp8jKjapO6ah75Ovt0gkDpb7S0KWZWWMW8J
         lHpv67U0uRKdOce8fRN9y8HAQ+FIruQP2q0vU6wZba4pjUlSgR45rKaaEGiw0c+GY3s6
         UFwXXiMpNGFvs0onzZLBPHI8wpYCoiBShWDBsavITRBEZVP3Ho7q4RN2v5OtFJEpdRFd
         BLs49zgQ/7EfC9ZKANAH+jKF1hK/iCLgDGOocZrJJgNRIGT12ya5i8ozSvcCIv4Q4ar5
         WjYFP2pR2iCHnhD3by94p1wTW7H92OnOkfzdXOE7+txGjH3brCk5h/F8oAVaESCfDg+p
         iZ9w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=QfWmNFzhd1S/Ji2/R39Bqc12Zh4EulMnH47lj47aGq8=;
        b=MPalYeX9IDbzhLsz9tD1SFra4NAjLOSv3vBOXJR0HpaxgnEUfjtBx32/sYZ8fEuh3Y
         ib581N3KY1Gqz+XytUqE66vcSNazt82CiH2lTqXtupp/CVvIiT1OI2uXymbHVFVDWHCc
         ahJ7g5m6qHl1o7sV2eabvn+Ouf2J2ixJaK4vFpqmBpIxVzwnxGD+rCOob2m2+M3AkMv4
         OGpORco+Yamk/QmPwsjPBAsPY8fE1HiBOsBhmbHk9snW8JIq4bib1OGEyZlVF3L7BkVt
         XJ7PF0RwTZJaE/62kPqMdRExIn+vNaS/30fTnnaJ8u8aMqh/O9AVhWEBausYq6olT9Gu
         et/w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=XumoXk4r;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from desiato.infradead.org (desiato.infradead.org. [2001:8b0:10b:1:d65d:64ff:fe57:4e05])
        by gmr-mx.google.com with ESMTPS id p65si1172323wmp.0.2021.05.03.05.46.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 03 May 2021 05:46:41 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as permitted sender) client-ip=2001:8b0:10b:1:d65d:64ff:fe57:4e05;
Received: from j217100.upc-j.chello.nl ([24.132.217.100] helo=noisy.programming.kicks-ass.net)
	by desiato.infradead.org with esmtpsa (Exim 4.94 #2 (Red Hat Linux))
	id 1ldXvz-00Dt54-Ne; Mon, 03 May 2021 12:46:28 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id DF9C83001D0;
	Mon,  3 May 2021 14:44:21 +0200 (CEST)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 1000)
	id B0B282CEAF0C5; Mon,  3 May 2021 14:44:21 +0200 (CEST)
Date: Mon, 3 May 2021 14:44:21 +0200
From: Peter Zijlstra <peterz@infradead.org>
To: "Eric W. Biederman" <ebiederm@xmission.com>
Cc: Marco Elver <elver@google.com>, Arnd Bergmann <arnd@arndb.de>,
	Florian Weimer <fweimer@redhat.com>,
	"David S. Miller" <davem@davemloft.net>,
	Ingo Molnar <mingo@kernel.org>,
	Thomas Gleixner <tglx@linutronix.de>,
	Peter Collingbourne <pcc@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Alexander Potapenko <glider@google.com>,
	sparclinux <sparclinux@vger.kernel.org>,
	linux-arch <linux-arch@vger.kernel.org>,
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>,
	Linux API <linux-api@vger.kernel.org>,
	kasan-dev <kasan-dev@googlegroups.com>
Subject: Re: [PATCH 7/3] signal: Deliver all of the perf_data in si_perf
Message-ID: <YI/wJSwQitisM8Xf@hirez.programming.kicks-ass.net>
References: <YIpkvGrBFGlB5vNj@elver.google.com>
 <m11rat9f85.fsf@fess.ebiederm.org>
 <CAK8P3a0+uKYwL1NhY6Hvtieghba2hKYGD6hcKx5n8=4Gtt+pHA@mail.gmail.com>
 <m15z031z0a.fsf@fess.ebiederm.org>
 <YIxVWkT03TqcJLY3@elver.google.com>
 <m1zgxfs7zq.fsf_-_@fess.ebiederm.org>
 <m11rarqqx2.fsf_-_@fess.ebiederm.org>
 <CANpmjNNJ_MnNyD4R2+9i24E=9xPHKnwTh6zwWtBYkuAq1Xo6-w@mail.gmail.com>
 <m1wnshm14b.fsf@fess.ebiederm.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <m1wnshm14b.fsf@fess.ebiederm.org>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=desiato.20200630 header.b=XumoXk4r;
       spf=pass (google.com: best guess record for domain of
 peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as
 permitted sender) smtp.mailfrom=peterz@infradead.org
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

On Sun, May 02, 2021 at 01:39:16PM -0500, Eric W. Biederman wrote:

> The one thing that this doesn't do is give you a 64bit field
> on 32bit architectures.
> 
> On 32bit builds the layout is:
> 
> 	int si_signo;
> 	int si_errno;
> 	int si_code;
> 	void __user *_addr;
>         
> So I believe if the first 3 fields were moved into the _sifields union
> si_perf could define a 64bit field as it's first member and it would not
> break anything else.
> 
> Given that the data field is 64bit that seems desirable.

The data field is fundamentally an address, it is internally a u64
because the perf ring buffer has u64 alignment and it saves on compat
crap etc.

So for the 32bit/compat case the high bits will always be 0 and
truncating into an unsigned long is fine.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YI/wJSwQitisM8Xf%40hirez.programming.kicks-ass.net.
