Return-Path: <kasan-dev+bncBD3JNNMDTMEBBGFCW3DAMGQEDAZ65EY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73c.google.com (mail-qk1-x73c.google.com [IPv6:2607:f8b0:4864:20::73c])
	by mail.lfdr.de (Postfix) with ESMTPS id EEAAFB8ABDF
	for <lists+kasan-dev@lfdr.de>; Fri, 19 Sep 2025 19:21:29 +0200 (CEST)
Received: by mail-qk1-x73c.google.com with SMTP id af79cd13be357-8153161a93esf544988985a.1
        for <lists+kasan-dev@lfdr.de>; Fri, 19 Sep 2025 10:21:29 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758302488; cv=pass;
        d=google.com; s=arc-20240605;
        b=gYKV5PmmmrhnN24nepk4QCHmJRkHYyLeWpE+iKOyBxbcOlXO8NL0f0u5if6xUHQaJN
         RNxEpZIc1MSdXv+FSpsD74nNxm3TGykk8otR7Yr7r8Nfy+72Ft/6twLbMOBQyGZBN3Yh
         HSvwaZXHCxpj5HRboSaPShauetevH+XboZ8BLVHcz0WAnvj+ZHS+3dxHT76AgLXS0teN
         +qn2E7Yoz/lXlR0Gdep4jmrwhvdhE1T40egcAfIbCuYCaR0XMwSwFO5k7791u7Wy+wjH
         LbdGhwGTlTWCF4js/+mGvjDDPPsmGO03cjht3k/7BAb/6eU4o7cmjudNwn2yViamUK3N
         3lOw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to:from
         :content-language:references:cc:to:subject:user-agent:mime-version
         :date:message-id:dkim-signature;
        bh=puigKufHZBP5PLEUONdA7+fm0JqjpX6Tsif4mJimzcg=;
        fh=2dKDaLXFg5GlF2wd4K8RuzX/xI08nCN0FwwNzaFVNfc=;
        b=GScpX1ljGaP87pXq1BlJm+XRxREme0I/IOPlU1EPPPsp924eDfAlRoTg41KBwcBk54
         J2ZWrC+juNx7zbHy5AINsQQcnf/IWDGeU5wEzKx16slpKa7yVX3yZWroX90O3KYQ+D9W
         4QgcKBGi65jED1h0TyRaFZILyoIFITsEY4ShbPpx9D8B67EUcMPjs/C7zZTo/IJHx3HA
         wRoDdkvSibHsEJXKYflTJm6/L66XSvQUnIeedxpwyM8hRP13Fpt25hyzL6DWMR+8pTfL
         X7ETgUrlZFvrIvVkFfT+14A1PhsobnYzoxYdb4vtzrYYz3DlxcnMHm8DhiOHIamezEty
         vVWQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@acm.org header.s=mr01 header.b="L8/5f0d8";
       spf=pass (google.com: domain of bvanassche@acm.org designates 199.89.3.6 as permitted sender) smtp.mailfrom=bvanassche@acm.org;
       dmarc=pass (p=REJECT sp=QUARANTINE dis=NONE) header.from=acm.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758302488; x=1758907288; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:content-language:references:cc:to:subject:user-agent
         :mime-version:date:message-id:from:to:cc:subject:date:message-id
         :reply-to;
        bh=puigKufHZBP5PLEUONdA7+fm0JqjpX6Tsif4mJimzcg=;
        b=ol0nPTOP0D5eD4meWziXK4Qeh1PYX6hyUj7qf468h2PpdDJZ0EFGG7a2PwfCw7r0W7
         nZM0doZ3/zo4BwyzbYI2x+Sz7HDczY0qiW6w7tQf/1tpOA6j1/bg8Ls49lCQd5OhfzQ1
         HMkHJHsYuUhwUlU2gEnAe01hfCuhfuruDBQmHhUUjidKhkGt1WnmETO5MuA682AgIEUZ
         KvRPzWsXsd8tjnHus+ZyIaQgRl8Rx4qTUUv6K0shrI5SSh6svr1qw8YRNLE0nGi2oNCw
         uFjKSe3sifTPnSNwuaAJEtB+waUJJYUyqYlCAgWP3jYEDVgWoa7W67hk3QktiaJMmMRE
         OtEA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758302488; x=1758907288;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:content-language:references:cc:to:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:from:to
         :cc:subject:date:message-id:reply-to;
        bh=puigKufHZBP5PLEUONdA7+fm0JqjpX6Tsif4mJimzcg=;
        b=Ft4TuQPYZfIR1qHK7T0t9LrlZzjw4Or+3G1lF2AobMkJ/mMlQgkVrusds18C7rOLfA
         h0V0OTKT1kvzVe5OBO+yjPda/5fSQseTMx2p6dZnekxDsDfn5ZHJSpRa4OM05IDQu/A1
         RmMupyI7tSfedA6zJusIXcgq352y/8A4ZlwalmdMK1tP4ihvx4Rkslfvgb6vfSIkcGA9
         SE2Psw/VLAswLViOqpy/BPMaTkxkXuv2HeID4sE+dCc+Kg3guPy1AxFThkSZNOiLKAR1
         YBhw0tfmxc+KJNWpp2k/U1f2aYDPAmM35G1u4udesq9f15mX6JYRCm13Cy4vJ3GWwV3O
         oVmw==
X-Forwarded-Encrypted: i=2; AJvYcCVLly6q/4kDazbvSdsGZ5NpbINju4u7cj5BvqKCDgCl9wiLQH7Dw2hceJU9XBIxozJJZ38Z2g==@lfdr.de
X-Gm-Message-State: AOJu0YxxvGrF3tci/4HawUV9GRssMv+yt7VAhPDJMX5ngSvDnmD7A/CO
	UNmEcoLsIBGAemBvQDUhAodPLO9p4k9p4Y9WEIgux9mw69kOqcIj8O9i
X-Google-Smtp-Source: AGHT+IFUF17MPW9O8vO30aOhyTHBTSvRsNaLZxbwD3mSbYvxZMIfb/WH8wr7Q38n0U9a6wN7uRfaUw==
X-Received: by 2002:a05:620a:f14:b0:81d:2537:916a with SMTP id af79cd13be357-83bad6dcf50mr421463785a.83.1758302488283;
        Fri, 19 Sep 2025 10:21:28 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd49VB0ISK+GJ2sRwMth8C+26pLLBbcOCq4K3eo/2S/xNA==
Received: by 2002:a05:622a:6:b0:4ba:49f2:92d7 with SMTP id d75a77b69052e-4bf978e9fe1ls26417181cf.2.-pod-prod-06-us;
 Fri, 19 Sep 2025 10:21:27 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWrqqA4xrvB9NnHHfhfrpJfAY0ebCjxY218AlNQngGxruV62yUI7xBft0KGSc0WTf1fGAh3jhVI5mU=@googlegroups.com
X-Received: by 2002:ac8:5dd1:0:b0:4b4:96a8:f79c with SMTP id d75a77b69052e-4c073c99e35mr56063791cf.79.1758302487102;
        Fri, 19 Sep 2025 10:21:27 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1758302487; cv=none;
        d=google.com; s=arc-20240605;
        b=RS1uAY+weJJjYqMbt/2rJxW6/fhxUAMYmqcQMow/aVfFJI2+EebDuG0ZwOpOsrGGc/
         jXV7f6nmN1T9bvd/xn+pRPv+HCOTIrOPW85py8BqG/PccJTSp9L/palfFkpl6Yz83tQX
         Rby7AWiS4U3/v5c/F7tELImTboisJPw09U2Q3Lt9fWrwg/HZv5z9YDQRPfLzL7x0/slP
         1yZrAdczVAAzRsbTWSAEJ8HISwtHCRzad7lQS0WnFwovpqJV1SNjcHBOzPTyupxVaiH3
         q7lX6Aonw2TDRMkfWYTPGwDJAbyTmaG97eTfwAXmUSBqIBnHhuHH55cElZYDVbiz9EbW
         iKuQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=KlBMZtQYmssvvNlMdIFNyVIKCykDzp91ay9FSX4ijvY=;
        fh=9xb6osGjnAfon9uwauMrr9rseJDVtGZpbaCoLvuMd0s=;
        b=QEVbGp3xq6EpLau++12dvkpDNhfbtr+K9ngUmVKxlMRZLNeiLGWp6VMqmfGN/yZQFt
         ra+CrIfewJAKUC0gyYRx+3Vzvj+k7QqRLyJhIMLFfK1S9lrpRgXWdmhTIzRKxWtUMNdg
         jDBSsZwdEEMcEOjWT1Nt0Z3RgBlD9AdNLvuL0agQSvJG6vyFvacjuAmxSE9MifQQ0U8e
         BoJ9t4OGSDCGJ8BKnJvN0sws/MHDZIP586Ul5Qh9QeeSmrrZsURNFvrWpKn5cg20sJb3
         m2ykBCNZdXyQsXlXZ6iY3aDhdkbRwTMyKA+dw+0QlnW2iQqgmtj+R5I2RFPn+YUrCbAn
         vKUg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@acm.org header.s=mr01 header.b="L8/5f0d8";
       spf=pass (google.com: domain of bvanassche@acm.org designates 199.89.3.6 as permitted sender) smtp.mailfrom=bvanassche@acm.org;
       dmarc=pass (p=REJECT sp=QUARANTINE dis=NONE) header.from=acm.org
Received: from 003.mia.mailroute.net (003.mia.mailroute.net. [199.89.3.6])
        by gmr-mx.google.com with ESMTPS id d75a77b69052e-4bd99c8a1a9si1576841cf.0.2025.09.19.10.21.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 19 Sep 2025 10:21:27 -0700 (PDT)
Received-SPF: pass (google.com: domain of bvanassche@acm.org designates 199.89.3.6 as permitted sender) client-ip=199.89.3.6;
Received: from localhost (localhost [127.0.0.1])
	by 003.mia.mailroute.net (Postfix) with ESMTP id 4cSznL5LKTzlgqVk;
	Fri, 19 Sep 2025 17:21:26 +0000 (UTC)
X-Virus-Scanned: by MailRoute
Received: from 003.mia.mailroute.net ([127.0.0.1])
 by localhost (003.mia [127.0.0.1]) (mroute_mailscanner, port 10029) with LMTP
 id OCIV4NH48gVh; Fri, 19 Sep 2025 17:21:19 +0000 (UTC)
Received: from [100.66.154.22] (unknown [104.135.204.82])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	(Authenticated sender: bvanassche@acm.org)
	by 003.mia.mailroute.net (Postfix) with ESMTPSA id 4cSzmX4zj3zlgqW0;
	Fri, 19 Sep 2025 17:20:43 +0000 (UTC)
Message-ID: <a75f7b70-2b72-4bb0-a940-52835f290502@acm.org>
Date: Fri, 19 Sep 2025 10:20:37 -0700
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v3 00/35] Compiler-Based Capability- and Locking-Analysis
To: Christoph Hellwig <hch@lst.de>, Nathan Chancellor <nathan@kernel.org>
Cc: Marco Elver <elver@google.com>, Peter Zijlstra <peterz@infradead.org>,
 Boqun Feng <boqun.feng@gmail.com>, Ingo Molnar <mingo@kernel.org>,
 Will Deacon <will@kernel.org>, "David S. Miller" <davem@davemloft.net>,
 Luc Van Oostenryck <luc.vanoostenryck@gmail.com>,
 "Paul E. McKenney" <paulmck@kernel.org>,
 Alexander Potapenko <glider@google.com>, Arnd Bergmann <arnd@arndb.de>,
 Bill Wendling <morbo@google.com>, Dmitry Vyukov <dvyukov@google.com>,
 Eric Dumazet <edumazet@google.com>, Frederic Weisbecker
 <frederic@kernel.org>, Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
 Herbert Xu <herbert@gondor.apana.org.au>, Ian Rogers <irogers@google.com>,
 Jann Horn <jannh@google.com>, Joel Fernandes <joelagnelf@nvidia.com>,
 Jonathan Corbet <corbet@lwn.net>, Josh Triplett <josh@joshtriplett.org>,
 Justin Stitt <justinstitt@google.com>, Kees Cook <kees@kernel.org>,
 Kentaro Takeda <takedakn@nttdata.co.jp>,
 Lukas Bulwahn <lukas.bulwahn@gmail.com>, Mark Rutland
 <mark.rutland@arm.com>, Mathieu Desnoyers <mathieu.desnoyers@efficios.com>,
 Miguel Ojeda <ojeda@kernel.org>, Neeraj Upadhyay
 <neeraj.upadhyay@kernel.org>,
 Nick Desaulniers <nick.desaulniers+lkml@gmail.com>,
 Steven Rostedt <rostedt@goodmis.org>,
 Tetsuo Handa <penguin-kernel@i-love.sakura.ne.jp>,
 Thomas Gleixner <tglx@linutronix.de>, Thomas Graf <tgraf@suug.ch>,
 Uladzislau Rezki <urezki@gmail.com>, Waiman Long <longman@redhat.com>,
 kasan-dev@googlegroups.com, linux-crypto@vger.kernel.org,
 linux-doc@vger.kernel.org, linux-kbuild@vger.kernel.org,
 linux-kernel@vger.kernel.org, linux-mm@kvack.org,
 linux-security-module@vger.kernel.org, linux-sparse@vger.kernel.org,
 llvm@lists.linux.dev, rcu@vger.kernel.org
References: <20250918140451.1289454-1-elver@google.com>
 <20250918141511.GA30263@lst.de> <20250918174555.GA3366400@ax162>
 <20250919140803.GA23745@lst.de>
Content-Language: en-US
From: "'Bart Van Assche' via kasan-dev" <kasan-dev@googlegroups.com>
In-Reply-To: <20250919140803.GA23745@lst.de>
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: bvanassche@acm.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@acm.org header.s=mr01 header.b="L8/5f0d8";       spf=pass
 (google.com: domain of bvanassche@acm.org designates 199.89.3.6 as permitted
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

On 9/19/25 7:08 AM, Christoph Hellwig wrote:
> 3) Wrappers that take multiple locks conditionally
> 
> We have helpers that take different locks in the same object based on the
> arguments like xfs_ilock() or those that take the same lock and a variable
> number of objects like xfs_dqlockn based on input and sorting.  The
> first are just historic and we might want to kill them, but the
> sorting of objects to acquire locks in order thing is a pattern in
> various places including the VFS, so we'll need some way to annotate it.

Hi Christoph,

As you probably remember some time ago I took a look myself at adding
locking annotations to kernel code. I ended up annotating multiple XFS
functions with NO_THREAD_SAFETY_ANALYSIS. Maybe the locking patterns in
XFS are too complex for compile-time analysis? See also the XFS changes
in 
https://lore.kernel.org/lkml/20250206175114.1974171-33-bvanassche@acm.org/.

Thanks,

Bart.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/a75f7b70-2b72-4bb0-a940-52835f290502%40acm.org.
