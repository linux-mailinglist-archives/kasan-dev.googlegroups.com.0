Return-Path: <kasan-dev+bncBD3JNNMDTMEBB5HUS3FAMGQEICEZRLI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53a.google.com (mail-pg1-x53a.google.com [IPv6:2607:f8b0:4864:20::53a])
	by mail.lfdr.de (Postfix) with ESMTPS id B45FFCD1D50
	for <lists+kasan-dev@lfdr.de>; Fri, 19 Dec 2025 21:49:58 +0100 (CET)
Received: by mail-pg1-x53a.google.com with SMTP id 41be03b00d2f7-bddf9ce4935sf2024824a12.1
        for <lists+kasan-dev@lfdr.de>; Fri, 19 Dec 2025 12:49:58 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1766177397; cv=pass;
        d=google.com; s=arc-20240605;
        b=PnMkd1J4EErF6tWJn9CRyTSk2/jiV68b/BNLKHK9IB9YYh9So4WD+VQ30agDYtIlvh
         WvbdQjB4easfrfQ5GG6r0/KlV8HWIxkTrMIj2KQztHNsSFdFpxsoRLrxmOptmip5UIXV
         1iAE7kbLy+2xADsCIbr8VI+KoDWqdkI5DUPld3UavQIUtYva3Z6Pw2R26reccr62AQ5f
         RFyxweZ3/MCrrSqEsB6GngBgyVwnGtSUF2j8me5N6nCa32Lhz5MCK/DUCjH64/I6/+62
         4SLhKrAzqaXl8GSlhTxzdApyTao7QelrMsm3eezL/WAGmJOZwC7DwMlGmBOau4yfBl+B
         5D2Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to:from
         :content-language:references:cc:to:subject:user-agent:mime-version
         :date:message-id:dkim-signature;
        bh=1mZMs95orOMIrfo92fboMhUj6+jnXAphZ1rgHHL0QKI=;
        fh=nTJnZtQ8PgCIq4FZAT5TJV66PK1VJfQh6lyn+KOgcGY=;
        b=FBXtf2x4mGDWh2TmDOmfP4VsqbTF6LQQ46fnR9z5XSsQPreHfFJmPL7+Naclw+y/IC
         puN2VnO4v7w3J7Cf3bdnmrD74dvWTT+UXM3n1o+TNbxsmiHmOCiRkAtqPaTaeJf5uGnc
         kW2mVIFWJZtabIPfj9MuAS/1mfQIsDuqHBgKy0lBBSQXDLwPLK1HkdAIxllwdAG5bOpS
         j8/nvgxqEQHKNSzsGfhrP9N/slnPEUaySwcy2r6hzM0/dEB9FaEs1QFQJZvBD0cn3dq9
         5yIZ1KRKbeCb51NKWS+6zOvVYL4mHl6jdAYWZRwsR5bqbrzxLQqpm63uLD54zsVl+PYc
         AS6w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@acm.org header.s=mr01 header.b=AywLvfsv;
       spf=pass (google.com: domain of bvanassche@acm.org designates 199.89.1.14 as permitted sender) smtp.mailfrom=bvanassche@acm.org;
       dmarc=pass (p=REJECT sp=QUARANTINE dis=NONE) header.from=acm.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1766177397; x=1766782197; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:content-language:references:cc:to:subject:user-agent
         :mime-version:date:message-id:from:to:cc:subject:date:message-id
         :reply-to;
        bh=1mZMs95orOMIrfo92fboMhUj6+jnXAphZ1rgHHL0QKI=;
        b=xl4BfkrmfH87s9X7f02a58nvIFsY33BcevWi86ZN8MHDZ6WAasZyCH5CW12XXDzeLx
         TQBBVVpTCCXUoXmTvFdIV/QXTF50Kuw3fGiGHhC7kmrEC8f1jTqhWGNG7JLGLcf6b4hi
         P49NPkkVcGIkmz+LrnilNUrtCioPDCTdQPPTqHV4LQmjI/Dg89zfO0u1sVaHjIn7lt5v
         gv21bexXr29nmRlMqfVAq2ycL3+PMhyfO4fAjrGk7sa6v/cUyH3VzUcS3yOZGdApmcED
         iz9xRBvb7CWp18Ysw/mR5RP1URk6w8aFpp1DNKldvrNoALNoCIakHBhEqjNCCVUL0+Xr
         7Afg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1766177397; x=1766782197;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:content-language:references:cc:to:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:from:to
         :cc:subject:date:message-id:reply-to;
        bh=1mZMs95orOMIrfo92fboMhUj6+jnXAphZ1rgHHL0QKI=;
        b=bHblLY46uXNM3rkgv9XNJ7VTdtjml0x0XPXXxHmxiKCM56u7AcLMb+a+hkHU/ZuN1P
         xTB4Tw6VxmdxcGF360tAKhAQPOZVkD/AQxu2VHYyQJ4nBY+6MKSDXRw+2tK8Ornk4AiC
         BTSkSM50wwWoZ//gdwQBN+U/2110T720ih9QSRt7KLVfNmv7evMTNkcTanWz6rKqA3eO
         Kpr1J/PWeqC7Vo5Ej41U4FYbmCpT2bfv5I7HoraGKCpMtKQbVf1tRhCgNwITnqMhAv3+
         gkKngYWAGu9CpX+JHb34fsSAaQyE/5HDczwQUBsKoxUR2VzWPLFPoBkciWH89JiRT69M
         V2fQ==
X-Forwarded-Encrypted: i=2; AJvYcCWpYuKj16eb8PAlrC/QcJhfHSlNluit2ouPT0yUzJbvKg4u7vuyMmqngTJA6rXbUoNE6y/7PQ==@lfdr.de
X-Gm-Message-State: AOJu0YydXbp32TzfrPdp6tsBKAb9NCKSi5OQd8SNQIoPpSPb/7Ubk4ym
	KxpZuu/BufVNaz9wVm2iLoeuOAm3/sfKLjjmrsOKMDhpcRdw5ar1aFNI
X-Google-Smtp-Source: AGHT+IEnQWa8j9b151dyEfafUm6MzB8bklx5RCLphUFc+dcSmh/4q6KYq+3BFfU2LRWB6LDuHDczYA==
X-Received: by 2002:a05:7022:985:b0:11b:1966:8732 with SMTP id a92af1059eb24-121722dd5c6mr4954265c88.25.1766177396609;
        Fri, 19 Dec 2025 12:49:56 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWZqeCFhtmLOfDfNTSg5Niw7HixtvbtHIeopQvWboYJmCQ=="
Received: by 2002:a05:7022:42b:b0:11b:519:bafc with SMTP id
 a92af1059eb24-12056878967ls2634215c88.0.-pod-prod-09-us; Fri, 19 Dec 2025
 12:49:55 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVSKIoBZEyd0fdxFhDziuXpbl20qyZeLA1KUp2fM8NjG7jUP6q1x70h+r3+vOkznnup8qnbHEH4ArY=@googlegroups.com
X-Received: by 2002:a05:7301:648f:b0:2ae:554a:64c1 with SMTP id 5a478bee46e88-2b05ec96473mr3656980eec.31.1766177394913;
        Fri, 19 Dec 2025 12:49:54 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1766177394; cv=none;
        d=google.com; s=arc-20240605;
        b=fCmmxg/+LBo1Li9PiOVz92f2z7vZDdxeh6ByXtN1QzZCX3v0d0kwP/oLUAD5ECGVyV
         CT6NIymqF0KHotjxCZsRbE8wGZqa+M2VgTLoip0OqS8CShrZlv9GHDSdQtkqogIRmOCb
         njiORnaSZeqtSej3rHCQfw404/VLn4M1J9qcZRN5xCI6hUMykYvpKhU0iXX8OuvYZ906
         NAv00yivc44Uf77Evf+GmqU8OoVQ78z3DFGFgoNuVrt6NNtWU5WUcNVJFxRsjDngIXia
         wuY3GLzNrrgtRpHf3rctZeWqk0V/Ym0P0c/zYmYMlo3HS864s0h8OrJ6tXLdcdB6koj9
         7k1g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=rM/P2MMDWg56fhUQ0iWC3oQCnvFdb3z2dk9Gbl198tE=;
        fh=oscsWGUi8qXSCGbxjzWMCAbvCbb+T4RkBriBWr6Vjhk=;
        b=EPJ8J4bqsMi/PH0znmLfYQA1MAbt+2PECFMBhj966pGAeNkVTWcHEHgDaFGL7ppqxm
         Be2MDpXiDey5LEzUZo7S9ER6xfXUO4ZzS+1DR70d9aSUKzE1Qcotv3L0RBhjsAWcFH/s
         1AT4PDAJSFqVDQY/OCASAGX18/njRf7hIsO32+icTRbbGR2dfySa5t0noSDjZDAsWdPN
         DiaW7WQ1ap3WgIN6o8axxV4w/lVi2tHN+3nmTiTCP9SMf+UgffGg6BFFIHeueMw6cEZO
         qZlKeYTb9h9Ad8gJ5nTSRDujemkGbibd8Tu6tS+0aypV1xkqS/unFf9HO9qccpqiEFLv
         fPqw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@acm.org header.s=mr01 header.b=AywLvfsv;
       spf=pass (google.com: domain of bvanassche@acm.org designates 199.89.1.14 as permitted sender) smtp.mailfrom=bvanassche@acm.org;
       dmarc=pass (p=REJECT sp=QUARANTINE dis=NONE) header.from=acm.org
Received: from 011.lax.mailroute.net (011.lax.mailroute.net. [199.89.1.14])
        by gmr-mx.google.com with ESMTPS id 5a478bee46e88-2b05fe3e061si31669eec.1.2025.12.19.12.49.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 19 Dec 2025 12:49:54 -0800 (PST)
Received-SPF: pass (google.com: domain of bvanassche@acm.org designates 199.89.1.14 as permitted sender) client-ip=199.89.1.14;
Received: from localhost (localhost [127.0.0.1])
	by 011.lax.mailroute.net (Postfix) with ESMTP id 4dY05t3Kwcz1XM6Jk;
	Fri, 19 Dec 2025 20:49:54 +0000 (UTC)
X-Virus-Scanned: by MailRoute
Received: from 011.lax.mailroute.net ([127.0.0.1])
 by localhost (011.lax [127.0.0.1]) (mroute_mailscanner, port 10029) with LMTP
 id oFKrgFOoi46b; Fri, 19 Dec 2025 20:49:47 +0000 (UTC)
Received: from [100.119.48.131] (unknown [104.135.180.219])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	(Authenticated sender: bvanassche@acm.org)
	by 011.lax.mailroute.net (Postfix) with ESMTPSA id 4dY05T54J7z1XM0pZ;
	Fri, 19 Dec 2025 20:49:33 +0000 (UTC)
Message-ID: <3fb5a98d-d44e-4edc-8220-149d411c1ab6@acm.org>
Date: Fri, 19 Dec 2025 12:49:32 -0800
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v5 16/36] kref: Add context-analysis annotations
To: Marco Elver <elver@google.com>, Peter Zijlstra <peterz@infradead.org>,
 Boqun Feng <boqun.feng@gmail.com>, Ingo Molnar <mingo@kernel.org>,
 Will Deacon <will@kernel.org>
Cc: "David S. Miller" <davem@davemloft.net>,
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
 Tetsuo Handa <penguin-kernel@I-love.SAKURA.ne.jp>,
 Thomas Gleixner <tglx@linutronix.de>, Thomas Graf <tgraf@suug.ch>,
 Uladzislau Rezki <urezki@gmail.com>, Waiman Long <longman@redhat.com>,
 kasan-dev@googlegroups.com, linux-crypto@vger.kernel.org,
 linux-doc@vger.kernel.org, linux-kbuild@vger.kernel.org,
 linux-kernel@vger.kernel.org, linux-mm@kvack.org,
 linux-security-module@vger.kernel.org, linux-sparse@vger.kernel.org,
 linux-wireless@vger.kernel.org, llvm@lists.linux.dev, rcu@vger.kernel.org
References: <20251219154418.3592607-1-elver@google.com>
 <20251219154418.3592607-17-elver@google.com>
Content-Language: en-US
From: "'Bart Van Assche' via kasan-dev" <kasan-dev@googlegroups.com>
In-Reply-To: <20251219154418.3592607-17-elver@google.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: bvanassche@acm.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@acm.org header.s=mr01 header.b=AywLvfsv;       spf=pass
 (google.com: domain of bvanassche@acm.org designates 199.89.1.14 as permitted
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

On 12/19/25 7:40 AM, Marco Elver wrote:
> Mark functions that conditionally acquire the passed lock.
Reviewed-by: Bart Van Assche <bvanassche@acm.org>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/3fb5a98d-d44e-4edc-8220-149d411c1ab6%40acm.org.
