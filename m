Return-Path: <kasan-dev+bncBD3JNNMDTMEBBROTSS6QMGQEKRL24PQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf37.google.com (mail-qv1-xf37.google.com [IPv6:2607:f8b0:4864:20::f37])
	by mail.lfdr.de (Postfix) with ESMTPS id 004F5A2B42A
	for <lists+kasan-dev@lfdr.de>; Thu,  6 Feb 2025 22:29:42 +0100 (CET)
Received: by mail-qv1-xf37.google.com with SMTP id 6a1803df08f44-6e433c65b40sf30943546d6.3
        for <lists+kasan-dev@lfdr.de>; Thu, 06 Feb 2025 13:29:42 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1738877382; cv=pass;
        d=google.com; s=arc-20240605;
        b=IoVwuZIy2ehEqJhvbR8Vr6T2Wi3Sik9QxO/hJWoiVg8q2f3ThiQIX/CeoxsqdtFvvD
         +yJ7xHm4QGjJcqzozt2ZLqrbx/M5Xwc60x0k83yG0AMuLb7WgRSENTV/5VZCDqT5WzRz
         NdZbZ4/b3QmU8c7U88qo+luoZQrlj+AweBJ9zOjGkKRKTrI2uMKoonLip6Ba++rer3w9
         EPSuatdGhEvik1zJjr8u7uHFe4+T5yjsEzxuSMxEgJNOIHCM/UEqTT2WVnqoV52yjqkp
         NzombYZpZnV9S2vtIHU8gxpmIjibQePUcMQOGacs4VMwZ7EdZEqUnqi7zqLhJzwhbWVy
         qH0A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to:from
         :content-language:references:cc:to:subject:user-agent:mime-version
         :date:message-id:dkim-signature;
        bh=mrio1yMqQLIo4n855WoC4a/0MXPo6jNgXcqgcI+bx+8=;
        fh=rb3PmaWY0urZAznqGI5nAVghExuujaIPD96U0jhgFow=;
        b=XrcLsqqSgmmA/RQzrlN9nxlIH/J7SfQ4CVPQOIx1t4fiDdi0kVCc6PcijIoXRvAL1a
         EgsxBIup7zGrJyaL4XRLaLJfe5xSkhHOjeEjoi0W2kl22XaO/MPYntnW7jojCutPf3me
         KnjkXW5JLzS8AOL+Z/4bipwMx6xAAUy6uzsno31f7DEAebfQN2KLxQ2TPxkZWsywWIoA
         yV3DbmERpRzyfZK2Hcx/OTK3TDezWI1kEJB+An3Xh3FMrxcLiz0hDuYjVx3HPq+LwrnY
         PsireEpcHtnpwiMT03+l/SDmYdbTcfd7mmzeL3ysxwZ83bxJ2yh25Gp0mR+EbemQzAf1
         camw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@acm.org header.s=mr01 header.b=yUhEgFbx;
       spf=pass (google.com: domain of bvanassche@acm.org designates 199.89.1.12 as permitted sender) smtp.mailfrom=bvanassche@acm.org;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=acm.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1738877382; x=1739482182; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:content-language:references:cc:to:subject:user-agent
         :mime-version:date:message-id:from:to:cc:subject:date:message-id
         :reply-to;
        bh=mrio1yMqQLIo4n855WoC4a/0MXPo6jNgXcqgcI+bx+8=;
        b=wbMY2MfEoFeXdblxm/NTrA/D7Df/MGsVOwS1ANZUtTPs2x4gd+ZK2UQ6GgEam0pAnS
         Ifp5Zooz0SkVmdFUedjy0piGGt7zcfZuGjMUd+81XQwBgTx5PWYeO5aHXDoefv6MuKho
         VHaC5Xf1/iNEe+64NMbwtcDiXHv2dRxfAzM+JktEF8/SGLOuiRnTuxl1B54kDTWOHiCT
         /F8PS/s9MxgBHrUZvht+7RATJieX0nEPbV2wzfb9hZfBlbaioXoI2BtaZ6xrXlRoeIbb
         fcuS8ErK6Z9PWWz1/luIF5oyE2q61lIpTn+lStczK9TGEQcv7JrOhmv/eFp/MA3zLbBU
         4tIA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1738877382; x=1739482182;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:content-language:references:cc:to:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:from:to
         :cc:subject:date:message-id:reply-to;
        bh=mrio1yMqQLIo4n855WoC4a/0MXPo6jNgXcqgcI+bx+8=;
        b=XStEDZ1BQcZN4dQi2bR/y6a9V5X9O617h+4Si2lVbEDph83tqE/K1G3zRSW7wvTue3
         4sdB8zicouvJ0HvRyFuNBxIXRumAsj3Hush7Xw2QWek4IpNNEmrmBYaUezsxMoR3lFk2
         bizsqhxNIK7eXyDdM5+MyXZIvGBmfHZvvc0RkKwe/UeK6Uut72juxSP5gIZqXV0Sx7fZ
         t1DiS3bR8uetPPGpjzhhBxJjRLH09WTqvCKmp9wy74MZn87Ss+TpO03gQZ5+xjYsDfvn
         BICTDF9K+B3iLraZepePLtY5wLgD0TDFTlyPqAQ4LzxH2h60qh2qfK2J/ekKj1sgv16E
         kgYQ==
X-Forwarded-Encrypted: i=2; AJvYcCWSDXxLs9CdKvd6evL14V1qmsBl4pGFXBCU/GDa+oVD96J9fJGv5rOla1BQxt2utRbnMwbDWA==@lfdr.de
X-Gm-Message-State: AOJu0YwD78r2AkPplY1mngWHX4gkofsfoNvlWVLTpZUQ2+0Y8vdgXq86
	LX7lgwvOyzCVioOIRvHIOIQ9WfrbeYWATtancJZR/BPpKwDRn/pp
X-Google-Smtp-Source: AGHT+IHgZpq5w+mvYZzVXYU98w1xzs0YU3tq6kNFBZaWvIYA737wnhCz2X3l1VGQAFSmuvfec7NaJw==
X-Received: by 2002:a05:620a:2621:b0:7be:2a68:6d79 with SMTP id af79cd13be357-7c047c34ad5mr153613985a.7.1738877381550;
        Thu, 06 Feb 2025 13:29:41 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h=AT6nircycF9YgvGTbJK7VmePu+XoYIN9IMW/Mx1eCJb/eFCMDA==
Received: by 2002:a0c:e850:0:b0:6e1:8e40:5ef6 with SMTP id 6a1803df08f44-6e444f932ecls2385496d6.0.-pod-prod-03-us;
 Thu, 06 Feb 2025 13:29:40 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUrgW0tPML/iLtenZF6msCOJf47W5P8tIEndy83kvdliAFQ4TZcT/e3Jh6vDLaGuzQLGarbLGyI/aA=@googlegroups.com
X-Received: by 2002:ad4:5fca:0:b0:6d8:a5da:3aba with SMTP id 6a1803df08f44-6e44566e7d3mr6927546d6.20.1738877380381;
        Thu, 06 Feb 2025 13:29:40 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1738877380; cv=none;
        d=google.com; s=arc-20240605;
        b=d0jCQAK+hSKqE/yT5jgJS4QOV2wQwaSc+FrVydri2A+ZzruJZBkKKIBzxxQ0gCKyK4
         cHCvcOiTWTz+9+VgF2cJXtte6uCyZspY7vjAKKlUCvorZN8fvJuLY3J+wOEMPU+Pwl8R
         JA96eWiSPJjmbQ1uYp1TbSaGemQLwzTpI7RrUSoSyO7biwqMF8I9uJXu678UPYv4Z7kb
         QPccnlDLZEm4vhQpG5rdRzU8Cfb5LuWLcNHMCmhM/AP6RvNxULAKLWhlsuyasKF1TP6f
         RaUzI3vFMMl2lb2BHF0IkBx6qEM1kCgIVVFDNxLCJreRZ51VGyn/UjRE13IRvroVjmDX
         Cg5w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=ygRwFLCUciivthCdQYJVLmlK5fpOtVZDy4dVAV/W3mE=;
        fh=0Ovo09T/l7iyAM2CZR26Zg4xB/uj/2vRoIXmdAf37Lk=;
        b=Z1Hu2Pg9w2MRG0n1bTmrnrcA+0FtwH8JHrRUogQZ9N/paGAamw5JLEp7dj+mwHPrdS
         CDhF3nfiPiH08k2uxpCkDaDCWclNAcaNGkmeFANOph05c/nCkIcl+xXKLQa4fkYvTu3X
         ojuInexvvc5rYGv0d0QDJ9WqG4bwufTpteMe57FxzACWDX3bU9Pi49EYr2H003RovPJx
         WiIQr6jYV0G6deAU9c4NJRh9Ab0xG1Yul0cqEJAWzIPsIGHH8TEgIb1APTp1rwtXALR+
         6Dt8Ne5QxZ6QF8uoSZ4zVXWy2CsqVLZG6O9ib3LLzR9nvOZLbijPB0V6m/cIaHdPgmx9
         mJrA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@acm.org header.s=mr01 header.b=yUhEgFbx;
       spf=pass (google.com: domain of bvanassche@acm.org designates 199.89.1.12 as permitted sender) smtp.mailfrom=bvanassche@acm.org;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=acm.org
Received: from 009.lax.mailroute.net (009.lax.mailroute.net. [199.89.1.12])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-6e4473c0a5asi27396d6.0.2025.02.06.13.29.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 06 Feb 2025 13:29:40 -0800 (PST)
Received-SPF: pass (google.com: domain of bvanassche@acm.org designates 199.89.1.12 as permitted sender) client-ip=199.89.1.12;
Received: from localhost (localhost [127.0.0.1])
	by 009.lax.mailroute.net (Postfix) with ESMTP id 4Ypqxb3yCRzlgTwF;
	Thu,  6 Feb 2025 21:29:39 +0000 (UTC)
X-Virus-Scanned: by MailRoute
Received: from 009.lax.mailroute.net ([127.0.0.1])
 by localhost (009.lax [127.0.0.1]) (mroute_mailscanner, port 10029) with LMTP
 id NqM4EdqVb7bb; Thu,  6 Feb 2025 21:29:27 +0000 (UTC)
Received: from [100.66.154.22] (unknown [104.135.204.82])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	(Authenticated sender: bvanassche@acm.org)
	by 009.lax.mailroute.net (Postfix) with ESMTPSA id 4YpqxB2wn3zlgTw4;
	Thu,  6 Feb 2025 21:29:17 +0000 (UTC)
Message-ID: <4ce8f5f2-4196-43e7-88a2-0b5fa2af37fb@acm.org>
Date: Thu, 6 Feb 2025 13:29:17 -0800
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH RFC 07/24] cleanup: Basic compatibility with capability
 analysis
To: Marco Elver <elver@google.com>
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
 Peter Zijlstra <peterz@infradead.org>, Steven Rostedt <rostedt@goodmis.org>,
 Thomas Gleixner <tglx@linutronix.de>, Uladzislau Rezki <urezki@gmail.com>,
 Waiman Long <longman@redhat.com>, Will Deacon <will@kernel.org>,
 kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org,
 llvm@lists.linux.dev, rcu@vger.kernel.org, linux-crypto@vger.kernel.org
References: <20250206181711.1902989-1-elver@google.com>
 <20250206181711.1902989-8-elver@google.com>
Content-Language: en-US
From: "'Bart Van Assche' via kasan-dev" <kasan-dev@googlegroups.com>
In-Reply-To: <20250206181711.1902989-8-elver@google.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: bvanassche@acm.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@acm.org header.s=mr01 header.b=yUhEgFbx;       spf=pass
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

On 2/6/25 10:10 AM, Marco Elver wrote:
> @@ -243,15 +243,18 @@ const volatile void * __must_check_fn(const volatile void *val)
>   #define DEFINE_CLASS(_name, _type, _exit, _init, _init_args...)		\
>   typedef _type class_##_name##_t;					\
>   static inline void class_##_name##_destructor(_type *p)			\
> +	__no_capability_analysis					\
>   { _type _T = *p; _exit; }						\
>   static inline _type class_##_name##_constructor(_init_args)		\
> +	__no_capability_analysis					\
>   { _type t = _init; return t; }

guard() uses the constructor and destructor functions defined by
DEFINE_GUARD(). The DEFINE_GUARD() implementation uses DEFINE_CLASS().
Here is an example that I found in <linux/mutex.h>:

DEFINE_GUARD(mutex, struct mutex *, mutex_lock(_T), mutex_unlock(_T))

For this example, how is the compiler told that mutex _T is held around
the code protected by guard()?

Thanks,

Bart.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/4ce8f5f2-4196-43e7-88a2-0b5fa2af37fb%40acm.org.
