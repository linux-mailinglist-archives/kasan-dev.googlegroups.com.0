Return-Path: <kasan-dev+bncBD3JNNMDTMEBBK7ASXFQMGQEQWMEM2Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3f.google.com (mail-qv1-xf3f.google.com [IPv6:2607:f8b0:4864:20::f3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 1BC99D15846
	for <lists+kasan-dev@lfdr.de>; Mon, 12 Jan 2026 23:05:33 +0100 (CET)
Received: by mail-qv1-xf3f.google.com with SMTP id 6a1803df08f44-88a3929171bsf145065796d6.3
        for <lists+kasan-dev@lfdr.de>; Mon, 12 Jan 2026 14:05:33 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768255531; cv=pass;
        d=google.com; s=arc-20240605;
        b=cdJBBic3B7zo8ji4hNiB73yZ0XeADu1AIA52mOLP2X88MSMHOh93JanT0d9Xx/aZVr
         FD1pu/pb3n2IYgh6cAJ0sgt8T6E1Ad7e1BHLG0yB+CeJm8iktC6ERFYXwrfoce3eV3uA
         cFQq0aOGaVRuDkTlLroP16qRX4R+aF/uTWqZqyUfGzwlGf/oswVilD90qiU1XE45lgdh
         ehVkGfMatvGqcXB6suVSLg7rwM9l9bhHrpWWB1gShh48vq8PuV+xtgGH39ldl/g3wT7F
         VJT6XIm+ctkB/oQrtX7epfJgOvHtILTkvMMZRJbZli0Pqx4XROWoqDpB4ewcljt0gYOY
         vuiw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to:from
         :content-language:references:cc:to:subject:user-agent:mime-version
         :date:message-id:dkim-signature;
        bh=Zak2C4+xNPoBwk69OoefKf0Agv69dqJR9ahNEwhn/1g=;
        fh=t6EBdAVIuUWHHW54CCWdYZKit3hbyxcL1+r5/amyuwA=;
        b=dgf0ymuYpGlqQJInobegyNABFtk/0glRsQddvJdPmWI3+thCD0qmjWG+Nm8X4JmIgY
         jbJs1aJwfJYyUGL/9/7wEbbf0IRikr4q8iWcOu6B+9NLe0+8ySwat9KH/GYCb7I2N0ey
         tizp2wAkTgxbkMQoc0xT3ewZtOPPWYMWzlBizndYBrcKDkSyRDwN9IeFu4dQz7MMEu3t
         5hneMfst2R1BO8Cjh86ksBZr1vVq/qAJdG3OGZODmx9ZjzsmvTJdGElZA/+sGFwdZkrK
         81Iz/6qJm8xGc2xFwiki+RwlCs3qG/TGgBM7LfNxQEK1SCVgd5Dhrljj2QaXcO8G74SU
         KByw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@acm.org header.s=mr01 header.b=hs5fvItj;
       spf=pass (google.com: domain of bvanassche@acm.org designates 199.89.1.16 as permitted sender) smtp.mailfrom=bvanassche@acm.org;
       dmarc=pass (p=REJECT sp=QUARANTINE dis=NONE) header.from=acm.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768255531; x=1768860331; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:content-language:references:cc:to:subject:user-agent
         :mime-version:date:message-id:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Zak2C4+xNPoBwk69OoefKf0Agv69dqJR9ahNEwhn/1g=;
        b=GTLAGZ/kRb4Q/sjVQd7rNc8Zos1LqcRuvVlMnMw2mIM2r8eMi2YAvYPALwCvx/u63K
         S8Pm/hhV/u/H3YMkaU+aMsgCtBIZnEKbZ3qE9MgCfzkcoqtV3CMZrNx8FMfj9Q/TX/vG
         dzKgA4uu//ISI2KsUU4O4Wjv3d0bNv/fw5P1CVOmCUwOGzHxxchyUXNi1Z0e1z3cbW9R
         T0TY3PPnAHNj87OqRM7FYKH2t+AHOgkgWIEUhf7sV0aJbU/2n+rnT4y6Q1RvWyv0WedH
         tm/cx6h0DBw7LaWrXGyhbAqLpmWsfbQoBObQYP7myuVFuZv2BGu78ofJvaIN2fRkOH4u
         V35w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768255531; x=1768860331;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:content-language:references:cc:to:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:from:to
         :cc:subject:date:message-id:reply-to;
        bh=Zak2C4+xNPoBwk69OoefKf0Agv69dqJR9ahNEwhn/1g=;
        b=iPMf4KFCWCDFBWrBdOcEhGirsCtylesHfLZ51iox/svGp5JZTwFZ7I8dAAQvrQN9gb
         astJ9LqxazM1vyfNBBatKRisoI3PNvXpLsExnWDhqYxaiMCmX/qurhfI2CjHz0hnbgvg
         TXAmCIhte8t92iiIuTXYk0PYE5apPQ+UAj1GjM3Wyltlp/ZvMd/l4xStSLcqGVibO3fQ
         kJKWv+eKux7h5AmBogpTLDqHUvw7WCXu6TFbWT7ww//fkh032WhXnfxLnVKqJIg2xeBD
         G65meb/2mNjekhemo41EE3s5ERx1s6ZyBT54jiYlTKVLxJ40lEvpCZ/h+1hMw0ALd+sA
         Ztqw==
X-Forwarded-Encrypted: i=2; AJvYcCXpsJ045/mWcsSyeuVuBhbemRSPtVuVWbolUzG03KXaxf1tVfF/j5A0SFE7WXoBeBzEc8bE1g==@lfdr.de
X-Gm-Message-State: AOJu0YwZEQt+yTGYGhiJWae+GYcDDSv4qXmUUgAg6hkEyYyOYsjb1O77
	GK97/CMU89fiZD5K22CnXY6x4WfGqQxYx6puUqnkGvzq4UvUrj0Dk80v
X-Google-Smtp-Source: AGHT+IECLzBCa32NTV6rpiVldgMfF2v5ZYteP0LCImtUpMNVTo1ii9K4HsEKisLJltrhNc3CyJWbHQ==
X-Received: by 2002:ac8:7f0a:0:b0:4ee:1d84:306a with SMTP id d75a77b69052e-4ffb4a27ad8mr265565231cf.71.1768255531511;
        Mon, 12 Jan 2026 14:05:31 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+EYm3EaLf0gX1frwhZ/sVMahuG3QKY2vhhgyT4p5DZ+Tg=="
Received: by 2002:a05:6214:e82:b0:880:59ee:bbc with SMTP id
 6a1803df08f44-890756b83c2ls52942446d6.1.-pod-prod-09-us; Mon, 12 Jan 2026
 14:05:30 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCU98Wo5mo7tZtEZ5AFrTl7qw/e/I+6DxXjjRiROraiRSva2GE9RFo7E9bBOkZ3Y8CU8LXgA2MTnErc=@googlegroups.com
X-Received: by 2002:a05:6102:2910:b0:5f1:6c5d:9b28 with SMTP id ada2fe7eead31-5f16c5da2admr420869137.15.1768255530438;
        Mon, 12 Jan 2026 14:05:30 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768255530; cv=none;
        d=google.com; s=arc-20240605;
        b=jLbaYBccnmrXvAi3VJlDW8J2M0X7YlcFE7kAlPUQveFPJdXQaF10jR/GeLtSIYvLoJ
         4JZ+vtTot2v/TpMTDA5RNHdBk1GfEBkrtFbFNwgL4cXfV5Zo9LLLOlPpSUlx7wvyMcKs
         nC4hRF6bLwIewupUwdXJ3r0noySKbBw7+Lyey3oFsuxntKtV9IwNuEAcyzA9Bq0KsIcJ
         tn+VwJuJAchjZz4Gd/VAoUUZbYsw93ec23m9cY29/ti8MilCDk2P+G61OLk6KizY3IQV
         OcCafbLLDTG5JsAhGZa8kfq+4WbE5kwSMVQi3k58d61QjBKHeZgoMmkfsMqS032DuLpf
         vv7A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=z9Y4BPiPU5vZeqyn1OIEPsktkMud/fciou6gPOxT/Gg=;
        fh=Waj6xoWyFO3Afe3eZSPB9Mk4d9+KcqVnMFurmc1E+Y8=;
        b=iuLK3fz/nGLxlAlpNVViRga7e8I8eZ3oM1NpiNJsUBAalxmdOtThh3HMUyjFr4UDTM
         j2WqJPwJ11XaR7hOSoRiBBVB4/X7/Fz2ZmRTFLc4WFFfe/tCVMdgu97+opCL5KOseyvp
         wVTPQOpMP39h97JL82IYsMFWe1skwz2EjeaJeIuFZdPqh8jbJP+dqMPyffvPOTmpn2mr
         hFtw77FMv/Yms/DE9/xK8II2FFMShy14EDcbWrOjn6r4UTmMlEWQeUuM4+giofyOh9Q6
         mU/EF4o2KjSzFReLs7zsuJ4/hvIGrslHsp8WlUfDz4ehb0+qOSakHDYeFukzLvdSLqal
         kPTw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@acm.org header.s=mr01 header.b=hs5fvItj;
       spf=pass (google.com: domain of bvanassche@acm.org designates 199.89.1.16 as permitted sender) smtp.mailfrom=bvanassche@acm.org;
       dmarc=pass (p=REJECT sp=QUARANTINE dis=NONE) header.from=acm.org
Received: from 013.lax.mailroute.net (013.lax.mailroute.net. [199.89.1.16])
        by gmr-mx.google.com with ESMTPS id ada2fe7eead31-5ed0a398c30si532756137.3.2026.01.12.14.05.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 12 Jan 2026 14:05:30 -0800 (PST)
Received-SPF: pass (google.com: domain of bvanassche@acm.org designates 199.89.1.16 as permitted sender) client-ip=199.89.1.16;
Received: from localhost (localhost [127.0.0.1])
	by 013.lax.mailroute.net (Postfix) with ESMTP id 4dqmf137mPzlqfHK;
	Mon, 12 Jan 2026 22:05:29 +0000 (UTC)
X-Virus-Scanned: by MailRoute
Received: from 013.lax.mailroute.net ([127.0.0.1])
 by localhost (013.lax [127.0.0.1]) (mroute_mailscanner, port 10029) with LMTP
 id IkkI-SR9t1-b; Mon, 12 Jan 2026 22:05:22 +0000 (UTC)
Received: from [100.119.48.131] (unknown [104.135.180.219])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	(Authenticated sender: bvanassche@acm.org)
	by 013.lax.mailroute.net (Postfix) with ESMTPSA id 4dqmdS2QtzzllB6t;
	Mon, 12 Jan 2026 22:04:59 +0000 (UTC)
Message-ID: <3de714fc-7a18-4bcc-9ab5-c3831efbdb84@acm.org>
Date: Mon, 12 Jan 2026 14:04:59 -0800
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v5 36/36] sched: Enable context analysis for core.c and
 fair.c
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
 linux-wireless@vger.kernel.org, llvm@lists.linux.dev, rcu@vger.kernel.org,
 Ingo Molnar <mingo@redhat.com>
References: <20251219154418.3592607-1-elver@google.com>
 <20251219154418.3592607-37-elver@google.com>
Content-Language: en-US
From: "'Bart Van Assche' via kasan-dev" <kasan-dev@googlegroups.com>
In-Reply-To: <20251219154418.3592607-37-elver@google.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: bvanassche@acm.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@acm.org header.s=mr01 header.b=hs5fvItj;       spf=pass
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

On 12/19/25 8:40 AM, Marco Elver wrote:
> diff --git a/include/linux/sched/signal.h b/include/linux/sched/signal.h
> index a63f65aa5bdd..a22248aebcf9 100644
> --- a/include/linux/sched/signal.h
> +++ b/include/linux/sched/signal.h
> @@ -738,10 +738,12 @@ static inline int thread_group_empty(struct task_struct *p)
>   		(thread_group_leader(p) && !thread_group_empty(p))
>   
>   extern struct sighand_struct *lock_task_sighand(struct task_struct *task,
> -						unsigned long *flags);
> +						unsigned long *flags)
> +	__acquires(&task->sighand->siglock);

I think the above annotation is wrong and should be changed into
__cond_acquires(nonnull, &task->sighand->siglock). My understanding of
the code in kernel/signal.c is that lock_task_sighand() only returns
with sighand->siglock acquired if it returns a non-NULL pointer.

Bart.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/3de714fc-7a18-4bcc-9ab5-c3831efbdb84%40acm.org.
