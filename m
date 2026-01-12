Return-Path: <kasan-dev+bncBCHL7E6W5ENBB5E3SPFQMGQEGUKZVSQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23d.google.com (mail-lj1-x23d.google.com [IPv6:2a00:1450:4864:20::23d])
	by mail.lfdr.de (Postfix) with ESMTPS id 56170D11E6C
	for <lists+kasan-dev@lfdr.de>; Mon, 12 Jan 2026 11:33:26 +0100 (CET)
Received: by mail-lj1-x23d.google.com with SMTP id 38308e7fff4ca-38323e5932esf11997561fa.2
        for <lists+kasan-dev@lfdr.de>; Mon, 12 Jan 2026 02:33:26 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768214005; cv=pass;
        d=google.com; s=arc-20240605;
        b=CeFE7mGiz70QIJwaK3y/ty29Dhk0oY7l8/RMrKrzyDisn1wIQmmH3ZrB4AokKitnxj
         29Aw9a+sUNBfypGUeGUANRaNFfpjXma8ByHVn0G/qca/rYOfVqOHMk7mWcRifxUzekGM
         a04xquDrqOE5z+rVwTZ/ZYs3a9EnGo6keG3Iem59a2fkdYBhzwwD/pmPbpUwd/qHJhfb
         qxkqTh4ZDkWO0d2+LmxO818INkkOlbHO1h+6tVqshkZygVAQXN5evBXzGzQRwaXVm117
         ywjDYiA9vmDWS9e6/oOn0tr7XuHOWa8HEHZIhS8lLnnm/r622ngpA1gk1+IUM3nPBs5O
         DotQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=6Mmq5YBlGHpZfcc3qQ9xaD+tcV3JoKjk7rnnTkBcGPE=;
        fh=q/0FXT2iKcsZZ64GAJl7tU/lqmNas3xXzPGsAphi3IY=;
        b=YKVv2R7cso9VcxDv91HxO2UP9MnLy8P1945mmzxPtcOx5NEcllmsg8sWZV/nZzlUEH
         +lBfBimir7du3lGqN/wRae72SyHQhQTiMX/ywAhCSRiHTQUq+St6xXJwo+TO8mjScCJT
         PTATXVbiWbBQXERMZnfpXbSHt2HmF0NnSxYTZpVXPg90eozpgnUw9i+6zX83L9GhGQ1q
         kFx60tPRjrhKMgukVl+hjX5BSj8cKE7fmt7UKD/kAdKgvP+1bmwNMR1f4Vur6tuIsIlf
         f0CdGQ4SQ2KA++ksrGZGY3pBEVVd4XtMs6WnFSmdYDoLb1tJJwfRwDTCrDBkGT9/skvD
         tErA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=f1DEsroA;
       spf=pass (google.com: domain of maarten.lankhorst@linux.intel.com designates 198.175.65.12 as permitted sender) smtp.mailfrom=maarten.lankhorst@linux.intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768214005; x=1768818805; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:content-language:references:cc
         :to:subject:user-agent:mime-version:date:message-id:sender:from:to
         :cc:subject:date:message-id:reply-to;
        bh=6Mmq5YBlGHpZfcc3qQ9xaD+tcV3JoKjk7rnnTkBcGPE=;
        b=OBqookHZDoq0IANO3eHLQ2jI02cAX5KMltfgwtWEgonj07iIP91dUt6IihW7KMEzeO
         pGStTJEoCW761xgmlfLdzfjKBAUDvze2Rf7QESDm0/K0wfh1wbo+nn1ZRHPQauQi/WnV
         D5jNw0R61sIl4dd4/467JthAjSCKW74w7sapgUggXr1XYie/YUl4Rl9SEFm0YV8zK6hm
         3Zidyj46dju5KLob/SK7F1k1ZrM+VRB6WxmUyTmm5EtJ0MRkhhLMNJT8dWYzmeAR3nFs
         +swrFNlQ841yM8oVcOy+YhKRblO5mAxi4WxR2Bbz8B1DLyeNmFHEFcEY0uETnzqaS+NF
         vdzA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768214005; x=1768818805;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:content-language:references:cc:to:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=6Mmq5YBlGHpZfcc3qQ9xaD+tcV3JoKjk7rnnTkBcGPE=;
        b=m9nBaT79Dg/tIEaFOO01/ySdmcja4JtOY/k+AKYMLvBnLcjOHgtWdcyffXZOD0U1l8
         xg+8XdsLRQ3jtdfvRwxlA7GAsGEl0NsDOtrzViCqcsBGSq2mI+RKyJQBUGGNLMCX9QCx
         FJpUH8KXbr/kvQMjkKmm43hTPT29x94rFtBJv/7d2yhH8JKYgrzRFONduKXBcjHpxqNH
         EdVkyrWmls5TCVnVEPeRke+IULHHXGMBEWBmpMkj04DEQNZM8svNQcS+Dim7VAuxnFvz
         71bJS6cq2L7azVKFN1DNpdpqSfu9WDiaUaZWjRaW4ZdC3+qQJmK6q+1tlC9Yqiporq/x
         qLLQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUrjMkD/xI3osrGf9vNzBjfRNRIiIvdUR79rhQgZXeem7VoqvZkxcfFgxG2YSG9iSQUHf6fTg==@lfdr.de
X-Gm-Message-State: AOJu0YwXAzwzKcg8wvtkM8UgqzaM3CbQneX15zLe5b0Up17/lthuKFsT
	y6yy9Fc5KB8n741qeJdkcKdyLlLkcszRDEfIPMCcGDycDA9C24keQ+3y
X-Google-Smtp-Source: AGHT+IGoBVrJGTZL9OPEooeaSGNuBQlty9MIOWiXqsZUoQdfFQfVOXmQlUL/DJUlmyPbOP2Z8s7bUw==
X-Received: by 2002:a05:651c:31d2:b0:37b:ba96:ce07 with SMTP id 38308e7fff4ca-382ff683953mr54212381fa.15.1768214005119;
        Mon, 12 Jan 2026 02:33:25 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+GKf56yQHhqQtu+XuRWLnBkpVDU3hpaG4nca4x+beox5w=="
Received: by 2002:a05:651c:441b:20b0:37f:ab54:159c with SMTP id
 38308e7fff4ca-38300fb4aedls4985051fa.1.-pod-prod-01-eu; Mon, 12 Jan 2026
 02:33:22 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUjBO/j1RjaZqPqhCVZiJ9I2gw8zaDv4WvFHQja83ANMx/+Uq1a0UxaKByUJ7okP3SjohSw3RAzDrQ=@googlegroups.com
X-Received: by 2002:a2e:a593:0:b0:380:a1c:702b with SMTP id 38308e7fff4ca-382ff66892dmr42130041fa.5.1768214002121;
        Mon, 12 Jan 2026 02:33:22 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768214002; cv=none;
        d=google.com; s=arc-20240605;
        b=UmNtsG+QdjF6qLrTcb6FkPq0QOesWqKxqrt0TosfrrcWGPzRsrs5atl6Mow59eY6Ql
         hpwAurQfF5gwXthzbfdgEGt65LNzqtzTzb8VVdJMhyp8yc90NeO8cBnpMZh0Wo1poI7G
         RKEzX6NCnEKd99RSOmqkYwibWIONVEjRnI1JoD3DSNnTSdwjJT4ZkpFOSBLIo2WbkXX3
         ZDZ31u7+AZXJRTKcXJz2qx5HC3unNVRO78E+aYkFgtrXFr4y5kHU6zPBvMYOMOfMCnH5
         rSfgmnJv7io2Cz+n5ceqz8iiCIj+KNYq2Q0wAhtR1o22hVw3C2Y73c9S0Gd+j1Zz3Mgr
         itzg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=XSeDYcO86cEIXpPJgflnLo7t2+igEm9lsEiKHctLN/c=;
        fh=WmSLSzhqmVCL6r4rE9SauH8x0nBWvjWhmJ9J83OCSvo=;
        b=Od/DobgEvL+4y1VXeR9sN2brpLH06JmV+2snIrBKtrKwFDYA3bAnQBe/qWkZsx3y0k
         m6IPXOhoi1vwkurI/KWVN+sQ5SjwogVymR8UD7qYnX/IEd2HwZKjeMa0pscH/UtQ3ZQ1
         J6fesFQvKnobepvURScStUVPIhhS3026+V+u08gv75pU0I2VKfYyKYk+bpdBoUDDBJ9k
         vyxQsVvv72tAbg5R9ycgqpZHOT9kPdpIB4C8uaxJz2xzySVyRZnv9wX2YVsz3s9BIA3E
         pCzITz/B7UfkaR4dMmCkejXodPSlCNDin9+kVytqTgO9lEeZdtjzP3QodcErw+lOfdaT
         wsjA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=f1DEsroA;
       spf=pass (google.com: domain of maarten.lankhorst@linux.intel.com designates 198.175.65.12 as permitted sender) smtp.mailfrom=maarten.lankhorst@linux.intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [198.175.65.12])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-3831a5fadf5si1523081fa.5.2026.01.12.02.33.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 12 Jan 2026 02:33:21 -0800 (PST)
Received-SPF: pass (google.com: domain of maarten.lankhorst@linux.intel.com designates 198.175.65.12 as permitted sender) client-ip=198.175.65.12;
X-CSE-ConnectionGUID: Nf5Ze9m4Tc+3d7qRiJgjAw==
X-CSE-MsgGUID: wfAATafISy2YhqURgScUaA==
X-IronPort-AV: E=McAfee;i="6800,10657,11668"; a="80939937"
X-IronPort-AV: E=Sophos;i="6.21,219,1763452800"; 
   d="scan'208";a="80939937"
Received: from orviesa001.jf.intel.com ([10.64.159.141])
  by orvoesa104.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 12 Jan 2026 02:32:39 -0800
X-CSE-ConnectionGUID: KeVRm3ThTIyu/02WLS2Cvw==
X-CSE-MsgGUID: T5zF6Dw6TdejExXJJsJSFw==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.21,219,1763452800"; 
   d="scan'208";a="241588226"
Received: from fpallare-mobl4.ger.corp.intel.com (HELO [10.245.245.90]) ([10.245.245.90])
  by smtpauth.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 12 Jan 2026 02:32:28 -0800
Message-ID: <1502e5eb-0ac7-4581-85ce-2f0c390bd7db@linux.intel.com>
Date: Mon, 12 Jan 2026 11:32:25 +0100
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v5 20/36] locking/ww_mutex: Support Clang's context
 analysis
To: Bart Van Assche <bvanassche@acm.org>
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
 <8143ab09-fd9b-4615-8afb-7ee10e073c51@acm.org>
Content-Language: en-US
From: Maarten Lankhorst <maarten.lankhorst@linux.intel.com>
In-Reply-To: <8143ab09-fd9b-4615-8afb-7ee10e073c51@acm.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: maarten.lankhorst@linux.intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=f1DEsroA;       spf=pass
 (google.com: domain of maarten.lankhorst@linux.intel.com designates
 198.175.65.12 as permitted sender) smtp.mailfrom=maarten.lankhorst@linux.intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
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

Hey,

The acquire_done() call was always optional. It's meant to indicate that after this point,
ww_acquire_lock may no longer be called and backoff can no longer occur.

It's allowed to call ww_acquire_fini() without ww_acquire_done()

Think of this case:
ww_acquire_init()

ww_acquire_lock_interruptible() -> -ERESTARTSYS

ww_acquire_fini()

Here it wouldn't make sense to call ww_acquire_done().

It's mostly to facilitate this case:

ww_acquire_init()

ww_acquire_lock() a bunch.

/* Got all locks, do the work as no more backoff occurs */
ww_acquire_done()

...

unlock_all()
ww_acquire_fini()

If you call ww_acquire_lock after done, a warning should occur as this should no longer happen.

Kind regards,
~Maarten Lankhorst

Den 2026-01-09 kl. 22:26, skrev Bart Van Assche:
> (+Maarten)
> 
> On 1/9/26 2:06 PM, Marco Elver wrote:
>> If there's 1 out of N ww_mutex users that missed ww_acquire_done()
>> there's a good chance that 1 case is wrong.
> 
> $ git grep -w ww_acquire_done '**c'|wc -l
> 11
> $ git grep -w ww_acquire_fini '**c'|wc -l
> 33
> 
> The above statistics show that there are more cases where
> ww_acquire_done() is not called rather than cases where
> ww_acquire_done() is called.
> 
> Maarten, since you introduced the ww_mutex code, do you perhaps prefer
> that calling ww_acquire_done() is optional or rather that all users that
> do not call ww_acquire_done() are modified such that they call
> ww_acquire_done()? The full email conversation is available here:
> https://lore.kernel.org/all/20251219154418.3592607-1-elver@google.com/
> 
> Thanks,
> 
> Bart.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/1502e5eb-0ac7-4581-85ce-2f0c390bd7db%40linux.intel.com.
