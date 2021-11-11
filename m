Return-Path: <kasan-dev+bncBDAOBFVI5MIBBT7NWOGAMGQEUCEGQBQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x340.google.com (mail-wm1-x340.google.com [IPv6:2a00:1450:4864:20::340])
	by mail.lfdr.de (Postfix) with ESMTPS id 46BFB44D55D
	for <lists+kasan-dev@lfdr.de>; Thu, 11 Nov 2021 11:56:16 +0100 (CET)
Received: by mail-wm1-x340.google.com with SMTP id g80-20020a1c2053000000b003331a764709sf4614123wmg.2
        for <lists+kasan-dev@lfdr.de>; Thu, 11 Nov 2021 02:56:16 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1636628176; cv=pass;
        d=google.com; s=arc-20160816;
        b=bEZzfCk8g0S0K18i3gqpfGLuv8MQ7MOK9bqr77foP8O++Pb69EGs2yLwclAYWglhbF
         D8IY2EE3cfHTfC5bw5lKQgx5c3AI2nGu5PnmJNVv+74zg9l9Ds0gofhzd2f1C4fkGJFv
         NWpdDZmxldLZjlO1KgZC8RoP4AckVGZDmTsCjnLIUVdtenccvSnnhH+RpjInilnKDviZ
         BB6q3GfgV2s5dHmJxU9qEzpkrfKEk572050FQn2pJli2IQfRC76ntyh/NwrOkyCuAwsw
         C6/0Vvndme7UlD8ddUoHNxTrTfFs1lyd53j6m6Zz96cbsgS66xdsG+AqzexC3Qr34fge
         3vAw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :references:in-reply-to:subject:cc:to:from:sender:dkim-signature;
        bh=IBx3GbXuLbsMpNtkarnToIr5Tcb+IG84cAvZt4gku4k=;
        b=OBHmau5jZmSzgj9nmNlm6e4lajFHuu3+WkaSMmUiUkjmF5X7KXyZB39qIOS/FvcdAO
         WsmEgLFoa5b9Aj8+NXCT/ltpTvnGVcPXC+euvLpgoN2yJB1GSI5v/8L6WJqmbnuc4zg7
         rP2Mb+3/vyvVCMp4wJyQdSSnVakRDlDs9NIIFB6j988cH9+jBBZt4weS23ExXdsPmc79
         Kqaa7enN8fQOYmEw83WwBCYW3i1gwi2DFcckrAmIU10YsFY2PpRVtDzNNiLOmzkTsnq3
         nuHvNzEWmqv20PFldORgM0f1yd6HjvwI2OsPMd910JFl+s5kwM18llURHUGCZ6whF1Cs
         mN0w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of valentin.schneider@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=valentin.schneider@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:in-reply-to:references:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=IBx3GbXuLbsMpNtkarnToIr5Tcb+IG84cAvZt4gku4k=;
        b=J1m5M88zJ2aTIU5E0g8vuwd7H7Xu1aqnmkd0x/FW8e8uynOIlbLYHdnZWupUKEp6oY
         u92cKaFTnwOIXtN0BTc596zBW+bT9MU4ITe21D8qmhbx6xkbkYlNNFA/OJ2phNism4Q/
         82q5GY9CQW9g8V0fmaxUWRrizOT8uRcED+UZOJnGEwCThClUgc+HLx0hlVdZF3LuxoZc
         UXkd5yA1xFEEjN4jWZoH6pZIw3GRw/4XrmdInmt2PHe4lpw5zRYI1QXH3ERH5pdr90NA
         YaRltiCg+cmeHR2xkwDI7HXSdyhz8ou8xsVYZTTutT+ReQZNNGBmihyb813YWs+thqVo
         uepg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:in-reply-to:references
         :date:message-id:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=IBx3GbXuLbsMpNtkarnToIr5Tcb+IG84cAvZt4gku4k=;
        b=SAAngmBNrf+6w1s6KJAhDUznTl2Oe4gL3MVU2K19QrT5gP5e/tQEB0HA9JiQ61xTMV
         fl5dXMB1GqtbWV/wFPlYQh0Zn/C+8HiCALNpUX2oUMYyHRg93SZShmswZcl+lr9G6QAr
         C2igEH8mlO1z8Qa39lcSKldxd8zhRmNN/djDBFLKc+DsxIjlpEh1MUAKRGOlFbHB8fYU
         jdQ1pvIKIALI0pCP3COLMKNR9SwBbcLgGgJyss3tMDNQVDXqTA5SPeDCcY9H0J/gZ57X
         +MTj+FpnELhZDtCqiYmKlRyPJjdhC9AS9iga3IXpDJug7Cc1DP2oLwtPnOPx/JkevuL7
         DEeA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5316eCl1uz51rnIoyALg95rOLEZsU6hs6tmiompslB4bdEPyzaX7
	K5JpNpUNzXy0N0mALZ8xxj0=
X-Google-Smtp-Source: ABdhPJyo+6H6DionsN/RpgAROzWL2vbh7XQgMtmzcuyEjeQKk1sETx6ImSgRCgA77GregQGKBkYUMQ==
X-Received: by 2002:adf:ec90:: with SMTP id z16mr7991526wrn.247.1636628176088;
        Thu, 11 Nov 2021 02:56:16 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:23c8:: with SMTP id j191ls1291489wmj.1.gmail; Thu, 11
 Nov 2021 02:56:15 -0800 (PST)
X-Received: by 2002:a05:600c:a08:: with SMTP id z8mr7444956wmp.52.1636628175227;
        Thu, 11 Nov 2021 02:56:15 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1636628175; cv=none;
        d=google.com; s=arc-20160816;
        b=goo8ZZa0rUVTGUWrjQudi4lSG9eWlqxSG7hSc7WlJehvdPh4STps4mQMXcv53tA5gQ
         h1/fi7R2vzZ8I36nkMCJVNaokvIsMZEa/JFmIyop8NN813KLB0iSgFg3YX6qQnHnB/E6
         g87Djyz4Lcyenpby6AUTtC1Qfm/U9GxD3NVGL7LLalFg0FKxmaREvf5L4tYWozU3dNdI
         dl9UgkqjatPSaEu1XNtVatUPodmOvpfOneOMU3NgCh0J+h5a6rgzoIYajMmULT9ShUOX
         4X290v0knfrzALyBQsG8BjjNQUHIXGejyNJ8AVTpLyKErd1kUxxXhFsnWLJz+qpjnqCS
         7kkg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:references:in-reply-to:subject:cc:to
         :from;
        bh=A6C8awyxO4vCV8zYMAIAiWKZtb+FvJRxHnzbl8red/I=;
        b=1B1bagRz/50EnVt4c4xFPs0eTnU1AIW44ajkJEJKMjM/ZAKzl9/p2SQxbzZZBa2N3N
         T5rFesbcfYGN37h2AeuIAQXO1r+W4tKZgaXE8IAI6NbqMnNzKavbENkDKEOtaJRPzMLf
         kZReftlB7f/CSCgnkXbIzz3432XGBcbkZ8msmEAuGoQcXeJLbM6CP/96PUqxlv873nNz
         cG2XFNsaCgF1gctTup3lVEN5SNOVRte+kRiZ1gj8xITJb+Ognp17WUgTuurZuNyAkSqS
         8/SGPXIrsSXI/NMVTYbrhLPQGu76TPgLK28JZTLzsDMvges4jBLuDWpslUsHA5OftmIk
         YquA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of valentin.schneider@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=valentin.schneider@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id c2si227371wmq.2.2021.11.11.02.56.15
        for <kasan-dev@googlegroups.com>;
        Thu, 11 Nov 2021 02:56:15 -0800 (PST)
Received-SPF: pass (google.com: domain of valentin.schneider@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 54C17D6E;
	Thu, 11 Nov 2021 02:56:14 -0800 (PST)
Received: from e113632-lin (e113632-lin.cambridge.arm.com [10.1.196.57])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 3BE0E3F70D;
	Thu, 11 Nov 2021 02:56:12 -0800 (PST)
From: Valentin Schneider <valentin.schneider@arm.com>
To: Marco Elver <elver@google.com>
Cc: linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, linuxppc-dev@lists.ozlabs.org, linux-kbuild@vger.kernel.org, Peter Zijlstra <peterz@infradead.org>, Ingo Molnar <mingo@kernel.org>, Frederic Weisbecker <frederic@kernel.org>, Mike Galbraith <efault@gmx.de>, Dmitry Vyukov <dvyukov@google.com>, Michael Ellerman <mpe@ellerman.id.au>, Benjamin Herrenschmidt <benh@kernel.crashing.org>, Paul Mackerras <paulus@samba.org>, Steven Rostedt <rostedt@goodmis.org>, Masahiro Yamada <masahiroy@kernel.org>, Michal Marek <michal.lkml@markovi.net>, Nick Desaulniers <ndesaulniers@google.com>
Subject: Re: [PATCH v2 2/5] preempt/dynamic: Introduce preempt mode accessors
In-Reply-To: <YYzaLTtf1tFbqDSn@elver.google.com>
References: <20211110202448.4054153-1-valentin.schneider@arm.com> <20211110202448.4054153-3-valentin.schneider@arm.com> <YYzaLTtf1tFbqDSn@elver.google.com>
Date: Thu, 11 Nov 2021 10:56:06 +0000
Message-ID: <874k8jrmex.mognet@arm.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: valentin.schneider@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of valentin.schneider@arm.com designates 217.140.110.172
 as permitted sender) smtp.mailfrom=valentin.schneider@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
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

On 11/11/21 09:54, Marco Elver wrote:
> On Wed, Nov 10, 2021 at 08:24PM +0000, Valentin Schneider wrote:
> [...]
>> +#ifdef CONFIG_PREEMPT_DYNAMIC
>> +
>> +extern bool is_preempt_none(void);
>> +extern bool is_preempt_voluntary(void);
>> +extern bool is_preempt_full(void);
>> +
>> +#else
>> +
>> +#define is_preempt_none() IS_ENABLED(CONFIG_PREEMPT_NONE)
>> +#define is_preempt_voluntary() IS_ENABLED(CONFIG_PREEMPT_VOLUNTARY)
>> +#define is_preempt_full() IS_ENABLED(CONFIG_PREEMPT)
>> +
>> +#endif
>> +
>> +#define is_preempt_rt() IS_ENABLED(CONFIG_PREEMPT_RT)
>> +
>
> Can these callables be real functions in all configs, making the
> !DYNAMIC ones just static inline bool ones? That'd catch invalid use in
> #if etc. in all configs.
>

Ack

>>  /*
>>   * Does a critical section need to be broken due to another
>>   * task waiting?: (technically does not depend on CONFIG_PREEMPTION,
>> diff --git a/kernel/sched/core.c b/kernel/sched/core.c
>> index 97047aa7b6c2..9db7f77e53c3 100644
>> --- a/kernel/sched/core.c
>> +++ b/kernel/sched/core.c
>> @@ -6638,6 +6638,17 @@ static void __init preempt_dynamic_init(void)
>>      }
>>  }
>>
>> +#define PREEMPT_MODE_ACCESSOR(mode) \
>> +	bool is_preempt_##mode(void)						 \
>> +	{									 \
>> +		WARN_ON_ONCE(preempt_dynamic_mode == preempt_dynamic_undefined); \
>> +		return preempt_dynamic_mode == preempt_dynamic_##mode;		 \
>> +	}
>
> This needs an EXPORT_SYMBOL, so it's usable from modules like the
> kcsan_test module.

Ah, wasn't sure about that one, thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/874k8jrmex.mognet%40arm.com.
