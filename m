Return-Path: <kasan-dev+bncBCR6PUHQH4IKHRNTXEDBUBFK5L6TK@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc39.google.com (mail-oo1-xc39.google.com [IPv6:2607:f8b0:4864:20::c39])
	by mail.lfdr.de (Postfix) with ESMTPS id A5EDF9C0A75
	for <lists+kasan-dev@lfdr.de>; Thu,  7 Nov 2024 16:54:12 +0100 (CET)
Received: by mail-oo1-xc39.google.com with SMTP id 006d021491bc7-5eb60cc6d66sf799710eaf.0
        for <lists+kasan-dev@lfdr.de>; Thu, 07 Nov 2024 07:54:12 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1730994851; cv=pass;
        d=google.com; s=arc-20240605;
        b=jCG5meJ/jhDTuKbkzvCeEEBBS1a3u2KpT6iSoSnb3enb0F2VPB0EfTHEfw5Suxq+8B
         SoJ8RGKM1zxCoFNgEU7XXb9OKNZ1hroByTNSRaj+GPqriLzIg1ScBRrSvcrs2k1zKICe
         f0EIwWJdfWmBIW+VrmfdxhBzIPZasQfnUeABhDQFau3GtZe7XEKfv2D6HYapADW2d5/T
         gF10zZf72hjfJqkbS3+zQYdtlZbB+QVrSrqOVvsCuPT74PUqjvDciZ/RNWYCOt3vVlh6
         V/rHBCMlomzLH60OEf5SBUjJcJ9H/bAt6hcYIiL7cWFADvD+QgKP7avwVv66gumf4y3O
         7WGA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=1awyfeJn/+bHXWbCqkXl1NRmX6mvBUPY1JZN/6b76Jc=;
        fh=u4HCpjC8QnN+5CZ0MUmqrk9Y+wpVBGBJGBdkmiHfH6I=;
        b=cAkh3h7TBJSiW/fUKK8kYDZJ22Jc5GOTFzwwNzE4ZwFV2tPIyhVy0wyYYsazRO5oLQ
         aI5/sK9fnQRFPQg+T80Ja6xrzyKVYyS+aed9nonEsGoerq2QpxNr0TZfQZUfX1S/3zl5
         Z6q9biYHVjS9b2Xb1K+1iBOvVMSxsYgxar5mN8m6M8qKgqnfOBo5cIt/CxzaVEME4dHK
         vUk9c2nVL+rElm/asdQYBZC9UundGw8/3xfWht/Nuz591URxxeGqrwujqAaTfdFLSfGd
         LC1BzkQm2T3RuD0/MBZEC0+OZKcipqRRWe80Dyy1b0M3EuQTr+5dPY4oLUw6zrS8OUoK
         8xhw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@efficios.com header.s=smtpout1 header.b=rrqT6gFA;
       spf=pass (google.com: domain of mathieu.desnoyers@efficios.com designates 2607:5300:203:b2ee::31e5 as permitted sender) smtp.mailfrom=mathieu.desnoyers@efficios.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=efficios.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1730994851; x=1731599651; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:content-language:references:cc
         :to:subject:user-agent:mime-version:date:message-id:sender:from:to
         :cc:subject:date:message-id:reply-to;
        bh=1awyfeJn/+bHXWbCqkXl1NRmX6mvBUPY1JZN/6b76Jc=;
        b=BRlPjUfw/OB+z3ifbO10AMlaCgQsqOoIQnjeKTBs/mjxlpo1X0LZJ1AR+EBXh1tNk3
         oNPs37JVeLzldWyfEvTnq5nRXPn/JISSBdubT3Inyilie7LFYjnsNI5un8NSA3shvf+W
         Qdk7YFshlfhJVShkaeZlFbMi4eGG5+YNyRTo4MdQZ5OK+WcImRn4XxEGeiu37RaoVodd
         zFC90+VZxmUbUHD0a+qMU6J1Hk+UBvR+QLppkeaJ5usx4STgaTvmGDSbNQszwXSWq4YM
         BYh5+c6WgJAHqsRo6JeCKFbleytJp/2u7rr7CgymF8E2CG/xahxbiqQdqq4NFFU7MRLN
         bZ6A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1730994851; x=1731599651;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:content-language:references:cc:to:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=1awyfeJn/+bHXWbCqkXl1NRmX6mvBUPY1JZN/6b76Jc=;
        b=lfK9IC1fOHx6y1YVuzN1FIHQMaa2cQ+nfwuAD5B9KbDhvfNWG6wAA3MgFvTT8aybNz
         TGGpuez8BNsLRsK+q+vpDU6vUQAdue+E4Dl7I/6iU3PMOSiu6kB0xfbcVi1SIsUSeEai
         VqVfAooaY2kyG9YNso1lPqz/jrzvAQFEXpA9GNvfSPgWzpMIgH6FNdUu4FLJojwv2zJz
         tgTWwdXsITbwgU/Xa/6d5cSJzEaCBMeCu99B3PdgELUv/QSiyd2P7ENTEdT0We7vvBb7
         AlljmaQO75Tdb5upn5JxBWIJpqRG19lrk4X7lHTFgcJasqrH/Hxck9GLBsQYq7dGZTRH
         FJWw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWzGqG3ZtqIx7CCrGZxXHEdnVjrT0XMcCnVArrvfC9GhneMOivMH4Qvcp/GvynqhbUn6L4VQQ==@lfdr.de
X-Gm-Message-State: AOJu0Yz45hTbjrnMcuX6U4WqD7Cn4lDHv/fQb3i/NDuX5vMcOgpqJ7CO
	W+2ytVvWN+khmJe1xfTX/rIOAbl+YinAV9fjWGl/tlbzSnMzDjVT
X-Google-Smtp-Source: AGHT+IEL6+ShOgRiDLqFL2pGt8rhdMbJFqjQ0gZ248IKlvZY3gk5ZQ0y/l1BmkSaiLhIwJSzvnWtDw==
X-Received: by 2002:a05:6820:1f08:b0:5eb:75a9:3aac with SMTP id 006d021491bc7-5ee566ccb00mr70836eaf.6.1730994851395;
        Thu, 07 Nov 2024 07:54:11 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6820:4d0a:b0:5ed:f9c5:832a with SMTP id
 006d021491bc7-5ee459a354als985455eaf.0.-pod-prod-09-us; Thu, 07 Nov 2024
 07:54:08 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXinL/ntL4qOmNIPVsnXfi0Dmrquu36ISZZJifjJvpUvSUXBYJjrtJtgizETGL/UI3aixdmrKBOuWE=@googlegroups.com
X-Received: by 2002:a4a:e90f:0:b0:5eb:c6ba:796d with SMTP id 006d021491bc7-5ee568de65emr23954eaf.1.1730994848129;
        Thu, 07 Nov 2024 07:54:08 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1730994848; cv=none;
        d=google.com; s=arc-20240605;
        b=kncuZ28cDtOio3kPmeDqaFSNrwLll6p04eGy/WCPreIhbn9peoRfQL66mumVfjnLZ6
         wpdAMg+vpVtzHuSpa5pUVxt6ePOL1amiTuM0cmKRn9DVLTIFcak/P6la4BxSwuiLShWO
         FyU831d1gXht6MLulFcSwn4cPFOXMbuHgEOywPTLHLEmsFcP/TCWr5f/txOVArUyqsNx
         93RfWIEgSiGS1aPXPgL5tE2CwxLCMnqU25wkSNgHv739Twkq3iK6KL6ISb2JaDLVtINq
         yv3fTvXH7iXo8K7XdSKOonj14bEC7VQZyqkmL2wa0UmSRVGl8a7tftE10bAMcAfIZnz7
         S6Qw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=ItjcwwFWJ1eN8C6GeicRaz4ZF3Qa5clzrN3+55+EGPU=;
        fh=hPVy8hZoYoKgFBD7jpNt4DrkUeK6gv5h1xZcyiS3szs=;
        b=MLue9CmbJxI2dxRnQjP2Nonm5poAmisRihOfa7+/AhDkPZB8OQ6Kv/Un4c51qpIbR5
         6SsWpLFrBbk67T+8AWTFNH/InY4KdV4gctL6mmE4O8TFdd1p6pqWsi6ExgA0YGGlFKf7
         BEQD/MZqajAMad0QEP1kNuVpFEjSA/togD+SB+KoxmhBTZFchx5PPM8j6M7Ee7V6JXfO
         vdqWPkHhhWxiQ6opuZyb5Ox0+O83ZUh0OaObTxKD3SoirPsKa90VbjhEaWa9il/FFV6/
         pVEXrf9TjtlcX3Mx+rWvyPRYiEPaWqdg8IuxG3FUSZA9C8c1H0SNFu802WjalWNNyG6N
         rwOQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@efficios.com header.s=smtpout1 header.b=rrqT6gFA;
       spf=pass (google.com: domain of mathieu.desnoyers@efficios.com designates 2607:5300:203:b2ee::31e5 as permitted sender) smtp.mailfrom=mathieu.desnoyers@efficios.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=efficios.com
Received: from smtpout.efficios.com (smtpout.efficios.com. [2607:5300:203:b2ee::31e5])
        by gmr-mx.google.com with ESMTPS id 006d021491bc7-5ee4967312bsi78723eaf.1.2024.11.07.07.54.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 07 Nov 2024 07:54:08 -0800 (PST)
Received-SPF: pass (google.com: domain of mathieu.desnoyers@efficios.com designates 2607:5300:203:b2ee::31e5 as permitted sender) client-ip=2607:5300:203:b2ee::31e5;
Received: from [172.16.0.134] (96-127-217-162.qc.cable.ebox.net [96.127.217.162])
	by smtpout.efficios.com (Postfix) with ESMTPSA id 4XkmpR0prGzxsy;
	Thu,  7 Nov 2024 10:54:07 -0500 (EST)
Message-ID: <3326c8a1-36c7-476b-8afa-2957f5bd5426@efficios.com>
Date: Thu, 7 Nov 2024 10:52:37 -0500
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v2 1/2] tracing: Add task_prctl_unknown tracepoint
To: Marco Elver <elver@google.com>
Cc: Steven Rostedt <rostedt@goodmis.org>, Kees Cook <keescook@chromium.org>,
 Masami Hiramatsu <mhiramat@kernel.org>,
 Andrew Morton <akpm@linux-foundation.org>, Oleg Nesterov <oleg@redhat.com>,
 linux-kernel@vger.kernel.org, linux-trace-kernel@vger.kernel.org,
 Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com
References: <20241107122648.2504368-1-elver@google.com>
 <5b7defe4-09db-491e-b2fb-3fb6379dc452@efficios.com>
 <CANpmjNPWLOfXBMYV0_Eon6NgKPyDorTxwS4b67ZKz7hyz5i13A@mail.gmail.com>
Content-Language: en-US
From: Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
In-Reply-To: <CANpmjNPWLOfXBMYV0_Eon6NgKPyDorTxwS4b67ZKz7hyz5i13A@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: mathieu.desnoyers@efficios.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@efficios.com header.s=smtpout1 header.b=rrqT6gFA;       spf=pass
 (google.com: domain of mathieu.desnoyers@efficios.com designates
 2607:5300:203:b2ee::31e5 as permitted sender) smtp.mailfrom=mathieu.desnoyers@efficios.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=efficios.com
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

On 2024-11-07 10:46, Marco Elver wrote:
> On Thu, 7 Nov 2024 at 16:45, Mathieu Desnoyers
> <mathieu.desnoyers@efficios.com> wrote:
>>
>> On 2024-11-07 07:25, Marco Elver wrote:
>>> prctl() is a complex syscall which multiplexes its functionality based
>>> on a large set of PR_* options. Currently we count 64 such options. The
>>> return value of unknown options is -EINVAL, and doesn't distinguish from
>>> known options that were passed invalid args that also return -EINVAL.
>>>
>>> To understand if programs are attempting to use prctl() options not yet
>>> available on the running kernel, provide the task_prctl_unknown
>>> tracepoint.
>>>
>>> Note, this tracepoint is in an unlikely cold path, and would therefore
>>> be suitable for continuous monitoring (e.g. via perf_event_open).
>>>
>>> While the above is likely the simplest usecase, additionally this
>>> tracepoint can help unlock some testing scenarios (where probing
>>> sys_enter or sys_exit causes undesirable performance overheads):
>>>
>>>     a. unprivileged triggering of a test module: test modules may register a
>>>        probe to be called back on task_prctl_unknown, and pick a very large
>>>        unknown prctl() option upon which they perform a test function for an
>>>        unprivileged user;
>>>
>>>     b. unprivileged triggering of an eBPF program function: similar
>>>        as idea (a).
>>>
>>> Example trace_pipe output:
>>>
>>>     test-484     [000] .....   631.748104: task_prctl_unknown: comm=test option=1234 arg2=101 arg3=102 arg4=103 arg5=104
>>>
>>
>> My concern is that we start adding tons of special-case
>> tracepoints to the implementation of system calls which
>> are redundant with the sys_enter/exit tracepoints.
>>
>> Why favor this approach rather than hooking on sys_enter/exit ?
> 
> It's __extremely__ expensive when deployed at scale. See note in
> commit description above.

I suspect you base the overhead analysis on the x86-64 implementation
of sys_enter/exit tracepoint and especially the overhead caused by
the SYSCALL_WORK_SYSCALL_TRACEPOINT thread flag, am I correct ?

If that is causing a too large overhead, we should investigate if
those can be improved instead of adding tracepoints in the
implementation of system calls.

Thanks,

Mathieu


-- 
Mathieu Desnoyers
EfficiOS Inc.
https://www.efficios.com

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/3326c8a1-36c7-476b-8afa-2957f5bd5426%40efficios.com.
