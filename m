Return-Path: <kasan-dev+bncBCR6PUHQH4IMZWNTXEDBUBG3HSJ5C@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53c.google.com (mail-pg1-x53c.google.com [IPv6:2607:f8b0:4864:20::53c])
	by mail.lfdr.de (Postfix) with ESMTPS id 88F6A9C0BD0
	for <lists+kasan-dev@lfdr.de>; Thu,  7 Nov 2024 17:37:34 +0100 (CET)
Received: by mail-pg1-x53c.google.com with SMTP id 41be03b00d2f7-7f4034d6516sf1238084a12.1
        for <lists+kasan-dev@lfdr.de>; Thu, 07 Nov 2024 08:37:34 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1730997453; cv=pass;
        d=google.com; s=arc-20240605;
        b=lM3XoS24X57p0Hd7WuMbaYDQdmlj1teeQABfpsodERRCM31uRXg8Fl+a2ZPOVWyapP
         PGucBtiORZy0+/rt46WPZKj/y5pG8C+O9BEeCzO9GBxS5NLcnYXYXLaiAR6duO7hwBde
         7c7Yj6mQ+6nWeTx8uycvOqXf58XKcWmp33CFq1KG5XEHNrZBQ5DVxWe2/8Df+fD04lWU
         x+4tYDhyeyEbIcssdmxlBzdcmsFdHoBsB7oOVxhAh5q9aOqpr7xotjmcKsyvxlUSrZkZ
         2ycaX50RriLrHQvd1tCPBwSzZq0coebcqV1cvzBedxAgvS//KH99Q6ejs3EoJHAJoj+s
         /HVw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=7hzZfEhBKjh1T/buYWR2Zf2iW+5TKCH4xgiDIkgLT+o=;
        fh=Fh6VuxjA6L905Hk0av9WpwxgqTYRKgewTv4rue/OQj8=;
        b=GWxmwmn/VI8/TDgjBym21nz8exkF31+InvcC9W1aV4yidMYcWQ9wqat0hB3gzh697q
         Rt3e222bdpaq9/Z6zaV8oDNUOq0xLzkVwOiPdZn+jYGh6nB4hPizjZTh9sgHcBBw6U4z
         Wh6AaIwX53qKkSkYD2qyra+djozZJEbd8Z7xPvmbY5iGO8KYohBPSD0OkaXNVB+VqKXR
         3/8j7WQrHTYvjnluCsLyxfUXYfMtoO7/rnJPom5q7Rhe/YGnglmlaaNoMR5RXa1EZ830
         DH3OnJo4+k1YjZ3tD+lD+yocajUtSYsoFc6FNFzCCzb7U+xXygLDnDL6YR5BYz2blIxQ
         jEzg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@efficios.com header.s=smtpout1 header.b="kafR/THq";
       spf=pass (google.com: domain of mathieu.desnoyers@efficios.com designates 2607:5300:203:b2ee::31e5 as permitted sender) smtp.mailfrom=mathieu.desnoyers@efficios.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=efficios.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1730997453; x=1731602253; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:content-language:references:cc
         :to:subject:user-agent:mime-version:date:message-id:sender:from:to
         :cc:subject:date:message-id:reply-to;
        bh=7hzZfEhBKjh1T/buYWR2Zf2iW+5TKCH4xgiDIkgLT+o=;
        b=TBbOGAugzJG+E5H4WmU84mDY6rFOK1EAHATeX3aAS33IxokiPU9sqosjdLNIwzLJ7k
         FEWM+3f2WmzZNMG5K36+M/CxcF2li3M5SlnnfzdIper8slJT4/eCGFnukGsMEexWdJmH
         5gRMqrc2RMNfOc8WYOUljWvJI1xRQeMTcUCtoi3VdsoB//F/HFAVnRL4VMEB9oNVczFa
         h9zm2omBaWebE0bHoBSxxznv8ZaJ3xhci7tR71kJ3ETn08WonSYj7hhI0+0PBJK8qoI+
         VVLvqm1HebXC8vGlfmDBcTl/S3YEm1ljUFyb2W+0D2aNZ3zrni7aNwWIUReh981mIWC/
         rp9Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1730997453; x=1731602253;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:content-language:references:cc:to:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=7hzZfEhBKjh1T/buYWR2Zf2iW+5TKCH4xgiDIkgLT+o=;
        b=EWoKEL9kMdlSlhrqSdbZxsqrVyh2VY1QEvWX+PDPV+J5QmetC4AAi70nQIzaKTElyK
         FBax9QRVcJVWu6jdW2z84TtH1sSo/Hel20PjIyYOvrq3Gc1lz1RP/sdnC54AmDzbDr89
         8+lHG/R1Vm2+usxPNwh6kHgDnZstXpRlflVjgP4WhkPQTGg2hQK6xax192Bl7tmxIh5m
         qVCZqkP34qzIvJeVyjr5Mzjqs/JDRUbhwj+tfZKtbo/jKgfJvqq3z+LOc0y4QVkXaTNs
         bqpUdC++Yfwx1yzqkfxDOdwhE2E6JbgdtUn5AfUMkoOw41Gw7W/3RWCcDrBsc/B8xCov
         MRDQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVAQSbDobIj//RCIsECoSwIiu1WYGL+rNhqMzTpINCy99zZwm+QfyjLsEyFDMgQ96eCp1INDg==@lfdr.de
X-Gm-Message-State: AOJu0YzmVP9+/+3snWS8bjZzOwQPmPWkKcy7yF2PBoBMReAkGIC6Z8IC
	fHJ9Ienat0iNb30crd2Xk0yLeP5nzSl4G+WkTuxUxvCLOwo4EHjE
X-Google-Smtp-Source: AGHT+IFhmHZ7J0+fyDTIEd8zmuMdBCDcQAtaFjGLsjpzBtueslFe1L3E/N9HOF/m4opMgFcXEVtXhw==
X-Received: by 2002:a17:90b:4d0a:b0:2c9:b72:7a1f with SMTP id 98e67ed59e1d1-2e94c5175d5mr32924088a91.28.1730997452899;
        Thu, 07 Nov 2024 08:37:32 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:4b10:b0:2e2:c421:c3e with SMTP id
 98e67ed59e1d1-2e9a407587dls252554a91.2.-pod-prod-05-us; Thu, 07 Nov 2024
 08:37:31 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXBZ097FFXp4RAXSHxfAidjt55Mzm+JQo82HlGwBOJ2bgwVTu4T6+kGiu52wsoZMiAdSgX9TcooDVU=@googlegroups.com
X-Received: by 2002:a17:90b:2d84:b0:2c8:65cf:e820 with SMTP id 98e67ed59e1d1-2e94c298d3dmr33561411a91.2.1730997451533;
        Thu, 07 Nov 2024 08:37:31 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1730997451; cv=none;
        d=google.com; s=arc-20240605;
        b=Xdsou8xy0SeC7o4rwAKfwfYVr/ZkYAd3RXwQwijVoYL/a5Q5MqHwq5tRBMkrUPeWip
         qdL3dGV4RNQGjuZR9qABugsBGxPTEDoGgQ0oNTcCcbgJdZT8pxcy9+wFYSY8RrB9I9jv
         m9A86yeiCr43jeZYRt6r9K9i2crHXTGKl6fFgwERAA/2BnNlH1b/W4plwAxzJkLisaRV
         NaIHy7zO9arBie9JpSTafDXrbJgUooDJ/3l/mCN4rYKIX7X+UCslIbetESOgB0W8fPRG
         E5dmEJPe/TghlJK4xuvbiXoLx+b+Ys+2QbWm+UH4GNtaPFIJCTiUB1MS1+qK33fxN+ma
         7p/A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=I6j3PVt5gfR5xjAdMdLhLxJodsQDrPN83Ydtgs2945c=;
        fh=CMRc4oW4ObfMoq15IqbInDHypO1sxnk3Y+XkeqP5goA=;
        b=U1xZSvO1QI8Wm3JRKdQa1fOUe3qIuTwa0/UKUrEQXLtg5M6wZcc9GXcpcz4ypQJfJw
         zU0bHONrIjur+TItmUl9IZR0eSNw2ucNIUyY6w16aEmP8EUXfcADFkDPD+OpAIg6+n/O
         +/Xd4rhPrI2MI1YakS0sF/BVbtb2ctfj+yd6+/eoawWj6qOTDnwTXJYDe5UhhqW+heVc
         Ypmxg7eBvVUIlik990A2yKy0VWAzKQg/uO7iJ3hB3R/JJ4qV+Z6S7C8xf7hCWGuriWdQ
         4i3KnEXOnqWw2s7mPQKwmgdZaM3Oo+bT8w4/qB3fpegGJrZfSQqxX3/NuP5TJnGeLEnr
         BAkw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@efficios.com header.s=smtpout1 header.b="kafR/THq";
       spf=pass (google.com: domain of mathieu.desnoyers@efficios.com designates 2607:5300:203:b2ee::31e5 as permitted sender) smtp.mailfrom=mathieu.desnoyers@efficios.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=efficios.com
Received: from smtpout.efficios.com (smtpout.efficios.com. [2607:5300:203:b2ee::31e5])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-2e98ae8833asi457112a91.0.2024.11.07.08.37.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 07 Nov 2024 08:37:31 -0800 (PST)
Received-SPF: pass (google.com: domain of mathieu.desnoyers@efficios.com designates 2607:5300:203:b2ee::31e5 as permitted sender) client-ip=2607:5300:203:b2ee::31e5;
Received: from [172.16.0.134] (96-127-217-162.qc.cable.ebox.net [96.127.217.162])
	by smtpout.efficios.com (Postfix) with ESMTPSA id 4XknmV0yXbzy86;
	Thu,  7 Nov 2024 11:37:30 -0500 (EST)
Message-ID: <dc36b163-5626-4d39-bd8f-35dc353bef17@efficios.com>
Date: Thu, 7 Nov 2024 11:36:00 -0500
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v2 1/2] tracing: Add task_prctl_unknown tracepoint
To: Steven Rostedt <rostedt@goodmis.org>
Cc: Marco Elver <elver@google.com>, Kees Cook <keescook@chromium.org>,
 Masami Hiramatsu <mhiramat@kernel.org>,
 Andrew Morton <akpm@linux-foundation.org>, Oleg Nesterov <oleg@redhat.com>,
 linux-kernel@vger.kernel.org, linux-trace-kernel@vger.kernel.org,
 Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com
References: <20241107122648.2504368-1-elver@google.com>
 <5b7defe4-09db-491e-b2fb-3fb6379dc452@efficios.com>
 <CANpmjNPWLOfXBMYV0_Eon6NgKPyDorTxwS4b67ZKz7hyz5i13A@mail.gmail.com>
 <3326c8a1-36c7-476b-8afa-2957f5bd5426@efficios.com>
 <20241107110417.7850d68f@gandalf.local.home>
Content-Language: en-US
From: Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
In-Reply-To: <20241107110417.7850d68f@gandalf.local.home>
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: mathieu.desnoyers@efficios.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@efficios.com header.s=smtpout1 header.b="kafR/THq";       spf=pass
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

On 2024-11-07 11:04, Steven Rostedt wrote:
> On Thu, 7 Nov 2024 10:52:37 -0500
> Mathieu Desnoyers <mathieu.desnoyers@efficios.com> wrote:
> 
>> I suspect you base the overhead analysis on the x86-64 implementation
>> of sys_enter/exit tracepoint and especially the overhead caused by
>> the SYSCALL_WORK_SYSCALL_TRACEPOINT thread flag, am I correct ?
>>
>> If that is causing a too large overhead, we should investigate if
>> those can be improved instead of adding tracepoints in the
>> implementation of system calls.
> 
> That would be great to get better, but the reason I'm not against this
> patch is because prctl() is not a normal system call. It's basically an
> ioctl() for Linux, and very vague. It's basically the garbage system call
> when you don't know what to do. It's even being proposed for the sframe
> work.
> 
> I understand your sentiment and agree. I don't want any random system call
> to get a tracepoint attached to it. But here I'd make an exception.

Should we document this as an "instrumentation good practice" then ?

     When the system call is a multiplexor such as ioctl(2) and prctl(2),
     then instrumenting it with tracepoints within each of the "op" case
     makes sense for overall maintainability.

     For non-multiplexor system calls, using the existing sys_enter/exit
     tracepoints should be favored.

This opens the following question for non-multiplexors system calls:
considering that the overhead of the current sys_enter/exit
instrumentation is deemed to large to use in production, perhaps
we should consider a few alternatives, namely:

A) Modify SYSCALL_DEFINE so it emits a function wrapper with tracepoints
    for each system call enter/exit, except for multiplexors, or

B) Add the plumbing required to allow system call tracing to be
    activated for specific system calls only, more fine-grained than
    the current system-wide for_each_process_thread()
    SYSCALL_WORK_SYSCALL_TRACEPOINT thread flag big hammer.

Another scenario to consider is system calls that have iovec arguments.
Should we add tracepoint within the iovec iteration, or should it target
the entire iovec as input/output at system call enter/exit ?

Thanks,

Mathieu

-- 
Mathieu Desnoyers
EfficiOS Inc.
https://www.efficios.com

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/dc36b163-5626-4d39-bd8f-35dc353bef17%40efficios.com.
