Return-Path: <kasan-dev+bncBCTJ7DM3WQOBBK6DUSDAMGQELH4NHFA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x337.google.com (mail-wm1-x337.google.com [IPv6:2a00:1450:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id 85F883A8B6F
	for <lists+kasan-dev@lfdr.de>; Tue, 15 Jun 2021 23:54:51 +0200 (CEST)
Received: by mail-wm1-x337.google.com with SMTP id z19-20020a7bc1530000b02901ab5fafdcb4sf3515wmi.0
        for <lists+kasan-dev@lfdr.de>; Tue, 15 Jun 2021 14:54:51 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1623794091; cv=pass;
        d=google.com; s=arc-20160816;
        b=iD5Zo5YCcCHD72uipFKIfsX85SuwK0dbc1AILTGJPb4a92eyJ8QcoFtmeEubHtMckD
         9rt2NvqX7zmfxCW8RZ4tPOv0tdVZE/YKz5qAVyM1aElZ4d42DgYAzyVyh8J6aijn5/Yx
         R4uu163NXETQ2Qlmaf7OfmUoWrEPxXJBkcGztN7HVeqPXqnFTztJTXn0rS8bfVK9dAx+
         l4mZnPdjk4KcXmf9zXuZd0OKX6u3Rpd/xuiAOQRQdHPbEHIGV6LUhFmIMmdU5KhWciW9
         x763PjDAnMR9sldFHpXvpgQXnhfWMU00vDFQj5gC6GtFVN1NzPtoXbFK1vcpm9k+PPZ7
         ckJA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=sDfpFaR0yTG89iZaa77j5Xj/Db/D/mBh9yuE2ewovX4=;
        b=C8GiHU0gHmSEM4YWqo16H5zkFMziCekdO+gfCLU4YUVoPwV99LsexM+1sYDQmadRj3
         Orw3pdKkPwwdyfUlhTDB+HSzKOTBGYi+5cMYpZnoXk4BOyNx+BR02ygu1hwsNYz2Skc1
         Q47eTx75oomL+K6NVIMYEgB+gOmUkpnWW8WoPO5XsVM4+xk3oc/ZqiTvwGWX1tCUFf51
         lUsAPQ+otJbkn5woVa7dplrs0qJGwkzZz43S6Gv834N8cWHQf8IEmQehlYnTekQutb6S
         7N5yJEbZJYuRiorZFSO3T6A+I4zOg9R9N2T4KMDLLks2Cc0BwQQkhRQsiN5Iiuai5MBS
         C60Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of daniel@iogearbox.net designates 213.133.104.62 as permitted sender) smtp.mailfrom=daniel@iogearbox.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=sDfpFaR0yTG89iZaa77j5Xj/Db/D/mBh9yuE2ewovX4=;
        b=PbrcOOK4417wjSFvAYrBckSuCaQXKqPC/UMYDxcuN7Hszn499fyu6MspiavA4ilXll
         z5kOwU7ypgXfEQP+W8exyjpuDmtS3p41emHdRGDpfTy6sJ32748AsGczSWLJxMynSQ++
         7+ldQgyjDeip98yINLuou1xJNZ7KCv0P/jBWy2tqWp+19R3T3EvHkzoO+jErd9YWFzy3
         FPq1/ChwVm+6Tqmm8ZQDvjLpjWX6ZxS1gfxQvEgvQXIj/BJ20HAkKHDTYzKnS6U0bVeO
         8jK0Z0gobi+DVjfQCEnqQ412DC6Z5212ElkoisBT4v51Jj2mG1/Hm/asf1Ta6xLvkUJV
         mfzg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=sDfpFaR0yTG89iZaa77j5Xj/Db/D/mBh9yuE2ewovX4=;
        b=kD4WHXCPpBXrM/cB/EKB38yeFuhfA1/3Srk9klvJT+REOFdzqIRkqJqA6dDcoVREN3
         afCgGeloi5oUWUT+wNv/BpZPQmCt+qSRKE1pesWjJKA7jvAH24vplP+ANa0AoD1ghLyD
         v4LU7qf7UBRH0nieKTSYOiWhPHZbdbJi5VLtKvS8A92yoUY5FN3WjtPZz3C3mcWKbKyf
         +AQTaTjCu+3ZGbON3U3asN4sY0y3pz7/63VaZAdl216YjY42EG9HnpJwvO7fcWZwbNpy
         7WdKdHSdBQydUg7wNJ0c6zjSX0oa3ODa8F2YbrcvrJ4z/QTKh5pVAikGeekZe/JDgbgS
         JsxQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531HwtZ4nSLCjnIExvui+w9h2iquciQGOJic1zf2HPTTUGYxQgRP
	zZp/syxqtrn69g5rNqqsIGM=
X-Google-Smtp-Source: ABdhPJxicKohBL5FiTnYTf7xP7Aowpb30qVQfgW975OSbFrbEjBz13r76ZRHPE8OXf3Db4nXDFB4uQ==
X-Received: by 2002:a5d:58d3:: with SMTP id o19mr1398887wrf.404.1623794091226;
        Tue, 15 Jun 2021 14:54:51 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:7919:: with SMTP id l25ls135591wme.1.gmail; Tue, 15 Jun
 2021 14:54:50 -0700 (PDT)
X-Received: by 2002:a1c:ac87:: with SMTP id v129mr710025wme.45.1623794090403;
        Tue, 15 Jun 2021 14:54:50 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1623794090; cv=none;
        d=google.com; s=arc-20160816;
        b=H7Go0+zX5lQQoEF63hSVFABS566hq3/MPEm3/M5eFha2j+4SUESM/zcMpBEc+N7abr
         6fBrurQnEvOMJOMHSzMDmdLB0NLVHjxTl2Mm6xfyi+N7aS7JAfoBiqTSuZAF7yJFhzO8
         e6G/kx4S/SjqtPiTs4AbZJMHfj9ktj7rKePkF9OnP29lm6Xl4qjlPFvwuLiee/RPuawK
         mN28rzlcsb4VHWbhe1Tgzt2pHwaXiKohsBzj9B9Rqt/0IgkLMi0IXRL8e1ZTp3JEzeuX
         uAXvECPOAwsSb7mDg76ZnY5i9jFd7pV3zkSXV6uUfwGIJbXw40/3cG4nf3Azg2T76OBB
         vb9Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=k3ccg9mpyGuJlP4StkHf/KwlYBnsSRYrs6zxKfc17wc=;
        b=XzDCAhxzuU48lel7QgTVBn4tJJRihDnjmU9s3tgLRtxy7j78kIqIRpg5nRVkIsnY+e
         h0Q+s4S+6xV0PaKYQmKZne/b4p//O0D4d53tu99PsjnkIo6j90503v0AeY95mz78YkXt
         pyd7TRxiDigX96LohvrmMLn4MRQ3YgPahsGAMNAYikXeV7hfRXhbybalALs6kie8MMp5
         XYLEvuyomvOjVfNJObaZ+GwxD9YVaMuLWE72JRo9Ej6hEsZUk66nLCYpC34C4cwFQaqM
         j+fqQbKn32xz0qrxlOrYMQIZmf388zKB9hjxlPRYof3vgD2N2/WKp98AC29B8j2WDJWa
         1NNA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of daniel@iogearbox.net designates 213.133.104.62 as permitted sender) smtp.mailfrom=daniel@iogearbox.net
Received: from www62.your-server.de (www62.your-server.de. [213.133.104.62])
        by gmr-mx.google.com with ESMTPS id v4si6303wrg.2.2021.06.15.14.54.50
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 15 Jun 2021 14:54:50 -0700 (PDT)
Received-SPF: pass (google.com: domain of daniel@iogearbox.net designates 213.133.104.62 as permitted sender) client-ip=213.133.104.62;
Received: from sslproxy01.your-server.de ([78.46.139.224])
	by www62.your-server.de with esmtpsa (TLSv1.3:TLS_AES_256_GCM_SHA384:256)
	(Exim 4.92.3)
	(envelope-from <daniel@iogearbox.net>)
	id 1ltH19-0009sn-8n; Tue, 15 Jun 2021 23:54:43 +0200
Received: from [85.7.101.30] (helo=linux-3.home)
	by sslproxy01.your-server.de with esmtpsa (TLSv1.3:TLS_AES_256_GCM_SHA384:256)
	(Exim 4.92)
	(envelope-from <daniel@iogearbox.net>)
	id 1ltH18-000IMK-PK; Tue, 15 Jun 2021 23:54:42 +0200
Subject: Re: [PATCH v5] bpf: core: fix shift-out-of-bounds in ___bpf_prog_run
To: Eric Biggers <ebiggers@kernel.org>
Cc: Edward Cree <ecree.xilinx@gmail.com>,
 Kurt Manucredo <fuzzybritches0@gmail.com>,
 syzbot+bed360704c521841c85d@syzkaller.appspotmail.com,
 keescook@chromium.org, yhs@fb.com, dvyukov@google.com, andrii@kernel.org,
 ast@kernel.org, bpf@vger.kernel.org, davem@davemloft.net, hawk@kernel.org,
 john.fastabend@gmail.com, kafai@fb.com, kpsingh@kernel.org, kuba@kernel.org,
 linux-kernel@vger.kernel.org, netdev@vger.kernel.org, songliubraving@fb.com,
 syzkaller-bugs@googlegroups.com, nathan@kernel.org, ndesaulniers@google.com,
 clang-built-linux@googlegroups.com, kernel-hardening@lists.openwall.com,
 kasan-dev@googlegroups.com
References: <752cb1ad-a0b1-92b7-4c49-bbb42fdecdbe@fb.com>
 <CACT4Y+a592rxFmNgJgk2zwqBE8EqW1ey9SjF_-U3z6gt3Yc=oA@mail.gmail.com>
 <1aaa2408-94b9-a1e6-beff-7523b66fe73d@fb.com> <202106101002.DF8C7EF@keescook>
 <CAADnVQKMwKYgthoQV4RmGpZm9Hm-=wH3DoaNqs=UZRmJKefwGw@mail.gmail.com>
 <85536-177443-curtm@phaethon>
 <bac16d8d-c174-bdc4-91bd-bfa62b410190@gmail.com> <YMkAbNQiIBbhD7+P@gmail.com>
 <dbcfb2d3-0054-3ee6-6e76-5bd78023a4f2@iogearbox.net>
 <YMkcYn4dyZBY/ze+@gmail.com> <YMkdx1VB0i+fhjAY@gmail.com>
From: Daniel Borkmann <daniel@iogearbox.net>
Message-ID: <4713f6e9-2cfb-e2a6-c42d-b2a62f035bf2@iogearbox.net>
Date: Tue, 15 Jun 2021 23:54:41 +0200
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101
 Thunderbird/60.7.2
MIME-Version: 1.0
In-Reply-To: <YMkdx1VB0i+fhjAY@gmail.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Language: en-US
X-Authenticated-Sender: daniel@iogearbox.net
X-Virus-Scanned: Clear (ClamAV 0.103.2/26202/Tue Jun 15 13:21:24 2021)
X-Original-Sender: daniel@iogearbox.net
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of daniel@iogearbox.net designates 213.133.104.62 as
 permitted sender) smtp.mailfrom=daniel@iogearbox.net
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

On 6/15/21 11:38 PM, Eric Biggers wrote:
> On Tue, Jun 15, 2021 at 02:32:18PM -0700, Eric Biggers wrote:
>> On Tue, Jun 15, 2021 at 11:08:18PM +0200, Daniel Borkmann wrote:
>>> On 6/15/21 9:33 PM, Eric Biggers wrote:
>>>> On Tue, Jun 15, 2021 at 07:51:07PM +0100, Edward Cree wrote:
>>>>>
>>>>> As I understand it, the UBSAN report is coming from the eBPF interpreter,
>>>>>    which is the *slow path* and indeed on many production systems is
>>>>>    compiled out for hardening reasons (CONFIG_BPF_JIT_ALWAYS_ON).
>>>>> Perhaps a better approach to the fix would be to change the interpreter
>>>>>    to compute "DST = DST << (SRC & 63);" (and similar for other shifts and
>>>>>    bitnesses), thus matching the behaviour of most chips' shift opcodes.
>>>>> This would shut up UBSAN, without affecting JIT code generation.
>>>>
>>>> Yes, I suggested that last week
>>>> (https://lkml.kernel.org/netdev/YMJvbGEz0xu9JU9D@gmail.com).  The AND will even
>>>> get optimized out when compiling for most CPUs.
>>>
>>> Did you check if the generated interpreter code for e.g. x86 is the same
>>> before/after with that?
>>
>> Yes, on x86_64 with gcc 10.2.1, the disassembly of ___bpf_prog_run() is the same
>> both before and after (with UBSAN disabled).  Here is the patch I used:
>>
>> diff --git a/kernel/bpf/core.c b/kernel/bpf/core.c
>> index 5e31ee9f7512..996db8a1bbfb 100644
>> --- a/kernel/bpf/core.c
>> +++ b/kernel/bpf/core.c
>> @@ -1407,12 +1407,30 @@ static u64 ___bpf_prog_run(u64 *regs, const struct bpf_insn *insn)
>>   		DST = (u32) DST OP (u32) IMM;	\
>>   		CONT;
>>   
>> +	/*
>> +	 * Explicitly mask the shift amounts with 63 or 31 to avoid undefined
>> +	 * behavior.  Normally this won't affect the generated code.

The last one should probably be more specific in terms of 'normally', e.g. that
it is expected that the compiler is optimizing this away for archs like x86. Is
arm64 also covered by this ... do you happen to know on which archs this won't
be the case?

Additionally, I think such comment should probably be more clear in that it also
needs to give proper guidance to JIT authors that look at the interpreter code to
see what they need to implement, in other words, that they don't end up copying
an explicit AND instruction emission if not needed there.

>> +	 */
>> +#define ALU_SHIFT(OPCODE, OP)		\
>> +	ALU64_##OPCODE##_X:		\
>> +		DST = DST OP (SRC & 63);\
>> +		CONT;			\
>> +	ALU_##OPCODE##_X:		\
>> +		DST = (u32) DST OP ((u32)SRC & 31);	\
>> +		CONT;			\
>> +	ALU64_##OPCODE##_K:		\
>> +		DST = DST OP (IMM & 63);	\
>> +		CONT;			\
>> +	ALU_##OPCODE##_K:		\
>> +		DST = (u32) DST OP ((u32)IMM & 31);	\
>> +		CONT;

For the *_K cases these are explicitly rejected by the verifier already. Is this
required here nevertheless to suppress UBSAN false positive?

>>   	ALU(ADD,  +)
>>   	ALU(SUB,  -)
>>   	ALU(AND,  &)
>>   	ALU(OR,   |)
>> -	ALU(LSH, <<)
>> -	ALU(RSH, >>)
>> +	ALU_SHIFT(LSH, <<)
>> +	ALU_SHIFT(RSH, >>)
>>   	ALU(XOR,  ^)
>>   	ALU(MUL,  *)
>>   #undef ALU
> 
> Note, I missed the arithmetic right shifts later on in the function.  Same
> result there, though.
> 
> - Eric
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/4713f6e9-2cfb-e2a6-c42d-b2a62f035bf2%40iogearbox.net.
