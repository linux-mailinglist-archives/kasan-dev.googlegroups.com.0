Return-Path: <kasan-dev+bncBCTJ7DM3WQOBB256VSDAMGQEUYNWQOI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23f.google.com (mail-lj1-x23f.google.com [IPv6:2a00:1450:4864:20::23f])
	by mail.lfdr.de (Postfix) with ESMTPS id 807863AB0FE
	for <lists+kasan-dev@lfdr.de>; Thu, 17 Jun 2021 12:09:48 +0200 (CEST)
Received: by mail-lj1-x23f.google.com with SMTP id m11-20020a2e580b0000b0290152246e1297sf2480754ljb.13
        for <lists+kasan-dev@lfdr.de>; Thu, 17 Jun 2021 03:09:48 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1623924588; cv=pass;
        d=google.com; s=arc-20160816;
        b=BLnWA19srGeGUNLCV6pQ7XNwAO7v+LpzptQ1hy4mQdSdWtrqMZMKDPuqp4eWng/ct5
         HDt5kmMCO49Fboc+VxsdC3QayKZhAAmfDU6MNr7UbIlLgqXEv0hMqoNRwg9KtWuvxhre
         umVhjAk4dwON3RyNEMfTjgpjLDbq57vublapZwHqbhiA2ns7j84OVypKVGmIqhAHlbLv
         SYodPzs7EEcmHjdnw+qBYfdHJSf2SnN/tLdjKIXHEBg4Hrq/QhVzTb3tLWTnP+t18Srh
         nxbUOrw0B7WU56Fs6hnW2KChSxZ26v3134WTULlN4EECKECNZsQngXnm1YAdfK7Eskp3
         /5XA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=8iWJPSIjMwsWRGlirsK1sQmsyDQg2GZvaZohNuiPvkQ=;
        b=nn9dDASRe0SmdqKJfUI+wGUF/P2e2Of31fWl+l03mh3yGmz98jl8iX4yV1Q9/Wmj8r
         EIwhelcTzUCBueUGfsu5KP9w9tCnLbPkri/sRECM7b2PRW6jFAoZDhed3M1rwTbPBXO5
         JQDc+em1DTpbH1UX1QLi34RrlPPdzCPWPm5w9WMsD2B8otYrktbKiBOHopTV7sV6MA/8
         2+q4fNysXnYKWzqJhy6QIkIXrS3b8p2N2Zdb9oXOC8F++1TD2VWFjtjUrGNGBIKil7Ef
         qTRgWgjgpdF/uG20cMkm54d/phXvhQnb9eO+x8dR4I0Y860CSwhCRqXTkzG5qP1iSbFc
         qt8Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of daniel@iogearbox.net designates 213.133.104.62 as permitted sender) smtp.mailfrom=daniel@iogearbox.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=8iWJPSIjMwsWRGlirsK1sQmsyDQg2GZvaZohNuiPvkQ=;
        b=kDTFlioPkzIG+KsPeQyFxbgYR5/E5iEUqjeydcP2AAM15kynCEnqdOjs2+kHKqr+/B
         x8SO3G5EFerxonZpTUYP5cgeQmfRoK6NQgv5bQHn457XeobpR8bR/aNE3dvB3cDSN77c
         AROo1gKMgpZV2DCX7RubMCybFTUxSqlG+b2xGpmIH6Jq0JDEdAk7dTHL09KrOyycen+0
         B2gOSssKHTbvdEt7UVbX7J8AIFeUy7mMsATPkNgwptrm3KAuSI+ZG96V0OnXiyhKiKIs
         s/2tzKavA5OO5fpW4EydahXnACXO93RDWQiO88GgC5cMxjUB6FZzJh0ropTC5Kkupz4l
         dKkg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=8iWJPSIjMwsWRGlirsK1sQmsyDQg2GZvaZohNuiPvkQ=;
        b=kObTsjehBWsb57SAcphARTPuJZyfDVTboC+DCUaEM4Di9pH7i8aofQA2GThqMNrIQt
         SR6NqvTlsuITXwuRwOkPKLf6I9uec/dz47VobiborDdmrKwcxFvbbyh/FNiP/mTUhZNv
         VpADXSz81LzEHJQV2mBHSLPwnW03GXkCJ5QKepeEdEe4eoXLBHMUxzDXNP3gDTSK7Bov
         cClkPjG/9TjRMaLVbS0EgpGejDAVOkTi/lrMaszytTfrzqMk9+yNVr3JBP5OA1aLisXI
         TBl28ofMg6zeYZIX18PYav6mvDe+4hv3FvB98SFLscyeCG7c/Cd/rwUPA1WrKCKJO5nV
         K7Zg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531UorWJre58OZmFecI1P4x2Dv2grIOYmAmBUgDUM6APyFTHf84w
	xSXjnDSX13lLI6Ls5w23n8E=
X-Google-Smtp-Source: ABdhPJz0ufjNZSmRC7dXmj+kXlaBXIliu9ClrEnpz4d87fLyvAfqqh6Cy+k11UPHsKjSQq9R23MUIg==
X-Received: by 2002:ac2:446a:: with SMTP id y10mr3485348lfl.298.1623924587992;
        Thu, 17 Jun 2021 03:09:47 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:8155:: with SMTP id t21ls405094ljg.1.gmail; Thu, 17 Jun
 2021 03:09:47 -0700 (PDT)
X-Received: by 2002:a2e:380b:: with SMTP id f11mr4005964lja.269.1623924586963;
        Thu, 17 Jun 2021 03:09:46 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1623924586; cv=none;
        d=google.com; s=arc-20160816;
        b=yPIZpV2CD0rGXd/SDaPc1j93ow9XQ4adKvnucZVVWbERBw8FA9kLeDYrpVmBiRtDqh
         2dOipHoVHMDoDHiRrxgQpnICahH9DJBASCX1wsH1BhUlPZLiVObytScxEbDF0IHbnw16
         TJgMJfaH0AnLxRXFCPoYewKrrezR6DPBJHvdNLevBldCYhI64+vVXd9vDtpZVpXbJawe
         GWFqGnqOvH8jLATBSKishv1WezryWANF+30YfufLKFwFtzQdxsOE2QIbR6LbL13J41du
         ZhT7FwXdBu/l0enJyROedREf6Trzurcz2WWjUahRGsV8i61NpIkNVt7Rh9FGUF7X1cQU
         CQVA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=naMT9usCXIV9LeHpCzOtsQq//B+jDDo5rOT1ZsTZ0OM=;
        b=gAZM7EgWqaxFS5O3Yt72uvP9DOjGogHjNYTxoOUw6on4xskMP94vkJrgsTsOF26Vqh
         wfgiEq/ukxPaNCnaSiCMfrUpgzXSAFlyEW/SrvRCM9LYlgFBawvioFIvQG9jtmeZ0zVM
         ipZpTWtvLbplcUM3z1+j6NY+6eXq3v1LrAi/+vRztA3ZmBLPuRa7ukUrtFAaQRTOPkA0
         2h6ybdEmd2FjHY+XjFFEqoh/e1/OObo9KkBKo0Lx/sHj7l8PLTxzXCws6U9Y0+j9vujU
         73kzallltj15QJkwWQMoNMt54pQS9NxNB4tD7GMNjBzfYaoqjAcozOq4JhxtgxN26tfB
         flGA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of daniel@iogearbox.net designates 213.133.104.62 as permitted sender) smtp.mailfrom=daniel@iogearbox.net
Received: from www62.your-server.de (www62.your-server.de. [213.133.104.62])
        by gmr-mx.google.com with ESMTPS id z4si68516lfs.0.2021.06.17.03.09.46
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 17 Jun 2021 03:09:46 -0700 (PDT)
Received-SPF: pass (google.com: domain of daniel@iogearbox.net designates 213.133.104.62 as permitted sender) client-ip=213.133.104.62;
Received: from sslproxy06.your-server.de ([78.46.172.3])
	by www62.your-server.de with esmtpsa (TLSv1.3:TLS_AES_256_GCM_SHA384:256)
	(Exim 4.92.3)
	(envelope-from <daniel@iogearbox.net>)
	id 1ltoxu-000BTK-0B; Thu, 17 Jun 2021 12:09:38 +0200
Received: from [85.7.101.30] (helo=linux.home)
	by sslproxy06.your-server.de with esmtpsa (TLSv1.3:TLS_AES_256_GCM_SHA384:256)
	(Exim 4.92)
	(envelope-from <daniel@iogearbox.net>)
	id 1ltoxt-000DB3-IW; Thu, 17 Jun 2021 12:09:37 +0200
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
References: <1aaa2408-94b9-a1e6-beff-7523b66fe73d@fb.com>
 <202106101002.DF8C7EF@keescook>
 <CAADnVQKMwKYgthoQV4RmGpZm9Hm-=wH3DoaNqs=UZRmJKefwGw@mail.gmail.com>
 <85536-177443-curtm@phaethon>
 <bac16d8d-c174-bdc4-91bd-bfa62b410190@gmail.com> <YMkAbNQiIBbhD7+P@gmail.com>
 <dbcfb2d3-0054-3ee6-6e76-5bd78023a4f2@iogearbox.net>
 <YMkcYn4dyZBY/ze+@gmail.com> <YMkdx1VB0i+fhjAY@gmail.com>
 <4713f6e9-2cfb-e2a6-c42d-b2a62f035bf2@iogearbox.net>
 <YMkkr5G6E8lcFymG@gmail.com>
From: Daniel Borkmann <daniel@iogearbox.net>
Message-ID: <845ad31f-ca3f-0326-e64b-423a09ea4bea@iogearbox.net>
Date: Thu, 17 Jun 2021 12:09:36 +0200
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101
 Thunderbird/60.7.2
MIME-Version: 1.0
In-Reply-To: <YMkkr5G6E8lcFymG@gmail.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Language: en-US
X-Authenticated-Sender: daniel@iogearbox.net
X-Virus-Scanned: Clear (ClamAV 0.103.2/26203/Wed Jun 16 13:07:58 2021)
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

On 6/16/21 12:07 AM, Eric Biggers wrote:
> On Tue, Jun 15, 2021 at 11:54:41PM +0200, Daniel Borkmann wrote:
>> On 6/15/21 11:38 PM, Eric Biggers wrote:
>>> On Tue, Jun 15, 2021 at 02:32:18PM -0700, Eric Biggers wrote:
>>>> On Tue, Jun 15, 2021 at 11:08:18PM +0200, Daniel Borkmann wrote:
>>>>> On 6/15/21 9:33 PM, Eric Biggers wrote:
>>>>>> On Tue, Jun 15, 2021 at 07:51:07PM +0100, Edward Cree wrote:
>>>>>>>
>>>>>>> As I understand it, the UBSAN report is coming from the eBPF interpreter,
>>>>>>>     which is the *slow path* and indeed on many production systems is
>>>>>>>     compiled out for hardening reasons (CONFIG_BPF_JIT_ALWAYS_ON).
>>>>>>> Perhaps a better approach to the fix would be to change the interpreter
>>>>>>>     to compute "DST = DST << (SRC & 63);" (and similar for other shifts and
>>>>>>>     bitnesses), thus matching the behaviour of most chips' shift opcodes.
>>>>>>> This would shut up UBSAN, without affecting JIT code generation.
>>>>>>
>>>>>> Yes, I suggested that last week
>>>>>> (https://lkml.kernel.org/netdev/YMJvbGEz0xu9JU9D@gmail.com).  The AND will even
>>>>>> get optimized out when compiling for most CPUs.
>>>>>
>>>>> Did you check if the generated interpreter code for e.g. x86 is the same
>>>>> before/after with that?
>>>>
>>>> Yes, on x86_64 with gcc 10.2.1, the disassembly of ___bpf_prog_run() is the same
>>>> both before and after (with UBSAN disabled).  Here is the patch I used:
>>>>
>>>> diff --git a/kernel/bpf/core.c b/kernel/bpf/core.c
>>>> index 5e31ee9f7512..996db8a1bbfb 100644
>>>> --- a/kernel/bpf/core.c
>>>> +++ b/kernel/bpf/core.c
>>>> @@ -1407,12 +1407,30 @@ static u64 ___bpf_prog_run(u64 *regs, const struct bpf_insn *insn)
>>>>    		DST = (u32) DST OP (u32) IMM;	\
>>>>    		CONT;
>>>> +	/*
>>>> +	 * Explicitly mask the shift amounts with 63 or 31 to avoid undefined
>>>> +	 * behavior.  Normally this won't affect the generated code.
>>
>> The last one should probably be more specific in terms of 'normally', e.g. that
>> it is expected that the compiler is optimizing this away for archs like x86. Is
>> arm64 also covered by this ... do you happen to know on which archs this won't
>> be the case?
>>
>> Additionally, I think such comment should probably be more clear in that it also
>> needs to give proper guidance to JIT authors that look at the interpreter code to
>> see what they need to implement, in other words, that they don't end up copying
>> an explicit AND instruction emission if not needed there.
> 
> Same result on arm64 with gcc 10.2.0.
> 
> On arm32 it is different, probably because the 64-bit shifts aren't native in
> that case.  I don't know about other architectures.  But there aren't many ways
> to implement shifts, and using just the low bits of the shift amount is the most
> logical way.
> 
> Please feel free to send out a patch with whatever comment you want.  The diff I
> gave was just an example and I am not an expert in BPF.
> 
>>
>>>> +	 */
>>>> +#define ALU_SHIFT(OPCODE, OP)		\
>>>> +	ALU64_##OPCODE##_X:		\
>>>> +		DST = DST OP (SRC & 63);\
>>>> +		CONT;			\
>>>> +	ALU_##OPCODE##_X:		\
>>>> +		DST = (u32) DST OP ((u32)SRC & 31);	\
>>>> +		CONT;			\
>>>> +	ALU64_##OPCODE##_K:		\
>>>> +		DST = DST OP (IMM & 63);	\
>>>> +		CONT;			\
>>>> +	ALU_##OPCODE##_K:		\
>>>> +		DST = (u32) DST OP ((u32)IMM & 31);	\
>>>> +		CONT;
>>
>> For the *_K cases these are explicitly rejected by the verifier already. Is this
>> required here nevertheless to suppress UBSAN false positive?
> 
> No, I just didn't know that these constants are never out of range.  Please feel
> free to send out a patch that does this properly.

Summarized and fixed via:

https://git.kernel.org/pub/scm/linux/kernel/git/bpf/bpf-next.git/commit/?id=28131e9d933339a92f78e7ab6429f4aaaa07061c

Thanks everyone,
Daniel

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/845ad31f-ca3f-0326-e64b-423a09ea4bea%40iogearbox.net.
