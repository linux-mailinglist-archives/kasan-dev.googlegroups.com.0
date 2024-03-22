Return-Path: <kasan-dev+bncBCMIFTP47IJBBXP46OXQMGQEIALFQXY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3e.google.com (mail-oa1-x3e.google.com [IPv6:2001:4860:4864:20::3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 589D288659D
	for <lists+kasan-dev@lfdr.de>; Fri, 22 Mar 2024 04:43:27 +0100 (CET)
Received: by mail-oa1-x3e.google.com with SMTP id 586e51a60fabf-221d1cc21desf2010668fac.3
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Mar 2024 20:43:27 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1711079006; cv=pass;
        d=google.com; s=arc-20160816;
        b=xI4GRBvXzXUG1PzSfw2fmReNWJ46OBiiIOieAiRFSUXqeArMwVR9nhqdZEmGyO7mMc
         +U2b7kqrP8yBdSmEQrHvgBHk1CL9QulHa5a2CmbCZ+t/NWuwfOcaKBlcPvYvsNOarpWQ
         F7UzFEEiIsaiIRCfq468BgN7jc/At8r4ZA8wkfHkwUuHaORk94CjEIAuOON4dv3m7ruG
         f/+vAkNOp3A/kqji5j2jAXQytdQF6sD4QVa9qDWo2+fcG3uLfdVG5OT+acHOjeZ8U8Rp
         AgvvKPh37d/70QMXNWSKXpE11CvFfncUTjt3JtFXGAZgsn/PduKttYGRh2z8PSjISznS
         qTLQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to:from
         :references:cc:to:content-language:subject:user-agent:mime-version
         :date:message-id:dkim-signature;
        bh=ioUSZ6IxyN3Gyvn8UGF03NyjTVLNvj/KP7u7kGYO2yk=;
        fh=MDpUAhTXxMnI6rpl0K83TfbC5l9ZD0FEfuF2is3eUwE=;
        b=PKNCouiTQP2+IKF8PPVXd4ZoWKYF60W2M+wUnhHSbqkQVWBqiQa2mz+ViDb6fcocii
         elwVpBKW3g3TuH/U1v3IHl6yyWQeWg131ezZhyNoMZOwU/HoUeAms0RoNh+J7OuBH7z7
         1XueIvBUjrNh3W/df+u4rAMaaRfn2VpRbePvULpkMsd6L4OnX4uen60JkKOd7CJjTv16
         kRiOkwAZSEF9SxNktLiICNSSnzXWpXv1OatOSEjM+d8ILdWpIxq7Gxi0d+rIbL2a/QsG
         LtEVhKLKMUXLtV7KMhQifi7C3X9Tg8hkMkK9cUTm0HQgN+37bHpZ4okLJMrSfyalKm+L
         xHbg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@sifive.com header.s=google header.b=BKuzsNi+;
       spf=pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::135 as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=sifive.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1711079006; x=1711683806; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:from:to:cc:subject:date:message-id
         :reply-to;
        bh=ioUSZ6IxyN3Gyvn8UGF03NyjTVLNvj/KP7u7kGYO2yk=;
        b=Z3722BI3zg7T8qnnTJqsWehaOTC0WouBRjB9JnVTMDimeZjJzmT2uW4FIDICX/nqm9
         eL9SSt+3CnLNkQhY6R4/nh+98yz2/10HuEpx9wFs0WxCdWTDuIiyS4uFCjSfyytycglN
         nqL11VIAz4NImm6rbjHv1ak5NntCgCqmKceAGwP5tqSA1Dg+K149B6ugmo9dSOekMbOG
         ouhXhKrxZy6fwjMIm88FWJGMPw3rVbh2qb4y9GszzkYtOM1i0ZxYEZqRRKwGbHbgjnSW
         ZqNbBNm8KMMIR65sguoKqPzH7EKSpqk0sECP3590t9eA9FDL4Klt5rFL4P3Aamxh2KFn
         hFhA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1711079006; x=1711683806;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:from:to
         :cc:subject:date:message-id:reply-to;
        bh=ioUSZ6IxyN3Gyvn8UGF03NyjTVLNvj/KP7u7kGYO2yk=;
        b=r0yZCrCuOMwqFsSi4ShiyJrjqnz/4oB4SAaNR2f1rS7g9LrfXXQyGEi+Kztw4gqWEm
         zUdGwtRtoHAaJwetQIzXLur3rJN74T54sjgmieOQN0K4c8Za1wFGuU4YmtcMAyv+asAO
         yq5GAOxyCEi3apjydeI/ZGlzLzJdfvtffzu/p7Dc9lMQUaH58vWnGqI50XB9LHOUQRsO
         /K5hRYaMSObEHpkkBcXc/PRqN6XiX9Izmm2QyjmsQxnvWgAaXrppG8ppd67tN+RtnAds
         e83FBIdFDs83EAgO0QLJj9/y4cz8g9k636qSf/Q9b/ZIwZEJymCM8eu1j3PCmtz2n8aY
         dVRg==
X-Forwarded-Encrypted: i=2; AJvYcCWYRrkDmEA1EUCnSyVpVsqHUGW8qNSuroH9NeNIvMs10/T8pjRVfbrwmNDCIf/oOcRVmpL222eqo67n3+B9YcvkR+kAmbe4ZA==
X-Gm-Message-State: AOJu0YzxduCEmwZE5S8z9GYzb5Sxw8RUTS1m7L+hMLKtX72zJjyV2ALQ
	qM6tk9aR+POGXEaTBuqkyPffSDHc53iHxYgUWKjSCqSknUECTzsm
X-Google-Smtp-Source: AGHT+IHYTU2HZmkqSZuQFir7dQFEDlJ8bfUi9rPSyIMZG2MXrw86YtxMC8NU4lDzZhsjRjT40fQuOg==
X-Received: by 2002:a05:6870:4201:b0:221:9ed0:51f3 with SMTP id u1-20020a056870420100b002219ed051f3mr1176882oac.39.1711079005845;
        Thu, 21 Mar 2024 20:43:25 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:46a0:b0:229:eefd:98d5 with SMTP id
 a32-20020a05687046a000b00229eefd98d5ls27489oap.2.-pod-prod-07-us; Thu, 21 Mar
 2024 20:43:25 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCU/1j9EnkJRKaM5HRAcL3wvHfHDSEfO1ZSwKxGFwX8Ldx78oXiXGZb2hgQzTKGeUCUyZX6d9SVN+TT/V6sOfqpf2m3d1LhDIdK7Gw==
X-Received: by 2002:a05:6870:179d:b0:229:a66e:e94e with SMTP id r29-20020a056870179d00b00229a66ee94emr1196562oae.28.1711079004877;
        Thu, 21 Mar 2024 20:43:24 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1711079004; cv=none;
        d=google.com; s=arc-20160816;
        b=ac6ZTm4/SZWL6VyfVb24wphthoyhqvXs4GWoWUW0oirtFneIFlKeC+xEMwQUYx8IIn
         9TggchQbMF7EzJ+YVJRtJCPIL7cte6l+w9iOU/V9Gp/CirOD/o+x1RsNgFQnC/56ygy2
         wU0hTbKHgCP1SKMWeSb+8zSYAVg1B6n59ImGO6z9bqJBhscAx7eINx0hYLl1H8hLeYlZ
         wddyTnCpwSUrNwT90g1s4xe8W49RDGBAl7oPm0Xb4vXYl037PtlOaQsIqbzLaOb/WCV0
         3voALqG+66sIVU5wtanMyAMivHN0wmDdU3VoiACdK+gtVDxeO9R6c0pgKQOjpFU9opmw
         0YWw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=TxrwCimaFyIjWf+99S22XQ+0Yy92SbX36MYkSACyHkI=;
        fh=YeGYQyjy0rChgI7T2vg+03PjVvtVvJbE93/nZgffbac=;
        b=I3uhGjodKmJDIcrthJgAtC4qxBXFUMYBqA/6sjNqyOFulQXJ6OvPJkQ30dILrd3X+B
         PY+4FMcCCfRqG2qsy6re9A2I7blRscp6/v+YHx7j27klNru+NQRxsR1gCEuhk2wQ2kam
         6Z5rGBbXVCcBD/3vuRWr4gOUP2pArmOAp+BeY8iYPfxriKaNmwywOcu3fuCnjVKl4DLw
         btTaAVxp+alMkxcrL4F9UqPcwgRhErSiZw5rrfl9v/bluOLhtm2S28MrjAzo0ZDDRUbg
         LvOhNAVn09/Ub1a7jj6GsJ8UtDLQtfER8cFos1XnnLvnEMMTpB8PUZW8R0OwZSKyRYt5
         7hQQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@sifive.com header.s=google header.b=BKuzsNi+;
       spf=pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::135 as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=sifive.com
Received: from mail-il1-x135.google.com (mail-il1-x135.google.com. [2607:f8b0:4864:20::135])
        by gmr-mx.google.com with ESMTPS id lh22-20020a0568700b1600b00229c91af0easi169230oab.5.2024.03.21.20.43.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 21 Mar 2024 20:43:24 -0700 (PDT)
Received-SPF: pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::135 as permitted sender) client-ip=2607:f8b0:4864:20::135;
Received: by mail-il1-x135.google.com with SMTP id e9e14a558f8ab-366c49ee863so7214725ab.1
        for <kasan-dev@googlegroups.com>; Thu, 21 Mar 2024 20:43:24 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVEujgFGjVyDDWIupntKKMg+DM7CkB8Fy76YGHVBD67uYDNDRZV/Oo1t6cs12142bGjJqy6LcNDwlvNVf4v8ek/QCRo2dD8aZu5Ng==
X-Received: by 2002:a05:6e02:e07:b0:368:5ee4:e5ab with SMTP id a7-20020a056e020e0700b003685ee4e5abmr1564361ilk.4.1711079004428;
        Thu, 21 Mar 2024 20:43:24 -0700 (PDT)
Received: from [100.64.0.1] ([136.226.86.189])
        by smtp.gmail.com with ESMTPSA id u8-20020a056e02080800b00366c4a8990asm329288ilm.27.2024.03.21.20.43.23
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 21 Mar 2024 20:43:24 -0700 (PDT)
Message-ID: <5c8c01be-d847-48bd-aea8-bf40a2576372@sifive.com>
Date: Thu, 21 Mar 2024 22:43:22 -0500
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [RISC-V] [tech-j-ext] [RFC PATCH 5/9] riscv: Split per-CPU and
 per-thread envcfg bits
Content-Language: en-US
To: Deepak Gupta <debug@rivosinc.com>, Andrew Jones <ajones@ventanamicro.com>
Cc: Palmer Dabbelt <palmer@dabbelt.com>, linux-riscv@lists.infradead.org,
 devicetree@vger.kernel.org, Catalin Marinas <catalin.marinas@arm.com>,
 linux-kernel@vger.kernel.org, tech-j-ext@lists.risc-v.org,
 Conor Dooley <conor@kernel.org>, kasan-dev@googlegroups.com,
 Evgenii Stepanov <eugenis@google.com>,
 Krzysztof Kozlowski <krzysztof.kozlowski+dt@linaro.org>,
 Rob Herring <robh+dt@kernel.org>, Guo Ren <guoren@kernel.org>,
 Heiko Stuebner <heiko@sntech.de>, Paul Walmsley <paul.walmsley@sifive.com>
References: <20240319215915.832127-1-samuel.holland@sifive.com>
 <20240319215915.832127-6-samuel.holland@sifive.com>
 <CAKC1njSg9-hJo6hibcM9a-=FUmMWyR39QUYqQ1uwiWhpBZQb9A@mail.gmail.com>
 <40ab1ce5-8700-4a63-b182-1e864f6c9225@sifive.com>
 <17BE5F38AFE245E5.29196@lists.riscv.org>
 <CAKC1njTnheUHs44qUE2sTdr4N=pwUiOc2H1VEMYzYM84JMwe9w@mail.gmail.com>
From: "'Samuel Holland' via kasan-dev" <kasan-dev@googlegroups.com>
In-Reply-To: <CAKC1njTnheUHs44qUE2sTdr4N=pwUiOc2H1VEMYzYM84JMwe9w@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: samuel.holland@sifive.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@sifive.com header.s=google header.b=BKuzsNi+;       spf=pass
 (google.com: domain of samuel.holland@sifive.com designates
 2607:f8b0:4864:20::135 as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=sifive.com
X-Original-From: Samuel Holland <samuel.holland@sifive.com>
Reply-To: Samuel Holland <samuel.holland@sifive.com>
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

Hi Deepak,

On 2024-03-20 6:27 PM, Deepak Gupta wrote:
>>>> And instead of context switching in `_switch_to`,
>>>> In `entry.S` pick up `envcfg` from `thread_info` and write it into CSR.
>>>
>>> The immediate reason is that writing envcfg in ret_from_exception() adds cycles
>>> to every IRQ and system call exit, even though most of them will not change the
>>> envcfg value. This is especially the case when returning from an IRQ/exception
>>> back to S-mode, since envcfg has zero effect there.
>>>
>>> The CSRs that are read/written in entry.S are generally those where the value
>>> can be updated by hardware, as part of taking an exception. But envcfg never
>>> changes on its own. The kernel knows exactly when its value will change, and
>>> those places are:
>>>
>>>  1) Task switch, i.e. switch_to()
>>>  2) execve(), i.e. start_thread() or flush_thread()
>>>  3) A system call that specifically affects a feature controlled by envcfg
>>
>> Yeah I was optimizing for a single place to write instead of
>> sprinkling at multiple places.
>> But I see your argument. That's fine.
>>
> 
> Because this is RFC and we are discussing it. I thought a little bit
> more about this.

Thanks for your comments and the discussion! I know several in-progress features
depend on envcfg, so hopefully we can agree on a design acceptable to everyone.

> If we were to go with the above approach that essentially requires
> whenever a envcfg bit changes, `sync_envcfg`
> has to be called to reflect the correct value.

sync_envcfg() is only needed if the task being updated is `current`. Would it be
more acceptable if this happened inside a helper function? Something like:

static inline void envcfg_update_bits(struct task_struct *task,
				      unsigned long mask, unsigned long val)
{
	unsigned long envcfg;

	envcfg = (task->thread.envcfg & ~mask) | val;
	task->thread.envcfg = envcfg;
	if (task == current)
		csr_write(CSR_ENVCFG, this_cpu_read(riscv_cpu_envcfg) | envcfg);
}

> What if some of these features enable/disable are exposed to `ptrace`
> (gdb, etc use cases) for enable/disable.
> How will syncing work then ?

ptrace_check_attach() ensures the tracee is scheduled out while a ptrace
operation is running, so there is no need to sync anything. Any changes to
task->thread.envcfg are written to the CSR when the tracee is scheduled back in.

> I can see the reasoning behind saving some cycles during trap return.
> But `senvcfg` is not actually a user state, it
> controls the execution environment configuration for user mode. I
> think the best place for this CSR to be written is
> trap return and writing at a single place from a single image on stack
> reduces chances of bugs and errors. And allows
> `senvcfg` features to be exposed to other kernel flows (like `ptrace`)

If ptrace is accessing a process, then task->thread.envcfg is always up to date.
The only complication is that the per-CPU bits need to be ORed back in to get
the real CSR value for another process, but this again is unrelated to whether
the CSR is written in switch_to() or ret_from_exception().

> We can figure out ways on how to optimize in trap return path to avoid
> writing it if we entered and exiting on the same
> task.

Optimizing out the CSR write when the task did not switch requires knowing if
the current task's envcfg was changed during this trip to S-mode... and this
starts looking similar to sync_envcfg().

Regards,
Samuel

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/5c8c01be-d847-48bd-aea8-bf40a2576372%40sifive.com.
