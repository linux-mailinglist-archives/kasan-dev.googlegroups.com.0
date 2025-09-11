Return-Path: <kasan-dev+bncBD53XBUFWQDBBEN7RDDAMGQEKEVDDRA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3a.google.com (mail-oo1-xc3a.google.com [IPv6:2607:f8b0:4864:20::c3a])
	by mail.lfdr.de (Postfix) with ESMTPS id B9FEEB52545
	for <lists+kasan-dev@lfdr.de>; Thu, 11 Sep 2025 03:02:10 +0200 (CEST)
Received: by mail-oo1-xc3a.google.com with SMTP id 006d021491bc7-621790be6a0sf169350eaf.2
        for <lists+kasan-dev@lfdr.de>; Wed, 10 Sep 2025 18:02:10 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757552529; cv=pass;
        d=google.com; s=arc-20240605;
        b=KxjnhxtnCTQo8zo8i7t+WbExZEf0zRb9T38D8yXa59J3txCdogm5DCc2T8AFwFUjmO
         IpmjK7ctACBraGWL/paG2eWmZZ4sTfdCgjASWN9c11gn0PwCammrf/K5A17FINGudSev
         YkPvI3cl8VSoaCraLh8WKqHryPNDNszpr32ZtjbvepvExLeOvyCB1r2aAUN5lF4tlj0O
         9ZhKIyKyIue02f0hEmZMqAdzEpCx4+W6Dh0mpIgdN4Ol0UJeeKs66PAZEgGRJH+NdEhW
         zWNWmp1KbizNf3dxd9mJ8vY6X/HBe1CNmGk8iuxdnKgITzFSMSOO3JWsBdSN9K5t+tQ3
         PeYA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature:dkim-signature;
        bh=CzkTWtrni9tNrqVpPGGKJbS0plP3PS4fUt2PRe7s3Fk=;
        fh=S9KkPUcP16XvU3X0zbKRsM9RuM4y1XvV8h0danHm3z4=;
        b=A6FFE7AQrEeiahaFshxNMJQU2BQZeCbjdFOA13s256YAztn1WEIqG8a8nxqjwdIm4M
         GCMYiQBlT/yTXi2THMkfmRcNOinVYd2aaLMccNgMUicBnVE+GEUDMvqDcIWoP7KonsYP
         ckGzWiLbCHFnANRz0kIjzwF1i6hAdiU1IciU9Q2r9R2nhgbbkb9I4AXbBnwlwDiOnRRH
         sMF89yeF9g21ZWiDzjE0pKLVqEs5ruEv898IPq6ykLny4ajl07h0NG5p4RtiT21NuzOM
         A/HUS8xCM/wqpGNrHv1QdULktC+2xa0D7YNZSZI5jrcgHyyhrBoLvPxSo61dbdnimPsI
         HL1Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=bhIJXpbJ;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::42b as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757552529; x=1758157329; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=CzkTWtrni9tNrqVpPGGKJbS0plP3PS4fUt2PRe7s3Fk=;
        b=Mw5OIeo0Am3Sqwm7Y/Tavkzh1Z2/hTfD3YmKKzf9tQFHdTLn6rZifAlpoMgRe7S53P
         7T9eT5E5rSDEthAqEoT4p6sjj8mWkPH55B08q+HFIOOg5E1+zLv4+Dpq0K+DyvDMJIpn
         pVrMsyR3VNQZxABddLJ6LS+qwshkQuVcsCgWSCv6Pe4QJW+tqkCqJN5kPH1PPPERMr+7
         ST7YWHeYZ4k1HNy/jvI/r7wGXMoQoknuQz3+8c4yIerUovhqYCXqncCJPJb/eUZc3Flb
         HhIMXVBb63VHOQQfZqm2XUAV+S1+utoJFm4FgWjHCzLe3syLVv86JuQGYhmCcu95iKiB
         exrg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1757552529; x=1758157329; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :from:to:cc:subject:date:message-id:reply-to;
        bh=CzkTWtrni9tNrqVpPGGKJbS0plP3PS4fUt2PRe7s3Fk=;
        b=dRqGj+vRhMLc+ZDDtWl9g2/3AlZLaGhSW/UxFyINdcDENo4c1bWu7b1JCy57HQqvw1
         M+aj5rLbVkqL4DWiKaRCLV6TkH1Mx0SqyVNMRj03LTGh76Ca9ujc5Yjtjj+voWpNL/z7
         WDq7tG/2P+cqmhqclLsPYbaAxU//n44+zuHi49nRiWHu7g60csKvoXpiuEglixKYKVC6
         ablS5GaHDrdBDuMMYJRLk/LXJa66g+r17RH9J47GgrbmkhZicFD7vw0BZj4XiB63kokD
         P0coEtkjAMueO01gNQ0P8zqo5PsG8Ysyrmnjt5dXHUEtaLrqcJFoYOsdEAPz1C4rCYRy
         tBVg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757552529; x=1758157329;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=CzkTWtrni9tNrqVpPGGKJbS0plP3PS4fUt2PRe7s3Fk=;
        b=cVwDY9/aI8CLql5t+9LHZ4aD/NPEpizXBQjwbhd0uBt6frxuVw9CqJ5KO+9M9hGXdJ
         hTkYsHRhXEg3T7JmUmFCVZetsMFDzfGCOwLjW0CKE2oi2kQuOkF3bErdP6knDh4ucDB3
         qmuHwVCxnxgwcZwmdRYd5fOATO2Lnwef7RT9ZHZWNTxXufiXO6BfDvCRYjkjvTQ0eCuu
         Di/MbSmdo+m7+9lG0PddtfavNyb5h5jLjxvVCp3Fa+WnkyQ8vKzZdiNbGBuN7akSoD7+
         vjuUwvOX0RV78DBsmmeTGOWf3dDb8KEGYgN3drhoVaAJrok2pL1YOoUC6WtfmmroQdzO
         U4BA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCV6+1Q5YUNcXe9gVL3rOxBXKCWQSVwp2wcuAu/7sRYHNYPvfdejwBubhOJuY25YYsVW3h2jhA==@lfdr.de
X-Gm-Message-State: AOJu0YyU+/lPHzbtSoOsJr8rU6DBgrTbIXxosdWm8hE3pOlLJXFlmabf
	bFBFTVKawxiQ4h0XisMBwq58g/72pe7Z9t7lgE23SsO0S69/nsiPqNJT
X-Google-Smtp-Source: AGHT+IEDdbBipkZCyAFi4mj0fHrQXBk6c3Ah5DRACg+8x0EP31uRTZLxfFfLy9q01KS8SnoH660EiA==
X-Received: by 2002:a05:6820:515:b0:621:9802:d190 with SMTP id 006d021491bc7-6219802d300mr4789107eaf.7.1757552529347;
        Wed, 10 Sep 2025 18:02:09 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfC2A1h3C0moTeTBNRqENTzxBzMpOIlEB6ta3Jm0oSPQQ==
Received: by 2002:a05:6820:8312:b0:621:767d:3566 with SMTP id
 006d021491bc7-621b44d5077ls24318eaf.2.-pod-prod-07-us; Wed, 10 Sep 2025
 18:02:08 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXD7ebTbkh4cgkcMcG9FVI6OzNK/qz2IMGvU+Fudx+qdTo47tvXA8Lt8oNAYc054oobRYQz5JC7Fmo=@googlegroups.com
X-Received: by 2002:a05:6820:624:b0:61f:f591:8a2c with SMTP id 006d021491bc7-6217898bebcmr6728617eaf.0.1757552528283;
        Wed, 10 Sep 2025 18:02:08 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1757552528; cv=none;
        d=google.com; s=arc-20240605;
        b=UZPB1MCZnXd/njhUW6KQYFO6YqP1O/nWfCEIBoaPRkK41IrrUakiGWWFxuxxifPAJx
         s3wgn9Bly/knyMWou/Gfkls44xZizdnOk9Tt3x7KcuedK3Ee8QiawyQdmP2I382gQwc6
         UO0uw/WNBcM4peV5EGEVwEc27AXmVCah9h0wm5oIwEc63jHxPDLnA3m/udxmbDhtkuMZ
         bQ+vVnKMwsRmtKaINQmFmFSigqL8Ijq5jiY/MaWYQdvSGt/SWeYcuYIvbZcn6JfNbQ60
         GhTl5VONsCHpRgmW2+2AmHQJIn+B7C0XEVYzXNWC1MSQtaKzqW7CCtOh26LKK2jGpR4G
         0rew==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=c6RyKxrXBphbUIxCwH62JzKN1u04ZKF0pThPVVL+cJk=;
        fh=X44N1k+ZzyOhdHilhUTOQf9vg7dXDy0q+AtgCqlQcaM=;
        b=gvmIW6qFcFK/DWH/SQh74HrwVestvSKnQGE8eINL+ejn3sYUf8SK9S4dvwdayatEsY
         cMN8iFDWljehH7pTyEypPK4nMe9vK2hZbLSBjyewin20nWMKvQ1nHZk723yZMDqPtC3R
         Cycfx6BO/I95Jd5FVF0lX9/fAufJtEq0dy7PDfflpd/a569CXnEQAplXn09Bdew7OeJ7
         SJXsi0tKd3TJZu3ewy9153B2ZgatPLQ2m0sbtCWJKS7eWT8D+euB0xyjYnisjt5JpDBL
         rxxCSiFeqZalm/Mis1+0E70GnESw19K1GY0MbySGpa+Xn3V3y+O7d2RHtsvdGVK6FJMu
         kIhw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=bhIJXpbJ;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::42b as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pf1-x42b.google.com (mail-pf1-x42b.google.com. [2607:f8b0:4864:20::42b])
        by gmr-mx.google.com with ESMTPS id 006d021491bc7-621b7230713si1665eaf.1.2025.09.10.18.02.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 10 Sep 2025 18:02:08 -0700 (PDT)
Received-SPF: pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::42b as permitted sender) client-ip=2607:f8b0:4864:20::42b;
Received: by mail-pf1-x42b.google.com with SMTP id d2e1a72fcca58-7722c8d2694so158389b3a.3
        for <kasan-dev@googlegroups.com>; Wed, 10 Sep 2025 18:02:08 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVLlUAv8Xu8C5k/yvDfKRtQyV/NO/eqIUzCvgbQdal7osRqD3U8x0o+KdDMHeE2ZfioLHkHNZlrwz4=@googlegroups.com
X-Gm-Gg: ASbGncu25Bp0p6DX9P0Y7nXUniMm2HovpCIaTpkP/G5wMvCF5GsRFww05vE2O6M72ox
	joL1XbTYUJkHL5ZMTTrxvqHSFk7IE09Gh7YI2khSQRpZS6SCvVe+jDn3h9cA4s0FOcHcok0QfdX
	LMN3fKuZT1s7LYpKxwSX4jf1JDDnZPnhrJCtHMB3IPgM/TiAdfPH+4ZHOZ3HdrukGb/FfqgbEge
	7KdF+knLGC7sj0cJsA8/8Rgb5FVroEkeOetrx3vdFIcdcE4ZGJ+FfMkg0eL9qTdrFZ0WhRjWXgu
	gh7c8pb4WJy1g10VSJM7tLrlObQnxtzHiUWAXDkdn1NGnzKuZEnavX+w0+zBUgQneZRZnksGKgk
	X/n9L01G3FdK19lFaJ8SWktZaz0Q=
X-Received: by 2002:a05:6a00:4652:b0:772:5ba4:d75 with SMTP id d2e1a72fcca58-7742dd1270emr21626263b3a.4.1757552527499;
        Wed, 10 Sep 2025 18:02:07 -0700 (PDT)
Received: from [127.0.0.1] ([2a11:3:200::20f3])
        by smtp.gmail.com with ESMTPSA id d2e1a72fcca58-77607b34254sm122807b3a.75.2025.09.10.18.01.52
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 10 Sep 2025 18:02:06 -0700 (PDT)
Message-ID: <5ed43490-6894-4780-8faf-52d5f25bf3cc@gmail.com>
Date: Thu, 11 Sep 2025 09:01:49 +0800
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v3 01/19] x86/hw_breakpoint: introduce
 arch_reinstall_hw_breakpoint() for atomic context
Content-Language: en-US
To: "Masami Hiramatsu (Google)" <mhiramat@kernel.org>
Cc: Andrew Morton <akpm@linux-foundation.org>,
 Peter Zijlstra <peterz@infradead.org>, Mike Rapoport <rppt@kernel.org>,
 "Naveen N . Rao" <naveen@kernel.org>,
 Andrey Ryabinin <ryabinin.a.a@gmail.com>,
 Alexander Potapenko <glider@google.com>,
 Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>,
 Vincenzo Frascino <vincenzo.frascino@arm.com>, kasan-dev@googlegroups.com,
 "David S. Miller" <davem@davemloft.net>, Steven Rostedt
 <rostedt@goodmis.org>, Mathieu Desnoyers <mathieu.desnoyers@efficios.com>,
 Ingo Molnar <mingo@redhat.com>, Arnaldo Carvalho de Melo <acme@kernel.org>,
 Namhyung Kim <namhyung@kernel.org>, Mark Rutland <mark.rutland@arm.com>,
 Alexander Shishkin <alexander.shishkin@linux.intel.com>,
 Jiri Olsa <jolsa@kernel.org>, Ian Rogers <irogers@google.com>,
 Adrian Hunter <adrian.hunter@intel.com>,
 "Liang, Kan" <kan.liang@linux.intel.com>,
 Thomas Gleixner <tglx@linutronix.de>, Borislav Petkov <bp@alien8.de>,
 Dave Hansen <dave.hansen@linux.intel.com>, x86@kernel.org,
 "H. Peter Anvin" <hpa@zytor.com>, linux-mm@kvack.org,
 linux-trace-kernel@vger.kernel.org, linux-perf-users@vger.kernel.org,
 linux-kernel@vger.kernel.org
References: <20250910052335.1151048-1-wangjinchao600@gmail.com>
 <20250910052335.1151048-2-wangjinchao600@gmail.com>
 <20250911094609.5f30e9767ffc3040068ed052@kernel.org>
From: Jinchao Wang <wangjinchao600@gmail.com>
In-Reply-To: <20250911094609.5f30e9767ffc3040068ed052@kernel.org>
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: wangjinchao600@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=bhIJXpbJ;       spf=pass
 (google.com: domain of wangjinchao600@gmail.com designates
 2607:f8b0:4864:20::42b as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
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


On 9/11/25 08:46, Masami Hiramatsu (Google) wrote:
> Hi Jinchao,
>
> On Wed, 10 Sep 2025 13:23:10 +0800
> Jinchao Wang <wangjinchao600@gmail.com> wrote:
>
>> Introduce arch_reinstall_hw_breakpoint() to update hardware breakpoint
>> parameters (address, length, type) without freeing and reallocating the
>> debug register slot.
>>
>> This allows atomic updates in contexts where memory allocation is not
>> permitted, such as kprobe handlers.
>>
>> Signed-off-by: Jinchao Wang <wangjinchao600@gmail.com>
>> ---
>>   arch/x86/include/asm/hw_breakpoint.h |  1 +
>>   arch/x86/kernel/hw_breakpoint.c      | 50 ++++++++++++++++++++++++++++
>>   2 files changed, 51 insertions(+)
>>
>> diff --git a/arch/x86/include/asm/hw_breakpoint.h b/arch/x86/include/asm/hw_breakpoint.h
>> index 0bc931cd0698..bb7c70ad22fe 100644
>> --- a/arch/x86/include/asm/hw_breakpoint.h
>> +++ b/arch/x86/include/asm/hw_breakpoint.h
>> @@ -59,6 +59,7 @@ extern int hw_breakpoint_exceptions_notify(struct notifier_block *unused,
>>   
>>   
>>   int arch_install_hw_breakpoint(struct perf_event *bp);
>> +int arch_reinstall_hw_breakpoint(struct perf_event *bp);
>>   void arch_uninstall_hw_breakpoint(struct perf_event *bp);
>>   void hw_breakpoint_pmu_read(struct perf_event *bp);
>>   void hw_breakpoint_pmu_unthrottle(struct perf_event *bp);
>> diff --git a/arch/x86/kernel/hw_breakpoint.c b/arch/x86/kernel/hw_breakpoint.c
>> index b01644c949b2..89135229ed21 100644
>> --- a/arch/x86/kernel/hw_breakpoint.c
>> +++ b/arch/x86/kernel/hw_breakpoint.c
>> @@ -132,6 +132,56 @@ int arch_install_hw_breakpoint(struct perf_event *bp)
>>   	return 0;
>>   }
>>   
>> +/*
>> + * Reinstall a hardware breakpoint on the current CPU.
>> + *
>> + * This function is used to re-establish a perf counter hardware breakpoint.
>> + * It finds the debug address register slot previously allocated for the
>> + * breakpoint and re-enables it by writing the address to the debug register
>> + * and setting the corresponding bits in the debug control register (DR7).
>> + *
>> + * It is expected that the breakpoint's event context lock is already held
>> + * and interrupts are disabled, ensuring atomicity and safety from other
>> + * event handlers.
>> + */
>> +int arch_reinstall_hw_breakpoint(struct perf_event *bp)
>> +{
>> +	struct arch_hw_breakpoint *info = counter_arch_bp(bp);
>> +	unsigned long *dr7;
>> +	int i;
>> +
>> +	lockdep_assert_irqs_disabled();
>> +
>> +	for (i = 0; i < HBP_NUM; i++) {
>> +		struct perf_event **slot = this_cpu_ptr(&bp_per_reg[i]);
>> +
>> +		if (*slot == bp)
>> +			break;
>> +	}
>> +
>> +	if (WARN_ONCE(i == HBP_NUM, "Can't find a matching breakpoint slot"))
>> +		return -EINVAL;
>> +
>> +	set_debugreg(info->address, i);
>> +	__this_cpu_write(cpu_debugreg[i], info->address);
>> +
>> +	dr7 = this_cpu_ptr(&cpu_dr7);
>> +	*dr7 |= encode_dr7(i, info->len, info->type);
>> +
>> +	/*
>> +	 * Ensure we first write cpu_dr7 before we set the DR7 register.
>> +	 * This ensures an NMI never see cpu_dr7 0 when DR7 is not.
>> +	 */
>> +	barrier();
>> +
>> +	set_debugreg(*dr7, 7);
>> +	if (info->mask)
>> +		amd_set_dr_addr_mask(info->mask, i);
>> +
>> +	return 0;
>> +}
>> +EXPORT_SYMBOL_GPL(arch_reinstall_hw_breakpoint);
> Please do not expose the arch dependent symbol. Instead, you should
> expose an arch independent wrapper.
>
> Anyway, you also need to share the same code with arch_install_hw_breakpoint()
> like below;
>
> Thanks,

You are right. The arch-dependent symbol has been removed and the code 
is shared

with arch_install_hw_breakpoint() in the next version of the patch.

https://lore.kernel.org/lkml/20250910093951.1330637-1-wangjinchao600@gmail.com


>
> diff --git a/arch/x86/kernel/hw_breakpoint.c b/arch/x86/kernel/hw_breakpoint.c
> index 89135229ed21..2f3c5406999e 100644
> --- a/arch/x86/kernel/hw_breakpoint.c
> +++ b/arch/x86/kernel/hw_breakpoint.c
> @@ -84,6 +84,28 @@ int decode_dr7(unsigned long dr7, int bpnum, unsigned *len, unsigned *type)
>   	return (dr7 >> (bpnum * DR_ENABLE_SIZE)) & 0x3;
>   }
>   
> +static void __arch_install_hw_breakpoint(struct perf_event *bp, int regno)
> +{
> +	struct arch_hw_breakpoint *info = counter_arch_bp(bp);
> +	unsigned long *dr7;
> +
> +	set_debugreg(info->address, regno);
> +	__this_cpu_write(cpu_debugreg[i], info->address);
> +
> +	dr7 = this_cpu_ptr(&cpu_dr7);
> +	*dr7 |= encode_dr7(i, info->len, info->type);
> +
> +	/*
> +	 * Ensure we first write cpu_dr7 before we set the DR7 register.
> +	 * This ensures an NMI never see cpu_dr7 0 when DR7 is not.
> +	 */
> +	barrier();
> +
> +	set_debugreg(*dr7, 7);
> +	if (info->mask)
> +		amd_set_dr_addr_mask(info->mask, i);
> +}
> +
>   /*
>    * Install a perf counter breakpoint.
>    *
> @@ -95,8 +117,6 @@ int decode_dr7(unsigned long dr7, int bpnum, unsigned *len, unsigned *type)
>    */
>   int arch_install_hw_breakpoint(struct perf_event *bp)
>   {
> -	struct arch_hw_breakpoint *info = counter_arch_bp(bp);
> -	unsigned long *dr7;
>   	int i;
>   
>   	lockdep_assert_irqs_disabled();
> @@ -113,22 +133,7 @@ int arch_install_hw_breakpoint(struct perf_event *bp)
>   	if (WARN_ONCE(i == HBP_NUM, "Can't find any breakpoint slot"))
>   		return -EBUSY;
>   
> -	set_debugreg(info->address, i);
> -	__this_cpu_write(cpu_debugreg[i], info->address);
> -
> -	dr7 = this_cpu_ptr(&cpu_dr7);
> -	*dr7 |= encode_dr7(i, info->len, info->type);
> -
> -	/*
> -	 * Ensure we first write cpu_dr7 before we set the DR7 register.
> -	 * This ensures an NMI never see cpu_dr7 0 when DR7 is not.
> -	 */
> -	barrier();
> -
> -	set_debugreg(*dr7, 7);
> -	if (info->mask)
> -		amd_set_dr_addr_mask(info->mask, i);
> -
> +	__arch_install_hw_breakpoint(bp, i);
>   	return 0;
>   }
>   
> @@ -146,8 +151,6 @@ int arch_install_hw_breakpoint(struct perf_event *bp)
>    */
>   int arch_reinstall_hw_breakpoint(struct perf_event *bp)
>   {
> -	struct arch_hw_breakpoint *info = counter_arch_bp(bp);
> -	unsigned long *dr7;
>   	int i;
>   
>   	lockdep_assert_irqs_disabled();
> @@ -162,22 +165,7 @@ int arch_reinstall_hw_breakpoint(struct perf_event *bp)
>   	if (WARN_ONCE(i == HBP_NUM, "Can't find a matching breakpoint slot"))
>   		return -EINVAL;
>   
> -	set_debugreg(info->address, i);
> -	__this_cpu_write(cpu_debugreg[i], info->address);
> -
> -	dr7 = this_cpu_ptr(&cpu_dr7);
> -	*dr7 |= encode_dr7(i, info->len, info->type);
> -
> -	/*
> -	 * Ensure we first write cpu_dr7 before we set the DR7 register.
> -	 * This ensures an NMI never see cpu_dr7 0 when DR7 is not.
> -	 */
> -	barrier();
> -
> -	set_debugreg(*dr7, 7);
> -	if (info->mask)
> -		amd_set_dr_addr_mask(info->mask, i);
> -
> +	__arch_install_hw_breakpoint(bp, i);
>   	return 0;
>   }
>   EXPORT_SYMBOL_GPL(arch_reinstall_hw_breakpoint);
>
-- 
Thanks,
Jinchao

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/5ed43490-6894-4780-8faf-52d5f25bf3cc%40gmail.com.
