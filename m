Return-Path: <kasan-dev+bncBDLKPY4HVQKBB47JZ2GAMGQEZ2WEQ4A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53c.google.com (mail-ed1-x53c.google.com [IPv6:2a00:1450:4864:20::53c])
	by mail.lfdr.de (Postfix) with ESMTPS id 97DF5453308
	for <lists+kasan-dev@lfdr.de>; Tue, 16 Nov 2021 14:41:07 +0100 (CET)
Received: by mail-ed1-x53c.google.com with SMTP id i9-20020a508709000000b003dd4b55a3casf17246464edb.19
        for <lists+kasan-dev@lfdr.de>; Tue, 16 Nov 2021 05:41:07 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1637070067; cv=pass;
        d=google.com; s=arc-20160816;
        b=t+wzYbNTKz0lj1PwSJE6otuq/RmBzaD0L/eq22es/M01P25E4HOFS3Y3ppJYeX5R27
         vLWd63XK6fd+Y30d13MPOThjeaH7XIXdbiWw2nFOHE8HMQU8mp8eGSK285Ff1MlQSS4p
         N7SocpkwazBxPGO5n1B9lOm0HNXImcUQajyynR9NZXBu8kT8wh5iZqIa1r5B3ozwJyaK
         CmMYCpxVFBz8wFhkMWXg+Q+soPoFQh6BzL7QY2AI1HQ4WTR+zKcEg19heuvKTQ1k5MLH
         c2Gsc9W4/qiGzvCY8W9Y4AJVre5x2cwIVuuTfLNb2TpybhpMjwmVGwRxjXlP+a34HAYi
         DpTA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :in-reply-to:from:references:cc:to:content-language:subject
         :user-agent:mime-version:date:message-id:sender:dkim-signature;
        bh=N6lOXQIW9f6ELVJwWIlh/DkcpVvNNjLt3ahlZuT/2YI=;
        b=So+4ff+Nkst4rfLeiq7D7LrNyxQxiQFgHcuKPIwbTKFBEp3CB8/eIiri998S8kMz5+
         wa/kWnUsnbpBdgj2/jK/n1spBZOzvh9EEFJECbaCnt4uxUMWgPC6QSflQK5kvSIieISZ
         yAG3l5u+qXRCLkEzfFwTpkjuqCFUs0UO8QaQzFqLBh9ezrTDa5LkWe1YBIJIDfjli8LB
         rqxcchpaC0nfhRaDOpTvuQZ/QzpkKzQY38oyjLAhaJV7JEA7dsmHGeCOPqe9amQWuQdV
         O5OJA1C0iphn2qluOeemOXiw2ttaX9P19k3Eh1kuDcyqx97KnTIPvKQmPgf+khjJHL0t
         +mkQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.235.10 as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:message-id:date:mime-version:user-agent:subject
         :content-language:to:cc:references:from:in-reply-to
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=N6lOXQIW9f6ELVJwWIlh/DkcpVvNNjLt3ahlZuT/2YI=;
        b=oVXxOtSj7QN30Ez6MwcTjL4uOC6SkLyXskc3YzO7QNU4afS/ONKRPjjlh7w7qAemi0
         FpB8y7ctb7ZH7/Q4RJ8ev7VAKIXynKenNBFeN/FWoL4iDjpVwUrj2AqLZSB1bSHot9Ky
         m5oSyIqX6JQx4DyjqUw0OqlDemmk3WnjcjcY/6mCWNsg5aBzr7uOIZqAcpHQtjkEm2ai
         XkTgu4kCrHn7KzUFQNUW01UzuRxvfY6LRNAOhQKqpnIQNmG8UrN0To3m5sS4ntQAyDSc
         HOSRx+jZfy+bkEVGPxjkDadPdMM9j8m0o+L1E2qNaDLq8uO4ETGK8iAIBhEkd5nrA44n
         8YoQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:message-id:date:mime-version:user-agent
         :subject:content-language:to:cc:references:from:in-reply-to
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=N6lOXQIW9f6ELVJwWIlh/DkcpVvNNjLt3ahlZuT/2YI=;
        b=fL0piNShsbAtkz2WwUtNELTzowOuLu7gPJ2so5OmQkZt9XybGIzXg7Ln02JM5upik1
         6Kn1oDBHZh6WtzEtavLbhkJFqyf7CBgvcbEi4XLVpgr4J5/wo1P/BQuqFHZrOnqZguQd
         qvLhe3vvn2jR4/hGknfqwgG1YqmoHCHt/3eUjkebwiVqZNkvQcTPt9hvHopvyOUdG7ox
         ZI46cXfdtM8QVH7NyNZ58C83MMntCkVJANd+Y7vE3Uk1xaUAtZG/rzL2RX60MK1t+0sY
         jBiygEFNfZJkkgYCbPLs9wUUNhWQnXxm6IDADNDVmlPMkS0eIWJ/8N0mdQPY5LPUaSQF
         1yZg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530nt40dOP8wX4z6wH2iqtddzX6yX3KtvMDf+/Ryf/AQG7lr5TEB
	/Bp5og0i6wE4Ge3AkZwjHME=
X-Google-Smtp-Source: ABdhPJyKxxTZSjuH8KAjtJbjLcIpwjgovHBI1Gmyw4ZKkVh2aGcPbUg6m8SQPrkr9alXVLIitGTidA==
X-Received: by 2002:a17:907:7d8b:: with SMTP id oz11mr10092194ejc.507.1637070067369;
        Tue, 16 Nov 2021 05:41:07 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a50:8e41:: with SMTP id 1ls2773320edx.0.gmail; Tue, 16 Nov
 2021 05:41:06 -0800 (PST)
X-Received: by 2002:a05:6402:268e:: with SMTP id w14mr10194377edd.48.1637070066476;
        Tue, 16 Nov 2021 05:41:06 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1637070066; cv=none;
        d=google.com; s=arc-20160816;
        b=spnMVDpCanJTbNxhddfZJ641HHrglWy4mjwmc/Ua4X5PWrWPwWkKhXhK3/FgMqpzq0
         ne/RM13Dm08+09HCMNU4i6Bbrj/O4Ki/zmylO4wXr+NhpzFPXqtnb12754QF+t607IDp
         ITqCd/FDcKEDggaRou9D4wxkDgfMRG3JYwCsAJ0Tu0t3kvWAoqVwBFxQGdaGtHYn+9og
         c6qXeHZBUM2voU0gSoHcKwbL+GXW8gApwMOR4XiJghsZyf4fVp5yDDspSMOj504NTx/O
         Tr30gsklXBQg8QrsAKaPxTMgB/jKSDNeBHPoa1ZkcdinuzN11uGx4eQkWbbtQhuiMeIK
         QvFg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id;
        bh=nQ1Gc5SYViUfAk5KqfqKCGyJTu464xnyJQmhfyxWflA=;
        b=O5wGeoUf1JYeAPASR8fN8MPoIpWYNwaYHtTDzLV/+TgwnyGORTHf/vFg8djnQAhD85
         I6g5QBgVuoWnLS+i5OutTflT0xgsABzEX9o43x1OOOIyHFjGsVbF94fDTn7ZOPhiBOsK
         8MWrZ1gDHLSnBCcKS6SkgWlLAMqnv3N0FLo+ReKRLc7BsvaFNAVJsM58ZJWlVg36GQbk
         amhiAiABaaYLbRvOVQ96GfCieABoXS+HhP1dGZw5qqvXXY/TX8k3Eqpv5azjtFJyPdxY
         LuHLGif7X16xHprbSU8lZpiwuWWMapUDymXQr8PArn8OEE0U8xoJ6VKUIzjotSE01OQb
         rRww==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.235.10 as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu
Received: from pegase2.c-s.fr (pegase2.c-s.fr. [93.17.235.10])
        by gmr-mx.google.com with ESMTPS id o19si186300edz.5.2021.11.16.05.41.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 16 Nov 2021 05:41:06 -0800 (PST)
Received-SPF: pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.235.10 as permitted sender) client-ip=93.17.235.10;
Received: from localhost (mailhub3.si.c-s.fr [172.26.127.67])
	by localhost (Postfix) with ESMTP id 4HtnJf0bH4z9sSJ;
	Tue, 16 Nov 2021 14:41:06 +0100 (CET)
X-Virus-Scanned: amavisd-new at c-s.fr
Received: from pegase2.c-s.fr ([172.26.127.65])
	by localhost (pegase2.c-s.fr [127.0.0.1]) (amavisd-new, port 10024)
	with ESMTP id u7mAiaYI_xFI; Tue, 16 Nov 2021 14:41:05 +0100 (CET)
Received: from messagerie.si.c-s.fr (messagerie.si.c-s.fr [192.168.25.192])
	by pegase2.c-s.fr (Postfix) with ESMTP id 4HtnJd6N0tz9sSH;
	Tue, 16 Nov 2021 14:41:05 +0100 (CET)
Received: from localhost (localhost [127.0.0.1])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id C51128B77A;
	Tue, 16 Nov 2021 14:41:05 +0100 (CET)
X-Virus-Scanned: amavisd-new at c-s.fr
Received: from messagerie.si.c-s.fr ([127.0.0.1])
	by localhost (messagerie.si.c-s.fr [127.0.0.1]) (amavisd-new, port 10023)
	with ESMTP id Nh3y__qSDvzK; Tue, 16 Nov 2021 14:41:05 +0100 (CET)
Received: from [192.168.234.8] (unknown [192.168.234.8])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id 036078B763;
	Tue, 16 Nov 2021 14:41:04 +0100 (CET)
Message-ID: <431fb6da-fe21-c5a6-bfb3-4e26bdc153b4@csgroup.eu>
Date: Tue, 16 Nov 2021 14:41:03 +0100
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101
 Thunderbird/91.2.0
Subject: Re: [PATCH v2 3/5] powerpc: Use preemption model accessors
Content-Language: fr-FR
To: Valentin Schneider <valentin.schneider@arm.com>,
 linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
 linuxppc-dev@lists.ozlabs.org, linux-kbuild@vger.kernel.org
Cc: Marco Elver <elver@google.com>, Michal Marek <michal.lkml@markovi.net>,
 Peter Zijlstra <peterz@infradead.org>,
 Frederic Weisbecker <frederic@kernel.org>, Mike Galbraith <efault@gmx.de>,
 Nick Desaulniers <ndesaulniers@google.com>,
 Steven Rostedt <rostedt@goodmis.org>, Paul Mackerras <paulus@samba.org>,
 Masahiro Yamada <masahiroy@kernel.org>, Ingo Molnar <mingo@kernel.org>,
 Dmitry Vyukov <dvyukov@google.com>
References: <20211110202448.4054153-1-valentin.schneider@arm.com>
 <20211110202448.4054153-4-valentin.schneider@arm.com>
From: Christophe Leroy <christophe.leroy@csgroup.eu>
In-Reply-To: <20211110202448.4054153-4-valentin.schneider@arm.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: christophe.leroy@csgroup.eu
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.235.10 as
 permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu
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



Le 10/11/2021 =C3=A0 21:24, Valentin Schneider a =C3=A9crit=C2=A0:
> Per PREEMPT_DYNAMIC, checking CONFIG_PREEMPT doesn't tell you the actual
> preemption model of the live kernel. Use the newly-introduced accessors
> instead.

Is that change worth it for now ? As far as I can see powerpc doesn't=20
have DYNAMIC PREEMPT, a lot of work needs to be done before being able=20
to use it:
- Implement GENERIC_ENTRY
- Implement STATIC_CALLS (already done on PPC32, to be done on PPC64)

>=20
> sched_init() -> preempt_dynamic_init() happens way before IRQs are set up=
,
> so this should be fine.

It looks like you are mixing up interrupts and IRQs (also known as=20
"external interrupts").

ISI (Instruction Storage Interrupt) and DSI (Data Storage Interrupt) for=20
instance are also interrupts. They happen everytime there is a page=20
fault so may happen pretty early.

Traps generated by WARN_ON() are also interrupts that may happen at any=20
time.

>=20
> Signed-off-by: Valentin Schneider <valentin.schneider@arm.com>
> ---
>   arch/powerpc/kernel/interrupt.c | 2 +-
>   arch/powerpc/kernel/traps.c     | 2 +-
>   2 files changed, 2 insertions(+), 2 deletions(-)
>=20
> diff --git a/arch/powerpc/kernel/interrupt.c b/arch/powerpc/kernel/interr=
upt.c
> index de10a2697258..c56c10b59be3 100644
> --- a/arch/powerpc/kernel/interrupt.c
> +++ b/arch/powerpc/kernel/interrupt.c
> @@ -552,7 +552,7 @@ notrace unsigned long interrupt_exit_kernel_prepare(s=
truct pt_regs *regs)
>   		/* Returning to a kernel context with local irqs enabled. */
>   		WARN_ON_ONCE(!(regs->msr & MSR_EE));
>   again:
> -		if (IS_ENABLED(CONFIG_PREEMPT)) {
> +		if (is_preempt_full()) {

I think the cost of that additionnal test should be analysed. Maybe it's=20
worth not doing the test at all and check _TIF_NEED_RESCHED everytime,=20
unless that recurrent test is changed into a jump label as suggested in=20
patch 2.


>   			/* Return to preemptible kernel context */
>   			if (unlikely(current_thread_info()->flags & _TIF_NEED_RESCHED)) {
>   				if (preempt_count() =3D=3D 0)
> diff --git a/arch/powerpc/kernel/traps.c b/arch/powerpc/kernel/traps.c
> index aac8c0412ff9..1cb31bbdc925 100644
> --- a/arch/powerpc/kernel/traps.c
> +++ b/arch/powerpc/kernel/traps.c
> @@ -265,7 +265,7 @@ static int __die(const char *str, struct pt_regs *reg=
s, long err)
>   	printk("%s PAGE_SIZE=3D%luK%s%s%s%s%s%s %s\n",
>   	       IS_ENABLED(CONFIG_CPU_LITTLE_ENDIAN) ? "LE" : "BE",
>   	       PAGE_SIZE / 1024, get_mmu_str(),
> -	       IS_ENABLED(CONFIG_PREEMPT) ? " PREEMPT" : "",
> +	       is_preempt_full() ? " PREEMPT" : "",
>   	       IS_ENABLED(CONFIG_SMP) ? " SMP" : "",
>   	       IS_ENABLED(CONFIG_SMP) ? (" NR_CPUS=3D" __stringify(NR_CPUS)) :=
 "",
>   	       debug_pagealloc_enabled() ? " DEBUG_PAGEALLOC" : "",
>=20

Would it be interesting as well to know that we are indeed in a DYNAMIC=20
PREEMPT context when dying ?

Christophe

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/431fb6da-fe21-c5a6-bfb3-4e26bdc153b4%40csgroup.eu.
