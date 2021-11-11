Return-Path: <kasan-dev+bncBC7OBJGL2MHBBNNUWOGAMGQEIYDC52Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53c.google.com (mail-ed1-x53c.google.com [IPv6:2a00:1450:4864:20::53c])
	by mail.lfdr.de (Postfix) with ESMTPS id 5BA4744D38A
	for <lists+kasan-dev@lfdr.de>; Thu, 11 Nov 2021 09:54:14 +0100 (CET)
Received: by mail-ed1-x53c.google.com with SMTP id y12-20020a056402270c00b003e28de6e995sf4809961edd.11
        for <lists+kasan-dev@lfdr.de>; Thu, 11 Nov 2021 00:54:14 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1636620854; cv=pass;
        d=google.com; s=arc-20160816;
        b=jyTPqKaCEWcmWg/8s7o79YqNR/bXzNmzO906RdUx6xGWrPfZNwjEaPzO2NJbJICRPl
         sI1cHYTkYeMMZITctsknwJpCPc6D9Ubz+QepA57of9s3OyULK9xE18lS5TrwAyOOhcjQ
         tE1U5DBbeVmLzxJFXtBDCfOs8MJRzLRAiaycCcOOAm4JGECi/qD9cfasUmIqJ4lprXW5
         kRrGKIdLHLqttaUEnKWYdQs88mv+PK50jX8k+WuwJYhepOuw6f8mRXTQ8N3UDKKwniZS
         iqJlHWUMoi7LSO/vhVQEFMV39rmev8Qx/iVIkYEk4UYkNVg0C+/q+ry/+cDWjr+zr00x
         TzQQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=FP/6pWSnnh4kdjzc/UyAr9zNe4WaIJkVtToMzd9hreA=;
        b=mYQ6TIiz06bmxRTAMyVgSC2WTjr2rJ3JnNuFYb2vMyecEc/WvSP6taM6h4gW3UuP5V
         k2LGG5AJi10ldCw4ag54lQ+9AqOzk6UN8n3OP8Sw1AT8GQtnBwqlSKA9KfgiikZORLDL
         1/MsR3+S5eNwbO9o0Jot1KGUBSbudOIVAPIO85m825lQOQCAeICabDZshAjEh9dB46Nz
         o7q4SwaXakkJ3eUrJnZfEfv4uWb47ah6Xxvwhvy48LfUpBd9TPy+aW1M1Ddw3RlR9vwh
         7M6H1HvJ3jfcqlCXYewiQRFaL5pzd4mEBcy+d+tWxVbuNznsMJ3UynXzl2MqO+aCPC8W
         YFgA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=hKMluJXv;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::333 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=FP/6pWSnnh4kdjzc/UyAr9zNe4WaIJkVtToMzd9hreA=;
        b=Q026BmgD1OSDMMuFybyZ6tqFv6503TFtdzpgb6FS5b2u9SJo5JhE1+FsRj/fkoE6W3
         SPwLYdoqKWq0jn9VKpcxQIu9hOrJeUsrrBx5Ag5HEvRMB+Hduef0OxlN988eW/12UDUC
         fvugaugj30BkYWNX1NYfsqlnogZHNx0pUXylZEAMVaK4yyqdhLuBzGff9weJiHIEWGzP
         f5VnxsfHyYM3WC6seAzBw9wmfQBygYZFO6t6v+64KExtdv28l0/y+W3bSWbr5joQkcyy
         ZKSTsF93Ho1ZIpeq35RoFiw5QChWprX5U1tUTpSF525IpzUnxqD09J50+oJ+45ND6t6h
         SQAA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=FP/6pWSnnh4kdjzc/UyAr9zNe4WaIJkVtToMzd9hreA=;
        b=frY8r740o06+FyXNzY1PdoLwA/zBuO1NukYHkaVJkUXWKO+H4SrjFnFP3fqjWcaJ7n
         h+4ugRT2S+wuSte7iBuUuEyf0wnRp9qMrD1Mfk8nqf/0f4JTQIxNM2ZYBQomYKXJFmow
         i3hSABadgKgeaj2Yyft3VE50Vb+KMyJNDkq139FNrcvte8LFcs1Sj15IVffsY6XXQ270
         NAmwsvQ/JztLh4ARUUYvv0pNN3TclrDL10g3BA0zjYWBYKaUyO+zqg3lKYFiCL9bGmSO
         v9vjmzYF46dIyElmEEuYrFc3zqA3dKhul+4k4X+TkF24dTuhqgBPf+J3dV9H6spX1R9j
         W+IQ==
X-Gm-Message-State: AOAM533sRkDIeQdpuo++Yh9eVptrcemrK5CjqxvPKxXbKrAs1oU94ShV
	v6gQcWwkVqIlqqySnNScFuo=
X-Google-Smtp-Source: ABdhPJxz7kfE6dy1Dg54qaJnBrZB7WJjfohtZcKjXoTTVMC+vt2h8NLET8s4YVmeLUGG1hgVKTs/Rg==
X-Received: by 2002:a05:6402:2786:: with SMTP id b6mr7579094ede.247.1636620854130;
        Thu, 11 Nov 2021 00:54:14 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:1603:: with SMTP id f3ls2394239edv.0.gmail; Thu, 11
 Nov 2021 00:54:13 -0800 (PST)
X-Received: by 2002:a05:6402:22d6:: with SMTP id dm22mr7671272edb.400.1636620853004;
        Thu, 11 Nov 2021 00:54:13 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1636620853; cv=none;
        d=google.com; s=arc-20160816;
        b=u9W26oPUoTCpvSeWxjxEnPDF6jED9DUCB+p6d56SwOmVtgy0pWRm91TAYkXjcohSNf
         lhw7YW7Ibclr53oaJdg3T95JXhpTuTuJWE96W5KveLC9kDO2z6K4zsedocUor5vUD+6r
         8VtzuaxRsreBvCsITxeMz6qzJcirSP9Ts//aVl2fVcfCujDJbuRy9kwrKmcVdI7FX5RO
         ArGY2rthW4qj+d5zMVpUliiuPdyG+kkD4X4US9ivZHW/UW9pK1G6N1QVq1NXxIBagzAC
         xw1L/a4CKRUgFJWP35k0CBMVtXzrHOr04cLd9T9/gdPu8yKKlRpM2pTsoJe6y7XUMoOw
         qv3A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=C2pRx3VrkRvZzvTAGodY7FBYbqa7VwcKa7WgFhF9R6k=;
        b=dJJkFypQcU8CfsVQb1oOEpHsPOcoaTJbhHvxUtNt8pR5K7+A8h2Oaf8KdzpwlFexIv
         WiNjkxeHNeI8JnHwGj2K2hwm88ONkPCtGbsZsyb95GTZeQegke9gzUJWZovXyLDHXZqD
         /uOxzeT46ymgcoUZvhKhlYETJz5qoialzpi48noHsXdRNft12g9ZDaXWoh1BZ/K44vwX
         cHKqk2cgDMJJgl0s1VODv8KDieP3dbDaUVPN88HJE9hNy2YVqtFZxD0t0f7O5T2FBdSk
         kkk80PKycUvSz2ldSvMMatD/WjisEXT6GPg4szwsJCBNkpLzZJJetniKBHdX74fwFYXM
         kzpQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=hKMluJXv;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::333 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x333.google.com (mail-wm1-x333.google.com. [2a00:1450:4864:20::333])
        by gmr-mx.google.com with ESMTPS id w5si162435ede.3.2021.11.11.00.54.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 11 Nov 2021 00:54:12 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::333 as permitted sender) client-ip=2a00:1450:4864:20::333;
Received: by mail-wm1-x333.google.com with SMTP id az33-20020a05600c602100b00333472fef04so5930400wmb.5
        for <kasan-dev@googlegroups.com>; Thu, 11 Nov 2021 00:54:12 -0800 (PST)
X-Received: by 2002:a05:600c:4f8a:: with SMTP id n10mr6436687wmq.54.1636620852405;
        Thu, 11 Nov 2021 00:54:12 -0800 (PST)
Received: from elver.google.com ([2a00:79e0:15:13:fd21:69cc:1f2b:9812])
        by smtp.gmail.com with ESMTPSA id l2sm8637092wmq.42.2021.11.11.00.54.11
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 11 Nov 2021 00:54:11 -0800 (PST)
Date: Thu, 11 Nov 2021 09:54:05 +0100
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: Valentin Schneider <valentin.schneider@arm.com>
Cc: linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
	linuxppc-dev@lists.ozlabs.org, linux-kbuild@vger.kernel.org,
	Peter Zijlstra <peterz@infradead.org>,
	Ingo Molnar <mingo@kernel.org>,
	Frederic Weisbecker <frederic@kernel.org>,
	Mike Galbraith <efault@gmx.de>, Dmitry Vyukov <dvyukov@google.com>,
	Michael Ellerman <mpe@ellerman.id.au>,
	Benjamin Herrenschmidt <benh@kernel.crashing.org>,
	Paul Mackerras <paulus@samba.org>,
	Steven Rostedt <rostedt@goodmis.org>,
	Masahiro Yamada <masahiroy@kernel.org>,
	Michal Marek <michal.lkml@markovi.net>,
	Nick Desaulniers <ndesaulniers@google.com>
Subject: Re: [PATCH v2 2/5] preempt/dynamic: Introduce preempt mode accessors
Message-ID: <YYzaLTtf1tFbqDSn@elver.google.com>
References: <20211110202448.4054153-1-valentin.schneider@arm.com>
 <20211110202448.4054153-3-valentin.schneider@arm.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20211110202448.4054153-3-valentin.schneider@arm.com>
User-Agent: Mutt/2.0.5 (2021-01-21)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=hKMluJXv;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::333 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Wed, Nov 10, 2021 at 08:24PM +0000, Valentin Schneider wrote:
[...]
> +#ifdef CONFIG_PREEMPT_DYNAMIC
> +
> +extern bool is_preempt_none(void);
> +extern bool is_preempt_voluntary(void);
> +extern bool is_preempt_full(void);
> +
> +#else
> +
> +#define is_preempt_none() IS_ENABLED(CONFIG_PREEMPT_NONE)
> +#define is_preempt_voluntary() IS_ENABLED(CONFIG_PREEMPT_VOLUNTARY)
> +#define is_preempt_full() IS_ENABLED(CONFIG_PREEMPT)
> +
> +#endif
> +
> +#define is_preempt_rt() IS_ENABLED(CONFIG_PREEMPT_RT)
> +

Can these callables be real functions in all configs, making the
!DYNAMIC ones just static inline bool ones? That'd catch invalid use in
#if etc. in all configs.

>  /*
>   * Does a critical section need to be broken due to another
>   * task waiting?: (technically does not depend on CONFIG_PREEMPTION,
> diff --git a/kernel/sched/core.c b/kernel/sched/core.c
> index 97047aa7b6c2..9db7f77e53c3 100644
> --- a/kernel/sched/core.c
> +++ b/kernel/sched/core.c
> @@ -6638,6 +6638,17 @@ static void __init preempt_dynamic_init(void)
>  	}
>  }
>  
> +#define PREEMPT_MODE_ACCESSOR(mode) \
> +	bool is_preempt_##mode(void)						 \
> +	{									 \
> +		WARN_ON_ONCE(preempt_dynamic_mode == preempt_dynamic_undefined); \
> +		return preempt_dynamic_mode == preempt_dynamic_##mode;		 \
> +	}

This needs an EXPORT_SYMBOL, so it's usable from modules like the
kcsan_test module.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YYzaLTtf1tFbqDSn%40elver.google.com.
