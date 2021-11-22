Return-Path: <kasan-dev+bncBDAOBFVI5MIBBR4O56GAMGQEYLLIUQY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33c.google.com (mail-wm1-x33c.google.com [IPv6:2a00:1450:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id 9BF6B459331
	for <lists+kasan-dev@lfdr.de>; Mon, 22 Nov 2021 17:37:27 +0100 (CET)
Received: by mail-wm1-x33c.google.com with SMTP id k25-20020a05600c1c9900b00332f798ba1dsf10429731wms.4
        for <lists+kasan-dev@lfdr.de>; Mon, 22 Nov 2021 08:37:27 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1637599047; cv=pass;
        d=google.com; s=arc-20160816;
        b=NypT2SNdlaq8eqlJXowi9ZICztVLcZYRLT4dbfduC4cT+3A283tgTO3iK8jZVXaod3
         OKnhMPXjIJ1kjC4yHywESZJaQY9lW8OtkicKhTLkEosaKcFmqxkqbWwKevbkNikbEPwh
         5s6EFCWM6/7fX+KoM0NMcohVeeI7ieqFxfIvyug/m4k7kRWJA/kQ9bYPDpiMeJiL2r6D
         hVHaRPcUNdVNwViaZJJYjhURguIWEUO4BVaMmI6OROp/YaADxhCoZrW/9JNiuyIOFZgI
         u72zCi1mhfid97uGk+8U66yEzh8JsUbChIwzQpGKEsnJe34IoGO+eRrLiDRxHbD6PtW0
         cjWg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :mime-version:message-id:date:references:in-reply-to:subject:cc:to
         :from:sender:dkim-signature;
        bh=KYRKKOTxUigz8km+ItRH8YKyGy+FDeaH4L3584gzMGY=;
        b=mvFPAx64PssgBr5fqOaI7tb4WJ2lEVzaQJZEBj8ogUANY6F+PeAVZ27wfwBxanH0Z1
         KNdn1vo0dgfvDMtcJno6e22LnDPwgXiA/FhQfoKJsvbbyJz53BVXBE2hyp/ovNpFqQQ0
         G+Yr71fMZxUVgqSRMLMO7RP/A7VM4zDmtJEselZsQfHRWpA0gcB99WbO3QoCrUsr11gH
         3HtsPnHPELoNRFgIBOSI3uU7OHkp37ydrFbvODMgKstsL9Y9YbleFaZH691e+JKiPgts
         mIdnmcELaZumCPWEjNXPv99jyEIKowiSSZUf/r3dN54+spdTaojRu4xm2SJ77eJs7EYL
         YixA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of valentin.schneider@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=valentin.schneider@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:in-reply-to:references:date:message-id
         :mime-version:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=KYRKKOTxUigz8km+ItRH8YKyGy+FDeaH4L3584gzMGY=;
        b=OZkquLD0JzDN69GRx8OOuzFEOlOV37KDtIjcU50UDzHWvC29W6Y4OPJxyri6D59Itb
         ZsefReAQ+6c9j4gb6hOYAutqrJHT8mZL9KOnLKYgLfjdSvlzs3chuEQYFV3KFbVgAOf6
         6ul610nC7kFpuSdlgOvuHfoqD+wzN8rplautk6TUBc1Oa2gI6Rrz2bjiIncVmE8fVCJM
         IGzLeLopdLqTuRaDMBDPiddLf5mR9Z1vpj+sKqM7qOTEsbgH6MQDg4orjsKnQJXY19tW
         VxMLMUfYjC4m4xnF5UuakfDvaunX3nFHt7pDhBPWIyI/Vos50dkysbR4Vs/z7STCgiKq
         LNPQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:in-reply-to:references
         :date:message-id:mime-version:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=KYRKKOTxUigz8km+ItRH8YKyGy+FDeaH4L3584gzMGY=;
        b=2y2HhkStwpg+NarIkskArlsJ1GUMMMsORI8eGnf78xiOsjss5uuJJlUbfHDR5PUQ9T
         Qh1DVbRcm6dwmIICw5B+hzkyZHaxkehYy/772fc/t/9kymQoEOsR+KvXVG8StP64isjc
         +EBUjN8UCn4nk0dP0h5MGq5Lye8cHbcqQbYAnKXIG4BfhavLplHe1WSIiuXDeQkbCvb7
         cZf8OiSxmx87D1t6s+fpAKszmEJYlo8xOM46sT+01rpnq5VwWS7Up0jevLuaOvSkzBHB
         LFCeFJ3AKHu2R4r2OCoRMg4sVzzLBFBL7bbmb2D24Lc60OeWToz5eiaWZyrAdx9bTIax
         BNOQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532ThEes5jRjtnlwFxTuvHgxP+Ic6KNl+GOgZy3CsT2+mml8xyNe
	pmTSwAx0Tbd6UuXMmD1buHE=
X-Google-Smtp-Source: ABdhPJwshXFM1M0TGLC/bVpURJdqb7N2+WO3nqrRAL3vhfUdXHk29FhIrwi3HFlbHJlR+AMeYt3hZA==
X-Received: by 2002:adf:aac5:: with SMTP id i5mr40839643wrc.67.1637599047294;
        Mon, 22 Nov 2021 08:37:27 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:fe0b:: with SMTP id n11ls1343011wrr.0.gmail; Mon, 22 Nov
 2021 08:37:26 -0800 (PST)
X-Received: by 2002:a5d:4443:: with SMTP id x3mr40492733wrr.189.1637599046465;
        Mon, 22 Nov 2021 08:37:26 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1637599046; cv=none;
        d=google.com; s=arc-20160816;
        b=G6uXDwfvcVxOgTEsIMM5Cq1GCu/GboK7kDPZvKXkprRraC+jcUzKTe/bZ1iRkmv4/Q
         4J7gI5t3+a6Fxbdz3kj+JEQaBst4rvCC12Qr0QrpLpcrHZE4iN3rmhnTpY7rpRU23xIU
         VM3zeUSVwkZZh7ba3SahIPgtwPq2NS0d3FWlhTXlCM7fO6XNkZZCMFNBrkyI3RC6CwcJ
         8llpqvCB7+y69uYiWC2c5uUT+Wrm08t28Op8QoBdH0CWu91BEwh56AqlU8/9SrT1k1vC
         IEjkQHE4gjc4oT6vIfLJuY64oUZM0vkw+rgYtCh/fpzFmZumT5J/toRFDl99c+QohL3D
         1ynQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:references
         :in-reply-to:subject:cc:to:from;
        bh=hAGghvXqo+MMbjLcUQQs/8YfFpiLGLQDQ+gt/TijPYg=;
        b=kR3IwaiKt0XLxrJrQ3TlBFXJ5U02zf+dCS2OOv++Aq//vQbuCBRC4auGe5gS6LM5mZ
         cqMReF/GluWk2SNuMehp6FISRLwaZP1/Zk33V1Hf+jqa0Z6tnRm2IgOzv+vpPr2XbOw/
         QVXaqjnBZ/5l0Tmx8/8ozqjvzRqDWkdNy8WqkT/zQN+2pua6aNU5qh15OevDcOd6JK3j
         DPunWgOy2ppsqnhU57LGvhkcIVr953dS9uX6Q5FFNBUtK2f6f8mEts43ZW/2+guh0Ayt
         GHCsi8uRTR/AcDX6HUmX2ckbvOBahqxCGhqOlP4wUDP0TorUyrMU3w12973S/qDSAV5g
         6q0A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of valentin.schneider@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=valentin.schneider@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id o19si931780wme.2.2021.11.22.08.37.26
        for <kasan-dev@googlegroups.com>;
        Mon, 22 Nov 2021 08:37:26 -0800 (PST)
Received-SPF: pass (google.com: domain of valentin.schneider@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 57A04ED1;
	Mon, 22 Nov 2021 08:37:25 -0800 (PST)
Received: from e113632-lin (usa-sjc-imap-foss1.foss.arm.com [10.121.207.14])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 5A2243F66F;
	Mon, 22 Nov 2021 08:37:23 -0800 (PST)
From: Valentin Schneider <valentin.schneider@arm.com>
To: Christophe Leroy <christophe.leroy@csgroup.eu>, linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, linuxppc-dev@lists.ozlabs.org, linux-kbuild@vger.kernel.org
Cc: Marco Elver <elver@google.com>, Michal Marek <michal.lkml@markovi.net>, Peter Zijlstra <peterz@infradead.org>, Frederic Weisbecker <frederic@kernel.org>, Mike Galbraith <efault@gmx.de>, Nick Desaulniers <ndesaulniers@google.com>, Steven Rostedt <rostedt@goodmis.org>, Paul Mackerras <paulus@samba.org>, Masahiro Yamada <masahiroy@kernel.org>, Ingo Molnar <mingo@kernel.org>, Dmitry Vyukov <dvyukov@google.com>
Subject: Re: [PATCH v2 2/5] preempt/dynamic: Introduce preempt mode accessors
In-Reply-To: <2f22c57d-9bf0-3cc1-f0f1-61ecdf5dfa52@csgroup.eu>
References: <20211110202448.4054153-1-valentin.schneider@arm.com> <20211110202448.4054153-3-valentin.schneider@arm.com> <2f22c57d-9bf0-3cc1-f0f1-61ecdf5dfa52@csgroup.eu>
Date: Mon, 22 Nov 2021 16:37:16 +0000
Message-ID: <87y25gcfk3.mognet@arm.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
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

On 16/11/21 14:29, Christophe Leroy wrote:
> Le 10/11/2021 =C3=A0 21:24, Valentin Schneider a =C3=A9crit=C2=A0:
>> CONFIG_PREEMPT{_NONE, _VOLUNTARY} designate either:
>> o The build-time preemption model when !PREEMPT_DYNAMIC
>> o The default boot-time preemption model when PREEMPT_DYNAMIC
>>
>> IOW, using those on PREEMPT_DYNAMIC kernels is meaningless - the actual
>> model could have been set to something else by the "preempt=3Dfoo" cmdli=
ne
>> parameter.
>>
>> Introduce a set of helpers to determine the actual preemption mode used =
by
>> the live kernel.
>>
>> Suggested-by: Marco Elver <elver@google.com>
>> Signed-off-by: Valentin Schneider <valentin.schneider@arm.com>
>> ---
>>   include/linux/sched.h | 16 ++++++++++++++++
>>   kernel/sched/core.c   | 11 +++++++++++
>>   2 files changed, 27 insertions(+)
>>
>> diff --git a/include/linux/sched.h b/include/linux/sched.h
>> index 5f8db54226af..0640d5622496 100644
>> --- a/include/linux/sched.h
>> +++ b/include/linux/sched.h
>> @@ -2073,6 +2073,22 @@ static inline void cond_resched_rcu(void)
>>   #endif
>>   }
>>
>> +#ifdef CONFIG_PREEMPT_DYNAMIC
>> +
>> +extern bool is_preempt_none(void);
>> +extern bool is_preempt_voluntary(void);
>> +extern bool is_preempt_full(void);
>
> Those are trivial tests supposed to be used in fast pathes. They should
> be static inlines in order to minimise the overhead.
>
>> +
>> +#else
>> +
>> +#define is_preempt_none() IS_ENABLED(CONFIG_PREEMPT_NONE)
>> +#define is_preempt_voluntary() IS_ENABLED(CONFIG_PREEMPT_VOLUNTARY)
>> +#define is_preempt_full() IS_ENABLED(CONFIG_PREEMPT)
>
> Would be better to use static inlines here as well instead of macros.
>

I realize I stripped all ppc folks from the cclist after dropping the ppc
snippet, but you guys might still be interested - my bad. That's done in
v3:

https://lore.kernel.org/lkml/20211112185203.280040-1-valentin.schneider@arm=
.com/

>> +
>> +#endif
>> +
>> +#define is_preempt_rt() IS_ENABLED(CONFIG_PREEMPT_RT)
>> +
>>   /*
>>    * Does a critical section need to be broken due to another
>>    * task waiting?: (technically does not depend on CONFIG_PREEMPTION,
>> diff --git a/kernel/sched/core.c b/kernel/sched/core.c
>> index 97047aa7b6c2..9db7f77e53c3 100644
>> --- a/kernel/sched/core.c
>> +++ b/kernel/sched/core.c
>> @@ -6638,6 +6638,17 @@ static void __init preempt_dynamic_init(void)
>>      }
>>   }
>>
>> +#define PREEMPT_MODE_ACCESSOR(mode) \
>> +	bool is_preempt_##mode(void)						 \
>> +	{									 \
>> +		WARN_ON_ONCE(preempt_dynamic_mode =3D=3D preempt_dynamic_undefined); =
\
>
> Not sure using WARN_ON is a good idea here, as it may be called very
> early, see comment on powerpc patch.

Bah, I was gonna say that you *don't* want users of is_preempt_*() to be
called before the "final" preemption model is set up (such users would need
to make use of static_calls), but I realize there's a debug interface to
flip the preemption model at will... Say an initcall sees
is_preempt_voluntary() and sets things up accordingly, and then the debug
knob switches to preempt_full. I don't think there's much we can really do
here though :/

>
>> +		return preempt_dynamic_mode =3D=3D preempt_dynamic_##mode;		 \
>> +	}
>
> I'm not sure that's worth a macro. You only have 3 accessors, 2 lines of
> code each. Just define all 3 in plain text.
>
> CONFIG_PREEMPT_DYNAMIC is based on using strategies like static_calls in
> order to minimise the overhead. For those accessors you should use the
> same kind of approach and use things like jump_labels in order to not
> redo the test at each time and minimise overhead as much as possible.
>

That's a valid point, though the few paths that need patching up and don't
make use of static calls already (AFAICT the ppc irq path I was touching in
v2 needs to make use of irqentry_exit_cond_resched()) really seem like
slow-paths.

>> +
>> +PREEMPT_MODE_ACCESSOR(none)
>> +PREEMPT_MODE_ACCESSOR(voluntary)
>> +PREEMPT_MODE_ACCESSOR(full)
>> +
>>   #else /* !CONFIG_PREEMPT_DYNAMIC */
>>
>>   static inline void preempt_dynamic_init(void) { }
>>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/87y25gcfk3.mognet%40arm.com.
