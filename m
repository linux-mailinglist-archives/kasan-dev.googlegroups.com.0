Return-Path: <kasan-dev+bncBDLKPY4HVQKBBU7EZ2GAMGQEQRU3DNQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x238.google.com (mail-lj1-x238.google.com [IPv6:2a00:1450:4864:20::238])
	by mail.lfdr.de (Postfix) with ESMTPS id 63C674532DA
	for <lists+kasan-dev@lfdr.de>; Tue, 16 Nov 2021 14:29:56 +0100 (CET)
Received: by mail-lj1-x238.google.com with SMTP id o15-20020a2e90cf000000b00218dfebebdesf6195117ljg.13
        for <lists+kasan-dev@lfdr.de>; Tue, 16 Nov 2021 05:29:56 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1637069395; cv=pass;
        d=google.com; s=arc-20160816;
        b=0utvH/Xosk9z3R+qCUnCQ1kURChFSLLsZh2H0iFbT59LcFYBNgGOr1/D93/I2vvLdl
         QF3UaLsmgNaL+QZneS8H5TwMwsMO0jxP/1Fw9zGOFNG6pKd3bfdIG3QAD02eq9UExrKb
         +fqAMEozSB2/O3AgH/ECzpTNHLvFRQMhyjQMXJXjtexd6ALjICs5bfoMI8YvN6v4MreF
         C3t3FvD7tI4O6nhLHvCyxS2wGIa2QtiB5itv7G43OQ03QrpTYFBOcHECxMd5rkbpiUTF
         wrNJ9b8iGoYBkysRCDdOZ2JD0C6uAOk5mfedRqryknb8Pagw59iAVCCgd4CaXA6ELz5S
         2RTw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :in-reply-to:from:references:cc:to:content-language:subject
         :user-agent:mime-version:date:message-id:sender:dkim-signature;
        bh=ejsQzvXOHCNgFLExBVqB0FPCIZoQ3cx+mHEGCTdalVo=;
        b=nEcJJ6ZfL1dA6irKVDtVChXdqUQJkV+dPwCQEDETeOyKDWSNAwMBmRI6MEQ6J4GkCs
         n0dS9af4TgbRPsQTrv+825/qv1yArkurPfYAo9410ELezyN7rHOfVu0OQFEv9xsuiqOd
         4Re2HIr0bI49maHvcLMxFNKrJLjS84p05vb3fNahhXJQ0oy4PaqgJHtl04QWqzlwHiTh
         217fSnWEDBErxPQkJTRDEERgQgz1/zW1ZWpI7ERLJ5tB9QTt7bcmfvj5dq3A/ySDIemS
         sJvWY2jKzW7iQQpC1NEmuUBDHWyOn1DS1pvBI1h0wo01IDG2GOdo43ITD9zki8BcQ3P2
         MoIw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.235.10 as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:message-id:date:mime-version:user-agent:subject
         :content-language:to:cc:references:from:in-reply-to
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=ejsQzvXOHCNgFLExBVqB0FPCIZoQ3cx+mHEGCTdalVo=;
        b=XQT9ixkfNA1+/Bh+R5/E8newzniIwdJYrlXVSupmwPwPOoxD+8m63rkZkksekIDzzu
         0D/aQJnRU04KjGk+wkJzLaukfrj516MCNvANBoDvo8Tlypolj+9wJPnlMnyKezPK7cBP
         z0DbJeWcv/WpGeDqvdBwEKQTV5Y3vYFiqV3T9LgiXPR9MJOdRhWiPyr+TrosecEMxCGG
         VqTo5EW/yI52Cht5lwQxXgF2rEdKYbThgKv04edJolzhKDYaxKHUINfQ7g1W9FVdmoYT
         QnfT8TB9xdNnEjLOiv1sze2wu28bJWX8V8oJXhH5RKCzXMchtHc4ZvbZyZGBHlxj0arZ
         nlAg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:message-id:date:mime-version:user-agent
         :subject:content-language:to:cc:references:from:in-reply-to
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ejsQzvXOHCNgFLExBVqB0FPCIZoQ3cx+mHEGCTdalVo=;
        b=Npk5HKLvAiiY8hVsxgAFOdqS0nGCaHqXpd+x5kylSQf8MlLE478Rz54RcZi4fFLJJU
         G9EVvn1PZ/GPHSKRhj7H0SREWsH53T7BNvYsm+aiIu5oMs2gClQGDEZpStJg8nhXyBI1
         6XdNX8Bzb6/NRZAwANKy2Ts+Bu9Pq/8eJLN5zf6EsZ7N+DZvn14XYhNh8jFcNFqOIIVU
         WuN2EDXM6Yu73B6hE47jTKZ/PxYmwoDg/5BeCf0LoLej7u0TNkArjjN3zrii9JGQ6qaS
         AETTNSINB0LGJ8eVf20TzlmQkXQAnPtvQ2pCPecUBGa+CPBMoxexOc2D6SPIssDyRc1b
         ENyw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5306v0k2GcLzqnnJt1FEKpXbYUWkoV05KbWzTySnCahJfikzNgBx
	cgDnFTkzj6NK1gBbjZb7xA0=
X-Google-Smtp-Source: ABdhPJzW8rKcd5Zhjd+iIS5aLJUsQhcEOnRw85aWLpp+tKbRy4u8cqsJ5vmzsmSsGcFO9IAdkwUoJw==
X-Received: by 2002:a05:6512:3e04:: with SMTP id i4mr6742155lfv.167.1637069395827;
        Tue, 16 Nov 2021 05:29:55 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:2610:: with SMTP id bt16ls376856lfb.2.gmail; Tue,
 16 Nov 2021 05:29:54 -0800 (PST)
X-Received: by 2002:a05:6512:2348:: with SMTP id p8mr6846339lfu.428.1637069394801;
        Tue, 16 Nov 2021 05:29:54 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1637069394; cv=none;
        d=google.com; s=arc-20160816;
        b=nRkeUP144YRHtfdIw9t8VAimLcy/kDx2GBV2IaSK3+6tIUCnpRQdA1SsKM3jeJZG3x
         b62j4oqCN3uln5LhkFMhkdsD7ifvsq/sgXDrOO/fIdMoLpwf2v6SbcNootgZ33JY4Lhi
         n4CIHQYdD4HiVF8XAeHWbgDe1PygBm94rEcWc3zM9IM1aTkQ9rGsp4yXWTICJN/vxi0h
         5/IP8FKGJ4LiEVagW8fqmdcp//7BraUobq4bwYDIggoSv8HCz9arXcayukS76W5bPc24
         UYN59YgWs4N8EiWXGYeJwHkhrojUJ3BRWy0jDx8VA3gj6xquBQnR2dOjE4LfRQWtrSAp
         bzpw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id;
        bh=zr3GahUMNSp9KOfquKN/GwDfv6NI9JWhLSnHMxCyGeg=;
        b=VIwfpm4BEeKB4KhMU4RjzrpT1diyBKvpKHYQvB+MS0NTlsYvBGSGGdXiXeOcoALK1y
         mXUnX0m5lf3s4SOSgoZ7r7EMu5S96Uvio3tVuQL0TnMqarQwxY8RjIWbZrgZLJdRoNP2
         s3uB46WwqIZRqoFppslX3LSBfZAjbT2Rq+oxgocAGotpb00Q65O3Cwi1D7pGVSZi0Kd2
         XkYXF99uYRdGCGmPjuOCPPZddq/J2wDPejCEbr9MZmXo+taLfDwrQLQRvaCydW1Bzkee
         KRuDQzFsvFCFvKlaQBgiD/N/ro1n/scNTHtXsx9+9wCtjeHz0Mb5/HcU2etiiznv1Cyf
         DZJw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.235.10 as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu
Received: from pegase2.c-s.fr (pegase2.c-s.fr. [93.17.235.10])
        by gmr-mx.google.com with ESMTPS id x65si923469lff.10.2021.11.16.05.29.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 16 Nov 2021 05:29:54 -0800 (PST)
Received-SPF: pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.235.10 as permitted sender) client-ip=93.17.235.10;
Received: from localhost (mailhub3.si.c-s.fr [172.26.127.67])
	by localhost (Postfix) with ESMTP id 4Htn3j6dQLz9sSJ;
	Tue, 16 Nov 2021 14:29:53 +0100 (CET)
X-Virus-Scanned: amavisd-new at c-s.fr
Received: from pegase2.c-s.fr ([172.26.127.65])
	by localhost (pegase2.c-s.fr [127.0.0.1]) (amavisd-new, port 10024)
	with ESMTP id US9XL2ibzr6x; Tue, 16 Nov 2021 14:29:53 +0100 (CET)
Received: from messagerie.si.c-s.fr (messagerie.si.c-s.fr [192.168.25.192])
	by pegase2.c-s.fr (Postfix) with ESMTP id 4Htn3j50jLz9sSH;
	Tue, 16 Nov 2021 14:29:53 +0100 (CET)
Received: from localhost (localhost [127.0.0.1])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id 95FD48B77A;
	Tue, 16 Nov 2021 14:29:53 +0100 (CET)
X-Virus-Scanned: amavisd-new at c-s.fr
Received: from messagerie.si.c-s.fr ([127.0.0.1])
	by localhost (messagerie.si.c-s.fr [127.0.0.1]) (amavisd-new, port 10023)
	with ESMTP id f2Vdc5Ovhuop; Tue, 16 Nov 2021 14:29:53 +0100 (CET)
Received: from [192.168.234.8] (unknown [192.168.234.8])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id BFA358B763;
	Tue, 16 Nov 2021 14:29:52 +0100 (CET)
Message-ID: <2f22c57d-9bf0-3cc1-f0f1-61ecdf5dfa52@csgroup.eu>
Date: Tue, 16 Nov 2021 14:29:51 +0100
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101
 Thunderbird/91.2.0
Subject: Re: [PATCH v2 2/5] preempt/dynamic: Introduce preempt mode accessors
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
 <20211110202448.4054153-3-valentin.schneider@arm.com>
From: Christophe Leroy <christophe.leroy@csgroup.eu>
In-Reply-To: <20211110202448.4054153-3-valentin.schneider@arm.com>
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
> CONFIG_PREEMPT{_NONE, _VOLUNTARY} designate either:
> o The build-time preemption model when !PREEMPT_DYNAMIC
> o The default boot-time preemption model when PREEMPT_DYNAMIC
>=20
> IOW, using those on PREEMPT_DYNAMIC kernels is meaningless - the actual
> model could have been set to something else by the "preempt=3Dfoo" cmdlin=
e
> parameter.
>=20
> Introduce a set of helpers to determine the actual preemption mode used b=
y
> the live kernel.
>=20
> Suggested-by: Marco Elver <elver@google.com>
> Signed-off-by: Valentin Schneider <valentin.schneider@arm.com>
> ---
>   include/linux/sched.h | 16 ++++++++++++++++
>   kernel/sched/core.c   | 11 +++++++++++
>   2 files changed, 27 insertions(+)
>=20
> diff --git a/include/linux/sched.h b/include/linux/sched.h
> index 5f8db54226af..0640d5622496 100644
> --- a/include/linux/sched.h
> +++ b/include/linux/sched.h
> @@ -2073,6 +2073,22 @@ static inline void cond_resched_rcu(void)
>   #endif
>   }
>  =20
> +#ifdef CONFIG_PREEMPT_DYNAMIC
> +
> +extern bool is_preempt_none(void);
> +extern bool is_preempt_voluntary(void);
> +extern bool is_preempt_full(void);

Those are trivial tests supposed to be used in fast pathes. They should=20
be static inlines in order to minimise the overhead.

> +
> +#else
> +
> +#define is_preempt_none() IS_ENABLED(CONFIG_PREEMPT_NONE)
> +#define is_preempt_voluntary() IS_ENABLED(CONFIG_PREEMPT_VOLUNTARY)
> +#define is_preempt_full() IS_ENABLED(CONFIG_PREEMPT)

Would be better to use static inlines here as well instead of macros.

> +
> +#endif
> +
> +#define is_preempt_rt() IS_ENABLED(CONFIG_PREEMPT_RT)
> +
>   /*
>    * Does a critical section need to be broken due to another
>    * task waiting?: (technically does not depend on CONFIG_PREEMPTION,
> diff --git a/kernel/sched/core.c b/kernel/sched/core.c
> index 97047aa7b6c2..9db7f77e53c3 100644
> --- a/kernel/sched/core.c
> +++ b/kernel/sched/core.c
> @@ -6638,6 +6638,17 @@ static void __init preempt_dynamic_init(void)
>   	}
>   }
>  =20
> +#define PREEMPT_MODE_ACCESSOR(mode) \
> +	bool is_preempt_##mode(void)						 \
> +	{									 \
> +		WARN_ON_ONCE(preempt_dynamic_mode =3D=3D preempt_dynamic_undefined); \

Not sure using WARN_ON is a good idea here, as it may be called very=20
early, see comment on powerpc patch.

> +		return preempt_dynamic_mode =3D=3D preempt_dynamic_##mode;		 \
> +	}

I'm not sure that's worth a macro. You only have 3 accessors, 2 lines of=20
code each. Just define all 3 in plain text.

CONFIG_PREEMPT_DYNAMIC is based on using strategies like static_calls in=20
order to minimise the overhead. For those accessors you should use the=20
same kind of approach and use things like jump_labels in order to not=20
redo the test at each time and minimise overhead as much as possible.

> +
> +PREEMPT_MODE_ACCESSOR(none)
> +PREEMPT_MODE_ACCESSOR(voluntary)
> +PREEMPT_MODE_ACCESSOR(full)
> +
>   #else /* !CONFIG_PREEMPT_DYNAMIC */
>  =20
>   static inline void preempt_dynamic_init(void) { }
>=20

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/2f22c57d-9bf0-3cc1-f0f1-61ecdf5dfa52%40csgroup.eu.
