Return-Path: <kasan-dev+bncBAABBT5CXG6AMGQEDUURUTI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x437.google.com (mail-wr1-x437.google.com [IPv6:2a00:1450:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id B5A25A16D75
	for <lists+kasan-dev@lfdr.de>; Mon, 20 Jan 2025 14:36:17 +0100 (CET)
Received: by mail-wr1-x437.google.com with SMTP id ffacd0b85a97d-388d1f6f3b2sf1930592f8f.0
        for <lists+kasan-dev@lfdr.de>; Mon, 20 Jan 2025 05:36:17 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1737380177; cv=pass;
        d=google.com; s=arc-20240605;
        b=gXekMSQ4EaUxq/hD2LhQAAJsiAbn6unzovUEx7dOFJzTEK8KdLH0mXvpi8elpdtglM
         SaPdXeO64BD9FTBn8JHODUFmNlwyt/jDAIdWLR6Ob0UWd3TVXxpss3sgadWLtbwLJZH0
         9IFX2PzAVdZkWTQtaF0uqZjjWZs+xQxB4Vix+fAPjrg233SWRBHk8soN7fj4seLukymd
         Txt+D8BcLmdYRRTDVwfvm6m7YZ6AIHvOpd1ngDVIPE2aXf9K/v4w/R9fYoErL1rJJsfT
         lcFhL0pCWEqpokqhXfatCnVrMR3glXSOXlCODqRAbN5W33shZMPtnxMRYhZV4lqHIdTC
         /WZg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=D1I92WiKzjf7b37oJ3Z+wOq41TgPfYZtLuZQ5jHYOwM=;
        fh=qa7/tqwCOGWo8SBgWrWahfPk0K1755cOFhpK/mhOIMU=;
        b=JpFElGlgejEeuwQrZ07+j/lPO7MLIvqRNeePiRE0xFtsqVFiYC2BX5h8QFf0vxVHHf
         DembXCFK5w3DJLWyowAUVkGQzLpkdoIfnG3l73qLLzrpt8p83abhpXXH8QYGZv1UTMGb
         1zTquWsWruNXvWeQCV9XyE/F+g8+ImKgC22D/ghDl1GtCz2lX4fUEMVBFrtw84eHtVbp
         lrgtQaDf06zDamwb+IX8UfE0xEPD4BnybtOTRjSn0Y2GdW/OnVonjlkK2V3S5fnrUdZ6
         gMp/7hhRf21p1g1Y3yZqESTLOzJAMHHd5omQXny26yusdRsT/zCX4ruNepucn3yGLtZw
         A2bA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=ucadM5bO;
       dkim=neutral (no key) header.i=@linutronix.de;
       spf=pass (google.com: domain of t-8ch@linutronix.de designates 193.142.43.55 as permitted sender) smtp.mailfrom=t-8ch@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1737380177; x=1737984977; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=D1I92WiKzjf7b37oJ3Z+wOq41TgPfYZtLuZQ5jHYOwM=;
        b=mrsmkfWD0Nwq+70YDQHBYyPkugoWR7yTSOnTw0MWsrvSvPh7WwJlq7TVd8YhZNGIY5
         GFclt3dXMj+avMDDW52oOD0qXPUgKSD14F8mcPYLvM9+od/ODa0ee3PQJqmon2x0+Pn5
         kzuNgpxLlxq3EKC9XyNoYSmpfkDXggqixo0EojfZf8Kmcd6nBNheZSDzA5yAY+KdSUvN
         QZc9cyrKzJ7/y4b7mSsf/lDIwTY8wTZBqbkAvQ7vY0+ick8Q6xFG4P64WkDwQMw3+5Nb
         0RgiFLy4rxK5nxXcRPIhWrX/sccIlSwKr+lOmwkv65tFumPn3gamuYaCovg2jmHqUsYu
         PDjg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1737380177; x=1737984977;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=D1I92WiKzjf7b37oJ3Z+wOq41TgPfYZtLuZQ5jHYOwM=;
        b=PiJ2t3uBZdfrRvL8SiH09E+QNvmrwdmDMoqLCbyKhwrtAuUUx6fuMmmGi6y4+V3gTO
         aS8dwm+W1XFr59CEoXYiYk6lmTlG7KbSN2mprZSjS/ZTr5g0wi3gi4segevsNJrCLbjS
         9XLbkZrrJy5YPSM7ImzYnsujRfFueTPrBALL8fMq/aVYj+jXqES0Jey/JWBdVAr3F8gW
         bY5GbFuS08VEisli73H4gjFV/d+xgZUTi3+zXHU/P2AEegvsXlSVWBxnf3eUh5puQclN
         ykv9gDtWMnYK5GMyZykH+FY064VKHTaUQuszPrsMD/xd/JhkU1LAiRrzoDddR+ykNAEp
         693g==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCU32z4xxTZRVAakLn1qn+uqRAM7sOmli8VXqL7BwrhheFeeUyai46HgEX+1X87M9Zi8P/j9QQ==@lfdr.de
X-Gm-Message-State: AOJu0Yz/FFcJ/0vqEZXCfoifZ6ML+wS6jncd8S0+cwyf24vkbjDr+xHT
	/z/bJYJJDO5fGwSA6me7oQfJN4sayU84j+9QeJ98NSaHTQ3aoxB/
X-Google-Smtp-Source: AGHT+IGGB0biDeOrbvI6WuGp0LF3XkN+KP6sWzc4PpZMQsgB/qTEUFCAqS+yL5ushD9iM1/inAwcgQ==
X-Received: by 2002:a05:6000:120f:b0:386:41bd:53b4 with SMTP id ffacd0b85a97d-38bf57b36bemr8420697f8f.34.1737380176336;
        Mon, 20 Jan 2025 05:36:16 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:6d42:0:b0:386:386b:afbe with SMTP id ffacd0b85a97d-38beaef8a69ls1995455f8f.0.-pod-prod-01-eu;
 Mon, 20 Jan 2025 05:36:15 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUbh9YNPM5Hh0L4RLuZL9oQybD6NeWsaPbryVFi+uLV8IEKEpuBZwzaUwth+nP0DVaRQCGvwgh/miY=@googlegroups.com
X-Received: by 2002:a5d:53c1:0:b0:38a:50f7:240c with SMTP id ffacd0b85a97d-38bf57c92f7mr8457517f8f.47.1737380174616;
        Mon, 20 Jan 2025 05:36:14 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1737380174; cv=none;
        d=google.com; s=arc-20240605;
        b=UZH4PUgDXPiOAmGEVZ9CQmaLvYAQD8/6obe3FEEjh7q8XQRWU12Ma2rDGpW3qVh3U9
         ZYT1fXCxWl1Dw3eVnXxXnrGiiZc+SMig1SEhdhBzOP1E+eMUukaODKIzgNBsQuO7EkrV
         HRMJP2uAX5S4VZEBPaGykYoeH5QVX/BOtlYxfXBwE3iVIq3Car16bF1t3Paddb8yhOsV
         5IW2qdpkSgDkjfG1XxB8vHIxMkiLnRiCaTXNOjjc8tKoOdYY6/HCntXBfq2+TwfJj8XF
         /9SB+FZjBs6o65e4xPMBJIIZEjv5XCKWsovb5HeT2pKiIDVXxk6yVG+nq2Lm5+i0WJHy
         RxLQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from
         :dkim-signature:dkim-signature:date;
        bh=t0Y1ype3ppnk0OeLhlW6Fo6oGTzJOolSI9eUh0ZWOLg=;
        fh=dFKwGhGEYa4oO6IlyO4Y3VT4ZhmkRdAhr9u8S/RFqSs=;
        b=Y6wxCSSwIzjNuRbMlb4I8SnxdhkDWnRuisNiKNp74OXlLLSQFb+Nhp1kkx5H2BfUwS
         SI8Zdt+HzCCtHT9faPreAKj2LpAK6NHFgqrEkXbbVoOfHlb7ACdYkKQmyaVWycgLHgpf
         UFgTPG6QwnKd2VcFo6KqRrzcg+R4nmJXIgysigvv8iFvpWcdzD0F8EChsCvxLFyaQkNO
         H8G5ji6IZVotJ067blkKTTv6N36G6y3zX946H90KhjXNlbRvUsRRm6dcHuKd1oy8DWma
         7BhAQ0Fm68Gjxsfqbw4Fi5UVOHxENI4Ct2s/R2Ggyf2SEptfm/ncnOqDTcjkHrxP7ll1
         CsGA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=ucadM5bO;
       dkim=neutral (no key) header.i=@linutronix.de;
       spf=pass (google.com: domain of t-8ch@linutronix.de designates 193.142.43.55 as permitted sender) smtp.mailfrom=t-8ch@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
Received: from galois.linutronix.de (Galois.linutronix.de. [193.142.43.55])
        by gmr-mx.google.com with UTF8SMTPS id 5b1f17b1804b1-437c1661248si5766385e9.1.2025.01.20.05.36.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 20 Jan 2025 05:36:14 -0800 (PST)
Received-SPF: pass (google.com: domain of t-8ch@linutronix.de designates 193.142.43.55 as permitted sender) client-ip=193.142.43.55;
Date: Mon, 20 Jan 2025 14:36:13 +0100
From: Thomas =?utf-8?Q?Wei=C3=9Fschuh?= <thomas.weissschuh@linutronix.de>
To: Benjamin Berg <benjamin@sipsolutions.net>
Cc: linux-arch@vger.kernel.org, linux-um@lists.infradead.org, 
	x86@kernel.org, briannorris@chromium.org, linux-kernel@vger.kernel.org, 
	kasan-dev@googlegroups.com, Benjamin Berg <benjamin.berg@intel.com>
Subject: Re: [PATCH 2/3] um: avoid copying FP state from init_task
Message-ID: <20250120142855-9d570200-cef7-4cfb-9ee5-81c8005a99d8@linutronix.de>
References: <20241217202745.1402932-1-benjamin@sipsolutions.net>
 <20241217202745.1402932-3-benjamin@sipsolutions.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <20241217202745.1402932-3-benjamin@sipsolutions.net>
X-Original-Sender: thomas.weissschuh@linutronix.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linutronix.de header.s=2020 header.b=ucadM5bO;       dkim=neutral
 (no key) header.i=@linutronix.de;       spf=pass (google.com: domain of
 t-8ch@linutronix.de designates 193.142.43.55 as permitted sender)
 smtp.mailfrom=t-8ch@linutronix.de;       dmarc=pass (p=NONE sp=QUARANTINE
 dis=NONE) header.from=linutronix.de
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

On Tue, Dec 17, 2024 at 09:27:44PM +0100, Benjamin Berg wrote:
> From: Benjamin Berg <benjamin.berg@intel.com>
>=20
> The init_task instance of struct task_struct is statically allocated and
> does not contain the dynamic area for the userspace FP registers. As
> such, limit the copy to the valid area of init_task and fill the rest
> with zero.
>=20
> Note that the FP state is only needed for userspace, and as such it is
> entirely reasonable for init_task to not contain it.
>=20
> Reported-by: Brian Norris <briannorris@chromium.org>
> Closes: https://lore.kernel.org/Z1ySXmjZm-xOqk90@google.com
> Fixes: 3f17fed21491 ("um: switch to regset API and depend on XSTATE")

No stable backport? The broken commit is now in the 6.13 release.

> Signed-off-by: Benjamin Berg <benjamin.berg@intel.com>

Tested-by: Thomas Wei=C3=9Fschuh <thomas.weissschuh@linutronix.de>

> ---
>  arch/um/kernel/process.c | 10 +++++++++-
>  1 file changed, 9 insertions(+), 1 deletion(-)
>=20
> diff --git a/arch/um/kernel/process.c b/arch/um/kernel/process.c
> index 30bdc0a87dc8..3a67ba8aa62d 100644
> --- a/arch/um/kernel/process.c
> +++ b/arch/um/kernel/process.c
> @@ -191,7 +191,15 @@ void initial_thread_cb(void (*proc)(void *), void *a=
rg)
>  int arch_dup_task_struct(struct task_struct *dst,
>  			 struct task_struct *src)
>  {
> -	memcpy(dst, src, arch_task_struct_size);
> +	/* init_task is not dynamically sized (missing FPU state) */
> +	if (unlikely(src =3D=3D &init_task)) {
> +		memcpy(dst, src, sizeof(init_task));
> +		memset((void *)dst + sizeof(init_task), 0,
> +		       arch_task_struct_size - sizeof(init_task));
> +	} else {
> +		memcpy(dst, src, arch_task_struct_size);
> +	}

Nitpick:
This could make use of memcpy_and_pad() in various forms.

> +
>  	return 0;
>  }
> =20
> --=20
> 2.47.1
>=20

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/2=
0250120142855-9d570200-cef7-4cfb-9ee5-81c8005a99d8%40linutronix.de.
