Return-Path: <kasan-dev+bncBDAOBFVI5MIBB6UR56GAMGQE237LB6Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13e.google.com (mail-lf1-x13e.google.com [IPv6:2a00:1450:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id 66C35459349
	for <lists+kasan-dev@lfdr.de>; Mon, 22 Nov 2021 17:44:43 +0100 (CET)
Received: by mail-lf1-x13e.google.com with SMTP id j9-20020a05651231c900b004037efe9fddsf12765530lfe.18
        for <lists+kasan-dev@lfdr.de>; Mon, 22 Nov 2021 08:44:43 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1637599482; cv=pass;
        d=google.com; s=arc-20160816;
        b=fs+ylgPSuP7ihAS9duAmo0IUv2L/CMl4e2vapYY0ZofFD9GCNTqLab0z1BpVhTedON
         SsQsET0VXUbEbTJFoqQS9Guc/mg/uONrP3ryHmGsSUbbga2bDpB4bH9OH4tefPWfy2b2
         h35hjHnUA8S8cVg9uoi/mrRAxVYebodDMN2mzQyk/rww1eihxDYiqteheEPpQFdNQqnT
         Ychrg8k67XUjhbVStda5R7UMBBxni1Uz8xk4akFr3qGR2JajIBDK92Dj2zEIEA9ylvkO
         17yMsN7426YdaGSO9tWpYqJnz+DNk1R22l7a00i01N4+gjBiDa1tCLXqIGz6+m8wAyst
         nsOQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :mime-version:message-id:date:references:in-reply-to:subject:cc:to
         :from:sender:dkim-signature;
        bh=9sa0ysl5sIxpd//FFFzP35J3nrI32Nbc86tfH4GWoX0=;
        b=Bgcm5kneh6+UWZ2Ixm4vJWHNMd9XUW6FYzAZTFrR/ULr6jlpfN8ZuYTkI6zdJkYbwC
         duf6QKwBHYXLZjgdFi65QcVGUPQYKwsj7JRM/LapSCiqMZyrxff0RKIz5IQrD6B8PkGB
         Mjm2cryHmW6ZSjcXcKUorB5GW4GUK1jKphpGQiDtQCy3bKl9I3lwG1l38wh6cM+o1/Sw
         6yBes0FmV9VViyO60gWql7NVevIQMXQ8q053+FxKZBkOGfNpj70lV26BnN6Ti8gWxN6p
         0AmEcDzUBhDtPezZQUQEdHTarmjeyMglaTgBrEKpbFUevU1GGNCUJPMJ+VFLZcbT1sQ+
         uaEw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of valentin.schneider@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=valentin.schneider@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:in-reply-to:references:date:message-id
         :mime-version:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=9sa0ysl5sIxpd//FFFzP35J3nrI32Nbc86tfH4GWoX0=;
        b=D2lqmHkQyxwigfcdW5ZlZkqW9L13DwHbOqvx6h9C5W6L2v5CIvX45PlXR4KmLtPyeu
         /nAHCXOud2T9e4X0qWbEbGKmvw9HdRnv9jzNRd90D/NDcaCYjIldvfuHovLCEq/c90WF
         0XolHxggqhRphpCPewFJhgqFvOnzYm6bA49Ju8imrz10253EjcSw/FGwtG5IedvLrj1r
         pKNzxF0qblAx71ndvBqSPj1M74XdE3HNyW3vKnvdCDPNb7QHbLNHXKEHhAj4YDPkfAnZ
         tXB2G7cgjUiMmyTS0VsvWQvawRHkekda8nUGlH0r8baWm2puU0ptFDVvS4uZur98RK8Y
         845w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:in-reply-to:references
         :date:message-id:mime-version:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=9sa0ysl5sIxpd//FFFzP35J3nrI32Nbc86tfH4GWoX0=;
        b=VVV5q1PFEyMygo4P5RxAzhe5I1b/Xq4K5+YRiRAgcKqcbN3aB/VNfgCZuCosg+Opn/
         eBv/j1QfxQRzL3rXsO9S2mAwyHRdCIo1LkE/3p73mhsD3nO9nkaczsHWso6plk+C3LX9
         OdgoWiKKVX9AZPiWQ/ItXlchSEvV07RT5ZdhB4/vXtqPTsN0wLPvd3zy5DyJnFjiUxNp
         GFtR84EwgZxnoZ9jxuKCWvddjjmo0hl/z5rLp3ma70p6V7uc7FVzaKtdPCydWPZakuTX
         32rNG5IPQ5B1RtP+i65BPPiwkjYWv9YVEjUPUdf3OJYk+UFaGQ0f127CrARdZupHFwTt
         LNvw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533SDHpr2Q3HzC1y01rr0fwXxFm/Z+hqLl7umM1WHQAZ7VPNWX71
	zUob+TMv0VQBgdvyVxFmiZ4=
X-Google-Smtp-Source: ABdhPJxozLYbe0reu0dkdVvACpP6nRkPC1/KfnjsASUo9fMo4pKnOsaxsMDx2fO6iNAR8IokGu3Tiw==
X-Received: by 2002:a19:c7d2:: with SMTP id x201mr57243503lff.684.1637599482810;
        Mon, 22 Nov 2021 08:44:42 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:898c:: with SMTP id c12ls1132426lji.11.gmail; Mon, 22
 Nov 2021 08:44:41 -0800 (PST)
X-Received: by 2002:a2e:b907:: with SMTP id b7mr53999208ljb.214.1637599481745;
        Mon, 22 Nov 2021 08:44:41 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1637599481; cv=none;
        d=google.com; s=arc-20160816;
        b=uHo9ZX4fy5z8zDx1PKULnG34fz1sgTwmgxMF8BMUNLJcQUvDdoLPeAaVM8blY5fMHs
         t+m9HYve59Ht3XdHleQsbiuqzX8bJpGi6LY8iklv6G6YG1layvbmxa2M318xq1YR6rte
         C3Lc8BbXSfQktCvq2VU7YsriX1fXIhtxrbgyXzP0Ik7FLJCApEw0HUVd0e1zMNIxYW6K
         h2VsL6JSHkYSGrMZjmUmbKHP5hu7EOlKFkSv6nj8r9dm82Z4yAEs6qEF2VmST/4GNOx3
         RrJDdJ4CTnFFj/mBp8jghko1ovcphVe4WBPsU9RPPtXivuaziyRCcNW0vgxiO77XD4Qp
         fuaw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:references
         :in-reply-to:subject:cc:to:from;
        bh=MQRt7a2nmJo22Sj0ZZ1FQqTqPMdjS7lwOUP+VsAmC3M=;
        b=LM+3Tgx17Mv2ev1OyTTgWl6GJoTjLnwulN8ESjJ+hfMx1JEsS02oeNl5s4faaY7yn4
         pxmaUEoxrFEJ4OYBObNSeo0HB7TYHUcYcPiZGTMTQfqW5Zz1v2BOHC5Xv//VUzMvmNlK
         +jFcrPuTj3Mj/5mefPMG1xzebYpncJAJwY0igFy/i3c4Ezicl/P5qXEZyZ+SfTPbwJvO
         HNgxQgCR0ugbo1oCQeeM/ke4qfxCN7UxkHiQN0Shbp2vLZ6P2t0go6mEYd7zMcXheI4W
         abEs75EgHscBMxGOiafsviCPoE0raZ2r7Hnd0A2cMXU7VELDDytwYu58eZRhY5VQVkUj
         +rXw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of valentin.schneider@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=valentin.schneider@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id v25si645292lfr.1.2021.11.22.08.44.41
        for <kasan-dev@googlegroups.com>;
        Mon, 22 Nov 2021 08:44:41 -0800 (PST)
Received-SPF: pass (google.com: domain of valentin.schneider@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 8491EED1;
	Mon, 22 Nov 2021 08:44:40 -0800 (PST)
Received: from e113632-lin (usa-sjc-imap-foss1.foss.arm.com [10.121.207.14])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 85E503F66F;
	Mon, 22 Nov 2021 08:44:38 -0800 (PST)
From: Valentin Schneider <valentin.schneider@arm.com>
To: Christophe Leroy <christophe.leroy@csgroup.eu>, linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, linuxppc-dev@lists.ozlabs.org, linux-kbuild@vger.kernel.org
Cc: Marco Elver <elver@google.com>, Michal Marek <michal.lkml@markovi.net>, Peter Zijlstra <peterz@infradead.org>, Frederic Weisbecker <frederic@kernel.org>, Mike Galbraith <efault@gmx.de>, Nick Desaulniers <ndesaulniers@google.com>, Steven Rostedt <rostedt@goodmis.org>, Paul Mackerras <paulus@samba.org>, Masahiro Yamada <masahiroy@kernel.org>, Ingo Molnar <mingo@kernel.org>, Dmitry Vyukov <dvyukov@google.com>
Subject: Re: [PATCH v2 3/5] powerpc: Use preemption model accessors
In-Reply-To: <431fb6da-fe21-c5a6-bfb3-4e26bdc153b4@csgroup.eu>
References: <20211110202448.4054153-1-valentin.schneider@arm.com> <20211110202448.4054153-4-valentin.schneider@arm.com> <431fb6da-fe21-c5a6-bfb3-4e26bdc153b4@csgroup.eu>
Date: Mon, 22 Nov 2021 16:44:36 +0000
Message-ID: <87v90kcf7v.mognet@arm.com>
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

On 16/11/21 14:41, Christophe Leroy wrote:
> Le 10/11/2021 =C3=A0 21:24, Valentin Schneider a =C3=A9crit=C2=A0:
>> Per PREEMPT_DYNAMIC, checking CONFIG_PREEMPT doesn't tell you the actual
>> preemption model of the live kernel. Use the newly-introduced accessors
>> instead.
>
> Is that change worth it for now ? As far as I can see powerpc doesn't
> have DYNAMIC PREEMPT, a lot of work needs to be done before being able
> to use it:
> - Implement GENERIC_ENTRY
> - Implement STATIC_CALLS (already done on PPC32, to be done on PPC64)
>

You're right, I ditched this patch for v3 - AFAICT the change wasn't even
valid as the preempt_schedule_irq() call needs to be replaced with
irqentry_exit_cond_resched() (IOW this needs to make use of the generic
entry code).

>>
>> sched_init() -> preempt_dynamic_init() happens way before IRQs are set u=
p,
>> so this should be fine.
>
> It looks like you are mixing up interrupts and IRQs (also known as
> "external interrupts").
>
> ISI (Instruction Storage Interrupt) and DSI (Data Storage Interrupt) for
> instance are also interrupts. They happen everytime there is a page
> fault so may happen pretty early.
>
> Traps generated by WARN_ON() are also interrupts that may happen at any
> time.
>

Michael pointed this out and indeed triggering a WARN_ON() there is not
super smart. Thanks for teaching me a bit of what I'm putting my grubby
hands in :)

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/87v90kcf7v.mognet%40arm.com.
