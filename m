Return-Path: <kasan-dev+bncBDE6RCFOWIARBHUG5O4AMGQERNPSRYY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x340.google.com (mail-wm1-x340.google.com [IPv6:2a00:1450:4864:20::340])
	by mail.lfdr.de (Postfix) with ESMTPS id 3A7629AF4E3
	for <lists+kasan-dev@lfdr.de>; Thu, 24 Oct 2024 23:58:56 +0200 (CEST)
Received: by mail-wm1-x340.google.com with SMTP id 5b1f17b1804b1-43150f13cf2sf2237365e9.1
        for <lists+kasan-dev@lfdr.de>; Thu, 24 Oct 2024 14:58:56 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1729807135; cv=pass;
        d=google.com; s=arc-20240605;
        b=O2Xj4uQ1jnyGsadE66oh0G0dkHB/oCJH3HOs4sQw1hg4IeyG1RPCrn0+qPy0wlSOKe
         e8gLiUpMIQ+fZjx1vN5BQE1ECddmZkQObWqQmmn1zBw0+OK+w3h62kIj1s2JL3hF+Q1+
         v0T9/3v8Jgi4hYpw0HqQWbbNsxJfdpbJM9O/sOIa855j/612fvBInfNg1Q3fekco+JKw
         Kzdw81tY3wH3yGURaJOI3IFM5fxXRcXDbryT96uoTzDejx/ASiaqRJ08/v07UgnlUoL9
         2U2H1HYzf/DKecQHoMXcgGm+h2Ori6MuIZkLLL4sSM9lTWR4U9Od9OWxLD2Isk8snnoX
         ClYA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature;
        bh=W3Rc48kB3siKAQaOZL+oHOI7nwH3wlGDjU+mEhYxgBo=;
        fh=FAoSLozcRUGqJEDAta2hwp3ly6EdNKjXM6sqrERBrBE=;
        b=jp4vkKUzlUWizaNa70pi69VFZ3RR7zGD0yVdaHeTzlFMx+5BAvdp6aX6OUvmU3VPFf
         8HO0ZF5K7EDkSkhwAsZkB56cFZODJeC5+UkH0UbEZwgG9tJyAJN900Pw5CKnpsTLzXRf
         BvHDmN77ml+m9GW+cqM2UztL/YoToRctOVpkrpvdISEYbuVLJkLukHl5yG1xkVPrc3nh
         WvWnn3xYkEkfzWKJnBnxCGXFckTUKhWPm2w+zaGZc9/64d2IgScHL+4YdfTID3yN1OKl
         m/IqPXpt0R77yDBcmP4GZjPw/RhAx17LMUGnI3IxtEhOrjTV+ZbQSaWnjlCnaUdEvtCI
         E1QA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=wH8exBzc;
       spf=pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::22a as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1729807135; x=1730411935; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=W3Rc48kB3siKAQaOZL+oHOI7nwH3wlGDjU+mEhYxgBo=;
        b=av5cMGKY/1qQ1GHuC4rpUWfbonjs2FPW3k5u3/1wor+u/iV/hOtykz7phxRTVncgl1
         wZrHUpCwHwOAwVKDY7S1sRi2sHJhVxSbqNY23uj4bkhU4Q9vgSyiboq7feTDfNRhf2sY
         hqVPEDTwXK2ZSXXJujZ1P/5efiO2y/tG8uIlpiB0YSCdSdKzQlzXIOar/wzaS3wfhdir
         tY9g9DlBJOkfqJ2DEfnD2QLNtRMiEX2JMFiT0+zQWAtN0izmVldXvlyBpL75Z7JIX0t9
         XrkinZOAGq1vFY8Hp/jovU1Z2oB4A3o04fzYr0MavT235zFIM7/5++WiYv9yPhy1CuXl
         0Srg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1729807135; x=1730411935;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=W3Rc48kB3siKAQaOZL+oHOI7nwH3wlGDjU+mEhYxgBo=;
        b=byvdfUKzFYs/EBI4ytFamfPIZPye83WOpFKbM6k9VcBTlfz6J1S0Yoo3A0hbpZknoT
         jumDxGi2l13ocNew2jW2zmZaFmv0iSdgi3FScVEIU0SXois3K6YBIJC6/lWFAtWO7BN4
         QeXy7oblKQCDkPN8enVebcUL+uX+/CaoaZwSu+zXtAmqgtZMFFC0Qazo976p6Abim9+w
         dN8OH3kOn9OnpLqEeWdSRhQj756mCZtD7/tjqrpVFrCoofVZ10nr2X2eB2MOIZVbTaaG
         d1DkQ5WxbVT8Mu/aYkGabgf45sAjx7VjAs1jmA2mGiXGYHEKQtlBoE/OzKfra9wbGmSS
         Tj0A==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUNASVKS39F1z02X0VlEgBZomXQUmeVgPD94M6TIp3OdkhnVvR4E4xR5llWcHB3Kb2vzrQeRA==@lfdr.de
X-Gm-Message-State: AOJu0YyD4C3W6TN89eMVn14Gt/42UysjdLKmwBlolCXHzM5U1pX1+F52
	OMKQoj1r/PxEh9K2LxQQ9ULj5Irw3wiVL4jE4Uwm4l8Yrc5rNDJ/
X-Google-Smtp-Source: AGHT+IEGj7qFLt2HzDRrOqIB87KvOVddx9+hFwHotkQ32dHGB7usvN8cZNblyrm6dCexkPIRd7RnDA==
X-Received: by 2002:a05:6000:400c:b0:37d:4705:ff71 with SMTP id ffacd0b85a97d-37efcf84d12mr2642076f8f.10.1729807134982;
        Thu, 24 Oct 2024 14:58:54 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:1c14:b0:431:55bf:fdf with SMTP id
 5b1f17b1804b1-4318a1f30afls7486825e9.0.-pod-prod-04-eu; Thu, 24 Oct 2024
 14:58:53 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUL3WNZN5ojYEls7aS0wJPBmrq/B+UTsD7IpzLm56Rc6N6ya05P7eeqNL99F7UmkkU7yIkxqH8ThpI=@googlegroups.com
X-Received: by 2002:a05:600c:4751:b0:431:58c4:2eb9 with SMTP id 5b1f17b1804b1-431841e175bmr70198465e9.3.1729807133142;
        Thu, 24 Oct 2024 14:58:53 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1729807133; cv=none;
        d=google.com; s=arc-20240605;
        b=j6r0JLAy/1XYPOE/i+Zl9/CHLBt8BRbMrq+PBAc5Gibd+laCDwfmL+ITwwgo7Ilymm
         vJkYBZU1WfJ8La76LrKLcCMzulLDM6Skvin4NSO5+542HOOpNn7IqtpN/RidG6yLcGpZ
         4aHM0a+U7RBCEjdIyQuIEBGqpHsNzsDHxtCgFT685racXORLveu5fby0mbKGtgldBxff
         r598wufJR0K7O1uiGoFaEeVT5osFl4SxSV0XUtWed4WN9Fjzg2/hQ6+3x/S5W8lsyK+a
         TBtWg+VWaYl9IaS4M4mMgy+IG+igpxAfV7NnUMzhFNz8iTMj0D1E9y62DUt/l0PKrtVs
         7Aiw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=XFVxrWwlGXu7xwVCAmBNg01QSRfDgCIGYPTLM5Loo7A=;
        fh=ptWgCc8pt4KKKMQ8hrWMn9RR+uIIvE36uLIKdw3iqKo=;
        b=CJUdfvmYhWa6C2j01je3TbUP9rx8qC9PenAn2nvF+3m86P6GOF4CPRv7eC3qy/EiYe
         8NtIMzYh19RJbT9R2UI9qSquTzL7bkIJ1MrtLZK5OM+DgxD3wFD14JePmRTrIn9rkydi
         A9ZOigT9TvNLpm+3ApUDY6yY+6W82/elsrZh4GOEvjq4yC16sxZfRbrI0Vhj89GuMBLO
         Ux/IPymNyXaBmAj1Vj27W8UNFz71Lz5Tv304iYzj4Hz8rOtB0OGQX/XonNay7xGnfjIG
         ByqEt7WETI0Ucxw0SvAfqUGJ6si5pchLRxOn4BtVk2Nx5YpZ1UhU9V68MoUhgg2+d60Q
         URFg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=wH8exBzc;
       spf=pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::22a as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org;
       dara=pass header.i=@googlegroups.com
Received: from mail-lj1-x22a.google.com (mail-lj1-x22a.google.com. [2a00:1450:4864:20::22a])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-43186bd6bc5si997385e9.1.2024.10.24.14.58.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 24 Oct 2024 14:58:53 -0700 (PDT)
Received-SPF: pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::22a as permitted sender) client-ip=2a00:1450:4864:20::22a;
Received: by mail-lj1-x22a.google.com with SMTP id 38308e7fff4ca-2fb599aac99so14935451fa.1
        for <kasan-dev@googlegroups.com>; Thu, 24 Oct 2024 14:58:53 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUBYLEP6o1LDF987EcfBycpUWSmTUDzHg1S+UG71UBKLIGC44RRdaKBDzhTy3LJdya16BXalx6fMkc=@googlegroups.com
X-Received: by 2002:a2e:9010:0:b0:2fb:3e01:b2bd with SMTP id
 38308e7fff4ca-2fc9d35a589mr34560231fa.21.1729807132380; Thu, 24 Oct 2024
 14:58:52 -0700 (PDT)
MIME-Version: 1.0
References: <20241017-arm-kasan-vmalloc-crash-v3-0-d2a34cd5b663@linaro.org>
 <20241017-arm-kasan-vmalloc-crash-v3-1-d2a34cd5b663@linaro.org>
 <69f71ac8-4ba6-46ed-b2ab-e575dcada47b@foss.st.com> <CACRpkdYvgZj1R4gAmzFhf4GmFOxZXhpHVTOio+hVP52OBAJP0A@mail.gmail.com>
 <46336aba-e7dd-49dd-aa1c-c5f765006e3c@foss.st.com>
In-Reply-To: <46336aba-e7dd-49dd-aa1c-c5f765006e3c@foss.st.com>
From: Linus Walleij <linus.walleij@linaro.org>
Date: Thu, 24 Oct 2024 23:58:40 +0200
Message-ID: <CACRpkdY2=qdY_0GA1gB03yHODPEvxum+4YBjzsXRVnhLaf++6Q@mail.gmail.com>
Subject: Re: [PATCH v3 1/2] ARM: ioremap: Sync PGDs for VMALLOC shadow
To: Clement LE GOFFIC <clement.legoffic@foss.st.com>, Ard Biesheuvel <ardb@kernel.org>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Russell King <linux@armlinux.org.uk>, Kees Cook <kees@kernel.org>, 
	AngeloGioacchino Del Regno <angelogioacchino.delregno@collabora.com>, Mark Brown <broonie@kernel.org>, 
	Mark Rutland <mark.rutland@arm.com>, Antonio Borneo <antonio.borneo@foss.st.com>, 
	linux-stm32@st-md-mailman.stormreply.com, 
	linux-arm-kernel@lists.infradead.org, stable@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: linus.walleij@linaro.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linaro.org header.s=google header.b=wH8exBzc;       spf=pass
 (google.com: domain of linus.walleij@linaro.org designates
 2a00:1450:4864:20::22a as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org;
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

Hi Clement,

I saw I missed to look closer at the new bug found in ext4
on the STM32:

On Mon, Oct 21, 2024 at 2:12=E2=80=AFPM Clement LE GOFFIC
<clement.legoffic@foss.st.com> wrote:

> Perhaps not related with this topic but as in the backtrace I am getting
> some keyword from our start exchange, I dump the crash below.
> If this backtrace is somehow related with our issue, please have a look.
(...)
> [ 1439.351945] PC is at __read_once_word_nocheck+0x0/0x8
> [ 1439.356965] LR is at unwind_exec_insn+0x364/0x658
(...)
> [ 1440.333183]  __read_once_word_nocheck from unwind_exec_insn+0x364/0x65=
8
> [ 1440.339726]  unwind_exec_insn from unwind_frame+0x270/0x618
> [ 1440.345352]  unwind_frame from arch_stack_walk+0x6c/0xe0
> [ 1440.350674]  arch_stack_walk from stack_trace_save+0x90/0xc0
> [ 1440.356308]  stack_trace_save from kasan_save_stack+0x30/0x4c
> [ 1440.362042]  kasan_save_stack from __kasan_record_aux_stack+0x84/0x8c
> [ 1440.368473]  __kasan_record_aux_stack from task_work_add+0x90/0x210
> [ 1440.374706]  task_work_add from scheduler_tick+0x18c/0x250
> [ 1440.380245]  scheduler_tick from update_process_times+0x124/0x148
> [ 1440.386287]  update_process_times from tick_sched_handle+0x64/0x88
> [ 1440.392521]  tick_sched_handle from tick_sched_timer+0x60/0xcc
> [ 1440.398341]  tick_sched_timer from __hrtimer_run_queues+0x2c4/0x59c
> [ 1440.404572]  __hrtimer_run_queues from hrtimer_interrupt+0x1bc/0x3a0
> [ 1440.411009]  hrtimer_interrupt from arch_timer_handler_virt+0x34/0x3c
> [ 1440.417447]  arch_timer_handler_virt from
> handle_percpu_devid_irq+0xf4/0x368
> [ 1440.424480]  handle_percpu_devid_irq from
> generic_handle_domain_irq+0x38/0x48
> [ 1440.431618]  generic_handle_domain_irq from gic_handle_irq+0x90/0xa8
> [ 1440.437953]  gic_handle_irq from generic_handle_arch_irq+0x30/0x40
> [ 1440.444094]  generic_handle_arch_irq from __irq_svc+0x88/0xc8
> [ 1440.449920] Exception stack(0xde803a30 to 0xde803a78)
> [ 1440.454914] 3a20:                                     de803b00
> 00000000 00000001 000000c0
> [ 1440.463141] 3a40: e5333f40 de803ba0 de803bd0 00000001 e5333f40
> de803b00 c1241d90 bad0075c
> [ 1440.471262] 3a60: c20584b8 de803a7c c0114114 c0113850 200f0013 fffffff=
f
> [ 1440.477959]  __irq_svc from unwind_exec_insn+0x4/0x658
> [ 1440.483078]  unwind_exec_insn from call_with_stack+0x18/0x20

This is hard to analyze without being able to reproduce it, but it talks
about the stack and Kasan and unwinding, so could it (also) be related to t=
he
VMAP:ed stack?

Did you try to revert (or check out the commit before and after)
b6506981f880 ARM: unwind: support unwinding across multiple stacks
to see if this is again fixing the issue?

Yours,
Linus Walleij

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
ACRpkdY2%3DqdY_0GA1gB03yHODPEvxum%2B4YBjzsXRVnhLaf%2B%2B6Q%40mail.gmail.com=
.
