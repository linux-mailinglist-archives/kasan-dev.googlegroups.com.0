Return-Path: <kasan-dev+bncBDE6RCFOWIARB2HW5W4AMGQE27L3AFA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x63c.google.com (mail-ej1-x63c.google.com [IPv6:2a00:1450:4864:20::63c])
	by mail.lfdr.de (Postfix) with ESMTPS id A86C49B00D8
	for <lists+kasan-dev@lfdr.de>; Fri, 25 Oct 2024 13:05:13 +0200 (CEST)
Received: by mail-ej1-x63c.google.com with SMTP id a640c23a62f3a-a9a2ae49a32sf141205066b.3
        for <lists+kasan-dev@lfdr.de>; Fri, 25 Oct 2024 04:05:13 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1729854313; cv=pass;
        d=google.com; s=arc-20240605;
        b=WwpeFy4qVWwWjUr6IUdswlF1ASBU9unU1sn8mP54GcXkAn3g69uHNf6+oU6aisbRsX
         JJyoX8rJLvs0pvfDQ6kP3LPOc67XvkbnDX0UNzUwmc97Zt5/135z8CZLvK8hDhvxBQKv
         rxp/r6JwzAlBNW0LyA5K29zbPtquQJmAzNC3SaDs6T2pwBwD4ncT15ZG0gkO/4fAHK0i
         S/1ijOcvh+NqXzHbft8yXDGljxrGg3W+PwUvG446iq9HfOX6RF6ynGDEUtgqymJWhq0h
         oeI2AxI8v4ybda2pUo2bL0eNZ0txj7qYwziZf/ByS8Jl6BX12SOlYn7oeCR6MvO/Ob7O
         f7jA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature;
        bh=/D6N2ynoSr8H6D+P77hVy0+/o2fZInrWhBXWyEpNRbM=;
        fh=N5k2vH/bFxIcR3RALIYNeT6rwfC4SfyTWxbhepXCTmo=;
        b=P8m7NjfFcbAqiL5OMRC1oQNSHU5sA0jnRGAwnM33mQxhIJUX8fLH3fPFtiNnJu45+9
         K7r4tQLkC76gFSZUpsCUn1Yz5ObkjJg4YhZdazBw5B0ZXdlX3Z6xt0NZLW/HnMjzdxob
         hC9Z6smcZJvRTjdCDRq1JtHprmuHq4k4FkGst8imT7qwpTA97Eem3kdlb0+vet48Z+du
         OPHTezXsxYKQlFzQJe3FsLwv8wKWroN6sl5Zct/RF12TxyiTrAp80IwqX6xj7bmXN4G9
         PEa1cJHNCG0SOGbqKGX1P5NOv8cG4k6rHcyAkjTboSZTbnAW10O6xJX2o7GiheKHmd3u
         MhJQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b="NF/Giqxy";
       spf=pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::12b as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1729854313; x=1730459113; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=/D6N2ynoSr8H6D+P77hVy0+/o2fZInrWhBXWyEpNRbM=;
        b=Iu9BeqcWrUTOMRmWu/4nb9tZp5CKs+8YxTiKfEq8jfs/qKagsnjjlI+S0m7Fcbx2qH
         ORwozF5eu3EF3qu4Y55ZyoqvH8Sk6rmfDwLuHsamm0v/04G0DOOYrE0pR6G/lRPzl/QJ
         hq8KhLXDOPBZ0NR7+L4D8c4hMYuDRUSFykiO7lyzt+uTIThee05i4P/61mGgdJDez1q+
         UTIA/xvs5WWwRGDDtSDjDcVrYpCKBS/NZkTp6uJpakd0BwuXErPhJLaQwjVqjtmjwQfx
         WUbnymfnjkg7bOnb3jZiiWHr8vZdvPVuoKboTuDyXUCoNd2mBDMJSXCyfu1tPnv7oRC2
         GBAw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1729854313; x=1730459113;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=/D6N2ynoSr8H6D+P77hVy0+/o2fZInrWhBXWyEpNRbM=;
        b=E4LPELLLG27aB8LTAEd0ItKPH0lvyVUHjIowBFN5YGiiQuyp0I2k3tBKJecV5PlhI3
         Q3OKsuUB97Y6BoU+B3Jz9xX9y/6IkSknkAGtccGZupJGQ2bMY1kEtO12j6OWqo3a/RRA
         1o16we16dPDFaYbVuZgD2cXQTD8Yy2h34m4zK9SwwO9myxCwhLwfWqjqmfKKHjMTWk2X
         Ivf87KWJzRh/9kEB7LIZ9vQWZkD6abHQ8euhN9Wu6BfPkpTjH4MkRpQ1eGhp5yPeng2n
         k7xDaKyvOFQ1f8E9URj9bldQbgeWaFXjbggitOcwizZgacLWCW3T19s3O7HEyjPgWaGT
         dWDA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCU2sTYdc7WwmoPZtK3Z7UAuxovf4gmkdOdG1oJoH+ekB49cJ1eJzZfmL6XD4gLRSHnBglgCnw==@lfdr.de
X-Gm-Message-State: AOJu0YzVqrJTihBBzVTBcDjMaJ/vhqvxZTbpvH4N0aP3TE42b+i14QzN
	GzxL3XFUze/dVpN5ihl7mxyotj51Kw6oH9iGph7BPMaYBRXAMQyW
X-Google-Smtp-Source: AGHT+IGeIv09cOnESw7khVTAJ1vkDaqm69VRqYOymn9I9HK5NNNqwruDNELZuMWQyM2Mspi/BDLWWA==
X-Received: by 2002:a05:6402:3605:b0:5cb:7318:aa2b with SMTP id 4fb4d7f45d1cf-5cb8af721eemr7169064a12.26.1729854312585;
        Fri, 25 Oct 2024 04:05:12 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:524d:b0:5cb:73a6:e040 with SMTP id
 4fb4d7f45d1cf-5cb9987a679ls23721a12.0.-pod-prod-03-eu; Fri, 25 Oct 2024
 04:05:10 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVS7moVV8cvfKD6PVBS90vMbHA9v9W0xBaHsugqAC90Rg4NSiAlbj0J1WraCWWWbqLl0O+NpvhOQG8=@googlegroups.com
X-Received: by 2002:a05:6402:84a:b0:5cb:674f:b0a2 with SMTP id 4fb4d7f45d1cf-5cb8b1b1f0amr6493687a12.36.1729854310586;
        Fri, 25 Oct 2024 04:05:10 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1729854310; cv=none;
        d=google.com; s=arc-20240605;
        b=i6Bs/ZD1Be6AL3TM+WDOnAT8Kpk+954l/O60UzfD+OQt2YXYB6Oe1kjtQF+ZjRT2+y
         GqbhW0mvn/1hYYgo7atbOjrS1ygWbNfa0YHHZXpSmZ7g5E2QnYR6oTMduDhUjIg4VGKa
         EWzo+v4eGmDksy2lkSHMjoYii/ixURw8ZcQNvJg53nkVZDfnUALty0VrjRVNcQ3Yfhmp
         Q6/Mxs3uZt5OjGS1aC3kilvxoNhKwDLmE9adXMnfpgnM19Mn18BOnV11IKhBsa+HvEA0
         iBe16PNTycnKqqcY/y2WL+rHxck6dMnLs34M7NrWtPGdvERjO/CUvzeaFfCu+aIirqFg
         /H2w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=JuomQA4el8BSAut2vwLq507qc8/7nzyKhdkv644V4tk=;
        fh=ZSVyv/Gypatdm4nCc6oaidI6P/mJmaxL1FMGQKfE8T4=;
        b=OXRnLpI1GMh4RmQ+uSKIKmoab9doXJa3i/Ys45EDyfjYVsAI39UrkllBZIiAFou/pv
         OYiOeOWv8GGAyJOlBSZZ1vYddkRmg1/4DRYYP6YqCYJbqq1KVWAvSnL0Lb3g2UWjk5d/
         O1QPD0BLLyvk1IZpxnCNLacddieAW5BYU87ZcPdHLCBxMMVoJgj96PsynIkRff+1BuVE
         g0nYOVgjr57Fzr/KMnHd+bwcIs9Or3pCnIoipt55T7ho4sN8bSDU5nX9D2UhhMuINSRu
         PfKa52geMQPxQ2YF8yW4hPh97YYztD6FcY2mcdGTzPXd6dfcCk+H6C9LU8QjTBbIbQ4D
         65NQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b="NF/Giqxy";
       spf=pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::12b as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org;
       dara=pass header.i=@googlegroups.com
Received: from mail-lf1-x12b.google.com (mail-lf1-x12b.google.com. [2a00:1450:4864:20::12b])
        by gmr-mx.google.com with ESMTPS id 4fb4d7f45d1cf-5cbb6257efesi15964a12.2.2024.10.25.04.05.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 25 Oct 2024 04:05:10 -0700 (PDT)
Received-SPF: pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::12b as permitted sender) client-ip=2a00:1450:4864:20::12b;
Received: by mail-lf1-x12b.google.com with SMTP id 2adb3069b0e04-539fbbadf83so2601171e87.0
        for <kasan-dev@googlegroups.com>; Fri, 25 Oct 2024 04:05:10 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWwCeM73TOZgssGVFPEOrWwSMcNkkzMmyAV1xBet73j+PktVMQWnZy/e85njV0/KWbR9503U20+B+A=@googlegroups.com
X-Received: by 2002:a05:6512:3996:b0:539:f593:c19e with SMTP id
 2adb3069b0e04-53b1a3b018amr5062359e87.60.1729854309787; Fri, 25 Oct 2024
 04:05:09 -0700 (PDT)
MIME-Version: 1.0
References: <20241017-arm-kasan-vmalloc-crash-v3-0-d2a34cd5b663@linaro.org>
 <20241017-arm-kasan-vmalloc-crash-v3-1-d2a34cd5b663@linaro.org>
 <69f71ac8-4ba6-46ed-b2ab-e575dcada47b@foss.st.com> <CACRpkdYvgZj1R4gAmzFhf4GmFOxZXhpHVTOio+hVP52OBAJP0A@mail.gmail.com>
 <46336aba-e7dd-49dd-aa1c-c5f765006e3c@foss.st.com> <CACRpkdY2=qdY_0GA1gB03yHODPEvxum+4YBjzsXRVnhLaf++6Q@mail.gmail.com>
 <f3856158-10e6-4ee8-b4d5-b7f2fe6d1097@foss.st.com>
In-Reply-To: <f3856158-10e6-4ee8-b4d5-b7f2fe6d1097@foss.st.com>
From: Linus Walleij <linus.walleij@linaro.org>
Date: Fri, 25 Oct 2024 13:04:57 +0200
Message-ID: <CACRpkdZa5x6NvUg0kU6F0+HaFhKhVswvK2WaaCSBx3-JCVFcag@mail.gmail.com>
Subject: Re: [PATCH v3 1/2] ARM: ioremap: Sync PGDs for VMALLOC shadow
To: Clement LE GOFFIC <clement.legoffic@foss.st.com>
Cc: Ard Biesheuvel <ardb@kernel.org>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, Russell King <linux@armlinux.org.uk>, 
	Kees Cook <kees@kernel.org>, 
	AngeloGioacchino Del Regno <angelogioacchino.delregno@collabora.com>, Mark Brown <broonie@kernel.org>, 
	Mark Rutland <mark.rutland@arm.com>, Antonio Borneo <antonio.borneo@foss.st.com>, 
	linux-stm32@st-md-mailman.stormreply.com, 
	linux-arm-kernel@lists.infradead.org, stable@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: linus.walleij@linaro.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linaro.org header.s=google header.b="NF/Giqxy";       spf=pass
 (google.com: domain of linus.walleij@linaro.org designates
 2a00:1450:4864:20::12b as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
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

On Fri, Oct 25, 2024 at 11:27=E2=80=AFAM Clement LE GOFFIC
<clement.legoffic@foss.st.com> wrote:
> On 10/24/24 23:58, Linus Walleij wrote:
> > Hi Clement,
> >
> > I saw I missed to look closer at the new bug found in ext4
> > on the STM32:
> >
> > On Mon, Oct 21, 2024 at 2:12=E2=80=AFPM Clement LE GOFFIC
> > <clement.legoffic@foss.st.com> wrote:
> >
> >> Perhaps not related with this topic but as in the backtrace I am getti=
ng
> >> some keyword from our start exchange, I dump the crash below.
> >> If this backtrace is somehow related with our issue, please have a loo=
k.
> > (...)
> >> [ 1439.351945] PC is at __read_once_word_nocheck+0x0/0x8
> >> [ 1439.356965] LR is at unwind_exec_insn+0x364/0x658
> > (...)
> >> [ 1440.333183]  __read_once_word_nocheck from unwind_exec_insn+0x364/0=
x658
> >> [ 1440.339726]  unwind_exec_insn from unwind_frame+0x270/0x618
> >> [ 1440.345352]  unwind_frame from arch_stack_walk+0x6c/0xe0
> >> [ 1440.350674]  arch_stack_walk from stack_trace_save+0x90/0xc0
> >> [ 1440.356308]  stack_trace_save from kasan_save_stack+0x30/0x4c
> >> [ 1440.362042]  kasan_save_stack from __kasan_record_aux_stack+0x84/0x=
8c
> >> [ 1440.368473]  __kasan_record_aux_stack from task_work_add+0x90/0x210
> >> [ 1440.374706]  task_work_add from scheduler_tick+0x18c/0x250
> >> [ 1440.380245]  scheduler_tick from update_process_times+0x124/0x148
> >> [ 1440.386287]  update_process_times from tick_sched_handle+0x64/0x88
> >> [ 1440.392521]  tick_sched_handle from tick_sched_timer+0x60/0xcc
> >> [ 1440.398341]  tick_sched_timer from __hrtimer_run_queues+0x2c4/0x59c
> >> [ 1440.404572]  __hrtimer_run_queues from hrtimer_interrupt+0x1bc/0x3a=
0
> >> [ 1440.411009]  hrtimer_interrupt from arch_timer_handler_virt+0x34/0x=
3c
> >> [ 1440.417447]  arch_timer_handler_virt from
> >> handle_percpu_devid_irq+0xf4/0x368
> >> [ 1440.424480]  handle_percpu_devid_irq from
> >> generic_handle_domain_irq+0x38/0x48
> >> [ 1440.431618]  generic_handle_domain_irq from gic_handle_irq+0x90/0xa=
8
> >> [ 1440.437953]  gic_handle_irq from generic_handle_arch_irq+0x30/0x40
> >> [ 1440.444094]  generic_handle_arch_irq from __irq_svc+0x88/0xc8
> >> [ 1440.449920] Exception stack(0xde803a30 to 0xde803a78)
> >> [ 1440.454914] 3a20:                                     de803b00
> >> 00000000 00000001 000000c0
> >> [ 1440.463141] 3a40: e5333f40 de803ba0 de803bd0 00000001 e5333f40
> >> de803b00 c1241d90 bad0075c
> >> [ 1440.471262] 3a60: c20584b8 de803a7c c0114114 c0113850 200f0013 ffff=
ffff
> >> [ 1440.477959]  __irq_svc from unwind_exec_insn+0x4/0x658
> >> [ 1440.483078]  unwind_exec_insn from call_with_stack+0x18/0x20
> >
> > This is hard to analyze without being able to reproduce it, but it talk=
s
> > about the stack and Kasan and unwinding, so could it (also) be related =
to the
> > VMAP:ed stack?
> >
> > Did you try to revert (or check out the commit before and after)
> > b6506981f880 ARM: unwind: support unwinding across multiple stacks
> > to see if this is again fixing the issue?
> I Linus,
>
> Yes, I've tried to revert this particular commit on top of your last
> patches but I have some conflicts inside arch/arm/kernel/unwind.c

What happens if you just

git checkout b6506981f880^

And build and boot that? It's just running the commit right before the
unwinding patch.

Yours,
Linus Walleij

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
ACRpkdZa5x6NvUg0kU6F0%2BHaFhKhVswvK2WaaCSBx3-JCVFcag%40mail.gmail.com.
