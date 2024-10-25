Return-Path: <kasan-dev+bncBAABBFGJ5W4AMGQESS5FLNA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x339.google.com (mail-wm1-x339.google.com [IPv6:2a00:1450:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id AF4419AFE29
	for <lists+kasan-dev@lfdr.de>; Fri, 25 Oct 2024 11:27:49 +0200 (CEST)
Received: by mail-wm1-x339.google.com with SMTP id 5b1f17b1804b1-431673032e6sf12890795e9.0
        for <lists+kasan-dev@lfdr.de>; Fri, 25 Oct 2024 02:27:49 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1729848469; cv=pass;
        d=google.com; s=arc-20240605;
        b=SyLBq7aHyAZDf6AbfpQsPjqT7fI3HrBoLzj5L5+OT3g4QZXKfJedFXAP5w+ECqKwsQ
         XWFc6Mz1YCmw9otD07mEIpqiSp2H416wgEbNMI8ljQpIWP0FwjDxUdtDpQF9AfQiws2c
         zJaOfCfYxN2J/iLEZSzd3Dhdd+cl2xGdHev3Kw864ukaHOXo2ofPamH8jaRQLrj+tUDb
         U8jCZa3GtHQ5Epbkh79Q74zDRfM/GZaNUzJlOMz2bl0YWb/1j5vRgSTzhVKbvOroQ9sa
         LuA3+6GYQgtH3ZaIMKQ3mI0p8dWugtshQ9u6vYVUqpNfXAmR7HwGTO7sfiX9hfoMleJl
         zXVg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :in-reply-to:from:content-language:references:cc:to:subject
         :user-agent:mime-version:date:message-id:sender:dkim-signature;
        bh=s7KJmjcYBkCc6PAa0RwP1cGeyDZBL/0398DgDTKNZ1o=;
        fh=Ol6uXu2ZAiQBYmxbFlBfY7wDutDD8W1LHQiJACr0ZyE=;
        b=HiTxzKgKcCWfinhBCzFC/hhZMciyplpt2rpOMK/m0JybXD4hgfVCguapTaYNre1SgY
         Bx+WdAbZP+FWt0ubv1CiNlfznd/OyT1GBaLqqRpwThGfZ6vCUpYrTrLvYFvQVn3z3BPR
         wbV2TlOZ7qI1vaV3wz+nilkegWDo8gLqm1cUJT4EHran3myVwl6wG4gHXfHZc6ZCMj3E
         Z6ni6y2xygCun7j1g7p0XW5Ahuiy1Y7nte6ENSCSowfzATnHh5Qq+lYW0K+kd34mvSzw
         YD/Z8I8iLrerGjMDI1nLhL7ps4q2TUyMXwzVSKjfPfLWjUG3I0c9Xf9B2FQzbPCqV4HP
         n3OA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@foss.st.com header.s=selector1 header.b="AN96QTd/";
       spf=pass (google.com: domain of prvs=0028e6b0e8=clement.legoffic@foss.st.com designates 185.132.182.106 as permitted sender) smtp.mailfrom="prvs=0028e6b0e8=clement.legoffic@foss.st.com";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=foss.st.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1729848469; x=1730453269; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:in-reply-to:from
         :content-language:references:cc:to:subject:user-agent:mime-version
         :date:message-id:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=s7KJmjcYBkCc6PAa0RwP1cGeyDZBL/0398DgDTKNZ1o=;
        b=kJtQ80UI9eb5mlNsiBZp1oR+PRnoUCqoTUnk+W8FmeR8dkgL+19jtXvVXQdHdo7dgQ
         VriSc1sAxw7Q2WXA3BNWMXvd0me4DJSdQNEpL38M45JQ9oHy2rALH+vJB2Gar9cUmwf4
         p0g2+OwPWH3+LZE31MDM2gUm+TY9sk2HKQBORl3wYVJJCLyZc/yjdwu9/pTV0OIlFhrt
         Zt81U2mT6xuxMVpS/Gw1CaUOtvy5PvgtgWPXBNTaALvRh3dCn9NZYLThqfr4hAaJvOe8
         0vBYj8Jr9NMEOvQvAFSRx1kDd3GlYKMCf6VgndJj3AjSzhvkRJrXBBHW4KRH9MB/6KHo
         ieqg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1729848469; x=1730453269;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=s7KJmjcYBkCc6PAa0RwP1cGeyDZBL/0398DgDTKNZ1o=;
        b=bsjb4GwyPdgfIY2ea91xF9IznB50L5rmUfT7lELsmp3Nb2Y3YR2vXAMTrqwfw9qIHh
         /bKiipYJQzTuB6rOUDAzt4bxnRHRqMJyE4MzzqvQEy2yzxnM8wC4NffREollc7FuaQHV
         Sq4Kx6ZFpVfm4We+YitukNgR1F1MX3E9dz+S6R0xIIpLKaBHv4sL+behb4L0fUARkev+
         E8TfHuWX+gOqqH5nLb+rcvbU6+1ThY0oT0PCyXPdd/qV1pog2Bq5J2Fr4V3T2mNll5qK
         GUF1O4Vfd01sEaoP46KxGy89fRTruEzX6GGZyjMUsBD9zgXJQ7cbLUQiuTCSzKCN2vok
         qWrA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUvXPvl2qEzPZizHqvPts3nxquxnF4AU2YTo31Em+DJ8KkzF0pNUyNXo+CXL7TLGsEo2RUJZA==@lfdr.de
X-Gm-Message-State: AOJu0Yz7lfDkSVxte7JksHwrbwvHiC5Jg1lTAgroYmdwzN4+S9Q12j8N
	GCqN7Nadb4bJwN0zP45n1PLLYCdsQXjAQNy//5ohQN7/RZak2irS
X-Google-Smtp-Source: AGHT+IEmVE1GVjpR1PORIoNsX2ERpK7Eff6rbryNPcNXxpQaiVRSqrbJiDIuN3vaxoEL4kQi4hEHag==
X-Received: by 2002:a05:600c:4fc4:b0:431:5632:4497 with SMTP id 5b1f17b1804b1-4318418aef8mr84021635e9.26.1729848468662;
        Fri, 25 Oct 2024 02:27:48 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:4f4e:b0:431:1228:2580 with SMTP id
 5b1f17b1804b1-4318a1f26e5ls8727545e9.0.-pod-prod-01-eu; Fri, 25 Oct 2024
 02:27:47 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWKHWG7MobjbOE/jrrvLVR0dKV7MhbBpYHBtVGlqCDp6gfz7GldoCNNJ0p34t7lJJlaVtaVcDexRlI=@googlegroups.com
X-Received: by 2002:a05:600c:4708:b0:42c:a89e:b0e6 with SMTP id 5b1f17b1804b1-4318413e8b1mr69352865e9.11.1729848466749;
        Fri, 25 Oct 2024 02:27:46 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1729848466; cv=none;
        d=google.com; s=arc-20240605;
        b=LdYSTprTW04xq/iOi5X0BcHOBuDYmPAIv9Ueb/N5PUQUj1nMitzwDb8YHtMPXFG/nu
         ciGeg7t4hbxrFGunDjwa3rKKIIK0d6FbQBY2Y6Oo8GFTIjHaB09O5AKq2fag4kEpV7lI
         5mXfPYo195Ry4W4IlRSlIxuPWNlgtGz5jIBSRta1QL8BOFJV4aSN8toH5zAgDJIjgCkG
         wlBQR8I9+1ExgLjs6lddMw/KUuMU+BKu0rl+oC+Ras3hKXY0jCJpeOfFbxuv6OS2meU/
         w86U4ifnAWJSCkcMjubDWKwME7JtnEsc8FgUJRMlWXlE0/EmAqNScOhiUfDD9sdAsXup
         vh8w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=/NjitP+EsJbsLPMXwvV3a07N9NXtXF6fLkWZSKiMJ6I=;
        fh=JWG6MbBWyBs8B59LGsgsvJj0LACr1BQnxjwFrlphSnA=;
        b=NI/L8dEglPaWFy1tYw6JRtGChSHiQ3kAKl2sXOPsEwzsG6IFs/6LimfcKLQIqtkLWb
         orY91EIONxcP4+7k+9S5zGdEbUkELbGhpCsAGi5QNE8/bueR2pLE160esaRdY6ou1fGt
         SW2bgm3ZiKljSYMSPDJRHn7IjGlq0+8NtF0zmS98DAoKtYTMrXP6PYX7fYwgfqNuGcH/
         B8KNt0QunitM6u/TqnQaEWMQhklKr22bOeK2IRErds+LmWtA0Wyj9FXcNg3706KzVaA6
         TvLgOonYYw8eAMmHx3oUZVnXBvHyRycz7OJHzo6RPrio9oMbpg/DTgMHf6UcxqOlHwZk
         q6sQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@foss.st.com header.s=selector1 header.b="AN96QTd/";
       spf=pass (google.com: domain of prvs=0028e6b0e8=clement.legoffic@foss.st.com designates 185.132.182.106 as permitted sender) smtp.mailfrom="prvs=0028e6b0e8=clement.legoffic@foss.st.com";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=foss.st.com
Received: from mx07-00178001.pphosted.com (mx07-00178001.pphosted.com. [185.132.182.106])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-4317dde0840si3470665e9.1.2024.10.25.02.27.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 25 Oct 2024 02:27:46 -0700 (PDT)
Received-SPF: pass (google.com: domain of prvs=0028e6b0e8=clement.legoffic@foss.st.com designates 185.132.182.106 as permitted sender) client-ip=185.132.182.106;
Received: from pps.filterd (m0288072.ppops.net [127.0.0.1])
	by mx07-00178001.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 49P6oAjO006920;
	Fri, 25 Oct 2024 11:27:32 +0200
Received: from beta.dmz-ap.st.com (beta.dmz-ap.st.com [138.198.100.35])
	by mx07-00178001.pphosted.com (PPS) with ESMTPS id 42em4cn7ts-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 25 Oct 2024 11:27:32 +0200 (MEST)
Received: from euls16034.sgp.st.com (euls16034.sgp.st.com [10.75.44.20])
	by beta.dmz-ap.st.com (STMicroelectronics) with ESMTP id 344E24002D;
	Fri, 25 Oct 2024 11:25:41 +0200 (CEST)
Received: from Webmail-eu.st.com (shfdag1node2.st.com [10.75.129.70])
	by euls16034.sgp.st.com (STMicroelectronics) with ESMTP id 136B225F1B4;
	Fri, 25 Oct 2024 11:24:35 +0200 (CEST)
Received: from [10.48.86.107] (10.48.86.107) by SHFDAG1NODE2.st.com
 (10.75.129.70) with Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id 15.1.2507.37; Fri, 25 Oct
 2024 11:24:34 +0200
Message-ID: <f3856158-10e6-4ee8-b4d5-b7f2fe6d1097@foss.st.com>
Date: Fri, 25 Oct 2024 11:24:33 +0200
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v3 1/2] ARM: ioremap: Sync PGDs for VMALLOC shadow
To: Linus Walleij <linus.walleij@linaro.org>, Ard Biesheuvel <ardb@kernel.org>
CC: Andrey Ryabinin <ryabinin.a.a@gmail.com>,
        Alexander Potapenko
	<glider@google.com>,
        Andrey Konovalov <andreyknvl@gmail.com>,
        Dmitry Vyukov
	<dvyukov@google.com>,
        Vincenzo Frascino <vincenzo.frascino@arm.com>,
        kasan-dev <kasan-dev@googlegroups.com>,
        Russell King <linux@armlinux.org.uk>, Kees Cook <kees@kernel.org>,
        AngeloGioacchino Del Regno
	<angelogioacchino.delregno@collabora.com>,
        Mark Brown <broonie@kernel.org>, Mark Rutland <mark.rutland@arm.com>,
        Antonio Borneo
	<antonio.borneo@foss.st.com>,
        <linux-stm32@st-md-mailman.stormreply.com>,
        <linux-arm-kernel@lists.infradead.org>, <stable@vger.kernel.org>
References: <20241017-arm-kasan-vmalloc-crash-v3-0-d2a34cd5b663@linaro.org>
 <20241017-arm-kasan-vmalloc-crash-v3-1-d2a34cd5b663@linaro.org>
 <69f71ac8-4ba6-46ed-b2ab-e575dcada47b@foss.st.com>
 <CACRpkdYvgZj1R4gAmzFhf4GmFOxZXhpHVTOio+hVP52OBAJP0A@mail.gmail.com>
 <46336aba-e7dd-49dd-aa1c-c5f765006e3c@foss.st.com>
 <CACRpkdY2=qdY_0GA1gB03yHODPEvxum+4YBjzsXRVnhLaf++6Q@mail.gmail.com>
Content-Language: en-US
From: Clement LE GOFFIC <clement.legoffic@foss.st.com>
In-Reply-To: <CACRpkdY2=qdY_0GA1gB03yHODPEvxum+4YBjzsXRVnhLaf++6Q@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Transfer-Encoding: quoted-printable
X-Originating-IP: [10.48.86.107]
X-ClientProxiedBy: SHFCAS1NODE1.st.com (10.75.129.72) To SHFDAG1NODE2.st.com
 (10.75.129.70)
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1039,Hydra:6.0.680,FMLib:17.12.60.29
 definitions=2024-09-06_09,2024-09-06_01,2024-09-02_01
X-Original-Sender: clement.legoffic@foss.st.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@foss.st.com header.s=selector1 header.b="AN96QTd/";       spf=pass
 (google.com: domain of prvs=0028e6b0e8=clement.legoffic@foss.st.com
 designates 185.132.182.106 as permitted sender) smtp.mailfrom="prvs=0028e6b0e8=clement.legoffic@foss.st.com";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=foss.st.com
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

On 10/24/24 23:58, Linus Walleij wrote:
> Hi Clement,
>=20
> I saw I missed to look closer at the new bug found in ext4
> on the STM32:
>=20
> On Mon, Oct 21, 2024 at 2:12=E2=80=AFPM Clement LE GOFFIC
> <clement.legoffic@foss.st.com> wrote:
>=20
>> Perhaps not related with this topic but as in the backtrace I am getting
>> some keyword from our start exchange, I dump the crash below.
>> If this backtrace is somehow related with our issue, please have a look.
> (...)
>> [ 1439.351945] PC is at __read_once_word_nocheck+0x0/0x8
>> [ 1439.356965] LR is at unwind_exec_insn+0x364/0x658
> (...)
>> [ 1440.333183]  __read_once_word_nocheck from unwind_exec_insn+0x364/0x6=
58
>> [ 1440.339726]  unwind_exec_insn from unwind_frame+0x270/0x618
>> [ 1440.345352]  unwind_frame from arch_stack_walk+0x6c/0xe0
>> [ 1440.350674]  arch_stack_walk from stack_trace_save+0x90/0xc0
>> [ 1440.356308]  stack_trace_save from kasan_save_stack+0x30/0x4c
>> [ 1440.362042]  kasan_save_stack from __kasan_record_aux_stack+0x84/0x8c
>> [ 1440.368473]  __kasan_record_aux_stack from task_work_add+0x90/0x210
>> [ 1440.374706]  task_work_add from scheduler_tick+0x18c/0x250
>> [ 1440.380245]  scheduler_tick from update_process_times+0x124/0x148
>> [ 1440.386287]  update_process_times from tick_sched_handle+0x64/0x88
>> [ 1440.392521]  tick_sched_handle from tick_sched_timer+0x60/0xcc
>> [ 1440.398341]  tick_sched_timer from __hrtimer_run_queues+0x2c4/0x59c
>> [ 1440.404572]  __hrtimer_run_queues from hrtimer_interrupt+0x1bc/0x3a0
>> [ 1440.411009]  hrtimer_interrupt from arch_timer_handler_virt+0x34/0x3c
>> [ 1440.417447]  arch_timer_handler_virt from
>> handle_percpu_devid_irq+0xf4/0x368
>> [ 1440.424480]  handle_percpu_devid_irq from
>> generic_handle_domain_irq+0x38/0x48
>> [ 1440.431618]  generic_handle_domain_irq from gic_handle_irq+0x90/0xa8
>> [ 1440.437953]  gic_handle_irq from generic_handle_arch_irq+0x30/0x40
>> [ 1440.444094]  generic_handle_arch_irq from __irq_svc+0x88/0xc8
>> [ 1440.449920] Exception stack(0xde803a30 to 0xde803a78)
>> [ 1440.454914] 3a20:                                     de803b00
>> 00000000 00000001 000000c0
>> [ 1440.463141] 3a40: e5333f40 de803ba0 de803bd0 00000001 e5333f40
>> de803b00 c1241d90 bad0075c
>> [ 1440.471262] 3a60: c20584b8 de803a7c c0114114 c0113850 200f0013 ffffff=
ff
>> [ 1440.477959]  __irq_svc from unwind_exec_insn+0x4/0x658
>> [ 1440.483078]  unwind_exec_insn from call_with_stack+0x18/0x20
>=20
> This is hard to analyze without being able to reproduce it, but it talks
> about the stack and Kasan and unwinding, so could it (also) be related to=
 the
> VMAP:ed stack?
>=20
> Did you try to revert (or check out the commit before and after)
> b6506981f880 ARM: unwind: support unwinding across multiple stacks
> to see if this is again fixing the issue?
I Linus,

Yes, I've tried to revert this particular commit on top of your last=20
patches but I have some conflicts inside arch/arm/kernel/unwind.c

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/f=
3856158-10e6-4ee8-b4d5-b7f2fe6d1097%40foss.st.com.
