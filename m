Return-Path: <kasan-dev+bncBCMIZB7QWENRB6V3T2PAMGQEPW77H7Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x338.google.com (mail-wm1-x338.google.com [IPv6:2a00:1450:4864:20::338])
	by mail.lfdr.de (Postfix) with ESMTPS id EF7C9671502
	for <lists+kasan-dev@lfdr.de>; Wed, 18 Jan 2023 08:21:31 +0100 (CET)
Received: by mail-wm1-x338.google.com with SMTP id m7-20020a05600c4f4700b003d971a5e770sf17643213wmq.3
        for <lists+kasan-dev@lfdr.de>; Tue, 17 Jan 2023 23:21:31 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1674026491; cv=pass;
        d=google.com; s=arc-20160816;
        b=VhKTWFVbib4SxsmBp11QGdW8yDKIlumOGMxi3r0OPsKqhbTc4c7wm21oZBE8YjU/gp
         XiK5UZDOUvr8jQ6CAAy7eNHVyOy/cu/Sx0dMzbuwSIamlfbzfC1HmnAkDqnGXcnlxCqb
         IveAjunMhH/RZ4f0ZtPx44RmqutVpd/xn7NbhCcJNpcI8fSnQWopLO5KdsVBcOwt+CpB
         8jmirn+E5ccffADI4NLW3M71ImSK+wgib3Yc0SI/TlOZwZO7MutplskNysedDXuu3zEj
         MfnWZtPNYlrX40k4kMm9kfi4/in8v7Dk+Ten2ezN8NbbVygpxv4wVwAop7TSQDAs/AIt
         598A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=dFsekrYxiHXog6lDu9VTtMQ6cqzIXzrcqc3lbBoL3Qw=;
        b=kaTkXei/XTgeqLHOV//xVWK2k9Dk/sr4HYW4zVOrY1OF7DqcBY+1+lEicXbOmR7VzK
         Pp7hem3Q8BHY8xFr7eiGT7tRt706OhWS1AVHcnJ09alPAKOCEn2z7E1tfWCX03mLKwl3
         kt5plCMXbDmWBpNYLj2So99169p/XCqKUCMW/HYB5E/HnDEpCCme2lUFMtekhgdhr776
         KFx1o3lu5vOVIAYBPtyijzw002c/p9H/KGVU5KxzGG/gubHHI2Vq2+Sv+UVtFlpmCBL9
         QcOxUR9/aAKPD7aNsNIvL01XEwV6ntRTfh7ct/FNgyQ4S2C9L/Gpao9ZOh4hSjri41PK
         9pTg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=W7IV0KUy;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::22f as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=dFsekrYxiHXog6lDu9VTtMQ6cqzIXzrcqc3lbBoL3Qw=;
        b=J96seml6E64LQKanGJpjJRa+0Nhb3hm3YK/la8xIyy9H4KNzoLdU87LiuYpLIccvDY
         UnBMZl5X3Tai26tAWV0rYoyVszawgzntHMcO81AVzpVQOXeaFkO4MCz2qRqWf5L50NKB
         TpvNyxbdk/0H2CPH16mM1QW3oDD3Co8EQii4fPFsSNU0g94o6osZoeP77cOFIQzc6nD6
         TweEAlmklL6suWb6YMtzUNohQtqwniKCclglfWrDnJ4cfZUbIc/zsAJbK6oEqwWDFFSv
         e0GdwYlBFZCFEOMzMuDZBmeVdcD7cU26SRAY2hauT69KBYjTIslmPaKrl366gOsl8OXG
         O6LQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=dFsekrYxiHXog6lDu9VTtMQ6cqzIXzrcqc3lbBoL3Qw=;
        b=MPawNJELs4gCCFtLazyzCTs/nxEgJ8BQAxgTXWldvg1aTxM+wO3VW7/8Zx2Gs1FnOX
         6tbO7K4LP8SFYFRL1Rs6uj06J59/STxZ3pu7tSXqNhWKm2nPLHpp5kRe8v5Zwyo9W8EW
         NLqyVskBI5rHH7ErHZCPLDyTd7r5tV4zumLOXkEsTevgj1ct4j5OXkl6HHSXqAM2hjKt
         krD85NzDalDObKWYVtXTiJhOC9kd/2ue6WgD7WNmixeb5O9iCJ4NIJnkeZsF/39yxIv3
         NCu9w8nPOvwCiP181JScJ6GW2uiqWRflHeX0sRG1J/el2Q0smxdmIl31qWTG9kCohE0N
         7wYQ==
X-Gm-Message-State: AFqh2kp4UhP5Utf9SJPFjKU57WwiBZxnEc5rmx5ZR0vfDSKoKiJ+loo2
	GJAQ+8iELcVK1KbPPePgaEo=
X-Google-Smtp-Source: AMrXdXtkRUoOdHVJ65oB/QHdtED7KTxUg27+hhiuQ1cdHHpbIuNYWIAfZt7Yd/f7PppBMovkROWf4w==
X-Received: by 2002:adf:f4c2:0:b0:2bc:1242:efd7 with SMTP id h2-20020adff4c2000000b002bc1242efd7mr314778wrp.626.1674026490960;
        Tue, 17 Jan 2023 23:21:30 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:d230:0:b0:225:6559:3374 with SMTP id k16-20020adfd230000000b0022565593374ls94252wrh.2.-pod-prod-gmail;
 Tue, 17 Jan 2023 23:21:30 -0800 (PST)
X-Received: by 2002:a5d:46c6:0:b0:2bd:15c6:a88a with SMTP id g6-20020a5d46c6000000b002bd15c6a88amr13979484wrs.54.1674026489966;
        Tue, 17 Jan 2023 23:21:29 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1674026489; cv=none;
        d=google.com; s=arc-20160816;
        b=lQWBvBPqa1oNekxpCSZU3lQqamgXvy+8AblDXMUThZN1IPC0JAT3gLeh3zSYa7/ZwK
         7gtU69eCOz7EBtdtGR5sbqEko2Jl/GcTelkZRgJaaS+dRfrdC+fqlBINQokrqHTNnTEp
         Ep1w0h+EIi2mC8Aum69lgtl5BvQnZJodVO6x38Wm6deTSMLCtqXZZC8Zzvrh6Plm/6KS
         u5HLZNdQPZSvyi8AXZiHJr3BRY68cCXa8NV/UmYqe36uFAULI3zjF0+RIq/hvSpRYAr0
         v+JJfVa4CWFoaUcO9tGYGgSkDixygmMlzr7ovkJPwawmjkJarbrt9nOx96wigQAQsrWo
         aHyQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=/KS0Ac1fk39R+mnsk4FGiw4jEMF+kWPMgOZ0L9WOZj4=;
        b=zRzfwT6swhkBi2IvKnHfS0rCAxdV03LCZp1DiMw0kkn/iTM4qSCK2cPdjolL8I+FzS
         vHDIjQH3sbpg+pOebakRSjUjjFL0a+frAa60btPE7cG/M43cBU7T79OsXbGppaFkKeUp
         5DU0ETNHbtyyp0Hf/l1aJ2TtPySPh0YvOAHUAqyWJBHEifxIlmuxFwmD/nfKbUF+CX5X
         z6fhmjAV63yKwKJAubYEgmxFR3v7PVOBe8D7elz7RtphFJwORKTl59VrU2tnZWwX6ExD
         4WeHOWwQi9aeprMtfg02Qf26Z9aAk58EbL5hDCQUwCuvfyum60H2ejuED4h34YoaEXd9
         FBsg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=W7IV0KUy;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::22f as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-lj1-x22f.google.com (mail-lj1-x22f.google.com. [2a00:1450:4864:20::22f])
        by gmr-mx.google.com with ESMTPS id c1-20020adfed81000000b002be29f05cdfsi122339wro.0.2023.01.17.23.21.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 17 Jan 2023 23:21:29 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::22f as permitted sender) client-ip=2a00:1450:4864:20::22f;
Received: by mail-lj1-x22f.google.com with SMTP id bn6so35624627ljb.13
        for <kasan-dev@googlegroups.com>; Tue, 17 Jan 2023 23:21:29 -0800 (PST)
X-Received: by 2002:a2e:bba1:0:b0:28b:75e7:c551 with SMTP id
 y33-20020a2ebba1000000b0028b75e7c551mr275520lje.463.1674026489358; Tue, 17
 Jan 2023 23:21:29 -0800 (PST)
MIME-Version: 1.0
References: <0c87033a-fcef-7c7e-742b-86f9a3477d78@redhat.com> <CAN=P9phn2xLw-saXVL2Y30KAMV3kgE-Sn0ASxpeZJfQLVZOZRg@mail.gmail.com>
In-Reply-To: <CAN=P9phn2xLw-saXVL2Y30KAMV3kgE-Sn0ASxpeZJfQLVZOZRg@mail.gmail.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 18 Jan 2023 08:21:16 +0100
Message-ID: <CACT4Y+acK9nPmCFU7kPL2M0EeXzAL6rCQ5LhScGbzvFAFwHAQg@mail.gmail.com>
Subject: Re: kpatch and kasan
To: Joe Lawrence <joe.lawrence@redhat.com>
Cc: Kostya Serebryany <kcc@google.com>, kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=W7IV0KUy;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::22f
 as permitted sender) smtp.mailfrom=dvyukov@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Dmitry Vyukov <dvyukov@google.com>
Reply-To: Dmitry Vyukov <dvyukov@google.com>
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

On Tue, 17 Jan 2023 at 17:50, Kostya Serebryany <kcc@google.com> wrote:
>
> +kernel-dynamic-tools
>
> On Tue, Jan 17, 2023 at 6:32 AM Joe Lawrence <joe.lawrence@redhat.com> wrote:
>>
>> Hi Kostya,
>>
>> I work on the kernel livepatching Kpatch project [1] and was hoping to
>> learn some info about compiler-generated (k)asan ELF sections.  If you
>> can point me to any references or folks who might entertain questions,
>> we would be much appreciated.
>>
>> The tl/dr; is that we would like to build kasan-enabled debug kernels
>> and then kpatches for them to help verify CVE mitigations.
>>
>> If you are unfamiliar with kpatch, it accepts an input .patch file,
>> builds a reference and patched kernel (with -ffunction-sections and
>> -fdata-sections) ... then performs a binary comparison between
>> reference/patched ELF sections.  New or changed ELF sections are
>> extracted into a new object file.  Boilerplate code is then added to
>> create a livepatch kernel module from that.
>>
>> The devil is in details, of course, so our kpatch-build tool needs to
>> know whether it should omit, copy, or re-generate an ELF section
>> depending on its purpose.  The kernel is rife with interesting sections
>> like para-virt instructions, jump labels, static call sites, etc.
>>
>> So, before trying to reverse engineer sections like .data..LASANLOC1 and
>> data..LASAN0 from the gcc source code, I was wondering if these were
>> documented somewhere?
>>
>>
>> Regards,
>>
>> [1] https://github.com/dynup/kpatch
>> --
>> Joe

+kasan-dev

Hi Joe,

But why not just build a new KASAN kernel and re-test? This looks so
much simpler.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BacK9nPmCFU7kPL2M0EeXzAL6rCQ5LhScGbzvFAFwHAQg%40mail.gmail.com.
