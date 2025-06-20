Return-Path: <kasan-dev+bncBDTMJ55N44FBBG5K2XBAMGQEHDQC5ZQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53d.google.com (mail-ed1-x53d.google.com [IPv6:2a00:1450:4864:20::53d])
	by mail.lfdr.de (Postfix) with ESMTPS id 3C28AAE1AFF
	for <lists+kasan-dev@lfdr.de>; Fri, 20 Jun 2025 14:33:33 +0200 (CEST)
Received: by mail-ed1-x53d.google.com with SMTP id 4fb4d7f45d1cf-606b62ce2d4sf1551086a12.3
        for <lists+kasan-dev@lfdr.de>; Fri, 20 Jun 2025 05:33:33 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1750422813; cv=pass;
        d=google.com; s=arc-20240605;
        b=gSbKW5SVg1MEzMBVnPmQ+jIih2B6mTNUwACu3m3n1qP3qlGU4HL7PaDkMV6IKuJpzD
         smt5ZBGrqfJ1aJHMAMwd6K9IUU0Y6F0Fcf885vChc6VvnQALMVNM99+Pf3Mu0qb0rXv8
         1kn0zMpgip1PlbPpc1y7QqxwFDhlcUw+26vFmF4AOVkYZWEg/nj9LstqXt71UKYQdORJ
         c5jmf58Ydn2o5cHD+D6YxvXIuAs5NqhTaMdm30VIF/ZfKV+Ln84vfZd0Fu5iloXKEFZb
         By/sNAx9nbkFCnyBQ6umd/tPz4+6cWJAG0fL0qqcCMAkcAFgsyY17ma4V2FD1srAz/YE
         RytA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-disposition:mime-version
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=2My4QsLaFFKwA/CAXPi3zkVCxiNwQiX83a9c+iMSbaI=;
        fh=3BmEwX6VZfJ1ymr90WieNr5pBt7yCTQOvCBXG9qBDAU=;
        b=MXtcU3C/XKCW0xNEr7B2f3jbwU4qX7pnj1k1b817oOiwyPJK0XTMAmsn1J5h+xdkJS
         DBTxPy4EV7VdiZpnd+5PhzSWcg9hzOjJxI1fY4yrkuGf2tjyZj/X+YkVNLS7fmX+MfCi
         uNNOD/YnHvQA5qKW1HjL7T8t3YJJwjltEFLS01294ZNYECLcwyLMb48AnV8aq1m0VFT1
         e9hSmooxKTMG3phNN7B5WgpZuMOrjlBoU3OWGpmxY1zf9VW+gs4sHxaPAnchhNq2uH+q
         IbHod9vl5kOCdXg+WYx/UvOvqy7tleCkvzQ+dQOpkyaq4ZI3WIrswZWuYDBW8F9Utr4I
         2l/g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of breno.debian@gmail.com designates 209.85.218.42 as permitted sender) smtp.mailfrom=breno.debian@gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1750422813; x=1751027613; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-disposition:mime-version:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=2My4QsLaFFKwA/CAXPi3zkVCxiNwQiX83a9c+iMSbaI=;
        b=D+uMNpCvUF6hlF42UcQQAI9ZHl3yI0YdhRlJzA+9Fb9lNgh1cE9bFc+KusJkiSewNG
         afoHL99UfGU61Itva9zsYXSvlAN7nZd8e9oBpnXnmQ/T80iV3yAqF1MhLUP0mzxKb1Kb
         +8RG0fsobkuXiobrNNP7b/7y9d67TjPwo8ZT8i+ZFF0dUPUY5m/YIoBnUYMj7loezJGk
         601P3nPINbBRgIAEkds3o90UDpGKq+Cpz2O3XBph4kzJ+K3Q2tzZtYNQauK90xRJJFgg
         MC5TdcmzLof9zuQSGVVPdLD0QFLRzjStCA9KcTuVUisHQDNo2JCNf6DbgkgkLl75i13D
         iUZQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1750422813; x=1751027613;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-disposition:mime-version:message-id:subject:cc:to:from:date
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=2My4QsLaFFKwA/CAXPi3zkVCxiNwQiX83a9c+iMSbaI=;
        b=BqXnV6CzSTOXY29nkpqq7Ho/syrDxcEHRg3Fo11UCzSLwjJ/lA04xzquBTYW2Dx8SE
         Bb1naDaU8I/kmiH9kyJKSmmvkGZI7Wn/H7JxAJXJAr8bRzUBHwN1JHuK1Sl7oTX2grxS
         MHRa8pXLbxzeJ+EMElm/Zzx4xdV5qdOE3eo0l/oDjM9dmmnhigxLHdXEkYTINjannVjc
         iUR93XgoTKmA9POwya0DszHBCS16DpBQ4AZtlUkcosQ3e8MHE5vvAqXCnFtRqLFIWdPv
         K1GnW3heuZffrlGnU1mceSqpMkB1HyvpkADOaoF8+EBwUJUxQUsZQZbfCmFk9+Lo8vD+
         hgbg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCV3xBoivVjGYFvFt4bWsPMjAFc4b7kLPrlsJEoaKCax98ZnDuxJ0yyrDEH//WNPAOLb2a06Dg==@lfdr.de
X-Gm-Message-State: AOJu0YwmOeBqxVA6xW/k6gh02OegTg5gh30k7fVohaQ3CTz8g00wGfQz
	JVZMaSuFIHZrdnoiWpN/fsOtjgYTyvF7uK7fvyAHBy0b2rvi07mkUuHd
X-Google-Smtp-Source: AGHT+IFfzSMf52SkBTHSN18YQpK/Z9lRXfTmmw9eGuEzIdewnignoKXSlKel2L244WexvVlvvajnpA==
X-Received: by 2002:a05:6402:2695:b0:601:89d4:968e with SMTP id 4fb4d7f45d1cf-60a1cd33336mr2395850a12.27.1750422812285;
        Fri, 20 Jun 2025 05:33:32 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcr4c+XMyVTiy+WJlg3sDPl8jFs48PMoW0g080T+zxZkQ==
Received: by 2002:a05:6402:26d1:b0:607:2358:a2fa with SMTP id
 4fb4d7f45d1cf-609e789ccbcls1607668a12.1.-pod-prod-01-eu; Fri, 20 Jun 2025
 05:33:29 -0700 (PDT)
X-Received: by 2002:a05:6402:50d1:b0:606:f7bf:86f3 with SMTP id 4fb4d7f45d1cf-60a1ccaa02amr2566020a12.6.1750422809608;
        Fri, 20 Jun 2025 05:33:29 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1750422809; cv=none;
        d=google.com; s=arc-20240605;
        b=G52QDxaZepVfnpXL1xwWBz75H7F1TFwe1MTQLPUwEITbJQCYbrM+QJy6nL7MA7/xl3
         kYmpn/yHSKj6XOCcitJBzCuNdkvX++0VSTspBqUNSvr2j7lq7YxgrdLwTvXGDSQkxD+i
         I3N0ypXA61aRcdRFtjlQfNoj/exX+tdrNDW9fJdT1YMT77HSTBIzzQSr+flGQ/qdmGlg
         ywVivxob0dtBiPaB7m/WUHsnAhY2Sgu4GZdkMByo6YuU76hOJibFHxp5FSOabWIXLK57
         Q1+pKc+us0ek5syPptmtDqUQT3OxoiBeBNgGxiT0wp8ctJQYFx9z7065+EuoHY176R13
         f77Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-disposition:mime-version:message-id:subject:cc:to:from:date;
        bh=9vnjuLto9+1rU3NSYkM8aaoyxJ4wq394y7ayDcBF8ls=;
        fh=UBQD2PfzEQT1uqYiWLpq6QQBNb+7Un7syKzUlIKrUrw=;
        b=G/Wb0P4mrT21s0Uv61vGmq6wIw0iR6DSiYZbE0ROSEzBg9v6+VEFIGj1dboiRMyErk
         qqUKSSD9kg3TCv6OJHkhivzB+1UaGDBzjrFHBRlLcX6MfwI6wcmZbbK8GucYioag4LoD
         F+/BFzCzqGPfUsRIkHf+Hmv18RfI3Se40BdZWLUmQd2l5r19nmnn3w4H2dpwwaojf9u1
         d5EnAV3IpSh53856LHIg4F9jnc6K4pbfuVmN5Hk3Ln2Q1Kp5Y3Ce34VEXIL6LO0ZN7ab
         BHD2dvY0X3kjWXqcHH6RjpJiggjOOOfySmPu4XDK25t9diK5PKCpmY/LSBPqx7Zz4Vw7
         3kzA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of breno.debian@gmail.com designates 209.85.218.42 as permitted sender) smtp.mailfrom=breno.debian@gmail.com
Received: from mail-ej1-f42.google.com (mail-ej1-f42.google.com. [209.85.218.42])
        by gmr-mx.google.com with ESMTPS id 4fb4d7f45d1cf-60a18cb8e0fsi48335a12.5.2025.06.20.05.33.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 20 Jun 2025 05:33:29 -0700 (PDT)
Received-SPF: pass (google.com: domain of breno.debian@gmail.com designates 209.85.218.42 as permitted sender) client-ip=209.85.218.42;
Received: by mail-ej1-f42.google.com with SMTP id a640c23a62f3a-ade4679fba7so347545766b.2
        for <kasan-dev@googlegroups.com>; Fri, 20 Jun 2025 05:33:29 -0700 (PDT)
X-Gm-Gg: ASbGncsmAnAz0+3gFb6uThuFWvMNJNLQ7xIAGTjOpIXH7dLzbhsMGebwx24o+U2IglN
	BmtvtiFww/arRffB+Lz6924Q+Gi3aeA/wiaK9+u4vJtOdbtTYiG4+XYX1fsXmwtrNM3FWyqPG52
	Zz/Sr5fKFXgVYLD/fv2A7CdlwJQCbnYq++1YvdhwglRDO588xYc6VNBSp/pXo+4eBaqo5keFpdv
	kiVdRNKT7jGLjv7JkJ4e7Lw6MUazaol1Y/VJq6e1s5waqvX8lYreZvZ8sxXbszGxJo4G3cO9Y+N
	OeKSPjc0MJ2Ik22y0Zg403CWIDPcRWMuzaSjyXj2lol2RnNekY4q
X-Received: by 2002:a17:907:d8f:b0:ad8:8c09:a51a with SMTP id a640c23a62f3a-ae0578f5642mr266573166b.4.1750422808480;
        Fri, 20 Jun 2025 05:33:28 -0700 (PDT)
Received: from gmail.com ([2a03:2880:30ff:5::])
        by smtp.gmail.com with ESMTPSA id a640c23a62f3a-ae05408303asm154565466b.83.2025.06.20.05.33.27
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 20 Jun 2025 05:33:27 -0700 (PDT)
Date: Fri, 20 Jun 2025 05:33:22 -0700
From: Breno Leitao <leitao@debian.org>
To: kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org
Cc: catalin.marinas@arm.com, will@kernel.org, song@kernel.org,
	mark.rutland@arm.com, usamaarif642@gmail.com
Subject: arm64: BUG: KASAN: invalid-access in arch_stack_walk
Message-ID: <aFVVEgD0236LdrL6@gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
X-Original-Sender: leitao@debian.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of breno.debian@gmail.com designates 209.85.218.42 as
 permitted sender) smtp.mailfrom=breno.debian@gmail.com
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

I'm encountering a KASAN warning during aarch64 boot and I am struggling
to determine the cause. I haven't come across any reports about this on
the mailing list so far, so I'm sharing this early in case others are
seeing it too.

This issue occurs both on Linus's upstream branch and in the 6.15 final
release. The stack trace below is from 6.15 final. I haven't started
bisecting yet, but that's my next step.

Here are a few details about the problem:

1) it happen on my kernel boots on a aarch64 host
2) The lines do not match the code very well, and I am not sure why. It
   seems it is offset by two lines. The stack is based on commit
   0ff41df1cb26 ("Linux 6.15")
3) My config is at https://pastebin.com/ye46bEK9


	[  235.831690] ==================================================================
	[  235.861238] BUG: KASAN: invalid-access in arch_stack_walk (arch/arm64/kernel/stacktrace.c:346 arch/arm64/kernel/stacktrace.c:387)
	[  235.887206] Write of size 96 at addr a5ff80008ae8fb80 by task kworker/u288:26/3666
	[  235.918139] Pointer tag: [a5], memory tag: [00]
	[  235.942722] Workqueue: efi_rts_wq efi_call_rts
	[  235.942732] Call trace:
	[  235.942734] show_stack (arch/arm64/kernel/stacktrace.c:468) (C)
	[  235.942741] dump_stack_lvl (lib/dump_stack.c:123)
	[  235.942748] print_report (mm/kasan/report.c:409 mm/kasan/report.c:521)
	[  235.942755] kasan_report (mm/kasan/report.c:636)
	[  235.942759] kasan_check_range (mm/kasan/sw_tags.c:85)
	[  235.942764] memset (mm/kasan/shadow.c:53)
	[  235.942769] arch_stack_walk (arch/arm64/kernel/stacktrace.c:346 arch/arm64/kernel/stacktrace.c:387)
	[  235.942773] return_address (arch/arm64/kernel/return_address.c:44)
	[  235.942778] trace_hardirqs_off.part.0 (kernel/trace/trace_preemptirq.c:95)
	[  235.942784] trace_hardirqs_off_finish (kernel/trace/trace_preemptirq.c:98)
	[  235.942789] enter_from_kernel_mode (arch/arm64/kernel/entry-common.c:62)
	[  235.942794] el1_interrupt (arch/arm64/kernel/entry-common.c:559 arch/arm64/kernel/entry-common.c:575)
	[  235.942799] el1h_64_irq_handler (arch/arm64/kernel/entry-common.c:581)
	[  235.942804] el1h_64_irq (arch/arm64/kernel/entry.S:596)
	[  235.942809]  0x3c52ff1ecc (P)
	[  235.942825]  0x3c52ff0ed4
	[  235.942829]  0x3c52f902d0
	[  235.942833]  0x3c52f953e8
	[  235.942837] __efi_rt_asm_wrapper (arch/arm64/kernel/efi-rt-wrapper.S:49)
	[  235.942843] efi_call_rts (drivers/firmware/efi/runtime-wrappers.c:269)
	[  235.942848] process_one_work (./arch/arm64/include/asm/jump_label.h:36 ./include/trace/events/workqueue.h:110 kernel/workqueue.c:3243)
	[  235.942854] worker_thread (kernel/workqueue.c:3313 kernel/workqueue.c:3400)
	[  235.942858] kthread (kernel/kthread.c:464)
	[  235.942863] ret_from_fork (arch/arm64/kernel/entry.S:863)

	[  236.436924] The buggy address belongs to the virtual mapping at
	[a5ff80008ae80000, a5ff80008aea0000) created by:
	arm64_efi_rt_init (arch/arm64/kernel/efi.c:219)

	[  236.506959] The buggy address belongs to the physical page:
	[  236.529724] page: refcount:1 mapcount:0 mapping:0000000000000000 index:0x0 pfn:0x12682
	[  236.562077] flags: 0x17fffd6c0000000(node=0|zone=2|lastcpupid=0x1ffff|kasantag=0x5b)
	[  236.593722] raw: 017fffd6c0000000 0000000000000000 dead000000000122 0000000000000000
	[  236.625365] raw: 0000000000000000 0000000000000000 00000001ffffffff 0000000000000000
	[  236.657004] page dumped because: kasan: bad access detected

	[  236.685828] Memory state around the buggy address:
	[  236.705390]  ffff80008ae8f900: 00 00 00 00 00 a5 a5 a5 a5 00 00 00 00 00 a5 a5
	[  236.734899]  ffff80008ae8fa00: a5 a5 a5 00 00 00 00 00 00 a5 a5 a5 a5 a5 00 a5
	[  236.764409] >ffff80008ae8fb00: 00 a5 a5 a5 00 a5 a5 a5 a5 a5 a5 00 a5 a5 a5 00
	[  236.793918]                                                     ^
	[  236.818810]  ffff80008ae8fc00: a7 a5 a5 a5 a5 a5 a5 a5 a5 00 a5 00 a5 a5 a5 a5
	[  236.848321]  ffff80008ae8fd00: a5 a5 a5 a5 00 a5 00 a5 a5 a5 a5 a5 a5 a5 a5 a5
	[  236.877828] ==================================================================

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aFVVEgD0236LdrL6%40gmail.com.
