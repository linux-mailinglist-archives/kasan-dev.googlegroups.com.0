Return-Path: <kasan-dev+bncBDTMJ55N44FBBMOY6ONQMGQEVA4O5HQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x538.google.com (mail-ed1-x538.google.com [IPv6:2a00:1450:4864:20::538])
	by mail.lfdr.de (Postfix) with ESMTPS id E148863403A
	for <lists+kasan-dev@lfdr.de>; Tue, 22 Nov 2022 16:35:13 +0100 (CET)
Received: by mail-ed1-x538.google.com with SMTP id h9-20020a05640250c900b00461d8ee12e2sf9050427edb.23
        for <lists+kasan-dev@lfdr.de>; Tue, 22 Nov 2022 07:35:13 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1669131313; cv=pass;
        d=google.com; s=arc-20160816;
        b=JtMWHePQBCZkUIhL0J374aQeBXU64kNLfzwn4UixBVMxiegkM4sSDcTe66Recr3+8H
         +Ofgll3YIb0sLLNnyakuGolUL41rguTzTIQt1slR+P17ymnaWBT5TNKGlMzRmo11L4Do
         4hRElHUKK/aWxMFR37Y7/vhNrDr7dtZs2BgW4Ds1lV8O20V5wHdIHQgGe3fOJqQlYwtK
         RlPulD9mgL6DgjeorIcDF7Blwd85szL8puMGp06wWNHaTQlZo5TkSLiLCsFe0ayjpnmG
         Ff7cCg+gm3wh7N73e/ocOI1YL2C5/HZ+ByoaEqx07xjeP0LoVbFp8Aq8ODSo6g+UCq9o
         ggMA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-disposition:mime-version
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=2vqJe8FMJ7YXAUkYmdnzd9LrkxX+Ew6d1z/lzoljRdQ=;
        b=i/TyO5gOJwvni+2F28eCprRfaxR5H7Nyg0NGEjVI2I0kD3GnGLpVVD6KwSyJ9QJBuB
         vZ+rs5Yus66WYBPkx6kpmQDGWn96XSj74CH3gArmdWO39DmUi+Bdf86SMSuuMIcjp/yQ
         ryHEaNxQc/cwUHxT6+SN2OvjHEnhDHAffPZT/HoMq894izpuA/yj1B/mQausnHyYOrWi
         mBt0n4kaEzLYi4w9UrT1/6C/f5AVBwL42+s0UnylL33K/L3tPqiSouhbSuhCY2DoQBeN
         PL1GnA01ilE8zV+dWsiUVOaSzWsqmqAjw1LK0Zw7BB1a6/D4Qp3Aeaeq9VMM30Fy0kHj
         8wTg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of breno.debian@gmail.com designates 209.85.218.53 as permitted sender) smtp.mailfrom=breno.debian@gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-disposition:mime-version:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=2vqJe8FMJ7YXAUkYmdnzd9LrkxX+Ew6d1z/lzoljRdQ=;
        b=db+8Hwn2hBLNr9yhA7l8+iQ+/V7pRgvYZSGURe4OfYORTaUwHYUlk3XM/7qJiP0u8M
         VWu2z4TZYkYx1fwRqCCXFnLMX/G5YMtEh9L75iOfdGuANHbdEjobx7hzUOu5AYBzOh8x
         g9c3YsY+jSRj7IkneLdiZWE+F5tIFpJ0TXFYBCU2o1JYL6wSiRjDeBsqDyCFMoahd8yX
         Kz3OO+BCA/p4oASNV3MC+SYfM8M1XPTAFvdkrIbBpvedaf2bo/R14OVYUJLIfY4OH2Yu
         pEf9P8DdFwkE+qgtDeFG2EWaPRfrtb1IDT17OFFHnUjuDVMg3Aa4++8c795R5JfkMnkL
         qZbA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-disposition:mime-version:message-id:subject:cc:to:from:date
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=2vqJe8FMJ7YXAUkYmdnzd9LrkxX+Ew6d1z/lzoljRdQ=;
        b=yC6ZV47T9k+4zl1LC9AjcIcBiByrwgchI1JUFjUY1TqnJL5iIE/DpoXbLwCs9Y5jmF
         A1xcEhVURlqd9PvM14s90hR4Fb9OeOG2bWuGLF4f3lwkCX/akMbPxKgKugq7pe1YD0X6
         nrARCkNWC63R8MIra1wMmILa3al+jPacoM7F9ceXv/mF8tKortk6tBumKUw8tVi2rhrg
         ssW3M4aWRjxJxWGm7VU0489zUO1zPM8FkG4OUjdvYazpHwNKKJ6stxbKgg1mx385y1fq
         W2LdBaAC6hgb1fqyOM/PjhJ6C1ipehDgqf8YhO86nLE4SOyrHYBmKdMid3B+9dU0Rdhx
         xYpw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANoB5pmcNYpatGjzr4IYU8VUDKBjN/lvgma7+Hlunxy042CcunSz3CdZ
	qPMHOCfSbfpAw+HFb9FejY8=
X-Google-Smtp-Source: AA0mqf5OKr5JAnML0GC5r+4DtqmmRnar8ArkZ37/gDBecBgSWhRSL52WcOXNCgn2gWNqRlFPD7QkyQ==
X-Received: by 2002:a17:907:7782:b0:7b6:dd6d:b829 with SMTP id ky2-20020a170907778200b007b6dd6db829mr7480039ejc.602.1669131313470;
        Tue, 22 Nov 2022 07:35:13 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:d184:b0:7ad:9efd:4692 with SMTP id
 c4-20020a170906d18400b007ad9efd4692ls8137430ejz.4.-pod-prod-gmail; Tue, 22
 Nov 2022 07:35:12 -0800 (PST)
X-Received: by 2002:a17:907:778c:b0:7ad:79c0:4669 with SMTP id ky12-20020a170907778c00b007ad79c04669mr20840153ejc.395.1669131312060;
        Tue, 22 Nov 2022 07:35:12 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1669131312; cv=none;
        d=google.com; s=arc-20160816;
        b=QHscxCihk6xK0gRAML/RNbRjPu2sgv14/PSBsxKRhhnR8d/OwI5pYUqvq7KFyGqtyT
         mNhWJBUnnu/uRzNcjAmRET1wRSa1va8Ubh5G3w8eJS0UfjAXVnyvQEfYQjZjfjR/K4cg
         RHzTHg1WiNdSBdJuswf03fWAOJuRahWCfoiJi98E65oz7oIbhlH2qDZ7ZpjghVyJoWhU
         gTZqMHrEcZFd1TIRP5c++6YKq3odNYtk2QXI9Tt89FdNqPCKIvXxuhKdFAv25ApQj7HD
         IsBuFMs9liEF7YNa4W8XwQYul1a0hYcppK4Gpr9A1yanoobQ6H4Dg0HLNNmBsmtLtywz
         yvew==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-disposition:mime-version:message-id:subject:cc:to:from:date;
        bh=fDnT7JqXXZv6MsZA5D8dFeyNu2TPtZA6obJD/jbd9GE=;
        b=PoLP1PSIavVwGOx4TbADjI/G0mjdPbqUI6g5KsV92Mbi/SWmoqUA31u7OGZ0773SAa
         PW9g5gfCPGKcvUza+7LNKhSk/Ph7/qypolzHI98ofCkYvVnxQIBoSsPwW3XvwdNqz71l
         hR+RvYasruzUfRBJFDe7Qi1UrJ+/+G8kL/Z+aQF1+6uAqNUsoC/vlhqvnJR/jd7qMfJE
         DvOaaFtSKbjQVvDXoiiuFM+kolIEXKMCf0NwFuHxgC8HJXVR9IsWknDo/kCVG+NBpNfV
         2RveOrymnJibMFipLtflKndUQ4MhXB/E1dwNYQTrHDSChQb++Xwenk5UPpbB/szNgHJh
         HdDA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of breno.debian@gmail.com designates 209.85.218.53 as permitted sender) smtp.mailfrom=breno.debian@gmail.com
Received: from mail-ej1-f53.google.com (mail-ej1-f53.google.com. [209.85.218.53])
        by gmr-mx.google.com with ESMTPS id a5-20020aa7d905000000b00461ad0b1dc0si487139edr.3.2022.11.22.07.35.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 22 Nov 2022 07:35:12 -0800 (PST)
Received-SPF: pass (google.com: domain of breno.debian@gmail.com designates 209.85.218.53 as permitted sender) client-ip=209.85.218.53;
Received: by mail-ej1-f53.google.com with SMTP id me22so20080632ejb.8
        for <kasan-dev@googlegroups.com>; Tue, 22 Nov 2022 07:35:12 -0800 (PST)
X-Received: by 2002:a17:906:dfef:b0:7ae:db2:f10a with SMTP id lc15-20020a170906dfef00b007ae0db2f10amr5276708ejc.709.1669131311119;
        Tue, 22 Nov 2022 07:35:11 -0800 (PST)
Received: from gmail.com (fwdproxy-cln-004.fbsv.net. [2a03:2880:31ff:4::face:b00c])
        by smtp.gmail.com with ESMTPSA id w14-20020a056402070e00b004691de0e25bsm5296060edx.54.2022.11.22.07.35.10
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 22 Nov 2022 07:35:10 -0800 (PST)
Date: Tue, 22 Nov 2022 07:35:05 -0800
From: Breno Leitao <leitao@debian.org>
To: kasan-dev@googlegroups.com
Cc: leit@meta.com
Subject: swapper/0 stalling (RIP: kasan_check_range)
Message-ID: <Y3zsKcQC2T80A29e@gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
X-Original-Sender: leitao@debian.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of breno.debian@gmail.com designates 209.85.218.53 as
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

Hello,

I am trying KASAN on kernel 6.1-rc6, and I am getting a lot of CPU
stalls in the swapper/0, and RIP is pointing to the kasan_check_range()

This happens at boot time, and here are a few examples:

[   37.136063] rcu: INFO: rcu_sched self-detected stall on CPU
[   37.146062] rcu: 	26-....: (25921 ticks this GP) idle=96fc/1/0x4000000000000000 softirq=382/382 fqs=12577
[   37.166043] 	(t=26030 jiffies g=-699 q=458415 ncpus=52)
[   37.176062] CPU: 26 PID: 1 Comm: swapper/0 Not tainted 6.1.0_rc6_geb7081409f94 #1
[   37.192026] Hardware name: Quanta Delta Lake MP 29F0EMA0714/Delta Lake-Class1, BIOS F0E_3A15 12/27/2021
[   37.212026] RIP: 0010:kasan_check_range+0x43/0x2a0

and

[  141.928062] watchdog: BUG: soft lockup - CPU#28 stuck for 75s! [swapper/0:1]
[  141.942089] Modules linked in:
[  141.948061] irq event stamp: 606
[  141.954062] hardirqs last  enabled at (605): [<ffffffff82954e7f>] _raw_spin_unlock_irqrestore+0x8f/0x100
[  141.973026] hardirqs last disabled at (606): [<ffffffff82954c25>] _raw_spin_lock_irqsave+0x85/0xf0
[  141.991026] softirqs last  enabled at (358): [<ffffffff811545a0>] __irq_exit_rcu+0xe0/0x170
[  142.007054] softirqs last disabled at (351): [<ffffffff811545a0>] __irq_exit_rcu+0xe0/0x170
[  142.024063] CPU: 28 PID: 1 Comm: swapper/0 Tainted: G             L     6.1.0_rc6_geb7081409f94 #1
[  142.044060] Hardware name: Quanta Delta Lake MP 29F0EMA0714/Delta Lake-Class1, BIOS F0E_3A15 12/27/2021
[  142.063044] RIP: 0010:kasan_check_range+0x3/0x2a0

Full Log: https://paste.debian.net/1261524/

I am trying to understand how to read it.
PS: I am enabling other debug options as well, as lockdep, kmemleak,
etc.

Thank you
Breno

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Y3zsKcQC2T80A29e%40gmail.com.
