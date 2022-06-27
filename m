Return-Path: <kasan-dev+bncBAABBBUL42KQMGQEUAAFNYY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe3f.google.com (mail-vs1-xe3f.google.com [IPv6:2607:f8b0:4864:20::e3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 219DA55B91B
	for <lists+kasan-dev@lfdr.de>; Mon, 27 Jun 2022 12:25:12 +0200 (CEST)
Received: by mail-vs1-xe3f.google.com with SMTP id u11-20020a056102072b00b003542c71ba13sf524922vsg.0
        for <lists+kasan-dev@lfdr.de>; Mon, 27 Jun 2022 03:25:12 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1656325511; cv=pass;
        d=google.com; s=arc-20160816;
        b=vWsVtytY6BMqcQclaf7LBgK7ywnPcRr2bn+coNBIIoZCxUreWETPhb2gClP8C8VU2M
         uXyo8g+4VP5hR32Wzy4rxPgReAw/iuzQsVKfNlNGG0R3+FemazUuvh+k+OFLG8RHJFWf
         znVajWPXe7xgpmu2gDFDXKPDIvbM3TkMMaxQy3jGPx2NJd3QNUekd002LCRJPJfIUlJA
         DyQLZee2FY36+y5nMIu4PafHJd7noZqwhB1bIk/MgSaFxVFGRR4VUmliHU2yxKI3p3Hh
         76aMB3MXwX3LlArlF+e33/xTjVM76RLQaTm3Rf105xPuE0iiWYrTj2Xryf5A6+mUIpjK
         q+Sg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=qJ6k0x+YFvHccXUjgnpkq5eIxciKczjjjC8NQWqAR1A=;
        b=EFKSpnnahwA/lNKl6OvGHq8s++KV2nkIuXb66aMEZcnmGaQPu68Ya3GUlZAaVqoDKF
         F9XJfFAf+mV+X3mLyJugo8GNVICgLW+i7Qm56B6qAodfMV10iE8tm6ULIUBai+IKDZ10
         sDzed+hW3ZyuqZFi8/pLb/QZT9D5pjnI4OAual7j2YPuJMJraeQUE7S7e43/PQDkVGzr
         43MQHllILSexLL4/C08M44ZGkUjK1BdXNmcXPmqsBS/ggK7E395mLhco/kjd8/GJCHsy
         L6xtCtKJY0jMBcYQMNiWOlEQxgXazvKa9S8PhTxfYtgRrDvL19vnVp3vFrXovzmnkPzD
         kkAQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=KSFNMvNW;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=qJ6k0x+YFvHccXUjgnpkq5eIxciKczjjjC8NQWqAR1A=;
        b=Rk7UF4hg4TvtumX0zZPO4Of4cIKwZAm8y9STkbf84s9qQEVHnQLZN74pzFowfVN9BA
         PRu7QDFmTwAfp1xRuYLZvuTbjkwfYYnjCrcb2ei6PeozYf9VddhGspufuBlsnxH1hxYH
         3X8NT5imti8QJt6ohl1CxftyZtzu8DDLRricD2yzA6LqT77ORp5MBXUyGrWpYVo834dB
         QWSWKIKjSknaEoyZrMYjIoWIvu/3R9yBnrm/JIyVX8Iz26O4vcwlJ/XbX43dbr6zkBdu
         lPc02+ImMQoejmDnb8AoUWj603eszOXHSmWwr/hwWd3IJD75Os26kfSlzXwXj+ce3H5n
         sf8Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=qJ6k0x+YFvHccXUjgnpkq5eIxciKczjjjC8NQWqAR1A=;
        b=TDCJWqdSQosK0Rz8qHOvJmkitBrRDEegCmnUMNdwEwWjaiIZgLaVlY5r+88+PSNPKA
         fxLP7JrbC6VqE2r5R3YjbAbLxTpfCw0Dc/IZrsD2rdzz5mE2MfZnDoj+aOR16NV4FaCs
         Y98yhzhdcWlfzISmnLt8KfSxNffpEI2ti4ThSdEnX5Hl3S61qy4gzYdXJZQSHhUq3FQs
         hshOJ+DKhEVzHHwurNciTpvi6EUHTst/PSXYsUJb+z83nGr0Rj1ZhhjJXlcVlnnvnYLY
         oLwr4leFd7vDomzflayszaWN2Agz2p4hsWCv48x9eC5UXok4cLqqDuiH0TMUbKr2KtRI
         5M/Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AJIora9gK9aqKryydjL/OPHDYXTfwdBPhnhMW0oya2gpkZw6P6P5cQF1
	LcXFBdV5WTlT/VLLcRjGI18=
X-Google-Smtp-Source: AGRyM1uv2nnyMuJuuaaaxF/j0Zen+ZZi1T+77hC5svHOhhneAIYmD8yM85Ujc94eaXTLRt66hK4zDw==
X-Received: by 2002:ab0:482b:0:b0:37f:10e3:54e0 with SMTP id b40-20020ab0482b000000b0037f10e354e0mr4076385uad.2.1656325511052;
        Mon, 27 Jun 2022 03:25:11 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1f:f8c9:0:b0:36c:572e:1b99 with SMTP id w192-20020a1ff8c9000000b0036c572e1b99ls1502154vkh.7.gmail;
 Mon, 27 Jun 2022 03:25:10 -0700 (PDT)
X-Received: by 2002:a05:6122:c6f:b0:36b:fa5c:7dba with SMTP id i47-20020a0561220c6f00b0036bfa5c7dbamr3907160vkr.19.1656325510609;
        Mon, 27 Jun 2022 03:25:10 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1656325510; cv=none;
        d=google.com; s=arc-20160816;
        b=ljqDvIDCUz93kl/gSwCG9Gz9AVbaK4NVDpR6i0pR8qeBHB3KlI4kckbj71aOMKErGZ
         ZwWDTgFke9N2IogZ3psgvM3Tg3boSgVx6AoNLDiy2ARL/SQueOp0+csE33Cc8hDSDpjA
         oNj3COnVe/7h5SvF1otrUBhZE2Dc1TcMLwR6Yf9e0JdWVKRzJM34rJu2lHB4RoN7ieJ8
         PgJAxuOXFqNCBOEMteORjWfIlX0P7g2r/kB7kHJsHjA7nmvYWD0lAqtnsO37vpLlmRnI
         c/6ryRCvc1Vui73EjH+RTUs4yjUjgAZ9u+Lnz9TSYUM1Tc9dBwnn7gb4XTG0JB3nm+F7
         gn1Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=sAg9O/dWiRxv/4oXwq2Xypj/IawCCz+4gFn8O2pXPMc=;
        b=Q2MMPVEACtz9FNBE3bxMReOXhdQBOgkDOOnZo2qtq/qO0FJRtBPWzXhig2j1L//FpM
         AnBtdt3ZVLx7SWzNs8MTi7KQ26AdJusPmXBG3UQIDuXiGpRhZSJeSh66nW/tFS3AnfOw
         /ezE8vTK/IsLl7E/bGNfNi32eSbEoU6ZfGMO/a03OyvHFoGx0vZ+8KAYTCZUVl1qtmDF
         JsoHwgciC28AAjaMJe1yasM0J51GVEuAkB/cbCaNe9w5hXYaV31StMSO0XbsBLw4PQzI
         e/C8sPNPtNvXzldd8pGaZ/HpTAtuUtyTWL1ZZIWf/FKOcHhK1oGVuDMXG8G2HeTfd0lD
         a3QA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=KSFNMvNW;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id p65-20020a1fa644000000b003700a12ecbcsi138166vke.5.2022.06.27.03.25.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 27 Jun 2022 03:25:10 -0700 (PDT)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id 194B5611E6
	for <kasan-dev@googlegroups.com>; Mon, 27 Jun 2022 10:25:10 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id 7D3ADC385A2
	for <kasan-dev@googlegroups.com>; Mon, 27 Jun 2022 10:25:09 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id 5ED40CC13B3; Mon, 27 Jun 2022 10:25:09 +0000 (UTC)
From: bugzilla-daemon@kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 216180] KASAN: some memset's are not intercepted
Date: Mon, 27 Jun 2022 10:25:09 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Sanitizers
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: enhancement
X-Bugzilla-Who: glider@google.com
X-Bugzilla-Status: NEW
X-Bugzilla-Resolution: 
X-Bugzilla-Priority: P1
X-Bugzilla-Assigned-To: mm_sanitizers@kernel-bugs.kernel.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: 
Message-ID: <bug-216180-199747-RBVNAv0Kgd@https.bugzilla.kernel.org/>
In-Reply-To: <bug-216180-199747@https.bugzilla.kernel.org/>
References: <bug-216180-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=KSFNMvNW;       spf=pass
 (google.com: domain of bugzilla-daemon@kernel.org designates
 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
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

https://bugzilla.kernel.org/show_bug.cgi?id=216180

--- Comment #3 from Alexander Potapenko (glider@google.com) ---
> Does KASAN interceptor tail-call memset_erms in this build?

It calls __memset:

ffffffff81c68d30 <memset>:
ffffffff81c68d30:       41 55                   push   %r13
ffffffff81c68d32:       41 89 f5                mov    %esi,%r13d
ffffffff81c68d35:       41 54                   push   %r12
ffffffff81c68d37:       49 89 d4                mov    %rdx,%r12
ffffffff81c68d3a:       ba 01 00 00 00          mov    $0x1,%edx
ffffffff81c68d3f:       55                      push   %rbp
ffffffff81c68d40:       48 8b 4c 24 18          mov    0x18(%rsp),%rcx
ffffffff81c68d45:       4c 89 e6                mov    %r12,%rsi
ffffffff81c68d48:       48 89 fd                mov    %rdi,%rbp
ffffffff81c68d4b:       e8 30 f8 ff ff          call   ffffffff81c68580
<kasan_check_range>
ffffffff81c68d50:       84 c0                   test   %al,%al
ffffffff81c68d52:       74 13                   je     ffffffff81c68d67
<memset+0x37>
ffffffff81c68d54:       4c 89 e2                mov    %r12,%rdx
ffffffff81c68d57:       44 89 ee                mov    %r13d,%esi
ffffffff81c68d5a:       48 89 ef                mov    %rbp,%rdi
ffffffff81c68d5d:       5d                      pop    %rbp
ffffffff81c68d5e:       41 5c                   pop    %r12
ffffffff81c68d60:       41 5d                   pop    %r13
ffffffff81c68d62:       e9 79 81 5b 02          jmp    ffffffff84220ee0
<__memset>
ffffffff81c68d67:       5d                      pop    %rbp
ffffffff81c68d68:       31 c0                   xor    %eax,%eax
ffffffff81c68d6a:       41 5c                   pop    %r12
ffffffff81c68d6c:       41 5d                   pop    %r13
ffffffff81c68d6e:       c3                      ret    
ffffffff81c68d6f:       90                      nop


, which uses an ALTERNATIVE_2 to switch between memset_orig() and
memset_erms():
https://elixir.bootlin.com/linux/latest/source/arch/x86/lib/memset_64.S#L27

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-216180-199747-RBVNAv0Kgd%40https.bugzilla.kernel.org/.
