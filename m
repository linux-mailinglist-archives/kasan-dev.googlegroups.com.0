Return-Path: <kasan-dev+bncBDA5JVXUX4ERBEXDQTFAMGQERLDFNFQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53e.google.com (mail-ed1-x53e.google.com [IPv6:2a00:1450:4864:20::53e])
	by mail.lfdr.de (Postfix) with ESMTPS id 78665CC1EE8
	for <lists+kasan-dev@lfdr.de>; Tue, 16 Dec 2025 11:16:51 +0100 (CET)
Received: by mail-ed1-x53e.google.com with SMTP id 4fb4d7f45d1cf-6495bf3d674sf567320a12.3
        for <lists+kasan-dev@lfdr.de>; Tue, 16 Dec 2025 02:16:51 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1765880211; cv=pass;
        d=google.com; s=arc-20240605;
        b=Tz73K44H4Z8CCN53ESs/kO2knveWPRezjstX6m9jgV7sy2F2Y2QxLdMUQoSsLf7z3D
         t9ck5m+CpfRIzOhr/8hesfa06ebdAF8/4tDaM+6I75Sfh8HE5pTiSl6ktIcyY1Dxwjia
         nRz0JPkLpaQVjXR4Q0+wEdR+097NGitzH5dL9QZsHnYwNVME8joVq54wQmAQaQDckxnT
         ng6r9h//ZkO/8xuKEOzPLQJ6yw5FDaJIB5uYgDfWt8DQRFnobRGwbhNEQ9R3agv9yK6Y
         ThF5nk0/+Jw/E9gIMBFpEs5GQ4BTZN6dSMY7UjXlUWfqS7glEY1qVfolSZ0yv0lw0HiD
         9PFA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=ZyUWCyWeQbXaWH+r8llSARqkPzxo76z6n2sS7sSUyi4=;
        fh=vGOOAcBdTHXSlHHHMwOFnEb4xp2zDEoOG0/NBZNhnDQ=;
        b=ATmPf+aSOHYHTYwUcxZ0ayqaFihOAu7LBxtgszH+5ae4U4mp74a+N4kHlzHn9RqPMN
         aKWKz6Jl6tcnK1VbBY0n+13mKQJyW4COvkeXqUIyp8+7KCOJ2gGmjv/oI+xlf5iBRKqB
         tw48F8gEAH/IOCz7VK9PcYdBwrQ20Zo0nlfsdAQOgYUJGvyXhOLM8zXhpUvohqShidqm
         yiaeAHhwesXTGInxov6pMG23MSlMFgoTQFwFLy4A+JLIXO5o2ikf4TSsjZEh3Numobpv
         vS+3eZY8qehLux9FKiK1HcQjbMUmTuLDPivbEkGl9VlDqkeX9exiOh6d7wlzs781O6vW
         bC2g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=yll42igO;
       spf=pass (google.com: domain of 3jzfbaqgkcugtkmuwkxlqyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--jackmanb.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3jzFBaQgKCUgtkmuwkxlqyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--jackmanb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1765880211; x=1766485011; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=ZyUWCyWeQbXaWH+r8llSARqkPzxo76z6n2sS7sSUyi4=;
        b=MIICKO/W/AMMFRqhmSqmBCVuKU+5BwvxprPVvcBz0egHrmX2Zgd93itP0L08pzJ8Td
         4ATv6hfGkg+OmAFLvtco+zPBsf4afdvUXPl/UoSAkhEtP8RYbU//XKaLXP18x4Xp7SM2
         I/D1ls61F1NxfEMAOgeRBEn3KPeqHOHS2Pnc9wDySHaEdiiCK4RLuLjInqv0P1phWwXu
         TyabDlIyXIM2y13pA91x0+cSIH7IRtVbWb+tpKnR6Pm0+5yUwMTNDdNLZ4+adfDvzEJB
         v3BkWTZlZtvv/EB6EhNhgGcINxPVM2m/gJ/Yy4c9gdoCy6FnseByH3ozAO85GjMA2KIm
         YiDw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1765880211; x=1766485011;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=ZyUWCyWeQbXaWH+r8llSARqkPzxo76z6n2sS7sSUyi4=;
        b=qw5k2nQBf5btQJYy50we94Fr68pNs3jVY2ibv9j1zQa8wMSF5XPri+ZYRV01+BMJGO
         vRdUcj8+/Ls9Xf5OCGAWlCUxIKLjzgL4gBve4f1n+lQRvj6bq8N0oGgEeqxlsTdV3Bv2
         dqSGOOy6oQSzAgeVs47z81Yx+TlnsQ3XUXd/yLyqDoC4ITiN2yUSBjQ7+s4/7UdRv2VB
         r5iVbX0dwob7lRkmd766RWFAGkKUn8E+xy4uRgasCpRtTrwQpNkDIlOqGsJyoESiZlkm
         RiiyDip/i+fQKBqkMc2U4eZxILVMWccwwmjQmqIdEjfKZME5tSnLGURsb3CHS+giO00E
         V+rg==
X-Forwarded-Encrypted: i=2; AJvYcCUT1tCP0JaZF1/0aoX0uhYBOfAqbJ/zrHb8MURP23zOwZOI4nI+Avp992tryXhNsMOQS1jhCw==@lfdr.de
X-Gm-Message-State: AOJu0Yzr5CsfONz1D3U1KCf+wSlVrFjavKfpJ622GyEXmw9Y5fY4kgnJ
	V2a4ODcSO0iBkSbKxsFLjBJOjTSYi9ABluwyyrqD77wO+grNcSx6z+pS
X-Google-Smtp-Source: AGHT+IEIxZuvnt6m5mTFYpct7a1SObKt53JErppHBG7JrhEzOd9pQsqs2RNxkLNDO/QHobswxdKcAg==
X-Received: by 2002:a05:6402:50d0:b0:645:ed64:963e with SMTP id 4fb4d7f45d1cf-6499b17e3c4mr7760832a12.1.1765880210610;
        Tue, 16 Dec 2025 02:16:50 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWY1SleBMJZVH/V+8SS/UyYKHsCKt6EnplpuKF0G6AfPGg=="
Received: by 2002:aa7:d742:0:b0:641:68af:a582 with SMTP id 4fb4d7f45d1cf-6499a46cf01ls3850257a12.2.-pod-prod-02-eu;
 Tue, 16 Dec 2025 02:16:48 -0800 (PST)
X-Received: by 2002:a17:907:b022:b0:b7f:f862:df26 with SMTP id a640c23a62f3a-b7ff862e2f0mr80817566b.14.1765880208016;
        Tue, 16 Dec 2025 02:16:48 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1765880208; cv=none;
        d=google.com; s=arc-20240605;
        b=LCg1jKuLOxxehnqYs4XWK9n09FpX/qhP707uGE9kl0zW2amAONP3GqDDNH4W85JDio
         EnRNBtTA85uUIRku4p6az4gOkNAuigl+6Dz0h12fEvCFJ+meXJCCHyZqyFn3NNwvdyyz
         GnK32QjTxaeKH4DYIJKz+9xtG0jBai/TDzI+tY3IEac7r1TLPt1cXv42vZCxTaKwlYmD
         3+P+a8dVTiJSruJ+6ypHc4h0eBd4UWKCEJor5g2nKpypuWK2ZL0VYExTVHTE9CNP9HGI
         Tw99Yb7+gkECRwVlCnmLtwkIY+s2b14O7ieOsMOF7Zitd2rVKHFZZEFBX2kNk6IS9C1s
         2Czg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=eBg82DgwaEqXYt7FN7z5QKnLiVSgwPtdomNA9XrlWso=;
        fh=x2ubLsttaGNDEohungEU+QxSNGIjpxcBkXhQGHGw3fc=;
        b=HCYDkrvbhf4scDUUVkXp3ebsWom+h6TEwK/7YuzN3rAabtxOJIsyMUM3qBL44OZZ2V
         w12+AeRf1kbpNgeHXZOI1BYVe64+qJmgEOJEkLEcqtXQDyJF72vmFR0F4Ot9oVPaPWi8
         QbTAfNS5Dl6JZI84slBp845dlDm1w5Y+x94gwu6TFWA8DD8DQTGnLDjPUFmy95SUiTP9
         M7t9DOkxy2P9/t4ZqtiU/I0ktzIR8ztMa5EFM6hUsuqI6a++GVT8nlfttBvYS6D2KBtl
         +xG3wSuC12EKm+zmzv7Ahds/q9pChhzQVQIhV/RfhTfz+DMX0KidXsD1TvBoFp6/u6E/
         kg1A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=yll42igO;
       spf=pass (google.com: domain of 3jzfbaqgkcugtkmuwkxlqyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--jackmanb.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3jzFBaQgKCUgtkmuwkxlqyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--jackmanb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x349.google.com (mail-wm1-x349.google.com. [2a00:1450:4864:20::349])
        by gmr-mx.google.com with ESMTPS id a640c23a62f3a-b7cf9f386d6si18891266b.0.2025.12.16.02.16.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 16 Dec 2025 02:16:48 -0800 (PST)
Received-SPF: pass (google.com: domain of 3jzfbaqgkcugtkmuwkxlqyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--jackmanb.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) client-ip=2a00:1450:4864:20::349;
Received: by mail-wm1-x349.google.com with SMTP id 5b1f17b1804b1-4779edba8f3so30791465e9.3
        for <kasan-dev@googlegroups.com>; Tue, 16 Dec 2025 02:16:47 -0800 (PST)
X-Received: from wmbju24.prod.google.com ([2002:a05:600c:56d8:b0:477:7aa2:99cb])
 (user=jackmanb job=prod-delivery.src-stubby-dispatcher) by
 2002:a05:600d:6405:20b0:47a:935f:618e with SMTP id 5b1f17b1804b1-47a935f64d7mr109743655e9.15.1765880207747;
 Tue, 16 Dec 2025 02:16:47 -0800 (PST)
Date: Tue, 16 Dec 2025 10:16:36 +0000
In-Reply-To: <20251216-gcov-inline-noinstr-v3-0-10244d154451@google.com>
Mime-Version: 1.0
References: <20251216-gcov-inline-noinstr-v3-0-10244d154451@google.com>
X-Mailer: b4 0.14.2
Message-ID: <20251216-gcov-inline-noinstr-v3-3-10244d154451@google.com>
Subject: [PATCH v3 3/3] x86/sev: Disable GCOV on noinstr object
From: "'Brendan Jackman' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Marco Elver <elver@google.com>, 
	Ard Biesheuvel <ardb@kernel.org>, Andrew Morton <akpm@linux-foundation.org>, 
	Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>, 
	Dave Hansen <dave.hansen@linux.intel.com>, x86@kernel.org, 
	"H. Peter Anvin" <hpa@zytor.com>, Nathan Chancellor <nathan@kernel.org>, 
	Nick Desaulniers <nick.desaulniers+lkml@gmail.com>, Bill Wendling <morbo@google.com>, 
	Justin Stitt <justinstitt@google.com>
Cc: kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	llvm@lists.linux.dev, Brendan Jackman <jackmanb@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: jackmanb@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=yll42igO;       spf=pass
 (google.com: domain of 3jzfbaqgkcugtkmuwkxlqyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--jackmanb.bounces.google.com
 designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3jzFBaQgKCUgtkmuwkxlqyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--jackmanb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
X-Original-From: Brendan Jackman <jackmanb@google.com>
Reply-To: Brendan Jackman <jackmanb@google.com>
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

With Debian clang version 19.1.7 (3+build5) there are calls to
kasan_check_write() from __sev_es_nmi_complete, which violates noinstr.
Fix it by disabling GCOV for the noinstr object, as has been done for
previous such instrumentation issues.

Note that this file already disables __SANITIZE_ADDRESS__ and
__SANITIZE_THREAD__, thus calls like kasan_check_write() ought to be
nops regardless of GCOV. This has been fixed in other patches. However,
to avoid any other accidental instrumentation showing up, (and since, in
principle GCOV is instrumentation and hence should be disabled for
noinstr code anyway), disable GCOV overall as well.

Signed-off-by: Brendan Jackman <jackmanb@google.com>
---
 arch/x86/coco/sev/Makefile | 2 ++
 1 file changed, 2 insertions(+)

diff --git a/arch/x86/coco/sev/Makefile b/arch/x86/coco/sev/Makefile
index 3b8ae214a6a64de6bb208eb3b7c8bf12007ccc2c..b2e9ec2f69014fa3507d40c6c266f1b74d634fcb 100644
--- a/arch/x86/coco/sev/Makefile
+++ b/arch/x86/coco/sev/Makefile
@@ -8,3 +8,5 @@ UBSAN_SANITIZE_noinstr.o	:= n
 # GCC may fail to respect __no_sanitize_address or __no_kcsan when inlining
 KASAN_SANITIZE_noinstr.o	:= n
 KCSAN_SANITIZE_noinstr.o	:= n
+
+GCOV_PROFILE_noinstr.o		:= n

-- 
2.50.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251216-gcov-inline-noinstr-v3-3-10244d154451%40google.com.
