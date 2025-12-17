Return-Path: <kasan-dev+bncBDA5JVXUX4ERBYHLRLFAMGQE56NZBDA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33d.google.com (mail-wm1-x33d.google.com [IPv6:2a00:1450:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id ECD13CC7FC3
	for <lists+kasan-dev@lfdr.de>; Wed, 17 Dec 2025 14:53:37 +0100 (CET)
Received: by mail-wm1-x33d.google.com with SMTP id 5b1f17b1804b1-4779ecc3cc8sf40110905e9.3
        for <lists+kasan-dev@lfdr.de>; Wed, 17 Dec 2025 05:53:37 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1765979617; cv=pass;
        d=google.com; s=arc-20240605;
        b=bzyVCS8yvgKd1COjgfGLfpIEtaZEHDRtq2GYWcL7hgZW1Lc+jCfTjwsPDQMf7B7t4J
         RYoVjJK/G3q2LTZPtqYf8Mwk2do6T7PdEIzcdh1k22SUfokD+0/itELD5oU2HENKAPyW
         WU3IW0nGnKDUJsROgDrDH50gKCkmkby6WfI6PnDx1OShL7nfUxopAZcI+GPSSadXho9X
         0iPY3DU88gc6n+HFAA+vq+VqiSSB3dJv+9yrO9lLMpgpGHEH0Z5TnzUkcK1bce7wROOb
         rOCW3+pCFmONoT19ICSIuQmKl8uYJDB1geiWx9uZWvI4GizXucWuShiwP51kyde+aQdH
         x7Mg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=JTF99WNeB3VMUPuH7x6jKS4YHYZMTtL1olNAYk+WGIs=;
        fh=mQirXIvvimpB0hzgLr0GlKl+28pMIAGHMc9TRmwvR/I=;
        b=eHttlzZK5p+Gfjk2nvTt+2G19u0XIc2X+lXoKZ+qeKSrPnQy1xx8BPIzFHHNAjlECB
         uKnCzxxqAJfch7orA7Xx/4yaIHRYt5qTlOSJ+YGXId597L4DxCyN4T71C2Jk4gyJTgP1
         +wzx2lpRa1r3HDpqT8epfeff58a8Q2xbkXSQSTpKhnrDoCBAUW6OYFBxq8jzcDoBmLlF
         WAnz5p+gZ8dWnB2+AE248TEkqZLnbCB1wpbJWjRH5ik07mCn3q4D4DLlAfgPOkXNAITi
         ycYaif0aqFroTDYrU/IzuVXL/PBCpMyuZ7gSlbOYNKVtnYZDezC3QkMtA8I1A2Ky1+VT
         ii6A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=QVDAboF5;
       spf=pass (google.com: domain of 33rvcaqgkcauofhprfsglttlqj.htrpfxfs-ijalttlqjlwtzux.htr@flex--jackmanb.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=33rVCaQgKCaUOFHPRFSGLTTLQJ.HTRPFXFS-IJaLTTLQJLWTZUX.HTR@flex--jackmanb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1765979617; x=1766584417; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=JTF99WNeB3VMUPuH7x6jKS4YHYZMTtL1olNAYk+WGIs=;
        b=bkS+CmT8379Au3gJfj3697WAvlBvkbpMl1TbE/PutMY1iXDkSKu4eXXz2Oh2w/mzPA
         S2zeTva0NkfugfGo5KUFEGWd/YRH56isPDvqLzgQD5I46fFlFO5wq7h92MpbjpjWF2UW
         mLCuDTOrfeudv3xLwxmgCEGWlDEousS4cDid/I0jq3gB8E+R2AWPArrrdEzbM/0WTcW1
         +5UsoIymVo0JAHRX3gVpk/RZu88LwUv/qX8rf7F+JI7xUhtaKyL+OY/MPiBqTPpfW8Rr
         SX1F86xzZo0/gqKIwE7IYtlWmUY0naRaCPni83AiB2WCG1sZXwo5m2xmNh1nBe4f0iHQ
         nA5Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1765979617; x=1766584417;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=JTF99WNeB3VMUPuH7x6jKS4YHYZMTtL1olNAYk+WGIs=;
        b=T0G3QnhCzeBDrl9zEukdD/6gLONyAeZv+sjQ14xeQh+N+WRSNpXx5jqhq+8OVgkfEF
         dadnFlhazuyh7oJ0KZU8OpJe6W/H9RtvTZsrDWr1Sn1j6Vl7PjBjPvpWo/RGmCJEx1hi
         3WAjpqIZ304eGSM1itJO2Cz3os89FeSd1bYRrxmJM39D1IZznUMbwtQdYZIiUe+KHxik
         NM1IfeaxBsC0vaOzm5EgZMhodmtgQooHXLdcc/uQMginRsenr4zBwdpXOuD6WMwP1wbT
         jLcUf0tCgBE7s3j6nMl6MFHMvgakcBY/TKtK24XMkLWSnBCE6wn9GciCYucDVncKl5yW
         s5MA==
X-Forwarded-Encrypted: i=2; AJvYcCXO8ceHZDjqsSxfbnA99iyP4pfxwAmaPyTo/pgfy+haY31l/c4BJb+JoQsFP7iwTSA/3V+6WA==@lfdr.de
X-Gm-Message-State: AOJu0YypRYtycfhqt6UkJqZPjUmthjI827mb4ZeTLXvlV1QhSxkqLI/p
	BAQ8B5d2qX5qk1iebUioFcwk3gpYSRWEE1mTlVeC4wd8kAOqELU3zh+l
X-Google-Smtp-Source: AGHT+IECsdzt0ey50Kyxo87lU9uu5JCYGTtcksPy55sn1BMCDUzZX+x569KuAsyBHSn2e4MSp6umOQ==
X-Received: by 2002:a05:600c:a31a:b0:47a:9165:efc4 with SMTP id 5b1f17b1804b1-47a9165f157mr157501625e9.33.1765979617246;
        Wed, 17 Dec 2025 05:53:37 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWa3Ha7USfPk8pqojZM52IUxynFn8C0Y4SSIt+22vSbcgw=="
Received: by 2002:a05:600c:3ba8:b0:477:a2eb:9a0a with SMTP id
 5b1f17b1804b1-47a8ec5c4aals19054405e9.1.-pod-prod-07-eu; Wed, 17 Dec 2025
 05:53:34 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXli2MrEmV2MVBUcbg2gGTQMdsr9wTmLAtJhQ7Zz8v2T4nLBusp/khsQyDyhQAOumRhDlER6smNmxM=@googlegroups.com
X-Received: by 2002:a05:600c:3b05:b0:477:7bca:8b34 with SMTP id 5b1f17b1804b1-47a8f8ab546mr189928245e9.6.1765979614572;
        Wed, 17 Dec 2025 05:53:34 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1765979614; cv=none;
        d=google.com; s=arc-20240605;
        b=hsCMhLxzgZXPBooZYZVqEL9kcZEEoWo7C2iRHvb8uUxWSw5DflVI3eAgWNNMuTYtTB
         sgcFSA7zkGyUIahz/VhGjGkgElKStaOcOAVA115Y09kFV/dBx07QdxJg69rQ8b5z1tCZ
         +Q2TlCDZambmrBDXuCKTm/5uyvyJhetJq40EVsY9vtROkZ1u+U9mds4jCAciAi9CiDaC
         gsviB56T2E0ed7Gxt9gnXygvhTDhA7+RmQbdJ3oOSBzyOktWH8UdG0+heCQ4yqNh/fZs
         QJ/5ayGN3hz9zhXxXJEXOLcyHg1qsDFcW0xG2iIRhohSAOHNOHcSVrLj2GspcIYlZL2I
         RV0w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=GwYQjUeDdM5Nle1IpM5e5V1FvMRCYFAI0uCKIrSa2SQ=;
        fh=8tS1NZwyuf37U2a/jx0f5coy7Mr5G78gn1uXQrZAmPs=;
        b=lM2bPzmRWug5MHWcvuIgwNn4Y7P8CBYsNhFTXf13yz+g4z9IaIEvwlEavOfKk2Afk/
         ThjUY1GC3SXDC3bCsvCjca0Swkef+KLRnMfavbV/LQmbOXe/NnwQLn7PJgp2dAM4JS5d
         yuALYRin62CpjytySltZBbwHH7BIH4DZrA8LpvfUjLsMap48tGnsWplglyBFBH0PH9gE
         Z9yVzGUkWvKn1JPTSE9FOBT54bZ5Jo4ZUZzbbys9qRX3IAJvRkUmZ/qFKHFXPyW64KOd
         GmOFqaBxz8dtgpiGyFO1N4aROJPYJxHuCeHS8EgtQ9rDGWCDzYhg5vh9ML0kQXJDHgtJ
         Vglg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=QVDAboF5;
       spf=pass (google.com: domain of 33rvcaqgkcauofhprfsglttlqj.htrpfxfs-ijalttlqjlwtzux.htr@flex--jackmanb.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=33rVCaQgKCaUOFHPRFSGLTTLQJ.HTRPFXFS-IJaLTTLQJLWTZUX.HTR@flex--jackmanb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x34a.google.com (mail-wm1-x34a.google.com. [2a00:1450:4864:20::34a])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-47bd8f29f8asi525575e9.1.2025.12.17.05.53.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 17 Dec 2025 05:53:34 -0800 (PST)
Received-SPF: pass (google.com: domain of 33rvcaqgkcauofhprfsglttlqj.htrpfxfs-ijalttlqjlwtzux.htr@flex--jackmanb.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) client-ip=2a00:1450:4864:20::34a;
Received: by mail-wm1-x34a.google.com with SMTP id 5b1f17b1804b1-4779b432aecso31669515e9.0
        for <kasan-dev@googlegroups.com>; Wed, 17 Dec 2025 05:53:34 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCWtG5Ge+Vx4dKOmQlZSa10W/HMq/eFKjN6HlRFQC0MapSmPfKbOmxUJ2WAPoCybm+AGyVZ5Gv8djtw=@googlegroups.com
X-Received: from wmgp21.prod.google.com ([2002:a05:600c:2055:b0:477:afa:d217])
 (user=jackmanb job=prod-delivery.src-stubby-dispatcher) by
 2002:a05:600c:4f90:b0:477:b0b8:4dd0 with SMTP id 5b1f17b1804b1-47a8f905680mr190102895e9.17.1765979614010;
 Wed, 17 Dec 2025 05:53:34 -0800 (PST)
Date: Wed, 17 Dec 2025 13:53:33 +0000
In-Reply-To: <20251216130155.GD3707891@noisy.programming.kicks-ass.net>
Mime-Version: 1.0
References: <20251216-gcov-inline-noinstr-v3-0-10244d154451@google.com>
 <20251216-gcov-inline-noinstr-v3-1-10244d154451@google.com> <20251216130155.GD3707891@noisy.programming.kicks-ass.net>
X-Mailer: aerc 0.21.0
Message-ID: <DF0JIYFQGFCP.9RDI8V58PFNH@google.com>
Subject: Re: [PATCH v3 1/3] kasan: mark !__SANITIZE_ADDRESS__ stubs __always_inline
From: "'Brendan Jackman' via kasan-dev" <kasan-dev@googlegroups.com>
To: Peter Zijlstra <peterz@infradead.org>, Brendan Jackman <jackmanb@google.com>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Marco Elver <elver@google.com>, 
	Ard Biesheuvel <ardb@kernel.org>, Andrew Morton <akpm@linux-foundation.org>, 
	Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>, 
	Dave Hansen <dave.hansen@linux.intel.com>, <x86@kernel.org>, 
	"H. Peter Anvin" <hpa@zytor.com>, Nathan Chancellor <nathan@kernel.org>, 
	Nick Desaulniers <nick.desaulniers+lkml@gmail.com>, Bill Wendling <morbo@google.com>, 
	Justin Stitt <justinstitt@google.com>, <kasan-dev@googlegroups.com>, 
	<linux-kernel@vger.kernel.org>, <llvm@lists.linux.dev>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: jackmanb@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=QVDAboF5;       spf=pass
 (google.com: domain of 33rvcaqgkcauofhprfsglttlqj.htrpfxfs-ijalttlqjlwtzux.htr@flex--jackmanb.bounces.google.com
 designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=33rVCaQgKCaUOFHPRFSGLTTLQJ.HTRPFXFS-IJaLTTLQJLWTZUX.HTR@flex--jackmanb.bounces.google.com;
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

On Tue Dec 16, 2025 at 1:01 PM UTC, Peter Zijlstra wrote:
> On Tue, Dec 16, 2025 at 10:16:34AM +0000, Brendan Jackman wrote:
>> The x86 instrumented bitops in
>> include/asm-generic/bitops/instrumented-non-atomic.h are
>> KASAN-instrumented via explicit calls to instrument_* functions from
>> include/linux/instrumented.h.
>> 
>> This bitops are used from noinstr code in __sev_es_nmi_complete(). This
>> code avoids noinstr violations by disabling __SANITIZE_ADDRESS__ etc for
>> the compilation unit.
>
> Yeah, so don't do that? That's why we use raw_atomic_*() in things like
> smp_text_poke_int3_handler().

Right, this was what Ard suggested in [0]:

> For the short term, we could avoid this by using arch___set_bit()
> directly in the SEV code that triggers this issue today. But for the
> longer term, we should get write of those explicit calls to
> instrumentation intrinsics, as this is fundamentally incompatible with
> per-function overrides.

But, I think the longer term solution is actually now coming from what
Marco described in [1].

So in the meantime what's the cleanest fix? Going straight to the arch_*
calls from SEV seems pretty yucky in its own right. Adding special
un-instrumented wrappers in bitops.h seems overblown for a temporary
workaround. Meanwhile, disabling __SANITIZE_ADDRESS__ is something the
SEV code already relies on as a workaround, so if we can just make that
workaround work for this case too, it seems like a reasonable way
forward?

Anyway, I don't feel too strongly about this, I'm only pushing back
for the sake of hysteresis since I already flipflopped a couple of times
on this fix. If Ard/Marco agree with just using the arch_ functions
directly I'd be fine with that.

And in the meantime, I guess patch 3/3 is OK? As it happens, that will
already make the current error go away without needing the first 2
patches. So maybe we should just merge that and be done with it? There's
probably a good chance no other issues will show up between now and
whenever Marco's nice compiler support arrives.

[0] https://lore.kernel.org/all/CAMj1kXHiA91hH80tHFCO9QjkkfzEGZ2GJgpHnuKrusKhOULMXA@mail.gmail.com/
[1] https://lore.kernel.org/all/CANpmjNNc9vRJbD2e5DPPR8SWNSYa=MqTzniARp4UWKBUEdhh_Q@mail.gmail.com/

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/DF0JIYFQGFCP.9RDI8V58PFNH%40google.com.
