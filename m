Return-Path: <kasan-dev+bncBDX4HWEMTEBRBMMT3P4QKGQEFJL2DNQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x237.google.com (mail-oi1-x237.google.com [IPv6:2607:f8b0:4864:20::237])
	by mail.lfdr.de (Postfix) with ESMTPS id 78A8A244DD2
	for <lists+kasan-dev@lfdr.de>; Fri, 14 Aug 2020 19:28:18 +0200 (CEST)
Received: by mail-oi1-x237.google.com with SMTP id w201sf4451687oiw.11
        for <lists+kasan-dev@lfdr.de>; Fri, 14 Aug 2020 10:28:18 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1597426097; cv=pass;
        d=google.com; s=arc-20160816;
        b=fpkXG0bnK4WnZRvDQD6p+vKJ8r5EXlBYkXxqXNGP2GMthCjgS/GE95k83cV1YUr0r9
         vmD3qnq+GB7jrNSDsf0Baku12Ckn9obPvdHBA7z3suEq7CNXhDweDu8TXhk858DNGvu4
         hLUPTS0blxICeX/mK/e0aGNJAQ8yVBac6hi2ODqyFc1VYqiqLdcn7l198rTGaIoV/4BQ
         RGR9UuMUlxobfe8YBfu4yplP0LQarDVvpF8bCuP0nE+mNigZ35HpTFuKGdDeUpMRJMip
         Rs7kHuX4gjTr7ZftmEiOO5mnELeU/JI7tT5OGNkUJp6ufURkyHMIgqwUzOECnjMXBfzt
         /d4A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=Uri0EHgo6rgETT3LJLDS+cp6kvvAmBTdcZLQmNcN7fE=;
        b=QeZAz2NRa8r/hLG2SUCYK1OgrE43Vms8Yax7jT5JIj5cdUvuur/x/hO2PiJFxh/+O+
         5D77UQ9HyIUwCfuiYisBXkUkUzRC0O8cVVKwe8Kl6+D9sOMqv5YP1ry+bzGKuloACTCA
         QHXFe/4T/JHYLYDWbuLY106DpTxUGSN1J0uxHtglMUkWwnQElbvtibTnvN/zxWGtNnOq
         Aj7eHccW/9PaYrA1WYJursnjG+f7wEFUzNDBrNhlnlvzo59z5LcG91zCQT2JAQPebw7w
         SBwOBws+RCov+RFOxidFP13hkH+DNlKUhISTnbI8GxuBtJuEuQg7HWazoTXbyDPwdjxV
         +4BA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="VBd8Y8/0";
       spf=pass (google.com: domain of 3r8k2xwokcr44h7l8sehpfaiiaf8.6ige4m4h-78paiiaf8aliojm.6ig@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=3r8k2XwoKCR44H7L8SEHPFAIIAF8.6IGE4M4H-78PAIIAF8ALIOJM.6IG@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Uri0EHgo6rgETT3LJLDS+cp6kvvAmBTdcZLQmNcN7fE=;
        b=PU798hhGhCrUD7Kps7UEICTijfp1XNvs3sYRGzi3v8mJp6s55TdxUtugpES1fakqb2
         joiF3nKtDhL+aZhEBdnD1WJi1JtxwYcEbyC3y/n6+aNPMG8KwWu11msAHIGkyRFaARYT
         hwzB6qsO7YqyrHwm7lfW4XNpjgb/AMzp2LaMMb8r11o9/z5TGubZU8KByDVjnOb541Ln
         TgAhPtL3VIGsCbHkwnMLh24fIniGPdKaiBEEbTZhrifzBhGmykjGoZ8i1/4v0ib2Z0IJ
         Krs3Q/ExMSuZN66oc7BqLzpYIPF+/tyKPk5MtMzmwYksP17u8iXD3LNfu4Oz/SAZ5syR
         Eq1A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Uri0EHgo6rgETT3LJLDS+cp6kvvAmBTdcZLQmNcN7fE=;
        b=j12NJZOnC6koVeNWlc8QwOzeom2cxh7FxlNtvlVfujnRKE2SNpGOKN+uG6cQlRJZ7o
         uMZa9tKJ0ZZQPNt496zpjPp3P057e/X6qb6/Jh6ccJW4PhWt1i5imIUpvdBlyCQMlB7X
         y5zjszCqV7WzRXY/b3iozksA/CcZXYmO8/E+Iw8cJ2y7h3yVcnpKUqTXB0hRGdyLNRED
         JLFcRzVS9oVvqlmGzu5UIIsR1lcSlmrpx1U9Tm/v8XNBaDvaFx4ZS+3LiYvAyFvNA8Ez
         zvetFTk+W7Xek+hJanvZqq5OWOM9VV6YGV54b6w7cv795P2oox/F9cjQ2A253mt0vJci
         3iWg==
X-Gm-Message-State: AOAM530gu7Aah1h57vudjdF48pIAfvp+AbeziXeUGtXKv+EH8TVjzXIb
	ccGsIXO58InlhgnDxoMJgug=
X-Google-Smtp-Source: ABdhPJzHll20HC5i9ZKq2opekgSwHp4+1jAuxDqRa0PgDD00mFSUpwlRCAxEeE7KmV3DhjJEsWqsXg==
X-Received: by 2002:a05:6808:64c:: with SMTP id z12mr2231729oih.5.1597426097290;
        Fri, 14 Aug 2020 10:28:17 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:d9d4:: with SMTP id q203ls2041361oig.4.gmail; Fri, 14
 Aug 2020 10:28:17 -0700 (PDT)
X-Received: by 2002:aca:31d2:: with SMTP id x201mr2252618oix.5.1597426096494;
        Fri, 14 Aug 2020 10:28:16 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1597426096; cv=none;
        d=google.com; s=arc-20160816;
        b=fIJw1ZvV3Q086+M2LhLQIyv4o4qaPGFgjIKfMxJRwWVQn9JH3AXCaB7NbYXwrPemTo
         uRUIcSGl67EoVs1fT3rLayRFVpfxFRzs71uJBL8/VgBqWzOg+04DhU6300YL2Qm2sS3l
         w9c4LTxGBO0NJqyOZuWoF0xcTYEQ4QNLQSOtoE9qXxJUBmRlPxYzFpWoXd9qAqtUZeFe
         hwmbzfjXbtdv9RM+YU/1e269LcbsB6acP58ZiizOpP+ycbICHkA3S7fjKnHdELo8jjaa
         lhbi/KF3CiShBuYl2IWvAWBsLySlzb9jqtbPguSt9l+CofmlP/6uk+UCxN+FI6B/fxa7
         QeJw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=LewkbAtBTS3fxa2ioFCrxocMUQLUBlN7d9swTrdmfVk=;
        b=tfs2NwfmsSnx4ZPf31kTbJvce28tHK3j1mNBEXiC6LzXwdh4WP9SiiSSsIoQeZ1hwc
         MSBJYVhzPO7j/TV8qbrWF1cQ42InJttLceA1nUMWL+zyqBY4eAL9uEcPwJ3NKoR1sksy
         fYIZMyoOz98j4A3YKJLFAI/9xyyouKxsLPjb+nD36sREBVENvKnBH1bB6KaRFkkWzIh2
         lxPfsIS990b9HRUbNq7AWbZv56RaY+eSF+1z93BRpCh1siSPPQ9BuJ/LMBcIm4knyN1s
         Y24INuqmxrTTgudcjDVAyjugdKKD6GHWnzhHc51aeXuzFkZFOYwOntK0rKJlgj6J5+al
         6yqw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="VBd8Y8/0";
       spf=pass (google.com: domain of 3r8k2xwokcr44h7l8sehpfaiiaf8.6ige4m4h-78paiiaf8aliojm.6ig@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=3r8k2XwoKCR44H7L8SEHPFAIIAF8.6IGE4M4H-78PAIIAF8ALIOJM.6IG@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf4a.google.com (mail-qv1-xf4a.google.com. [2607:f8b0:4864:20::f4a])
        by gmr-mx.google.com with ESMTPS id r64si427943oor.2.2020.08.14.10.28.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 14 Aug 2020 10:28:16 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3r8k2xwokcr44h7l8sehpfaiiaf8.6ige4m4h-78paiiaf8aliojm.6ig@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) client-ip=2607:f8b0:4864:20::f4a;
Received: by mail-qv1-xf4a.google.com with SMTP id f1so6509064qvx.13
        for <kasan-dev@googlegroups.com>; Fri, 14 Aug 2020 10:28:16 -0700 (PDT)
X-Received: by 2002:ad4:4b0b:: with SMTP id r11mr3633062qvw.94.1597426095910;
 Fri, 14 Aug 2020 10:28:15 -0700 (PDT)
Date: Fri, 14 Aug 2020 19:27:04 +0200
In-Reply-To: <cover.1597425745.git.andreyknvl@google.com>
Message-Id: <6a83a47d9954935d37a654978e96c951cc56a2f6.1597425745.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1597425745.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.28.0.220.ged08abb693-goog
Subject: [PATCH 22/35] arm64: mte: Enable in-kernel MTE
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Catalin Marinas <catalin.marinas@arm.com>, kasan-dev@googlegroups.com
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Elena Petrova <lenaptr@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="VBd8Y8/0";       spf=pass
 (google.com: domain of 3r8k2xwokcr44h7l8sehpfaiiaf8.6ige4m4h-78paiiaf8aliojm.6ig@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=3r8k2XwoKCR44H7L8SEHPFAIIAF8.6IGE4M4H-78PAIIAF8ALIOJM.6IG@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

From: Vincenzo Frascino <vincenzo.frascino@arm.com>

The Tag Checking operation causes a synchronous data abort as
a consequence of a tag check fault when MTE is configured in
synchronous mode.

Enable MTE in Synchronous mode in EL1 to provide a more immediate
way of tag check failure detection in the kernel.

As part of this change enable match-all tag for EL1 to allow the
kernel to access user pages without faulting. This is required because
the kernel does not have knowledge of the tags set by the user in a
page.

Note: For MTE, the TCF bit field in SCTLR_EL1 affects only EL1 in a
similar way as TCF0 affects EL0.

Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
---
 arch/arm64/kernel/cpufeature.c | 6 ++++++
 1 file changed, 6 insertions(+)

diff --git a/arch/arm64/kernel/cpufeature.c b/arch/arm64/kernel/cpufeature.c
index 4d3abb51f7d4..4d94af19d8f6 100644
--- a/arch/arm64/kernel/cpufeature.c
+++ b/arch/arm64/kernel/cpufeature.c
@@ -1670,6 +1670,9 @@ static void cpu_enable_mte(struct arm64_cpu_capabilities const *cap)
 	write_sysreg_s(0, SYS_TFSR_EL1);
 	write_sysreg_s(0, SYS_TFSRE0_EL1);
 
+	/* Enable Match-All at EL1 */
+	sysreg_clear_set(tcr_el1, 0, SYS_TCR_EL1_TCMA1);
+
 	/*
 	 * CnP must be enabled only after the MAIR_EL1 register has been set
 	 * up. Inconsistent MAIR_EL1 between CPUs sharing the same TLB may
@@ -1687,6 +1690,9 @@ static void cpu_enable_mte(struct arm64_cpu_capabilities const *cap)
 	mair &= ~MAIR_ATTRIDX(MAIR_ATTR_MASK, MT_NORMAL_TAGGED);
 	mair |= MAIR_ATTRIDX(MAIR_ATTR_NORMAL_TAGGED, MT_NORMAL_TAGGED);
 	write_sysreg_s(mair, SYS_MAIR_EL1);
+
+	/* Enable MTE Sync Mode for EL1 */
+	sysreg_clear_set(sctlr_el1, SCTLR_ELx_TCF_MASK, SCTLR_ELx_TCF_SYNC);
 	isb();
 
 	local_flush_tlb_all();
-- 
2.28.0.220.ged08abb693-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/6a83a47d9954935d37a654978e96c951cc56a2f6.1597425745.git.andreyknvl%40google.com.
