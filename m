Return-Path: <kasan-dev+bncBCCMH5WKTMGRBFEZ2WZQMGQEKDQJEOA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23a.google.com (mail-lj1-x23a.google.com [IPv6:2a00:1450:4864:20::23a])
	by mail.lfdr.de (Postfix) with ESMTPS id 44DB0912126
	for <lists+kasan-dev@lfdr.de>; Fri, 21 Jun 2024 11:49:10 +0200 (CEST)
Received: by mail-lj1-x23a.google.com with SMTP id 38308e7fff4ca-2ec3cb4354bsf14124661fa.3
        for <lists+kasan-dev@lfdr.de>; Fri, 21 Jun 2024 02:49:10 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718963349; cv=pass;
        d=google.com; s=arc-20160816;
        b=cpn5J4mrGjzxD4ShbnVyXay6ByePDZ5cBGSLqLB+BpBBhxDgZYGK7MDUiQ+EQYb0b4
         TcDT0AbYIkv9a2d02gto5kiBs2cznCASRI9WOvyUSsoeUZsj02DxcLbN9Y1HwIu+Y591
         TLm4OWYpAlEibMCO0vinsx4ZDiqeE3ukM1X+7suAiAYZybHTDU4TnrPpjKwzmT+N+srT
         E9AqRUAta/cC9zU0DBcxe89ITYt5VSY4GzKnzYWOThdDGbPgygkR2IUBJ/99IEyWgsEz
         HYFQPptlwvqBvZkKlpm4b3/Gigmf+1DWjah4ovv6OPp8iExOCDhdl+TA3gIDiC51K38F
         5wxQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:mime-version:date:dkim-signature;
        bh=GPwbnN6nq3q+RG6cy/ZabJJQgDDIlHezWR+TkTKsfGo=;
        fh=/n59ILkXS9JLdLcqqoylMEGcy+GoshoJFhrVCCUn0Qc=;
        b=1IOHVEAi4disvu7nZr9C8HVLubZNHAHVGaovcopPzdNKpoNZtmCgf2yn3o7zfx/4KO
         R1L/Lvxmi9fYyCyuMX8wZsShdFxrqDaSx0LAnyiPuf53N6QdVDVLXOcM+LRtp7Hd/t87
         lMQ3oiY+e4bcpO2xW6e2mR3AZScoFvhIXr8+INnaEKDSX4gqJ/IZShLCAOqunT08bqCY
         LTcfrkj8emcIHzCdTc5J7gwWM2EJ0NPjcbjSoijSB2E2Ctn+/5Ql29m5eYHIH6wAUhoZ
         9JFzIGLDJ+1F3c8jKOfxOnUWcbFC3ozIKNJecfUszvE05zEVdGOtC/hQNnuEnWVam7jx
         ttdg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=SSAN4CU4;
       spf=pass (google.com: domain of 3kux1zgykctochezanckkcha.ykigwowj-zarckkchacnkqlo.yki@flex--glider.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3kUx1ZgYKCTocheZanckkcha.YkigWoWj-Zarckkchacnkqlo.Yki@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718963349; x=1719568149; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:from:to:cc:subject:date
         :message-id:reply-to;
        bh=GPwbnN6nq3q+RG6cy/ZabJJQgDDIlHezWR+TkTKsfGo=;
        b=Z06PtFy4gpCLdcz+Pr6Bu5uaqk41j5KUIqXo0/hbbv2cR5mw3BH2fv4XTFxFfZCo5p
         yBMHIw0mnFUMlr7Fy6x6gDkzE2DKo8P2SDlzFwDDHlgXr+kV8B/GSv9QV2O31xu8oguA
         XPfQsTGGvkgIGI0BWKq7PSeELEQ32kIlm42lHYnctyOy0yX+pnvjXWzSL2ONuojeYSAP
         k02pp6jjf3oWZEFxvQG9DglPi5qIyccGGrtWa0GnwpC7GzoGLjmH8bI8o/X3A2Cfg7Mh
         aCDfk1tPi6ZX2K38MBt2HmBcfuiYUZyt6O+q26C4kk46//Yj0kvc0JQOIqc0O+hblOC+
         Rwbw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718963349; x=1719568149;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=GPwbnN6nq3q+RG6cy/ZabJJQgDDIlHezWR+TkTKsfGo=;
        b=Lvyieg4J0XvC8LcY8JZs9lR4M2HCVETU5l2eBQdIBKMo4Gr4hbFqNOBAXtTveKaKWp
         bmNzILi2JpYYppeDKg96oVetud/tmSItfqKizvu/PtfJg5Af3vyjnpRuMRRbz7sJy7Hq
         Hput4i4+3qAxtugLOXeF62is0Lt3LTI0i/dlb7srom7vkGSsVqV8N+KJW+yBdurf3pmj
         2OICS6NmO8Ke2BXHTokgnaCq0cxV87bhDmknpWQUA6mmEpIthM//1WC9ZMX43e8go/DC
         CFHEUV66QUyOE+wuCc+5O23UMaAmwcGqD8H83zhhCcZ7sYUH44qSpJaiwEqDg7APe3U7
         ialQ==
X-Forwarded-Encrypted: i=2; AJvYcCUDpC2Z1uwJS9NZRxVU1ygR34fYfa29e9OM0XVia3+6fv9eiCz7pQULa+zPdD+yXYXiDfLmBGlZdL5gktJT23cZlX27kQuYeQ==
X-Gm-Message-State: AOJu0Yz2OyGjCGYOZRbwMDMjhh/QweAslnp/STQznTE2DqpacD90J8hU
	83k0inNfaYOfNwTyV5KVrVLcb588c1Mc/nx2EqkHxqbx8hlQInrc
X-Google-Smtp-Source: AGHT+IHIoVi/qOxV/DFXTVNedOX0dq6ouPbx6E4L38JalaC552V5LGpPxcJwT6Y6/dldCf608ccPBA==
X-Received: by 2002:a2e:7818:0:b0:2ec:3bc4:3e36 with SMTP id 38308e7fff4ca-2ec3ceb6a56mr49406861fa.14.1718963348755;
        Fri, 21 Jun 2024 02:49:08 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:7e09:0:b0:2ec:2ee1:d8bd with SMTP id 38308e7fff4ca-2ec442e652cls6899901fa.0.-pod-prod-02-eu;
 Fri, 21 Jun 2024 02:49:07 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWSx1v5eFuyQfSleqCsRoKlP5lhV6fIk64I9heMKj6sR1ZYL66jVmix3VTHWqjiOetEEVMzr56c4xzi8JIUiqLUOdIMejGWL4RowA==
X-Received: by 2002:a05:6512:a90:b0:52c:cb8d:6381 with SMTP id 2adb3069b0e04-52ccb8d643dmr5064593e87.13.1718963346675;
        Fri, 21 Jun 2024 02:49:06 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718963346; cv=none;
        d=google.com; s=arc-20160816;
        b=xjrd65E/881tf7D5CKnw8BAQ7mT3Oae3qIM5IyfC7yRc/7LWkrKqXALlQ5pvuCtc93
         416KW72Fdwj58AEWwTR1MI5e3AeY2iMrb5PRIPjZrOLCkOTCmqGyhWvaHG48qxxyr1Sb
         yWg2/np9aQQl9qPpSOrupeyyG2o+CrxWq7lYcr5ptw/bhqREJXwkkeEhEZiZd6YMLwDm
         Qp8dw4xai+pw1VPOili4+UvNTdKuRIP1iyr93swMZtGVZi0ecFQpPAgjCvgYJZd8hDiv
         f5PAM+K2e8wn1zBXYUrdBWQiUcJD+r00IgtDuGY0twtKGNHVuzY/1JnumGWI8/sHuNuM
         U2tg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:mime-version:date:dkim-signature;
        bh=OPh0O/AeDSq3BCIIPxPFqWQwYbgJlUXgbUqbCxM5Jxg=;
        fh=MMpT88EhcRUIVt3hKrVVLvG9NXrQOH6gOXNMdi0KTT0=;
        b=1Cjv8MnmSzVow9na2sBYLDBgxQnrTlgsRDKXboPYCtb1j6jJcl/X9s/mn+EQlXI7hv
         q8LBHZBUxF9Cyrr94YoJKaKGRqNPpZEzgvZS6qHf7vF5U98ElQzwSGC+Oxsy7v+2mCRa
         H/lWUdiTAq3RQzOF/7oaNn0DcPR439YkQIapb+NAmxwKbbHUgUR+fskUsXDg7ouoMwj6
         KBgNUeZQRwkCqVhf5erz/CA0kOF1yPMtSB8WRwz+GoM3Rc2krC8rov8Wur31lrYU/Enu
         AgR0X2576tbkBEg01sbk5tKRWNQs94UtgT3dHhyXkJ/Z5o42V2d/ziSMWSXXg6W326Z1
         G21A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=SSAN4CU4;
       spf=pass (google.com: domain of 3kux1zgykctochezanckkcha.ykigwowj-zarckkchacnkqlo.yki@flex--glider.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3kUx1ZgYKCTocheZanckkcha.YkigWoWj-Zarckkchacnkqlo.Yki@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ej1-x64a.google.com (mail-ej1-x64a.google.com. [2a00:1450:4864:20::64a])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-52cd627e653si17602e87.0.2024.06.21.02.49.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 21 Jun 2024 02:49:06 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3kux1zgykctochezanckkcha.ykigwowj-zarckkchacnkqlo.yki@flex--glider.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) client-ip=2a00:1450:4864:20::64a;
Received: by mail-ej1-x64a.google.com with SMTP id a640c23a62f3a-a6fc7cf2581so143262866b.1
        for <kasan-dev@googlegroups.com>; Fri, 21 Jun 2024 02:49:06 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXYFON0ssJRo1DPGMi6vTvhXSbXa0BbmV0NLJ10qia5nPJ9dWXkAHed8ehtig6Xo8zdoEXMO2NYnXQ/4zOLgHnpwc6+AxJvcVEsXA==
X-Received: from glider.muc.corp.google.com ([2a00:79e0:9c:201:485e:fb16:173e:13ce])
 (user=glider job=sendgmr) by 2002:a17:907:7215:b0:a6f:9f9f:fabb with SMTP id
 a640c23a62f3a-a6fa449538cmr731166b.5.1718963345670; Fri, 21 Jun 2024 02:49:05
 -0700 (PDT)
Date: Fri, 21 Jun 2024 11:48:59 +0200
Mime-Version: 1.0
X-Mailer: git-send-email 2.45.2.741.gdbec12cfda-goog
Message-ID: <20240621094901.1360454-1-glider@google.com>
Subject: [PATCH 1/3] x86: mm: disable KMSAN instrumentation for physaddr.c
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
To: glider@google.com
Cc: elver@google.com, dvyukov@google.com, dave.hansen@linux.intel.com, 
	peterz@infradead.org, akpm@linux-foundation.org, x86@kernel.org, 
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, 
	"Kirill A . Shutemov" <kirill.shutemov@linux.intel.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=SSAN4CU4;       spf=pass
 (google.com: domain of 3kux1zgykctochezanckkcha.ykigwowj-zarckkchacnkqlo.yki@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3kUx1ZgYKCTocheZanckkcha.YkigWoWj-Zarckkchacnkqlo.Yki@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

Enabling CONFIG_DEBUG_VIRTUAL=y together with KMSAN led to infinite
recursion, because kmsan_get_metadata() ended up calling instrumented
__pfn_valid() from arch/x86/mm/physaddr.c.

Prevent it by disabling instrumentation of the whole file.

Reported-by: Kirill A. Shutemov <kirill.shutemov@linux.intel.com>
Closes: https://github.com/google/kmsan/issues/95
Signed-off-by: Alexander Potapenko <glider@google.com>
---
 arch/x86/mm/Makefile | 1 +
 1 file changed, 1 insertion(+)

diff --git a/arch/x86/mm/Makefile b/arch/x86/mm/Makefile
index 8d3a00e5c528e..d3b27a383127d 100644
--- a/arch/x86/mm/Makefile
+++ b/arch/x86/mm/Makefile
@@ -17,6 +17,7 @@ KCSAN_SANITIZE := n
 # Avoid recursion by not calling KMSAN hooks for CEA code.
 KMSAN_SANITIZE_cpu_entry_area.o := n
 KMSAN_SANITIZE_mem_encrypt_identity.o := n
+KMSAN_SANITIZE_physaddr.o := n
 
 ifdef CONFIG_FUNCTION_TRACER
 CFLAGS_REMOVE_mem_encrypt.o		= -pg
-- 
2.45.2.741.gdbec12cfda-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240621094901.1360454-1-glider%40google.com.
