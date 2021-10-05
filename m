Return-Path: <kasan-dev+bncBC7OBJGL2MHBBUPA6CFAMGQELKVZ6QQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x439.google.com (mail-pf1-x439.google.com [IPv6:2607:f8b0:4864:20::439])
	by mail.lfdr.de (Postfix) with ESMTPS id B337842243B
	for <lists+kasan-dev@lfdr.de>; Tue,  5 Oct 2021 13:00:34 +0200 (CEST)
Received: by mail-pf1-x439.google.com with SMTP id a188-20020a627fc5000000b004446be17615sf10891872pfd.7
        for <lists+kasan-dev@lfdr.de>; Tue, 05 Oct 2021 04:00:34 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1633431633; cv=pass;
        d=google.com; s=arc-20160816;
        b=xwCpXsVsU3NcHIP8Bs20E98xlYMxzXvlNiAVlwd4vaZAmt1Aw9W272rB/D/7LxFG1Z
         bJoLvSSqabZfSXncAKzFszI61QViP08MXjJeu3F4IDofDY+fl0y6ZvsWOIcZJ7ZUVclP
         YTwLxrSq5k/KTUGc51jx+jMhP7mNOQFTiBcIscDqeuZkCIhu6N8RUWdPlNMaa9P1XO/1
         xoR5xWIuWvtyOgMxOvvvo12/V0iV/7kP0nkbfbyBkMeyBYPB+hxO+Tgrh2fh9dEglnFY
         wdGrYfdRDl3Q8fTcYguc4xiDZlQKGYMV+Qk0afVj7BP1D1hDswHfSOxOkxl53jPIpyeL
         L+zg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=8pwY2hBmRK1EbDV0kzpzCfXHkZOvCgFPYOmZ0pyqUlo=;
        b=y/WjgrkeuCf6M+V9tdjWYlKyTeOsQCBkWp6iYuRh33gsTD754dy3pmdSmzu89ku0R3
         SQphil7fnkM87Q/GD+HNXMmYl4lTZQuwjRa3xcUdpN/Tlb9sYynzJEUTgtDXDY8rZ6AD
         Y4IJAnRSp/PNTasbxFdpfEj9mOcs48z3hFQVlK7FhxlFkOpqaiic4dB4n0haQvF19lml
         JRZH6R99VBtEqqBu4Hrm40dpY58/UF/04SU7AcPwkz3LcxGOO9IqhBz3muIiHxMHcKI6
         Tfr6bDKsl5zFjjsQmEwLgSzb1wjLT+uCLM9MLAElVdn1zXoUhrUqGbmnqHXUmqdq5ezz
         oa2Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=JKcUv82m;
       spf=pass (google.com: domain of 3tzbcyqukctiszjsfuccuzs.qcayogob-rsjuccuzsufcidg.qca@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3TzBcYQUKCTISZjSfUccUZS.QcaYOgOb-RSjUccUZSUfcidg.Qca@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=8pwY2hBmRK1EbDV0kzpzCfXHkZOvCgFPYOmZ0pyqUlo=;
        b=mh6DISo83DLjfsV6LP0xj8sIQz36TpkZD+zuAEVp7qot/I6mXyWTHSnx1GojTJKe3b
         Lw5T4sHd9F4xNKP0QOVkCERWUFuWOW5YROwk/Upb5JhOQpPA6JMJms0p2h9VWy8se1Gm
         ohSNBQe7qCkuI07P2ofd1j2UiVCOIJA+C2KpHWFi2fBujuiL3bt37L0bSBR6Pq6wUhh9
         zLWGgXzt9zKgzaqCS8hVbHnCLN3+Owz6PW3z34jvI0ZVkr5ZmoHA41YImazCugKTekz0
         kT+0Krn3Ptoyd3zpo6+qZFgSj+rnJSODvuteYlIQyTvGSC0NSuM2uELmDeyp6pAF4IA8
         Kllw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=8pwY2hBmRK1EbDV0kzpzCfXHkZOvCgFPYOmZ0pyqUlo=;
        b=VTMVdMrP4trN/rjLBibqZot0wWIZMruxFxX6Vtm+/HSeQ16lPp0xOKkLRjnStZcj+5
         vT6/oPrftBJ49ADEOHxdfzjZ3bxj5AGcvr72n2h1qcx/ZXPraasGRtktUJkym/+oNXHF
         G08CLZDEHV2nGVogBnyAhbAhUJJmmg0OYjNaodTtijJ7+Ad64KA0bnHc/uz5Ui9jCJjq
         j3ZEhMHi4zykZtj3eCz3dojyTKLBxqvH69sZEXV/82td8nZobP8fX4ziwubL2g01qh3o
         NMiGTPc9HjTzG9u/02KUMBmSasSoXHCIiDc/cIBqEYCmR3kcu135m0SBBJ5ZKmg4zKff
         3CSw==
X-Gm-Message-State: AOAM530mFx33ZPDQbCSjhvkjfzFLGXvBAteGXPUbbkJLB9NS8ZEAupl6
	sqi40XpxzoBt1y8f6JEPizI=
X-Google-Smtp-Source: ABdhPJxsb62flSi24MugxxlXlr7vtb/gMCy4k96NQUe8zC6pjgRQnHMicCE/tl/vfdB3jACkN/ofKg==
X-Received: by 2002:a17:90a:d58f:: with SMTP id v15mr2997593pju.28.1633431633427;
        Tue, 05 Oct 2021 04:00:33 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:ac9:: with SMTP id r9ls1022451pje.1.gmail; Tue, 05
 Oct 2021 04:00:32 -0700 (PDT)
X-Received: by 2002:a17:902:868d:b0:13d:dfa7:f3f2 with SMTP id g13-20020a170902868d00b0013ddfa7f3f2mr4753500plo.30.1633431632775;
        Tue, 05 Oct 2021 04:00:32 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1633431632; cv=none;
        d=google.com; s=arc-20160816;
        b=MYPylIb+jjP5fn5aru8FK3NE/aH14AV0bjMjtgUh7d3NylGPXvHNZ5Ivw5Xi+8HIRG
         axY3/NLfPMqAOMcXC3rsgMN9NMPrzq8Qi3+W3WPBZusM3y9u5m/QZFl7vg8rpTO5I0a6
         Fm9j/5FAHDYFsPD1czBiT2TV7YUvYQ2YB0OHjs6PvI6SioY4f2Bd3mk++MiMxfEmzwm6
         Dc10UGaOpY9ZCpRJpbGwL2OUy7Mq+huxOdntkTHM5q4v9lB6MqZGkC9Ev8D6v/+FgkDO
         O2rZeMkGdoisUWft0fZy5eRgq+g404W1bSvVNWZlein8w8DQebqsbJM7JPAG8XnosSfR
         OXYA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=TKNtzDHuk87hCc1lxzVppXFapgrghO5zpeN0ZyRA5jw=;
        b=eecxrWhdt8X6/eKn7/DmtVQ+lkSIL9SdV3yj4KnuuTw/icyIuRVeLszhJcZJ4PWcGV
         Eb5Va6fDP8/OsSmyLpWszKIM4M+TuhKjN9l6Sq235jqC3/RozhSlMt6bLmUHbMwFlHCN
         2fMK3Gko7XeqaxNAFmEaCH4eNFQQ+xJM+AnJx/crxGMVt+/DqymBxh7vCHcAEiMHUFNp
         8dsYTwECllCz3KdcSWtqUGUgCdGPXDFA+v1TPitIp46/vnMA1hiPyRal76aCj0ahRSw0
         K9TK2b74cHR7CqTP1fh+NyXrcmaJRGs+NN44ZOSZ2nLkNyib1MeomCxXLWUWH3KehA07
         E8kg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=JKcUv82m;
       spf=pass (google.com: domain of 3tzbcyqukctiszjsfuccuzs.qcayogob-rsjuccuzsufcidg.qca@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3TzBcYQUKCTISZjSfUccUZS.QcaYOgOb-RSjUccUZSUfcidg.Qca@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x84a.google.com (mail-qt1-x84a.google.com. [2607:f8b0:4864:20::84a])
        by gmr-mx.google.com with ESMTPS id p18si1308477plr.1.2021.10.05.04.00.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 05 Oct 2021 04:00:32 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3tzbcyqukctiszjsfuccuzs.qcayogob-rsjuccuzsufcidg.qca@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) client-ip=2607:f8b0:4864:20::84a;
Received: by mail-qt1-x84a.google.com with SMTP id o7-20020ac86d07000000b002a69537d614so22738541qtt.21
        for <kasan-dev@googlegroups.com>; Tue, 05 Oct 2021 04:00:32 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:e44f:5054:55f8:fcb8])
 (user=elver job=sendgmr) by 2002:ad4:46d1:: with SMTP id g17mr26469108qvw.5.1633431631997;
 Tue, 05 Oct 2021 04:00:31 -0700 (PDT)
Date: Tue,  5 Oct 2021 12:59:03 +0200
In-Reply-To: <20211005105905.1994700-1-elver@google.com>
Message-Id: <20211005105905.1994700-22-elver@google.com>
Mime-Version: 1.0
References: <20211005105905.1994700-1-elver@google.com>
X-Mailer: git-send-email 2.33.0.800.g4c38ced690-goog
Subject: [PATCH -rcu/kcsan 21/23] sched, kcsan: Enable memory barrier instrumentation
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, "Paul E . McKenney" <paulmck@kernel.org>
Cc: Alexander Potapenko <glider@google.com>, Boqun Feng <boqun.feng@gmail.com>, 
	Borislav Petkov <bp@alien8.de>, Dmitry Vyukov <dvyukov@google.com>, Ingo Molnar <mingo@kernel.org>, 
	Josh Poimboeuf <jpoimboe@redhat.com>, Mark Rutland <mark.rutland@arm.com>, 
	Peter Zijlstra <peterz@infradead.org>, Thomas Gleixner <tglx@linutronix.de>, 
	Waiman Long <longman@redhat.com>, Will Deacon <will@kernel.org>, kasan-dev@googlegroups.com, 
	linux-arch@vger.kernel.org, linux-doc@vger.kernel.org, 
	linux-kbuild@vger.kernel.org, linux-kernel@vger.kernel.org, 
	linux-mm@kvack.org, x86@kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=JKcUv82m;       spf=pass
 (google.com: domain of 3tzbcyqukctiszjsfuccuzs.qcayogob-rsjuccuzsufcidg.qca@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3TzBcYQUKCTISZjSfUccUZS.QcaYOgOb-RSjUccUZSUfcidg.Qca@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

There's no fundamental reason to disable KCSAN for scheduler code,
except for excessive noise and performance concerns (instrumenting
scheduler code is usually a good way to stress test KCSAN itself).

However, several core sched functions imply memory barriers that are
invisible to KCSAN without instrumentation, but are required to avoid
false positives. Therefore, unconditionally enable instrumentation of
memory barriers in scheduler code. Also update the comment to reflect
this and be a bit more brief.

Signed-off-by: Marco Elver <elver@google.com>
---
 kernel/sched/Makefile | 7 +++----
 1 file changed, 3 insertions(+), 4 deletions(-)

diff --git a/kernel/sched/Makefile b/kernel/sched/Makefile
index 978fcfca5871..90da599f5560 100644
--- a/kernel/sched/Makefile
+++ b/kernel/sched/Makefile
@@ -7,11 +7,10 @@ endif
 # that is not a function of syscall inputs. E.g. involuntary context switches.
 KCOV_INSTRUMENT := n
 
-# There are numerous data races here, however, most of them are due to plain accesses.
-# This would make it even harder for syzbot to find reproducers, because these
-# bugs trigger without specific input. Disable by default, but should re-enable
-# eventually.
+# Disable KCSAN to avoid excessive noise and performance degradation. To avoid
+# false positives ensure barriers implied by sched functions are instrumented.
 KCSAN_SANITIZE := n
+KCSAN_INSTRUMENT_BARRIERS := y
 
 ifneq ($(CONFIG_SCHED_OMIT_FRAME_POINTER),y)
 # According to Alan Modra <alan@linuxcare.com.au>, the -fno-omit-frame-pointer is
-- 
2.33.0.800.g4c38ced690-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211005105905.1994700-22-elver%40google.com.
