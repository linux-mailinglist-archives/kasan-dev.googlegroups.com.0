Return-Path: <kasan-dev+bncBC7OBJGL2MHBBLFPTPWQKGQEMSIMZSY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13a.google.com (mail-lf1-x13a.google.com [IPv6:2a00:1450:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id E5BD1D8B48
	for <lists+kasan-dev@lfdr.de>; Wed, 16 Oct 2019 10:41:16 +0200 (CEST)
Received: by mail-lf1-x13a.google.com with SMTP id c7sf4574125lfh.9
        for <lists+kasan-dev@lfdr.de>; Wed, 16 Oct 2019 01:41:16 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1571215276; cv=pass;
        d=google.com; s=arc-20160816;
        b=ocSFr2FDDwYtMDEyDbz70/ueYVjj7gN/KNsaU9+65IrVh697atNeun6ffxgV3Q7iOL
         7OFuYTZHMtkc1VqsVi71DhXHuhuMBk7pWkgjpbGwGm6mbc6f+4HSmREYYSFDGB4uc7Bg
         jRekLtEiwasEz4MfiT7U5RZkuaYxRV1RkyHpDj9ibwn8xngD2vW45nu4cAb0AjRyrQ3s
         7Hse7YfttYXLKQZZhTvD0qHcXU9mwQr+PSn+giXv4minTw9pMWC/ist1gLtwqfsK+/gD
         kjHyJ8AxdJIUN7ubxi/M1HYoE+16kTtkJHCk1x6syO/0dU0pSZEgf5FewroTM9jGX0d7
         0URA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=ZmcehKhjeWENan0hhOg+MYqTxjBcyDciSgMJC+IJkh8=;
        b=c8sTpZjBaWkwYBN6PfXA11oiwXYKy5HREVHVa4l9/42OojwkPhyGqm7VlZ1jZSdcF6
         vG2soX46uRKjt2XOhdrC3cSwA6gSvykE69OfsYk7Xa8oZC3UqcDAzvMiwazJM3AiVbR/
         qJa/roUsVkcorwPmgBVq3Jj0Qu0TD6eiT7aQkYSRmg0ouhN+IAfb7KMEKh9cKIPhrRmd
         4MydJx6bdC5mppc1yHQv0gFiQljt3xxJ5cquJ/wDf00R1AXNkj/JyhUxr/NWrmtazQAh
         dLlTXVIXPRGJdYDS6VB3k48OvjT8F2J3O+gF/gtcFRmhfvZWC67SUcSv41WUGJWaITIQ
         SFzQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="FDIPWUL/";
       spf=pass (google.com: domain of 3qtemxqukcecnuenapxxpun.lxvtjbjw-mnepxxpunpaxdyb.lxv@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3qtemXQUKCecNUeNaPXXPUN.LXVTJbJW-MNePXXPUNPaXdYb.LXV@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ZmcehKhjeWENan0hhOg+MYqTxjBcyDciSgMJC+IJkh8=;
        b=ORrhCdqxnQLvo8qLB7etmsP8qgmI6vawWV3Is216ggCtMmQcURxXzCuMIZCMQb3NOP
         OBL0HE+TdRYgSyv00hNdSmItelz5hwJqGtbl7U/3gvNnj5pgt6ncYFaSFemd8wDr2Csj
         zjuqFgCDbgxUpVTqQOM95xOOOTXoR+KbpqcOmr5wCbaxVieUUNlHCgXm2gHMhpi8oX50
         xR7qDcP+RYIfNGMwApS4onO+83if4gHhwltDMoFcoDKpKOQLd1Byh86IFDVesMzKyZ/0
         QPXG2/L8tUPSFx8r+iSE5tgkExMc4A11JoL8BZJXek2t+GM141q2Og2i5EWKPY/FAQUl
         jlcw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ZmcehKhjeWENan0hhOg+MYqTxjBcyDciSgMJC+IJkh8=;
        b=LWXKrBHJV3e+6Mcq5r48THPRSUrr19agt6C9XuLo4bRrgVhsTHKD87N/9JXoeCa4tk
         A1PsiCsUJizXsd9UuCcTVpnxNBQAYehlZgoCCkZNAbbrOpESZs0EgDLryMex8Y7/Wj5q
         +mdOEcfJrm7acN25OecYbXG1+LNqWfeUIQ8npWM9P0+QNHXe0eFcdfMNP7uqQnwOIB9F
         23HFFQb3JVWg11zdjeN8ptgskzWoFKtDDY4/FGGuQmSuljOs6WRVpC6t6GHvKYQKwDvE
         eO9qdDN+EKsCiFghi440meDeJC2GEmhNeQBKNKihtg4kLGBswLxZ9AZUbuRRzvO+EgS6
         SnDw==
X-Gm-Message-State: APjAAAU0PkhUwq276iDZCZ/a1hpaDFNbn4ZfdjfeSPuxjVHrGSRwoNc+
	X2lYUndPn3lqvG+w0761RWk=
X-Google-Smtp-Source: APXvYqyMFigundqF+6KHZjAfAgV7QrAtQbSfgllRxUBTgCbUz7wn3/HRKJQSv8ajGyy2IoK6PQqyUw==
X-Received: by 2002:a05:6512:4c1:: with SMTP id w1mr23779455lfq.96.1571215276489;
        Wed, 16 Oct 2019 01:41:16 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:f246:: with SMTP id d6ls1917721lfk.9.gmail; Wed, 16 Oct
 2019 01:41:15 -0700 (PDT)
X-Received: by 2002:a05:6512:25b:: with SMTP id b27mr512207lfo.39.1571215275805;
        Wed, 16 Oct 2019 01:41:15 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1571215275; cv=none;
        d=google.com; s=arc-20160816;
        b=F0VFLAatQu+Zt4pf6bdWADXIiMiriNejWK7pZTztfp9PBdvKxXuSLWgJGQ35I17gOh
         SCyuocuRjqfRy9XZED8nKf2KDjDhdXHBMhDTyCL4WtyiW0JLiCjyGxyECUzgmeCBIItu
         7RzWb6/4/Yh3MMGPf27LDaBDpP2BW84ChGdtqmOl2nk5RVdNhqJeSMY8rTQ75qGMd5y7
         NFXJ72CrTljQ6RPHyamFlE/z94QYKIvRz/mhXkBz6xvdXmSHTIQlg8t1bzRlH0Aa0Gx/
         ukthJAmbqZ9sNREMAL5Dn/pas3RG2z6B2EX+p8uC+J3i6vSa9qeUj8z+0j3hNht6xXq4
         nJ3g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=9SMgLZKRCrUAwZ4Rshpo1HVyP5RqT+TntrXHNZ73xYY=;
        b=iOIIrblJG2MTv/2fRHOMzwBsxFWLlkBeozoKhP1HGtKVnpNTIT4xoAQSG4swvXMrsE
         iPMA2jTGR/kfGm69ZuwEwbddiWl5V97guWhXSLQKWpbtiFJJpJenFydq/hpkt4aJ1l4M
         0s/U3RZ/4IH6axp/L0ND5Njmz6HAwI/mrjSlVIObAo/sw9uqTGnh7/as6b2cJa57lErZ
         3EPgJxCIzNLQdjgyjIQF5g1RLPbhmhzb/f+Pee9MLHLIY+7lN55CRYPCtIsxMXSeWxrf
         KDDnUAfnJeV2uhfIym8YGL9qZ/CkNGSx5AgMuuYfNWMEdueWyoYIeHtp5EHmQwLAskfv
         F/XA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="FDIPWUL/";
       spf=pass (google.com: domain of 3qtemxqukcecnuenapxxpun.lxvtjbjw-mnepxxpunpaxdyb.lxv@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3qtemXQUKCecNUeNaPXXPUN.LXVTJbJW-MNePXXPUNPaXdYb.LXV@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x349.google.com (mail-wm1-x349.google.com. [2a00:1450:4864:20::349])
        by gmr-mx.google.com with ESMTPS id h6si971316lfc.3.2019.10.16.01.41.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 16 Oct 2019 01:41:15 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3qtemxqukcecnuenapxxpun.lxvtjbjw-mnepxxpunpaxdyb.lxv@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) client-ip=2a00:1450:4864:20::349;
Received: by mail-wm1-x349.google.com with SMTP id c188so655798wmd.9
        for <kasan-dev@googlegroups.com>; Wed, 16 Oct 2019 01:41:15 -0700 (PDT)
X-Received: by 2002:a5d:4588:: with SMTP id p8mr1610112wrq.180.1571215274810;
 Wed, 16 Oct 2019 01:41:14 -0700 (PDT)
Date: Wed, 16 Oct 2019 10:39:53 +0200
In-Reply-To: <20191016083959.186860-1-elver@google.com>
Message-Id: <20191016083959.186860-3-elver@google.com>
Mime-Version: 1.0
References: <20191016083959.186860-1-elver@google.com>
X-Mailer: git-send-email 2.23.0.700.g56cf767bdb-goog
Subject: [PATCH 2/8] objtool, kcsan: Add KCSAN runtime functions to whitelist
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com
Cc: akiyks@gmail.com, stern@rowland.harvard.edu, glider@google.com, 
	parri.andrea@gmail.com, andreyknvl@google.com, luto@kernel.org, 
	ard.biesheuvel@linaro.org, arnd@arndb.de, boqun.feng@gmail.com, bp@alien8.de, 
	dja@axtens.net, dlustig@nvidia.com, dave.hansen@linux.intel.com, 
	dhowells@redhat.com, dvyukov@google.com, hpa@zytor.com, mingo@redhat.com, 
	j.alglave@ucl.ac.uk, joel@joelfernandes.org, corbet@lwn.net, 
	jpoimboe@redhat.com, luc.maranget@inria.fr, mark.rutland@arm.com, 
	npiggin@gmail.com, paulmck@linux.ibm.com, peterz@infradead.org, 
	tglx@linutronix.de, will@kernel.org, kasan-dev@googlegroups.com, 
	linux-arch@vger.kernel.org, linux-doc@vger.kernel.org, 
	linux-efi@vger.kernel.org, linux-kbuild@vger.kernel.org, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, x86@kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="FDIPWUL/";       spf=pass
 (google.com: domain of 3qtemxqukcecnuenapxxpun.lxvtjbjw-mnepxxpunpaxdyb.lxv@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3qtemXQUKCecNUeNaPXXPUN.LXVTJbJW-MNePXXPUNPaXdYb.LXV@flex--elver.bounces.google.com;
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

This patch adds KCSAN runtime functions to the objtool whitelist.

Signed-off-by: Marco Elver <elver@google.com>
---
 tools/objtool/check.c | 17 +++++++++++++++++
 1 file changed, 17 insertions(+)

diff --git a/tools/objtool/check.c b/tools/objtool/check.c
index 044c9a3cb247..d1acc867b43c 100644
--- a/tools/objtool/check.c
+++ b/tools/objtool/check.c
@@ -466,6 +466,23 @@ static const char *uaccess_safe_builtin[] = {
 	"__asan_report_store4_noabort",
 	"__asan_report_store8_noabort",
 	"__asan_report_store16_noabort",
+	/* KCSAN */
+	"__kcsan_check_watchpoint",
+	"__kcsan_setup_watchpoint",
+	/* KCSAN/TSAN out-of-line */
+	"__tsan_func_entry",
+	"__tsan_func_exit",
+	"__tsan_read_range",
+	"__tsan_read1",
+	"__tsan_read2",
+	"__tsan_read4",
+	"__tsan_read8",
+	"__tsan_read16",
+	"__tsan_write1",
+	"__tsan_write2",
+	"__tsan_write4",
+	"__tsan_write8",
+	"__tsan_write16",
 	/* KCOV */
 	"write_comp_data",
 	"__sanitizer_cov_trace_pc",
-- 
2.23.0.700.g56cf767bdb-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191016083959.186860-3-elver%40google.com.
