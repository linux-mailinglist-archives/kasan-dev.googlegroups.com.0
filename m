Return-Path: <kasan-dev+bncBDBK55H2UQKRBQMDUGMQMGQEH2IOVSI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33a.google.com (mail-wm1-x33a.google.com [IPv6:2a00:1450:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id 26AA75BC676
	for <lists+kasan-dev@lfdr.de>; Mon, 19 Sep 2022 12:17:38 +0200 (CEST)
Received: by mail-wm1-x33a.google.com with SMTP id b5-20020a05600c4e0500b003b499f99acesf4466454wmq.1
        for <lists+kasan-dev@lfdr.de>; Mon, 19 Sep 2022 03:17:38 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1663582658; cv=pass;
        d=google.com; s=arc-20160816;
        b=vJK6lRanuKGxL71C5cWA3qhsPPika1QrAB6XClDpRp80GWF2jnbMYqgzbLcStD0pEO
         ojk8Zx3JHlsIJatQkBVfCtsAFdJJCe+9ucs3lRMf9ufIeoeO66CLweOpg451OogTnCHE
         k1gAlfdpglD81ifVqTpgT5GzLJGhXyXF1YjSWTLobFareT93GVuM7g0MjPgEIvDf6rOp
         6JsjF5vhzCefrJsoO0MRYoxs4itziO2EyWrsdx4IYMat8RkDTfM8dJFe/rb+/f+am/rg
         aGyNNifZNL5/l8qihDxOTQ1IPZL8USy2/ovXVmmbMmlD0qMKYIDJSrhsdd53ULUg7COx
         tu6w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:subject:cc
         :to:from:date:user-agent:message-id:sender:dkim-signature;
        bh=EGgx9XSC3pyfZneagjTfJYn5ZUa0Ab8Udr+QRKtUa64=;
        b=jiG4z82nmwp9FctGZFFLof1yM0YhxE7ceQxj+Tr8eU/R/BiY+z+mQX20hY/+JuwfFI
         jE0r2sABFIsg1oYNOlnAMNkgvRVyCHsQfs75eEMwO0jwTTxcueo2TA3HszApvBZYjotq
         poXHr3Jq9gEcInlIqYW9vsKu9ueKyBcITB3YdZ6QByRb4bgxw4sTeizKzbjpTVX7p65T
         EXrJzoYIh7OxF6RJannUbtteXoTp4fS5viJxP2zOwRR7/iAQ/312oT9+5G3H9mznTVwi
         XCpGeQs0SByauR5V3ecRocjxdu59tu3J0NJtxRwYZfCgUWosAqw2K5Oh9zHhWbrQ3Jwc
         TM4A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=dV5VKjJC;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:subject:cc:to:from:date
         :user-agent:message-id:sender:from:to:cc:subject:date;
        bh=EGgx9XSC3pyfZneagjTfJYn5ZUa0Ab8Udr+QRKtUa64=;
        b=YsRLeVKnoVi7SH5D/Q8rzRBqzv14K1gcg2knm7ll/vErvOR60Hs/4NhvpeiqdSEHnh
         wNUEba+N1VPvdxQ+A6tiQUsKv0cq0ldjcJwMhpVJbSnrseLxB4DrDYcsNl14omO9704H
         PsaWCUiJ+bKr1gCdjz7JWzvBbFZ2Soy2VvdskQqA8EdqEYitaHcy4SQkdAB/4XbdLeQX
         Lj8ou8Bp+i3c7RN3oBCJ5VApF1wma57sjtFnW0CWSAzeBCIAlJkCa4MZ52VJSa4z2i+s
         xWij50h66IMdyXsqYWxXKi4d/UadmdDXKD9ydMEwrE75EE5rjiGpJIrt5LJ+3t5OfFMJ
         XMnQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:subject:cc:to:from:date:user-agent:message-id
         :x-gm-message-state:sender:from:to:cc:subject:date;
        bh=EGgx9XSC3pyfZneagjTfJYn5ZUa0Ab8Udr+QRKtUa64=;
        b=DUgDtfWgFlkAKQw8HDBDIF0eGYt0c7k1WJBh+JuWrDvF2g1BGfiHgKiUHnyMjtvslO
         BTwiV6GhtfCCYjVxd/6xpKUTy2Sq9Xt4ywq1yabkNUs0q8IqB1zLkcvR7MyE1rCmRAGI
         ICEpnybG0M0txcwwALTPm6Rm0gK2EieKLbUrxBui2l52NvMPmYN59vUTHhwmOrOrbW0g
         fOx0cfLA/GpAcKbE6CjX7I1/xgceViPPGHc0j0FGmEHfzJ/icipSBW5F+g5+MFhrs2zW
         8hCwjGMU4YnoHPUU+CKQ6/ExHHXUisBVgqpyNNdXm1jyxLXl4R4yqZ7l1nNNpAPZoezL
         rGqA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf3baZVUP15BqtTRyTH4rgb6jdfq3+s0j09PO+DC00G4agDh68xb
	VnY/2tmnBEhpTulRHDPJTl0=
X-Google-Smtp-Source: AMsMyM75o1RMwDc9fywW5fMTDX7DAJQjXVwa1MwMaUrLZKBrOkgv/IkjyRXcyQ3u/Jl4JGzGmI9Ung==
X-Received: by 2002:a05:600c:2241:b0:3b4:88aa:dcba with SMTP id a1-20020a05600c224100b003b488aadcbamr11953998wmm.203.1663582657785;
        Mon, 19 Sep 2022 03:17:37 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:c5:b0:3b3:1ac5:fc2c with SMTP id
 u5-20020a05600c00c500b003b31ac5fc2cls1735315wmm.1.-pod-prod-gmail; Mon, 19
 Sep 2022 03:17:36 -0700 (PDT)
X-Received: by 2002:a05:600c:3d0c:b0:3b4:c481:c63b with SMTP id bh12-20020a05600c3d0c00b003b4c481c63bmr6915301wmb.147.1663582656571;
        Mon, 19 Sep 2022 03:17:36 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1663582656; cv=none;
        d=google.com; s=arc-20160816;
        b=MIbgYUjZH0W35K1omKd6kmP8ObIDkKd9EhxG7uW9giKk1M87XlQDFSj4e9N3f+tKFB
         2pHiJf/gqCXDmhkTn6IuhdKLJ/8XYbBihwnZjzsjcU1Um+kTBjYqeq3DCmfIbVy+h6R/
         1wm04uUi45kyM5n1AKwSLH8VVA5DlOu1bi50oPvkMxqhXE8fTZ/SbiaP9IrE9/89lc+5
         DTJ61/UNj4KShEqnHorfx+E3BXP/6zuopeKhRKKgmViJotk6mNeDfRSQeUot60ZzxWTu
         YQ84EAy1V6L/AFCH7JxR2lZ741GLciS1cn0EcI2SCgfqaWyZly776QjdMAp//tMTb2ZV
         +s4w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:subject:cc:to:from:date:user-agent
         :message-id:dkim-signature;
        bh=o5HILV8lXWZVR34kQkfXu7ELtM3PHvDf12JWqGFz8as=;
        b=R18MQdSxwW6qW7Wab+Wpj/swSLIJi4cEwNUYoVLPMaJbpFiv2jPK7o4HF1sHht/gP/
         kjgIzfGnaFgh15tOVfs1QKBsv2fyPpIErxxtIB2tNa+CUk3T0i7uB7YdcLKGRs0otM5x
         jhEz/eJE7waWPYfYyeMp2TWaUDjQMce8I/1VL3694v131ixwsreVUxwQv2H1gse4Rcpg
         A5TEpBGMl28GjSmvgvRPWnxnDRMSmDbSyGVG2bdMjCksSzXRKeQ6svXXCBYuTTyzbW5K
         Hk9HkdVlU6VNfgFOSz3HsDbyp/ACUKzzk0SZ0mRh56lSgsx22YTQBZFlfzD7cPlcUn2h
         U6Ew==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=dV5VKjJC;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from casper.infradead.org (casper.infradead.org. [2001:8b0:10b:1236::1])
        by gmr-mx.google.com with ESMTPS id 4-20020a05600c020400b003a83f11cec0si201749wmi.2.2022.09.19.03.17.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 19 Sep 2022 03:17:36 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) client-ip=2001:8b0:10b:1236::1;
Received: from j130084.upc-j.chello.nl ([24.132.130.84] helo=noisy.programming.kicks-ass.net)
	by casper.infradead.org with esmtpsa (Exim 4.94.2 #2 (Red Hat Linux))
	id 1oaDq7-004b9C-BF; Mon, 19 Sep 2022 10:17:23 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id 4246B302F32;
	Mon, 19 Sep 2022 12:16:25 +0200 (CEST)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 0)
	id 5B7DB2BAC75A2; Mon, 19 Sep 2022 12:16:22 +0200 (CEST)
Message-ID: <20220919101522.156951075@infradead.org>
User-Agent: quilt/0.66
Date: Mon, 19 Sep 2022 12:00:06 +0200
From: Peter Zijlstra <peterz@infradead.org>
To: peterz@infradead.org
Cc: richard.henderson@linaro.org,
 ink@jurassic.park.msu.ru,
 mattst88@gmail.com,
 vgupta@kernel.org,
 linux@armlinux.org.uk,
 ulli.kroll@googlemail.com,
 linus.walleij@linaro.org,
 shawnguo@kernel.org,
 Sascha Hauer <s.hauer@pengutronix.de>,
 kernel@pengutronix.de,
 festevam@gmail.com,
 linux-imx@nxp.com,
 tony@atomide.com,
 khilman@kernel.org,
 catalin.marinas@arm.com,
 will@kernel.org,
 guoren@kernel.org,
 bcain@quicinc.com,
 chenhuacai@kernel.org,
 kernel@xen0n.name,
 geert@linux-m68k.org,
 sammy@sammy.net,
 monstr@monstr.eu,
 tsbogend@alpha.franken.de,
 dinguyen@kernel.org,
 jonas@southpole.se,
 stefan.kristiansson@saunalahti.fi,
 shorne@gmail.com,
 James.Bottomley@HansenPartnership.com,
 deller@gmx.de,
 mpe@ellerman.id.au,
 npiggin@gmail.com,
 christophe.leroy@csgroup.eu,
 paul.walmsley@sifive.com,
 palmer@dabbelt.com,
 aou@eecs.berkeley.edu,
 hca@linux.ibm.com,
 gor@linux.ibm.com,
 agordeev@linux.ibm.com,
 borntraeger@linux.ibm.com,
 svens@linux.ibm.com,
 ysato@users.sourceforge.jp,
 dalias@libc.org,
 davem@davemloft.net,
 richard@nod.at,
 anton.ivanov@cambridgegreys.com,
 johannes@sipsolutions.net,
 tglx@linutronix.de,
 mingo@redhat.com,
 bp@alien8.de,
 dave.hansen@linux.intel.com,
 x86@kernel.org,
 hpa@zytor.com,
 acme@kernel.org,
 mark.rutland@arm.com,
 alexander.shishkin@linux.intel.com,
 jolsa@kernel.org,
 namhyung@kernel.org,
 jgross@suse.com,
 srivatsa@csail.mit.edu,
 amakhalov@vmware.com,
 pv-drivers@vmware.com,
 boris.ostrovsky@oracle.com,
 chris@zankel.net,
 jcmvbkbc@gmail.com,
 rafael@kernel.org,
 lenb@kernel.org,
 pavel@ucw.cz,
 gregkh@linuxfoundation.org,
 mturquette@baylibre.com,
 sboyd@kernel.org,
 daniel.lezcano@linaro.org,
 lpieralisi@kernel.org,
 sudeep.holla@arm.com,
 agross@kernel.org,
 bjorn.andersson@linaro.org,
 konrad.dybcio@somainline.org,
 anup@brainfault.org,
 thierry.reding@gmail.com,
 jonathanh@nvidia.com,
 jacob.jun.pan@linux.intel.com,
 atishp@atishpatra.org,
 Arnd Bergmann <arnd@arndb.de>,
 yury.norov@gmail.com,
 andriy.shevchenko@linux.intel.com,
 linux@rasmusvillemoes.dk,
 dennis@kernel.org,
 tj@kernel.org,
 cl@linux.com,
 rostedt@goodmis.org,
 pmladek@suse.com,
 senozhatsky@chromium.org,
 john.ogness@linutronix.de,
 juri.lelli@redhat.com,
 vincent.guittot@linaro.org,
 dietmar.eggemann@arm.com,
 bsegall@google.com,
 mgorman@suse.de,
 bristot@redhat.com,
 vschneid@redhat.com,
 fweisbec@gmail.com,
 ryabinin.a.a@gmail.com,
 glider@google.com,
 andreyknvl@gmail.com,
 dvyukov@google.com,
 vincenzo.frascino@arm.com,
 Andrew Morton <akpm@linux-foundation.org>,
 jpoimboe@kernel.org,
 linux-alpha@vger.kernel.org,
 linux-kernel@vger.kernel.org,
 linux-snps-arc@lists.infradead.org,
 linux-omap@vger.kernel.org,
 linux-csky@vger.kernel.org,
 linux-hexagon@vger.kernel.org,
 linux-ia64@vger.kernel.org,
 loongarch@lists.linux.dev,
 linux-m68k@lists.linux-m68k.org,
 linux-mips@vger.kernel.org,
 openrisc@lists.librecores.org,
 linux-parisc@vger.kernel.org,
 linuxppc-dev@lists.ozlabs.org,
 linux-riscv@lists.infradead.org,
 linux-s390@vger.kernel.org,
 linux-sh@vger.kernel.org,
 sparclinux@vger.kernel.org,
 linux-um@lists.infradead.org,
 linux-perf-users@vger.kernel.org,
 virtualization@lists.linux-foundation.org,
 linux-xtensa@linux-xtensa.org,
 linux-acpi@vger.kernel.org,
 linux-pm@vger.kernel.org,
 linux-clk@vger.kernel.org,
 linux-arm-msm@vger.kernel.org,
 linux-tegra@vger.kernel.org,
 linux-arch@vger.kernel.org,
 kasan-dev@googlegroups.com
Subject: [PATCH v2 27/44] cpuidle,sched: Remove annotations from TIF_{POLLING_NRFLAG,NEED_RESCHED}
References: <20220919095939.761690562@infradead.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=casper.20170209 header.b=dV5VKjJC;
       spf=pass (google.com: best guess record for domain of
 peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
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

vmlinux.o: warning: objtool: mwait_idle+0x5: call to current_set_polling_and_test() leaves .noinstr.text section
vmlinux.o: warning: objtool: acpi_processor_ffh_cstate_enter+0xc5: call to current_set_polling_and_test() leaves .noinstr.text section
vmlinux.o: warning: objtool: cpu_idle_poll.isra.0+0x73: call to test_ti_thread_flag() leaves .noinstr.text section
vmlinux.o: warning: objtool: intel_idle+0xbc: call to current_set_polling_and_test() leaves .noinstr.text section
vmlinux.o: warning: objtool: intel_idle_irq+0xea: call to current_set_polling_and_test() leaves .noinstr.text section
vmlinux.o: warning: objtool: intel_idle_s2idle+0xb4: call to current_set_polling_and_test() leaves .noinstr.text section

vmlinux.o: warning: objtool: intel_idle+0xa6: call to current_clr_polling() leaves .noinstr.text section
vmlinux.o: warning: objtool: intel_idle_irq+0xbf: call to current_clr_polling() leaves .noinstr.text section
vmlinux.o: warning: objtool: intel_idle_s2idle+0xa1: call to current_clr_polling() leaves .noinstr.text section

vmlinux.o: warning: objtool: mwait_idle+0xe: call to __current_set_polling() leaves .noinstr.text section
vmlinux.o: warning: objtool: acpi_processor_ffh_cstate_enter+0xc5: call to __current_set_polling() leaves .noinstr.text section
vmlinux.o: warning: objtool: cpu_idle_poll.isra.0+0x73: call to test_ti_thread_flag() leaves .noinstr.text section
vmlinux.o: warning: objtool: intel_idle+0xbc: call to __current_set_polling() leaves .noinstr.text section
vmlinux.o: warning: objtool: intel_idle_irq+0xea: call to __current_set_polling() leaves .noinstr.text section
vmlinux.o: warning: objtool: intel_idle_s2idle+0xb4: call to __current_set_polling() leaves .noinstr.text section

vmlinux.o: warning: objtool: cpu_idle_poll.isra.0+0x73: call to test_ti_thread_flag() leaves .noinstr.text section
vmlinux.o: warning: objtool: intel_idle_s2idle+0x73: call to test_ti_thread_flag.constprop.0() leaves .noinstr.text section
vmlinux.o: warning: objtool: intel_idle_irq+0x91: call to test_ti_thread_flag.constprop.0() leaves .noinstr.text section
vmlinux.o: warning: objtool: intel_idle+0x78: call to test_ti_thread_flag.constprop.0() leaves .noinstr.text section
vmlinux.o: warning: objtool: acpi_safe_halt+0xf: call to test_ti_thread_flag.constprop.0() leaves .noinstr.text section

Signed-off-by: Peter Zijlstra (Intel) <peterz@infradead.org>
---
 include/linux/sched/idle.h  |   40 ++++++++++++++++++++++++++++++----------
 include/linux/thread_info.h |   18 +++++++++++++++++-
 2 files changed, 47 insertions(+), 11 deletions(-)

--- a/include/linux/sched/idle.h
+++ b/include/linux/sched/idle.h
@@ -23,12 +23,37 @@ static inline void wake_up_if_idle(int c
  */
 #ifdef TIF_POLLING_NRFLAG
 
-static inline void __current_set_polling(void)
+#ifdef _ASM_GENERIC_BITOPS_INSTRUMENTED_ATOMIC_H
+
+static __always_inline void __current_set_polling(void)
 {
-	set_thread_flag(TIF_POLLING_NRFLAG);
+	arch_set_bit(TIF_POLLING_NRFLAG,
+		     (unsigned long *)(&current_thread_info()->flags));
 }
 
-static inline bool __must_check current_set_polling_and_test(void)
+static __always_inline void __current_clr_polling(void)
+{
+	arch_clear_bit(TIF_POLLING_NRFLAG,
+		       (unsigned long *)(&current_thread_info()->flags));
+}
+
+#else
+
+static __always_inline void __current_set_polling(void)
+{
+	set_bit(TIF_POLLING_NRFLAG,
+		(unsigned long *)(&current_thread_info()->flags));
+}
+
+static __always_inline void __current_clr_polling(void)
+{
+	clear_bit(TIF_POLLING_NRFLAG,
+		  (unsigned long *)(&current_thread_info()->flags));
+}
+
+#endif /* _ASM_GENERIC_BITOPS_INSTRUMENTED_ATOMIC_H */
+
+static __always_inline bool __must_check current_set_polling_and_test(void)
 {
 	__current_set_polling();
 
@@ -41,12 +66,7 @@ static inline bool __must_check current_
 	return unlikely(tif_need_resched());
 }
 
-static inline void __current_clr_polling(void)
-{
-	clear_thread_flag(TIF_POLLING_NRFLAG);
-}
-
-static inline bool __must_check current_clr_polling_and_test(void)
+static __always_inline bool __must_check current_clr_polling_and_test(void)
 {
 	__current_clr_polling();
 
@@ -73,7 +93,7 @@ static inline bool __must_check current_
 }
 #endif
 
-static inline void current_clr_polling(void)
+static __always_inline void current_clr_polling(void)
 {
 	__current_clr_polling();
 
--- a/include/linux/thread_info.h
+++ b/include/linux/thread_info.h
@@ -177,7 +177,23 @@ static __always_inline unsigned long rea
 	clear_ti_thread_flag(task_thread_info(t), TIF_##fl)
 #endif /* !CONFIG_GENERIC_ENTRY */
 
-#define tif_need_resched() test_thread_flag(TIF_NEED_RESCHED)
+#ifdef _ASM_GENERIC_BITOPS_INSTRUMENTED_NON_ATOMIC_H
+
+static __always_inline bool tif_need_resched(void)
+{
+	return arch_test_bit(TIF_NEED_RESCHED,
+			     (unsigned long *)(&current_thread_info()->flags));
+}
+
+#else
+
+static __always_inline bool tif_need_resched(void)
+{
+	return test_bit(TIF_NEED_RESCHED,
+			(unsigned long *)(&current_thread_info()->flags));
+}
+
+#endif /* _ASM_GENERIC_BITOPS_INSTRUMENTED_NON_ATOMIC_H */
 
 #ifndef CONFIG_HAVE_ARCH_WITHIN_STACK_FRAMES
 static inline int arch_within_stack_frames(const void * const stack,


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220919101522.156951075%40infradead.org.
