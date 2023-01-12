Return-Path: <kasan-dev+bncBDBK55H2UQKRB2WMQGPAMGQE5YWVWIY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33c.google.com (mail-wm1-x33c.google.com [IPv6:2a00:1450:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id D51DA667FE9
	for <lists+kasan-dev@lfdr.de>; Thu, 12 Jan 2023 20:58:34 +0100 (CET)
Received: by mail-wm1-x33c.google.com with SMTP id l9-20020a7bc349000000b003d35aa4ed8esf4488941wmj.0
        for <lists+kasan-dev@lfdr.de>; Thu, 12 Jan 2023 11:58:34 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1673553514; cv=pass;
        d=google.com; s=arc-20160816;
        b=eZfK6fELCILrbpwhS9kGdVUR7Cpqg3o6ELleHXkBKxIp28WFJo6jV1VPIkzOdwWOcT
         y7TJJqTbJrEbu9KdHDko/Tb57iP//aDyqbniJdhdizwo6wLVh3PF8yWcye7ez5oTt0zL
         Sf6AB6MQjxthMRa4eDQcIYkrnuJElfIaBxA5GoALZBoYGttc2uH0rF5RQ/4dMoWTqzQf
         u9NmhLFQjWqxkbGDpm6ExllxL+noC7q2pRFyaCzMnBGmrgBtqbHdNNtWYiPMr49rgcIb
         5C1eRHk1FjthTQWTIr/SyFa5gW7oQujg/FFpsmRJuZlM1qg4tMubiRJWCKIxicmMUoHi
         Xp2A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:subject:cc
         :to:from:date:user-agent:message-id:sender:dkim-signature;
        bh=w+TXnD9BlKnSHBAvJuXskCnpNZ7ftkmUaNwi126jSbs=;
        b=xWJ/TlkAQqhor+wYSlOwE4hn45zMVMC3QYDoKVJuBOwJVyOu8i9eotcWAfRgvexXKR
         QIF158n2UNlwGIjH7ONBL+fDJw8DU0JciGPzfDvZphzr6SgH4S7Mc+MEnbqScFpKgz6d
         /odePuwV8oqZBIFQNs5XxmX0Ypi814skNgT0ju6CtSsEIpN+tKjuUJrU5cy6p2DiBOCk
         NT/nAvkJwS1oDUJhRiZYzzo2gw8d2MZzmLD6dCwDUAEhmBauwFYbg5xunZpDcef7LYoJ
         3dZM2xXY5vF+7/jrwpFo117uiFRWdSoocnW2zZ9WriiLpnOHhdpd3ompJuwCZQ/nutxU
         fbfQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=BJ9XJoRA;
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:subject:cc:to:from:date
         :user-agent:message-id:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=w+TXnD9BlKnSHBAvJuXskCnpNZ7ftkmUaNwi126jSbs=;
        b=QyDqi8MVJK3Oft5lxKCojbSuybsf2hCH04OQH8Qpcl9dDIGvBLJ7BAjQhhYf8LnPiw
         WLHW2YhA5jAMKCNovtxSpB5hDap/lVWCgfrbnffqnWWUvq60yiTsx2bBRa81/LkCbpr2
         CrCV2xWib/8QAyQh5LK+n6d+jklhZ6lNmwCK0MYRkg5D6gu45NnIUVFkQHtdLTlkojhT
         Auc4bVUndim4IiWPuDNGRTg+MRwrRmeA3oK3UmoM+su2R6Ec35tQxKIL4HqhJbNSl1/2
         RxrIXzQYs75nMCEsQ7ZMSwyX/AfyaVTZH1jILs3Mj5BB43gmQU3N2WktRosPZU28M4BG
         TnsQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:subject:cc:to:from:date:user-agent:message-id
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=w+TXnD9BlKnSHBAvJuXskCnpNZ7ftkmUaNwi126jSbs=;
        b=T0CFbcPsc3hNFGIHZSqIi/iKHddnimdiJCMSpu+meYannsJrXwR/2dWAnX/6x+6mkM
         n0WDBAm6alzYK8gT/on7HoiCOQ6PfFOefnCC6GUc8RlkEdQKFQ721aKiCjMBB3SEhSNI
         cS3rAeZbUK3h7qmvqEvlZfpvqpS2x0LzMX6L8NIbrIOezp6BWjbBCj42gOJ1z3+6w1Bq
         a5DDf6I2+0UJXmlMN6A2KwslCiQDT0OIHDDo4eryX+5LLebbTWvHSjBK0FzVi8S31RJ5
         YI2jRIwF9oESaHyec/zEWjUwgMaiy7SgIrnhHMbUhq1RnzBqvAlAQW48CaQOCd8TzF9z
         x4HQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2kquM7HxE0cBiosVh4iKZ3uMX4xMHja/GGuSJurjCWoVSnmR+h01
	d9xhVRsRmmDgZFbPK+6iCAg=
X-Google-Smtp-Source: AMrXdXuBRoJWASqh0Whf2De6utQCzeGU4MCezEqcvNz+llDPKHGwwt8s+JDgEfxOjE4qxQ11wE6YqQ==
X-Received: by 2002:a5d:6a0b:0:b0:2bb:ea8c:ac79 with SMTP id m11-20020a5d6a0b000000b002bbea8cac79mr663367wru.293.1673553514387;
        Thu, 12 Jan 2023 11:58:34 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:3b0c:b0:3cf:72dc:df8 with SMTP id
 m12-20020a05600c3b0c00b003cf72dc0df8ls2948678wms.0.-pod-canary-gmail; Thu, 12
 Jan 2023 11:58:33 -0800 (PST)
X-Received: by 2002:a05:600c:4e51:b0:3cf:7b8b:6521 with SMTP id e17-20020a05600c4e5100b003cf7b8b6521mr55926653wmq.32.1673553513266;
        Thu, 12 Jan 2023 11:58:33 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1673553513; cv=none;
        d=google.com; s=arc-20160816;
        b=wf9ZFt5yzbW5XPtSZTINTsVP937urPBOd/e9+U8/ZZIRMxex8WT8pVqSMfe2jEYqjV
         wa0dNfKi+L1mBg9Ar1dqlM/jHrpNxpCZ5AuJdLvxeTeDdKwh50+bais+nsFnN3/FRqBe
         tzdsU6bb+C+/gccpTmn8hItl3Vjdp9MQy9Omu7Q4+rhRiMDuD4qeKc2t8bSCkcFOrDLW
         vdfwCjLnfkpPt28zbJo6vl/hFsonbqG0P3BWQBQqfAkN1YV1m4GtYuW9HSqDn2K/9l5Z
         6xywYhv0YbNn7FWqqSvnabW59PoB7svu2ggor9xroAny9L+weTcW9ONVvXi/4XCSuoUO
         GdyQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:subject:cc:to:from:date:user-agent
         :message-id:dkim-signature;
        bh=tM6S3oZ3zLjQ2zmmTNKitB7HqpfpXnjxYwChM2FqbVs=;
        b=Bw8rBjcAy/C9iNfaaQCveaxPWfkOSESqrHQR1LTv4JTPx4lN81fqif5iWVpjb1hPNn
         HxiZeBdQ0TqnsxN/ruULD7QC+tuJPI19lcXzern2QN+beViCXgsn3TahZtpy/nMWYqCz
         hfmSv56mNwdGhg9cAmjssZH5C8vzJCyUw8E/4hECrtrJ3lLmEwHwB3mTv4LYEzETZxNN
         fAicu7VIq/xqls5PiFb6bec2qFyNl5rj910niTTx8JlFycj8JZ+qYeAi2xHN/juwfV72
         S8ANXxIMU1YNhY3lVA5v1scoX/42FE65xUXrBdNPGQyALFQM8ftO9JQ2BlQBWGrPQ5dx
         JOpg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=BJ9XJoRA;
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
Received: from casper.infradead.org (casper.infradead.org. [2001:8b0:10b:1236::1])
        by gmr-mx.google.com with ESMTPS id v6-20020a1cf706000000b003d9ae6cfd2esi918073wmh.2.2023.01.12.11.58.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 12 Jan 2023 11:58:33 -0800 (PST)
Received-SPF: none (google.com: infradead.org does not designate permitted sender hosts) client-ip=2001:8b0:10b:1236::1;
Received: from j130084.upc-j.chello.nl ([24.132.130.84] helo=noisy.programming.kicks-ass.net)
	by casper.infradead.org with esmtpsa (Exim 4.94.2 #2 (Red Hat Linux))
	id 1pG3hh-005Okc-KK; Thu, 12 Jan 2023 19:57:37 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id 096C630346B;
	Thu, 12 Jan 2023 20:57:14 +0100 (CET)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 0)
	id 573AE2CD066CC; Thu, 12 Jan 2023 20:57:08 +0100 (CET)
Message-ID: <20230112195541.906007455@infradead.org>
User-Agent: quilt/0.66
Date: Thu, 12 Jan 2023 20:43:56 +0100
From: Peter Zijlstra <peterz@infradead.org>
To: peterz@infradead.org
Cc: richard.henderson@linaro.org,
 ink@jurassic.park.msu.ru,
 mattst88@gmail.com,
 vgupta@kernel.org,
 linux@armlinux.org.uk,
 nsekhar@ti.com,
 brgl@bgdev.pl,
 ulli.kroll@googlemail.com,
 linus.walleij@linaro.org,
 shawnguo@kernel.org,
 Sascha Hauer <s.hauer@pengutronix.de>,
 kernel@pengutronix.de,
 festevam@gmail.com,
 linux-imx@nxp.com,
 tony@atomide.com,
 khilman@kernel.org,
 krzysztof.kozlowski@linaro.org,
 alim.akhtar@samsung.com,
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
 andersson@kernel.org,
 konrad.dybcio@linaro.org,
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
 mhiramat@kernel.org,
 frederic@kernel.org,
 paulmck@kernel.org,
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
 linux-samsung-soc@vger.kernel.org,
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
 linux-mm@kvack.org,
 linux-trace-kernel@vger.kernel.org,
 kasan-dev@googlegroups.com,
 "Rafael J. Wysocki" <rafael.j.wysocki@intel.com>,
 Ulf Hansson <ulf.hansson@linaro.org>
Subject: [PATCH v3 42/51] ubsan: Fix objtool UACCESS warns
References: <20230112194314.845371875@infradead.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=casper.20170209 header.b=BJ9XJoRA;
       spf=none (google.com: infradead.org does not designate permitted sender
 hosts) smtp.mailfrom=peterz@infradead.org
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

clang-14 allyesconfig gives:

vmlinux.o: warning: objtool: emulator_cmpxchg_emulated+0x705: call to __ubsan_handle_load_invalid_value() with UACCESS enabled
vmlinux.o: warning: objtool: paging64_update_accessed_dirty_bits+0x39e: call to __ubsan_handle_load_invalid_value() with UACCESS enabled
vmlinux.o: warning: objtool: paging32_update_accessed_dirty_bits+0x390: call to __ubsan_handle_load_invalid_value() with UACCESS enabled
vmlinux.o: warning: objtool: ept_update_accessed_dirty_bits+0x43f: call to __ubsan_handle_load_invalid_value() with UACCESS enabled

Add the required eflags save/restore and whitelist the thing.

Signed-off-by: Peter Zijlstra (Intel) <peterz@infradead.org>
Acked-by: Rafael J. Wysocki <rafael.j.wysocki@intel.com>
Acked-by: Frederic Weisbecker <frederic@kernel.org>
Tested-by: Tony Lindgren <tony@atomide.com>
Tested-by: Ulf Hansson <ulf.hansson@linaro.org>
---
 lib/ubsan.c           |    5 ++++-
 tools/objtool/check.c |    1 +
 2 files changed, 5 insertions(+), 1 deletion(-)

--- a/lib/ubsan.c
+++ b/lib/ubsan.c
@@ -340,9 +340,10 @@ void __ubsan_handle_load_invalid_value(v
 {
 	struct invalid_value_data *data = _data;
 	char val_str[VALUE_LENGTH];
+	unsigned long ua_flags = user_access_save();
 
 	if (suppress_report(&data->location))
-		return;
+		goto out;
 
 	ubsan_prologue(&data->location, "invalid-load");
 
@@ -352,6 +353,8 @@ void __ubsan_handle_load_invalid_value(v
 		val_str, data->type->type_name);
 
 	ubsan_epilogue();
+out:
+	user_access_restore(ua_flags);
 }
 EXPORT_SYMBOL(__ubsan_handle_load_invalid_value);
 
--- a/tools/objtool/check.c
+++ b/tools/objtool/check.c
@@ -1068,6 +1068,7 @@ static const char *uaccess_safe_builtin[
 	"__ubsan_handle_type_mismatch",
 	"__ubsan_handle_type_mismatch_v1",
 	"__ubsan_handle_shift_out_of_bounds",
+	"__ubsan_handle_load_invalid_value",
 	/* misc */
 	"csum_partial_copy_generic",
 	"copy_mc_fragile",


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230112195541.906007455%40infradead.org.
