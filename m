Return-Path: <kasan-dev+bncBDBK55H2UQKRB36MQGPAMGQEA3JMCHI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13c.google.com (mail-lf1-x13c.google.com [IPv6:2a00:1450:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id A304666800F
	for <lists+kasan-dev@lfdr.de>; Thu, 12 Jan 2023 20:58:40 +0100 (CET)
Received: by mail-lf1-x13c.google.com with SMTP id bq3-20020a056512150300b004b9c5dff97bsf7353135lfb.17
        for <lists+kasan-dev@lfdr.de>; Thu, 12 Jan 2023 11:58:40 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1673553520; cv=pass;
        d=google.com; s=arc-20160816;
        b=zrUwkKtj+0vauZg04UlJx5iEYtSS3yLpKG8IBX+s1dAHjuDPAEBe1x9MYdEigZwZT3
         NPhDL7EURclgJZ9Xre4ZzTWGkfdHCxuQeuV6iysn4rTAxr7QU9hCkw078nufz/ADOYeI
         8IrknThasGeE/GAs5ZdsuNKramJXIE+0LZkW9rDL4wTgSv3ecOsVF6IY2UiZeqTYN7Sz
         ToLcNl9aBU2Tz6gY6V/DlbMs8DIu2T0kQ/xpZrm9vYUMXs2jNmLA9XyLkiA8NlJ9rZDi
         aQJx1WVuQqKJbh1ASoJClc9cM+cfZORTFT2To4na3jMLFG5ShKyX00rxmCBVX0F4/kfa
         zfew==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:subject:cc
         :to:from:date:user-agent:message-id:sender:dkim-signature;
        bh=zAGLEFMANXr+Tdu/QUEsXCgWVBFOzm9jHVx4l76S/W8=;
        b=ofN6DYINHbFaATSfwTXNhbGUNSE4vLJiOz44nsv1U9uFZmdVTm0x/FVUui3eVhcBGN
         uxtqEv/YWPN9Q1cCgF+6ICk4ym+B13OMUAZWWef0AnG0Dym3UU+Xw/mAiOzEI/zMyoLp
         ELwZTLRTtyBYAwxZaKOJJlNwW0kIi0aQFAgDXp5Xdb9Pq93NLNK9nGyO2LWmENRCz66+
         k0vD9aU92C+rvlZ9lLIP/u8LfH4DZ9dz9xdL5GWC/t54U0V9NelmwmJoZyuZ6hUR0bu5
         EjzJbGwP08+QN3epwuqafL3AKfTSfOBj3ZXbwIjoZ+AHK4iLeu5xFUNm/F8ily8Ren2N
         LW0w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=WVuIFhrj;
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:subject:cc:to:from:date
         :user-agent:message-id:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=zAGLEFMANXr+Tdu/QUEsXCgWVBFOzm9jHVx4l76S/W8=;
        b=fyoIc6/xPWcIYSLFSUsms4It+rT9EWPe3JeaNiDye8OAWoHjdefKYwnNT/iHhPSfU8
         5FR7wPBxtmnZj6NThgqdgWmwSsheVNwZfbN5mWY9KYmJZg95gw3xourZAdXiQYkS3dQN
         ExkY+sjM75/DH1hg2Jdp61pt1Lv0UYrQCXAgd39eNn/4fl47TU7QbPaOBE6RdZUiG/Tq
         /Z0rqhZH7+Qv5bXZlUIaTdAY6HhtLsB4KZNs3YUilMD+AFzct+fwSbmdDn6uVgSG3Zin
         8WJVieAuKzEMNPG7Rw+hdnotmKkw84Q7siN83XrDwahgj3KNVI/ibVNvk2eM0A4DOQH9
         5Wtw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:subject:cc:to:from:date:user-agent:message-id
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=zAGLEFMANXr+Tdu/QUEsXCgWVBFOzm9jHVx4l76S/W8=;
        b=jTmbRrantgnhNHMPphVG/4Wn2azMVkglTzPaCAAaIbhoduLyVVgO+/ebsNxE9TQzmS
         aUQKgiT3M49/110xKuElYciCXcTEbBwEbE+l7sSsNzP5OrlUQIcJ7aQuXxrnSDjbGeEm
         8Vx3igUb4IzCMkIzJ7irdF/E0qAHiWb3wqnQJsJAW6u3bfrK8B+4fmySDANgXO5pKsag
         7xscPGEDYowuWx2Tx/4CBvpwpTCr2vPRC45heBGoDt2DOpzX+JNQnHsnlviXcRXZfR84
         Py8scD7suPG2j+5A8nfRtRdehdQhL3cXWZgwyB1E7j/KrAMWtB/uGH6A/28/4psz/bjh
         0OBw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2kqpMYc6V7DvRJt/IT7Y6PaMlW5u7uFCb+saoYuOHhgtFPIenvDe
	T6LynM3IDq5oqE3LUI3nlqk=
X-Google-Smtp-Source: AMrXdXvzRdj7E4bbs5gAi/rQdTQzNWJX3Chl21h689RKxO/B0ypXHwrwsWKAePbJr0TLXeaQv5AIFQ==
X-Received: by 2002:a2e:7a17:0:b0:282:e42c:b31d with SMTP id v23-20020a2e7a17000000b00282e42cb31dmr1492280ljc.235.1673553520093;
        Thu, 12 Jan 2023 11:58:40 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:214f:b0:4c8:8384:83f3 with SMTP id
 s15-20020a056512214f00b004c8838483f3ls1937564lfr.3.-pod-prod-gmail; Thu, 12
 Jan 2023 11:58:38 -0800 (PST)
X-Received: by 2002:a05:6512:3b87:b0:4a4:68b7:d623 with SMTP id g7-20020a0565123b8700b004a468b7d623mr26857907lfv.10.1673553518866;
        Thu, 12 Jan 2023 11:58:38 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1673553518; cv=none;
        d=google.com; s=arc-20160816;
        b=kx5eQ3RhJcl9u3jN1IuAAUHn7wq3koJDBj7T04t2XBbPVpw6pIPxn3ZDsJXL2csj4T
         Q39cOkZqs55D6VauWpguiSkzgpDGDUN6EJKI0c+0LK3niadiZAP7fURRIAnGWe6xIN6h
         ajU9uRTywtD/ajBXg6d+KsycQ6iKmhjvC2X3u4xUCaGtowQsiaOWSbhK/kXrTZPXo3wF
         hyqzD6gFsDyNw4PtJ/ErRSw/robyrywyi+6bfT0kyDiqbyBPKYJdeczVffW0SwBelwVW
         PCYEx8nx/azHDokVO7exVxFUSOz9Iu+8a5Mev29Ru4YwWv+cc/SKT6UZFe1JmjHh2aVd
         DTiw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:subject:cc:to:from:date:user-agent
         :message-id:dkim-signature;
        bh=US/ew+5Vik6jGnrGGiz1QKoghqD4+Lgz+zGR8hxwH/s=;
        b=JZFu35u82vUlHnu0AIj3dVX85EIgN8ozn6IT5OsSqQvZpH2vU8jsu7WCVhc/Od1fQj
         ba6AOKHuE9ujlhpPRLqW8zx93JaBBfAxBZL3XagX1hfuY3Bor2M6bZV2pTuAkrPvHyG5
         5nDU4CWn8NgDFN9/Mp8UOAFjUq8JlFU15SDKckVqe1E8qPm/vpaCoMb0r9utA1v/oqYu
         cpygI3UJSq8k7aKuWRDUGgsSwDq5SfENEzegjrBkAW5bmN3QgF/6f00ADrDkq7WGhbV5
         DjmanTvXX8pTKJzFUqrXZzK+gTMQtfNLt1+IbdoPpU8aH4vTvtHUhWMWCQ61Ktb7NRwR
         SKog==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=WVuIFhrj;
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
Received: from desiato.infradead.org (desiato.infradead.org. [2001:8b0:10b:1:d65d:64ff:fe57:4e05])
        by gmr-mx.google.com with ESMTPS id a14-20020ac25e6e000000b004cfe6a1a3e7si4477lfr.13.2023.01.12.11.58.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 12 Jan 2023 11:58:38 -0800 (PST)
Received-SPF: none (google.com: infradead.org does not designate permitted sender hosts) client-ip=2001:8b0:10b:1:d65d:64ff:fe57:4e05;
Received: from j130084.upc-j.chello.nl ([24.132.130.84] helo=noisy.programming.kicks-ass.net)
	by desiato.infradead.org with esmtpsa (Exim 4.96 #2 (Red Hat Linux))
	id 1pG3hH-0045pI-2Y;
	Thu, 12 Jan 2023 19:57:25 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id B2F9A303445;
	Thu, 12 Jan 2023 20:57:13 +0100 (CET)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 0)
	id 2953C2CCF62B7; Thu, 12 Jan 2023 20:57:08 +0100 (CET)
Message-ID: <20230112195541.233779815@infradead.org>
User-Agent: quilt/0.66
Date: Thu, 12 Jan 2023 20:43:45 +0100
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
Subject: [PATCH v3 31/51] cpuidle,nospec: Make noinstr clean
References: <20230112194314.845371875@infradead.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=desiato.20200630 header.b=WVuIFhrj;
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

vmlinux.o: warning: objtool: mwait_idle+0x47: call to mds_idle_clear_cpu_buffers() leaves .noinstr.text section
vmlinux.o: warning: objtool: acpi_processor_ffh_cstate_enter+0xa2: call to mds_idle_clear_cpu_buffers() leaves .noinstr.text section
vmlinux.o: warning: objtool: intel_idle+0x91: call to mds_idle_clear_cpu_buffers() leaves .noinstr.text section
vmlinux.o: warning: objtool: intel_idle_s2idle+0x8c: call to mds_idle_clear_cpu_buffers() leaves .noinstr.text section
vmlinux.o: warning: objtool: intel_idle_irq+0xaa: call to mds_idle_clear_cpu_buffers() leaves .noinstr.text section

Signed-off-by: Peter Zijlstra (Intel) <peterz@infradead.org>
Acked-by: Rafael J. Wysocki <rafael.j.wysocki@intel.com>
Acked-by: Frederic Weisbecker <frederic@kernel.org>
Tested-by: Tony Lindgren <tony@atomide.com>
Tested-by: Ulf Hansson <ulf.hansson@linaro.org>
---
 arch/x86/include/asm/nospec-branch.h |    2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

--- a/arch/x86/include/asm/nospec-branch.h
+++ b/arch/x86/include/asm/nospec-branch.h
@@ -310,7 +310,7 @@ static __always_inline void mds_user_cle
  *
  * Clear CPU buffers if the corresponding static key is enabled
  */
-static inline void mds_idle_clear_cpu_buffers(void)
+static __always_inline void mds_idle_clear_cpu_buffers(void)
 {
 	if (static_branch_likely(&mds_idle_clear))
 		mds_clear_cpu_buffers();


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230112195541.233779815%40infradead.org.
