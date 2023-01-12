Return-Path: <kasan-dev+bncBDBK55H2UQKRB3GMQGPAMGQEEHHDFPY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x339.google.com (mail-wm1-x339.google.com [IPv6:2a00:1450:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id 7A942667FFD
	for <lists+kasan-dev@lfdr.de>; Thu, 12 Jan 2023 20:58:37 +0100 (CET)
Received: by mail-wm1-x339.google.com with SMTP id o33-20020a05600c512100b003da1f94e8f7sf127863wms.8
        for <lists+kasan-dev@lfdr.de>; Thu, 12 Jan 2023 11:58:37 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1673553517; cv=pass;
        d=google.com; s=arc-20160816;
        b=Zq9zU/+D1K+KE/TSkUsBdBBa3bChZkBBagzh0BtHZz1IX3gqBiTeXR4YvxlqXkyM4T
         nPlrv6uejmoZXc+tQcT0faA65/8xjRKjag+Ypt+ME2yVbtYFoDVHmBuwVn/ihJqXqmdr
         rIKiMtQaki2kx5HoC2hIJjSwdM1AnqtLDjcg64+QYCh0xlK5fKu+FJyVrUyMq85MsZz8
         8AGTCv0rGB6fD7pQl/iGW6Mu/rnqfW4OEmmukVCLQRRW3NWPvakcsU+kiIecyRCCl/IT
         uUDq5kNmAk7VhVrw2rBvOfigNL765smCzcRNhzOmoAHmUBd5BTE9dOxrz2oWsfowN9BP
         SyKw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:subject:cc
         :to:from:date:user-agent:message-id:sender:dkim-signature;
        bh=xZ9TXfFlgyolttqbgq5p5TdTraFJTS27bUwhme1lLvc=;
        b=dll1xyhhTJu4KBv8z/jsZOX621UPJqzg8HH+2ScPTLHUP4m8TKI93BCzEjqcoeFZ/O
         u35JBNgRvgPAY6/jUSIZ8HR/hzn+ZALRe/LIwG15DBUdvznpV+l5Bp1Bh9gSjpuLuvAM
         68Os7uExOaJVsUSY7kHSBYls+TM1QEwhHzcHXWmD0pfoyWi0xZvd/9D/mG0EKjkj6PiV
         n2X2wsQE7z7SJNfepxvdvXVYibaQZ0JEZfLLBAwHQFipv+yk/ocMPTZvdJvscoogDgK/
         KUvwlN+vi4Jh5pavEdhxxZFNs0Y5GvDcpaFcoyDkulPxGMfPBr7EHM4Vj8lStmZraihG
         Llhw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=kYTEx0rz;
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:subject:cc:to:from:date
         :user-agent:message-id:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=xZ9TXfFlgyolttqbgq5p5TdTraFJTS27bUwhme1lLvc=;
        b=nJ+UD+X2gyLgNufIwrmnYPV08WjNdTNP2gE6hK1rqteGUyK0olCtPmlvTyi89/dgf2
         vNZ/0Zr/p6n/E2sa5pCMH266h6bGyWV/Jqe7UVfOl9PewTLboOQ543O4JEEsAiFQ51qN
         sgnLZbOpkBU5CPs2XIUJykbMq1S93pHa0msmLFITtkJOs4r38j5D1E95pJVKEV9QO5AS
         7mfRQeU8OV+bnLzrFHCNrTRcSMqDecbyXK03GqDcB1bYz+aYFXbc7DVg3A1YV3T5+6ne
         nvxrHE8eKYEZGQJZVkf0aH2mgp3yuU4pjtVjrIaYW9T6tb+RLYAha8E92136hdPVCB0T
         uemg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:subject:cc:to:from:date:user-agent:message-id
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=xZ9TXfFlgyolttqbgq5p5TdTraFJTS27bUwhme1lLvc=;
        b=HDOdVnebZBTYF5ja8ntJS+MBA62TBsbAWZW3n+pBceueBL4tGWPk3cNe2EZ8D6Y7Zu
         9FnVLpquAYSw5+tQTbXFRND3aDIo51m0Sh28rNzG+K1kxoNpg2HmwJLA8LmooX0ZN8wl
         3kdzAMeEpSSD6J1OXxztarHJxPFpaQMLKRuGmdss423fTJrNROK65N3bf2iR0M58wQac
         3jcK7pMVlpNzAn5bR4Wo5ZezAXd8Q8ME0rZX1bCb31Ki8gD3wk3Lxc0VNoYJcFpWiBnD
         MVp8ny/HYcvSguqg1UngXVFayUigY1kJPoWa8k3GbXXmLKypDziRxlV4DOCwTi8Ws55E
         6rLQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2kqH4CkhjnzkzoJZNXyEDRVInLZzrOfhgTFiz478W0q7gl7zOSaO
	wczsgG1VwQkSSS4Nb6K1mIg=
X-Google-Smtp-Source: AMrXdXvOCh67TkSbUxOTdIPGf3N0bC7SJqNhF4lzpfWbJ3lMiARbgm5iYpqtsbHnIp3uOKrwKOJeuw==
X-Received: by 2002:a05:600c:a53:b0:3cf:35c8:289f with SMTP id c19-20020a05600c0a5300b003cf35c8289fmr4980759wmq.153.1673553517098;
        Thu, 12 Jan 2023 11:58:37 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:17d8:b0:3c6:c1ff:1fd with SMTP id
 y24-20020a05600c17d800b003c6c1ff01fdls2949088wmo.2.-pod-canary-gmail; Thu, 12
 Jan 2023 11:58:36 -0800 (PST)
X-Received: by 2002:a05:600c:220c:b0:3d2:3831:e5c4 with SMTP id z12-20020a05600c220c00b003d23831e5c4mr60429375wml.40.1673553515985;
        Thu, 12 Jan 2023 11:58:35 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1673553515; cv=none;
        d=google.com; s=arc-20160816;
        b=yes5aznIwWezIPVkl5/9KnqW7gwZMEX+6jhvKUAZ2snGfFW0MMk/NqMfOAG5sK926L
         zU3vdBgk8dLk+VbnGIaH2Y4M+aDCv6Umz6FP5yTK+DUMEinlrgVEOgwjK9zSoqywnNXA
         GUpbWQNfkEHsfj0LnsjfKsIQ3pXGZc2M/QmoGTF66ASELWtNvzTJ5n+EiqGfUjliiqIG
         iz2rV+kqEWLMnhfk2SnT/RDeDnnFSPQN4KjFwFMQT7TIyCMD9NDADPBoHXBbzguO4wN9
         icMlAn6p0zomwlYAFYlCOeD77jCc6K2z3XS764o5FfAzbUfU94RM5QXh13P5NxwxRCLD
         Cx9g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:subject:cc:to:from:date:user-agent
         :message-id:dkim-signature;
        bh=mHHfLn3ZXDs7+W84iYI4l64Hgzvzv2j66VWrzu7dGbw=;
        b=O0/CgUtCv/mCEZidIeJxaLdmloEltGoCmUBsIYHvKELExBdaytUXexLf7R0HQ/kpIF
         W4aTODI5oOzqXP7wlBdk/YXFaHlxngak0oi/8YCvV2mijm8ZZiaY39LIPJTM5aW3C1VV
         lW03RjxusDLM7nybTN2o2ss3WbxX8j8gAm13vgIk4K/HWz9oWBsDvOqsFHLlZevSHXL2
         /Mt+8xE/A21WK9Zx3AYjveRC2naRAIKVVeBSZVt7MYYv0Rb9QyuVR6EPaJD4Wl2WZSeg
         fTyIOOPa0Jn6GUwQXlno5WcxT5xuYCfYb1MjbYhfqXnVVdzpqlllOugAydRvloncXvb5
         Cs0g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=kYTEx0rz;
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
Received: from desiato.infradead.org (desiato.infradead.org. [2001:8b0:10b:1:d65d:64ff:fe57:4e05])
        by gmr-mx.google.com with ESMTPS id r188-20020a1c2bc5000000b003d9cc2bca83si396437wmr.0.2023.01.12.11.58.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 12 Jan 2023 11:58:35 -0800 (PST)
Received-SPF: none (google.com: infradead.org does not designate permitted sender hosts) client-ip=2001:8b0:10b:1:d65d:64ff:fe57:4e05;
Received: from j130084.upc-j.chello.nl ([24.132.130.84] helo=noisy.programming.kicks-ass.net)
	by desiato.infradead.org with esmtpsa (Exim 4.96 #2 (Red Hat Linux))
	id 1pG3hG-0045ou-02;
	Thu, 12 Jan 2023 19:57:11 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id 84261303433;
	Thu, 12 Jan 2023 20:57:13 +0100 (CET)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 0)
	id 11A262CCF62AB; Thu, 12 Jan 2023 20:57:08 +0100 (CET)
Message-ID: <20230112195540.865735001@infradead.org>
User-Agent: quilt/0.66
Date: Thu, 12 Jan 2023 20:43:39 +0100
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
Subject: [PATCH v3 25/51] printk: Remove trace_.*_rcuidle() usage
References: <20230112194314.845371875@infradead.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=desiato.20200630 header.b=kYTEx0rz;
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

The problem, per commit fc98c3c8c9dc ("printk: use rcuidle console
tracepoint"), was printk usage from the cpuidle path where RCU was
already disabled.

Per the patches earlier in this series, this is no longer the case.

Signed-off-by: Peter Zijlstra (Intel) <peterz@infradead.org>
Reviewed-by: Sergey Senozhatsky <senozhatsky@chromium.org>
Acked-by: Petr Mladek <pmladek@suse.com>
Acked-by: Rafael J. Wysocki <rafael.j.wysocki@intel.com>
Acked-by: Frederic Weisbecker <frederic@kernel.org>
Tested-by: Tony Lindgren <tony@atomide.com>
Tested-by: Ulf Hansson <ulf.hansson@linaro.org>
---
 kernel/printk/printk.c |    2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

--- a/kernel/printk/printk.c
+++ b/kernel/printk/printk.c
@@ -2238,7 +2238,7 @@ static u16 printk_sprint(char *text, u16
 		}
 	}
 
-	trace_console_rcuidle(text, text_len);
+	trace_console(text, text_len);
 
 	return text_len;
 }


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230112195540.865735001%40infradead.org.
