Return-Path: <kasan-dev+bncBDBK55H2UQKRBYEDUGMQMGQEZVUFEAQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33b.google.com (mail-wm1-x33b.google.com [IPv6:2a00:1450:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id BAFFC5BC6CD
	for <lists+kasan-dev@lfdr.de>; Mon, 19 Sep 2022 12:18:08 +0200 (CEST)
Received: by mail-wm1-x33b.google.com with SMTP id e3-20020a05600c218300b003b4e4582006sf367183wme.6
        for <lists+kasan-dev@lfdr.de>; Mon, 19 Sep 2022 03:18:08 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1663582688; cv=pass;
        d=google.com; s=arc-20160816;
        b=J3neXLtMn++kTUXpDqD+0txpoRTrf9UPX4sbQMN6DRGQ+amTjVjPaxTR9++1MCOhuu
         XcujBTD9zvurCVZa4LKlbZ5Mol92X+m6ClO4oZLX0LXWZGRmvnRfv5GRPtM1OkOi+8G2
         eQdpRNYYqzTxB4k5drfbX29+ABiFaR48HgJxZmk/MONzoX1mkeXiMnKNRB9p6k6FuRO2
         RSQ3c0N5yG4+TW9WDsdRS1+ptyEWbQ7UqAO4GVZ36e2k/hbpBG+Q46NorE3P3eRtYmOQ
         nG0loZvcWiX07JB5W8SucAW8S2Ux9N08sNm+C+UGiTDUF7gW9e/V568M25epR9n/HKac
         2jEg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:subject:cc
         :to:from:date:user-agent:message-id:sender:dkim-signature;
        bh=yBpbm3Vf1RxzHcZbmyL+8YZwbfgiOjpM1tbkPlUv4oA=;
        b=yTy0G3HyQu0gj35lmNBHNpRlyhFYqAJ7bKhfqFXEciqqRgBTVUoFKg88EpVGS8iyCB
         KWvSoQDcNrogwCiCkiUCkM3HZyj77rB38mO5ZuknyGvCKyvLMuDcs1guwL9Rri5hAvP1
         Ge2JXfrt0TnSKgvSeGB01ZVqVy6gVmN41xhKIAmsDKQhH+lKAYYdWfdBSR+dbngPTDCJ
         AL8cGqjRhw2romGwS8nmIKvT9VNjuy95N9WLdPtH6NKx2YZwtohR6nxBunLBCqxsG5c5
         KESN4QEmAfwUW+42+qq3FcdER5F9EOlMol0P8UqZkaD6p+BoKYYde1nq9d0w+slcnUZM
         dn3g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b="aME6C/8+";
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:subject:cc:to:from:date
         :user-agent:message-id:sender:from:to:cc:subject:date;
        bh=yBpbm3Vf1RxzHcZbmyL+8YZwbfgiOjpM1tbkPlUv4oA=;
        b=d2SDN/tdNRFrHob3mqTdzYbpQWAan1HC3e7X/v2BGtByux5Jed2/Hx9fg2NvDnltsb
         YxjFC5/FpcbE2GV8PlUiXW8a1mHWLezCq/telIZExV+Xz23DOlZkzqiqBxkvTxEGYpMc
         khy20eS6TqZFunsKwmEkCzBPmu+SxEmONEg538OjiUUMQe17Ro7EnD/AUszNMVV72UvJ
         PCut+qIXcHam5GlgNSAptg4MJC+htrgabiCgT8AnbRrVqVi9EVMbuMcCMNhEy/TK1WAk
         MN8Y8DokGyEHVSSOu0fQ3ajfT/lJuQ51Ykm8NJgK+mH7y6HNaPcPCTpVfRgWymz0j8Kh
         fGCQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:subject:cc:to:from:date:user-agent:message-id
         :x-gm-message-state:sender:from:to:cc:subject:date;
        bh=yBpbm3Vf1RxzHcZbmyL+8YZwbfgiOjpM1tbkPlUv4oA=;
        b=XbwONzWfLZFiyIgkbd6F9GPv7rFZxT2w2WIBI3dAOw0t+1PLEPkCUe9Rf3fJZlJGin
         usrke/xvl9WqPOG3lj9h769pOQhRdosad19FhtwKXUhm1bVvTSMpFtsbsDAjd233+NiI
         V+d01p47StE0XNFKE0Lt+t2cLHmMa5lRHn6IfPvhNVAJtuBRqYX8Z5SlesRksWwP3+IJ
         ju1STy1gl6AZ3gOl7NnkAmRrpZokTWkqWdX2zIGaVlkAWyF5ZfFGXqIRZLlClCPe5cyp
         9+K70xFXo3gEVHAxBdNobyiksQt6k//4P8AIa6xsD9jgEYc/l8uAGB+jWy5u7+gdzrs5
         /f4g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo1jXhUvZoxP/EeQrDVB1+8qfTO9z89ztLk3dE1kz9SsahOsCJVF
	jnw3l2REFXLdknyO4WNgQnY=
X-Google-Smtp-Source: AA6agR5yl7GymIHSuE7grKlIFm6rClzpXZkCX1ShIUk/gJ8nqHzlm7vCF0W8nxciJJL6f2QE6L9XsQ==
X-Received: by 2002:a05:600c:a05:b0:3a6:71e6:47b8 with SMTP id z5-20020a05600c0a0500b003a671e647b8mr18541216wmp.29.1663582688412;
        Mon, 19 Sep 2022 03:18:08 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:695:b0:22b:e6:7bce with SMTP id bo21-20020a056000069500b0022b00e67bcels2883543wrb.1.-pod-prod-gmail;
 Mon, 19 Sep 2022 03:18:07 -0700 (PDT)
X-Received: by 2002:adf:fd09:0:b0:22a:f514:d7b7 with SMTP id e9-20020adffd09000000b0022af514d7b7mr5201435wrr.430.1663582687282;
        Mon, 19 Sep 2022 03:18:07 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1663582687; cv=none;
        d=google.com; s=arc-20160816;
        b=01wl22cVhtwWSphNzN9vk/UWS3GYly9pgGDzua30p5sxs+ZGTIpvO+0iF1fyUu4JEh
         nV5PZdAdeSlMdXw69PS4Oe9VIzQ1a3ahyhwruQLFcy4g67XboeuXrs0NyKe6ZLqN7dRU
         Gn0FcBj6jtvseYDyeSufXswAewjdfpdkmMQYNiZZ4Ch1rtHDIs45YaLuOhAgQqswnKiV
         lHOHEzOUphjr1069LQPd7XUKHDzf2f4sZqAR5p1w/HsQG3JXJCIZmyGK2i658oNVBwTf
         wsZ78Y62u8j+ykoFvygTHAzsuAC04zhE3wrLgTsvELnLwRf6XVM5gRPyxS6rWTXZcUvv
         UY6Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:subject:cc:to:from:date:user-agent
         :message-id:dkim-signature;
        bh=VPG6Pv8mWlQqWm+kW/xAIKtiRyMjOEN9R6RnNMCwxdw=;
        b=W8kh13ycvIaQ1m0RlHZ1uG1e/8ZtGhXORqJ0ju7dW4Xh2vO8/vpeD+fb+2RiMZsxCY
         qJlizAXKQhCs8MFQ+kH56g1q2MWpW6Tf9PtKls5OmU5goE1CN2mbA06xSiKXpDyIWXb0
         QMoXIX1Clh7eAMDlfdNfhPIKEVopzzgjJMXyLs2O1Npfh8F2Lr4ynLg7S8dnO5uJ42nX
         5uiZ4ALmI/UmAEByudFyUAE/WAV+o7uxMfDFmBW4lGrS78bcFe9ZTmaHatDDRlecnRno
         gI56K/BmCC/lUuPzfkuaYZmCgPbP5IHTv9ppN7oE50sDY1nzW+fi0g7BHgGKqO7nTmQR
         HiKg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b="aME6C/8+";
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from desiato.infradead.org (desiato.infradead.org. [2001:8b0:10b:1:d65d:64ff:fe57:4e05])
        by gmr-mx.google.com with ESMTPS id n24-20020a7bcbd8000000b003b4924f599bsi351455wmi.2.2022.09.19.03.18.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 19 Sep 2022 03:18:07 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as permitted sender) client-ip=2001:8b0:10b:1:d65d:64ff:fe57:4e05;
Received: from j130084.upc-j.chello.nl ([24.132.130.84] helo=noisy.programming.kicks-ass.net)
	by desiato.infradead.org with esmtpsa (Exim 4.94.2 #2 (Red Hat Linux))
	id 1oaDq4-00E2Ax-4v; Mon, 19 Sep 2022 10:17:21 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id 2A064302F25;
	Mon, 19 Sep 2022 12:16:25 +0200 (CEST)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 0)
	id 4F9B32BABC0C9; Mon, 19 Sep 2022 12:16:22 +0200 (CEST)
Message-ID: <20220919101522.021681292@infradead.org>
User-Agent: quilt/0.66
Date: Mon, 19 Sep 2022 12:00:04 +0200
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
Subject: [PATCH v2 25/44] printk: Remove trace_.*_rcuidle() usage
References: <20220919095939.761690562@infradead.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=desiato.20200630 header.b="aME6C/8+";
       spf=pass (google.com: best guess record for domain of
 peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as
 permitted sender) smtp.mailfrom=peterz@infradead.org
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220919101522.021681292%40infradead.org.
