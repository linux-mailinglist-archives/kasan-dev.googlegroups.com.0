Return-Path: <kasan-dev+bncBCQPVKWLVAIRBB5NZKMQMGQEXE6HVEA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13e.google.com (mail-il1-x13e.google.com [IPv6:2607:f8b0:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id 1516A5EBA7A
	for <lists+kasan-dev@lfdr.de>; Tue, 27 Sep 2022 08:22:01 +0200 (CEST)
Received: by mail-il1-x13e.google.com with SMTP id h9-20020a056e021b8900b002f19c2a1836sf6872815ili.23
        for <lists+kasan-dev@lfdr.de>; Mon, 26 Sep 2022 23:22:01 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1664259719; cv=pass;
        d=google.com; s=arc-20160816;
        b=nmp1GobXWQp6iBn0779YuZiU9s62GaaSmyKp0NgI1sy2xnzmpPppl5tyDRWjvKEK7W
         wJdmNMljIUNtSFr04PrT1DRJ1Ha7WQYFJxF6PKLokhNuW98KeFise3aRLPygQKFBAocN
         lU5mQ3iyI6vmR+Wel6n/uGf+MmdSZ4xfn/UVlG3bFdoWZsBGTsjHpO8cYTYCglEx9uj0
         r3CcDgZlTBWidw9OoPfi2BbHq0kzyaBsv/VX+vo9Fv3vRLTnhWrQS23KlgxXScof7dti
         UuoRX4cveB/hvRghnwXyLxbIvoDFvs+na6HPvMfT7J33oVE+wSEG/VEu6QYgmZSHIsgh
         7DDw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=dAkZVHaaF9M4Ra7wTVtvU0fYNLQ3plR2L7nuJD5onUU=;
        b=Ym8WPVZA6LrTlod0x/I2jWtonS0aUmWkPwY/B3DUOV/W8tV3QjrulkVgzeplWNdTSu
         zkF32sxOd566W80S9UzSRPVZ9jScxC9B2Ww+ugu4hcHZJj0zFURBHZXEAYVEVdBzOWuq
         5+S4saLnRjf/y+g2Q2+tcrAhfKkyZI6exFBXeGFKhuPXD2CtuvNy1T1bprqHD5LnwlcO
         07CCmov22UfvlwV4k3zvK1Z1h/mV6So9FAzTWgb9HDPlD+gehuyVFBSnXTi19h0TYzg7
         hJ8Y/qnRIO2zXmOPGp5D5GCLFYhT/BUAbCxJy2lepLjhH2kQgHP2UflhNG8RW/q61C1l
         XOpQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=neutral (google.com: 72.249.23.125 is neither permitted nor denied by best guess record for domain of tony@atomide.com) smtp.mailfrom=tony@atomide.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date;
        bh=dAkZVHaaF9M4Ra7wTVtvU0fYNLQ3plR2L7nuJD5onUU=;
        b=kFHFuGQ7cHFUdrnWT0UldGxrTVvphQ624Y2nxXgobTLJJBzqYtEJtLYy0bBtPm18yx
         ixKXbOXjdE9s9/2CxRtrjBRZ9GbzNWbyczT/E2Ulq4qIhcKIn2U42srHkh41cjZy/FgC
         ks6agykCNCT9/wqhj1cSsrhykGHZQLDI7LE1vUOjcFYK7LlSsWV3VDaD6rc0ki0djnww
         1bSYyfHbemikNgrYXV0f0Ubwd1PKs/NhzlYGtvDYpkBq7eycLqabbhwYw+gV1Ha/adM6
         mw6/Ub/1HvQPlj9oTaF0JBmCQ45Dmx73wToKrVW6dEdf9dmmDXIO5HMw3c6z9gaBNdkK
         9WBg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:sender:from:to:cc:subject:date;
        bh=dAkZVHaaF9M4Ra7wTVtvU0fYNLQ3plR2L7nuJD5onUU=;
        b=sSaWdwbPOebtnbJhfd8+1/LLP5dyCBkTRVk6dl5erlnP045m0UBY5vLWiJLvCcx2mo
         zcVddBB3euHLONddIlzm1dbY4WK8+iawWQSBUW7SH0W1dohY+yUiawF2Biu/N132o3yK
         Ul4MmTIkxK6KDnevLtTWRCBfvmyMxKI8OkvU0e4Ho6nyU3lGQWpglTIUwRN7Np+JoGVu
         6QPicjCVWZj7HgI6jsPA0OVtdzneAXrh0LOJbmgMTklfxGk4uHcu5vaFNzNnYoMd7Yt7
         ov6qH6IFC02VpNjRPFMStWqioFy4sf4SUcGmrcCduivFcGG9H/bX8knLvdKLzlVxX+yg
         E/Tw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf00PDTm55PB0Eiu2XUCtIOz7avMJ0eruMa7CkzYE7wBP+ypL/i9
	rlt2TrbWaTA3jQR3YUEiWIQ=
X-Google-Smtp-Source: AMsMyM4O6DvsABbpFWTK6eRDX/QQhb7XjC3nfd+XT6QQVhtOjpOf+GAh/REQWJRQSj0JIWq61U5opQ==
X-Received: by 2002:a05:6e02:154c:b0:2f2:f8c:5b54 with SMTP id j12-20020a056e02154c00b002f20f8c5b54mr11694702ilu.134.1664259719625;
        Mon, 26 Sep 2022 23:21:59 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:958f:0:b0:688:5b72:e3fd with SMTP id a15-20020a5d958f000000b006885b72e3fdls199799ioo.8.-pod-prod-gmail;
 Mon, 26 Sep 2022 23:21:59 -0700 (PDT)
X-Received: by 2002:a6b:ba05:0:b0:68a:8a2f:8fdc with SMTP id k5-20020a6bba05000000b0068a8a2f8fdcmr11039284iof.148.1664259719199;
        Mon, 26 Sep 2022 23:21:59 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1664259719; cv=none;
        d=google.com; s=arc-20160816;
        b=z0dAFBudX5+AsOe6BtNBaqJSp/yOMvo4uGp/N/usn0WIsv+LBePXkB0XttaTb5pESO
         RvMwiELshtqMd1PdQ+11kTaw+IQ6hy1fOJdy0RZg2tITL1ZcYf5WtjDWMPPTHh26KvH8
         zkXmIpt2dqqBnDLvTwEYKRURKB8ZANh65b/ypz56jzx3SG6iNXcBx1ZCDN/we9g0+m/v
         mxtT2KlEK55RVQ50eXNs2IAcHGAxRgPqLK/A4xKQyBKkzsgcPQgxLtI2/AC6zF2C0jRE
         Ekz+2SfjsyEoRMIC8Q9IrF0Abf6lF0ovEH4K8Hnv/c2STKVfMSqXmXr3eh1CJTCgjDEH
         zF9g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date;
        bh=B4XnREFs3ccQlnYL8kqWkVV4lszG7FBZmZf1SbhCSO0=;
        b=JYPwKourwDc3ENs+RQ8wkVsaX+Xypbb+D3YYtlnS7V+n1f4kEWyeay3chz9I13+dFn
         /i+lX0TaSf55nNUqL1M2QV9yJHac2JVPFKA8GfyxD272CM8Vfs1NS9MgaTf+U4uVO7hR
         RmawPdodPI3yjyZbscUBhZQLF6AUNRqOX85PO0vwgZxUYt11KB0UnuIrYH9hD/MDssh9
         G3l14LakqFY9I6NKJh38IDZdQqHuSoF29Plc6kea3XMYMVN49b2dSjrBWBW1wIy9QSeT
         CL7zi7SYSY4kBzPWHZ2/GiyP2EebUK2HfsAmRdQvfalFIOFTYJxH+7jeil6d0Pf9h1bz
         N02w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=neutral (google.com: 72.249.23.125 is neither permitted nor denied by best guess record for domain of tony@atomide.com) smtp.mailfrom=tony@atomide.com
Received: from muru.com (muru.com. [72.249.23.125])
        by gmr-mx.google.com with ESMTP id w2-20020a92c882000000b002ea3697eb7asi80695ilo.0.2022.09.26.23.21.58
        for <kasan-dev@googlegroups.com>;
        Mon, 26 Sep 2022 23:21:59 -0700 (PDT)
Received-SPF: neutral (google.com: 72.249.23.125 is neither permitted nor denied by best guess record for domain of tony@atomide.com) client-ip=72.249.23.125;
Received: from localhost (localhost [127.0.0.1])
	by muru.com (Postfix) with ESMTPS id E879B80E0;
	Tue, 27 Sep 2022 06:13:36 +0000 (UTC)
Date: Tue, 27 Sep 2022 09:21:54 +0300
From: Tony Lindgren <tony@atomide.com>
To: Peter Zijlstra <peterz@infradead.org>
Cc: richard.henderson@linaro.org, ink@jurassic.park.msu.ru,
	mattst88@gmail.com, vgupta@kernel.org, linux@armlinux.org.uk,
	ulli.kroll@googlemail.com, linus.walleij@linaro.org,
	shawnguo@kernel.org, Sascha Hauer <s.hauer@pengutronix.de>,
	kernel@pengutronix.de, festevam@gmail.com, linux-imx@nxp.com,
	khilman@kernel.org, catalin.marinas@arm.com, will@kernel.org,
	guoren@kernel.org, bcain@quicinc.com, chenhuacai@kernel.org,
	kernel@xen0n.name, geert@linux-m68k.org, sammy@sammy.net,
	monstr@monstr.eu, tsbogend@alpha.franken.de, dinguyen@kernel.org,
	jonas@southpole.se, stefan.kristiansson@saunalahti.fi,
	shorne@gmail.com, James.Bottomley@hansenpartnership.com,
	deller@gmx.de, mpe@ellerman.id.au, npiggin@gmail.com,
	christophe.leroy@csgroup.eu, paul.walmsley@sifive.com,
	palmer@dabbelt.com, aou@eecs.berkeley.edu, hca@linux.ibm.com,
	gor@linux.ibm.com, agordeev@linux.ibm.com,
	borntraeger@linux.ibm.com, svens@linux.ibm.com,
	ysato@users.sourceforge.jp, dalias@libc.org, davem@davemloft.net,
	richard@nod.at, anton.ivanov@cambridgegreys.com,
	johannes@sipsolutions.net, tglx@linutronix.de, mingo@redhat.com,
	bp@alien8.de, dave.hansen@linux.intel.com, x86@kernel.org,
	hpa@zytor.com, acme@kernel.org, mark.rutland@arm.com,
	alexander.shishkin@linux.intel.com, jolsa@kernel.org,
	namhyung@kernel.org, jgross@suse.com, srivatsa@csail.mit.edu,
	amakhalov@vmware.com, pv-drivers@vmware.com,
	boris.ostrovsky@oracle.com, chris@zankel.net, jcmvbkbc@gmail.com,
	rafael@kernel.org, lenb@kernel.org, pavel@ucw.cz,
	gregkh@linuxfoundation.org, mturquette@baylibre.com,
	sboyd@kernel.org, daniel.lezcano@linaro.org, lpieralisi@kernel.org,
	sudeep.holla@arm.com, agross@kernel.org, bjorn.andersson@linaro.org,
	konrad.dybcio@somainline.org, anup@brainfault.org,
	thierry.reding@gmail.com, jonathanh@nvidia.com,
	jacob.jun.pan@linux.intel.com, atishp@atishpatra.org,
	Arnd Bergmann <arnd@arndb.de>, yury.norov@gmail.com,
	andriy.shevchenko@linux.intel.com, linux@rasmusvillemoes.dk,
	dennis@kernel.org, tj@kernel.org, cl@linux.com, rostedt@goodmis.org,
	pmladek@suse.com, senozhatsky@chromium.org,
	john.ogness@linutronix.de, juri.lelli@redhat.com,
	vincent.guittot@linaro.org, dietmar.eggemann@arm.com,
	bsegall@google.com, mgorman@suse.de, bristot@redhat.com,
	vschneid@redhat.com, fweisbec@gmail.com, ryabinin.a.a@gmail.com,
	glider@google.com, andreyknvl@gmail.com, dvyukov@google.com,
	vincenzo.frascino@arm.com,
	Andrew Morton <akpm@linux-foundation.org>, jpoimboe@kernel.org,
	linux-alpha@vger.kernel.org, linux-kernel@vger.kernel.org,
	linux-snps-arc@lists.infradead.org, linux-omap@vger.kernel.org,
	linux-csky@vger.kernel.org, linux-hexagon@vger.kernel.org,
	linux-ia64@vger.kernel.org, loongarch@lists.linux.dev,
	linux-m68k@lists.linux-m68k.org, linux-mips@vger.kernel.org,
	openrisc@lists.librecores.org, linux-parisc@vger.kernel.org,
	linuxppc-dev@lists.ozlabs.org, linux-riscv@lists.infradead.org,
	linux-s390@vger.kernel.org, linux-sh@vger.kernel.org,
	sparclinux@vger.kernel.org, linux-um@lists.infradead.org,
	linux-perf-users@vger.kernel.org,
	virtualization@lists.linux-foundation.org,
	linux-xtensa@linux-xtensa.org, linux-acpi@vger.kernel.org,
	linux-pm@vger.kernel.org, linux-clk@vger.kernel.org,
	linux-arm-msm@vger.kernel.org, linux-tegra@vger.kernel.org,
	linux-arch@vger.kernel.org, kasan-dev@googlegroups.com
Subject: Re: [PATCH v2 37/44] arm,omap2: Use WFI for omap2_pm_idle()
Message-ID: <YzKWgjNLWSmDss/h@atomide.com>
References: <20220919095939.761690562@infradead.org>
 <20220919101522.842219871@infradead.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20220919101522.842219871@infradead.org>
X-Original-Sender: tony@atomide.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=neutral
 (google.com: 72.249.23.125 is neither permitted nor denied by best guess
 record for domain of tony@atomide.com) smtp.mailfrom=tony@atomide.com
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

* Peter Zijlstra <peterz@infradead.org> [220919 10:09]:
> arch_cpu_idle() is a very simple idle interface and exposes only a
> single idle state and is expected to not require RCU and not do any
> tracing/instrumentation.
> 
> As such, omap2_pm_idle() is not a valid implementation. Replace it
> with a simple (shallow) omap2_do_wfi() call.
> 
> Omap2 doesn't have a cpuidle driver; but adding one would be the
> recourse to (re)gain the other idle states.

Looks good to me thanks:

Acked-by: Tony Lindgren <tony@atomide.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YzKWgjNLWSmDss/h%40atomide.com.
