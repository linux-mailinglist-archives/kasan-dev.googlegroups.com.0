Return-Path: <kasan-dev+bncBCKY3KPSYUPRB5MOV2MQMGQEND725DI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x439.google.com (mail-wr1-x439.google.com [IPv6:2a00:1450:4864:20::439])
	by mail.lfdr.de (Postfix) with ESMTPS id 23CF05E557A
	for <lists+kasan-dev@lfdr.de>; Wed, 21 Sep 2022 23:51:50 +0200 (CEST)
Received: by mail-wr1-x439.google.com with SMTP id d9-20020adfa349000000b0022ad6fb2845sf2782870wrb.17
        for <lists+kasan-dev@lfdr.de>; Wed, 21 Sep 2022 14:51:50 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1663797109; cv=pass;
        d=google.com; s=arc-20160816;
        b=tJf4aI29+ddmf29axTBJDVgdFxJVWQ3TQ0wVoHuLtPDpAJZ5ZKb/+j1pgqzyD2KOYN
         X4zwCcwCSgDzsEvZj0IUmdANWl9hEXBG0RpIEDtg0VSg8+nNgWFJ5lDl511Mv+ebipvN
         yKuZBiNUGb/XZf9DZ1iEy5FKMWlpxxLmvCCDFzwSPmLO3B1doPNzq6jc9IG7YmsxZK8U
         HoFMXMr72H+ANeIxJS7T1Nrgm4fjM7yg5WHt1ax5DUNIkNvrZ52xU8tOhWgl6jdgOkmq
         zkXzOdP6u7Qx1Y2eZms8u1r3D8WhSoqR0rJ+pX5AMYLYIf0edzWlGYH0oxtIfq61Fcb5
         Y/VA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=GL36hGodAN/VBZGLPx/eaZgundnijBvK2HBLuQ+W904=;
        b=SXcYliniNI95BxEV1g2QEj3nqqicRVIgU/ELxr39S5+MJRpMaU7XnqR4XC7N+0u80G
         yvA00PSwOoVJ/T+VjyPPHKKu2WUR+8IATZ/hRTL8klS3CKjgCiaP2IlMuXnl954FmVHz
         62w1SFeQgwBSbD0PZnZoWoemVolgfscjH/e9usYYTCxiFPgFx4mYsHk0kcabZ1umvUFt
         H6gOQXWz9TfmrWVXXRr3RB6XMZWZHm9dY8aRROYla9Q9t5xFuT7EJpXQtwCuW9y/bzXT
         jGANKnQaIcnEgJCJIz60sPt+X/mTmhY3zDF0oKB7XeMuoeymS9aKrgFAnHXJ762+SvXH
         0Ssw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of kajetan.puchalski@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=kajetan.puchalski@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date;
        bh=GL36hGodAN/VBZGLPx/eaZgundnijBvK2HBLuQ+W904=;
        b=E619szhwxbk48GdmtZ1qDShskBrPYq4tygWZux348bMEXK4/R5Eh6/9EX8u1UA7mA6
         ps2uZNYpBBwM2OPWwZaFnRwQhORf5K2wq8gLsBEJj1DCJ/0nP2+9pqIIjLawzUytHDva
         Eog7eNWukhZIEyuw/vLroFTEoSyxEfiCD2Wyhjkx5zaFG/APVgkVOBu9uPNtSG8apbX8
         Q4RgOSJuzWHdeowWW4Xhu+M2m+99+mBDvif8DNHy9qitBxukDPmQMeIpaLiyy8QRTu+1
         6CYbFwPrYZfFUfJxEY92Av2bJf16SYkF5k8ReGvwHw9vB6Zk/utaXy5c2Xt0Lea3j/AM
         7Hww==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:sender:from:to:cc:subject:date;
        bh=GL36hGodAN/VBZGLPx/eaZgundnijBvK2HBLuQ+W904=;
        b=4PBJE02Dlaf63+R12QzXo+LKguMaNuKR9Y9AJT7vT0QYHflIf5DYtEcYrHN1wd64RO
         TOtz3q6A8o7m577JyxNMTc8QihO1yuTKD/vHYEIUJT7sSFUO3AFBDFeJdACt9efkBeIf
         RKwRA8RBnPlpR3Y6MQqaIQ8Tl7krd5jHybKMioJiu22bBcqocH3hGIThLKNpOPAQ9FzZ
         +dq7aj1IJa3J+OnVHg4/xBSMixO3pVjlO7wHYzioF4mCFOVZ2WZnJSl/6W20k1UfFf+8
         u35kofl4WBfy/BJKZbrFU1B3o1Pb8XvbEw89uWUXmrpbw/FpRPvFZaS/5zn5vhxXFlhH
         cy/w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf30yJq+1GnJvwjFpny+QpqtfCCanI3BhizUiNVjcuIDBHy2E4RZ
	w8cAZFABxIk+KYKUL0sXNVQ=
X-Google-Smtp-Source: AMsMyM6/G4wTTRCk3/ZOkKzai6jrYU3p9Yjs+Ols/dsZJAbZt2oTcBnaPFziccF6oMHrX5Y6m2UMhw==
X-Received: by 2002:a5d:69ca:0:b0:228:dd17:9534 with SMTP id s10-20020a5d69ca000000b00228dd179534mr120258wrw.652.1663797109582;
        Wed, 21 Sep 2022 14:51:49 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:3786:b0:3a5:2d3d:d97a with SMTP id
 o6-20020a05600c378600b003a52d3dd97als4287065wmr.3.-pod-prod-gmail; Wed, 21
 Sep 2022 14:51:48 -0700 (PDT)
X-Received: by 2002:a05:600c:5128:b0:3b5:d6:eb8f with SMTP id o40-20020a05600c512800b003b500d6eb8fmr243219wms.65.1663797108479;
        Wed, 21 Sep 2022 14:51:48 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1663797108; cv=none;
        d=google.com; s=arc-20160816;
        b=TcTtI7IKYxZi+zyl3moavE4Gh+AWNEp8jgkQNolrpOZsQw5FRWw78LHb2sJFNCfqaq
         zBGcwbMv90V7jIPUQ1y9k8sv5jBFM96atqG2PjT7x5H6KgFI968E3CLawkKo7RVdlVJ4
         uJsIYpw6NxvND5VVZ7rl9QV+oHgBIrR1k040Cs8vbRT5PLVtXmtgeY/7biTpcObFCccL
         55f87RRa5kRXP7qMY2GRAs4vlGxRBkU/2atpacQFSCbMsx3DKzBPU1EI88iWauBpbmtR
         4ILIFjC5Y0p7rHhC95l/dw8QS2GwWkIAZ7ewcJKof5oSomsGOE2A+inMLDwHYD5GpBuu
         h01g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date;
        bh=7EGaw0/mn9TNguQCeQDWIMiuSDsMk2I5CBAE8h7vZGI=;
        b=XX4CXIVEE2xR4ukkgS7PJ6urAItNS4lq4EBJnUYT4RRV1gLTQxNNg6hXcRPweBMgao
         pUqnZojlA2rcidj2o+s5M6LLyTXmsGlVPq0QLnbshC+2483q01kMHZ2mgywGyjeOBEze
         A8wgxCIGChDb0dPqyfRGh1YQ3xMDkrGvQSi56rnSQpo+5rzuv8Q0cKFBNNE7NG3+TvdF
         ahq0o6QhiIPfGaNGi42EpcxpwMUgSE+UlpWuW3Cghg4r1GL+F5T5R9fe/bx9R5eRxXat
         eX2Y6zTVmYB0c0C8uPHrbgLwDPDdve5FZa0iR5v9z0EqMhIt9yxiI0henVQ1jYESnJ2S
         58YQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of kajetan.puchalski@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=kajetan.puchalski@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id m17-20020a05600c3b1100b003a66dd18895si251986wms.4.2022.09.21.14.51.48
        for <kasan-dev@googlegroups.com>;
        Wed, 21 Sep 2022 14:51:48 -0700 (PDT)
Received-SPF: pass (google.com: domain of kajetan.puchalski@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id D9569143D;
	Wed, 21 Sep 2022 14:51:53 -0700 (PDT)
Received: from e126311.manchester.arm.com (unknown [10.57.76.246])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 6F35F3F73B;
	Wed, 21 Sep 2022 14:51:19 -0700 (PDT)
Date: Wed, 21 Sep 2022 22:51:10 +0100
From: Kajetan Puchalski <kajetan.puchalski@arm.com>
To: Peter Zijlstra <peterz@infradead.org>
Cc: richard.henderson@linaro.org, ink@jurassic.park.msu.ru,
	mattst88@gmail.com, vgupta@kernel.org, linux@armlinux.org.uk,
	ulli.kroll@googlemail.com, linus.walleij@linaro.org,
	shawnguo@kernel.org, Sascha Hauer <s.hauer@pengutronix.de>,
	kernel@pengutronix.de, festevam@gmail.com, linux-imx@nxp.com,
	tony@atomide.com, khilman@kernel.org, catalin.marinas@arm.com,
	will@kernel.org, guoren@kernel.org, bcain@quicinc.com,
	chenhuacai@kernel.org, kernel@xen0n.name, geert@linux-m68k.org,
	sammy@sammy.net, monstr@monstr.eu, tsbogend@alpha.franken.de,
	dinguyen@kernel.org, jonas@southpole.se,
	stefan.kristiansson@saunalahti.fi, shorne@gmail.com,
	James.Bottomley@HansenPartnership.com, deller@gmx.de,
	mpe@ellerman.id.au, npiggin@gmail.com, christophe.leroy@csgroup.eu,
	paul.walmsley@sifive.com, palmer@dabbelt.com, aou@eecs.berkeley.edu,
	hca@linux.ibm.com, gor@linux.ibm.com, agordeev@linux.ibm.com,
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
Subject: Re: [PATCH v2 07/44] cpuidle,psci: Push RCU-idle into driver
Message-ID: <YyuHTgRh7t6vYjHw@e126311.manchester.arm.com>
References: <20220919095939.761690562@infradead.org>
 <20220919101520.802976773@infradead.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20220919101520.802976773@infradead.org>
X-Original-Sender: kajetan.puchalski@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of kajetan.puchalski@arm.com designates 217.140.110.172
 as permitted sender) smtp.mailfrom=kajetan.puchalski@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
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

On Mon, Sep 19, 2022 at 11:59:46AM +0200, Peter Zijlstra wrote:
> Doing RCU-idle outside the driver, only to then temporarily enable it
> again, at least twice, before going idle is daft.
> 
> Signed-off-by: Peter Zijlstra (Intel) <peterz@infradead.org>

Tried it on Pixel 6 running psci_idle, looks good with no apparent issues.

Tested-by: Kajetan Puchalski <kajetan.puchalski@arm.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YyuHTgRh7t6vYjHw%40e126311.manchester.arm.com.
