Return-Path: <kasan-dev+bncBCBMVA7CUUHRBZOYUGMQMGQENTJJOAA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x239.google.com (mail-lj1-x239.google.com [IPv6:2a00:1450:4864:20::239])
	by mail.lfdr.de (Postfix) with ESMTPS id B8A5E5BCCD3
	for <lists+kasan-dev@lfdr.de>; Mon, 19 Sep 2022 15:19:34 +0200 (CEST)
Received: by mail-lj1-x239.google.com with SMTP id a13-20020a2ebe8d000000b0026bfc93da46sf5864231ljr.16
        for <lists+kasan-dev@lfdr.de>; Mon, 19 Sep 2022 06:19:34 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1663593574; cv=pass;
        d=google.com; s=arc-20160816;
        b=IpF3130qi7KWSX9M+2PFB2RksMcLeKdjq2EsFrzYeJn85pJ4WcE3R4QeU4o3BPxjC1
         hPomPFGj4pYj7X2BC0eDW0mFR1DbholAqLmlwsBPmB3vIxBJfquME+SBDwzCkgrMVPj5
         Sa2O4cD+MbshOujqmsqMiiFmWEwTdoRgamW3o+R7BWw8q9NEwc9796vJR2YIOIgDkCeR
         svoU0+0uF8oviT8EArQxvbi2vyUzsHAR0enXoO1eB10vUFT6ray1w+jefyeLE97jdtQG
         d57kYThMbOTYrT7nECT6O1MDaAhv7seQ3HbR38RG13PxOMfG7voiHM4KSAqDM0KyfjGg
         o36A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=gAMpo/syQ8eXLgftaztqtbB7MpdTFObB+ZVT8P4gb4U=;
        b=D6RRoD1tLALlDNCRBbn5llNhtecfZcUvb1rjuiLtaqMj7jzGdaRqv0CcXus8FR9cpJ
         lwCbXgtdyUM8RsfN+nCYUmzy3JjCjli+pkyFyc/f+QtV6bMydddjLaf4fBrGHJTHCAjB
         KccZJzT0QjV6LJ+24znhupXw9oA1IBD+DBdnUEbiOJseoFI3KS8M8Kerl+KJrRmdL5W2
         jzS9WcpV3RlEs544toviQjb0i05ia53w01uKVWULgC0ZPcc7Lbw/S9AuE5sZyiI0ZjUc
         o/nlEs1HTU/JNmHPN6bgaOoCl+hMzsMYvTIOy0JwodiYuC4d91+vDXs0NdCpcwfZwgsq
         G3ow==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="QSt/tYd0";
       spf=pass (google.com: domain of frederic@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=frederic@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date;
        bh=gAMpo/syQ8eXLgftaztqtbB7MpdTFObB+ZVT8P4gb4U=;
        b=SUHPDriezNaQlfPMiQV6WxUU+XcBA4ka8WjeAdAD8slfFH+M4LlxjkSEzCzvuTzL/e
         qg1MT0O9RALC76rUALSE9CwJZUkpIZToWuBXawRu25FTRDNTAYYFzCLVzsg5LUdg4Y6i
         nASeIwDU5ZEVdZGvsq1wXumMpsK6QYrjNesO7p7K3hUCrtUkew54802Tw1auksMAd8x1
         7FCdhYSlSDFipq00HNDFcPSCFXEAM8/J0XBfeFCmr8sRJAP8Pd8lzudQ41jiQsFEywpt
         CX/ltRkcei/z7NupjbyjK+YzMiwV55NVWyVRpSxKlduBxG0zbmBVHzUFA2b/mCx5doPh
         wIPA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:sender:from:to:cc:subject:date;
        bh=gAMpo/syQ8eXLgftaztqtbB7MpdTFObB+ZVT8P4gb4U=;
        b=keDxIzCtjLG8SAJEfhZmOdIrVgyVMW/l+XABcUTkzwmeqqErQ6DeKgsE8sOWN7V4+j
         wpHEmsu+QQ9HFmmuO9D+DQMErU1C+wcm4/39dNnGkFbf6y7xZVUnW8pC05Vy/2Ump6mi
         G5vbg/aqfamL5NvU/UNdteUG01JvVA5I23u2oobaI2ISDFrunFDOZeOlKi1CVFBPAXRa
         Igd1x9P7uNHy0x9cDCUs572FSDrc9XiEr95A6BSWr0QaQjQdOKzjDxWvu1x6QJrsd6YX
         TG/k2PRhrRrredbzCJ2FCZX/1sXBT9TLxRWTQaDT0TlRgcvjtmrvWx/bhCC34sW1eux1
         9JOQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf3WRjDgCn8evY9ZcZ69cvdypY90anJYpociL2ayazTF+PW6TjJi
	LJWAuLwSGG6XnwqN8MDa9Hs=
X-Google-Smtp-Source: AMsMyM43IkyGuoVZEh7Od17LIV9fICkjyESrgMVL5jQ/kwZQWsqjAAJ+e7BF8ucs7nqGm+Miq1R6bg==
X-Received: by 2002:a05:651c:101:b0:250:896d:f870 with SMTP id a1-20020a05651c010100b00250896df870mr5660820ljb.235.1663593574092;
        Mon, 19 Sep 2022 06:19:34 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:5e7b:0:b0:48b:2227:7787 with SMTP id a27-20020ac25e7b000000b0048b22277787ls114778lfr.3.-pod-prod-gmail;
 Mon, 19 Sep 2022 06:19:33 -0700 (PDT)
X-Received: by 2002:a05:6512:3d8c:b0:49a:4872:858 with SMTP id k12-20020a0565123d8c00b0049a48720858mr5932265lfv.145.1663593572905;
        Mon, 19 Sep 2022 06:19:32 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1663593572; cv=none;
        d=google.com; s=arc-20160816;
        b=zohfOlBrwjQk/WxLFAiE5fGyFBRpT9CCoIKgtf4csqMIFxgydzu8PtFJPhBl9F962J
         P6w1FRlaTxuzvszC2YXcFaMAF6ggrlc2D/m2yv4ew6T+3KXnRF4HnMyiCfznyQTmw7yB
         qELbbtcYwxdOffE+7heiS4cV8tH849bzloJdDZhQchl1zaSdVNHuKJHI1VU9O2axPPfh
         agnyZ1HbXWAQR3w++aTHC+gv4jKvXOjZkbepA01K3mKwhUEKX5C1mm4dMcxVWvfnMn7Z
         zkZwIT5/U7Q57NuTjys5NJ9bYyxKAfLXP7rKuhbeOTogrF33tEYiGupQw8G2DOjE+5aq
         o+8A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=5zPDaEKNl0b1ovrl7QRhM6GgvCvxJPb4dPtDagSAZ68=;
        b=chE3mP8EwNG2fkFsVw6C7GQmA7XznWd9JPQ/u5K/vJqB0JXZYh0GF79xWVGxXtamNc
         wg2wKwjfTm68p+kMpGj1GoZ1u89xosD6uPLWizwnO1vAkOWOvOxUJx1JhqgxZbOBDPHM
         /Q2jaCS1XaYXNLYpTXfU8gyhZHO2PvCs62KMv59ORdL2pzSUwgWHX7LUtEASDM4Hli08
         LwJbvEGjuPcUvxf6sfxTVjb3FtiTbdDvu4IOQVEHkfDEBsXQsy49wwXbDCOyh3e3wxKq
         zJgCv/zTxSUgENf8kjWVYjLoBQrAlfG5OKti9fzSOuicmRTHhdro/407pTvWeiGMFtpd
         2wbQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="QSt/tYd0";
       spf=pass (google.com: domain of frederic@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=frederic@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from ams.source.kernel.org (ams.source.kernel.org. [2604:1380:4601:e00::1])
        by gmr-mx.google.com with ESMTPS id s7-20020a056512214700b0049ba11e2f38si558345lfr.11.2022.09.19.06.19.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 19 Sep 2022 06:19:32 -0700 (PDT)
Received-SPF: pass (google.com: domain of frederic@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) client-ip=2604:1380:4601:e00::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ams.source.kernel.org (Postfix) with ESMTPS id 452D1B81BDE;
	Mon, 19 Sep 2022 13:19:32 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id D334CC433D6;
	Mon, 19 Sep 2022 13:19:29 +0000 (UTC)
Date: Mon, 19 Sep 2022 15:19:27 +0200
From: Frederic Weisbecker <frederic@kernel.org>
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
	linux-arch@vger.kernel.org, kasan-dev@googlegroups.com,
	"Rafael J. Wysocki" <rafael.j.wysocki@intel.com>
Subject: Re: [PATCH v2 03/44] cpuidle/poll: Ensure IRQ state is invariant
Message-ID: <20220919131927.GA58444@lothringen>
References: <20220919095939.761690562@infradead.org>
 <20220919101520.534233547@infradead.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20220919101520.534233547@infradead.org>
X-Original-Sender: frederic@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b="QSt/tYd0";       spf=pass
 (google.com: domain of frederic@kernel.org designates 2604:1380:4601:e00::1
 as permitted sender) smtp.mailfrom=frederic@kernel.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=kernel.org
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

On Mon, Sep 19, 2022 at 11:59:42AM +0200, Peter Zijlstra wrote:
> cpuidle_state::enter() methods should be IRQ invariant

Got a bit confused with the invariant thing since the first chunck I
see in this patch is a conversion to an non-traceable local_irq_enable().

Maybe just add a short mention about that and why?

Thanks.

> 
> Signed-off-by: Peter Zijlstra (Intel) <peterz@infradead.org>
> Reviewed-by: Rafael J. Wysocki <rafael.j.wysocki@intel.com>
> ---
>  drivers/cpuidle/poll_state.c |    4 +++-
>  1 file changed, 3 insertions(+), 1 deletion(-)
> 
> --- a/drivers/cpuidle/poll_state.c
> +++ b/drivers/cpuidle/poll_state.c
> @@ -17,7 +17,7 @@ static int __cpuidle poll_idle(struct cp
>  
>  	dev->poll_time_limit = false;
>  
> -	local_irq_enable();
> +	raw_local_irq_enable();
>  	if (!current_set_polling_and_test()) {
>  		unsigned int loop_count = 0;
>  		u64 limit;
> @@ -36,6 +36,8 @@ static int __cpuidle poll_idle(struct cp
>  			}
>  		}
>  	}
> +	raw_local_irq_disable();
> +
>  	current_clr_polling();
>  
>  	return index;
> 
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220919131927.GA58444%40lothringen.
