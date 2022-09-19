Return-Path: <kasan-dev+bncBCBMVA7CUUHRBD76UGMQMGQEIMT544A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x138.google.com (mail-il1-x138.google.com [IPv6:2607:f8b0:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id 16D695BCF28
	for <lists+kasan-dev@lfdr.de>; Mon, 19 Sep 2022 16:39:13 +0200 (CEST)
Received: by mail-il1-x138.google.com with SMTP id h10-20020a92c26a000000b002f57c5ac7dbsf3171391ild.15
        for <lists+kasan-dev@lfdr.de>; Mon, 19 Sep 2022 07:39:13 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1663598352; cv=pass;
        d=google.com; s=arc-20160816;
        b=yCiAGa75zHVjUUGL6Yufw0Qybc2qCgKdabcYkHrPGi5YAj/pZhWU8rlQSWymQK10vi
         FuLdtp5CoucRwN4Wg2C22gGZIN0qM3/iJsspGpDqSHW8E5RO5aZiS7rYhOf1FwFLjVT1
         b2fv3XswFUveueVxSbVRPw8ZhvsJvHbs9Z2SdWPhHWVRlQJlgPTCgG//YWPAejgoPYhK
         eRI+Ntk03fs/eM8BFS8xb3alOBOSLl7EMz1rfmohu5oZTKslbSJG4Dz9833KC8WE9q1/
         Jshpi1DqvCDbeQQgH+C3ONLrWtqeEKJOJxF11Wjqtbp0TKD9kv8/zD/ly/Z37QrzJNQE
         WbSw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=nWi/KT/40RgRiOVKwiO4dRFt/MUUgqYebx699rfrwOA=;
        b=WB6lK6axRMnj5ALqzkTusEOpL/duPFEmZaT2xfXJia7XkKjfUv4tj7OTdoPZR67+Ob
         l97r8kXUwQpmOHYu16x/1ExQkUcO4UzkpR9oqdjfbm9CeglgpAiYBwqN6EwqdONC1XDp
         djBgqTeoI9/DMx5pnbKTFCj9EK7RZVk3k64TQ8GMe8iQrKYiHsVdELKuxcDD+VadjRCP
         1DzAq8KDCuqNCXO2Nva0EvJwzgQ8oWAMJds3YjZSlDgFh1jp28rzAZUyzjwS9vDxz3r5
         wN1zDyUgFgolTKOH6LtRdBoyI3ShfyaAEkChXhiqZbtWhh9WFm8EbkWUSmdKDPvS8lok
         2liw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=s3+f9C0K;
       spf=pass (google.com: domain of frederic@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=frederic@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date;
        bh=nWi/KT/40RgRiOVKwiO4dRFt/MUUgqYebx699rfrwOA=;
        b=OyJKTVoIEq/OhD12LxOlitcJ3waWEqOX0P81QHKmQY/wLuUpiqtHVD5HUSWEuujE4s
         OycvOuxpXpySLavRiw54nzuH07L/0dvVBPM7pShp4O7ib4Xl7tjRBya8bCSe82ZQgH6z
         Xh74q92svqxhac8jFLM53ZOBJQKVJOKv/yP0V2kMvoEt198YVCUwrAk/cDV9TXlzW4Nc
         fH9bygD7sjdN7O7AKj5JQ6jGswDwSOQ4MqMTSB9kMK3rbbLziJ/D7LQU1QwYQ17PlicQ
         Sq0YnHn72L6ZOBYwtHATy7E+DjGGkWwtDTBO33NX1QiQLkDcuMqy+0Q90h82tnlWJ9eC
         f/rA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:sender:from:to:cc:subject:date;
        bh=nWi/KT/40RgRiOVKwiO4dRFt/MUUgqYebx699rfrwOA=;
        b=4NcIplokdPamPZL21wnbCIsW8vpT2oByiUaeN1Qbgx4N8vlxclCNc1AkX6ldIcWdTw
         Xwg2seNkCbcsYsHng4hBdWIGUpYBE38hVrdXNi6B47vsJxctXUA4FtIjsv+MlDOx8SM/
         HUXiPoqLhOusDDn5z79ZkHAWwK8J+KIVGSBv/NyC469I1c/ugl+dRGmtZM+Q16gNxU38
         Lx0kagWWze2zXgdStoSlTluVnp/jXZC0aHmDmIFV53T3haTa7Gn5hPPBpf3th57kOyIx
         EnSNtwwFXf+iixUo6Wu4h4rt1PVzpRhnyR2TzSqaLm5FFvvcYtm4HLYQ44jvaIVr548V
         JBAg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf1VUKoFbAvopQG9qUzNTTz3BSUxx17QZvhUs2rx8Yyy3IXw8VMs
	2R6nzznj9jpYIMf+5LEEaxw=
X-Google-Smtp-Source: AMsMyM4s/f+JnYHyvKXZ4/16beBiCvSfi4QQG8Fr5VmY1s0aYYtD18JQR4r1I4Ca/0BkMYstjYPL2Q==
X-Received: by 2002:a05:6e02:1c82:b0:2f1:b5e0:2584 with SMTP id w2-20020a056e021c8200b002f1b5e02584mr7323335ill.302.1663598351892;
        Mon, 19 Sep 2022 07:39:11 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:92c:b0:2ea:d0a2:17a7 with SMTP id
 o12-20020a056e02092c00b002ead0a217a7ls972983ilt.4.-pod-prod-gmail; Mon, 19
 Sep 2022 07:39:11 -0700 (PDT)
X-Received: by 2002:a92:c549:0:b0:2f5:e036:6b7a with SMTP id a9-20020a92c549000000b002f5e0366b7amr1482888ilj.180.1663598351537;
        Mon, 19 Sep 2022 07:39:11 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1663598351; cv=none;
        d=google.com; s=arc-20160816;
        b=hts0NPBIJtBiUHMJ/3cuwIj1kNSEdGNjcT116ksqa9aVBXZmncjNdLoMPgUSZCJJ6z
         wp5/A7ilRkTM2dIuzD85VBCzcPezn8JEe6JPFm23Ceg01dEXoA+W5HngpGozXOdUMR4f
         9bXMantCdsDG9k8Yx6n5fiCZvwOVg+G/iEir1oKTk7zll0isUmTrt1W21zD+qpQ5uEMz
         1tIEAKDYWYm9h2e9vVbJ2nc9zzcZVH5VDXFjjPuhJOy7bX6SPdal9yQbTz2BakYeDtig
         SAxOCt0RSl6ID/cXzvGmrHoRhSp5Te+UKqKnWhXZCPEyV3NGwOEfdiARbeelzfRa+VFD
         EbvA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=v1p6FYIaO1j3zgdXmhpAGHOjJDjlsvvU2FU8TQXAwOg=;
        b=NEReUPP1P6orpXHBgYylR1kdGP53h1fMsTiOUW7c3m/RJAdfihim2mEehRgcbMdIgF
         1hPZELwHeS1LKyTHkXt5ydz03/WjSEJos3ErgMiS1I5/InDozPEvf5zHtpQbBU+Vu/pm
         HczBfqIz1f8QkaeTijhjznZ3skizom0jLAwFWWonakwwYtdJTr8iA6mbKihr6YskGJRI
         YIbss3yWPjAAfwF3gCrKhOVRMVjdtCz12mZDR+QuxrSK0es+CRsI+zXUY6G/VwtF4aIN
         GklV5kGbboBFJAmU/Csx9fKYQqkRdQx7QIzSguJMzfjdGxW6dOxusP8MUmd4GuE8iHaF
         6FBw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=s3+f9C0K;
       spf=pass (google.com: domain of frederic@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=frederic@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id a6-20020a02ac06000000b00349dba16b8dsi555578jao.6.2022.09.19.07.39.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 19 Sep 2022 07:39:11 -0700 (PDT)
Received-SPF: pass (google.com: domain of frederic@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id 133F261D5A;
	Mon, 19 Sep 2022 14:39:11 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 64C85C433D6;
	Mon, 19 Sep 2022 14:39:09 +0000 (UTC)
Date: Mon, 19 Sep 2022 16:39:07 +0200
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
	linux-arch@vger.kernel.org, kasan-dev@googlegroups.com
Subject: Re: [PATCH v2 10/44] cpuidle,armada: Push RCU-idle into driver
Message-ID: <20220919143907.GB61009@lothringen>
References: <20220919095939.761690562@infradead.org>
 <20220919101521.004425686@infradead.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20220919101521.004425686@infradead.org>
X-Original-Sender: frederic@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=s3+f9C0K;       spf=pass
 (google.com: domain of frederic@kernel.org designates 139.178.84.217 as
 permitted sender) smtp.mailfrom=frederic@kernel.org;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=kernel.org
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

On Mon, Sep 19, 2022 at 11:59:49AM +0200, Peter Zijlstra wrote:
> Doing RCU-idle outside the driver, only to then temporarily enable it
> again before going idle is daft.

Ah wait, now I see, that's cpu_pm_enter()/cpu_pm_exit() -> cpu_pm_notify*() the culprits.
Might be worth adding a short note about that on your changelogs.

> 
> Signed-off-by: Peter Zijlstra (Intel) <peterz@infradead.org>
> ---
>  drivers/cpuidle/cpuidle-mvebu-v7.c |    7 +++++++
>  1 file changed, 7 insertions(+)
> 
> --- a/drivers/cpuidle/cpuidle-mvebu-v7.c
> +++ b/drivers/cpuidle/cpuidle-mvebu-v7.c
> @@ -36,7 +36,10 @@ static int mvebu_v7_enter_idle(struct cp
>  	if (drv->states[index].flags & MVEBU_V7_FLAG_DEEP_IDLE)
>  		deepidle = true;
>  
> +	ct_idle_enter();
>  	ret = mvebu_v7_cpu_suspend(deepidle);
> +	ct_idle_exit();

And then yes of course:

Reviewed-by: Frederic Weisbecker <frederic@kernel.org>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220919143907.GB61009%40lothringen.
