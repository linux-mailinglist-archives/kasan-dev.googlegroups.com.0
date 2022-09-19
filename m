Return-Path: <kasan-dev+bncBCBMVA7CUUHRBRHFUGMQMGQENZFEWNI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x140.google.com (mail-lf1-x140.google.com [IPv6:2a00:1450:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id BFF9B5BCD7F
	for <lists+kasan-dev@lfdr.de>; Mon, 19 Sep 2022 15:46:45 +0200 (CEST)
Received: by mail-lf1-x140.google.com with SMTP id bp4-20020a056512158400b0049f93244164sf1701302lfb.13
        for <lists+kasan-dev@lfdr.de>; Mon, 19 Sep 2022 06:46:45 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1663595205; cv=pass;
        d=google.com; s=arc-20160816;
        b=G+F6I8a5Pv1D1N/J+t5OVrB2t3gWPt6QIwdgJ2p7XQ1szE7vt1oVMih7dtCN/OferF
         bjZgp+wW1DkvcFCRuCrfF+APi2+n4qfoTqVk4l929EaK4ZaUKpAG7hj8tEyqDq5WXe1l
         y/dbG1suU5rdkamfjQSF2fVx2i3Np4IiV7xoCQJS/bju2XiZvKZQOCUjieusgPn/NPgF
         5+cx0VUmqCmH4zy1DgPtAhRr4fXIRjAfYDgsFQ2hdnhZK82oxZAKJ1sOsxi3s17mqjA+
         HvFqyeEbHbSVnV6b93S8ZerkNknYx3jdbjljzXounbJWWlh0IAgDsfegVyW3MvsU4rH2
         UQFw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=YbILbYhK6JLz/w3zL8qKQcyUROvbPjNnPGTQN0afzRs=;
        b=Bp39YFafiX3LmoEoreabx8O/rmHIfF2tJZIhaFgnpvwS38zQUv5uN32AmrcA9s5oKY
         4SgDN9OxozkQHaD+RgEaoULffMQpA1f6KaUsFQ7CPAKH88JHac3uzEFpt7sp8aPKt7fL
         Rpcfi/8osVMYi4nbe21iTcDPoQTAQ4fFYBieflUVbId5YbiU4Tizg6fW3CueEE+rWRuP
         4wGi7LizjDBHo2joKE3UCy2nBqlMdFjpw5K22Cnal8NIrEBj8VBEorvaT0WVRPWz3GS4
         ujqQpr6mUMOWY5KxdjBDq61U14aSFwQqhJ3DYyYhzf9Ho8H3Y6fWgSc3CZCtZJk0v/qX
         fwhg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="BBg87/yL";
       spf=pass (google.com: domain of frederic@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=frederic@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date;
        bh=YbILbYhK6JLz/w3zL8qKQcyUROvbPjNnPGTQN0afzRs=;
        b=Qb6APxRUnKwJYUVn+Ytcs6JTdMvr50qXCIKJaYeUnA/aE+nBhD5MwoogK1jRjduqHX
         KjULg99zo7LyBfTp/8jUSiQlUnVN+pCZ0k7DQmPVtnO2glmJQPY9FmBFG+MuJa2PHrIi
         1/7XpJcoOKG3ylqlkuensQiaTzTFtho6aaFu9mBb3YMNRuvKWeb1ynlDvLYUwqGDCcxM
         nZWUEGXpL/BgTC/mGlM/rpolmAf40O6o7xEeDwsOisKrELSPkZ5UkmokqfSjPwqGrpYk
         /5mz8HCa4/+FHltTYp/NLKFPonzl73nSEmn8IaM0+7DOexSaemqXAYHiNqBdbQQe0ZV/
         r7tQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:sender:from:to:cc:subject:date;
        bh=YbILbYhK6JLz/w3zL8qKQcyUROvbPjNnPGTQN0afzRs=;
        b=MzHefIfY8CwyVmvMuUtFZqv83R2CGIrL+vcAAxgiO0jvBvyQJjOPc7lrgQT4zjfUQV
         YzqpHgpc8c9FOBtxqUWOAjenoyZpFps/NjmQ844E19KVSozvzeLssjyErJgRCRKx5sUZ
         zJdJauOZEiAjmfO98pFXz4ad2mmQ+90RwD+SVnQyrfiEjM8mboZf0j4oYNG1ICO/EvG7
         cCzPMN3OGiBGqClHc5IgMGApizjJt6Ib2ouTkig5GCNyYjfRifWqxAiq3d0SBqgssemd
         Fl117b3vfDoWvt5EM+LyCJ+UgVtCL8EEWb32Y4ATT3/4CK1+4EzNmzHAK+HImYob2pUW
         Tg2w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf1LAPT31imlVf5drgUO8OJjFJX3ZNE2Fp46WYExjFmvxeJYx3B0
	Oeqp7ZcXVzdgMea0WRgFovY=
X-Google-Smtp-Source: AMsMyM7rDswkk67q9cgWp0Ez73Afi2NiRkLgZDaLg88OZhqunYXgmCUI2/Cbvua0C5/107iIEl1U5Q==
X-Received: by 2002:a19:ca5a:0:b0:49f:64f2:c6e5 with SMTP id h26-20020a19ca5a000000b0049f64f2c6e5mr3939517lfj.317.1663595205149;
        Mon, 19 Sep 2022 06:46:45 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:5e7b:0:b0:48b:2227:7787 with SMTP id a27-20020ac25e7b000000b0048b22277787ls175349lfr.3.-pod-prod-gmail;
 Mon, 19 Sep 2022 06:46:44 -0700 (PDT)
X-Received: by 2002:a05:6512:110b:b0:49a:26c6:fa13 with SMTP id l11-20020a056512110b00b0049a26c6fa13mr6836155lfg.215.1663595204162;
        Mon, 19 Sep 2022 06:46:44 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1663595204; cv=none;
        d=google.com; s=arc-20160816;
        b=AqEN/VoL3kukA8c3EbqtW78ngJRj+ODHcigehTF3cjE0AtpKmmZhtV18k8QuRTrjyk
         kqPfL6na9rt/akIH38Yqqhx21dVo6miZkDYVOd4hBYNgvUZCjfHTjl5UqoYLdctP490i
         78ckriTPC4U/L86zvnEPCyGwvKYTRyJipQ8e0Z8FaNeDe3BYfcQfX9jK+T6IX8tOAKjs
         XOf7tloB0FoesiajSUivShXZ7JgdPK8WngGQ6QwSyQ6YsYMGwdiE22exNYwoB+28h2VF
         hnojdObrjLRAO+9qD2Z2lhKs49AS42NeumM06eP4Wm5/FrOV8cGUvNnNVkHiXJlml/zm
         7R4A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=BA+jgAEECljnmV1htuqdTPAZYyfhraMAo1p5ERw74mY=;
        b=G2uF1/YKJ4tuhcCdN3gsAUj7oVuRsLDQXujvvEOMwiu9ifjRuVWFDp1+SeWS5oCYTd
         tJbYpLwKxNzEVK7yYH2hw9Wz5YEKKbd1S72LQ4fV2LTfqQkoM9y/1eRoZffnXN7RjKJp
         +7FHn67lF5nFbOf2iVH9LMIvZFgZozPs7TisDiP79zgNuNIn/6CCJ3NJ+9LKFatPHjc3
         NkEXsnr/1Z58Nk34t1U6AQmMjE0VpGAoYy1qJ3RcWVSptB0d8TXZzCC9BLCfpBWfDvWa
         E14E5ysXh2f03VSyrhR/7qOyRkCoLLnbj4axZXGqNVhEA7K9x2aeXiPM1p7DivLetjdo
         P4Fw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="BBg87/yL";
       spf=pass (google.com: domain of frederic@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=frederic@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from ams.source.kernel.org (ams.source.kernel.org. [2604:1380:4601:e00::1])
        by gmr-mx.google.com with ESMTPS id u10-20020a05651220ca00b00492f1480d0fsi789133lfr.13.2022.09.19.06.46.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 19 Sep 2022 06:46:44 -0700 (PDT)
Received-SPF: pass (google.com: domain of frederic@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) client-ip=2604:1380:4601:e00::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ams.source.kernel.org (Postfix) with ESMTPS id 09747B81B4D;
	Mon, 19 Sep 2022 13:46:43 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id AFD1BC433D7;
	Mon, 19 Sep 2022 13:46:40 +0000 (UTC)
Date: Mon, 19 Sep 2022 15:46:38 +0200
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
Subject: Re: [PATCH v2 05/44] cpuidle,riscv: Push RCU-idle into driver
Message-ID: <20220919134638.GB58444@lothringen>
References: <20220919095939.761690562@infradead.org>
 <20220919101520.669962810@infradead.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20220919101520.669962810@infradead.org>
X-Original-Sender: frederic@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b="BBg87/yL";       spf=pass
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

On Mon, Sep 19, 2022 at 11:59:44AM +0200, Peter Zijlstra wrote:
> Doing RCU-idle outside the driver, only to then temporarily enable it
> again, at least twice, before going idle is daft.
> 
> Signed-off-by: Peter Zijlstra (Intel) <peterz@infradead.org>

Reviewed-by: Frederic Weisbecker <frederic@kernel.org>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220919134638.GB58444%40lothringen.
