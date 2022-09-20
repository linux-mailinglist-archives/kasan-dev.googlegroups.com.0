Return-Path: <kasan-dev+bncBCBMVA7CUUHRB3UCU2MQMGQEIL2MDLY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe3e.google.com (mail-vs1-xe3e.google.com [IPv6:2607:f8b0:4864:20::e3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 05AB55BE11B
	for <lists+kasan-dev@lfdr.de>; Tue, 20 Sep 2022 11:01:36 +0200 (CEST)
Received: by mail-vs1-xe3e.google.com with SMTP id 65-20020a670344000000b0039b3020da1bsf257251vsd.3
        for <lists+kasan-dev@lfdr.de>; Tue, 20 Sep 2022 02:01:36 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1663664495; cv=pass;
        d=google.com; s=arc-20160816;
        b=EFH3Ux6gUCxXYVfsnYomZJ4yz5CJvPFYlnKj67SN/TG4Ogl+hwRRkGDIFuwT/mljkJ
         dNr1v/3DBka7MFXeUazgwK0QbDAfO5A/hMquPk/qd0zTap6ldQwV2vygWgVlSsw8XVch
         WK6ltJ97Y5uwN/rJcEDyfHM6gX2k4cy4fg4ZHcNnGmspzIY9ihli1Jdnjru4GAyRcI+q
         iKnxHfz4BF6yoZ1XCNYI5eijp3IFbvRWcZbtTiRmdum5q1kpfQ57YtBcpmMbIB+hWF8w
         6TfWXLpTeUSCXERT/fMVnWhJTex4sUe9WVSrHu5jkQp2v0hbg/n8bF5lARnHW6wImPrX
         T/Eg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=dQ65TUIkhXf1i81OyMgiY0/Ys9jfjmjhDFnAZWRjb6U=;
        b=q7sxYgt4h0LJ0yZd2OrtwVarurJVGTT4TP2s4gONFO6wzPNyepR5t69rRlFI5JvuTM
         +5abvxpzC6oU/oEHVPyNtyR9b6hpjSYUdqmRZCAswKuwJuLphqm4obs0a5E/wJw4Wj5h
         /Svz6+PV3B76hpxAMNfdMechTQVfFw3LvG51XkGAUvOiGbIRik6vpKwxzqbXmdc7V7Ng
         MaSq+7kmRGKFCX3OmTJ0MswA/yqk87QXKBEaD7uhzzWMogSKy3DB6ZnVDEXXhFmBZDND
         1WQ078uKgj5YwA9TDImi2Z3duWFBZADxobkSQkDPZrrIhKaw9gXUB+jVcUYNEesrmS8g
         gHNA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=AzxE+ep+;
       spf=pass (google.com: domain of frederic@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=frederic@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date;
        bh=dQ65TUIkhXf1i81OyMgiY0/Ys9jfjmjhDFnAZWRjb6U=;
        b=ofg1VDc5l6ptgaISGdYQM48E23idnEqIhhPNSKWU5eowMQjEuZmHTDYp52b/a5AdrY
         RKEqz9jW/vZcRwcji0GXkeCPenQB+mKUgVoTPNsRwMKPunPkf9yuNzDrtU9g62hMNeyZ
         0FmGeq1GWDexF91y72JkZEPsE8f+/DglRbWlnNwr7QiA6Z+97q7OiDkryH3sTKXcVy1F
         yfw0Pl8LUGM5hcpI07C3ZTn/whWW41fNyHF+9CKA54ifT6GSOqrwq21SKG0UEViMmqmt
         V6xGGZzFi+RbujlQnvUksZRTjUFlWMZ/5W7+oYrSpwtSGrAIfFM+c4L1oeqG711JFE8k
         bAoQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:sender:from:to:cc:subject:date;
        bh=dQ65TUIkhXf1i81OyMgiY0/Ys9jfjmjhDFnAZWRjb6U=;
        b=HbMmyRNRqkh0jdB8wpPGvajRROfpEZQv+J+b9AdbrJXRWIrUMw3iIZ2h0aBZKB2wiB
         D3OVGW9MXu2VhrvLWTsH2mEhu7Byljgyww2Vj6VOmLl/5cl410Lso5mcAW7rEN+uzoCD
         zh1n0sybsWNAxPhQJ8EKSh1tpkeaC1ngHM/DVUQLu3PCZuXrQVtbzyhroeeNfy6zqXBx
         AqRMTeCzFLphWuHBV6Dk2jHo05n2WpjoQrYp9UKRc6lCyTH2ZNhN/baQCn/nNyDRe7o3
         lt7S7W2mV3cT90IzqOHO/2GWMRt+CxQoZWuUaZ17u7EQF0/qURFSRGmpgGD1Hw3iUKMS
         cSZg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf2gq3hDBFU7xuBr7yFsZsDY4EraJRVQBPSMgr21rxY7J1jsZNgn
	yo0N1+V4jmg9pbc3mWJ/s7A=
X-Google-Smtp-Source: AMsMyM5pPa7SqR3064lrBANZRCEDZDwzhCrLIBAiBnoNjmeGUSGBhxOUtXI2xG/Y+W12GFldtcgloQ==
X-Received: by 2002:a1f:1d12:0:b0:3a3:d387:24dd with SMTP id d18-20020a1f1d12000000b003a3d38724ddmr120707vkd.16.1663664494890;
        Tue, 20 Sep 2022 02:01:34 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6102:2385:b0:395:3560:5755 with SMTP id
 v5-20020a056102238500b0039535605755ls1357992vsr.9.-pod-prod-gmail; Tue, 20
 Sep 2022 02:01:34 -0700 (PDT)
X-Received: by 2002:a05:6102:acd:b0:39b:3a7e:e29a with SMTP id m13-20020a0561020acd00b0039b3a7ee29amr141547vsh.27.1663664494278;
        Tue, 20 Sep 2022 02:01:34 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1663664494; cv=none;
        d=google.com; s=arc-20160816;
        b=baZJQWQMVI8LJWc7OfN1T1edVZBnBTGvOsyVzuznKjGaInQywQXXajE/CmCB9xSuvm
         9fthIJeav5T96nry5ohvshruubQFvueOJayQ3OY5JoUsALuyYRqf9yxaBXJAyCnh1CZX
         3oIzqOyLAUvg1HEr4Ah/9aqKPN38woeL4RqN0aTtQYQS2HUe49Zd0qmaxxIp76CXh58L
         wAx1ZNGMPPxueaYc5c1PHSm97ZUeV5dHlWq/mH0d+si8YpPRElpSFKrvYhTBbtVd8mQH
         sVR3fs8oXOwgGNv3R7WohJSg0SdTDC190P8o6+n69dyEet517OQBPg9ChySp/7yf1QaA
         yPBA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=e4+9PTf2jdrOtKcIMmcKAQXPI81G/XkdnUuEoWLsLM4=;
        b=SOgRdBdx64ZnnmD/sjXSzY0c5v11nLw9qNoy2vf2ypH4QUY3ZBfQEu1RmEIDfPeaae
         0tJ1OfW8+tIwwDLxDj3CiLe5+q8NshEJVuPf+oB9cKGBcBbqr1dvRmj38ddbg+L97rtO
         79q+hLrSzt6N13960/JEnn6NHtsIcGNTJYmS8QkXRycossUroX95ki8zIf8BtwumPcw+
         qnvoFnDnMEeGZioP8YY3iOnVqyacoi70BS4O5kxsGLqhtWfxfnT3wavovneO0dX8xqk9
         SxnVMXoJMJVSTKdR6amB0p7fBw4pYpYbMbt+H9hlEXqOnJWRpNEVEFNMOYNGDcWGWqMQ
         Qnpw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=AzxE+ep+;
       spf=pass (google.com: domain of frederic@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=frederic@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id ay19-20020a056130031300b003b38a9f6c6dsi122217uab.2.2022.09.20.02.01.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 20 Sep 2022 02:01:34 -0700 (PDT)
Received-SPF: pass (google.com: domain of frederic@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id C0C04621CE;
	Tue, 20 Sep 2022 09:01:33 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 12021C433C1;
	Tue, 20 Sep 2022 09:01:32 +0000 (UTC)
Date: Tue, 20 Sep 2022 11:01:29 +0200
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
	James.Bottomley@hansenpartnership.com, deller@gmx.de,
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
Subject: Re: [PATCH v2 08/44] cpuidle,imx6: Push RCU-idle into driver
Message-ID: <20220920090129.GD69891@lothringen>
References: <20220919095939.761690562@infradead.org>
 <20220919101520.869531945@infradead.org>
 <20220919142123.GE58444@lothringen>
 <YymA0yJybIWLco/v@hirez.programming.kicks-ass.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <YymA0yJybIWLco/v@hirez.programming.kicks-ass.net>
X-Original-Sender: frederic@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=AzxE+ep+;       spf=pass
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

On Tue, Sep 20, 2022 at 10:58:59AM +0200, Peter Zijlstra wrote:
> On Mon, Sep 19, 2022 at 04:21:23PM +0200, Frederic Weisbecker wrote:
> > On Mon, Sep 19, 2022 at 11:59:47AM +0200, Peter Zijlstra wrote:
> > > Doing RCU-idle outside the driver, only to then temporarily enable it
> > > again, at least twice, before going idle is daft.
> > 
> > Hmm, what ends up calling RCU_IDLE() here? Also what about
> > cpu_do_idle()?
> 
> I've ammended patches 5-12 with a comment like:
> 
> Notably both cpu_pm_enter() and cpu_cluster_pm_enter() implicity
> re-enable RCU.
> 
> (each noting the specific sites for the relevant patch).

Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220920090129.GD69891%40lothringen.
