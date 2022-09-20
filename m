Return-Path: <kasan-dev+bncBCBMVA7CUUHRBVXYUWMQMGQEEEWZWZA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53f.google.com (mail-pg1-x53f.google.com [IPv6:2607:f8b0:4864:20::53f])
	by mail.lfdr.de (Postfix) with ESMTPS id AC3665BE05C
	for <lists+kasan-dev@lfdr.de>; Tue, 20 Sep 2022 10:39:52 +0200 (CEST)
Received: by mail-pg1-x53f.google.com with SMTP id 126-20020a630284000000b0043942ef3ac7sf1234271pgc.11
        for <lists+kasan-dev@lfdr.de>; Tue, 20 Sep 2022 01:39:52 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1663663191; cv=pass;
        d=google.com; s=arc-20160816;
        b=rJqbkmAMGxvTT8/zf55BJTKqsvej1PWWviV41Y/E+aAUBn6mkYSeykWWSS4Z/I9qZq
         81FP19+wmJtYNPW68R96/vO6E77733Zdn6XTCh4oGW06qDIpO2wqTNU0wKfg6yadqO8r
         nKkNGzYJXi00nZEiam6/eg+PXHxYzBe9vf2ImK9CXMcZA0kcUaKbcdx9w1aDnlIMVj+J
         x5F6qWhc7xV2vVJ/r0i7exFK8zpecQIf7pWdfFkYE3ekCJcBQknOufW6gcWq4vYGzRCs
         NG/hKVUpmty+Gk53EQsk1yjir0izWdiY8yNgyVcmtGqFYm6GdVbi7WwWrGvYGXGYE6hW
         4JjQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=e7CpGMq7ivSCeVs2gsKycIpicbH0hTI85DRq2FKFRko=;
        b=OHmZ/Pi2gSFLpqoqY0W9sv5pmH9n9I2L8iJxgM4v7tUF00SuDXIUpfN32kcF6kYxPX
         V/4kYgQJfquFq6SpQWEGEf1+rXef5H5AFhyI63bkc419URjQ5qvibq6wFsZY+MAqNnza
         XUPEQNdQmVaHHroyL023HgiWWdZnJqGhgCDjf1+DZZI9Ws2Hwnwxr9XhSaZdJoJEQVMp
         KlK0kn/xMVHE3Q4lD5WLGQ0i4rIJNC5KRKvJOoGHf0hnD4c0PnHcBxJygN17pi1W3sO+
         bSQjthRFm1cPvQVV8TrzRs8rruOVbjLQwrub80dxxSNoJQHvoTGmZDrfGBvKxz2XF1jQ
         F77Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=AfHPkPep;
       spf=pass (google.com: domain of frederic@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=frederic@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date;
        bh=e7CpGMq7ivSCeVs2gsKycIpicbH0hTI85DRq2FKFRko=;
        b=R5ovPmQ/HRsKyh+uMjikIrg0KUzojNF4qzYzf5qCubwUY8T4b3uSucBpelcz/YDHe2
         U/UXklI9j6meCWRX20V+qhR4CJsi04Aul5whh8h2WY4qQcRkP5D23DYMP8iVq913sIH6
         vhW96Ee5I4IDsPEnGgO91dsDeOW7s1+8FKL3tFG/xBzPwfd/bfzyJ123YgixMW11zmhA
         bjTuMCTdc9c7rBdaaHFYGvUg62/HfAvdJFLtEqzrazdq55v0xlPrkqxV4eWbOsyPC7q4
         04wYihG9xc8MIzLb/S/h8tI8q6X7HXi5xt/kCwc3WTd9THeDf4DDBYf5hFRuqRTxwX1G
         mh8A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:sender:from:to:cc:subject:date;
        bh=e7CpGMq7ivSCeVs2gsKycIpicbH0hTI85DRq2FKFRko=;
        b=xHzkycQMOOamHT9LPGruoM9NG7QFhdE7sE7kxhzWE7Vs0ldVk2QtD4X8VPzJXK/gNH
         PYnI9XSxxO1IzQ2WZYVY90JNkiuJqGPm/ErQTnXvSlIMFvFCXqCFWvPV0C6N04Kj7qRS
         Yl8XWWVN8x7Jd/ThVwvsGP2g9coClgRcrPTt3AwS1eBYaIEt+Kda8uJ5tggj1Glcwzse
         eFNTcnzQglrqMW/O41DSa2O/48vXSmTBDTRL3pFOFyfEGqdkH6FjKnzgesRNwqjr5kqJ
         497hR1i3/RsUfqsZB7XjMyv8OAC1tBovRWeghCnknR36k3Vg8wc4nIZEkWK660wvX8pG
         vPbw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf1WetiRxI1+NPxRc0dyKm5+ZoA5a1KvELvOo2bAuvJH2TikNKWc
	AAArYhFW0ANkzCTdLb5DHRk=
X-Google-Smtp-Source: AMsMyM7zJGUD9UpzX2Wtv/CzoBlyMYOalN5crWG3qcFkYo2E12NJFT5NsmysBLr2lx2mWXlF0rKdHg==
X-Received: by 2002:a65:5504:0:b0:42a:352d:c79c with SMTP id f4-20020a655504000000b0042a352dc79cmr20207573pgr.58.1663663191126;
        Tue, 20 Sep 2022 01:39:51 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:298f:b0:541:d22f:4f4a with SMTP id
 cj15-20020a056a00298f00b00541d22f4f4als3989573pfb.10.-pod-prod-gmail; Tue, 20
 Sep 2022 01:39:50 -0700 (PDT)
X-Received: by 2002:a05:6a00:18a1:b0:542:5e3a:3093 with SMTP id x33-20020a056a0018a100b005425e3a3093mr23072371pfh.18.1663663190395;
        Tue, 20 Sep 2022 01:39:50 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1663663190; cv=none;
        d=google.com; s=arc-20160816;
        b=OMnA0V2W0UmLz5F0yKewCVKWzujSLszk1A8osFt1Tnom0iADXSThqcfPZOPI3Ag8/k
         25Ika+5c2j0EifwxJlJV69PBZw2DC7eeY08VFnb/dzT8ma31wRutvhxHKewprbUZMKc2
         hyIeY9TY1iQsFJfRdnkpv9bi8VMN7yYAZJIii/cG6aFmd23DdfL9cZt/idq+mncuq7rm
         ueg1G7jiiVYRceu5msrwpGxGe0u1yySPgV8OXgAIdhuioFUFk/w+zOQWmB1e8E2sAOBc
         rRrI45DhexR7NaDKjHmp78mmveccowRGrE9pjvc5hwPjgKEg533yKMIhSSw514y/mZMB
         7g4A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=UqdWDfGlw+0cexQ0+i6BAF8SgKmxkzRB1tEm5H+3leU=;
        b=FWsOIunj66Fr4Mtt+WROVv44Tq/5f6r17BqgAr/13DJDxMAlJm08o8sNuxJ5+u+0eR
         Kl0vNKCiXszsmCC7iQ8inQbPhNYXKEEQRhZUrRmbn5pK3QrGiqimg47tkEgr8QIRtteZ
         bh88yyHPdAw/SSN8Mv+mLTlWhSGnSi3ZTWWbjByP+WcJRxSQYu15UmqM7bWd1oCRyJ+x
         w28iz3t2pET9pjpc9cZlxtLUrlhVbwAaf06upy0I4zULNHYtV/unyT+fXeNXuE2/rwZw
         +Lhi6wwLahcQXP/Wv86VkLjdviRrSMGGXQDvCrGEUGiv2MbaYZKy50SSzyrUQQbzK99Y
         8/NQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=AfHPkPep;
       spf=pass (google.com: domain of frederic@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=frederic@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id l15-20020a170903244f00b00176d0b3d584si28790pls.11.2022.09.20.01.39.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 20 Sep 2022 01:39:50 -0700 (PDT)
Received-SPF: pass (google.com: domain of frederic@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id D45F561CC0;
	Tue, 20 Sep 2022 08:39:49 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 2BF8AC433D6;
	Tue, 20 Sep 2022 08:39:48 +0000 (UTC)
Date: Tue, 20 Sep 2022 10:39:45 +0200
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
Subject: Re: [PATCH v2 09/44] cpuidle,omap3: Push RCU-idle into driver
Message-ID: <20220920083945.GA69891@lothringen>
References: <20220919095939.761690562@infradead.org>
 <20220919101520.936337959@infradead.org>
 <20220919143142.GA61009@lothringen>
 <YyiIaeQY8STLK0d0@hirez.programming.kicks-ass.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <YyiIaeQY8STLK0d0@hirez.programming.kicks-ass.net>
X-Original-Sender: frederic@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=AfHPkPep;       spf=pass
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

On Mon, Sep 19, 2022 at 05:19:05PM +0200, Peter Zijlstra wrote:
> On Mon, Sep 19, 2022 at 04:31:42PM +0200, Frederic Weisbecker wrote:
> > On Mon, Sep 19, 2022 at 11:59:48AM +0200, Peter Zijlstra wrote:
> > > Doing RCU-idle outside the driver, only to then teporarily enable it
> > > again before going idle is daft.
> > 
> > That doesn't tell where those calls are.
> 
> cpu_pm_enter/exit and the power domain stuff, possibly also the clock
> domain stuff. It's all over :/
> 
> I suppose I can add a blub and copy/paste it around the various patches
> if you want.

Yes please, sorry I don't want to bother but, just for the sake of
git blame to report something useful in 5 years.

Thanks.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220920083945.GA69891%40lothringen.
