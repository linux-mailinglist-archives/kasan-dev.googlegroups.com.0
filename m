Return-Path: <kasan-dev+bncBDJ7DEXEZ4LRBIEY2KMQMGQEQ3LGUAY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa3a.google.com (mail-vk1-xa3a.google.com [IPv6:2607:f8b0:4864:20::a3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 2DB635EE3C3
	for <lists+kasan-dev@lfdr.de>; Wed, 28 Sep 2022 20:02:10 +0200 (CEST)
Received: by mail-vk1-xa3a.google.com with SMTP id b198-20020a1fb2cf000000b003a344f1be22sf4624363vkf.12
        for <lists+kasan-dev@lfdr.de>; Wed, 28 Sep 2022 11:02:10 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1664388129; cv=pass;
        d=google.com; s=arc-20160816;
        b=cTNAb7BxeCemcuHTfOI+lL/AgupsSBWsJKeOt1ThYFimL8cceROg4wFsmJuHPtNspT
         WDr0IkbVGaVr0M5pAsZN5kwp13zk9CjWWrGVqsF9hDhq2lzxUQL7kDqJXNTVzGbQ42ks
         RqEKzrhHaYjtaGSTlt3l//pBWimwO5mbesyILVpbXDTRTA0O8z02wPCFe/kM8FC0DVf9
         mPvCFngV6ebsdOTJ3WDEf20xas278SRwFRYMZWs2QKJP1Mwrts67dwxwONrJVzLZthMF
         YgE8w8nseKk+1Pyjs7hDrIVi6Xaha0r41QZ9Gu8/MI12ouH04TBLTypyb/5USwYZuRS8
         9i+g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:message-id:user-agent:date:to:cc
         :from:subject:references:in-reply-to:mime-version:sender
         :dkim-signature;
        bh=4VOW9IN6OPYt1r8xUTWE1dNHRCBsd9IiRg//ASUK908=;
        b=KSGv0bpHHJhzHOxqyUJF2dm33Kyq+gOYxIgj0ZcsDxTdPwMST4Se4byFKflTOjVKuu
         nf6op7xrEenXgPW/OFQRoglGlwnb0mFI8uLjZ4vuKlGtKDXEaeGxPX6fxxUrOzWi9Fvz
         Z4Y7Q4FlHogPKmULmN6cRx3u6EjeqzD5hPu7+8REmnm+8YBI00kT1l7XjKyN9otx+wPO
         FjzrPoJFD8JAOu449EWhMSKzAc9p8A5RzbwS8JBONqx831/d/BWFy3ZoOYnITlqkwGna
         VFN3eqmd2eTlt1eAy3gDWGB4NiBvEFErepqrHDlGX3vnDjRlOrsYlH52JU5GLR3xV+ty
         5urA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=fail header.i=@kernel.org header.s=k20201202 header.b=T+jczSmR;
       spf=pass (google.com: domain of sboyd@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=sboyd@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:message-id:user-agent:date:to:cc:from:subject
         :references:in-reply-to:mime-version:sender:from:to:cc:subject:date;
        bh=4VOW9IN6OPYt1r8xUTWE1dNHRCBsd9IiRg//ASUK908=;
        b=WW7dK7Q/cINtH8IcpFrUBgfHeeFV58s+vh45Vg7XE49FcYvLv2WrsnPc7EysVi0KuQ
         BfgrSxmN0QxO19s2yYUfvjI759f+jvce7RvUOTPPQ8/wvKWj8tid9k7aOTYc0G25VnGJ
         CixErgjBoBvt/l9rSPt5NizygPpR7nJEnaJz6tyw91YR8cMwg73fcg6Pc9g1a874zi3h
         mGZz3aNKlRtsaUimNz7qEEdypGgB0DlijCkWdGQh9Hk4HiAPrx68PkU1OIaorbynBzv5
         mH1X6dh2aJIOB/N11CtBQOJDKValvHaRiZG/+e3iuUBYJ/tEeHPeqL89s+Lmm3S8+NfK
         By5Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:message-id
         :user-agent:date:to:cc:from:subject:references:in-reply-to
         :mime-version:x-gm-message-state:sender:from:to:cc:subject:date;
        bh=4VOW9IN6OPYt1r8xUTWE1dNHRCBsd9IiRg//ASUK908=;
        b=7CklIWbixHGM7G8f62pZv5aXp0kmmdVrWivpDVGm/pdtakJ3U0UCKOcC98NMD5XGRK
         vBLguWocrV0ubqr9vgC5uZgqootF1JcZOOQGhsCFVjWfxFatIv1GH7zZ8sjhJeiWc7Z8
         7XM0qt7a0ueC0al+NWW/f1lQmArIZkpWklLwxY7ajvfYRSf3x72oFSKp4aegXtnFte/J
         HzIBy/BT9zYAP9cwFVBoRNp3bLm+lcolmujlwTrCRsrtAHxXKsuRHbUOLL7DgS8cMMir
         fOESw4Vm4WeOQH12eBrsDeACEPnZcBLzUQiuI+mJCBJSce4i9MA1ETQZ7R5iB+pDxntb
         9AeA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf01iZOCnSVPesgVRCj2HeL9ap7XnkMTZD7qx+Hoy/j9+/MFNA/V
	dBJ8ENQR61B5qmFuwoFTOjI=
X-Google-Smtp-Source: AMsMyM4jBikNmxpcpd3991kRTTfFBlVRNrh9i+6gUF10gjhoxEjNczoDnMS4ZvEhfYmB1lEuZ7Mz+Q==
X-Received: by 2002:a05:6122:218a:b0:3a3:9de2:1d7b with SMTP id j10-20020a056122218a00b003a39de21d7bmr15594956vkd.1.1664388128827;
        Wed, 28 Sep 2022 11:02:08 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:c105:0:b0:397:63a3:3998 with SMTP id d5-20020a67c105000000b0039763a33998ls1318434vsj.7.-pod-prod-gmail;
 Wed, 28 Sep 2022 11:02:08 -0700 (PDT)
X-Received: by 2002:a67:a406:0:b0:39b:22fe:78d6 with SMTP id n6-20020a67a406000000b0039b22fe78d6mr15441918vse.72.1664388121641;
        Wed, 28 Sep 2022 11:02:01 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1664388121; cv=none;
        d=google.com; s=arc-20160816;
        b=qU/+uWcl7tHfIPq5FEwjv2QHv+MNxmzQVf5r1I15dfMKXAYXdW9AK/E3zsqKTYth3X
         JKQ/lCLkDk2Se8pJ/M1dl+sKj1Fmr1WFm8h9iEQcs2FS07LpAOveQmpEJ5RW0/mGuy0s
         jJHAtvrw0MeYjhnoEIlm8BInHFoor1pe8U5mPzdQ2YYwOwAK2UgxJA8DB6P1bBKXMb4W
         wfHNKFKaHW40sDtWlY54avlQfWr6Mnyc3MkTMkt9XsV2ZqJ6MD9KxDFdmsQeH1KGkyUX
         jb13VYCdD/pKaEdF2zFKmEFLmWKd9vf6bgyj+TW84e1zrM2ncHHwS7gzAbiqpR+vgAKu
         OAug==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=message-id:user-agent:date:to:cc:from:subject:references
         :in-reply-to:content-transfer-encoding:mime-version:dkim-signature;
        bh=+R+5Ns222VYKCsIAXm0EtGUD9zLCQPxIpEujC1GgACo=;
        b=DSxVijQiPROd5dpkZrJ6dEc1U2ct1rEvncVnNtwAcTGyViXDOOcqySalIwJNOLD30w
         kvDJ3cFJFSbSONV9K1R0VFVBdFYOedOA09FlZn7xWxQqgdY5+epjM/qxuyHMERLvIGnL
         2Syc7CfaTBk5yzdDujLlu4L6CMNHqVi+Aqs4A1grkJGuGFwFdCGks0gZJuFgZVKO5Bbi
         GyybvvT2fycJIhNfo25g8GyLIobyBcg3CkrATxmaAG2XHb5JO6LUurPuDEiGMm1EaQmE
         sfgtn6LMu/P4Nlr9WHXB0r8Vh4UBZbOV/fKNLEx01wiI78svPWWykRP5CZXEU8yEJKJo
         tn6w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=fail header.i=@kernel.org header.s=k20201202 header.b=T+jczSmR;
       spf=pass (google.com: domain of sboyd@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=sboyd@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id f12-20020ab03d0c000000b003d22af4df42si159359uax.1.2022.09.28.11.02.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 28 Sep 2022 11:02:01 -0700 (PDT)
Received-SPF: pass (google.com: domain of sboyd@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id E611461F80;
	Wed, 28 Sep 2022 18:02:00 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 3512EC4314C;
	Wed, 28 Sep 2022 18:01:59 +0000 (UTC)
Content-Type: text/plain; charset="UTF-8"
MIME-Version: 1.0
In-Reply-To: <20220919101522.975285117@infradead.org>
References: <20220919095939.761690562@infradead.org> <20220919101522.975285117@infradead.org>
Subject: Re: [PATCH v2 39/44] cpuidle,clk: Remove trace_.*_rcuidle()
From: Stephen Boyd <sboyd@kernel.org>
Cc: richard.henderson@linaro.org, ink@jurassic.park.msu.ru, mattst88@gmail.com, vgupta@kernel.org, linux@armlinux.org.uk, ulli.kroll@googlemail.com, linus.walleij@linaro.org, shawnguo@kernel.org, Sascha Hauer <s.hauer@pengutronix.de>, kernel@pengutronix.de, festevam@gmail.com, linux-imx@nxp.com, tony@atomide.com, khilman@kernel.org, catalin.marinas@arm.com, will@kernel.org, guoren@kernel.org, bcain@quicinc.com, chenhuacai@kernel.org, kernel@xen0n.name, geert@linux-m68k.org, sammy@sammy.net, monstr@monstr.eu, tsbogend@alpha.franken.de, dinguyen@kernel.org, jonas@southpole.se, stefan.kristiansson@saunalahti.fi, shorne@gmail.com, James.Bottomley@HansenPartnership.com, deller@gmx.de, mpe@ellerman.id.au, npiggin@gmail.com, christophe.leroy@csgroup.eu, paul.walmsley@sifive.com, palmer@dabbelt.com, aou@eecs.berkeley.edu, hca@linux.ibm.com, gor@linux.ibm.com, agordeev@linux.ibm.com, borntraeger@linux.ibm.com, svens@linux.ibm.com, ysato@users.sourceforge.jp, dalias@libc.org, davem@davemloft.n
 et, richard@nod.at, anton.ivanov@cambridgegreys.com, johannes@sipsolutions.net, tglx@linutronix.de, mingo@redhat.com, bp@alien8.de, dave.hansen@linux.intel.com, x86@kernel.org, hpa@zytor.com, acme@kernel.org, mark.rutland@arm.com, alexander.shishkin@linux.intel.com, jolsa@kernel.org, namhyung@kernel.org, jgross@suse.com, srivatsa@csail.mit.edu, amakhalov@vmware.com, pv-drivers@vmware.com, boris.ostrovsky@oracle.com, chris@zankel.net, jcmvbkbc@gmail.com, rafael@kernel.org, lenb@kernel.org, pavel@ucw.cz, gregkh@linuxfoundation.org, mturquette@baylibre.com, daniel.lezcano@linaro.org, lpieralisi@kernel.org, sudeep.holla@arm.com, agross@kernel.org, bjorn.andersson@linaro.org, konrad.dybcio@somainline.org, anup@brainfault.org, thierry.reding@gmail.com, jonathanh@nvidia.com, jacob.jun.pan@linux.intel.com, atishp@atishpatra.org, Arnd Bergmann <arnd@arndb.de>, yury.norov@gmail.com, andriy.shevchenko@linux.intel.com, linux@rasmusvillemoes.dk, dennis@kernel.org, tj@kernel.org, cl@linux.com, ro
 stedt@goodmis.org, pmladek@suse.com, senozhatsky@chromium.org, john.ogness@linutronix.de, juri.lelli@redhat.com, vincent.guittot@linaro.org, dietmar.eggemann@arm.com, bsegall@google.com, mgorman@suse.de, bristot@redhat.com, vschneid@redhat.com, fweisbec@gmail.com, ryabinin.a.a@gmail.com, glider@google.com, andreyknvl@gmail.com, dvyukov@google.com, vincenzo.frascino@arm.com, Andrew Morton <akpm@linux-foundation.org>, jpoimboe@kernel.org, linux-alpha@vger.kernel.org, linux-kernel@vger.kernel.org, linux-snps-arc@lists.infradead.org, linux-omap@vger.kernel.org, linux-csky@vger.kernel.org, linux-hexagon@vger.kernel.org, linux-ia64@vger.kernel.org, loongarch@lists.linux.dev, linux-m68k@lists.linux-m68k.org, linux-mips@vger.kernel.org, openrisc@lists.librecores.org, linux-parisc@vger.kernel.org, linuxppc-dev@lists.ozlabs.org, linux-riscv@lists.infradead.org, linux-s390@vger.kernel.org, linux-sh@vger.kernel.org, sparclinux@vger.kernel.org, linux-um@lists.infradead.org, linux-perf-users@vger
 .kernel.org, virtualization@lists.linux-foundation.org, linux-xtensa@linux-xtensa.org, linux-acpi@vger.kernel.org, linux-pm@vger.kernel.org, linux-clk@vger.kernel.org, linux-arm-msm@vger.kernel.org, linux-tegra@vger.kernel.org, linux-arch@vger.kernel.org, kasan-dev@googlegroups.com
To: peterz@infradead.org
Date: Wed, 28 Sep 2022 11:01:57 -0700
User-Agent: alot/0.10
Message-Id: <20220928180159.3512EC4314C@smtp.kernel.org>
X-Original-Sender: sboyd@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=fail
 header.i=@kernel.org header.s=k20201202 header.b=T+jczSmR;       spf=pass
 (google.com: domain of sboyd@kernel.org designates 139.178.84.217 as
 permitted sender) smtp.mailfrom=sboyd@kernel.org;       dmarc=pass (p=NONE
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

Quoting Peter Zijlstra (2022-09-19 03:00:18)
> OMAP was the one and only user.
> 
> Signed-off-by: Peter Zijlstra (Intel) <peterz@infradead.org>
> ---

Acked-by: Stephen Boyd <sboyd@kernel.org>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220928180159.3512EC4314C%40smtp.kernel.org.
