Return-Path: <kasan-dev+bncBDF57NG2XIHRB75G6CMQMGQEH4YAKLI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x839.google.com (mail-qt1-x839.google.com [IPv6:2607:f8b0:4864:20::839])
	by mail.lfdr.de (Postfix) with ESMTPS id 871975F415D
	for <lists+kasan-dev@lfdr.de>; Tue,  4 Oct 2022 13:05:36 +0200 (CEST)
Received: by mail-qt1-x839.google.com with SMTP id v9-20020a05622a188900b0035cc030ca25sf8967519qtc.1
        for <lists+kasan-dev@lfdr.de>; Tue, 04 Oct 2022 04:05:36 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1664881535; cv=pass;
        d=google.com; s=arc-20160816;
        b=ye9JG1qJbuRvleTIHMzm6GL4ck3Bm1O0r9xAQOPt0AvmQC45OXgb5e0fvqpMYmVbwi
         wC+gGUfX+V3yw49AttultI0//NNXwPgk+SH2HrXLIAMql4/qfnZ3hn7DT6DffY/Q106P
         E2JgLqnX0B7KxI2jHZMarEFJGE3z+zeLpN6WHlTB0Vv0gkpH9rMrz4iVI/xzXA3oOJ2u
         PYUNaUwdmtPLIcJKWZDKCqECk9vYW/Gsb8FG0XTTFOKIR5ApK7NoHdhdu2vuw4Jn7fBU
         3qdKRIC90p0pJZIP5i6Hian8GnV2Q5DLqz1sWMIiKoKdwvzdmOeMhTyxiPiPFLBclvzC
         tJhg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=AgD9XpKJ8ry7ksPVVHrEkPqoc3kRQr+vWaD8SV2XAHs=;
        b=ByIziUxJ/9RRQ2P6zKgVWMdllqFwPAI8z78blAaK7hr4kMA+oYBQAxEzeV+QSKs80F
         NNFNc9BSDom8AD1lpA90o0iXzZNaN+qDc/NZBp6Cn23oIw2ziPZhUh5powyDtmr6yTqH
         Db1EeL4VMvB17A0CzJCI99kbKfRSY4iEc4qxwxL58HjN2OSKFvTKNUuDRxBjQxAEMqan
         MvvFumEya2PdTVxFRNd4qPwXUtUFT4fBikylrRJwMxbfnVIpC79zpIcjkjFDHlB+oeku
         ImlEAqAZrIVH6RmFQPnnOJM3HKpKNneawZjxNuw2vaAQPHoZ7af6sRd5zJysJJFlzf1I
         iTKw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=ALPYtY9N;
       spf=pass (google.com: domain of ulf.hansson@linaro.org designates 2607:f8b0:4864:20::102c as permitted sender) smtp.mailfrom=ulf.hansson@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:sender:from:to:cc:subject:date;
        bh=AgD9XpKJ8ry7ksPVVHrEkPqoc3kRQr+vWaD8SV2XAHs=;
        b=ESWTRPgzkMr471OiDl9cqjxjjkiNckLpeWw4qMW+6xbALbMHZl/f5hgM3WnnHZ/0Kp
         o+aGJgvr9ga308CRPbbPEVZwZW+IlcUzFHQnoAYdv7zYfNiihu+HuBnvJrlsx9XmyWfl
         pdnKF60kzV41ax9tdZO4LLoTMscpUQZbThcYhyc31QkIoereh/KHyMGfapYM6KX9Nm+b
         SQg1Cj67vUhEOyrGRKNQ7JOODaYz0KcWo0ZjXursYHZ5nD/CUgLA2h1CAuSciSh/YJ4k
         r8gUk/z/1Dc1lOGnz9QFvmyoo8r03nAR0vdUftHb+tZ5a045bbmIQhrbEVELr28GswSu
         imaA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:sender:from:to:cc:subject:date;
        bh=AgD9XpKJ8ry7ksPVVHrEkPqoc3kRQr+vWaD8SV2XAHs=;
        b=qx9huDnYaFU7jgAtAcsD19wYAEKPsKB4SSfZ6v8nywOzhrT6iX7api7gOAm318WyFm
         Esjji19rHOyUWnTUfaew6NlxESVFzyZHywMY+BLYg9tSajFYkHSSZ+VPTHLPLT7lohdk
         A2kicZWPGyJQp/dr6OX3R+aT1AAsNtlWmSNQujKJEncSblDppBLHFQ5iSQl99yOrzWj6
         IC2iXMFAkiwpbcCXfg2NRjC1nha+kxtB8uYtEVsanNoMKwyIdLkKEfz7/2fmkUzIyWd4
         9jM3j2kQl6DJEmPdRpuLysZzFOLHDc1Wl//WZH3oRNK1O36nkdalZdMhd0DaSAODECcK
         Cprg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf0fTfwXKDgDrT9FA3h6r1hVawnQaA3K3rmqeUfCIxVMvDlm1moz
	+AXVPDeUXYrTjAisuS7uJg0=
X-Google-Smtp-Source: AMsMyM6dcJ9ApU7CKsDiFCeNzuiLbMvPDldNpU5zrRqbDjRb40zrj78dgU1cUMMTRWK8tG/s63h69A==
X-Received: by 2002:ac8:598b:0:b0:35c:d6a4:ba0a with SMTP id e11-20020ac8598b000000b0035cd6a4ba0amr19275287qte.663.1664881535553;
        Tue, 04 Oct 2022 04:05:35 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0c:f284:0:b0:4aa:5803:b529 with SMTP id k4-20020a0cf284000000b004aa5803b529ls1565767qvl.5.-pod-prod-gmail;
 Tue, 04 Oct 2022 04:05:35 -0700 (PDT)
X-Received: by 2002:a05:6214:3005:b0:4ad:8042:128a with SMTP id ke5-20020a056214300500b004ad8042128amr19557140qvb.66.1664881535042;
        Tue, 04 Oct 2022 04:05:35 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1664881535; cv=none;
        d=google.com; s=arc-20160816;
        b=m4T48TkQS0gxH16pYq3igquc72NAm2nBDy8n9S/vVb4zbzDThUM1oAMyPoS5ruD8X+
         XFzr/4QNWJPcttiDUgFWRIW3is26s1kUrkN2eI3Ep+lNdGZHjyO/4PzzwMVk/Lrz+9mj
         daxJcxqFmsrZdZVNrELPMO4FDuDcDiFiJ2DpccRQvMCQ7+pOZZZNIh4/AC0IU9VBa9gu
         HVgMLapB/zXEC0xk4HprL4Ef7NFbp3bkjUY2eNJ9xBe/sRWEliOmXMA0/1lUuxdb3TNb
         irPOd5PY1EjFT3O448sFyjhzqOLJzx1KgbI9Y2qS0IzE1eWKrVzSY0cOk/3BPGhHD01o
         Pcnw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=8dOAtcXqtbDTbOtGHdeMRx2lSxGZ/p81xoeulWg88O8=;
        b=0r5184skjbySJK0MToGKdK6l5pgEbZVAerL0K6S2TO1yfcHGXOoQDw62QB9TSs5SRN
         HrfhrPna+sdnj5mkSmzkHLE4pxR5IFc9legTkv4bvPeqK3ebrNY/d2/sqsu4wgiAbkFj
         muL+KYV0gByOE56+xnFlUDLyZcQ13pCAy9axiopJ/hkb7o1AVCgVTJJt+M0hnjfK06j0
         NV/Jo792jNuY5TCPhQuMtbTpHLydbWxOoZt0VJe8sVHdKJkxtFh/Qg5MDcXJ6zrGhyAw
         EiUEDNi/Q1Yuzx9/wBgUT0Y3wcVc5oAYr/EZxik0gsBqikMIR+Q9oyM6X0svLEmU/b+Y
         VhSg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=ALPYtY9N;
       spf=pass (google.com: domain of ulf.hansson@linaro.org designates 2607:f8b0:4864:20::102c as permitted sender) smtp.mailfrom=ulf.hansson@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
Received: from mail-pj1-x102c.google.com (mail-pj1-x102c.google.com. [2607:f8b0:4864:20::102c])
        by gmr-mx.google.com with ESMTPS id e13-20020ac84b4d000000b0035baed984fesi577951qts.5.2022.10.04.04.05.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 04 Oct 2022 04:05:35 -0700 (PDT)
Received-SPF: pass (google.com: domain of ulf.hansson@linaro.org designates 2607:f8b0:4864:20::102c as permitted sender) client-ip=2607:f8b0:4864:20::102c;
Received: by mail-pj1-x102c.google.com with SMTP id p3-20020a17090a284300b0020a85fa3ffcso6613864pjf.2
        for <kasan-dev@googlegroups.com>; Tue, 04 Oct 2022 04:05:34 -0700 (PDT)
X-Received: by 2002:a17:90b:4d07:b0:1ef:521c:f051 with SMTP id
 mw7-20020a17090b4d0700b001ef521cf051mr17203785pjb.164.1664881533975; Tue, 04
 Oct 2022 04:05:33 -0700 (PDT)
MIME-Version: 1.0
References: <20220919095939.761690562@infradead.org> <20220919101521.274051658@infradead.org>
In-Reply-To: <20220919101521.274051658@infradead.org>
From: Ulf Hansson <ulf.hansson@linaro.org>
Date: Tue, 4 Oct 2022 13:04:57 +0200
Message-ID: <CAPDyKFquBVkYmKsriPD+BfVrrz62ih7oCxb7HwOML+Zzs-5U_Q@mail.gmail.com>
Subject: Re: [PATCH v2 14/44] cpuidle,cpu_pm: Remove RCU fiddling from cpu_pm_{enter,exit}()
To: Peter Zijlstra <peterz@infradead.org>
Cc: richard.henderson@linaro.org, ink@jurassic.park.msu.ru, mattst88@gmail.com, 
	vgupta@kernel.org, linux@armlinux.org.uk, ulli.kroll@googlemail.com, 
	linus.walleij@linaro.org, shawnguo@kernel.org, 
	Sascha Hauer <s.hauer@pengutronix.de>, kernel@pengutronix.de, festevam@gmail.com, 
	linux-imx@nxp.com, tony@atomide.com, khilman@kernel.org, 
	catalin.marinas@arm.com, will@kernel.org, guoren@kernel.org, 
	bcain@quicinc.com, chenhuacai@kernel.org, kernel@xen0n.name, 
	geert@linux-m68k.org, sammy@sammy.net, monstr@monstr.eu, 
	tsbogend@alpha.franken.de, dinguyen@kernel.org, jonas@southpole.se, 
	stefan.kristiansson@saunalahti.fi, shorne@gmail.com, 
	James.Bottomley@hansenpartnership.com, deller@gmx.de, mpe@ellerman.id.au, 
	npiggin@gmail.com, christophe.leroy@csgroup.eu, paul.walmsley@sifive.com, 
	palmer@dabbelt.com, aou@eecs.berkeley.edu, hca@linux.ibm.com, 
	gor@linux.ibm.com, agordeev@linux.ibm.com, borntraeger@linux.ibm.com, 
	svens@linux.ibm.com, ysato@users.sourceforge.jp, dalias@libc.org, 
	davem@davemloft.net, richard@nod.at, anton.ivanov@cambridgegreys.com, 
	johannes@sipsolutions.net, tglx@linutronix.de, mingo@redhat.com, bp@alien8.de, 
	dave.hansen@linux.intel.com, x86@kernel.org, hpa@zytor.com, acme@kernel.org, 
	mark.rutland@arm.com, alexander.shishkin@linux.intel.com, jolsa@kernel.org, 
	namhyung@kernel.org, jgross@suse.com, srivatsa@csail.mit.edu, 
	amakhalov@vmware.com, pv-drivers@vmware.com, boris.ostrovsky@oracle.com, 
	chris@zankel.net, jcmvbkbc@gmail.com, rafael@kernel.org, lenb@kernel.org, 
	pavel@ucw.cz, gregkh@linuxfoundation.org, mturquette@baylibre.com, 
	sboyd@kernel.org, daniel.lezcano@linaro.org, lpieralisi@kernel.org, 
	sudeep.holla@arm.com, agross@kernel.org, bjorn.andersson@linaro.org, 
	konrad.dybcio@somainline.org, anup@brainfault.org, thierry.reding@gmail.com, 
	jonathanh@nvidia.com, jacob.jun.pan@linux.intel.com, atishp@atishpatra.org, 
	Arnd Bergmann <arnd@arndb.de>, yury.norov@gmail.com, andriy.shevchenko@linux.intel.com, 
	linux@rasmusvillemoes.dk, dennis@kernel.org, tj@kernel.org, cl@linux.com, 
	rostedt@goodmis.org, pmladek@suse.com, senozhatsky@chromium.org, 
	john.ogness@linutronix.de, juri.lelli@redhat.com, vincent.guittot@linaro.org, 
	dietmar.eggemann@arm.com, bsegall@google.com, mgorman@suse.de, 
	bristot@redhat.com, vschneid@redhat.com, fweisbec@gmail.com, 
	ryabinin.a.a@gmail.com, glider@google.com, andreyknvl@gmail.com, 
	dvyukov@google.com, vincenzo.frascino@arm.com, 
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
	linux-perf-users@vger.kernel.org, virtualization@lists.linux-foundation.org, 
	linux-xtensa@linux-xtensa.org, linux-acpi@vger.kernel.org, 
	linux-pm@vger.kernel.org, linux-clk@vger.kernel.org, 
	linux-arm-msm@vger.kernel.org, linux-tegra@vger.kernel.org, 
	linux-arch@vger.kernel.org, kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: ulf.hansson@linaro.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linaro.org header.s=google header.b=ALPYtY9N;       spf=pass
 (google.com: domain of ulf.hansson@linaro.org designates 2607:f8b0:4864:20::102c
 as permitted sender) smtp.mailfrom=ulf.hansson@linaro.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=linaro.org
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

On Mon, 19 Sept 2022 at 12:17, Peter Zijlstra <peterz@infradead.org> wrote:
>
> All callers should still have RCU enabled.
>
> Signed-off-by: Peter Zijlstra (Intel) <peterz@infradead.org>
> Acked-by: Mark Rutland <mark.rutland@arm.com>

Reviewed-by: Ulf Hansson <ulf.hansson@linaro.org>

Kind regards
Uffe

> ---
>  kernel/cpu_pm.c |    9 ---------
>  1 file changed, 9 deletions(-)
>
> --- a/kernel/cpu_pm.c
> +++ b/kernel/cpu_pm.c
> @@ -30,16 +30,9 @@ static int cpu_pm_notify(enum cpu_pm_eve
>  {
>         int ret;
>
> -       /*
> -        * This introduces a RCU read critical section, which could be
> -        * disfunctional in cpu idle. Copy RCU_NONIDLE code to let RCU know
> -        * this.
> -        */
> -       ct_irq_enter_irqson();
>         rcu_read_lock();
>         ret = raw_notifier_call_chain(&cpu_pm_notifier.chain, event, NULL);
>         rcu_read_unlock();
> -       ct_irq_exit_irqson();
>
>         return notifier_to_errno(ret);
>  }
> @@ -49,11 +42,9 @@ static int cpu_pm_notify_robust(enum cpu
>         unsigned long flags;
>         int ret;
>
> -       ct_irq_enter_irqson();
>         raw_spin_lock_irqsave(&cpu_pm_notifier.lock, flags);
>         ret = raw_notifier_call_chain_robust(&cpu_pm_notifier.chain, event_up, event_down, NULL);
>         raw_spin_unlock_irqrestore(&cpu_pm_notifier.lock, flags);
> -       ct_irq_exit_irqson();
>
>         return notifier_to_errno(ret);
>  }
>
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAPDyKFquBVkYmKsriPD%2BBfVrrz62ih7oCxb7HwOML%2BZzs-5U_Q%40mail.gmail.com.
