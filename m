Return-Path: <kasan-dev+bncBDF57NG2XIHRBB5J6CMQMGQEJ3O22AI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x537.google.com (mail-pg1-x537.google.com [IPv6:2607:f8b0:4864:20::537])
	by mail.lfdr.de (Postfix) with ESMTPS id EA2515F418B
	for <lists+kasan-dev@lfdr.de>; Tue,  4 Oct 2022 13:10:00 +0200 (CEST)
Received: by mail-pg1-x537.google.com with SMTP id r7-20020a632047000000b00439d0709849sf8756904pgm.22
        for <lists+kasan-dev@lfdr.de>; Tue, 04 Oct 2022 04:10:00 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1664881799; cv=pass;
        d=google.com; s=arc-20160816;
        b=t6LdBzKnk9lPg/0+OWY45hpVaDHL7fBxqqFr/UYMZ7mPy3b/FypZpnZGtW/w/fpzab
         7eT9wTNoq4FnsnWYfSDSMWZmMvnnkqCh6Gq/D4f2c69XLwrgBZNqYGeB+THOYh94go6I
         e/yHo/f08iOC6CBKybeLnY+FW39vZLVeh83vXK6yfGsMeshFSfpoV40w3F68nBgnhKoZ
         XGOXth9/6rNVXx7T6zGMDfO6M6Pj2/u1SHSrIvegkkF/ry5fRWaZPZoRp+SvgOM/Rvb0
         KiIUrYRK2/zCj41kh0OVSspBkEZEof3XKBplHvGcbjrZyaDLzT30Dn10Y1TsAh/YHH7U
         Bswg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=sFdF4GZOX086ISrwK9l5LUhY5IqIxyxTMWCR9UIlKXo=;
        b=D0RccYxnrNBKEevElM+mYRBwx8otVr+d+tn7otqu9RH9cCHX3fK4x1LoBvHlTN7ytT
         pZb+69g5gPIljCyM5lz5Bqci3HkXGQ3jc0jixRI0WyCF166mpcVlVNOe2UbskD7nGWGh
         P3MCnL3NutK5zJXlQsRy5RMrF39o3lJS1IFA9JWczr51Bkc5NXP+7G9XBjNw1L7kotGQ
         U+Ii4yfgzepVdr1V2xfGh4m/yIo9Oqn87W9WsyAY7Yln5K53oPKirzRqaUpDjePMFCKZ
         cdQoAcuvYPbmpF79glVJvWAA5hvVJzamRz5an7e8IApxaVdf+JD4ntV8GyrFyKKjmuyT
         pSlQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=OhrgekEJ;
       spf=pass (google.com: domain of ulf.hansson@linaro.org designates 2607:f8b0:4864:20::530 as permitted sender) smtp.mailfrom=ulf.hansson@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:sender:from:to:cc:subject:date;
        bh=sFdF4GZOX086ISrwK9l5LUhY5IqIxyxTMWCR9UIlKXo=;
        b=f6B1tYh2YQiB08h/gIOS0WBLD+mMO6TSP8vJT+1SBCDA1pdD3lbqac1T+xeOKrmwsR
         MB3v9vNGeker3641wuTgLs3HPzBrTb+wxVqpfq0w+HBKaqTsgR1XjtzfRXQDnVxXRQnF
         wzrtuXGKhwvsi0r9zvDyLpQXyj5GIT6hrb5osFBOK6cs+xFz8LRocaTp/YFlrmCkCmtG
         e4yS9PFgv3EqXrv6NC1roZPhl5wMXa+vFJJzx/0z1fbmq2vAT6zYyXt2F3x05+WYfDJ5
         nc3BfmwFSc1OdRNZmoguZnFlz0pw+UMc7oQyJ21XPI4kSsGj2S2Yz/eXEQbmv+cDth+W
         pOGg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:sender:from:to:cc:subject:date;
        bh=sFdF4GZOX086ISrwK9l5LUhY5IqIxyxTMWCR9UIlKXo=;
        b=Hv+cEOddN5RxAy7Tp28SQb93jhfq/7kiZfCa0kbrDmJ/TBi/GLG8wDe4SYlblkYOK7
         fdEysWD3BHQbeoKEmlT+06Ixzbt4wHl+K5zFSET9rzG3iUqJ2IpOLVHtslZTGu2NgRWC
         ZjCxW+TKNuGlj45tWUhHb/SL9AeROMqykXQuN2Q0QuF18hFn94Jb4WSZzqXp79iarFJh
         N1c+ZV0OLd0CT806Pn7sFVSV+zOle0T2njDPJKSDyJGeKOCgLRkL8Sg0RJVHwKHW3ted
         hj+Qcs7x986HlLSt1RQzzrm46KGUN8ZlVDhdpquk30vG8OhmT+v4XawKkVkgPczYEIl9
         921w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf1PUUyO1D0+n8oVufbpUYMPusqO7vhnaCNSfqrBMLss4I0UcOPn
	TIEwgAKdGCvPaNejaNGIVWg=
X-Google-Smtp-Source: AMsMyM4QdTq4HT8Ebk76dQyLGQF2eA2iBJyGYyGS/QseOwYWfqNBg28xTJGdjWPQJ/TIbsnCFsk9JQ==
X-Received: by 2002:a17:90a:1b6e:b0:1f5:1902:af92 with SMTP id q101-20020a17090a1b6e00b001f51902af92mr17128900pjq.238.1664881799248;
        Tue, 04 Oct 2022 04:09:59 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:6907:0:b0:43c:ad84:1eb4 with SMTP id e7-20020a636907000000b0043cad841eb4ls7677134pgc.1.-pod-prod-gmail;
 Tue, 04 Oct 2022 04:09:58 -0700 (PDT)
X-Received: by 2002:a63:e211:0:b0:43b:f03e:3cc5 with SMTP id q17-20020a63e211000000b0043bf03e3cc5mr22817319pgh.256.1664881798448;
        Tue, 04 Oct 2022 04:09:58 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1664881798; cv=none;
        d=google.com; s=arc-20160816;
        b=H79UBiSKmMp+rog/84VlgE21rUeXyzi/JZdiZlzlDWu6p68cdr2lejbD4NYACbDTF5
         suhVO4+ZYzbJjmIf3yKZl0j8ZFxVlPRlSupVL8FI2EqwP4cMapZZzoAIRvzZUH2CEXO0
         Iyt/LYCjE32LAS7VOhGINaC3h+EtJzwawRfs0kvwvVIzGf2lOYmmVlfOQGuc5ZMgQ9jh
         NRkh1P9pRMF9uIYOF6mpZFl2AnJCrhrUf1YCnJVkTcICt1iCgqAH+uCELpO6UN2/1TTU
         ksHLsmcXyXcHEnHBitF9XiuhQ8cRCS2xB2xVugTn7tfEMbtKBw+oY2m8+2JGMQ68/+Yr
         cngw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Z7fvRiwPcYU72K21mcsEeWsle1VHrp2FoZLK7rnaPdE=;
        b=qUsLS3GtQs9cB6Yt/6O/emnj52HEU6AAI46/pgipIfuVDLf5H53xC3opxLrOxBo0M8
         maAi0dJxNOe3V9LpEozu6KUa7XRAXUtQ6bOM30ZU7TaZT9mjmporSfwKsWPXH6cmCRXw
         EEuyvPg0/7A+5HpnEWSMNnYkWKHV+4rCEMuEzgxGRs7nEjQBIx3xiVbHfpeXJ4bjOBve
         Eli/2kJoq2KtnwyYqD+1hfXV9trRedF7UGtstc4dVhgvzGF9IAASZm6HBKbuwBe3vmrV
         9gOs/ZAYDQLizC9P7ZPp/P16v5D49jSWKCBt9laVDBSm4RLHY6S55QK7jHOSQVoAPqGk
         nMgw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=OhrgekEJ;
       spf=pass (google.com: domain of ulf.hansson@linaro.org designates 2607:f8b0:4864:20::530 as permitted sender) smtp.mailfrom=ulf.hansson@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
Received: from mail-pg1-x530.google.com (mail-pg1-x530.google.com. [2607:f8b0:4864:20::530])
        by gmr-mx.google.com with ESMTPS id pc7-20020a17090b3b8700b001faab3fc6a0si766627pjb.3.2022.10.04.04.09.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 04 Oct 2022 04:09:58 -0700 (PDT)
Received-SPF: pass (google.com: domain of ulf.hansson@linaro.org designates 2607:f8b0:4864:20::530 as permitted sender) client-ip=2607:f8b0:4864:20::530;
Received: by mail-pg1-x530.google.com with SMTP id j71so6285873pge.2
        for <kasan-dev@googlegroups.com>; Tue, 04 Oct 2022 04:09:58 -0700 (PDT)
X-Received: by 2002:a63:464d:0:b0:441:5968:cd0e with SMTP id
 v13-20020a63464d000000b004415968cd0emr18985801pgk.595.1664881798027; Tue, 04
 Oct 2022 04:09:58 -0700 (PDT)
MIME-Version: 1.0
References: <20220919095939.761690562@infradead.org> <20220919101522.975285117@infradead.org>
In-Reply-To: <20220919101522.975285117@infradead.org>
From: Ulf Hansson <ulf.hansson@linaro.org>
Date: Tue, 4 Oct 2022 13:09:21 +0200
Message-ID: <CAPDyKFqoBJPgehVODY0DGuUcnqJE5rpZjRPfdMCzOP0=JrvKNw@mail.gmail.com>
Subject: Re: [PATCH v2 39/44] cpuidle,clk: Remove trace_.*_rcuidle()
To: Peter Zijlstra <peterz@infradead.org>
Cc: juri.lelli@redhat.com, rafael@kernel.org, catalin.marinas@arm.com, 
	linus.walleij@linaro.org, bsegall@google.com, guoren@kernel.org, pavel@ucw.cz, 
	agordeev@linux.ibm.com, linux-arch@vger.kernel.org, 
	vincent.guittot@linaro.org, mpe@ellerman.id.au, chenhuacai@kernel.org, 
	christophe.leroy@csgroup.eu, linux-acpi@vger.kernel.org, agross@kernel.org, 
	geert@linux-m68k.org, linux-imx@nxp.com, vgupta@kernel.org, 
	mattst88@gmail.com, mturquette@baylibre.com, sammy@sammy.net, 
	pmladek@suse.com, linux-pm@vger.kernel.org, 
	Sascha Hauer <s.hauer@pengutronix.de>, linux-um@lists.infradead.org, npiggin@gmail.com, 
	tglx@linutronix.de, linux-omap@vger.kernel.org, dietmar.eggemann@arm.com, 
	andreyknvl@gmail.com, gregkh@linuxfoundation.org, 
	linux-kernel@vger.kernel.org, linux-perf-users@vger.kernel.org, 
	senozhatsky@chromium.org, svens@linux.ibm.com, jolsa@kernel.org, 
	tj@kernel.org, Andrew Morton <akpm@linux-foundation.org>, mark.rutland@arm.com, 
	linux-ia64@vger.kernel.org, dave.hansen@linux.intel.com, 
	virtualization@lists.linux-foundation.org, 
	James.Bottomley@hansenpartnership.com, jcmvbkbc@gmail.com, 
	thierry.reding@gmail.com, kernel@xen0n.name, cl@linux.com, 
	linux-s390@vger.kernel.org, vschneid@redhat.com, john.ogness@linutronix.de, 
	ysato@users.sourceforge.jp, linux-sh@vger.kernel.org, festevam@gmail.com, 
	deller@gmx.de, daniel.lezcano@linaro.org, jonathanh@nvidia.com, 
	dennis@kernel.org, lenb@kernel.org, linux-xtensa@linux-xtensa.org, 
	kernel@pengutronix.de, gor@linux.ibm.com, linux-arm-msm@vger.kernel.org, 
	linux-alpha@vger.kernel.org, linux-m68k@lists.linux-m68k.org, 
	loongarch@lists.linux.dev, shorne@gmail.com, chris@zankel.net, 
	sboyd@kernel.org, dinguyen@kernel.org, bristot@redhat.com, 
	alexander.shishkin@linux.intel.com, fweisbec@gmail.com, lpieralisi@kernel.org, 
	atishp@atishpatra.org, linux@rasmusvillemoes.dk, kasan-dev@googlegroups.com, 
	will@kernel.org, boris.ostrovsky@oracle.com, khilman@kernel.org, 
	linux-csky@vger.kernel.org, pv-drivers@vmware.com, 
	linux-snps-arc@lists.infradead.org, mgorman@suse.de, 
	jacob.jun.pan@linux.intel.com, Arnd Bergmann <arnd@arndb.de>, ulli.kroll@googlemail.com, 
	linux-clk@vger.kernel.org, rostedt@goodmis.org, ink@jurassic.park.msu.ru, 
	bcain@quicinc.com, tsbogend@alpha.franken.de, linux-parisc@vger.kernel.org, 
	ryabinin.a.a@gmail.com, sudeep.holla@arm.com, shawnguo@kernel.org, 
	davem@davemloft.net, dalias@libc.org, tony@atomide.com, amakhalov@vmware.com, 
	konrad.dybcio@somainline.org, bjorn.andersson@linaro.org, glider@google.com, 
	hpa@zytor.com, sparclinux@vger.kernel.org, linux-hexagon@vger.kernel.org, 
	linux-riscv@lists.infradead.org, vincenzo.frascino@arm.com, 
	anton.ivanov@cambridgegreys.com, jonas@southpole.se, yury.norov@gmail.com, 
	richard@nod.at, x86@kernel.org, linux@armlinux.org.uk, mingo@redhat.com, 
	aou@eecs.berkeley.edu, hca@linux.ibm.com, richard.henderson@linaro.org, 
	stefan.kristiansson@saunalahti.fi, openrisc@lists.librecores.org, 
	acme@kernel.org, paul.walmsley@sifive.com, linux-tegra@vger.kernel.org, 
	namhyung@kernel.org, andriy.shevchenko@linux.intel.com, jpoimboe@kernel.org, 
	dvyukov@google.com, jgross@suse.com, monstr@monstr.eu, 
	linux-mips@vger.kernel.org, palmer@dabbelt.com, anup@brainfault.org, 
	bp@alien8.de, johannes@sipsolutions.net, linuxppc-dev@lists.ozlabs.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: ulf.hansson@linaro.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linaro.org header.s=google header.b=OhrgekEJ;       spf=pass
 (google.com: domain of ulf.hansson@linaro.org designates 2607:f8b0:4864:20::530
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
> OMAP was the one and only user.

OMAP? :-)

>
> Signed-off-by: Peter Zijlstra (Intel) <peterz@infradead.org>

Reviewed-by: Ulf Hansson <ulf.hansson@linaro.org>

Kind regards
Uffe

> ---
>  drivers/clk/clk.c |    8 ++++----
>  1 file changed, 4 insertions(+), 4 deletions(-)
>
> --- a/drivers/clk/clk.c
> +++ b/drivers/clk/clk.c
> @@ -978,12 +978,12 @@ static void clk_core_disable(struct clk_
>         if (--core->enable_count > 0)
>                 return;
>
> -       trace_clk_disable_rcuidle(core);
> +       trace_clk_disable(core);
>
>         if (core->ops->disable)
>                 core->ops->disable(core->hw);
>
> -       trace_clk_disable_complete_rcuidle(core);
> +       trace_clk_disable_complete(core);
>
>         clk_core_disable(core->parent);
>  }
> @@ -1037,12 +1037,12 @@ static int clk_core_enable(struct clk_co
>                 if (ret)
>                         return ret;
>
> -               trace_clk_enable_rcuidle(core);
> +               trace_clk_enable(core);
>
>                 if (core->ops->enable)
>                         ret = core->ops->enable(core->hw);
>
> -               trace_clk_enable_complete_rcuidle(core);
> +               trace_clk_enable_complete(core);
>
>                 if (ret) {
>                         clk_core_disable(core->parent);
>
>
> _______________________________________________
> Virtualization mailing list
> Virtualization@lists.linux-foundation.org
> https://lists.linuxfoundation.org/mailman/listinfo/virtualization

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAPDyKFqoBJPgehVODY0DGuUcnqJE5rpZjRPfdMCzOP0%3DJrvKNw%40mail.gmail.com.
