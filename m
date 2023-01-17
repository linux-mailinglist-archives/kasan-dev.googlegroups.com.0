Return-Path: <kasan-dev+bncBDBK55H2UQKRBX6ETGPAMGQEZQLMSFQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x338.google.com (mail-ot1-x338.google.com [IPv6:2607:f8b0:4864:20::338])
	by mail.lfdr.de (Postfix) with ESMTPS id 10A1B66D8CA
	for <lists+kasan-dev@lfdr.de>; Tue, 17 Jan 2023 09:54:57 +0100 (CET)
Received: by mail-ot1-x338.google.com with SMTP id y14-20020a0568301d8e00b00670641b451bsf16066664oti.15
        for <lists+kasan-dev@lfdr.de>; Tue, 17 Jan 2023 00:54:57 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1673945695; cv=pass;
        d=google.com; s=arc-20160816;
        b=Bs8VHhJl6r7zBbdEwQwRUBL9OuiILvUwKQnl74myZaCyB2dS/7upHNLuh0YsPnqcPM
         bfuj6X+lJxL/5LWVoSJxNjAYZl4Popd+MEhbstdJy7Jh2ajxKAndzFxiFxBhAdXFAXKu
         y0aAZBzyey+dUGxQzZKde0l2S7sI7b8IstZYxwVO6YHwtEk3fzpMSrmrl/L7WHWaUBbD
         mpD4QNyc7xUd9e2fhCv+ql9IAlIMPXka6XOxIaPGJkCC1CplFMdO6PKItuUIvqnFI+UC
         eS0/rx8jKZpg+aOBdvBlsN+aMCGKog3j7DFB9QwOgeQqtbOo8D5z0zongJZFHfZ2xOB5
         e7mg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=boC4P0IZPta1b3S0sITeZ050tR8zLeJHlXlHRAAiHwk=;
        b=cdLES0tmQc5+iyyYXfyV5czfT1fbrlSTQnrcrbpfIIRTNiOTzKWVldIJO12onA56NL
         ysYUnVhehYTmfuKYXkCA/P4l56QTAfbDgIlYeM44YmxhwK4I+d2JrWFLiFFmBiy3qr1J
         U6NDeOVF+bzDY5tZJAxd5Oh7IOjUXzYtAdvk6tZ/wzXIyiiHOFat3tFJWoKrCb4JtE8h
         r68rqWXJVFzZJE5LoCKP05C2zO3XsXZmpZ8TkYqxZDRnUDR3qaIvOHI9IxNVFWTUX4ub
         o5lTl91sBkVTHa0w2pOPCjVA4y5L3TCzyh9Yxo1zlS5zPNoq79qMv5g9xpu78JVqzXiE
         Cshg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=Ke5GdVNv;
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=boC4P0IZPta1b3S0sITeZ050tR8zLeJHlXlHRAAiHwk=;
        b=SS6FQ7FZ7zo3/k7+sSuWmQ/zfbFoB4qqtjPtpQsx5LegbWa54jVdPRI1PIEr+0p6/t
         6bhUF/w8cwcsplI8bMBSnV+TDOatrh3pPS1t8S6c4Z+rxwtbTlbR4tPJQujeCyrB1jLk
         mb7Zxu5n41maA38J5/kPwfLR8BXDecxMQXW/Bb3XGNt3x4OZQTKB9jlfR7AGoYEVx/rw
         CQrHWmGdWGMafNGNS69EwDg9dElwKXouXcLvnKmpb5VAkzShxcqq2SyrMohIpYsOOPnr
         03wO+D3nJC2Y05/Iq2QxzsUOfUH/gcS19b21LmeuE3ZXG6OGIN7eXI3jNoJ3s9k3wpSf
         VRqA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=boC4P0IZPta1b3S0sITeZ050tR8zLeJHlXlHRAAiHwk=;
        b=QZmu0m95GqABlbGM6gFKykAPDqoFUk7HI/WneMQy2FVOzZ3/32NV0R5uPaoxTzyoDl
         aACIUasqKLxeParvDobb0PW8jf0mwaYU5ptFkDPDNfZOmILnGXSouUk0dD9/mTPb9yWD
         Nf9z7n/tYWpKw0KqP+D4xXWWbB+VtJtRsYXvWzx4CzoA9VeMnAe40qfe8hDOPayxZNOM
         WKdDm8y6BfiR/IieMXr2aHpht0IZ3me0br/mY9VnCsYqEkrOVD2QODq2p5L3Lv7QPtl3
         ApzVkTPWejvyOWz1HaJ+gUzBK+cPRow5ppS7XgMiyGcuiP1SsTOE2LsNF/bXdJzOhDUC
         IW6Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2kq389zrgexCOUPa2DIEkBieHoiuBS3xBuL+b7+G2G/fURsvNurs
	E1ZE2vGXcVniBQQxgMqkCEk=
X-Google-Smtp-Source: AMrXdXsS1rnnZwXo6k66MiFr9acDyWUlS4W1l8RYUpkpYjOvPLpMA52TBHDm9e4TnTuu0KPjSUnKMQ==
X-Received: by 2002:a05:6871:a6a7:b0:142:82cd:8194 with SMTP id wh39-20020a056871a6a700b0014282cd8194mr199982oab.286.1673945695465;
        Tue, 17 Jan 2023 00:54:55 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:648c:b0:684:ccc3:155d with SMTP id
 ck12-20020a056830648c00b00684ccc3155dls2513835otb.2.-pod-prod-gmail; Tue, 17
 Jan 2023 00:54:55 -0800 (PST)
X-Received: by 2002:a9d:704f:0:b0:66e:378c:e39c with SMTP id x15-20020a9d704f000000b0066e378ce39cmr1072772otj.0.1673945694956;
        Tue, 17 Jan 2023 00:54:54 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1673945694; cv=none;
        d=google.com; s=arc-20160816;
        b=Ns7j1ObDF+8WTje5BhugSf3p66pV+GRi/zWyr/pxt64XsYh8Xe4U6tvDkjQSw20evX
         MWGenM4slQgvNEBLytcRBDoDJTCNan8y7Gtpef0Ciy9FB2B2QZh1xB3q5EtOMzSCy/Du
         HgXdvoUrdzkDkhtYC0adp3CvoMinWWQJ12u67s0LmE2EiEXhq+LKPn+duRs8kTgJFlE7
         pM48Y2kR7NtOehrsb5DvsWFfI2rwznZO8qm9k1cEh1lQCu8CYPaEcva7AC7TE6KUEhvo
         +h/xfyE5H6t9uV/NPVPGzTimdTn0tGV0PbORNOo8J3tdrcgQJjP9Xhe56qmnoi3JUIRw
         AYhg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=82O7MPpmKDKH/y6naoktZs3WQBLC/PHyEl3Wjqd7/dM=;
        b=aXfIxTWEy1gyaXGmN0ll+Pdr+eC/NwGeFlZ6aKuowePZ0oudHEvoJJm3FmgM0DbYFi
         w+fR8/Ry7IxgH6SpQ6JUMKVPuaS0KucY0JfNYiyBZRXeJndITfYSukhU0CsrOquWFnRn
         I2rJJAX5qe7Flv5gdMdrxSAnzP0prn7BaLrZjPo4yixK0ditOtQFdcXpDnEphoHLXzl4
         AiAQTryLl4jbD3tK0d9tJ2xzOC0BVzNolanPl646f6Gy4MVPqVjK+b8Gy/ikWJOQHYZ3
         /TRZ40/Yb47hfN5OisJ7ueaWhOu6C7jhCafNVHm1Pc181Fu/5DKs9M6i3B9Fl1ruT7ei
         VmTw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=Ke5GdVNv;
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
Received: from casper.infradead.org (casper.infradead.org. [2001:8b0:10b:1236::1])
        by gmr-mx.google.com with ESMTPS id cg15-20020a056830630f00b0066fe878940fsi2525264otb.5.2023.01.17.00.54.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 17 Jan 2023 00:54:54 -0800 (PST)
Received-SPF: none (google.com: infradead.org does not designate permitted sender hosts) client-ip=2001:8b0:10b:1236::1;
Received: from j130084.upc-j.chello.nl ([24.132.130.84] helo=noisy.programming.kicks-ass.net)
	by casper.infradead.org with esmtpsa (Exim 4.94.2 #2 (Red Hat Linux))
	id 1pHhjP-009Wex-5i; Tue, 17 Jan 2023 08:54:11 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id 781E9300193;
	Tue, 17 Jan 2023 09:53:52 +0100 (CET)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 1000)
	id 46751201ABB3C; Tue, 17 Jan 2023 09:53:52 +0100 (CET)
Date: Tue, 17 Jan 2023 09:53:52 +0100
From: Peter Zijlstra <peterz@infradead.org>
To: Masami Hiramatsu <mhiramat@kernel.org>
Cc: richard.henderson@linaro.org, ink@jurassic.park.msu.ru,
	mattst88@gmail.com, vgupta@kernel.org, linux@armlinux.org.uk,
	nsekhar@ti.com, brgl@bgdev.pl, ulli.kroll@googlemail.com,
	linus.walleij@linaro.org, shawnguo@kernel.org,
	Sascha Hauer <s.hauer@pengutronix.de>, kernel@pengutronix.de,
	festevam@gmail.com, linux-imx@nxp.com, tony@atomide.com,
	khilman@kernel.org, krzysztof.kozlowski@linaro.org,
	alim.akhtar@samsung.com, catalin.marinas@arm.com, will@kernel.org,
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
	sudeep.holla@arm.com, agross@kernel.org, andersson@kernel.org,
	konrad.dybcio@linaro.org, anup@brainfault.org,
	thierry.reding@gmail.com, jonathanh@nvidia.com,
	jacob.jun.pan@linux.intel.com, atishp@atishpatra.org,
	Arnd Bergmann <arnd@arndb.de>, yury.norov@gmail.com,
	andriy.shevchenko@linux.intel.com, linux@rasmusvillemoes.dk,
	dennis@kernel.org, tj@kernel.org, cl@linux.com, rostedt@goodmis.org,
	frederic@kernel.org, paulmck@kernel.org, pmladek@suse.com,
	senozhatsky@chromium.org, john.ogness@linutronix.de,
	juri.lelli@redhat.com, vincent.guittot@linaro.org,
	dietmar.eggemann@arm.com, bsegall@google.com, mgorman@suse.de,
	bristot@redhat.com, vschneid@redhat.com, ryabinin.a.a@gmail.com,
	glider@google.com, andreyknvl@gmail.com, dvyukov@google.com,
	vincenzo.frascino@arm.com,
	Andrew Morton <akpm@linux-foundation.org>, jpoimboe@kernel.org,
	linux-alpha@vger.kernel.org, linux-kernel@vger.kernel.org,
	linux-snps-arc@lists.infradead.org, linux-omap@vger.kernel.org,
	linux-samsung-soc@vger.kernel.org, linux-csky@vger.kernel.org,
	linux-hexagon@vger.kernel.org, linux-ia64@vger.kernel.org,
	loongarch@lists.linux.dev, linux-m68k@lists.linux-m68k.org,
	linux-mips@vger.kernel.org, openrisc@lists.librecores.org,
	linux-parisc@vger.kernel.org, linuxppc-dev@lists.ozlabs.org,
	linux-riscv@lists.infradead.org, linux-s390@vger.kernel.org,
	linux-sh@vger.kernel.org, sparclinux@vger.kernel.org,
	linux-um@lists.infradead.org, linux-perf-users@vger.kernel.org,
	virtualization@lists.linux-foundation.org,
	linux-xtensa@linux-xtensa.org, linux-acpi@vger.kernel.org,
	linux-pm@vger.kernel.org, linux-clk@vger.kernel.org,
	linux-arm-msm@vger.kernel.org, linux-tegra@vger.kernel.org,
	linux-arch@vger.kernel.org, linux-mm@kvack.org,
	linux-trace-kernel@vger.kernel.org, kasan-dev@googlegroups.com
Subject: Re: [PATCH v3 35/51] trace,hardirq: No moar _rcuidle() tracing
Message-ID: <Y8ZiIMHyXX/yW1EI@hirez.programming.kicks-ass.net>
References: <20230112194314.845371875@infradead.org>
 <20230112195541.477416709@infradead.org>
 <20230117132446.02ec12e4c10718de27790900@kernel.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20230117132446.02ec12e4c10718de27790900@kernel.org>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=casper.20170209 header.b=Ke5GdVNv;
       spf=none (google.com: infradead.org does not designate permitted sender
 hosts) smtp.mailfrom=peterz@infradead.org
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

On Tue, Jan 17, 2023 at 01:24:46PM +0900, Masami Hiramatsu wrote:
> Hi Peter,
> 
> On Thu, 12 Jan 2023 20:43:49 +0100
> Peter Zijlstra <peterz@infradead.org> wrote:
> 
> > Robot reported that trace_hardirqs_{on,off}() tickle the forbidden
> > _rcuidle() tracepoint through local_irq_{en,dis}able().
> > 
> > For 'sane' configs, these calls will only happen with RCU enabled and
> > as such can use the regular tracepoint. This also means it's possible
> > to trace them from NMI context again.
> > 
> > Signed-off-by: Peter Zijlstra (Intel) <peterz@infradead.org>
> 
> The code looks good to me. I just have a question about comment.
> 
> > ---
> >  kernel/trace/trace_preemptirq.c |   21 +++++++++++++--------
> >  1 file changed, 13 insertions(+), 8 deletions(-)
> > 
> > --- a/kernel/trace/trace_preemptirq.c
> > +++ b/kernel/trace/trace_preemptirq.c
> > @@ -20,6 +20,15 @@
> >  static DEFINE_PER_CPU(int, tracing_irq_cpu);
> >  
> >  /*
> > + * ...
> 
> Is this intended? Wouldn't you leave any comment here?

I indeed forgot to write the comment before posting, my bad :/ Ingo fixed
it up when he applied.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Y8ZiIMHyXX/yW1EI%40hirez.programming.kicks-ass.net.
