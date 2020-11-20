Return-Path: <kasan-dev+bncBCU73AEHRQBBBKVR4D6QKGQETVZ4U2A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43c.google.com (mail-pf1-x43c.google.com [IPv6:2607:f8b0:4864:20::43c])
	by mail.lfdr.de (Postfix) with ESMTPS id D2CE02BB53E
	for <lists+kasan-dev@lfdr.de>; Fri, 20 Nov 2020 20:27:39 +0100 (CET)
Received: by mail-pf1-x43c.google.com with SMTP id n21sf7725329pfu.9
        for <lists+kasan-dev@lfdr.de>; Fri, 20 Nov 2020 11:27:39 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605900458; cv=pass;
        d=google.com; s=arc-20160816;
        b=mlOoQ14VT7qzZdjvxNmM+tVopCbMe+SNPhBMWHrWZQGCbL0FmaLxcSV624D3asPBIf
         AEy+TFE7vFTNcRBbGkxk001ivPBL8/8+mEghtT2J3O6VAf0iQiflwIj2m2zPYGWoyQZQ
         1fUT81VE/aSbYiSxqBQA5zH7mNFJLQbBe3OtWqUsv/yFUw51OtkWV+lV/s/Mq6rWtvb+
         vEjNdUcSE5D4X9XOTeAtdraiu/d5SO9tmOADqGfqQfJCdZS/CJFOLbZyqxhrAIWSdsCS
         BRnu3f4KP59IASQi2wC36oANGFIKG3gvtZWQzIisrBoTS4cSZKwhZ/7Fw9DW723Tso0w
         zy/g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=hCP/3d5SBBMOwo6UHqSgWgZljTJ4eeR15ff79KrKz/A=;
        b=nWZBXHpfWnP4ViDhle+Xm9BOpjKZdgNyyYG4xPuIrUcl/B3IeoETEsRhvRsfrOOXcT
         0f4sreVaUHjSQTm+3CPPVaQ9T+tWQL0qCttkwnozIooCW3JyyLKO397Ba+QW/H9axRh3
         ylt/PaWeFpbEh2OGDdOBE2PcmHZmyMWaRV88NOi88RqzdmYsyc8tMxUI6vzjw5lstd5r
         2DlX1xjZ3n4Vg1dIBA23B68eS8b2bUkGhW+V2iKZBdbcI1/U44kpopYJm9J5RrnWdBI1
         aPiRrE4Sr01sX1TeW2aY+380tawPS+80qSsTpeapulZ+xPFFIONkCl4ujmSlyWEhY9WA
         OjBQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=g+oz=e2=goodmis.org=rostedt@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=G+oZ=E2=goodmis.org=rostedt@kernel.org"
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=hCP/3d5SBBMOwo6UHqSgWgZljTJ4eeR15ff79KrKz/A=;
        b=evDjHr+2Q1IeimTV1auE4v3Zm0rv0g9pmSxv1S1/g4qllNXyrvtX0rykn/wkCJ6SZ1
         d3B4Klzm+rMw1Yxf3uqUBo1DWcRH4AMxGfHrdWsUQweyYPMKym+K/VQ8ev5vC4BVJEP7
         ygk9rhtIYJ/xOqqcbZE/KRr5YUMJEk0UN1LP9DbBo8lsYNNdbAmiB4LSxFn085b+lAxe
         siy/d2bMRXJAvkNYNTqDHUWE1hpTW7ZV0qCectnUTfMlFPfimZK2cONtDQY0/y4gc95l
         +XyQAb8QAH++9LnM1gO53gj6cOtaMtPKLxaaGK6DPra8mXkkaFrQN2TqX3HhSuW5HYK3
         7lZQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=hCP/3d5SBBMOwo6UHqSgWgZljTJ4eeR15ff79KrKz/A=;
        b=Ng03BrXE6rNlHsLQO7tsq1X6wBvxbKXQ3/pKXaL3ax9W0+gETEY6PnQExFTW/hNBJn
         oVdvMmZ6O3MJX9Y5arbYVoyaCNA57Qy6Ixad/aJiHZ0CE2c9khh6bBPeXFPH67z+XcZX
         BU3cwOzQzbpibiW9sGYq7MwI1PU9J5r+VowfbBehK1GTASsncgY0lYqbT92FsDyX7dLj
         Lml36lgYDduoht+xHW8aJyZOLesdXWENMdiaBqxjW1RhTLEvV7FbWHqmicp3PpYwi0qd
         z145yPMy5+XfsALXNSyifXCPeHq9SW3U1RMbSeoMps8DqUT0ao6IXfR4dWNOYz1QhdKl
         5+ew==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530Xqly8RdhyZ3AmlgIYPgq1xXxyaJRu4mye41sc62lmPTDdRaae
	MHfS0Q8Q/s886M+uUJYwqgY=
X-Google-Smtp-Source: ABdhPJyn5m4LDw1J/QFZ+0tfTsJ9vLzLItLnUJiDU0Ka/IWDmIlJLQp1Rd6eQoGNvWQmRQ7r0Mr4hQ==
X-Received: by 2002:a17:902:6b08:b029:d6:c471:8b5b with SMTP id o8-20020a1709026b08b02900d6c4718b5bmr15148365plk.78.1605900458368;
        Fri, 20 Nov 2020 11:27:38 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:7745:: with SMTP id s66ls2788722pfc.0.gmail; Fri, 20 Nov
 2020 11:27:37 -0800 (PST)
X-Received: by 2002:aa7:9198:0:b029:18b:3835:3796 with SMTP id x24-20020aa791980000b029018b38353796mr16369219pfa.9.1605900457825;
        Fri, 20 Nov 2020 11:27:37 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605900457; cv=none;
        d=google.com; s=arc-20160816;
        b=AvvREW6wVH8RAhkYBSCyKJsJgMsz62Hf2IbwCn6LHnswkexL+rFs0xukQRtLILinLb
         q+EJnzqcb1uKWXBwuwWf7H4S8H6rh62ZfrOH9Yxf85Fr6TrXMrbkfO/DOKxzN5Ljxdtk
         OXj8xCpA47UU6rqkQujse5OdkOCyVuQEGdCzKZ8R/p1/HcbJBtnMq5EsXDQzKvygA3Tb
         vI+P0I0IhYBuXxy2O2bvS+fI3PQGdWSULIJf1OT81FwRZBkDydoMyygZ1C3DaC3PyYUE
         2TDdXIPjAB8SGWQOrUyOIt2RpIUBOnIy2lObNAR01qPQdyqEuNSsSVqa4pFD8Mgs6kxq
         +95g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date;
        bh=XK9pfOqnFLJgtG/Boe+RTmh05iItoQRR5Fgw2EiMBZw=;
        b=OhuN5Akn/QMU0hxRwWtC15rX9446DQy0gPOuw/3iElXkR5Vq+9xLlOHTQY5x0QsXlH
         MmvbCDWWIeZaj0Vktr5IBNp1mULNXhdMuw0i8wds0TlebeKabhW9Od/SsLUQncfeENwU
         3/v/THZuEebC2M7uMzdQ3S9JICHWCSh1PMX/jbGYzTo8b8GnM+KcxlNnNg+MOHumSPUk
         ADOE13pJjLttVkfDmGrQw1dHDLjomC3GX5q/SgJkzszo8l+Ql+DPl9dfLOFdwnz6+9M7
         6aWBrMYewWIoC3oE7eHaf0pBZpQ+GmZTcGKhNXkRFPp20rWHn05AIxQN51HgLWp9BsSk
         cvOg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=g+oz=e2=goodmis.org=rostedt@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=G+oZ=E2=goodmis.org=rostedt@kernel.org"
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id i22si888946pjx.1.2020.11.20.11.27.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 20 Nov 2020 11:27:37 -0800 (PST)
Received-SPF: pass (google.com: domain of srs0=g+oz=e2=goodmis.org=rostedt@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from gandalf.local.home (cpe-66-24-58-225.stny.res.rr.com [66.24.58.225])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id D2C75221F1;
	Fri, 20 Nov 2020 19:27:35 +0000 (UTC)
Date: Fri, 20 Nov 2020 14:27:34 -0500
From: Steven Rostedt <rostedt@goodmis.org>
To: Marco Elver <elver@google.com>
Cc: "Paul E. McKenney" <paulmck@kernel.org>, Anders Roxell
 <anders.roxell@linaro.org>, Andrew Morton <akpm@linux-foundation.org>,
 Alexander Potapenko <glider@google.com>, Dmitry Vyukov
 <dvyukov@google.com>, Jann Horn <jannh@google.com>, Mark Rutland
 <mark.rutland@arm.com>, Linux Kernel Mailing List
 <linux-kernel@vger.kernel.org>, Linux-MM <linux-mm@kvack.org>, kasan-dev
 <kasan-dev@googlegroups.com>, rcu@vger.kernel.org, Peter Zijlstra
 <peterz@infradead.org>, Tejun Heo <tj@kernel.org>, Lai Jiangshan
 <jiangshanlai@gmail.com>
Subject: Re: [PATCH] kfence: Avoid stalling work queue task without
 allocations
Message-ID: <20201120142734.75af5cd6@gandalf.local.home>
In-Reply-To: <20201119125357.GA2084963@elver.google.com>
References: <20201111202153.GT517454@elver.google.com>
	<20201112001129.GD3249@paulmck-ThinkPad-P72>
	<CANpmjNNyZs6NrHPmomC4=9MPEvCy1bFA5R2pRsMhG7=c3LhL_Q@mail.gmail.com>
	<20201112161439.GA2989297@elver.google.com>
	<20201112175406.GF3249@paulmck-ThinkPad-P72>
	<20201113175754.GA6273@paulmck-ThinkPad-P72>
	<20201117105236.GA1964407@elver.google.com>
	<20201117182915.GM1437@paulmck-ThinkPad-P72>
	<20201118225621.GA1770130@elver.google.com>
	<20201118233841.GS1437@paulmck-ThinkPad-P72>
	<20201119125357.GA2084963@elver.google.com>
X-Mailer: Claws Mail 3.17.3 (GTK+ 2.24.32; x86_64-pc-linux-gnu)
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: rostedt@goodmis.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of srs0=g+oz=e2=goodmis.org=rostedt@kernel.org designates
 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=G+oZ=E2=goodmis.org=rostedt@kernel.org"
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

On Thu, 19 Nov 2020 13:53:57 +0100
Marco Elver <elver@google.com> wrote:

> Running tests again, along with the function tracer
> Running tests on all trace events:
> Testing all events: 
> BUG: workqueue lockup - pool cpus=0 node=0 flags=0x0 nice=0 stuck for 12s!

The below patch might be noisy, but can you add it to the kernel that
crashes and see if a particular event causes the issue?

[ note I didn't even compile test. I hope it works ;) ]

Perhaps run it a couple of times to see if it crashes on the same set of
events each time.

-- Steve

diff --git a/kernel/trace/trace_events.c b/kernel/trace/trace_events.c
index 98d194d8460e..eb1dd9cf77a9 100644
--- a/kernel/trace/trace_events.c
+++ b/kernel/trace/trace_events.c
@@ -773,6 +773,8 @@ static void remove_event_file_dir(struct trace_event_file *file)
 	kmem_cache_free(file_cachep, file);
 }
 
+static int spam;
+
 /*
  * __ftrace_set_clr_event(NULL, NULL, NULL, set) will set/unset all events.
  */
@@ -808,6 +810,8 @@ __ftrace_set_clr_event_nolock(struct trace_array *tr, const char *match,
 		if (event && strcmp(event, name) != 0)
 			continue;
 
+		if (spam)
+			printk("%s event %s\n", set ? "enabling" : "disabling", name);
 		ret = ftrace_event_enable_disable(file, set);
 
 		/*
@@ -3647,6 +3651,7 @@ static __init void event_trace_self_tests(void)
 	pr_info("Running tests on all trace events:\n");
 	pr_info("Testing all events: ");
 
+	spam = 1;
 	ret = __ftrace_set_clr_event(tr, NULL, NULL, NULL, 1);
 	if (WARN_ON_ONCE(ret)) {
 		pr_warn("error enabling all events\n");
@@ -3661,6 +3666,7 @@ static __init void event_trace_self_tests(void)
 		pr_warn("error disabling all events\n");
 		return;
 	}
+	spam = 0;
 
 	pr_cont("OK\n");
 }

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201120142734.75af5cd6%40gandalf.local.home.
