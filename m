Return-Path: <kasan-dev+bncBCV5TUXXRUIBBDV64X3AKGQE5PMYLJY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x240.google.com (mail-oi1-x240.google.com [IPv6:2607:f8b0:4864:20::240])
	by mail.lfdr.de (Postfix) with ESMTPS id 1B1B81EEC71
	for <lists+kasan-dev@lfdr.de>; Thu,  4 Jun 2020 22:52:32 +0200 (CEST)
Received: by mail-oi1-x240.google.com with SMTP id l197sf3789179oih.11
        for <lists+kasan-dev@lfdr.de>; Thu, 04 Jun 2020 13:52:32 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1591303951; cv=pass;
        d=google.com; s=arc-20160816;
        b=BnDDCbXsOvM0R0PcQU7zf3pYagtIQtNbRJ1bdZZSmeUj5R0mXwpFYiV9/48BDHODkG
         P4DqHCOswgYhM7f02BWLoVLYZwmcCeEVdfEJ97yKpI81R1SLt0AlguTxgALCcNi+SGCP
         sCoK4vAyyGlzcdwBI9Y/R20J3GuB0lWdjNicltKXqH9QxOozIEsKV7dBNBwb2g8wykZ6
         cDzfuTyKab6eXgOFvExKuxFyP+ByK5/KOVa4m7LMNULBKKQWUtu3TqKqcYAk9jCuA9XU
         cWlBiMKpVoiHEyjY49/Qn+Rby36cHVw3FP0oCM73orMGoPr3kKCuiGVgqaqkyJtZ8H7Y
         2Lyg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=/7rR+SwMtvxDkWm8ej+wvPA2SGRnxocmItbVg2ey1XI=;
        b=U8zQKwnYvkar8fNl9jCDltNlEukN+Dg83lKRI0zTgbN3Ov9WVeDEZhYrkMYAd/LUHh
         MgO0R4gNb8Y749t/bT9+tWg1M8r0tv7UTIUsx25EOfRwDIrVhj4iW7ggx1spaJTAkg9H
         WqT1/tOkGUNqT2UWrXLSTSgObbuiBexwlj6jI0pYbxc0Ji27xQEAlUbPGmsFWK/1BXg3
         AjKbXKIL8oB8pCVi18nQ39MCZzrl50tH8xkxHSxJfnEpwAJfgwnAxfpBE0VK7ARmP89F
         asrpYfB5ZIL91GCHvXW/N05/PbiLuPaEY+3+is5bPfCfl4KJorOj98OAfeLm1VIivsrW
         ur3w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=bombadil.20170209 header.b=rxvICSWi;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2607:7c80:54:e::133 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=/7rR+SwMtvxDkWm8ej+wvPA2SGRnxocmItbVg2ey1XI=;
        b=OHzZBTMEqWsPI0oewZhrjg/KSBJNTDaCAJjsrIzqZ/UMljdLH9mkvhxqASJj85hm5w
         jJDfBb3FbSrx74CCIX5sQG5kj2SEaD9bInXML4NoTRzb2H1ns5Ys/9t+YPBoA6atUvbn
         e194tCLLwwqeq17VYfpAhbfUxpO9xX6vMzB1xNxGTVNEeJMXnBSo7OJ3uVOeeuR8y0zT
         Z3+J1uSHceA5OUH0w9xdU+rg5F0PKzlmoHiADfeaN8rZyMpuAiuZPNNK3W0t2Ihsqf6N
         gRt7OFItdcF+2pOwHPlljp6ZQmNuLWQFJfY3UCScO41/1o3gb+Tk8tDQ6exQ6HjcsdSm
         2o1w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=/7rR+SwMtvxDkWm8ej+wvPA2SGRnxocmItbVg2ey1XI=;
        b=cs6mtVPaZ+9pyyDxg13ldypGnoH1Y5nLjeyUe5gS+Obr/97SkQ0Weejn/aTNkUBCau
         Qhk2ghbZCR2YklQo0Gr+LE3gqkmlliB/6Xw3uMHw8DDiwC3N1oHxuU6jHop3rDO7DGeh
         A/17jGsUJ108cwerbMCz69GBL1+Xt2LWL7wZKgNB8wtoVuqAlz5tIIbRnK7EdfMnyqpL
         XQLxm9lX+CyYfRISDQdpzf/XR5UeaUgc95ApDv4ATi+lMHICG9TuSltI3uiExK9SK+jV
         gIKh3TWVf7dIPcXUXDxzR5gInIseNQpbAv69h5594SMUHGsWueWoL33qljh8yxFLzIni
         Egrg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533okqgth6lP/8dnWnGWIhpG/FbFOcTCIFl9s7GIbfNsDv0wVZMp
	brpxdWh5P1XvX/PUObhw4uM=
X-Google-Smtp-Source: ABdhPJwUWrJiaCm/PONE2sJGnWEaLS7Er0yP8O3jo6rs0246a18nMsdZY50wSaWtEXdy0HkILtgFbA==
X-Received: by 2002:a9d:7484:: with SMTP id t4mr5394578otk.110.1591303950829;
        Thu, 04 Jun 2020 13:52:30 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:4fc3:: with SMTP id d186ls1424034oib.1.gmail; Thu, 04
 Jun 2020 13:52:30 -0700 (PDT)
X-Received: by 2002:aca:f4ce:: with SMTP id s197mr4603128oih.115.1591303950456;
        Thu, 04 Jun 2020 13:52:30 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1591303950; cv=none;
        d=google.com; s=arc-20160816;
        b=FvAueYEaCISXoRE+zvDb1tKAhx3N6Saf3er6iTt1PT+p2R8kSYcwSzJ/+s49PYe+RF
         /yWbdT/aU6DMUgf+Q50pFqRnUgXdfF0DCXbeosLgT/2dCgODOfHoe+5S1S37lZ4O6ws4
         d1DxwNRIJxA7Cyr2vzm1QJfgHMiPlOMiLwRKpY8M6K1/TBIuSY2fu8BYmMFdDdBO2QXl
         GyMvAtBk0jpIEnexZai1WE1ZtcwQtEkJtFpImZy1hzJrvgSFS3gs+5vGtBoTNnffULVW
         +4vUT5hLITpnzp8FhyXZlR35pGxSISJD0myRcfE927iq7jaIjrHpvTZEfWYIBOxL8npx
         ox2Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=PiE7DNxO3pqAGslsM8EXoQp6h0xtdTMR2V3mK8r5hpk=;
        b=seP7aWZbYC3FxcpAk0cmtHA8tZn6/CkPo+q+aeMX4O3eot0tiZJbDrMh+H2NmM1fK6
         wR98cK68j5Lg6W6Ju6wyAZqndPk8kLxNmMYp7iUoGGEl0GdaLlvt+V3Yv+6737B3gzAa
         86/ibwjZFTPRP5T1GCUq/PD+anV26WTzI0FgSM9CU6VzjaFTjHog9GOGhz7yF8nVTVdD
         dwuqdDdLnzB++uVRwIGVdamjGFJE+RtbAUOFoQz5h0AD9DE/F8eQFTtrMhNwmYknQaXd
         BBUcKKjnnKSE4KfBsqmgC6Ur+lnSSC86G+F6Z/sTagqvgc8YxBVafpV8LV5G6aSRfulu
         RtFw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=bombadil.20170209 header.b=rxvICSWi;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2607:7c80:54:e::133 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from bombadil.infradead.org (bombadil.infradead.org. [2607:7c80:54:e::133])
        by gmr-mx.google.com with ESMTPS id a13si356362otl.0.2020.06.04.13.52.26
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 04 Jun 2020 13:52:26 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2607:7c80:54:e::133 as permitted sender) client-ip=2607:7c80:54:e::133;
Received: from j217100.upc-j.chello.nl ([24.132.217.100] helo=worktop.programming.kicks-ass.net)
	by bombadil.infradead.org with esmtpsa (Exim 4.92.3 #3 (Red Hat Linux))
	id 1jgwqb-0002DS-T9; Thu, 04 Jun 2020 20:52:22 +0000
Received: by worktop.programming.kicks-ass.net (Postfix, from userid 1000)
	id 65A5A9838B9; Thu,  4 Jun 2020 22:52:19 +0200 (CEST)
Date: Thu, 4 Jun 2020 22:52:19 +0200
From: Peter Zijlstra <peterz@infradead.org>
To: Marco Elver <elver@google.com>
Cc: Andrey Konovalov <andreyknvl@google.com>,
	Borislav Petkov <bp@alien8.de>,
	Thomas Gleixner <tglx@linutronix.de>,
	Ingo Molnar <mingo@kernel.org>,
	clang-built-linux <clang-built-linux@googlegroups.com>,
	"Paul E . McKenney" <paulmck@kernel.org>,
	Dmitry Vyukov <dvyukov@google.com>,
	Alexander Potapenko <glider@google.com>,
	kasan-dev <kasan-dev@googlegroups.com>,
	LKML <linux-kernel@vger.kernel.org>
Subject: Re: [PATCH -tip] kcov: Make runtime functions noinstr-compatible
Message-ID: <20200604205219.GZ2483@worktop.programming.kicks-ass.net>
References: <20200604095057.259452-1-elver@google.com>
 <20200604110918.GA2750@hirez.programming.kicks-ass.net>
 <CAAeHK+wRDk7LnpKShdUmXo54ij9T0sN9eG4BZXqbVovvbz5LTQ@mail.gmail.com>
 <CANpmjNML7hBNpYGL81M1-=rrYn5PAJPTxFc_Jn0DVhUgwJV8Hg@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNML7hBNpYGL81M1-=rrYn5PAJPTxFc_Jn0DVhUgwJV8Hg@mail.gmail.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=bombadil.20170209 header.b=rxvICSWi;
       spf=pass (google.com: best guess record for domain of
 peterz@infradead.org designates 2607:7c80:54:e::133 as permitted sender) smtp.mailfrom=peterz@infradead.org
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

On Thu, Jun 04, 2020 at 04:23:38PM +0200, Marco Elver wrote:
> Sadly no. 'noinstr' implies 'notrace', but also places the function in
> the .noinstr.text section for the purpose of objtool checking.

Not only the compile time checking, but also for purpose of runtime
exclusion for things like kprobes and hw-breakpoints.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200604205219.GZ2483%40worktop.programming.kicks-ass.net.
