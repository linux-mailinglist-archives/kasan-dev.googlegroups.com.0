Return-Path: <kasan-dev+bncBCV5TUXXRUIBB7XZ52AAMGQEUPAJZUA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103d.google.com (mail-pj1-x103d.google.com [IPv6:2607:f8b0:4864:20::103d])
	by mail.lfdr.de (Postfix) with ESMTPS id A2E3C30EF8E
	for <lists+kasan-dev@lfdr.de>; Thu,  4 Feb 2021 10:23:11 +0100 (CET)
Received: by mail-pj1-x103d.google.com with SMTP id ob3sf1605117pjb.0
        for <lists+kasan-dev@lfdr.de>; Thu, 04 Feb 2021 01:23:11 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1612430590; cv=pass;
        d=google.com; s=arc-20160816;
        b=f01AcIz4mFqlxV2+RvGrsIHKCAdatjHc9ynyL3CIH5KYU0btjDc4EOtBSixjalqAUI
         IyQMeyW/JXAPYmn50QbdDLQn7hs5vJVoI1srdsQAoF8Zj0Sxw6UplOlLqi/Bf3sKfhtA
         jKOoTJ79D8GfvqzU/vQGVUnQ0SIpCVv6tuxHzxFphX3b5EtIO65VQob0ltclWrTg9BsV
         z3Ymm7w6kjtXM+oAII9tub+H5WMLIEHMHk1/APAjAFnqbsdGhCl0b8E9rd3YiixZNJgr
         J/FimWVMNYawBsI6NQEqs1MkYwMT+ELXmGSXksNmZMxboFpC8ZjwAhwcyt9aP7s6efV/
         q6mg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=7oJ7+HeyEU0eKKsVwBn3kax+34Tl9fHK0vboV6o98qg=;
        b=n1ZopLeqK+kY219Pfm9apYGh1NLLF0+EcoJ3Gq+8d47s1clZ11PkIcufWIXanhnW/F
         xR6iac42q0efy02GyG71fYNCcnDugxunf2GNtYPoPbpeeGEYweu4H4JMJnYlluaBgbjf
         ppeIQeb5s6CWforW8KEyHKbVC/viI2MPvsulad2R3z/tDyUUzPj7WmxjSdj5a+S03O+B
         DoZI4kc1+9RLk652XFyFS2VwPZnME5QH8ybDTrnrxdjWvqwHalgvGNATgTI8vyGo9O4B
         hU7cBWPl0zHE/dbW7r3uUmwrWezOGwM9GMyvT4V2GP343TgOtqwZMsGlYWBCqEBTzObw
         L9cw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=merlin.20170209 header.b=r0BCCyAZ;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=7oJ7+HeyEU0eKKsVwBn3kax+34Tl9fHK0vboV6o98qg=;
        b=qVcQP5DNnGSY/TydVDb05RsS2WP0ZzVI0YGurR/drfTe1i5m35OEgp8xKw0abPe7UY
         LCvLO77a1iUmJ82079LaVs6qcGT5tnLgi4VoZelRcieLIVdaNCCUDPDA9MTrqJSMqOFi
         QKXMwFFdhwFKoIiErS830AbgFuMtuc15KDrnAHkLYtTWZEIsYtqf8GkADt2njAnUMc8B
         UTI7IPVcnT3SXGqqUmTv6lYzn797WMhM9i0xBw4oXA9ERE3aWybfvR87ycwsMpmO+SmU
         X1IApGNOINcQhiGcs24aF/bytufnWgAChbLq9Cf21TSd+RLPJJM2r605SBqxWs2aZhdF
         DAeA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=7oJ7+HeyEU0eKKsVwBn3kax+34Tl9fHK0vboV6o98qg=;
        b=OteBu6iNpJ4Egg7NbWVSp3lsvxWUtf4f4/LMvBQHHjiCE3Z8s5EJxqMDeguCpQWhkX
         8rCFy3D7SrZNYXmBF3fEpTtwIdOS0LE5oDhHb6M4HSfwW9Hrke7caHnxM3qEHArq1XZM
         HQM1cy4sxjc5DlsmqQyEZ5FEwdRxUyaKr0XSGmFfTgIJCQiHIHnr5iOCY7hORJ8/ImI5
         7LT1//Atvaton0BZigKijk7NfNbQEx23Xysugy8uAszQGH1sp/aWndXpEcr07N8IY8Xb
         z1c8cd0gkHFBqP9baFG256U1MWtsdqzOGT5m5FGWi0L/I00Xaw/tUaaEYo5Xvek5tD0v
         pwrA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532YD1T19Ziexox/xw03CshxJ6yb4O2W80hRjmUsUbgt2QfYa1jy
	AHiC1znuWK2CWaBMm89M5ko=
X-Google-Smtp-Source: ABdhPJy1BlWMeGk8L5SJRAg3l9NPEhX9/WvA9ka5SxqIDvn66UaPJR7O3rDmb74/fNYS/JB9kWWX3A==
X-Received: by 2002:a17:902:9690:b029:e1:5a03:87b5 with SMTP id n16-20020a1709029690b02900e15a0387b5mr7204364plp.39.1612430590397;
        Thu, 04 Feb 2021 01:23:10 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:2dcd:: with SMTP id q13ls2628278pjm.0.gmail; Thu, 04
 Feb 2021 01:23:09 -0800 (PST)
X-Received: by 2002:a17:90a:5513:: with SMTP id b19mr7585437pji.99.1612430589793;
        Thu, 04 Feb 2021 01:23:09 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1612430589; cv=none;
        d=google.com; s=arc-20160816;
        b=G2F6fw4RiwuleiqSfqSEtnaOG8kKvDcPUSKf3tKZmiTdIt2tQ6ftGMbbSiXhpTdnpj
         RRHTv+4T36x3IzIguzGP9JOLq3dH7Www7+Dd0JKoHPwgh2DzII+q96+/1J585h1vg1rf
         mMlTQx8EqUtz3Ho7uCY0A8XE+HB41EgqzSNKyr4jrIn2APTxH8q7ZfdNa1MC6QTaQxBH
         5GLLFiqufFZATWyfB0CBpOkBKUuGBR6UqePNaDqlhBbN30bHZw7YzbwT3WfPxemDKPr0
         XXKNrqyKIhe/oNZvRQ2vdkewn/E+hMf5EzdQqiedf4zOfZ110WugW66VXOz7cbbswCfu
         GHZQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=CPyUnilJQ2QKupjj2xtE65PWmSMXgunXFpzexlPe1UE=;
        b=wx8XXITz8MT4CVWo0L6akxVSOZtKbzMrv/LuB7Twz3gP0Kvs2/Eb6tAbbpXLMxNfou
         Oe7U4VgQvBX3HAhlNqwGuUsH+N33c7qjHquPZF0EC09tX9mIwsmZRtt4N/GzWWu2rI71
         YxTJv/p2QhfeiuV5oBH291uZ1bYDjmjU+Ou857oXcZc/qHnkpt4B83l69akEthANAscY
         5Z1+BYOG/34V9ZmrRwm9ANMpmuNM/GIldg95vvhLqgeZut6yvCgzYyHjb557mZcD0Utg
         Vv8YshEHvAt4RGSxcGeP8hxfysiVnVVrl+xcxUE8eckPif3uXaJQSrAdDDkzMclls/J/
         B04Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=merlin.20170209 header.b=r0BCCyAZ;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from merlin.infradead.org (merlin.infradead.org. [2001:8b0:10b:1231::1])
        by gmr-mx.google.com with ESMTPS id q10si23857pjp.0.2021.02.04.01.23.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 04 Feb 2021 01:23:09 -0800 (PST)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) client-ip=2001:8b0:10b:1231::1;
Received: from j217100.upc-j.chello.nl ([24.132.217.100] helo=noisy.programming.kicks-ass.net)
	by merlin.infradead.org with esmtpsa (Exim 4.92.3 #3 (Red Hat Linux))
	id 1l7aqj-0008Nd-U9; Thu, 04 Feb 2021 09:22:54 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id 385F2301A32;
	Thu,  4 Feb 2021 10:22:48 +0100 (CET)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 1000)
	id 15BDD213D2E27; Thu,  4 Feb 2021 10:22:48 +0100 (CET)
Date: Thu, 4 Feb 2021 10:22:48 +0100
From: Peter Zijlstra <peterz@infradead.org>
To: Ivan Babrou <ivan@cloudflare.com>
Cc: kernel-team <kernel-team@cloudflare.com>,
	Ignat Korchagin <ignat@cloudflare.com>,
	Hailong liu <liu.hailong6@zte.com.cn>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Thomas Gleixner <tglx@linutronix.de>,
	Ingo Molnar <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>,
	x86@kernel.org, "H. Peter Anvin" <hpa@zytor.com>,
	Josh Poimboeuf <jpoimboe@redhat.com>,
	Miroslav Benes <mbenes@suse.cz>,
	Julien Thierry <jthierry@redhat.com>,
	Jiri Slaby <jirislaby@kernel.org>, kasan-dev@googlegroups.com,
	linux-mm@kvack.org, linux-kernel <linux-kernel@vger.kernel.org>,
	Alasdair Kergon <agk@redhat.com>, Mike Snitzer <snitzer@redhat.com>,
	dm-devel@redhat.com,
	"Steven Rostedt (VMware)" <rostedt@goodmis.org>,
	Alexei Starovoitov <ast@kernel.org>,
	Daniel Borkmann <daniel@iogearbox.net>,
	Martin KaFai Lau <kafai@fb.com>, Song Liu <songliubraving@fb.com>,
	Yonghong Song <yhs@fb.com>, Andrii Nakryiko <andriin@fb.com>,
	John Fastabend <john.fastabend@gmail.com>,
	KP Singh <kpsingh@chromium.org>, Robert Richter <rric@kernel.org>,
	"Joel Fernandes (Google)" <joel@joelfernandes.org>,
	Mathieu Desnoyers <mathieu.desnoyers@efficios.com>,
	Linux Kernel Network Developers <netdev@vger.kernel.org>,
	bpf@vger.kernel.org, Alexey Kardashevskiy <aik@ozlabs.ru>
Subject: Re: BUG: KASAN: stack-out-of-bounds in
 unwind_next_frame+0x1df5/0x2650
Message-ID: <YBu86G1ckCckRyim@hirez.programming.kicks-ass.net>
References: <CABWYdi3HjduhY-nQXzy2ezGbiMB1Vk9cnhW2pMypUa+P1OjtzQ@mail.gmail.com>
 <CABWYdi27baYc3ShHcZExmmXVmxOQXo9sGO+iFhfZLq78k8iaAg@mail.gmail.com>
 <YBrTaVVfWu2R0Hgw@hirez.programming.kicks-ass.net>
 <CABWYdi2ephz57BA8bns3reMGjvs5m0hYp82+jBLZ6KD3Ba6zdQ@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CABWYdi2ephz57BA8bns3reMGjvs5m0hYp82+jBLZ6KD3Ba6zdQ@mail.gmail.com>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=merlin.20170209 header.b=r0BCCyAZ;
       spf=pass (google.com: best guess record for domain of
 peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
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

On Wed, Feb 03, 2021 at 09:46:55AM -0800, Ivan Babrou wrote:
> > Can you pretty please not line-wrap console output? It's unreadable.
> 
> GMail doesn't make it easy, I'll send a link to a pastebin next time.
> Let me know if you'd like me to regenerate the decoded stack.

Not my problem that you can't use email proper. Links go in the
bitbucket. Either its in the email or it don't exist.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YBu86G1ckCckRyim%40hirez.programming.kicks-ass.net.
