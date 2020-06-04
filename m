Return-Path: <kasan-dev+bncBCV5TUXXRUIBB45W4T3AKGQE7UWSBOQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3c.google.com (mail-io1-xd3c.google.com [IPv6:2607:f8b0:4864:20::d3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 57D291EE82E
	for <lists+kasan-dev@lfdr.de>; Thu,  4 Jun 2020 18:04:04 +0200 (CEST)
Received: by mail-io1-xd3c.google.com with SMTP id 5sf3867959iou.6
        for <lists+kasan-dev@lfdr.de>; Thu, 04 Jun 2020 09:04:04 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1591286643; cv=pass;
        d=google.com; s=arc-20160816;
        b=osxYou6h4z6V+dMCk7QpHKhQ45wEU+NYoGz5xIvHgKrtQGvZTGbRjSL3UjoKXKC8nj
         A5qqA+Qrc9f7KEOYeH0OdX/TcbLBYopRqrBHCxJC21F/l39SmxfFk2xeAYQhkWnNIBhd
         7R7WEOMS2N22mWTO6E+B2NsO9+h6Ly1xpIc2VIlJfAw1mme5ZQ5ge51Rir9eVONDLQgT
         V5jvlXwYwlPmEWNOKogoLkzzdHdKVX3UGDFNuqanTXyWFHEHNq1DGwHTYaOdDUhONPKj
         MyF/TVRbTbNcN6RcaOam9wODqlk0d8iOYfANc/DBMKYulH0wRlYuIvGu0DaT5XsUwAAQ
         //oA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=2+CZkBoSMxeQP5OCISMHpOCmnEiA2kbR6If5cojFRVI=;
        b=XLHIf95x+MBcQmvnVAAf2YJfFDntPoACWUz0pm5lwaAgfIPG2AR6JMpBOE8Dnz7MyT
         skXF55O4WlZ6pco5ZP1gT78Bx822oObIBY2c6GS+NeOuavb3IROvClwmX5JggvcikB1D
         yWXZ1NL54DbqI7NQOt7nKDywuxwV0pp95LYlxXS068Jn4THfcWLZHpc13J9/CT/IfJn0
         LpUz+JK0RFMOJZzOqf4hLuT4KYSGzBb+/bMWH72nJLWSR7UvkiAPtxhLJWo7LOMef4Db
         eBkqs8VJYjSro0x/p5IpzAzYaC+tEI4nYRT4xS8b5AQyXgQoUvR9/mUgKDDTd1DYEgVN
         Immg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=merlin.20170209 header.b=pBLxwY3F;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=2+CZkBoSMxeQP5OCISMHpOCmnEiA2kbR6If5cojFRVI=;
        b=LPAB/EaPYEQokDjATZr29RJCSj6dtwLoOPF3TwR8Of+ALaNLF3SiS+NWGCH83DkKU9
         9Ww68/07i5//izOZAW05wFiBcNaBHKprg7NRVyLFiCV9FMYMHVzpt4StCkmJ5zWF8806
         F4MFvVSwygFvZeQrPQ9/n2U99Lc63Kwb+QUkVXTQmjdaqCdn4nzAUnnh3mLCs5YKg1ho
         xgyqZtTr4RSzET7rJsBGpPR1l1VBk2kT6k5U2OeT/K9Cd/c61HN8A9lHqOgEeOnXBcG6
         csfVTbMIWHaqpShb+8Z5QNG08GzhRUyLo/c4BaWEUr41iTQx8t3xLnh5hFdTlCBNeZCr
         w7KA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=2+CZkBoSMxeQP5OCISMHpOCmnEiA2kbR6If5cojFRVI=;
        b=iL461XMoncvqQBEiKh0R+ickSiPgN+vmQ6DSKndbnvuTZDNDWHLqhs6vAQxfDc0HDp
         CNn+5jKYVTH/dFm408l4XvAwAoL55izCwMw2En2cmNSfU6Udg/JMMh9PAg/bhEkuXHlq
         79jL0UOQZCB3pbUFdsi+HF8GqSmo19aVD3NKvUqnMlWumi+pbfFmFfx+OuVdCeWOdz9v
         Q5i0GzerVRda4kPSskykL92NazDaCk88z7Msm/xfLDNqhsJ2rU+ylo0k/uOWAKZH3Dni
         5KqW13zInvw6OC4r2pHbsAK3FF+KRvAlOHi8HY79mdgkxxhQYS3NnMzDhIZkeLmtYEID
         bSQw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532u7ZRsRK4CaG/5HoLnNz2UEsGyuwYbI5Dk+9F9VYO3MOskMVzs
	7Jib0QrscBhQx6yA4O2CVIk=
X-Google-Smtp-Source: ABdhPJyRU6e7Fvnp9QBWak4vfEfmleXmviELfrXvL8wxpGgnCZgGv/L9OIhKRCohm/1SKz4lSya+0Q==
X-Received: by 2002:a05:6e02:6c8:: with SMTP id p8mr4774468ils.113.1591286643208;
        Thu, 04 Jun 2020 09:04:03 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6602:1584:: with SMTP id e4ls1026105iow.0.gmail; Thu, 04
 Jun 2020 09:04:02 -0700 (PDT)
X-Received: by 2002:a6b:91d4:: with SMTP id t203mr4538968iod.149.1591286642785;
        Thu, 04 Jun 2020 09:04:02 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1591286642; cv=none;
        d=google.com; s=arc-20160816;
        b=RO2CTB8/JKibTX6d5Do8rb43H+v17uTZ1kRUR4vcs1QUWCVBeeg3/mhanxeAjneVfM
         CfT7cnvMF2Hhl71SFFWqvMfTQD+Wr6MTAVDpKgSYg/cZMwJhP2HEDtedmxwHBQFvuMB/
         rExsxFSVY0aO2t3LuN05GhXUTsvov7rGYGCYUp4zhVxgMQsiCUjr7emaTShAbACXZmu7
         Nto0jkvd07yeKANWSgkgst8ZuBtsSP4oLmYDzaW8cZCIhnoRI0m9cxNfvOvcgi4cSlw6
         O1RhPt3+cTHrCtYmCAw9ule98SJvqgXrnqXE3r1UQ6+C1ENPB4dNOrQ0kW01TSVoCFlD
         MQ+A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=tL9q+t8Vqftp23TReUP0WPRi7rrcPb/Bl/OGGiR0B+c=;
        b=cyOhD2abDz18h6MJ93K+ZDMwqgd7JCyUl5Z6klTaL+log9owYjqcFAcwWqKDsB2ARS
         e7qm1kzViDC9DDNQuCX5pVziMbsZLiIW8n3eFp+taKIdOSkUHgGZYlRx43lv9EDBwI/1
         G6z/Q3KhVb6qdm6+98sVO1ZsVHG7pty6WESW95kJdbbg4fHa+AbuFWd2dv7dmPuHLsa9
         wW35k1YqVYsk8/eRPrsCFDF9vVpd4BFme4Dj+uEDJNTqn/ZttOqn7x3HetNvsHANzkFX
         HBCHB7SP7PyJzx0nCfTtVAAnp6j/5C1n5LxeAksXr+xBylgBta2jSLScoQZIP8WVjI/l
         4xpQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=merlin.20170209 header.b=pBLxwY3F;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from merlin.infradead.org (merlin.infradead.org. [2001:8b0:10b:1231::1])
        by gmr-mx.google.com with ESMTPS id 2si1897iox.0.2020.06.04.09.04.02
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 04 Jun 2020 09:04:02 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) client-ip=2001:8b0:10b:1231::1;
Received: from j217100.upc-j.chello.nl ([24.132.217.100] helo=noisy.programming.kicks-ass.net)
	by merlin.infradead.org with esmtpsa (Exim 4.92.3 #3 (Red Hat Linux))
	id 1jgsLW-0004Zj-Fw; Thu, 04 Jun 2020 16:03:58 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id 239A430008D;
	Thu,  4 Jun 2020 18:03:57 +0200 (CEST)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 1000)
	id 0DB1D20D6E7D6; Thu,  4 Jun 2020 18:03:57 +0200 (CEST)
Date: Thu, 4 Jun 2020 18:03:57 +0200
From: Peter Zijlstra <peterz@infradead.org>
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Marco Elver <elver@google.com>, Borislav Petkov <bp@alien8.de>,
	Thomas Gleixner <tglx@linutronix.de>,
	Ingo Molnar <mingo@kernel.org>,
	clang-built-linux <clang-built-linux@googlegroups.com>,
	"Paul E . McKenney" <paulmck@kernel.org>,
	Dmitry Vyukov <dvyukov@google.com>,
	Alexander Potapenko <glider@google.com>,
	kasan-dev <kasan-dev@googlegroups.com>,
	LKML <linux-kernel@vger.kernel.org>
Subject: Re: [PATCH -tip] kcov: Make runtime functions noinstr-compatible
Message-ID: <20200604160357.GF3976@hirez.programming.kicks-ass.net>
References: <20200604095057.259452-1-elver@google.com>
 <20200604110918.GA2750@hirez.programming.kicks-ass.net>
 <CAAeHK+wRDk7LnpKShdUmXo54ij9T0sN9eG4BZXqbVovvbz5LTQ@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CAAeHK+wRDk7LnpKShdUmXo54ij9T0sN9eG4BZXqbVovvbz5LTQ@mail.gmail.com>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=merlin.20170209 header.b=pBLxwY3F;
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

On Thu, Jun 04, 2020 at 04:02:54PM +0200, Andrey Konovalov wrote:
> On Thu, Jun 4, 2020 at 1:09 PM Peter Zijlstra <peterz@infradead.org> wrote:

> > That whole kcov_remote stuff confuses me.
> >
> > KCOV_ENABLE() has kcov_fault_in_area(), which supposedly takes the
> > vmalloc faults for the current task, but who does it for the remote?
> 
> Hm, no one. This might be an issue, thanks for noticing!
> 
> > Now, luckily Joerg went and ripped out the vmalloc faults, let me check
> > where those patches are... w00t, they're upstream in this merge window.
> 
> Could you point me to those patches?
> 
> Even though it might work fine now, we might get issues if we backport
> remote kcov to older kernels.

Thinking more about this; you can't actually pre-fault for kernel
threads, as kernel threads will run with the mm of whatever regular
thread ran before them, and who knows if they have that vmalloc region
faulted in.

So Joerg's patches are pretty much the only way to guarantee remotes
will not his the vmalloc fault.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200604160357.GF3976%40hirez.programming.kicks-ass.net.
