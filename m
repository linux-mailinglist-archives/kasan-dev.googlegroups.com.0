Return-Path: <kasan-dev+bncBCV5TUXXRUIBB55CX73AKGQEAQOSQOY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43b.google.com (mail-pf1-x43b.google.com [IPv6:2607:f8b0:4864:20::43b])
	by mail.lfdr.de (Postfix) with ESMTPS id 593C51E64F2
	for <lists+kasan-dev@lfdr.de>; Thu, 28 May 2020 16:58:01 +0200 (CEST)
Received: by mail-pf1-x43b.google.com with SMTP id w5sf22611429pfu.5
        for <lists+kasan-dev@lfdr.de>; Thu, 28 May 2020 07:58:01 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1590677880; cv=pass;
        d=google.com; s=arc-20160816;
        b=i0tsSKm16rpgstt9BqV33cUYyNRzE0hO9e5YpkaDLzcH5FZAXIdTXvubb7QXhTqlHd
         ycmI3B7I5mxagKsikRqWQ6C8I4TRQkxExGR8Cscg9uzLZdDTLukbpOUCkQXjx9IQdyI6
         zfjz8O3nrpzjGsqcsHhsOvnCPY8Oe4xunb0/+SZSnEgsX8gnAd1XvgDFOYb+Dh22BDDU
         LsPn1QeR5yVr06+EyccrU+HjRIPpc1CO7xgC5s/VYBjnvRZTwEyBHtNi/4tHiHcacmDd
         z9w+1R9NtI0XohD8ecn5hEWepm8yqsY195hZxiU4Ud7c3HX7rY6cJINMmO/h05wgZGT1
         L7Rw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=TvgcLQ/ksYy5bkeY6SFLqWMOVKcJqU6uwojfpl8Iebg=;
        b=Ra0poeGqrDI4r+W1HRZhE6wcXNLqdsQ514crrLfis8+DoHXCs0zTc7QjXfvD1mwY9c
         DghiAzYKNmxAF2jM+WE/TWYgMxZk8YxOZ4cgNx6te1caMWCcplT8vcdogoji1X7iyRCF
         lo53l1YZS14iHC3q36iiJrO4j2tQkbwUfphUE4LbBpWopvRfSPaN/Ie534X6XDcZW70z
         Jr4U0OsnpR+efDSibSU5NVn+CX5ryIE6nKUyn8R2FQLiJ4m304HL42uVABeAkbZyRcYl
         4wn32PgFT8crRBFyiV5K3SyzZ+rUT2VNysGM1AOedLS5PJjud/zpxp26qB4Vnmwx6xtE
         9LkA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=merlin.20170209 header.b=2hjQjRWx;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 205.233.59.134 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=TvgcLQ/ksYy5bkeY6SFLqWMOVKcJqU6uwojfpl8Iebg=;
        b=mHlTkjWv8CCyg77m0Vaqq4957c1MkNxDAphMO0pOrODaUgzqvdWlUqPghS5a9RV6f5
         5W7qE0AXZgpQmEddp7pNXLRp6t42EPqmbJ0UZq3eINnrz2QeELAlRCv4Y1dPMwcHc94q
         0+dmVMAfT16i9HX2zHEgBRzCrm1QCN0gfLcXlPRQtleE+lHGJqSdBeSAOWC4FfDkK5oY
         hM3abXQOTvTH6ECqIlcA2V74fEhT37LgIJb4qQTdAS2uSTMRdWhpcLCfDMj6pBNZD+HN
         Fh9LyT1u9O0vLxTtqEcOgzEMlfZETOeWOe/NImJe4uXpNdWm+kxP/9IxC4pbhkfe35qo
         bxoA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=TvgcLQ/ksYy5bkeY6SFLqWMOVKcJqU6uwojfpl8Iebg=;
        b=ptdpPAkl2Ij8NT8ILxzOyYCjnXsA3ewvODVSW6ZvfOgdiwWJdwD4W6cLrZ5qmJKsfz
         sBlz+g9T5uIGjcVnAKg/3nqJnGzg60+xme3F0ksaIILYmgVKtO0r2EDmx824kTU3MEJv
         1xGU23C5puhU/gGWRkpZt19WkFoN+hBrIAhlkTVVqqgAmnJlmoEJNiqg6JCNR7sCjMcg
         boZ6MQbQj0h7U8HLT91gNDuDxLuBIBw2URZHL/gdsU0uIaHYhs6yGWvjLJDecdyt+D+q
         FRJ5sf4edIuPMuF4MgJ106sJySJF/2Rxm8CWzaKhNh1nYq2EZDzoVexGqze9rkDHBM7y
         6AdQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532F/0aWooSC5l0+tYPVTAncRJWFM+KVcrk+J7YrVVXVXv+F/wM/
	h+O7g632IREaAnF5fHYQeHk=
X-Google-Smtp-Source: ABdhPJwy+iXdN1kVdWKCqANO/FqTIuydDkCFv7JTahR+gB1el9WykNrPiY7oKRn9ITmHwSs6m1kWzA==
X-Received: by 2002:a17:902:fe03:: with SMTP id g3mr4063701plj.323.1590677879939;
        Thu, 28 May 2020 07:57:59 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:7604:: with SMTP id s4ls1206022pjk.1.gmail; Thu, 28
 May 2020 07:57:59 -0700 (PDT)
X-Received: by 2002:a17:902:502:: with SMTP id 2mr3849284plf.134.1590677879443;
        Thu, 28 May 2020 07:57:59 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1590677879; cv=none;
        d=google.com; s=arc-20160816;
        b=uPCE3KkV6LBRQjB+aY8a9dAtzetBiF05Pna5Y9nj29YBfJ0JwAxQ3wN4RxS6ZlTggd
         GKdcRcK/uhp0JDXaK0xdcpznj/35MMdaJ4m42DhoIW+HVl6IwY/Zm/5bkvEoIfyyUAVK
         5RuDlmM7CSwRijEkXi5SVCI1TSkWumj+ds0vo8nSQ09pW0BtzXbeHmxUnIOQtkMGvvmB
         Vs0lC7b9fleha0ep+m3s/u/hCJFN3XjG0RqVrNG1wYKJ14Kj87WKGeuhynmHalyclQ4r
         V6Hpku4X0/3SccdcFzQaK1cGQGMHSJNOzMmWenDqgg3F1aAwHTTs83NknRim/3t9VxMC
         W1rQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=XfDBa6L5beYtY9Mm6rzbZ08MMV6LAgrWZgziccfPExk=;
        b=RuVG+zv7XRAssMqaeEPB0xhwWQnTnrcxNqNC5rY1VCVZ8rbVPo9Wo08yUBI+HyrIDG
         rNAoasC82O2+qZm7NFDdnj8BzTFaR02YtFqwIEO8aNYl4bjKV11aXOSMD+G5NPARP8rN
         b5yGJMkDtd1B8p7kVL0D5QqZNc/WIND97UJSHWcCP4JotvbRqQP5gzYdSboFWv+VnFNT
         Bj3YOZobIb+9DsoKXzckCtRzCdCEbSSZ1n8wWYOkB3V0sNrJ+8AhnXpuQ+gYu9VXo89c
         hKE4L8UWbNsL6wbwS7FSS1qNM0OrPM4NarvzPnq3NlL8HRKk2cGItsfiCm61bwFPPzsu
         e1sQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=merlin.20170209 header.b=2hjQjRWx;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 205.233.59.134 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from merlin.infradead.org (merlin.infradead.org. [205.233.59.134])
        by gmr-mx.google.com with ESMTPS id b4si207691plr.5.2020.05.28.07.57.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 28 May 2020 07:57:59 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 205.233.59.134 as permitted sender) client-ip=205.233.59.134;
Received: from j217100.upc-j.chello.nl ([24.132.217.100] helo=noisy.programming.kicks-ass.net)
	by merlin.infradead.org with esmtpsa (Exim 4.92.3 #3 (Red Hat Linux))
	id 1jeJwS-00037f-Sp; Thu, 28 May 2020 14:55:33 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id 7270F301205;
	Thu, 28 May 2020 16:55:30 +0200 (CEST)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 1000)
	id 555032B9FB566; Thu, 28 May 2020 16:55:30 +0200 (CEST)
Date: Thu, 28 May 2020 16:55:30 +0200
From: Peter Zijlstra <peterz@infradead.org>
To: Josh Poimboeuf <jpoimboe@redhat.com>
Cc: Qian Cai <cai@lca.pw>, Andrey Konovalov <andreyknvl@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com,
	linux-mm@kvack.org, linux-kernel@vger.kernel.org,
	Leon Romanovsky <leonro@mellanox.com>,
	Leon Romanovsky <leon@kernel.org>,
	Randy Dunlap <rdunlap@infradead.org>
Subject: Re: [PATCH 2/3] kasan: move kasan_report() into report.c
Message-ID: <20200528145530.GG706495@hirez.programming.kicks-ass.net>
References: <29bd753d5ff5596425905b0b07f51153e2345cc1.1589297433.git.andreyknvl@google.com>
 <78a81fde6eeda9db72a7fd55fbc33173a515e4b1.1589297433.git.andreyknvl@google.com>
 <20200528134913.GA1810@lca.pw>
 <20200528143341.ntxtnq4rw5ypu3k5@treble>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20200528143341.ntxtnq4rw5ypu3k5@treble>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=merlin.20170209 header.b=2hjQjRWx;
       spf=pass (google.com: best guess record for domain of
 peterz@infradead.org designates 205.233.59.134 as permitted sender) smtp.mailfrom=peterz@infradead.org
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

On Thu, May 28, 2020 at 09:33:41AM -0500, Josh Poimboeuf wrote:
> On Thu, May 28, 2020 at 09:49:13AM -0400, Qian Cai wrote:
> > On Tue, May 12, 2020 at 05:33:20PM +0200, 'Andrey Konovalov' via kasan-dev wrote:
> > > The kasan_report() functions belongs to report.c, as it's a common
> > > functions that does error reporting.
> > > 
> > > Reported-by: Leon Romanovsky <leon@kernel.org>
> > > Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> > 
> > Today's linux-next produced this with Clang 11.
> > 
> > mm/kasan/report.o: warning: objtool: kasan_report()+0x8a: call to __stack_chk_fail() with UACCESS enabled
> > 
> > kasan_report at mm/kasan/report.c:536
> 
> Peter, this was also reported with GCC about a month ago.  Should we add
> __stack_chk_fail() to the uaccess safe list?

It calls panic(), which I suppose is pretty safe, it kills the entire
machine dead :-)

Ok.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200528145530.GG706495%40hirez.programming.kicks-ass.net.
