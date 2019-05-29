Return-Path: <kasan-dev+bncBCV5TUXXRUIBBPVPXHTQKGQEERJFPDA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63b.google.com (mail-pl1-x63b.google.com [IPv6:2607:f8b0:4864:20::63b])
	by mail.lfdr.de (Postfix) with ESMTPS id 571C72D9C3
	for <lists+kasan-dev@lfdr.de>; Wed, 29 May 2019 11:58:24 +0200 (CEST)
Received: by mail-pl1-x63b.google.com with SMTP id y9sf1216335plt.11
        for <lists+kasan-dev@lfdr.de>; Wed, 29 May 2019 02:58:24 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1559123902; cv=pass;
        d=google.com; s=arc-20160816;
        b=lL/+liVlWxQ3++JK5nYroaxcw2nras7Z5Mv5o0WnH4yR7n8X0YKD+GoR8XEnfx4DF3
         FQrSRRGFMzXRDCc+2hbASxKU/SBFCt9cRxAmq/0O2sCkvrXS0BbaOLiXZPkuivmnCicn
         47ocXv39d7I3y87eDfuKqPC8wtO1kAsZPyPSsJDyKAeWdc4+PK2huQkUgt5MS0m1y/Vh
         Hxw+VomBZEDBZiT2EH/+xX0L0fC7pbO+xIW+IQtEfMA4oqZqVpUS4j2BDyg/3U3iZfRb
         +sGfHTuTm3spFMYBoHl4t5BwYha/AmVscp+cWAl1M2jwFaiZpRglQDgUeeJMR7PGjaL5
         oLAQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=5G3N6fpY5Bw6E4wx6WokSv9YwSJ2Q/pZUwpZneNi+pE=;
        b=rfXNbCnGar7JBXNoc4pSQykYAAt4tYzOK5EDmRJuwS3BQWXZZGGKPRotrftGmybXaB
         aoe5U+zr7w2AzyVgQq1b3TgKgVd7Q7lfJtkOdaeeutcJYxinIxJ15O9SiwhCQETsch+3
         txd8mZ3K31by2JQPjtCVzDeX5snRcsAzqxUbOvpYSiObeGhNaubvfIBLXIL9cCgYTpe9
         ojdxHJQBDMQoGQIslqJgGq98kDiCUzWAoGv1Ik9rIdMndjDQcU16XxoHcwo1JCggAjvv
         wI0oTkMXbMaacziWkntkQsqmniJsXx0OltUw0xhh6LxlRSg6BBI4ZW/Z5IiFnQW6b/3s
         mxFg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=bombadil.20170209 header.b=C+ffkDjw;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2607:7c80:54:e::133 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=5G3N6fpY5Bw6E4wx6WokSv9YwSJ2Q/pZUwpZneNi+pE=;
        b=XdTBfobncNLBnTvI1RXiv1cTY6tnHa/dJPmMSBM7OIUyeEaIH8hCKZpqe1LZ6GBJoV
         ztUGBsog6BrGFL2MFqSdnkBU9mvNtUebq1cSDOsD0876JSlhJZD9IcfoY5WkqDjERRwR
         KYMrMEFdA04M5JIUbViYyjxTrqW0VVRQoRJ3wThAdc7bGJ/QI2dfQBJJqLlpcQ/rufsR
         nJG2h/0jHbQY3YmqbLho+Mn2fetH8Ne9R7Um9Ijq6oR8Bnb7wMMRbPd06B6svTLRts/W
         F7ViADfLdeMM2QecBFr5Tzf4FKD+R1w2pfiSoyAz/Vxn6Bp/PUOx0c2EBeBpBBJdEEtE
         p7IQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=5G3N6fpY5Bw6E4wx6WokSv9YwSJ2Q/pZUwpZneNi+pE=;
        b=Z6qjYX5d6mYrbN1TkpTJhzV6RUKfkxYL5mWz4OHvaFU59+qv5s7bkIQiDSz3NFWEGq
         T30kUmCLnsoe7gIg9hsYKvbY2u3bX17c7J88lwQ1xfwh4QM8Sf3H+OnzOFOZzUvczqPv
         o94uleoMbnEBoicIBeGZdcFrlF7S7dCh8PgF/Ch7G8uGh2MK637gZd/NiQ4gxeZYFZ7g
         C9Bu8yR1sZjLvs/68dXH37TMocSQVfRE+mD4QkcwgvL7my4twvmHTcNTuGmH/W5Z8Xqb
         P3jSU6TDBHO4dLhIcUsH4Zpu+dlQ9ZwHKBDJRr/HMmop4WrWazhSDuaOwrBpxcNmMNIO
         Pibw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAUx5wWyP7sWzwlNz09sQvFEspDnKUby65jS0HilOF++6O2h6uCJ
	YU2tmnoeYPfieBj+SmftRkA=
X-Google-Smtp-Source: APXvYqx0l4KOPhBG0l2eB/emtD++2osp+z/VkF2dRwBXJGphn5Z4r3wyW1DW0OBnHJYN5zG1oQLQTw==
X-Received: by 2002:a17:902:8609:: with SMTP id f9mr79609325plo.252.1559123902693;
        Wed, 29 May 2019 02:58:22 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:24f:: with SMTP id 76ls413237pgc.10.gmail; Wed, 29 May
 2019 02:58:22 -0700 (PDT)
X-Received: by 2002:a63:5d54:: with SMTP id o20mr10178161pgm.97.1559123902417;
        Wed, 29 May 2019 02:58:22 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1559123902; cv=none;
        d=google.com; s=arc-20160816;
        b=E37MkgSVGuZmskBSLZ1xHzJKUtqZXQvPn9GtseHeT5h7rM3b/nN7OablHt/ym1J9BL
         ZXPTVJE5M0esmeUF7jXi569Ig1/lRQrn9X4W7sPwW7jm1lc837A8Tp5rVB33R5kuH0g/
         av96WDO225UHjeE+U8lg8eyBLb5h6FKQGu/2wUyATElE8vmRKs7D5drqBEYGM/H0bQkE
         Iaj6K7Zma2U1zSat+AKT1dcjHQLzjnJOHd1COcgLMvr+8VtcjQ21NxItNL1ZE3TEQr3s
         3ez55IW0Zeis987+ifs8iA/2spNh3sIGYTHz/fUma3nrJRG2fxH3U6rUeBPTgldoC8d+
         5xAQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=40Ww1U6jHSA8ZmRiYmC+C6BB0Qna+KOdSYwCoTc6YjQ=;
        b=lKPdS2Ahy0vpn7tqy5iiNcdIVM9fBL31W5gwwH/KzHwJeM458tFCyFwdRmdqAuykQg
         GyQKV98uQgQjBlWvjA2G+GpDasUn0wziTxt9S1UeGfUyFZjJVQVqz516I8sZC2KsneSi
         TRUN9NEiW4Te6/o1Aew+BQ194ELEzIuX909zDTuUkzwLKIZUaHUoK7FkuHZs7j7PVmtQ
         fH2sexY+O50dvZsIqYzWQQgbWiH7XG4yRbh1KQQMZRufhROUQzHbRQ1gxCdwXlL9b5mO
         Rqrtc7mgJWf7nb5VgY9fjcmEYfwJz3aPdFbQR1INs4EgDh0JCtzbjY6MJpz0orOIRjZ1
         xBFQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=bombadil.20170209 header.b=C+ffkDjw;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2607:7c80:54:e::133 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from bombadil.infradead.org (bombadil.infradead.org. [2607:7c80:54:e::133])
        by gmr-mx.google.com with ESMTPS id q6si109637pjb.1.2019.05.29.02.58.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-CHACHA20-POLY1305 bits=256/256);
        Wed, 29 May 2019 02:58:22 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2607:7c80:54:e::133 as permitted sender) client-ip=2607:7c80:54:e::133;
Received: from j217100.upc-j.chello.nl ([24.132.217.100] helo=hirez.programming.kicks-ass.net)
	by bombadil.infradead.org with esmtpsa (Exim 4.90_1 #2 (Red Hat Linux))
	id 1hVvLc-0002EX-JV; Wed, 29 May 2019 09:58:16 +0000
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 1000)
	id 22A822065C636; Wed, 29 May 2019 11:58:15 +0200 (CEST)
Date: Wed, 29 May 2019 11:58:15 +0200
From: Peter Zijlstra <peterz@infradead.org>
To: Marco Elver <elver@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@google.com>,
	Jonathan Corbet <corbet@lwn.net>,
	Thomas Gleixner <tglx@linutronix.de>,
	Ingo Molnar <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>,
	"H. Peter Anvin" <hpa@zytor.com>,
	the arch/x86 maintainers <x86@kernel.org>,
	Arnd Bergmann <arnd@arndb.de>, Josh Poimboeuf <jpoimboe@redhat.com>,
	"open list:DOCUMENTATION" <linux-doc@vger.kernel.org>,
	LKML <linux-kernel@vger.kernel.org>,
	linux-arch <linux-arch@vger.kernel.org>,
	kasan-dev <kasan-dev@googlegroups.com>
Subject: Re: [PATCH 2/3] tools/objtool: add kasan_check_* to uaccess whitelist
Message-ID: <20190529095815.GL2623@hirez.programming.kicks-ass.net>
References: <20190528163258.260144-1-elver@google.com>
 <20190528163258.260144-2-elver@google.com>
 <20190528171942.GV2623@hirez.programming.kicks-ass.net>
 <CACT4Y+ZK5i0r0GSZUOBGGOE0bzumNor1d89W8fvphF6EDqKqHg@mail.gmail.com>
 <CANpmjNP7nNO36p03_1fksx1O2-MNevHzF7revUwQ3b7+RR0y+w@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNP7nNO36p03_1fksx1O2-MNevHzF7revUwQ3b7+RR0y+w@mail.gmail.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=bombadil.20170209 header.b=C+ffkDjw;
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

On Wed, May 29, 2019 at 11:46:10AM +0200, Marco Elver wrote:
> On Wed, 29 May 2019 at 10:55, Dmitry Vyukov <dvyukov@google.com> wrote:
> >
> > On Tue, May 28, 2019 at 7:19 PM Peter Zijlstra <peterz@infradead.org> wrote:
> > >
> > > On Tue, May 28, 2019 at 06:32:57PM +0200, Marco Elver wrote:
> > > > This is a pre-requisite for enabling bitops instrumentation. Some bitops
> > > > may safely be used with instrumentation in uaccess regions.
> > > >
> > > > For example, on x86, `test_bit` is used to test a CPU-feature in a
> > > > uaccess region:   arch/x86/ia32/ia32_signal.c:361
> > >
> > > That one can easily be moved out of the uaccess region. Any else?
> >
> > Marco, try to update config with "make allyesconfig" and then build
> > the kernel without this change.
> >
> 
> Done. The only instance of the uaccess warning is still in
> arch/x86/ia32/ia32_signal.c.
> 
> Change the patch to move this access instead? Let me know what you prefer.

Yes, I think that might be best. The whitelist should be minimal.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20190529095815.GL2623%40hirez.programming.kicks-ass.net.
For more options, visit https://groups.google.com/d/optout.
