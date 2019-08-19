Return-Path: <kasan-dev+bncBAABBWUD5HVAKGQERIFQB2Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53d.google.com (mail-pg1-x53d.google.com [IPv6:2607:f8b0:4864:20::53d])
	by mail.lfdr.de (Postfix) with ESMTPS id E44FF91D0F
	for <lists+kasan-dev@lfdr.de>; Mon, 19 Aug 2019 08:29:50 +0200 (CEST)
Received: by mail-pg1-x53d.google.com with SMTP id k20sf1947883pgg.15
        for <lists+kasan-dev@lfdr.de>; Sun, 18 Aug 2019 23:29:50 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1566196189; cv=pass;
        d=google.com; s=arc-20160816;
        b=anllNy/UjZoK1jENZSiTjXbnAHCOWBb0pszIL7wEqDvq1736MLYke2od9qyZ4UTFHu
         BRDlxLA2V3AOF0n/gcCIS+sbmYFxX3zUd00J3MORC+JY3jtEwIjNwygusKmIlL75Wo0u
         A6qf/+kDq6mo9FYymQ8uPG7SVIR4fe7GnibKnkTTJrmXYGdwIMRfZbAPC6c9u08ON/7C
         TMYub9HJQn7uvARolrnny62mgf2d5ugWzDBRz4/cwvzufaRd4jAJN+kDkbHMIwfws6Uf
         w/3B6HDdFCndSAIzkolH4D7w43sGDqZX4HfmaSPIA12tLrU+xG5vzOvH7nrQmgMknzbu
         EIew==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=wY9l6eXrrOfc8uosSJihELJGsOo51KSt3b37ayg7ovc=;
        b=h2faURNXcQHkafEDiWd6RAOwC4sopiotABmzzbmlRCRTNCepm8BWX7/SU3zNqcNovS
         WFDjH5Xz8Ms8PdtFtnPIgkLbOFxNt0Gu9mnJS4yXAEzKqbPAarXfnJP0K9gLICYUEfSB
         /1vdRIkobqwLUT2lVQNIBNeDePfSj5uL+dCbnN8LluQfsaH+s9ibQNvuqwclE2v4wYbd
         S7QyK43i8Bu9v+f/f/vzM0OAm0o8OTToPeiFfiuw6Hy8AC9vwmdrSnSTkh8eXhaEenUd
         ZP6kDRTwpD16YovRP/tKzl59p7bC4s1ajLQ9FPr9hUcR/eEi8347QckVqPa9DDO8CVI3
         IQtQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of nickhu@andestech.com designates 59.120.53.16 as permitted sender) smtp.mailfrom=nickhu@andestech.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=wY9l6eXrrOfc8uosSJihELJGsOo51KSt3b37ayg7ovc=;
        b=okkQw9NyuTamXnNQy3+SKmbHRLRrvQKAlFdsAGKCsrmGh+FB2aT9UmZ8A8Ru+9s7/Q
         HvBDV4EFqUqFgVUs8sbFGcb6td05kYVp65P2C5zWNrHb51aVbP8gqdkPxMsfrpLmD4wq
         Ojz7JKEBnzKUGyyZxFrjtRbCZcJZbhKu1sO3pCs8tQRAKmRVvM7YvZDhrgb6rBJqX6lM
         NUnqUG5c6feQhJ85tDQHyiHvwMOwCLxaZjtlCs1SBS6ks/jTeP+AwQ8JNydUNzM8Dp/t
         S6pwheIBQCRkfRYs9ZyNWXwAik2rYk+5LGrxccfKUctPIdqqdiACaEcTl+hVq2zHDQZG
         zWww==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=wY9l6eXrrOfc8uosSJihELJGsOo51KSt3b37ayg7ovc=;
        b=SUDZ6WwTTF26hzc/VnUO3mqnCBnx5gC1wyFSTweKRWnCvCNNV5tQjulWfS9wQ4AwXz
         +DrSVxZetdjy/hTN+c01fqRZI9NSUamwO/9CtAtfiFl5+MeZGO/WlTfTT6Gw1Hj+Cw39
         A63PwbHfcbus8pAvuCnhz8/Eb4S1Awa5XlDuqb6nPJl7tx3uFjhQzxJ0PoMwxsNU2fSh
         my9qq5U6fX+bdgdgrnG/P5MWvVe7hnVUUAL1Libwakr8Ub2R65stz5dzG10SaIzDfbco
         hRTaRFZF9mbf9aC/mBzvJF7g7abTDlUcyxe2rJ1F+mlLg5QPGZbiD8xnB2LJVso9+jOY
         mJ5A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAWneGMIttlYQzhWPREZujUBIW7FDXo7fUE1yPeu5Uc1sDG9hIxi
	mCGkbR0dspm7fBlLmmydCzY=
X-Google-Smtp-Source: APXvYqzYIwojZa+/K3VlD4p17m8w1RSBUcY1eeWRfZXKsuFd8+bW4cfF2SN0pJOTxZtHFFy1xySg/w==
X-Received: by 2002:a17:90a:d146:: with SMTP id t6mr19406257pjw.76.1566196187122;
        Sun, 18 Aug 2019 23:29:47 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:8d45:: with SMTP id s5ls6921pfe.8.gmail; Sun, 18 Aug
 2019 23:29:46 -0700 (PDT)
X-Received: by 2002:a63:10a:: with SMTP id 10mr18637085pgb.281.1566196186683;
        Sun, 18 Aug 2019 23:29:46 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1566196186; cv=none;
        d=google.com; s=arc-20160816;
        b=FOY4yF27ptf0BRWIFjrrdvG+rh3czaL6uQXCceQlMYIcIzHHYtQS2GfGnIBsB5kXGG
         DfMOFNCroIQJDnxEjY+bRlATLbKYi4h/zEvpYs4Etz76WPz+KAm7aYxHpMk1+rNfjEC+
         5fJcFi9Wr2Zq4iv4WLuavMW0kI4QC8XBdwS1/5W1tP2EnHhEwnXRzIgT6byzH511LGbg
         d140TCIqklYb6aWKcU49ew1utfHSh1o8djXSny8rbQbsJHk1d1mksR5iNoI80Q9uIp99
         ytv4VIj7m+Jf8mAuZ0QsQm1XK3JqmuGYFWVWXtSbKlUdqsjbmtDoJXjcAlQSavkNwyUJ
         Tx3g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=AsbuCL5KX44Zc/fmI+dhU1r9ok078/v73DrYIRzV92I=;
        b=miOjWCkuvs+bamoOUqVaxOhW9yaA5xhMp0yTHQcSu1NFv4zHb7HwJl72x0pxuHxr0b
         Henfh5zWCkQPL1n+a58+3W5z/RrM1U24ao6Fo1g/+kgkUZdMqOnW8z6iu+oquA0KHerK
         /SD/1acqm5aswl1PpSTHT6tXEA0MTERd0/yGxkC3yNVYmBrGNx5jgr057B5g37FUFmVz
         xgV0m0fNxh4hNjnhvy4z/QfNe2ZvPkb5TPRT0mhZbfvnctzMziuViO3cJGVkrRPti6V4
         criXBluVlVQRCzCKq+OTDKAz4MWawfMk8Rl4Eqv0IvwL4YxlJ4Ko1X6oQBhdRvb0NMtC
         KJZg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of nickhu@andestech.com designates 59.120.53.16 as permitted sender) smtp.mailfrom=nickhu@andestech.com
Received: from ATCSQR.andestech.com (59-120-53-16.HINET-IP.hinet.net. [59.120.53.16])
        by gmr-mx.google.com with ESMTPS id z9si427248pjp.0.2019.08.18.23.29.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Sun, 18 Aug 2019 23:29:46 -0700 (PDT)
Received-SPF: pass (google.com: domain of nickhu@andestech.com designates 59.120.53.16 as permitted sender) client-ip=59.120.53.16;
Received: from mail.andestech.com (atcpcs16.andestech.com [10.0.1.222])
	by ATCSQR.andestech.com with ESMTP id x7J6HLhb095426;
	Mon, 19 Aug 2019 14:17:21 +0800 (GMT-8)
	(envelope-from nickhu@andestech.com)
Received: from andestech.com (10.0.15.65) by ATCPCS16.andestech.com
 (10.0.1.222) with Microsoft SMTP Server id 14.3.123.3; Mon, 19 Aug 2019
 14:29:18 +0800
Date: Mon, 19 Aug 2019 14:29:19 +0800
From: Nick Hu <nickhu@andestech.com>
To: Paul Walmsley <paul.walmsley@sifive.com>
CC: Palmer Dabbelt <palmer@sifive.com>, Christoph Hellwig <hch@infradead.org>,
        Alan Quey-Liang =?utf-8?B?S2FvKOmrmOmtgeiJryk=?= <alankao@andestech.com>,
        "aou@eecs.berkeley.edu" <aou@eecs.berkeley.edu>,
        "green.hu@gmail.com"
	<green.hu@gmail.com>,
        "deanbo422@gmail.com" <deanbo422@gmail.com>,
        "tglx@linutronix.de" <tglx@linutronix.de>,
        "linux-riscv@lists.infradead.org"
	<linux-riscv@lists.infradead.org>,
        "linux-kernel@vger.kernel.org"
	<linux-kernel@vger.kernel.org>,
        "aryabinin@virtuozzo.com"
	<aryabinin@virtuozzo.com>,
        "glider@google.com" <glider@google.com>,
        "dvyukov@google.com" <dvyukov@google.com>,
        Anup Patel <Anup.Patel@wdc.com>, Greg KH <gregkh@linuxfoundation.org>,
        "alexios.zavras@intel.com"
	<alexios.zavras@intel.com>,
        Atish Patra <Atish.Patra@wdc.com>,
        =?utf-8?B?6Zui6IG3Wm9uZyBab25nLVhpYW4gTGko5p2O5a6X5oayKQ==?=
	<zong@andestech.com>,
        "kasan-dev@googlegroups.com"
	<kasan-dev@googlegroups.com>
Subject: Re: [PATCH 1/2] riscv: Add memmove string operation.
Message-ID: <20190819062919.GA6480@andestech.com>
References: <mhng-ba92c635-7087-4783-baa5-2a111e0e2710@palmer-si-x1e>
 <alpine.DEB.2.21.9999.1908131921180.19217@viisi.sifive.com>
 <20190814032732.GA8989@andestech.com>
 <alpine.DEB.2.21.9999.1908141002500.18249@viisi.sifive.com>
 <20190815031225.GA5666@andestech.com>
 <alpine.DEB.2.21.9999.1908151124450.18249@viisi.sifive.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <alpine.DEB.2.21.9999.1908151124450.18249@viisi.sifive.com>
User-Agent: Mutt/1.5.24 (2015-08-30)
X-Originating-IP: [10.0.15.65]
X-DNSRBL: 
X-MAIL: ATCSQR.andestech.com x7J6HLhb095426
X-Original-Sender: nickhu@andestech.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of nickhu@andestech.com designates 59.120.53.16 as
 permitted sender) smtp.mailfrom=nickhu@andestech.com
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

Hi Paul,

On Thu, Aug 15, 2019 at 11:27:51AM -0700, Paul Walmsley wrote:
> On Thu, 15 Aug 2019, Nick Hu wrote:
> 
> > On Wed, Aug 14, 2019 at 10:03:39AM -0700, Paul Walmsley wrote:
> >
> > > Thanks for the explanation.  What do you think about Palmer's idea to 
> > > define a generic C set of KASAN string operations, derived from the newlib 
> > > code?
> > 
> > That sounds good to me. But it should be another topic. We need to investigate
> > it further about replacing something generic and fundamental in lib/string.c
> > with newlib C functions.  Some blind spots may exist.  So I suggest, let's
> > consider KASAN for now.
> 
> OK.  Here is the problem for us as maintainers.  You, Palmer, and I all 
> agree that a C-language version would be better.  We'd rather not merge a 
> pure assembly-language version unless it had significant advantages, and 
> right now we're not anticipating that.  So that suggests that a C-language 
> memmove() is the right way to go.
> 
> But if we merge a C-language memmove() into arch/riscv, other kernel 
> developers would probably ask us why we're doing that, since there's 
> nothing RISC-V-specific about it.  So do you think you might reconsider 
> sending patches to add a generic C-language memmove()?
> 
> 
> - Paul

About pushing mem*() generic, let's start with the reason why in the first place
KASAN needs re-implement its own string operations:

In mm/kasan/common.c:

	#undef memset
	void *memset(void *addr, int c, size_t len)
	{
		check_memory_region((unsigned long)addr, len, true, _RET_IP_);

		return __memset(addr, c, len);
	}

KASAN would call the string operations with the prefix '__', which should be
just an alias to the proper one.

In the past, every architecture that supports KASAN does this in assembly.
E.g. ARM64:

In arch/arm64/lib/memset.S:

	ENTRY(__memset)
	ENTRY(memset)
	...
	...
	EXPORT_SYMBOL(memset)
	EXPORT_SYMBOL(__memset) // export this as an alias

In arch/arm64/include/asm/string.h

	#define __HAVE_ARCH_MEMSET
	extern void *memset(void *, int, __kernel_size_t);
	extern void *__memset(void *, int, __kernel_size_t);

Now, if we are going to replace the current string operations with newlib ones
and let KASAN use them, we must provide something like this:

In lib/string.c:
        void *___memset(...)
        {
                ...
        }

In include/linux/string.h:

	#ifndef __HAVE_ARCH_MEMCPY 
	#ifdef CONFIG_KASAN
	static inline void* __memset(...)
	{
		___memset(...);
        }
	extern void memset(...); // force those who include this header uses the
					memset wrapped by KASAN
	#else
	static inline void *memset(...)
	{
		___memset(...);
	}
	#endif
	#endif

Does this look OK to you?

Nick

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20190819062919.GA6480%40andestech.com.
