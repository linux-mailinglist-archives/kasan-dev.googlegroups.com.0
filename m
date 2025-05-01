Return-Path: <kasan-dev+bncBDBK55H2UQKRBXNQZ3AAMGQEAQJVVSA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x63c.google.com (mail-ej1-x63c.google.com [IPv6:2a00:1450:4864:20::63c])
	by mail.lfdr.de (Postfix) with ESMTPS id D326CAA60F2
	for <lists+kasan-dev@lfdr.de>; Thu,  1 May 2025 17:50:55 +0200 (CEST)
Received: by mail-ej1-x63c.google.com with SMTP id a640c23a62f3a-ac31adc55e4sf98201466b.3
        for <lists+kasan-dev@lfdr.de>; Thu, 01 May 2025 08:50:55 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1746114655; cv=pass;
        d=google.com; s=arc-20240605;
        b=Gpy9A6nsyjKkR6kGh99I24Q+NdhX3aBq0Eu1qrZzG4wMS9/iVAGo1yxV7Xkc+sEfWV
         zY0ppZDVSsfWwwBrvbBKcGxRgJFijSVObdeiyDR0dnTy1DujyG+Stx0D4TMpavmJUEfo
         08qi2pp6ggbP7zNVadR/nUhhwfCLTGAtMW+tKHiX+RewzX5xl3PGgxm2XyV4qPwF/aZj
         d8Gct9NGKW2vvuBgh5KPJUZkzcibSzrJxjWoY1EZlMuTgybPXK+chA4BMKASNUVNWC0y
         md6COPN2vQcG1gR4qanL47CNTteDfGm2TxLzDsG7Gra4idf/Ke7YXMoSXEKxP4zYPD9u
         TFIQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=a86Rwid2a1pVc5fJHCu9IrZEkPpFjEV1iGUFbwJi12Y=;
        fh=vlsAuY4WXC6q8YI5FuyQvD8h8klWAv+2oBJJbltNjmE=;
        b=isieEdNNMtBwVwokvwOJvPckLm/uEx4OHvwVzcKZlFsbCArCRZJPCCfRCxNKfFdpvB
         WbHGVe9iyvkZlRkng1XZiGsK+hUVLEJuecQLy4kLvCYI5FpXYZcWXSBKf+F8u7BUNciO
         TZlDDjUicsVh+EZkiFcyYTDGu8jld1hkuYyzo6BVhmGqu8aOnUbTl8xeA/dpEaU92n6I
         0b9q/5WHOjLcd2I5uRj9D7DLoSfHad6pdxc/gXFeO6+DaR9b8c12D2lKZ0VVlvAaG2jO
         tv/Aq5oGcBiXJeE2yXaL1bVV7rS5i6jw00ZDnQYgKkMIUY4ZevHEOKY96FrxedWq2Y44
         wNIw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=Vvw1f1nb;
       spf=none (google.com: peterz@infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1746114655; x=1746719455; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=a86Rwid2a1pVc5fJHCu9IrZEkPpFjEV1iGUFbwJi12Y=;
        b=MxZtan+9S/WCQj+0uEY9aZywnxu4gVp8SmamBJVVfXWs5cBI1TIzWF5L5I2hpDOftY
         Yww7e8YnV0zYCekN8HBGhQXu6BZywcmH/IYtzspa8Nl714xiOvjY+MxEnOXvpyXH7M+r
         pc/6TaP5t/qX0UOId/tDNf8GOWbNtu34OSsYcpRVoA3vJt/QfFVb50bToPS3J0ka36KZ
         sLf1u8Flo55tWbahg2HXjsok2UApEqSnRivMhngzCYiX6U8RSgpuJQK436uJRp8HosV6
         4kEAIsS2gpNrNkcK1lZPpTHPk36DkX0lkUCZGyyO6jr+6rHqpP0Q/3D0mYrZb0oGZChK
         XzcA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1746114655; x=1746719455;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=a86Rwid2a1pVc5fJHCu9IrZEkPpFjEV1iGUFbwJi12Y=;
        b=ZpMH4CQYP+3B+xdI87nYWrZXRPuAnUj8U9hFDggqRixx+wugUpqrSAIWQkAcHtOxNG
         AYJ6TkCSOlPAXwQVrnVOmusSFCRBduNIn/qlBfh6rjiMRNrXwbf3MUpB/ZKcplnRd6ph
         eOO0y/L+C/3T6sXJEBDgWo91wfLtQcFRXUCRnWrHxdp9zO70kyJ8NMYpa5hPEealc4rJ
         wIMM9+REJn9c1FpLooNFcDTwCxVtt7v2ZtRAqUGB+2T6BLul7UjU4nTwooVB6WKyua/P
         vQ+HcE+tY9jnodD/Gms35fx80axmW7CWG4gyMyVrck4+70gOkhuNnD9c8Sd0oErv7k3M
         fagQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWgY5D6ssX5KDbc9JeB902NPBvyNMmiAI4tKijgP1xB14tcZPG00/pSYBWBiMiFUX60pdirEg==@lfdr.de
X-Gm-Message-State: AOJu0YwdByp3I+Br3oCxkTB6ASFt2HVtRdPxKN7h+ZvGYbGWDFHorXfr
	p6W2knx8dEvLKX31W+9Zyu7AccymngeOXrcQs5lgaGri4aYzZSIP
X-Google-Smtp-Source: AGHT+IGTIMw72zHQvXdDXgW+IfOe/oHSugguU1XTGYVU18t6gfxwAKLLI2Jh071bNhrulk24ZzcWsg==
X-Received: by 2002:a17:907:3e14:b0:ac6:e33e:9ef8 with SMTP id a640c23a62f3a-aceff3f59d5mr251473366b.2.1746114654061;
        Thu, 01 May 2025 08:50:54 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AVT/gBE6fSuv9+IP80RSWmY0qmgMKDBDQMOC0ObUowCHmrg8wA==
Received: by 2002:a05:6402:50cc:b0:5f4:961e:9a5f with SMTP id
 4fb4d7f45d1cf-5f90a18d1b3ls1085861a12.1.-pod-prod-01-eu; Thu, 01 May 2025
 08:50:51 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVnVNLrQK6zLuNsqo8X905jBpMvf4HIyTMjjE2B78V725pCC8EjAhuD/W4h4P+Usmap2mBAC9HSbEQ=@googlegroups.com
X-Received: by 2002:a17:907:c23:b0:ace:4197:9ad6 with SMTP id a640c23a62f3a-aceff46ab54mr238935466b.30.1746114650956;
        Thu, 01 May 2025 08:50:50 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1746114650; cv=none;
        d=google.com; s=arc-20240605;
        b=WOiHu0M8FlFbftGZfQbRAyRo56KnZY+sl/AxYgEstpxP3ySf9OXzsM/Wo7hW8RbDKR
         VIhQ0w/i/2Z9TGIv+XD+lAMKXMaimx6vGGPeHX96POabh6YHKjMb9/5XuvAPYTECocBL
         AmsyxShZQm8nxFhRRezifdCvoF0y8Jd0BZkawFag9ZkRYU5XqbRG4cfu/FK6AMCE7G6K
         AmO9yIBmmOA8mBfaFIyrHslMikYAAMUhK6n9+bXjxLn/hOsgymsAxz7PKYz/yloNaLKL
         2k+1Y3uBTlGe5/ZwlDZzcf9bZPN/u9jyTXC1uVHBau4kTEdpjALgHQBrNiQLSd0uI1bK
         a/xg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=P3VRTKEBNLquqRhFZYT5aVzDoqfQbBS2lj2/Gfm1dd8=;
        fh=ZuwnSeP6FwlyaXPSOCgT792irPNp9/xqhWcm2Z0rZvQ=;
        b=L9qOJmxDhuxU4D3xnXLx8IBHK83YjM9VDOu+jFZPKLAD37schOSakpah36K6JH5CRM
         FHAYO+/vBJOvYSgY9O8yTxIahl10EQXywTKAXu99RDwqTIWBs5r6GIOBO+ttoXCCIW3m
         yMpSFkBJpFNqKmKeuda/l5LE8wVQbTR2t7i4YaHpMkyiyOQY5fQxHOdmfYoog/xMlLyF
         CYFghxCKGXqdDSy64gxb1ksbCuGTebDNUILjGHzeW4f/FSDPvtobW/bZjlrHuKp85iHC
         m+/sPGrKyM2DRYjvVzchBRw8Jtb3ZSGV4xur9/kpRrhEzlVj6PvzFGJNZZKJEX5VDUj7
         YT6w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=Vvw1f1nb;
       spf=none (google.com: peterz@infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
Received: from casper.infradead.org (casper.infradead.org. [2001:8b0:10b:1236::1])
        by gmr-mx.google.com with ESMTPS id a640c23a62f3a-ad0bede3f02si1844766b.0.2025.05.01.08.50.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 01 May 2025 08:50:50 -0700 (PDT)
Received-SPF: none (google.com: peterz@infradead.org does not designate permitted sender hosts) client-ip=2001:8b0:10b:1236::1;
Received: from 77-249-17-252.cable.dynamic.v4.ziggo.nl ([77.249.17.252] helo=noisy.programming.kicks-ass.net)
	by casper.infradead.org with esmtpsa (Exim 4.98.2 #2 (Red Hat Linux))
	id 1uAWBP-00000000vWm-1k5y;
	Thu, 01 May 2025 15:50:43 +0000
Received: by noisy.programming.kicks-ass.net (Postfix, from userid 1000)
	id 04927300642; Thu,  1 May 2025 17:50:43 +0200 (CEST)
Date: Thu, 1 May 2025 17:50:42 +0200
From: Peter Zijlstra <peterz@infradead.org>
To: Brendan Jackman <jackmanb@google.com>
Cc: Christoph Hellwig <hch@lst.de>, chenlinxuan@uniontech.com,
	Keith Busch <kbusch@kernel.org>, Jens Axboe <axboe@kernel.dk>,
	Sagi Grimberg <sagi@grimberg.me>,
	Andrew Morton <akpm@linux-foundation.org>,
	Yishai Hadas <yishaih@nvidia.com>, Jason Gunthorpe <jgg@ziepe.ca>,
	Shameer Kolothum <shameerali.kolothum.thodi@huawei.com>,
	Kevin Tian <kevin.tian@intel.com>,
	Alex Williamson <alex.williamson@redhat.com>,
	Peter Huewe <peterhuewe@gmx.de>,
	Jarkko Sakkinen <jarkko@kernel.org>,
	Masahiro Yamada <masahiroy@kernel.org>,
	Nathan Chancellor <nathan@kernel.org>,
	Nicolas Schier <nicolas.schier@linux.dev>,
	Nick Desaulniers <nick.desaulniers+lkml@gmail.com>,
	Bill Wendling <morbo@google.com>,
	Justin Stitt <justinstitt@google.com>,
	Vlastimil Babka <vbabka@suse.cz>,
	Suren Baghdasaryan <surenb@google.com>,
	Michal Hocko <mhocko@suse.com>,
	Johannes Weiner <hannes@cmpxchg.org>, Zi Yan <ziy@nvidia.com>,
	Mathieu Desnoyers <mathieu.desnoyers@efficios.com>,
	"Paul E. McKenney" <paulmck@kernel.org>,
	Boqun Feng <boqun.feng@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Juergen Gross <jgross@suse.com>,
	Boris Ostrovsky <boris.ostrovsky@oracle.com>,
	Thomas Gleixner <tglx@linutronix.de>,
	Ingo Molnar <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>,
	Dave Hansen <dave.hansen@linux.intel.com>, x86@kernel.org,
	"H. Peter Anvin" <hpa@zytor.com>, linux-nvme@lists.infradead.org,
	linux-kernel@vger.kernel.org, linux-mm@kvack.org,
	kvm@vger.kernel.org, virtualization@lists.linux.dev,
	linux-integrity@vger.kernel.org, linux-kbuild@vger.kernel.org,
	llvm@lists.linux.dev, Winston Wen <wentao@uniontech.com>,
	kasan-dev@googlegroups.com, xen-devel@lists.xenproject.org,
	Changbin Du <changbin.du@intel.com>,
	Linus Torvalds <torvalds@linux-foundation.org>
Subject: Re: [PATCH RFC v3 0/8] kernel-hacking: introduce
 CONFIG_NO_AUTO_INLINE
Message-ID: <20250501155042.GR4198@noisy.programming.kicks-ass.net>
References: <20250429-noautoinline-v3-0-4c49f28ea5b5@uniontech.com>
 <20250429123504.GA13093@lst.de>
 <D9KW1QQR88EY.2TOSTVYZZH5KN@google.com>
 <20250501150229.GU4439@noisy.programming.kicks-ass.net>
 <D9KXE2YX8R2M.3L7Q6NVIXKPE9@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <D9KXE2YX8R2M.3L7Q6NVIXKPE9@google.com>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=casper.20170209 header.b=Vvw1f1nb;
       spf=none (google.com: peterz@infradead.org does not designate permitted
 sender hosts) smtp.mailfrom=peterz@infradead.org
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

On Thu, May 01, 2025 at 03:22:55PM +0000, Brendan Jackman wrote:

> Whereas enlarging the pool of functions that you can _optionally target_
> for tracing, or nice reliable breakpoints in GDB, and disasm that's
> easier to mentally map back to C, seems like a helpful improvement for
> test builds. Personally I sometimes spam a bunch of `noinline` into code
> I'm debugging so this seems like a way to just slap that same thing on
> the whole tree without dirtying the code, right?

Dunno, I'm more of the printk school of debugging. Very rarely do I
bother with GDB (so rare in fact that I have to look up how to even do
this).

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250501155042.GR4198%40noisy.programming.kicks-ass.net.
