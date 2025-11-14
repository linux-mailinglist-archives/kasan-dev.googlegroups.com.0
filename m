Return-Path: <kasan-dev+bncBD4NDKWHQYDRBQXE3LEAMGQESN5YPBQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3f.google.com (mail-oa1-x3f.google.com [IPv6:2001:4860:4864:20::3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 942E9C5B54A
	for <lists+kasan-dev@lfdr.de>; Fri, 14 Nov 2025 05:38:28 +0100 (CET)
Received: by mail-oa1-x3f.google.com with SMTP id 586e51a60fabf-3d1b82f5880sf3111899fac.1
        for <lists+kasan-dev@lfdr.de>; Thu, 13 Nov 2025 20:38:28 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1763095107; cv=pass;
        d=google.com; s=arc-20240605;
        b=JgIiB4Y/+W715TW83EKULqVEnBEPx+NK9uw7aZJb4nNMxzhSN/vuf3feXnU5+cXDns
         RWSfZcwtMUJqOU//XgJhZ8CXHPut+iydHhptyu51XRzgDvsmhMX0dHpKj1jEu7jfFCih
         u4+8eRTTPyLqNdjnGw8Air0MCFSb5STLDHxKifeGOIeeLOgELvwVxMETDBA9MSj7Kx/l
         guruqrybGSg3/ByaeDVjeiJf7Refr1/4Tu9+JQQOCvY0Fwn4hsiZYvJVjQVX03HNXoYA
         hjALdsDuvnunVnUmtwSsMIDGLmFGjA5zR8dtLMxZQDYtwc89oBHq8F5635DCG0x3ucSz
         tLbA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=yx9pCp473xwD0EiKHD8L1xUkgYvFfWOioUg8D60UAQU=;
        fh=3c42mRRKSUwi0k9YELyhyMYVHoZ6sohZLwoVPIlRmk4=;
        b=XLtF09gxER7CNRx5m+QgKYmQwH38rNrPjRsrgnZ6d11xsdM0g//r0P+LDhBqCZu7dy
         j7rmpWHV1XLb3+Wl/7adPY+ZEkX4PzBeMAtA74o4z6JTonn/+/8yqsXHzpVxSHpl7sZZ
         bb/y/ichk4cN8vaPw2MDIuy4dVYZOloFZcDeRVJJVn+TrDSm6eHQwuVHe+KLp3yXW13S
         iEWSoF05+GDPiq3jdnUDGjy7jgN4BWdbSN5s5v2BEuppmMVgKsr3vRg9Ybp2JWXhhBM2
         0MXxdlbv7gE0xvYU9geC52MyYeH0ylTk43zCdu5JFjWueMgJHuXIE4FLNIAdZixQ9uAB
         +jeg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=D3U+OeK9;
       spf=pass (google.com: domain of nathan@kernel.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=nathan@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1763095107; x=1763699907; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=yx9pCp473xwD0EiKHD8L1xUkgYvFfWOioUg8D60UAQU=;
        b=i2Pc+eE1nz7AeTcxa3iQS1RBJYJV/3b2pB7JMBWUFoP20HdqjqzibzqkHP/qmQKEPO
         O1Y1JUdNpORy790yRqfm8DPWnLX4cUTPE1BtdgHmlcLM35ZXXaTPs+gdLyJGsvF8ymPL
         enslEG1k28OQVF69sT1bUNeiC27crxwRd/1pZYZhBCVJdELsR1JnXY5HIQf4fuxoJHFB
         1prfjKvjIJICC9cm3X5kKYMtCeqJG/gbVW7/Vp/8UULMDK71Pg+VrPzActFT/x2gy4Kk
         bUFIXmKbfyyG5pp+H25obCj0mTZ+d+Jrx07BMfGHPS7M0RxDAviGuPLBQf5k84m9iPmT
         f9Sw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1763095107; x=1763699907;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=yx9pCp473xwD0EiKHD8L1xUkgYvFfWOioUg8D60UAQU=;
        b=NIuA4Q6dIyhBYY1AZmX6UOcAV29VvZwHQsNVfCC54+briDNniQkMUIu3nwnzyBuGD2
         OGCgn6Hf0eXVSiynqgF7t8j0W8Xj8hxJqrnu7IicQ6yLEizTRdBAo3xO/QV0MWT26FJU
         lQx4ePoKbkw7HPw4C1T2nLd+bWbJoKQr9spIOePvTg3tfXUjTb1iEUV/fJMLazhDrVqj
         40wGCNFNkAsUNav3fTRIKhGoIjA0OvEx0E6eZEJ99Fw+POp8i0xsrvK2dTIX7a6GiDK9
         6HAk8sJ2MuvUP7h5m0GYoIN0HvFUQ8DkVSYxcFI1kXWBG0QnXDhHxTbaier9iPMt/BI2
         z25Q==
X-Forwarded-Encrypted: i=2; AJvYcCXcArMrd/KgF4MCdku4Y8ftz6Y4kJRQ7idzRQKs6aBozRrUGYRX755a6d7y5abHxExGKbbMfw==@lfdr.de
X-Gm-Message-State: AOJu0Yy1t+QpQSv14zKzxYdlIfi3xHD7u3zUJrh9ZBNMHxfTlVnOg10S
	sedMjV2TPu/26qnozPEW7JCtdLjD8CvJyAy8Cnb5z/NVzAcCaJpmqImx
X-Google-Smtp-Source: AGHT+IF2rMDiN/qlukaqOx0O9ZhnKqeHwTRXD1tgiJ7Y032oQrwy5MSWsf37j8tJ6Dr5RtvVnWAA/Q==
X-Received: by 2002:a05:6870:1615:b0:3db:6c26:b6c5 with SMTP id 586e51a60fabf-3e8673a2a5cmr1256019fac.16.1763095106947;
        Thu, 13 Nov 2025 20:38:26 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+bJyYTmpAvDGpXI7hKtg9YNKhNEJtnrZ9YP94FZvHhfRg=="
Received: by 2002:a05:6871:8759:20b0:374:de90:136b with SMTP id
 586e51a60fabf-3e83285b557ls711292fac.2.-pod-prod-00-us-canary; Thu, 13 Nov
 2025 20:38:26 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXzzizpc71KvqpANur6Jp2XhNkyRZQq3hjCbu4UT1r+1ePQsAxCd6jcd7jIGE01QkuSSQAAHuWwVsg=@googlegroups.com
X-Received: by 2002:a05:6808:1205:b0:450:89ee:922b with SMTP id 5614622812f47-45095dcdc29mr1187018b6e.22.1763095106129;
        Thu, 13 Nov 2025 20:38:26 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1763095106; cv=none;
        d=google.com; s=arc-20240605;
        b=YNqdAtR2zxbjm0HdHnpjLlnnn8oiYttBsUzxnDrlQUgxVJyYpRoRtYaVux3uvM02dd
         ohwdaii517BcRu2HTJ4Xim3DxwWoxBobpbSGlpK+MQMKInyQh8jF6tMswp0RGsQpaM0s
         C1RQr7VAlp1phnPdqoQEWs1eSSZ/LaPMRG21NqJt2onEsJDrLAk26u+nqh8FZGXjz39q
         aIM5kf0U9dn7hgdcpFlK6/5IRL3J0peOeCpQHsd2J8ch6C3ITJ3kCI1f04T1q4M/vdWJ
         mRWJm4epaQuBTcFEBxUq8pol7x7XCg/jmM6PMPrb6/oEDfppe/sKylUHotvHzNWSShNZ
         wHDQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=/KGUOKaMgQGk1AtOrPMAFhEklPPuCbyLaBZCVybPbFQ=;
        fh=d6LxOBo27aivjYApbKE9WcSLPH6BPASPzAOJI0hd/TQ=;
        b=L8Ce/BvmRps9AvORMVbG9ge9MbSZdlvV+WVw4a1V9KECG0NTexTaqGrtNeD7V0g4xU
         v3rhug3S+Zwmf/DnQUE7Phnqc8qBIkqX+f2fWF6nZ38Gwt+8+vsDmq7rKBjmhdtLmS60
         f9soBXvLyxfw48QerrnSoIMlVjB2Pvvt1xK8Gaelk8qJ9z5IJ6kVXoX+Im3w3jsqF9KK
         0u/GKdj0pPhhrLZRmdtZunYP8TwFr0VkaPlQ2jQJ6SNZFu3K49EpCN2Y9qU9PWY0VWVM
         zB8RjZB38i9W6hLQcq1bRjmVTpcOobYEv4j/aaQkkt5hNhdurUAxzrfN3AUs8b16qt7+
         +30Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=D3U+OeK9;
       spf=pass (google.com: domain of nathan@kernel.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=nathan@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [172.234.252.31])
        by gmr-mx.google.com with ESMTPS id 5614622812f47-4508a6ccbc4si93224b6e.5.2025.11.13.20.38.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 13 Nov 2025 20:38:25 -0800 (PST)
Received-SPF: pass (google.com: domain of nathan@kernel.org designates 172.234.252.31 as permitted sender) client-ip=172.234.252.31;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id 267B741B14;
	Fri, 14 Nov 2025 04:38:25 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 9D54CC4AF09;
	Fri, 14 Nov 2025 04:38:15 +0000 (UTC)
Date: Thu, 13 Nov 2025 21:38:12 -0700
From: "'Nathan Chancellor' via kasan-dev" <kasan-dev@googlegroups.com>
To: Marco Elver <elver@google.com>
Cc: Linus Torvalds <torvalds@linux-foundation.org>,
	Peter Zijlstra <peterz@infradead.org>,
	Boqun Feng <boqun.feng@gmail.com>, Ingo Molnar <mingo@kernel.org>,
	Will Deacon <will@kernel.org>,
	"David S. Miller" <davem@davemloft.net>,
	Luc Van Oostenryck <luc.vanoostenryck@gmail.com>,
	"Paul E. McKenney" <paulmck@kernel.org>,
	Alexander Potapenko <glider@google.com>,
	Arnd Bergmann <arnd@arndb.de>, Bart Van Assche <bvanassche@acm.org>,
	Bill Wendling <morbo@google.com>, Christoph Hellwig <hch@lst.de>,
	Dmitry Vyukov <dvyukov@google.com>,
	Eric Dumazet <edumazet@google.com>,
	Frederic Weisbecker <frederic@kernel.org>,
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
	Herbert Xu <herbert@gondor.apana.org.au>,
	Ian Rogers <irogers@google.com>, Jann Horn <jannh@google.com>,
	Joel Fernandes <joelagnelf@nvidia.com>,
	Jonathan Corbet <corbet@lwn.net>,
	Josh Triplett <josh@joshtriplett.org>,
	Justin Stitt <justinstitt@google.com>, Kees Cook <kees@kernel.org>,
	Kentaro Takeda <takedakn@nttdata.co.jp>,
	Lukas Bulwahn <lukas.bulwahn@gmail.com>,
	Mark Rutland <mark.rutland@arm.com>,
	Mathieu Desnoyers <mathieu.desnoyers@efficios.com>,
	Miguel Ojeda <ojeda@kernel.org>,
	Neeraj Upadhyay <neeraj.upadhyay@kernel.org>,
	Nick Desaulniers <nick.desaulniers+lkml@gmail.com>,
	Steven Rostedt <rostedt@goodmis.org>,
	Tetsuo Handa <penguin-kernel@i-love.sakura.ne.jp>,
	Thomas Gleixner <tglx@linutronix.de>, Thomas Graf <tgraf@suug.ch>,
	Uladzislau Rezki <urezki@gmail.com>,
	Waiman Long <longman@redhat.com>, kasan-dev@googlegroups.com,
	linux-crypto@vger.kernel.org, linux-doc@vger.kernel.org,
	linux-kbuild@vger.kernel.org, linux-kernel@vger.kernel.org,
	linux-mm@kvack.org, linux-security-module@vger.kernel.org,
	linux-sparse@vger.kernel.org, llvm@lists.linux.dev,
	rcu@vger.kernel.org
Subject: Re: [PATCH v3 00/35] Compiler-Based Capability- and Locking-Analysis
Message-ID: <20251114043812.GC2566209@ax162>
References: <20250918140451.1289454-1-elver@google.com>
 <CAHk-=wgd-Wcp0GpYaQnU7S9ci+FvFmaNw1gm75mzf0ZWdNLxvw@mail.gmail.com>
 <aMx4-B_WAtX2aiKx@elver.google.com>
 <CAHk-=wgQO7c0zc8_VwaVSzG3fEVFFcjWzVBKM4jYjv8UiD2dkg@mail.gmail.com>
 <aM0eAk12fWsr9ZnV@elver.google.com>
 <CANpmjNNoKiFEW2VfGM7rdak7O8__U3S+Esub9yM=9Tq=02d_ag@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNNoKiFEW2VfGM7rdak7O8__U3S+Esub9yM=9Tq=02d_ag@mail.gmail.com>
X-Original-Sender: nathan@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=D3U+OeK9;       spf=pass
 (google.com: domain of nathan@kernel.org designates 172.234.252.31 as
 permitted sender) smtp.mailfrom=nathan@kernel.org;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Nathan Chancellor <nathan@kernel.org>
Reply-To: Nathan Chancellor <nathan@kernel.org>
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

On Thu, Nov 13, 2025 at 03:30:08PM +0100, Marco Elver wrote:
> On Fri, 19 Sept 2025 at 11:10, Marco Elver <elver@google.com> wrote:
> [..]
> > I went with "context guard" to refer to the objects themselves, as that
> > doesn't look too odd. It does match the concept of "guard" in
> > <linux/cleanup.h>.
> >
> > See second attempt below.
> [..]
> 
> I finally got around baking this into a renamed series, that now calls
> it "Context Analysis" - here's a preview:
> https://git.kernel.org/pub/scm/linux/kernel/git/melver/linux.git/log/?h=ctx-analysis/dev
> 
> As for when we should give this v4 another try: I'm 50/50 on sending
> this now vs. waiting for final Clang 22 to be released (~March 2026).
> 
> Preferences?

For the record, I can continue to upload clang snapshots for testing and
validating this plus the sooner this hits a tree that goes into -next,
the sooner the ClangBuiltLinux infrastructure can start testing it. I
assume there will not need to be many compiler side fixes but if
__counted_by has shown us anything, it is that getting this stuff
deployed and into the hands of people who want to use it is the only
real way to find corner cases to address. No strong objection from me if
you want to wait for clang-22 to actually be released though for more
access.

Cheers,
Nathan

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251114043812.GC2566209%40ax162.
