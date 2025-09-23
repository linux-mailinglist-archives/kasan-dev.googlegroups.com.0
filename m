Return-Path: <kasan-dev+bncBD4NDKWHQYDRBSHTZPDAMGQEBIZNNRI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x740.google.com (mail-qk1-x740.google.com [IPv6:2607:f8b0:4864:20::740])
	by mail.lfdr.de (Postfix) with ESMTPS id D74CAB9769A
	for <lists+kasan-dev@lfdr.de>; Tue, 23 Sep 2025 21:49:30 +0200 (CEST)
Received: by mail-qk1-x740.google.com with SMTP id af79cd13be357-82968fe9e8csf1599840785a.0
        for <lists+kasan-dev@lfdr.de>; Tue, 23 Sep 2025 12:49:30 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758656969; cv=pass;
        d=google.com; s=arc-20240605;
        b=Ih7aQ2seRNBGWO8rF8qnneC5OHpYg/Yz/ljb0YrJISltC3sAkwqTEeHp/pFB7UqOo7
         yfxF5WgLJ/C2PgYgepO0JnkH8pIbqHWPfc2eT7LbYY4goJDeovrVfAtrxnzX8lrWAyQ6
         vOdBBxMT9Stb88gO8RW3jxHr0P20a6wSUJFC7eu2z6iW3nmglCYLNw5ixhf3oDob9jpM
         eBV1/NhT3bHm8BPgItrg09qFVIuFMy56bFc9vbI4anjXHCnjJQT0XZOimGoyfLLPZIiw
         lxZ6SI4nmyJBGNjllRViFWgWpyY1gI+63jbCdIX2NYdVi2fhCBfFDKSqptwneBykgARF
         vJDQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=vnxE4u813tTassD+IlSMpPmZoiz/24DQ8ztGxsq1aZA=;
        fh=1/v6hh/n9iE5k0SA0A5ppS66eqqBmdlp+uNfFijidYk=;
        b=THFesYTETjnJ42D7pLJd4QKNPkrbpGXerKMaZmMgHvNq44NFWCHh6EY36wmg7mEYlD
         hiSgmKD0oCjwDBwdIAdYKYRsK6vNxOWn+1HOVoahu2khZ3ITP+pqebe2itDfnMAexlbx
         IOOmnAQxlnfLMfqKSb1HGE5FxE6QTwQeffuKepb3xY52HOLX3krkDle70vUVq10PyLJ5
         Tkpc4getL1uWUvOFnYjdAep31ZLYX2LZBPsFdAkLDFvj87ZEoUeTZyWq5PtnPfpBLyhW
         rrwIxmErWKgsbfNQiKCe7UnB5cMqmSsaPwk72IYp9vfbogh6zNpVcJ8GEEXQ81m/4szn
         vo0w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=PvIaGTqH;
       spf=pass (google.com: domain of nathan@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) smtp.mailfrom=nathan@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758656969; x=1759261769; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=vnxE4u813tTassD+IlSMpPmZoiz/24DQ8ztGxsq1aZA=;
        b=wFb5Rc5D0CI3WRKZO6TMJu++DC22t34rfkj1F2R2mviWmaQ9oOX6JFeVXyWc1igGuW
         906BC1HIgca0u2DMhi0uJDJSLKbfYo3AaIPBVHcFpKYS//RMDqSvzFlUQWkqK8Nf/FTA
         8EpTInhhaOk8eX6C1SavqHCYJ7TTluLGnQeWEfiQKY2JrnwTbxxNZVkFKgJTmWAK2KHC
         2DA+6/wP3Fh4PjGCzb/R/0oDvzwEeXJwej5Lgib6b0Fc6/W8u1YAIBs52QQTu7rVFP1Y
         TEpQdpKBkj0r66o2ZNujYbLWddxWtfFlzTRjEqYh3K4T0+u5FYeRe1QCtZymcEnZ0eST
         BbcA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758656969; x=1759261769;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=vnxE4u813tTassD+IlSMpPmZoiz/24DQ8ztGxsq1aZA=;
        b=O+vkjZ8ch/Kh5mtlQ+fK6/WwH5Z6RcWd6z0vJKGgE21f3FpZMi9DQR0MJNwJVIpm7y
         3cibDHYbAeIVLTqgpSRC0hwg1D9GJfRAEuFYccFo5ohg6BPCIZ20Eo3Kl+d6Qkvf8mrO
         tGUsQ0UdLhqi809lFjLDL+Xv4SlfsaLfmS5Q9inuQ/aRw5BikDq2PnD0D425oMKo+OFG
         fo62dWGoNrrBU+18V3pEU6K+6BRDLhAzfgkBkxlXgdmtfKLDpA2HFcq9m9twi7WrUDHC
         S8D782Qahh5svr5A4Gvv2xU3zYL6ZlIgnB0VQ8Gxn62TbSukeHfBru3k0BqdmYEnXp7N
         g6VA==
X-Forwarded-Encrypted: i=2; AJvYcCWaKJfbEphy5aXXojdcpjcq+UC6jO4FpKQdlyO61H59SI9tebvIO7B3vlOSaJJM40UXzJcjpQ==@lfdr.de
X-Gm-Message-State: AOJu0Yxscl6zuctdIZHJyaXbdOCGSsX7VnLxA2FH8oB/WPio0hsyeCRT
	GrGTZK75ZngF2abkZ7RpqIT6tLzyiM7LbSPNqlrEA4F5ZGX3HJfPDKJO
X-Google-Smtp-Source: AGHT+IE+Hx0XkHZHvAQc816Dzp4LZew9+jjNLAgc8RD9IdnKp1IKyx5mSvQ0rjNyxSPEE0hrVv03Wg==
X-Received: by 2002:a05:620a:318f:b0:80b:b42f:aaec with SMTP id af79cd13be357-8517184e8c1mr409336585a.69.1758656969199;
        Tue, 23 Sep 2025 12:49:29 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd7UwsEaBJ+TM5oKMFv8q/fBsHg2R2oTn5c3a/9iW2/E5w==
Received: by 2002:ac8:580e:0:b0:4b0:9935:4645 with SMTP id d75a77b69052e-4bdfb5af4edls95434651cf.0.-pod-prod-05-us;
 Tue, 23 Sep 2025 12:49:28 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCV2cZ7skw0X66RFfd8O+289jYAD32YFl5kuqrpq1AUlppQsueoKq6cG2p0LXw4yFsxWmERBQxj0X2w=@googlegroups.com
X-Received: by 2002:a05:620a:6f0c:b0:852:1df5:614 with SMTP id af79cd13be357-8521df5083fmr394521685a.58.1758656967902;
        Tue, 23 Sep 2025 12:49:27 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1758656967; cv=none;
        d=google.com; s=arc-20240605;
        b=HUOSBuSa/FFSfU5mhbNa4KOezcVFy3YT+OWKfle1aUYungaw/Obo7yGG4I7b0MFOM8
         Eo9WKATnMhdW0iauetNxA7CmRNB69KbArs4gzUZZXjf4Dl/LPWdNOcwJMVHbWkYlFTIt
         gsxpGp6oU8Wh+ETIKCZvy7ygh8w2auiOPnuDms/B1tHWJgKZwduyyxL7sZaoUETTZjBZ
         h6UUBPM2dXkTrBZrxO2gyToOsNquq0+EsVboR70YVVyBFch3OehvVbjCNxB5xq0EznhM
         w4IreYY99ZbuHARvLRxBQpu47c4LKP8shP6XUNdSPabQ8ofAjUv3EJzUzAWyOpBTL8zP
         xvQw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=7gv2WzZ+nMC2bdsHIbBsKOEQPNt5h99Cw1wDY0M9npo=;
        fh=Sr9dVf1ODb+dS4WtdFn8iEDZgsrhT9aFWFJcv29/uu8=;
        b=S1S9O42ELxtXdRSiqKeaYKejBsJyp/qRfKXWnTQ8cVqaSH5Knft98KgGJc2jvyoua4
         +ICcP8vAzIH/qeZExo+gn7ESBJGrCbHd8OKhlNx8XyD1nlKWPJ5YxaCrnEUFSxkSKJFv
         8ekPozwv6CF/HhY5fgK7T5uqXn+A1ES8LgbGT3AfaNF9z86kgxyAQYZhcFROYCBDX24I
         eKNxb04OdmFlwYDBtfW5sDBfi2wX2olTSTPriMtYd5pxv0VLN7KUPzcEabUdpJakbo2o
         Me1tjoQqPzgwI5Qf/f2bv8FIJNFnBUq1YQEIxJzkPC2+fnbsk+wrXWN0TfhkfP6DXQbx
         jIQQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=PvIaGTqH;
       spf=pass (google.com: domain of nathan@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) smtp.mailfrom=nathan@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from tor.source.kernel.org (tor.source.kernel.org. [2600:3c04:e001:324:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id d75a77b69052e-4bda02b2f2asi1524781cf.2.2025.09.23.12.49.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 23 Sep 2025 12:49:27 -0700 (PDT)
Received-SPF: pass (google.com: domain of nathan@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) client-ip=2600:3c04:e001:324:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by tor.source.kernel.org (Postfix) with ESMTP id 41C246025A;
	Tue, 23 Sep 2025 19:49:27 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 2C0DAC4CEF5;
	Tue, 23 Sep 2025 19:49:17 +0000 (UTC)
Date: Tue, 23 Sep 2025 12:49:15 -0700
From: "'Nathan Chancellor' via kasan-dev" <kasan-dev@googlegroups.com>
To: Marco Elver <elver@google.com>
Cc: Christoph Hellwig <hch@lst.de>, Peter Zijlstra <peterz@infradead.org>,
	Boqun Feng <boqun.feng@gmail.com>, Ingo Molnar <mingo@kernel.org>,
	Will Deacon <will@kernel.org>,
	"David S. Miller" <davem@davemloft.net>,
	Luc Van Oostenryck <luc.vanoostenryck@gmail.com>,
	"Paul E. McKenney" <paulmck@kernel.org>,
	Alexander Potapenko <glider@google.com>,
	Arnd Bergmann <arnd@arndb.de>, Bart Van Assche <bvanassche@acm.org>,
	Bill Wendling <morbo@google.com>,
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
Message-ID: <20250923194915.GA2127565@ax162>
References: <20250918140451.1289454-1-elver@google.com>
 <20250918141511.GA30263@lst.de>
 <20250918174555.GA3366400@ax162>
 <20250919140803.GA23745@lst.de>
 <20250919140954.GA24160@lst.de>
 <aNEX46WJh2IWhVUc@elver.google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <aNEX46WJh2IWhVUc@elver.google.com>
X-Original-Sender: nathan@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=PvIaGTqH;       spf=pass
 (google.com: domain of nathan@kernel.org designates 2600:3c04:e001:324:0:1991:8:25
 as permitted sender) smtp.mailfrom=nathan@kernel.org;       dmarc=pass
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

On Mon, Sep 22, 2025 at 11:33:23AM +0200, Marco Elver wrote:
> [1] https://github.com/llvm/llvm-project/pull/159921

Now that this is merged, I have pushed an updated snapshot for x86_64:

https://mirrors.edge.kernel.org/pub/tools/llvm/files/prerelease/llvm-22.0.0-ca2e8fc928ad103f46ca9f827e147c43db3a5c47-20250923-185804-x86_64.tar.xz

Cheers,
Nathan

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250923194915.GA2127565%40ax162.
