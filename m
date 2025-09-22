Return-Path: <kasan-dev+bncBDUNBGN3R4KRBUEGY3DAMGQELNWZ54Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x239.google.com (mail-lj1-x239.google.com [IPv6:2a00:1450:4864:20::239])
	by mail.lfdr.de (Postfix) with ESMTPS id 7B014B925AF
	for <lists+kasan-dev@lfdr.de>; Mon, 22 Sep 2025 19:11:46 +0200 (CEST)
Received: by mail-lj1-x239.google.com with SMTP id 38308e7fff4ca-36ac2323417sf7918131fa.1
        for <lists+kasan-dev@lfdr.de>; Mon, 22 Sep 2025 10:11:46 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758561106; cv=pass;
        d=google.com; s=arc-20240605;
        b=k7koDhtm7KUUOXdg4GMrlmMhEJpPkVYQD1RKihy/LIe8mL15/MZPMHJ9mPM/N4/Tf4
         cGpHZA6hW9Suljn8DAI0/BZheXW4cVh+qDPcY+oNcUFbXVYQFHxY1hJ7H6eexqPngDfw
         aaGr9OOkN/ymoX9u2j9zWNIS3fYM54Jn2Byojv+SAXpWWahy5NjaxmloAR4pgBdG49MG
         QUgB0xq08Cqin+4ZFMDKY62nt0eIWlQgwfYC3Lu620K4sdSV4haCjSO2KDPEQ0aIigPk
         nMVukENjEpDSkG8Bl+y6DPKOxg1HbZvWok5Te0uxMj3vRV3Hw1vEByk5cY5/4/0EaAyD
         mTvQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=T5pAjtiBlKzSvv1YKXjiZy1MuN0dOxc/N3QYb0QqZmQ=;
        fh=p4DpCwZ2xXkFxnxaETiDFM5tfabbm4Nw7gEKX0Sz9g0=;
        b=hKbtXbo5gdVW1iBI3021/T/B0nXlQF8edc2wQKlgi6684iaxQcxepG85oWJQvdRJvj
         GbSnRymO53lItvUOzf7qfvuPHtyv5yfSa919hURWxNifpgRQxuUQ+L35eLYjdAhDE2dY
         0QNPRUqjQB7JS9fBGULIjBIAX8eNknkgGQ54LMOuOFKS0Eu/YVNDMr+LIA7SHhVQzKT4
         0I8cWkkv1AkM9PxRPUUi7Rk6B/3ftLkd4n1+8HV4SN+oxFDHrCCHnl41hHTw9tBcoy+f
         1G2p3isxrDl0rcHx3ONRqXKjAN0p+bE4wR7E0h324hqR1MjdBSfvEI0hKYqWOrYPfqKG
         w8pQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of hch@lst.de designates 213.95.11.211 as permitted sender) smtp.mailfrom=hch@lst.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=lst.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758561106; x=1759165906; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:user-agent:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=T5pAjtiBlKzSvv1YKXjiZy1MuN0dOxc/N3QYb0QqZmQ=;
        b=UKWNiG4jM1edOaaNYZ5dxzFxR0Ay/YncJwINcRnTnzzlP2RizYGuT+rDs1gqtc11/w
         OK762E6/BHXPosMyfaTmOchBrA/5ZjUaatLmLNATbeD/RbRXx5LpkeAGZLTCJ6BKJN+8
         bJqqqaCToiNUk4wG4U2A6tn/gRPX/gwS7I1+DnHwOFPODC4kwT1NoG1nalJNQ50XDc6L
         B3t6P7EspYaK1gwz7TtCCkg6ud1PLfMk4EMhfBKsrsAWN+m9dKGPMCkbYnWjMDpzZws3
         /mgE3I2ajks23EsRZ7t12KH61eL7TIZjrDt/6O4hOZutaR+VUTihClBZhMXT+ZIQnxNF
         uHMA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758561106; x=1759165906;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:x-beenthere:x-gm-message-state:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=T5pAjtiBlKzSvv1YKXjiZy1MuN0dOxc/N3QYb0QqZmQ=;
        b=e636SxjFLJo+XONLPKlqDEdcSvfGqRgTEcad0sjppMHbMgX8PdARC2wHHv42PXPABU
         6RZSnEqklJyT9rVhvnVktMpP+LRAGXMkK2w+TttqncD6KoBJuo18ffBZQDobiGeuYyp+
         67hrirgCR1TMNd6KykaxCbMyqGanYiT9fyOgOwDEkbFcfrfpvID0ZaMXm74B4OfikP28
         Br1yshmLdBXo6mejt+YHyyol/nDXcyvllruydOvA0Y1PCZP/dsGFrwxXJNrEtNQ5Aw5Q
         JYIshSMKaSYotbTT1WtxmvmegYjRZR4qxydM0ovO1+dKFVu7SCfOyj/+P+sNhM4IkItl
         bcHg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXZHAWYPl6YsFmlZUcVmfIkXcxfVEYsBKlx73OA5JyfFUtqiJ+0pqiSls2GRuA4y/NRlAjUKQ==@lfdr.de
X-Gm-Message-State: AOJu0YyMRnZ4tJCeQH4VeHqcy+OBigPDHG3iw7KE33xFIjLTVxztSJeo
	/1LA7YJcz0Zuk1FYA+0Hhh8dTpzkM0bLj0FeEaYdPyg1clOLoxpPMquh
X-Google-Smtp-Source: AGHT+IGLUVTn8G8C8oG8J42utYPsOIpq7rE5WTEtlc0/OzIeXiugYEOh0T7Ygax9i0RGOxg5LlX+wA==
X-Received: by 2002:a2e:a547:0:b0:36a:cdb0:c1f3 with SMTP id 38308e7fff4ca-36acdb0c432mr23318451fa.29.1758561105250;
        Mon, 22 Sep 2025 10:11:45 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd4998g2jI/EjvPAr0tPq2X1+HEoRccsfBV65Uw3E3tgWQ==
Received: by 2002:a05:651c:1195:b0:337:e84b:ebd with SMTP id
 38308e7fff4ca-361c5d7eb7dls5969051fa.0.-pod-prod-07-eu; Mon, 22 Sep 2025
 10:11:42 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUwNdqB0W8ebGIYhw/7d/7j1Tsg2IIKFwYuHHF7XIS5eS9fYMvbpsHqSwXe106JB+slOlUnAyiAU5c=@googlegroups.com
X-Received: by 2002:a2e:bea2:0:b0:36b:1a89:36b0 with SMTP id 38308e7fff4ca-36b1a893b9amr15151841fa.10.1758561101995;
        Mon, 22 Sep 2025 10:11:41 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1758561101; cv=none;
        d=google.com; s=arc-20240605;
        b=iqM8EVeC0wkq7B16CmNiYf4xEBZkZrnjOUBjnMX4soIKbkmzfIgw412VsNVfMi5N2L
         hEN77n9EinRVfalGiKLE+DUasm9uWra7sdhR8iutYYJedpTJVJYoSmuE2v2WOyivMDRh
         nfyadpmiL/Y+DVpq7FdiAPiC35SMhGxCo2Tf5d1AqMnqClqyYnvYr95Qw5oL8d9u3Z7x
         zyRFcoYZnnwr9cJl9FFeBm8Ln939WzMAEuR1GbKHq2MPl0htnsyrQvVRUvF2kWITlGVW
         NGIU5ej6bYtsUxRuCVHrDUhIiXtK7a2VETxNjbBZXRobV6Ih0LcMQuZGds/Deo4QAqtJ
         iobQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=AzW1D6cu4bgVFbuNUR4Gt+p4oEdRJ1ELKVbXdnqrKQk=;
        fh=Xh6wg5Q0/UTyFLqoMOIQtxlhPOb5yibgb80e0u0F6y8=;
        b=FyF41I0rWGrKlqOiOHnWEvfZujTdTq7YyvsgnN+/xd4lGMN4c2Ibq359d3LYTdMhWL
         azPkco8fRf8tR8giSqjwJ+M/DHSHg0zG0GzjQ8/yEq+VAS4/5g95CbiJVd49oO1SGzYK
         BzEQ8PCiCfSsxBGlia2awj7MiA3UCAsLMn86O8/8K4g7YC1nTSbLW9kBAav3RAt9JKTV
         1CA29y7EwhubKEhOBxhYegysPK5dyZQaFw0m4xhcDgoLiDutofKv7HlH4twR2VGFOrGM
         HyQuGWn9ND8i9zjr76DKyY6YnHCGiuOoOnSjl67IA5yFsJ/WPU8rX8FjYDdfyAil5eDN
         Qrzw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of hch@lst.de designates 213.95.11.211 as permitted sender) smtp.mailfrom=hch@lst.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=lst.de
Received: from verein.lst.de (verein.lst.de. [213.95.11.211])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-361a62c8fe9si2200641fa.4.2025.09.22.10.11.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 22 Sep 2025 10:11:41 -0700 (PDT)
Received-SPF: pass (google.com: domain of hch@lst.de designates 213.95.11.211 as permitted sender) client-ip=213.95.11.211;
Received: by verein.lst.de (Postfix, from userid 2407)
	id 11211227AAF; Mon, 22 Sep 2025 19:11:37 +0200 (CEST)
Date: Mon, 22 Sep 2025 19:11:36 +0200
From: Christoph Hellwig <hch@lst.de>
To: Marco Elver <elver@google.com>
Cc: Christoph Hellwig <hch@lst.de>, Nathan Chancellor <nathan@kernel.org>,
	Peter Zijlstra <peterz@infradead.org>,
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
Subject: Re: [PATCH v3 00/35] Compiler-Based Capability- and
 Locking-Analysis
Message-ID: <20250922171136.GA12668@lst.de>
References: <20250918140451.1289454-1-elver@google.com> <20250918141511.GA30263@lst.de> <20250918174555.GA3366400@ax162> <20250919140803.GA23745@lst.de> <20250919140954.GA24160@lst.de> <aNEX46WJh2IWhVUc@elver.google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <aNEX46WJh2IWhVUc@elver.google.com>
User-Agent: Mutt/1.5.17 (2007-11-01)
X-Original-Sender: hch@lst.de
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of hch@lst.de designates 213.95.11.211 as permitted
 sender) smtp.mailfrom=hch@lst.de;       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=lst.de
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
> I gave this a try, and with the below patch and the Clang fix [1],
> fs/xfs compiles cleanly. I think the fundamental limitation are the
> conditional locking wrappers. I suspect it's possible to do better than
> disabling the analysis here, by overapproximating the lock set taken
> (like you did elsewhere), so that at least the callers are checked, but
> when I tried it showed lots of callers need annotating as well, so I
> gave up at that point. Still, it might be better than no checking at
> all.

I guess this at least allows us to work with the analysis, even if it 
drops coverage for one of the most important locks.  I guess you also
have CONFIG_XFS_QUOTA disabled as that would lead to similar warnings,
and also currently has the lock the object on return if it's not a
NULL return case?  I now have a local series to remove that instance,
but I've seen that pattern elsewhere in the kernel code.

Besides the conditional locking these two also do another thing that
is nasty to the analysis, the locked state can be attached to a
transaction and unlocked at transaction commit.  Not sure how to best
model that.

> [1] https://github.com/llvm/llvm-project/pull/159921

Thanks for all the work!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250922171136.GA12668%40lst.de.
