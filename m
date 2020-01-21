Return-Path: <kasan-dev+bncBAABBVURTTYQKGQEYG4HTTA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53b.google.com (mail-pg1-x53b.google.com [IPv6:2607:f8b0:4864:20::53b])
	by mail.lfdr.de (Postfix) with ESMTPS id 67797143F4E
	for <lists+kasan-dev@lfdr.de>; Tue, 21 Jan 2020 15:21:11 +0100 (CET)
Received: by mail-pg1-x53b.google.com with SMTP id w21sf1612632pgf.19
        for <lists+kasan-dev@lfdr.de>; Tue, 21 Jan 2020 06:21:11 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1579616470; cv=pass;
        d=google.com; s=arc-20160816;
        b=tY43lAeb0mJ+nT9/35nSxGnuYKFR7aWwr0hQNSJGJvORULixF29sv3An2brf3Zn10p
         hAFE+c7jDcuNwdMSdTtY9q9dJQbDiQkzfUiiBab0rvhjc5D8uMUJK/kPq99sPQJfxXqx
         Y7OPBwYWFDQh0d6PoNVo45IVZ3VWCjABItpDPEmSa0Q/itir6v1A4sxzBJJrimXJgzQM
         JaoaTMKlCVJanGJjktB5pS2g2Nlb6kwlP8AQGf53chJGGmNcShLkzGI/cik9QMomSl1S
         1q1fUyrotXXWFwuc920PHVnfB2rpMZES3Vw6rpLtXlM83c1t1ptkgBnBRq/afFoBGy+H
         7vUw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:reply-to:message-id
         :subject:cc:to:from:date:sender:dkim-signature;
        bh=sJ2nNOjeOzO3tZtC3LJF6+oIWV8TAJwBbTEk25H68O8=;
        b=xSlXy+g4nPep/ZDUZhIsE7ttdCfRjR7ngJBy6YbZaLHfNCO2Djp6SZUnLwMI2jWhK4
         Fy4SYDzZZhXLFxY9yPufNhxhQWzN8Y/gP1sOrg8NOCdtg8ufF/DDulMizoPn6ndOlzhj
         2OMOALv1rVCIiS8c33yThEj5MtI7T7HkORL6/xSi5rtwGqF9KKxBDv3Kb6T89q3o0bNS
         YjwEaEKTvD4u87V3Y9Bp9GEvy/y/gGeHDOhtOpb+FoHY9Bf/pIT7FHKEA3EwP61XZaGe
         BDHsh8Mvt2tYhJ0Fm66G82o9HvtUKRv9TY8O1S5aoCMkg0ZlL9oOhXFI//JdavspEb73
         ACRg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=wQU1jn0f;
       spf=pass (google.com: domain of srs0=adgr=3k=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=ADgR=3K=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=sJ2nNOjeOzO3tZtC3LJF6+oIWV8TAJwBbTEk25H68O8=;
        b=EQ6LJG4t5tkpQ2QR4RfY/Ilohy4F5YOKsauaoa667Sv/D657bOtNoypQQ5oS9na53i
         UzA25eJdQc2E7pJKiJyFexHWERMRaJL7JvGuMBBTvN5/kSXGoNeppk2uSZObSBUg9qCq
         EYh+Pyos5YAqcLhXtspvfWAEK0oblUbenuHybu3a2J+zT7qSNSWRozTdkkBI+g2Qek6u
         CZcnyyJOIDGlMC+a9omNzM7K6gtucnnfuzfKh8pZuRbc2nhs8SxuSZ5tsqwv/oAyy45x
         NVHsmDp9J9X1eXa/WYOkLfz9Eon/Djhrm07WJxqUdDa6byEDsM8eVPAwdPjXgsS+BRM/
         M3hA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition:in-reply-to
         :user-agent:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=sJ2nNOjeOzO3tZtC3LJF6+oIWV8TAJwBbTEk25H68O8=;
        b=aAPJ+4cF2d2PxkPVCadm+dpLSch6T42qiP5F9IDQbGtTdnM1qaNLmbWmOWDOcG6pjo
         D762daMqFhy0HnyOa4j56bKFbIUi05orxHZsslKdBLAsei67bBsaxrEHb7D0wUpHT+mF
         azzqjoTQfwVIF6ZQcV28ftiX/Ocz8zgT/cQq+f2KZVCSNZmRe7YGBKvucxHLIVcybRhL
         LsD0SlY3ddFbJJbl9vAnFlzYibqW+VOesqFFztSJoAhk0fMpbMFKX9i4d4vVf39j0GzH
         dxvvKBK7qPSJENra+76A0vaGBP4xET4nlZxBmelgOUQeUJPqrpp3xmJuicio4nIIz/rT
         7HOw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAU1nSEgM2Vehhi4PzZjCAx1wugBZt2z9Lxu/bGibNmlj1eaqfkm
	QxXbSzxSiroYjAM4K+b88EA=
X-Google-Smtp-Source: APXvYqwTO4yQuiYADf4pYwsI6FM5gCpyRNWqp3LM7D3KelnbN4xBsBoQaHfDyeL41BJOkViiqq5GyQ==
X-Received: by 2002:a63:1344:: with SMTP id 4mr5932486pgt.0.1579616470139;
        Tue, 21 Jan 2020 06:21:10 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:b26:: with SMTP id 35ls1262488pjq.1.gmail; Tue, 21
 Jan 2020 06:21:09 -0800 (PST)
X-Received: by 2002:a17:90b:147:: with SMTP id em7mr5759017pjb.49.1579616469823;
        Tue, 21 Jan 2020 06:21:09 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1579616469; cv=none;
        d=google.com; s=arc-20160816;
        b=VdF0NodaPOB5RzIG/scYT6i9eZx2bLghqXR+kUMDTZcTR1okXVyBkA03thBMweFyNR
         nWo/z3Xu4zyOfOkzZUgfY4sD+kvdEbhrunoQqIjxzlan4k6H7eEzlDa9WugD0E52RJcK
         M2sPHaryLncCErsiHdDOd+Pm33mxOhXhL9UiS2B+dFhKd+mxrS/fg1MKjoQ/Ugko/o2e
         vjxn/h/KQlx2md/nnCCVDJLhLf209UcU4StUw9zDsWKaL3+Uls52AW2H7wgQ8JVVqB0i
         SnNY4tVCDWCuq+qf7q1wsoaB1KtD8VKL0tGZXqmJQTWBe9+glsV9Mh9+oTpkmqNkStH1
         Lclw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :reply-to:message-id:subject:cc:to:from:date:dkim-signature;
        bh=SVgC+jMYvEM5kzmEulk/F8o/dTw93obdIAmm3WHGNtc=;
        b=jWIQBcYViYTNi+GH7VXoHGMpCsSLdDFqkvTXY4T5nBlJd5QRPT8hHS9Y02UKSRqrVL
         cEeoDqfo1moMRUd51UnmnMEBtUOI/u9sjufTR8vhPa9Z8HQXX9JFkmKEVNVjxcDT6D29
         ccKAa8cLUHR+B+yiV18l/a+kQ4JjZGMetEE5Bc4K7eCykqQDbijQYjrYkY/daMZoaT+e
         e6NC6ogQrUYpdKLkW0n4nS3x0YFhSML2lm+Y4K/W+4AjEUiAqW3BMdy+71Ov6sbglwbO
         JnP5dK48OhEVvwCWePTtWs6AmdwKFg9lRtx7QHnTPqDzjcybw9HC3gRoKnYPSb9h6FuH
         Rirg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=wQU1jn0f;
       spf=pass (google.com: domain of srs0=adgr=3k=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=ADgR=3K=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id h19si1753615pfn.1.2020.01.21.06.21.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 21 Jan 2020 06:21:09 -0800 (PST)
Received-SPF: pass (google.com: domain of srs0=adgr=3k=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (50-39-105-78.bvtn.or.frontiernet.net [50.39.105.78])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 80C6B217F4;
	Tue, 21 Jan 2020 14:21:09 +0000 (UTC)
Received: by paulmck-ThinkPad-P72.home (Postfix, from userid 1000)
	id 54B7F35227E4; Tue, 21 Jan 2020 06:21:09 -0800 (PST)
Date: Tue, 21 Jan 2020 06:21:09 -0800
From: "Paul E. McKenney" <paulmck@kernel.org>
To: Peter Zijlstra <peterz@infradead.org>
Cc: Marco Elver <elver@google.com>, andreyknvl@google.com,
	glider@google.com, dvyukov@google.com, kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org, mark.rutland@arm.com, will@kernel.org,
	boqun.feng@gmail.com, arnd@arndb.de, viro@zeniv.linux.org.uk,
	christophe.leroy@c-s.fr, dja@axtens.net, mpe@ellerman.id.au,
	rostedt@goodmis.org, mhiramat@kernel.org, mingo@kernel.org,
	christian.brauner@ubuntu.com, daniel@iogearbox.net,
	cyphar@cyphar.com, keescook@chromium.org,
	linux-arch@vger.kernel.org
Subject: Re: [PATCH 3/5] asm-generic, kcsan: Add KCSAN instrumentation for
 bitops
Message-ID: <20200121142109.GQ2935@paulmck-ThinkPad-P72>
Reply-To: paulmck@kernel.org
References: <20200120141927.114373-1-elver@google.com>
 <20200120141927.114373-3-elver@google.com>
 <20200120144048.GB14914@hirez.programming.kicks-ass.net>
 <20200120162725.GE2935@paulmck-ThinkPad-P72>
 <20200120165223.GC14914@hirez.programming.kicks-ass.net>
 <20200120202359.GF2935@paulmck-ThinkPad-P72>
 <20200121091501.GF14914@hirez.programming.kicks-ass.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20200121091501.GF14914@hirez.programming.kicks-ass.net>
User-Agent: Mutt/1.9.4 (2018-02-28)
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=wQU1jn0f;       spf=pass
 (google.com: domain of srs0=adgr=3k=paulmck-thinkpad-p72.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=ADgR=3K=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
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

On Tue, Jan 21, 2020 at 10:15:01AM +0100, Peter Zijlstra wrote:
> On Mon, Jan 20, 2020 at 12:23:59PM -0800, Paul E. McKenney wrote:
> > We also don't have __atomic_read() and __atomic_set(), yet atomic_read()
> > and atomic_set() are considered to be non-racy, right?
> 
> What is racy? :-) You can make data races with atomic_{read,set}() just
> fine.

Like "fairness", lots of definitions of "racy".  ;-)

> Anyway, traditionally we call the read-modify-write stuff atomic, not
> the trivial load-store stuff. The only reason we care about the
> load-store stuff in the first place is because C compilers are shit.
> 
> atomic_read() / test_bit() are just a load, all we need is the C
> compiler not to be an ass and split it. Yes, we've invented the term
> single-copy atomicity for that, but that doesn't make it more or less of
> a load.
> 
> And exactly because it is just a load, there is no __test_bit(), which
> would be the exact same load.

Very good!  Shouldn't KCSAN then define test_bit() as non-racy just as
for atomic_read()?

							Thanx, Paul

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200121142109.GQ2935%40paulmck-ThinkPad-P72.
