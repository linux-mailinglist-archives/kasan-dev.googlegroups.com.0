Return-Path: <kasan-dev+bncBAABBXENTLXQKGQEWKYIGDI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63e.google.com (mail-pl1-x63e.google.com [IPv6:2607:f8b0:4864:20::63e])
	by mail.lfdr.de (Postfix) with ESMTPS id 6A8E31101B3
	for <lists+kasan-dev@lfdr.de>; Tue,  3 Dec 2019 17:01:34 +0100 (CET)
Received: by mail-pl1-x63e.google.com with SMTP id y8sf1930003plk.16
        for <lists+kasan-dev@lfdr.de>; Tue, 03 Dec 2019 08:01:34 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1575388892; cv=pass;
        d=google.com; s=arc-20160816;
        b=LH67D+rc61UbVcWy7uSHOf4rcXFEEUQsziG68GJxmhKKro9HEYnotnrQlxKasTi50C
         FBOsfORH1asapeuOsp58hN5cOZxy5Zq1GJxQoyVJDtLTOPCgs78kstaUmKB4O/G3E3pm
         ZquAtSgdNpHrYqjfxkE1szdYuhPs87MlLggLRfmRTogbyxK4bk+8QbzY20Ie9TmxgVqP
         rE8GfWF7xNVfGawJqUAsJ1sMvc2bMKs5o4lz4c/Gw+7wiZpJxMDdgEyJy4Ff96cCoFwZ
         c6D9hs7QgB0oyp7sY55hIcr4mgJn/eDt4n6oToHaScPQkUVaE4OpA0jPrv+RLPw/DiPm
         KozA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:reply-to:message-id
         :subject:cc:to:from:date:sender:dkim-signature;
        bh=3XKo3gG7507KXnrnNv7TjxkGvgftLk1+cl3HqaHNTlc=;
        b=t7hW+QAWejkeq+er6QnFTd+hQCS9//1G9PEBLzYOPsU6n5i9BpFlqVRaR0aMPLvB3R
         D9O0F6hT0UcMDhUVW4CXQVjzXAYikeb2ilEvtAXRKABQHOppOmcv129CcnhImYI0Lpkh
         oHzA8gDr6BgHqnRblge6MFaoGGZG7QYH5QMfgzogsPfby3SDbm7I56Ue+tPssM1BPHSn
         02HR0kfMaHiEjLeHuljWLHgA5soKZui0p1h9cl6Oa4oyj5hh+qhq+I9/LVQrJH9w2pN9
         UykIXDij5CIZEIML/JErOz294FETuZMQqiifeFZ+04WyroHM/6aR1xaAdZ2UFaB25yNi
         v7ag==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=H3l95Tad;
       spf=pass (google.com: domain of srs0=2qc+=zz=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=2Qc+=ZZ=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=3XKo3gG7507KXnrnNv7TjxkGvgftLk1+cl3HqaHNTlc=;
        b=SWCak92UZGXKUO33OOelacNzyBeuLw1LPHJBx2+hAe8y3a2fc/boZxK2wAhsgytrC8
         U2WEWex+/bXc1RPgvexqQY3UzWuSwgwUEafjrrmHLrcpKMXEOzaPC1mJCCKUajYB0HET
         dhAYeWHtkUyRm1flCM85zkhXgQ2x4xfxqTE2frFXnC/nhSeslP0zuwrEIVmBjgY+c3Uu
         kdHC6fQUmyCg4o4KUdAvRvWyUvqKzzoM2f0ly812i8HXklr/veTHKaPw0j4lzFGsBSRI
         sY1iaXGC9fKaTHrYQG0f2ysTQ6i21MM12uCiTPBoWcRamQvqE5lQRc331RfnR/jWR5jh
         o7Dw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition:in-reply-to
         :user-agent:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=3XKo3gG7507KXnrnNv7TjxkGvgftLk1+cl3HqaHNTlc=;
        b=R1Hso0AaqfRJWNajo8i14SFNoYTQjvvq4hN5EvPfk0+l9T4d47ALLVSTWrEwFFePkE
         kraWa2nsIiuC/PwppONCdKDcWMrNQJ9pUTLlSY8frIVxqDzMW17v7Vk2DLITWhyobpL9
         0jAUv1DSh6i4naGGdzQpCGozs7d1RU4ctdHHLRuIKLfHAkx3WTuQNryrTL9nO5Fu9VX8
         l10cHHIgl4J6/XY/EWhK91nva3ALdl1/OybGlQ0qCVoYA4UZNWf3uvk4n0ffWAoJB73h
         HfsFGsdjaCgZQeqwf+NRlQiUaIHg+hw6IGmW0pMUQuWk5+MddUGxlYTwAC+oYKeo9p7y
         gMWA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAUUBYG+I8dNmZWeB3v3U1Jg6bAaYy4eNxef/2mZj37Mi8YSj3BP
	z41SuuA7cccj8/3De2HSjqQ=
X-Google-Smtp-Source: APXvYqxa1MbV6YIFr1ZrSUn3lbfP4+tUFfYYUIe0PgRvSCekwugFaWngbvp9/9aKl99Pt5sLTvK0YA==
X-Received: by 2002:a63:181a:: with SMTP id y26mr6236414pgl.423.1575388892508;
        Tue, 03 Dec 2019 08:01:32 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:fe5:: with SMTP id 92ls891493pjz.5.canary-gmail;
 Tue, 03 Dec 2019 08:01:32 -0800 (PST)
X-Received: by 2002:a17:902:542:: with SMTP id 60mr5452471plf.207.1575388892084;
        Tue, 03 Dec 2019 08:01:32 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1575388892; cv=none;
        d=google.com; s=arc-20160816;
        b=VUbeUaxWjW7ysMyqb7U6W9x6+/OtspwCqQZxe6j/2dAcIS2YU1mQ0/FNqSTAqC7+1k
         Cvjv7dVwQbwqRFpwVKpxcNVbj1eAUhgYW426bU7vrolBF5YDuUmyGjqZcso6H0aZb+M2
         wR4TjRuRByxaXuEpaz+SDsilv7J6PF6/EDunSLFxrTcBcbteHDQ1AQQP+okwfwJ1NvsP
         qAyRwUv/6DNNyvQsPuYMkFhI/oyCqq1Tyyy24662eDcuqjUZKjjF8irB4nFYoFtkQCRz
         M6Z+wQE1s1OFHhd3RUy0Gasci66AZLTMS9t/926nldibk2XUVX1PUZ6hllOt9J3OV63D
         dUzA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :reply-to:message-id:subject:cc:to:from:date:dkim-signature;
        bh=2UV/W5HHbnQCMtlWrusg/hTvmmLUyOcSU5uuJe1XBvY=;
        b=GWH6IdnV+8AuVuM+H/FXPsKjyqB1yg2vo7udu0RJvvu9G7g56vuypgv+IvD5jIz6Rq
         uCt8Uk832gYonmsowMQ9PXAXFXT3kCrj9pEcbeCwyZmrPl6xBif22YnpodIeTW3rNmJx
         VNzFkHlkrKO9fo8c4BHABAm4uORXkekR+gH4OTJO+xzXXS3FCTQfgHowJlReMePgYCbx
         pbRbsu27o5MdxYWzRh/CkS9BXlP3Ho3KE/Rx97aJMvtJFy1MIbGhIaUWcx1zxLZJUQ6r
         lUmFHEwtB/DiQlXVeaNL4c+gG57mvGi5oRUDP1Ak/nC5VPrFP6PKZv5A1g7EFrAmVSMD
         tHyw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=H3l95Tad;
       spf=pass (google.com: domain of srs0=2qc+=zz=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=2Qc+=ZZ=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id n2si280025pgq.0.2019.12.03.08.01.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 03 Dec 2019 08:01:32 -0800 (PST)
Received-SPF: pass (google.com: domain of srs0=2qc+=zz=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (50-39-105-78.bvtn.or.frontiernet.net [50.39.105.78])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 3D6C42068E;
	Tue,  3 Dec 2019 16:01:30 +0000 (UTC)
Received: by paulmck-ThinkPad-P72.home (Postfix, from userid 1000)
	id 1D2EF3522780; Tue,  3 Dec 2019 08:01:28 -0800 (PST)
Date: Tue, 3 Dec 2019 08:01:28 -0800
From: "Paul E. McKenney" <paulmck@kernel.org>
To: Randy Dunlap <rdunlap@infradead.org>
Cc: Marco Elver <elver@google.com>, mark.rutland@arm.com,
	linux-kernel@vger.kernel.org, will@kernel.org, peterz@infradead.org,
	boqun.feng@gmail.com, arnd@arndb.de, dvyukov@google.com,
	linux-arch@vger.kernel.org, kasan-dev@googlegroups.com
Subject: Re: [PATCH v3 3/3] kcsan: Prefer __always_inline for fast-path
Message-ID: <20191203160128.GC2889@paulmck-ThinkPad-P72>
Reply-To: paulmck@kernel.org
References: <20191126140406.164870-1-elver@google.com>
 <20191126140406.164870-3-elver@google.com>
 <00ee3b40-0e37-c9ac-3209-d07b233a0c1d@infradead.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <00ee3b40-0e37-c9ac-3209-d07b233a0c1d@infradead.org>
User-Agent: Mutt/1.9.4 (2018-02-28)
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=H3l95Tad;       spf=pass
 (google.com: domain of srs0=2qc+=zz=paulmck-thinkpad-p72.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=2Qc+=ZZ=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
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

On Mon, Dec 02, 2019 at 09:30:22PM -0800, Randy Dunlap wrote:
> On 11/26/19 6:04 AM, Marco Elver wrote:
> > Prefer __always_inline for fast-path functions that are called outside
> > of user_access_save, to avoid generating UACCESS warnings when
> > optimizing for size (CC_OPTIMIZE_FOR_SIZE). It will also avoid future
> > surprises with compiler versions that change the inlining heuristic even
> > when optimizing for performance.
> > 
> > Report: http://lkml.kernel.org/r/58708908-84a0-0a81-a836-ad97e33dbb62@infradead.org
> > Reported-by: Randy Dunlap <rdunlap@infradead.org>
> > Signed-off-by: Marco Elver <elver@google.com>
> 
> Acked-by: Randy Dunlap <rdunlap@infradead.org> # build-tested

Thank you, Randy!

							Thanx, Paul

> Thanks.
> 
> > ---
> > Rebased on: locking/kcsan branch of tip tree.
> > ---
> >  kernel/kcsan/atomic.h   |  2 +-
> >  kernel/kcsan/core.c     | 16 +++++++---------
> >  kernel/kcsan/encoding.h | 14 +++++++-------
> >  3 files changed, 15 insertions(+), 17 deletions(-)
> > 
> > diff --git a/kernel/kcsan/atomic.h b/kernel/kcsan/atomic.h
> > index 576e03ddd6a3..a9c193053491 100644
> > --- a/kernel/kcsan/atomic.h
> > +++ b/kernel/kcsan/atomic.h
> > @@ -18,7 +18,7 @@
> >   * than cast to volatile. Eventually, we hope to be able to remove this
> >   * function.
> >   */
> > -static inline bool kcsan_is_atomic(const volatile void *ptr)
> > +static __always_inline bool kcsan_is_atomic(const volatile void *ptr)
> >  {
> >  	/* only jiffies for now */
> >  	return ptr == &jiffies;
> > diff --git a/kernel/kcsan/core.c b/kernel/kcsan/core.c
> > index 3314fc29e236..c616fec639cd 100644
> > --- a/kernel/kcsan/core.c
> > +++ b/kernel/kcsan/core.c
> > @@ -78,10 +78,8 @@ static atomic_long_t watchpoints[CONFIG_KCSAN_NUM_WATCHPOINTS + NUM_SLOTS-1];
> >   */
> >  static DEFINE_PER_CPU(long, kcsan_skip);
> >  
> > -static inline atomic_long_t *find_watchpoint(unsigned long addr,
> > -					     size_t size,
> > -					     bool expect_write,
> > -					     long *encoded_watchpoint)
> > +static __always_inline atomic_long_t *
> > +find_watchpoint(unsigned long addr, size_t size, bool expect_write, long *encoded_watchpoint)
> >  {
> >  	const int slot = watchpoint_slot(addr);
> >  	const unsigned long addr_masked = addr & WATCHPOINT_ADDR_MASK;
> > @@ -146,7 +144,7 @@ insert_watchpoint(unsigned long addr, size_t size, bool is_write)
> >   *	2. the thread that set up the watchpoint already removed it;
> >   *	3. the watchpoint was removed and then re-used.
> >   */
> > -static inline bool
> > +static __always_inline bool
> >  try_consume_watchpoint(atomic_long_t *watchpoint, long encoded_watchpoint)
> >  {
> >  	return atomic_long_try_cmpxchg_relaxed(watchpoint, &encoded_watchpoint, CONSUMED_WATCHPOINT);
> > @@ -160,7 +158,7 @@ static inline bool remove_watchpoint(atomic_long_t *watchpoint)
> >  	return atomic_long_xchg_relaxed(watchpoint, INVALID_WATCHPOINT) != CONSUMED_WATCHPOINT;
> >  }
> >  
> > -static inline struct kcsan_ctx *get_ctx(void)
> > +static __always_inline struct kcsan_ctx *get_ctx(void)
> >  {
> >  	/*
> >  	 * In interrupts, use raw_cpu_ptr to avoid unnecessary checks, that would
> > @@ -169,7 +167,7 @@ static inline struct kcsan_ctx *get_ctx(void)
> >  	return in_task() ? &current->kcsan_ctx : raw_cpu_ptr(&kcsan_cpu_ctx);
> >  }
> >  
> > -static inline bool is_atomic(const volatile void *ptr)
> > +static __always_inline bool is_atomic(const volatile void *ptr)
> >  {
> >  	struct kcsan_ctx *ctx = get_ctx();
> >  
> > @@ -193,7 +191,7 @@ static inline bool is_atomic(const volatile void *ptr)
> >  	return kcsan_is_atomic(ptr);
> >  }
> >  
> > -static inline bool should_watch(const volatile void *ptr, int type)
> > +static __always_inline bool should_watch(const volatile void *ptr, int type)
> >  {
> >  	/*
> >  	 * Never set up watchpoints when memory operations are atomic.
> > @@ -226,7 +224,7 @@ static inline void reset_kcsan_skip(void)
> >  	this_cpu_write(kcsan_skip, skip_count);
> >  }
> >  
> > -static inline bool kcsan_is_enabled(void)
> > +static __always_inline bool kcsan_is_enabled(void)
> >  {
> >  	return READ_ONCE(kcsan_enabled) && get_ctx()->disable_count == 0;
> >  }
> > diff --git a/kernel/kcsan/encoding.h b/kernel/kcsan/encoding.h
> > index b63890e86449..f03562aaf2eb 100644
> > --- a/kernel/kcsan/encoding.h
> > +++ b/kernel/kcsan/encoding.h
> > @@ -59,10 +59,10 @@ encode_watchpoint(unsigned long addr, size_t size, bool is_write)
> >  		      (addr & WATCHPOINT_ADDR_MASK));
> >  }
> >  
> > -static inline bool decode_watchpoint(long watchpoint,
> > -				     unsigned long *addr_masked,
> > -				     size_t *size,
> > -				     bool *is_write)
> > +static __always_inline bool decode_watchpoint(long watchpoint,
> > +					      unsigned long *addr_masked,
> > +					      size_t *size,
> > +					      bool *is_write)
> >  {
> >  	if (watchpoint == INVALID_WATCHPOINT ||
> >  	    watchpoint == CONSUMED_WATCHPOINT)
> > @@ -78,13 +78,13 @@ static inline bool decode_watchpoint(long watchpoint,
> >  /*
> >   * Return watchpoint slot for an address.
> >   */
> > -static inline int watchpoint_slot(unsigned long addr)
> > +static __always_inline int watchpoint_slot(unsigned long addr)
> >  {
> >  	return (addr / PAGE_SIZE) % CONFIG_KCSAN_NUM_WATCHPOINTS;
> >  }
> >  
> > -static inline bool matching_access(unsigned long addr1, size_t size1,
> > -				   unsigned long addr2, size_t size2)
> > +static __always_inline bool matching_access(unsigned long addr1, size_t size1,
> > +					    unsigned long addr2, size_t size2)
> >  {
> >  	unsigned long end_range1 = addr1 + size1 - 1;
> >  	unsigned long end_range2 = addr2 + size2 - 1;
> > 
> 
> 
> -- 
> ~Randy
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191203160128.GC2889%40paulmck-ThinkPad-P72.
