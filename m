Return-Path: <kasan-dev+bncBCV5TUXXRUIBBZ7V6CFAMGQEPG3MT4Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x539.google.com (mail-ed1-x539.google.com [IPv6:2a00:1450:4864:20::539])
	by mail.lfdr.de (Postfix) with ESMTPS id 94C7D422595
	for <lists+kasan-dev@lfdr.de>; Tue,  5 Oct 2021 13:45:43 +0200 (CEST)
Received: by mail-ed1-x539.google.com with SMTP id r21-20020a50c015000000b003db1c08edd3sf543887edb.15
        for <lists+kasan-dev@lfdr.de>; Tue, 05 Oct 2021 04:45:43 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1633434343; cv=pass;
        d=google.com; s=arc-20160816;
        b=dmbzY7cQKDzGwm/yEeE5e5Cx1x+edxivC9ws//pFNMJMume4cP1Lnht8lZAkICZ4AX
         oAEouptoiDSkY+cSrxRRtnJlE1GZrBpgmz3U+sa7jPLVUNsMZIhEjLnqo9V4VP4dNvjl
         HJLDGYDD8RLnLptXippkVQ7mAJNhyuh4awS5zIs82VZxp3B5ewsnimmMjgMu9atAD9RA
         yl/nx18kSzsDdlsk/DtxY0oupbJuUcoGDkl74XkhC7dvLtHakbHJ8QGKOSjM2yucRrqD
         xg1Rk8+P3W61pnHhHrxLSfds+S8Qp5xdYs0x6YxvBg+5Yj4RGHnJVLckyNXMNSCvrz4n
         8vyw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=iscn92jeozx/6Cevnc6nOd0okvSjqpwrLAftEaNq2nY=;
        b=poEsMUKnQdX5rhypWFkzguyH6KwaAGCcRBSloRf1Gegd+FDUt7nhRbUYhx417ZJPK1
         oeCJ0Zd7r00kk+VbBz5adwB23/+BNHwq5Ak8MKuRJqm8HMae8Ma3rvaPdnMse2WdCTS2
         HI2OykRpS9CJDq4/NA+fav241lyBHpA3UOvu3T/f5amFw53FKhBssiemMALN4IF621Il
         dqKt7KM51h4bgMO5Def4ehg0MckmvjtmEQq0edGfTsSU48u9FtYM9nyEtY7Qg5cmQApB
         +7CMSXoh9ZDBLWdvvCWCdWj+vN4C/fNg5fa5bmzbGx1S8cv5NsIGgQEXCWSpOavIh0Mr
         33MA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=EVw7JiEF;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=iscn92jeozx/6Cevnc6nOd0okvSjqpwrLAftEaNq2nY=;
        b=Tby5m2SmzNoEQhdWl0FSfUmcJxytj3F2Ahqiae8ZEkD9D6H90o1l//yEng5wYK4Nng
         3N+zNxuu+N/WpfLSEssKq7PNutUdFduh3Lqh96sRW06spUVDeLDQr8JVUIopHGlPGgh0
         jAlFvG/4AnAPmwq7WSsUEDFF9LNo2ZOlJJ2WGjY+6Fsj0RteDYq16+5AqsQMitCKRDEO
         vNUkAp8gO8HJvWCfuS73MUcs+MVfmYEJ8sKbWGfoX69a33RG2Ht2Xi8gtPoJVWXNVSqU
         OUbHtVfSxS4ymtwPwr1Ps3vUA+XfkXnFhGHKNVFGgk2Mx3IbRgbiDjclP2awPGAmPaAO
         4Gcw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=iscn92jeozx/6Cevnc6nOd0okvSjqpwrLAftEaNq2nY=;
        b=W3Ebc1/5xNCzFmWpc0Sz3HsLWa5r+NdZWhHA2HRa0zVuNWoCwe2dA6h1f/eOujXr9/
         CkN0L8v5V/TbvLdNT6v+ID22tjyeBBxAi1ITybUe4KVUkjMtvY2MndbpFrMECXFeDEgj
         FZOBtrTflsLOgcuLN14fy6oxMJovTpicDHneC4VTGwZ1O+aB7kFdMyx6nit7zyCEMKLY
         giyJA40tILjaiRkf0a0mTA+W9YwDMDSbb3HJvtzmYLUDCcRGdUgBTML3O8TPrS828xrE
         tbi8KM4a1LYXWM4PRFQ4ngesf0XwLAb84PqeHjidHKZ/7f3WwijvroAq/Clb2K9je1JE
         pU9A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533tUrbERO2mPVVrLPSebv3L2mPoy6mqzRJGOiS+R4Z7iKKIi28+
	Qh+Z9Z2dnlTDzGclo88vmV0=
X-Google-Smtp-Source: ABdhPJzPLqEXFV2gzIJV9qf8SrRajXTxIXm9LReFNVGOIKSI9rpj7rFrpRc31SD8Oonjo/pl3Km+sw==
X-Received: by 2002:a17:906:4482:: with SMTP id y2mr24006432ejo.484.1633434343375;
        Tue, 05 Oct 2021 04:45:43 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:5941:: with SMTP id g1ls9967579ejr.10.gmail; Tue, 05
 Oct 2021 04:45:42 -0700 (PDT)
X-Received: by 2002:a17:906:7d42:: with SMTP id l2mr25180571ejp.467.1633434342409;
        Tue, 05 Oct 2021 04:45:42 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1633434342; cv=none;
        d=google.com; s=arc-20160816;
        b=NbBBrrrCyCrGlHU9XiljiXWeO5+SPX8wjBSLHgLx888J2Cfx4/yyELNr3gl007QKWj
         6xFz3k0ypEPH12JvyRMK1NvxAGzqq+fhWNg03LLqkdJV1RVnxUyfRaL24raCEqxFylg5
         Svlh8sn7RrV8axxxEqGA9NbEUEpSErrvwe2zB7OZMEkhGteaIBuSI5s27Q8vcGjmfrJq
         6GAnQqRxrRehFkJm6cnh/MgUlGWyB0ZmARBfADq9F31yW21Ze0nqhOfw4ZTkFRhxqfGO
         /8B2jVlSTCvzv3xStvL2L2e/uEHIKkqcfp6eg1naCS/p9yyM5zxEldH8cq79HQ9kR91i
         Um0A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=13tbC3Gouv1KRuynQBuv27/8d3oljsFDDnHed+AikeM=;
        b=zeiw665gNwHAU1rmWAh6joOGSG82KaMXGXKuszhFKK5fO6jENKTD7GJmvJKU0brEPn
         2MBMQKeMZkvjhodL3R1r2pw8ylpwaEEP9O2Hgr0+TDh4+v7uwOey2HHs3kMFIOQbUeJw
         2BsErkmG+m/Bmz0BZa7UUzlef1SWAi0WGnMFNnkV9+waiC5y24Ru45HZkBTfsidwYS/b
         yNR/ZCkl4+Wik/CbDIzNVm5AWI+zQ6VEUqMBMvHNdbwrW2HByWw31VcsPeHvOcxIpOtd
         eGb9VDZUKHUBTtdbAtcxNcNvrac0RleVgTrfKKRfqGd77U0J6uu2B1akMewiXvn5GAnL
         l/kw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=EVw7JiEF;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from desiato.infradead.org (desiato.infradead.org. [2001:8b0:10b:1:d65d:64ff:fe57:4e05])
        by gmr-mx.google.com with ESMTPS id r21si570494edq.2.2021.10.05.04.45.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 05 Oct 2021 04:45:42 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as permitted sender) client-ip=2001:8b0:10b:1:d65d:64ff:fe57:4e05;
Received: from j217100.upc-j.chello.nl ([24.132.217.100] helo=noisy.programming.kicks-ass.net)
	by desiato.infradead.org with esmtpsa (Exim 4.94.2 #2 (Red Hat Linux))
	id 1mXit5-0082aO-Hm; Tue, 05 Oct 2021 11:45:35 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id 86EB13002DE;
	Tue,  5 Oct 2021 13:45:34 +0200 (CEST)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 1000)
	id 740772038E207; Tue,  5 Oct 2021 13:45:34 +0200 (CEST)
Date: Tue, 5 Oct 2021 13:45:34 +0200
From: Peter Zijlstra <peterz@infradead.org>
To: Marco Elver <elver@google.com>
Cc: "Paul E . McKenney" <paulmck@kernel.org>,
	Alexander Potapenko <glider@google.com>,
	Boqun Feng <boqun.feng@gmail.com>, Borislav Petkov <bp@alien8.de>,
	Dmitry Vyukov <dvyukov@google.com>, Ingo Molnar <mingo@kernel.org>,
	Josh Poimboeuf <jpoimboe@redhat.com>,
	Mark Rutland <mark.rutland@arm.com>,
	Thomas Gleixner <tglx@linutronix.de>,
	Waiman Long <longman@redhat.com>, Will Deacon <will@kernel.org>,
	kasan-dev@googlegroups.com, linux-arch@vger.kernel.org,
	linux-doc@vger.kernel.org, linux-kbuild@vger.kernel.org,
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, x86@kernel.org
Subject: Re: [PATCH -rcu/kcsan 05/23] kcsan: Add core memory barrier
 instrumentation functions
Message-ID: <YVw63tqctCMm+d7M@hirez.programming.kicks-ass.net>
References: <20211005105905.1994700-1-elver@google.com>
 <20211005105905.1994700-6-elver@google.com>
 <YVw53mP3VkWyCzxn@hirez.programming.kicks-ass.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <YVw53mP3VkWyCzxn@hirez.programming.kicks-ass.net>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=desiato.20200630 header.b=EVw7JiEF;
       spf=pass (google.com: best guess record for domain of
 peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as
 permitted sender) smtp.mailfrom=peterz@infradead.org
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

On Tue, Oct 05, 2021 at 01:41:18PM +0200, Peter Zijlstra wrote:
> On Tue, Oct 05, 2021 at 12:58:47PM +0200, Marco Elver wrote:
> > +static __always_inline void kcsan_atomic_release(int memorder)
> > +{
> > +	if (memorder == __ATOMIC_RELEASE ||
> > +	    memorder == __ATOMIC_SEQ_CST ||
> > +	    memorder == __ATOMIC_ACQ_REL)
> > +		__kcsan_release();
> > +}
> > +
> >  #define DEFINE_TSAN_ATOMIC_LOAD_STORE(bits)                                                        \
> >  	u##bits __tsan_atomic##bits##_load(const u##bits *ptr, int memorder);                      \
> >  	u##bits __tsan_atomic##bits##_load(const u##bits *ptr, int memorder)                       \
> >  	{                                                                                          \
> > +		kcsan_atomic_release(memorder);                                                    \
> >  		if (!IS_ENABLED(CONFIG_KCSAN_IGNORE_ATOMICS)) {                                    \
> >  			check_access(ptr, bits / BITS_PER_BYTE, KCSAN_ACCESS_ATOMIC, _RET_IP_);    \
> >  		}                                                                                  \
> > @@ -1156,6 +1187,7 @@ EXPORT_SYMBOL(__tsan_init);
> >  	void __tsan_atomic##bits##_store(u##bits *ptr, u##bits v, int memorder);                   \
> >  	void __tsan_atomic##bits##_store(u##bits *ptr, u##bits v, int memorder)                    \
> >  	{                                                                                          \
> > +		kcsan_atomic_release(memorder);                                                    \
> >  		if (!IS_ENABLED(CONFIG_KCSAN_IGNORE_ATOMICS)) {                                    \
> >  			check_access(ptr, bits / BITS_PER_BYTE,                                    \
> >  				     KCSAN_ACCESS_WRITE | KCSAN_ACCESS_ATOMIC, _RET_IP_);          \
> > @@ -1168,6 +1200,7 @@ EXPORT_SYMBOL(__tsan_init);
> >  	u##bits __tsan_atomic##bits##_##op(u##bits *ptr, u##bits v, int memorder);                 \
> >  	u##bits __tsan_atomic##bits##_##op(u##bits *ptr, u##bits v, int memorder)                  \
> >  	{                                                                                          \
> > +		kcsan_atomic_release(memorder);                                                    \
> >  		if (!IS_ENABLED(CONFIG_KCSAN_IGNORE_ATOMICS)) {                                    \
> >  			check_access(ptr, bits / BITS_PER_BYTE,                                    \
> >  				     KCSAN_ACCESS_COMPOUND | KCSAN_ACCESS_WRITE |                  \
> > @@ -1200,6 +1233,7 @@ EXPORT_SYMBOL(__tsan_init);
> >  	int __tsan_atomic##bits##_compare_exchange_##strength(u##bits *ptr, u##bits *exp,          \
> >  							      u##bits val, int mo, int fail_mo)    \
> >  	{                                                                                          \
> > +		kcsan_atomic_release(mo);                                                          \
> >  		if (!IS_ENABLED(CONFIG_KCSAN_IGNORE_ATOMICS)) {                                    \
> >  			check_access(ptr, bits / BITS_PER_BYTE,                                    \
> >  				     KCSAN_ACCESS_COMPOUND | KCSAN_ACCESS_WRITE |                  \
> > @@ -1215,6 +1249,7 @@ EXPORT_SYMBOL(__tsan_init);
> >  	u##bits __tsan_atomic##bits##_compare_exchange_val(u##bits *ptr, u##bits exp, u##bits val, \
> >  							   int mo, int fail_mo)                    \
> >  	{                                                                                          \
> > +		kcsan_atomic_release(mo);                                                          \
> >  		if (!IS_ENABLED(CONFIG_KCSAN_IGNORE_ATOMICS)) {                                    \
> >  			check_access(ptr, bits / BITS_PER_BYTE,                                    \
> >  				     KCSAN_ACCESS_COMPOUND | KCSAN_ACCESS_WRITE |                  \
> > @@ -1246,6 +1281,7 @@ DEFINE_TSAN_ATOMIC_OPS(64);
> >  void __tsan_atomic_thread_fence(int memorder);
> >  void __tsan_atomic_thread_fence(int memorder)
> >  {
> > +	kcsan_atomic_release(memorder);
> >  	__atomic_thread_fence(memorder);
> >  }
> >  EXPORT_SYMBOL(__tsan_atomic_thread_fence);
> 
> I find that very hard to read.. kcsan_atomic_release() it not in fact a
> release. It might be a release if @memorder implies one.

Also, what's the atomic part signify? Is that because you're modeling
the difference in acquire/release semantics between
smp_load_{acquire,release}() and atomic*_{acquire,release}() ?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YVw63tqctCMm%2Bd7M%40hirez.programming.kicks-ass.net.
