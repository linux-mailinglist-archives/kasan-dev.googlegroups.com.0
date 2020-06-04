Return-Path: <kasan-dev+bncBCV5TUXXRUIBBP6W4L3AKGQE477M2AQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x638.google.com (mail-pl1-x638.google.com [IPv6:2607:f8b0:4864:20::638])
	by mail.lfdr.de (Postfix) with ESMTPS id 756F01EDF03
	for <lists+kasan-dev@lfdr.de>; Thu,  4 Jun 2020 10:05:20 +0200 (CEST)
Received: by mail-pl1-x638.google.com with SMTP id ba6sf4158181plb.3
        for <lists+kasan-dev@lfdr.de>; Thu, 04 Jun 2020 01:05:20 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1591257919; cv=pass;
        d=google.com; s=arc-20160816;
        b=dNOt5ygqsHpu1kdhgJ+yI7iFwFd/CVA3dx2KT1nA9K7G3q141N/gQPE0CL4ASVV525
         Sse6ou/qgo4drege+83gXadfou/3khFrHa9oCrGbNkUgnoS8DcfrgP9s6XMraoRm/VE8
         TmKB/++tNkI8Uad/dJ6rZsU3TWhJGXKwklUwN1tlJL5yAYhBUm+cTP8pFyc9YZKkt3kY
         4fgtGGtLO1Kkz48iccDVkaLXyn8XWHRJ0k6y/+JdF00+CuZQbD3t6daql2OWAXtEYHx5
         ZEuk90feDRCjVh529jK668DKOMXmkQ7kB4ikSDdSEc9MvDITrHf7IpW3GnzzdK7N7UKz
         eKcQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=KEZkPs3VRS6c58XFK2yM03GsK8ojXQIQHE9uJtYUOEQ=;
        b=jj5z7uyuaghndQGb0NVLAbSl24nrCY80p+ipQgfgXUppbL5YtMBklGDQWN/CKaj/YP
         BNKkOf0FT+F06vk44Ht/l9WW5KwX++WuDIUMfF/RliHbx7fUHaPH+BcxJMV/S05HclUE
         eNQTjOpgeiNUWaZYjk/Vq1IggedxyBYDamikcxsnxuLYZu26rsb28HHqa4twuV8uXpaO
         kaPneSheH36xpyPHTKASwW8irTaObWUSXz/zcvWor59SSGlyrR1AfjOXvJoV7xstsWSs
         BtNEHmWd+cEST0EQovHJV+0nyVLXTN95f9kSB82dh+qhN12A8I082wkNe7QIVEFTGay0
         uSdg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=merlin.20170209 header.b="Z/jlrBjK";
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=KEZkPs3VRS6c58XFK2yM03GsK8ojXQIQHE9uJtYUOEQ=;
        b=oiF4ItblAGr162rSmRk2Yr2u8WUTrFXp2a26YiObF269ppcVtutg0n/rWeukfXc/Oa
         S+/YztctAl6sZvxcQ43bW+cKDySHSsFTgASVBEj/St2g71X2JVW0Kj9YZDFzJ+FmuHaW
         KBWzvBQzZUQ8S29vlD47zkgIhTVxsEYFfySCdK+58vAoT5ClStyY9v2/AUSgmbKr6dpQ
         7BRitVo4sjCaUN9/EEHs7Objzn7V7bto60P9KnRg1jN+DrNWJIJWwpq0nIULdGOQd4Dz
         5QBJkJhBahQvo4xFH0r1KcJoAvi1fKvC8P/asjIHMXWTqGpoqDa6WYODpFtRw8K4b+EV
         6qBg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=KEZkPs3VRS6c58XFK2yM03GsK8ojXQIQHE9uJtYUOEQ=;
        b=R5FnMY80y6/nHAltfuPz7nlttQJ3farJLr8A1i09D0WZZ9rT0DC56/yE4ZwPa5CBFi
         Y2SpcfgF8MYipoIZEzmCKoqj5IeMAs0Y9qpR6Sb0ZLfbA/HbDlJCfELoRghGUxhrszHn
         H+2ZTV6fxXvfnUjB4HYDRF5gb+q90D/mvaGG7rtVAXxGSbBXH5O13A/YCe+QPB7gNjPb
         yY94Isjd13CuqzQ+VWdluUX2BhwVEu2gKuGnjE2TX0dcomovj9/nNdafCrSYPV+jLJIe
         g/f1n/BDmlPy/0Ktki/gGWZH0m5Nfu8yfGbN+q9sXG4uDtDpj3l60f+dDeNkPgpXhgtf
         f5Sw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532w7jvpQFIq9Ld6FeFDdKgdMB4WoZQNmPeHmnZSn1HOoC8xbmEy
	mFy1EK3VDa7QGnP8RY++OgM=
X-Google-Smtp-Source: ABdhPJzP/sIsj6bbbxGueTTN3LKIW1cLu0jnxh6VhIUjQ47Kfi91a4908mxyohqPEQuJSgx0rRnOhQ==
X-Received: by 2002:a17:90a:4805:: with SMTP id a5mr5023492pjh.22.1591257919212;
        Thu, 04 Jun 2020 01:05:19 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:7a0c:: with SMTP id v12ls1158581pfc.1.gmail; Thu, 04 Jun
 2020 01:05:18 -0700 (PDT)
X-Received: by 2002:a63:7016:: with SMTP id l22mr3308508pgc.284.1591257918829;
        Thu, 04 Jun 2020 01:05:18 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1591257918; cv=none;
        d=google.com; s=arc-20160816;
        b=XptoqKb5ndMUS5j7y5/Vwciq3RiM+Fzwe3iNdfvGLUMiviQ4HgndibGjySGdYn45PI
         D2sL8N4Uk0iDnbe57OE99kj4mD7peQAruCp6LE3CKI0xLZhaUjNvJfvYXNQLokFgVIAS
         W1lOHCmZTkLp4tZGs6scJH5AjyCpeL1v7eFzfz4fi7FQ/1Z/kwdskHBCc5BJSrRnlHSk
         absmIV60EnvzqqaXmGYhlwh33znLTXE3TwVNZV7LQ/t1JxPS8XbqfW1i3CWwjBLk0w8G
         m/Thgc7IwWBPJwAo7Ag7J2pFTVlRiwToXMBMG68qcAuljHnMoLSJn1S7NsR5VWTdO12F
         DqLg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=KNW9NL3uD47FUjnpw82UUardVK7E6+mLshnuYV72GPY=;
        b=AxsU9FE4fQ03r04PpjlKgNInG+bZU6hpEuU29K7wtY/1wUXsHIfiWDphsFsxUEyfpP
         CKwpxAcTUKd16HFrmkY8MQddqzP2EQ4jRq8Wvjgqe95X1REvXjXWrHv6T1JkdcYBs77e
         q5FjISwCurMlUO7q/6fgVg8h8R+fKKqAqT1nBlndxzEXzRV7t+vzbcDb4BusfK61srEI
         0iydXJwVzzeNpOpvrbCvxGTfql/qpMRrwHq07qzRaFy4q7wXeq/KJ19RtH07bmKkAUkE
         5RoHDte1LGSGWWZR0eOeSkd7PbV05BWWdvvs7qNDtQvgE/5E1Xs0JKP/zmVxUT5UG1Rw
         Qs6w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=merlin.20170209 header.b="Z/jlrBjK";
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from merlin.infradead.org (merlin.infradead.org. [2001:8b0:10b:1231::1])
        by gmr-mx.google.com with ESMTPS id l137si286934pfd.3.2020.06.04.01.05.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 04 Jun 2020 01:05:17 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) client-ip=2001:8b0:10b:1231::1;
Received: from j217100.upc-j.chello.nl ([24.132.217.100] helo=noisy.programming.kicks-ass.net)
	by merlin.infradead.org with esmtpsa (Exim 4.92.3 #3 (Red Hat Linux))
	id 1jgksE-0000Go-TI; Thu, 04 Jun 2020 08:05:15 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id 45B8D301DFD;
	Thu,  4 Jun 2020 10:05:12 +0200 (CEST)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 1000)
	id 31B5620CC68B2; Thu,  4 Jun 2020 10:05:12 +0200 (CEST)
Date: Thu, 4 Jun 2020 10:05:12 +0200
From: Peter Zijlstra <peterz@infradead.org>
To: "Paul E. McKenney" <paulmck@kernel.org>
Cc: tglx@linutronix.de, x86@kernel.org, elver@google.com,
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org,
	will@kernel.org, dvyukov@google.com, glider@google.com,
	andreyknvl@google.com
Subject: Re: [PATCH 2/9] rcu: Fixup noinstr warnings
Message-ID: <20200604080512.GA2587@hirez.programming.kicks-ass.net>
References: <20200603114014.152292216@infradead.org>
 <20200603114051.896465666@infradead.org>
 <20200603164600.GQ29598@paulmck-ThinkPad-P72>
 <20200603171320.GE2570@hirez.programming.kicks-ass.net>
 <20200604033409.GX29598@paulmck-ThinkPad-P72>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20200604033409.GX29598@paulmck-ThinkPad-P72>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=merlin.20170209 header.b="Z/jlrBjK";
       spf=pass (google.com: best guess record for domain of
 peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
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

On Wed, Jun 03, 2020 at 08:34:09PM -0700, Paul E. McKenney wrote:
> On Wed, Jun 03, 2020 at 07:13:20PM +0200, Peter Zijlstra wrote:
> > On Wed, Jun 03, 2020 at 09:46:00AM -0700, Paul E. McKenney wrote:

> > > > @@ -313,7 +313,7 @@ static __always_inline bool rcu_dynticks
> > > >  {
> > > >  	struct rcu_data *rdp = this_cpu_ptr(&rcu_data);
> > > >  
> > > > -	return !(atomic_read(&rdp->dynticks) & RCU_DYNTICK_CTRL_CTR);
> > > > +	return !(arch_atomic_read(&rdp->dynticks) & RCU_DYNTICK_CTRL_CTR);
> > 
> > The above is actually instrumented by KCSAN, due to arch_atomic_read()
> > being a READ_ONCE() and it now understanding volatile.
> > 
> > > Also instrument_atomic_write(&rdp->dynticks, sizeof(rdp->dynticks)) as
> 
> Right, this should instead be instrument_read(...).
> 
> Though if KCSAN is unconditionally instrumenting volatile, how does
> this help?  Or does KCSAN's instrumentation of volatile somehow avoid
> causing trouble?

As Marco already explained, when used inside noinstr no instrumentation
will be emitted, when used outside noinstr it will emit the right
instrumentation.

> > > o	In theory in rcu_irq_exit_preempt(), but as this generates code
> > > 	only in lockdep builds, it might not be worth worrying about.
> > > 
> > > o	Ditto for rcu_irq_exit_check_preempt().
> > > 
> > > o	Ditto for __rcu_irq_enter_check_tick().
> > 
> > Not these, afaict they're all the above arch_atomic_read(), which is
> > instrumented due to volatile in these cases.

I this case, the above call-sites are all not noinstr (double negative!)
and will thus cause instrumentation to be emitted.

This is all a 'special' case for arch_atomic_read() (and _set()),
because they're basically READ_ONCE() (and WRITE_ONCE() resp.). The
normal atomics are asm() and it doesn't do anything for those (although
I suppose clang could, since it has this internal assembler to parse the
inline asm, but afaiu that's not something GCC ever wants to do).

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200604080512.GA2587%40hirez.programming.kicks-ass.net.
