Return-Path: <kasan-dev+bncBCBMVA7CUUHRB6MBW37AKGQEZQIOEQQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x537.google.com (mail-pg1-x537.google.com [IPv6:2607:f8b0:4864:20::537])
	by mail.lfdr.de (Postfix) with ESMTPS id C01A62D08B6
	for <lists+kasan-dev@lfdr.de>; Mon,  7 Dec 2020 02:10:18 +0100 (CET)
Received: by mail-pg1-x537.google.com with SMTP id b35sf7411961pgl.8
        for <lists+kasan-dev@lfdr.de>; Sun, 06 Dec 2020 17:10:18 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1607303417; cv=pass;
        d=google.com; s=arc-20160816;
        b=BhgJZLVRfURUjhiRH5GdrXgWAhhGWZcVDrzXOLJwN4esDq66f/ypSfDlBZxFGKKPW+
         OOltKBdK+017VT1sdn8EB1cC7EQuEz90sRrs7Wzj57rxfeyUKQxuKQ17Z1VPLg8lzhYs
         fgKfrz6o8ilBh6KumDxAB7elSNi22FwUGGSBRquUhFkQetRmtitg06gVbfs49HSGi1tP
         7QdkE7zK7S7vGRn2bN2Z0XRTHO+TluwvWWo3T0rJaWnMgFSqYUxtJZGSQVgG40RFwwON
         AOEdBT4q5DXdWICojK44HGdM/7O0ioBPKjuWflzcBll26tBCBpwNJSKd3GTaf1pqRLvw
         wkQw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=Rze83tnzeZepG5HFy93MsoIIn7rI8GKWUZ0/yDHClPQ=;
        b=EPE6qgWPQAXx5Zi7Lwhlb5C+Cc8a3KSK2u4FPOmZK1FQ1mM40hXE9SqoiEBbRo23F2
         UG7PdHODmNAkk6FSkzON/Z3gpwkwomJ1+dADBDDtUzJmWikZL2ftp35+F4agnseJktHk
         imOaLiWHQXXVMGi0+Pw/vQJ0gSHYACyR5q5p2pab6lPMtpmOTBd36vLhUoEXhkjgpuz1
         SgElpiD5AMl/Hrz2IP/zTo8nnFKTIWK5u65jCVG6ujxRCAnQB2i52tzsp0w4Nm5a9+Hv
         EA4bThiV+qT9KBJ6ZPQj7j1DwJkBqE3nsIsARP7G20V863u90Fg5tEjpgrF0XQFSowY2
         qtLw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Hv71Zg5b;
       spf=pass (google.com: domain of frederic@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=frederic@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Rze83tnzeZepG5HFy93MsoIIn7rI8GKWUZ0/yDHClPQ=;
        b=NP+7vOWElv5Jaoz9VqWonNGMm2sMrca+BV0WxhFLLZJk4kmbGKEpWrtZu18/FWPnNK
         iD29TNT/EGhEPuJ4WDCNWrztLy4SbELy22+CKT5SU2qrTKY3N7L/eLgQ/NCfCVQuJP+6
         0l6rXZvNI11p/jOFli5uWgzBc8uQpgB6sNm7LUWI0cIJP3OlYntCft1vkGIpwQq29R91
         1zRDV+KEt97WdSaXqM1cAg4AvdLv3ijKEcMdQzsGoI38s0I/boCU9Mrj4ACx5NI0AwgK
         FcqrcHb0519cbU3JKLuR60PgYltQz2lppIhLoW96+/u8gQIhcGHqCbSkNQS+9bloOU/e
         mvLg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=Rze83tnzeZepG5HFy93MsoIIn7rI8GKWUZ0/yDHClPQ=;
        b=YwbOZ2+pKs/9aK7tuEPyHnbrCkhw5wI3IRqvKDvaqW3xmJx9Q2t65DJ3KxbDqgPYB8
         KC0K8hhU39zGYDYYUpAkluxr8qSw5BNAbs0/T8u+Tm5uF9Q8LLCWr8ROpNjnQwUdYZlA
         oVAOA1cJubSG2iruW2l4TiQ4rt7q3Nuw6RyYkA6zXtPiCkvNUcug03eZfMvUELyJDzuN
         lQlWZybR3kuka1BrE+4n/flF6nb88VH3/82apBsq9eAszOTR6/brS0vldzeKJEUEO+LF
         cKvjHNZO8xm8xe/mFWokepWAuWfA65z6qD3a3DqTihh83hTArK47ZlX2iB7ZpyxJXIqq
         BFOA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531IBuSMtTDHgjanGoFGNYFnWJzeN4M9OJ/Gg3wB60J0Ta0jigpr
	68E3j7Yw+cBxVWEMkaUhvp8=
X-Google-Smtp-Source: ABdhPJysOP+Wf3lvEPTSs2zYTZAns/gf116fKKvqFIc1Bco0tKKSvXcdnocG9IPvUHRJGMbLzF2tEg==
X-Received: by 2002:a63:f045:: with SMTP id s5mr2188225pgj.92.1607303417557;
        Sun, 06 Dec 2020 17:10:17 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:4b61:: with SMTP id k33ls4950160pgl.0.gmail; Sun, 06 Dec
 2020 17:10:17 -0800 (PST)
X-Received: by 2002:aa7:8744:0:b029:18b:a9e1:803d with SMTP id g4-20020aa787440000b029018ba9e1803dmr13808927pfo.50.1607303416973;
        Sun, 06 Dec 2020 17:10:16 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1607303416; cv=none;
        d=google.com; s=arc-20160816;
        b=Pu/uyJDWo4lZ+qmQW8+U8IjwSch0dvyvF6veO4QmjY2IMZFKfcQwYsDsjsfBEFhmBT
         snhym6n15fkV/oo5RE8SSDWFAEayekmRpDeeVvf++ffNwUTafxzlEEZItT8IpRI6KCA2
         gh5iGisICBypRwrnRxQ2WiqsjnfpfmDITEl1jpPaLdStBumA70uQ1sm1jKqSQ2mZZZWA
         f2Dhzz1NCguhj0DokT0tAWk2eVfjHiMhs7NvqRi4hpIhC/3COblPIKKsuPe311ONTFaU
         cZYWYMfbUnFiN5XpK46Im6z1FNOgYY4c523F55CgeZWPIJX8y66cbAv7/WitkwcNjcNJ
         Srfw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:dkim-signature:date;
        bh=SO4ikM9iQCDI5pC801rkR8A3FOE8MLi7/gz6fDJIad4=;
        b=dBUVhteeXH2gPXYYkkn1bhsUy1qFTd9gn1bShWsg10HfSZ1PW34fTgxKM09uketKN4
         BzMeylbUxNT/RI78kQmnwZYIb4bGc74qGyyr9YOLCEtwEsldZokcmqwu7cKzKQimkX7c
         VNtff9p4FvdE1/u46p6fZNU+paABc+ueAxBbHcm4xOWhwn9iWFVBQ5hvJ7TopZVCkSkE
         xMTstZJ7QvQ5i0A6K0vg2xS9SadJI7+dm+aqBo1VEU0uY/PWGCnqar4wdGV3GuzobqKn
         2zi0YexxJOKi+pElklm9iE7PF5xqTmpmsBi1lvHgZbl1UFcy+ubdiG9znZQ5+XmJ1OMd
         49pQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Hv71Zg5b;
       spf=pass (google.com: domain of frederic@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=frederic@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id z10si762230plk.0.2020.12.06.17.10.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sun, 06 Dec 2020 17:10:16 -0800 (PST)
Received-SPF: pass (google.com: domain of frederic@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Date: Mon, 7 Dec 2020 02:10:13 +0100
From: Frederic Weisbecker <frederic@kernel.org>
To: Thomas Gleixner <tglx@linutronix.de>
Cc: LKML <linux-kernel@vger.kernel.org>, Marco Elver <elver@google.com>,
	kasan-dev <kasan-dev@googlegroups.com>,
	Peter Zijlstra <peterz@infradead.org>,
	"Paul E. McKenney" <paulmck@kernel.org>,
	Anna-Maria Behnsen <anna-maria@linutronix.de>,
	Sebastian Andrzej Siewior <bigeasy@linutronix.de>
Subject: Re: timers: Move clearing of base::timer_running under base::lock
Message-ID: <20201207011013.GB113660@lothringen>
References: <87lfea7gw8.fsf@nanos.tec.linutronix.de>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <87lfea7gw8.fsf@nanos.tec.linutronix.de>
X-Original-Sender: frederic@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=Hv71Zg5b;       spf=pass
 (google.com: domain of frederic@kernel.org designates 198.145.29.99 as
 permitted sender) smtp.mailfrom=frederic@kernel.org;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=kernel.org
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

On Sun, Dec 06, 2020 at 10:40:07PM +0100, Thomas Gleixner wrote:
> syzbot reported KCSAN data races vs. timer_base::timer_running being set to
> NULL without holding base::lock in expire_timers().
> 
> This looks innocent and most reads are clearly not problematic but for a
> non-RT kernel it's completely irrelevant whether the store happens before
> or after taking the lock. For an RT kernel moving the store under the lock
> requires an extra unlock/lock pair in the case that there is a waiter for
> the timer. But that's not the end of the world and definitely not worth the
> trouble of adding boatloads of comments and annotations to the code. Famous
> last words...

There is another thing I noticed lately wrt. del_timer_sync() VS timer execution:


    int data = 0;

    void timer_func(struct timer_list *t)
    {
        data = 1;
    }

                 CPU 0                                           CPU 1
    ------------------------------                             --------------------------
    base = lock_timer_base(timer, &flags);                     raw_spin_unlock(&base->lock);
    if (base->running_timer != timer)                          call_timer_fn(timer, fn, baseclk);
        ret = detach_if_pending(timer, base, true);            base->running_timer = NULL;
    raw_spin_unlock_irqrestore(&base->lock, flags);            raw_spin_lock(&base->lock);

    x = data;
    

Here if the timer has previously executed on CPU 1 and then CPU 0 sees base->running_timer == NULL,
it will return, assuming the timer has completed. But there is nothing to enforce the fact that x
will be equal to 1. Enforcing that is a behaviour I would expect in this case since this is a kind
of "wait for completion" function. But perhaps it doesn't apply here, in fact I have no idea...

But if we recognize that as an issue, we would need a mirroring load_acquire()/store_release() on
base->running_timer.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201207011013.GB113660%40lothringen.
