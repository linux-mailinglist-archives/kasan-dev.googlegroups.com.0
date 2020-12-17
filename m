Return-Path: <kasan-dev+bncBAABB3PE5X7AKGQEFS44ARQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83e.google.com (mail-qt1-x83e.google.com [IPv6:2607:f8b0:4864:20::83e])
	by mail.lfdr.de (Postfix) with ESMTPS id 3A24B2DD376
	for <lists+kasan-dev@lfdr.de>; Thu, 17 Dec 2020 15:59:58 +0100 (CET)
Received: by mail-qt1-x83e.google.com with SMTP id k12sf11500806qth.23
        for <lists+kasan-dev@lfdr.de>; Thu, 17 Dec 2020 06:59:58 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1608217197; cv=pass;
        d=google.com; s=arc-20160816;
        b=Y2/uTwIOOLuQqTUL1TZXuspbDYMvvfiu5Isk9XfrGE+RCw+DxCOC5xMgKkjo2lanhR
         yjxUDUnqb1h1if7yDif5LCSas3GT8GTncf8mMAK8Hhq3sGvPOEOpLBIdyETL8wxaWCWV
         a47JHQsxiPmUp0BzSNYWuS0uvz5bc0s95GfCkovl8NTWWtbesraMI9cBZ2YYlmtoki6X
         dm6z/cuZ95cwakHzTmbcNmVBB9TpY/pWq+0Pr/1/Z5KC0UsmdQCMPQZm+TBxvMP7prni
         s7ZTj4FIn9eYfWl2MF2XeDz/SIEwu9GdSsCvqx9oIUNu6etrYzYtF/3+E8JyTYTZbrEV
         hXTA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:reply-to:message-id
         :subject:cc:to:from:date:sender:dkim-signature;
        bh=5Amj3ZJg9AeSq8q023DBFN51fwC+3z5q0UtEDUOsGLo=;
        b=iC3sB+9U/NA552/vJ3cI4szwllmb6SxWk2vvQuaS8TBSrwi2T35tAO6/7l/ooPMiKi
         Jnu2lZ7QtR0meVahTeK7M9CjeHWc1g2h7n8IhOCx19S0zwiLMCgW3mrjgxpumK608lNV
         0D4oTl4/Aa12BYidP6sJlHS2zuIyGaMLMUd5G6J/mw7FH1wG8fu2qT47Ud+ylpQGWFC4
         KgezBAH1uB0NnTw4/mgfOY8LrTawQMIo3AMWsQrdh6KzJrO0yhAc6QgigzvwzTJvXxed
         f7p+ZPm6p1lhkj/cGNyTiTBUCd7DAr3r6IarA9KD7HZ73/Az2BaCDjzEALvd66hsFU8L
         iHFQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=AuuLhQ52;
       spf=pass (google.com: domain of srs0=z6r7=fv=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=z6R7=FV=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=5Amj3ZJg9AeSq8q023DBFN51fwC+3z5q0UtEDUOsGLo=;
        b=WiYtgFLG1UM5ItF2j66rA0EfA1VJP5f2cZJqVsXxvPUfC6pGdlzhA/EKjzxwRcNgNO
         eFVh6YTnotjs8DAPITryYGY1zncyzCN9eP5XofK29A3+IdTesyxxDyIRKdsml6cZiqEE
         esW4cccTI3F3N+Ua7/XU4ZFivHytUd8yWn35zMJrB1ceY36vBU52M/qZ1Zg4Clo9C3Xg
         agQkA51eqorUB5wIqFGz3ETv9q/CRomwl/7Geou00bH8+tfFxACQsyF8saV5B0M7KUqt
         9TAmaPNSXyVJ8Eqj3pl4bNe+sERAlZng1i9fnCph/UJ4fetb+1np5XOD1SCQ+ebSM6t8
         MGOA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition:in-reply-to
         :user-agent:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=5Amj3ZJg9AeSq8q023DBFN51fwC+3z5q0UtEDUOsGLo=;
        b=quZ+ECWs6vJmxcwIPUtLc/klc0MUzDNQAa16In/jvxLGD8/4/4hTVjYFV4v8QXPdz4
         cFxMp4ZOMHSzdpC0shda7P31S1UBB3suvA7HMrMy7INMnGqFFvzjvka4+OVP1cLvfcP/
         h7kgTlGCP3smx/6NUR4wx7pmQ5G+Z2lIdvYYuTCh9RAHwucpm4A9t87kWF0imWEfeAFo
         9qg9XVB9RiZK77CmHfH6sliRhKEiJmDOKdYnyoKcQYYrpcC4U47V3hdWa4un46RAGNdl
         9WtYsbbwINNzpGjVqcunDA4r7P/jtlHVrBLMXh0e5YEYwNINxSCB3TF91TmJ2RMF9hW0
         sbsA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533lqEfLAP2b99h0rNOSJJWLr6oxW26Cr8Pq+l4BQGtlLMNb5/tC
	pkmUebf5fTQQysshKtVRu8w=
X-Google-Smtp-Source: ABdhPJwTHlTuaTDgVH+pnPF9Qy04Ju+z18oFrWKZEXwYg0ZyG/S6Z6Llv8ujki30pRpA30PRo8YYiA==
X-Received: by 2002:a37:bd84:: with SMTP id n126mr11409333qkf.54.1608217197214;
        Thu, 17 Dec 2020 06:59:57 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ad4:4812:: with SMTP id g18ls6529777qvy.11.gmail; Thu, 17
 Dec 2020 06:59:56 -0800 (PST)
X-Received: by 2002:a05:6214:14af:: with SMTP id bo15mr37517586qvb.19.1608217196634;
        Thu, 17 Dec 2020 06:59:56 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1608217196; cv=none;
        d=google.com; s=arc-20160816;
        b=zTLfpzVeqxFHnk1kGTAxPS8KR8jVybwEpG7HuhZIMKVVrzpLYyx4daDKBV1igx2LHn
         LNo48g6qf4FWKwfTfgMoYbNsiWWfBGIvmhAqOGX1HwU2cZpwgQsBAV9CRs8VyBwOop4o
         KpCdjaxUdfduSGswlZqYuF1FS3Q7cEyjcc7vDOPrZktLpq62XeVHV7WI2ud3Lzc3DNEe
         SWaPGJkbVynJ0mqv6fUC3f4bzuo+dNgLfOMhn5tu8LsW3Ztv86peonBkJin8Dt2qjAWv
         3JD9sx73fYW8pPtNR7KB/ts6uObGyxdKVdFOWuJBZHpkgIPoNPx+uAxjRfzWSz5UnslZ
         uZFA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :reply-to:message-id:subject:cc:to:from:dkim-signature:date;
        bh=uo21sJT3/7oo9SO8oDEx6wiQdyyLi1OExjX87isUG6M=;
        b=XM95SC+BvEY7M+Y8VUIDY1q1lqJDVPT0N7cvdMOH6UV1pPCdOmyaWeiyJvDhzcdyvh
         F8/Y3FjM6awsqLB4vkT7RSl0lt0UKC0szHqnRrUyf6EfdEq6hGxns2/lhvkndDnjrKG0
         UhHNIKfeSxyQpP3WFS8pCZk3DjMJZ0QBwX0OdDA3GcfLviI6p6/WZv6nMFIYAWvxRqG3
         E6gYmUUA8uMwQoV1+9qzwxVvrYS9Wlg4ZvQzSO/ppFz0fvZ6tWjO7J02p3n/9JKMYSPz
         yWZ+2OMvetBbBwX9FYYA2kEo0JRcmfLT0eS67MV2BFwI/Wl17PdXE+ZJ+HhxyCrx8iGg
         Pmhg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=AuuLhQ52;
       spf=pass (google.com: domain of srs0=z6r7=fv=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=z6R7=FV=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id s190si542425qkf.4.2020.12.17.06.59.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 17 Dec 2020 06:59:56 -0800 (PST)
Received-SPF: pass (google.com: domain of srs0=z6r7=fv=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Date: Thu, 17 Dec 2020 06:59:55 -0800
From: "Paul E. McKenney" <paulmck@kernel.org>
To: Peter Zijlstra <peterz@infradead.org>
Cc: Thomas Gleixner <tglx@linutronix.de>, Marco Elver <elver@google.com>,
	LKML <linux-kernel@vger.kernel.org>,
	kasan-dev <kasan-dev@googlegroups.com>,
	Ingo Molnar <mingo@kernel.org>,
	Frederic Weisbecker <frederic@kernel.org>,
	Will Deacon <will@kernel.org>,
	Naresh Kamboju <naresh.kamboju@linaro.org>,
	syzbot+23a256029191772c2f02@syzkaller.appspotmail.com,
	syzbot+56078ac0b9071335a745@syzkaller.appspotmail.com,
	syzbot+867130cb240c41f15164@syzkaller.appspotmail.com
Subject: Re: [patch 3/3] tick: Annotate tick_do_timer_cpu data races
Message-ID: <20201217145955.GP2657@paulmck-ThinkPad-P72>
Reply-To: paulmck@kernel.org
References: <20201206212002.876987748@linutronix.de>
 <20201207120943.GS3021@hirez.programming.kicks-ass.net>
 <87y2i94igo.fsf@nanos.tec.linutronix.de>
 <CANpmjNNQiTbnkkj+ZHS5xxQuQfnWN_JGwSnN-_xqfa=raVrXHQ@mail.gmail.com>
 <20201207194406.GK2657@paulmck-ThinkPad-P72>
 <20201208081129.GQ2414@hirez.programming.kicks-ass.net>
 <20201208150309.GP2657@paulmck-ThinkPad-P72>
 <873606tx1c.fsf@nanos.tec.linutronix.de>
 <20201216211931.GL2657@paulmck-ThinkPad-P72>
 <20201217104823.GU3040@hirez.programming.kicks-ass.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20201217104823.GU3040@hirez.programming.kicks-ass.net>
User-Agent: Mutt/1.9.4 (2018-02-28)
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=AuuLhQ52;       spf=pass
 (google.com: domain of srs0=z6r7=fv=paulmck-thinkpad-p72.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=z6R7=FV=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
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

On Thu, Dec 17, 2020 at 11:48:23AM +0100, Peter Zijlstra wrote:
> On Wed, Dec 16, 2020 at 01:19:31PM -0800, Paul E. McKenney wrote:
> > Given that there is no optimization potential, then the main reason to use
> > data_race() instead of *_ONCE() is to prevent KCSAN from considering the
> > accesses when looking for data races.  But that is mostly for debugging
> > accesses, in cases when these accesses are not really part of the
> > concurrent algorithm.
> > 
> > So if I understand the situation correctly, I would be using *ONCE().
> 
> Huh, what, why?
> 
> The code doesn't need READ_ONCE(), it merely wants to tell kasan that
> the race it observes is fine and as to please shut up.
> 
> IOW data_race() is accurate and right.

Other way around.

The code does not need any of the compiler optimizations that might
someday be enabled by data_race().  So why do you need data_race() here?
What do exactly is lost by instead using READ_ONCE()?

							Thanx, Paul

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201217145955.GP2657%40paulmck-ThinkPad-P72.
