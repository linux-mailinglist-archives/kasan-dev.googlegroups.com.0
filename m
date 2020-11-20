Return-Path: <kasan-dev+bncBAABBNNR376QKGQEXTLIJAQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63b.google.com (mail-pl1-x63b.google.com [IPv6:2607:f8b0:4864:20::63b])
	by mail.lfdr.de (Postfix) with ESMTPS id D5AD92BAC37
	for <lists+kasan-dev@lfdr.de>; Fri, 20 Nov 2020 15:54:46 +0100 (CET)
Received: by mail-pl1-x63b.google.com with SMTP id x11sf6629064plv.7
        for <lists+kasan-dev@lfdr.de>; Fri, 20 Nov 2020 06:54:46 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605884085; cv=pass;
        d=google.com; s=arc-20160816;
        b=r5mngzUp/gRZhrhElE6l7nGRTXJB/OZEpLexuits4VnRqaqEHxK/+gCC++l6ac1QQK
         dw/h9ODlzosCZzMOH0I87XEXv7b0p3kHAf3wpL5HYNFrpLOYu8mcsyaB1ylK5Xf3GoUA
         tdNU4eH62EE6aealITEHPNJ+tkyjc8hEpipJCygZNXJ4XicS6ZiLdhNqwEB5+mdHL/Sk
         VcIbxBQ6lgnNFc8gEOwpagvp7/8FtfFWFWIJXh6l8ZCWg8uMu1/A/6Jpur0eHz5ZyNuo
         CFQY7tuYn3h6HVJKsBWcZiKWxNFZaQ4wkzKxjO4pAJv1Fx+VbVjYBVOWSb0s+E9xd0bM
         YoVg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:reply-to:message-id
         :subject:cc:to:from:date:sender:dkim-signature;
        bh=EmYMs1IB0VdkN0jhrMG6pH5FpPpUlVLkSdXOEdGu504=;
        b=nlndYrdoNhdUO8YHs8kvuqTUyULv0kuJmnlZxPbgyVyTjaw5H2JiJ2ldLs1CGggDV7
         /1o7PpfVZD2wTF/qFcaKs/X+lbsGQR6tB7OlccfZtYitWb0R5UTaLe2g7tvn/DEil3X7
         iT2jF7y0d0fOm+mbnuf+mfXxKSFgHgfGdsJQv5WrprwlqZ8mIEf/kRdhqm3CkI6wiVUT
         WLzv2sOMYazZoUoGOzNNo6itf/2JH+NSZYwEUTk6EEPF48b+uKa8YGJCm7GhiNCwNguH
         t6EcYJsxK4wY52fVmM1xbSi8T65rd5GIRHGPP55J9CJBw1soW3N2bwQ7KXf7L2M0TPM3
         0I3g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=Mv+xTalB;
       spf=pass (google.com: domain of srs0=zhla=e2=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=ZHLA=E2=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=EmYMs1IB0VdkN0jhrMG6pH5FpPpUlVLkSdXOEdGu504=;
        b=NTl6mNjci72uOkB+OtWen7Bm/1cB7CrvQhCYNFLNFvPuOcAEY6YAJpp0mAubtwFN/6
         LlKiCq+xxkwrn5g6W1xVgGB+BbxlCe8xLVpbwGw8KZ+2psSb6iZ9Ay9lS76NNmk62f+m
         9z9CwgG84fSMP2Chqgndovq21U70zGoLWNzBd2x/fEtnCAJSyjz/iBPnA2Y5V7mn0PxG
         mWwpPvKozuBeFsAgrtXgC0mg/skpDfpJSV5KtVxSraVOOSpjVUDRLtdJOqfFcaiuE5iV
         2SNnq0Q/OtyBsYyFUXw3G3AoM6fBSSbVx/Ef31kq3La3tDG+D+ugYNBHuXXZg+QShkPh
         HuHA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition:in-reply-to
         :user-agent:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=EmYMs1IB0VdkN0jhrMG6pH5FpPpUlVLkSdXOEdGu504=;
        b=ailUXH9MWnCAspMIQe4B/T7JgjCGhIpGPZWd5ucUMPzEyNPGTfkNxTZkkVHbdmf2cF
         dQQPEJsEL1vUME5KP4ekLmq6wMgO5jsQ0W+zd0/EoG75NLN7DiF98cc+A5Z/0XbeqDlt
         iz+JAdtNrRmmziWfYkJ7xgP7niFrnoqb5oZ5v8A2Mo86TEdkfcxU7zG1GDGx3mRK6yBN
         O+DZrWsxAJTguwYWchTXqmLN2O/lgPxOppGUzSxajOCKkjATYNxXdx5gF28QeQHH94vj
         6QDnIgi71/qHDPCodb9FFBz1Q3nS/4qp/JqRg0J7etroB7+GEd8/uzKcWsycQkgTh2AA
         iZsQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532EeNPl58320xMzlwz6xIF/ZyCdYLK8NG2WyPrh0CotwbusGqbp
	mITj6LpvP4oYkYi0JVS/Zso=
X-Google-Smtp-Source: ABdhPJxCixoAB5zj6CeokfZRNyV/b8H58ENzitjR6iURB+iTU4XCHmS2PV0vwr7ccnL8vpf0utWRIA==
X-Received: by 2002:a17:902:9a48:b029:d6:e0ba:f301 with SMTP id x8-20020a1709029a48b02900d6e0baf301mr13831680plv.30.1605884085585;
        Fri, 20 Nov 2020 06:54:45 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:f601:: with SMTP id m1ls2294252pgh.4.gmail; Fri, 20 Nov
 2020 06:54:45 -0800 (PST)
X-Received: by 2002:aa7:9582:0:b029:18b:86c2:23f9 with SMTP id z2-20020aa795820000b029018b86c223f9mr14454909pfj.27.1605884085117;
        Fri, 20 Nov 2020 06:54:45 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605884085; cv=none;
        d=google.com; s=arc-20160816;
        b=EoqjQ5yjlfS0IIOYrMW7DWaW9Yscsc7PeI4Zx5E7FMXb7nkQIBmTWsTdnymZTC/sON
         NmW+pKiDkg0LpOEO8YSWwzSRSdcqR0WpEq8+O5qJKoEeDBKqx2kgmW7TxEO1AbVcdu7z
         Iu1koVd5YgIXsbmNAa4xa65rwFjgRoagoWRm420tsf4WdnFDH2iPT2+TrnZTGMHdriDt
         oZN7eNoHnIlPIvyL+Gi2RiIVlwF2ISM9GV13YPMfj25asO4S7Nlu47DKvv+B7XcHwTP/
         AbhtPCzLC+krHdcXDyXenjoHiwH0IdK8Av6rugDaQurDpE62sOq7lIPSqEqfv1p+eIMI
         2WOg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :reply-to:message-id:subject:cc:to:from:date:dkim-signature;
        bh=1PAVWUR8Gi5ESEbuPtgMNszfyW0P6k7DMaoonslk+V0=;
        b=NLfkJPDbqSqQ3aXxSM5Qs3V58N2sGoz7pPi9Mos1ax0JQ79/0VL64Qs4CguxoVxc9R
         41nWaZFrcA7EqsWxLjfG57qZrqRv6O3B1SY7TZWqA1S9KbAcunN87JAajUw9tsbfro8v
         C91UYW3jG7VDG8/fnV+wQlUlJGlVAUhrLmZ8X0ljJOR9QPGWqGt39yAJ3i046QS3GWu3
         PkDWVqtbXMJupzxxQnxK2OYtbOwIAuuTvNiATtraybNvLYBsSWaK8tsh0gADjIVEBsRI
         /9hmAXtYipgR49Z2IvN7LUOH85Vpzw2IpEYRh5xofrA/XdbQmFNAHdnYPSJClAjjF/rP
         cBvw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=Mv+xTalB;
       spf=pass (google.com: domain of srs0=zhla=e2=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=ZHLA=E2=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id lw12si280943pjb.1.2020.11.20.06.54.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 20 Nov 2020 06:54:45 -0800 (PST)
Received-SPF: pass (google.com: domain of srs0=zhla=e2=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (50-39-104-11.bvtn.or.frontiernet.net [50.39.104.11])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id B923A22272;
	Fri, 20 Nov 2020 14:54:44 +0000 (UTC)
Received: by paulmck-ThinkPad-P72.home (Postfix, from userid 1000)
	id 5B8EC3522A6E; Fri, 20 Nov 2020 06:54:44 -0800 (PST)
Date: Fri, 20 Nov 2020 06:54:44 -0800
From: "Paul E. McKenney" <paulmck@kernel.org>
To: Dmitry Vyukov <dvyukov@google.com>
Cc: "Zhang, Qiang" <qiang.zhang@windriver.com>,
	Josh Triplett <josh@joshtriplett.org>,
	Steven Rostedt <rostedt@goodmis.org>,
	Joel Fernandes <joel@joelfernandes.org>, rcu@vger.kernel.org,
	LKML <linux-kernel@vger.kernel.org>,
	kasan-dev <kasan-dev@googlegroups.com>,
	Uladzislau Rezki <urezki@gmail.com>
Subject: Re: [PATCH] rcu: kasan: record and print kvfree_call_rcu call stack
Message-ID: <20201120145444.GI1437@paulmck-ThinkPad-P72>
Reply-To: paulmck@kernel.org
References: <20201118035309.19144-1-qiang.zhang@windriver.com>
 <20201119214934.GC1437@paulmck-ThinkPad-P72>
 <CACT4Y+bas5xfc-+W+wkpbx6Lw=9dsKv=ha83=hs1pytjfK+drg@mail.gmail.com>
 <20201120143440.GF1437@paulmck-ThinkPad-P72>
 <CACT4Y+ZNBRaVOK4zjv7WyyJKeS54OL8212EtjQHshYDeOVmCGQ@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CACT4Y+ZNBRaVOK4zjv7WyyJKeS54OL8212EtjQHshYDeOVmCGQ@mail.gmail.com>
User-Agent: Mutt/1.9.4 (2018-02-28)
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=Mv+xTalB;       spf=pass
 (google.com: domain of srs0=zhla=e2=paulmck-thinkpad-p72.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=ZHLA=E2=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
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

On Fri, Nov 20, 2020 at 03:44:04PM +0100, Dmitry Vyukov wrote:
> On Fri, Nov 20, 2020 at 3:34 PM Paul E. McKenney <paulmck@kernel.org> wrote:
> >
> > On Fri, Nov 20, 2020 at 09:51:15AM +0100, Dmitry Vyukov wrote:
> > > On Thu, Nov 19, 2020 at 10:49 PM Paul E. McKenney <paulmck@kernel.org> wrote:
> > > >
> > > > On Wed, Nov 18, 2020 at 11:53:09AM +0800, qiang.zhang@windriver.com wrote:
> > > > > From: Zqiang <qiang.zhang@windriver.com>
> > > > >
> > > > > Add kasan_record_aux_stack function for kvfree_call_rcu function to
> > > > > record call stacks.
> > > > >
> > > > > Signed-off-by: Zqiang <qiang.zhang@windriver.com>
> > > >
> > > > Thank you, but this does not apply on the "dev" branch of the -rcu tree.
> > > > See file:///home/git/kernel.org/rcutodo.html for more info.
> > > >
> > > > Adding others on CC who might have feedback on the general approach.
> > > >
> > > >                                                         Thanx, Paul
> > > >
> > > > > ---
> > > > >  kernel/rcu/tree.c | 2 +-
> > > > >  1 file changed, 1 insertion(+), 1 deletion(-)
> > > > >
> > > > > diff --git a/kernel/rcu/tree.c b/kernel/rcu/tree.c
> > > > > index da3414522285..a252b2f0208d 100644
> > > > > --- a/kernel/rcu/tree.c
> > > > > +++ b/kernel/rcu/tree.c
> > > > > @@ -3506,7 +3506,7 @@ void kvfree_call_rcu(struct rcu_head *head, rcu_callback_t func)
> > > > >               success = true;
> > > > >               goto unlock_return;
> > > > >       }
> > > > > -
> > > > > +     kasan_record_aux_stack(ptr);
> > > > >       success = kvfree_call_rcu_add_ptr_to_bulk(krcp, ptr);
> > > > >       if (!success) {
> > > > >               run_page_cache_worker(krcp);
> > >
> > > kvfree_call_rcu is intended to free objects, right? If so this is:
> >
> > True, but mightn't there still be RCU readers referencing this object for
> > some time, as in up to the point that the RCU grace period ends?  If so,
> > won't adding this cause KASAN to incorrectly complain about those readers?
> >
> > Or am I missing something here?
> 
> kvfree_call_rcu does not check anything, not poison the object for
> future accesses (it is also called in call_rcu which does not
> necessarily free the object).
> It just notes the current stack to provide in reports later.
> The problem is that the free stack is pointless for objects freed by
> rcu. In such cases we want call_rcu/kvfree_call_rcu stack in
> use-after-free reports.

OK, sounds good, thank you!

I will take this patch with your ack and Uladzislau's reviewed-by.
I had to forward-port this to -rcu brach "dev", and along the way I
updated the commit log to make Dmitry's point above, so please let me
know if I messed anything up.

							Thanx, Paul

------------------------------------------------------------------------

commit 3ce23b2df528877623ffc9c9cc2b6885eb3ae9db
Author: Zqiang <qiang.zhang@windriver.com>
Date:   Fri Nov 20 06:53:11 2020 -0800

    rcu: Record kvfree_call_rcu() call stack for KASAN
    
    This commit adds a call to kasan_record_aux_stack() in kvfree_call_rcu()
    in order to record the call stack of the code that caused the object
    to be freed.  Please note that this function does not update the
    allocated/freed state, which is important because RCU readers might
    still be referencing this object.
    
    Acked-by: Dmitry Vyukov <dvyukov@google.com>
    Reviewed-by: Uladzislau Rezki (Sony) <urezki@gmail.com>
    Signed-off-by: Zqiang <qiang.zhang@windriver.com>
    Signed-off-by: Paul E. McKenney <paulmck@kernel.org>

diff --git a/kernel/rcu/tree.c b/kernel/rcu/tree.c
index 1d956f9..4aa7745 100644
--- a/kernel/rcu/tree.c
+++ b/kernel/rcu/tree.c
@@ -3514,6 +3514,7 @@ void kvfree_call_rcu(struct rcu_head *head, rcu_callback_t func)
 		return;
 	}
 
+	kasan_record_aux_stack(ptr);
 	success = add_ptr_to_bulk_krc_lock(&krcp, &flags, ptr, !head);
 	if (!success) {
 		run_page_cache_worker(krcp);

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201120145444.GI1437%40paulmck-ThinkPad-P72.
