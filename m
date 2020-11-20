Return-Path: <kasan-dev+bncBCMIZB7QWENRBQVM376QKGQELEBLRGQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33a.google.com (mail-ot1-x33a.google.com [IPv6:2607:f8b0:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id C93CA2BAC16
	for <lists+kasan-dev@lfdr.de>; Fri, 20 Nov 2020 15:44:19 +0100 (CET)
Received: by mail-ot1-x33a.google.com with SMTP id f7sf4107952oti.1
        for <lists+kasan-dev@lfdr.de>; Fri, 20 Nov 2020 06:44:19 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605883458; cv=pass;
        d=google.com; s=arc-20160816;
        b=xufWcKSVezYJbY/ufL0Fspae+fDNf/GXRmcBTxNUukbSVGT77DIUIcmBmiUZ0Mse1k
         oe3nLdgbznbbT+KufGwFyOPNPYCUbB92sg3vJM4gPdNYZiBY+8OSavXIiK3mbi75xbMM
         cF19JjwALrNzH29c/ZV/U6UdktVUJMomYTZwLB368K+t8rkcgPqy7LSQc/EP+s7nmDZF
         DH6NQ3B5V0p3qKBZjUmX6dkfvzpvFkTVxCbC1Oz+yySiYHHXpS6eRX24/R87DmnY+2BA
         Wv3vQZxmNNnreD2fyPgJEldd0sNCagvPLPuTtAoXq2cEt89oTB8yavtsGmoufuknpwBH
         /htg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=ruWUb+NIoM3B0w48ODzPsML+PPw83FLa+vagAexDssw=;
        b=ezIuzA+ZDf9aZVW+mRdrdXxZ5ehqF+TnNy3JV4dZofbkGXqmcDTeIbu89pE77UFHcl
         0ovNLnNGu2v5C3UpkxSi/CL2x0c58x0BmsTADiCr12sQEtyTZ35qr4AcIzEqH0RQ7n82
         glG0dKdFs9gDXI1PceGQwztpSg0zP3ECK7rRRNKl0uoPeMFnhQlxQiv2M2QSmv4FL9M4
         hfk+YcYlMh65ituZ3o7Nl0Bv75I9SpkL136ufAKBfMa62HQAKHdXiQCQDqVJTpXBMPGK
         jupuSxA4CVW+ndY4LC1/AdgrXc6HPKGYdj41XNI/XXRidzWKgWuui8yQSqNNdOG87LpV
         9qlQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=RTlyczda;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::742 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ruWUb+NIoM3B0w48ODzPsML+PPw83FLa+vagAexDssw=;
        b=oYyiQZjBRq9Nu7u6eunAbwNU1s6HwejzLKHebYmM9eOpTa05H0JS5h5t+BfGNy7++v
         pwQ4TIvDXmeChTPSs5SmxmF9EpAAv3LCqH+Z05d0ae8HLg4UojCoJCW5pdKjkFaQZueA
         bKyPoTqpQUwhb4ShbqzbEq/ZlmOdIJuMi/feyN3l4Wlh/FJPGZMBW5+AYhz7Ec44qH/0
         5sGwEmn3f74Eg9xe+093+x02GohIGkOcynvEZ5tFDTuDe1lnXgd2ELshzuC9wWWQGqxp
         CA8RmryNESJ1GZLiwNrxuRnk6k+OrEvfazZIAgU/OWgBG7nvepypAWtqRqHteusdu+4k
         VF8A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ruWUb+NIoM3B0w48ODzPsML+PPw83FLa+vagAexDssw=;
        b=ZnCY6FJtMX4ukwMEB/12f7c60zGBguSXOSmamk9awoTfahiSw6NsM8QnW4J+Z4mUwU
         YY0xkrf5Z0CgttqKPrRP/mVRzLvcI5uFY4LrY9aDCkCxPmJ/zo1nHhoHIofn44LkgkNP
         sNgRUB8SjPRzzEIHanY3gvaDK6FYLxalQnBGOnEc5WXSA9LWpeFhDqojJgHzgmGQSJdM
         ofctYGbqoGucLlWSvQUw9o5GlLPFXXJNQ8gld625uDtwf/1VC0Q04ds0ReNfzeFKIr+U
         eITHIWEbGWSTMoseKhcLTZ+2j/G4oX8vcn6gd0gyd61UClTnpIiGadKK6yauH/NapJPF
         xg9w==
X-Gm-Message-State: AOAM530E7A6/SaN9YxmwbVC1MQl+wVAMXIuBtQ7Dbc+a2m6g82LSp1tX
	IER4/h+e2PcqDgFP3njCMSw=
X-Google-Smtp-Source: ABdhPJzhrsT8morRUGVO7F+Z3YnE1aHpm4o4+IuXgXa/Lvpl+AYpGlccefd61EqgM/IQQuv1yWSnAg==
X-Received: by 2002:a4a:e80b:: with SMTP id b11mr14177017oob.1.1605883458346;
        Fri, 20 Nov 2020 06:44:18 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:2238:: with SMTP id o53ls115380ota.9.gmail; Fri, 20 Nov
 2020 06:44:18 -0800 (PST)
X-Received: by 2002:a9d:75d6:: with SMTP id c22mr13995220otl.350.1605883457966;
        Fri, 20 Nov 2020 06:44:17 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605883457; cv=none;
        d=google.com; s=arc-20160816;
        b=shvCV9qIR5r6jAJ0B5j/q2xk6vwaQqxMJXFwGiyAGUmEYdNV/vdbujpGjv+GlhyrL0
         yvTrTPgErqPF4MXshL7tmjVs1FFvvbZAidp7ykQhxhBASdMla+6QgEtVteSiv5emaysr
         bwYGNSmZVrbUkBUYnVh08xte110x77IzTEq+w3l0WtN+i2+O+NPSWNNWdMVqMQpB2NxN
         EBXqD1POQRgS3RDWamlns5OJSp2aigymIIeBisgi6WWWC5XyYPsJs8a4qarxgxkjdBEy
         CMkH/S0/YuGi+afVO1zZ+yTHXRbEbjDZwVLxcGNqlP/GIeO2HLE7g6Zo0/UXgAPW8R8j
         7Emw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=C1CYOETxY2mWhhteoELoIdcbW6dqQyY7MF0yoQEntsU=;
        b=vahpbknRmOrS3qCXJOHtLjoErAM86fNSjfFQpkuKo6wAN2OFuQWvDSjPHRFVlEPZ5T
         MtRw01RO7jdrTrPOgAAHkIoE6CGPMARDDXalqz0DWIOVESj6XGMwkn71h6xGpT+CvSrE
         Hg18JujwSxNS7ALFzC4yYjhzf1xow5vNpEGe7N2tgbJZEAfHW37clUHM35O6jfJrujax
         Y/SdtxO41F8sASwNXOKXerspZCPcVoEk28INDU7H4dTcmyXdDtTDKkrIHhh0xBmM0KQL
         BSK/2MedGC9YEuVGMlHwOGB/G9bAWcNX+0GfZZiZXexNASm66IBHIlGfXklCtD1L8yrd
         o0UA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=RTlyczda;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::742 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x742.google.com (mail-qk1-x742.google.com. [2607:f8b0:4864:20::742])
        by gmr-mx.google.com with ESMTPS id i23si248465oto.5.2020.11.20.06.44.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 20 Nov 2020 06:44:17 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::742 as permitted sender) client-ip=2607:f8b0:4864:20::742;
Received: by mail-qk1-x742.google.com with SMTP id d28so9005072qka.11
        for <kasan-dev@googlegroups.com>; Fri, 20 Nov 2020 06:44:17 -0800 (PST)
X-Received: by 2002:a05:620a:15ce:: with SMTP id o14mr17381328qkm.231.1605883457341;
 Fri, 20 Nov 2020 06:44:17 -0800 (PST)
MIME-Version: 1.0
References: <20201118035309.19144-1-qiang.zhang@windriver.com>
 <20201119214934.GC1437@paulmck-ThinkPad-P72> <CACT4Y+bas5xfc-+W+wkpbx6Lw=9dsKv=ha83=hs1pytjfK+drg@mail.gmail.com>
 <20201120143440.GF1437@paulmck-ThinkPad-P72>
In-Reply-To: <20201120143440.GF1437@paulmck-ThinkPad-P72>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 20 Nov 2020 15:44:04 +0100
Message-ID: <CACT4Y+ZNBRaVOK4zjv7WyyJKeS54OL8212EtjQHshYDeOVmCGQ@mail.gmail.com>
Subject: Re: [PATCH] rcu: kasan: record and print kvfree_call_rcu call stack
To: "Paul E. McKenney" <paulmck@kernel.org>
Cc: "Zhang, Qiang" <qiang.zhang@windriver.com>, Josh Triplett <josh@joshtriplett.org>, 
	Steven Rostedt <rostedt@goodmis.org>, Joel Fernandes <joel@joelfernandes.org>, rcu@vger.kernel.org, 
	LKML <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Uladzislau Rezki <urezki@gmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=RTlyczda;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::742
 as permitted sender) smtp.mailfrom=dvyukov@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Dmitry Vyukov <dvyukov@google.com>
Reply-To: Dmitry Vyukov <dvyukov@google.com>
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

On Fri, Nov 20, 2020 at 3:34 PM Paul E. McKenney <paulmck@kernel.org> wrote:
>
> On Fri, Nov 20, 2020 at 09:51:15AM +0100, Dmitry Vyukov wrote:
> > On Thu, Nov 19, 2020 at 10:49 PM Paul E. McKenney <paulmck@kernel.org> wrote:
> > >
> > > On Wed, Nov 18, 2020 at 11:53:09AM +0800, qiang.zhang@windriver.com wrote:
> > > > From: Zqiang <qiang.zhang@windriver.com>
> > > >
> > > > Add kasan_record_aux_stack function for kvfree_call_rcu function to
> > > > record call stacks.
> > > >
> > > > Signed-off-by: Zqiang <qiang.zhang@windriver.com>
> > >
> > > Thank you, but this does not apply on the "dev" branch of the -rcu tree.
> > > See file:///home/git/kernel.org/rcutodo.html for more info.
> > >
> > > Adding others on CC who might have feedback on the general approach.
> > >
> > >                                                         Thanx, Paul
> > >
> > > > ---
> > > >  kernel/rcu/tree.c | 2 +-
> > > >  1 file changed, 1 insertion(+), 1 deletion(-)
> > > >
> > > > diff --git a/kernel/rcu/tree.c b/kernel/rcu/tree.c
> > > > index da3414522285..a252b2f0208d 100644
> > > > --- a/kernel/rcu/tree.c
> > > > +++ b/kernel/rcu/tree.c
> > > > @@ -3506,7 +3506,7 @@ void kvfree_call_rcu(struct rcu_head *head, rcu_callback_t func)
> > > >               success = true;
> > > >               goto unlock_return;
> > > >       }
> > > > -
> > > > +     kasan_record_aux_stack(ptr);
> > > >       success = kvfree_call_rcu_add_ptr_to_bulk(krcp, ptr);
> > > >       if (!success) {
> > > >               run_page_cache_worker(krcp);
> >
> > kvfree_call_rcu is intended to free objects, right? If so this is:
>
> True, but mightn't there still be RCU readers referencing this object for
> some time, as in up to the point that the RCU grace period ends?  If so,
> won't adding this cause KASAN to incorrectly complain about those readers?
>
> Or am I missing something here?

kvfree_call_rcu does not check anything, not poison the object for
future accesses (it is also called in call_rcu which does not
necessarily free the object).
It just notes the current stack to provide in reports later.
The problem is that the free stack is pointless for objects freed by
rcu. In such cases we want call_rcu/kvfree_call_rcu stack in
use-after-free reports.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BZNBRaVOK4zjv7WyyJKeS54OL8212EtjQHshYDeOVmCGQ%40mail.gmail.com.
