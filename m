Return-Path: <kasan-dev+bncBDGIV3UHVAGBBMUD22KQMGQE5B3AYTA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13b.google.com (mail-lf1-x13b.google.com [IPv6:2a00:1450:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id 4FC3B55964C
	for <lists+kasan-dev@lfdr.de>; Fri, 24 Jun 2022 11:19:47 +0200 (CEST)
Received: by mail-lf1-x13b.google.com with SMTP id bq4-20020a056512150400b0047f7f36efc6sf1104970lfb.9
        for <lists+kasan-dev@lfdr.de>; Fri, 24 Jun 2022 02:19:47 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1656062386; cv=pass;
        d=google.com; s=arc-20160816;
        b=otH8BEU4nY89JkSsvgvjIYijaVkdZOxz71R2bgaFXZdOAeKk5RayR6+i6VF5YAMjqC
         5ilT2P3Fcq9XbDzzHqeaPxa0zIoa1+XMsbVI7lnNBfi6fQgv/NgU8KgCnSV33Rc+9pp/
         ZHxN4zLMCRgmgkLmFoPx/gEbU0aJoteTA2CZkdyxiyzj5C+gT6D+rfFAblwoFfTzROZb
         Vyy4/9Ygx9b5Q0CeXnSqZPE2CAZEMz3HHPZPHjFd+q5IERRRj3vZQGT+AknTdlX4afvc
         YEvdBvTyIbO4IQQtaspSKaPNmTHdHSic1EnntWkvb/CWqtBhimF+XHxOC5TrP3pLItur
         zcSQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=8sYnokkrdP2qYNayHZkSYcUWg9x+SV7l4a8xjMLThsU=;
        b=lWNmBm2jg9t/ZhNE0CxAyA/xYbzAJQezr+ayQ9qY2Bc6EyJdae9Ct4ZVmnykyhUNTh
         roEAcyBY+9Mcz/q7vtrDKhiG+Q4B4/6Bks/q5f5BYdp6VQER/bygrbVUPZ/AioqHnYhx
         HSIrmuEfxdjOwrJvY3R3KdJCo+M7AmsVerLpMVAB9xNiurkabXGTU7j5axyKp6x6OR1r
         Al49Vc7haOuJI+J8Jif0zeqLd+rIxKiHJnBFsfq7JKSMZK2nCjkTx6gsBuWJNCUA9wG9
         0eBWlVT81/FQZXWIisam4uG8NhDF1g4OGmrPP/ucPHw1BglvV2XOaOSMzZpe08jTs1Sc
         8olQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=Pb+MsIID;
       dkim=neutral (no key) header.i=@linutronix.de;
       spf=pass (google.com: domain of bigeasy@linutronix.de designates 193.142.43.55 as permitted sender) smtp.mailfrom=bigeasy@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=8sYnokkrdP2qYNayHZkSYcUWg9x+SV7l4a8xjMLThsU=;
        b=P4htJ6/xm8D5aoh6c1AV6wq339d5+Lq58S73bspmH91Z3Nftdoo4MZafKQAo1/vNlf
         r4UvgmfkVrNfHAMUlKt9z7wD7FWzxQzQW52sJCqhR0spjiJMwLtEAaS+ufrxqnO91bo/
         MtsDeXOYvAQJokxJ7n7gQ4I8VGTUKRmDL9x60c65vEx0h8KCZIt464AojH5bicbJwQ2Q
         HaPVibkuOE+koXBD54/XkkpJjyDw71hIsYBUSwEy83emvtnkjZlj7jZsQv886gSd1ktg
         HDAVMp4z4gesEPlgjQgS438nEZwdeSIUOV8ecYE56toVwTQS3rIFHoi5xdkcIujU/PxV
         p3Og==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=8sYnokkrdP2qYNayHZkSYcUWg9x+SV7l4a8xjMLThsU=;
        b=C8pLG7GRmzR6wUbjKhEMdChik+u2Ql4Xme1cTeZWF6TuKlUnMhclzHPTcOiS7eoi/S
         sehFl+hZCNW1D/X7LdOGlZf8nfKMV/7z5Ay9co9dx4vbfOfrKIzUDZ99ElwXprj5+Ohb
         o/CjRfMkK/fOsoHmHJErnjaL5K5U1wS0EVYrMq0E0hXPO1hsQvuVXmMPSqiVP4GsrQnp
         VXsszwyCOWQPdrKxRtbJ5lSzn4niAEdgz1Hdvi9gRzdnjznJiZ7iDTFw9nxxGm9Um5jH
         4IYwVptgqKcmdhTg3JP2Oxct9pc726BHi1oLrS0tNbLppr5YGCeidGK8xpeyjbr3P5U3
         mggA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AJIora89mRggH+2Aumiztl9XtBFKGLcrygNJyV/6vn3hxt3qesXoeoTt
	rXb5Pf5v5JZqB2zCoFOcQSc=
X-Google-Smtp-Source: AGRyM1unzyrBl7eQy8/FJ5EvDCa+Lg+j6eipnoyvsVv4LLGiqx9uQfPOPkw3nsrPpKcgRg6wgWPCZA==
X-Received: by 2002:a2e:bc20:0:b0:25a:8b8c:8f32 with SMTP id b32-20020a2ebc20000000b0025a8b8c8f32mr6317781ljf.114.1656062386656;
        Fri, 24 Jun 2022 02:19:46 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:b9f:b0:47f:a2ed:7ada with SMTP id
 b31-20020a0565120b9f00b0047fa2ed7adals51401lfv.0.gmail; Fri, 24 Jun 2022
 02:19:45 -0700 (PDT)
X-Received: by 2002:a05:6512:3d1a:b0:47f:79df:2ea8 with SMTP id d26-20020a0565123d1a00b0047f79df2ea8mr8718425lfv.610.1656062385567;
        Fri, 24 Jun 2022 02:19:45 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1656062385; cv=none;
        d=google.com; s=arc-20160816;
        b=vFfQmh4XfRsV7WCo7kl7fwKb1F8pOZTr7YN6i/me2HHfzANru/Hp7a91BKmZbaHXwX
         c41kjafnJ3TtGJTMqpAtL2MQCCxmoli1eX/qfXYOiHbgNXdnyZUgATys8vEWvC2IHiUI
         7/L63SM/d8S5cnMzbE2sNJnm9uj7ePeoErBx4LvjGKpYY6kQdMbeGUHn2Y5ZbII05zn5
         ccONHNEpitxVeCvbEPDqkyojiZ2x0Acb5PnyndUNMgoUIAaSJXsu2eqKN//RcmZvhrv1
         hjcbL0NvO6hMSbYfE67dynkP+4vYPXQZdWy6MJMmbjQEF3/GnMYRcZDpD0L3N8pfnddS
         ebSA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:dkim-signature:dkim-signature:date;
        bh=Cx+bQTWtoAOD6jl0yOfLYrwaIzxse7M0gbo3RmLJABY=;
        b=0DLO0VnzAIh7PdPw2JLUMoAOgxTi7pM/PFOHnXL9srMn/E8TG2186XFiHu0Mr4lpDr
         wctDqC9F+mAFFz/KBv3SlpfnUck4RqIjLfX7HUJRt4GhhLqfxK8Dsx+4BVkniRcHi6y8
         8gnE6FANwccN1J8oo5jxXUC+vMX87OU6K+EMLm92aCnf0uO6L3MJDqqRXPlSlWJk7iZG
         rTXB2zsvJ5sGVCORPBnLQvOAv60Qc9jUem16wTajQi4bn086sEyvBHgM/CzBIvKPcniQ
         1nICFi4D0BnjZGyjYIPq8Mxk785CC8kfA5zMuG4kHo0hxbpcuCgZdX6jPtXMUttmEgab
         9ssg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=Pb+MsIID;
       dkim=neutral (no key) header.i=@linutronix.de;
       spf=pass (google.com: domain of bigeasy@linutronix.de designates 193.142.43.55 as permitted sender) smtp.mailfrom=bigeasy@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
Received: from galois.linutronix.de (Galois.linutronix.de. [193.142.43.55])
        by gmr-mx.google.com with ESMTPS id f12-20020a056512228c00b004793154b447si67503lfu.13.2022.06.24.02.19.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 24 Jun 2022 02:19:45 -0700 (PDT)
Received-SPF: pass (google.com: domain of bigeasy@linutronix.de designates 193.142.43.55 as permitted sender) client-ip=193.142.43.55;
Date: Fri, 24 Jun 2022 11:19:43 +0200
From: Sebastian Andrzej Siewior <bigeasy@linutronix.de>
To: Marco Elver <elver@google.com>
Cc: Mike Galbraith <efault@gmx.de>, RT <linux-rt-users@vger.kernel.org>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com
Subject: Re: v5.19-rc2-rt3: mm/kfence might_sleep() splat
Message-ID: <YrWBr+jiFyZRLufc@linutronix.de>
References: <bf74019da22b3c6a750153cbc74ffe3fcdb0ddf7.camel@gmx.de>
 <YrV+Vu47VDGDQpx8@linutronix.de>
 <CANpmjNO+4uHo8sECw4e+hANQSHP+5UmFrZ2TgeRCsu2iuowYfw@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNO+4uHo8sECw4e+hANQSHP+5UmFrZ2TgeRCsu2iuowYfw@mail.gmail.com>
X-Original-Sender: bigeasy@linutronix.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linutronix.de header.s=2020 header.b=Pb+MsIID;       dkim=neutral
 (no key) header.i=@linutronix.de;       spf=pass (google.com: domain of
 bigeasy@linutronix.de designates 193.142.43.55 as permitted sender)
 smtp.mailfrom=bigeasy@linutronix.de;       dmarc=pass (p=NONE sp=QUARANTINE
 dis=NONE) header.from=linutronix.de
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

On 2022-06-24 11:10:55 [+0200], Marco Elver wrote:
> On Fri, 24 Jun 2022 at 11:05, Sebastian Andrzej Siewior
> <bigeasy@linutronix.de> wrote:
> >
> > On 2022-06-18 11:34:51 [+0200], Mike Galbraith wrote:
> > > I moved the prandom_u32_max() call in kfence_guarded_alloc() out from
> > > under raw spinlock to shut this one up.
> >
> > Care to send a patch? I don't even why kfence_metadata::lock is a
> > raw_spinlock_t. This is the case since the beginning of the code.
> 
> Because kfence_handle_page_fault() may be called from anywhere, incl.
> other raw_spinlock critical sections. We have this problem with all
> debugging tools where the bug may manifest anywhere.

Oh thank you. I had some vague memory of this but could find anything.

> A patch for it already exists in -mm:
> https://git.kernel.org/pub/scm/linux/kernel/git/akpm/mm.git/commit/?h=mm-hotfixes-stable&id=327b18b7aaed5de3b548212e3ab75133bf323759

Thanks for the pointer.

Sebastian

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YrWBr%2BjiFyZRLufc%40linutronix.de.
