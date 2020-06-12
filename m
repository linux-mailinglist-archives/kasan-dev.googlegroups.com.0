Return-Path: <kasan-dev+bncBCVJB37EUYFBBBNSRX3QKGQE5WHVZMI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43d.google.com (mail-pf1-x43d.google.com [IPv6:2607:f8b0:4864:20::43d])
	by mail.lfdr.de (Postfix) with ESMTPS id 064AA1F76BE
	for <lists+kasan-dev@lfdr.de>; Fri, 12 Jun 2020 12:29:27 +0200 (CEST)
Received: by mail-pf1-x43d.google.com with SMTP id b186sf6774417pfg.10
        for <lists+kasan-dev@lfdr.de>; Fri, 12 Jun 2020 03:29:26 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1591957765; cv=pass;
        d=google.com; s=arc-20160816;
        b=DbFLLi9+HyO1tj1l/JOR7jfuJGwFmEgaAVdZMpblRoGy82uU69iHDW2b0h4987Ukjd
         XnWhJzo6JZB7+rp3rUJbjsLmsqRLMk9DnxYThNoMP/jse9MsxMvqMG169CFGoHGhiJyM
         8xC6Pz9h5y7MCrEBi2blrpLEVNB3MeDH+f9lP266wPThaleIvoepWjqUn9jdKojHU89I
         JSYKc5j5A394AScW9fnKjNbAhedRzGlKFDhaC7mP3OKHXFETTvjyhYTLFEAwMQnqrlRg
         1/P5QfxJpfi6YNpFJIbIigqf9lxXuvbEv/1GEC6RaGjTX72aPstVdFjSLJW+DyRpx8+/
         Nm5A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-disposition:user-agent
         :in-reply-to:mime-version:references:reply-to:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=eU4vox2tDJwyMbcd3UBzWfg38siHXyqx2oFZz5Lasb0=;
        b=LSCNcDj/DxD+uTkTjuVwPQTaRj2Yvp5wIAZ2l7upDBKSibYGB65W5WsSeVxV8RJYHs
         U49Kkm6QI0izv6l1/NHQ/utnYpmlgKwTEYGpMjczNoDvr0KH/AsiRBSL7pC1of3r+ehk
         FT62Gits+WFH1NieClhzwGaTUt/kJEIuvqRJi0QVyZw52f78v/d8kRImvFtzeH7qXCki
         CoyxSq2XWUYJqIpXwNrdqaGAdNOuV0+zbJDxglx4V7TIsprYKlgmhUqf6BEdtWvEqDYG
         k9y/Dd9nLYp1Wx+SprD5IByfvqdhtdfwXy9oRcqId5vDntE+rejoBX/bWT4cCbQBUaZe
         5uGw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b="YiO/eYym";
       spf=pass (google.com: domain of jakub@redhat.com designates 205.139.110.61 as permitted sender) smtp.mailfrom=jakub@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:in-reply-to:user-agent:content-disposition
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=eU4vox2tDJwyMbcd3UBzWfg38siHXyqx2oFZz5Lasb0=;
        b=GXEB9bpWNHBZP/9fGL3f48/a0lCku22r47zsl5F4tRnXwEXiOhCHa2y/WMQcOzY2wm
         jp02/zUxivZanXHQGEY64q9TR3M88akMBsMCA8/se5FaB3mc3EXeePaThrgWXC75OJLr
         1eXhhniIdzRqQZ/Gv7X1Zgjjfk0xa+B5Pu1A0u93PwPJRr7hS/RSq+A0OPDt4v4NMHk+
         WT6Lvgg3notK9Ie18aqGJKryj6r9ReMP4GFjkY9xJT4r4b+tvEX0r74uMHOhopF2P3OO
         uxdsZ8KLoiPXEOYXlM+glbSuADP8Yg6ubQfY9daT1dkiZqccDXMBsyQKj/3467ic2DyU
         k5bA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:in-reply-to:user-agent
         :content-disposition:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=eU4vox2tDJwyMbcd3UBzWfg38siHXyqx2oFZz5Lasb0=;
        b=DVVkQQHO8Y2Cl/QuEaNXdwL+QILB6IM/XX91mnUGl+RgMxv05PCypfGLGiUvdybBCX
         UEvDrG7TSq+KRPK6MA8IAllT0jcJRBTLT+CevydSuQuHVIVJaNj7sq8gSgLwnsDx61uA
         Z22acdzSXXsVC4JRTwbNYO4BZwr+xuY9spXDsYM/w1FVOXKibvtV0mShnCPaxt4CIdq6
         gEHG6CHTXR52ObjRgAXbcQk+xXRYIz0/8Eck6WPms47DvmRT+Yhf7OdW1PoIKRJ4mqDA
         lico1gV73QsJA1h0kl8sNAi0QOphuyA+6RVBcprkrsQanEQ9WFoOYoT7WD7jhTCR3Uxy
         bMFQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5312ldpcBusUOqy1pXMiAj0XWBwtu0ZXQI+IWUrJXsEPHY+L/CsO
	VjiZwej8uTL4Ws52jeoNeAU=
X-Google-Smtp-Source: ABdhPJxQUgfPjLAOTzhmaFydJqAR5bmOsp1/pBEIYW+qBFBK+hVWemUyj/4NeJnbGRgVgxyAu3o64w==
X-Received: by 2002:a17:902:207:: with SMTP id 7mr11365258plc.169.1591957765429;
        Fri, 12 Jun 2020 03:29:25 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:c253:: with SMTP id d19ls2206668pjx.2.gmail; Fri, 12
 Jun 2020 03:29:25 -0700 (PDT)
X-Received: by 2002:a17:902:c14a:: with SMTP id 10mr11224840plj.222.1591957765034;
        Fri, 12 Jun 2020 03:29:25 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1591957765; cv=none;
        d=google.com; s=arc-20160816;
        b=H4/+VZo74x7UulbqqUuU2CZ/rPqwmmDsFF3mSOQrxT2gbm3ccKDRXr6ZgFcXnojjRv
         ag+RfqJrsm2Z6z/Ptgu1v0vv+T5Qm3/PqXJutG+0rGByrJIv2Zu+8VcGMlZ699gLtbR9
         5NgBETS8KsO7U3Jv9sBAAVI20aaBRoe3MXinspuxNiCsLLUs/mKOuFUWXkqSY1i78gHr
         dxv20NdLskqN6xnb4VMe2ArW/53Z8pr/FHB5aQO7X5V++kfQ7Wzo7ENdt3+zmms/fjL6
         eoK+EGMH2N0u2n/RC9rCaR1HGcn3RDuC40fq8xOp8ZnCf73dBgepz11eKi2DGSvRo17Y
         cbdQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-disposition:user-agent:in-reply-to:mime-version:references
         :reply-to:message-id:subject:cc:to:from:date:dkim-signature;
        bh=SeHMhJlEx3sc/KQDY0K2uyPl99GyDwFk7J0cjnG+2mM=;
        b=MkyAOy1+xAjMUFQR7u6tpfG/BPPPGEdXGqPCCEkj+YA0R7sihiBEiOnK7BnTNdA5/9
         GoZqhhILxio6JA1kvWb1L5qDPGb2xWAlOzl5dYGHtCjReovWIcIOyUT7MXl+TfsIz0rN
         jnUq4ULlIZKTrQq1szFWtIsH/aZjWsRY5bE8ZslqAZ527nmJNXWSXtJph9JpziT6c7M5
         6zqUrKfVaVK7p3iVEIjt6PJDBBU/6FnDj2A/LXX4MfO1PfHfEQdoe24jSAPsGb1dfnUe
         KWnnPMtPeSvHej69cT2DXXGY/MYm8Gum4jg8anPA3HcS0z/9VBHxRHSyE0zPFPBcqBf6
         e5Dg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b="YiO/eYym";
       spf=pass (google.com: domain of jakub@redhat.com designates 205.139.110.61 as permitted sender) smtp.mailfrom=jakub@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-1.mimecast.com (us-smtp-1.mimecast.com. [205.139.110.61])
        by gmr-mx.google.com with ESMTPS id x14si393136pjt.2.2020.06.12.03.29.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 12 Jun 2020 03:29:25 -0700 (PDT)
Received-SPF: pass (google.com: domain of jakub@redhat.com designates 205.139.110.61 as permitted sender) client-ip=205.139.110.61;
Received: from mimecast-mx01.redhat.com (mimecast-mx01.redhat.com
 [209.132.183.4]) (Using TLS) by relay.mimecast.com with ESMTP id
 us-mta-362-BY5RZ_yMPTqIQZOo0-_nVQ-1; Fri, 12 Jun 2020 06:29:20 -0400
X-MC-Unique: BY5RZ_yMPTqIQZOo0-_nVQ-1
Received: from smtp.corp.redhat.com (int-mx05.intmail.prod.int.phx2.redhat.com [10.5.11.15])
	(using TLSv1.2 with cipher AECDH-AES256-SHA (256/256 bits))
	(No client certificate requested)
	by mimecast-mx01.redhat.com (Postfix) with ESMTPS id 9F250184517B;
	Fri, 12 Jun 2020 10:29:18 +0000 (UTC)
Received: from tucnak.zalov.cz (ovpn-112-94.ams2.redhat.com [10.36.112.94])
	by smtp.corp.redhat.com (Postfix) with ESMTPS id 0286E7C41E;
	Fri, 12 Jun 2020 10:29:17 +0000 (UTC)
Received: from tucnak.zalov.cz (localhost [127.0.0.1])
	by tucnak.zalov.cz (8.15.2/8.15.2) with ESMTP id 05CATEHe009356;
	Fri, 12 Jun 2020 12:29:14 +0200
Received: (from jakub@localhost)
	by tucnak.zalov.cz (8.15.2/8.15.2/Submit) id 05CATCrp009355;
	Fri, 12 Jun 2020 12:29:12 +0200
Date: Fri, 12 Jun 2020 12:29:12 +0200
From: Jakub Jelinek <jakub@redhat.com>
To: Marco Elver <elver@google.com>
Cc: gcc-patches@gcc.gnu.org, mliska@suse.cz, kasan-dev@googlegroups.com,
        dvyukov@google.com, bp@alien8.de
Subject: Re: [PATCH] tsan: Add param to disable func-entry-exit
 instrumentation
Message-ID: <20200612102912.GJ8462@tucnak>
Reply-To: Jakub Jelinek <jakub@redhat.com>
References: <20200612072159.187505-1-elver@google.com>
MIME-Version: 1.0
In-Reply-To: <20200612072159.187505-1-elver@google.com>
User-Agent: Mutt/1.11.3 (2019-02-01)
X-Scanned-By: MIMEDefang 2.79 on 10.5.11.15
X-Mimecast-Spam-Score: 0
X-Mimecast-Originator: redhat.com
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
X-Original-Sender: jakub@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b="YiO/eYym";
       spf=pass (google.com: domain of jakub@redhat.com designates
 205.139.110.61 as permitted sender) smtp.mailfrom=jakub@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
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

On Fri, Jun 12, 2020 at 09:21:59AM +0200, Marco Elver wrote:
> Adds param tsan-instrument-func-entry-exit, which controls if
> __tsan_func_{entry,exit} calls should be emitted or not. The default
> behaviour is to emit the calls.

If you want that, I wonder if the spots you've chosen are the best ones.
E.g. shouldn't
  if (sanitize_flags_p (SANITIZE_THREAD))
    {
      gcall *call = gimple_build_call_internal (IFN_TSAN_FUNC_EXIT, 0);
...
in gimplify.c have this && param_tsan_instrument_func_entry_exit, so that
we don't waste a call or several in every function when we are going to dump
them all?
And in tsan.c, perhaps instead of changing instrument_gimple twice change:
            fentry_exit_instrument |= instrument_gimple (&gsi);
to:
            fentry_exit_instrument
	      |= (instrument_gimple (&gsi)
		  && param_tsan_instrument_func_entry_exit);
?

> gcc/ChangeLog:
> 
> 	* params.opt: Add --param=tsan-instrument-func-entry-exit=.
> 	* tsan.c (instrument_gimple): Make return value if
> 	  func entry and exit  should be instrumented dependent on
> 	  param.

No tab + 2 spaces please, the further lines should be just tab indented.
And s/  / /.

	Jakub

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200612102912.GJ8462%40tucnak.
