Return-Path: <kasan-dev+bncBCVJB37EUYFBB34HUH2QKGQEPYECY3A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43e.google.com (mail-pf1-x43e.google.com [IPv6:2607:f8b0:4864:20::43e])
	by mail.lfdr.de (Postfix) with ESMTPS id 944801BC209
	for <lists+kasan-dev@lfdr.de>; Tue, 28 Apr 2020 16:55:44 +0200 (CEST)
Received: by mail-pf1-x43e.google.com with SMTP id t9sf20844126pfq.14
        for <lists+kasan-dev@lfdr.de>; Tue, 28 Apr 2020 07:55:44 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1588085743; cv=pass;
        d=google.com; s=arc-20160816;
        b=o7oNy9vV3QlCMOPLAb2DGfo+Iya/dcz8jVrtMrdanc/R1A1jTzxHuHheS0J7yAWMDH
         dbxC4uW7iFPYTXt331xT26wR93ZO6liWp7/yXvi90T2z7kHvctWi43dr4p+i8EJxL1ik
         zEJ8Bh5HZyUfw9jbj6PZdziOuvXx7i0v1fkDI9tIEypWUSLaBABOwK/U4oc5uWcHXEVK
         iQRbgpbEnWTZWxzsG0643MP8i6wRqK86PeqtzMuTAYanvcQ+PX0jw5HoLuQb4O5qw23e
         rC22TlFYn+rkOdNR5jBCdgh4IH8mT/9hFs1GQhYwi1C5IGV3UoJDExO7reZv/efmmW4Z
         dLAQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-disposition:user-agent
         :in-reply-to:mime-version:references:reply-to:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=abKkwKJzJ0ni4aWGZ3j2+hKurai4VFglE5J4ClFmx0A=;
        b=aNgk0LKu5uuY0rQIxW5n9ZtbMQPAU3C6O+ITMWDvPIXTEkkoC0o3683Q7XZrTBnksf
         p26Ra+A2K9WW/IZ9bDzANGxpAdEykrIMsRq910G7RRxj3evpsZpNffkKbsRvHPR1MCQs
         b59260eN9JGtf9LPc2TnJaSm/BV38lfEZ6eRdS+9EUloUCg10OPPUM56gpeiunP9VR1S
         Tm4Pdi2V0zaholwulYy3N89B9u9541tsek+W+t10Cj3qkCdOjqa9yt0HA4QWvJEpAtrQ
         UEQ6nsGu3DXuoio9LWafA79m3gA/lZAadL9yGdz2Rl5CnrvhhNXtrhKez/EviJYm7fQ8
         rWRQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=Q6maEc9B;
       spf=pass (google.com: domain of jakub@redhat.com designates 205.139.110.120 as permitted sender) smtp.mailfrom=jakub@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:in-reply-to:user-agent:content-disposition
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=abKkwKJzJ0ni4aWGZ3j2+hKurai4VFglE5J4ClFmx0A=;
        b=hZ10+Fu0vb5VOyc5F3b7r2SfhH2+EwbN90H1CL1U40CcpdPsom/i6ewLyiZLutArKG
         V+oo6PHk1duC/ERJRzMhhOiwY6gB0tu+vfdLtCZXu7sBrWBaJRNeR339dSwTebaC3VZU
         tDaQIPLYFQ8uJ96ZS28qbSX2iGfmqe1+wVM5/a6hJ5/t59AwzFHqe78FGQLw45uG7rLb
         qHKDHnl6XohBZszut9vRurppJdLa4JMj3hbH/wHaFjhuAvlopJAOkUWMekRPft4qJP5V
         7YKelEz2ABc1ebJXmpMTBckZ9k6xLz9sPeHaQU39Bi/UjLwcFO9qpG3o6xZNUizEt+HH
         rVEQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:in-reply-to:user-agent
         :content-disposition:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=abKkwKJzJ0ni4aWGZ3j2+hKurai4VFglE5J4ClFmx0A=;
        b=qZdsxQ8QIJHov5V1WorAufRPV+UTsI9ysaVY3S6iAOXPAwUARvKiZGg7j70CTW+rpp
         2bC5QjOU0wrnE7BqiPLcLOUk3Ia8wNQVQn2dTw6jY6W950cvS7+XMr/tiGW8G362c++9
         hZQyrc5n7mvggpgW5FduJSRlG9zcKx1uoiF93DIoSA7XwxhNez91hwuNKgia+BUlN60N
         8RYvqlviW//VBnVTYEluwM+lB35rGfx5PHIWMuEql11qAxvRLCi+5VfdhXrXS2H7TYBz
         ix2WQwKsyMazd2hmyS0p/NpkwmD5WvHhXrl7Wz/y2lEvY7lPYhRC6MHeCxUCvIIUEWaL
         KRdA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AGi0PubwoTcabvDfdz//VfxuBstWuo2CDYsP+BFb4hj3r2tfgq4jgedT
	e/GnUkuXrqwcC3VFRaxB/T0=
X-Google-Smtp-Source: APiQypL5E2WeTiwkK9qLKOaWrePRYAy94hMrgC9yPe+1HafnZpZ/HGYtNPPIUsCjr5k/FRby3K489A==
X-Received: by 2002:a63:5a5d:: with SMTP id k29mr9241004pgm.176.1588085743132;
        Tue, 28 Apr 2020 07:55:43 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:1657:: with SMTP id 84ls16016975pfw.7.gmail; Tue, 28 Apr
 2020 07:55:42 -0700 (PDT)
X-Received: by 2002:a62:4ec8:: with SMTP id c191mr16026760pfb.30.1588085742732;
        Tue, 28 Apr 2020 07:55:42 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1588085742; cv=none;
        d=google.com; s=arc-20160816;
        b=VLZ2a/caDUbzYGpBIffYkk41musgvh8S4kguJ8+ItKY4diJTjjgyKoDvcqF9J+I7MX
         818fIvzwWFkAt+bxbqvbxkHB7w6ebvRDRRSkUZht3nFoqgwMySn4iuNXpnrx//HdrGzl
         xEG7XW3tnMHlQkp7IwXbeaH1FBt+X8324oEYpLwS6EKlxNRj7jHAcLDqPDnt4nq2iHVn
         B0/+qJHxdA0DYdXitgKiZtMx3z5nEB8GNQys+yOV4KTOGqKcJNoLH+op4K6WajEDGveS
         Je0zUGV/HzmxE+ECc91z2P36dTSBrfIoqkL8PGtiOSy9dT53Bv19JYb2aI4D9v6O81nC
         lAkw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-disposition:content-transfer-encoding:user-agent
         :in-reply-to:mime-version:references:reply-to:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=usgYA0/PQa+FYvlL6ufLDd3h++u8RraOk5/WGCux8n0=;
        b=qfBlcDSCJS38VReVEARsmsmxA/iwL3KvxYYXccjKEbi95cqOI9YGVdOUX9jfCGywRL
         BxvtKesYLhULU1gCkJ2I+fqUsDJYwmn4tsbH77Q/gpnTCcyNS6HRZvSFGYlLoIBDh/gM
         xkbkq2USw0aN7VLxnrHdhOfVjriTGGPudtqEYpspUUgIL00tFLQevkEIFMu0nInon0ku
         d2qWf1G0qDxGveeCXjjStS+t2sqULeG1lxrac4ReZO7IQH5sSJlPeNY1wzZ8z7RwFUq+
         gNL4/Zvj9anSGI6DoNN7KtWOBAnmNRPstI4IIaog8WSf2bkShiG5nrsY5f1POJjptbg1
         tAeA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=Q6maEc9B;
       spf=pass (google.com: domain of jakub@redhat.com designates 205.139.110.120 as permitted sender) smtp.mailfrom=jakub@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
Received: from us-smtp-1.mimecast.com (us-smtp-delivery-1.mimecast.com. [205.139.110.120])
        by gmr-mx.google.com with ESMTPS id g23si336623pgi.5.2020.04.28.07.55.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 28 Apr 2020 07:55:42 -0700 (PDT)
Received-SPF: pass (google.com: domain of jakub@redhat.com designates 205.139.110.120 as permitted sender) client-ip=205.139.110.120;
Received: from mimecast-mx01.redhat.com (mimecast-mx01.redhat.com
 [209.132.183.4]) (Using TLS) by relay.mimecast.com with ESMTP id
 us-mta-506-I7weKL3FMn66Xc2VRZ5RmQ-1; Tue, 28 Apr 2020 10:55:37 -0400
X-MC-Unique: I7weKL3FMn66Xc2VRZ5RmQ-1
Received: from smtp.corp.redhat.com (int-mx07.intmail.prod.int.phx2.redhat.com [10.5.11.22])
	(using TLSv1.2 with cipher AECDH-AES256-SHA (256/256 bits))
	(No client certificate requested)
	by mimecast-mx01.redhat.com (Postfix) with ESMTPS id 4966B835B41;
	Tue, 28 Apr 2020 14:55:36 +0000 (UTC)
Received: from tucnak.zalov.cz (ovpn-112-104.ams2.redhat.com [10.36.112.104])
	by smtp.corp.redhat.com (Postfix) with ESMTPS id C58BF10013BD;
	Tue, 28 Apr 2020 14:55:35 +0000 (UTC)
Received: from tucnak.zalov.cz (localhost [127.0.0.1])
	by tucnak.zalov.cz (8.15.2/8.15.2) with ESMTP id 03SEtXFn022054;
	Tue, 28 Apr 2020 16:55:33 +0200
Received: (from jakub@localhost)
	by tucnak.zalov.cz (8.15.2/8.15.2/Submit) id 03SEtWAn022053;
	Tue, 28 Apr 2020 16:55:32 +0200
Date: Tue, 28 Apr 2020 16:55:32 +0200
From: Jakub Jelinek <jakub@redhat.com>
To: Dmitry Vyukov <dvyukov@google.com>
Cc: Marco Elver <elver@google.com>, GCC Patches <gcc-patches@gcc.gnu.org>,
        kasan-dev <kasan-dev@googlegroups.com>
Subject: Re: [PATCH] tsan: Add optional support for distinguishing volatiles
Message-ID: <20200428145532.GR2424@tucnak>
Reply-To: Jakub Jelinek <jakub@redhat.com>
References: <20200423154250.10973-1-elver@google.com>
 <CACT4Y+arbSpBSwNoH4ySU__J4nBiEbE0f7PffWZFdcJVbFmXAA@mail.gmail.com>
MIME-Version: 1.0
In-Reply-To: <CACT4Y+arbSpBSwNoH4ySU__J4nBiEbE0f7PffWZFdcJVbFmXAA@mail.gmail.com>
User-Agent: Mutt/1.11.3 (2019-02-01)
X-Scanned-By: MIMEDefang 2.84 on 10.5.11.22
X-Mimecast-Spam-Score: 0
X-Mimecast-Originator: redhat.com
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
X-Original-Sender: jakub@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=Q6maEc9B;
       spf=pass (google.com: domain of jakub@redhat.com designates
 205.139.110.120 as permitted sender) smtp.mailfrom=jakub@redhat.com;
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

On Tue, Apr 28, 2020 at 04:48:31PM +0200, Dmitry Vyukov wrote:
> FWIW this is:
> 
> Acked-by: Dmitry Vyukov <dvuykov@google.com>
> 
> We just landed a similar change to llvm:
> https://github.com/llvm/llvm-project/commit/5a2c31116f412c3b6888be361137efd705e05814
> 
> Do you have any objections?

I don't have objections or anything right now, we are just trying to
finalize GCC 10 and once it branches, patches like this can be
reviewed/committed for GCC11.

	Jakub

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200428145532.GR2424%40tucnak.
