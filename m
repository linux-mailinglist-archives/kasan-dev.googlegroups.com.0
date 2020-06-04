Return-Path: <kasan-dev+bncBCV5TUXXRUIBBFEO4T3AKGQEKYRGGWI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb40.google.com (mail-yb1-xb40.google.com [IPv6:2607:f8b0:4864:20::b40])
	by mail.lfdr.de (Postfix) with ESMTPS id CBF7A1EE6C1
	for <lists+kasan-dev@lfdr.de>; Thu,  4 Jun 2020 16:37:09 +0200 (CEST)
Received: by mail-yb1-xb40.google.com with SMTP id c17sf8013387ybf.7
        for <lists+kasan-dev@lfdr.de>; Thu, 04 Jun 2020 07:37:09 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1591281429; cv=pass;
        d=google.com; s=arc-20160816;
        b=Q+fjVzC6CeDoZxwVT4GFQ1rczu8yGZjsv61tSgFKe6J0ksnTiURcNmOMXwFqTj5RQu
         pbs8FJ1H56iea6PgsaDQTn+Cbe5Vd1SPa70onh0d0a3txmIG5CSyvnzsf2Q0rM+6TMU7
         TaVD9Z0TqqMeR0lNuQJrau3IrIqPBkVTFdhstECACT30vDfe2RzhG7ufh5b3bRPM41rv
         9jTSljlr0+XZAcHw4fJ8rbRXktrzHC3fQYFKior0aYQ7x9mMagc7xbcGGlIscRXcAl48
         0hc+1rMirc2AEZSyVndxjgiJ5mEgI+KMfsigedXBy7qy/G6V2D9n9Z8f5kuFD11rpakz
         uYbw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=k3jakk4Ps19ngs0DAbIC2nQSM59c8WvJm+7ESXsj4b8=;
        b=q1P9NiQN/hfBFUrVUWq9fl/TOpJGukGspgEQ6cC1ETTDxF4S4n5sD2mdN03CJkKWfJ
         V30dv4ML6zIqsAVwec+Y5x7HerEhLf0cDSN0JAq6kICSbEDdG7EsiBWfT4G6J+zEsu3B
         lmhgTgp3PjSEiU7Gl9pu7UpEpuFw0+odQgzMplHOIpgockSbS83GZd2E3EBvKf597FM0
         CjzIQJcM8JogV6368ReDbxFtaN0nbSl87vCA8pN7HVACtdhxah+U2tSpSFl5u8rkyxTi
         CRbwdTc+lcD4bgC/XQNet9iKoYFvArmK4suwRvRTT/BUYL+oWDoMRAJ52otari3fdwyI
         3Tfg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=bombadil.20170209 header.b=QXaWkkQ9;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2607:7c80:54:e::133 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=k3jakk4Ps19ngs0DAbIC2nQSM59c8WvJm+7ESXsj4b8=;
        b=cwyS0bDzZFKHzVdjUlFdHcps83Vagadq1lD0Mr2o4BIUVkM/GpUjtqoNG+DowFna3Z
         BkmZDaT6c44qqYc6brfNZyyOydZqXHz2I2flIC+sO0WHJJrEDVSXkgHdcbBsXPL06OpD
         8Fyc9a8GwjCrxtcauFeqk0XLylWXV+qzpFvlqeIPbhFtce0t9HLZGN5UgZSYa6QEopLi
         aZcMDXUcUyymTQdcGqIB/cAq5vXefQ9f0mt9WmmPnmJmwQfU9icd1jxp39Xi2LEJ2hWy
         WSrU+CcgUU7qOfwIJmuS53khvD3RJ/Q9LAoBa9oCBud8eD6MD9BYSSsMJKI4fGfRxzzn
         lcLg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=k3jakk4Ps19ngs0DAbIC2nQSM59c8WvJm+7ESXsj4b8=;
        b=do5Ni3OXGKPsQFFwTVk9lkVKwzfSVMw8CvDaT3QeTqvdpRi1RBtuZlJzUA/iQAWmzQ
         nZLBza7ynWP6okXXfMPy3KvCNtAM0a+kDYBMWPyu3IccN/Kru7U6ws8TVFHa0xR2CXKe
         zr2V/tK7njR5KSLyM/45galRz23t57FfkBS9XYdqzkGlzYyXPzvD1u5PlgFk733T74xo
         M2YpSBfnjffjYwuv07/Vfoi090/hVGzZ2xSmAzElkma12GQKJMD9Z7eBlsXpL6Cq56Os
         nE+yeKpDLq+NnTxHiWoicA2pAzXjy+WSEvIbus7x2PpnWoK4I0utkSCspeN2djUHbgLz
         HSQQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532ov+8UtONfqebpngoCLdqzo9FprI1MljH7OLD+WADZA3tFERAz
	QNUWUSNSk8DekbDu9mopBg8=
X-Google-Smtp-Source: ABdhPJwhDD+Ec9zr6YIPtMh6YVUzctYXxk5Mha2VEqzjJKp+HvfLDTLc+31YaT5E8tjfpXN3g4nQ8w==
X-Received: by 2002:a25:bd47:: with SMTP id p7mr8414874ybm.39.1591281428866;
        Thu, 04 Jun 2020 07:37:08 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:be4d:: with SMTP id d13ls2580253ybm.2.gmail; Thu, 04 Jun
 2020 07:37:08 -0700 (PDT)
X-Received: by 2002:a25:7c46:: with SMTP id x67mr8192549ybc.279.1591281428531;
        Thu, 04 Jun 2020 07:37:08 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1591281428; cv=none;
        d=google.com; s=arc-20160816;
        b=TT+FQZQPHyesKGID2drTlcx6wHMw3Gz/pDgAqb9/FM35B6jNoOcub/Rkf1dq1l08B8
         Endw8SJnebiwTvet7fTD2p1Bo8RPep5hAmg7BZCKsbYF0XmODSLTeY1E/MjjsI9Jde1c
         Q0dwhnrud8YmneNfctn+sSsfnC5RI9TKmsHQN8NMHhkhqs0JqpHadRbBpz3Dwl8ZjQUc
         1nepDn9UmVF7N5MwKwiwdi7XDPOkbq2EQd4lq11c1ut9OHzk+iy+DXIkl5wWLDCK2fbc
         TLwt6jCPNwEhs9nKtkI5UuLSTCvjWV8HZBX3ZPjlMAJEBs4cDDkTzVM7TYiI8JYDVAU3
         ux1w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=2tvTdBck+ipf49OrMMt2ID3t3c6rSt/FosoZQVmo6lI=;
        b=Ln4wKzFzSGgKIHO19+/9/87YJeXpDFOdjHzfsw2w9+zS/PF+vKLofbkbT4Y1h/NJn6
         Irle0Mo4cWp9VvK4x7Tgq9yAaHRxaLCAwtusqVVgIoHaRXqiH5z+fe+C2oMWIy0+UvhA
         STCBYwVTlNH8lLUQb+af7OHbhDYLihCTV8QZ24iQViQjHic0G1SGpqRA9L+/X4VR/7Kj
         QspkP3gFGmbtSx3NzezrFcwIJPWoDalPdrUDtOCn+ziPdONoOlcpntNo2FP1Sw8l2Pqv
         W+GdujhskNG4suZAyIp9O/hEDPvZo074Hor68/k3TGy4yVX92JlslzUbwaRYhyPy9KoP
         6Q5A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=bombadil.20170209 header.b=QXaWkkQ9;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2607:7c80:54:e::133 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from bombadil.infradead.org (bombadil.infradead.org. [2607:7c80:54:e::133])
        by gmr-mx.google.com with ESMTPS id n63si302272ybb.1.2020.06.04.07.37.08
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 04 Jun 2020 07:37:08 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2607:7c80:54:e::133 as permitted sender) client-ip=2607:7c80:54:e::133;
Received: from j217100.upc-j.chello.nl ([24.132.217.100] helo=noisy.programming.kicks-ass.net)
	by bombadil.infradead.org with esmtpsa (Exim 4.92.3 #3 (Red Hat Linux))
	id 1jgqzQ-0005iR-Kq; Thu, 04 Jun 2020 14:37:04 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id 2F99C301ABC;
	Thu,  4 Jun 2020 16:37:01 +0200 (CEST)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 1000)
	id 20B3720E06071; Thu,  4 Jun 2020 16:37:01 +0200 (CEST)
Date: Thu, 4 Jun 2020 16:37:01 +0200
From: Peter Zijlstra <peterz@infradead.org>
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Marco Elver <elver@google.com>, Borislav Petkov <bp@alien8.de>,
	Thomas Gleixner <tglx@linutronix.de>,
	Ingo Molnar <mingo@kernel.org>,
	clang-built-linux <clang-built-linux@googlegroups.com>,
	"Paul E . McKenney" <paulmck@kernel.org>,
	Dmitry Vyukov <dvyukov@google.com>,
	Alexander Potapenko <glider@google.com>,
	kasan-dev <kasan-dev@googlegroups.com>,
	LKML <linux-kernel@vger.kernel.org>
Subject: Re: [PATCH -tip] kcov: Make runtime functions noinstr-compatible
Message-ID: <20200604143701.GC3976@hirez.programming.kicks-ass.net>
References: <20200604095057.259452-1-elver@google.com>
 <20200604110918.GA2750@hirez.programming.kicks-ass.net>
 <CAAeHK+wRDk7LnpKShdUmXo54ij9T0sN9eG4BZXqbVovvbz5LTQ@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CAAeHK+wRDk7LnpKShdUmXo54ij9T0sN9eG4BZXqbVovvbz5LTQ@mail.gmail.com>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=bombadil.20170209 header.b=QXaWkkQ9;
       spf=pass (google.com: best guess record for domain of
 peterz@infradead.org designates 2607:7c80:54:e::133 as permitted sender) smtp.mailfrom=peterz@infradead.org
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

On Thu, Jun 04, 2020 at 04:02:54PM +0200, Andrey Konovalov wrote:

> > Now, luckily Joerg went and ripped out the vmalloc faults, let me check
> > where those patches are... w00t, they're upstream in this merge window.
> 
> Could you point me to those patches?

git log 7f0a002b5a21302d9f4b29ba83c96cd433ff3769...d8626138009ba58ae2c22356966c2edaa1f1c3b5

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200604143701.GC3976%40hirez.programming.kicks-ass.net.
