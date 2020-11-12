Return-Path: <kasan-dev+bncBDDL3KWR4EBRBJHBWT6QKGQE3YFWLEI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53d.google.com (mail-pg1-x53d.google.com [IPv6:2607:f8b0:4864:20::53d])
	by mail.lfdr.de (Postfix) with ESMTPS id D7E5E2B0539
	for <lists+kasan-dev@lfdr.de>; Thu, 12 Nov 2020 13:55:01 +0100 (CET)
Received: by mail-pg1-x53d.google.com with SMTP id m11sf3592477pgq.7
        for <lists+kasan-dev@lfdr.de>; Thu, 12 Nov 2020 04:55:01 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605185700; cv=pass;
        d=google.com; s=arc-20160816;
        b=ZZiWo1RrHY7GoRIRBVNcYY5hVif2zGjYswIT02+KZCWqy18RovYIJ5VSrK8H/SvNLJ
         Og+iZzHEfT/BJMFRoP57SQVoMiVO5MyEM/f+4h5GqT9zamr7Mz0LJ0dFkzLj+zQqh0/l
         w3BEsma7QP3OOJpD9BYoWQ6mZgBeqPZfNzGYjXj6yzoJ8kUtLTEue1hnaaSCFlwMeGZl
         d7ePAHThO6FWWwfFHNIGGA8Lc98Q9nDX8xxDVvBA6qD/Gvq/QhtQE9Iu3NhoB6Wsdp6p
         nJe2RivNPAwE5pN1vnZ+5860zlFpTcztNdRslK0fmtbaByXJ9jpyYPVw/FDJFS9TKSst
         A1fQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=puB3KxQcsZW4Mv3BBV3OZKzncQmOOmbd/mY+bUp6Qhs=;
        b=MfBabLkQxeiQWF47d4hl3c/RWnJKlMZFSFz+2+jcxHR6fY/eO8ILS5+kJgtxuWxxaa
         RfND/kJacQI/S9HbEX2GJaS2i2RLwQT70j0CdSUkmzWL5BBjb6PIsqTbuS+ActVQbjjU
         /lxVt6w9AdN6MdiE7kI7Xtyt6Q6EUC3tBfCo2piBWyuxi9a8giIeoPTqoAr+Icps66A1
         rZIDaummcZoh/x5Hicca/PWlVzTPvUN/f5sYG6JIw1RQE7NbYVrUfvbDT13Tq6MyGm2d
         LCAMVLr8SHi009+s7mJlJBOTBaVUCKHvcpLoDw6P4QrxRUp2Yi+p1eVS6PFbe3cW22KN
         g20g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=puB3KxQcsZW4Mv3BBV3OZKzncQmOOmbd/mY+bUp6Qhs=;
        b=Uzv+9r7+vLTB6fcnZkQQPRjwbgn35puECKTeq5H9shm6kgvgrg0KJxy3n49L/U7+8C
         fyA6oADT1toCiU578hJJjonoSGfMPsa90KmVqAnvoefiHbgO53Stz4MQMJ014CW9tcq5
         CIygUM1OzCczsuEWjo26vzE5yV7cyLEIUNFxxFVctUMSvei5ZFm+RlRDjyNRLuVIc09s
         0ACMZVP5CWhjSQJlhRobjK/WO1UmpmIHEQLSr7DfgJjTEFc8dY38zUz5waD/8/p0VyO7
         SKjs3BJn0+utZraQ9KqhASRnn3jwpGlTeThgbX1ZeoAh/LHMbx1NbsT5tKRlGh0vA0nG
         moKw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=puB3KxQcsZW4Mv3BBV3OZKzncQmOOmbd/mY+bUp6Qhs=;
        b=q2/+MvQTd06xEpfALfevlnfSSGq485BWcf26wEUyY5M67Wp8PimmuOhtrYQ8W6pKFN
         XTXMkPffLhttsSe6UEY4SQirDSoXbwRTmiAWUrSVSv0a7nFjJPiOm06BJAFXqiIn1M/M
         nOI0RKq1seHdLofcGSzQzwJ5pei8V7VhqXfUy5aShQZut0GUN1AbjGoe+CdVvKOKfKC6
         4u9kkpKx2Qry47OL3bB6kE2q2Lws54WH1bUxg+ocpzkBFBZk0qYbJg6e4cFEzsumHZyt
         pqy76XKenMUGLByAoXn0fReT96yeaOX0IT8odAx58jWeisI6Se6AsY15h1I9MqETa6uQ
         44GQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531L/nC0hx2RZE8D7v3HZTItZthSK5qS+pl9/SxldHV79N/KmTKf
	0bjAwpayKkwRvbX3dZox/Rc=
X-Google-Smtp-Source: ABdhPJx9HkC3VdvAQQ1Rla2CoZF12liZYc9c5PfWKnFSABW7iEFzwxOaLVgLSccbKk0mGh2Gk+fNLg==
X-Received: by 2002:a17:902:a412:b029:d6:8b91:ecf6 with SMTP id p18-20020a170902a412b02900d68b91ecf6mr914961plq.77.1605185700455;
        Thu, 12 Nov 2020 04:55:00 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:6a85:: with SMTP id n5ls1426859plk.9.gmail; Thu, 12
 Nov 2020 04:54:59 -0800 (PST)
X-Received: by 2002:a17:90b:f10:: with SMTP id br16mr9224747pjb.60.1605185699790;
        Thu, 12 Nov 2020 04:54:59 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605185699; cv=none;
        d=google.com; s=arc-20160816;
        b=RU+MjjAVRuQz4JraiagVTNwtJP0lR8jAAkNJZyDiSv5imWkt3MnyI3wkS+uCOCIhuJ
         lTxFVSOZot1dfYJY7NnkKX2SmseAMO5p9HRcHFLYgtfdiii0eXT2Bgw8SN2pt5XdkCr/
         F7O2OtEqnRYechf46DnYoIUk1MOUowweX3vLSRRxTyVEKTE7VoykEcOJOBhA0vQjGTlU
         s/OOFEBxpRz+nliXOwU48HvbGtb2ns1qnBL4f/nyeVD3B+0tiY8/Wqz8Xv3WxcvN+ozp
         yWbmlTr04wsFuUVDdR+ZM7bJnr5kRrJ7BksNzJM9SKWYJVlgZxEaaeCZtb1mNZQ9xU1e
         ABlg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=UdDP3pjZtrznljrlHAECnZTmEmit63VYkxxHUeKD2dc=;
        b=xaVoZgQqfaEmR6XfgDNbXSGj7VlGnE2IyeNdYHORO5ZqTmfyTCXOA1COZ6kpcwgJQB
         wR+IkJouLdnsUoHOf6hQL4gDPKyyT6Rm7tIF9gGaMJUNu3SykMAe0gyg1TTiwXdgEHk2
         mXUINSzXqrdBBz1/C4aTjYbDQ2vO6vMp19/pAT/wDiycxI9faqDgiUq9xwVkr8JGW7Ez
         bv7orI6jRk/R3wm+s+yqLysc1l4yNxoXfv4Ox84MX7dqYB51LZ+o9WnBKwYsl4f1kS/x
         +6qV7U41uec//VgBaVpmg7tgHN+gqB6mzCW7VTir6wvNLnrEXP+p3kxRPZoWWoCqJ5+p
         Bp3A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id m1si316847pls.4.2020.11.12.04.54.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 12 Nov 2020 04:54:59 -0800 (PST)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from gaia (unknown [2.26.170.190])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id B5E4521D7F;
	Thu, 12 Nov 2020 12:54:56 +0000 (UTC)
Date: Thu, 12 Nov 2020 12:54:54 +0000
From: Catalin Marinas <catalin.marinas@arm.com>
To: Marco Elver <elver@google.com>
Cc: Andrey Konovalov <andreyknvl@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Alexander Potapenko <glider@google.com>,
	Will Deacon <will.deacon@arm.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Kevin Brodsky <kevin.brodsky@arm.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	kasan-dev <kasan-dev@googlegroups.com>,
	Linux ARM <linux-arm-kernel@lists.infradead.org>,
	Linux Memory Management List <linux-mm@kvack.org>,
	LKML <linux-kernel@vger.kernel.org>
Subject: Re: [PATCH v2 11/20] kasan: add and integrate kasan boot parameters
Message-ID: <20201112125453.GM29613@gaia>
References: <cover.1605046662.git.andreyknvl@google.com>
 <fdf9e3aec8f57ebb2795710195f8aaf79e3b45bd.1605046662.git.andreyknvl@google.com>
 <20201112113541.GK29613@gaia>
 <CANpmjNMsxME==wFhk=aSaz19iX4Dj8HBXqjhDg5aG_iR-uk7Cg@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNMsxME==wFhk=aSaz19iX4Dj8HBXqjhDg5aG_iR-uk7Cg@mail.gmail.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: catalin.marinas@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as
 permitted sender) smtp.mailfrom=cmarinas@kernel.org;       dmarc=fail (p=NONE
 sp=NONE dis=NONE) header.from=arm.com
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

On Thu, Nov 12, 2020 at 12:53:58PM +0100, Marco Elver wrote:
> On Thu, 12 Nov 2020 at 12:35, Catalin Marinas <catalin.marinas@arm.com> wrote:
> >
> > On Tue, Nov 10, 2020 at 11:20:15PM +0100, Andrey Konovalov wrote:
> > > Hardware tag-based KASAN mode is intended to eventually be used in
> > > production as a security mitigation. Therefore there's a need for finer
> > > control over KASAN features and for an existence of a kill switch.
> > >
> > > This change adds a few boot parameters for hardware tag-based KASAN that
> > > allow to disable or otherwise control particular KASAN features.
> > >
> > > The features that can be controlled are:
> > >
> > > 1. Whether KASAN is enabled at all.
> > > 2. Whether KASAN collects and saves alloc/free stacks.
> > > 3. Whether KASAN panics on a detected bug or not.
> > >
> > > With this change a new boot parameter kasan.mode allows to choose one of
> > > three main modes:
> > >
> > > - kasan.mode=off - KASAN is disabled, no tag checks are performed
> > > - kasan.mode=prod - only essential production features are enabled
> > > - kasan.mode=full - all KASAN features are enabled
> >
> > Alternative naming if we want to avoid "production" (in case someone
> > considers MTE to be expensive in a production system):
> >
> > - kasan.mode=off
> > - kasan.mode=on
> > - kasan.mode=debug
> 
> I believe this was what it was in RFC, and we had a long discussion on
> what might be the most intuitive options. Since KASAN is still a
> debugging tool for the most part, an "on" mode might imply we get all
> the debugging facilities of regular KASAN. However, this is not the
> case and misleading. Hence, we decided to be more explicit and avoid
> "on".

Even better, kasan.mode=fast ;).

-- 
Catalin

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201112125453.GM29613%40gaia.
