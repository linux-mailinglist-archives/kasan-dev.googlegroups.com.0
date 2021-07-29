Return-Path: <kasan-dev+bncBC7OBJGL2MHBBP55RKEAMGQEPC4RFIQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x93c.google.com (mail-ua1-x93c.google.com [IPv6:2607:f8b0:4864:20::93c])
	by mail.lfdr.de (Postfix) with ESMTPS id 5BF343DA312
	for <lists+kasan-dev@lfdr.de>; Thu, 29 Jul 2021 14:27:44 +0200 (CEST)
Received: by mail-ua1-x93c.google.com with SMTP id c11-20020ab030cb0000b02902a6696b6acdsf2355393uam.7
        for <lists+kasan-dev@lfdr.de>; Thu, 29 Jul 2021 05:27:44 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1627561663; cv=pass;
        d=google.com; s=arc-20160816;
        b=PI68Ghg+JS+C7VJsMb0TNPC2FuoDcSEo00av+WpLRIiK3UaCdC+Yc9lasTgse2IZJ5
         07npXnDvyX4rQ/oedsw0v5bOtKDZAmOAVXgzon26nck04U0vuqaVc9ExJXdhSAwSFK7Q
         erno73v/eaefcWptSCe/Cos01l4EoMzLRGSBwx7LWOoG4B20izL/dD/Qp5FdTqpPD7MO
         8+E3g932KdGgYlCeJWSZ8BDIaYfW/i2bIS8CGA6Z3nH6+hemosbK9+2V0IzDySLbQtqq
         bpPk6aFkPwqUgKXUeLylUQKTl0EWhyPmgN6rTmh/02cRhVOCyE0I0b0TpJhASMMuw4MO
         ymUg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=TQdZB90acknguCGa17nnXL66ht7CWMA6blc/qvNliP4=;
        b=ZGLO+aZyYGctEHB1HurKJTYd1xpr+AZxMlPsosLi4zOOjsin00IPha9iL8HYtF4WpL
         SLxaZKM/D43iO37ckoBtFZ7dRhWxS3y9dAVpsTPx7j5G7+ex20PU8zrAePnVKgAsJBB/
         XMkWMK0c4OoHFsyV1Gv0yS7Pl69IsDk1GIHZC6UjQ1mG6gRKP1zgXyz51NejbaM+an+0
         hNG6N5ZjPeIA3K7nK0bGLeCdBDBqyA7sc0sDDScMzO9xPWF1TNZDTJuLR6zUjZ3l7rej
         amhj54vABpR2tWa4g+D1eaiBXXFGeXxP5zUALuLLaaGLrJGSHI3hMwZcDI8f9jFmROiL
         sSXA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="ml7Q/Yn+";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c34 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=TQdZB90acknguCGa17nnXL66ht7CWMA6blc/qvNliP4=;
        b=RVSnfY6PQXSgVGjzCTEfpx9Vxd8j29Y6LaToedUulknsnnzsT/7TORaFs/Pwxp7Dxn
         5bDsKnRkfNcNhxlMJYhRxwZsyrWdxfFr+WoEvHhkwHSQ7800N/pRHBGqYerHkYkQxChl
         zOqLrjbDgHeV5DJqFZqNKgWTBBTaxTtttaRuB57oMBXwNrzw6qhtnDDFOjxGLy+sYvzI
         j7X7usOxFD7cDC8q8MGDVdhnZHBqDo8laaIn4yMA+akoiZVqIAZvDL6dHnXZpUc4Bwu/
         rjF49tn21NKIsSQAWuiUESbFxYFdbz5mWrl0GLdNJGXTSPtegV4rtjK96rDmcLr8R7K9
         3nJQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=TQdZB90acknguCGa17nnXL66ht7CWMA6blc/qvNliP4=;
        b=R9X/tfR8fncXp9JV5tdKsN9AP80SymhaHiCf63SKYjxVvpRzA2BbzA3VqK1JOWpGKu
         tqTEhAkKNbJZoMoO78vVWgf2KTkd2XLoSuiV6z3u4780KR7Lcpo8HHykRoZFwI1MQc32
         FmA+KpWq/6Uoz633wzDFzEinGRW8KYQF5/2tQf6cXFSgXx9eEi8isYXIRe43pBOMn9fE
         xH3r18xxAkCr4yWs94sWaZ4fsjWSugbJiCrkk3TP2OQACzg9jsGSbr4obv6ikiUpEUfb
         Oc9Lk4du0jQgbMPw8FwiPXZ0Y6bn3GRIhmp6VQB023n0GIV1HJaIDtXWqvNbXRTE/gK8
         hfiA==
X-Gm-Message-State: AOAM533dPujnkh39Vv3VzaVpkR/D2i7FdVzwpFTwVWptmtEz68Yu+DUY
	D+YjONGxqMDDZwTd/Why+QE=
X-Google-Smtp-Source: ABdhPJwB1oyPi28jU0Rr6uc7ZE+XAf4Z49Hg4oPcprYZWYDTMHefU7Iv7Sik0X0CFknxeHVetrBcNw==
X-Received: by 2002:a67:3346:: with SMTP id z67mr3638529vsz.3.1627561663368;
        Thu, 29 Jul 2021 05:27:43 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6102:a81:: with SMTP id n1ls1004585vsg.8.gmail; Thu, 29
 Jul 2021 05:27:42 -0700 (PDT)
X-Received: by 2002:a05:6102:d8a:: with SMTP id d10mr3654625vst.10.1627561662838;
        Thu, 29 Jul 2021 05:27:42 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1627561662; cv=none;
        d=google.com; s=arc-20160816;
        b=k5q14i9/TzccYh1marsEd4XJJhicL8/zU4jvDPxOHipAngR0uq71CX53X/cr/TOzzw
         I6FfUpJkJu80Q9J2i3dLX6K4t2O/PxqPoeeicC1IrostSWJa6XZX4wR8o5UtdhXtMEKZ
         vzHcJRUsAVuiVjqxfuzvDCSqx/ZJJr+HDRb9PNU7/58z2N5oTa5wqcPWOVqJJ3skBxKH
         x/XPTxLscSoh8Rz8dEfC6KVmGDMeHHuaujsMIvs/cBLpMu0mKB5cLlO6FhEOxZfZaTsK
         cUqKTuwgGsgP5LPYvru+KHTZV9IrGmutteotO/xBKgo8XgeXOSvIiXVBZ4zs/PsD3ZZL
         dEag==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=jAeYpTpD86gcaq0fp6AOwIIDB2L6QnWwp67+iHCveIY=;
        b=IBSfzsYhRo65Yv4ZyNI2T7dcdn43MJbfNI0tjpx9m93YyQ5SyCv8mnXbj2XQHrIPAz
         KbyRlVDEwAv4env8838tUBQT2cb8BXkUYJXxl7EXACFEB5dOFneQrppYPw9LfGkP416u
         +J+h5jIRQiTifT3VXc0AWSiRJceSPkaS8GW+VONhwmDexf0vPr57POpXM6e3CwCRj+HN
         n40/gW8oBZ4cp5gC2tVSzF3mRg930YltcVxvTxPlHe2E48sIJcUkzoDPYNNGNRbhZ3At
         V+gXx+IuL0gqlSBSY4prfaMnJ8VIQ9xbdoNKIaRSJN1zIbGS9yWQTEE19/xNZ0miii6y
         sJ4w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="ml7Q/Yn+";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c34 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oo1-xc34.google.com (mail-oo1-xc34.google.com. [2607:f8b0:4864:20::c34])
        by gmr-mx.google.com with ESMTPS id v23si222395vsm.1.2021.07.29.05.27.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 29 Jul 2021 05:27:42 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c34 as permitted sender) client-ip=2607:f8b0:4864:20::c34;
Received: by mail-oo1-xc34.google.com with SMTP id b25-20020a4ac2990000b0290263aab95660so1522844ooq.13
        for <kasan-dev@googlegroups.com>; Thu, 29 Jul 2021 05:27:42 -0700 (PDT)
X-Received: by 2002:a4a:e502:: with SMTP id r2mr2827562oot.36.1627561662128;
 Thu, 29 Jul 2021 05:27:42 -0700 (PDT)
MIME-Version: 1.0
References: <20210728190254.3921642-1-hca@linux.ibm.com> <20210728190254.3921642-3-hca@linux.ibm.com>
 <YQJdarx6XSUQ1tFZ@elver.google.com> <YQKeNbU4HJhFP8kn@osiris>
In-Reply-To: <YQKeNbU4HJhFP8kn@osiris>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 29 Jul 2021 14:27:30 +0200
Message-ID: <CANpmjNPWj2vjNd2V-Wqgh1+AvmKQEbg=Qh43DQ_5P2vNv7+JDw@mail.gmail.com>
Subject: Re: [PATCH 2/4] kfence: add function to mask address bits
To: Heiko Carstens <hca@linux.ibm.com>
Cc: Alexander Potapenko <glider@google.com>, Sven Schnelle <svens@linux.ibm.com>, 
	Vasily Gorbik <gor@linux.ibm.com>, Christian Borntraeger <borntraeger@de.ibm.com>, kasan-dev@googlegroups.com, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, linux-s390@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="ml7Q/Yn+";       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c34 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Thu, 29 Jul 2021 at 14:25, Heiko Carstens <hca@linux.ibm.com> wrote:
> On Thu, Jul 29, 2021 at 09:48:58AM +0200, Marco Elver wrote:
> > On Wed, Jul 28, 2021 at 09:02PM +0200, Heiko Carstens wrote:
> > > From: Sven Schnelle <svens@linux.ibm.com>
> > >
> > > s390 only reports the page address during a translation fault.
> > > To make the kfence unit tests pass, add a function that might
> > > be implemented by architectures to mask out address bits.
> > >
> > > Signed-off-by: Sven Schnelle <svens@linux.ibm.com>
> > > Signed-off-by: Heiko Carstens <hca@linux.ibm.com>
> >
> > I noticed this breaks on x86 if CONFIG_KFENCE_KUNIT_TEST=m, because x86
> > conditionally declares some asm functions if !MODULE.
> >
> > I think the below is the simplest to fix, and if you agree, please carry
> > it as a patch in this series before this patch.
>
> Will do.
>
> > With the below, you can add to this patch:
> >
> >       Reviewed-by: Marco Elver <elver@google.com>
>
> Done - Thank you! I silently assume this means also you have no
> objections if we carry this via the s390 tree for upstreaming.

I think that's reasonable. I'm not aware of any conflicts, nor am I
expecting any for the upcoming cycle.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNPWj2vjNd2V-Wqgh1%2BAvmKQEbg%3DQh43DQ_5P2vNv7%2BJDw%40mail.gmail.com.
