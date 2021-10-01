Return-Path: <kasan-dev+bncBCM2HQW3QYHRB7VL3SFAMGQEKDOV5FQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53d.google.com (mail-ed1-x53d.google.com [IPv6:2a00:1450:4864:20::53d])
	by mail.lfdr.de (Postfix) with ESMTPS id C1DB841EF1A
	for <lists+kasan-dev@lfdr.de>; Fri,  1 Oct 2021 16:06:54 +0200 (CEST)
Received: by mail-ed1-x53d.google.com with SMTP id y15-20020a50ce0f000000b003dab997cf7dsf6945110edi.9
        for <lists+kasan-dev@lfdr.de>; Fri, 01 Oct 2021 07:06:54 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1633097214; cv=pass;
        d=google.com; s=arc-20160816;
        b=FwOVj929iQywYyWqSn+3DUv1AQ1vleFqKkZu6McPt07OqrlH1imLt4c9A1US6CP0+V
         WhntqAoxo2gCxdDZ5HcllcLNHn9iWTeR8I54N0sn8L91GcncqlgUXhJai+SBClA/GbpT
         NfBOEA9/4lNsbf5BTF18bp2CVICXH1vFSM0WuMwLtGPLRyU7fsTTqiA93zd6gBHfxwWB
         ygyU7lfduutxwXoVsv9ShuSzrseWzxyOh+/LwZhnL3ekezasDXp1p8htIHPBG8LDLnA8
         kAFci5oGvPFsRdvtq28vEyqaKJXFSSTHV/UxEhwyj+MXgAI/JDBQfA6heryp+DXI5bAV
         v+UA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=Na6BTU4xx+WM8a945FDk2pLbXQSvRc09zUvYZhoCUL0=;
        b=wspXl2wqAUcfhg3F+mrh1E4+HjW292Jk6E5aKWg/36pCj4wADzXE0U5v4whjlWXPXZ
         8373JZYJ/Zvgypgu2yPXU+4iL6N5ESpnG0lSC958MQbQDhjqcYZ9diHunwjUDt0kavPy
         /7VU3RC0cv43/CoxV78xGruQO2+rRBQqIhuTCuJSwCYUkZMIiNUrjitTIA+bgkEeDYey
         oHl4dhBcIOM8j+3+/ss3smleyxOwAEn1YT6xo5cDMiXPDLk63htKy4AvZqGwk14yXhNi
         fkfjGDwzZxh3OEetirrxYEmWE4L6cG48kxlM+env0qxt1OfXxOolpHXuG09gI8e1OkYR
         PK4w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=VnlExgmh;
       spf=pass (google.com: best guess record for domain of willy@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=willy@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Na6BTU4xx+WM8a945FDk2pLbXQSvRc09zUvYZhoCUL0=;
        b=TULdf6JxaAG3BSkq9uqdlODhN3EGsF2LyzBK/C4MaO3+/4aQPxCECwdTpkuxka41nP
         8gDbgzGqpziuAjfJcEtksr/kPfqyrDgITivKYGaXGXFdkIH145We94htp0sW/+A2/NZO
         511zVVRCZ7baUgRZ2lFuqgiTYrYxOlvvioC0+Co0kOpJ2uHVuEjV7vQKAmyw+lNJWoZr
         0rWDscbIcBEiTuGhZVRCm84gv/wjJw+7WlHzK0vy8ixkHCOdyQv0dCrMXxSGa7+MjA9C
         Kkf267mOBLkWCui33Qprfni0MccFGoiUWpz+f0FgQtO4g466H9qNWnSBps0Q4HIkXGap
         1WNA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=Na6BTU4xx+WM8a945FDk2pLbXQSvRc09zUvYZhoCUL0=;
        b=txoNF6gI0T7Q9NzKHXHOyCMKh0eyRvDgZw0pStDRxh5KsXc8koUjSUkdOlT6jfMLrn
         LN7QWZ1+13CG+Gr4YszX2FdLe8YC+V8n8aaH4gAn4ZqC0QjYTd8fFWnBhXSKRKK5D12+
         m6SsemZmDM/93PVmoloKsG33BR3JMQxwCIQmCIkXKz2DmLmsUb9zWSINlEZjKZFv21pi
         ovcc+8coIXNJjhu99vZOTCeV2kI6PEh+vvzIia8xAwVUYhji3KYOw3sNI9mKh290II1v
         7ToOKLIcwtJjGUzj7JxZYg3qJePzbSsapwHfD/jTQfOKMqHtO+u4v9hZcfg4PZB7Ubq2
         I6AA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531chnNWyng2q/rBNNBSvC13aFtUuqWiPR/wydEUxvkHxPbQdVxg
	ErAsqilGMysNGS/4K63ccp0=
X-Google-Smtp-Source: ABdhPJwAm+y0ua4zz+cPMZwFbJIvQ9dQkCVSK6eKiv8/3KG6F5GnX7AcE2NI8b24/OdhyTUt0wTlgA==
X-Received: by 2002:a17:906:3542:: with SMTP id s2mr6729873eja.379.1633097214471;
        Fri, 01 Oct 2021 07:06:54 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:7047:: with SMTP id r7ls4535405ejj.5.gmail; Fri, 01
 Oct 2021 07:06:53 -0700 (PDT)
X-Received: by 2002:a17:906:c7c1:: with SMTP id dc1mr6767967ejb.6.1633097213647;
        Fri, 01 Oct 2021 07:06:53 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1633097213; cv=none;
        d=google.com; s=arc-20160816;
        b=I9B6bl4g8LclOKpu6/SfdNUEbZLlAs5TfmH80XdlHf/JMqhXYuVdmwGd0ITdXbv2AI
         OMbL2/cSMzpQzztYSdYNTEex9oIOxRtxpxb1VX1ckwYMbzRGJ9fyEfE8Q677F5vW4d4j
         i5w9sd7UNobAVbig7gFf0rgsjYxPNay80SQKVvgps/Zzu93uSjSGDFg4CTvbAZlD2Ljn
         w9RI0awxURn8+Zis+hyfzOE40yVkk5MxUfccnY1QAmqFZBcoiC6O7pWLrFMMuT6ecHFE
         uxfmpPwIrsFB7bKG2SWejdXXt4uzndIOzX1yC4/2sZ8txvLNu4KZWDPk5qVPigtkWxjY
         dixQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=v+V/r4h62iC1rLKsrgjisVTgoRvyIjeKcO+78KSD2u0=;
        b=nzowq7qHIV+WNqPkbfSxZoqIp/kKHgmtzL/hLv/qk+0fbze/8UOj5Dp96MJ28OqL4m
         5D03PSRKczoFjhUSRC+ePl4o96vWNaNjhG3mqC/eUJuCIt0DmntJ6y0MsFlneOw5o742
         e2pl9xTOUK8BoGJbPaBD75AA3K2sxFVDAxa6RDiFseXKteP/F/tKI5TQ2nJaQ2fV1Srj
         KffFj6ax1Z2ViKG5zBlCB9zNl9iEkNBS0XwKKFH7rNh6ZT6G1d0kXrj4WGG/Z/6mWBwy
         mA6h3nlj8Oj2LumujFfrF2gbRjbxCeTE9a22AdzBiZ9plrjwGbKYW0a4WM7v+KazSUgJ
         4KHg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=VnlExgmh;
       spf=pass (google.com: best guess record for domain of willy@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=willy@infradead.org
Received: from casper.infradead.org (casper.infradead.org. [2001:8b0:10b:1236::1])
        by gmr-mx.google.com with ESMTPS id zh8si454043ejb.0.2021.10.01.07.06.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 01 Oct 2021 07:06:53 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of willy@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) client-ip=2001:8b0:10b:1236::1;
Received: from willy by casper.infradead.org with local (Exim 4.94.2 #2 (Red Hat Linux))
	id 1mWJAS-00Dxk8-98; Fri, 01 Oct 2021 14:06:04 +0000
Date: Fri, 1 Oct 2021 15:05:40 +0100
From: Matthew Wilcox <willy@infradead.org>
To: Andrey Konovalov <andreyknvl@gmail.com>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	kasan-dev <kasan-dev@googlegroups.com>,
	Linux Memory Management List <linux-mm@kvack.org>,
	LKML <linux-kernel@vger.kernel.org>
Subject: Re: [PATCH] kasan: Fix tag for large allocations when using
 CONFIG_SLAB
Message-ID: <YVcVtNLnyJModOhn@casper.infradead.org>
References: <20211001024105.3217339-1-willy@infradead.org>
 <CA+fCnZfSUxToYKUfHwQT0r3bC9NYZNc2iC3PXv+GciuW0Fm79A@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CA+fCnZfSUxToYKUfHwQT0r3bC9NYZNc2iC3PXv+GciuW0Fm79A@mail.gmail.com>
X-Original-Sender: willy@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=casper.20170209 header.b=VnlExgmh;
       spf=pass (google.com: best guess record for domain of
 willy@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=willy@infradead.org
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

On Fri, Oct 01, 2021 at 03:29:29PM +0200, Andrey Konovalov wrote:
> On Fri, Oct 1, 2021 at 4:42 AM Matthew Wilcox (Oracle)
> <willy@infradead.org> wrote:
> >
> > If an object is allocated on a tail page of a multi-page slab, kasan
> > will get the wrong tagbecause page->s_mem is NULL for tail pages.
> 
> Interesting. Is this a known property of tail pages? Why does this
> happen? I failed to find this exception in the code.

Yes, it's a known property of tail pages.  kmem_getpages() calls
__alloc_pages_node() which returns a pointer to the head page.
All the tail pages are initialised to point to the head page.
Then in alloc_slabmgmt(), we set ->s_mem of the head page, but
we never set ->s_mem of the tail pages.  Instead, we rely on
people always passing in the head page.  I have a patch in the works
to change the type from struct page to struct slab so you can't
make this mistake.  That was how I noticed this problem.

> The tag value won't really be "wrong", just unexpected. But if s_mem
> is indeed NULL for tail pages, your fix makes sense.
> 
> > I'm not quite sure what the user-visible effect of this might be.
> 
> Everything should work, as long as tag values are assigned
> consistently based on the object address.

OK, maybe this doesn't need to be backported then?  Actually, why
subtract s_mem in the first place?  Can we just avoid that for all
tag calculations?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YVcVtNLnyJModOhn%40casper.infradead.org.
