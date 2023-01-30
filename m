Return-Path: <kasan-dev+bncBCCMH5WKTMGRBVEC32PAMGQEHOTWK4Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63f.google.com (mail-pl1-x63f.google.com [IPv6:2607:f8b0:4864:20::63f])
	by mail.lfdr.de (Postfix) with ESMTPS id 9A7A568077F
	for <lists+kasan-dev@lfdr.de>; Mon, 30 Jan 2023 09:35:34 +0100 (CET)
Received: by mail-pl1-x63f.google.com with SMTP id t12-20020a170902b20c00b00192e3d10c5bsf6269412plr.4
        for <lists+kasan-dev@lfdr.de>; Mon, 30 Jan 2023 00:35:34 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1675067733; cv=pass;
        d=google.com; s=arc-20160816;
        b=CeJCCoqgMz+613/5iBAZSa7WbwwTU0tE3tLUjxgNol+8q3Os4N3OFIGHRHA0WQt5ck
         s26p5Uu/QN80BW1q4c5ytENp9JXJ67ccIDqCgd3LnqIfZV5DBt98JqUC2vgOkCrXYyoi
         EiHLw1eACpDTmoZVoqIY1S2OCnreSLr4QVTk9RKkhL9hwDLy6mv/mbEvtpOUvs79bQ/X
         RISq0ENYdiH/RRuUqlpZj6zv+CHOCwVINd7P4/wTIyZ/opS207DBWup4IB+21WCS/qkl
         tAqLKAdBU1f3EugJJWatQvI43C09GfnUCWnOua9EbAK2/tmrbGSYRFSmtsao2vvSE8/W
         9zrg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=yIWZqKHGJyz0WUw45ZFijwFMF59vL0Twd/Om1ZTV64w=;
        b=eyzqhntsfMeHJfX3dCYWLZMCa8HHoXnP1Ctrz7wDgLAHMxQQVwAHdbs/80ifLM037b
         IhfpAvcoDYUt0XGfqGCaInnZwjO1Q70hy6Sa3a8R8M391IOjFukJ+p33GwYk93clhLTR
         Tie5/h3OehJxkIrP+0hzzX3MK67pBDkwYsw1/PFXH/iSMNsOwrpSNO3t74kp4ns1mYOm
         oWYckNRDjuHZbkMQ0iE9N93M8a7jDP93pQJwFNCnJZiW85tMf/YWWNs8xyqLKGfYZvec
         kpV9nKkSKqfHKnWeT7pULjwZd2ZV7SQFt3g5qYeF/ldipHgt45zpNZ2mpEygLvdCsmjQ
         zX0A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=ev6TkzkN;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::e30 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=yIWZqKHGJyz0WUw45ZFijwFMF59vL0Twd/Om1ZTV64w=;
        b=AfuzMSn1UxcBpUbx4i6araoYPpQ9dx4sZsq+u0OHGWYsonOYpXkleQpWJIYQn4PtJh
         gvL2NluV5lFwVD3XC3hWKYsVbjrt6p999GipjphWNc4S2T6OyijG0v6rZ92uAWtk5q0l
         McAM5VqKeYtm8c1IMPU90lDjdaV5dl13AoDVy2rSXCGCV+hncv2eNAs4MEcCZiT8yR0Z
         KS7VRyUvuV89D9BqQoTzKutQByiDbQFiMtuA7UQyeLXrj8mR9nlmTOQTGlFVSwA4yPCj
         03JdTz47libLcsws/9m765evcDwOlRGpHq80tyWKC5qnN2KCAqpiW/pa0p9dUbF6vgn2
         S5PQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=yIWZqKHGJyz0WUw45ZFijwFMF59vL0Twd/Om1ZTV64w=;
        b=EN7/YHhXfYbHzztOaUOQl0rEwX+gmq5VsvvTVMmMtJ8O+L7AXIQwvJRxs+j2SrjWqB
         hv8Mm9GDY3lc2m6PKYqOm/xzYCZRLvPS3WEtSnz9FGhVBgTWwS25efZ8fN3xVQxuGHDL
         tl6+q1ZlJ4TkLefpkfnNnM5JvT9p93lHDMOlCA0OLbVFU/hyWuW5Scor9+05csIpcQ8r
         4IpXMuOPCNMJR4UnRLB8bo2nQRO6EuGFuZpDeegIoDa3idp6dT1gA7lQzEyX4IqRuIYx
         5UpIlzMA7eFcd9L04JCcaOqzZbatycG8wK0i6qQSvG+mc03zxrj6bN68uOrUh50v5xGj
         Xy8A==
X-Gm-Message-State: AO0yUKWEr/rPAuVL5t3z5ITRN+OJIAcPOSBIqekUIWWk3IRnOF00qe6e
	v+GY3O/S4mPIizUNNJgrvbg=
X-Google-Smtp-Source: AK7set99p8BsyqY41CHp0CCjt/boV36kWdhaLcrgZg2wwEEKfeaCyHfgTjT3GZ0tbAcxMtMeptxtow==
X-Received: by 2002:a17:90a:c690:b0:22b:e58a:955f with SMTP id n16-20020a17090ac69000b0022be58a955fmr4526971pjt.85.1675067732824;
        Mon, 30 Jan 2023 00:35:32 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:7c88:b0:189:b2b2:56d5 with SMTP id
 y8-20020a1709027c8800b00189b2b256d5ls12242799pll.0.-pod-prod-gmail; Mon, 30
 Jan 2023 00:35:32 -0800 (PST)
X-Received: by 2002:a17:90b:1b49:b0:22b:f208:aeed with SMTP id nv9-20020a17090b1b4900b0022bf208aeedmr23038005pjb.30.1675067732048;
        Mon, 30 Jan 2023 00:35:32 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1675067732; cv=none;
        d=google.com; s=arc-20160816;
        b=1B/AwswROuJUFHt+s6baV+LHcEGjKICQXTS4lF3cNcVIaJqf/2ZjG3AEvPnjcz9du2
         jPW+6sxltJjKwJQKAsfUG4wrgxxTDN4ild9MVlai2/QOCK6borYVNV/y4Yp/hJ3LvDdR
         LQ34TYiXJ5XrQe9GDH1tAtMX5UCxBuySIPQlgF5oqGTVr3HnLC97mFSv6MGiSEhgubdI
         JWp8j9A5g9owtu8SLiUEOPrZsjeVOENl50ilrCMVYJWffUJRDLYB/7DTNw3g9Trrv+Ix
         rJjfeaUUsv8vn7gj48diqzIolpfJCZCB311TFznFzbmomjJkstgG+YlYtvJB99g7MONw
         eC8w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=SDsKqyepeY63ocyMIwF8lZiaR+pOTU94INwLNWf/i/Q=;
        b=y3N88v8F4Z+jHmf2g5fNXYNiRa7fVcQYx9RKBw47BzRQdwu6VCj5jH4DGMFHO1oV5I
         SzwEZR2peRJfJgLbzcuBlC7dsp5E2iNVbP0hloMtjDdJria5eBxy5psuu4CXqe2HC+64
         ltJO0eCV79bR8OuiXfbredcKHyMG6YjFayVEKxc1TMFbQ9wRhXjB2hn//V6WcAQ5uH9c
         955lBj7zDwgF1PsHjhU3Zg/ShIU04QLJHkDkP8oEPsPt7h/L4bBdVOXMpv7hdqajRDX1
         g5IQLcUxYVrOIASnO8qWYtmVnZbPA8uFFhq1gn99E4m1C7MVkRSW1tzT5Ky3P24bOWpn
         uEqQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=ev6TkzkN;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::e30 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-vs1-xe30.google.com (mail-vs1-xe30.google.com. [2607:f8b0:4864:20::e30])
        by gmr-mx.google.com with ESMTPS id x8-20020a17090aca0800b00229b4d7172fsi827047pjt.3.2023.01.30.00.35.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 30 Jan 2023 00:35:32 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::e30 as permitted sender) client-ip=2607:f8b0:4864:20::e30;
Received: by mail-vs1-xe30.google.com with SMTP id y8so11712664vsq.0
        for <kasan-dev@googlegroups.com>; Mon, 30 Jan 2023 00:35:31 -0800 (PST)
X-Received: by 2002:a05:6102:3237:b0:3f4:eee1:d8c4 with SMTP id
 x23-20020a056102323700b003f4eee1d8c4mr514404vsf.19.1675067731131; Mon, 30 Jan
 2023 00:35:31 -0800 (PST)
MIME-Version: 1.0
References: <20220701142310.2188015-1-glider@google.com> <20220701142310.2188015-11-glider@google.com>
 <CANpmjNOYqXSw5+Sxt0+=oOUQ1iQKVtEYHv20=sh_9nywxXUyWw@mail.gmail.com>
 <CAG_fn=W2EUjS8AX1Odunq1==dV178s_-w3hQpyrFBr=Auo-Q-A@mail.gmail.com> <63b74a6e6a909_c81f0294a5@dwillia2-xfh.jf.intel.com.notmuch>
In-Reply-To: <63b74a6e6a909_c81f0294a5@dwillia2-xfh.jf.intel.com.notmuch>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 30 Jan 2023 09:34:54 +0100
Message-ID: <CAG_fn=XNfrpTxWYYLnG5L-ogKmxvWvLGTzgqbT7sWxnFgnu7_w@mail.gmail.com>
Subject: Re: [PATCH v4 10/45] libnvdimm/pfn_dev: increase MAX_STRUCT_PAGE_SIZE
To: Dan Williams <dan.j.williams@intel.com>
Cc: Marco Elver <elver@google.com>, Alexander Viro <viro@zeniv.linux.org.uk>, 
	Alexei Starovoitov <ast@kernel.org>, Andrew Morton <akpm@linux-foundation.org>, 
	Andrey Konovalov <andreyknvl@google.com>, Andy Lutomirski <luto@kernel.org>, Arnd Bergmann <arnd@arndb.de>, 
	Borislav Petkov <bp@alien8.de>, Christoph Hellwig <hch@lst.de>, Christoph Lameter <cl@linux.com>, 
	David Rientjes <rientjes@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Eric Dumazet <edumazet@google.com>, Greg Kroah-Hartman <gregkh@linuxfoundation.org>, 
	Herbert Xu <herbert@gondor.apana.org.au>, Ilya Leoshkevich <iii@linux.ibm.com>, 
	Ingo Molnar <mingo@redhat.com>, Jens Axboe <axboe@kernel.dk>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, 
	Kees Cook <keescook@chromium.org>, Mark Rutland <mark.rutland@arm.com>, 
	Matthew Wilcox <willy@infradead.org>, "Michael S. Tsirkin" <mst@redhat.com>, Pekka Enberg <penberg@kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>, Petr Mladek <pmladek@suse.com>, 
	Steven Rostedt <rostedt@goodmis.org>, Thomas Gleixner <tglx@linutronix.de>, 
	Vasily Gorbik <gor@linux.ibm.com>, Vegard Nossum <vegard.nossum@oracle.com>, 
	Vlastimil Babka <vbabka@suse.cz>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux Memory Management List <linux-mm@kvack.org>, Linux-Arch <linux-arch@vger.kernel.org>, 
	LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=ev6TkzkN;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::e30 as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

On Thu, Jan 5, 2023 at 11:09 PM Dan Williams <dan.j.williams@intel.com> wrote:
>
> Alexander Potapenko wrote:
> > (+ Dan Williams)
> > (resending with patch context included)
> >
> > On Mon, Jul 11, 2022 at 6:27 PM Marco Elver <elver@google.com> wrote:
> > >
> > > On Fri, 1 Jul 2022 at 16:23, Alexander Potapenko <glider@google.com> wrote:
> > > >
> > > > KMSAN adds extra metadata fields to struct page, so it does not fit into
> > > > 64 bytes anymore.
> > >
> > > Does this somehow cause extra space being used in all kernel configs?
> > > If not, it would be good to note this in the commit message.
> > >
> > I actually couldn't verify this on QEMU, because the driver never got loaded.
> > Looks like this increases the amount of memory used by the nvdimm
> > driver in all kernel configs that enable it (including those that
> > don't use KMSAN), but I am not sure how much is that.
> >
> > Dan, do you know how bad increasing MAX_STRUCT_PAGE_SIZE can be?
>
> Apologies I missed this several months ago. The answer is that this
> causes everyone creating PMEM namespaces on v6.1+ to lose double the
> capacity of their namespace even when not using KMSAN which is too
> wasteful to tolerate. So, I think "6e9f05dc66f9 libnvdimm/pfn_dev:
> increase MAX_STRUCT_PAGE_SIZE" needs to be reverted and replaced with
> something like:
>
> diff --git a/drivers/nvdimm/Kconfig b/drivers/nvdimm/Kconfig
> index 79d93126453d..5693869b720b 100644
> --- a/drivers/nvdimm/Kconfig
> +++ b/drivers/nvdimm/Kconfig
> @@ -63,6 +63,7 @@ config NVDIMM_PFN
>         bool "PFN: Map persistent (device) memory"
>         default LIBNVDIMM
>         depends on ZONE_DEVICE
> +       depends on !KMSAN
>         select ND_CLAIM
>         help
>           Map persistent memory, i.e. advertise it to the memory
>

Looks like we still don't have a resolution for this problem.
I have the following options in mind:

1. Set MAX_STRUCT_PAGE_SIZE to 80 (i.e. increase it by 2*sizeof(struct
page *) added by KMSAN) instead of 128.
2. Disable storing of struct pages on device for KMSAN builds.

, but if those are infeasible, we can always go for:

3. Disable KMSAN for NVDIMM and reflect it in Documentation. I am
happy to send the patch if we decide this is the best option.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAG_fn%3DXNfrpTxWYYLnG5L-ogKmxvWvLGTzgqbT7sWxnFgnu7_w%40mail.gmail.com.
