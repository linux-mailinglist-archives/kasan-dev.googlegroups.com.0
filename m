Return-Path: <kasan-dev+bncBCKMR55PYIGBBXEJYSMAMGQEIMW6NVY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x238.google.com (mail-lj1-x238.google.com [IPv6:2a00:1450:4864:20::238])
	by mail.lfdr.de (Postfix) with ESMTPS id F03855A9FAD
	for <lists+kasan-dev@lfdr.de>; Thu,  1 Sep 2022 21:15:40 +0200 (CEST)
Received: by mail-lj1-x238.google.com with SMTP id k13-20020a05651c0a0d00b00265d5dfe102sf32390ljq.11
        for <lists+kasan-dev@lfdr.de>; Thu, 01 Sep 2022 12:15:40 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662059740; cv=pass;
        d=google.com; s=arc-20160816;
        b=xbkKg3lDqo5FVQTBGxW/2Wsa762oQY5/e/PQA+sh5vXdDEIDtj0HlnmCxgxQRVo1IT
         DmyYNyNr3oZhsvDIsRGLa+xR5F2qQChLZDvskJ6kGAIvJQ4xNeoZ8gTurvCbmvMiAXmF
         QwkeJF/RwfDoAW595B8Qhu87IuwM6QXldJZsFSSFAXcmt38ye9u/Ro9C4zTzpbOZyXNO
         MUECwA5OZaDw1QQ9JuJ/6kp+h+BAlH/IAh1PyVi3KHXn/GPBAJ6LfjxJ+fDJISh3izq8
         RknjU9umgfinC6E25Jls1puLSUQdiP2DK5gsMubSlAr/l6SJK52tT2yCvUA75eqaQOZc
         EvZw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=3L1xt3np3f5JydOcd7BbdSnUEVPZv0u+BcFdAfgX5hk=;
        b=B/Gg4Fvfs5QgAg3SlE7+Vw9Te/dRuJY95VJbsrVNor9OY2Xi+Kff+zD7twN/K0kc8w
         bG22BErprI0wt5LtPyuCW7g7XUddYaxfeEB+mVzHKPLagboRGRZbbIZdzRhG0goWI4Xo
         ToQvypFp+KYyIiWzjd7jvJ/mKH4OmIn1n0gOonHMiMsXrZVAUJqbb4XoyiJ6DQPXcbSn
         HMnGSlRGtK7qP6zIBQQgsb3PGiLxDEYFQH5ZdbZGQdKRV3ctyv5MKrBsYL/9FyEbq887
         SbJsDNGtP3+OPFa55Vcs3dbDmge2UgjB3111CZkJSea2odJmp3ayQ8c0qHar4QZIiHnN
         y/pg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.com header.s=susede1 header.b=HIwU2Ypw;
       spf=pass (google.com: domain of mhocko@suse.com designates 195.135.220.28 as permitted sender) smtp.mailfrom=mhocko@suse.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=suse.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date;
        bh=3L1xt3np3f5JydOcd7BbdSnUEVPZv0u+BcFdAfgX5hk=;
        b=MYgb5Pm/vrEPPQxP4HW23b4HNeIaoNsQR6zNBK//OUu6cTLKJlce/JaZehFHxmMcKJ
         n28fuoYM26dCJ0o6yS2RZcjiMcFXctlgotLKD380OrdFaAyHexzv8L4BONWiM148vmZc
         eKC0zWOpv/A6anCEWrxNjCWvfx3581JGZIh6nlJzjghRJ2q4GwgBMSIlpYMqBNit8ufv
         KX/TDurOTJMatglOHR/Xr/MFTB7AEcXMEHeWN1cXdgmg9hGRVFn97OlDa7FQ+D+M3TiD
         H3ugaz37Fum2nLqq+opFtUrKGgJXtc9b6NxxmGDOluWHMjy0QEB1JVHtmND7UWUFr95v
         0ZGQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:from:to:cc:subject:date;
        bh=3L1xt3np3f5JydOcd7BbdSnUEVPZv0u+BcFdAfgX5hk=;
        b=tvhqg4o1M+UKyazv9fw2Qfvj7xvZOibWQYkSCYiJYJYNPflYzT7k/GiZVTe7+/JmPv
         e1U5b/0XxfeKsi+VSH6A8hZzyGB1eIjq1req2joYq8V4W0RKpeT+N2Nt1pvt+k5uvtX+
         RpPvnLtQZo0Nlb498uVfv+y/K/5fwZfRrGoNaAQDzGklkgGYjolfigaPWNwNU4zJ3X30
         ifSMgo62zshqk13oGX36kA41mSLJ9W4pso6GKVTGOk3qEKmwYoFrt10Urscr56qqUyU7
         f08mNo6K1DmNhVVeU7YghgnBX5OagYEE5u0A4THkTuskLhL9V1zZZzwmjsSxLxgS5WPo
         9vIw==
X-Gm-Message-State: ACgBeo00ZX9gn9KFdq6i6s1ZTGrZd9d15vgFM0Itu28YJuvH7L2OT/E5
	UvUWeo/KEdQ7NLaXCXIXU5E=
X-Google-Smtp-Source: AA6agR5FoF/wr/KLbInc3xQrKhLwm6Ig7JR1wiXupo+ZC6eUffcBFh4NNBz30VE3Md29TxktloXOiA==
X-Received: by 2002:ac2:4c42:0:b0:482:cb18:25ac with SMTP id o2-20020ac24c42000000b00482cb1825acmr12188644lfk.643.1662059740308;
        Thu, 01 Sep 2022 12:15:40 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3582:b0:494:6c7d:cf65 with SMTP id
 m2-20020a056512358200b004946c7dcf65ls2145868lfr.2.-pod-prod-gmail; Thu, 01
 Sep 2022 12:15:38 -0700 (PDT)
X-Received: by 2002:a05:6512:39ca:b0:494:6c90:647c with SMTP id k10-20020a05651239ca00b004946c90647cmr5973681lfu.25.1662059738855;
        Thu, 01 Sep 2022 12:15:38 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662059738; cv=none;
        d=google.com; s=arc-20160816;
        b=C7VzTy/qmnBXm0tYzkseapYVqrzqbXzLgFpKBzNBe0ncu5OsUmXNwvnQ/ziSFNC5rt
         2asFzdlXwcFKYBfCpQcXmhajKR3ROj/hLLMi+BcWDcVZgI+x8jGTPQzY+g1hQxJu/9J4
         mqkAnabKPyndYduxsGZ8NMQT+krVgzVpf2mgAEoHs0LGm13gzuJmOAm2cjz9+XBJJ4UR
         /9HztqGVmxtpyaWxjfu0kn3ObhnrL0qhkCp482+2L3BYZ79SSZK6gC//yDfl6txHazZp
         D49DT6VWpKm3jOXHymMPMYVGmPVlZtvTkwE8Nyaz7OdfmLdPecEn5hi8bMpMJv0L3JX2
         f+vA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=ZXQSRqer3+FtfHBMGJ4s/SGRUTOoWiBwBxr7NnCmrIE=;
        b=eTN9eG9AGL2u9QPfnnaGmK34jpLa4ebp5wueHM0LnCl1CTy/lRasCMQ/SQhaDcY4SR
         a5lABJvO50KrcZvw+GG+rWQao13YXHEt1g3k6Khe3mq9Fj/G+pNXFKXiViYT3YKhGRr4
         KnolBgs3jP6FMsRvL6a8FgSflaLioY+KkHjwULHNpL46sTq9hY7rJJ4QhuZUy0d/+bXM
         SqzrQRLy8d+Y5iEAoQULDnuCTKJaNbnbUc7otnvSWOVP5YcZ/BYw4Yt5TD2+VcAxRQk0
         sBK18f4tZjV9SYlXBtBxR4AsUQ+qvkaj77BMPym0cDDuZAV/8TrAC8eslL6CriEc9DYK
         c5hg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.com header.s=susede1 header.b=HIwU2Ypw;
       spf=pass (google.com: domain of mhocko@suse.com designates 195.135.220.28 as permitted sender) smtp.mailfrom=mhocko@suse.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=suse.com
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [195.135.220.28])
        by gmr-mx.google.com with ESMTPS id p15-20020a2ea4cf000000b002652a5a5536si471135ljm.2.2022.09.01.12.15.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 01 Sep 2022 12:15:38 -0700 (PDT)
Received-SPF: pass (google.com: domain of mhocko@suse.com designates 195.135.220.28 as permitted sender) client-ip=195.135.220.28;
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id 164EB33749;
	Thu,  1 Sep 2022 19:15:38 +0000 (UTC)
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by imap2.suse-dmz.suse.de (Postfix) with ESMTPS id E01CE13A79;
	Thu,  1 Sep 2022 19:15:37 +0000 (UTC)
Received: from dovecot-director2.suse.de ([192.168.254.65])
	by imap2.suse-dmz.suse.de with ESMTPSA
	id fSsfNtkEEWNbVwAAMHmgww
	(envelope-from <mhocko@suse.com>); Thu, 01 Sep 2022 19:15:37 +0000
Date: Thu, 1 Sep 2022 21:15:34 +0200
From: "'Michal Hocko' via kasan-dev" <kasan-dev@googlegroups.com>
To: Suren Baghdasaryan <surenb@google.com>
Cc: Kent Overstreet <kent.overstreet@linux.dev>,
	Mel Gorman <mgorman@suse.de>, Peter Zijlstra <peterz@infradead.org>,
	Andrew Morton <akpm@linux-foundation.org>,
	Vlastimil Babka <vbabka@suse.cz>,
	Johannes Weiner <hannes@cmpxchg.org>,
	Roman Gushchin <roman.gushchin@linux.dev>,
	Davidlohr Bueso <dave@stgolabs.net>,
	Matthew Wilcox <willy@infradead.org>,
	"Liam R. Howlett" <liam.howlett@oracle.com>,
	David Vernet <void@manifault.com>,
	Juri Lelli <juri.lelli@redhat.com>,
	Laurent Dufour <ldufour@linux.ibm.com>,
	Peter Xu <peterx@redhat.com>, David Hildenbrand <david@redhat.com>,
	Jens Axboe <axboe@kernel.dk>, mcgrof@kernel.org,
	masahiroy@kernel.org, nathan@kernel.org, changbin.du@intel.com,
	ytcoode@gmail.com, Vincent Guittot <vincent.guittot@linaro.org>,
	Dietmar Eggemann <dietmar.eggemann@arm.com>,
	Steven Rostedt <rostedt@goodmis.org>,
	Benjamin Segall <bsegall@google.com>,
	Daniel Bristot de Oliveira <bristot@redhat.com>,
	Valentin Schneider <vschneid@redhat.com>,
	Christopher Lameter <cl@linux.com>,
	Pekka Enberg <penberg@kernel.org>,
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, 42.hyeyoo@gmail.com,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>, dvyukov@google.com,
	Shakeel Butt <shakeelb@google.com>,
	Muchun Song <songmuchun@bytedance.com>, arnd@arndb.de,
	jbaron@akamai.com, David Rientjes <rientjes@google.com>,
	Minchan Kim <minchan@google.com>,
	Kalesh Singh <kaleshsingh@google.com>,
	kernel-team <kernel-team@android.com>,
	linux-mm <linux-mm@kvack.org>, iommu@lists.linux.dev,
	kasan-dev@googlegroups.com, io-uring@vger.kernel.org,
	linux-arch@vger.kernel.org, xen-devel@lists.xenproject.org,
	linux-bcache@vger.kernel.org, linux-modules@vger.kernel.org,
	LKML <linux-kernel@vger.kernel.org>
Subject: Re: [RFC PATCH 00/30] Code tagging framework and applications
Message-ID: <YxEE1vOwRPdzKxoq@dhcp22.suse.cz>
References: <20220830214919.53220-1-surenb@google.com>
 <Yw8P8xZ4zqu121xL@hirez.programming.kicks-ass.net>
 <20220831084230.3ti3vitrzhzsu3fs@moria.home.lan>
 <20220831101948.f3etturccmp5ovkl@suse.de>
 <Yw88RFuBgc7yFYxA@dhcp22.suse.cz>
 <20220831190154.qdlsxfamans3ya5j@moria.home.lan>
 <YxBc1xuGbB36f8zC@dhcp22.suse.cz>
 <CAJuCfpGhwPFYdkOLjwwD4ra9JxPqq1T5d1jd41Jy3LJnVnhNdg@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CAJuCfpGhwPFYdkOLjwwD4ra9JxPqq1T5d1jd41Jy3LJnVnhNdg@mail.gmail.com>
X-Original-Sender: mhocko@suse.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.com header.s=susede1 header.b=HIwU2Ypw;       spf=pass
 (google.com: domain of mhocko@suse.com designates 195.135.220.28 as permitted
 sender) smtp.mailfrom=mhocko@suse.com;       dmarc=pass (p=QUARANTINE
 sp=QUARANTINE dis=NONE) header.from=suse.com
X-Original-From: Michal Hocko <mhocko@suse.com>
Reply-To: Michal Hocko <mhocko@suse.com>
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

On Thu 01-09-22 08:33:19, Suren Baghdasaryan wrote:
> On Thu, Sep 1, 2022 at 12:18 AM Michal Hocko <mhocko@suse.com> wrote:
[...]
> > So I find Peter's question completely appropriate while your response to
> > that not so much! Maybe ftrace is not the right tool for the intented
> > job. Maybe there are other ways and it would be really great to show
> > that those have been evaluated and they are not suitable for a), b) and
> > c) reasons.
> 
> That's fair.
> For memory tracking I looked into using kmemleak and page_owner which
> can't match the required functionality at an overhead acceptable for
> production and pre-production testing environments.

Being more specific would be really helpful. Especially when your cover
letter suggests that you rely on page_owner/memcg metadata as well to
match allocation and their freeing parts.

> traces + BPF I
> haven't evaluated myself but heard from other members of my team who
> tried using that in production environment with poor results. I'll try
> to get more specific information on that.

That would be helpful as well.

> > E.g. Oscar has been working on extending page_ext to track number of
> > allocations for specific calltrace[1]. Is this 1:1 replacement? No! But
> > it can help in environments where page_ext can be enabled and it is
> > completely non-intrusive to the MM code.
> 
> Thanks for pointing out this work. I'll need to review and maybe
> profile it before making any claims.
> 
> >
> > If the page_ext overhead is not desirable/acceptable then I am sure
> > there are other options. E.g. kprobes/LivePatching framework can hook
> > into functions and alter their behavior. So why not use that for data
> > collection? Has this been evaluated at all?
> 
> I'm not sure how I can hook into say alloc_pages() to find out where
> it was called from without capturing the call stack (which would
> introduce an overhead at every allocation). Would love to discuss this
> or other alternatives if they can be done with low enough overhead.

Yes, tracking back the call trace would be really needed. The question
is whether this is really prohibitively expensive. How much overhead are
we talking about? There is no free lunch here, really.  You either have
the overhead during runtime when the feature is used or on the source
code level for all the future development (with a maze of macros and
wrappers).

Thanks!
-- 
Michal Hocko
SUSE Labs

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YxEE1vOwRPdzKxoq%40dhcp22.suse.cz.
