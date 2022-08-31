Return-Path: <kasan-dev+bncBC7OD3FKWUERB6EIX2MAMGQEQK6WSWQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1040.google.com (mail-pj1-x1040.google.com [IPv6:2607:f8b0:4864:20::1040])
	by mail.lfdr.de (Postfix) with ESMTPS id 89F835A826B
	for <lists+kasan-dev@lfdr.de>; Wed, 31 Aug 2022 17:55:43 +0200 (CEST)
Received: by mail-pj1-x1040.google.com with SMTP id d16-20020a17090ad3d000b001fb42eb7467sf6250677pjw.9
        for <lists+kasan-dev@lfdr.de>; Wed, 31 Aug 2022 08:55:43 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1661961337; cv=pass;
        d=google.com; s=arc-20160816;
        b=XfpSvSNpob4KRXSYwcgdcSTwJuWH3lrf+5gp8n6qm6kboAltCaQzY+i4wcPcEho5/t
         gVGKMHFRfDhuYOX91bPLJfN3t2oxHDPuMZb4zDUOsrROzlUtNLqFKjyA2BfWXvwkO/wc
         w/d2c7LqfZ3vNozHlpYn0PzOWwHifS7535bMEQAeQsUF34nw8PICRW2xGibyxjJbsdBn
         ixJaz+10rFqU09//P8woSxf0yX6S80vyULNlvoWrm9KSqUekpQEtmHkG78RpsbV/3JKy
         k+m9MQeQS2xvaI03x1RX06f6Uq8Jnq+fasc6iQ9I3QXBpuT90/XpPvPc+sxge+GVSAbM
         bhfQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=Zfi0RpFBGuocefxLWbDIZnqSRTsS6MAQi/ZZh5r7mjk=;
        b=FyQsYMUgG/Y5XIfaLicztkZGgSicRp4C0Xxt7fuA7Wxb+J8oQDfbkJaKO+RsWcSzDJ
         A0HInNZbfPZDhbM9vTth9p1lrLmsX2wxCgpW+HMlKCzyHBuNNMIvGB65YeCI1uTdGJ74
         phjBOKXngCOxBwo5/5eG5tb6sqNXas4e/im+P4VSHVNEzHZhzPMac78P2GxvvSdeaSZU
         4ysHnTsHaivfFX+6vkZ4hTMv8ebzacTSS21d/hmcBhBdRqv/TtxniowdSwhMqk1B4kKm
         emIhz2vVhVRo+9+lAeO/DoQqf48oY1px21BR1YPpOQmnn4w90jQE6Ot7F3NxaMAoU9tj
         TMFQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=ONehLJlM;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::112e as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc;
        bh=Zfi0RpFBGuocefxLWbDIZnqSRTsS6MAQi/ZZh5r7mjk=;
        b=J6/D2Y2QmTNw0BUPXeYueQ4n0SXXfW+sDZZwKNYXpl0Th9t4rYRZ7lGvaEDUCP5IO4
         W5UjknuzEnZ3VLHhN4J6oAKd8/x3C+ksc8yDa02uxBOZuTjvRsRgAyq01CMSuUGeDvMK
         GvvptWSIxgk5ga630440CQp3zOWG7KwDtTnSrRlgtRCMegG9w0LFHw6k+6fIhBpsskPT
         C0eXLIzwBNZiD2G3XhRC9lDyI3bjO9103m4ufuPjwqmBG+1yjWTtXZjzOIQuf6EQ0MNM
         C577xhjVZU2+aPS4s+SsBBLGwI2Zbo5JPWO3oKnOcWm/Cp/jeTxTjvMp7LlZEVZb/BLS
         IA6Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc;
        bh=Zfi0RpFBGuocefxLWbDIZnqSRTsS6MAQi/ZZh5r7mjk=;
        b=EdzSvSlt/Ogir6qjt1H1VAtArts8hT1d6nT4d94AQoh9IOEWW1mVynWAcocp+RM34R
         jCMndZ4LyyTlr4P7gj3MFC3J8fMZciB2/Pne2qjBTvA8HEGmG5zRX6XKYwxl/9wtuXSP
         Nwu6B+ybUIDzxyDT0w1AHJHJtIcclvSoqeuCWiSg4OiEkfJPetr2P1F5mVH/0nMg/Yib
         oTnHVB+YKxuOYZVa9I7b5hF63q4POfCxVeq30+qlg2dep88Za/3uhsVE53/xQO6QtLW4
         J8mzSrDCA8uWmfN0w2sn7w6TT1g/wcIbKsqk/chzzwGApxoRQ9vYK5ybeLfz+sn3y4bM
         IceQ==
X-Gm-Message-State: ACgBeo1ZAb6UE1KwzIkwM6z+t8QNxxE9lTCnnaE2J89YFS2Vp18bJCqD
	OscKwKrD09fAz5BdWwa0PY8=
X-Google-Smtp-Source: AA6agR4YPEdpt/moi4HgvbSS0mD1s+5VpVr5OVrtsx4Y2VLr5zKFqeTk1Q2ymANfGFjn12jSxSa5Zg==
X-Received: by 2002:a17:902:dac8:b0:174:cf17:6e93 with SMTP id q8-20020a170902dac800b00174cf176e93mr14521203plx.93.1661961336648;
        Wed, 31 Aug 2022 08:55:36 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:28c4:b0:1fb:a751:8707 with SMTP id
 f62-20020a17090a28c400b001fba7518707ls1577908pjd.2.-pod-canary-gmail; Wed, 31
 Aug 2022 08:55:36 -0700 (PDT)
X-Received: by 2002:a17:903:32d2:b0:172:f62a:2f33 with SMTP id i18-20020a17090332d200b00172f62a2f33mr26188357plr.16.1661961335953;
        Wed, 31 Aug 2022 08:55:35 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1661961335; cv=none;
        d=google.com; s=arc-20160816;
        b=fueCNDZRKaKc/8+eOwgfD4/4VJ11R+A+gBqYhfrRYwhfAl00/eQXy06K0BN+oDfES2
         oLn2KxHd8iYfiq3phVzD28vkvqsgwLAGwdSqAv1ADYOb+aqwFzzqdxU9foq/9v/FY+Ke
         QSeUt2o+f1a1P54FDNDTvKAcs7gbjfqm7UDjZxYVO4kq7yir1kko4UITKfOtBEsChP6C
         p81jRs63b5FcUrjsBXRUMMYindUxa+V3bVvpiicsUwZhSMfa8sFSTCEv7SERI2PF6TeG
         X1h2LvONYDQ+C850Tp7cFNXHg4Lq0stng9zpUVf30Po7qjoMdgVJMQjJvWpQIw3j2HQw
         XCgg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=sybFcqH1KKlLZJ30kAOhH4vwj7X3FRQlsLR8cFlMDYU=;
        b=pGYQnmx5tllg9pS4nj0tpzgrX5zqQWgkpfX2IpDg4CzIuot6V6MQENB8xKW9g+oFQQ
         NgQ76ZqViMHhw7Ebg7HQXYRfKk3H0CdA6KbjQZauGwWyOpQGgkehNMofxlB3/XeW9IcP
         m5eA2zlGu/xAwz/FWeK3QwNzIpKOHilYmfvLhRL7B4g1Acb5KHFn0eG566bpgDrWb/2z
         m1qBLIV23vKpQgoOorT79+fzx9XejxqmvoAaf/O6obEkPz3gSyEHUxiKrUI49wDGmSoq
         tKAz6KRLN2B1C4Oa67BEsC7W1qPJuxUiXz1OLUDi7CpXntYBxo2BkFodSwENR1ZKWq6T
         At2A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=ONehLJlM;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::112e as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x112e.google.com (mail-yw1-x112e.google.com. [2607:f8b0:4864:20::112e])
        by gmr-mx.google.com with ESMTPS id i189-20020a636dc6000000b0042ba5b4bd9asi81985pgc.2.2022.08.31.08.55.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 31 Aug 2022 08:55:35 -0700 (PDT)
Received-SPF: pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::112e as permitted sender) client-ip=2607:f8b0:4864:20::112e;
Received: by mail-yw1-x112e.google.com with SMTP id 00721157ae682-33dc31f25f9so311226757b3.11
        for <kasan-dev@googlegroups.com>; Wed, 31 Aug 2022 08:55:35 -0700 (PDT)
X-Received: by 2002:a81:a186:0:b0:33d:bf97:5b14 with SMTP id
 y128-20020a81a186000000b0033dbf975b14mr18636737ywg.514.1661961335065; Wed, 31
 Aug 2022 08:55:35 -0700 (PDT)
MIME-Version: 1.0
References: <20220830214919.53220-1-surenb@google.com> <20220830214919.53220-28-surenb@google.com>
 <241c05a3-52a2-d49f-6962-3af5a94bc3fc@infradead.org>
In-Reply-To: <241c05a3-52a2-d49f-6962-3af5a94bc3fc@infradead.org>
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 31 Aug 2022 08:55:24 -0700
Message-ID: <CAJuCfpE2qrN7uXqZjJz6o20Rh4cQgcUBzAxzP4s+u=6XtmBnbg@mail.gmail.com>
Subject: Re: [RFC PATCH 27/30] Code tagging based latency tracking
To: Randy Dunlap <rdunlap@infradead.org>
Cc: Andrew Morton <akpm@linux-foundation.org>, Kent Overstreet <kent.overstreet@linux.dev>, 
	Michal Hocko <mhocko@suse.com>, Vlastimil Babka <vbabka@suse.cz>, Johannes Weiner <hannes@cmpxchg.org>, 
	Roman Gushchin <roman.gushchin@linux.dev>, Mel Gorman <mgorman@suse.de>, 
	Davidlohr Bueso <dave@stgolabs.net>, Matthew Wilcox <willy@infradead.org>, 
	"Liam R. Howlett" <liam.howlett@oracle.com>, David Vernet <void@manifault.com>, 
	Peter Zijlstra <peterz@infradead.org>, Juri Lelli <juri.lelli@redhat.com>, 
	Laurent Dufour <ldufour@linux.ibm.com>, Peter Xu <peterx@redhat.com>, 
	David Hildenbrand <david@redhat.com>, Jens Axboe <axboe@kernel.dk>, mcgrof@kernel.org, 
	masahiroy@kernel.org, nathan@kernel.org, changbin.du@intel.com, 
	ytcoode@gmail.com, Vincent Guittot <vincent.guittot@linaro.org>, 
	Dietmar Eggemann <dietmar.eggemann@arm.com>, Steven Rostedt <rostedt@goodmis.org>, 
	Benjamin Segall <bsegall@google.com>, Daniel Bristot de Oliveira <bristot@redhat.com>, 
	Valentin Schneider <vschneid@redhat.com>, Christopher Lameter <cl@linux.com>, Pekka Enberg <penberg@kernel.org>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, 42.hyeyoo@gmail.com, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, dvyukov@google.com, 
	Shakeel Butt <shakeelb@google.com>, Muchun Song <songmuchun@bytedance.com>, arnd@arndb.de, 
	jbaron@akamai.com, David Rientjes <rientjes@google.com>, Minchan Kim <minchan@google.com>, 
	Kalesh Singh <kaleshsingh@google.com>, kernel-team <kernel-team@android.com>, 
	linux-mm <linux-mm@kvack.org>, iommu@lists.linux.dev, kasan-dev@googlegroups.com, 
	io-uring@vger.kernel.org, linux-arch@vger.kernel.org, 
	xen-devel@lists.xenproject.org, linux-bcache@vger.kernel.org, 
	linux-modules@vger.kernel.org, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: surenb@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=ONehLJlM;       spf=pass
 (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::112e
 as permitted sender) smtp.mailfrom=surenb@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Suren Baghdasaryan <surenb@google.com>
Reply-To: Suren Baghdasaryan <surenb@google.com>
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

On Tue, Aug 30, 2022 at 6:53 PM Randy Dunlap <rdunlap@infradead.org> wrote:
>
>
>
> On 8/30/22 14:49, Suren Baghdasaryan wrote:
> > diff --git a/lib/Kconfig.debug b/lib/Kconfig.debug
> > index b7d03afbc808..b0f86643b8f0 100644
> > --- a/lib/Kconfig.debug
> > +++ b/lib/Kconfig.debug
> > @@ -1728,6 +1728,14 @@ config LATENCYTOP
> >         Enable this option if you want to use the LatencyTOP tool
> >         to find out which userspace is blocking on what kernel operations.
> >
> > +config CODETAG_TIME_STATS
> > +     bool "Code tagging based latency measuring"
> > +     depends on DEBUG_FS
> > +     select TIME_STATS
> > +     select CODE_TAGGING
> > +     help
> > +       Enabling this option makes latency statistics available in debugfs
>
> Missing period at the end of the sentence.

Ack.

>
> --
> ~Randy

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAJuCfpE2qrN7uXqZjJz6o20Rh4cQgcUBzAxzP4s%2Bu%3D6XtmBnbg%40mail.gmail.com.
