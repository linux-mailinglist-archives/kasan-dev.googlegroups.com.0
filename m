Return-Path: <kasan-dev+bncBCKMR55PYIGBBH5NZWVAMGQETLH5YRQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53a.google.com (mail-ed1-x53a.google.com [IPv6:2a00:1450:4864:20::53a])
	by mail.lfdr.de (Postfix) with ESMTPS id BF7DC7EAEA8
	for <lists+kasan-dev@lfdr.de>; Tue, 14 Nov 2023 12:14:40 +0100 (CET)
Received: by mail-ed1-x53a.google.com with SMTP id 4fb4d7f45d1cf-54366567af4sf6336923a12.1
        for <lists+kasan-dev@lfdr.de>; Tue, 14 Nov 2023 03:14:40 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1699960480; cv=pass;
        d=google.com; s=arc-20160816;
        b=vCGhpq4l+Uv9E5hyV2oEqmxKErNoJqSz+/ZxdnOhLgOZ6iU9jESGW2vXAaLTEoExS+
         r1u5u4oJxjlltn39PaoSJ0zKSNgI2FEoSGqPybQE1sqJsS2JZiBYIv2FsgLsdDgTSYKf
         wRpxlSWNHBKS5JIGL09nD4GlrTpVgcFvGcE0f5uBJWAgktYWU7TLCuXG0bL5s8nufpWo
         l7IN3ny58I3zOd4mtvmmSpkekjUxf9JQ8oeLROLPM6iKMJluclNlkaQ4fso5AdQQu5YZ
         k13p0DDKVOqr+35QUpuNPwYCfM1NeS2cPD9Xmk1yTAhKn71LpuOS5uX6WV7/2VY57VVf
         no7Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=r+CbTKpLkmD+TIHjJzOqMrB/fiQl6MOOD9/EuoEyCWE=;
        fh=nYtaDO5H8e3I+e0Fs1cFZXNS6k7fh10G/jAvTGFgWoA=;
        b=CP/ZQKWEns0m7xWDEutswT0leJG2DZr0p83gaa6fWqxDFl+JJtTWBkXf9gIfw4Jaqh
         urEFW1PDBdXtDgmpI1i1jB7whCsm4jOEPrQIXjXwsMRc0wCwUZO23ZpSL/kLk5EvEAub
         wNPS5CkqUV5Bg2gvOG9ucJJ+rTgg3NgONWGoSIaalN/tqsbRU/x78JHFMiZTnlJuuPgI
         5/w2ycFqSIrz3vfIvmvgp4Q3u6P2ciLW4ISqhhBFVuYifKM+D4LDdG5AgYe+yO62IkpO
         7GkzeHj6colqFdOiTyYSOYoYK4L0ldaJCpIeKF6a+L0cEmSUyn0cfXgoJ9qZZQvOH/0o
         dgIg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.com header.s=susede1 header.b=mFbVnbw1;
       spf=pass (google.com: domain of mhocko@suse.com designates 195.135.220.28 as permitted sender) smtp.mailfrom=mhocko@suse.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=suse.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1699960480; x=1700565280; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=r+CbTKpLkmD+TIHjJzOqMrB/fiQl6MOOD9/EuoEyCWE=;
        b=DBziYrU4gj1E1y/yLElCtYa3C/6gRXcaJZOm1e+hpGvazqMyv8KnDZpIwVSZ1Hrcsc
         j+d7ea//AemihORT7hjzTahZD5TVVTiDNo8pnVI9Xg45vCzXcP4LwNY1MIAR5fnSBit8
         2R42JfgtHVgyYuL6nktuTc2eH4MI75ZkBDVH0lGFtzAFmQ3svaEajdpfVoK98qnUqD+g
         I/GOg9EZ5xS2SVIAaKMJjc9JtqM6tCyIhncl8XvjX2gVsddJp9F4xYqdR0BRYNqFsESC
         a7YtCygU6fjji8I0YtpQTMhON2X2iHWQZWX7hZbjKHcaFJaYZaUixqotob/Ecfxr3Kqt
         /47w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1699960480; x=1700565280;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=r+CbTKpLkmD+TIHjJzOqMrB/fiQl6MOOD9/EuoEyCWE=;
        b=flkixbN5fQOra0hGaiTYsxLRXo22Eze4ZXgAkalvIQ/NbkqpB8XaoAoTFIkRK4TsNz
         UzAHJsmT0LoVehr/9+6a26eqQ5Vfdp4mg3EjSGgrhfUk8KpfjBQX+GINR82Kg3j7E3iF
         w/m2ymhffXEKZ1mXrx/vb5SVJqrowFBvOTOypSH4BV+0dc1xicA1OGHIn+ghpJ9EMYLr
         pSxOVp99OQuk7Cbkp2qOPCxa39ayXKdfzVXkDn1McBNLm4ZKdxw3abt3NykO17e838JH
         n8mEH8OwNl25n2pD6C4EfknCu4CBlL1HB0h6EoNi3EGlCqKkKJ/Q4S9Uj/XFwAz3BzNB
         wEgA==
X-Gm-Message-State: AOJu0YwWuGzq1V3Z2wl4i3wzzrEFrkoqE+/WLis/vyGzdsWOBw83Po/e
	uge3u5sXIaSMvDv1Di2lqfE=
X-Google-Smtp-Source: AGHT+IEBj9AUov29Llez4LBQ8OqUs+r4l1mO4Q1MjUfdH5DCrpVGjIEhSwfWUoFdLexRvn0WE9kGrw==
X-Received: by 2002:a05:6402:440f:b0:531:14c4:ae30 with SMTP id y15-20020a056402440f00b0053114c4ae30mr2538485eda.0.1699960479747;
        Tue, 14 Nov 2023 03:14:39 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:2ce:b0:544:cb17:901d with SMTP id
 b14-20020a05640202ce00b00544cb17901dls1082166edx.2.-pod-prod-00-eu; Tue, 14
 Nov 2023 03:14:37 -0800 (PST)
X-Received: by 2002:a17:907:d408:b0:9ed:da4b:189e with SMTP id vi8-20020a170907d40800b009edda4b189emr1910758ejc.5.1699960477500;
        Tue, 14 Nov 2023 03:14:37 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1699960477; cv=none;
        d=google.com; s=arc-20160816;
        b=Egu9dmtqu4pwoy578UROhq+KEHDiX9l5j1KXIYhuonnmXd1XF8bGsYLrkdwtj9IMhN
         ADRXn3aFpxT8Oh7V++l2qOCP5/f9uEjGXqpphmrx6V/jUrkMoqc05+WyU7mBeVXGaNd9
         SdGdFa1D1pqgK/FIC1DStLiOZdCx+PGXaM1/gn53jvtJKMFUaw24cOWxGl5hJ0yNpMMh
         SkJ7Y9sUi5dcwk+xRYvWHdlxHAf/CJjVrhk80e0xgtV46x0nQecpicZn0ZlYCburBfpQ
         KNvKjJARbDhjsyj/n/kVX/p3+G5EV9kHZJfYSCVpzpPBgCRyPMWIJI17tkwSrRoegTIE
         KQ8Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=XDqzWLx2K+JvK/ZPpwmsrJYyQOBFyyUyoFsG3is7Iq8=;
        fh=nYtaDO5H8e3I+e0Fs1cFZXNS6k7fh10G/jAvTGFgWoA=;
        b=mQEIPmz9Y4v9H4iYnOMYBNigkQFkJiSSnr1TOS77TLzLyvPDbURa9qL1J569Nxj1Lf
         Rnm9IJGFziac6swqf52oo2A6YqKKeJm+p8fVP2gVWzMRaftkbcMrzDsM8wQfyf8e7QRa
         xNZRT2PuaJ3j3YDUNM7z9rkwvmb7N3Z7mLI/NLkOo7jjRrhZGnjY9ot+a+C5bOdVTvPM
         vup1J9jN6r+S531pjeTiMe47K3KecnRPIyyrdBfY3b67YIP1MeizVumGrS16Bz+es5I8
         6uVvleWLQQO2D+lOYWBcnH+2NuQm8gr6s51eg96S/VA0nhPP3ay8kN+b/wqGKVpA3bRj
         CfGQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.com header.s=susede1 header.b=mFbVnbw1;
       spf=pass (google.com: domain of mhocko@suse.com designates 195.135.220.28 as permitted sender) smtp.mailfrom=mhocko@suse.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=suse.com
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [195.135.220.28])
        by gmr-mx.google.com with ESMTPS id bn4-20020a170906c0c400b009f0ec8d7ff6si18988ejb.1.2023.11.14.03.14.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 14 Nov 2023 03:14:37 -0800 (PST)
Received-SPF: pass (google.com: domain of mhocko@suse.com designates 195.135.220.28 as permitted sender) client-ip=195.135.220.28;
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id 134DD21898;
	Tue, 14 Nov 2023 11:14:37 +0000 (UTC)
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by imap2.suse-dmz.suse.de (Postfix) with ESMTPS id D79A813460;
	Tue, 14 Nov 2023 11:14:36 +0000 (UTC)
Received: from dovecot-director2.suse.de ([192.168.254.65])
	by imap2.suse-dmz.suse.de with ESMTPSA
	id sEGsMZxWU2UERQAAMHmgww
	(envelope-from <mhocko@suse.com>); Tue, 14 Nov 2023 11:14:36 +0000
Date: Tue, 14 Nov 2023 12:14:36 +0100
From: "'Michal Hocko' via kasan-dev" <kasan-dev@googlegroups.com>
To: Vlastimil Babka <vbabka@suse.cz>
Cc: David Rientjes <rientjes@google.com>, Christoph Lameter <cl@linux.com>,
	Pekka Enberg <penberg@kernel.org>,
	Joonsoo Kim <iamjoonsoo.kim@lge.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Hyeonggon Yoo <42.hyeyoo@gmail.com>,
	Roman Gushchin <roman.gushchin@linux.dev>, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org, patches@lists.linux.dev,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Marco Elver <elver@google.com>,
	Johannes Weiner <hannes@cmpxchg.org>,
	Shakeel Butt <shakeelb@google.com>,
	Muchun Song <muchun.song@linux.dev>,
	Kees Cook <keescook@chromium.org>, kasan-dev@googlegroups.com,
	cgroups@vger.kernel.org
Subject: Re: [PATCH 04/20] mm/memcontrol: remove CONFIG_SLAB #ifdef guards
Message-ID: <ZVNWnPYHXpQjCDZ3@tiehlicka>
References: <20231113191340.17482-22-vbabka@suse.cz>
 <20231113191340.17482-26-vbabka@suse.cz>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20231113191340.17482-26-vbabka@suse.cz>
X-Spam-Level: 
X-Spam-Score: -1.97
X-Spamd-Result: default: False [-1.97 / 50.00];
	 ARC_NA(0.00)[];
	 RCVD_VIA_SMTP_AUTH(0.00)[];
	 RCVD_TLS_ALL(0.00)[];
	 FROM_HAS_DN(0.00)[];
	 TO_DN_SOME(0.00)[];
	 FREEMAIL_ENVRCPT(0.00)[gmail.com];
	 TO_MATCH_ENVRCPT_ALL(0.00)[];
	 TAGGED_RCPT(0.00)[];
	 MIME_GOOD(-0.10)[text/plain];
	 BAYES_SPAM(0.13)[63.14%];
	 NEURAL_HAM_LONG(-3.00)[-1.000];
	 DKIM_SIGNED(0.00)[suse.com:s=susede1];
	 NEURAL_HAM_SHORT(-1.00)[-1.000];
	 RCPT_COUNT_TWELVE(0.00)[23];
	 FROM_EQ_ENVFROM(0.00)[];
	 MIME_TRACE(0.00)[0:+];
	 MID_RHS_NOT_FQDN(0.50)[];
	 FREEMAIL_CC(0.00)[google.com,linux.com,kernel.org,lge.com,linux-foundation.org,gmail.com,linux.dev,kvack.org,vger.kernel.org,lists.linux.dev,arm.com,cmpxchg.org,chromium.org,googlegroups.com];
	 RCVD_COUNT_TWO(0.00)[2];
	 SUSPICIOUS_RECIPS(1.50)[]
X-Spam-Flag: NO
X-Original-Sender: mhocko@suse.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.com header.s=susede1 header.b=mFbVnbw1;       spf=pass
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

On Mon 13-11-23 20:13:45, Vlastimil Babka wrote:
> With SLAB removed, these are never true anymore so we can clean up.
> 
> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>

Acked-by: Michal Hocko <mhocko@suse.com>

> ---
>  mm/memcontrol.c | 5 ++---
>  1 file changed, 2 insertions(+), 3 deletions(-)
> 
> diff --git a/mm/memcontrol.c b/mm/memcontrol.c
> index 774bd6e21e27..947fb50eba31 100644
> --- a/mm/memcontrol.c
> +++ b/mm/memcontrol.c
> @@ -5149,7 +5149,7 @@ static ssize_t memcg_write_event_control(struct kernfs_open_file *of,
>  	return ret;
>  }
>  
> -#if defined(CONFIG_MEMCG_KMEM) && (defined(CONFIG_SLAB) || defined(CONFIG_SLUB_DEBUG))
> +#if defined(CONFIG_MEMCG_KMEM) && defined(CONFIG_SLUB_DEBUG)
>  static int mem_cgroup_slab_show(struct seq_file *m, void *p)
>  {
>  	/*
> @@ -5258,8 +5258,7 @@ static struct cftype mem_cgroup_legacy_files[] = {
>  		.write = mem_cgroup_reset,
>  		.read_u64 = mem_cgroup_read_u64,
>  	},
> -#if defined(CONFIG_MEMCG_KMEM) && \
> -	(defined(CONFIG_SLAB) || defined(CONFIG_SLUB_DEBUG))
> +#if defined(CONFIG_MEMCG_KMEM) && defined(CONFIG_SLUB_DEBUG)
>  	{
>  		.name = "kmem.slabinfo",
>  		.seq_show = mem_cgroup_slab_show,
> -- 
> 2.42.1

-- 
Michal Hocko
SUSE Labs

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZVNWnPYHXpQjCDZ3%40tiehlicka.
