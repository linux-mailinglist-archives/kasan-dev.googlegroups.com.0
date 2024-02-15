Return-Path: <kasan-dev+bncBCKMR55PYIGBB5FVXGXAMGQE67CF3AY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13a.google.com (mail-lf1-x13a.google.com [IPv6:2a00:1450:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id 522A0856CEC
	for <lists+kasan-dev@lfdr.de>; Thu, 15 Feb 2024 19:41:57 +0100 (CET)
Received: by mail-lf1-x13a.google.com with SMTP id 2adb3069b0e04-5115b4756d4sf1003541e87.1
        for <lists+kasan-dev@lfdr.de>; Thu, 15 Feb 2024 10:41:57 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708022517; cv=pass;
        d=google.com; s=arc-20160816;
        b=a/q0hq+VG/46aFSDjU/yGN8w76a3tAB5UUrJtt3Weqnnz4ADrgf+Er8txbRgFpNe05
         307Phu7zy33vhIEqfjsd4meD/4noJdai8ICVZNMZH2G7DQvrLYROqRGVFg+/EOG4vI44
         Mqn/0yPI77PnFafHjEu2yg+9QMNNfInIHw2iIWGgHpn1qOpw+MZ5mi1QYabgUK+bAO7Z
         9kKAaQ1NIhSiAyV55SVzpCBsTu9M5Grome/uz0lzxxgYQw9dAvPv5ymis/vuD981BUNY
         4UX59wUhIQxQhv4smKDGktVMQ+059UB5dCgazRcE4LVU+pCVUM2qwBDe83oWzOOofn/c
         6FxA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:dkim-signature;
        bh=IxqTDI3s2FXushweZeO6lE6bho0HUTVIJnLZrxPmZ3c=;
        fh=AcEWtj8BRUW9ugsVPeYXLyQctzLEGB5JN0IgNAEzaP4=;
        b=WMi94g1lvQ5+A4/BCgKYtZy3BYKywcI5qHw35UTKUM77Tk9uBJsHKwtrOpqV3t+8pV
         bOQ4aF7uwyZnIvnevh/agnQy3VQXhiBnzVAVEUj+3xmHiv28kw3sVvz0FjNeimJMh7vL
         +XJFQ90o/9+3+vaPOPGbRT3gKLjTQQX8yc4ug8dfuC7x1eyQgSzURXBTT8hb3OR3iS4S
         64b+6OCuppjIrkLH9RJK52dldzmjxofOKCeyvtdOu44UBaGfyH4hDFb3dXEAYvKdRdUW
         IgCKqUzsw8H6r9/1YYJnmu9I5Q4M+aicuTS1xv8NmWPwD7KzoIKZGIuBRX1i391NqraS
         Hu3Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.com header.s=susede1 header.b=K4vEFx6D;
       dkim=pass header.i=@suse.com header.s=susede1 header.b=K4vEFx6D;
       spf=pass (google.com: domain of mhocko@suse.com designates 195.135.223.131 as permitted sender) smtp.mailfrom=mhocko@suse.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=suse.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708022517; x=1708627317; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:from:to:cc:subject
         :date:message-id:reply-to;
        bh=IxqTDI3s2FXushweZeO6lE6bho0HUTVIJnLZrxPmZ3c=;
        b=X/eAPMwucF2no17WWwHvnzLe4Pzb9bbvK1D4iY+F54TmkfLnlyBPM95O8/Zhcaut2E
         +In0JtnsRJm2kFvHGiyqrUHaEv96eGePibNV3mnnzuPS2uMoRy+9gLB08gxP8jhtSnuJ
         4pgJa6Sn+xpqyd5hHHLXW8+TtUVSmwIU8vRt8zcDS/a8lMlgxo/uatF9wvlLfyGqCEwm
         5yUeG6VnCpBAB4nFjB4/NzSBcqyFwBl/mJT35Bexhbgbpqj4iBbBTHIOH44rHPnnlJco
         msxX0bTumXHx7dobQZ++iulbflLby/W4b5DGDhqq2x9B0gkbwV16ox4THfMADG08AnOR
         zrzQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708022517; x=1708627317;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=IxqTDI3s2FXushweZeO6lE6bho0HUTVIJnLZrxPmZ3c=;
        b=ZLR377k45hMCoDhnT2RijFei9xc0pE3HK/TvgbxIkhXio+tbu8wbUdDHWtSV6vaujd
         pyy4G+s+UUsuOFn69FoNWYgwuofY9qmThU8dzMvbnegvRijceEkfjMDeH2r9jZbPygSJ
         7Lvp+CGtqMonBHBnW79v49L/q86eE2SWF1Dh/9hjUV2xqP/FF9sxJmedB66YoaE6g3dg
         W7xahFsIu/KuNXC8pN0PfCpO6Y+3JhTud4VMjXBrRwU1HP+Pg7j9/jeSvoq3phEqALW0
         UhmxcZQ6bUTuwy/hWKc6VdH5jfLWgpKLZoF2eQMDundVGy0OMO2YFOevDVG+dx02bE9y
         jI2w==
X-Forwarded-Encrypted: i=2; AJvYcCUOqDljbCuGVXsEFUTgdl5SVxyaxJCezknhzJPdOv+bly8SErUGmqLGwa+N3+6hbGkMqmEvPOYSutczwqO4jWCRKUAZv0ZOvA==
X-Gm-Message-State: AOJu0Yz9Yc5DXee5yoI9nzs7gN6C9eyRi1+MQLzsZS/5t2se0lR+K4wM
	8nys1dEAAiKAkF6cLFO5/oByBxWlDYvxLiNAEMG+usQAg6w2kT63
X-Google-Smtp-Source: AGHT+IGup7zSGgVgziO3O9/GGMezf8SPhKwCP+Y7Ic1dKrImXpMqEODTWULSGtXfaR7P5kvFlL0RfQ==
X-Received: by 2002:a19:f70d:0:b0:511:454e:6032 with SMTP id z13-20020a19f70d000000b00511454e6032mr1952687lfe.63.1708022516299;
        Thu, 15 Feb 2024 10:41:56 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:2346:b0:511:62f8:1ec0 with SMTP id
 p6-20020a056512234600b0051162f81ec0ls34287lfu.1.-pod-prod-04-eu; Thu, 15 Feb
 2024 10:41:54 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWcbw6/VpOqWwZOvmf9MKa0in6B+T2c4nnr4JuT9LkHjpU4Cn+mxrAcMne6It4msgr7XGzcwUTLddJTedeMenH0p8Z1jRKPjz0Tqg==
X-Received: by 2002:a05:6512:3292:b0:511:4ff5:4dbc with SMTP id p18-20020a056512329200b005114ff54dbcmr2114984lfe.60.1708022514131;
        Thu, 15 Feb 2024 10:41:54 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1708022514; cv=none;
        d=google.com; s=arc-20160816;
        b=wudhAY8j3Re4BgyYRm3so5ohbRk15Vpyohkhvkox39FJ+t1fha//GTFxZLUt53XhD6
         VhqVjny0fM5TvutNJkImP2KFg2CXPP22P9LevZkcK8vq8ks3taZHXOl9N0OZmoDU+hug
         SadTzFSTCwaTqfisywbRVI6bAQDOnVdNa6g+eg2TcfO6ohb6HXeGBruopJ/NeEWck624
         ECjg5qa/gKGkLpKUwg/pMPTVjCFuC+xWZnu0mJoncgbv9URhYptPsK3b5IwjYZ5Q7jnN
         UmON7nTWdsMOnxAx1lu+KRhHsy2FfxGPqYTOQobBr+/gKkTZ/sAXkpHNOAfPsXNfUo/9
         4gZA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :dkim-signature:dkim-signature;
        bh=6TTmhcKgvDK5cRi30z9TDoJsmkkknH993fB0Fcc6Lyc=;
        fh=+geQM+smpZX7MaYzt9zTpAeUcNjXUwmsbFgQ0lMtIHk=;
        b=d0jp0VkMjYZRVHzM19DNIBdE/pKgMUQMbiBk36WmrEBoGC3gq8fIdg3emRGnNUNAJM
         agkgtlZJOdcJLOVfEpDgUWFCLYROKb14reXnoYnl23RjZ8UB/cmug7VIuhJObiRJZ31K
         OnxnlW08aH/BIWH6KlI8rzgbqevmzvMK0NrQKqrlQLm6GcPjfRM9Fcc6cFy9Qh8NoHS7
         OqQEt5VuDTH/8LbSVg7vtfOhuBLLrPGeIqBM2Jj/kCI3o5KYuzJdnvWwyVJLH0ECEEDc
         HWsv+zeQvOyoh5dcY2M7SkMUJYd1t8GuYHL4CxDapv08kpK6G0XHsNKJnE9M3lElIZV+
         /3Qw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.com header.s=susede1 header.b=K4vEFx6D;
       dkim=pass header.i=@suse.com header.s=susede1 header.b=K4vEFx6D;
       spf=pass (google.com: domain of mhocko@suse.com designates 195.135.223.131 as permitted sender) smtp.mailfrom=mhocko@suse.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=suse.com
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [195.135.223.131])
        by gmr-mx.google.com with ESMTPS id m28-20020a50999c000000b005610f27d125si121852edb.0.2024.02.15.10.41.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 15 Feb 2024 10:41:54 -0800 (PST)
Received-SPF: pass (google.com: domain of mhocko@suse.com designates 195.135.223.131 as permitted sender) client-ip=195.135.223.131;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [10.150.64.97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id 86A671F8D4;
	Thu, 15 Feb 2024 18:41:53 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 1DA2813A53;
	Thu, 15 Feb 2024 18:41:53 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id CjnpBvFazmXdJAAAD6G6ig
	(envelope-from <mhocko@suse.com>); Thu, 15 Feb 2024 18:41:53 +0000
Date: Thu, 15 Feb 2024 19:41:52 +0100
From: "'Michal Hocko' via kasan-dev" <kasan-dev@googlegroups.com>
To: Kent Overstreet <kent.overstreet@linux.dev>
Cc: Suren Baghdasaryan <surenb@google.com>, akpm@linux-foundation.org,
	vbabka@suse.cz, hannes@cmpxchg.org, roman.gushchin@linux.dev,
	mgorman@suse.de, dave@stgolabs.net, willy@infradead.org,
	liam.howlett@oracle.com, corbet@lwn.net, void@manifault.com,
	peterz@infradead.org, juri.lelli@redhat.com,
	catalin.marinas@arm.com, will@kernel.org, arnd@arndb.de,
	tglx@linutronix.de, mingo@redhat.com, dave.hansen@linux.intel.com,
	x86@kernel.org, peterx@redhat.com, david@redhat.com,
	axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org,
	nathan@kernel.org, dennis@kernel.org, tj@kernel.org,
	muchun.song@linux.dev, rppt@kernel.org, paulmck@kernel.org,
	pasha.tatashin@soleen.com, yosryahmed@google.com, yuzhao@google.com,
	dhowells@redhat.com, hughd@google.com, andreyknvl@gmail.com,
	keescook@chromium.org, ndesaulniers@google.com, vvvvvv@google.com,
	gregkh@linuxfoundation.org, ebiggers@google.com, ytcoode@gmail.com,
	vincent.guittot@linaro.org, dietmar.eggemann@arm.com,
	rostedt@goodmis.org, bsegall@google.com, bristot@redhat.com,
	vschneid@redhat.com, cl@linux.com, penberg@kernel.org,
	iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com, glider@google.com,
	elver@google.com, dvyukov@google.com, shakeelb@google.com,
	songmuchun@bytedance.com, jbaron@akamai.com, rientjes@google.com,
	minchan@google.com, kaleshsingh@google.com, kernel-team@android.com,
	linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org,
	iommu@lists.linux.dev, linux-arch@vger.kernel.org,
	linux-fsdevel@vger.kernel.org, linux-mm@kvack.org,
	linux-modules@vger.kernel.org, kasan-dev@googlegroups.com,
	cgroups@vger.kernel.org
Subject: Re: [PATCH v3 31/35] lib: add memory allocations report in show_mem()
Message-ID: <Zc5a8MsJyt27jeJC@tiehlicka>
References: <20240212213922.783301-1-surenb@google.com>
 <20240212213922.783301-32-surenb@google.com>
 <Zc3X8XlnrZmh2mgN@tiehlicka>
 <CAJuCfpHc2ee_V6SGAc_31O_ikjGGNivhdSG+2XNcc9vVmzO-9g@mail.gmail.com>
 <Zc4_i_ED6qjGDmhR@tiehlicka>
 <CAJuCfpHq3N0h6dGieHxD6Au+qs=iKAifFrHAMxTsHTcDrOwSQA@mail.gmail.com>
 <ruxvgrm3scv7zfjzbq22on7tj2fjouydzk33k7m2kukm2n6uuw@meusbsciwuut>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <ruxvgrm3scv7zfjzbq22on7tj2fjouydzk33k7m2kukm2n6uuw@meusbsciwuut>
X-Spam-Level: 
X-Spam-Score: -2.30
X-Spamd-Result: default: False [-2.30 / 50.00];
	 ARC_NA(0.00)[];
	 RCVD_VIA_SMTP_AUTH(0.00)[];
	 BAYES_HAM(-3.00)[100.00%];
	 FROM_HAS_DN(0.00)[];
	 TO_DN_SOME(0.00)[];
	 FREEMAIL_ENVRCPT(0.00)[gmail.com];
	 NEURAL_HAM_LONG(-1.00)[-1.000];
	 TAGGED_RCPT(0.00)[];
	 MIME_GOOD(-0.10)[text/plain];
	 R_RATELIMIT(0.00)[to_ip_from(RLibijwhxa4crtso4io181jfzy)];
	 RCVD_COUNT_THREE(0.00)[3];
	 DKIM_SIGNED(0.00)[suse.com:s=susede1];
	 NEURAL_HAM_SHORT(-0.20)[-1.000];
	 TO_MATCH_ENVRCPT_SOME(0.00)[];
	 RCPT_COUNT_GT_50(0.00)[73];
	 DBL_BLOCKED_OPENRESOLVER(0.00)[suse.com:email];
	 FUZZY_BLOCKED(0.00)[rspamd.com];
	 FROM_EQ_ENVFROM(0.00)[];
	 MIME_TRACE(0.00)[0:+];
	 MID_RHS_NOT_FQDN(0.50)[];
	 FREEMAIL_CC(0.00)[google.com,linux-foundation.org,suse.cz,cmpxchg.org,linux.dev,suse.de,stgolabs.net,infradead.org,oracle.com,lwn.net,manifault.com,redhat.com,arm.com,kernel.org,arndb.de,linutronix.de,linux.intel.com,kernel.dk,soleen.com,gmail.com,chromium.org,linuxfoundation.org,linaro.org,goodmis.org,linux.com,lge.com,bytedance.com,akamai.com,android.com,vger.kernel.org,lists.linux.dev,kvack.org,googlegroups.com];
	 RCVD_TLS_ALL(0.00)[];
	 SUSPICIOUS_RECIPS(1.50)[]
X-Spam-Flag: NO
X-Original-Sender: mhocko@suse.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.com header.s=susede1 header.b=K4vEFx6D;       dkim=pass
 header.i=@suse.com header.s=susede1 header.b=K4vEFx6D;       spf=pass
 (google.com: domain of mhocko@suse.com designates 195.135.223.131 as
 permitted sender) smtp.mailfrom=mhocko@suse.com;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=suse.com
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

On Thu 15-02-24 13:29:40, Kent Overstreet wrote:
> On Thu, Feb 15, 2024 at 08:47:59AM -0800, Suren Baghdasaryan wrote:
> > On Thu, Feb 15, 2024 at 8:45=E2=80=AFAM Michal Hocko <mhocko@suse.com> =
wrote:
> > >
> > > On Thu 15-02-24 06:58:42, Suren Baghdasaryan wrote:
> > > > On Thu, Feb 15, 2024 at 1:22=E2=80=AFAM Michal Hocko <mhocko@suse.c=
om> wrote:
> > > > >
> > > > > On Mon 12-02-24 13:39:17, Suren Baghdasaryan wrote:
> > > > > [...]
> > > > > > @@ -423,4 +424,18 @@ void __show_mem(unsigned int filter, nodem=
ask_t *nodemask, int max_zone_idx)
> > > > > >  #ifdef CONFIG_MEMORY_FAILURE
> > > > > >       printk("%lu pages hwpoisoned\n", atomic_long_read(&num_po=
isoned_pages));
> > > > > >  #endif
> > > > > > +#ifdef CONFIG_MEM_ALLOC_PROFILING
> > > > > > +     {
> > > > > > +             struct seq_buf s;
> > > > > > +             char *buf =3D kmalloc(4096, GFP_ATOMIC);
> > > > > > +
> > > > > > +             if (buf) {
> > > > > > +                     printk("Memory allocations:\n");
> > > > > > +                     seq_buf_init(&s, buf, 4096);
> > > > > > +                     alloc_tags_show_mem_report(&s);
> > > > > > +                     printk("%s", buf);
> > > > > > +                     kfree(buf);
> > > > > > +             }
> > > > > > +     }
> > > > > > +#endif
> > > > >
> > > > > I am pretty sure I have already objected to this. Memory allocati=
ons in
> > > > > the oom path are simply no go unless there is absolutely no other=
 way
> > > > > around that. In this case the buffer could be preallocated.
> > > >
> > > > Good point. We will change this to a smaller buffer allocated on th=
e
> > > > stack and will print records one-by-one. Thanks!
> > >
> > > __show_mem could be called with a very deep call chains. A single
> > > pre-allocated buffer should just do ok.
> >=20
> > Ack. Will do.
>=20
> No, we're not going to permanently burn 4k here.
>=20
> It's completely fine if the allocation fails, there's nothing "unsafe"
> about doing a GFP_ATOMIC allocation here.

Nobody is talking about safety. This is just a wrong thing to do when
you are likely under OOM situation. This is a situation when you
GFP_ATOMIC allocation is _likely_ to fail. Yes, yes you will get some
additional memory reservers head room, but you shouldn't rely on that
because that will make the output unreliable. Not something you want in
situation when you really want to know that information.

More over you do not need to preallocate a full page.

--=20
Michal Hocko
SUSE Labs

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/Zc5a8MsJyt27jeJC%40tiehlicka.
