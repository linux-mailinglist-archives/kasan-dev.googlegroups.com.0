Return-Path: <kasan-dev+bncBCKMR55PYIGBBNEQXKXAMGQEQGXQSFI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33e.google.com (mail-wm1-x33e.google.com [IPv6:2a00:1450:4864:20::33e])
	by mail.lfdr.de (Postfix) with ESMTPS id 7EFEB856F9A
	for <lists+kasan-dev@lfdr.de>; Thu, 15 Feb 2024 22:55:01 +0100 (CET)
Received: by mail-wm1-x33e.google.com with SMTP id 5b1f17b1804b1-411c650ec25sf7506285e9.1
        for <lists+kasan-dev@lfdr.de>; Thu, 15 Feb 2024 13:55:01 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708034101; cv=pass;
        d=google.com; s=arc-20160816;
        b=NiexirGfEAdXazmSP39Kqa8tR8LYUNmoO2Cqc515MGEfVuVZHMVVHW3YmUtG3mT8p8
         qmNdscFYZHpci4YhetKPZRQIjjOgYTV9g4RfWFbU1iNxbBhBgmTfjboSm3osPgYmPIzc
         1KlCdfDnxj00YYVB8HoMqkWIdc0rJ6FmfEpHKOwjdXcY7UKnmFd4DcJiR1IefWhh7nh8
         QxO4m5xQj5dQDulZIAfNCXGqT+zrR17xTnZ737tKYMYwZ6KXnVWgj/AdrQ/iwPYo6OO9
         yQ6eSNmwsawm55iimtFpbYHV3rO3wSW6lQfOdDiYjX4h5zKQ72gjLALYSDJFi71XQIUr
         7PEQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:dkim-signature;
        bh=mTPSHZCyevtjXPlbWawmSgofINZPIC4ym7C1vkHm62Y=;
        fh=hx5756eX1T+P66+NrMDb+/DUGnHjrRHhGwLvTS2qesE=;
        b=weHA2DyagSlbPDyT/NnjZSImz/IiiUvcwvI7BSeZBn3Xv63QnGFrIoxKAaS2YKmip1
         6TpWtkHuOgFkVO/vokkVtY5egAYROYHM5vE9w57DmVmacVyasDXToR2ef3Tp2SOhqWxh
         yHOn7G4ylsESGV1BvWuBYOTmvME2o5a8aRFP3vH8db84SdrIe+dUsSKKFXhWBVrt0EQA
         cflt0kxG15vgM5ph76NFzZA37wgStDgRkv+OUA7AYw1WvxmY/AOzVcoQfST1ahYhexJ2
         dqJYJsi0riqd6NRa65gOjXkJMv5nmbhfO9SBkR1SmFIaxEMjFkmphD2WQU2YrW7QVNO1
         KAfw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.com header.s=susede1 header.b=XEuIaBAO;
       dkim=pass header.i=@suse.com header.s=susede1 header.b=XEuIaBAO;
       spf=pass (google.com: domain of mhocko@suse.com designates 195.135.223.130 as permitted sender) smtp.mailfrom=mhocko@suse.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=suse.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708034101; x=1708638901; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:from:to:cc:subject
         :date:message-id:reply-to;
        bh=mTPSHZCyevtjXPlbWawmSgofINZPIC4ym7C1vkHm62Y=;
        b=PsbTN4kQMqNS4aZjOaIs1Hjw7eBuOz9hoTb52ALDM/1gF3HdkLVgguMdj8yUg+z1VH
         GwC+tfWIoI4tKLAYH5obwPxJZhg2SkKmRqO3cazVGDVLpLOIb85eKcwecNa8i3TviThx
         KGwILOMH6mjQ6gLxxiHHcs8t9rhVjHB8psCtDc87R+mugKwJlyKWmtiDmzJZ8QkAfB14
         cX6mqRlj2ZX37JUmn5ZfGHaX+A/L2SKhrs1v1zCwNrnOS85ujujcE/JU6TFveWf/85h7
         idhp2XYi6kU04Qzvny9Ralv6XOmFOY4GHG4YUDqxNtlnjs3LmoOsmgpf+ilw30hOL2bo
         ynYw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708034101; x=1708638901;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=mTPSHZCyevtjXPlbWawmSgofINZPIC4ym7C1vkHm62Y=;
        b=NGMj3l+HfXviuakip5j1sBPorZqr1QfsuRUwCxxJK4eO7ZtIAENQVew0ba7bN/0fmp
         K6kfB4zbw3AjzSJ6+h1U6dUSdTLFTZMWkEWaJDQ2KpwNWv+97gvRszh8JSi8zEwqzy58
         YMe7GrIU/S0WxwQ7t7+hS1ujNyNAjlcYc4QyydT5REDr5+SEznkQq2H9D41QmkKOzWfv
         cfqS//Lk6FeRwlFx+dQYxABRdut3DSPugOrSn9YYJom4+MePo4YKR7MzR6iNalh3xeFz
         RbhWTm6hEDzJFbv0ZpgC4BaSEO6HBGRpDCSS5m92DgZzdyMO3U2heGjHYvECpA8vUwFg
         CwpQ==
X-Forwarded-Encrypted: i=2; AJvYcCV9y0K0XDQ/LJR46VBTfyPtI0eqiGb9bPbks49Z8XIUw/Sq1sQbd4NFuV8h3d424n3n0MI3sIIsqQWavFcrPoCQE34q8nJ4Ew==
X-Gm-Message-State: AOJu0YxauRg/TmH6JzFlx3hhPC+3BTZSAd9vRWXnP9o0ZhjoG4SlibZh
	czMSrtFwrmznyrJJbSzVds3N90Ggdejv4POauTAr04tZ+/eAyokT
X-Google-Smtp-Source: AGHT+IELx+gIQYL0VZ898f5yqwmp+Z1d+XN+wvUDOv83FLrqOaJrjoC8HN4J9nbK/lgufhUAgu07aw==
X-Received: by 2002:a05:600c:1f8e:b0:411:e178:2a73 with SMTP id je14-20020a05600c1f8e00b00411e1782a73mr2298484wmb.22.1708034100779;
        Thu, 15 Feb 2024 13:55:00 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:58d5:0:b0:33d:1369:6b4e with SMTP id o21-20020a5d58d5000000b0033d13696b4els35846wrf.2.-pod-prod-05-eu;
 Thu, 15 Feb 2024 13:54:59 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXPg+u8MSbZlM8dlsDiBYAtWVO+j+rrzNl4pQS/mdqswb8msJeSGYhyJsYdYMoZl67Kv4EsJ3UWyxgSDDR6o7g+9n0KrmRSTEN1Mg==
X-Received: by 2002:adf:f50d:0:b0:33b:4649:a1e0 with SMTP id q13-20020adff50d000000b0033b4649a1e0mr2222379wro.15.1708034098811;
        Thu, 15 Feb 2024 13:54:58 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1708034098; cv=none;
        d=google.com; s=arc-20160816;
        b=kbuRaH6OwzJHQPNr78UCuAMRXcZ3wP6Ci3MER3/tpywV/P8b2s9BJEULHrplzAx/hy
         fPqsr8PdZvKhQ3kKfXPGIhKisWy5u2WyDQwK73GjU+EWtmKVpUgBBLuQusJZcK9X0rGD
         D5OA/PGg/uhg0k8649azmVMnI4mljhA/pRHW1CPtFtQjBGHItAh1IgrmmIZYsWFUdMql
         nyB6ZUJ0OC9l2TsO3B7zoPKD21svfeN2/l6hTniM/uKEJhXZiEZzNWhXlxPhDtXEnNWk
         9ky8OmLOdGTQVpD9eM6/IwXFKt9G1h2rYselSMwHwxSwgYX/dTy3PDOd1K4aIXGjWy6J
         GeCg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :dkim-signature:dkim-signature;
        bh=78B4kvvPSh8JDp9MHEmUxKS9HotTbXRsyldcw+EPHkU=;
        fh=KgrTcvnzEsaxRv5J9uuaD5frYWVy1ScEih1LFpWrxQc=;
        b=f0FMM8MGejI/KomsVY/JimmbsYDiG4uPkfOlNNJdrKzoHRprlISKx81g3vEYpFvwC0
         MpXSYqo00HiOr65ULifkhfGypuX2JcZ3wtrm72GPik8OBRZeze/mTWfBgsV+7p1kapPV
         a5mAVEtzQa1yL5ykYdoCAoep6ZbUoZ8Ie05KLCnOULpbJjgXwln9H788RFzsUnW6Y0OW
         /GFfejJcSV9Mh7fgl7exGC7h0pXwzLi7pQEnvIvgsDkAiN+qi+gNVHzccu518K79HtD/
         4GGrjxqmuVlNM74St16XUyIw2mcHtEDlCZ2bmPDrwQ/1+xlZ7IGVXu0UtQsUUdbFjKGa
         z/ZQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.com header.s=susede1 header.b=XEuIaBAO;
       dkim=pass header.i=@suse.com header.s=susede1 header.b=XEuIaBAO;
       spf=pass (google.com: domain of mhocko@suse.com designates 195.135.223.130 as permitted sender) smtp.mailfrom=mhocko@suse.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=suse.com
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [195.135.223.130])
        by gmr-mx.google.com with ESMTPS id z4-20020a5d44c4000000b0033cf7e78241si11812wrr.3.2024.02.15.13.54.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 15 Feb 2024 13:54:58 -0800 (PST)
Received-SPF: pass (google.com: domain of mhocko@suse.com designates 195.135.223.130 as permitted sender) client-ip=195.135.223.130;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [10.150.64.97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id 60B1C22056;
	Thu, 15 Feb 2024 21:54:58 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 38FD213A82;
	Thu, 15 Feb 2024 21:54:58 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id QXBuDTKIzmWKTwAAD6G6ig
	(envelope-from <mhocko@suse.com>); Thu, 15 Feb 2024 21:54:58 +0000
Date: Thu, 15 Feb 2024 22:54:53 +0100
From: "'Michal Hocko' via kasan-dev" <kasan-dev@googlegroups.com>
To: Kent Overstreet <kent.overstreet@linux.dev>
Cc: Vlastimil Babka <vbabka@suse.cz>,
	Suren Baghdasaryan <surenb@google.com>, akpm@linux-foundation.org,
	hannes@cmpxchg.org, roman.gushchin@linux.dev, mgorman@suse.de,
	dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com,
	corbet@lwn.net, void@manifault.com, peterz@infradead.org,
	juri.lelli@redhat.com, catalin.marinas@arm.com, will@kernel.org,
	arnd@arndb.de, tglx@linutronix.de, mingo@redhat.com,
	dave.hansen@linux.intel.com, x86@kernel.org, peterx@redhat.com,
	david@redhat.com, axboe@kernel.dk, mcgrof@kernel.org,
	masahiroy@kernel.org, nathan@kernel.org, dennis@kernel.org,
	tj@kernel.org, muchun.song@linux.dev, rppt@kernel.org,
	paulmck@kernel.org, pasha.tatashin@soleen.com,
	yosryahmed@google.com, yuzhao@google.com, dhowells@redhat.com,
	hughd@google.com, andreyknvl@gmail.com, keescook@chromium.org,
	ndesaulniers@google.com, vvvvvv@google.com,
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
Message-ID: <Zc6ILbveSQvDtayj@tiehlicka>
References: <20240212213922.783301-1-surenb@google.com>
 <20240212213922.783301-32-surenb@google.com>
 <Zc3X8XlnrZmh2mgN@tiehlicka>
 <CAJuCfpHc2ee_V6SGAc_31O_ikjGGNivhdSG+2XNcc9vVmzO-9g@mail.gmail.com>
 <Zc4_i_ED6qjGDmhR@tiehlicka>
 <CAJuCfpHq3N0h6dGieHxD6Au+qs=iKAifFrHAMxTsHTcDrOwSQA@mail.gmail.com>
 <ruxvgrm3scv7zfjzbq22on7tj2fjouydzk33k7m2kukm2n6uuw@meusbsciwuut>
 <320cd134-b767-4f29-869b-d219793ba8a1@suse.cz>
 <efxe67vo32epvmyzplmpd344nw2wf37azicpfhvkt3zz4aujm3@n27pl5j5zahj>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <efxe67vo32epvmyzplmpd344nw2wf37azicpfhvkt3zz4aujm3@n27pl5j5zahj>
X-Spamd-Result: default: False [-1.10 / 50.00];
	 ARC_NA(0.00)[];
	 RCVD_VIA_SMTP_AUTH(0.00)[];
	 BAYES_HAM(-3.00)[100.00%];
	 FROM_HAS_DN(0.00)[];
	 TO_DN_SOME(0.00)[];
	 FREEMAIL_ENVRCPT(0.00)[gmail.com];
	 TAGGED_RCPT(0.00)[];
	 MIME_GOOD(-0.10)[text/plain];
	 R_RATELIMIT(0.00)[to_ip_from(RLibijwhxa4crtso4io181jfzy)];
	 RCVD_COUNT_THREE(0.00)[3];
	 DKIM_SIGNED(0.00)[suse.com:s=susede1];
	 TO_MATCH_ENVRCPT_SOME(0.00)[];
	 RCPT_COUNT_GT_50(0.00)[73];
	 DBL_BLOCKED_OPENRESOLVER(0.00)[suse.com:email];
	 FUZZY_BLOCKED(0.00)[rspamd.com];
	 FROM_EQ_ENVFROM(0.00)[];
	 MIME_TRACE(0.00)[0:+];
	 MID_RHS_NOT_FQDN(0.50)[];
	 FREEMAIL_CC(0.00)[suse.cz,google.com,linux-foundation.org,cmpxchg.org,linux.dev,suse.de,stgolabs.net,infradead.org,oracle.com,lwn.net,manifault.com,redhat.com,arm.com,kernel.org,arndb.de,linutronix.de,linux.intel.com,kernel.dk,soleen.com,gmail.com,chromium.org,linuxfoundation.org,linaro.org,goodmis.org,linux.com,lge.com,bytedance.com,akamai.com,android.com,vger.kernel.org,lists.linux.dev,kvack.org,googlegroups.com];
	 RCVD_TLS_ALL(0.00)[];
	 SUSPICIOUS_RECIPS(1.50)[]
X-Spam-Level: 
X-Spam-Flag: NO
X-Spam-Score: -1.10
X-Original-Sender: mhocko@suse.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.com header.s=susede1 header.b=XEuIaBAO;       dkim=pass
 header.i=@suse.com header.s=susede1 header.b=XEuIaBAO;       spf=pass
 (google.com: domain of mhocko@suse.com designates 195.135.223.130 as
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

On Thu 15-02-24 15:33:30, Kent Overstreet wrote:
> On Thu, Feb 15, 2024 at 09:22:07PM +0100, Vlastimil Babka wrote:
> > On 2/15/24 19:29, Kent Overstreet wrote:
> > > On Thu, Feb 15, 2024 at 08:47:59AM -0800, Suren Baghdasaryan wrote:
> > >> On Thu, Feb 15, 2024 at 8:45=E2=80=AFAM Michal Hocko <mhocko@suse.co=
m> wrote:
> > >> >
> > >> > On Thu 15-02-24 06:58:42, Suren Baghdasaryan wrote:
> > >> > > On Thu, Feb 15, 2024 at 1:22=E2=80=AFAM Michal Hocko <mhocko@sus=
e.com> wrote:
> > >> > > >
> > >> > > > On Mon 12-02-24 13:39:17, Suren Baghdasaryan wrote:
> > >> > > > [...]
> > >> > > > > @@ -423,4 +424,18 @@ void __show_mem(unsigned int filter, no=
demask_t *nodemask, int max_zone_idx)
> > >> > > > >  #ifdef CONFIG_MEMORY_FAILURE
> > >> > > > >       printk("%lu pages hwpoisoned\n", atomic_long_read(&num=
_poisoned_pages));
> > >> > > > >  #endif
> > >> > > > > +#ifdef CONFIG_MEM_ALLOC_PROFILING
> > >> > > > > +     {
> > >> > > > > +             struct seq_buf s;
> > >> > > > > +             char *buf =3D kmalloc(4096, GFP_ATOMIC);
> > >> > > > > +
> > >> > > > > +             if (buf) {
> > >> > > > > +                     printk("Memory allocations:\n");
> > >> > > > > +                     seq_buf_init(&s, buf, 4096);
> > >> > > > > +                     alloc_tags_show_mem_report(&s);
> > >> > > > > +                     printk("%s", buf);
> > >> > > > > +                     kfree(buf);
> > >> > > > > +             }
> > >> > > > > +     }
> > >> > > > > +#endif
> > >> > > >
> > >> > > > I am pretty sure I have already objected to this. Memory alloc=
ations in
> > >> > > > the oom path are simply no go unless there is absolutely no ot=
her way
> > >> > > > around that. In this case the buffer could be preallocated.
> > >> > >
> > >> > > Good point. We will change this to a smaller buffer allocated on=
 the
> > >> > > stack and will print records one-by-one. Thanks!
> > >> >
> > >> > __show_mem could be called with a very deep call chains. A single
> > >> > pre-allocated buffer should just do ok.
> > >>=20
> > >> Ack. Will do.
> > >=20
> > > No, we're not going to permanently burn 4k here.
> > >=20
> > > It's completely fine if the allocation fails, there's nothing "unsafe=
"
> > > about doing a GFP_ATOMIC allocation here.
> >=20
> > Well, I think without __GFP_NOWARN it will cause a warning and thus
> > recursion into __show_mem(), potentially infinite? Which is of course
> > trivial to fix, but I'd myself rather sacrifice a bit of memory to get =
this
> > potentially very useful output, if I enabled the profiling. The necessa=
ry
> > memory overhead of page_ext and slabobj_ext makes the printing buffer
> > overhead negligible in comparison?
>=20
> __GFP_NOWARN is a good point, we should have that.
>=20
> But - and correct me if I'm wrong here - doesn't an OOM kick in well
> before GFP_ATOMIC 4k allocations are failing?

Not really, GFP_ATOMIC users can compete with reclaimers and consume
those reserves.

> I'd expect the system to
> be well and truly hosed at that point.

It is OOMed...
=20
> If we want this report to be 100% reliable, then yes the preallocated
> buffer makes sense - but I don't think 100% makes sense here; I think we
> can accept ~99% and give back that 4k.

Think about that from the memory reserves consumers. The atomic reserve
is a scarse resource and now you want to use it for debugging purposes
for which you could have preallocated.
--=20
Michal Hocko
SUSE Labs

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/Zc6ILbveSQvDtayj%40tiehlicka.
