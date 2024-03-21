Return-Path: <kasan-dev+bncBCS2NBWRUIFBBCGH6KXQMGQEVDRR6WQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43e.google.com (mail-wr1-x43e.google.com [IPv6:2a00:1450:4864:20::43e])
	by mail.lfdr.de (Postfix) with ESMTPS id 5F373886266
	for <lists+kasan-dev@lfdr.de>; Thu, 21 Mar 2024 22:15:53 +0100 (CET)
Received: by mail-wr1-x43e.google.com with SMTP id ffacd0b85a97d-33ed44854ddsf595892f8f.2
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Mar 2024 14:15:53 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1711055753; cv=pass;
        d=google.com; s=arc-20160816;
        b=HI4HvdlB38QbcUbzx1dIrlHtgVcb4hmQqMUIn2s2yeEZUkcoGATeJMuYaYRbl9JT+j
         t+lho86S8JZ65h9sMONkFlOP0rfVZtGmv5KVPVsZcJ9rjOPEoSNJhR5a2lutFmnEk6pJ
         cD9usi5zLxY2CBn94+a5XuM14Rn8rAz3uOZkcT0n1ZV3F8dmBDTwtb/PFST+xSKWvLc0
         WS+IppOWGyW912MnRWU9WKe4re4Xl5lZGI3GgSUiXb4lZhrPCCUoMpZcOfi2YXJRla/V
         OE2I5uNJRtUWiFnC7I/5C5QeAQwPdo8feNLK8JdginbDln2GLHNQjGQrSxGa1j6aq4Hb
         rnUA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=Nhj1Q5+y1BuCQOZhmgrXFirMKd90FtlJCfNOLHwkoN4=;
        fh=1AcykYonkgz+zGBaIKK99XALH04pUPO0stDlvb2SIWs=;
        b=YXz2LTbP3VEhu9yFZEh2gQRg7AypGJyZUXQ++5gPyJN83FywRWQ+hbboan+gZ+DL1X
         1GLij85S51aS/Ps5+Wu3gkAbxOCdGjT0vIhsZmU6I1P982qDnNXr7f9x6a4z19hjByC/
         TmbNbW4Jh51oQUkycFJN8mxyKLh7oE1lQSnEU2DU5mCIdlBZ9KMZIj/YCfyZJ6k+/Rgq
         ZPxh+igjCVl4Dcyp6ma5/g4LHCs+nJPK/1osS8/9PLMr2Z7gimJAaYkpExHyd1NVEHt/
         6b4ILtaI1vVOZgn/ie7UspKA05hbkF+yrWWEqemowh5Cl5PSCC2aNWjCbdKZV1gywPSd
         r6WA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=eH8oK6O3;
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 91.218.175.181 as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1711055753; x=1711660553; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=Nhj1Q5+y1BuCQOZhmgrXFirMKd90FtlJCfNOLHwkoN4=;
        b=EF74byAxlGEY1FvbVM3U3+4jnCX6bQVP1PTHQavSNmkx6GIEwEPcTMInftPu4SAbin
         Y+HTNu6Isg+tr2buSE7lVAcBn+Q6cVr0h+ggBBnTqEZ6+goEYq4PZ/aH5nLodmuvGFC2
         v7+fWgyVwaYMV6OWABZIho+M8zIu0oLmLMy50cHpRj6ncqwf5iRfivz88Gb55csw8Cwy
         id61cAWDtNDLuf1BeplfvhjTRS3wLdCsuIcybyAQ9tyHY1NisfMLSyJlWF99SGQfIJ24
         xa0Xe+eS9Dnwqz164fAtXs9vtL3VH3p4MuchtYam/2Q4UAX8c3iAN7QaZ4tlFt6MDtwp
         0c3Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1711055753; x=1711660553;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=Nhj1Q5+y1BuCQOZhmgrXFirMKd90FtlJCfNOLHwkoN4=;
        b=if7IX4Clybqbj7rKZOsvGSFu0FdnOrUzUcsRnyNzb+LmYfs/wt8yO03M3hOzkl6xnw
         GJ2qIJICdBdQT2X7Z0qys3SDjpEs1VraClwY0Pf3i7oKoGqKfAb6SYEIVyQIaKxv8uSW
         vA99jt4y4NxKcgDEt3RhS89nC2RwPGXCRx7VsYtXbTwWf/jww1I4ZYk9W0eo3H011ozN
         EEd07M11pcThdkUfw5vFUX1fLflQlSzLnt7i+/QizC7buMpM43go/3gMc+Nd2XvhFtMQ
         uIETWCRjyK7fmyOWRycfkF+eGfbU00dco+Sd5WGGu2d6qkE9sy5sSqJNjUlbhWmSavJ/
         uJow==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVyeF9mXL/UNpASpeSv/k0U4nc+kjp8WBMzk1hiTSUCktCujU34elC8D4YBfrDG7vmVTgxMGa89kB/Cp4DMtCuKMZkHFKTUPg==
X-Gm-Message-State: AOJu0Yx9lJYI0P1IYVR67D9O2gC2VWZKYx5oYgFsLrGhkzMdcdKFlPTJ
	5a6EmGRI0QXbxCK3YgZmPuA2t1Yxk3wEygk1M9oXUgeUoVCkL+Gy
X-Google-Smtp-Source: AGHT+IHhm98x58Nm/3Puq7IhS6wLTq9KwinMJxGbFF8vMNfUtvLrKez4qikgOr6fMkMR+qUa7t6gsw==
X-Received: by 2002:a5d:5506:0:b0:33e:dd4:ca5c with SMTP id b6-20020a5d5506000000b0033e0dd4ca5cmr214083wrv.45.1711055752522;
        Thu, 21 Mar 2024 14:15:52 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:3d8d:b0:414:8fc:c9f1 with SMTP id
 bi13-20020a05600c3d8d00b0041408fcc9f1ls632683wmb.2.-pod-prod-09-eu; Thu, 21
 Mar 2024 14:15:51 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWgzy7pg5Vzc1J/gMRZyKjspLWFGYmXHN4JxoBLpmtykK16lp5yc13dmPvWAekgfcw1vmFb4/VvyP8Z8lhbvap1BH7QGfncBpR1hw==
X-Received: by 2002:a05:600c:4f86:b0:414:6219:3090 with SMTP id n6-20020a05600c4f8600b0041462193090mr199399wmq.38.1711055751013;
        Thu, 21 Mar 2024 14:15:51 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1711055750; cv=none;
        d=google.com; s=arc-20160816;
        b=HW46IYwZCX3O+9yONhRjEbELJr3JALaCZn+X819cENFOKYnm4/TKajpEOirifiVOqd
         lP/FknmuROiUETnpDHrFGENNV2T7+m1IkFzZK6wFg+bGOnKq5Ks6kOYd2/x6SmIQzJJ8
         RVKRtZea1Mg1n0yI8j+ua40IJvt0RuB1R5hc8SrV+fo9Fw2jfbCVBc7ZRT7j1fx89vrX
         lXboFsC+/vnC19bLVSpdQim4TAxOXAnhrQno10XWk8lJFuQCTcwZABe6ioqK3mlHdVrE
         fP4cMiuXdgXf/rBO+O8fDi3buDEcpXULYWKus+p93UDVVOiaiTmCug7B4gHYkldINuJq
         /gzA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:dkim-signature:date;
        bh=Zg+YcWxUSQ4PW9xsrv1Bq8A+bJWYc2oFdFSsmHcvMpk=;
        fh=Q8iXvLX7AMaL15JHtP679LkEjZAcP9VlW5xkTCDgguY=;
        b=roh3SIFa3DgPXVdVXvriOrPb3UeqPNcGZ4f+rDGcxlpWriEGm79yc9dAz3C3Nrh5YP
         L3KgKb9QBSJRfNsC8ADsUHQyzXX5gy6z/KtMQByq5obA3jlH15SENxIQXt5llRzkH/QA
         /pUeJdfKj0KL6tryi1j5Pz6XM/MqKbTnu5NuS89ZKmg+0axwTVdWKdtMD2t1Z5VzPj0o
         jvIYOR4FMLLukIc8hTLVrud5LjrOjKzRxoEkcHDLTdvcSMVpJDF9THD1GLQLw8CXjoPO
         lTy8t+L1c5p0KqjWUWNF/QSbhOg7eFL56T3C4d91msOGzKtw9uEHKRXgh15hmAt9Kh3V
         HMvA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=eH8oK6O3;
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 91.218.175.181 as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-181.mta0.migadu.com (out-181.mta0.migadu.com. [91.218.175.181])
        by gmr-mx.google.com with ESMTPS id p6-20020a05600c430600b004140e37ecf5si243385wme.1.2024.03.21.14.15.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 21 Mar 2024 14:15:50 -0700 (PDT)
Received-SPF: pass (google.com: domain of kent.overstreet@linux.dev designates 91.218.175.181 as permitted sender) client-ip=91.218.175.181;
Date: Thu, 21 Mar 2024 17:15:39 -0400
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: Kent Overstreet <kent.overstreet@linux.dev>
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Suren Baghdasaryan <surenb@google.com>, mhocko@suse.com, 
	vbabka@suse.cz, hannes@cmpxchg.org, roman.gushchin@linux.dev, mgorman@suse.de, 
	dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com, 
	penguin-kernel@i-love.sakura.ne.jp, corbet@lwn.net, void@manifault.com, peterz@infradead.org, 
	juri.lelli@redhat.com, catalin.marinas@arm.com, will@kernel.org, arnd@arndb.de, 
	tglx@linutronix.de, mingo@redhat.com, dave.hansen@linux.intel.com, x86@kernel.org, 
	peterx@redhat.com, david@redhat.com, axboe@kernel.dk, mcgrof@kernel.org, 
	masahiroy@kernel.org, nathan@kernel.org, dennis@kernel.org, jhubbard@nvidia.com, 
	tj@kernel.org, muchun.song@linux.dev, rppt@kernel.org, paulmck@kernel.org, 
	pasha.tatashin@soleen.com, yosryahmed@google.com, yuzhao@google.com, dhowells@redhat.com, 
	hughd@google.com, andreyknvl@gmail.com, keescook@chromium.org, 
	ndesaulniers@google.com, vvvvvv@google.com, gregkh@linuxfoundation.org, 
	ebiggers@google.com, ytcoode@gmail.com, vincent.guittot@linaro.org, 
	dietmar.eggemann@arm.com, rostedt@goodmis.org, bsegall@google.com, bristot@redhat.com, 
	vschneid@redhat.com, cl@linux.com, penberg@kernel.org, iamjoonsoo.kim@lge.com, 
	42.hyeyoo@gmail.com, glider@google.com, elver@google.com, dvyukov@google.com, 
	songmuchun@bytedance.com, jbaron@akamai.com, aliceryhl@google.com, rientjes@google.com, 
	minchan@google.com, kaleshsingh@google.com, kernel-team@android.com, 
	linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org, iommu@lists.linux.dev, 
	linux-arch@vger.kernel.org, linux-fsdevel@vger.kernel.org, linux-mm@kvack.org, 
	linux-modules@vger.kernel.org, kasan-dev@googlegroups.com, cgroups@vger.kernel.org, 
	Alexander Viro <viro@zeniv.linux.org.uk>
Subject: Re: [PATCH v6 05/37] fs: Convert alloc_inode_sb() to a macro
Message-ID: <gnqztvimdnvz2hcepdh3o3dpg4cmvlkug4sl7ns5vd4lm7hmao@dpstjnacdubq>
References: <20240321163705.3067592-1-surenb@google.com>
 <20240321163705.3067592-6-surenb@google.com>
 <20240321133147.6d05af5744f9d4da88234fb4@linux-foundation.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20240321133147.6d05af5744f9d4da88234fb4@linux-foundation.org>
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: kent.overstreet@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=eH8oK6O3;       spf=pass
 (google.com: domain of kent.overstreet@linux.dev designates 91.218.175.181 as
 permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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

On Thu, Mar 21, 2024 at 01:31:47PM -0700, Andrew Morton wrote:
> On Thu, 21 Mar 2024 09:36:27 -0700 Suren Baghdasaryan <surenb@google.com> wrote:
> 
> > From: Kent Overstreet <kent.overstreet@linux.dev>
> > 
> > We're introducing alloc tagging, which tracks memory allocations by
> > callsite. Converting alloc_inode_sb() to a macro means allocations will
> > be tracked by its caller, which is a bit more useful.
> 
> I'd have thought that there would be many similar
> inlines-which-allocate-memory.  Such as, I dunno, jbd2_alloc_inode(). 
> Do we have to go converting things to macros as people report
> misleading or less useful results, or is there some more general
> solution to this?

No, this is just what we have to do.

But a fair number of these helpers shouldn't exist - jbd2_alloc_inode()
is one of those, it looks like it predates kmalloc() being able to use
the page allocator for large allocations.

> 
> > --- a/include/linux/fs.h
> > +++ b/include/linux/fs.h
> > @@ -3083,11 +3083,7 @@ int setattr_should_drop_sgid(struct mnt_idmap *idmap,
> >   * This must be used for allocating filesystems specific inodes to set
> >   * up the inode reclaim context correctly.
> >   */
> > -static inline void *
> > -alloc_inode_sb(struct super_block *sb, struct kmem_cache *cache, gfp_t gfp)
> > -{
> > -	return kmem_cache_alloc_lru(cache, &sb->s_inode_lru, gfp);
> > -}
> > +#define alloc_inode_sb(_sb, _cache, _gfp) kmem_cache_alloc_lru(_cache, &_sb->s_inode_lru, _gfp)
> 
> Parenthesizing __sb seems sensible here?  

yeah, we can do that

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/gnqztvimdnvz2hcepdh3o3dpg4cmvlkug4sl7ns5vd4lm7hmao%40dpstjnacdubq.
