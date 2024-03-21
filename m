Return-Path: <kasan-dev+bncBC7OD3FKWUERB3GF6KXQMGQEDKVE26Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3e.google.com (mail-qv1-xf3e.google.com [IPv6:2607:f8b0:4864:20::f3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 646EE88625A
	for <lists+kasan-dev@lfdr.de>; Thu, 21 Mar 2024 22:13:17 +0100 (CET)
Received: by mail-qv1-xf3e.google.com with SMTP id 6a1803df08f44-69654139bd5sf12653536d6.1
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Mar 2024 14:13:17 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1711055596; cv=pass;
        d=google.com; s=arc-20160816;
        b=CAASSJFEfivNcxpIij504XfTPHnIuVTQg/Ph1vVS3HqZNheo+rrGWfpQsy0TjhfD7x
         JMSuVtt4mO2oPljO1jNvIJuqzJYsvd3zo2IjoOz0T6UPSZxgMQZgRrM7GHYq4QvCSU5F
         Su7TIYHfHx5wuO/V+r8vp4rW7fxyk9PlF/qzQ2FlJcbtVXXplAedknsW3jpPWY4Ik6cU
         Zdf1piw2SJ9kIeQ4m1G/7DkQnbYIGLeNMPE8BT0Njgdkt9KaPpcNbAEb3wo0wKQ8aUqD
         QMKW4xGUDTOq9vlHfjjSPBLDntuLbjhlrPRkLAnu4jGWtZw67qtOHqWvzc/QGdwpVote
         Xtgw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=TMDUhPWPM44R5UVLMcwS5G/8g2t9IAWqlpvUXxLPZ+w=;
        fh=qLR9iMW9ivJ62PQwC5fZi9K3YSxhT225tZatOfXVPEc=;
        b=SxQv/iF2hglxwNubhzvztPtwTX6g284m4zmBB15ZtopcrGP7W/+mmKursOBAG7HxNk
         m1LcRUn+dZM6BTy4r+XBbWYp7HfBNCDHgPjrq78D0t9mDpW0IezE6X5kRyRRDCkXm3A3
         PvAR0Gz8dSn8ogex0V517CdyEVKpjRiVAbTl4TYJGr1Z4Oq1ph9EfgvPIy9JJHrm3NBY
         TWwwC18SwgSTScgovJf7tkBKAd6smBL/VgKONRc/CLoaTxgHxwmmunVxbx/J96hkhAtN
         N6Q0uv44E1J4fmak0RgctAQFIhSl4WV6UIhP30ezAYo22wjQW0ULGVIaahy+mZNlA+Oe
         39YA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=1x2wzAro;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b2f as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1711055596; x=1711660396; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=TMDUhPWPM44R5UVLMcwS5G/8g2t9IAWqlpvUXxLPZ+w=;
        b=PI0qJVIQmEL6nr53fhXHFPn2JdeqMDP0oJuGwTCcv6524CTjUlIJh5XaMoVneIyRD5
         10zW6AOVZ+BrKzrQ2CB3Fe/jeuVY90s7ltfJX0JaPqApo8/58vZv35G7lXf3hKNeCVsB
         rrD4fjO9xNb1wP5MviXv4IUQaH78014ewto8Xg4yHro16BS+eCQqKXKiUB4NN/ncWP83
         JY7Cg48j6mIyBPId9IJ1ajNubYQVonj0HgoyyY3afYDpiLvvm+zCbafRAr91uffKQzqm
         Un1yDgMeA+10EGnJKTHyPgdTgsPDRg5jvKto1rsYWkKgirrEXsd+61Q++VaC1ST2+Dm8
         2p1g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1711055596; x=1711660396;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=TMDUhPWPM44R5UVLMcwS5G/8g2t9IAWqlpvUXxLPZ+w=;
        b=NqTx4AH3e/bBZ1Obu3P4EOTauB8yIw/oHFk7VzllVy0wM6QTFtikznQhPXSm3a7a6X
         eug299N5RxdDqyPufphHfSM5LUbZyTJRk3j5Dg5g2I3XHHb42Q9sc2avNYq5xhiXX0mg
         uCeEeKrAnyiz3ygEojMrV+FTFNCcisRja77wfXxZVOkxo+wC4mwOWnEIrHVUT0McsJeX
         Cf8b7yQWiKiJEqT3hW1nWg3rAuiEwNIbvoJu8Jh9W+ECe6d5udRD5W51Su0+HQNSj0Gl
         fwD3qpD7KlZKM8QanB4M+ibX2KNtsEJr7p1Ctf78rTg5eGcJeA+SXZFpQGUBHOmhUDGe
         Lfbg==
X-Forwarded-Encrypted: i=2; AJvYcCVDByaRm0G5cBqcCVvMRakUbbWyLo3qAgbhpUjCU1ftnD9FynS1gGc3wPFigZl4KA6j/Gv60gY64xYuj9z9qm/dwduTnPXtwA==
X-Gm-Message-State: AOJu0YxdvRqJt9UaLesHaGwjDF0F8ZGVxlzzhvBpGRQw6yyFQjin0H9d
	T53Jqykx6ZeglJM2/YQlW89h4IgZsUBeuA0sn2sbI2toEFmUXnTe
X-Google-Smtp-Source: AGHT+IG7xz2y4B00CO/W95UTRSxfaPpJ8CAi/SPioKUn5RP9xk9+GTwgQKBipivdAOnQTjvz9e7eyg==
X-Received: by 2002:a05:6214:226f:b0:691:42a0:55e1 with SMTP id gs15-20020a056214226f00b0069142a055e1mr342794qvb.39.1711055596166;
        Thu, 21 Mar 2024 14:13:16 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:2406:b0:690:aaf4:3ed with SMTP id
 fv6-20020a056214240600b00690aaf403edls2417046qvb.2.-pod-prod-08-us; Thu, 21
 Mar 2024 14:13:15 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCU5KgIYXG4pknwCzijBaS7Nim4MUOWUZTFLjf/qZk7hr5CuGdz33i7GigpbhO/B+jC0FchH0PhdtodYbRklL9Lc9f0qMvMzTSEE9A==
X-Received: by 2002:ad4:5bec:0:b0:693:c4d5:166 with SMTP id k12-20020ad45bec000000b00693c4d50166mr473711qvc.9.1711055595229;
        Thu, 21 Mar 2024 14:13:15 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1711055595; cv=none;
        d=google.com; s=arc-20160816;
        b=j/ZagRA70i6rs+Tn4lDglZ9x8yVgOO4f3Kww418BGbZLLKyMLF2KSymgNg6ERmlhwa
         +3zRdO0z7R1uqvyvwPSr7iJX6R41O8WgrvcLYLPd9yrDRI1VSELX/sCLN6x2Ubxpsk4c
         71iJ4od9sAy+NxJuLd+xdQzMlNCDVOxtvp2CI76vdiFa8nNc93U4vLplrssXGeiPEXh6
         711Mb1MQBSRuZ1/F0fLsWDu33M0d8VjCRrFtRf4wPTD5m4m6r0Fy7oNnQZ/lD7MLDbwh
         BP2Q+hdYPX4+RGtmqLkEgxpyyzIq4RWY5yypBImkHZNd9MgNihSNtAm94Ap6GT8hUc9U
         rH4w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=ebQxy1c2E58rfYFrtDF0LlwrADqhUaZL+Ah6PQaZrV4=;
        fh=mnOzvJs6v85nKRmF/JDbLEfHzmS4AMD4UvKD6dbrynI=;
        b=COcYPt20hbWKprSUFKAslIUGFN2yEjU5A3LrrwSwWWgNed3ZRHylzwTDP62fiywM+t
         1fGSAxjW4hJ5M5cLuAGjnaSR/z7VUs56fW1nI5e7CRLXkI6CHQr5AXGLNXY+XYq0Jmm2
         Pd3zQv+fU1OpqQvt6WgyQLfucWdgyywmveuvBaqWzHXDYp1F063sR2UJ1qxLULkkoWIM
         A5ZAzf5QuLqKjttGls+o7ECwB3MQBwBu2VDe9Rflci+t8zYaAt6S31YfSNPSKhtRoXOO
         q7zJAncKaKc9LU9ok7rTqW/DhFBFzA+5wlJFTsrkOZnhrJahKrNi5osAHJ3kJC2H6siN
         p9bA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=1x2wzAro;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b2f as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb2f.google.com (mail-yb1-xb2f.google.com. [2607:f8b0:4864:20::b2f])
        by gmr-mx.google.com with ESMTPS id w10-20020a0562140b2a00b00696419ee0desi50865qvj.4.2024.03.21.14.13.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 21 Mar 2024 14:13:15 -0700 (PDT)
Received-SPF: pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b2f as permitted sender) client-ip=2607:f8b0:4864:20::b2f;
Received: by mail-yb1-xb2f.google.com with SMTP id 3f1490d57ef6-dcbef31a9dbso1141631276.1
        for <kasan-dev@googlegroups.com>; Thu, 21 Mar 2024 14:13:15 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXx3szVSTZvt6SYDageVlCqebDs3e9Bn01wTu6tg9SzFCRCxCZwoht6HV9Dy7lXl9cAsiikOrTIYY8YuGuHHxSscuarhfdNolCEhw==
X-Received: by 2002:a25:f40f:0:b0:dc7:4367:2527 with SMTP id
 q15-20020a25f40f000000b00dc743672527mr366083ybd.49.1711055594451; Thu, 21 Mar
 2024 14:13:14 -0700 (PDT)
MIME-Version: 1.0
References: <20240321163705.3067592-1-surenb@google.com> <20240321163705.3067592-6-surenb@google.com>
 <20240321133147.6d05af5744f9d4da88234fb4@linux-foundation.org>
In-Reply-To: <20240321133147.6d05af5744f9d4da88234fb4@linux-foundation.org>
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 21 Mar 2024 14:13:03 -0700
Message-ID: <CAJuCfpFtXx=NH-Zykh+dfO2fAASV8eObLLxC4Fu_Zu2Y=idZuw@mail.gmail.com>
Subject: Re: [PATCH v6 05/37] fs: Convert alloc_inode_sb() to a macro
To: Andrew Morton <akpm@linux-foundation.org>
Cc: kent.overstreet@linux.dev, mhocko@suse.com, vbabka@suse.cz, 
	hannes@cmpxchg.org, roman.gushchin@linux.dev, mgorman@suse.de, 
	dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com, 
	penguin-kernel@i-love.sakura.ne.jp, corbet@lwn.net, void@manifault.com, 
	peterz@infradead.org, juri.lelli@redhat.com, catalin.marinas@arm.com, 
	will@kernel.org, arnd@arndb.de, tglx@linutronix.de, mingo@redhat.com, 
	dave.hansen@linux.intel.com, x86@kernel.org, peterx@redhat.com, 
	david@redhat.com, axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org, 
	nathan@kernel.org, dennis@kernel.org, jhubbard@nvidia.com, tj@kernel.org, 
	muchun.song@linux.dev, rppt@kernel.org, paulmck@kernel.org, 
	pasha.tatashin@soleen.com, yosryahmed@google.com, yuzhao@google.com, 
	dhowells@redhat.com, hughd@google.com, andreyknvl@gmail.com, 
	keescook@chromium.org, ndesaulniers@google.com, vvvvvv@google.com, 
	gregkh@linuxfoundation.org, ebiggers@google.com, ytcoode@gmail.com, 
	vincent.guittot@linaro.org, dietmar.eggemann@arm.com, rostedt@goodmis.org, 
	bsegall@google.com, bristot@redhat.com, vschneid@redhat.com, cl@linux.com, 
	penberg@kernel.org, iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com, 
	glider@google.com, elver@google.com, dvyukov@google.com, 
	songmuchun@bytedance.com, jbaron@akamai.com, aliceryhl@google.com, 
	rientjes@google.com, minchan@google.com, kaleshsingh@google.com, 
	kernel-team@android.com, linux-doc@vger.kernel.org, 
	linux-kernel@vger.kernel.org, iommu@lists.linux.dev, 
	linux-arch@vger.kernel.org, linux-fsdevel@vger.kernel.org, linux-mm@kvack.org, 
	linux-modules@vger.kernel.org, kasan-dev@googlegroups.com, 
	cgroups@vger.kernel.org, Alexander Viro <viro@zeniv.linux.org.uk>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: surenb@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=1x2wzAro;       spf=pass
 (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b2f as
 permitted sender) smtp.mailfrom=surenb@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
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

On Thu, Mar 21, 2024 at 1:31=E2=80=AFPM Andrew Morton <akpm@linux-foundatio=
n.org> wrote:
>
> On Thu, 21 Mar 2024 09:36:27 -0700 Suren Baghdasaryan <surenb@google.com>=
 wrote:
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

Yeah, that's unfortunately inevitable. Even if we had compiler support
we would have to add annotations for such inlined functions.
For the given example of jbd2_alloc_inode() it's not so bad since it's
used only from one location but in general yes, that's something we
will have to improve as we find more such cases.

>
> > --- a/include/linux/fs.h
> > +++ b/include/linux/fs.h
> > @@ -3083,11 +3083,7 @@ int setattr_should_drop_sgid(struct mnt_idmap *i=
dmap,
> >   * This must be used for allocating filesystems specific inodes to set
> >   * up the inode reclaim context correctly.
> >   */
> > -static inline void *
> > -alloc_inode_sb(struct super_block *sb, struct kmem_cache *cache, gfp_t=
 gfp)
> > -{
> > -     return kmem_cache_alloc_lru(cache, &sb->s_inode_lru, gfp);
> > -}
> > +#define alloc_inode_sb(_sb, _cache, _gfp) kmem_cache_alloc_lru(_cache,=
 &_sb->s_inode_lru, _gfp)
>
> Parenthesizing __sb seems sensible here?

Ack.
Let's wait for more comments and then I'll post fixes.
Thanks!

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAJuCfpFtXx%3DNH-Zykh%2BdfO2fAASV8eObLLxC4Fu_Zu2Y%3DidZuw%40mail.=
gmail.com.
