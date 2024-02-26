Return-Path: <kasan-dev+bncBCS2NBWRUIFBBHXT6OXAMGQE7D4ISDY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x239.google.com (mail-lj1-x239.google.com [IPv6:2a00:1450:4864:20::239])
	by mail.lfdr.de (Postfix) with ESMTPS id 3BB0E86820F
	for <lists+kasan-dev@lfdr.de>; Mon, 26 Feb 2024 21:50:40 +0100 (CET)
Received: by mail-lj1-x239.google.com with SMTP id 38308e7fff4ca-2d2617b1214sf29391831fa.1
        for <lists+kasan-dev@lfdr.de>; Mon, 26 Feb 2024 12:50:40 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708980639; cv=pass;
        d=google.com; s=arc-20160816;
        b=tesJVwNR0igJP7l5UuUSoyDRVgRm60MpXxMLLrqXCN/VkfAtlAANrc2urt7y+jlA8l
         gDaIwS68NhF8dWEyyRAbkhphSIKxE1gnyLgJnv2euxjBeerB9ZlK1Ml2WmtuV1cQYpd/
         CY/5rvNBVFwIaFrTyY9mKWEqteBm8KYbA18OUL9IzOR+QwBBqE+lXJOUNcFxkJ+64yOS
         SrlnoiL3T8LRSb5/BapKImLmwSfk/b2486j6J46+bF/OpQQeQAzEEIi0vFCJ1+Z+rryj
         4Z6XX65BnL2u1bUpVITRaYdHnow3wqoV4HsfIoZayS6rTI1cUxC2ZUYB/d+82hj11DcG
         CdLQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=b41EB3iu8jp+sKaPqwzurCqasjoHNc05XPQWTb6CUcY=;
        fh=S17kpoy8RVhmVMmmZoxZAwRqKp7WLPHP7lBUB99ULKU=;
        b=P8CZEIHVwnNwnEo+0v2MjCx9+AM7LPslE35vVOG0+9XRxtPtIHF+P9sUpfmHVA2nST
         RcVRgzlevQpGL672B8aWw0MjmUbF/aeKdiDbZ/SVMYVunlFwmKTEJCpYLg9oHyRbuOBM
         A9rYGq0eNDu5E9OD8Nb0rVZgOLL153ypIuZHi1bH2Ggmjr0p9lwqLPEFV4IcqC8ohaI9
         DKupiQBTYCklK0HlbVQqwy5oZsmHn/tvxBh6Enie7fQfELc4kakluz/+9AsbEjWMAzc9
         8eZ/dCLesPdXlO1Y8xzSAIOmJ4f2b1CriH63YlbXXOJbwWsC9EpDBaD+1YwWhMyR0qPf
         nR/Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=HcSqhizu;
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 2001:41d0:203:375::b0 as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708980639; x=1709585439; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=b41EB3iu8jp+sKaPqwzurCqasjoHNc05XPQWTb6CUcY=;
        b=Z9qnQjbWLWB2epNXG5A/Ygjj3VRh6u1vkk6la5u6GVUTNn7YA3kSE9VzRgR39q1aI/
         cHnplfxPeyAYgW1W4FMfGUqbvMggPwqWccjfXbijYAwee9QBt+9xMNLI1MBYl0yWTNj3
         A3AI8k0K/w6VCzuaaoXEShdIO7UMobtgajaeft1Iy+NHaGZ1gYdAluBjyb7oGCPFPraH
         luaXOV5NFXkxNwSYOgN1AUWChw+Axscrs7UKfxPijjLeqysVkYeiNMg9TzDul/sVa82C
         WU72AZqYCE0QfV9mzkrqR56Y6WBcZz3zUsMoZBkxMRR7XLdW0fgYxiksgfd9/5ybcOEF
         vctQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708980639; x=1709585439;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=b41EB3iu8jp+sKaPqwzurCqasjoHNc05XPQWTb6CUcY=;
        b=dXFNi2MTMkrcj8l94vDcIr8VK1vc0S39XxdUnH+OYS46PZyOoQSuLB+3oxgTBzhUZT
         Qc4bbfvuAgzY1Au5Jf5+ORtmnm1RqtfWK4XCfxpx2StDUdvLi6xsWmHn38AymzTqtKIM
         faj9rnpxijGxJtKJotBnAk0PnzhtYE9K75X3kmhOFKzHvGlD9E563uUV2W0StlSons+G
         ARHKvCAvdLDYEgp+sXLIs1RVy82LmC2em11ZCajwcRPOEa9jVQQsVd3e5gDOo/U9bx+N
         dfweIL9sWpkD/ZpjjJ7NBl6KlhJa0F8yiMMN4/xd5l0b8XX65fbtGVusdUq4xmMwgRPH
         n6Yw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUCOIRuYUTFqOZBSrJTDJJlPOyBMpcqb0msRQNlsqfSXWu8jzoM/3eatG1NTkq/wD1F+uiMuNenEPOrX1TF0M1ncPvrfZD/EA==
X-Gm-Message-State: AOJu0YxFuDLXn/1PS/bNfISTSsnCkVb32kRPUYSc7c8jZ+GS8mGcANs8
	7xgahPIINVe8kNj5aY3ujC0PTDkSkMo194Okdpi/O+P1Z1qkFpA7
X-Google-Smtp-Source: AGHT+IFXmN51aTJGkhd/AFvFJqwmunS0t4SODKhxUWvnhu77zPwu1g0MyTd0zj4bk8l5YSww8r+A4A==
X-Received: by 2002:a19:e054:0:b0:512:f302:2262 with SMTP id g20-20020a19e054000000b00512f3022262mr4302636lfj.62.1708980638680;
        Mon, 26 Feb 2024 12:50:38 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3f04:b0:511:4a70:6ac4 with SMTP id
 y4-20020a0565123f0400b005114a706ac4ls579479lfa.0.-pod-prod-05-eu; Mon, 26 Feb
 2024 12:50:37 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXcqlssAzz051VlIduDE/zLk8oar7zjmkDgcCzSjfwKu6ZCtHdygSh0S1nXUmWDweVMe8lKxQqJ3pdQUU/wOExJe1F53i++BAZJ6Q==
X-Received: by 2002:a05:6512:3e24:b0:512:fce4:327b with SMTP id i36-20020a0565123e2400b00512fce4327bmr3664492lfv.39.1708980636813;
        Mon, 26 Feb 2024 12:50:36 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1708980636; cv=none;
        d=google.com; s=arc-20160816;
        b=utlf38PWvDphRJ84GSlciYiKO/r1Jfj88uC3nFevPeDX2hK9wKfsFkJALp33EPYo3S
         ivfCoikFg++Z0O8ARrvJaNfuLhMRkhZQH+ZnmqSZQxgyI3qeJwnIjk1BSW2OXILleds4
         oj8LPQRfuxjRk4w+UHZj71yXMi3wC4GSD3vVt0cup9JP9A47hun7Y4iCf/WklP/nawEC
         MaEkeEpKsf/td3jcwj3nSrCzGJ1S4BbkPkqioHeLCPf7N8FwLJrsge3uceZAzZ+PJN77
         3TSoZDSt3ol1k4drAHp7GKj9ZJKh4T+dednOPhLsvawPm58gYijPzEDmdIriHwoRNcFs
         O0hA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:dkim-signature:date;
        bh=mIdkIRtnrOSnd32neZalGi5cjdozYTT6FIEdWcWsU6U=;
        fh=nwsjY1ZwiHU5WZagqiKdnucPJisv/rfexZ35a7jdLa8=;
        b=S1XAsrsZPwF42XFY0IsFXf+9oCz28zWY6YT/dd5sHUSYvIAHugobqW7UjB9D/ilmNV
         Q8JYpXlN7uGTgwovidrAstmcAUDsCT5vo7H/FqsU3s2QiJMWuKqtTBPsRVb+wQ32YvB4
         amqa/0zRN04KQOpbGmV4//dSEmzKkWfenzb3mN0ov7hZhB1ESlZiCvAmgaHpuc5AiFXU
         AFM5m8Kzd8E83jaxUIQ9DddSNdWx0IECYGycaA2dmPXjr+PF+O2d7PNl5rIWJhLC+8KY
         soKATExHKaQy5KTLUbly/DHg7yHELlFLsQ/UkseP9o6L4SHmmOII792yZCz0Kk9kCOFp
         /2jg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=HcSqhizu;
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 2001:41d0:203:375::b0 as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-176.mta1.migadu.com (out-176.mta1.migadu.com. [2001:41d0:203:375::b0])
        by gmr-mx.google.com with ESMTPS id d17-20020a0565123d1100b00512f7e7717esi275251lfv.2.2024.02.26.12.50.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 26 Feb 2024 12:50:36 -0800 (PST)
Received-SPF: pass (google.com: domain of kent.overstreet@linux.dev designates 2001:41d0:203:375::b0 as permitted sender) client-ip=2001:41d0:203:375::b0;
Date: Mon, 26 Feb 2024 15:50:23 -0500
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: Kent Overstreet <kent.overstreet@linux.dev>
To: Vlastimil Babka <vbabka@suse.cz>
Cc: Suren Baghdasaryan <surenb@google.com>, akpm@linux-foundation.org, 
	mhocko@suse.com, hannes@cmpxchg.org, roman.gushchin@linux.dev, mgorman@suse.de, 
	dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com, 
	penguin-kernel@i-love.sakura.ne.jp, corbet@lwn.net, void@manifault.com, peterz@infradead.org, 
	juri.lelli@redhat.com, catalin.marinas@arm.com, will@kernel.org, arnd@arndb.de, 
	tglx@linutronix.de, mingo@redhat.com, dave.hansen@linux.intel.com, x86@kernel.org, 
	peterx@redhat.com, david@redhat.com, axboe@kernel.dk, mcgrof@kernel.org, 
	masahiroy@kernel.org, nathan@kernel.org, dennis@kernel.org, tj@kernel.org, 
	muchun.song@linux.dev, rppt@kernel.org, paulmck@kernel.org, pasha.tatashin@soleen.com, 
	yosryahmed@google.com, yuzhao@google.com, dhowells@redhat.com, hughd@google.com, 
	andreyknvl@gmail.com, keescook@chromium.org, ndesaulniers@google.com, 
	vvvvvv@google.com, gregkh@linuxfoundation.org, ebiggers@google.com, 
	ytcoode@gmail.com, vincent.guittot@linaro.org, dietmar.eggemann@arm.com, 
	rostedt@goodmis.org, bsegall@google.com, bristot@redhat.com, vschneid@redhat.com, 
	cl@linux.com, penberg@kernel.org, iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com, 
	glider@google.com, elver@google.com, dvyukov@google.com, shakeelb@google.com, 
	songmuchun@bytedance.com, jbaron@akamai.com, rientjes@google.com, minchan@google.com, 
	kaleshsingh@google.com, kernel-team@android.com, linux-doc@vger.kernel.org, 
	linux-kernel@vger.kernel.org, iommu@lists.linux.dev, linux-arch@vger.kernel.org, 
	linux-fsdevel@vger.kernel.org, linux-mm@kvack.org, linux-modules@vger.kernel.org, 
	kasan-dev@googlegroups.com, cgroups@vger.kernel.org, 
	Alexander Viro <viro@zeniv.linux.org.uk>
Subject: Re: [PATCH v4 05/36] fs: Convert alloc_inode_sb() to a macro
Message-ID: <4uhmoltnaywbhhecnj53g5a6ye3x5acf4upbutgraxn2eg2pe2@6ab667edrl2z>
References: <20240221194052.927623-1-surenb@google.com>
 <20240221194052.927623-6-surenb@google.com>
 <f68e7f17-c288-4dc9-9ae9-78015983f99c@suse.cz>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <f68e7f17-c288-4dc9-9ae9-78015983f99c@suse.cz>
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: kent.overstreet@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=HcSqhizu;       spf=pass
 (google.com: domain of kent.overstreet@linux.dev designates
 2001:41d0:203:375::b0 as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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

On Mon, Feb 26, 2024 at 04:44:51PM +0100, Vlastimil Babka wrote:
> On 2/21/24 20:40, Suren Baghdasaryan wrote:
> > From: Kent Overstreet <kent.overstreet@linux.dev>
> > 
> > We're introducing alloc tagging, which tracks memory allocations by
> > callsite. Converting alloc_inode_sb() to a macro means allocations will
> > be tracked by its caller, which is a bit more useful.
> > 
> > Signed-off-by: Kent Overstreet <kent.overstreet@linux.dev>
> > Signed-off-by: Suren Baghdasaryan <surenb@google.com>
> > Cc: Alexander Viro <viro@zeniv.linux.org.uk>
> > Reviewed-by: Kees Cook <keescook@chromium.org>
> > ---
> >  include/linux/fs.h | 6 +-----
> >  1 file changed, 1 insertion(+), 5 deletions(-)
> > 
> > diff --git a/include/linux/fs.h b/include/linux/fs.h
> > index 023f37c60709..08d8246399c3 100644
> > --- a/include/linux/fs.h
> > +++ b/include/linux/fs.h
> > @@ -3010,11 +3010,7 @@ int setattr_should_drop_sgid(struct mnt_idmap *idmap,
> >   * This must be used for allocating filesystems specific inodes to set
> >   * up the inode reclaim context correctly.
> >   */
> > -static inline void *
> > -alloc_inode_sb(struct super_block *sb, struct kmem_cache *cache, gfp_t gfp)
> 
> A __always_inline wouldn't have the same effect? Just wondering.

nope, macro expansion within an inline happens once, and will show
__func__ and __line__ of the helper, we want it expanded in the caller

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/4uhmoltnaywbhhecnj53g5a6ye3x5acf4upbutgraxn2eg2pe2%406ab667edrl2z.
