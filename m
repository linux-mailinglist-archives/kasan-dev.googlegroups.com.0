Return-Path: <kasan-dev+bncBCS2NBWRUIFBBLHMYKXQMGQEJUJTXQA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33f.google.com (mail-wm1-x33f.google.com [IPv6:2a00:1450:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id DB2B8879C9A
	for <lists+kasan-dev@lfdr.de>; Tue, 12 Mar 2024 21:08:13 +0100 (CET)
Received: by mail-wm1-x33f.google.com with SMTP id 5b1f17b1804b1-412e51c20fdsf34623335e9.2
        for <lists+kasan-dev@lfdr.de>; Tue, 12 Mar 2024 13:08:13 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1710274093; cv=pass;
        d=google.com; s=arc-20160816;
        b=u4SNmnm7BxklUzoxKAaub1kBjFSACkENjCLWko6LK3kY5qsyvKnbwo9Q+N5oF3dXZ7
         AhmBxPe3aW4Xw6OmspBaDqXZ0QnaJpEfFDIEZ6fy2cPYQhAN8onUDpcDw67ZdSifdqhx
         VNi1K0bw6sR68GKi3hDN8an928XWS77Qmu9580IG7Aj1kqJw9jXrwsci/CaMgdSLemFQ
         Kn4pes2KBDGrr5SD3dklZ3n69es6Nd2cnDCqsCDxiimzd2eXKUW6LJISUP5cqoSYc4TK
         oDN4Bm8RRz/W1CZsUwAuf6cIpWqWuXUqX6Yk41DV2PpdYoaWYRCZeZB+SQqMrpTI+qn1
         ArBw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=ncBPG41gSWjfhKTzk2Uo5E06dSUEXvSbhQm05fbdHKE=;
        fh=G/z87z450hFzq4xfj48B8gc4IW9iPVvdipyMof3Y3F8=;
        b=XKwJSW+LBXx0UTCUAlEeSrglsisGrJDxyhqGp02wMu9C/lSXW97KZ35J8l20kV39fo
         EqomNsYEXFgSg6F1X5+XMqQ+RBKrcM0NfJrZ7PZ+nbPjYF41DxA+JjRcost0KZv/fMtL
         I94GJODux81Tnp0C1R9XYTrulrIiH5eljMqQ/V2N1wiXY86w58KXnUI8dxW0jDV3N3hc
         V3SvJZEs6fJRedsA+BbH9vJi1jMKqYvtDaeMnrEA43oWzLMY7YWaUQGP15axNkv9jwJ+
         wn+O/Du7LBrqXPFGDXx9ufmdj54lFSJBsBrLBSv3yfqqjXS+WxBcXJm2OrQnqU9wZ5dI
         O5Fw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=fGa0rx+R;
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 91.218.175.171 as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1710274093; x=1710878893; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=ncBPG41gSWjfhKTzk2Uo5E06dSUEXvSbhQm05fbdHKE=;
        b=hC8T542mWoYicsqVh9oIs5uE/8Pcg+GaJiazh+P39z+VD5YRE6UyuOL+vyCg9ZYFg9
         Qt+DPkeEkhYy4jqqQvlQLUkhNRIkZA9kjWxukJpv3qzIHOro0E9AeGph63JiPISfC7Ds
         hXyEIw+RuGOuuXndoIIMiv0k5k4gnLduDb/fij8wq5hwlUY1is93k33cg226EmbeM1+d
         SGZKXyo1PMHlCRKqG8DfXVyXp8Ip/awcleVuBtkn4sw+01/d44DloDZHRlKHzZ5kdP1G
         8l76Rz8x1OkZpFTYd0yaxfKkwaK4Cvm8wLEy9IU6+WT+sEtySCpJYBCuQD1vJsRqm6wC
         WIRQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1710274093; x=1710878893;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=ncBPG41gSWjfhKTzk2Uo5E06dSUEXvSbhQm05fbdHKE=;
        b=wj4eDuthorXbsZ8jLAa6cU6EVkNdeb7DZG3GXbiIs4R5jH0nDcdsoLV/b5HAh3bSb1
         U1U19UVSnhik5l3ACByjJ85KH07tpX3KFoW13Nw+kMrt4O1BU2D/KEhR6t3jAtnEFQ9k
         ZFDnt2TSktOvShbdNClgk1svdLsMMnyQnghtl/fPQT9CHunpbmPnFe/Q+xjo21cqwZp7
         JL+qQI/pf4CQH4vbytXT103MPhF0Rha6lyKszGTHZvmBVdFAH3FrAMMlaZsfwQXmV8xd
         F7GKUoD4a+5jpZvZkJyFJ/FF+18koTKTd2ADUDcwHaRcoBlQICH1rE3MEIlIJS3ifYDb
         /nxw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXv/bN1pcONZrT9ynXbL0F0kVl8mCvT8vro3Kzj89vkX21Vcy4sg1Oh4Cz8+TCyrg3fhsKb8nEwYNm2UBfG9RSZvHg+3gmEwg==
X-Gm-Message-State: AOJu0Yw9TfaJttN4L4WPMBGpxlz35WZ0WWeSQXTFhXHjICQg1VxWiJi4
	BD4hFsS73HtI/eXWHXMSkNlyJJEty8zEJZ9JSvM+qIosMSj+3Pyq5lY=
X-Google-Smtp-Source: AGHT+IF1rSNmorNj4COOCD3nT4IpSKTqCOYUNJYK4aTxm72eYxX8PiS5AZPQhWofdTO5dmhx5GsdjA==
X-Received: by 2002:a05:600c:520d:b0:413:e856:daeb with SMTP id fb13-20020a05600c520d00b00413e856daebmr122215wmb.4.1710274092943;
        Tue, 12 Mar 2024 13:08:12 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:35cf:b0:413:27ac:a341 with SMTP id
 r15-20020a05600c35cf00b0041327aca341ls1151287wmq.1.-pod-prod-06-eu; Tue, 12
 Mar 2024 13:08:11 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXJuIqK3sZJAGRUEXy12FKy5XB4PwVOn4RkWTWMj1TZM/xFm/Fh/ffRs2LmFl0XetLJpto1ttRYEyxT2R+8dkrPPFmhxG5MKE6AKg==
X-Received: by 2002:a05:600c:5023:b0:413:3c83:db32 with SMTP id n35-20020a05600c502300b004133c83db32mr1773339wmr.38.1710274091415;
        Tue, 12 Mar 2024 13:08:11 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1710274091; cv=none;
        d=google.com; s=arc-20160816;
        b=kV2NedyR4BG/yvkrEg2ogqE5hBESTOB8YgfDJWq2CfhwilX2bosYnzFs8xqPHQ5EiI
         Q53M9qYnVdE1h3kDu9aaQILYxKDC6q85cKm9PBWl4nV+qdwC9aOHjT2s7Uq9odFpvxn3
         VF6NIJtIm7XV82Gc2AKYO7Z4oDL+7hZA/h9/R7BrS+bTXV0holIvikxa8EnzyRTWQ5Au
         E2CJGxEVLIy3X9Fi2rwudEmuz8hyDjEacEdDUCS0cJZPf+NUx+Ge/SEZnd2nhGsvWKgu
         e62yCeFJa6ZupmTzQ89O7ub7lU/V9KPYlpTft5A00KxvE1McO+cqYiCherahLLzyUIn2
         My9g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:dkim-signature:date;
        bh=yVCYd35eicxoyDwHWZ5Xnl3STwUduIDprFGFDUbtbK8=;
        fh=vlWpBTSR2vxZ1fnEB2bt4fl5hg5SeTvkiFDS2bJYuk8=;
        b=gjhoF21L8H/GAMTRpnxARc9F8luAOsRlagLrUZ9BphsW64nuuHpV9HBVshMgcPrpM2
         hvOjzhjEwj0jdzw+oueGCtciU69EmmFJWv6PHZIqnUUpF15qbKiTwrLwOqSaB6XIRjsX
         8AhFgKsV2h9zFHQU4+YZQcN300lZ6S40/OwS1dnt9coefnRjc42m7hu5gia3DVOUK//e
         znzNmzwXDShInA8n8cFINeb+hOxs4v0rELKXlObkrw6pLN8AJDqqmRlzJ2eudon9VCZz
         Lfhvxnc0n7D9L9jxkbQ3f4usAspDPRo+65gDuhiNsdHPc8aY5k/7OnJfyx9c5a+/diX2
         qp8w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=fGa0rx+R;
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 91.218.175.171 as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-171.mta0.migadu.com (out-171.mta0.migadu.com. [91.218.175.171])
        by gmr-mx.google.com with ESMTPS id l10-20020a05600c1d0a00b004132f97fa43si123085wms.0.2024.03.12.13.08.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 12 Mar 2024 13:08:11 -0700 (PDT)
Received-SPF: pass (google.com: domain of kent.overstreet@linux.dev designates 91.218.175.171 as permitted sender) client-ip=91.218.175.171;
Date: Tue, 12 Mar 2024 16:07:50 -0400
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: Kent Overstreet <kent.overstreet@linux.dev>
To: Luis Chamberlain <mcgrof@kernel.org>
Cc: Vlastimil Babka <vbabka@suse.cz>, 
	Suren Baghdasaryan <surenb@google.com>, akpm@linux-foundation.org, mhocko@suse.com, hannes@cmpxchg.org, 
	roman.gushchin@linux.dev, mgorman@suse.de, dave@stgolabs.net, willy@infradead.org, 
	liam.howlett@oracle.com, penguin-kernel@i-love.sakura.ne.jp, corbet@lwn.net, 
	void@manifault.com, peterz@infradead.org, juri.lelli@redhat.com, 
	catalin.marinas@arm.com, will@kernel.org, arnd@arndb.de, tglx@linutronix.de, 
	mingo@redhat.com, dave.hansen@linux.intel.com, x86@kernel.org, peterx@redhat.com, 
	david@redhat.com, axboe@kernel.dk, masahiroy@kernel.org, nathan@kernel.org, 
	dennis@kernel.org, tj@kernel.org, muchun.song@linux.dev, rppt@kernel.org, 
	paulmck@kernel.org, pasha.tatashin@soleen.com, yosryahmed@google.com, 
	yuzhao@google.com, dhowells@redhat.com, hughd@google.com, andreyknvl@gmail.com, 
	keescook@chromium.org, ndesaulniers@google.com, vvvvvv@google.com, 
	gregkh@linuxfoundation.org, ebiggers@google.com, ytcoode@gmail.com, 
	vincent.guittot@linaro.org, dietmar.eggemann@arm.com, rostedt@goodmis.org, 
	bsegall@google.com, bristot@redhat.com, vschneid@redhat.com, cl@linux.com, 
	penberg@kernel.org, iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com, glider@google.com, 
	elver@google.com, dvyukov@google.com, shakeelb@google.com, 
	songmuchun@bytedance.com, jbaron@akamai.com, rientjes@google.com, minchan@google.com, 
	kaleshsingh@google.com, kernel-team@android.com, linux-doc@vger.kernel.org, 
	linux-kernel@vger.kernel.org, iommu@lists.linux.dev, linux-arch@vger.kernel.org, 
	linux-fsdevel@vger.kernel.org, linux-mm@kvack.org, linux-modules@vger.kernel.org, 
	kasan-dev@googlegroups.com, cgroups@vger.kernel.org
Subject: Re: [PATCH v4 13/36] lib: prevent module unloading if memory is not
 freed
Message-ID: <kjg5lzzgjuls4hmyz3ym3u5ff3pu2ran7e7azabinak6oa6vrh@2vq4e73ftekk>
References: <20240221194052.927623-1-surenb@google.com>
 <20240221194052.927623-14-surenb@google.com>
 <a9ebb623-298d-4acf-bdd5-0025ccb70148@suse.cz>
 <ZfCdsbPgiARPHUkw@bombadil.infradead.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <ZfCdsbPgiARPHUkw@bombadil.infradead.org>
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: kent.overstreet@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=fGa0rx+R;       spf=pass
 (google.com: domain of kent.overstreet@linux.dev designates 91.218.175.171 as
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

On Tue, Mar 12, 2024 at 11:23:45AM -0700, Luis Chamberlain wrote:
> On Mon, Feb 26, 2024 at 05:58:40PM +0100, Vlastimil Babka wrote:
> > On 2/21/24 20:40, Suren Baghdasaryan wrote:
> > > Skip freeing module's data section if there are non-zero allocation tags
> > > because otherwise, once these allocations are freed, the access to their
> > > code tag would cause UAF.
> > > 
> > > Signed-off-by: Suren Baghdasaryan <surenb@google.com>
> > 
> > I know that module unloading was never considered really supported etc.
> 
> If its not supported then we should not have it on modules. Module
> loading and unloading should just work, otherwise then this should not
> work with modules and leave them in a zombie state.

Not have memory allocation profiling on modules?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/kjg5lzzgjuls4hmyz3ym3u5ff3pu2ran7e7azabinak6oa6vrh%402vq4e73ftekk.
