Return-Path: <kasan-dev+bncBCS2NBWRUIFBBAPE6KXQMGQEDY2IMOY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33d.google.com (mail-wm1-x33d.google.com [IPv6:2a00:1450:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id B1B71886326
	for <lists+kasan-dev@lfdr.de>; Thu, 21 Mar 2024 23:17:38 +0100 (CET)
Received: by mail-wm1-x33d.google.com with SMTP id 5b1f17b1804b1-41413823c1bsf12094345e9.1
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Mar 2024 15:17:38 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1711059458; cv=pass;
        d=google.com; s=arc-20160816;
        b=D17dBniB/nw5jFBoUC2JCAYmclRlIoOQxtmo/GYCxZVyEhdYZCM4mOSsxNnJc8Q9As
         N3eVyjH3lbMfVVf+0HSNyemtcQZeCLp/LlqtexHQFhOPiHBG2II3nRm6J9tGI1MSR4Ml
         uSSQZpmcbEx0ul+f7EG7Z3KYFg8rxtyMCEYDLZVU84EWuh5hSzY45R5FhJzzuagppThc
         68IMciodSExE4soef1V5AmGIzmm8A4Ec6GvPxizvvZ+YhWbueYiABk3op9v7abyqGB7a
         rM7/hVoqYSn9Qu5YorkmQQ2VzU5rMgn6suCUE/BVxztb9/Fe8tX3lE9NCBMhz87IOVrz
         q9rw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=Rn9KY0+Pc8cP+17EU7Z6uCJAvUV9xM7CsLnePPQCKUw=;
        fh=uuhMMmFSSpj+UZYjp25St48/oCyjTqN2YHAznTGcOoo=;
        b=l9Yuw3zJxXVC+ASxsWCxonmXEViDLP28xlEqumgx0kwPbQ5JJkJs7Ik+slCoz7DEYb
         R1PPnNMzApNVEFu+pv5gmaa1VoDT6V+kdLTU6VJbIsQENzrHmrexq6L7Xx8ZpM3nI5sY
         7XKnLAwTHq3HVkTGc6ZOjnuDc50o4tK5wTmdzrP1f5VmXxa2yoGoVznrOcySiT5bnGP0
         YYumFO1S82c3guj4DXfMRxX4fah3BaGOUAJ9MTWSLRIfkyOOfYTgCNRr9y4iEOPp1X0N
         0qFMBD/na6PGBxoIxq7LDMSgOahZdT4xC24RM27FXioqnAWwQvVL1GWupeq9FRlrHCyi
         2tJg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=FZysDbxQ;
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 2001:41d0:203:375::ac as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1711059458; x=1711664258; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=Rn9KY0+Pc8cP+17EU7Z6uCJAvUV9xM7CsLnePPQCKUw=;
        b=ekJG8SgD8OH618P6GoPuQt7EBexnrjXXmZdGQ6XCgEGbK00PcWpt1Nx6r3bZ6lGIKP
         mKzvxNSRz1pQ9wdoI64p2Dnvd7QWfEnxVBv13pCwksQIvm0gA9B1y3cDJf3v52XDD/Al
         yssuhJC/FjO3yWJuRoO63VHjJsvb+tX1bxe9PJi3O9e1WEP2Xsoazh8LwVAbIYqiFmBI
         PrBMCMXtIOT88EEVJZnE74OcSbYFH1v2ApRJHpU3mheecPPQx1PdCZQZdzqR7EJR6HzJ
         gQSHvr6cvaYj36+L8YbO+RmbfgkxZL5CC5VQD1ZUVpmg+fDTIWDwWbxbl9gpaj06NCFS
         W3xA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1711059458; x=1711664258;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=Rn9KY0+Pc8cP+17EU7Z6uCJAvUV9xM7CsLnePPQCKUw=;
        b=uXvwETpWH3MP/1Cu7XPKWV6/mJGu3zBQmEE3ZYLNGnjoVqJpAOk9znVlY5iCkg66+L
         0oOVLp1Ea1N/y3IeLkTk7S2R6h40NwQqm35jPrhvmG0QkoqfcyQMA5wmIF7OUFx7D7LK
         Dmesvyo3nc51JnM1WeCgHZrbwhu9kWDIx5jj79rflPvF0s/eQ92+4RJYveClUCmHECkJ
         /SxbbaDOrlCeSQhIQ8MGq5vImDvoV0Uw/Gh2n02RecCAfZl8Kg4EwLMZCLXWC3Bf/VtZ
         L1uHGJaO6bOsT+ZtGyC1Q1imeGYvT2aM7VAPx/mTW3OOsbxmp4B2rDFtX+vGsg2O+FWB
         An9g==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVDuU3KJTuWac1eoo1EzvM7wzVIHSop0olLuC3BYyQ1mziItLUV7ubPCDby27I5j+fRAvRDlFaWjOwn0d2wyNlmOhMGBLURog==
X-Gm-Message-State: AOJu0YyrRK4ltKORDwgNXrg3k8Kik2nyADoAzRc4Z2SlT3bKKfOL4mXh
	mUP3MRmocgcHZ6fP/TpP+eZlS0emX1HW9ngyQsWUoWMbq6xJwdP8
X-Google-Smtp-Source: AGHT+IGBhzYCuztRm3gTNz3O+MVUOKPN+GBtVJb+lwcQORV01yEZRROXHmtXGdxtFNqvw1Jjp5GQJg==
X-Received: by 2002:a05:600c:1386:b0:414:43e:4aaf with SMTP id u6-20020a05600c138600b00414043e4aafmr215736wmf.1.1711059458012;
        Thu, 21 Mar 2024 15:17:38 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:4f07:b0:414:7751:d76d with SMTP id
 l7-20020a05600c4f0700b004147751d76dls350485wmq.2.-pod-prod-00-eu; Thu, 21 Mar
 2024 15:17:36 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXYGPk89WAkaN7N9IWQQmWuAc8rPnE1O4tIH9BdGBLeH+KfnNKwCUfIPdBmhHi6rocAD+eZ7XD2BtF6/cM0DXXWxVtLFnvDRcbzZw==
X-Received: by 2002:a05:600c:1391:b0:414:ea1:451 with SMTP id u17-20020a05600c139100b004140ea10451mr243528wmf.2.1711059456247;
        Thu, 21 Mar 2024 15:17:36 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1711059456; cv=none;
        d=google.com; s=arc-20160816;
        b=akH6d2lh4jJplR41hReR9mC/7I6NkBYHXx94k/6HCrxptrDYcDaHhLq5y+4H5KF7qu
         tVapWi6sr4CPSTunRDn1DQhMJyKn56f/lDSDjk/BBIC8rIBXLblKhfCvR7o204NdndOm
         z67vvGlwN8tltF86c4YwcVky0Pf29pBoF7Dj2f1y2PyGkAyYAh2lBxiMmX+HfzsHIp5I
         gwEVGvn7UQ8gWgRoY34vmDbTLbUY5J0IA+FoINkZ/ssd4bXOSuhDKnXsC319N0uqJbJV
         WvjQvgLCk1x7qWTJvbIRv8PRfP2Zv5lNMXoWdL6RLK0YTlKrKdhEgWIV9ErJwUIERl6W
         IxwQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:dkim-signature:date;
        bh=Avwu9Obvo7iLXBxmizf/EO08qQLthSdSW59GBeW8H+I=;
        fh=Q8iXvLX7AMaL15JHtP679LkEjZAcP9VlW5xkTCDgguY=;
        b=m3JUuDR13JRvMfgHy6AGW8t/WB7NUhfatqOyWhJiOJGEIHqCSmayl1DKNLFh5+HWbN
         94unNSYwsXaIHjWEaDo/VHAOfdhsJp4Eyj/FuJd9lBGpbc17Ggf/c/lCl3qY29kQCMdg
         M55tlIkAl99kmaur+JTV3n2VeB7vqEvp3CQWSu42MAnSYnW9Kynlsf6b+Tkd8PMDoMDQ
         aYCffzPsTRqNXsbTGi6XPoWZr9ZHUr2UhFsJ1T98Kz4O42oNEkxFC03dF1QbOGXUaS6N
         EH6e41PYXYTyklPcn4ZLUlLYNS827HWAV7LTxG8Nl4IRr7lM21H3UxO2FJ7JsBfoVmfx
         fpkw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=FZysDbxQ;
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 2001:41d0:203:375::ac as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-172.mta1.migadu.com (out-172.mta1.migadu.com. [2001:41d0:203:375::ac])
        by gmr-mx.google.com with ESMTPS id w17-20020adfee51000000b0033da1913960si18571wro.7.2024.03.21.15.17.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 21 Mar 2024 15:17:36 -0700 (PDT)
Received-SPF: pass (google.com: domain of kent.overstreet@linux.dev designates 2001:41d0:203:375::ac as permitted sender) client-ip=2001:41d0:203:375::ac;
Date: Thu, 21 Mar 2024 18:17:24 -0400
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
Message-ID: <bliyhrwtskv5xhg3rxxszouxntrhnm3nxhcmrmdwwk4iyx5wdo@vodd22dbtn75>
References: <20240321163705.3067592-1-surenb@google.com>
 <20240321163705.3067592-6-surenb@google.com>
 <20240321133147.6d05af5744f9d4da88234fb4@linux-foundation.org>
 <gnqztvimdnvz2hcepdh3o3dpg4cmvlkug4sl7ns5vd4lm7hmao@dpstjnacdubq>
 <20240321150908.48283ba55a6c786dee273ec3@linux-foundation.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20240321150908.48283ba55a6c786dee273ec3@linux-foundation.org>
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: kent.overstreet@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=FZysDbxQ;       spf=pass
 (google.com: domain of kent.overstreet@linux.dev designates
 2001:41d0:203:375::ac as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
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

On Thu, Mar 21, 2024 at 03:09:08PM -0700, Andrew Morton wrote:
> On Thu, 21 Mar 2024 17:15:39 -0400 Kent Overstreet <kent.overstreet@linux.dev> wrote:
> 
> > On Thu, Mar 21, 2024 at 01:31:47PM -0700, Andrew Morton wrote:
> > > On Thu, 21 Mar 2024 09:36:27 -0700 Suren Baghdasaryan <surenb@google.com> wrote:
> > > 
> > > > From: Kent Overstreet <kent.overstreet@linux.dev>
> > > > 
> > > > We're introducing alloc tagging, which tracks memory allocations by
> > > > callsite. Converting alloc_inode_sb() to a macro means allocations will
> > > > be tracked by its caller, which is a bit more useful.
> > > 
> > > I'd have thought that there would be many similar
> > > inlines-which-allocate-memory.  Such as, I dunno, jbd2_alloc_inode(). 
> > > Do we have to go converting things to macros as people report
> > > misleading or less useful results, or is there some more general
> > > solution to this?
> > 
> > No, this is just what we have to do.
> 
> Well, this is something we strike in other contexts - kallsyms gives us
> an inlined function and it's rarely what we wanted.
> 
> I think kallsyms has all the data which is needed to fix this - how
> hard can it be to figure out that a particular function address lies
> within an outer function?  I haven't looked...

This is different, though - even if a function is inlined in multiple
places there's only going to be one instance of a static var defined
within that function.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bliyhrwtskv5xhg3rxxszouxntrhnm3nxhcmrmdwwk4iyx5wdo%40vodd22dbtn75.
