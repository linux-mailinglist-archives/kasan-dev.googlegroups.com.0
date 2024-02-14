Return-Path: <kasan-dev+bncBCS2NBWRUIFBBBGZWOXAMGQEMCIML2A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x240.google.com (mail-lj1-x240.google.com [IPv6:2a00:1450:4864:20::240])
	by mail.lfdr.de (Postfix) with ESMTPS id CF20C854EB1
	for <lists+kasan-dev@lfdr.de>; Wed, 14 Feb 2024 17:38:29 +0100 (CET)
Received: by mail-lj1-x240.google.com with SMTP id 38308e7fff4ca-2d0ffdb5d44sf17267071fa.1
        for <lists+kasan-dev@lfdr.de>; Wed, 14 Feb 2024 08:38:29 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1707928709; cv=pass;
        d=google.com; s=arc-20160816;
        b=ZsIiaiPvVeKOh1hT5ubgOMJkDk9YCW383kelhdW1VzVgT8XF0U5e1hubAsxLYQzvXF
         qj9v04Fa1QMLog62aMiaal+sMz3gjb/Fybbq6a2buO+pQCgw+XrULP35dxECp/VRXQZn
         9DRHUEa9ea9MNF0NQAziEfE2+YQzqK1CUgk/UXLcPIu01+NV3XGspJTVPZ+CRdlCfdzl
         cF1gFUFOjS1hKBgm7F0khPT5AHhO14zuxqW473tGb0FsQysCWMDZTM18XnONg7SjKEt2
         kb/carle8Xkk/k7kUDs0vjJMAeFdkujjfD8DriTc1Zrwu/pcB2/9EpY4NGPYJC5FbzTB
         AsxQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=peBu44HkA+xTVQMsGlavDalu/ampRqs1afoDh+n2HfU=;
        fh=Tv6G2tRv7EdNsIAOTDoWSiOGix5vfL6aTzELJ0ipBaI=;
        b=P4ykv/RyNg1WD8yQSMRd2wlKEeOlkg/iiMymDCxWWai9168JAiIqxWv2SBGNmdwCFT
         zrEiIRKwExh/DSGnJ2z4ZtFoaVh50+M22CJuZBAXq7IsW7UZy1iaEEmmY6yty68l22Gd
         2FcCg5wihwsJ1mvfsQxZ7eOpqKMwjZAdoXRymquclTJ0tONDUXV//AGmzG5U7UqZsRxF
         b1fy/vSv4HbaZj3+T53XKHCWOPG2VCVTE7lRajlXxq6Ar/GtKFyRR1HK31GVbrVhCFpH
         04nQw5DzBG/RpIh9chqOP6i+uAw6BpwVrU30m4astnNhCRMS/dwo7hfpsdFEJyJwUlVM
         kiNg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=Xm+zNKCM;
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 2001:41d0:1004:224b::b0 as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1707928709; x=1708533509; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=peBu44HkA+xTVQMsGlavDalu/ampRqs1afoDh+n2HfU=;
        b=pbJ3DRcNp6tSWZhIrgh3ZR7FVk/JYpPtedmGPOKX0AngZzuH62dnm7bqaE+g74zdNX
         uLoz866T4/fRPF2aub28cwrOP14O+eS7+3qqzsYQOgdj5UHOr207k2hpgYTdxEjDVlja
         28ZoYXuCAdwaS1UiHPvj66v47PfXVKeafAYPSahAC/4Wa0Azms40K4J9Gxd8h+/PGc3H
         bjCmxAssVboE5s4gCRupGHKZsughDmV7n6ocxcUYgoLwRYH+DcdRbKqRBpKueH0yBHzj
         EgodFECYgL9vJYVBvr3XFXAOixQvF1gOKWfTooUN67mlXlSXRcKU7Nl+LYRAhBM/+Q7M
         JsrA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1707928709; x=1708533509;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=peBu44HkA+xTVQMsGlavDalu/ampRqs1afoDh+n2HfU=;
        b=U8Jd30jHyoaX/SJfI9fLffcHsgmnBiiLH0auYAtGNfgl0KTXAnRd30vsfnqmvey7bZ
         ZXvEWJtCljMGAMyNKG+c5lhrRdVEr6H52unWg8BzVvHwu9BpKWPbETlYb2aJ4WNSHc50
         04KGg7uY4F/XVndWEmJfocJXpsijvVlFn5/Y8/EwY1LIKhh8rHKnrosF225Rb6prcQPn
         vmt63crUnSWzONzgsJOQd87x44rSHFbArcuxzUhy7aSRYoEFwv7unNCCG3WF7iEUCOMV
         LfzqMFu57jnz9jSMoqHvx30ukY/6qpGUktQ9+rGl1W4psYZYT90kjEU10hRGTBJXX2eW
         87qA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUPWhlJFuknYkl6z4pU2QpD8rPc+eEtB5nKFzQG0LhuyXvo2LloxlWYANlthyN2dbDaeLPfFza06n5jSGvw/FQhvNkNFvZpCw==
X-Gm-Message-State: AOJu0Yz8FSeRdWntJz3OErN1WpPmybWEYn30FmStTTXdTSe2bALMRhjc
	WHGbE6galgBiLsRV4x+rRwT1hCgLZSh6Dwf6aK1QNkyjC33orvv0
X-Google-Smtp-Source: AGHT+IGwaXXExOwzT+OTQ97Nry6WbyEqZ67IR15Y/9XGxEyISkwdA4sDaAm3AkRXpielqijlncvQMg==
X-Received: by 2002:a2e:804f:0:b0:2d1:1d91:376c with SMTP id p15-20020a2e804f000000b002d11d91376cmr1155203ljg.31.1707928708465;
        Wed, 14 Feb 2024 08:38:28 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:9ad8:0:b0:2d0:e91b:7e98 with SMTP id p24-20020a2e9ad8000000b002d0e91b7e98ls846075ljj.0.-pod-prod-02-eu;
 Wed, 14 Feb 2024 08:38:27 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXCAY9lrHMuRmogsLhMoFnSyEa+o1uyCgKRX9CcVx0ICQbuoKPzpCk09A3zKuuViu3kzwshA2Zfv5pS+N/vFXgyDxu9kXUtw5Sm0w==
X-Received: by 2002:a2e:9917:0:b0:2d1:638:82f6 with SMTP id v23-20020a2e9917000000b002d1063882f6mr2157585lji.43.1707928706600;
        Wed, 14 Feb 2024 08:38:26 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1707928706; cv=none;
        d=google.com; s=arc-20160816;
        b=ncyL6I4FvXUwHj0cgWQVbdQaGNGWNnEGxh81DXnM/HzQLArqvEwo6oQM+ozKXoUQCG
         UOOUfqIpXvnn88gOoajqlXcggMXGy2z1G9NkhbKghE1ua8uX4iONDtIyohjR1VHJyf9I
         ATCgQ4MTifyseECRSjJABtiIwVvoZCnPqHKUnbxxGiVjKvQ3J7Ft+h3SBnXDg7oNnfxv
         XSLJyzPrfhqh3W/81jlR5KhhnJHpJcLDo89INuE0O+kHAZNxP+C9Mtem308eI+bB6s8K
         ovjOXrHhs29yq2POLbPro0yit+GrV7gI5jm6877CeLp6lu+zi6ynqf9/Al3dy/O5KXB1
         zjGw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:dkim-signature:date;
        bh=GhC8U54i48aAhQsKXgUpTdpqc3Q9oBEWvXQFXanbxaU=;
        fh=MkSRbqQAGp2p2/Zgu2Rxu6B7jF1ATnoMx30mYHAaV6Y=;
        b=d6dX/zP+eLSlGRoy8CWqtleNxPy7oxGG9MWCOB617fdwV3YlaUe3zkvZG0S75Q3fRN
         fEetBPEmy/MZ8b+F2orXQKqI+7g6b6d0IHI0n4n1V6NN2b19Rr10vXTHZoj9VW6F9rIT
         jcI/l8kgGGWe9fEf8W57cNXhp8UEQEFP9zwPkbTmrszs+v+MfetIVXoqg5bFIljavYpG
         14m+e4yY3MhruOoOlg1cienY2REU4Pl2Ms4heRtGqNmF4WGpbzL1Pq9qnsphdbpLmjJF
         nIJiC0E2/laUyRWyaCqlrYot5nQ1xLj7YXEE1jvns6SXmcEo8BDD9VLI0Y++r4zNMTmz
         yCcA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=Xm+zNKCM;
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 2001:41d0:1004:224b::b0 as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
X-Forwarded-Encrypted: i=1; AJvYcCXHasY916EdxFZ2PYPU+8mo3yooNwY3taJlNHhuDDpgN1mqBszsQTcSPpaLxSCyhLfph6l2VrZnscFrXgDQ5JM6DXxqAHxmQ3ATPA==
Received: from out-176.mta0.migadu.com (out-176.mta0.migadu.com. [2001:41d0:1004:224b::b0])
        by gmr-mx.google.com with ESMTPS id d22-20020a2e8916000000b002d0ce94fc66si334569lji.2.2024.02.14.08.38.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 14 Feb 2024 08:38:26 -0800 (PST)
Received-SPF: pass (google.com: domain of kent.overstreet@linux.dev designates 2001:41d0:1004:224b::b0 as permitted sender) client-ip=2001:41d0:1004:224b::b0;
Date: Wed, 14 Feb 2024 11:38:14 -0500
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: Kent Overstreet <kent.overstreet@linux.dev>
To: Vlastimil Babka <vbabka@suse.cz>
Cc: Suren Baghdasaryan <surenb@google.com>, 
	David Hildenbrand <david@redhat.com>, Michal Hocko <mhocko@suse.com>, akpm@linux-foundation.org, 
	hannes@cmpxchg.org, roman.gushchin@linux.dev, mgorman@suse.de, dave@stgolabs.net, 
	willy@infradead.org, liam.howlett@oracle.com, corbet@lwn.net, void@manifault.com, 
	peterz@infradead.org, juri.lelli@redhat.com, catalin.marinas@arm.com, will@kernel.org, 
	arnd@arndb.de, tglx@linutronix.de, mingo@redhat.com, 
	dave.hansen@linux.intel.com, x86@kernel.org, peterx@redhat.com, axboe@kernel.dk, 
	mcgrof@kernel.org, masahiroy@kernel.org, nathan@kernel.org, dennis@kernel.org, 
	tj@kernel.org, muchun.song@linux.dev, rppt@kernel.org, paulmck@kernel.org, 
	pasha.tatashin@soleen.com, yosryahmed@google.com, yuzhao@google.com, dhowells@redhat.com, 
	hughd@google.com, andreyknvl@gmail.com, keescook@chromium.org, 
	ndesaulniers@google.com, vvvvvv@google.com, gregkh@linuxfoundation.org, 
	ebiggers@google.com, ytcoode@gmail.com, vincent.guittot@linaro.org, 
	dietmar.eggemann@arm.com, rostedt@goodmis.org, bsegall@google.com, bristot@redhat.com, 
	vschneid@redhat.com, cl@linux.com, penberg@kernel.org, iamjoonsoo.kim@lge.com, 
	42.hyeyoo@gmail.com, glider@google.com, elver@google.com, dvyukov@google.com, 
	shakeelb@google.com, songmuchun@bytedance.com, jbaron@akamai.com, rientjes@google.com, 
	minchan@google.com, kaleshsingh@google.com, kernel-team@android.com, 
	linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org, iommu@lists.linux.dev, 
	linux-arch@vger.kernel.org, linux-fsdevel@vger.kernel.org, linux-mm@kvack.org, 
	linux-modules@vger.kernel.org, kasan-dev@googlegroups.com, cgroups@vger.kernel.org
Subject: Re: [PATCH v3 00/35] Memory allocation profiling
Message-ID: <wbe5dfkrjpspzykhbi4dshhfgc4t3jpyymutogppyyevzxyyra@r32wpro3xrbi>
References: <CAJuCfpEsWfZnpL1vUB2C=cxRi_WxhxyvgGhUg7WdAxLEqy6oSw@mail.gmail.com>
 <9e14adec-2842-458d-8a58-af6a2d18d823@redhat.com>
 <2hphuyx2dnqsj3hnzyifp5yqn2hpgfjuhfu635dzgofr5mst27@4a5dixtcuxyi>
 <6a0f5d8b-9c67-43f6-b25e-2240171265be@redhat.com>
 <CAJuCfpEtOhzL65eMDk2W5SchcquN9hMCcbfD50a-FgtPgxh4Fw@mail.gmail.com>
 <adbb77ee-1662-4d24-bcbf-d74c29bc5083@redhat.com>
 <r6cmbcmalryodbnlkmuj2fjnausbcysmolikjguqvdwkngeztq@45lbvxjavwb3>
 <CAJuCfpF4g1jeEwHVHjQWwi5kqS-3UqjMt7GnG0Kdz5VJGyhK3Q@mail.gmail.com>
 <ea5vqiv5rt5cdbrlrdep5flej2pysqbfvxau4cjjbho64652um@7rz23kesqdup>
 <4bb7b1e4-d107-4708-bb65-ac44d4af9959@suse.cz>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <4bb7b1e4-d107-4708-bb65-ac44d4af9959@suse.cz>
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: kent.overstreet@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=Xm+zNKCM;       spf=pass
 (google.com: domain of kent.overstreet@linux.dev designates
 2001:41d0:1004:224b::b0 as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
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

On Wed, Feb 14, 2024 at 11:20:26AM +0100, Vlastimil Babka wrote:
> On 2/14/24 00:08, Kent Overstreet wrote:
> > And, as I keep saying: that alloc_hooks() macro will also get us _per
> > callsite fault injection points_, and we really need that because - if
> > you guys have been paying attention to other threads - whenever moving
> > more stuff to PF_MEMALLOC_* flags comes up (including adding
> > PF_MEMALLOC_NORECLAIM), the issue of small allocations not failing and
> > not being testable keeps coming up.
> 
> How exactly do you envision the fault injection to help here? The proposals
> are about scoping via a process flag, and the process may then call just
> about anything under that scope. So if our tool is per callsite fault
> injection points, how do we know which callsites to enable to focus the
> fault injection on the particular scope?

So the question with fault injection is - how do we integrate it into
our existing tests?

We need fault injection that we can integrate into our existing tests
because that's the only way to get the code coverage we need - writing
new tests that cover all the error paths isn't going to happen, and
wouldn't work as well anyways.

But the trouble with injecting memory allocation failures is that
they'll result in errors bubbling up to userspace, and in unpredictable
ways.

We _definitely_ cannot enable random memory allocation faults for the
entire kernel at runttme - or rather we _could_, and that would actually
be great to do as a side project; but that's not something we can do in
our existing automated tests because the results will be completely
unpredictable. If we did that the goal would be to just make sure the
kernel doesn't explode - but what we actually want is for our automated
pass/fail tests to still pass; we need to constrain what will fail.

So we need at a minumum to be able to only enable memory allocation
failures for the code we're interested in testing (file/module) -
enabling memory allocation failures in some other random subsystem we're
not developing or looking at isn't what we want.

Beyond that, it's very much subsystem dependent. For bcachefs, my main
strategy has been to flip on random (1%) memory allocation failures
after the filesystem has mounted. During startup, we do a ton of
allocations (I cover those with separate tests), but after startup we
should be able to run normally in the precence of allocation failures
without ever returning an error to userspace - so that's what I'm trying
to test.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/wbe5dfkrjpspzykhbi4dshhfgc4t3jpyymutogppyyevzxyyra%40r32wpro3xrbi.
