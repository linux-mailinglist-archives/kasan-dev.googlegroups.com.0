Return-Path: <kasan-dev+bncBAABBMH2UW2QMGQE4RCP6II@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83b.google.com (mail-qt1-x83b.google.com [IPv6:2607:f8b0:4864:20::83b])
	by mail.lfdr.de (Postfix) with ESMTPS id 51738942398
	for <lists+kasan-dev@lfdr.de>; Wed, 31 Jul 2024 01:54:26 +0200 (CEST)
Received: by mail-qt1-x83b.google.com with SMTP id d75a77b69052e-44d5d16dd68sf229221cf.0
        for <lists+kasan-dev@lfdr.de>; Tue, 30 Jul 2024 16:54:26 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1722383665; cv=pass;
        d=google.com; s=arc-20160816;
        b=vGCJXpReRDqS3lnYKIPr+hwvTmMpasPTpJwT/NU0NazynXKGR4wwsisYygCmxafPnr
         jY56bhJjs24eTagrlf4htDfkWV9NDbOSY/4guUwyGRrAXgqGc45QcS8hFvwdJt9WkmFY
         U/2H0yGbZBCqSda63Nhs2UeuDuVVtMdo3ZrJEsUeJX1t20rVcYJjo8Yg9W+ARrFOUt7h
         8QMHreNPIPrT8XlKevFDsoelJ8EIRRPn3GVZxtGQ3ZBSIKSfZEfL6DLbv+HwDme8P8V9
         WZI7/MVhZs70V+4tPf+0kJYFnXlAuGPq7O3/xict2suFkyse7aEK4N6wQbAvlAoS1o6o
         ZiAw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=JrZiWYsfUZIjjqKGQ/V7u2kJn4Nvl73hULkEM+8iOy8=;
        fh=5gZ2WIXWTIsPyLGSN1IgehMDLOzUrZ0Q8waMSVanfxw=;
        b=ymd85kfjSgd5Ztg4pHTAg4Q8g6NTcLwUwVPq11cAaElhGAGK6bEv/yrFjZoy8eUytt
         V3PCdMPnKpHdfih8WOojvprmzG4trZxnI6ma+I1lGrEGmdm6JHx4uTDF1VZhEXOx3b2/
         Pek9tv3SZP+XgKICDJ/5uHE2Jbib0x5xwCWSrXvcd/n2B+qYI01zbkQESS+TpSd0WXOd
         Gu1rz/4ywO6Gi34RTHn34mLcPBaCbUzGVcHuHjkX+SlKdvg00pD92WIh31JOqnjCNT74
         atrDgWhnyoXbpHlihP746WL/bqpSZIkHSIi+PKAJNqTF+/f25wOWCw/hCguJCCdRMjCp
         TgBQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=eEIOlIPc;
       spf=pass (google.com: domain of dakr@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=dakr@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1722383665; x=1722988465; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=JrZiWYsfUZIjjqKGQ/V7u2kJn4Nvl73hULkEM+8iOy8=;
        b=toOeOkbmClJjk53Kh2VdulkL/hvr6MFIExlwdL/50TK750XoT0gnUYoOwWZFtH5DH5
         DoBlEnLqKOxVreycooZD4/XiPv6B5ZRlLGfOqWuaPTl22uso9Aeeu/fa9ZHJNSqoG0PG
         NxOFMx+e/3MY0ejzNAP4mCTqz1fE9KQhRf9Nvmm3T2/DjtTHPDDu9FHiebBxMiQqrILw
         69caxSVZoWLEsSVRaJUTuw4YY1Jeg692XFnbiwx/ySlYKmctOK/mynV19133SHM/VhOY
         pxp+1Ai3rOMOS7YKpoJQzgWJ66AtRXmi74A9RAw+mRLwLjCrr5Zsuiol+mITVyFV5ERs
         fniw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1722383665; x=1722988465;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=JrZiWYsfUZIjjqKGQ/V7u2kJn4Nvl73hULkEM+8iOy8=;
        b=FQ2axhfNd2YXqp3VYeeUt23Xx3FPcp++ktdARTKlEcjH5nnMl1bl5x1wggYnTab+1C
         nxEMXZ56EQjBicHdPh5vNqODxTv3Oo4Fh0xObymHzvTPelTpC3hIJx42PIx1zl9Mza21
         uF2Ay2Y27ouc0snq78jjyEWElelPnfCFNGNlslm6PoBgEiOaNzrMh+KWjwY1gKMlcoxV
         8oC54G+JlYJjtM88G35VXRQixmbtSIxbfV/XIcEiJhNHzkn/+qoi7VQSkVG4bi19FobE
         qudyH2+mTCPfOattvAJnaSbYzbqbP1LWW1qIOgPwfD6Rb0XGHx7vM6+jMn4/vWmEYGLb
         FTmQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWeEscepYSFbisfIMj/LJ8uCop5O2Ug9+HtpkGYcqU7NrmdVm0X34MTJxXFli9CPwEQI6cN0H7j+JyDkCSY2pDjY1J4VRg7tA==
X-Gm-Message-State: AOJu0YxUWcVTGNu6Q8TJTHfOIAalyKg1Mgtz/yqJDe5LEGNJOf3vG/f7
	EJKsHzL8MjkLeKO+NQMO7gI7H/oXoiMsF0NjuoFgXarBRpyKg+Og
X-Google-Smtp-Source: AGHT+IFtOZ0emqCUCea+COQackUHr0A9QIEpeqjGo8ISXB+1n2bfjQ9+PQv9RZeRstPbHXgu8U1v3Q==
X-Received: by 2002:a05:622a:138c:b0:44f:9e0f:bc41 with SMTP id d75a77b69052e-45043177cc0mr735831cf.27.1722383664809;
        Tue, 30 Jul 2024 16:54:24 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:5a52:0:b0:447:e787:1d5b with SMTP id d75a77b69052e-44fe2ecba3dls98334241cf.0.-pod-prod-03-us;
 Tue, 30 Jul 2024 16:54:24 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCW5EOUxjKSD3ttEPZSX8GXyHotC9BrIEwFdlSAzhJcap944QMn4YFOzhPiL+XvlJlsQsmYiSBS0RFW/BHNZ884oyxFU2yJKQQ7D4g==
X-Received: by 2002:a05:620a:458d:b0:79f:11d7:8175 with SMTP id af79cd13be357-7a1e525e636mr1667605085a.32.1722383664163;
        Tue, 30 Jul 2024 16:54:24 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1722383664; cv=none;
        d=google.com; s=arc-20160816;
        b=YCeWnfIAt6clDDcsAIm5Uz35ToJqbx4D9kxkbDKFssSRRkx9qPE/95BorCwYVmrcH1
         e8rZtIaVcqfMKuF2lBnHVsjzk0OYifNoAkWFKO7Z5UX39NdMVnMyYoDcOdtvM8NsH5Lq
         TIV9+oXVF9ILP//24EVG8d76k3UIt8vDuM8FvoBPe3JUjx/5V1ObIHTcqEpROz/HajBL
         yA5QHHkLF9ONsFrGQKo4/7JvlE3+pY0GcU90AUAvvPLfVkmiiWYYmrxjs7JLVAHENHa3
         rhBt+n58FO/SRiZ+B8JaTUkOI6Dh1INfj+Ob/2JTlOm0ogrSQrcQihhi/WbZhiRm5tls
         lxRw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=LuUrlNqGPe38xuuQs2lzgyjqgCy46ibUXC+XOrJyiE4=;
        fh=j3NheWI2oh+ARal7YvlPWD5f/U2hI64lQTAUrF6j8Po=;
        b=n6rDvNLF/cmF2F9lcwQjiu+wKWKZohViNZOgkiJmW9EMa3aNzs5mPdPLpq+oon9my+
         QLUAzlqs8GJrTnUM5kBEBo8RpE74Vzs5CTBxgR1VbBLoZzWM9gfXZQTWPyR30tye1fDN
         DuFS45GBn60T3Q1Vy6ro0kFZoZRmuJLJbKio+kNG5qp631zBsCsoRS2n41aSs0ftrPqK
         ba6pjk+7jMZPJnmsSwF0b3OEQnwQampcs5IeD2FEm9lKTZMzY+l/AKN8aVOpzy0cABUV
         n0B4Tbhxz/6CgP4qG8Hof9ku87wwB43UaEGLyqACoPSKBxz9NvtHZegAZb6tbCMJ0EkX
         UsqA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=eEIOlIPc;
       spf=pass (google.com: domain of dakr@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=dakr@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-7a1d739946csi50590285a.1.2024.07.30.16.54.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 30 Jul 2024 16:54:24 -0700 (PDT)
Received-SPF: pass (google.com: domain of dakr@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id A3F9862072;
	Tue, 30 Jul 2024 23:54:23 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id EBA6BC32782;
	Tue, 30 Jul 2024 23:54:20 +0000 (UTC)
Date: Wed, 31 Jul 2024 01:54:17 +0200
From: Danilo Krummrich <dakr@kernel.org>
To: Vlastimil Babka <vbabka@suse.cz>
Cc: akpm@linux-foundation.org, cl@linux.com, penberg@kernel.org,
	rientjes@google.com, iamjoonsoo.kim@lge.com,
	roman.gushchin@linux.dev, 42.hyeyoo@gmail.com,
	linux-kernel@vger.kernel.org, linux-mm@kvack.org,
	kasan-dev <kasan-dev@googlegroups.com>
Subject: Re: [PATCH 1/2] mm: krealloc: consider spare memory for __GFP_ZERO
Message-ID: <Zql9KXRDBb5Ufpp-@pollux.localdomain>
References: <20240730194214.31483-1-dakr@kernel.org>
 <66836dd6-b0c2-4f77-b2a3-c43296aa6c93@suse.cz>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <66836dd6-b0c2-4f77-b2a3-c43296aa6c93@suse.cz>
X-Original-Sender: dakr@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=eEIOlIPc;       spf=pass
 (google.com: domain of dakr@kernel.org designates 2604:1380:4641:c500::1 as
 permitted sender) smtp.mailfrom=dakr@kernel.org;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=kernel.org
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

On Tue, Jul 30, 2024 at 11:14:16PM +0200, Vlastimil Babka wrote:
> On 7/30/24 9:42 PM, Danilo Krummrich wrote:
> > As long as krealloc() is called with __GFP_ZERO consistently, starting
> > with the initial memory allocation, __GFP_ZERO should be fully honored.
> > 
> > However, if for an existing allocation krealloc() is called with a
> > decreased size, it is not ensured that the spare portion the allocation
> > is zeroed. Thus, if krealloc() is subsequently called with a larger size
> > again, __GFP_ZERO can't be fully honored, since we don't know the
> > previous size, but only the bucket size.
> > 
> > Example:
> > 
> > 	buf = kzalloc(64, GFP_KERNEL);
> > 	memset(buf, 0xff, 64);
> > 
> > 	buf = krealloc(buf, 48, GFP_KERNEL | __GFP_ZERO);
> > 
> > 	/* After this call the last 16 bytes are still 0xff. */
> > 	buf = krealloc(buf, 64, GFP_KERNEL | __GFP_ZERO);
> > 
> > Fix this, by explicitly setting spare memory to zero, when shrinking an
> > allocation with __GFP_ZERO flag set or init_on_alloc enabled.
> > 
> > Signed-off-by: Danilo Krummrich <dakr@kernel.org>
> > ---
> >  mm/slab_common.c | 7 +++++++
> >  1 file changed, 7 insertions(+)
> > 
> > diff --git a/mm/slab_common.c b/mm/slab_common.c
> > index 40b582a014b8..cff602cedf8e 100644
> > --- a/mm/slab_common.c
> > +++ b/mm/slab_common.c
> > @@ -1273,6 +1273,13 @@ __do_krealloc(const void *p, size_t new_size, gfp_t flags)
> >  
> >  	/* If the object still fits, repoison it precisely. */
> >  	if (ks >= new_size) {
> > +		/* Zero out spare memory. */
> > +		if (want_init_on_alloc(flags)) {
> > +			kasan_disable_current();
> > +			memset((void *)p + new_size, 0, ks - new_size);
> > +			kasan_enable_current();
> 
> If we do kasan_krealloc() first, shouldn't the memset then be legal
> afterwards without the disable/enable dance?

No, we always write into the poisoned area. The following tables show what we do
in the particular case:

Shrink
------
          new        old
0         size       size        ks
|----------|----------|----------|
|   keep   |        poison       |  <- poison
|--------------------------------|
|   keep   |         zero        |  <- data


Poison and zero things between old size and ks is not necessary, but we don't
know old size, hence we have do it between new size and ks.

Grow
----
          old        new
0         size       size        ks
|----------|----------|----------|
|       unpoison      |   keep   | <- poison
|--------------------------------|
|         keep        |   zero   | <- data

Zeroing between new_size and ks in not necessary in this case, since it must be
zero already. But without knowing the old size we don't know whether we shrink
and actually need to do something, or if we grow and don't need to do anything.

Analogously, we also unpoison things between 0 and old size for the same reason.

> 
> > +		}
> > +
> >  		p = kasan_krealloc((void *)p, new_size, flags);
> >  		return (void *)p;
> >  	}
> > 
> > base-commit: 7c3dd6d99f2df6a9d7944ee8505b195ba51c9b68
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Zql9KXRDBb5Ufpp-%40pollux.localdomain.
