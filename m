Return-Path: <kasan-dev+bncBAABBAEBWLBQMGQEX2XU6VA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3e.google.com (mail-yb1-xb3e.google.com [IPv6:2607:f8b0:4864:20::b3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 11EC1AFC0C6
	for <lists+kasan-dev@lfdr.de>; Tue,  8 Jul 2025 04:20:50 +0200 (CEST)
Received: by mail-yb1-xb3e.google.com with SMTP id 3f1490d57ef6-e7b4e43d31asf4020201276.1
        for <lists+kasan-dev@lfdr.de>; Mon, 07 Jul 2025 19:20:50 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1751941249; cv=pass;
        d=google.com; s=arc-20240605;
        b=M7awUl9JstGMM/xshF3qFOI5D1IeXqmU6FG5gHhuVGp2oZcCUgy+BCDTlGhGTxEmQk
         wlUpJ+u05JAB8FX4e16SfgZR2ySIxML605g0IG76wewuSoQi2WP6g2hhjshbB1D/wNhp
         EkFYcFgYzLGb5eFeBmIZqnYYzJ7uumgWkliktbzioSFcmbpbbEFHqClXbehMlUsC+gLX
         JunOGuz96MWB/2WxD/2vO1JoTnFRWq6Z6ogYajTQapc5gKyvX2qopeF8IocYipQYJL/6
         f1v4/I7vp2+o2NqipUCOpi3B3JcoR7vpQ3s4QTLGOvP+ErP2yWTvkZSqd5k3Wb1xRgn4
         UFwQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=eg8u2v+/bnM8/blHlI3hSGJiGECbS2yGFdg7XFdgjP8=;
        fh=Zi3c3avtUoQFvJEE0u1zFOqBQ3U+BVb1C8FsXZoqvu4=;
        b=H7qX6YxSpejdeS5ENVRc1lgfyqqvJE9z7SvD89hd3fmHsCikOIUOF76xXXsitHfCTJ
         SRj0ExkWnMRPu/dKe5JDplX8fo3G71EXlVPG/B1RMgKSt8fZ2ZzYGKR0CP9OmZjd2iHn
         fgrDoyW0d0feon63S6Pi0o1x141ullx32HA6pi0rbrfO477oRNTqdLxP+zXSdMmtQ+3i
         WqnQpU1asCVpDaGB1VauaX9LWKCOwVTHIjbE0qqy9pxrcDsdcdIsSvYvnH8vltMTDUq+
         17MU329G3Ak3RctAExdp4fmTodXhW7Nu8rWFe8UEdNrvycJDjBtF4ANDomZl5nvt+kHc
         Xmhw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=SfVuVxjD;
       spf=pass (google.com: domain of alx@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=alx@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1751941248; x=1752546048; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=eg8u2v+/bnM8/blHlI3hSGJiGECbS2yGFdg7XFdgjP8=;
        b=o1HRKTB81EloIDpq18Z/xmaN7STllByAnw27nLC+VT4u6DGgjTHdMnj7jhvziNNcMg
         cRimfiXxe+vfSS/edSm6EbItDCPUeaAEwfEAy4OLq8wl832BEaqgjak/9P9kZGK8yB66
         U1Yv1F+it/n2PdeBMG0CnLHvmLD2d2fCXatL/8n+cjoBAmy/4IDyHqtym6HEAKvOM74I
         ZCX/bKdyNHN5BKzlL1/xg1gHx0wgNlp06xkZGWjiGT2CC6slWZtVoFs/nOjqgd92J1VP
         V44vjdqewUAAHXOmJQTsNMkMK5vtylpXm+s5lSAcEcnZb5C79ERwA4L8jNcJYHTGghv2
         UR4w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1751941248; x=1752546048;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=eg8u2v+/bnM8/blHlI3hSGJiGECbS2yGFdg7XFdgjP8=;
        b=IMSQK5Y7351ksC/S7JVgn5qQTnTUxRnnRfnqwgPdV5a9A87E+XrGxtPOCIGTXWbZZP
         FRetBns83T+5AjPLBDFn2d46Q+OXpuFprre2m9v+xEX9F79zDi1cyO21mnGD613IoP1Z
         i8ufVVxMC00wPtw4UNFGDKpxmGmvRUY/SiRSlEdDPT1XdBIx4kU11qGCgNdMQpaUpk8C
         W4+gKNyAY5NElxdCeoZMWCioLXvtsWJVC2UU2fN3SODRBfIFmHk6WnCG1nnDb2iAx3B5
         TCFaSv439fpTQNm8r7MtSTdbzMVcOkDdRxgrA1JFZS7XhGFdUyA6PZpsQCqEHXyxrpwm
         Mj7g==
X-Forwarded-Encrypted: i=2; AJvYcCW03fSDDj8/kS39pCLzGhPi78BT4gcYLc8LD2XmsyhK3NwXi18qucwChcvpubk0RFtVn7E+yQ==@lfdr.de
X-Gm-Message-State: AOJu0YwxCmMCK42TWwv8dAvVFQLmPlduZZdJ9d0D5yrE6gAcBZjF+xtC
	X4/gcUxRDZPKUcYzh0MAKn42J4HdgBU2Un5KcTfa17in40wsqFPEF8hA
X-Google-Smtp-Source: AGHT+IHzLMoNUFoCC+KWKSn/AV7SkRPt7iT170G26/s8YYMSb8edpabMNjZpoktRYswEYFJg8MpGWw==
X-Received: by 2002:a05:6902:724:b0:e81:57f6:519a with SMTP id 3f1490d57ef6-e8b60a88bbbmr2655021276.0.1751941248617;
        Mon, 07 Jul 2025 19:20:48 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZeivhAKHEiit3GMF38tT8mR04drPJo4ojmMtZCFENQbPA==
Received: by 2002:a25:781:0:b0:e7d:cd62:3589 with SMTP id 3f1490d57ef6-e89a38aee04ls3354021276.2.-pod-prod-04-us;
 Mon, 07 Jul 2025 19:20:47 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWlkDHXz8ouX8Ri6HiPDCS3X/oR/pcNaiG1N4YYfru+kWLdrhurNZ5h0BDvZtCxZMuJCFphYs6gAoE=@googlegroups.com
X-Received: by 2002:a05:690c:9508:b0:70e:1d14:2b76 with SMTP id 00721157ae682-7179e4227a0mr21563357b3.23.1751941247261;
        Mon, 07 Jul 2025 19:20:47 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1751941247; cv=none;
        d=google.com; s=arc-20240605;
        b=FfdpEGiJhzXTiVLxm2/gBwswyuValZzzNKa9DfgzzcrfsHakQ1L+WlidwpaGKZK0Fi
         G+DD3oGZPsRBi9WMGjE9JvZYjYyz977wgD2puUPILophcdBrG2GEtDkVdOVIVYqAu+CF
         8wmnFFfVOlej6axP47ukHdPbRuyd2pEmfaym5b058qmWLuooNipM8WKPdFESonVU46am
         McqfzYoxkx0eU4LuGpdodsPvFNf4AFCzCC7ScnAkZT7pm04jrdInHYGhZkLO3Rq6yM+E
         XQC4lN2PRt1vO/Pt+2Z6a+Ng4U0+8FoLaG7QctjttzLpLxfA++h06oqgdgjFFFYoRCch
         97wg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=s8p/5XWM6vjjEz1QPiqKBJehgSk+4YR1hgsGa0W7OiE=;
        fh=ZEmjEA+beua0ACHfvGG6b46BenHjaWFbMeK4riMguPk=;
        b=Z4FSHuPlqpVnAcyfvPpgMK3Ixlpoqqmm4LzRua/5puqV3qJRo5t4wpd2yY9Vi7rSxj
         V0jGQ1Vu7UysgLCQhr9ZDH2bDKpOK8qhvx/Ey4zmpCq3RGOYu6B7hYf7W0jBNUISABtb
         jDmJ4fMs1hO7fJP29swMNr8YxazGePEmeoyUpayr+rXmFcxgLcbax82rVC6+8rWceTln
         Um7dqKN7eckrBwFaFwZt6YgBugo+IPp8DMrAJ47dz1QEjBoiKyiOf686yKZu4q3+dlRW
         46lY+iO13d1lmDmMnLVTWHAtNG6m6U6LvJnyx1h6IGoTSBGKQI/GWZ++tPmxj70nZcYF
         v65A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=SfVuVxjD;
       spf=pass (google.com: domain of alx@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=alx@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [2600:3c0a:e001:78e:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id 00721157ae682-71665a156b9si5002347b3.4.2025.07.07.19.20.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 07 Jul 2025 19:20:47 -0700 (PDT)
Received-SPF: pass (google.com: domain of alx@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) client-ip=2600:3c0a:e001:78e:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id 4E911437F9;
	Tue,  8 Jul 2025 02:20:46 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id A883DC4CEE3;
	Tue,  8 Jul 2025 02:20:44 +0000 (UTC)
Date: Tue, 8 Jul 2025 04:20:43 +0200
From: "'Alejandro Colomar' via kasan-dev" <kasan-dev@googlegroups.com>
To: Linus Torvalds <torvalds@linux-foundation.org>
Cc: linux-mm@kvack.org, linux-hardening@vger.kernel.org, 
	Kees Cook <kees@kernel.org>, Christopher Bazley <chris.bazley.wg14@gmail.com>, 
	shadow <~hallyn/shadow@lists.sr.ht>, linux-kernel@vger.kernel.org, 
	Andrew Morton <akpm@linux-foundation.org>, kasan-dev@googlegroups.com, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, Christoph Lameter <cl@linux.com>, 
	David Rientjes <rientjes@google.com>, Vlastimil Babka <vbabka@suse.cz>, 
	Roman Gushchin <roman.gushchin@linux.dev>, Harry Yoo <harry.yoo@oracle.com>, 
	Andrew Clayton <andrew@digital-domain.net>, Sven Schnelle <svens@linux.ibm.com>, 
	Heiko Carstens <hca@linux.ibm.com>, Tvrtko Ursulin <tvrtko.ursulin@igalia.com>, 
	"Huang, Ying" <ying.huang@intel.com>, Lee Schermerhorn <lee.schermerhorn@hp.com>, 
	Christophe JAILLET <christophe.jaillet@wanadoo.fr>, Hyeonggon Yoo <42.hyeyoo@gmail.com>, Chao Yu <chao.yu@oppo.com>
Subject: Re: [RFC v3 3/7] mm: Use seprintf() instead of less ergonomic APIs
Message-ID: <gnds5llds2bfqynijuaxafwsbb4ukafxfgggzuvhrqsi2rc6nb@dyf3qgdsmnti>
References: <cover.1751862634.git.alx@kernel.org>
 <033bf00f1fcf808245ae150346019aa7b997ea11.1751862634.git.alx@kernel.org>
 <CAHk-=wh9Pqz07ne9iSt1_v0c14rkOGvF9AbEkaq1KnFhQD1SSA@mail.gmail.com>
 <ugf4pu7qrojegz7arkcpa4cyde6hoyh73h66oc4f6ncc7jg23t@bklkbbotyzvp>
 <CAHk-=whQ_0qFvg3cugt84+iKXi_eebNGY4so+PSnyyVNGVde1A@mail.gmail.com>
 <gjxc2cxjlsnccopdghektco2oulmhyhonigy7lwsaqqcbn62wj@wa3tidbvpyvk>
 <r43lulact3247k23clhbqnp3ms75vykf7yxa526agenq2b4osk@q6qp7hk7efo2>
 <CAHk-=wj6gEmYih1VfYZu9FiYtOJYSFQ0f45CQZtDLrJpzF47Bg@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CAHk-=wj6gEmYih1VfYZu9FiYtOJYSFQ0f45CQZtDLrJpzF47Bg@mail.gmail.com>
X-Original-Sender: alx@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=SfVuVxjD;       spf=pass
 (google.com: domain of alx@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25
 as permitted sender) smtp.mailfrom=alx@kernel.org;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Alejandro Colomar <alx@kernel.org>
Reply-To: Alejandro Colomar <alx@kernel.org>
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

Hi Linus,

On Mon, Jul 07, 2025 at 03:17:50PM -0700, Linus Torvalds wrote:
> On Mon, 7 Jul 2025 at 14:27, Alejandro Colomar <alx@kernel.org> wrote:
> >
> > If the name is your main concern, we can discuss a more explicit name in
> > the kernel.
> 
> So as they say: "There are only two hard problems in computer science:
> cache invalidation, naming and off-by-one errors".

Indeed.  And we have two of these classes here.  :)

> And the *worst* model for naming is the "add random characters" (ok, I
> still remember when people believed the insane "Hungarian Notation"
> BS, *that* particular braindamage seems to thankfully have faded away
> and was probably even worse, because it was both pointless, unreadable
> _and_ caused long identifiers).

To be fair, one letter is enough if you're used to the name.  Everything
of the form s*printf() people know that the differentiating part is that
single letter between 's' and 'p', and a quick look at the function
prototype usually explains the rest.

More than that, and it's unnecessarily noisy to my taste.  But not
everyone does string work all the time, so I get why you'd be less prone
to liking the name.

I won't press for the name.  Unless you say anything, my next revision
of the series will call it sprintf_end().

> Now, we obviously tend to have the usual bike-shedding discussions
> that come from naming, but my *personal* preference is to avoid the
> myriad of random "does almost the same thing with different
> parameters" by using generics.
> 
> This is actually something that the kernel has done for decades, with
> various odd macro games - things like "get_user()" just automatically
> doing the RightThing(tm) based on the size of the argument, rather
> than having N different versions for different types.

In this case, I wouldn't want to go that way and reuse the name
snprintf(3), because the kernel implementation of snprintf(3) is
non-conforming, and both the standard and the kernel snprintf() have
semantics that are importantly different than this API in terms of
handling errors.

I think reusing the name with slightly different semantics would be
prone to bugs.

Anyway, sprintf_end() should be clear enough that I don't expect much
bikeshedding for the name.  Feel free to revisit this in the future and
merge names if you don't like it; I won't complain.  :)


Have a lovely night!
Alex

P.S.:  I'm not able to sign this email.

> So we actually have a fair number of "generics" in the kernel, and
> while admittedly the header file contortions to implement them can
> often be horrendous - the *use* cases tend to be fairly readable.
> 
> It's not just get_user() and friends, it's things like our
> type-checking min/max macros etc. Lots of small helpers that
> 
> And while the traditional C model for this is indeed macro games with
> sizeof() and other oddities, these days at least we have _Generic() to
> help.
> 
> So my personal preference would actually be to not make up new names
> at all, but just have the normal names DoTheRightThing(tm)
> automatically.
> 
> But honestly, that works best when you have good data structure
> abstraction - *not* when you pass just random "char *" pointers
> around.  It tends to help those kinds of _Generic() users, but even
> without the use of _Generic() and friends, it helps static type
> checking and makes things much less ambiguous even in general.
> 
> IOW, there's never any question about "is this string the source or
> the destination?" or "is this the start or the end of the buffer", if
> you just have a struct with clear naming that contains the arguments.
> 
> And while C doesn't have named arguments, it *does* have named
> structure initializers, and we use them pretty religiously in the
> kernel. Exactly because it helps so much both for readability and for
> stability (ie it catches things when you intentionally rename members
> because the semantics changed).
> 
>                 Linus

-- 
<https://www.alejandro-colomar.es/>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/gnds5llds2bfqynijuaxafwsbb4ukafxfgggzuvhrqsi2rc6nb%40dyf3qgdsmnti.
