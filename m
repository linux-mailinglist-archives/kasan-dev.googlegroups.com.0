Return-Path: <kasan-dev+bncBDCPL7WX3MKBB6MW43BQMGQE6FQSWNA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3f.google.com (mail-qv1-xf3f.google.com [IPv6:2607:f8b0:4864:20::f3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 22A0FB09893
	for <lists+kasan-dev@lfdr.de>; Fri, 18 Jul 2025 01:47:07 +0200 (CEST)
Received: by mail-qv1-xf3f.google.com with SMTP id 6a1803df08f44-6fad9167e4csf29214646d6.1
        for <lists+kasan-dev@lfdr.de>; Thu, 17 Jul 2025 16:47:07 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1752796026; cv=pass;
        d=google.com; s=arc-20240605;
        b=GULJp7hGsnSVDv5S0j6NTWv39DdsC+Qxw6yDE2T10FJK4Ra+tycoMzTgkwWTBrHiXe
         HXgI247KnMLVG8LcE/FHT1CSAl8TtQgH2WdceU9GQMZhR7Ejlw1hYieSCwQJMnSpIX6B
         t6sebkA20CcK3IZwD5hmENE8wnlQkoLEXNwFgzu977yh9bES+4AJrfzJPTPQP1pE1XW4
         WlbF2377GikVDYKQFyojTHqmSOQ2KMrjro77xjvof9rtRNax1vOvHhDRPl6zt+9SJBnq
         gUWSCtZl1dOIWSXpsEUP98oVGB4RAQQpgQoiw3y/tBihSu3DiBdB7OCC0QCByVIQf9r+
         3ojg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=eTZkZWP23x/jBAn1kI5XQj31yPTskbGNcHbFJrgmNOc=;
        fh=t5s4M2lHKI0GRJZ/P8LR/Lb31YZN0gNFJN6jJmK1LXc=;
        b=NCbvlmzJxYsPXa+L+tkc19EXe3mNeNrPccjPSZHv34dNSwxlBB2hSscip2Z35A8Vbq
         7H6Eh0kSAMLS3j0Hch+eQhClonhv2Zp5Ixn7idY6tcnwwx1vwJFW7YvyRiL41LbeFMRv
         cwwK9MTvMrT4j2J5wLBd+YNMTLaxvl0XKb1nfLtqSMx5b105x5YsCOEeZ9lrYwS9Ljy3
         N9VMg5sA7pV3fpACC+vTt8YRe+Bt/GoBYM5G+6jmOpqNQ1Ogr/FmRFAcpluhPi8Dto8G
         JTFv++ty0k6zyOQzoul2IJXT5pazEKem7o8rszEzedP2khxHUs4uEXINcpazp2EEXiit
         AmXQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=cpLCkMB3;
       spf=pass (google.com: domain of kees@kernel.org designates 147.75.193.91 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1752796026; x=1753400826; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=eTZkZWP23x/jBAn1kI5XQj31yPTskbGNcHbFJrgmNOc=;
        b=fQoXZIyg3rIEQL4AfzZ2dvdXO6iWYxebxLcQo3Cs6g8jNxmh7z6ARW82VGUjAUfvRW
         r/P7bz6pkrY2VmBIzzrFB6pylnIYh9SABQ7Ua+TovcudX3uAQCiumlcaqc7OFDpH33VT
         NQKtPJHyFS9+N6ePLZoji5dHHoMZCb6hw18kiHABbBBSrW8m3DwkyuUIbTMRsN0oBcOY
         8DpAgi5PIwwXyQNGekZiSqLvUkarsfI8OIEiALAoR1NlBhRNX9xpZmZOmK/RAt5w6UUy
         qCOVVVJjKg9+Iu/hfbuLdkpXBrkMQ1dA0f9W7NbCaoFzsIQdV4gcFbTPURsWDUbWqihD
         6ihw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1752796026; x=1753400826;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=eTZkZWP23x/jBAn1kI5XQj31yPTskbGNcHbFJrgmNOc=;
        b=VP6Z+zb5J/SE9Vj6ed/tig3WEAyCwYOg7peIDpfL+3CABfSGGDfD+sEdre8NY51gWx
         l0ZOEpxlAhkf9/GlAPfVR6TwJzu5OLVnind+8UWpsV5knfEIktuflAQWzDzBkg+s6G3z
         +4E1AiNx44+ByDeewPOKK3lLKxBpGNE4oSEngypdBWJj8NCR8/KwQyrl10PL8oQPaDyq
         MkJmNnaMI85f1vvI5Udt91B4L5LrvRZA0CpFKCSz3DmIueOIhHQJB2KNosWJE+CIgQKS
         KhnIGXeV+ErvjwbctjYBMdnpb/adUhYiKbOhhEBa8qsPL6zpPA5c+YprZ5UtSS7thy9f
         DNow==
X-Forwarded-Encrypted: i=2; AJvYcCU66AKBNBaf550Vzi1VFRzF59qZ6CSbm36hxfVpk5c8JU4Gwnm3bjdveILFqIASEmi7LpCT1g==@lfdr.de
X-Gm-Message-State: AOJu0Ywj42sKg2PSYsYMt3fqp3gUKkYTs8ZhIeMrr8SO768kohWhaM5v
	rX7k5BfLa4kM/NK7xyfxsMO+xTh5OlcSg5js4sozG5/TYm36bZI5TMjX
X-Google-Smtp-Source: AGHT+IHBkAgIxV8IjEnCqerqmPwrVxTSyU1QPqKyUBSUN2fgkOfxXMv50VFY9cCQNJWhUYWOaHYEAw==
X-Received: by 2002:a05:6214:3c8c:b0:704:f392:1f11 with SMTP id 6a1803df08f44-704f6b18079mr148244446d6.19.1752796025896;
        Thu, 17 Jul 2025 16:47:05 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdLoZT7BcBmdvZt4GAF6pBB6UKX1qcz/uAFGJ/oI0YZcQ==
Received: by 2002:a05:6214:5098:b0:6fb:4bc7:dc0d with SMTP id
 6a1803df08f44-70504c28582ls24337466d6.1.-pod-prod-06-us; Thu, 17 Jul 2025
 16:47:05 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXFw85GW4Bot+9s/TDbcrKPvbhJUzqDyIXb+uVIxaRiEh5N5u18YDCXL+Ub/AaAP3AIJltp68ULBk4=@googlegroups.com
X-Received: by 2002:a05:6214:8113:b0:704:f7d8:703e with SMTP id 6a1803df08f44-704f7d88982mr85932646d6.50.1752796024974;
        Thu, 17 Jul 2025 16:47:04 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1752796024; cv=none;
        d=google.com; s=arc-20240605;
        b=KhOSUt/2kGO523L+pcxL7ATSZX31jRDB3Zr3wH3+DT6lp4+CvbWPzXnnWFLv+s4tUn
         2VWWQ+7Zvl80p/6TsECeypQ6dANe+MJqGB7KeOODEW/4Nx4XKLwsANLwSzXtufa6GEYB
         Y11ziYFOBLTkUTp3NNXMuQuBIbaM5WjrSEsJ0Te05oLu7IQPxtqNyiF1BI1R66oFyuNP
         73DkJmk0w5C4SJMTRP1O/H0i/wrN0GMnaxujK6XC7dR8Ylvvoi3y7D9cLMJZETBBrdlE
         SyyN6RRowRPnqyUpai/Lx1UsF2Xu6FvvtQhWFMxAVFVMepuQJoXDpkLLwQmZiNfC2DxK
         iaaw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=Rbhgw3Wjy5GIsm1C3qdiYnAmE/jyfTO+0acb0HNz8AY=;
        fh=iMyG71Y+GvFp2T6+JDzFKqbffmil65XCqPPVKCzp/yQ=;
        b=O1SCMslZT6V/0JF3WbJX0xPPl9ogsUACywhtXhDIBB5y4WZr8fI1QxSCwVEGKyIgRW
         YOuDNDQjEytVDM8p0VqWNIgxLtL0GQ/7GI7RBT/4LRwBaBNwRK7r5CsaL50ZbGu8t7+e
         vVEzXSgTOIBhMS9I04TEjcis1ye3NP4O1fLu0k4jcrrv+TGGpRC5qmHZLb0hiCXS6Mm+
         GQWx3+nr26JGuSSXVY/gJSUrQznKVBSmQp3zOiaRM+YU4Ee8Qs8EPrLgxSDQP9KqIp/u
         ysl6gqTl5eY9zcmrezPx2xBYQwsfN/kRUVzv1LTstv5+ur3r7TLQAKnT/Tlt5QEOOahf
         UiaA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=cpLCkMB3;
       spf=pass (google.com: domain of kees@kernel.org designates 147.75.193.91 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from nyc.source.kernel.org (nyc.source.kernel.org. [147.75.193.91])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-7051ba4b93esi108316d6.5.2025.07.17.16.47.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 17 Jul 2025 16:47:04 -0700 (PDT)
Received-SPF: pass (google.com: domain of kees@kernel.org designates 147.75.193.91 as permitted sender) client-ip=147.75.193.91;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by nyc.source.kernel.org (Postfix) with ESMTP id AED54A57A33;
	Thu, 17 Jul 2025 23:47:04 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 57D14C4CEE3;
	Thu, 17 Jul 2025 23:47:04 +0000 (UTC)
Date: Thu, 17 Jul 2025 16:47:04 -0700
From: "'Kees Cook' via kasan-dev" <kasan-dev@googlegroups.com>
To: Alejandro Colomar <alx@kernel.org>
Cc: Linus Torvalds <torvalds@linux-foundation.org>,
	David Laight <david.laight.linux@gmail.com>,
	Martin Uecker <ma.uecker@gmail.com>, linux-mm@kvack.org,
	linux-hardening@vger.kernel.org,
	Christopher Bazley <chris.bazley.wg14@gmail.com>,
	shadow <~hallyn/shadow@lists.sr.ht>, linux-kernel@vger.kernel.org,
	Andrew Morton <akpm@linux-foundation.org>,
	kasan-dev@googlegroups.com, Dmitry Vyukov <dvyukov@google.com>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>, Christoph Lameter <cl@linux.com>,
	David Rientjes <rientjes@google.com>,
	Vlastimil Babka <vbabka@suse.cz>,
	Roman Gushchin <roman.gushchin@linux.dev>,
	Harry Yoo <harry.yoo@oracle.com>,
	Andrew Clayton <andrew@digital-domain.net>,
	Rasmus Villemoes <linux@rasmusvillemoes.dk>,
	Michal Hocko <mhocko@suse.com>, Al Viro <viro@zeniv.linux.org.uk>,
	Sam James <sam@gentoo.org>, Andrew Pinski <pinskia@gmail.com>
Subject: Re: [RFC v5 6/7] sprintf: Add [v]sprintf_array()
Message-ID: <202507171644.7FB3379@keescook>
References: <cover.1751823326.git.alx@kernel.org>
 <cover.1752182685.git.alx@kernel.org>
 <04c1e026a67f1609167e834471d0f2fe977d9cb0.1752182685.git.alx@kernel.org>
 <CAHk-=wiNJQ6dVU8t7oM0sFpSqxyK8JZQXV5NGx7h+AE0PY4kag@mail.gmail.com>
 <28c8689c7976b4755c0b5c2937326b0a3627ebf6.camel@gmail.com>
 <20250711184541.68d770b9@pumpkin>
 <CAHk-=wjC0pAFfMBHKtCLOAcUvLs30PpjKoMfN9aP1-YwD0MZ5Q@mail.gmail.com>
 <202507142211.F1E0730A@keescook>
 <3o3ra7vjn44iey2dosunsm3wa4kagfeas2o4yzsl34girgn2eb@6rnktm2dmwul>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <3o3ra7vjn44iey2dosunsm3wa4kagfeas2o4yzsl34girgn2eb@6rnktm2dmwul>
X-Original-Sender: kees@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=cpLCkMB3;       spf=pass
 (google.com: domain of kees@kernel.org designates 147.75.193.91 as permitted
 sender) smtp.mailfrom=kees@kernel.org;       dmarc=pass (p=QUARANTINE
 sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Kees Cook <kees@kernel.org>
Reply-To: Kees Cook <kees@kernel.org>
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

On Tue, Jul 15, 2025 at 09:08:14AM +0200, Alejandro Colomar wrote:
> Hi Kees,
> 
> On Mon, Jul 14, 2025 at 10:19:39PM -0700, Kees Cook wrote:
> > On Fri, Jul 11, 2025 at 10:58:56AM -0700, Linus Torvalds wrote:
> > >         struct seq_buf s;
> > >         seq_buf_init(&s, buf, szie);
> > 
> > And because some folks didn't like this "declaration that requires a
> > function call", we even added:
> > 
> > 	DECLARE_SEQ_BUF(s, 32);
> > 
> > to do it in 1 line. :P
> > 
> > I would love to see more string handling replaced with seq_buf.
> 
> The thing is, it's not as easy as the fixes I'm proposing, and
> sprintf_end() solves a lot of UB in a minimal diff that you can dumbly
> apply.

Note that I'm not arguing against your idea -- I just think it's not
going to be likely to end up in Linux soon given Linus's objections. My
perspective is mainly one of pragmatic damage control: what *can* we do
in Linux that would make things better? Currently, seq_buf is better
than raw C strings...

-- 
Kees Cook

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/202507171644.7FB3379%40keescook.
