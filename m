Return-Path: <kasan-dev+bncBC7OD3FKWUERB64KYTFQMGQE7LE6NLQ@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id wNW1HX0FcWmgbAAAu9opvQ
	(envelope-from <kasan-dev+bncBC7OD3FKWUERB64KYTFQMGQE7LE6NLQ@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Wed, 21 Jan 2026 17:57:33 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3b.google.com (mail-oa1-x3b.google.com [IPv6:2001:4860:4864:20::3b])
	by mail.lfdr.de (Postfix) with ESMTPS id DFBE25A36B
	for <lists+kasan-dev@lfdr.de>; Wed, 21 Jan 2026 17:57:32 +0100 (CET)
Received: by mail-oa1-x3b.google.com with SMTP id 586e51a60fabf-3ff48fbeadfsf261854fac.1
        for <lists+kasan-dev@lfdr.de>; Wed, 21 Jan 2026 08:57:32 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1769014651; cv=pass;
        d=google.com; s=arc-20240605;
        b=BEy1pgYwq+Ca3kOkgVJ8UctPiWtuA+kDqEtN7/HG4d/GMqchohmZCrouB//Un2i76M
         1+3vv68ZDZ+baNHawNzg9IW7RrHXJvQdos5EPLAcl8giIR6CVigDipkPBpRK7YVHFmAz
         mG+wnerW5mKM8DfHDgOQH9YKN630cAkDmlGH9nqPSvf+9bTyftdFfxcuZrCQ/oFB1XbM
         nbAOIPb6rditZTg/+Z8bivveBRYZ9lxb5V/c68bo0cp/jVifFQN66UyPwNuk1yJJkh/q
         mm7nQQ/DRiiLknT97Tdc8r3mRuHD1aUC1fAHN0w4+rbt5fWXM7muha0GqNLFjWS3ids7
         WV1A==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=mzhhtndRuxZt+E5swuhBr7rLg33l4oY10obaimzjmzs=;
        fh=xTo3n8e3No3LlAgy7YN4er4TXdcbvQeMEp7oMWpdo5s=;
        b=hNI7uQ9YU0A9lrzxCxZtMUlvHUkBx5wjqkdhGBuS9PmQiWYtXwn7LAS8F+oFsJNw/l
         YmhO+suQuuNzlNQITYAZCD6/jDC5gUo3CW5e6Kl1K+58k2qV0fFieHcLwkxkCH6lkOAq
         bXUQEOdS7p9ON/mNW6jx2TQAMtuZGeuTjev2b6s4zizSGyA+JVIiSF7cqSw55LFgGxFX
         BvYDrEF5MLzdYrOMg4pVHBzpexSZ9ZOQ48pQ7A9Oq0BUivpd1Zl2uVRl33N+xVcwwnXE
         z6kRCAq6ZtFfJXrZxGBbccqI97Hw17FTT9+tg71obEdJgsdDMfsZo2BCZP//UTMRuOCi
         +E1g==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=TjQp8mv8;
       arc=pass (i=1);
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::833 as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1769014651; x=1769619451; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=mzhhtndRuxZt+E5swuhBr7rLg33l4oY10obaimzjmzs=;
        b=NEagHZ7HGONJ567Sd8JXcAAy3m0EMEKxkUuQwV4uCxXwnGkKSDcyR9i1YHcb5KSxiX
         sRrTNLLEv8Kg45VkwnCjUx8UQ8SAer/KV9pim5IzyJDYOlck9TusB2YWanLgTfC6NFlT
         ieQWduLZTJpqgzb+SsRwg54w5NqS2Ej2HD4Nw6GhemfBfE5iF7xQYbX7Z0BFPRszn5jC
         eMbx2B7kl6YQ5WLBODnj70ESU3r4V8vESTqRnU7CZFBJbgr9v6i7hu7GJYnesQy0lKeu
         gPRw1TKDA8GXX3CcECRGRQX+9C29WMCfBBKQ+nvzeX/7sKq7a05reBdiKJg8p17XL69m
         +ttg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1769014651; x=1769619451;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-gm-gg:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=mzhhtndRuxZt+E5swuhBr7rLg33l4oY10obaimzjmzs=;
        b=Z4kNZaW3/pAKD4hVeZXK+SekqfooaOfQLJILRQ+gInA3wbpFvwbp60owyL3RHtgI0U
         gFzNTJVSX6mrM2L8stPuWxsd/AZ0/Rg9do6JpahiFFIDaRYmvWL1UhuB1hanaNIYe++E
         +VR9cjC7atmkjZ+cErI6RFk4r/3t1ymK1k6+oOjEQVjrAECevcOCXzq/N8Xc2oNk/qio
         4WcITSDWqpsgfg69Cu5/RsjrF1Mi3B5klt5lyr80ZE5kw1c7QjmyAikldUEyZ9P8QhCs
         5MYM4jGbycuFXXiJntxHme/9yfRZAOyY2/Rb8QMvInzpl2XvL0795DQqVbu1JlpYKjBP
         asLw==
X-Forwarded-Encrypted: i=3; AJvYcCU/HGUg0iqUMSTVVifDaLFbr2rF6dUPUxyhkOE6LEATSfP8NsUx6l3gHSySSkPgW5/ZFDMzwQ==@lfdr.de
X-Gm-Message-State: AOJu0YymtClxv7cSOcWoLX4aZ1n1bdMSSVg/S7ZHYBVDrU7ky+j5VXCY
	8FWiGOkNvAmJZX19gZq9BJGvEHBxTCjpCyukRHe3X7fpkD0X1hOpvSyj
X-Received: by 2002:a05:6870:d69a:b0:3ff:c04a:ce9c with SMTP id 586e51a60fabf-4044c1f1d0cmr8883272fac.20.1769014651268;
        Wed, 21 Jan 2026 08:57:31 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+Fgkdt/yrn+18+e5ap8tnOsnKGQAbsO21gKn31woP3QoQ=="
Received: by 2002:a05:6871:789:b0:3fd:9a1d:4743 with SMTP id
 586e51a60fabf-408825e01e6ls21240fac.2.-pod-prod-02-us; Wed, 21 Jan 2026
 08:57:29 -0800 (PST)
X-Forwarded-Encrypted: i=3; AJvYcCUrxA0sj6tdE/qV46ytaLU9FrCZPMwp0j8EiKYi3+0xU/3Vc1936x8vltmraL/x4A0qTBLMIJG4DrM=@googlegroups.com
X-Received: by 2002:a05:6870:ac09:b0:3fd:abea:847e with SMTP id 586e51a60fabf-4044c6b4937mr7941053fac.57.1769014649080;
        Wed, 21 Jan 2026 08:57:29 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1769014649; cv=pass;
        d=google.com; s=arc-20240605;
        b=gXx8UVpJPmNCBgu40D6VEJEquqx1jiOiafyeuMY5CT1qt9YyxhVaSljTSzySO1MDei
         sjlgDQGNbka47JzwKNaJiolL0l+PCdSF5QReDP3BhD2g46bFstzFG3UXSxAlNMGLba4C
         PLGscke8LeoPZa8CmURN4kObVxNwMIEqPEAffExm6Ira00P0oI5sdeihiDmIcD/5/QwC
         ddkm0INrkHmoaskWJCE0U2l9Ns7EznMpmQehREFmTZ5bxQVQBGXVED+ecQaiKMVYz6Sx
         9hTHDD5Xl30slT3E82eCJ69AWuaDYMM/0jr7VcLVLvcoIrwc5pEGwvdZjS3IqTzklKpL
         hG+Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=DzJlvh2XyLMGkwtl0QberzuQSLWoZAkg3qQo6w3w0Bo=;
        fh=vvS9HyiZdBddfO8pMlGP9XueCWYTFQchHCF7HwQbwwA=;
        b=hmfa6pG56LPZaKTl38zmW/fHJsOVgZZGLotWBbXwHHrksHCY11gOYQLvjSPZjLUx2I
         9+Da3EVAMq/Ng/KNxkzIabmMEOpm9Th5FiEOmP079Zqw6MHGS+TwTzEY+G2uo0bmRkbs
         Vd45pbeYRMht0CiqiKokfYK3KAK2irdoM/HDRvGS6tBjgHFc9fy62VqyoX5SMNI/cld+
         wPtEht8HxP3PZ4ZncEzka4r/JvQwIaQKMDvadY1Qnadqe2blZnJ4wG6QELH5VJ/isBfg
         7H8Rs//HPX5TD1Ee/VDJda6CyEYnBrgG1BEdeLkY5XbdqjJ//b7ey2w/rBpg9ayBBHRz
         vBjw==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=TjQp8mv8;
       arc=pass (i=1);
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::833 as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qt1-x833.google.com (mail-qt1-x833.google.com. [2607:f8b0:4864:20::833])
        by gmr-mx.google.com with ESMTPS id 586e51a60fabf-4044b5a56e8si639676fac.0.2026.01.21.08.57.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 21 Jan 2026 08:57:29 -0800 (PST)
Received-SPF: pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::833 as permitted sender) client-ip=2607:f8b0:4864:20::833;
Received: by mail-qt1-x833.google.com with SMTP id d75a77b69052e-5014b5d8551so502491cf.0
        for <kasan-dev@googlegroups.com>; Wed, 21 Jan 2026 08:57:29 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1769014648; cv=none;
        d=google.com; s=arc-20240605;
        b=dAmWl+V1jlAqIKw+Y526QbA1Nhl2POMofE7+FlTsmWIWhewfSY6Ned9ZdZbyt3bIGB
         qwB+6ZacFUG8jfJvisYirbEWE6pGN07vvJ1zxe/APewaS5DEHVweXpS4KAjCL1khuyfn
         8fXD9Zc905Wq3am20YlgHXa35VDZXYC9/9M/seeyVmPGzIk6UlRO1SnzQz7yq3v020dR
         NwNBzbTpspd3T0IP8TDW9W1Dkt7NbzeymPSpyke2xokmxseXiN+1A64H2rQDcRRtPnZm
         on41x2Y1yLLS6BgEXjSP5g3CoWJNPxWlXq67G3OGPmTCXMIE5spk9m+uUtKkMcdS9c1D
         8fdw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=DzJlvh2XyLMGkwtl0QberzuQSLWoZAkg3qQo6w3w0Bo=;
        fh=vvS9HyiZdBddfO8pMlGP9XueCWYTFQchHCF7HwQbwwA=;
        b=e8TDycP8hcYVXpWlmbcZivmN0GJG/y/D7m1YcKD/kFORDwvsoHTTQ1MhWZlL7ADQQD
         Trcdn7qbAgwHi+1xfN/OPsHxpTlzuupiafowV0j8KngloTFnEYgMwR7N9sh65PeSTTi/
         AKcRQnhM3nchaI/FTjGDl7sKJ8N1+jpRDTd0Huofz+9Ks1lzft27hjihraMbNiNQc1R2
         3dMR1WJFK5uLMVfiYJNBZ0J0AaT2l79itRB5HP6FM1E6kx+Cn37HtzBLHsMvcvF6uC5Q
         PCe3XFh3ZSwtkuBY/6/i2Rq3SRVB8fNWXPQbzkDeDgwNCufytAEOlvA1V/SpjXW7A3jH
         7xwA==;
        dara=google.com
ARC-Authentication-Results: i=1; mx.google.com; arc=none
X-Forwarded-Encrypted: i=1; AJvYcCUk17dGX4Ws+Gl3mghqBBvcVvV+GJN7nWLKHGeDGMChP9ljwMd2BW+UDdYh8hbysQNqRkY9BEhaijo=@googlegroups.com
X-Gm-Gg: AZuq6aKcI3YvkglBoIr3AHUXan30WyyhHyyV3SWUCjy7drTR0gBuCggm/fTGdoRY6du
	ceT3UTQC7jPRkaDUFh0oDYRiGg0uqzIWJO/iQx3Hp5b+9Vf8kqgC/IDJbPNrZu2V6A24jYUfb0r
	UwDI38rFmbHYxtY7/Mh9uE/NLjP0oO+ZDT7TsRVXWL90UpvmSNC5OTglldHdaA1XLwFbyB2W5f0
	Oq+qFdr2XkbeTpfR2vVvXYVxiyxwkNYQhYvHK/4p9Ey8hJpy7Ifw7vZlYwmPuM642+DLjJDbGwJ
	/8FKpN+Bpabc2I/4Lzpif2k=
X-Received: by 2002:ac8:584d:0:b0:4ff:c109:6a4 with SMTP id
 d75a77b69052e-502e0c0d426mr15219551cf.4.1769014648007; Wed, 21 Jan 2026
 08:57:28 -0800 (PST)
MIME-Version: 1.0
References: <20260116-sheaves-for-all-v3-0-5595cb000772@suse.cz>
 <20260116-sheaves-for-all-v3-12-5595cb000772@suse.cz> <yejhiw37av3o23z6s4oewlmhip3iqxxkkfcjp2jhlo4qf7nm23@hojkan5ym5cv>
In-Reply-To: <yejhiw37av3o23z6s4oewlmhip3iqxxkkfcjp2jhlo4qf7nm23@hojkan5ym5cv>
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 21 Jan 2026 16:57:17 +0000
X-Gm-Features: AZwV_QgOY9Ovo2gtiQ4jhpdmFVjl8h8HKayG692yA7UEj4JquBoNIBa9LT-cydc
Message-ID: <CAJuCfpFaeYyzHirCYUPT0JDeavuq5UGqegW0OMata31XbYGnww@mail.gmail.com>
Subject: Re: [PATCH v3 12/21] slab: remove the do_slab_free() fastpath
To: Hao Li <hao.li@linux.dev>
Cc: Vlastimil Babka <vbabka@suse.cz>, Harry Yoo <harry.yoo@oracle.com>, 
	Petr Tesarik <ptesarik@suse.com>, Christoph Lameter <cl@gentwo.org>, David Rientjes <rientjes@google.com>, 
	Roman Gushchin <roman.gushchin@linux.dev>, Andrew Morton <akpm@linux-foundation.org>, 
	Uladzislau Rezki <urezki@gmail.com>, "Liam R. Howlett" <Liam.Howlett@oracle.com>, 
	Sebastian Andrzej Siewior <bigeasy@linutronix.de>, Alexei Starovoitov <ast@kernel.org>, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, linux-rt-devel@lists.linux.dev, 
	bpf@vger.kernel.org, kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: surenb@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=TjQp8mv8;       arc=pass
 (i=1);       spf=pass (google.com: domain of surenb@google.com designates
 2607:f8b0:4864:20::833 as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
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
X-Spamd-Result: default: False [-2.21 / 15.00];
	ARC_ALLOW(-1.00)[google.com:s=arc-20240605:i=3];
	DMARC_POLICY_ALLOW(-0.50)[googlegroups.com,none];
	R_SPF_ALLOW(-0.20)[+ip6:2001:4860:4000::/36];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601];
	MAILLIST(-0.20)[googlegroups];
	MIME_GOOD(-0.10)[text/plain];
	HAS_LIST_UNSUB(-0.01)[];
	RCVD_TLS_LAST(0.00)[];
	TAGGED_FROM(0.00)[bncBC7OD3FKWUERB64KYTFQMGQE7LE6NLQ];
	RCVD_COUNT_THREE(0.00)[4];
	FROM_HAS_DN(0.00)[];
	RCPT_COUNT_TWELVE(0.00)[17];
	MIME_TRACE(0.00)[0:+];
	TO_DN_SOME(0.00)[];
	FREEMAIL_CC(0.00)[suse.cz,oracle.com,suse.com,gentwo.org,google.com,linux.dev,linux-foundation.org,gmail.com,linutronix.de,kernel.org,kvack.org,vger.kernel.org,lists.linux.dev,googlegroups.com];
	REPLYTO_DOM_NEQ_TO_DOM(0.00)[];
	HAS_REPLYTO(0.00)[surenb@google.com];
	TAGGED_RCPT(0.00)[kasan-dev];
	FROM_EQ_ENVFROM(0.00)[];
	REPLYTO_DOM_NEQ_FROM_DOM(0.00)[];
	ASN(0.00)[asn:15169, ipnet:2001:4860:4864::/48, country:US];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	MISSING_XM_UA(0.00)[];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	DBL_BLOCKED_OPENRESOLVER(0.00)[mail.gmail.com:mid,suse.cz:email,linux.dev:email,mail-oa1-x3b.google.com:rdns,mail-oa1-x3b.google.com:helo]
X-Rspamd-Queue-Id: DFBE25A36B
X-Rspamd-Action: no action
X-Rspamd-Server: lfdr

On Tue, Jan 20, 2026 at 12:30=E2=80=AFPM Hao Li <hao.li@linux.dev> wrote:
>
> On Fri, Jan 16, 2026 at 03:40:32PM +0100, Vlastimil Babka wrote:
> > We have removed cpu slab usage from allocation paths. Now remove
> > do_slab_free() which was freeing objects to the cpu slab when
> > the object belonged to it. Instead call __slab_free() directly,
> > which was previously the fallback.
> >
> > This simplifies kfree_nolock() - when freeing to percpu sheaf
> > fails, we can call defer_free() directly.
> >
> > Also remove functions that became unused.
> >
> > Reviewed-by: Suren Baghdasaryan <surenb@google.com>
> > Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
> > ---
> >  mm/slub.c | 149 ++++++------------------------------------------------=
--------
> >  1 file changed, 13 insertions(+), 136 deletions(-)
> >
>
> Looks good to me.
> Reviewed-by: Hao Li <hao.li@linux.dev>

There are some hits in the comments on __update_cpu_freelist_fast and
do_slab_free but you remove them later. Nice cleanup!

Reviewed-by: Suren Baghdasaryan <surenb@google.com>

>
> --
> Thanks,
> Hao

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
AJuCfpFaeYyzHirCYUPT0JDeavuq5UGqegW0OMata31XbYGnww%40mail.gmail.com.
