Return-Path: <kasan-dev+bncBC7OD3FKWUERBZURYTFQMGQEKWULTAY@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id uKbDMugIcWmPcQAAu9opvQ
	(envelope-from <kasan-dev+bncBC7OD3FKWUERBZURYTFQMGQEKWULTAY@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Wed, 21 Jan 2026 18:12:08 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3e.google.com (mail-qv1-xf3e.google.com [IPv6:2607:f8b0:4864:20::f3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 411705A585
	for <lists+kasan-dev@lfdr.de>; Wed, 21 Jan 2026 18:12:08 +0100 (CET)
Received: by mail-qv1-xf3e.google.com with SMTP id 6a1803df08f44-88fd7ddba3fsf386586d6.1
        for <lists+kasan-dev@lfdr.de>; Wed, 21 Jan 2026 09:12:08 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1769015527; cv=pass;
        d=google.com; s=arc-20240605;
        b=Xhi5xl/Wpuj+YsHNU96aIaN9/tNEi3VH5zq4zMcPd6Gew/dqS5JyAMOsZwx4FxVYgf
         QK/2pxTcofcAHkl+Y7QB/1gE5qg1EpH0Vi1a6JX4xCu468trnGJKDNnNDe0z7q+wQkg4
         a0QBz/Sf10YEeYV64jZHipCexQcs1pELv/yZkAnGXBH5JTUiGXQCDoeMKRqsy7REx1vk
         8JJVeAA2fe/4psviuWI9Uftv7oBcSaAwcMqqrtff0ePcdQ/2nax0/nRBCgWiovBM99aj
         PnBZ410WOZg3zF07ICNbKpmlBMGnJvTUKahMVJHtSIG4cq3V0837oZ7A0GV61CzlyFTQ
         idAg==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Y02DfSrISRZaFpmRekttpuLnmlVOPpNf4E37V9ZWPc4=;
        fh=SnU+go+hh90VltG3pcuhx93mIqJIeso9tPS3Xj93CnA=;
        b=E67RDkmf1rpIeJgdhGskIL0ZZI2Hra+ut/vTozmu8T+v+ZgNjIkMWPsrlec2rOVX1Z
         2DTTYoM4nk1wCUQqs1JrYOi82FGE2wf6O1Y4Ac5+G4Zf6UmcZ4lxdHSRr7zvG9y3Qr9I
         /0IZJyubJcthVNN47dTx/o+XNm7XHTTmXwtf+GaGFfzKzzpRqmLUtSf8hlr7fVrf0i2K
         0Gz+uoR3HAfqCROs7NOiqKa2IhWuYdEpDaXKRqOThZwwD8++96d5Npeh5geRQw2yzZAW
         g3d6yDFO59Rr3duDlZdSySucabdzn3mVyYHlJNzf7IiJGH4c9W84uAQrQY1mnus/r9xG
         gfPA==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=PC94MGR1;
       arc=pass (i=1);
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::82f as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1769015527; x=1769620327; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=Y02DfSrISRZaFpmRekttpuLnmlVOPpNf4E37V9ZWPc4=;
        b=SafNwVSb/eIciWlt9Q8CvdKwjXvmdze0rXCHSBBCpouzij3HpiZZyFa7RFjuTrzMoF
         k5up2Oi9NrRPGGuWrHFjo57P6tdnwd+mtqTIUzq8KLZCFxdaEW/oiR4IxqZlbRIH8uiR
         vU7FqLhEAmiZiUllWDEunjVLSx6Ar7UaoZpgO7/97TjQI72o+wZWEcuQWwSefcjR4HPz
         fAuTO7SPnrzy4WFXjofgo9NGZtth2GM9DZEh9tt+h9VlhmzMMTG4I4YiBpwlydcbVt/d
         506ygbuSeH8NV1usdl4D3SKzvZUh9SKYlxpreHopGd5ZO0RTk9bGVVqkWHg/k1hF8a7n
         g8qA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1769015527; x=1769620327;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-gm-gg:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=Y02DfSrISRZaFpmRekttpuLnmlVOPpNf4E37V9ZWPc4=;
        b=s+qV3MJTuV1IeYtJx81sHr3SYUcZSJOdcVVWV6cGMH9XJ3aJLS421wapMEHtLva80n
         KToVxUkn6TOPMgZs6Op8qw/nqT4BboNCRT1GCc1i3ntJc4Dskox7KdImjCGiwN+k9t/G
         soXotHygERioiqJgQmRlgxho+1+4nMaJcOUi4YuwRivibUda/GFoxCRLWG9v95DOKJn3
         HuexagvCBT+i9IrVn4F5yMDLb4uZZUBUowv6FA2REkif6OCfs+dnifnS7rLB+b+y3nVM
         GkA/obygrYRR4OIrdNj1YdZg2oLKTDPIzQo16NjE/rZGE3XIRYT5Dx1fTmUtEAqFHeb8
         sS+Q==
X-Forwarded-Encrypted: i=3; AJvYcCXHkeeiYtcaMUPqATzxetafsfIv69GvVgSBtm8WWB16jDmCsmYUICFDYjZlyPe45F4lzh0S+Q==@lfdr.de
X-Gm-Message-State: AOJu0Yzt8xRXtMH+zlSNvFs5nb5S3lQI4iAFsCHb++u0S0WYLc0YKFb2
	fLvhnY/uKlGzjkaBPuegoC3YPMCGyh0lA6gbQYhi/1APZme3cSKqIfXF
X-Received: by 2002:a05:6214:4f17:b0:888:2032:4ad2 with SMTP id 6a1803df08f44-8942ddf47admr192765436d6.8.1769015526842;
        Wed, 21 Jan 2026 09:12:06 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+FBspu4lfglLZjNrvADLutcIHPuaJijxIl6vPDvkirCVg=="
Received: by 2002:a05:6214:a0f:b0:880:5222:360 with SMTP id
 6a1803df08f44-89470307fb6ls17433496d6.1.-pod-prod-00-us-canary; Wed, 21 Jan
 2026 09:12:05 -0800 (PST)
X-Forwarded-Encrypted: i=3; AJvYcCWGbg9qKMec5jBXcavrnkPSKrXQC+HmshZasf+NoXayVntT9W4Iug+9UIb7fAqYgx9V6704p2VuqkI=@googlegroups.com
X-Received: by 2002:a05:620a:4045:b0:8c6:a64e:f66a with SMTP id af79cd13be357-8c6da8ceeb6mr19166285a.21.1769015525323;
        Wed, 21 Jan 2026 09:12:05 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1769015525; cv=pass;
        d=google.com; s=arc-20240605;
        b=CqctOts4NkJd3WlTdQW9xQiDyY93c3kSadmuyEcXo3hPwF+nzuBZb6BHVdMn1YV0p+
         m4QCSpqQlJvs+Uc5CdjGKdcggdwNmXyUUrk/Ngr4JucNc/Q5OOqfWEvHcTjCBKv8R/mB
         yMhObzW3mgQpIE96cZ2OlZqi5Y3ug69KTZzmI8K5I/Y02Yxjnpkk1wJGpGHef9dl2j7H
         Gc2Uu/Dzcv0smfL5YeS+XLeb+5hI1pxNs5NBFJ6TvRYDjEonq5JMnmTCp0j/GgDwju6l
         p6HHDEkBtaLp5JnqHe7wxHC6smmTJaigA/Ey3S1L0pjB6m4L+PX92AdCMijsGJzG6c9/
         zjcA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=Wxe8ja7BPp0xudXZUtfCAF8pkuXAFux2AU5rIUV3nM4=;
        fh=88I7YZ9V3ZMRIdiC3iUu9nOEdk6pn5KajIjieE88DHM=;
        b=TuntIV3gwhp/dafVH4zLp+13PwHSTQBChYhRiEPZAKzd6LKJVvW2kzOSv43wxQpTdA
         Q0yK5ov098lAgXlSnD8KGd4RJorO1tNATSQdU8Lx7vhRTU/pQ9S3jgJUybankIA7kiwL
         36+lhTD995N76iwS7nAYMUe8Gh5AxZiOuava1ho4yyj7tios6CHopapUHwwSNEo0/Gux
         I8BlQUhuRzWLHGwBhBiZDS0PfoGZvlb9y1ee+t63fEGuOLDqMHpPhTv8TWGbkEKXEWMk
         isB78xKmtp93Dfv2PXu8mazpso5tix6TEops1tY7XYmL2wl+qMcbpvkeMCsDPk4Y1HQH
         PzUA==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=PC94MGR1;
       arc=pass (i=1);
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::82f as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qt1-x82f.google.com (mail-qt1-x82f.google.com. [2607:f8b0:4864:20::82f])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-8947108c5c1si874456d6.0.2026.01.21.09.12.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 21 Jan 2026 09:12:05 -0800 (PST)
Received-SPF: pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::82f as permitted sender) client-ip=2607:f8b0:4864:20::82f;
Received: by mail-qt1-x82f.google.com with SMTP id d75a77b69052e-501511aa012so151261cf.0
        for <kasan-dev@googlegroups.com>; Wed, 21 Jan 2026 09:12:05 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1769015525; cv=none;
        d=google.com; s=arc-20240605;
        b=EXXeHCG5pxqaUIhUW3yx/Rycezo5iMKRczFuBt/DHKB1BHJgyf8QHpsLxScvHLFFlT
         wmYfrWnfR3dD55ugP0dx3TTLA/rnNG+kOmd2XSZIQq1q0XVMi6b2k5lwT7zOA/FzUgHR
         vo7Mz/J/RDIzSh6Kv5CNb0slhL7XSDfFdckcLFms17PNz9y+HFuyluKrIitBY4dQHbbe
         qiltByWT10Y/SBTX2aKGLHRHlBgIErN4RlW/mF2wEl2MD4cOq9+aBFNmwippsL5XZ+0a
         7PXe/1c/sKLL8u0eGR9VrjG8pNVhEN6fismmmiKN2yQXiQwML929kmAYTWeyw9jTuzdy
         WF/A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=Wxe8ja7BPp0xudXZUtfCAF8pkuXAFux2AU5rIUV3nM4=;
        fh=88I7YZ9V3ZMRIdiC3iUu9nOEdk6pn5KajIjieE88DHM=;
        b=P+fa9HN6i4CZg3vwhAkThhqUB65y+CUy4kw4YVqcbQaOvob+ZOHcsHuog03df4dgnc
         077bJjckK465GIM/iHxm2wQoLQqTcbsgRIykUcTVdANRWmK+kaHFOqWvAkowCqX1g+cR
         gmV/9ofuuQmoxrRLZl/1igJAMwf/Xb91CdbggSblrWlntRDq5bZXbpr6Xw7T6a+eDevN
         FHNTM2tWA0A+CKMd7Y9Vk/tcmO3md59wZqnRrGKdu0mgajqD6gL5Q22Ns2Y6QkA3ncSY
         zuxwe9JQPd/pv35orolQbru2ItCy+IKR2kl/M4wwntdpYdc+UdyTeRpxBcrZSvn9UQRO
         Y7XQ==;
        dara=google.com
ARC-Authentication-Results: i=1; mx.google.com; arc=none
X-Forwarded-Encrypted: i=1; AJvYcCWex3zWW8jOH89tFfXZfORSs1Xzoryp2w7TsyPxTGmdsHotcC9PsD+EaoeeO4zB6YKEZj3cDxpMI14=@googlegroups.com
X-Gm-Gg: AZuq6aK0Yg33Y6MXSL7/e6+Ua7dNJsR5zCN+BWx4SsF6eCbfewwSuYu6fz9xP4idi+v
	eh+25haQfSOkMU3sT6HMZaaq1TNAeukBSv0EtuFC0X3HachREZH5YHg+UvZ5Ss9CvytX8+BH2XJ
	l+TUt3e6FRtn3ngWhU5kQvghZ0iUptjEAXMmknxrpc8JmUA8H+l+Yb6tWgwzwRw8Jh7zj0DH+0Q
	wnGBkWRG5Atv3vTR+/+x+wAF/n/i+Vg94I7MZE1oavyMZeCq+RXi/MkEHWCD4kYd3Q/m/yQsYnk
	Ad2cXPx5xu/y5OkPbhNeZTw=
X-Received: by 2002:ac8:7e8c:0:b0:4e8:aa24:80ec with SMTP id
 d75a77b69052e-502e0c62ce0mr14559311cf.14.1769015518740; Wed, 21 Jan 2026
 09:11:58 -0800 (PST)
MIME-Version: 1.0
References: <20260116-sheaves-for-all-v3-0-5595cb000772@suse.cz>
 <20260116-sheaves-for-all-v3-13-5595cb000772@suse.cz> <veqtpod2liqsi4mgcxndgaiyqlhupnymmj4pquueqziqyakmnk@fzympoan5pds>
In-Reply-To: <veqtpod2liqsi4mgcxndgaiyqlhupnymmj4pquueqziqyakmnk@fzympoan5pds>
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 21 Jan 2026 17:11:47 +0000
X-Gm-Features: AZwV_Qi9FJEvRsSrApnNVXPgEwKn9hYifa6IChzrQfzwFnpFd6X3lSwIuICSEss
Message-ID: <CAJuCfpH3DVwK7FqfKb3WChWyz_ZJvECBf57Ehxr7qCzS=Ym_8g@mail.gmail.com>
Subject: Re: [PATCH v3 13/21] slab: remove defer_deactivate_slab()
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
 header.i=@google.com header.s=20230601 header.b=PC94MGR1;       arc=pass
 (i=1);       spf=pass (google.com: domain of surenb@google.com designates
 2607:f8b0:4864:20::82f as permitted sender) smtp.mailfrom=surenb@google.com;
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
	R_SPF_ALLOW(-0.20)[+ip6:2607:f8b0:4000::/36];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601];
	MAILLIST(-0.20)[googlegroups];
	MIME_GOOD(-0.10)[text/plain];
	HAS_LIST_UNSUB(-0.01)[];
	RCVD_TLS_LAST(0.00)[];
	TAGGED_FROM(0.00)[bncBC7OD3FKWUERBZURYTFQMGQEKWULTAY];
	RCVD_COUNT_THREE(0.00)[4];
	FROM_HAS_DN(0.00)[];
	RCPT_COUNT_TWELVE(0.00)[17];
	MIME_TRACE(0.00)[0:+];
	TO_DN_SOME(0.00)[];
	FREEMAIL_CC(0.00)[suse.cz,oracle.com,suse.com,gentwo.org,google.com,linux.dev,linux-foundation.org,gmail.com,linutronix.de,kernel.org,kvack.org,vger.kernel.org,lists.linux.dev,googlegroups.com];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	HAS_REPLYTO(0.00)[surenb@google.com];
	TAGGED_RCPT(0.00)[kasan-dev];
	FROM_EQ_ENVFROM(0.00)[];
	REPLYTO_DOM_NEQ_FROM_DOM(0.00)[];
	ASN(0.00)[asn:15169, ipnet:2607:f8b0::/32, country:US];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	MISSING_XM_UA(0.00)[];
	REPLYTO_DOM_NEQ_TO_DOM(0.00)[];
	DBL_BLOCKED_OPENRESOLVER(0.00)[mail.gmail.com:mid,linux.dev:email,suse.cz:email,googlegroups.com:email,googlegroups.com:dkim]
X-Rspamd-Queue-Id: 411705A585
X-Rspamd-Action: no action
X-Rspamd-Server: lfdr

On Tue, Jan 20, 2026 at 9:35=E2=80=AFAM Hao Li <hao.li@linux.dev> wrote:
>
> On Fri, Jan 16, 2026 at 03:40:33PM +0100, Vlastimil Babka wrote:
> > There are no more cpu slabs so we don't need their deferred
> > deactivation. The function is now only used from places where we
> > allocate a new slab but then can't spin on node list_lock to put it on
> > the partial list. Instead of the deferred action we can free it directl=
y
> > via __free_slab(), we just need to tell it to use _nolock() freeing of
> > the underlying pages and take care of the accounting.
> >
> > Since free_frozen_pages_nolock() variant does not yet exist for code
> > outside of the page allocator, create it as a trivial wrapper for
> > __free_frozen_pages(..., FPI_TRYLOCK).
> >
> > Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
> > ---
> >  mm/internal.h   |  1 +
> >  mm/page_alloc.c |  5 +++++
> >  mm/slab.h       |  8 +-------
> >  mm/slub.c       | 56 ++++++++++++++++++++-----------------------------=
-------
> >  4 files changed, 27 insertions(+), 43 deletions(-)
> >
>
> Looks good to me.
> Reviewed-by: Hao Li <hao.li@linux.dev>

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
AJuCfpH3DVwK7FqfKb3WChWyz_ZJvECBf57Ehxr7qCzS%3DYm_8g%40mail.gmail.com.
