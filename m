Return-Path: <kasan-dev+bncBC7OD3FKWUERBXNFYTFQMGQEAHJZZJI@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id +HGGAOAScWlEcgAAu9opvQ
	(envelope-from <kasan-dev+bncBC7OD3FKWUERBXNFYTFQMGQEAHJZZJI@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Wed, 21 Jan 2026 18:54:40 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf39.google.com (mail-qv1-xf39.google.com [IPv6:2607:f8b0:4864:20::f39])
	by mail.lfdr.de (Postfix) with ESMTPS id 8F6A25ACDB
	for <lists+kasan-dev@lfdr.de>; Wed, 21 Jan 2026 18:54:39 +0100 (CET)
Received: by mail-qv1-xf39.google.com with SMTP id 6a1803df08f44-890587d4e87sf8761266d6.0
        for <lists+kasan-dev@lfdr.de>; Wed, 21 Jan 2026 09:54:39 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1769018078; cv=pass;
        d=google.com; s=arc-20240605;
        b=OtYNKJPsa8FFCy7tZFgTZ8V0Q1d1ROImylLoWUk2GVMYH3h5eyCF/agkNlFMmh58Y3
         BGOVkSCKp1XAWu6eTuQClsmt9Dv1sOYULdR0A1LuP+m+Y6dBSEBJFH7+UhQv55gU4/o/
         bOYSZIkS+jLYOKwISL2ckFL9aTHXdwnDCOJP6KhA7a7Vdu5wmWK1eUyPQd7/cfYdePLb
         pSjDz8LT+pbGZHs2mCzBzdItO8oeOk0HP5FxZW2sqXpkADo15XAyxyYZpwWVufBfP58C
         XBPY9S2PJqz4lVysx/OvNIIAUaUpMtxFonfCfk/rWvf6bzgJ2SeAVKM/9PWEgpdUNCwW
         t3kA==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Ul2QSD47eTI0hfDx++l6bwmgO79iAuFbbis+uSbGNKc=;
        fh=PHIOSGe36ayUsQZZnuq5E4erFdeFqJojaHFVR9g1yHY=;
        b=kV3UbOqFZfZCz0uGa6iDe8g1NW0Ppfu0fWVlFL+l+HmNsTglEj0a/k5Xic5RCQFRAM
         eD3J9wGx1f37WGuVNxSKjkkgI3ifSvCK32WgIg/oCDiAUjmUY7R1fW/xq00ez95QISFB
         uKytV5nDOucD4KpL0mjZw3jts6Kt4v34jKs9uTd6/IJweQxUM02xH8kbrl6tgOa1ura1
         z5woMpktvbf3sDFwucf1q0OQQrRMWb1mBwWxkWd5BZd+RYaF5ixfz5Lsh+7avU+6mKgY
         2oLfzxu8qleBvXfvy9hl+tMu6/ozuSRSQoHG9oqYb+7K6kC8Sl4gfCAdeIcuauFQemhh
         Leyw==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=m15M8irU;
       arc=pass (i=1);
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::833 as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1769018078; x=1769622878; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=Ul2QSD47eTI0hfDx++l6bwmgO79iAuFbbis+uSbGNKc=;
        b=Rdns1zzYsC2KqOQ+lYxX5kC97W9MdQ7CfKxw9RPA49TMrv1qi2kJ8PzNFCGqr8mmfu
         uhvdEj36j0HkNo2TNllDGCFGnTfHRIN61fgQn+MQyRurgT/lwejotMoHijvralbppnQt
         pC5fxMyChl2EG23DLeMDSK7724Cw8mStOqA/i1wfSNnBhQmh8hrQeEpKXQuv+0ddqgzV
         8prxntZWxJIuwiIUmpMzVmCyJ02c8mFXe4c1KECs7m+M/e68h3e4be5Jdo9aYHMr3W5p
         YH71K3EWvsofL0GpUO+nioc66Da05r1Y7q1IXMup/2ehxMLSBjTTseg6/HJhpSzHS/T5
         Y4Zw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1769018078; x=1769622878;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-gm-gg:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=Ul2QSD47eTI0hfDx++l6bwmgO79iAuFbbis+uSbGNKc=;
        b=SoIjQU9VbPZKEYz6Ptb6l10rZYKEZDf0p851J+rOtD1G3I/5iL0dqD1OhOnlkN62wS
         bfuXNC5ekoEAtOUHfn25J8pxejbWz0b1y/QikbDUhVGT5C/knSxFcEIpBtPddtd/IQUi
         CzX/CLNXDIlnO8UT5tHsaAfVTCnzSsSP3pNLXviB2LFBHh8VhYnInfVrQcker3YcOKvO
         BuqQBiuOzuOvUEI33kTe5EuUK8r/keUlpcMTbZoDcznRht0JflP1S+ndBCzyueBv9ucF
         YC8ocXCfUdkFPh8gujPPfpPScR+aWPAFb5fuyuvW4ze7rcRCfxNZvMuyULsEbVZjGhmH
         rgMw==
X-Forwarded-Encrypted: i=3; AJvYcCXDcSZF/VOjqMwN4h8DJZJemgMvaa2naLn9e1kLZCl/Qdxg8oNUjwKVXsWgi+fU57RrW77fjA==@lfdr.de
X-Gm-Message-State: AOJu0Yyv7gcx6obXiI1cJqvozAQ+1fOlEjsozJVyc2g1YPe315RBQIg4
	+TsSmkDkUEZUjisWKr8GhtajQLSVHqtxK843A8hZBA5iVJpahge9t27X
X-Received: by 2002:ad4:5746:0:b0:890:aa72:8ea3 with SMTP id 6a1803df08f44-894638878eamr79665686d6.28.1769018078129;
        Wed, 21 Jan 2026 09:54:38 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+HSSQV1xsmkJ0pvODiqJcYJWEY5XwNVnK3+3AQUgZd39A=="
Received: by 2002:a05:6214:f0f:b0:880:59ee:bbc with SMTP id
 6a1803df08f44-8947de9ba7bls4941496d6.1.-pod-prod-09-us; Wed, 21 Jan 2026
 09:54:37 -0800 (PST)
X-Forwarded-Encrypted: i=3; AJvYcCVq4alnr7hx/DaM7IsQJ1vMkbLFogIaTjKf2rA7DXpsQr6YnRy8ScBKX6H9liE8EEe6Nnp8W+jswg4=@googlegroups.com
X-Received: by 2002:a05:6102:dd2:b0:5f1:c561:8dc7 with SMTP id ada2fe7eead31-5f50aa7ef51mr2399436137.38.1769018077385;
        Wed, 21 Jan 2026 09:54:37 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1769018077; cv=pass;
        d=google.com; s=arc-20240605;
        b=a7HEmo0Y0FileqpHQj9lJrFTDgtVmJlyAN/v8AZBoFHKQWkzVdj0KdNYFdXSbTTlz2
         eDirIYni4/UHTFb90iHcGJ2dVII9uOCYWb37wECIJO+Lb2cqqi54I3DmgQ+IXGcpHrXv
         DEaZzBIaS1gke2SM0mp8OBtYGI6qZkuZQGErnOdZbeA3/1EXalV50hyBlJOK6Oc9gFCt
         Evp9iqa+ScjKR551KZ+W6d7zYrlYxTwFDAJPYkRK16TFmNE3ESjwM/tNje27CETRB6BW
         ZTUbZ9XG2U9b+5bhcMcaOCVdvY3WYXhaKDPFdswnQQwqHhzSCbLM09t0pVg8Zg23ENO2
         MdxA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=xH16wCmi7yX9t7ufNOPGVV4N0WTciDc4F9eI40Y8JvU=;
        fh=mIAPtjMc3gVwRDD2cl4efdleeyA8KYtiVEkT20w3Vxc=;
        b=E7I+/mNmMALNp0eqqXdBJ7ozDjuiy5jZ7fXZMqFjnfh8R9X7oISxlXWBw23hsWe580
         rzFIA44WYB5APKQ4fAIpx34ELnb/mZh/wJKH1wdVRuV5w6/dg51+T8tmgDWK6TxrRjO/
         GX78BchOdRWzlijij2TdGgH98NlbwH/5t1AgFRB29iXmzA2y6v/MpYfswJ/jFiRd8fi3
         DOICp9KcobIhBB6kp3Uc8kKNpicEK7aqrogqaHJx+13VVfkxl1mN1wOQ/FexYyOisCcj
         L+WBQQ4gNvgjeeNNNPPb+QdiGZPT312uyW3l5VMRF9afB9q2ixy36VK8TLnIMEmUfsiu
         9Zew==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=m15M8irU;
       arc=pass (i=1);
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::833 as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qt1-x833.google.com (mail-qt1-x833.google.com. [2607:f8b0:4864:20::833])
        by gmr-mx.google.com with ESMTPS id ada2fe7eead31-5f1a6f4c6c3si510002137.3.2026.01.21.09.54.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 21 Jan 2026 09:54:37 -0800 (PST)
Received-SPF: pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::833 as permitted sender) client-ip=2607:f8b0:4864:20::833;
Received: by mail-qt1-x833.google.com with SMTP id d75a77b69052e-5014acad6f2so7431cf.1
        for <kasan-dev@googlegroups.com>; Wed, 21 Jan 2026 09:54:37 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1769018077; cv=none;
        d=google.com; s=arc-20240605;
        b=WRfbuFmmTNHJy0cFIW/Y2cl8OokeR05A9fvS+XUYbXzA250uziv9TDOaEgP2WKYE1v
         PKfb2h5x2Vy7Z97ydgreAlWR3kg1iWxJFHy6H7DwdZIFIYTRkNCCAtq+A6+gniHJcXa9
         J4Thni8u7MFpQ6Oqg0OkaAAaSaddBQfxYMmiXyQhPIizZTU8eJMRYJRxXlcg5P2gn5pE
         3aYXhfPdwhfJyGJqjisqEkFIrCZbj83UNutGO9u/rKISrXU+QdlPLAnoiPAeugVsIxcx
         HPActbsGbDcM+mq87E9XWHcfkWWOQ8aAFCrGMxNF19asV6Z9QuhZJWxom8rNqq/FL+sp
         q+XA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=xH16wCmi7yX9t7ufNOPGVV4N0WTciDc4F9eI40Y8JvU=;
        fh=mIAPtjMc3gVwRDD2cl4efdleeyA8KYtiVEkT20w3Vxc=;
        b=Ena43YVZK3F7R9sYd1a6ZRlKA07zM7eO+WNI8nlciMOqiQx4VX2PWgUG3He1glqQeL
         RLnwWg2n1MgQuKvuu1xMAZppbsV240Zfv4IZRJY+W3xV2geVnnWIR5ReTg6TfTIoJN4/
         trETizmMr1XMBaX9GbskpNXFlsXwi9xpDTX5rABl/E61vdr1a8fT2/ZQ4Vppjh1Q4QSi
         3MPVDSgRFvdfWZGfs5O7SZHsK+ftdoQfJsjTOGGuX9diy6lItLT7J2+P8cc+YuwJm76T
         Z+uz3urVBoJ5cRZHqgyfaHxKTyr3J15yIK4TYoBiBwwiwq/ff9HzjdEIjknPUQH5h0vc
         4EKg==;
        dara=google.com
ARC-Authentication-Results: i=1; mx.google.com; arc=none
X-Forwarded-Encrypted: i=1; AJvYcCW8slj6PQq2MKGcCM+h2+bn3NUNpTGYO04NnyRQziGTPQM+ionWFZM79mGXLFcXeS8PDkF66jp64Bg=@googlegroups.com
X-Gm-Gg: AZuq6aIISlpaEATfgHTRq4YfjKMymJtsmWn3r1eXCOJIIjunYnTHUrpy1kR4svXrYY+
	+dHCmlWmhboYWmC1t/WbDlMnXLIf0FcyYMq58AaXvIkdufI1ESN5uy+dnAIEMJ6E8qv6XouXzdd
	+Y7p3zzBgPSDba8B5e4Ky6mk6a/jbBDQYYX3xUXi211iVLx391CGF3llcSJG3ShqbWagtxKXhHQ
	8Zhqw7bqR3dc3lwkuORgNadLqFt+NUNzpcx4Xm3ez22p8O7HyZNnEoCpNiR2q4KAK7IcMg0lhQe
	SdfbDk4NHkmgpXNeL7IdsKtE9eu5RK5wOg==
X-Received: by 2002:a05:622a:1392:b0:501:4eae:dbfc with SMTP id
 d75a77b69052e-502e1a8066bmr12579381cf.5.1769018076530; Wed, 21 Jan 2026
 09:54:36 -0800 (PST)
MIME-Version: 1.0
References: <20260116-sheaves-for-all-v3-0-5595cb000772@suse.cz>
 <20260116-sheaves-for-all-v3-15-5595cb000772@suse.cz> <dxrm4m545d4pzxmxjve34qwxwlw4kbmuz3xwdhvjheyeosa6y7@2zezo6xejama>
 <6a814aef-7b81-4b9d-a0a5-39f7dd7daf3d@suse.cz>
In-Reply-To: <6a814aef-7b81-4b9d-a0a5-39f7dd7daf3d@suse.cz>
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 21 Jan 2026 17:54:24 +0000
X-Gm-Features: AZwV_QgoKQ8T9fdP0Ka4mFnfPpLd-1PHmliqOQBpu_g2EWtZ_-XqW6Axzna0iU8
Message-ID: <CAJuCfpHRrFS3a8=x4shoNXHLtmvkFgV8xASsQL0-hiUBb-O1Kw@mail.gmail.com>
Subject: Re: [PATCH v3 15/21] slab: remove struct kmem_cache_cpu
To: Vlastimil Babka <vbabka@suse.cz>
Cc: Hao Li <hao.li@linux.dev>, Harry Yoo <harry.yoo@oracle.com>, 
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
 header.i=@google.com header.s=20230601 header.b=m15M8irU;       arc=pass
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
	R_SPF_ALLOW(-0.20)[+ip6:2607:f8b0:4000::/36];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601];
	MAILLIST(-0.20)[googlegroups];
	MIME_GOOD(-0.10)[text/plain];
	HAS_LIST_UNSUB(-0.01)[];
	RCVD_TLS_LAST(0.00)[];
	TAGGED_FROM(0.00)[bncBC7OD3FKWUERBXNFYTFQMGQEAHJZZJI];
	RCVD_COUNT_THREE(0.00)[4];
	FROM_HAS_DN(0.00)[];
	RCPT_COUNT_TWELVE(0.00)[17];
	MIME_TRACE(0.00)[0:+];
	TO_DN_SOME(0.00)[];
	FREEMAIL_CC(0.00)[linux.dev,oracle.com,suse.com,gentwo.org,google.com,linux-foundation.org,gmail.com,linutronix.de,kernel.org,kvack.org,vger.kernel.org,lists.linux.dev,googlegroups.com];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	HAS_REPLYTO(0.00)[surenb@google.com];
	TAGGED_RCPT(0.00)[kasan-dev];
	FROM_EQ_ENVFROM(0.00)[];
	REPLYTO_DOM_NEQ_FROM_DOM(0.00)[];
	ASN(0.00)[asn:15169, ipnet:2607:f8b0::/32, country:US];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	MISSING_XM_UA(0.00)[];
	REPLYTO_DOM_NEQ_TO_DOM(0.00)[];
	DBL_BLOCKED_OPENRESOLVER(0.00)[suse.cz:email,linux.dev:email,mail.gmail.com:mid,mail-qv1-xf39.google.com:rdns,mail-qv1-xf39.google.com:helo,googlegroups.com:email,googlegroups.com:dkim]
X-Rspamd-Queue-Id: 8F6A25ACDB
X-Rspamd-Action: no action
X-Rspamd-Server: lfdr

On Wed, Jan 21, 2026 at 2:29=E2=80=AFPM Vlastimil Babka <vbabka@suse.cz> wr=
ote:
>
> On 1/20/26 13:40, Hao Li wrote:
> > On Fri, Jan 16, 2026 at 03:40:35PM +0100, Vlastimil Babka wrote:
> >> @@ -3853,7 +3632,7 @@ static bool has_pcs_used(int cpu, struct kmem_ca=
che *s)
> >>  }
> >>
> >>  /*
> >> - * Flush cpu slab.
> >> + * Flush percpu sheaves
> >>   *
> >>   * Called from CPU work handler with migration disabled.
> >>   */
> >> @@ -3868,8 +3647,6 @@ static void flush_cpu_slab(struct work_struct *w=
)
> >
> > Nit: Would it make sense to rename flush_cpu_slab to flush_cpu_sheaf fo=
r better
> > clarity?
>
> OK
>
> > Other than that, looks good to me. Thanks.
> >
> > Reviewed-by: Hao Li <hao.li@linux.dev>

I noticed one hit on deactivate_slab in the comments after applying
the entire patchset. Other than that LGTM.

Reviewed-by: Suren Baghdasaryan <surenb@google.com>

>
> Thanks!
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
AJuCfpHRrFS3a8%3Dx4shoNXHLtmvkFgV8xASsQL0-hiUBb-O1Kw%40mail.gmail.com.
