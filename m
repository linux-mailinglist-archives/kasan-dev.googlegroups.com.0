Return-Path: <kasan-dev+bncBC6LHPWNU4DBBVXQWC6QMGQEYAODTZA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3f.google.com (mail-oa1-x3f.google.com [IPv6:2001:4860:4864:20::3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 0C8E2A31E5F
	for <lists+kasan-dev@lfdr.de>; Wed, 12 Feb 2025 06:57:44 +0100 (CET)
Received: by mail-oa1-x3f.google.com with SMTP id 586e51a60fabf-2a8e3905c56sf2543239fac.2
        for <lists+kasan-dev@lfdr.de>; Tue, 11 Feb 2025 21:57:43 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1739339862; cv=pass;
        d=google.com; s=arc-20240605;
        b=lgzvqOzBM5lSeY+93yx5VemkoHUUbyUZ4O/ezbaiBofwP+ByZ2hRf/VlZIYuKkSUn/
         eI3nyms/XT23OvEbQL3kY1UJ1PnBW38AOAQEuWgRIb53tCytIGelQJz5yf3ZP8baagBG
         tvJtpQ9OzISrPG66ydYlKhS+Y1tmBRWY9LPpiyvAbleED1ZsZ6zU2wPxybQKEGHxtYIj
         jtEGnZRITpEkfOQCpKDxslbk8XcCEXds2c+CJxzAeBXoeUWvj6cq8jUfbyyhifo2tIal
         OD9RDmoVTGJfsrIlE2qzDHVesPy5NTtzhUmY0Na1qV2ImdHRNr2FaCVVhgnLh+cOIYUQ
         C/RA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :feedback-id:sender:dkim-signature:dkim-signature;
        bh=+/R6coAAxSkYTJU6ag/E8fFFZaqhz2fLYPnxT5QzFZw=;
        fh=QtkC8qeMWZeEe0I5V8GmKz4ExbwfSGM94u77Wfx7EGc=;
        b=BLw9f0Kf+lD9H9ALw2s3aHn1erLllYRUVH8PHrFOsuySYesECPAmDc61EL7dfW5PlJ
         t20htZlUjhC5fSErwKUYmsaB5XmKk0SXWr9f7y5vxs2LZ95ZqMs2ZiylJeKrh45UT0Nj
         lDcpnGHarNR/BDwtQO516YduwpD0cGONd13TikQpLEfX3OvIDNCsDzlEf9A6dlfSvXZ1
         R+DXdbovmBmwWqUvMOhrwOY75Qr/spTvm59duo2pnE9ardLgaHJXrLQDcC1pkLNBewSC
         7cll6sBlyIkwJWFlEhT5jNoilrzEAQJDjnuAjaaEAqAuqZNgQWzdtoKPvWReNhp9cA6u
         9oSw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=HQj2HR45;
       spf=pass (google.com: domain of boqun.feng@gmail.com designates 2607:f8b0:4864:20::f34 as permitted sender) smtp.mailfrom=boqun.feng@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1739339862; x=1739944662; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:feedback-id:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=+/R6coAAxSkYTJU6ag/E8fFFZaqhz2fLYPnxT5QzFZw=;
        b=nlybSC8KTnlZHYAhSjipaKGEyrNgULLCOVurzorGNfgumcmvEuG+IdztK1+u4+J3Go
         PaQwPZMhKnwylgBkMXqhTBx1oevlL/xZDaIVM5CSxrbucp+zUUnLwxd6NaKu6IqHBYIv
         oB+6ruTM4EZShNH47yDeu6JipKEw/2q8b8GYjtIkR5DltXemlmPni9yJNgXyPglTg2BS
         airpwA0kDUbmGA38gK/SE7GUUbsZBxchyC3FCLhSC5hb1VMmXrV8sDTgMHbC90KZwmRx
         RJHPBi1rSZXyqWJM6s5CUHPiMDf6gv0hTjglzNvtbdwHMG/Jf35xM45tXSF9WvfvhpeG
         xw7g==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1739339862; x=1739944662; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:feedback-id:from:to
         :cc:subject:date:message-id:reply-to;
        bh=+/R6coAAxSkYTJU6ag/E8fFFZaqhz2fLYPnxT5QzFZw=;
        b=JBgsmE1pJLNXGUGEHIxOI5O0W65NNRldReNpUq8nokN6lOSFrZywgITFp/qnKCNRIQ
         ehsbpM7ql8ZRSYDtlGZKgjeA1kZ2ePS5FYs3afk+1vh8/IQpuub6VgSkh8GL90e1Qanb
         IQ3+rtQLmN/hUe182K5HqQfU2TJG/9m2/ElSGytTiQ7qvx/8fdMfK7jmTgE+PZKixWtG
         atQq0svs850DXt/WKva8LyxtaMFCsUUOZXIZ6nXg6S5M604a5YUD05IdIVtUbcHysU8Z
         +6UQm9ag/DB1cBaULHfTsoSHD8r10KoK/z1liI9YSVYxvnAUSd0hcT70Ef6kZrggU90b
         pGNA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1739339862; x=1739944662;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:feedback-id:x-beenthere:x-gm-message-state:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=+/R6coAAxSkYTJU6ag/E8fFFZaqhz2fLYPnxT5QzFZw=;
        b=nm2d80K/n1GzkiAyWP0tZkrL3/SZzYEiuXQmJM/qEbg7P43Z4zUO2NlhV1eUVBp7+M
         vtMNA/sKeJdSKziF5fX0ElxRJ1U4a7odqZATMdPA6Qza72QBlwGcvw1DpMG3hMHbTONc
         zaAq96rBMqcEpb3SGrK8/XFvDE5hBlktxKSulZQPJVucitUVKNx99ekbwVFyjFrARvXE
         Btrh3uxxV/Ic10xxHW/Cnl9n8GNwwJ6hJ8CjlebymwwMfgLQUuwX7tUvepVu0Lb0ERbk
         W7wkHOcRZKVCj/+0bT/NvdmOWOVbJVjUVxWPX33B6rfWyYp5RSv8fw0KfpnhyKUFwf6r
         6LCQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUqSbSQJI/3PE2JRgnKNBE6r1kgia0ih3JO30nInugRQYckoADdGVIeegNzSc5BpKyz3ckaFg==@lfdr.de
X-Gm-Message-State: AOJu0YwYZrjrm7Dv04t8tb0xPNNKD59c1k9e+1Xht44OIZvr+vHI3qsM
	gE7NnGqcCP9CzM6lbIYMv8XfGVxqZOusbVKb+f4h/C2Hs407rV1j
X-Google-Smtp-Source: AGHT+IHDq4lscw4TJR+noSNBUARsI2NxgVzKScdw9zQn1P0c1ZyJmeBTHrcWlvrEJUhnK0JOpIwSFQ==
X-Received: by 2002:a05:6870:3508:b0:29e:2704:6216 with SMTP id 586e51a60fabf-2b8d68c8b21mr1341027fac.36.1739339862446;
        Tue, 11 Feb 2025 21:57:42 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVFqlsfZiQYyleypk1LzKygEGu1iDB9Iw1SRsDwCpN5nXQ==
Received: by 2002:a05:6870:1d0c:b0:2a9:5c2a:c3b8 with SMTP id
 586e51a60fabf-2b83e0c5ad1ls1721220fac.0.-pod-prod-02-us; Tue, 11 Feb 2025
 21:57:41 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUz1ePED3AU/b/m5Q9q1qGQRS+8xZ/sPCeUzEsZgnGKp2tECzoWYJG9QxwBd9Wz/3UkS//Ef/zykoY=@googlegroups.com
X-Received: by 2002:a05:6870:c191:b0:296:e46a:6e5e with SMTP id 586e51a60fabf-2b8d658a32emr1198381fac.21.1739339861624;
        Tue, 11 Feb 2025 21:57:41 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1739339861; cv=none;
        d=google.com; s=arc-20240605;
        b=MzsvzqKjc5rXMXKSyXauTrweoSyjjWJNGDnsGTNWn9RFgM+f3T4aQppuZDxvZbp1vx
         HhSjvnUMxysdxzYdV76D7KTorCsUiFEDFlTnql0CK+7bMKQWnbNj8YCbG7n48dJ/lVS8
         c9GyS19tKxU8MAfmmNjHvfpNIpFyL41uYGjO1L/yCxcu+XfA73ouZn6Z1THOEl6TWQTd
         p7CJU06Nni0KS8cpbIZn/LIDIvm5wntx6RyMpisqtxB1TuD+WISyrxtyMltJCXKaTp/3
         tHpQvC2R45NOM0NdtG9CBYium6Yb7TntA0ReYx0such6iAxTPEpvl6wbhIGEam9m3zrx
         seag==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:feedback-id:dkim-signature;
        bh=eBCiVpUQxmyhbDltoFsuEwDS/2Q9oN0bzv5AHCnlEZs=;
        fh=qlKXrkLuvdWkSQrbmiI3OUAfwsJ/WC1+I3f18Afie+0=;
        b=GZ1MonRQKkmM564KdRbJCdTWMW945xe5uGdwMYICYBXLM5Do4ZqDwaPtUg827ea2hL
         EopZHDdos+qKtcPQhn2NZ82KxZPJB8kUORMIF0IPNQAeAbUwENeYoLDUS8DeasNu1Wnc
         C1DaNbMC2neOjLn6rioZFhLPkehtQOP+CACijJMJe6M3qDjzoZt/jW6D/xpNt4dZLMCU
         466zmuXgJLxHo92LMZM+OUYhJa6jwbebZKtses6uX50604lZp+Pln3GVKMHe93kum5SS
         OM8C6bzHHk9SToZCwnv1dZLIMixug2mZQn8G5Vr/N7cuuxI7j7YuC7tP6L/fVEbdyV34
         9FMw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=HQj2HR45;
       spf=pass (google.com: domain of boqun.feng@gmail.com designates 2607:f8b0:4864:20::f34 as permitted sender) smtp.mailfrom=boqun.feng@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qv1-xf34.google.com (mail-qv1-xf34.google.com. [2607:f8b0:4864:20::f34])
        by gmr-mx.google.com with ESMTPS id 586e51a60fabf-2b8262d5957si513653fac.5.2025.02.11.21.57.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 11 Feb 2025 21:57:41 -0800 (PST)
Received-SPF: pass (google.com: domain of boqun.feng@gmail.com designates 2607:f8b0:4864:20::f34 as permitted sender) client-ip=2607:f8b0:4864:20::f34;
Received: by mail-qv1-xf34.google.com with SMTP id 6a1803df08f44-6e432beabbdso48316266d6.3
        for <kasan-dev@googlegroups.com>; Tue, 11 Feb 2025 21:57:41 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCUBFYIpa+FMHZMatRKR7zCj3Ecb2Xnkdv1XZEn1b2VfQ5vDLBqB2oFnon+4tENWGfU8bBwr7nUuDEk=@googlegroups.com
X-Gm-Gg: ASbGncukFwlf0kgl80q7X42xT3VHBngXdLDbjrKffv/ff4Kz81dzgN9fKC6/gdMvpKW
	6kZJUYreXbbrf1JZbyCvdmjsdGMsnqAGnnzYvfIzPgZwIykaN8V5CZWuU5K1yVHC4jbwjLkhXD1
	XhCzJ16415fzss0xz1KbY0lLlF1axC2lYfDXhZ9hkS7wTEaLvoomZf97DQ5WhxbWeFxKrKwgF1U
	PSHA/Xq1+v61/jxdeuvRzPX+N8xGdyukPHVwnBOX56pcnoBk/yqw2ReMK51aMwWLaRUDZ0ndMZ4
	1jdaueacU0Ag9uLF82fcDBuBemxbSMDMc5K5eqrzVZZ8Q4UBnmHTBW7LcGRHp7LQOxAPVTVaCnA
	JZDiImA==
X-Received: by 2002:a05:6214:d6e:b0:6d8:8b9d:1502 with SMTP id 6a1803df08f44-6e46edaba55mr33637816d6.30.1739339860920;
        Tue, 11 Feb 2025 21:57:40 -0800 (PST)
Received: from fauth-a2-smtp.messagingengine.com (fauth-a2-smtp.messagingengine.com. [103.168.172.201])
        by smtp.gmail.com with ESMTPSA id 6a1803df08f44-6e4556d153asm50548926d6.13.2025.02.11.21.57.40
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 11 Feb 2025 21:57:40 -0800 (PST)
Received: from phl-compute-09.internal (phl-compute-09.phl.internal [10.202.2.49])
	by mailfauth.phl.internal (Postfix) with ESMTP id 18B591200043;
	Wed, 12 Feb 2025 00:57:40 -0500 (EST)
Received: from phl-mailfrontend-01 ([10.202.2.162])
  by phl-compute-09.internal (MEProxy); Wed, 12 Feb 2025 00:57:40 -0500
X-ME-Sender: <xms:UzisZ8Xk12b_23q3PfWvWu3GQlRksxhDz5jbkBmlLuF1WlJNH5zPfg>
    <xme:UzisZwmCB8WxgfYLOrLDjv2fF2AixKcxr7t-0gTEgIyO6BAYB2jHswYIvbn3BcJC7
    IBntUNogXJ7odJjlg>
X-ME-Received: <xmr:UzisZwbMskjtY7BNyxxiItZfxNcLDJsjZn-Li7TP7ocos8hM2C-Y7NTJ5w>
X-ME-Proxy-Cause: gggruggvucftvghtrhhoucdtuddrgeefvddrtddtgdegfedtlecutefuodetggdotefrod
    ftvfcurfhrohhfihhlvgemucfhrghsthforghilhdpggftfghnshhusghstghrihgsvgdp
    uffrtefokffrpgfnqfghnecuuegrihhlohhuthemuceftddtnecusecvtfgvtghiphhivg
    hnthhsucdlqddutddtmdenucfjughrpeffhffvvefukfhfgggtuggjsehttdertddttddv
    necuhfhrohhmpeeuohhquhhnucfhvghnghcuoegsohhquhhnrdhfvghnghesghhmrghilh
    drtghomheqnecuggftrfgrthhtvghrnhephedugfduffffteeutddvheeuveelvdfhleel
    ieevtdeguefhgeeuveeiudffiedvnecuvehluhhsthgvrhfuihiivgeptdenucfrrghrrg
    hmpehmrghilhhfrhhomhepsghoqhhunhdomhgvshhmthhprghuthhhphgvrhhsohhnrghl
    ihhthidqieelvdeghedtieegqddujeejkeehheehvddqsghoqhhunhdrfhgvnhhgpeepgh
    hmrghilhdrtghomhesfhhigihmvgdrnhgrmhgvpdhnsggprhgtphhtthhopeduvddpmhho
    uggvpehsmhhtphhouhhtpdhrtghpthhtoheplhhonhhgmhgrnhesrhgvughhrghtrdgtoh
    hmpdhrtghpthhtohepphgvthgvrhiisehinhhfrhgruggvrggurdhorhhgpdhrtghpthht
    ohepmhhinhhgohesrhgvughhrghtrdgtohhmpdhrtghpthhtohepfihilhhlrdguvggrtg
    honhesrghrmhdrtghomhdprhgtphhtthhopehlihhnuhigqdhkvghrnhgvlhesvhhgvghr
    rdhkvghrnhgvlhdrohhrghdprhgtphhtthhopehrhigrsghinhhinhdrrgdrrgesghhmrg
    hilhdrtghomhdprhgtphhtthhopehglhhiuggvrhesghhoohhglhgvrdgtohhmpdhrtghp
    thhtoheprghnughrvgihkhhnvhhlsehgmhgrihhlrdgtohhmpdhrtghpthhtohepughvhi
    hukhhovhesghhoohhglhgvrdgtohhm
X-ME-Proxy: <xmx:UzisZ7Wu2SUeaPL_YS52-7TJH82ULURBqq5nAyQwBrVTdaOJZxPsPg>
    <xmx:VDisZ2nFxfFZwKAhJiUg3Flu0hOoWzyTVRNq2qzSuZ1pePoJccypGA>
    <xmx:VDisZwcARCzB61ftBWyMmbKEpl8lYq9S2fdchTOhStIDMvd4CbBjrg>
    <xmx:VDisZ4HeC3yOM-032aEndsvwEF19VCk_K2RkkHmYUPo6ECd0yflUlA>
    <xmx:VDisZ8lvkoDyjrSj8HldPRqLrtN4lZj6JJmENSpnyX0S3tsn4WZxDGwL>
Feedback-ID: iad51458e:Fastmail
Received: by mail.messagingengine.com (Postfix) with ESMTPA; Wed,
 12 Feb 2025 00:57:39 -0500 (EST)
Date: Tue, 11 Feb 2025 21:57:38 -0800
From: Boqun Feng <boqun.feng@gmail.com>
To: Waiman Long <longman@redhat.com>
Cc: Peter Zijlstra <peterz@infradead.org>, Ingo Molnar <mingo@redhat.com>,
	Will Deacon <will.deacon@arm.com>, linux-kernel@vger.kernel.org,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	kasan-dev@googlegroups.com
Subject: Re: [PATCH v3 3/3] locking/lockdep: Disable KASAN instrumentation of
 lockdep.c
Message-ID: <Z6w4UlCQa_g1OHlN@Mac.home>
References: <20250210042612.978247-1-longman@redhat.com>
 <20250210042612.978247-4-longman@redhat.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250210042612.978247-4-longman@redhat.com>
X-Original-Sender: boqun.feng@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=HQj2HR45;       spf=pass
 (google.com: domain of boqun.feng@gmail.com designates 2607:f8b0:4864:20::f34
 as permitted sender) smtp.mailfrom=boqun.feng@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
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

[Cc KASAN]

A Reviewed-by or Acked-by from KASAN would be nice, thanks!

Regards,
Boqun

On Sun, Feb 09, 2025 at 11:26:12PM -0500, Waiman Long wrote:
> Both KASAN and LOCKDEP are commonly enabled in building a debug kernel.
> Each of them can significantly slow down the speed of a debug kernel.
> Enabling KASAN instrumentation of the LOCKDEP code will further slow
> thing down.
> 
> Since LOCKDEP is a high overhead debugging tool, it will never get
> enabled in a production kernel. The LOCKDEP code is also pretty mature
> and is unlikely to get major changes. There is also a possibility of
> recursion similar to KCSAN.
> 
> To evaluate the performance impact of disabling KASAN instrumentation
> of lockdep.c, the time to do a parallel build of the Linux defconfig
> kernel was used as the benchmark. Two x86-64 systems (Skylake & Zen 2)
> and an arm64 system were used as test beds. Two sets of non-RT and RT
> kernels with similar configurations except mainly CONFIG_PREEMPT_RT
> were used for evaulation.
> 
> For the Skylake system:
> 
>   Kernel			Run time	    Sys time
>   ------			--------	    --------
>   Non-debug kernel (baseline)	0m47.642s	      4m19.811s
>   Debug kernel			2m11.108s (x2.8)     38m20.467s (x8.9)
>   Debug kernel (patched)	1m49.602s (x2.3)     31m28.501s (x7.3)
>   Debug kernel
>   (patched + mitigations=off) 	1m30.988s (x1.9)     26m41.993s (x6.2)
> 
>   RT kernel (baseline)		0m54.871s	      7m15.340s
>   RT debug kernel		6m07.151s (x6.7)    135m47.428s (x18.7)
>   RT debug kernel (patched)	3m42.434s (x4.1)     74m51.636s (x10.3)
>   RT debug kernel
>   (patched + mitigations=off) 	2m40.383s (x2.9)     57m54.369s (x8.0)
> 
> For the Zen 2 system:
> 
>   Kernel			Run time	    Sys time
>   ------			--------	    --------
>   Non-debug kernel (baseline)	1m42.806s	     39m48.714s
>   Debug kernel			4m04.524s (x2.4)    125m35.904s (x3.2)
>   Debug kernel (patched)	3m56.241s (x2.3)    127m22.378s (x3.2)
>   Debug kernel
>   (patched + mitigations=off) 	2m38.157s (x1.5)     92m35.680s (x2.3)
> 
>   RT kernel (baseline)		 1m51.500s	     14m56.322s
>   RT debug kernel		16m04.962s (x8.7)   244m36.463s (x16.4)
>   RT debug kernel (patched)	 9m09.073s (x4.9)   129m28.439s (x8.7)
>   RT debug kernel
>   (patched + mitigations=off) 	 3m31.662s (x1.9)    51m01.391s (x3.4)
> 
> For the arm64 system:
> 
>   Kernel			Run time	    Sys time
>   ------			--------	    --------
>   Non-debug kernel (baseline)	1m56.844s	      8m47.150s
>   Debug kernel			3m54.774s (x2.0)     92m30.098s (x10.5)
>   Debug kernel (patched)	3m32.429s (x1.8)     77m40.779s (x8.8)
> 
>   RT kernel (baseline)		 4m01.641s	     18m16.777s
>   RT debug kernel		19m32.977s (x4.9)   304m23.965s (x16.7)
>   RT debug kernel (patched)	16m28.354s (x4.1)   234m18.149s (x12.8)
> 
> Turning the mitigations off doesn't seems to have any noticeable impact
> on the performance of the arm64 system. So the mitigation=off entries
> aren't included.
> 
> For the x86 CPUs, cpu mitigations has a much bigger impact on
> performance, especially the RT debug kernel. The SRSO mitigation in
> Zen 2 has an especially big impact on the debug kernel. It is also the
> majority of the slowdown with mitigations on. It is because the patched
> ret instruction slows down function returns. A lot of helper functions
> that are normally compiled out or inlined may become real function
> calls in the debug kernel. The KASAN instrumentation inserts a lot
> of __asan_loadX*() and __kasan_check_read() function calls to memory
> access portion of the code. The lockdep's __lock_acquire() function,
> for instance, has 66 __asan_loadX*() and 6 __kasan_check_read() calls
> added with KASAN instrumentation. Of course, the actual numbers may vary
> depending on the compiler used and the exact version of the lockdep code.
> 
> With the newly added rtmutex and lockdep lock events, the relevant
> event counts for the test runs with the Skylake system were:
> 
>   Event type		Debug kernel	RT debug kernel
>   ----------		------------	---------------
>   lockdep_acquire	1,968,663,277	5,425,313,953
>   rtlock_slowlock	     -		  401,701,156
>   rtmutex_slowlock	     -		      139,672
> 
> The __lock_acquire() calls in the RT debug kernel are x2.8 times of the
> non-RT debug kernel with the same workload. Since the __lock_acquire()
> function is a big hitter in term of performance slowdown, this makes
> the RT debug kernel much slower than the non-RT one. The average lock
> nesting depth is likely to be higher in the RT debug kernel too leading
> to longer execution time in the __lock_acquire() function.
> 
> As the small advantage of enabling KASAN instrumentation to catch
> potential memory access error in the lockdep debugging tool is probably
> not worth the drawback of further slowing down a debug kernel, disable
> KASAN instrumentation in the lockdep code to allow the debug kernels
> to regain some performance back, especially for the RT debug kernels.
> 
> Signed-off-by: Waiman Long <longman@redhat.com>
> ---
>  kernel/locking/Makefile | 3 ++-
>  1 file changed, 2 insertions(+), 1 deletion(-)
> 
> diff --git a/kernel/locking/Makefile b/kernel/locking/Makefile
> index 0db4093d17b8..a114949eeed5 100644
> --- a/kernel/locking/Makefile
> +++ b/kernel/locking/Makefile
> @@ -5,7 +5,8 @@ KCOV_INSTRUMENT		:= n
>  
>  obj-y += mutex.o semaphore.o rwsem.o percpu-rwsem.o
>  
> -# Avoid recursion lockdep -> sanitizer -> ... -> lockdep.
> +# Avoid recursion lockdep -> sanitizer -> ... -> lockdep & improve performance.
> +KASAN_SANITIZE_lockdep.o := n
>  KCSAN_SANITIZE_lockdep.o := n
>  
>  ifdef CONFIG_FUNCTION_TRACER
> -- 
> 2.48.1
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/Z6w4UlCQa_g1OHlN%40Mac.home.
