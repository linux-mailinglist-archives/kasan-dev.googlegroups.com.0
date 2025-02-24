Return-Path: <kasan-dev+bncBC6LHPWNU4DBBYVK566QMGQESNMDK5I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3b.google.com (mail-oo1-xc3b.google.com [IPv6:2607:f8b0:4864:20::c3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 48363A41334
	for <lists+kasan-dev@lfdr.de>; Mon, 24 Feb 2025 03:11:48 +0100 (CET)
Received: by mail-oo1-xc3b.google.com with SMTP id 006d021491bc7-5fce3f2d8e4sf1753601eaf.0
        for <lists+kasan-dev@lfdr.de>; Sun, 23 Feb 2025 18:11:48 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1740363106; cv=pass;
        d=google.com; s=arc-20240605;
        b=DieMEeK3gzDEsu+SYEFnScn91bAYf/+vsL87ZmO9t6XPxpXXZBDuFN9fimbLprLCLm
         EomPDUDtsPKJ2oiEYZUX9ISlYAsKiQYEMSJU1IINjX4ZMHfcixvnLj19VyluSQwdy+Ur
         2xdzRBKk5xwrAFnoR07zbCjwakzvqORkf4EQsVnMXQB3WBBz7l0GJMt882eizmntnQc2
         7nTN7XofudIxRxWPlXEfUbi3j+0eljmzKIGyqTiHslwkSnfN+deiM7OHRUo2trpv3dpW
         f1mIQFnMiL8ZTkATFizQykkda+IWH4IHnj6DDWEG7Q7v0JoRReqHR/87bLtFj8YMk/KZ
         5qrw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :feedback-id:sender:dkim-signature:dkim-signature;
        bh=qZ3rEnHJCbPka5nvN4pGCeNDe2uOtLyYJqC83/kgl40=;
        fh=p5A0w98QJFfJwSChXxFr2VuSO2XbE1RXCqZ38VEIiZE=;
        b=O9fZ5TVYvU/AbwvlWaZhbhh82r47CsS5xg/5pOLWQbEcIVFkXfr3P733KDEL8qNo3L
         s+Et5uS9P7nxpey+fvg/fzRMsFgRPuYJmPwvahvSUvPhsOBi4QQWwCDpAAUrXauFpSGn
         OyLgozofZS1saIoZsrbEVlkXop2V84/hfE3ghkDU52Vv6UJhA96BWOJxZnqjfYNmabaO
         CloncNV88YjdQenbz8KYy7BgAGjUKQBOsNFjx9IyZ62CWZJjM3aNTPHXZHFRyRYhTIjo
         b3hK2lKw7IZeIh3TCkhG+jXh5HH81ZL7WHqXzaSX1krOp9EVjIf04zneVVkVjw+RtTHb
         rmRw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=CPuGYEZi;
       spf=pass (google.com: domain of boqun.feng@gmail.com designates 2607:f8b0:4864:20::72e as permitted sender) smtp.mailfrom=boqun.feng@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1740363106; x=1740967906; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:feedback-id:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=qZ3rEnHJCbPka5nvN4pGCeNDe2uOtLyYJqC83/kgl40=;
        b=iLz+tkPKlEdhF80P0Io5pPl79SSdCyFztQBRtAh/1p5ayvv4ZSSwE89NfiCn6MLmnc
         AeQtHIa3j6WETus5Ki2Ep4mTaggCr2iLWrfT/w6xaIkOOGnR7nKCwizP9Mh4+v81GFlh
         OhUKeiALy5zqYNXnOnU41N+7UW1EYWcciRAhNiV003BSVFurkd3/WklnMXwHjsjD/s+U
         OG05qQliHzJZ5dU/L98u+TcsZgxTda1clqj4eTwMbpNc5+HS95eUGoJsN4r0PvRLiBCu
         wPVkN3LLBxnXExuzcBFIFfanogVXCp1+lN/PffHfd84M57bX+pVLPpJ9RHgr2Ax8FalU
         Hb6g==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1740363106; x=1740967906; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:feedback-id:from:to
         :cc:subject:date:message-id:reply-to;
        bh=qZ3rEnHJCbPka5nvN4pGCeNDe2uOtLyYJqC83/kgl40=;
        b=ZhBTyfYlIggUoo1z2pal0+YlWRnH/Ho3rR9SV0JFXqMzOyJZxwrObId0WpX0OE5ObL
         rpRUPuCTy+fXwehUuTPWRwmLxdWG85tTcU+lRA+0rAYr9d4XSG7N1Esl/q5dUkcMXOjm
         kEIHWiWKvqV63Dt1QtCPlkuo1cLjUcRWgKDdwAjxOC7iItHlIt9XjxZodFlYqwB/+9Vw
         rLxzrBB/yi7C2UIVOqg6ayFg9JxrhbZDdfIC9tX344HIXLOupWIm0Gwmgs5/KvbTWpBz
         K5h0mwt25iTjS2phoBJefhSHX8US3mg6FogSTSjui2+sY/8XVzACEI/LWdNE1Ln3mM77
         AYwA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1740363106; x=1740967906;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:feedback-id:x-beenthere:x-gm-message-state:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=qZ3rEnHJCbPka5nvN4pGCeNDe2uOtLyYJqC83/kgl40=;
        b=OdC1XXdQw4vKDl/Y3ac0An/J5lBL+JHCi74bMYJSy0UuzSIHgNXBM46ORermfQgvqn
         QllkLvOyjdRRsC1JVezWX0WAZ3NSDnVt82E5rCQ7vlsOrDGN/mNJPYc1EuiwEI2Jcc1c
         PZWz4/E8Sdc9YA/KJP4W+SQCIGOS72rQ26y8Xx+XIwjiaRYqpWRg5L22lHEqEAaXdiXQ
         Mez/PocLFQqIsfguuEUC0WpA1uzrjjY10HaohYBQB7CgzBcSWTqL4Y8tKAbfq/zejCYd
         5CawSKzqX3uWq7b/V5HHutJoGvZsmoziRCmFbSyG0f4KaMOBkAcQbdRUlP7DYwTXe2xR
         UV5g==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCV9HyWjcT+W3oguhbGXjIZz5fQ0CghnI5OTvAB/ORf9jvgdfgAzU0PC2b+E5WVIuLh0Vqz/cQ==@lfdr.de
X-Gm-Message-State: AOJu0YxFDWUFO7xGxhOyBsRbEQEt5HnnAfrMMXaJIx8wEjtW+HIOeNpT
	GmkKRjf95tkZnREZvejKrrF0tPF4uGwigx6vcR0al6iTG4Tj8DPT
X-Google-Smtp-Source: AGHT+IFYHT7n/6r+gX7Sac7BleIcAWza2uVrtZy0R1PSeEvaxTSC0XP3IURMwVIgABKFFeF1uCISrA==
X-Received: by 2002:a05:6871:3a08:b0:2b8:3d1c:772 with SMTP id 586e51a60fabf-2bd5151441amr8617456fac.5.1740363106384;
        Sun, 23 Feb 2025 18:11:46 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVE0JFa9ybqoYiiBYvII/8nhkE8m+xJnEDRnRLz4q3CwVw==
Received: by 2002:a05:6870:6388:b0:29d:e970:3ca4 with SMTP id
 586e51a60fabf-2bd50b53477ls389636fac.1.-pod-prod-02-us; Sun, 23 Feb 2025
 18:11:45 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVHFjB/40Yj/xiyp+QDAXPfS+F2rHu2O88NLbslwkwD1oxiN+c0Mxuiz2Cr/s6lCSnTvBb2W1yCbWA=@googlegroups.com
X-Received: by 2002:a05:6808:1899:b0:3f4:117c:4d57 with SMTP id 5614622812f47-3f425c01d0cmr6315329b6e.33.1740363105688;
        Sun, 23 Feb 2025 18:11:45 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1740363105; cv=none;
        d=google.com; s=arc-20240605;
        b=D5kNZ/iyCxBevISl7IZxDofdpw9R9pZb+QZLuRyLGr+SnfqZaaTMNLNZUJOIFpqzyz
         RwLHnKnRkQKjiX+a/XVGqKGs4l9vwxRXMHpfQMf/T6jb5uHskAkMhccyG8N8v4m0b7ea
         CzGVtWoQWCP8MjC75VLBdsDeRRI/0w4L4cd9P3iy6cM1Oy+MlZ6im6RXankZo9bGixYk
         DXlG3Cpi/kJfVYlk4feqgAYYTrDvqnsv1l7qzRzXbqTsCFJYtcuAsyx1vFFTCjgB5042
         1eayr2rjrL++X+Lvny/0bUhDXCZ58zGrgpkQ/xag0YOB+IaUR9LHZkrcA+WGAWMr4Ye1
         X6Nw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:feedback-id:dkim-signature;
        bh=WRPOTUWvKIwPCoGVuzKX18gR/kJ5CZNtCyu7DNmFy0U=;
        fh=lD7abhxtfw5es3eXmRHD1KyX56YmL229X7XzsPNf/A4=;
        b=TsNVdebEzg8XxkSCO5+rFpmIlqKXg2IdCwqcijaUxnSx2Jw+SIs8eDCOB1IlACf9f3
         pj1VL/umfMFkyLLiTXT8mOU2ppBFYElJ1eYQ/wNmxmlETBCSp5DVmL9d1RJW6ubX+AQ3
         eRJK3AcVqzJpJO2OMOpPGhJJLAR0sewtTGesj9wK3C3MLEobJIh9+5Cy5/EvW/Lpg3h3
         x1zbi96t99OT3/PasqubCYmoWrN88fJHbyPOGXg6J9OWNeQgUI3zCNTvRSe2tOcWffU3
         5Z7L/Iyv3hkC8B/0ssUAoxdrxluY/UBJzXGMHu1OJgOhqgh9HQC4LUVaJhSKDY6b1O9J
         T7xw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=CPuGYEZi;
       spf=pass (google.com: domain of boqun.feng@gmail.com designates 2607:f8b0:4864:20::72e as permitted sender) smtp.mailfrom=boqun.feng@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qk1-x72e.google.com (mail-qk1-x72e.google.com. [2607:f8b0:4864:20::72e])
        by gmr-mx.google.com with ESMTPS id 5614622812f47-3f404919c20si780345b6e.1.2025.02.23.18.11.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 23 Feb 2025 18:11:45 -0800 (PST)
Received-SPF: pass (google.com: domain of boqun.feng@gmail.com designates 2607:f8b0:4864:20::72e as permitted sender) client-ip=2607:f8b0:4864:20::72e;
Received: by mail-qk1-x72e.google.com with SMTP id af79cd13be357-7c0818add57so410996885a.3
        for <kasan-dev@googlegroups.com>; Sun, 23 Feb 2025 18:11:45 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCUT8Jfk7Bp9lebc3EhPXWSSzCAcYcxLg8DSnZYiqeeksDq9frjF1xsK7CQICZIPUwwjNcPq0wpFvLQ=@googlegroups.com
X-Gm-Gg: ASbGncuGJqyBAks067l53aUCyteFNYT/uDmr8awQ7D5tNCesck7FmIsl1sTFzx6/2eK
	8YZgMTyUtqwxoKKEUaFSVww/6XYEY/oqQYhMxWwsA1oYgEz2z6y0QhGEGb1P4jii/G4616L5VsH
	AbuAJ2LlvTceawUdILaspsJz4eCejoi0Ni4c7zxdGoW8/lHhmqa/GR6hJhzZEs0rdeFPFbKMAXn
	GpnaUXlrgk+RNqLnGR2Cw1RXBcMUShNkkBHk3NUBycO56ztif0wn+iAVwKhiKDjGembQ3+e4h8/
	Q5gGR1R+kbS9057baYNCk+RhIggQEfQnJUruDGfsQNy2Y8mQ/QmCymWp/sef9RiAiFsVgaNPfvF
	z0RiJI6WSrrQvjy8P
X-Received: by 2002:a05:620a:880f:b0:7c0:b685:1bba with SMTP id af79cd13be357-7c0cf8cd09fmr1348896985a.19.1740363105102;
        Sun, 23 Feb 2025 18:11:45 -0800 (PST)
Received: from fauth-a2-smtp.messagingengine.com (fauth-a2-smtp.messagingengine.com. [103.168.172.201])
        by smtp.gmail.com with ESMTPSA id af79cd13be357-7c0a0baa1e9sm926472085a.72.2025.02.23.18.11.44
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sun, 23 Feb 2025 18:11:44 -0800 (PST)
Received: from phl-compute-08.internal (phl-compute-08.phl.internal [10.202.2.48])
	by mailfauth.phl.internal (Postfix) with ESMTP id 162E91200043;
	Sun, 23 Feb 2025 21:11:44 -0500 (EST)
Received: from phl-mailfrontend-02 ([10.202.2.163])
  by phl-compute-08.internal (MEProxy); Sun, 23 Feb 2025 21:11:44 -0500
X-ME-Sender: <xms:X9W7Z3UAvg6V_C-cunSlU-n_XMJ8mBERNuwUkbqbGlwUElZjftkzcg>
    <xme:X9W7Z_lrISUdSZL0qnw_icLlEoXy1n7LTeMep-4W8fRgsflGGH7zpfUW9haJJNJO-
    g0kfAaAsrrRgmfX1Q>
X-ME-Received: <xmr:X9W7ZzYHKUW_iKrEuPRmfC4O12ICYGmSJq14MKpx8GE9xIC_qUphn-9Mkw>
X-ME-Proxy-Cause: gggruggvucftvghtrhhoucdtuddrgeefvddrtddtgdejjeehudcutefuodetggdotefrod
    ftvfcurfhrohhfihhlvgemucfhrghsthforghilhdpggftfghnshhusghstghrihgsvgdp
    uffrtefokffrpgfnqfghnecuuegrihhlohhuthemuceftddtnecusecvtfgvtghiphhivg
    hnthhsucdlqddutddtmdenucfjughrpeffhffvvefukfhfgggtuggjsehttdertddttddv
    necuhfhrohhmpeeuohhquhhnucfhvghnghcuoegsohhquhhnrdhfvghnghesghhmrghilh
    drtghomheqnecuggftrfgrthhtvghrnhephedugfduffffteeutddvheeuveelvdfhleel
    ieevtdeguefhgeeuveeiudffiedvnecuvehluhhsthgvrhfuihiivgeptdenucfrrghrrg
    hmpehmrghilhhfrhhomhepsghoqhhunhdomhgvshhmthhprghuthhhphgvrhhsohhnrghl
    ihhthidqieelvdeghedtieegqddujeejkeehheehvddqsghoqhhunhdrfhgvnhhgpeepgh
    hmrghilhdrtghomhesfhhigihmvgdrnhgrmhgvpdhnsggprhgtphhtthhopedufedpmhho
    uggvpehsmhhtphhouhhtpdhrtghpthhtoheplhhonhhgmhgrnhesrhgvughhrghtrdgtoh
    hmpdhrtghpthhtohepphgvthgvrhiisehinhhfrhgruggvrggurdhorhhgpdhrtghpthht
    ohepmhhinhhgohesrhgvughhrghtrdgtohhmpdhrtghpthhtohepfihilhhlrdguvggrtg
    honhesrghrmhdrtghomhdprhgtphhtthhopehrhigrsghinhhinhdrrgdrrgesghhmrghi
    lhdrtghomhdprhgtphhtthhopehglhhiuggvrhesghhoohhglhgvrdgtohhmpdhrtghpth
    htoheprghnughrvgihkhhnvhhlsehgmhgrihhlrdgtohhmpdhrtghpthhtohepughvhihu
    khhovhesghhoohhglhgvrdgtohhmpdhrtghpthhtohepvhhinhgtvghniihordhfrhgrsh
    gtihhnohesrghrmhdrtghomh
X-ME-Proxy: <xmx:X9W7ZyUCng1HEuw-GNoc3czs40Ks7UN5ZLLzzk3QweDoprnaOEtU5A>
    <xmx:YNW7Zxnskw4Il1NOtmxTZqPiFXYJeA-JWmKW4i9DVvaoC-s44aZIww>
    <xmx:YNW7Z_eYDPGWBVe2PrN7HN1uWv4p0P5mekFFXymDq_g-pi1iMzzAfg>
    <xmx:YNW7Z7GcHJxpTZQYZP5EuZGKC25FNhj3dFpUs1XWIh-T4zMlZ4UYLQ>
    <xmx:YNW7ZzmK0ibO6cW1pE_lH4wWNlrFHhl6tk0HlOxyBRbckn84GsaRVEuv>
Feedback-ID: iad51458e:Fastmail
Received: by mail.messagingengine.com (Postfix) with ESMTPA; Sun,
 23 Feb 2025 21:11:43 -0500 (EST)
Date: Sun, 23 Feb 2025 18:11:42 -0800
From: Boqun Feng <boqun.feng@gmail.com>
To: Waiman Long <longman@redhat.com>
Cc: Peter Zijlstra <peterz@infradead.org>, Ingo Molnar <mingo@redhat.com>,
	Will Deacon <will.deacon@arm.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Marco Elver <elver@google.com>, linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com
Subject: Re: [PATCH v4 0/4] locking/lockdep: Disable KASAN instrumentation of
 lockdep.c
Message-ID: <Z7vVXs7F1re40KRX@Mac.home>
References: <20250213200228.1993588-1-longman@redhat.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250213200228.1993588-1-longman@redhat.com>
X-Original-Sender: boqun.feng@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=CPuGYEZi;       spf=pass
 (google.com: domain of boqun.feng@gmail.com designates 2607:f8b0:4864:20::72e
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

On Thu, Feb 13, 2025 at 03:02:24PM -0500, Waiman Long wrote:
>  v3: 
>   - Add another patch to insert lock events into lockdep.c.
>   - Rerun all the tests with the simpler defconfig kernel build and do
>     further analysis of the of the performance difference between the
>     the RT and non-RT debug kernels.
> 
>  v4:
>   - Update test results in patch 3 after incorporating CONFIG_KASAN_INLINE
>     into the test matrix.
>   - Add patch 4 to call kasan_check_byte() in lock_acquire.
> 
> It is found that disabling KASAN instrumentation when compiling
> lockdep.c can significantly improve the performance of RT debug kernel
> while the performance benefit of non-RT debug kernel is relatively
> modest.
> 
> This series also include patches to add locking events to the rtmutex
> slow paths and the lockdep code for better analysis of the different
> performance behavior between RT and non-RT debug kernels.
> 

Thank you, and thank Marco and Andrey for the reviews. Queued for v6.15.

Regards,
Boqun

> Waiman Long (4):
>   locking/lock_events: Add locking events for rtmutex slow paths
>   locking/lock_events: Add locking events for lockdep
>   locking/lockdep: Disable KASAN instrumentation of lockdep.c
>   locking/lockdep: Add kasan_check_byte() check in lock_acquire()
> 
>  kernel/locking/Makefile           |  3 ++-
>  kernel/locking/lock_events_list.h | 29 +++++++++++++++++++++++++++++
>  kernel/locking/lockdep.c          | 22 +++++++++++++++++++++-
>  kernel/locking/rtmutex.c          | 29 ++++++++++++++++++++++++-----
>  4 files changed, 76 insertions(+), 7 deletions(-)
> 
> -- 
> 2.48.1
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/Z7vVXs7F1re40KRX%40Mac.home.
