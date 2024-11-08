Return-Path: <kasan-dev+bncBC6LHPWNU4DBBY44XG4QMGQEJ4TM4SI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103b.google.com (mail-pj1-x103b.google.com [IPv6:2607:f8b0:4864:20::103b])
	by mail.lfdr.de (Postfix) with ESMTPS id 0C7C59C23E0
	for <lists+kasan-dev@lfdr.de>; Fri,  8 Nov 2024 18:46:14 +0100 (CET)
Received: by mail-pj1-x103b.google.com with SMTP id 98e67ed59e1d1-2e2d396c77fsf2684646a91.2
        for <lists+kasan-dev@lfdr.de>; Fri, 08 Nov 2024 09:46:13 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1731087972; cv=pass;
        d=google.com; s=arc-20240605;
        b=kHARoc/et4MqLoUuWWgnxJ0e971TsgH+8qus0tvzjvqFnjuH3J0vFruJtgfaEf9+wg
         XrrYhegsJko6r2dIM18QtZq69oH24BYtgHHvUfaSdhNqKspRbOkiivqLuNekgSZW9cB5
         mj0lluL/5/VRZ7P2ZOBm9YSbZeCQAhgwpYKXzcHx02hRJ4Dgo0SxLyKFB1zhretVbgCG
         pVyjiv6aMiIqMZ9PnB1KH9WGg9vX5e1baO6GfW6Vee7KI6mGE7N1ZNdiqy8FlaNJ1LT2
         iYrzWkydKlGaneZwdQeOjt9FaaJu62h9fqiRNWB6B43adbbIZvtXtHgTwoe+snv46630
         8ZQQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :feedback-id:sender:dkim-signature:dkim-signature;
        bh=oWkI2KWvNkMuVO6SRiPPlt7Pp0WQ5h40/fQjVoaIm98=;
        fh=YTcmhI39GOABmVuYJN3BrydJ6k3NFTkXhO+dCCivJp0=;
        b=YvNuELxrxBKSo9cWZTBK4WKSsRX20wtqQm6B5iMcRcvV+/e9PwgkNrLod5XzrIjnCp
         /332TpDunizXggYlNqqWsXVAJPRLbCCpssmc/X/KTy0dUUgYhJngBpM4eCZf5BvJ4/40
         UczglWNBSMJfOKTMcOTYuVfpXc/Z9UbX13D8R7eAJcCMnchJbQ2d7/k4u0DSjKNPRmfW
         sIIwU06Ieyc5CXSsOxNk8L/7nKqFNMhO2N207eyvyO7jsdXu+yYE1stJOgYmUhBS+id2
         gK4JlGs+MtV1hIXA3SFqXttRqmGjvyfOi+q1eYe97HBjQZI+vnvApMXGMpJUjTdObwBb
         kfhA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=AHOfdcif;
       spf=pass (google.com: domain of boqun.feng@gmail.com designates 2607:f8b0:4864:20::f2c as permitted sender) smtp.mailfrom=boqun.feng@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1731087972; x=1731692772; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:feedback-id:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=oWkI2KWvNkMuVO6SRiPPlt7Pp0WQ5h40/fQjVoaIm98=;
        b=MT6UpPeRn69G09q4BTaCFBu7L9DjpM8sn9IEUiaqJyGZ089yo/0jARvTjtnmJX7TtQ
         OP+Ao/k4TdIuCEqFwfczVn37KfftvIVw9vhbAiwMEc+MIl5u3j09jAIy79MQtuQh9ZLR
         zgt4c2HDzNgaMiG0Y7XrryrGkvIjsT0AjrNn5AytwNmce8wMnt68HJ72hqNHqBigFDP5
         A9Wwv1zAkkByVXE1B1CE/qiVT8VVkAQ1AND0qkeB5yPbm1mGBtX2hcQ0cFh7eYQmx6gY
         WbuUhEUB4nwtM9kr3kCxRdfkg9v2D2IMGbRA97jKKtS8ayeYG1l8mVfJ76BYLOmMkfIL
         pymA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1731087972; x=1731692772; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:feedback-id:from:to
         :cc:subject:date:message-id:reply-to;
        bh=oWkI2KWvNkMuVO6SRiPPlt7Pp0WQ5h40/fQjVoaIm98=;
        b=f1XrQVvLgRLEEg1LkVbJ4dz8QG5hXa+CHCEP3Ah0K/8phkaWMjh6QNhLMGKrFOF/Os
         2A55xZ76x1jY+9cUsd/ep9avuaSQfmc4SqsDrbuaDa0HpxoafXt+EIsb2o4zwS17Dvnl
         tUZgXtvFeGe5qq3w9jlk1akI6W/FyyZwU6p+m1sO6Bs65JHSVvPNtJlmw9KMokvCJR3n
         zA4+Ut6BrvY+V4C8mVG7dPQ5ht/BymWp+YHkHvJhF6mJg4f+HjfHavU4/zBV2VzqBfJj
         3QWuwDi/+ZaHUy5zAEApf2ttvM4lJxEFlv42lM3VGVx3nv9WBVaGAh25SyDbuHXEPYHc
         Rjfg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1731087972; x=1731692772;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:feedback-id:x-beenthere:x-gm-message-state:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=oWkI2KWvNkMuVO6SRiPPlt7Pp0WQ5h40/fQjVoaIm98=;
        b=RQQhMpYEO32q0EA/6/ipByskAbOc/Z8ZHDoEMIeowS+bwgkD8PLpS9n266Z5uMUJMH
         1VFy7QChMPyJPLH1WWpYzcWjlL8LP8l8UzHL16UkzqAqjFJ4V6KZZPqsiGAF2T5xEPLM
         tZ1AvoeOYVHtiD4tZf3lo19V8sJ6nOwemvAA+88LoUuqVvd8K0VuV417/JIJDtDuqU4p
         hzkP5XqjQXTc3bMdMbO4LsyO+xg3h9hXXr8umcGdxfAIzwSKhWFz5u9FirwQSr2hQ0dI
         lne+4BRbgzninrhM8hIg8JOnVmDx1Yy7cZk19hvBtzfrA6bQD3hy89JczYkAjtkvqRPQ
         xSOA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWjJjskEJ0I/ZMOQjfcqlc/aoQcSfWrVlVGZvR3XZEheHiucJu1DMmaD8swdQxV9LBk9HKALw==@lfdr.de
X-Gm-Message-State: AOJu0YxqtqRQoj0VDTAOuX6iMK6fzNYeNbhZcarGaLdb3YEw8UpjFD+N
	NH4EcDWWPpDSyqPoRP4eSAKsMzGSGffcCylIqr8mv/PgjdBJrXjk
X-Google-Smtp-Source: AGHT+IEIm8s9F+eMa55E6I9Kj4kpYkwMwofSNvYOgak5aIbhfmTPEB5zltqfz96xRDYoXaVOe94m6w==
X-Received: by 2002:a17:90b:2ece:b0:2e2:d33b:cc with SMTP id 98e67ed59e1d1-2e9b172e0bemr4850718a91.21.1731087971977;
        Fri, 08 Nov 2024 09:46:11 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:5204:b0:2e9:be83:ed28 with SMTP id
 98e67ed59e1d1-2e9be83edc6ls8715a91.2.-pod-prod-06-us; Fri, 08 Nov 2024
 09:46:10 -0800 (PST)
X-Received: by 2002:a17:90b:3d91:b0:2e2:a029:3b4b with SMTP id 98e67ed59e1d1-2e9b177632bmr4871416a91.28.1731087970533;
        Fri, 08 Nov 2024 09:46:10 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1731087970; cv=none;
        d=google.com; s=arc-20240605;
        b=WT5wXdRWY2lQhCVm9uzNBd2xlNnxIFGli0V/9J7IFqcNkAcMeu9IG97JdCvoyWks3a
         MvY/J2L9VYaGnLdSRi/Xhaxz4EzLwYGSJ4SVelOSQIMxiN2B0f1PLNkJ4Nv2nmwq/851
         LFcl5v4ZfBfxKaM8WMNJmjD9bLjvWc5ycz5ksDFsYOBmpukqItntenhBABok5TRmEmCG
         wgqhvRCt3qrdmQz+CyXphButX6BhYE3krgbnUo2K9lPD6TcyYCYorRqmVK5yekSi5ObN
         4CLgGeCebqX5KLCfaFdSy4l2FYgTukaIArPHuHOf/jIJp1sxqsP9j1TrFkDD957LDPj/
         8mfw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:feedback-id:dkim-signature;
        bh=HigXSvE1YCLW2Udt6TV+7TWMr4D2/j3S3P0/mBJY7SM=;
        fh=wB/Lt1I4u79n5LBJqB5IJWLA8T5MOF+P6O50A7DiuT8=;
        b=PU6bpWm8SDPGj47hp4eElBhh8BM9eZOPjj5GsJxmw/kWBj9wo79vinMCDcWYqDFHsg
         X8UdHZgr5rbA9cOU74CWWI1UciZaNvAhlRYcR2kN8QKtMpGWlMDJhNhVVZ5EziLAIUdZ
         eTxCYeKhDKf62P/eQcufR1qyMv5CN328mD4gS0s1Dc6Ok9fY/orvTlXousdCjI6BJlNw
         7LyMSCnznw02XYhc05CXp1k2PKyaSJzzmSg5FBD87QsJW5gde5wmP76xfewJBIC1mx58
         v5N9AOz+qc6XUbipDm1kJ/bATucRo7KBX3l8pphzVnhVBXUee3O4wSWcEs3i9DeOzbGS
         DbYA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=AHOfdcif;
       spf=pass (google.com: domain of boqun.feng@gmail.com designates 2607:f8b0:4864:20::f2c as permitted sender) smtp.mailfrom=boqun.feng@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qv1-xf2c.google.com (mail-qv1-xf2c.google.com. [2607:f8b0:4864:20::f2c])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-2e99a34be9esi280204a91.0.2024.11.08.09.46.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 08 Nov 2024 09:46:10 -0800 (PST)
Received-SPF: pass (google.com: domain of boqun.feng@gmail.com designates 2607:f8b0:4864:20::f2c as permitted sender) client-ip=2607:f8b0:4864:20::f2c;
Received: by mail-qv1-xf2c.google.com with SMTP id 6a1803df08f44-6cbcd49b833so13638616d6.3
        for <kasan-dev@googlegroups.com>; Fri, 08 Nov 2024 09:46:10 -0800 (PST)
X-Received: by 2002:a05:6214:5885:b0:6d1:9724:80fa with SMTP id 6a1803df08f44-6d39e1a53a0mr49322616d6.32.1731087970039;
        Fri, 08 Nov 2024 09:46:10 -0800 (PST)
Received: from fauth-a1-smtp.messagingengine.com (fauth-a1-smtp.messagingengine.com. [103.168.172.200])
        by smtp.gmail.com with ESMTPSA id 6a1803df08f44-6d39620d14asm21687576d6.67.2024.11.08.09.46.09
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 08 Nov 2024 09:46:09 -0800 (PST)
Received: from phl-compute-08.internal (phl-compute-08.phl.internal [10.202.2.48])
	by mailfauth.phl.internal (Postfix) with ESMTP id E22AF1200043;
	Fri,  8 Nov 2024 12:46:08 -0500 (EST)
Received: from phl-mailfrontend-02 ([10.202.2.163])
  by phl-compute-08.internal (MEProxy); Fri, 08 Nov 2024 12:46:08 -0500
X-ME-Sender: <xms:YE4uZwNc1W3SnnSrNcWZbQdseIs2AX-hR0p8uSBWW19K2MsThKRoSQ>
    <xme:YE4uZ2_7PClqqKc0nE9nLg1dnFDyw2rT4YTsuQtXW__Q16I9YDwHMaKO608aPgBBm
    yjmz8vZKWRk5l2RRw>
X-ME-Received: <xmr:YE4uZ3QgkVw96NvpCansF0Tmq_bbtVV2xpWoSaAQpYOqHs6EyO2ZtX3nzEs>
X-ME-Proxy-Cause: gggruggvucftvghtrhhoucdtuddrgeefuddrtdeigddutdduucetufdoteggodetrfdotf
    fvucfrrhhofhhilhgvmecuhfgrshhtofgrihhlpdggtfgfnhhsuhgsshgtrhhisggvpdfu
    rfetoffkrfgpnffqhgenuceurghilhhouhhtmecufedttdenucesvcftvggtihhpihgvnh
    htshculddquddttddmnecujfgurhepfffhvfevuffkfhggtggujgesthdtredttddtuden
    ucfhrhhomhepuehoqhhunhcuhfgvnhhguceosghoqhhunhdrfhgvnhhgsehgmhgrihhlrd
    gtohhmqeenucggtffrrghtthgvrhhnpeevheetffdvffetkeeuudeuudektdfghedtudfg
    hedvgfdtgedufffhudduhfejueenucevlhhushhtvghrufhiiigvpedtnecurfgrrhgrmh
    epmhgrihhlfhhrohhmpegsohhquhhnodhmvghsmhhtphgruhhthhhpvghrshhonhgrlhhi
    thihqdeiledvgeehtdeigedqudejjeekheehhedvqdgsohhquhhnrdhfvghngheppehgmh
    grihhlrdgtohhmsehfihigmhgvrdhnrghmvgdpnhgspghrtghpthhtohepudejpdhmohgu
    vgepshhmthhpohhuthdprhgtphhtthhopegsihhgvggrshihsehlihhnuhhtrhhonhhigi
    druggvpdhrtghpthhtohepkhgrshgrnhdquggvvhesghhoohhglhgvghhrohhuphhsrdgt
    ohhmpdhrtghpthhtoheplhhinhhugidqkhgvrhhnvghlsehvghgvrhdrkhgvrhhnvghlrd
    horhhgpdhrtghpthhtoheplhhinhhugidqmhhmsehkvhgrtghkrdhorhhgpdhrtghpthht
    ohepphgruhhlmhgtkheskhgvrhhnvghlrdhorhhgpdhrtghpthhtohepvghlvhgvrhesgh
    hoohhglhgvrdgtohhmpdhrtghpthhtohepphgvthgvrhiisehinhhfrhgruggvrggurdho
    rhhgpdhrtghpthhtohepthhglhigsehlihhnuhhtrhhonhhigidruggvpdhrtghpthhtoh
    epvhgsrggskhgrsehsuhhsvgdrtgii
X-ME-Proxy: <xmx:YE4uZ4t1xpS1LELuJjk1DgWaeJmtkgPguwfF0H2t2YqRYLp-vz81fA>
    <xmx:YE4uZ4eygsiljrFGmPU6K4BfQ5zfNsO1h5lpaMzBF5UfEyqEzHnk2Q>
    <xmx:YE4uZ83pZfMgXORtu-nCtTMqs1AUZExlYo4_tmduFCuZeYBa1qvtaw>
    <xmx:YE4uZ89LDPSBLdBtLdHWyLJ2B_ZnOQFRVED-36Gidcf6zTLq-lhNyw>
    <xmx:YE4uZ_8N3WLBj3haFsurfLARTigNsU7WTHuv_1Xd7Al6A5Xto9nweh0f>
Feedback-ID: iad51458e:Fastmail
Received: by mail.messagingengine.com (Postfix) with ESMTPA; Fri,
 8 Nov 2024 12:46:08 -0500 (EST)
Date: Fri, 8 Nov 2024 09:46:07 -0800
From: Boqun Feng <boqun.feng@gmail.com>
To: Sebastian Andrzej Siewior <bigeasy@linutronix.de>
Cc: kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org,
	linux-mm@kvack.org, "Paul E. McKenney" <paulmck@kernel.org>,
	Marco Elver <elver@google.com>,
	Peter Zijlstra <peterz@infradead.org>,
	Tomas Gleixner <tglx@linutronix.de>,
	Vlastimil Babka <vbabka@suse.cz>, akpm@linux-foundation.org,
	cl@linux.com, iamjoonsoo.kim@lge.com, longman@redhat.com,
	penberg@kernel.org, rientjes@google.com, sfr@canb.auug.org.au
Subject: Re: [PATCH v3 0/4] scftorture: Avoid kfree from IRQ context.
Message-ID: <Zy5OX5Wy0LsFPdjO@Boquns-Mac-mini.local>
References: <20241108104217.3759904-1-bigeasy@linutronix.de>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20241108104217.3759904-1-bigeasy@linutronix.de>
X-Original-Sender: boqun.feng@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=AHOfdcif;       spf=pass
 (google.com: domain of boqun.feng@gmail.com designates 2607:f8b0:4864:20::f2c
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

On Fri, Nov 08, 2024 at 11:39:30AM +0100, Sebastian Andrzej Siewior wrote:
> Hi,
> 
> Paul reported kfree from IRQ context in scftorture which is noticed by
> lockdep since the recent PROVE_RAW_LOCK_NESTING switch.
> 
> The last patch in this series adresses the issues, the other things
> happened on the way.
> 
> v2...v3:
>   - The clean up on module exit must not be done with thread numbers.
>     Reported by Boqun Feng.
>   - Move the clean up on module exit prior to torture_cleanup_end().
>     Reported by Paul.
> 
> v1...v2:
>   - Remove kfree_bulk(). I get more invocations per report without it.
>   - Pass `cpu' to scf_cleanup_free_list in scftorture_invoker() instead
>     of scfp->cpu. The latter is the thread number which can be larger
>     than the number CPUs leading to a crash in such a case. Reported by
>     Boqun Feng.
>   - Clean up the per-CPU lists on module exit. Reported by Boqun Feng.
> 
> Sebastian
> 

For the whole series:

Reviewed-by: Boqun Feng <boqun.feng@gmail.com>
Tested-by: Boqun Feng <boqun.feng@gmail.com>

Regards,
Boqun

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/Zy5OX5Wy0LsFPdjO%40Boquns-Mac-mini.local.
