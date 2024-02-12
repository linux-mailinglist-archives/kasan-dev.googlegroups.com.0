Return-Path: <kasan-dev+bncBCF5XGNWYQBRBOVQVKXAMGQE6ZUKXXI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa37.google.com (mail-vk1-xa37.google.com [IPv6:2607:f8b0:4864:20::a37])
	by mail.lfdr.de (Postfix) with ESMTPS id 0013D852120
	for <lists+kasan-dev@lfdr.de>; Mon, 12 Feb 2024 23:14:19 +0100 (CET)
Received: by mail-vk1-xa37.google.com with SMTP id 71dfb90a1353d-4c03c961e66sf1241351e0c.2
        for <lists+kasan-dev@lfdr.de>; Mon, 12 Feb 2024 14:14:19 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1707776058; cv=pass;
        d=google.com; s=arc-20160816;
        b=SIeoAR2igCba05cywXv2OoeUJ5r25EXr7pZRLLbjuaR9e0XV84U9CfW8JDtciDWJlT
         Z8VtKaQ2luHXKfn41+1DsrrEW1Ky8g/Bg4AhLhyEyEy4fhL4W3bj0W/K1r8mvB3YcQq+
         dqihHTuuQVonBuMFPFYrMEHJkP6FssVXov30AEgwdLv2kMGiYzMudSyqIEX+8ff6JmfS
         U+DFzrhDSlDSFEFDmpyUpjq8qz3+/SQGssfW4+y91CS+d7xdxzY9qB+4OiqEPQjZIiKu
         ieFewxVH0iUm+x7jT/nTlJA9u5jtS+wBilbvgGcVMBOtg0Xt6I7yLXvI26tGc3QD53HH
         WcTg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=FeQg5K9Da0LUewF1x3ZlxLE+wBrje5PwtGhYneL/Kek=;
        fh=5XKJoENbCeQQidiAgQtXymoiW8gis/f1kj6KCCDr084=;
        b=0FTKfaJQcEKedYL/s5EldLKatZ+2xEthMPhae8PIC/YIQx+SRQXUX3X+dc+6lBrgAp
         eBPBxoiYwe74Yi5Gs2M0JQ6Xu2kKvpSROGeWZaEJTygvLjYkbUwsxW0mMCmOgDvIz27C
         uh/m9/pgLd/KY0YYJESs06xEx5AAQRaY43FgMQ81AceNK9F3+emF7eAgppMDRKz0n/Q8
         iJW1ugFY92UwTvIShVWEVSrbSLQN3ZJ6jwDY3zAfDbhqqQ80+GFg/dnlPMf9QjHflPMz
         Ve1LIw83Re/actbj+aZAEthKD+X4Me6c8AfJjLOmvakHCjo5ZGM/s0poVooKf2cCg1Fa
         m6yQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=EF9UqTfl;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::42f as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1707776058; x=1708380858; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=FeQg5K9Da0LUewF1x3ZlxLE+wBrje5PwtGhYneL/Kek=;
        b=oBx4OBHC3PfWbe3aoJK4p3NV0NPDmWTbOAsGU9IPA3tFdpn9+z5UQtMaupdJ9/9GJ9
         ZT8c04SUtMBIZhUgkQ8qA5Vq8WqWzMiy3dw1LSsnyeNPakS4Qp8o7Vml9FWl8f3Q2CFS
         u1jcH9Oo8EHY6DvELevuOKrJ8CiWCJiQQMNaJN+l7aJTxiRQ6LRB6IaucySb9Tpo/Smk
         3CvEay3/PvaUTgv/RHNnw58ZRl7KPRwG+kLJNbsftBzpRm8147Zq7Rxnl0C+3jdzLwvA
         h2bNpqCFBXb/0Dk9Yz4oSU3UJFKEKYacpeN3QpkRgTEd6nwKjiIG/Tp/anJI22THHA36
         vS7w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1707776058; x=1708380858;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=FeQg5K9Da0LUewF1x3ZlxLE+wBrje5PwtGhYneL/Kek=;
        b=g5kyQJvlwd+WeTbpDBWAaNkG+YIi2iAnrysBBuFC/JwuKkGiBDKfKv032AjFmwCzFx
         +4qnuRY1P2F9d0zCPM6GpnRBsBJohPtd4IZZi1OJSJ5THNuZOVtcrV1YFiJsavPx4412
         IpVyDiCY3gDhyQfnfXQ/g4Uh9G/cZoYHYXOQGQXRysVq4tmMxXaTAbTuHcXJT/c+l7Nh
         47fp20T0n15VM9GgiggFa3YdLRjT3OsHundpaDvXevZpm/k/K8kC+4qfhPeSGh0GbMua
         198FK9mxuYiUhsZfWVXqjw9rFxHiruVmyZGw6pirGJVZ1j2PKHeXGCcLAbOpdpOz2TZc
         lzpQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVyAQk4HKV5x/AtsponyPgj57dAxhcLbEk27hnzqSNyMPEgqoccw3avWDIY/SV++K0avZpoch4pCRjpSi/FHR8Ru9TC28KCRA==
X-Gm-Message-State: AOJu0YzEmx9rEytoEtguZjGC0/+OCrTvhGYvuscxnjeh5Phw8ktRZe+N
	G4cSuwpu5RCteQLEzbEXUqx8gPn97AJhNzvWKhSaBnBkGtx37XC2
X-Google-Smtp-Source: AGHT+IEG46xALaCkX8LITA3ombsyoVgQr2e2XP+hJMZUumZTAFmiAyZQBtXJt1sIEPYPsP67Cph6kg==
X-Received: by 2002:a05:6102:cd4:b0:46e:c5c7:a794 with SMTP id g20-20020a0561020cd400b0046ec5c7a794mr3249325vst.27.1707776058536;
        Mon, 12 Feb 2024 14:14:18 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:2a48:b0:68c:cca7:f6d5 with SMTP id
 jf8-20020a0562142a4800b0068ccca7f6d5ls2350357qvb.0.-pod-prod-09-us; Mon, 12
 Feb 2024 14:14:18 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVGo0T0SXlucg51+q99XiVA9YjLgLl8IsCiRibRAQIU39MLdA91Sf66F+DQqvHdrO7rTEz78UeT3vgbCPBWB4eGMI4giiCKn4FNqg==
X-Received: by 2002:a1f:e604:0:b0:4c0:fda:7d8c with SMTP id d4-20020a1fe604000000b004c00fda7d8cmr4775002vkh.2.1707776057939;
        Mon, 12 Feb 2024 14:14:17 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1707776057; cv=none;
        d=google.com; s=arc-20160816;
        b=bUjUOrWfaWyo0mLyM8LX4jxaRKlRi56mlNFP9C4cVHZdmuuCmMR5sT8qLQa7b2EpBo
         xogiLFhRNXUHg/rndWGSiML1u41XfpRrpGww1dbC5oWb7PyuWIzMYrE0ycWLZsOCSEPy
         GRTcwIhZRMUouC4ImTn1QsOncz2Xi7Rw+YEvfQ56yNQ2etSIvyNmbI7Ce120KDHDEtTl
         40l4bg3lX2P7Ib3ZxSo6Nt7r81i5rBeH9mOY+mCl1OIPa3EuBYsRtNechsUo7qbLOeu6
         AGqAp4gberMJ2XbM4UFU4nVZ67W+332k93+THhZqMuAqPB3tBtu1rzEV1KT3KXJSBsXW
         DM2g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=wZiXjxKnrMyz6iBNN8FZ/8Z5umOyXaSKjAB1K7uHil4=;
        fh=KTcE06bufMpvMRZj1rLS87yPaqmQRn35+iAVdpE0S6w=;
        b=Qi0t/HB6M36IwZTAqyRVCoWG/5kHuSQMk9abvB1JVIDzlR8Eqw5C7Z0J4UQL+RXDCX
         yPSuCeOQrUxtJDNZes/JvLRnSl0Dz/3HPq4auQc4jews/FeXcP/43TMynyN8VPsNSP+X
         QxAnOaoNpD5baeZlRtJ4HJKChwfEIkLb15WLQMjQkVn0zksdEuMo9KsuBrAzh8bmvcpw
         yNVn1ZLYc8rrYdkx56eT99Fe6LLz8XuzsSq9D9tYYfsofdcEcKXOkB1e+CPM9azekRzr
         7JYoE8WYbiT+uIyq3rozPWGzmqFA7C6+WfqMotNejXX5KWW8TYSgdHYxZ6cOEUHKuwL0
         GQ+w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=EF9UqTfl;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::42f as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
X-Forwarded-Encrypted: i=1; AJvYcCUbJ7Xfb/PtZ9oyeQNwPNrkXZ9gGiPIsoliqRqD7V30/gRX0Kx6uiYMkEMwn43Rh47YAhvy17u1iOqCBtPfrn9HCauGtz8WRE1O8w==
Received: from mail-pf1-x42f.google.com (mail-pf1-x42f.google.com. [2607:f8b0:4864:20::42f])
        by gmr-mx.google.com with ESMTPS id cl25-20020a056122251900b004c027d19fd3si670316vkb.5.2024.02.12.14.14.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 12 Feb 2024 14:14:17 -0800 (PST)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::42f as permitted sender) client-ip=2607:f8b0:4864:20::42f;
Received: by mail-pf1-x42f.google.com with SMTP id d2e1a72fcca58-6e0eacc5078so680315b3a.0
        for <kasan-dev@googlegroups.com>; Mon, 12 Feb 2024 14:14:17 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCVAJBGqWzQLPQZ7oSK9uUh0OOM8/xanprEIRMAuaCjpV4C8ZuzqkhnD+JVMSdN8Hzdh7bZreUAg4NSCcB422Lwzuhi6rnaHcXNRpA==
X-Received: by 2002:a17:90a:6d63:b0:297:efb:a102 with SMTP id z90-20020a17090a6d6300b002970efba102mr4462729pjj.24.1707776057533;
        Mon, 12 Feb 2024 14:14:17 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCXd6Iq94q+nzQyCD7UZJ5Sd0PLWQMPHoB3mx4VB94zSEAg6IDNu3br5BFE1eExmR8cznMledKK/STod2OwDKt3zpiL9K85KXz30T+3IW5Z4dKcTg9r1ac0EEUD4orveMTPKHk3bLfh6Aylcultx+6/EM3g7DmgMIYcj6hnpXS66oGrT71C9p1CgOOxaRMan99c6UCn7Sn+p+IvntLAgbRRVfwkunhtCj4f5eVCwCu4DKWVui3zHnw3AJz06cdJfNktpp/VV5PbRNLNoImtleaRTHzYgXIs/WIDx+xT6Kz8EWsujXT2jMbE4X5u5fT87mjDfPmGn+1IdHJJNwdkj228s16NXmbvbaT4YP14OQbBPyMep7EYrAemlPIrRcAvM1Wj62bScBU7/wkLr+G3h8FtoDPd7DUIp+S1rASLajvbE50SSNDkkiBQqflqcemkXEQMgq10Y0niiz34utlfhE4QO7v3+EtZRNQo/GqSYUKg7ImwgImoEw59woCM8lweKyFgbatF48fphJJzzRZyBsh3T8TgCEowBLjPs/SCQWn/AIOlcB6tFiB2JlIEh/OQ2vpPW1pQ/UPfQMRcveHBB+/Np7KH9wijIcaFh6DjTe9i0bDyokd2bNMo9X4pBUPXitvkMI3uLL7HWP0YmGkBx9bu33mdwCIXc4AbJA/8ccSv1wldtJdTIc4D4Ozjg5KJM1Vsb0nIM56ZFpC9vxrcHud1897BU2QdaNeII7Nmc9B246ykAxToMlQyJKI7B6iPl6Cvxgm717dOmdkMzYlTAJ2O8cuOSWvBAvVpD489mppNE/xIykNqg4URbN9qOfd8dSdh3FT/fK7IQZLy1KcCFEp2ofuLQF9ioGhyGce8w7dfxURqBE3USurbd/E0RvSJ0ZHHQ5gTKJMqMPyr8gQozI00P/SQTiVYtGl4DURF6svyVxPb5+uyHByXQccvT8rAYhch7YP
 V5R/i4jJ6YoIZW/jnXbMdBrDdTJthtr5TygxefEGqrSX7DzBxpili/VgBq9iYDTspwvuG7c/F4gui3OanGvi+kOaAyYLJjgC20DmEdhz1GjBp/NqJlZG26Lm8Hm4ZPkaD7NfBxhnQCjrJqSaQJORKWzE0Lfu3TISPrywXj4QJVO4FWbQELICQEP+mWAvvAmElvO8UIl7/GhZ2X3ZL6YlgX5yrXaWEuumfYq3VTBKn/TD9Yl271QeCPVHJf4zPubjVJ0o6r2cvCTfYxS5usoB1a2Ccs8LSuT+Futjhzb2Dr+M/seOau0i9/gRYJA4kxtEagaCb02w9fnNIouyjGzuLGopAt97CavVot1hv7V3byqHrATkBzChhCU1p6A1oyxA6hXzJAYHo215VrceSIb+X6czQ4qtsKEmLewSsEhDsB+UR5DGbNDX0GtK/jDWM=
Received: from www.outflux.net ([198.0.35.241])
        by smtp.gmail.com with ESMTPSA id ok5-20020a17090b1d4500b0029703476e9bsm1031910pjb.44.2024.02.12.14.14.16
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 12 Feb 2024 14:14:16 -0800 (PST)
Date: Mon, 12 Feb 2024 14:14:16 -0800
From: Kees Cook <keescook@chromium.org>
To: Suren Baghdasaryan <surenb@google.com>
Cc: akpm@linux-foundation.org, kent.overstreet@linux.dev, mhocko@suse.com,
	vbabka@suse.cz, hannes@cmpxchg.org, roman.gushchin@linux.dev,
	mgorman@suse.de, dave@stgolabs.net, willy@infradead.org,
	liam.howlett@oracle.com, corbet@lwn.net, void@manifault.com,
	peterz@infradead.org, juri.lelli@redhat.com,
	catalin.marinas@arm.com, will@kernel.org, arnd@arndb.de,
	tglx@linutronix.de, mingo@redhat.com, dave.hansen@linux.intel.com,
	x86@kernel.org, peterx@redhat.com, david@redhat.com,
	axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org,
	nathan@kernel.org, dennis@kernel.org, tj@kernel.org,
	muchun.song@linux.dev, rppt@kernel.org, paulmck@kernel.org,
	pasha.tatashin@soleen.com, yosryahmed@google.com, yuzhao@google.com,
	dhowells@redhat.com, hughd@google.com, andreyknvl@gmail.com,
	ndesaulniers@google.com, vvvvvv@google.com,
	gregkh@linuxfoundation.org, ebiggers@google.com, ytcoode@gmail.com,
	vincent.guittot@linaro.org, dietmar.eggemann@arm.com,
	rostedt@goodmis.org, bsegall@google.com, bristot@redhat.com,
	vschneid@redhat.com, cl@linux.com, penberg@kernel.org,
	iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com, glider@google.com,
	elver@google.com, dvyukov@google.com, shakeelb@google.com,
	songmuchun@bytedance.com, jbaron@akamai.com, rientjes@google.com,
	minchan@google.com, kaleshsingh@google.com, kernel-team@android.com,
	linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org,
	iommu@lists.linux.dev, linux-arch@vger.kernel.org,
	linux-fsdevel@vger.kernel.org, linux-mm@kvack.org,
	linux-modules@vger.kernel.org, kasan-dev@googlegroups.com,
	cgroups@vger.kernel.org
Subject: Re: [PATCH v3 05/35] mm: introduce slabobj_ext to support slab
 object extensions
Message-ID: <202402121413.94791C74D5@keescook>
References: <20240212213922.783301-1-surenb@google.com>
 <20240212213922.783301-6-surenb@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20240212213922.783301-6-surenb@google.com>
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=EF9UqTfl;       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::42f
 as permitted sender) smtp.mailfrom=keescook@chromium.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=chromium.org
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

On Mon, Feb 12, 2024 at 01:38:51PM -0800, Suren Baghdasaryan wrote:
> Currently slab pages can store only vectors of obj_cgroup pointers in
> page->memcg_data. Introduce slabobj_ext structure to allow more data
> to be stored for each slab object. Wrap obj_cgroup into slabobj_ext
> to support current functionality while allowing to extend slabobj_ext
> in the future.
> 
> Signed-off-by: Suren Baghdasaryan <surenb@google.com>

It looks like this doesn't change which buckets GFP_KERNEL_ACCOUNT comes
out of, is that correct? I'd love it if we didn't have separate buckets
so GFP_KERNEL and GFP_KERNEL_ACCOUNT came from the same pools (so that
the randomized pools would cover GFP_KERNEL_ACCOUNT ...)

Regardless:

Reviewed-by: Kees Cook <keescook@chromium.org>

-- 
Kees Cook

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/202402121413.94791C74D5%40keescook.
