Return-Path: <kasan-dev+bncBCF5XGNWYQBRB75QVKXAMGQE2VXQQAY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13c.google.com (mail-il1-x13c.google.com [IPv6:2607:f8b0:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id 6AE5C852131
	for <lists+kasan-dev@lfdr.de>; Mon, 12 Feb 2024 23:15:28 +0100 (CET)
Received: by mail-il1-x13c.google.com with SMTP id e9e14a558f8ab-363bc4a8d38sf33858685ab.2
        for <lists+kasan-dev@lfdr.de>; Mon, 12 Feb 2024 14:15:28 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1707776127; cv=pass;
        d=google.com; s=arc-20160816;
        b=mcs0PqhyCohGydRyPr//KKETQTXIdgkxJKADNNQ9fB7MY7yjIVtJXIfQiZMEYP0Em4
         PIw8uBWdacRBSwWYtUrjxQs4OJd1KVeE1HmXzBJ9pMDc67NlR34VDQwhVM0JZG9cjzcV
         M1dEnlJgSw7pdP5to8rRuI4zfvyXH9jOuh8/f+qJjB1kg3qzn4QieFnH2dfAJEnvUSOt
         f+8vPMmOTlO0Himp0qc+QTRx48gfj/lj4X0xCakLRz2MUC8LX+MhSr9Ywj1DWsm/l97w
         zUoIRc50LlJgXBpK09K7iCzxGRgltarVHW3kLleN4viTeLBJl2LW/g0B4vpWSp3qWAsO
         NoOg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=zGWz1ZIdKSqdBXMmmCZFFSgsGJAgN6vqpbb08EFC6+k=;
        fh=Xd2lkTHFGuYaCocPQynHxm6/hHE1dN64vBgpvFoYyKc=;
        b=taMj0cec8bOQxdtfD24johqA7/XLvjjcJeZMa37MkdiKcBsW07eqUJTBCoiFdIljgc
         AGFq13hQd4WQU7i45+GP/hjR0h1sYY4zS2p4/802I/ROFZZikLFQeiXkbENhB3PgnQBg
         FjxwX24UbOcyBnIa7AbGIPJhDsENU0HaVR2qT2uEVr0ZMG7Lp7MiFOhUwZRtz9afSKrf
         Vb3bwB9its+JxuWBHyLzxKJp3CUWsPEaJOE4XMCZx59/YLPXt2B5tXZxU+BCwqlzu7mW
         JVi5z1/CDII7HnH8PHY8RUpUYaiPt0Vuya29hwrJ6uT64+vztlXMrPECokH4i1LxdHiV
         MoXQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=mDqfQEI4;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::1030 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1707776127; x=1708380927; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=zGWz1ZIdKSqdBXMmmCZFFSgsGJAgN6vqpbb08EFC6+k=;
        b=or7IP/YXoNJlLL6IfI+FoFPThrOcuXzK2eyKJZOOB7Izl9iQZPMLO7vD+ahmNHa18U
         lnx7MABfunBnrjalghk1JqNKmWuxWmn9WK5cEc/P18RFK9AHTPYdRPnmWzpZtvEqkRu7
         E7MQLar7f7DXZSBzlG2Ikp52jmYaVJJ+IueisJgygt1ztVMsUJFtshBbag5oB3Y/G0HW
         ArHKsTzw9POmjsAFku/eT1eIVPOtgG1D167eguyNhk08aMCThedWRpisUIkCYP8OizqN
         +hqbo314F04qxWhU5gRL1AjZfkf5DaOuB4grs63e5AM+fWgffJ1bh5MWouzP5/mRdNNy
         F6ow==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1707776127; x=1708380927;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=zGWz1ZIdKSqdBXMmmCZFFSgsGJAgN6vqpbb08EFC6+k=;
        b=TCl0wqvV4nsOz7Cjx4/iXgeyxDDjqYcUEo9lE/i39WXCeKSHSFKNFYQ/cF8BUBqBRy
         TvMzxPUdQOFTbSHuC+hZX992UIZa3vPtp4PPdtaW+a+G6uKA6I9lHxgiKj2GQX5ZCEzQ
         yVI6zHAxS7+fQ9hoyQrlPssnPOeqn9XgSbRoux1A9Efw4GHLVfM1WNMd95Ysh3e8HhAq
         930Uus5lNEZhZ9gcCR0F1dsMkkcFDo3OzQl8Wf5gb5prGmCJ75XCI2VUwoJHRkQqy+Gn
         R75T+w1qTfJK7LnR1vr1NopggRH8QjHrzAmFyOiwo8CJCsqvk5GQ8Q8iPjeLJSEoiEaD
         LdCw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YwuEZ1vF9ffZDqNRf8uQ/utcsQQNKCG1DyoWBPkbaCQLBy5bfMY
	As1UK06rIP3ibZrTZh+M7qhC8NgA1NmhrzYC1n53iswx1xU21jVD
X-Google-Smtp-Source: AGHT+IG2f5t3n75CXmIHZIU9r2iitgZ53Wv+MvzYsefByOYJIPWb1JbQlLFs/maYnlFieQBSMnOfsg==
X-Received: by 2002:a92:db12:0:b0:363:c5b0:ae4 with SMTP id b18-20020a92db12000000b00363c5b00ae4mr8417786iln.13.1707776127270;
        Mon, 12 Feb 2024 14:15:27 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:3184:b0:363:d634:8954 with SMTP id
 cb4-20020a056e02318400b00363d6348954ls2244173ilb.2.-pod-prod-06-us; Mon, 12
 Feb 2024 14:15:26 -0800 (PST)
X-Received: by 2002:a05:6602:450:b0:7c0:3d1c:bf4e with SMTP id e16-20020a056602045000b007c03d1cbf4emr8341648iov.20.1707776126573;
        Mon, 12 Feb 2024 14:15:26 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1707776126; cv=none;
        d=google.com; s=arc-20160816;
        b=mdlfEIVtYDkcZI8GOLEllsNDem8ZDrLL2tdC/+NaGKJHAxwa7/kGbW1W0oNJPCgzym
         OrKQiFlSzk5DJcnv7toQK9lia5PY8wZUrciHg39KNnolID3mJgLjVwKSgLGrUyPRUFwD
         e/JGKIlRNo0LIZMmACA5tey0EZv+ZuDkP6og99tYyC52+1YiFO2QBm2s3Lh7tgA0YKYR
         G+elNBMja9daCsAB5gudIy6/dch+kBm5NRt2J9T0qUs/Xqwwx1IUAtbJ528YEcLkzKnU
         C98lX78e56tsTuH/qvsANDZ6QFwU9NTv3fX2RKVdRCqShVGrdKc3dfA+riTXy4lnV18s
         7tTQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=VGyor2jQd80o7izL2Q665nn1vzR3SBtHBIgEg9t9XJs=;
        fh=Xd2lkTHFGuYaCocPQynHxm6/hHE1dN64vBgpvFoYyKc=;
        b=G3EZ66bPpp3/7FExjtxIoL4x6Z/cpQzw5ZExou73CAsJ1s1euxSscXBjGnEA0L8B5B
         wMRQ04xqun04M88+4T8XOBYRn+ChoFEmHRBS14kZZwnUuomUhbAteQ6FQvbVG9bEQ3tH
         CkP2FyFUqRw1wN3p5bKxZCLZWF3uGi5WKHpCnTSK3N4KcDyAm5eZMCWpaY2skrRSLM5O
         hG9m4QerXe549ru4trMmnhWcBEZoaZo4IT7Ox+vfmVzZ5MxIca/rIe5s+HDwkznufPr5
         s36XcgQBqcIjxpJmCJ1B2Z9xkOUp305N/f7a0ptdFzP1Q7XAAPV96eYwzwNKRJc2l3Ox
         ogeA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=mDqfQEI4;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::1030 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
X-Forwarded-Encrypted: i=1; AJvYcCXhqIWtpbUoCuZYkBwBpGqXEvJbez0x2IyWyYi2E3QqKEZaPFJi62502+L1zOrbgVxKDOHZwWvxim0FjDSnw9drNvrUJ1UDG1IZ9g==
Received: from mail-pj1-x1030.google.com (mail-pj1-x1030.google.com. [2607:f8b0:4864:20::1030])
        by gmr-mx.google.com with ESMTPS id w20-20020a056638139400b00472c7ee34e7si582887jad.5.2024.02.12.14.15.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 12 Feb 2024 14:15:26 -0800 (PST)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::1030 as permitted sender) client-ip=2607:f8b0:4864:20::1030;
Received: by mail-pj1-x1030.google.com with SMTP id 98e67ed59e1d1-29080973530so2678970a91.1
        for <kasan-dev@googlegroups.com>; Mon, 12 Feb 2024 14:15:26 -0800 (PST)
X-Received: by 2002:a17:90a:f014:b0:297:a5f:4fb with SMTP id bt20-20020a17090af01400b002970a5f04fbmr5735341pjb.17.1707776126081;
        Mon, 12 Feb 2024 14:15:26 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCXuS8l0SNNP37L18DjB7CHigtOpu2mBOh2bDf9AXMn3h0c7pDY/OuL3AIxKk9ZAx2n91f9GyBGnJ0Axeve48hw4QnnjI1dbienG7TJ3+hOwIyzrNUmxZcX1BR+yRe8iuuNcX14w9s/m0+HOPBvGZaMcNKT8MXNIoja+c25zk+T2ysfbj5F9HdjgzzoF7u2GjsnCbL6IFkH08JwX5WXhOLQeJp33JetEDNS8/WXwzyr8tQekx1rqQOMCzxTl7xVMB0ENp0Gm7llaix/ILuzr6ZO+VwChvhtBArqLgANwAUFrBP0f8RhEnpn/PN/b9tPP7R/0oLgaOusxEtM5DqAIwSPQbsV8PBd0flIh/nMXVhA3KGD1lubX93MBbdiHSPmkei9E/wqSQ7QmFXyC2txaiY9r4Yz8yyD/3ZMvzXeJnUJKu8uoa13hIWJIROKH2yB2KGUoayTLHlUEthuzLhT+Iwtd/KcdfzA6oTHAEts5OcPsdGGPlc+iSVsfj79/d90XX9nrbgLZQUqkJJtulMdohk2KOSh8Yvx68sFUVNBwrD5qtkec9EpiHUbS5prNNvgOKP0SFkyQZdk/mw6IZ8Hfn3x3qqRNimDvYMHmNRTL6vv+38GOWP+UiiCHher3il3xXtz9pLlMY+Nsx29tW3qjog8DEdApy0+kpTYajR/N4oWzKVr/xTRW83L/sU+tVSQiIlwJLjnuel1C2GM19JRUtesT/T/I/BTApvdjZHycOLQ1RKO9XOHLDhcEKV/hfd5xOilC+4PVisCzzNQRFYn0qSVJnxRAfBs3Tq0qkWUMG0vdvcQFCEDgGlO621YwKr8LaWx9Mdsu5TiQ+pcbIX8vHgNorR04rXV519R/AShWTnLD4UK/iwiV9upY/ExnRiijMvHzRfFqxKLuIRK8395+YqbHPWBPH2QbJoc8RZHPkC52Iw1o36q9rJ1k/1QfIbJb1PXkB/
 C8OW4pcZdo36VtoZYRs2pFwP78+GTbDERSlOYcMTo27uSvTPSlyW7V4owwaG1Zkb2cBiLnEsrN6ryjkOYUlbqHSGnvHY3dWuD2HXMP0N+nPYOskP0jkRjoj/S3x0W3+38OBo7TIT+TUfzvz3fDonfSVPrkjSbRkCWO1mIKl3Xr/ju6rZRZOIroO8gSnQKMVGk/M9U0Five32eQdmoA+dw/V7GFNcDOdL+gZ2lcXUcbsdurcpX1e8NARv2ibn/hbQ4jEIjHTneEZYUjtWV3hzQLU95j0Seqe8B8RmOxPOo/Va4TeXqjCK50coRfWXVp7IkUkVRn7NIAQ+gkOIcXKEtZRHuyTm1VUujiD1I8lKCbq2SeWDaqvoy0oVY5ovMkK8qudTv1GGv+Q3m3zfXiUDSeO/6KkDQ7ovK6Pes1qCrdXrUpXqSrf3I6eK31D2I=
Received: from www.outflux.net ([198.0.35.241])
        by smtp.gmail.com with ESMTPSA id pl7-20020a17090b268700b002970f177ce8sm1056099pjb.11.2024.02.12.14.15.25
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 12 Feb 2024 14:15:25 -0800 (PST)
Date: Mon, 12 Feb 2024 14:15:24 -0800
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
Subject: Re: [PATCH v3 08/35] mm: prevent slabobj_ext allocations for
 slabobj_ext and kmem_cache objects
Message-ID: <202402121415.77843B9D39@keescook>
References: <20240212213922.783301-1-surenb@google.com>
 <20240212213922.783301-9-surenb@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20240212213922.783301-9-surenb@google.com>
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=mDqfQEI4;       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::1030
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

On Mon, Feb 12, 2024 at 01:38:54PM -0800, Suren Baghdasaryan wrote:
> Use __GFP_NO_OBJ_EXT to prevent recursions when allocating slabobj_ext
> objects. Also prevent slabobj_ext allocations for kmem_cache objects.
> 
> Signed-off-by: Suren Baghdasaryan <surenb@google.com>

I almost feel like this can be collapsed into earlier patches, but
regardless:

Reviewed-by: Kees Cook <keescook@chromium.org>

-- 
Kees Cook

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/202402121415.77843B9D39%40keescook.
