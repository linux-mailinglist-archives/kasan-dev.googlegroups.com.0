Return-Path: <kasan-dev+bncBDLYD555WYHBBIEUWSXAMGQE532AH6A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc38.google.com (mail-oo1-xc38.google.com [IPv6:2607:f8b0:4864:20::c38])
	by mail.lfdr.de (Postfix) with ESMTPS id 2D7A985527D
	for <lists+kasan-dev@lfdr.de>; Wed, 14 Feb 2024 19:44:50 +0100 (CET)
Received: by mail-oo1-xc38.google.com with SMTP id 006d021491bc7-598f047f034sf38816eaf.3
        for <lists+kasan-dev@lfdr.de>; Wed, 14 Feb 2024 10:44:50 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1707936289; cv=pass;
        d=google.com; s=arc-20160816;
        b=dx+fdmfhFMVH2FNiPxsRjuhnuexdKCWjFWb+TYxmYaUgFD3MExWUisxZEN3lmWfBF4
         R9ue2e9X9sResGDKJtzR9aE8bycbrw/OFcvFripPjoztT0sO0BaZVrJiMQsy5+5wbTp0
         qrWuuu205yC7hfpeBSzpMMxHPj0aEmqX0I/sM5RN5z2/sJdj5CYKtYf6r7Hg07X2fBid
         5gp5Vl7GoCzOpRxv3NviePtJ3z3sK6UNXXh7dz/LByJkh6Ew+0oEEhNexY/7EVYlvwMO
         N0tokzK+owD4FlhApOZywmXZOFndQkZ/WD3MGmT9twzvecu+yLiDQUf1NIx0aUD9REUO
         gOCw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=x0m9qEzjHlC1rOrq8YE7zRJoynGzyIiha+pjXJxHiYM=;
        fh=PVnXtq11KLLNRfEdSZOdrW9jNuiPh/o5r6IyEbuMYeo=;
        b=kbgXaaCCBEHIAwc4QctBsNvmrXc+SPy9t2ybfm8M9nVe6Cl7KPtF5TaKc4Fn/Bp+O6
         CYHDSRH6FXIj0d//U6YFQl1OH2RDhK+vzOeMpAJzBD4RECvgOcik6BOtEhiKXjA5Tjg2
         7T1pC9ct42EjyoSQhTHxDO8ehNkiuhXJ7n8QVm6PTgu6WVPyP/g2ULQEmej601cCJDmL
         WRuGJv7uNJaAPvsBf1XuedkUdyxJQOVMS0Yk3rZ92un5cn3QbKw7KPG/pbY+b130y0qV
         qmzFLWEG4Q3iE1tJ9X5PmJlM03XsQIPk0A/JxvxfW8iF6nwoQq9D3dfijWKu8yfsUxKF
         8ZpA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of andriy.shevchenko@intel.com designates 198.175.65.19 as permitted sender) smtp.mailfrom=andriy.shevchenko@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1707936289; x=1708541089; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=x0m9qEzjHlC1rOrq8YE7zRJoynGzyIiha+pjXJxHiYM=;
        b=K0r+mi/V0ej7Bw1PUkKGoe3k48qdWUOtV3H9uM1PjXMrSZ72QCoWcuvgvcr4q1gSiG
         4od+bFbYQ3n7EOeYFQP5ZwSBof8BFyZNb4G7eD7xKIBs4e7GTuFrM7EAVoDrE6cqLhEI
         hw3ZG7IAylSofQt3eBDyvkdleTjfs2qRLTZx66UCdnx1Gl6UxhmVJC2GVyYUNZs0XCJa
         fU25dZIpiAdn/gtv5hdY6igsfqtEUDWDdAOrqfbNFapDRnBrfsZuFBttZigaAAAFayKf
         GAwD8dAbjtYbVwykMSTduN41zLQGiJstRcnCxfzAMRcd33wU2UeP7r8WCrwNB9/P2kHL
         NZ9g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1707936289; x=1708541089;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=x0m9qEzjHlC1rOrq8YE7zRJoynGzyIiha+pjXJxHiYM=;
        b=L45+Zmj/MZ5ENBWUSU85Ph0/qURCHT647ZI7FE9jhZTlV08u72lOCFh8e60lmuW9iv
         Sv/U4aIhrXHbLonnGxQ+hHESCiTHZjodghZiM9KHxVqvV1UQ+8FdMQ+aCvOx//iD/h9K
         wuXXjdZuc3Lz729GjMTzeRvqgmtqUBn/S7XJdQkrxGqn4zlsq5DweBq1/+KyRgmoN3Hj
         Gu+pshoj/79PLN38Iclu0P1kylRGjyfUBAvROKVHHgUII8AjSWuW6B4o0DNX42jOqwOz
         84lNfHIoxGhhVr5hpT5miybdsjj8Q0XA41FMP6i242ZcpPGwpqUeT6Q+FKhDi+P14b3d
         /ycg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWAXQR7zCdQm8xeqeID+M2FlcHuh+927gwalc84Ylolo0Y7C4Qf62DhoEw8xjVdXXo7l+oQTvBoPgEH1EBheUD0UE1dajJjrg==
X-Gm-Message-State: AOJu0YzPGysgKfUja+CtinGFtuRrS6SDAuw396j4imnKEZEUOTpiQ9hz
	RZrI+xXKgUnKfri81/uMvyhTTb3mNN16NKMCdItj7NPUmBTClVql
X-Google-Smtp-Source: AGHT+IFVqnWkBpTxdDC3V8CTbMJCmOeWh7D2EWLj9KCQ51q9xvBZpoIQxQu7KKyoZlrSP/l/BNPbmQ==
X-Received: by 2002:a4a:3c16:0:b0:59c:2ab:511d with SMTP id d22-20020a4a3c16000000b0059c02ab511dmr3893394ooa.2.1707936288238;
        Wed, 14 Feb 2024 10:44:48 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:5543:0:b0:59a:622:89d8 with SMTP id e64-20020a4a5543000000b0059a062289d8ls2276815oob.0.-pod-prod-09-us;
 Wed, 14 Feb 2024 10:44:47 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXvDhl/9Cg5K+RNWN6Xck3kiPsZA89IM7BMD4fYI3wLWefDrJRXvqAhSw5OjanN4f/xPKQKYvq/bvLjx+Ew9lFFqRb5EbA4q8sEHA==
X-Received: by 2002:a05:6808:1250:b0:3bf:f05d:a65c with SMTP id o16-20020a056808125000b003bff05da65cmr4389980oiv.29.1707936287318;
        Wed, 14 Feb 2024 10:44:47 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1707936287; cv=none;
        d=google.com; s=arc-20160816;
        b=ik4+TED9v7hlmmyU2bvCCAgZTuqbP9R6+RZl5Xtx73yTJTsmV2ZBMNGCSp6h5DdT3W
         2kYWbNj5IXi21U0EemJcMd3hfHqa6Cr7cluG1QF+nLl3Wx7Lq9h0AJKV0rbm2YfxSTrF
         7DhjpodtBFj4w9dTVkqknfeTK6dKcdqWZo9Ea5Uo730gQxStCWne28sg+i8AjFnPEuhq
         qG9izWJ1ZWu4+JukB2Bl7tmbIlBW7tUN+0Z04zS6RNbqqB0JORzsI4H0CBazx7C3Ra00
         4Ull3dDpuqzL3Zic6oNrKXnJ+KDMt1HprAY/TFkSDLkSRiNuybOO6hxg7FXQGWFml9Nv
         sE7A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date;
        bh=SPs16kDmgcgEiakduqPfzaImLWB9NgycWTd/sSfXcDE=;
        fh=AMLq3mzuDbsrRnwZHHrtCD9g4/t/zczB5kzmvX5fhHY=;
        b=nGZLvpGuRmujmrtXWOEG8aIhajVJchv/X2zNs/q383GL2TEFr5vS1DJ1t62E1Lu97J
         bmZUIEPjnqZCDGEYTVnqKg3nJvieozNYbD76VV2QVw3am75LZkrZ1XG5jTtSnY8I1Bcj
         ltKGLyPpBrIBubLaLju3Vg9+byguy9GsLDoqumtMWyd5zBmoZ1wTl1KKb/klnuE8cvaW
         WUGRLW1aAHU2PPopEHN0osFCeQeW1/WTMnNIIKrNeAfRYN1hIZ8OJyAZi+5gg3HJ/mnv
         CIwiFqBBhmvcYlor+v9eguxvukPlAhgO0VOGlGMTVHQYWpaQeJP5sQRS7u5lKFDVWoQN
         Hg3w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of andriy.shevchenko@intel.com designates 198.175.65.19 as permitted sender) smtp.mailfrom=andriy.shevchenko@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
X-Forwarded-Encrypted: i=1; AJvYcCVr47Zz+CRGOELcmtes+WHEFa2A/2TLf1huUruT9qOvGQDC2vZQ/lU4YTifKU5hEAQQzWtCXsvAo7XG/flPRJOjVcEZlgT1EapYnQ==
Received: from mgamail.intel.com (mgamail.intel.com. [198.175.65.19])
        by gmr-mx.google.com with ESMTPS id uc6-20020a05620a6a0600b0078731b86e21si64704qkn.1.2024.02.14.10.44.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 14 Feb 2024 10:44:47 -0800 (PST)
Received-SPF: pass (google.com: domain of andriy.shevchenko@intel.com designates 198.175.65.19 as permitted sender) client-ip=198.175.65.19;
X-IronPort-AV: E=McAfee;i="6600,9927,10984"; a="1850790"
X-IronPort-AV: E=Sophos;i="6.06,160,1705392000"; 
   d="scan'208";a="1850790"
Received: from fmsmga001.fm.intel.com ([10.253.24.23])
  by orvoesa111.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 14 Feb 2024 10:44:46 -0800
X-ExtLoop1: 1
X-IronPort-AV: E=McAfee;i="6600,9927,10984"; a="935617409"
X-IronPort-AV: E=Sophos;i="6.06,160,1705392000"; 
   d="scan'208";a="935617409"
Received: from black.fi.intel.com ([10.237.72.28])
  by fmsmga001.fm.intel.com with ESMTP; 14 Feb 2024 10:44:34 -0800
Received: by black.fi.intel.com (Postfix, from userid 1003)
	id B4D90204; Wed, 14 Feb 2024 20:44:33 +0200 (EET)
Date: Wed, 14 Feb 2024 20:44:33 +0200
From: Andy Shevchenko <andy@black.fi.intel.com>
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
	keescook@chromium.org, ndesaulniers@google.com, vvvvvv@google.com,
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
Subject: Re: [PATCH v3 00/35] Memory allocation profiling
Message-ID: <Zc0KEfoCVvP1kWvA@black.fi.intel.com>
References: <20240212213922.783301-1-surenb@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20240212213922.783301-1-surenb@google.com>
X-Original-Sender: andriy.shevchenko@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of andriy.shevchenko@intel.com designates 198.175.65.19
 as permitted sender) smtp.mailfrom=andriy.shevchenko@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
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

On Mon, Feb 12, 2024 at 01:38:46PM -0800, Suren Baghdasaryan wrote:
> Memory allocation, v3 and final:

Would be nice to have --base added to cover letter. The very first patch
can't be applied on today's Linux Next.

-- 
With Best Regards,
Andy Shevchenko


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Zc0KEfoCVvP1kWvA%40black.fi.intel.com.
