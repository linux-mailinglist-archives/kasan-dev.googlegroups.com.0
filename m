Return-Path: <kasan-dev+bncBCS2NBWRUIFBBEOYYKRAMGQEL74ZHTI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33a.google.com (mail-wm1-x33a.google.com [IPv6:2a00:1450:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id 1B5586F3D51
	for <lists+kasan-dev@lfdr.de>; Tue,  2 May 2023 08:22:10 +0200 (CEST)
Received: by mail-wm1-x33a.google.com with SMTP id 5b1f17b1804b1-3f080f534acsf20309105e9.0
        for <lists+kasan-dev@lfdr.de>; Mon, 01 May 2023 23:22:10 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1683008529; cv=pass;
        d=google.com; s=arc-20160816;
        b=Fsw42Vj+pG1ld8r58RCEcf6B2v2L+2sx90DjxaACwD/lqyb7V2JNITEN7szcel8zPL
         gLxVbx8xN6oYZZHJ2n3ygauS+dN9Yx3i7OJxFHLOBmeFGaqz2sl++qy/hvrDsyrhiXg/
         nzoDWslrut/wTw+L6qloACs/AJQgSRnRy1qHVnt4c5feTiFlSO2vEMbEBz37Fa0Pz3Sf
         zRkaBygmqG29H3FKNZoyerhM/HjCxp2nznsZQ9xHONSEywFM13APSdCZ8ml7T0WfcyO6
         tuq4ZPp6LPKxBFWaNjb4Nei1xadtIu2G1fW63UcK7h/u2wQ+7dmVfokcCUtd4LZYxAhy
         B+5w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=hBDz9Mh2SbgkMLh5neJ8LjNDvV+9klyj2ozryGJM3s0=;
        b=z3AwVQbTVT8eb8fpzLIsyNyq72mJxZI6A3/cRbfconLs7XIYRPXc3FCVnCW33hsXGE
         lHZZ0BoOm9a2OEqIU4/XzmFQnSKxqRmS4GgH6tyRr+elHziINU7R27A8NsuocuHbqr6r
         Pf2DMTVKnov8dsp36/f/xOYFA3H112K6wuOj3YRkDSWwKd1GQqk999v5hgRo9KVIyTVt
         OPwHUZcmp1s1/iyIh9msmOIM/8lrpchmg31FeLitOQrY/OPd/oR0notnRLZDHYQmGHkC
         I4wDPpEwgx7Og4W8gFNDqPeAagGu3vyIxYgxSHytfgM4nkoq5LZuokE9Tyfsjtrc24By
         bnKA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=XXE5oA4K;
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 91.218.175.3 as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1683008529; x=1685600529;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=hBDz9Mh2SbgkMLh5neJ8LjNDvV+9klyj2ozryGJM3s0=;
        b=eHl6auctNd1tyMilatlADkjBCViI/ra7mvxrYEdlBZ9w4X32c123BrzVE79hugfPnK
         394WEH5lKriOHXMHk/s7z0z3jeV3D4iRg/A/hZRfmXSR+c4d848KZNhcK79dQJPn04f0
         2UvlR9nFM+uMYCKpDR2pMtx3b8auoay0eK6m3eZecsJFB3/yD+1mV0oI8nniXi2TnsG2
         9a60nkGA2wlckQsDnZBfksTxoqNC2QBMzWp3ITPQbnQgXYboh7aoSyhbMRfQVN4P3/EE
         av87yIroiKVttnpN7tdTy/kbCrmH1JHq/+rITQgMqNljYBdXi0uqkENjbQcLIJ1Os0GN
         zwEg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1683008529; x=1685600529;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=hBDz9Mh2SbgkMLh5neJ8LjNDvV+9klyj2ozryGJM3s0=;
        b=Hx4VKW4OnOsWT2fjXkmV3+6ggfFmWMU53KFPmBlfUapl0vrMu9XsLRTUKC/D0dNY+B
         IUKQYJZvo14uN1/h05bp0TjxGXbNUS4bwQmhtNNmkKYTRLeHNiYmBkidHxjGLX3GAtcR
         q8MufYtvydRClI6oodetvjRgcf5GiEDJBM2d6LPuNsxmG65L8zyUTG4McaQXLR/9w+5Z
         KpxHjGPlVBYkUBh0nlbQSc+iPUqSMJDkSOgkZfAdxnYSk/iAYQdzruWSxMS69vDM/nJ5
         kg4UB9GxR+Kn9gIu2ahmA/hKLjT0PI6jgyGPTO0y6L7vvlLupdVr+8vwrsb8FKOZ2cTR
         pq0g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AC+VfDwkHlVtDoGOoVUq1RX3ct662WG+ezbMb+HSdGy4IYrxFAdnxL+G
	MP2BNm3beleOUEbRwGj2GUM=
X-Google-Smtp-Source: ACHHUZ7bBNHVxhzzTI6uK0BatfEO1MGsxyoNkJ3xnHZ2QxVyx8tJmdWPRloGzLm5T6zMcH7AjWnyJg==
X-Received: by 2002:a1c:f217:0:b0:3f1:758e:40f0 with SMTP id s23-20020a1cf217000000b003f1758e40f0mr2818344wmc.5.1683008529348;
        Mon, 01 May 2023 23:22:09 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:5a18:0:b0:306:35d:2f11 with SMTP id bq24-20020a5d5a18000000b00306035d2f11ls10644962wrb.2.-pod-prod-gmail;
 Mon, 01 May 2023 23:22:07 -0700 (PDT)
X-Received: by 2002:a5d:6291:0:b0:2f7:f6e:566 with SMTP id k17-20020a5d6291000000b002f70f6e0566mr12154564wru.31.1683008527691;
        Mon, 01 May 2023 23:22:07 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1683008527; cv=none;
        d=google.com; s=arc-20160816;
        b=RIKLZnizLOlt/CeuaWHUT33M+S+4ZHAggsNrNq1q2YQ8OVp2cJfgH8i0aFrJDqkcOu
         PCXjfFEwAzHPD3xsGErCUIzVeveD9sUvbCqSbRRAnh0R526py9xiaiTwKZf2kluF0YFu
         rgCbIYa5tDcbPZ2TD+QWW2EX6mdItx04gRB7jvx8yS6QQco0BAzuAa8PU2qtzTZCK4Wq
         HLoRVFXdYZ4plYQVOUtRoEoHlddgrP1RMsUmukizviaIjs0JChtwIMk1aqDEQRAuSKMy
         tJ3eYL2CDyMlAnmJqOsJTggOVFXx5C/Y4wStUPjGDFGhT+jYLDQkKy0iqCsnxMt944Uw
         C/GA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:dkim-signature:date;
        bh=Mq+P+Or5S2cDa8uRDb0VbMIKnPfazrh1Ie3ittG4NpA=;
        b=kT7MNeWdzlIhmNe10UEMlR2lu9eXye7EXHY572WmIPmzHhzhiYot+IYY3Cb1GEIqVV
         mn/SKKPBXT3lwKk1fjJlvwIfLMWlBuY8+sX6RXFX2Z5S1LmEIrn/zQelGyRwVWh8WSoW
         F1fownNqClNvlIJCNvq4sPu9MIXZtDpczyznVmphr8oXpdkEtb24A/kB0cx1IqHwYHp2
         XCF1gU4O1+KAlyq2YF0Cy8eCs/mP3piEPhnGx4n4bj36sbbFXmiiXMATYbIiXgFCwWdo
         tVvSzYwDN8Kns4D1RJsmRFUtrMGFpRpGNVX5QIwTkn6UKDyVI+rkANoPRQzA7LEB5zOP
         nFIA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=XXE5oA4K;
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 91.218.175.3 as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-3.mta0.migadu.com (out-3.mta0.migadu.com. [91.218.175.3])
        by gmr-mx.google.com with ESMTPS id bq27-20020a5d5a1b000000b003062eb5c8adsi215936wrb.1.2023.05.01.23.22.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 01 May 2023 23:22:07 -0700 (PDT)
Received-SPF: pass (google.com: domain of kent.overstreet@linux.dev designates 91.218.175.3 as permitted sender) client-ip=91.218.175.3;
Date: Tue, 2 May 2023 02:21:53 -0400
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: Kent Overstreet <kent.overstreet@linux.dev>
To: Andy Shevchenko <andy.shevchenko@gmail.com>
Cc: James Bottomley <James.Bottomley@hansenpartnership.com>,
	Suren Baghdasaryan <surenb@google.com>, akpm@linux-foundation.org,
	mhocko@suse.com, vbabka@suse.cz, hannes@cmpxchg.org,
	roman.gushchin@linux.dev, mgorman@suse.de, willy@infradead.org,
	liam.howlett@oracle.com, corbet@lwn.net, void@manifault.com,
	peterz@infradead.org, juri.lelli@redhat.com, ldufour@linux.ibm.com,
	catalin.marinas@arm.com, will@kernel.org, arnd@arndb.de,
	tglx@linutronix.de, mingo@redhat.com, dave.hansen@linux.intel.com,
	x86@kernel.org, peterx@redhat.com, david@redhat.com,
	axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org,
	nathan@kernel.org, dennis@kernel.org, tj@kernel.org,
	muchun.song@linux.dev, rppt@kernel.org, paulmck@kernel.org,
	pasha.tatashin@soleen.com, yosryahmed@google.com, yuzhao@google.com,
	dhowells@redhat.com, hughd@google.com, andreyknvl@gmail.com,
	keescook@chromium.org, ndesaulniers@google.com,
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
	cgroups@vger.kernel.org, Andy Shevchenko <andy@kernel.org>,
	Michael Ellerman <mpe@ellerman.id.au>,
	Benjamin Herrenschmidt <benh@kernel.crashing.org>,
	Paul Mackerras <paulus@samba.org>,
	"Michael S. Tsirkin" <mst@redhat.com>,
	Jason Wang <jasowang@redhat.com>,
	Noralf =?utf-8?B?VHLDr8K/wr1ubmVz?= <noralf@tronnes.org>
Subject: Re: [PATCH 01/40] lib/string_helpers: Drop space in
 string_get_size's output
Message-ID: <ZFCsAZFMhPWIQIpk@moria.home.lan>
References: <20230501165450.15352-1-surenb@google.com>
 <20230501165450.15352-2-surenb@google.com>
 <ouuidemyregstrijempvhv357ggp4tgnv6cijhasnungsovokm@jkgvyuyw2fti>
 <ZFAUj+Q+hP7cWs4w@moria.home.lan>
 <b6b472b65b76e95bb4c7fc7eac1ee296fdbb64fd.camel@HansenPartnership.com>
 <ZFCA2FF+9MI8LI5i@moria.home.lan>
 <CAHp75VdK2bgU8P+-np7ScVWTEpLrz+muG-R15SXm=ETXnjaiZg@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CAHp75VdK2bgU8P+-np7ScVWTEpLrz+muG-R15SXm=ETXnjaiZg@mail.gmail.com>
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: kent.overstreet@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=XXE5oA4K;       spf=pass
 (google.com: domain of kent.overstreet@linux.dev designates 91.218.175.3 as
 permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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

On Tue, May 02, 2023 at 08:33:57AM +0300, Andy Shevchenko wrote:
> Actually instead of producing zillions of variants, do a %p extension
> to the printf() and that's it. We have, for example, %pt with T and
> with space to follow users that want one or the other variant. Same
> can be done with string_get_size().

God no.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZFCsAZFMhPWIQIpk%40moria.home.lan.
