Return-Path: <kasan-dev+bncBCS2NBWRUIFBBZWMZCRAMGQEBHVUW3Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x440.google.com (mail-wr1-x440.google.com [IPv6:2a00:1450:4864:20::440])
	by mail.lfdr.de (Postfix) with ESMTPS id DA1A86F544E
	for <lists+kasan-dev@lfdr.de>; Wed,  3 May 2023 11:16:23 +0200 (CEST)
Received: by mail-wr1-x440.google.com with SMTP id ffacd0b85a97d-3062a46bf21sf2304255f8f.1
        for <lists+kasan-dev@lfdr.de>; Wed, 03 May 2023 02:16:23 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1683105383; cv=pass;
        d=google.com; s=arc-20160816;
        b=oijVXk9UK3dqVDoZ+9tDK3dgBg8pY1YYlZW/FUd+Cya+ZJqLCh+hwqSoEoZlDdB36v
         PENA7Y67fRPkneKEuvJ5CHK8LWqG2DpEjrDnTY95nLLn5uJCZpUnLqB5CmsqgEmpIAJW
         uSzgz9hCWkFyXoBZAjCy6GrfJG3XudzGUel3mOIpUCyxlojL0pfDJw6be2/D9ISylDom
         uSLDvebXjB4bHPrEKXbY95AklspNB3v7DtTKrSj1+rgZOzA0o3pO5+f1Smwne9BUvZi0
         5+sfSTenQMsQnGU3JaNnnLOmuFaMLDfNSqkQ1fC9Cr7g5LwE7gcziSDNE0pIGIvSZM5r
         WoHQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=FpizLmUMCPxCxRq7LsBz3I/WqYSam9VhiYXZ49plDt8=;
        b=kN0bIq7TvJzcxfHiIkkgsn9Awbw8nEcsrUSDtb5HboJ0ynWrDbPvWN3HOk89AVZ4HR
         1yDKrWlO5demiFbRwcogDf1ocriIr1tq11u6Ea2R55exsGzJesv0JuCNi2Uy61Ue/VyM
         G8IYi95ducCFfAoJ8Jg+payN4vMfowDEzQRbZuMdK1qCmJ9AwKfo5fu8gxuqWq9c2GCm
         /9AOOqNiz4V28hEFqE+zzfW3LZS6MTIHKTAjGbmcTZV5x4UQH78wK0Bnjby6NoC9gFHa
         JNlofSwDIHEHzC3glYD9MVepmuh063IEqmpc1dkf9PR85KvILCIYNq6kJcKdufzZaskT
         DtEw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=CZumf72d;
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 2001:41d0:1004:224b::2d as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1683105383; x=1685697383;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=FpizLmUMCPxCxRq7LsBz3I/WqYSam9VhiYXZ49plDt8=;
        b=UaF2YoKm83uzP5MY0MMV1DM+d3ky79dnyf0uO+m+vAPtlFrWtS+z9S7VHHi70pHy3z
         IQbPjHEfYX8v14XdKxA3NkFzJdK27U/FLiJAKJwznskWZ3AM2zvkPq7wvAyaNpINiL/N
         eKwh0mjtnhCSA7g1DY1BU3DMSWxBoZjpoTLflgqaveKgI0QfMmveRxllKMDNb+CKp+y9
         8OKH0MYaVN8ldktdKBePV/pUr+9Q781jEIVMDOgDka9p7yUWZWO5jUv9CBJ1RfkLFqfv
         yJvgvUyxlruqMsdzDs76+rUAr9QWpmwDN9xP3ZEisDBmpfJI9O0QzoYR8plk8jsOKAsG
         Zgkg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1683105383; x=1685697383;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=FpizLmUMCPxCxRq7LsBz3I/WqYSam9VhiYXZ49plDt8=;
        b=S66W/b7XQrCoT40hFuDqtMicudYp1SPdoUGI1Pz5EmMMUBoiDFGenRdcwVDBX4HP8E
         4A+kJ84777Mld6jAGSd3gmE6Y46vkglsW7UUTqI3roAlv/KUniOkSNblJ+L3ewktfKu0
         qH9rwTmYnQcnE3shUH2ZK3i6lm/XDqyK1i81DlEYjPx1lAygUz3WcZTk6RWDw2J52bMU
         U+Byl1kJSBu7NeGVptvyr/0tdumE6+65y2eExTlrq5WUXlHLXiyOhDld4kUN7JXO6T+i
         C+cAsPu7IITCavExIbfzwOfo71M1mN/GyJR9x/BjVlP03Y/1GlWctOv9WkPozHAimFLH
         FuKA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AC+VfDwyJJUHP0Z3I9mquqNX4EybrYdfm15f7t7P5X8HxCx/5d2wp1tf
	UmYpu+BaGm4p8SVFUBZmocw=
X-Google-Smtp-Source: ACHHUZ77Ry8vuGxObMHzD+RHfmbV+OPEkN3JiEqJabQlUy3AZKX1KJWsY7l0kCup2gRqV21dIYvftQ==
X-Received: by 2002:adf:ee05:0:b0:2fa:d7ac:6462 with SMTP id y5-20020adfee05000000b002fad7ac6462mr3299529wrn.11.1683105383113;
        Wed, 03 May 2023 02:16:23 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:5c0c:0:b0:2f4:1b04:ed8f with SMTP id cc12-20020a5d5c0c000000b002f41b04ed8fls2919463wrb.1.-pod-prod-gmail;
 Wed, 03 May 2023 02:16:22 -0700 (PDT)
X-Received: by 2002:a5d:4a02:0:b0:2ef:bc0b:e70 with SMTP id m2-20020a5d4a02000000b002efbc0b0e70mr15365172wrq.54.1683105381959;
        Wed, 03 May 2023 02:16:21 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1683105381; cv=none;
        d=google.com; s=arc-20160816;
        b=LtgdAfeKU1HalVUEMVUuf/VoybvXAEExxlc6rdVpeEEHtGQ3zN1c+r1oxLMKgsbp3R
         zDO1btRTqnOhDhXXuiwoqDUXyR9NZoaJZzI6WVtriiGgXQ4tmes2Sfui3QguhR9+3+kQ
         XQ39XfNMg181M2ri7kRUnjO4lsWpteGlTUQ9oGJ0HHF4l3q59N6re/KpLOrUyYMtWSzh
         Mp9eZUlBsiQpSKrIMg09g8VP4Yx4ITnG7x3916hSoO9QnuTCh1M7gVPpUgCxUBsdiGY2
         NK4g80H7rhJJ/19HjWWbM1sh/gIUc/iDLXPBXj34HpG2ET+vId7s6upGIuAIe9hX7ZKg
         MH+g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:dkim-signature:date;
        bh=rDmvTxexy8RqBi9izHKM2Pvx/4yBq3qFG2lSYNPsBT0=;
        b=K6l3xbC4gqnZmGvpe4JKlYgm7Pc/OLs5McSZ/z8T1RAuP3e/+pkCJsGztI6+jRuOS6
         PKcTD1/IQ9GN0tyWkkkhOzKoOdxlQKS5U8l59G7t2JZj3ZGiENrnmEW21pNNxGND+Zrx
         RNSc3767dgIsoazljF6mBhsZDcG4BB9FWfe8PkP+wKotBXx5Zvfthqh+ll0P7AWziOI5
         lcCmajQD14LsST+Yg12OMBjifmJGWqFMu199YMp6ivyL4PzNToQwLvdL5gRQ3R4vG5/g
         62rVQgqg8+jLjGdmN3AHGmEnOCoMja4dFDdQ89FlJQY7iC7l4XJWtQ95Ceyxk+iyXrBR
         JFGQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=CZumf72d;
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 2001:41d0:1004:224b::2d as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-45.mta0.migadu.com (out-45.mta0.migadu.com. [2001:41d0:1004:224b::2d])
        by gmr-mx.google.com with ESMTPS id az28-20020a05600c601c00b003f173302d8bsi64764wmb.1.2023.05.03.02.16.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 03 May 2023 02:16:21 -0700 (PDT)
Received-SPF: pass (google.com: domain of kent.overstreet@linux.dev designates 2001:41d0:1004:224b::2d as permitted sender) client-ip=2001:41d0:1004:224b::2d;
Date: Wed, 3 May 2023 05:16:08 -0400
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
Message-ID: <ZFImWLvv0ILJ+V2F@moria.home.lan>
References: <ZFAUj+Q+hP7cWs4w@moria.home.lan>
 <b6b472b65b76e95bb4c7fc7eac1ee296fdbb64fd.camel@HansenPartnership.com>
 <ZFCA2FF+9MI8LI5i@moria.home.lan>
 <CAHp75VdK2bgU8P+-np7ScVWTEpLrz+muG-R15SXm=ETXnjaiZg@mail.gmail.com>
 <ZFCsAZFMhPWIQIpk@moria.home.lan>
 <CAHp75VdvRshCthpFOjtmajVgCS_8YoJBGbLVukPwU+t79Jgmww@mail.gmail.com>
 <ZFHB2ATrPIsjObm/@moria.home.lan>
 <CAHp75VdH07gTYCPvp2FRjnWn17BxpJCcFBbFPpjpGxBt1B158A@mail.gmail.com>
 <ZFIJeSv9xn9qnMzg@moria.home.lan>
 <CAHp75Vd_VMOh1zxJvr0KqhxYBXAU1X+Ax7YA1sJ0G_abEpn-Dg@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CAHp75Vd_VMOh1zxJvr0KqhxYBXAU1X+Ax7YA1sJ0G_abEpn-Dg@mail.gmail.com>
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: kent.overstreet@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=CZumf72d;       spf=pass
 (google.com: domain of kent.overstreet@linux.dev designates
 2001:41d0:1004:224b::2d as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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

On Wed, May 03, 2023 at 12:12:12PM +0300, Andy Shevchenko wrote:
> > So, are you dropping your NACK then, so we can standardize the kernel on
> > the way everything else does it?
> 
> No, you are breaking existing users. The NAK stays.
> The whole discussion after that is to make the way on how users can
> utilize your format and existing format without multiplying APIs.

Dave seems to think we shouldn't be, and I'm in agreement.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZFImWLvv0ILJ%2BV2F%40moria.home.lan.
