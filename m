Return-Path: <kasan-dev+bncBDLYD555WYHBBTHA6DEQMGQEXE3KVAA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc39.google.com (mail-oo1-xc39.google.com [IPv6:2607:f8b0:4864:20::c39])
	by mail.lfdr.de (Postfix) with ESMTPS id 9EF97CB9106
	for <lists+kasan-dev@lfdr.de>; Fri, 12 Dec 2025 16:10:06 +0100 (CET)
Received: by mail-oo1-xc39.google.com with SMTP id 006d021491bc7-656b7cf5c66sf1600890eaf.2
        for <lists+kasan-dev@lfdr.de>; Fri, 12 Dec 2025 07:10:06 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1765552205; cv=pass;
        d=google.com; s=arc-20240605;
        b=ZqbeLLSTbN+jfbxt8Ufzt69BeqKut8utH11UyX/koOaBH/M9fZSci/sBT5/JiXXwnl
         zhTsYBnNkoCwXI/Qz9JPI/jIcUQK6ov78YkDJ/7pG8111cIBlT1Sa0zO3Ij+mU217aBz
         DfF3L/kLLOGWgS/kYDDho+puD4G+f3KApCenZXjIV5fiB42L/rAD9AStWncA1vUqGnKg
         y5FB2azxMJil+T76ddzpmwTb8Kqyp37zpSkXbGgTlTGX/1qDcJghWguuMoUbCxb7RB1M
         lFBhtRB03OAzfef6bAF5S6Ti98IXAYXZ/5NjJDh1ZhoY/24614tT1x8h01M2r2TV49kM
         gAPw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:organization:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=YjaORiCLtXUfY68N+xAyuS909boVHOcXxGTYdlZJekI=;
        fh=T22qC/p4W5/Z+w0kduLPLdJepgMVDn/ANhVLKvkVZ+U=;
        b=ZpjZwVgU1//ahHEHohu85g2iEel42MqSwzUjZhYrB7l5gJIVbBaGSMK3F4L3iGP00M
         v59Gc0kki4vryyHIx1mVp3JuCDINshNvIkC1KyP7Q/rRfjLkylaObXUlrDWPD6m3c2iE
         KZzh0G8zVpDa6wEfLngoNPkDdBjPvYo4ZvWZdz8wOYKQ6Tf/YhXgYqXbJVb3A1NN1+UH
         xw8RtVPMGzrW2hl4AWAhqRvys24L5aafLvlRYnOzbHlAbaXQt9X+r0OY8yhVqFu9Zg95
         krJ4HrtlLxDoreb9EyVpmxPNTwdImA0I9r80SRyuIwDJrFyNHAeW5JDswV1v+vtl1/7r
         UHTQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=CEwVI4pB;
       spf=pass (google.com: domain of andriy.shevchenko@intel.com designates 198.175.65.19 as permitted sender) smtp.mailfrom=andriy.shevchenko@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1765552205; x=1766157005; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:organization:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=YjaORiCLtXUfY68N+xAyuS909boVHOcXxGTYdlZJekI=;
        b=khtIW7eDl4DuJQssAPjRa+lhroAXlBHsAINW/NAWUuSLpAIOxmjmu0je0aZVxd1i+k
         Lx2PjHRJS2xlizvX7QPT7r+rA0RkfZnk4+ZZOAHk7JHq/atn7HLGv/dwo2ZFF9aL6zkF
         3v0iQCIAqIYhYtkB/d32Ird3Mg58QiGcS7SCX7Dkqyg6FtJN7E0/qIzjBaenrBhn5xjg
         6gK3LGvMb6XhnihGVYmcbV/wdQS/UWbqQXmhxSOaUCblct4JcF2Q2Y6vrJlIlnKDcuFX
         4mZgUCQjT5ZIwyf/mUwspK+Z9BXaDpCzOh6Q8DAEgIXrtdzgK7RwhZWFqLAwxFKHicxH
         87dA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1765552205; x=1766157005;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:organization
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:x-beenthere:x-gm-message-state:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=YjaORiCLtXUfY68N+xAyuS909boVHOcXxGTYdlZJekI=;
        b=Ysz52dhjtwh4dD7inZi5i6QrIQhYhwCINMsDzsnufziSA+ze5cW7hyc42CGPGTKwhh
         PKrD3R3kPpA2qfDIu7bgI6pojHYjiaca9f3XmvxZLkbPcgjHCdmW+NxrwoQ+D193bRV7
         J8L9j/TEOPkn85Ox+2dk8p5iK/Wy4HlJ886o8kg3lgP9rzRZP9DyG0GKhYL8C6+d9Jy6
         rbef9nnDcYi/O5q/fMKNBaP/DEHcFWv65wiDD3ZTBGpLpWzh6PQGU0F4XUbQpNyPzgjl
         CSTMSoUv7OR3cuJYEm+lYAoMegAb5QjpWdFweM+O6WByb1sryIeeO9ytTUDMRpRRGUDt
         lNCA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVxkXZCgncJrYoGCL5tEr0+2mDmjlZJzXVlPK7p0FAaNTb7VWuMnIupcBLXhOG3SrS2dxpj9Q==@lfdr.de
X-Gm-Message-State: AOJu0Yw9RrUETWoapZnJEEsy1K0qTfmdGMU6mng9AcvUE3kdZLnsD094
	6B3FH1O5ArBe1Rfxh61Fnn38AznHPt2YFSdBuwkyJH5fhas+G9JdEcBy
X-Google-Smtp-Source: AGHT+IFfj425P6PzOSZTDSdsw6EtItmjmvY/TqvBc6V+ZgaSbArs9aVbkQUL0FWk37yvK5heUmlAdw==
X-Received: by 2002:a05:6820:2207:b0:65b:35fe:4323 with SMTP id 006d021491bc7-65b45226095mr1330610eaf.67.1765552205005;
        Fri, 12 Dec 2025 07:10:05 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWbtH9u3/X+zqgzQrzcsRwdUl46p3hGaeAEyNtV69RZDNw=="
Received: by 2002:a4a:bb8f:0:b0:65b:2551:35e7 with SMTP id 006d021491bc7-65b4399cb5dls439827eaf.1.-pod-prod-07-us;
 Fri, 12 Dec 2025 07:10:04 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVmbFU+YfF1CBWX1P8BaY9+3neoHI+OY/88gMtmbXMYy68hJGVNa4yRRhcf9K2RvPB4pT9BMQeF9EU=@googlegroups.com
X-Received: by 2002:a05:6808:398c:b0:453:7a2a:6453 with SMTP id 5614622812f47-455ac989103mr1122480b6e.46.1765552204222;
        Fri, 12 Dec 2025 07:10:04 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1765552204; cv=none;
        d=google.com; s=arc-20240605;
        b=DJcXA4vfBVjsBzIAEDmvqHL3mnP9ATuV1WqUMYR49WnIG1EVkc0qeayb6TJ7SQnt1W
         EZXFNazXJcDNjVjOnX2I3kXhDAmwsaAGwVpIwXD0VdNVxrvgycNdeGie4MhgDUFszWSK
         RXcd/4zHDNqlLgn3hrF9zC3umuEIT3iYfgHOmDIIDj9tRbYx7YaB8aQQ4wIqXaZdmISH
         lSFKzO3b56fM5pa5sIvM7CEj5IpN6+/Gwyi2jAZcUWlpSP/ciJ6vppXad78uigC6qK5A
         qxmilmo82STVJfQu0VHsXQj8n4BgclSbq9iy6vtJ0JcjyH4DGuvfh9d8sRW7nFFrAFpl
         QY2g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=organization:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:dkim-signature;
        bh=5VKDfy+K1GgUhNW5FkCqib+stquGwqC7Rcl/vg0Asqw=;
        fh=srVnkgPR0L625Jq1b5bc9B8Tc3KpgW023ASvhlOZx6U=;
        b=lJcmHZnNCB4MZ9z+M8Lu/d+hsnmNWn+ufAB9/TxwxUuv8RYodsPW6Ppd8gTVIfl6pH
         vYsWovl0ZHDE5G+UbTaWBhJUVJvozNuLshfAZe4LclvE4JrqlXsKgELGBMB6InreTSr1
         EUcSHKIIl04FvmgCyhIjkuAghSfDrWwMS8M/c/gzpdGEKzya8tspWAzrzhZK6WYqRwei
         hysA3uYFdgwSy14Gqp3Kp9+2aWuGH2qICSWrrNNee7T+PjSzprNA1LOnon/6UXuvDuzd
         AmeztEuRLNb+nHRVz5E3+NZLJVXEIZ97R6jla8I9dXZOxOiB2ZAUqBB1Ao9FO1tM7bt/
         h2bA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=CEwVI4pB;
       spf=pass (google.com: domain of andriy.shevchenko@intel.com designates 198.175.65.19 as permitted sender) smtp.mailfrom=andriy.shevchenko@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [198.175.65.19])
        by gmr-mx.google.com with ESMTPS id 5614622812f47-45598b60a32si142812b6e.1.2025.12.12.07.10.03
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Fri, 12 Dec 2025 07:10:04 -0800 (PST)
Received-SPF: pass (google.com: domain of andriy.shevchenko@intel.com designates 198.175.65.19 as permitted sender) client-ip=198.175.65.19;
X-CSE-ConnectionGUID: COoCUbt0QCKZGe+GEoI77g==
X-CSE-MsgGUID: 3ot5jZmmRHyRzG0a0DOzQg==
X-IronPort-AV: E=McAfee;i="6800,10657,11640"; a="67430968"
X-IronPort-AV: E=Sophos;i="6.21,144,1763452800"; 
   d="scan'208";a="67430968"
Received: from fmviesa008.fm.intel.com ([10.60.135.148])
  by orvoesa111.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 12 Dec 2025 07:10:02 -0800
X-CSE-ConnectionGUID: RL4aPco+TpyRA01jwc33Yw==
X-CSE-MsgGUID: w9WQhZahTXmmhDgvv8vikQ==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.21,144,1763452800"; 
   d="scan'208";a="197380979"
Received: from cpetruta-mobl1.ger.corp.intel.com (HELO localhost) ([10.245.245.181])
  by fmviesa008-auth.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 12 Dec 2025 07:09:55 -0800
Date: Fri, 12 Dec 2025 17:09:52 +0200
From: Andy Shevchenko <andriy.shevchenko@intel.com>
To: Luis Chamberlain <mcgrof@kernel.org>
Cc: Ethan Graham <ethan.w.s.graham@gmail.com>, glider@google.com,
	andreyknvl@gmail.com, andy@kernel.org, andy.shevchenko@gmail.com,
	brauner@kernel.org, brendan.higgins@linux.dev, davem@davemloft.net,
	davidgow@google.com, dhowells@redhat.com, dvyukov@google.com,
	elver@google.com, herbert@gondor.apana.org.au, ignat@cloudflare.com,
	jack@suse.cz, jannh@google.com, johannes@sipsolutions.net,
	kasan-dev@googlegroups.com, kees@kernel.org,
	kunit-dev@googlegroups.com, linux-crypto@vger.kernel.org,
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, lukas@wunner.de,
	rmoar@google.com, shuah@kernel.org, sj@kernel.org,
	tarasmadan@google.com, da.gomez@kernel.org, julia.lawall@inria.fr
Subject: Re: [PATCH v3 00/10] KFuzzTest: a new kernel fuzzing framework
Message-ID: <aTwwQLc0HjR_GbTY@smile.fi.intel.com>
References: <20251204141250.21114-1-ethan.w.s.graham@gmail.com>
 <aTvLyFsE55MR0kHo@bombadil.infradead.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <aTvLyFsE55MR0kHo@bombadil.infradead.org>
Organization: Intel Finland Oy - BIC 0357606-4 - c/o Alberga Business Park, 6
 krs, Bertel Jungin Aukio 5, 02600 Espoo
X-Original-Sender: andriy.shevchenko@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=CEwVI4pB;       spf=pass
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

On Fri, Dec 12, 2025 at 12:01:12AM -0800, Luis Chamberlain wrote:
> On Thu, Dec 04, 2025 at 03:12:39PM +0100, Ethan Graham wrote:
> > This patch series introduces KFuzzTest, a lightweight framework for
> > creating in-kernel fuzz targets for internal kernel functions.
> 
> As discussed just now at LPC, I suspected we could simplify this with
> Cocccinelle. The below patch applies on top of this series to prove
> that and lets us scale out fuzzing targets with Coccinelle.

That's nice! Much better than having tons of files being developed and
stitched in Makefile:s.

-- 
With Best Regards,
Andy Shevchenko


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aTwwQLc0HjR_GbTY%40smile.fi.intel.com.
