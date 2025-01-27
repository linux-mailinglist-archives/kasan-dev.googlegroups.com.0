Return-Path: <kasan-dev+bncBDLYD555WYHBBS4S326AMGQEGP7B25I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3b.google.com (mail-yb1-xb3b.google.com [IPv6:2607:f8b0:4864:20::b3b])
	by mail.lfdr.de (Postfix) with ESMTPS id F2446A1D696
	for <lists+kasan-dev@lfdr.de>; Mon, 27 Jan 2025 14:25:32 +0100 (CET)
Received: by mail-yb1-xb3b.google.com with SMTP id 3f1490d57ef6-e5789a8458esf11561424276.2
        for <lists+kasan-dev@lfdr.de>; Mon, 27 Jan 2025 05:25:32 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1737984332; cv=pass;
        d=google.com; s=arc-20240605;
        b=LKOniBtEQGuktf4Gz3HjMu3zsxWl5wyjaGWE12SNSdjtnJOp6eRKh839mwQLjhR4UW
         mvzwOWM0tR3wPPWdPkHZsAlvKQX5xwU4EroplbPUtl47xRTFQ4Jxrsm4+TAlujltrf7c
         B3C/F8DIyt81MWBNUyRgvFM7CoDPobOt/3qFU6/0WfS0KUItVtYFnIkBVdOZID2RJWx0
         6ICC9jM4MWncUWQ8FaL4/duuev5FCeU6mWi/HO/uHvIaGqm7mY2AwaJMXk9+2BHSRiyT
         YXDYKHlQoihOsPre/DLsIN/5eZrNOmPOOADKWTjTAnuCpW63nFURkl6id3BdB5yogwCd
         RMcw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:organization:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=WlBJmNYHw3J2slQ7++ojZrqXtLrPYTATqSsM7tTw6Aw=;
        fh=KwVfba3omgNTfwncwdkmbHDNHm6sp5dPDIfRkzQj9sk=;
        b=eRbwMusyyalsefrTBp11nbXYu18iCFlLxF4zwi5kCDYBlV3yDCaMmrvluRKkVLvKo0
         Y+YvP5I8GbnnBqfKYrhtHBqPj0bHGsqtMQd0Boqjp+MS46P/J2lIfQGxG5oHWYQhfsgP
         O3DNJskKZ1In6MLSTVaTxMYdx910oeLGV9ReleFfQmuA9OqTzvPQBkEKO7AlkaYKmYVT
         Y5YcL3uggUEMHQz4cAKS9T2S/ky3qbVpTpmJCwmdYUCasYlnEuet1enQ5AF8GbHDOq8z
         WvIqmL7J0K3SvSzIF8rG2aOrRC8O5BrvKW9A1GGzmyyQDXaaduRwpM9+4UPzApf9r088
         aBZg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=QSGUOvEZ;
       spf=pass (google.com: domain of andriy.shevchenko@intel.com designates 198.175.65.15 as permitted sender) smtp.mailfrom=andriy.shevchenko@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1737984332; x=1738589132; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:organization:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=WlBJmNYHw3J2slQ7++ojZrqXtLrPYTATqSsM7tTw6Aw=;
        b=aAoHxgJDFFnWeHsy0k9MeWs4WFEbLy0t8x1b2n66/Ssvee9hnf/YaUHw1KpATXzrC4
         +Yoftgxft2k2N13hV25oQsOOdXUeWMc/yRaFxeGsX0lNTx+N+oxjg50kDw3xhql1TZMT
         TD3dL5suE2nhNnEMCTOsDMKZ2pqi/7c2StjK45C/2l+2/6i7i6bO9VgSPiAovnneBVdf
         dkuOM9wEsxZr8cPQZySUTJ18laSfT3V6tO+P6COwz4e3S+o0UJ0H628lWMa/gRswEoG0
         s+ISvJCW8beE6veA86DPn1vuTz+wRgIyeTAzXlqpKxcL+0PsoQ3mkVogY9WKz3SXiKIF
         MKFg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1737984332; x=1738589132;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:organization
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:x-beenthere:x-gm-message-state:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=WlBJmNYHw3J2slQ7++ojZrqXtLrPYTATqSsM7tTw6Aw=;
        b=PBCK2hvp8flivZBL2LoYER0uQn7kEhhd/TnWrHD5vQvOEwVzF5wLMlgrGLtOm1lXps
         a8hlkS2obNhtfgpco9D+5I2tQDRbUGcuOUe5kt21ABACvIfS7jI7s8BJ4xQeJJBU70lv
         9s7o8v8tcljMW2wNnf8lHkQ5Wu/Dw92/rRaUVc8+59Zep3XOLpAorIhuoahQ3EX3rHfK
         w5xn+7F+J6/ojfyMExy6+oiDiuBI/b1vc53J1gxsWGLFaEdpzokOfE4sHxwJp4sw5rg6
         WjZ3lVvEwph/CCb8sfmWqSfEFyNEWDZoE3yANK9pfaWZmOzUiqnJ1VxY1/wgiXIW9Cbd
         p/cg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCU5UcQDsVNwa4j7VIMdc+YqDiEP8UyL/PhBmmFPO+EAJk3+SLtPPb7Dg2/f4HqIM+gbVPnZqg==@lfdr.de
X-Gm-Message-State: AOJu0Yz2Mw+R9h8DJJKtpVKZ7LtTiZk6YmXw7IBy9EBzK21S9KH6pic2
	nZf4Wo6zJLPdUBjFIlDCeWjm/ig3TM55qexK3cXrl3ULncO1HjVG
X-Google-Smtp-Source: AGHT+IEyl0Jcbn29441OBjjObT/2UKKjzLt7N0tOaCKiZvyPhsz/mTgVUinbMWKmGj2NdAEMca6SUw==
X-Received: by 2002:a05:6902:12cb:b0:e58:148c:ea39 with SMTP id 3f1490d57ef6-e58148ceb0fmr15261231276.0.1737984331656;
        Mon, 27 Jan 2025 05:25:31 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:ae60:0:b0:e57:ff95:45c6 with SMTP id 3f1490d57ef6-e5825aa9cccls4108560276.2.-pod-prod-06-us;
 Mon, 27 Jan 2025 05:25:31 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWbRhynCOo0HW9we9m2l2qEFLf9sJPa/qBnPX4BeZ+We2tkC0JG6HutvndPOzODKBdXQczUoPhVG38=@googlegroups.com
X-Received: by 2002:a05:690c:c1b:b0:6f6:cd43:543c with SMTP id 00721157ae682-6f6eb93d119mr304833717b3.34.1737984330842;
        Mon, 27 Jan 2025 05:25:30 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1737984330; cv=none;
        d=google.com; s=arc-20240605;
        b=EsQBv27zDD8tU8dFzyNWTCRDJj6qaqpfKw6mYJIIlypepS5u3sFZ3CO1EktH1bFQf+
         5MMQFpOUkBkYg0We7Cirx/ezCjkfx1XWaQt1yvVHfDOtFwWQISGgI/IKKLzFebGdmMk/
         Mua0kQlw4GP803OjH7yRc46FaIIit8cUCjvZEeTdoU8ucPXc7Vw1/4qHXvHkq5123ZIs
         VpyQ9os7LEUr8vqkKWEbDnaCQgwhYBQx4Z/6augdgHM4356zTVBUqQemlXDPeGGx7Sqg
         1VYVW00TB0trSNLk1ayx6kXscawt/KQs3X3k8fJWCCwpDriDiv0DjnjGXZlPLCyRSmyG
         /7nA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=organization:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:dkim-signature;
        bh=8zhSZmwclT1lFpSMh22BW/UMVkHqTlcnWx4Yhu83TkA=;
        fh=Li9bSppW1HNw2cEKGD7zwnYUh6FYm+0PuaCsOn2FCic=;
        b=LyyXEzhMhuSm3zDAMH/OppFY1DWGlXsfBW7JKUflyPFlSM33/w057TWA0vcaQudren
         qdrcTxQs0cnVMlhtgPMWGVS/5JWA+kl0fY837j76+rUdAxNMaPv8g0S24mAPHrWyJ7vF
         gNM+ALpGLfoGoXGYrXY2E88iMDmzmwVIcvhACKjoRkt0GWBajtol3jbQcDyKnYoSnhAO
         0LnXI/m064SVQcQgck5yB/GjC1fpl0/G8Gzcyss60fHsS9FwZnYXVy1ukBKYFCMpBmIh
         EYfewHGJnIgb43fvfrTFbczAhScOubKFZ6ZdiY9+WCSOl6vwyPJv1yRgk9Wi0j8xjkH8
         ldqQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=QSGUOvEZ;
       spf=pass (google.com: domain of andriy.shevchenko@intel.com designates 198.175.65.15 as permitted sender) smtp.mailfrom=andriy.shevchenko@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [198.175.65.15])
        by gmr-mx.google.com with ESMTPS id 00721157ae682-6f7578f9ba7si3695767b3.2.2025.01.27.05.25.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 27 Jan 2025 05:25:29 -0800 (PST)
Received-SPF: pass (google.com: domain of andriy.shevchenko@intel.com designates 198.175.65.15 as permitted sender) client-ip=198.175.65.15;
X-CSE-ConnectionGUID: gCB7I7y0ThuRbAsVqc95Vg==
X-CSE-MsgGUID: YuwyD2UMQFaDowkcxQcgug==
X-IronPort-AV: E=McAfee;i="6700,10204,11328"; a="42105367"
X-IronPort-AV: E=Sophos;i="6.13,238,1732608000"; 
   d="scan'208";a="42105367"
Received: from fmviesa002.fm.intel.com ([10.60.135.142])
  by orvoesa107.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 27 Jan 2025 05:25:22 -0800
X-CSE-ConnectionGUID: oOw//HyuRH2sXbDiVD3/cA==
X-CSE-MsgGUID: F7vXYkyrSx2N1gt4t3xT9A==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.12,224,1728975600"; 
   d="scan'208";a="131730368"
Received: from smile.fi.intel.com ([10.237.72.58])
  by fmviesa002.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 27 Jan 2025 05:25:02 -0800
Received: from andy by smile.fi.intel.com with local (Exim 4.98)
	(envelope-from <andriy.shevchenko@intel.com>)
	id 1tcP6l-00000005jpm-3fIe;
	Mon, 27 Jan 2025 15:24:55 +0200
Date: Mon, 27 Jan 2025 15:24:55 +0200
From: Andy Shevchenko <andriy.shevchenko@intel.com>
To: Arnd Bergmann <arnd@kernel.org>
Cc: linux-kernel@vger.kernel.org, Arnd Bergmann <arnd@arndb.de>,
	Michael Ellerman <mpe@ellerman.id.au>,
	Christophe Leroy <christophe.leroy@csgroup.eu>,
	Damien Le Moal <dlemoal@kernel.org>, Jiri Kosina <jikos@kernel.org>,
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
	Corey Minyard <minyard@acm.org>, Peter Huewe <peterhuewe@gmx.de>,
	Jarkko Sakkinen <jarkko@kernel.org>,
	Tero Kristo <kristo@kernel.org>, Stephen Boyd <sboyd@kernel.org>,
	Ian Abbott <abbotti@mev.co.uk>,
	H Hartley Sweeten <hsweeten@visionengravers.com>,
	Srinivas Pandruvada <srinivas.pandruvada@linux.intel.com>,
	Len Brown <lenb@kernel.org>,
	"Rafael J. Wysocki" <rafael@kernel.org>,
	John Allen <john.allen@amd.com>,
	Herbert Xu <herbert@gondor.apana.org.au>,
	Vinod Koul <vkoul@kernel.org>, Ard Biesheuvel <ardb@kernel.org>,
	Bjorn Andersson <andersson@kernel.org>,
	Moritz Fischer <mdf@kernel.org>, Liviu Dudau <liviu.dudau@arm.com>,
	Benjamin Tissoires <benjamin.tissoires@redhat.com>,
	Andi Shyti <andi.shyti@kernel.org>,
	Michael Hennerich <michael.hennerich@analog.com>,
	Peter Rosin <peda@axentia.se>, Lars-Peter Clausen <lars@metafoo.de>,
	Jonathan Cameron <jic23@kernel.org>,
	Dmitry Torokhov <dmitry.torokhov@gmail.com>,
	Markuss Broks <markuss.broks@gmail.com>,
	Alexandre Torgue <alexandre.torgue@foss.st.com>,
	Lee Jones <lee@kernel.org>, Jakub Kicinski <kuba@kernel.org>,
	Shyam Sundar S K <Shyam-sundar.S-k@amd.com>,
	Iyappan Subramanian <iyappan@os.amperecomputing.com>,
	Yisen Zhuang <yisen.zhuang@huawei.com>,
	Stanislaw Gruszka <stf_xl@wp.pl>, Kalle Valo <kvalo@kernel.org>,
	Sebastian Reichel <sre@kernel.org>,
	Tony Lindgren <tony@atomide.com>, Mark Brown <broonie@kernel.org>,
	Alexandre Belloni <alexandre.belloni@bootlin.com>,
	Xiang Chen <chenxiang66@hisilicon.com>,
	"Martin K. Petersen" <martin.petersen@oracle.com>,
	Neil Armstrong <neil.armstrong@linaro.org>,
	Heiko Stuebner <heiko@sntech.de>,
	Krzysztof Kozlowski <krzysztof.kozlowski@linaro.org>,
	Vaibhav Hiremath <hvaibhav.linux@gmail.com>,
	Alex Elder <elder@kernel.org>, Jiri Slaby <jirislaby@kernel.org>,
	Jacky Huang <ychuang3@nuvoton.com>, Helge Deller <deller@gmx.de>,
	Christoph Hellwig <hch@lst.de>, Robin Murphy <robin.murphy@arm.com>,
	Steven Rostedt <rostedt@goodmis.org>,
	Masami Hiramatsu <mhiramat@kernel.org>,
	Andrew Morton <akpm@linux-foundation.org>,
	Kees Cook <keescook@chromium.org>,
	Trond Myklebust <trond.myklebust@hammerspace.com>,
	Anna Schumaker <anna@kernel.org>,
	Masahiro Yamada <masahiroy@kernel.org>,
	Nathan Chancellor <nathan@kernel.org>,
	Takashi Iwai <tiwai@suse.com>, linuxppc-dev@lists.ozlabs.org,
	linux-ide@vger.kernel.org, openipmi-developer@lists.sourceforge.net,
	linux-integrity@vger.kernel.org, linux-omap@vger.kernel.org,
	linux-clk@vger.kernel.org, linux-pm@vger.kernel.org,
	linux-crypto@vger.kernel.org, dmaengine@vger.kernel.org,
	linux-efi@vger.kernel.org, linux-arm-msm@vger.kernel.org,
	linux-fpga@vger.kernel.org, dri-devel@lists.freedesktop.org,
	linux-input@vger.kernel.org, linux-i2c@vger.kernel.org,
	linux-iio@vger.kernel.org, linux-stm32@st-md-mailman.stormreply.com,
	linux-arm-kernel@lists.infradead.org, netdev@vger.kernel.org,
	linux-leds@vger.kernel.org, linux-wireless@vger.kernel.org,
	linux-rtc@vger.kernel.org, linux-scsi@vger.kernel.org,
	linux-spi@vger.kernel.org, linux-amlogic@lists.infradead.org,
	linux-rockchip@lists.infradead.org,
	linux-samsung-soc@vger.kernel.org, greybus-dev@lists.linaro.org,
	linux-staging@lists.linux.dev, linux-serial@vger.kernel.org,
	linux-usb@vger.kernel.org, linux-fbdev@vger.kernel.org,
	iommu@lists.linux.dev, linux-trace-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com, linux-hardening@vger.kernel.org,
	linux-nfs@vger.kernel.org, linux-kbuild@vger.kernel.org,
	alsa-devel@alsa-project.org, linux-sound@vger.kernel.org
Subject: Re: [PATCH 00/34] address all -Wunused-const warnings
Message-ID: <Z5eJJ199QwL0HVJT@smile.fi.intel.com>
References: <20240403080702.3509288-1-arnd@kernel.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20240403080702.3509288-1-arnd@kernel.org>
Organization: Intel Finland Oy - BIC 0357606-4 - Westendinkatu 7, 02160 Espoo
X-Original-Sender: andriy.shevchenko@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=QSGUOvEZ;       spf=pass
 (google.com: domain of andriy.shevchenko@intel.com designates 198.175.65.15
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

On Wed, Apr 03, 2024 at 10:06:18AM +0200, Arnd Bergmann wrote:
> From: Arnd Bergmann <arnd@arndb.de>
> 
> Compilers traditionally warn for unused 'static' variables, but not
> if they are constant. The reason here is a custom for C++ programmers
> to define named constants as 'static const' variables in header files
> instead of using macros or enums.
> 
> In W=1 builds, we get warnings only static const variables in C
> files, but not in headers, which is a good compromise, but this still
> produces warning output in at least 30 files. These warnings are
> almost all harmless, but also trivial to fix, and there is no
> good reason to warn only about the non-const variables being unused.
> 
> I've gone through all the files that I found using randconfig and
> allmodconfig builds and created patches to avoid these warnings,
> with the goal of retaining a clean build once the option is enabled
> by default.
> 
> Unfortunately, there is one fairly large patch ("drivers: remove
> incorrect of_match_ptr/ACPI_PTR annotations") that touches
> 34 individual drivers that all need the same one-line change.
> If necessary, I can split it up by driver or by subsystem,
> but at least for reviewing I would keep it as one piece for
> the moment.
> 
> Please merge the individual patches through subsystem trees.
> I expect that some of these will have to go through multiple
> revisions before they are picked up, so anything that gets
> applied early saves me from resending.

Arnd, can you refresh this one? It seems some misses still...
I have got 3+ 0-day reports against one of the mux drivers.

https://lore.kernel.org/all/?q=adg792a.c

-- 
With Best Regards,
Andy Shevchenko


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/Z5eJJ199QwL0HVJT%40smile.fi.intel.com.
