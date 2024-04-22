Return-Path: <kasan-dev+bncBCY6ZYHFGUIOXOUYWEDBUBCET7FPE@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x739.google.com (mail-qk1-x739.google.com [IPv6:2607:f8b0:4864:20::739])
	by mail.lfdr.de (Postfix) with ESMTPS id 4E41A8AC699
	for <lists+kasan-dev@lfdr.de>; Mon, 22 Apr 2024 10:18:53 +0200 (CEST)
Received: by mail-qk1-x739.google.com with SMTP id af79cd13be357-7906ec81e49sf134412785a.1
        for <lists+kasan-dev@lfdr.de>; Mon, 22 Apr 2024 01:18:53 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1713773932; cv=pass;
        d=google.com; s=arc-20160816;
        b=vOYn52xJ3HCY1NCGXSUJ7pi6L+nr7tBxKjs94f2u9Pbsw3whY1On5nvA7eWholLYhG
         dcpy1LtA1RytKYjRx6M36NC5z0rYc2ASDEhEz6d5Pvj6TOTHSO8MkYaAC3MuvHKO1pJ6
         ZpCrhQyA0NE6m9FYg0McDmSTKH4e8wQ2ePHqxoJDgsYLW300GZGCuh+FyVXSm/2vWunZ
         0Fqfvi23JW4688ao9BwOXDRjrh9LEVHXLsKEJhKQT96pn/zOXgMyCW7NFT1NloBUqrrC
         SiwjZxgBG4ai2Tp0W99DkPlWhIVxfmrHiIXKTvZs8QVnW4hbEzy3+1+37GF5ex5aZfCN
         +cVA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:date:message-id
         :subject:references:in-reply-to:cc:to:from:sender:dkim-signature;
        bh=w7ZqnShg7AC8jg8kCpddKK5qaSLL7eLNEtGh0zO5M+0=;
        fh=klNj1DnsPFQ6eeyzbejQQQjrldWGd3rbbOz6SMTOC9A=;
        b=aY+0YQUSs38EvCSuMo0uDB04SGO/6ddxG1Hdvd8AGzjWL9vfE1zdg0vnNFMsXq9to7
         P/fIisA/su9h7YTSPn751j7+MRCACcWeIzPesTv+9OqfQjrXi3XWH2rMU6WMc8n/ml6g
         ekSX1YEpo9r/s+FYF7CSOqpc4Z3zjiuB0NzLeuRkZJkEyC/s9P6k/VnNG3wCS4DFlBoc
         wze2OMl73BIzhyhodAIoL17/YYU7+xBss13BzhHrS+yo882753nquSppv4IdSI8e3a4i
         B5y33D+vlu/2nDQR1NGstOejwYr8WYh9vB2G53IFk8kNyEF/p6WLAK3FjV3UWG4A9rOJ
         3nGA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of michael@ellerman.id.au designates 2404:9400:2221:ea00::3 as permitted sender) smtp.mailfrom=michael@ellerman.id.au
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1713773932; x=1714378732; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:date:message-id:subject:references
         :in-reply-to:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=w7ZqnShg7AC8jg8kCpddKK5qaSLL7eLNEtGh0zO5M+0=;
        b=YG+fHApnM5cDaU1Mbz+Bk0npo/WZLsohsNmfOP6Q3qIWIumBaZmxtXerMEJpCRNeIA
         gpop0t8aHt6gAppnrIb4ctP7K3l/rU/gRY6+DvbT2pKNQhxgvuImifPs/1FxP8ODEhs2
         dWfpToijZ5g+QZigtE88+uRMEcua5twP/TBcnznRCKXgvH43pH0yTx5FgyOKl/CHKYae
         +HXcTabUAcUEgFWHC61E5gLEDyZxKRuenxQMaic/NKht2GG3UOSPGeIfGF/CSlQsNVLT
         23SFV6lSzsFjHDg9u68fg60PDxy9D/S2XR2bAwv6hTk2OBsgDUePprM1pEjYXHwDvH/q
         x69Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1713773932; x=1714378732;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :date:message-id:subject:references:in-reply-to:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=w7ZqnShg7AC8jg8kCpddKK5qaSLL7eLNEtGh0zO5M+0=;
        b=b4UC4W6fLJ8JnmGV93Vw6RBZrGiaerqaFY0lGTviHqwqCBChyFSDSyDa1eXj8NDfHG
         8oETbsuk7aCY4QilCfjRz3H99fGImQrMUN/TT+DTV7EWH5yOlJHgYhKUOzkDC3vCQpHl
         9ppJkCqZot0eoXPI7T2HiZZVgV+ZkKcwZVaQjm/SixzPf67RWWDuEUNSAvD0TvdBKICV
         BbpOF/FaOljp6YD4jNjoiq2KXunOA+56HgC7IEBGeuIMY93t+8Y5pY+v/nPSTg4U1frW
         ONbIAcS7v/sZPCXHvrf4/tR1pL6y+kHqyIlRQjuDXCZ3kr6OLrxs0yEnWIoF60IJ4DD2
         CxVg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWFPVDQghSFTTCXAfJ2BELbUkzbBTHS9qWI4FKUdnsfGsWr3R/jsEpAtc/R3EM4FKZ/5uH8z2+2f/6uu+Jsmg8rWTaQmdl1+g==
X-Gm-Message-State: AOJu0YyhfTZTb3siE/OuHwu9q24cuCSGPoUn3W+6Ia/iKrXT9eah2EsY
	rDPFKIHl0ZzjKx6pdL5JsqXJT4DoXTRmYdvMDHq14eNbZkhTyARe
X-Google-Smtp-Source: AGHT+IH2w0qPMnsWK7W/Jp3EwfCUs3tUh7lTtdAYKWNQ/O9Fiur8fjXKoBa+9dDYUcq78Ary29Si+A==
X-Received: by 2002:a05:6214:11a3:b0:6a0:7a3d:841d with SMTP id u3-20020a05621411a300b006a07a3d841dmr3235674qvv.22.1713773931777;
        Mon, 22 Apr 2024 01:18:51 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:130d:b0:699:27da:1247 with SMTP id
 6a1803df08f44-6a05d77ebd7ls44893486d6.2.-pod-prod-08-us; Mon, 22 Apr 2024
 01:18:50 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVWddeDdNZd0V9mDVGFeDOTbZIDSkriB1k7WFHWRnhugy86Zj9Gx3D27rTUl764JVUVZkskHZ4g+M1Nz7/fWwmlVvDGe6Wf2psMqg==
X-Received: by 2002:a0c:eec1:0:b0:6a0:804a:c3e9 with SMTP id h1-20020a0ceec1000000b006a0804ac3e9mr2561835qvs.47.1713773930589;
        Mon, 22 Apr 2024 01:18:50 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1713773930; cv=none;
        d=google.com; s=arc-20160816;
        b=EeebMaqmWKUc+hrGglNK2w5SgoiiHu/F9rGR/FUVjjZ1yMkudiuz9q3fEmZLS6Hj8x
         oxRTuRMWLUrZn4X31T14EASCc+niAXLAlBhrtqGEDNiWFs+56Wr1vkRBFpmbfI90FRNw
         uwmJOTRb2695qu3eIUm77hhWnThTd4PrhG3Bo8RPs1UWLF3vZC6lWizOdycH6UJfCI1P
         KF0No/62zT4CKEnxA87iuNOYP9bAG8KnzchxGgOjtzmpYD6+dTxDVUnPoJ6RAk9rUEmp
         YuhOjw9Gpx96/rArBwDA/RRjCThbUK7U4oVFdQ3zHVycoXrzwpowW6IJHxZw/yUYVaJV
         vgBQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:date:message-id:subject
         :references:in-reply-to:cc:to:from;
        bh=xqHaI+XdxFuJ3WlZeDncB1aTCwCPpLjzmr2C2uh6xiw=;
        fh=oTApAdc9VTJRNGMBGF9rvKRk3Y6MxlOZ/FqsaTbeooA=;
        b=xDkp7jnU1kqAxiattF+U/44s2XYbCyCCUHcX8ARX2vJGqW6xGXtaV3wSNGXZV3xY/o
         Goie0KWM6Oj7OCgel/QcTU9LBeTV3QzHKCIREIGupmxMUdNfh2aHPSxMTqzh513jWMNB
         6BP2+KHtz7lT2/WLnnyCCfiou0114vKWu6do1Qz/pXuDwby5EWesKMro/03uNB+uMng/
         jnS3cqvaiqatByvSkGS+zHAIEH2feaDndEFv2BB07Xzc6Ko+NOzPDi3iB17864SyH84T
         7TzMt/wwpqXA0o41jajJ9DpoQfp8+NCIPsaLB/CdeTG+2hrhaFojXb+PvmLjGwN6HiBZ
         dMNQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of michael@ellerman.id.au designates 2404:9400:2221:ea00::3 as permitted sender) smtp.mailfrom=michael@ellerman.id.au
Received: from gandalf.ozlabs.org (mail.ozlabs.org. [2404:9400:2221:ea00::3])
        by gmr-mx.google.com with ESMTPS id i7-20020a056214030700b0069b52b5ada4si750367qvu.6.2024.04.22.01.18.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 22 Apr 2024 01:18:50 -0700 (PDT)
Received-SPF: pass (google.com: domain of michael@ellerman.id.au designates 2404:9400:2221:ea00::3 as permitted sender) client-ip=2404:9400:2221:ea00::3;
Received: from authenticated.ozlabs.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by mail.ozlabs.org (Postfix) with ESMTPSA id 4VNJ6g0Nzdz4x1R;
	Mon, 22 Apr 2024 18:18:35 +1000 (AEST)
From: Michael Ellerman <patch-notifications@ellerman.id.au>
To: linux-kernel@vger.kernel.org, Arnd Bergmann <arnd@kernel.org>
Cc: Arnd Bergmann <arnd@arndb.de>, Michael Ellerman <mpe@ellerman.id.au>, Christophe Leroy <christophe.leroy@csgroup.eu>, Damien Le Moal <dlemoal@kernel.org>, Jiri Kosina <jikos@kernel.org>, Greg Kroah-Hartman <gregkh@linuxfoundation.org>, Corey Minyard <minyard@acm.org>, Peter Huewe <peterhuewe@gmx.de>, Jarkko Sakkinen <jarkko@kernel.org>, Tero Kristo <kristo@kernel.org>, Stephen Boyd <sboyd@kernel.org>, Ian Abbott <abbotti@mev.co.uk>, H Hartley Sweeten <hsweeten@visionengravers.com>, Srinivas Pandruvada <srinivas.pandruvada@linux.intel.com>, Len Brown <lenb@kernel.org>, "Rafael J. Wysocki" <rafael@kernel.org>, John Allen <john.allen@amd.com>, Herbert Xu <herbert@gondor.apana.org.au>, Vinod Koul <vkoul@kernel.org>, Ard Biesheuvel <ardb@kernel.org>, Bjorn Andersson <andersson@kernel.org>, Moritz Fischer <mdf@kernel.org>, Liviu Dudau <liviu.dudau@arm.com>, Benjamin Tissoires <benjamin.tissoires@redhat.com>, Andi Shyti <andi.shyti@kernel.org>, Michael Hennerich <michael.hennerich@analo
 g.com>, Peter Rosin <peda@axentia.se>, Lars-Peter Clausen <lars@metafoo.de>, Jonathan Cameron <jic23@kernel.org>, Dmitry Torokhov <dmitry.torokhov@gmail.com>, Markuss Broks <markuss.broks@gmail.com>, Alexandre Torgue <alexandre.torgue@foss.st.com>, Lee Jones <lee@kernel.org>, Jakub Kicinski <kuba@kernel.org>, Shyam Sundar S K <Shyam-sundar.S-k@amd.com>, Iyappan Subramanian <iyappan@os.amperecomputing.com>, Yisen Zhuang <yisen.zhuang@huawei.com>, Stanislaw Gruszka <stf_xl@wp.pl>, Kalle Valo <kvalo@kernel.org>, Sebastian Reichel <sre@kernel.org>, Tony Lindgren <tony@atomide.com>, Mark Brown <broonie@kernel.org>, Alexandre Belloni <alexandre.belloni@bootlin.com>, Xiang Chen <chenxiang66@hisilicon.com>, "Martin K. Petersen" <martin.petersen@oracle.com>, Neil Armstrong <neil.armstrong@linaro.org>, Heiko Stuebner <heiko@sntech.de>, Krzysztof Kozlowski <krzysztof.kozlowski@linaro.org>, Vaibhav Hiremath <hvaibhav.linux@gmail.com>, Alex Elder <elder@kernel.org>, Jiri Slaby <jirislaby@kernel.
 org>, Jacky Huang <ychuang3@nuvoton.com>, Helge Deller <deller@gmx.de>, Christoph Hellwig <hch@lst.de>, Robin Murphy <robin.murphy@arm.com>, Steven Rostedt <rostedt@goodmis.org>, Masami Hiramatsu <mhiramat@kernel.org>, Andrew Morton <akpm@linux-foundation.org>, Kees Cook <keescook@chromium.org>, Trond Myklebust <trond.myklebust@hammerspace.com>, Anna Schumaker <anna@kernel.org>, Masahiro Yamada <masahiroy@kernel.org>, Nathan Chancellor <nathan@kernel.org>, Takashi Iwai <tiwai@suse.com>, linuxppc-dev@lists.ozlabs.org, linux-ide@vger.kernel.org, openipmi-developer@lists.sourceforge.net, linux-integrity@vger.kernel.org, linux-omap@vger.kernel.org, linux-clk@vger.kernel.org, linux-pm@vger.kernel.org, linux-crypto@vger.kernel.org, dmaengine@vger.kernel.org, linux-efi@vger.kernel.org, linux-arm-msm@vger.kernel.org, linux-fpga@vger.kernel.org, dri-devel@lists.freedesktop.org, linux-input@vger.kernel.org, linux-i2c@vger.kernel.org, linux-iio@vger.kernel.org, linux-stm32@st-md-mailman.stormr
 eply.com, linux-arm-kernel@lists.infradead.org, netdev@vger.kernel.org, linux-leds@vger.kernel.org, linux-wireless@vger.kernel.org, linux-rtc@vger.kernel.org, linux-scsi@vger.kernel.org, linux-spi@vger.kernel.org, linux-amlogic@lists.infradead.org, linux-rockchip@lists.infradead.org, linux-samsung-soc@vger.kernel.org, greybus-dev@lists.linaro.org, linux-staging@lists.linux.dev, linux-serial@vger.kernel.org, linux-usb@vger.kernel.org, linux-fbdev@vger.kernel.org, iommu@lists.linux.dev, linux-trace-kernel@vger.kernel.org, kasan-dev@googlegroups.com, linux-hardening@vger.kernel.org, linux-nfs@vger.kernel.org, linux-kbuild@vger.kernel.org, alsa-devel@alsa-project.org, linux-sound@vger.kernel.org
In-Reply-To: <20240403080702.3509288-1-arnd@kernel.org>
References: <20240403080702.3509288-1-arnd@kernel.org>
Subject: Re: (subset) [PATCH 00/34] address all -Wunused-const warnings
Message-Id: <171377378377.1025456.1313405994816400451.b4-ty@ellerman.id.au>
Date: Mon, 22 Apr 2024 18:16:23 +1000
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: michael@ellerman.id.au
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of michael@ellerman.id.au designates 2404:9400:2221:ea00::3
 as permitted sender) smtp.mailfrom=michael@ellerman.id.au
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

On Wed, 03 Apr 2024 10:06:18 +0200, Arnd Bergmann wrote:
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
> [...]

Applied to powerpc/next.

[01/34] powerpc/fsl-soc: hide unused const variable
        https://git.kernel.org/powerpc/c/01acaf3aa75e1641442cc23d8fe0a7bb4226efb1

cheers

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/171377378377.1025456.1313405994816400451.b4-ty%40ellerman.id.au.
