Return-Path: <kasan-dev+bncBDR7LJOD4ENBBN6UUSMQMGQELHWJWIQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3e.google.com (mail-oa1-x3e.google.com [IPv6:2001:4860:4864:20::3e])
	by mail.lfdr.de (Postfix) with ESMTPS id A0C5C5BDA5E
	for <lists+kasan-dev@lfdr.de>; Tue, 20 Sep 2022 04:49:28 +0200 (CEST)
Received: by mail-oa1-x3e.google.com with SMTP id 586e51a60fabf-1278ff55da4sf846393fac.18
        for <lists+kasan-dev@lfdr.de>; Mon, 19 Sep 2022 19:49:28 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1663642167; cv=pass;
        d=google.com; s=arc-20160816;
        b=aIiah4GxMzxQHfsdfwNcV904hvzGZft04axlyi0g1Pjax1dC1HKI3HHvpZWeFuqPus
         xnTIQIzprjaXZFM60E4R+Ij6MrdaIXfx3BFoua7hfg4/5r8AjXnU+rA0+fXyTrIjSmyW
         hOA6FgKhmmCR805fmLNW+NmWlnG1FOc2q2QWt+JaLk80Ig7irHlVHz2FXS6A7Z9LevVk
         bq1A9n4Ro1Jd+afKJd42+3v6scstDHh02Zltzpf5uUGRn69LYw52Gsecx3f12EzmpkSM
         miDCJEKBze2QRsdA1Db/qVstSZlog7wxhBMbBByo9frR6KU2YI23kGKzQYLpt2M4nBbK
         6dEQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=s+TCOUeWQlUJqAW81QuksGb8HjcySoGeSc7+t3Mx5r8=;
        b=TF0tZIaLk9SMOk4ZhFbQJrKcLRv3+U05s/lrGRVGTyeeVeLNU6y6F93WKQ48dXQhCF
         zHeO15Vy8XmTvHrVqky8CL0VEk4GOyRWqsTYMGzeClHqgGUYJD4jqpgom7+kCXrZZdus
         kwa3hgUftLJdyZZIl6mgK/hGXSI4yuffAAeBzNRd5rLqdW4qlrxvu6BEOWBekmbq3Kru
         vwVQktilu931oMEfXJxy0x2oPM7v0VuvuEZwgLS6ae6ja43h62LM5R1o9PEtUoYAk3Oi
         RmWt9g7S8zqf4Y3lQjJsYcG7b0HT0mJUdJ/IBfafibCUJuAcWrHVeIwwu+qBF5OPuN+5
         pNag==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=lnIljFKp;
       spf=pass (google.com: domain of senozhatsky@chromium.org designates 2607:f8b0:4864:20::1032 as permitted sender) smtp.mailfrom=senozhatsky@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date;
        bh=s+TCOUeWQlUJqAW81QuksGb8HjcySoGeSc7+t3Mx5r8=;
        b=gj//Y0z4CkyPCiK6oA4AMNf3B6UDYc8xWbtMPof22CtX3Rn+fKwcdWdljXij+45W3w
         EqlX9HYPTkRoA9Cm2+wFz2KUYEFu3uf3Na9IDU6W5ii+UPHqHfF6tjVHCVQVm3CCGbb0
         2DGtNQQlq4T1ABekv1gGqyTnxHp3tWJDUirbr9LRCnj7ALh6+fnpEyyRWlfuLjXpNMvv
         lvwhEMFhKJ+A5ILf1JydyQOf49bqbqCJ5XOikYY9c+aDl2D0bh0ntT7nCowSkC5ZbH9K
         pYw2RezUko0kw0CzzWsyuM0k/p1S7dvqH4UL6hnu6G3LER29p080TPqP2oMK3UBCSrEX
         Dk9w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:sender:from:to:cc:subject:date;
        bh=s+TCOUeWQlUJqAW81QuksGb8HjcySoGeSc7+t3Mx5r8=;
        b=sQSaEmVHlYCtkKUoP4X5k4H4xiFm7n5ArkcR2PM7oyyiYFHvG452yy1zRAVoZsdFuy
         zO4sexMgwFEsBKWjQ69hjSz2PV6VWMopqKgWXI38v/7h6PA9Ql0eAcNhQZYPKkZ2++Ol
         z0ypWMm+GCqXDFlIRlmpCerAbewbFyJhAzBtSvKG5zU0yuJohHXYHv851VU1GA2P+rLT
         5EafIisVbDRpZZKDgsnoDYYpGgyg4P20e4eNiDhNuJwlD8bTvF0kmjuxgVlpQU+ASznG
         9MOCy8hE6B6WtxgPl7EOu1eFFx6MrntJsWjhzXL1x828O/dS84By0hb8fo3VoxdY6rN8
         ArgQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf0EpAhTBoG7ubsYePEgZwWJJWvgBvW5uuAY9O8fg9jV/ogmY/xj
	y0z8f2hkXRALml9PxUoYHu0=
X-Google-Smtp-Source: AMsMyM7w7AlJOI4c/fuBfhBI8tfaKR/Gz9nO/9ajmiHp5CD2wnyKKg/tRFUW6WbmRTGvSkvOcknY1A==
X-Received: by 2002:a05:6870:e60e:b0:12a:f442:5024 with SMTP id q14-20020a056870e60e00b0012af4425024mr751988oag.36.1663642167111;
        Mon, 19 Sep 2022 19:49:27 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:e407:b0:11e:e2d7:74d7 with SMTP id
 n7-20020a056870e40700b0011ee2d774d7ls3357587oag.1.-pod-prod-gmail; Mon, 19
 Sep 2022 19:49:26 -0700 (PDT)
X-Received: by 2002:a05:6870:1607:b0:116:8083:a163 with SMTP id b7-20020a056870160700b001168083a163mr761412oae.282.1663642166684;
        Mon, 19 Sep 2022 19:49:26 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1663642166; cv=none;
        d=google.com; s=arc-20160816;
        b=nc3mzEg0o/H5QtquqOmDdmEKp/IDd22ipSzI+kcDZQuNHOiB7epv4a5FBRT8QtNXv8
         cY9fTkNQknAVy3eZhpstgjL5DS+yf5sjM31AT1vWCgwq/vAVH3MC1cMa5RhQN1yfaPhn
         0OoGeOQO8g183ZntYz4sf2cE2xSYEbbbEk6RFfECytTRxgkEImU3xzbec7DmTz1pV7yi
         VxYPDffPtLAP2Mx6g8qLotQJdsBzAcZofd1HnxTclp6Q+wuHs8r5cQ/hwUME/vsXeVGg
         C+iFKxkJ2a5MxP3q+nTzHk4kLasYAU3VIsGoRBnylqyI6xAQwhtuhKY4ztLEyjdJ4kqK
         nmFg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=rI0IpfDVb05suW6mssP/QFC86Iigix9NLenW3JQ6Phs=;
        b=WtCttT1unQe8C6hqwIbhj0vunCKGzOswczJkoGDoRgjGzHFsW392xSKjhcPlt2go+H
         ZIqs+skuB1qhZ4QlLCYJxvhPk72oS8k7j4SDRZ4zk2guaoAOzrxIxWaXzVFexPXa3Kc+
         vm3aheObQBMoZ9BjkPKOscBtEYy1G/sahOkcOxWKkGrrkg97C9Li4YB1VbppWcMlfDXD
         Mb8b2wKR/VD/2Lfr9ZpN8TvUFLUA2FCozFvCn8OMext1lHzGRjWUY+hqEa00ZdLt8XsX
         btJIWnLTFIWdXrAt7bcwjSgQr+Z8ZB8tuaV0+/qzWyxrqptdHPhJjYt9Qe7HM39HC2a9
         tj3Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=lnIljFKp;
       spf=pass (google.com: domain of senozhatsky@chromium.org designates 2607:f8b0:4864:20::1032 as permitted sender) smtp.mailfrom=senozhatsky@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-pj1-x1032.google.com (mail-pj1-x1032.google.com. [2607:f8b0:4864:20::1032])
        by gmr-mx.google.com with ESMTPS id el19-20020a056870f69300b00108c292109esi62561oab.2.2022.09.19.19.49.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 19 Sep 2022 19:49:26 -0700 (PDT)
Received-SPF: pass (google.com: domain of senozhatsky@chromium.org designates 2607:f8b0:4864:20::1032 as permitted sender) client-ip=2607:f8b0:4864:20::1032;
Received: by mail-pj1-x1032.google.com with SMTP id j6-20020a17090a694600b00200bba67dadso1062658pjm.5
        for <kasan-dev@googlegroups.com>; Mon, 19 Sep 2022 19:49:26 -0700 (PDT)
X-Received: by 2002:a17:902:8e84:b0:178:57e4:805b with SMTP id bg4-20020a1709028e8400b0017857e4805bmr2741327plb.144.1663642166279;
        Mon, 19 Sep 2022 19:49:26 -0700 (PDT)
Received: from google.com ([240f:75:7537:3187:5744:3726:1f8b:92ad])
        by smtp.gmail.com with ESMTPSA id j6-20020a170903024600b00178a9b193cfsm119779plh.140.2022.09.19.19.49.17
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 19 Sep 2022 19:49:25 -0700 (PDT)
Date: Tue, 20 Sep 2022 11:49:14 +0900
From: Sergey Senozhatsky <senozhatsky@chromium.org>
To: Peter Zijlstra <peterz@infradead.org>
Cc: linux@armlinux.org.uk, linux-imx@nxp.com, tglx@linutronix.de,
	mingo@redhat.com, x86@kernel.org, rostedt@goodmis.org,
	pmladek@suse.com, senozhatsky@chromium.org,
	john.ogness@linutronix.de,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-alpha@vger.kernel.org, linux-kernel@vger.kernel.org,
	linux-snps-arc@lists.infradead.org, linux-omap@vger.kernel.org,
	linux-csky@vger.kernel.org, linux-hexagon@vger.kernel.org,
	linux-ia64@vger.kernel.org, loongarch@lists.linux.dev,
	linux-m68k@lists.linux-m68k.org, linux-mips@vger.kernel.org,
	openrisc@lists.librecores.org, linux-parisc@vger.kernel.org,
	linuxppc-dev@lists.ozlabs.org, linux-riscv@lists.infradead.org,
	linux-s390@vger.kernel.org, linux-sh@vger.kernel.org,
	sparclinux@vger.kernel.org, linux-um@lists.infradead.org,
	linux-perf-users@vger.kernel.org,
	virtualization@lists.linux-foundation.org,
	linux-xtensa@linux-xtensa.org, linux-acpi@vger.kernel.org,
	linux-pm@vger.kernel.org, linux-clk@vger.kernel.org,
	linux-arm-msm@vger.kernel.org, linux-tegra@vger.kernel.org,
	linux-arch@vger.kernel.org, kasan-dev@googlegroups.com
Subject: Re: [PATCH v2 25/44] printk: Remove trace_.*_rcuidle() usage
Message-ID: <YykqKm5j5q9DEKk7@google.com>
References: <20220919095939.761690562@infradead.org>
 <20220919101522.021681292@infradead.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20220919101522.021681292@infradead.org>
X-Original-Sender: senozhatsky@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=lnIljFKp;       spf=pass
 (google.com: domain of senozhatsky@chromium.org designates
 2607:f8b0:4864:20::1032 as permitted sender) smtp.mailfrom=senozhatsky@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
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

On (22/09/19 12:00), Peter Zijlstra wrote:
> The problem, per commit fc98c3c8c9dc ("printk: use rcuidle console
> tracepoint"), was printk usage from the cpuidle path where RCU was
> already disabled.
> 
> Per the patches earlier in this series, this is no longer the case.
> 
> Signed-off-by: Peter Zijlstra (Intel) <peterz@infradead.org>
> Reviewed-by: Sergey Senozhatsky <senozhatsky@chromium.org>
> Acked-by: Petr Mladek <pmladek@suse.com>

Acked-by: Sergey Senozhatsky <senozhatsky@chromium.org>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YykqKm5j5q9DEKk7%40google.com.
