Return-Path: <kasan-dev+bncBDBK55H2UQKRBO7JQ6KQMGQEMPNKVQY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33d.google.com (mail-wm1-x33d.google.com [IPv6:2a00:1450:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id 05BD7544D8B
	for <lists+kasan-dev@lfdr.de>; Thu,  9 Jun 2022 15:25:16 +0200 (CEST)
Received: by mail-wm1-x33d.google.com with SMTP id m22-20020a7bcb96000000b0039c4f6ade4dsf3618090wmi.8
        for <lists+kasan-dev@lfdr.de>; Thu, 09 Jun 2022 06:25:16 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1654781115; cv=pass;
        d=google.com; s=arc-20160816;
        b=tkivLUhf8UFbxezcrA+a5EUNFXfH2ZgKTBAYvT1d2uWzkHkglp9CFKeptoCGMmlA6D
         FSVepq8ogDw3unWJQADj0NnulLmiHSCztw+4WLeAC7ybLX0O9vzt6YMUgcdtUteC06iN
         1N65r2WmOR1HtTaU5E3NY1zhvUBlVBO/f3Izq73VgEQ0oSo9Kz7z4Lx7nxvmFrPJZb8b
         QnB0pOypvD1G16h956jESZRJbr1A5C3vsFkgNIrbVjYxYI19pRr+8IMoWrOYuvXbOWJz
         XwugxvJJ5GkNm3A/I2V0re5uabcUBjBhzsgihxV/JVMS+5kPx6RLvYfJFsxSJcE8Ve/U
         wpMA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=9tyiCNo0CzRdtl6UWbuqLSgc9YES2cRw9ZXHqHCx9Jw=;
        b=H9qE/jsXbPGZDkaC1FF7lOI1Y12klrysAL/ENgWkpLi4cX+vruZLwjlyH9N8it7fGO
         ki1gH4gvWihPIiTLItYuxikGeJg2MD1A2KeMr1bG0v5wCdQkiRctALqtAxqFL9LBc6aQ
         etS4n3qcgpf3lZg3KVemSCVRz3a+QN5cJ+5xUt7qhZ4ximqkYlBSlwqWWtA6XK8rg3Sj
         ZBAissz61DYSWxTkm4SUNTiGaNfQLWmU9tUDtQi/Rlu0ZMkupRP172J0NZ1OP79Xgji+
         qsJqkv6tW4gV/wUHB/g9DWQz4nGCRjpnKylMvJW6pgLZZgjo7mG/tU2P85S2pIhvy8tU
         fLlg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=ZTuTdisB;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=9tyiCNo0CzRdtl6UWbuqLSgc9YES2cRw9ZXHqHCx9Jw=;
        b=LHmr1RsqozgyHlqfbM9Td9Jzz0Q3AcLs43IM7KHLd94uHUoLqmKE1ZZfepSHv8EiJF
         s5ulniwV2pn3rZzy73w6heOYlU75t5UOMcigb4txSp4eAA4EGUHY0k/bvraGQA6ZKI3g
         xoZTkm+gpacIbM1cDIHsTEgZ+lZEzS084d4YWeLAPqtjLASeipMhKmt5OLVorrGFdVkE
         CqHwj55ok7MCzUK+koKU/cUsBhttxzWGCHXxldK58ghh+G7HkmB0e4TxT/Kclfl2DM6B
         O5j9RBNDMie4L4FAyfWOEOvu1FHWn/SFM3urniKpy/jIaMfetFDlBZyvtO1NW4sxNygK
         xcCQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=9tyiCNo0CzRdtl6UWbuqLSgc9YES2cRw9ZXHqHCx9Jw=;
        b=eUml1TCgXmB3dLfJy90YlX68O4ox2ezm7g4nMC60jq118RjAk19kvSyjW0A6SGzJJl
         Sgkg9xnh83/ZB5WFtRFHPWyqtP3+VNs6g6jW+8DeM52UzJB/fHjRZqhiYMWOIYrefq3r
         Rvdmcca+ar1Keqljl4E3Fgm1aWQ8Ik9AX6+xr79xDwt9TuKvDutw6QVK8ClrNqCtaTKv
         Py4U69uRuO3f5rZyaKzJuhHJtlJJFP+TXuvkecsCcT03iPJpACguWyDpuoDQW3zQ6lFn
         plnsYBEOYpgboo96eteMPuPhhvFR+JbQg5bXcA+FLMwMvz+OKHxBoQuoT0LOLI77H+cW
         gfUw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530VNW/UOB5NW87TcyVcwJq+FKVBWbOxC7/68s3jjhbQjMI4CfCh
	gWV3G0cOII8vrcxCcxfnCtc=
X-Google-Smtp-Source: ABdhPJxNtiIC8Yy6nzcW59nVcj/FgtqeQcjAlTlP3JyNzfzAQmlhhc8XqDVFgwR5EjYlK+RBtzQsKQ==
X-Received: by 2002:a05:6000:124a:b0:210:2f22:1f4d with SMTP id j10-20020a056000124a00b002102f221f4dmr38679696wrx.147.1654781115607;
        Thu, 09 Jun 2022 06:25:15 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:3d8c:b0:39c:5b80:3b5c with SMTP id
 bi12-20020a05600c3d8c00b0039c5b803b5cls878849wmb.2.gmail; Thu, 09 Jun 2022
 06:25:14 -0700 (PDT)
X-Received: by 2002:a05:600c:4ec9:b0:39c:69c7:715d with SMTP id g9-20020a05600c4ec900b0039c69c7715dmr3451869wmq.154.1654781114391;
        Thu, 09 Jun 2022 06:25:14 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1654781114; cv=none;
        d=google.com; s=arc-20160816;
        b=B/ONCFCfdX68mjErroGtqDY76aSWO2wy7jPYWQuD3Ss037mfmxUa6FHg5uThzGg47J
         P0xQFhWnlN6g126p2dBUKoPxFI8EYqA7rNd5tVqZPbyN/fQaOIOM+Lq8iZeWJrzXmsMf
         WW736RYAiMmwY9WoD02YckBvqgm5Tin/IjEtu8rO1OpdDfIRLmk0ikCGXyIQbglGsSpz
         yX6bkGyzdYjAd0itIYYf6paSmDLd5NmwU6AMFfV1zrEcmf5ZGdebyscH5JLjkmLs20fj
         4dUyA7HKBjbctHdj2h3e0i9L2CmtYCeJxnbbhhv9kDvhdS+cDMRCJT31zy7gkZIAajAg
         x2Sg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=RDnJZHWmp+ysb0h5kWT0rkgoVabhczhnKUMjH+r+EEo=;
        b=Rk9geZpr4YG2IultL/TtgQtiy09Ff8K8dA471OpEHYB3/FyhmKUbVUPg+Fusf6ddqy
         hU3sUvd1JOCiqZFVJLhx3cPzQNe1Krqs5Z4vxP2pRsQXnNcii0ryDk7Il+5pDX1Tudu5
         Vy2NJ+rxyxaLCD9z5MrcHsc4V6w09SmRLq3VUR+jyJ+wvM8W570CK1oX4rvg5WCd8RAH
         owL6eOz/h/Jej1rKs7YvIYYEwfazoq+MJInlXcVJumNR5/dGcE76j++ldn/pVA8QlfBg
         H4NrPX6ZIrsBSxl8B6DeeVILs5Gfx5DORvrkHbz++ezSIZBlU6yBotoOP1v1yp/ycthq
         4yVg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=ZTuTdisB;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from casper.infradead.org (casper.infradead.org. [2001:8b0:10b:1236::1])
        by gmr-mx.google.com with ESMTPS id o42-20020a05600c512a00b0039c53b7b69esi443866wms.0.2022.06.09.06.25.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 09 Jun 2022 06:25:14 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) client-ip=2001:8b0:10b:1236::1;
Received: from dhcp-077-249-017-003.chello.nl ([77.249.17.3] helo=noisy.programming.kicks-ass.net)
	by casper.infradead.org with esmtpsa (Exim 4.94.2 #2 (Red Hat Linux))
	id 1nzI9u-00DZzb-Gd; Thu, 09 Jun 2022 13:25:10 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id 3096930017D;
	Thu,  9 Jun 2022 15:25:08 +0200 (CEST)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 1000)
	id 16C59200ECBB2; Thu,  9 Jun 2022 15:25:08 +0200 (CEST)
Date: Thu, 9 Jun 2022 15:25:08 +0200
From: Peter Zijlstra <peterz@infradead.org>
To: Dmitry Vyukov <dvyukov@google.com>
Cc: Marco Elver <elver@google.com>,
	Frederic Weisbecker <frederic@kernel.org>,
	Ingo Molnar <mingo@kernel.org>,
	Thomas Gleixner <tglx@linutronix.de>,
	Arnaldo Carvalho de Melo <acme@kernel.org>,
	Mark Rutland <mark.rutland@arm.com>,
	Alexander Shishkin <alexander.shishkin@linux.intel.com>,
	Jiri Olsa <jolsa@redhat.com>, Namhyung Kim <namhyung@kernel.org>,
	linux-perf-users@vger.kernel.org, x86@kernel.org,
	linux-sh@vger.kernel.org, kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org
Subject: Re: [PATCH 4/8] perf/hw_breakpoint: Make hw_breakpoint_weight()
 inlinable
Message-ID: <YqH0tAT2kboGG8FZ@hirez.programming.kicks-ass.net>
References: <20220609113046.780504-1-elver@google.com>
 <20220609113046.780504-5-elver@google.com>
 <CACT4Y+YHp1mxxGNuGke42qcph0ibZb+6Ri_7fNJ+jg11NL-z8g@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CACT4Y+YHp1mxxGNuGke42qcph0ibZb+6Ri_7fNJ+jg11NL-z8g@mail.gmail.com>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=casper.20170209 header.b=ZTuTdisB;
       spf=pass (google.com: best guess record for domain of
 peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
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

On Thu, Jun 09, 2022 at 02:03:12PM +0200, Dmitry Vyukov wrote:

> > -__weak int hw_breakpoint_weight(struct perf_event *bp)
> 
> Humm... this was added in 2010 and never actually used to return
> anything other than 1 since then (?). Looks like over-design. Maybe we
> drop "#ifndef" and add a comment instead?

Frederic, you have any recollection what this was supposed to go do?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YqH0tAT2kboGG8FZ%40hirez.programming.kicks-ass.net.
