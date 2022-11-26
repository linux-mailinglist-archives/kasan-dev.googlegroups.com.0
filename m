Return-Path: <kasan-dev+bncBDW2JDUY5AORB7NPRGOAMGQEW4QUTGI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3f.google.com (mail-oa1-x3f.google.com [IPv6:2001:4860:4864:20::3f])
	by mail.lfdr.de (Postfix) with ESMTPS id C2ACD639794
	for <lists+kasan-dev@lfdr.de>; Sat, 26 Nov 2022 19:16:30 +0100 (CET)
Received: by mail-oa1-x3f.google.com with SMTP id 586e51a60fabf-13cbfc38be2sf3974950fac.0
        for <lists+kasan-dev@lfdr.de>; Sat, 26 Nov 2022 10:16:30 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1669486589; cv=pass;
        d=google.com; s=arc-20160816;
        b=O6vtnKF1aeOtB9xJHyugtF/V+18X23CIzpox+BJaRu7OuFr5TnOtLXewMx35CUJnJi
         nqyGZl32ECwcSqkhaNUSfGVJxW4Ym5bTCKdn8L6dwo4xRUfq914jqcJ3+l20ClLk1jz4
         H/WW2MJdjOZ40o3arqYyKOXU28PzdnWcpVZuaTCuDgTgjZQT0oIbormbOn4ePVlv2Q0p
         rwv9rGoBacyqaiU6VulkiTacTCLe8SBEYUiPKM4fNo/XA91UySJNYz+t4Dr5fVVoXqJF
         AEaVccpxWjx1EcAUZOReNI2ZPjJeSICDO2pXx+/+v8n0zhr6PS2Ub52SvaImlbYwu4w4
         FpKw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=E7sGh7Tkvvtsgwo8iEWo6nUeM9IGqpwK2amFBNNfYGY=;
        b=fW8Cuy9qNncIULTW7rsXBKIEhvKqUMq70DUgEOZHUmeesRWqn/f29iFsT86FqZgKrT
         zfPN6/nKoEY5e/mTNY5x7o9Pc9Yqa+iwVxM1inEt/K2uBEYyW4LFyU7FKgkmrcRKD7JY
         7lF4998xl3E6PawPmmH+6SDo8cUFa+fkzurteD+XyvG0pCdyb9O41IkvKxuQR+TiVdWu
         4VHQs7Q+TRE5tYwhNtWhiq+L1XJRk6rvx8bqRwVxsUvPd7yoQEGmhcWC6iucLsArp1o8
         VRMJHujuKx0eHEqiiCVMMQaVI7U48J7Os3gpmdB8BS7/5mMmDVjoIwjI2I9BcKdkDiiT
         X+5Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=o8y5SyU0;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::435 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=E7sGh7Tkvvtsgwo8iEWo6nUeM9IGqpwK2amFBNNfYGY=;
        b=HvSKwL1bwG4PrwPdDSge2lIpQG78lpuJWMhZmHlgL+PnZ5FuhGSEzGEhhX0fQXmWKa
         tjpjleUKKnNUfCwG/2iT/VtGQNlVraWCTi0GUu2Zi5WzzJs4K3GrkY67BLj8I3UzBnWH
         MBu9WSfq13293Mo3OOYe8Fg2v8qVGGoMiFwvyDeNpZ4a+JFC915LHbXCGhdmKN4KUxUq
         CyOx++THAPR5nj9iUrzxW6JEwW6oKT+msMhbPrav8PunqWZkS8f/ckvl9IpSWqHzTAzb
         Ve10SWvS/Txq32NIGt3RpGiNBXozVbl5o/PvPrKcRavHy11P/1JCjaXVmsHNc7MuCwT7
         YTxA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:from:to:cc:subject:date:message-id:reply-to;
        bh=E7sGh7Tkvvtsgwo8iEWo6nUeM9IGqpwK2amFBNNfYGY=;
        b=BJz0TikRoI89OYOWi+KZPS3CpcGyBM3dJd0Z227IIpChsw1s90UX1AzDeI6KRqHrVz
         aADgTPEdxT9GBP10w+U8+MsLBIpEvzvWUYn39KTumeJArDba32fka0xs/VBJq4CRYl/3
         Pmnn729oRHYHAqWO49UWGNfy/YJ4KXcD8la8rHogY1eaWNZ0rnNH6UttAQGaN9/bW1yJ
         9Y9YYp+39d5IfxmuTuE1kUeSabLTc3Ot9iB7axkg6eOJ31KkbncM5QgJqE8EZWF1mcpe
         a8Lq795HNrd4cmHivXmRzt2He6tiQgwm9DRlDsuR19H65cW16tXt/tMNKW2xxbYSPjFP
         CuTQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=E7sGh7Tkvvtsgwo8iEWo6nUeM9IGqpwK2amFBNNfYGY=;
        b=72KiKmbnnEGam/d1Ayenagc/cXOm8Q7S4XBpwYlGfvKVkd94EJ6Y33+6JRHIJZJASj
         w3Mgjjyc0SVIBaKZFzuGv8oqzdlivW7c0MFQ70VDR5R7vc7XCdQjJWpHIoPW3siraaIv
         uCNYBgrwlgOAyRKM35MeDPkfvZqRLd/FnkQuv31/JtNXdV78BhjFz6s0mHKbst7togGd
         8pKLeRHxW6/4xjjs0h9xIEGxQrrgvQJznTKFrs4dYcxiohVnq7pv/crDT8u80XZTR1Fc
         52a+ICCNl2KrAuiCRO5YD9yDmvanYHaoUdWukApPPLfSY8OrxBwaH0W52gd2d1e8UOnF
         Tk1A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANoB5pnOGdWNBVpNptdxMwIG1l54nAYKdk2032UN1pnIFyWCLj/ZMwt0
	JpLXP/Yz9xOM/MHUNTlClL8=
X-Google-Smtp-Source: AA0mqf4fpARN0t//4Au2TfLGb2ieLUgmTzxCDSRyKbG1QpGI6PDk7nu31lvuT73qz+Uw3QaAVdCq7g==
X-Received: by 2002:aca:b7d4:0:b0:354:4cfe:aaad with SMTP id h203-20020acab7d4000000b003544cfeaaadmr20338969oif.246.1669486589382;
        Sat, 26 Nov 2022 10:16:29 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:956b:b0:143:5382:1db4 with SMTP id
 v43-20020a056870956b00b0014353821db4ls2374329oal.8.-pod-prod-gmail; Sat, 26
 Nov 2022 10:16:29 -0800 (PST)
X-Received: by 2002:a05:6870:b426:b0:142:c277:2e94 with SMTP id x38-20020a056870b42600b00142c2772e94mr14015965oap.129.1669486589010;
        Sat, 26 Nov 2022 10:16:29 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1669486589; cv=none;
        d=google.com; s=arc-20160816;
        b=neS8IJwoJZEsHhgqoswKmW5VxHbiuVHzXXJnir3HllC0E5s2pi/YEYgyXPxNJk1DUh
         in9Dda4tDu4rAA02EBABekAoDSAETLA5BI0vEPoQ8RKkQHScUqkoG+nw5koU2ETLyGTI
         VJYNAMDbNr8cT94p/sN3HqiOgpfeR9KvJBjlxBd16OGfoGliqVKDu3tWFbn3dGPOcI0M
         C9/5PIFi859V+I/P1iy0wrKTrP/Rc+P1s7OGSlSu7KZy+fa4mnjmt6uIh14RfEFx4Gaa
         vpmMt6xgKtuvsT8NxlZIJaWVZ+fzm09R17Jlj+L1YhMkJYfaaU6oFc3hIcgXInQXp+4H
         2x3g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=JGpKt/08MfScwB6fADFvl3111rWPJnPqOlgX6pbF40Q=;
        b=XbZPqMVx7jr5EWLyPsfdzijS6PJtArmmKAkVkzlRo7JNTNWuai5khxLmCIIj7EkqO/
         2/SVeOUoEXesJxy3iPeWdBCEele2RxsIo4c4+AaAsklgO3aHb4z+/zRZ8NzANLKo2rNB
         Q/WT6HoaHJUNyGnFOk+MCPs7JHkZxvPmvWLHNviBYf9CoQmmCSSZ/VCBtc+GuHdOVqFD
         oqSg2/bbdXDE1alsdhSC+MbJxnuFhvEkm7/A+C5dIzkQJ2UZPoRnSKtIVCK7S+X/lPiy
         Vc5cghLY8l4zFHOBcw316YUwGSImloPRm3wv8tosdewLj09nFIqVeaibSe0LPvGyTJHJ
         XhtQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=o8y5SyU0;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::435 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pf1-x435.google.com (mail-pf1-x435.google.com. [2607:f8b0:4864:20::435])
        by gmr-mx.google.com with ESMTPS id l28-20020a056870219c00b001371e49ab90si589197oae.3.2022.11.26.10.16.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 26 Nov 2022 10:16:29 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::435 as permitted sender) client-ip=2607:f8b0:4864:20::435;
Received: by mail-pf1-x435.google.com with SMTP id q12so2710083pfn.10
        for <kasan-dev@googlegroups.com>; Sat, 26 Nov 2022 10:16:28 -0800 (PST)
X-Received: by 2002:a62:2702:0:b0:572:8766:598b with SMTP id
 n2-20020a622702000000b005728766598bmr24121255pfn.21.1669486588616; Sat, 26
 Nov 2022 10:16:28 -0800 (PST)
MIME-Version: 1.0
References: <655fd7e303b852809d3a8167d28091429f969c73.1669486407.git.andreyknvl@google.com>
In-Reply-To: <655fd7e303b852809d3a8167d28091429f969c73.1669486407.git.andreyknvl@google.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Sat, 26 Nov 2022 19:16:17 +0100
Message-ID: <CA+fCnZceUx+Vqj7nUPiLrexnmU11KkGGtJ3-9KfXm336e+cv3w@mail.gmail.com>
Subject: Re: [PATCH mm] kasan: fail non-kasan KUnit tests on KASAN reports
To: David Gow <davidgow@google.com>
Cc: Marco Elver <elver@google.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, kasan-dev@googlegroups.com, 
	Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>, 
	andrey.konovalov@linux.dev
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=o8y5SyU0;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::435
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Sat, Nov 26, 2022 at 7:15 PM <andrey.konovalov@linux.dev> wrote:
>
> From: Andrey Konovalov <andreyknvl@google.com>
>
> After the recent changes done to KUnit-enabled KASAN tests, non-KASAN KUnit
> tests stopped being failed when KASAN report is detected.
>
> Recover that property by failing the currently running non-KASAN KUnit test
> when KASAN detects and prints a report for a bad memory access.
>
> Note that if the bad accesses happened in a kernel thread that doesn't
> have a reference to the currently running KUnit-test available via
> current->kunit_test, the test won't be failed. This is a limitation of
> KUnit, which doesn't yet provide a thread-agnostic way to find the
> reference to the currenly running test.
>
> Fixes: 49d9977ac909 ("kasan: check CONFIG_KASAN_KUNIT_TEST instead of CONFIG_KUNIT")
> Fixes: 7f29493ba529 ("kasan: switch kunit tests to console tracepoints")
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

Hi David,

Could you please check whether this patch resolves the issue with
non-KASAN KUnit tests for you?

Thank you!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZceUx%2BVqj7nUPiLrexnmU11KkGGtJ3-9KfXm336e%2Bcv3w%40mail.gmail.com.
