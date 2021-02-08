Return-Path: <kasan-dev+bncBCK2XL5R4APRBIHQQWAQMGQEZN7PTTY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23d.google.com (mail-lj1-x23d.google.com [IPv6:2a00:1450:4864:20::23d])
	by mail.lfdr.de (Postfix) with ESMTPS id D6A70313B2E
	for <lists+kasan-dev@lfdr.de>; Mon,  8 Feb 2021 18:42:56 +0100 (CET)
Received: by mail-lj1-x23d.google.com with SMTP id p11sf5553843ljn.5
        for <lists+kasan-dev@lfdr.de>; Mon, 08 Feb 2021 09:42:56 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1612806176; cv=pass;
        d=google.com; s=arc-20160816;
        b=xA8xGKQlgRU9ZgI43BO+jLQ0Dktfhtz3BJJ3vzeX/PDMq1AkeN/kT2z3tU4o6Ud46A
         UQmBLeMYBHk12gGW7OPnC+6LOL/HSwNfpibOYoegdZvt95HtED2twOMxZjoAXGNRNdjY
         kUOSplJN8POENLK8mB/Boq9iwpTkZj5yvnmLFyBsIGwy8kpzhzlBHeXCegaUfUYQ8Wyb
         IDKqh+RJd7T/VqqPItKJmE2ZswjzAtTmZGHo0Zr8HT6UQ22ZTz0caQlcr/wafwI6Ptgz
         a/2tQvwqd/72udmJ0ibeWkGtDjSMN0iryrLon58HYSDZaFpc86ScKpFNqts5TWNlxAiY
         i4jg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=2gze2ZPuQ8WqmZX1z/RLIkVlHV+90Z4pxRuna9mK/rw=;
        b=r3bEsFaHYxDin/bg5JLkJO7k3nyJ6LaLVHtuyYQs2QMz5BXYIWfFCnNu2EWSPtTmkb
         otRK6KFI5Qq2M0cKTGvFOQVqwqPkE1FxFK6VW5zZy4q8ii1jgAvxNo+iElsqfgxsNhrf
         GGPE8NJUcgWQFRW2Ds3V584wp69xDhK3alJnmnv8obnTLrDlVG9Elrux/1RWmp75lrML
         NG3Mqc2Gj+ywOJ0Tw9TB91ekg+gITef5twJkuotAxMpQdKZF3t+tBlLqgaPjKveYTT23
         fVoiRLg0K4twqCtsS4f6VgiWxHB6q/loG6y6/hTw7f3tyBchD2Q+4iC2Fzw1sFjBSyqP
         8wog==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=o3Rxjl8u;
       spf=pass (google.com: best guess record for domain of batv+2f40751f11b88fcdb4d6+6378+infradead.org+hch@casper.srs.infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=BATV+2f40751f11b88fcdb4d6+6378+infradead.org+hch@casper.srs.infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=2gze2ZPuQ8WqmZX1z/RLIkVlHV+90Z4pxRuna9mK/rw=;
        b=mE5twC+KZDtsLPD5DZQR7kaoP0H2NyU2cFqyL7w9cc+7S8sFGhkLMlRp1p77gzJEow
         Jf/MOSPJ+4j1vYqDwdcUyOeeeuubd0khwTd/qXqV4YpWFTx+J6QPmLDSo1tw776Sr3V1
         wM0nVa3NvhniD9IvMNOJjLi6WQ05DKVH/Q9bx9bXILP6WcIEvOT3PD8mnF00WKkqdGoF
         uF0Fa+KSbVpc2cBapK05HuYKqwpohcHdU3ex1Fox+2k2u3z1LNMKFAqmHy9stISgdckS
         s3tmrVpB/QGCZMF6oKmfcDMhJ7vz1oBkyOIfedqdkpCcjM0ws3r1sbn+pGrXRCZc+Gk9
         RMmw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=2gze2ZPuQ8WqmZX1z/RLIkVlHV+90Z4pxRuna9mK/rw=;
        b=doYg7tVlRj3hYkk+nnP02pwMVSuFqr0kxXz8P40+xhvtMk5RH3LFUY096NA5FrjUeU
         Sc35pxuq3JXA0a9Kxy9Fl1gonMxmWqQynOigq0PM6tKTqsSj/GsyuVbPNsKeTNVP48UE
         L6UU4c4bRKc7t2Umkx7yoVmnNL+UEvwfdhHE4MLqnD4SEm61g4FtpRh+/0Cjs+P5jyky
         hssp0CaHh5WxybYb0PiCJsVWeCFBxDZFSXrdGeE0XS1EWZqHJhM8Y8y0tZ91A5GMGcQB
         JddLNkz71aQy+UkUqwjsN02B8q6YbTE9Whb18SdPOavDwM+aXmkbo/JfyYW9vWTzjTej
         mXKg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533X97zGEwUmffue4PX4Dol2LamUTlKRzg6fS3xBJXS1cNDlQmny
	RGpGMNnTHLlP1sepVy1uTUc=
X-Google-Smtp-Source: ABdhPJxzrPukj1818XR4Gf75ImLQKHK79UTTIcOZX4r5FIBjXxDrwD2nL0IgiEKvvhu6UipDuLVbTw==
X-Received: by 2002:ac2:4831:: with SMTP id 17mr11407012lft.474.1612806176357;
        Mon, 08 Feb 2021 09:42:56 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:6d4:: with SMTP id u20ls1010858lff.1.gmail; Mon, 08
 Feb 2021 09:42:55 -0800 (PST)
X-Received: by 2002:a19:ad47:: with SMTP id s7mr11034768lfd.72.1612806175435;
        Mon, 08 Feb 2021 09:42:55 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1612806175; cv=none;
        d=google.com; s=arc-20160816;
        b=NyPNIn84AoPZfib55S8XRBz2MDLYra/STa5XOklBPgxmRt7JRK3SrSFRpovHrM6Un1
         gNmQtnfY4B9BPU5tzB8eNH5PltE7bnxmZCOSwA7k546bX4rHve94l61W3bxO6gxDFoqo
         4/9W1YPfqgarX2mEUNXQ2/lAzVpCcWJMIWrV0xKHoc3daldrFn1o5Oiv+FWF3JXIojXw
         /m00HwfUju195iDHUgTAvq4Vsn5HYgO+Oe5zR/HmOP8hr79t3HsIJQpNxP57Rge/qXt7
         T/FyVhCGtJCQLezhyU79N90hOg55h9NuM1C6fY18wElv2xuDax1YsjrZbZNaNdMQRzfb
         +e1g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=vidqzNM6LHEiqGq9XxJTqIlShemMdM/td8LbkD0squQ=;
        b=rAEIXjScYpdK4B10GlfTs0B8RDEbWBClRkcz97PODUcy326ZrCc93ycNNExWQRvoZx
         MT2VYgVfaOS9y/VumzPOfzu52uGJQuiGrOBGWo+yUTp5eBej3cU5C2j9ZLl3EI10BzXu
         JBLWUMhieZBrK9wAK9ixIgZYQjvvz6PRuBdkOCLTfVhDEQxQIxRgIiRV2il3xheoECFG
         IkHpvB/7UkpnUu6aN1qPI3d0YSOKYpR3UlSl+1suInsJpj7KngHjHNtgPUB2OyAJ4TdH
         hoWLqDmAqhESsp7xIAUM4b8kVso5pXdQA1ZFSDufnXWS00glI+RHxyL6rYEU4FsRfWcj
         KBjg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=o3Rxjl8u;
       spf=pass (google.com: best guess record for domain of batv+2f40751f11b88fcdb4d6+6378+infradead.org+hch@casper.srs.infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=BATV+2f40751f11b88fcdb4d6+6378+infradead.org+hch@casper.srs.infradead.org
Received: from casper.infradead.org (casper.infradead.org. [2001:8b0:10b:1236::1])
        by gmr-mx.google.com with ESMTPS id s5si995166ljg.7.2021.02.08.09.42.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 08 Feb 2021 09:42:55 -0800 (PST)
Received-SPF: pass (google.com: best guess record for domain of batv+2f40751f11b88fcdb4d6+6378+infradead.org+hch@casper.srs.infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) client-ip=2001:8b0:10b:1236::1;
Received: from hch by casper.infradead.org with local (Exim 4.94 #2 (Red Hat Linux))
	id 1l9AYh-006IPI-NU; Mon, 08 Feb 2021 17:42:48 +0000
Date: Mon, 8 Feb 2021 17:42:47 +0000
From: Christoph Hellwig <hch@infradead.org>
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>, Will Deacon <will.deacon@arm.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Peter Collingbourne <pcc@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Kevin Brodsky <kevin.brodsky@arm.com>, kasan-dev@googlegroups.com,
	linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org
Subject: Re: [PATCH v2 12/12] arm64: kasan: export MTE symbols for KASAN tests
Message-ID: <20210208174247.GA1500382@infradead.org>
References: <cover.1612538932.git.andreyknvl@google.com>
 <068ab897dc5e73d4a8d7c919b84339216c2f99da.1612538932.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <068ab897dc5e73d4a8d7c919b84339216c2f99da.1612538932.git.andreyknvl@google.com>
X-SRS-Rewrite: SMTP reverse-path rewritten from <hch@infradead.org> by casper.infradead.org. See http://www.infradead.org/rpr.html
X-Original-Sender: hch@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=casper.20170209 header.b=o3Rxjl8u;
       spf=pass (google.com: best guess record for domain of
 batv+2f40751f11b88fcdb4d6+6378+infradead.org+hch@casper.srs.infradead.org
 designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=BATV+2f40751f11b88fcdb4d6+6378+infradead.org+hch@casper.srs.infradead.org
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

On Fri, Feb 05, 2021 at 04:39:13PM +0100, Andrey Konovalov wrote:
> Export mte_enable_kernel_sync() and mte_set_report_once() to fix:
> 
> ERROR: modpost: "mte_enable_kernel_sync" [lib/test_kasan.ko] undefined!
> ERROR: modpost: "mte_set_report_once" [lib/test_kasan.ko] undefined!

Please put this under an ifdef for the testing option that pull the
symbols in.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210208174247.GA1500382%40infradead.org.
