Return-Path: <kasan-dev+bncBCF5XGNWYQBRBV5D575QKGQECC3XKMY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63f.google.com (mail-pl1-x63f.google.com [IPv6:2607:f8b0:4864:20::63f])
	by mail.lfdr.de (Postfix) with ESMTPS id 78DE22843EF
	for <lists+kasan-dev@lfdr.de>; Tue,  6 Oct 2020 04:09:29 +0200 (CEST)
Received: by mail-pl1-x63f.google.com with SMTP id s9sf531427plq.15
        for <lists+kasan-dev@lfdr.de>; Mon, 05 Oct 2020 19:09:29 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1601950168; cv=pass;
        d=google.com; s=arc-20160816;
        b=D26+FDLQi2HrwQNmJpNigkrfBJN67AwBNbXMr4fGzDk8BNxl+xPRbfMUZSeQZOov1C
         akhfQM3JydATpD57jyfdrlcWNNj59Tyf/FKCGMteFSFa8iAxwD2qWZIKzZ92HjGN90gm
         Vmpotb4TsuOcToR3mX4ZFMayLaG5TlHw19mhpj19PLnc3xq+hXCcRflzSxf12nqfqW2p
         h1XdxwPG2I2HCSkMA+tUSJQ8Hd6ciG0URtdzly8Ahlx4JB5MJfqUcpTcDgDtfvgQOCUV
         /fZzSu3kpa5lMrrn6FtWNdILODTL4MeQ8bNyHbP1Ye1SXoA/TIXxQG5r7HwFq93jOYtX
         OnnA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=JxpmoYPxxTgamvVmEPGarOKe/rHfqjDuHmVwfGD5zyE=;
        b=m0yPx0PPuann+DnPTC/mk0XjmC6Co5V/gEl8YKVUpCy0q4kSNB7+9X8lxcVXGmaApA
         DNwOIir/PVvth6qrKwAOWc285S331Ms1ByzIJRCYbcdzhtb8mPGPKU57fVSkm9kS7d55
         QOj1DQo/gdWSNi9igCbLGNW06vDeZP7N8oUaqnNA9lTmu4LhHuhMcLEzHr3YkOtL6UOJ
         F+e+bGMufGkL6Ovt/j+K+1nXcIyN5qD7cH7854GRc/y/CI6dvL30NbVHt4v8EbUmVYOk
         JaKyDodENxqySWuOR/e/B6AiWBm4Suz6Oi9F4JYjYO0JpWYlW7VvK3++0ss1fSlScpWx
         G4lg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=jDfIYFTb;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::543 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=JxpmoYPxxTgamvVmEPGarOKe/rHfqjDuHmVwfGD5zyE=;
        b=sLRHAld2Po4EHb651R90/DThn+Wvrd4D0a1o2uHRJ/J/TSIY7MDwgfo+YPR/Maxb9P
         Lnht89NnUMhAPOMXr/vrwZ7BtVDb6dHv+As2b0orNXaYh2h5EB3DITM7nV/F8U5NZw63
         PMNUi4LcaFzy/v0UsUudM4sIifoUdD/WqQqkZFm+5962QY3siiTxtKL2skulYGJqPa3S
         qh5TaZQRsT6CTOLdFfuea3bCa/xXnKi8uDqgMkBRAbIRkf359AcS17X/qESCUFYIppUk
         HHJAylpbZZ7n0PGvSKuJ0Ubdj22GKhhlBkysvP+ysdhlmrgJt7ousUsbzYUAO6cW4uak
         2EYg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=JxpmoYPxxTgamvVmEPGarOKe/rHfqjDuHmVwfGD5zyE=;
        b=iviOc699Rc9lSNLFXn3kkObUZXGFDHpdnl9vjLprPP5RlsnRgtppQDrndVU6D9+3NI
         zKEDA5qQSmz4bIrldNpaD3WQwPt/l4XRSNAr41DASpvAyUVoEuBKjDXFOzLcDgPZCeaI
         X7vOo6wMahwGH3zNmVAXLchKTLTsqP56ee/uMCUFfhZ7EHqFmAKwh5Y9ittn+eSTcFI9
         exWnvFUOChBXzsKtUd44XSLWI49isHjpgWSDPBzn3eT+CG1dxOA5QY1v+IGxODx1xWzs
         /7aKH5pmgC2SLNLjdQ3GSpSfj1N5rFm7dgevOry0f+uiV0DdCrB8ciwiaktL9DXnASGv
         COkw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532U+WxRhJA6x7w7jY/7jKvXz2HrYLnqAKJXFd9nFUsDEBjzbbWv
	QNdnZeLM0+NuMQ58+ExFt0c=
X-Google-Smtp-Source: ABdhPJy/XrrlbbZWgD0hVKzMx56prSCPps4LvTM3e6qpZWLXW6l6Rd4JED/hwVutSHqCYvGdp7xlLA==
X-Received: by 2002:a62:cfc5:0:b029:13e:d13d:a083 with SMTP id b188-20020a62cfc50000b029013ed13da083mr2444741pfg.26.1601950167898;
        Mon, 05 Oct 2020 19:09:27 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:7c92:: with SMTP id y18ls432395pll.0.gmail; Mon, 05
 Oct 2020 19:09:27 -0700 (PDT)
X-Received: by 2002:a17:90b:1b03:: with SMTP id nu3mr2171576pjb.148.1601950167385;
        Mon, 05 Oct 2020 19:09:27 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1601950167; cv=none;
        d=google.com; s=arc-20160816;
        b=j8A6lLByeuuSCwawEQ3Td5F6QmwJSUflVRX1a/BSuUPCjM4v3O7lgd4LinIpsS9nwr
         mwjwme9vN/ABbw/e1Y1+yTIC0VWoPdOIlRYUWmiyQaip9c2p5pBFxsKg3rViz8LBX2yw
         zl4tx0UkDr3eLyToW0gcGyAbxfl6tG5tcXSm8tT7D+aarO+c3AsyvEeOC8uqEUyYAjUb
         Ho8HC3PkIFf1kzn+q1fVCIn8hx8oElRyTP2CeFBJVNP/kiq2RPIOgFVYZilXPbKxnOl3
         C9nwZVMmwYAteHfojwqjEHmOCFT1Dum3MU3PWu63obZATLU8QhA/vaRi8dyvq+god0aG
         kH8Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=5uyUjU81WTaoePaJ6pjDUCkELEhzyE83H9lRZhP1V5g=;
        b=mH+OuVYym81Li9KUJQo7xhsGt+rAcGUopmuK9R/A+BIcXrZnz8+R/sncpJAJjYvAFP
         pqs9xPPBCTLXWu8k8cz95EIQS1xNAsYku9/SwRNdv0wMrFQxTB4xJ83JE6cy2a6psdNV
         VU98Mx1f3ZA2PZSJD5OHbQMD85c2vIiP4iPnpq1O+XcfwxPVL76uStA0e1/91vH6x+V1
         YBUkdIWJvlNUZ19UA0CJ8NTG8lZh0K98Zjl03NdoEL4Douk5jkH1QSP+z7FtkXQcaVic
         rlDbL4OBpU0QrCIxXtBkhNzWdbTTDCrezp8iJzUEIHZZmdxCXUEzBQU2X0ijjkPvVHHt
         Xv0g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=jDfIYFTb;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::543 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-pg1-x543.google.com (mail-pg1-x543.google.com. [2607:f8b0:4864:20::543])
        by gmr-mx.google.com with ESMTPS id h10si139993pgm.4.2020.10.05.19.09.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 05 Oct 2020 19:09:27 -0700 (PDT)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::543 as permitted sender) client-ip=2607:f8b0:4864:20::543;
Received: by mail-pg1-x543.google.com with SMTP id o25so7124074pgm.0
        for <kasan-dev@googlegroups.com>; Mon, 05 Oct 2020 19:09:27 -0700 (PDT)
X-Received: by 2002:aa7:8249:0:b029:142:2501:3964 with SMTP id e9-20020aa782490000b029014225013964mr2373840pfn.41.1601950167029;
        Mon, 05 Oct 2020 19:09:27 -0700 (PDT)
Received: from www.outflux.net (smtp.outflux.net. [198.145.64.163])
        by smtp.gmail.com with ESMTPSA id c9sm941792pgl.92.2020.10.05.19.09.25
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 05 Oct 2020 19:09:25 -0700 (PDT)
Date: Mon, 5 Oct 2020 19:09:24 -0700
From: Kees Cook <keescook@chromium.org>
To: Matthew Wilcox <willy@infradead.org>
Cc: Jann Horn <jannh@google.com>, Alexander Popov <alex.popov@linux.com>,
	Will Deacon <will@kernel.org>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Christoph Lameter <cl@linux.com>, Pekka Enberg <penberg@kernel.org>,
	David Rientjes <rientjes@google.com>,
	Joonsoo Kim <iamjoonsoo.kim@lge.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Masahiro Yamada <masahiroy@kernel.org>,
	Masami Hiramatsu <mhiramat@kernel.org>,
	Steven Rostedt <rostedt@goodmis.org>,
	Peter Zijlstra <peterz@infradead.org>,
	Krzysztof Kozlowski <krzk@kernel.org>,
	Patrick Bellasi <patrick.bellasi@arm.com>,
	David Howells <dhowells@redhat.com>,
	Eric Biederman <ebiederm@xmission.com>,
	Johannes Weiner <hannes@cmpxchg.org>,
	Laura Abbott <labbott@redhat.com>, Arnd Bergmann <arnd@arndb.de>,
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
	Daniel Micay <danielmicay@gmail.com>,
	Andrey Konovalov <andreyknvl@google.com>,
	Pavel Machek <pavel@denx.de>,
	Valentin Schneider <valentin.schneider@arm.com>,
	kasan-dev <kasan-dev@googlegroups.com>,
	Linux-MM <linux-mm@kvack.org>,
	Kernel Hardening <kernel-hardening@lists.openwall.com>,
	kernel list <linux-kernel@vger.kernel.org>, notify@kernel.org
Subject: Re: [PATCH RFC v2 0/6] Break heap spraying needed for exploiting
 use-after-free
Message-ID: <202010051905.62D79560@keescook>
References: <20200929183513.380760-1-alex.popov@linux.com>
 <91d564a6-9000-b4c5-15fd-8774b06f5ab0@linux.com>
 <CAG48ez1tNU_7n8qtnxTYZ5qt-upJ81Fcb0P2rZe38ARK=iyBkA@mail.gmail.com>
 <20201006004414.GP20115@casper.infradead.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20201006004414.GP20115@casper.infradead.org>
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=jDfIYFTb;       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::543
 as permitted sender) smtp.mailfrom=keescook@chromium.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=chromium.org
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

On Tue, Oct 06, 2020 at 01:44:14AM +0100, Matthew Wilcox wrote:
> On Tue, Oct 06, 2020 at 12:56:33AM +0200, Jann Horn wrote:
> > It seems to me like, if you want to make UAF exploitation harder at
> > the heap allocator layer, you could do somewhat more effective things
> > with a probably much smaller performance budget. Things like
> > preventing the reallocation of virtual kernel addresses with different
> > types, such that an attacker can only replace a UAF object with
> > another object of the same type. (That is not an idea I like very much
> > either, but I would like it more than this proposal.) (E.g. some
> > browsers implement things along those lines, I believe.)
> 
> The slab allocator already has that functionality.  We call it
> TYPESAFE_BY_RCU, but if forcing that on by default would enhance security
> by a measurable amount, it wouldn't be a terribly hard sell ...

Isn't the "easy" version of this already controlled by slab_merge? (i.e.
do not share same-sized/flagged kmem_caches between different caches)

The large trouble are the kmalloc caches, which don't have types
associated with them. Having implicit kmem caches based on the type
being allocated there would need some pretty extensive plumbing, I
think?

-- 
Kees Cook

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/202010051905.62D79560%40keescook.
