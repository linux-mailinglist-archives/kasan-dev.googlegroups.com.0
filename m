Return-Path: <kasan-dev+bncBC7OBJGL2MHBBEHFZT5QKGQEMOZ2NAY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43c.google.com (mail-wr1-x43c.google.com [IPv6:2a00:1450:4864:20::43c])
	by mail.lfdr.de (Postfix) with ESMTPS id E08C427CEA2
	for <lists+kasan-dev@lfdr.de>; Tue, 29 Sep 2020 15:11:44 +0200 (CEST)
Received: by mail-wr1-x43c.google.com with SMTP id v5sf1720308wrs.17
        for <lists+kasan-dev@lfdr.de>; Tue, 29 Sep 2020 06:11:44 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1601385104; cv=pass;
        d=google.com; s=arc-20160816;
        b=GtilluVr+GVx5o1CDHjT0WxRL07yB19Y6vX6gBP+Qsl58fD9mbHqEQ60JbHDVmN8Ea
         pxoLsthR3d8b1wsHcyk1sfLiJkHrlsfvlOsyLd21tqPxhdn2+V/J3BKpPQVCu7RKqoK9
         7MmkXUq8f/tQgI9/qtc3kk3dQb5fwG7Bnc0tBuN/HTb0K63gqqw2Q3uBBuC6hVm1dX6s
         49vR3CB5HxvII8MxGhA9iaMnvbZwcWrkbHfuGI5TAX4+fAWLnuINHW1maH4Pkwifuarn
         SySIyWTYdwiezAeJyfnk1KDm1QdAU1kClG9888HMmSzoR8hjC5G59d+HX3ROSGeQeMgT
         RgYw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=pu70wE4ERpW8al1l0ENHREjf8tS8uFR5FqsTov0U09I=;
        b=gdcpKwx/RSrTg1bG/3/z11QOP1attJok7mEd52FGruGoysoJ8uf/tWKVb+XbIKnMcS
         PPds4Nsu9QoePXo8+W7PtE329QgF1EePd14pBMNWOxnw1kEIu5Nqjz5VBa1HbiNUwIGF
         BzvydRkPyGM2DaUoFQkfEp4vbdbhd5ijGAB07zh3XoPFt3zUi6ovg7GIEpsDlHIvWFoq
         n5E+UV3tuhp7AzlsQe2l1gdqcqC7cUnvHsIEoTSwkSm5ZORG+NoXZmVhFb+64sXifBMa
         F1InRwy6CwgYoKM2Xpm2yXtw9rG0ivPYR8Ab+BSpCqpSXaw5k72BiJFesfEQiB+yL075
         yjJQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=RNHLBk7i;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::444 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=pu70wE4ERpW8al1l0ENHREjf8tS8uFR5FqsTov0U09I=;
        b=XQGOo2AFZr4xHxHgryabDgAsktW59X2RK/VXqBmc1VeYVSWDL/lHD+Ni3kY4gsfMru
         nmYrdtPjPediAvPkuGsO3WYdw7sT+O3iGHZqm9cV87x9dcixSPqzvlgB1cmDfCPh7sgr
         WVd8pnwgAYE4R8xRuVAczx+dgE7PnHSv1yozZUNfMlc0jvAYQlYkc9GoSk/9Ns8foGYb
         bdzZUvrv3vHU5tDljQhV3nGJrV2xe32QWUMvXdgWnYfd+61bN7CBD+6bHps1QzEnmPyB
         h6IuiFCuDxddIU3piHlK4ods/Usc3ysGzMmSuUnnV4kx/9ZfLpIqHcK1WJgpoN64lcEd
         FLJA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=pu70wE4ERpW8al1l0ENHREjf8tS8uFR5FqsTov0U09I=;
        b=C4Xk3XP87AgZQgbup7jBdZrnH1qpj2D0nRvcBeol9z2O7wxJSjkl3yp+Z+mphbmwtW
         vhzXSuswZQBQND4TpPYTkCtJkqdO/FsCSD3dabkrXRbHslep0QXiaPEZWp4gprc6EoKd
         bkUHiTLjQXJwxcsbTVAzV0/Pgv8aDkdEGwiLFja7Wajpxd3yjomTxIBqHKzcyewFksJA
         6n49hQg+XooJpdBRiAhfBSw9aQ8a78zbzbRpw1KYN7tmd4NNeBm9ykOazmd5mY6BrrFA
         3MHI/RbivaaUqK8vPURCbEEvn/gDG9gPAGOvsStItvX8HGDEsGJzmuBBAcwSxGC+bW12
         DQ4Q==
X-Gm-Message-State: AOAM53149PYR8L7X66qn3E+0CAPnmoJZbm0MybcUgcJF8SpItG6aGsdR
	vtt4jIx1vfRBsRJtGTEeR9M=
X-Google-Smtp-Source: ABdhPJx2aQpbG5qycyPngQ2fqHtHew8rAFI0RNE4hTLkMEhfOdr5oa80ljWCp5fFuiorR35tzgGxZg==
X-Received: by 2002:a7b:c847:: with SMTP id c7mr4567086wml.149.1601385104590;
        Tue, 29 Sep 2020 06:11:44 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:230d:: with SMTP id 13ls1789866wmo.0.canary-gmail;
 Tue, 29 Sep 2020 06:11:43 -0700 (PDT)
X-Received: by 2002:a7b:c21a:: with SMTP id x26mr3168573wmi.100.1601385103327;
        Tue, 29 Sep 2020 06:11:43 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1601385103; cv=none;
        d=google.com; s=arc-20160816;
        b=d1kvC6/8yIFi6YVla9CWz0pepVUqECcIFDCCu0ybsfSCVcM/xplgq8s4IGgJ/0XZWI
         I1ovBXv6QVhWzxDUp70GbbAOt+qguz2CylMkY5/rmZMDLGCl8bVYjb6f4vhWquW5294z
         DWTNSUWwf3kLeJKhu94ALMIjN9W+UPXL9VczMSepxAt/TclHlbkcvwsbJyFvAzGY+LJC
         ESi1PY1D3BKItmbSGCPwr7iYn394HsGtWhePzIbMQUSg/lA1D5ypf3PU7K72kkL9WDrV
         8bbQ+WCs0Oq75grHKAT++QVifv5WwapFfxv5Ms9AwiNutAOAqqBD2pNLfrU/ni8H2Rcp
         g6YQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=4Zoo7sR5M5htbvHNu3bicEUq1AAqj0gs6k4W5/ci+9Q=;
        b=cGlBaChGLT+cOIL4QI2sORcnJGJV6So3t1vtkV0ZsPMmTMSTN7dP7qCckaI/BAmJqq
         NiL58RGSpx1hdvppuzshdwsdbo9jEi1FS6jLItmPNO70mP6FSoorcUZUsvBRzsMaeSqc
         fqVnxLz+uryQkKbFRWhSYlMiWDE6o9hqvMli6bUQJvyylHTEPcUyNkm8ltOhtvqKczu/
         SnKWP7K8/apEvKKOVfN+WkHbOgDpOf6Ac3VMJSYtGjCc4NHMGYMCGY8dXGAMpHo6tPzW
         B0XIbHzAKY6Cw1w4V8IsrhQykZWdbug4zD3hBXot5KAMUeo+Mw+Ohvl7l32A9qlsupnG
         pj0A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=RNHLBk7i;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::444 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x444.google.com (mail-wr1-x444.google.com. [2a00:1450:4864:20::444])
        by gmr-mx.google.com with ESMTPS id s192si227789wme.1.2020.09.29.06.11.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 29 Sep 2020 06:11:43 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::444 as permitted sender) client-ip=2a00:1450:4864:20::444;
Received: by mail-wr1-x444.google.com with SMTP id e16so5371344wrm.2
        for <kasan-dev@googlegroups.com>; Tue, 29 Sep 2020 06:11:43 -0700 (PDT)
X-Received: by 2002:adf:ee01:: with SMTP id y1mr4452655wrn.2.1601385102792;
        Tue, 29 Sep 2020 06:11:42 -0700 (PDT)
Received: from elver.google.com ([100.105.32.75])
        by smtp.gmail.com with ESMTPSA id s12sm5024777wmd.20.2020.09.29.06.11.40
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 29 Sep 2020 06:11:41 -0700 (PDT)
Date: Tue, 29 Sep 2020 15:11:35 +0200
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>,
	Alexander Potapenko <glider@google.com>,
	"H. Peter Anvin" <hpa@zytor.com>,
	"Paul E . McKenney" <paulmck@kernel.org>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Andy Lutomirski <luto@kernel.org>, Borislav Petkov <bp@alien8.de>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Christoph Lameter <cl@linux.com>,
	Dave Hansen <dave.hansen@linux.intel.com>,
	David Rientjes <rientjes@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Eric Dumazet <edumazet@google.com>,
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
	Hillf Danton <hdanton@sina.com>, Ingo Molnar <mingo@redhat.com>,
	Jann Horn <jannh@google.com>, Jonathan.Cameron@huawei.com,
	Jonathan Corbet <corbet@lwn.net>,
	Joonsoo Kim <iamjoonsoo.kim@lge.com>,
	Kees Cook <keescook@chromium.org>,
	Mark Rutland <mark.rutland@arm.com>,
	Pekka Enberg <penberg@kernel.org>,
	Peter Zijlstra <peterz@infradead.org>, sjpark@amazon.com,
	Thomas Gleixner <tglx@linutronix.de>,
	Vlastimil Babka <vbabka@suse.cz>, Will Deacon <will@kernel.org>,
	the arch/x86 maintainers <x86@kernel.org>,
	"open list:DOCUMENTATION" <linux-doc@vger.kernel.org>,
	LKML <linux-kernel@vger.kernel.org>,
	kasan-dev <kasan-dev@googlegroups.com>,
	Linux ARM <linux-arm-kernel@lists.infradead.org>,
	Linux Memory Management List <linux-mm@kvack.org>
Subject: Re: [PATCH v3 01/10] mm: add Kernel Electric-Fence infrastructure
Message-ID: <20200929131135.GA2822082@elver.google.com>
References: <20200921132611.1700350-1-elver@google.com>
 <20200921132611.1700350-2-elver@google.com>
 <CAAeHK+zYP6xhAEcv75zdSt03V2wAOTed6vNBYReV_U7EsRmUBw@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CAAeHK+zYP6xhAEcv75zdSt03V2wAOTed6vNBYReV_U7EsRmUBw@mail.gmail.com>
User-Agent: Mutt/1.14.4 (2020-06-18)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=RNHLBk7i;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::444 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Tue, Sep 29, 2020 at 02:42PM +0200, Andrey Konovalov wrote:
[...]
> > +        */
> > +       index = (addr - (unsigned long)__kfence_pool) / (PAGE_SIZE * 2) - 1;
> 
> Why do we subtract 1 here? We do have the metadata entry reserved for something?

Above the declaration of __kfence_pool it says:

	* We allocate an even number of pages, as it simplifies calculations to map
	* address to metadata indices; effectively, the very first page serves as an
	* extended guard page, but otherwise has no special purpose.

Hopefully that clarifies the `- 1` here.

[...]
> > +       /* Allocation and free stack information. */
> > +       int num_alloc_stack;
> > +       int num_free_stack;
> > +       unsigned long alloc_stack[KFENCE_STACK_DEPTH];
> > +       unsigned long free_stack[KFENCE_STACK_DEPTH];
> 
> It was a concious decision to not use stackdepot, right? Perhaps it
> makes sense to document the reason somewhere.

Yes; we want to avoid the dynamic allocations that stackdepot does.

[...]

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200929131135.GA2822082%40elver.google.com.
