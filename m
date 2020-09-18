Return-Path: <kasan-dev+bncBC7OBJGL2MHBBT4PSP5QKGQEM3PX43A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53b.google.com (mail-ed1-x53b.google.com [IPv6:2a00:1450:4864:20::53b])
	by mail.lfdr.de (Postfix) with ESMTPS id 1DA00270010
	for <lists+kasan-dev@lfdr.de>; Fri, 18 Sep 2020 16:44:32 +0200 (CEST)
Received: by mail-ed1-x53b.google.com with SMTP id i23sf2403539edr.14
        for <lists+kasan-dev@lfdr.de>; Fri, 18 Sep 2020 07:44:32 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1600440272; cv=pass;
        d=google.com; s=arc-20160816;
        b=HUyW08swC6M8z15+jBL1MOZfEj5sfpV9EOw61bQIpioBe76jJwyNNZJy6m1VWftKtx
         Vmpstnf1C0ZemrPw+4Ps3VdtBhqVWJFuTkMHa1GwFhjCqurjL1L3S32UvkniJ8yXfuC2
         DAQX/457NQkUd8cJPzcC0B09RAu1hZyzLEEPKnkOK9DdNSPiigGpR1T+hVpB9POC5M+x
         eOTFfAYfdn5mz3vNAbZP9zw7aoKlEIQE8W2Db7dWjydJf596R2DYmVFjli+z7SCX8BtY
         0ji3xmZjN2dhy1Lzi991qegkcJx2YKv7VMVEhYLu5OnXetBtKYDo47idGZUY5E6FW0eL
         J3nA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=04mPDTMpH9x6ibFP+PlVBMyfnXHoL5RKbqP/G4I5hbI=;
        b=hjAtMpeafQ5rYob0j+i1wvhYZ+vgmMNnE+oxcZGPENq753UOi6aNP0Qkt4CZ6UjwiE
         17Z8jGmO9cynaczG/hoJD2bRuzvQuyZDJktuk/2YFsWC+qoa90yspI0qhI9vjXfQBFU7
         iQtzfSwIhp6nFTtL+NXjQGJvxp6SNFz3GKHkQ+nqSfVFyx5ek9Hz7ScsNSWCrg8v6iof
         A+qvoX/PigrBiLZ90LCNSMNKlLtRL670jqs+l6FONBbTc3+bDUDNtz1PVLL4uG48/bYK
         Z3ORalFAGMj+v0/sAKgEtwRQ3OEM4wkp5Furg7eVSrzkf3gz06EPc7JFmFIRLEaRKcjd
         qVBg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=XIp6kndV;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::343 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=04mPDTMpH9x6ibFP+PlVBMyfnXHoL5RKbqP/G4I5hbI=;
        b=ZjCesinmHHu1CJQ3ypV43vbt1CQT2l3MmH+kpaJEllG/Of9sRQNz/GIkSaAorvoZKl
         gHYlfyvkGPTlhQGYZ7BTisKTg2sxXnThtZGUiSJoh9H0fwq6Bmyl9bx91g4jXzI2mKYO
         MxSQYEojz1S0IDYgBgn2oaxBjYyjLnHpeXT+BTMldFQV/D3i4+pVdsew9hL2SAMgArFs
         a6hyZY8jYRXqbxxngoMq5UhKqPRp6QsE9ANgqlRxtpbXKbpOPYaiqOXIwZgDDMzK85lc
         S4MlNi1P+KXRBj/Y/JbUit5nWeFqluzSO7BFMrZLqDYKRuXIzzE1Hz1ZbAPDJiftL8z2
         kb5w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=04mPDTMpH9x6ibFP+PlVBMyfnXHoL5RKbqP/G4I5hbI=;
        b=k3lZ6adg8uXq3E28qBJKWkRBLaGM3J5x+TBTYZAXMaEiiukZDN3lHVXQz54LmUbE0x
         ep5l622eQRWPOAF65IS9an1mMHdCYtWHgEdDAsYIOzqb4Aa12BeMI5S/EPEKKjIxM6kA
         EAgJpQh9mZ66IWtIN1ck9/Co/Xc4Ighbz3fVHvcPTT+bDRkpJU0U4HtXEO6+BmPPZ+2I
         HRrqYQ/l195xcFqTGP6r45p9C0AdoIWIIH+vwPqPEsVxwTeU2zD9f9OZcXUea5+vD6eK
         uZ4cccIDrai6iRrrA0miPQXejwlknB/urmIQ3JhwGjTsXa1kkm77nNhFiM69X79B9vrC
         VZUA==
X-Gm-Message-State: AOAM53353ddkmD/bSMm+dVOCKfn0d0MUOxHamGJh/r4+CfsDbjJsNEC6
	XGhqRy/Nye48LgFb+UscaZQ=
X-Google-Smtp-Source: ABdhPJzPAsJio268x4o83mmmrydZ1tIQPcUfaDhpenqS/QOQqCgbD/Oy3SVxvpxE3zvHVIUQztswsw==
X-Received: by 2002:a17:906:a4b:: with SMTP id x11mr38403077ejf.368.1600440271832;
        Fri, 18 Sep 2020 07:44:31 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:c9c2:: with SMTP id i2ls742129edt.2.gmail; Fri, 18 Sep
 2020 07:44:30 -0700 (PDT)
X-Received: by 2002:a50:fb0e:: with SMTP id d14mr40433506edq.172.1600440270777;
        Fri, 18 Sep 2020 07:44:30 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1600440270; cv=none;
        d=google.com; s=arc-20160816;
        b=jQlVjVblowEeAnLmoNnLAh5gslPDoKHHfsicYj5RM3T/GHgtD7DJp6YmNO7OZtlB9T
         LixbULgwuSCjE+jhvyJ/6SSGgFSgFPhx5ykINgbwltF7TsLazaOp0H11/pAahambwFQS
         6jw4IYO+OO2QjswWgTnOrYv+aRANBlW4Te6EjD1ALbZy8mLP4RTZxfEDVDgNxbc88MLS
         ZSkxLG6nzcYBfrTNtfhGsbyrF5UpnMKA7ZP8hDAubS2H97086hI8DCCdBlTL9OZNS3g7
         T4JbubPyVis+FgdADLG9y/3Vs0n5JD/MYoA+miRlyiegTzrr7OeWs+vnPY14+ijzjeGq
         CzuA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=6NiKzp3GYnVNlrj1nKLgBBFJ1a03bOSILhGt3u/+Pok=;
        b=Wz/xzywjcCCSNGgIH96lsGZizigd1nvsTz+yz58QXmPyuJAXbD6LiBXq0t0iSEtW34
         RmVRlES/Q/hwrmACaWd90OWtZJflMT5qtzTaMfoByZslYAzOlu34xVeCYs74tlaADoSy
         /3MdrK+QzEHQ9wemBgeiHYgLzUxW6I6y9CaJttRW1WeAsD2rzzhPL3+mjFhWIVZLldWC
         HGQTyBi61GYUWCdYq92swjBzEhFxeRW3YJIOQ2EJ09Ghv/kDu+mXI2xXsUbAHMSe9YOj
         PaKDrpSl2vKhHjcksRYcgT3GHZwjGkdfJ3GOw6vPPLdOSS/gfYXTPcdxx+GOQ/0GVPzp
         iblA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=XIp6kndV;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::343 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x343.google.com (mail-wm1-x343.google.com. [2a00:1450:4864:20::343])
        by gmr-mx.google.com with ESMTPS id t16si60255edc.0.2020.09.18.07.44.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 18 Sep 2020 07:44:30 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::343 as permitted sender) client-ip=2a00:1450:4864:20::343;
Received: by mail-wm1-x343.google.com with SMTP id d4so5582773wmd.5
        for <kasan-dev@googlegroups.com>; Fri, 18 Sep 2020 07:44:30 -0700 (PDT)
X-Received: by 2002:a1c:a953:: with SMTP id s80mr15793418wme.70.1600440270291;
        Fri, 18 Sep 2020 07:44:30 -0700 (PDT)
Received: from elver.google.com ([100.105.32.75])
        by smtp.gmail.com with ESMTPSA id s17sm5860736wrr.40.2020.09.18.07.44.28
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 18 Sep 2020 07:44:29 -0700 (PDT)
Date: Fri, 18 Sep 2020 16:44:23 +0200
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	kasan-dev@googlegroups.com,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Elena Petrova <lenaptr@google.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Kevin Brodsky <kevin.brodsky@arm.com>,
	Will Deacon <will.deacon@arm.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org
Subject: Re: [PATCH v2 35/37] kasan, slub: reset tags when accessing metadata
Message-ID: <20200918144423.GF2384246@elver.google.com>
References: <cover.1600204505.git.andreyknvl@google.com>
 <f511f01a413c18c71ba9124ee3c341226919a5e8.1600204505.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <f511f01a413c18c71ba9124ee3c341226919a5e8.1600204505.git.andreyknvl@google.com>
User-Agent: Mutt/1.14.4 (2020-06-18)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=XIp6kndV;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::343 as
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

On Tue, Sep 15, 2020 at 11:16PM +0200, Andrey Konovalov wrote:
[...]
>  static void set_track(struct kmem_cache *s, void *object,
> @@ -583,7 +585,8 @@ static void set_track(struct kmem_cache *s, void *object,
>  		unsigned int nr_entries;
>  
>  		metadata_access_enable();
> -		nr_entries = stack_trace_save(p->addrs, TRACK_ADDRS_COUNT, 3);
> +		nr_entries = stack_trace_save(kasan_reset_tag(p->addrs),
> +						TRACK_ADDRS_COUNT, 3);

Suggested edit (below 100 cols):

-		nr_entries = stack_trace_save(kasan_reset_tag(p->addrs),
-						TRACK_ADDRS_COUNT, 3);
+		nr_entries = stack_trace_save(kasan_reset_tag(p->addrs), TRACK_ADDRS_COUNT, 3);

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200918144423.GF2384246%40elver.google.com.
