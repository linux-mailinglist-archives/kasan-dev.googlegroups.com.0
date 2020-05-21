Return-Path: <kasan-dev+bncBDAZZCVNSYPBBYEHTL3AKGQEXC26CCA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1037.google.com (mail-pj1-x1037.google.com [IPv6:2607:f8b0:4864:20::1037])
	by mail.lfdr.de (Postfix) with ESMTPS id D4D7E1DCE3E
	for <lists+kasan-dev@lfdr.de>; Thu, 21 May 2020 15:36:38 +0200 (CEST)
Received: by mail-pj1-x1037.google.com with SMTP id gw3sf4886724pjb.1
        for <lists+kasan-dev@lfdr.de>; Thu, 21 May 2020 06:36:38 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1590068192; cv=pass;
        d=google.com; s=arc-20160816;
        b=A9XHILT3QikxIBdKwfddaEZV9iYZqvi75yTydWPUSOWVIyxRhvPMZhKHogw0Mtu2xa
         bHGUvSPi6zt2aTJ0VmlN7L6TTYKBBT2gs1wPCsvdp8G/DPif1ogRsCtv2SL+i68TNSda
         VXQHb7e0UJfki5vkQ8jX08n5vftaLQm2bc/Nq5jTUxjLS/tmMz8epq/wHcCWAKp/B+0B
         XkXriOyRrUxcaXXJsuYyYU9iAF9DlReKcCRtywIgTJ9aMC6GiAhVM06WjSMIZUsopdsi
         S60hJ9Pf39srh0cbYxOfZJrgZ9zJgjNIq5LwnIrat54Tht+IXdrQcZ+m7BG//4kxbDZr
         kYBw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=kSJVMl16zjRl2vTfTMelVlINyZyJGantc0FsiPIVBuk=;
        b=rr0V+ND8V8W5R0AQ0HC8FJQxqRtlZN0gmYUMG2zCM8/rb45eugYXjxn+0RFqfc1c+n
         Ok1m6Yt/m/QFJe0SuK5CqoAqeEOJk+TuVPH4f4T0iwj0OTK2b2zT1SfRNjvlO/jOuRej
         cQHV3DOm0It6xzGIFvhw4pakf0aajPUYM7x/gauKGMYJ4Uy36f4AdzYr2zd/42YGMq8u
         wUxUSi+AkSHLgvdbopAEbBcwam+7qP2GkxTGrnorg7yYhLj/+ZP0Gr1VVZ8E2byluQHj
         CnoR6RxinPLKkQuVNbLs+7d+FsanY/DEVsadY0lThpd4JNZyu7Ry0VQ4fb9upjYyxsZu
         1eTA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=fiiMcKpG;
       spf=pass (google.com: domain of will@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=will@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=kSJVMl16zjRl2vTfTMelVlINyZyJGantc0FsiPIVBuk=;
        b=pK2QpknQsQ8xRh/4is2t2Nory7I9XXo5CmyVg/mk18SgCc5i/i7MBEtD0X8KfSlvjf
         mkz2v8THRnkT+TZtSZjrEqhBEK19HEFGVHuc4d2vGQXwiO+kSsF0/dJalk+IjQ4L2s7G
         3kAwfd0Jf1NnahPSfph8kHIMzgMRE/G5eLaSReP2G0E+acVZW/zwVS/R4yNvqaOiSv0V
         HhNCDYXvldyc+EtEaKJ8SVP9OOCfzUC2OIsY6c0E2y65Zg5quNNigR0Onh0BMLroCMm3
         yHLmkyilbEegMaODP2ok8tQmc/7Piol8FI0ULYJs7A1Y8VckknUruEo59gu/Ud7zjGYU
         p1nw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=kSJVMl16zjRl2vTfTMelVlINyZyJGantc0FsiPIVBuk=;
        b=sPUXw/pzM8c9rS+aveLetBxz4PV6qB2JjMFJ8oQMeDcLcLcDWZA4OkifAbu6b66cRl
         McxSgkva0yZrEDO98KpEqs7hF57DELhAd55jy2pOB3voCrR+e4c7E0IynHzBssOqAbfz
         3AuhkLaKuXCJE1GDTiOWIHiHB8sTVzQhbTVrras+AMOJO0eKhZ4pyGoacVn7DqUy9Bwx
         6N33LXvK0CgXHMXQmbEa05Ui5LH+E8skIVGvjCJlIIAyMKJQHavQF02kxtTiBixvTjws
         uBwybI+XFZw/b1F0LLKA3kEu4+eXq697nOW3BtcBCZCSc83p0fjB+cWy4V0kodwzYdGI
         6nHQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532n6sWj4TVa9hYqQ7zdMqKuuy1wipnL1lX+3xn1NjtWnyGY2TUw
	oC5waZrcKl0OxILUXSYA0v0=
X-Google-Smtp-Source: ABdhPJxYkUEC1dqpHAR/Jd7VBrEKk0197VC6Js81aW3iY/g956kAYh14dAXd90WjCwnZYNgn3NbshA==
X-Received: by 2002:a17:902:9049:: with SMTP id w9mr9897511plz.27.1590068192607;
        Thu, 21 May 2020 06:36:32 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:12c:: with SMTP id 41ls851067plb.2.gmail; Thu, 21
 May 2020 06:36:32 -0700 (PDT)
X-Received: by 2002:a17:90b:1482:: with SMTP id js2mr11708938pjb.54.1590068192193;
        Thu, 21 May 2020 06:36:32 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1590068192; cv=none;
        d=google.com; s=arc-20160816;
        b=MoXr2SGt4nwGNsz+7OvK2xjRPAg9wLwXBvu1mWlfSFyFw/THQmeTmKRCyPMWFMBjqo
         /FuO3VLLEi7LHVSwVeWGfY78YZP8OsE/u1K+srj+Oq6i6TgXUygwoIx1qwlcb31RqP/h
         bPmjf/eEBUac1l9UcsLoYLGltOsuOgw5lOWJNKfjVnv/U2hRww21C9zoFShr7eRgpn8W
         XXl9l8ubMLqYkDGNEmFW8UgHZE/WVfatQGQueNh5Vf0PnGh1AicTnBESahRg8wgVE2LI
         xcP5h1xtQEc9qWvw1FPAQ9N958q9GfxRA0ETNCZtGMx//qgpZxrcdyG5dACoDA9lsAfW
         3DaA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=TrxgtGTSAC7ifLG9JVpgD2MapbqmJasl4O3XfSPPhiw=;
        b=aXBblP8qarGe95kAXm44wlBDdi9XdBvbSbJbzxy/HgU7HucxiAdHnl5EAuTXdRqCHs
         S9PB01VRvZ2P5lEZqNb9xk467khyfpug0Y6v4CrbiaT4WINlQC9ieMtTw+0CXtMjuw9S
         2H+kiBGP+fPwcUwrUdCRRCf1R7c7Mf5VyDhnewnLbOd7k+XCVtmOItk6rOfMRdaidJnA
         pszCUJAehsGcFjfz7N7FxaBF3T5ywTsN1tLkYOsHlhwygXmKPx8sfk1Vqz8J9R4Mx96r
         bKkC08gAJ36vXjuT6+MOxMvgMdljMKlEkgT1VS6Xp9ZHhoUBlHP0Utr525PRkVR7Dl4U
         aufg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=fiiMcKpG;
       spf=pass (google.com: domain of will@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=will@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id q1si369452pgg.5.2020.05.21.06.36.32
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 21 May 2020 06:36:32 -0700 (PDT)
Received-SPF: pass (google.com: domain of will@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from willie-the-truck (236.31.169.217.in-addr.arpa [217.169.31.236])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 02B1720721;
	Thu, 21 May 2020 13:36:29 +0000 (UTC)
Date: Thu, 21 May 2020 14:36:27 +0100
From: Will Deacon <will@kernel.org>
To: Marco Elver <elver@google.com>
Cc: paulmck@kernel.org, dvyukov@google.com, glider@google.com,
	andreyknvl@google.com, kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org, tglx@linutronix.de, mingo@kernel.org,
	peterz@infradead.org, clang-built-linux@googlegroups.com,
	bp@alien8.de
Subject: Re: [PATCH -tip v2 00/11] Fix KCSAN for new ONCE (require Clang 11)
Message-ID: <20200521133626.GD6608@willie-the-truck>
References: <20200521110854.114437-1-elver@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20200521110854.114437-1-elver@google.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: will@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=fiiMcKpG;       spf=pass
 (google.com: domain of will@kernel.org designates 198.145.29.99 as permitted
 sender) smtp.mailfrom=will@kernel.org;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=kernel.org
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

On Thu, May 21, 2020 at 01:08:43PM +0200, Marco Elver wrote:
> This patch series is the conclusion to [1], where we determined that due
> to various interactions with no_sanitize attributes and the new
> {READ,WRITE}_ONCE(), KCSAN will require Clang 11 or later. Other
> sanitizers are largely untouched, and only KCSAN now has a hard
> dependency on Clang 11. To test, a recent Clang development version will
> suffice [2]. While a little inconvenient for now, it is hoped that in
> future we may be able to fix GCC and re-enable GCC support.
> 
> The patch "kcsan: Restrict supported compilers" contains a detailed list
> of requirements that led to this decision.
> 
> Most of the patches are related to KCSAN, however, the first patch also
> includes an UBSAN related fix and is a dependency for the remaining
> ones. The last 2 patches clean up the attributes by moving them to the
> right place, and fix KASAN's way of defining __no_kasan_or_inline,
> making it consistent with KCSAN.
> 
> The series has been tested by running kcsan-test several times and
> completed successfully.

I've left a few minor comments, but the only one that probably needs a bit
of thought is using data_race() with const non-scalar expressions, since I
think that's now prohibited by these changes. We don't have too many
data_race() users yet, so probably not a big deal, but worth bearing in
mind.

Other than that,

Acked-by: Will Deacon <will@kernel.org>

Thanks!

Will

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200521133626.GD6608%40willie-the-truck.
