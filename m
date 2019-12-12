Return-Path: <kasan-dev+bncBAABBQNLY3XQKGQE23XKNEQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63d.google.com (mail-pl1-x63d.google.com [IPv6:2607:f8b0:4864:20::63d])
	by mail.lfdr.de (Postfix) with ESMTPS id 971A011C20C
	for <lists+kasan-dev@lfdr.de>; Thu, 12 Dec 2019 02:20:03 +0100 (CET)
Received: by mail-pl1-x63d.google.com with SMTP id t17sf428066ply.5
        for <lists+kasan-dev@lfdr.de>; Wed, 11 Dec 2019 17:20:03 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1576113602; cv=pass;
        d=google.com; s=arc-20160816;
        b=W2pkEByEne8KU5hrAUqLfMbx9/Js5tusoYUDYRmaya8y3lQtyINdB14NRfrb9Nw9EE
         TgMVXo+e4oVEkhjLxj8eGeA6V+CDuYtd5O4LIfH++QRmH0qFmiFm1HILbdF/MT8z52uu
         34NpxWGPfdmwoXyzHNTO4nYcTWtLO6pavRcxq9LG+9UvN1PxeUnWEbgDMKjX6VG30axS
         0D9FGH3DWafa32BulF81Gsqf3laUDgaWsWlcmV6kza6p3uMWEwbLvGW2T2fybG086308
         w8UHX6q6fntdA4vBKRYhYr2Rh998bZCRsHP2hNHEHvxTt53mR4pfsEeyCLkgLcAGTLGU
         okiQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:reply-to:message-id
         :subject:cc:to:from:date:sender:dkim-signature;
        bh=z/pOVu5XTIw7nDFwxfke7mM/14DDMHVK1DMVQrqu5bk=;
        b=ZJ1Zo9VAeKqpEUuRG1didxrOZMyOLn1r9G3rWXXAZX7Z40V5PMxs3pOe9cWE5F/qDE
         Gx2xjOud5cU7wujAaDFS3LMgI+t3GAnHDIohuurXDHQ06rdcMd1qwD16pMAW6rkSYE9n
         /xx6MjakcOItKacwsnezzZpt4VnZQxy9Uf4qo4/8QNZOuq4BWCl3wNekFInk2dlh1EZm
         I+DPBL8TV5AB6kNfO8e3xJoDv9LOfFvqiRE79f3yld/88+4FTo1TkKtvnlJWvTmZXRmc
         PdfXqrMfzj4LIFdBdRBO4L195LjfFSQxyfaL0jxBOqgjzSWjYe9XTw2DBtnIl2OuFRz/
         AJUQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=L5fWSRXd;
       spf=pass (google.com: domain of srs0=vt98=2c=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=Vt98=2C=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=z/pOVu5XTIw7nDFwxfke7mM/14DDMHVK1DMVQrqu5bk=;
        b=ZyMIfaImxegzHRphsf4E2IaydSeGZckrisR9AnZpFwo5ui922hPXrsdPVLE0/TYUAF
         hTj2vBmKWfHT+K+LTYNDOzx1B6VtSsd6RCZ4xesYdwh3z0qOCCjl9oz2LPkmuQYkSSL3
         48siboKG4Ma0R/EBClSCqkM5Qayj/s56nHuUAld2KM28ul4HTQsGefvDGnqeIyuhSPP0
         wLT/U1lMS/HW+YdcM9dzG0ZCax12PW5+n01kDQPbhkyBUn2iQH+OEys2mGzCdJhnqkLf
         QDnSEHEQjv6qMUPJsd5VvETjAala8+5N5OyM4tT2q8wjhdiEK6H6eosG+nmuc+P3qySz
         Eeag==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition:in-reply-to
         :user-agent:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=z/pOVu5XTIw7nDFwxfke7mM/14DDMHVK1DMVQrqu5bk=;
        b=kSeCOMvQnd1tlJq2dIh4uU4NrusNb+HAN895h7DdqtIoMOjzKzPrlzZRwi2n1NQ9jF
         l7jSLAVFlQntguad78Wr3EmfbPvgI6edlLiuZD+fRATwH3Nt8UkQBGEhV14/KZA8KBkc
         pP49c/gxxx36m+35ublvP/kedsbSUpaDHRPewI9HC0G59z170w7Ttk/TUyxI3DQMkq9l
         OOj8W2MfeXVb/3ea3oYDGtp8Am9NQbTeMRomaakffAlGGoLEUZ98NmdQsVTuHKyMVtv9
         zKnVCfTZPzDWmAku73nzoTvBcCOneafA7v2+lVETkPfotiMwHyX0Ib+lzuIEVMhDb4J9
         nywg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVqWhzAOuN5vhyo6NRTly+uEFm6F299tcKqEU+6gBJeo7/l5a0J
	A4ygau1Znks2TPbcaOIiTAc=
X-Google-Smtp-Source: APXvYqwi5FGbxvFKEqRfPXE+kkRYc65MnNhD/JhsFJfL/te+1YMRVT0Ki7eHdrcBXJkA5f7Pfb3ctw==
X-Received: by 2002:a17:90a:b38f:: with SMTP id e15mr7026060pjr.101.1576113601673;
        Wed, 11 Dec 2019 17:20:01 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:2703:: with SMTP id n3ls906526pgn.5.gmail; Wed, 11 Dec
 2019 17:20:01 -0800 (PST)
X-Received: by 2002:a63:4b49:: with SMTP id k9mr7528945pgl.269.1576113601349;
        Wed, 11 Dec 2019 17:20:01 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1576113601; cv=none;
        d=google.com; s=arc-20160816;
        b=o4/HMPQPfjnz4E0RZ5H03BhxKqwRjtICOHkmyUmp7TbElyeleOOGW3M0/PmPHGlr/3
         F9GbTkc5v3u6moS+3KKBFIJsuq/zc19ZVCMeSg4pwl4J2nxxv2XXiM811PgG9JVa6khS
         nzC23Krdt6ilDnYOu48kpsgh4pbtMFhBRiGSNpdNF4Ow/06ofjr90r/okZmjS6/MPYPm
         DoOVCCpnMwGnin/N59LTBE6W1DkyCeWQQVBLNZkK0VqFsbY853REk3dsxIY9FKzq4WMh
         8+2J0FeeKezAat2U3SlBaSHOtf2dLz4A1hUKUcAChyvARChjwW2h7c09vI2jyj5Vhjy4
         JWSg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :reply-to:message-id:subject:cc:to:from:date:dkim-signature;
        bh=/CgnngspqXUiViVBtDBHO52oSAxz2y2DL75wL6Ka794=;
        b=U9M2kcPOA22ELyCZ2pmSjCjzE0gvUGadlxhc+ZPzuy+3VfO9Ay6xM1GJsWVA8aXm1f
         QZKgBusTf0nbsi9Uw0UNxbJGZRM1tNuAl1FC1Z2jVUh+FVR5R+TKl3Y6jVXvpuq6EwF2
         JgNoG7wupqQqIBUitiRz+EDk5rnPmunCmpEAmBRLKzBByE6Vx6qA5MkRag3Y6uVmQKm4
         2VlPtPtNpxJc2GoH2fO2MpAF6GI2qFBSUTCvPgknUFy56KoZECTGdPX6wV1ogDuxlLt5
         2P4TiOnxLfZTpjpdCegVr7KwLL6LdbR+99IxblphOhTWt0Ys/8c9k9FKA4NcTMaLVCoI
         EupA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=L5fWSRXd;
       spf=pass (google.com: domain of srs0=vt98=2c=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=Vt98=2C=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id 102si144379plb.3.2019.12.11.17.20.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 11 Dec 2019 17:20:01 -0800 (PST)
Received-SPF: pass (google.com: domain of srs0=vt98=2c=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (unknown [199.201.64.130])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 06904214D8;
	Thu, 12 Dec 2019 01:20:01 +0000 (UTC)
Received: by paulmck-ThinkPad-P72.home (Postfix, from userid 1000)
	id 8DCB535203C6; Wed, 11 Dec 2019 17:20:00 -0800 (PST)
Date: Wed, 11 Dec 2019 17:20:00 -0800
From: "Paul E. McKenney" <paulmck@kernel.org>
To: Marco Elver <elver@google.com>
Cc: torvalds@linux-foundation.org, mingo@kernel.org, peterz@infradead.org,
	will@kernel.org, tglx@linutronix.de, akpm@linux-foundation.org,
	stern@rowland.harvard.edu, dvyukov@google.com, mark.rutland@arm.com,
	parri.andrea@gmail.com, edumazet@google.com,
	linux-doc@vger.kernel.org, kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org
Subject: Re: [PATCH -rcu/kcsan 1/2] kcsan: Document static blacklisting
 options
Message-ID: <20191212012000.GP2889@paulmck-ThinkPad-P72>
Reply-To: paulmck@kernel.org
References: <20191212000709.166889-1-elver@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20191212000709.166889-1-elver@google.com>
User-Agent: Mutt/1.9.4 (2018-02-28)
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=L5fWSRXd;       spf=pass
 (google.com: domain of srs0=vt98=2c=paulmck-thinkpad-p72.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=Vt98=2C=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
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

On Thu, Dec 12, 2019 at 01:07:08AM +0100, Marco Elver wrote:
> Updates the section on "Selective analysis", listing all available
> options to blacklist reporting data races for: specific accesses,
> functions, compilation units, and entire directories.
> 
> These options should provide adequate control for maintainers to opt out
> of KCSAN analysis at varying levels of granularity. It is hoped to
> provide the required control to reflect preferences for handling data
> races across the kernel.
> 
> Signed-off-by: Marco Elver <elver@google.com>

Both queued for testing and review, thank you!

							Thanx, Paul

> ---
>  Documentation/dev-tools/kcsan.rst | 24 +++++++++++++++++-------
>  1 file changed, 17 insertions(+), 7 deletions(-)
> 
> diff --git a/Documentation/dev-tools/kcsan.rst b/Documentation/dev-tools/kcsan.rst
> index a6f4f92df2fa..65a0be513b7d 100644
> --- a/Documentation/dev-tools/kcsan.rst
> +++ b/Documentation/dev-tools/kcsan.rst
> @@ -101,18 +101,28 @@ instrumentation or e.g. DMA accesses.
>  Selective analysis
>  ~~~~~~~~~~~~~~~~~~
>  
> -To disable KCSAN data race detection for an entire subsystem, add to the
> -respective ``Makefile``::
> +It may be desirable to disable data race detection for specific accesses,
> +functions, compilation units, or entire subsystems.  For static blacklisting,
> +the below options are available:
>  
> -    KCSAN_SANITIZE := n
> +* KCSAN understands the ``data_race(expr)`` annotation, which tells KCSAN that
> +  any data races due to accesses in ``expr`` should be ignored and resulting
> +  behaviour when encountering a data race is deemed safe.
> +
> +* Disabling data race detection for entire functions can be accomplished by
> +  using the function attribute ``__no_kcsan`` (or ``__no_kcsan_or_inline`` for
> +  ``__always_inline`` functions). To dynamically control for which functions
> +  data races are reported, see the `debugfs`_ blacklist/whitelist feature.
>  
> -To disable KCSAN on a per-file basis, add to the ``Makefile``::
> +* To disable data race detection for a particular compilation unit, add to the
> +  ``Makefile``::
>  
>      KCSAN_SANITIZE_file.o := n
>  
> -KCSAN also understands the ``data_race(expr)`` annotation, which tells KCSAN
> -that any data races due to accesses in ``expr`` should be ignored and resulting
> -behaviour when encountering a data race is deemed safe.
> +* To disable data race detection for all compilation units listed in a
> +  ``Makefile``, add to the respective ``Makefile``::
> +
> +    KCSAN_SANITIZE := n
>  
>  debugfs
>  ~~~~~~~
> -- 
> 2.24.0.525.g8f36a354ae-goog
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191212012000.GP2889%40paulmck-ThinkPad-P72.
