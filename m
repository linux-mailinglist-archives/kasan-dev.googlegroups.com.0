Return-Path: <kasan-dev+bncBCS4VDMYRUNBBTN7WWPQMGQEODVH76Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x1140.google.com (mail-yw1-x1140.google.com [IPv6:2607:f8b0:4864:20::1140])
	by mail.lfdr.de (Postfix) with ESMTPS id 47F0D698804
	for <lists+kasan-dev@lfdr.de>; Wed, 15 Feb 2023 23:42:23 +0100 (CET)
Received: by mail-yw1-x1140.google.com with SMTP id 00721157ae682-53317a0238dsf4243577b3.17
        for <lists+kasan-dev@lfdr.de>; Wed, 15 Feb 2023 14:42:23 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1676500942; cv=pass;
        d=google.com; s=arc-20160816;
        b=zJNMIFsYnMjxh8oAGIXOsSubFQadRk4MeSIjKCsQr2vQPXAgJ1PoPfeH3Nd2O/mVlk
         /OMnBPPJR62yYOaqtaqP9iIWEcMroHETsVUEPGctDGVncHAgc29ohGttadBIokjRy80Z
         sH6QHcQAXRLQi3GZE8kWKO+RVHtMIJ03Wps9L8j2oLHRO8H/H5+lgLYeRlnV6mnkFo4Z
         /snnXDNx001+3DIpPq/a16SUVtZn6Nh6lPSXlCsLWL5Oe29Z+VhScRSvldxzk1nImAHN
         5+tY7RpPwMWtmmF/9E3D3Tb4BHTFsO3cNOVNqLPjmwUlKfTDxdINmivM4Jvmf6hvC2wp
         d9jw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:reply-to:message-id:subject:cc:to:from:date
         :sender:dkim-signature;
        bh=Cc9QzvqCdw+T+ixUf5fykEyEvesLvQlyF+KVfGmzA8A=;
        b=dLTr+8d2EMK1VHwfDZIHWwvYLlJ0difUWX69McPPqXizq5OJ7voi2IiKdTxV80uEJn
         +b2ZHSHUX0XyeGVGdSkBVgvaksnYqQNvRwQHYuFjWHwTcc/bSeKi+GGOUxIxVOzl6yzT
         4KWRvaGkbuno3CQOkSIwH1ornNUrmFB/bvBrSUIeP9Fu98PDYeLYazNrOBir4Jycsh0O
         9wo/Zv/MegVdO5BFtuRZ+IDCxRnwBAcrmrCV83HRHmM2wXvsQcH6qbXnwd6peYhb27U6
         Wh7kmJqszkczq/Sbub80NIRHtCgvFYPL3Jju58zDXcpOPzFeHLmkvfUiGzJp4JYK1Un4
         NcFw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=HNwd9NX0;
       spf=pass (google.com: domain of srs0=dnx9=6l=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom="SRS0=DNX9=6L=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:reply-to:message-id:subject:cc:to:from:date:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=Cc9QzvqCdw+T+ixUf5fykEyEvesLvQlyF+KVfGmzA8A=;
        b=ryY07YolDuKaLvsRDEIUOGckV17EwpGmcea1USK5dASloJwzj+9/plMQn/Bq/CyuWO
         xgJw/e/QWlUlA7U7y6oWUq6WB6pSMG9ZfsJq5FJDSJxJexN45/G+NDVlQ1Yr2PXJz9A4
         86RIg3kreUGSiQImtltGJhls6syjtYbG8KS9A98Ye7eJPJtC1xAgOGn+vGvz08FWzhP3
         fom/57WZc+06z32YwVpLBc+UQ0XqNx7pdXaL2c5XgVAB62in+ZN+39Js151DC9MgXZdx
         hJJBXVuiGnl7331g+FiFk6IK3DSEOBhMDdwevOXhEHo9oKIYJE0UqJJHvm0VHvqYTcZQ
         os/g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:reply-to:message-id
         :subject:cc:to:from:date:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=Cc9QzvqCdw+T+ixUf5fykEyEvesLvQlyF+KVfGmzA8A=;
        b=foSsE5dGUwNy9AOTBXDxlimX2KG4ULoJ35ODRnpyvUicvfJLNrbNUsHpKzpPwSbknL
         ch7oxNb+4DVGHTnN4RI9zEfr5rtj/5qA1FdYSdpN/LqMCmt1YeJ3NXSjN+yCdYRT7jmo
         cufPe1jHhWZVhCNcy/iOFueoTmC0/UVAnpsjuuO31P1TsxACPSA9toCwSBC/crOpZRB9
         Eo1qV75XCGyV7/2wtisp7KtRYq9obOkm8GWtKgXW3DCmK1L+HjgFNK4ihvPwIiwSxXbU
         c+68IyUW9Sc26jao4DFlQGtT+nCSwaRCnav8984bk5qloT8B2xWFsuPIk/J7F841LM3r
         Cs0g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKWx5yTZDzRSLu+SwmWjj26W8pLcsUH2i4mecjhYkG0jgTiWhdCC
	fl+QfY4PHaDfhJdh5BaxHaM=
X-Google-Smtp-Source: AK7set9r4io4xsJsH19LB4l9XPO7pVBtocDUNI9j975n53M535Pvv1Q3Aptm7h/vV3beH8RIoFSOpQ==
X-Received: by 2002:a81:7186:0:b0:50e:e7f6:f3d3 with SMTP id m128-20020a817186000000b0050ee7f6f3d3mr431508ywc.87.1676500942000;
        Wed, 15 Feb 2023 14:42:22 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0d:cb50:0:b0:52e:eb33:90c6 with SMTP id n77-20020a0dcb50000000b0052eeb3390c6ls8094279ywd.9.-pod-prod-gmail;
 Wed, 15 Feb 2023 14:42:21 -0800 (PST)
X-Received: by 2002:a81:a547:0:b0:533:80b:1b25 with SMTP id v7-20020a81a547000000b00533080b1b25mr467099ywg.39.1676500941336;
        Wed, 15 Feb 2023 14:42:21 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1676500941; cv=none;
        d=google.com; s=arc-20160816;
        b=LtiodPWCCrcfdfdqW1KxSSQuK7Fuwd3G/ZtwGtwrgEmSXOTB4gcHKhFJb5xJeCecMr
         AxagGdc13ARIezNkNa+Yc3iJHRjT6DjIgzb21HFAeWvz/1aQyiG7GwlRNfcB/FNZ/ZvS
         DHO/tkaV+uXPU0V38x1d7NOp6uLRmZ0QKT/JblSxyZ7NX28mKGCIf6s+O4an1EHZahQB
         mY33IiTDkoBLA/39pSItCkkzL7fu0Yrvr6sjP6uLzX7to4TIfinVWP//v6emMY8KAc7E
         JZBN2BdAMbAzss2eGWZvC4pfFyOgdXCOO30FyoX/I8CXXaqkigRgo9JvziRuUMHoTmtg
         tJfg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=9GS9Yvu/3U1TI/QU0o5xSDvJIb2dNGuHoUwZetUkdvU=;
        b=lqMgknO/ckZ3fxmYxGn+vyFc/ZoKM7Xt/WDzfJz43suLpmB2Vly8RlEsNr6NKKznSB
         1MfQ5J1GnCN5+5is+qVJ0LEs9AABwHzsnfDpVQ5ehamsUDoJDjZXnn2WtzQie6Yq+X1D
         9J2H1q8Aq0pcnN7l46LC2/9RiueRDGoO69ZjiCpgEpCtRZ83IO1Qg+1Y0SUQ79vp8RfA
         iDsUz4Pdylo387BR47tf9i77zDuxz/4etb/ms6mpRCooGyvdkBvg18FFAjfMvb/4623p
         C0dM+BieBvJ4anbkOVYsbRRu7gCMVqUnd8zo5COrznPtjZ1liG+UYwH3FjB9InwluTbR
         xUAQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=HNwd9NX0;
       spf=pass (google.com: domain of srs0=dnx9=6l=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom="SRS0=DNX9=6L=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id k189-20020a25c6c6000000b00898c1f86550si7023ybf.4.2023.02.15.14.42.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 15 Feb 2023 14:42:21 -0800 (PST)
Received-SPF: pass (google.com: domain of srs0=dnx9=6l=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id F01C861DD0;
	Wed, 15 Feb 2023 22:42:20 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 374DAC433D2;
	Wed, 15 Feb 2023 22:42:20 +0000 (UTC)
Received: by paulmck-ThinkPad-P17-Gen-1.home (Postfix, from userid 1000)
	id 0EFE65C0F9D; Wed, 15 Feb 2023 14:42:18 -0800 (PST)
Date: Wed, 15 Feb 2023 14:42:18 -0800
From: "Paul E. McKenney" <paulmck@kernel.org>
To: Arnd Bergmann <arnd@arndb.de>
Cc: Marco Elver <elver@google.com>, Arnd Bergmann <arnd@kernel.org>,
	Kees Cook <keescook@chromium.org>,
	Dmitry Vyukov <dvyukov@google.com>,
	Josh Poimboeuf <jpoimboe@kernel.org>,
	Peter Zijlstra <peterz@infradead.org>,
	Miroslav Benes <mbenes@suse.cz>, kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org
Subject: Re: [PATCH] kcsan: select CONFIG_CONSTRUCTORS
Message-ID: <20230215224218.GN2948950@paulmck-ThinkPad-P17-Gen-1>
Reply-To: paulmck@kernel.org
References: <20230215091503.1490152-1-arnd@kernel.org>
 <CANpmjNNz+zuV5LpWj5sqeR1quK4GcumgQjjDbNx2m+jzeg_C7w@mail.gmail.com>
 <78b2ed7d-2585-479f-98b1-ed2574a64cb8@app.fastmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <78b2ed7d-2585-479f-98b1-ed2574a64cb8@app.fastmail.com>
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=HNwd9NX0;       spf=pass
 (google.com: domain of srs0=dnx9=6l=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org
 designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom="SRS0=DNX9=6L=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
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

On Wed, Feb 15, 2023 at 10:48:11AM +0100, Arnd Bergmann wrote:
> On Wed, Feb 15, 2023, at 10:25, Marco Elver wrote:
> > On Wed, 15 Feb 2023 at 10:15, Arnd Bergmann <arnd@kernel.org> wrote:
> 
> > Looks like KASAN does select CONSTRUCTORS already, so KCSAN should as well.
> >
> > Do you have a tree to take this through, or should it go through -rcu
> > as usual for KCSAN patches?
> 
> I don't have a tree for taking these build fixes, so it would be good if you could forward it as appropriate.

Queued and pushed, thank you both!

Is this ready for the upcoming merge window, or would you rather that
I hold off until the v6.4 merge window?  (I am tempted to treat this
as a bug fix, thus sending it earlier rather than later, but figured I
should ask.)

							Thanx, Paul

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230215224218.GN2948950%40paulmck-ThinkPad-P17-Gen-1.
