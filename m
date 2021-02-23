Return-Path: <kasan-dev+bncBDAZZCVNSYPBB5XT2OAQMGQEVRN76AI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63c.google.com (mail-pl1-x63c.google.com [IPv6:2607:f8b0:4864:20::63c])
	by mail.lfdr.de (Postfix) with ESMTPS id DC8CF322AC9
	for <lists+kasan-dev@lfdr.de>; Tue, 23 Feb 2021 13:49:59 +0100 (CET)
Received: by mail-pl1-x63c.google.com with SMTP id w22sf9986559pll.6
        for <lists+kasan-dev@lfdr.de>; Tue, 23 Feb 2021 04:49:59 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1614084598; cv=pass;
        d=google.com; s=arc-20160816;
        b=aDnWKgog1AX34RPsN5j4dCnft8mebV2IyVq3wP6WvVOJtt4Z2QGg25uXSLjNnPfcNz
         BKkltqU9FNJY5taAd8bAHMy74rZaX8bT9h2F6Os0gPNvSAeenerYzUTrVD2oPvJMfb65
         3+d01Jju5gfwk2aP3nP//wmVarmu6XTwtsgN6KBgLaOoec8jesh3ek88lN7RhKG5SoQh
         x58CEU3sVGnyPGMZ8UhexVz4AEwGjBGHpcS6SzPiezE3rS5vGS35Z0ZlJr2IYxt+9zpT
         MtrOfel6WqUFOIhm3EHe05kT/mT/iuOv0mka9uU6goEKOf5ej4LUvCNKEjh4UM6ahe9p
         0lPA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=yV1u9arsLimYsj93gOcu6wLUZ32KVKqvVtVvOJge1SA=;
        b=jR+inJ1rUjA0tu61ftpL5i6H2uaA5LqfFcA5k6n7simahx3GSGilElIPqE1YH1sSHi
         6IRvM1jTXPEpgYVZaaNk5FREj7Vm+4foUk2FRh5HCU2x9C7/QkiHtW7yyInApWHWhc0y
         OAih5V7rEN+JlTfM/7na+NBNoBrKsLQBCQKXZf6ESevM9mjqIGQLW2nxrzcIJewi/ocx
         uCK15dimVreNKf1lSmN8HO3tbQL1lJP3j1vzJGLfHzbAhmN1xz5CDKp46GTLMiQ2gyXe
         BA/K1Txp0tlaUoKD25bi2M5TPLLJvzwx1VM/DtgXytm/EVQpJmdFjh/TumTSenviThpw
         uM1w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="cjBbeVP/";
       spf=pass (google.com: domain of will@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=will@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=yV1u9arsLimYsj93gOcu6wLUZ32KVKqvVtVvOJge1SA=;
        b=EnuaM16Gd5IpV79WRbzHbsu2tQf8zjFvp1jqjr1PypHCTILuVZOiEjboKTMaOy6JZF
         qt62Fr0DJFLn6VGxXPJRZNy9gMB9K6IwYuX14c++gz5KGV27U8PVXA9glDLE3P91B4Nz
         k01dz1a68FfUkvRanDBZcyNjnnqUmt4UAHwcJUOQSQUSd41qtgH22vvFIPjdiFqDXaPv
         tMHa/fluIymG+iiM4BN6/t+vCtA+8umTaW2I5kZEVCWd+2SxQXuR4wKGR8GzlD58fQdQ
         Ns/tA/vWfcds71jQksaH3T+Dpekhhws/AN/7+fI+NWihE9GPwRcbfk1cJ4+Pl146yN08
         DiJw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=yV1u9arsLimYsj93gOcu6wLUZ32KVKqvVtVvOJge1SA=;
        b=lZ18TmcN/e1x4tOkslwv9hq6jvGVHX1U2qDcZuJ3KzOn52PJtPNBixM9jULqyJ5QJf
         BOoGsV5FmEQugipohXp3050DvB3q/zXIgnw0bEv095k0+JmYjw0tG/FLcscV013aWGZa
         viTOdZ8CBateYkSHZOtrGT5ghtyml53hS6Rdy8dMqZLa0DDKJ0i+pFRA6mH5qumQC6d5
         yWqQ94iQrT9G66EMwCYCUv5IIdZHLMvaV2VxapLFZKEm7xW6ISrms48cEkXW/eJprAiJ
         gaLIrdktLKk7Mlbb5oRilm2e1r2icvWReKPpnZtSpVwgbWc5iVejMZpLeFBKss598Mvf
         ifrQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530RJz+dJQ9fduiDff7jxQD7EXnP7wwxjxHS9LdkvqKVOcTjOoqE
	e56aNY/SnFx32y4tDLmT6mw=
X-Google-Smtp-Source: ABdhPJwP2oKPQE1NGAcRHG0hrOCuKJqtfIghu5Ht0zUonjS8bff8LqOJMrdXFWSZAWYeADSV07gNEw==
X-Received: by 2002:a63:4808:: with SMTP id v8mr23838198pga.381.1614084598599;
        Tue, 23 Feb 2021 04:49:58 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:903:2311:: with SMTP id d17ls10069852plh.6.gmail; Tue,
 23 Feb 2021 04:49:58 -0800 (PST)
X-Received: by 2002:a17:902:228:b029:e3:e895:7d7f with SMTP id 37-20020a1709020228b02900e3e8957d7fmr12911774plc.57.1614084598026;
        Tue, 23 Feb 2021 04:49:58 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1614084598; cv=none;
        d=google.com; s=arc-20160816;
        b=KcgESH+raOeR1Io3K4d+EN8pCe0IPLRxysbsg6FFm/9E/06BRhLKLVwOEnmDXx0C3M
         dfFHAsylbSzJS5JhifMX8Oq6hPtlDNi2zI1q6paCCrNookbLj+Ad9e6Qe5kB2mcNysjv
         oKtISwkb3cRA9yq4xyfiBUygcgBLzI1lTB5y55AwBzWyUj75KEQPw/eXX1SSFQ6KXIT+
         H3mJKUOHAponPDkUR652+rkx9k+fw/HWJUcoI8zy1ZUNLHM46XispxuENDUyVUTCi1tJ
         gRGhqa1VlgC3heMFg8ReEU4rX1jh9euesmrACQFJQpxc7omfiU+ga3n9aBTSPpEUmhAY
         D7hg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=EffLcHzEI3sgFri9iUU2fxbo+cmR2oDgq3oKRnWTsI8=;
        b=VoBFIgmIWYZz00+c3cCcWgrtcv0bxPD9FMn+FhsBRhDqeybECL9cEyWxELZpyb/Utb
         ky1/mPwVoqCGL/OQdx1AmKIwFAPBD2jb/WEYbCONMjP/NnAmYIGRycau2H0JUaaeFS2x
         nK/Hc71kzlMPQPfE9/a8K5K8Bb4/0xJCHbTVpoU+e8ZZ4BZ5JZT58Ju9R8wHBMtRvMWw
         02WdlGNk0VtF79A4jxlSMUq5AkRhwXox5ch5H5YeG44OQ5Q+vgZJA5O92Fupnq6W2cr2
         +4o5UBZS3nfZ/1sO9MWfw5i6Prqsy98tZ40rZeibDRSQptJYZBuxcgyasOLikB1nvj8k
         eDrA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="cjBbeVP/";
       spf=pass (google.com: domain of will@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=will@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id g7si155392pju.3.2021.02.23.04.49.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 23 Feb 2021 04:49:58 -0800 (PST)
Received-SPF: pass (google.com: domain of will@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 69BA464E57;
	Tue, 23 Feb 2021 12:49:55 +0000 (UTC)
Date: Tue, 23 Feb 2021 12:49:52 +0000
From: Will Deacon <will@kernel.org>
To: Catalin Marinas <catalin.marinas@arm.com>
Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>,
	linux-arm-kernel@lists.infradead.org, linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	Andrew Morton <akpm@linux-foundation.org>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Andrey Konovalov <andreyknvl@google.com>,
	Lorenzo Pieralisi <lorenzo.pieralisi@arm.com>
Subject: Re: [PATCH v13 4/7] arm64: mte: Enable TCO in functions that can
 read beyond buffer limits
Message-ID: <20210223124951.GA10563@willie-the-truck>
References: <20210211153353.29094-1-vincenzo.frascino@arm.com>
 <20210211153353.29094-5-vincenzo.frascino@arm.com>
 <20210212172128.GE7718@arm.com>
 <c3d565da-c446-dea2-266e-ef35edabca9c@arm.com>
 <20210222175825.GE19604@arm.com>
 <6111633c-3bbd-edfa-86a0-be580a9ebcc8@arm.com>
 <20210223120530.GA20769@arm.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20210223120530.GA20769@arm.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: will@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b="cjBbeVP/";       spf=pass
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

On Tue, Feb 23, 2021 at 12:05:32PM +0000, Catalin Marinas wrote:
> On Tue, Feb 23, 2021 at 10:56:46AM +0000, Vincenzo Frascino wrote:
> > On 2/22/21 5:58 PM, Catalin Marinas wrote:
> > > We'll still have an issue with dynamically switching the async/sync mode
> > > at run-time. Luckily kasan doesn't do this now. The problem is that
> > > until the last CPU have been switched from async to sync, we can't
> > > toggle the static label. When switching from sync to async, we need
> > > to do it on the first CPU being switched.
> > 
> > I totally agree on this point. In the case of runtime switching we might need
> > the rethink completely the strategy and depends a lot on what we want to allow
> > and what not. For the kernel I imagine we will need to expose something in sysfs
> > that affects all the cores and then maybe stop_machine() to propagate it to all
> > the cores. Do you think having some of the cores running in sync mode and some
> > in async is a viable solution?
> 
> stop_machine() is an option indeed. I think it's still possible to run
> some cores in async while others in sync but the static key here would
> only be toggled when no async CPUs are left.

Just as a general point, but if we expose stop_machine() via sysfs we
probably want to limit that to privileged users so you can't DoS the system
by spamming into the file.

Will

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210223124951.GA10563%40willie-the-truck.
