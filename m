Return-Path: <kasan-dev+bncBDVIXXP464BBBTWE3WRQMGQECPQIJPQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x240.google.com (mail-lj1-x240.google.com [IPv6:2a00:1450:4864:20::240])
	by mail.lfdr.de (Postfix) with ESMTPS id B021771859D
	for <lists+kasan-dev@lfdr.de>; Wed, 31 May 2023 17:05:51 +0200 (CEST)
Received: by mail-lj1-x240.google.com with SMTP id 38308e7fff4ca-2af2cff231csf30088461fa.2
        for <lists+kasan-dev@lfdr.de>; Wed, 31 May 2023 08:05:51 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1685545551; cv=pass;
        d=google.com; s=arc-20160816;
        b=oEprOcpxt9uXvyIs5Dm2dABHcheMFKp5egpEItuWCncOr+O+STIFnH+rAZnRQHHBia
         GC7D1WgsCWtZXHfU36abdzHcWLIKbAeazJyKuRPlPLs92yxPOKsYXObtRjfD1JrxBIWl
         Xf3ZxkeY4xRBHTLji2qwB0GOBXP5p2Qq6xCmT0aohi+C+NujnBDWCgR+4RlgGQ7JJPS9
         2+PuS7T2sYI7z5q+OFsr7XG0CwAtgmiyVyV9/neHFy5NlZ+svJQ6lefTK2BiLbq5f2FC
         o2y4/euQA5KGQGg49Zm3b47hJIMgy2+U3tQmo0AS+MXUSLt3xyKZPoX/ZVj55eumOjiK
         pakQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=ISD1QzZ2FBPw7SMOHcNu39LCFKq9e2rNq2InBz78y5g=;
        b=eskjcwZX3Qu6eM5RDKvA1fSiaoXlzjNeAsalw5ZoP9hm2bUvfpTHiKCgDKHNETWfkG
         xZPdq8DBFBilsd3ekKntrjOIukRleg/ZN63DxqZk3ocdTAXd32hcI0fn9bUHxkN43EBJ
         cwnqW3lQLIMGtkIIJWFR4lfxssd9qAa/QA5bhD9EOMxCZtQ+hAcaXOCJGh7qj76cT6we
         XR+jFZLNhqGGdLibCHQXi7p7/Uqu/rz3uiP4Lcqx9HdF54omfnKLGTN3xyUgk+0U2b4D
         0Hi02XgIcCHr4uaLZjohycwg7xbYMomPKRshqMb2k9VYxHAp727KKAPhXSGbY7ylurkv
         ZgzQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.com header.s=susede1 header.b="K/IKmt2r";
       spf=pass (google.com: domain of mkoutny@suse.com designates 2001:67c:2178:6::1c as permitted sender) smtp.mailfrom=mkoutny@suse.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=suse.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1685545551; x=1688137551;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=ISD1QzZ2FBPw7SMOHcNu39LCFKq9e2rNq2InBz78y5g=;
        b=oe7tvt+SwnoJr4wnDafclsDxYgtcjeLVYka3bEsZZ+9VxBTnDYONsUwA8QNjIsAvGq
         TGq7CQKIG6BvyQol8PdMEvehnjuxURIOQc/y/BuBliyQZzQfOvEbV86NWxnnAe9SyV6M
         71vL5tejS+HloFOpSXIHq1Rsn8XAUDvgQUOhOMc0HFBQSWdRalKlZLNAGYlk2hrwEY3j
         RKf0G5a/i2GAw530sa0zzk1U2RyVKm4Ugh+WOGQFHr1a9NSQMG4WMNr4x1cEiVyAOJHQ
         Os3LRoHt6PBwgxKPZPBKS2CgxKzLf/lpcwcVGl1PwxtB4kaQzQfSndbQ+YFXsO/hEX5h
         fobw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1685545551; x=1688137551;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=ISD1QzZ2FBPw7SMOHcNu39LCFKq9e2rNq2InBz78y5g=;
        b=NQfGmL8S8CUPeg6OGp11w8wWVZ6YmokBEctVAz2qfFYBshMA2LV7ZYK2yvNCyyRnDJ
         X9RQ4MsPlTk7azqCfTw0fVmQpIvgleZ4cBl1NmHZE4Mrc/Vca8uKmvD9qaciJehjNOEf
         rfZPSeewh3Qf5SVeTCd+ucgDVKAm8AVXXnmjDZHqB/Wv3mC+fChuH6RlAa6RVuGRYw93
         KOZMRtImuiRzvU8VbJ9kyuYNCHZ2H2DrhlLlnHFWCQkdgPZhIW80LIRMHwbXOxbBa6xC
         c9DFMVKn41Mkc4xYKyqTMQjRb18WP4sv3xQkcnVQHQxZVEhDK7Tl9zqO6YAcEa2O/arz
         CIFA==
X-Gm-Message-State: AC+VfDxfvt8+il2fRGxV22rJexPcri1o5S+YtpFFx4MBI2+SANLUEci8
	Gtnydy0mA/cSp9nXTjLd5Ro=
X-Google-Smtp-Source: ACHHUZ5JAJjmI8vy0aGLIt9bk7c9qaPUzrAXJgVQNgNMJhFOKMPLZmOi6909pFYfTIA5rVRm3UDr9w==
X-Received: by 2002:a2e:7a0b:0:b0:2ac:78d5:fd60 with SMTP id v11-20020a2e7a0b000000b002ac78d5fd60mr3208199ljc.9.1685545550474;
        Wed, 31 May 2023 08:05:50 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:a556:0:b0:2b0:2eee:3eb3 with SMTP id e22-20020a2ea556000000b002b02eee3eb3ls160939ljn.1.-pod-prod-03-eu;
 Wed, 31 May 2023 08:05:49 -0700 (PDT)
X-Received: by 2002:a2e:3e15:0:b0:2ad:93c4:417a with SMTP id l21-20020a2e3e15000000b002ad93c4417amr2644920lja.28.1685545548762;
        Wed, 31 May 2023 08:05:48 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1685545548; cv=none;
        d=google.com; s=arc-20160816;
        b=bkZM7UVArge4M9Zjt+UslzbA6FoFdRT7buucq/b8iooDR9GlEvOb3dTtslLzvtvGP8
         w0mqYqU93wNwcs52YnwsgLmSHRnNk/R7xenSfnOME14Bgg8HtVAL67tbimuUgtdB3OAT
         pGX1QzU7NUzB4bS3SGjawe5f5MUudWCWOEYGDIC4Qq1Bf9gYi5mxsXJ7ZeJzKjIxbO6W
         NUQ3B3YVZ2IWj1nU9J2KVtm9VWgrhD4mS3I/9oF5NHRGVOwePxXZyqv3/Df575D8TS2e
         qmG8Aqy660H15T8dUAtXuYHOHrFDd+EsNh5LBxLDVpUCqy+tihPW/ZYcT5FIf4a6wdeN
         jW0Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=UVltXgwItraV4FGz/uii8cqWK65XtkelAgQIafLv8C4=;
        b=C9p+F9foyv3eZTNCQj+UoJAAvy0ePKV+3H0mFib+aAA/8NPm/MnZU5x46X+xDIgFQj
         FRWtqssQfej/ON6ibon2uRyW9AjLbNUcLcNCVK+VjxL7/zT5O16iLz2qo+vgmn2Kj9cU
         G5ku8LpQu8nLAIBBeEjsuGctrdmwC8GYGOklJ2d2n3vdFJiCWY5HhycYCcrwMx4vYHEo
         WIQ33Dhb6R/6oH40F2sctHvjPdKkPh44pZTFwdcXdfc6IKuCWh5PfgZlrMHpqwV2MQPG
         K8kfupfn4yVdKtO5A7JnYkrPzOpKHioaYDqRi+9Btz5FQ7RgaeFGrb+t4lPS8x7ojMRR
         nOdQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.com header.s=susede1 header.b="K/IKmt2r";
       spf=pass (google.com: domain of mkoutny@suse.com designates 2001:67c:2178:6::1c as permitted sender) smtp.mailfrom=mkoutny@suse.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=suse.com
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [2001:67c:2178:6::1c])
        by gmr-mx.google.com with ESMTPS id o6-20020a05651c050600b002a77f4969bdsi1398329ljp.5.2023.05.31.08.05.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 31 May 2023 08:05:48 -0700 (PDT)
Received-SPF: pass (google.com: domain of mkoutny@suse.com designates 2001:67c:2178:6::1c as permitted sender) client-ip=2001:67c:2178:6::1c;
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id 134E321904;
	Wed, 31 May 2023 15:05:48 +0000 (UTC)
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by imap2.suse-dmz.suse.de (Postfix) with ESMTPS id DB43613488;
	Wed, 31 May 2023 15:05:47 +0000 (UTC)
Received: from dovecot-director2.suse.de ([192.168.254.65])
	by imap2.suse-dmz.suse.de with ESMTPSA
	id MHHQNEtid2TMPQAAMHmgww
	(envelope-from <mkoutny@suse.com>); Wed, 31 May 2023 15:05:47 +0000
Date: Wed, 31 May 2023 17:05:46 +0200
From: =?UTF-8?B?J01pY2hhbCBLb3V0bsO9JyB2aWEga2FzYW4tZGV2?= <kasan-dev@googlegroups.com>
To: Andrey Ryabinin <ryabinin.a.a@gmail.com>
Cc: Dave Hansen <dave.hansen@intel.com>, 
	the arch/x86 maintainers <x86@kernel.org>, LKML <linux-kernel@vger.kernel.org>, 
	Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	kasan-dev@googlegroups.com, Kees Cook <keescook@chromium.org>, 
	Thomas Garnier <thgarnie@google.com>
Subject: Re: KASLR vs. KASAN on x86
Message-ID: <ldxj7p22ze4ccoe4bmojhlabflw34t6jwyh24fklvessdyyial@w3fw6wwo7icp>
References: <299fbb80-e3ab-3b7c-3491-e85cac107930@intel.com>
 <CAPAsAGyG2_sUfb7aPSPuMatMraDbPCFKxhv2kSDkrV1XxQ8_bw@mail.gmail.com>
 <20230313094127.3cqsnmngbdegbe6o@blackpad>
 <CAPAsAGzYSi_mCy64rFH=o+m8eT-A9ffttsFO9Wx94=nsj+Q8Jg@mail.gmail.com>
MIME-Version: 1.0
Content-Type: multipart/signed; micalg=pgp-sha512;
	protocol="application/pgp-signature"; boundary="4ycvjxkeevdduqu4"
Content-Disposition: inline
In-Reply-To: <CAPAsAGzYSi_mCy64rFH=o+m8eT-A9ffttsFO9Wx94=nsj+Q8Jg@mail.gmail.com>
X-Original-Sender: mkoutny@suse.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.com header.s=susede1 header.b="K/IKmt2r";       spf=pass
 (google.com: domain of mkoutny@suse.com designates 2001:67c:2178:6::1c as
 permitted sender) smtp.mailfrom=mkoutny@suse.com;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=suse.com
X-Original-From: Michal =?utf-8?Q?Koutn=C3=BD?= <mkoutny@suse.com>
Reply-To: Michal =?utf-8?Q?Koutn=C3=BD?= <mkoutny@suse.com>
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


--4ycvjxkeevdduqu4
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline

On Mon, Mar 13, 2023 at 02:40:33PM +0100, Andrey Ryabinin <ryabinin.a.a@gmail.com> wrote:
> Yes, with the vaddr_end = KASAN_SHADOW_START  it should work,
>  kaslr_memory_enabled() can be removed in favor of just the kaslr_enabled()

Thanks. FWIW, I've found the cautionary comment at vaddr_end from the
commit 1dddd2512511 ("x86/kaslr: Fix the vaddr_end mess"), so I'm not
removing kaslr_enabled_enabled() now.

Michal

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ldxj7p22ze4ccoe4bmojhlabflw34t6jwyh24fklvessdyyial%40w3fw6wwo7icp.

--4ycvjxkeevdduqu4
Content-Type: application/pgp-signature; name="signature.asc"

-----BEGIN PGP SIGNATURE-----

iHUEABYKAB0WIQTrXXag4J0QvXXBmkMkDQmsBEOquQUCZHdiSAAKCRAkDQmsBEOq
uVkZAQC9Jm2mWgPAUPqqgO0NNrvFotzE3yEA2+E+A790k74cFAEA3oDkSBjN98F6
5BBgyox4635j0nByjmoVA5lwtCBxhwE=
=FH1X
-----END PGP SIGNATURE-----

--4ycvjxkeevdduqu4--
