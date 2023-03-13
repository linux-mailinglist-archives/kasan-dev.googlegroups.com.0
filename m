Return-Path: <kasan-dev+bncBDVIXXP464BBBS67XOQAMGQEVIYBXII@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x137.google.com (mail-lf1-x137.google.com [IPv6:2a00:1450:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id 1A0B56B72D1
	for <lists+kasan-dev@lfdr.de>; Mon, 13 Mar 2023 10:41:33 +0100 (CET)
Received: by mail-lf1-x137.google.com with SMTP id p8-20020a056512234800b004dda0f69233sf3378306lfu.13
        for <lists+kasan-dev@lfdr.de>; Mon, 13 Mar 2023 02:41:33 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1678700492; cv=pass;
        d=google.com; s=arc-20160816;
        b=sl1WFK4doze16cLs877+BnSiu998zjgbjYf82Wo2EQZSrncxUffH/QZuF27EkeGlFg
         HodX8A+DTt6YXQMIOY0sq938BbGtSyWMJvb758VEVWi39xXijpzdkim+9LYAV6sSpdC7
         1ifaGOsYEX63Vj0qLesKdfWBU1BmBNKtU6rO3CR8sqrV0rWVrYr4i+ENOzLdi6tggbsl
         n6KIIAw6GW0httqcLuoYWM/oZ7JabLjB07LRzxdJark7wLtofDRoxkBJ8QZHJHGKAobU
         kThPCigC71YkPpCM2a+ufnyOd0yPorbnSXOMT6Bk+wK4h357QvhEEXSUqYLuKHvO1JOz
         z3Qw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=ElIkU8jYGHSMOT1a/ABWxvD6CjwKeVz6cyVQYgfF11k=;
        b=bXe8rcx7GnjA7rD4bupYom+ikz3okEs2cFoQIc7RXgC30nwJermeqaWZeB1yVtx4HF
         KyRIUeHysdOEELpRaUVYW9OpJkEvW0QrxlTNIDYkhBhm5MOzdt9+FeiMiDmdJrDK7Jxr
         Zi5KqEzBm+Ig87UQDjBoG9dtXosXvVoaUmJ+PWaCJQiK2W8EgRAulWSMPuh9v9qj4uch
         9u5EAQmv871M4Ry+zeC14J+7cp6DbL2exmrGVPV+JXVUoExE7EjQySmJ1oxY9T0UTyJn
         kZx329ApH8nMxKRgo5EbvzTVkSxVT7lqWq0nX/vaN/rSZQj8nZYGs62LV0OhgRQIqK3R
         dhOw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.com header.s=susede1 header.b=bvJaOYw9;
       spf=pass (google.com: domain of mkoutny@suse.com designates 195.135.220.29 as permitted sender) smtp.mailfrom=mkoutny@suse.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=suse.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112; t=1678700492;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=ElIkU8jYGHSMOT1a/ABWxvD6CjwKeVz6cyVQYgfF11k=;
        b=TG4cGvqd5Odx6gf9ffkOcHUiWMmgm/RIer2FK/v3/F/d4SxYcQhsTd9qRnWH9iT/WE
         YLaisUOb3jciF1DNzcMEd5I+O0tBX76LXrAW2WRqN/noVeVEWFlFiQoir+I8mk9hGQWo
         D9eIB5Zr+xRWpjEN+wm620z3WjrBZyVnYxDTdAcQHrVTSOc69rH+OB4+DbfUvpaonN0m
         YQr6MmcQHSj1YQT/EoSdNohz3I4YCCp9ZFM0D42vry+F2skyP+0UOpBmqptfBBRgccwg
         Mo8TEtrB76Quo3k7/xqQjISMlgnSq/a1HW3obP0cK8aNGCu2L6/yXZNOSRS7WYd8JmGu
         1cDg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1678700492;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=ElIkU8jYGHSMOT1a/ABWxvD6CjwKeVz6cyVQYgfF11k=;
        b=oiTTeWR1C1R97wmCIuZSR1NHqKANoM+TDIjAFeGpjVMzWraaURnJopk3YZlgE746Li
         +dg8q/Y9zjqcd1MUwuIHgqi55ONjON8BUZBUdNqFccK8rJWO+hIfmlzwZqnto/w07AC1
         zsFmYeLSJYl2lgSlzlw15y0ktxCw49lzmACoR2eQHuW0mP3L/mfT0r4p2kQCHjPsate2
         IZy/nGXiyTFGB1RCGPGFdo+2TV3fJ8e2me57amM2z5NS4M2AkQy2BXa84EggDG284iGn
         5X0GRU/FQ/tiNdxHA4WS8drlXe0g0o1OZ3YxUbZnOwc4mKmzPAg7gObCl623A4yZ+Ql5
         oRSw==
X-Gm-Message-State: AO0yUKXHicpTKXlnzODa/tcLjx+SmQgsBfrYHirK2HB+7qV57nu2hgQR
	xsSK9Py5Ydn0I2j5LECHfv4=
X-Google-Smtp-Source: AK7set+XGRVuMO10fxbiUQcjBmDtVumMca/9GgaWC49B0iFSOQPTaH4TOBGv/3cqCwXXW2b09phsnQ==
X-Received: by 2002:a2e:595:0:b0:298:6d17:eaa7 with SMTP id 143-20020a2e0595000000b002986d17eaa7mr5700281ljf.2.1678700492060;
        Mon, 13 Mar 2023 02:41:32 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:bc0e:0:b0:295:a3ad:f338 with SMTP id b14-20020a2ebc0e000000b00295a3adf338ls1857685ljf.4.-pod-prod-gmail;
 Mon, 13 Mar 2023 02:41:30 -0700 (PDT)
X-Received: by 2002:a2e:989a:0:b0:293:51ba:24b3 with SMTP id b26-20020a2e989a000000b0029351ba24b3mr10534677ljj.41.1678700490319;
        Mon, 13 Mar 2023 02:41:30 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1678700490; cv=none;
        d=google.com; s=arc-20160816;
        b=mprLbZf8ts0AuThNxDARz0ZSlMdPfo8Odt0RquFE7AdMsKUQI0Gbe9L3iofcIvs9iw
         PbEDoJ28hDL9hnNY/FNz3u2Xuv+nTN4jcELJaosKt9/842B3xRiKUPiFWURC1qgllwlT
         pNzMQaPhnjKEBjmfeOxabnc8lmf25wdfwJ7y9SpMdxyT6zlNwzJpynlpChzzU0NiIdi+
         ots3IIbPDKr0Gdxm4G7YlWINghWY2u9lVAZ0UO8hyW/mvE78YRdFysae4aG7E+Gl8Ru5
         YXX64qjWYAVVAacl1hNh+XesgYDGQP38W507KMzMJKOcNRFDdIp7ecmNIy7+VdUHbhL5
         GlLQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=taPYVRLjiV8XDl67HXIGpVQRzMdlFoR13+oyuxu7LjQ=;
        b=DFh7tTysjpj4rGb7zneZ9WS+w4jta9RCUElIBK7qb2dQmLwPvMfwRKXyLucUD209g6
         GqzYGCmpO6++lA/MNJY6Lakeoq+Q7XzUaVQkLwCFrRXHDWvmWvtI7M3dxhsVkrHHlPZ6
         h6zDGyECxmni1IWLSNhTogEJjE9yhwuo0ENkFZBEAY6Vqi4o/PVHW4w1k3VMdM995Uz5
         YZ15ddTd0oK7fhRKk3Y3EPKcZjFnKeo/rnA0Npx8hwZBiV6HYk9h+F3kuxDNz7+5SU86
         i3Og4JDlnkfn3nypYWB4/I+3Kxpooq7zuNQm2A55KVIqL+eARr5498KmiNBq5HRxDC7J
         +w5g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.com header.s=susede1 header.b=bvJaOYw9;
       spf=pass (google.com: domain of mkoutny@suse.com designates 195.135.220.29 as permitted sender) smtp.mailfrom=mkoutny@suse.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=suse.com
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [195.135.220.29])
        by gmr-mx.google.com with ESMTPS id bi6-20020a0565120e8600b004dc4feeb7c2si369818lfb.5.2023.03.13.02.41.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 13 Mar 2023 02:41:30 -0700 (PDT)
Received-SPF: pass (google.com: domain of mkoutny@suse.com designates 195.135.220.29 as permitted sender) client-ip=195.135.220.29;
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id 6FFCA1FD86;
	Mon, 13 Mar 2023 09:41:29 +0000 (UTC)
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by imap2.suse-dmz.suse.de (Postfix) with ESMTPS id 3548A13517;
	Mon, 13 Mar 2023 09:41:29 +0000 (UTC)
Received: from dovecot-director2.suse.de ([192.168.254.65])
	by imap2.suse-dmz.suse.de with ESMTPSA
	id /pqoC8nvDmTFJQAAMHmgww
	(envelope-from <mkoutny@suse.com>); Mon, 13 Mar 2023 09:41:29 +0000
Date: Mon, 13 Mar 2023 10:41:27 +0100
From: =?UTF-8?B?J01pY2hhbCBLb3V0bsO9JyB2aWEga2FzYW4tZGV2?= <kasan-dev@googlegroups.com>
To: Andrey Ryabinin <ryabinin.a.a@gmail.com>
Cc: Dave Hansen <dave.hansen@intel.com>,
	the arch/x86 maintainers <x86@kernel.org>,
	LKML <linux-kernel@vger.kernel.org>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	kasan-dev@googlegroups.com, Kees Cook <keescook@chromium.org>,
	Thomas Garnier <thgarnie@google.com>
Subject: Re: KASLR vs. KASAN on x86
Message-ID: <20230313094127.3cqsnmngbdegbe6o@blackpad>
References: <299fbb80-e3ab-3b7c-3491-e85cac107930@intel.com>
 <CAPAsAGyG2_sUfb7aPSPuMatMraDbPCFKxhv2kSDkrV1XxQ8_bw@mail.gmail.com>
MIME-Version: 1.0
Content-Type: multipart/signed; micalg=pgp-sha512;
	protocol="application/pgp-signature"; boundary="wptupshxqazattjd"
Content-Disposition: inline
In-Reply-To: <CAPAsAGyG2_sUfb7aPSPuMatMraDbPCFKxhv2kSDkrV1XxQ8_bw@mail.gmail.com>
X-Original-Sender: mkoutny@suse.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.com header.s=susede1 header.b=bvJaOYw9;       spf=pass
 (google.com: domain of mkoutny@suse.com designates 195.135.220.29 as
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


--wptupshxqazattjd
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline

On Wed, Mar 08, 2023 at 06:24:05PM +0100, Andrey Ryabinin <ryabinin.a.a@gmail.com> wrote:
> So the vmemmap_base and probably some part of vmalloc could easily end
> up in KASAN shadow.

Would it help to (conditionally) reduce vaddr_end to the beginning of
KASAN shadow memory?
(I'm not that familiar with KASAN, so IOW, would KASAN handle
randomized: linear mapping (__PAGE_OFFSET), vmalloc (VMALLOC_START) and
vmemmap (VMEMMAP_START) in that smaller range.)

Thanks,
Michal

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230313094127.3cqsnmngbdegbe6o%40blackpad.

--wptupshxqazattjd
Content-Type: application/pgp-signature; name="signature.asc"

-----BEGIN PGP SIGNATURE-----

iHUEABYKAB0WIQTrXXag4J0QvXXBmkMkDQmsBEOquQUCZA7vxQAKCRAkDQmsBEOq
uW2lAQCeUCKhA8GYQAuXZu5XL/lsP5d2pNCA006hwmRC9KpGBAEAqFyQ693lk1ii
t3tc9mNSO+lVUFd9KFGdT0D8NP7zDgg=
=nAh2
-----END PGP SIGNATURE-----

--wptupshxqazattjd--
