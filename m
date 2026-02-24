Return-Path: <kasan-dev+bncBC7OBJGL2MHBBMOT7DGAMGQEI4VZ6JA@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id MHbZArQpnmn5TgQAu9opvQ
	(envelope-from <kasan-dev+bncBC7OBJGL2MHBBMOT7DGAMGQEI4VZ6JA@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Tue, 24 Feb 2026 23:44:04 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43f.google.com (mail-pf1-x43f.google.com [IPv6:2607:f8b0:4864:20::43f])
	by mail.lfdr.de (Postfix) with ESMTPS id 847A518D98C
	for <lists+kasan-dev@lfdr.de>; Tue, 24 Feb 2026 23:44:03 +0100 (CET)
Received: by mail-pf1-x43f.google.com with SMTP id d2e1a72fcca58-824af3c6c0csf2594183b3a.3
        for <lists+kasan-dev@lfdr.de>; Tue, 24 Feb 2026 14:44:03 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1771973041; cv=pass;
        d=google.com; s=arc-20240605;
        b=MS7UOthbEZE3L7RgdHfcxflAkgFDU+qmOItCjwmPuMdP6w+GCmSXuentN/i139fWso
         LKSItI4cdPJNtqdiu8Zuex5LO3R917iNhLvZ/l4mMF+qynICQeFdYN1DKJw2nUxcd+bD
         ePetkEFQFwt257v0aL7cQdoreIKJJOPNAd8nyI92mCCJoii7MgI1HL62kxbfLOWPvirk
         hHJesT1rjs1Ybibcu/CFdG7+s40eZAHtXC5+oBdqpGhHkMRd5i+tUkMoaNjLanI1UG0F
         E2Qpg8pnCOeevK+VV3MXnd3kGqtUEx5Bw0kuCA0eCTsiSjKveREVlD7dxV5/GIYUfeWY
         rH9g==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=mL0VOkBH2/YvMAchG4In0cda8JsUptgDb2N/ku9BJG0=;
        fh=D82ghbRAgT03ksHpY9dS7iS448i9YgYlUtlEfv+GibA=;
        b=cAUGYiAKqqephPkk13xHGvQ1vCMBfIVrR87YcT0FKNMJ3LWYJoRvoVKmak8MThhwAA
         w06xMw7DIswJL2ssSf05ROTtrwQfdKkGOyI8kCEbz0glSp+G2sKQ4+vTx3P3PHTb9WOD
         joUkUgOUj6KcUwdgwwBWgnmPT8EZpXyijnz/4AVU051qeBJV4zju062/EQJkPVtzD0LH
         C/AUhRMzoLA46t7Ih8+RvlYkqhD7qwTfSNhUsb3s5r+DnHqwmOVMMqAGFxiiidUDODuV
         4fXyvOGdf3AjgMjVv5jJfAHWZD+Xjs4Zu3QkVPrEcpoKFGYWGSCFDsZisTGfxpToXnsA
         nlyw==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=nB9PL8Pd;
       arc=pass (i=1);
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1232 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1771973041; x=1772577841; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=mL0VOkBH2/YvMAchG4In0cda8JsUptgDb2N/ku9BJG0=;
        b=Vq1Md2zglpcFUNmviMdCB7AhBhD6Ft6UXpJLow5HhJud9CqfBAvt+jGsod0Bc/mB6C
         5/60N+AMo7BkdqpztTdopcIK3waGUJn+MFHNUqcn3gDKf7vs5Nz+VOPsOtKjUCnXF4m6
         ntQr6wItQkUVsKLn21JKpXGIniSkum/3l5rCO+irV2xVRT0hUPKkC5UAxhje3W/kbMJU
         QWJEwhq0AEgDcPDnRxTaWb5RYiJQgWz+DO4qcnnRb2s6t5WAH/KAxW4Tw5fg5QddcQ7C
         R4tKjBPlCIZKN28iEh8+4mr+eP8gVicymy/dD/yxwGWToIMos0Hk04fZDoJAXZEDHyYl
         VUyA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1771973041; x=1772577841;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:x-gm-gg
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=mL0VOkBH2/YvMAchG4In0cda8JsUptgDb2N/ku9BJG0=;
        b=N9MLFfrWhvso1XxhfBfLNQB67NlphkH7AkZE+AR0tAD/5vSQ4l/edMOpF7bWxfCDU/
         alzz0LWQnaqqVBP6B8pWEEWZOD0BhukjhGVUzitURAm1zZcUe9W+zTBdfalIINDWiDSG
         U7f98mnYzK6plzTfbHiGCf0sKzcSQ9KAm0BMejOmanh/LyQ/CRVn9oHKp8YMB/tvXcMU
         tkHeT3cCaSPosXvI2c/9H7I9w8wceFN/KL8si+L2DIX56fdYiWyPPgxt4DGLp4uzBTuI
         jYWZ7YRIRjcOx27sLkz/PEELiBgFWJBD0e6e4rs9MjTDkabrqBGUeyUS43fR7t+NwMc8
         pjJA==
X-Forwarded-Encrypted: i=3; AJvYcCUEli2PbaUpI6AzgmgMSsqeLHIUvzBEwYisqs7SClojRu0EvXXqn1OYpcFXMkKwWuQ0QY8f2Q==@lfdr.de
X-Gm-Message-State: AOJu0Yz3qn7mV7gIVo3pLZpbmdikfnax/BrmL8axiDb3Uknhq0lTn9CR
	9xZO+SuJ0XcD4gMnR7i0U31jtmCj+lADnU2GBOdXerbGROF8A7uACtmj
X-Received: by 2002:a05:6a00:4b47:b0:824:a6d8:3fc0 with SMTP id d2e1a72fcca58-826da8f4d59mr11519320b3a.25.1771973041466;
        Tue, 24 Feb 2026 14:44:01 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+Htt6b72VRJ3ujL1JLPyJij72+4n9Y2SJmKxsYmPwojIg=="
Received: by 2002:a05:6a00:1716:b0:822:747d:3af9 with SMTP id
 d2e1a72fcca58-824b1fbd582ls9585401b3a.2.-pod-prod-09-us; Tue, 24 Feb 2026
 14:44:00 -0800 (PST)
X-Forwarded-Encrypted: i=3; AJvYcCUVyAWrju+ZcYiNT9QYQc1r1wS+ylHZ9SG/1gwP432YKZApnjeGAUaONAfnHPhtWy42xPKJLktckEg=@googlegroups.com
X-Received: by 2002:a05:6a00:148b:b0:824:cc05:ce88 with SMTP id d2e1a72fcca58-826da9f164amr12989915b3a.30.1771973039983;
        Tue, 24 Feb 2026 14:43:59 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1771973039; cv=pass;
        d=google.com; s=arc-20240605;
        b=Fp1fQjeNYXvZEHNZtYAQTnPpNG+t+GNKrSEJLptc40XowdDiazakGi2n0fz3QFtqkq
         U26wGMaKJlZW1B2V0Fq0cwUGnOtG7dAdf6KbTVnUjzwshZ4HPb0iH6AoWWbhpquW9uzp
         QzO5AvOb3ELvmxVkvRaVMUQslXQtOEYdAsmme6gx/BXMp2kq7pv1pqpxB6RlYjJwn5/Q
         cJyDqs+pjjr89dByWnWIOvP9km/CtUywyheZtUuGXwmSqPSS5c/8L2lhZh9p5UWkixC5
         OJ0c0CrW52yZO43pq0S1azb5FITmx8PUnF/ZJgtyhALyd4QbfXLDo01pCdNJXMo79NvO
         Nc+g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=0vyzXs6Nuf3YPypneYs9PIt3O29SiUmlFmPJ2dtgRHo=;
        fh=sZqR0iGPm8KjBWR+P2eiMvMaKM9hH+JZb0CEfPObBo4=;
        b=f/Mz5u1OZzruLctklE1rqwUWJg0YDgSaag//JnAdiwLuNgEo8eR22Q5XVbx4muWTii
         B0NadAWzmMUmAuxxIkBmEBolFxQas2Aqkif0V6FFy0/wQygsKIYK3IK6Adzcs4+Ila/u
         /CUvYRKAikhpxvxyx4yQxiny8mod1fWkF6t4VJaJvS9L5F4KDzSsUuWfVtjt/TqZQNMf
         gSxN6HwC5eeW5Ha8rT9F1tDOEa8mfDkm1PE6jLJkhkymzu3HnwJ7oO0968CMNq5X5T4N
         +4gNnJNHLznoVLM48uOK8iN2cAsuSgIATL3fz6QtYk44DWd3+RiU+SPnkLWURcjjoFT4
         KzOQ==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=nB9PL8Pd;
       arc=pass (i=1);
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1232 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-dl1-x1232.google.com (mail-dl1-x1232.google.com. [2607:f8b0:4864:20::1232])
        by gmr-mx.google.com with ESMTPS id d2e1a72fcca58-826dd8e12b4si374493b3a.8.2026.02.24.14.43.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 24 Feb 2026 14:43:59 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1232 as permitted sender) client-ip=2607:f8b0:4864:20::1232;
Received: by mail-dl1-x1232.google.com with SMTP id a92af1059eb24-124a635476fso5781292c88.0
        for <kasan-dev@googlegroups.com>; Tue, 24 Feb 2026 14:43:59 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1771973039; cv=none;
        d=google.com; s=arc-20240605;
        b=OlKEir6OrGuwRYXIrnjBRRIFwjZF+pngD7iVpAfldNyHqaJ7IWr29wKzH/VKnzmZn7
         ZuwVc3yxz0b0xxnO6vLzrvbWmPDMJbIeBUlM2qjH7E0QU1DH2j0cGeTBMzrlrNS7lO21
         v+MOrCB/gtrO5CZEiGJvGSOgl5DJt+FMx+dDLhn1raIKXsa4kXXG538UpR1834H1HSNT
         j8emRmHVDNdSGVnJ14WvY+T6CoOVcQ4WcWeoth9rB7dLRR4Cl10m6fwithcGjmURe5gY
         mnGAeuCVmlse0vrIrI57ONql6DryLk/+qLnPp5A9F2Gl3rKRIIONSlJjiTSmdXcxvrCa
         e6Qg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=0vyzXs6Nuf3YPypneYs9PIt3O29SiUmlFmPJ2dtgRHo=;
        fh=sZqR0iGPm8KjBWR+P2eiMvMaKM9hH+JZb0CEfPObBo4=;
        b=E1EOxH8dMbWP+AR+ZdY/fAFkb+aOBVFs/Nt+AGPTK9XrFz5NlCP78T/Ha57qtdlWG9
         0Vdwc4iMKSKLgvX9RYatO2Yl9KxMjNFMTK92qsLULk4PPs+oVvdDc5RGsYaPBwC88iMX
         C3FCseA4Zm4Y7EEzs1KGX0rs/pH1eYEaEQoAabM6oVsYh9+llAkumoWCUKDOGou4Q8/m
         UeVkAtfYnkYKC7/1qAvmLG0alhEy5S5VViOXritpZkMGKxowCpr6MgRUpQNtinmaC65t
         KvEVUx5qrx3XbCnZUY4yuUI5E97UMwZ15GJSs+gjFMu1DzCaJB1W51VbOq6R80r28IxD
         EoMw==;
        dara=google.com
ARC-Authentication-Results: i=1; mx.google.com; arc=none
X-Forwarded-Encrypted: i=1; AJvYcCUThx8fnWTEceMWANAuP6eq1YiBYdoIXnYVI6MrkzIL4jeBOZSSOc9KlMIBWumXKLz7zB7ra6xRCNw=@googlegroups.com
X-Gm-Gg: ATEYQzyvrvWdoCZ1GWpk9Bc3uNyLooIf0FfpUPRFW3MhR49RiUTxC92yh+jW2N0DaOw
	eCtkbt97mxiAtIAdhyM9WX67xHp01WHf50yXeXOy7YCSNeScaLVH5xfyViKDMLrBo/P4B5E89N7
	cesd+DfybM7amgePrxmsijUcwZ3YkQxx9vpwgtmipe719skE0prPfnTN2q7hKOlABqXg8DB2wcW
	uEXgpkKAVSIlTUajNWuVuXxBWSZ+w9+Q8Pe8mukNYPL2nmG77BQ3yJGKqRFl8MDHp5syOtPreOc
	rFXSQM5BBtl7maZx+Y2apR/zV6FyN5njX/zSAg==
X-Received: by 2002:a05:7022:128d:b0:11d:f44c:ad97 with SMTP id
 a92af1059eb24-1276ad11a13mr5314920c88.24.1771973039031; Tue, 24 Feb 2026
 14:43:59 -0800 (PST)
MIME-Version: 1.0
References: <20260223222226.work.188-kees@kernel.org> <CANpmjNOpXe7tCP7tyR04Hm+a8zdiBWWQdK=US-qTL31mm+Yzkw@mail.gmail.com>
 <202602241316.CFFF256ED6@keescook> <202602241440.1D885B8@keescook>
In-Reply-To: <202602241440.1D885B8@keescook>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 24 Feb 2026 23:43:22 +0100
X-Gm-Features: AaiRm530nNUyIcHEvt2U9h7SlrZ-STR58Elq_z7lf5SVlQwk7vDX4kQaD1idsQ0
Message-ID: <CANpmjNORUfQEVimGFwJtxsuae8VhimHEFWZUnqvtTZ6dC3_o5A@mail.gmail.com>
Subject: Re: [PATCH] kcsan: test: Adjust "expect" allocation type for kmalloc_obj
To: Kees Cook <kees@kernel.org>
Cc: Nathan Chancellor <nathan@kernel.org>, Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, linux-hardening@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=nB9PL8Pd;       arc=pass
 (i=1);       spf=pass (google.com: domain of elver@google.com designates
 2607:f8b0:4864:20::1232 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
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
X-Rspamd-Server: lfdr
X-Spamd-Result: default: False [-2.21 / 15.00];
	ARC_ALLOW(-1.00)[google.com:s=arc-20240605:i=3];
	DMARC_POLICY_ALLOW(-0.50)[googlegroups.com,none];
	MAILLIST(-0.20)[googlegroups];
	R_SPF_ALLOW(-0.20)[+ip6:2607:f8b0:4000::/36:c];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601];
	MIME_GOOD(-0.10)[text/plain];
	HAS_LIST_UNSUB(-0.01)[];
	REPLYTO_DOM_NEQ_FROM_DOM(0.00)[];
	RCVD_TLS_LAST(0.00)[];
	TAGGED_FROM(0.00)[bncBC7OBJGL2MHBBMOT7DGAMGQEI4VZ6JA];
	FROM_HAS_DN(0.00)[];
	MIME_TRACE(0.00)[0:+];
	RCVD_COUNT_THREE(0.00)[4];
	TO_DN_SOME(0.00)[];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	RCPT_COUNT_FIVE(0.00)[6];
	HAS_REPLYTO(0.00)[elver@google.com];
	FROM_EQ_ENVFROM(0.00)[];
	REPLYTO_DOM_NEQ_TO_DOM(0.00)[];
	NEURAL_HAM(-0.00)[-1.000];
	ASN(0.00)[asn:15169, ipnet:2607:f8b0::/32, country:US];
	TAGGED_RCPT(0.00)[kasan-dev];
	MISSING_XM_UA(0.00)[];
	DBL_BLOCKED_OPENRESOLVER(0.00)[googlegroups.com:email,googlegroups.com:dkim,mail.gmail.com:mid]
X-Rspamd-Queue-Id: 847A518D98C
X-Rspamd-Action: no action

On Tue, 24 Feb 2026 at 23:41, Kees Cook <kees@kernel.org> wrote:
>
> On Tue, Feb 24, 2026 at 01:48:51PM -0800, Kees Cook wrote:
> > On Tue, Feb 24, 2026 at 11:09:44AM +0100, Marco Elver wrote:
> > > On Mon, 23 Feb 2026 at 23:22, Kees Cook <kees@kernel.org> wrote:
> > > >
> > > > Instead of depending on the implicit case between a pointer to pointers
> > > > and pointer to arrays, use the assigned variable type for the allocation
> > > > type so they correctly match. Solves the following build error:
> > > >
> > > > ../kernel/kcsan/kcsan_test.c: In function '__report_matches':
> > > > ../kernel/kcsan/kcsan_test.c:171:16: error: assignment to 'char (*)[512]' from incompatible pointer type 'char (*)[3][512]'
> > > > [-Wincompatible-pointer-types]
> > > >   171 |         expect = kmalloc_obj(observed.lines);
> > > >       |                ^
> > > >
> > > > Tested with:
> > > >
> > > > $ ./tools/testing/kunit/kunit.py run \
> > > >         --kconfig_add CONFIG_DEBUG_KERNEL=y \
> > > >         --kconfig_add CONFIG_KCSAN=y \
> > > >         --kconfig_add CONFIG_KCSAN_KUNIT_TEST=y \
> > > >         --arch=x86_64 --qemu_args '-smp 2' kcsan
> > > >
> > > > Reported-by: Nathan Chancellor <nathan@kernel.org>
> > > > Fixes: 69050f8d6d07 ("treewide: Replace kmalloc with kmalloc_obj for non-scalar types")
> > > > Signed-off-by: Kees Cook <kees@kernel.org>
> > > > ---
> > > > Cc: Marco Elver <elver@google.com>
> > > > Cc: Dmitry Vyukov <dvyukov@google.com>
> > > > Cc: <kasan-dev@googlegroups.com>
> > > > ---
> > > >  kernel/kcsan/kcsan_test.c | 2 +-
> > > >  1 file changed, 1 insertion(+), 1 deletion(-)
> > > >
> > > > diff --git a/kernel/kcsan/kcsan_test.c b/kernel/kcsan/kcsan_test.c
> > > > index 79e655ea4ca1..056fa859ad9a 100644
> > > > --- a/kernel/kcsan/kcsan_test.c
> > > > +++ b/kernel/kcsan/kcsan_test.c
> > > > @@ -168,7 +168,7 @@ static bool __report_matches(const struct expect_report *r)
> > > >         if (!report_available())
> > > >                 return false;
> > > >
> > > > -       expect = kmalloc_obj(observed.lines);
> > > > +       expect = kmalloc_obj(*expect);
> > >
> > > This is wrong. Instead of allocating 3x512 bytes it's now only
> > > allocating 512 bytes, so we get OOB below with this change. 'expect'
> > > is a pointer to a 3-dimensional array of 512-char arrays (matching
> > > observed.lines).
> >
> > Why did running the kunit test not trip over this? :(
> >
> > Hmpf, getting arrays allocated without an explicit cast seems to be
> > impossible. How about this:
> >
> >
> > diff --git a/kernel/kcsan/kcsan_test.c b/kernel/kcsan/kcsan_test.c
> > index 056fa859ad9a..ae758150ccb9 100644
> > --- a/kernel/kcsan/kcsan_test.c
> > +++ b/kernel/kcsan/kcsan_test.c
> > @@ -168,7 +168,7 @@ static bool __report_matches(const struct expect_report *r)
> >       if (!report_available())
> >               return false;
> >
> > -     expect = kmalloc_obj(*expect);
> > +     expect = (typeof(expect))kmalloc_obj(observed.lines);
> >       if (WARN_ON(!expect))
> >               return false;
>
> Or:
>
>         expect = kmalloc_objs(*observed.lines, ARRAY_SIZE(observed.lines));
>
> I think the quoted cast is probably better...

The cast is easier to read (no indirection needed to understand it's
just allocating same size as observed.lines).

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNORUfQEVimGFwJtxsuae8VhimHEFWZUnqvtTZ6dC3_o5A%40mail.gmail.com.
