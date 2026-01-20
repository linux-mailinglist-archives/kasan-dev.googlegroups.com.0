Return-Path: <kasan-dev+bncBCCMH5WKTMGRBDUEX3FQMGQEKIGYKOY@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id wPXqNnurb2lUEwAAu9opvQ
	(envelope-from <kasan-dev+bncBCCMH5WKTMGRBDUEX3FQMGQEKIGYKOY@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Tue, 20 Jan 2026 17:21:15 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x839.google.com (mail-qt1-x839.google.com [IPv6:2607:f8b0:4864:20::839])
	by mail.lfdr.de (Postfix) with ESMTPS id 67F1247567
	for <lists+kasan-dev@lfdr.de>; Tue, 20 Jan 2026 17:21:15 +0100 (CET)
Received: by mail-qt1-x839.google.com with SMTP id d75a77b69052e-5014ca48a56sf75073201cf.1
        for <lists+kasan-dev@lfdr.de>; Tue, 20 Jan 2026 08:21:15 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1768926074; cv=pass;
        d=google.com; s=arc-20240605;
        b=BMyP6OB/mwrHDrnBQv+dny+UMFLegiuy+BcH6dOFt/K+qYyiMyICg4G5KJmGJoItn/
         G+DEZBY2x4gmt/dFRBT6aS1Tj+7NsEDE6Lwk/jjmcLLU2S+5sCz5ve3id9aaIJSazDey
         aDKH0qPacJm9eyhaIpdM+OxjSM5AUgboAOhrvz4izMviTB2wga70eTylc5NdbIHrX0m7
         QQ9n4s3TR/1JXrdpTGxDL30RWnovtrzoRwAwRl0y+gryevkDxUWr1FgAVxfFZc69h4wU
         hA8Pun4mp0PKgQtcNl6eO+Dcmk0Kahtl3YXSrnxF1UsJXW6YoA35k8e2KuRgvWPK6S+Y
         xUFA==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Z89qKe+MfkP3a2yRW6JLTE9e74s2LjsNWQh+UnFypAc=;
        fh=CVDIg6LY6fZ3iu+2792hHsBhJjRQGscNrBWNIsrqhDY=;
        b=Qb4sk5redKa6k3eJbRNw2smmhVT9G9tQdh2PRZZDoSE2pT/uJvOxmfJPdQIbqA2cGL
         S0KGzT66FTyWXdL71cUMHu42UqGeKyM/x+wavLy41n9OOGD+FTtMN7B2uw1TVvQ1f2Zw
         5PDty55RrNEkyfrvshRDBeWqAQNAd3wiRoJHy24wxfFRusmtaALWQbOG/CWlN73kzaUE
         zWRaKr3df/IsQk7BvbqIA/uTs3/8bERlGPeLbNxAP3RngL3rhkjQLBk37WI8/A9xqDYN
         cwo628dU8eTpocxMKMTd6mQJZmtastX+PUaRyMUE/cQvG7J55wz+u1CxEZ4jSr2FRXT4
         glFg==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=Vu3NQ+VT;
       arc=pass (i=1);
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::72a as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768926074; x=1769530874; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=Z89qKe+MfkP3a2yRW6JLTE9e74s2LjsNWQh+UnFypAc=;
        b=v9JqD2yhgtMeoIHD6I+jT78k9QyfrBie+vhZXlyYQgz46M+U4HTw0pvfxhZReLryoQ
         o1Fsz7wzPMoKvUwbmdQDhLpNW+NW/wvH92BkdGXW2A3ugYnCu9OJ6+yJIToH1cuK//rb
         77YXxt5rkIiKHI3CWOaidwcvOsf65i9lOWRn/mdW7WiPhzIxM5YjpelD7lf08yPbV/GY
         YJgghxfGlGXHPoKUPWDum23PeqCjOcgDTBtPJy/ZuUosT0LX66c3HNuFl/6PLLfmAr9B
         aYcqtyCwVZ4n7EP8lGSaNIKiWxcE9Z5hrAUYNtKAyqsezegLfHwFeyrQTyjlWrTtbrVA
         f5ug==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768926074; x=1769530874;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-gm-gg:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=Z89qKe+MfkP3a2yRW6JLTE9e74s2LjsNWQh+UnFypAc=;
        b=HZGM2yljBzzeV+z943rN5KvUZWfbtIgWXdzMPNG+64UpLAOognmDgj/r2/R0JBSoDu
         P/bK+NV7L+KO9KcFqOkIVgpxb+Xnn129qa9ANuglPNlUqESGn4444sUCI4cMKaiRL+Rs
         tsA5dzVqHbvySRdYCm2fbwm9RYyjdK3u0eTBWMV97Lsox6Xx+fNIuOlvk+75Pb5ea8No
         wbrLntHvdMJuGmyzsP8GtYWmLSSX31IsnsGP3K3xgDp+IklSplF6glGsrt4x1YJTCHkq
         JK4xKwuyYe+pgn250R1rDDBQ8uuu2x9s44exRDuI7bVnTSiY5UTrg4m8AvdZ1AjR0thm
         k3TA==
X-Forwarded-Encrypted: i=3; AJvYcCXa33JR28VVa/ddUx4Id5OQ9EJOSPhp2dETh5QxOxrR4qSJu++cTc3CGj7Q5L1LHBXhnh3Nlw==@lfdr.de
X-Gm-Message-State: AOJu0YwgCzB6gGes0g+qWFcgWq40R/1cX53bmgM+UlUiSa/wDAaPMt9J
	T45Dm6PXbSOuOuhZmxpBXqjYsZgBKDf6W6IfTFJ5S38tksvfjOwH2ZAK
X-Received: by 2002:a17:902:f64c:b0:297:e3c4:b2b0 with SMTP id d9443c01a7336-2a71894325amr159013725ad.54.1768915470509;
        Tue, 20 Jan 2026 05:24:30 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+ENcG7kS9rTXZM3Ss4UQSq+JKEMDOnDSB5CR/XzrlxOew=="
Received: by 2002:a17:903:3df2:b0:2a7:5dcc:80c9 with SMTP id
 d9443c01a7336-2a75dcc8373ls7942765ad.1.-pod-prod-06-us; Tue, 20 Jan 2026
 05:24:29 -0800 (PST)
X-Forwarded-Encrypted: i=3; AJvYcCVeCRCqKvQW3So+6yknnAw3YFzIshUhWrpZ4Y5f7F8vNF0/F929/kd58Xj405fiM9iG/mBdg0Dygmo=@googlegroups.com
X-Received: by 2002:a17:903:124b:b0:2a7:80d9:22cc with SMTP id d9443c01a7336-2a780d92338mr5038135ad.24.1768915468844;
        Tue, 20 Jan 2026 05:24:28 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768915468; cv=pass;
        d=google.com; s=arc-20240605;
        b=Y8ljwjPqhHozaODUmUTg6c9+Z/8x6ySm70fnzeqmfT0UZalN5av56vCWnCzv21YVvm
         g6HB2AFLOF/MgANksMa5ONYo0nA1DoQx6ybyLkgnFmWXlengjT5LBaWt9GhxbGTiSD7W
         fF/gx2eHMGKIZ4G1ZlkSv6eaVCRAfLyRhmjWTZi5bdpk8gtpExq1wA1g18jqUwpIIGZ2
         vg0kt9/09Aaf6BDMJLbz2j2WNSkZyv1109U/DMLmQBI9lGu0MxhQJ4yFSJ7dPs0lOcE2
         LZhrIakvcd0Z+hPG0JqxUyZw2PWyosDNRlg2TVYKN2+w/Zl6Qc0h3Edp0EC74iKKpExo
         mO1w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=4nu4xZEY0rSvLbxW/bG040Gc/VM91yZ6fjUuBWMnaOo=;
        fh=KkMNYOvpEW4Wl61GPZeEZPrBMhh6EA5TMHspfdbJkZk=;
        b=NQgq68YVxbZ3GxhDTB6twZlr0GeBmJKUJgaytoEGOa4qzUb8rGpaal2jgpt5bZFano
         kGQiOjbLZ5qV2qGRwUD0A3+X/1zZz4zONJqCgAhSQ+HP1d6v9R9QU2FVxNjAWjhxjVqB
         ixmIghO/rcP94yCVOMu0dD3TpMmxrDErix/ZfU7HDh19eTGvDSj4I4JU5fp3SV8vtMxC
         D12R3RNCj5ikYQWLgyIdGVOEbQC67SiWtxkBFMmtp46s/aIvs07PxHtBt9r0dagukx1e
         CPXz54zigfwyMNiPZGuQDTvPc4BjXc/ZTzaYwzFqdzBARgPgJmdzoLzmwO7vpFNn1S0v
         VeyA==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=Vu3NQ+VT;
       arc=pass (i=1);
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::72a as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qk1-x72a.google.com (mail-qk1-x72a.google.com. [2607:f8b0:4864:20::72a])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-2a7193ac455si3167265ad.8.2026.01.20.05.24.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 20 Jan 2026 05:24:28 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::72a as permitted sender) client-ip=2607:f8b0:4864:20::72a;
Received: by mail-qk1-x72a.google.com with SMTP id af79cd13be357-8c538d17816so703728285a.0
        for <kasan-dev@googlegroups.com>; Tue, 20 Jan 2026 05:24:28 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768915468; cv=none;
        d=google.com; s=arc-20240605;
        b=RVytyhrFrttAs95HFGLZP+PfK0lR+VPr5yyfSnOchAlt7PkRaUV3aecfjFWGPVKWk2
         GCjyUSzXgz4piIhtyBrQD5uwKa7uzCFwYqWCDRlweKb5G565Zt1o4nGQi3FZzs+FGoZw
         j66cH+1isgmkPywxB5CjvySCTDCdicGJDR1YBLqMHxSNicEe+5vmcTn3/fQdqCm5JEH3
         pH/JTfGPIgM6Oga/HQHAv2+YvB2kG8I1LJUNFVvayf3Dk2NukutGo+kF8LPvSbwpu/98
         /wTkPgW58y3GuzkKy4cPqZ1hxTunNhMGtGLTksSXubmX0NKe+vqDGgXEq2GlPy+bHPJH
         MRYA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=4nu4xZEY0rSvLbxW/bG040Gc/VM91yZ6fjUuBWMnaOo=;
        fh=KkMNYOvpEW4Wl61GPZeEZPrBMhh6EA5TMHspfdbJkZk=;
        b=I674w75IuzYkP22Nu1GLPzFyi1utgvrwl1Fq6pgLNxYEpoZmDYLDCh6u9rj+DOK5LY
         POr4XpJsMpFTwBsvzTIQQH04uLGhJHHZExAKiGasTQLrni/nxEUyJEGUQ9UOfXkVkg74
         3egLjap4If3nPjrvP+suADzwqEGhEGIjwHRDHyffRPlPDexvKdmugv266Tj9rSIZ53BI
         RWLP67gFJHvspMmgUfeOE8Y9WMfOqDBkcYcD4kh1zYNgpHG8GqjNDMoZpvL8ABq+++0u
         7s3awpFgtKGJc3BPcAT3/y5YCzgy+UT8GeRi1Acr5EY+s9dnT2WkNLIDagiJqsDRssYI
         pRYw==;
        dara=google.com
ARC-Authentication-Results: i=1; mx.google.com; arc=none
X-Forwarded-Encrypted: i=1; AJvYcCVDP636jB852Q7Ovq8nsMgaW5PZiRxyAKFIVsb3l0c/mt94Vjl+O0B7kfuu3wOD3VtamQm5ibXvqTQ=@googlegroups.com
X-Gm-Gg: AY/fxX4NQ0sHrlv32qds0RhYYrznVIfpj0kSFPHQVxQAO3SIfcF7dztAy6qc6yfCsCG
	utOFThmg8bVEsK6B7NvJmPJKnka5eesU1645ZcNQu9SaSvH4U72FrU6RUqgf9PBUop1R8SjhDJF
	jAQAFIBiL56kNnusH/QUtxWIO43/cF4cr1gehijaw9jGepDtMmfApUgx4yO73zGqdgjwYiam9w5
	Jt2o0zKokBCSPhszKeJSVUIwXHaNXLNJuZWTvG6++0OVBqyVhSUM6bIQVx61HKaX3yuEoUFLECn
	pdDciIyOtfJ9PqdMjXlZPkBSUS2cucRoN1I=
X-Received: by 2002:a05:620a:a819:b0:8c6:aaf3:cb44 with SMTP id
 af79cd13be357-8c6aaf3cd9bmr1776741585a.4.1768915467445; Tue, 20 Jan 2026
 05:24:27 -0800 (PST)
MIME-Version: 1.0
References: <20260112192827.25989-1-ethan.w.s.graham@gmail.com> <20260112192827.25989-2-ethan.w.s.graham@gmail.com>
In-Reply-To: <20260112192827.25989-2-ethan.w.s.graham@gmail.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 20 Jan 2026 14:23:50 +0100
X-Gm-Features: AZwV_QjW2mQ_xeztIGqfilZWMz9KqTXvzLTRYEAqSaJ4no1YJpwzVkinmD1XMRA
Message-ID: <CAG_fn=U46vT+gOAX1D1RxDP3oaduWbsRMs2RWG99U2ND+BM_Vg@mail.gmail.com>
Subject: Re: [PATCH v4 1/6] kfuzztest: add user-facing API and data structures
To: Ethan Graham <ethan.w.s.graham@gmail.com>
Cc: akpm@linux-foundation.org, andreyknvl@gmail.com, andy@kernel.org, 
	andy.shevchenko@gmail.com, brauner@kernel.org, brendan.higgins@linux.dev, 
	davem@davemloft.net, davidgow@google.com, dhowells@redhat.com, 
	dvyukov@google.com, ebiggers@kernel.org, elver@google.com, 
	gregkh@linuxfoundation.org, herbert@gondor.apana.org.au, ignat@cloudflare.com, 
	jack@suse.cz, jannh@google.com, johannes@sipsolutions.net, 
	kasan-dev@googlegroups.com, kees@kernel.org, kunit-dev@googlegroups.com, 
	linux-crypto@vger.kernel.org, linux-kernel@vger.kernel.org, 
	linux-mm@kvack.org, lukas@wunner.de, mcgrof@kernel.org, rmoar@google.com, 
	shuah@kernel.org, sj@kernel.org, skhan@linuxfoundation.org, 
	tarasmadan@google.com, wentaoz5@illinois.edu
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=Vu3NQ+VT;       arc=pass
 (i=1);       spf=pass (google.com: domain of glider@google.com designates
 2607:f8b0:4864:20::72a as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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
X-Spamd-Result: default: False [-0.71 / 15.00];
	SUSPICIOUS_RECIPS(1.50)[];
	ARC_ALLOW(-1.00)[google.com:s=arc-20240605:i=3];
	DMARC_POLICY_ALLOW(-0.50)[googlegroups.com,none];
	R_SPF_ALLOW(-0.20)[+ip6:2607:f8b0:4000::/36:c];
	MAILLIST(-0.20)[googlegroups];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601];
	MIME_GOOD(-0.10)[text/plain];
	HAS_LIST_UNSUB(-0.01)[];
	RCVD_TLS_LAST(0.00)[];
	TAGGED_FROM(0.00)[bncBCCMH5WKTMGRBDUEX3FQMGQEKIGYKOY];
	RCVD_COUNT_THREE(0.00)[4];
	FREEMAIL_TO(0.00)[gmail.com];
	TO_DN_SOME(0.00)[];
	MIME_TRACE(0.00)[0:+];
	RCPT_COUNT_TWELVE(0.00)[33];
	FROM_HAS_DN(0.00)[];
	REPLYTO_DOM_NEQ_FROM_DOM(0.00)[];
	HAS_REPLYTO(0.00)[glider@google.com];
	ASN(0.00)[asn:15169, ipnet:2607:f8b0::/32, country:US];
	TAGGED_RCPT(0.00)[kasan-dev];
	FROM_EQ_ENVFROM(0.00)[];
	FREEMAIL_CC(0.00)[linux-foundation.org,gmail.com,kernel.org,linux.dev,davemloft.net,google.com,redhat.com,linuxfoundation.org,gondor.apana.org.au,cloudflare.com,suse.cz,sipsolutions.net,googlegroups.com,vger.kernel.org,kvack.org,wunner.de,illinois.edu];
	MISSING_XM_UA(0.00)[];
	REPLYTO_DOM_NEQ_TO_DOM(0.00)[];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	DBL_BLOCKED_OPENRESOLVER(0.00)[mail.gmail.com:mid]
X-Rspamd-Queue-Id: 67F1247567
X-Rspamd-Action: no action
X-Rspamd-Server: lfdr

On Mon, Jan 12, 2026 at 8:28=E2=80=AFPM Ethan Graham <ethan.w.s.graham@gmai=
l.com> wrote:

> diff --git a/include/asm-generic/vmlinux.lds.h b/include/asm-generic/vmli=
nux.lds.h
> index ae2d2359b79e..5aa46dbbc9b2 100644
> --- a/include/asm-generic/vmlinux.lds.h
> +++ b/include/asm-generic/vmlinux.lds.h
> @@ -373,7 +373,8 @@ defined(CONFIG_AUTOFDO_CLANG) || defined(CONFIG_PROPE=
LLER_CLANG)
>         TRACE_PRINTKS()                                                 \
>         BPF_RAW_TP()                                                    \
>         TRACEPOINT_STR()                                                \
> -       KUNIT_TABLE()
> +       KUNIT_TABLE()                                                   \
> +       KFUZZTEST_TABLE()
>
>  /*
>   * Data section helpers
> @@ -966,6 +967,17 @@ defined(CONFIG_AUTOFDO_CLANG) || defined(CONFIG_PROP=
ELLER_CLANG)
>                 BOUNDED_SECTION_POST_LABEL(.kunit_init_test_suites, \
>                                 __kunit_init_suites, _start, _end)
>
> +#ifdef CONFIG_KFUZZTEST
> +#define KFUZZTEST_TABLE()                                              \
> +       . =3D ALIGN(PAGE_SIZE);                                          =
 \

Can you remind me if PAGE_SIZE alignment is strictly required here?


> +
> +#define KFUZZTEST_MAX_INPUT_SIZE (PAGE_SIZE * 16)

Right now KFUZZTEST_MAX_INPUT_SIZE is only used in a single C file,
can you move it there?


> + * User-provided Logic:
> + * The developer must provide the body of the fuzz test logic within the=
 curly
> + * braces following the macro invocation. Within this scope, the framewo=
rk
> + * implicitly defines the following variables:
> + *
> + * - `char *data`: A pointer to the raw input data.
> + * - `size_t datalen`: The length of the input data.
> + *
> + * Example Usage:
> + *
> + * // 1. The kernel function that we want to fuzz.
> + * int process_data(const char *data, size_t datalen);

Maybe we'd better use u8 or unsigned char here for clarity?


                                \
> +               void *buffer;                                            =
                                               \
> +               int ret;                                                 =
                                               \
> +                                                                        =
                                               \
> +               ret =3D kfuzztest_write_cb_common(filp, buf, len, off, &b=
uffer);                                          \
> +               if (ret < 0)                                             =
                                               \
> +                       goto out;                                        =
                                               \
> +               ret =3D kfuzztest_simple_logic_##test_name(buffer, len); =
                                                 \
> +               if (ret =3D=3D 0)                                        =
                                                   \
> +                       ret =3D len;                                     =
                                                 \
> +               kfree(buffer);                                           =
                                               \

Please ensure we have includes for everything used in this header
(e.g. linux/slab.h is missing).

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
AG_fn%3DU46vT%2BgOAX1D1RxDP3oaduWbsRMs2RWG99U2ND%2BBM_Vg%40mail.gmail.com.
