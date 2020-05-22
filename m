Return-Path: <kasan-dev+bncBCP4ZTXNRIFBBXWRT33AKGQEOYA3WGQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23f.google.com (mail-lj1-x23f.google.com [IPv6:2a00:1450:4864:20::23f])
	by mail.lfdr.de (Postfix) with ESMTPS id 151091DE45B
	for <lists+kasan-dev@lfdr.de>; Fri, 22 May 2020 12:26:39 +0200 (CEST)
Received: by mail-lj1-x23f.google.com with SMTP id e7sf2732966lja.16
        for <lists+kasan-dev@lfdr.de>; Fri, 22 May 2020 03:26:39 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1590143198; cv=pass;
        d=google.com; s=arc-20160816;
        b=F53ojjP38/ultMn/NqlTTZtVoT2OMRON8Ytcdipy08P4mzlUS+6pK17Y2yJdPQ3g7B
         H7R+/yUBuahO8DVLOw4DTgiJbwG/+YNoFBQ55/ucFLNpeaJu07wrq4crLNs05xA/aYYm
         1lHmEtluAQ1AGG0EKsoA05ItA3W+RZjw/K35DBFL+S8lfVoyuujIyWVgPLhO1Cw4J0d3
         KgDPLfAjGvMbjCHZBQzFvfM6YyzeaTpU55keBHPkQ6NUIpdeoqXmjqTFMWl39WavnbmD
         Nw4v1CZYPmN1Rl6pyGR3HuRCTlVRUEh7KwnukbFiy3cCRU6rYcfcqVgUzA+ormdDPqrM
         3jIA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=EkuHFHrmOxytdeIjfx8UTEd7K1OJaZqeG/jeQWaOfdc=;
        b=cXEu2gAnRIBJ0fv39yqHw7SL2a+PSoegcXnWkZpgaEt92m3d8381PJul3BrrrEtSA/
         vG5NtlbCaUwpdDi5DcbrYV03Jz+Uv+IMMMDge6TozVb9Qun/UY1tZPWDx98NEFisoVCX
         YqOS5MA+qFzBEI/Kf2Z7x2LMxcUeh0GmLrdGmfSajDZ6+m//olYy/LWjPUYD3aLiKNLv
         dxi8tYG7fHaEF0l16rZKK6Gz81+9+bKTf1GTaBBKywFe1J0xNpCl7Hcb8Vy2cesFqEku
         MMCG28OW/gTqyt+7hLQllkNeVpzqYIChQHwFhFnjaEyZbgvJ3zZjxuuR6DU+Uy+ZX/jx
         bZCg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@alien8.de header.s=dkim header.b=qdA9OPqs;
       spf=pass (google.com: domain of bp@alien8.de designates 2a01:4f8:190:11c2::b:1457 as permitted sender) smtp.mailfrom=bp@alien8.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=alien8.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:content-transfer-encoding:in-reply-to
         :user-agent:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=EkuHFHrmOxytdeIjfx8UTEd7K1OJaZqeG/jeQWaOfdc=;
        b=sizL5RIP64/O6YpQLKZf10YKgo8GttVVG5yHry17EJdx9yTxhVYgulkrcHXv9hladx
         tgL/tAYXCK20yQgO0XdUevf9IjDMAK1CrlhUjCJruEhElqdetnmbX7D3r+UFupCfQola
         IJkUAiWqfR3H+EJSZSC9GNOV62dYRVguNzHUZBIDBltS0zE9ZIBhWHefXmd4gM1fivic
         TzDe790qoxYs1cE5YFDz2vBl+CwZinhh1vKyLTUROt8338p0zn2zWAf7UAC9oySLh2wv
         d2LzPGNjDBklm+WiL3gwBb9zyPx2pnugRoJw+XjBgComaTGVmmEPvg94FSbciaTJUb3L
         ieXw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition
         :content-transfer-encoding:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=EkuHFHrmOxytdeIjfx8UTEd7K1OJaZqeG/jeQWaOfdc=;
        b=Y+ffCYHLTivvaczCG40Ldpu/OwkK6oPT7dWmq4eZQ1n3BrniVtZ8FrzivboiNhRsQC
         IMVgwzg3URCF93rFMICzfQkpVHoROwfnLY4IyQk0GNLYWBmlp0XYELRAqWsGyAwOiYxO
         0/8QpLcg7SprIeTFmi/DBzmuv5jsS+y5F2Dp/8yfrC+6nLTQZw1CC0BivwrouRAekVvv
         NRvU7wISkAvq/TptQ0M4XRD1wEYEjGaBAhz9Fq1TctHtpzRZuTdfrXVaz050PhC3OnT9
         RQW/810hFV6/6SawW46tBLrMTzQFkgzHUr+iEH+rGMzJHtfl9YzHboSjwVPXSYKO5Odp
         jkkw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531OjULHU0ERD+Zmb2gqscq939UNSoftdMGnS7u3IfQ1aJFGrTGQ
	+q3LddCeA3cIfGnRtmRIslk=
X-Google-Smtp-Source: ABdhPJxZtS359ewDH1cBo4KXSJBhSPUQsNZcBiTEp7E6RnmfdcQte+ZGB9I1EQ1w+/ZXzC13iTgBzA==
X-Received: by 2002:a2e:9410:: with SMTP id i16mr5667822ljh.406.1590143198578;
        Fri, 22 May 2020 03:26:38 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:b5d5:: with SMTP id g21ls236325ljn.1.gmail; Fri, 22 May
 2020 03:26:38 -0700 (PDT)
X-Received: by 2002:a05:651c:3c1:: with SMTP id f1mr7180051ljp.77.1590143198032;
        Fri, 22 May 2020 03:26:38 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1590143198; cv=none;
        d=google.com; s=arc-20160816;
        b=JNU/JEcHPbSAfuE8LYYuuDXmkD4mtXU4CtEeDA8nhns+20OwbdHM3rM+arnoJtYLkE
         9VI3nYE96D+O5TSH7yZTQpOTvkfZGCH8xJf8tu2qBy7iSo+aVRIzMNuq/T2h7Z1x5MkT
         vNF9j/Kl7SZUD2N5J1ht0dXRKnnMR0Y28j6h6LTWgEAk/tl3DecJaiPbX6Io3Il1Ot/c
         v2IZ/Ou9kb4iJFwEI5leA0mQZrdup/3+Y0v/kBlRcLeFc0paLQHanPH4wCzHD1t2MZg0
         j8ntdXQyT8dePs/ISzY/1WwDP4EzKrbEiN6h3FM0jdwzFb2TSjfMkIsFTKse0uzJtil2
         iBSw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=P/XDVTKccx+x8Mgp+Gyd+1EjhHIf2Ys7dOXVJ8hPhJY=;
        b=vehdFMV1avL3ZBit6qVB0B8gw4WAlPF72zV5XDEhVbvPVmE9tC+GFVKJDqux8xg3c2
         qKhlf+knqjrVrge0orcwhiS4aoHfMPGCKt+BKUvxyvdIo5cmwNARGbOBChZ5STCEhj1F
         pyI+LWTEVBlGhEiUgZTjBqrOG19bHs5PZXX5i+eeoipg8VCmSrCyPDFcSftdtu8sfWXk
         MtSfSzis1EsLiVcXUacmy9xHeLNXaN6xqoqHOTnYnuEk0nKi8UWy72unhaztEBkAjy7R
         LW2B0FauomialN3EeSGu2syTCUSEZy4GkSYkYXUB2fEaoMnQGt+0nzahXdikl+40Xt6d
         JhaA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@alien8.de header.s=dkim header.b=qdA9OPqs;
       spf=pass (google.com: domain of bp@alien8.de designates 2a01:4f8:190:11c2::b:1457 as permitted sender) smtp.mailfrom=bp@alien8.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=alien8.de
Received: from mail.skyhub.de (mail.skyhub.de. [2a01:4f8:190:11c2::b:1457])
        by gmr-mx.google.com with ESMTPS id c10si33260lji.1.2020.05.22.03.26.37
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 22 May 2020 03:26:37 -0700 (PDT)
Received-SPF: pass (google.com: domain of bp@alien8.de designates 2a01:4f8:190:11c2::b:1457 as permitted sender) client-ip=2a01:4f8:190:11c2::b:1457;
Received: from zn.tnic (p200300ec2f0d490039ac3da161697ee8.dip0.t-ipconnect.de [IPv6:2003:ec:2f0d:4900:39ac:3da1:6169:7ee8])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.skyhub.de (SuperMail on ZX Spectrum 128k) with ESMTPSA id 12E0A1EC02B2;
	Fri, 22 May 2020 12:26:37 +0200 (CEST)
Date: Fri, 22 May 2020 12:26:31 +0200
From: Borislav Petkov <bp@alien8.de>
To: Marco Elver <elver@google.com>
Cc: paulmck@kernel.org, dvyukov@google.com, glider@google.com,
	andreyknvl@google.com, kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org, tglx@linutronix.de, mingo@kernel.org,
	peterz@infradead.org, will@kernel.org,
	clang-built-linux@googlegroups.com
Subject: Re: [PATCH -tip v3 03/11] kcsan: Support distinguishing volatile
 accesses
Message-ID: <20200522102630.GC28750@zn.tnic>
References: <20200521142047.169334-1-elver@google.com>
 <20200521142047.169334-4-elver@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <20200521142047.169334-4-elver@google.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: bp@alien8.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@alien8.de header.s=dkim header.b=qdA9OPqs;       spf=pass
 (google.com: domain of bp@alien8.de designates 2a01:4f8:190:11c2::b:1457 as
 permitted sender) smtp.mailfrom=bp@alien8.de;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=alien8.de
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

On Thu, May 21, 2020 at 04:20:39PM +0200, Marco Elver wrote:
> diff --git a/scripts/Makefile.kcsan b/scripts/Makefile.kcsan
> index 20337a7ecf54..75d2942b9437 100644
> --- a/scripts/Makefile.kcsan
> +++ b/scripts/Makefile.kcsan
> @@ -9,7 +9,10 @@ else
>  cc-param =3D --param -$(1)
>  endif
> =20
> +# Keep most options here optional, to allow enabling more compilers if a=
bsence
> +# of some options does not break KCSAN nor causes false positive reports=
.
>  CFLAGS_KCSAN :=3D -fsanitize=3Dthread \
> -	$(call cc-option,$(call cc-param,tsan-instrument-func-entry-exit=3D0) -=
fno-optimize-sibling-calls)
> +	$(call cc-option,$(call cc-param,tsan-instrument-func-entry-exit=3D0) -=
fno-optimize-sibling-calls) \
> +	$(call cc-param,tsan-distinguish-volatile=3D1)

gcc 9 doesn't like this:

cc1: error: invalid --param name =E2=80=98-tsan-distinguish-volatile=E2=80=
=99
make[1]: *** [scripts/Makefile.build:100: scripts/mod/devicetable-offsets.s=
] Error 1
make[1]: *** Waiting for unfinished jobs....
cc1: error: invalid --param name =E2=80=98-tsan-distinguish-volatile=E2=80=
=99
make[1]: *** [scripts/Makefile.build:267: scripts/mod/empty.o] Error 1
make: *** [Makefile:1141: prepare0] Error 2
make: *** Waiting for unfinished jobs....

git grep "tsan-distinguish-volatile" in gcc's git doesn't give anything.

Hmm.

--=20
Regards/Gruss,
    Boris.

https://people.kernel.org/tglx/notes-about-netiquette

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20200522102630.GC28750%40zn.tnic.
