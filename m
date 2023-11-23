Return-Path: <kasan-dev+bncBDW2JDUY5AORBT4G7OVAMGQEI3LYSMI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc39.google.com (mail-oo1-xc39.google.com [IPv6:2607:f8b0:4864:20::c39])
	by mail.lfdr.de (Postfix) with ESMTPS id 52AF97F56EB
	for <lists+kasan-dev@lfdr.de>; Thu, 23 Nov 2023 04:13:21 +0100 (CET)
Received: by mail-oo1-xc39.google.com with SMTP id 006d021491bc7-58a2803007asf411039eaf.3
        for <lists+kasan-dev@lfdr.de>; Wed, 22 Nov 2023 19:13:21 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1700709200; cv=pass;
        d=google.com; s=arc-20160816;
        b=UUkoy3cuGnhUlq1fu8D9sCrOz3sQ1WeGGKGskq8AJ86ZQFqm+laPXN87XlF1PWA+6w
         AcyRI0s4fp90SglAtktoh5dgm9JkdTBDoKdh63hPHNxQgck0/jQNxWiSBUuwCxFJ387c
         SCEHvtQVVarVcIkSO9f8fLrUSgin446X0HokM5OFdcZbQyrXqxabwASPzOjS0e4KwiSq
         OPzEjdCh1FXPPfPs0P/L/PPlm5lKxtoh/j0jUXmHblKY3EvfmuCwy8I/ovNHkj3y0p/o
         eE3aaOI2ofOOqPQU2v2VA0C2G//ffiaU3kXPrB2hKvP1TxH+kH9Ton1eGlMJrjri0/Qs
         bRkA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=qiCIFnmYh8W7shDq/cbFHL3c/gu1pJjUspr79QSSBss=;
        fh=DMpuiuGddKAd9gJK1ZWZ3xeGsMHnmViVLNra/uemh1o=;
        b=FMZtipcl/Qx6hU9DxFkLqjtb+JOpJQrjYiSfQ8VBq4WEruFwea+X5WEGu1vRe3Bhpc
         PAe+Eei+OtEY6G/tK9DmXq/Va2wzIYOooaBGL70xZeugk+zU4N0oLStWZceuqmRv9nvp
         h/mjPyWCu+YK5j3PTNiUgFUxlOXGtAblD1LCvGlyuizBvtx6CuMsGeFIgAM2SZ079qwA
         7B/nZVjkvlXCmaX3RWmDqYDlnXTr4VM125nrK0Ebt9Nr6vI7Vo6Yw/58bxzGky4aixFE
         YOOgg8AueENOw6qxyRKdoqbSrKVzfv2gqtgq81LxucrRkQzbxW34W3DIoddjTc9yK7j+
         wPLg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=a6vPTFnR;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::42b as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1700709200; x=1701314000; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=qiCIFnmYh8W7shDq/cbFHL3c/gu1pJjUspr79QSSBss=;
        b=sLpjFPJwDZM+draDkUf3YYYzq7XJQXNMh1eSbWPT50uWvEgwf+Vi7edBF0gRwiEaIy
         UkYU/ADkGuTSYfGwbyewKrXAo5LtjsFcvi9wwZ9KFXsZ/HcRVoZDZTVt44tT+pCTC34T
         hpR0c/sLoiCy+KK4gGN4WtotCvuH7zn4uBnmbM+R5n3/FLpedsHLIzP+VbVZ3MKdjIVH
         7YWHpLcllzKqQ04hfKy535GjhhiXbyzSHq6pBfAEyI/KNmG8rcLMV6Mxxo5PIiosUlA1
         GXedLsLHSCuA1BnwmSzNbykYatt3MlFR/gOgVyTElvhRcepj6dhGvZJoHslk5cEX2Uad
         SdHQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1700709200; x=1701314000; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=qiCIFnmYh8W7shDq/cbFHL3c/gu1pJjUspr79QSSBss=;
        b=SXjBPfBKgHJ/H9rHQxcWMjsIOIi4QdFGiVtwtmnXzpFDpM9edQ+AFfUZvvCipxu6EI
         35uK5xBFWxeIoKjtT85x7h9cPy25fgy9zMqEKb79f94CbVwtJursMEf5nhMBRViWRVKF
         PIX9gGKvGSdwHjc+JlRta1KJG/1ygPt36vjto6qDJtq1fJApM4bf0//MVAMB4eucIAxL
         McXUoZww2SyVktFHEFmJIAuAFvLlcH08C4nzGC+hTe7TxsRJAqhKkKjDG5uzmmR1rM3J
         0NTlzZ7hgQzNRcghdZFT8KZnyazHbf+GGrpY+qesc/dsoC9bkICIQjWWN9BqVwNgWpub
         Djaw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1700709200; x=1701314000;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=qiCIFnmYh8W7shDq/cbFHL3c/gu1pJjUspr79QSSBss=;
        b=wrUU85P5SU9LPaqh9bAakG9M3sWHMbLN3fyaCeNe0xQrL/OmsqZaOCtryyxSQ3Omfs
         k4M0RZYPF3IYws6p+JpjYAw3MKGV166ZaVOMa/oq4ew25YheewMT/CNpglYzSNmgegrp
         8+F125HbxB1rDDsig6X2uwFDUoJqwP+FoCAEf7C+2AYTVYNKcVq8eHxZRVZWSyj82uMh
         Wig+6Sps+85T/pKNrdKTgkzBDm3fxQpiWmRHzBUz64xCOhgaaXa1Bnu1FzvJLnEUHnsM
         Itac58ZzAWLBQdB+Q+DViHL7NwyJhxujTS/6dJHF78Nrm/bTgvq2RXJpMtANIcYQJKL8
         tApg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YzUNUk3EhGXb+qusxHQb8dHW8AlB8RYozo/rqKXbVb/Cgud/+vg
	FnrHpRxC3KoVcJwYFfXLRmk=
X-Google-Smtp-Source: AGHT+IHOPeeHuK9rfI8Hrszu585xAHEOGEn4JfEwMcFm7lAhZgc2FLMXTY0Th67xp6auISfdCOrhoQ==
X-Received: by 2002:a4a:bf18:0:b0:581:f2d8:3f9f with SMTP id r24-20020a4abf18000000b00581f2d83f9fmr3825858oop.7.1700709199789;
        Wed, 22 Nov 2023 19:13:19 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6820:612:b0:58a:b02:fee with SMTP id e18-20020a056820061200b0058a0b020feels301222oow.1.-pod-prod-06-us;
 Wed, 22 Nov 2023 19:13:19 -0800 (PST)
X-Received: by 2002:a05:6870:c07:b0:1e9:b4d1:9bed with SMTP id le7-20020a0568700c0700b001e9b4d19bedmr5707978oab.40.1700709199149;
        Wed, 22 Nov 2023 19:13:19 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1700709199; cv=none;
        d=google.com; s=arc-20160816;
        b=s6RmXxK1Jp7xfQDhyi8BkgvLoVGPb1pz/sJdoVYvwngoIWzn3ZloXpmoIy3Rs4sVqU
         DU/xWGO9e12HGVQDAQgsZmDhd5NraZq0KTOunlEUor7EVzWjKIwdM8X265HXZrQrnCdC
         Ysbru7ENPKuasMpoz/SBsT3WaXoQcmuKH1BbsnhFd+1p8sYY50+bFfNXD1D6yTaTIcBS
         1UIO+kfnMz+2RwJZFPP8Fl1OJ7JL+8Y3PfaCBGPO6gBcR6L44gqnahpXbMoiizo+wM5z
         Vt99sDotBwJ1BF9KCagQ3dnkbjwxVPk1iizSvNKvB5LWa58FA13QXlR2IffhU/Tgg8Pq
         x/Wg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=Oi0aE1CoZEk7o6yHZvNub+boTKgxjNTVuh11lvWZM4g=;
        fh=DMpuiuGddKAd9gJK1ZWZ3xeGsMHnmViVLNra/uemh1o=;
        b=u/6vWGbmfpNv6p5BJZmNBnZodVNJnqnHGozZkqwSgoOnVZ1buAwAH/zIgieHZd27BI
         9dJ+OuSd93sOT/4E4cDyAeCaKliwRZMJK/p/Mtss7OSHIoN5nqaDSBIf0zwP5n6K0X5o
         tylDXo5SpoB9ifloiVyydmS3cPUVGhNMEeW96nZVtN/qfLncUZMb4/8GH1BywdF6CBET
         /RlGHB5180clBAKJsqUgKIOaFufiB21jW4BtbhHAQsiJFRADIzV3zLdNL1tWvdRd4LAK
         yT3Qpa2oN5b0RgIbBdT/wGMLFQdj2CesOGNoPRAoR2zWe8UZN7G8Rzan+Ht8ePj1fI8p
         3pHQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=a6vPTFnR;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::42b as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pf1-x42b.google.com (mail-pf1-x42b.google.com. [2607:f8b0:4864:20::42b])
        by gmr-mx.google.com with ESMTPS id u27-20020a056870f29b00b001dcf3f50667si47727oap.0.2023.11.22.19.13.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 22 Nov 2023 19:13:19 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::42b as permitted sender) client-ip=2607:f8b0:4864:20::42b;
Received: by mail-pf1-x42b.google.com with SMTP id d2e1a72fcca58-6c4eb5fda3cso454497b3a.2
        for <kasan-dev@googlegroups.com>; Wed, 22 Nov 2023 19:13:19 -0800 (PST)
X-Received: by 2002:a05:6a20:e11b:b0:187:7af3:bb0c with SMTP id
 kr27-20020a056a20e11b00b001877af3bb0cmr5645234pzb.58.1700709198541; Wed, 22
 Nov 2023 19:13:18 -0800 (PST)
MIME-Version: 1.0
References: <20231122231202.121277-1-andrey.konovalov@linux.dev>
 <CAB=+i9QFeQqSAhwY_BF-DZvZ9TL_rWz7nMOBhDWhXecamsn=dw@mail.gmail.com>
 <CA+fCnZdp4+2u8a6mhj_SbdmfQ4dWsXBS8O2W3gygzkctekUivw@mail.gmail.com> <CAB=+i9RnOz0jDockOfw3oNageCUF5gmF+nzOzPpoTxtr7eqn7g@mail.gmail.com>
In-Reply-To: <CAB=+i9RnOz0jDockOfw3oNageCUF5gmF+nzOzPpoTxtr7eqn7g@mail.gmail.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Thu, 23 Nov 2023 04:13:07 +0100
Message-ID: <CA+fCnZcpLE_uR4D9eyUA9_TzF0w2GgY=yWYB63b2VL1snAQi1Q@mail.gmail.com>
Subject: Re: [PATCH mm] slub, kasan: improve interaction of KASAN and
 slub_debug poisoning
To: Hyeonggon Yoo <42.hyeyoo@gmail.com>
Cc: andrey.konovalov@linux.dev, Andrew Morton <akpm@linux-foundation.org>, 
	Marco Elver <elver@google.com>, Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, 
	Evgenii Stepanov <eugenis@google.com>, Oscar Salvador <osalvador@suse.de>, Feng Tang <feng.tang@intel.com>, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=a6vPTFnR;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::42b
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Thu, Nov 23, 2023 at 3:58=E2=80=AFAM Hyeonggon Yoo <42.hyeyoo@gmail.com>=
 wrote:
>
> 1. I reverted the commit "kasan: improve free meta storage in Generic KAS=
AN",
>     on top of linux-next (next-20231122), and it is still stuck at boot.

This is expected: the patch you bisected to still requires this fix
that I posted.

> 2. I reverted the commit "kasan: improve free meta storage in Generic KAS=
AN",
>     on top of linux-next (next-20231122),
>    _and_ applied this patch on top of it, now it boots fine!

Great! Thank you for testing!

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BfCnZcpLE_uR4D9eyUA9_TzF0w2GgY%3DyWYB63b2VL1snAQi1Q%40mail.gm=
ail.com.
