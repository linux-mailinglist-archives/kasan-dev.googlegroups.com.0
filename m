Return-Path: <kasan-dev+bncBD2NJ5WGSUOBBPHOWKKAMGQEPVGTZDQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x63e.google.com (mail-ej1-x63e.google.com [IPv6:2a00:1450:4864:20::63e])
	by mail.lfdr.de (Postfix) with ESMTPS id C640B532810
	for <lists+kasan-dev@lfdr.de>; Tue, 24 May 2022 12:45:16 +0200 (CEST)
Received: by mail-ej1-x63e.google.com with SMTP id sh14-20020a1709076e8e00b006f4a5de6888sf7597595ejc.8
        for <lists+kasan-dev@lfdr.de>; Tue, 24 May 2022 03:45:16 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1653389116; cv=pass;
        d=google.com; s=arc-20160816;
        b=c6BlqfnRyQMTZEKqjygO1tqlqnfJGr+9IvV8QjeFsvSPDI0b6OXSkHTatdgldKOJVa
         iYYiWXKFugBnD88UihUJUtU9C0DPA1/F37NguaQ/yIEEP258BISSFU1Lv2R1nH3mGI8k
         AI3ZvOK4m+S9x6Ypn5Yy5GIO2wwF+zUaBS3dwR4DMHJrdmcjE8wu9OJKGTkbSbpjshbZ
         uEz7idzZC4SAvaeqTRvivLLyZ7JH20AysgxbESS2kCIMV8r116bXrZhApqqkgq4qb4y9
         tat3SR9MZSgRro+8Su6yjL3fklDA3O2xPAnCbsG+bgJbHJ4iN12maUveCGqVYUBFZOM7
         cF6w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:user-agent:references
         :in-reply-to:date:cc:to:from:subject:message-id:sender
         :dkim-signature;
        bh=87V037gCsgK/SgXO2VJboNuLlYufQUKFignwKQBQun8=;
        b=GIsrvzDOn2y1/N35eREVdN3oRakvRB4BzbHzpRB7d1Aw8krM22qipBoSEeGbDZ/Ptn
         CeswGxysPC3AMl8Cy93ejHjnqkOQJQAdLviNm0mSQJm9OhP2lSVHuCv54vdFZUqLkSYE
         C1HCWbVtmvSD7+WwctAFh27KSM5v3CrCC9YMg/0mKlX/UZv0uOVVHrPAx3fI0daZY8Bc
         NHChLfucG3QwdtZIN0dodLagmzp1Yt0wHrSQHrXJclkF54kM26+97WSY+vfPqruDuX41
         ADogdHelu6NI84hYvxIY74I4zkY/2leVc2laOJZKOGFUs0+pwi+u3f8m9fFMW3tLpy6o
         606Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@sipsolutions.net header.s=mail header.b=gtlUhWaD;
       spf=pass (google.com: domain of johannes@sipsolutions.net designates 2a01:4f8:191:4433::2 as permitted sender) smtp.mailfrom=johannes@sipsolutions.net;
       dmarc=pass (p=NONE sp=REJECT dis=NONE) header.from=sipsolutions.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:message-id:subject:from:to:cc:date:in-reply-to:references
         :user-agent:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=87V037gCsgK/SgXO2VJboNuLlYufQUKFignwKQBQun8=;
        b=Q+g/9150urp0PmG4Rd/xft8hF2MJebSsy8/qkqf17V/2yyAxMdjw/y24FUkS91w9D+
         mnf079PHxccy3/1+2+Jor81MC29K4JPJY3GQOldupIw+Y8QA2swai6nTx+OasgqaR21k
         +TPBbcO85MjlJ5D8X7F/L/bPQlczFJBQYBQG5kUgxnJZWCWRvPtGYKzARqgPhMlFdPMX
         74g3gQZwBXuciq1i7OIfBFBpujrDYyLHmub4A1v+T61xBX8YTRQsTSoKvYO2lFMxe4jn
         OwsFNFPHUZX7ceV5YC/IEj+3ATR5jeduiJqkUJl/BSc90+lcHsxRo3M4AqJ/eO0rhzA0
         LtwA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:message-id:subject:from:to:cc:date
         :in-reply-to:references:user-agent:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=87V037gCsgK/SgXO2VJboNuLlYufQUKFignwKQBQun8=;
        b=0kpbJ8KSJtw9HnISVSQKNPcVLWSbd3zcFaEn1HdxRy67ULdua6Nuvm4IDF9FFP/6CZ
         If+hBOIUZeY2WoNRtvoJfA2NUq4+4AB9G/pLfCc4+SQsXShLlcOQ5jaipHgzMYL9jIH8
         UQ4pHFlMcF2hXBmVfbmyjjkz61Y1Gz0S1DcyKqybRj1jIpyCSGQTPwqKIDLRHx1j6cFV
         z/EMisMfWUjpfYTkk8V7urrGMTzRWhoZNC3hxUlbdI6L0QSmoVhwA6Tb1L1vOqOvG+Ga
         xtgwDKlLOXtxcQp+jL5+3G1NRHTVO35p2fVL+S/wzCvT8ZtTl8ZIPiEJ6XzlGpgctBG3
         M69g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531lYQt1QhOa8gvo8uGgqy077rtdLDuQPEfpw+Grv/5ZRE+pujI3
	jCJhuoW/ikAyqQzdA+8Riyo=
X-Google-Smtp-Source: ABdhPJxiZ+ZY2BgLSckZp3newemjBCkWsjopSpqN4sH+FqjHpPwYghGJzBOEG2C+f4QTuDjZ5b4vlg==
X-Received: by 2002:a17:906:16da:b0:6fe:988b:d242 with SMTP id t26-20020a17090616da00b006fe988bd242mr22361283ejd.606.1653389116493;
        Tue, 24 May 2022 03:45:16 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:3fc5:b0:6fe:fc5b:a579 with SMTP id
 k5-20020a1709063fc500b006fefc5ba579ls2199397ejj.10.gmail; Tue, 24 May 2022
 03:45:15 -0700 (PDT)
X-Received: by 2002:a17:907:6e05:b0:6fe:2f42:449e with SMTP id sd5-20020a1709076e0500b006fe2f42449emr2865948ejc.164.1653389115462;
        Tue, 24 May 2022 03:45:15 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1653389115; cv=none;
        d=google.com; s=arc-20160816;
        b=xOr3Ob+RkUeBGMUpFfdMUyA0Q4Ar+jjwtywh1+Qxyyq7fCC/VRyc7iHnXf2G2Ag07w
         /GEsY/Pib9Gl5Xfh0PI/CYt9M4E3AS0nRZBkaHo9l/kgbb1XENO6QATnYRE+ErDKJgnR
         tQivw66EA6KKqw8P7JrKDBjFCeQIFTbtHijgizIouIzc/0LBRT9/Ae3+lsxAa6XfWJFw
         2cEnD0SAlTkCrzQqPm+Lc+/yeOc5jOlhw3OLXma4YQTs4wO3ExkodiAgONzmET4BNZMP
         iDDtFisHtsBfLx/JI4Rho1MtORuYIhyScpnvn8rIVaPFRE8Ozh5ml4ZTD7umFswN43p4
         kWnQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:user-agent:content-transfer-encoding:references
         :in-reply-to:date:cc:to:from:subject:message-id:dkim-signature;
        bh=kt2sayrFs9fm5f2jDsLTGATuG5rlPL0q0HMqvl93aaY=;
        b=hA1HH7SZEm81IVreBV9tRRez/CvlNbRuUjmp3bG6TkYa0HEfSvpwDnZej0xiNsro2D
         TfWxOPmM/Pnjh0gMCr2SwcFpj/yt+KAUHlq7yyCiSLWV/4KsrLJr2Z3qbqQH2L8WhHj6
         ZIXwnHyaRRbtNr7SnVMWDZf/ZJMZFrvVJ2N5OX7Gk/DNZJm9kn3ZMx9dKLqZcFSIHYA8
         pVB/42fwRxZuSbBJuPdhEstje9DA/Sss1mYh4v1+dCCsF05bECs1JUOyk0TjykiKTlPv
         pzchbQ767NwVTl8F06qxguM8UANgh5XBlTYZB3K6aRywl5zeY7Xj0hw09y6WqJYteA0u
         rzwA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@sipsolutions.net header.s=mail header.b=gtlUhWaD;
       spf=pass (google.com: domain of johannes@sipsolutions.net designates 2a01:4f8:191:4433::2 as permitted sender) smtp.mailfrom=johannes@sipsolutions.net;
       dmarc=pass (p=NONE sp=REJECT dis=NONE) header.from=sipsolutions.net
Received: from sipsolutions.net (s3.sipsolutions.net. [2a01:4f8:191:4433::2])
        by gmr-mx.google.com with ESMTPS id hy3-20020a1709068a6300b006fefa121de4si150272ejc.1.2022.05.24.03.45.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 24 May 2022 03:45:15 -0700 (PDT)
Received-SPF: pass (google.com: domain of johannes@sipsolutions.net designates 2a01:4f8:191:4433::2 as permitted sender) client-ip=2a01:4f8:191:4433::2;
Received: by sipsolutions.net with esmtpsa (TLS1.3:ECDHE_X25519__RSA_PSS_RSAE_SHA256__AES_256_GCM:256)
	(Exim 4.95)
	(envelope-from <johannes@sipsolutions.net>)
	id 1ntS2D-003HQk-AK;
	Tue, 24 May 2022 12:45:05 +0200
Message-ID: <fce12845b59a49cc2994e55cfd88071f6890c138.camel@sipsolutions.net>
Subject: Re: [PATCH] UML: add support for KASAN under x86_64
From: Johannes Berg <johannes@sipsolutions.net>
To: Vincent Whitchurch <vincent.whitchurch@axis.com>
Cc: Patricia Alfonso <trishalfonso@google.com>, Jeff Dike
 <jdike@addtoit.com>,  Richard Weinberger <richard@nod.at>,
 anton.ivanov@cambridgegreys.com, Andrey Ryabinin <aryabinin@virtuozzo.com>,
 Dmitry Vyukov <dvyukov@google.com>, Brendan Higgins
 <brendanhiggins@google.com>, David Gow <davidgow@google.com>, kasan-dev
 <kasan-dev@googlegroups.com>, LKML <linux-kernel@vger.kernel.org>, 
 linux-um@lists.infradead.org
Date: Tue, 24 May 2022 12:45:03 +0200
In-Reply-To: <20220524103423.GA13239@axis.com>
References: <20200226004608.8128-1-trishalfonso@google.com>
	 <CAKFsvULd7w21T_nEn8QiofQGMovFBmi94dq2W_-DOjxf5oD-=w@mail.gmail.com>
	 <4b8c1696f658b4c6c393956734d580593b55c4c0.camel@sipsolutions.net>
	 <CAKFsvULGSQRx3hL8HgbYbEt_8GOorZj96CoMVhx6sw=xWEwSwA@mail.gmail.com>
	 <1fb57ec2a830deba664379f3e0f480e08e6dec2f.camel@sipsolutions.net>
	 <20220524103423.GA13239@axis.com>
Content-Type: text/plain; charset="UTF-8"
User-Agent: Evolution 3.44.1 (3.44.1-1.fc36)
MIME-Version: 1.0
X-malware-bazaar: not-scanned
X-Original-Sender: johannes@sipsolutions.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@sipsolutions.net header.s=mail header.b=gtlUhWaD;       spf=pass
 (google.com: domain of johannes@sipsolutions.net designates
 2a01:4f8:191:4433::2 as permitted sender) smtp.mailfrom=johannes@sipsolutions.net;
       dmarc=pass (p=NONE sp=REJECT dis=NONE) header.from=sipsolutions.net
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

Hi Vincent,

> Old thread, but I had a look at this the other day and I think I got it
> working.  Since the entire shadow area is mapped at init, we don't need
> to do any mappings later.

Nice!! I've always wanted to get back to this too.

> It works both with and without KASAN_VMALLOC.  KASAN_STACK works too
> after I disabled sanitization of the stacktrace code.  All kasan kunit
> tests pass and the test_kasan.ko module works too.

:-)

> The CONFIG_UML checks need to
> be replaced with something more appropriate (new config? __weak
> functions?) and the free functions should probably be hooked up to
> madvise(MADV_DONTNEED) so we discard unused pages in the shadow
> mapping.

I guess a new config would be most appropriate - that way code can be
compiled out accordingly. But I don't know who maintains the KASAN code,
I guess have to discuss with them.

> Note that there's a KASAN stack-out-of-bounds splat on startup when just
> booting UML.  That looks like a real (17-year-old) bug, I've posted a
> fix for that:
> 
>  https://lore.kernel.org/lkml/20220523140403.2361040-1-vincent.whitchurch@axis.com/

Hah, right, I was wondering how that came up suddenly now... Almost
suprised it's just a single bug so far :)

> --- a/mm/kasan/shadow.c
> +++ b/mm/kasan/shadow.c
> @@ -295,8 +295,14 @@ int kasan_populate_vmalloc(unsigned long addr, unsigned long size)
>  		return 0;
>  
>  	shadow_start = (unsigned long)kasan_mem_to_shadow((void *)addr);
> -	shadow_start = ALIGN_DOWN(shadow_start, PAGE_SIZE);
>  	shadow_end = (unsigned long)kasan_mem_to_shadow((void *)addr + size);
> +
> +	if (IS_ENABLED(CONFIG_UML)) {
> +		__memset(kasan_mem_to_shadow((void *)addr), KASAN_VMALLOC_INVALID, shadow_end - shadow_start);
> +		return 0;
> +	}
> 

If that were

	if (IS_ENABLED(CONFIG_KASAN_NO_SHADOW_ALLOC)) {
		...
	}

(or so) as discussed above, it might be a little more readable, but
otherwise it doesn't really seem all _that_ intrusive.

I'll give it a spin later.

johannes

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/fce12845b59a49cc2994e55cfd88071f6890c138.camel%40sipsolutions.net.
