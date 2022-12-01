Return-Path: <kasan-dev+bncBCF5XGNWYQBRBEFXUOOAMGQE4QICKDA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc40.google.com (mail-oo1-xc40.google.com [IPv6:2607:f8b0:4864:20::c40])
	by mail.lfdr.de (Postfix) with ESMTPS id 5EDF963F5AE
	for <lists+kasan-dev@lfdr.de>; Thu,  1 Dec 2022 17:51:30 +0100 (CET)
Received: by mail-oo1-xc40.google.com with SMTP id j30-20020a4ad2de000000b004a0831640e6sf681664oos.20
        for <lists+kasan-dev@lfdr.de>; Thu, 01 Dec 2022 08:51:30 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1669913489; cv=pass;
        d=google.com; s=arc-20160816;
        b=OU0zBhDzIQBFyXekO0uMf58GrN9kkqa7hPMxZCdodO/QBK1eUFKegHH/rAo8wrgDQ3
         0bQhfEepxj71WB+0Pn9ieNJtw+V+ZpkpKSkWPvLpHmdQK6/8k0D6KpoO21XHn3CcPFWP
         TIyBauq9KjCF0dA0q0dnJraKZ39n1bNob7Tt4tC/SBxq/SbI6MLJTx1/KpOM7aEI0LC+
         3X2mUghhsiRhdyfc3l13XjfMI8xHZw48nHGynEKdqfSshxSnluPg7j37casqzfM6+zoA
         Bbg+nS6eJkovWvAOGa4WHwFYqepHUSnhcrwjKYHOWOyNhAX5JFy4zOcg+GUTEvPdfNLs
         P9TQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=C08gyqNxseUc9C0G5e2bt2U4QGCBemK/iY4gpD8EcXk=;
        b=aquYQqrtRv27VuqanvnkARA+RO5BWzy0RqZuPJB0o5fKpcuJyUY7TVimvW0uytvGhA
         vszAYvlnCYEExi4lmWvSu7X4rn5fyNmrrMxBBk0pb29gjEsB0Q0Eb8SKyfAGF73hnOGP
         S7ZobC47iX1GsqJsgixZf3z5qxj5pubh77STfCPyk8z5hhNf3jEG8FsbpJ5jKEsPCXQj
         gNimwAlHhmJk4FA2p5YIpWNgxnbrbrOXfUUc+BEHfmFOFHEEQ4LoWVTU0Nx4fkegf1nJ
         uB+6Lkctq62ELPAf+5ju+1+xsYJztk6bHm7xkoHGQ9e5CnVAxa0AURxRc1EVEdx3NqzZ
         drDw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=DwwmIVJC;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::535 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=C08gyqNxseUc9C0G5e2bt2U4QGCBemK/iY4gpD8EcXk=;
        b=aPUhaKYBFT7SZNo1OkJwl6B++AeCmbk+DgW07ZhOSvH2XZtXDSyWLaHs242PCH02T0
         P0CU+jssWGVVyi+rLfqoObGpjbZC1Zl2OaT9GAKbQ0B21hsogAoZKI6Es3hV6DGABOm/
         8P8K9dQG0ljKVZVfe3Lyv6ch+cJ3tA0hqDhbqO2FGJpnSCB69txzGqwUcsjbxI/MyADu
         0Ez7ZSZaIzb2qaxXXKsxxUP8BwRXSzaamGL5yaRaph+fPnViDp8PBLXpNXY6zCfgh/dg
         n7pqfF8/QilkW/wBKcljUhhMXCb3zeXdN3P32C28GXbFsyLkDkq+u1pQQHBMC+B+m6/C
         W99Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=C08gyqNxseUc9C0G5e2bt2U4QGCBemK/iY4gpD8EcXk=;
        b=eSGfCpRqNEaZ6rlvFeKRiNXLWj9SPwXIYibsMrhJhOY5gAknKFZvWr2j3+VLVOMiH4
         h7oY5FV0IZHRY7AkZ987OzSuRuGyXhKvMZueLFtzBhXJX8z8dPLBZWY3CxV3X85ikE9m
         k0YNmUA86WsasLQmRPT9+u5UgbDiLV1gzdlDcf/HHZnA9AP/5+nay6pt6gc/SapDg9Lr
         +3MejDNVT0e/1BG3RlXQ4M7d1c967/RIM+VxnpjsIW8lZ15pVanRautKbIBh7/3kzouj
         1xV29OZ2lI25oLybuiP8MCicY9nY9AkDC6nBXlwU+0rA/mJEn9Hpjf2KNHcyd9cWq3W2
         GuOw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANoB5pnDz4w6c7Vw3vEJaz6PPnERYcqKHHmnGvo3UyjhcIgiitwXBPSF
	Eb0RzL8g8CeY07HXx9w367E=
X-Google-Smtp-Source: AA0mqf6+W92mjeNkqcdfadMcxhdNB0UwMnOXEpEdnmhvxXBD5GKgoL6sZjQ8v+jy+F6NGlHu9SbzCQ==
X-Received: by 2002:a05:6870:be98:b0:144:1e17:9a4d with SMTP id nx24-20020a056870be9800b001441e179a4dmr2355216oab.91.1669913489079;
        Thu, 01 Dec 2022 08:51:29 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:c7ab:b0:143:86b4:f098 with SMTP id
 dy43-20020a056870c7ab00b0014386b4f098ls972283oab.11.-pod-prod-gmail; Thu, 01
 Dec 2022 08:51:28 -0800 (PST)
X-Received: by 2002:a05:6871:4182:b0:13c:b04b:9b14 with SMTP id lc2-20020a056871418200b0013cb04b9b14mr40925282oab.25.1669913488638;
        Thu, 01 Dec 2022 08:51:28 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1669913488; cv=none;
        d=google.com; s=arc-20160816;
        b=GWl70mWmUuy/tqJLkWtjkuORJJR/MSDWvogN9r5qRi2rObtjcB7qzCg0eX6x100K7e
         Mzfy7quXhbqrT+z5tDp8/4y0RyV7vfSu+LhwZ6Z+0YZzHGmnciP05bxtgkOWzZkKEhi9
         OfWLPvrTMiGIVyOOjc0p86ufTi72Cvu7U1YkF3B34paG2OF56G7LyC337TvNcixzS5vr
         P29GVAuW0OvYvoKLDdEOtKxjql/8j4idm3QRe/LLtWqqRQmfpmsxiO2s5yYfv3VITp/M
         k8Ev9p/rLFhqdpNshse4MiYFZSGwwWvw179fvkwjTMPRX5dnQgZNDXo9D6jelV3EfCns
         fjKg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=frCt6pKGWIhEPpxLesPSV/Mh3cTSx4zBWHAWHmqSudQ=;
        b=zSflW/K+j24TawzRGdecubU+Hb5nhUtkFJ4im0DWo4VrLSiR2ZHa77zP5nManmCsJi
         XrbfnqRWfyz2m8yJIqNSyV2j2k40mg+nGAyVjOz48JKxFrSnzZB55LjB/tAmUWCuWoei
         lCLe8jZol/RkEYTZsWkXEujAZUZPZN4hNf7IRZQzMxdhxImkbAX/I+C9p9/jrnznBpmI
         S8PTkr63HQH7tJXvcVwFV2i4Vn4SdoxX8Fn0L7PIaLkT9WREd0CJKEBx6HoH8Ci6WUTg
         rQoprFuedsFVwcDt54YCSK+XndOTSPRJgVwNwPDgoJHsl3dm/VPrcv5KwSQNNUvsW/XZ
         ezfQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=DwwmIVJC;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::535 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-pg1-x535.google.com (mail-pg1-x535.google.com. [2607:f8b0:4864:20::535])
        by gmr-mx.google.com with ESMTPS id g23-20020a544f97000000b00359a21e3ffesi333149oiy.2.2022.12.01.08.51.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 01 Dec 2022 08:51:28 -0800 (PST)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::535 as permitted sender) client-ip=2607:f8b0:4864:20::535;
Received: by mail-pg1-x535.google.com with SMTP id f3so2167514pgc.2
        for <kasan-dev@googlegroups.com>; Thu, 01 Dec 2022 08:51:28 -0800 (PST)
X-Received: by 2002:a63:5262:0:b0:477:6e5d:4e44 with SMTP id s34-20020a635262000000b004776e5d4e44mr44707636pgl.7.1669913487993;
        Thu, 01 Dec 2022 08:51:27 -0800 (PST)
Received: from www.outflux.net (smtp.outflux.net. [198.145.64.163])
        by smtp.gmail.com with ESMTPSA id 13-20020a170902c24d00b001745662d568sm3844626plg.278.2022.12.01.08.51.27
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 01 Dec 2022 08:51:27 -0800 (PST)
Date: Thu, 1 Dec 2022 08:51:26 -0800
From: Kees Cook <keescook@chromium.org>
To: Andrey Konovalov <andreyknvl@gmail.com>
Cc: Christoph Lameter <cl@linux.com>, Pekka Enberg <penberg@kernel.org>,
	David Rientjes <rientjes@google.com>,
	Joonsoo Kim <iamjoonsoo.kim@lge.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Roman Gushchin <roman.gushchin@linux.dev>,
	Hyeonggon Yoo <42.hyeyoo@gmail.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>, linux-mm@kvack.org,
	kasan-dev@googlegroups.com, Vlastimil Babka <vbabka@suse.cz>,
	linux-kernel@vger.kernel.org, linux-hardening@vger.kernel.org
Subject: Re: [PATCH v2] mm: Make ksize() a reporting-only function
Message-ID: <202212010851.33009FA7@keescook>
References: <20221118035656.gonna.698-kees@kernel.org>
 <CA+fCnZfVZLLmipRBBMn1ju=U6wZL+zqf7S2jpUURPJmH3vPLNw@mail.gmail.com>
 <202211261654.5F276B51B@keescook>
 <CA+fCnZeb_Q==L9V2Cc2JbOfh11ZH+V0FC5C_q0Rs1NQYm74dUg@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CA+fCnZeb_Q==L9V2Cc2JbOfh11ZH+V0FC5C_q0Rs1NQYm74dUg@mail.gmail.com>
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=DwwmIVJC;       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::535
 as permitted sender) smtp.mailfrom=keescook@chromium.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=chromium.org
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

On Wed, Nov 30, 2022 at 03:11:35PM +0100, Andrey Konovalov wrote:
> On Sun, Nov 27, 2022 at 1:55 AM Kees Cook <keescook@chromium.org> wrote:
> >
> > > I just realized there's an issue here with the tag-based modes, as
> > > they align the unpoisoned area to 16 bytes.
> > >
> > > One solution would be to change the allocation size to 128 -
> > > KASAN_GRANULE_SIZE - 5, the same way kmalloc_oob_right test does it,
> > > so that the last 16-byte granule won't get unpoisoned for the
> > > tag-based modes. And then check that the ptr[size] access fails only
> > > for the Generic mode.
> >
> > Ah! Good point. Are you able to send a patch? I suspect you know exactly
> > what to change; it might take me a bit longer to double-check all of
> > those details.
> 
> Let's do it like this:
> 
> size_t size = 128 - KASAN_GRANULE_SIZE - 5, real_size.
> 
> ...
> 
> /* These must trigger a KASAN report. */
> if (IS_ENABLED(CONFIG_KASAN_GENERIC))
>     KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr)[size]);
> KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr)[size + 5]);
> KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr)[real_size - 1]);

Done, and tested! Thanks :)

-- 
Kees Cook

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/202212010851.33009FA7%40keescook.
