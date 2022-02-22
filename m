Return-Path: <kasan-dev+bncBC7OBJGL2MHBBFHA2SIAMGQEVIYA63Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x438.google.com (mail-pf1-x438.google.com [IPv6:2607:f8b0:4864:20::438])
	by mail.lfdr.de (Postfix) with ESMTPS id 040084C019C
	for <lists+kasan-dev@lfdr.de>; Tue, 22 Feb 2022 19:48:54 +0100 (CET)
Received: by mail-pf1-x438.google.com with SMTP id g19-20020aa796b3000000b004e136dcec34sf7497629pfk.23
        for <lists+kasan-dev@lfdr.de>; Tue, 22 Feb 2022 10:48:53 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1645555732; cv=pass;
        d=google.com; s=arc-20160816;
        b=GeyDLFWOW8iwyPE/rFpVB2yE40XohkE0fn49VJk6rsK1OvIBtfGnWsUMHlAKgR7O3J
         gtrFDgrrFSK4RwmDyU1YsUX3+bP0FS5sPDgwer50FGINu2zINkc/fhQY6o/OYLiVUpiL
         iKv7zzaQwAw5IRvESjXZ1qPqQDXc6Ic77wdUMf2XLxi31wv4XOiqVpdD9cMLAX0q5gTp
         uC2Qq0yGGOTjmrEc1CpTuOvNJa5NKu5DQK0Knii7QELK4vyL3dbDn8whE9ZmFyZIYfaS
         AVRvdVKzbXKaNhqRxtjk9EKarSiuv0wIH/uaHueHYAf6vBYEuIcdBmZleB2KnxY3En6R
         uBqw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=6EsT3kt4XQTBsGcpiyke3NGWdsuqu0jPwj6kx0zDzsE=;
        b=ij8B3liNKRRKDidHciCFfUdYkbRebcpeWTDmUIkL04JTqlfNAsgrPKIpgdNixtWJxD
         hJsEy+iiXIqa/RTVDTl0O0X+Vrqc1A8LegBuiFGC78Yyxg6iqlXb3Gkprlytxq8qORIO
         pdHAyeQg0+g9jJkuHOWFjYDPgJwkQwNSBRkLrCMOQrGBV0nckN5mupsBm185i3uFyij9
         QkrtClRaqZZd2dt2H0tUPdu9rOKJTcIifCEEcalvvmKZiOU0dNuFzA20IKKzBJ8DGKbR
         40rlLu+cg4A4PSbFRRAsicz0XcRCeN4o/HTxTs0I9KCBT3yws03vpA+X5aGoKPfTHsOB
         o2Eg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=rXGJIwjZ;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b2c as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=6EsT3kt4XQTBsGcpiyke3NGWdsuqu0jPwj6kx0zDzsE=;
        b=GR8psgjtZRWTU8N23X9ouAcwwIMEOVV9HLgRXd2Xkg1A6SKdUu2SKNlB6rnRN+Kr6j
         D0778JAU6gRcvwZu1vLXDdej6lWtc2//N6aBTELvu2kzKLP1MothoTSMFccJPBn1RaIB
         AgJkcpJzccK5Ow28nmBdZR7BZSRpspSHKhcpjAS24aTpJvwQnZQhpcgZcsyMF7+07BFF
         hSqCaV7Rebp4Eehh+v2yASd4u6I+YXQSeZnZQxwb9FaaJSTUh9lrtGGtGLuGwwwXKzo5
         pL+YTF7OGlVlOerHUfaadhlfpM90lWaYcrDxi4GBoE8zdP1PZRdsIkxvVb1tbd2hQFUO
         0YZw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=6EsT3kt4XQTBsGcpiyke3NGWdsuqu0jPwj6kx0zDzsE=;
        b=Zd2LPd20eyObToicGjPLq2/UUjPYEZvIcSX5LNDNUsX1Dql6G0kVnt2uKZWA4ZS9n9
         0VDeRe2HvJenRp/9OwVDNhW9V9kO9QpAIYuVoP7lbmSpKFdmdWblbViS+p7BosYr3M/Q
         5NsBFdRMgza9q4JSQpyDAAaAJuOiuUQuel3ie4v98eViIYGzTs93jMUEjnSW7PtC+T4d
         TGKbye4KC/lWrEjHN9DcKioUh8LCEiQttm82Oj52oZ2cMDyo/PMlxAHUVKEYMA/ApE+J
         w2Bip+h+1sEe/G9ILbcXS2PIOcUae/V8rSvzkUZ02HYKhE422ZQJRgO+zDCKQdL+LwhG
         2jWg==
X-Gm-Message-State: AOAM533H1854CGqX/gRM/wlkKgLD4nhZ81mU7OGgNsMW9PZF6aQuu9F9
	PdVGEcZUz9OTXMeW8BATXFk=
X-Google-Smtp-Source: ABdhPJwzPwKXHSYnRVumTSSsEuWkWxuvkv4DAADCQhRkcoH8Qcsju/pXM0l3hYh3kEtjrjYKZmFs0A==
X-Received: by 2002:a63:de46:0:b0:364:cad7:bf3b with SMTP id y6-20020a63de46000000b00364cad7bf3bmr20780143pgi.491.1645555732640;
        Tue, 22 Feb 2022 10:48:52 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:139c:b0:4e1:5730:7011 with SMTP id
 t28-20020a056a00139c00b004e157307011ls7691962pfg.1.gmail; Tue, 22 Feb 2022
 10:48:52 -0800 (PST)
X-Received: by 2002:a63:5959:0:b0:35e:ae24:7935 with SMTP id j25-20020a635959000000b0035eae247935mr20555338pgm.120.1645555731933;
        Tue, 22 Feb 2022 10:48:51 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1645555731; cv=none;
        d=google.com; s=arc-20160816;
        b=uem/SbJAvafGdV3nVYfr966CgSJVNpnC8zyhAC1VVhyGvnBEHyY7+z4+EFbI1X6sUq
         c9AYy4mf0OV68l0BDnpfCK/iP5bpH4zcYeOeSzL7V0s5Tc7Jr9glkD4WP4nn8Jjbz8j6
         0m7rzLbMSZry5SmpAjkIHOADFUOk0aSglIgX19OSgpx+/xvT2T9B/wo8r+Pv1fGNogir
         j0EteaEmsWZ19vn0bZ9pwFNmFwtIQixyr0mDgIMwX1/e5TG0hyTBl3fgBW9Mo/YWEqGb
         yfZJE9Saqe6tHjxhhUaY3gwlZjJiX6vnaBgcIxGgy+tr5jMXUHJyGs0dnCkh/SaEPUOB
         wlgA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=GEvSCVwL/A3X3tCkaLLRRca+X+c7l6RWUROLPaM/Tx8=;
        b=CKDyeEx0OdwoJFeThrTJ3QlrU5gqaD7oeQj93JnJgnDyb3e1nWph+i6Pu+YT6Cw+GX
         bHmiaCLCndhPPsSIUcilTuTX8mpUv2JHyL69smzGGimt0menmzAZQOqyyOawMF9ZLU6b
         PUsmXyAx6ctV7m1cFgYISjh+82y4fy2VoofnZU14OmeFIe6p88LDH7j6R24JyEzzVG0D
         f/9OpT4b7assSqBoV6Flw4hypUD3qoyeEOk/5IW+q5newSptPtMTsPE6WMwwJkS+AYao
         5LsKI97DV5m3Jk2xpgINgxagkf/vgI+6fYtAJsovjvm3UAAYl5Qc1eckq4NV2CnDXaGY
         juuQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=rXGJIwjZ;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b2c as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb2c.google.com (mail-yb1-xb2c.google.com. [2607:f8b0:4864:20::b2c])
        by gmr-mx.google.com with ESMTPS id c21si909031pfd.6.2022.02.22.10.48.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 22 Feb 2022 10:48:51 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b2c as permitted sender) client-ip=2607:f8b0:4864:20::b2c;
Received: by mail-yb1-xb2c.google.com with SMTP id j2so43333390ybu.0
        for <kasan-dev@googlegroups.com>; Tue, 22 Feb 2022 10:48:51 -0800 (PST)
X-Received: by 2002:a25:3542:0:b0:622:caf1:2c88 with SMTP id
 c63-20020a253542000000b00622caf12c88mr20154405yba.625.1645555731413; Tue, 22
 Feb 2022 10:48:51 -0800 (PST)
MIME-Version: 1.0
References: <019ac41602e0c4a7dfe96dc8158a95097c2b2ebd.1645554036.git.andreyknvl@google.com>
In-Reply-To: <019ac41602e0c4a7dfe96dc8158a95097c2b2ebd.1645554036.git.andreyknvl@google.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 22 Feb 2022 19:48:40 +0100
Message-ID: <CANpmjNNhvxEnjkq_s9DRyFd-r0hDnxGST6ommX3anTY+fBcLaA@mail.gmail.com>
Subject: Re: [PATCH mm v2] another fix for "kasan: improve vmalloc tests"
To: andrey.konovalov@linux.dev
Cc: Andrew Morton <akpm@linux-foundation.org>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>, 
	kernel test robot <lkp@intel.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=rXGJIwjZ;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b2c as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
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

On Tue, 22 Feb 2022 at 19:26, <andrey.konovalov@linux.dev> wrote:
>
> From: Andrey Konovalov <andreyknvl@google.com>
>
> set_memory_rw/ro() are not exported to be used in modules and thus
> cannot be used in KUnit-compatible KASAN tests.
>
> Do the checks that rely on these functions only when the tests are
> built-in.
>
> Reported-by: kernel test robot <lkp@intel.com>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

Looks reasonable, thanks.

Reviewed-by: Marco Elver <elver@google.com>


> ---
>
> Changes v1->v2:
> - Hide checks under #if instead of dropping.
> ---
>  lib/test_kasan.c | 2 ++
>  1 file changed, 2 insertions(+)
>
> diff --git a/lib/test_kasan.c b/lib/test_kasan.c
> index ef99d81fe8b3..c4b7eb2bad77 100644
> --- a/lib/test_kasan.c
> +++ b/lib/test_kasan.c
> @@ -1083,11 +1083,13 @@ static void vmalloc_helpers_tags(struct kunit *test)
>         KUNIT_ASSERT_TRUE(test, is_vmalloc_addr(ptr));
>         KUNIT_ASSERT_NOT_ERR_OR_NULL(test, vmalloc_to_page(ptr));
>
> +#if !IS_MODULE(CONFIG_KASAN_KUNIT_TEST)
>         /* Make sure vmalloc'ed memory permissions can be changed. */
>         rv = set_memory_ro((unsigned long)ptr, 1);
>         KUNIT_ASSERT_GE(test, rv, 0);
>         rv = set_memory_rw((unsigned long)ptr, 1);
>         KUNIT_ASSERT_GE(test, rv, 0);
> +#endif
>
>         vfree(ptr);
>  }
> --
> 2.25.1
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNhvxEnjkq_s9DRyFd-r0hDnxGST6ommX3anTY%2BfBcLaA%40mail.gmail.com.
