Return-Path: <kasan-dev+bncBDW2JDUY5AORBI6JTWOAMGQEXJURTJI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63b.google.com (mail-pl1-x63b.google.com [IPv6:2607:f8b0:4864:20::63b])
	by mail.lfdr.de (Postfix) with ESMTPS id 1141F63D7D5
	for <lists+kasan-dev@lfdr.de>; Wed, 30 Nov 2022 15:11:49 +0100 (CET)
Received: by mail-pl1-x63b.google.com with SMTP id l7-20020a170902f68700b001890d921b36sf17492605plg.2
        for <lists+kasan-dev@lfdr.de>; Wed, 30 Nov 2022 06:11:48 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1669817507; cv=pass;
        d=google.com; s=arc-20160816;
        b=hsG1AHlOKfjrU35TV8sUb+pF/QtDZ11LSWdw+Yy9L92E9vDAwkr/n8SbrbasEdRtLB
         fsUa39f7hPSJfF+irBpeYpwaC+pRcBFPvxNuIyl0a/90+j3GkQ0XpeKoRKgENt4mmXQF
         jka/E3p50beEN6RL1ra3z7rzoMFUGCaxFYLaPu5FWVDwiSNEJRGFawugrJOGZR3W8XJY
         XVprev8S7eeTwJSAuZDsBe7aLfKQXL7xcB3YQ3PG4c7wEiIzaeckjAPB7oR/RvF9y0AX
         A8DTvZWd5M/6wYsY+4k0nqoTGd/eVY7bscadFPAQ+vjWHJ9Dp9ajkmy2Rwk0FVBcSmGg
         aciQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=jyVkemv6EP/NJjBxwf/iecZsoYtWTZTKictD1oVh3zc=;
        b=MLSNAqPZwzdCEOBLTDYP2FoKAyYUS3TOUuq4Zw0oJtB7+8RaAvBz9clOeO/nXNXVgC
         AY5VzBeqCYod9J9srChGpg1FpJKXYPZ01vs/lvICLYkEg9EXvOATB86tCE9MsAjDG6wK
         p+Q2+iiZbj6TymXrHvy/YFIVPfJk0SVHDPhCFZP6WKwA5TmMmfQq6fK7iREXya8tHi0T
         VQGLpWHvP7Sswp82FEn6Bs0qPu94C500HqC2M/sMit39ZRhncmE0I2otBPKgdQnZxcgU
         TDgp59EduZO9ho2hbm1kiXqdShuLqLcUk8f4pS66fLGsspnPfvYeItkQ9RxwS/hO986/
         ldoQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=XKwVdAfO;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::531 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=jyVkemv6EP/NJjBxwf/iecZsoYtWTZTKictD1oVh3zc=;
        b=n/QbQBc1VVk7o3tEtzZRDd9X4OPYiN30JI/XwzOiSevpmoGNitYvcVvt5lu5N2Py7G
         Fi8oyKtxBim3M2JRWhmAYxK6JtTab3/cOBdsLtR4qdWlLoLwcSANw1vp9xcM4cMv4tnl
         WaEcGQ7hdFRlKqVgcASDsKHvriBuHlkmw464vdmmMErXaY4TtS8yfoBBPqMsz7B4fw2E
         TqZISHekH/P6dzPmxlbaah0/FFxaZR0+eIaP8nvqSEa3+9gJoxFBuOSfjm4EMR7+noHO
         bbiDoBkYINGq+S/LL19jQAFy5dfpv5DK8KXx3VFiGB0uax3AkzcT/sShcI7/UW7Bd2rT
         qT9g==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:from:to:cc:subject:date:message-id:reply-to;
        bh=jyVkemv6EP/NJjBxwf/iecZsoYtWTZTKictD1oVh3zc=;
        b=WjMrZsGjMT5rEegKhwvOBK+KeROd3KtLDTIkvz2+EAgF663Zg9nUMyhW51GTpXEGxZ
         vR9n17DihD1+92lHpOh5sb+qDER9OdgYsBYJqmJ/Vr74mtoXoAweeIUmVMAah+/UeKlo
         dpnV7OqnahGuYZZm2+ZN2japS2O6iXAVUsQyPBpPYJ+sSbNvWPo7zBsI2OTmHZHvDz4j
         4np6+c6EG9cBw1wrig6351lv60fgQKQq9kV068TQTzRsPqtlQ5zkXW7IJeSgShkbtHpA
         Fcwq7MC729elTjtzO42/JffpHOzDIbKkYWbtJ494Ye/R8Axw1YngnwqEQWpuBpFqI7gD
         aITA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=jyVkemv6EP/NJjBxwf/iecZsoYtWTZTKictD1oVh3zc=;
        b=MrWwTdM6K/S24wKqvl4p2u0m797C4v1XaLIQiczN/2sWB/YfhQf+yQK8ErPD2XExRb
         MP2s5CG27k5CcV1PKajQGAyFEdVrxEIRfK/9bum6OpsXxcZD6JUFwOUvanwFxysWhORZ
         tBcalQxhyf7un8v5LRS/KloQMGtN0W+CTB8bu+1FrPzFS4najNTwPvZ4aZCeJuVoVNwa
         VivhxOpq3AQALg1m+V8YlDPENf2bAxSDQnrfY+6Dm9L0MvCnqF1iThL1MtbEDkbKjiv1
         uaBP8gRXvp6+qN13XjUKGckHYgsg/vh2hEGulyl3T6ckfaKs05bVZowtupRE5nTdsVwz
         GU3w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANoB5pmhysqryLdqHT8SVjDT1/RM7EwpPTemj+hzgHF4Y0SBGQ8piwqo
	4+rtffd+AvfYNmlABI8Z1Kc=
X-Google-Smtp-Source: AA0mqf5QcPZwVz2cCb97jbVG4DMzAS2Bp02dcqyWMatGTMBVJhk3W0PxkE52TYFtZ/SKTtq6YrusYg==
X-Received: by 2002:a17:902:ab8d:b0:187:1e83:2505 with SMTP id f13-20020a170902ab8d00b001871e832505mr46897004plr.132.1669817507277;
        Wed, 30 Nov 2022 06:11:47 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:1d99:b0:56c:78e9:352e with SMTP id
 z25-20020a056a001d9900b0056c78e9352els8790707pfw.7.-pod-prod-gmail; Wed, 30
 Nov 2022 06:11:46 -0800 (PST)
X-Received: by 2002:a63:465f:0:b0:477:c889:cb33 with SMTP id v31-20020a63465f000000b00477c889cb33mr29095687pgk.12.1669817506520;
        Wed, 30 Nov 2022 06:11:46 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1669817506; cv=none;
        d=google.com; s=arc-20160816;
        b=zC7olbBvphJ/4FngmAvODgYEnT0GG4yPu36EflQ2xxQrwt1QknctTjilUuOKpDQgDh
         ME9OLre0lyWtT2mYBUXyHCYdUuDARnU0sspY7bo62TUsJia250pvknG4x01dxoBCwSbV
         9nLSNCFIXiJV0/olqmkGJg+EoecIcbQ5+O+iY1PboqcqWMuY777KFtw/yewxZGlbMV+a
         IYDxYLyDxkDvGfS7KIdSVWNkFNfh1pbUjd18HIiW3F9uS10BKmiPR8r/M7/K+d1FlzCo
         X01tKNnTkZYhq7JDCQyaFwWamNODmKdRhGj2Co43+FuBrno8LujaV4o6cqL5BXEW0jQn
         VRCg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=8cVvNyKtufNa8rAjSWHiN1tGPoWILfr7xg86SXOtMxo=;
        b=MLs4kaq6wcbMb0I/1fIkRT645iy83hw653kkV7lQ6vLrNBelAhfDdYcQx7hzxLeA1q
         k7FXjOB8ykxz9eNjZ8cQPJVQMb9JOqPoGWUcjpFwS6QT+Q1YYJZlg+k1Tgh0uJsJIomT
         gQChPGvhh2vjRUR5O1XQ03lTofWdX7Ne++8OVG4ezFkHroy1vm+0KHfek2wNsyq6iUIQ
         bH2c7t+sdwC3Xa0bgJRkMO+jNIklXrfIqqZxRAC/iursWPyuqX/WWe99Ac38qu8qSk2G
         B1ORKAvwBfU83Gi2ZEvRRC16JF3TK+5LoE678ilSvNg5l60WTOwT7w1PucQRmS95e+5y
         Dg1w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=XKwVdAfO;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::531 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pg1-x531.google.com (mail-pg1-x531.google.com. [2607:f8b0:4864:20::531])
        by gmr-mx.google.com with ESMTPS id oj18-20020a17090b4d9200b0020d43c5c99csi82582pjb.0.2022.11.30.06.11.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 30 Nov 2022 06:11:46 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::531 as permitted sender) client-ip=2607:f8b0:4864:20::531;
Received: by mail-pg1-x531.google.com with SMTP id f9so16146764pgf.7
        for <kasan-dev@googlegroups.com>; Wed, 30 Nov 2022 06:11:46 -0800 (PST)
X-Received: by 2002:a62:2702:0:b0:572:8766:598b with SMTP id
 n2-20020a622702000000b005728766598bmr42059861pfn.21.1669817506180; Wed, 30
 Nov 2022 06:11:46 -0800 (PST)
MIME-Version: 1.0
References: <20221118035656.gonna.698-kees@kernel.org> <CA+fCnZfVZLLmipRBBMn1ju=U6wZL+zqf7S2jpUURPJmH3vPLNw@mail.gmail.com>
 <202211261654.5F276B51B@keescook>
In-Reply-To: <202211261654.5F276B51B@keescook>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Wed, 30 Nov 2022 15:11:35 +0100
Message-ID: <CA+fCnZeb_Q==L9V2Cc2JbOfh11ZH+V0FC5C_q0Rs1NQYm74dUg@mail.gmail.com>
Subject: Re: [PATCH v2] mm: Make ksize() a reporting-only function
To: Kees Cook <keescook@chromium.org>
Cc: Christoph Lameter <cl@linux.com>, Pekka Enberg <penberg@kernel.org>, 
	David Rientjes <rientjes@google.com>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Roman Gushchin <roman.gushchin@linux.dev>, 
	Hyeonggon Yoo <42.hyeyoo@gmail.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, linux-mm@kvack.org, kasan-dev@googlegroups.com, 
	Vlastimil Babka <vbabka@suse.cz>, linux-kernel@vger.kernel.org, 
	linux-hardening@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=XKwVdAfO;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::531
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

On Sun, Nov 27, 2022 at 1:55 AM Kees Cook <keescook@chromium.org> wrote:
>
> > I just realized there's an issue here with the tag-based modes, as
> > they align the unpoisoned area to 16 bytes.
> >
> > One solution would be to change the allocation size to 128 -
> > KASAN_GRANULE_SIZE - 5, the same way kmalloc_oob_right test does it,
> > so that the last 16-byte granule won't get unpoisoned for the
> > tag-based modes. And then check that the ptr[size] access fails only
> > for the Generic mode.
>
> Ah! Good point. Are you able to send a patch? I suspect you know exactly
> what to change; it might take me a bit longer to double-check all of
> those details.

Let's do it like this:

size_t size = 128 - KASAN_GRANULE_SIZE - 5, real_size.

...

/* These must trigger a KASAN report. */
if (IS_ENABLED(CONFIG_KASAN_GENERIC))
    KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr)[size]);
KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr)[size + 5]);
KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr)[real_size - 1]);

Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZeb_Q%3D%3DL9V2Cc2JbOfh11ZH%2BV0FC5C_q0Rs1NQYm74dUg%40mail.gmail.com.
