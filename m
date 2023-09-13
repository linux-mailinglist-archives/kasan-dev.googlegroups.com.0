Return-Path: <kasan-dev+bncBDW2JDUY5AORBCOZQ6UAMGQEMBPJBWI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x837.google.com (mail-qt1-x837.google.com [IPv6:2607:f8b0:4864:20::837])
	by mail.lfdr.de (Postfix) with ESMTPS id 5653279EFDC
	for <lists+kasan-dev@lfdr.de>; Wed, 13 Sep 2023 19:08:26 +0200 (CEST)
Received: by mail-qt1-x837.google.com with SMTP id d75a77b69052e-4121afec295sf25381cf.0
        for <lists+kasan-dev@lfdr.de>; Wed, 13 Sep 2023 10:08:26 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1694624905; cv=pass;
        d=google.com; s=arc-20160816;
        b=hxAe931SWylJWUIHDakWBvQgsmAjnaPuDCVRLmH7SdhhbIkOffOQtsQ6fpY2F9zSRV
         8Ihw9Ge1v/8E3DVKDs8TNAyCAEi7EW5hYWIotX5TrLPQrqZV84AL/aPzAFYa4WT7XIEb
         EaQgynoFafhiee2PQ4YFe7foaoZBi+rfJsEf+yf5qlD9p99NW0rYx5cY3dEdSnFK/W4G
         RUoGSahGhJO0WQ/bs0s1sU/NhcIhTuTK7yjv/6FhbmEQMjbpHQY6rX/j17WpUm/oc4ns
         lOlenytqlGaI8mN31hdjc/HsWdDRUMSP+6SUxvNkaTJGG64i+T/DA/JrfrYAl8uRSL2o
         XSEA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=1m27sMNVl8JTitzChtAZSlS5Ls2dTfD3TFd6nY23yVU=;
        fh=vhyMgzwtVf8Cd+Xluz+kIPeaZIksHpPCItLJmpWVnQM=;
        b=FXhMt5ZpD4nPQS1U2CicPDJiUR+H29Ce4uUqxpREZ4EmLEOWtfuH7T45vDLfTOaOXx
         LfI2KaJf/tW50TUx1gNmZCMZ/DBV6P1BlBTzF9D6mCHRbU0BARgDVfXfymxaPahbEJ68
         AN0BExTCx0moAcv8W3ez5PfDL9/cswqFY48WrPxnc3T7yqW7BpSXI+NaYdRoNAEwOHr8
         Yi+RO/OdZAXyrxv+pcu4wjTQSZ7Wtf1cI5czEm6IEynqhJllPfjiI/kat0IZ7fkEns+d
         9xM6oKMEjy7rHPM2FpBbFZnNhVZIaX3hu5rwDQTGULtJNTh6EBupmLWLC2z1onGFCyHt
         ykPA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20221208 header.b=kT0Zly3L;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::1034 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1694624905; x=1695229705; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=1m27sMNVl8JTitzChtAZSlS5Ls2dTfD3TFd6nY23yVU=;
        b=qzkYrwjyXdMAg0XUSKknaQIPQkC8AW4LJ/3LA3ldarRzRc+nfdfbUYHd76AYVhLzFO
         QXVlcnUlP/AdXEZ0LFOjq48IyJVKDAV3tCjfCFGZ1P5KIKlF7+jEhaIFBftDGZ+47TTS
         yvNfP1M4Uoj/JpOcsJsJ8HYPM1TAGvwdLG+5Ucb/iihz9U8B7NPOS2jIFIAfVW4i0x06
         OMkYaYpA1+zF+CCcZ9ydV5w7mkxQ2Sts+Al/0++5GTRmB2gPur3hvtS3glB86racLDCA
         OUOwXlSUemYWpM06tH7ZIiTEAwl8HFdaliiccG2u8TYw45LIhOL9Uq8n6DJmgkDjwtv4
         SHhw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20221208; t=1694624905; x=1695229705; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=1m27sMNVl8JTitzChtAZSlS5Ls2dTfD3TFd6nY23yVU=;
        b=aDD3AnQXqYxpRyiLj4rGan0mnc1knnM0wNuyi5gPcTJYxEGTBzfQGDstnODoqOAU3z
         ES4+xhEWWZS26KDqYJxSCkIL2y6CgW3DMispmeuKDdY8mfwoWFlEIciH6T1S0epfEdMR
         HyCsziU/xHlTV/s+Pq6VHs6kp6JeDxGI/qefPKBz6afZEvMqY0dlfqWp3zzxFByUI8pD
         quLg4DSF1BeSCCRO+S+fiyH8Yug2ftyQhHWKY9XMFjpaIPf9J5TNs3E36Qs8B8AQfcjc
         WNxZhd6GQQUt8BLYnjkZaqdbU3FlehcWRN17qKtlQRbWuyDLyE1tMAmCUKvn94bLRLLj
         rRRA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1694624905; x=1695229705;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=1m27sMNVl8JTitzChtAZSlS5Ls2dTfD3TFd6nY23yVU=;
        b=Q78dzuLZ4BAqCa0IvFboohYNy1OcbpUNV4eVP46xiDmCvp0y1uTmqXrzDZCEilIBoX
         UxTe6FYdc8zLlU+Gvzq6cn5ZrzvGQKg1Zl+ggch79R1CockitpLSwrCAzxaZAyP6Fkbh
         mHWJ8J83JbrV6aHJNhrdhJam5JnWlOBEgqmCDEr9JkJKiAt+pUyOd3e1sLn00r1lAzM7
         PbsR8ERl4BoMnRnw3w5zYwYrRnD7YPrlH1BcBampNxnV6L97ey+aQZFjjv3eFN3vSPxK
         oTKY0YnflZGc9pgbv45KZu+4iPHPZqVmLAAsZTQGgWfAu+HLISWyL2ADVmz8pQyM4pbR
         fMhw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YyC4Wfxxm8rySjJJV4EmxT7PTNXs9p5AwljbgR07BLfGhVNVwmS
	eJpDmwd4FuBnykcsAur+lBU=
X-Google-Smtp-Source: AGHT+IHOMcBxT/Fv4vFSUp/CtAPqW95bhTPGIozJRS8NeEMnN7JG5kx601mfOThXM23X2HPl8CQGdQ==
X-Received: by 2002:a05:622a:15ca:b0:40f:c60d:1c79 with SMTP id d10-20020a05622a15ca00b0040fc60d1c79mr343536qty.28.1694624905264;
        Wed, 13 Sep 2023 10:08:25 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:ac27:b0:1bb:7823:8b04 with SMTP id
 kw39-20020a056870ac2700b001bb78238b04ls2068975oab.2.-pod-prod-02-us; Wed, 13
 Sep 2023 10:08:24 -0700 (PDT)
X-Received: by 2002:a05:6808:1598:b0:3a7:62ad:af39 with SMTP id t24-20020a056808159800b003a762adaf39mr3933856oiw.13.1694624904642;
        Wed, 13 Sep 2023 10:08:24 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1694624904; cv=none;
        d=google.com; s=arc-20160816;
        b=O+hKdhIm3R3bPzJ38VY5VQp/6xZEApvK0ZvRVsHPCOx+gzS2SB5G/GzA1OapeFt3V3
         cxlhkv6S2TGEjSxYa5UTwL8/tDjkmMFwKy/xc2UBQCunQohcXSMAB5XUSXMf1gQ44sjy
         qVhLmPA1yBguhU2ficqJR+FscBJRbPgWszQJzC3ynLOQ/3LzyoqeZ/PaVG5i1KTkWFex
         CVKXe2C6i0HWVaU/Pkbvoz0iTRJgvqHIHKNcbt33O4wXC6k4ZN9YVt4aKMWiX2VbOMeX
         nXHnG907rUpbRPWVhXBb6EC+bNoskl2UArXj83ZYcl3Md7MuuTQmlftTldvn+N1sz+VH
         a42w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=0ihId+82HD26SjvNufvLy8at2aoRO48c9rDf8oEccLw=;
        fh=vhyMgzwtVf8Cd+Xluz+kIPeaZIksHpPCItLJmpWVnQM=;
        b=IT5Lx1c7NXXmhQE33SBwaseY0nzPz7rhaUHreYLK0glEGn4dqjuotLbS/7BAAC1SYI
         4lXY1Ar+0SE4BDxV7SLOM//YcUMUb9dkkkI+HSWJoNz/fpGM4dVrWv/9JRwTq8CVeFXh
         GJ4AI6HXg3I3M3u8CqP6y4er6puzYI8UKd2uUL5xn/YydEGUhW2POqQLjtZ6cJThUaoj
         oYU19t6+971267LO3/HaXYSdb1lCrBPWJIm3KfAGl5IZWy1X+eR01h2pairWRMb625Dt
         39/JMrxsrLzfu6pJem0OF5Z9k25NkpOXWFLW7FmF3xui5+4RmQAVUOK+zGt85Nwn4O6U
         wORA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20221208 header.b=kT0Zly3L;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::1034 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pj1-x1034.google.com (mail-pj1-x1034.google.com. [2607:f8b0:4864:20::1034])
        by gmr-mx.google.com with ESMTPS id gl9-20020a0568083c4900b003a85eb09ec3si2011209oib.1.2023.09.13.10.08.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 13 Sep 2023 10:08:24 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::1034 as permitted sender) client-ip=2607:f8b0:4864:20::1034;
Received: by mail-pj1-x1034.google.com with SMTP id 98e67ed59e1d1-273dfceb3easo61809a91.0
        for <kasan-dev@googlegroups.com>; Wed, 13 Sep 2023 10:08:24 -0700 (PDT)
X-Received: by 2002:a17:90b:357:b0:269:2682:11fb with SMTP id
 fh23-20020a17090b035700b00269268211fbmr2891842pjb.8.1694624903831; Wed, 13
 Sep 2023 10:08:23 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1693328501.git.andreyknvl@google.com> <f7ab7ad4013669f25808bb0e39b3613b98189063.1693328501.git.andreyknvl@google.com>
 <ZO8OACjoGtRuy1Rm@elver.google.com> <CA+fCnZcAuipLKDiNY6LJAs6ODaOG9i6goVLQSdbALrzUDsnv5w@mail.gmail.com>
 <CANpmjNPVu10Y+gO=r3eaU9GP8VL_dqmch3QQXYX8g9D-+HjVPg@mail.gmail.com>
In-Reply-To: <CANpmjNPVu10Y+gO=r3eaU9GP8VL_dqmch3QQXYX8g9D-+HjVPg@mail.gmail.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Wed, 13 Sep 2023 19:08:12 +0200
Message-ID: <CA+fCnZdempKJg13K5HsRyB9oeR0AKeYVkUg487dR510m_avqDQ@mail.gmail.com>
Subject: Re: [PATCH 15/15] kasan: use stack_depot_evict for tag-based modes
To: Marco Elver <elver@google.com>
Cc: andrey.konovalov@linux.dev, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, 
	Evgenii Stepanov <eugenis@google.com>, Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20221208 header.b=kT0Zly3L;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::1034
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

On Mon, Sep 4, 2023 at 8:59=E2=80=AFPM Marco Elver <elver@google.com> wrote=
:
>
> >
> > Hm, I actually suspect we don't need these READ/WRITE_ONCE to entry
> > fields at all. This seems to be a leftover from the initial series
> > when I didn't yet have the rwlock. The rwlock prevents the entries
> > from being read (in kasan_complete_mode_report_info) while being
> > written and the try_cmpxchg prevents the same entry from being
> > rewritten (in the unlikely case of wrapping during writing).
> >
> > Marco, do you think we can drop these READ/WRITE_ONCE?
>
> Yes, I think they can be dropped.

Will drop in v2, thanks!

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BfCnZdempKJg13K5HsRyB9oeR0AKeYVkUg487dR510m_avqDQ%40mail.gmai=
l.com.
