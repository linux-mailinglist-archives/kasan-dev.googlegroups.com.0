Return-Path: <kasan-dev+bncBC7OBJGL2MHBBE425P4QKGQEEUPQRKY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23d.google.com (mail-oi1-x23d.google.com [IPv6:2607:f8b0:4864:20::23d])
	by mail.lfdr.de (Postfix) with ESMTPS id 516D72471A6
	for <lists+kasan-dev@lfdr.de>; Mon, 17 Aug 2020 20:31:49 +0200 (CEST)
Received: by mail-oi1-x23d.google.com with SMTP id f13sf6490460oij.8
        for <lists+kasan-dev@lfdr.de>; Mon, 17 Aug 2020 11:31:49 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1597689108; cv=pass;
        d=google.com; s=arc-20160816;
        b=fPNTJRwZeALAgsOjdSDzXl/vaAw/AA2W+lgMNj+NGwEMpN6yg9K/9nehqTGokoR1Vc
         VErbgDyMYYgn0TXj4upIZXgmNsgHEd3gvpKRhIzv0aIRUuenC8HUgs+Unw98Dz4BBWAp
         hFTOgJKRyCtIqupoe4JJy0Jb/8IpuB4SQ/LldbhbAmyGjehGCKLIc4WLrJiihO4oETPw
         c/jd4JeZffdcc+NVBAy1SaRpKTZgFGVLI0P70sAAdyI3fkREcqBG/jiQYFbdGJpkNLUj
         Q7rRAZ9ZFSNMlFdAqNVzAQboVDShiLAyWV0P0IGit7AAo2SJ5Dq5jj7LyAVeIvSfar66
         IBEQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=AoSkU67Yur9o3nszflzNCd4hNm6ohxt8gyn1T0ixncE=;
        b=jX46kSI/NyNiwukekaXyKBWORmyFvg7gA4zOnPujEUC714zai8+Lf15j19cfGK7Zs/
         ph75fpExe1HXvgYI96bgDt4+L5PUac9IZtUv38aLkZeQcVPac9kbajvcM0LS0CngV7s8
         BuzR2AtNbOzuy1ZpR8VjrcGAYaw2HCqh5p8Q1n3WNH72fTCpjnAK1rEm6c7waY9UC+AX
         gN7iVxbEITph34yZkMFRFTMKMY9Zqme89SNTIq3URyAB3pemZOtLr6v+rnRd40Djvn+6
         UB+/Yc1MEBRiDsgc3a1Jdgn34Ue04FSK3xuYgT39epH8Qz1XnWtj2TTvswQHAlQmH1i+
         WjcA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=FFGxBcVr;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::243 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=AoSkU67Yur9o3nszflzNCd4hNm6ohxt8gyn1T0ixncE=;
        b=sfNVvTKy6iDrsay/82d51tc0cDp5ATxmeT4f9FOD6LQ1MSN8BY9YLbjwaVUx3U44Kz
         VzbCEXDHUX+X4gcfcYmd8dTnKkaN4QDm864AzawVZNLJ7bEZxwe+YGUzlhntgyo5ns9W
         v+Q9+6sNr0kW6OLDhFpttNutPl55gfczf7k/ak4wpaMsBKhGGDFmMVZv6x6SV84D3wiQ
         HLcwHEgAdmuxKsk7NDTEzyJdMutn6KxHUqBiGcZm3gCyrheFUEcXMsmodKCfuh7zn8Aw
         YqObcV6lDGko5NxYvtLZAMIm0W5MxLpXwMMJBtw63Nmup/VHw/bVwIg18EwjLoOs53o2
         EcJQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=AoSkU67Yur9o3nszflzNCd4hNm6ohxt8gyn1T0ixncE=;
        b=L6awXFpAA7h8gdNDpIeQu1mTIVYjLzuxkBZ7oijO3Q0joGfpQrNwz+rfBnKi+OeTua
         jC435rS9CY581l7iJ/UeIL+vYkquhNjwcc0SjXLB1eFfjNEUwED5NMDnmVcs9w3EIKrd
         pczKTkqe5Lzpx9eoejk1cACrvuS9S3us/Myg9QhpPhdedZ/UE+KbUFZty3fFS9FWSev4
         cBuOY2OOOu2yCskQao+PLmRqqnq4b+99zVsy5Zi0K7PnTujEsNWhJj4WTqq2FQaB7EsD
         db4JQrr1i9ZwycxVBsQnnqOjccpUWIYs/Gv6b7OMoR3SNqBLQnbCGS8kqmwwL8L9WFQO
         MvdA==
X-Gm-Message-State: AOAM530AalAyTYvXnSMh2EBIMDCgIj+Zl2T/vrUGfaYc9CefNWq1rCzk
	jy/vFXQy1Mo9vAPUAJ3g8kA=
X-Google-Smtp-Source: ABdhPJyeUBy2OLazDTm6aK2v1DqL345GdLd2Mczx3rGPC6RJSW7PW4TbWjir1ob+L5XL2virHvOddw==
X-Received: by 2002:a05:6808:64c:: with SMTP id z12mr10548737oih.5.1597689108068;
        Mon, 17 Aug 2020 11:31:48 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:20cc:: with SMTP id z12ls514970otq.4.gmail; Mon, 17
 Aug 2020 11:31:47 -0700 (PDT)
X-Received: by 2002:a05:6830:4a6:: with SMTP id l6mr12544972otd.229.1597689107708;
        Mon, 17 Aug 2020 11:31:47 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1597689107; cv=none;
        d=google.com; s=arc-20160816;
        b=q448BQWcjiZaxyvY9JCHOkhI3ixoUAmjLU5fWOEF/r5jGYSjIm42pqURqDfRhnC3Y1
         hswnUq3AiuDNMxpaSJpS3/SxriEtv/5xpGPDiQwXB3NEgbpwZHnrJ7+DfDuOXsCuB5fP
         /Nw9CrkXiOKDK2hv+pzJbKyx0TqK6DXrqtz9GtFpZgVWeqjS4uiQq513/A2j/JlzPHTy
         kY5C9tu+dk2mbcge2saRC8XcF6EBKuYNUsxTSN7hwm/2sDtXgpLcVhm7H2ckj/hXHSRC
         IyiO2L7BSwPtt4KFwjgSLn0DYXYckNlUWxQDzRX0z8lVwpdjdqv8jkWy7G8SdWWjo9iB
         OAEQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=9vrg7EhUgrz2VdstxenWZe+fFP5TU9hDojaa4QJfF8Q=;
        b=QF/fFmeyRxem2sKVQF790p/TKKm78AQFNeHU5TLYOKP3auBn2OPmsPcwj3QC6tNu6l
         19fv9BQeDoPPWX2yogsKTznXjrSlvgvJNAGSiWFgEUu4w2B6FBy3mTkJ160dsQjHZYQT
         4MnOS7ApJuqCtVwcHlrn0mC+tlgqclK3L5Wbi/13+IPymijSbwxos6L+RkBXy2B/CV1Y
         mxCFN+EfnbRgJxDI20yrbsf6yCo2pw8Pyad4njIiKmVsgdd1EfhiP4q/lH2D50rEq9BS
         BHuOLlE/jELaHspHnlnTuIyMU37x2ldd9+Xd+NKq0RPfHdw5yh0fM6ub5quHHuZndy6p
         pocw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=FFGxBcVr;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::243 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x243.google.com (mail-oi1-x243.google.com. [2607:f8b0:4864:20::243])
        by gmr-mx.google.com with ESMTPS id w1si874240otm.5.2020.08.17.11.31.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 17 Aug 2020 11:31:47 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::243 as permitted sender) client-ip=2607:f8b0:4864:20::243;
Received: by mail-oi1-x243.google.com with SMTP id u24so14523607oic.7
        for <kasan-dev@googlegroups.com>; Mon, 17 Aug 2020 11:31:47 -0700 (PDT)
X-Received: by 2002:aca:d4d5:: with SMTP id l204mr10539438oig.70.1597689107235;
 Mon, 17 Aug 2020 11:31:47 -0700 (PDT)
MIME-Version: 1.0
References: <20200807160627.GA1420741@elver.google.com> <CAOJsxLGikg5OsM6v6nHsQbktvWKsy7ccA99OcknLWJpSqH0+pg@mail.gmail.com>
 <20200807171849.GA1467156@elver.google.com> <CAOJsxLEJtXdCNtouqNTFxYtm5j_nnFQHpMfTOsUL2+WrLbR39g@mail.gmail.com>
In-Reply-To: <CAOJsxLEJtXdCNtouqNTFxYtm5j_nnFQHpMfTOsUL2+WrLbR39g@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 17 Aug 2020 20:31:35 +0200
Message-ID: <CANpmjNNhG4VuGq2_kocsTD3CnCv-Y4Kvnz7_VuvZ9Eug+-T=Eg@mail.gmail.com>
Subject: Re: Odd-sized kmem_cache_alloc and slub_debug=Z
To: Pekka Enberg <penberg@gmail.com>
Cc: Alexander Potapenko <glider@google.com>, Andrew Morton <akpm@linux-foundation.org>, 
	David Rientjes <rientjes@google.com>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, 
	Christoph Lameter <cl@linux.com>, Kees Cook <keescook@chromium.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, LKML <linux-kernel@vger.kernel.org>, 
	"linux-mm@kvack.org" <linux-mm@kvack.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=FFGxBcVr;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::243 as
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

On Fri, 7 Aug 2020 at 21:06, Pekka Enberg <penberg@gmail.com> wrote:
...
> Yeah, it reproduces with defconfig too, as long as you remember to
> pass "slub_debug=Z"... :-/
>
> The following seems to be the culprit:
>
> commit 3202fa62fb43087387c65bfa9c100feffac74aa6
> Author: Kees Cook <keescook@chromium.org>
> Date:   Wed Apr 1 21:04:27 2020 -0700
>
>     slub: relocate freelist pointer to middle of object
>
> Reverting this commit and one of it's follow up fixes from Kees from
> v5.8 makes the issue go away for me. Btw, please note that caches with
> size 24 and larger do not trigger this bug, so the issue is that with
> small enough object size, we're stomping on allocator metadata (I
> assume part of the freelist).

Was there a patch to fix this? Checking, just in case I missed it.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNhG4VuGq2_kocsTD3CnCv-Y4Kvnz7_VuvZ9Eug%2B-T%3DEg%40mail.gmail.com.
