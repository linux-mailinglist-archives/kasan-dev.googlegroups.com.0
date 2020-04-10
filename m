Return-Path: <kasan-dev+bncBC7OBJGL2MHBBDVUYH2AKGQEFQGFZWY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23e.google.com (mail-oi1-x23e.google.com [IPv6:2607:f8b0:4864:20::23e])
	by mail.lfdr.de (Postfix) with ESMTPS id BA9E21A45B7
	for <lists+kasan-dev@lfdr.de>; Fri, 10 Apr 2020 13:35:44 +0200 (CEST)
Received: by mail-oi1-x23e.google.com with SMTP id w203sf1557296oiw.10
        for <lists+kasan-dev@lfdr.de>; Fri, 10 Apr 2020 04:35:44 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1586518543; cv=pass;
        d=google.com; s=arc-20160816;
        b=od+O7kJVasJ3AvXSpwJg6pKxtma9Kv0nGj0jgtyOW5fa74ntahlNDqThHMgJN5dCpo
         mGy980eMGlcEzuLCMRJQQsyTi8e0XltU7pG6ZGJIOqHyJDiz56YJRl6/gvW6j2keK4UL
         AIPbnI/THeM/38YWfCJWnk5nfJwDEXrqXukWDuOpfDbZDTozRD0CIlds/6DwelfyHc+3
         ntmLyUVgWfoqgQ8e9YQhP7fLRuf5zmDzfX9Gfi8sRYMxSSt5HtAAj3/p0ONnP5X6cDG0
         SmfE0cR+IB/iOtkTZf6wHUBmWeKsOHJiCfT586GLlvPFwaIfv3gSHOxminCLp9hxgjDU
         LnUg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=1Rp7KKp7VelQYyoBUWfTC/nWZeNr3JV1EOkGYvpLKuQ=;
        b=F4/0W++xRnJ7DnKAYW5HIAFvgTA2MDt/Emg2vU9OYY1U8AaJl8AAQGLRDVwwRDI5u8
         BniZ9jwOah5o/dFgGiZ/WeiN4sv4l91FIqIfoiHedJ7x9DZc0nAf59l5E9XCwh3WFuzb
         7j22OjJYvGBGqkKalkaZuVZzRYaNOQptBNFo6nEOlEPcoHtaEAQUM709NDMLdde3VdGg
         9bMbKvFUR44p31H5S+3vxIeriAZT+EOFbmVxpf+XzZKECjjQoVrskLiZ0Z68BxZncnjK
         Mbt89mFzeqNY7nqAZe1cI/cDLx28dvpq1zhLMSNxtrmJZQRIONgUWZi5HP3xALXvkpt2
         iJYg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="g/fO0oCd";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::243 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=1Rp7KKp7VelQYyoBUWfTC/nWZeNr3JV1EOkGYvpLKuQ=;
        b=eywUiY5rKTk6ZTiEnmUxf0YWdNiGqDzBwGmmZUk9ywpGbvBUa3Cq4BUraVToANQjWl
         W0O3GeUR2GNf5cKb5L9ZNArlIlP9UVdLuugj+B7Hnr8nkQmg6DLyTZITzjPo2/UY65uO
         BFBkYyZN3FLbtHB5USUTdTWZHgpuTMpTOyZ0eB96ELNMfZWZk6pMWn5eHrCaHbTc1n4A
         RqE52eMYZ4jAt7w9GJImGcH1sCBBnRSJs2tDcNhsedqO9OWCtxneUdeXlDoQXuX0Y3SB
         8Vp6iRVQCJwgXbcYovEa8z0wYD+Q+uq/MJQXPeT+JghP2ah9k+wCbg5cEEcd6JIVN/yu
         yjqw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=1Rp7KKp7VelQYyoBUWfTC/nWZeNr3JV1EOkGYvpLKuQ=;
        b=DoNArwG2vNIX6G+e8ILuHXWcPtavIcu+MwpQVgQ4PyCt/vysNYr3UlxBtfUEXAdAS1
         Ka8PEwKsJXZ8ZnCscVdwRF7ZF7UJ48H0A1oqTGC1ZAsraO49EQt7QH6/aclm91Cav/gJ
         vIw3vAzXlPO0zv+QuffseOyTAzzcU/0E32wDV5BhjA7LwB0+ZLgqEa41z4ni7nWDcj8W
         BDrei4pLQFCplF47UhUGsoALER7oiR4H+E4Y5j/Asd3s/uCjI7u4gcvlfcWLtxYidBFB
         xXIQ0wpNxznD/M6e9iodPyz0u50CwD82jwwyh+RP2EA5PICaX3A1vtsoIp77w+hhczwG
         +3/w==
X-Gm-Message-State: AGi0PuYmDzeRlZWKlkkXX5WNdmwEm5c3MpDOssZA8DeG42pn2hJBhf7y
	y49UhLE4twBHYmS5zAT+K2M=
X-Google-Smtp-Source: APiQypJxC5Y+rro3bJrh3NuYOdmtR2ywUG8ToJyuYcvafsnB3iDTYtUBPJtZCwXzLc/TwH9WVb7BsA==
X-Received: by 2002:a4a:250b:: with SMTP id g11mr3802882ooa.27.1586518543033;
        Fri, 10 Apr 2020 04:35:43 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:3807:: with SMTP id c7ls432441ooa.8.gmail; Fri, 10 Apr
 2020 04:35:42 -0700 (PDT)
X-Received: by 2002:a4a:a7ca:: with SMTP id n10mr3827125oom.46.1586518542616;
        Fri, 10 Apr 2020 04:35:42 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1586518542; cv=none;
        d=google.com; s=arc-20160816;
        b=k1LnAQ4nyaTEFt7Baf2/lfPr8FCIGbZ4Du8J8es9yDluhJSDqYPrGkc9tkEIl2hoxQ
         pnQX67EPccOtdxkc4Z0NJi1pwafbIrfZuOXjdx4mCSwOWAIEZBQC2UZVmuc3JhFH6G8r
         uEMMv+nql+pm/2ug5UG7JNBBCIhgh87mTVJ8aPO3/dbcS1AwCPjTYIPCZlnDXbp0aiuu
         DjI+6Nz0VXzcXj7yJEZVH1KmPTgvAwnL65lmKV0mNpp74ydKdKLCWrp2Wc+A9Ex/QAIU
         tCX1nDy8wfD75wHYDbwyCbfMwudEVAS+J8Ih/Xt2wn3aac6S69DfwzMlVrvXpxXu7OGr
         C3Qg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=ak/n/QFprJwiNkpwHaAXa7wOUuxlUvr0M/v9pCPaJMI=;
        b=ywvs61PYVdMlviaAq6J33xPKHUFeXyFuKfvRTLqJCp2UwDnFtOqgcCfuKFYzcFPubQ
         WGpiyHchDcg1wlrPE8ajVWYqtAh+Ao0/Ydz3/ivKFcC4CqWFB1qTu844Yq4KSQA08CXh
         BFXTXFmH78R5cr7ht4eKG3Co/nvnaTmYvimq3/oiyYlKCXbz+wZrT9xDaNbud7yX9xDt
         Rs+IpWvejEJGSuCPkh4aAo5OQSpyDfR2fPFM1dyRYkoKPUvN9Va6hxZUsxB595zAdB6W
         /lDO0B+/BlN30GlYjLLZ8+LTwa+2p/BuWdv2y2rTFt7gHA+1V0+ksZEmfZpOy4DAWlD9
         fcfQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="g/fO0oCd";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::243 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x243.google.com (mail-oi1-x243.google.com. [2607:f8b0:4864:20::243])
        by gmr-mx.google.com with ESMTPS id t81si116114oie.5.2020.04.10.04.35.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 10 Apr 2020 04:35:42 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::243 as permitted sender) client-ip=2607:f8b0:4864:20::243;
Received: by mail-oi1-x243.google.com with SMTP id b10so1183760oic.2
        for <kasan-dev@googlegroups.com>; Fri, 10 Apr 2020 04:35:42 -0700 (PDT)
X-Received: by 2002:a05:6808:4e:: with SMTP id v14mr3091006oic.70.1586518541919;
 Fri, 10 Apr 2020 04:35:41 -0700 (PDT)
MIME-Version: 1.0
References: <CANpmjNMR4BgfCxL9qXn0sQrJtQJbEPKxJ5_HEa2VXWi6UY4wig@mail.gmail.com>
 <AC8A5393-B817-4868-AA85-B3019A1086F9@lca.pw>
In-Reply-To: <AC8A5393-B817-4868-AA85-B3019A1086F9@lca.pw>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 10 Apr 2020 13:35:30 +0200
Message-ID: <CANpmjNPqQHKUjqAzcFym5G8kHX0mjProOpGu8e4rBmuGRykAUg@mail.gmail.com>
Subject: Re: KCSAN + KVM = host reset
To: Qian Cai <cai@lca.pw>
Cc: Paolo Bonzini <pbonzini@redhat.com>, "paul E. McKenney" <paulmck@kernel.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, LKML <linux-kernel@vger.kernel.org>, 
	kvm@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="g/fO0oCd";       spf=pass
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

On Fri, 10 Apr 2020 at 13:25, Qian Cai <cai@lca.pw> wrote:
>
>
>
> > On Apr 10, 2020, at 5:47 AM, Marco Elver <elver@google.com> wrote:
> >
> > That would contradict what you said about it working if KCSAN is
> > "off". What kernel are you attempting to use in the VM?

Ah, sorry this was a typo,
  s/working if KCSAN/not working if KCSAN/

> Well, I said set KCSAN debugfs to =E2=80=9Coff=E2=80=9D did not help, i.e=
., it will reset the host running kvm.sh. It is the vanilla ubuntu 18.04 ke=
rnel in VM.
>
> github.com/cailca/linux-mm/blob/master/kvm.sh

So, if you say that CONFIG_KCSAN_INTERRUPT_WATCHER=3Dn works, that
contradicts it not working when KCSAN is "off". Because if KCSAN is
off, it never sets up any watchpoints, and whether or not
KCSAN_INTERRUPT_WATCHER is selected or not shouldn't matter. Does that
make more sense?

But from what you say, it's not the type of kernel run in VM. I just
thought there may be some strange interaction if you also run a KCSAN
kernel inside the VM.

Since I have no way to help debug right now, if you say that
"KCSAN_SANITIZE_svm.o :=3D n" works, I'd suggest that you just send a
patch for that. If you think that's not adequate, it may be possible
to try and find the offending function(s) in that file and add
__no_kcsan to the  function(s) that cause problems.

Thanks,
-- Marco

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CANpmjNPqQHKUjqAzcFym5G8kHX0mjProOpGu8e4rBmuGRykAUg%40mail.gmail.=
com.
