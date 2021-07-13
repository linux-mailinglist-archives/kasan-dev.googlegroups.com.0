Return-Path: <kasan-dev+bncBC7OBJGL2MHBBIH2W2DQMGQELME52GI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53a.google.com (mail-pg1-x53a.google.com [IPv6:2607:f8b0:4864:20::53a])
	by mail.lfdr.de (Postfix) with ESMTPS id EC0053C744D
	for <lists+kasan-dev@lfdr.de>; Tue, 13 Jul 2021 18:19:45 +0200 (CEST)
Received: by mail-pg1-x53a.google.com with SMTP id 1-20020a6317410000b0290228062f22a0sf17533838pgx.22
        for <lists+kasan-dev@lfdr.de>; Tue, 13 Jul 2021 09:19:45 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1626193184; cv=pass;
        d=google.com; s=arc-20160816;
        b=OQV6LlR9ePexfIkQ14VOk0hthfV737wxZFYvvzQK30UmchU/Am7+kf6LsfbJT8NUyr
         fSY7b8yss7r2gqmH5vgxWXpaHlixlWDqqpINw359ue4wLMgFkmQE/1R38LapXnrk8O+S
         dDFgriWl3GU2i+vu7fO6n9kkkjBxz4Cc1bl5m56IVNjzfPmBGimVDQ9FYG6jJmpqrzXz
         8x37LjQ7lZ5at5aXLOiDtF4pyJzEIsK8UN/j3kr9/HMGGSRfPOJJKchPfWZvs1G+u07N
         TCV7OoLKsWhWmN/mtK5+qVmG0wsbCPyxDdw8LyLRVmyC4cwTW0yyeFMMI5DPV5kBPYF1
         FUZA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=JzAIRZNSW2ImHBLBPg3x0suc/0O3EoFFjNmRHPAc+Rk=;
        b=ggVsbQ3DZ/io2E/GkfeiqHtAGG2el6Cc22jjCly04k2ETor7wJqDO/8ZovvBpDYgmy
         otkk8MfM3EUWKkiNplXucLdDKYRoIROoHg2kB//Kku4LxWLMALgsdgJh0+4kMlSfeOGK
         QmNPGFutXybe8CrO7GP1zVF7kKNtp2hhGpDx6zVQNgbiKkkMx9dqWHQztYx8C2hMuJJw
         JofBCDXSvdy2UD/bvBDlsfuNeq5HXFWBTAe5OH4Grupp31hlcjLUK2yFqgXm4dRU9+rc
         UTqy/8C9HVIRxpPrPrSqmYeBqn3zTQdNKU8D2KSERrcBWrxqoAnjZtHvw01Tjab0DIko
         Z39Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=s2qdVmQA;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22b as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=JzAIRZNSW2ImHBLBPg3x0suc/0O3EoFFjNmRHPAc+Rk=;
        b=QUdConlfESmiA8rc3QJ4xDYAEVsK0ZhGMK1erVQgU/GjGwn/ZPPhgYwX0yHzeW/P3C
         m+/S3DWZaxSxUx94IjK52nQxIGFdIg+Fm1WQ7QJxlOdzZvBxPue1/rnOrLmOmUAXZN0Z
         2XxAgeDBH5n9FbdmiEkVXyvHRTDBsKfjN3nqrYWZU68GsM7uNwQWNpRRKKJpi6zcAsEk
         W1/YFYQULd3RdWC3OFTeDQTcX666B8bP/COH9swL3C3sSt8xlYjbkvTUqWmklrbulS67
         1wvmsy+XarSBF91tYmZeVdsiWHnhzH6Aj8YIBZtR5SwV84+MfbSlvG04uxgzMuVkK7T7
         F6IA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=JzAIRZNSW2ImHBLBPg3x0suc/0O3EoFFjNmRHPAc+Rk=;
        b=nlo47qh2QtpE0mbBmHLo0T27fbLhN9glHaNJKCVU6t+Pb/ZEYSGVOwRWP2WHW9VgWb
         i23syY6IlqlVgMQOWsHzgBChX4STIh3yVqaXP3fQnh1c273hGaQWhB7fwN+tbD1bF9oH
         qffSyjbgjBHeuvxMnEvbFnl8iRpnSjFved+9L/j2K6hxM/GUY4YtVnekhTjxLk/vcLXG
         /478bC6EHUbS7FN+pZUaMByP5E0lYZ7p0eMnmxr44nPjEYsxM+cW6mVlDrg1/xlklA1i
         oCZ2HLCwDnG7oPvmXj58IqnWgdNdxHXtmVttNuMESGQJYKvghDsFpS2+90aIhsDXlSUw
         DxtQ==
X-Gm-Message-State: AOAM5331BT43DN+XRliJkaaxuFtw72RPGKCiTxlmxM/n0gPDn3n/GMgQ
	7hPmEJi4P7l8qZz8+gWo0rg=
X-Google-Smtp-Source: ABdhPJwX191AyBoCeU2mRKBby8/6jEXSBBRnS7iM7pIhxaFKvKAvPsujcDdxlTz+8461xxPVQI+1TQ==
X-Received: by 2002:a17:90b:184:: with SMTP id t4mr125661pjs.161.1626193184653;
        Tue, 13 Jul 2021 09:19:44 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:4a0e:: with SMTP id e14ls10663387pjh.2.gmail; Tue,
 13 Jul 2021 09:19:44 -0700 (PDT)
X-Received: by 2002:a17:90a:f698:: with SMTP id cl24mr96026pjb.79.1626193184094;
        Tue, 13 Jul 2021 09:19:44 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1626193184; cv=none;
        d=google.com; s=arc-20160816;
        b=f0uqWZHJeZ6rlYCzJtGC/JrGILC6zmRVBd8Xnj7C0RXyt7QfLuvUvfx1O0EZMyVugT
         5d8JNnCbFRvhDN5R83EvMucEcgawS9LtHZNnW659nEH+Mi+OtQtO2YrzDuYohPVjpebj
         wZlvr+OJWGalWcfD5lGJn1oFAsuaHgYTZTpk5QeHw3q9mYNx4Ez/Jr+ufZIUCA5pYLh3
         cL6eFU1GCFrDjar8BS4NXJoqgUz0t/lQ6QKdTfuJqTv/49nxuxzhwmnWllJbtFssi/N4
         5TUHXkzZFMZyUHo4WLxQSRde5zolDBcvPu9ILbRqwyiXltNiZjq5as5U/xQ8t4gkPt46
         3iBQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=dp68kZ8Q63rdtMpfnAuQFhGyVZFwXtaAN9MVU2dhJVw=;
        b=Cgfg6PXQZv7p/rW5itAJzG9DFDzbc+dROlPd3X/Tiy5iAvFR3O+PbfItwz96pn30Va
         ZRKmKV7Qa+Uojgm7d2jsh9L5e44TkaFa7vlJr5ofGTU5hhaKd5i7jPLIjANhHVOKkAeQ
         J7Tu2C7ApLMSMZjUe50MroxrMO78CBtSOY+p+aMss1m3uaUeUEeLP4lQUGDdRYRSHfYa
         0Cfl1s9HG5vT2imjCqfXqYIO44R/L4PSWW8kGAWiLJ1V7JZ2tD9xD9NQ5X9Tbgtwac94
         r4IM03FrTzvnQPfSMNkWpYoB6NkwpcZQAN+BaR49LTUwy49LLCoGDeBm16CcYZLV36R3
         iJrw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=s2qdVmQA;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22b as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x22b.google.com (mail-oi1-x22b.google.com. [2607:f8b0:4864:20::22b])
        by gmr-mx.google.com with ESMTPS id c9si2729219pfr.5.2021.07.13.09.19.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 13 Jul 2021 09:19:44 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22b as permitted sender) client-ip=2607:f8b0:4864:20::22b;
Received: by mail-oi1-x22b.google.com with SMTP id t143so9970188oie.8
        for <kasan-dev@googlegroups.com>; Tue, 13 Jul 2021 09:19:44 -0700 (PDT)
X-Received: by 2002:a05:6808:1286:: with SMTP id a6mr3772723oiw.121.1626193183652;
 Tue, 13 Jul 2021 09:19:43 -0700 (PDT)
MIME-Version: 1.0
References: <20210629113323.2354571-1-elver@google.com> <CAG_fn=V2H7UX8YQYqsQ08D_xF3VKUMCUkafTMVr-ywtki6S0wA@mail.gmail.com>
 <YNsGnyHJL6i1OZFl@cork>
In-Reply-To: <YNsGnyHJL6i1OZFl@cork>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 13 Jul 2021 18:19:32 +0200
Message-ID: <CANpmjNOif53i2zx5hZCN97U9Hb_BPv15dchSTfg9qpJa8iZ3rA@mail.gmail.com>
Subject: Re: [PATCH] kfence: show cpu and timestamp in alloc/free info
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Alexander Potapenko <glider@google.com>, =?UTF-8?Q?J=C3=B6rn_Engel?= <joern@purestorage.com>, 
	Dmitriy Vyukov <dvyukov@google.com>, LKML <linux-kernel@vger.kernel.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	"open list:DOCUMENTATION" <linux-doc@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=s2qdVmQA;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22b as
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

Hello, Andrew,

This patch is ready to be picked up.

Many thanks,
-- Marco

On Tue, 29 Jun 2021 at 13:40, 'J=C3=B6rn Engel' via kasan-dev
<kasan-dev@googlegroups.com> wrote:
> On Tue, Jun 29, 2021 at 01:34:27PM +0200, Alexander Potapenko wrote:
> > On Tue, Jun 29, 2021 at 1:33 PM Marco Elver <elver@google.com> wrote:
> > >
> > > Record cpu and timestamp on allocations and frees, and show them in
> > > reports. Upon an error, this can help correlate earlier messages in t=
he
> > > kernel log via allocation and free timestamps.
> > >
> > > Suggested-by: Joern Engel <joern@purestorage.com>
> > > Signed-off-by: Marco Elver <elver@google.com>
> >
> > Acked-by: Alexander Potapenko <glider@google.com>
> Acked-by: Joern Engel <joern@purestorage.com>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CANpmjNOif53i2zx5hZCN97U9Hb_BPv15dchSTfg9qpJa8iZ3rA%40mail.gmail.=
com.
