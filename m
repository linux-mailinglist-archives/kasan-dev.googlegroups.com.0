Return-Path: <kasan-dev+bncBC7OBJGL2MHBB4GJXSDQMGQEVF7XSWI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa3b.google.com (mail-vk1-xa3b.google.com [IPv6:2607:f8b0:4864:20::a3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 8F8CB3C8A3F
	for <lists+kasan-dev@lfdr.de>; Wed, 14 Jul 2021 19:54:57 +0200 (CEST)
Received: by mail-vk1-xa3b.google.com with SMTP id i124-20020a1f22820000b029025c99c6b992sf991109vki.10
        for <lists+kasan-dev@lfdr.de>; Wed, 14 Jul 2021 10:54:57 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1626285296; cv=pass;
        d=google.com; s=arc-20160816;
        b=jWHMbPnjDX1Sa27dEXZodMPXs0oxwUyrX6VflLLpPXEN48URWng/iC7dTpntloM+aJ
         Q4WLjHFv8lFQE5Moveuz+PudXKmufVSW+mvQc4VhWFNuczFrDIUFfHK/jL+6euf5pWt8
         LCAB82VmED9lBbkvGq0z/O3z0xDnirumZEJHK5WKxVCTYcz5+gx6G7ua+kusWw8xt6gr
         OFmRWM3ylofg6rr0R/luh+7RSH/f9gUOBCe+JpJz1+g1BRqock/6BH6V2QgHrMv1Jo9Z
         qIOw9+KjezV6eT9V90P5UbNVAgnfCCtbd1Y6OHDsWfPwb+XtUv4X3vuChwwUFio9dlid
         wLdw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=SQRnK4MiMjGUncm7q5VnArVBzxXBYAF1bol+kp9F/kU=;
        b=DSU+zIrL15kIQIrAPq3aoyawRc8MfAdVewejv6NX/hgkk6tSo8MjK76RrIctE1Wh1E
         brU4V6rOjrubapJqw7ziTw6Gz3Qz+0atClmZdBg07dxR1C5YcSKRbP4TYu/T3MeZSALm
         9vVxFtUagpp8ICIDAoY+xvVqvBav1rjoXNi04A360somxlz3AWxc2TaFOjmX8p7+D3yd
         8qrn6dptCkDA8m4x4rK493i8q01FkTdeU1tQ3QmP0zTPVOSzrIE5OwnH1npgYn6cCKaM
         gkAlglrmgfatr3J1rtSoMkIWsB6DiP+WVSjwilKaujlUkkq94kIipuKD2S4v2+edNATM
         r6MQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=mXM94q6e;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::332 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=SQRnK4MiMjGUncm7q5VnArVBzxXBYAF1bol+kp9F/kU=;
        b=as7KxAX796HXyP2tXRT5fMRPR4K4g/6/D7lJPIxN4PMjSYRc2IKwO4Fzg1wvaCz1W5
         kEOY36SX11tx1RK578arNZRmreZ2rVyO/8j22VRRZIMoHeamDTf1mFH3upJw1rlNashZ
         76wfbm/ZcsHAeQNxIrtXr480AryN9+pUe6POMzxkKhhdUe/4Lu1QSaRCORfnSu4r2jDb
         6Ms+KJR9DFVSb73ddkRUk6xt2Dvy0WMCeUpQuQ9cv5U4hd0BHRRy9p1iM2yqFxpfBpL1
         TPxNVeplXQj5mvGmS5K+oa5iTEwX2M09KnOFmi7YYoJyWYqHcXW/Q4UI+5ZnRNAB2ClC
         sQ4Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=SQRnK4MiMjGUncm7q5VnArVBzxXBYAF1bol+kp9F/kU=;
        b=Y7bV0G9lCL1S1H2dE0Uxo06k+kCnSwSC5iyEVpLLQlT6vZ4z8h4vHAXOvprewbVFc9
         qrSqixh62lyPHnERX3KIEUdNRVzitZCqMAs5Xvxfg8qDGQZtzBhxWAr8Oh29mnvcE75U
         Ep+Opns0hsl+MVg4QgedzmgNYttLH/GvZxLxSVWjhHqjCWkd+jXuZLjvQYI6cd14tviB
         NVJRp3mTWJLdj6Zsqwvg28L74qpd7nn5R846nG0LGllEmfouvImunKFSaTmU3Q0ggt86
         h1yVZ3kWiilJpbP0vsZPtYDoX6XADkKST3UKvHufFe7FNBHRvUHXsjlGGPBJ0eZgpdbC
         RbMw==
X-Gm-Message-State: AOAM530m/8YzH7eowFRxxhMq3mYO75yMCfDrz4YubEIN6fSuH/bye/lM
	i+hN3eiyYgp/73Sio2ncKwI=
X-Google-Smtp-Source: ABdhPJx65Syhy/maDgfAL4UoMieirKo+IFKON2UGtY2mv6BcEcas3/GR6dX9sum4sl4BKV0pfBTfaQ==
X-Received: by 2002:a1f:dd43:: with SMTP id u64mr13627967vkg.20.1626285296485;
        Wed, 14 Jul 2021 10:54:56 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1f:9cd0:: with SMTP id f199ls448735vke.5.gmail; Wed, 14 Jul
 2021 10:54:56 -0700 (PDT)
X-Received: by 2002:a1f:6247:: with SMTP id w68mr13656159vkb.11.1626285295984;
        Wed, 14 Jul 2021 10:54:55 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1626285295; cv=none;
        d=google.com; s=arc-20160816;
        b=cf8Q9O4azMRBB3PHpv7BSIobdll69OHS/jtsYzscMB2rCL1+uoKMISAFmnjrVRk0Lb
         v6WGDrjbztFtz5tCvuBkjuVD6zCrZWBjG5k3YO/oCVmaSwkg1tSXbIfCgH/QB8G7BUb2
         t/xprM9x120W6Y97MhjVnEZtlKeT8DT8chZ4mBxt4H7IPJq43/arewHr/tW63rKtihQc
         YwrYTgLuefM1hwPlsODsiWteto+H5CUEp2GcTyHqbCPnSKdP/JpVs/CGqB0pdk+euRuQ
         kO0UBREp12QldUbyytMSJLbKtSrFF5Ze66pMdOpScP7Ey6wf7J3Hcna+nu8yL8VJDxqT
         EVaA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=jrD1pQ3OBKYY3c2yMtsYHqlgwFHdU07pE4enP3uNpXI=;
        b=e3rW7yxId6CIqDKZOczUjFQVTRYagCu8LsTBm+5i0o+0EQ4UhaPPPNsHT5ovDnDh9L
         HyZ0V8ZsTgF+7V7Q8v/4qQjkbnjYzLrdPIYvETBo6uca/3VuqKWsvfVAH2I9E8MiHjkP
         01diOjROY9L02H9yNlKtWfHlL0lj7Y69y3mXkpvjLK/zcpVl7ov39P/OtqDomEAd1iS8
         CUAWEANW212WHiS4kUv6NKolqp0OUSG97HGQ+p1FxHuATIWwKha/2LXsE01m0FpJ+zSw
         W2aoYz0iYSmOVIIFDs8XDJHGidE9vdiik8KtwH5v6QpKPhlwr5/x1iE2lcBgZk7UyL21
         mVyw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=mXM94q6e;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::332 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x332.google.com (mail-ot1-x332.google.com. [2607:f8b0:4864:20::332])
        by gmr-mx.google.com with ESMTPS id d66si371038vkg.3.2021.07.14.10.54.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 14 Jul 2021 10:54:55 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::332 as permitted sender) client-ip=2607:f8b0:4864:20::332;
Received: by mail-ot1-x332.google.com with SMTP id h24-20020a9d64180000b029036edcf8f9a6so3397154otl.3
        for <kasan-dev@googlegroups.com>; Wed, 14 Jul 2021 10:54:55 -0700 (PDT)
X-Received: by 2002:a9d:650e:: with SMTP id i14mr9109289otl.233.1626285295243;
 Wed, 14 Jul 2021 10:54:55 -0700 (PDT)
MIME-Version: 1.0
References: <20210714082145.2709233-1-elver@google.com> <20210714173755.1083-1-yzhong@purestorage.com>
In-Reply-To: <20210714173755.1083-1-yzhong@purestorage.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 14 Jul 2021 19:54:34 +0200
Message-ID: <CANpmjNNBjD3KnNCu+9nF8bKDyrjpkZMwkWiZOe83FgZomcb_3w@mail.gmail.com>
Subject: Re: [PATCH mm v2] kfence: show cpu and timestamp in alloc/free info
To: Yuanyuan Zhong <yzhong@purestorage.com>
Cc: akpm@linux-foundation.org, corbet@lwn.net, dvyukov@google.com, 
	glider@google.com, joern@purestorage.com, kasan-dev@googlegroups.com, 
	linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org, linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=mXM94q6e;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::332 as
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

On Wed, 14 Jul 2021 at 19:38, 'Yuanyuan Zhong' via kasan-dev
<kasan-dev@googlegroups.com> wrote:
> > +     /* Timestamp matches printk timestamp format. */
> > +     seq_con_printf(seq, "%s by task %d on cpu %d at %lu.%06lus:\n",
> > +                    show_alloc ? "allocated" : "freed", meta->alloc_track.pid,
> > +                    meta->alloc_track.cpu, (unsigned long)ts_sec, rem_nsec / 1000);
>
> s/meta->alloc_track\./track->/

Thanks for spotting this!

v3: https://lkml.kernel.org/r/20210714175312.2947941-1-elver@google.com

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNBjD3KnNCu%2B9nF8bKDyrjpkZMwkWiZOe83FgZomcb_3w%40mail.gmail.com.
