Return-Path: <kasan-dev+bncBDW2JDUY5AORB2VFQODAMGQEATKF53A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x339.google.com (mail-wm1-x339.google.com [IPv6:2a00:1450:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id F35F13A1792
	for <lists+kasan-dev@lfdr.de>; Wed,  9 Jun 2021 16:40:44 +0200 (CEST)
Received: by mail-wm1-x339.google.com with SMTP id l32-20020a05600c1d20b02901a82ed9095dsf892195wms.2
        for <lists+kasan-dev@lfdr.de>; Wed, 09 Jun 2021 07:40:44 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1623249643; cv=pass;
        d=google.com; s=arc-20160816;
        b=VizLe+0pbFpaJGmXbK+VPCj0kCT2BtjYZRrxyYBQYrw5OaYm24wIGz6tXGjXXklz4C
         VnigT8p1ADA7sXvjAtaokblph5Y4WpFgwIOahSEM+zJfRTxiNI/Q0rjAi41OsUqSMMVl
         abKRNbnckPtRpBwgVtwW7yZBhKXfVErOPE2J2FDRO7JMJdpsoypYAwOYt6TSZjnAuNyP
         5ior2TsPUK78O+GkhbSebdlnPkTnoCc5izH6Hw9MF6wFJYmbd/+nsgWOkS0pvmyEk/R7
         9Tcgxbz7kvz52asEAvzXtGW2nI1BzLx6UHAeKTL31z1AGQrMj7eZu76XZi/Ku8b641RX
         D4kg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=8zUyFT+FnbyQPGHYsVmUhNq2GXJDfI2xgK1qdgThbcM=;
        b=LwXEeftm1kgDqRMH8Vch21cMFoYUPiqIbq/RhlfWFpvkZVXPgcFpodEjAE1/n2sCgS
         QFyPimC3cunhEuE3XJ34Z2Qt7tKNISOdcgBXS3L4lhRpjZOuxWhKIPCbuvdABS8QOOnj
         hB189BhSuLHUEivYRsck93rJfJlslHVuq4BVFnTrC3K43lP/pAkszrPMQVpb0ekwleXq
         Og0k/tRsYsTyWi2nIDQs3Jg20KZehSKxgbinMt0yfwXyjijMMAi9G6lcOfGbIu3PPlz6
         cwXdRDNdhFR75pZmFfgy9A66/1ZpZdZktBnxwUWe4KmE7bFQjo/EQs1xb7/Nh5KTThbG
         i1Tw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=UDsKsF0i;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::62b as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=8zUyFT+FnbyQPGHYsVmUhNq2GXJDfI2xgK1qdgThbcM=;
        b=Dsr+cppb86I2LWWeLfPILp4KwMbrv8vfZaHTq9kxIgGGWr04J1Btst3KFKKPkOvtdg
         6pDEX4NxhyvFP/bXsh8o1imrZUiye/oiA/C0n3Hnnai6r6QltDsj+YGOU4+aKoQp8DM/
         ujzHlnZNnyqXswBEtCX/LMiM4IjdpDlXN6awHZPd7qFDMkMAHA+LGZaHJDfYGVON1KF+
         L6JA+utZErIE0UU4yxDibF3JF0TQtrIP1eCAAlxX9n+dn0GsjUxsJaKPaID4UmRh/76x
         gKiYIl6tqmYJAnQaP8DPy+Xc0yTOVF4vQ2scPGmTJC/bX4H10Ibcp+pBli34Ny2vVw8j
         YcSw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=8zUyFT+FnbyQPGHYsVmUhNq2GXJDfI2xgK1qdgThbcM=;
        b=sFVh6KBG2SqVZWm61Eqmm6Kh27vWPhw7yhOaJVGQg/+FXEamNs1KfNtPRF0iLric3G
         FBAc8xlWKRBh34wr2g+huaujbit2WyqFZ5LeAkNMDJiZgr8Q9ie4F7TKv42SeelIl+E/
         jmHCtU+Gx7VUMTIQC6/phsH5waHegG2LA9ENvEJiA0lV7BIfaXJfL9v0XkQDgUZEkGEc
         Z/A1NxPzlhI0rHATrSxJz/3izLYj/8FC7ac2VJ/TmJC1DvMTvHW3hbep3uQj+pTJ0vG6
         4auL0/1k3wI/00dJEbhL+Z4tKBUryJOsxiqqwXFlqkzIFeDmM/+ZWHCXRx54pLrmpEIg
         6c4A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=8zUyFT+FnbyQPGHYsVmUhNq2GXJDfI2xgK1qdgThbcM=;
        b=DY6ySn7SsKBX8RChDa0f8GRghLnb2zUtKG4/pgxXPPL5RYSXksUsPDmm8KOXfLr3l5
         Z7j6rBt7DtzWcsPwPtObzwcHnS5xHsgcNjXmr6JyzUwYAurGOWNIKSNi4lA4I68qfLOu
         EgPRGVpKDkkTOzQk1XBKBVfbbEc6JiZXxgx6vi1XdU3b1lxnUPbbVM8D/Une3qHcHyqw
         Eh/ob26Epo3boIz9au4Y5s2/YFc0qjOfoDVAj8LKohAXcvsFtxY2Hk/rlUBebjwcxY2J
         oqbi3TSRsL1woxNtyZReLQwaYdS4Th4BGZQFslQvpLXRMcPl1KSR5MJWV9Tg//f6knmQ
         BAzA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5300bWjA75/sNzhC8PY4gufskgi1M0LZ6hy8hduAVZqYfPwslpF8
	meQY38I1LmB/Dc4Pi6YeMsQ=
X-Google-Smtp-Source: ABdhPJzirZ5JzCLd/fkT51KYLMecxm5n5odERLyhAcFn7Eyzd3PIH/z4Raqw8iLGtemMTqGDtWnftA==
X-Received: by 2002:a05:600c:354d:: with SMTP id i13mr156132wmq.67.1623249642724;
        Wed, 09 Jun 2021 07:40:42 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:1d0e:: with SMTP id l14ls3512059wms.1.canary-gmail;
 Wed, 09 Jun 2021 07:40:41 -0700 (PDT)
X-Received: by 2002:a05:600c:243:: with SMTP id 3mr162515wmj.35.1623249641900;
        Wed, 09 Jun 2021 07:40:41 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1623249641; cv=none;
        d=google.com; s=arc-20160816;
        b=MSrjsvSkD9xkSGX8TJEYrIzD3mwfhe0Iv4rwdy6GJx+O6OydRPm4SLydOPBK9Pe8Ss
         flob8rEz2AdU11Z3dsX0Q6/3itZkzKUSWUzACLD1KaTH3cB7iV3kUCKvrkkHGRRCEBd8
         uhytnqNwE3mZAHLfKegMnVFNze8Wcy8knFcimxUK+vzgOMaPRySBWQzFELDHkgp4M6JG
         W8wp5jS7+kdsg/FNIKN1iUHnYhPJQvCWCRX91lhF+6ryI7BHIQZAfjS55hPgw1FfrCRt
         jwoSSJz5EGCMQkTvUhgqJQ23v2v3rlb9a3bAfZVxcDN35rtXvbN/4ZVywW3U1dLstlXS
         28jA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=j3DFrycmwxSEuvSCbAPtF95LHPzNMu8yExfA6gEnmbs=;
        b=ieH8pNLwkjuGOSErB+TRv4mBttXszd/lKeBkTrzhSC9BcveUSo5klkXablIUJzdJc5
         rYj6eF5iXKGz4gFmW3ugcYQo4kpW7HeVY2RAm6imazIRJZ1Bdzib7OEKBTigMlGIQU/x
         /MubOgCCHejcLX8CbtvD49AZtaXjLo7HKfIJ4xFPA7TLhKpb5IXoz2IWeOGM2kbfUcwZ
         7vsxKB9DsjFkPhuI0kkossnHpfDyohJTpdg+8X3HDBWtIrCTG7+BN5lqE+FhZc+LFveE
         fZ/2YWWc6XjHX7ZxK/eqLmSk+VHsS46OxRyW7Mr4uAoi+rvY3O4Yw5ZwtZkyjyUbYZsn
         omqQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=UDsKsF0i;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::62b as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-ej1-x62b.google.com (mail-ej1-x62b.google.com. [2a00:1450:4864:20::62b])
        by gmr-mx.google.com with ESMTPS id o24si174377wms.2.2021.06.09.07.40.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 09 Jun 2021 07:40:41 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::62b as permitted sender) client-ip=2a00:1450:4864:20::62b;
Received: by mail-ej1-x62b.google.com with SMTP id h24so38904727ejy.2
        for <kasan-dev@googlegroups.com>; Wed, 09 Jun 2021 07:40:41 -0700 (PDT)
X-Received: by 2002:a17:906:f6cb:: with SMTP id jo11mr172996ejb.439.1623249641693;
 Wed, 09 Jun 2021 07:40:41 -0700 (PDT)
MIME-Version: 1.0
References: <DM8PR12MB5416B119812D7B939F9AC9CBAD369@DM8PR12MB5416.namprd12.prod.outlook.com>
In-Reply-To: <DM8PR12MB5416B119812D7B939F9AC9CBAD369@DM8PR12MB5416.namprd12.prod.outlook.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Wed, 9 Jun 2021 17:40:29 +0300
Message-ID: <CA+fCnZesNpTSrdnig+fx5A2_ZpZQxpN6fJwuXi5kgTVnJLncmQ@mail.gmail.com>
Subject: Re: Question about KHWASAN for global variables
To: Sober Liu <soberl@nvidia.com>
Cc: "kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=UDsKsF0i;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::62b
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

On Wed, Jun 9, 2021 at 5:23 PM Sober Liu <soberl@nvidia.com> wrote:
>
> Hi,
>
> Sorry to interrupt. And hope this email group is suitable for this questi=
on.
>
> I am confused by whether global variables are supported by KHWASAN or not=
 in GCC.
>
> From https://bugzilla.kernel.org/show_bug.cgi?id=3D203493 (for KASAN with=
 sw-tag), it tells LLVM doesn=E2=80=99t, and GCC does.
>
> While for gcc/asan.c, both its GCC submit log and comments mention that  =
=E2=80=9CHWASAN does not tag globals=E2=80=9D.
>
> I also tried to make a comparison here: https://godbolt.org/z/Pqvdaj3ao. =
Looks like GCC doesn=E2=80=99t generates tagging infra for global registeri=
ng.
>
> Could anyone help to confirm that?

Hi Sober,

SW_TAGS KASAN does not support globals.

I was under the impression that GCC has global tagging support for
userspace HWASAN, but I might have been wrong. Clang support global
tagging now, AFAICS. But there's no support for global tagging on the
kernel side.

Thanks!

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BfCnZesNpTSrdnig%2Bfx5A2_ZpZQxpN6fJwuXi5kgTVnJLncmQ%40mail.gm=
ail.com.
