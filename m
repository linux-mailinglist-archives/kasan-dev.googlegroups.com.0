Return-Path: <kasan-dev+bncBD63B2HX4EPBBC5BTT6AKGQEIDBIQCI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33b.google.com (mail-ot1-x33b.google.com [IPv6:2607:f8b0:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id 8C52728E282
	for <lists+kasan-dev@lfdr.de>; Wed, 14 Oct 2020 16:51:56 +0200 (CEST)
Received: by mail-ot1-x33b.google.com with SMTP id 33sf1067379ota.10
        for <lists+kasan-dev@lfdr.de>; Wed, 14 Oct 2020 07:51:56 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1602687115; cv=pass;
        d=google.com; s=arc-20160816;
        b=jkxDkC2nKRSYRonaUvjkLM7jkl4AAX28XeiVfX2+cdgLw5dtWDpXuy2zVo4Cdud5DU
         5Mds+r1CBVLUv/ZalxUFZTcKHvLOqNASqkxFPswz3utjuQQULAC29jWS/7ftfrX/yhCN
         1zbzJeLSzpQk0ZKu9VLUh42QjUh23ONdadZ6kvA6DgOQEwDmyvG3X3LCHRpx/nCTz+20
         WXRur8+yqehTQ69GkYIp90B14IPyXVr/LpHkFhGwbVwCTny7skOXPOlVxD7pFnLsxUMi
         d5tEPatXmTqDjWOtGdd5A4ccS5cWhnGAhuM0TzV1rDqvVpnWxRSHGK6971UwIvqHXIkY
         /6kA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:dkim-signature;
        bh=DI+hvW2m46wZCLCiTRk7ObhFN2XTsdEPr94OSL7CiVg=;
        b=QxLuxQRIsOfiye6gvpwsbQmduJ14wsMOrdlrmNVahJ4cf6ZqMRRX2qXFhhZHWu6TjI
         Evs9xKHwpWcm47HI3DLK83mc2woFt5YM0CqUut25pswBqIa4e/1UrDayhVIImRMGIIji
         WqtiVNmXSYjwf0ZIe6PQ1A1TTWfkGlL4gQqdbRkuome0fiF9Lnx293HyJDivM1zeflUW
         RiqwiVEzNSjM337l7RjuwH5g9QE2cjX802THHRpwI6ioFdzDUzjK48g20rRhVowT/1BS
         kJNcK6dB38JV2mY9LEaXEG61zmENZhEGOOFQ7mv8F3KPAct2vJQDUqhxYVf3UAdJzlCs
         ZSNg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@purestorage.com header.s=google header.b=U90fnHnQ;
       spf=pass (google.com: domain of joern@purestorage.com designates 2607:f8b0:4864:20::1029 as permitted sender) smtp.mailfrom=joern@purestorage.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=purestorage.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:content-transfer-encoding:in-reply-to
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=DI+hvW2m46wZCLCiTRk7ObhFN2XTsdEPr94OSL7CiVg=;
        b=nLpf4gRW4dVquj6q95kc0OApyPvPwL9b+6pWdgGHMl22BrEAIrHiZUMC6CSQ5RJdWS
         tu8S9F5frcgB89NQGYFtYzPe1vgNIIbYzctIDo6b4UjxqCdA+NCGVLnvnjKjkydsB9Vf
         oCHuqTxBzTkqYIL75A54ilgykZxUMgIBypCdRKh1KBB8yVKisXMDRZo7kWdH1ZNioKem
         W781X0RgVkMfdHY5myGW4SSsqLqEdMZLfH4VLijG8Fds2sioqG9b5Sfk6CrCHSaYFC3Z
         6Tv4m5Vq2fJd699KCgOvjjdIZANSEaaI4J1OOz4agAoGoNmZmm+8W0SfgeqJbeSO3HFP
         VbXQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:content-transfer-encoding
         :in-reply-to:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:x-spam-checked-in-group
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=DI+hvW2m46wZCLCiTRk7ObhFN2XTsdEPr94OSL7CiVg=;
        b=K8JX8akjHC1pY9F0r0uj2NoQpfZd20xsAssrguE5N/mfPuAyd0+soWTPoIEwCRNqhf
         fIYRUVT6IU3ZSdwJklzdTL2N+Lpo1opwl3pAPpnIpVyOEH4c22ipF5bXKZJLdYf0OzTz
         j1BsS0cTPpuPq2MXVFuacd8/CTqL2kMaBo7/xHpDpNKYlcFyMarBSWnYXeAPs9wH4oGj
         8ZHKzI3RLXR6e+1T8ziGh6CtCpsjKDwAaluycL0nZGOiw6MHdAms+WgIsJIeY13nYhoG
         C7tOm/+ABTNStE4yNaFgImsq994AN67W0461/2z43QEd+hGoANLzk3ZWhhqDF8M3P8Xc
         0DjA==
X-Gm-Message-State: AOAM531oQ+GONoSdqNNt3lUlhV6z+stADdwiob+iZcVrDycEIqnAL++4
	z7+bnMjttPbV9oX8X6OqyNE=
X-Google-Smtp-Source: ABdhPJzNRZD9P6sJ/6C/TWQhbYTisx1k36C/8E1dPHdFBNcR4iqQ8yEItgLVGUyB/4k+UnQhYoDHLg==
X-Received: by 2002:a05:6830:1046:: with SMTP id b6mr3788464otp.363.1602687115371;
        Wed, 14 Oct 2020 07:51:55 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:cd96:: with SMTP id d144ls149251oig.5.gmail; Wed, 14 Oct
 2020 07:51:55 -0700 (PDT)
X-Received: by 2002:aca:170a:: with SMTP id j10mr2541236oii.82.1602687115032;
        Wed, 14 Oct 2020 07:51:55 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1602687115; cv=none;
        d=google.com; s=arc-20160816;
        b=u+6XfkgplPXtLJCaM0EUs81jTlIsXZ136wa8Ysl9y2VyqYUC2uqj+slD2LVM5zYVe9
         HIgShZzSGvRO4JG2dGiKmG70Xtu7s53Y+QA853pJrOASjeBTsGsjH8J+sDA9X96CcB02
         R4sQTRJBJ9oq30Os8Yy2rTxa9/1isArpznoOdAYcD+QWFXrBxmDxVXyQzv7c8M0YJCW5
         aI5C0dACZPENj8H6tqSwmAYmgfaFi229c6mPAuY4JyLZadH15/A6W2P85bRG2AsgzvT1
         2o0IYaOTnVUDjPgUErFZxovwVYipyiRVTkd5ztkRmkD6rLhbQoQdyVhVcqDa/MOFIjtw
         H/KA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=+6T8DfgZqFXYkYrSLfelRAbPzgMbAiAKKTcVSP9FVqg=;
        b=UNoH1M4AocUBo0Q1DJwzkGjB7GEkRL4W7gHYvY14+MdvCd1EUHXpVOtmR+VZoayWKO
         DbtdGoRFqNTKe3bkiyajk9dbhfF0raUKy42rXlcZOiM4/gDZdkM8Y6ZMK3iX70MvgMpr
         9BSlNpx110GZK6Y+CaiiieBeMeiqa4V+oPR4yIu5/WHDpY14dmHXoqIn9OMEYltqBvZO
         gsBhBsXa/1xUmrfzDtLfzl/as7zaGpt5y9a1SCSzMIDycqjm+dRLAXlwsXnvLS6lR5hp
         KrAcwqdwrW2l/ZMBgJlS2yGvui9Cryop4ziyLlpjCwCucprkU/C64lLkgsySC6zbw3Ya
         5VjA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@purestorage.com header.s=google header.b=U90fnHnQ;
       spf=pass (google.com: domain of joern@purestorage.com designates 2607:f8b0:4864:20::1029 as permitted sender) smtp.mailfrom=joern@purestorage.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=purestorage.com
Received: from mail-pj1-x1029.google.com (mail-pj1-x1029.google.com. [2607:f8b0:4864:20::1029])
        by gmr-mx.google.com with ESMTPS id o22si341564otk.2.2020.10.14.07.51.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 14 Oct 2020 07:51:54 -0700 (PDT)
Received-SPF: pass (google.com: domain of joern@purestorage.com designates 2607:f8b0:4864:20::1029 as permitted sender) client-ip=2607:f8b0:4864:20::1029;
Received: by mail-pj1-x1029.google.com with SMTP id gm14so1722027pjb.2
        for <kasan-dev@googlegroups.com>; Wed, 14 Oct 2020 07:51:54 -0700 (PDT)
X-Received: by 2002:a17:90a:8596:: with SMTP id m22mr3801808pjn.42.1602687114250;
        Wed, 14 Oct 2020 07:51:54 -0700 (PDT)
Received: from cork (dyndsl-085-016-209-235.ewe-ip-backbone.de. [85.16.209.235])
        by smtp.gmail.com with ESMTPSA id p62sm3837391pfb.180.2020.10.14.07.51.51
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 14 Oct 2020 07:51:53 -0700 (PDT)
Date: Wed, 14 Oct 2020 07:51:49 -0700
From: =?UTF-8?B?J0rDtnJuIEVuZ2VsJyB2aWEga2FzYW4tZGV2?= <kasan-dev@googlegroups.com>
To: Marco Elver <elver@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>,
	kasan-dev <kasan-dev@googlegroups.com>,
	Alexander Potapenko <glider@google.com>
Subject: Re: GWP-ASAN
Message-ID: <20201014145149.GH3567119@cork>
References: <20201014113724.GD3567119@cork>
 <CACT4Y+Z=zNsJ6uOTiLr6Vpwq-ARewwptvyWUEkBgC1UOdt=EnA@mail.gmail.com>
 <CANpmjNPy3aJak_XqYeGq11gkTLFTQyuXTGR8q8cYuHA-tHSDRg@mail.gmail.com>
 <20201014134905.GG3567119@cork>
 <CANpmjNPGd5GUZ0O0NuqTMBgBbv3J1irxm16ATxuhYJJWKvoUTA@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <CANpmjNPGd5GUZ0O0NuqTMBgBbv3J1irxm16ATxuhYJJWKvoUTA@mail.gmail.com>
X-Original-Sender: joern@purestorage.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@purestorage.com header.s=google header.b=U90fnHnQ;       spf=pass
 (google.com: domain of joern@purestorage.com designates 2607:f8b0:4864:20::1029
 as permitted sender) smtp.mailfrom=joern@purestorage.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=purestorage.com
X-Original-From: =?iso-8859-1?Q?J=F6rn?= Engel <joern@purestorage.com>
Reply-To: =?iso-8859-1?Q?J=F6rn?= Engel <joern@purestorage.com>
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

On Wed, Oct 14, 2020 at 04:25:41PM +0200, Marco Elver wrote:
>=20
> While I can see that it'd be nice to catch larger and larger OOB
> strides, I'm not sure where we should draw the limit.

Ideally you wouldn't.  An alternative design would reserve a virtual
memory chunk, maybe 1GB to pick a round number.  If you add a bitmap of
free pages, you need 1GB/32kB or 32kB worth of bitmap.  On allocation
you search for a free range large enough for the allocation and guard
pages.  Notice that this works for larger allocations as well, you're
not limited to 4k.

Scanning 32k from the beginning is clearly horrible, so you remember the
last position you scanned in a per-CPU variable.  Different CPUs have
different cursors, reducing the odds of stepping on each other's toes.
You should also limit how much you are willing to scan.  A 64B cacheline
worth of bitmap would cover 2MB, so maybe 1-2 cachelines.  If you don't
find a good spot, fall back to regular memory allocation and move your
cursor to a random location for the next allocation.

Anyway, this is bordering on a bikeshed discussion.  You should get the
existing patches in first, then we can consider possible improvements.
No point blocking a 98% solution just because it could be a 99% one.

> > Unmap could be made cheaper by doing it lazily.  It is expensive,
> > particularly on large systems, because it involved TLB shootdown across
> > many CPUs.  It can also amplify latency problems when you keep waiting
> > for the slowest CPU.
>=20
> It already is done lazily. We only invalidate the local CPU's TLB (on
> x86) and no IPIs are involved.

Nice!  I haven't read that far yet, but clearly should!

> We have found that a sample interval as low as 10ms is still not
> noticeable. Since the tool is not meant as a substitute for KASAN, but
> a complementary tool, we think sample intervals for a large enough
> fleet will be closer to 1sec. But here our current guidance is to
> monitor /sys/kernel/debug/kfence/stats across that fleet to decide on
> a suitable sample interval.

I'm leaning towards being more aggressive, but I also tend to receive
all those impossible-to-debug memory corruptions and would like to get
rid of them. :)

J=C3=B6rn

--
Luck is when opportunity meets good preparation.
-- Chinese proverb

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20201014145149.GH3567119%40cork.
