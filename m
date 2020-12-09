Return-Path: <kasan-dev+bncBD63B2HX4EPBBRW6YT7AKGQECKVESDI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53a.google.com (mail-pg1-x53a.google.com [IPv6:2607:f8b0:4864:20::53a])
	by mail.lfdr.de (Postfix) with ESMTPS id B3DB52D4B4D
	for <lists+kasan-dev@lfdr.de>; Wed,  9 Dec 2020 21:10:47 +0100 (CET)
Received: by mail-pg1-x53a.google.com with SMTP id o17sf1807548pgm.18
        for <lists+kasan-dev@lfdr.de>; Wed, 09 Dec 2020 12:10:47 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1607544646; cv=pass;
        d=google.com; s=arc-20160816;
        b=w7/XTibZUtuZSinh9JYr2EWw1m3bViDZMrCKNCPb4YdgxHFoh2ru5Nxn9bDCh+IQFb
         tq6MEdtegxYQsZ/6aTkg4GMV43dlfRsoayCP9EIQWb9UtaYa1WuuFSbCG3WAJ8NGVdEb
         xQQKZJNLoOktMZx7cHmHdUQqlUaBcf1YJT0a21qa2vWiJ2Y2Lsdc7g9+n3O3K5btA5Qe
         avDVc/zrxIGEW+sbwkjHFh7PVE8UBjYcgiOV9Rsf99zTTKuuKLogscoD+1xn3xK9L4of
         V7QMcWhfkz0douM6fL+Lasxw1Chie2ZcEhjCc1rZaNhPgdnUgllxQ9Sc+b9G3XS+KR/2
         JYSA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:dkim-signature;
        bh=WlsdznmuukOJrFh1s/gyZR8bdxgKyT0BdWn4S1r77S0=;
        b=jyjX+2j+rgOFzJHm+uf82aQWBR5FFEzzYNZj3DiFShUSMdj+ZmBbh3+4/VIymDRDJJ
         J000fSHZHRff8P3NJlupl3PwN+dpjqgaUASDaWqA2/0QkuCT+B50mhmyzzJLfnbXoLkd
         mma3bCRIu1ajCbPYQG9FTSeEs4jCueSpnxsUOUEvdoNZ0MEaC2xzZpYGG6kyJa5QHAhy
         igBlbEp3ipXzbH3L3f75hXBMaK+NPLYCrXmVxPjSN7uDhpiKSdpEquJHV4jsiMwEaX0j
         z+aMXdqrmPjxiGQmHNAU+VTszPOy0Z237tQO9e/5YbUoC52si3eiEZf197lFnuEMvj60
         t/rw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@purestorage.com header.s=google header.b=Sq2PAwKz;
       spf=pass (google.com: domain of joern@purestorage.com designates 2607:f8b0:4864:20::634 as permitted sender) smtp.mailfrom=joern@purestorage.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=purestorage.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:content-transfer-encoding:in-reply-to
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=WlsdznmuukOJrFh1s/gyZR8bdxgKyT0BdWn4S1r77S0=;
        b=tdgnnV35AfSUrunGtyjCHXAzA8QT4ya/R4HcqltvKNVguklo2+/IEu+ueBccv3lP3O
         ioS62EOpLYBGYXsKo0Me16rNKgdKZ/HRv8oq/wGRwGpP9msbwHwDADB/n9wLqnEPYopc
         4a0t30Yrk1jK5/EVG4hwkFtYKpo1hStoN+6i+wXq5oFLYHWlb3u7n4h4a4giz0vaPdiT
         vHW4Jbqu/sZ86bcanI5MyJWAheoLpz/k3K+ylZCOxnCx1ECHKVtqp9Ssff+3+nIlLbTg
         VGk7XIWrJyR7FolxKZ8Arr8vBYo7TW462SA4LjpgOLmkrAeBOprj06VW7Tr3ML3k0Lxs
         yojg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:content-transfer-encoding
         :in-reply-to:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:x-spam-checked-in-group
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=WlsdznmuukOJrFh1s/gyZR8bdxgKyT0BdWn4S1r77S0=;
        b=I3QZAyH/AHzNBQnBUhI2aMfGkjnsymxM3oKiCQKhXh96R+JCbJtIX5tpNi2uKEzIKM
         QMEd0fU8eRmfkFMOyZkwoBpLQlnMSAOR3BWCuC9WNLvCtV00txPniSPB6MVN1m058wL9
         cYKzus+5aN1ttsO2/+q2pojCyFeSA9HP6N7stFZ9UpflW5/a7J/SKtcimaTeDYjo+gVR
         LZI9TaitkLR+rqapKFe/IcsT655gWR88E7VZO0XD/X4EdVKtLxCR4S5vLBQcAU3WtgG6
         r988MTP1QcQfdpxCYChuzCO6NJtTE5H8d7mrDT0Y5X+VNSEO27kj9FnezKucCNeV6rBn
         tKjw==
X-Gm-Message-State: AOAM531UovZP5TQcnn54Xhhz7+KfUpx/okLEEbyQFaNlUlIahDplOwP9
	TpxbINDEr3mHkpP/lcifoAs=
X-Google-Smtp-Source: ABdhPJwqadN35jFT1gMg/V8XSVR4RlfVBLFpZVF2YpLgeHJ4n4Zrfy615GT7gTcV9hf4f9+YpNVfdw==
X-Received: by 2002:a63:ef15:: with SMTP id u21mr3506997pgh.56.1607544646202;
        Wed, 09 Dec 2020 12:10:46 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:2c94:: with SMTP id s142ls1091997pgs.9.gmail; Wed, 09
 Dec 2020 12:10:45 -0800 (PST)
X-Received: by 2002:aa7:8003:0:b029:197:eb02:d711 with SMTP id j3-20020aa780030000b0290197eb02d711mr3816253pfi.72.1607544645636;
        Wed, 09 Dec 2020 12:10:45 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1607544645; cv=none;
        d=google.com; s=arc-20160816;
        b=oTNuZIuGVubaWORngfqu5v80dEupGCH74sBHpvi9fnMK/xyQvbI1P2Hm5bzyHsnC0j
         23AuJMvdUqR6dVK6c7K0uKibyk8H4rK7JLWTDBycxnkdmJkizh8mMiWW7UasFy+jqRnm
         VuNa5C9idxKh7klzeaOciyj+jS8AIB3LQNxEw28trLd9z2KZo0FJOuILdXHoYeV5+KH/
         sY6fIrkkqjPiWp+hTZF1G7Ojd3x79JTNvMdflSF/1tdNaHd2bfqVMmdZUcaE6rPLZqXS
         cmLftxEkd/C3eluQYz05cYKDopyEO5XA0kQ7KhiE1RHjhfHZScmiojxkWuwzPc2wO63Z
         Qmkw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=fgk8+uxZmmYvhmlZ6tB9qZRW0HU6HEQlM4eqDuMo+7U=;
        b=bzmIaZMnbNgk8O3ASV768KDU+89KeFMxFuu1GFNQJQUcJYJPjiBzSg0DlO7ohbHhIi
         oAp34/XGksia8VFckxUoACJ7IX5ztjI+tHOUJEJIRYatzUMxkdiJJsjy+LwUxfLXbC1n
         8/SF71ZNK5Uut+VmDEj/NpRy7bzDhy1SFjPBhazTZzxrnFBc4PUywBeyobn7K1tb/I9h
         uy2rQmTcVgFtE7wp97GBCu14M5FUjsIUIVVDfkRj33Q6mJ2qurHc89FTLwDBRqLvS79c
         AuK177EeD6S/TvrH6xCIU8zF5KXkU+es+/gWqcIYrqa9vOHY+vf5Ys7TtBFsX4LH1gm/
         N+aA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@purestorage.com header.s=google header.b=Sq2PAwKz;
       spf=pass (google.com: domain of joern@purestorage.com designates 2607:f8b0:4864:20::634 as permitted sender) smtp.mailfrom=joern@purestorage.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=purestorage.com
Received: from mail-pl1-x634.google.com (mail-pl1-x634.google.com. [2607:f8b0:4864:20::634])
        by gmr-mx.google.com with ESMTPS id ne6si3392pjb.1.2020.12.09.12.10.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 09 Dec 2020 12:10:45 -0800 (PST)
Received-SPF: pass (google.com: domain of joern@purestorage.com designates 2607:f8b0:4864:20::634 as permitted sender) client-ip=2607:f8b0:4864:20::634;
Received: by mail-pl1-x634.google.com with SMTP id g20so706805plo.2
        for <kasan-dev@googlegroups.com>; Wed, 09 Dec 2020 12:10:45 -0800 (PST)
X-Received: by 2002:a17:902:7149:b029:db:a6de:4965 with SMTP id u9-20020a1709027149b02900dba6de4965mr3473859plm.3.1607544645342;
        Wed, 09 Dec 2020 12:10:45 -0800 (PST)
Received: from cork (dyndsl-091-248-061-095.ewe-ip-backbone.de. [91.248.61.95])
        by smtp.gmail.com with ESMTPSA id y69sm3501094pfb.64.2020.12.09.12.10.41
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 09 Dec 2020 12:10:42 -0800 (PST)
Date: Wed, 9 Dec 2020 12:10:38 -0800
From: =?UTF-8?B?J0rDtnJuIEVuZ2VsJyB2aWEga2FzYW4tZGV2?= <kasan-dev@googlegroups.com>
To: Marco Elver <elver@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>,
	kasan-dev <kasan-dev@googlegroups.com>,
	Alexander Potapenko <glider@google.com>
Subject: Re: GWP-ASAN
Message-ID: <20201209201038.GC2526461@cork>
References: <CACT4Y+Z=zNsJ6uOTiLr6Vpwq-ARewwptvyWUEkBgC1UOdt=EnA@mail.gmail.com>
 <CANpmjNPy3aJak_XqYeGq11gkTLFTQyuXTGR8q8cYuHA-tHSDRg@mail.gmail.com>
 <20201014134905.GG3567119@cork>
 <CANpmjNPGd5GUZ0O0NuqTMBgBbv3J1irxm16ATxuhYJJWKvoUTA@mail.gmail.com>
 <20201014145149.GH3567119@cork>
 <CANpmjNPuuCsbV5CwQ5evcxaWd-p=vc4ZGmR0gOdbxdJvL2M8aQ@mail.gmail.com>
 <20201206164145.GH1228220@cork>
 <CANpmjNNZDuRo+1UZam=pZFij=QHR9sSa-BaNGrgVse-PjQF5zw@mail.gmail.com>
 <20201206201045.GI1228220@cork>
 <X83nnTV62M/ZXFDR@elver.google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <X83nnTV62M/ZXFDR@elver.google.com>
X-Original-Sender: joern@purestorage.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@purestorage.com header.s=google header.b=Sq2PAwKz;       spf=pass
 (google.com: domain of joern@purestorage.com designates 2607:f8b0:4864:20::634
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

On Mon, Dec 07, 2020 at 09:28:13AM +0100, Marco Elver wrote:
>=20
> I ran benchmarks where count was (2^31)-1, so only the branch and
> decrement were in the fast-path. That resulted in a 3% throughput
> reduction of the benchmark we ran (sysbench I/O). Details here:
> https://github.com/google/kasan/issues/72#issuecomment-655549813

Took a look and this is triggering my bad-science-detector.

In the office, I regularly reject benchmarks that do only one run each
before/after.  We often have 5% noise between successive benchmark runs
without code changes.  The minimal quality I demand off benchmarks is 3
interleaved runs, so ABABAB.

Usually 3 runs each are enough, but sometimes I do more to get a more
precise answer.  1 run is a waste of time - either you care enough to do
proper benchmarks or you don't. ;)

J=C3=B6rn

--
Given two functions foo_safe() and foo_fast(), the shorthand foo()
should be an alias for foo_safe(), never foo_fast().
-- me

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20201209201038.GC2526461%40cork.
