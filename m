Return-Path: <kasan-dev+bncBCD3NZ4T2IKRBUVZSLZAKGQEJGZ5YMI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13c.google.com (mail-il1-x13c.google.com [IPv6:2607:f8b0:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id 80D5515B617
	for <lists+kasan-dev@lfdr.de>; Thu, 13 Feb 2020 01:48:19 +0100 (CET)
Received: by mail-il1-x13c.google.com with SMTP id o5sf3213700ilg.19
        for <lists+kasan-dev@lfdr.de>; Wed, 12 Feb 2020 16:48:19 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1581554898; cv=pass;
        d=google.com; s=arc-20160816;
        b=mlYuLL5xjm9ZkxRvNDbZY/OoTIiBhSvjsJ6MhZql749v+BPYBiuOk/tsnnUHjCEYAL
         LK5o6nbKvxGZsjYSDXgrsgBeaDBIzbT3/ylAvnnvC+9R+W+zaRjSHEuOqO99eKHnhNM/
         UeVC2YSvf22kxT11Nms3j1ApAFZOJ2O5vlc/XVnJuAC2ARS3Rke/fHF/lz/+oc7AL5QW
         NsIkY1M7Vu6yOinOH2jtqjTIcKyPm1BKqh0V2I0joBJljkGhLD43uqQ3OVQodlUxXU3I
         N1RE1HcwkDIKodLJFgbg5ETJpLUZlzV9OjIYgL9wQvyuH0wyyoRFLAWajAfkFt4bVqgq
         fRfQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:references:message-id
         :content-transfer-encoding:cc:date:in-reply-to:from:subject
         :mime-version:sender:dkim-signature;
        bh=6/4XiE6RjNgjBuGVtSdlCAjImXowCAoZsxFPvnjBXHc=;
        b=qulU1C1tjbUUunS+zt2IhiHiTle5AuhdHuV0xFxRjc11SjQyzNh2wRCoazLbC4c7/V
         mZMcHKXI3Id7nhPOtL7QMIYYnDhHTZldM/+LmJVQD7fcpYgtq4IvGB1lOSHfpTJNVQnE
         pnZW1U3x/DD1x5KmOOAC9daOFXTU5uQO85LSm58v3X6/0SQzxKaCwRYxVHz8wLgePv4M
         uvCBXIOnM4Y4oqC3vhARZfgczchV+j3LPFN6O2dIyy7qFCxbGwHE5TFu+qukJb0maG4Z
         ZVa/r9GuSThPkVMOsCVTCWzTdugMr+0suqmwtiDZmQy1xeTWdIhq1kMWfH0E6adE7N0j
         iLxQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@lca.pw header.s=google header.b=aSjmmByi;
       spf=pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::742 as permitted sender) smtp.mailfrom=cai@lca.pw
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:subject:from:in-reply-to:date:cc
         :content-transfer-encoding:message-id:references:to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=6/4XiE6RjNgjBuGVtSdlCAjImXowCAoZsxFPvnjBXHc=;
        b=MXonXrWhHi8XQSKHCnFass2jSKlPP1022rsK7NmCqWWxH0KTD+8lrMqBCqvKokD1Oc
         JR0JAqZN8OSSVb/DxiikF8cCiWu7d8up67AAOz37kufvxynKzPg7Gtm5Zs3NaUMWpB+5
         9p3nj1M2+GQxNAT7dlTUOY0xI0m6hTiJVcgo9zPr5OMw2PbkOxzkfNIkjwEZ9Gt3Rzaz
         Hs7D9oysrfBYFmSDXP5eZOopwfppuSEmWcOY8Bp9vLDaXPOCj2wckGpG7D6qqiwVH1V+
         tpA+OUGmRR/LhGdUuOJ3o7kIOz4beL3Nnael2ljo65CfXhEneiVD3wMBuGZ+L7Dgc9W5
         rUTw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:subject:from:in-reply-to
         :date:cc:content-transfer-encoding:message-id:references:to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=6/4XiE6RjNgjBuGVtSdlCAjImXowCAoZsxFPvnjBXHc=;
        b=PnIP9FtquK8barEn+Bi/QDDXdyG0Igz0yD+IT8jq6VTFmZLUEUl4mJ3zTJE2yrbaXS
         iLXTuQWACKGePet/AuQLIu5gkQJGZcKnuN5p5HnJW4h0EjehD+WmKpxv7UVTs3MfHYYG
         wFpD/mxm8ljI7U9beU0gW2d8Rr+3pASHWEyhPFLZtfBsRMrXIt1s1SqmXAGWodYuAKx7
         GLA3/5BtZ1A6YRFCsp8306nQHxKH8cvqcaiVIxA61OPbuFPGHYgJwVnpKuxBgYKh6K4g
         NpJVEtbSLaSbH81lx1vqc3P7A3NnYHRmQ3mnZi9Uki/6MSe2qJ4DMdLKcjeGfvuRoa1a
         vs6w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVYlYJWmxJqU2lBWKzkFr75nRH6mfoHrjhlEwU06LoNjcdRSdTZ
	BsK3H3TCtXqnYdAY8hPSKzY=
X-Google-Smtp-Source: APXvYqyJHr/Ao/5Ktu2SyhiyFzoqxjY+zt3Wf9ne9R5F38B7NSZUcB8qw4d01FAvzztxdCdyw+d4hA==
X-Received: by 2002:a6b:7902:: with SMTP id i2mr1205723iop.67.1581554898254;
        Wed, 12 Feb 2020 16:48:18 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:1d89:: with SMTP id g9ls4186165ile.3.gmail; Wed, 12 Feb
 2020 16:48:17 -0800 (PST)
X-Received: by 2002:a92:91c7:: with SMTP id e68mr14092563ill.161.1581554897820;
        Wed, 12 Feb 2020 16:48:17 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1581554897; cv=none;
        d=google.com; s=arc-20160816;
        b=YZsrKghUAHSX1W1TXANyFX1mG87kpmenoHzUxK4cCXX9DljoVg4wVlArRAmQR+m9Ho
         AO6qISeAz+MQ2l0m/SghkwlZpDZw3fDFiMfcdkzy3++Kc3yUaSrd0+zEg+6vZ3ZuY0z7
         ht71lkYuyy7ftKocI/kmsD4mOoA++yWXcLEUfuDGd8gBLrR9kRStrcHRCc/TWfgYEK7T
         tt7hDXhNYPjByJevgJjamHdwhiR5l5BaXoLHcgEhbW7YiELx2+9EcBZhCr0usi1kMxw9
         OzQMefoea8CDBXyMK34ILdPeZDoYm8leR2Ty0ddwJTQZ4/lx4bmG5FOciRoMkZhkR1rH
         vbyw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=to:references:message-id:content-transfer-encoding:cc:date
         :in-reply-to:from:subject:mime-version:dkim-signature;
        bh=179Yt5PBUg2b6L8viYwRFsPlTIoidUR/f0EhWo/bqrQ=;
        b=FB3LRWsEnVfFawyzIk84IvH9dLAW3AFQKLZa/LYI9u57g0erZDcRfCKni+nm5XCQkW
         snvdrTY3Vv0bPLU/pASdc8k9m+C5v0Bxa/YTAqw6CXv84vtNsJLwRip2R67sywcyhw2Y
         Vqknq8NDRgYFtthTy52CyRaVtj7ntpg24YVpTLlpsvSPW1BH1TUiSwjJ0CZIZrvWdDxK
         gJPZFWl1NMaGJEskvyWwmTEI42tr5lnts2g0lbsUCgI4tVva4JeyqBqSJu1/zZVXUcWA
         Zzki3OOMvkUdRlXu1J05l3kQAsHBB2l+3Hh6tVKraBwGDpF0b3pnDv4iatDSCKQunjjN
         IS/w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@lca.pw header.s=google header.b=aSjmmByi;
       spf=pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::742 as permitted sender) smtp.mailfrom=cai@lca.pw
Received: from mail-qk1-x742.google.com (mail-qk1-x742.google.com. [2607:f8b0:4864:20::742])
        by gmr-mx.google.com with ESMTPS id i4si41388ioi.1.2020.02.12.16.48.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 12 Feb 2020 16:48:17 -0800 (PST)
Received-SPF: pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::742 as permitted sender) client-ip=2607:f8b0:4864:20::742;
Received: by mail-qk1-x742.google.com with SMTP id w25so4092785qki.3
        for <kasan-dev@googlegroups.com>; Wed, 12 Feb 2020 16:48:17 -0800 (PST)
X-Received: by 2002:ae9:c318:: with SMTP id n24mr13889195qkg.38.1581554897259;
        Wed, 12 Feb 2020 16:48:17 -0800 (PST)
Received: from [192.168.1.153] (pool-71-184-117-43.bstnma.fios.verizon.net. [71.184.117.43])
        by smtp.gmail.com with ESMTPSA id 13sm356902qke.85.2020.02.12.16.48.16
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 12 Feb 2020 16:48:16 -0800 (PST)
Content-Type: text/plain; charset="UTF-8"
Mime-Version: 1.0 (Mac OS X Mail 13.0 \(3608.60.0.2.5\))
Subject: Re: [PATCH v2 5/5] kcsan: Introduce ASSERT_EXCLUSIVE_BITS(var, mask)
From: Qian Cai <cai@lca.pw>
In-Reply-To: <20200212214029.GS2935@paulmck-ThinkPad-P72>
Date: Wed, 12 Feb 2020 19:48:15 -0500
Cc: Marco Elver <elver@google.com>,
 John Hubbard <jhubbard@nvidia.com>,
 Andrey Konovalov <andreyknvl@google.com>,
 Alexander Potapenko <glider@google.com>,
 Dmitry Vyukov <dvyukov@google.com>,
 kasan-dev <kasan-dev@googlegroups.com>,
 LKML <linux-kernel@vger.kernel.org>,
 Andrew Morton <akpm@linux-foundation.org>,
 David Hildenbrand <david@redhat.com>,
 Jan Kara <jack@suse.cz>
Content-Transfer-Encoding: quoted-printable
Message-Id: <79934F2A-E151-480F-B1B1-1C713F932CEC@lca.pw>
References: <CANpmjNOWzWB2GgJiZx7c96qoy-e+BDFUx9zYr+1hZS1SUS7LBQ@mail.gmail.com>
 <ED2B665D-CF42-45BD-B476-523E3549F127@lca.pw>
 <20200212214029.GS2935@paulmck-ThinkPad-P72>
To: "Paul E. McKenney" <paulmck@kernel.org>
X-Mailer: Apple Mail (2.3608.60.0.2.5)
X-Original-Sender: cai@lca.pw
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@lca.pw header.s=google header.b=aSjmmByi;       spf=pass
 (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::742 as
 permitted sender) smtp.mailfrom=cai@lca.pw
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



> On Feb 12, 2020, at 4:40 PM, Paul E. McKenney <paulmck@kernel.org> wrote:
>=20
> On Wed, Feb 12, 2020 at 07:30:16AM -0500, Qian Cai wrote:
>>=20
>>=20
>>> On Feb 12, 2020, at 5:57 AM, Marco Elver <elver@google.com> wrote:
>>>=20
>>> KCSAN is currently in -rcu (kcsan branch has the latest version),
>>> -tip, and -next.
>>=20
>> It would like be nice to at least have this patchset can be applied agai=
nst the linux-next, so I can try it a spin.
>>=20
>> Maybe a better question to Paul if he could push all the latest kcsan co=
de base to linux-next soon since we are now past the merging window. I also=
 noticed some data races in rcu but only found out some of them had already=
 been fixed in rcu tree but not in linux-next.
>=20
> I have pushed all that I have queued other than the last set of five,
> which I will do tomorrow (Prague time) if testing goes well.
>=20
> Could you please check the -rcu "dev" branch to see if I am missing any
> of the KCSAN patches?

Nope. It looks good to me.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/79934F2A-E151-480F-B1B1-1C713F932CEC%40lca.pw.
