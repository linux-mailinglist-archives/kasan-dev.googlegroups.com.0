Return-Path: <kasan-dev+bncBDW2JDUY5AORBMO67W6QMGQEOOJZ7NI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33f.google.com (mail-wm1-x33f.google.com [IPv6:2a00:1450:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id 61991A46B4D
	for <lists+kasan-dev@lfdr.de>; Wed, 26 Feb 2025 20:44:51 +0100 (CET)
Received: by mail-wm1-x33f.google.com with SMTP id 5b1f17b1804b1-43943bd1409sf1686995e9.3
        for <lists+kasan-dev@lfdr.de>; Wed, 26 Feb 2025 11:44:51 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1740599091; cv=pass;
        d=google.com; s=arc-20240605;
        b=gREXkwNSECl1AO+pXRLcZvfalZV7LGMVjqBspDKZpSQ4MNZQHO4OqZfunaFhC4hSb4
         KxchBBn0KEUzqEDEBm6hiIF0v06DuE/J9yYBdQCv3elob54wcdOdNbxiOOsLFThKqvpK
         egZwmm1EnnF6SMqMyCKBrmoTyhfzsrf03/gKzUHnhD8Tf0Si/OcRZGk7L7pZvD9bHXB3
         262HJx/+0GiiqueQdFC1iwiWuScGvrjqXHsf3Sh+lXyvQDUqppSHPP9joY6faKHi28rk
         StSXYg25M8adJGw/4Sr5X4bjQWejQEW+A8nqZIlZq4NsiIsnpQzq2MVDQBSVa8rjAss3
         XvEw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=G5S0oxvXJU4TtjPDDOBSwgq3y3e3dXyzYh9gaoOj5gU=;
        fh=Ap1NMok8aI7Ua+wDw+U+/SPaaYhtKChj3FjVeGN18qk=;
        b=MI87TQNmH+RU9xKBJgNZkzOhT0lYt9enQtaCcKjmWoN0ftLCZ2lnRTtmm8jkgHkryf
         MCbNTTNOfIKPuitIAQdKalHzC9ctKiPKkGe6l1X8SYIlAPXwsE2MkEdSbS1pZYDLFg5A
         RaXv0ub1GQzbeFTv1EYPyMJ65qmi3KuehSKRKdHhVqIMduu4QDDUJuxZQdEwdq5QqGgK
         BH82Cg0PQ0Wnq2/5MBY0/9T6CgJ1LjK3M0PDrRNiyAgY2fKPLtW757Me+Tv3LpYM76mZ
         NFx7FBZWzvkM4W4xFzUh7JCUof9aNqooKamlOmi8952lp5c+yRVQHKp+6lgw1gkBN9q7
         /S2Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="iaYUTeJ/";
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42c as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1740599091; x=1741203891; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=G5S0oxvXJU4TtjPDDOBSwgq3y3e3dXyzYh9gaoOj5gU=;
        b=N2MCA8T1oBNO4PHjPO1Xo+IZY5O/NmneOpfBji/7hFQmdIzA1wIoivWYsIJkhlSsQp
         CdEKAKKtCyS29Hqhtai8Ot6rnXD2poGCSLrHDNgNJLD1rOTkexIxd+hJDA3DdEXlarab
         slunuy3mnv3HjD/bvEAV658VORCZAm8T2f0zGf7whH1r5PEJLlCJKdWk0B9bzh8ZHSJB
         WnE8ECiIaD01F+HFZoAbkID7LXjRyiCjZkkiADyXmIb6C3bBepoLzFDOw1tOI3SfJvCO
         u4rKWIzAnLc7qdRegRvyWdZc07WVle+OtEZwZQmnWZ2M96gI91NhkR2Dn/BoWU0a4KU6
         CFiQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1740599091; x=1741203891; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=G5S0oxvXJU4TtjPDDOBSwgq3y3e3dXyzYh9gaoOj5gU=;
        b=Lp4hqbfHH19Fx/KWV6Hj8wFK7hNfAJtgdivR12rjAqWP06obu/hTEBwOnpf7NowGso
         0hNTPZBgKkmcx2OfizRy+noNjEboFea8+c/ynLp5FwFMih2EXRAAjXGWUKWH3pKBMJ3e
         kE8mmXoWzqQJFmQGZTEFQNO/20Jyo+niWOEalh2gkq2OPzWBNOQdUs+sHYEMM8yl/T3d
         dtyT/lCzCPT9sB8CCnkh+c8Prm9XLgYYmg4St13sjjOCpNBv5WFjRcJUN8aqZxmC//xk
         Fy4u7zgHBj1vf8Iq3xy2vjhX8xZlG0FBPE5DFL5FoK19t1WOlbEQUG5Z2GmG8Jx4sma+
         WWxQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1740599091; x=1741203891;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=G5S0oxvXJU4TtjPDDOBSwgq3y3e3dXyzYh9gaoOj5gU=;
        b=FqbBa582QZ626omM2z5s2lSmsS50b+JDv9gfeXxNqm4a7UdCKLe3FRyi1o0lOS9Ge3
         +S4nuSGe+a0+ge/8e5qKjB2B15LQ53Is88cQt5tAcG1pwraqtXcLR4fPsrPxr7IbSiNw
         FgVqjX9di4P1/gIoF3lFWr8elnPZxjmMfsG3EH2GKzJ/VnhJUUSy4XnRg6eK5qIvdd3n
         qFzn/Yit/V2y2Hmuy8BpijU6+FRwRpIeGoCISEltGHMGvAz6FIj4qxnE+SrxQLVuIJ1y
         hH6yLnzS4H0yEhHCGuGPqfbhX5WME8nunsV3AHb8TGVv8nAxCmKouMl8kKCy83oyXcBN
         A9Bw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCX5RhjiwzwGftmTikZe01r62x53Bqj+siLdrV7wHP4T9xm3EROFQ4qvaTMpSkKRISTjbXXIyw==@lfdr.de
X-Gm-Message-State: AOJu0YwqF6rKrUbcEsV1Lmzn6Kp7aVFmn/r5uFG0OqmtYobWV3n/ojia
	aLPqO/iI0hmJLbCX9BtbhsXsYT95J8d6wHWZmnmAcUBVWoQqCXcr
X-Google-Smtp-Source: AGHT+IFUb6hrbqeQUdNuuHfewiSqYlJk9g+1nRqIUVQOGTZHUrhoeP5DBlB0SRBA795eDnbKZKsbSA==
X-Received: by 2002:a05:600c:4506:b0:439:6e12:fdb4 with SMTP id 5b1f17b1804b1-43ab8fe90camr48695195e9.14.1740599090362;
        Wed, 26 Feb 2025 11:44:50 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVFjDUU14dgUaYy/pMgdfYqCNwhiuLwvo5Aq4LA2jiu7qw==
Received: by 2002:a05:600c:468c:b0:439:8202:ee83 with SMTP id
 5b1f17b1804b1-43af792f5c3ls956875e9.1.-pod-prod-09-eu; Wed, 26 Feb 2025
 11:44:48 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVqUb2NKmGodkZOK+SzcZE2FAlIoNqmMhJl5r/yXf8GarmPqdl6cXONxdH+/vA7QlwFlQfxDLNk820=@googlegroups.com
X-Received: by 2002:a05:600c:3506:b0:439:6dba:adf2 with SMTP id 5b1f17b1804b1-43ab8fe7734mr43930135e9.15.1740599087975;
        Wed, 26 Feb 2025 11:44:47 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1740599087; cv=none;
        d=google.com; s=arc-20240605;
        b=hcOqkwyAIXRvkMC6uWCuFd0rH6aTvo6j0U7RznZTRKQrcIx1EE9e0Q3swSKtN0GS+h
         bQPu0U19lNyf+N52MHeuUGGB970vNzoeXA6SpjgiGdppDfKqhn1pdPKj2foRTgsQROJR
         BZLYGoqXyYhvfrVFQPcBJl1ZbRahlvJKcMVYwLGGLVqFzcB5UXXDmgxcHxkOZaFSclbd
         jtIrpKKYsUCnLAA9+SHe459jVBZSOmT5vkLioCWgyKtM7j0DxAi9heldRUHcKci6jUna
         7lFwSVI/k6KeIAT0o+9Y3zQbNgiJVgweII55SsIY3D0mk74H5H+oVqyIhbNAOSL0tDxh
         XPgQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=0ALXJzO2ZhXP82Zb99HSpRWAbbmI+C+3+0buhND8ud8=;
        fh=0KmqBLdGok7yBD0iy98LKbFYXNbaX0Qo41S8E+/tLE0=;
        b=L/pg3Vm2G5rPDJGmD+zWsfN9sjjxju220ytb8GEsO9ju0FSW+bVs41u1eoFHvqAz/y
         pLBSbmzzrGNLW8EZcxGNSVEmY7OeehmgBq0RIG3+JzcIaEeVZ9Tz6eRghjXZtYqIHLzQ
         h6uan/0Dzpga0QdNOIcws8DPrusxyRHuUD9cJI57d4xyp2YLqtTChgWnixbx1oBJXQYk
         QE9OGpXpavfW2kBSTu4jgQR+xIt7ueZI91In9+muG6Giem5xXpgnrfpc1nNJfH100yEW
         6xYjejVqTpZCaLcFMZCUiFvCBhjltN3WHVXh/tfaWt8+ouj65+0DC4VUB3khSBn2DlGM
         D5lw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="iaYUTeJ/";
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42c as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x42c.google.com (mail-wr1-x42c.google.com. [2a00:1450:4864:20::42c])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-43ab374a2adsi2892375e9.1.2025.02.26.11.44.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 26 Feb 2025 11:44:47 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42c as permitted sender) client-ip=2a00:1450:4864:20::42c;
Received: by mail-wr1-x42c.google.com with SMTP id ffacd0b85a97d-38f406e9f80so71323f8f.2
        for <kasan-dev@googlegroups.com>; Wed, 26 Feb 2025 11:44:47 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCWuBWxW/JgefSwSztdD6Ip9m/oOe3urq0e/1C6n1bHKzAlPGroSszDCeRBnoGHmg2IvxWT079Tt3W8=@googlegroups.com
X-Gm-Gg: ASbGnct8XoDivHmiu8C7IEJrxDaODDtJWnWUVz5o7obJLUgNYwOos/MVIkAAaswRhgz
	GNYMp8Jh9VQjw61WUJz4QTgDoI4CysGjQD8vkSZOOXNtYnawN3Ly7pLjKa9fCUx3dBYv7VsTLw9
	qaDVL+v34Fjg==
X-Received: by 2002:a05:6000:1848:b0:38d:d5af:29af with SMTP id
 ffacd0b85a97d-390d4fa3e25mr3522475f8f.49.1740599087190; Wed, 26 Feb 2025
 11:44:47 -0800 (PST)
MIME-Version: 1.0
References: <cover.1739866028.git.maciej.wieczor-retman@intel.com>
 <168f775c4587f3a1338271390204a9fe16b150dd.1739866028.git.maciej.wieczor-retman@intel.com>
 <CA+fCnZcVSwUAC9_xtVAHvO6+RWDzt6wOzWN623m=dT-3G=NnTQ@mail.gmail.com>
 <cik7z3nwspdabtw5n2sfoyrq5nqfhuqcsnm42iet5azibsf4rs@jx3qkqwhf6z2>
 <CA+fCnZd6O0_fc1U-D_i2shcF4Td-6389F3Q=fDkdYYXQupX1NA@mail.gmail.com>
 <uup72ceniis544hgfaojy5omctzf7gs4qlydyv2szkr5hqia32@t6fgaxcaw2oi>
 <gisttijkccu6pynsdhvv3lpyxx7bxpvqbni43ybsa5axujr7qj@7feqy5fy2kgt>
 <6wdzi5lszeaycdfjjowrbsnniks35zhatavknktskslwop5fne@uv5wzotu4ri4>
 <CA+fCnZeEm+-RzqEXp1FqYJ5Gsm+mUZh5k3nq=92ZuTiqwsaWvA@mail.gmail.com> <qnxlqbc4cs7izjilisbjlrup4zyntjyucvfa4s6eegn72wfbkd@czthvwkdvo3v>
In-Reply-To: <qnxlqbc4cs7izjilisbjlrup4zyntjyucvfa4s6eegn72wfbkd@czthvwkdvo3v>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Wed, 26 Feb 2025 20:44:35 +0100
X-Gm-Features: AQ5f1JrdMqMC3b0HBepr7R3zwbWYmhOcf6RK7JusOEJWTmRQO7QPte-5YIs-RgA
Message-ID: <CA+fCnZdUFO0+G9HHy4oaQfEx8sm3D_ZfxdkH3y2ZojjYqTN74Q@mail.gmail.com>
Subject: Re: [PATCH v2 01/14] kasan: sw_tags: Use arithmetic shift for shadow computation
To: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
Cc: Vitaly Buka <vitalybuka@google.com>, kees@kernel.org, 
	julian.stecklina@cyberus-technology.de, kevinloughlin@google.com, 
	peterz@infradead.org, tglx@linutronix.de, justinstitt@google.com, 
	catalin.marinas@arm.com, wangkefeng.wang@huawei.com, bhe@redhat.com, 
	ryabinin.a.a@gmail.com, kirill.shutemov@linux.intel.com, will@kernel.org, 
	ardb@kernel.org, jason.andryuk@amd.com, dave.hansen@linux.intel.com, 
	pasha.tatashin@soleen.com, guoweikang.kernel@gmail.com, dwmw@amazon.co.uk, 
	mark.rutland@arm.com, broonie@kernel.org, apopple@nvidia.com, bp@alien8.de, 
	rppt@kernel.org, kaleshsingh@google.com, richard.weiyang@gmail.com, 
	luto@kernel.org, glider@google.com, pankaj.gupta@amd.com, 
	pawan.kumar.gupta@linux.intel.com, kuan-ying.lee@canonical.com, 
	tony.luck@intel.com, tj@kernel.org, jgross@suse.com, dvyukov@google.com, 
	baohua@kernel.org, samuel.holland@sifive.com, dennis@kernel.org, 
	akpm@linux-foundation.org, thomas.weissschuh@linutronix.de, surenb@google.com, 
	kbingham@kernel.org, ankita@nvidia.com, nathan@kernel.org, ziy@nvidia.com, 
	xin@zytor.com, rafael.j.wysocki@intel.com, andriy.shevchenko@linux.intel.com, 
	cl@linux.com, jhubbard@nvidia.com, hpa@zytor.com, 
	scott@os.amperecomputing.com, david@redhat.com, jan.kiszka@siemens.com, 
	vincenzo.frascino@arm.com, corbet@lwn.net, maz@kernel.org, mingo@redhat.com, 
	arnd@arndb.de, ytcoode@gmail.com, xur@google.com, morbo@google.com, 
	thiago.bauermann@linaro.org, linux-doc@vger.kernel.org, 
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	llvm@lists.linux.dev, linux-mm@kvack.org, 
	linux-arm-kernel@lists.infradead.org, x86@kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b="iaYUTeJ/";       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42c
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
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

On Wed, Feb 26, 2025 at 5:43=E2=80=AFPM Maciej Wieczor-Retman
<maciej.wieczor-retman@intel.com> wrote:
>
> >What value can bit 63 and take for _valid kernel_ pointers (on which
> >KASAN is intended to operate)? If it is always 1, we could arguably
> >change the compiler to do | 0xFE for CompileKernel. Which would leave
> >us with only one region to check: [0xfe00000000000000,
> >0xffffffffffffffff]. But I don't know whether changing the compiler
> >makes sense: it technically does as instructed by the LAM spec.
> >(Vitaly, any thoughts? For context: we are discussing how to check
> >whether a pointer can be a result of a memory-to-shadow mapping
> >applied to a potentially invalid pointer in kernel HWASAN.)
>
> With LAM, valid pointers need to have bits 63 and 56 equal for 5 level pa=
ging
> and bits 63 and 47 equal for 4 level paging. Both set for kernel addresse=
s and
> both clear for user addresses.

Ah, OK. Then I guess we could even change to compiler to do | 0xFF,
same as arm. But I don't know if this makes sense.

> >With the way the compiler works right now, for the perfectly precise
> >check, I think we need to check 2 ranges: [0xfe00000000000000,
> >0xffffffffffffffff] for when bit 63 is set (of a potentially-invalid
> >pointer to which memory-to-shadow mapping is to be applied) and
> >[0x7e00000000000000, 0x7fffffffffffffff] for when bit 63 is reset. Bit
> >56 ranges through [0, 1] in both cases.
> >
> >However, in these patches, you use only bits [60:57]. The compiler is
> >not aware of this, so it still sets bits [62:57], and we end up with
> >the same two ranges. But in the KASAN code, you only set bits [60:57],
> >and thus we can end up with 8 potential ranges (2 possible values for
> >each of the top 3 bits), which gets complicated. So checking only one
> >range that covers all of them seems to be reasonable for simplicity
> >even though not entirely precise. And yes, [0x1e00000000000000,
> >0xffffffffffffffff] looks like the what we need.
>
> Aren't the 2 ranges you mentioned in the previous paragraph still valid, =
no
> matter what bits the __tag_set() function uses? I mean bits 62:57 are sti=
ll
> reset by the compiler so bits 62:61 still won't matter. For example addre=
sses
> 0x1e00000000000000 and 0x3e00000000000000 will resolve to the same thing =
after
> the compiler is done with them right?

Ah, yes, you're right, it's the same 2 ranges.

I was thinking about the outline instrumentation mode, where the
shadow address would be calculated based on resetting only bits
[60:57]. But then there we have a addr_has_metadata() check in
kasan_check_range(), so KASAN should not try to deference a bad shadow
address and thus should not reach kasan_non_canonical_hook() anyway.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
A%2BfCnZdUFO0%2BG9HHy4oaQfEx8sm3D_ZfxdkH3y2ZojjYqTN74Q%40mail.gmail.com.
