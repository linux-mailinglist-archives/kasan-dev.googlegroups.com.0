Return-Path: <kasan-dev+bncBC7OD3FKWUERBB4CU3FQMGQETRDYDAQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x138.google.com (mail-lf1-x138.google.com [IPv6:2a00:1450:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id A93D6D295D3
	for <lists+kasan-dev@lfdr.de>; Fri, 16 Jan 2026 01:06:32 +0100 (CET)
Received: by mail-lf1-x138.google.com with SMTP id 2adb3069b0e04-59b7e2b4a18sf921104e87.3
        for <lists+kasan-dev@lfdr.de>; Thu, 15 Jan 2026 16:06:32 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1768521992; cv=pass;
        d=google.com; s=arc-20240605;
        b=ZtP1FDFrjmVRaKIPhXavS95eDtx3pkni29rXG5yVUbNl4kCtQa+6q6mYHpCzgk3zav
         UXGfUIJhcv7p4K0ccDKmZwHmRFCKdD4VgS4UNfUvPcgHTCmqDbh2kAPWtBV4ItFlkbQv
         pRq7FFCJz5m4Xz5K0csa/FR6IzvKPsDhL0mpucW2ksyUe4F+EZxDqzBPc5IPNCYB2TP6
         G+T1fZacvwLT9QikvO5lFVju9A+0ix0Wk/iKzx0+NUAhGyP6xFWXmBISrH9zqeCSmVK4
         VGvUZg49obkJNkqSoNajsiTr0TW/D52lUILMldmag4KoDFVSWcvAO+Pld9xn65MHRJzS
         ckvQ==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Y7zdYfzRZKWkCHfkhW7fkkqxEZjIXjQ+JpiQLjroyPI=;
        fh=ZTXC4155+Cu6gnIOgnsQ1O9NDhRFZtDJS4RATGhF+80=;
        b=P25dOlOcpdXhZSlTE7nhhcEDIfXhAggo1TNpssKNybGHxtgjAHS6ubX/YA+hKYlyIa
         BL9yL/kOj4uE0NobqNw+TR7LkX1af8gogu2mJKjDBtbyQvHOwbONPHRpLdDHzdnQB7xF
         tSJJtBfqPHMaupvwAXqS3SVhGZBGGy2KiviB4cADkujXYpaLny2dK+5MdjiufLoZA42y
         7DEg5P9QHsZ0oKvcSH91Y0VFJguneM2NjPOpeeeW+UZqTz5UtKC5ML1d3oAn8iv0x+xa
         I20+Rx2HmkiUckuu56aPVpnQ8iPNncvATW7CFZDRuaoLMMcDgFlHtjhqKsegVcK2xbG1
         Yeuw==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=rQBm7DuO;
       arc=pass (i=1);
       spf=pass (google.com: domain of surenb@google.com designates 2a00:1450:4864:20::52c as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768521992; x=1769126792; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=Y7zdYfzRZKWkCHfkhW7fkkqxEZjIXjQ+JpiQLjroyPI=;
        b=OAsWIQUlFODs8Ku3IVuvHMyNL/xPBKQfMQuU3CVmkZz9YXa5koqzSZxxBZ47b/wh8s
         FCu3qdOEhC9hBHLGMtKHHeVKIlIOYlyRi/TpZA/oUQTuF3TnB6xnAUndP8grrWiP5WVU
         7hhXLvjK+cgCPb1adCFOFlKEF/QiWTxkUQRjPmjf6wNhOwEoJwYvU5VhEUqKqf1uL3GB
         MVpkCX+EnYe3DdZ2+w2oXjk/ivPkU6N0Pg3U4NNTfY9QNH0IHvrt8a5VFeW6WN0CyqNr
         7cYoa32HH3MWk9eCUMHR293QNkm3YA43hyDmpNosQcyAxRFTBZrT3TdDyK6BTGXZK58o
         ouzQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768521992; x=1769126792;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-gm-gg:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=Y7zdYfzRZKWkCHfkhW7fkkqxEZjIXjQ+JpiQLjroyPI=;
        b=iI36jAOclDU0aaB8+ARLzWmXfJ3U3uXMFdqdzfpBLhfvZ/SdTcfH0oFbE2GUzHhMsq
         XsDuZ245LT4aJOEbj8Rf9CxwWCoxuMZAPrjaxwum1bVEYV+/dnjlJ2BMKwEYtj5cvFmN
         ijMH4inAqkxGy6RNoj6CPIGi9NWYakrPTyEpI3Bs5P+TIoJSEIYA2nVLScVvd6LZgUSq
         3+qvSv6p5Oj5UIBEght+otWBa5iB67A1KA56wdcunZQclkdRSJ7wJD01iXS6bpEWcN/9
         tM7co/YDQJHLA7Ii0Q3j4bn5ZdcRg3aI9xze2H6KlvbZOgi1gkPcgEbXcDXA3Be7yL9/
         8DCw==
X-Forwarded-Encrypted: i=3; AJvYcCWFwFdzOSWlKNrRUPELbg2DmgHWfVWtQu09tcqiFWRHmxuDqBFWHGSkHcPihvsa+S58CCskpA==@lfdr.de
X-Gm-Message-State: AOJu0YxD8YgfCJK35HBpeOMIsYlN91mug27W6Akk5ru864dwxjgdpFaA
	wSJKdTqh8usXIJFkTI2jf8LOvVKN6xg94bnSbzxS7RTcwb3Qd+AUPq5r
X-Received: by 2002:a05:6512:3ca8:b0:59b:79d9:6cc with SMTP id 2adb3069b0e04-59baeef1358mr422970e87.33.1768521991812;
        Thu, 15 Jan 2026 16:06:31 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+HQ3NHtgYHpQJ54h3MHL9HtxIK2E6hV3+MsWVvTaOsKeQ=="
Received: by 2002:a05:6512:12d1:b0:59b:6d59:30f5 with SMTP id
 2adb3069b0e04-59ba718d57cls553093e87.2.-pod-prod-02-eu; Thu, 15 Jan 2026
 16:06:29 -0800 (PST)
X-Forwarded-Encrypted: i=3; AJvYcCWZp3WXdsHBz/oZ8LNmKYA4kVchq0NixTucFLOgNePi7khVzAC70Orr0mNCl3A6kLOVz+5r92xMsK0=@googlegroups.com
X-Received: by 2002:a2e:bd83:0:b0:383:1d89:8cfa with SMTP id 38308e7fff4ca-383842dea57mr3407021fa.31.1768521988944;
        Thu, 15 Jan 2026 16:06:28 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768521988; cv=pass;
        d=google.com; s=arc-20240605;
        b=Xve713Pmh7dA27vPO1xcJxxlF1R3eyydQc9MSu8MIIjv3HJ2mMF5XjxJMmRA4bIX0E
         TbbScus0sgPVm2YtQU9HPm1XxWuqdehFj25yAIDNxVHymkZF4BEuVxsJklCTQ4PrH/vi
         i65zzYsTPhJ5B6MjorM3b274uPZmKgeKmlNtUkPuJE+k7p7PDtQP5NuJKtQ/23cuG2/+
         fOH2MpCrMldC+CKxprKQRFRSnC5/3kAJgpz/HcMcwGlhaNDL2+dwIY1TxAL1eD9kXNf0
         5q7HXq8Td4pTVbYLdbiGRW+A9rGNozuPtSWa8dHvO3H2bC6FowS3g2geUFA5T4Q7lh9x
         C56Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=026F9tB9C4DnFMNAbwjqTuZTqI/FPwSez2fEDi6wXsM=;
        fh=o70NwP3S7EAJx8osS9SKIMnJdwY5HLxIQfp5qaHXlE8=;
        b=ij0avGlQLqDphx8zT5KAtcO/vmis1Lz3Z5DRKnQJwtJgDub2GrAlVULzNMPwlm5sA3
         6KMjwSgBXBwvrSPKgCamztH0K81gqq4wFt5Y2iZQ+EfSgyfppO7pywNjfhb8QtuUsZIt
         AQICe/gAegt8wqoE2dfQbSkYcp/ZZ0EkG90snS4Lz0Vs0Irvlu/VpzHRp57op1jhiayR
         8yeLMoCw2GDSpAtuhXqcyqHRFAzL/6mE6o32Jo1TZUrSKQUV8W5dW0rXn2OmarupCJnW
         uPayvtMWhGqxGQ+NTm9YoW0nD/58IXKZ1UQ1oZ0mlXxHKbriVCzQo2C5EADgeASLRnlM
         pmLA==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=rQBm7DuO;
       arc=pass (i=1);
       spf=pass (google.com: domain of surenb@google.com designates 2a00:1450:4864:20::52c as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ed1-x52c.google.com (mail-ed1-x52c.google.com. [2a00:1450:4864:20::52c])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-38384d0ff47si201601fa.1.2026.01.15.16.06.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 15 Jan 2026 16:06:28 -0800 (PST)
Received-SPF: pass (google.com: domain of surenb@google.com designates 2a00:1450:4864:20::52c as permitted sender) client-ip=2a00:1450:4864:20::52c;
Received: by mail-ed1-x52c.google.com with SMTP id 4fb4d7f45d1cf-64baa44df99so4132a12.0
        for <kasan-dev@googlegroups.com>; Thu, 15 Jan 2026 16:06:28 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768521988; cv=none;
        d=google.com; s=arc-20240605;
        b=WpGQr9Z1ZDrKCvy4xAz/XbOPQa+KaFY1Q3/V/b1Rx/WgjHMCSxQjUtNT7BSOYSRhr0
         T2npJLb53boNeGTL614pcy8kMrKN5ZdVmq+ezo89/t6Drpy/t7HOhqiI4+4Y0Q8dMoao
         sqsNHnQpow5eoXQQsHWQn0KdAYxAuyC0eyepiX2TTaHg6s0mQqgAhydWECZF3p9MMVnc
         aqiNQ50CnGAwrY6OdNCJBFmbEoR3LbwRfTb3b0/wDR6hE++zwhSpjTPAb3AmkvYnuIeU
         0UgjnI9TMuCJJ8gbZxIPw4awg4dmpKMh+mJSFpE3xWJi01dOYcNmof3hU2LgzBEnDHsW
         TGcA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=026F9tB9C4DnFMNAbwjqTuZTqI/FPwSez2fEDi6wXsM=;
        fh=o70NwP3S7EAJx8osS9SKIMnJdwY5HLxIQfp5qaHXlE8=;
        b=cnn3AwTCTU56OZ8deo0Lq+68Jucv1SvJ5TMP27gW3rIc5D0KRECEkqoxJFGkyNO8tL
         HVGum7c9TfcP7jjtrFt60kKdAZu3Yio/kq5Kl9jtOqi9AJ7x657941Q7BwKd0ttEFLw4
         +D3TZgJdWA99zsr8a/T6J+pWddCTRZLyS0B4XnmhN8eL3TM7dY2FRZdrCXYCMSIbQ19H
         YkTCJl/KgrAaPjrIbGMpa9h4Mnslpj7k/1kCCBoZhwg7PY5m4FjJy9pYJsSM13vhYH4j
         j4C4kMzoBPYaXMyaH2M+2ngyWWyCTJyIUSh909sZ6jtE8F2HLB3kgkvrSCogIKew1AF0
         2Ccg==;
        dara=google.com
ARC-Authentication-Results: i=1; mx.google.com; arc=none
X-Forwarded-Encrypted: i=1; AJvYcCUnpS1otZ+VJfj1mXFnMvkTTcW5aiY9s0mli3tzENRgpVxbMeZp4zfOs8Eangmp6iELGDMDO/p6cwU=@googlegroups.com
X-Gm-Gg: AY/fxX4a2H79xlFCMQr/Z0XZRvTsJwV5dq7qn7wrPh+Gy/F1xav60MGFNLHM5gGdbz2
	DA99BCwKEKXIKUhAbP9IHabYGJWIYOfgUXrorqPEp8f7ULhEdx3sG5WkCiAcGytzu4ZT8v/FmQB
	jfcQ4iVIQeUO++GilsN70Rw9Gp8br3LHdnvBrpSNq4x51Lfvuc19zDiOMfs5+jazGrMnx5KOAw3
	oc99+ZLOMzC8y9003r3Kwl6lK/fS78rMzx7LZc96YPxqgTBX/4vfEUn5VOba50qjs18hoe3oVw+
	z5BE9l9fgZKhQux85uwB82M=
X-Received: by 2002:a05:6402:564a:b0:645:21c1:28f9 with SMTP id
 4fb4d7f45d1cf-655252e133fmr5226a12.17.1768521988035; Thu, 15 Jan 2026
 16:06:28 -0800 (PST)
MIME-Version: 1.0
References: <20260112-sheaves-for-all-v2-0-98225cfb50cf@suse.cz>
 <20260112-sheaves-for-all-v2-2-98225cfb50cf@suse.cz> <aWXvAGA_GqQEJpB4@hyeyoo>
In-Reply-To: <aWXvAGA_GqQEJpB4@hyeyoo>
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 16 Jan 2026 00:06:15 +0000
X-Gm-Features: AZwV_QiPFAF4oyordk9NHVKA3LxKDdMlmD4Vltq0PHkaKAiIFW6MRACIK30AxWk
Message-ID: <CAJuCfpE7ctb+AYEsmmDbW-3+DU-kDb2ApYWYXRur5FDtPP6zng@mail.gmail.com>
Subject: Re: [PATCH RFC v2 02/20] mm/slab: move and refactor __kmem_cache_alias()
To: Harry Yoo <harry.yoo@oracle.com>
Cc: Vlastimil Babka <vbabka@suse.cz>, Petr Tesarik <ptesarik@suse.com>, Christoph Lameter <cl@gentwo.org>, 
	David Rientjes <rientjes@google.com>, Roman Gushchin <roman.gushchin@linux.dev>, 
	Hao Li <hao.li@linux.dev>, Andrew Morton <akpm@linux-foundation.org>, 
	Uladzislau Rezki <urezki@gmail.com>, "Liam R. Howlett" <Liam.Howlett@oracle.com>, 
	Sebastian Andrzej Siewior <bigeasy@linutronix.de>, Alexei Starovoitov <ast@kernel.org>, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, linux-rt-devel@lists.linux.dev, 
	bpf@vger.kernel.org, kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: surenb@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=rQBm7DuO;       arc=pass
 (i=1);       spf=pass (google.com: domain of surenb@google.com designates
 2a00:1450:4864:20::52c as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
X-Original-From: Suren Baghdasaryan <surenb@google.com>
Reply-To: Suren Baghdasaryan <surenb@google.com>
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

On Tue, Jan 13, 2026 at 7:06=E2=80=AFAM Harry Yoo <harry.yoo@oracle.com> wr=
ote:
>
> On Mon, Jan 12, 2026 at 04:16:56PM +0100, Vlastimil Babka wrote:
> > Move __kmem_cache_alias() to slab_common.c since it's called by
> > __kmem_cache_create_args() and calls find_mergeable() that both
> > are in this file. We can remove two slab.h declarations and make
> > them static. Instead declare sysfs_slab_alias() from slub.c so
> > that __kmem_cache_alias() can keep caling it.

nit: s/caling/calling

> >
> > Add args parameter to __kmem_cache_alias() and find_mergeable() instead
> > of align and ctor. With that we can also move the checks for usersize
> > and sheaf_capacity there from __kmem_cache_create_args() and make the
> > result more symmetric with slab_unmergeable().
> >
> > No functional changes intended.
> >
> > Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
>
> Looks good to me, so:
> Reviewed-by: Harry Yoo <harry.yoo@oracle.com>

Reviewed-by: Suren Baghdasaryan <surenb@google.com>

>
> --
> Cheers,
> Harry / Hyeonggon

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
AJuCfpE7ctb%2BAYEsmmDbW-3%2BDU-kDb2ApYWYXRur5FDtPP6zng%40mail.gmail.com.
