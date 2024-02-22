Return-Path: <kasan-dev+bncBCC2HSMW4ECBBJFB3KXAMGQEX35XDZI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x238.google.com (mail-oi1-x238.google.com [IPv6:2607:f8b0:4864:20::238])
	by mail.lfdr.de (Postfix) with ESMTPS id DAB6285ED98
	for <lists+kasan-dev@lfdr.de>; Thu, 22 Feb 2024 01:09:09 +0100 (CET)
Received: by mail-oi1-x238.google.com with SMTP id 5614622812f47-3c0a8d38b32sf10148065b6e.2
        for <lists+kasan-dev@lfdr.de>; Wed, 21 Feb 2024 16:09:09 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708560548; cv=pass;
        d=google.com; s=arc-20160816;
        b=lMCM5vrmEhrZhWduxjedOUa5nHGEjDECs5vCLu7mYXG9RfnUgP76maAbqgLoUs7rvH
         /JR9O4BNPVwNnWqMM+PsFIHyJ1xN5FmKwpz5jG7T89H7Vi7dpj4miAn9pusnZUNSaLf3
         x2D56UPrYhNoy+D+LeM3wdEwcGbODdZrdbfkZ7gIpsA986yaXtnsXnKijOtcRlYApdaM
         DtqrNdLMF7QAbDTzCLpvQvdjuFzApN66oF+4H/6145B+/2gMRlEEsp3rw3GCVQ51N4Ut
         HLEARpgKR4ZbwPI0HpmbGFv74j433+VejFugGzF+qZn2MCPzQsqUy5REYxn9i9fUZsQ9
         JEvg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature;
        bh=0mo9qHfKENUFfps/W7JPToBe/QNQJxFpm/KaPwxo7jg=;
        fh=/0AMqyhQPFeDQY046AGcdAhFPc3zjESnJ+sUzXnQ8ww=;
        b=hSlDZcM9Ws1gOwgcsbBT6wtqU+9v5BooL9IGG3zzUqX888MAmOjDVfHmE9pZGU7KAw
         XzVtevSW50vOLI0J8edANq3w3YzvLYO5kaaj17iy8q8/S7jIAnXWiUZIkzC9+4X3F+9U
         CRQHxoRFbivsV+PnTbqdrh5GGcEMNvHxZPPGxe7U9Q6OtoQuPTvpP/GzZkY/eTNupIRx
         GH13p0OVMd70rf0jD4pO3bSwqcfzDI8fhOICo8h66leq4FWfXHG1MB7wpOV/rTR6e9y6
         AZ3vKnO1IXL2OJHAn/w5ejEt23lHaBKghF2Q4rpk2QIHS2NaQP18s1RXXy0gAdIRf83R
         stQw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@soleen-com.20230601.gappssmtp.com header.s=20230601 header.b=lx60P6jt;
       spf=pass (google.com: domain of pasha.tatashin@soleen.com designates 2607:f8b0:4864:20::933 as permitted sender) smtp.mailfrom=pasha.tatashin@soleen.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=soleen.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708560548; x=1709165348; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=0mo9qHfKENUFfps/W7JPToBe/QNQJxFpm/KaPwxo7jg=;
        b=xe7dJX2i0UGzPIkJxKgz8RWUSq8O673yoelCbkMwKFjW/6XxYCJO5XURcYnnkONu4f
         tKuKwJpAEjC5HI1isvT2FtYFvNge7Fzy2s4zVyuRuCo3tOd047XUPsHD446LzyFv2NL2
         /z1FpqCt+TbJpyF9eGFeGGmypT8GGyozAyxTvN1n9p2dihwoFu5JpNj0l4ZUaN+o2y2N
         iTif1J4GezI7T9sluy3XYvbU45fSWoNDqVOJhqZIk5VEXFE+HiuTDij8bJAHKL8fyvKP
         N1b1/SQhAS81N+f4h3Ft/jtKPj/yHVeGtO1yxAs9h1ApLjSaWouMEtOhJpH1AGOzlRWM
         oQnw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708560548; x=1709165348;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=0mo9qHfKENUFfps/W7JPToBe/QNQJxFpm/KaPwxo7jg=;
        b=QfNQ4oKDRxpN5XBRZ03rV8bdShk/JddNCtT2iurro4MjeitkS0wnRX/NAFIJIYL6IX
         EAlQVrnll1khnsXGCMfftC/RJ6CP6AjR/prxi1kwuOrWEzslRmoh2bUMmcH/4toFVSMD
         W8B0SxYfGJO9Fq77BW6y/9PKuME/7xDhRGpPEY9EAPJDSe53LbY4U+j+l3stWb1Oq7is
         vS4i+GKef9tPz3vXLPMADShN6c1g0Mq4kRJyHTWjABjYq5jeohq7QjHkhtIkFnyC0XVm
         JvSHc//ZC0+Bij4HZ8u6wam/NEnrEvSi0l5FKqoRTMhVi9dPn7oCQdUD4rqMix3YQ2oB
         m5bQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWH/XFuDdRD9MwCdnxCXlRVqWlOWkh2H/cIB9DMox0WfjGNNGo+v6EPbmIxW7VI/7viYUdHfqM2NYNlAqYFyi8NCtY1piSteQ==
X-Gm-Message-State: AOJu0Yy/wJV5NFAij7DDwgcR+/dUpm0fIOiIdndDkjhJmbb2l6/QDoQa
	UpVTbK6Ec6n2bLsU2ZMndDX7vv6WDNMvbZMONva1XR9aYqoFeNCY
X-Google-Smtp-Source: AGHT+IGWmcNaApKgjNNIyzVoLuEs+AmVKBuMfeQB/csxmjyM7aCrE/8F7bc/Oz/AKBCX7Kbe15RnjQ==
X-Received: by 2002:a05:6870:9a14:b0:21e:9df9:2596 with SMTP id fo20-20020a0568709a1400b0021e9df92596mr13521770oab.42.1708560548527;
        Wed, 21 Feb 2024 16:09:08 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6871:3a2c:b0:21a:216d:4818 with SMTP id
 pu44-20020a0568713a2c00b0021a216d4818ls2088016oac.2.-pod-prod-01-us; Wed, 21
 Feb 2024 16:09:08 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWrGj1i2/1oA5w64pC67IJFRxsjb2J9tsT4gKBp+3zlc62jXskiWCMeCW9JzPJWnDVsfF+o+XUJGd4F1aF9FcH5kmXsKe0dWIi7TA==
X-Received: by 2002:a05:6870:230f:b0:21e:a71f:d7f4 with SMTP id w15-20020a056870230f00b0021ea71fd7f4mr12859296oao.11.1708560547836;
        Wed, 21 Feb 2024 16:09:07 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1708560547; cv=none;
        d=google.com; s=arc-20160816;
        b=btDpVHZ8oQRShBp3MELgBx2vc1uYriIpx7KDbWaJPQOel68yMw4K7+dZy8SjJGTIaB
         PgzWHJ1Jk7baR0MG3wNQILKGavgTJZFzen4iZg4ugV3ngOecMLJtDlnztL8B/XankD2f
         RsHfF9R2+bpSts2O36uh4srukoBeWRtekJw3fNRHtNmDennNEFsjlUwnLRoZIoJ5ARLr
         3spzO4UgRtmsZUE5RVxP9sgEfUoP4d+FNgyp57pNDweDOUbGYVfe3VMX46V0MeeecANL
         PHPrM3X/HUku3Lj4ekqyd68XKBFZUwU3VIRJOQHrQkecP9ri7XBDZWL9DOyGYyqVbaNf
         33+g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=aiZ2wjkXdUeF2DZJw2oBIl8u+9EyfQfZ9ycNkF8fAgk=;
        fh=mq6L8WZfRuoiboM4w4GvSNbABp7TAN+64GFUpu5loCo=;
        b=uJKOnnexkmkpFU89T3qB5m98yQTDFgd47/l1/9KZZIaA+ArNCA+dYzsSJ7pE/rAwe3
         jJhdFH7YF+BMhDNMQQt3cI1/7K7Mba+xGcqk1hHXGECzQ6rGuHAAXJ7H8jhLIRUl8IBA
         i39rFi8tuLskA4/najTujf33C1lsFoj2jj80TfR6P1dP9CpWdtvt5ZQX8VhipqsMS6Zp
         FjLuNh89/1Drtvfsr5r60rgXRlI6lSSPE+1Ec6emVsIF4O8eupKIylDcaVDa1V3/G5MU
         kPY1ZhGcVpk2OIF5f+YjCoJu9Lb8QV5NJBLEWM8ZU/Dd4rmtlXv7RMDdak4LiXiH6f1k
         mYxQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@soleen-com.20230601.gappssmtp.com header.s=20230601 header.b=lx60P6jt;
       spf=pass (google.com: domain of pasha.tatashin@soleen.com designates 2607:f8b0:4864:20::933 as permitted sender) smtp.mailfrom=pasha.tatashin@soleen.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=soleen.com
Received: from mail-ua1-x933.google.com (mail-ua1-x933.google.com. [2607:f8b0:4864:20::933])
        by gmr-mx.google.com with ESMTPS id j24-20020a056870169800b0021e7b88e4c0si794099oae.1.2024.02.21.16.09.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 21 Feb 2024 16:09:07 -0800 (PST)
Received-SPF: pass (google.com: domain of pasha.tatashin@soleen.com designates 2607:f8b0:4864:20::933 as permitted sender) client-ip=2607:f8b0:4864:20::933;
Received: by mail-ua1-x933.google.com with SMTP id a1e0cc1a2514c-7d6a85586e3so3433944241.2
        for <kasan-dev@googlegroups.com>; Wed, 21 Feb 2024 16:09:07 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCX3ZidXrJ3fcqDkgkt5ipWQr9kwXkC7IQfr6dtSWEqvKwjfDxG4GfYH7wCnWqGrV5uhszzyTEAZqPvqgUw71gNf7GXrHr9twXPwbg==
X-Received: by 2002:a05:6102:953:b0:470:605a:6a4 with SMTP id
 a19-20020a056102095300b00470605a06a4mr10156813vsi.21.1708560547208; Wed, 21
 Feb 2024 16:09:07 -0800 (PST)
MIME-Version: 1.0
References: <20240221194052.927623-1-surenb@google.com> <20240221194052.927623-9-surenb@google.com>
In-Reply-To: <20240221194052.927623-9-surenb@google.com>
From: Pasha Tatashin <pasha.tatashin@soleen.com>
Date: Wed, 21 Feb 2024 19:08:30 -0500
Message-ID: <CA+CK2bD-AvHR45zWrLOGA7Y=HQeFf=Ty4vCB5bWxbX7XyMsYRw@mail.gmail.com>
Subject: Re: [PATCH v4 08/36] mm: introduce __GFP_NO_OBJ_EXT flag to
 selectively prevent slabobj_ext creation
To: Suren Baghdasaryan <surenb@google.com>
Cc: akpm@linux-foundation.org, kent.overstreet@linux.dev, mhocko@suse.com, 
	vbabka@suse.cz, hannes@cmpxchg.org, roman.gushchin@linux.dev, mgorman@suse.de, 
	dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com, 
	penguin-kernel@i-love.sakura.ne.jp, corbet@lwn.net, void@manifault.com, 
	peterz@infradead.org, juri.lelli@redhat.com, catalin.marinas@arm.com, 
	will@kernel.org, arnd@arndb.de, tglx@linutronix.de, mingo@redhat.com, 
	dave.hansen@linux.intel.com, x86@kernel.org, peterx@redhat.com, 
	david@redhat.com, axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org, 
	nathan@kernel.org, dennis@kernel.org, tj@kernel.org, muchun.song@linux.dev, 
	rppt@kernel.org, paulmck@kernel.org, yosryahmed@google.com, yuzhao@google.com, 
	dhowells@redhat.com, hughd@google.com, andreyknvl@gmail.com, 
	keescook@chromium.org, ndesaulniers@google.com, vvvvvv@google.com, 
	gregkh@linuxfoundation.org, ebiggers@google.com, ytcoode@gmail.com, 
	vincent.guittot@linaro.org, dietmar.eggemann@arm.com, rostedt@goodmis.org, 
	bsegall@google.com, bristot@redhat.com, vschneid@redhat.com, cl@linux.com, 
	penberg@kernel.org, iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com, 
	glider@google.com, elver@google.com, dvyukov@google.com, shakeelb@google.com, 
	songmuchun@bytedance.com, jbaron@akamai.com, rientjes@google.com, 
	minchan@google.com, kaleshsingh@google.com, kernel-team@android.com, 
	linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org, 
	iommu@lists.linux.dev, linux-arch@vger.kernel.org, 
	linux-fsdevel@vger.kernel.org, linux-mm@kvack.org, 
	linux-modules@vger.kernel.org, kasan-dev@googlegroups.com, 
	cgroups@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: pasha.tatashin@soleen.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@soleen-com.20230601.gappssmtp.com header.s=20230601
 header.b=lx60P6jt;       spf=pass (google.com: domain of pasha.tatashin@soleen.com
 designates 2607:f8b0:4864:20::933 as permitted sender) smtp.mailfrom=pasha.tatashin@soleen.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=soleen.com
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

On Wed, Feb 21, 2024 at 2:41=E2=80=AFPM Suren Baghdasaryan <surenb@google.c=
om> wrote:
>
> Introduce __GFP_NO_OBJ_EXT flag in order to prevent recursive allocations
> when allocating slabobj_ext on a slab.
>
> Signed-off-by: Suren Baghdasaryan <surenb@google.com>
> Reviewed-by: Kees Cook <keescook@chromium.org>

Reviewed-by: Pasha Tatashin <pasha.tatashin@soleen.com>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BCK2bD-AvHR45zWrLOGA7Y%3DHQeFf%3DTy4vCB5bWxbX7XyMsYRw%40mail.=
gmail.com.
