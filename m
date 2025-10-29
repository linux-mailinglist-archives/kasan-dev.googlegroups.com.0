Return-Path: <kasan-dev+bncBCSL7B6LWYHBB6OMRDEAMGQEEUINDAQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x538.google.com (mail-ed1-x538.google.com [IPv6:2a00:1450:4864:20::538])
	by mail.lfdr.de (Postfix) with ESMTPS id BE7BEC1B400
	for <lists+kasan-dev@lfdr.de>; Wed, 29 Oct 2025 15:36:42 +0100 (CET)
Received: by mail-ed1-x538.google.com with SMTP id 4fb4d7f45d1cf-63c46c86cffsf7547557a12.2
        for <lists+kasan-dev@lfdr.de>; Wed, 29 Oct 2025 07:36:42 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1761748602; cv=pass;
        d=google.com; s=arc-20240605;
        b=inwUfBHd1iV7GdqIVdsOfWvFqdCx9GcWBHOfrZoXhQ22QWxf88gt2J4zUtMWuaVp3r
         o47UsgOZ71NhsNXTMY+NqjTTF9D8Ltmc6MzU/RsuV7CCK27m3EZfWrzLPfwGEd/Je1la
         IXktWQv6krzB0MKy+MXhU617aot/jOd0yGOHUeAr9ZOmm16lQzoO+bnRwwLLLScSzwHV
         OkAp/vLPVYjwxxYNp3BmXExlLYbuf2Z2CPOAY2jUULxP7b1/hoxmLTZLE9kKz9b1xEMi
         XxTFlrU7GzQ0FivFZF4KSeYjspir/5Vx8jciiDCiRTXwvUDiifc7CPZNQWTs9fkVgGDd
         IkqA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature:dkim-signature;
        bh=EquQbPk9Dq+O2Za1+ISO0rAjNJmEc/+IoEjTdv1duIo=;
        fh=q+N0eJCYn2aGU8PqVVvylelB6k0uI/LQJN5F2ptUkHs=;
        b=PVp1JFfxAYoBYsLKKdzOId+4K8E9aixNSmRdSL0tgAfbucyw/V1iRvXVDCmF2vaoYQ
         ZO3t5V/s80UFoX0Rm2iYtrJcKfsd0i0dB93bePg9QDmbRUC3/z4K7blwS2DrBO2Jg2mH
         b5cGSV0AVQj+D9G3HVerYcLkr12EJZxfOKKIhk45tkG34i4hL1YVw5gALnExyUGiHHpJ
         61n5HoaKQMh9bV3v4wDBsSFYkqL5kIxep3gpdOG05s0WGzSvGK3lalDVxXfscWSnKjes
         jRdgNE1OYNII3tZK13m0GWDB36WdG7C7aKoojzWYjUfYnoE0kh8TBbk2wrVb0O0kJFir
         0NTw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=YxkpSo6E;
       spf=pass (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::12c as permitted sender) smtp.mailfrom=ryabinin.a.a@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1761748602; x=1762353402; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:content-language:references:cc
         :to:subject:user-agent:mime-version:date:message-id:sender:from:to
         :cc:subject:date:message-id:reply-to;
        bh=EquQbPk9Dq+O2Za1+ISO0rAjNJmEc/+IoEjTdv1duIo=;
        b=P22z73f8zlhgn+gMGNsknujouZeZC0qAHwLfY2PXV7Ov51I2hx3LPWu3My80zbBNqZ
         OL3kDg7k2bbTn55Om4KlMYkuNi39fbF97XnRFP+pe4vxECUbh7R0dKp8TmFbaW/SrzUd
         ZmaFhzzQSEIPyZh6ImSuEm8PVejXqmfmKvCtw7qcA5Q7MlZZfDnx1J/f4YmfYdQydl2g
         ufCnf/EilU5jR0T59PP1lOiAsjQjooCxe+EToHPWR6wbjiTApIMzU1QLZcvYcLWK3Uy4
         7Wzbi7FvkfMXkKxXsZCFWHOw+fdUSNX99Wbagsd8gimZzDBCmwA4deLDsYu32SayfjCP
         T5VA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1761748602; x=1762353402; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:content-language:references:cc
         :to:subject:user-agent:mime-version:date:message-id:from:to:cc
         :subject:date:message-id:reply-to;
        bh=EquQbPk9Dq+O2Za1+ISO0rAjNJmEc/+IoEjTdv1duIo=;
        b=j9erVDmxpEtMdA4tER052H1PinVjXJIdym4Efetz/AyG6JHYCRSlFRww9Nr105fqfX
         cr6+zzfFZMRINRLHwUe57QAZlfOntFVer43XXO5aUjfP/hZFUYcP3QfOLB6JZ9tveoqZ
         HkRGH10GfKirnaSXrmWfaLteBI9i9eEKJaLSvHIt8UXD3ELOpklWd30o/QGPz6Vv3bEg
         I6mIZ/IU9dXbeizc/2Mh9XDAvv84F+J17BVp7WGT0KRC6Ni5eCjLsTo4jP3xR/D+rMLx
         Hx2yklGrgB467twHXDIih+5j2UyHneGeevF2ZnhpxsrCwcsNXzLIpZLNQAMEckuptakn
         iC2A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1761748602; x=1762353402;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:content-language:references:cc:to:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=EquQbPk9Dq+O2Za1+ISO0rAjNJmEc/+IoEjTdv1duIo=;
        b=ChOWYrhbaRE0vHdDZVQ/K/Dvr/x4zwRckFbU2kWAFmPisAq123F4/MOtIXH5isSSo8
         1G+jldcCkq3QWaQ4hH6Ft4ANMMGgGnVgZxV8llvcIPAL0M2HzKI4AH6IqQiNER2MrDYa
         3YOYpHs0AihpT8722+xJ71OAY8MZJBxQvS1omO7eMa+rg9ytiklKHrPg58pZd5xrVMMu
         h2Nu2nS2ANBCCXrgxmMquNTw0r82yuVNBJje19JkachmN+H7Qp/zd4eblfOMT2Bal2rH
         XGOXtp5MYYNICpPnYeOXDAI2CB7hsQDTbPood5G1V4yaakG7f9hM8I3yPMbWdP+FwGFc
         52sQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUYkY6swbhVNlv78d3o9u2U69kYXoUjzvBfm75b3f6410HaCHTHFhqG+qg3IpBiMYoh0NiBlg==@lfdr.de
X-Gm-Message-State: AOJu0Ywke4v5zph3xQD6+0ujmhxwfav2OY04AFqd9+zYxF5vvICZgYKy
	ZIzJET5WoHlb5bzXZF3QDnEBLK2Ick1d91lF+Mjf1nvlggi1vPPPh2sO
X-Google-Smtp-Source: AGHT+IGIUT4BTKAbkwGbdy1gug+wCKzkYY6FOHQJR9gdWAAtZZCJEE1Ldfg4Y9ii1UufG+EWfaIUyg==
X-Received: by 2002:a05:6402:a0c1:b0:640:36d9:54fe with SMTP id 4fb4d7f45d1cf-6404439927fmr2520030a12.24.1761748601801;
        Wed, 29 Oct 2025 07:36:41 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+bH/42xzQUXHz5JCybVBNqA+9n7jRs92nUS63hfutsVtg=="
Received: by 2002:a05:6402:20d1:10b0:63b:ec3a:da94 with SMTP id
 4fb4d7f45d1cf-63e3eb6a138ls1475967a12.1.-pod-prod-06-eu; Wed, 29 Oct 2025
 07:36:37 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWZPdIogwf6EzA49x1E07GWXKaxDDtO3MGO8L3AHB4+I2C18FcAlEolzJwxdRrBSgQVDhBv7A2K6Ro=@googlegroups.com
X-Received: by 2002:a17:907:3f9e:b0:b55:c30d:c9fc with SMTP id a640c23a62f3a-b703d2bb971mr307884666b.11.1761748596870;
        Wed, 29 Oct 2025 07:36:36 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1761748596; cv=none;
        d=google.com; s=arc-20240605;
        b=jT9gBAGA+b42BXoSANF6Ak+v23IWw2kYmKSDU5Ei7/Be8C1xng6rz7CPUuSa5Rkz1g
         EfE3HmDAj+a7+aVrxpieU+AzBQbnvv9vl2TxZaZrpNMv8kPfEwMTvtb/l6Qy3q1nf9wO
         8mex+K/bMaUMdwGCvLDVXkENzvKGLRxlZlfoShehg3O+1VLT3VHYwJ1RHUffZYEL2Sd5
         Ju0b7b3G0CHJSLzx1JxoETsNDhi3GPrX3WMzH5kIzBC04ZR06XZxgl+aXxH/dohOwT/m
         IU6OerhACVltsIeKCXOyuTIIed82zsNwoAO6cSC6+wunH4W8UEab3tCO3RbjVxaoK8Ka
         OomA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=EMm3nDEHqh0Duo/pCGz7alBh4a7cGfmIeQ4bIaczRPI=;
        fh=DGTCTN2WH+KGK41I9zG7QwCPjCbNZhFsdQGB1ZypMDI=;
        b=ifHel+3VHSp9DKoLGKte7kDGwzsNKLQMSzNa9fEB8SRgH5EJXT3C1zV/PDKz1ruBoK
         5C9I40KbyLlWHZb1th3wxdz3xJdIZlzHEAe3Wq4GLLFHdda6WbpjhMjpt90F/XELFvLa
         cgUv7gTMybgvGQbNr6Sc72Erkn/c/tTALJUw0E3NiUSNOFkkg8q99lIKQnQ3gwk1a9L+
         ztUjXLE8cQqb6/hjVERHNRyilc5QK82m+p50vBe0epGB3WwHdrpp5BCEb23rUxQgUzAR
         SIxxqb6UJ4+TgwZ9pg9M49c7zZnRUpfzGuyU7vxhLs7Jb+HVF84ok57favZXrKBrNOQT
         zfpA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=YxkpSo6E;
       spf=pass (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::12c as permitted sender) smtp.mailfrom=ryabinin.a.a@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-lf1-x12c.google.com (mail-lf1-x12c.google.com. [2a00:1450:4864:20::12c])
        by gmr-mx.google.com with ESMTPS id 4fb4d7f45d1cf-63e8149ba87si270725a12.4.2025.10.29.07.36.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 29 Oct 2025 07:36:36 -0700 (PDT)
Received-SPF: pass (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::12c as permitted sender) client-ip=2a00:1450:4864:20::12c;
Received: by mail-lf1-x12c.google.com with SMTP id 2adb3069b0e04-591b99cb0c4so825237e87.2
        for <kasan-dev@googlegroups.com>; Wed, 29 Oct 2025 07:36:36 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUrmNi3L8VZYfuMYeZorJc3eyGgv1FwdAQ2GCqYVtCuP5zUJXkiK/8gOMdcxm8qRUL+b9Te/U6IaFY=@googlegroups.com
X-Gm-Gg: ASbGncstvw4NwIwgsNY2OlKKJm8itZpwtZMaj0br6mAD36JEdGBdVVMdilxS9QfNIbg
	XDoAVzKq8POeAQTz6ELugY7J76eQ+5FtIErcXf2LF4r+h4e/d1a4YkihluGLrFesOmeVtIB/twX
	6JAF0rOu0q/VSvjVVfpXkHSBnJE7jc864O/NjI5ry/ITT9n3ahZ4GsIcl4jwsQPT7eNydkhJ5+c
	QS4M3CTMFEmkFV+qKd1xcgTv/s2nS2iK2haTtBrxE7E6nUBts8PUcH6Josli7UVLms9syg/xoKy
	/KANjZrJjQJKvYd7IRLorpS/9hWUIOej5E438xQtphEiRezQR0JSFycngeADtltdIlJ++8aMJne
	jj3LSMei2gQs6DIPxcDOR9ZEVW27AmATqiy1ZyFYasvdq0eGNO3NWGWsBB0G7ry4DvXwOe+XhBg
	+c+g+Gm+2ykSjJexpi
X-Received: by 2002:a05:6512:3f0e:b0:57d:720:9eb0 with SMTP id 2adb3069b0e04-594128e00b4mr758281e87.10.1761748595850;
        Wed, 29 Oct 2025 07:36:35 -0700 (PDT)
Received: from [10.214.35.248] ([80.93.240.68])
        by smtp.gmail.com with ESMTPSA id 2adb3069b0e04-59301f700fbsm3962183e87.81.2025.10.29.07.36.34
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 29 Oct 2025 07:36:35 -0700 (PDT)
Message-ID: <1bc9a01a-24b3-40a0-838c-9337151e55c5@gmail.com>
Date: Wed, 29 Oct 2025 15:36:28 +0100
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH V2] mm/slab: ensure all metadata in slab object are
 word-aligned
To: Harry Yoo <harry.yoo@oracle.com>, Vlastimil Babka <vbabka@suse.cz>
Cc: David Rientjes <rientjes@google.com>,
 Alexander Potapenko <glider@google.com>,
 Roman Gushchin <roman.gushchin@linux.dev>,
 Andrew Morton <akpm@linux-foundation.org>,
 Vincenzo Frascino <vincenzo.frascino@arm.com>,
 Feng Tang <feng.79.tang@gmail.com>, Christoph Lameter <cl@gentwo.org>,
 Dmitry Vyukov <dvyukov@google.com>, Andrey Konovalov <andreyknvl@gmail.com>,
 linux-mm@kvack.org, Pedro Falcato <pfalcato@suse.de>,
 linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
 stable@vger.kernel.org
References: <20251027120028.228375-1-harry.yoo@oracle.com>
Content-Language: en-US
From: Andrey Ryabinin <ryabinin.a.a@gmail.com>
In-Reply-To: <20251027120028.228375-1-harry.yoo@oracle.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: Ryabinin.A.A@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=YxkpSo6E;       spf=pass
 (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::12c
 as permitted sender) smtp.mailfrom=ryabinin.a.a@gmail.com;       dmarc=pass
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



On 10/27/25 1:00 PM, Harry Yoo wrote:
> When the SLAB_STORE_USER debug flag is used, any metadata placed after
> the original kmalloc request size (orig_size) is not properly aligned
> on 64-bit architectures because its type is unsigned int. When both KASAN
> and SLAB_STORE_USER are enabled, kasan_alloc_meta is misaligned.
> 

kasan_alloc_meta is properly aligned. It consists of 4 32-bit words,
so the proper alignment is 32bit regardless of architecture bitness.

kasan_free_meta however requires 'unsigned long' alignment
and could be misaligned if placed at 32-bit boundary on 64-bit arch

> Note that 64-bit architectures without HAVE_EFFICIENT_UNALIGNED_ACCESS
> are assumed to require 64-bit accesses to be 64-bit aligned.
> See HAVE_64BIT_ALIGNED_ACCESS and commit adab66b71abf ("Revert:
> "ring-buffer: Remove HAVE_64BIT_ALIGNED_ACCESS"") for more details.
> 
> Because not all architectures support unaligned memory accesses,
> ensure that all metadata (track, orig_size, kasan_{alloc,free}_meta)
> in a slab object are word-aligned. struct track, kasan_{alloc,free}_meta
> are aligned by adding __aligned(__alignof__(unsigned long)).
> 

__aligned() attribute ensures nothing. It tells compiler what alignment to expect
and affects compiler controlled placement of struct in memory (e.g. stack/.bss/.data)
But it can't enforce placement in dynamic memory.

Also for struct kasan_free_meta, struct track alignof(unsigned long) already dictated
by C standard, so adding this __aligned() have zero effect.
And there is no reason to increase alignment requirement for kasan_alloc_meta struct.

> For orig_size, use ALIGN(sizeof(unsigned int), sizeof(unsigned long)) to
> make clear that its size remains unsigned int but it must be aligned to
> a word boundary. On 64-bit architectures, this reserves 8 bytes for
> orig_size, which is acceptable since kmalloc's original request size
> tracking is intended for debugging rather than production use.
I would suggest to use 'unsigned long' for orig_size. It changes nothing for 32-bit,
and it shouldn't increase memory usage for 64-bit since we currently wasting it anyway
to align next object to ARCH_KMALLOC_MINALIGN.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/1bc9a01a-24b3-40a0-838c-9337151e55c5%40gmail.com.
