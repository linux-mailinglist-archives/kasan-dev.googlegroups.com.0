Return-Path: <kasan-dev+bncBAABBWN4XTEQMGQEDPQOS5Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33a.google.com (mail-wm1-x33a.google.com [IPv6:2a00:1450:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id 92D6DC9C5B5
	for <lists+kasan-dev@lfdr.de>; Tue, 02 Dec 2025 18:14:02 +0100 (CET)
Received: by mail-wm1-x33a.google.com with SMTP id 5b1f17b1804b1-4776079ada3sf51523915e9.1
        for <lists+kasan-dev@lfdr.de>; Tue, 02 Dec 2025 09:14:02 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1764695642; cv=pass;
        d=google.com; s=arc-20240605;
        b=HrvilN61Nsd86S38iuTQsA5lBsgPgUeFUKeH0KmZM3RDEE7fYYnjKpp4ABzGdHi12o
         Ga+hirQPbbfYcwxO1vuolFEQ3QfvFJdOXy6X861B3ykz8RaFdfcm/G2HrZtJrYrYQlR1
         xvGwzhiS4NjHEMhy6GJX7vnKwethlEYQiRgZRKP4xrMMYCTvejgbCVt28K+DW8GYeBjC
         qYFDTjttN3d53Q63AVRMn+x76EQtxGyPNsQ7JWHKd+Nv4AJ0oHo9K9FiOz6XWGLRcYeb
         oVmDGTTn1AsPm+H0QxK3/kb06zVEFHt0oJjynIvBQqSVcI/+L6tAAmIg3xfyNTEiIWcS
         HwYw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :mime-version:feedback-id:references:in-reply-to:message-id:subject
         :cc:from:to:date:dkim-signature;
        bh=Pbxg5DDmPfU24CWjqt8yj0fwA5EhVlFPapkRvU+qch8=;
        fh=Ll+lGrSIfK/C+s9iDTFEXv6yjHaZWyPte6QdKGT4lcw=;
        b=VcoiCbVHgnNVZz8vZNcjXltflx5pNlW5LK2IxXOEYp/IqcF9ee8vO0dC6PE/i1E7aY
         PaMyac0+kRsFT6Ry+N0HgKakNkX4Z+pKgTeUUJKEVqKuHMalc8Cj/+j6vAb0tme6tD4A
         9FuFfRF9VMHPMGTbWH6qHC2jaWZrG9RrFTZxTEDGrAMXT26LLid1q4gwQrNKRHEruBaS
         k1TH1lLWQvc6bAyD/v+e3YZ9KIzm4EEoyA1oRsAxdyXQyB1+XROxbVi+e65v1NENMiNO
         SmZmyGEH4yDf6/ZE098NtadBfHk/klJEYA9ckRh7PxAHan7Ay8OGWloL6GvnopN2j/4r
         JNMg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b=D0IrwHbz;
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 79.135.106.118 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1764695642; x=1765300442; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:feedback-id:references
         :in-reply-to:message-id:subject:cc:from:to:date:from:to:cc:subject
         :date:message-id:reply-to;
        bh=Pbxg5DDmPfU24CWjqt8yj0fwA5EhVlFPapkRvU+qch8=;
        b=WAQjzrY8AigPEzALIO/Ktb7NV92jt20Z6xiDpDWov1u+1xm6/rWlttUPtEaCKXczDS
         VJBKBITJx8ue3y4QQVkp5Om/yvQ9H4cSJ/eOLCwP0Pa3vc+NPgeL2DOFpFmgs211Ab3O
         4Wo7dtLvgEmF/zl6n++2vg35uF6FgnAlNfPaUg0frjlp2uFrEpZNTCqsmD24iuYi7A09
         aR8WVpZPhTqzV7uYXrLWGN8PyS0ICc9CENDRnIQxjK2PNu5v0CwErucFE6jixsbQnvdr
         kHOn3ZrCd2k5mbHax+lhyFmT+TKtrSgweeV0NvDlHXTw3xJM7bqvRaAjktN/HFo1n6E/
         vGpw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1764695642; x=1765300442;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:feedback-id:references
         :in-reply-to:message-id:subject:cc:from:to:date:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=Pbxg5DDmPfU24CWjqt8yj0fwA5EhVlFPapkRvU+qch8=;
        b=h95KK0c8Yby309QZgOmgzxVxBDmWU4KDtCL38JctZVOWutuLtznbOXEnXcnpE0eoNU
         3k4Sn/HrGNf9DLnjnrPki7CQyC/xmyu54c/uZYVRIuVgEIYOwmUqJbrYZR8INssn807h
         dX2ARRgn29gCobcDH5wLHuYOuK6zrT2FTMr8hMNk6z+E+suLUF9vAAL9wnCXDaR3ebjU
         P616CsENKQdCMHUKgE46eEbxRhm7frzFf4vOkA+6FQE21rdHYjBIKJRedA5fy1hWQOvb
         YeJVgNekv3GcDqs5UXPjhzNAYnPA4ncQetKWn95Lr3Vj682FG3Gk9kNSSXO4FRY7SW+X
         s20g==
X-Forwarded-Encrypted: i=2; AJvYcCVYsl0wfr21mOQcd6q7UzkraWzpAlBhrtIvRDX71T4Q7iL137d82JXMl+baLhzfeCwoLhgA3Q==@lfdr.de
X-Gm-Message-State: AOJu0YyW0GvP6Aq4jW2kcMSP2Uoq2+iqsWZHNR8y3jJj/KaLCJ4vgpmB
	Cx2FgG8+QdIU3Pxnhzjsn6Lr7uZW58YlEP2euPGV4T1tiYfxOM5/GuJ4
X-Google-Smtp-Source: AGHT+IGNiPjcpr5j3VOwORB9ksIttpvDAdLBS+c9e2VUBKwzT0+bE5wNmUnmRvkAMQ6aqXLmw4vFkg==
X-Received: by 2002:a05:600c:3b1a:b0:477:55ce:f3bc with SMTP id 5b1f17b1804b1-47904b12f1dmr325298675e9.19.1764695641661;
        Tue, 02 Dec 2025 09:14:01 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+a07bR7ps1wawAJWiovfKo5udJJxCe+GJvG/iCduGM8CA=="
Received: by 2002:a05:600c:3152:b0:477:a036:8e80 with SMTP id
 5b1f17b1804b1-4790fd192fbls30515495e9.0.-pod-prod-07-eu; Tue, 02 Dec 2025
 09:13:59 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXbNKGOKvwVaQTYjal99oPJbt3GwT4rKt7NBbXlIAVY0JHPTWGzprnDKJihx1u9UfVZ2cjiKfvT8+c=@googlegroups.com
X-Received: by 2002:a05:600c:4f53:b0:475:e007:bae0 with SMTP id 5b1f17b1804b1-47904b12f35mr349735825e9.16.1764695639425;
        Tue, 02 Dec 2025 09:13:59 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1764695639; cv=none;
        d=google.com; s=arc-20240605;
        b=GzmZtkCFtuTx1gghxxOMHXKua8QR2n+VG2h3zPUQYycN2wRBRPa5fderfLJLi2TpHt
         PmGlMK0xpwOUBWz2oCI/3n/fufLvzuu2ml4QcwlWvr2uHU3jY87krNi2sdUH9xmypDCu
         4qMmXAJ0xkX+0qPQ89Pm0WTIq0sUVakH2g6hFaEIcz6txOYjeYNx8bMawvKWx1vg7lMH
         Jyd9U7UJulfiv8i/7Ag4M+LDBgPHRlR/WMWa+KRB/4Vpme6OsEA8iDdkEAG17IGYfWL+
         eu6+xDSEkDZ4OqqINx15OoIES2jjEZhKQrt5M2nJ72FRpBwJLS1vaa9ExoXP0yBKNRjm
         okqQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:feedback-id:references
         :in-reply-to:message-id:subject:cc:from:to:date:dkim-signature;
        bh=9Vp4X2XP9zzZX2mNOr3bIXwE/WvkzEbcvbYHxtX/1nI=;
        fh=AQ61BNYmez3l77g8PKEeiNKmH4aoTInsDJvuedpOfvE=;
        b=L3zXMGp7xTucAMiu1rOF3K52FCy+lZSLQiQfmllpmTZ+jcyPjxe3W71BtHAiR3RCQD
         p7XW/UPXwXsipS1CCG6dwcej5EFFQMQEcmnNdfjanDqQRTAMOzj9CGo+JPLC5DubUuch
         91ke/0pE/oOdc/TeKsvU9k1aoYw1aN0W0CLDZ7UTTzJxbUM59ZEFAMtCsGuvUbVNZr9I
         X1dQXz6uh7P/DUBuZqrHWNjF8GGeoakF+iAMlL8k+wS6OLcqNGCh6IWe+4MNzRmhnkJW
         6AJ9w3Js5v+lH0qt9FsxiFrFpb9cwVqjKMtpcPaAsIt5MI+ehqJd5py2JYJecdiwRMcx
         7D6A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b=D0IrwHbz;
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 79.135.106.118 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
Received: from mail-106118.protonmail.ch (mail-106118.protonmail.ch. [79.135.106.118])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-4792a790073si1265e9.1.2025.12.02.09.13.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 02 Dec 2025 09:13:59 -0800 (PST)
Received-SPF: pass (google.com: domain of m.wieczorretman@pm.me designates 79.135.106.118 as permitted sender) client-ip=79.135.106.118;
Date: Tue, 02 Dec 2025 17:13:44 +0000
To: Andrew Morton <akpm@linux-foundation.org>
From: =?UTF-8?Q?=27Maciej_Wiecz=C3=B3r=2DRetman=27_via_kasan=2Ddev?= <kasan-dev@googlegroups.com>
Cc: urezki@gmail.com, elver@google.com, vincenzo.frascino@arm.com, glider@google.com, dvyukov@google.com, ryabinin.a.a@gmail.com, andreyknvl@gmail.com, kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, linux-mm@kvack.org, maciej.wieczor-retman@intel.com, Jiayuan Chen <jiayuan.chen@linux.dev>
Subject: Re: [PATCH v2 0/2] kasan: vmalloc: Fix incorrect tag assignment with multiple vm_structs
Message-ID: <pql2nsktwqkh7olaq7yzh5wtqvnpr6u2mdvtmaqipwwzvomtzo@bilmkfsgxhbo>
In-Reply-To: <20251202083522.1b0349117b9159b891808532@linux-foundation.org>
References: <cover.1764685296.git.m.wieczorretman@pm.me> <20251202083522.1b0349117b9159b891808532@linux-foundation.org>
Feedback-ID: 164464600:user:proton
X-Pm-Message-ID: 8e7bff291b714af2d585f45dc4652be83736ad4d
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: m.wieczorretman@pm.me
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@pm.me header.s=protonmail3 header.b=D0IrwHbz;       spf=pass
 (google.com: domain of m.wieczorretman@pm.me designates 79.135.106.118 as
 permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
X-Original-From: =?utf-8?Q?Maciej_Wiecz=C3=B3r-Retman?= <m.wieczorretman@pm.me>
Reply-To: =?utf-8?Q?Maciej_Wiecz=C3=B3r-Retman?= <m.wieczorretman@pm.me>
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

On 2025-12-02 at 08:35:22 -0800, Andrew Morton wrote:
>On Tue, 02 Dec 2025 14:27:56 +0000 Maciej Wieczor-Retman <m.wieczorretman@=
pm.me> wrote:
...
>
>This series overlaps a lot with
>
>https://lkml.kernel.org/r/20251128111516.244497-1-jiayuan.chen@linux.dev
>
>Please discuss!
>

Thanks for pointing it out, I'll test if Jiayuan's version of
__kasan_unpoison_vmalloc fixes the issue I'm seeing.

kind regards
Maciej Wiecz=C3=B3r-Retman

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/p=
ql2nsktwqkh7olaq7yzh5wtqvnpr6u2mdvtmaqipwwzvomtzo%40bilmkfsgxhbo.
