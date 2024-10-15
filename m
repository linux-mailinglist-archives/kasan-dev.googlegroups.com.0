Return-Path: <kasan-dev+bncBDW2JDUY5AORB34FW64AMGQE6IFCIQY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x438.google.com (mail-wr1-x438.google.com [IPv6:2a00:1450:4864:20::438])
	by mail.lfdr.de (Postfix) with ESMTPS id 6EBE399DB3E
	for <lists+kasan-dev@lfdr.de>; Tue, 15 Oct 2024 03:18:41 +0200 (CEST)
Received: by mail-wr1-x438.google.com with SMTP id ffacd0b85a97d-37d45de8bbfsf3025660f8f.3
        for <lists+kasan-dev@lfdr.de>; Mon, 14 Oct 2024 18:18:41 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1728955120; cv=pass;
        d=google.com; s=arc-20240605;
        b=GfZo6PnUNLJx6JvOFBSzwUkV5lZVF+wC9p0qHcGaSyP7/0zViQj6a466+Ml0Vt1Gf5
         taiKTmOk+QiUvd/0ORnS57Z1Jx/CJgVW4MIhWtWPIMrnjQoIMYlcUDFeY8siVVeA5/rz
         0HWSFu0Pbp9s7+aDKpUQ2fgnV8U8B1K1pFbdv/uqlNok/WOZ+1QhZ+zRD3KI87LUWVJf
         3sc9sSUOJr4vIan2suUEbQUW8clOaIH3Ub4xzDww6QXCR8/07dTORfamMvVnZfM8RgPA
         dZbjjHnOVCz5kkfGYKId8Fut/WzcF9o1F8DGbDtksVjk+DHIH5xSkwSnjuZsY5I6iNSm
         bt/g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=9YQODpJ4DrNB/I4AAKDztm+15bUWlQ5jOarpy2ae5zE=;
        fh=nt8GFZpJxTx6yGJ+XVSqUP7JfsCK6Lxqj6YcXwhD9GE=;
        b=dKv7osIza4NPtgp4c7Ueu8NXNi0DZCZvbJIlxO0RSytIuMKmz1DibC9472enBrNN3d
         J4bENw38y7lyaY3tTn7j0cwvL6nOP+NTYXebGpEbEXbHCmC16jClFH3t0O+IIgJHD954
         lI2S7wBtFs/xtGlOl3ettOn4eaSZI+CNMOq0GFjemfvNdWd0pWX3ATMMBEbA9LPKYehZ
         lwrl+ItriUZ94FFE65Lyx2amdxQKO4kH+S9aF0ucxBnA6HBvQ7+1B2HxB5lGcrX6AwhP
         T/ZnViXN/vC7NDc8YO1TFa/Fiv66ZRvLPJMbbw2MogSZO/v08iyyprgLJdrvOJhBJCzz
         0FQg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=OGHUUC59;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42a as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1728955120; x=1729559920; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=9YQODpJ4DrNB/I4AAKDztm+15bUWlQ5jOarpy2ae5zE=;
        b=oEkZrcjkIYyqeTpDEkcqW8K+vi8zp77PwGyX6aglVQJWV7ElT14N+a429wkmOFQf/Y
         poVmdfHA+14t9uaNSsIYeDFX91PHmIhm69bt1ON3jdZ8ZMsM5sxVNS7trPfFX52WSkMJ
         EKernavrZpNqWr3NoXCuGnEg/4lKT2orCFij8jIb7UKzsCUTnhr2F+2zqtiOKydKS60p
         8q/RMSI9pKXyk7RP22wcBwNPgO252w3ZzwLm4vE2SKOAghEauIp5R/9VXjGt1Ahb1wvz
         6NJGiuCtPIvjgZ1p7MXvnTiUkwPk6ZCL/S/ragUHNMiyQRVu3zQUrFzY4bBtHj3EIL+i
         LmtQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1728955120; x=1729559920; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=9YQODpJ4DrNB/I4AAKDztm+15bUWlQ5jOarpy2ae5zE=;
        b=Ui03xR3Pk6EJBBH+BLymzStkl1BxMjWnlnmmSRwRu4zGbpV0XqI7jOZOYdKbuOFOwv
         43JahZ8bEhToW01a+ThRBmAHjhI/qrUGuGQ2OlM7MV3UKkNzqH6J926jN2qFYV7fJ8ou
         oEXDs0GNXPk9U4swGxocUy3/cVxQma1QAwOi3BMelwS4G4BKSDQnBse4F4VOgq8890bR
         NBJuGzn+LlveUAnQ82vx0WRttCd/1FCWIE2Sxv6+BlfuMXqPyFo6TX1/jqOp+1tCJCKH
         NjLho3pqPGaPQsWKaUXj8PwM6Q8VqGu9AcLF/yefpOA43kB6xzpkkWA/MylDt3p+cAPu
         3HXQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1728955120; x=1729559920;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=9YQODpJ4DrNB/I4AAKDztm+15bUWlQ5jOarpy2ae5zE=;
        b=YdD3Bi6o4phlIIOz6kXhM/3SmTH0eN6yBwCNCs/uANi1lDD7M6FBmdm5iGRxf9MfS7
         NeTBBsWWz1HtjiWBnvVvLJR3Eq2LWB6WtVRPKbY82bR2yOm6cQHxEiDKcXUV0XnBE4Vq
         KDZSoTauwstGu5ofo+VtkopA0JUTQqp42oOnj4t3V4Bp3VqbeNyd+0cgNWQb6JWBFsyz
         0x0aQwXjSfzYt/whoQ4W80HYUuI4tjDi7wMooeFVWCDEZUEnpNZyo3lBHTX4Mqoc8Rzj
         gK9EggRbVNECP1SuPtRx6xdmzRT4m3eFY615AEl3T3BNjfDS5JZojcp9R5p1lGcQwtEX
         VogA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWRuSpP183ZNUmKM88jDJiW97Wrr2RioJikMJl76B0O9NSvDDXkcuLXIBiZ7UkJQN5ucN3S6w==@lfdr.de
X-Gm-Message-State: AOJu0Yzo20JwYhXlLk4CkNCAlUNlR2gKkl6zwQoSgfVB3ZUMt/9qjOXI
	HMJ5g3Yu0WBs2ZSf1ddRWLDukO2shhp98pGarnGVsWuZBilNBzej
X-Google-Smtp-Source: AGHT+IFwFWjTfsMIIfAj7ThXT/uuM9hRwuSAUeFSh12ula26KTfS1LjOc3H+qb3yP2a7SoGo4P6j2Q==
X-Received: by 2002:a5d:62d2:0:b0:37c:d1c6:7e45 with SMTP id ffacd0b85a97d-37d600d2f59mr8229825f8f.40.1728955119978;
        Mon, 14 Oct 2024 18:18:39 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:1c28:b0:42c:c82f:e2f with SMTP id
 5b1f17b1804b1-43115fe01b8ls8446955e9.2.-pod-prod-05-eu; Mon, 14 Oct 2024
 18:18:38 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVbbwee0pZOgSUaHuWe3mF/LZkG7hCYiTuqKIPtQa4Xdnrze7leToI4y0iEjpwQSYdCESUkq8Eu09I=@googlegroups.com
X-Received: by 2002:a05:6000:459f:b0:37d:4eeb:7366 with SMTP id ffacd0b85a97d-37d5ff27c30mr7704429f8f.4.1728955117988;
        Mon, 14 Oct 2024 18:18:37 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1728955117; cv=none;
        d=google.com; s=arc-20240605;
        b=TsG3Yt++lrdW/vuHxU1ATb4A97jBzkLCoacnUG3mWHHQQHE11h0a6yQRaUPTimM12G
         oMr1iBzdqO14+Oqhxk8ErdTo+rr/VYKOOBX7A+/3tC+T+ovTL0uzIHw+86K4jH36imwR
         FAku9Ruxfpa7hp9EgiYHXtO5UvaraBevr3Zc30PEGSpbsPMDztrEykaXQ/KbnN/BneCE
         l4n7SLRMcAWeUr0xDVbeR7UXG3in8uM9/xKZW8/Hobp3xdp1nZ/zgwxZo1qFZ7HStsaC
         HyWQv8Ty2Xq+9TQz5BMKxq3VmQSwx+kzsLimRJzPx1gHG5PKTo2r3AjhdSoG9G4i5aRX
         /RCg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=5/bXP3m0Q4mEvUmx0OmjCLIQItF8jOXbfM/6ldYROco=;
        fh=w+pwQB7O6ZzVnZf7DJWQgmiX4i4rKJyz1wS479iIY8w=;
        b=MTKFwDR9nqSqhVmWupSgPRLDoJ0W/g5qLjgTht3ELD4w0SHPHKc93mMs3YaznPApdE
         QGDH3lOhrh02QecXZ8HijrD3KhGw6q1mQC+lVwaz0F3vMxZOtHeHnYyN4g0yV5M7aSM3
         3E0r8DaZrVk9m3WDIxqqxYYj//KlklHNyMzLDsqE9Vdhf2cl3/5++5uOMGhno/h1CLfM
         bo8QaHrRbEBlBQ8oZ7TgNFoAWOQU3u0biGsixnY1PD1ztWOM4ueeIH4RXMIORtSQp6TW
         N0dvg9sZSgF2nM0YNTD7OLoA4V568+hYiZF3ubrXuSXytGYHA63AeYsifmqPMeUnIhRs
         /mJg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=OGHUUC59;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42a as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x42a.google.com (mail-wr1-x42a.google.com. [2a00:1450:4864:20::42a])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-4304ecf88d7si6491315e9.1.2024.10.14.18.18.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 14 Oct 2024 18:18:37 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42a as permitted sender) client-ip=2a00:1450:4864:20::42a;
Received: by mail-wr1-x42a.google.com with SMTP id ffacd0b85a97d-37d4ac91d97so4184960f8f.2
        for <kasan-dev@googlegroups.com>; Mon, 14 Oct 2024 18:18:37 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUaQamYoJQUCsxmeruPtnG6bTd+N81fB9IINzBeC0/V0qPdvk4kx3zHYC9AMEU4qWW0dtHDAWNSxds=@googlegroups.com
X-Received: by 2002:a05:6000:459f:b0:37d:4eeb:7366 with SMTP id
 ffacd0b85a97d-37d5ff27c30mr7704415f8f.4.1728955117170; Mon, 14 Oct 2024
 18:18:37 -0700 (PDT)
MIME-Version: 1.0
References: <CA+fCnZcyrGf5TBdkaG4M+r9ViKDwdCHZg12HUeeoTV3UNZnwBg@mail.gmail.com>
 <20241014025701.3096253-1-snovitoll@gmail.com> <20241014025701.3096253-3-snovitoll@gmail.com>
 <20241014161042.885cf17fca7850b5bbf2f8e5@linux-foundation.org>
In-Reply-To: <20241014161042.885cf17fca7850b5bbf2f8e5@linux-foundation.org>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Tue, 15 Oct 2024 03:18:26 +0200
Message-ID: <CA+fCnZcwoL3qWhKsmgCCPDeAW0zpKGn=H7F8w8Fmsg+7-Y8p3g@mail.gmail.com>
Subject: Re: [PATCH RESEND v3 2/3] kasan: migrate copy_user_test to kunit
To: Andrew Morton <akpm@linux-foundation.org>, Sabyrzhan Tasbolatov <snovitoll@gmail.com>
Cc: 2023002089@link.tyut.edu.cn, alexs@kernel.org, corbet@lwn.net, 
	dvyukov@google.com, elver@google.com, glider@google.com, 
	kasan-dev@googlegroups.com, linux-doc@vger.kernel.org, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, ryabinin.a.a@gmail.com, 
	siyanteng@loongson.cn, vincenzo.frascino@arm.com, workflows@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=OGHUUC59;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42a
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

On Tue, Oct 15, 2024 at 1:10=E2=80=AFAM Andrew Morton <akpm@linux-foundatio=
n.org> wrote:
>
> On Mon, 14 Oct 2024 07:57:00 +0500 Sabyrzhan Tasbolatov <snovitoll@gmail.=
com> wrote:
>
> > Migrate the copy_user_test to the KUnit framework to verify out-of-boun=
d
> > detection via KASAN reports in copy_from_user(), copy_to_user() and
> > their static functions.
> >
> > This is the last migrated test in kasan_test_module.c, therefore delete
> > the file.
> >
>
> x86_64 allmodconfig produces:
>
> vmlinux.o: warning: objtool: strncpy_from_user+0x8a: call to __check_obje=
ct_size() with UACCESS enabled

Too bad. I guess we have to duplicate both kasan_check_write and
check_object_size before both do_strncpy_from_user calls in
strncpy_from_user.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BfCnZcwoL3qWhKsmgCCPDeAW0zpKGn%3DH7F8w8Fmsg%2B7-Y8p3g%40mail.=
gmail.com.
