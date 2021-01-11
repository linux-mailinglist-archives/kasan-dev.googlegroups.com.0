Return-Path: <kasan-dev+bncBD63B2HX4EPBBQGZ6L7QKGQEABT5G5Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x738.google.com (mail-qk1-x738.google.com [IPv6:2607:f8b0:4864:20::738])
	by mail.lfdr.de (Postfix) with ESMTPS id B3D6B2F1FE3
	for <lists+kasan-dev@lfdr.de>; Mon, 11 Jan 2021 20:53:37 +0100 (CET)
Received: by mail-qk1-x738.google.com with SMTP id f27sf469658qkh.0
        for <lists+kasan-dev@lfdr.de>; Mon, 11 Jan 2021 11:53:37 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610394816; cv=pass;
        d=google.com; s=arc-20160816;
        b=U68Y/vZq5FQ2Tkt4GDYeWqmIHYpv/4Sd850hVAv8J9OFqDuXkunvnPTZdl9aZFROmz
         u0w1+Nymby/eytYroIaKa0k9ylevLOlJ0Gigtai69IwJ7JHcjkHp2lq/FZfD2bB124lP
         i5QvVOjR5u+z5bdKMeaAO+YSE1WURonNfHLbKG+xoZkkO7lkmTYOc37B8hcKr3AVUB3z
         RUmXVIimOyKiF9/GPzv5Bx+ZbfaIg20utzwas1cYbXq2vJ7A/Fed+drlCvbuGwHb5c8v
         vFsQj65Rvy5y/CkNeLqEoCFR5Ew5dNiISR/R8eYh3oOGIzgL6fERoq1iw9ZgvPJNVJYQ
         i1fA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:dkim-signature;
        bh=vcCKpG15lFxkfUhW2Xa4yP4GBnj8iKJzranwVbKhlio=;
        b=EoqZNmamW5YZdxhBzP6FE4WCaZk/Qj/axURBXkkhYVgmaNDZrwlTLuooduLa5syL2a
         Z2tbvdBz4WN3tVc2t45oyeyzoAqyBuMHbpw/XRyPv0MGGiMbLCNj+KLu/G4XRSi/nnQ/
         a59sffIPOnKvBKTLAAmenGIcqA2XVxWZHAQ0SG1l7WSdVaeBFwZ4/etERhOXqCdGjXWo
         eHKMy+HlNREyREAc2hPSP4wG58LYBvOR5lMMhW5a5Y+vZUIAYW8WW+4FSeMGKd8hsxDE
         wOGW629EFvmpfrPbuUonCnKIL6u7o+ZjcegZaZVxitjx1ltbRGhsYNtTCNyY819Lhpiv
         YnuQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@purestorage.com header.s=google header.b=VW3dSKL+;
       spf=pass (google.com: domain of joern@purestorage.com designates 2607:f8b0:4864:20::52d as permitted sender) smtp.mailfrom=joern@purestorage.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=purestorage.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:content-transfer-encoding:in-reply-to
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=vcCKpG15lFxkfUhW2Xa4yP4GBnj8iKJzranwVbKhlio=;
        b=btOGEA/yJfLST56dXu8/YNIe8UPBJNgse4yD4K9jVOPEOED2cGCMn3iybNM2qlhT+g
         XE2WPTGPub6Mrussg4mAtSf1GA2tlKhcf7y79KiuwdVpfEocS64UsNbz/RiROstZEsK2
         qmYB7IXMdOlyrFLYGThjECu4+TsUpJAm6b//DdSsJys36zARDD0ZN3iU8OTuNcXaksQR
         4Gm87S2GxHk0Sm8qxh9EUokpszElgmA7+Q/9KDGc32QXSTlZcNi6xDVFnmLzpBqV8hW5
         pxzQhG8T/j/kx3O0t/4j+5L3yZ4uenN3hizrTxtnhpbxXJ2Il7Pg1jcA9jjPp9J/bnBE
         /hpg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:content-transfer-encoding
         :in-reply-to:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:x-spam-checked-in-group
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=vcCKpG15lFxkfUhW2Xa4yP4GBnj8iKJzranwVbKhlio=;
        b=XvqQ/3CkN85+EaEvUXEZuwGKD43EDSdoPAbZTE30scPh4yY/co84xG+YaS2XUybQKF
         i/n/x7PNMetORVTIP5/Rdceo5jSyqW0v50yPCHW0aSsjiRE/FJ2VxKxRW9TItvIwDt91
         T1qhvQ3ZwfcVj1r0el9keDqUupgq2zSIlVgxIqNaMXUO/PVsXhchpt4zDhc1Ucdg0Gk8
         O8F+J5T/ko4iFWI+7sb3M3CGlH6mZLf/2KTIcEBOta2AvwSLnFW+w2P+7bIgrkRb0ig8
         B8CwOVCUfoY30QHurpxjM0+PG51rdQnXWMlYPHrh+7I2M0f0EmDtV5pV3ghIOv30whLh
         TxWA==
X-Gm-Message-State: AOAM531xYwG0J0twHU4N27OQsgtf9jdv5ytbsl7NX1NjYHdKpdyEIsOh
	7D/KRyG7exQviAQu2e43EJU=
X-Google-Smtp-Source: ABdhPJzX4px2s24zMcoTtOQILMYvlFkZhCDheKTCDE4LJvrpflyLVKJxwQaZMDvAqdlPj6n8ZB1Wwg==
X-Received: by 2002:ad4:43ca:: with SMTP id o10mr936054qvs.25.1610394816292;
        Mon, 11 Jan 2021 11:53:36 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ae9:ea19:: with SMTP id f25ls441206qkg.7.gmail; Mon, 11 Jan
 2021 11:53:35 -0800 (PST)
X-Received: by 2002:a05:620a:1372:: with SMTP id d18mr1033212qkl.6.1610394815830;
        Mon, 11 Jan 2021 11:53:35 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610394815; cv=none;
        d=google.com; s=arc-20160816;
        b=Y58w1veL+5ZG817tC7oEwD5TVfZqofjvLFpkcK8r94pvfejYE9YOm6Hfg1btrWCnoQ
         S/rUD/kDWRvc6wmh2qEPbBsr11wlHDF5x6ld37QW4COLfrw5D5eeiIwBTzy4nMrGWJZj
         TQw0JZAyeISWuH5G8peODHhQATC8AsfHYkA6feme/4esGUm14Nk0lYhwBo5ql5w8DwwD
         WzYsUTOpoWdhVvsIaUkoD8aELUILj7VoskxFQ5H6TZpQhuVZvc0mTivJg+SPzyN6qriQ
         D5cLcbVeS1WtW8noB1I28zcXfPfYLk/6N2s6j4OI4J2XL7Ch+aVyfJuTepLyqPzarVIY
         pd9A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=W0UlAxGx6cPxB4zsQ5Of6JULhAu0iyeaTVS9cOPK46I=;
        b=Y5CeMOHzFRltVcz810DicHwRLsF9D5OetonIAHJwIdNC76+BLL5cvdAReboQopYevw
         uRpkUKJAOPZpxCnoejJ7LHQaOExSKvWDNUr4OD7YdWT3QmFujKm+W+KMMZQ0nu2QaKoU
         GKsUJ5rE4JT39Z+IOZZLUD0fEOJZTpqLHaOZTbVIgEHMV6zGpZgYgEVn2zUvjZH1M0QQ
         0r3eJNqGwJz8ktjb+NYnNiOsFrJyzgjiEEXsu3kNZF3/ckNeLDuDaE6kvBizaIxN3gKo
         H1SEus34EfeoWezcppqelKwQFTIRppqIu8QUpFaPsq477f3B1u//5HjFCl5iWAqSXlpE
         3N/g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@purestorage.com header.s=google header.b=VW3dSKL+;
       spf=pass (google.com: domain of joern@purestorage.com designates 2607:f8b0:4864:20::52d as permitted sender) smtp.mailfrom=joern@purestorage.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=purestorage.com
Received: from mail-pg1-x52d.google.com (mail-pg1-x52d.google.com. [2607:f8b0:4864:20::52d])
        by gmr-mx.google.com with ESMTPS id z25si63417qth.3.2021.01.11.11.53.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 11 Jan 2021 11:53:35 -0800 (PST)
Received-SPF: pass (google.com: domain of joern@purestorage.com designates 2607:f8b0:4864:20::52d as permitted sender) client-ip=2607:f8b0:4864:20::52d;
Received: by mail-pg1-x52d.google.com with SMTP id i5so370161pgo.1
        for <kasan-dev@googlegroups.com>; Mon, 11 Jan 2021 11:53:35 -0800 (PST)
X-Received: by 2002:a62:19ca:0:b029:19d:cd0d:af83 with SMTP id 193-20020a6219ca0000b029019dcd0daf83mr994521pfz.51.1610394815031;
        Mon, 11 Jan 2021 11:53:35 -0800 (PST)
Received: from cork (c-73-93-175-39.hsd1.ca.comcast.net. [73.93.175.39])
        by smtp.gmail.com with ESMTPSA id z12sm423456pfn.186.2021.01.11.11.53.32
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 11 Jan 2021 11:53:33 -0800 (PST)
Date: Mon, 11 Jan 2021 11:53:23 -0800
From: =?UTF-8?B?J0rDtnJuIEVuZ2VsJyB2aWEga2FzYW4tZGV2?= <kasan-dev@googlegroups.com>
To: Marco Elver <elver@google.com>
Cc: akpm@linux-foundation.org, glider@google.com, dvyukov@google.com,
	andreyknvl@google.com, jannh@google.com, mark.rutland@arm.com,
	linux-kernel@vger.kernel.org, linux-mm@kvack.org,
	kasan-dev@googlegroups.com
Subject: Re: [PATCH mm 1/2] kfence: add option to use KFENCE without static
 keys
Message-ID: <20210111195323.GA842777@cork>
References: <20210111091544.3287013-1-elver@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <20210111091544.3287013-1-elver@google.com>
X-Original-Sender: joern@purestorage.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@purestorage.com header.s=google header.b=VW3dSKL+;       spf=pass
 (google.com: domain of joern@purestorage.com designates 2607:f8b0:4864:20::52d
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

On Mon, Jan 11, 2021 at 10:15:43AM +0100, Marco Elver wrote:
> For certain usecases, specifically where the sample interval is always
> set to a very low value such as 1ms, it can make sense to use a dynamic
> branch instead of static branches due to the overhead of toggling a
> static branch.

I ended up with 100=C2=B5s and couldn't measure a performance problem in ou=
r
benchmarks.  My results don't have predictive value for anyone else, of
course.

> Therefore, add a new Kconfig option to remove the static branches and
> instead check kfence_allocation_gate if a KFENCE allocation should be
> set up.
>=20
> Suggested-by: J=C3=B6rn Engel <joern@purestorage.com>
> Signed-off-by: Marco Elver <elver@google.com>

Reviewed-by: J=C3=B6rn Engel <joern@purestorage.com>

J=C3=B6rn

--
One of the things I=E2=80=99ve discovered over the years, is that you can
create change or you can receive credit =E2=80=93 not both.
-- Stephen Downes

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20210111195323.GA842777%40cork.
