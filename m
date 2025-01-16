Return-Path: <kasan-dev+bncBCCMH5WKTMGRBS7PUK6AMGQEJEWLCXA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1037.google.com (mail-pj1-x1037.google.com [IPv6:2607:f8b0:4864:20::1037])
	by mail.lfdr.de (Postfix) with ESMTPS id 609A5A13405
	for <lists+kasan-dev@lfdr.de>; Thu, 16 Jan 2025 08:39:57 +0100 (CET)
Received: by mail-pj1-x1037.google.com with SMTP id 98e67ed59e1d1-2ee3206466asf3590194a91.1
        for <lists+kasan-dev@lfdr.de>; Wed, 15 Jan 2025 23:39:57 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1737013195; cv=pass;
        d=google.com; s=arc-20240605;
        b=SLYqY4ZFIBRiMrxweJkQZDEQlLH17fgUuQeAeh5rwNn8nSz61d1orr4lUOlnUwXvc8
         slhnl5dtPQZDrtTEX8Mk+0yoj/cErIYWRUX7SRox3PSbL++v3t5+JdLbX+8bmR9a9WQT
         LS//4ZpiLsfUp+CwfqlJx3IdNBlFnNfEb32ymEIiUwdFnmmlhFpTpQXvHabs5gOxB2+p
         8tsJxGjWbE4NiY1MpMetO1fjVFpjPKVucrWcvuyIv8izY6ywpoi2aaFuYwLPiK9X45Bo
         sxvrXlNZhBFfBLE0QiTPCta+6ZsZAefdhIDaOglbtFWe7AI4PERpr0D0PbSktdrUsDd6
         7Xow==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=vM84/GUZh9B0oDlWW9jsmIv3deHu/XOSb0wtdZWCtuc=;
        fh=B+JNGadKBDwQWWMvbxmkycItDXzZTHvW7g9Y7yD5DDQ=;
        b=c5AEw2orYuZQjp8GWAEHjugO0vxTYKc046DFZjnTQB6LfJYxyJ37cIYWEmonKRppPh
         Z1z7mJU2aDJFpMHpMF8KxIkbNCr4RtfA9S3l/bWJXTwkldZF2qvuv32kQfgbYyrlVxuO
         8T7FWoQtiQH8blkV/VwpZ427Q8jKCvD/MO3WIqQxFbsVtNDPFKmmm4ORFCcx1eWMj29f
         NKAe8ezEb1MeG4/wIgLpwzH9fd6EPOInDmx54rbZPG3dtZHqVyGsouUt9GlZQFXcZRgQ
         8RKYUBuWssJ1Fsn5bOn5/BHiI5QbUm560GapCMvID15aby3wRTblaC9KAeGkdpSeoaKy
         n/EA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=YQaIXPS0;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2a as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1737013195; x=1737617995; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=vM84/GUZh9B0oDlWW9jsmIv3deHu/XOSb0wtdZWCtuc=;
        b=Bn0urbD4nKCRe8kztt8STwsvnZMvUyUmKLlykIoDcEQjSjo1iHzOjovMsnoJcZfYMZ
         XrTatvQTHJDaU3jpGqnHquJFiWjeOR80w3unmxwDNJQUaHmg/ThxR2M74ELLDXK+yVul
         C6g8C7/bMhMWxGpH2Uxf42TsnxqRnh783API2/nkTVSziL2BPJwFYh+dmWXSrxVQIfv8
         o/+Xz5RiuqHXeSHSDMXE1OagfiV0L5OwKsZJwiKeKUG6YpcZQC4w8t23t7eWn7EvJ52f
         4weVwf4VdSiEUqiqZezXfw4Zrj/1D4jER9i3ctNLpOO9MhGnjfwh2JFSMXpFu0KjXRVq
         acTQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1737013195; x=1737617995;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=vM84/GUZh9B0oDlWW9jsmIv3deHu/XOSb0wtdZWCtuc=;
        b=TaUfphzm+n4v5MOUX1YsS0PkZ/wIdQcnYzIsa9WVWXmNncSVDENcQSB1G+5wxT5G2Z
         iVhpN5t7xcjquVHcfupL5438PJ49bNLs541XCQprRc8XBzwArh/wFZrtpG42pRtanZiq
         /0nGsDWwa9ddwwZa++SdW+OXRNidtTn6SOoCuC2o3WUj7LpFUpxll/dEtI3A6dNEeBeZ
         ySYKHALe9t6IN78vAxMBj5EsLmWzax6CYCQnVX1ORHEPI52zbhd3s2GZSIJcOPKnecxD
         r2v2W5Zid9Ijz0NQyywxazduPdszb2Vn1aVWt0JEdCSpVwxVg2+NrKNqWkR9gaL/XYzK
         8KPA==
X-Forwarded-Encrypted: i=2; AJvYcCWP9JkYDZ9I2t1ooF0PEMd/Es1oYpeIkULBG0pB+G9cHAE4UHcSREw6WuFLbtchjNkOnZrmYQ==@lfdr.de
X-Gm-Message-State: AOJu0YxLk7VW9SUEQqG6w3IC9afoZKrijIVsG9ALI0h7JiI5lWFTe++c
	mnNJNm7ProX8qNImerYydlJIz5AI5w7ewUXvCdfjENKf4lczEYaP
X-Google-Smtp-Source: AGHT+IHYrkmGvjEesBfg7GW75S7p2DEMBmBXJS1rOjsAasEnCN8aDyPw1gdfS2g3Glt1oOh5n6J8fA==
X-Received: by 2002:a17:90b:1a81:b0:2ef:7be8:e987 with SMTP id 98e67ed59e1d1-2f728e4841cmr9233373a91.12.1737013195439;
        Wed, 15 Jan 2025 23:39:55 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:c88c:b0:2ef:67c2:401e with SMTP id
 98e67ed59e1d1-2f7272548b0ls1379772a91.0.-pod-prod-00-us-canary; Wed, 15 Jan
 2025 23:39:54 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXQy27Ic92AsTGn1a7vk/Eb183If7KYDB4VYfl0GDItxoq1veSCSN2LtgtWS9eJL5/SOYP/L6kmkvA=@googlegroups.com
X-Received: by 2002:a17:902:d581:b0:216:4122:ab3a with SMTP id d9443c01a7336-21bf029debemr103044895ad.1.1737013194014;
        Wed, 15 Jan 2025 23:39:54 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1737013194; cv=none;
        d=google.com; s=arc-20240605;
        b=UAlEN1pKcTWJKngCAu1xjmNY/O+7tpkcrrSPb7yb0G8Ub2eAkxz30hv3t/ssdLoau5
         nTvJ6e3OTLbp0hIQKNKPMEPnRLcG5lYgRqm1HOcZvZEBC4d9ulzc2/ZRxFrU2jxpwb+l
         jJTVZVN0ymOrf8pO9LVgBReY1G1eVq9Yq34ADItB9evAlQsnLq57o7RnbyjHjXh2egrN
         ejSW9dZpu2bgmuIycZyupvhYU9ORn1A0Cg5CTo4ogDIGkxFYKsFYh6A90wPT2TfLYzLD
         8lELcHVKm5i/NLxfqX4lDfKg2TDMpoxEQTXbWLI3SIY0BVraJvAfQ83qV47QKxftkHPZ
         x4wA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=XnsonSG3YAIuM3BeNkOarero+je6Iz6iPZTQyi6Z0yU=;
        fh=gTf4ghf0rNStmh+hHsB+iEIsbmB+FXCG1X384mrmcFI=;
        b=AkbhXXKgOLJtTU651nIDL1HtvJ/gBaGvtZFheEUYyibgSv9BMbWLagqyRrEAXU+nLV
         ifVOVX+8yGiisar+dPQqZlhiLjXYaA0KsWvPzH/n8FGexMoFe7gCVdhjr99isdxhGx+R
         zk/NIQe59MLwlPmWd0x4qmx1Q9hRD/3wykaUtMaRkOUwmaAjwFa9Ym3+QPic5tZpZLqv
         rv1FQ+ONLWAqjlXS1O94mIlTNigXVk6ejIe+52DFI9gOhSaBr4WLTuEHaxL+A+WLd+WF
         M91gwsFEqsNglk68ll2FN7jFyJuWJAZXA5Naucs5ocw7aUaqz5gobuk7c5wqtPnTpt+r
         dKTg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=YQaIXPS0;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2a as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qv1-xf2a.google.com (mail-qv1-xf2a.google.com. [2607:f8b0:4864:20::f2a])
        by gmr-mx.google.com with ESMTPS id 41be03b00d2f7-a31b946c5f1si620243a12.4.2025.01.15.23.39.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 15 Jan 2025 23:39:54 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2a as permitted sender) client-ip=2607:f8b0:4864:20::f2a;
Received: by mail-qv1-xf2a.google.com with SMTP id 6a1803df08f44-6d88cb85987so6190426d6.1
        for <kasan-dev@googlegroups.com>; Wed, 15 Jan 2025 23:39:53 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCWv6uqJzuz41RCgnH02pq1EWaEjAI+FcWt2GsWPFvsS/1B5NtZuxFDebEQb0aLPulM8S/+AlXpdx28=@googlegroups.com
X-Gm-Gg: ASbGncvuY6zv4I4lXmc6irlDNI+yQLKVCQ5qHo9C+ztUmDcHWun0FPyrWHEOq1rcuGS
	YUIK8rr5uZ9MV8NuciEr2atyHyX8Y9yQUWHyptFdhuDv4sC7mpOognFExiMo5PUqW8or8
X-Received: by 2002:a05:6214:d6f:b0:6e1:a5c2:316e with SMTP id
 6a1803df08f44-6e1a5c2339fmr18714536d6.15.1737013193048; Wed, 15 Jan 2025
 23:39:53 -0800 (PST)
MIME-Version: 1.0
References: <20250116062403.2496-2-thorsten.blum@linux.dev>
In-Reply-To: <20250116062403.2496-2-thorsten.blum@linux.dev>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 16 Jan 2025 08:39:14 +0100
X-Gm-Features: AbW1kvZkPRL-ICwmcawuyYem4W9qjbznY16Uq017-DUYV88YGwbShARwSzhsKtI
Message-ID: <CAG_fn=X6i2CRJR9JMaJWJmiQqt+54O=a2KJY76nVuGTF9YKhow@mail.gmail.com>
Subject: Re: [PATCH] kasan: sw_tags: Use str_on_off() helper in kasan_init_sw_tags()
To: Thorsten Blum <thorsten.blum@linux.dev>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Anshuman Khandual <anshuman.khandual@arm.com>, 
	kasan-dev@googlegroups.com, linux-mm@kvack.org, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=YQaIXPS0;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2a as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

On Thu, Jan 16, 2025 at 7:24=E2=80=AFAM Thorsten Blum <thorsten.blum@linux.=
dev> wrote:
>
> Remove hard-coded strings by using the str_on_off() helper function.
>
> Suggested-by: Anshuman Khandual <anshuman.khandual@arm.com>
> Signed-off-by: Thorsten Blum <thorsten.blum@linux.dev>
Reviewed-by: Alexander Potapenko <glider@google.com>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
AG_fn%3DX6i2CRJR9JMaJWJmiQqt%2B54O%3Da2KJY76nVuGTF9YKhow%40mail.gmail.com.
