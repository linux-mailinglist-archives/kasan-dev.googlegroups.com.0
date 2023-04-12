Return-Path: <kasan-dev+bncBCBJ5VHVTUFBB2XO3OQQMGQE4AUOL6I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3b.google.com (mail-qv1-xf3b.google.com [IPv6:2607:f8b0:4864:20::f3b])
	by mail.lfdr.de (Postfix) with ESMTPS id C24B26DFD6A
	for <lists+kasan-dev@lfdr.de>; Wed, 12 Apr 2023 20:24:44 +0200 (CEST)
Received: by mail-qv1-xf3b.google.com with SMTP id p14-20020a0cc3ce000000b005e14204a86bsf18076119qvi.10
        for <lists+kasan-dev@lfdr.de>; Wed, 12 Apr 2023 11:24:44 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1681323883; cv=pass;
        d=google.com; s=arc-20160816;
        b=JBhuHJz8EySN6aeDCsNMULqq4U1Fevsyy5lT5vY8IIW4+DQgZ3WPLDXu+nV489tIj5
         ckbjgL7hxNuNtW/gaSbutG38rFNpG+coNMprWSLtzdggO5aeETOy/37LqqAS/71I3k7p
         /u1IGDuNKBycRIo6pZOUYT75r6XNjRwpiyjsijOpHcRhARbHSuy0F8jHcwAhoEurivQK
         yb1S9yKJYubV9gporKv7qLPfElf9vyA1kOap1ZI7NOvfJkZXRIfseOQ2MEBiHifGRlzX
         /deM0Ok8HJ+qT8CuZHrVwZeF5bNAtAYm7S0s24Xt0NON4/oTIePuMeZxp4Js3oFjJJyp
         V3mg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=jrX2RnVGMJBjNbZENPox/+h7Mud+OsIY35eUD6lQ78k=;
        b=ROBxlUYkMvXxAbR3HdbatMwTIo1qJebuNiSOIJLc/+k1vwVu4B5mpr4PJh0FrOiW/z
         U1ejSyh0lTVETGs3WW/RYIOngZO617fnGx2ISOAOUnoquDbN3mv48E761BSQ1miTg7OA
         YxctLpTVj62EWFod0qmrUABAN4RAJEg4SqLdh4pKaXpuMBTIC8/NjigrhUKEIaBpvAYm
         r/CPsLg1yurU6XJCmyVffIai1DfvE7aDWMoIKDZRkC8pSsmrYImdRvry99tzXUDZ494a
         oy+h/89ZM9T91r6gD0o0yH1voiPDFCE1d6n4nZOA/QL325fnZBVtfgPbD+I0P1EQx+4g
         LJ4g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20221208 header.b=MKMmL4qs;
       spf=pass (google.com: domain of mail.dipanjan.das@gmail.com designates 2607:f8b0:4864:20::330 as permitted sender) smtp.mailfrom=mail.dipanjan.das@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1681323883; x=1683915883;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=jrX2RnVGMJBjNbZENPox/+h7Mud+OsIY35eUD6lQ78k=;
        b=bhk0f+c3Iaka5rmBfKn9LcmDGGmO5DQnFtacmxaUM2nslQu9uBbrDYwbSCrivEqHvr
         3TYxAyBTfWHexnV6AQK5Lt0RbWQlVhjMEbVXR9H+ZQD4kK1QDpLoaNVFOhPWR0Xu8+Nt
         tLiRrmfi3JnLIiUHQ8+UQtMqpnPeOEgA2Cyh1Cn8/9b/DUDKUZdhJknvUjwxKQrISHBg
         R3dQW64lNmaCRbQaqWLPo16aAYo0YjYIXXKYSeY3p1HTtCovQv6hFLJz3bHBGUUcm0rS
         ebQ47x9ibHdxQXbCeQV1epnQG9qe6HrOHO/B/sFvs1+EEdwD4ge9Tfx267Brm10eaGxu
         /DkQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20221208; t=1681323883; x=1683915883;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=jrX2RnVGMJBjNbZENPox/+h7Mud+OsIY35eUD6lQ78k=;
        b=D1NOEre6BJBDihDugq5dLqFNa4hUCUh1CrN8j7VP4OgIQg0UMB0y0Dx41pQjl1kh5F
         6w8PgiKL25mbrJg1mkj8i72ug56PC+NGkTV0G5x+MLttzo13dPGl+hCpwmkAmsTg/33U
         HzlnqMnSWY1ezow9fW4D5bfkDNRmWWFiBTBj/KBjLZIc0cGzypIXjq8aZefVRYF7IgrT
         hUF7/7bP6kAfL+7w69JzQIbVl+2yBPc8+YY5/GUuf0uxCBeodnvjpirZSbJ6ONNUJ6/J
         yDjUTFPbiLh0c6ZQ1GtcPKKhKkz8Aq82pJV9qidYZerXBG4r3sHi5Td3PwqYgPafGaDd
         BgxA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1681323883; x=1683915883;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=jrX2RnVGMJBjNbZENPox/+h7Mud+OsIY35eUD6lQ78k=;
        b=PFjYozlrHKVf/5T9UWSijImnZ8XZDuSdJeiMV9c41tT7KfEL5+GYH3vkW/Jy4s47By
         lxXIVy+wuoRms8XmswEy2lrkBG9HGRjDplzk+1nlWU8pkBOnjPVGGB3chNsDS9NmB6+C
         DMW7C0gPXLWk6zJt+3SNQ3XH27Cw/cDjo6X8UQxFe6ZKpJ4uOvvSWeMvTKYWtOac05D0
         nYPi0mMnVNi8kD9cUF1x3/2JDR4P+18j815SlU9vCAmJJ6EZkV3iyitwrOz4W0aCn3Q3
         MkIBgawTJigJZOtyWnKIr4Lqgn0zzPOWTp2O5Sy/LRvlKMVIhk+OQXV8DGzrNEZYFkX3
         jSqw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AAQBX9f+T2bBTP2eX+JSYK9s5njc6Qsi2FTYLvcC4hpW7q5064ROr8je
	VqZ7kpJXw61nNVp+ZV+STw4=
X-Google-Smtp-Source: AKy350Z1Ftc+4jx+pMqhgSTHxDel1NC2aE62afUGmVQAVeazM1M1KOwxcvPpJ/V1sc9D7m1rmL0Uyg==
X-Received: by 2002:a05:622a:1801:b0:3d7:9d03:75af with SMTP id t1-20020a05622a180100b003d79d0375afmr5228966qtc.12.1681323883108;
        Wed, 12 Apr 2023 11:24:43 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:5889:b0:5ee:87d9:b564 with SMTP id
 md9-20020a056214588900b005ee87d9b564ls5151672qvb.4.-pod-prod-gmail; Wed, 12
 Apr 2023 11:24:42 -0700 (PDT)
X-Received: by 2002:a05:6214:1cce:b0:56f:c138:2844 with SMTP id g14-20020a0562141cce00b0056fc1382844mr105360qvd.37.1681323882561;
        Wed, 12 Apr 2023 11:24:42 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1681323882; cv=none;
        d=google.com; s=arc-20160816;
        b=YK7j9P6gFKJAgONHkzkUBJVLJk8P7oEwBmAAdp/gSkq9QfT/ltkvAEv0ffVb1AJnwe
         N3GZzh2gJ9EwXDMGHB8nUhI9P7qmT4Z81ikWvjzIjAq9Q6LMEe+fR0p6drzsv6nLW9h7
         TuVcIv/dEo5PmrN9K5W+S6XPgLUW5qulbhA1v22nPkJygP6MlhufZroaW+j7iU3VbM5r
         BBM06puMgL5USwSa50cLA1yDFIQ+xUqN3tOenQ+LiwvjJxtVIQix1DaEW9u/zuidYHJr
         7+vpKDcs3hha471urtYS5stV4V71C8Mt/1rkLXuCzQTETOLzifOGWqOLOOkg54PpbfCs
         Jo9w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=VezbKOf2ys8mmlrW6/XtyNOzwlQ4f87v3oaLK1/JLPM=;
        b=sQ1Zz13k1fvf4BXHGdgMeq6Me7CmM844FAtwLsbouCbQh1MGP0CcFSlunpYPLuGWOJ
         TUsiHOdWzbrMP+KDnwDcJRfd4BERoOBEFEqd8wUu1AjXHD2Rg4d9M5o1Z223ek9XodZY
         jizQ1IIIW+9FOPk3KVPnQvDCEu5Gh31CRT7mz2N+5U6L7wc1jpx0EpzHZzgU1wggGHH/
         JFnWmo1SEoSs1K9lVgmaonqAMKiyNykQv/pVWvXZOdsXfKj/1yeToQWG6Q3E3gQUAdR7
         bWXiYGDZNib8I0WqMuNYEtk8gPRxHWdFinp+0SX2W486YOqlfLE50KRjmhmSqf0O2Zwp
         Htkw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20221208 header.b=MKMmL4qs;
       spf=pass (google.com: domain of mail.dipanjan.das@gmail.com designates 2607:f8b0:4864:20::330 as permitted sender) smtp.mailfrom=mail.dipanjan.das@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-ot1-x330.google.com (mail-ot1-x330.google.com. [2607:f8b0:4864:20::330])
        by gmr-mx.google.com with ESMTPS id od7-20020a0562142f0700b005e63f83b836si1115303qvb.4.2023.04.12.11.24.42
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 12 Apr 2023 11:24:42 -0700 (PDT)
Received-SPF: pass (google.com: domain of mail.dipanjan.das@gmail.com designates 2607:f8b0:4864:20::330 as permitted sender) client-ip=2607:f8b0:4864:20::330;
Received: by mail-ot1-x330.google.com with SMTP id i15-20020a9d610f000000b006a11f365d13so5220937otj.0;
        Wed, 12 Apr 2023 11:24:42 -0700 (PDT)
X-Received: by 2002:a05:6830:114e:b0:6a1:3fd6:5a0b with SMTP id
 x14-20020a056830114e00b006a13fd65a0bmr4189583otq.2.1681323882121; Wed, 12 Apr
 2023 11:24:42 -0700 (PDT)
MIME-Version: 1.0
References: <CANX2M5ZRrRA64k0hOif02TjmY9kbbO2aCBPyq79es34RXZ=cAw@mail.gmail.com>
 <CAG_fn=V57m0om5HUHHFOQr9R9TWHtfm4+jO96Smf+Q+XjRkxtQ@mail.gmail.com>
In-Reply-To: <CAG_fn=V57m0om5HUHHFOQr9R9TWHtfm4+jO96Smf+Q+XjRkxtQ@mail.gmail.com>
From: Dipanjan Das <mail.dipanjan.das@gmail.com>
Date: Wed, 12 Apr 2023 11:24:31 -0700
Message-ID: <CANX2M5bWPMDJGgD=xq33A3p96ii3wBOuy9UKYAstX4psdAGrrA@mail.gmail.com>
Subject: Re: Possible incorrect handling of fault injection inside KMSAN instrumentation
To: Alexander Potapenko <glider@google.com>
Cc: Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrew Morton <akpm@linux-foundation.org>, kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>, syzkaller <syzkaller@googlegroups.com>, 
	Marius Fleischer <fleischermarius@googlemail.com>, 
	Priyanka Bose <its.priyanka.bose@gmail.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: mail.dipanjan.das@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20221208 header.b=MKMmL4qs;       spf=pass
 (google.com: domain of mail.dipanjan.das@gmail.com designates
 2607:f8b0:4864:20::330 as permitted sender) smtp.mailfrom=mail.dipanjan.das@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Wed, Apr 12, 2023 at 7:39=E2=80=AFAM Alexander Potapenko <glider@google.=
com> wrote:

> Here are two patches that fix the problem:
>  - https://github.com/google/kmsan/commit/b793a6d5a1c1258326b0f53d6e3ac8a=
a3eeb3499
> - for kmsan_vmap_pages_range_noflush();
>  - https://github.com/google/kmsan/commit/cb9e33e0cd7ff735bc302ff69c02274=
f24060cff
> - for kmsan_ioremap_page_range()
>
> Can you please try them out?

The second patch needs a small modification.

The return value of `__vmap_pages_range_noflush` at Line 181
(https://github.com/google/kmsan/commit/cb9e33e0cd7ff735bc302ff69c02274f240=
60cff#diff-6c23520766ef70571c16b74ed93474716645c7ba81dc07028c076b6fd5ad2731=
R181)
should also be assigned to `mapped`. With this modification, the patch
works.

--=20
Thanks and Regards,

Dipanjan

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CANX2M5bWPMDJGgD%3Dxq33A3p96ii3wBOuy9UKYAstX4psdAGrrA%40mail.gmai=
l.com.
