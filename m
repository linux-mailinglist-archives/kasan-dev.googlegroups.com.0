Return-Path: <kasan-dev+bncBCSL7B6LWYHBBJPRYPFQMGQEGW2XSEY@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id yEX4Jqn4cGmgbAAAu9opvQ
	(envelope-from <kasan-dev+bncBCSL7B6LWYHBBJPRYPFQMGQEGW2XSEY@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Wed, 21 Jan 2026 17:02:49 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1039.google.com (mail-pj1-x1039.google.com [IPv6:2607:f8b0:4864:20::1039])
	by mail.lfdr.de (Postfix) with ESMTPS id 987D4599EA
	for <lists+kasan-dev@lfdr.de>; Wed, 21 Jan 2026 17:02:48 +0100 (CET)
Received: by mail-pj1-x1039.google.com with SMTP id 98e67ed59e1d1-34c66cb671fsf25877a91.3
        for <lists+kasan-dev@lfdr.de>; Wed, 21 Jan 2026 08:02:48 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1769011367; cv=pass;
        d=google.com; s=arc-20240605;
        b=GYGBDGiTfEUHfcrEkgDG/ZYJXF11Hmob5P58hxTx4uF2yaaKfBy2H1JTa4Fa7VHnEP
         5fi2akh/DZfcNjJAKbwraOSgk521UnyVUZ2c3YLCBica5AF8XdAgj80Ha7KeoRUyKaTa
         /P3VYrShoiWFSPj5iISlGFvk8S4eLcifQCHKosLP/x67wgw3osndbJguL3SOnDNzGv5/
         YdGGIM/MuTdpeJUcm6u48Pg4ePC+70CaPpJwI11xxwj9MEHDS3850DCfL0tuM2lFhtFi
         hkGcWqkx6+NlJqCXzGn3sKNI+zpKFTk26tbdv/8VCRUgqGBo7so0M6UfRmz9JIpUsKD4
         BdxQ==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=hidLeRAWL7AP8x81lcM9voR9YrI60CHx2tNgi6RD8BE=;
        fh=H7wH6XN2jmuOUZ/A7FzbXDqFtv6QRjCtek+mDigzPi8=;
        b=VNuXNcYLgH3nXKmE4U+o9uGpgYGPYN/EP/Z1roFcoCuAdRHxv+3pcfpV6yQyUqJ5Ge
         6ZoYxXpfFEMM8B156trZK5fTzueDB1b79i66XTJdsgnJW7N41l5jY8RJ3jqw7kZ8a+K2
         i9ZMqWdn8JFg5+xzRn7N97NWRyDEERhBGcRLTBxMmzanEOulI0b0S3BTM/5ITkiXefHC
         /Sd2Z693jjMdJu9ENmB+CP6hqcRApKzQvB25i2x1ddBxf4qUXTydpTewDoF+nICN0RxJ
         fHTGmC0EKGDtPeciiQEkqLW2MrtBmzh81E6IzoelNKSa2h/xpc2O4/M2C5yKseddzJZE
         sWog==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=ZGop6kh0;
       arc=pass (i=1);
       spf=pass (google.com: domain of ryabinin.a.a@gmail.com designates 2607:f8b0:4864:20::b12a as permitted sender) smtp.mailfrom=ryabinin.a.a@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1769011367; x=1769616167; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=hidLeRAWL7AP8x81lcM9voR9YrI60CHx2tNgi6RD8BE=;
        b=WGLxqaTeIVejD9USl03DXu4T0CUpG7M12Q2pN6RbvKdEX9BmWPE2UPRYU8IZ43KZoY
         Wj3j0w6asvjkbQlTCbgDEEGrDVSOz29HwqhOuYzk23yecotFjTqpqxwoiCTZDqGvCKzA
         OxkQzXtId4vT6LN7gSzulgGV19RtAolTRc+DMjNGqQ3bu76BLeBJv3CwNuaiXJFgPPpS
         NUx4sQ5TUUrR1j+pO6ebjE443C1vEtkz6SupcwAjyv9+nBe7cXq/N+1FedllV9JKWXGq
         VS9VCAyK6733FAuw5W0+wt+hbqKp5WE3DmL0/E6ohI6ky1aSBPTS4cdGgiGNo7i+Rai/
         shNw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1769011367; x=1769616167; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=hidLeRAWL7AP8x81lcM9voR9YrI60CHx2tNgi6RD8BE=;
        b=R/nzUtcXw5CxMdhRH2Q9zOYyG8cBzH4YK60gYHqGTch+s1DWBQuLQwgMUPElv/6+Q+
         PBGbQ1FPtYs+4hulXRgy+fxQuZUiwbiRKiOChCSIYYsJtIYbvUY4ogNJtFclhLxxihOF
         EzJc+v6ks5hegWc/cVAGfWEcBHGAw5eJsBhZ5mGwjN9YB1Xk10hH/4trV9PGCGLn0+hT
         uflVfdRXEBJZsL91OoXNvRVnnLkNbI/VfkL8tqkMXOOOr+ee+/5UDN4aeKUZ/yKm8pkb
         6TpQ6lekNY74SEu/xhHA675QqWKUvqQfPukyy0TzwSz3l8GR9Ck8AiNMjQPLGUJ0iuB6
         VuzA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1769011367; x=1769616167;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-gm-gg:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=hidLeRAWL7AP8x81lcM9voR9YrI60CHx2tNgi6RD8BE=;
        b=Cy8qbe+NOhvB9RSoxyo9/UZkHUeibghmm/FPXUpKqfRNVmunRZ/iUcEnEqgdeYy8Bo
         /jb0WNM94AsybmvREJeKx3bknzoAT8rpIhGUy4uZvqlv9Tsm++GJAEE8yoHG19uUp2IZ
         swSWWphTs7Cw1C06pKwpn9eO+uOonlOKIggPdH/OajclRBJv05hmYAagnJviHVH3Mfno
         V9Di8QmGUypl9IZlxc6GKQAEu3ibG2tsYfRWvD/EaoKiDdXslsFO3marFf7nOY33grzA
         Dy53tzcPVFfqxI+rzw2/+uvFa6L0KbFhnbS0S11MZdWUDYxRjHf4UHOJnjeiGZuE4V2t
         SqvQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=3; AJvYcCXMGMF0MAvuoWju73qgm2t6YifkJm95P5IlqFspVLmqmNGn57rBGMpbhctkxSR+qO3Q5mcDcg==@lfdr.de
X-Gm-Message-State: AOJu0YwKanRGq2gXi9uNuLV75ZuiOyMIRN6notOC/jwqLFRmIYra91O1
	FF2WZSkHWoKWGBKl/111KX+tKBUV+dECNg8JwDp4lOC5weQ1HxKKwNGn
X-Received: by 2002:a17:90b:17c1:b0:34a:adf1:677d with SMTP id 98e67ed59e1d1-352c3e7f2c3mr4616373a91.9.1769011366338;
        Wed, 21 Jan 2026 08:02:46 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+Elp+BqUeC+t3lbIrwz1gQR75yO8huPWNYZ+xOjN7Wv8w=="
Received: by 2002:a17:90a:a88:b0:349:967e:1491 with SMTP id
 98e67ed59e1d1-352686e2db0ls6000131a91.1.-pod-prod-09-us; Wed, 21 Jan 2026
 08:02:44 -0800 (PST)
X-Forwarded-Encrypted: i=3; AJvYcCXooFvMOxnr+z3iVR5qfTH4eIxrxKrHtD9QX2A7cxgKRgVWMZv6J5YuNQ31jrV8TXkV+fp5SmSPmb8=@googlegroups.com
X-Received: by 2002:a17:90a:d44d:b0:343:edb0:1012 with SMTP id 98e67ed59e1d1-352c4047c36mr4941878a91.21.1769011364684;
        Wed, 21 Jan 2026 08:02:44 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1769011364; cv=pass;
        d=google.com; s=arc-20240605;
        b=O/VOfFZQIVwljh9WVjUNV0ynuKCN0ZSS05lB5VRw8ynJVQAVC9zrYZ0SP8ZVe0DGc9
         8HiWflsOAashYaWzpdsY8NFf28fcV02shMrkZrNhuMbdAVPfx4RCf1GlgbAw2Ww5cU1X
         7baNdYZAZ3bx44ClSaeF38OtmV88B9TwHkk4of1WBNG1S5ykFVCJ2dqMSxdQDjZ7l9MF
         EltrazTjgB0dis9NxuASpldwyS3KwMwcioiIwyULbfiJ8EjaK16h78FdG+E4eEnEBzzR
         qwnQERXXKVp3iCYcigzLexDDfkBdvSHmukcmLIOPXCRzATt4OW+zz8GV7FWuxAS2BP3V
         5jOQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=DjAz9KoCtw5JjXr43UPq95MQTMGTgk1KGWTvjY/q3LA=;
        fh=W8nFYZpfG7a2F73YL6LjaaXqr/iPJNP6GxEKKHwneO4=;
        b=K0+p+rV7jKlEk65MlPoVEh1i5nn7ulEdnWtDczGTwrS2nF/VKoX6YHaVAcbkssy37+
         cUYtWCdQ54fqZM6elfDpjOH0zq0hrFVAqngAnS4/9RD8U7MKP7DSmKA7++r81mA76l8+
         LqaCs/n9UBLWrG26kRzLda65nFtYFq7MqP++LgxQ9Z7ED8uGWzf32x1fzTLC/aeYeQNI
         rtkTYCM6gbaaIfOrVD18Gdg1cphDLS60Sov3yV6TgzvfrXm46gIuABlfRtKp3NM1b30o
         mocXygT++c6Z3te3+AmMywdIHbCjsAtMxN9XYwWp0ZX9wVgMBEct6/j1yLkfF/zX+PT4
         fw2Q==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=ZGop6kh0;
       arc=pass (i=1);
       spf=pass (google.com: domain of ryabinin.a.a@gmail.com designates 2607:f8b0:4864:20::b12a as permitted sender) smtp.mailfrom=ryabinin.a.a@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-yx1-xb12a.google.com (mail-yx1-xb12a.google.com. [2607:f8b0:4864:20::b12a])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-352faecab53si28814a91.0.2026.01.21.08.02.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 21 Jan 2026 08:02:44 -0800 (PST)
Received-SPF: pass (google.com: domain of ryabinin.a.a@gmail.com designates 2607:f8b0:4864:20::b12a as permitted sender) client-ip=2607:f8b0:4864:20::b12a;
Received: by mail-yx1-xb12a.google.com with SMTP id 956f58d0204a3-646a1384584so3349d50.1
        for <kasan-dev@googlegroups.com>; Wed, 21 Jan 2026 08:02:44 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1769011364; cv=none;
        d=google.com; s=arc-20240605;
        b=VeK/9O9IPcWAgsaVIKKPAnIerL5Ibx24qdY/mevjxJOf4txfA9WZpkCMT31FVtT09l
         I4mlWBi5B7bBkNay9HCMMcDWvoXFXWTp9gOuanPM2Vr9GxED3xccZAPXRgNdadTpRMOH
         +TnN6oB82gQP+u285hhblhBkJYtvBzLg3HlD1GdBjnY9RE9NznDRgjCpBySLV7LwiPZz
         8YTJBogtH0AgzfmDC2cgaG9ByudG9ULU+1Xu6bbpwOUfQ5Ilg5k+TL6LWWdUwCs/iQyZ
         ljsHXn2s0DPgjYLIfkFo1Pet+eeLamdBDV6TqLFoIqNSrDT1pAPd5cWPQ01O+NuZUuXt
         zyhA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=DjAz9KoCtw5JjXr43UPq95MQTMGTgk1KGWTvjY/q3LA=;
        fh=W8nFYZpfG7a2F73YL6LjaaXqr/iPJNP6GxEKKHwneO4=;
        b=WGw+l62Xm+nEA9EhZzEce3sA0tdIPUiB/FtwzMmb69DYe0y6oNJNe33rxS2bM8p9Kd
         QDNspLQkoDxuF8gcjqiKj1q7wX325vyr6v4Zy4u80YBEQ0wZuEP1ztLV5N8CNdT8XbWN
         EruhPNDVFPTTBg2PH8ybKTQB7FkAdINEZYVnbYppOcyyFfJZPDDSR2xvivXWnqXizgx+
         DmkeKuYjNh2otEzhYR7Hm+wmeWdFCHzAtOzSfnUCoOwtXJ/P53yCEjq/1nOFbS++B7Pc
         E4AedS5uMqS5NinXBi3zQ9Z1p5BmABDwgCPoIQBCMBdMff/ycgj+FV9iKn2zfB2bciqB
         A5eg==;
        dara=google.com
ARC-Authentication-Results: i=1; mx.google.com; arc=none
X-Forwarded-Encrypted: i=1; AJvYcCXxGS7Vi6KuyPCKB52WT6k5PMhL6m9iQl8OMi3EXCV3pkZixICoF/24Tndostt3hdMduDXyaAhoAgQ=@googlegroups.com
X-Gm-Gg: AZuq6aKHf87Ecq3rq2RlSy6s3cllVh49ZVlqzeRe+RL5z5hxYjfMFbDa3jSn/qKoQCr
	5Mgk5gtg3CmQGoPfuI0YL9Wy/iAWdv/gWhie1qyyBeoylec0ZzTFyOp550FiB/FFkSib2LWsWY3
	FqTX4NczQj4UAWmYBHBWeoCOQJEG5LP4YiBNQFtTQP9HqcjDC0vbcnEeUXaLC+Jrq3jkC4rr/UW
	74Lzvdl7XU148Ia/O7z/QRNkGrUTbbnNJXUyvXo7DkV6I8I7VPN1ukUGkooktkYgr6PT/DABGm2
	8cz6fLuXpwZTYNmewr5Dl5kI51zY
X-Received: by 2002:a05:690e:bc9:b0:649:45e9:5545 with SMTP id
 956f58d0204a3-64945e956cdmr2171879d50.2.1769011363372; Wed, 21 Jan 2026
 08:02:43 -0800 (PST)
MIME-Version: 1.0
References: <CA+fCnZcFcpbME+a34L49pk2Z-WLbT_L25bSzZFixUiNFevJXzA@mail.gmail.com>
 <20260119144509.32767-1-ryabinin.a.a@gmail.com> <CA+fCnZddq=S0H5qXZ_CLSB3Y1cNw7nY4AYTBsGRR5DmY5+=paA@mail.gmail.com>
In-Reply-To: <CA+fCnZddq=S0H5qXZ_CLSB3Y1cNw7nY4AYTBsGRR5DmY5+=paA@mail.gmail.com>
From: Andrey Ryabinin <ryabinin.a.a@gmail.com>
Date: Wed, 21 Jan 2026 17:01:38 +0100
X-Gm-Features: AZwV_QgZKfvJ8durzk3-qWhK-3WciMuskgbHg7adkHLjd0cRD9-mKJKeXArIs6Q
Message-ID: <CAPAsAGxiPhL7evokSWWXveVdZjU+8kUSjCA1PnEA9WGP2hiFxg@mail.gmail.com>
Subject: Re: [PATCH] mm-kasan-fix-kasan-poisoning-in-vrealloc-fix
To: Andrey Konovalov <andreyknvl@gmail.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, =?UTF-8?Q?Maciej_=C5=BBenczykowski?= <maze@google.com>, 
	Maciej Wieczor-Retman <m.wieczorretman@pm.me>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	kasan-dev@googlegroups.com, Uladzislau Rezki <urezki@gmail.com>, linux-kernel@vger.kernel.org, 
	linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: Ryabinin.A.A@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=ZGop6kh0;       arc=pass
 (i=1);       spf=pass (google.com: domain of ryabinin.a.a@gmail.com
 designates 2607:f8b0:4864:20::b12a as permitted sender) smtp.mailfrom=ryabinin.a.a@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
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
X-Spamd-Result: default: False [-2.21 / 15.00];
	ARC_ALLOW(-1.00)[google.com:s=arc-20240605:i=3];
	DMARC_POLICY_ALLOW(-0.50)[gmail.com,none];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601,gmail.com:s=20230601];
	R_SPF_ALLOW(-0.20)[+ip6:2607:f8b0:4000::/36];
	MAILLIST(-0.20)[googlegroups];
	MIME_GOOD(-0.10)[text/plain];
	HAS_LIST_UNSUB(-0.01)[];
	FROM_HAS_DN(0.00)[];
	RCVD_TLS_LAST(0.00)[];
	TAGGED_FROM(0.00)[bncBCSL7B6LWYHBBJPRYPFQMGQEGW2XSEY];
	RCVD_COUNT_THREE(0.00)[4];
	FREEMAIL_TO(0.00)[gmail.com];
	MIME_TRACE(0.00)[0:+];
	FORGED_SENDER_MAILLIST(0.00)[];
	TO_DN_SOME(0.00)[];
	FREEMAIL_CC(0.00)[linux-foundation.org,google.com,pm.me,arm.com,googlegroups.com,gmail.com,vger.kernel.org,kvack.org];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	FREEMAIL_FROM(0.00)[gmail.com];
	MID_RHS_MATCH_FROMTLD(0.00)[];
	FROM_NEQ_ENVFROM(0.00)[ryabininaa@gmail.com,kasan-dev@googlegroups.com];
	DKIM_TRACE(0.00)[googlegroups.com:+,gmail.com:+];
	RCPT_COUNT_SEVEN(0.00)[11];
	ASN(0.00)[asn:15169, ipnet:2607:f8b0::/32, country:US];
	TAGGED_RCPT(0.00)[kasan-dev];
	MISSING_XM_UA(0.00)[];
	DBL_BLOCKED_OPENRESOLVER(0.00)[mail.gmail.com:mid,googlegroups.com:email,googlegroups.com:dkim]
X-Rspamd-Queue-Id: 987D4599EA
X-Rspamd-Action: no action
X-Rspamd-Server: lfdr

On Tue, Jan 20, 2026 at 6:46=E2=80=AFPM Andrey Konovalov <andreyknvl@gmail.=
com> wrote:
>
> On Mon, Jan 19, 2026 at 3:46=E2=80=AFPM Andrey Ryabinin <ryabinin.a.a@gma=
il.com> wrote:
> >
> > Move kasan_enabled() check to header function to avoid function call
> > if kasan disabled via boot cmdline.
> >
> > Move __kasan_vrealloc() to common.c to fix CONFIG_KASAN_HW_TAGS=3Dy
> >
> > Signed-off-by: Andrey Ryabinin <ryabinin.a.a@gmail.com>
> > ---
> >  include/linux/kasan.h | 10 +++++++++-
> >  mm/kasan/common.c     | 21 +++++++++++++++++++++
> >  mm/kasan/shadow.c     | 24 ------------------------
> >  3 files changed, 30 insertions(+), 25 deletions(-)
> >
> > diff --git a/include/linux/kasan.h b/include/linux/kasan.h
> > index ff27712dd3c8..338a1921a50a 100644
> > --- a/include/linux/kasan.h
> > +++ b/include/linux/kasan.h
> > @@ -641,9 +641,17 @@ kasan_unpoison_vmap_areas(struct vm_struct **vms, =
int nr_vms,
> >                 __kasan_unpoison_vmap_areas(vms, nr_vms, flags);
> >  }
> >
> > -void kasan_vrealloc(const void *start, unsigned long old_size,
> > +void __kasan_vrealloc(const void *start, unsigned long old_size,
> >                 unsigned long new_size);
> >
> > +static __always_inline void kasan_vrealloc(const void *start,
> > +                                       unsigned long old_size,
> > +                                       unsigned long new_size)
> > +{
> > +       if (kasan_enabled())
> > +               __kasan_vrealloc(start, old_size, new_size);
> > +}
> > +
> >  #else /* CONFIG_KASAN_VMALLOC */
> >
> >  static inline void kasan_populate_early_vm_area_shadow(void *start,
> > diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> > index ed489a14dddf..b7d05c2a6d93 100644
> > --- a/mm/kasan/common.c
> > +++ b/mm/kasan/common.c
> > @@ -606,4 +606,25 @@ void __kasan_unpoison_vmap_areas(struct vm_struct =
**vms, int nr_vms,
> >                         __kasan_unpoison_vmalloc(addr, size, flags | KA=
SAN_VMALLOC_KEEP_TAG);
> >         }
> >  }
> > +
> > +void __kasan_vrealloc(const void *addr, unsigned long old_size,
> > +               unsigned long new_size)
> > +{
> > +       if (new_size < old_size) {
> > +               kasan_poison_last_granule(addr, new_size);
>
> I wonder if doing this without a is_vmalloc_or_module_addr() check
> could cause issues. I remember that removing
> is_vmalloc_or_module_addr() checks from other vmalloc hooks did cause
> problems, but I don't remember what kind.
>

vrealloc() operates only on vmalloc-backed allocations, so 'addr' is
always expected to be a vmalloc address here. Calling vrealloc() on a
non-vmalloc address would already be a misuse, independent of this change.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
APAsAGxiPhL7evokSWWXveVdZjU%2B8kUSjCA1PnEA9WGP2hiFxg%40mail.gmail.com.
