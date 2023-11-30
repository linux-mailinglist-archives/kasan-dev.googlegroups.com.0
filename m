Return-Path: <kasan-dev+bncBD63B2HX4EPBBF6RUCVQMGQEONROFGA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3c.google.com (mail-oo1-xc3c.google.com [IPv6:2607:f8b0:4864:20::c3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 07AC27FE909
	for <lists+kasan-dev@lfdr.de>; Thu, 30 Nov 2023 07:15:53 +0100 (CET)
Received: by mail-oo1-xc3c.google.com with SMTP id 006d021491bc7-58a83a73ce9sf784639eaf.2
        for <lists+kasan-dev@lfdr.de>; Wed, 29 Nov 2023 22:15:52 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1701324951; cv=pass;
        d=google.com; s=arc-20160816;
        b=MywGD0RE/wtCZaOtOA3IvVF4FHKRpnqpmKE+gKQSO8h3e9zdIdMQpqmh+lgLJjIhau
         USRhbX6t7EgT3oVrGGt7eCR7DTRLzC6XrzsUK9vjD+hEPu0XCGNU2YMItDRx3Cl8SgqD
         rBxRTG03OyI+KbVyKR88xuyLHg9/bcGqgBOZPpv/UQgGZ0mMq7H89hwJK1I9NBYOoX8U
         xlu0cV27bFtYF6Ho0ttHjMrY+TZF8odPCyENpgspR1MrXVOz0U1vB6SzHbImyk3zSgL8
         TKh8/NazKNWoU3OpVqAP0oSm+LvLSVxl3ZlXdDYiEZBU2Ri1r1Bny1eXpv/Ea/Ky5Ef/
         zmoQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :content-disposition:mime-version:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=Tujs27WRDmaKAIlz4NpbS7GMCz/scAZzpmJTEcERi/Y=;
        fh=BCL3G4/EB/6E43qIQvqiTmSskf1MQ2+iKF4M83YUI6k=;
        b=iqUMc4cDlJOaXWToaG0S4wRPCINPWkC5ypuZu4WF5roRSQBq936R1k/ESzpc9wxKPk
         UkVeGecnwUwHBl/oza1ThwMaE56djlhDYbc7Th8jTmAd++YGjcgkPk/ppcJgRgm42KSh
         W38FLix1o6zJDVpCNXMh5+o8dO4LEcSenZIGjN2bWy6yyJeCYb2qe86Y8VdHP0NqmfeP
         UNL09rhcSldElZfb7/M492HudXKbA2Nzgvq5EuODjybQjCDi+Xxcxc8TASoY/ffjBbYW
         VuN95SG/1lbN5UjhX60cKsum4q2wFY+f/c7JepKgM00Ytf3oJ5dMeFbai7CmTIugVFWl
         VeFw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@purestorage.com header.s=google2022 header.b=KRTCGuL7;
       spf=pass (google.com: domain of joern@purestorage.com designates 2001:4860:4864:20::32 as permitted sender) smtp.mailfrom=joern@purestorage.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=purestorage.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1701324951; x=1701929751; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:content-disposition:mime-version
         :message-id:subject:cc:to:from:date:from:to:cc:subject:date
         :message-id:reply-to;
        bh=Tujs27WRDmaKAIlz4NpbS7GMCz/scAZzpmJTEcERi/Y=;
        b=kPM5arW3GJNDRGif43vnC2GSdRlg9n917IRnw0e/7pWLTA+xRSvdEET5edJqRZz3+B
         AKUTdY/oRxpuqdm7w+JxtihQsVzI/g1PIQjFfpyQYdXWm7lPO6wnMhO7m9woA6MPrMg4
         nzRFhP4CqGzNKg5BKjlBssa60huCPA/UG9rIOpkU3xybcDgZL+Yi2ieWftDG7FgdxPx7
         3egqXtZgCzycVlPVzMD3Z6zFpr29Hzy/ySq7+6JqtrInNEjGJkRMclwT9bkptlPLNVgc
         /WNR/wtC/gk/uPzweL6qFzDY3qFxof/9CGPk82Zf622xzHRv+BSJFzbygnzH2EBl4hb7
         Uc1w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1701324951; x=1701929751;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:content-disposition:mime-version
         :message-id:subject:cc:to:from:date:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=Tujs27WRDmaKAIlz4NpbS7GMCz/scAZzpmJTEcERi/Y=;
        b=TUDIbLYHZwpa4Liys/fKijT1YObKW2U5F6hj93xYAgD8R3m/lsDowKMr3UVNsK+4Gt
         HUmDdo09suFp4eqonX5KsC7PxkCQorkopWPQ6C3dBh47gE3hM2lNvKg1Bd7vgWzoX9dZ
         s/qUS5/EcOqaa8icerameFjmhLKieLsiwJr08CxxDujIiYbzqwkuxP66sbT2Q4WYV3kz
         KMKAsu0RqPhjPTE8EEFKcwcEonqm/NPt8DSJzj+8yeivaUFtDlBhmMAjCp/rmlQ67s5z
         S385LgTbq3PTkLHiAypPzQQRTtoEttc8ooQfwsK0Bged9NecdFxhQAiXicLUzRI5BTfZ
         4vrQ==
X-Gm-Message-State: AOJu0YyueXjDtGbv1WNk9JATIicfj2N9N6WsKMKbhPdq1/bFXJptlBLc
	lN7VRYoA4rTS6ZYcb/tjwvc=
X-Google-Smtp-Source: AGHT+IFpgsDM6c9eg3/2GftMmlAo1t/HcmDV5A295dX/un4QkXLTuBcdUmrvoIXQER//Og4Y1qSXVg==
X-Received: by 2002:a05:6820:1c8c:b0:58d:eb9c:de54 with SMTP id ct12-20020a0568201c8c00b0058deb9cde54mr616804oob.0.1701324951681;
        Wed, 29 Nov 2023 22:15:51 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6820:617:b0:589:f297:6025 with SMTP id
 e23-20020a056820061700b00589f2976025ls84100oow.0.-pod-prod-02-us; Wed, 29 Nov
 2023 22:15:51 -0800 (PST)
X-Received: by 2002:a05:6808:30a4:b0:3b8:950b:6e8c with SMTP id bl36-20020a05680830a400b003b8950b6e8cmr264509oib.4.1701324951368;
        Wed, 29 Nov 2023 22:15:51 -0800 (PST)
Received: by 2002:a05:6808:211a:b0:3b2:e349:d5c2 with SMTP id 5614622812f47-3b83d618754msb6e;
        Wed, 29 Nov 2023 22:07:22 -0800 (PST)
X-Received: by 2002:aca:2117:0:b0:3ae:156f:d312 with SMTP id 23-20020aca2117000000b003ae156fd312mr25177659oiz.34.1701324442102;
        Wed, 29 Nov 2023 22:07:22 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1701324442; cv=none;
        d=google.com; s=arc-20160816;
        b=QW6W8oJeKu5TPAOkxj7vL3q73xGLla3hH8TMasczlLLRy4BcWf7Bk4e/UCKSK76dlp
         ZUxvXQe8c5LjLF2qK6G41KnuU9xtq4NXLD2s/Kr0U2tNin2Rjs7qkOxmUHoWefx9j4Ta
         Uxtr5ENvtJyyeA53wjSPyuuvoPk3fYtVgBI6ALMb22gc8mnkyuZmp/Bi3T7XpzAL+/10
         H4Bth0hfXT+yXbOKg8CF12oHQCQog7QfuJ1OayjGnc5RlFZjuUefXJPeGcdkgZz6YNrL
         avqKKVk2Iq1BEbE7HEWUxGjWHMktZa/fAgmTdjkjr1Bn5eqj5Oi0FUIs9J9Dg+hDYq/D
         8nbw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-disposition:mime-version
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=72cVFLQjUXtMhSq4G7MPNyhB5k0k3Wvi9MngA0PY6L0=;
        fh=BCL3G4/EB/6E43qIQvqiTmSskf1MQ2+iKF4M83YUI6k=;
        b=kLxBIu+8whQSu1Eypvc0c2t1UI81p62tBKUr7qHF4pr5PJx18Fl+NVlU3V5t3/OEfr
         yD5svJRby84BfvFMnjQDDZxtW/3Crz6/7Bb9e9GtxPIWpmIgD5Z0o/YMxPbncTnh7dZn
         jSXB/rHopi6JByIq6qemUX4j5aVNswNa3nYoJWA2M0JoUkD7xqQL1OTkwouU8aCknPe5
         70UP24yL+xqiPVCKacBklxO1az6macGmMTLOavVNSyVOFs+SmarP6tIoH4W9w+B4bVab
         TB+2Ho6TYGMO1BlxqHHeS9u8uIssx0hdP+gwaU6LYks8in/FYITQ97fa2cVlmCD5VZ2K
         So1g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@purestorage.com header.s=google2022 header.b=KRTCGuL7;
       spf=pass (google.com: domain of joern@purestorage.com designates 2001:4860:4864:20::32 as permitted sender) smtp.mailfrom=joern@purestorage.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=purestorage.com
Received: from mail-oa1-x32.google.com (mail-oa1-x32.google.com. [2001:4860:4864:20::32])
        by gmr-mx.google.com with ESMTPS id eu10-20020a056808288a00b003b8979bb6c1si71763oib.4.2023.11.29.22.07.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 29 Nov 2023 22:07:22 -0800 (PST)
Received-SPF: pass (google.com: domain of joern@purestorage.com designates 2001:4860:4864:20::32 as permitted sender) client-ip=2001:4860:4864:20::32;
Received: by mail-oa1-x32.google.com with SMTP id 586e51a60fabf-1f9f9e62248so77936fac.0
        for <kasan-dev@googlegroups.com>; Wed, 29 Nov 2023 22:07:22 -0800 (PST)
X-Received: by 2002:a05:6871:4184:b0:1f5:d3f5:2b92 with SMTP id lc4-20020a056871418400b001f5d3f52b92mr26484367oab.2.1701324441721;
        Wed, 29 Nov 2023 22:07:21 -0800 (PST)
Received: from cork (c-73-158-249-15.hsd1.ca.comcast.net. [73.158.249.15])
        by smtp.gmail.com with ESMTPSA id s188-20020a625ec5000000b006c0685422e0sm395662pfb.214.2023.11.29.22.07.20
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 29 Nov 2023 22:07:21 -0800 (PST)
Date: Wed, 29 Nov 2023 22:07:19 -0800
From: =?UTF-8?B?J0rDtnJuIEVuZ2VsJyB2aWEga2FzYW4tZGV2?= <kasan-dev@googlegroups.com>
To: Marco Elver <elver@google.com>
Cc: dvyukov@google.com, kasan-dev@googlegroups.com
Subject: dynamic kfence scaling
Message-ID: <ZWgml3PCpk1kWcEg@cork>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: joern@purestorage.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@purestorage.com header.s=google2022 header.b=KRTCGuL7;
       spf=pass (google.com: domain of joern@purestorage.com designates
 2001:4860:4864:20::32 as permitted sender) smtp.mailfrom=joern@purestorage.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=purestorage.com
X-Original-From: =?iso-8859-1?Q?J=F6rn?= Engel <joern@purestorage.com>
Reply-To: =?iso-8859-1?Q?J=F6rn?= Engel <joern@purestorage.com>
Precedence: list
Mailing-list: list kasan-dev@googlegroups.com; contact kasan-dev+owners@googlegroups.com
List-ID: <kasan-dev.googlegroups.com>
X-Google-Group-Id: 358814495539
List-Post: <https://groups.google.com/group/kasan-dev/post>, <mailto:kasan-dev@googlegroups.com>
List-Help: <https://groups.google.com/support/>, <mailto:kasan-dev+help@googlegroups.com>
List-Archive: <https://groups.google.com/group/kasan-dev
List-Subscribe: <https://groups.google.com/group/kasan-dev/subscribe>, <mailto:kasan-dev+subscribe@googlegroups.com>
List-Unsubscribe: <mailto:googlegroups-manage+358814495539+unsubscribe@googlegroups.com>,
 <https://groups.google.com/group/kasan-dev/subscribe>

Hello Marco!

One thing that came up for us is that we want a more aggressive kfence
during in-house testing.  But we don't want a debug build, those tend to
cause more trouble than they are worth.  So the goal is to dynamically
scale kfence via sysfs-knobs.

That works for the instrumentation frequency.  But it doesn't work for
the amount of memory reserved for kfence.  We should be able to scale
that dynamically as well.

I don't think we have time to implement this anytime soon.  You are
probably in no better position, but at least you should be aware that
this would be useful.

If I had a magical wand and six months of spare time, I would reserve a
fairly large portion of virtual memory and add/remove physical pages to
that range as desired.  That approach seems the cleanest and can easily
scale from tiny to huge amounts of memory, on 64bit systems at least.
Drawback is that we likely need some new infrastructure, hence the six
months.

J=C3=B6rn

--
Bugs are like mushrooms - found one, look around for more...
-- Al Viro

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/ZWgml3PCpk1kWcEg%40cork.
