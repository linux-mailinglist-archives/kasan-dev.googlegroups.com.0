Return-Path: <kasan-dev+bncBCSL7B6LWYHBB44L6G7AMGQENK4JW6Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23c.google.com (mail-lj1-x23c.google.com [IPv6:2a00:1450:4864:20::23c])
	by mail.lfdr.de (Postfix) with ESMTPS id AC1B7A6AB4D
	for <lists+kasan-dev@lfdr.de>; Thu, 20 Mar 2025 17:44:37 +0100 (CET)
Received: by mail-lj1-x23c.google.com with SMTP id 38308e7fff4ca-30c4cbc324bsf6019281fa.1
        for <lists+kasan-dev@lfdr.de>; Thu, 20 Mar 2025 09:44:37 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1742489077; cv=pass;
        d=google.com; s=arc-20240605;
        b=ZR6GgU41rT4F0bv/PrDfp201nHC5rGaeMuTRvPfzAbtMdUZo1feHlI/EQUBzAalSRg
         sx5o1HWqsvKK2+efb6+nW5PlG5I4TApCq97tHefA4DkEJ1cz610/krilDbXgIezzSeCG
         OKuh7REan51ttlEuqidNckPeCxn75XOMxN3nWMfd1ne4G28nHEHNUeeKUi7FO5y4shma
         fFPbb41QsdUhNSO1yYpg7MtdpID+OrAUqpT81mlz1y4NhClPQ3LPNGtVhY0gHZHciaPi
         +uU2fVljQk2ScMFeIkVQ89pHEIS1S043wHRDWWCrL3WfKgbvh5w1shlIgGhkEqY8dpm6
         S6BQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=aoKziBtJqVJgivpAZe8d8O1gmsMYbYUkGPtCoLg2rig=;
        fh=ZSXNZl4ucwSHB5sWNwxqg7GeUw7/vUYC6fCkXl0mI9Q=;
        b=O06pZlUOd1WOIi2XYnECuyHMuUXRcFfams+RuaqTegofpedPmEdAgFyKVkn6DYMpI8
         FZMvZPyWwTsniqILSmmRq+kxNL9C2kh/atT5YwNE76gEcuyReU1e38ebEVaJmztrEgZx
         xCmy8/hwBiU2DYlCPwEP7bU7lJv70B7XQWoICeLol7v+D/2O9xUPb8vM3fk8GAkQTD+e
         wTIQISsxZEQ2DdfL7gmb8NOLAcZ1MDNKI+Zc4zV4qJk2YR/OkOPl5O//OekABu9eITjK
         exXFVU4BNtoDebnNUMqakeXp6XRo/mFrfEE32E5qmFNj6yIupCg1U7To3gyMtyBXAL2K
         +LBQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=UPvck2p5;
       spf=pass (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::42e as permitted sender) smtp.mailfrom=ryabinin.a.a@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1742489077; x=1743093877; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=aoKziBtJqVJgivpAZe8d8O1gmsMYbYUkGPtCoLg2rig=;
        b=PodPttuBfxz5D7Hh+XfmKWOL542K8Rapb+50Swzf1r06k5G/FAh/8RLcwSuxuV3u3V
         VgZ3tthnSURcxQ/Z4IBAJRzKQWRPnpGpXZJB+zYrutaCn9EepAxBJhrRL9YS9rzen7bx
         Z7rrIWue3zjVAJ0FYJVibKzrK61aQm4LJqTQjeCvO+hBcftdgAgoqTtBrTHq02yXunR6
         6LKiGKEbZDv+qf+VpmrmTYWvIDwT0/3sKg97zwpgmlZ2mJNFbNTHyitiSqmxzB5ogG8O
         opZJjK7UDWh/Z2dRCUX3/fluuuIXrS39yzINgA2XGHOfbZVP+nNyCLRkEx9a3uh05E5h
         w5XQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1742489077; x=1743093877; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=aoKziBtJqVJgivpAZe8d8O1gmsMYbYUkGPtCoLg2rig=;
        b=eXjnde0OUbS+fgfxE52XajzEbvdcjLTQE1eEijstAaIPQZcmqfVGbDbAh9rXdH37WM
         SJ6D7RkepIEWwlg6RbzF1xDh+L4kbmCgXCI3OVk+i0o6264gXF11QnAeu3FSAr2BIioG
         vXvdqaF+c+nqWbnb0boOfXB7wwN0pL7/UaTQXtlp1m8CDc9kLR+JTYM6Ultp0oVcHcs4
         NrqTG6I9FQ+ff0n2TmcatavQBfck9g0okEPV9b86+np0mSS9caQoWglfkDxExEYzokwl
         NfFMANsmPtJJga53F3iWDfOgftQUGcTuLpoP0O45Mz/xBa/03Wz5EepCUn/jGZIWSxwi
         a85w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1742489077; x=1743093877;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=aoKziBtJqVJgivpAZe8d8O1gmsMYbYUkGPtCoLg2rig=;
        b=N3ELiwyoPzO2HNHJ++51/kQSSIT2Z79vaNcoORo2MmQVy9fFWuTdenZ8j7Qgx04rVg
         ZYTcDK6Wa+kj9BwnKFicCSIRDAlKgsIKciqF5lZtPPrTq72y68PIamXDpBujYtBoA3Oc
         EO2jcpAh6sSInUOUT/5BC55tTdcyNEx4n0Y8Wh4lV3L8zuzId0UEI1CptO3PtBUjkOG6
         yDJBXLBO4FFebyGJts6bN3rhupmpIsRvy9DBln1kkMdV8ezPgkuC8MCGOQSdyZXCRT+4
         JfOnOaV+waXj7Qh8i3Tf4xYuHOluvaVKYLoBz/ROT8D1ZJtcFeJKK6dqAN1Pyv9H+Bv1
         RMyA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWepJeVKLZxYXjo8tI8lHLEbKABmHJtU2zK1rKxKD1lyOTyy9s7LqNf+m5i1c5r1g6ihLr78w==@lfdr.de
X-Gm-Message-State: AOJu0YxTYjPTxW/3XQQdWewyaC/72JE+9YWEsZBd8hJpQfjWjyLgvGim
	C0b+D5XiQe2VlWxaekdcS5+wJtVRaXD6VAjN+GnEVvlwKJ1paPLP
X-Google-Smtp-Source: AGHT+IHvfUW7CoMSUcf3p4KQW5ak1KqlEp76E9sMRv5UBlpjmQIyJ1ZqigsS+fZtK3vEX/rnk55GwQ==
X-Received: by 2002:a2e:be9e:0:b0:30c:7fe:9c95 with SMTP id 38308e7fff4ca-30d7291ea1fmr16545101fa.8.1742489076302;
        Thu, 20 Mar 2025 09:44:36 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARLLPAKec9+lQXWzmKJqEu6py3fTIsMYUzb7IlQbm/Zj4hBE8g==
Received: by 2002:a2e:8096:0:b0:30b:f139:c898 with SMTP id 38308e7fff4ca-30d7b928cacls473291fa.1.-pod-prod-09-eu;
 Thu, 20 Mar 2025 09:44:32 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCX8w3pbNPDb6fKdOeHZ0a5JwccyGHjvcU3cihqPkwgMKbm3zFYjH6UhnNvYIUgu8QxMQxPva+W9XEc=@googlegroups.com
X-Received: by 2002:a2e:a542:0:b0:30b:a92e:8b42 with SMTP id 38308e7fff4ca-30d72af54f5mr19257511fa.26.1742489071810;
        Thu, 20 Mar 2025 09:44:31 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1742489071; cv=none;
        d=google.com; s=arc-20240605;
        b=OHjZo95fFgkmCZ1ek60p66mDOTjC5f6zCGA1DV4nIkX94J0A81z+j3Mevd0aL0eHGO
         3SWcy5Aq6pp1nlUCyIq5py+gaNtzK1BxuKhXpjyg7hQMhY0xF2YYVggm2cdcGhYlBoSE
         xcnNFjHbHRjZHzurVU2muPp0Nr4Urev40LvxF9CBZzINDwvxHK1Fr9nmoqL903zadiyH
         EwjGg5+WuZs0TIYU7/gq3dnKCHGyvPGDtnsQZu5tjc0i1nYqDEbHdEYvG2oHlUXgC1dC
         wRqVAu2X9PAmB9scWt4bIipWAtCeX1zPP0B8KfAsoZfFZUe3sXNHxpzSIWvBwoD/6GtO
         sbcg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=Sl+Q3tAbqojV0VFuCPLFXyH+mpVFTX55Wv7F6O0y5c8=;
        fh=pRujYibCYwb8Q8629qp+Q53Voog+kyAYXsvLj12BhBw=;
        b=avTxTR6q4HeiXgfHMOAJ1n9nqlBlxuV8nDeXjnC9Ky6+WSY2/2LvbD/RjOxcL0gkvI
         L9UXitpxutp442WbdQa6LVDcEpSYnn3TLc9WN679wspRDUdtmubg/FUy4o/nlqJvRk+B
         Kf0KOsSc8x1Ky8tYoYd+akT8Vstnv/YHww0oO+dZYJQzq6cWSdw3+Eqpo30C0MhZN3wV
         cq+wUFJex7zWpFVzGv5Rovm+4/PDFmUqmB1KJxXaEpUJxyfQ82b8bEntIv5R2P5hOE26
         m0kRTr8jMrZH7JDZPLCe8L3BjIHanw/69n4zibeKb5nNzI2FUuXtLSVRs8dSJ4YXRg4B
         5TXQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=UPvck2p5;
       spf=pass (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::42e as permitted sender) smtp.mailfrom=ryabinin.a.a@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x42e.google.com (mail-wr1-x42e.google.com. [2a00:1450:4864:20::42e])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-30d7d8575a4si28121fa.6.2025.03.20.09.44.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 20 Mar 2025 09:44:31 -0700 (PDT)
Received-SPF: pass (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::42e as permitted sender) client-ip=2a00:1450:4864:20::42e;
Received: by mail-wr1-x42e.google.com with SMTP id ffacd0b85a97d-3996683dd7bso132783f8f.3
        for <kasan-dev@googlegroups.com>; Thu, 20 Mar 2025 09:44:31 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCX/Q9wdCHhn9e4JK2t+Hl0jHy1Osm4+WO5pfVBFz/HgwXf8NMExqyTNqjjSOKdyOB4ZeBXy8uP5MyA=@googlegroups.com
X-Gm-Gg: ASbGncsIR2frVWwWQ5Wx0rCygpO1MpelDDWzVJen2bY0Uj2CRDsYrHl+VzR4jv0Y9le
	NZydXv8wPKzLOvfCYZ3LmliPk1dKjPsSQWy/7aMEE5wWlhybp8HxTqUWV4QfvIhYoLI7MivScXr
	PfvuCPGp+5B7e7ObP5gk8eKue14B+/8d1BI+XHiYroIB1cdH9DpomPlMGCAHXSSxc3WEs=
X-Received: by 2002:a5d:6da1:0:b0:38d:d371:e03d with SMTP id
 ffacd0b85a97d-3997f8ee224mr80691f8f.3.1742489070959; Thu, 20 Mar 2025
 09:44:30 -0700 (PDT)
MIME-Version: 1.0
References: <20250318015926.1629748-1-harry.yoo@oracle.com>
In-Reply-To: <20250318015926.1629748-1-harry.yoo@oracle.com>
From: Andrey Ryabinin <ryabinin.a.a@gmail.com>
Date: Thu, 20 Mar 2025 17:44:06 +0100
X-Gm-Features: AQ5f1Jo9CZLQDM2kpJQ_9WPJBbin-yAHC_Ppwb9Qyz7cZjnJt1uQNfIhmTJ0Fcw
Message-ID: <CAPAsAGxdD04nOz35TERJi0aPs+9TBEytrqNVq8h4EA819PA9pg@mail.gmail.com>
Subject: Re: [PATCH mm-unstable] mm/kasan: use SLAB_NO_MERGE flag instead of
 an empty constructor
To: Harry Yoo <harry.yoo@oracle.com>
Cc: Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: Ryabinin.A.A@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=UPvck2p5;       spf=pass
 (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::42e
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

On Tue, Mar 18, 2025 at 2:59=E2=80=AFAM Harry Yoo <harry.yoo@oracle.com> wr=
ote:
>
> Use SLAB_NO_MERGE flag to prevent merging instead of providing an
> empty constructor. Using an empty constructor in this manner is an abuse
> of slab interface.
>
> The SLAB_NO_MERGE flag should be used with caution, but in this case,
> it is acceptable as the cache is intended solely for debugging purposes.
>
> No functional changes intended.
>
> Signed-off-by: Harry Yoo <harry.yoo@oracle.com>

Acked-by: Andrey Ryabinin <ryabinin.a.a@gmail.com>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
APAsAGxdD04nOz35TERJi0aPs%2B9TBEytrqNVq8h4EA819PA9pg%40mail.gmail.com.
