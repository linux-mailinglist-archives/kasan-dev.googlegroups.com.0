Return-Path: <kasan-dev+bncBDW2JDUY5AORBD55SKWAMGQEVVRDYKY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103e.google.com (mail-pj1-x103e.google.com [IPv6:2607:f8b0:4864:20::103e])
	by mail.lfdr.de (Postfix) with ESMTPS id 55DF981BF86
	for <lists+kasan-dev@lfdr.de>; Thu, 21 Dec 2023 21:22:41 +0100 (CET)
Received: by mail-pj1-x103e.google.com with SMTP id 98e67ed59e1d1-28bf83bcae2sf604349a91.0
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Dec 2023 12:22:41 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1703190159; cv=pass;
        d=google.com; s=arc-20160816;
        b=knkHMcoZfGYFoL444boNS/17JV7XHM5PzgSpoR3VJlgkv/RVjYQbpp4F2ycc9cmr8B
         X35Z8iQgai+Pt/hZi2OaJBaPnmDPWXEwMqXBA7Xslowj+BHm7MVaQ2kyhR1+7YUw3fa5
         stBbcoTh64JI2RauaUZUGIzO6sal6njEhdnwNKEKNWXZwyVKfOKaXtA1nQy+N5Jb3Ve1
         4H5KQZPgA4bDhm/BjhsjC/aFpTzZnjWbeI4Eb7sfdSCMx0bBXg4OwniQRluTuYafiPI2
         qbXOeAMlSJtRnn7JnnwejOxGz65hf4s3kCcY+RIWnIK/1rUVEkphVzzhulOaEc/miYux
         wsNA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=TEjCelXUxkytAUXWnkAMKSv0xXN4N1SC7EZTtlPbtlQ=;
        fh=qObQPquzet5p+fCG/gXi9YGx8Kjp+xLTApIfLaO5n2U=;
        b=WB6aWr9EYw3hESZhUHCWROPSWSXonntk9NLUjM6sJ12WmllgJ/3fESyKqh11va2pbz
         wTwa27DPPfugFYYLOqA+r4LKcpjOIrdFKq3Y73K1ytePS5qMh8APlr0anlE5+9254g/R
         +t4/Zkw+Z16paAPGBoCbV6jsKx8kIkYWmamVnXT+wEFlP+aj9n8n/okEjBRmf1f5w38j
         rHrIb0TbLVfAbcsATBwmmvFk9vtAwI95WoH5KA0dzqIgmFKFOP2Y/gD3V8yiF0lPlz3i
         XnvO9Ovkx6EJSbiB+x9mEIH/gq5E0c4zdY9zNQedXieDvrl3LgLOnYnHcib3xusOQeHI
         N6bw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=m1qDS51J;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::431 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1703190159; x=1703794959; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=TEjCelXUxkytAUXWnkAMKSv0xXN4N1SC7EZTtlPbtlQ=;
        b=Xew2nGQniWsQGvc3vh3SlCrqwKm5FuieKJCstMgWdcBmB4QXWYEs7J4qM/ixHyLHsh
         LfwWDzkpRzC+yb+ayMBQEsY7mrrMyy2acesm9vM8PTvuuNyFzsEKkF1xtRA2CW+6u23P
         KwmmEC44gNsqONurZDep/KVlEVV3V1MfCzLVUJ4qWEiWUIAOlsxPbL4R0ic76DOpKcsy
         Uz7EmrHuguX1a0LMK54hyiAKfmZW3JYFylBIDkV3da9Y6BVa9RAB+4QwZ2oolWJ0R2Ft
         7ckhxAAfOIJMl2duL/s0+N5npapIl7291Th1fdTvtLwNIJC/vsVLgJPqxwr/GJfpVtFA
         T2EQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1703190159; x=1703794959; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=TEjCelXUxkytAUXWnkAMKSv0xXN4N1SC7EZTtlPbtlQ=;
        b=NGqeEfH/RdUD221DXNTr1QNdoQLofAY3tIcQBZrJC9C4s0stIU8lLbQVYxPG8oe/ma
         /vZXiyglOjUncYtXHUpmkEeJcoJ/0DjrCcY6TkUNXuXtelyCXZXm8n5pqk3Ic4FXazCu
         v2iVeSBeXjFTCuzSlUl/q8vXGHo92Mjpdb77xp2Lyqo8z2ORWbVoU+JwFOjNWiZaG+j5
         1duPTnOBIDfD8FrWzq8tgBBUPzYiIvKplExsQVuSYgOkG2wtP1wzsHJsJIvBzmaXQFop
         5aTMcAkIxbJqWU32YmtuKsZo6OO+dnrFSWMCwlTttNgpS54a6mjyAwymBFkytZArGoQ2
         8dfg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1703190159; x=1703794959;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=TEjCelXUxkytAUXWnkAMKSv0xXN4N1SC7EZTtlPbtlQ=;
        b=WbBtz4NttMBGSQjm2rj8xB6HgcYqZCaFD26jWIUseIw0Uy2clKWK9AQM1LpjXJhZcT
         EC/jr7cIkaxNlPkDL0LO/qQlcMI3PQ9jG5xU520Vs0iRcSy+eR3MylNC+VPP8UXxiYKe
         6+I6qiwufQfmoeBrEtjqpn4UWEgYYJPAk0Vc4nli/HzpWDWemIjnVV4+4ZW4DOospQmy
         Qe8QMIbl5OwTu0YYMzaTn6X3ZzYuroFODB7uQ8Ht/cTYMrilA4sYdiq7xfOUXyYUffKM
         52vL0ak3fFukRkUUl6KppCMmkw67CwCjpazre3K5ytxS2Q+H2/g/i3WnP07nmzZSZqQe
         jjFg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yzkei03xC42MJtvhZKXF3mv25Xt5wmSM8JeftmSh1JnLAiIDiAx
	0VWYY83RGUVo1eYBocBuT8A=
X-Google-Smtp-Source: AGHT+IEtFaf3xnqFALEAUTnfiLhaBjoNQ57tjR+VRjn5tXcxOPR0H11im2Q2Au3PMQu2Wv7UG2+Pcw==
X-Received: by 2002:a17:90a:c387:b0:285:b7b9:dcd5 with SMTP id h7-20020a17090ac38700b00285b7b9dcd5mr306490pjt.36.1703190159695;
        Thu, 21 Dec 2023 12:22:39 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:1b47:b0:28b:dd9e:4f8e with SMTP id
 nv7-20020a17090b1b4700b0028bdd9e4f8els1011583pjb.0.-pod-prod-08-us; Thu, 21
 Dec 2023 12:22:38 -0800 (PST)
X-Received: by 2002:a17:90b:1089:b0:28b:b87a:d4b3 with SMTP id gj9-20020a17090b108900b0028bb87ad4b3mr282187pjb.98.1703190158577;
        Thu, 21 Dec 2023 12:22:38 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1703190158; cv=none;
        d=google.com; s=arc-20160816;
        b=WUCGgfsZt3I9jQQN4uBYLFUS7hnAlcNNB9LD50eZornl/Nm6pGhjgvvzm8JuN28Had
         +At+OAaPycbZtFqwzySEByHk2xAEGgz1tp+JQ2DiNM2pa6aboYWs2W6le0gLvZVxqxCm
         9j+ArBbSiI0AJ2Jn4lvyU1wrLeZPhkJCyJoE29VhpLpMefE67OTNgjutw48vkyNsljUK
         s0RlGh8y8fGaGNO1VejtuAexZ3Egy4C5AKsVuqQWPgLfwZFAT//f+KSj9nuY5AfyfY9d
         C0BTa3C5znYxyiU4OOJSRu/mnWGmPhz75fkKjpjipy7l9E12DKsm4pXpbWdMxhT4uCq4
         niXw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=TJf9nuaR/XCC7BWiN5csd+/5Qq/ivgehUMmQB0WS6r4=;
        fh=qObQPquzet5p+fCG/gXi9YGx8Kjp+xLTApIfLaO5n2U=;
        b=r88mKo0bD9wOPiHLdV0EZII2cm07T2HgTnwDMDvCFr4kE/6tqlt6inI4J7rBuVex4V
         jY8iLwjUoNAZJBQFX+DPobChy4ZqJlEhdZHNTTzrrdXU/VKc1t3P96UJ8ewNbW14cY+b
         D1ODXFMfywN11HrFEJvO9WBF8DeqLM5BLXHQWbO01cYYTj6BouictMxsTtHIjD0jZAmf
         IEWqNzNjfQERdhfy2DYpkgygeHhNJTqUfItA//6gZjBy1xLMjAf8vYT7zGzWs1BU3V9w
         sOr8twpZ98lDQm3HVwg3SKv1el/N7f92l9/rCdoC/e5HAcFFeof8Z06wl6OoqTsDKsOn
         2SxQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=m1qDS51J;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::431 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pf1-x431.google.com (mail-pf1-x431.google.com. [2607:f8b0:4864:20::431])
        by gmr-mx.google.com with ESMTPS id a8-20020a17090a6d8800b0028bc9da1651si307381pjk.1.2023.12.21.12.22.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 21 Dec 2023 12:22:38 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::431 as permitted sender) client-ip=2607:f8b0:4864:20::431;
Received: by mail-pf1-x431.google.com with SMTP id d2e1a72fcca58-6d775f9af42so1095370b3a.3
        for <kasan-dev@googlegroups.com>; Thu, 21 Dec 2023 12:22:38 -0800 (PST)
X-Received: by 2002:a62:e703:0:b0:6d9:4598:d1f6 with SMTP id
 s3-20020a62e703000000b006d94598d1f6mr236967pfh.18.1703190158185; Thu, 21 Dec
 2023 12:22:38 -0800 (PST)
MIME-Version: 1.0
References: <20231221183540.168428-1-andrey.konovalov@linux.dev>
 <20231221183540.168428-4-andrey.konovalov@linux.dev> <CANpmjNMJM0zp9qmxh0MkAfKTLgzkcxyraGMp6JKSf9YquW4WMg@mail.gmail.com>
In-Reply-To: <CANpmjNMJM0zp9qmxh0MkAfKTLgzkcxyraGMp6JKSf9YquW4WMg@mail.gmail.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Thu, 21 Dec 2023 21:22:27 +0100
Message-ID: <CA+fCnZdovMDygNE-ACEd++4Q23BAHp5QKaj6YhD929vTAhEDsQ@mail.gmail.com>
Subject: Re: [PATCH mm 4/4] kasan: simplify kasan_complete_mode_report_info
 for tag-based modes
To: Marco Elver <elver@google.com>
Cc: andrey.konovalov@linux.dev, Andrew Morton <akpm@linux-foundation.org>, 
	Juntong Deng <juntong.deng@outlook.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, kasan-dev@googlegroups.com, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=m1qDS51J;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::431
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Thu, Dec 21, 2023 at 9:14=E2=80=AFPM Marco Elver <elver@google.com> wrot=
e:
>
> On Thu, 21 Dec 2023 at 19:35, <andrey.konovalov@linux.dev> wrote:
> >
> > From: Andrey Konovalov <andreyknvl@google.com>
> >
> > memcpy the alloc/free tracks when collecting the information about a ba=
d
> > access instead of copying fields one by one.
> >
> > Fixes: 5d4c6ac94694 ("kasan: record and report more information")
> > Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
>
> Reviewed-by: Marco Elver <elver@google.com>
>
> > ---
> >  mm/kasan/report_tags.c | 23 ++++-------------------
> >  1 file changed, 4 insertions(+), 19 deletions(-)
> >
> > diff --git a/mm/kasan/report_tags.c b/mm/kasan/report_tags.c
> > index 688b9d70b04a..d15f8f580e2c 100644
> > --- a/mm/kasan/report_tags.c
> > +++ b/mm/kasan/report_tags.c
> > @@ -27,15 +27,6 @@ static const char *get_common_bug_type(struct kasan_=
report_info *info)
> >         return "invalid-access";
> >  }
> >
> > -#ifdef CONFIG_KASAN_EXTRA_INFO
> > -static void kasan_complete_extra_report_info(struct kasan_track *track=
,
> > -                                        struct kasan_stack_ring_entry =
*entry)
> > -{
> > -       track->cpu =3D entry->track.cpu;
> > -       track->timestamp =3D entry->track.timestamp;
> > -}
> > -#endif /* CONFIG_KASAN_EXTRA_INFO */
> > -
> >  void kasan_complete_mode_report_info(struct kasan_report_info *info)
> >  {
> >         unsigned long flags;
> > @@ -80,11 +71,8 @@ void kasan_complete_mode_report_info(struct kasan_re=
port_info *info)
> >                         if (free_found)
> >                                 break;
> >
> > -                       info->free_track.pid =3D entry->track.pid;
> > -                       info->free_track.stack =3D entry->track.stack;
> > -#ifdef CONFIG_KASAN_EXTRA_INFO
> > -                       kasan_complete_extra_report_info(&info->free_tr=
ack, entry);
> > -#endif /* CONFIG_KASAN_EXTRA_INFO */
> > +                       memcpy(&info->free_track, &entry->track,
> > +                              sizeof(info->free_track));
>
> Not sure why the line break is necessary.

Ah, just the old desire to use 80-column line limit :)

Let's keep this as this for now, but I'll fix it if I end up sending
v2 of this series.

Thanks!

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BfCnZdovMDygNE-ACEd%2B%2B4Q23BAHp5QKaj6YhD929vTAhEDsQ%40mail.=
gmail.com.
