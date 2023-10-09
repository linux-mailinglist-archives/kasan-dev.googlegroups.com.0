Return-Path: <kasan-dev+bncBDW2JDUY5AORB7FSSGUQMGQEIOALVKA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x139.google.com (mail-il1-x139.google.com [IPv6:2607:f8b0:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id EC7937BEAD5
	for <lists+kasan-dev@lfdr.de>; Mon,  9 Oct 2023 21:50:21 +0200 (CEST)
Received: by mail-il1-x139.google.com with SMTP id e9e14a558f8ab-35129e6494asf39878205ab.2
        for <lists+kasan-dev@lfdr.de>; Mon, 09 Oct 2023 12:50:21 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1696881020; cv=pass;
        d=google.com; s=arc-20160816;
        b=PXMvSmE/P63AZggNVP7T8S+EEB47t7fYRRXY/Zlg34XQqbqsXX7O8iqSwv/YZOLMKd
         oYlhrZ5WRQeq/Szt2MZzKDBo7CrJh3Cv68WABBatfUHojlNx/65tYfAUDIF9+vAi+s9T
         8xrZkti2DK2MVp7uGybz18SBZwB2VT6shFEX3knOHVeS6MCVQCsd247HXJoYt4O68JZh
         rXXfgJqoFMnk++OK4TFbZTIaHAga6d9U01l5mGkFh15PjJvFgMSrJ7Alj7nsT11Hd5aG
         IgYhL5G8Abk85tKVK86xZAu4dSkhClWuQOVBj272VPyL+WWW5jgequM67X7q+DrxtnUI
         FCHA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=LZs+LjMIt/OtUCvgqAyDHVYM5q5yBQRdYo/pLlyMT5M=;
        fh=7igJxN9LckRTWOqPqITFhKv7QvF9IZfOm1aZGp1o+b4=;
        b=X5WuS3PjqfYKulI4ak66pEvIkAmhdTVvBaoKPykmq8rDefyoD+VpqfZPNf5t9Bt6kn
         mx0+F7lqou1jcPhAUVbrbl2LaQzy4QJ8pauUP+TAuiKds1MfzvSZYFzDjGyUTTmvbmUg
         i3MxeQ4aGShYRhIgTJ829WTZsitMOcmw5+LV++m3XGk8YJC83kRrHfzPEpS1AXPsLXBM
         C54TcxqNm1XannxQbo6ELlvjk94tOAeR/LSvaZNd+nLaZ64rxkdJO6Ay0UufmCsst9zW
         hpSEdxMCY1xNKsquXk29LIvfvEDrtoU8Zu1ioUdKczPdOomnD00wKN3/+v/yPQEkOVwT
         uPpQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=GXHveFpt;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::1030 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1696881020; x=1697485820; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=LZs+LjMIt/OtUCvgqAyDHVYM5q5yBQRdYo/pLlyMT5M=;
        b=o/EODRaMtCv21JTuq3uak4QIcE8TEziMvEUKxlaC2pVroyivgRxa9NdG+/SRCA2ohQ
         Ednx5Tp4HhL3ClkR/7BikfeAF4I3H51f6/GPydAewYQQ0U87uF9hkvo4L1y9LFldvAwL
         cwcvgpoZHaeLL6o23NQ83Ipe1xnJJap8i5vTOmvvmrKPiZ8aHxcIMzvXVZ3+grb+2TzW
         h6yL+kfnNgXae9DQKy7lsXTi/a4nm4ZmbtG22PK1z+3FqAbjGXMe0BG4Y6eZAkO0eokB
         j++KSE9kxb5nIS774lc2ZNdg0UJZl0aA4LiMWC03oX03nRN8HLlrAzrFSDstzgII1bR3
         gc3Q==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1696881020; x=1697485820; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=LZs+LjMIt/OtUCvgqAyDHVYM5q5yBQRdYo/pLlyMT5M=;
        b=jvA6U+5IGrZw8HsfPzKGMuCZBufY3XbsjFD9+vTIiBMdtHQrOcN9TLS1bLatXdjrqa
         U17pZQ0x12HKYoQL1SGFR/YNervBcqRpOjSTbpe2fz7kvLPUokYN/eUPhn0Cany40HHu
         +2LaJQK/PAjncqFX2pEccCI7z2K7r5TRMsAW6b6R00k9giXM0XPbVYJ7WD5SKHqJSuZ6
         k3HYblYLZSRSjdpwbB/uE97Hbxuk0vdsCMXtS4HKxJTqsPfYoXw8b9n3pqVUE09iqKM5
         r0Fru753jRonf/P0JEANCVWUzhUHYw5ljyNNNewPRzmueyvtUS0LmkDzfTxui/fl7sRk
         1b9w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1696881020; x=1697485820;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=LZs+LjMIt/OtUCvgqAyDHVYM5q5yBQRdYo/pLlyMT5M=;
        b=X+CLhnQcnlozDQUnLG4xJw2u12QmdMIP7Ly/Bz3e1U9QtaXvyzHkoGCUlr2io5X96q
         8iNw9OKnCl3/AV+6jWr3SiTv2XWhha3/GcxNWMyShOZhrHq3CCqpIUPDcwPKtZT84RGG
         eWO6TlcXGX2iaFoAYSuugpzObgDrbGknodLbz7e9L+l7Lp1O3029TK+EbMwSV3JNnf9/
         eJ3hAEqhCGmqS3Q5CY7wSmLydG75rx1DyBPsCmjSl6DeuC8jTmEk51LFIdb3bstyv4+g
         K5zIRSyP/KSyw6d8fXANNhyMZFfy8aS+viwd5ud3p/fzWw99VEPFpxZQo4H+v36v5aXT
         CPmA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YymHE2MpVgc4abLolx981LGk2z+JzqPTppHLb7OkUnFzxoWGMK1
	08wA6tvz6+MPlJEMP5arwLY=
X-Google-Smtp-Source: AGHT+IFDBGas/5crVEGtaOCPMsbtjkaSs3e/L22n22eNPENlNuGs68sEQSNuKWI8SZMUSyeE1e0FwQ==
X-Received: by 2002:a05:6e02:13d0:b0:351:526a:4ac with SMTP id v16-20020a056e0213d000b00351526a04acmr16186439ilj.2.1696881020409;
        Mon, 09 Oct 2023 12:50:20 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:3409:0:b0:352:6621:64a9 with SMTP id b9-20020a923409000000b00352662164a9ls241572ila.0.-pod-prod-01-us;
 Mon, 09 Oct 2023 12:50:19 -0700 (PDT)
X-Received: by 2002:a92:cd8b:0:b0:34f:7e36:5f8b with SMTP id r11-20020a92cd8b000000b0034f7e365f8bmr21853229ilb.25.1696881019075;
        Mon, 09 Oct 2023 12:50:19 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1696881019; cv=none;
        d=google.com; s=arc-20160816;
        b=p7ZFldy0jg5BTddu/3Hi/uELK+5A+1UuPLfI0t2Eq/9WJ0VBnpsPOGxtlxTaTs9Ap/
         c84JQ9178Uf9ugZNa439Dq4UITlM+2XGaOScRkQ+tp0bI48XdBnD8KQ9d1ZtyN9ahjYN
         888SznCt2EogvuqpkNKNn05l4imUrPX1S3vFJbXewfNEK3YHkeipq/50bnTy/9Rp435A
         Mn/ysebwkoTBx+EVTvzggvIXIiIpl/sBqRxKkBbU6IcIkjUeh+CXLJdDOBqVHKYh2aFd
         C4OffIT7Lu7b1oqZG4WP8JrizhH0xsRG1gCeW2H3hZR7N66zSu3iL+fNx4NQjvLAePtB
         DeKA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=e8wgkR84iWM9wxhviglgJUbOlzdCkXj/+h+ORKDao4Y=;
        fh=7igJxN9LckRTWOqPqITFhKv7QvF9IZfOm1aZGp1o+b4=;
        b=eeqUo281Iisj8aPvYPBnG4L9L4OjUvJJQ+02V817WuNwatSsL1Outq449EOpQ6pFJf
         F6luRvuWIEYrkhOTnTBjgjB5JrGkteQ6tywo7Cn0eOqUhEl5w+k42zH9h805cnJlbXKq
         iwrfzbGaQ0du894gATZuUuQillnyQB8xTFQVI9x3vMB39efzpYJJbWY8KNn62z0x5tPp
         rSgcjSjXD0LmSKzOkNQlObgQL7rHOipIcV8Iw+5QxeTcFeiH/BLpN5NSz2D7F4+05120
         XihnRixlVHVIwZVEljyVZACppG5elZcqcC+Kniac0DuB1LCB0HsDZEBAM86N6DgGgToW
         WO7A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=GXHveFpt;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::1030 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pj1-x1030.google.com (mail-pj1-x1030.google.com. [2607:f8b0:4864:20::1030])
        by gmr-mx.google.com with ESMTPS id cx17-20020a056638491100b004312fb02a61si637634jab.4.2023.10.09.12.50.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 09 Oct 2023 12:50:19 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::1030 as permitted sender) client-ip=2607:f8b0:4864:20::1030;
Received: by mail-pj1-x1030.google.com with SMTP id 98e67ed59e1d1-277564f049dso2855310a91.1
        for <kasan-dev@googlegroups.com>; Mon, 09 Oct 2023 12:50:18 -0700 (PDT)
X-Received: by 2002:a17:90a:b97:b0:273:4672:98b5 with SMTP id
 23-20020a17090a0b9700b00273467298b5mr12577856pjr.42.1696881018348; Mon, 09
 Oct 2023 12:50:18 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1696605143.git.andreyknvl@google.com> <6f621966c6f52241b5aaa7220c348be90c075371.1696605143.git.andreyknvl@google.com>
 <CANpmjNOHPRHOOPNwx04S_CE5OoQMAmfxHjxqeqy=YUpU+sY7yA@mail.gmail.com>
In-Reply-To: <CANpmjNOHPRHOOPNwx04S_CE5OoQMAmfxHjxqeqy=YUpU+sY7yA@mail.gmail.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Mon, 9 Oct 2023 21:50:06 +0200
Message-ID: <CA+fCnZc+JVdxzfiaSon+0V6-5c7SsXv8pNUvjWsfiLPyvMr9Ow@mail.gmail.com>
Subject: Re: [PATCH 3/5] kasan: use unchecked __memset internally
To: Marco Elver <elver@google.com>
Cc: andrey.konovalov@linux.dev, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, kasan-dev@googlegroups.com, 
	Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=GXHveFpt;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::1030
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

On Mon, Oct 9, 2023 at 10:46=E2=80=AFAM Marco Elver <elver@google.com> wrot=
e:
>
> On Fri, 6 Oct 2023 at 17:18, <andrey.konovalov@linux.dev> wrote:
> >
> > From: Andrey Konovalov <andreyknvl@google.com>
> >
> > KASAN code is supposed to use the unchecked __memset implementation whe=
n
> > accessing its metadata.
> >
> > Change uses of memset to __memset in mm/kasan/.
> >
> > Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
>
> Do we need a "Fixes" tag?

Good idea, let's add them:

Fixes: 59e6e098d1c1 ("kasan: introduce kasan_complete_mode_report_info")
Fixes: 3c5c3cfb9ef4 ("kasan: support backing vmalloc space with real
shadow memory")

> Reviewed-by: Marco Elver <elver@google.com>

Thanks!

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BfCnZc%2BJVdxzfiaSon%2B0V6-5c7SsXv8pNUvjWsfiLPyvMr9Ow%40mail.=
gmail.com.
