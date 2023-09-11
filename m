Return-Path: <kasan-dev+bncBCCMH5WKTMGRBQOT7STQMGQEBISEDLA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103a.google.com (mail-pj1-x103a.google.com [IPv6:2607:f8b0:4864:20::103a])
	by mail.lfdr.de (Postfix) with ESMTPS id 58C1179A913
	for <lists+kasan-dev@lfdr.de>; Mon, 11 Sep 2023 16:52:53 +0200 (CEST)
Received: by mail-pj1-x103a.google.com with SMTP id 98e67ed59e1d1-26f6ed09f59sf5366324a91.1
        for <lists+kasan-dev@lfdr.de>; Mon, 11 Sep 2023 07:52:53 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1694443971; cv=pass;
        d=google.com; s=arc-20160816;
        b=l1sonK/NzxRA+u+rFTOGNbCd7ER69/x4PAQWT44wbL5+0zvEMw+adsrPKsj0t4h2FA
         99wu6BjEreBdA8jQTwXdMwUknj2kfSxwvvSD6RabDOZrn/vBJWDrc/56ritbsPvWDzCE
         Tqoq1DHsPrgC4BvKRmodM8z50yG+hAq41WnMJrUxh+r3B2ODAOiGOZLxhQsDLUYb/Y7z
         cqiYcUhCFta8K+ar7pAT63iwx65ik/LRqWFriMpQXBZ8lApBhhnWGcU3jEwJcoG+LWWr
         gb5/F9KPz82F770YDvpPLEqyp/Kh9jTv83zWs+fHrjWAtf/OnS3wBkAM6tSRa0kqO+cd
         rihA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=4Kn5Qx0Pj6M84mdU4ltLDnbmV4Cd2sVrN39INm07/jg=;
        fh=upfTbkGPKUkGiCC9CQlGbqG1HxO1nTUtaIbjlhcOzHA=;
        b=RN7IUCVO2IOLAg5raa3dNx36ZLDrmqXLOBo8V6fvor48AtVgrhBUKMK1aY/wKXjeSh
         3ydn8YGAnUQecfX4xNiugXmYHE2YipKokv2LmutwlqJ41+Ikeg6vAq0QqG7XorFbpqlA
         C3IBUS7LWENMRmO2iKBOpZY9hks8QQxvzjcCODwu13GWKkJIx3QI6dDrWr1BtP7uHux8
         jIEyI+gJl5cLFRvOE1sOdZy4D4yo6hf960dYx1LdKV/L5z26kkXDIpLHRcnG+AjaihnX
         79KBU1UYTm5H6fUR6477UBFiPhhlyUvWtxWTEl/NhBl3MxIP7ZAQRwEZr2jtscmD4up9
         kX7Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=Ql9i32jw;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::d36 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1694443971; x=1695048771; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=4Kn5Qx0Pj6M84mdU4ltLDnbmV4Cd2sVrN39INm07/jg=;
        b=EmKfzoegr65bRc9GGW6xjniXOhUhVH+XnUJIEVt2hkZ4fdKvXXOYAelX1+KxZ1mzio
         93bjFHvFM44yCHrqMcWs+Lm+VXyvMAuu9kyPJgar/0pw5N1jCJFuyJERGO84Ty+HBxG2
         oarrTokWRHdCEKDgvfhCeUT++eZZUCCpxjgRFf1sVwyCDnoi89IzkfwJsgXNmXJAYvDQ
         h/IvE78BbeSTW24lIs3ZZ85RenoDjCLOA3vLq1CK19T3o4itUpzEQI2TPUSZ7HBa6LMn
         2s3+4xwX9wNL1Mu3GZplUlin+ZZ19L65y2Id9/P5MMlYGi543Fhsz0OlnVOq9J4H1MPo
         ZOGQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1694443971; x=1695048771;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=4Kn5Qx0Pj6M84mdU4ltLDnbmV4Cd2sVrN39INm07/jg=;
        b=OQkehUCLOo+JaaV85PE1s4Jwukh1fbXlyJN3ZOjMoxa1gNRBF5KwfxLkDW9JA53zXc
         Hiu5se3ucSRgxe4riQhHWPdnTE8spXNZqlX0KtnpyrPfP7dAWB15ciiUcBoEZT1bYKPT
         C+GP25FZ1dyVQASqyLFdo/H58DTZ38zmmXWRHPnwIHVHsi+nA3yLUhQQagYhbGuoVM9G
         H9zlLZZz7DQODp2pis1AFVrx6i1IhbbPjYblfpSba6O88wk9Zijan+HaVpgu9R/ezNbJ
         tJ1ZiBYHRSDl6B1wfyL8RCxgHul5Er2HskPnqA6SIXTWfYh/cyk2s1N1X2OOTiqjrj6o
         d3Ng==
X-Gm-Message-State: AOJu0YzTqHBKCtkKpoAjCXKMCehqUGR8GIKU1glXwlFJgknH9vxTKF+r
	dmUxCHHL9bM9qD3lcgmmb3JRJg==
X-Google-Smtp-Source: AGHT+IGnM1KOCrTFxBmWaPB2ecuC29DQXZmUczuDkA/Ixe1mNvwxXxv6TUEyXkbik/e80L1sns+viw==
X-Received: by 2002:a17:90a:7506:b0:273:ef5d:b287 with SMTP id q6-20020a17090a750600b00273ef5db287mr4246974pjk.8.1694443970044;
        Mon, 11 Sep 2023 07:52:50 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:f492:b0:269:5435:ebd with SMTP id
 bx18-20020a17090af49200b0026954350ebdls358087pjb.2.-pod-prod-01-us; Mon, 11
 Sep 2023 07:52:49 -0700 (PDT)
X-Received: by 2002:a17:90b:1b01:b0:26b:56fa:87d3 with SMTP id nu1-20020a17090b1b0100b0026b56fa87d3mr7270728pjb.31.1694443968951;
        Mon, 11 Sep 2023 07:52:48 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1694443968; cv=none;
        d=google.com; s=arc-20160816;
        b=aWaJzBMhAXZBGTB+FsWkLMTKmR1GhfO9/k3N2DmdKzyjbaetVwniduSG2pV+0I6cwa
         gyG0Ds9wBRWhJ8LrnuKWv2oblkUgopnwC4k9NDUoIbxj8UyoGw5x1XJ4Qw9VS719IqgD
         GzsbCF7oSunRYrMSDxin6QlcsdScVi+uziNjlqdrmjr1PCnKYvpXGrK//aBw+piY0xX8
         AHBSIgtfkcZkbSOglBQEdE6G3fQj349tq57E7QlQExUhbp9i70HS3Vu68U1H8FA9NYPF
         LnbF+CuJkWC6K591mEhb2lWVjGvJ4o62Ahdyssafz+qnT46yy4Wpt60m3h4jL0D10oo0
         oW4A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=90PlK9+vusP71rfnLS7AlLwtgErcjzc4R1LcqrGfUdo=;
        fh=upfTbkGPKUkGiCC9CQlGbqG1HxO1nTUtaIbjlhcOzHA=;
        b=xvJ+nI3YAVkjQAGLKdgmv/M8uBojlrs4cJPmrzX4xTwUuutdPHJrjT9HGHf2vWm5HO
         icQoyRP1NPg55iQRQXKArOhttQvzbtBTpCU06ad+wh7F0s0AtJJW6zv087eOpM+1ifCj
         svorqznTaKB9SFxoAypd5OBfk9l4r2jBCWSfa0B3hpmVT7EHMqHhnrxFUt0v8GarxTMi
         7jDPa+v0DowJ6Lrcfc8H5wPK3EJQJHEgXNMqKkdQPTQr1aOxhLT3hxeEFEAkUfNGaxR3
         YTHMwL3ezsS8C7/MHgUvmJciHQjopQQyTZFxMrkFmYodL01FdphA+UR+bZJGISf5LqNp
         mB9A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=Ql9i32jw;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::d36 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-io1-xd36.google.com (mail-io1-xd36.google.com. [2607:f8b0:4864:20::d36])
        by gmr-mx.google.com with ESMTPS id qi17-20020a17090b275100b00271a1895140si1083489pjb.0.2023.09.11.07.52.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 11 Sep 2023 07:52:48 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::d36 as permitted sender) client-ip=2607:f8b0:4864:20::d36;
Received: by mail-io1-xd36.google.com with SMTP id ca18e2360f4ac-79536bc669dso154171739f.3
        for <kasan-dev@googlegroups.com>; Mon, 11 Sep 2023 07:52:48 -0700 (PDT)
X-Received: by 2002:a05:6602:185:b0:790:aa71:b367 with SMTP id
 m5-20020a056602018500b00790aa71b367mr12539404ioo.4.1694443968284; Mon, 11 Sep
 2023 07:52:48 -0700 (PDT)
MIME-Version: 1.0
References: <20230907130642.245222-1-glider@google.com> <CANpmjNOO+LUgCWHPg4OXLzm9c7N3SNfLm1MsgME_ms07Ad5L=A@mail.gmail.com>
In-Reply-To: <CANpmjNOO+LUgCWHPg4OXLzm9c7N3SNfLm1MsgME_ms07Ad5L=A@mail.gmail.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 11 Sep 2023 16:52:07 +0200
Message-ID: <CAG_fn=X9bHcqnFawrKQv=cEVQ0cj4tQL-Cr+iJpAxUGn3ssMxg@mail.gmail.com>
Subject: Re: [PATCH 1/2] kmsan: simplify kmsan_internal_memmove_metadata()
To: Marco Elver <elver@google.com>
Cc: dvyukov@google.com, akpm@linux-foundation.org, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20221208 header.b=Ql9i32jw;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::d36 as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
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

On Mon, Sep 11, 2023 at 1:44=E2=80=AFPM Marco Elver <elver@google.com> wrot=
e:
>
> On Thu, 7 Sept 2023 at 15:06, Alexander Potapenko <glider@google.com> wro=
te:
> >
> > kmsan_internal_memmove_metadata() is the function that implements
> > copying metadata every time memcpy()/memmove() is called.
> > Because shadow memory stores 1 byte per each byte of kernel memory,
> > copying the shadow is trivial and can be done by a single memmove()
> > call.
> > Origins, on the other hand, are stored as 4-byte values corresponding
> > to every aligned 4 bytes of kernel memory. Therefore, if either the
> > source or the destination of kmsan_internal_memmove_metadata() is
> > unaligned, the number of origin slots corresponding to the source or
> > destination may differ:
> >
> >   1) memcpy(0xffff888080a00000, 0xffff888080900000, 4)
> >      copies 1 origin slot into 1 origin slot:
> >
> >      src (0xffff888080900000): xxxx
> >      src origins:              o111
> >      dst (0xffff888080a00000): xxxx
> >      dst origins:              o111
> >
> >   2) memcpy(0xffff888080a00001, 0xffff888080900000, 4)
> >      copies 1 origin slot into 2 origin slots:
> >
> >      src (0xffff888080900000): xxxx
> >      src origins:              o111
> >      dst (0xffff888080a00000): .xxx x...
> >      dst origins:              o111 o111
> >
> >   3) memcpy(0xffff888080a00000, 0xffff888080900001, 4)
> >      copies 2 origin slots into 1 origin slot:
> >
> >      src (0xffff888080900000): .xxx x...
> >      src origins:              o111 o222
> >      dst (0xffff888080a00000): xxxx
> >      dst origins:              o111
> >                            (or o222)
> >
> > Previously, kmsan_internal_memmove_metadata() tried to solve this
> > problem by copying min(src_slots, dst_slots) as is and cloning the
> > missing slot on one of the ends, if needed.
> > This was error-prone even in the simple cases where 4 bytes were copied=
,
> > and did not account for situations where the total number of nonzero
> > origin slots could have increased by more than one after copying:
> >
> >   memcpy(0xffff888080a00000, 0xffff888080900002, 8)
> >
> >   src (0xffff888080900002): ..xx .... xx..
> >   src origins:              o111 0000 o222
> >   dst (0xffff888080a00000): xx.. ..xx
> >                             o111 0000
> >                         (or 0000 o222)
> >
> > The new implementation simply copies the shadow byte by byte, and
> > updates the corresponding origin slot, if the shadow byte is nonzero.
> > This approach can handle complex cases with mixed initialized and
> > uninitialized bytes. Similarly to KMSAN inline instrumentation, latter
> > writes to bytes sharing the same origin slots take precedence.
> >
> > Signed-off-by: Alexander Potapenko <glider@google.com>
>
> I think this needs a Fixes tag.
Thanks, will add in v2!

> Also, is this corner case exercised by one of the KMSAN KUnit test cases?
Ditto

> Otherwise,
>
> Acked-by: Marco Elver <elver@google.com>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DX9bHcqnFawrKQv%3DcEVQ0cj4tQL-Cr%2BiJpAxUGn3ssMxg%40mail.=
gmail.com.
