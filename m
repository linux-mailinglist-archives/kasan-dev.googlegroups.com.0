Return-Path: <kasan-dev+bncBDW2JDUY5AORBMXSR2VAMGQEBL7I7QA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3e.google.com (mail-oo1-xc3e.google.com [IPv6:2607:f8b0:4864:20::c3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 890EF7DF571
	for <lists+kasan-dev@lfdr.de>; Thu,  2 Nov 2023 15:59:00 +0100 (CET)
Received: by mail-oo1-xc3e.google.com with SMTP id 006d021491bc7-581e1547fcdsf1330325eaf.0
        for <lists+kasan-dev@lfdr.de>; Thu, 02 Nov 2023 07:59:00 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1698937138; cv=pass;
        d=google.com; s=arc-20160816;
        b=m6062M+C3yKfYE6a88+mBfZMblPp7rAIakQRiiGD+CKNcqPmbGqHTQKTtpkKorExnC
         Nvo8UUT9jB+LzY19lGf3uf3Vo8qgvX6kyk/eXGkgYMMUU72HR6oMwLv8xe7HwxAIQE0N
         ih9/HnjK+UXgRBI2E8VswAEql6OG/c8wBxCYxnZFFNt1k/ZihAprmr7VQaeD8NRcgwWH
         6QUDGxHYJqd4BbSnKzlFFt4CBOBZpjAK410BWeuY57zgiQGsdLbfMbnlYg6aFXxFbmeT
         q8+Wb+7CqfNAIZ01tLKXN6o/3A+GeZ6PmZG8zH06C6xEvH31mJ1a4dX4ug0WqA7iSlAX
         8rvQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=NGoAL+Igiv7PbR+PP/R3GY6MOY9101da4b4+iUySdAk=;
        fh=ryOnPr3C6ahf4FXGiLv6MVMeJ7GFuwecZ2iLNzMX0nY=;
        b=tmWzPLrQBZEm4+a+K9Wc4NK9vvr057yp7Mes6EPYoh2nu1DFG2DLyhWqpoUEbr+htu
         ah5L41tNP8D9BuLvuMacQEuP+6DVvTj8dXFB0IskS0R482Bjv73KAUtDJ7KlgBesZ+yC
         K+CMnSvRyALlGbaq6iVdI/Zc+oImJPVwrr48qw5+1ScWjxyEepQ1TQZH4LvOWUe40Fr8
         saerkoseNUaUNFnjifIcoRA61zrS4j7kQlrxgl7QC0MtGYLCELNzTGo06M0cK3UpDsH1
         YS0/uu0n2XXLKt8cpjw+fRImn+a6rdT2ylqELyF54tO+Y1RHfarEm2vOKTBPM+miQyq6
         WfrA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=l5oUNN8t;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::635 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1698937138; x=1699541938; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=NGoAL+Igiv7PbR+PP/R3GY6MOY9101da4b4+iUySdAk=;
        b=IFLvhckMT9Xr2O9Si4KpzkFK2iLGe80zl/O/bXJvkKhVH8zMDtUTTN/RzfCKoApKTo
         Ov3nwr1o8sX2U0W91Xmw5WvmVacG+GoU+9A+eNtsxgwNm6frcgMZ3/Oa2+U8pkWKK1F0
         Ngy/TOqClc5PBnjb0ZMzZ0xqUcP0YpwuwS71J0ZsInWyXhL6mEBuD9bvp0TSTzuOoPHP
         OBjbuB7CcKI1eeA0KDFKGnn5s87kKQlScTIXi+/UEI6EpUdetvvR+7L/zi81S1FRej/L
         j1JUrAGaYi2vgpGYpveoL81+oJ9MI6BT+fTie0K7RBhHcmawqZrrasv3ybkGEXDE/rkQ
         GFEg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1698937138; x=1699541938; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=NGoAL+Igiv7PbR+PP/R3GY6MOY9101da4b4+iUySdAk=;
        b=Iomb4k1+1nuDcGmQRrH1TJ5klj+MBnqZDRmD7Gi3EtJ79vfsemTdYEl+lScICzu0oo
         s8VpcjkWYUu5Rh1SxjqHI22uR8jEW2DVT0u2dg3zLr/taCyh6gxMpZTOEBoLXVd2Y29P
         kz+0tlfiBPGwZ5eD/uAa3SNSlVDdYNQLh4dhHi7yQyHpcUWh7kLdDh/4/N2llTB52u2j
         ljY+PqzfrF6sk40BB8TSanVzQ5C/e/gcB3PF89v/+3ztPQ5/P7aMWF366jM7sZlenAg0
         VBbIcL1ndsc+sRteJpSC6zqZy5ijRzfBWTFh3W1w3+o/PPe/mh6ImkdGTMrFA2Zuon2I
         1uHA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1698937138; x=1699541938;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=NGoAL+Igiv7PbR+PP/R3GY6MOY9101da4b4+iUySdAk=;
        b=GHwIaDs0L/bCdsow2NEzYpPHk+jYSUw7v0DcjChTkAkcxwhE8pRLhx+fjQu5XsIqNX
         FPhREzjUgzicg0BefDvXUrT0MHpwS4Ru3f5b10gwaXQYeIiY5GqTr+sMYHeDgW3cpuhu
         wDb54JSK6kUABnXIyQm6/6i0mx60UX84kfjxcCCGPuY2lKyPSf/lgeJbtp59fbBN/DBZ
         vSW2yTOgQg88eW3AoeOdMQEagETc7XhUan9YRoQdyhHLWhyTv5HtZ+fiJwYnjay+UKJ3
         qIUyWY/lapLiKpnGVlW9UG8P7HHpHlpoKUBSdZcCSlZCL/8IEvBF5wr5c7LNg3XjTaKz
         qDOw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YyG8YwJOsGa5Qi46zV08PJ0p2wZ2dpGcsZhHPCk7F9hqVbOmSRR
	t6I5s3iWwYYmLcJHhpc/b5M=
X-Google-Smtp-Source: AGHT+IEcPLTevO5J1Qjzxv7NpcOxjUyJRSDgo4V/3eqR7iGOdjcwV4jpcslN7zkQJ/1QGupI9P3BMg==
X-Received: by 2002:a4a:dc94:0:b0:57b:7ac4:7a94 with SMTP id g20-20020a4adc94000000b0057b7ac47a94mr17646935oou.2.1698937138129;
        Thu, 02 Nov 2023 07:58:58 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:5e84:0:b0:587:31f8:bc6d with SMTP id h126-20020a4a5e84000000b0058731f8bc6dls1005345oob.1.-pod-prod-07-us;
 Thu, 02 Nov 2023 07:58:57 -0700 (PDT)
X-Received: by 2002:a05:6830:2b2a:b0:6d3:1f3e:4c4 with SMTP id l42-20020a0568302b2a00b006d31f3e04c4mr4862063otv.0.1698937137173;
        Thu, 02 Nov 2023 07:58:57 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1698937137; cv=none;
        d=google.com; s=arc-20160816;
        b=tFIHJgNYoAdqVz8WuqxmOdUM6oJbYneCCk+ozeFfz8EViaC8C1GWpyay41wvMLl4f9
         kefn2hTOePG9pdVf9Xcmaqu29L+2qhOJgk+pfmMS0QRVI4vZx9SsRTK9gewCOZlvRxeA
         yS2aze0W/bfjL2ayMdBoK9grHg+di0BdaHC0eQsUhiHtwkClJpiJ/CbHVHsfrKiDux0m
         iKaCGHCDLq9jet66cB5L/s7vxasTqxXtwOcHQLhoAUklQliS+yUl8U5wk8xaX+TKGYHv
         lywAVESRDqYRvnR8qxwrlOtqbaaQ4WXrYByJSrn7tdpAcGhD97/FfFuwAX7S69SWCpWx
         usZw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=V4u7No3WKyf2rx02w8WP9k4VSXCaz8LOG7ZTnqR2+ek=;
        fh=ryOnPr3C6ahf4FXGiLv6MVMeJ7GFuwecZ2iLNzMX0nY=;
        b=xiz2JOaPWmXDNu0/UIrCjxaXYDquYmnnjfS/sA4eNk71IdcQoz2Dm0k8jeDXgrpcxb
         BFHGph73IlvchvZCqyVn1600IqiIiysjTHY7yBbI3pX6lfx7Ui8k5+m2lwFsyJZKrJ3S
         6XYrKxBUQ1SPGAC0gPnzaC0BN+8J64BbprliTVzIN2z9ydPDbEj3WBxbi/FhhN7J0uHy
         +DyF92MpRyNKLmxTGAGLTrUoGhstO9ZY3Hjspdklub0mSpkL7JMA7R3KKG8GwEiLBekW
         s3Q9MUOiiJU98n4q4vE1myaM40MSM5dS9/fob7DGRXtIPd7v2C0Ye+URWQMn0i9fgeZs
         OUuQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=l5oUNN8t;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::635 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pl1-x635.google.com (mail-pl1-x635.google.com. [2607:f8b0:4864:20::635])
        by gmr-mx.google.com with ESMTPS id ed3-20020a0568306e8300b006ce2f207148si488854otb.0.2023.11.02.07.58.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 02 Nov 2023 07:58:57 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::635 as permitted sender) client-ip=2607:f8b0:4864:20::635;
Received: by mail-pl1-x635.google.com with SMTP id d9443c01a7336-1cc3bb4c307so8135545ad.0
        for <kasan-dev@googlegroups.com>; Thu, 02 Nov 2023 07:58:57 -0700 (PDT)
X-Received: by 2002:a17:90a:ec03:b0:280:664d:cd9e with SMTP id
 l3-20020a17090aec0300b00280664dcd9emr10351944pjy.19.1698937136368; Thu, 02
 Nov 2023 07:58:56 -0700 (PDT)
MIME-Version: 1.0
References: <VI1P193MB075256E076A09E5B2EF7A16F99D6A@VI1P193MB0752.EURP193.PROD.OUTLOOK.COM>
 <CA+fCnZfn0RnnhifNxctrUaLEptE=z9L=e3BY_8tRH2UXZWAO6Q@mail.gmail.com>
 <VI1P193MB07524EFBE97632D575A91EDB99A2A@VI1P193MB0752.EURP193.PROD.OUTLOOK.COM>
 <CACT4Y+a+xfzXBgqVz3Gxv4Ri1CqHTV1m=i=h4j5KWxsmdP+t5A@mail.gmail.com>
 <VI1P193MB075221DDE87BE09A4E7CBB1A99A1A@VI1P193MB0752.EURP193.PROD.OUTLOOK.COM>
 <CACT4Y+bxMKEVUhu-RDvOMcbah=iYCWdXFZDU0JN3D7OP26Q_Dw@mail.gmail.com>
 <VI1P193MB0752753CB059C9A4420C875799A1A@VI1P193MB0752.EURP193.PROD.OUTLOOK.COM>
 <CACT4Y+ZS5cz9wZgxLVo2EsGtt-tkFXkFPA6CGAA8Gy7+sEyDUQ@mail.gmail.com>
In-Reply-To: <CACT4Y+ZS5cz9wZgxLVo2EsGtt-tkFXkFPA6CGAA8Gy7+sEyDUQ@mail.gmail.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Thu, 2 Nov 2023 15:58:45 +0100
Message-ID: <CA+fCnZdRWs=P4EgzC9sSDLfO=Bxbs9FyeOcqAiY8pzvMLUX=Aw@mail.gmail.com>
Subject: Re: [RFC] mm/kasan: Add Allocation, Free, Error timestamps to KASAN report
To: Dmitry Vyukov <dvyukov@google.com>, Juntong Deng <juntong.deng@outlook.com>
Cc: ryabinin.a.a@gmail.com, glider@google.com, vincenzo.frascino@arm.com, 
	akpm@linux-foundation.org, kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	"linux-kernel@vger.kernel.org" <linux-kernel@vger.kernel.org>, 
	"linux-kernel-mentees@lists.linuxfoundation.org" <linux-kernel-mentees@lists.linuxfoundation.org>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=l5oUNN8t;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::635
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

On Tue, Oct 31, 2023 at 10:46=E2=80=AFAM Dmitry Vyukov <dvyukov@google.com>=
 wrote:
>
> > >>> There is also an aspect of memory consumption. KASAN headers increa=
se
> > >>> the size of every heap object. So we tried to keep them as compact =
as
> > >>> possible. At some point CPU numbers and timestamps (IIRC) were alre=
ady
> > >>> part of the header, but we removed them to shrink the header to 16
> > >>> bytes.

> > Do you think it is worth using the extra bytes to record more
> > information? If this is a user-configurable feature.
>
> If it's user-configurable, then it is OK.

FWIW, Generic KASAN already stores the auxiliary stack handles in the
redzone, so the size of the redzone header is 24 bytes. Perhaps, we
should hide them under a config as well.

However, the increase of the redzone header size will only affect
small kmalloc allocations (<=3D 16 bytes, as kmalloc allocations are
aligned to the size of the object and the redzone is thus as big as
the object anyway) and small non-kmalloc slab allocations (<=3D 64
bytes, for which optimal_redzone returns 16). So I don't think adding
new fields to the redzone will increase the memory usage by much. But
this needs to be tested to make sure.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BfCnZdRWs%3DP4EgzC9sSDLfO%3DBxbs9FyeOcqAiY8pzvMLUX%3DAw%40mai=
l.gmail.com.
