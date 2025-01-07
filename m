Return-Path: <kasan-dev+bncBCCMH5WKTMGRBUH46O5QMGQEDKNVAYI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf40.google.com (mail-qv1-xf40.google.com [IPv6:2607:f8b0:4864:20::f40])
	by mail.lfdr.de (Postfix) with ESMTPS id 0B6D2A03BF0
	for <lists+kasan-dev@lfdr.de>; Tue,  7 Jan 2025 11:13:38 +0100 (CET)
Received: by mail-qv1-xf40.google.com with SMTP id 6a1803df08f44-6d931c7fc26sf252447136d6.3
        for <lists+kasan-dev@lfdr.de>; Tue, 07 Jan 2025 02:13:37 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1736244816; cv=pass;
        d=google.com; s=arc-20240605;
        b=Qy8e7NSi1gBliQ5F4xnZdbl8/AbnmjX0PBhh+nFbYyz/MC/HbEmDsuaPME6B75KlYC
         BY5Z70ujMETPf9EaRMz6UMKevFIESmPEND98Tm7AWU0e7ZGSUMo2UgN0/T/i+ZktJgY/
         Ir9LSaVIbz3UdSjlk9wG7Z9D8wqSBxWp9NHUSRg6dk5p/EXnCDwK6SRl5I3vDSZa4vsS
         O8Xm9FWGoPHEQK78mPp5rnyHjkp41drJuvngmr5L9IiPU1PyTwGAlENN8z8VKrorbMx7
         ZB31WCtCD9DrI31QNas9AmT48KTEPCetRUifGdsKxvDp/5BJUUNVzoIPx43xXrZWqsnO
         +FzQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=scjDrH5A/5xjUMIZHjU/ihUE4PyhbxOnBycf+lWoOrw=;
        fh=JgTSvRjv2nhe0AMIta04ZcmyEovQptIqQweMAaHYOVI=;
        b=Su1iZ0XbwwUgEfoFp11SSNVe5F1BiMkflYI7nR3kMyf/4uxhGvguj7t64cXOvtHjIz
         FcA3o36joD8ymypSwXXP0rQmqyy/WcosPfNr+MbhhZpomu7nHlYXA3ibF394hE0BChUn
         maeW9Zc81LbICctTWx/oC8wCBIiSunYJmH0C12Q/h2lnAxmBXndmSATZ8qhT4/bWzx7V
         IZeOpQ1MuUz79GK/X9mlWnloBDVceyPKrfFDOviOdsPLDs4+OXgnBPxizhtbPJtS/Kso
         kaPzxDZ2ALM+xPToRzMSfKp8OcVMXM8aOf2FIUahM8PjcOG5OZDvYxlOfujYyAgi5y9T
         EajA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=BiYnT8H8;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f35 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1736244816; x=1736849616; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=scjDrH5A/5xjUMIZHjU/ihUE4PyhbxOnBycf+lWoOrw=;
        b=kRozPwTHUNjsR+TSoeorci+y2LSd/qZY3n3ea63SyZs8YRq83lBeO2TPhr7orvOUEJ
         6EYbnng1gjVXCj3iF12t2jd7wETig/PZZxB0UoXHRoU+0fpuZuhGhGT7IDxP6jvFa6f5
         0vsiW9xDy3/E/3Yl1C+XG3mlWasLK+apOj41iIpjkyD/T2CmGVohYNaPWIgvJ8/YUce4
         cenx5cigGnz6N/Dz0TvCcUCbApo+solnfDMGO1iSV7Zz6rxvYYgsxeLhb7ggaUZKVVn5
         BVsjrbHcM6/vsPcMWdRgCrzuqw7Iw4cI5lYoRulhQ1xtDEJqhoNqDO+vRQyHyU4o6UDS
         OUbA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1736244816; x=1736849616;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=scjDrH5A/5xjUMIZHjU/ihUE4PyhbxOnBycf+lWoOrw=;
        b=oUxY0bsO5yhXJy9S0sreAlQt7XeTy8aDRoEZlYTp0Wbr5e1b2D42hGtRAo9cKjmD5c
         WsmPPKJJfgZFTJdP+AAgfc8FP+czcaFM0Y80YY+F5/QOU5ZGx59NPReQUn0zottbZ39O
         7TXyeZbwl0dkjRfOVXvXDgZXhNEgREK0QSUwIrrUc3Q4pfSp5Of/aKKtvGVDC9ot2MoP
         tgtCrJSU0XpY1ksSWaZZ51uIVFLQts61bD4CRiaBf5H1XrvkxOIbMzlalmHYltzinAj5
         fbiFQxVEykXp57rL6uN76hT0ng4UBKj2+hLI55jCk5B8uO6y33FAQ/n2BvoPrRs0fSfV
         ZcVw==
X-Forwarded-Encrypted: i=2; AJvYcCVInn9Wt90gvYc1BLwfrv4PfttufyUHAsLubD+ArX1dGcXe8epXPtdxAp2ZNLYgQU1jIPkctA==@lfdr.de
X-Gm-Message-State: AOJu0YzVwSjJjMDqd9llD8BamSba8twxN30/gF4bsjs8tUnFyKLCnBQ+
	wpXMQ6Biwbg/LFFxIxms/8FUs2lzFKi8d8L73MDjJ1D/KsrPn7so
X-Google-Smtp-Source: AGHT+IFguCLuQhXCZJTqi97A0z1LjELwJDN18aSgTyGf1w8M/V/2quR4F4i2ZTTITTg7PctPL3J1nQ==
X-Received: by 2002:a05:6214:238c:b0:6d8:8390:15db with SMTP id 6a1803df08f44-6dd2331f24emr970076616d6.6.1736244816491;
        Tue, 07 Jan 2025 02:13:36 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:242b:b0:6cb:be88:c825 with SMTP id
 6a1803df08f44-6dd153c23cbls16575936d6.0.-pod-prod-05-us; Tue, 07 Jan 2025
 02:13:35 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCX2cyU4S0eTl1yq3zs6D5EsqUCrNchdNz9yFXePwmr88YbU42HRFnO4rjyPfdxnItdOFjdAc4h63SA=@googlegroups.com
X-Received: by 2002:a05:6122:25db:b0:51b:b750:8303 with SMTP id 71dfb90a1353d-51bb75083dcmr27320972e0c.11.1736244815695;
        Tue, 07 Jan 2025 02:13:35 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1736244815; cv=none;
        d=google.com; s=arc-20240605;
        b=ANOwkcnCU6BLRAcEUjR7HU1Gj15vOlS8m9CaGMZG1MTOKhuq3HscucRQuZGfU3Zt2f
         +MU5qsZ+3wk+QcXrvr8fmfPG2JEnVu+osf7bNtTwRUR/vLZLpeOh2vRM8kVBGAdlTh3b
         NeNbHz0XJOZTXeUe2BVPFZgOF3D1WA2gs9KlSKxTLwxT8aE3uiXrwGZO7eQ19x7c8SnK
         WXcDk3oWHhV2ralmbr4WjfxTa1Tw4WxQw6+S/usmYTC9I8QwDHsPw+egEyV3buPcBcwx
         ZgvB1kI5VAAE/7vAwX62g37DbASNuUVjUikIHqUm87EuWe6kwmsneUg8hgV0pv0aMSGa
         vf/w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=W4S+LpsvsXKg7F5CuXeRv+riltei5CMrS0KTgUvA8Mo=;
        fh=tkbbO5+IlHP+BOWD8Xmnk+1o+V6GjCpufrQ5b9QB670=;
        b=aPgkQ9+apxXtio5bt+lnIKNFMvr/leFs194FUgyaVFUNsK9Rea994N5otyYGYh0wKr
         a9HNddS8Y7LVNoDuAp2T2XgmshgrCFJ8hT3bN4TFVdTR+tQS8/BgG2Ov1Sspo033zVmf
         pBrnLzM86No6vSiwvT9jFvPVcQMPYgiebCMI7alu+Kzmjqgrx3g3pzkj/8XbpcfCeqZN
         IOyteSEtmeMU/w2SoMOmwXa+2WGrlsJ7tTGwcJ3IzaqcVvU4heZBH57HH4CNcHsRqi8g
         s8Xpi4K3CtGyq71fYOJQ6FtrOpWeZw3JLbBQvt4vJBL5Uj0v2KnT9UlYYKo9VR9bZwb+
         d1uQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=BiYnT8H8;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f35 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qv1-xf35.google.com (mail-qv1-xf35.google.com. [2607:f8b0:4864:20::f35])
        by gmr-mx.google.com with ESMTPS id 71dfb90a1353d-51b68b9f29fsi1089074e0c.2.2025.01.07.02.13.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 07 Jan 2025 02:13:35 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f35 as permitted sender) client-ip=2607:f8b0:4864:20::f35;
Received: by mail-qv1-xf35.google.com with SMTP id 6a1803df08f44-6dd16e1cfa1so132337926d6.1
        for <kasan-dev@googlegroups.com>; Tue, 07 Jan 2025 02:13:35 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCWhoqyc0QEIHiSj141ebW7UzQi05k+B8PUa3UEAy7XFEgr9k9/ngnRL3zKafs0NS+SR+idR1Pf9bLU=@googlegroups.com
X-Gm-Gg: ASbGncvdFBUDpTQLq4Po7Eu9N0nrR3H+PTTB1ZBfMnRFs5XW5vh9ZrcBp2HQBeB11Im
	i+d0x9OOPX8frHCX+Ka5/LWwLTEuDELakBrPyAv0Lnv+iMpVGUdhHAXKNF2nW1QiP5uGv
X-Received: by 2002:a05:6214:4187:b0:6d8:a027:9077 with SMTP id
 6a1803df08f44-6dd2331f1dfmr1052106506d6.5.1736244815211; Tue, 07 Jan 2025
 02:13:35 -0800 (PST)
MIME-Version: 1.0
References: <20241220181205.9663-1-dominik.karol.piatkowski@protonmail.com>
In-Reply-To: <20241220181205.9663-1-dominik.karol.piatkowski@protonmail.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 7 Jan 2025 11:12:58 +0100
Message-ID: <CAG_fn=U83cywRB4BypuqqKKrb6PCK_tf9bf0uFWCa6O-iXHQ7Q@mail.gmail.com>
Subject: Re: [PATCH RESEND] kasan: Fix typo in kasan_poison_new_object documentation
To: =?UTF-8?Q?Dominik_Karol_Pi=C4=85tkowski?= <dominik.karol.piatkowski@protonmail.com>
Cc: akpm@linux-foundation.org, ryabinin.a.a@gmail.com, andreyknvl@gmail.com, 
	dvyukov@google.com, vincenzo.frascino@arm.com, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=BiYnT8H8;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f35 as
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

On Fri, Dec 20, 2024 at 7:12=E2=80=AFPM Dominik Karol Pi=C4=85tkowski
<dominik.karol.piatkowski@protonmail.com> wrote:
>
> Fix presumed copy-paste typo of kasan_poison_new_object documentation
> referring to kasan_unpoison_new_object.
>
> No functional changes.
>
> Fixes: 1ce9a0523938 ("kasan: rename and document kasan_(un)poison_object_=
data")
> Signed-off-by: Dominik Karol Pi=C4=85tkowski <dominik.karol.piatkowski@pr=
otonmail.com>
> Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>
Reviewed-by: Alexander Potapenko <glider@google.com>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
AG_fn%3DU83cywRB4BypuqqKKrb6PCK_tf9bf0uFWCa6O-iXHQ7Q%40mail.gmail.com.
