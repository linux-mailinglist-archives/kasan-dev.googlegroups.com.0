Return-Path: <kasan-dev+bncBDLNDJMHSEARBGUZZPBQMGQE7NXJCYA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf40.google.com (mail-qv1-xf40.google.com [IPv6:2607:f8b0:4864:20::f40])
	by mail.lfdr.de (Postfix) with ESMTPS id 4F85CB02D00
	for <lists+kasan-dev@lfdr.de>; Sat, 12 Jul 2025 22:59:08 +0200 (CEST)
Received: by mail-qv1-xf40.google.com with SMTP id 6a1803df08f44-6fb01bb5d9asf45943176d6.3
        for <lists+kasan-dev@lfdr.de>; Sat, 12 Jul 2025 13:59:08 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1752353947; cv=pass;
        d=google.com; s=arc-20240605;
        b=BpyTJaBh9VD0fR6Ux8CoJWq490E9qADZPkSDio7/JqB022Jhx7vfkZzFdh8YEkjtI2
         I2JeVESShSv8Ab+FXizGbLmlLyRrOGMiA920e5liUvMCuAJ9N6pQ+kSAev2O1c6y3yX/
         Wteb/9SYXrmW0/WL6MS1GRTB17w6Psn83k9TVnPRRclm9gEDnqx2omTWY5/c5RVccIG/
         R2lFlwnjdaRpgMojwSv9v9Vjrg+0CqHmgxScbWq8M91vrXbWg+1uRySJgVFwASOF+WBF
         /UzCPOHD0tKNAxTuqLopZ3pYkGbXdAyo0lNzuijNKr7m/tasFACSp3bUwY99Jp/bf9AG
         4Atg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=tQicteVkfnScsEC9OiZ1lVnCxfmn2mnCANKw8A8L4OM=;
        fh=mThSE2Q+8MW2Qv346MiDLRIxtY2TnVet8nTIBf8HLuc=;
        b=Oq7IGOKXfX4XxnsVHucUK6s/cIzVeOh/DRbrsyyU9PCY0T5bHUhiJMs/KqaSpNR6pY
         KPhIw9UYCzph1yW4aOrbsNp0m5k17/oytODCjSNRO248C+T8ywwxG6UcQs/SsXtrxWYF
         P6sATr12eZo1rW6QMTuKSyvsxZrnWxxPFScZgawDnU5ek12qishgTo4lbR8qohfBJNLr
         y7PRQuYhq4nyZzASO/TjsJu3VzlfJEFuN5zqHfxlhFGILqFhjNSJ40InUmx0sfU35ZMQ
         Alblea3dPY/BB9A2Ma/EYe379dhBE4ovHw1P65TsIGZj/l30/MGW1yfvg8QnTKxPq/yS
         K+JQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=emoxDXzI;
       spf=pass (google.com: domain of chris.bazley.wg14@gmail.com designates 2607:f8b0:4864:20::52d as permitted sender) smtp.mailfrom=chris.bazley.wg14@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1752353947; x=1752958747; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=tQicteVkfnScsEC9OiZ1lVnCxfmn2mnCANKw8A8L4OM=;
        b=r/CkJW6Ep3Y55mVlTKdEZVsEbBoLuzb1k8s7LH+u82bQhEPhbIkxfMRk27Yyz/G50v
         AGPdO9G5FdidAoq+tH20ZsMie/yJEBIkuJnl+0yvFwZZApnoWk8ECXv63C4cwMJQ9NS5
         GyThhn3bU71dv3hobIh1YzlSoeXn6r4p7EBXF19MXJPVlgkraVTL2I7+1tq8HpnwjJRn
         4/z5jz4puSL6LJgN1VdHsFOV1UqkfIhPyRBCtYlYWiv8df10Jzw4kdV3utElF7RpglV/
         5ipZQpIS4Q41Vj1ufODKClK3H6fxyafX5pmWyKnjv0SEj38ClPlMENhNl0cFqxqlLECQ
         tJNQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1752353947; x=1752958747; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=tQicteVkfnScsEC9OiZ1lVnCxfmn2mnCANKw8A8L4OM=;
        b=ESS7loOKgTg4cH6vyvpB3TIWoKGeBKbxTwz4LFLQDmDJ/mfxXl1+P9ZiXsPBuehq5B
         z+iP+mYZaM8ptEAak4tJbz9U9mNeSzjmZXFUI60L+jtWq/ts9V/fhaknSUMqq9bT/hab
         vOJWt/iQUoJYPeuybmKKoC6TSQ2vEVShhD7xPEJx+s4BJzGYif/vNdn+gTN+sfnyXOd4
         SqqQvSlYAlQtEx5gKPkpvWXuAdiSScDc/dgxgMBeSfTrFRxQ3QH+nQBEBx/OA7d13CGP
         a0/ZBuZTUIIspErOlx/orS2DwNv08AjICQBPdeAMZ4OX9pHsTL0sbDZKs8P52zr4Fn+a
         WT6w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1752353947; x=1752958747;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=tQicteVkfnScsEC9OiZ1lVnCxfmn2mnCANKw8A8L4OM=;
        b=XqNmSiX+4e/LZmzDaipjMauMsqj5GnE6ipzIIEwTZexY/3ZyZ6Tw8zA5pX5rvpmIGv
         4v86xi92PQxnJ9lufr88M83PDlPfX8B14toCkLQUR4I1XxQ58q5+4bGrG2b/8fGNiLY6
         d814R7xzUKoM62ZXLDmq8+TQvUDGO7Obfw0y9Mxzs73EiNH7+IX/Nc4RyvoZLwcJ3IXi
         wq4lCo3h7stVCAOPqf7ZdsawVtouW0fL2BMl062+/g0Ke+581vxgQt9GP7s3JrVRFaaa
         rkiMTgzP5rEZN9BmAjp2uqYBklu1ZeskRJb7F6W20Fo3n1NgcCNzg57SVo9CZ9Klh6ze
         j18g==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWPVjSuCl5iCfLgFhssA1UxaT60iY6WjUjVoIuDbn4EuWFeEVyYR2W6iHQIkyibl1XEYK84og==@lfdr.de
X-Gm-Message-State: AOJu0Yzh0i8ruWzV0+1nVDX4yqvOtVHAMAs+VtKXfVZ/gBydRj+U1ffy
	WJdwEb1bM8O8w2k+Xz920/vdq+sAMqKbqyD2toJbdu3I6+12GOj5HpqA
X-Google-Smtp-Source: AGHT+IEpuHhZX8LFvIsGEjcnRVlsUaX5SF+oRr1Y06+o+AYbL2XeQu45+pKJ2KvbXaSJ5YSmfpWOiw==
X-Received: by 2002:a05:6214:5d01:b0:704:7e40:dfe4 with SMTP id 6a1803df08f44-704a6f269d1mr142083066d6.14.1752353946874;
        Sat, 12 Jul 2025 13:59:06 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZe4oq8PTdaGdlx5eADvEi9DZvLrUzL6DWbudTIT9DkXsg==
Received: by 2002:ad4:574e:0:b0:6fa:fb65:95dc with SMTP id 6a1803df08f44-704956cfa66ls53951976d6.1.-pod-prod-01-us;
 Sat, 12 Jul 2025 13:59:05 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCV4u+j6EHEV7TWTFAc8qK1xsZlrDJ03dKm1CLvJsYrkn6otAE/Ks6ONg8x78WsBKBn3iIVTpGfM9/E=@googlegroups.com
X-Received: by 2002:a05:6214:2345:b0:703:d091:d941 with SMTP id 6a1803df08f44-704a709d914mr123292336d6.45.1752353945576;
        Sat, 12 Jul 2025 13:59:05 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1752353945; cv=none;
        d=google.com; s=arc-20240605;
        b=i7zDpppENKWiIUCRH4TTj+mtYbuBOYgReMkWVNPgH1uGAou9nMGN7VylkmE+Wjs6Ns
         IJ9wvo2E/3AHTdbej7BGI4q+zY3UmVcZa5o7is+MrKchM9f/e9eHy/JC8RpP4+34W2Du
         gkWGe6Q201aUsianulEdBpJct2xLTQWo4Boy2raaZQzQ8pn61nSdxcagEpn+AAwGwbFp
         XMYX8QLhLSxzGPj6lLgGPXozVja1xPkVgqaRJYa6QYMzAFeO4voZGRMxIuXItaHoF0P0
         6/ay4wFS+bwxeUfRfvkoRL7jJ9bv9p7GWb6WV6TkwTz98IuxT0AeZME7E/Qm9z8ftG0h
         9qOw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=1ZuS0G5loQ6VTp2rtwXZCwwcpkBS4A9zfG+scNKGaJg=;
        fh=2BYlqV3SiG0Hh5xt+PDCtJ86wOBjxCMIB/DjFRqlmbc=;
        b=Xc3E8hclW5PLyFZz0ewrXqExEx4GInf1hEUqPdC6hoHUkVq7CFmmQ9hnN6E+wnbDzP
         Q47cr/wKm9Zte8kvgUByw0YK0Yfe0UevzJRgFx5AQvkNuLSCh5DuOeykk4Jo91rAoLUK
         cHyeYz3by0YAPvoUK6VbFm4FujWs2VdALJ/zZT4xlI2IRe+pYxLITHC3+jRcJF3rhrfQ
         74tMWrxJfoqQkj+rjkAvFGJA+f/oGW/VC3q4AOi67N1Qo3p+DyaZdZFl4+vTLWophPZf
         gze2Fdab66AS0ZWw7rnjgy4snsrcWAB2oRF1+/F7H/nzCuyFQLxxAsGz4ZQ3e1xYF+pN
         L+9Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=emoxDXzI;
       spf=pass (google.com: domain of chris.bazley.wg14@gmail.com designates 2607:f8b0:4864:20::52d as permitted sender) smtp.mailfrom=chris.bazley.wg14@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pg1-x52d.google.com (mail-pg1-x52d.google.com. [2607:f8b0:4864:20::52d])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-7e192209cccsi3429985a.7.2025.07.12.13.59.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 12 Jul 2025 13:59:05 -0700 (PDT)
Received-SPF: pass (google.com: domain of chris.bazley.wg14@gmail.com designates 2607:f8b0:4864:20::52d as permitted sender) client-ip=2607:f8b0:4864:20::52d;
Received: by mail-pg1-x52d.google.com with SMTP id 41be03b00d2f7-b3bdab4bf19so622312a12.2
        for <kasan-dev@googlegroups.com>; Sat, 12 Jul 2025 13:59:05 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVSgoVmEaNTz3Gg+ePRqYavmbbrm8aD3F3m8CAd4cnodWibf9dsJGM+PvRmNxxPVc7Kg493PuCLg38=@googlegroups.com
X-Gm-Gg: ASbGncsy8t/7PvqGbUdoYiOYOkkHXWrWFNRLV7k46+7EvkIzlPoqvI4kMHbXLeNAlOL
	sVUbCZ5gUPEP63HABYQ+F7S/yUDJ1BAZeAaQDFnoyeSUnkOPnf+gA5wOQIiIJLbN3Ha3gbBxFXt
	X5z3S7lTYlt6Q/T0it1Dz4+5PhZvrkcL8Alo4eNl6zGcjvkB7PYbgsIMmakShhmd8eNJdCWBhYR
	83tRlpk6pdERrQOv8PkUx7pN/oU0qTneIXyY/0KNh2iEYZprFE=
X-Received: by 2002:a17:90b:5804:b0:311:b005:93d4 with SMTP id
 98e67ed59e1d1-31c50e2c50dmr10076417a91.25.1752353944580; Sat, 12 Jul 2025
 13:59:04 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1751862634.git.alx@kernel.org> <033bf00f1fcf808245ae150346019aa7b997ea11.1751862634.git.alx@kernel.org>
 <CAHk-=wh9Pqz07ne9iSt1_v0c14rkOGvF9AbEkaq1KnFhQD1SSA@mail.gmail.com>
In-Reply-To: <CAHk-=wh9Pqz07ne9iSt1_v0c14rkOGvF9AbEkaq1KnFhQD1SSA@mail.gmail.com>
From: Christopher Bazley <chris.bazley.wg14@gmail.com>
Date: Sat, 12 Jul 2025 21:58:53 +0100
X-Gm-Features: Ac12FXzabVR3CNZ1e6s3vvkMYX7Q2knC-RQiMrmuvB567KXzcfJDo2IIzUb977w
Message-ID: <CAEHU8x9UKFWjuE2JPd99CS7wY-x_0kE0k=K3rfYUCJ29uzOSOA@mail.gmail.com>
Subject: Re: [RFC v3 3/7] mm: Use seprintf() instead of less ergonomic APIs
To: Linus Torvalds <torvalds@linux-foundation.org>
Cc: Alejandro Colomar <alx@kernel.org>, linux-mm@kvack.org, linux-hardening@vger.kernel.org, 
	Kees Cook <kees@kernel.org>, shadow <~hallyn/shadow@lists.sr.ht>, 
	linux-kernel@vger.kernel.org, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev@googlegroups.com, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, Christoph Lameter <cl@linux.com>, 
	David Rientjes <rientjes@google.com>, Vlastimil Babka <vbabka@suse.cz>, 
	Roman Gushchin <roman.gushchin@linux.dev>, Harry Yoo <harry.yoo@oracle.com>, 
	Andrew Clayton <andrew@digital-domain.net>, Sven Schnelle <svens@linux.ibm.com>, 
	Heiko Carstens <hca@linux.ibm.com>, Tvrtko Ursulin <tvrtko.ursulin@igalia.com>, 
	"Huang, Ying" <ying.huang@intel.com>, Lee Schermerhorn <lee.schermerhorn@hp.com>, 
	Christophe JAILLET <christophe.jaillet@wanadoo.fr>, Hyeonggon Yoo <42.hyeyoo@gmail.com>, 
	Chao Yu <chao.yu@oppo.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: chris.bazley.wg14@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=emoxDXzI;       spf=pass
 (google.com: domain of chris.bazley.wg14@gmail.com designates
 2607:f8b0:4864:20::52d as permitted sender) smtp.mailfrom=chris.bazley.wg14@gmail.com;
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

Hi Linus,

On Mon, Jul 7, 2025 at 8:17=E2=80=AFPM Linus Torvalds
<torvalds@linux-foundation.org> wrote:
>
> On Sun, 6 Jul 2025 at 22:06, Alejandro Colomar <alx@kernel.org> wrote:
> >
> > -       p +=3D snprintf(p, ID_STR_LENGTH - (p - name), "%07u", s->size)=
;
> > +       p =3D seprintf(p, e, "%07u", s->size);
>
> I am *really* not a fan of introducing yet another random non-standard
> string function.
>
> This 'seprintf' thing really seems to be a completely made-up thing.
> Let's not go there. It just adds more confusion - it may be a simpler
> interface, but it's another cogniitive load thing, and honestly, that
> "beginning and end" interface is not great.
>
> I think we'd be better off with real "character buffer" interfaces,
> and they should be *named* that way, not be yet another "random
> character added to the printf family".

I was really interested to see this comment because I presented a
design for a standard character buffer interface, "strb_t", to WG14 in
summer of 2014. The latest published version of that paper is
https://www.open-std.org/jtc1/sc22/wg14/www/docs/n3306.pdf (very long)
and the slides (which cover most of the important points) are
https://www.open-std.org/jtc1/sc22/wg14/www/docs/n3276.pdf

I contacted you beforehand, for permission to include kasprintf and
kvasprintf in the 'prior art' section of my paper. At the time, you
gave me useful information about the history of those and related
functions. (As an aside, Alejandro has since written a proposal to
standardise a similar function named aprintf, which I support:
https://www.open-std.org/jtc1/sc22/wg14/www/docs/n3630.txt )

Going back to "strb_t", I did not bother you about it again because I
didn't anticipate it being used in kernel space, which has its own
interfaces for most things. I'd be interested to hear what you think
of it though. My intent was to make it impossible to abuse, insofar as
that is possible. That led me to make choices (such as use of an
incomplete struct type) that some might consider strange or
overengineered. I didn't see the point in trying to replace one set of
error-prone functions with another.

Alejandro has put a lot of thought into his proposed seprintf
function, but it still fundamentally relies on the programmer passing
the right arguments and it doesn't seem to extend the functionality of
snprintf in any way that I actually need.

For example, some of my goals for the character buffer interface were:

- A buffer should be specified using a single parameter.
- Impossible to accidentally shallow-copy a buffer instead of copying
a reference to it.
- No aspect of character consumption delegated to character producers, e.g.=
:
  * whether to insert or overwrite.
  * whether to prepend, insert or append.
  * whether to allocate extra storage, and how to do that.
- Minimize the effect of ignoring return values and not require
ubiquitous error-handling.
- Able to put strings directly into a buffer from any source.
- Allow diverse implementations (mostly to allow tailoring to
different platforms).

This small program demonstrates some of those ideas:
https://godbolt.org/z/66Gnre6dx
It uses my ugly hacked-together prototype.

Chris

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
AEHU8x9UKFWjuE2JPd99CS7wY-x_0kE0k%3DK3rfYUCJ29uzOSOA%40mail.gmail.com.
