Return-Path: <kasan-dev+bncBDY3NC743AGBB4NS2GVAMGQEVUGHEPA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3d.google.com (mail-oo1-xc3d.google.com [IPv6:2607:f8b0:4864:20::c3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 853487EBCCB
	for <lists+kasan-dev@lfdr.de>; Wed, 15 Nov 2023 06:38:59 +0100 (CET)
Received: by mail-oo1-xc3d.google.com with SMTP id 006d021491bc7-589ce3eb26csf6035744eaf.2
        for <lists+kasan-dev@lfdr.de>; Tue, 14 Nov 2023 21:38:59 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1700026738; cv=pass;
        d=google.com; s=arc-20160816;
        b=wyKtdfWKd4Hb+TkLRVxeCzii7zrWFOHs0qd4WPzYDJJOBphJF4dtO05tMs367eiEVz
         YcKt5N0s7OhBwQ24B3ayhinvdhnVi907Df7yOtiX9eoFeRtc/hfwqe5XjXO0Irdp9Std
         epLe8UB1zUFZ1ov1SVvSZrs6XuUPKHkw29J4mtF+faV1MWFX/mLAQD4q/Hp1sC8vpf3U
         eJL8mwglEy2vT7foXvTx9OGb5YaOOfc7egtZxw4CNK/u1ftiBkZe7QQOQTwOfc8MUVdY
         Sy2dYLMIREx2QoSI6PeYusCa3V7pnPWDpC/9Tvb5p/Oncp5g706d7ElOT4WqJakffVV6
         fhag==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:user-agent:references
         :in-reply-to:date:cc:to:from:subject:message-id:sender
         :dkim-signature;
        bh=y/ZqA0u9+sSHEt++sI2UXhAFxtqNXD/vDriIaEIaB/U=;
        fh=Xslw8xe6ZI6W7qLy/yctDADjYiBzbqRh3LeSeGN5b5I=;
        b=CjGM2Cq4id/0/f63bOr/iFMPhUwE1SWWVEtOnD140wFLavsImWWGkCEaNRhEKF8k29
         SNvUvugUiB5Sqq7bTXXyvVdGddnIpaYnpEzqwccpbqseGgtoWOXkVGfrKY1jkuhPrgDM
         CWUi+4CX9O2THAs239f9uXx97GRmK0lG6gNXQ55tlknhKtQvNU7bcdlyo/pELDFsom5z
         Nz+fe4Ysa6sQ5MTi6KglIsvHomfM8xCwl9BjrdvLqTM5AvpI8tRfUrWLvDBl0IPo6olq
         MKW4IdZvyJ/QiNOGSoWOUJRdRnJybdfksOoyBz4qaxjtjgwBCdkFeln5XIbdXAarLWm8
         gAcg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of joe@perches.com designates 216.40.44.16 as permitted sender) smtp.mailfrom=joe@perches.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1700026738; x=1700631538; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:user-agent:references:in-reply-to
         :date:cc:to:from:subject:message-id:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=y/ZqA0u9+sSHEt++sI2UXhAFxtqNXD/vDriIaEIaB/U=;
        b=oEJ9ZMkMS20Sr4+p2CvXFjAKtuY/Dk/XfD7H/4x/5w4BSMnQ4MpA459IRRjfQRplXW
         rr9xuuuOMPPRUji3d4NHJDivVNyFpTlCUI5iikzeRYrKbPlYn4tUtYdMOKxNGlz46ctQ
         FCL0Qy99q1lLYzzrgEAaG5lF2I7nkf5xcJ4BA4QdOm6IvzUcrpzpR4b+oY8UNTx32b4M
         nbXI6YvH/DIQV5Bcm6mG6kEeh56/zelC58o57EI2N+ZGtkFybcRbyybs6s8mATPujE2f
         fk+v1kjpXMCToFRwAUXuFR+tFWpsMNhIcViXb7/3JLdTgAB2PYNxz8uXVdYJuDQ9y9t0
         Bozg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1700026738; x=1700631538;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :user-agent:references:in-reply-to:date:cc:to:from:subject
         :message-id:x-beenthere:x-gm-message-state:sender:from:to:cc:subject
         :date:message-id:reply-to;
        bh=y/ZqA0u9+sSHEt++sI2UXhAFxtqNXD/vDriIaEIaB/U=;
        b=A+KItTh1fP2bl9529nIuiB0bsPdH4ZsysIbABSKiZz9bjUZZmGV/qNiJ1qDHbu5DXy
         VR2epfECe+kJl1/A7w1QSYeyxuI+lJNJ5CtTABPGjCvX+zdlw9nsT3I5gESAbEx+c0Wc
         oJacF4UTVRvgvaldLKTOmaSyP6uRJVOpQM+WGFCuUITuRc5AvljC6WGBWQFmF04RZwsD
         +B7iOldIdQMwIASHOPzgOl5PerROU6tS+huM5revL1Oru48m9TLzw9F1vufQgiwZMiql
         Iwi2pzP8rxZIBronfNRBadKambuddf9X/jQ859/UgLnqWuzkAFqVwbLN3Ycja9PD8lpg
         vYGg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Ywm6JUIfgDDIlFMCHWa45fUknweKI045RVQmUDk8n+iQX2PSko6
	cFV70TyrbHThhWA2C0X7QzA=
X-Google-Smtp-Source: AGHT+IGH12R3DPr3BAOUNqtJSLF5epABVATT612wV6vS3/czyDZusEZGJKvGK8+opnP566DHbOXK4A==
X-Received: by 2002:a05:6820:2707:b0:58a:703e:fbf5 with SMTP id db7-20020a056820270700b0058a703efbf5mr4523047oob.5.1700026737946;
        Tue, 14 Nov 2023 21:38:57 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:5896:0:b0:58a:74b0:573c with SMTP id f144-20020a4a5896000000b0058a74b0573cls1164412oob.1.-pod-prod-05-us;
 Tue, 14 Nov 2023 21:38:57 -0800 (PST)
X-Received: by 2002:a54:4503:0:b0:3ab:84f0:b49d with SMTP id l3-20020a544503000000b003ab84f0b49dmr13962193oil.3.1700026736961;
        Tue, 14 Nov 2023 21:38:56 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1700026736; cv=none;
        d=google.com; s=arc-20160816;
        b=GZXFHP5WSRBP1ZZzAe5MjBN1lIHJclzjYXozXOrFCoVHiHPmz0JhZEwGkhTQAtZt90
         sajCQc80EkQ8QZszOntDshxjjTB73q+ItrLZntW5rujMvae4A+SG8mtlM9uh9ufxR1/X
         oYl9YWRHBTtTLTsAlklVHkKwXUA8ZlIPGQGCQBHlyyxONmQ8AZYlXi2wvRevmkUT/fp2
         RY0CUnQNejkbdDhH9909amVbJrm+ieNAJN6M58yPaEushPxvbK0DRbLIJqlO1xkUC0Bf
         viKMXY1xh1hZORnw6fpFiZ6d5YWxE7+1sIGANu3OzJ7bC1399Pb02vTyb5Ybj47qliwb
         u3ow==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:user-agent:content-transfer-encoding:references
         :in-reply-to:date:cc:to:from:subject:message-id;
        bh=ZjIaKiOElw59QE5VcsYavNSNHKEVOXO/Tp/yUXXH7jM=;
        fh=Xslw8xe6ZI6W7qLy/yctDADjYiBzbqRh3LeSeGN5b5I=;
        b=JwapJnGIYfHSgGL5SiWBU74I4uGyzqlyDEw6NK9fwNNc9C2fUPvz1us9bVZtQGVejD
         KUiE+ngWS4tjf9uRtHK2Wzm3LdqFpi2Djr0Q+a/+4r6VoHiUHRhjbFNqzrPL/onh9QeJ
         4GMEOv0j3m6TKD2oNsbkikP6zDCyuJ1Q5GTzSgazQYMu/0h96dsgJg2xmvqFYnTzMTGT
         TjsxVrvjCCVakC9c86eNkXi83jwotWg3yKnjT2OVIce1lWe6C9Vv1QT14XrD/8nFXa0/
         f0LvKq3wGmDHY/g57hzXQfvUcAMtrRGLfR3ZDX15nvzd4mR2cJkIbdGFJucVGWhz/79a
         g5DA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of joe@perches.com designates 216.40.44.16 as permitted sender) smtp.mailfrom=joe@perches.com
Received: from relay.hostedemail.com (smtprelay0016.hostedemail.com. [216.40.44.16])
        by gmr-mx.google.com with ESMTPS id u11-20020a056a00098b00b00690d911f63fsi475452pfg.4.2023.11.14.21.38.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 14 Nov 2023 21:38:56 -0800 (PST)
Received-SPF: pass (google.com: domain of joe@perches.com designates 216.40.44.16 as permitted sender) client-ip=216.40.44.16;
Received: from omf19.hostedemail.com (a10.router.float.18 [10.200.18.1])
	by unirelay06.hostedemail.com (Postfix) with ESMTP id AA08BB5DB9;
	Wed, 15 Nov 2023 05:38:54 +0000 (UTC)
Received: from [HIDDEN] (Authenticated sender: joe@perches.com) by omf19.hostedemail.com (Postfix) with ESMTPA id C817E20027;
	Wed, 15 Nov 2023 05:38:51 +0000 (UTC)
Message-ID: <918c3ff64f352427731104c5275786c815b860d9.camel@perches.com>
Subject: Re: [PATCH] kasan: default to inline instrumentation
From: Joe Perches <joe@perches.com>
To: Andrew Morton <akpm@linux-foundation.org>, Marco Elver <elver@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>, Paul
	=?ISO-8859-1?Q?Heidekr=FCger?=
	 <paul.heidekrueger@tum.de>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Alexander Potapenko
	 <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino
	 <vincenzo.frascino@arm.com>, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org
Date: Tue, 14 Nov 2023 21:38:50 -0800
In-Reply-To: <20231114151128.929a688ad48cd06781beb6e5@linux-foundation.org>
References: <20231109155101.186028-1-paul.heidekrueger@tum.de>
	 <CA+fCnZcMY_z6nOVBR73cgB6P9Kd3VHn8Xwi8m9W4dV-Y4UR-Yw@mail.gmail.com>
	 <CANpmjNNQP5A0Yzv-pSCZyJ3cqEXGRc3x7uzFOxdsVREkHmRjWQ@mail.gmail.com>
	 <20231114151128.929a688ad48cd06781beb6e5@linux-foundation.org>
Content-Type: text/plain; charset="UTF-8"
User-Agent: Evolution 3.48.4 (3.48.4-1.fc38)
MIME-Version: 1.0
X-Rspamd-Queue-Id: C817E20027
X-Spam-Status: No, score=0.95
X-Stat-Signature: ci149tmxg7ynwwbqxitaxzaddtdefgft
X-Rspamd-Server: rspamout08
X-Session-Marker: 6A6F6540706572636865732E636F6D
X-Session-ID: U2FsdGVkX1+fwTSWmNgrcNTJZaKLozXEV3IPMeeU9UY=
X-HE-Tag: 1700026731-843050
X-HE-Meta: U2FsdGVkX1+caAPtzwnqvBR+2LKczFrolduz4aRhs8OeGmb8crQA/jnrIxMEPLomnp/ciubtECf+tC0J9Hxkm5F65pHJzKaur0uu+wBM+bWZJWfZUTIKBXJaLp48fS6vmPxp6yOXzRFGV3H7fVgUiVXn+qPW/Lzz3w/e1hkJTjt52NSDxv/G5fh8SlnVZ/6nUfhgpdM4NQtcfGAyZSY5NSkgD+3L+gHyxjarU/SnEdjGngkUhZVftUMqElPxTv/ckJ52HpE3mkDMlVznP7NmAV9H08tkU8WXSVkWKZpMMZgmBtg009HHH3X8Dk9HlM901TYzxcHzi9i4pOn2VYo7KC7SETZOTMTbg7HqmNDgOWgsFlBYifaImDPmxDCyv2i6cjI8NQuwt9FsughtfFgAY/QAssjf5JW1fv5PIsKE3tOHACYWhuIzGLRklExWgtv+VuKvxmGxrYW71SmqK0JMDw==
X-Original-Sender: joe@perches.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of joe@perches.com designates 216.40.44.16 as permitted
 sender) smtp.mailfrom=joe@perches.com
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

On Tue, 2023-11-14 at 15:11 -0800, Andrew Morton wrote:
> On Tue, 14 Nov 2023 12:00:49 +0100 Marco Elver <elver@google.com> wrote:
> 
> > +Cc Andrew (get_maintainers.pl doesn't add Andrew automatically for
> > KASAN sources in lib/)
> 
> Did I do this right?
> 
> 
> From: Andrew Morton <akpm@linux-foundation.org>
> Subject: MAINTAINERS: add Andrew Morton for lib/*
> Date: Tue Nov 14 03:02:04 PM PST 2023
> 
> Add myself as the fallthough maintainer for material under lib/
> 
> Signed-off-by: Andrew Morton <akpm@linux-foundation.org>
> ---
> 
>  MAINTAINERS |    7 +++++++
>  1 file changed, 7 insertions(+)
> 
> --- a/MAINTAINERS~a
> +++ a/MAINTAINERS
> @@ -12209,6 +12209,13 @@ F:	include/linux/nd.h
>  F:	include/uapi/linux/ndctl.h
>  F:	tools/testing/nvdimm/
>  
> +LIBRARY CODE
> +M:	Andrew Morton <akpm@linux-foundation.org>
> +L:	linux-kernel@vger.kernel.org
> +S:	Supported

Dunno.

There are a lot of already specifically maintained or
supported files in lib/

Maybe be a reviewer?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/918c3ff64f352427731104c5275786c815b860d9.camel%40perches.com.
