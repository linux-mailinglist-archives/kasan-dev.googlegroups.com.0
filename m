Return-Path: <kasan-dev+bncBCCMH5WKTMGRBWUD7PAQMGQEFVOTPII@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63a.google.com (mail-pl1-x63a.google.com [IPv6:2607:f8b0:4864:20::63a])
	by mail.lfdr.de (Postfix) with ESMTPS id AA9A9ACC335
	for <lists+kasan-dev@lfdr.de>; Tue,  3 Jun 2025 11:35:24 +0200 (CEST)
Received: by mail-pl1-x63a.google.com with SMTP id d9443c01a7336-231d13ac4d4sf78092115ad.3
        for <lists+kasan-dev@lfdr.de>; Tue, 03 Jun 2025 02:35:24 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1748943322; cv=pass;
        d=google.com; s=arc-20240605;
        b=XwXcqMEDRr5ItXuPUQ5aJyFefUfwZ491n77h1ozwDfmRdPzsLafuRlYTX7VKWo6ZgU
         0hBQ35PAfOdQnHXYOd5TbjdtVVXUs0ltrYqz6qUAGedTJPGn4b1V230OtNGMNQ2pIyxU
         YsmUanS0oGMy58SF9f3kKBrvHFF2V81BqktjKmLXWNcOKNbsbPvn32UhX8IWGXYI9pKw
         17DlzvAMCs4/nprWZbzcTMOHdGag7jqMXRhivgcKGY/SpcmCkQjn1f43FiBxoA8QWEmm
         2L7WoSWjpl0PLWvo4o+IuGLsorQ48nQ7x82/htAnHgFPP0F52ntAXX9nooou8aeQpahJ
         aICA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=MiAKxLDQwkEDE+q3b1gatFfFrlyACmawG5sNlNFIVJU=;
        fh=Z44bLGUYMH0Dscr22ZoI/xyHeMEESgE3Smz+lI6cldw=;
        b=eYbXy9/lzNmltaN1rRfC48nOTCieWeh0RQtXCRlhT6N+IVHm0kp71Zl2QsxgtODleU
         TTOS1CAsB4+WUxW1AnMd69HppRzLCS6shP6jros5nbEbhx1+odg0buhQ2kFtQ2nqgGqC
         /xfHRRy59aOtn/G5q7nOWk8/NWR3MIEyywOeXsIWeskk2EyErqHTVSnan/4Azapw34zd
         TaXsC9wyZhvJ6XIr6wh7yQcCQiYSUxKCLo9oNN2Ry+NPXDfxzkzx3matZEJhBhHnvFjj
         0yXR7NQJ9JzjSiKJkHLYuQTPjmwtdnRuKwdB0QfgXuh5TQSYnadwa1qV5Eg5lUhaU9UL
         cuuQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="GASlZH/U";
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::736 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1748943322; x=1749548122; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=MiAKxLDQwkEDE+q3b1gatFfFrlyACmawG5sNlNFIVJU=;
        b=tEC/4fR+idw1cAbP2h703kR7MTeszAeWKMBHh6IURO/vFv6EgdbRZ4ZbO86f4XyfIR
         USELO6iZj36uTNs+QVS47hGhagIh09Wdy4Ap2i3ZdYx28nktQHoN/JGVEhsMbmWGOdlI
         IVOzc/soqQVn39KsbKqe6qWuyThlszHI7arEMmc6Xw3kvMJaEKFSeScoAKBbByHbOJA4
         Ez8wuiou7m9GwN7Pdisrt5Qwqvww5eFrynxaAa4/zaZ19bQLbu+zzJvNFLHbvpagF1Kr
         DPXWYMFMlGtB/DomioWhIjs4rqQWqo9SZOyjw5sAlQfoqlsWI/5kVbxBKxQlBgFRqKVx
         KCnw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1748943322; x=1749548122;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=MiAKxLDQwkEDE+q3b1gatFfFrlyACmawG5sNlNFIVJU=;
        b=rtxdVYyELKbz4//XPkG0ECGIhXrA3SF689Ma7bJvx5yURYrDLQbqqsh1zPPVTHbPKE
         jlTBTVlEQhdfs8fe1ZIphZiAKeNfJpfCRARnVgf5R6tnWm6KSuMYb+7pY00uB3dFRHKy
         hSA+UiaVUFdiDxvQWQ5lmo7RYJyLT6w79LJWZP7HnxQM9NMhzVW0T/uOhvMQTc73xYwV
         dX54cHh5fMmL/3aZMTM9+Nw/NqoSBGBIMt56RMaOF9FNqDmrLUB3kRJ+hmDzV22Nrm53
         8F7aK4IRQpMhSiaoIToAYx3mWOpB2qQ3GmB5N4UvP3BJjVjg9tZr3aJAkz16irDqStot
         IvHw==
X-Forwarded-Encrypted: i=2; AJvYcCXoXJ2RE2bt77ECWhyV9C3JvgxUgZl4Hyh1CkYnrmHZ1e/D94S0K0jGW43h6OiVMTFkmtIGxA==@lfdr.de
X-Gm-Message-State: AOJu0Yz3zVUZFJ8wpQQWE+ja/saDaU3iiZOOrFJezjU32Ep8cJVsFbMu
	VuH2dpmiDIfNkcnwpNiwM7Sw8VcHxgTGDPpz0Q2CDztbZktONdncfkOC
X-Google-Smtp-Source: AGHT+IHDnfv/Zw4+6dEC6gDkFqmz/tkCLfOJmINNmAkYJiHYpXlVWzP4QvQ1xibfOVoEoixxGCdl8A==
X-Received: by 2002:a17:903:1a45:b0:223:619e:71da with SMTP id d9443c01a7336-2355fa003f2mr181183695ad.49.1748943322443;
        Tue, 03 Jun 2025 02:35:22 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcsoGGJZOFxLT3QeSeiw5M8HpvqIUlIa6yn4pU0x0on9Q==
Received: by 2002:a17:90b:fc3:b0:311:dec0:b0bb with SMTP id
 98e67ed59e1d1-312150a507bls4960594a91.2.-pod-prod-08-us; Tue, 03 Jun 2025
 02:35:21 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXmpuC4S5rv+yuD/Vw5Nvfa96g3wNahlxNgG6eGVoPmN6dRnMrguPx5HFNRBJIf4H39TJdD4NITSVE=@googlegroups.com
X-Received: by 2002:a17:90a:ec8d:b0:312:1e41:3a58 with SMTP id 98e67ed59e1d1-3127c871ca7mr15124207a91.34.1748943321149;
        Tue, 03 Jun 2025 02:35:21 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1748943321; cv=none;
        d=google.com; s=arc-20240605;
        b=KeIIeanV0JR/nLgHgFKDZM0eLFEnuZ4JmkfbgLzj7UKY5TPWff7qkfYNKDRIrO3a6p
         Sf7Q8X7tKrZdj3QnYfRr8+3oljgouP8r3uiTyiZZz6ip1VKpY8U89G6tmA34U1Y4Xjtn
         Wr0Z5TRLaak81XL6dvavP71TKgig6sfZKRfAScEyZ6K6A8oruqqZO6hVvWIvZGt4Ic/u
         TbH8A3Q8RgUdjl2LtCzzZZ5O1qQGNKKsZ079eHJ9gCSycwXqOJNQB+7MNzpeGxFFhusx
         c9AlTs/u2SfngAvsNTVDSx9ozkrlNUeLIQm6bjnkcSBZ2LQMWEySizdct/Z/oCh7MTF/
         jP4Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=HiHVn8KM1a38CHqKEjF7hCVjdYq1SEXILXEyXKXUsj4=;
        fh=CzBMaN1pxnel+Aley1oTZLwtbmb3mmWBxz9Ubwoer/w=;
        b=LrnAOrYFx/idHu1CaUgm3rg4PCmK5reh5zeXIOaSM2ig+p8Th97SPPEbxtnHlADBEb
         rH5e7dn4FTUyhbC2c/vNmqGNyrTPdxv+y/QDQVNOMVt4FetPr2gGIk828B6f5KcrpP/q
         d7reb6DljXs3GwWmIHAxkspOWv1bLai61mL+pMQMRUrv2Lx+OMeXiiUtfx0lzlW9Ei3W
         s+xWZeYiN/KIFZH9EZ2PVfPr7TeO4HSyrQ1Wf9UwANHM3EO6+6QlFrUhZsbrejIYGFZR
         hF6SRG+qKwEDIUX/AS3qmv/kXoBebQr0pdcXHp8IRSE2UmO0iwYJPoT2R6defRkFJxX5
         1QYA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="GASlZH/U";
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::736 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qk1-x736.google.com (mail-qk1-x736.google.com. [2607:f8b0:4864:20::736])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-3124e2c5922si357708a91.2.2025.06.03.02.35.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 03 Jun 2025 02:35:21 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::736 as permitted sender) client-ip=2607:f8b0:4864:20::736;
Received: by mail-qk1-x736.google.com with SMTP id af79cd13be357-7d09b0a5050so315681585a.3
        for <kasan-dev@googlegroups.com>; Tue, 03 Jun 2025 02:35:21 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXlETyYrB0IgPV6VkausghOLzwXTI+iriCydaK5yfkuulyavQJNXdJwtFwy0jfqpzFwY1BHfxGKI7I=@googlegroups.com
X-Gm-Gg: ASbGnct62OduVWuKjUR7YieDEYsSDTBUoU2PSCiGmwJsBk4dfW0mdRa8jDxa14mk8vl
	r3kHSKpmv95klUkYN7m+/7jMeNF0BeXSH42UtFqYNuQIeXru0OkyQuFLfsoz+uAMfVB6+NB78Lj
	CLdTH8HAwvrcRBQAefvfmhG0AjL7t7lRmxQKV5qBiATNUr8x8wsqGnc6/iSeHD9pe+kSAau62H
X-Received: by 2002:a05:620a:278c:b0:7d2:1504:f6cc with SMTP id
 af79cd13be357-7d21504f985mr138275685a.56.1748943320043; Tue, 03 Jun 2025
 02:35:20 -0700 (PDT)
MIME-Version: 1.0
References: <20250603075323.1839608-1-arnd@kernel.org>
In-Reply-To: <20250603075323.1839608-1-arnd@kernel.org>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 3 Jun 2025 11:34:43 +0200
X-Gm-Features: AX0GCFtk4x4wNn6b7UP0VNv0sOlQbYFq-yDz0olLoxl5nq3NojRVUcRiaes1dx8
Message-ID: <CAG_fn=U38uPLKbg6_VArW1k3DGm8VDehdY0fArsqJ75WNuku9Q@mail.gmail.com>
Subject: Re: [PATCH] kmsan: test: add module description
To: Arnd Bergmann <arnd@kernel.org>
Cc: Andrew Morton <akpm@linux-foundation.org>, Arnd Bergmann <arnd@arndb.de>, 
	Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Sabyrzhan Tasbolatov <snovitoll@gmail.com>, kasan-dev@googlegroups.com, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b="GASlZH/U";       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::736 as
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

On Tue, Jun 3, 2025 at 9:54=E2=80=AFAM 'Arnd Bergmann' via kasan-dev
<kasan-dev@googlegroups.com> wrote:
>
> From: Arnd Bergmann <arnd@arndb.de>
>
> Every module should have a description, and kbuild now warns for those
> that don't.

Thanks!
>
> WARNING: modpost: missing MODULE_DESCRIPTION() in mm/kmsan/kmsan_test.o
>
> Signed-off-by: Arnd Bergmann <arnd@arndb.de>
Reviewed-by: Alexander Potapenko <glider@google.com>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
AG_fn%3DU38uPLKbg6_VArW1k3DGm8VDehdY0fArsqJ75WNuku9Q%40mail.gmail.com.
