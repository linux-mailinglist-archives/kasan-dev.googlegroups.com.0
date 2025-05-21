Return-Path: <kasan-dev+bncBCCMH5WKTMGRBTGJW3AQMGQEQREPRPY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x840.google.com (mail-qt1-x840.google.com [IPv6:2607:f8b0:4864:20::840])
	by mail.lfdr.de (Postfix) with ESMTPS id 8C5C6ABF0AA
	for <lists+kasan-dev@lfdr.de>; Wed, 21 May 2025 12:02:53 +0200 (CEST)
Received: by mail-qt1-x840.google.com with SMTP id d75a77b69052e-476870bad3bsf93550861cf.3
        for <lists+kasan-dev@lfdr.de>; Wed, 21 May 2025 03:02:53 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1747821772; cv=pass;
        d=google.com; s=arc-20240605;
        b=hF+B6p16iUIWOVuQDgl0KnILeA3XKhAfSthjdaA9dbeAQDjZ657UJ4BJ9HfXNx0Nqu
         Orz9o4b8DntP9OyaofbI7lqVItz49yBVPptNa7hOv0Gciujc+U7fJXXD0cyC/HzD+pdH
         ec+HYTlkY904ZLvG0/M56o1T9b78zzTG46NDpkJh34T31yMfQ906sVc5h/Fd1PpsXaQR
         j+6JelCEWxRnY9kSlxDBL4O01u4KzQTkrO+H+81+J5Ln2A5WB5gjDB9NP3LVQdbPOwY7
         bi/m/n4J9tozIFgg9p8++oIXfLBv8Ub3l68wGviBB7t1RfiZZBtNNnfVLNDUnhybnYv4
         fuFQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=QzSnSnSC540Dz/qyesoOyCU3zcysBTgmY3cmVC1e7JQ=;
        fh=10axKgEn7kuYwnSEAWKj4IDJu0srd4L8o5tRORw3CKk=;
        b=FQMBFlA6ChybqwR6b+e/W07aW1r/1lwsgz7ySNrOL8v/pYVc1loMY0d1euCiV1L727
         7A+9FnXrKZj5FR9qNQCVbcsYZOMSb43j2B+14d9eCsZlH5lOBGluiqw81PtcaDGApY9O
         GpwIbaNgTtFtqMRBXe0eOkm4uZytK7BxOr+4GnVmuBveJKqQnVmhdDZMNLD9Ioek06F6
         uwoZZBxJXvTDKG/Jx2Tb2rq3YUTRw7qV6LDJuzjvC/kzE/we0FmB5syMrFZ8Ca8eDtk5
         rMWPLKeTyqSx0Wlwj59c1GzEcQrqgyncNbTe5mLInD1SOoh/20K8N4WkbIYzoa1tb/pq
         N14A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=SvEOXi9+;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2b as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1747821772; x=1748426572; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=QzSnSnSC540Dz/qyesoOyCU3zcysBTgmY3cmVC1e7JQ=;
        b=daWX4oSjPJORQ3hVRSy8JrEb2qJAxlzO06GVQjiVKi7DOkp+b1/zcYKSghzoDEuleA
         5Oku5tiumztDfq18NYmkJhKJpV2b1KgjmfDX9VU4JM6Zh28+Y5zyD8SQFXck7L5yVqXh
         SPnnDdE+xg1bR43ZQUJg6sYRnaXHEWwCWJJiAKad1nvOeBfn2FEZSswxrdOzIRtZRK3c
         UMHg738b2h8VMteezLTZ5QtH+BrDUQcBdXYZ73ojDRhPBNUaYAdjnWfZv8e1NTufWX1g
         YDe11Khek5KDq38Y9ObKtxketbPIXs6wgohvSVMLm3Xktr18fBUTXV13enAMUFSa03kz
         m7KA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1747821772; x=1748426572;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=QzSnSnSC540Dz/qyesoOyCU3zcysBTgmY3cmVC1e7JQ=;
        b=ViZeUokEri4lYBrNCzWVabx3WQ4QmGB25sAGrvQnl2zerPzVi5wWogJi099jRuklH1
         Qkt7wkBXtfpztGh5XV/vQ1wfnipBt1gLmKe9f6kpWgbe5PaeujnG7B34031WoOhlPTVy
         TUBzPdZA7hIz+2dq7RCsUg79LAgjU+64d214o3UeVNXvcWyZsKvSuCTQyRfncnFTLrDy
         6dbmdyC1g7JsYLSM67gowW3nyHNlOmolEQl7+PN9dEuPHdL7GZDAbH7apDWAvcYcR8MP
         XIyW1XW/VXBJtJKigMFM5kjl7U6va9YeEqgkX+GlzvmkCLUpYrOcAfOabA8ZPx7crbpG
         jJEw==
X-Forwarded-Encrypted: i=2; AJvYcCUsUdLEReNOKejwbOVnGwZ8R+aOnxOr6HHDUlqVsLboNSjr2HMCs7RTaOJXrx/RPmu7p66X0A==@lfdr.de
X-Gm-Message-State: AOJu0Yyp/dNV0J+/vNOhlOq6S04QAGYaGIkwNrydxEQFwKBhSDxEl/KP
	g6FuO1eEm8mMnBoOWjHG/2DS1PXtGUEN3F2Z00TQ82iD1Und+hWpNU2m
X-Google-Smtp-Source: AGHT+IGLBW20NehVkk47ZbwpV7novuP+43bh/9z3+mQZ9WWsMcEKG+9I6m7ZN6sQnwvUt/1TruOjmQ==
X-Received: by 2002:ac8:5cd0:0:b0:494:a987:8f25 with SMTP id d75a77b69052e-494ae33844fmr338705671cf.4.1747821772157;
        Wed, 21 May 2025 03:02:52 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AVT/gBGieGUQEiXIvNo95KU9sgmq87wi5Xc8Z91QZhTfJMEDOw==
Received: by 2002:ac8:5d91:0:b0:476:8286:80fb with SMTP id d75a77b69052e-494a1445010ls103315691cf.2.-pod-prod-01-us;
 Wed, 21 May 2025 03:02:51 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWuNFCfJKLPvtwBI5MhNEaRrb9vcmkpOXrq/4zcDPn8wbOZTOPVKFiBFX5GLpRG2L5/iXxYIylUw4Y=@googlegroups.com
X-Received: by 2002:a05:620a:201a:b0:7cd:4b5b:a202 with SMTP id af79cd13be357-7cd4b5baa17mr2056226185a.20.1747821771380;
        Wed, 21 May 2025 03:02:51 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1747821771; cv=none;
        d=google.com; s=arc-20240605;
        b=XLAGUTaf9x+wMsSZYR1ZaLTyqCeexHDAA58UIN0OaO4DBP1Kh7cdT5SJvH2YUL6YhH
         exTG0n/X8cn/VX5W1KWdohhWyZlyyBHxlsS/8IE6OtyCACHP8G7z8L6z/GtRrDPWXYQ8
         m9Su/ECGP/PchSNszHQ4Zd2uJ7qeNhHZ0GHnhzV/k5W1EVYmErewOlo2ccdGyB6+zl5/
         ddz6i2jvBnyytetst96I9lOE5lRy+6eUC+tUF0B+L5yP0FMfhALuQ12yoMw/tm74wOLX
         a6WpEq0jciRuEdQotQ9pLYrQTfSEYz9y+dzH0dtOVacOXkjbaeMYpKk4BoNjTH0SkByY
         Wg9A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=hGVCzMZOE97pm/+7xdNe3qSpEf0+u5dNQxNicc26ENo=;
        fh=SYz5tAv9EmTBLwgZy1dR8t426LTIIta9dtCkK9cSQ8E=;
        b=WNuk4iuWI60RguCZ7x/cWj4hI8wNdCTmgPoPj0gfqQBuKxCYsh5DtbFNSvanIiJP2g
         JEyR8fW+nv2EtM1b9sShNIB1GY4q81dkFzT3eyZN7dsSU/vjd3f7PA+pt1HdxfkN6i+X
         gIChgt3gezzA1+1oMZEfOQQO2u6XcCtQKDv3/LQSHx3BbkkT4jErI+R9sdnvfSAUjmk6
         qAMLH/hdA5Y3aX1r3xtOh+62P/YcGzyTghLo0AzLgAjdJ2rY8ewNju49wb0iZRBtLbg0
         V7LBbOb0FRkEn4bOgusJFBfc+J/GMvj0FKe+/7wAjfRH2ZjDNzoWxsY93PSBdbLU/hPc
         zpDg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=SvEOXi9+;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2b as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qv1-xf2b.google.com (mail-qv1-xf2b.google.com. [2607:f8b0:4864:20::f2b])
        by gmr-mx.google.com with ESMTPS id a1e0cc1a2514c-87bec027b89si56403241.0.2025.05.21.03.02.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 21 May 2025 03:02:51 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2b as permitted sender) client-ip=2607:f8b0:4864:20::f2b;
Received: by mail-qv1-xf2b.google.com with SMTP id 6a1803df08f44-6f8ae08e38dso67336366d6.2
        for <kasan-dev@googlegroups.com>; Wed, 21 May 2025 03:02:51 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCULPHNQz3SiW/HAI6Oh9ysVsCJnqeU6sCLCWBUsylfCO7OjHbHlvS7M9reyaDDQCRTkAsFFGZrjAbk=@googlegroups.com
X-Gm-Gg: ASbGncvvhSeKWQ6kUKyBqAKM5/UWIbF601C7ngNxL0uA6aQs9M34EH38knwXDkxOe4r
	aWwDmQ5vqWhHN2Mxa8smOCKWRQxeYWWqyv8gG2ZjVkBakLz7UlYXYtgkY33J4dLnhZG8pvlSMiG
	zJ4wry+yhvq5/R3rE76t2elCSgxbmPkRrT9d8U6w7+IXezf7B7y+hRONpFU6BqtiUeB/4oYQFo
X-Received: by 2002:a05:6214:40b:b0:6df:97a3:5e5a with SMTP id
 6a1803df08f44-6f8b08ceb3amr357793746d6.28.1747821770566; Wed, 21 May 2025
 03:02:50 -0700 (PDT)
MIME-Version: 1.0
References: <20250507133043.61905-1-lukas.bulwahn@redhat.com>
 <20250508164425.GD834338@ax162> <CACT4Y+a=FLk--rrN0TQiKcQ+NjND_vnSRnwrrg1XzAYaUmKxhw@mail.gmail.com>
In-Reply-To: <CACT4Y+a=FLk--rrN0TQiKcQ+NjND_vnSRnwrrg1XzAYaUmKxhw@mail.gmail.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 21 May 2025 12:02:14 +0200
X-Gm-Features: AX0GCFubuxvb81f_x5em7Iy6MU7avDIHjdMdNZqeGYpj71-tqlOCNdY-AOhiHCU
Message-ID: <CAG_fn=XTLcqa8jBTQONNDEWFMJaMTKYO+rxjoWMHESWaYVYbgA@mail.gmail.com>
Subject: Re: [PATCH] Makefile.kcov: apply needed compiler option
 unconditionally in CFLAGS_KCOV
To: Linux Memory Management List <linux-mm@kvack.org>, Andrew Morton <akpm@linux-foundation.org>
Cc: Nathan Chancellor <nathan@kernel.org>, Lukas Bulwahn <lbulwahn@redhat.com>, 
	Masahiro Yamada <masahiroy@kernel.org>, Nicolas Schier <nicolas.schier@linux.dev>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Arnd Bergmann <arnd@arndb.de>, linux-kbuild@vger.kernel.org, 
	kasan-dev@googlegroups.com, kernel-janitors@vger.kernel.org, 
	linux-kernel@vger.kernel.org, Lukas Bulwahn <lukas.bulwahn@redhat.com>, 
	Dmitry Vyukov <dvyukov@google.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=SvEOXi9+;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2b as
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

On Tue, May 20, 2025 at 4:57=E2=80=AFPM 'Dmitry Vyukov' via kasan-dev
<kasan-dev@googlegroups.com> wrote:
>
> On Thu, 8 May 2025 at 18:44, Nathan Chancellor <nathan@kernel.org> wrote:
> >
> > On Wed, May 07, 2025 at 03:30:43PM +0200, Lukas Bulwahn wrote:
> > > From: Lukas Bulwahn <lukas.bulwahn@redhat.com>
> > >
> > > Commit 852faf805539 ("gcc-plugins: remove SANCOV gcc plugin") removes=
 the
> > > config CC_HAS_SANCOV_TRACE_PC, as all supported compilers include the
> > > compiler option '-fsanitize-coverage=3Dtrace-pc' by now.
> > >
> > > The commit however misses the important use of this config option in
> > > Makefile.kcov to add '-fsanitize-coverage=3Dtrace-pc' to CFLAGS_KCOV.
> > > Include the compiler option '-fsanitize-coverage=3Dtrace-pc' uncondit=
ionally
> > > to CFLAGS_KCOV, as all compilers provide that option now.
> > >
> > > Fixes: 852faf805539 ("gcc-plugins: remove SANCOV gcc plugin")
> > > Signed-off-by: Lukas Bulwahn <lukas.bulwahn@redhat.com>
> >
> > Good catch.
> >
> > Reviewed-by: Nathan Chancellor <nathan@kernel.org>
>
> Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
>
> Thanks for fixing this!

@akpm, could you please take this patch at your convenience?

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
AG_fn%3DXTLcqa8jBTQONNDEWFMJaMTKYO%2BrxjoWMHESWaYVYbgA%40mail.gmail.com.
