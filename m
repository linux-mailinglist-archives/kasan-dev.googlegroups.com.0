Return-Path: <kasan-dev+bncBCCMH5WKTMGRBIPN22RQMGQET64KYMI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53b.google.com (mail-ed1-x53b.google.com [IPv6:2a00:1450:4864:20::53b])
	by mail.lfdr.de (Postfix) with ESMTPS id EF9D17158D7
	for <lists+kasan-dev@lfdr.de>; Tue, 30 May 2023 10:41:06 +0200 (CEST)
Received: by mail-ed1-x53b.google.com with SMTP id 4fb4d7f45d1cf-50a16ab50e6sf3444819a12.0
        for <lists+kasan-dev@lfdr.de>; Tue, 30 May 2023 01:41:06 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1685436066; cv=pass;
        d=google.com; s=arc-20160816;
        b=PuYnGs1GvnVtZZoEW589ihiwpA3eQxSahc55wnendwBXw/S5CIRS8enRuImnZesVmI
         T14icJqQdl5DFku3Ul7owgwlxZNmHD+MxqUaurkw5b6/wgahuJHqopuDM1MA0w9ZYFY1
         B+WVHbdo+8T09gJGmk6p2zXD11FtMJGksh2sPx3cUlgYYEdjbvibEavP0E0t7saXoaci
         xDhMEwEWKFkpryJY6DIO7EZQTAKvpuhb5aAjc57LmvEIlgs3MIhBzw7y2ucXlmyUxwtc
         FsNB1+1N1freCHG7AaPKHNJ/gBcwGzJ1lOuvvOUI+D0RTx2mnqYdYlo2u33c6w/AX/Kk
         jFhg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=BdvuFRwX7oZ+OU+eXPbUQT2idixxYDG/pALcRgmoyac=;
        b=fILywI2R8vfuoWIbVkRqqsf0G0acHCOoB/L4121BFrZOfdrLJ/iZrisChSAs0xB0qF
         b+H7cmnvCFBXjp6fK0debe8lMNh5I9iU9Hy7FAFtHEs9GuVF0WvvAO1XvBRprVyAURoX
         VgnEc8iQpAl0Cc2ql6gGjqogyXWQqj3qMe+Cy7OJMkmxIQKkqtRJ7GApVydWU2AZLODt
         9828jI1zO5dJRJC426YqLrBlJ9c+jJXUF6LdLELp8M90zH/IGqsY3zii5mYA+CMl0vKP
         Q9orhAt6sX3XYICgHN5Q3OPt9lnCpRAA3R/+ZxNvyDyx0OJs4wQOpLUGZS7dyCwzjeil
         qs7A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=r2xfxhW6;
       spf=pass (google.com: domain of glider@google.com designates 2a00:1450:4864:20::334 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1685436066; x=1688028066;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=BdvuFRwX7oZ+OU+eXPbUQT2idixxYDG/pALcRgmoyac=;
        b=mI9qnRxXX1ek8gxa+kysH/8a9nozKp+Eve/0IYX7BjRbQ3K5Lf3g0+9aCd6bU6fynV
         I4ft+LA61Bp3H7Iz03SsZOL7U/3ktLPKJHLmK+OFrAPvSOO7j6yaB6DXU+NEmXnN3U1C
         mi2Mk9ONnapa//iExxzf+EjLF57cHg7X6A3V4uFuKfWc19tXHVa54VRUvm5lZZ6+oIwN
         Ti55w/+uWTwTDsz0mfbbO6hPHVCwCxuAuS4Vrcy3MveIpw0qPp7PFKwHwrQGbO1kmcR9
         Z/JgMczBbzJoFEIvbagvtfuPrsEEUnrOCVJjaZZMbhuZ3hQKp42zRUkKfjFaiMYlqULx
         QboQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1685436066; x=1688028066;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=BdvuFRwX7oZ+OU+eXPbUQT2idixxYDG/pALcRgmoyac=;
        b=bCt2Kacr0sfEfu2G4ooQ2iRDMEEa3mfyvMzwfXgBtN/Cq9O7RypwJHTc7GKvKbrDFr
         JqWZH6PG+cEtVS2zsoliOKTu0/CzVmJnoXahVNPvv0LpjCQydYEc9/hIg5t1oSynVcbw
         jEMaVy1MVoZoIOgH3dqc1FxXFf2aetZ5gviTt3ugN78JWwhjgPRRhDDmgnkUL4zkj/BC
         Ysk2k/hQ34mgZobDJCSAQkPWOOmyirsktkWRqq1U1S2n7U0WQPoSnOiyGQ5sF5P7zEnt
         WJs6PpLa/1K+sVMU/vTrnVp95XUY42iAsGF1dGnuKvOXlG0gH2GSzLOl3IRvugwS3pwJ
         YMkA==
X-Gm-Message-State: AC+VfDxMLEmEHn6TA1XHfgqGH5vgIM4BgZYnYv/TXyXmOvBphqd32xIV
	/QFK75Lb5fzdrArY+7YaUnA=
X-Google-Smtp-Source: ACHHUZ5/S6k4wE/Sx1DO9koNspogPqtrYchMaFHnvd1Ur/nSF8zpS/WeC8g9JX2G5WkDGS7WO14Uvg==
X-Received: by 2002:a50:ef01:0:b0:514:75c3:268a with SMTP id m1-20020a50ef01000000b0051475c3268amr1106856eds.28.1685436065621;
        Tue, 30 May 2023 01:41:05 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:ce06:0:b0:514:9bd1:56ca with SMTP id d6-20020aa7ce06000000b005149bd156cals272115edv.0.-pod-prod-09-eu;
 Tue, 30 May 2023 01:41:04 -0700 (PDT)
X-Received: by 2002:a17:907:3da0:b0:974:1e0e:9bd2 with SMTP id he32-20020a1709073da000b009741e0e9bd2mr1711102ejc.14.1685436064303;
        Tue, 30 May 2023 01:41:04 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1685436064; cv=none;
        d=google.com; s=arc-20160816;
        b=zNhAOBXGyB0LsQQ9UqXv4+QlOcpXNKZY+k2tTaQ/rQRGWFJY7py6aTevdQekW+EKNO
         n6sm0gFrHq9erSfqv0lvh9HPqioi5KytJQVZt0zpeuceaWCyneHs1/kAcLZdNHuZsZ1/
         Cy1R7ytZgLR55TClq06qUhw7mLS9u7e1c8QiwbIY8MlZVjaKTEXJOY9hvzbiDLx+TA9O
         oo0TjpQ1d2MmJSNVsDPJcgFG1SJBcNcpqeDdH6CQeGXnc4oli5XqHEH+/wdF3607H5wV
         pF7O2/1edmcY8GTjyr2H/utDzizGdEp7N3+Zla5VnFUER9sZpWABlybOLdexBaNNLyo8
         MBvA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=lFTo/TdSXcdAD7s8nzeXWfL6YJOnEyi31YyJRsIFKlo=;
        b=YchMc6G7w574+dUX2pjXib3kNcbVI3PxCwiIrqT0v+mKGKgB7rkJjAsmsHAc9Umv9h
         xJnGgJDOoacyB03RGKcGI1YCINXlJiiWR0sVtHqKSDJEO3pG2sNrD/zAGLodDNrKUCoe
         pL3u85HluOuBqGPOfBwL4E8mT6ROo2aqAgJRbVxg9IxS8lXMUDq3KLo44TSzKASbAhEH
         +GVSVK1frZLpvTkAqeiaMW/lDUfFraxrJUfY2Ftu026K2zOZfzaLgUTpM5PA0lEfWAaG
         zvwJPnmaK7qHneBzhhv++249VdF5AmAmxgsNBO0w6cgSRk9y+NKjfUOQG2ojTPVSoZzB
         DbmA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=r2xfxhW6;
       spf=pass (google.com: domain of glider@google.com designates 2a00:1450:4864:20::334 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x334.google.com (mail-wm1-x334.google.com. [2a00:1450:4864:20::334])
        by gmr-mx.google.com with ESMTPS id er12-20020a056402448c00b0050bd0abf2b4si638324edb.3.2023.05.30.01.41.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 30 May 2023 01:41:04 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2a00:1450:4864:20::334 as permitted sender) client-ip=2a00:1450:4864:20::334;
Received: by mail-wm1-x334.google.com with SMTP id 5b1f17b1804b1-3f6d3f83d0cso43992765e9.2
        for <kasan-dev@googlegroups.com>; Tue, 30 May 2023 01:41:04 -0700 (PDT)
X-Received: by 2002:a1c:7712:0:b0:3f6:44e:9d8 with SMTP id t18-20020a1c7712000000b003f6044e09d8mr1087598wmi.22.1685436063826;
 Tue, 30 May 2023 01:41:03 -0700 (PDT)
MIME-Version: 1.0
References: <20230530083911.1104336-1-glider@google.com>
In-Reply-To: <20230530083911.1104336-1-glider@google.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 30 May 2023 10:40:26 +0200
Message-ID: <CAG_fn=U67cq4502h2G8kms8r6e=13tn8Ta+QWhA8N6cK-PFyaA@mail.gmail.com>
Subject: Re: [PATCH v2] string: use __builtin_memcpy() in strlcpy/strlcat
To: glider@google.com, andy@kernel.org, akpm@linux-foundation.org
Cc: linux-kernel@vger.kernel.org, linux-mm@kvack.org, elver@google.com, 
	dvyukov@google.com, kasan-dev@googlegroups.com, ndesaulniers@google.com, 
	nathan@kernel.org, keescook@chromium.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20221208 header.b=r2xfxhW6;       spf=pass
 (google.com: domain of glider@google.com designates 2a00:1450:4864:20::334 as
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

On Tue, May 30, 2023 at 10:39=E2=80=AFAM Alexander Potapenko <glider@google=
.com> wrote:
>
> lib/string.c is built with -ffreestanding, which prevents the compiler
> from replacing certain functions with calls to their library versions.
>
> On the other hand, this also prevents Clang and GCC from instrumenting
> calls to memcpy() when building with KASAN, KCSAN or KMSAN:
>  - KASAN normally replaces memcpy() with __asan_memcpy() with the
>    additional cc-param,asan-kernel-mem-intrinsic-prefix=3D1;
>  - KCSAN and KMSAN replace memcpy() with __tsan_memcpy() and
>    __msan_memcpy() by default.
>
> To let the tools catch memory accesses from strlcpy/strlcat, replace
> the calls to memcpy() with __builtin_memcpy(), which KASAN, KCSAN and
> KMSAN are able to replace even in -ffreestanding mode.
>
> This preserves the behavior in normal builds (__builtin_memcpy() ends up
> being replaced with memcpy()), and does not introduce new instrumentation
> in unwanted places, as strlcpy/strlcat are already instrumented.
>
> Suggested-by: Marco Elver <elver@google.com>
> Signed-off-by: Alexander Potapenko <glider@google.com>
> Link: https://lore.kernel.org/all/20230224085942.1791837-1-elver@google.c=
om/

Sorry, missed a "Reviewed-by: Marco Elver <elver@google.com>" from the
previous thread:
https://lore.kernel.org/lkml/CAG_fn=3DUzQ-jnQrxzvLE6EV37zSVCOGPmsVTxyfp1wXz=
Bir4vAg@mail.gmail.com/T/


> Acked-by: Kees Cook <keescook@chromium.org>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DU67cq4502h2G8kms8r6e%3D13tn8Ta%2BQWhA8N6cK-PFyaA%40mail.=
gmail.com.
