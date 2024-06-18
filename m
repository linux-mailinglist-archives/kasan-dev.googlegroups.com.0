Return-Path: <kasan-dev+bncBCCMH5WKTMGRBDFFYWZQMGQEDW2HGRY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x839.google.com (mail-qt1-x839.google.com [IPv6:2607:f8b0:4864:20::839])
	by mail.lfdr.de (Postfix) with ESMTPS id C2A3190C547
	for <lists+kasan-dev@lfdr.de>; Tue, 18 Jun 2024 11:25:35 +0200 (CEST)
Received: by mail-qt1-x839.google.com with SMTP id d75a77b69052e-4405e3b3b78sf397521cf.0
        for <lists+kasan-dev@lfdr.de>; Tue, 18 Jun 2024 02:25:35 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718702734; cv=pass;
        d=google.com; s=arc-20160816;
        b=x6SMiLW3RsalNGBjr9p05n5e7vEQK2VNFuxUZn4HzEZSZ+AqYt1myMcW2HZRmFcj90
         bfBWgY7cA9vdx9cpGfTtpmSx5BB4rUMYt+nIsaQ2Xn4qUZq53IrDp5HbNtbGXnrYzbBV
         hkUmgGLT4Usfryc2TP9LOYNpexo5uGnPmowmXhCMnA6WiBSEjbHFpdEB8sgRiTfYkrlh
         7wwi35kI2dbaTW49thw7WIcX9AlwaZAmB1m8d20o2WUyhhAxRm/3xcShJygmgDragT+d
         FDVnEdDbIMSq2MuXJtA2MSh7A1hN7t6VdDUuyOM55yQ1IGiNrNIi0Y4KfspGhT3a0ty0
         IoNQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=8JEmNe5hozJqh3sElvF3IcKuXqSRFtAmAyHC5rw5hSg=;
        fh=lT3JUAsHGTVDyU4C67XMOLPfKkXmpysJhOSOHVONPfA=;
        b=zjeO+2zYAEifPIidjxYykVhFWirDCsZwpWGic30YkvpVvrVqHE7RI4JeeEJ66pxrpo
         dOOsGyWkZCpVL5JKcUJbUfn5wKMmZ9Xq1xXY9QCh3zb8hLc3tU16Ha4k+SBWMpDzb25e
         6JDz56h4rxHsjp6lSvc4WLLEXJphQzqR0VdMCvCtN7/P9lql4S4314uBWMlDRbc6UD8D
         VNQbUNczT5OVOLfSFDOwxHBd0yAJVuAUGdt2IIKllKlqXWphR2dHkVDzidAOzjOcz0BV
         0ZX41oWXaRechsJAe0Akor11fx+Sg+pI3fX68uMtITgWbUhl98a4VUcfFkhISv5JFECB
         qgyQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=arLuilNt;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f29 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718702734; x=1719307534; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=8JEmNe5hozJqh3sElvF3IcKuXqSRFtAmAyHC5rw5hSg=;
        b=Y7mlFwwlr3sOwowZplGjhRUmGDrKvt4bcqbAO8Kyo2zPzUSMR6RLa0luPmDGoFkr56
         d1G0T00wLU5P4ZtL3GA7SuZaQmQ6wNhBlMoEzvQYt7kVSU77Td88v4JJBVvEkl2zxbUt
         NCfssJpaKJm07AKLiPfc5SC5hO03saQE/QQkKUe40T5GPfl0FMHPrIKxLJgpXnR4l2xo
         hKfPLcyd1tLlLAMywfvh29x7sPBQ7mGTkwhw5cpI7eF3/flaaeemg7DEEfFZOF2hrCMp
         iJ1ZxQSM3D6zGOmq2ruk5A1WMuXiS6reN9QkHwJHt5RjdWD0yUF3t5pnDDtjK7wuUVSB
         yprw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718702734; x=1719307534;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=8JEmNe5hozJqh3sElvF3IcKuXqSRFtAmAyHC5rw5hSg=;
        b=AeRk2YGaxgj7b/LHwi9IoFKPrTZGvXSzoG9JFN3QrvVZXydLeP1TsK172pRP9HmI9h
         QaMx28cm9Y6gVv/J/rJetEDbae9qFQRltQWtIwmT/lntF1B6T5noyllzsQTEYlhcEpYw
         aa2/r8bR4x7FleUeoXK6zDmeDRIyDETuE7/q978cbYdLJQKoo5/633QEOyHFobYI6YV0
         43INvYEZFL3QktFvI77y3vim2GGszIWyaU/b7+XhUSpXKBn80dCpQoqKPortxVPj4jB2
         apPNVbUpoSVpPN7NmFyd/cW2JYOpfqy1OFmFj7WlDRzV4rRLz5uosJjluZBDsQwLWMV1
         u9qw==
X-Forwarded-Encrypted: i=2; AJvYcCUDdXG5P9XLrZRVLuvJNwV5Qi7uVQnQyB0Sk6J4jZR0yJmmOy+epZSLq0ddgM+l1mo8FxUd7O7hVd1Cd89JhFBvcakTAu6gUg==
X-Gm-Message-State: AOJu0YwK98cHmsE5EQ6k0FgGMEVY3kvqExiOr9pDIcZXNjMzzvJQ/u+S
	+5lbSK834QlM7K+XWda7S0JFx+7PJl78CNKrYu4rsISMXSu9nYKw
X-Google-Smtp-Source: AGHT+IHl7F8++5iJlPsOthqig9+tbMTJr4UG9u3p32Yj1wh8w0xhTiY52lvRTizg45Xkl0gkGY/whg==
X-Received: by 2002:a05:622a:5c8:b0:444:911f:5353 with SMTP id d75a77b69052e-4449d9f66eemr2029701cf.5.1718702732924;
        Tue, 18 Jun 2024 02:25:32 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6902:1009:b0:dfe:54e6:8233 with SMTP id
 3f1490d57ef6-dff34cda093ls3431078276.0.-pod-prod-08-us; Tue, 18 Jun 2024
 02:25:32 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVWeAxTHEnNsChT0jc5PCUA3admd2ACLhYUAgQ41cit6byHr+wwHVo8PgJ6FjUYnD3/QQa1769tZoSRImSrUKYrzZhGwByES/T/SQ==
X-Received: by 2002:a81:7144:0:b0:627:dfbd:3175 with SMTP id 00721157ae682-6322275af2dmr128449607b3.10.1718702732056;
        Tue, 18 Jun 2024 02:25:32 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718702732; cv=none;
        d=google.com; s=arc-20160816;
        b=S+VhnxNh3tNSsYgZEikbrK3kzPlRdbceOg8JW9p06xWida77tmcvb5WVe3DnQuGkCO
         xyKum2ztWiq70OQsvgzHeVJ3xs60N1W8WzfW3HPFVpX3rgsQ0wWxPIKTTVPyBmunuuUu
         lOxmXUpKkP359fLfrGJdUthNKbdqvG0o0xC5ZRuUnEEIBDuB5fbdPMtD9uPthgx11QQd
         O4rlZHsl2XO/HLYn1/ZbJkOfBvwAxAP9tPYZHqjE/ZEeSqqP0m6j/YStsRCBTRkff4FL
         mq9uTMYLOXhq3d142cHduLIXQiMC3mUBbcXEuBbb/PQBKm3poBkPQnjXC2vKVDzF8dHN
         lLjg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=V4MXEMKcp5I9XclPQt9HVJ1nbtcnQ61M4kMdjmYxvDU=;
        fh=Fx4zpqhlUYpWWosr24k/gSEeqeAZgrJW1wunz3M5LXI=;
        b=hEKhlbYPj+T3AJwwkYnNwA8meRAByb2QzdR7yt9WsWHgKF9VpbD2hVSOFsyfb2+a0L
         ralkkS25O+hvOOFZTrs0RJ9rEWoE9pkMr7ytD80TiL4porCBmGPhpIVRMq1NnWOxkoyx
         2oDPH1I4wGGcyilU1ci1n6C/rteOXwjygtH9XP5X97tUVmiE61JPgQbvIFdgFRWN6cXa
         uhmdH4iLzpCB43t0ezGMi2uORT28n+NTAL0WbpXu4ky6WLKiwIuqzkaqFSSa7m/LkgE+
         s+Fi6OtVtAHeknvaGDidcW9EzDAVfTe/qfaZzH7CskXBCnES1IHg5CRrMY/4A1/hPVUJ
         m7nw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=arLuilNt;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f29 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf29.google.com (mail-qv1-xf29.google.com. [2607:f8b0:4864:20::f29])
        by gmr-mx.google.com with ESMTPS id 00721157ae682-6311aa26feasi5548757b3.2.2024.06.18.02.25.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 18 Jun 2024 02:25:32 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f29 as permitted sender) client-ip=2607:f8b0:4864:20::f29;
Received: by mail-qv1-xf29.google.com with SMTP id 6a1803df08f44-6b05c9db85fso26606326d6.2
        for <kasan-dev@googlegroups.com>; Tue, 18 Jun 2024 02:25:32 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWSnzbcbwiEtn9rPTntI+AibNrX4uutv8mdSnlMvybYtKExKy2LMh0Kelb8RZ5KxmKRqpC3dhpDn711Hb6LJOOnlUh5+RLqVRv5AQ==
X-Received: by 2002:a0c:c607:0:b0:6b2:9c01:86b7 with SMTP id
 6a1803df08f44-6b2afc76589mr116376566d6.5.1718702731438; Tue, 18 Jun 2024
 02:25:31 -0700 (PDT)
MIME-Version: 1.0
References: <20240613153924.961511-1-iii@linux.ibm.com> <20240613153924.961511-33-iii@linux.ibm.com>
In-Reply-To: <20240613153924.961511-33-iii@linux.ibm.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 18 Jun 2024 11:24:50 +0200
Message-ID: <CAG_fn=X6wHfmGsVgdqwms_Hk1CQAZ6M5623WyatjVp=Uk-z9pQ@mail.gmail.com>
Subject: Re: [PATCH v4 32/35] s390/uaccess: Add KMSAN support to put_user()
 and get_user()
To: Ilya Leoshkevich <iii@linux.ibm.com>
Cc: Alexander Gordeev <agordeev@linux.ibm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Christoph Lameter <cl@linux.com>, David Rientjes <rientjes@google.com>, Heiko Carstens <hca@linux.ibm.com>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, Marco Elver <elver@google.com>, 
	Masami Hiramatsu <mhiramat@kernel.org>, Pekka Enberg <penberg@kernel.org>, 
	Steven Rostedt <rostedt@goodmis.org>, Vasily Gorbik <gor@linux.ibm.com>, 
	Vlastimil Babka <vbabka@suse.cz>, Christian Borntraeger <borntraeger@linux.ibm.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Hyeonggon Yoo <42.hyeyoo@gmail.com>, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, linux-s390@vger.kernel.org, 
	linux-trace-kernel@vger.kernel.org, Mark Rutland <mark.rutland@arm.com>, 
	Roman Gushchin <roman.gushchin@linux.dev>, Sven Schnelle <svens@linux.ibm.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=arLuilNt;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f29 as
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

On Thu, Jun 13, 2024 at 5:39=E2=80=AFPM Ilya Leoshkevich <iii@linux.ibm.com=
> wrote:
>
> put_user() uses inline assembly with precise constraints, so Clang is
> in principle capable of instrumenting it automatically. Unfortunately,
> one of the constraints contains a dereferenced user pointer, and Clang
> does not currently distinguish user and kernel pointers. Therefore
> KMSAN attempts to access shadow for user pointers, which is not a right
> thing to do.
>
> An obvious fix to add __no_sanitize_memory to __put_user_fn() does not
> work, since it's __always_inline. And __always_inline cannot be removed
> due to the __put_user_bad() trick.
>
> A different obvious fix of using the "a" instead of the "+Q" constraint
> degrades the code quality, which is very important here, since it's a
> hot path.
>
> Instead, repurpose the __put_user_asm() macro to define
> __put_user_{char,short,int,long}_noinstr() functions and mark them with
> __no_sanitize_memory. For the non-KMSAN builds make them
> __always_inline in order to keep the generated code quality. Also
> define __put_user_{char,short,int,long}() functions, which call the
> aforementioned ones and which *are* instrumented, because they call
> KMSAN hooks, which may be implemented as macros.

I am not really familiar with s390 assembly, but I think you still
need to call kmsan_copy_to_user() and kmsan_copy_from_user() to
properly initialize the copied data and report infoleaks.
Would it be possible to insert calls to linux/instrumented.h hooks
into uaccess functions?

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DX6wHfmGsVgdqwms_Hk1CQAZ6M5623WyatjVp%3DUk-z9pQ%40mail.gm=
ail.com.
