Return-Path: <kasan-dev+bncBCCMH5WKTMGRBQEEQGUQMGQEATZ2RSA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13e.google.com (mail-il1-x13e.google.com [IPv6:2607:f8b0:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id B57E77BBD9B
	for <lists+kasan-dev@lfdr.de>; Fri,  6 Oct 2023 19:22:09 +0200 (CEST)
Received: by mail-il1-x13e.google.com with SMTP id e9e14a558f8ab-35250666389sf36895ab.1
        for <lists+kasan-dev@lfdr.de>; Fri, 06 Oct 2023 10:22:09 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1696612928; cv=pass;
        d=google.com; s=arc-20160816;
        b=iQJp83tqOWnT7W77XDd55IO0QdO7aSC6ht/GN3jpTg45axPMppJn0v+8U/N+mLW2o/
         qY49QKalUlmTWuKTnKf3B7nR9+XXCE3VhX1mrphiF9sLL4NSxXWi2Q2ylcJahVkbdCE7
         xBXPowCZnK8xFMWP+96N+FISE/Bd1NkOGJ0wzQTQLPCJ0k4Ia/KHu3UzoYk0wmuJopI4
         3MyUMjXd8pgsGrn2BLmpVg++BXMcRavnYyCZ+Q3aXJ1AsBah2i/qPc8W2EF/xv7AlbG8
         vaKTsskuLTbVZUt/ZAni05rbJO+9XP8STl15qAzx1g93e/tKPxqfz+2NEGsvRX4woBq/
         LLZw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=SThOzFE40FGvbX3TxM/i5P9YIw75uuN5uDtkUkCVUMY=;
        fh=D7uhrQnmQG6xf11gbvfi3iQ1A4p/6GZN4OQA8frEvwo=;
        b=YCTIEKhhMLgdXR7qMNJ1qNtZUhhJUXMxpiDAQPr4Z75pi+zNmheSoStdDHmw5N4YWy
         /tPUbhJhoyVIvirhe/FuvgqtYZTxHPnc/dEwPqgy3CaIIVZfdp+nW4Fl18vdfyVHbGmX
         0eRPGtKLkSYUHR6cypqq2XmwY4BmUHsLT5pfLnlfW7tqDuTGiG3h50UiQGWeB4ZS59o3
         XcRaXvNrZvwyblXcYBjrouxOX4NuWCr9Nlv9mvN8L1xsilncGmKSqDus+yuz/wfQyqY3
         6qvn6oybUuyeTosf6x1tuekRcIyprlYKzPphOst2Hv5VYpk8EJDUsrIBBpsFe6T3GorX
         KiNw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=NQogSMhn;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2f as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1696612928; x=1697217728; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=SThOzFE40FGvbX3TxM/i5P9YIw75uuN5uDtkUkCVUMY=;
        b=VPu0tus/koQYldcQEKFL7kXzcF/6/p74AQSS5vtvcoAcmIWfpQsjJYbFM/jqIe3qwx
         PD93gTJoCpLUalv3z7qM82I5+t+Zc9FZsmShGsnNq2frNzhNv6bTFpebsblnisje6mgs
         CKcMStntEX8rTj72LxkDiVvXinXgX+Ggi7EooAr27NyOgJkfjJkKyfAmBQ0qy9YQCZmy
         /lSjztti4I1R4Nt4SMnCuOUgsaMDnJ2q5hPO9AQXgRmdh81bjx9Tb9rsulDfb09D/HSM
         wm3YcxfwvXMl5MlPNj5A963mzEax7hDyqRunAKn9pAn0LVWhSV/uUFSXBaAvg6V4jtO0
         m+qw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1696612928; x=1697217728;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=SThOzFE40FGvbX3TxM/i5P9YIw75uuN5uDtkUkCVUMY=;
        b=ebtkhJO6t+qw02UcEP3l1ij3cnCJloqEtqOvXNK33zHuSnG+3OyPmlmRO8PY5DTNm5
         UF+HIv0rgScbVs2FUzgi4aov+sDPy8TnHNZ5HGYQWpSQBKjcu6zEOA5SCkXv+txsR6Cv
         RI48AnW8nRdKbV3pwrxun6E+sovgOKVtgLV63RDb3+zd8bOtfJl67lSXaecjpGcL1k4N
         d4hXM68tfYS2uxsIrqAxP+Scwg3526xyZ0PrCmbBS/kD2Mef4KLHPPruR5c34pnfxZwB
         YVFXXFGHTRGi2Rh7YReT15Zt8XjtsqfyV8i3H0OrhrfuCdwvpuORYZ3mO9nIPf2r6WBW
         fQFg==
X-Gm-Message-State: AOJu0YwK/XizzznHdAbkJ2SCdMee2A3yPgIDM1vlUu13DOFW8D/3Z5H3
	hqyQUDSi8ts4wnYiKP1Xk7s=
X-Google-Smtp-Source: AGHT+IFXsQLAP1/2bbn03bJdREmI/LvmgY+tZN3NImYDUYRUvJNTW7BXHwq4ViUZqEcySzkCt0W+nA==
X-Received: by 2002:a05:6e02:1c88:b0:34f:da0c:e1c5 with SMTP id w8-20020a056e021c8800b0034fda0ce1c5mr437934ill.24.1696612928201;
        Fri, 06 Oct 2023 10:22:08 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:4f4a:0:b0:57b:6a17:53f7 with SMTP id c71-20020a4a4f4a000000b0057b6a1753f7ls3129072oob.2.-pod-prod-09-us;
 Fri, 06 Oct 2023 10:22:07 -0700 (PDT)
X-Received: by 2002:a9d:7751:0:b0:6b9:ba85:a5fa with SMTP id t17-20020a9d7751000000b006b9ba85a5famr9887800otl.5.1696612927606;
        Fri, 06 Oct 2023 10:22:07 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1696612927; cv=none;
        d=google.com; s=arc-20160816;
        b=Q/QxiA+GCLRn/0QYIFaDHt4UEk9GZW0nTEI2JJPb745+nu/4Pu+xgCKRNwWK+5Dc53
         +GWoa7vP8o67awBginwSC930GsdLzmFSGFfnoa7zWV761lhhSqiT0NaJbu7IuUc5Q9+n
         n4doaAMXYlJYo81x91Yr6nJjg1IOlNW8EKXHMlxgb4EIH98qzpN+TO+EiHNt2527OcWC
         QSvSjywpdbUagwlvypH9J4KEs/pfWZ8cq44a/LxYioiMnLhXbRNtv9qzQA1EObsH9+gn
         llsCA6nh/Bv7z9oRImGnN9XBFFpZAhm0KGC9H3Kn0jZbR8Ssv5m8engdOaC/hKpbiFmN
         wclQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=EknEuy8+VO/WBZWGFtfzssW3dtzNayZawyALF7dqvnA=;
        fh=D7uhrQnmQG6xf11gbvfi3iQ1A4p/6GZN4OQA8frEvwo=;
        b=mAZ/wC9n6iNJz7h1JvLtUSFovdB0SSBaSfpXi6P9GAUdCzX+9+T7uUnY91ISrMpugD
         pRtMjkS9cjpWJk5laXkVJrAqukMpdbUwo8MZgoDUanN+f3N40h0Vn78ZHo6F9h7fjr+r
         KQkCOJHFZvg66h3qCBToJUfsDqWe2oOqCaCoV3pxkolkOfwBf4TL6IMtdlX5e4xYz5nD
         V2j3i4XwYv/bzESGumZMJbiqzDgtwU2W7+TlOIoB9d1iORl/49/1GMjaEhnf+2WiqD2y
         wZwu/MlJru+8+pRMBPORz8e7FLGRc0c3JCh4/M4Zy+786JfIe4+cOOVO7HkzQxSMOM+w
         Tg2g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=NQogSMhn;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2f as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf2f.google.com (mail-qv1-xf2f.google.com. [2607:f8b0:4864:20::f2f])
        by gmr-mx.google.com with ESMTPS id u20-20020a4ad0d4000000b0057acba9658bsi171274oor.2.2023.10.06.10.22.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 06 Oct 2023 10:22:07 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2f as permitted sender) client-ip=2607:f8b0:4864:20::f2f;
Received: by mail-qv1-xf2f.google.com with SMTP id 6a1803df08f44-65cff6a6878so12659946d6.1
        for <kasan-dev@googlegroups.com>; Fri, 06 Oct 2023 10:22:07 -0700 (PDT)
X-Received: by 2002:a05:6214:180e:b0:65b:ed3:9a02 with SMTP id
 o14-20020a056214180e00b0065b0ed39a02mr8264327qvw.17.1696612926911; Fri, 06
 Oct 2023 10:22:06 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1694625260.git.andreyknvl@google.com> <e78360a883edac7bc3c6a351c99a6019beacf264.1694625260.git.andreyknvl@google.com>
 <CAG_fn=UAF2aYD1mFbakNhcYk5yZR6tFeP8R-Yyq0p_7hy9owXA@mail.gmail.com>
In-Reply-To: <CAG_fn=UAF2aYD1mFbakNhcYk5yZR6tFeP8R-Yyq0p_7hy9owXA@mail.gmail.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 6 Oct 2023 19:21:25 +0200
Message-ID: <CAG_fn=XyqgfZO=bduYPTGpM9NovQPZOzZf8cidt7=m6H092sSg@mail.gmail.com>
Subject: Re: [PATCH v2 06/19] lib/stackdepot: fix and clean-up atomic annotations
To: andrey.konovalov@linux.dev
Cc: Marco Elver <elver@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, 
	Evgenii Stepanov <eugenis@google.com>, Oscar Salvador <osalvador@suse.de>, 
	Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=NQogSMhn;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2f as
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

On Fri, Oct 6, 2023 at 6:14=E2=80=AFPM Alexander Potapenko <glider@google.c=
om> wrote:
>
> On Wed, Sep 13, 2023 at 7:15=E2=80=AFPM <andrey.konovalov@linux.dev> wrot=
e:
> >
> > From: Andrey Konovalov <andreyknvl@google.com>
> >
> > Simplify comments accompanying the use of atomic accesses in the
> > stack depot code.
> >
> > Also drop smp_load_acquire from next_pool_required in depot_init_pool,
> > as both depot_init_pool and the all smp_store_release's to this variabl=
e
> > are executed under the stack depot lock.

Maybe add this to the comment before "if (!next_pool_required)" ?

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DXyqgfZO%3DbduYPTGpM9NovQPZOzZf8cidt7%3Dm6H092sSg%40mail.=
gmail.com.
