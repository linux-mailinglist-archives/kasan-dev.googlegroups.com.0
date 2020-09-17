Return-Path: <kasan-dev+bncBCCMH5WKTMGRBJHDRT5QKGQE5VKDXZQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43c.google.com (mail-wr1-x43c.google.com [IPv6:2a00:1450:4864:20::43c])
	by mail.lfdr.de (Postfix) with ESMTPS id D84C826D81A
	for <lists+kasan-dev@lfdr.de>; Thu, 17 Sep 2020 11:51:32 +0200 (CEST)
Received: by mail-wr1-x43c.google.com with SMTP id l17sf666636wrw.11
        for <lists+kasan-dev@lfdr.de>; Thu, 17 Sep 2020 02:51:32 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1600336292; cv=pass;
        d=google.com; s=arc-20160816;
        b=azFYp3qs0wrYdgmf3GzpVzS8qNrNWFkMHcqz2ucpFjyv7DgXb4hR0vKb+clPQhSZ0u
         lBX3WLjbIOV1ZGhvq552RdYf0EXW+1asNx1adl62O6IrEUN2wwgKz3zizHDkuh4+hi3b
         Plo7mfed73gICBdCNU+If7F9bmWpQRTIaOoc5MKHqR2mE5e5TvveFlqJf5Rro+rzza23
         q3MYZ8HYnSWCY3d5WEarzBk0wgxc3AEqKSa1HSXRBxAFakHRnc9I00dqFkpJP5BVou4N
         SA8ob7IbeU+R6xpwXQxeMprHWMqBAS3eEvgE9rBw9P9FUETrKBLpyWIuODc1HFdYWWPL
         NycQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=i082T+ywME9fbisAIHCA1RIDDitY3BkHAyuBXUqdVtQ=;
        b=iBR3D5GBzN7OsweVcuvXYM5gpCz+Cd/SdZDKYDnJufaxhaAHxcQKHF9DE7ELuplql+
         HfdvTt0SUHWifDku9gijMaBN2yeiPRO+magUMxGO8WUvnUc/dYsCzD0v2q702Lzjtdo0
         5NkQ4S+ozfP3oFt/999oyWJG8P2UAkgFHktzkJXKfgWP1fAS2Y7mT5h56d5iCgfc5Vhx
         cUFxe0zt97zp6eSxEht+fkOviMkyWKrxW7MdNw23Zw/h3a/BmpacS6Zri9W2Fglh/lS5
         C6oXyyRn5RWebNilZJSeTCyZvXpTR5V51sk3l/e3rU9IWj33y6++185ZGMXfRu5P3KfD
         5Msg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=G2R7ulBT;
       spf=pass (google.com: domain of glider@google.com designates 2a00:1450:4864:20::443 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=i082T+ywME9fbisAIHCA1RIDDitY3BkHAyuBXUqdVtQ=;
        b=KZb/ymND0pa2ECgSGdRjor/CxmD0Hqo4wxB0o6bWQWazW4vHh+c9SThl2hdB/7YenH
         MQJabPODSEO2tKBHKJ79QjqftZKNTENBpGweaJQkwSsY+M+Fp3TLHWGmViwikclBrKnL
         8qZIic3A2JUwwj+1mGM0Cf/M+s1NPqUV5ERtWvTpyDys2yeKJqZChfQdizGfhzgjaJtS
         eG4hz/j7U4s9VONMuH16lwd+FlfTiEz5SwVn1RuZJA06EN0Nu+Q/DyWKN1QvgAxPVdnO
         IV4Eroz1w3LThgyUgBWMQoy6wSGidgLnmPip0FPSOx0abfueYTHX4rEXyeCCs9xWirEH
         SDgw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=i082T+ywME9fbisAIHCA1RIDDitY3BkHAyuBXUqdVtQ=;
        b=tRlath9m0oVvXtOcPaeCPkdYlQ7/m0CbVAABSL0T33WUEGKjR6jXExxq4pPdUtGw0Z
         uK8aqcWxPz/xFxSUnXeXNzJvedAh57Jd0safcAg5pSQMjcmNNnlkWLC4kIUkOY6cHM8g
         CMZIgZ166LrDIqsc1dQqZ3e687fDzK3wpFs5aTSO/Agn9iAwvCJJPZr+WTqiFh0e0ukT
         OPYUHNVDS07WLHLhVFSLfEmAr5+Rc7J+UK6r/DzD6AfB9c8jh1dYF0TmoL2y2/R8HNUZ
         a8A49lo/f0Jb/I0y/kRNSDIXyMSuw0gnJ84JJNdU8v0t1q7kDBU3F+54EZBzRqpAQ+3/
         hMUw==
X-Gm-Message-State: AOAM532/Aqh9RDm+j0NhyVanKbc/unGPRlm2WgZ1zwrBQZ7BQ1RXW7UO
	ocZXEbh5xdErLYQrQRvtAuU=
X-Google-Smtp-Source: ABdhPJwjanYL590mfNpz8piN7IeCZ6ZI5sH7s8BJk0/JMyOSPg0qiMnrClMg4V769wLqC5cEyWnt2Q==
X-Received: by 2002:a1c:f20b:: with SMTP id s11mr9419353wmc.144.1600336292581;
        Thu, 17 Sep 2020 02:51:32 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:1b86:: with SMTP id b128ls810094wmb.3.canary-gmail; Thu,
 17 Sep 2020 02:51:31 -0700 (PDT)
X-Received: by 2002:a1c:4e0a:: with SMTP id g10mr9470434wmh.71.1600336291696;
        Thu, 17 Sep 2020 02:51:31 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1600336291; cv=none;
        d=google.com; s=arc-20160816;
        b=MXlIbxb/7xB5XkDv6SmjFfqhv8UIbSxhySMX8AcLfPFamXZQfz8C9fvKJ5CtbyOfX/
         w7VJq+pN2UumAkpUnNUUlZGUBTwXrgf9gnlvN8jsH6PaQItTDcfKVOr2CX4aFcqJOjfS
         W16knkjmq2XKpZeb7xh96jbSHSLVlxOeVmpijweyqVNylKnFEZNNAsfscYC+JdwId1lx
         gUFvn8BH7TLVfU6rVvUnKucrGOX5H326AolmI75pUHnuue20RqnhRO+OgMiRsZ/NCJ0w
         yriIvqVw3/VwPtPZkw+9xEt1ftnELXKohHea2/oJ8fELxDYqI6ZbsxOZj41erUCj0mFn
         poIg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=1z0Dzoz+hRHyGT5fLUrVWCjo5PxPXHMObR+QlG59yhI=;
        b=p5xaEsfUeQDlY93g18FDmwr+CSrXHvV55f+RMjM0njpf9E9jZTQItQeJcOykye4z/T
         TP1amF1wsxs7hRDzTYXTGpjNmMDqPktHHFfW89KnAuNBwA453hOU9poET/WZ1vBVJTJW
         fmB1sMDMuekK6JymKb6UVbMcE8QXIgnF65hPYQ/ppVHiIeeoNyWpBW+FJM8vCHczB82g
         k1izGqzSyQeW48PchXcBEf7y7ceepBrj5Y+w3dz8D+7JFGfch4ElioQOgaOssfb2Z8/D
         HLw2frXw7wmDLr7Zu/TvPjXiuZ5a35ol2O20OhqicytvQZDsv9MpMCi1IuMMHwRP0LE6
         3nYw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=G2R7ulBT;
       spf=pass (google.com: domain of glider@google.com designates 2a00:1450:4864:20::443 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x443.google.com (mail-wr1-x443.google.com. [2a00:1450:4864:20::443])
        by gmr-mx.google.com with ESMTPS id h11si467037wrr.3.2020.09.17.02.51.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 17 Sep 2020 02:51:31 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2a00:1450:4864:20::443 as permitted sender) client-ip=2a00:1450:4864:20::443;
Received: by mail-wr1-x443.google.com with SMTP id w5so1343037wrp.8
        for <kasan-dev@googlegroups.com>; Thu, 17 Sep 2020 02:51:31 -0700 (PDT)
X-Received: by 2002:adf:e312:: with SMTP id b18mr8525505wrj.372.1600336291198;
 Thu, 17 Sep 2020 02:51:31 -0700 (PDT)
MIME-Version: 1.0
References: <20200915132046.3332537-1-elver@google.com> <20200915132046.3332537-6-elver@google.com>
 <alpine.DEB.2.22.394.2009170938030.1492@www.lameter.com>
In-Reply-To: <alpine.DEB.2.22.394.2009170938030.1492@www.lameter.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 17 Sep 2020 11:51:19 +0200
Message-ID: <CAG_fn=W1CqBgCqpYBNgYE7V+i4iqK4iyVydJyz7K4Zfc0zZvEw@mail.gmail.com>
Subject: Re: [PATCH v2 05/10] mm, kfence: insert KFENCE hooks for SLUB
To: Christopher Lameter <cl@linux.com>
Cc: Marco Elver <elver@google.com>, Andrew Morton <akpm@linux-foundation.org>, 
	"H. Peter Anvin" <hpa@zytor.com>, "Paul E. McKenney" <paulmck@kernel.org>, 
	Andrey Konovalov <andreyknvl@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Andy Lutomirski <luto@kernel.org>, Borislav Petkov <bp@alien8.de>, 
	Catalin Marinas <catalin.marinas@arm.com>, Dave Hansen <dave.hansen@linux.intel.com>, 
	David Rientjes <rientjes@google.com>, Dmitriy Vyukov <dvyukov@google.com>, 
	Eric Dumazet <edumazet@google.com>, Greg Kroah-Hartman <gregkh@linuxfoundation.org>, 
	Ingo Molnar <mingo@redhat.com>, Jann Horn <jannh@google.com>, Jonathan.Cameron@huawei.com, 
	Jonathan Corbet <corbet@lwn.net>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, 
	Kees Cook <keescook@chromium.org>, Mark Rutland <mark.rutland@arm.com>, 
	Pekka Enberg <penberg@kernel.org>, Peter Zijlstra <peterz@infradead.org>, Qian Cai <cai@lca.pw>, 
	Thomas Gleixner <tglx@linutronix.de>, Vlastimil Babka <vbabka@suse.cz>, Will Deacon <will@kernel.org>, 
	"the arch/x86 maintainers" <x86@kernel.org>, "open list:DOCUMENTATION" <linux-doc@vger.kernel.org>, 
	LKML <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=G2R7ulBT;       spf=pass
 (google.com: domain of glider@google.com designates 2a00:1450:4864:20::443 as
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

On Thu, Sep 17, 2020 at 11:40 AM Christopher Lameter <cl@linux.com> wrote:
>
> On Tue, 15 Sep 2020, Marco Elver wrote:
>
> >  void *kmem_cache_alloc(struct kmem_cache *s, gfp_t gfpflags)
> >  {
> > -     void *ret =3D slab_alloc(s, gfpflags, _RET_IP_);
> > +     void *ret =3D slab_alloc(s, gfpflags, _RET_IP_, s->object_size);
>
> The additional size parameter is a part of a struct kmem_cache that is
> already passed to the function. Why does the parameter list need to be
> expanded?

See my response to the similar question about the SLAB allocator:
https://lore.kernel.org/linux-arm-kernel/CAG_fn=3DXMc8NPZPFtUE=3DrdoR=3DXJH=
4F+TxZs-w5n4VuaWKTjcasw@mail.gmail.com/



--=20
Alexander Potapenko
Software Engineer

Google Germany GmbH
Erika-Mann-Stra=C3=9Fe, 33
80636 M=C3=BCnchen

Gesch=C3=A4ftsf=C3=BChrer: Paul Manicle, Halimah DeLaine Prado
Registergericht und -nummer: Hamburg, HRB 86891
Sitz der Gesellschaft: Hamburg

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DW1CqBgCqpYBNgYE7V%2Bi4iqK4iyVydJyz7K4Zfc0zZvEw%40mail.gm=
ail.com.
