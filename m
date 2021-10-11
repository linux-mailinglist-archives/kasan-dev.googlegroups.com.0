Return-Path: <kasan-dev+bncBC7OBJGL2MHBB7W6SGFQMGQEYOR4DRA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa40.google.com (mail-vk1-xa40.google.com [IPv6:2607:f8b0:4864:20::a40])
	by mail.lfdr.de (Postfix) with ESMTPS id 3B377429547
	for <lists+kasan-dev@lfdr.de>; Mon, 11 Oct 2021 19:08:15 +0200 (CEST)
Received: by mail-vk1-xa40.google.com with SMTP id r10-20020a056122014a00b002a3bd59eda8sf1683649vko.6
        for <lists+kasan-dev@lfdr.de>; Mon, 11 Oct 2021 10:08:15 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1633972094; cv=pass;
        d=google.com; s=arc-20160816;
        b=YgC8TviQb/QZdvLWIMF3ZJYnEJqb9yJz1LHdQ6IJrra6NAoQGgkOnJSnHEGb/QDw1n
         zd7Nror5UNYvU48MmwdJL+p0FTsejyCcXI4A2WCM1oRh7RHsWGdzPXDbaAVS9GeTNYUl
         RMP3hOD0WUTraqla8iz5FOVzJGqamL/mIS2VpYwZlnJq8OXRpBTmTtu8ceFoKR3WtHuc
         oHBTIsgZMLLxZoZOkHW/U8QvGXPzmCXPjRk5UxQvw2vOOxfG+NKwP+lRyXNnxKHYFAfR
         pAVpuTgd/3taXKOHDHmDCGWpNCu2GtQok3zy1+yqdRKtl21Lc7ZoI6Q+WpGQqFpEzKOg
         6dsw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=5lC01agLI3ERBIk2/Luc2C5cXn26l6HIq3SmoTNI0Ac=;
        b=zmNVVIAXNsgE/9XmO8u5bywd2xUcRsu1eFWn+CqUlBZvuCVeuvyJQ2RIU1c7x9hU2d
         ymy/t6m+WJdWxbcna2Pe/aCga/ikzX/1hS4T3WWD15Qpv3EJWcatoi9Irvs/6E1HS+jl
         X/8A+hqRJ2cZ6ngasuMTZ1PbejUzvf9r8XZ+713G8fYAorxwCqRaWBNRzSkHk5zTpZDM
         jraYDdTg7NIKTk2cDLI2U0arFwmUIn+9i46FHcq4Bzkzz15sXwqBcZWQH750Bo+6qxgj
         g9SBmfEM+hpLgix0N1Gdg5utO6i6rmJJ7vfPu88bUnUcRyx1LPrkbjiGQNo4tB3v9mso
         +JWQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=MADCvz5N;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::231 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=5lC01agLI3ERBIk2/Luc2C5cXn26l6HIq3SmoTNI0Ac=;
        b=CG9yIPic6jVoBIrkILcc1+iFnFGEk4OQWp4cc+tlIfMv4gRs1urp6hd1zHBdQTgkU5
         TTWpqu6oEukSZ73wAZsuYZ8yF+t5NVjNqVhj0RGtBZ3YqqvWPhlgBDLSRDDnmLGknm8D
         AM+1LkDcMdcpcmo2wp1NjxFYcPl3mNJGi/BOpajPwZdLEJsm+HjxVA8nMXjqJx2R2CUT
         OHx04Q3ZIZSHVaxY5/JEH2JE1RA82HioSVLV9l86eff6zrjImanjIawmV7SLH7xbKWlz
         3iH9AB62JWhTLk5VbiCTqcbQRMha7026N+Am24XRxHrr2f8Ed5NammDiziXhEwLix15u
         Iz1g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=5lC01agLI3ERBIk2/Luc2C5cXn26l6HIq3SmoTNI0Ac=;
        b=hiMmlqpYpf6ze4WITKbBv+nTde7ziaGDbPcNI5EAS44zJLlUInUe+bqDTNcXekXet1
         vst4Td4wmtxk1pV4cBMUYJ62IU7wRRJf3vAXzssc30GiZGEd0RGPQzAm/sFYq3284CDq
         dhb1fJPqWHbpeV/nVDAfC9mM8fRZnCV7YOL26jCF9CbFtu7Qlxn1SO7R8rmVXz679hgQ
         MipbrFZDDhAzPzu0Evc6Mbew0X1NxpeF7r9ACddtr8y3ZcKjOyjjYM44PamxvPZwNSe6
         yPyAXXf1lzdD0dR0Yz9IEWDlmAGlwdcvcomyf6mPSPvohGPT/XzV4BIVjgbrfoKPLC9i
         n2Vw==
X-Gm-Message-State: AOAM5323YAqnWRU+jrcNDk6arJBMy8DtWvNysPc6+iJe/RYXKZ5tWRp+
	Otji6BJoqwhyoNmdtqAmvmw=
X-Google-Smtp-Source: ABdhPJw0y+iEaFkqKrEqlr6aG5pCLvbnUeZaNvGvLyOf1jObpcDhSUk4DMwb4Lt6B5tMfxg8UnaFUg==
X-Received: by 2002:a67:bc06:: with SMTP id t6mr24112115vsn.23.1633972094159;
        Mon, 11 Oct 2021 10:08:14 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:c083:: with SMTP id x3ls2717962vsi.1.gmail; Mon, 11 Oct
 2021 10:08:13 -0700 (PDT)
X-Received: by 2002:a05:6102:21d0:: with SMTP id r16mr25526810vsg.39.1633972093634;
        Mon, 11 Oct 2021 10:08:13 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1633972093; cv=none;
        d=google.com; s=arc-20160816;
        b=Y8YWJCR6KZ1Xg7Q0FjNUiBbtsPrp1Cu6MjYA9DXkaVRzcooE76hFed4chFQmDHURtG
         kg5WRdmXdu4qRIHMIeJY3zFtSd8neSu7JPVTK1Lv2qFNW8a5WUB2h7MMnqPzxfVVqCWZ
         7TvrQ0oB+u2hWhQt1U9M1heUVW1qp3DvN54OSFwyADjcO59PjZZx9Ao72rQkw1x9rwa0
         UdvYALWIVdR8OzeXUiR03aNLr0sXdaEEfH+qa90Hx/xmtdOfiEiG2KivMCYunIJZWvx3
         mlDWF+SSM3henOJd6lWfWcwIWMzBBrR7g55kaDdZwSw2zUjaiRwmJM7F8ucd5fMP9SA2
         vctQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=bdR8B2SCkgkhZRGwEibKgUZJ+mS8tIXLqdrjvZhlSeY=;
        b=LHPKAtMlEOoCqYptAbakVtbAQi71VQgB5Eu3HohmKXdw45diVR+Dwa7TT1wWzYl5/B
         DYx9SH+ko8L7CW+ALFvAHxdjuSd9a0yBUDmb37w3i6+iCwyxL29OIJf9EyTfragwCQPQ
         V5jrI8MblKvVHzV3f9G9uRXuZpX1SvI9NPZDF4pHkApklf7DQ1FrWs/xgUTaBqxMBvId
         +PM0Lm04G54r7nSNkpFWshZcyx6Txmm0a/q2eXnRanuQsfZuP5U+nkXEswBgCvYbii/v
         SRKfD5cLG9tkjwf+iIRWL5ugHNTeAz9jin4CG7ZkV7moTmw+z6WsVys2+1XAkmGFNV2z
         ZIdA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=MADCvz5N;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::231 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x231.google.com (mail-oi1-x231.google.com. [2607:f8b0:4864:20::231])
        by gmr-mx.google.com with ESMTPS id 3si349055vkc.0.2021.10.11.10.08.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 11 Oct 2021 10:08:13 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::231 as permitted sender) client-ip=2607:f8b0:4864:20::231;
Received: by mail-oi1-x231.google.com with SMTP id z11so25529426oih.1
        for <kasan-dev@googlegroups.com>; Mon, 11 Oct 2021 10:08:13 -0700 (PDT)
X-Received: by 2002:a54:4618:: with SMTP id p24mr109828oip.134.1633972093136;
 Mon, 11 Oct 2021 10:08:13 -0700 (PDT)
MIME-Version: 1.0
References: <20211007095815.3563-1-vbabka@suse.cz> <YV7TnygBLdHJjmRW@elver.google.com>
 <2a62971d-467f-f354-caac-2b5ecf258e3c@suse.cz>
In-Reply-To: <2a62971d-467f-f354-caac-2b5ecf258e3c@suse.cz>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 11 Oct 2021 19:08:01 +0200
Message-ID: <CANpmjNP4U9a5HFoRt=HLHpUCNiR5v82ia++wfRCezTY1TpR9RA@mail.gmail.com>
Subject: Re: [PATCH] lib/stackdepot: allow optional init and stack_table
 allocation by kvmalloc()
To: Vlastimil Babka <vbabka@suse.cz>
Cc: Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, dri-devel@lists.freedesktop.org, 
	intel-gfx@lists.freedesktop.org, kasan-dev@googlegroups.com, 
	Vijayanand Jitta <vjitta@codeaurora.org>, 
	Maarten Lankhorst <maarten.lankhorst@linux.intel.com>, Maxime Ripard <mripard@kernel.org>, 
	Thomas Zimmermann <tzimmermann@suse.de>, David Airlie <airlied@linux.ie>, Daniel Vetter <daniel@ffwll.ch>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Geert Uytterhoeven <geert@linux-m68k.org>, Oliver Glitta <glittao@gmail.com>, 
	Imran Khan <imran.f.khan@oracle.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=MADCvz5N;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::231 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Mon, 11 Oct 2021 at 19:02, Vlastimil Babka <vbabka@suse.cz> wrote:
[...]
> > On the other hand, the lazy initialization mode you're introducing
> > requires an explicit stack_depot_init() call somewhere and isn't as
> > straightforward as before.
> >
> > Not sure what is best. My intuition tells me STACKDEPOT_LAZY_INIT would
> > be safer as it's a deliberate opt-in to the lazy initialization
> > behaviour.
>
> I think it should be fine with ALWAYS_INIT. There are not many stackdepot
> users being added, and anyone developing a new one will very quickly find
> out if they forget to call stack_depot_init()?

I think that's fine.

> > Preferences?
> >
> > [...]
> >> --- a/drivers/gpu/drm/drm_mm.c
> >> +++ b/drivers/gpu/drm/drm_mm.c
> >> @@ -980,6 +980,10 @@ void drm_mm_init(struct drm_mm *mm, u64 start, u64 size)
> >>      add_hole(&mm->head_node);
> >>
> >>      mm->scan_active = 0;
> >> +
> >> +#ifdef CONFIG_DRM_DEBUG_MM
> >> +    stack_depot_init();
> >> +#endif
> >
> > DRM_DEBUG_MM implies STACKDEPOT. Not sure what is more readable to drm
> > maintainers, but perhaps it'd be nicer to avoid the #ifdef here, and
> > instead just keep the no-op version of stack_depot_init() in
> > <linux/stackdepot.h>. I don't have a strong preference.
>
> Hm, but in case STACKDEPOT is also selected by something else (e.g.
> CONFIG_PAGE_OWNER) which uses lazy init but isn't enabled on boot, then
> without #ifdef CONFIG_DRM_DEBUG_MM above, this code would call a
> stack_depot_init() (that's not a no-op) even in case it's not going to be
> using it, so not what we want to achieve.
> But it could be changed to use IS_ENABLED() if that's preferred by DRM folks.

You're right -- but I'll leave this to DRM folks.

> BTW it's possible that there won't be any DRM review because this failed to
> apply:
> https://patchwork.freedesktop.org/series/95549/
> DRM folks, any hint how to indicate that the base was next-20211001?
>
[...]
> > +#ifdef CONFIG_STACKDEPOT_ALWAYS_INIT
> > +static inline int stack_depot_early_init(void)       { return stack_depot_init(); }
> > +#else
> > +static inline int stack_depot_early_init(void)       { return 0; }
> > +#endif       /* CONFIG_STACKDEPOT_ALWAYS_INIT */
>
> We could, but it's a wrapper made for only a single caller...
>
> >>  #endif
> >> diff --git a/init/main.c b/init/main.c
> >> index ee4d3e1b3eb9..b6a5833d98f5 100644
> >> --- a/init/main.c
> >> +++ b/init/main.c
> >> @@ -844,7 +844,8 @@ static void __init mm_init(void)
> >>      init_mem_debugging_and_hardening();
> >>      kfence_alloc_pool();
> >>      report_meminit();
> >> -    stack_depot_init();
> >> +    if (IS_ENABLED(CONFIG_STACKDEPOT_ALWAYS_INIT))
> >> +            stack_depot_init();
> >
> > I'd push the decision of when to call this into <linux/stackdepot.h> via
> > wrapper stack_depot_early_init().
>
> No strong preferrences, if you think it's worth it.

All the other *init() functions seem to follow the same idiom as there
are barely any IS_ENABLED() in init/main.c.  So I think it's just
about being consistent with the rest.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNP4U9a5HFoRt%3DHLHpUCNiR5v82ia%2B%2BwfRCezTY1TpR9RA%40mail.gmail.com.
