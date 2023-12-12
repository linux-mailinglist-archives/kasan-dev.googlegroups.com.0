Return-Path: <kasan-dev+bncBC7OBJGL2MHBBXXJ4KVQMGQEUAZM4FA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x113a.google.com (mail-yw1-x113a.google.com [IPv6:2607:f8b0:4864:20::113a])
	by mail.lfdr.de (Postfix) with ESMTPS id 7130480F6AE
	for <lists+kasan-dev@lfdr.de>; Tue, 12 Dec 2023 20:30:40 +0100 (CET)
Received: by mail-yw1-x113a.google.com with SMTP id 00721157ae682-5d0c4ba7081sf71758437b3.0
        for <lists+kasan-dev@lfdr.de>; Tue, 12 Dec 2023 11:30:40 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1702409439; cv=pass;
        d=google.com; s=arc-20160816;
        b=p2sZb++jOCnUC2aSfBtLa65XZCBmWZNneLcP8BuJqkQfY3rL7LjlyL6fBvfKAlKIP9
         4Ia5sTJauVqKwKPxqyURTv1vbF7hYGazzHR6aRmJjaFS0pk830Ga+4cHW/idhrTH/+BW
         IAI+GKwgsG0E+WNWYsLbEiBEgKq/VJFiwbTiUt7FET3GkHCapvNjyillRJnG31etNtFt
         ikVtfKHpzMyfMZ83seQ6FLFnam3gVr0QKeQIYbEOvpopu0rQ8grKvkxD6MLS83iSljgm
         pXipFFhCmRLQjGzQQybnjDm1B8FOudZNv5MOW4Lb3aQJTu3JXtNmiMxBjJVbC7u47BRe
         pUMw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=c71KIDfDey9XGEpZVQEYtPooPzMaRBEKICjYh2b5ySY=;
        fh=U+LkbmzWWCZxhGJEzEnoma1O4OhNrWGKYws0tLC4nok=;
        b=0eMF5WKSlz0CGa2oxJeuAiw/XjaRIMTgrIYGAGHpQ93giOLDn1PjdxUtYMRiHEJwwV
         1rjpLZzCXG4IG6V/nF6FENsDvAgiJRLNtOp25rLnYK25jkYSxP8+DKiOfONs4Vz2sD+p
         Ajk3k0Sa+XmjLrqWDGZmK3ixrzonRHV5VkWzDFX94I2AVz7B5UE+ZOgCkUt2DgCzaAtA
         9J8clu870y4weGWsx4n0wyiVTcuhK+GjfkaWJ5gPpAc3WNb+QdfJ4GUEQxchqtyonsqH
         HjmTELm5AYzi4n7isaBrIc0zAxSvNWwxv9r3IZrL6JvTnBtKUsZzVeMPhS1YI2B3eDTQ
         0kkA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=S6tMAm2j;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::92c as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1702409439; x=1703014239; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=c71KIDfDey9XGEpZVQEYtPooPzMaRBEKICjYh2b5ySY=;
        b=g27Pc2AYhaGzRnN5OuX/syuYLGL4P8w41dqb9BROGUNzTVagqk6ILAD3Kl/gW2Dee8
         wNvSxFgHcHXv5QCGiW7xcNEOmixzNHkwGjodEg5KQ5G8dvuwxtZ8RUtmZ7PuOeMWcAXa
         fUyo5N2vBDOmzrb0dSAImt6s+T1YxiT1gSfa3uIkyTqH5PyAZO/b8clNqKxPBEn1Fozl
         7MYpYBcYOP+ByegHucKAzIbrekIidohQolZkmQtqSmiGQKXVqMLuqkogDWNgkYzp/Qie
         GZVKJaSohG/tgyxN57OoLjy3CShZCbpEDkxUwpxBkT/+bUhr1IM2gK5O5AqP42OQ+JN5
         q7Rw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1702409439; x=1703014239;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=c71KIDfDey9XGEpZVQEYtPooPzMaRBEKICjYh2b5ySY=;
        b=oMQlkKEskhcsiDFT8vgu07j3bSXMns+XMMOY5AdrgtUTZaNCLR3Wx8O5p7SkB/0MwK
         sR6sERBIyi/UQ19zdOJDiuhnOzoUSxngQr6mftSSKpJlfKCpBT2Me8hQprRSHIkTQ1Sn
         8FuiYA0Gz1K8cKy9RRgsq+QNE6lplBGE/5VGloaaVBssa30xroWeTERN65E2Sky+O1Jn
         DL6i9GtOWzMvnKD24G5Do6GgmU/dWLof0jLor/H1QXnS3O6acjdi7u/86MFyJjgirvPY
         5altpxPh6Mfh7GQ2KBPk+bc+qWXVV+q4isGC84pCCjxRru2kmABCJOpqi7aoCu8Xd2l2
         m7wA==
X-Gm-Message-State: AOJu0YxUXVFyHwzcIQkkJtVGJp21FOx8OhNUCpWuaT1ge0Bgzj2dknqi
	eA1slJ5VzELTBuM5COsu4SM=
X-Google-Smtp-Source: AGHT+IF3fBFmvOBpEOFuVr18lMZlOKprUHHs8No7qDI0z9lmfp30DEGE5wQ7HAxz3EvAOPBtnAmSYg==
X-Received: by 2002:a25:8d0c:0:b0:dbc:66a0:a930 with SMTP id n12-20020a258d0c000000b00dbc66a0a930mr3699819ybl.23.1702409439077;
        Tue, 12 Dec 2023 11:30:39 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:418a:0:b0:dbc:b968:47e1 with SMTP id o132-20020a25418a000000b00dbcb96847e1ls960377yba.0.-pod-prod-04-us;
 Tue, 12 Dec 2023 11:30:38 -0800 (PST)
X-Received: by 2002:a81:73c6:0:b0:5d7:1940:b395 with SMTP id o189-20020a8173c6000000b005d71940b395mr5404107ywc.97.1702409438222;
        Tue, 12 Dec 2023 11:30:38 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1702409438; cv=none;
        d=google.com; s=arc-20160816;
        b=i7QZDhhx1QorbnJBmadstHizqD+Snl2c6ggh08fLVgHQXcfq4Nrcwyk7YjUezbH1zt
         wvKKc0HTVlyWXuF3mD5R/a8J4IgG+KJ0owKZO8LJ6DgzRsDkKOy22ZQdvihQsdbpP+xF
         Jx7VRcNMrotVHNAmV83YT4rqdJhd7xhi/TytOrZlhPUBZTZ4esZWdWpSlIZg9SB1nwJd
         0laYuvog2VoBw1aU2+R09RhrVFAbEKMBJUf423FTm2qxvtavh3oCkPIoh38OyHR4LbYa
         B/a/PTMJjvYquTFGk9yVGQmsZPqEuHe6E7kM29nLQDRF5iVEfCvPVSnaOzS/0HFQIBM9
         ocKw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Pcoi2NJ5WlkDrXij7nG/i+1L6bQHIDHmRGBrwHts7ds=;
        fh=U+LkbmzWWCZxhGJEzEnoma1O4OhNrWGKYws0tLC4nok=;
        b=GyL8QyxjeeaLsNvcn76CHufh96FZqDryKafo3cuK5T3YlRbZZR+dWFxb0yMXBFjNrf
         g8OX1qI+mUSHeCuJalVe1s6Cbc9S7XuFaLXD4baYXrtxgRHB5BuW7pZBg2eIqMjyMLGL
         swChYXbFfqkqBHPcygoEPP3YRVspRPUJSQDqA1/holhGsysPnIHGHt2k5era9E6X3Dpe
         RzaRPPhRCjoTVBITduo2hZMeCmQNV+phKYTZmZdVxRIk1WUFjB9X7gqlKE6VF/K4c5Gp
         uot0etc47RRBS0B6AtNCSLTYmlwt1Gsae5Oyuw2+2CkXeopfmF0egL/PuiFxN4YheXo0
         752A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=S6tMAm2j;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::92c as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ua1-x92c.google.com (mail-ua1-x92c.google.com. [2607:f8b0:4864:20::92c])
        by gmr-mx.google.com with ESMTPS id h2-20020a816c02000000b005e29aadb51asi10245ywc.3.2023.12.12.11.30.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 12 Dec 2023 11:30:38 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::92c as permitted sender) client-ip=2607:f8b0:4864:20::92c;
Received: by mail-ua1-x92c.google.com with SMTP id a1e0cc1a2514c-7c51d5e6184so2033196241.2
        for <kasan-dev@googlegroups.com>; Tue, 12 Dec 2023 11:30:38 -0800 (PST)
X-Received: by 2002:a05:6102:510a:b0:462:8ca2:1bb0 with SMTP id
 bm10-20020a056102510a00b004628ca21bb0mr4858842vsb.20.1702409437702; Tue, 12
 Dec 2023 11:30:37 -0800 (PST)
MIME-Version: 1.0
References: <cover.1702339432.git.andreyknvl@google.com> <d0943bd69fdfe27fbda20fde9b143e57c825546f.1702339432.git.andreyknvl@google.com>
In-Reply-To: <d0943bd69fdfe27fbda20fde9b143e57c825546f.1702339432.git.andreyknvl@google.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 12 Dec 2023 20:30:01 +0100
Message-ID: <CANpmjNNTA2qvBTLvA6Qn4HSpsWP6dmMODCFSVtLKZrZfGSAL0A@mail.gmail.com>
Subject: Re: [PATCH mm 3/4] kasan: memset free track in qlink_free
To: andrey.konovalov@linux.dev
Cc: Andrew Morton <akpm@linux-foundation.org>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, Vlastimil Babka <vbabka@suse.cz>, 
	kasan-dev@googlegroups.com, Evgenii Stepanov <eugenis@google.com>, 
	Tetsuo Handa <penguin-kernel@i-love.sakura.ne.jp>, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=S6tMAm2j;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::92c as
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

On Tue, 12 Dec 2023 at 01:14, <andrey.konovalov@linux.dev> wrote:
>
> From: Andrey Konovalov <andreyknvl@google.com>
>
> Instead of only zeroing out the stack depot handle when evicting the
> free stack trace in qlink_free, zero out the whole track.
>
> Do this just to produce a similar effect for alloc and free meta. The
> other fields of the free track besides the stack trace handle are
> considered invalid at this point anyway, so no harm in zeroing them out.
>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

Reviewed-by: Marco Elver <elver@google.com>

> ---
>
> This can be squashed into "kasan: use stack_depot_put for Generic mode"
> or left standalone.
> ---
>  mm/kasan/quarantine.c | 2 +-
>  1 file changed, 1 insertion(+), 1 deletion(-)
>
> diff --git a/mm/kasan/quarantine.c b/mm/kasan/quarantine.c
> index 265ca2bbe2dd..782e045da911 100644
> --- a/mm/kasan/quarantine.c
> +++ b/mm/kasan/quarantine.c
> @@ -157,7 +157,7 @@ static void qlink_free(struct qlist_node *qlink, struct kmem_cache *cache)
>         if (free_meta &&
>             *(u8 *)kasan_mem_to_shadow(object) == KASAN_SLAB_FREETRACK) {
>                 stack_depot_put(free_meta->free_track.stack);
> -               free_meta->free_track.stack = 0;
> +               __memset(&free_meta->free_track, 0, sizeof(free_meta->free_track));
>         }
>
>         /*
> --
> 2.25.1
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNTA2qvBTLvA6Qn4HSpsWP6dmMODCFSVtLKZrZfGSAL0A%40mail.gmail.com.
