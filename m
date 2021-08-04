Return-Path: <kasan-dev+bncBC7OBJGL2MHBBQNFVGEAMGQEHIZIZGI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x737.google.com (mail-qk1-x737.google.com [IPv6:2607:f8b0:4864:20::737])
	by mail.lfdr.de (Postfix) with ESMTPS id CA7D33DFD19
	for <lists+kasan-dev@lfdr.de>; Wed,  4 Aug 2021 10:41:38 +0200 (CEST)
Received: by mail-qk1-x737.google.com with SMTP id b9-20020a05620a1269b02903b8bd5c7d95sf1654038qkl.12
        for <lists+kasan-dev@lfdr.de>; Wed, 04 Aug 2021 01:41:38 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1628066498; cv=pass;
        d=google.com; s=arc-20160816;
        b=PNRYe2DGXJ+s89eNQJBCsO9b2lIKjOCltlyuGWT8Ysnt3XsWfwYwvfiO7xDp9YwUwE
         HXhTnTQ/qBPJJlBA11BBtQs2GnNN49+adkouzO+G/+jcP8OyRtzDNHQ3B/DTfFX1CDHl
         1uXvQ7mGGL3yLpHsT6Yq+hPe/XJ/Rhiij5XD5apwuWDTEjvpcoT+SA/SgstluP/T914e
         d9ZWbwG1M6zZ9PoRmZFb74rCJqIPqmsDACxJAKWm0pa0PjXApIkkQbu9gtxpdQkcODTo
         2EMI3lZI0ljvR48q4GRffyQquiWEJnmsfJD1vMVG54LFLbxvPpDIYkvXfHKl0Dbc1An8
         XbwQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=fjM2IPIA35kbHQd2/5p+5s89/wpbw3TryxRDswlKGb0=;
        b=0OX0LgF+q4i4GH4CcmK6HjTl9YVgUgRQ4B+KGLQN1lveAncg7gtjdSTxoEpVsdM0we
         6wYc+pU+TGGP3Th7YJW17VY82qOr7bxqWd/VlhwvEM5gM1bzliVpmWneHGmXNiIOnMvj
         QWdNO2ZQeQbbp+xOhI1KDdYGuCoBLeM1hj897Utl0XjUbxIEDL8kLuRW805U8eNpzjrG
         nq/VDW2ZmW8VGc/WdIK2q7LUedaCGQNpUbSbL57YZRiNPxb9PQIJtzWKL9yiA2GIczIL
         2XTahiLphGHIPkElWabxSpn0EPuvRMlVlEN+KxviGyHzFn0DsWpFHVoLasjZbwfjxyxg
         0UbA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=CdeSijkP;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32d as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=fjM2IPIA35kbHQd2/5p+5s89/wpbw3TryxRDswlKGb0=;
        b=jelzLPgnqeVH3ocKgciU6eonrNAd1/7EO4JBVY6Tt5KruiHq1s6JxFr+vK9qR19czL
         Y32Ph0rhBBKidJK0v6Ot9jALIp7m2QN89XzxotCUX7F8ulcyIMY6qLvOWgVjKlXAfHcY
         0FhjXMwaxS5rMLhKchrgcp3MHpyXGvihzPpDTvtxp/DUl4a0MrFsMfZkTKQ0eE+EhE/c
         jGF8ARiOkofsIolZ/e8HxRLVrRG2JSV3ltLbQ2vpJ7ItwdBqhWrjagZfMk6/J3XuflMT
         hQ1vpKnv8m3axCmqE1oR+kmLtpLZD02wM2ts9JWgtE4vaLJZYM9I2VCx8peTLBOZHHki
         6DWw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=fjM2IPIA35kbHQd2/5p+5s89/wpbw3TryxRDswlKGb0=;
        b=RV6sw1grw0LIivtWvTwpA5C7kwUvdTmI3hc6/YHVMIPC99o91djIahEmFICoEZiqK9
         Y9SFog7pIys8YqWZOy3gErwhj7hwwnuh4D+layseYubxrUovqJn4GNwcXH3Wr+bSm/F5
         16s8uoEVUL1BaX9j6T+/NLwFzBeGFvtvs23n8iIVgrNYPyjFW0vx/swm+FPzUTCROHo9
         pxsHRLEXTGTCFHotC5sXTcK3KZO7Gas7Io0LC+ETKNd9sxnQ42kmLoLWsBsUITL0mnF3
         uNPpXZ/+ABlj5FEZHiqquA7DJZqQI5oPg8UdredCdenRmXjFyIrmYcofuyFEaW4W7Q0m
         bY2w==
X-Gm-Message-State: AOAM530x8rLAUqVcko3lqY4h6SP6OOzlAdpHSke3kGCCpBRa1pbQ8PLA
	w4HKnSPH6qwiOhCUNktNAjw=
X-Google-Smtp-Source: ABdhPJwApFq7XpYiIpVYkPmatXlL30nZshzShXwzD6MZ9lYHWL4iKURBNVq//keHOsC6z9sQenK8ow==
X-Received: by 2002:a37:354:: with SMTP id 81mr6394567qkd.198.1628066497985;
        Wed, 04 Aug 2021 01:41:37 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:5398:: with SMTP id x24ls697078qtp.3.gmail; Wed, 04 Aug
 2021 01:41:37 -0700 (PDT)
X-Received: by 2002:ac8:6886:: with SMTP id m6mr11934251qtq.255.1628066497524;
        Wed, 04 Aug 2021 01:41:37 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1628066497; cv=none;
        d=google.com; s=arc-20160816;
        b=fEAVxFqPRg1yuSYVC8uM3HqHVziVYZ5kWEjc9H+/EJ6Az6V3XwiuhBASAYISJYQ8yI
         yKA8VJejCxqe6XjWVknGMLtnPuu30dVjLwMIrEaqCpCq+hjqGpECkigY0wM5HAQzeQUk
         f+/dEu+y5GMIaYzabyoh2B1czs1BxVjovH2EkCFKSMBKqtHad5CoSgZ1MF+TGvu5hAGU
         tnG1m2Wb1vukVoGnEA/uQY1dy5fpVyZbEhVwE1lDAyTcovTvLmTWshDVdzhCPMf48WxW
         Z2sE01PuIreFmx1X8V5YVlg+dv26q14LTUbm4P76Jb/PjTeAAGM2mGbvlDIgwrxmKlVm
         s2Gg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Ry/C788Ax+QRjoem679Qz9xjcGp3R8vxYXF3Ug8T/cU=;
        b=glaaKHRLEYfl8mQxyKI/dHJoRTa3ybOGFI6+PzmwEZEhEtcnQIQ45o84kIx6+7nqv0
         yuJmxUvxYCF0Md+eGWAdecEpVJu9ggv3fMTuMLOv8V3WndSOgR7viI0S5XVsOeS0KX1c
         d9dAeQkLsklOBUm2/STZBbu6b9+C3Gic7NNpXoYdZT8j6HBwFs22BM8Fi/qBGCKTwT5W
         x4/zpUxPFAEYtu/+vBODtqI8xkzQsELXm4mLbriUiHFrPmSxsJd0cvu5wvICWxJWkdGj
         l5ffpxfnkK0JMhtGl3dxg6YEr/DooHkGPilp7YksNGADDOdCF3uHIyR+ShCe+socq8Df
         3Arg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=CdeSijkP;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32d as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x32d.google.com (mail-ot1-x32d.google.com. [2607:f8b0:4864:20::32d])
        by gmr-mx.google.com with ESMTPS id m4si82758qkn.1.2021.08.04.01.41.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 04 Aug 2021 01:41:37 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32d as permitted sender) client-ip=2607:f8b0:4864:20::32d;
Received: by mail-ot1-x32d.google.com with SMTP id f20-20020a9d6c140000b02904bb9756274cso1010096otq.6
        for <kasan-dev@googlegroups.com>; Wed, 04 Aug 2021 01:41:37 -0700 (PDT)
X-Received: by 2002:a05:6830:1490:: with SMTP id s16mr2295783otq.233.1628066496794;
 Wed, 04 Aug 2021 01:41:36 -0700 (PDT)
MIME-Version: 1.0
References: <20210804082230.10837-1-Kuan-Ying.Lee@mediatek.com> <20210804082230.10837-3-Kuan-Ying.Lee@mediatek.com>
In-Reply-To: <20210804082230.10837-3-Kuan-Ying.Lee@mediatek.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 4 Aug 2021 10:41:25 +0200
Message-ID: <CANpmjNMAw=rcp_V+G_vjRjArj+09AkOxtC+wUNs-e1RRvfQm6w@mail.gmail.com>
Subject: Re: [PATCH v2 2/2] kasan, slub: reset tag when printing address
To: Kuan-Ying Lee <Kuan-Ying.Lee@mediatek.com>
Cc: Nicholas Tang <nicholas.tang@mediatek.com>, Andrew Yang <andrew.tang@mediatek.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Alexander Potapenko <glider@google.com>, Catalin Marinas <catalin.marinas@arm.com>, 
	Chinwen Chang <chinwen.chang@mediatek.com>, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev@googlegroups.com, linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	linux-arm-kernel@lists.infradead.org, linux-mediatek@lists.infradead.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=CdeSijkP;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32d as
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

On Wed, 4 Aug 2021 at 10:23, Kuan-Ying Lee <Kuan-Ying.Lee@mediatek.com> wrote:
>
> The address still includes the tags when it is printed.
> With hardware tag-based kasan enabled, we will get a
> false positive KASAN issue when we access metadata.
>
> Reset the tag before we access the metadata.
>
> Fixes: aa1ef4d7b3f6 ("kasan, mm: reset tags when accessing metadata")
> Signed-off-by: Kuan-Ying Lee <Kuan-Ying.Lee@mediatek.com>
> Suggested-by: Marco Elver <elver@google.com>

Note, in this case Suggested-by is inappropriate, because I did not
suggest the change in any way (you already had it in v1). I just
commented on the fact that it's missing a Fixes so stable can pick it
up and some clarification.

Reviewed-by: Marco Elver <elver@google.com>

> ---
>  mm/slub.c | 4 ++--
>  1 file changed, 2 insertions(+), 2 deletions(-)
>
> diff --git a/mm/slub.c b/mm/slub.c
> index b6c5205252eb..f77d8cd79ef7 100644
> --- a/mm/slub.c
> +++ b/mm/slub.c
> @@ -576,8 +576,8 @@ static void print_section(char *level, char *text, u8 *addr,
>                           unsigned int length)
>  {
>         metadata_access_enable();
> -       print_hex_dump(level, kasan_reset_tag(text), DUMP_PREFIX_ADDRESS,
> -                       16, 1, addr, length, 1);
> +       print_hex_dump(level, text, DUMP_PREFIX_ADDRESS,
> +                       16, 1, kasan_reset_tag((void *)addr), length, 1);
>         metadata_access_disable();
>  }
>
> --
> 2.18.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNMAw%3Drcp_V%2BG_vjRjArj%2B09AkOxtC%2BwUNs-e1RRvfQm6w%40mail.gmail.com.
