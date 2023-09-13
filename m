Return-Path: <kasan-dev+bncBDW2JDUY5AORBY6YQ6UAMGQEBKIGL4I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x840.google.com (mail-qt1-x840.google.com [IPv6:2607:f8b0:4864:20::840])
	by mail.lfdr.de (Postfix) with ESMTPS id E2ED379EFDA
	for <lists+kasan-dev@lfdr.de>; Wed, 13 Sep 2023 19:07:48 +0200 (CEST)
Received: by mail-qt1-x840.google.com with SMTP id d75a77b69052e-4121afec295sf25011cf.0
        for <lists+kasan-dev@lfdr.de>; Wed, 13 Sep 2023 10:07:48 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1694624868; cv=pass;
        d=google.com; s=arc-20160816;
        b=dEbQX6BwfmERVXDAtW5KkfiH7R4+gKhc6p4OaKhRdjgUo7s7klPrArc40++ZNkyajG
         RjrGpWoWrF2gSLTdZ6oz6lTUsPJew48WeVtTHSi42jJNdfEy/shKq0hadJbvD8E4UynV
         uzTWxBEEY1ci01A/X9O9sUfWmh09t2g/BffIa3O352zkwPIzPLyR38j4Esck6WcTShGz
         FSptVSEdop7xvRbKiAla8vWypEHtOxrsBUsZOQU0GAkFv7UklDVUlEp77dAutaJJtgg6
         jp1bzaS9bJMjwgkbK0SUc/rOvqMJzViBtI52cHwYgHaFHarxEQ24FRwHkI3BE8ZL7lWG
         xgjg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=Y90dYlQS2zu0wk2zflRmbF7HYb2oumQcJpkDtEBVU1Q=;
        fh=vhyMgzwtVf8Cd+Xluz+kIPeaZIksHpPCItLJmpWVnQM=;
        b=sOYmhdwqa5MgHtKuqBHypq0BYWrn4CpSk/V27Aur8nK6BqmhiOGzr0aK3XRbUGF+8k
         Qaw9B6/jFkO5mzcADEMZ2zQDnOu2vMqMcCNM5ZWq5wwFuEIwQFrRV9msQIWrGP5u3iJW
         chiehJeZLATqxX4zcQE9M53WFJ5Er+3KIVTHpJRnSlGxwuDKWDxZuW9+B6V5ZHUKw9Vl
         0YbEVIEAP1DQbtmkZ/JDzXFkZVFpVuVHF93G2HngyhsuNDvJXtmV0sYuaGSqQXEFDT2T
         KdwKaBJxhXYiJEonUwXS3c/5NUX/Nk+wRgcgj0D6qtzqHxi1CH5wGsr5QIEfWoJtSUjh
         7nRA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20221208 header.b=STi6vYBM;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::431 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1694624868; x=1695229668; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=Y90dYlQS2zu0wk2zflRmbF7HYb2oumQcJpkDtEBVU1Q=;
        b=Us7ejn5I3Q4MlUKZLM8OfV52YVjvsSqE0xoq1sPa8Tl9CiAWWZ82k7y85Qb6YeDOqC
         LreUrMLJQxFrKvVS9yk+f5qTeJRXEPyXobU1Wer6FcbcKvPs5wODMuDo1uUR77Ts+eMt
         eCN92ZhMfAVB4+AD+YLIK5+KMal7s+KubpazNas2gPfDlTbZRlIm9r9YrejhE2yyaXAN
         7zxnEBzJLh9yD82A4gvAhB3I9k0wE7dt5nXTzTvD8qHW1PXTqpZvD7QP2CMF7lVFOm7p
         KahFvccqVF6fvxbHnttZC+4szzIHNMSHw5LxyCtESLZ+OM1HUCTYJhPo4RfQL8MrgeID
         IZeg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20221208; t=1694624868; x=1695229668; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=Y90dYlQS2zu0wk2zflRmbF7HYb2oumQcJpkDtEBVU1Q=;
        b=c+FwenPBAUa5t340gWTQqp6hSkpu+wLEZiS+zpUqD6znOH4en5qw8q8quHp/WBApJN
         eHzpSPyXWm0oUT5/5SXTia7TB+NaDlZqqK323yvtdbNX7gtbZ+mCVf/YQTimp8f7GP6Y
         6asE8wTWnSkuLjIFgoh2lH8jwfiMyy6TJcpfbU02XH6FuzSgTnJxA3SA2omzlEmb7c8g
         NcDcjh1tjXEOtc+0h+6e9fkcngHmV4Q+FVN4ROF9yjnlfgN09VGagLaciT2ayFgoWPgT
         9qwCu+/Ov930TOrXveu4exYTH8MGz90jmrRyBgOSshXJSguPMUaGKb4KdnE0omD/eAqw
         /jyw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1694624868; x=1695229668;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=Y90dYlQS2zu0wk2zflRmbF7HYb2oumQcJpkDtEBVU1Q=;
        b=D5F6X+Oiz2LELOlCFID46QouRvNeJziN7QMg4fqLMGfX2+Q4fjcQpxyT9TOxA9lrXR
         ma/spAR8Nkfzxu8kp3lSTTi8vo2Uyr843oMPLzW9I5x9O5R0+2r/gxsVsn9RGTsEwe/l
         8r0OF/RCYLZjxz8q2m57+sqkgBgjOpPW/O9GvSW3Mo6cYjCN9Qdxp26noAXt4ZzTod1k
         bJX7Use4sflcGQ6Dh1V753ZrqbjkoD84GonAJst/npmqeUeYHtfvFPRh/w3ffuy/iY3I
         fUjMSRkmp0aNZu8XmPrmJarFEIUBbpRM3lclLg4ud8ACNNRdQismw1IKrR13r7BZ+L8p
         cUnA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YzMf46jw2JyoxWyIWuRqqNYK1kWLE9ZDyVv+2uPcNTpjG4ZFtsd
	Vz92yKvykPSQpv1cu9b3bDI=
X-Google-Smtp-Source: AGHT+IEkM+BEzoCUKil30BO1h/aahml678iCg1vV2Ekrnak1ZeMvASdJoRCowRp+2G922d+fku6Amg==
X-Received: by 2002:a05:622a:60b:b0:412:9cd:473b with SMTP id z11-20020a05622a060b00b0041209cd473bmr333225qta.4.1694624867684;
        Wed, 13 Sep 2023 10:07:47 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0c:9b09:0:b0:635:e560:ecc9 with SMTP id b9-20020a0c9b09000000b00635e560ecc9ls388688qve.2.-pod-prod-08-us;
 Wed, 13 Sep 2023 10:07:47 -0700 (PDT)
X-Received: by 2002:a1f:6241:0:b0:495:bf04:89f9 with SMTP id w62-20020a1f6241000000b00495bf0489f9mr2516826vkb.10.1694624866913;
        Wed, 13 Sep 2023 10:07:46 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1694624866; cv=none;
        d=google.com; s=arc-20160816;
        b=UfKeb4GuVCEM0E3tEdpT4R+p2DLVHK3DF8t/dNsUrNvtAs+3axdHIqKTbPsomovnob
         /dmMu6Bf2Vr8GMDI/OqJ8DXkjeuxpI1itz2XEX+WgYatsuo32kfPVSXwm7LbdslcANCM
         vmjlI/iMe//FpItaJzFkHVodnC8q80yaBcBCjSaBVEs/l81f2RWdYdso+MOj8S9qXy7k
         bOfSsaD+ef7QrfNUrWjWyn5sbqazA6rCflPrxGcadHUK+fVon2n+oyYPcqACsKYdWfp3
         Or5CIjcW9icfHx2Q2Vf2YMCQD5N5/1bZaP9Jk4sScyxS0f4EKMWTXT2yD27VURFKjs8V
         xSmw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=RKjqLRHBaK4WXz9nWdn/oC9Zz8hGXtmarbif3LIzAxY=;
        fh=vhyMgzwtVf8Cd+Xluz+kIPeaZIksHpPCItLJmpWVnQM=;
        b=sFyI466YldUzCh77xweZ2GAAs63idj4ShwEM8XcAR5Owc4x6fUR6Nv9lm5DdKaY2cz
         Rg5IqHr18Hz1WAQKZmvOzUg3OQ9ZYsOZg9A+8Iy8omzWP2XpLV2SVuj0Ighn1WOo1Li6
         fmD8B4ThzGrAIvAKgT0YUCOubHJM65a5FgMw6Fd5J59iIXgQb+yt/yn6Zg6VPC/wWdA8
         UBgdKlVSLnwYGjllugrJOpPzdhlGXEJ3mspiUcIEQK+d4qUQZVyVLbDH9wZTzIY5dwtz
         Pm3k6YjHhWxa0TmlOJNZ6J4xzZcqW2J3Gb9QEz4x2/pseyhZU3+rInKXgcXedhE4fNWm
         ZxXA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20221208 header.b=STi6vYBM;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::431 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pf1-x431.google.com (mail-pf1-x431.google.com. [2607:f8b0:4864:20::431])
        by gmr-mx.google.com with ESMTPS id n69-20020a1fa448000000b004936ba690ffsi1597030vke.2.2023.09.13.10.07.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 13 Sep 2023 10:07:46 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::431 as permitted sender) client-ip=2607:f8b0:4864:20::431;
Received: by mail-pf1-x431.google.com with SMTP id d2e1a72fcca58-68fe39555a0so2278574b3a.3
        for <kasan-dev@googlegroups.com>; Wed, 13 Sep 2023 10:07:46 -0700 (PDT)
X-Received: by 2002:a05:6a20:9187:b0:149:122b:6330 with SMTP id
 v7-20020a056a20918700b00149122b6330mr3471096pzd.10.1694624866041; Wed, 13 Sep
 2023 10:07:46 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1693328501.git.andreyknvl@google.com> <e9ed24afd386d12e01c1169c17531f9ce54c0044.1693328501.git.andreyknvl@google.com>
 <ZO8KzKWszioRKrks@elver.google.com>
In-Reply-To: <ZO8KzKWszioRKrks@elver.google.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Wed, 13 Sep 2023 19:07:35 +0200
Message-ID: <CA+fCnZdGuJmGZDUDaX7=NqydApbox4hMrOZL9_znL=9KpLpQhg@mail.gmail.com>
Subject: Re: [PATCH 13/15] stackdepot: add backwards links to hash table buckets
To: Marco Elver <elver@google.com>
Cc: andrey.konovalov@linux.dev, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, 
	Evgenii Stepanov <eugenis@google.com>, Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20221208 header.b=STi6vYBM;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::431
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Wed, Aug 30, 2023 at 11:24=E2=80=AFAM Marco Elver <elver@google.com> wro=
te:
>
> > diff --git a/lib/stackdepot.c b/lib/stackdepot.c
> > index a84c0debbb9e..641db97d8c7c 100644
> > --- a/lib/stackdepot.c
> > +++ b/lib/stackdepot.c
> > @@ -58,6 +58,7 @@ union handle_parts {
> >
> >  struct stack_record {
> >       struct stack_record *next;      /* Link in hash table or freelist=
 */
> > +     struct stack_record *prev;      /* Link in hash table */
>
> At this point this could be a normal list_head? Then you don't have to
> roll your own doubly-linked list manipulation (and benefit from things
> like CONFIG_LIST_DEBUG).

Yeah, I think this makes sense. Will do in v2. Thanks!

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BfCnZdGuJmGZDUDaX7%3DNqydApbox4hMrOZL9_znL%3D9KpLpQhg%40mail.=
gmail.com.
