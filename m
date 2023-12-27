Return-Path: <kasan-dev+bncBCT4XGV33UIBBROBWKWAMGQE347ECFY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x437.google.com (mail-wr1-x437.google.com [IPv6:2a00:1450:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id B98D381F24D
	for <lists+kasan-dev@lfdr.de>; Wed, 27 Dec 2023 23:10:14 +0100 (CET)
Received: by mail-wr1-x437.google.com with SMTP id ffacd0b85a97d-33697ddbf63sf3119256f8f.3
        for <lists+kasan-dev@lfdr.de>; Wed, 27 Dec 2023 14:10:14 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1703715014; cv=pass;
        d=google.com; s=arc-20160816;
        b=DNnlKUvL7ImVoC79yfHzwehIT7qgA7zKixbp07pITAd+Jq0WXPbpQls7ixkZMf5OZ7
         Crb2RG7aJMWKTRboQv2sNTKKVB7g7pjg8Fe9K2V+OC7KIJJ0Q3l23rdx//0+VdNXlJoo
         0QsvtRr2QkxXNiJgy7dAvC2goIlKTRE/BqBbcLMZMeUsEttwuwd0OznC+FnrLIgX4rt1
         sbZiSOgnOEZOjGnBy+mICWBrh6CK2nD51Yv3BStAFLTWbAkRBumAxu7Fgny8KHZIGeC6
         qQZlUpX/E0KiD0dJpQ4l4VhzGhlxHmRtW+tynIA8o/txpv+CQdaeAYj6A78rXjCcV2wG
         +rTQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :mime-version:references:in-reply-to:message-id:subject:cc:to:from
         :date:sender:dkim-signature;
        bh=A8DYrJbpjqohO1JkSejmF0WwzTWm7rsCJMXF9NVfDQY=;
        fh=alWGelObRkKDSeGH5FNgPzT45v0l97HgM4toqaSmMb4=;
        b=PJ+vWW6Pjt2KvbbqYLxBuhMmoFfX6GF7nsg0tMbTZVlQdwynYkB/EGPuzvlmMOoS9q
         twg4hj9P1AL9kmBikpOlgZrMWdUUs3A9eayO4NQVqW4bySxpAj92sGlygQUKSzrlfrDR
         PA/LZq3M8hqaxwKkfZNG34k2RFZDK9I9w1gA82rru0mhcCdEa6PtfrgPOIsbOXw8rqMr
         TXyWvzNIMI+s01lWfWtkWtk1TFpJ+890Dr9YhZWwBz4rsa8k5LXS1JfEHFR3GkA3RCT8
         a6Um/gzCrF2rFDamD+v/Bey4akeE89V65zSzHOqLIXXWiykIw1rf8tdzT97TkGzwu5Pl
         u1Ng==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=djtb3RQw;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 145.40.73.55 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1703715014; x=1704319814; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:mime-version:references
         :in-reply-to:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=A8DYrJbpjqohO1JkSejmF0WwzTWm7rsCJMXF9NVfDQY=;
        b=Z1qK579Ak4J/ndu33VQBHc9rox3V1RIPepVz/bCvJBZc0sZ/FO4Ve+/jqUqIcxKOF4
         xwn2tqokZnH8vF8cawb+b1gkybt1Yogx9lzTNr8Fcjrf8U3CyU3nsC+7jj10nPAFTdeu
         lj3QHnooKJsiOnSHEZ4KWQUlHub0c14IMqR2kXQQZtwF/VCCM6RFuwYx4T2iuzg9hDqJ
         op3k2H4d8JdCBjt5dAiOlp9K+hSR2MJ2hb4BHqphGAHaDX+mCksxOXTp7xSK8oV3MB/D
         P53/CUXpZM5+/AzEvBPYssrbrA1sUBw6ADSCozGCcJYxg6FavzJQA30DZyqfq+GCqvBC
         Hiiw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1703715014; x=1704319814;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=A8DYrJbpjqohO1JkSejmF0WwzTWm7rsCJMXF9NVfDQY=;
        b=mk7dKLe3MI7VZRbh2jw4KFN+Va3FGCIreLrYoAWtkGPYw5RSOy4EtEt95X66N1wPst
         aa3ob8kSYpkYL1X7q7n0zhpUZN9LCVT79SbrdD5SL5qtNV9GL7V7UfmTqky6xM3OB13T
         +8HQGNxA1xEboZZOIP6vzudqV8b1WsjU7G+NPnQ0PqOU0wumSsfiWZdyjgP/WZHnnNC6
         q6bky3gF8weMukrLsLjwp0snayEQoSZic2lInN1c1gKvMGqLqTI4bqMszDdcUCxt+oO4
         ZXyMkJ74YMF5Cif/AmsUQX5BzWEmKATv+eNcmgEmI7cYVvXboUr1zT26sOhHtd6XhSPl
         lQGA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YyLBrSGWe8C9iLUM61E8PH7lX+QE+5Gab5Ao0uHJTPKNhcvcY2w
	Ygg7SFOVzY9tiRv8Hyb0O+Q=
X-Google-Smtp-Source: AGHT+IGt+endtZFaLD+6niT72WCYpCOwGGrKqLQ575VgVAAztCADKKNfBAQo5UcLU2LAgVn6DI2rhA==
X-Received: by 2002:a5d:690e:0:b0:336:53bb:158 with SMTP id t14-20020a5d690e000000b0033653bb0158mr4286842wru.31.1703715013744;
        Wed, 27 Dec 2023 14:10:13 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:e847:0:b0:336:61a0:bd54 with SMTP id d7-20020adfe847000000b0033661a0bd54ls3140256wrn.2.-pod-prod-01-eu;
 Wed, 27 Dec 2023 14:10:11 -0800 (PST)
X-Received: by 2002:a05:600c:3487:b0:40d:59b7:328b with SMTP id a7-20020a05600c348700b0040d59b7328bmr1471081wmq.242.1703715011413;
        Wed, 27 Dec 2023 14:10:11 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1703715011; cv=none;
        d=google.com; s=arc-20160816;
        b=aF698mLkGC2NyiatqfdqUUGM/194z+sKNL3pgLPp7bewUG+0DJ4lyhZj6Kw1BhPHt1
         lXMgVlnVKanPd4aL4g/MXdOIT7kg2EXKyM94DEB3DvnOAoQ/8Fjl/2s7sJoDcWDfP251
         5Bhm2gaKnNs+7HJVDXXe9FOphbHaPJgBBqAHKL5j5i/wTGkJflu4WSvAOXAbAkktTHR0
         2Xoh5UOtbBOljWw8AELPrCVXXO94oRIqAy+ipQpt91dpDm6X2buR9HhC6++XQ7dLO4sx
         i4cT7ADNFQc9XX4/MV5B5bsIo0ztvyZXNVXBoqOby1I65cJAv/D7h3CZEd3VyWAkSRmr
         YTXQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=mvbWQPtLRjTEXBG8qxYD9GJ79sXogi23Rjf5NvvIXn8=;
        fh=alWGelObRkKDSeGH5FNgPzT45v0l97HgM4toqaSmMb4=;
        b=C/0SwzPDB56m/23AN1G8zJUHKnBR50llsD5JZgvPzLLVCPVdsMyQC/ABMAtfv7jRU5
         QSuPbMgw7wLhaSSa7bO/gK4mchzw84YOW931X0Z3MoFOc6DBz9uo7qcbPe2yFtay4DNr
         gbfjAhphA3tUabpyEQ/b0mQrPRZ8kbCsXd7DJFI1k1DLKKQTw22yDYMD3irJ+MffakZI
         1+6/aOZgu/LZk86GUbEUaFeywp/K6xpDLzuaCX4SoabQQn4eDEWQiQNAPxIL6LI5O4j7
         JyQfR4+xUy9Rkv0XfD50ju/KLr8PgbRyZ7RWWwvg7JReapRe7klESO3PHlamC0y0JnCD
         4mBQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=djtb3RQw;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 145.40.73.55 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from sin.source.kernel.org (sin.source.kernel.org. [145.40.73.55])
        by gmr-mx.google.com with ESMTPS id gi34-20020a1709070ca200b00a2355945814si449459ejc.2.2023.12.27.14.10.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 27 Dec 2023 14:10:11 -0800 (PST)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 145.40.73.55 as permitted sender) client-ip=145.40.73.55;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sin.source.kernel.org (Postfix) with ESMTP id D4A49CE1312;
	Wed, 27 Dec 2023 22:10:07 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id F36D5C433C7;
	Wed, 27 Dec 2023 22:10:05 +0000 (UTC)
Date: Wed, 27 Dec 2023 14:10:05 -0800
From: Andrew Morton <akpm@linux-foundation.org>
To: Andrey Konovalov <andreyknvl@gmail.com>
Cc: kernel test robot <lkp@intel.com>, andrey.konovalov@linux.dev, Marco
 Elver <elver@google.com>, oe-kbuild-all@lists.linux.dev, Linux Memory
 Management List <linux-mm@kvack.org>, Alexander Potapenko
 <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin
 <ryabinin.a.a@gmail.com>, kasan-dev@googlegroups.com,
 linux-kernel@vger.kernel.org
Subject: Re: [PATCH mm] kasan: stop leaking stack trace handles
Message-Id: <20231227141005.14e278c3f08dd0d64004dbf7@linux-foundation.org>
In-Reply-To: <CA+fCnZfZMhkqOvsvavJ-YTddY4kniP+sWFZRYy+nd3+8_C9hPA@mail.gmail.com>
References: <20231226225121.235865-1-andrey.konovalov@linux.dev>
	<202312280213.6j147JJb-lkp@intel.com>
	<20231227132311.557c302e92bdc9ffb88b42d5@linux-foundation.org>
	<CA+fCnZfZMhkqOvsvavJ-YTddY4kniP+sWFZRYy+nd3+8_C9hPA@mail.gmail.com>
X-Mailer: Sylpheed 3.8.0beta1 (GTK+ 2.24.33; x86_64-pc-linux-gnu)
Mime-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b=djtb3RQw;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates
 145.40.73.55 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
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

On Wed, 27 Dec 2023 22:42:40 +0100 Andrey Konovalov <andreyknvl@gmail.com> =
wrote:

> On Wed, Dec 27, 2023 at 10:23=E2=80=AFPM Andrew Morton
> <akpm@linux-foundation.org> wrote:
> >
> > Thanks, I added this fix:
> >
> > --- a/mm/kasan/generic.c~kasan-stop-leaking-stack-trace-handles-fix
> > +++ a/mm/kasan/generic.c
> > @@ -503,7 +503,7 @@ void kasan_init_object_meta(struct kmem_
> >          */
> >  }
> >
> > -void release_alloc_meta(struct kasan_alloc_meta *meta)
> > +static void release_alloc_meta(struct kasan_alloc_meta *meta)
> >  {
> >         /* Evict the stack traces from stack depot. */
> >         stack_depot_put(meta->alloc_track.stack);
> > @@ -514,7 +514,7 @@ void release_alloc_meta(struct kasan_all
> >         __memset(meta, 0, sizeof(*meta));
> >  }
> >
> > -void release_free_meta(const void *object, struct kasan_free_meta *met=
a)
> > +static void release_free_meta(const void *object, struct kasan_free_me=
ta *meta)
> >  {
> >         /* Check if free meta is valid. */
> >         if (*(u8 *)kasan_mem_to_shadow(object) !=3D KASAN_SLAB_FREE_MET=
A)
> > _
> >
>=20
> Could you mark them as "static inline" even?

That's rather old-fashioned.  Nowadays gcc is supposed to work out
whether or not to inline things, and we override that with noinline and
__always_inline.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20231227141005.14e278c3f08dd0d64004dbf7%40linux-foundation.org.
