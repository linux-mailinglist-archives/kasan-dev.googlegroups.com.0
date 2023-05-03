Return-Path: <kasan-dev+bncBC7OD3FKWUERBZPTZKRAMGQEVAIA55Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63e.google.com (mail-pl1-x63e.google.com [IPv6:2607:f8b0:4864:20::63e])
	by mail.lfdr.de (Postfix) with ESMTPS id B66EC6F5F5B
	for <lists+kasan-dev@lfdr.de>; Wed,  3 May 2023 21:45:43 +0200 (CEST)
Received: by mail-pl1-x63e.google.com with SMTP id d9443c01a7336-1aad7096521sf27335075ad.0
        for <lists+kasan-dev@lfdr.de>; Wed, 03 May 2023 12:45:43 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1683143142; cv=pass;
        d=google.com; s=arc-20160816;
        b=hzPmNMty9ZqEbN4Xa/WSubMOUH/YyEm+iO0g1MOwRvcP+zGvitA+g6DW3Iww4uL9ls
         QJW1Dm7+/D/yVGr52SZqgG9mcyUX8+HkMob0GsXMTYlHS164+6ysYVaVJGXxA32zjz9i
         /0KZiTJCN4rSUixnsH/temESo4jgYVQJ9D2Hhb8H+D7Y2Mr/33kJdUrAH1NPkC0It21l
         9oOxseATFhvvXtkJPFf22eKIeAfYnSMX8BIqKLNqd5DKjY0vDFhoVcieu8X+SDUN/xAT
         Rxr39RIaxjwatCEZNrJN/BywvnDEgBrixnWA2EyIeQo5XTJpwm+/4T2KlZ1L9LmTLi8V
         LIrQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=rgMbzbNdCfKwX0yAWy8Jqor2RrVIbrFBZ8D/u55Dkj8=;
        b=DjpJ/T9jw+Nmq1zGxepRXjVXWw8KXh52QEWkC+6P5+OaUYHKQTra47dBYG8R2GLTyj
         T5zSV32W+GLjSn35/oPonGVsBx3yyjzgbb0n6k4RRH79xtrJS++MYH6+4mVhQRaDFJXq
         WrUgu4E329f07YeOBdV8r3FKhqUXQMEw/Q+rvxI5UuZ6OZQfn+96AkhF5eCoKlTfpEKB
         4gq5d/IAADAOqAQearRcaIdCcF/gdAKRt0r67stQAgsxd4jrmnlxUJw4XnzbkJSucsrj
         lJi4QSbMyM8HIASrnehrkp8DtDkKWSAPP7rnfCj8Sow2BRqUz9lR+fTvFrEOt7uIKQgB
         WP3w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=mNn8mOJ9;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b35 as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1683143142; x=1685735142;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=rgMbzbNdCfKwX0yAWy8Jqor2RrVIbrFBZ8D/u55Dkj8=;
        b=QY9jbGS7WURWT/7CnQlm7637xhwTBKvzEZNK+KSEEVV6ZHdbspcSflHqteNX5TnIWM
         H32pLZ2ETyMUduTW6UiANAxeZfv0I4vivbSv4t5fznKp0JIKlfaE+JOeT6Za+hawRMYr
         jjb/FgZgYWpKDp67zlSoFARM/3P8n+duyn13833jjkt1r7nh9G+cy5BRcJUHy5MJ5KVi
         hzLPvEoq4Y8rU3uF++da9FAdSiGnMMc/DDTLgBCTrZw6gdLHmMKIPFV4fJrjtmG+16z2
         pgKhVQyt7u1L3NuQ6kOcSOovxTb9+Z/7CyBBYjETTGSfxbCQY3NGd+0FxB3xUiCSNNKb
         x7+g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1683143142; x=1685735142;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=rgMbzbNdCfKwX0yAWy8Jqor2RrVIbrFBZ8D/u55Dkj8=;
        b=ctCj6/DpSmXK4sOga2d1mOiS7RlHcTI/SArYXFmS5H6LiWqxU8ll4/6Ni5lEdPi/SX
         0578ff7jqC9QDIfuHFw4d/9VpxwmiuYfpCXK92BLEudq6q5wIpY41D+wpgvJINtrGo3K
         jL/AaikvgaxfEkChV7Ra9+1DZIJvw662nDlpgrde1KCtGCiUywnkcYFBfZ3EbkpQvrGi
         WJT96g7akjqJwjONUzLF4jkRw0dnMKG6/sEgvBV8OQnczO8kd+Z/SXYG7cFj35pYMMHC
         cxE6ahnOz84tPrr02ywi7by9IlgJOYzq24cBupMZcfeOmldz2p4AyEXglBgFPAmUW6SX
         cwpA==
X-Gm-Message-State: AC+VfDxtBTAN4+cy6E9RGnaGRBuDBiFh8BMdWYnGoL1+hkbYa+WH/XN/
	z+CTR1blZxMyYCxVbQERDkg=
X-Google-Smtp-Source: ACHHUZ4Rq/IPpDqqKDdkXfoyy2Y7osC/tXJSUpYDtuLuEqf9vYGteQo8wcoyJ/8dRbMH/qrRi0/JFw==
X-Received: by 2002:a17:902:ea85:b0:1a2:1674:3902 with SMTP id x5-20020a170902ea8500b001a216743902mr335807plb.10.1683143142046;
        Wed, 03 May 2023 12:45:42 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:ec91:b0:19c:a399:e651 with SMTP id
 x17-20020a170902ec9100b0019ca399e651ls501785plg.1.-pod-prod-06-us; Wed, 03
 May 2023 12:45:41 -0700 (PDT)
X-Received: by 2002:a17:902:7294:b0:1a9:21bc:65f8 with SMTP id d20-20020a170902729400b001a921bc65f8mr1231841pll.11.1683143141343;
        Wed, 03 May 2023 12:45:41 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1683143141; cv=none;
        d=google.com; s=arc-20160816;
        b=zkTAkPB2oZRBCS6VGZy6xKGKEvWdxgjWZStwMVTAdN3kv/0PAEBDvDr5ESda2kc0V0
         YOYN3pBn6AyBW0ETOGAbk2XPCeX26WQ3uftDY6tlLhmR8giLZE8eBoBtrKNeIiR3Pbiy
         rOoZwX15jLjaA2P+78bW1ta4tcw4dtypDYTjWMoTWRY73lWmsSQbArNt1kCHl9pQFbHl
         m+a5OKDIi4TSpPK89epI8VWTBBfe8yIL5XNcaeAbk+MAyL7zPc8i9eJpjPdlQgICtgcg
         2mEMw0RchHkAWwAj30+4pptVfw8ObdpTs6nYPr1s8Qez6IH2lYg9W12OP9Rrew8heIhf
         TN3g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=bq44fWKfzB7azpC5445h4zSgjB+E0XG23Sx5k3P/Wrs=;
        b=hwIuGD3ncAZ+ppgpaorpBL82RwwU/2BvcUaIEx46+MLSQNS26CijP9D1OBC8wNYuzX
         Du7kBD0zq3kF9kLFJiXoASBjAPd3OEdosCg2cM9FYiqOgTmiy52wopT9cjuH7UR8Wvnu
         A26VCounv7W/kS2+KKcDisUxfChT5uK7VHaUzcpUSVhm2JHVHn6drsexWpyxmzA2og1R
         9RYR8NvcokvAW9i9wqgM+Fw9GjgC0vNM3WXFpPttz5BRx/Y4gl6mY8kYHwWixKeNL0sS
         j5Gad2VoZZ7t8WZcyHWjtWZah/g1EC5uycXxSvLTDgYrGOvlHEvk3ZvuK22GLvB+P0WC
         DzJA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=mNn8mOJ9;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b35 as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb35.google.com (mail-yb1-xb35.google.com. [2607:f8b0:4864:20::b35])
        by gmr-mx.google.com with ESMTPS id l11-20020a170902f68b00b001ab132cdbbcsi226108plg.12.2023.05.03.12.45.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 03 May 2023 12:45:41 -0700 (PDT)
Received-SPF: pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b35 as permitted sender) client-ip=2607:f8b0:4864:20::b35;
Received: by mail-yb1-xb35.google.com with SMTP id 3f1490d57ef6-b996127ec71so8165496276.0
        for <kasan-dev@googlegroups.com>; Wed, 03 May 2023 12:45:41 -0700 (PDT)
X-Received: by 2002:a25:4f86:0:b0:b9a:9ad4:1d3 with SMTP id
 d128-20020a254f86000000b00b9a9ad401d3mr18494816ybb.5.1683143140255; Wed, 03
 May 2023 12:45:40 -0700 (PDT)
MIME-Version: 1.0
References: <20230501165450.15352-1-surenb@google.com> <20230501165450.15352-35-surenb@google.com>
 <ZFIO3tXCbmTn53uv@dhcp22.suse.cz> <CAJuCfpHrZ4kWYFPvA3W9J+CmNMuOtGa_ZMXE9fOmKsPQeNt2tg@mail.gmail.com>
 <b8ab89e6-0456-969d-ed31-fa64be0a0fd0@intel.com>
In-Reply-To: <b8ab89e6-0456-969d-ed31-fa64be0a0fd0@intel.com>
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 3 May 2023 12:45:29 -0700
Message-ID: <CAJuCfpGq4CjFLJ=QdQZUJPN72ecvWhVi_vUKrOz5_DvMAM07EQ@mail.gmail.com>
Subject: Re: [PATCH 34/40] lib: code tagging context capture support
To: Dave Hansen <dave.hansen@intel.com>
Cc: Michal Hocko <mhocko@suse.com>, akpm@linux-foundation.org, kent.overstreet@linux.dev, 
	vbabka@suse.cz, hannes@cmpxchg.org, roman.gushchin@linux.dev, mgorman@suse.de, 
	dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com, 
	corbet@lwn.net, void@manifault.com, peterz@infradead.org, 
	juri.lelli@redhat.com, ldufour@linux.ibm.com, catalin.marinas@arm.com, 
	will@kernel.org, arnd@arndb.de, tglx@linutronix.de, mingo@redhat.com, 
	dave.hansen@linux.intel.com, x86@kernel.org, peterx@redhat.com, 
	david@redhat.com, axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org, 
	nathan@kernel.org, dennis@kernel.org, tj@kernel.org, muchun.song@linux.dev, 
	rppt@kernel.org, paulmck@kernel.org, pasha.tatashin@soleen.com, 
	yosryahmed@google.com, yuzhao@google.com, dhowells@redhat.com, 
	hughd@google.com, andreyknvl@gmail.com, keescook@chromium.org, 
	ndesaulniers@google.com, gregkh@linuxfoundation.org, ebiggers@google.com, 
	ytcoode@gmail.com, vincent.guittot@linaro.org, dietmar.eggemann@arm.com, 
	rostedt@goodmis.org, bsegall@google.com, bristot@redhat.com, 
	vschneid@redhat.com, cl@linux.com, penberg@kernel.org, iamjoonsoo.kim@lge.com, 
	42.hyeyoo@gmail.com, glider@google.com, elver@google.com, dvyukov@google.com, 
	shakeelb@google.com, songmuchun@bytedance.com, jbaron@akamai.com, 
	rientjes@google.com, minchan@google.com, kaleshsingh@google.com, 
	kernel-team@android.com, linux-doc@vger.kernel.org, 
	linux-kernel@vger.kernel.org, iommu@lists.linux.dev, 
	linux-arch@vger.kernel.org, linux-fsdevel@vger.kernel.org, linux-mm@kvack.org, 
	linux-modules@vger.kernel.org, kasan-dev@googlegroups.com, 
	cgroups@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: surenb@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20221208 header.b=mNn8mOJ9;       spf=pass
 (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b35 as
 permitted sender) smtp.mailfrom=surenb@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Suren Baghdasaryan <surenb@google.com>
Reply-To: Suren Baghdasaryan <surenb@google.com>
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

On Wed, May 3, 2023 at 8:26=E2=80=AFAM Dave Hansen <dave.hansen@intel.com> =
wrote:
>
> On 5/3/23 08:18, Suren Baghdasaryan wrote:
> >>> +static inline void rem_ctx(struct codetag_ctx *ctx,
> >>> +                        void (*free_ctx)(struct kref *refcount))
> >>> +{
> >>> +     struct codetag_with_ctx *ctc =3D ctx->ctc;
> >>> +
> >>> +     spin_lock(&ctc->ctx_lock);
> >> This could deadlock when allocator is called from the IRQ context.
> > I see. spin_lock_irqsave() then?
>
> Yes.  But, even better, please turn on lockdep when you are testing.  It
> will find these for you.  If you're on x86, we have a set of handy-dandy
> debug options that you can add to an existing config with:
>
>         make x86_debug.config

Nice!
I thought I tested with lockdep enabled but I might be wrong. The
beauty of working on multiple patchsets in parallel is that I can't
remember what I did for each one :)

>
> That said, I'm as concerned as everyone else that this is all "new" code
> and doesn't lean on existing tracing or things like PAGE_OWNER enough.

Yeah, that's being actively discussed.

>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAJuCfpGq4CjFLJ%3DQdQZUJPN72ecvWhVi_vUKrOz5_DvMAM07EQ%40mail.gmai=
l.com.
