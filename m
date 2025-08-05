Return-Path: <kasan-dev+bncBCQ2XPNX7EOBBLMYZDCAMGQEXIYKXAY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53b.google.com (mail-ed1-x53b.google.com [IPv6:2a00:1450:4864:20::53b])
	by mail.lfdr.de (Postfix) with ESMTPS id E64FBB1B544
	for <lists+kasan-dev@lfdr.de>; Tue,  5 Aug 2025 15:50:46 +0200 (CEST)
Received: by mail-ed1-x53b.google.com with SMTP id 4fb4d7f45d1cf-60c9d8a169csf5465419a12.0
        for <lists+kasan-dev@lfdr.de>; Tue, 05 Aug 2025 06:50:46 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1754401840; cv=pass;
        d=google.com; s=arc-20240605;
        b=h3jm5mE6SvCTCnKECjHyL2E2DgTljU55d9cU3DKXHbPtHuvYd4sjGSRJrrCmCc28m8
         fJNiB2MuU7j73pFiS7rxqOp7fxP1BV2mexblsEr7qe53byd3uzjzXXlFEsdakOYIn5Zr
         lmGXtLz9vcRLEYOk3FgAAOIgy7rYMrbk5fyiFKa/DTaZ3v518N8KizyZu4jP4/HL6UQV
         +SpFL7qQlvrvXVN3w9Fys4swAjX8F6ykVrOM+CUwub+jVVl12IxgGYcYS1GPBXvSS0jH
         qa52DKQDjFnDFt4QDbKxRqscFDF3HDViuVfEdm8gQRoIk2rtmkbFK+xetgO5NzSJgVQe
         rRZQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=L8+g1BM4rOdZ6NmT7lsLw1Oh6q7tu0JRR8S0Smsp/6E=;
        fh=NXE0o5dFYEYBT+jMY4A9aH4ohZQhqyfbdzDxR2fezmw=;
        b=BQ4dyMWDdfxRfakACCxlTm/nwSsMNZ95/hRe/VU2xp6RBfS+dsVU39CAnhVL3qnN8V
         zMjDeS5t2S5AlgrftMIYtACgwvJOqc+X5tyJJkHYyhrWZoartaQ6qU41T+rnt8GlOLoC
         vH6zZAvBg8BYj/BFL7TRw/ZpUkt1XMCrhWuDN6J6bs3O6P+Pig6G3mepIe9/D6FyxQtV
         V/oHlu3j1B6JhNqfUMjCBuueyulM5Bu4bKDvR1VzKp57RqOKz/2ZtUn8cr2p89Z5hz4U
         XGjX4IpUKZLFehmKj8rvU2/o/0VZKax5+rnmSlJrAVt1WQ9HPGksLe4HEIVoM2CArjq2
         D35Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=MfUVZFDo;
       spf=pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::530 as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1754401840; x=1755006640; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=L8+g1BM4rOdZ6NmT7lsLw1Oh6q7tu0JRR8S0Smsp/6E=;
        b=EUnC97J4IeuYPicsBM3vN6I7EfPqEfo91NVc+MfWyzvSMsCtSa1tmW3E6F8bkMLGh3
         00c+ABcXXZ+9bYleOLd41B1Vn4IyHiu6XUXA7WIiuwfjdj1MZXkeARaQVMYTp5zO010P
         v5bT286ufF4aNjnhE6pg4hgErdOyvBVWhc1z4NbwMoTKmSkoPhpXFUSlInQYMXhKZuU+
         aNoPtVw6Rf6JkPp9Dp0GkG41YlKIAhC82P7tPa2kdBvwjJ+LGRjrIVK9cZA39qTNo/53
         vkdel88jJvKNteNoJiyuTBPT8tm68uj/Ml5XGWHNR69CscQt1QlXHn9tYnMl+kOzF0Wv
         VQAQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1754401840; x=1755006640;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=L8+g1BM4rOdZ6NmT7lsLw1Oh6q7tu0JRR8S0Smsp/6E=;
        b=uv1YGeimxejFWj/pPUysC+VA2WHzac8FHJec0EwlQa/WawFgwS9O39dChRKKIly/aP
         KvBqAS+4Mqd55D57pK2e1hRcf2DKUMbH9E5Ggna6uCdP4rYUtXQDSz1R0VCN3F5Zsfga
         6HreOUH9VoPp2QrPOBaX0YHx88yJlOWVBYmlk5MbobLN0RqNOkjxFErXlms8+QZG22QP
         +RTDaPQw37or/NWsptazn7L+GV7jG/iZNNZeqtFcC5nX3GGwGQStKIJa0XYY6ldbYS/l
         fAlzgp0fNTTcmxIxseSZ0Ev+X5BcSzIP8AnWO05zA4TJK1d2yMNSrUpbpoMoiEsI1T7i
         yIfw==
X-Forwarded-Encrypted: i=2; AJvYcCU9p+RPkqFDgDbs8yp7Ri6hV+yn9DarbKDMYCK7aQi/pPNsarc9iqsDiBgC6wf9RnhM1MlvIw==@lfdr.de
X-Gm-Message-State: AOJu0YwGT2K2dPfcJnx79PKDEdVywwge5TIa7L9syfNB0JyTZIQmcLMi
	iYkt812lHBKU2jPNiLFhjdE7z2oUoKqn9O0t2TsyfimGDAbCDgBtJEj/
X-Google-Smtp-Source: AGHT+IFb14Tl63sKdIdd2zM041xmdtMPB+iHdTZ9RfGwrYVlSdBMevHMW34mBQ52O4uMoQO8Pn/Niw==
X-Received: by 2002:a05:6402:210b:b0:615:b7d8:72ed with SMTP id 4fb4d7f45d1cf-615e715da35mr12417480a12.28.1754401838068;
        Tue, 05 Aug 2025 06:50:38 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZc65q9MLmM9NUiZF5xs9tPC0UkCuUFNOVV5ko2Sldpaig==
Received: by 2002:a05:6402:2353:b0:605:b948:8854 with SMTP id
 4fb4d7f45d1cf-615a7b16e80ls5295720a12.1.-pod-prod-06-eu; Tue, 05 Aug 2025
 06:50:35 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVlE4vQzfvi6DVDumbhdF1eYTJVYL1h6psVJ1gCdID+H649iWN35jntOa0k5tK/EaK7UIgtHmqAwug=@googlegroups.com
X-Received: by 2002:a05:6402:270a:b0:615:cc03:e6ae with SMTP id 4fb4d7f45d1cf-615e6eb6a33mr11764932a12.6.1754401822683;
        Tue, 05 Aug 2025 06:50:22 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1754401822; cv=none;
        d=google.com; s=arc-20240605;
        b=MkMgrv3in8VxznVvgZ0p//uX3ugN4qZSLspDdj7nLwfrQ2ut8JkYSkI94KAz5u1swi
         WfRhtWEFsxBqDBsdSqaLqfU8Cz39WG4Bw6dv5A4enqrbm56To4bWWB38zryVy0ZlF+yt
         Mga5o65KZL2ZeQ1kyOEZ7CnrOyQ9f8OQCDHRtYU/5Xodg1Sf4y+8Ertu0b84oBFSqYnO
         dNtuP6PgdEbv8YQb0HIwuiQOsl1rhUw2+WUzYAenqPYuRODxQxzHrT96qspWtfAvEZrf
         FX5+IyTr/mkDpFUxO+4bINvxpjMpk0dgGJfH8Hw6xgZRNuLGD0V8GLQ0n9Ik8V958K99
         GoAg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=OM5Sak9VYNXA/4oFKKbDTzSyVDrMPAA9ankjux7yv0E=;
        fh=h9c5vPioR4g51rWCggcgTWkT42s7lUpOlNo7Zh/YynU=;
        b=lpYzjxzBVGUj8lICD7m8z2vMVOtsqhmr38C0zgZ2KYhwWVD9FFm2a3V+6ZaOSLhpea
         IHQ4n1dDOroYQ2Y+fIqAbIMNXJ9xSi1bYiWrLUED6eDjjWaUUFEDdrHynL49mC1tJqd4
         pQI1FYeXNcG6dMLc4U/Ncc4TTX74QkPMwghGAmFjK4Rcx4Ll96payk4tElaFZMcALMtd
         xKaLpBWz3DjRyRyFi2/fnYWjw05+mowoo8AOKdPdxOEbPat23EjQSJQ+lTviqYGAmYkF
         bvn6PNdzgDhLKhquwksiwPY2nBJ7nYCDjxVHu+vgIT1SL6LTlJ75bztid5pj7NCJoOVT
         bx9A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=MfUVZFDo;
       spf=pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::530 as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ed1-x530.google.com (mail-ed1-x530.google.com. [2a00:1450:4864:20::530])
        by gmr-mx.google.com with ESMTPS id 4fb4d7f45d1cf-615a8f80accsi334052a12.2.2025.08.05.06.50.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 05 Aug 2025 06:50:22 -0700 (PDT)
Received-SPF: pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::530 as permitted sender) client-ip=2a00:1450:4864:20::530;
Received: by mail-ed1-x530.google.com with SMTP id 4fb4d7f45d1cf-6154c7b3ee7so14083a12.0
        for <kasan-dev@googlegroups.com>; Tue, 05 Aug 2025 06:50:22 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWkqE02UVWlX1eHA+KEYm3sMoPJBuvag+H5rB5akqiLebIrlUYjNmlqk0sRCka/a2Q3En9vJ2X37gc=@googlegroups.com
X-Gm-Gg: ASbGncv7UGlWIzy9SvmMynbbvQN3g6YlrQMboQONWuK2ZBiKTy38MeOZdP3bZ9II8dv
	wPlKAMPc2GSjEa8eofGy2jWiSqXQ7huFZ/iZ5hdtV5k2bFSRnjt184TBOQudDiVckpSdNRpDh+4
	dOa6eMdmZnCKulieeUzQpcrnqmXmcq6Oa4c1gIsTPjMhiEs/LvDfwMASzO/WXHmybiK2mXXnN5e
	ZQ+oWPCMIVGvnbQ5p1mEno+9vodeF+Azxg=
X-Received: by 2002:a05:6402:325a:b0:615:3fe5:a925 with SMTP id
 4fb4d7f45d1cf-617848372e4mr53602a12.7.1754401821913; Tue, 05 Aug 2025
 06:50:21 -0700 (PDT)
MIME-Version: 1.0
References: <20250804-kasan-via-kcsan-v1-0-823a6d5b5f84@google.com>
 <20250804-kasan-via-kcsan-v1-2-823a6d5b5f84@google.com> <CANpmjNOJxJ+kM4J7O5J8meSD_V=4uAa6SwFCiG83Vv_8kn56sw@mail.gmail.com>
In-Reply-To: <CANpmjNOJxJ+kM4J7O5J8meSD_V=4uAa6SwFCiG83Vv_8kn56sw@mail.gmail.com>
From: "'Jann Horn' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 5 Aug 2025 15:49:45 +0200
X-Gm-Features: Ac12FXy65DGv8cn62c1xeecD1pKxLWVWZniqqA9hR2KQYd_-HuNZowNKVDRPddo
Message-ID: <CAG48ez2_HrKjRuH+5KSB+vK_9dGeNnh2O6qAN0ePr4BRnt3xzw@mail.gmail.com>
Subject: Re: [PATCH early RFC 2/4] kbuild: kasan: refactor open coded cflags
 for kasan test
To: Marco Elver <elver@google.com>
Cc: Masahiro Yamada <masahiroy@kernel.org>, Nathan Chancellor <nathan@kernel.org>, 
	Nicolas Schier <nicolas.schier@linux.dev>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Christoph Lameter <cl@gentwo.org>, 
	David Rientjes <rientjes@google.com>, Vlastimil Babka <vbabka@suse.cz>, 
	Roman Gushchin <roman.gushchin@linux.dev>, Harry Yoo <harry.yoo@oracle.com>, 
	linux-kbuild@vger.kernel.org, linux-kernel@vger.kernel.org, 
	kasan-dev@googlegroups.com, linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: jannh@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=MfUVZFDo;       spf=pass
 (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::530 as
 permitted sender) smtp.mailfrom=jannh@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
X-Original-From: Jann Horn <jannh@google.com>
Reply-To: Jann Horn <jannh@google.com>
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

On Tue, Aug 5, 2025 at 2:31=E2=80=AFPM Marco Elver <elver@google.com> wrote=
:
> On Mon, 4 Aug 2025 at 21:18, Jann Horn <jannh@google.com> wrote:
> > In the Makefile for mm/kasan/, KASAN is broadly disabled to prevent the
> > KASAN runtime from recursing into itself; but the KASAN tests must be
> > exempt from that.
> >
> > This is currently implemented by duplicating the same logic that is als=
o
> > in scripts/Makefile.lib. In preparation for changing that logic,
> > refactor away the duplicate logic - we already have infrastructure for
> > opting in specific files inside directories that are opted out.
> >
> > Signed-off-by: Jann Horn <jannh@google.com>
> > ---
> >  mm/kasan/Makefile | 12 ++----------
> >  1 file changed, 2 insertions(+), 10 deletions(-)
> >
> > diff --git a/mm/kasan/Makefile b/mm/kasan/Makefile
> > index dd93ae8a6beb..922b2e6f6d14 100644
> > --- a/mm/kasan/Makefile
> > +++ b/mm/kasan/Makefile
> > @@ -35,18 +35,10 @@ CFLAGS_shadow.o :=3D $(CC_FLAGS_KASAN_RUNTIME)
> >  CFLAGS_hw_tags.o :=3D $(CC_FLAGS_KASAN_RUNTIME)
> >  CFLAGS_sw_tags.o :=3D $(CC_FLAGS_KASAN_RUNTIME)
> >
> > -CFLAGS_KASAN_TEST :=3D $(CFLAGS_KASAN)
> > -ifndef CONFIG_CC_HAS_KASAN_MEMINTRINSIC_PREFIX
> > -# If compiler instruments memintrinsics by prefixing them with __asan/=
__hwasan,
> > -# we need to treat them normally (as builtins), otherwise the compiler=
 won't
> > -# recognize them as instrumentable. If it doesn't instrument them, we =
need to
> > -# pass -fno-builtin, so the compiler doesn't inline them.
> > -CFLAGS_KASAN_TEST +=3D -fno-builtin
>
> Has the -fno-builtin passed to test if
> !CONFIG_CC_HAS_KASAN_MEMINTRINSIC_PREFIX become redundant?

... oh, bleh, good catch. Somehow I had convinced myself that
scripts/Makefile.kasan did this, but no, that only sets -fno-builtin
for uninstrumented code... I misunderstood what was going on here.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
AG48ez2_HrKjRuH%2B5KSB%2BvK_9dGeNnh2O6qAN0ePr4BRnt3xzw%40mail.gmail.com.
