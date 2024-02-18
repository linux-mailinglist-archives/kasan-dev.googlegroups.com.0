Return-Path: <kasan-dev+bncBC7OD3FKWUERBY5FYWXAMGQE3AOXEPY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3a.google.com (mail-oo1-xc3a.google.com [IPv6:2607:f8b0:4864:20::c3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 132B98593B3
	for <lists+kasan-dev@lfdr.de>; Sun, 18 Feb 2024 01:44:21 +0100 (CET)
Received: by mail-oo1-xc3a.google.com with SMTP id 006d021491bc7-59fb255d718sf778592eaf.3
        for <lists+kasan-dev@lfdr.de>; Sat, 17 Feb 2024 16:44:20 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708217059; cv=pass;
        d=google.com; s=arc-20160816;
        b=WHItOT3PZOih3XMCQpGNiETlOJbbicl8e+jStCtfm0dQ2IyRMvlZ4Ip9XQU9XC+o0/
         na30/iLsqv70ucxKt7SLxPybAqlpbMzRpbanv2gYbcgBx5ah67p2LiNnuqIeJ0Rlox+c
         M43++2gbNrs8Ez8BHFd1CKKofvj2c5Z8VQ2W+utS5Z4tAVVYurZDb6L7WbyeWTXv7ibe
         GV3lT+6AR6cC53wXZVhKQoZBLGT1iO/6XxWOH30uiG7WcXaQBQeaH1cXvvzwjPPlFLHr
         mrhQVeACzETDT57VBmNDvSo4mwEkDiIgrReH01s8reY8hbWkfFgjh1RzXRg5CRMboBMZ
         SdEA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=IG9mqPDREOqsnb+Do6DrKmc39Cg6sx8pTJrJqLnLgXQ=;
        fh=GiJzzU0X4P40CmZY632TGtr2HplE/29JRu439pCgMTM=;
        b=pilCjI47exmissuOAt/a3Za4pC9dKyp2uCPsBUTbpDTu5FcayIGt5XBdxFFrQqO+HG
         S73r+4dRBPm3jGULP/PRZpvbp9I9lyqHkMBY7vZtFWvhWFmgoz6Nlw4LQY0omYumi0/G
         pHYH3iQOfZB/9xOrsm32x/fMai3XaiC6Nq7kwPTDt9A7U2wl+/xk50DmyinO+pIGoWr/
         wYpYJ4BNMxmf5H7Y/6aqRnYHTxVe41cIPA276E/QW7HEXc1UD4u2KUSA5M+JSklky7Iz
         mFfJdG2TknOzpA2RO4e/EA81q/zrSGxd6XSZ9C0dpX+dTrCnUUheun6WQoFi8gdu+gG8
         SiRA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=DV62NfTY;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::112e as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708217059; x=1708821859; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=IG9mqPDREOqsnb+Do6DrKmc39Cg6sx8pTJrJqLnLgXQ=;
        b=u/FHpjDCV5CFuaKbFaM+ujYDTacRD5BIDblnIA1YYhmVfU4YJdnZgeVc/lUqpKbvoj
         5cDeeZHGLonV8SjdH8P1gZ13YqSYugq6pUqSyy/9KF3PrCVbAzlpBv3T+qZNjqIMjadm
         KoaNiu6YPBT5dQ0Wsn5/7TR2KEzPpUbupXXCuvKRgXsMt+x4STjVnkO4ZIWW77KGLzOB
         uYTzPxrlUZyvXM/2dEJ0BNGvMaZi3EVv1o032DXZhhxMzDCtKMjxJJ9zwgLzzmPyv3hV
         Sl0fh9yjdj6ouE9KQxISF5FEJRpdEx6YSIKte3ee77TTqCy/X/23+qzTEm9P8vfdxVP0
         tT4Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708217059; x=1708821859;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=IG9mqPDREOqsnb+Do6DrKmc39Cg6sx8pTJrJqLnLgXQ=;
        b=hit8Hv/+39fpa+1SLoqG7GNGVQNaOZ9kuxpDUT5p3xBnHk+mEqPEwpad0ekkAURE5w
         wOg4ysJwpuGIrhckmYAHa+WqTzT7M+lpbOIdCvlG+Pg+eqrH0qxvEoZRnp78+/6vsb4K
         RWgmbkf1K9qbnii/T/k+aloOOLuLOru+m+nCk4NBwop0qix9YjZTxYAcmWg87f8sshrp
         ZfPmzkRG9YXaFO/3heu8XedX6Au2j/ltyAhAVtnRMpoi4+oqLqWuMuHe/QnJyxqlB3cw
         DXyrtvc2BK5ZJgUKawSzUhxdaesnB4IMU2xksOuzVI4sPO/p2oaUQZHvWEyOnbtkzCUE
         Q62A==
X-Forwarded-Encrypted: i=2; AJvYcCWVxroZalYvhMETlVVgOiG377sBvwjXAni/nUEQpufcD6XHthtC9Whl2d/vea6EvUe3fdMUvDdne36aJ2tlxWRjkq3CQc+ULQ==
X-Gm-Message-State: AOJu0YxSx7zxL8GF+J7/Oai3aM5/rGTnaOflIo3voDJqP/alpKATlCzN
	L1AECl+BTKA46/o1wBCn9dAB0Ysh2zKxi2jbrEMpQ/sPI4y0GZij
X-Google-Smtp-Source: AGHT+IEuX+D+MeKyNT+hZ2SPTbqsXtn200cSswfTqK/gZgorM9imfrfQh7xvHohS+zrUb9GhT6lKyA==
X-Received: by 2002:a4a:ead2:0:b0:59f:8465:5405 with SMTP id s18-20020a4aead2000000b0059f84655405mr7803584ooh.0.1708217059421;
        Sat, 17 Feb 2024 16:44:19 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:558d:0:b0:598:74b6:da43 with SMTP id e135-20020a4a558d000000b0059874b6da43ls2017873oob.1.-pod-prod-04-us;
 Sat, 17 Feb 2024 16:44:18 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXoZHWkse3ShISCbO5AmuoWu/5wFAfO+IdL7get8wB+c+L1hTsUGlUJH0EaKjr/F6UmB5VARA4N+Nxi0OZhPoQ38GluILOp+8dtMg==
X-Received: by 2002:a05:6830:1cc:b0:6e2:eac0:b671 with SMTP id r12-20020a05683001cc00b006e2eac0b671mr9132898ota.33.1708217058602;
        Sat, 17 Feb 2024 16:44:18 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1708217058; cv=none;
        d=google.com; s=arc-20160816;
        b=gd3ZILtwYWZnNsn1DqKUup0lKSvHZ+ME4OUdsR9FBGeHFYyHBSzlVPgxdLnUCaR0/u
         +wwl8ioFGJnFoELWAaQ9xdDw8oAqbyjvPJGVTxojb5BQDlFR1jzYuiTo5A5Qvayle2vu
         k2JkYAszJm84IZ/R7k7HKHaPKGp3R7Oyopr3EMaavdGj1GUADYlxmS5j72yCZcAdw7Dd
         LhMrENRXDLMrN5hVlPBMHWBFJea4/H989wcCPuy/noJrvPHLRahsz06/609y/w5DZ3gW
         /GHBy7wjf6S68Ag6tOfZPFmKC5lwPFlM9x9MiI7A8cIT5jPwSv0ZgqrFuy1E7xztDTV+
         Q28A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=cFEGcM8EospHG4JmqyUXYLdSoH1Alzf1U0lPv6eqJTM=;
        fh=RiZI5rADsFnFl722adT9E1xJRx1hpuQFCQAT4qL/lTI=;
        b=kV2XHJnPQ6LAa57LbZTZtzfGr5+WHxWqTHxG9FHa90VbEzR0j9NUk5G/o72xbIExYC
         OH2bXA5Lh7VV/qggFEh7X+zlGm5+J2l58YbNm7LKTfz5YLqUbLU0QkRWVsU8HdHmSsoR
         O2Aigk6VVPBm9K1Bfi/gosoU1KEuLo1opMPQusavji85ENt3/7a9QfOw6JR0cj29hz83
         m9+2tKdVNnti96QmcgrLfF2yin6sq2eadCaPFd4/tUwyy/PgcgCI86sG14eSKwfIjNBs
         X3MfsH1ATHOXVEbWu4+yLoECkRw5Ag8JHepIXpo3veAfIkI6AHZSOb9hMwNvHaN5mv4V
         fxTw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=DV62NfTY;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::112e as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x112e.google.com (mail-yw1-x112e.google.com. [2607:f8b0:4864:20::112e])
        by gmr-mx.google.com with ESMTPS id i10-20020a05683033ea00b006e2dc907d04si198506otu.2.2024.02.17.16.44.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 17 Feb 2024 16:44:18 -0800 (PST)
Received-SPF: pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::112e as permitted sender) client-ip=2607:f8b0:4864:20::112e;
Received: by mail-yw1-x112e.google.com with SMTP id 00721157ae682-6080a3eecd4so10966027b3.2
        for <kasan-dev@googlegroups.com>; Sat, 17 Feb 2024 16:44:18 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCUH3onfRX3g4o+OxdEY182Qc3nzU7CBgfMqZQS8tK89g/6b5NM2q/pRLNnDjP65F7gQuYnDlhxpAWJbsaT8URFsDKE8cswEv8xEnQ==
X-Received: by 2002:a81:914a:0:b0:604:f681:a1 with SMTP id i71-20020a81914a000000b00604f68100a1mr9152837ywg.16.1708217057719;
 Sat, 17 Feb 2024 16:44:17 -0800 (PST)
MIME-Version: 1.0
References: <20240212213922.783301-1-surenb@google.com> <20240212213922.783301-19-surenb@google.com>
 <2e26bdf7-a793-4386-bcc1-5b1c7a0405b3@suse.cz> <CAJuCfpGUH9DNEzfDrt5O0z8T2oAfsJ7-RTTN2CGUqwA+m3g6_w@mail.gmail.com>
In-Reply-To: <CAJuCfpGUH9DNEzfDrt5O0z8T2oAfsJ7-RTTN2CGUqwA+m3g6_w@mail.gmail.com>
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Sun, 18 Feb 2024 00:44:05 +0000
Message-ID: <CAJuCfpFvSOtz7DaYdv=FXRvTvoRbMziXctFXqSpP_u97uNsFSQ@mail.gmail.com>
Subject: Re: [PATCH v3 18/35] mm: create new codetag references during page splitting
To: Vlastimil Babka <vbabka@suse.cz>
Cc: akpm@linux-foundation.org, kent.overstreet@linux.dev, mhocko@suse.com, 
	hannes@cmpxchg.org, roman.gushchin@linux.dev, mgorman@suse.de, 
	dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com, 
	corbet@lwn.net, void@manifault.com, peterz@infradead.org, 
	juri.lelli@redhat.com, catalin.marinas@arm.com, will@kernel.org, 
	arnd@arndb.de, tglx@linutronix.de, mingo@redhat.com, 
	dave.hansen@linux.intel.com, x86@kernel.org, peterx@redhat.com, 
	david@redhat.com, axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org, 
	nathan@kernel.org, dennis@kernel.org, tj@kernel.org, muchun.song@linux.dev, 
	rppt@kernel.org, paulmck@kernel.org, pasha.tatashin@soleen.com, 
	yosryahmed@google.com, yuzhao@google.com, dhowells@redhat.com, 
	hughd@google.com, andreyknvl@gmail.com, keescook@chromium.org, 
	ndesaulniers@google.com, vvvvvv@google.com, gregkh@linuxfoundation.org, 
	ebiggers@google.com, ytcoode@gmail.com, vincent.guittot@linaro.org, 
	dietmar.eggemann@arm.com, rostedt@goodmis.org, bsegall@google.com, 
	bristot@redhat.com, vschneid@redhat.com, cl@linux.com, penberg@kernel.org, 
	iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com, glider@google.com, 
	elver@google.com, dvyukov@google.com, shakeelb@google.com, 
	songmuchun@bytedance.com, jbaron@akamai.com, rientjes@google.com, 
	minchan@google.com, kaleshsingh@google.com, kernel-team@android.com, 
	linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org, 
	iommu@lists.linux.dev, linux-arch@vger.kernel.org, 
	linux-fsdevel@vger.kernel.org, linux-mm@kvack.org, 
	linux-modules@vger.kernel.org, kasan-dev@googlegroups.com, 
	cgroups@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: surenb@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=DV62NfTY;       spf=pass
 (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::112e
 as permitted sender) smtp.mailfrom=surenb@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
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

On Fri, Feb 16, 2024 at 4:46=E2=80=AFPM Suren Baghdasaryan <surenb@google.c=
om> wrote:
>
> On Fri, Feb 16, 2024 at 6:33=E2=80=AFAM Vlastimil Babka <vbabka@suse.cz> =
wrote:
> >
> > On 2/12/24 22:39, Suren Baghdasaryan wrote:
> > > When a high-order page is split into smaller ones, each newly split
> > > page should get its codetag. The original codetag is reused for these
> > > pages but it's recorded as 0-byte allocation because original codetag
> > > already accounts for the original high-order allocated page.
> >
> > Wouldn't it be possible to adjust the original's accounted size and
> > redistribute to the split pages for more accuracy?
>
> I can't recall why I didn't do it that way but I'll try to change and
> see if something non-obvious comes up. Thanks!

Ok, now I recall what's happening here. alloc_tag_add() effectively
does two things:
1. it sets reference to point to the tag (ref->ct =3D &tag->ct)
2. it increments tag->counters

In pgalloc_tag_split() by calling
alloc_tag_add(codetag_ref_from_page_ext(page_ext), tag, 0); we
effectively set the reference from new page_ext to point to the
original tag but we keep the tag->counters->bytes counter the same
(incrementing by 0). It still increments tag->counters->calls but I
think we need that because when freeing individual split pages we will
be decrementing this counter for each individual page. We allocated
many pages with one call, then split into smaller pages and will be
freeing them with multiple calls. We need to balance out the call
counter during the split.

I can refactor the part of alloc_tag_add() that sets the reference
into a separate alloc_tag_ref_set() and make it set the reference and
increments tag->counters->calls (with a comment explaining why we need
this increment here). Then I can call alloc_tag_ref_set() from inside
alloc_tag_add() and when splitting  pages. I think that will be a bit
more clear.

>
> >

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAJuCfpFvSOtz7DaYdv%3DFXRvTvoRbMziXctFXqSpP_u97uNsFSQ%40mail.gmai=
l.com.
