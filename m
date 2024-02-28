Return-Path: <kasan-dev+bncBC7OD3FKWUERBZXM7WXAMGQEWRGAU6A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3b.google.com (mail-oo1-xc3b.google.com [IPv6:2607:f8b0:4864:20::c3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 1428286B6C6
	for <lists+kasan-dev@lfdr.de>; Wed, 28 Feb 2024 19:07:36 +0100 (CET)
Received: by mail-oo1-xc3b.google.com with SMTP id 006d021491bc7-5a0494c8929sf194eaf.1
        for <lists+kasan-dev@lfdr.de>; Wed, 28 Feb 2024 10:07:36 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1709143654; cv=pass;
        d=google.com; s=arc-20160816;
        b=S38qAu6/7s2c3jkrrvRRiKIw/NHueV4c2InF8ih0bgT7Bcw7WrSmWLcy/sAVAQbmG3
         74zXzn5qgPIUw4Ml8jsH9j48givxUE+m/eitElhGS+8NOUa60m7ZhkhVjkVOqVp58MBF
         KZTm8kxKJsHnuaNiAstLuquCRyXjgwWnx+R7l5qBxweqFe3jJHLtQGgVuNowueQpIxo4
         gB+VuDIM5IxXD1LTiDXXjj7mSNyNddAJsM7dvTy99ON6Cwil2NHknEG0g1UAqovluwO1
         VxZxmJ9uzjNH2ydTmLU0xD33Uat1rgFG5oUZfOoLw0MDVRIAl18tDWbdIbnn/+YZLbnl
         xjWQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=f6iBjAe0DvBUxz/rIGs71DM1Weu5YMao0JuwlSOpS90=;
        fh=fj+f4On3tYJrYoyJkMBkI2vb7/Hxsac2AEecyEr0Ed8=;
        b=ddxhdJiC3WIKFFIyVz6e0bh4MAuATOsbw7EftVorCN37dmiFYiU0kl1si0D+D7GMrE
         2Mf6IheH5NGrx3FWLobhRqmqHxX0+ml/2pmnzqgzL6Z2rkkBYbwRBAuOk2vgf+Q1AFH6
         d9ol2FTb5MZwsnj35E5FMozaSsNpXhI8aA5oqW9j6Z+ckWyt4dw6lgYobXYR6ZQmWcqi
         DHfbCcS1btO6z/nrSluJdVytQ3xk+Ph334MzVls3dV9xjMTxSAaILG2n8DVNEwIVFgAl
         MaOqdftiDalZMYBiSemZJjtdoA0C8e1u8jo/U9XqI6b98GOFTCcGqHLSL93gJ+FzHVTZ
         f2mA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="x/PMJKv5";
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::235 as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1709143654; x=1709748454; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=f6iBjAe0DvBUxz/rIGs71DM1Weu5YMao0JuwlSOpS90=;
        b=bAzTVxHNDIGr7nluHeHAhR+BbGMAXBENKfuT7EtYL13gqiccc8jZbQ2cTDhbp6m355
         0qQvps8Ejt+ZS/b4hN2557HOz1HkP5DzHEHTiic34zp89Bi898Y5tFRADemuDhzcYAdj
         yPf2yRR1j2hROOBwg5PUccFIME0DEZfR0U49Zi1Mo9dq5Ck7YMj76YtW1IW/UUKtyzyW
         9YFe1mrxCqDCpS6H386cCeibHhFz3l572cbcMX+ulsEAxUsLcKSnT8+bPZejYrBf/NaF
         JxJomcl2qXUvdGc86zP7BvSUuryecvADxMwWPTAc2bHwAMq+BfOE8FUW2rZdeecIvp3E
         9kRw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1709143654; x=1709748454;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=f6iBjAe0DvBUxz/rIGs71DM1Weu5YMao0JuwlSOpS90=;
        b=eMPhONJMFnNWccUY11jMCQrfbdCilfn+KHUzu5vQ0SEdjmt8I8lk371fAP9a5H1w+G
         w4uTm2GIVGgJ5mArlAhc10Ziz/prjV3M6EeqeuXusBDkBYH354laxu3nbolhMoafUw1Y
         Pi6P0h/8Vi8M9dhtR9nchDTdmDyX6U5AcystQXl2fGZIWzXAaicflc8wgptmDskAyeBU
         gR5+Y3+8qFqI67WtgDQipN1PW5MucZMyy2SlU3ghMvXd9xS5gMVQhTcpIWyV/PK3TY85
         z3xp7d3+zFfr2sRmwtRsAEwOzKHjfW9XAhl7yP+dKtcNzGkTiCY3lMn2hboBSmFtRO15
         z8Kg==
X-Forwarded-Encrypted: i=2; AJvYcCXAv5RCih+x8yRhUKObzKB2fZNSn8AIHMkmOp2t3JU35k25MCHLWl3n4TMXxKlSL8MBFV+9xDADs41iXb7pCSVCvnObdH3KEQ==
X-Gm-Message-State: AOJu0YxX28MO4uQyTuNhlhUSSnZRMAJlImL6uMcQJ5/X/R0RLvS4XZ3Q
	IjUSzCjRYFkMp1MOoRDvjoelRM317FQYoV8BHusKnwE8O7Y5ABRb
X-Google-Smtp-Source: AGHT+IE1fnd5sNB2pRCXscB8FjlChAYdZGvs3Ib6YINDf5ZxzbexSyokPgZCaEsNgJSZugdbZ9Ov3w==
X-Received: by 2002:a4a:d037:0:b0:5a0:3d13:a45a with SMTP id w23-20020a4ad037000000b005a03d13a45amr13195843oor.0.1709143654508;
        Wed, 28 Feb 2024 10:07:34 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:4487:0:b0:5a0:c482:52e3 with SMTP id o129-20020a4a4487000000b005a0c48252e3ls60377ooa.2.-pod-prod-04-us;
 Wed, 28 Feb 2024 10:07:33 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVH/GxGy2RJ6JXUqUbyy77WILIR6sfgjV55fH1E4TM3P/sVVQjF0ID33dm3HrDgo/rnJohmKUsq0Oop0X18U34z4xAqsiVCGWDj3g==
X-Received: by 2002:a05:6808:bce:b0:3c1:a1e8:aa56 with SMTP id o14-20020a0568080bce00b003c1a1e8aa56mr7083114oik.17.1709143653654;
        Wed, 28 Feb 2024 10:07:33 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1709143653; cv=none;
        d=google.com; s=arc-20160816;
        b=o1brYR+g/fXjUwJXyf5EDaAOreo2VlBvjMTY4qeC3I2N3vMEZYyYnV/UeXqtgd7j/1
         wvYKFsYk96z0GJNQaEKm5iZw14IZKSo/wX4MFreaZESIWv/WXE66K/uDeVEVjMCY0ZbI
         e9YRoJf6bjMb8/K5Cdr8rQiP7Ixh0sSz04BAQL4+lqF/9iO9u/CNBJgHIFmi8m3lyHI2
         6GCjvkE+wUS53rO6ksk9jOlbqAs2lF69t7za+yjTZTEpZDww0yPf5eqmJBZ0K+TsWDMh
         p2hxlBG1bjsq9VnVW9YBopSD6rThbLKUoK5Jtn1fspcS9rTM5ImOtsPtfwLhtOTFXlQ0
         9eUA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=TpJn79d7ymx24Tp5aF1RCceBrMYpEjjJMLmxKg1qMeo=;
        fh=tJGLVY6vRVsQiKHlud0NEbIECQzN+mzyXaNbaf524ro=;
        b=FgLdXd1WOeLsZpOKheuLy0yiCILLZy+oyWSVqF5TYK2qQNly7V0fwpYQbBuME8lF7V
         guX8MC4Dla0pZ5I/+rapTCJufP0fRZM1WnKafX2M6Rw+SO4nFvf22DrGYRVHvHLfayHV
         sdX7+CFkvQmUb3VkwfYUA8DZxHk7vnPY95m/Y4rygWlpMzp8A71q/7tC7JwM95KjshTu
         hxwdvfF/9dDERjg3+oOGuBbHjZoygQT7Un24iyKW38xO8mwYEN3sHcVj/Uzj+Cmx3ddg
         7hq/9XvvRgju5xvYpY+toKc0RRbJJ0EPJor8i7AMtIsRksKwFX+bJpezQ3BaDie3CeE5
         /CvQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="x/PMJKv5";
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::235 as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x235.google.com (mail-oi1-x235.google.com. [2607:f8b0:4864:20::235])
        by gmr-mx.google.com with ESMTPS id bl25-20020a056808309900b003c1b010a07esi315653oib.2.2024.02.28.10.07.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 28 Feb 2024 10:07:33 -0800 (PST)
Received-SPF: pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::235 as permitted sender) client-ip=2607:f8b0:4864:20::235;
Received: by mail-oi1-x235.google.com with SMTP id 5614622812f47-3c19bc08f96so3580100b6e.2
        for <kasan-dev@googlegroups.com>; Wed, 28 Feb 2024 10:07:33 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCX8eov6CN7C8ZADb3yHywyoo+3itziPZS6G9qvkv51b/5Io23zxU4UdM0yo//L9143/qyZyFBMcsJRaMByGSSoQa69jLlei1/o9iw==
X-Received: by 2002:a05:6358:80a8:b0:17b:521f:b2ae with SMTP id
 a40-20020a05635880a800b0017b521fb2aemr6472rwk.14.1709143652850; Wed, 28 Feb
 2024 10:07:32 -0800 (PST)
MIME-Version: 1.0
References: <20240221194052.927623-1-surenb@google.com> <20240221194052.927623-15-surenb@google.com>
 <b62d2ace-4619-40ac-8536-c5626e95d87b@suse.cz>
In-Reply-To: <b62d2ace-4619-40ac-8536-c5626e95d87b@suse.cz>
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 28 Feb 2024 18:07:18 +0000
Message-ID: <CAJuCfpEsBEK5M72v1MdSBnh_bFgJLRj3JzDdz1X1BGzfJw6sfw@mail.gmail.com>
Subject: Re: [PATCH v4 14/36] lib: add allocation tagging support for memory
 allocation profiling
To: Vlastimil Babka <vbabka@suse.cz>
Cc: akpm@linux-foundation.org, kent.overstreet@linux.dev, mhocko@suse.com, 
	hannes@cmpxchg.org, roman.gushchin@linux.dev, mgorman@suse.de, 
	dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com, 
	penguin-kernel@i-love.sakura.ne.jp, corbet@lwn.net, void@manifault.com, 
	peterz@infradead.org, juri.lelli@redhat.com, catalin.marinas@arm.com, 
	will@kernel.org, arnd@arndb.de, tglx@linutronix.de, mingo@redhat.com, 
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
 header.i=@google.com header.s=20230601 header.b="x/PMJKv5";       spf=pass
 (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::235 as
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

On Wed, Feb 28, 2024 at 8:41=E2=80=AFAM Vlastimil Babka <vbabka@suse.cz> wr=
ote:
>
> Another thing I noticed, dunno how critical
>
> On 2/21/24 20:40, Suren Baghdasaryan wrote:
> > +static inline void __alloc_tag_sub(union codetag_ref *ref, size_t byte=
s)
> > +{
> > +     struct alloc_tag *tag;
> > +
> > +#ifdef CONFIG_MEM_ALLOC_PROFILING_DEBUG
> > +     WARN_ONCE(ref && !ref->ct, "alloc_tag was not set\n");
> > +#endif
> > +     if (!ref || !ref->ct)
> > +             return;
>
> This is quite careful.
>
> > +
> > +     tag =3D ct_to_alloc_tag(ref->ct);
> > +
> > +     this_cpu_sub(tag->counters->bytes, bytes);
> > +     this_cpu_dec(tag->counters->calls);
> > +
> > +     ref->ct =3D NULL;
> > +}
> > +
> > +static inline void alloc_tag_sub(union codetag_ref *ref, size_t bytes)
> > +{
> > +     __alloc_tag_sub(ref, bytes);
> > +}
> > +
> > +static inline void alloc_tag_sub_noalloc(union codetag_ref *ref, size_=
t bytes)
> > +{
> > +     __alloc_tag_sub(ref, bytes);
> > +}
> > +
> > +static inline void alloc_tag_ref_set(union codetag_ref *ref, struct al=
loc_tag *tag)
> > +{
> > +#ifdef CONFIG_MEM_ALLOC_PROFILING_DEBUG
> > +     WARN_ONCE(ref && ref->ct,
> > +               "alloc_tag was not cleared (got tag for %s:%u)\n",\
> > +               ref->ct->filename, ref->ct->lineno);
> > +
> > +     WARN_ONCE(!tag, "current->alloc_tag not set");
> > +#endif
> > +     if (!ref || !tag)
> > +             return;
>
> This too.
>
> > +
> > +     ref->ct =3D &tag->ct;
> > +     /*
> > +      * We need in increment the call counter every time we have a new
> > +      * allocation or when we split a large allocation into smaller on=
es.
> > +      * Each new reference for every sub-allocation needs to increment=
 call
> > +      * counter because when we free each part the counter will be dec=
remented.
> > +      */
> > +     this_cpu_inc(tag->counters->calls);
> > +}
> > +
> > +static inline void alloc_tag_add(union codetag_ref *ref, struct alloc_=
tag *tag, size_t bytes)
> > +{
> > +     alloc_tag_ref_set(ref, tag);
>
> We might have returned from alloc_tag_ref_set() due to !tag
>
> > +     this_cpu_add(tag->counters->bytes, bytes);
>
> But here we still assume it's valid.

Yes, this is a blunder on my side after splitting alloc_tag_ref_set()
into a separate function. I'll fix this in the next version. Thanks!

>
> > +}
> > +
>
> --
> To unsubscribe from this group and stop receiving emails from it, send an=
 email to kernel-team+unsubscribe@android.com.
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAJuCfpEsBEK5M72v1MdSBnh_bFgJLRj3JzDdz1X1BGzfJw6sfw%40mail.gmail.=
com.
