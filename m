Return-Path: <kasan-dev+bncBC7OD3FKWUERB5HB5KUQMGQECBAA4RI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3b.google.com (mail-oa1-x3b.google.com [IPv6:2001:4860:4864:20::3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 9EAF07D8858
	for <lists+kasan-dev@lfdr.de>; Thu, 26 Oct 2023 20:33:25 +0200 (CEST)
Received: by mail-oa1-x3b.google.com with SMTP id 586e51a60fabf-1e98a9dd333sf1606616fac.2
        for <lists+kasan-dev@lfdr.de>; Thu, 26 Oct 2023 11:33:25 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1698345204; cv=pass;
        d=google.com; s=arc-20160816;
        b=cS6M1zXVc+KzH1rQ08QVylAgnSFIrnHEo6Fcqjd2yo3NxCBnLfuVV3LRxOZORMsYI4
         NjYfR++PAqveJk+fhDOPTxCMk0dGjmqmHib6rWUyscitm31RhQjWfZKpmpQIVG+FAIXW
         4l0qKIlQnzq9qWxUSjeKDQQHl7tzEytB1Rtc5wED8WssUVmnb0Go5KiFm+1xpI5z3T19
         42nlKhSA3XYe0g3IOxBCNkM2q/EyGObDoCPi9QKsgw0OepKfpDQzqYXnpaIxtivIGxfZ
         x7E9wmnQ4OcguJsYaw4Sz92y8GlkVnuD+VtCHzLdXft51xk82dmhypwS9XNcyJmtml2Z
         vZCg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=kyRMliF9wTASMyXTR/5GgSDIHcBBNktYovmOhWTaLXY=;
        fh=3IFX2VjqT5C4LntNjqSc4nAZbLSkTz4EF6/spOuY/Zs=;
        b=OVMMclarMSqDxS3qsuTIBTRaMybP9xu6f0Ysx/ChJMkXqOcvO4438EDFSPlVTO58yy
         Q87D9wfg1fBE7VkBFr74mDf5DIcyYeMVsktNM1WElSB4QKuZdHt6hKyD9PSdu/fU5xUO
         hnq7qOWpXu2XPBuhh5/9R6ogWvo2SB0bdcGSyareffmryN8YBIdbe61OUxpnS5nE7r5o
         zCRZdxBBQgUucKMuk05zvPxTvfu32jEEw0UHMoDECnonkxHuTtrTUQUrh5RFlID1Ko8S
         aRdENlpbZ9L8H4yAqgDOmHAZMG2CGyFjFMfgF8wOeA8CSM8vrT+ZZFT+IPz34Uh0Vnm5
         qkHA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=O061S8NP;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::112a as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1698345204; x=1698950004; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=kyRMliF9wTASMyXTR/5GgSDIHcBBNktYovmOhWTaLXY=;
        b=RdaR/tprY3rGWYS4SjXSCu8+JK7J8TQKCKK1KcIN9t4L1qF0vVulN+EZo5hjV3KrW1
         Q28KuHBTBHRNXJVJeL189d9NyLbs0zjvCdpX2SYTjJfMdop6ElwiuxnLfjS7FoKUNGBf
         Jn74VES5frEOB5BrOOd+GgUuH4tk8oFyFrpvFZ6Ik/Lhf8mOoleMWXpiLKWc0njqgdHO
         9HKHrrPfiuXzqkqoliu/hUUTWqQL7bOftc0jMswmnMaYg7a4WoVpjcoN6VUVNXmezaLH
         0nX9YY1UBBVyiDdgJwMEz0qLCbxlpvC0M8BMJMsZt94luquHL2Y1hwe2VfCdbY/I9wsW
         JcUQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1698345204; x=1698950004;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=kyRMliF9wTASMyXTR/5GgSDIHcBBNktYovmOhWTaLXY=;
        b=Lkc+hPAAUHDxXtnRQygaN0lz7kE7cRHWhFxrUgFouI8n6acAcHWaVJ7dyFS45gaNMU
         DJyN9zM5XO+ltU1sTbCwQlj2xzu5rOZRqApJubi51d0t1VjI/BpjB+jBjweIhoseVh1T
         oyDwgYeyH+uEo0YoRbLa1LB96JqK5Oevkz46OFVVXnQuQEVBdKvgNJ2QRDGavWjEdPB4
         DFizQ1mRYdeZb6q1xpLk127+FsPPxqzkmIaJ1JzTZbVEBHMT/BTNSa6dLAgkJb6Yzm7z
         yfxEU4uLuaF3jRQTSBJU2AbbE9pf3zWZPjwUgkFf/vSJMal5t+djiN0oI5yEA/5OWHh/
         s3Yg==
X-Gm-Message-State: AOJu0YxE3GumDH6VtqKVemoqZAYchTWr42rap03eFbP5HotrUPmEIW6H
	Ks1PPYuT5MOFADAfiOIdouQ=
X-Google-Smtp-Source: AGHT+IGFjSSmv/tOArU3fzow9ekm4nhTQUIa4eNgMyLJ1yGT31WT6KLsjK8Y5QOGvfmgGB45S74c6A==
X-Received: by 2002:a05:6870:b628:b0:1ef:15f5:1733 with SMTP id cm40-20020a056870b62800b001ef15f51733mr491742oab.25.1698345204229;
        Thu, 26 Oct 2023 11:33:24 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6871:a503:b0:1e9:d835:c43d with SMTP id
 wc3-20020a056871a50300b001e9d835c43dls469696oab.0.-pod-prod-06-us; Thu, 26
 Oct 2023 11:33:23 -0700 (PDT)
X-Received: by 2002:a05:6870:b88:b0:1ec:7e2a:6e31 with SMTP id lg8-20020a0568700b8800b001ec7e2a6e31mr541937oab.35.1698345203567;
        Thu, 26 Oct 2023 11:33:23 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1698345203; cv=none;
        d=google.com; s=arc-20160816;
        b=A3PYf3P/AM+HFi91PYZjetQIDB+onpFW5pG1F/8VcjbrOYwH4UAVI9wXTzrqI8Z4eT
         gMPf7ycU/YgRCeKMXaAST8GrMHtrYj5CSO/9BFSKVbb60f3+YWk65CmtRLlTbsQU8cU/
         /SqxgpKc60zOPBg3w8LQ2NtrL8V2hpoDy+XKeaRvWsJnxlS07jgQxe8qBypfCQvuZHoc
         f8f24oAioq8VngDGf4EH8jd7EL7U2CmSOsbxuYD9AniiMYzWMJnUId9B3MkMSaIMg6op
         09fSHub3sqRMnqptf4gFcx57swJ8YYqbQTwvQplAZFWztb2E32Yvq7XldkolGl93FhLy
         JM/A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=Rsh3dPt2/r73NgmaoP1t7gGhxASdUa0L8chPdmn23Qo=;
        fh=3IFX2VjqT5C4LntNjqSc4nAZbLSkTz4EF6/spOuY/Zs=;
        b=QH6tIJ/9ibLsP1d3kPmlePjn07gTWjEPMbSCl3duRwYPBLzr85+M+TABqCZui08LUV
         h6ToVuF4PH1olaLqag+RiB+D7+BHs/E6AN0J/o6kcqjXwrwNvpf0Ib2dR5NPU4fztcUi
         wNfCftoUkQ+N32pqKv4QEkiiWbPU7VBAudU8mMXt/UY3UXPffshOVxxpaqvg/s/ZCa2Y
         /4+RtHB1PWIS+RBO244CoFACZagVzatnfJucjqmaJTKdlY5NL/OQw+gswvV4NOnUnZ+n
         LT3O6izAnZ0jWKGvBZanglf0eywqL2FVTqWVC5xA9dk/QDTeC/zEHcwIRnzZFSYY5ElD
         +YDg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=O061S8NP;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::112a as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x112a.google.com (mail-yw1-x112a.google.com. [2607:f8b0:4864:20::112a])
        by gmr-mx.google.com with ESMTPS id s19-20020a05687090d300b001c8bbdda1a5si1880303oab.1.2023.10.26.11.33.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 26 Oct 2023 11:33:23 -0700 (PDT)
Received-SPF: pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::112a as permitted sender) client-ip=2607:f8b0:4864:20::112a;
Received: by mail-yw1-x112a.google.com with SMTP id 00721157ae682-5a7c08b7744so9583077b3.3
        for <kasan-dev@googlegroups.com>; Thu, 26 Oct 2023 11:33:23 -0700 (PDT)
X-Received: by 2002:a25:74c5:0:b0:da0:46ad:fb46 with SMTP id
 p188-20020a2574c5000000b00da046adfb46mr114458ybc.41.1698345202763; Thu, 26
 Oct 2023 11:33:22 -0700 (PDT)
MIME-Version: 1.0
References: <20231024134637.3120277-1-surenb@google.com> <20231024134637.3120277-29-surenb@google.com>
 <87h6me620j.ffs@tglx>
In-Reply-To: <87h6me620j.ffs@tglx>
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 26 Oct 2023 18:33:09 +0000
Message-ID: <CAJuCfpH1pG513-FUE_28MfJ7xbX=9O-auYUjkxKLmtve_6rRAw@mail.gmail.com>
Subject: Re: [PATCH v2 28/39] timekeeping: Fix a circular include dependency
To: Thomas Gleixner <tglx@linutronix.de>
Cc: akpm@linux-foundation.org, kent.overstreet@linux.dev, mhocko@suse.com, 
	vbabka@suse.cz, hannes@cmpxchg.org, roman.gushchin@linux.dev, mgorman@suse.de, 
	dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com, 
	corbet@lwn.net, void@manifault.com, peterz@infradead.org, 
	juri.lelli@redhat.com, ldufour@linux.ibm.com, catalin.marinas@arm.com, 
	will@kernel.org, arnd@arndb.de, mingo@redhat.com, dave.hansen@linux.intel.com, 
	x86@kernel.org, peterx@redhat.com, david@redhat.com, axboe@kernel.dk, 
	mcgrof@kernel.org, masahiroy@kernel.org, nathan@kernel.org, dennis@kernel.org, 
	tj@kernel.org, muchun.song@linux.dev, rppt@kernel.org, paulmck@kernel.org, 
	pasha.tatashin@soleen.com, yosryahmed@google.com, yuzhao@google.com, 
	dhowells@redhat.com, hughd@google.com, andreyknvl@gmail.com, 
	keescook@chromium.org, ndesaulniers@google.com, vvvvvv@google.com, 
	gregkh@linuxfoundation.org, ebiggers@google.com, ytcoode@gmail.com, 
	vincent.guittot@linaro.org, dietmar.eggemann@arm.com, rostedt@goodmis.org, 
	bsegall@google.com, bristot@redhat.com, vschneid@redhat.com, cl@linux.com, 
	penberg@kernel.org, iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com, 
	glider@google.com, elver@google.com, dvyukov@google.com, shakeelb@google.com, 
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
 header.i=@google.com header.s=20230601 header.b=O061S8NP;       spf=pass
 (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::112a
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

On Wed, Oct 25, 2023 at 5:33=E2=80=AFPM Thomas Gleixner <tglx@linutronix.de=
> wrote:
>
> On Tue, Oct 24 2023 at 06:46, Suren Baghdasaryan wrote:
> > From: Kent Overstreet <kent.overstreet@linux.dev>
> >
> > This avoids a circular header dependency in an upcoming patch by only
> > making hrtimer.h depend on percpu-defs.h
>
> What's the actual dependency problem?

Sorry for the delay.
When we instrument per-cpu allocations in [1] we need to include
sched.h in percpu.h to be able to use alloc_tag_save(). sched.h
includes hrtimer.h. So, without this change we end up with a circular
inclusion: percpu.h->sched.h->hrtimer.h->percpu.h

[1] https://lore.kernel.org/all/20231024134637.3120277-32-surenb@google.com=
/

>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAJuCfpH1pG513-FUE_28MfJ7xbX%3D9O-auYUjkxKLmtve_6rRAw%40mail.gmai=
l.com.
