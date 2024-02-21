Return-Path: <kasan-dev+bncBCC2HSMW4ECBBMWQ3GXAMGQEJ4DIBAA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63a.google.com (mail-pl1-x63a.google.com [IPv6:2607:f8b0:4864:20::63a])
	by mail.lfdr.de (Postfix) with ESMTPS id 0E32D85E9C2
	for <lists+kasan-dev@lfdr.de>; Wed, 21 Feb 2024 22:16:36 +0100 (CET)
Received: by mail-pl1-x63a.google.com with SMTP id d9443c01a7336-1dc35ee0918sf8360325ad.1
        for <lists+kasan-dev@lfdr.de>; Wed, 21 Feb 2024 13:16:35 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708550194; cv=pass;
        d=google.com; s=arc-20160816;
        b=iCzSLlVrfbYs1p57iNJiN/LEMqm/HcvdlOcMQjghTnyN0tPqKCVOxGgieXqVerGYRv
         PnhXRlulUQHY4oLP65b1sIm4nPvxYcYrCQAVVZcordXGvhTPTGeCRIe/9Hk/5pfdljoL
         cjfXEV1486zbgJKgnwdCl6qnk0bo13gcTqHcmdsgj5nJ18hKmJfyRiHgyBBWFxDr5snF
         1jD+Z4fLMmtz6AGtSLPgzpS0hTNB8FjwNE+G7LVVsa2kToIUQ2kH2vlxSSpCrNtCh0n9
         kRwvyD6raH5LTGQTwmLFB1/WKoWRsJB9eGJQv7t/d1x/EvD57rVTzDg9qmZR2jzsqY+D
         VsqQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature;
        bh=76uBW5oNe/H7rRtAf5JFEorMW8r29aQabz0Wu21H28Y=;
        fh=F910OTHLHXHh05AO6amnLZF1W6JbyPFsK2L5+JsZTak=;
        b=FCdWhTNBno0c9V2WopI4Jo2WlnJKfZy5IqUu2IdmISjjI2PuES6uzZeJpnWPvgjVKL
         Mo4BFoccULA95eoAGkKuthzQBkyXinA4k43ejTI2rIe3Tf45mQ4wfY/EnKlzi3WD3dPT
         QyQDfhFdYxqWFFdR8VUlEG0KUxAQrvV80a47wKIPGdovACsRS8s7CQgVra/sPYDEyHTU
         RS9/jjVa0JS0kQLq9DSuZLxgbzXt0n2xxQhEoCAsvNVPn0ok+1A9bcch3RBgP/MSdkIw
         +4NPW8zcN1nbiSMj2SBIJWjwjEu0Xxv2Vv7cEsxr40R9zQco9KcNPqsIX7gkZUeXC3Ni
         flmg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@soleen-com.20230601.gappssmtp.com header.s=20230601 header.b=nedk7Aky;
       spf=pass (google.com: domain of pasha.tatashin@soleen.com designates 2607:f8b0:4864:20::32b as permitted sender) smtp.mailfrom=pasha.tatashin@soleen.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=soleen.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708550194; x=1709154994; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=76uBW5oNe/H7rRtAf5JFEorMW8r29aQabz0Wu21H28Y=;
        b=HKgadif3voBlBM0UrDU3kLX30+USlxETvUiiGaUjq3pYeehOnDB/5MBeW8tpNr4opf
         kr0X9TMuncnxtvho+Be+rNn3uvce6uHsPlICceiKF15ZHz6PjT9X2VmLcVaEhGnyqdvp
         F65fWDQvRRU7u15sIkOpWV3LMhGgh7dpFg9hedFbMD2dXFFgDSdmVYXtos2UmrtswLJz
         geLcmJL0CB7q9ugJfxOncPXUnA9Ctn8k/jsYmGpMi9Frw1GoiE6zazBBQRBXFCqrNLTM
         bXMDToNYY62U9838jekLoZ+XFgLmrU0g4xfNiUXMRXW8ZCz/8K3jOu45JCfwdtdjkgXg
         5lkw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708550194; x=1709154994;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=76uBW5oNe/H7rRtAf5JFEorMW8r29aQabz0Wu21H28Y=;
        b=AOcvDZJ7BpVThD4UuPIDvaXjXqs5QDdqTbTmdCkl3cXvui7sT2vYgWGu/F3s08bgyR
         ewgbyfuBMMDS3kXoMLplBpx3ETxRLgzZitA26g11J5tFJsYEJFCSKIXKvc70JxsNM9YU
         ESNq+UeKli/N8s9CsyjSNHwxzYeldGOIBVDLV9xBdNskxbvfFqevTLjciiFRpp38PjxA
         LOrLKXp9P+VmgqgEn8Q6MxU6INNQUL5Gyr4xugcmJ/mF/5mZVEWaHA0QIyy8a7uycwul
         pABrIk7wvwhjywDayjloeXwM8wU3UhNXk5UcRmWHaLxUH7qtCm+xp/VIqYmLR3u9iWG1
         FpIA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCW58n5ooQmd89TcIIainCln8VOl0DLQN7buOZuzDdBDmvutpfmjgxK9TTuv0bJdyYLySFLcEaxXDEVL0W/6I0h3uHqeoabRZg==
X-Gm-Message-State: AOJu0Yx1C0r8kM9NaNF9kTBkMricibvLh37oCZNbRRTxHljvaI6irAsy
	lWmEBLI8gkOUIAgut0Vo6iIbAUw4EQTOqvzQoJ5seokPhiZ2eLwJ
X-Google-Smtp-Source: AGHT+IHZ9PreFHmP7NuW1siJyabehudWISBg8OWjv0CvZCn7vTyt6NGg5sEWqlkcV9p4SexDbr2Ixw==
X-Received: by 2002:a17:902:64c8:b0:1dc:1df6:48a0 with SMTP id y8-20020a17090264c800b001dc1df648a0mr4111057pli.66.1708550194486;
        Wed, 21 Feb 2024 13:16:34 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:dac2:b0:1db:3ede:8aa7 with SMTP id
 q2-20020a170902dac200b001db3ede8aa7ls3892455plx.1.-pod-prod-01-us; Wed, 21
 Feb 2024 13:16:33 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWA1MDhP11lnO6R8Nll0FOg3E7mSA8QkgrwOFpXUEnee1Rg7cZnCl0TAeaXanIwkjTjgsvByDuyM97EEFHYrLe0dBuKWKUnqWdMFg==
X-Received: by 2002:a17:902:f688:b0:1db:f941:c9a with SMTP id l8-20020a170902f68800b001dbf9410c9amr10252464plg.45.1708550193432;
        Wed, 21 Feb 2024 13:16:33 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1708550193; cv=none;
        d=google.com; s=arc-20160816;
        b=bJqzQsY47jCkJgT+37May40OCBAtPwxSPFcWsBiXM0vVKOj+YeAYnRXYOtm7wGQoit
         Ystp+/1sy5ZIs05uFJuF36Ph7lLUffMZSaQdg6w+mYVRvfA2Ug5H3Eybmv/8gdqGyNs4
         2l+KPAkQos0ZRv933TPA2nmT7Ff3+Wh6fngA96SCF9UMKwJ9v4fEuUw1lUyeTapGKTGM
         Gc9ui7WJ8/uJjZnKtsxbJic4WKrDQ5Ek2upYejMPOe+aq3Nje5HkwF7P+K/aGL4P44Rr
         8ahDBPQ2v8jVTqvQ1d9qX9HQQWHUZQTEpdN8mkRFOLI30V2spsPbXwT/EqaGys2tEYW/
         1Tjw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=YWpAXMfptvXBWhPj/Zu9FAZfSnAxEQBXKk45RWYFa4c=;
        fh=FrTAG/EQkhdQTeFKVPT5TDR2UG99M3T9toyoiy7ehc8=;
        b=u1bDLjcHB42V57LAHelUQ6e4MQFTFuEq7jCh9M5LASrjENI5vWv7tdphJ2SVRYESMd
         YBfR7v/syL3CGHx0w6ZMLRSiGUT+37vdcTFpoFfqc+N2aEE2lTVALTCAGtv0R5oSgtaU
         rkIMHxsTC6m3IXO7/tnu272LmJQyC4Cytm+h3Unt8dSwcRZbxiMEgsozFAqx8eQEOxhm
         SCGTSMHOkzeMw4ZCzScp/X8zqPLZTcAtLg4/CIkejgRjJhnar135meOts8qchVJM8aAH
         FhKErdXnpeZl9wc2AEOFMRe3wd+o+Nqqpp5mZrNaLv4rbHraXboDq/fM5BulzUZhfDfe
         ARvw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@soleen-com.20230601.gappssmtp.com header.s=20230601 header.b=nedk7Aky;
       spf=pass (google.com: domain of pasha.tatashin@soleen.com designates 2607:f8b0:4864:20::32b as permitted sender) smtp.mailfrom=pasha.tatashin@soleen.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=soleen.com
Received: from mail-ot1-x32b.google.com (mail-ot1-x32b.google.com. [2607:f8b0:4864:20::32b])
        by gmr-mx.google.com with ESMTPS id mi13-20020a170902fccd00b001d8cea8344bsi636728plb.7.2024.02.21.13.16.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 21 Feb 2024 13:16:33 -0800 (PST)
Received-SPF: pass (google.com: domain of pasha.tatashin@soleen.com designates 2607:f8b0:4864:20::32b as permitted sender) client-ip=2607:f8b0:4864:20::32b;
Received: by mail-ot1-x32b.google.com with SMTP id 46e09a7af769-6e4423b64acso2750286a34.2
        for <kasan-dev@googlegroups.com>; Wed, 21 Feb 2024 13:16:33 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCVNdliCsBuFOQuwBmzuSPhTjedEftffGnIS62knn40nwW8cno7hE15FCrdkPqW2g/bubLVskiSzEy5syjFnObR3+h6XveRD8tVTQQ==
X-Received: by 2002:a05:6830:1345:b0:6e2:f2cc:e985 with SMTP id
 r5-20020a056830134500b006e2f2cce985mr19962028otq.13.1708550192733; Wed, 21
 Feb 2024 13:16:32 -0800 (PST)
MIME-Version: 1.0
References: <20240221194052.927623-1-surenb@google.com> <20240221194052.927623-4-surenb@google.com>
In-Reply-To: <20240221194052.927623-4-surenb@google.com>
From: Pasha Tatashin <pasha.tatashin@soleen.com>
Date: Wed, 21 Feb 2024 16:15:56 -0500
Message-ID: <CA+CK2bD8Cr1V2=PWAsf6CwDnakZ54Qaf_q5t4aVYV-jXQPtPbg@mail.gmail.com>
Subject: Re: [PATCH v4 03/36] mm/slub: Mark slab_free_freelist_hook() __always_inline
To: Suren Baghdasaryan <surenb@google.com>
Cc: akpm@linux-foundation.org, kent.overstreet@linux.dev, mhocko@suse.com, 
	vbabka@suse.cz, hannes@cmpxchg.org, roman.gushchin@linux.dev, mgorman@suse.de, 
	dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com, 
	penguin-kernel@i-love.sakura.ne.jp, corbet@lwn.net, void@manifault.com, 
	peterz@infradead.org, juri.lelli@redhat.com, catalin.marinas@arm.com, 
	will@kernel.org, arnd@arndb.de, tglx@linutronix.de, mingo@redhat.com, 
	dave.hansen@linux.intel.com, x86@kernel.org, peterx@redhat.com, 
	david@redhat.com, axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org, 
	nathan@kernel.org, dennis@kernel.org, tj@kernel.org, muchun.song@linux.dev, 
	rppt@kernel.org, paulmck@kernel.org, yosryahmed@google.com, yuzhao@google.com, 
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
X-Original-Sender: pasha.tatashin@soleen.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@soleen-com.20230601.gappssmtp.com header.s=20230601
 header.b=nedk7Aky;       spf=pass (google.com: domain of pasha.tatashin@soleen.com
 designates 2607:f8b0:4864:20::32b as permitted sender) smtp.mailfrom=pasha.tatashin@soleen.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=soleen.com
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

On Wed, Feb 21, 2024 at 2:41=E2=80=AFPM Suren Baghdasaryan <surenb@google.c=
om> wrote:
>
> From: Kent Overstreet <kent.overstreet@linux.dev>
>
> It seems we need to be more forceful with the compiler on this one.
> This is done for performance reasons only.
>
> Signed-off-by: Kent Overstreet <kent.overstreet@linux.dev>
> Signed-off-by: Suren Baghdasaryan <surenb@google.com>
> Reviewed-by: Kees Cook <keescook@chromium.org>
> ---
>  mm/slub.c | 2 +-
>  1 file changed, 1 insertion(+), 1 deletion(-)
>
> diff --git a/mm/slub.c b/mm/slub.c
> index 2ef88bbf56a3..d31b03a8d9d5 100644
> --- a/mm/slub.c
> +++ b/mm/slub.c
> @@ -2121,7 +2121,7 @@ bool slab_free_hook(struct kmem_cache *s, void *x, =
bool init)
>         return !kasan_slab_free(s, x, init);
>  }
>
> -static inline bool slab_free_freelist_hook(struct kmem_cache *s,
> +static __always_inline bool slab_free_freelist_hook(struct kmem_cache *s=
,

__fastpath_inline seems to me more appropriate here. It prioritizes
memory vs performance.

>                                            void **head, void **tail,
>                                            int *cnt)
>  {
> --
> 2.44.0.rc0.258.g7320e95886-goog
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BCK2bD8Cr1V2%3DPWAsf6CwDnakZ54Qaf_q5t4aVYV-jXQPtPbg%40mail.gm=
ail.com.
